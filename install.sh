#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# Xray VLESS/WS + SSH/TLS + SSH WebSocket
# Ubuntu/Debian | for servers you own/control
#
# Layout:
#   DOMAIN_443:443  -> VLESS/WS (TLS)
#   DOMAIN_WS:443   -> SSH/TLS
#   DOMAIN_WS:8880  -> SSH WebSocket (/ssh)
#
# 443 is multiplexed by SNI. Therefore DOMAIN_443 and DOMAIN_WS
# must be different hostnames if both VLESS and SSH/TLS use 443.
# ============================================================

CONFIG="/etc/vpn_script.conf"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_VLESS_PORT=10443
SSH_TLS_PORT=8443
WS_PORT=8880
WS_PATH="/ssh"
MENU="/usr/local/bin/vpn-menu"
SSH_WS_APP="/usr/local/sbin/ssh-ws-proxy.py"
SSH_WS_UNIT="/etc/systemd/system/ssh-ws.service"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
TLS_DIR="/etc/vpn-tls"
VLESS_CERT="$TLS_DIR/vless.crt"
VLESS_KEY="$TLS_DIR/vless.key"
SSH_CERT="$TLS_DIR/ssh.pem"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
die(){ echo -e "${RED}[X] $*${NC}" >&2; exit 1; }
ok(){ echo -e "${GREEN}[✓] $*${NC}"; }
warn(){ echo -e "${YELLOW}[!] $*${NC}"; }
info(){ echo -e "${CYAN}[*] $*${NC}"; }

require_root(){ [[ "$EUID" -eq 0 ]] || die "Run this installer as root."; }
detect_os(){
  [[ -r /etc/os-release ]] || die "Cannot detect operating system.";
  . /etc/os-release
  case "${ID:-}" in ubuntu|debian) ;; *) die "Supported systems: Ubuntu/Debian. Detected: ${ID:-unknown}";; esac
}
valid_domain(){ [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]; }
valid_path(){ [[ "$1" == /* ]] && [[ "$1" != *[[:space:]]* ]]; }

save_config(){
  umask 077
  cat >"$CONFIG" <<CFG
DOMAIN_443=$(printf '%q' "$DOMAIN_443")
DOMAIN_WS=$(printf '%q' "$DOMAIN_WS")
SNI_443=$(printf '%q' "$SNI_443")
WS_HOST=$(printf '%q' "$WS_HOST")
USER_UUID=$(printf '%q' "$USER_UUID")
CFG
}
load_config(){ [[ -f "$CONFIG" ]] && . "$CONFIG"; }

install_packages(){
  info "Installing required packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y haproxy stunnel4 openssl curl ca-certificates jq lsof psmisc python3 python3-websockets
}

install_xray(){
  if command -v xray >/dev/null 2>&1; then
    ok "Xray already installed."
  else
    info "Installing Xray..."
    bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
  fi
}

generate_uuid(){ [[ -n "${USER_UUID:-}" ]] || USER_UUID="$(cat /proc/sys/kernel/random/uuid)"; }

stop_conflicts(){
  # Only stop common services that could occupy the required ports.
  systemctl stop nginx 2>/dev/null || true
  systemctl stop apache2 2>/dev/null || true
  systemctl stop haproxy 2>/dev/null || true
  fuser -k 80/tcp 2>/dev/null || true
  fuser -k 443/tcp 2>/dev/null || true
  fuser -k 8880/tcp 2>/dev/null || true
  fuser -k "$XRAY_VLESS_PORT/tcp" 2>/dev/null || true
  fuser -k "$SSH_TLS_PORT/tcp" 2>/dev/null || true
}

make_self_signed(){
  local domain="$1" cert="$2" key="$3"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$key" -out "$cert" -subj "/CN=$domain" \
    -addext "subjectAltName=DNS:$domain" >/dev/null 2>&1
  chmod 600 "$cert" "$key"
}

configure_tls(){
  mkdir -p "$TLS_DIR" /etc/stunnel
  chmod 700 "$TLS_DIR"

  # Prefer a trusted Let's Encrypt certificate when both DNS names already
  # resolve to this server. Fall back to a self-signed certificate for testing.
  local le_ok=0
  if command -v certbot >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
    if certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email \
        -d "$DOMAIN_443" -d "$DOMAIN_WS" >/tmp/certbot.log 2>&1; then
      cp -f "/etc/letsencrypt/live/$DOMAIN_443/fullchain.pem" "$VLESS_CERT"
      cp -f "/etc/letsencrypt/live/$DOMAIN_443/privkey.pem" "$VLESS_KEY"
      cat "/etc/letsencrypt/live/$DOMAIN_443/fullchain.pem" \
          "/etc/letsencrypt/live/$DOMAIN_443/privkey.pem" >"$SSH_CERT"
      chmod 600 "$VLESS_CERT" "$VLESS_KEY" "$SSH_CERT"
      le_ok=1
      ok "Trusted certificate obtained from Let's Encrypt."
    else
      warn "Let's Encrypt certificate was not obtained; using self-signed certificates."
      warn "Check /tmp/certbot.log if you expected a trusted certificate."
    fi
  fi

  if [[ "$le_ok" -eq 0 ]]; then
    make_self_signed "$DOMAIN_443" "$VLESS_CERT" "$VLESS_KEY"
    local tmpcert="$TLS_DIR/ssh.crt" tmpkey="$TLS_DIR/ssh.key"
    make_self_signed "$DOMAIN_WS" "$tmpcert" "$tmpkey"
    cat "$tmpcert" "$tmpkey" >"$SSH_CERT"
    rm -f "$tmpcert" "$tmpkey"
    chmod 600 "$SSH_CERT"
  fi

  cat >/etc/stunnel/stunnel.conf <<EOF2
client = no
foreground = no
pid = /run/stunnel4/stunnel.pid
cert = $SSH_CERT
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls]
accept = 127.0.0.1:$SSH_TLS_PORT
connect = 127.0.0.1:22
EOF2

  if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 || true
  fi

  # Keep copies used by Xray/stunnel updated after future Certbot renewals.
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/vpn-script-cert.sh <<HOOK
#!/usr/bin/env bash
set -e
if [[ -f /etc/letsencrypt/live/$DOMAIN_443/fullchain.pem && -f /etc/letsencrypt/live/$DOMAIN_443/privkey.pem ]]; then
  cp -f /etc/letsencrypt/live/$DOMAIN_443/fullchain.pem $VLESS_CERT
  cp -f /etc/letsencrypt/live/$DOMAIN_443/privkey.pem $VLESS_KEY
  cat /etc/letsencrypt/live/$DOMAIN_443/fullchain.pem /etc/letsencrypt/live/$DOMAIN_443/privkey.pem >$SSH_CERT
  chmod 600 $VLESS_CERT $VLESS_KEY $SSH_CERT
  systemctl restart xray stunnel4 haproxy || true
fi
HOOK
  chmod 700 /etc/letsencrypt/renewal-hooks/deploy/vpn-script-cert.sh
}
configure_tls(){
  # Separate certificates match the two SNI names. They are self-signed.
  make_cert "$DOMAIN_443" "$VLESS_CERT"
  make_cert "$DOMAIN_WS" "$SSH_CERT"

  mkdir -p /etc/stunnel
  cat >/etc/stunnel/stunnel.conf <<EOF2
client = no
foreground = no
pid = /run/stunnel4/stunnel.pid
cert = $SSH_CERT
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls]
accept = 127.0.0.1:$SSH_TLS_PORT
connect = 127.0.0.1:22
EOF2
  if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 || true
  fi
}

configure_xray(){
  mkdir -p "$(dirname "$XRAY_CONFIG")"
  cat >"$XRAY_CONFIG" <<EOF2
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": $XRAY_VLESS_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$USER_UUID"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "$VLESS_CERT",
          "keyFile": "$VLESS_KEY"
        }]
      },
      "wsSettings": {"path": "/vless-ws"}
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF2
  jq empty "$XRAY_CONFIG" >/dev/null || die "Invalid Xray JSON."
  xray run -test -config "$XRAY_CONFIG" >/tmp/xray-test.log 2>&1 || { cat /tmp/xray-test.log; die "Xray configuration test failed."; }
}

configure_ssh_ws(){
  cat >"$SSH_WS_APP" <<'PY'
#!/usr/bin/env python3
import asyncio
import websockets

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8880
PATH = "/ssh"
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 22

async def bridge(ws):
    reader, writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
    async def from_ws():
        try:
            async for msg in ws:
                if isinstance(msg, str):
                    msg = msg.encode()
                writer.write(msg)
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    async def to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await ws.send(data)
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    await asyncio.gather(from_ws(), to_ws())

async def handler(ws):
    # websockets versions differ in whether path is passed separately.
    path = getattr(ws, "path", PATH)
    if path != PATH:
        await ws.close(code=1008, reason="Invalid path")
        return
    try:
        await bridge(ws)
    except Exception:
        try:
            await ws.close()
        except Exception:
            pass

async def main():
    async with websockets.serve(
        handler, LISTEN_HOST, LISTEN_PORT,
        max_size=None, ping_interval=20, ping_timeout=60
    ):
        print(f"SSH WebSocket listening on {LISTEN_HOST}:{LISTEN_PORT}{PATH}", flush=True)
        await asyncio.Future()

asyncio.run(main())
PY
  chmod 700 "$SSH_WS_APP"
  cat >"$SSH_WS_UNIT" <<EOF2
[Unit]
Description=SSH WebSocket bridge on port $WS_PORT
After=network-online.target ssh.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SSH_WS_APP
Restart=always
RestartSec=2
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF2
}

configure_haproxy(){
  cat >"$HAPROXY_CFG" <<EOF2
global
    log /dev/log local0
    log /dev/log local1 notice
    daemon
    maxconn 4096

defaults
    log global
    mode tcp
    timeout connect 10s
    timeout client 2m
    timeout server 2m

frontend tls_443
    bind 0.0.0.0:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
    use_backend vless_tls if { req_ssl_sni -i $DOMAIN_443 }
    use_backend ssh_tls if { req_ssl_sni -i $DOMAIN_WS }
    default_backend vless_tls

backend vless_tls
    mode tcp
    server xray 127.0.0.1:$XRAY_VLESS_PORT check

backend ssh_tls
    mode tcp
    server stunnel 127.0.0.1:$SSH_TLS_PORT check
EOF2
  haproxy -c -f "$HAPROXY_CFG" >/tmp/haproxy-test.log 2>&1 || { cat /tmp/haproxy-test.log; die "HAProxy configuration test failed."; }
}

restart_services(){
  systemctl daemon-reload
  systemctl enable xray stunnel4 ssh-ws haproxy >/dev/null 2>&1 || true
  systemctl restart ssh-ws
  systemctl restart xray
  systemctl restart stunnel4
  systemctl restart haproxy
}

check_services(){
  sleep 1
  systemctl is-active --quiet ssh-ws || { journalctl -u ssh-ws -n 30 --no-pager; die "SSH WebSocket service failed."; }
  systemctl is-active --quiet xray || { journalctl -u xray -n 30 --no-pager; die "Xray failed."; }
  systemctl is-active --quiet stunnel4 || { journalctl -u stunnel4 -n 30 --no-pager; die "stunnel4 failed."; }
  systemctl is-active --quiet haproxy || { journalctl -u haproxy -n 30 --no-pager; die "HAProxy failed."; }
  ss -lntp | grep -Eq ':443\b' || die "Nothing is listening on 443."
  ss -lntp | grep -Eq ':8880\b' || die "Nothing is listening on 8880."
  ok "All services are active and ports 443/8880 are listening."
}

create_account(){
  clear; load_config
  echo "========== CREATE SSH ACCOUNT =========="
  read -rp "Username: " username
  read -rsp "Password: " password; echo
  read -rp "Expiration days [30]: " days; days="${days:-30}"
  [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { warn "Invalid username."; read -r; return; }
  [[ "$days" =~ ^[0-9]+$ ]] || { warn "Days must be numeric."; read -r; return; }
  [[ -n "$password" ]] || { warn "Password cannot be empty."; read -r; return; }
  id "$username" >/dev/null 2>&1 && { warn "User already exists."; read -r; return; }
  local expire; expire="$(date -d "+$days days" +%Y-%m-%d)"
  useradd -e "$expire" -M -s /bin/bash "$username"
  echo "$username:$password" | chpasswd
  echo
  ok "Account created."
  echo "Username : $username"
  echo "Password : $password"
  echo "Expires  : $expire"
  echo
  echo "SSH TLS Server : $DOMAIN_WS"
  echo "SSH TLS Port   : 443"
  echo "SSH TLS SNI    : $DOMAIN_WS"
  echo
  echo "SSH WebSocket  : $DOMAIN_WS:8880"
  echo "SSH WS Path    : $WS_PATH"
  echo "SSH WS format  : $DOMAIN_WS:8880@$username:$password"
  echo
  read -rp "Press Enter..."
}

delete_account(){
  clear; read -rp "Username to delete: " username
  if id "$username" >/dev/null 2>&1; then userdel "$username"; ok "Deleted: $username"; else warn "User not found."; fi
  read -rp "Press Enter..."
}

list_accounts(){
  clear; echo "========== SSH ACCOUNTS =========="
  awk -F: '$3 >= 1000 {print $1}' /etc/passwd | while read -r u; do
    exp="$(chage -l "$u" 2>/dev/null | awk -F': ' '/Account expires/{print $2}')"
    printf '%-20s %s\n' "$u" "${exp:-unknown}"
  done
  echo; read -rp "Press Enter..."
}

show_settings(){
  clear; load_config
  echo "========== VLESS =========="
  echo "Server : $DOMAIN_443"
  echo "Port   : 443"
  echo "SNI    : $SNI_443"
  echo "Host   : $DOMAIN_443"
  echo "Path   : /vless-ws"
  echo "UUID   : $USER_UUID"
  echo
  echo "========== SSH TLS =========="
  echo "Server : $DOMAIN_WS"
  echo "Port   : 443"
  echo "SNI    : $DOMAIN_WS"
  echo
  echo "========== SSH WebSocket =========="
  echo "Server : $DOMAIN_WS"
  echo "Port   : 8880"
  echo "Path   : $WS_PATH"
  echo "Format : $DOMAIN_WS:8880@USER:PASS"
  echo
  warn "The bundled certificates are self-signed. For certificate-verifying clients, install a trusted certificate matching the domains."
  read -rp "Press Enter..."
}

status(){
  clear; echo "========== SERVICE STATUS =========="
  for svc in haproxy xray stunnel4 ssh-ws; do
    if systemctl is-active --quiet "$svc"; then ok "$svc: ACTIVE"; else warn "$svc: NOT ACTIVE"; fi
  done
  echo; echo "========== LISTENING PORTS =========="
  ss -lntp 2>/dev/null | grep -E ':(22|443|8880|8443|10443)\b' || true
  echo; read -rp "Press Enter..."
}

test_config(){
  clear; echo "========== CONFIG TEST =========="
  haproxy -c -f "$HAPROXY_CFG" >/tmp/haproxy-test.log 2>&1 && ok "HAProxy config: OK" || { warn "HAProxy config: FAILED"; cat /tmp/haproxy-test.log; }
  xray run -test -config "$XRAY_CONFIG" >/tmp/xray-test.log 2>&1 && ok "Xray config: OK" || { warn "Xray config: FAILED"; cat /tmp/xray-test.log; }
  systemctl is-active --quiet ssh-ws && ok "SSH WebSocket: ACTIVE" || { warn "SSH WebSocket: FAILED"; journalctl -u ssh-ws -n 20 --no-pager; }
  systemctl is-active --quiet stunnel4 && ok "SSH TLS: ACTIVE" || { warn "SSH TLS: FAILED"; journalctl -u stunnel4 -n 20 --no-pager; }
  echo; ss -lntp 2>/dev/null | grep -E ':(443|8880)\b' || true
  read -rp "Press Enter..."
}

change_settings(){
  clear; load_config
  echo "========== SETTINGS =========="
  echo "443 Domain : $DOMAIN_443"
  echo "8880 Domain: $DOMAIN_WS"
  echo "443 SNI    : $SNI_443"
  echo "WS Host    : $WS_HOST"
  echo
  read -rp "Enter domain for port 443 [$DOMAIN_443]: " v; DOMAIN_443="${v:-$DOMAIN_443}"
  read -rp "Enter domain for port 8880 [$DOMAIN_WS]: " v; DOMAIN_WS="${v:-$DOMAIN_WS}"
  read -rp "Enter SNI for port 443 [$SNI_443]: " v; SNI_443="${v:-$SNI_443}"
  read -rp "Enter WebSocket Host [$WS_HOST]: " v; WS_HOST="${v:-$WS_HOST}"
  valid_domain "$DOMAIN_443" || die "Invalid 443 domain."
  valid_domain "$DOMAIN_WS" || die "Invalid 8880 domain."
  valid_domain "$SNI_443" || die "Invalid SNI."
  [[ "$DOMAIN_443" != "$DOMAIN_WS" ]] || die "Use two different domains for SNI routing on 443."
  save_config; stop_conflicts; configure_tls; configure_xray; configure_ssh_ws; configure_haproxy; restart_services; check_services
  ok "Settings applied."; read -rp "Press Enter..."
}

initial_setup(){
  clear; echo "========== INITIAL SETUP =========="
  read -rp "Enter domain for port 443: " DOMAIN_443
  read -rp "Enter domain for port 8880: " DOMAIN_WS
  read -rp "Enter SNI for port 443 [$DOMAIN_443]: " SNI_443; SNI_443="${SNI_443:-$DOMAIN_443}"
  read -rp "Enter WebSocket Host for port 8880 [$DOMAIN_WS]: " WS_HOST; WS_HOST="${WS_HOST:-$DOMAIN_WS}"
  valid_domain "$DOMAIN_443" || die "Invalid 443 domain."
  valid_domain "$DOMAIN_WS" || die "Invalid 8880 domain."
  valid_domain "$SNI_443" || die "Invalid SNI."
  valid_domain "$WS_HOST" || die "Invalid WebSocket Host."
  [[ "$DOMAIN_443" != "$DOMAIN_WS" ]] || die "Use two different domains for SNI routing on 443."
  generate_uuid; save_config
  stop_conflicts; install_packages; install_xray; configure_tls; configure_xray; configure_ssh_ws; configure_haproxy; restart_services; check_services
  ok "Installation completed."
  echo "Run: $MENU"
}

uninstall_all(){
  clear; warn "This removes the services/configuration created by this installer."
  read -rp "Type REMOVE to continue: " confirm; [[ "$confirm" == REMOVE ]] || return
  systemctl disable --now haproxy stunnel4 ssh-ws xray >/dev/null 2>&1 || true
  rm -f "$HAPROXY_CFG" "$SSH_WS_APP" "$SSH_WS_UNIT" "$XRAY_CONFIG" "$CONFIG"
  rm -rf "$TLS_DIR"
  systemctl daemon-reload
  ok "Removed installer configuration."
  exit 0
}

menu(){
  while true; do
    load_config; clear
    echo "================================================"
    echo "             VPN CONFIG MANAGER"
    echo "================================================"
    echo "443 Domain  : ${DOMAIN_443:-Not set}"
    echo "8880 Domain : ${DOMAIN_WS:-Not set}"
    echo "SNI         : ${SNI_443:-Not set}"
    echo "WS Host     : ${WS_HOST:-Not set}"
    echo "VLESS Path  : /vless-ws"
    echo "SSH WS Path : $WS_PATH"
    echo "------------------------------------------------"
    echo "[1] Create SSH account"
    echo "[2] Delete SSH account"
    echo "[3] List SSH accounts"
    echo "[4] Show VLESS/SSH settings"
    echo "[5] Service status"
    echo "[6] Test configuration"
    echo "[7] Change domains / SNI / Host"
    echo "[8] Restart services"
    echo "[9] Uninstall"
    echo "[0] Exit"
    echo "================================================"
    read -rp "Choice: " choice
    case "$choice" in
      1) create_account;; 2) delete_account;; 3) list_accounts;; 4) show_settings;;
      5) status;; 6) test_config;; 7) change_settings;;
      8) restart_services; check_services; sleep 1;; 9) uninstall_all;; 0) exit 0;;
      *) warn "Invalid choice."; sleep 1;;
    esac
  done
}

main(){
  require_root; detect_os
  if [[ ! -f "$CONFIG" ]]; then initial_setup; fi
  cp -f "$0" "$MENU" 2>/dev/null || true
  chmod +x "$MENU" 2>/dev/null || true
  menu
}
main "$@"
