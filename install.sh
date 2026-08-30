#!/usr/bin/env bash
# ============================================================
# Xray + VLESS/WS + SSH/TLS + SSH WebSocket installer
# Ubuntu/Debian. Use only on a server you own/control.
#
# Layout:
#   DOMAIN_443:443  -> HAProxy TCP SNI -> Xray VLESS/WS
#                                      -> stunnel SSH/TLS
#   DOMAIN_WS:8880  -> SSH WebSocket -> 127.0.0.1:22
#
# The two domains must point to this server.
# ============================================================
set -Eeuo pipefail

CONFIG="/etc/vpn_script.conf"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_WS_PATH="/vless-ws"
SSH_TLS_DIR="/etc/vpn-tls"
SSH_TLS_CERT="$SSH_TLS_DIR/server.pem"
STUNNEL_PORT=8443
VLESS_PORT=10001
WS_PORT=8880
MENU="/usr/local/bin/vpn-menu"
SSH_WS_APP="/usr/local/sbin/ssh-ws-proxy.py"
SSH_WS_UNIT="/etc/systemd/system/ssh-ws.service"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
die(){ echo -e "${RED}[X] $*${NC}" >&2; exit 1; }
ok(){ echo -e "${GREEN}[✓] $*${NC}"; }
warn(){ echo -e "${YELLOW}[!] $*${NC}"; }
info(){ echo -e "${CYAN}[*] $*${NC}"; }

require_root(){ [[ "$EUID" -eq 0 ]] || die "Run this installer as root."; }
detect_os(){
  [[ -r /etc/os-release ]] || die "Cannot detect operating system."
  . /etc/os-release
  case "${ID:-}" in ubuntu|debian) ;; *) die "Supported systems: Ubuntu/Debian. Detected: ${ID:-unknown}";; esac
}
valid_domain(){ [[ "$1" =~ ^[A-Za-z0-9.-]+$ ]] && [[ "$1" != .* ]] && [[ "$1" != *..* ]]; }
valid_path(){ [[ "$1" == /* ]] && [[ "$1" != *[[:space:]]* ]]; }

save_config(){
  umask 077
  cat >"$CONFIG" <<EOF
DOMAIN_443="${DOMAIN_443}"
DOMAIN_WS="${DOMAIN_WS}"
SNI_443="${SNI_443}"
WS_HOST="${WS_HOST}"
WS_PATH="${WS_PATH}"
USER_UUID="${USER_UUID}"
EOF
}
load_config(){ [[ -f "$CONFIG" ]] && . "$CONFIG"; }

install_packages(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nginx haproxy stunnel4 openssl curl ca-certificates jq lsof psmisc python3 python3-websockets certbot
}

install_xray(){
  if command -v xray >/dev/null 2>&1; then
    ok "Xray already installed: $(xray version 2>/dev/null | head -n1 || true)"
  else
    info "Installing Xray..."
    bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
  fi
}

generate_uuid(){
  [[ -n "${USER_UUID:-}" ]] || USER_UUID="$(cat /proc/sys/kernel/random/uuid)"
}

configure_cert(){
  mkdir -p "$SSH_TLS_DIR"; chmod 700 "$SSH_TLS_DIR"
  # Fallback certificate for testing only. Replace with a trusted certificate
  # if your client verifies certificates.
  if [[ ! -s "$SSH_TLS_CERT" ]]; then
    openssl req -new -newkey rsa:2048 -nodes -x509 -days 3650 \
      -subj "/CN=${DOMAIN_443}" \
      -keyout "$SSH_TLS_CERT" -out "$SSH_TLS_CERT" >/dev/null 2>&1
    chmod 600 "$SSH_TLS_CERT"
  fi
}

configure_stunnel(){
  cat >/etc/stunnel.conf <<EOF
foreground = yes
pid =
cert = ${SSH_TLS_CERT}

[ssh-tls]
accept = 127.0.0.1:${STUNNEL_PORT}
connect = 127.0.0.1:22
EOF
  if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 || true
  fi
}

configure_xray(){
  mkdir -p "$(dirname "$XRAY_CONFIG")"
  cat >"$XRAY_CONFIG" <<EOF
{
  "log":{"loglevel":"warning"},
  "inbounds":[{
    "listen":"127.0.0.1",
    "port":${VLESS_PORT},
    "protocol":"vless",
    "settings":{
      "clients":[{"id":"${USER_UUID}"}],
      "decryption":"none"
    },
    "streamSettings":{
      "network":"ws",
      "wsSettings":{"path":"${WS_PATH}"}
    }
  }],
  "outbounds":[{"protocol":"freedom"}]
}
EOF
  jq empty "$XRAY_CONFIG" || die "Generated Xray config is invalid."
  xray run -test -config "$XRAY_CONFIG" >/tmp/xray-config-test.log 2>&1 ||
    { cat /tmp/xray-config-test.log; die "Xray configuration test failed."; }
}

configure_ssh_ws(){
  cat >"$SSH_WS_APP" <<'PY'
#!/usr/bin/env python3
import asyncio
import websockets

TARGET_HOST="127.0.0.1"
TARGET_PORT=22
LISTEN_HOST="0.0.0.0"
LISTEN_PORT=8880

async def proxy(ws):
    reader, writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
    async def ws_to_tcp():
        try:
            async for data in ws:
                if isinstance(data, str):
                    data = data.encode()
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await ws.send(data)
        finally:
            try: await ws.close()
            except Exception: pass
    await asyncio.gather(ws_to_tcp(), tcp_to_ws())

async def handler(ws):
    path = getattr(ws, "path", "/")
    if path != "/ssh":
        await ws.close(code=1008, reason="Invalid path")
        return
    try:
        await proxy(ws)
    except Exception:
        try: await ws.close()
        except Exception: pass

async def main():
    async with websockets.serve(handler, LISTEN_HOST, LISTEN_PORT,
                                ping_interval=20, ping_timeout=60,
                                max_size=None):
        print(f"SSH WebSocket listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
        await asyncio.Future()

asyncio.run(main())
PY
  chmod 700 "$SSH_WS_APP"

  cat >"$SSH_WS_UNIT" <<EOF
[Unit]
Description=SSH WebSocket bridge
After=network-online.target ssh.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${SSH_WS_APP}
Restart=always
RestartSec=2
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

configure_haproxy(){
  # HAProxy terminates no TLS here. It inspects SNI and sends the encrypted
  # connection to either Xray's local TLS endpoint or stunnel's local endpoint.
  # Xray itself must therefore receive TLS, so generate a local Xray TLS cert.
  # We use HAProxy TCP passthrough and both backends receive the original TLS.
  #
  # For VLESS/WS TLS, Xray must terminate TLS. For SSH-TLS, stunnel terminates it.
  # Each backend needs the same certificate; SNI selects the backend.
  mkdir -p /etc/haproxy/certs
  # Put a combined PEM in HAProxy only for parsing SNI; TCP mode does not need it.
  cat >"$HAPROXY_CFG" <<EOF
global
    log /dev/log local0
    log /dev/log local1 notice
    daemon
    maxconn 4096

defaults
    log global
    mode tcp
    timeout connect 10s
    timeout client  2m
    timeout server  2m

frontend tls_443
    bind 0.0.0.0:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }

    use_backend vless_tls if { req_ssl_sni -i ${DOMAIN_443} }
    use_backend ssh_tls if { req_ssl_sni -i ${DOMAIN_WS} }

    default_backend vless_tls

backend vless_tls
    mode tcp
    server xray 127.0.0.1:${VLESS_TLS_PORT:-10443} check

backend ssh_tls
    mode tcp
    server stunnel 127.0.0.1:${STUNNEL_PORT} check
EOF
}

# Xray TLS listener used behind HAProxy.
configure_xray_tls(){
  mkdir -p "$(dirname "$XRAY_CONFIG")"
  # Use the same certificate for both local TLS endpoints in this installer.
  # The certificate is self-signed unless replaced by the administrator.
  cat >"$XRAY_CONFIG" <<EOF
{
  "log":{"loglevel":"warning"},
  "inbounds":[{
    "listen":"127.0.0.1",
    "port":10443,
    "protocol":"vless",
    "settings":{
      "clients":[{"id":"${USER_UUID}"}],
      "decryption":"none"
    },
    "streamSettings":{
      "network":"ws",
      "security":"tls",
      "tlsSettings":{
        "serverName":"${DOMAIN_443}",
        "certificates":[{"certificateFile":"${SSH_TLS_CERT}","keyFile":"${SSH_TLS_CERT}"}]
      },
      "wsSettings":{"path":"${WS_PATH}"}
    }
  }],
  "outbounds":[{"protocol":"freedom"}]
}
EOF
  jq empty "$XRAY_CONFIG" || die "Generated Xray config is invalid."
  xray run -test -config "$XRAY_CONFIG" >/tmp/xray-config-test.log 2>&1 ||
    { cat /tmp/xray-config-test.log; die "Xray configuration test failed."; }
}

restart_services(){
  systemctl daemon-reload
  systemctl enable haproxy nginx xray stunnel4 ssh-ws >/dev/null 2>&1 || true
  # nginx is not needed on 443 in this layout; keep it installed but don't bind 443.
  systemctl stop nginx >/dev/null 2>&1 || true
  systemctl restart xray
  systemctl restart stunnel4 >/dev/null 2>&1 || warn "stunnel4 could not be started."
  systemctl restart ssh-ws
  systemctl restart haproxy
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
  if id "$username" >/dev/null 2>&1; then warn "User already exists."; read -r; return; fi
  local expire; expire="$(date -d "+${days} days" +%Y-%m-%d)"
  useradd -e "$expire" -M -s /bin/bash "$username"
  echo "${username}:${password}" | chpasswd
  echo
  ok "Account created."
  echo "Username : $username"
  echo "Password : $password"
  echo "Expires  : $expire"
  echo
  echo "SSH TLS : ${DOMAIN_WS}:443"
  echo "SSH WS  : ${DOMAIN_WS}:8880"
  echo "SSH WS path : /ssh"
  echo "SSH WS config : ${DOMAIN_WS}:8880@${username}:${password}"
  echo
  echo "VLESS : ${DOMAIN_443}:443"
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

show_links(){
  clear; load_config
  local enc_host enc_sni enc_path link
  enc_host="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$DOMAIN_443")"
  enc_sni="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$SNI_443")"
  enc_path="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$WS_PATH")"
  link="vless://${USER_UUID}@${DOMAIN_443}:443?encryption=none&security=tls&sni=${enc_sni}&type=ws&host=${enc_host}&path=${enc_path}#VLESS-${DOMAIN_443}"
  echo "========== VLESS =========="; echo "$link"; echo
  echo "========== SSH TLS =========="
  echo "Server : ${DOMAIN_WS}"; echo "Port   : 443"; echo "SNI    : ${DOMAIN_WS}"; echo
  echo "========== SSH WebSocket =========="
  echo "Server : ${DOMAIN_WS}"; echo "Port   : 8880"; echo "Path   : /ssh"
  echo "Format : ${DOMAIN_WS}:8880@USER:PASS"
  echo
  warn "The bundled certificates are self-signed for testing. For normal TLS clients, install trusted certificates for your domains."
  read -rp "Press Enter..."
}

status(){
  clear; echo "========== SERVICE STATUS =========="
  for svc in haproxy xray stunnel4 ssh-ws; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then ok "$svc: ACTIVE"; else warn "$svc: NOT ACTIVE"; fi
  done
  echo; echo "========== LISTENING PORTS =========="
  ss -lntp 2>/dev/null | grep -E ':(22|443|8880|8443|10443)\b' || true
  echo; read -rp "Press Enter..."
}

test_config(){
  clear; echo "========== CONFIG TEST =========="
  if haproxy -c -f "$HAPROXY_CFG" >/tmp/haproxy-test.log 2>&1; then ok "HAProxy configuration: OK"; else warn "HAProxy configuration: FAILED"; cat /tmp/haproxy-test.log; fi
  if xray run -test -config "$XRAY_CONFIG" >/tmp/xray-test.log 2>&1; then ok "Xray configuration: OK"; else warn "Xray configuration: FAILED"; cat /tmp/xray-test.log; fi
  if systemctl is-active --quiet ssh-ws; then ok "SSH WebSocket service: OK"; else warn "SSH WebSocket service: FAILED"; journalctl -u ssh-ws -n 20 --no-pager; fi
  echo; ss -lntp 2>/dev/null | grep -E ':(22|443|8880|8443|10443)\b' || true
  read -rp "Press Enter..."
}

change_settings(){
  clear; load_config
  echo "========== SETTINGS =========="
  echo "443 domain : ${DOMAIN_443:-Not set}"
  echo "8880 domain: ${DOMAIN_WS:-Not set}"
  echo "443 SNI    : ${SNI_443:-Not set}"
  echo "WS Host    : ${WS_HOST:-Not set}"
  echo "WS Path    : ${WS_PATH:-Not set}"; echo
  read -rp "Domain for port 443 [${DOMAIN_443}]: " v; DOMAIN_443="${v:-$DOMAIN_443}"
  read -rp "Domain for port 8880 [${DOMAIN_WS}]: " v; DOMAIN_WS="${v:-$DOMAIN_WS}"
  read -rp "SNI for port 443 [${SNI_443}]: " v; SNI_443="${v:-$SNI_443}"
  read -rp "WebSocket Host [${WS_HOST}]: " v; WS_HOST="${v:-$WS_HOST}"
  read -rp "WebSocket Path [${WS_PATH}]: " v; WS_PATH="${v:-$WS_PATH}"
  valid_domain "$DOMAIN_443" || die "Invalid 443 domain."
  valid_domain "$DOMAIN_WS" || die "Invalid 8880 domain."
  valid_domain "$SNI_443" || die "Invalid SNI."
  valid_domain "$WS_HOST" || die "Invalid WS Host."
  valid_path "$WS_PATH" || die "Invalid WS Path."
  save_config
  configure_cert; configure_stunnel; configure_xray_tls; configure_ssh_ws; configure_haproxy; restart_services
  ok "Settings applied."; read -rp "Press Enter..."
}

initial_setup(){
  clear; echo "========== INITIAL SETUP =========="
  read -rp "Enter domain for port 443: " DOMAIN_443
  read -rp "Enter domain for port 8880: " DOMAIN_WS
  read -rp "Enter SNI for port 443 [${DOMAIN_443}]: " SNI_443; SNI_443="${SNI_443:-$DOMAIN_443}"
  read -rp "Enter WebSocket Host for port 8880 [${DOMAIN_WS}]: " WS_HOST; WS_HOST="${WS_HOST:-$DOMAIN_WS}"
  read -rp "Enter WebSocket Path [/ssh]: " SSH_PATH; SSH_PATH="${SSH_PATH:-/ssh}"
  WS_PATH="/vless-ws"
  valid_domain "$DOMAIN_443" || die "Invalid 443 domain."
  valid_domain "$DOMAIN_WS" || die "Invalid 8880 domain."
  valid_domain "$SNI_443" || die "Invalid SNI."
  valid_domain "$WS_HOST" || die "Invalid WS Host."
  valid_path "$SSH_PATH" || die "Invalid SSH WS Path."
  generate_uuid; save_config
  install_packages; install_xray; configure_cert; configure_stunnel
  # Use /ssh fixed in the websocket bridge.
  configure_ssh_ws; configure_xray_tls; configure_haproxy
  # nginx is installed as a dependency but deliberately stopped because HAProxy owns 443.
  systemctl disable nginx >/dev/null 2>&1 || true
  restart_services
  ok "Installation completed."
  echo "Run: $MENU"
}

uninstall_all(){
  clear; warn "This removes the configuration created by this installer."
  read -rp "Type REMOVE to continue: " confirm; [[ "$confirm" == REMOVE ]] || return
  systemctl disable --now haproxy stunnel4 ssh-ws xray >/dev/null 2>&1 || true
  rm -f "$HAPROXY_CFG" "$SSH_WS_APP" "$SSH_WS_UNIT" "$XRAY_CONFIG" "$CONFIG"
  ok "Installer configuration removed."; exit 0
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
    echo "VLESS Path  : ${WS_PATH:-Not set}"
    echo "SSH WS Path : /ssh"
    echo "------------------------------------------------"
    echo "[1] Create SSH account"
    echo "[2] Delete SSH account"
    echo "[3] List SSH accounts"
    echo "[4] Show VLESS/SSH settings"
    echo "[5] Service status"
    echo "[6] Test configuration"
    echo "[7] Change domains / SNI / Host / Path"
    echo "[8] Restart services"
    echo "[9] Uninstall"
    echo "[0] Exit"
    echo "================================================"
    read -rp "Choice: " choice
    case "$choice" in
      1) create_account ;; 2) delete_account ;; 3) list_accounts ;; 4) show_links ;;
      5) status ;; 6) test_config ;; 7) change_settings ;;
      8) restart_services; ok "Services restarted."; sleep 2 ;;
      9) uninstall_all ;; 0) exit 0 ;; *) warn "Invalid choice."; sleep 1 ;;
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
