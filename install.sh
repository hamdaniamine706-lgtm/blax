#!/usr/bin/env bash
# ============================================================
# Xray + SSH/TLS + VLESS/WS installer
# Designed for Debian/Ubuntu-like systems.
# NOTE: Use only on a server you own/control.
# ============================================================

set -Eeuo pipefail

CONFIG="/etc/vpn_script.conf"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
NGINX_SITE="/etc/nginx/sites-available/vpn-xray"
SSH_TLS_DIR="/etc/vpn-tls"
SSH_TLS_CERT="$SSH_TLS_DIR/server.pem"
SSH_TLS_PORT=8443
VLESS_PORT=10001
WS_PORT=8880
MENU="/usr/local/bin/vpn-menu"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

die(){ echo -e "${RED}[X] $*${NC}" >&2; exit 1; }
ok(){ echo -e "${GREEN}[✓] $*${NC}"; }
warn(){ echo -e "${YELLOW}[!] $*${NC}"; }
info(){ echo -e "${CYAN}[*] $*${NC}"; }

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run this installer as root."
}

detect_os() {
  [[ -r /etc/os-release ]] || die "Cannot detect operating system."
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) ;;
    *) die "Supported systems: Ubuntu/Debian. Detected: ${ID:-unknown}" ;;
  esac
}

save_config() {
  umask 077
  cat > "$CONFIG" <<EOF
SERVER_DOMAIN="${SERVER_DOMAIN}"
SNI="${SNI}"
WS_HOST="${WS_HOST}"
WS_PATH="${WS_PATH}"
USER_UUID="${USER_UUID}"
EOF
}

load_config() {
  [[ -f "$CONFIG" ]] && . "$CONFIG"
}

valid_domain_or_name() {
  [[ "$1" =~ ^[A-Za-z0-9.-]+$ ]]
}

valid_path() {
  [[ "$1" == /* ]] && [[ "$1" != *[[:space:]]* ]]
}

install_packages() {
  info "Installing required packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nginx openssl curl ca-certificates jq lsof psmisc python3
}

install_xray() {
  if command -v xray >/dev/null 2>&1; then
    ok "Xray already installed: $(xray version 2>/dev/null | head -n1 || true)"
    return
  fi

  info "Installing Xray..."
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
}

stop_conflicting_services() {
  info "Checking ports..."
  for p in 443 8880 10001 10002 "$SSH_TLS_PORT"; do
    fuser -k "${p}/tcp" >/dev/null 2>&1 || true
  done
}

generate_uuid() {
  if [[ -z "${USER_UUID:-}" ]]; then
    USER_UUID="$(cat /proc/sys/kernel/random/uuid)"
  fi
}

configure_tls() {
  mkdir -p "$SSH_TLS_DIR"
  chmod 700 "$SSH_TLS_DIR"

  # Self-signed certificate is suitable for lab/testing only.
  # For production, replace it with a trusted certificate.
  if [[ ! -s "$SSH_TLS_CERT" ]]; then
    info "Creating a self-signed TLS certificate for testing..."
    openssl req -new -newkey rsa:2048 -nodes -x509 -days 3650 \
      -subj "/CN=${SERVER_DOMAIN}" \
      -keyout "$SSH_TLS_CERT" -out "$SSH_TLS_CERT" >/dev/null 2>&1
    chmod 600 "$SSH_TLS_CERT"
  fi

  cat > /etc/stunnel.conf <<EOF
foreground = yes
pid =
cert = ${SSH_TLS_CERT}

[ssh-tls]
accept = 0.0.0.0:${SSH_TLS_PORT}
connect = 127.0.0.1:22
EOF

  # stunnel is optional. If unavailable in the image, do not fail the
  # complete Xray installation.
  if apt-cache show stunnel4 >/dev/null 2>&1; then
    apt-get install -y stunnel4 >/dev/null 2>&1 || true
  fi

  if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 || true
  fi
}

configure_xray() {
  mkdir -p "$(dirname "$XRAY_CONFIG")"

  cat > "$XRAY_CONFIG" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": ${VLESS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${USER_UUID}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${WS_PATH}"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

  jq empty "$XRAY_CONFIG" || die "Generated Xray config is invalid."

  if command -v xray >/dev/null 2>&1; then
    xray run -test -config "$XRAY_CONFIG" >/tmp/xray-config-test.log 2>&1 \
      || { cat /tmp/xray-config-test.log; die "Xray configuration test failed."; }
  fi
}

configure_nginx() {
  cat > "$NGINX_SITE" <<EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${SERVER_DOMAIN};

    ssl_certificate ${SSH_TLS_CERT};
    ssl_certificate_key ${SSH_TLS_CERT};
    ssl_protocols TLSv1.2 TLSv1.3;

    location ${WS_PATH} {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_pass http://127.0.0.1:${VLESS_PORT};
    }

    location / {
        return 404;
    }
}
EOF

  rm -f /etc/nginx/sites-enabled/default
  ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/vpn-xray

  nginx -t || die "Nginx configuration test failed."
}

restart_services() {
  info "Starting/restarting services..."

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files >/dev/null 2>&1; then
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl restart nginx

    if systemctl list-unit-files | grep -q '^xray.service'; then
      systemctl enable xray >/dev/null 2>&1 || true
      systemctl restart xray
    else
      pkill -x xray >/dev/null 2>&1 || true
      nohup xray run -config "$XRAY_CONFIG" >/var/log/xray-manual.log 2>&1 &
    fi

    if command -v stunnel4 >/dev/null 2>&1; then
      systemctl restart stunnel4 >/dev/null 2>&1 || warn "stunnel4 could not be started."
    fi
  else
    pkill -x xray >/dev/null 2>&1 || true
    nohup xray run -config "$XRAY_CONFIG" >/var/log/xray-manual.log 2>&1 &
    nginx -s reload >/dev/null 2>&1 || nginx
  fi
}

create_account() {
  clear
  load_config
  echo "========== CREATE SSH ACCOUNT =========="
  read -rp "Username: " username
  read -rsp "Password: " password; echo
  read -rp "Expiration days [30]: " days
  days="${days:-30}"

  [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { warn "Invalid username."; read -r; return; }
  [[ "$days" =~ ^[0-9]+$ ]] || { warn "Days must be numeric."; read -r; return; }
  [[ -n "$password" ]] || { warn "Password cannot be empty."; read -r; return; }

  if id "$username" >/dev/null 2>&1; then
    warn "User already exists."
    read -r
    return
  fi

  local expire
  expire="$(date -d "+${days} days" +%Y-%m-%d)"
  useradd -e "$expire" -M -s /bin/bash "$username"
  echo "${username}:${password}" | chpasswd

  echo
  ok "Account created."
  echo "Username : $username"
  echo "Password : $password"
  echo "Expires  : $expire"
  echo
  echo "SSH TLS :443"
  echo "SNI     : $SNI"
  echo "SSH TLS direct backend :${SSH_TLS_PORT}"
  echo
  read -rp "Press Enter..."
}

delete_account() {
  clear
  read -rp "Username to delete: " username
  if id "$username" >/dev/null 2>&1; then
    userdel "$username"
    ok "Deleted: $username"
  else
    warn "User not found."
  fi
  read -rp "Press Enter..."
}

list_accounts() {
  clear
  echo "========== SSH ACCOUNTS =========="
  awk -F: '$3 >= 1000 {print $1}' /etc/passwd | while read -r u; do
    exp="$(chage -l "$u" 2>/dev/null | awk -F': ' '/Account expires/{print $2}')"
    printf '%-20s %s\n' "$u" "${exp:-unknown}"
  done
  echo
  read -rp "Press Enter..."
}

show_links() {
  clear
  load_config

  local link
  link="vless://${USER_UUID}@${SERVER_DOMAIN}:443?encryption=none&security=tls&sni=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$SNI")&type=ws&host=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$WS_HOST")&path=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$WS_PATH")#VLESS-${SERVER_DOMAIN}"

  echo "========== VLESS =========="
  echo "$link"
  echo
  echo "========== SSH TLS =========="
  echo "Server : ${SERVER_DOMAIN}"
  echo "Port   : 443"
  echo "SNI    : ${SNI}"
  echo
  echo "========== WebSocket =========="
  echo "Host   : ${WS_HOST}"
  echo "Port   : 443"
  echo "Path   : ${WS_PATH}"
  echo
  warn "The generated TLS certificate is self-signed. A normal client may reject it until you install a trusted certificate."
  echo
  read -rp "Press Enter..."
}

status() {
  clear
  echo "========== SERVICE STATUS =========="
  for svc in nginx xray stunnel4; do
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$svc" 2>/dev/null; then
      ok "$svc: ACTIVE"
    else
      warn "$svc: not active/managed"
    fi
  done
  echo
  echo "========== LISTENING PORTS =========="
  ss -lntp 2>/dev/null | grep -E ':(22|443|8443|8880|10001)\b' || true
  echo
  read -rp "Press Enter..."
}

test_config() {
  clear
  echo "========== CONFIG TEST =========="

  if nginx -t >/tmp/nginx-test.log 2>&1; then
    ok "Nginx configuration: OK"
  else
    warn "Nginx configuration: FAILED"
    cat /tmp/nginx-test.log
  fi

  if xray run -test -config "$XRAY_CONFIG" >/tmp/xray-test.log 2>&1; then
    ok "Xray configuration: OK"
  else
    warn "Xray configuration: FAILED"
    cat /tmp/xray-test.log
  fi

  echo
  echo "TLS certificate:"
  openssl x509 -in "$SSH_TLS_CERT" -noout -subject -dates 2>/dev/null || true

  echo
  echo "Listening:"
  ss -lntp 2>/dev/null | grep -E ':(22|443|8443|8880|10001)\b' || true
  echo
  read -rp "Press Enter..."
}

change_settings() {
  clear
  load_config

  echo "========== SETTINGS =========="
  echo "Current domain: $SERVER_DOMAIN"
  echo "Current SNI   : $SNI"
  echo "Current Host  : $WS_HOST"
  echo "Current Path  : $WS_PATH"
  echo

  read -rp "Server domain [$SERVER_DOMAIN]: " v
  SERVER_DOMAIN="${v:-$SERVER_DOMAIN}"
  valid_domain_or_name "$SERVER_DOMAIN" || { warn "Invalid domain."; read -r; return; }

  read -rp "SNI [$SNI]: " v
  SNI="${v:-$SNI}"
  valid_domain_or_name "$SNI" || { warn "Invalid SNI."; read -r; return; }

  read -rp "WebSocket Host [$WS_HOST]: " v
  WS_HOST="${v:-$WS_HOST}"
  valid_domain_or_name "$WS_HOST" || { warn "Invalid Host."; read -r; return; }

  read -rp "WebSocket Path [$WS_PATH]: " v
  WS_PATH="${v:-$WS_PATH}"
  valid_path "$WS_PATH" || { warn "Path must start with / and contain no spaces."; read -r; return; }

  save_config
  configure_xray
  configure_nginx
  restart_services
  ok "Settings applied."
  read -rp "Press Enter..."
}

initial_setup() {
  clear
  echo "========== INITIAL SETUP =========="
  read -rp "Server domain (DNS should point to this server): " SERVER_DOMAIN
  read -rp "SNI [$SERVER_DOMAIN]: " SNI
  SNI="${SNI:-$SERVER_DOMAIN}"
  read -rp "WebSocket Host [$SERVER_DOMAIN]: " WS_HOST
  WS_HOST="${WS_HOST:-$SERVER_DOMAIN}"
  read -rp "WebSocket Path [/vless-ws]: " WS_PATH
  WS_PATH="${WS_PATH:-/vless-ws}"

  valid_domain_or_name "$SERVER_DOMAIN" || die "Invalid server domain."
  valid_domain_or_name "$SNI" || die "Invalid SNI."
  valid_domain_or_name "$WS_HOST" || die "Invalid WebSocket Host."
  valid_path "$WS_PATH" || die "Invalid WebSocket path."

  generate_uuid
  save_config

  stop_conflicting_services
  install_packages
  install_xray
  configure_tls
  configure_xray
  configure_nginx
  restart_services

  ok "Installation completed."
  echo "Run: $MENU"
}

uninstall_all() {
  clear
  warn "This removes the Xray/Nginx configuration created by this installer."
  read -rp "Type REMOVE to continue: " confirm
  [[ "$confirm" == "REMOVE" ]] || return

  rm -f "$NGINX_SITE" /etc/nginx/sites-enabled/vpn-xray
  rm -f "$XRAY_CONFIG"
  rm -f "$CONFIG"
  pkill -x xray >/dev/null 2>&1 || true
  nginx -s reload >/dev/null 2>&1 || true
  ok "Removed installer configuration."
  exit 0
}

menu() {
  while true; do
    load_config
    clear
    echo "================================================"
    echo "             VPN CONFIG MANAGER"
    echo "================================================"
    echo "Domain : ${SERVER_DOMAIN:-Not set}"
    echo "SNI    : ${SNI:-Not set}"
    echo "Host   : ${WS_HOST:-Not set}"
    echo "Path   : ${WS_PATH:-Not set}"
    echo "------------------------------------------------"
    echo "[1] Create SSH account"
    echo "[2] Delete SSH account"
    echo "[3] List SSH accounts"
    echo "[4] Show VLESS/SSH settings"
    echo "[5] Service status"
    echo "[6] Test configuration"
    echo "[7] Change domain / SNI / Host / Path"
    echo "[8] Restart services"
    echo "[9] Uninstall"
    echo "[0] Exit"
    echo "================================================"
    read -rp "Choice: " choice

    case "$choice" in
      1) create_account ;;
      2) delete_account ;;
      3) list_accounts ;;
      4) show_links ;;
      5) status ;;
      6) test_config ;;
      7) change_settings ;;
      8) restart_services; ok "Services restarted."; sleep 2 ;;
      9) uninstall_all ;;
      0) exit 0 ;;
      *) warn "Invalid choice."; sleep 1 ;;
    esac
  done
}

main() {
  require_root
  detect_os

  if [[ ! -f "$CONFIG" ]]; then
    initial_setup
  fi

  # Install the menu itself for subsequent runs.
  cp -f "$0" "$MENU" 2>/dev/null || true
  chmod +x "$MENU" 2>/dev/null || true

  menu
}

main "$@"
