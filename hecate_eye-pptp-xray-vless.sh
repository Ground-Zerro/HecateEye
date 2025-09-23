#!/bin/bash

if [ -z "${BASH_VERSION:-}" ]; then exec /usr/bin/env bash "$0" "$@"; fi
set -u -o pipefail

# ------------------------- Config ----------------------------
VPN_USER="vpnuser"
VPN_PASS=""
VPN_LOCAL_IP="10.20.30.1"
VPN_REMOTE_IP_RANGE="10.20.30.40-200"
XRAY_TPROXY_PORT=12345
XRAY_CONF_PATH="/usr/local/etc/xray/config.json"
INSTALL_LOG="/tmp/xray-install.log"
SYSTEMD_SERVICE_PATH="/etc/systemd/system/tproxy-restore.service"
TPROXY_SCRIPT_PATH="/usr/local/bin/tproxy-restore.sh"
SYSCTL_CONF="/etc/sysctl.d/99-tproxy.conf"
MODULES_CONF="/etc/modules-load.d/tproxy.conf"

declare -a WARNINGS=()

# ----------------------- Utils --------------------------------
log()  { printf "[*] %s\n" "$*"; }
ok()   { printf "    ✅ %s\n" "$*"; }
warn() { printf "    ⚠️  %s\n" "$*"; WARNINGS+=("$*"); }
err()  { printf "[!] %s\n" "$*" >&2; }
die()  { err "$1"; exit "${2:-1}"; }
need_root() { if [[ ${EUID:-0} -ne 0 ]]; then die "Run as root"; fi; }
rand_pw() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12; }

show_spinner() {
  local pid=$1
  local message="$2"
  local spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  
  printf "%s " "$message"
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r%s %s" "$message" "${spinner[i]}"
    i=$(((i + 1) % ${#spinner[@]}))
    sleep 0.1
  done
  printf "\r%s ✅\n" "$message"
}

run_with_animation() {
  local message="$1"
  shift

  "$@" >/dev/null 2>&1 &
  local pid=$!

  show_spinner $pid "$message"

  wait $pid
  return $?
}

url_decode() {
  local input="$1"

  input="${input//%2F//}"
  input="${input//%3A/:}"
  input="${input//%3D/=}"
  input="${input//%26/&}"
  input="${input//%3F/?}"
  input="${input//%23/#}"
  input="${input//%20/ }"
  input="${input//%21/!}"
  input="${input//%22/\"}"
  input="${input//%25/%}"
  echo "$input"
}

base64_urlsafe_decode() {
  python3 - <<'PY'
import sys, base64
s=sys.stdin.read().strip()
pad = '=' * (-len(s) % 4)
print(base64.urlsafe_b64decode((s+pad).encode()).decode('utf-8','ignore'))
PY
}

json_pp() { jq -cM .; }

# -------------------- URI Validation -------------------------
validate_uri() {
  local uri="$1" scheme
  [[ -z "$uri" ]] && { err "URI is empty"; return 1; }
  
  scheme="${uri%%://*}"
  case "$scheme" in
    vless) ;;
    *) err "Unsupported scheme: $scheme. Only vless is supported."; return 1 ;;
  esac

  if [[ ! "$uri" =~ ^[a-z]+://[^[:space:]]+$ ]]; then
    err "Invalid URI format"
    return 1
  fi

  local test_result
  test_result="$(make_outbound_from_uri "$uri" 2>/dev/null)" || { 
    err "URI parsing failed - invalid format or missing parameters"
    return 1
  }

  if ! echo "$test_result" | jq empty >/dev/null 2>&1; then
    err "URI parsing produced invalid JSON"
    return 1
  fi

  if [[ "$uri" == *"#"* ]]; then
    local raw_tag="${uri##*#}"
    local decoded_tag="$(echo -n "$raw_tag" | url_decode 2>/dev/null || echo "$raw_tag")"
    log "Extracted tag: '$decoded_tag'"
  else
    log "No tag found in URI, using default: 'upstream'"
  fi
  
  ok "URI validation successful"
  return 0
}

# -------------------- Outbound builder -----------------------
make_outbound_from_uri() {
  local uri="$1" scheme
  scheme="${uri%%://*}"
  case "$scheme" in
    vless) _build_vless_out "$uri" ;;
    *) err "Unknown scheme: $scheme"; return 2 ;;
  esac
}

# ----------------------- VLESS --------------------------------
_build_vless_out() {
  local uri rest userhost q addr port uuid enc security type host path sni flow alpn sid pbk spx fp stream user_json tag
  uri="${1:-}"

  if [[ "$uri" == *"#"* ]]; then
    tag="${uri##*#}"
    tag="$(url_decode "$tag")"

    uri="${uri%%#*}"
  else
    tag="upstream"
  fi
  
  rest="${uri#vless://}"
  q="${rest#*?}"
  userhost="${rest%%\?*}"
  uuid="${userhost%@*}"; uuid="${uuid:-}"
  addr="${userhost#*@}"; addr="${addr%:*}"
  port="${userhost##*:}"; port="${port%%\?*}"

  enc=""; security=""; type=""; host=""; path=""; sni=""; flow=""; alpn=""; sid=""; pbk=""; spx=""; fp=""

  IFS='&' read -ra PARAMS <<< "$q"
  for param in "${PARAMS[@]}"; do
    case "$param" in
      encryption=*) enc="$(url_decode "${param#*=}")" ;;
      security=*) security="$(url_decode "${param#*=}")" ;;
      type=*) type="$(url_decode "${param#*=}")" ;;
      host=*) host="$(url_decode "${param#*=}")" ;;
      path=*) path="$(url_decode "${param#*=}")" ;;
      sni=*) sni="$(url_decode "${param#*=}")" ;;
      flow=*) flow="$(url_decode "${param#*=}")" ;;
      alpn=*) alpn="$(url_decode "${param#*=}")" ;;
      sid=*) sid="$(url_decode "${param#*=}")" ;;
      pbk=*) pbk="$(url_decode "${param#*=}")" ;;
      spx=*) spx="$(url_decode "${param#*=}")" ;;
      fp=*) fp="$(url_decode "${param#*=}")" ;;
    esac
  done

  [[ -z "$enc" ]] && enc="none"
  [[ -z "$type" ]] && type="tcp"
  [[ -z "$fp" ]] && fp="chrome"

  case "$type" in
    ws) stream="$(jq -n --arg path "$path" --arg host "$host" '{network:"ws",wsSettings:{path:$path,headers:( $host|length>0 ? {Host:$host} : null )}}')" ;;
    grpc) stream="$(jq -n '{network:"grpc",grpcSettings:{}}')" ;;
    *) stream="$(jq -n '{network:"tcp"}')" ;;
  esac

  if [[ "$security" == "tls" ]]; then
    stream="$(echo "$stream" | jq --arg sni "$sni" --arg alpn "$alpn" '.security="tls" | .tlsSettings={allowInsecure:false} | (if $sni!="" then .tlsSettings.serverName=$sni else . end) | (if $alpn!="" then .tlsSettings.alpn=($alpn|split(",")) else . end)')"
  elif [[ "$security" == "reality" ]]; then
    if [[ -z "$pbk" || -z "$sni" ]]; then warn "VLESS/reality usually needs pbk and sni"; fi

    stream="$(echo "$stream" | jq --arg sni "$sni" --arg pbk "$pbk" --arg sid "$sid" --arg spx "$spx" --arg fp "$fp" '
      .security="reality" | 
      .realitySettings = {
        show: false
      } |
      (.realitySettings += if $pbk != "" then {publicKey: $pbk} else {} end) |
      (.realitySettings += if $sni != "" then {serverName: $sni} else {} end) |
      (.realitySettings += if $sid != "" then {shortId: $sid} else {} end) |
      (.realitySettings += if $spx != "" then {spiderX: $spx} else {} end) |
      (.realitySettings += if $fp != "" then {fingerprint: $fp} else {} end)
    ')"
  fi

  stream="$(echo "$stream" | jq '.sockopt={mark:0,tcpFastOpen:true}')"

  user_json="$(jq -n --arg id "$uuid" --arg enc "$enc" --arg flow "$flow" '
    {id: $id, encryption: $enc} + 
    (if $flow != "" then {flow: $flow} else {} end)
  ')"

  jq -n --arg tag "$tag" --arg addr "$addr" --arg port "$port" --argjson user "$user_json" --argjson stream "$stream" '{
    tag: $tag,
    protocol: "vless",
    settings: { 
      vnext: [{ 
        address: $addr, 
        port: ($port|tonumber), 
        users: [$user] 
      }] 
    },
    streamSettings: $stream
  }'
}

resolve_domain_to_ipv4() {
  local domain="$1"

  dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || true
}

# ----------------------- Create systemd service for persistence --------------------------
create_tproxy_restore_service() {
  log "Creating TPROXY restore service for persistence after reboot..."

  cat > "$TPROXY_SCRIPT_PATH" <<'EOF'
#!/bin/bash

set -e

XRAY_TPROXY_PORT=12345
VPN_LOCAL_IP="10.20.30.1"
UPSTREAM_URI_FILE="/usr/local/etc/xray/upstream_uri"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | logger -t tproxy-restore; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | logger -t tproxy-restore -p user.err; }

log "Starting TPROXY restoration..."

log "Loading required kernel modules..."
modprobe xt_TPROXY 2>/dev/null || { log_error "Failed to load xt_TPROXY module"; exit 1; }
modprobe nf_tproxy_core 2>/dev/null || true  # This module may not exist in newer kernels
modprobe xt_socket 2>/dev/null || { log_error "Failed to load xt_socket module"; exit 1; }
modprobe xt_owner 2>/dev/null || { log_error "Failed to load xt_owner module"; exit 1; }
modprobe iptable_mangle 2>/dev/null || true

log "Applying sysctl settings..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || { log_error "Failed to set ip_forward"; exit 1; }
sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || { log_error "Failed to set route_localnet"; exit 1; }
for p in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$p" 2>/dev/null || true; done

if ! iptables -t mangle -C PREROUTING -i ppp+ -j XRAY_ALL 2>/dev/null; then
  log "TPROXY iptables rules not found, they should be persistent via iptables-persistent"

fi

log "Setting up policy routing..."
if ! grep -q '^100[[:space:]]\+tproxy$' /etc/iproute2/rt_tables 2>/dev/null; then
  echo "100 tproxy" >> /etc/iproute2/rt_tables
fi

ip -4 rule del fwmark 0x1 lookup tproxy 2>/dev/null || true
ip -4 route flush table tproxy 2>/dev/null || true

ip -4 rule add fwmark 0x1 lookup tproxy 2>/dev/null || { log_error "Failed to add fwmark rule"; exit 1; }
ip -4 route add local 0.0.0.0/0 dev lo table tproxy 2>/dev/null || { log_error "Failed to add tproxy route"; exit 1; }

log "TPROXY restoration completed successfully"
EOF

  chmod +x "$TPROXY_SCRIPT_PATH" || die "Failed to make TPROXY script executable"

  cat > "$SYSTEMD_SERVICE_PATH" <<EOF
[Unit]
Description=TPROXY Settings Restoration for PPTP+XRay
After=network.target
Before=pptpd.service xray.service
Wants=network.target

[Service]
Type=oneshot
ExecStart=$TPROXY_SCRIPT_PATH
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  log "Creating persistent sysctl configuration..."
  cat > "$SYSCTL_CONF" <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF

  log "Creating persistent kernel modules configuration..."
  cat > "$MODULES_CONF" <<EOF
xt_TPROXY
xt_socket
xt_owner
iptable_mangle
EOF

  if ! run_with_animation "    Reloading systemd daemon..." systemctl daemon-reload; then
    warn "Failed to reload systemd daemon"
  fi
  
  if ! run_with_animation "    Enabling TPROXY restore service..." systemctl enable tproxy-restore.service; then
    warn "Failed to enable TPROXY restore service"
  fi

  if ! run_with_animation "    Testing TPROXY restore service..." systemctl start tproxy-restore.service; then
    warn "TPROXY restore service failed to start"
  else
    ok "TPROXY restore service created and tested successfully"
  fi

  if [[ -n "${UPSTREAM_URI:-}" ]]; then
    echo "$UPSTREAM_URI" > "/usr/local/etc/xray/upstream_uri" || warn "Failed to save upstream URI"
    chmod 600 "/usr/local/etc/xray/upstream_uri" 2>/dev/null || true
  fi
}

# ----------------------- Kernel & FW --------------------------
setup_kernel_and_fw() {
  log "Applying sysctl..."
  sysctl -w net.ipv4.ip_forward=1 2>/dev/null || warn "Failed to set ip_forward"
  sysctl -w net.ipv4.conf.all.route_localnet=1 2>/dev/null || warn "Failed to set route_localnet"
  for p in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$p" 2>/dev/null || true; done

  log "Checking iptables backend..."
  if iptables --version 2>/dev/null | grep -q "nf_tables"; then
    log "Detected nf_tables backend, switching to iptables-legacy for TPROXY compatibility..."
    if command -v update-alternatives >/dev/null 2>&1; then
      update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null 2>&1 || warn "Failed to switch to iptables-legacy"
      update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy >/dev/null 2>&1 || warn "Failed to switch to ip6tables-legacy"

      if iptables --version 2>/dev/null | grep -q "legacy"; then
        ok "Successfully switched to iptables-legacy"
      else
        warn "iptables-legacy switch may not have worked properly"
      fi
    else
      warn "update-alternatives not available, cannot switch to legacy iptables"
    fi
  else
    ok "Using legacy iptables backend"
  fi

  log "Loading kernel modules..."
  modprobe xt_TPROXY 2>/dev/null || warn "Failed to load xt_TPROXY module"
  modprobe nf_tproxy_core 2>/dev/null || true  # This module may not exist in newer kernels
  modprobe xt_socket 2>/dev/null || warn "Failed to load xt_socket module"
  modprobe xt_owner 2>/dev/null || warn "Failed to load xt_owner module"
  modprobe iptable_mangle 2>/dev/null || true

  log "Cleaning existing iptables rules..."
  iptables -t mangle -D PREROUTING -i ppp+ -j XRAY_ALL 2>/dev/null || true
  iptables -t mangle -F XRAY_ALL 2>/dev/null || true
  iptables -t mangle -X XRAY_ALL 2>/dev/null || true

  local XRAY_SERVER_HOST
  XRAY_SERVER_HOST=$(echo "$UPSTREAM_URI" | grep -oE '@[^:/?#]+' | tr -d '@' | head -1 || true)
  local SERVER_IPS=""
  
  if [[ -n "$XRAY_SERVER_HOST" ]]; then

    if [[ "$XRAY_SERVER_HOST" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      SERVER_IPS="$XRAY_SERVER_HOST"
      log "XRay server IP: $XRAY_SERVER_HOST (already an IP)"
    else

      log "Resolving XRay server domain '$XRAY_SERVER_HOST' to IPv4 A records only..."
      SERVER_IPS=$(resolve_domain_to_ipv4 "$XRAY_SERVER_HOST")
      if [[ -n "$SERVER_IPS" ]]; then
        log "Resolved XRay server IPv4 addresses:"
        for ip in $SERVER_IPS; do
          log "  - $ip"
        done
      else
        warn "Failed to resolve XRay server domain to IPv4 addresses"
      fi
    fi
  fi

  log "Setting up TPROXY routing for TCP and UDP traffic..."

  if ! iptables -t mangle -N XRAY_ALL 2>/dev/null; then
    warn "XRAY_ALL chain already exists or failed to create"
  fi

  log "Adding bypass rules..."
  iptables -t mangle -A XRAY_ALL -d 127.0.0.0/8 -j RETURN || warn "Failed to add localhost bypass rule"
  iptables -t mangle -A XRAY_ALL -d 10.20.30.0/24 -j RETURN || warn "Failed to add VPN network bypass rule"
  iptables -t mangle -A XRAY_ALL -d 169.254.0.0/16 -j RETURN || warn "Failed to add link-local bypass rule"
  iptables -t mangle -A XRAY_ALL -d 224.0.0.0/4 -j RETURN || warn "Failed to add multicast bypass rule"

  if [[ -n "$SERVER_IPS" ]]; then
    for ip in $SERVER_IPS; do
      if iptables -t mangle -A XRAY_ALL -d "$ip" -j RETURN; then
        log "Added bypass rule for XRay server IP: $ip"
      else
        warn "Failed to add bypass rule for XRay server IP: $ip"
      fi
    done
  fi

  log "Testing TPROXY support..."
  local test_rule_comment="TPROXY_TEST_$(date +%s%N | tail -c 6)"
  local tcp_test_passed=0
  local udp_test_passed=0

  log "Testing TCP TPROXY support..."
  if iptables -t mangle -A PREROUTING -p tcp -m tcp -m comment --comment "${test_rule_comment}_TCP" -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 0x1/0x1; then
    ok "TCP TPROXY test successful"
    tcp_test_passed=1

    iptables -t mangle -D PREROUTING -p tcp -m tcp -m comment --comment "${test_rule_comment}_TCP" -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 0x1/0x1 2>/dev/null || true
  else
    err "TCP TPROXY test failed"

    iptables -t mangle -D PREROUTING -p tcp -m tcp -m comment --comment "${test_rule_comment}_TCP" -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 0x1/0x1 2>/dev/null || true
  fi

  log "Testing UDP TPROXY support..."
  if iptables -t mangle -A PREROUTING -p udp -m udp -m comment --comment "${test_rule_comment}_UDP" -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 0x1/0x1; then
    ok "UDP TPROXY test successful"
    udp_test_passed=1

    iptables -t mangle -D PREROUTING -p udp -m udp -m comment --comment "${test_rule_comment}_UDP" -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 0x1/0x1 2>/dev/null || true
  else
    err "UDP TPROXY test failed"

    iptables -t mangle -D PREROUTING -p udp -m udp -m comment --comment "${test_rule_comment}_UDP" -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 0x1/0x1 2>/dev/null || true
  fi

  if [[ $tcp_test_passed -eq 1 && $udp_test_passed -eq 1 ]]; then
    ok "TPROXY support confirmed for both TCP and UDP"
  else
    err "TPROXY support incomplete:"
    [[ $tcp_test_passed -eq 0 ]] && err "  - TCP TPROXY not supported"
    [[ $udp_test_passed -eq 0 ]] && err "  - UDP TPROXY not supported"
    die "TPROXY is not fully supported on this system. Please check kernel modules and iptables version."
  fi

  if iptables -t mangle -A PREROUTING -i ppp+ -j XRAY_ALL; then
    ok "TPROXY chain attached to PREROUTING"
  else
    err "Failed to attach TPROXY chain to PREROUTING"
    die "TPROXY chain attachment failed"
  fi

  log "Adding TCP TPROXY rule to attached chain..."
  if iptables -t mangle -A XRAY_ALL -p tcp -m tcp -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 0x1/0x1; then
    ok "TCP TPROXY rule added successfully"
  else
    err "Failed to add TCP TPROXY rule to attached chain"
    die "TCP TPROXY configuration failed"
  fi
  
  log "Adding UDP TPROXY rule to attached chain..."
  if iptables -t mangle -A XRAY_ALL -p udp -m udp -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 0x1/0x1; then
    ok "UDP TPROXY rule added successfully"
  else
    err "Failed to add UDP TPROXY rule to attached chain"
    die "UDP TPROXY configuration failed"
  fi

  if ! grep -q '^100[[:space:]]\+tproxy$' /etc/iproute2/rt_tables 2>/dev/null; then
    echo "100 tproxy" >> /etc/iproute2/rt_tables || warn "Couldn't add tproxy to rt_tables"
  fi

  ip -4 rule del fwmark 0x1 lookup tproxy 2>/dev/null || true
  ip -4 route flush table tproxy 2>/dev/null || true

  ip -4 rule add fwmark 0x1 lookup tproxy 2>/dev/null || warn "Failed to add fwmark rule"
  ip -4 route add local 0.0.0.0/0 dev lo table tproxy 2>/dev/null || warn "Failed to add tproxy route"

  local WAN_IFACE
  WAN_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}' || echo "eth0")
  log "WAN_IFACE: ${WAN_IFACE:-<unknown>}"

  iptables -D FORWARD -i ppp+ -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WAN_IFACE" -o ppp+ -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i ppp+ -o ppp+ -j ACCEPT 2>/dev/null || true

  iptables -I FORWARD -i ppp+ -o "$WAN_IFACE" -j ACCEPT
  iptables -I FORWARD -i "$WAN_IFACE" -o ppp+ -j ACCEPT  
  iptables -I FORWARD -i ppp+ -o ppp+ -j ACCEPT

  iptables -t nat -C POSTROUTING -s 10.20.30.0/24 -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.20.30.0/24 -o "$WAN_IFACE" -j MASQUERADE

  if command -v netfilter-persistent >/dev/null 2>&1; then
    if ! run_with_animation "    Saving iptables rules..." netfilter-persistent save; then
      warn "netfilter-persistent save failed"
    fi
  fi
}

# ----------------------- Install packages ---------------------
install_packages() {
  UBUNTU_VER=$(lsb_release -rs | cut -d'.' -f1,2)
  export DEBIAN_FRONTEND=noninteractive
  log "Installing required packages..."

  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections >/dev/null 2>&1
  echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections >/dev/null 2>&1

  if ! run_with_animation "    Updating package list..." apt-get update -y; then
    die "apt-get update failed"
  fi

  log "Installing pptpd..."
  if dpkg --compare-versions "$UBUNTU_VER" gt "22.04"; then
    log "    Detected Ubuntu $UBUNTU_VER – manual installation: libssl1.1, ppp, bcrelay, pptpd."

    if ! run_with_animation "    Downloading libssl1.1..." wget -O /tmp/libssl1.1.deb "http://nova.clouds.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.24_amd64.deb"; then
      die "Failed to download libssl1.1"
    fi

    if ! run_with_animation "    Downloading ppp..." wget -O /tmp/ppp.deb "http://ru.archive.ubuntu.com/ubuntu/pool/main/p/ppp/ppp_2.4.9-1%2b1ubuntu3_amd64.deb"; then
      die "Failed to download ppp"
    fi
   
    if ! run_with_animation "    Downloading bcrelay..." wget -O /tmp/bcrelay.deb "http://nova.clouds.archive.ubuntu.com/ubuntu/pool/main/p/pptpd/bcrelay_1.4.0-11build1_amd64.deb"; then
      die "Failed to download bcrelay"
    fi

    if ! run_with_animation "    Downloading pptpd..." wget -O /tmp/pptpd.deb "http://ru.archive.ubuntu.com/ubuntu/pool/main/p/pptpd/pptpd_1.4.0-12build2_amd64.deb"; then
      die "Failed to download pptpd"
    fi

    if ! run_with_animation "    Installing libssl1.1..." dpkg -i /tmp/libssl1.1.deb; then
      warn "libssl1.1 installation had issues, but continuing..."
    fi

    if ! run_with_animation "    Installing ppp..." dpkg -i /tmp/ppp.deb; then
      warn "ppp installation had issues, but continuing..."
    fi

    if ! run_with_animation "    Installing bcrelay..." dpkg -i /tmp/bcrelay.deb; then
      warn "bcrelay installation had issues, but continuing..."
    fi

    if ! run_with_animation "    Installing pptpd..." dpkg -i /tmp/pptpd.deb; then
      warn "pptpd installation had issues, but continuing..."
    fi

    if ! run_with_animation "    Fixing dependencies..." apt-get install -f -y; then
      warn "Dependency fixing had issues, but continuing..."
    fi

    if ! run_with_animation "    Holding packages from updates..." apt-mark hold libssl1.1 ppp pptpd bcrelay; then
      warn "Package holding failed, but continuing..."
    fi

    rm -f /tmp/{libssl1.1,ppp,bcrelay,pptpd}.deb 2>/dev/null || true
  else
    log "    Detected Ubuntu $UBUNTU_VER – installing pptpd from repository."
    if ! run_with_animation "    Installing pptpd..." apt-get install -y pptpd; then
      die "Failed to install pptpd from repository"
    fi
  fi

  if ! run_with_animation "    Installing dependencies..." apt-get install -y --no-upgrade jq curl iproute2 iptables-persistent ca-certificates python3 unzip dnsutils; then
    die "Failed to install dependencies"
  fi

  if ! command -v xray >/dev/null 2>&1; then
    log "Installing XRay-Core..."
    
    if ! run_with_animation "    Downloading XRay installer..." curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o /tmp/xray-install.sh; then
      die "Failed to download XRay installer"
    fi
    
    chmod +x /tmp/xray-install.sh || die "chmod failed on XRay installer"
    
    if ! run_with_animation "    Installing XRay-Core..." /bin/bash /tmp/xray-install.sh; then
      err "XRay installer failed; checking log: $INSTALL_LOG"
      if [[ -f "$INSTALL_LOG" ]]; then
        tail -n 20 "$INSTALL_LOG" >&2 || true
      fi
      die "XRay installation failed"
    fi
    
    ok "XRay-Core installed successfully"
    rm -f /tmp/xray-install.sh
  else
    ok "XRay-Core already installed"
  fi
}

# ----------------------- PPTP config --------------------------
configure_pptp() {
  [[ -z "$VPN_PASS" ]] && VPN_PASS="$(rand_pw)"
  log "Configuring pptpd..."
  cat > /etc/pptpd.conf <<EOF
option /etc/ppp/pptpd-options
logwtmp
localip $VPN_LOCAL_IP
remoteip $VPN_REMOTE_IP_RANGE
EOF

  cat > /etc/ppp/pptpd-options <<'EOF'
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
nobsdcomp
nodeflate
noipx
noccp
debug
lock
auth
mtu 1400
mru 1400
lcp-echo-interval 30
lcp-echo-failure 4
ms-dns 9.9.9.9
ms-dns 8.8.8.8
EOF

  local CHAP_SECRETS="/etc/ppp/chap-secrets"
  touch "$CHAP_SECRETS" && chmod 600 "$CHAP_SECRETS"
  if ! grep -q "^$VPN_USER[[:space:]]\+pptpd[[:space:]]" "$CHAP_SECRETS"; then
    echo "$VPN_USER pptpd $VPN_PASS *" >> "$CHAP_SECRETS"
  fi

  if ! run_with_animation "    Enabling pptpd service..." systemctl enable pptpd; then
    warn "Failed to enable pptpd service"
  fi
  
  if ! run_with_animation "    Starting pptpd service..." systemctl restart pptpd; then
    warn "Failed to restart pptpd service"
  fi
}

# ----------------------- UFW rule for PPTP -------------------
configure_ufw() {
  log "Configuring UFW for PPTP (TCP/1723)..."
  if command -v ufw >/dev/null 2>&1; then
    local status
    status="$(ufw status 2>/dev/null | head -n1 || true)"
    if printf "%s" "$status" | grep -qi "Status: active"; then
      if ufw allow 1723/tcp >/dev/null 2>&1; then
        ok "Added 'ufw allow 1723/tcp'"
      else
        warn "Failed to add UFW rule 'allow 1723/tcp'"
      fi
    else
      warn "UFW is installed but not active; skipping rule"
    fi
  else
    warn "UFW is not installed; skipping TCP/1723 rule"
  fi
}

# ----------------------- XRay config --------------------------
write_xray_config() {
  log "Building outbound from URI..."
  local outbound_obj
  outbound_obj="$(make_outbound_from_uri "$UPSTREAM_URI")" || { err "Failed to parse upstream URI"; return 2; }

  log "Writing $XRAY_CONF_PATH ..."
  install -d -m 755 "$(dirname "$XRAY_CONF_PATH")"
  
  local outbound_tag
  outbound_tag="$(echo "$outbound_obj" | jq -r '.tag')"

  local temp_config="/tmp/xray_config_$$.json"  # FIX: Use proper $ for process ID

  jq -n '{
    inbounds:[
      { 
        tag:"unified_tproxy", 
        port:12345, 
        protocol:"dokodemo-door", 
        listen:"0.0.0.0",
        settings:{network:"tcp,udp", followRedirect:true}, 
        streamSettings:{sockopt:{tproxy:"tproxy"}}, 
        sniffing:{enabled:true, destOverride:["http","tls","quic"]} 
      }
    ],
    outbounds:[],
    routing:{}
  }' > "$temp_config"

  jq --argjson outbound "$outbound_obj" '.outbounds = [$outbound, {tag:"direct", protocol:"freedom"}, {tag:"block", protocol:"blackhole"}]' "$temp_config" > "${temp_config}.1"

  jq --arg tag "$outbound_tag" '.routing = {
    domainStrategy:"UseIPv4", 
    rules:[ 
      {type:"field", ip:["geoip:private"], outboundTag:"direct"}, 
      {type:"field", inboundTag:["unified_tproxy"], outboundTag:$tag} 
    ]
  }' "${temp_config}.1" > "$XRAY_CONF_PATH"

  rm -f "$temp_config" "${temp_config}.1"
  
  if [[ ! -f "$XRAY_CONF_PATH" ]]; then
    die "Failed to write XRay config"
  fi

  log "Validating XRay configuration JSON syntax..."
  if jq empty < "$XRAY_CONF_PATH" >/dev/null 2>&1; then
    ok "XRay configuration JSON syntax is valid"
  else
    warn "XRay configuration has invalid JSON syntax"
    if command -v jq >/dev/null 2>&1; then
      err "JSON validation error:"
      jq empty < "$XRAY_CONF_PATH" 2>&1 | head -5 >&2 || true
    fi
  fi

  if ! run_with_animation "    Reloading systemd daemon..." systemctl daemon-reload; then
    warn "Failed to reload systemd daemon"
  fi
  
  if ! run_with_animation "    Stopping XRay service..." systemctl stop xray; then
    warn "XRay service was not running"
  fi
  
  if ! run_with_animation "    Starting XRay service..." systemctl start xray; then
    warn "Failed to start XRay service"

    if [[ -f /var/log/xray/error.log ]]; then
      err "XRay error log (last 10 lines):"
      tail -n 10 /var/log/xray/error.log >&2 2>/dev/null || true
    fi
  fi
  
  if ! run_with_animation "    Enabling XRay service..." systemctl enable xray; then
    warn "Failed to enable XRay service"
  fi

  if systemctl is-active xray >/dev/null 2>&1; then
    ok "XRay service is running"
  else
    warn "XRay service is not running properly"

    if [[ -f /var/log/xray/error.log ]]; then
      err "XRay error log (last 10 lines):"
      tail -n 10 /var/log/xray/error.log >&2 2>/dev/null || true
    fi
  fi
}

# ----------------------- main --------------------------------
main() {
  need_root

  install_packages
  
  while :; do
    read -rp "Введите ссылку upstream (vless://): " UPSTREAM_URI || true
    UPSTREAM_URI="$(echo -n "${UPSTREAM_URI:-}" | xargs)"
    
    if [[ -z "$UPSTREAM_URI" ]]; then
      err "Upstream URI is empty, try again."
      continue
    fi
    
    log "Validating URI format and parameters..."
    if validate_uri "$UPSTREAM_URI"; then
      break
    else
      err "URI validation failed, please try again."
      continue
    fi
  done
  
  configure_pptp
  configure_ufw
  setup_kernel_and_fw
  write_xray_config
  create_tproxy_restore_service

  local SERVER_IP
  SERVER_IP=$(curl -fsSL https://ipinfo.io/ip || echo "<server-ip>")
  echo
  echo "================= Done ================="
  echo "  PPTP server: $SERVER_IP"
  echo "  Account:     $VPN_USER / $VPN_PASS"
  echo
  echo "  ALL TCP/UDP traffic -> XRay TPROXY port: $XRAY_TPROXY_PORT"
  echo "  XRay outbound: parsed from URI"
  echo "  Config: $XRAY_CONF_PATH"
  echo "  TPROXY routing for TCP/UDP protocols"
  echo "  Persistence: TPROXY restore service enabled"
  echo "======================================="

  if ((${#WARNINGS[@]})); then
    echo -e "\nWarnings:"; for w in "${WARNINGS[@]}"; do echo " - $w"; done
  fi

  echo -e "\nService Status:"
  if systemctl is-active pptpd >/dev/null 2>&1; then
    echo "  ✅ PPTP service: Running"
  else
    echo "  ❌ PPTP service: Not running"
  fi
  
  if systemctl is-active xray >/dev/null 2>&1; then
    echo "  ✅ XRay service: Running"
  else
    echo "  ❌ XRay service: Not running"
  fi
  
  if systemctl is-enabled tproxy-restore.service >/dev/null 2>&1; then
    echo "  ✅ TPROXY restore service: Enabled"
  else
    echo "  ❌ TPROXY restore service: Not enabled"
  fi
  
  echo -e "\nPersistence Features:"
  echo "  ✅ Kernel modules auto-load: $MODULES_CONF"
  echo "  ✅ Sysctl settings persist: $SYSCTL_CONF"
  echo "  ✅ Iptables rules persist: netfilter-persistent"
  echo "  ✅ TPROXY routing restore: $SYSTEMD_SERVICE_PATH"
  echo "  ✅ Policy routing persist: /etc/iproute2/rt_tables"
  
  echo -e "\nPost-reboot verification:"
  echo "  systemctl status tproxy-restore.service"
  echo "  ip rule show"
  echo "  ip route show table tproxy"
  echo "  iptables -t mangle -L XRAY_ALL -n"
}

main "$@"