#!/usr/bin/env bash
# SEKA TUNEL - Professional Tunnel Panel (Direct / Reverse / GAAF)
# Version: 1.5.1
# Forked & enhanced from DR-CPanel
# Focus: Clean Linux install · Strong GAAF protocol · Better Persian UI
#
# GAAF = Guarded Adaptive Authenticated Forwarding
#        SM4-GCM (Chinese national standard) + X25519 + modern AEAD
#
# v2.2: per-forward traffic quota, user usage link (/sub/<token>), domain + HTTPS
# Run this on the Iran server. Users connect to it, traffic is forwarded
# to the foreign node. Nothing is needed on the foreign server.
#
# Usage:  sudo bash seka-tunel.sh        (interactive menu)
#         seka-tunel apply | list | update   (non-interactive; apply is used by systemd)

set -u

# Load GAAF + Balancer modules if available
for _seka_mod in gaaf.sh balancer.sh checker.sh common.sh; do
  if [[ -f /usr/local/lib/seka-tunel/$_seka_mod ]]; then
    # shellcheck source=/dev/null
    source /usr/local/lib/seka-tunel/$_seka_mod
  elif [[ -f "$(dirname "$0")/lib/$_seka_mod" ]]; then
    # shellcheck source=/dev/null
    source "$(dirname "$0")/lib/$_seka_mod"
  elif [[ -f /home/workdir/artifacts/seka-tunel/lib/$_seka_mod ]]; then
    source /home/workdir/artifacts/seka-tunel/lib/$_seka_mod
  fi
done
unset _seka_mod

SEKA_VERSION="1.5.1"
# Original base was DR-CPanel v2.9.x
SEKA_VERSION="1.5.1"
CONF_DIR="/etc/seka-tunel"
SEC="$CONF_DIR/security.conf"         # lines: listen_port|allowed_ips(comma, CIDR ok)|max_conn_per_ip|new_conn_per_min_per_ip
TUN="$CONF_DIR/tunnels.conf"      # id|foreign_ip|udp_port|mtu|iran_priv|foreign_priv|iran_pub|foreign_pub|active|preset|type|join_token|name|token_expiry|transport|carrier_port
                                   # type: fwd=classic forward (Iran dials out), dir=direct (Iran dials out), rev=reverse (kharej dials in);
                                   # foreign_ip is "pending" for a rev tunnel until the kharej side fetches its join link;
                                   # transport: udp|tcp|ws|wss|kcp|quic|gaaf - how the WG packets travel (empty/udp = kernel WG over UDP);
                                   # for the other transports a gost carrier carries them: the LISTENING side runs
                                   # seka-gost<id> (relay+TR on carrier_port), the DIALING side runs seka-gostc<id> which feeds WG
                                   # from a local UDP port 30000+id*37, so the WG Endpoint becomes 127.0.0.1 on the dialing side
REV="$CONF_DIR/reverse.conf"       # reverse forwards: foreign_ip|listen_port_on_foreign|dest_port_on_iran|proto
BLK="$CONF_DIR/blocked"             # ports cut off by their quota (written by the web panel)
CONF="$CONF_DIR/rules.conf"          # lines: name|proto|listen_port|dest_ip|dest_port
DEF_IP_FILE="$CONF_DIR/default_ip"
BIN="/usr/local/bin/seka-tunel"
UNIT="/etc/systemd/system/seka-tunel.service"
SYSCTL_FWD="/etc/sysctl.d/99-seka-tunel-forward.conf"
SYSCTL_OPT="/etc/sysctl.d/99-seka-tunel-optimize.conf"
PERF_STATE="$CONF_DIR/perf_preset"
AUDF="/var/log/seka-tunel-audit.log"

C_RST=$'\e[0m'; C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
C_CYN=$'\e[36m'; C_BLD=$'\e[1m'

ok()   { echo "  ${C_GRN}✔${C_RST} $*"; }
err()  { echo "  ${C_RED}✘${C_RST} $*"; }
warn() { echo "  ${C_YEL}!${C_RST} $*"; }
info() { echo "  ${C_CYN}•${C_RST} $*"; }
pause(){ echo; read -rp "  Press Enter to continue..." _; }
confirm(){ local a; read -rp "  $1 [y/N]: " a; [[ $a =~ ^[Yy]$ ]]; }

need_root() { [[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }; }

ensure_deps() {
  command -v iptables >/dev/null 2>&1 && return 0
  warn "iptables not found, installing..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq iptables
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iptables
  elif command -v yum >/dev/null 2>&1; then
    yum install -y iptables
  fi
  command -v iptables >/dev/null 2>&1 || { err "Could not install iptables."; exit 1; }
}

valid_port() { [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
valid_ip() {
  local re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
  [[ $1 =~ $re ]] || return 1
  local i; for i in 1 2 3 4; do (( BASH_REMATCH[i] <= 255 )) || return 1; done
}
proto_list() { case "$1" in both) echo "tcp udp";; *) echo "$1";; esac; }
proto_num()  { case "$1" in tcp) echo 6;; udp) echo 17;; esac; }
hb() {
  awk -v b="$1" 'BEGIN{split("B KB MB GB TB",u," ");i=1;while(b>=1024&&i<5){b/=1024;i++}printf "%.1f %s",b,u[i]}'
}

banner() {
  clear 2>/dev/null || true
  echo "${C_CYN}${C_BLD}"
  echo "  ┌──────────────────────────────────────────────────┐"
  printf "  │  SEKA TUNEL v%-6s  Port-Forward Tunnel Manager   │\n" "$VERSION"
  echo "  │  Run on the Iran server · nothing needed abroad  │"
  echo "  │  by @DR_Gojo_Satoruu  (t.me/DR_Gojo_Satoruu)     │"
  echo "  └──────────────────────────────────────────────────┘${C_RST}"
  echo
}

# ---------------------------------------------------------------- core ----

valid_cidr() {   # IPv4 or IPv4/mask
  local ip=${1%%/*} m=""
  [[ $1 == */* ]] && m=${1#*/}
  valid_ip "$ip" || return 1
  [[ -z $m ]] || { [[ $m =~ ^[0-9]+$ ]] && (( m >= 0 && m <= 32 )); }
}

sec_get() {   # sets SEC_ALLOW SEC_MAXC SEC_RATE for a listen port
  SEC_ALLOW=""; SEC_MAXC=0; SEC_RATE=0
  [[ -s $SEC ]] || return 0
  local l; l=$(awk -F'|' -v p="$1" '$1==p{print; exit}' "$SEC")
  [[ -n $l ]] || return 0
  IFS='|' read -r _ SEC_ALLOW SEC_MAXC SEC_RATE <<< "$l"
  [[ ${SEC_MAXC:-} =~ ^[0-9]+$ ]] || SEC_MAXC=0
  [[ ${SEC_RATE:-} =~ ^[0-9]+$ ]] || SEC_RATE=0
}

sec_set() {   # lport allow maxconn rate   (all empty/0 removes the entry)
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  [[ -f $SEC ]] && sed -i "/^$1|/d" "$SEC"
  if [[ -n $2 || ${3:-0} -gt 0 || ${4:-0} -gt 0 ]]; then
    echo "$1|$2|${3:-0}|${4:-0}" >> "$SEC"
  fi
}

sec_cleanup() {   # remove per-tunnel allow-list chains (mangle)
  local c
  for c in $(iptables -t mangle -S 2>/dev/null | awk '/^-N SEKA_A[0-9]/{print $2}'); do
    iptables -t mangle -F "$c" 2>/dev/null; iptables -t mangle -X "$c" 2>/dev/null
  done
}

sec_apply() {   # lport proto-list : build the security rules for one tunnel (mangle PREROUTING, before DNAT)
  local lport=$1 plist=$2 a p burst
  sec_get "$lport"
  [[ -z $SEC_ALLOW && $SEC_MAXC -eq 0 && $SEC_RATE -eq 0 ]] && return 0
  if [[ -n $SEC_ALLOW ]]; then
    iptables -t mangle -N "SEKA_A$lport" 2>/dev/null || iptables -t mangle -F "SEKA_A$lport"
    for a in ${SEC_ALLOW//,/ }; do iptables -t mangle -A "SEKA_A$lport" -s "$a" -j RETURN; done
    iptables -t mangle -A "SEKA_A$lport" -j DROP
  fi
  for p in $plist; do
    [[ -n $SEC_ALLOW ]] && iptables -t mangle -A SEKA_SEC -p "$p" --dport "$lport" -j "SEKA_A$lport"
    if (( SEC_MAXC > 0 )); then
      iptables -t mangle -A SEKA_SEC -p "$p" --dport "$lport" -m conntrack --ctstate NEW \
        -m connlimit --connlimit-above "$SEC_MAXC" --connlimit-mask 32 --connlimit-saddr -j DROP
    fi
    if (( SEC_RATE > 0 )); then
      burst=$SEC_RATE; (( burst < 10 )) && burst=10
      iptables -t mangle -A SEKA_SEC -p "$p" --dport "$lport" -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-name "d${lport}${p:0:1}" --hashlimit-mode srcip \
        --hashlimit-above "${SEC_RATE}/min" --hashlimit-burst "$burst" -j DROP
    fi
  done
}


# ------------------------------------------- encrypted transport (WireGuard)
# Every foreign server gets its own WireGuard link: 10.66.<id>.1 (this server) <-> 10.66.<id>.2 (foreign).
# rules.conf keeps the real foreign IP. Once a link is switched on ("active"), apply_rules DNATs to the link
# address instead, so counters, quotas, health checks and the security rules keep working unchanged.

tun_row()    { [[ -s $TUN ]] && awk -F'|' -v ip="$1" '$2==ip||$1==ip{print;exit}' "$TUN"; }   # matches the foreign IP or the tunnel id
tun_target() { local r; r=$(tun_row "$1"); if [[ -n $r && $(cut -d'|' -f9 <<<"$r") == 1 ]]; then echo "10.66.${r%%|*}.2"; else echo "$1"; fi; }
tun_token()  { od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'; }

# ------------------------------------------------------- multi-transport carrier
# Like BackPack, every tunnel picks how it crosses the Iran<->abroad path. The encrypted
# core is always WireGuard; the transport is the carrier that moves its UDP packets:
#   udp  plain kernel WG (fastest, the default)      tcp  simple TCP relay when UDP is blocked
#   ws   WebSocket over plain HTTP (passes HTTP-only filters/CDN)
#   wss  WebSocket inside TLS (looks like HTTPS; self-signed cert is automatic)
#   kcp  UDP + KCP (error correction for lossy paths)   quic real QUIC session (TLS 1.3)
# Carriers are carried by gost v3, installed as /usr/local/bin/seka-gost.
GOST_VER="3.3.3"
tr_valid() { [[ $1 =~ ^(udp|tcp|ws|wss|kcp|quic|gaaf)$ ]]; }
tr_mtu()   { case $1 in tcp) echo 1380;; ws) echo 1360;; wss) echo 1340;; kcp) echo 1330;; quic) echo 1350;; *) echo 1420;; esac; }
tr_proto() { case $1 in kcp|quic) echo udp;; *) echo tcp;; esac; }   # what the carrier port itself speaks
tr_carrier_port() {   # id [port] : the carrier port on the LISTENING side (default: derived from the tunnel id, never collides)
  local p=${2:-}
  [[ $p =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )) && { echo "$p"; return; }
  echo $((20000 + ${1:-1} * 37))
}
tr_local_port() { echo $((30000 + ${1:-1} * 37)); }   # local UDP feed port on the DIALING side

gost_have() { [[ -x /usr/local/bin/seka-gost ]]; }

gost_install() {   # install gost v3 as /usr/local/bin/seka-gost (sha256-verified against the release checksums)
  gost_have && { echo "/usr/local/bin/seka-gost"; return 0; }
  local arch tmp want
  case $(uname -m) in
    x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; armv7l) arch=armv7;; i686|i386) arch=386;;
    *) echo "error: unsupported architecture $(uname -m) for the gost carrier" >&2; return 1;;
  esac
  tmp=$(mktemp -d) || return 1
  echo "Downloading gost v$GOST_VER (${arch})..." >&2
  curl -fsSL --retry 2 --retry-delay 2 -o "$tmp/g.tgz" \
    "https://github.com/go-gost/gost/releases/download/v$GOST_VER/gost_${GOST_VER}_linux_${arch}.tar.gz" \
    && curl -fsSL --retry 2 -o "$tmp/s.txt" \
    "https://github.com/go-gost/gost/releases/download/v$GOST_VER/checksums.txt" \
    || { rm -rf "$tmp"; echo "error: could not download gost (is GitHub reachable?)" >&2; return 1; }
  want=$(awk -v f="gost_${GOST_VER}_linux_${arch}.tar.gz" '$2==f{print $1}' "$tmp/s.txt")
  if [[ -n $want ]] && ! (cd "$tmp" && echo "$want  g.tgz" | sha256sum -c >/dev/null 2>&1); then
    rm -rf "$tmp"; echo "error: gost checksum FAILED - download is broken, not installing" >&2; return 1
  fi
  tar xzf "$tmp/g.tgz" -C "$tmp" gost 2>/dev/null || tar xzf "$tmp/g.tgz" -C "$tmp"
  install -m 755 "$tmp/gost" /usr/local/bin/seka-gost || { rm -rf "$tmp"; echo "error: could not install gost" >&2; return 1; }
  rm -rf "$tmp"; echo "/usr/local/bin/seka-gost"
}

gost_unit_client() {   # id local_udp_port wg_port carrier_port host tr token : the DIALING side feeds WG through the carrier
  local sec=""; [[ $6 == wss ]] && sec="?secure=false"
  cat > "/etc/systemd/system/seka-gostc$1.service" <<EOF
[Unit]
Description=SEKA TUNEL transport carrier (tunnel $1, client)
After=network-online.target
[Service]
ExecStart=/usr/local/bin/seka-gost -L "udp://127.0.0.1:$2/127.0.0.1:$3?keepalive=true" -F "relay+$6://$7@$5:$4$sec"
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
}

gost_unit_server() {   # id carrier_port tr token : the LISTENING side accepts the carrier and hands it to the local WG port
  cat > "/etc/systemd/system/seka-gost$1.service" <<EOF
[Unit]
Description=SEKA TUNEL transport carrier (tunnel $1, server)
After=network-online.target
[Service]
ExecStart=/usr/local/bin/seka-gost -L "relay+$3://$4@:${2}"
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
}

gost_side_up() {   # id : start the gost carrier THIS (Iran) side needs - no-op for plain UDP
  local r id fip port mtu _5 _6 ipub _8 _9 _10 ty tok _13 _14 tr cport lp
  r=$(awk -F'|' -v i="$1" '$1==i{print;exit}' "$TUN"); [[ -n $r ]] || return 0
  IFS='|' read -r id fip port mtu _5 _6 ipub _8 _9 _10 ty tok _13 _14 tr cport <<< "$r"
  tr=${tr:-udp}; [[ $tr != udp ]] || return 0
  gost_have || gost_install >/dev/null 2>&1 || { echo "error: gost carrier is not installed" >&2; return 1; }
  if [[ ${#tok} -lt 16 ]]; then   # every carried tunnel needs a shared carrier token
    tok=$(tun_token); [[ ${#tok} -ge 16 ]] || { echo "error: no entropy for the carrier token" >&2; return 1; }
    awk -F'|' -v OFS='|' -v i="$id" -v v="$tok" '$1==i{$12=v}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
  fi
  cport=$(tr_carrier_port "$id" "$cport"); lp=$(tr_local_port "$id")
  if [[ $ty == rev ]]; then   # Iran listens: the kharej dials the carrier port
    gost_unit_server "$id" "$cport" "$tr" "$tok"
    iptables -I INPUT -p "$(tr_proto "$tr")" --dport "$cport" -m comment --comment "seka-gost$id" -j ACCEPT 2>/dev/null || true
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow "$cport/$(tr_proto "$tr")" >/dev/null 2>&1 || true; fi
    systemctl daemon-reload >/dev/null 2>&1; systemctl enable --now "seka-gost$id" >/dev/null 2>&1
  else                        # Iran dials: the local gost feeds WG from 127.0.0.1:<local port>
    gost_unit_client "$id" "$lp" "$port" "$cport" "$fip" "$tr" "$tok"
    systemctl daemon-reload >/dev/null 2>&1; systemctl enable --now "seka-gostc$id" >/dev/null 2>&1
  fi
}

gost_side_down() {   # id : stop the carrier of this side and clear its firewall rule
  systemctl disable --now "seka-gost$1" "seka-gostc$1" >/dev/null 2>&1
  rm -f "/etc/systemd/system/seka-gost$1.service" "/etc/systemd/system/seka-gostc$1.service"
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1
  local r tr cport
  r=$(awk -F'|' -v i="$1" '$1==i{print;exit}' "$TUN")
  if [[ -n $r ]]; then
    tr=$(cut -d'|' -f15 <<< "$r"); cport=$(tr_carrier_port "$1" "$(cut -d'|' -f16 <<< "$r")")
    local n=0
    while iptables -D INPUT -p "$(tr_proto "${tr:-udp}")" --dport "$cport" -m comment --comment "seka-gost$1" -j ACCEPT 2>/dev/null; do (( ++n > 50 )) && break; done
  fi
}

gost_boot() {   # after a reboot: bring every tunnel's carrier back (idempotent)
  [[ -s $TUN ]] || return 0
  local id
  while IFS='|' read -r id _; do [[ -n $id ]] && gost_side_up "$id" >/dev/null 2>&1; done < "$TUN"
}

tun_need_wg() {
  if ! command -v wg-quick >/dev/null 2>&1; then
    echo "Installing WireGuard..." >&2
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard >/dev/null 2>&1 || {
        apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard >/dev/null 2>&1; }
    elif command -v dnf >/dev/null 2>&1; then dnf install -y wireguard-tools >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then yum install -y epel-release wireguard-tools >/dev/null 2>&1
    fi
  fi
  command -v wg-quick >/dev/null 2>&1 || { echo "error: could not install WireGuard" >&2; return 1; }
  modprobe wireguard >/dev/null 2>&1
  if ip link add sekawgchk type wireguard >/dev/null 2>&1; then ip link del sekawgchk >/dev/null 2>&1
  else echo "error: this kernel has no WireGuard support" >&2; return 1; fi
}

tun_write_conf() {   # id
  local r id fip port mtu ipriv _fp ipub fpub _a _pr ty tok _nm _ex tr cport ep="" post="" listen=""
  r=$(awk -F'|' -v i="$1" '$1==i{print;exit}' "$TUN")
  IFS='|' read -r id fip port mtu ipriv _fp ipub fpub _a _pr ty tok _nm _ex tr cport <<< "$r"
  ty=${ty:-fwd}; tr=${tr:-udp}
  (( mtu >= 1200 && mtu <= 1500 )) || mtu=$(tr_mtu "$tr")   # 0 = auto: start from the carrier's safe value
  if [[ $ty == rev ]]; then
    # the kharej dials IN: this side listens on the WG port (the join script dials it)
    listen=$'ListenPort = '"$port"$'\n'
    if [[ $tr == udp ]]; then
      post=$'PostUp = iptables -I INPUT -p udp --dport '"$port"$' -j ACCEPT || true; iptables -I INPUT -i sekawg'"$id"$' -j ACCEPT || true\nPostDown = iptables -D INPUT -p udp --dport '"$port"$' -j ACCEPT || true; iptables -D INPUT -i sekawg'"$id"$' -j ACCEPT || true\n'
    fi
    # other transports: gost_side_up opens the carrier port itself
  elif [[ $tr == udp ]]; then
    valid_ip "$fip" && ep=$'Endpoint = '"$fip:$port"$'\n'
  else
    ep=$'Endpoint = 127.0.0.1:'"$(tr_local_port "$id")"$'\n'   # WG rides the local gost carrier
  fi
  mkdir -p /etc/wireguard
  ( umask 077; cat > "/etc/wireguard/sekawg$id.conf" <<EOF
[Interface]
Address = 10.66.$id.1/30
PrivateKey = $ipriv
${listen}MTU = $mtu
Table = off
${post}
[Peer]
PublicKey = $fpub
${ep}AllowedIPs = 10.66.$id.2/32
PersistentKeepalive = 25
EOF
  )
}

tun_up() {   # id
  gost_side_up "$1" >/dev/null 2>&1 || true   # carrier first; WG retries until it is up
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable "wg-quick@sekawg$1" >/dev/null 2>&1
    systemctl restart "wg-quick@sekawg$1" >/dev/null 2>&1
  else
    wg-quick down "sekawg$1" >/dev/null 2>&1; wg-quick up "sekawg$1" >/dev/null 2>&1
  fi
}

tun_down() {   # id
  gost_side_down "$1"
  if command -v systemctl >/dev/null 2>&1; then systemctl disable --now "wg-quick@sekawg$1" >/dev/null 2>&1
  else wg-quick down "sekawg$1" >/dev/null 2>&1; fi
  ip link del "sekawg$1" >/dev/null 2>&1
  rm -f "/etc/wireguard/sekawg$1.conf"
}

tun_add() {   # foreign_ip [udp_port] [mtu] [preset] [type fwd|dir] [name] [transport] [carrier_port]
  local fip=$1 port=${2:-51820} mtu=${3:-0} preset=${4:-} ty=${5:-fwd} name=${6:-} tr=${7:-udp} cport=${8:-} id=1 ipriv fpriv
  valid_ip "$fip" || { echo "error: invalid IP" >&2; return 1; }
  [[ $port =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { echo "error: invalid UDP port" >&2; return 1; }
  [[ $mtu =~ ^[0-9]+$ ]] && (( mtu == 0 || (mtu >= 1200 && mtu <= 1500) )) || { echo "error: invalid MTU" >&2; return 1; }
  [[ -z $preset || $preset =~ ^(balanced|turbo|throughput|gaming)$ ]] || { echo "error: invalid preset" >&2; return 1; }
  [[ $ty =~ ^(fwd|dir)$ ]] || { echo "error: invalid type" >&2; return 1; }
  tr=${tr:-udp}; tr_valid "$tr" || { echo "error: invalid transport (udp tcp ws wss kcp quic gaaf)" >&2; return 1; }
  [[ -z $cport || $cport =~ ^[0-9]+$ ]] || { echo "error: invalid carrier port" >&2; return 1; }
  name=$(printf '%s' "$name" | sed 's/[^A-Za-z0-9._-]/_/g' | cut -c1-40)
  [[ -n $(tun_row "$fip") ]] && { echo "error: a tunnel to $fip already exists" >&2; return 1; }
  tun_need_wg || return 1
  while [[ -s $TUN ]] && cut -d'|' -f1 "$TUN" | grep -qx "$id"; do id=$((id + 1)); done
  (( id <= 200 )) || { echo "error: too many tunnels" >&2; return 1; }
  ipriv=$(wg genkey); fpriv=$(wg genkey)
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  ( umask 077; echo "$id|$fip|$port|$mtu|$ipriv|$fpriv|$(wg pubkey <<< "$ipriv")|$(wg pubkey <<< "$fpriv")|0|$preset|$ty||$name||$tr|$cport" >> "$TUN" )
  tun_write_conf "$id"
  if ! tun_up "$id"; then
    tun_down "$id"; sed -i "/^$id|/d" "$TUN"
    echo "error: could not start the WireGuard interface" >&2; return 1
  fi
  apply_rules
}

tun_add_rev() {   # [udp_port] [preset] [name] [transport] [carrier_port] : pending REVERSE tunnel - the kharej joins with the one-line link
  local port=${1:-51820} preset=${2:-turbo} name=${3:-} tr=${4:-udp} cport=${5:-} id=1 ipriv fpriv tok
  [[ $port =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { echo "error: invalid UDP port" >&2; return 1; }
  [[ -z $preset || $preset =~ ^(balanced|turbo|throughput|gaming)$ ]] || { echo "error: invalid preset" >&2; return 1; }
  tr=${tr:-udp}; tr_valid "$tr" || { echo "error: invalid transport (udp tcp ws wss kcp quic gaaf)" >&2; return 1; }
  [[ -z $cport || $cport =~ ^[0-9]+$ ]] || { echo "error: invalid carrier port" >&2; return 1; }
  if [[ -s $TUN ]] && awk -F"|" -v p="$port" '$3==p{f=1} END{exit !f}' "$TUN"; then   # rev listens on this side: the WG port must stay free
    echo "error: another tunnel already uses UDP port $port" >&2; return 1
  fi
  name=$(printf '%s' "$name" | sed 's/[^A-Za-z0-9._-]/_/g' | cut -c1-40)
  tun_need_wg || return 1
  while [[ -s $TUN ]] && cut -d'|' -f1 "$TUN" | grep -qx "$id"; do id=$((id + 1)); done
  (( id <= 200 )) || { echo "error: too many tunnels" >&2; return 1; }
  tok=$(tun_token); [[ ${#tok} -ge 16 ]] || { echo "error: no entropy for the join token" >&2; return 1; }
  ipriv=$(wg genkey); fpriv=$(wg genkey)
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  ( umask 077; echo "$id|pending|$port|0|$ipriv|$fpriv|$(wg pubkey <<< "$ipriv")|$(wg pubkey <<< "$fpriv")|0|${preset:-turbo}|rev|$tok|$name||$tr|$cport" >> "$TUN" )
  tun_write_conf "$id"
  tun_up "$id" || true   # this side listens right away; the kharej dials in once its join link is run
  apply_rules
  echo "$tok"
}

tun_link() {   # ip-or-id [new_token] : print (or rotate) the join token of a tunnel
  local r id tok
  r=$(tun_row "$1"); [[ -n $r ]] || { echo "error: no tunnel for $1" >&2; return 1; }
  id=${r%%|*}
  if [[ -n ${2:-} ]]; then
    awk -F'|' -v OFS='|' -v i="$id" -v v="$2" '$1==i{$12=v}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
    echo "$2"; return 0
  fi
  tok=$(cut -d'|' -f12 <<< "$r")
  if [[ -z $tok ]]; then tok=$(tun_token) && tun_link "$id" "$tok" >/dev/null || return 1; fi
  echo "$tok"
}

tun_join_setip() {   # token client_ip : a kharej fetched its join link - resolve a pending rev tunnel to its real IP
  local tok=$1 cip=$2 r id
  [[ $tok =~ ^[0-9a-f]{16,64}$ ]] || { echo "error: bad token" >&2; return 1; }
  valid_ip "$cip" || { echo "error: bad IP" >&2; return 1; }
  [[ -s $TUN ]] || { echo "error: unknown or expired link" >&2; return 1; }
  r=$(awk -F'|' -v t="$tok" '$12==t{print;exit}' "$TUN")
  [[ -n $r ]] || { echo "error: unknown or expired link" >&2; return 1; }
  id=${r%%|*}
  if [[ $(cut -d'|' -f2 <<< "$r") == pending ]]; then
    awk -F'|' -v OFS='|' -v i="$id" -v v="$cip" '$1==i{$2=v}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
    apply_rules
  fi
  echo "$id"
}

tun_preset() {   # foreign_ip [preset] : read or set the per-tunnel preset ("none" clears it)
  local r id cur
  r=$(tun_row "$1"); [[ -n $r ]] || { echo "error: no tunnel for $1" >&2; return 1; }
  id=${r%%|*}; cur=$(cut -d'|' -f10 <<< "$r")
  if [[ -z ${2:-} ]]; then echo "$cur"; return 0; fi
  if [[ $2 == none ]]; then
    awk -F'|' -v OFS='|' -v i="$id" -v v="" '$1==i{$10=v}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
    echo ""; return 0
  fi
  [[ $2 =~ ^(balanced|turbo|throughput|gaming)$ ]] || { echo "error: invalid preset" >&2; return 1; }
  awk -F'|' -v OFS='|' -v i="$id" -v v="$2" '$1==i{$10=v}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
  if [[ $(cut -d'|' -f9 <<< "$r") == 1 ]]; then perf_apply "$2" >/dev/null 2>&1 || true; fi   # active tunnel: apply right away
  echo "$2"
}

tun_transport() {   # ip-or-id [transport] [carrier_port] : read or set the per-tunnel transport (BackPack-style carrier switch)
  local r id cur tr cport tok
  r=$(tun_row "$1"); [[ -n $r ]] || { echo "error: no tunnel for $1" >&2; return 1; }
  id=${r%%|*}; cur=$(cut -d'|' -f15 <<< "$r"); [[ -n $cur ]] || cur=udp
  if [[ -z ${2:-} ]]; then echo "$cur"; return 0; fi
  tr=$2; tr_valid "$tr" || { echo "error: invalid transport (udp tcp ws wss kcp quic gaaf)" >&2; return 1; }
  cport=${3:-}; [[ -z $cport || $cport =~ ^[0-9]+$ ]] || { echo "error: invalid carrier port" >&2; return 1; }
  tok=$(cut -d'|' -f12 <<< "$r")
  if [[ $tr != udp && ${#tok} -lt 16 ]]; then   # carried tunnels share a carrier token
    tok=$(tun_token); [[ ${#tok} -ge 16 ]] || { echo "error: no entropy for the carrier token" >&2; return 1; }
    awk -F'|' -v OFS='|' -v i="$id" -v v="$tok" '$1==i{$12=v}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
  fi
  awk -F'|' -v OFS='|' -v i="$id" -v v="$tr" -v c="$cport" '$1==i{$15=v;$16=c}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
  gost_side_down "$id"     # stop the old carrier (its unit and firewall rule go away)
  tun_write_conf "$id"     # rewrite the WG conf: new start MTU and, when carried, the local Endpoint
  tun_up "$id"             # WG back up (tun_up starts the new carrier too)
  apply_rules
  echo "$tr"
}

tun_probe_mtu() {   # id : echo the largest inner-MTU the link actually passes (binary search with DF pings)
  local id=$1 lo=1200 hi=1500 mid best=0
  ip link set dev "sekawg$id" mtu 1500 >/dev/null 2>&1 || return 1
  while (( lo <= hi )); do
    mid=$(( (lo + hi) / 2 ))
    if ping -M do -s $((mid - 28)) -c1 -W1 "10.66.$id.2" >/dev/null 2>&1; then best=$mid; lo=$((mid + 1)); else hi=$((mid - 1)); fi
  done
  echo "$best"
}

tun_probe_pub() {   # ip-or-id : measure the link MTU without touching the saved config
  local r id cur got
  r=$(tun_row "$1"); [[ -n $r ]] || { echo "error: no tunnel for $1" >&2; return 1; }
  id=${r%%|*}; cur=$(cut -d'|' -f4 <<< "$r"); (( cur >= 1200 && cur <= 1500 )) || cur=1420
  got=$(tun_probe_mtu "$id" 2>/dev/null)
  ip link set dev "sekawg$id" mtu "$cur" >/dev/null 2>&1 || true
  echo "${got:-0}"
}

tun_automtu() {   # foreign_ip : detect the best MTU, save it and bounce the interface
  local r id mtu; r=$(tun_row "$1"); [[ -n $r ]] || return 1
  id=${r%%|*}
  [[ $(wg show "sekawg$id" latest-handshakes 2>/dev/null | awk '{print $2}') -gt 0 ]] || return 1   # needs a live link
  mtu=$(tun_probe_mtu "$id"); (( mtu >= 1200 )) || return 1
  awk -F'|' -v OFS='|' -v i="$id" -v m="$mtu" '$1==i{$4=m}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
  tun_write_conf "$id"; tun_up "$id"
  echo "$mtu"
}

tun_del() {   # foreign_ip
  local r; r=$(tun_row "$1")
  [[ -n $r ]] || { echo "error: no tunnel for $1" >&2; return 1; }
  tun_down "${r%%|*}"
  sed -i "/^${r%%|*}|/d" "$TUN"
  [[ -s $REV ]] && sed -i "/^$1|/d" "$REV"   # drop this tunnel's reverse forwards too
  apply_rules
}

tun_active() {   # foreign_ip 0|1   (1 = send the forwards through the tunnel)
  local r id; r=$(tun_row "$1")
  [[ -n $r ]] || { echo "error: no tunnel for $1" >&2; return 1; }
  id=${r%%|*}
  if [[ $2 == 1 ]]; then
    local hs; hs=$(wg show "sekawg$id" latest-handshakes 2>/dev/null | awk '{print $2}')
    [[ ${hs:-0} -gt 0 ]] || { echo "error: no handshake yet. Run the setup script on the foreign server first" >&2; return 1; }
    ping -c 2 -W 2 "10.66.$id.2" >/dev/null 2>&1 || { echo "error: the foreign end does not answer inside the tunnel" >&2; return 1; }
    local am; am=$(awk -F'|' -v i="$id" '$1==i{print $4}' "$TUN")
    if [[ $am == 0 ]]; then tun_automtu "$1" >/dev/null 2>&1 || true; fi   # MTU "auto": measure the real path once the link is live
    local tp; tp=$(cut -d'|' -f10 <<< "$r")   # this tunnel's own performance preset
    [[ $tp =~ ^(balanced|turbo|throughput|gaming)$ ]] && perf_apply "$tp" >/dev/null 2>&1 || true
  fi
  awk -F'|' -v OFS='|' -v ip="$1" -v v="$2" '$2==ip{$9=v}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"
  apply_rules
}

tun_sync() {   # rebuild interfaces from tunnels.conf (after a restore)
  local id
  [[ -s $TUN ]] || return 0
  tun_need_wg || return 1
  for id in $(cut -d'|' -f1 "$TUN"); do tun_write_conf "$id"; tun_up "$id"; done
  apply_rules
}

# ------------------------------------------------------ reverse forwards ----
# Reverse = the port opens on the FOREIGN server and lands on a service of the
# IRAN server, through the encrypted tunnel. Needed on both sides: the Iran
# side writes the local DNAT (apply_rules), the foreign side gets the same
# rules inside its setup script (tun_script), which the user runs again.

rev_valid() {   # fip lport dport proto
  valid_ip "$1" || { echo "error: invalid IP" >&2; return 1; }
  valid_port "$2" && valid_port "$3" || { echo "error: invalid port" >&2; return 1; }
  [[ $4 =~ ^(tcp|udp|both)$ ]] || { echo "error: invalid protocol" >&2; return 1; }
  [[ -n $(tun_row "$1") ]] || { echo "error: no tunnel for $1 — create the tunnel first" >&2; return 1; }
}

rev_add() {   # foreign_ip listen_port dest_port_on_iran [proto]
  local fip=$1 lp=$2 dp=$3 proto=${4:-tcp}
  rev_valid "$fip" "$lp" "$dp" "$proto" || return 1
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  touch "$REV"; chmod 600 "$REV"
  grep -q "^$fip|$lp|" "$REV" && { echo "error: this reverse port already exists for $fip" >&2; return 1; }
  echo "$fip|$lp|$dp|$proto" >> "$REV"
  apply_rules
}

rev_del() {   # foreign_ip listen_port
  local fip=$1 lp=$2
  [[ -s $REV ]] || { echo "error: no reverse forwards" >&2; return 1; }
  grep -q "^$fip|$lp|" "$REV" || { echo "error: no such reverse forward" >&2; return 1; }
  awk -F'|' -v f="$fip" -v l="$lp" '!($1==f && $2==l)' "$REV" > "$REV.tmp" && cat "$REV.tmp" > "$REV"; rm -f "$REV.tmp"
  apply_rules
}

rev_list() {   # echo "foreign_ip|listen_port|dest_port|proto" rows
  [[ -s $REV ]] && grep -v '^$' "$REV" || true
}

rev_test() {   # foreign_ip listen_port : 12 TCP probes through the loop kharej-DNAT -> Iran (BackPack-style)
  local r id fip lp
  r=$(tun_row "$1"); [[ -n $r ]] || { echo "error: no tunnel for $1" >&2; return 1; }
  id=${r%%|*}; valid_port "$2" || { echo "error: invalid port" >&2; return 1; }
  grep -q "^$1|$2|" "$REV" 2>/dev/null || { echo "error: no reverse forward on port $2 for $1" >&2; return 1; }
  local i ms ok=0 tot=0 mn=999999 mx=0
  for i in $(seq 1 12); do
    ms=$(tcp_time "10.66.$id.2" "$2")
    if [[ $ms != fail ]]; then ok=$((ok + 1)); tot=$((tot + ms)); (( ms < mn )) && mn=$ms; (( ms > mx )) && mx=$ms; fi
    sleep 0.15
  done
  if (( ok == 0 )); then echo "fail"; return 1; fi
  echo "$ok/12 ok · avg $((tot / ok)) ms · min $mn · max $mx"
}

repair_wg() {   # watchdog helper: bounce every active interface whose handshake went stale
  local r id hs
  [[ -s $TUN ]] || return 0
  while IFS='|' read -r id _ _ _ _ _ _ _ a _; do
    [[ -z $id || $a != 1 ]] && continue
    hs=$(wg show "sekawg$id" latest-handshakes 2>/dev/null | awk '{print $2}')
    if [[ ${hs:-0} -gt 0 ]]; then
      (( $(date +%s) - hs > 300 )) || continue
    fi
    wg show "sekawg$id" >/dev/null 2>&1 || { tun_write_conf "$id"; tun_up "$id"; continue; }
    (( $(date +%s) - ${hs:-0} > 300 )) && { systemctl restart "wg-quick@sekawg$id" 2>/dev/null || { tun_write_conf "$id"; tun_up "$id"; }; }
  done < "$TUN"
}

tun_script() {   # foreign_ip : the script to run on the foreign server
  local r id port mtu fpriv ipub revrules="" revn=0 rf lp dp rp p ty epdecl=""
  r=$(tun_row "$1"); [[ -n $r ]] || { echo "error: no tunnel for $1" >&2; return 1; }
  IFS='|' read -r id _ port mtu _ fpriv ipub _ _ _ ty _ _ _ tr cport <<< "$r"
  ty=${ty:-fwd}; tr=${tr:-udp}
  (( mtu >= 1200 && mtu <= 1500 )) || mtu=$(tr_mtu "$tr")   # 0 = auto: the foreign conf needs a number
  if [[ $ty == rev ]]; then   # kharej dials in: it needs this (Iran) server's address as the WG endpoint
    local myip; myip=$(web_pubip 2>/dev/null || true)
    [[ -n $myip ]] && epdecl=$'Endpoint = '"$myip:$port"$'\nPersistentKeepalive = 25\n'
  fi
  if [[ -s $REV ]]; then   # embed the reverse forwards of THIS tunnel into the script
    while IFS='|' read -r rf lp dp rp; do
      [[ $rf == "$1" ]] || continue
      for p in $(proto_list "$rp"); do
        revrules+="iptables -t nat -A SEKA_REV -p $p --dport $lp -j DNAT --to-destination 10.66.$id.1:$dp"$'\n'
      done
      revn=$((revn + 1))
    done < "$REV"
  fi
  # BackPack-style forwarded ports: users hit Iran:<lport>, the service listens on the kharej
  # (often only on its loopback) - bake the loopback redirect into the foreign script.
  local fwdin="" fwdn=0
  if [[ -s $CONF ]]; then
    while IFS='|' read -r fn fp fl fi fd; do
      [[ $fi == "10.66.$id.2" ]] || continue
      for p in $(proto_list "$fp"); do
        fwdin+="iptables -t nat -A SEKA_REV -i sekawg$id -p $p -d 10.66.$id.2 --dport $fd -j DNAT --to-destination 127.0.0.1:$fd"$'\n'
      done
      fwdn=$((fwdn + 1))
    done < "$CONF"
    [[ -n $fwdin ]] && fwdin=$'sysctl -q -w net.ipv4.conf.sekawg'"$id"$'.route_localnet=1 || true\n'"$fwdin"
  fi
  # when the transport is not plain UDP, the foreign side listens for the gost carrier
  GOST_SRV=""
  if [[ $tr != udp ]]; then
    local cp tok
    cp=$(tr_carrier_port "$id" "$cport")
    tok=$(cut -d'|' -f12 <<< "$r")
    [[ ${#tok} -ge 16 ]] || { tok=$(tun_token); awk -F'|' -v OFS='|' -v i="$id" -v v="$tok" '$1==i{$12=v}1' "$TUN" > "$TUN.tmp" && cat "$TUN.tmp" > "$TUN"; rm -f "$TUN.tmp"; }
    gost_have || gost_install >/dev/null 2>&1   # this side too (for the status/preview); the foreign script installs its own copy
    GOST_SRV="# --- transport carrier: gost listens on $(tr_proto "$tr")/$cp and hands the traffic to the local WireGuard ---
if [[ ! -x /usr/local/bin/seka-gost ]]; then
  garch=amd64; [[ \$(uname -m) == aarch64 || \$(uname -m) == arm64 ]] && garch=arm64; [[ \$(uname -m) == armv7l ]] && garch=armv7; [[ \$(uname -m) == i686 || \$(uname -m) == i386 ]] && garch=386
  gtmp=\$(mktemp -d)
  curl -fsSL --retry 2 -o \$gtmp/g.tgz \"https://github.com/go-gost/gost/releases/download/v$GOST_VER/gost_${GOST_VER}_linux_\$garch.tar.gz\" \
    && curl -fsSL --retry 2 -o \$gtmp/s.txt \"https://github.com/go-gost/gost/releases/download/v$GOST_VER/checksums.txt\" \
    || { echo \"gost download failed - the transport carrier needs it\"; exit 1; }
  gwant=\$(awk -v f=\"gost_${GOST_VER}_linux_\$garch.tar.gz\" '\$2==f{print \$1}' \$gtmp/s.txt)
  [[ -z \$gwant ]] || { (cd \$gtmp && echo \"\$gwant  g.tgz\" | sha256sum -c >/dev/null) || { echo \"gost checksum FAILED\"; exit 1; }; }
  tar xzf \$gtmp/g.tgz -C \$gtmp gost 2>/dev/null || tar xzf \$gtmp/g.tgz -C \$gtmp
  install -m 755 \$gtmp/gost /usr/local/bin/seka-gost && rm -rf \$gtmp
fi
cat > /etc/systemd/system/seka-gost$id.service <<GEOF
[Unit]
Description=SEKA TUNEL transport carrier (tunnel $id)
After=network-online.target
[Service]
ExecStart=/usr/local/bin/seka-gost -L \"relay+$tr://$tok@:$cp\"
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
GEOF
iptables -I INPUT -p $(tr_proto "$tr") --dport $cp -j ACCEPT 2>/dev/null || true
command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q \"Status: active\" && ufw allow $cp/$(tr_proto "$tr") >/dev/null 2>&1
systemctl daemon-reload; systemctl enable --now seka-gost$id >/dev/null 2>&1
echo \"Transport carrier: $tr on port $cp\"
"
  fi
  cat <<EOS
# SEKA TUNEL: foreign-server side of the encrypted tunnel. Run once, as root.
set -e
[ "\$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
if ! command -v wg-quick >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard
  elif command -v dnf >/dev/null 2>&1; then dnf install -y wireguard-tools
  elif command -v yum >/dev/null 2>&1; then yum install -y epel-release wireguard-tools
  else echo "install WireGuard first"; exit 1; fi
fi
mkdir -p /etc/wireguard
( umask 077; cat > /etc/wireguard/sekawg$id.conf <<'WGEOF'
[Interface]
Address = 10.66.$id.2/30
ListenPort = $port
PrivateKey = $fpriv
MTU = $mtu
PostUp = iptables -I INPUT -p udp --dport $port -j ACCEPT || true; iptables -I INPUT -i sekawg$id -j ACCEPT || true
PostDown = iptables -D INPUT -p udp --dport $port -j ACCEPT || true; iptables -D INPUT -i sekawg$id -j ACCEPT || true

[Peer]
PublicKey = $ipub
${epdecl}AllowedIPs = 10.66.$id.1/32
WGEOF
)
systemctl enable wg-quick@sekawg$id >/dev/null 2>&1 || true
systemctl restart wg-quick@sekawg$id 2>/dev/null || { wg-quick down sekawg$id 2>/dev/null; wg-quick up sekawg$id; }
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then ufw allow $port/udp; ufw allow in on sekawg$id; fi
${GOST_SRV}# iperf3 listener on the tunnel IP: lets the panel measure the real bandwidth of this link
command -v iperf3 >/dev/null 2>&1 || {
  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3 >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q iperf3 >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then yum install -y -q iperf3 >/dev/null 2>&1 || true; fi
}
if command -v iperf3 >/dev/null 2>&1; then
cat > /etc/systemd/system/seka-iperf.service <<IPEOF
[Unit]
Description=SEKA TUNEL bandwidth test (iperf3 on the tunnel link)
After=network-online.target
[Service]
ExecStart=/usr/bin/iperf3 -s -B 10.66.$id.2
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
IPEOF
systemctl daemon-reload; systemctl enable --now seka-iperf >/dev/null 2>&1 || true
fi
# --- SEKA TUNEL reverse forwards: these ports on THIS server reach services on the IRAN server ---
sysctl -q -w net.ipv4.ip_forward=1 || true
iptables -t nat    -N SEKA_REV     2>/dev/null || true; iptables -t nat    -F SEKA_REV
iptables -t nat    -C PREROUTING  -j SEKA_REV 2>/dev/null || iptables -t nat -I PREROUTING 1 -j SEKA_REV
iptables -t nat    -N SEKA_REVPOST 2>/dev/null || true; iptables -t nat    -F SEKA_REVPOST
iptables -t nat    -C POSTROUTING -j SEKA_REVPOST 2>/dev/null || iptables -t nat -I POSTROUTING 1 -j SEKA_REVPOST
iptables -t nat    -A SEKA_REVPOST -o sekawg$id -j MASQUERADE
iptables -t filter -N SEKA_REVFWD  2>/dev/null || true; iptables -t filter -F SEKA_REVFWD
iptables -t filter -C FORWARD -j SEKA_REVFWD 2>/dev/null || iptables -t filter -I FORWARD 1 -j SEKA_REVFWD
iptables -t filter -A SEKA_REVFWD -i sekawg$id -j ACCEPT
${revrules}${fwdin}
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then ufw allow in on sekawg$id; fi
echo "Done. Tunnel address on this server: 10.66.$id.2 · reverse forwards: $revn · forwarded ports: $fwdn"
EOS
}

tun_script_join() {   # token host client_ip : the one-line join script the panel serves at /join/<token>
  local tok=$1 host=$2 cip=$3 r id fip port mtu fpriv ipub ty name tr cport revrules="" revn=0 rf lp dp rp p ephost
  r=$(awk -F'|' -v t="$tok" '$12==t{print;exit}' "$TUN" 2>/dev/null)
  [[ -n $r ]] || { echo "error: unknown or expired join link" >&2; return 1; }
  IFS='|' read -r id fip port mtu _ fpriv ipub _ _ _ ty _ name _ tr cport <<< "$r"
  ty=${ty:-rev}; tr=${tr:-udp}
  if [[ $(cut -d'|' -f2 <<< "$r") == pending ]]; then
    tun_join_setip "$tok" "$cip" >/dev/null || return 1
    fip=$cip
  fi
  ephost=$host
  if [[ $ephost == *:* ]]; then
    [[ ${ephost##*:} =~ ^[0-9]+$ ]] && ephost=${ephost%:*}   # strip the panel port from "host:port"
    [[ $ephost == *:* ]] && ephost="[$ephost]"                # bare IPv6 host needs brackets
  fi
  [[ -n $ephost ]] || ephost=$(hostname -I 2>/dev/null | awk '{print $1}')
  if [[ -s $REV ]]; then   # reverse forwards already defined for this tunnel are baked into the join script
    while IFS='|' read -r rf lp dp rp; do
      [[ $rf == "$fip" ]] || continue
      for p in $(proto_list "$rp"); do
        revrules+="iptables -t nat -A SEKA_REV -p $p --dport $lp -j DNAT --to-destination 10.66.$id.1:$dp"$'\n'
      done
      revn=$((revn + 1))
    done < "$REV"
  fi
  # BackPack-style forwarded ports of this tunnel: bake the kharej loopback redirect in as well
  local fwdin="" fwdn=0
  if [[ -s $CONF ]]; then
    while IFS='|' read -r fn fp fl fi fd; do
      [[ $fi == "10.66.$id.2" ]] || continue
      for p in $(proto_list "$fp"); do
        fwdin+="iptables -t nat -A SEKA_REV -i sekawg$id -p $p -d 10.66.$id.2 --dport $fd -j DNAT --to-destination 127.0.0.1:$fd"$'\n'
      done
      fwdn=$((fwdn + 1))
    done < "$CONF"
    [[ -n $fwdin ]] && fwdin=$'sysctl -q -w net.ipv4.conf.sekawg'"$id"$'.route_localnet=1 || true\n'"$fwdin"
  fi
  local epdecl="" lp
  lp=$(tr_local_port "$id")
  if [[ $ty == rev ]]; then
    if [[ $tr == udp ]]; then
      [[ -n $ephost ]] && epdecl=$'Endpoint = '"$ephost:$port"$'
PersistentKeepalive = 25
'
    else   # carried transport: WG dials the local gost feed, gost dials the Iran carrier port
      [[ -n $ephost ]] && epdecl=$'Endpoint = 127.0.0.1:'"$lp"$'
PersistentKeepalive = 25
'
    fi
  fi
  (( mtu >= 1200 && mtu <= 1500 )) || mtu=$(tr_mtu "$tr")
  # when the transport is not plain UDP, the foreign side runs a gost client that feeds WG
  GOST_CLI=""
  if [[ $tr != udp ]]; then
    local cp tok sec=""
    cp=$(tr_carrier_port "$id" "$cport")
    tok=$(cut -d'|' -f12 <<< "$r")
    [[ $tr == wss ]] && sec="?secure=false"
    GOST_CLI="# --- transport carrier: a gost client feeds the local WireGuard through $tr to Iran:$cp ---
if [[ ! -x /usr/local/bin/seka-gost ]]; then
  garch=amd64; [[ \$(uname -m) == aarch64 || \$(uname -m) == arm64 ]] && garch=arm64; [[ \$(uname -m) == armv7l ]] && garch=armv7; [[ \$(uname -m) == i686 || \$(uname -m) == i386 ]] && garch=386
  gtmp=\$(mktemp -d)
  curl -fsSL --retry 2 -o \$gtmp/g.tgz \"https://github.com/go-gost/gost/releases/download/v$GOST_VER/gost_${GOST_VER}_linux_\$garch.tar.gz\" \\
    && curl -fsSL --retry 2 -o \$gtmp/s.txt \"https://github.com/go-gost/gost/releases/download/v$GOST_VER/checksums.txt\" \\
    || { echo \"gost download failed - the transport carrier needs it\"; exit 1; }
  gwant=\$(awk -v f=\"gost_${GOST_VER}_linux_\$garch.tar.gz\" '\$2==f{print \$1}' \$gtmp/s.txt)
  [[ -z \$gwant ]] || { (cd \$gtmp && echo \"\$gwant  g.tgz\" | sha256sum -c >/dev/null) || { echo \"gost checksum FAILED\"; exit 1; }; }
  tar xzf \$gtmp/g.tgz -C \$gtmp gost 2>/dev/null || tar xzf \$gtmp/g.tgz -C \$gtmp
  install -m 755 \$gtmp/gost /usr/local/bin/seka-gost && rm -rf \$gtmp
fi
cat > /etc/systemd/system/seka-gostc$id.service <<GEOF
[Unit]
Description=SEKA TUNEL transport carrier (tunnel $id, client)
After=network-online.target
[Service]
ExecStart=/usr/local/bin/seka-gost -L \"udp://127.0.0.1:$lp/127.0.0.1:$port?keepalive=true\" -F \"relay+$tr://$tok@$ephost:$cp$sec\"
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
GEOF
systemctl daemon-reload; systemctl enable --now seka-gostc$id >/dev/null 2>&1
echo \"Transport carrier: $tr to $ephost:$cp (local feed 127.0.0.1:$lp)\"
"
  fi
  cat <<EOS
#!/usr/bin/env bash
# SEKA TUNEL join script (tunnel #$id${name:+ "$name"}, type: $ty). Run once, as root, on the KHAREJ server.
set -e
[ "\$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
if ! command -v wg-quick >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard
  elif command -v dnf >/dev/null 2>&1; then dnf install -y wireguard-tools
  elif command -v yum >/dev/null 2>&1; then yum install -y epel-release wireguard-tools
  else echo "install WireGuard first"; exit 1; fi
fi
mkdir -p /etc/wireguard
( umask 077; cat > /etc/wireguard/sekawg$id.conf <<'WGEOF'
[Interface]
Address = 10.66.$id.2/30
ListenPort = $port
PrivateKey = $fpriv
MTU = ${mtu:-1420}
PostUp = iptables -I INPUT -p udp --dport $port -j ACCEPT || true; iptables -I INPUT -i sekawg$id -j ACCEPT || true
PostDown = iptables -D INPUT -p udp --dport $port -j ACCEPT || true; iptables -D INPUT -i sekawg$id -j ACCEPT || true

[Peer]
PublicKey = $ipub
${epdecl}AllowedIPs = 10.66.$id.1/32
WGEOF
)
systemctl enable wg-quick@sekawg$id >/dev/null 2>&1 || true
systemctl restart wg-quick@sekawg$id 2>/dev/null || { wg-quick down sekawg$id 2>/dev/null; wg-quick up sekawg$id; }
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then ufw allow $port/udp; ufw allow in on sekawg$id; fi
command -v iperf3 >/dev/null 2>&1 || {
  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3 >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q iperf3 >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then yum install -y -q iperf3 >/dev/null 2>&1 || true; fi
}
if command -v iperf3 >/dev/null 2>&1; then
cat > /etc/systemd/system/seka-iperf.service <<IPEOF
[Unit]
Description=SEKA TUNEL bandwidth test (iperf3 on the tunnel link)
After=network-online.target
[Service]
ExecStart=/usr/bin/iperf3 -s -B 10.66.$id.2
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
IPEOF
systemctl daemon-reload; systemctl enable --now seka-iperf >/dev/null 2>&1 || true
fi
${GOST_CLI}# --- SEKA TUNEL reverse forwards: these ports on THIS server reach services on the Iran server ---
sysctl -q -w net.ipv4.ip_forward=1 || true
iptables -t nat    -N SEKA_REV     2>/dev/null || true; iptables -t nat    -F SEKA_REV
iptables -t nat    -C PREROUTING  -j SEKA_REV 2>/dev/null || iptables -t nat -I PREROUTING 1 -j SEKA_REV
iptables -t nat    -N SEKA_REVPOST 2>/dev/null || true; iptables -t nat    -F SEKA_REVPOST
iptables -t nat    -C POSTROUTING -j SEKA_REVPOST 2>/dev/null || iptables -t nat -I POSTROUTING 1 -j SEKA_REVPOST
iptables -t nat    -A SEKA_REVPOST -o sekawg$id -j MASQUERADE
iptables -t filter -N SEKA_REVFWD  2>/dev/null || true; iptables -t filter -F SEKA_REVFWD
iptables -t filter -C FORWARD -j SEKA_REVFWD 2>/dev/null || iptables -t filter -I FORWARD 1 -j SEKA_REVFWD
iptables -t filter -A SEKA_REVFWD -i sekawg$id -j ACCEPT
${revrules}${fwdin}
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then ufw allow in on sekawg$id; fi
echo "Done. Tunnel address on this server: 10.66.$id.2 · type: $ty · transport: $tr · reverse forwards: $revn · forwarded ports: $fwdn"
EOS
}

tunnel_cli() {
  case "${1:-}" in
    add)     shift; tun_add "$@";;
    join-open) shift; tun_add_rev "${1:-}" "${2:-turbo}" "${3:-}" "${4:-udp}" "${5:-}";;
    link)    tun_link "${2:-}";;
    script-join) shift; tun_script_join "${1:-}" "${2:-}" "${3:-}";;
    transport) shift; tun_transport "${1:-}" "${2:-}" "${3:-}";;
    mtuprobe) tun_probe_pub "${2:-}";;
    del)     tun_del "${2:-}";;
    script)  tun_script "${2:-}";;
    use)     tun_active "${2:-}" 1;;
    direct)  tun_active "${2:-}" 0;;
    sync)    tun_sync;;
    mtu)     tun_automtu "${2:-}";;
    preset)  tun_preset "${2:-}" "${3:-}";;
    reverse) case "${2:-}" in
               add)  rev_add "${3:-}" "${4:-}" "${5:-}" "${6:-tcp}";;
               del)  rev_del "${3:-}" "${4:-}";;
               list) rev_list;;
               test) rev_test "${3:-}" "${4:-}";;
               *) echo "Usage: $0 reverse add IP LPORT DPORT [proto] | del IP LPORT | list | test IP LPORT"; return 1;;
             esac;;
    repair)  repair_wg;;
    *) echo "Usage: $0 tunnel add IP [UDP_PORT] [MTU] [preset] [fwd|dir] [name] [transport] | join-open [UDP_PORT] [preset] [name] [transport] | link IP-or-ID | script IP | script-join TOKEN HOST CLIENT_IP | tcp|tcp|ws|wss|kcp|quic] [carrier_port] | use IP | direct IP | mtu IP | mtuprobe IP | preset IP [name] | reverse add|del|list|test ... | sync | repair"; return 1;;
  esac
}

kharej_join() {   # [url] : run on a FOREIGN server - fetch the join script from the Iran panel and bring the tunnel up
  local url=${1:-} sc
  banner
  echo "  ${C_BLD}Setup Kharej - join an Iran tunnel${C_RST}"; echo
  info "Paste the join link the Iran panel gave you (looks like https://IRAN:8443/join/<token>)."
  [[ -n $url ]] || read -rp "  Join link: " url
  url=$(printf '%s' "$url" | tr -d '"'\''')
  [[ $url =~ ^https?://[^[:space:]]+/join/[0-9a-f]{16,64}$ ]] || { err "That does not look like a SEKA TUNEL join link."; return 1; }
  info "Fetching the join script from the Iran server..."
  sc=$(curl -fsSLk --max-time 60 "$url") || { err "Could not fetch the link (is the Iran panel reachable from here?)"; return 1; }
  [[ $sc == *"SEKA TUNEL join script"* ]] || { err "The server did not return a SEKA TUNEL join script."; return 1; }
  bash -c "$sc"
  echo
  kharej_status
}

kharej_status() {   # the foreign-side view: every sekawg* link, its handshake age and its carrier
  local hs ifc n=0
  banner
  echo "  ${C_BLD}Kharej links (this server)${C_RST}"; echo
  for ifc in $(ip -o link show 2>/dev/null | awk -F': ' '/sekawg/{print $2}'); do
    n=$((n + 1))
    hs=$(wg show "$ifc" latest-handshakes 2>/dev/null | awk '{print $2}')
    local age="no handshake"
    [[ ${hs:-0} -gt 0 ]] && age="$(( ($(date +%s) - hs) / 60 )) min ago"
    printf "  %-12s %s\n" "$ifc" "$age"
  done
  (( n == 0 )) && info "No tunnels on this server yet - run: seka-tunel join '<link>'"
  return 0
}

reverse_menu() {   # ports on the foreign server that reach services on the Iran server
  banner; echo "  ${C_BLD}Reverse forwards${C_RST}"; echo
  info "The port opens on the FOREIGN server; whoever connects lands on a service of THIS (Iran) server, through the encrypted tunnel."
  info "Example: your vpn/panel runs on this Iran server; publish it on the foreign server's clean IP."
  local n=0 rf fip lp dp rp c
  if [[ -s $REV ]]; then
    printf "\n  ${C_BLD}%-3s %-17s %-13s %-13s %s${C_RST}\n" "#" "FOREIGN IP" "PORT (foreign)" "PORT (iran)" PROTO
    while IFS='|' read -r fip lp dp rp; do
      [[ -z $fip ]] && continue; n=$((n + 1))
      printf "  %-3s %-17s %-13s %-13s %s\n" "$n" "$fip" "$lp" "$dp" "$rp"
    done < "$REV"
  else
    info "No reverse forwards yet."
  fi
  echo
  echo "   1) Add a reverse forward       (foreign port -> an Iran service port)"
  echo "   2) Remove a reverse forward"
  echo "   3) Test a reverse forward      (12 probes through the whole loop)"
  echo "   4) Show the foreign script     (run it again on the foreign server after any change)"
  echo "   0) Back"; echo
  read -rp "  Select: " c
  case $c in
    1) read -rp "  Foreign server IP: " fip; read -rp "  Port on the FOREIGN server: " lp
       read -rp "  Port of the service on THIS (Iran) server: " dp; read -rp "  Protocol tcp/udp/both [tcp]: " rp
       if rev_add "$fip" "$lp" "$dp" "${rp:-tcp}"; then
         ok "Reverse forward saved."
         warn "Now show the foreign script (option 4) and run it on the foreign server again — the port opens there."
       else err "Failed."; fi;;
    2) read -rp "  Foreign server IP: " fip; read -rp "  Port on the foreign server: " lp
       rev_del "$fip" "$lp" && { ok "Removed."; warn "Run the foreign script again (option 4) to close the port there."; };;
    3) read -rp "  Foreign server IP: " fip; read -rp "  Port on the foreign server: " lp
       local res; res=$(rev_test "$fip" "$lp") && ok "Reverse test: $res" || err "${res#*: }";;
    4) read -rp "  Foreign server IP: " fip && tun_script "$fip";;
  esac
}

apply_rules() {
  sysctl -q -w net.ipv4.ip_forward=1 >/dev/null 2>&1
  local spec t chain parent
  for spec in "mangle PREROUTING SEKA_SEC" "mangle FORWARD SEKA_MSS" "nat PREROUTING SEKA_PRE" "nat POSTROUTING SEKA_POST" "filter FORWARD SEKA_FWD" "filter INPUT SEKA_IN"; do
    set -- $spec; t=$1; parent=$2; chain=$3
    iptables -t "$t" -N "$chain" 2>/dev/null || true
    iptables -t "$t" -F "$chain"
    iptables -t "$t" -C "$parent" -j "$chain" 2>/dev/null || iptables -t "$t" -I "$parent" 1 -j "$chain"
  done
  sec_cleanup
  local tid
  if [[ -s $TUN ]]; then   # keep TCP packets small enough for the tunnel MTU
    while IFS='|' read -r tid _; do
      [[ -n $tid ]] && iptables -t mangle -A SEKA_MSS -o "sekawg$tid" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    done < "$TUN"
  fi
  # reverse forwards: packets arriving from the foreign side for a service on this (Iran) server.
  # The foreign script DNATs kharej:listen -> 10.66.<id>.1:port; here we steer it to 127.0.0.1
  # so services that only listen on localhost work too (route_localnet makes that legal).
  if [[ -s $REV ]]; then
    local rf fip lp dp rp trow
    while IFS='|' read -r fip lp dp rp; do
      [[ -z $fip ]] && continue
      trow=$(tun_row "$fip"); [[ -n $trow ]] || continue
      tid=${trow%%|*}
      sysctl -q -w "net.ipv4.conf.sekawg$tid.route_localnet=1" >/dev/null 2>&1 || true
      for p in $(proto_list "$rp"); do
        iptables -t nat    -A SEKA_PRE -i "sekawg$tid" -p "$p" -d "10.66.$tid.1" --dport "$dp" -j DNAT --to-destination "127.0.0.1:$dp"
        iptables -t filter -A SEKA_IN  -i "sekawg$tid" -p "$p" --dport "$dp" -m comment --comment "seka-rev:$lp" -j ACCEPT
      done
    done < "$REV"
  fi
  [[ -s $CONF ]] || return 0
  local name proto lport ip dport p act tip
  while IFS='|' read -r name proto lport ip dport; do
    [[ -z $name ]] && continue
    tip=$(tun_target "$ip")
    act=ACCEPT; [[ -s $BLK ]] && grep -qx "$lport" "$BLK" && act=DROP
    sec_apply "$lport" "$(proto_list "$proto")"
    for p in $(proto_list "$proto"); do
      iptables -t nat    -A SEKA_PRE  -p "$p" --dport "$lport" -j DNAT --to-destination "$tip:$dport"
      iptables -t nat    -A SEKA_POST -p "$p" -d "$tip" --dport "$dport" -j MASQUERADE
      iptables -t filter -A SEKA_FWD  -p "$p" -d "$tip" --dport "$dport" -m comment --comment "drc:$lport" -j "$act"
      iptables -t filter -A SEKA_FWD  -p "$p" -s "$tip" --sport "$dport" -m comment --comment "drc:$lport" -j "$act"
    done
  done < "$CONF"
}

ensure_boot() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  echo "net.ipv4.ip_forward=1" > "$SYSCTL_FWD"
  local self; self=$(readlink -f "$0" 2>/dev/null || echo "$0")
  if [[ $self != "$BIN" && -f $self ]]; then
    install -m 755 "$self" "$BIN" 2>/dev/null || cp "$self" "$BIN"
  fi
  command -v systemctl >/dev/null 2>&1 || return 0
  cat > "$UNIT" <<EOF
[Unit]
Description=SEKA TUNEL port forwards
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIN apply

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable seka-tunel.service >/dev/null 2>&1
}

counters() {   # echo "<packets> <bytes>" for a rule
  local p out pk=0 by=0
  for p in $(proto_list "$1"); do
    out=$(iptables -t nat -nvxL SEKA_PRE 2>/dev/null | awk -v p="$p" -v n="$(proto_num "$p")" -v d="dpt:$2 " \
      '($4==p||$4==n) && index($0,d){a+=$1;b+=$2} END{print a+0, b+0}')
    pk=$(( pk + ${out% *} )); by=$(( by + ${out#* } ))
  done
  echo "$pk $by"
}

tcp_time() {   # echo connect time in ms, or "fail"
  local s e
  s=$(date +%s%N)
  if timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null </dev/null; then
    e=$(date +%s%N); echo $(( (e - s) / 1000000 ))
  else
    echo fail
  fi
}

# ------------------------------------------------------ migration ---------

migrate_legacy() {   # one-time upgrade from the old FWPanel
  local old="/etc/fw""panel" o="FW""P_"
  [[ -d $old ]] || return 0
  if [[ ! -s $CONF && -s $old/rules.conf ]]; then
    mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
    cp "$old/rules.conf" "$CONF"
    [[ -f $old/default_ip ]] && cp "$old/default_ip" "$DEF_IP_FILE"
  fi
  local spec t parent chain
  for spec in "nat PREROUTING ${o}PRE" "nat POSTROUTING ${o}POST" "filter FORWARD ${o}FWD"; do
    set -- $spec; t=$1; parent=$2; chain=$3
    iptables -t "$t" -D "$parent" -j "$chain" 2>/dev/null
    iptables -t "$t" -F "$chain" 2>/dev/null
    iptables -t "$t" -X "$chain" 2>/dev/null
  done
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now fw"panel.service" >/dev/null 2>&1
    rm -f "/etc/systemd/system/fw""panel.service"; systemctl daemon-reload >/dev/null 2>&1
  fi
  rm -f "/usr/local/bin/fw""panel" "/etc/sysctl.d/99-fw""panel-forward.conf"
  mv "$old" "$old.migrated"
  apply_rules; ensure_boot
  ok "Migrated from FWPanel to SEKA TUNEL (old settings kept in $old.migrated)."
}

# ------------------------------------------------------- web panel --------

WEB_DIR="/usr/local/lib/seka-tunel"
WEB_PY="$WEB_DIR/web.py"
WEB_UI="$WEB_DIR/index.html"
WEB_UNIT="/etc/systemd/system/seka-tunel-web.service"
WEB_CFG="$CONF_DIR/web.json"

web_write_files() {
  mkdir -p "$WEB_DIR"
  cat > "$WEB_PY" <<'PYEOF'
#!/usr/bin/env python3
import json, os, re, ssl, subprocess, hashlib, hmac, secrets, socket, threading, time, ipaddress, sys
import shutil, tarfile, io, base64, urllib.request, collections, html
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie

D = "/etc/seka-tunel"; CONF = D + "/rules.conf"; WEB = D + "/web.json"; DEF = D + "/default_ip"
BIN = "/usr/local/bin/seka-tunel"; UI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
CERT = D + "/web.crt"; KEY = D + "/web.key"; LOGF = "/var/log/seka-tunel.log"; SECF = D + "/security.conf"
LOCK = threading.Lock(); CLOCK = threading.Lock(); SESS = {}; FAILS = {}
LOGS = collections.deque(maxlen=300); HEALTH = {}; SYS = {}
JOINMISS = {}   # rate limiting for the public /join/<token> endpoint
CTMISS = {}     # rate limiting for the public /ctest/<id> + report endpoints

# ------------------------------------------------------------ config / log
def cfg():
    try: return json.load(open(WEB))
    except Exception: return {"port": 8443, "tls": False}

def save(c):
    os.makedirs(D, exist_ok=True)
    with open(WEB, "w") as f: json.dump(c, f)
    os.chmod(WEB, 0o600)

def upd(**kw):
    with CLOCK:
        c = cfg(); c.update(kw); save(c)

def log(level, msg):
    LOGS.append({"t": time.time(), "l": level, "m": msg})
    try:
        with open(LOGF, "a") as f: f.write("%s [%s] %s\n" % (time.strftime("%F %T"), level, msg))
    except Exception: pass

def tg_send(text):
    c = cfg()
    if not (c.get("tg_token") and c.get("tg_chat")): return "Telegram is not configured"
    try:
        u = "%s/bot%s/sendMessage" % (c.get("tg_api") or "https://api.telegram.org", c["tg_token"])
        u = u.replace("//bot", "/bot")
        req = urllib.request.Request(u, data=json.dumps({"chat_id": c["tg_chat"], "text": text}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read(); return None
    except Exception as e: return "%s" % type(e).__name__

def notify(text):
    def run():
        e = tg_send(text)
        if e and e != "Telegram is not configured": log("warn", "Telegram send failed: " + e)
    threading.Thread(target=run, daemon=True).start()

def mkhash(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex()

# ------------------------------------------------- audit / TOTP (stdlib only)
AUDF = "/var/log/seka-tunel-audit.log"

def audit(action, detail="", ip="-"):
    try:
        with open(AUDF, "a") as f: f.write("%s|%s|%s|%s\n" % (time.strftime("%F %T"), ip, action, str(detail)[:300]))
    except Exception: pass

def audit_read(n=300):
    out = []
    try:
        with open(AUDF) as f: out = [l.rstrip("\n") for l in f if l.strip()][-n:]
    except Exception: pass
    return out

def b32secret(): return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

def totp_code(secret, off=0):
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    c = int(time.time() // 30) + off
    h = hmac.new(key, c.to_bytes(8, "big"), hashlib.sha1).digest()
    o = h[19] & 15
    return "%06d" % ((int.from_bytes(h[o:o + 4], "big") & 0x7FFFFFFF) % 1000000)

def totp_ok(secret, code):
    try: return any(hmac.compare_digest(totp_code(secret, o), code) for o in (0, 1, -1))
    except Exception: return False

def rec_use(code, c):   # one-time recovery codes: c["rec"] = [sha256hex, ...]
    h = hashlib.sha256(code.strip().encode()).hexdigest()
    lst = c.get("rec") or []
    for x in lst:
        if hmac.compare_digest(x, h):
            lst.remove(x); upd(rec=lst); return True
    return False

# ------------------------------------------------------------------ rules
def read_rules():
    out = []
    try:
        for l in open(CONF):
            p = l.rstrip("\n").split("|")
            if len(p) == 5: out.append(dict(name=p[0], proto=p[1], lport=int(p[2]), ip=p[3], dport=int(p[4])))
    except FileNotFoundError: pass
    return out

def write_rules(rs):
    os.makedirs(D, exist_ok=True)
    with open(CONF + ".tmp", "w") as f:
        for r in rs: f.write("%s|%s|%d|%s|%d\n" % (r["name"], r["proto"], r["lport"], r["ip"], r["dport"]))
    quota_tick()
    os.replace(CONF + ".tmp", CONF)
    subprocess.run([BIN, "apply"], timeout=20)
    quota_rebase()

def sec_read():
    out = {}
    try:
        for l in open(SECF):
            p = l.rstrip("\n").split("|")
            if len(p) >= 4: out[p[0]] = dict(allow=p[1], maxc=int(p[2] or 0), rate=int(p[3] or 0))
    except (FileNotFoundError, ValueError): pass
    return out

def sec_file(cur):
    os.makedirs(D, exist_ok=True)
    with open(SECF + ".tmp", "w") as f:
        for k, v in cur.items(): f.write("%s|%s|%d|%d\n" % (k, v["allow"], v["maxc"], v["rate"]))
    os.replace(SECF + ".tmp", SECF)

def sec_save(lport, d, run=True):
    raw = d.get("allow") or []
    if isinstance(raw, str): raw = re.split(r"[\s,]+", raw)
    raw = [x.strip() for x in raw if x and x.strip()]
    if len(raw) > 200: raise ValueError("Too many IPs")
    nets = []
    for x in raw:
        try: n = ipaddress.ip_network(x, strict=False)
        except Exception: raise ValueError("Invalid IP or network")
        if n.version != 4: raise ValueError("Invalid IP or network")
        nets.append(x if "/" in x else str(n.network_address))
    try: maxc = int(d.get("maxc") or 0); rate = int(d.get("rate") or 0)
    except Exception: raise ValueError("Numbers out of range")
    if not (0 <= maxc <= 1000000 and 0 <= rate <= 100000000): raise ValueError("Numbers out of range")
    cur = sec_read(); k = str(lport)
    if nets or maxc > 0 or rate > 0: cur[k] = dict(allow=",".join(nets), maxc=maxc, rate=rate)
    else: cur.pop(k, None)
    sec_file(cur)
    if run: subprocess.run([BIN, "apply"], timeout=20)

TUNF = D + "/tunnels.conf"

def tunnels():
    out = {}
    try:
        for l in open(TUNF):
            p = l.rstrip("\n").split("|")
            if len(p) >= 9:
                pend = p[1] == "pending"   # rev tunnel created in the wizard; the kharej has not fetched its join link yet
                ty = p[10] if len(p) > 10 and p[10] in ("fwd", "dir", "rev") else "fwd"
                tr = p[14] if len(p) > 14 and p[14] in ("udp", "tcp", "ws", "wss", "kcp", "quic", "gaaf") else "udp"
                cp = int(p[15]) if len(p) > 15 and p[15].isdigit() else 0
                key = ("pending%s" % p[0]) if pend else p[1]
                out[key] = dict(id=int(p[0]), ip=("pending" if pend else p[1]), port=int(p[2]), mtu=int(p[3]), active=p[8] == "1",
                                preset=(p[9] if len(p) > 9 and p[9] in ("balanced", "turbo", "throughput", "gaming") else ""),
                                type=ty, pending=pend, name=(p[12] if len(p) > 12 else ""), has_link=bool(len(p) > 11 and p[11]),
                                tr=tr, cport=cp)
    except (FileNotFoundError, ValueError): pass
    return out

def tun_by(k):   # look a tunnel up by its foreign IP, its id, or its pending-<id> key
    ts = tunnels()
    return ts.get(k) or next((t for t in ts.values() if str(t["id"]) == str(k)), None)

REVF = D + "/reverse.conf"

def rev_rows():
    out = []
    try:
        for l in open(REVF):
            p = l.rstrip("\n").split("|")
            if len(p) == 4: out.append(dict(ip=p[0], lport=int(p[1]), dport=int(p[2]), proto=p[3]))
    except (FileNotFoundError, ValueError): pass
    return out

def peer(t): return "10.66.%d.2" % t["id"]

def eff_ip(ip):   # where traffic for this foreign IP really goes (the tunnel address when the tunnel is switched on)
    t = tunnels().get(ip)
    return peer(t) if t and t["active"] else ip

def tunnel_info():
    now = time.time(); out = []
    for t in tunnels().values():
        d = dict(t, up=False, age=None, rx=0, tx=0, peer=peer(t))
        try:
            ln = subprocess.run(["wg", "show", "sekawg%d" % t["id"], "dump"], capture_output=True, text=True, timeout=5).stdout.splitlines()
            if len(ln) > 1:
                f = ln[1].split("\t"); hs = int(f[4]); d.update(rx=int(f[5]), tx=int(f[6]))
                if hs: d.update(age=int(now - hs), up=now - hs < 240)
        except Exception: pass
        out.append(d)
    return out

def tun_cmd(*a, t=180):
    try: r = subprocess.run([BIN, "tunnel", *a], capture_output=True, text=True, timeout=t)
    except Exception: raise ValueError("Command failed")
    if r.returncode:
        msg = (r.stderr or r.stdout).strip().splitlines()
        raise ValueError(re.sub(r"^error: ", "", msg[-1])[:200] if msg else "Command failed")
    return r.stdout

def summarize(v):
    ok = [x for x in v if x is not None]; n = len(v)
    if not ok: return dict(ok=False, loss=100)
    j = sum(abs(a - b) for a, b in zip(ok, ok[1:])) / (len(ok) - 1) if len(ok) > 1 else 0
    return dict(ok=True, min=round(min(ok)), avg=round(sum(ok) / len(ok)), max=round(max(ok)), jitter=round(j, 1), loss=round(100 * (n - len(ok)) / n))

def tcp_series(ip, port, n=12, to=4, gap=0.15):
    # BackPack-style probe: TCP connect timing (ICMP is often blocked where tunnel traffic flows fine)
    v = []
    for _ in range(n):
        s = time.time()
        try: socket.create_connection((ip, port), to).close(); v.append((time.time() - s) * 1000)
        except Exception: v.append(None)
        time.sleep(gap)
    return summarize(v)

def udp_egress():
    # one DNS query over UDP to three resolvers: does UDP leave this machine at all? (WireGuard needs it)
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    for dns in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5)
            s.sendto(q, (dns, 53)); s.recvfrom(512); s.close(); return True
        except Exception:
            try: s.close()
            except Exception: pass
    return False

def recommend(res, udp_ok):
    # maps the measured link to a SEKA TUNEL preset, the way BackPack's Link Test maps it to a transport
    if not udp_ok:
        return dict(preset="", label="udp_blocked", fa="خروجی UDP بسته است")
    q = (res.get("tunnel") or {}).get("tcp") or res.get("direct") or {}
    if not q.get("ok"): return dict(preset="", label="unreachable", fa="مقصد پاسخ نمی‌دهد")
    loss, jit, avg = q.get("loss", 100), q.get("jitter", 0), q.get("avg", 0)
    if loss >= 20: return dict(preset="gaming", label="unstable", fa="لینک ناپایدار — پیشنهاد: Gaming")
    if loss >= 2:  return dict(preset="throughput", label="lossy", fa="پکت‌خسری %s%% — پیشنهاد: Throughput" % loss)
    if avg and jit > avg / 3: return dict(preset="turbo", label="jittery", fa="لینک شلوغ/نوسانی — پیشنهاد: Turbo")
    return dict(preset="turbo", label="clean", fa="لینک تمیز و پایدار — Turbo مناسب است")

def transport_test(ip, port):
    # BackPack-style Link Test: 12 TCP probes direct vs tunnel + UDP egress + a preset recommendation
    t = tun_by(ip)
    ports = [r["dport"] for r in read_rules() if r["ip"] == ip and r["proto"] != "udp"]
    port = port or (ports[0] if ports else 443)
    res = dict(ip=ip, port=port, direct=None, tunnel=None, verdict="no_tunnel")
    with ThreadPoolExecutor(3) as ex:
        fd = ex.submit(tcp_series, ip, port)
        ft = ex.submit(tcp_series, peer(t), port) if t else None
        fu = ex.submit(udp_egress)
        res["direct"] = fd.result()
        if t: res["tunnel"] = dict(tcp=ft.result())
        res["udp"] = fu.result()
    if t:
        up = next((x["up"] for x in tunnel_info() if x["ip"] == ip), False); w = res["tunnel"]["tcp"]; d = res["direct"]
        if not w["ok"]: res["verdict"] = "wg_nosvc" if up else "wg_down"
        elif not d["ok"]: res["verdict"] = "wg"
        else:
            sd = d["avg"] + 15 * d["loss"]; sw = w["avg"] + 15 * w["loss"]
            res["verdict"] = "wg" if sw <= sd * 1.3 + 10 else "direct"
    res["rec"] = recommend(res, res["udp"])
    return res

def rev_test(ip, lport):
    # full reverse loop: Iran -> foreign tunnel IP:listen -> foreign DNAT -> back to the Iran service
    t = tun_by(ip)
    if not t: raise ValueError("no_tunnel")
    if not any(r["ip"] == ip and r["lport"] == int(lport) for r in rev_rows()): raise ValueError("no_reverse")
    return tcp_series(peer(t), int(lport))

def bwtest(ip):
    # real throughput of the encrypted link: iperf3 UDP to the iperf3 listener on the foreign tunnel IP
    t = tun_by(ip)
    if not t: raise ValueError("no_tunnel")
    if not shutil.which("iperf3"):
        for pm in (["apt-get", "install", "-y", "-qq", "iperf3"], ["dnf", "install", "-y", "iperf3"], ["yum", "install", "-y", "iperf3"]):
            if shutil.which(pm[0]):
                subprocess.run(pm, capture_output=True, timeout=300); break
    if not shutil.which("iperf3"): raise ValueError("no_iperf")
    try:
        r = subprocess.run(["iperf3", "-c", peer(t), "-u", "-b", "0", "-t", "5", "-J"], capture_output=True, text=True, timeout=45)
    except Exception: raise ValueError("bw_fail")
    if r.returncode: raise ValueError("bw_nosvc")
    try:
        s = json.loads(r.stdout).get("end", {}).get("sum_sent") or {}
        assert s.get("bits_per_second")
    except Exception: raise ValueError("bw_fail")
    return dict(mbps=round(s.get("bits_per_second", 0) / 1e6, 1), jitter=round(s.get("jitter_ms", 0), 2),
                loss=round(s.get("lost_percent", 0), 1), pps=round(s.get("packets", 0) / 5), mtu=t.get("mtu"))

# --------------------------------------------------- connection test (BackPack-style)
CTF = D + "/conntest.json"
CTF2 = D + "/ctest.json"   # two-server connection test: {"id","tport","uport","until","report"}
CT = {"running": False, "result": None}

def ctest_script(cid, host, tport, uport, api):
    # the script the kharej runs for the two-server test: real probes (ICMP + TCP echo + UDP echo),
    # a table printed on BOTH sides, and the report posted back to this panel
    host = str(host).split(":")[0]
    sc = """#!/usr/bin/env bash
# SEKA TUNEL two-server connection test - run as root on the KHAREJ server
IRAN="@HOST@"; TPORT=@TPORT@; UPORT=@UPORT@; RID="@CID@"; API="@API@"
icmp='{"ok":false,"loss":100}'; tcp='{"ok":false}'; udp='{"ok":false}'
pl=$(ping -4 -q -c 10 -W 1 "$IRAN" 2>/dev/null | tail -2)
loss=$(sed -n 's/.*, \\([0-9.]*\\)% packet loss.*/\\1/p' <<<"$pl" | tail -1)
rtt=$(sed -n 's@.* = [0-9.]*/\\([0-9.]*\\)/[0-9.]*/\\([0-9.]*\\).*@\\1 \\2@p' <<<"$pl" | tail -1)
avg=${rtt%% *}; jit=${rtt##* }
if [[ -n $loss && $loss != 100 ]]; then
  icmp=$(printf '{"ok":true,"loss":%s,"avg":%s,"jit":%s}' "$loss" "${avg:-0}" "${jit:-0}")
fi
if command -v python3 >/dev/null 2>&1; then
  tcp=$(python3 - "$IRAN" "$TPORT" <<'PYP'
import json,socket,sys,time
h,p=sys.argv[1],int(sys.argv[2]); ok=[]; n=12
for _ in range(n):
    try:
        t0=time.time(); s=socket.create_connection((h,p),3); s.sendall(b"seka-ctest")
        d=s.recv(4096); s.close()
        if d==b"seka-ctest": ok.append(round((time.time()-t0)*1000,1))
    except Exception: pass
print(json.dumps({"ok":bool(ok),"loss":round(100*(n-len(ok))/n),"avg":round(sum(ok)/len(ok),1) if ok else None,"jit":round(max(ok)-min(ok),1) if len(ok)>1 else None}))
PYP
) || tcp='{"ok":false}'
  udp=$(python3 - "$IRAN" "$UPORT" <<'PYP'
import json,socket,sys,time
h,p=sys.argv[1],int(sys.argv[2]); ok=[]; n=20
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1.5)
for i in range(n):
    try:
        t0=time.time(); s.sendto(b"seka-ctest-%d"%i,(h,p)); d,_=s.recvfrom(2048)
        if d==b"seka-ctest-%d"%i: ok.append(round((time.time()-t0)*1000,1))
    except Exception: pass
s.close()
print(json.dumps({"ok":bool(ok),"loss":round(100*(n-len(ok))/n),"avg":round(sum(ok)/len(ok),1) if ok else None,"jit":round(max(ok)-min(ok),1) if len(ok)>1 else None}))
PYP
) || udp='{"ok":false}'
else
  okc=0; tots=""
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    t0=$(date +%s%N)
    if timeout 3 bash -c "exec 3<>/dev/tcp/$IRAN/$TPORT" 2>/dev/null </dev/null; then
      t1=$(date +%s%N); okc=$((okc+1)); tots="$tots $(( (t1-t0)/1000000 ))"
    fi
  done
  avgc=$(printf '%s\\n' $tots | awk '{s+=$1;n++} END{if(n)printf "%.1f",s/n}')
  [[ -n $avgc ]] && tcp=$(printf '{"ok":true,"loss":%d,"avg":%s}' $(( (12-okc)*100/12 )) "$avgc")
  echo "  (python3 not found - TCP measured via /dev/tcp, UDP skipped)"
fi
echo
echo "  SEKA TUNEL two-server test:  KHAREJ  ->  IRAN ($IRAN)"
if command -v python3 >/dev/null 2>&1; then
python3 - "$icmp" "$tcp" "$udp" <<'PYP'
import json,sys
def g(j,k):
    try: v=json.loads(j).get(k); return "-" if v is None else v
    except Exception: return "-"
rows=[("ping (ICMP)",g(sys.argv[1],"avg"),g(sys.argv[1],"jit"),g(sys.argv[1],"loss")),
      ("tcp echo",g(sys.argv[2],"avg"),g(sys.argv[2],"jit"),g(sys.argv[2],"loss")),
      ("udp echo",g(sys.argv[3],"avg"),g(sys.argv[3],"jit"),g(sys.argv[3],"loss"))]
print("  | %-10s | %8s | %8s | %6s |" % ("path","avg ms","jitter","loss%"))
print("  " + "-"*42)
for r in rows: print("  | %-10s | %8s | %8s | %5s%% |" % r)
PYP
else
  echo "  icmp: $icmp"; echo "  tcp: $tcp"
fi
curl -fsSLk --max-time 10 -X POST -H 'Content-Type: application/json' \\
  -d "{\\"icmp\\":$icmp,\\"tcp\\":$tcp,\\"udp\\":$udp}" \\
  "$API/api/ctest/report?id=$RID" >/dev/null 2>&1 \\
  && echo "  report sent - open the panel's connection-test page to see it on both sides" \\
  || echo "  panel unreachable - the table above is still valid"
echo
"""
    return (sc.replace("@HOST@", host).replace("@TPORT@", str(int(tport))).replace("@UPORT@", str(int(uport)))
              .replace("@CID@", cid).replace("@API@", api))

def ping_stats(host, n=10):
    # latency / jitter / loss of a real ICMP ping (jitter = the mdev field ping already computes)
    try:
        r = subprocess.run(["ping", "-4", "-n", "-q", "-c", str(n), "-W", "1", host], capture_output=True, text=True, timeout=25)
        loss = re.search(r"([\d.]+)% packet loss", r.stdout)
        rtt = re.search(r"= [\d.]+/([\d.]+)/([\d.]+)/([\d.]+)" , r.stdout)
        if not loss: return None
        d = dict(loss=round(float(loss.group(1))))
        if rtt: d.update(avg=round(float(rtt.group(1))), mx=round(float(rtt.group(2))), jitter=round(float(rtt.group(3)), 1))
        d["ok"] = d["loss"] < 100 and "avg" in d
        return d
    except Exception: return None

def dl_speed():
    # plain HTTPS download from Cloudflare's speed endpoint -> Mbit/s of the direct internet path
    try:
        t0 = time.time(); n = 0
        req = urllib.request.Request("https://speed.cloudflare.com/__down?bytes=15000000", headers={"User-Agent": "SEKA TUNEL"})
        with urllib.request.urlopen(req, timeout=25) as r:
            while True:
                b = r.read(65536)
                if not b: break
                n += len(b)
        dt = time.time() - t0
        return round(n * 8 / dt / 1e6, 1) if dt > 0.2 and n > 1000000 else None
    except Exception: return None

def conntest_run():
    res = dict(t=time.time())
    with ThreadPoolExecutor(4) as ex:
        f1 = ex.submit(ping_stats, "4.2.2.4"); f2 = ex.submit(ping_stats, "1.1.1.1")
        f3 = ex.submit(dl_speed); fu = ex.submit(udp_egress)
        res["g1"], res["g2"], res["dl"], res["udp"] = f1.result(), f2.result(), f3.result(), fu.result()
    res["tunnels"] = []
    for t in tunnel_info():
        e = dict(id=t["id"], ip=t["ip"], name=t.get("name", ""), up=t["up"], type=t.get("type", "fwd"), active=t["active"])
        if t["up"]:
            e.update(ping_stats("10.66.%d.2" % t["id"]) or {"ok": False})
            try: e["mtu"] = int(tun_cmd("mtuprobe", str(t["id"]), t=150).strip() or 0) or None
            except Exception: e["mtu"] = None
        res["tunnels"].append(e)
    # the BackPack-style banner: best method, its numbers, and the preset to go with it
    tun = next((x for x in res["tunnels"] if x.get("up") and x.get("ok")), None)
    g = tun or res["g1"] or res["g2"] or {}
    rec = dict(preset="", label="", fa="")
    if res["udp"] is False:
        rec.update(label="udp_blocked", fa="خروجی UDP بسته است — تانل WireGuard بالا نمی‌آید؛ اول UDP را باز کن")
    elif tun:
        rec.update(label="tunnel", fa="تانل رمزنگاری‌شده سالم است — فورواردها را روی همین بگذار",
                   preset=(tun_preset_of(tun["id"]) or "turbo"))
    elif g.get("ok"):
        rec.update(label="direct", fa="تانلی برقرار نیست — لینک مستقیم سالم است؛ یک تانل بساز")
    else:
        rec.update(label="offline", fa="هیچ مقاصدی پاسخ نمی‌دهند — اتصال سرور را بررسی کن")
    res["rec"] = rec
    jsave(CTF, res)
    return res

def tun_preset_of(tid):
    t = tun_by(str(tid))
    return (t or {}).get("preset", "")

def counters():
    c = {}
    try: out = subprocess.run(["iptables", "-t", "nat", "-nvxL", "SEKA_PRE"], capture_output=True, text=True, timeout=5).stdout
    except Exception: return c
    for l in out.splitlines():
        f = l.split(); m = re.search(r"dpt:(\d+)", l)
        if len(f) > 3 and m and f[0].isdigit():
            k = ({"6": "tcp", "17": "udp"}.get(f[3], f[3]), int(m.group(1)))
            a = c.setdefault(k, [0, 0]); a[0] += int(f[0]); a[1] += int(f[1])
    return c

def tcp_ms(ip, port):
    s = time.time()
    try:
        socket.create_connection((ip, port), 4).close()
        return int((time.time() - s) * 1000)
    except Exception: return None

def validate(d):
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(d.get("name") or ""))
    proto = d.get("proto", "tcp")
    if proto not in ("tcp", "udp", "both"): raise ValueError("Invalid protocol")
    try: lport = int(d.get("lport")); dport = int(d.get("dport") or lport)
    except Exception: raise ValueError("Invalid port")
    if not (1 <= lport <= 65535 and 1 <= dport <= 65535): raise ValueError("Port out of range")
    try: ip = str(ipaddress.IPv4Address(str(d.get("ip")).strip()))
    except Exception: raise ValueError("Invalid IP")
    if lport == cfg().get("port"): raise ValueError("This port is used by the web panel")
    for r in read_rules():
        if r["lport"] == lport and (r["proto"] == proto or "both" in (r["proto"], proto)): raise ValueError("A forward on this port already exists")
    return dict(name=name or "fw%d" % lport, proto=proto, lport=lport, ip=ip, dport=dport)

def split_ports(v):
    out = []
    for x in re.split(r"[,\s\u060c;]+", str(v or "")):
        if not x: continue
        m = re.fullmatch(r"(\d+)-(\d+)", x)
        if m:   # range such as 2000-2010
            a, b = int(m.group(1)), int(m.group(2))
            if a > b or b - a >= 50: raise ValueError("Invalid port range (max 50 ports)")
            out += [str(p) for p in range(a, b + 1)]
        else: out.append(x)
    return out

def validate_many(d):
    # "lport" may hold several ports ("8899,2044"). All-or-nothing: if one is invalid, nothing is added.
    ls = split_ports(d.get("lport")); ds = split_ports(d.get("dport"))
    if not ls: raise ValueError("Invalid port")
    if len(ls) > 50: raise ValueError("Too many ports (max 50)")
    if len(ds) > 1 and len(ds) != len(ls): raise ValueError("Destination ports must be one value or the same count as listen ports")
    base = str(d.get("name") or "").strip()
    out = []
    for i, l in enumerate(ls):
        dd = dict(d, lport=l, dport=(ds[i] if len(ds) > 1 else ds[0] if ds else ""))
        if len(ls) > 1: dd["name"] = ("%s-%s" % (base, l)) if base else ""
        try: out.append(validate(dd))
        except ValueError as e:
            if len(ls) > 1: raise ValueError("%s: %s" % (l, e))
            raise
    if len({r["lport"] for r in out}) != len(out): raise ValueError("Duplicate port in the list")
    return out

# -------------------------------------------------------- system sampling
def sysval(k):
    try: return open("/proc/sys/" + k.replace(".", "/")).read().strip()
    except Exception: return "?"

def sampler():
    prev = None
    while True:
        try:
            v = list(map(int, open("/proc/stat").readline().split()[1:])); idle = v[3] + v[4]; tot = sum(v)
            cpu = SYS.get("cpu", 0)
            if prev and tot > prev[1]: cpu = round(100 * (1 - (idle - prev[0]) / (tot - prev[1])), 1)
            prev = (idle, tot)
            mi = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo") if ":" in l}
            du = shutil.disk_usage("/"); rx = tx = 0
            for l in list(open("/proc/net/dev"))[2:]:
                n, d = l.split(":", 1); f = d.split()
                if n.strip() != "lo": rx += int(f[0]); tx += int(f[8])
            SYS.update(cpu=cpu, ram_total=mi["MemTotal"] * 1024, ram_used=(mi["MemTotal"] - mi.get("MemAvailable", 0)) * 1024,
                       disk_total=du.total, disk_used=du.used, rx=rx, tx=tx, t=time.time(), load=os.getloadavg()[0],
                       up=int(float(open("/proc/uptime").read().split()[0])))
        except Exception: pass
        time.sleep(3)

# ------------------------------------------------------ monitor / watchdog
def probe(r):
    return r, tcp_ms(eff_ip(r["ip"]), r["dport"])

def monitor():
    time.sleep(5)
    while True:
        try:
            rs = [r for r in read_rules() if r["proto"] != "udp"]
            keys = {"%d/%s" % (r["lport"], r["proto"]) for r in rs}
            for k in list(HEALTH):
                if k not in keys: HEALTH.pop(k)
            with ThreadPoolExecutor(8) as ex:
                for r, ms in ex.map(probe, rs):
                    k = "%d/%s" % (r["lport"], r["proto"]); now = time.time()
                    h = HEALTH.setdefault(k, dict(ok=None, ms=None, since=now, hist=collections.deque(maxlen=40), fails=0))
                    h["hist"].append(ms); h["ms"] = ms
                    if ms is not None:
                        h["fails"] = 0
                        if h["ok"] is not True:
                            if h["ok"] is False:
                                log("info", "%s is back up (%d ms)" % (r["name"], ms)); notify("🟢 %s (:%d → %s:%d) is back up" % (r["name"], r["lport"], r["ip"], r["dport"]))
                            h["ok"] = True; h["since"] = now
                    else:
                        h["fails"] += 1
                        if h["fails"] >= 2 and h["ok"] is not False:
                            h["ok"] = False; h["since"] = now
                            log("warn", "%s is DOWN: %s:%d unreachable" % (r["name"], r["ip"], r["dport"]))
                            notify("🔴 %s (:%d → %s:%d) is DOWN" % (r["name"], r["lport"], r["ip"], r["dport"]))
            watchdog()
            try: wg_watch()
            except Exception as e: log("warn", "wg_watch error: %s" % type(e).__name__)
            try: traffic_tick()
            except Exception: pass
            try: tg_daily_jobs()
            except Exception: pass
            c = cfg(); cpu = SYS.get("cpu", 0); ram = 100 * SYS.get("ram_used", 0) / max(SYS.get("ram_total", 1), 1)
            if (cpu > 90 or ram > 92) and time.time() - c.get("_lastres", 0) > 1800:
                upd(_lastres=time.time()); log("warn", "High resource use: CPU %.0f%% RAM %.0f%%" % (cpu, ram)); notify("⚠️ High resource use: CPU %.0f%% · RAM %.0f%%" % (cpu, ram))
        except Exception as e: log("warn", "monitor error: %s" % type(e).__name__)
        time.sleep(15)

def watchdog():
    exp = sum(2 if r["proto"] == "both" else 1 for r in read_rules())
    try: out = subprocess.run(["iptables", "-t", "nat", "-S", "SEKA_PRE"], capture_output=True, text=True, timeout=5).stdout
    except Exception: return
    got = sum(1 for l in out.splitlines() if l.startswith("-A SEKA_PRE"))
    if got != exp:
        subprocess.run([BIN, "apply"], timeout=20)
        log("warn", "Watchdog: forwarding rules were missing (%d/%d) and have been restored" % (got, exp))
        notify("♻️ Watchdog restored forwarding rules (%d/%d)" % (got, exp))

def tg_send_file(data, name, caption=""):
    c = cfg()
    if not (c.get("tg_token") and c.get("tg_chat")): return "Telegram is not configured"
    try:
        b = "----drc" + secrets.token_hex(8)
        parts = [("--%s\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n%s\r\n" % (b, c["tg_chat"])).encode()]
        if caption: parts.append(("--%s\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n%s\r\n" % (b, caption[:900])).encode())
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"document\"; filename=\"%s\"\r\nContent-Type: application/gzip\r\n\r\n" % (b, name)).encode() + data + b"\r\n")
        parts.append(("--%s--\r\n" % b).encode())
        u = ("%s/bot%s/sendDocument" % (c.get("tg_api") or "https://api.telegram.org", c["tg_token"])).replace("//bot", "/bot")
        req = urllib.request.Request(u, data=b"".join(parts), headers={"Content-Type": "multipart/form-data; boundary=" + b})
        urllib.request.urlopen(req, timeout=60).read(); return None
    except Exception as e: return "%s" % type(e).__name__

def hum(sec):
    sec = int(sec); s = ""
    if sec >= 3600: s += "%dh " % (sec // 3600)
    if sec % 3600 >= 60 or not s: s += "%dm" % (sec % 3600 // 60)
    return s.strip()

WGF = D + "/wgstate.json"; T24F = D + "/traffic24.json"
T24 = None; T24_PREV = 0; T24_SAVED = 0

def traffic_tick():
    # hourly forwarded-bytes buckets for the 24 h chart
    global T24, T24_PREV, T24_SAVED
    cur = fwd_bytes()
    if cur is None: return
    tot = sum(cur.values())
    if T24 is None: T24 = jload(T24F).get("b", [])
    h = int(time.time() // 3600)
    if not T24 or T24[-1][0] != h:
        T24.append([h, 0]); T24 = T24[-25:]
    d = tot - T24_PREV if tot >= T24_PREV else tot
    if d > 0: T24[-1][1] += d
    T24_PREV = tot
    if time.time() - T24_SAVED > 300:
        T24_SAVED = time.time(); jsave(T24F, {"b": T24})

def wg_watch():
    # tunnel watchdog: track down/up, auto-restart stale links, report downtime (auto-heal after a foreign reboot)
    st = jload(WGF); now = time.time(); ids = set()
    for t in tunnel_info():
        k = str(t["id"]); ids.add(k); e = st.setdefault(k, {})
        if not t["active"]: continue
        if t["up"]:
            if e.get("down_since"):
                dt = now - e["down_since"]; e.pop("down_since", None); e.pop("restart", None)
                log("info", "Tunnel %s is linked again (downtime %s)" % (t["ip"], hum(dt)))
                notify("🟢 تانل WireGuard %s وصل شد (قطعی: %s)" % (t["ip"], hum(dt)))
        else:
            if not e.get("down_since"):
                e["down_since"] = now
                log("warn", "Tunnel %s: no handshake" % t["ip"]); notify("🔴 تانل WireGuard %s قطع شد (بدون handshake)" % t["ip"])
            if now - e["down_since"] > 300 and now - e.get("restart", 0) > 600:
                e["restart"] = now
                subprocess.run(["systemctl", "restart", "wg-quick@sekawg%s" % k], timeout=30)
                subprocess.run([BIN, "apply"], timeout=20)
                log("warn", "Watchdog restarted the WireGuard interface for %s" % t["ip"])
    for k in list(st):
        if k not in ids: st.pop(k)
    jsave(WGF, st)

def daily_report_text():
    up = dn = 0
    for r in read_rules():
        h = HEALTH.get("%d/%s" % (r["lport"], r["proto"]))
        if h and h["ok"] is True: up += 1
        elif h and h["ok"] is False: dn += 1
    t24 = sum(b for _, b in (T24 or [])[::-1][:24])
    tg = sum(1 for t in tunnel_info() if t["up"])
    tn = len(tunnel_info())
    bk = len(blocked())
    cpu = SYS.get("cpu", 0); ram = 100 * SYS.get("ram_used", 0) / max(SYS.get("ram_total", 1), 1)
    return "📊 گزارش روزانه SEKA TUNEL\n" \
           "🟢 سرویس‌های آنلاین: %d · 🔴 قطع: %d\n" \
           "🔗 تانل‌های WireGuard: %d/%d متصل\n" \
           "📈 ترافیک ۲۴ ساعت: %s\n" \
           "⛔ سرویس‌های قطع‌شده (حجم/انقضا): %d\n" \
           "🖥 CPU: %s%% · RAM: %s%%\n" \
           "⏱ آپتایم: %s" % (up, dn, tg, tn, hbytes(t24), bk, cpu, ram, hum(SYS.get("up", 0) * 60))

def tg_daily_jobs():
    # one daily report + one nightly backup, each once per day
    c = cfg()
    if not (c.get("tg_token") and c.get("tg_chat")): return
    day = time.strftime("%F")
    try: rh = int(c.get("tg_report_hour", 12))
    except Exception: rh = 12
    if c.get("tg_report", True) and c.get("_rday") != day and time.localtime().tm_hour >= rh:
        upd(_rday=day); e = tg_send(daily_report_text())
        log("info", "Daily report sent to Telegram" if not e else "Daily report failed: " + e)
    try: bh = int(c.get("tg_backup_hour", 3))
    except Exception: bh = 3
    if c.get("tg_backup", True) and c.get("_bday") != day and time.localtime().tm_hour >= bh:
        upd(_bday=day); e = tg_send_file(make_backup(), "seka-tunel-backup-%s.tar.gz" % day, "🌙 بکاپ خودکار شبانه SEKA TUNEL")
        log("info", "Nightly backup sent to Telegram" if not e else "Nightly backup failed: " + e)

def bot_reply(args):
    rs = read_rules()
    if not rs: return "هنوز تانلی ساخته نشده."
    a = (args or [""])[0].lower()
    if a.startswith("tunnel") or a.startswith("tan"):
        out = ["🔗 تانل‌ها:"]
        for t in tunnel_info():
            out.append("%s %s — %s، ترافیک ↓%s ↑%s" % ("🟢" if t["up"] else "🔴", t["ip"], "فعال" if t["active"] else "مستقیم", hbytes(t["rx"]), hbytes(t["tx"])))
        return "\n".join(out)
    if a.startswith("traf") or a.startswith("t24"):
        now = int(time.time() // 3600)
        per = sorted(((hbytes(e.get("used", 0)), r["name"]) for r, e in ((r, jload(QUOTA).get(str(r["lport"]), {})) for r in rs)), reverse=True)[:5]
        return "📈 ترافیک ۲۴ ساعت: %s\n" % hbytes(sum(b for h, b in (T24 or []) if h > now - 24)) + "\n".join("• %s — %s" % (n, v) for v, n in per)
    if a.startswith("repo") or a.startswith("gza"):
        return daily_report_text()
    up = dn = 0
    for r in rs:
        h = HEALTH.get("%d/%s" % (r["lport"], r["proto"]))
        up += 1 if h and h["ok"] else 0; dn += 1 if h and h["ok"] is False else 0
    return "🖥 وضعیت SEKA TUNEL\n🟢 آنلاین: %d · 🔴 قطع: %d · کل: %d\n" \
           "CPU: %s%% · RAM: %s%%\n" \
           "BBR: %s" % (up, dn, len(rs), SYS.get("cpu", 0), 100 * SYS.get("ram_used", 0) // max(SYS.get("ram_total", 1), 1), sysval("net.ipv4.tcp_congestion_control"))

def tg_bot():
    time.sleep(10); off = 0
    while True:
        try:
            c = cfg()
            if not (c.get("tg_token") and c.get("tg_chat") and c.get("tg_bot", True)): time.sleep(15); continue
            u = ("%s/bot%s/getUpdates" % (c.get("tg_api") or "https://api.telegram.org", c["tg_token"])).replace("//bot", "/bot")
            r = json.load(urllib.request.urlopen(u + "?timeout=25&offset=" + str(off), timeout=35))
            for up in r.get("result", []):
                off = up["update_id"] + 1
                msg = up.get("message") or {}
                if str(msg.get("chat", {}).get("id")) != str(c["tg_chat"]): continue
                txt = (msg.get("text") or "").strip().split()
                cmd = txt[0].split("@")[0].lstrip("/").lower() if txt else ""
                if cmd in ("status", "s", "start", "help", "report", "traffic", "tunnels"):
                    rep = bot_reply([cmd] if cmd not in ("start", "help") else [] ) if cmd not in ("start", "help") else \
                          "ربات SEKA TUNEL:\n/status — وضعیت سرویس‌ها\n/tunnels — وضعیت تانل‌های رمزنگاری‌شده\n/traffic — ترافیک ۲۴ ساعت\n/report — گزارش کامل روزانه"
                    if rep: tg_send(rep)
        except Exception: time.sleep(10)

# ------------------------------------------------------------ views / ops
def state():
    c = counters(); rs = []; qd = jload(QUOTA); sb = jload(SUBF); bk = blocked(); sec = sec_read(); tun = tunnels()
    for r in read_rules():
        pk = by = 0
        for p in (["tcp", "udp"] if r["proto"] == "both" else [r["proto"]]):
            a = c.get((p, r["lport"]), [0, 0]); pk += a[0]; by += a[1]
        h = HEALTH.get("%d/%s" % (r["lport"], r["proto"]))
        st = "unknown" if not h or h["ok"] is None else ("up" if h["ok"] else "down")
        e = qd.get(str(r["lport"]), {}); by = int(e.get("used", by))
        expired = bool(e.get("expires")) and time.time() > exp_ts(e["expires"])
        rs.append(dict(r, packets=pk, bytes=by, limit=int(e.get("limit", 0)), blocked=str(r["lport"]) in bk, sub=str(r["lport"]) in sb, sec=sec.get(str(r["lport"]), {}), enc=bool(tun.get(r["ip"], {}).get("active")), status=st, ms=h["ms"] if h else None,
                       hist=list(h["hist"]) if h else [], since=h["since"] if h else None,
                       period=e.get("period", ""), reset_at=e.get("reset_at", 0), expires=e.get("expires", ""), expired=expired, hours=e.get("h") or []))
    pc = perf_current_py()
    ct = cm = 0
    try: ct = int(open("/proc/sys/net/netfilter/nf_conntrack_count").read()); cm = int(open("/proc/sys/net/netfilter/nf_conntrack_max").read())
    except Exception: pass
    cf = cfg()
    return {"rules": rs, "host": socket.gethostname(), "sys": dict(SYS), "ip_forward": sysval("net.ipv4.ip_forward") == "1",
            "cc": sysval("net.ipv4.tcp_congestion_control"), "now": time.time(), "ver": "__DR_VERSION__",
            "t24": [(h * 3600, b) for h, b in (T24 or [])], "perf": dict(preset=pc, ct=ct, cm=cm),
            "reverse": rev_rows(),
            "totp": bool(cf.get("totp")), "bot": bool(cf.get("tg_bot", True)), "rhour": cf.get("tg_report_hour", 12), "bhour": cf.get("tg_backup_hour", 3)}

def perf_current_py():
    try:
        n = open(D + "/perf_preset").read().strip()
        if n in ("balanced", "turbo", "throughput", "gaming"): return n
    except Exception: pass
    try:
        if os.path.exists("/etc/sysctl.d/99-seka-tunel-optimize.conf"): return "custom"
    except Exception: pass
    return "default"

def health_check():
    items = []
    def add(lv, m, fix=""): items.append(dict(level=lv, msg=m, fix=fix))
    add("ok" if sysval("net.ipv4.ip_forward") == "1" else "err", "IP forwarding " + ("is on" if sysval("net.ipv4.ip_forward") == "1" else "is OFF"), "sysctl -w net.ipv4.ip_forward=1")
    try: ch = subprocess.run(["iptables", "-t", "nat", "-nL", "SEKA_PRE"], capture_output=True, timeout=5).returncode == 0
    except Exception: ch = False
    add("ok" if ch else "err", "Forwarding chain " + ("exists" if ch else "is missing"), "seka-tunel apply")
    try:
        en = subprocess.run(["systemctl", "is-enabled", "seka-tunel.service"], capture_output=True, text=True, timeout=5).stdout.strip()
        add("ok" if en == "enabled" else "warn", "Boot service: " + (en or "unknown"), "seka-tunel  (add any forward to re-install the service)")
    except Exception: pass
    try:
        u = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5).stdout
        if "Status: active" in u: add("warn", "ufw is active: every listen port must be allowed", "ufw allow <port>/tcp")
    except Exception: pass
    try:
        cc = int(open("/proc/sys/net/netfilter/nf_conntrack_count").read()); cm = int(open("/proc/sys/net/netfilter/nf_conntrack_max").read())
        add("ok" if cc < cm * 0.8 else "warn", "Connection tracking: %d / %d" % (cc, cm), "Menu 5 (Optimize) raises nf_conntrack_max")
    except Exception: pass
    add("ok" if sysval("net.ipv4.tcp_congestion_control") == "bbr" else "warn", "TCP congestion control: " + sysval("net.ipv4.tcp_congestion_control"), "Menu 5 (Optimize) enables BBR")
    if SYS.get("disk_total") and SYS["disk_used"] / SYS["disk_total"] > 0.9: add("warn", "Disk is over 90% full")
    for t in tunnel_info():
        add("ok" if t["up"] else "warn", "WireGuard tunnel to %s: %s" % (t["ip"], "linked" if t["up"] else "no handshake"), "Run the setup script on the foreign server, or check that UDP %d is open" % t["port"])
    for r in read_rules():
        h = HEALTH.get("%d/%s" % (r["lport"], r["proto"]))
        if r["proto"] == "udp": add("ok", "%s: UDP cannot be probed" % r["name"])
        elif not h or h["ok"] is None: add("warn", "%s: not probed yet" % r["name"])
        elif h["ok"]: add("ok", "%s: destination answers (%d ms)" % (r["name"], h["ms"] or 0))
        else: add("err", "%s: %s:%d does not answer" % (r["name"], r["ip"], r["dport"]), "Check the inbound on the foreign server and its firewall")
    return items

def make_backup():
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for n in ("rules.conf", "default_ip", "quota.json", "sub.json", "security.conf", "tunnels.conf", "web.json", "web.crt", "web.key", "traffic24.json", "wgstate.json", "perf_preset"):
            if os.path.exists(D + "/" + n): t.add(D + "/" + n, arcname=n)
    return b.getvalue()

def restore(data):
    n = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t.getmembers():
            if m.name in ("rules.conf", "default_ip", "quota.json", "sub.json", "security.conf", "tunnels.conf") and m.isfile() and m.size < 1000000:
                open(D + "/" + m.name, "wb").write(t.extractfile(m).read()); os.chmod(D + "/" + m.name, 0o600); n += 1
    if not n: raise ValueError("No forwards found in this file")
    subprocess.run([BIN, "tunnel", "sync"], timeout=120)
    subprocess.run([BIN, "apply"], timeout=20)

# ------------------------------------------------- quota / sub link / domain
QUOTA = D + "/quota.json"; BLKF = D + "/blocked"; SUBF = D + "/sub.json"
QLOCK = threading.Lock(); MISS = {}; HSTS_H = ()
HOOK = "/etc/letsencrypt/renewal-hooks/deploy/seka-tunel-web.sh"

def jload(p):
    try: return json.load(open(p))
    except Exception: return {}

def jsave(p, d):
    with open(p + ".tmp", "w") as f: json.dump(d, f)
    os.chmod(p + ".tmp", 0o600); os.replace(p + ".tmp", p)

def blocked():
    try: return {l.strip() for l in open(BLKF) if l.strip()}
    except Exception: return set()

def hbytes(n):
    u = ["B", "KB", "MB", "GB", "TB", "PB"]; i = 0; n = float(n or 0)
    while n >= 1024 and i < 5: n /= 1024; i += 1
    return ("%.2f" % n).rstrip("0").rstrip(".") + " " + u[i] if i else "%d B" % n

def fwd_bytes():
    # bytes forwarded per rule, both directions; every FWD rule carries a "drc:<port>" comment
    out = {}
    try: t = subprocess.run(["iptables", "-t", "filter", "-nvxL", "SEKA_FWD"], capture_output=True, text=True, timeout=5).stdout
    except Exception: return None
    for l in t.splitlines():
        m = re.search(r"drc:(\d+)", l); f = l.split()
        if m and len(f) > 1 and f[1].isdigit(): out[m.group(1)] = out.get(m.group(1), 0) + int(f[1])
    return out

def quota_tick():
    with QLOCK:
        cur = fwd_bytes()
        if cur is None: return
        now = time.time()
        q = jload(QUOTA); old = blocked(); new = set(); expired = set(); names = {}
        for r in read_rules(): names[str(r["lport"])] = r["name"]
        for k in list(q):
            if k not in names: q.pop(k)
        for k in names:
            e = q.setdefault(k, {"limit": 0, "used": 0, "last": 0}); c = cur.get(k, 0)
            d = c - e["last"] if c >= e["last"] else c
            if d > 0 and k not in old: e["used"] += d
            e["last"] = c
            pr = e.get("period")
            if pr in ("daily", "weekly", "monthly"):
                if not e.get("reset_at"):
                    e["reset_at"] = next_reset(now, pr)
                elif now >= e["reset_at"]:
                    e["used"] = 0; e["reset_at"] = next_reset(now, pr)
                    log("info", "Periodic quota of :%s (%s) reset" % (names[k], pr))
                    notify("🔄 حجم %s (:%s) دوره‌ای ریست شد (%s)" % (names[k], k, pr))
            ex = e.get("expires")
            if ex and now > exp_ts(ex): expired.add(k)
            hbkt = int(now // 3600)
            h = e.get("h")
            if not isinstance(h, list): h = []
            if not h or h[-1][0] != hbkt:
                h.append([hbkt, 0]); h = h[-25:]
            if d > 0 and k not in old: h[-1][1] += d
            e["h"] = h
            if (e["limit"] and e["used"] >= e["limit"]) or k in expired: new.add(k)
        if new != old:
            with open(BLKF, "w") as f: f.write("".join(k + "\n" for k in sorted(new)))
            subprocess.run([BIN, "apply"], timeout=20)
            for e in q.values(): e["last"] = 0
            for k in new - old:
                if k in expired:
                    log("warn", "%s (:%s) expired and is cut off" % (names[k], k)); notify("⌛ %s (:%s) تاریخ انقضایش رسیده و قطع شد" % (names[k], k))
                else:
                    log("warn", "%s (:%s) used up its quota and is cut off" % (names[k], k)); notify("⛔ %s (:%s) حجمش تمام شد و قطع شد" % (names[k], k))
            for k in old - new: log("info", "%s (:%s) is back online" % (names.get(k, "?"), k))
        jsave(QUOTA, q)

def quota_rebase():
    with QLOCK:
        q = jload(QUOTA)
        for e in q.values(): e["last"] = 0
        jsave(QUOTA, q)

def quota_loop():
    time.sleep(2)
    while True:
        try: quota_tick()
        except Exception as e: log("warn", "quota error: %s" % type(e).__name__)
        time.sleep(3)

def next_reset(ts, period):   # next daily / weekly (Mon) / monthly boundary, local time
    lt = time.localtime(ts)
    if period == "daily": return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + 1, 0, 0, 0, 0, 0, -1))
    if period == "weekly":
        d = (lt.tm_wday + 1) % 7   # 0 = Monday
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + (7 - d), 0, 0, 0, 0, 0, -1))
    m, y = (lt.tm_mon + 1, lt.tm_year) if lt.tm_mon < 12 else (1, lt.tm_year + 1)
    return time.mktime((y, m, 1, 0, 0, 0, 0, 0, -1))

def exp_ts(s):
    try:
        p = time.strptime(str(s)[:10], "%Y-%m-%d")
        return time.mktime(p[:3] + (23, 59, 59) + p[6:8] + (-1,))
    except Exception: return 0

def quota_set(lport, limit=None, reset=False, period=None, expires=None):
    quota_tick()
    with QLOCK:
        q = jload(QUOTA); e = q.setdefault(str(lport), {"limit": 0, "used": 0, "last": 0})
        if limit is not None: e["limit"] = max(0, int(limit))
        if reset: e["used"] = 0
        if period is not None:
            if period in ("daily", "weekly", "monthly"):
                e["period"] = period; e["reset_at"] = next_reset(time.time(), period)
            else: e.pop("period", None); e.pop("reset_at", None)
        if expires is not None:
            if str(expires).strip(): e["expires"] = str(expires).strip()[:10]
            else: e.pop("expires", None)
        jsave(QUOTA, q)
    quota_tick()

def forget(lport):
    k = str(lport)
    cur = sec_read()
    if k in cur: cur.pop(k); sec_file(cur)
    with QLOCK:
        q = jload(QUOTA); q.pop(k, None); jsave(QUOTA, q)
        s = jload(SUBF); s.pop(k, None); jsave(SUBF, s)
        b = blocked()
        if k in b:
            b.discard(k); open(BLKF, "w").write("".join(x + "\n" for x in sorted(b)))

def sub_html(name, used, lim, left, pct, off, expires="", days_left=None, hours=None):
    tone = "er" if off else ("wa" if lim and pct >= 90 else "ok")
    st = "حجم تمام شده — سرویس قطع است" if off else ("حجم رو به پایان است" if tone == "wa" else "سرویس فعال است")
    dl = ("%d روز مانده" % days_left) if days_left is not None else "امروز تمام می‌شود" if expires else ""
    exp = '<div class="exp">⌛ تاریخ انقضا: %s · %s</div>' % (expires, dl) if expires else ""
    chart = ""
    if hours:
        v = [b for _, b in hours][-24:]; m = max(v + [1])
        bars = "".join('<rect x="%d" y="%d" width="9" height="%d" rx="2"></rect>' % (i * 14, 44 - max(3, int(40 * x / m)), max(3, int(40 * x / m))) for i, x in enumerate(v))
        chart = '<div class="ch"><span>ترافیک ۲۴ ساعت اخیر</span><svg viewBox="0 0 %d 46" preserveAspectRatio="none">%s</svg></div>' % (max(len(v), 1) * 14 - 5, bars)
    page = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#07060f">
<meta name="robots" content="noindex,nofollow"><meta http-equiv="refresh" content="60"><title>وضعیت حجم</title><style>
:root{--bg:#07060f;--card:rgba(14,12,24,.82);--line:rgba(255,255,255,.09);--tx:#f6f5ff;--mu:#8d8aa5;--ok:#22c55e;--wa:#f59e0b;--er:#ef4444;--ac:#8b5cf6;--ac2:#6366f1}
*{box-sizing:border-box}html,body{margin:0}
body{min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--tx);font:15px/1.7 -apple-system,"Segoe UI",Vazirmatn,Tahoma,sans-serif;padding:18px;overflow-x:hidden}
.aur{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.aur i{position:absolute;border-radius:50%;filter:blur(90px);opacity:.5}
.a1{width:60vw;height:60vw;left:-18vw;top:-24vw;background:radial-gradient(circle,rgba(139,92,246,.55),transparent 66%);animation:f1 24s ease-in-out infinite alternate}
.a2{width:48vw;height:48vw;right:-14vw;top:24vh;background:radial-gradient(circle,rgba(99,102,241,.5),transparent 66%);animation:f2 30s ease-in-out infinite alternate}
.a3{width:40vw;height:40vw;left:22vw;bottom:-20vw;background:radial-gradient(circle,rgba(236,72,153,.38),transparent 66%);animation:f3 36s ease-in-out infinite alternate}
@keyframes f1{to{transform:translate(9vw,6vh) scale(1.15)}}
@keyframes f2{to{transform:translate(-8vw,-6vh) scale(1.18)}}
@keyframes f3{to{transform:translate(-6vw,-8vh) scale(1.1)}}
.stars{position:absolute;inset:0;opacity:.6;background-image:radial-gradient(1.2px 1.2px at 12% 22%,#fff9,transparent),radial-gradient(1px 1px at 38% 10%,#fff7,transparent),radial-gradient(1.3px 1.3px at 64% 28%,#fff8,transparent),radial-gradient(1px 1px at 84% 14%,#fff6,transparent),radial-gradient(1.2px 1.2px at 6% 66%,#fff7,transparent),radial-gradient(1px 1px at 92% 70%,#fff5,transparent),radial-gradient(1.2px 1.2px at 30% 86%,#fff7,transparent)}
.c{position:relative;z-index:1;width:100%;max-width:430px;background:var(--card);border-radius:24px;padding:30px 28px 24px;backdrop-filter:blur(20px);box-shadow:0 30px 80px rgba(0,0,0,.55);animation:pop .7s cubic-bezier(.16,1,.3,1) both}
.c::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(135deg,rgba(139,92,246,.55),rgba(255,255,255,.06) 40%,rgba(139,92,246,.22));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);mask-composite:exclude;pointer-events:none}
@keyframes pop{from{opacity:0;transform:translateY(18px) scale(.96)}to{opacity:1;transform:none}}
.ok{--t:var(--ok)}.wa{--t:var(--wa)}.er{--t:var(--er)}
.hd{display:flex;align-items:center;gap:13px;margin-bottom:20px}
.mk{width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg,var(--ac2),var(--ac));display:grid;place-items:center;flex:none;box-shadow:0 6px 22px -6px rgba(139,92,246,.7);animation:pulse 3.5s ease-in-out infinite}
.mk svg{width:22px;height:22px}
h1{margin:0;font-size:17px;letter-spacing:.01em}small{color:var(--mu)}
.st{display:flex;gap:8px;align-items:center;margin:0 0 18px;font-size:13.5px;color:var(--t)}.st i{width:9px;height:9px;border-radius:50%;background:var(--t);box-shadow:0 0 10px var(--t);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.bar{height:12px;border-radius:99px;background:rgba(255,255,255,.08);overflow:hidden;direction:ltr;box-shadow:inset 0 1px 3px rgba(0,0,0,.4)}
.bar b{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--ac2),var(--t));box-shadow:0 0 14px color-mix(in srgb,var(--t) 55%,transparent);animation:grow 1.3s cubic-bezier(.2,.7,.2,1) .15s both;position:relative;overflow:hidden}
.bar b::after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.35),transparent);animation:shine 2.4s ease-in-out infinite}
@keyframes grow{from{width:0}}
@keyframes shine{from{transform:translateX(-100%)}to{transform:translateX(100%)}}
.g{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:20px;text-align:center}
.g div{border:1px solid var(--line);border-radius:14px;padding:13px 4px;background:rgba(255,255,255,.03)}
.g span{display:block;color:var(--mu);font-size:11.5px;margin-bottom:5px}
.g b{font-size:15px;direction:ltr;display:inline-block;font-variant-numeric:tabular-nums}
.exp{margin:-6px 0 16px;padding:10px 13px;border:1px solid color-mix(in srgb,var(--wa) 35%,transparent);background:color-mix(in srgb,var(--wa) 9%,transparent);border-radius:12px;color:var(--wa);font-size:13px}
.ch{margin-top:18px;border:1px solid var(--line);border-radius:14px;padding:12px 14px;background:rgba(255,255,255,.03)}
.ch span{display:block;color:var(--mu);font-size:11.5px;margin-bottom:8px}
.ch svg{width:100%;height:46px;display:block}
.ch rect{fill:var(--ac);opacity:.75}
footer{margin-top:20px;padding-top:16px;border-top:1px solid var(--line);color:var(--mu);font-size:12px;display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap}
footer a{color:var(--mu);text-decoration:none;display:inline-flex;align-items:center;gap:6px;transition:.2s}
footer a:hover{color:var(--tx)}
footer svg{width:13px;height:13px;fill:currentColor}
.dot{width:3px;height:3px;border-radius:50%;background:var(--mu);opacity:.6}
@media(prefers-reduced-motion:reduce){*{animation:none!important}}
</style></head><body>
<div class="aur" aria-hidden="true"><i class="a1"></i><i class="a2"></i><i class="a3"></i><i class="stars"></i></div>
<main class="c @TONE@">
<div class="hd"><span class="mk"><svg viewBox="0 0 24 24"><path d="M13.5 2 5 13.5h6L9.5 22 19 9.5h-6.2z" fill="none" stroke="#fbbf24" stroke-width="1.8" stroke-linejoin="round"/></svg></span><div><h1>@NAME@</h1><small>وضعیت مصرف حجم</small></div></div>
<div class="st"><i></i>@ST@</div>@EXP@@BAR@@CHART@
<div class="g"><div><span>مصرف‌شده</span><b>@USED@</b></div><div><span>کل حجم</span><b>@LIM@</b></div><div><span>باقی‌مانده</span><b>@LEFT@</b></div></div>
<footer><span>آخرین بروزرسانی: @TIME@ · هر ۶۰ ثانیه خودکار تازه می‌شود</span></footer></main></body></html>"""
    rep = {"@TONE@": tone, "@NAME@": html.escape(name), "@ST@": st, "@USED@": hbytes(used),
           "@LIM@": hbytes(lim) if lim else "نامحدود", "@LEFT@": hbytes(left) if lim else "—",
           "@BAR@": '<div class="bar"><b style="width:%d%%"></b></div>' % pct if lim else "", "@TIME@": time.strftime("%F %H:%M"),
           "@EXP@": exp, "@CHART@": chart}
    for k, v in rep.items(): page = page.replace(k, v)
    return page

def offline_pkg():
    d = open(BIN, "rb").read()
    inst = (b"#!/usr/bin/env bash\n"
            b"# SEKA TUNEL offline installer - no internet needed\n"
            b"set -e; cd \"$(dirname \"$0\")\"\n"
            b"[ \"$(id -u)\" = 0 ] || { echo \"run as root\"; exit 1; }\n"
            b"sha256sum -c SHA256SUMS >/dev/null 2>&1 || { echo \"checksum FAILED - package is broken\"; exit 1; }\n"
            b"echo \"checksum OK\"\n"
            b"install -m 755 seka-tunel.sh /usr/local/bin/seka-tunel\n"
            b"echo \"installed. open the menu with: seka-tunel\"\n"
            b"exec /usr/local/bin/seka-tunel\n")
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for name, data, mode in (("seka-tunel.sh", d, 0o755), ("install.sh", inst, 0o755), ("SHA256SUMS", (hashlib.sha256(d).hexdigest() + "  seka-tunel.sh\n" + hashlib.sha256(inst).hexdigest() + "  install.sh\n").encode(), 0o644)):
            ti = tarfile.TarInfo(name); ti.size = len(data); ti.mode = mode; t.addfile(ti, io.BytesIO(data))
    return b.getvalue()

def restart_later():
    threading.Timer(1.5, lambda: subprocess.run(["systemctl", "restart", "seka-tunel-web"])).start()

def do_domain(domain, email="", restart=True):
    domain = str(domain).strip().lower(); email = str(email).strip()
    if not re.fullmatch(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain): raise ValueError("Invalid domain")
    if email and not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}", email): raise ValueError("Invalid email")
    if not shutil.which("certbot"):
        for pm in (["apt-get", "install", "-y", "-qq", "certbot"], ["dnf", "install", "-y", "certbot"], ["yum", "install", "-y", "certbot"]):
            if shutil.which(pm[0]):
                subprocess.run(pm, capture_output=True, timeout=300); break
        if not shutil.which("certbot"): raise ValueError("certbot is missing and could not be installed (server has no access to package mirrors?)")
    s = socket.socket()
    try: s.bind(("0.0.0.0", 80))
    except OSError: raise ValueError("Port 80 is busy: Let's Encrypt needs it for a moment")
    finally: s.close()
    os.makedirs(os.path.dirname(HOOK), exist_ok=True)
    with open(HOOK, "w") as f: f.write("#!/bin/sh\n[ -f /etc/seka-tunel/web.json ] && grep -q '\"cert\": \"/etc/letsencrypt' /etc/seka-tunel/web.json && systemctl restart seka-tunel-web\nexit 0\n")
    os.chmod(HOOK, 0o755)
    cmd = ["certbot", "certonly", "--standalone", "--preferred-challenges", "http", "--non-interactive", "--agree-tos", "-d", domain]
    cmd += ["-m", email] if email else ["--register-unsafely-without-email"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    live = "/etc/letsencrypt/live/%s/" % domain
    if r.returncode or not os.path.exists(live + "fullchain.pem"):
        raise ValueError("certbot failed (does the domain point to this server?): " + (r.stdout + r.stderr).strip()[-300:])
    upd(domain=domain, email=email, cert=live + "fullchain.pem", key=live + "privkey.pem", tls=True)
    log("info", "Domain %s set with a Let's Encrypt certificate" % domain)
    if restart: restart_later()

def do_nodomain():
    upd(domain="", email="", cert="", key=""); log("info", "Domain removed, back to the self-signed certificate"); restart_later()

def do_cert(cert, key):
    cert = str(cert).strip(); key = str(key).strip()
    if "BEGIN CERTIFICATE" not in cert or "PRIVATE KEY" not in key: raise ValueError("Certificate and key must be PEM text")
    tc, tk = CERT + ".new", KEY + ".new"
    open(tc, "w").write(cert + "\n"); open(tk, "w").write(key + "\n"); os.chmod(tk, 0o600)
    try:
        x = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); x.load_cert_chain(tc, tk)
    except Exception:
        os.remove(tc); os.remove(tk); raise ValueError("Certificate and key are invalid or do not match")
    os.replace(tc, CERT); os.replace(tk, KEY); upd(tls=True, cert="", key="")
    log("info", "Own certificate installed"); restart_later()

# ------------------------------------------------------------------- http
class H(BaseHTTPRequestHandler):
    server_version = "SEKA TUNEL"
    def log_message(self, *a): pass

    def out(self, code, body, ctype="application/json", extra=()):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(b))), ("Cache-Control", "no-store"),
                     ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                     ("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:")) + tuple(extra) + HSTS_H:
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def token(self):
        try: return SimpleCookie(self.headers.get("Cookie", ""))["drc"].value
        except Exception: return None

    def authed(self):
        t = self.token(); e = SESS.get(t)
        if e and e > time.time(): return True
        SESS.pop(t, None); return False

    def body(self, limit=4096):
        if "application/json" not in self.headers.get("Content-Type", ""): raise ValueError("Bad request")
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit: raise ValueError("Too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        try: self.get()
        except Exception: self.out(500, {"error": "Server error"})

    def get(self):
        p = self.path.split("?")[0]
        if p == "/": return self.out(200, open(UI, "rb").read(), "text/html; charset=utf-8")
        m = re.fullmatch(r"/join/([0-9a-f]{16,64})", p)
        if m:   # public, token-gated: the one-line script the kharej runs to join the tunnel
            ip = self.client_address[0]; now = time.time()
            if len(JOINMISS) > 5000: JOINMISS.clear()
            JOINMISS[ip] = [t for t in JOINMISS.get(ip, []) if t > now - 60]
            if len(JOINMISS[ip]) > 20: return self.out(429, {"error": "Too many requests"})
            try:
                sc = tun_cmd("script-join", m.group(1), self.headers.get("Host", ""), ip, t=60)
            except ValueError as e:
                return self.out(404, {"error": str(e)})
            log("info", "Join link fetched by %s (tunnel joined from that IP)" % ip); audit("join_served", ip, ip)
            return self.out(200, sc.encode(), "text/plain; charset=utf-8",
                            [("X-Robots-Tag", "noindex, nofollow"), ("Content-Disposition", "inline")])
        if p.startswith("/sub/"): return self.sub_public(p)
        m = re.fullmatch(r"/ctest/([0-9a-f]{16,64})", p)
        if m:   # public, id-gated: the two-server connection-test script the kharej runs
            ip = self.client_address[0]; now = time.time()
            if len(CTMISS) > 5000: CTMISS.clear()
            CTMISS[ip] = [t for t in CTMISS.get(ip, []) if t > now - 60]
            if len(CTMISS[ip]) > 20: return self.out(429, {"error": "Too many requests"})
            CTMISS[ip].append(now)
            st = jload(CTF2) or {}
            if m.group(1) != st.get("id") or now > st.get("until", 0):
                return self.out(404, {"error": "No open test (make a new link from the panel)"})
            host = (self.headers.get("Host") or socket.gethostname()).strip()
            sch = "https" if cfg().get("tls") else "http"
            sc = ctest_script(st["id"], host, int(st["tport"]), int(st["uport"]), "%s://%s" % (sch, host))
            log("info", "Connection-test link fetched by %s" % ip); audit("ctest_served", ip, ip)
            return self.out(200, sc.encode(), "text/plain; charset=utf-8",
                            [("X-Robots-Tag", "noindex, nofollow"), ("Content-Disposition", "inline")])
        if not p.startswith("/api/"): return self.out(404, {"error": "not found"})
        if not self.authed(): return self.out(401, {"error": "auth"})
        if p == "/api/state": return self.out(200, state())
        if p == "/api/logs": return self.out(200, list(LOGS)[::-1])
        if p == "/api/audit": return self.out(200, {"a": audit_read()})
        if p == "/api/health": return self.out(200, health_check())
        if p == "/api/tunnels": return self.out(200, {"tunnels": tunnel_info(), "wg": bool(shutil.which("wg"))})
        if p == "/api/reverse": return self.out(200, {"rows": rev_rows()})
        if p == "/api/conntest":
            return self.out(200, {"running": CT["running"], "result": CT["result"] or (jload(CTF) or None)})
        if p == "/api/ctest":
            st = jload(CTF2) or {}
            out = dict(tport=st.get("tport"), uport=st.get("uport"), until=st.get("until"), report=st.get("report"))
            if st.get("id") and (st.get("until", 0) or 0) > time.time():
                host = (self.headers.get("Host") or socket.gethostname()).strip()
                sch = "https" if cfg().get("tls") else "http"
                out.update(id=st["id"], cmd="bash <(curl -fsSLk %s://%s/ctest/%s)" % (sch, host, st["id"]))
            return self.out(200, out)
        if p == "/api/tunnel/link":
            mm = re.search(r"ip=([0-9.]+)", self.path)
            try: tok = tun_cmd("link", mm.group(1) if mm else "", t=20).strip()
            except ValueError as e: return self.out(400, {"error": str(e)})
            if not re.fullmatch(r"[0-9a-f]{16,64}", tok): return self.out(500, {"error": "Token error"})
            host = self.headers.get("Host") or socket.gethostname()
            sch = "https" if cfg().get("tls") else "http"
            return self.out(200, {"url": "bash <(curl -fsSLk %s://%s/join/%s)" % (sch, host, tok), "token": tok})
        if p == "/api/tunnel/script":
            m = re.search(r"ip=([\d.]+)", self.path)
            try: return self.out(200, {"script": tun_cmd("script", m.group(1) if m else "", t=20)})
            except ValueError as e: return self.out(400, {"error": str(e)})
        if p == "/api/sub":
            m = re.search(r"lport=(\d+)", self.path); k = m.group(1) if m else ""
            if k not in {str(r["lport"]) for r in read_rules()}: return self.out(404, {"error": "No such rule"})
            t = jload(SUBF).get(k, ""); return self.out(200, {"token": t, "path": "/sub/" + t if t else ""})
        if p == "/api/settings":
            c = cfg(); return self.out(200, {"domain": c.get("domain", ""), "tg_chat": c.get("tg_chat", ""), "tg_api": c.get("tg_api", ""), "has_token": bool(c.get("tg_token")), "port": c.get("port"), "tls": c.get("tls"), "totp": bool(c.get("totp")), "bot": bool(c.get("tg_bot", True)), "report": bool(c.get("tg_report", True)), "backup": bool(c.get("tg_backup", True)), "rhour": c.get("tg_report_hour", 12), "bhour": c.get("tg_backup_hour", 3)})
        if p == "/api/backup":
            return self.out(200, make_backup(), "application/gzip", [("Content-Disposition", 'attachment; filename="seka-tunel-backup-%s.tar.gz"' % time.strftime("%Y%m%d-%H%M%S"))])
        if p == "/api/package":
            return self.out(200, offline_pkg(), "application/gzip", [("Content-Disposition", 'attachment; filename="seka-tunel-offline.tar.gz"')])
        self.out(404, {"error": "not found"})

    def sub_public(self, p):
        ip = self.client_address[0]; now = time.time()
        if len(MISS) > 5000: MISS.clear()
        MISS[ip] = [t for t in MISS.get(ip, []) if t > now - 60]
        if len(MISS[ip]) > 30: return self.out(429, {"error": "Too many requests"})
        tok = p[5:]; js = tok.endswith(".json")
        if js: tok = tok[:-5]
        hit = None
        if re.fullmatch(r"[0-9a-f]{48}", tok):
            for k, v in jload(SUBF).items():
                if hmac.compare_digest(str(v), tok): hit = k
        r = next((x for x in read_rules() if str(x["lport"]) == hit), None) if hit else None
        if not r:
            MISS[ip].append(now); return self.out(404, {"error": "not found"})
        e = jload(QUOTA).get(hit, {}); used = int(e.get("used", 0)); lim = int(e.get("limit", 0))
        left = max(0, lim - used) if lim else 0; pct = min(100, int(100 * used / lim)) if lim else 0; off = hit in blocked()
        exp = e.get("expires", ""); xts = exp_ts(exp) if exp else 0
        dl = max(0, int((xts - now) // 86400) + 1) if exp and xts >= now else (0 if exp else None)
        ex = [("X-Robots-Tag", "noindex, nofollow"), ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")]
        if js: return self.out(200, {"name": r["name"], "used": used, "limit": lim, "left": left, "percent": pct, "offline": off, "unlimited": not lim, "expires": exp, "days_left": dl, "period": e.get("period", "")}, extra=ex)
        return self.out(200, sub_html(r["name"], used, lim, left, pct, off, exp, dl, e.get("h")).encode(), "text/html; charset=utf-8", ex)

    def do_DELETE(self):
        m = re.fullmatch(r"/api/rules/(\d+)", self.path)
        if not (m and self.authed()): return self.out(401, {"error": "auth"})
        with LOCK:
            rs = read_rules(); i = int(m.group(1)) - 1
            if not 0 <= i < len(rs): return self.out(404, {"error": "No such rule"})
            r = rs.pop(i); write_rules(rs); forget(r["lport"])
        log("info", "Removed forward %s (:%d)" % (r["name"], r["lport"])); audit("rule_del", ":%d" % r["lport"], self.client_address[0])
        self.out(200, {"ok": True})

    def do_POST(self):
        try:
            if self.path == "/api/login": return self.login(self.body())
            if self.path.startswith("/api/ctest/report"):
                # public but id-gated: the kharej side of the two-server connection test posts its results here
                ip = self.client_address[0]; now = time.time()
                if len(CTMISS) > 5000: CTMISS.clear()
                CTMISS[ip] = [t for t in CTMISS.get(ip, []) if t > now - 60]
                if len(CTMISS[ip]) > 10: return self.out(429, {"error": "Too many requests"})
                CTMISS[ip].append(now)
                d = self.body(8192)
                mm = re.search(r"id=([0-9a-f]{16,64})", self.path)
                st = jload(CTF2) or {}
                if not mm or not st or mm.group(1) != st.get("id"): return self.out(404, {"error": "No open test"})
                if now > st.get("until", 0): return self.out(410, {"error": "Test expired"})
                rep = {"icmp": d.get("icmp") if isinstance(d, dict) else None, "tcp": d.get("tcp") if isinstance(d, dict) else None,
                       "udp": d.get("udp") if isinstance(d, dict) else None, "t": now, "ip": ip}
                st["report"] = rep; jsave(CTF2, st)
                log("info", "Two-server test report from %s" % ip); audit("ctest_report", ip, ip)
                return self.out(200, {"ok": True})
            if not self.authed(): return self.out(401, {"error": "auth"})
            d = self.body(3000000 if self.path == "/api/restore" else 20000 if self.path in ("/api/cert", "/api/security") else 4096)
            if self.path == "/api/logout":
                SESS.pop(self.token(), None)
                return self.out(200, {"ok": True}, extra=[("Set-Cookie", "drc=; Max-Age=0; Path=/")])
            if self.path == "/api/rules":
                with LOCK:
                    new = validate_many(d); rs = read_rules(); rs.extend(new); write_rules(rs)
                    open(DEF, "w").write(new[0]["ip"])
                for r in new:
                    log("info", "Added forward %s :%d → %s:%d (%s)" % (r["name"], r["lport"], r["ip"], r["dport"], r["proto"]))
                audit("rule_add", ",".join(":%d" % r["lport"] for r in new), self.client_address[0])
                return self.out(200, {"ok": True})
            if self.path in ("/api/quota", "/api/sub"):
                k = str(int(d.get("lport", 0)))
                if k not in {str(r["lport"]) for r in read_rules()}: return self.out(404, {"error": "No such rule"})
                if self.path == "/api/quota":
                    if d.get("reset"):
                        quota_set(k, reset=True); log("info", "Usage of :%s reset" % k); audit("quota_reset", ":" + k, self.client_address[0])
                    else:
                        quota_set(k, limit=int(d.get("limit", 0)), period=d.get("period"), expires=d.get("expires"))
                        log("info", "Quota of :%s set to %s" % (k, hbytes(int(d.get("limit", 0))) if d.get("limit") else "unlimited"))
                        audit("quota_set", ":%s limit=%s period=%s expires=%s" % (k, d.get("limit", 0), d.get("period") or "-", d.get("expires") or "-"), self.client_address[0])
                    return self.out(200, {"ok": True})
                s = jload(SUBF); a = d.get("action")
                if a in ("create", "rotate"):
                    if a == "rotate" or k not in s: s[k] = secrets.token_hex(24)
                elif a == "delete": s.pop(k, None)
                else: raise ValueError("Bad action")
                jsave(SUBF, s); t = s.get(k, ""); return self.out(200, {"token": t, "path": "/sub/" + t if t else ""})
            if self.path in ("/api/tunnel", "/api/tunnel/test", "/api/tunnel/bw"):
                if self.path.endswith("/test") or self.path.endswith("/bw"):
                    try: ip = str(ipaddress.IPv4Address(str(d.get("ip", "")).strip()))
                    except Exception: raise ValueError("Invalid IP")
                    if self.path.endswith("/test"): return self.out(200, transport_test(ip, int(d.get("port") or 0)))
                    return self.out(200, bwtest(ip))
                a = d.get("action")
                if a == "add" and str(d.get("type") or "") == "rev":
                    # reverse wizard: no foreign IP needed - the kharej dials in with the one-line join link
                    pr = str(d.get("preset") or "turbo")
                    if pr not in ("balanced", "turbo", "throughput", "gaming"): raise ValueError("Bad preset")
                    tr = str(d.get("tr") or "udp")
                    if tr not in ("udp", "tcp", "ws", "wss", "kcp", "quic", "gaaf"): raise ValueError("Bad transport")
                    nm = re.sub(r"[^A-Za-z0-9_.-]", "_", str(d.get("name") or ""))[:40]
                    with LOCK: tun_cmd("join-open", str(int(d.get("port") or 51820)), pr, nm, tr, str(int(d.get("cport") or 0)), t=300)
                    log("info", "Reverse tunnel created - waiting for the kharej to run its join link")
                    audit("tunnel_add_rev", "wg port %s tr %s" % (d.get("port"), tr), self.client_address[0])
                    return self.out(200, {"ok": True, "pending": True})
                if a == "transport":
                    # works for pending rev tunnels too: the join script reads the row at join time
                    tr = str(d.get("tr") or "")
                    if tr not in ("udp", "tcp", "ws", "wss", "kcp", "quic", "gaaf"): raise ValueError("Bad transport")
                    key = str(d.get("id") or "").strip()
                    ip2 = key if re.fullmatch(r"\d+", key) else str(d.get("ip", "")).strip()
                    with LOCK: tun_cmd("transport", ip2, tr, str(int(d.get("cport") or 0)))
                    log("info", "Tunnel transport -> %s (%s)" % (tr, ip2)); audit("tunnel_transport", "%s %s" % (ip2, tr), self.client_address[0])
                    return self.out(200, {"ok": True})
                try: ip = str(ipaddress.IPv4Address(str(d.get("ip", "")).strip()))
                except Exception: raise ValueError("Invalid IP")
                with LOCK:
                    if a == "add":
                        ty = str(d.get("type") or "fwd")
                        if ty not in ("fwd", "dir"): raise ValueError("Bad type")
                        pr = str(d.get("preset") or "")
                        if pr and pr not in ("balanced", "turbo", "throughput", "gaming"): raise ValueError("Bad preset")
                        tr = str(d.get("tr") or "udp")
                        if tr not in ("udp", "tcp", "ws", "wss", "kcp", "quic", "gaaf"): raise ValueError("Bad transport")
                        nm = re.sub(r"[^A-Za-z0-9_.-]", "_", str(d.get("name") or ""))[:40]
                        tun_cmd("add", ip, str(int(d.get("port") or 51820)), "0", pr, ty, nm, tr, str(int(d.get("cport") or 0)))
                    elif a == "preset":
                        pr = str(d.get("preset") or "none")
                        if pr != "none" and pr not in ("balanced", "turbo", "throughput", "gaming"): raise ValueError("Bad preset")
                        tun_cmd("preset", ip, pr)
                    elif a in ("use", "direct", "del"): tun_cmd(a, ip)
                    else: raise ValueError("Bad action")
                log("info", "Tunnel %s: %s" % (a, ip)); audit("tunnel_" + str(a), ip, self.client_address[0]); return self.out(200, {"ok": True})
            if self.path == "/api/reverse":
                a = d.get("action")
                if a == "test":
                    return self.out(200, rev_test(str(d.get("ip", "")), int(d.get("lport") or 0)))
                ip = str(d.get("ip", "")).strip()
                try: ipaddress.IPv4Address(ip)
                except Exception: raise ValueError("Invalid IP")
                with LOCK:
                    if a == "add":
                        lp, dp = int(d.get("lport") or 0), int(d.get("dport") or 0)
                        proto = str(d.get("proto") or "tcp")
                        if proto not in ("tcp", "udp", "both"): raise ValueError("Invalid protocol")
                        if not (1 <= lp <= 65535 and 1 <= dp <= 65535): raise ValueError("Invalid port")
                        r = subprocess.run([BIN, "reverse", "add", ip, str(lp), str(dp), proto], capture_output=True, text=True, timeout=60)
                        if r.returncode:
                            msg = (r.stderr or r.stdout).strip().splitlines()
                            raise ValueError(re.sub(r"^error: ", "", msg[-1])[:200] if msg else "Command failed")
                        log("info", "Reverse forward %s:%d → this server:%d (%s)" % (ip, lp, dp, proto))
                        audit("reverse_add", "%s:%d->%d" % (ip, lp, dp), self.client_address[0])
                        return self.out(200, {"ok": True, "notice": "script"})
                    if a == "del":
                        lp = int(d.get("lport") or 0)
                        r = subprocess.run([BIN, "reverse", "del", ip, str(lp)], capture_output=True, text=True, timeout=60)
                        if r.returncode:
                            msg = (r.stderr or r.stdout).strip().splitlines()
                            raise ValueError(re.sub(r"^error: ", "", msg[-1])[:200] if msg else "Command failed")
                        log("info", "Reverse forward removed %s:%d" % (ip, lp)); audit("reverse_del", "%s:%d" % (ip, lp), self.client_address[0])
                        return self.out(200, {"ok": True, "notice": "script"})
                raise ValueError("Bad action")
            if self.path == "/api/perf":
                p = str(d.get("preset", ""))
                if p not in ("balanced", "turbo", "throughput", "gaming"): raise ValueError("Bad preset")
                r = subprocess.run([BIN, "perf", p], capture_output=True, text=True, timeout=120)
                if r.returncode: raise ValueError("Preset failed: " + (r.stderr or "").strip()[-150:])
                log("info", "Performance preset applied: %s" % p); audit("perf", p, self.client_address[0])
                return self.out(200, {"ok": True, "preset": p})
            if self.path == "/api/conntest":
                if CT["running"]: return self.out(200, {"running": True})
                CT["running"] = True
                def ctjob():
                    try: CT["result"] = conntest_run()
                    except Exception as e: log("warn", "conntest failed: %s" % type(e).__name__); CT["result"] = None
                    finally: CT["running"] = False
                threading.Thread(target=ctjob, daemon=True).start()
                log("info", "Connection test started"); audit("conntest", "", self.client_address[0])
                return self.out(200, {"running": True})
            if self.path == "/api/ctest":
                # two-server connection test: open ephemeral echo servers (or close them) and hand out the one-line link
                a = d.get("action")
                if a == "open":
                    r = subprocess.run([BIN, "ctest-open"], capture_output=True, text=True, timeout=30)
                    if r.returncode:
                        msg = (r.stderr or r.stdout).strip().splitlines()
                        raise ValueError(re.sub(r"^error: ", "", msg[-1])[:200] if msg else "Could not open the test")
                    out = r.stdout.split()
                    if len(out) != 3: raise ValueError((out[0] if out and str(out[0]).startswith("error:") else "Could not open the test"))
                    cid, tport, uport = out
                    host = (self.headers.get("Host") or socket.gethostname()).strip()
                    sch = "https" if cfg().get("tls") else "http"
                    log("info", "Two-server test link opened (tcp %s / udp %s)" % (tport, uport)); audit("ctest_open", "%s/%s" % (tport, uport), self.client_address[0])
                    return self.out(200, {"id": cid, "cmd": "bash <(curl -fsSLk %s://%s/ctest/%s)" % (sch, host, cid), "tport": int(tport), "uport": int(uport)})
                if a == "close":
                    subprocess.run([BIN, "ctest-close"], capture_output=True, text=True, timeout=30)
                    log("info", "Two-server test closed"); return self.out(200, {"ok": True})
                raise ValueError("Bad action")
            if self.path == "/api/totp":
                c = cfg(); a = d.get("action"); ip = self.client_address[0]
                if a == "setup":
                    s = b32secret(); upd(_totp_tmp=s)
                    return self.out(200, {"secret": s, "uri": "otpauth://totp/SEKA TUNEL:%s?secret=%s&issuer=SEKA TUNEL&algorithm=SHA1&digits=6&period=30" % (socket.gethostname(), s)})
                if a == "enable":
                    s = c.get("_totp_tmp")
                    if not s: raise ValueError("Setup first")
                    if not totp_ok(s, str(d.get("code", "")).strip()): raise ValueError("Wrong code")
                    codes = ["-".join((secrets.token_hex(2).upper() for _ in range(2))) for _ in range(8)]
                    upd(totp=True, totp_secret=s, rec=[hashlib.sha256(x.encode()).hexdigest() for x in codes], _totp_tmp="")
                    log("info", "2FA enabled"); audit("2fa_enabled", "", ip)
                    return self.out(200, {"ok": True, "codes": codes})
                if a == "disable":
                    if not hmac.compare_digest(mkhash(str(d.get("password", "")), c["salt"]), c["hash"]): raise ValueError("Current password is wrong")
                    upd(totp=False, totp_secret="", rec=[])
                    log("info", "2FA disabled"); audit("2fa_disabled", "", ip)
                    return self.out(200, {"ok": True})
                raise ValueError("Bad action")
            if self.path == "/api/rules/bulk":
                ks = {int(x) for x in d.get("lports", [])}
                with LOCK:
                    rs = read_rules(); keep = [r for r in rs if r["lport"] not in ks]
                    if len(keep) == len(rs): return self.out(404, {"error": "No such rule"})
                    write_rules(keep)
                    for k in ks: forget(k)
                log("info", "Removed %d forwards" % (len(rs) - len(keep))); return self.out(200, {"ok": True})
            if self.path == "/api/security":
                ks = [int(x) for x in (d.get("lports") or [d.get("lport", 0)])][:50]
                if not ks or not set(ks) <= {r["lport"] for r in read_rules()}: return self.out(404, {"error": "No such rule"})
                with LOCK:
                    for k in ks[:-1]: sec_save(k, d, False)
                    sec_save(ks[-1], d)
                log("info", "Security updated for %s" % ", ".join(":%d" % k for k in ks))
                return self.out(200, {"ok": True})
            if self.path == "/api/domain":
                if d.get("remove"): do_nodomain()
                else: do_domain(d.get("domain", ""), d.get("email", ""))
                return self.out(200, {"ok": True})
            if self.path == "/api/cert": do_cert(d.get("cert", ""), d.get("key", "")); return self.out(200, {"ok": True})
            m = re.fullmatch(r"/api/test/(\d+)", self.path)
            if m:
                rs = read_rules(); i = int(m.group(1)) - 1
                if not 0 <= i < len(rs): return self.out(404, {"error": "No such rule"})
                r = rs[i]
                return self.out(200, {"ms": None if r["proto"] == "udp" else tcp_ms(eff_ip(r["ip"]), r["dport"]), "udp": r["proto"] == "udp"})
            if self.path == "/api/settings/telegram":
                kw = {"tg_chat": str(d.get("chat", "")).strip()[:64], "tg_api": str(d.get("api", "")).strip().rstrip("/")[:200], "tg_bot": bool(d.get("bot", True)), "tg_report": bool(d.get("report", True)), "tg_backup": bool(d.get("backup", True))}
                if kw["tg_api"] and not kw["tg_api"].startswith("http"): raise ValueError("API address must start with https://")
                if d.get("token"): kw["tg_token"] = str(d["token"]).strip()[:200]
                for key, val in (("tg_report_hour", d.get("report_hour")), ("tg_backup_hour", d.get("backup_hour"))):
                    try: kw[key] = max(0, min(23, int(val)))
                    except Exception: pass
                upd(**kw); log("info", "Telegram settings updated"); audit("tg_settings", "", self.client_address[0]); return self.out(200, {"ok": True})
            if self.path == "/api/settings/tgtest":
                e = tg_send("✅ SEKA TUNEL: Telegram connection works")
                return self.out(200 if not e else 400, {"ok": not e, "error": e})
            if self.path == "/api/settings/password":
                c = cfg()
                if not hmac.compare_digest(mkhash(str(d.get("old", "")), c["salt"]), c["hash"]): raise ValueError("Current password is wrong")
                pw = str(d.get("new", ""))
                if len(pw) < 8: raise ValueError("New password must be at least 8 characters")
                salt = secrets.token_hex(16); upd(salt=salt, hash=mkhash(pw, salt))
                keep = self.token()
                for t in list(SESS):
                    if t != keep: SESS.pop(t)
                log("info", "Admin password changed"); audit("password_changed", "", self.client_address[0]); return self.out(200, {"ok": True})
            if self.path == "/api/restore":
                with LOCK: restore(base64.b64decode(d.get("data", ""))); log("info", "Forwards restored from backup"); audit("restore", "", self.client_address[0])
                return self.out(200, {"ok": True})
            self.out(404, {"error": "not found"})
        except (ValueError, tarfile.TarError, base64.binascii.Error) as e: self.out(400, {"error": str(e) or "Bad request"})
        except Exception: self.out(500, {"error": "Server error"})

    def login(self, d):
        ip = self.client_address[0]; n, until = FAILS.get(ip, (0, 0))
        if until > time.time(): return self.out(429, {"error": "Too many attempts, try later"})
        c = cfg()
        ok = "hash" in c and hmac.compare_digest(mkhash(str(d.get("password", "")), c["salt"]), c["hash"])
        if not ok:
            n += 1; FAILS[ip] = (n, time.time() + 300 if n >= 5 else 0)
            log("warn", "Failed login from %s" % ip); audit("login_failed", "", ip); time.sleep(1); return self.out(401, {"error": "Wrong password"})
        if c.get("totp"):
            code = str(d.get("code") or "").strip()
            if not code: return self.out(200, {"totp": True})   # client must ask for the second step
            if not (totp_ok(c.get("totp_secret", ""), code) or rec_use(code, c)):
                audit("2fa_failed", "", ip); time.sleep(1); return self.out(401, {"error": "Wrong code"})
        FAILS.pop(ip, None); t = secrets.token_urlsafe(32); SESS[t] = time.time() + 43200
        log("info", "Login from %s" % ip); audit("login", "", ip)
        ck = "drc=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200%s" % (t, "; Secure" if c.get("tls") else "")
        self.out(200, {"ok": True}, extra=[("Set-Cookie", ck)])

if __name__ == "__main__":
    a = sys.argv[1:] or ["serve"]; c = cfg()
    if a[0] == "setpass":
        c["salt"] = secrets.token_hex(16); c["hash"] = mkhash(a[1], c["salt"]); save(c)
    elif a[0] == "setport": c["port"] = int(a[1]); save(c)
    elif a[0] == "settls": c["tls"] = a[1] == "1"; save(c)
    elif a[0] == "setdomain":
        try: do_domain(a[1], a[2] if len(a) > 2 else "", restart=False); print("OK")
        except Exception as e: print("ERROR:", e); sys.exit(1)
    elif a[0] == "info": print(c.get("port", 8443), "https" if c.get("tls") else "http", c.get("domain") or "-")
    elif a[0] == "conntest": print(json.dumps(conntest_run()))
    else:
        threading.Thread(target=sampler, daemon=True).start()
        threading.Thread(target=monitor, daemon=True).start()
        threading.Thread(target=tg_bot, daemon=True).start()
        try: subprocess.run([BIN, "apply"], timeout=20)
        except Exception: pass
        threading.Thread(target=quota_loop, daemon=True).start()
        log("info", "SEKA TUNEL web panel started on port %s" % c.get("port", 8443))
        srv = ThreadingHTTPServer(("0.0.0.0", c.get("port", 8443)), H)
        if c.get("tls"):
            x = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try: x.load_cert_chain(c.get("cert") or CERT, c.get("key") or KEY)
            except Exception as e:
                log("warn", "Certificate could not be loaded (%s): using the self-signed one" % type(e).__name__); x.load_cert_chain(CERT, KEY)
            srv.socket = x.wrap_socket(srv.socket, server_side=True)
            if c.get("domain"): HSTS_H = (("Strict-Transport-Security", "max-age=31536000"),)
        srv.serve_forever()
PYEOF
  sed -i "s/__DR_VERSION__/$VERSION/g" "$WEB_PY"

  cat > "$WEB_UI" <<'HTMLEOF'
<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#07060f">
<title>SEKA TUNEL</title>
<script>try{if(localStorage.getItem("drl")==="en"){document.documentElement.lang="fa";document.documentElement.dir="ltr"}}catch(e){}</script>
<style>
:root{--bg:#07060f;--panel:#0c0b16;--gl:#1d1b2e;--fx:255,255,255;--acr:var(--fx);--line:#ffffff12;--line2:#ffffff24;--tx:#f6f5ff;--mu:#8d8aa5;--pr:#8b5cf6;--ok:#22c55e;--er:#ef4444;--wa:#f59e0b;--f:#100e1c;--sunk:#ffffff0a;--sh:0 1px 0 #ffffff08 inset,0 18px 50px #00000080}
body[data-t=light]{--bg:#f3f2fa;--panel:#ffffff;--gl:#e4e2f0;--fx:20,16,44;--line:#00000010;--line2:#00000022;--tx:#12101f;--mu:#6f6c85;--f:#ffffff;--sunk:#00000008;--sh:0 1px 0 #fff inset,0 18px 44px #1d164038}
*{box-sizing:border-box}
body{--ac:var(--tx);--acf:var(--bg);--acg:#c8c8ce;--acp:#8b5cf6}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.6 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Vazirmatn,Tahoma,system-ui,sans-serif;min-height:100vh;-webkit-font-smoothing:antialiased;transition:background .3s,color .3s;overflow-x:hidden;-webkit-tap-highlight-color:transparent}
button,input,select,textarea{font:inherit;color:inherit}
:focus-visible{outline:2px solid color-mix(in srgb,var(--ac) 70%,transparent);outline-offset:2px}
::selection{background:color-mix(in srgb,var(--ac) 32%,transparent)}
/* ---------------- galaxy lighting ---------------- */
#aur{position:fixed;inset:0;z-index:-1;pointer-events:none;overflow:hidden}
#aur .a{position:absolute;border-radius:50%;filter:blur(90px);mix-blend-mode:screen;opacity:.55;will-change:transform}
#aur .a1{width:58vw;height:58vw;left:-16vw;top:-22vw;background:radial-gradient(circle,color-mix(in srgb,var(--ac) 60%,transparent),transparent 66%);animation:au1 26s ease-in-out infinite alternate}
#aur .a2{width:46vw;height:46vw;right:-12vw;top:16vh;background:radial-gradient(circle,color-mix(in srgb,var(--acg) 52%,transparent),transparent 66%);animation:au2 32s ease-in-out infinite alternate}
#aur .a3{width:40vw;height:40vw;left:24vw;bottom:-20vw;background:radial-gradient(circle,color-mix(in srgb,var(--acp) 46%,transparent),transparent 66%);animation:au3 38s ease-in-out infinite alternate}
body[data-t=light] #aur .a{mix-blend-mode:normal;opacity:.22;filter:blur(110px)}
#aur .st{position:absolute;inset:0;opacity:.7;background-image:
 radial-gradient(1.2px 1.2px at 12% 22%,#ffffffcc,transparent),
 radial-gradient(1px 1px at 34% 8%,#ffffff9c,transparent),
 radial-gradient(1.4px 1.4px at 62% 30%,#ffffffb8,transparent),
 radial-gradient(1px 1px at 82% 12%,#ffffff8c,transparent),
 radial-gradient(1.2px 1.2px at 90% 44%,#ffffffaa,transparent),
 radial-gradient(1px 1px at 22% 58%,#ffffff7a,transparent),
 radial-gradient(1.3px 1.3px at 48% 74%,#ffffff9c,transparent),
 radial-gradient(1px 1px at 70% 60%,#ffffff6e,transparent),
 radial-gradient(1.1px 1.1px at 8% 82%,#ffffff90,transparent),
 radial-gradient(1px 1px at 94% 78%,#ffffff80,transparent);
 animation:twk 7s ease-in-out infinite alternate}
body[data-t=light] #aur .st{display:none}
@keyframes twk{from{opacity:.35}to{opacity:.85}}
@keyframes au1{to{transform:translate(10vw,7vh) scale(1.14)}}
@keyframes au2{to{transform:translate(-9vw,-6vh) scale(1.2)}}
@keyframes au3{to{transform:translate(-7vw,-9vh) scale(1.12)}}
body::before{content:"";position:fixed;top:0;bottom:0;left:-250px;right:0;z-index:-2;pointer-events:none;background:repeating-linear-gradient(90deg,transparent 0 118px,rgba(var(--fx),.04) 118px 250px);-webkit-mask:linear-gradient(to bottom,transparent 30%,#000 100%);mask:linear-gradient(to bottom,transparent 30%,#000 100%);animation:drift 40s linear infinite}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:radial-gradient(1000px 420px at 50% -10%,color-mix(in srgb,var(--ac) 14%,transparent),transparent 70%),linear-gradient(to top,rgba(var(--fx),.08),transparent 38%)}
@keyframes drift{to{transform:translateX(250px)}}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes pop{from{opacity:0;transform:scale(.94) translateY(10px)}to{opacity:1;transform:none}}
@keyframes tin{from{opacity:0;transform:translateY(16px) scale(.95)}to{opacity:1;transform:none}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
@keyframes glow{0%,100%{box-shadow:0 0 0 0 transparent,0 8px 26px -6px rgba(var(--acr),.55)}50%{box-shadow:0 0 26px 2px rgba(var(--acr),.28),0 10px 30px -6px rgba(var(--acr),.6)}}
.ic{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
.fi{width:15px;height:15px;fill:currentColor;flex:none}
.mk{width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,var(--acg),var(--ac));display:grid;place-items:center;flex:none;animation:glow 4.5s ease-in-out infinite;box-shadow:0 6px 22px -6px rgba(var(--acr),.65)}.mk svg{width:22px;height:22px}
.layout{min-height:100vh;display:flex;flex-direction:column}
/* ---------------- header / tabs ---------------- */
.top{direction:ltr;display:flex;align-items:center;justify-content:space-between;gap:12px;width:100%;max-width:1240px;margin:0 auto;padding:22px 28px 18px;animation:rise .5s both}
.brand{display:flex;align-items:center;gap:12px;min-width:0}.brand .dr{height:26px;width:auto;flex:none;filter:drop-shadow(0 2px 12px rgba(var(--acr),.55))}
.brand .tt{line-height:1.25;min-width:0}.brand .tt b{display:block;font-size:15px;letter-spacing:.02em}.brand .tt small{display:block;color:var(--mu);font-size:11.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tools{display:flex;gap:10px}
.ibtn{display:inline-flex;align-items:center;gap:8px;height:42px;padding:0 16px;border-radius:14px;border:1px solid var(--line2);background:var(--sunk);color:var(--mu);cursor:pointer;transition:.2s;backdrop-filter:blur(12px)}
.ibtn:hover{color:var(--tx);border-color:color-mix(in srgb,var(--ac) 55%,var(--line2));transform:translateY(-1px);box-shadow:0 6px 18px -8px rgba(var(--acr),.5)}.ibtn.sq{padding:0;width:42px;justify-content:center}
.tabs{display:flex;justify-content:center;padding:4px 16px 8px;animation:rise .55s .05s both}
.seg{position:relative;display:flex;gap:4px;padding:5px;border-radius:18px;background:color-mix(in srgb,var(--panel) 82%,transparent);border:1px solid var(--line2);box-shadow:var(--sh);max-width:100%;overflow-x:auto;scrollbar-width:none;backdrop-filter:blur(14px)}.seg::-webkit-scrollbar{display:none}
.ind{position:absolute;top:5px;bottom:5px;left:0;width:0;border-radius:13px;background:linear-gradient(135deg,var(--acg),var(--ac));box-shadow:0 6px 20px -4px rgba(var(--acr),.65),inset 0 1px 0 rgba(255,255,255,.25);transition:transform .38s cubic-bezier(.3,.9,.25,1),width .38s cubic-bezier(.3,.9,.25,1);z-index:0}
.nav{position:relative;z-index:1;display:inline-flex;align-items:center;gap:8px;white-space:nowrap;background:0;border:0;color:var(--mu);padding:10px 18px;border-radius:13px;cursor:pointer;transition:color .22s,background .22s}
.nav:hover{color:var(--tx);background:var(--sunk)}.nav.on{color:var(--acf);font-weight:600}
main{width:100%;max-width:1240px;margin:0 auto;padding:6px 28px 26px;flex:1}
section{animation:rise .5s both}
.sec{display:flex;align-items:center;gap:14px;color:var(--mu);font-size:12px;font-weight:600;margin:26px 0 12px}.sec::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}
/* ---------------- cards / panels ---------------- */
.panel{direction:ltr;display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1px;background:var(--gl);border-radius:24px;overflow:hidden;box-shadow:var(--sh);animation:rise .6s both;position:relative}
.panel::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(135deg,rgba(var(--acr),.5),rgba(var(--fx),.09) 38%,rgba(var(--acr),.16) 60%,rgba(var(--fx),.1));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);mask-composite:exclude;pointer-events:none}
.panel.two{grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}
.cell{background:color-mix(in srgb,var(--panel) 90%,transparent);padding:22px 24px;direction:ltr;text-align:left;transition:background .25s;backdrop-filter:blur(10px)}.cell:hover{background:color-mix(in srgb,var(--panel) 84%,var(--ac) 5%)}
.hd{display:flex;align-items:baseline;gap:8px}.v{font-size:34px;font-weight:700;letter-spacing:-.03em;line-height:1.1;font-variant-numeric:tabular-nums;text-shadow:0 0 22px rgba(var(--acr),.28)}
body[data-t=light] .v{text-shadow:none}
.v small{font-size:15px;font-weight:500;color:var(--mu);margin-left:2px;letter-spacing:0;text-shadow:none}.v.sm{font-size:20px;letter-spacing:-.01em}
.l{color:var(--mu);font-size:13px}.s{color:var(--mu);font-size:12px;margin-top:14px;direction:ltr}
.pb{height:11px;margin-top:22px;direction:ltr;background:var(--line2);-webkit-mask:repeating-linear-gradient(90deg,#000 0 12px,transparent 12px 16px);mask:repeating-linear-gradient(90deg,#000 0 12px,transparent 12px 16px)}
.pb i{display:block;height:100%;width:0;background:linear-gradient(90deg,color-mix(in srgb,var(--ac) 60%,transparent),var(--ac));box-shadow:0 0 12px rgba(var(--acr),.5);transition:width .9s cubic-bezier(.2,.7,.2,1)}
.hist{display:flex;gap:4px;align-items:flex-end;height:64px;margin-top:16px;direction:ltr}.hist i{flex:1;min-height:6px;background:rgba(var(--acr),.24);border-radius:3px;transition:height .6s cubic-bezier(.2,.7,.2,1)}
.hist i:last-child{background:linear-gradient(to top,var(--acg),var(--ac));box-shadow:0 0 12px rgba(var(--acr),.55)}
/* ---------------- buttons ---------------- */
.btn{border:1px solid var(--line2);background:var(--sunk);color:var(--tx);padding:8px 16px;border-radius:12px;cursor:pointer;transition:.18s}
.prsel{width:auto;min-width:104px;padding:7px 10px;border-radius:11px;font-size:13px}
.btn.okc{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,var(--line2))}.btn.errc{color:var(--er);border-color:color-mix(in srgb,var(--er) 45%,var(--line2))}
.btn:hover{border-color:color-mix(in srgb,var(--ac) 55%,var(--line2));transform:translateY(-1px);box-shadow:0 6px 16px -8px rgba(var(--acr),.55)}.btn:active{transform:scale(.97)}
.btn.p{background:linear-gradient(135deg,var(--acg),var(--ac));color:var(--acf);border-color:transparent;font-weight:600;box-shadow:0 5px 20px -6px rgba(var(--acr),.65),inset 0 1px 0 rgba(255,255,255,.22)}
.btn.p:hover{box-shadow:0 9px 28px -6px rgba(var(--acr),.75),inset 0 1px 0 rgba(255,255,255,.26)}
.btn.on{border-color:var(--ac);box-shadow:inset 0 0 0 1px var(--ac),0 0 16px -6px rgba(var(--acr),.6)}
.btn.d{color:var(--er)}.btn.d:hover{border-color:var(--er);box-shadow:0 6px 16px -8px rgba(239,68,68,.6)}.btn:disabled{opacity:.45;cursor:default;transform:none;box-shadow:none}
h1{font-size:19px;margin:22px 0 16px;letter-spacing:-.01em}
.card{position:relative;background:color-mix(in srgb,var(--panel) 88%,transparent);border-radius:22px;padding:22px;margin-bottom:16px;box-shadow:var(--sh);animation:rise .55s both;backdrop-filter:blur(12px)}
.card::before,.box::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(135deg,rgba(var(--acr),.5),rgba(var(--fx),.08) 40%,rgba(var(--acr),.14) 62%,rgba(var(--fx),.1));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);mask-composite:exclude;pointer-events:none}
.card:hover{box-shadow:var(--sh),0 0 36px -10px rgba(var(--acr),.3)}
.bar{display:flex;justify-content:space-between;align-items:center;margin:22px 0 14px}.bar h2,.bar h1{margin:0}
/* ---------------- tables ---------------- */
table{width:100%;border-collapse:collapse}th,td{padding:13px 12px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mu);font-weight:500;font-size:12px}tr:last-child td{border:0}tbody tr{transition:background .15s}tbody tr:hover td{background:rgba(var(--fx),.03)}
.ltr{direction:ltr;text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.tbl{overflow-x:auto}.tag{padding:2px 10px;border-radius:20px;font-size:11px;background:var(--sunk);border:1px solid var(--line2);text-transform:uppercase}
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 11px;border-radius:20px;font-size:12px}.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.pill.up{background:#22c55e1f;color:var(--ok);box-shadow:0 0 14px -4px rgba(34,197,94,.45)}.pill.up::before{animation:pulse 2s infinite;box-shadow:0 0 8px currentColor}
.pill.down{background:#ef44441f;color:var(--er);box-shadow:0 0 14px -4px rgba(239,68,68,.5)}.pill.unknown{background:var(--sunk);color:var(--mu)}
.mb{height:4px;border-radius:4px;background:var(--line2);margin-top:5px;min-width:110px;overflow:hidden}.mb i{display:block;height:100%;transition:width .6s;box-shadow:0 0 8px rgba(var(--acr),.4)}
.cp{cursor:copy;transition:color .15s}.cp::after{content:"⧉";opacity:0;font-size:11px;margin-inline-start:7px;transition:.15s;color:var(--ac)}.cp:hover{color:var(--tx)}.cp:hover::after{opacity:.75}
.empty{text-align:center;color:var(--mu);padding:34px}
/* ---------------- search ---------------- */
.srch{position:relative;display:flex;align-items:center;gap:9px;margin:2px 2px 14px;background:var(--f);border:1px solid var(--line2);border-radius:14px;padding:0 13px;transition:.2s;max-width:380px}
.srch:focus-within{border-color:var(--ac);box-shadow:0 0 0 4px color-mix(in srgb,var(--ac) 15%,transparent),0 0 20px -8px rgba(var(--acr),.6)}
.srch>.ic{color:var(--mu);width:16px;height:16px}
.srch input{border:0;background:0;padding:10px 2px;width:100%;direction:rtl;text-align:right}
.srch input:focus{box-shadow:none;border:0}
html[dir=ltr] .srch input{direction:ltr;text-align:left}
.srch .clr{position:absolute;inset-inline-end:7px;width:24px;height:24px;display:grid;place-items:center;border:0;background:0;color:var(--mu);border-radius:8px;cursor:pointer;transition:.15s}.srch .clr:hover{color:var(--tx);background:var(--sunk)}
/* ---------------- tunnel wizard + connection test ---------------- */
.wsteps{display:flex;gap:6px;margin:2px 0 14px}
.wsteps i{flex:1;height:4px;border-radius:99px;background:var(--sunk);transition:.25s}
.wsteps i.on{background:var(--acp);box-shadow:0 0 8px color-mix(in srgb,var(--acp) 60%,transparent)}
.wsteps i.done{background:color-mix(in srgb,var(--acp) 45%,transparent)}
.wcard{border:1px solid var(--line);border-radius:14px;padding:12px 14px;margin-bottom:9px;cursor:pointer;transition:.15s;background:var(--sunk)}
.wcard:hover{border-color:var(--line2)}
.wcard.on{border-color:var(--acp);background:color-mix(in srgb,var(--acp) 10%,transparent);box-shadow:0 0 0 1px var(--acp) inset}
.wcard b{display:flex;align-items:center;gap:8px;font-size:14px;margin-bottom:3px;flex-wrap:wrap}
.wcard small{color:var(--mu);line-height:1.6;display:block}
.wrow{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:12px}
.wrow .l{font-size:12px;color:var(--mu);display:block}
.wrow b{font-size:15px}
/* ---------------- modal / inputs ---------------- */
.modal{position:fixed;inset:0;background:rgba(4,3,10,.62);backdrop-filter:blur(10px);display:none;place-items:center;padding:16px;z-index:20}.modal.on{display:grid;animation:rise .2s both}
body[data-t=light] .modal{background:rgba(29,22,64,.32)}
.box{position:relative;background:color-mix(in srgb,var(--panel) 92%,transparent);border-radius:24px;padding:24px;width:100%;max-width:470px;max-height:92vh;overflow:auto;box-shadow:var(--sh);animation:pop .38s cubic-bezier(.16,1,.3,1) both;backdrop-filter:blur(18px)}
.box h3{margin:0 0 14px;font-size:17px}label{display:block;color:var(--mu);font-size:12px;margin:12px 0 5px}
input,select,textarea{width:100%;background:var(--f);border:1px solid var(--line2);color:var(--tx);border-radius:13px;padding:11px 13px;direction:ltr;text-align:left;transition:.18s}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--ac);box-shadow:0 0 0 4px color-mix(in srgb,var(--ac) 16%,transparent),0 0 20px -8px rgba(var(--acr),.55)}
.row{display:flex;gap:10px}.row>*{flex:1}.acts{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}
.grp{cursor:pointer;background:color-mix(in srgb,var(--ac) 7%,transparent)}.grp td{font-weight:600}.sub td{background:rgba(var(--fx),.025)}.sub td:first-child{opacity:.35}
.hint{color:var(--mu);font-size:12px;margin-top:6px}
.hl{display:flex;gap:12px;align-items:flex-start;padding:12px 0;border-bottom:1px solid var(--line)}.hl:last-child{border:0}
.hl b{font-size:16px;line-height:1.3}.hl .ok{color:var(--ok)}.hl .warn{color:var(--wa)}.hl .err{color:var(--er)}.hl code{display:block;direction:ltr;text-align:left;color:var(--mu);font-size:12px;margin-top:2px}
.lg{font:12px/1.9 ui-monospace,Menlo,Consolas,monospace;direction:ltr;text-align:left;max-height:62vh;overflow:auto}.lg .warn{color:var(--wa)}.lg .info{color:var(--mu)}.lg .err{color:var(--er)}
.qh{display:flex;gap:18px;align-items:center;margin:4px 0 14px}.ringw{position:relative;width:112px;height:112px;flex:none}.ringw svg{width:112px;height:112px;transform:rotate(-90deg)}
.trk{stroke:var(--line2);stroke-width:9;fill:none}.arc{stroke-width:9;fill:none;stroke-linecap:round;transition:stroke-dasharray .6s}.mid{position:absolute;inset:0;display:grid;place-items:center;font-size:21px;font-weight:700}
.qn{flex:1;display:grid;gap:6px}.qn div{display:flex;justify-content:space-between;gap:8px}.qn span{color:var(--mu)}.qn b{direction:ltr}
.pre{display:flex;flex-wrap:wrap;gap:8px}.qs{padding:10px 12px;border-radius:12px;margin:0 0 12px;font-size:13px;background:var(--sunk)}.qs.er{color:var(--er);background:#ef444419}
/* ---------------- footer ---------------- */
.foot{width:100%;max-width:1240px;margin:0 auto;padding:14px 28px 30px;display:flex;justify-content:center;animation:rise .6s .1s both}
.fin{display:flex;align-items:center;gap:14px;flex-wrap:wrap;justify-content:center;color:var(--mu);font-size:12.5px}
.fgl{display:inline-flex;align-items:center;gap:7px;color:var(--mu);text-decoration:none;transition:.2s;direction:ltr}
.fgl:hover{color:var(--tx);transform:translateY(-1px)}
.fgl .fi{filter:drop-shadow(0 0 7px rgba(var(--acr),.45))}
.fd{width:3px;height:3px;border-radius:50%;background:var(--mu);opacity:.55;flex:none}
.fver{direction:ltr;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;opacity:.7}
/* ---------------- login ---------------- */
#login{min-height:100vh;display:grid;place-items:center;padding:20px}
#login .lbox{position:relative;width:100%;max-width:420px;background:color-mix(in srgb,var(--panel) 86%,transparent);border-radius:28px;box-shadow:var(--sh);overflow:hidden;animation:pop .6s cubic-bezier(.16,1,.3,1) both;backdrop-filter:blur(22px)}
#login .lbox::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(135deg,rgba(var(--acr),.55),rgba(var(--fx),.08) 40%,rgba(var(--acr),.2));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);mask-composite:exclude;pointer-events:none}
#login .lin{padding:36px 30px 28px;position:relative}#login .hero{text-align:center;margin-bottom:26px}#login .hero .mk{width:62px;height:62px;border-radius:19px;margin:0 auto 16px}#login .hero .mk svg{width:32px;height:32px}
#login .hero .dr{height:30px;width:auto;display:block;margin:0 auto 6px;filter:drop-shadow(0 2px 14px rgba(var(--acr),.55))}#login .hero h2{margin:0;font-size:19px;letter-spacing:.01em}#login .hero p{margin:4px 0 0;color:var(--mu);font-size:13px}
#login label{margin:0 0 7px}
.pwf{position:relative}.pwf input{padding:15px 46px;border-radius:16px;font-size:15px}
.pwf .lk{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--mu);pointer-events:none}
.pwf .eye{position:absolute;right:7px;top:50%;transform:translateY(-50%);width:36px;height:36px;display:grid;place-items:center;border:0;background:0;color:var(--mu);border-radius:10px;cursor:pointer;transition:.18s}.pwf .eye:hover{color:var(--tx);background:var(--sunk)}
#login .go{width:100%;margin-top:14px;padding:14px;border-radius:16px;font-size:15px;display:flex;align-items:center;justify-content:center;gap:10px}#login .go .ic{transition:transform .2s;transform:scaleX(-1)}#login .go:hover .ic{transform:scaleX(-1) translateX(5px)}
#login .ft{border-top:1px solid var(--line);padding:15px;background:rgba(var(--fx),.02);display:flex;align-items:center;justify-content:center;gap:14px}
#login .lgl{position:fixed;top:18px;inset-inline-end:18px;z-index:2}
/* ---------------- toast ---------------- */
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);display:grid;gap:8px;z-index:30;width:max-content;max-width:92vw}
.t{background:color-mix(in srgb,var(--panel) 92%,transparent);border:1px solid var(--line2);border-radius:14px;padding:11px 18px;box-shadow:var(--sh);animation:tin .3s cubic-bezier(.16,1,.3,1) both;backdrop-filter:blur(14px);cursor:pointer}
.t.s{border-color:#22c55e55;box-shadow:var(--sh),0 8px 28px -8px rgba(34,197,94,.4)}
.t.e{border-color:#ef444455;box-shadow:var(--sh),0 8px 28px -8px rgba(239,68,68,.45)}
.hide{display:none!important}details summary{cursor:pointer;color:var(--mu);margin-top:14px}
@media(max-width:800px){.top{padding:16px 16px 12px}.brand .tt small{max-width:150px}.ibtn span{display:none}.ibtn{padding:0;width:42px;justify-content:center}.tabs{justify-content:flex-start;padding:4px 12px 6px}main{padding:6px 14px 20px}.foot{padding:14px 14px 24px}.v{font-size:28px}.cell{padding:18px}.row{flex-direction:column}.qh{flex-direction:column;align-items:flex-start}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
#login .sws{margin:0}
.sws{display:flex;flex-wrap:wrap;gap:14px;margin:16px 2px 6px}
.sw{position:relative;display:inline-block;width:34px;height:34px;border-radius:50%;border:0;padding:0;background:var(--c);cursor:pointer;transition:transform .18s,box-shadow .18s;box-shadow:inset 0 0 0 1px rgba(var(--fx),.2)}
.sw:hover{transform:scale(1.14)}.sw[data-c=mono]{background:linear-gradient(135deg,#fafafa 50%,#18181b 50%)}
.sw.cu{margin:0;background:conic-gradient(#ef4444,#f59e0b,#22c55e,#06b6d4,#3b82f6,#8b5cf6,#ec4899,#ef4444)}
.sw.on{box-shadow:0 0 0 2px var(--panel),0 0 0 4px var(--c),0 0 18px -2px rgba(var(--acr),.55)}
.sw input{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer;padding:0;border:0;border-radius:50%}
/* ---------------- boot ---------------- */
#boot{position:fixed;inset:0;z-index:50;display:grid;place-items:center;background:color-mix(in srgb,var(--bg) 62%,transparent);backdrop-filter:blur(20px);overflow:hidden;transition:opacity .6s,transform .6s,filter .6s;animation:fin .4s both}
#boot.out{opacity:0;transform:scale(1.06);filter:blur(8px);pointer-events:none}
.bwrap{position:relative;z-index:1;display:grid;justify-items:center;width:min(340px,86vw);direction:ltr;text-align:center}
.ring{position:relative;width:118px;height:118px;display:grid;place-items:center;margin-bottom:22px}
.ring::before{content:"";position:absolute;inset:-26px;border-radius:50%;background:radial-gradient(circle,rgba(var(--acr),.28),transparent 68%);animation:pulse 3s ease-in-out infinite}
.ring .rg{position:absolute;inset:0;width:100%;height:100%;transform:rotate(-90deg);overflow:visible}
.ring .r0{fill:none;stroke:var(--line2);stroke-width:2}
.ring .r1{fill:none;stroke:var(--ac);stroke-width:3;stroke-linecap:round;stroke-dasharray:289;stroke-dashoffset:289;transition:stroke-dashoffset .8s cubic-bezier(.3,.7,.2,1);filter:drop-shadow(0 0 6px rgba(var(--acr),.75))}
.ring .sp{transform-origin:50px 50px;animation:spin 1.3s linear infinite;transition:opacity .4s}
.ring .sp circle{fill:none;stroke:var(--ac);stroke-width:1.6;stroke-linecap:round;stroke-dasharray:24 265;opacity:.55}
#boot.done .sp{opacity:0}
.ring .mk{width:70px;height:70px;border-radius:22px;animation:glow 3.2s ease-in-out infinite,bob 3.2s ease-in-out infinite}.ring .mk svg{width:35px;height:35px}
#boot.done .ring .mk{animation:glow 3.2s ease-in-out infinite,pulseok .7s both}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-3px)}}
@keyframes fin{from{opacity:0}to{opacity:1}}
@keyframes sweep{from{transform:translateX(-120%)}to{transform:translateX(300%)}}
@keyframes pulseok{0%{transform:scale(1)}40%{transform:scale(1.12)}100%{transform:scale(1)}}
.bwrap .dr{height:34px;width:auto;margin-bottom:6px;filter:drop-shadow(0 2px 14px rgba(var(--acr),.5))}
.bt{font-weight:700;font-size:14px;letter-spacing:.34em;text-indent:.34em}
.bs{color:var(--mu);font-size:13px;margin:10px 0 28px;min-height:20px}.bs b{color:var(--tx);font-weight:600;margin-inline-start:8px;font-variant-numeric:tabular-nums}
.bsteps{display:grid;gap:12px;width:100%}
.bst{display:flex;align-items:center;gap:12px;color:var(--mu);font-size:12.5px;transition:color .3s}
.bst .tk{width:17px;height:17px;border-radius:50%;border:1.5px solid var(--line2);display:grid;place-items:center;flex:none;transition:.3s;font-style:normal}
.bst .tk svg{width:10px;height:10px;stroke:var(--acf);fill:none;stroke-width:3;stroke-linecap:round;stroke-linejoin:round;opacity:0;transform:scale(.4);transition:.3s}
.bst .lb{flex:none;width:124px;text-align:left}
.bst i{flex:1;height:3px;border-radius:3px;background:var(--line2);position:relative;overflow:hidden}
.bst b{position:absolute;inset:0 auto 0 0;width:0;background:linear-gradient(90deg,var(--acg),var(--ac));border-radius:3px;transition:width .5s;box-shadow:0 0 8px rgba(var(--acr),.5)}
.bst.run{color:var(--tx)}.bst.run .tk{border-color:var(--ac)}.bst.run b{width:38%;animation:sweep 1.1s ease-in-out infinite}
.bst.ok{color:var(--tx)}.bst.ok .tk{background:linear-gradient(135deg,var(--acg),var(--ac));border-color:transparent}.bst.ok .tk svg{opacity:1;transform:none}.bst.ok b{width:100%;animation:none}
html[dir=ltr] th,html[dir=ltr] td{text-align:left}
html[dir=ltr] .ltr{text-align:left}
html[dir=ltr] #login .go .ic{transform:none}
html[dir=ltr] #login .go:hover .ic{transform:translateX(5px)}
</style></head><body>
<div id="aur" aria-hidden="true"><i class="a a1"></i><i class="a a2"></i><i class="a a3"></i><i class="st"></i></div>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<linearGradient id="gBolt" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fbbf24"/><stop offset="1" stop-color="#ef4444"/></linearGradient>
<linearGradient id="gDR" x1="0" y1="0" x2="1" y2="1"><stop offset="0" style="stop-color:var(--tx)"/><stop offset="1" style="stop-color:var(--pr)"/></linearGradient>
<symbol id="i-bolt" viewBox="0 0 24 24"><path d="M13.5 2 5 13.5h6L9.5 22 19 9.5h-6.2z" fill="url(#gBolt)"/></symbol>
<symbol id="i-dr" viewBox="0 0 76 36"><g transform="skewX(-9) translate(5 0)" fill="none" stroke="url(#gDR)" stroke-width="4.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h13c10 0 15 6 15 14s-5 14-15 14H4z"/><path d="M43 32V4h12c7 0 10 4 10 8.5S62 21 55 21H43"/><path d="M54 21l11 11"/></g></symbol>
<symbol id="i-gh" viewBox="0 0 24 24"><path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55v-2.17c-3.2.7-3.87-1.37-3.87-1.37-.52-1.33-1.28-1.68-1.28-1.68-1.05-.72.08-.71.08-.71 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.23-1.28-5.23-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.1 11.1 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.38-5.25 5.66.41.36.78 1.05.78 2.13v3.16c0 .3.21.67.8.55A11.5 11.5 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5z"/></symbol>
<symbol id="i-tg" viewBox="0 0 24 24"><path d="M9.04 15.51l-.38 5.32c.54 0 .78-.23 1.06-.51l2.55-2.44 5.28 3.87c.97.53 1.66.25 1.92-.9L23.9 4.4c.31-1.42-.51-1.98-1.45-1.63L2.9 10.2c-1.38.53-1.36 1.3-.24 1.65l4.69 1.46L18.3 6.9c.51-.34.98-.15.6.19l-9.86 8.42z"/></symbol>
</defs></svg>
<div id="boot"><div class="bwrap">
<div class="ring"><svg class="rg" viewBox="0 0 100 100"><circle class="r0" cx="50" cy="50" r="46"/><circle class="r1" id="b_r" cx="50" cy="50" r="46"/><g class="sp"><circle cx="50" cy="50" r="46"/></g></svg><i class="mk"><svg><use href="#i-bolt"/></svg></i></div>
<svg class="dr" viewBox="0 0 76 36" aria-label="DR"><use href="#i-dr"/></svg><div class="bt">CPANEL</div>
<div class="bs"><span id="b_s">در حال بارگذاری…</span><b id="b_p">0%</b></div>
<div class="bsteps"><div class="bst"><em class="tk"><svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg></em><span class="lb">احراز هویت</span><i><b></b></i></div><div class="bst"><em class="tk"><svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg></em><span class="lb">داده‌های سرور</span><i><b></b></i></div><div class="bst"><em class="tk"><svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg></em><span class="lb">رابط کاربری</span><i><b></b></i></div></div></div></div>
<div id="login" class="hide"><button class="ibtn lng lgl" type="button" title="زبان"><svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9S14.5 18.3 12 21c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/></svg><span class="lc">EN</span></button><div class="lbox"><div class="lin">
<div class="hero"><i class="mk"><svg><use href="#i-bolt"/></svg></i><svg class="dr" viewBox="0 0 76 36" aria-label="DR"><use href="#i-dr"/></svg><h2>CPanel</h2><p>ورود به پنل مدیریت تانل</p></div>
<label for="pw">رمز عبور</label>
<div class="pwf"><svg class="ic lk" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg><input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus spellcheck="false" autocapitalize="off"><button class="eye" id="eye" type="button" title="نمایش رمز"><svg class="ic" viewBox="0 0 24 24"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button></div>
<div class="pwf hide" id="tfa"><svg class="ic lk" viewBox="0 0 24 24"><path d="M12 2l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V5z"/><path d="M9 12l2 2 4-4"/></svg><input id="to" inputmode="numeric" maxlength="10" placeholder="کد دومرحله‌ای یا کد بازیابی" autocomplete="one-time-code" spellcheck="false" autocapitalize="off"></div>
<button class="btn p go" id="lb" type="button">ورود<svg class="ic" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg></button>
</div><div class="ft"></div></div></div>

<div class="layout hide" id="app">
<header class="top"><div class="brand"><i class="mk"><svg><use href="#i-bolt"/></svg></i><svg class="dr" viewBox="0 0 76 36" aria-label="DR"><use href="#i-dr"/></svg><div class="tt"><b>CPanel</b><small><span id="host"></span> · <span id="ver"></span></small></div></div>
<div class="tools"><button class="ibtn lng" type="button" title="زبان"><svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9S14.5 18.3 12 21c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/></svg><span class="lc">EN</span></button><button class="ibtn" id="thm" title="تم"><svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 3v18a9 9 0 0 0 0-18z" fill="currentColor"/></svg><span>ظاهر</span></button><button class="ibtn sq" id="out" title="خروج"><svg class="ic" viewBox="0 0 24 24"><path d="M9 4H5v16h4M16 8l4 4-4 4M20 12H9"/></svg></button></div></header>
<nav class="tabs"><div class="seg"><i class="ind" id="ind" aria-hidden="true"></i><button class="nav on" data-p="dash"><svg class="ic" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg><span>داشبورد</span></button><button class="nav" data-p="tun"><svg class="ic" viewBox="0 0 24 24"><path d="M3 12h4l3-7 4 14 3-7h4"/></svg><span>تانل‌ها</span></button><button class="nav" data-p="test"><svg class="ic" viewBox="0 0 24 24"><path d="M12 3v3M5.6 5.6l2.2 2.2M3 12h3M18.4 5.6l-2.2 2.2M21 12h-3"/><circle cx="12" cy="15" r="5"/><path d="M12 15l2.5-2.5"/></svg><span>کانکشن تست</span></button><button class="nav" data-p="health"><svg class="ic" viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 4.5 3.4 8 8 9 4.6-1 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/></svg><span>بررسی سلامت</span></button><button class="nav" data-p="logs"><svg class="ic" viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h7"/></svg><span>لاگ‌ها</span></button><button class="nav" data-p="set"><svg class="ic" viewBox="0 0 24 24"><path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/></svg><span>تنظیمات</span></button></div></nav>
<main>
<section id="p_dash">
<div class="sec">سرور</div>
<div class="panel">
<div class="cell"><div class="hd"><b class="v" id="c_cpu">0<small>%</small></b><span class="l">CPU</span></div><div class="pb"><i id="b_cpu"></i></div><div class="s" id="s_load">—</div></div>
<div class="cell"><div class="hd"><b class="v" id="c_ram">0<small>%</small></b><span class="l">RAM</span></div><div class="pb"><i id="b_ram"></i></div><div class="s" id="s_ram">—</div></div>
<div class="cell"><div class="hd"><b class="v" id="c_dsk">0<small>%</small></b><span class="l">دیسک</span></div><div class="pb"><i id="b_dsk"></i></div><div class="s" id="s_dsk">—</div></div>
</div>
<div class="panel two" style="margin-top:14px">
<div class="cell"><div class="hd"><b class="v" id="c_dn">0<small>B/s</small></b><span class="l">Download</span></div><div class="hist" id="h_dn"></div><div class="s" id="s_dn">—</div></div>
<div class="cell"><div class="hd"><b class="v" id="c_up">0<small>B/s</small></b><span class="l">Upload</span></div><div class="hist" id="h_up"></div><div class="s" id="s_up">—</div></div>
</div>
<div class="sec">تانل‌ها</div>
<div class="panel">
<div class="cell"><div class="hd"><b class="v" id="t_n">0</b><span class="l">تانل</span></div><div class="s" id="t_ud">—</div></div>
<div class="cell"><div class="hd"><b class="v" id="t_b">0 B</b><span class="l">ترافیک کل</span></div><div class="s" id="t_p">—</div></div>
<div class="cell"><div class="hd"><b class="v" id="t_s">0 B/s</b><span class="l">سرعت لحظه‌ای</span></div><div class="s">live</div></div>
<div class="cell"><div class="hd"><b class="v sm" id="t_fw">—</b></div><div class="s" id="t_cc">—</div></div>
</div>
<div class="sec">ترافیک ۲۴ ساعت</div>
<div class="card" style="padding:16px"><div id="ch24" style="height:110px"></div><div class="hint" id="ch24s" style="margin:8px 0 0"></div></div>
<div class="sec">وضعیت تانل‌ها</div>
<div class="card"><div class="srch"><svg class="ic" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg><input id="q_d" placeholder="جستجو (نام، پورت، آی‌پی)…" autocomplete="off"><button class="clr hide" id="q_dx" type="button" title="پاک کردن"><svg class="ic" style="width:13px;height:13px" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div><div class="tbl"><table><thead><tr><th>نام</th><th>مسیر</th><th>وضعیت</th><th>پینگ</th><th>نمودار</th><th>سرعت</th></tr></thead><tbody id="tb_d"></tbody></table></div></div></section>

<section id="p_tun" class="hide"><div class="bar"><h1 style="margin:0">تانل‌ها</h1><button class="btn p" id="add">+ افزودن پورت فوروارد</button></div>
<div class="card"><h2 style="margin-top:0;font-size:16px">تانل رمزنگاری‌شده (WireGuard)</h2>
<div class="hint" style="margin:0 0 12px">ارتباط سرور ایران و سرور خارج را در هسته لینوکس رمزنگاری می‌کند (ChaCha20، سرعت بالا). فورواردها، حجم، سلامت و امنیت تانل بدون تغییر کار می‌کنند. فقط یک دستور روی سرور خارج اجرا می‌شود. ابتدا تانل را بساز، دستور را روی سرور خارج بزن، بعد با «تست» مقایسه کن و «فعال‌سازی» را بزن.</div>
<div style="overflow-x:auto"><table><thead><tr><th>سرور خارج</th><th>پورت UDP</th><th>وضعیت لینک</th><th>ترافیک</th><th>مسیر فورواردها</th><th>کارایی</th><th></th></tr></thead><tbody id="tb_t"></tbody></table></div>
<div class="acts" style="margin:12px 0 0;flex-wrap:wrap"><button class="btn p" id="t_add">+ ساخت تانل جدید</button><span class="hint" style="margin:0">ویزارد: نوع (ریورس / دایرکت / فوروارد) ← مشخصات ← کارایی ← اتصال. «لینک اتصال» هر تانل همیشه از ستون آخر قابل کپی است.</span></div></div>
<div class="card" style="margin-top:16px"><div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap"><h2 style="margin:0;font-size:16px">ریورس — پورت سرور خارج → سرویس همین سرور ایران</h2></div>
<div class="hint" style="margin:10px 0 12px">برعکس فوروارد: پورت روی <b>سرور خارج</b> باز می‌شود و هرکس به آن وصل شود، به سرویسی که روی همین سرور ایران اجرا شده می‌رسد (از داخل تانل رمزنگاری‌شده). مثلاً پنل یا VPN روی ایران داری و می‌خواهی با IP تمیز خارج دیده شود. بعد از هر تغییر، دکمه «دستور سرور خارج» را بزن و اسکریپت را دوباره روی سرور خارج اجرا کن.</div>
<div style="overflow-x:auto"><table><thead><tr><th>سرور خارج</th><th>پورت (سرور خارج)</th><th>پورت سرویس (ایران)</th><th>پروتکل</th><th></th></tr></thead><tbody id="tb_r"></tbody></table></div>
<div class="row" style="margin-top:12px"><div><label>سرور خارج</label><select id="rv_ip"></select></div><div><label>پورت روی سرور خارج</label><input id="rv_l" inputmode="numeric" placeholder="8443"></div><div><label>پورت سرویس روی ایران</label><input id="rv_d" inputmode="numeric" placeholder="8443"></div><div><label>پروتکل</label><select id="rv_p"><option>tcp</option><option>udp</option><option>both</option></select></div><div style="flex:0 0 auto;align-self:end"><button class="btn p" id="rv_add">+ افزودن ریورس</button></div></div><div id="rv_res" style="margin-top:10px"></div></div>
<div class="card" id="t_sc" style="display:none;margin-top:16px"><h2 style="margin-top:0;font-size:16px">این دستور را روی سرور خارج (root) اجرا کن</h2>
<div class="hint" style="margin:0 0 10px">فقط یک‌بار. بعد از اجرا حدود ۱۰ ثانیه صبر کن تا وضعیت لینک «متصل» شود. این متن شامل کلید خصوصی سرور خارج است؛ آن را جایی منتشر نکن.</div>
<textarea id="t_sx" rows="9" readonly style="font-size:12px"></textarea><div class="acts"><button class="btn p" id="t_cp">کپی</button></div></div>

<div class="card"><div class="srch"><svg class="ic" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg><input id="q_s" placeholder="جستجو (نام، پورت، آی‌پی)…" autocomplete="off"><button class="clr hide" id="q_sx" type="button" title="پاک کردن"><svg class="ic" style="width:13px;height:13px" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div><div class="tbl"><table><thead><tr><th>#</th><th>نام</th><th>پروتکل</th><th>پورت ورودی</th><th>مقصد</th><th>وضعیت</th><th>پینگ</th><th>حجم (مصرف / سقف)</th><th></th></tr></thead><tbody id="tb_m"></tbody></table></div></div></section>

<section id="p_test" class="hide"><div class="bar"><h1 style="margin:0">کانکشن تست</h1><button class="btn p" id="ct_run">اجرای تست</button></div>
<div class="panel">
<div class="cell"><div class="hd"><b class="v" id="ct_c">—</b><span class="l">CPU</span></div><div class="s" id="ct_cs">—</div></div>
<div class="cell"><div class="hd"><b class="v" id="ct_r">—</b><span class="l">RAM</span></div><div class="s" id="ct_rs">—</div></div>
<div class="cell"><div class="hd"><b class="v" id="ct_d">—</b><span class="l">دیسک</span></div><div class="s" id="ct_ds">—</div></div>
<div class="cell"><div class="hd"><b class="v" id="ct_n">—</b><span class="l">ترافیک سرور</span></div><div class="s" id="ct_ns">—</div></div>
</div>
<div class="card" style="margin-top:14px"><div id="ct_out"><div class="empty">برای شروع «اجرای تست» را بزن — حدود ۲۰ ثانیه طول می‌کشد: پینگ، نوسان، پکت‌خسری، سرعت دانلود، خروجی UDP و سلامت تانل‌ها</div></div></div>
<div class="card" style="margin-top:14px"><div class="bar" style="margin:0 0 10px"><h1 style="margin:0;font-size:16px">تست بین ایران و خارج <span class="hint" style="font-size:11px">(دوطرفه)</span></h1><button class="btn p" id="ct_open">ساخت لینک تست</button></div>
<div class="hint">یک لینک می‌سازد که روی <b>سرور خارج</b> اجرا می‌کنی (root) — پینگ ICMP، اکوی TCP و UDP واقعی بین دو سرور اندازه‌گیری می‌شود؛ جدول روی <b>هر دو سرور</b> نمایش داده می‌شود و پیشنهاد ترنسپورت می‌دهد.</div>
<div id="ct2_out" style="margin-top:10px"><div class="empty">هنوز لینکی ساخته نشده</div></div></div><div class="card" style="margin-top:16px"><h2 style="margin-top:0;font-size:16px">تست ترنسپورت (Link Test)</h2>
<div class="hint" style="margin:0 0 12px">مسیر مستقیم و تانل رمزنگاری‌شده را با هم مقایسه می‌کند؛ ۱۲ پروب TCP می‌زند، خروجی UDP را چک می‌کند (تانل WireGuard روی UDP سوار است) و بر اساس تأخیر، نوسان و پکت‌خسری، حالت کارایی پیشنهاد می‌دهد.</div>
<div class="row"><div><label>سرور خارج</label><select id="t_ti"></select></div><div><label>پورت سرویس روی سرور خارج (خالی = خودکار)</label><input id="t_tp" inputmode="numeric"></div><div style="flex:0 0 auto;align-self:end"><button class="btn p" id="t_run">اجرای تست</button> <button class="btn" id="t_bw">تست پهنای باند</button></div></div><div id="t_res" style="margin-top:12px"></div></div>
</section>
<section id="p_health" class="hide"><div class="bar"><h1 style="margin:0">بررسی سلامت</h1><button class="btn p" id="hrun">اجرای بررسی</button></div><div class="card" id="hl"><div class="empty">برای شروع «اجرای بررسی» را بزنید</div></div></section>
<section id="p_logs" class="hide"><div class="bar"><h1 style="margin:0">لاگ‌ها</h1><div class="acts" style="margin:0"><button class="btn on" id="lgs" type="button">سیستم</button><button class="btn" id="lga" type="button">حسابرسی</button></div></div><div class="card"><div class="lg" id="lg"></div></div></section>

<section id="p_set" class="hide"><h1>تنظیمات</h1>
<div class="card"><h2 style="margin-top:0;font-size:16px">پریست کارایی</h2>
<div class="hint" style="margin:0 0 10px">تنظیمات هسته (BBR، بافرها، conntrack) برای سناریوی شما. فعال: <b id="pf_c">—</b> · conntrack: <span id="pf_n">—</span></div>
<div class="acts" id="pf_b" style="margin:0"><button class="btn" data-pf="balanced" type="button">Balanced</button><button class="btn" data-pf="turbo" type="button">Turbo</button><button class="btn" data-pf="throughput" type="button">Throughput</button><button class="btn" data-pf="gaming" type="button">Gaming</button></div></div>
<div class="card"><h2 style="margin-top:0;font-size:16px">رنگ‌بندی و ظاهر</h2>
<div class="hint" style="margin:0">رنگ اصلی پنل را انتخاب کنید؛ روی دکمه‌ها، تب فعال، نوارها و نمودارها اعمال می‌شود.</div>
<div class="sws" id="sws"></div>
<label>زبان</label><div class="acts" style="margin-top:6px"><button class="btn" type="button" data-l="fa">فارسی</button><button class="btn" type="button" data-l="en">English</button></div></div>
<div class="card"><h2 style="margin-top:0;font-size:16px">تلگرام (اعلان قطع/وصل، ربات، گزارش و بکاپ)</h2>
<div class="row"><div><label>Bot Token</label><input id="g_t" placeholder="123456:ABC…" autocomplete="off"></div><div><label>Chat ID</label><input id="g_c"></div></div>
<label>آدرس API تلگرام (اختیاری — برای سرور ایران با پروکسی/ورکر)</label><input id="g_a" placeholder="https://api.telegram.org">
<div class="row" style="margin-top:8px"><div><label>ساعت گزارش روزانه (۰–۲۳)</label><input id="g_rh" type="number" min="0" max="23"></div><div><label>ساعت بکاپ شبانه (۰–۲۳)</label><input id="g_bh" type="number" min="0" max="23"></div></div>
<div class="acts" style="margin:4px 0 0;flex-wrap:wrap"><label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--mu);cursor:pointer;margin-inline-end:14px"><input type="checkbox" id="g_b"> ربات (/status /tunnels /traffic)</label><label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--mu);cursor:pointer;margin-inline-end:14px"><input type="checkbox" id="g_rep"> گزارش روزانه</label><label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--mu);cursor:pointer"><input type="checkbox" id="g_bk"> بکاپ شبانه در تلگرام</label></div>
<div class="hint" id="g_h"></div><div class="acts"><button class="btn p" id="g_s">ذخیره</button><button class="btn" id="g_x">ارسال پیام تست</button></div></div>
<div class="card"><h2 style="margin-top:0;font-size:16px">دامنه و HTTPS</h2>
<div class="hint" id="d_h" style="margin:0 0 8px"></div>
<div class="row"><div><label>دامنه (باید به IP همین سرور اشاره کند)</label><input id="d_d" placeholder="panel.example.com"></div><div><label>ایمیل (اختیاری)</label><input id="d_e" placeholder="you@example.com"></div></div>
<div class="hint">برای گرفتن گواهی Let's Encrypt پورت ۸۰ باید آزاد باشد. تمدید خودکار انجام می‌شود. لینک کاربران هم روی همین دامنه و HTTPS کار می‌کند.</div>
<div class="acts"><button class="btn p" id="d_s">دریافت گواهی و فعال‌سازی</button><button class="btn d" id="d_r">حذف دامنه</button></div>
<details><summary>یا گواهی خودم را وارد می‌کنم</summary><label>Certificate (PEM)</label><textarea id="c_c" rows="4"></textarea><label>Private key (PEM)</label><textarea id="c_k" rows="4"></textarea><div class="acts"><button class="btn" id="c_s">نصب گواهی</button></div></details></div>
<div class="card"><h2 style="margin-top:0;font-size:16px">تغییر رمز</h2>
<div class="row"><div><label>رمز فعلی</label><input id="w_o" type="password"></div><div><label>رمز جدید (حداقل ۸ کاراکتر)</label><input id="w_n" type="password"></div></div>
<div class="acts"><button class="btn p" id="w_s">تغییر رمز</button></div></div>
<div class="card"><h2 style="margin-top:0;font-size:16px">ورود دومرحله‌ای (TOTP)</h2>
<div class="hint" id="tf_h" style="margin:0 0 10px"></div>
<div id="tf_setup" style="display:none"><label>این راز را در Google Authenticator / Aegis ثبت کن (یا لینک otpauth):</label><textarea id="tf_s" rows="3" readonly></textarea><label>کد ۶ رقمی:</label><input id="tf_c" inputmode="numeric" maxlength="6"><div class="acts"><button class="btn p" id="tf_on">تأیید و فعال‌سازی</button></div></div>
<div class="acts" id="tf_acts" style="margin:0"></div><div id="tf_rc" class="hint" style="display:none;margin-top:10px"></div></div>
<div class="card"><h2 style="margin-top:0;font-size:16px">بکاپ و بازیابی</h2>
<div class="hint" style="margin:0 0 10px">بکاپ شامل تانل‌ها، تنظیمات پنل، رمز و گواهی است. بازیابی فقط لیست تانل‌ها را برمی‌گرداند. پکیج آفلاین برای سرورهایی است که به گیت‌هاب دسترسی ندارند و شامل checksum SHA256 است.</div>
<div class="acts" style="margin:0"><button class="btn p" id="k_d">دانلود بکاپ</button><button class="btn" id="k_r">بازیابی از فایل</button><button class="btn" id="k_p">پکیج آفلاین</button><input id="k_f" type="file" accept=".gz,.tgz" class="hide"></div></div></section>
</main>
<footer class="foot"><div class="fin">




<span class="fver" id="fver">v2.9.0</span>
</div></footer>
</div>

<div class="modal" id="m"><div class="box"><h3>افزودن تانل جدید</h3>
<div class="row"><div><label>پورت ورودی (این سرور)</label><input id="f_l" placeholder="8899,2044" dir="ltr" autocomplete="off"></div><div><label>پروتکل</label><select id="f_p"><option>tcp</option><option>udp</option><option>both</option></select></div></div>
<label>IP سرور خارج</label><input id="f_i" placeholder="1.2.3.4">
<div class="row"><div><label>پورت مقصد (خالی = برابر)</label><input id="f_d" inputmode="numeric"></div><div><label>نام (اختیاری)</label><input id="f_n"></div></div>
<div class="acts"><button class="btn p" id="f_ok">ذخیره</button><button class="btn" id="f_x">انصراف</button></div></div></div>
<div class="modal" id="qm"><div class="box"><h3 id="q_t">حجم تانل</h3><div id="q_b"></div>
<div class="acts"><button class="btn p" id="q_ok">ذخیره</button><button class="btn" id="q_x">بستن</button><button class="btn d" id="q_r">ریست مصرف</button></div></div></div>
<div class="modal" id="sm"><div class="box"><h3 id="s_t">لینک کاربر</h3><div class="hint" style="margin:0 0 10px">صفحه‌ای فقط‌خواندنی که کاربر بدون ورود به پنل، حجم مصرف‌شده و باقی‌مانده‌اش را می‌بیند. آدرس آن حدس‌زدنی نیست.</div><div id="s_b"></div>
<div class="acts"><button class="btn" id="s_x">بستن</button></div></div></div>
<div class="modal" id="cm"><div class="box"><h3 id="c_t">امنیت تانل</h3><div class="hint" style="margin:0 0 10px">این محدودیت‌ها فقط روی پورت همین تانل اعمال می‌شوند و ترافیک را دست‌نخورده عبور می‌دهند.</div>
<label>آی‌پی‌های مجاز (هر خط یا با کاما؛ خالی = همه)</label><textarea id="c_a" rows="3" class="ltr" placeholder="1.2.3.4 / 5.6.0.0/16"></textarea>
<div class="row" style="margin-top:10px"><div><label>حداکثر اتصال همزمان هر آی‌پی (۰ = خاموش)</label><input id="c_m" type="number" min="0"></div><div><label>اتصال جدید در دقیقه برای هر آی‌پی (۰ = خاموش)</label><input id="c_r" type="number" min="0"></div></div>
<div class="qs er" id="c_w" style="display:none;margin-top:10px">فقط آی‌پی‌های داخل لیست به این پورت می‌رسند. مطمئن شو آی‌پی مشتری‌ها داخل لیست است.</div>
<div class="acts"><button class="btn p" id="c_ok">ذخیره</button><button class="btn" id="c_x">بستن</button></div></div></div>
<div class="modal" id="wm"><div class="box"><h3 id="w_t">ساخت تانل جدید</h3>
<div class="wsteps" id="w_st"></div><div id="w_b"></div>
<div class="acts" style="margin-top:14px"><button class="btn" id="w_back">بازگشت</button><button class="btn p" id="w_next">ادامه</button></div></div></div>
<div id="toast"></div>
<script>
const $=id=>document.getElementById(id);let prev=null,timer=null,page="dash",SP={};
let LANG="fa";try{LANG=localStorage.getItem("drl")==="en"?"en":"fa"}catch(e){}
const EN={"ورود به پنل مدیریت تانل": "Sign in to the tunnel manager", "رمز عبور": "Password", "نمایش رمز": "Show password", "ورود": "Sign in", "تم": "Theme", "ظاهر": "Appearance", "خروج": "Sign out", "داشبورد": "Dashboard", "تانل‌ها": "Tunnels", "بررسی سلامت": "Health check", "لاگ‌ها": "Logs", "تنظیمات": "Settings", "سرور": "Server", "دیسک": "Disk", "تانل": "Tunnels", "ترافیک کل": "Total traffic", "سرعت لحظه‌ای": "Live speed", "وضعیت تانل‌ها": "Tunnel status", "نام": "Name", "مسیر": "Route", "وضعیت": "Status", "پینگ": "Ping", "نمودار": "Chart", "سرعت": "Speed", "+ افزودن تانل": "+ Add tunnel", "پروتکل": "Protocol", "پورت ورودی": "Listen port", "مقصد": "Destination", "حجم (مصرف / سقف)": "Quota (used / limit)", "اجرای بررسی": "Run check", "برای شروع «اجرای بررسی» را بزنید": "Press “Run check” to start", "تلگرام (اعلان قطع/وصل و منابع)": "Telegram (up/down and resource alerts)", "آدرس API تلگرام (اختیاری — برای سرور ایران با پروکسی/ورکر)": "Telegram API address (optional — for Iran servers via proxy/worker)", "ذخیره": "Save", "ارسال پیام تست": "Send test message", "دامنه و HTTPS": "Domain & HTTPS", "دامنه (باید به IP همین سرور اشاره کند)": "Domain (must point to this server's IP)", "ایمیل (اختیاری)": "Email (optional)", "برای گرفتن گواهی Let's Encrypt پورت ۸۰ باید آزاد باشد. تمدید خودکار انجام می‌شود. لینک کاربران هم روی همین دامنه و HTTPS کار می‌کند.": "To get a Let's Encrypt certificate, port 80 must be free. Renewal is automatic. User links also work on this domain over HTTPS.", "دریافت گواهی و فعال‌سازی": "Get certificate & enable", "حذف دامنه": "Remove domain", "یا گواهی خودم را وارد می‌کنم": "Or I'll enter my own certificate", "نصب گواهی": "Install certificate", "تغییر رمز": "Change password", "رمز فعلی": "Current password", "رمز جدید (حداقل ۸ کاراکتر)": "New password (min. 8 characters)", "بکاپ و بازیابی": "Backup & restore", "بکاپ شامل تانل‌ها، تنظیمات پنل، رمز و گواهی است. بازیابی فقط لیست تانل‌ها را برمی‌گرداند.": "The backup includes tunnels, panel settings, password and certificate. Restore only brings back the tunnel list.", "دانلود بکاپ": "Download backup", "بازیابی از فایل": "Restore from file", "افزودن تانل جدید": "Add new tunnel", "پورت ورودی (این سرور)": "Listen port (this server)", "IP سرور خارج": "Foreign server IP", "پورت مقصد (خالی = برابر)": "Destination port (empty = same)", "نام (اختیاری)": "Name (optional)", "انصراف": "Cancel", "حجم تانل": "Tunnel quota", "حجم تانل —": "Tunnel quota —", "بستن": "Close", "ریست مصرف": "Reset usage", "لینک کاربر": "User link", "صفحه‌ای فقط‌خواندنی که کاربر بدون ورود به پنل، حجم مصرف‌شده و باقی‌مانده‌اش را می‌بیند. آدرس آن حدس‌زدنی نیست.": "A read-only page where the user can see used and remaining data without signing in to the panel. Its address is not guessable.", "خطا": "Error", "آنلاین": "online", "قطع": "offline", "نامشخص": "unknown", "آنلاین ·": "online ·", "هنوز تانلی نساخته‌اید": "No tunnels yet", "حجم تمام": "Quota reached", "تست": "Test", "حجم": "Quota", "لینک": "Link", "حذف": "Delete", "UDP قابل تست نیست": "UDP can't be tested", "مقصد پاسخ نمی‌دهد": "Destination is not responding", "اتصال موفق ·": "Connected ·", "این تانل حذف شود؟": "Delete this tunnel?", "حذف شد": "Deleted", "تانل اضافه شد": "Tunnel added", "در حال بررسی…": "Checking…", "لاگی ثبت نشده": "No logs yet", "•••••• (ذخیره شده — برای تغییر وارد کنید)": "•••••• (saved — enter a new one to change)", "فعال: https://": "Active: https://", "بدون دامنه: گواهی self-signed (مرورگر هشدار می‌دهد)": "No domain: self-signed certificate (the browser will warn)", "HTTPS خاموش است": "HTTPS is off", "اگر سرور ایران به تلگرام دسترسی ندارد، آدرس یک پروکسی/ورکر سازگار با Bot API را در فیلد API بگذارید.": "If the Iran server can't reach Telegram, put the address of a Bot API–compatible proxy/worker in the API field.", "ذخیره شد": "Saved", "پیام تست ارسال شد": "Test message sent", "ارسال ناموفق:": "Send failed:", "رمز تغییر کرد": "Password changed", "لیست تانل‌ها با محتوای این بکاپ جایگزین شود؟": "Replace the tunnel list with this backup's contents?", "بازیابی شد": "Restored", "رمز را وارد کنید": "Enter the password", "مصرف": "Used", "سقف": "Limit", "نامحدود": "Unlimited", "باقی‌مانده": "Remaining", "حجم تمام شده و تانل قطع است. با بالا بردن سقف یا ریست مصرف، خودکار وصل می‌شود.": "The quota is used up and the tunnel is cut off. Raising the limit or resetting usage reconnects it automatically.", "مقدار دلخواه": "Custom amount", "افزودن به سقف:": "Add to limit:", "سقف حجم ذخیره شد": "Quota limit saved", "سقف حجم برداشته شد": "Quota limit removed", "مصرف این تانل صفر شود؟": "Reset this tunnel's usage to zero?", "مصرف صفر شد": "Usage reset", "لینک کاربر —": "User link —", "کپی لینک": "Copy link", "لینک جدید": "New link", "حذف لینک": "Delete link", "ساخت لینک": "Create link", "کپی شد": "Copied", "لینک قبلی از کار می‌افتد. ادامه؟": "The old link will stop working. Continue?", "لینک حذف شود؟": "Delete the link?", "دامنه را وارد کنید": "Enter a domain", "گواهی گرفته می‌شود و پنل ری‌استارت می‌شود. ادامه؟": "A certificate will be issued and the panel will restart. Continue?", "در حال دریافت گواهی؛ تا دو دقیقه صبر کنید…": "Getting the certificate; wait up to two minutes…", "فعال شد؛ در حال انتقال به دامنه…": "Enabled; redirecting to the domain…", "دامنه حذف شود و گواهی self-signed برگردد؟": "Remove the domain and go back to the self-signed certificate?", "انجام شد؛ پنل ری‌استارت می‌شود": "Done; the panel is restarting", "گواهی نصب شد؛ پنل ری‌استارت می‌شود": "Certificate installed; the panel is restarting", "رنگ‌بندی و ظاهر": "Colors & appearance", "رنگ اصلی پنل را انتخاب کنید؛ روی دکمه‌ها، تب فعال، نوارها و نمودارها اعمال می‌شود.": "Pick the panel's main color. It applies to buttons, the active tab, meters and charts.", "زبان": "Language", "حالت کارایی این تانل": "Performance preset for this tunnel", "کارایی": "Preset", "سیستم": "System", "ریورس — پورت سرور خارج → سرویس همین سرور ایران": "Reverse — a port on the foreign server → a service on this Iran server", "برعکس فوروارد: پورت روی <b>سرور خارج</b> باز می‌شود و هرکس به آن وصل شود، به سرویسی که روی همین سرور ایران اجرا شده می‌رسد (از داخل تانل رمزنگاری‌شده). مثلاً پنل یا VPN روی ایران داری و می‌خواهی با IP تمیز خارج دیده شود. بعد از هر تغییر، دکمه «دستور سرور خارج» را بزن و اسکریپت را دوباره روی سرور خارج اجرا کن.": "The opposite of a forward: the port opens on the <b>foreign server</b> and whoever connects to it lands on a service running on this Iran server, through the encrypted tunnel. For example your panel or VPN lives in Iran and you want it reachable on the foreign server clean IP. After every change press the foreign-script button and run the script on the foreign server again.", "پورت (سرور خارج)": "Port (foreign)", "پورت سرویس (ایران)": "Service port (Iran)", "+ افزودن ریورس": "+ Add reverse", "پورت روی سرور خارج": "Port on the foreign server", "پورت سرویس روی ایران": "Service port in Iran", "هنوز ریورسی ساخته نشده": "No reverse forwards yet", "اول یک تانل بساز": "Create a tunnel first", "پورت‌ها را وارد کنید": "Enter the ports", "ذخیره شد — اسکریپت سرور خارج را دوباره اجرا کن": "Saved — run the foreign-server script again", "این ریورس حذف شود؟ بعدش اسکریپت سرور خارج را دوباره اجرا کن.": "Delete this reverse forward? Run the foreign-server script again afterwards.", "حذف شد — اسکریپت سرور خارج را دوباره اجرا کن": "Deleted — run the foreign-server script again", "بی‌پاسخ": "no answer", "✘ خطا": "✘ error", "تست ترنسپورت (Link Test)": "Transport test (Link Test)", "مسیر مستقیم و تانل رمزنگاری‌شده را با هم مقایسه می‌کند؛ ۱۲ پروب TCP می‌زند، خروجی UDP را چک می‌کند (تانل WireGuard روی UDP سوار است) و بر اساس تأخیر، نوسان و پکت‌خسری، حالت کارایی پیشنهاد می‌دهد.": "Compares the direct path with the encrypted tunnel: fires 12 TCP probes, checks UDP egress (the WireGuard tunnel rides on UDP) and recommends a performance preset based on latency, jitter and packet loss.", "خروجی UDP از این سرور بسته است — تونل WireGuard روی UDP سوار است و بالا نمی‌آید. اول UDP را روی فایروال/اپراتور باز کن.": "UDP egress is blocked on this server — the WireGuard tunnel rides on UDP and will not come up. Open UDP on the firewall/operator first.", "اعمال ": "Apply ", "پیش‌فرض سیستم": "System default", "در حال تست… (حدود ۲۰ ثانیه)": "Testing… (about 20 seconds)", "در حال ساخت (نصب WireGuard ممکن است کمی طول بکشد)…": "Creating (installing WireGuard can take a moment)…", "در حال بارگذاری…": "Loading…", "احراز هویت": "Authentication", "داده‌های سرور": "Server metrics", "رابط کاربری": "Interface"};
const FA={"Wrong password": "رمز اشتباه است", "Too many attempts, try later": "تلاش‌های زیاد؛ بعداً امتحان کنید", "Too many requests": "درخواست‌های زیاد؛ کمی صبر کنید", "Current password is wrong": "رمز فعلی اشتباه است", "New password must be at least 8 characters": "رمز جدید باید حداقل ۸ کاراکتر باشد", "A forward on this port already exists": "برای این پورت قبلاً تانل ساخته شده", "Invalid IP": "آی‌پی نامعتبر است", "Invalid port": "پورت نامعتبر است", "Port out of range": "پورت خارج از محدوده است", "Invalid protocol": "پروتکل نامعتبر است", "Invalid domain": "دامنه نامعتبر است", "Invalid email": "ایمیل نامعتبر است", "This port is used by the web panel": "این پورت توسط خود پنل استفاده می‌شود", "No such rule": "چنین تانلی وجود ندارد", "Server error": "خطای سرور", "Bad request": "درخواست نامعتبر", "Too large": "حجم داده زیاد است", "Bad action": "عملیات نامعتبر", "Port 80 is busy: Let's Encrypt needs it for a moment": "پورت ۸۰ اشغال است؛ Let's Encrypt لحظه‌ای به آن نیاز دارد", "API address must start with https://": "آدرس API باید با https:// شروع شود", "No forwards found in this file": "در این فایل تانلی پیدا نشد", "Certificate and key are invalid or do not match": "گواهی و کلید نامعتبر یا ناهمخوان‌اند", "Certificate and key must be PEM text": "گواهی و کلید باید متن PEM باشند"};
Object.assign(EN,{"ترنسپورت":"Transport","تانل رمزنگاری‌شده (WireGuard)":"Encrypted tunnel (WireGuard)","سرور خارج":"Foreign server","پورت UDP":"UDP port","وضعیت لینک":"Link status","ترافیک":"Traffic","مسیر فورواردها":"Forwards via","متصل":"Linked","بدون handshake":"No handshake","مستقیم":"Direct","ساخت تانل":"Create tunnel","دستور سرور خارج":"Foreign setup script","برگشت به مستقیم":"Back to direct","فعال‌سازی":"Activate","کپی":"Copy","کپی شد":"Copied","انجام شد":"Done","هنوز تانلی ساخته نشده":"No tunnels yet","تست ترنسپورت":"Transport test","اجرای تست":"Run test","پاسخ می‌دهد":"Responds","بی‌پاسخ":"No answer","میانگین":"Average","کمترین / بیشترین":"Min / Max","نوسان":"Jitter","ازدست‌رفتن":"Loss","حذف همه":"Delete all","این تانل حذف شود؟ فورواردها به حالت مستقیم برمی‌گردند.":"Remove this tunnel? Its forwards go back to direct.","همه پورت‌های این سرور حذف شوند؟":"Delete every port of this server?","در حال تست… (حدود ۲۰ ثانیه)":"Testing… (about 20 s)","در حال ساخت (نصب WireGuard ممکن است کمی طول بکشد)…":"Creating (installing WireGuard can take a moment)…","این دستور را روی سرور خارج (root) اجرا کن":"Run this on the foreign server (root)","IP سرور خارج":"Foreign server IP","حذف شد":"Deleted","امنیت تانل ذخیره شد":"Tunnel security saved","امنیت تانل":"Tunnel security","امنیت":"Security","این محدودیت‌ها فقط روی پورت همین تانل اعمال می‌شوند و ترافیک را دست‌نخورده عبور می‌دهند.":"These limits apply only to this tunnel's port and pass traffic through untouched.","آی‌پی‌های مجاز (هر خط یا با کاما؛ خالی = همه)":"Allowed IPs (one per line or comma-separated; empty = anyone)","حداکثر اتصال همزمان هر آی‌پی (۰ = خاموش)":"Max simultaneous connections per IP (0 = off)","اتصال جدید در دقیقه برای هر آی‌پی (۰ = خاموش)":"New connections per minute per IP (0 = off)","فقط آی‌پی‌های داخل لیست به این پورت می‌رسند. مطمئن شو آی‌پی مشتری‌ها داخل لیست است.":"Only the listed IPs can reach this port. Make sure your clients' IPs are in the list.","پورت":"port","جستجو (نام، پورت، آی‌پی)…":"Search name, port, IP…","موردی پیدا نشد":"No matches found","پاک کردن":"Clear","نشست منقضی شد":"Session expired — sign in again"});
Object.assign(FA,{"Invalid IP or network":"آی‌پی یا شبکه نامعتبر است","Too many IPs":"تعداد آی‌پی‌ها زیاد است","Numbers out of range":"عدد خارج از محدوده است","Session expired — sign in again":"نشست منقضی شد — دوباره وارد شوید","Wrong code":"کد اشتباه است","Setup first":"اول «فعال‌سازی» را بزنید","no_tunnel":"تانل رمزنگاری‌شده‌ای برای این سرور ساخته نشده","no_iperf":"iperf3 نصب نشد (دسترسی مخازن؟)","bw_nosvc":"سرور خارج آماده تست نیست — اسکریپت سمت خارج را دوباره اجرا کن","bw_fail":"تست پهنای باند ناموفق بود","Bad preset":"پریست نامعتبر","Preset failed":"اعمال پریست ناموفق بود"});
Object.assign(EN,{"کانکشن تست":"Connection test","تست بین ایران و خارج":"Iran ⇄ abroad test","دوطرفه — مثل Connection Test بک‌پک":"two-sided","ساخت لینک تست":"Create test link","یک لینک می‌سازد که روی سرور خارج اجرا می‌کنی (root) — پینگ ICMP، اکوی TCP و UDP واقعی بین دو سرور اندازه‌گیری می‌شود؛ جدول روی هر دو سرور نمایش داده می‌شود و پیشنهاد ترنسپورت می‌دهد.":"Builds a link to run on the foreign server (root) — it measures real ICMP, TCP-echo and UDP-echo probes between the two servers, prints the table on both sides and recommends a transport.","هنوز لینکی ساخته نشده":"No test link yet","این یک خط را روی سرور خارج اجرا کن (root):":"Run this one line on the foreign server (root):","لینک تا ۱۵ دقیقه اعتبار دارد.":"The link is valid for 15 minutes.","بستن تست":"Close test","آخرین نتیجه از سرور خارج (":"Latest result from the foreign server (","مسیر":"Path","میانگین ms":"avg ms","نوسان ms":"jitter ms","پینگ (ICMP)":"Ping (ICMP)","اکوی TCP":"TCP echo","اکوی UDP":"UDP echo","ترنسپورت (مسیر تانل — برای هر تانل جدا)":"Transport (how the tunnel crosses — BackPack-style, per tunnel)","پورت ترنسپورت (روی سرور شنونده)":"Carrier port (on the listening server)","خالی = خودکار":"empty = automatic","ترافیک سرور":"Server traffic","برای شروع «اجرای تست» را بزن — حدود ۲۰ ثانیه طول می‌کشد: پینگ، نوسان، پکت‌خسری، سرعت دانلود، خروجی UDP و سلامت تانل‌ها":"Press “Run test” to start — takes about 20 s: ping, jitter, loss, download speed, UDP egress and tunnel health","هنوز تستی اجرا نشده":"No test has run yet","آخرین تست:":"Last run:","دانلود مستقیم (Cloudflare)":"Direct download (Cloudflare)","UDP خروجی":"UDP egress","باز":"open","بسته":"blocked","پکت‌خسری":"Loss","تانل ":"Tunnel ","+ ساخت تانل جدید":"+ New tunnel","ویزارد مثل بک‌پک: نوع (ریورس / دایرکت / فوروارد) ← مشخصات ← کارایی ← اتصال. «لینک اتصال» هر تانل همیشه از ستون آخر قابل کپی است.":"BackPack-style wizard: type (reverse / direct / forward) → details → performance → connect. Each tunnel's join link stays copyable from the last column.","ساخت تانل جدید":"New tunnel","نوع":"Type","اختیاری":"Optional","اتصال":"Connect","بازگشت":"Back","ادامه":"Continue","ساخت تانل و نمایش لینک":"Create tunnel & show the link","ریورس":"Reverse","دایرکت":"Direct","پورت فوروارد":"Port forward","پیشنهادی":"Recommended","ایران — همین سرور.":"Iran — this server.","دو سرور چطور به هم وصل شوند؟":"How should the two servers connect?","سرور خارج به ایران dial می‌زند. فقط یک دستور روی سرور خارج اجرا می‌کنی؛ حتی لازم نیست IP خارج را بدانی — مناسب وقتی خارج پشت NAT است یا ایران خروجی آزاد ندارد.":"The foreign server dials in to Iran (like BackPack). You run one command on the foreign server; you don't even need to know its IP — ideal when the foreign side is behind NAT or the Iran side has no free egress.","ایران به سرور خارج وصل می‌شود (حالت کلاسیک). IP سرور خارج و پورت UDP آن را داری.":"Iran dials out to the foreign server (the classic way). You have the foreign server's IP and its UDP port.","همان حالت همیشگی: فورواردهای این سرور از داخل تانل رمزنگاری‌شده رد می‌شوند. IP سرور خارج لازم است.":"The usual mode: this server's forwards ride the encrypted tunnel. Needs the foreign server's IP.","نام تانل (اختیاری)":"Tunnel name (optional)","پورت UDP تانل":"Tunnel UDP port","تصادفی":"Random","ریورس — سرور خارج به ایران وصل می‌شود؛ IP خارج لازم نیست.":"Reverse — the foreign server connects to Iran; no foreign IP needed.","ایران به سرور خارج وصل می‌شود؛ آدرس خارج را بده.":"Iran connects to the foreign server; enter its address.","حالت کارایی ":"Performance of ","— برای هر تانل جدا ذخیره می‌شود و موقع «فعال‌سازی» خودکار اعمال می‌شود.":"— stored per tunnel and applied automatically when you activate it.","اختیاری — اولین فوروارد را همین‌جا بساز یا خالی بگذار و بعداً از تب «تانل‌ها» اضافه کن.":"Optional — create the first forward here, or leave it empty and add it later from the Tunnels tab.","پورت ورودی (این سرور)":"Listen port (this server)","پورت مقصد (خالی = برابر)":"Destination port (empty = same)","مقصد این فوروارد خودکار آدرس داخلی تانل می‌شود.":"This forward's destination is the tunnel's internal address automatically.","مقصد:":"Destination:","این یک خط را روی ":"Run this one line on the ","سرور خارج":"foreign server"," اجرا کن (root) — WireGuard را نصب می‌کند، تانل را برپا می‌کند و به ایران dial می‌زند. چند ثانیه بعد وضعیت لینک در جدول «متصل» می‌شود:":" (root) — it installs WireGuard, brings the tunnel up and dials back to Iran. The link status turns “Linked” within seconds:","کپی دستور":"Copy command","اسکریپت کامل (جایگزین)":"Full script (alternative)","این لینک محرمانه است — کلید خصوصی سمت خارج داخلش است؛ جایی منتشرش نکن. دکمه «لینک اتصال» در جدول همیشه دوباره همین دستور را می‌دهد.":"This link is secret — it contains the foreign side's private key; do not publish it. The “Join link” button in the table always serves the same command again.","لینک اتصال تانل":"Tunnel join link","لینک اتصال":"Join link","منتظر اتصال":"Waiting to join","در انتظار اتصال سرور خارج…":"Waiting for the foreign server…","در حال تست… (حدود ۲۰ ثانیه)":"Testing… (about 20 s)","ثانیه) — پینگ، دانلود و تانل‌ها":"s) — ping, download and tunnels"});
const RE=new RegExp(Object.keys(EN).sort((a,b)=>b.length-a.length).map(k=>k.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")).join("|"),"g");
const TX=s=>{s=String(s);return LANG==="en"?s.replace(RE,m=>EN[m]):(FA[s]||s)};
const cf=s=>confirm(TX(s));
const ORIG=new WeakMap(),AR=/[\u0600-\u06FF]/;
function walk(root,fn){const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT,{acceptNode:n=>/^(SCRIPT|STYLE)$/.test(n.parentNode.nodeName)?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT});let n;while(n=w.nextNode())fn(n)}
function tNode(n){const has=ORIG.has(n),o=has?ORIG.get(n):n.nodeValue;if(!has&&!AR.test(o))return;ORIG.set(n,o);const v=LANG==="en"?o.replace(RE,m=>EN[m]):o;if(n.nodeValue!==v)n.nodeValue=v}
function tAttr(el){for(const a of["placeholder","title"]){if(!el.hasAttribute(a))continue;const k="fa"+a[0].toUpperCase()+a.slice(1),cur=el.getAttribute(a);if(AR.test(cur))el.dataset[k]=cur;const o=el.dataset[k];if(o===undefined)continue;const v=LANG==="en"?o.replace(RE,m=>EN[m]):o;if(cur!==v)el.setAttribute(a,v)}}
function tAll(r){if(r.nodeType===1)tAttr(r);walk(r,tNode);r.querySelectorAll&&r.querySelectorAll("[placeholder],[title]").forEach(tAttr)}
new MutationObserver(ms=>{if(LANG!=="en")return;for(const m of ms){if(m.type==="characterData")tNode(m.target);else if(m.type==="attributes")tAttr(m.target);else m.addedNodes.forEach(n=>{if(n.nodeType===3)tNode(n);else if(n.nodeType===1)tAll(n)})}}).observe(document.body,{childList:true,subtree:true,characterData:true,attributes:true,attributeFilter:["placeholder","title"]});
function setLang(l){LANG=l==="en"?"en":"fa";try{localStorage.setItem("drl",LANG)}catch(e){}const d=document.documentElement;d.lang=LANG;d.dir=LANG==="en"?"ltr":"rtl";tAll(document.body);
 document.querySelectorAll(".lng .lc").forEach(e=>e.textContent=LANG==="en"?"FA":"EN");document.querySelectorAll("[data-l]").forEach(b=>b.classList.toggle("on",b.dataset.l===LANG));buildSw();bootDraw();requestAnimationFrame(moveInd)}
let ACC="#8b5cf6";try{ACC=localStorage.getItem("drc")||"#8b5cf6"}catch(e){}
const ACS=[["mono","سفید","Mono"],["#8b5cf6","بنفش","Violet"],["#6366f1","ایندیگو","Indigo"],["#3b82f6","آبی","Blue"],["#06b6d4","فیروزه‌ای","Cyan"],["#22c55e","سبز","Green"],["#f59e0b","زرد","Amber"],["#ef4444","قرمز","Red"],["#ec4899","صورتی","Pink"]];
const fgc=h=>{const n=parseInt(h.slice(1),16),r=n>>16,g=n>>8&255,b=n&255;return(r*299+g*587+b*114)/1000>155?"#0a0a0a":"#fff"};
const mix=(a,b,t)=>{const A=parseInt(a.slice(1),16),B=parseInt(b.slice(1),16),c=i=>Math.round(((A>>i&255)*(1-t)+(B>>i&255)*t));return"#"+[16,8,0].map(i=>c(i).toString(16).padStart(2,"0")).join("")};
const ACG={"mono":"#c8c8ce","#8b5cf6":"#6366f1","#6366f1":"#3b82f6","#3b82f6":"#06b6d4","#06b6d4":"#3b82f6","#22c55e":"#06b6d4","#f59e0b":"#ef4444","#ef4444":"#f97316","#ec4899":"#8b5cf6"};
function markSw(){document.querySelectorAll("#sws .sw").forEach(e=>{if(e.classList.contains("cu")){const cu=!ACS.some(a=>a[0]===ACC);e.classList.toggle("on",cu);e.style.setProperty("--c",cu?ACC:"var(--tx)")}else e.classList.toggle("on",e.dataset.c===ACC)})}
function setAc(c){ACC=/^#[0-9a-f]{6}$/i.test(c)?c:"mono";try{localStorage.setItem("drc",ACC)}catch(e){}const st=document.body.style;
 if(ACC==="mono"){["--ac","--acf","--pr","--acr"].forEach(k=>st.removeProperty(k));st.setProperty("--acg",ACG.mono);st.setProperty("--acp","#8b5cf6")}
 else{const g=ACG[ACC]||mix(ACC,"#6366f1",.4);st.setProperty("--ac",ACC);st.setProperty("--acf",fgc(ACC));st.setProperty("--pr",ACC);st.setProperty("--acg",g);st.setProperty("--acp",mix(ACC,"#ec4899",.45));
  const n=parseInt(ACC.slice(1),16);st.setProperty("--acr",(n>>16&255)+","+(n>>8&255)+","+(n&255))}
 markSw()}
function buildSw(){const en=LANG==="en";$("sws").innerHTML=ACS.map(([v,f,e])=>`<button class="sw" type="button" data-c="${v}" style="--c:${v==="mono"?"var(--tx)":v}" title="${en?e:f}"></button>`).join("")+`<label class="sw cu" title="${en?"Custom":"دلخواه"}"><input type="color" id="ac_c" value="${/^#/.test(ACC)?ACC:"#8b5cf6"}"></label>`;markSw()}
const B={el:$("boot"),shown:0,target:0,t:0,min:1200,iv:0},PCT=[12,46,78,100];
function bootDraw(){const n=B.shown;B.el.querySelectorAll(".bst").forEach((e,i)=>{e.className="bst"+(i<n?" ok":i===n?" run":"")});$("b_r").style.strokeDashoffset=289*(1-PCT[n]/100);$("b_s").textContent=TX("در حال بارگذاری…");$("b_p").textContent=PCT[n]+"%";B.el.classList.toggle("done",n>=3)}
function bootOut(){clearInterval(B.iv);B.el.classList.add("out");setTimeout(()=>B.el.classList.add("hide"),650)}
function bootStart(n,min){B.shown=B.target=n;B.t=Date.now();B.min=min;B.el.classList.remove("hide","out");bootDraw();clearInterval(B.iv);B.iv=setInterval(()=>{if(B.shown<B.target){B.shown++;bootDraw()}else if(B.shown>=3&&Date.now()-B.t>=B.min)bootOut()},380)}
function bootGo(n){if(n>B.target)B.target=n}
function bootFast(){if(B.el.classList.contains("hide")||B.el.classList.contains("out"))return;clearInterval(B.iv);B.shown=B.target=3;bootDraw();setTimeout(bootOut,220)}

/* ---------------- sliding tab indicator ---------------- */
function moveInd(){const s=document.querySelector(".seg"),a=s&&s.querySelector(".nav.on"),i=$("ind");if(!a||!i)return;i.style.width=a.offsetWidth+"px";i.style.transform="translateX("+a.offsetLeft+"px)"}
window.addEventListener("resize",moveInd);

/* ---------------- helpers ---------------- */
const nv=t=>{const i=t.indexOf(" ");return t.slice(0,i)+"<small>"+t.slice(i+1)+"</small>"};
const HD=Array(22).fill(0),HU=Array(22).fill(0);function hist(id,a,v){a.push(v);if(a.length>22)a.shift();const m=Math.max(...a,1);$(id).innerHTML=a.map(x=>`<i style="height:${Math.max(8,x/m*100)}%"></i>`).join("")}
const hb=b=>{const u=["B","KB","MB","GB","TB"];let i=0;b=b||0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(i?1:0)+" "+u[i]};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function animNum(el,to,fmt){const A=el._an||(el._an={v:0});if(A.raf)cancelAnimationFrame(A.raf);const from=A.v,t0=performance.now(),D=520;
 const step=t=>{const p=Math.min(1,(t-t0)/D),e=1-Math.pow(1-p,3);A.v=from+(to-from)*e;el.innerHTML=fmt(A.v);if(p<1)A.raf=requestAnimationFrame(step)};A.raf=requestAnimationFrame(step)}
const toast=(t,k)=>{const e=document.createElement("div");e.className="t "+(k||"");e.textContent=TX(t);e.onclick=()=>e.remove();$("toast").appendChild(e);setTimeout(()=>e.remove(),3500)};
async function api(p,m,b){const r=await fetch("/api/"+p,{method:m||"GET",headers:{"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined});
 let j={};try{j=await r.json()}catch(e){}if(r.status===401&&p!=='login'){show(false);throw new Error("نشست منقضی شد")}if(!r.ok)throw new Error(j.error||"خطا");return j}
function show(on){if(!on&&!$("login").classList.contains("hide")){clearInterval(timer);return}
 $("app").classList.toggle("hide",!on);$("login").classList.toggle("hide",on);clearInterval(timer);
 if(on){bootGo(1);load().then(()=>bootGo(3));timer=setInterval(tick,3000);requestAnimationFrame(moveInd)}else{bootFast();$("pw").focus()}}
function tick(){load();if(page==="logs")logs()}
async function load(){try{render(await api("state"))}catch(e){}}
function nav(p){page=p;document.querySelectorAll(".nav[data-p]").forEach(b=>b.classList.toggle("on",b.dataset.p===p));moveInd();
 ["dash","tun","test","health","logs","set"].forEach(x=>{const el=$("p_"+x);el.classList.toggle("hide",x!==p);if(x===p){el.style.animation="none";void el.offsetWidth;el.style.animation=""}});
 if(p==="tun"){trLoad();rvLoad()}if(p==="test"){ctLoad();ct2Load();trLoad();load()}if(p==="logs")logs();if(p==="set")settings()}
document.querySelectorAll(".nav[data-p]").forEach(b=>b.onclick=()=>nav(b.dataset.p));
function spark(h){const v=(h||[]).map(x=>x==null?-1:x);if(v.length<2)return"";const m=Math.max(...v,1),w=84,H=22,st=w/(v.length-1);
 return `<svg width="${w}" height="${H}">`+v.map((x,i)=>x<0?`<line x1="${i*st}" x2="${i*st}" y1="3" y2="${H}" style="stroke:var(--er)" stroke-width="2"/>`:"").join("")+
 `<polyline fill="none" style="stroke:var(--ac)" stroke-width="1.6" points="${v.map((x,i)=>x<0?"":(i*st).toFixed(1)+","+(H-2-(x/m)*(H-4)).toFixed(1)).filter(Boolean).join(" ")}"/></svg>`}
const pill=s=>`<span class="pill ${s}">${{up:"آنلاین",down:"قطع",unknown:"نامشخص"}[s]}</span>`;
function bar(id,p){$("b_"+id).style.width=Math.min(100,p)+"%"}

/* ---------------- tunnel search + click-to-copy ---------------- */
const FLT={d:"",m:""};
const fmatch=(r,q)=>!q||(r.name+" "+r.ip+" "+r.lport+" "+r.dport+" "+r.proto).toLowerCase().includes(q);
function wireSearch(inp,btn,key,redraw){if(!inp)return;
 inp.addEventListener("input",()=>{FLT[key]=inp.value.trim().toLowerCase();btn.classList.toggle("hide",!FLT[key]);redraw()});
 btn.onclick=()=>{inp.value="";FLT[key]="";btn.classList.add("hide");redraw();inp.focus()};
 inp.addEventListener("keydown",e=>{if(e.key==="Escape"){inp.value="";FLT[key]="";btn.classList.add("hide");redraw()}})}
wireSearch($("q_d"),$("q_dx"),"d",()=>drawDash());
wireSearch($("q_s"),$("q_sx"),"m",()=>drawTunAll(true));
document.addEventListener("click",async e=>{const c=e.target.closest("[data-cp]");if(!c)return;
 const v=c.dataset.cp;try{await navigator.clipboard.writeText(v)}catch(x){const t=document.createElement("textarea");t.value=v;document.body.appendChild(t);t.select();try{document.execCommand("copy")}catch(y){}t.remove()}
 toast("کپی شد","s")});

/* ---------------- render ---------------- */
const ms=r=>r.ms==null?"—":r.ms+" ms";
function drawDash(){const s=window.LAST;if(!s)return;const rs=s.rules.filter(r=>fmatch(r,FLT.d));
 $("tb_d").innerHTML=rs.length?rs.map(r=>`<tr><td>${esc(r.name)}</td><td class="ltr cp" data-cp="${r.ip}:${r.dport}" title="کپی">${r.lport} → ${r.ip}:${r.dport}</td><td>${pill(r.status)}</td><td class="ltr">${ms(r)}</td><td>${spark(r.hist)}</td><td class="ltr">${hb(SP[r.lport+r.proto]||0)}/s</td></tr>`).join(""):`<tr><td colspan="6" class="empty">${s.rules.length?"موردی پیدا نشد":"هنوز تانلی نساخته‌اید"}</td></tr>`}
const qcr=r=>{const p=r.limit?Math.min(100,100*r.bytes/r.limit):0,c=r.blocked||p>=90?"var(--er)":p>=70?"var(--wa)":"var(--ok)";return `<div class="ltr">${hb(r.bytes)} / ${r.limit?hb(r.limit):"∞"}</div>${r.limit?`<div class="mb"><i style="width:${p}%;background:${c}"></i></div>`:""}`};
const ruleSig=r=>[r.name,r.proto,r.lport,r.ip,r.dport,r.status,r.blocked?1:0,r.expired?1:0,r.period||"",r.expires||"",r.sub?1:0,r.sec&&(r.sec.allow||r.sec.maxc||r.sec.rate)?1:0,r.enc?1:0].join("|");
let TSIG="";
function rowH(r,i,sub){return `<tr${sub?' class="sub"':''}><td>${sub?"":i+1}</td><td>${esc(r.name)}</td><td><span class="tag">${r.proto}</span></td><td class="ltr">${r.lport}</td><td class="ltr cp" data-cp="${r.ip}:${r.dport}" title="کپی">${r.ip}:${r.dport}</td><td>${r.expired?'<span class="pill down">منقضی</span>':r.blocked?'<span class="pill down">حجم تمام</span>':pill(r.status)}</td><td class="ltr" data-ms="${i}">${ms(r)}</td><td data-qc="${i}">${qcr(r)}</td><td><button class="btn" onclick="tst(${i+1},this)">تست</button> <button class="btn" onclick="qopen(${i})">حجم</button> <button class="btn" onclick="secopen(${i})">${r.sec&&(r.sec.allow||r.sec.maxc||r.sec.rate)?"🛡 ":""}امنیت</button> <button class="btn" onclick="sopen(${i})">${r.sub?"🔗 ":""}لینک</button> <button class="btn d" onclick="del(${i+1})">حذف</button></td></tr>`}
function drawTunAll(force){const s=window.LAST;if(!s)return;const q=FLT.m;
 const sig=s.rules.map(ruleSig).join(";")+"#"+q;
 if(!force&&sig===TSIG)return;TSIG=sig;let h="";
 if(q){const idx=[];s.rules.forEach((r,i)=>{if(fmatch(r,q))idx.push(i)});
  h=idx.length?idx.map(i=>rowH(s.rules[i],i,false)).join(""):`<tr><td colspan="9" class="empty">${s.rules.length?"موردی پیدا نشد":"هنوز تانلی نساخته‌اید"}</td></tr>`}
 else{const G=new Map();s.rules.forEach((r,i)=>{if(!G.has(r.ip))G.set(r.ip,[]);G.get(r.ip).push(i)});
  G.forEach((ix,ip)=>{
   if(ix.length<2){h+=rowH(s.rules[ix[0]],ix[0],false);return}
   const g=ix.map(i=>s.rules[i]),open=OPEN.has(ip),by=g.reduce((a,r)=>a+r.bytes,0),lim=g.every(r=>r.limit)?g.reduce((a,r)=>a+r.limit,0):0;
   const dn=g.filter(r=>r.blocked||r.status==="down").length,up=g.filter(r=>r.status==="up").length,m=g.filter(r=>r.ms!=null);
   const st=dn?`<span class="pill down">${dn}/${g.length} قطع</span>`:up===g.length?pill("up"):pill("unknown");
   const pr=[...new Set(g.map(r=>r.proto))].map(p=>`<span class="tag">${p}</span>`).join(" "),pt=g.slice(0,6).map(r=>r.lport).join(", ")+(g.length>6?" +"+(g.length-6):"");
   h+=`<tr class="grp" onclick="tg('${ip}')"><td>${open?"▾":"▸"}</td><td>${g.length} پورت${g[0].enc?" 🔒":""}</td><td>${pr}</td><td class="ltr">${pt}</td><td class="ltr cp" data-cp="${ip}" title="کپی">${ip}</td><td>${st}</td><td class="ltr" data-gms="${ip}">${m.length?Math.round(m.reduce((a,r)=>a+r.ms,0)/m.length)+" ms":"—"}</td><td data-gqc="${ip}">${qcr({bytes:by,limit:lim,blocked:false})}</td><td><button class="btn" onclick="event.stopPropagation();gtst('${ip}',this)">تست</button> <button class="btn" onclick="event.stopPropagation();secopen(0,'${ip}')">امنیت</button> <button class="btn d" onclick="event.stopPropagation();gdel('${ip}')">حذف همه</button></td></tr>`;
   if(open)ix.forEach(i=>{h+=rowH(s.rules[i],i,true)})})}
 $("tb_m").innerHTML=h||`<tr><td colspan="9" class="empty">هنوز تانلی نساخته‌اید</td></tr>`}
function patchTun(){const s=window.LAST;if(!s)return;const tb=$("tb_m");if(!tb)return;
 s.rules.forEach((r,i)=>{const a=tb.querySelector(`[data-ms="${i}"]`);if(a)a.innerHTML=ms(r);
  const b=tb.querySelector(`[data-qc="${i}"]`);if(b)b.innerHTML=qcr(r)});
 const G=new Map();s.rules.forEach(r=>{if(!G.has(r.ip))G.set(r.ip,[]);G.get(r.ip).push(r)});
 G.forEach((g,ip)=>{if(g.length<2)return;
  const a=tb.querySelector(`[data-gms="${ip}"]`);if(a){const m=g.filter(r=>r.ms!=null);a.innerHTML=m.length?Math.round(m.reduce((x,y)=>x+y.ms,0)/m.length)+" ms":"—"}
  const b=tb.querySelector(`[data-gqc="${ip}"]`);if(b)b.innerHTML=qcr({bytes:g.reduce((x,y)=>x+y.bytes,0),limit:g.every(r=>r.limit)?g.reduce((x,y)=>x+y.limit,0):0,blocked:false})})}
function render(s){window.LAST=s;
 const y=s.sys||{};$("host").textContent=s.host;$("ver").textContent="v"+s.ver;$("fver").textContent="v"+s.ver;
 animNum($("c_cpu"),y.cpu||0,v=>v.toFixed(0)+"<small>%</small>");bar("cpu",y.cpu||0);$("s_load").textContent="load "+(y.load||0).toFixed(2)+" · up "+Math.floor((y.up||0)/86400)+"d "+Math.floor((y.up||0)%86400/3600)+"h";
 const rp=100*(y.ram_used||0)/(y.ram_total||1);animNum($("c_ram"),rp,v=>v.toFixed(0)+"<small>%</small>");bar("ram",rp);$("s_ram").textContent=hb(y.ram_used)+" / "+hb(y.ram_total);
 const dp=100*(y.disk_used||0)/(y.disk_total||1);animNum($("c_dsk"),dp,v=>v.toFixed(0)+"<small>%</small>");bar("dsk",dp);$("s_dsk").textContent=hb(y.disk_used)+" / "+hb(y.disk_total);
 let nd=0,nu=0;if(prev&&prev.t&&y.t>prev.t){nd=Math.max(0,(y.rx-prev.rx)/(y.t-prev.t));nu=Math.max(0,(y.tx-prev.tx)/(y.t-prev.t))}
 animNum($("c_dn"),nd,v=>nv(hb(v)+"/s"));animNum($("c_up"),nu,v=>nv(hb(v)+"/s"));hist("h_dn",HD,nd);hist("h_up",HU,nu);
 $("s_dn").textContent="peak "+hb(Math.max(...HD))+"/s · total "+hb(y.rx);$("s_up").textContent="peak "+hb(Math.max(...HU))+"/s · total "+hb(y.tx);
 SP={};let all=0;if(prev&&prev.now){const dt=s.now-prev.now;s.rules.forEach(r=>{const o=prev.m[r.lport+r.proto];if(o!=null&&dt>0){SP[r.lport+r.proto]=Math.max(0,(r.bytes-o)/dt);all+=SP[r.lport+r.proto]}})}
 prev={now:s.now,t:y.t,rx:y.rx,tx:y.tx,m:Object.fromEntries(s.rules.map(r=>[r.lport+r.proto,r.bytes]))};
 const up=s.rules.filter(r=>r.status==="up").length,dn=s.rules.filter(r=>r.status==="down").length;
 $("t_n").textContent=s.rules.length;$("t_ud").textContent=up+" آنلاین · "+dn+" قطع";
 animNum($("t_b"),s.rules.reduce((a,r)=>a+r.bytes,0),v=>hb(v));$("t_p").textContent=s.rules.reduce((a,r)=>a+r.packets,0)+" packets";
 animNum($("t_s"),all,v=>nv(hb(v)+"/s"));
 $("t_fw").innerHTML=`<span style="color:var(${s.ip_forward?"--ok":"--er"})">●</span> IP Forward: ${s.ip_forward?"ON":"OFF"}`;$("t_cc").textContent="TCP: "+s.cc.toUpperCase();
 draw24(s.t24);
 const pf=s.perf||{};$("pf_c").textContent=pf.preset||"—";$("pf_n").textContent=(pf.ct||0)+" / "+(pf.cm||0);document.querySelectorAll("#pf_b [data-pf]").forEach(x=>x.classList.toggle("on",x.dataset.pf===pf.preset));
 drawDash();drawTunAll();patchTun()}
function draw24(v){const el=$("ch24");if(!el)return;v=v||[];
 if(!v.length){el.innerHTML='<div class="empty">هنوز داده‌ای ثبت نشده</div>';$("ch24s").textContent="";return}
 const w=720,h=110,pd=6,mx=Math.max(...v.map(x=>x[1]),1),n=v.length,st=w/Math.max(n,1);
 let pts="";v.forEach((x,i)=>{pts+=(i?" L":"M")+(i*st+st/2).toFixed(1)+","+(h-pd-(x[1]/mx)*(h-pd*2)).toFixed(1)});
 el.innerHTML=`<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:100%;display:block"><defs><linearGradient id="g24" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--ac)" stop-opacity=".35"/><stop offset="1" stop-color="var(--ac)" stop-opacity="0"/></linearGradient></defs><path d="${pts} L${w},${h} L0,${h} Z" fill="url(#g24)"/><path d="${pts}" fill="none" stroke="var(--ac)" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`;
 const hrs=[0,6,12,18].map(i=>{const b=v[Math.min(i,v.length-1)];return new Date(b[0]*1000).toLocaleTimeString("sv",{hour:"2-digit",minute:"2-digit"})}).join(" · ");
 $("ch24s").textContent="مجموع ۲۴ ساعت: "+hb(v.reduce((a,x)=>a+x[1],0))+" · بیشترین ساعت: "+hb(mx)+" · "+hrs}
async function tst(n,b){b.disabled=true;try{const r=await api("test/"+n,"POST",{});toast(r.udp?"UDP قابل تست نیست":r.ms==null?"مقصد پاسخ نمی‌دهد":"اتصال موفق · "+r.ms+" ms",r.udp?"":r.ms==null?"e":"s")}catch(e){toast(e.message,"e")}b.disabled=false}
async function del(n){if(!cf("این تانل حذف شود؟"))return;try{await api("rules/"+n,"DELETE");toast("حذف شد","s");load()}catch(e){toast(e.message,"e")}}
$("add").onclick=()=>$("m").classList.add("on");$("f_x").onclick=()=>$("m").classList.remove("on");
$("f_ok").onclick=async()=>{try{await api("rules","POST",{lport:$("f_l").value,proto:$("f_p").value,ip:$("f_i").value,dport:$("f_d").value,name:$("f_n").value});
 $("m").classList.remove("on");["f_l","f_d","f_n"].forEach(i=>$(i).value="");toast("تانل اضافه شد","s");load()}catch(e){toast(e.message,"e")}};
$("hrun").onclick=async()=>{$("hl").innerHTML='<div class="empty">در حال بررسی…</div>';try{const r=await api("health");
 $("hl").innerHTML=r.map(i=>`<div class="hl"><b class="${i.level}">${{ok:"✔",warn:"!",err:"✘"}[i.level]}</b><div>${esc(i.msg)}${i.fix&&i.level!=="ok"?`<code>${esc(i.fix)}</code>`:""}</div></div>`).join("")}catch(e){toast(e.message,"e")}};
const OPEN=new Set();
function tg(ip){OPEN.has(ip)?OPEN.delete(ip):OPEN.add(ip);drawTunAll(true)}
async function gtst(ip,b){b.disabled=true;try{const ix=window.LAST.rules.map((r,i)=>[r,i]).filter(([r])=>r.ip===ip&&r.proto!=="udp");const res=await Promise.all(ix.map(([r,i])=>api("test/"+(i+1),"POST",{})));const ok=res.filter(x=>x.ms!=null).length;toast(ok+" از "+res.length+" پورت پاسخ می‌دهند",ok===res.length?"s":"e")}catch(e){toast(e.message,"e")}b.disabled=false}
async function gdel(ip){const g=window.LAST.rules.filter(r=>r.ip===ip);if(!cf("همه پورت‌های این سرور حذف شوند؟"))return;try{await api("rules/bulk","POST",{lports:g.map(r=>r.lport)});toast("حذف شد","s");load()}catch(e){toast(e.message,"e")}}
let TUNS=[];const tage=a=>a==null?"—":a<90?a+"s":Math.round(a/60)+"m";const PRFA={balanced:"Balanced",turbo:"Turbo",throughput:"Throughput",gaming:"Gaming"};
async function trLoad(){try{const r=await api("tunnels");TUNS=r.tunnels;const cur=$("t_ti").value;
 $("tb_t").innerHTML=TUNS.length?TUNS.map((t,i)=>{const key=t.pending?t.id:t.ip;const ty=t.type==="rev"?'<span class="pill up" style="font-size:10px">ریورس</span>':t.type==="dir"?'<span class="pill unknown" style="font-size:10px">دایرکت</span>':"";
  const trb=t.tr&&t.tr!=="udp"?` <span class="pill unknown" style="font-size:10px">${t.tr.toUpperCase()}</span>`:"";
  return `<tr><td>${t.name?`<b>${esc(t.name)}</b><br>`:""}${t.pending?'<span class="hint">در انتظار اتصال سرور خارج…</span>':'<span class="ltr">'+t.ip+"</span>"} ${ty}${trb}</td><td class="ltr">${t.port}</td><td>${t.pending?'<span class="pill unknown">منتظر اتصال</span>':t.up?'<span class="pill up">متصل</span>':'<span class="pill down">بدون handshake</span>'}${t.pending?"":' <span class="hint">'+tage(t.age)+"</span>"}</td><td class="ltr">↓${hb(t.rx)} ↑${hb(t.tx)}</td><td>${t.active?'<span class="pill up">🔒 تانل</span>':'<span class="pill unknown">مستقیم</span>'}</td><td><select class="prsel" onchange="trPreset('${key}',this.value)">${["","balanced","turbo","throughput","gaming"].map(p=>`<option value="${p}" ${(t.preset||"")===p?"selected":""}>${p?PRFA[p]:"سیستم"}</option>`).join("")}</select><select class="prsel" style="margin-top:6px" onchange="trTransport('${key}',this.value)">${["udp","tcp","ws","wss","kcp","quic","gaaf"].map(x=>`<option value="${x}" ${(t.tr||"udp")===x?"selected":""}>${x.toUpperCase()}</option>`).join("")}</select></td><td><button class="btn" onclick="trLink(${i})">لینک اتصال</button> ${t.pending?"":`<button class="btn" onclick="trAct('script','${t.ip}')">دستور سرور خارج</button> <button class="btn" onclick="trAct('${t.active?"direct":"use"}','${key}')">${t.active?"برگشت به مستقیم":"فعال‌سازی"}</button> `}<button class="btn d" onclick="trAct('del','${key}')">حذف</button></td></tr>`}).join(""):'<tr><td colspan="7" class="empty">هنوز تانلی ساخته نشده</td></tr>';
 const ips=[...new Set((window.LAST?window.LAST.rules:[]).map(r=>r.ip))];
 $("t_ti").innerHTML=[...new Set([...TUNS.filter(t=>!t.pending).map(t=>t.ip),...ips])].map(i=>`<option>${i}</option>`).join("");if(cur)$("t_ti").value=cur;rvIps()}catch(e){toast(e.message,"e")}}
async function trTransport(key,v){if(!v)return;const t=TUNS.find(x=>(x.pending?x.id:x.ip)==key);if(!t)return;
 if(!cf(`ترنسپورت این تانل به ${v.toUpperCase()} تغییر کند؟`+(v!=="udp"&&t.tr==="udp"?" اسکریپت سمت سرور خارج باید دوباره اجرا شود.":"")))return;
 try{await api("tunnel","POST",{action:"transport",ip:t.pending?undefined:t.ip,id:t.id,tr:v});toast("ترنسپورت: "+v.toUpperCase()+" — اگر تانل carried است، دستور سمت خارج را دوباره اجرا کن","s");trLoad()}catch(e){toast(e.message,"e")}}
async function trPreset(ip,v){try{await api("tunnel","POST",{action:"preset",ip,preset:v||"none"});toast(v?"اعمال شد: "+PRFA[v]:"پیش‌فرض سیستم","s");trLoad();load()}catch(e){toast(e.message,"e")}}
let REVS=[];
function rvIps(){const el=$("rv_ip");if(!el)return;const cur=el.value;const ips=[...new Set(TUNS.filter(t=>!t.pending).map(t=>t.ip))];el.innerHTML=ips.map(i=>`<option>${i}</option>`).join("");if(cur)el.value=cur}
async function rvLoad(){try{const r=await api("reverse");REVS=r.rows;
 $("tb_r").innerHTML=REVS.length?REVS.map(x=>`<tr><td class="ltr">${esc(x.ip)}</td><td class="ltr">${x.lport}</td><td class="ltr">${x.dport}</td><td><span class="tag">${x.proto}</span></td><td><button class="btn" onclick="rvTest('${x.ip}',${x.lport},this)">تست</button> <button class="btn d" onclick="rvDel('${x.ip}',${x.lport})">حذف</button></td></tr>`).join(""):'<tr><td colspan="5" class="empty">هنوز ریورسی ساخته نشده</td></tr>'}catch(e){}}
$("rv_add").onclick=async()=>{const b=$("rv_add");b.disabled=true;try{const ip=$("rv_ip").value;if(!ip){toast("اول یک تانل بساز","e");return}
 if(!+$("rv_l").value||!+$("rv_d").value){toast("پورت‌ها را وارد کنید","e");return}
 await api("reverse","POST",{action:"add",ip,lport:+$("rv_l").value,dport:+$("rv_d").value,proto:$("rv_p").value});
 toast("ذخیره شد — اسکریپت سرور خارج را دوباره اجرا کن","s");$("rv_l").value=$("rv_d").value="";rvLoad();trAct("script",ip)}catch(e){toast(e.message,"e")}b.disabled=false};
async function rvDel(ip,lp){if(!cf("این ریورس حذف شود؟ بعدش اسکریپت سرور خارج را دوباره اجرا کن."))return;
 try{await api("reverse","POST",{action:"del",ip,lport:lp});toast("حذف شد — اسکریپت سرور خارج را دوباره اجرا کن","s");rvLoad()}catch(e){toast(e.message,"e")}}
async function rvTest(ip,lp,b){b.disabled=true;b.textContent="…";try{const r=await api("reverse","POST",{action:"test",ip,lport:lp});
 b.textContent=r.ok?`✔ ${r.avg} ms · ${r.loss}%`:"✘ بی‌پاسخ";b.classList.add(r.ok?"okc":"errc")}catch(e){b.textContent="✘ خطا";toast(e.message,"e")}b.disabled=false}
async function trAct(a,ip){try{
 if(a==="script"){const r=await api("tunnel/script?ip="+ip);$("t_sx").value=r.script;$("t_sc").style.display="block";$("t_sc").scrollIntoView({behavior:"smooth"});return}
 if(a==="del"&&!cf("این تانل حذف شود؟ فورواردها به حالت مستقیم برمی‌گردند."))return;
 await api("tunnel","POST",{action:a,ip});toast("انجام شد","s");await load();trLoad()}catch(e){toast(e.message,"e")}}
$("t_add").onclick=wOpen;
/* ---------------- tunnel wizard (BackPack-style) ---------------- */
const WTY={rev:{t:"ریورس",b:"پیشنهادی",d:"سرور خارج به ایران dial می‌زند (مثل بک‌پک). فقط یک دستور روی سرور خارج اجرا می‌کنی؛ حتی لازم نیست IP خارج را بدانی — مناسب وقتی خارج پشت NAT است یا ایران خروجی آزاد ندارد."},
dir:{t:"دایرکت",d:"ایران به سرور خارج وصل می‌شود (حالت کلاسیک). IP سرور خارج و پورت UDP آن را داری."},
fwd:{t:"پورت فوروارد",d:"همان حالت همیشگی: فورواردهای این سرور از داخل تانل رمزنگاری‌شده رد می‌شوند. IP سرور خارج لازم است."}};
const WTR=[["udp","UDP — سریع‌ترین (پیشنهادی)","دیتاگرام خام UDP؛ کمترین سربار. اگر UDP باز است همین را بردار."],
["gaaf","GAAF — پروتکل اختصاصی SEKA (SM4-GCM)","تانل اختصاصی با رمزنگاری SM4-GCM و تبادل کلید X25519. مناسب Direct و Reverse."],
["tcp","TCP","وقتی UDP بسته یا throttle می‌شود؛ بسته‌های تانل داخل یک اتصال TCP ساده سفر می‌کنند."],
["ws","WebSocket","تونل داخل HTTP عادی — از فیلترهای HTTP-only و CDN رد می‌شود."],
["wss","WebSocket + TLS","وب‌سوکت داخل TLS — شبیه ترافیک HTTPS؛ گواهی self-signed خودکار ساخته می‌شود."],
["kcp","UDP + KCP","UDP با تصحیح خطا (FEC) — جواب مسیر پرافت، بازی و تماس."],
["quic","QUIC","سشن واقعی QUIC با TLS 1.3 و کنترل ازدحام — هیچ تنظیمی نمی‌خواهد."]];
const WPR=[["turbo","Turbo","تعادل سرعت و پایداری — پیشنهاد برای اکثر تانل‌ها"],["balanced","Balanced","کم‌بارترین حالت برای سرورهای ضعیف"],["throughput","Throughput","بافر و پنجرهٔ بزرگ‌تر — برای حجم بالا"],["gaming","Gaming","کمترین تأخیر — برای گیم و تماس"],["","پیش‌فرض سیستم","تنظیمات کلی سرور (تب تنظیمات)"]];
const WSTEPS=["نوع","تانل","کارایی","اختیاری","اتصال"];
let WZ=null;
function wOpen(){WZ={step:0,type:"rev",name:"",port:51820,ip:"",tr:"udp",cport:"",preset:"turbo",lport:"",dport:""};$("w_t").textContent="ساخت تانل جدید";$("wm").classList.add("on");wDraw()}
function wClose(){WZ=null;$("wm").classList.remove("on")}
function wSet(k,v){if(WZ){WZ[k]=v;wDraw()}}
function wRand(){if(WZ){WZ.port=10000+Math.floor(Math.random()*50000);wDraw()}}
function wGrab(){const w=WZ;if(!w)return;
 if(w.step===1){if($("w_n"))w.name=$("w_n").value.trim().slice(0,40);if($("w_i"))w.ip=$("w_i").value.trim();if($("w_p"))w.port=+$("w_p").value||51820;if($("w_tr"))w.tr=$("w_tr").value;if($("w_c"))w.cport=$("w_c").value.trim()}
 if(w.step===3){if($("w_l"))w.lport=$("w_l").value.trim();if($("w_d"))w.dport=$("w_d").value.trim()}}
function wDraw(){const w=WZ;if(!w)return;
 $("w_st").innerHTML=WSTEPS.map((s,i)=>`<i class="${i<w.step?"done":i===w.step?"on":""}" title="${s}"></i>`).join("");
 const h=[];
 if(w.step===0){h.push('<div class="hint" style="margin:0 0 10px"><b>ایران — همین سرور.</b> دو سرور چطور به هم وصل شوند؟</div>');
  for(const[k,v]of Object.entries(WTY))h.push(`<div class="wcard ${w.type===k?"on":""}" onclick="wSet('type','${k}')"><b>${v.t}${v.b?` <span class="pill up" style="font-size:10px">${v.b}</span>`:""}</b><small>${v.d}</small></div>`)}
 else if(w.step===1){h.push(`<div class="hint" style="margin:0 0 10px">${w.type==="rev"?"ریورس — سرور خارج به ایران وصل می‌شود؛ IP خارج لازم نیست.":"ایران به سرور خارج وصل می‌شود؛ آدرس خارج را بده."}</div>`);
  h.push(`<label>نام تانل (اختیاری)</label><input id="w_n" placeholder="tanl-1" value="${esc(w.name)}">`);
  if(w.type!=="rev")h.push(`<label>IP سرور خارج</label><input id="w_i" placeholder="1.2.3.4" dir="ltr" value="${esc(w.ip)}">`);
  h.push(`<label>پورت UDP تانل</label><div style="display:flex;gap:8px;margin-top:4px"><input id="w_p" inputmode="numeric" value="${w.port}" style="flex:1"><button class="btn" type="button" onclick="wRand()">تصادفی</button></div>`);
  h.push(`<label style="margin-top:10px">ترنسپورت (مسیر تانل — مثل بک‌پک برای هر تانل جدا)</label><select id="w_tr" onchange="wSet('tr',this.value)">${WTR.map(x=>`<option value="${x[0]}" ${w.tr===x[0]?"selected":""}>${x[1]}</option>`).join("")}</select><div class="hint" style="margin:6px 0 0">${(WTR.find(x=>x[0]===w.tr)||["","",""])[2]}</div>`);
  if(w.tr!=="udp")h.push(`<label style="margin-top:8px">پورت ترنسپورت (روی سرور شنونده)</label><input id="w_c" inputmode="numeric" placeholder="خالی = خودکار" value="${esc(w.cport)}" dir="ltr">`)}
 else if(w.step===2){h.push('<div class="hint" style="margin:0 0 10px">حالت کارایی <b>همین تانل</b> — برای هر تانل جدا ذخیره می‌شود و موقع «فعال‌سازی» خودکار اعمال می‌شود.</div>');
  for(const[k,n,d]of WPR)h.push(`<div class="wcard ${w.preset===k?"on":""}" onclick="wSet('preset','${k}')"><b>${n}</b><small>${d}</small></div>`)}
 else if(w.step===3){h.push('<div class="hint" style="margin:0 0 10px">اختیاری — اولین فوروارد را همین‌جا بساز یا خالی بگذار و بعداً از تب «تانل‌ها» اضافه کن.</div>');
  h.push('<div class="row"><div><label>پورت ورودی (این سرور)</label><input id="w_l" inputmode="numeric" placeholder="443"></div><div><label>پورت مقصد (خالی = برابر)</label><input id="w_d" inputmode="numeric"></div></div>');
  h.push(w.type==="rev"?'<div class="hint">مقصد این فوروارد خودکار آدرس داخلی تانل می‌شود.</div>':`<div class="hint">مقصد: <b class="ltr">${esc(w.ip)}</b></div>`)}
 $("w_b").innerHTML=h.join("");
 $("w_back").style.visibility=(w.step===0||w.step===4)?"hidden":"visible";
 $("w_next").textContent=w.step===3?"ساخت تانل و نمایش لینک":w.step===4?"بستن":"ادامه"}
async function wFinish(){const w=WZ,b=$("w_next");if(!w)return;b.disabled=true;
 try{toast("در حال ساخت (نصب WireGuard ممکن است کمی طول بکشد)…","");
  if(w.type==="rev")await api("tunnel","POST",{action:"add",type:"rev",port:w.port,preset:w.preset,name:w.name,tr:w.tr,cport:w.cport});
  else await api("tunnel","POST",{action:"add",type:w.type,ip:w.ip,port:w.port,preset:w.preset,name:w.name,tr:w.tr,cport:w.cport});
  await trLoad();
  const t=w.type==="rev"?[...TUNS].filter(x=>x.pending).sort((a,c)=>c.id-a.id)[0]:TUNS.find(x=>x.ip===w.ip);
  if(w.lport&&t){const dip=w.type==="rev"?"10.66."+t.id+".2":w.ip;
   try{await api("rules","POST",{lport:w.lport,ip:dip,dport:w.dport||w.lport,proto:"tcp",name:w.name?("fw-"+w.name):""});await load()}catch(e){}}
  else load();
  let url="";try{const rr=await api("tunnel/link?ip="+(t?(t.pending?t.id:t.ip):w.ip));url=rr.url}catch(e){}
  wDone(url,t)}catch(e){toast(e.message,"e")}b.disabled=false}
function wDone(url,t){WZ={step:4};$("w_t").textContent="لینک اتصال تانل"+(t&&t.name?" — "+t.name:"");$("wm").classList.add("on");
 $("w_st").innerHTML='<i class="done"></i>'.repeat(5);
 $("w_b").innerHTML=`<div class="hl" style="margin:0 0 12px"><b class="ok">✔</b><div>این یک خط را روی <b>سرور خارج</b> اجرا کن (root) — WireGuard را نصب می‌کند، تانل را برپا می‌کند و به ایران dial می‌زند. چند ثانیه بعد وضعیت لینک در جدول «متصل» می‌شود:</div></div>
  <textarea id="w_lnk" rows="3" readonly dir="ltr" style="font-size:12.5px">${esc(url||"—")}</textarea>
  <div class="acts"><button class="btn p" id="w_cp">کپی دستور</button>${t&&!t.pending?'<button class="btn" id="w_scr">اسکریپت کامل (جایگزین)</button>':""}</div>
  <div class="hint" style="margin-top:8px">این لینک محرمانه است — کلید خصوصی سمت خارج داخلش است؛ جایی منتشرش نکن. دکمه «لینک اتصال» در جدول همیشه دوباره همین دستور را می‌دهد.</div>`;
 $("w_back").style.visibility="hidden";$("w_next").textContent="بستن";
 $("w_cp").onclick=async()=>{try{await navigator.clipboard.writeText($("w_lnk").value)}catch(e){$("w_lnk").select();document.execCommand("copy")}toast("کپی شد","s")};
 if($("w_scr"))$("w_scr").onclick=async()=>{try{const r=await api("tunnel/script?ip="+(t.pending?t.id:t.ip));$("w_lnk").value=r.script;$("w_lnk").rows=16;if($("w_scr"))$("w_scr").style.display="none"}catch(e){toast(e.message,"e")}}}
async function trLink(i){const t=TUNS[i];if(!t)return;try{const r=await api("tunnel/link?ip="+(t.pending?t.id:t.ip));wDone(r.url,t)}catch(e){toast(e.message,"e")}}
$("w_next").onclick=()=>{const w=WZ;if(!w)return;
 if(w.step===4){wClose();trLoad();load();return}
 if(w.step===1){wGrab();if(w.type!=="rev"&&!/^\d{1,3}(\.\d{1,3}){3}$/.test(w.ip)){toast("آی‌پی سرور خارج را درست وارد کن","e");return}
  if(!(w.port>=1&&w.port<=65535)){toast("پورت نامعتبر است","e");return}}
 if(w.step===3){wGrab();wFinish();return}
 w.step++;wDraw()};
$("w_back").onclick=()=>{const w=WZ;if(w&&w.step>0&&w.step<4){w.step--;wDraw()}};
/* ---------------- connection test ---------------- */
async function ctLoad(){try{const r=await api("conntest");ctDraw(r)}catch(e){}}
async function ctRun(){const b=$("ct_run");if(b.disabled)return;b.disabled=true;$("ct_out").innerHTML='<div class="empty">در حال تست… (حدود ۲۰ ثانیه)</div>';
 try{await api("conntest","POST",{});let n=0;const iv=setInterval(async()=>{n++;
  try{const r=await api("conntest");if(!r.running||n>45){clearInterval(iv);b.disabled=false;ctDraw(r);load()}
   else $("ct_out").innerHTML='<div class="empty">در حال تست… ('+(n*2)+' ثانیه) — پینگ، دانلود و تانل‌ها</div>'}catch(e){clearInterval(iv);b.disabled=false}},2000)}
 catch(e){b.disabled=false;toast(e.message,"e")}}
$("ct_run").onclick=ctRun;
/* ---- two-server connection test (BackPack-style) ---- */
function ct2Rec(r){const rp=r.report;if(!rp)return null;
 const ic=rp.icmp||{},tc=rp.tcp||{},ud=rp.udp||{};
 if(ud&&ud.ok&&ud.loss!=null&&ud.loss<5&&!(ic.jit&&ic.avg&&ic.jit>ic.avg/2))return{tr:"udp",fa:"مسیر UDP تمیز است — ترنسپورت UDP (سریع‌ترین) مناسب است."};
 if(ud&&ud.ok&&ud.loss!=null&&ud.loss>=5&&ud.loss<40)return{tr:"kcp",fa:"UDP پرافت است ("+ud.loss+"%) — ترنسپورت KCP (تصحیح خطا) پیشنهاد می‌شود."};
 if(ud&&ud.ok===false)return{tr:tc&&tc.ok?"tcp":"ws",fa:tc&&tc.ok?"UDP بین دو سرور رد نمی‌شود — ترنسپورت TCP پیشنهاد می‌شود.":"UDP و TCP هر دو ناپایدارند — ترنسپورت WebSocket (WS) را امتحان کن."};
 return{tr:"udp",fa:"UDP پاسخ می‌دهد — ترنسپورت UDP مناسب است."}}
function ct2Draw(r){const el=$("ct2_out");if(!el)return;let h="";
 if(r.cmd){h+=`<label>این یک خط را روی <b>سرور خارج</b> اجرا کن (root):</label><textarea id="ct2_lnk" rows="2" readonly dir="ltr" style="font-size:12.5px">${esc(r.cmd)}</textarea><div class="acts"><button class="btn p" id="ct2_cp">کپی دستور</button><button class="btn d" id="ct2_cl">بستن تست</button><span class="hint">لینک تا ۱۵ دقیقه اعتبار دارد.</span></div>`}
 const rp=r.report;
 if(rp){const dts=new Date(rp.t*1000).toLocaleString("sv");
  const cell=(x,k)=>x&&x[k]!=null?x[k]:"—";
  const row=(n,x)=>`<tr><td>${n}</td><td>${x&&x.ok?'<span class="pill up">پاسخ می‌دهد</span>':'<span class="pill down">بی‌پاسخ</span>'}</td><td class="ltr">${cell(x,"avg")}</td><td class="ltr">${cell(x,"jit")}</td><td class="ltr">${x&&x.loss!=null?x.loss+"%":"—"}</td></tr>`;
  h+=`<div class="hint" style="margin:10px 0 6px">آخرین نتیجه از سرور خارج (<span class="ltr">${esc(rp.ip||"")}</span> · <span class="ltr">${dts}</span>):</div><div style="overflow-x:auto"><table><thead><tr><th>مسیر</th><th>وضعیت</th><th>میانگین ms</th><th>نوسان ms</th><th>پکت‌خسری</th></tr></thead><tbody>${row("پینگ (ICMP)",rp.icmp)}${row("اکوی TCP",rp.tcp)}${row("اکوی UDP",rp.udp)}</tbody></table></div>`;
  const rec=ct2Rec(r);
  if(rec){h+=`<div class="hl" style="margin-top:10px"><b class="ok">⚡</b><div>${esc(rec.fa)}`;
   if(TUNS.filter(t=>!t.pending).length===1)h+=` <button class="btn p" style="margin-inline-start:10px" onclick="ct2Apply('${rec.tr}')">اعمال ${rec.tr.toUpperCase()} به تانل</button>`;
   h+="</div></div>"}}
 $("ct2_out").innerHTML=h||'<div class="empty">هنوز لینکی ساخته نشده</div>';
 if($("ct2_cp"))$("ct2_cp").onclick=async()=>{try{await navigator.clipboard.writeText($("ct2_lnk").value)}catch(e){$("ct2_lnk").select();document.execCommand("copy")}toast("کپی شد","s")};
 if($("ct2_cl"))$("ct2_cl").onclick=async()=>{try{await api("ctest","POST",{action:"close"});toast("تست بسته شد","s");ct2Load()}catch(e){toast(e.message,"e")}}}
async function ct2Apply(tr){const t=TUNS.filter(t=>!t.pending)[0];if(!t)return;
 try{await api("tunnel","POST",{action:"transport",ip:t.ip,tr});toast("ترنسپورت تانل: "+tr.toUpperCase()+" — دستور سمت خارج را دوباره اجرا کن","s");trLoad()}catch(e){toast(e.message,"e")}}
async function ct2Load(){try{const r=await api("ctest");ct2Draw(r)}catch(e){}}
$("ct_open").onclick=async()=>{const b=$("ct_open");if(!b||b.disabled)return;b.disabled=true;
 try{const r=await api("ctest","POST",{action:"open"});ct2Draw(r);toast("لینک تست ساخته شد — روی سرور خارج اجرا کن","s")}catch(e){toast(e.message,"e")}b.disabled=false};
function ctDraw(r){const s=(window.LAST||{}).sys||{};
 $("ct_c").textContent=(s.cpu!=null?Math.round(s.cpu):"—")+"%";$("ct_cs").textContent=s.load!=null?("load "+s.load):"—";
 $("ct_r").textContent=s.ram_total?Math.round(100*s.ram_used/s.ram_total)+"%":"—";$("ct_rs").textContent=s.ram_total?hb(s.ram_used)+" / "+hb(s.ram_total):"—";
 $("ct_d").textContent=s.disk_total?Math.round(100*s.disk_used/s.disk_total)+"%":"—";$("ct_ds").textContent=s.disk_total?hb(s.disk_used)+" / "+hb(s.disk_total):"—";
 $("ct_n").textContent=s.rx!=null?(hb(s.rx)+" ↓"):"—";$("ct_ns").textContent=s.tx!=null?(hb(s.tx)+" ↑"):"—";
 const res=r.result;
 if(!res){$("ct_out").innerHTML='<div class="empty">هنوز تستی اجرا نشده</div>';return}
 const dts=new Date(res.t*1000).toLocaleString("sv");
 const row=(n,x,ex)=>!x?"":`<tr><td>${n}</td><td>${x.down?'<span class="pill down">قطع</span>':x.ok?'<span class="pill up">پاسخ می‌دهد</span>':'<span class="pill down">بی‌پاسخ</span>'}</td><td class="ltr">${x.ok?x.avg+" ms":"—"}</td><td class="ltr">${x.ok?(x.jitter??"—")+" ms":"—"}</td><td class="ltr">${x.ok?x.loss+"%":"—"}</td>${ex||""}</tr>`;
 let html=`<div class="hint" style="margin:0 0 10px">آخرین تست: <span class="ltr">${dts}</span></div><div style="overflow-x:auto"><table><thead><tr><th>مقصد</th><th>وضعیت</th><th>میانگین</th><th>نوسان</th><th>پکت‌خسری</th></tr></thead><tbody>`
  +row("Cloudflare 1.1.1.1",res.g2)+row("Google 4.2.2.4",res.g1);
 for(const t of res.tunnels||[])html+=row("تانل "+(t.name||t.ip),t.up?t:{down:true},`<td class="ltr">${t.mtu?"MTU "+t.mtu:"—"}</td>`);
 html+="</tbody></table></div>"
  +`<div class="wrow"><div><span class="l">دانلود مستقیم (Cloudflare)</span><b class="ltr">${res.dl?res.dl+" Mbit/s":"—"}</b></div><div><span class="l">UDP خروجی</span><b>${res.udp?"باز":"بسته"}</b></div></div>`
  +(res.udp===false?'<div class="hl" style="margin-top:10px"><b class="err">✘</b><div>خروجی UDP بسته است — تانل WireGuard بالا نمی‌آید. اول UDP را روی فایروال/اپراتور باز کن.</div></div>':"")
  +((res.rec&&res.rec.fa)?`<div class="hl" style="margin-top:10px"><b class="${res.rec.label==="offline"||res.rec.label==="udp_blocked"?"err":"ok"}">${res.rec.label==="offline"||res.rec.label==="udp_blocked"?"✘":"⚡"}</b><div>${esc(res.rec.fa)}${res.rec.preset?` <button class="btn p" style="margin-inline-start:10px" onclick="applyRec('${res.rec.preset}')">اعمال ${PRFA[res.rec.preset]||res.rec.preset}</button>`:""}</div></div>`:"");
 $("ct_out").innerHTML=html}
$("t_cp").onclick=async()=>{try{await navigator.clipboard.writeText($("t_sx").value)}catch(e){$("t_sx").select();document.execCommand("copy")}toast("کپی شد","s")};
const TV={no_tunnel:["برای مقایسه ابتدا یک تانل رمزنگاری‌شده بساز. فعلاً فقط مسیر مستقیم تست شد.","warn"],wg_down:["لینک WireGuard برقرار نشده: یا دستور سمت سرور خارج هنوز اجرا نشده، یا UDP این مسیر بسته است. فعلاً مستقیم را نگه دار.","err"],wg_nosvc:["لینک WireGuard وصل است ولی این پورت از داخل تانل جواب نمی‌دهد. سرویس باید روی همه آی‌پی‌ها گوش بدهد، نه فقط آی‌پی عمومی.","err"],wg:["WireGuard مناسب است: پایدار و سریع، و ترافیک رمزنگاری می‌شود. «فعال‌سازی» را بزن.","ok"],direct:["در این مسیر مستقیم بهتر جواب می‌دهد (تأخیر یا افت بسته‌ی تانل بیشتر است). اگر رمزنگاری مهم‌تر است می‌توانی تانل را فعال کنی.","warn"]};
$("t_run").onclick=async()=>{const b=$("t_run");b.disabled=true;$("t_res").innerHTML='<div class="empty">در حال تست… (حدود ۲۰ ثانیه)</div>';
 try{const r=await api("tunnel/test","POST",{ip:$("t_ti").value,port:+$("t_tp").value||0});
  const row=(n,x)=>!x?"":`<tr><td>${n}</td><td>${x.ok?'<span class="pill up">پاسخ می‌دهد</span>':'<span class="pill down">بی‌پاسخ</span>'}</td><td class="ltr">${x.ok?x.avg+" ms":"—"}</td><td class="ltr">${x.ok?x.min+" / "+x.max:"—"}</td><td class="ltr">${x.ok?x.jitter+" ms":"—"}</td><td class="ltr">${x.loss}%</td></tr>`;
  const v=TV[r.verdict];
  $("t_res").innerHTML=`<div style="overflow-x:auto"><table><thead><tr><th>مسیر (پورت ${r.port})</th><th>وضعیت</th><th>میانگین</th><th>کمترین / بیشترین</th><th>نوسان</th><th>ازدست‌رفتن</th></tr></thead><tbody>${row("مستقیم (بدون رمزنگاری)",r.direct)}${row("WireGuard (رمزنگاری‌شده)",r.tunnel&&r.tunnel.tcp)}</tbody></table></div>`
  +(r.udp===false?`<div class="hl" style="margin-top:10px"><b class="err">✘</b><div>خروجی UDP از این سرور بسته است — تونل WireGuard روی UDP سوار است و بالا نمی‌آید. اول UDP را روی فایروال/اپراتور باز کن.</div></div>`:"")
  +(r.rec&&r.rec.label!=="unreachable"?`<div class="hl" style="margin-top:10px"><b class="${r.udp===false?"err":"ok"}">${r.udp===false?"✘":"⚡"}</b><div>${esc(r.rec.fa)} ${r.rec.preset?`<button class="btn p" style="margin-inline-start:10px" onclick="applyRec('${r.rec.preset}')">اعمال ${PRFA[r.rec.preset]}</button>`:""}</div></div>`:"")
  +`<div class="hl" style="margin-top:12px"><b class="${v[1]}">${{ok:"✔",warn:"!",err:"✘"}[v[1]]}</b><div>${v[0]}</div></div>`}catch(e){$("t_res").innerHTML="";toast(e.message,"e")}b.disabled=false};
async function applyRec(p){try{await api("perf","POST",{preset:p});toast("اعمال شد: "+PRFA[p],"s");load()}catch(e){toast(e.message,"e")}}
let LGV="s";
$("lgs").onclick=()=>{LGV="s";$("lgs").classList.add("on");$("lga").classList.remove("on");logs()};
$("lga").onclick=()=>{LGV="a";$("lga").classList.add("on");$("lgs").classList.remove("on");logs()};
async function logs(){if(LGV==="a"){try{const r=await api("audit");$("lg").innerHTML=r.a.length?r.a.map(l=>{const p=String(l).split("|");return `<div class="info">[${esc(p[0]||"")}] ${esc(p[2]||"")} · ${esc(p[3]||"")} · ${esc(p[1]||"")}</div>`}).join(""):'<div class="empty">لاگی ثبت نشده</div>'}catch(e){}return}
 try{const r=await api("logs");$("lg").innerHTML=r.length?r.map(l=>`<div class="${l.l}">${new Date(l.t*1000).toLocaleString("sv")} [${l.l}] ${esc(l.m)}</div>`).join(""):'<div class="empty">لاگی ثبت نشده</div>'}catch(e){}}
async function settings(){try{const s=await api("settings");$("g_c").value=s.tg_chat;$("g_a").value=s.tg_api;$("g_t").value="";$("g_t").placeholder=s.has_token?"•••••• (ذخیره شده — برای تغییر وارد کنید)":"123456:ABC…";
 $("g_rh").value=s.rhour;$("g_bh").value=s.bhour;$("g_b").checked=!!s.bot;$("g_rep").checked=s.report!==false;$("g_bk").checked=s.backup!==false;
 $("d_h").textContent=s.domain?"فعال: https://"+s.domain+":"+s.port:(s.tls?"بدون دامنه: گواهی self-signed (مرورگر هشدار می‌دهد)":"HTTPS خاموش است");$("g_h").textContent="اگر سرور ایران به تلگرام دسترسی ندارد، آدرس یک پروکسی/ورکر سازگار با Bot API را در فیلد API بگذارید.";tfUI(s)}catch(e){}}
function tfUI(s){const on=!!s.totp;$("tf_h").innerHTML=on?"✅ فعال است — ورود به پنل علاوه بر رمز، به کد اپ Authenticator یا یکی از کدهای بازیابی نیاز دارد.":"خاموش است. با فعال‌کردن، ورود به پنل علاوه بر رمز به کد ۶ رقمی اپ Authenticator نیاز دارد و ۸ کد بازیابی یک‌بارمصرف می‌گیری.";
 $("tf_setup").style.display="none";$("tf_rc").style.display="none";$("tf_acts").innerHTML=on?'<button class="btn d" id="tf_off">غیرفعال‌سازی</button>':'<button class="btn p" id="tf_st">فعال‌سازی</button>';
 $("tf_acts").onclick=async e=>{const b=e.target.closest("button");if(!b)return;
  if(b.id==="tf_st"){try{const r=await api("totp","POST",{action:"setup"});$("tf_s").value=r.secret+"\n"+r.uri;$("tf_setup").style.display="block";$("tf_c").focus()}catch(x){toast(x.message,"e")}}
  if(b.id==="tf_off"){const p=prompt(TX("رمز را وارد کنید"));if(p==null)return;try{await api("totp","POST",{action:"disable",password:p});toast("2FA خاموش شد","s");load();settings()}catch(x){toast(x.message,"e")}}};
 $("tf_on").onclick=async()=>{try{const r=await api("totp","POST",{action:"enable",code:$("tf_c").value.trim()});$("tf_setup").style.display="none";
  $("tf_rc").innerHTML="<b>کدهای بازیابی (فقط همین یک‌بار نشان داده می‌شوند — جایی ذخیره کن):</b><br>"+r.codes.map(esc).join(" · ");$("tf_rc").style.display="block";toast("2FA فعال شد","s");load()}catch(x){toast(x.message,"e")}};}
$("g_s").onclick=async()=>{try{await api("settings/telegram","POST",{token:$("g_t").value,chat:$("g_c").value,api:$("g_a").value,bot:$("g_b").checked,report:$("g_rep").checked,backup:$("g_bk").checked,report_hour:+$("g_rh").value||0,backup_hour:+$("g_bh").value||0});toast("ذخیره شد","s");settings()}catch(e){toast(e.message,"e")}};
$("g_x").onclick=async()=>{try{await api("settings/tgtest","POST",{});toast("پیام تست ارسال شد","s")}catch(e){toast("ارسال ناموفق: "+e.message,"e")}};
$("w_s").onclick=async()=>{try{await api("settings/password","POST",{old:$("w_o").value,new:$("w_n").value});$("w_o").value=$("w_n").value="";toast("رمز تغییر کرد","s")}catch(e){toast(e.message,"e")}};
$("k_d").onclick=async()=>{try{const r=await fetch("/api/backup");if(!r.ok)throw new Error("خطا");const a=document.createElement("a");a.href=URL.createObjectURL(await r.blob());a.download="seka-tunel-backup.tar.gz";a.click()}catch(e){toast(e.message,"e")}};
$("k_r").onclick=()=>$("k_f").click();
$("k_f").onchange=async e=>{const f=e.target.files[0];if(!f)return;if(!cf("لیست تانل‌ها با محتوای این بکاپ جایگزین شود؟"))return;
 const buf=new Uint8Array(await f.arrayBuffer());let s="";for(let i=0;i<buf.length;i+=8192)s+=String.fromCharCode.apply(null,buf.subarray(i,i+8192));
 try{await api("restore","POST",{data:btoa(s)});toast("بازیابی شد","s");load()}catch(x){toast(x.message,"e")}e.target.value=""};
$("pf_b").onclick=async e=>{const b=e.target.closest("[data-pf]");if(!b)return;if(!cf("این پریست sysctl سرور را بازنویسی می‌کند. اعمال شود؟"))return;try{await api("perf","POST",{preset:b.dataset.pf});toast("اعمال شد: "+b.dataset.pf,"s");load()}catch(x){toast(x.message,"e")}};
$("t_bw").onclick=async()=>{const b=$("t_bw");b.disabled=true;$("t_res").innerHTML='<div class="empty">در حال اندازه‌گیری… (حدود ۷ ثانیه)</div>';
 try{const r=await api("tunnel/bw","POST",{ip:$("t_ti").value});
  $("t_res").innerHTML=`<div style="overflow-x:auto"><table><thead><tr><th>پهنای باند تانل (${esc($("t_ti").value)})</th><th>نرخ</th><th>نوسان</th><th>ازدست‌رفتن</th><th>MTU</th></tr></thead><tbody><tr><td><span class="pill up">اندازه‌گیری شد</span></td><td class="ltr">${r.mbps} Mbps</td><td class="ltr">${r.jitter} ms</td><td class="ltr">${r.loss}%</td><td class="ltr">${r.mtu||"—"}</td></tr></tbody></table></div><div class="hint" style="margin-top:8px">UDP بدون سقف به‌مدت ۵ ثانیه از داخل تانل WireGuard. اگر خطا گرفتی، اسکریپت سمت سرور خارج را دوباره اجرا کن (سرویس iperf3 را نصب می‌کند).</div>`}catch(e){$("t_res").innerHTML="";toast(e.message,"e")}b.disabled=false};
$("k_p").onclick=async()=>{try{const r=await fetch("/api/package");if(!r.ok)throw new Error("خطا");const a=document.createElement("a");a.href=URL.createObjectURL(await r.blob());a.download="seka-tunel-offline.tar.gz";a.click();toast("پکیج آفلاین دانلود شد","s")}catch(e){toast(e.message,"e")}};
let TF=false;
async function login(){if($("tfa").classList.contains("hide")){if(!$("pw").value){toast("رمز را وارد کنید","e");return}}else if(!$("to").value){toast("کد را وارد کنید","e");return} try{const r=await api("login","POST",{password:$("pw").value,code:$("to").value});
  if(r.totp){$("tfa").classList.remove("hide");$("to").focus();toast("کد دومرحله‌ای را وارد کنید","");return}
  $("pw").value="";$("to").value="";$("tfa").classList.add("hide");bootStart(1,1500);show(true)}catch(e){toast(e.message,"e")}}
$("login").addEventListener("click",e=>{if(!e.target.closest("button,a,input"))$("pw").focus()});
document.addEventListener("keydown",e=>{if($("login").classList.contains("hide")||e.ctrlKey||e.metaKey||e.altKey||e.key.length!==1)return;const a=document.activeElement;if(a&&(a.id==="pw"||a.id==="to"))return;($("tfa").classList.contains("hide")?$("pw"):$("to")).focus()});
$("lb").onclick=login;$("pw").addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();login()}});
$("to").addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();login()}});
$("eye").onclick=()=>{const p=$("pw");p.type=p.type==="password"?"text":"password";p.focus()};
$("out").onclick=async()=>{await api("logout","POST",{}).catch(()=>{});show(false)};

document.body.dataset.t=localStorage.getItem("drt")||"dark";
function syncThemeColor(){const m=document.querySelector('meta[name="theme-color"]');if(m)m.content=document.body.dataset.t==="dark"?"#07060f":"#f3f2fa"}
$("thm").onclick=()=>{const t=document.body.dataset.t==="dark"?"light":"dark";document.body.dataset.t=t;localStorage.setItem("drt",t);syncThemeColor()};
const GB=1024**3,TB=1024**4;let QR=null,QW=0,SR=null;
function qopen(i){QR=window.LAST.rules[i];QW=QR.limit||0;$("q_t").textContent="حجم تانل — "+QR.name;$("qm").classList.add("on");qdraw()}
function qdraw(){const r=QR,u=r.bytes,w=QW,p=w?Math.min(1,u/w):0,col=!w?"var(--mu)":p>=.9?"var(--er)":p>=.7?"var(--wa)":"var(--ok)";
 $("q_b").innerHTML=`<div class="qh"><div class="ringw"><svg viewBox="0 0 120 120"><circle class="trk" cx="60" cy="60" r="52"/><circle class="arc" cx="60" cy="60" r="52" pathLength="1000" stroke="${col}" style="filter:drop-shadow(0 0 5px color-mix(in srgb,${col} 55%,transparent))" stroke-dasharray="${Math.round(p*1000)} 1000"/></svg><div class="mid">${w?Math.round(p*100)+"%":"∞"}</div></div>
 <div class="qn"><div><span>مصرف</span><b>${hb(u)}</b></div><div><span>سقف</span><b>${w?hb(w):"نامحدود"}</b></div><div><span>باقی‌مانده</span><b>${w?hb(Math.max(0,w-u)):"—"}</b></div></div></div>
 ${r.blocked?'<div class="qs er">حجم تمام شده و تانل قطع است. با بالا بردن سقف یا ریست مصرف، خودکار وصل می‌شود.</div>':""}
 <div class="pre">${[[0,"نامحدود"],[50*GB,"50 GB"],[100*GB,"100 GB"],[500*GB,"500 GB"],[TB,"1 TB"],[2*TB,"2 TB"]].map(([v,l])=>`<button class="btn${v===w?" on":""}" data-v="${v}">${l}</button>`).join("")}</div>
 <div class="row" style="margin-top:10px"><input id="q_n" type="number" min="0" step="any" placeholder="مقدار دلخواه"><select id="q_u"><option value="${GB}">GB</option><option value="${TB}">TB</option></select></div>
 <div class="row" style="margin-top:10px"><div><label>ریست دوره‌ای مصرف</label><select id="q_p"><option value="">خاموش</option><option value="daily"${r.period==="daily"?" selected":""}>روزانه</option><option value="weekly"${r.period==="weekly"?" selected":""}>هفتگی</option><option value="monthly"${r.period==="monthly"?" selected":""}>ماهانه</option></select></div><div><label>تاریخ انقضا (اختیاری)</label><input id="q_e" type="date" value="${r.expires||""}"></div></div>
 ${r.reset_at?`<div class="hint" style="margin-top:8px">ریست بعدی مصرف: ${new Date(r.reset_at*1000).toLocaleString("sv")}</div>`:""}
 <div class="pre" style="margin-top:10px"><span class="hint" style="align-self:center;margin:0">افزودن به سقف:</span>${[10*GB,100*GB,TB].map(a=>`<button class="btn" data-a="${a}">+ ${hb(a)}</button>`).join("")}</div>`;
 $("q_ok").disabled=w===(r.limit||0);$("q_r").disabled=!r.bytes}
$("q_b").onclick=e=>{const b=e.target.closest("button");if(!b)return;if(b.dataset.v!==undefined)QW=+b.dataset.v;else if(b.dataset.a)QW=(QW||QR.bytes||0)+ +b.dataset.a;else return;qdraw()};
$("q_b").oninput=e=>{if(e.target.id==="q_n"||e.target.id==="q_u"){const n=+$("q_n").value;if(n>0){QW=Math.round(n*+$("q_u").value);$("q_ok").disabled=QW===(QR.limit||0)}}};
$("q_b").onchange=e=>{if(e.target.id==="q_n")qdraw()};
$("q_x").onclick=()=>$("qm").classList.remove("on");
$("q_ok").onclick=async()=>{try{await api("quota","POST",{lport:QR.lport,limit:QW,period:$("q_p").value||null,expires:$("q_e").value||null});toast(QW?"سقف حجم ذخیره شد":"سقف حجم برداشته شد","s");$("qm").classList.remove("on");load()}catch(e){toast(e.message,"e")}};
$("q_r").onclick=async()=>{if(!cf("مصرف این تانل صفر شود؟"))return;try{await api("quota","POST",{lport:QR.lport,reset:true});toast("مصرف صفر شد","s");$("qm").classList.remove("on");load()}catch(e){toast(e.message,"e")}};
let CRS=[];
function secopen(i,ip){CRS=ip?window.LAST.rules.filter(r=>r.ip===ip):[window.LAST.rules[i]];const s=CRS[0].sec||{};$("c_t").textContent="امنیت تانل — "+(ip?ip+" ("+CRS.length+" پورت)":CRS[0].name);$("c_a").value=(s.allow||"").split(",").filter(Boolean).join("\n");$("c_m").value=s.maxc||0;$("c_r").value=s.rate||0;$("c_w").style.display=s.allow?"block":"none";$("cm").classList.add("on")}
$("c_a").oninput=()=>{$("c_w").style.display=$("c_a").value.trim()?"block":"none"};
$("c_x").onclick=()=>$("cm").classList.remove("on");
$("c_ok").onclick=async()=>{const a=$("c_a").value.split(/[\s,]+/).filter(Boolean);try{await api("security","POST",{lports:CRS.map(r=>r.lport),allow:a,maxc:+$("c_m").value||0,rate:+$("c_r").value||0});toast("امنیت تانل ذخیره شد","s");$("cm").classList.remove("on");load()}catch(e){toast(e.message,"e")}};
async function sopen(i){SR=window.LAST.rules[i];$("s_t").textContent="لینک کاربر — "+SR.name;$("sm").classList.add("on");sdraw(await api("sub?lport="+SR.lport))}
function sdraw(j){$("s_b").innerHTML=j.token?`<input id="s_u" readonly value="${esc(location.origin+j.path)}"><div class="acts"><button class="btn p" data-s="copy">کپی لینک</button><button class="btn" data-s="rotate">لینک جدید</button><button class="btn d" data-s="delete">حذف لینک</button></div>`:`<div class="acts" style="margin:0"><button class="btn p" data-s="create">ساخت لینک</button></div>`}
$("s_b").onclick=async e=>{const b=e.target.closest("button");if(!b)return;const a=b.dataset.s;try{
 if(a==="copy"){const el=$("s_u");try{await navigator.clipboard.writeText(el.value)}catch(x){el.select();document.execCommand("copy")}toast("کپی شد","s");return}
 if(a==="rotate"&&!cf("لینک قبلی از کار می‌افتد. ادامه؟"))return;if(a==="delete"&&!cf("لینک حذف شود؟"))return;
 sdraw(await api("sub","POST",{lport:SR.lport,action:a}));load()}catch(x){toast(x.message,"e")}};
$("s_x").onclick=()=>$("sm").classList.remove("on");
$("d_s").onclick=async()=>{const d=$("d_d").value.trim();if(!d)return toast("دامنه را وارد کنید","e");if(!cf("گواهی گرفته می‌شود و پنل ری‌استارت می‌شود. ادامه؟"))return;
 $("d_s").disabled=true;toast("در حال دریافت گواهی؛ تا دو دقیقه صبر کنید…");try{await api("domain","POST",{domain:d,email:$("d_e").value});toast("فعال شد؛ در حال انتقال به دامنه…","s");setTimeout(()=>location.href="https://"+d+":"+(location.port||443)+"/",4500)}catch(e){toast(e.message,"e")}$("d_s").disabled=false};
$("d_r").onclick=async()=>{if(!cf("دامنه حذف شود و گواهی self-signed برگردد؟"))return;try{await api("domain","POST",{remove:true});toast("انجام شد؛ پنل ری‌استارت می‌شود","s");setTimeout(()=>location.reload(),4500)}catch(e){toast(e.message,"e")}};
$("c_s").onclick=async()=>{try{await api("cert","POST",{cert:$("c_c").value,key:$("c_k").value});toast("گواهی نصب شد؛ پنل ری‌استارت می‌شود","s");setTimeout(()=>location.reload(),4500)}catch(e){toast(e.message,"e")}};
document.querySelectorAll(".lng").forEach(b=>b.onclick=()=>setLang(LANG==="en"?"fa":"en"));document.querySelectorAll("[data-l]").forEach(b=>b.onclick=()=>setLang(b.dataset.l));
$("sws").onclick=e=>{const b=e.target.closest(".sw[data-c]");if(b)setAc(b.dataset.c)};$("sws").oninput=e=>{if(e.target.id==="ac_c")setAc(e.target.value)};
document.addEventListener("click",e=>{const m=e.target.closest(".modal");if(m&&e.target===m)m.classList.remove("on")});
setAc(ACC);setLang(LANG);syncThemeColor();bootStart(0,900);
api("state").then(()=>{bootGo(1);show(true)}).catch(()=>show(false));
</script></body></html>
HTMLEOF
}

web_pubip() {   # public IPv4 of this server (validated, so error pages never leak into the URL)
  local re='^[0-9]{1,3}(\.[0-9]{1,3}){3}$' ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  if ! [[ $ip =~ $re ]] || [[ $ip =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
    ip=$(curl -s4 --max-time 4 https://api.ipify.org 2>/dev/null)
  fi
  [[ $ip =~ $re ]] || ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "$ip"
}

web_info() {
  [[ -f $WEB_PY ]] || { err "Web panel is not installed."; return; }
  local port scheme dom host; read -r port scheme dom < <(python3 "$WEB_PY" info)
  host=$(web_pubip); [[ ${dom:--} != "-" ]] && host=$dom
  ok "URL: ${scheme}://${host}:${port}"
  info "Service: $(systemctl is-active seka-tunel-web 2>/dev/null)"
  command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active" && warn "ufw is active: ufw allow ${port}/tcp"
}

web_install() {
  banner; echo "  ${C_BLD}Install / update web panel${C_RST}"; echo
  command -v python3 >/dev/null 2>&1 || {
    warn "python3 not found, installing..."
    if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq python3
    elif command -v dnf >/dev/null 2>&1; then dnf install -y python3
    elif command -v yum >/dev/null 2>&1; then yum install -y python3; fi
  }
  command -v python3 >/dev/null 2>&1 || { err "python3 is required."; return; }
  ensure_boot
  local fresh=0 port pw; [[ -f $WEB_CFG ]] || fresh=1
  web_write_files
  if (( fresh )); then
    read -rp "  Web panel port [8443]: " port; port=${port:-8443}
    valid_port "$port" || { err "Invalid port."; return; }
    pw=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 14)
    read -rp "  Admin password [$pw]: " p2; pw=${p2:-$pw}
    python3 "$WEB_PY" setport "$port"; python3 "$WEB_PY" setpass "$pw"
    if command -v openssl >/dev/null 2>&1 && \
       openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=seka-tunel" \
         -keyout "$CONF_DIR/web.key" -out "$CONF_DIR/web.crt" >/dev/null 2>&1; then
      chmod 600 "$CONF_DIR/web.key"; python3 "$WEB_PY" settls 1
      info "HTTPS enabled (self-signed certificate: the browser will warn once)."
    else
      warn "openssl not found: panel runs on plain HTTP."
    fi
  fi
  cat > "$WEB_UNIT" <<EOF
[Unit]
Description=SEKA TUNEL web panel
After=network-online.target

[Service]
ExecStart=/usr/bin/env python3 $WEB_PY serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable seka-tunel-web.service >/dev/null 2>&1
  systemctl restart seka-tunel-web.service
  sleep 1
  if systemctl is-active --quiet seka-tunel-web.service; then
    ok "Web panel is running."; web_info
    (( fresh )) && ok "Password: $pw  (change it from this menu any time)"
  else
    err "Service failed to start: journalctl -u seka-tunel-web -n 20"
  fi
}

web_passwd() {
  [[ -f $WEB_PY ]] || { err "Web panel is not installed."; return; }
  local pw; info "Paste with right-click or Shift+Insert (Ctrl+C would cancel the script)."
  read -rp "  New password (min 8 chars): " pw
  (( ${#pw} >= 8 )) || { err "Too short."; return; }
  python3 "$WEB_PY" setpass "$pw" && systemctl restart seka-tunel-web && ok "Password changed."
}

web_port() {
  [[ -f $WEB_PY ]] || { err "Web panel is not installed."; return; }
  local port; read -rp "  New port: " port
  valid_port "$port" || { err "Invalid port."; return; }
  python3 "$WEB_PY" setport "$port" && systemctl restart seka-tunel-web && ok "Port changed." && web_info
}

web_remove() {
  systemctl disable --now seka-tunel-web.service >/dev/null 2>&1
  rm -f "$WEB_UNIT"; systemctl daemon-reload >/dev/null 2>&1
  rm -rf "$WEB_DIR" "$WEB_CFG" "$CONF_DIR/web.crt" "$CONF_DIR/web.key"
  ok "Web panel removed."
}

web_domain() {
  [[ -f $WEB_PY ]] || { err "Web panel is not installed."; return; }
  local d e; read -rp "  Domain (its A record must point to this server): " d; [[ -n $d ]] || return
  read -rp "  Email for Let's Encrypt (optional): " e
  info "Requesting a certificate (port 80 must be free)..."
  if python3 "$WEB_PY" setdomain "$d" "$e"; then systemctl restart seka-tunel-web; ok "Domain set."; web_info; else err "Failed."; fi
}

web_menu() {
  banner; echo "  ${C_BLD}Web panel${C_RST}"; echo
  if [[ -f $WEB_UNIT ]]; then info "Status: $(systemctl is-active seka-tunel-web 2>/dev/null)"; else info "Status: not installed"; fi
  echo
  echo "   1) Install / update"
  echo "   2) Show access info"
  echo "   3) Change password"
  echo "   4) Change port"
  echo "   5) Restart"
  echo "   6) Remove web panel"
  echo "   7) Domain + HTTPS (Let's Encrypt)"
  echo "   0) Back"; echo
  local c; read -rp "  Select: " c; echo
  case $c in
    1) web_install;;
    2) web_info;;
    3) web_passwd;;
    4) web_port;;
    5) systemctl restart seka-tunel-web && ok "Restarted.";;
    6) confirm "Remove the web panel?" && web_remove;;
    7) web_domain;;
  esac
}

# ---------------------------------------------------------- operations ----

list_rules() {
  if [[ ! -s $CONF ]]; then info "No forwards configured yet."; return 0; fi
  printf "  ${C_BLD}%-3s %-16s %-5s %-7s %-23s %-9s %s${C_RST}\n" "#" NAME PROTO LISTEN DESTINATION PACKETS TRAFFIC
  local i=0 name proto lport ip dport pk by
  while IFS='|' read -r name proto lport ip dport; do
    [[ -z $name ]] && continue
    i=$((i+1))
    read -r pk by < <(counters "$proto" "$lport")
    printf "  %-3s %-16s %-5s %-7s %-23s %-9s %s\n" "$i" "$name" "$proto" "$lport" "$ip:$dport" "$pk" "$(hb "$by")"
  done < "$CONF"
}

add_forward() {
  banner; echo "  ${C_BLD}Add forward${C_RST}"; echo
  local lport proto name ip dport defip=""
  read -rp "  Listen port on this server: " lport
  valid_port "$lport" || { err "Invalid port."; return; }
  if ss -ltnH "sport = :$lport" 2>/dev/null | grep -q .; then
    warn "A local service already listens on TCP $lport (SSH?). Forwarding would take the port over."
    confirm "Continue anyway?" || return
  fi
  read -rp "  Protocol tcp/udp/both [tcp]: " proto; proto=${proto:-tcp}
  [[ $proto =~ ^(tcp|udp|both)$ ]] || { err "Invalid protocol."; return; }
  if awk -F'|' -v p="$lport" -v pr="$proto" '$3==p && ($2==pr||$2=="both"||pr=="both"){f=1} END{exit !f}' "$CONF" 2>/dev/null; then
    err "A forward on port $lport already exists."; return
  fi
  [[ -f $DEF_IP_FILE ]] && defip=$(<"$DEF_IP_FILE")
  read -rp "  Foreign server IP${defip:+ [$defip]}: " ip; ip=${ip:-$defip}
  valid_ip "$ip" || { err "Invalid IP."; return; }
  read -rp "  Foreign port [$lport]: " dport; dport=${dport:-$lport}
  valid_port "$dport" || { err "Invalid port."; return; }
  read -rp "  Name [fw$lport]: " name; name=${name:-fw$lport}
  name=${name//[^A-Za-z0-9_.-]/_}

  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  echo "$name|$proto|$lport|$ip|$dport" >> "$CONF"
  echo "$ip" > "$DEF_IP_FILE"
  apply_rules; ensure_boot
  echo; ok "Forward added: :$lport -> $ip:$dport ($proto), saved for reboot."
  if [[ $proto != udp ]]; then
    local t; t=$(tcp_time "$ip" "$dport")
    if [[ $t == fail ]]; then
      err "Foreign node did not answer on $dport (refused/timeout). Check the inbound exists and its firewall."
    else
      ok "Foreign node answers on $dport (${t} ms)."
    fi
  fi
  info "In the client config set the address to this server's IP; keep port/UUID/SNI/keys unchanged."
}

remove_forward() {
  banner; echo "  ${C_BLD}Remove forward${C_RST}"; echo
  [[ -s $CONF ]] || { info "Nothing to remove."; return; }
  list_rules; echo
  local n; read -rp "  Number to remove: " n
  [[ $n =~ ^[0-9]+$ ]] && (( n >= 1 && n <= $(wc -l < "$CONF") )) || { err "Invalid number."; return; }
  sed -i "${n}d" "$CONF"
  apply_rules
  ok "Removed."
}

test_forwards() {
  banner; echo "  ${C_BLD}Connection test${C_RST}"; echo
  [[ -s $CONF ]] || { info "No forwards configured."; return; }
  local name proto lport ip dport t out avg loss seen=" "
  while IFS='|' read -r name proto lport ip dport; do
    [[ -z $name ]] && continue
    echo "  ${C_BLD}$name${C_RST}  :$lport -> $ip:$dport ($proto)"
    if [[ $proto != udp ]]; then
      t=$(tcp_time "$ip" "$dport")
      if [[ $t == fail ]]; then err "  TCP connect FAILED"; else ok "  TCP connect ${t} ms"; fi
    else
      info "  UDP cannot be probed"
    fi
    if [[ $seen != *" $ip "* ]]; then
      seen="$seen$ip "
      out=$(ping -c 5 -W 2 -q "$ip" 2>/dev/null </dev/null)
      avg=$(awk -F'/' '/^rtt|^round-trip/{print $5}' <<<"$out")
      loss=$(grep -oE '[0-9.]+%' <<<"$out" | head -1)
      if [[ -n $avg ]]; then ok "  Ping avg ${avg} ms, loss ${loss:-?}"; else warn "  Ping: no reply (ICMP may be blocked)"; fi
    fi
  done < "$CONF"
}

perf_apply() {   # name : write one sysctl file for the preset and apply it
  local name=$1
  case $name in balanced|turbo|throughput|gaming) ;; *) echo "error: unknown preset '$name'" >&2; return 1;; esac
  modprobe tcp_bbr 2>/dev/null || true
  modprobe nf_conntrack 2>/dev/null || true
  local bbr=""
  grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null && bbr=1
  {
    echo "# SEKA TUNEL performance preset: $name (applied $(date '+%F %T'))"
    echo "net.ipv4.ip_forward=1"
    [[ -n $bbr ]] && { echo "net.core.default_qdisc=fq"; echo "net.ipv4.tcp_congestion_control=bbr"; }
    echo "net.ipv4.tcp_fastopen=3"
    echo "net.ipv4.tcp_mtu_probing=1"
    echo "net.netfilter.nf_conntrack_tcp_timeout_time_wait=30"
    case $name in
      balanced)
        echo "net.core.rmem_max=16777216";      echo "net.core.wmem_max=16777216"
        echo "net.ipv4.tcp_rmem=4096 87380 16777216"; echo "net.ipv4.tcp_wmem=4096 65536 16777216"
        echo "net.netfilter.nf_conntrack_max=262144"
        echo "net.netfilter.nf_conntrack_tcp_timeout_established=7200";;
      turbo)
        echo "net.core.rmem_max=33554432";      echo "net.core.wmem_max=33554432"
        echo "net.core.netdev_max_backlog=16384"; echo "net.core.somaxconn=8192"
        echo "net.ipv4.tcp_rmem=4096 87380 33554432"; echo "net.ipv4.tcp_wmem=4096 65536 33554432"
        echo "net.ipv4.tcp_max_syn_backlog=8192"; echo "net.ipv4.tcp_notsent_lowat=131072"
        echo "net.netfilter.nf_conntrack_max=524288"
        echo "net.netfilter.nf_conntrack_tcp_timeout_established=7200";;
      throughput)
        echo "net.core.rmem_max=67108864";      echo "net.core.wmem_max=33554432"
        echo "net.core.netdev_max_backlog=32768"; echo "net.core.somaxconn=16384"
        echo "net.ipv4.tcp_rmem=4096 87380 67108864"; echo "net.ipv4.tcp_wmem=4096 65536 33554432"
        echo "net.ipv4.tcp_max_syn_backlog=16384"; echo "net.ipv4.tcp_notsent_lowat=262144"
        echo "net.ipv4.tcp_slow_start_after_idle=0"
        echo "net.netfilter.nf_conntrack_max=1048576"
        echo "net.netfilter.nf_conntrack_tcp_timeout_established=86400";;
      gaming)
        echo "net.core.rmem_max=8388608";       echo "net.core.wmem_max=8388608"
        echo "net.ipv4.tcp_rmem=4096 87380 8388608";  echo "net.ipv4.tcp_wmem=4096 65536 8388608"
        echo "net.ipv4.tcp_notsent_lowat=16384"
        echo "net.ipv4.tcp_slow_start_after_idle=0"
        echo "net.ipv4.tcp_fin_timeout=15"; echo "net.ipv4.tcp_keepalive_time=300"
        echo "net.core.busy_poll=50"; echo "net.core.busy_read=50"
        echo "net.netfilter.nf_conntrack_max=262144"
        echo "net.netfilter.nf_conntrack_tcp_timeout_established=3600";;
    esac
  } > "$SYSCTL_OPT"
  sysctl -q -p "$SYSCTL_OPT" >/dev/null 2>&1
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  echo "$name" > "$PERF_STATE"
}

perf_current() {
  local n=""; [[ -s $PERF_STATE ]] && n=$(<"$PERF_STATE")
  [[ $n =~ ^(balanced|turbo|throughput|gaming)$ ]] || { [[ -s $SYSCTL_OPT ]] && n=custom || n=default; }
  echo "$n"
}

perf_menu() {
  banner; echo "  ${C_BLD}Performance presets${C_RST}"; echo
  local cur ct=0 cm=0
  cur=$(perf_current)
  ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
  cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
  info "Active preset: ${C_BLD}${cur}${C_RST} · congestion control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
  info "Conntrack: $ct / $cm"
  echo
  echo "   1) Balanced    default: BBR + 16 MB buffers + conntrack 256k"
  echo "   2) Turbo       BBR + 32 MB buffers + bigger backlogs + conntrack 512k"
  echo "   3) Throughput  BBR + 64 MB buffers, max windows, conntrack 1M (many users / heavy traffic)"
  echo "   4) Gaming      lowest latency: small buffers, busy-poll, short timeouts"
  echo "   0) Back"; echo
  local c; read -rp "  Select: " c
  case $c in
    1) perf_apply balanced && ok "Balanced preset applied.";;
    2) perf_apply turbo && ok "Turbo preset applied.";;
    3) perf_apply throughput && ok "Throughput preset applied.";;
    4) perf_apply gaming && ok "Gaming preset applied.";;
  esac
}

backup_restore() {
  banner; echo "  ${C_BLD}Backup & Restore${C_RST}"; echo
  echo "   1) Backup settings"
  echo "   2) Restore from file"
  echo "   3) Build offline package  (for servers without GitHub access)"
  echo "   0) Back"; echo
  local c f; read -rp "  Select: " c
  case $c in
    1) [[ -d $CONF_DIR ]] || { err "Nothing to back up."; return; }
       f="/root/seka-tunel-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
       tar czf "$f" -C / "${CONF_DIR#/}" && ok "Saved: $f";;
    2) read -rp "  Backup file path: " f
       [[ -f $f ]] || { err "File not found."; return; }
       tar xzf "$f" -C / "${CONF_DIR#/}" && apply_rules && ensure_boot && ok "Restored and applied.";;
    3) pkg_make;;
  esac
}

pkg_make() {   # build a self-contained offline package with SHA256 checksums (for servers that cannot reach GitHub)
  local self dir out
  self=$(readlink -f "$0" 2>/dev/null || echo "$0")
  [[ -s $self ]] || { err "Cannot find this script."; return 1; }
  dir=$(mktemp -d) || return 1
  cp "$self" "$dir/seka-tunel.sh"
  if gost_have; then cp /usr/local/bin/seka-gost "$dir/seka-gost"; fi   # bundle the transport carrier for carried tunnels
  cat > "$dir/install.sh" <<'OFEOF'
#!/usr/bin/env bash
# SEKA TUNEL offline installer — no internet needed
set -e
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
sha256sum -c SHA256SUMS >/dev/null 2>&1 || { echo "checksum FAILED — package is broken, do not use it"; exit 1; }
echo "checksum OK"
install -m 755 seka-tunel.sh /usr/local/bin/seka-tunel
[[ -f seka-gost ]] && { install -m 755 seka-gost /usr/local/bin/seka-gost; echo "transport carrier (gost) installed"; }
echo "installed. open the menu with:  seka-tunel"
exec /usr/local/bin/seka-tunel
OFEOF
  ( cd "$dir" && sha256sum seka-tunel.sh install.sh seka-gost 2>/dev/null > SHA256SUMS || sha256sum seka-tunel.sh install.sh > SHA256SUMS )
  out="/root/seka-tunel-$VERSION-offline.tar.gz"
  tar czf "$out" -C "$dir" . && rm -rf "$dir" || { rm -rf "$dir"; err "Could not create the package."; return 1; }
  ok "Offline package: $out"
  info "Move it to the server (scp/USB), extract, then: bash install.sh"
  sha256sum "$out"
}

do_rollback() {   # restore the version saved by the last update
  [[ -f $BIN.bak ]] || { err "No previous version saved (a .bak copy is kept on every update)."; return 1; }
  install -m 755 "$BIN.bak" "$BIN"
  command -v systemctl >/dev/null 2>&1 && { systemctl restart seka-tunel-web 2>/dev/null; systemctl restart seka-tunel 2>/dev/null; }
  ok "Rolled back to the previous version: $(grep -m1 'SEKA_VERSION="1.5.1"
}

import_legacy() {
  banner; echo "  ${C_BLD}Import manual iptables rules${C_RST}"; echo
  local re='-p ([a-z]+) .*--dport ([0-9]+) .*--to-destination ([0-9.]+):([0-9]+)'
  local line n=0 proto lport ip dport
  while IFS= read -r line; do
    [[ $line == *"-j DNAT"* && $line =~ $re ]] || continue
    proto=${BASH_REMATCH[1]}; lport=${BASH_REMATCH[2]}; ip=${BASH_REMATCH[3]}; dport=${BASH_REMATCH[4]}
    mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
    grep -qF "|$proto|$lport|$ip|$dport" "$CONF" 2>/dev/null || echo "imported-$lport|$proto|$lport|$ip|$dport" >> "$CONF"
    iptables -t nat ${line/#-A/-D}
    # matching manual MASQUERADE rule
    while IFS= read -r m; do
      [[ $m == *"-j MASQUERADE"* && $m == *"-d $ip/32"* && $m == *"--dport $dport "* ]] && iptables -t nat ${m/#-A/-D}
    done < <(iptables -t nat -S POSTROUTING 2>/dev/null)
    n=$((n+1)); ok "Imported :$lport -> $ip:$dport ($proto)"
  done < <(iptables -t nat -S PREROUTING 2>/dev/null)
  if (( n == 0 )); then info "No manual DNAT rules found."; return; fi
  apply_rules; ensure_boot
  ok "$n rule(s) now managed by the panel."
}

status() {
  banner; echo "  ${C_BLD}Status${C_RST}"; echo
  [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] && ok "IP forwarding: on" || err "IP forwarding: off"
  info "Congestion control: $(sysctl -n net.ipv4.tcp_congestion_control)"
  if command -v systemctl >/dev/null 2>&1; then
    info "Boot service: $(systemctl is-enabled seka-tunel.service 2>/dev/null || echo not-installed)"
    info "Web panel: $(systemctl is-active seka-tunel-web.service 2>/dev/null || echo not-installed)"
  fi
  local legacy; legacy=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -c -- '-j DNAT')
  (( legacy > 0 )) && warn "$legacy manual DNAT rule(s) outside the panel (use 'Import manual rules')."
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    warn "ufw is active: allow each listen port (ufw allow <port>/tcp)."
  fi
  echo; list_rules
}

uninstall() {
  banner; echo "  ${C_BLD}حذف کامل SEKA TUNEL${C_RST}"; echo
  warn "این کار همه تانل‌ها، قوانین، سرویس‌ها، UI و پوشه‌ها را پاک می‌کند."
  confirm "ادامه حذف کامل؟" || return

  # stop web + ui
  web_remove >/dev/null 2>&1
  pkill -f 'seka-tunel/web/api_server.py' 2>/dev/null || true
  pkill -f 'api_server.py' 2>/dev/null || true

  # delete tunnels / wg interfaces
  local fip id
  if [[ -s ${TUN:-/etc/seka-tunel/tunnels.conf} ]]; then
    while IFS='|' read -r id fip _; do
      [[ -z $id ]] && continue
      tun_del "$fip" >/dev/null 2>&1 || true
      wg-quick down "sekawg$id" >/dev/null 2>&1 || true
      systemctl disable --now "wg-quick@sekawg$id" >/dev/null 2>&1 || true
      rm -f "/etc/wireguard/sekawg$id.conf" 2>/dev/null || true
      systemctl disable --now "seka-gost$id" "seka-gostc$id" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/seka-gost${id}.service" "/etc/systemd/system/seka-gostc${id}.service" 2>/dev/null || true
    done < "$TUN"
  fi

  # iptables chains
  local spec t parent chain
  for spec in "mangle PREROUTING SEKA_SEC" "mangle FORWARD SEKA_MSS" "nat PREROUTING SEKA_PRE" "nat POSTROUTING SEKA_POST" "filter FORWARD SEKA_FWD" "nat POSTROUTING SEKA_REVPOST" "filter FORWARD SEKA_REVFWD"; do
    set -- $spec; t=$1; parent=$2; chain=$3
    iptables -t "$t" -D "$parent" -j "$chain" 2>/dev/null || true
    iptables -t "$t" -F "$chain" 2>/dev/null || true
    [[ $chain == SEKA_SEC ]] && sec_cleanup 2>/dev/null || true
    iptables -t "$t" -X "$chain" 2>/dev/null || true
  done

  # systemd units
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now seka-tunel.service seka-tunel-web.service seka-ui.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/seka-tunel.service \
          /etc/systemd/system/seka-tunel-web.service \
          /etc/systemd/system/seka-ui.service \
          ${UNIT:-/etc/systemd/system/seka-tunel.service} 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  # binaries & libs & web
  rm -f /usr/local/bin/seka-tunel /usr/local/bin/seka /usr/local/bin/dr-cpanel 2>/dev/null || true
  rm -f /usr/local/bin/seka-gost /usr/local/bin/drc-gost 2>/dev/null || true
  rm -rf /usr/local/lib/seka-tunel /usr/local/share/seka-tunel 2>/dev/null || true

  # configs & data & logs
  rm -rf /etc/seka-tunel /var/lib/seka-tunel /var/log/seka-tunel* 2>/dev/null || true
  rm -f /etc/sysctl.d/99-seka-tunel-forward.conf /etc/sysctl.d/99-seka-tunel-optimize.conf 2>/dev/null || true
  rm -f /var/log/seka-tunel-audit.log 2>/dev/null || true

  # leftover wireguard names
  for f in /etc/wireguard/sekawg*.conf /etc/wireguard/drwg*.conf; do
    [[ -e $f ]] || continue
    iface=$(basename "$f" .conf)
    wg-quick down "$iface" >/dev/null 2>&1 || true
    rm -f "$f"
  done

  ok "SEKA TUNEL به‌طور کامل از سرور حذف شد."
  exit 0
}

security_menu() {
  banner; echo "  ${C_BLD}Tunnel security${C_RST}"; echo
  [[ -s $CONF ]] || { info "No forwards configured yet."; return; }
  printf "  ${C_BLD}%-3s %-16s %-7s %-10s %-9s %s${C_RST}\n" "#" NAME LISTEN "ALLOWED" "MAX/IP" "NEW/MIN"
  local i=0 name proto lport ip dport al
  while IFS='|' read -r name proto lport ip dport; do
    [[ -z $name ]] && continue
    i=$((i+1)); sec_get "$lport"
    al=any; [[ -n $SEC_ALLOW ]] && al="$(tr ',' '\n' <<< "$SEC_ALLOW" | grep -c .) IPs"
    printf "  %-3s %-16s %-7s %-10s %-9s %s\n" "$i" "$name" "$lport" "$al" "$((SEC_MAXC))" "$((SEC_RATE))"
  done < "$CONF"
  echo; info "0 = off.  Allowed IPs empty = anyone can connect."
  local n; read -rp "  Tunnel number to edit (Enter = back): " n
  [[ -z $n ]] && return
  [[ $n =~ ^[0-9]+$ ]] && (( n >= 1 && n <= $(wc -l < "$CONF") )) || { err "Invalid number."; return; }
  lport=$(sed -n "${n}p" "$CONF" | cut -d'|' -f3)
  sec_get "$lport"
  echo; info "Editing port $lport. Press Enter to keep the current value."
  local a m r x bad=""
  read -rp "  Allowed IPs, comma separated, CIDR ok [${SEC_ALLOW:-any}] (- = allow all): " a
  if [[ -z $a ]]; then a=$SEC_ALLOW; elif [[ $a == "-" ]]; then a=""; fi
  a=${a// /}
  for x in ${a//,/ }; do valid_cidr "$x" || bad=$x; done
  [[ -z $bad ]] || { err "Invalid IP/CIDR: $bad"; return; }
  read -rp "  Max simultaneous connections per IP [$SEC_MAXC] (0 = off): " m; m=${m:-$SEC_MAXC}
  read -rp "  Max NEW connections per minute per IP [$SEC_RATE] (0 = off): " r; r=${r:-$SEC_RATE}
  [[ $m =~ ^[0-9]+$ && $r =~ ^[0-9]+$ ]] || { err "Numbers only."; return; }
  if [[ -n $a ]]; then
    warn "Only the listed IPs will reach port $lport. Make sure your clients' IPs are in the list."
    confirm "Apply?" || return
  fi
  sec_set "$lport" "$a" "$m" "$r"
  apply_rules; ok "Security updated for port $lport."
}

# ------------------------------------------- two-server connection test (BackPack-style)
CTESTF="$CONF_DIR/ctest.json"      # {"id","tport","uport","until","report"}

ctest_free_port() {   # a TCP+UDP free port in the 21000-21999 band
  local p
  for p in $(shuf -i 21000-21999 -n 20 2>/dev/null || seq 21000 21999); do
    if ! ss -uln "( sport = :$p )" 2>/dev/null | grep -q ":$p " && ! ss -tln "( sport = :$p )" 2>/dev/null | grep -q ":$p "; then echo "$p"; return 0; fi
  done
  return 1
}

ctest_open() {   # open ephemeral echo servers and print "ID TPORT UPORT" - the panel wraps them into a one-line link
  local id tport uport until
  id=$(tun_token); [[ ${#id} -ge 16 ]] || { echo "error: no entropy" >&2; return 1; }
  tport=$(ctest_free_port) || { echo "error: no free test port" >&2; return 1; }
  uport=$(ctest_free_port) || { echo "error: no free test port" >&2; return 1; }
  [[ $tport != "$uport" ]] || uport=$(ctest_free_port) || { echo "error: no free test port" >&2; return 1; }
  until=$(( $(date +%s) + 900 ))
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR" 2>/dev/null
  printf '{"id":"%s","tport":%s,"uport":%s,"until":%s,"report":null}\n' "$id" "$tport" "$uport" "$until" > "$CTESTF"
  chmod 600 "$CTESTF"
  nohup "$BIN" ctest-daemon "$tport" "$uport" "$until" >/dev/null 2>&1 &
  echo "$id $tport $uport"
}

ctest_close() {   # stop the echo servers and clear their firewall rules
  pkill -f "seka-tunel ctest-daemon" 2>/dev/null || true
  if [[ -s $CTESTF ]]; then
    local tport uport
    tport=$(python3 -c "import json;print(json.load(open('$CTESTF')).get('tport',''))" 2>/dev/null)
    uport=$(python3 -c "import json;print(json.load(open('$CTESTF')).get('uport',''))" 2>/dev/null)
    local n=0
    [[ -n $tport ]] && { while iptables -D INPUT -p tcp --dport "$tport" -m comment --comment seka-ctest -j ACCEPT 2>/dev/null; do (( ++n > 50 )) && break; done; }
    n=0
    [[ -n $uport ]] && { while iptables -D INPUT -p udp --dport "$uport" -m comment --comment seka-ctest -j ACCEPT 2>/dev/null; do (( ++n > 50 )) && break; done; }
  fi
  rm -f "$CTESTF"
  echo "closed"
}

ctest_daemon() {   # internal: TCP+UDP echo servers for the two-server test (tport uport until)
  local tport=$1 uport=$2 until=$3
  iptables -I INPUT -p tcp --dport "$tport" -m comment --comment seka-ctest -j ACCEPT 2>/dev/null || true
  iptables -I INPUT -p udp --dport "$uport" -m comment --comment seka-ctest -j ACCEPT 2>/dev/null || true
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$tport/tcp" >/dev/null 2>&1; ufw allow "$uport/udp" >/dev/null 2>&1
  fi
  cleanup() {
    local n=0
    while iptables -D INPUT -p tcp --dport "$tport" -m comment --comment seka-ctest -j ACCEPT 2>/dev/null; do (( ++n > 50 )) && break; done
    n=0
    while iptables -D INPUT -p udp --dport "$uport" -m comment --comment seka-ctest -j ACCEPT 2>/dev/null; do (( ++n > 50 )) && break; done
  }
  trap cleanup EXIT INT TERM
  exec python3 - "$tport" "$uport" "$until" <<'PYEOF'
import socket, sys, threading, time
tport, uport, until = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])

def tcp_echo():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", tport)); s.listen(16); s.settimeout(2)
    while time.time() < until:
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        def h(c):
            c.settimeout(10)
            try:
                while True:
                    b = c.recv(4096)
                    if not b: break
                    c.sendall(b)
            except Exception: pass
            finally:
                try: c.close()
                except Exception: pass
        threading.Thread(target=h, args=(c,), daemon=True).start()
    try: s.close()
    except Exception: pass

def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", uport)); s.settimeout(2)
    while time.time() < until:
        try:
            b, a = s.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        try: s.sendto(b, a)
        except Exception: pass
    try: s.close()
    except Exception: pass

t1 = threading.Thread(target=tcp_echo, daemon=True)
t2 = threading.Thread(target=udp_echo, daemon=True)
t1.start(); t2.start()
while time.time() < until and t1.is_alive() and t2.is_alive():
    time.sleep(1)
PYEOF
}

conntest_cli() {   # BackPack-style connection test, via the installed web backend (no panel needed)
  [[ -f $WEB_PY ]] || { echo "error: install the web panel first (menu option 9), then run this again" >&2; return 1; }
  python3 "$WEB_PY" conntest 2>/dev/null | python3 -c '
import json,sys
try: r=json.load(sys.stdin)
except Exception: print("conntest failed"); raise SystemExit(1)
def row(n,x,extra=""):
    if x is None: print("  %-26s %s" % (n, "n/a")); return
    print("  %-26s %s%s" % (n, ("%5s ms · loss %s%%" % (x.get("avg","-"), x.get("loss","-"))) if x.get("ok") else "unreachable", extra))
print("SEKA TUNEL connection test  (%s)" % time.strftime("%F %T", __import__("time").localtime(r.get("t", 0))) if True else "")
row("Cloudflare 1.1.1.1", r.get("g2"))
row("Google DNS 8.8.8.8→4.2.2.4", r.get("g1"))
print("  %-26s %s" % ("Download (Cloudflare)", ("%s Mbit/s" % r["dl"]) if r.get("dl") else "n/a"))
print("  %-26s %s" % ("UDP egress (WireGuard)", "open" if r.get("udp") else "BLOCKED"))
for t in r.get("tunnels", []):
    row("tunnel -> %s" % (t.get("name") or t.get("ip")), t, (" · MTU %s" % t["mtu"]) if t.get("mtu") else "")
rec=r.get("rec") or {}
print("  recommendation: %s%s" % (rec.get("fa","-"), (" (preset: %s)" % rec["preset"]) if rec.get("preset") else ""))
';
}


# ------------------------------------------------- BackPack-style menu flows
# The CLI follows BackPack 1:1: 0) Connection Test, 1) Setup Iran, 2) Setup
# Kharej (both ask the Direction first - Forward is Iran's third direction),
# 3) Manage (Tunnels lists tunnels and port forwards together). Tunnel
# creation is NOT buried under a transport menu any
# more: you say which server you are on, which direction, and the wizard asks
# the transport family -> variant, the address, the port, the forwarded ports,
# the name and the per-tunnel preset - then one link sets the other side up.

trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }

pick_menu() {   # $1=title, rest="key|label|desc"; menu on stderr, chosen key on stdout ("" = cancel)
  local title=$1; shift
  {
    banner; echo "  ${C_BLD}$title${C_RST}"; echo
    local o key label desc
    for o in "$@"; do IFS='|' read -r key label desc <<< "$o"
      printf "   %s) %-16s %s\n" "$key" "$label" "$desc"
    done
    echo "   0) Cancel"; echo
    printf "  Select: "
  } >&2
  local c o key label desc
  read -r c
  for o in "$@"; do IFS='|' read -r key label desc <<< "$o"
    [[ $key == "$c" ]] && { echo "$key"; return 0; }
  done
  echo ""; return 0
}

DIR_CHOICE=0
ask_direction() {   # $1 = Iran|Kharej : the one question that picks the engine (BackPack askDirection)
  DIR_CHOICE=0
  banner; echo "  ${C_BLD}Setup $1${C_RST}"; echo
  echo "  Direction - who dials whom:"
  echo "   1) Reverse   kharej dials Iran - try this first"
  echo "   2) Direct    Iran dials kharej - when inbound to Iran is blocked"
  [[ $1 == Iran ]] && echo "   3) Forward   classic DNAT: a port on this server -> a foreign node"
  echo "   0) Back"; echo
  local c; read -rp "  Select: " c
  case $c in 1) DIR_CHOICE=1;; 2) DIR_CHOICE=2;; 3) [[ $1 == Iran ]] && DIR_CHOICE=3;; *) DIR_CHOICE=0;; esac
}

choose_transport() {   # SEKA TUNEL transport picker (Persian + GAAF)
  local fam tr
  fam=$(pick_menu "انتخاب خانواده ترنسپورت" \
    "1|TCP|پایدار و ساده — گزینه امن پیش‌فرض" \
    "2|UDP|تأخیر کمتر، مناسب لینک‌های پراتلاف یا محدود شده" \
    "3|WebSocket|شبیه ترافیک وب معمولی — مناسب CDN" \
    "4|GAAF|پروتکل اختصاصی SEKA (SM4-GCM + X25519) — پیشنهادی جدید") || return 0
  [[ -z $fam ]] && return 0
  case $fam in
    1) tr=$(pick_menu "انتخاب ترنسپورت TCP" \
         "1|TCP|ساده و سریع — اگر مطمئن نیستید از اینجا شروع کنید");;
    2) tr=$(pick_menu "انتخاب ترنسپورت UDP" \
         "1|UDP|دیتاگرام خام — سریع‌ترین گزینه" \
         "2|UDP + KCP + FEC|مناسب گیم و تأخیر پایین با اصلاح خطا" \
         "3|UDP + QUIC|رمزنگاری TLS 1.3 روی UDP — خودتنظیم و مقاوم در برابر از دست رفتن پکت");;
    3) tr=$(pick_menu "انتخاب ترنسپورت WebSocket" \
         "1|WS|WebSocket — استتار HTTP، مناسب CDN" \
         "2|WSS|WebSocket امن — رمزنگاری TLS (گواهی self-signed خودکار)");;
    4) echo gaaf; return 0;;
  esac
  case $fam:$tr in
    1:1) echo tcp;;
    2:1) echo udp;; 2:2) echo kcp;; 2:3) echo quic;;
    3:1) echo ws;; 3:2) echo wss;;
    *)   echo "";;
  esac
}

wiz_preset() {   # BackPack "How Should The Tunnel Be Tuned?" - per-tunnel, at create time
  local p
  p=$(pick_menu "How Should The Tunnel Be Tuned?" \
    "1|Balanced|least memory - safe defaults" \
    "2|Turbo|recommended for Iran <-> abroad" \
    "3|Throughput|maximum bandwidth on fat links" \
    "4|Gaming|lowest latency for games and real-time") || { echo turbo; return 0; }
  case $p in 1) echo balanced;; 3) echo throughput;; 4) echo gaming;; *) echo turbo;; esac
}

parse_ports_spec() {   # "443, 8080=2096, 8080=127.0.0.1:2096" -> lines "listen destport" (BackPack port spec)
  local spec=$1 e l d
  [[ -z $(trim "$spec") ]] && return 0
  local IFS=,
  for e in $spec; do
    e=$(trim "$e"); [[ -z $e ]] && continue
    if [[ $e == *=* ]]; then
      l=$(trim "${e%%=*}"); d=$(trim "${e#*=}"); d=${d##*:}; d=$(trim "$d")   # bare port or host:port
    else
      l=$e; d=$e
    fi
    if [[ $l =~ ^[0-9]+$ && $d =~ ^[0-9]+$ ]] && valid_port "$l" && valid_port "$d"; then
      echo "$l $d"
    else
      err "Bad port spec '$e' (use 443, 8080=2096 or 8080=127.0.0.1:2096)"; return 1
    fi
  done
}

add_forward_auto() {   # name proto lport ip dport : the wizard's non-interactive forward add
  local name=$1 proto=$2 lport=$3 ip=$4 dport=$5
  valid_port "$lport" || { err "Invalid listen port $lport."; return 1; }
  [[ $proto =~ ^(tcp|udp|both)$ ]] || return 1
  awk -F'|' -v p="$lport" -v pr="$proto" '$3==p && ($2==pr||$2=="both"||pr=="both"){f=1} END{exit !f}' "$CONF" 2>/dev/null \
    && { err "A forward on port $lport already exists."; return 1; }
  valid_port "$dport" || { err "Invalid destination port $dport."; return 1; }
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR" 2>/dev/null
  echo "$name|$proto|$lport|$ip|$dport" >> "$CONF"
  apply_rules; ensure_boot
  return 0
}

web_base_url() {   # https://host:port of the web backend ("" when unavailable)
  [[ -f $WEB_PY ]] || return 0
  local info port tls dom host
  info=$(python3 "$WEB_PY" info 2>/dev/null) || return 0
  port=$(awk '{print $1}' <<< "$info"); tls=$(awk '{print $2}' <<< "$info"); dom=$(awk '{print $3}' <<< "$info")
  [[ $port =~ ^[0-9]+$ ]] || return 0
  host=$dom; [[ -z $host || $host == "-" ]] && host=$(web_pubip 2>/dev/null)
  [[ -z $host || $host == "-" ]] && host=$(hostname -I 2>/dev/null | awk '{print $1}')
  [[ -n $host ]] && echo "$([[ $tls == https ]] && echo https || echo http)://$host:$port"
  return 0
}

wizard_rev_iran() {   # Reverse Tunnel - Iran: listens; the kharej joins with one link
  local tr host port name preset spec id tok url l d fwdn=0 det
  banner; echo "  ${C_BLD}Reverse Tunnel - Iran${C_RST}"; echo
  info "Kharej dials IN and joins with one link; users connect to THIS server."
  tr=$(choose_transport)
  [[ -z $tr ]] && { warn "No transport chosen - canceled."; return 0; }
  echo
  det=$(web_pubip 2>/dev/null); [[ -z $det || $det == "-" ]] && det=$(hostname -I 2>/dev/null | awk '{print $1}')
  read -rp "  Iran IP Or Domain (What Kharej Dials)${det:+ [$det]}: " host; host=$(trim "${host:-$det}")
  read -rp "  Tunnel Port [51820]: " port; port=${port:-51820}
  valid_port "$port" || { err "Invalid port."; return 0; }
  read -rp "  Forwarded Ports (users hit IRAN, service runs on KHAREJ; e.g. 443, 8080=2096) [none]: " spec
  read -rp "  Tunnel Name [server-$port]: " name; name=$(trim "${name:-server-$port}")
  preset=$(wiz_preset)
  echo
  echo "  ${C_BLD}--- Summary ---${C_RST}"
  echo "  Type: Reverse (kharej dials Iran)   Transport: $tr   Preset: $preset"
  echo "  Iran endpoint: ${host:-<kharej will ask>}   Tunnel port: $port"
  echo "  Forwarded ports: $(trim "${spec:-none}")"
  echo
  confirm "Create This Tunnel?" || { info "Canceled."; return 0; }
  if [[ ! -f $WEB_PY ]]; then
    warn "The one-line join link is served by the web backend (not installed yet)."
    confirm "Install the web backend now?" && web_install || true
  fi
  if [[ -n $(trim "$spec") ]]; then
    parse_ports_spec "$spec" > "$CONF_DIR/.ports.$$" 2>/dev/null \
      || { rm -f "$CONF_DIR/.ports.$$"; err "No forwards were added."; spec=""; }
  fi
  tok=$(tun_add_rev "$port" "$preset" "$name" "$tr" "") \
    || { err "Tunnel creation failed - run 'seka-tunel doctor' to see why."; return 0; }
  id=$(awk -F'|' -v t="$tok" '$12==t{print $1; exit}' "$TUN")
  if [[ -s $CONF_DIR/.ports.$$ ]]; then
    while read -r l d; do
      add_forward_auto "rv$l" both "$l" "10.66.$id.2" "$d" \
        && { ok "Forward  :$l -> kharej :$d  (through the tunnel)"; fwdn=$((fwdn + 1)); }
    done < "$CONF_DIR/.ports.$$"
    (( fwdn > 0 )) && warn "If the service on kharej listens only on 127.0.0.1, re-run the kharej join line once after any change."
  fi
  rm -f "$CONF_DIR/.ports.$$"
  echo
  url=$(web_base_url)
  if [[ -n $url ]]; then
    ok "Tunnel #$id created - this side is listening. Run this ONE line on the KHAREJ server (as root):"
    echo; echo "  ${C_BLD}${C_GRN}bash <(curl -fsSLk $url/join/$tok)${C_RST}"; echo
    info "The link stays valid: Manage -> Tunnels -> #$id -> Setup Link."
  else
    ok "Tunnel #$id created - this side is listening."
    warn "The web backend is not reachable, so there is no one-line link. Install it (menu 5), then: Manage -> Tunnels -> #$id -> Setup Link."
  fi
}

wizard_direct_iran() {   # Direct Tunnel - Iran: Iran dials out to the kharej
  local tr fip port name preset spec id tok url l d fwdn=0 mtu
  banner; echo "  ${C_BLD}Direct Tunnel - Iran${C_RST}"; echo
  info "Iran dials OUT to the kharej server - use it when inbound to Iran is blocked."
  tr=$(choose_transport)
  [[ -z $tr ]] && { warn "No transport chosen - canceled."; return 0; }
  echo
  read -rp "  Kharej IP Or Domain (What Iran Dials): " fip; fip=$(trim "$fip")
  if ! valid_ip "$fip"; then
    local rip; rip=$(getent hosts "$fip" 2>/dev/null | awk '{print $1; exit}')
    if [[ -n $rip ]]; then ok "  $fip -> $rip"; fip=$rip; else err "Invalid IP or unresolvable domain."; return 0; fi
  fi
  read -rp "  Tunnel Port [51820]: " port; port=${port:-51820}
  valid_port "$port" || { err "Invalid port."; return 0; }
  read -rp "  Forwarded Ports (users hit IRAN, service runs on KHAREJ; e.g. 443, 8080=2096) [none]: " spec
  read -rp "  MTU [auto]: " mtu; mtu=$(trim "$mtu"); [[ -z $mtu ]] && mtu=0
  [[ $mtu =~ ^[0-9]+$ ]] && (( mtu == 0 || (mtu >= 1200 && mtu <= 1500) )) || { err "Invalid MTU."; return 0; }
  read -rp "  Tunnel Name [direct-$port]: " name; name=$(trim "${name:-direct-$port}")
  preset=$(wiz_preset)
  echo
  echo "  ${C_BLD}--- Summary ---${C_RST}"
  echo "  Type: Direct (Iran dials kharej)   Transport: $tr   Preset: $preset   MTU: $([[ $mtu == 0 ]] && echo auto || echo "$mtu")"
  echo "  Kharej: $fip   Tunnel port: $port"
  echo "  Forwarded ports: $(trim "${spec:-none}")"
  echo
  confirm "Create This Tunnel?" || { info "Canceled."; return 0; }
  if [[ ! -f $WEB_PY ]]; then
    warn "The one-line join link is served by the web backend (not installed yet)."
    confirm "Install the web backend now?" && web_install || true
  fi
  if [[ -n $(trim "$spec") ]]; then
    parse_ports_spec "$spec" > "$CONF_DIR/.ports.$$" 2>/dev/null \
      || { rm -f "$CONF_DIR/.ports.$$"; err "No forwards were added."; spec=""; }
  fi
  tun_add "$fip" "$port" "$mtu" "$preset" fwd "$name" "$tr" "" \
    || { rm -f "$CONF_DIR/.ports.$$"; err "Tunnel creation failed - run 'seka-tunel doctor' to see why."; return 0; }
  id=${TROW:-}; id=$(cut -d'|' -f1 <<< "$(tun_row "$fip")")
  if [[ -s $CONF_DIR/.ports.$$ ]]; then
    while read -r l d; do
      add_forward_auto "fw$l" both "$l" "10.66.$id.2" "$d" \
        && { ok "Forward  :$l -> kharej :$d  (through the tunnel)"; fwdn=$((fwdn + 1)); }
    done < "$CONF_DIR/.ports.$$"
  fi
  rm -f "$CONF_DIR/.ports.$$"
  (( fwdn > 0 )) && tun_active "$fip" 1 >/dev/null 2>&1 && ok "Forwards route through the encrypted tunnel."
  echo
  tok=$(tun_link "$fip" 2>/dev/null)
  url=$(web_base_url)
  if [[ -n $url && ${#tok} -ge 16 ]]; then
    ok "Tunnel #$id created. Run this ONE line on the KHAREJ server (as root):"
    echo; echo "  ${C_BLD}${C_GRN}bash <(curl -fsSLk $url/join/$tok)${C_RST}"; echo
    info "Classic alternative: Manage -> Tunnels -> #$id -> Foreign Script."
  else
    ok "Tunnel #$id created. Run this on the KHAREJ server:"
    echo; tun_script "$fip"; echo
    info "Save it as a file and run as root on the kharej server."
  fi
}

setup_iran_menu() {
  ask_direction Iran
  case $DIR_CHOICE in
    1) wizard_rev_iran; pause;;
    2) wizard_direct_iran; pause;;
    3) add_forward; pause;;
  esac
}

wizard_kharej_side() {   # $1 = 1 (reverse) | 2 (direct) - the kharej side of either direction
  local c tmp ty
  ty=$([[ $1 == 1 ]] && echo Reverse || echo Direct)
  banner; echo "  ${C_BLD}$ty Tunnel - Kharej${C_RST}"; echo
  echo "  How Do You Want To Set Up This Side?"
  echo "   1) Setup Link    recommended - paste the Iran server's link"
  echo "   2) Setup Script  paste the full script the Iran server printed"
  echo "   0) Back"; echo
  read -rp "  Select: " c; echo
  case $c in
    1) kharej_join;;
    2) info "Paste the script, then press Ctrl+D to run it:"
       tmp=$(mktemp); cat > "$tmp" 2>/dev/null || true
       if [[ -s $tmp ]]; then bash "$tmp"; else info "Nothing pasted."; fi
       rm -f "$tmp"; pause;;
  esac
}

setup_kharej_menu() {
  ask_direction Kharej
  case $DIR_CHOICE in
    1) wizard_kharej_side 1; pause;;
    2) wizard_kharej_side 2; pause;;
  esac
}

# --- 0) Connection Test ------------------------------------------------------
ct_print_report() {   # pretty-print the two-server report stored by the panel
  python3 - "$CTESTF" <<'PYEOF'
import json, sys
try: st = json.load(open(sys.argv[1]))
except Exception: raise SystemExit(2)
r = st.get("report")
if not r: raise SystemExit(2)
def g(k):
    d = r.get(k) or {}
    if not isinstance(d, dict) or not d.get("ok"): return ("BLOCKED", "-", "-")
    return (d.get("avg", "-"), d.get("jitter", "-"), d.get("loss", "-"))
print()
print("  SEKA TUNEL two-server test:  KHAREJ (%s) -> IRAN" % r.get("ip", "?"))
print("  | %-10s | %8s | %8s | %6s |" % ("path", "avg ms", "jitter", "loss%"))
print("  " + "-" * 42)
for name, k in (("ping (ICMP)", "icmp"), ("tcp echo", "tcp"), ("udp echo", "udp")):
    a, j, l = g(k)
    print("  | %-10s | %8s | %8s | %5s%% |" % (name, a, j, l))
print()
PYEOF
}

ct_wait_report() {
  local i=0
  echo
  info "Waiting for the kharej to run the link (up to 15 minutes) - Ctrl+C stops waiting."
  while (( ++i <= 180 )); do
    sleep 5
    if ct_print_report 2>/dev/null; then ok "Report received (also visible on the panel's connection-test page)."; return 0; fi
    (( i % 12 == 0 )) && printf "  ...waiting (%d/15 min)\n" $((i / 12))
  done
  warn "No report yet. The listeners stay open for 15 minutes - the kharej line can still be run in that window."
  info "Close the listeners any time with: seka-tunel ctest-close"
}

connection_test_menu() {
  local c
  banner; echo "  ${C_BLD}Connection Test${C_RST}"; echo
  info "Which paths actually work between the two servers - real ICMP + TCP echo + UDP echo."
  echo
  echo "  This Server Is:"
  echo "   1) Iran     start here, get the link"
  echo "   2) Kharej   paste the Iran server's link"
  echo "   0) Back"; echo
  read -rp "  Select: " c; echo
  case $c in
    1) ct_iran_menu; pause;;
    2) ct_kharej_menu;;
  esac
}

ct_iran_menu() {
  if [[ ! -f $WEB_PY ]]; then
    warn "The test link is served by the web backend (not installed yet)."
    confirm "Install it now?" || { info "Install it later from menu 5 (Web Panel)."; return 0; }
    web_install || return 0
  fi
  banner; echo "  ${C_BLD}Connection Test - Iran${C_RST}"; echo
  info "1/2  Preparing the test listeners (TCP + UDP echo, live 15 minutes)..."
  local out id tport uport url
  out=$(ctest_open) || { err "Could not open the test listeners (ports busy?)."; return 0; }
  read -r id tport uport <<< "$out"
  url=$(web_base_url)
  if [[ -z $url ]]; then
    err "Could not read the web backend address (menu 5 -> Show access info)."
    ctest_close >/dev/null
    return 0
  fi
  echo
  info "2/2  Connect the Kharej - run this ONE line there (as root):"
  echo
  echo "  ${C_BLD}${C_GRN}bash <(curl -fsSLk $url/ctest/$id)${C_RST}"
  echo
  warn "Leave this test open on Iran. Ctrl+C stops waiting (the listeners stay up 15 min)."
  ct_wait_report
}

ct_kharej_menu() {
  banner; echo "  ${C_BLD}Connection Test - Kharej${C_RST}"; echo
  local url; read -rp "  Test Link (from the Iran server): " url
  url=$(trim "$url"); [[ -n $url ]] || return 0
  url=$(printf '%s' "$url" | tr -d "\"'")
  [[ $url =~ ^https?://[^[:space:]]+/ctest/[0-9a-f]{16,64}$ ]] || { err "That does not look like a SEKA TUNEL test link."; return 0; }
  info "Measuring ICMP + TCP echo + UDP echo to the Iran server..."
  echo
  curl -fsSLk --max-time 60 "$url" | bash
  echo
  pause
}

# --- 3) Manage ---------------------------------------------------------------
tun_table() {   # the tunnel table; sets TUN_COUNT
  local i=0 id fip port a pr ty name tr hs st
  TUN_COUNT=0
  [[ -s $TUN ]] || { info "No tunnels yet - build one from Setup Iran / Setup Kharej."; return 1; }
  printf "  ${C_BLD}%-3s %-18s %-6s %-9s %-10s %-14s %-11s %s${C_RST}\n" "#" "NAME" "PORT" "TYPE" "TRANSPORT" "STATE" "PRESET" "FOREIGN IP"
  while IFS='|' read -r id fip port _ _ _ _ _ a pr ty tok name _ tr _; do
    [[ -z $id ]] && continue; i=$((i + 1))
    if [[ $fip == pending ]]; then st="waiting-join"
    else
      hs=$(wg show "sekawg$id" latest-handshakes 2>/dev/null | awk '{print $2}')
      if [[ ${hs:-0} -gt 0 ]]; then st="linked"; else st="no-handshake"; fi
      [[ $(systemctl is-active "wg-quick@sekawg$id" 2>/dev/null) == active ]] || st="stopped"
    fi
    printf "  %-3s %-18s %-6s %-9s %-10s %-14s %-11s %s\n" \
      "$i" "${name:-tunnel$id}" "$port" "$([[ $ty == rev ]] && echo reverse || echo direct)" \
      "${tr:-udp}" "$st" "${pr:--}" "$([[ $fip == pending ]] && echo '<waiting for the link>' || echo "$fip")"
  done < "$TUN"
  TUN_COUNT=$i
  return 0
}

tun_pick_row() {   # sets TROW/TID/TFIP from a table line number
  local n
  TROW=""; TID=""; TFIP=""
  [[ -s $TUN ]] || { err "No tunnels yet."; return 1; }
  read -rp "  Tunnel number: " n
  [[ $n =~ ^[0-9]+$ ]] || { err "Invalid number."; return 1; }
  TROW=$(sed -n "${n}p" "$TUN")
  [[ -n $TROW ]] || { err "Invalid number."; return 1; }
  TID=${TROW%%|*}; TFIP=$(cut -d'|' -f2 <<< "$TROW")
  return 0
}

tun_show_link() {   # id : the one-line join command for a tunnel
  local id=$1 r tok url fip
  r=$(awk -F'|' -v i="$id" '$1==i{print;exit}' "$TUN")
  [[ -n $r ]] || { err "No such tunnel."; return 1; }
  fip=$(cut -d'|' -f2 <<< "$r")
  tok=$(cut -d'|' -f12 <<< "$r")
  [[ ${#tok} -ge 16 ]] || tok=$(tun_link "$id") || { err "Could not create a join token."; return 1; }
  url=$(web_base_url)
  [[ -z $url ]] && { err "The web backend is not reachable - install/restart it from menu 5 first."; return 1; }
  ok "Run this ONE line on the KHAREJ server (as root):"
  echo; echo "  ${C_BLD}${C_GRN}bash <(curl -fsSLk $url/join/$tok)${C_RST}"; echo
  [[ $fip == pending ]] && info "Reverse tunnel: it goes live the moment the kharej runs that line."
  return 0
}

tun_switch_transport() {   # id : BackPack-style per-tunnel carrier switch
  local id=$1 cur ntr ncp got
  cur=$(tun_transport "$id")
  echo "  Current transport: $cur"
  echo "   1) UDP (plain WireGuard - fastest)   2) TCP   3) WS   4) WSS   5) KCP   6) QUIC"
  read -rp "  Select [1]: " c
  case ${c:-1} in 2) ntr=tcp;; 3) ntr=ws;; 4) ntr=wss;; 5) ntr=kcp;; 6) ntr=quic;; *) ntr=udp;; esac
  ncp=""; [[ $ntr != udp ]] && { read -rp "  Carrier port [auto]: " ncp; }
  if got=$(tun_transport "$id" "$ntr" "$ncp"); then
    ok "Transport: $got."
    [[ $got != udp ]] && warn "Carried transport: run the kharej join line / foreign script again after a switch."
  else
    err "Failed."
  fi
}

tun_switch_preset() {   # id
  local id=$1 cur got
  cur=$(tun_preset "$id")
  echo "  Current preset: ${cur:-- (system default)}"
  echo "   1) Balanced   2) Turbo   3) Throughput   4) Gaming   5) Follow the system preset"
  read -rp "  Select: " c
  case $c in 1) got=balanced;; 2) got=turbo;; 3) got=throughput;; 4) got=gaming;; 5) got=none;; *) err "Canceled."; return 0;; esac
  tun_preset "$id" "$got" >/dev/null && ok "Preset: $got (applies now if the tunnel is active)."
}

tunnel_actions() {   # BackPack ManageTunnels -> manageOne: pick a tunnel, then act on it
  local id fip name a got c
  banner; echo "  ${C_BLD}Tunnels${C_RST}"; echo
  tun_table
  echo
  info "Port forwards (classic DNAT) - add: Setup Iran > 3) Forward · full menu: Manage > Forward Ports"
  list_rules
  echo
  tun_pick_row || return 0
  id=$TID; fip=$TFIP
  name=$(cut -d'|' -f13 <<< "$TROW")
  while true; do
    echo
    echo "  ${C_BLD}Tunnel #$id${C_RST}${name:+ \"$name\"}  ($([[ $(cut -d'|' -f11 <<< "$TROW") == rev ]] && echo reverse || echo direct) · $(cut -d'|' -f15 <<< "$TROW"))"
    echo "   1) Start             bring the interface up"
    echo "   2) Stop              bring the interface down"
    echo "   3) Restart"
    echo "   4) Setup Link        the one-line join command for the kharej"
    echo "   5) Foreign Script    the classic full script for the kharej"
    echo "   6) Transport         switch UDP / TCP / WS / WSS / KCP / QUIC"
    echo "   7) Preset            per-tunnel performance preset"
    echo "   8) Auto MTU          find the largest packet the link passes"
    echo "   9) Route Forwards    via this tunnel / back to direct"
    echo "  10) Live Log          Ctrl+C to return"
    echo "  11) Delete            remove this tunnel"
    echo "   0) Back"; echo
    read -rp "  Select: " c || return 0
    case $c in
      1) tun_up "$id" && ok "Started.";;
      2) tun_down "$id" && ok "Stopped.";;
      3) tun_up "$id" && ok "Restarted.";;
      4) tun_show_link "$id";;
      5) echo; tun_script "$fip"; echo; info "Save the whole script above as a file on the kharej server and run it as root.";;
      6) tun_switch_transport "$id";;
      7) tun_switch_preset "$id";;
      8) got=$(tun_automtu "$id" 2>/dev/null) && ok "Best MTU for this link: $got" || err "Could not measure (the link must be connected first).";;
      9) a=$(cut -d'|' -f9 <<< "$TROW")
         if [[ $a == 1 ]]; then tun_active "$fip" 0 && ok "Forwards to $fip are direct again."
         else tun_active "$fip" 1 && ok "Forwards to $fip now ride the tunnel."; fi
         TROW=$(tun_row "$id");;
     10) echo; info "Live log of wg-quick@sekawg$id - Ctrl+C to return:"
         journalctl -n 30 -u "wg-quick@sekawg$id" -f 2>/dev/null || warn "journalctl unavailable.";;
     11) confirm "Delete tunnel #$id ($fip)?" && { tun_del "$fip" && ok "Deleted - its forwards went back to direct."; return 0; };;
      0) return 0;;
    esac
  done
}

forward_actions() {   # our one extra: the classic DNAT port forwarding
  local c
  while true; do
    banner; echo "  ${C_BLD}Forward Port${C_RST}"; echo
    info "The classic forwarding: a port on THIS server lands on a foreign node (iptables DNAT)."
    echo
    echo "   1) Add Forward          new port -> foreign node"
    echo "   2) List Forwards        with live traffic counters"
    echo "   3) Test Forwards        TCP connect time and ping"
    echo "   4) Import Manual Rules  adopt hand-made iptables rules"
    echo "   5) Remove Forward"
    echo "   0) Back"; echo
    read -rp "  Select: " c || return 0; echo
    case $c in
      1) add_forward; pause;;
      2) banner; list_rules; pause;;
      3) test_forwards; pause;;
      4) import_legacy; pause;;
      5) remove_forward; pause;;
      0) return 0;;
    esac
  done
}

manage_menu() {   # BackPack: "tunnels, status, health, tests"
  local c
  while true; do
    banner; echo "  ${C_BLD}Manage${C_RST}"; echo
    echo "   1) Tunnels              start/stop, links, transport, preset, MTU, delete"
    echo "   2) Forward Ports        list, test, remove the DNAT forwards"
    echo "   3) Reverse Forwards     ports on kharej that reach services on Iran"
    echo "   4) Status               full status"
    echo "   5) Tunnel Security      IP allow-list, connection and rate limits"
    echo "   0) Back"; echo
    read -rp "  Select: " c || return 0; echo
    case $c in
      1) tunnel_actions;;
      2) forward_actions;;
      3) reverse_menu;;
      4) status; pause;;
      5) security_menu; pause;;
      0) return 0;;
    esac
  done
}

# --- 7) Telegram Bot ---------------------------------------------------------
tg_cfg() {   # echo "token chat api on|off"
  python3 - "$WEB_CFG" <<'PYEOF'
import json, sys
try: c = json.load(open(sys.argv[1]))
except Exception: c = {}
print(c.get("tg_token") or "-", c.get("tg_chat") or "-", c.get("tg_api") or "-", "on" if c.get("tg_bot") else "off")
PYEOF
}

tg_cfg_set() {   # token chat on|off ("" keeps the current value)
  python3 - "$WEB_CFG" "${1:-}" "${2:-}" "${3:-}" <<'PYEOF'
import json, sys
p = sys.argv[1]; tok, chat, bot = sys.argv[2], sys.argv[3], sys.argv[4]
try: c = json.load(open(p))
except Exception: c = {}
if tok: c["tg_token"] = tok.strip()
if chat: c["tg_chat"] = chat.strip()
if bot in ("on", "off"): c["tg_bot"] = bot == "on"
json.dump(c, open(p, "w"))
print("saved")
PYEOF
}

telegram_menu() {
  local c tok chat api on
  read -r tok chat api on <<< "$(tg_cfg)"
  banner; echo "  ${C_BLD}Telegram Bot${C_RST}"; echo
  echo "  Token: $([[ $tok == - ]] && echo '<not set>' || echo '<set>')   Chat: $([[ $chat == - || -z $chat ]] && echo '<not set>' || echo '<set>')   Bot: $on"
  echo
  echo "   1) Bot Token           from @BotFather"
  echo "   2) Chat ID             the chat that receives the reports"
  echo "   3) Enable / Disable    the /status /traffic /report bot"
  echo "   4) Test Message        send one now"
  echo "   0) Back"; echo
  read -rp "  Select: " c; echo
  case $c in
    1) read -rp "  Bot Token: " tok; [[ -n $(trim "$tok") ]] && { tg_cfg_set "$tok" "" "" >/dev/null && ok "Token saved."; };;
    2) read -rp "  Chat ID: " chat; [[ -n $(trim "$chat") ]] && { tg_cfg_set "" "$chat" "" >/dev/null && ok "Chat saved."; };;
    3) if [[ $on == on ]]; then tg_cfg_set "" "" off >/dev/null && ok "Bot disabled."
       else tg_cfg_set "" "" on >/dev/null && ok "Bot enabled (the monitor service picks it up)."; fi;;
    4) read -r tok chat api on <<< "$(tg_cfg)"
       if [[ $tok == - || -z $chat ]]; then err "Set the bot token and the chat ID first."
       else
         curl -fsS --max-time 15 -H 'Content-Type: application/json' \
           -d "{\"chat_id\":\"$chat\",\"text\":\"SEKA TUNEL test message - $(hostname) $(date '+%F %T')\"}" \
           "$([[ $api == - || -z $api ]] && echo https://api.telegram.org || echo "$api")/bot$tok/sendMessage" >/dev/null 2>&1 \
           && ok "Sent." || err "Could not send (token / chat / api?)."
       fi;;
  esac
  systemctl restart seka-tunel-web 2>/dev/null || true
}

# --- 8) Update ---------------------------------------------------------------
update_menu() {
  local c
  banner; echo "  ${C_BLD}Update${C_RST}"; echo
  echo "  Current version: $VERSION"
  echo
  echo "   1) Update Now     pull the latest release from GitHub"
  echo "   2) Rollback       go back to the previous version"
  echo "   0) Back"; echo
  read -rp "  Select: " c; echo
  case $c in
    1) info "Updating..."
       bash <(curl -fsSL https://raw.githubusercontent.com/behymin12345-hash/SEKA TUNEL/main/install.sh)
       echo; info "Update finished - reopen the menu with: seka-tunel"
       exit 0;;
    2) do_rollback; pause;;
  esac
}

# --- doctor ------------------------------------------------------------------
doctor() {   # the first stop when a tunnel will not build
  banner; echo "  ${C_BLD}Doctor${C_RST}"; echo
  local bad=0 pip
  cok()  { ok "$1"; }
  cbad() { err "$1"; bad=$((bad + 1)); }
  command -v python3  >/dev/null 2>&1 && cok "python3"                     || cbad "python3 MISSING (the web backend needs it)"
  command -v curl     >/dev/null 2>&1 && cok "curl"                        || cbad "curl MISSING"
  command -v iptables >/dev/null 2>&1 && cok "iptables"                    || cbad "iptables MISSING"
  command -v wg       >/dev/null 2>&1 && cok "wireguard tools"             || cbad "wireguard tools MISSING - run the installer again"
  modprobe wireguard  2>/dev/null     && cok "wireguard kernel module"     || cbad "wireguard kernel module FAILED to load"
  [[ -x /usr/local/bin/seka-gost ]]     && cok "gost carrier installed"     || info "gost carrier: installs on the first carried tunnel"
  [[ -f $WEB_PY ]]                     && cok "web backend installed"      || warn "web backend NOT installed (join/test links need it - menu 5)"
  systemctl is-active seka-tunel-web >/dev/null 2>&1 && cok "web backend running" || warn "web backend NOT running (menu 5 -> Restart)"
  pip=$(web_pubip 2>/dev/null)
  [[ -n $pip && $pip != "-" ]]         && cok "public IP detected ($pip)"  || warn "public IP not detectable - type it manually in the wizards"
  [[ -r $TUN ]]                        && cok "tunnels config readable"    || info "tunnels config: empty (no tunnels yet)"
  echo
  if (( bad == 0 )); then ok "Nothing blocking - tunnel creation should work."
  else warn "$bad blocking problem(s) - fix the red ones and try again."; fi
  return 0
}

sales_menu() {
  banner; echo "  ${C_BLD}فروش و محدودیت تانل${C_RST}"; echo
  echo "  1) سهمیه ترافیک / سقف حجم (از Manage تانل‌ها و پنل وب)"
  echo "  2) تاریخ انقضا برای فوروارد"
  echo "  3) لینک کاربری مصرف (/sub/token)"
  echo "  4) امنیت پورت (IP مجاز / محدودیت اتصال)"
  echo "  5) بازگشت"
  echo
  read -rp "  انتخاب: " c
  case $c in
    1|2|3) info "از پنل وب یا Manage → تانل/فوروارد این موارد را تنظیم کنید."; manage_menu;;
    4) security_menu; pause;;
    *) return 0;;
  esac
}

main_menu() {
  local c
  while true; do
    banner
    echo "   0) تست اتصال دو سروره"
    echo "   1) راه‌اندازی ایران"
    echo "   2) راه‌اندازی خارج (Kharej)"
    echo "   3) مدیریت تانل‌ها"
    echo "   4) پروتکل GAAF"
    echo "   5) بالانسر و نودها"
    echo "   6) چکر کامل (پینگ/TCP/UDP/IPv6/سرعت)"
    echo "   7) فروش و محدودیت‌ها"
    echo "   8) پشتیبان‌گیری"
    echo "   9) پنل وب / UI جدید"
    echo "  10) بهینه‌سازی شبکه"
    echo "  11) ربات تلگرام"
    echo "  12) به‌روزرسانی"
    echo "  13) حذف کامل از سرور"
    echo "  14) خروج"
    echo
    read -rp "  انتخاب شما: " c || exit 0
    echo
    case $c in
      0) connection_test_menu; pause;;
      1) setup_iran_menu;;
      2) setup_kharej_menu;;
      3) manage_menu;;
      4) if declare -f gaaf_menu >/dev/null 2>&1; then gaaf_menu; else err "ماژول GAAF بارگذاری نشده."; pause; fi;;
      5) if declare -f bal_menu >/dev/null 2>&1; then bal_menu; else err "ماژول بالانسر بارگذاری نشده."; pause; fi;;
      6) if declare -f chk_menu >/dev/null 2>&1; then chk_menu; else err "ماژول چکر بارگذاری نشده."; pause; fi;;
      7) sales_menu;;
      8) backup_restore; pause;;
      9) web_menu; pause;;
      10) perf_menu; pause;;
      11) telegram_menu; pause;;
      12) update_menu; pause;;
      13) uninstall;;
      14) info "خداحافظ!"; echo; exit 0;;
    esac
  done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  need_root
  ensure_deps
  migrate_legacy
  case "${1:-}" in
    apply) apply_rules; gost_boot;;
    list)  list_rules;;
    tunnel) shift; tunnel_cli "$@";;
    reverse) shift; tunnel_cli reverse "$@";;
    join) shift; kharej_join "$@";;
    kharej) kharej_status;;
    ctest-open) shift; ctest_open;;
    ctest-close) ctest_close;;
    ctest-daemon) shift; ctest_daemon "$@";;
    conntest) conntest_cli;;
    doctor) doctor;;
    checker|check) shift; if declare -f chk_menu >/dev/null; then
            case "${1:-menu}" in
              menu|"") chk_menu;;
              all) chk_all_tunnels;;
              target) chk_target "${2:-}" "${3:-80,443,51820,24444}";;
              *) chk_menu;;
            esac
          else err "Checker module missing"; fi;;
    gaaf) shift; if declare -f gaaf_menu >/dev/null; then
            case "${1:-menu}" in
              menu|"") gaaf_menu;;
              status) gaaf_status "${2:-}";;
              create) gaaf_on_tunnel_create "${2:-1}" "${3:-rev}" "${4:-24444}" "gaaf-${2:-1}" "" "" "${5:-balanced}";;
              *) gaaf_menu;;
            esac
          else err "GAAF module missing"; fi;;
    balancer|bal) shift; if declare -f bal_menu >/dev/null; then
            case "${1:-menu}" in
              menu|"") bal_menu;;
              nodes) bal_list_nodes;;
              pools) bal_list_pools;;
              *) bal_menu;;
            esac
          else err "Balancer module missing"; fi;;
    ui)
      UI_PY="/usr/local/share/seka-tunel/web/api_server.py"
      [[ -f $UI_PY ]] || UI_PY="$(dirname "$0")/web/api_server.py"
      [[ -f $UI_PY ]] || UI_PY="/home/workdir/artifacts/seka-tunel/web/api_server.py"
      if [[ -f $UI_PY ]]; then
        export SEKA_WEB_ROOT="$(dirname "$UI_PY")"
        info "Starting new UI on port ${SEKA_UI_PORT:-8450} ..."
        exec python3 "$UI_PY"
      else
        err "UI backend not found"
      fi;;
    perf)  shift; perf_apply "${1:-}";;
    audit) tail -n "${2:-60}" "$AUDF" 2>/dev/null || info "Audit log is empty.";;
    package) pkg_make;;
    rollback) do_rollback;;
    update) bash <(curl -fsSL https://raw.githubusercontent.com/behymin12345-hash/SEKA TUNEL/main/install.sh);;
    "")    main_menu;;
    *)     echo "Usage: $0 [apply|list|update|rollback|package|perf NAME|audit|conntest|tunnel|reverse|join LINK|kharej|doctor|gaaf|balancer|ui]"; exit 1;;
  esac
fi
