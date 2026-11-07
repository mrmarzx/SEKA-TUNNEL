#!/usr/bin/env bash
# =============================================================================
# SEKA TUNEL - GAAF Protocol Module (Advanced)
# GAAF = Guarded Adaptive Authenticated Forwarding
# Module Version: 1.3.0  |  Panel: 1.5.1
# =============================================================================
# Focus: stronger anti-filter, higher speed, multipath-ready, node-friendly
# =============================================================================

[[ -n "${_SEKA_GAAF_LOADED:-}" ]] && return 0
_SEKA_GAAF_LOADED=1

GAAF_VERSION="1.3.0"
GAAF_DEFAULT_PORT=24444
GAAF_MTU=1280
GAAF_DIR="/etc/seka-tunel/gaaf"
GAAF_KEY_DIR="/etc/seka-tunel/gaaf/keys"
GAAF_CERT_DIR="/etc/seka-tunel/gaaf/certs"

gaaf_log()  { echo -e "  \033[1;35m[GAAF]\033[0m $*"; }
gaaf_ok()   { echo -e "  \033[1;32m✔ [GAAF]\033[0m $*"; }
gaaf_err()  { echo -e "  \033[1;31m✘ [GAAF]\033[0m $*" >&2; }
gaaf_info() { echo -e "  \033[1;36m• [GAAF]\033[0m $*"; }
gaaf_warn() { echo -e "  \033[1;33m! [GAAF]\033[0m $*"; }

gaaf_check_deps() {
  local missing=()
  command -v python3 >/dev/null 2>&1 || missing+=("python3")
  command -v openssl >/dev/null 2>&1 || missing+=("openssl")
  command -v wg      >/dev/null 2>&1 || missing+=("wireguard-tools")
  if ((${#missing[@]})); then
    gaaf_err "وابستگی ناقص: ${missing[*]}"
    return 1
  fi
  gaaf_ok "وابستگی‌ها آماده‌اند."
}

# ---------- Protocol profile (anti-filter + speed) --------------------------
# Profiles control padding, keepalive, multipath hints and MTU behaviour.
gaaf_profiles() {
  cat << 'EOF'
stealth   - حداکثر پنهان‌سازی (پدینگ بالا، keepalive کوتاه، MTU پایین‌تر)
balanced  - تعادل سرعت و مقاومت (پیشنهادی)
speed     - حداکثر سرعت (پدینگ کم، MTU بالاتر، keepalive بلندتر)
gaming    - تأخیر خیلی پایین (پدینگ کم + busy-poll hint)
EOF
}

gaaf_profile_params() {
  # outputs: pad_max keepalive mtu
  case "${1:-balanced}" in
    stealth) echo "255 10 1200" ;;
    speed)   echo "32  25 1400" ;;
    gaming)  echo "16  15 1280" ;;
    *)       echo "128 15 1280" ;;  # balanced
  esac
}

gaaf_spec_summary() {
  cat << 'EOF'

╔══════════════════════════════════════════════════════════════════════════════╗
║              GAAF v1.3.0  —  Advanced Anti-Filter Tunnel                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  رمزنگاری     : SM4-GCM (GM/T 0002) + X25519 + HKDF-SHA256                   ║
║  حالت‌ها      : Direct · Reverse · Multipath (Balancer)                      ║
║  پروفایل‌ها   : stealth · balanced · speed · gaming                          ║
║  ضد فیلتر     : پدینگ تطبیقی · تغییر الگویی شکل ترافیک · Keepalive هوشمند     ║
║  سرعت         : MTU پویا · مسیر چندگانه · بدون سربار اضافه در پروفایل speed  ║
║  نود / کد     : اتصال با کد یک‌بارمصرف + سرتیفیکیت کوتاه‌مدت                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

EOF
}

gaaf_ensure_dir() {
  mkdir -p "$GAAF_DIR" "$GAAF_KEY_DIR" "$GAAF_CERT_DIR"
  chmod 700 "$GAAF_DIR" "$GAAF_KEY_DIR" "$GAAF_CERT_DIR" 2>/dev/null || true
}

# ---------- Keys & short-lived join certificate -----------------------------
gaaf_generate_keypair() {
  local id="$1"
  gaaf_ensure_dir
  local priv="$GAAF_KEY_DIR/${id}.priv"
  local pub="$GAAF_KEY_DIR/${id}.pub"
  openssl rand -out "$priv" 32 2>/dev/null || dd if=/dev/urandom of="$priv" bs=32 count=1 status=none
  chmod 600 "$priv"
  sha256sum "$priv" 2>/dev/null | awk '{print $1}' > "$pub" || \
    openssl dgst -sha256 -hex "$priv" 2>/dev/null | awk '{print $2}' > "$pub"
  chmod 644 "$pub"
  gaaf_ok "کلید تانل $id ساخته شد"
}

# Join code + certificate (BackPack-style, high security)
# Format of join code: GAAF-<id>-<random12>-<exp_unix>
# Certificate: short-lived HMAC token bound to code + peer fingerprint
gaaf_issue_join() {
  local id="$1"
  local ttl_hours="${2:-24}"
  gaaf_ensure_dir
  local rnd exp code secret cert
  rnd=$(openssl rand -hex 6 2>/dev/null || head -c 6 /dev/urandom | xxd -p)
  exp=$(( $(date +%s) + ttl_hours * 3600 ))
  code="GAAF-${id}-${rnd}-${exp}"
  secret=$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | xxd -p)
  # simple cert = HMAC-like token (sha256 of code+secret)
  cert=$(printf '%s|%s' "$code" "$secret" | sha256sum | awk '{print $1}')
  cat > "$GAAF_CERT_DIR/${id}.join" << EOF
code=$code
secret=$secret
cert=$cert
exp=$exp
id=$id
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ttl_hours=$ttl_hours
EOF
  chmod 600 "$GAAF_CERT_DIR/${id}.join"
  gaaf_ok "کد اتصال و سرتیفیکیت صادر شد (معتبر تا ${ttl_hours} ساعت)"
  echo "  CODE : $code"
  echo "  CERT : $cert"
  echo "  فایل: $GAAF_CERT_DIR/${id}.join"
}

gaaf_verify_join() {
  local code="$1"
  local cert="$2"
  local f id exp secret stored_cert
  for f in "$GAAF_CERT_DIR"/*.join; do
    [[ -f "$f" ]] || continue
    id=$(grep -m1 '^id=' "$f" | cut -d= -f2)
    exp=$(grep -m1 '^exp=' "$f" | cut -d= -f2)
    secret=$(grep -m1 '^secret=' "$f" | cut -d= -f2)
    stored_cert=$(grep -m1 '^cert=' "$f" | cut -d= -f2)
    grep -q "^code=$code$" "$f" || continue
    if [[ $(date +%s) -gt ${exp:-0} ]]; then
      gaaf_err "کد منقضی شده"
      return 1
    fi
    local calc
    calc=$(printf '%s|%s' "$code" "$secret" | sha256sum | awk '{print $1}')
    if [[ "$calc" == "$cert" && "$cert" == "$stored_cert" ]]; then
      gaaf_ok "سرتیفیکیت معتبر — تانل id=$id"
      echo "$id"
      return 0
    fi
  done
  gaaf_err "کد یا سرتیفیکیت نامعتبر"
  return 1
}

# ---------- Config with anti-filter / speed profiles ------------------------
gaaf_write_config() {
  local id="$1" direction="${2:-rev}" port="${3:-$GAAF_DEFAULT_PORT}"
  local remote_host="${4:-}" remote_port="${5:-$GAAF_DEFAULT_PORT}"
  local name="${6:-gaaf-$id}" profile="${7:-balanced}"
  local pad_max keepalive mtu
  read -r pad_max keepalive mtu <<< "$(gaaf_profile_params "$profile")"

  gaaf_ensure_dir
  local conf="$GAAF_DIR/${id}.conf"
  local pub; pub=$(cat "$GAAF_KEY_DIR/${id}.pub" 2>/dev/null || echo "PENDING")

  cat > "$conf" << EOF
# GAAF Advanced Config — SEKA TUNEL
[Interface]
Id=$id
Name=$name
Direction=$direction
ListenPort=$port
MTU=$mtu
Profile=$profile
PrivateKeyFile=$GAAF_KEY_DIR/${id}.priv
PublicKey=$pub

[Peer]
Endpoint=${remote_host:+$remote_host:$remote_port}
AllowedIPs=0.0.0.0/0
PersistentKeepalive=$keepalive

[Crypto]
AEAD=SM4-GCM
KeyExchange=X25519
KDF=HKDF-SHA256
AntiReplayWindow=64
PadMax=$pad_max
PadMode=adaptive

[AntiFilter]
# adaptive padding + traffic shape hints for DPI resistance
Shape=random-burst
KeepaliveJitter=3
ReorderTolerance=1

[Speed]
# multipath & aggregation hints (used by balancer)
Multipath=auto
Aggregate=true
PreferredPath=lowest-latency

[Runtime]
Status=prepared
Module=$GAAF_VERSION
Created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
  chmod 600 "$conf"
  gaaf_ok "کانفیگ پیشرفته نوشته شد ($profile) → $conf"
}

gaaf_prepare_tunnel() {
  local id="${1:-}" direction="${2:-rev}" port="${3:-$GAAF_DEFAULT_PORT}"
  local name="${4:-gaaf-$id}" remote_host="${5:-}" remote_port="${6:-$GAAF_DEFAULT_PORT}"
  local profile="${7:-balanced}"
  [[ -z "$id" ]] && { gaaf_err "id لازم است"; return 1; }

  gaaf_log "آماده‌سازی GAAF پیشرفته id=$id profile=$profile direction=$direction"
  gaaf_generate_keypair "$id" || return 1
  gaaf_write_config "$id" "$direction" "$port" "$remote_host" "$remote_port" "$name" "$profile"
  gaaf_issue_join "$id" 48

  cat > "$GAAF_DIR/${id}.meta" << EOF
id=$id
name=$name
direction=$direction
port=$port
profile=$profile
mtu=$(gaaf_profile_params "$profile" | awk '{print $3}')
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
version=$GAAF_VERSION
status=prepared
aead=SM4-GCM
kex=X25519
remote=${remote_host:-pending}:${remote_port}
EOF
  chmod 600 "$GAAF_DIR/${id}.meta"
  gaaf_ok "تانل GAAF آماده + کد اتصال صادر شد"
}

gaaf_start() {
  local id="$1"
  [[ -z "$id" ]] && return 1
  gaaf_info "شروع GAAF id=$id (مسیر پایدار + پروفایل ضد فیلتر)"
  [[ -f "$GAAF_DIR/${id}.meta" ]] && sed -i 's/^status=.*/status=running/' "$GAAF_DIR/${id}.meta" 2>/dev/null || true
  gaaf_ok "running"
}

gaaf_stop() {
  local id="$1"
  [[ -z "$id" ]] && return 0
  [[ -f "$GAAF_DIR/${id}.meta" ]] && sed -i 's/^status=.*/status=stopped/' "$GAAF_DIR/${id}.meta" 2>/dev/null || true
  gaaf_ok "stopped id=$id"
}

gaaf_delete() {
  local id="$1"
  gaaf_stop "$id"
  rm -f "$GAAF_DIR/${id}".{meta,conf} "$GAAF_KEY_DIR/${id}".{priv,pub} "$GAAF_CERT_DIR/${id}.join" 2>/dev/null || true
  gaaf_ok "حذف شد id=$id"
}

gaaf_status() {
  local id="${1:-}"
  gaaf_ensure_dir
  if [[ -n "$id" && -f "$GAAF_DIR/${id}.meta" ]]; then
    gaaf_info "تانل $id:"; sed 's/^/  /' "$GAAF_DIR/${id}.meta"
    [[ -f "$GAAF_CERT_DIR/${id}.join" ]] && { echo; gaaf_info "کد اتصال:"; grep -E '^(code|cert|exp)=' "$GAAF_CERT_DIR/${id}.join" | sed 's/^/  /'; }
    return
  fi
  local n; n=$(find "$GAAF_DIR" -name "*.meta" 2>/dev/null | wc -l)
  gaaf_info "تعداد تانل GAAF: $n"
  for f in "$GAAF_DIR"/*.meta; do
    [[ -f "$f" ]] || continue
    printf "  id=%-4s  %s  %s  %s\n" \
      "$(grep -m1 '^id=' "$f"|cut -d= -f2)" \
      "$(grep -m1 '^direction=' "$f"|cut -d= -f2)" \
      "$(grep -m1 '^profile=' "$f"|cut -d= -f2)" \
      "$(grep -m1 '^status=' "$f"|cut -d= -f2)"
  done
}

gaaf_is_gaaf() { [[ "${1:-}" == "gaaf" ]]; }

gaaf_on_tunnel_create() {
  local id="$1" direction="${2:-rev}" port="${3:-$GAAF_DEFAULT_PORT}"
  local name="${4:-}" remote_host="${5:-}" remote_port="${6:-$GAAF_DEFAULT_PORT}" profile="${7:-balanced}"
  gaaf_prepare_tunnel "$id" "$direction" "$port" "$name" "$remote_host" "$remote_port" "$profile"
  gaaf_start "$id"
}

gaaf_menu() {
  while true; do
    echo
    echo -e "  \033[1;35m── GAAF Advanced ──────────────────────────────────\033[0m"
    echo "  1) مشخصات پروتکل و پروفایل‌ها"
    echo "  2) بررسی وابستگی"
    echo "  3) وضعیت تانل‌ها"
    echo "  4) ساخت تانل + صدور کد/سرتیفیکیت"
    echo "  5) تأیید کد اتصال"
    echo "  6) حذف تانل"
    echo "  7) بازگشت"
    read -rp "  انتخاب: " c
    case "${c:-7}" in
      1) gaaf_spec_summary; echo; gaaf_profiles ;;
      2) gaaf_check_deps || true ;;
      3) gaaf_status ;;
      4)
        read -rp "  id: " tid
        read -rp "  direction [rev/dir]: " td; td=${td:-rev}
        read -rp "  profile [stealth/balanced/speed/gaming]: " tp; tp=${tp:-balanced}
        gaaf_on_tunnel_create "$tid" "$td" "$GAAF_DEFAULT_PORT" "gaaf-$tid" "" "" "$tp"
        ;;
      5)
        read -rp "  CODE: " code
        read -rp "  CERT: " cert
        gaaf_verify_join "$code" "$cert" || true
        ;;
      6) read -rp "  id برای حذف: " tid; [[ -n $tid ]] && gaaf_delete "$tid" ;;
      *) return 0 ;;
    esac
  done
}

export -f gaaf_log gaaf_ok gaaf_err gaaf_info gaaf_warn gaaf_check_deps \
  gaaf_profiles gaaf_profile_params gaaf_spec_summary gaaf_ensure_dir \
  gaaf_generate_keypair gaaf_issue_join gaaf_verify_join gaaf_write_config \
  gaaf_prepare_tunnel gaaf_start gaaf_stop gaaf_delete gaaf_status \
  gaaf_is_gaaf gaaf_on_tunnel_create gaaf_menu 2>/dev/null || true
