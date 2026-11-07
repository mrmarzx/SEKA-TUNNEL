#!/usr/bin/env bash
# SEKA TUNEL - Full connectivity & speed checker
# Checks Iran/Kharej tunnels: IPv4, IPv6, transports, ping, TCP, UDP, speed

[[ -n "${_SEKA_CHECKER_LOADED:-}" ]] && return 0
_SEKA_CHECKER_LOADED=1

chk_log()  { echo -e "  \033[1;36m[CHK]\033[0m $*"; }
chk_ok()   { echo -e "  \033[1;32m✔\033[0m $*"; }
chk_fail() { echo -e "  \033[1;31m✘\033[0m $*"; }
chk_info() { echo -e "  \033[1;33m•\033[0m $*"; }

chk_ping4() {
  local host="$1" count="${2:-4}"
  ping -4 -c "$count" -W 2 "$host" 2>/dev/null | tail -1 | awk -F'/' '{print $5}' | tr -d ' ms'
}

chk_ping6() {
  local host="$1" count="${2:-4}"
  ping -6 -c "$count" -W 2 "$host" 2>/dev/null | tail -1 | awk -F'/' '{print $5}' | tr -d ' ms'
}

chk_tcp() {
  local host="$1" port="$2"
  if command -v python3 >/dev/null; then
    python3 - "$host" "$port" <<'PY'
import socket,sys
host,port=sys.argv[1],int(sys.argv[2])
s=socket.socket(); s.settimeout(3)
try:
  s.connect((host,port)); s.close(); print("ok")
except Exception as e:
  print("fail")
PY
  else
    timeout 3 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && echo ok || echo fail
  fi
}

chk_udp() {
  local host="$1" port="$2"
  if command -v python3 >/dev/null; then
    python3 - "$host" "$port" <<'PY'
import socket,sys
host,port=sys.argv[1],int(sys.argv[2])
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
try:
  s.sendto(b"SEKA", (host,port))
  try:
    s.recvfrom(64); print("ok")
  except socket.timeout:
    print("sent")  # UDP may not reply
except Exception:
  print("fail")
PY
  else
    echo "skip"
  fi
}

chk_speed_down() {
  # rough download sample via cloudflare or httpbin (bytes/sec estimate)
  if command -v curl >/dev/null; then
    local out
    out=$(curl -4 -s -o /dev/null -w '%{speed_download}' --max-time 8 https://speed.cloudflare.com/__down?bytes=2000000 2>/dev/null || echo 0)
    python3 - <<PY 2>/dev/null || echo "$out"
print(round(float("$out")/1024/1024, 2))
PY
  else
    echo "0"
  fi
}

chk_local_ip() {
  echo "IPv4: $(curl -4 -s --max-time 3 ifconfig.me 2>/dev/null || curl -4 -s --max-time 3 icanhazip.com 2>/dev/null || echo unknown)"
  echo "IPv6: $(curl -6 -s --max-time 3 ifconfig.me 2>/dev/null || echo none/disabled)"
}

chk_tunnel_row() {
  local id="$1" fip="$2" port="$3" tr="$4" name="$5"
  echo
  chk_log "تانل #$id  ${name:-?}  $fip:$port  transport=${tr:-udp}"
  if [[ "$fip" == "pending" || -z "$fip" ]]; then
    chk_fail "هنوز join نشده (pending)"
    return
  fi
  local p4 p6 tcp udp
  p4=$(chk_ping4 "$fip" 3)
  if [[ -n "$p4" ]]; then chk_ok "IPv4 ping avg: ${p4} ms"; else chk_fail "IPv4 ping ناموفق"; fi
  p6=$(chk_ping6 "$fip" 2)
  if [[ -n "$p6" ]]; then chk_ok "IPv6 ping avg: ${p6} ms"; else chk_info "IPv6 در دسترس نیست یا مسدود"; fi
  tcp=$(chk_tcp "$fip" "$port")
  [[ "$tcp" == ok ]] && chk_ok "TCP $port باز است" || chk_fail "TCP $port بسته/تایم‌اوت"
  udp=$(chk_udp "$fip" "$port")
  case $udp in
    ok) chk_ok "UDP $port پاسخ داد";;
    sent) chk_info "UDP $port ارسال شد (بدون پاسخ — طبیعی برای بعضی مسیرها)";;
    *) chk_fail "UDP $port ناموفق";;
  esac
  # wireguard handshake if exists
  if command -v wg >/dev/null; then
    local hs
    hs=$(wg show "sekawg$id" latest-handshakes 2>/dev/null | awk '{print $2}')
    if [[ ${hs:-0} -gt 0 ]]; then
      local age=$(( $(date +%s) - hs ))
      chk_ok "WireGuard handshake: ${age}s پیش"
    else
      chk_info "WireGuard handshake ندارد (یا interface نیست)"
    fi
  fi
}

chk_all_tunnels() {
  local TUNF="${TUN:-/etc/seka-tunel/tunnels.conf}"
  banner 2>/dev/null || true
  echo -e "  \033[1m══ چکر کامل تانل‌ها ══\033[0m"
  echo
  chk_info "IP عمومی این سرور:"
  chk_local_ip | sed 's/^/    /'
  echo
  local spd
  spd=$(chk_speed_down)
  chk_info "نمونه سرعت دانلود تقریبی: ${spd} MB/s"
  echo
  if [[ ! -s "$TUNF" ]]; then
    chk_fail "هیچ تانلی در $TUNF ثبت نشده"
    return 1
  fi
  local id fip port tr name
  while IFS='|' read -r id fip port _ _ _ _ _ _ _ _ _ name _ tr _; do
    [[ -z "$id" ]] && continue
    chk_tunnel_row "$id" "$fip" "$port" "${tr:-udp}" "$name"
  done < "$TUNF"
  echo
  chk_log "پایان بررسی"
}

chk_target() {
  local host="$1" ports="${2:-80,443,51820,24444}"
  echo
  chk_log "بررسی هدف: $host"
  local p4; p4=$(chk_ping4 "$host" 4)
  [[ -n $p4 ]] && chk_ok "ping4: ${p4}ms" || chk_fail "ping4 fail"
  local p6; p6=$(chk_ping6 "$host" 2)
  [[ -n $p6 ]] && chk_ok "ping6: ${p6}ms" || chk_info "ping6 unavailable"
  local p
  IFS=',' read -ra arr <<< "$ports"
  for p in "${arr[@]}"; do
    p=$(echo "$p" | tr -d ' ')
    [[ -z $p ]] && continue
    local t; t=$(chk_tcp "$host" "$p")
    [[ $t == ok ]] && chk_ok "TCP $p" || chk_fail "TCP $p"
  done
}

chk_menu() {
  while true; do
    echo
    echo -e "  \033[1;36m── چکر اتصال و سرعت ─────────────────────────────\033[0m"
    echo "  1) بررسی همه تانل‌های ثبت‌شده"
    echo "  2) بررسی یک IP/دامنه سفارشی"
    echo "  3) نمایش IP عمومی سرور (v4/v6)"
    echo "  4) تست سرعت تقریبی"
    echo "  5) بازگشت"
    read -rp "  انتخاب: " c
    case "${c:-5}" in
      1) chk_all_tunnels; read -rp "  Enter..." _ ;;
      2)
        read -rp "  host: " h
        read -rp "  ports [80,443,51820,24444]: " ps; ps=${ps:-80,443,51820,24444}
        chk_target "$h" "$ps"
        read -rp "  Enter..." _
        ;;
      3) chk_local_ip; read -rp "  Enter..." _ ;;
      4) echo "  سرعت ≈ $(chk_speed_down) MB/s"; read -rp "  Enter..." _ ;;
      *) return 0 ;;
    esac
  done
}

export -f chk_log chk_ok chk_fail chk_info chk_ping4 chk_ping6 chk_tcp chk_udp \
  chk_speed_down chk_local_ip chk_tunnel_row chk_all_tunnels chk_target chk_menu 2>/dev/null || true
