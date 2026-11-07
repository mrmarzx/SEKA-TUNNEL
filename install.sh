#!/usr/bin/env bash
# SEKA TUNEL installer / updater
# Version: 1.5.1
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_REPO/SEKA-TUNEL/main/install.sh)
#   bash install.sh join '<https://IRAN_IP:PORT/join/<token>>'   # on Kharej server
set -euo pipefail

REPO="${SEKA_REPO:-YOUR_USER/SEKA-TUNEL}"
BRANCH="${SEKA_BRANCH:-main}"
BASE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
BIN="/usr/local/bin/seka-tunel"
CONF_DIR="/etc/seka-tunel"
DATA_DIR="/var/lib/seka-tunel"

JOIN_LINK=""
if [[ ${1:-} == join ]]; then
  JOIN_LINK="${2:-}"
  [[ -n $JOIN_LINK ]] || { echo "Usage: bash install.sh join '<join link from Iran panel>'"; exit 1; }
fi

# Colors
G='\033[1;32m'; Y='\033[1;33m'; C='\033[1;36m'; R='\033[1;31m'; B='\033[1m'; N='\033[0m'
ok()   { echo -e "  ${G}✔${N} $*"; }
err()  { echo -e "  ${R}✘${N} $*"; }
info() { echo -e "  ${C}•${N} $*"; }
warn() { echo -e "  ${Y}!${N} $*"; }

clear 2>/dev/null || true
echo -e "${C}${B}"
echo "  ┌──────────────────────────────────────────────────────┐"
echo "  │                                                      │"
echo "  │          S E K A   T U N E L   v1.5.1                │"
echo "  │                                                      │"
echo "  │     پنل تانل حرفه‌ای  ·  Direct / Reverse / GAAF     │"
echo "  │                                                      │"
echo "  └──────────────────────────────────────────────────────┘${N}"
echo

[[ $EUID -eq 0 ]] || { err "باید با کاربر root اجرا شود (sudo)."; exit 1; }

# ---- detect package manager -----------------------------------------------
PKG=""
if command -v apt-get >/dev/null 2>&1; then PKG="apt"
elif command -v dnf >/dev/null 2>&1; then PKG="dnf"
elif command -v yum >/dev/null 2>&1; then PKG="yum"
else
  warn "مدیر بسته شناخته‌شده پیدا نشد. ادامه می‌دهیم..."
fi

install_pkg() {
  local pkgs=("$@")
  case $PKG in
    apt) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" ;;
    dnf) dnf install -y "${pkgs[@]}" ;;
    yum) yum install -y "${pkgs[@]}" ;;
    *)   return 1 ;;
  esac
}

# ---- curl -----------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
  info "در حال نصب curl..."
  install_pkg curl || { err "نصب curl ناموفق بود."; exit 1; }
fi

# ---- python3 (for web panel) ----------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  info "در حال نصب python3..."
  install_pkg python3 || warn "python3 نصب نشد. وب‌پنل ممکن است کار نکند."
fi

# ---- create directories ---------------------------------------------------
mkdir -p "$CONF_DIR" "$DATA_DIR" /usr/local/lib/seka-tunel
ok "دایرکتوری‌های پیکربندی ساخته شد."

# ---- download main script -------------------------------------------------
TMP="$(mktemp)"
info "در حال دانلود seka-tunel از مخزن..."

# First try the new repo, fallback to local if developing
if [[ -f /home/workdir/artifacts/seka-tunel/seka-tunel.sh ]]; then
  cp /home/workdir/artifacts/seka-tunel/seka-tunel.sh "$TMP"
  ok "از فایل محلی استفاده شد (حالت توسعه)."
else
  if ! curl -fsSL --retry 3 --retry-delay 2 "${BASE_URL}/seka-tunel.sh" -o "$TMP"; then
    err "دانلود ناموفق بود."
    info "اگر گیت‌هاب مسدود است، فایل seka-tunel.sh را دستی دانلود کنید"
    info "سپس اجرا کنید:  install -m 755 seka-tunel.sh $BIN && $BIN"
    rm -f "$TMP"
    exit 1
  fi
fi

# ---- validate -------------------------------------------------------------
if [[ ! -s $TMP ]] || ! head -1 "$TMP" | grep -qE 'usr/bin/env bash|!/bin/bash'; then
  err "فایل دانلودشده معتبر نیست."
  rm -f "$TMP"
  exit 1
fi

VER="$(grep -m1 -E 'VERSION=|SEKA_VERSION=' "$TMP" | sed -E 's/.*[" ]([0-9]+\.[0-9]+\.[0-9]+).*/\1/' || echo "1.5.1")"

# ---- backup previous version ----------------------------------------------
MODE="install"
if [[ -x $BIN ]]; then
  MODE="update"
  cp -f "$BIN" "${BIN}.bak" 2>/dev/null || true
  ok "نسخه قبلی برای rollback ذخیره شد."
fi

install -m 755 "$TMP" "$BIN"
rm -f "$TMP"
ok "SEKA TUNEL v${VER} در $BIN نصب شد."

# ---- install library modules (GAAF + common) -------------------------------
LIB_DST="/usr/local/lib/seka-tunel"
mkdir -p "$LIB_DST"
if [[ -d /home/workdir/artifacts/seka-tunel/lib ]]; then
  cp -f /home/workdir/artifacts/seka-tunel/lib/*.sh "$LIB_DST/" 2>/dev/null || true
  chmod 755 "$LIB_DST"/*.sh 2>/dev/null || true
  ok "ماژول‌های lib (از جمله GAAF) نصب شدند."

# web UI assets
WEB_DST="/usr/local/share/seka-tunel/web"
mkdir -p "$WEB_DST"
if [[ -d /home/workdir/artifacts/seka-tunel/web ]]; then
  cp -a /home/workdir/artifacts/seka-tunel/web/. "$WEB_DST/" 2>/dev/null || true
  ok "رابط وب جدید (تم نارنجی/آبی) نصب شد."
fi

else
  # try to fetch from repo when not in dev mode
  for mod in common.sh gaaf.sh balancer.sh checker.sh; do
    if curl -fsSL --retry 2 "${BASE_URL}/lib/${mod}" -o "${LIB_DST}/${mod}" 2>/dev/null; then
      chmod 755 "${LIB_DST}/${mod}"
      ok "ماژول ${mod} دانلود و نصب شد."
    fi
  done
fi

# ---- symlink for convenience ----------------------------------------------
ln -sf "$BIN" /usr/local/bin/seka 2>/dev/null || true

if [[ $MODE == update ]]; then
  ok "به‌روزرسانی انجام شد. تنظیمات قبلی حفظ شده‌اند."
  info "در صورت مشکل:  seka-tunel rollback"
else
  ok "نصب اولیه با موفقیت انجام شد."
  echo
  info "منوی اصلی:     seka-tunel   یا   seka"
  info "وب‌پنل:        از داخل منو → گزینه وب‌پنل"
fi

echo
if [[ -n $JOIN_LINK ]]; then
  echo -e "  ${G}${B}در حال اتصال به تانل ایران...${N}"
  echo
  sleep 1
  exec "$BIN" join "$JOIN_LINK"
fi

echo -e "  ${G}${B}تمام. در حال اجرای SEKA TUNEL v${VER}...${N}"
echo
sleep 1
exec "$BIN"
