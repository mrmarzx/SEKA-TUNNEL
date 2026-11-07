#!/usr/bin/env bash
# SEKA TUNEL - Common helpers
# Version: 1.5.1

# Colors (Persian-friendly terminal)
C_RST='\033[0m'
C_BLD='\033[1m'
C_RED='\033[1;31m'
C_GRN='\033[1;32m'
C_YLW='\033[1;33m'
C_BLU='\033[1;34m'
C_MAG='\033[1;35m'
C_CYN='\033[1;36m'

ok()   { echo -e "  ${C_GRN}✔${C_RST} $*"; }
err()  { echo -e "  ${C_RED}✘${C_RST} $*" >&2; }
info() { echo -e "  ${C_CYN}•${C_RST} $*"; }
warn() { echo -e "  ${C_YLW}!${C_RST} $*"; }
title(){ echo -e "\n  ${C_BLD}${C_CYN}$*${C_RST}\n"; }

# Default language preference (Persian first)
SEKA_LANG="${SEKA_LANG:-fa}"

is_root() { [[ $EUID -eq 0 ]]; }

require_root() {
  if ! is_root; then
    err "این دستور باید با دسترسی root اجرا شود."
    exit 1
  fi
}

# Simple banner
seka_banner() {
  echo -e "${C_CYN}${C_BLD}"
  echo "  ╔════════════════════════════════════════════════════╗"
  echo "  ║              S E K A   T U N E L                   ║"
  echo "  ║                   v1.5.1                           ║"
  echo "  ║         Direct · Reverse · GAAF                    ║"
  echo "  ╚════════════════════════════════════════════════════╝${C_RST}"
  echo
}
