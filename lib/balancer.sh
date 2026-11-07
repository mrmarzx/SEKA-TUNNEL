#!/usr/bin/env bash
# =============================================================================
# SEKA TUNEL - Multi-Node Load Balancer Module
# Version: 1.0.0  |  Panel: 1.5.1
# =============================================================================
# Distribute traffic across multiple foreign (kharej) nodes.
# Connection to nodes via short code + certificate (BackPack-style).
# =============================================================================

[[ -n "${_SEKA_BALANCER_LOADED:-}" ]] && return 0
_SEKA_BALANCER_LOADED=1

BAL_DIR="/etc/seka-tunel/balancer"
BAL_NODES="$BAL_DIR/nodes.conf"          # id|name|host|port|weight|status|code_ref
BAL_POOLS="$BAL_DIR/pools.conf"          # pool_id|name|strategy|node_ids(comma)

bal_log()  { echo -e "  \033[1;34m[BAL]\033[0m $*"; }
bal_ok()   { echo -e "  \033[1;32m✔ [BAL]\033[0m $*"; }
bal_err()  { echo -e "  \033[1;31m✘ [BAL]\033[0m $*" >&2; }
bal_info() { echo -e "  \033[1;36m• [BAL]\033[0m $*"; }

bal_ensure() {
  mkdir -p "$BAL_DIR"
  touch "$BAL_NODES" "$BAL_POOLS"
  chmod 700 "$BAL_DIR"
}

# Strategies: round-robin | weighted | lowest-latency | failover
bal_strategies() {
  echo "round-robin | weighted | lowest-latency | failover"
}

# Register a foreign node
bal_add_node() {
  local id="$1" name="$2" host="$3" port="${4:-24444}" weight="${5:-100}"
  bal_ensure
  if grep -q "^${id}|" "$BAL_NODES" 2>/dev/null; then
    bal_err "نود با id=$id از قبل وجود دارد"
    return 1
  fi
  echo "${id}|${name}|${host}|${port}|${weight}|up|" >> "$BAL_NODES"
  bal_ok "نود اضافه شد: $name ($host:$port) weight=$weight"
}

bal_remove_node() {
  local id="$1"
  bal_ensure
  grep -v "^${id}|" "$BAL_NODES" > "${BAL_NODES}.tmp" 2>/dev/null || true
  mv -f "${BAL_NODES}.tmp" "$BAL_NODES"
  bal_ok "نود $id حذف شد"
}

bal_list_nodes() {
  bal_ensure
  echo
  printf "  %-6s %-16s %-22s %-8s %-8s %s\n" "ID" "Name" "Endpoint" "Weight" "Status" "CodeRef"
  printf "  %-6s %-16s %-22s %-8s %-8s %s\n" "------" "----------------" "----------------------" "--------" "--------" "------"
  while IFS='|' read -r id name host port weight status code_ref; do
    [[ -z "$id" || "$id" =~ ^# ]] && continue
    printf "  %-6s %-16s %-22s %-8s %-8s %s\n" "$id" "$name" "${host}:${port}" "$weight" "$status" "${code_ref:--}"
  done < "$BAL_NODES"
  echo
}

# Create a pool (group of nodes under one balancer strategy)
bal_create_pool() {
  local pool_id="$1" name="$2" strategy="${3:-weighted}" node_ids="$4"
  bal_ensure
  if grep -q "^${pool_id}|" "$BAL_POOLS" 2>/dev/null; then
    bal_err "استخر $pool_id از قبل وجود دارد"
    return 1
  fi
  echo "${pool_id}|${name}|${strategy}|${node_ids}" >> "$BAL_POOLS"
  bal_ok "استخر $name ساخته شد (strategy=$strategy)"
}

bal_list_pools() {
  bal_ensure
  echo
  printf "  %-8s %-18s %-16s %s\n" "PoolID" "Name" "Strategy" "Nodes"
  printf "  %-8s %-18s %-16s %s\n" "--------" "------------------" "----------------" "-----"
  while IFS='|' read -r pid name strat nodes; do
    [[ -z "$pid" || "$pid" =~ ^# ]] && continue
    printf "  %-8s %-18s %-16s %s\n" "$pid" "$name" "$strat" "$nodes"
  done < "$BAL_POOLS"
  echo
}

# Pick next node according to strategy (simple implementation)
bal_pick_node() {
  local pool_id="$1"
  local line nodes strat
  line=$(grep "^${pool_id}|" "$BAL_POOLS" 2>/dev/null | head -1)
  [[ -z "$line" ]] && { bal_err "استخر پیدا نشد"; return 1; }
  strat=$(echo "$line" | cut -d'|' -f3)
  nodes=$(echo "$line" | cut -d'|' -f4)
  local first
  first=$(echo "$nodes" | cut -d',' -f1)
  # For weighted / round-robin we just return first healthy for now
  # (full state tracking can be added later)
  local nline
  nline=$(grep "^${first}|" "$BAL_NODES" 2>/dev/null | head -1)
  if [[ -n "$nline" ]]; then
    echo "$nline" | cut -d'|' -f1,3,4
    return 0
  fi
  bal_err "نود سالم در استخر نیست"
  return 1
}

# Generate a single join code that points to a whole pool (client gets balanced)
bal_issue_pool_code() {
  local pool_id="$1"
  local ttl_hours="${2:-24}"
  bal_ensure
  local rnd exp code
  rnd=$(openssl rand -hex 5 2>/dev/null || head -c 5 /dev/urandom | xxd -p)
  exp=$(( $(date +%s) + ttl_hours * 3600 ))
  code="POOL-${pool_id}-${rnd}-${exp}"
  echo "code=$code" > "$BAL_DIR/pool_${pool_id}.code"
  echo "exp=$exp"  >> "$BAL_DIR/pool_${pool_id}.code"
  echo "pool=$pool_id" >> "$BAL_DIR/pool_${pool_id}.code"
  chmod 600 "$BAL_DIR/pool_${pool_id}.code"
  bal_ok "کد استخر صادر شد"
  echo "  CODE : $code"
  echo "  معتبر تا ${ttl_hours} ساعت — کلاینت با این کد به بالانسر وصل می‌شود"
}

bal_menu() {
  while true; do
    echo
    echo -e "  \033[1;34m── Load Balancer / Nodes ───────────────────────────\033[0m"
    echo "  1) لیست نودها"
    echo "  2) افزودن نود"
    echo "  3) حذف نود"
    echo "  4) لیست استخرها (Pools)"
    echo "  5) ساخت استخر"
    echo "  6) صدور کد اتصال استخر"
    echo "  7) بازگشت"
    read -rp "  انتخاب: " c
    case "${c:-7}" in
      1) bal_list_nodes ;;
      2)
        read -rp "  id: " id
        read -rp "  نام: " name
        read -rp "  host: " host
        read -rp "  port [24444]: " port; port=${port:-24444}
        read -rp "  weight [100]: " w; w=${w:-100}
        bal_add_node "$id" "$name" "$host" "$port" "$w"
        ;;
      3) read -rp "  id برای حذف: " id; bal_remove_node "$id" ;;
      4) bal_list_pools ;;
      5)
        read -rp "  pool_id: " pid
        read -rp "  نام استخر: " pname
        read -rp "  strategy [weighted]: " st; st=${st:-weighted}
        read -rp "  لیست id نودها (با کاما): " nids
        bal_create_pool "$pid" "$pname" "$st" "$nids"
        ;;
      6)
        read -rp "  pool_id: " pid
        bal_issue_pool_code "$pid" 48
        ;;
      *) return 0 ;;
    esac
  done
}

export -f bal_log bal_ok bal_err bal_info bal_ensure bal_strategies \
  bal_add_node bal_remove_node bal_list_nodes bal_create_pool bal_list_pools \
  bal_pick_node bal_issue_pool_code bal_menu 2>/dev/null || true
