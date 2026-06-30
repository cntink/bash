#!/usr/bin/env bash
set -Eeuo pipefail

REPO="apernet/hysteria"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

SERVERCHAN_SENDKEY="SCT**********"
SERVERCHAN_URL="https://sctapi.ftqq.com/${SERVERCHAN_SENDKEY}.send"

LOCK_FILE="/run/hysteria2-auto-update.lock"
WORK_DIR="/tmp/hysteria2-auto-update"
STATE_DIR="/var/lib/hysteria2-auto-update"
STATE_FILE="${STATE_DIR}/current_version"
LOG_TAG="hysteria2-auto-update"
MAX_RETRY=3

MIRRORS=(
  "https://gh-proxy.com/"
  "https://ghproxy.net/"
  "https://gh.llkk.cc/"
  "https://ghfast.top/"
  "https://github.moeyy.xyz/"
  ""
)

log() {
  local msg="$*"
  echo "[$(date '+%F %T')] $msg"
  systemd-cat -t "$LOG_TAG" -p info echo "$msg" >/dev/null 2>&1 || true
}

warn() {
  local msg="$*"
  echo "[$(date '+%F %T')] WARNING: $msg" >&2
  systemd-cat -t "$LOG_TAG" -p warning echo "$msg" >/dev/null 2>&1 || true
}

error() {
  local msg="$*"
  echo "[$(date '+%F %T')] ERROR: $msg" >&2
  systemd-cat -t "$LOG_TAG" -p err echo "$msg" >/dev/null 2>&1 || true
}

notify_serverchan() {
  local title="$1"
  local desp="$2"

  curl -fsSL \
    --connect-timeout 8 \
    --max-time 20 \
    --data-urlencode "title=${title}" \
    --data-urlencode "desp=${desp}" \
    "$SERVERCHAN_URL" >/dev/null 2>&1 || true
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    error "缺少命令：$1"
    exit 1
  }
}

prepare_env() {
  need_cmd curl
  need_cmd grep
  need_cmd sed
  need_cmd awk
  need_cmd uname
  need_cmd sha256sum
  need_cmd systemctl
  need_cmd flock
  need_cmd install
  need_cmd mktemp

  mkdir -p "$STATE_DIR"
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
}

cleanup() {
  rm -rf "$WORK_DIR" >/dev/null 2>&1 || true
}

trap cleanup EXIT

detect_hysteria_bin() {
  local candidates=()

  while IFS= read -r service; do
    [[ -z "$service" ]] && continue

    local exec_line
    exec_line="$(systemctl show "$service" -p ExecStart --value 2>/dev/null || true)"

    if echo "$exec_line" | grep -qiE 'hysteria|hysteria2'; then
      local found
      found="$(echo "$exec_line" | grep -oE '/[^ ;"]*(hysteria|hysteria2)[^ ;"]*' | head -n1 || true)"
      if [[ -n "$found" && -x "$found" ]]; then
        candidates+=("$found")
      fi
    fi
  done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei 'hysteria|hysteria2' || true)

  command -v hysteria >/dev/null 2>&1 && candidates+=("$(command -v hysteria)")
  command -v hysteria2 >/dev/null 2>&1 && candidates+=("$(command -v hysteria2)")

  local common_paths=(
    "/usr/local/bin/hysteria"
    "/usr/bin/hysteria"
    "/opt/hysteria/hysteria"
    "/usr/local/bin/hysteria2"
    "/usr/bin/hysteria2"
    "/opt/hysteria/hysteria2"
  )

  local p
  for p in "${common_paths[@]}"; do
    [[ -x "$p" ]] && candidates+=("$p")
  done

  local unique
  unique="$(printf '%s\n' "${candidates[@]:-}" | awk '!seen[$0]++')"

  while IFS= read -r p; do
    [[ -z "$p" ]] && continue

    if "$p" version >/dev/null 2>&1; then
      echo "$p"
      return 0
    fi
  done <<< "$unique"

  error "未能自动找到 hysteria/hysteria2 二进制文件。"
  exit 1
}

detect_hysteria_service() {
  local bin_path="$1"
  local candidates=()

  while IFS= read -r service; do
    [[ -z "$service" ]] && continue
    candidates+=("$service")
  done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei 'hysteria|hysteria2' || true)

  while IFS= read -r service; do
    [[ -z "$service" ]] && continue

    local exec_line
    exec_line="$(systemctl show "$service" -p ExecStart --value 2>/dev/null || true)"

    if echo "$exec_line" | grep -Fq "$bin_path"; then
      candidates+=("$service")
    fi
  done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')

  local unique
  unique="$(printf '%s\n' "${candidates[@]:-}" | awk '!seen[$0]++')"

  while IFS= read -r service; do
    [[ -z "$service" ]] && continue

    if systemctl is-active "$service" >/dev/null 2>&1; then
      echo "$service"
      return 0
    fi
  done <<< "$unique"

  while IFS= read -r service; do
    [[ -z "$service" ]] && continue

    if systemctl is-enabled "$service" >/dev/null 2>&1; then
      echo "$service"
      return 0
    fi
  done <<< "$unique"

  error "未能自动找到 hysteria systemd 服务。"
  exit 1
}

detect_arch_asset() {
  local machine
  machine="$(uname -m)"

  case "$machine" in
    x86_64|amd64)
      if grep -qm1 -w avx /proc/cpuinfo 2>/dev/null; then
        echo "hysteria-linux-amd64-avx"
      else
        echo "hysteria-linux-amd64"
      fi
      ;;
    aarch64|arm64)
      echo "hysteria-linux-arm64"
      ;;
    armv7l|armv7)
      echo "hysteria-linux-arm"
      ;;
    armv5*)
      echo "hysteria-linux-armv5"
      ;;
    i386|i686)
      echo "hysteria-linux-386"
      ;;
    mipsel|mipsle)
      echo "hysteria-linux-mipsle"
      ;;
    s390x)
      echo "hysteria-linux-s390x"
      ;;
    *)
      error "不支持的系统架构：$machine"
      exit 1
      ;;
  esac
}

get_installed_version() {
  local bin_path="$1"

  "$bin_path" version 2>/dev/null | grep -Eo 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true
}

normalize_version() {
  local v="$1"
  v="${v#app/}"
  v="${v#v}"
  echo "$v"
}

fetch_latest_info() {
  local json="$WORK_DIR/latest.json"

  curl -fsSL \
    --connect-timeout 10 \
    --max-time 30 \
    --retry 3 \
    --retry-delay 2 \
    "$API_URL" -o "$json"

  local tag
  tag="$(grep -m1 '"tag_name"' "$json" | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)"

  [[ -n "$tag" ]] || {
    error "无法解析 GitHub 最新版本 tag。"
    return 1
  }

  echo "$tag"
}

asset_exists_in_release() {
  local asset="$1"
  local json="$WORK_DIR/latest.json"

  grep -q "\"name\"[[:space:]]*:[[:space:]]*\"${asset}\"" "$json"
}

speed_test_url() {
  local url="$1"
  local speed

  speed="$(
    curl -L \
      --range 0-1048575 \
      --connect-timeout 5 \
      --max-time 12 \
      -o /dev/null \
      -w '%{speed_download}' \
      -s \
      "$url" 2>/dev/null || echo 0
  )"

  printf '%.0f\n' "$speed" 2>/dev/null || echo 0
}

choose_fastest_prefix() {
  local url="$1"
  local best_prefix=""
  local best_speed=0
  local prefix speed name

  for prefix in "${MIRRORS[@]}"; do
    speed="$(speed_test_url "${prefix}${url}")"

    if [[ -z "$prefix" ]]; then
      name="原始 GitHub"
    else
      name="$prefix"
    fi

    # 关键修复：日志输出到 stderr，避免污染函数返回值
    echo "[$(date '+%F %T')] 测速 ${name}: ${speed} bytes/s" >&2
    systemd-cat -t "$LOG_TAG" -p info echo "测速 ${name}: ${speed} bytes/s" >/dev/null 2>&1 || true

    if (( speed > best_speed )); then
      best_speed="$speed"
      best_prefix="$prefix"
    fi
  done

  if (( best_speed <= 0 )); then
    error "全部下载源测速失败。"
    return 1
  fi

  if [[ -z "$best_prefix" ]]; then
    echo "[$(date '+%F %T')] 选择下载源：原始 GitHub" >&2
    systemd-cat -t "$LOG_TAG" -p info echo "选择下载源：原始 GitHub" >/dev/null 2>&1 || true
  else
    echo "[$(date '+%F %T')] 选择下载源：$best_prefix" >&2
    systemd-cat -t "$LOG_TAG" -p info echo "选择下载源：$best_prefix" >/dev/null 2>&1 || true
  fi

  # 函数唯一 stdout：只返回 prefix
  printf '%s' "$best_prefix"
}

download_with_prefix() {
  local prefix="$1"
  local url="$2"
  local output="$3"

  curl -fL \
    --connect-timeout 10 \
    --max-time 240 \
    --retry 3 \
    --retry-delay 3 \
    -o "$output" \
    "${prefix}${url}"
}

verify_sha256() {
  local asset="$1"
  local bin_file="$2"
  local hashes_file="$WORK_DIR/hashes.txt"
  local line expected actual

  [[ -s "$hashes_file" ]] || {
    error "hashes.txt 不存在或为空。"
    return 1
  }

  [[ -s "$bin_file" ]] || {
    error "新二进制不存在或为空：$bin_file"
    return 1
  }

  # Hysteria 的 hashes.txt 格式可能是：
  # sha256:<hash>  <filename>
  # <hash>  <filename>
  # <filename>: <hash>
  #
  # 这里不用宽泛 grep，避免 hysteria-linux-arm64 匹配到其他相邻行或错误上下文。
  line="$(
    awk -v a="$asset" '
      {
        # 精确边界匹配文件名：
        # 前后不能是字母、数字、点、下划线、横杠
        pattern = "(^|[^A-Za-z0-9._-])" a "([^A-Za-z0-9._-]|$)"
        if ($0 ~ pattern) {
          print
          exit
        }
      }
    ' "$hashes_file"
  )"

  if [[ -z "$line" ]]; then
    error "hashes.txt 中找不到资产行：$asset"
    error "hashes.txt 内容如下："
    sed -n '1,120p' "$hashes_file" >&2 || true
    return 1
  fi

  expected="$(printf '%s\n' "$line" | grep -Eo '[a-fA-F0-9]{64}' | head -n1 || true)"

  if [[ -z "$expected" ]]; then
    error "资产行中没有解析到 SHA256：$line"
    return 1
  fi

  actual="$(sha256sum "$bin_file" | awk '{print $1}')"

  log "SHA256 资产行：$line"
  log "SHA256 期望值：$expected"
  log "SHA256 实际值：$actual"

  if [[ "$actual" != "$expected" ]]; then
    error "SHA256 校验失败。expected=$expected actual=$actual"
    return 1
  fi

  log "SHA256 校验通过。"
}

verify_new_binary() {
  local bin_file="$1"

  [[ -s "$bin_file" ]] || {
    error "新二进制不存在或为空：$bin_file"
    return 1
  }

  chmod +x "$bin_file"

  if ! "$bin_file" version >/dev/null 2>&1; then
    error "新二进制无法执行。"
    return 1
  fi

  log "新二进制执行测试通过：$("$bin_file" version 2>/dev/null | head -n1)"
}

service_health_check() {
  local service="$1"
  local bin_path="$2"
  local expected_version="$3"
  local current_version current_norm expected_norm

  sleep 3

  if ! systemctl is-active --quiet "$service"; then
    error "服务未处于 active 状态：$service"
    return 1
  fi

  if ! "$bin_path" version >/dev/null 2>&1; then
    error "更新后的二进制执行异常：$bin_path"
    return 1
  fi

  current_version="$(get_installed_version "$bin_path")"
  current_norm="$(normalize_version "$current_version")"
  expected_norm="$(normalize_version "$expected_version")"

  if [[ "$current_norm" != "$expected_norm" ]]; then
    error "版本检查失败：当前=$current_version，期望=$expected_version"
    return 1
  fi

  log "服务状态检查通过：$service active，版本=$current_version"
}

restart_service() {
  local service="$1"

  systemctl daemon-reload || true
  systemctl restart "$service"
}

rollback_binary() {
  local backup="$1"
  local bin_path="$2"
  local service="$3"

  if [[ -f "$backup" ]]; then
    warn "开始回滚旧二进制：$backup -> $bin_path"
    install -m 0755 "$backup" "$bin_path"
    systemctl restart "$service" || true
  fi
}

do_update_once() {
  local bin_path="$1"
  local service="$2"
  local latest_tag="$3"
  local asset="$4"

  local download_url="https://github.com/${REPO}/releases/download/${latest_tag}/${asset}"
  local hashes_url="https://github.com/${REPO}/releases/download/${latest_tag}/hashes.txt"
  local prefix
  local new_bin="$WORK_DIR/$asset"
  local backup="${bin_path}.bak.$(date '+%Y%m%d%H%M%S')"

  prefix="$(choose_fastest_prefix "$download_url")" || return 1

  log "下载 hashes.txt"
  download_with_prefix "$prefix" "$hashes_url" "$WORK_DIR/hashes.txt" || return 1

  log "下载新版本：${prefix}${download_url}"
  download_with_prefix "$prefix" "$download_url" "$new_bin" || return 1

  verify_sha256 "$asset" "$new_bin" || return 1
  verify_new_binary "$new_bin" || return 1

  cp -a "$bin_path" "$backup" || return 1
  log "已备份旧二进制：$backup"

  install -m 0755 "$new_bin" "$bin_path" || {
    error "替换二进制失败。"
    return 1
  }

  log "已替换二进制：$bin_path"

  if ! restart_service "$service"; then
    error "服务重启失败。"
    rollback_binary "$backup" "$bin_path" "$service"
    return 1
  fi

  if ! service_health_check "$service" "$bin_path" "$latest_tag"; then
    rollback_binary "$backup" "$bin_path" "$service"
    return 1
  fi

  echo "$latest_tag" > "$STATE_FILE"
  log "更新成功：$latest_tag"
}

main() {
  exec 9>"$LOCK_FILE"

  if ! flock -n 9; then
    log "已有更新任务运行中，本次退出。"
    exit 0
  fi

  prepare_env

  local bin_path service asset installed_version latest_tag installed_norm latest_norm
  local attempt
  local host_info

  host_info="$(
    {
      echo "主机名：$(hostname)"
      echo "时间：$(date '+%F %T')"
      echo "系统：$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)"
      echo "内核：$(uname -a)"
    } 2>/dev/null
  )"

  bin_path="$(detect_hysteria_bin)"
  service="$(detect_hysteria_service "$bin_path")"
  asset="$(detect_arch_asset)"

  log "自动识别二进制路径：$bin_path"
  log "自动识别 systemd 服务：$service"
  log "自动匹配下载资产：$asset"

  latest_tag="$(fetch_latest_info)" || {
    notify_serverchan "Hysteria2 自动更新失败" "无法获取 GitHub 最新版本。

$host_info"
    exit 1
  }

  if ! asset_exists_in_release "$asset"; then
    error "最新 release 中不存在资产：$asset"
    notify_serverchan "Hysteria2 自动更新失败" "最新 release 中不存在资产：$asset

$host_info"
    exit 1
  fi

  installed_version="$(get_installed_version "$bin_path")"
  installed_norm="$(normalize_version "$installed_version")"
  latest_norm="$(normalize_version "$latest_tag")"

  log "当前版本：${installed_version:-unknown}"
  log "最新版本：$latest_tag"

  if [[ -n "$installed_norm" && "$installed_norm" == "$latest_norm" ]]; then
    log "当前已是最新版本，无需更新。"
    echo "$latest_tag" > "$STATE_FILE"
    exit 0
  fi

  log "检测到需要更新：${installed_version:-unknown} -> $latest_tag"

  for attempt in $(seq 1 "$MAX_RETRY"); do
    log "开始第 ${attempt}/${MAX_RETRY} 次更新尝试。"

    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    fetch_latest_info >/dev/null || true

    if do_update_once "$bin_path" "$service" "$latest_tag" "$asset"; then
      notify_serverchan "Hysteria2 自动更新成功" "Hysteria2 已自动更新成功。

当前版本：$latest_tag
二进制路径：$bin_path
服务名称：$service
下载资产：$asset

$host_info"
      exit 0
    fi

    warn "第 ${attempt}/${MAX_RETRY} 次更新失败。"

    if (( attempt < MAX_RETRY )); then
      sleep 10
    fi
  done

  error "连续 ${MAX_RETRY} 次更新失败。"

  local status_text
  status_text="$(systemctl status "$service" --no-pager -l 2>&1 | tail -n 80 || true)"

  notify_serverchan "Hysteria2 自动更新失败" "Hysteria2 自动更新连续 ${MAX_RETRY} 次失败，已停止继续尝试。

当前版本：${installed_version:-unknown}
目标版本：$latest_tag
二进制路径：$bin_path
服务名称：$service
下载资产：$asset

主机信息：
$host_info

服务状态：
$status_text"

  exit 1
}

main "$@"
