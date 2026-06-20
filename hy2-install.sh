#!/bin/bash

# 定义颜色变量用于终端输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无色

# 定义全局变量
LOG_FILE="/var/log/install_hysteria.log"
LOG_MAX_SIZE=$((5 * 1024 * 1024)) # 日志最大 5MB
BACKUP_DIR="/var/backups/hysteria"
CONFIG_DIR="/etc/hysteria"
CERT_DIR="/etc/ssl/certs"
ACME_SH="$HOME/.acme.sh/acme.sh"
SCRIPT_LANG=""
APT_UPDATED=false
CONFIG_FILE="$CONFIG_DIR/config.yaml"
SERVICE_NAME="hysteria"
SYSTEMD_SERVICE="/etc/systemd/system/$SERVICE_NAME.service"
HYSTERIA_SERVICES=("hysteria" "hysteria-server")
HYSTERIA_PASSWORD=""
HYSTERIA_ENABLE_OBFS="false"
HYSTERIA_OBFS_PASSWORD=""
HYSTERIA_OBFS_PROMPTED="false"
HYSTERIA_PORT_HOP_ENABLED="false"
HYSTERIA_PORT_RANGE=""
HYSTERIA_HOP_INTERVAL="300"
EXISTING_DOMAIN=""
EXISTING_CERT_PATH=""
EXISTING_KEY_PATH=""
EXISTING_MAIN_PORT=""
EXISTING_PASSWORD=""
EXISTING_MASQUERADE_URL=""
EXISTING_OBFS_ENABLED="false"
EXISTING_OBFS_PASSWORD=""

# 检查是否以 root 用户运行
check_root() {
  [[ $EUID -ne 0 ]] && { echo -e "${RED}Error: Please run this script as root!${NC}"; exit 1; }
}

# 初始化日志文件并检查权限
init_logging() {
  local log_dir=$(dirname "$LOG_FILE")
  mkdir -p "$log_dir" || { echo -e "${RED}Cannot create log directory $log_dir${NC}"; exit 1; }
  touch "$LOG_FILE" 2>/dev/null || { echo -e "${RED}Cannot create log file $LOG_FILE${NC}"; exit 1; }
  chmod 644 "$LOG_FILE"
  chown root:root "$LOG_FILE" 2>/dev/null || log "Warning: Failed to set log file ownership / 警告：无法设置日志文件所有权" "$YELLOW"
}

# 日志记录函数，支持轮转
log() {
  local message="$1"
  local color="${2:-$NC}"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  local display_message="$message"
  if [[ "$message" == *" / "* ]]; then
    if [[ "$SCRIPT_LANG" == "en" ]]; then
      display_message="${message%% / *}"
    else
      display_message="${message#* / }"
    fi
  fi
  if [[ -f "$LOG_FILE" ]]; then
    local log_date=$(stat -c %Y "$LOG_FILE" 2>/dev/null || echo 0)
    local current_date=$(date +%s)
    if [[ $log_date -ne 0 && $(( (current_date - log_date) / 86400 )) -ge 1 || $(stat -c%s "$LOG_FILE") -ge $LOG_MAX_SIZE ]]; then
      mv "$LOG_FILE" "${LOG_FILE}.$(date '+%Y%m%d%H%M%S').bak"
      touch "$LOG_FILE"
      chmod 644 "$LOG_FILE"
      chown root:root "$LOG_FILE" 2>/dev/null || log "Warning: Failed to set log file ownership / 警告：无法设置日志文件所有权" "$YELLOW"
      echo "$timestamp - ${YELLOW}$(get_msg log_rotated)${NC}" >> "$LOG_FILE"
    fi
  fi
  echo -e "$timestamp - ${color}${display_message}${NC}" | tee -a "$LOG_FILE" >&2
}

# 检查磁盘空间
check_disk_space() {
  local required_space=100
  local available_space=$(df -m / | tail -1 | awk '{print $4}')
  if [[ "$available_space" -lt "$required_space" ]]; then
    log "Error: Insufficient disk space ($available_space MB available, $required_space MB required) / 错误：磁盘空间不足 ($available_space MB 可用，需 $required_space MB)" "$RED"
    exit 1
  fi
}

# 语言选择函数
select_language() {
  clear
  echo -e "${RED}Select language / 请选择语言:${NC}"
  echo -e "${GREEN}1) Chinese / 中文${NC}"
  echo -e "${GREEN}2) English / 英文${NC}"
  read -p "Enter option (1/2) / 输入选项 (1/2): " lang_choice
  case "$lang_choice" in
    1) SCRIPT_LANG="zh" ;;
    2) SCRIPT_LANG="en" ;;
    *) SCRIPT_LANG="zh" ; log "$(get_msg invalid_lang)" "$YELLOW" ;;
  esac
  log "$(get_msg using_lang): $SCRIPT_LANG" "$GREEN"
}

# 定义语言提示
declare -A MESSAGES
# 中文提示
MESSAGES[zh_input_domain]="请输入域名: "
MESSAGES[zh_input_email]="域名证书申请邮箱 (默认自动生成): "
MESSAGES[zh_input_port]="主端口 (默认 443): "
MESSAGES[zh_input_range]="端口跳跃范围 (默认 40000-62000): "
MESSAGES[zh_input_url]="伪装 URL (默认 https://wx.qq.com): "
MESSAGES[zh_input_pwd]="密码 (默认生成 UUID): "
MESSAGES[zh_input_hop]="端口跳跃间隔 (秒, 默认 30): "
MESSAGES[zh_input_proxy_addr]="请输入代理地址 (默认 127.0.0.1:1080): "
MESSAGES[zh_input_proxy_user]="请输入代理服务器用户名 (默认 cntink): "
MESSAGES[zh_input_proxy_pass]="请输入代理服务器密码 (默认 cntink): "
MESSAGES[zh_confirm_split]="是否启用分流？(默认 N)\n${GREEN}y) 是${NC}\n${GREEN}N) 否${NC}\n输入选项 (y/N): "
MESSAGES[zh_select_cert]="选择证书申请方式:\n${GREEN}1) 独立模式${NC}\n${GREEN}2) Cloudflare DNS${NC}\n${GREEN}3) 阿里云 DNS${NC}\n选项 (1/2/3): "
MESSAGES[zh_confirm_uninstall]="检测到已有 Hysteria2，是否卸载旧版本？(默认 Y)\n${GREEN}Y) 是${NC}\n${GREEN}n) 否${NC}\n输入选项 (Y/n): "
MESSAGES[zh_confirm_backup]="是否备份旧版本配置？(默认 N)\n${GREEN}y) 是${NC}\n${GREEN}N) 否${NC}\n输入选项 (y/N): "
MESSAGES[zh_confirm_reissue]="现有证书剩余 %d 天，是否重新获取？(默认 N)\n${GREEN}y) 是${NC}\n${GREEN}N) 否${NC}\n输入选项 (y/N): "
MESSAGES[zh_err_root]="错误：请以 root 用户运行此脚本！"
MESSAGES[zh_err_domain_format]="错误：域名格式无效！"
MESSAGES[zh_err_domain_resolution]="错误：域名解析失败或与本地 IP 不匹配！"
MESSAGES[zh_err_ssl]="错误：OpenSSL 或 CA 证书安装失败！"
MESSAGES[zh_err_cert]="错误：无法解析证书有效期，请检查文件 %s"
MESSAGES[zh_err_proxy_addr]="错误：代理地址格式无效！必须为 地址:端口，端口范围 1-65535"
MESSAGES[zh_check_deps]="检查并安装依赖项..."
MESSAGES[zh_update_index]="更新包索引..."
MESSAGES[zh_install_dep]="安装依赖 %s..."
MESSAGES[zh_install_opt_dep]="安装可选依赖 %s..."
MESSAGES[zh_err_install]="错误：安装 %s 失败！详情：%s"
MESSAGES[zh_warn_install]="警告：安装 %s 失败，但将继续执行..."
MESSAGES[zh_deps_done]="依赖检查完成"
MESSAGES[zh_log_rotated]="日志已轮转"
MESSAGES[zh_invalid_lang]="无效选项，默认使用中文"
MESSAGES[zh_using_lang]="使用语言"
MESSAGES[zh_backup_uninstall]="备份并卸载旧版本..."
MESSAGES[zh_backup_done]="旧配置已备份至: %s"
MESSAGES[zh_config_firewall]="配置防火墙规则..."
MESSAGES[zh_check_ssl]="检查 SSL 证书环境..."
MESSAGES[zh_ssl_ok]="SSL 证书环境有效"
MESSAGES[zh_ssl_ca_missing]="警告：未找到 CA 证书文件 %s，正在安装..."
MESSAGES[zh_ssl_ca_invalid]="警告：CA 证书可能无效，正在更新..."
MESSAGES[zh_download_hy2]="下载 Hysteria2 (%d/%d)..."
MESSAGES[zh_create_service]="创建服务..."
MESSAGES[zh_check_health]="检查服务健康状态..."
MESSAGES[zh_service_ok]="服务正常运行"
MESSAGES[zh_install_done]="安装完成！配置文件位于: %s"
MESSAGES[zh_service_exists]="检测到 Hysteria2 服务已存在，请选择操作:\n${GREEN}1) 管理服务${NC}\n${GREEN}2) 安装新 Hysteria2${NC}\n${GREEN}3) 卸载 Hysteria2${NC}\n${GREEN}0) 退出脚本${NC}"
MESSAGES[zh_manage_menu]="请选择管理操作:\n${GREEN}1) 查看服务状态${NC}\n${GREEN}2) 查看最近 30 条日志${NC}\n${GREEN}3) 重启服务${NC}\n${GREEN}4) 停止服务${NC}\n${GREEN}5) 显示配置信息${NC}\n${GREEN}6) 查看证书到期时间${NC}\n${GREEN}7) 手动续期证书${NC}\n${GREEN}8) 热升级 Hysteria2 核心${NC}\n${GREEN}0) 返回上级菜单${NC}"
MESSAGES[zh_service_status]="Hysteria2 服务状态:"
MESSAGES[zh_service_logs]="Hysteria2 服务最近 30 条日志:"
MESSAGES[zh_service_restart]="正在重启 Hysteria2 服务..."
MESSAGES[zh_service_stop]="正在停止 Hysteria2 服务..."
MESSAGES[zh_service_config]="Hysteria2 服务配置信息:"
MESSAGES[zh_continue_prompt]="按回车返回管理菜单..."
MESSAGES[zh_input_option]="输入选项 (0-3): "
MESSAGES[zh_input_manage_option]="输入选项 (0-8): "
# 英文提示
MESSAGES[en_input_domain]="Please enter the domain: "
MESSAGES[en_input_email]="Email for certificate application (default auto-generated): "
MESSAGES[en_input_port]="Main port (default 443): "
MESSAGES[en_input_range]="Port hopping range (default 40000-62000): "
MESSAGES[en_input_url]="Masquerade URL (default https://wx.qq.com): "
MESSAGES[en_input_pwd]="Password (default UUID generated): "
MESSAGES[en_input_hop]="Port hopping interval (seconds, default 30): "
MESSAGES[en_input_proxy_addr]="Please enter the proxy address (default 127.0.0.1:1080): "
MESSAGES[en_input_proxy_user]="Please enter the proxy server username (default cntink): "
MESSAGES[en_input_proxy_pass]="Please enter the proxy server password (default cntink): "
MESSAGES[en_confirm_split]="Enable traffic splitting? (default N)\n${GREEN}y) Yes${NC}\n${GREEN}N) No${NC}\nEnter option (y/N): "
MESSAGES[en_select_cert]="Select certificate issuance method:\n${GREEN}1) Standalone${NC}\n${GREEN}2) Cloudflare${NC}\n${GREEN}3) Aliyun${NC}\nOption (1/2/3): "
MESSAGES[en_confirm_uninstall]="Existing Hysteria2 detected, uninstall old version? (default Y)\n${GREEN}Y) Yes${NC}\n${GREEN}n) No${NC}\nEnter option (Y/n): "
MESSAGES[en_confirm_backup]="Backup old version config? (default N)\n${GREEN}y) Yes${NC}\n${GREEN}N) No${NC}\nEnter option (y/N): "
MESSAGES[en_confirm_reissue]="Current certificate has %d days remaining, reissue? (default N)\n${GREEN}y) Yes${NC}\n${GREEN}N) No${NC}\nEnter option (y/N): "
MESSAGES[en_err_root]="Error: Please run this script as root!"
MESSAGES[en_err_domain_format]="Error: Invalid domain format!"
MESSAGES[en_err_domain_resolution]="Error: Domain resolution failed or does not match local IP!"
MESSAGES[en_err_ssl]="Error: Failed to install OpenSSL or CA certificates!"
MESSAGES[en_err_cert]="Error: Unable to parse certificate validity, check file %s"
MESSAGES[en_err_proxy_addr]="Error: Invalid proxy address format! Must be host:port, port range 1-65535"
MESSAGES[en_check_deps]="Checking and installing dependencies..."
MESSAGES[en_update_index]="Updating package index..."
MESSAGES[en_install_dep]="Installing dependency %s..."
MESSAGES[en_install_opt_dep]="Installing optional dependency %s..."
MESSAGES[en_err_install]="Error: Failed to install %s! Details: %s"
MESSAGES[en_warn_install]="Warning: Failed to install %s, but continuing..."
MESSAGES[en_deps_done]="Dependencies check completed"
MESSAGES[en_log_rotated]="Log rotated"
MESSAGES[en_invalid_lang]="Invalid choice, defaulting to Chinese"
MESSAGES[en_using_lang]="Using language"
MESSAGES[en_backup_uninstall]="Backing up and uninstalling old version..."
MESSAGES[en_backup_done]="Old config backed up to: %s"
MESSAGES[en_config_firewall]="Configuring firewall rules..."
MESSAGES[en_check_ssl]="Checking SSL certificate environment..."
MESSAGES[en_ssl_ok]="SSL certificate environment is valid"
MESSAGES[en_ssl_ca_missing]="Warning: CA certificate file %s not found, installing..."
MESSAGES[en_ssl_ca_invalid]="Warning: CA certificate may be invalid, updating..."
MESSAGES[en_download_hy2]="Downloading Hysteria2 (%d/%d)..."
MESSAGES[en_create_service]="Creating service..."
MESSAGES[en_check_health]="Checking service health..."
MESSAGES[en_service_ok]="Service running normally"
MESSAGES[en_install_done]="Installation completed! Config file located at: %s"
MESSAGES[en_service_exists]="Hysteria2 service detected, choose action:\n${GREEN}1) Manage service${NC}\n${GREEN}2) Install new Hysteria2${NC}\n${GREEN}3) Uninstall Hysteria2${NC}\n${GREEN}0) Exit script${NC}"
MESSAGES[en_manage_menu]="Select management action:\n${GREEN}1) View service status${NC}\n${GREEN}2) View last 30 log entries${NC}\n${GREEN}3) Restart service${NC}\n${GREEN}4) Stop service${NC}\n${GREEN}5) Show config info${NC}\n${GREEN}6) View certificate expiry${NC}\n${GREEN}7) Renew certificate now${NC}\n${GREEN}8) Hot upgrade Hysteria2 core${NC}\n${GREEN}0) Return to previous menu${NC}"
MESSAGES[en_service_status]="Hysteria2 service status:"
MESSAGES[en_service_logs]="Last 30 log entries for Hysteria2 service:"
MESSAGES[en_service_restart]="Restarting Hysteria2 service..."
MESSAGES[en_service_stop]="Stopping Hysteria2 service..."
MESSAGES[en_service_config]="Hysteria2 service configuration info:"
MESSAGES[en_continue_prompt]="Press Enter to return to the management menu..."
MESSAGES[en_input_option]="Enter option (0-3): "
MESSAGES[en_input_manage_option]="Enter option (0-8): "

# 获取语言特定消息
get_msg() {
  local key="$1"
  shift
  printf "${MESSAGES[${SCRIPT_LANG}_${key}]}" "$@"
}

i18n() {
  local zh="$1" en="$2"
  if [[ "$SCRIPT_LANG" == "en" ]]; then
    printf "%s" "$en"
  else
    printf "%s" "$zh"
  fi
}

log_i18n() {
  local zh="$1" en="$2" color="${3:-$NC}"
  log "$(i18n "$zh" "$en")" "$color"
}

read_yes_no() {
  local prompt="$1" default_answer="$2" answer
  while true; do
    read -p "$prompt" answer
    answer=${answer:-$default_answer}
    case "$answer" in
      Y|y|N|n) echo "$answer"; return 0 ;;
      *) log_i18n "错误：请输入 y 或 n" "Error: Enter y or n" "$RED" ;;
    esac
  done
}

# 更新包索引
update_package_index() {
  if ! $APT_UPDATED; then
    log "$(get_msg update_index)" "$BLUE"
    timeout 300 apt update &>/tmp/apt_update.log || log "Warning: Failed to update package index, details in /tmp/apt_update.log / 警告：更新包索引失败，详情见 /tmp/apt_update.log" "$YELLOW"
    APT_UPDATED=true
  fi
}

# 检查并安装依赖项
check_dependencies() {
  local required_deps=("curl" "wget" "jq" "iptables" "dnsutils" "uuid-runtime")
  local optional_deps=("ip6tables" "netfilter-persistent")
  log "$(get_msg check_deps)" "$BLUE"

  update_package_index

  for dep in "${required_deps[@]}"; do
    if ! dpkg -s "$dep" &>/dev/null; then
      log "$(get_msg install_dep "$dep")" "$BLUE"
      timeout 300 apt install -y "$dep" &>/tmp/apt_install.log || {
        log "$(get_msg err_install "$dep" "$(cat /tmp/apt_install.log)")" "$RED"
        exit 1
      }
    fi
  done

  for dep in "${optional_deps[@]}"; do
    if ! dpkg -s "$dep" &>/dev/null; then
      log "$(get_msg install_opt_dep "$dep")" "$BLUE"
      timeout 300 apt install -y "$dep" &>/tmp/apt_install.log || log "$(get_msg warn_install "$dep")" "$YELLOW"
    fi
  done
  log "$(get_msg deps_done)" "$GREEN"
}

# 验证域名格式
validate_domain_format() {
  local domain="$1"
  local labels label
  [[ ${#domain} -le 253 && "$domain" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$ ]] || return 1
  IFS=. read -ra labels <<< "$domain"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
    [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
  return 0
}

validate_email() {
  local email="$1"
  [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

validate_url() {
  local url="$1"
  [[ "$url" =~ ^https?://[^[:space:]]+$ ]]
}

validate_hysteria_secret() {
  local secret="$1"
  [[ "$secret" =~ ^[^[:space:]@:/?#\[\]]{6,128}$ ]]
}

validate_proxy_credential() {
  local credential="$1"
  [[ "$credential" =~ ^[A-Za-z0-9._-]{1,128}$ ]]
}

validate_non_empty_no_space() {
  local value="$1"
  [[ -n "$value" && ! "$value" =~ [[:space:]] ]]
}

validate_hop_interval() {
  local interval="$1"
  [[ "$interval" =~ ^[0-9]+$ && "$interval" -ge 1 && "$interval" -le 86400 ]]
}

# 验证域名解析是否匹配本地公网 IP
validate_domain_resolution() {
  local domain="$1"
  local server_ip=$(dig +short "$domain" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
  local local_ip=$(curl -s --connect-timeout 10 http://api4.ipify.org/)
  if [[ -z "$server_ip" || -z "$local_ip" ]]; then
    log "Error: Failed to resolve domain or fetch local IP / 错误：无法解析域名或获取本地 IP" "$RED"
    return 1
  fi
  if ! echo "$server_ip" | grep -q "$local_ip"; then
    log "Error: Domain resolves to $server_ip, but local IP is $local_ip / 错误：域名解析为 $server_ip，但本地 IP 为 $local_ip" "$RED"
    choice=$(read_yes_no "$(i18n "是否继续？(y/N): " "Continue anyway? (y/N): ")" "N")
    [[ "$choice" =~ ^[Yy]$ ]] || return 1
  fi
  return 0
}

# 获取用户输入的域名并验证
get_domain() {
  while true; do
    read -p "$(get_msg input_domain)" domain
    if ! validate_domain_format "$domain"; then
      echo -e "${RED}$(get_msg err_domain_format)${NC}"
      log "$(get_msg err_domain_format)" "$RED"
      continue
    fi
    if ! validate_domain_resolution "$domain"; then
      echo -e "${RED}$(get_msg err_domain_resolution)${NC}"
      log "$(get_msg err_domain_resolution)" "$RED"
      continue
    fi
    echo "$domain"
    break
  done
}

# 获取用户邮箱
get_email() {
  local domain="$1"
  local email
  while true; do
    read -p "$(get_msg input_email)" email
    email=${email:-"admin@$domain"}
    validate_email "$email" && break
    log_i18n "错误：邮箱格式无效，请重新输入" "Error: Invalid email format, please try again" "$RED"
  done
  log_i18n "使用邮箱: $email" "Using email: $email" "$GREEN"
  echo "$email"
}

# 安装 acme.sh
install_acme_sh() {
  [[ -f "$ACME_SH" ]] && return 0
  log "Installing acme.sh / 安装 acme.sh..." "$BLUE"
  curl -sL --connect-timeout 10 https://get.acme.sh | sh &>/tmp/acme_install.log || {
    log "Error: Failed to install acme.sh, details in /tmp/acme_install.log / 错误：安装 acme.sh 失败，详情见 /tmp/acme_install.log" "$RED"
    rm -rf "$HOME/.acme.sh"
    exit 1
  }
}

ensure_acme_renewal_job() {
  systemctl enable --now cron &>/dev/null || systemctl enable --now crond &>/dev/null || true
  [[ -x "$ACME_SH" ]] && "$ACME_SH" --install-cronjob &>/dev/null || true
}

# Check whether any known Hysteria service or install artifact exists.
hysteria_exists() {
  [[ -f /usr/local/bin/hysteria || -f "$CONFIG_FILE" ]] && return 0
  for svc in "${HYSTERIA_SERVICES[@]}"; do
    [[ -f "/etc/systemd/system/${svc}.service" ]] && return 0
    systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q "${svc}.service" && return 0
    systemctl list-units --all "${svc}.service" --no-legend 2>/dev/null | grep -q "${svc}.service" && return 0
  done
  return 1
}

backup_hysteria() {
  log "$(get_msg backup_uninstall)" "$BLUE"
  mkdir -p "$BACKUP_DIR"
  local backup_file="$BACKUP_DIR/hysteria_backup_$(date '+%Y%m%d%H%M%S').tar.gz"
  local backup_items=()
  [[ -f /usr/local/bin/hysteria ]] && backup_items+=("/usr/local/bin/hysteria")
  [[ -d "$CONFIG_DIR" ]] && backup_items+=("$CONFIG_DIR")
  for svc in "${HYSTERIA_SERVICES[@]}"; do
    [[ -f "/etc/systemd/system/${svc}.service" ]] && backup_items+=("/etc/systemd/system/${svc}.service")
  done
  if [[ ${#backup_items[@]} -eq 0 ]]; then
    log "No local files found to backup / 未找到可备份的本地文件" "$YELLOW"
    return 0
  fi
  tar -czf "$backup_file" "${backup_items[@]}" 2>/dev/null
  [[ -f "$backup_file" ]] && log "$(get_msg backup_done "$backup_file")" "$GREEN" || { log "Error: Failed to create backup file $backup_file / 错误：无法创建备份文件 $backup_file" "$RED"; exit 1; }
}

uninstall_hysteria() {
  local keep_settings="${1:-}"
  local skip_confirm="${2:-false}"

  if ! hysteria_exists; then
    log_i18n "未检测到已有 Hysteria2" "No existing Hysteria2 detected" "$GREEN"
    return 0
  fi

  if [[ "$skip_confirm" != "true" ]]; then
    confirm_uninstall=$(read_yes_no "$(i18n "确认卸载 Hysteria2？(默认 N): " "Confirm uninstall Hysteria2? (default N): ")" "N")
    [[ "$confirm_uninstall" =~ ^[Yy]$ ]] || { log_i18n "已取消卸载" "Canceled uninstall" "$YELLOW"; return 1; }
  fi

  if [[ -z "$keep_settings" ]]; then
    keep_settings=$(read_yes_no "$(i18n "是否保留原有配置和证书？(默认 Y): " "Keep existing config and certificates? (default Y): ")" "Y")
  fi

  local cert_path=""
  if [[ -f "$CONFIG_FILE" ]]; then
    cert_path=$(awk '/^[[:space:]]+cert:/ {gsub(/"/, "", $2); print $2; exit}' "$CONFIG_FILE")
  fi

  for svc in "${HYSTERIA_SERVICES[@]}"; do
    systemctl stop "$svc" &>/dev/null || true
    systemctl disable "$svc" &>/dev/null || true
    systemctl reset-failed "$svc" &>/dev/null || true
    rm -f "/etc/systemd/system/${svc}.service" "/etc/systemd/system/multi-user.target.wants/${svc}.service"
  done

  rm -f /usr/local/bin/hysteria || log "Warning: Failed to remove hysteria binary / 警告：删除 hysteria 主程序失败" "$YELLOW"

  if [[ ! "$keep_settings" =~ ^[Yy]$ ]]; then
    rm -rf "$CONFIG_DIR" || log "Warning: Failed to remove config dir / 警告：删除配置目录失败" "$YELLOW"
    case "$cert_path" in
      "$CERT_DIR"/*/fullchain.pem)
        rm -rf "$(dirname "$cert_path")" || log "Warning: Failed to remove cert dir / 警告：删除证书目录失败" "$YELLOW"
        ;;
    esac
  else
    log_i18n "已保留原有配置和证书" "Keeping existing config and certificates" "$GREEN"
  fi

  systemctl daemon-reload
  log_i18n "Hysteria2 已卸载" "Hysteria2 uninstalled" "$GREEN"
  return 0
}

# Overrides the earlier compatibility implementation.
check_existing_hysteria() {
  if hysteria_exists; then
    printf "$(get_msg confirm_uninstall)"
    confirm_uninstall=$(read_yes_no "" "Y")
    if [[ "$confirm_uninstall" =~ ^[Yy]$ ]]; then
      printf "$(get_msg confirm_backup)"
      confirm_backup=$(read_yes_no "" "N")
      [[ "$confirm_backup" =~ ^[Yy]$ ]] && backup_hysteria
      uninstall_hysteria "Y" "true"
    else
      log "Canceled installation / 取消安装" "$YELLOW"
      exit 0
    fi
  else
    log "No existing Hysteria2 detected / 未检测到已有 Hysteria2" "$GREEN"
  fi
}

# 配置防火墙规则
manage_firewall_rules() {
  local port_range="$1"
  local interface=$(ip -o -4 route show to default | awk '{print $5}')
  [[ -z "$interface" ]] && { log "Error: Cannot detect network interface! / 错误：无法检测网络接口！" "$RED"; exit 1; }

  log "$(get_msg config_firewall)" "$BLUE"

  clear_iptables_rules() {
    local table="$1" chain="$2" proto="$3" ports="$4"
    $table -t nat -L "$chain" -n --line-numbers | grep -E "$proto.*$ports" | awk '{print $1}' | sort -r | while read line; do
      $table -t nat -D "$chain" "$line" &>/dev/null
    done
    $table -L INPUT -n --line-numbers | grep -E "$proto.*multiport.*$ports" | awk '{print $1}' | sort -r | while read line; do
      $table -D INPUT "$line" &>/dev/null
    done
  }

  clear_iptables_rules "iptables" "PREROUTING" "udp" "$port_range"
  if command -v ip6tables &>/dev/null && ip -6 route list | grep -q "default"; then
    clear_iptables_rules "ip6tables" "PREROUTING" "udp" "$port_range"
  fi

  iptables -t nat -A PREROUTING -i "$interface" -p udp --dport "$port_range" -j REDIRECT --to-ports "$main_port"
  iptables -A INPUT -p udp -m multiport --dports "$port_range" -j ACCEPT
  if command -v ip6tables &>/dev/null && ip -6 route list | grep -q "default"; then
    ip6tables -t nat -A PREROUTING -i "$interface" -p udp --dport "$port_range" -j REDIRECT --to-ports "$main_port"
    ip6tables -A INPUT -p udp -m multiport --dports "$port_range" -j ACCEPT
  fi

  if ! iptables -C INPUT -p tcp --dport 22 -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    log "Added SSH rule (TCP 22) to INPUT chain / 添加 SSH 规则 (TCP 22) 到 INPUT 链" "$GREEN"
  fi

  mkdir -p /etc/iptables
  chmod 755 /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
  systemctl enable netfilter-persistent &>/dev/null || log "Warning: Failed to enable netfilter-persistent / 警告：无法启用 netfilter-persistent" "$YELLOW"
  systemctl start netfilter-persistent &>/dev/null || log "Warning: Failed to start netfilter-persistent / 警告：无法启动 netfilter-persistent" "$YELLOW"
  netfilter-persistent save &>/tmp/netfilter_error.log || log "Warning: Failed to save firewall rules, details in /tmp/netfilter_error.log / 警告：保存防火墙规则失败，详情见 /tmp/netfilter_error.log" "$YELLOW"
}

# A CA bundle contains many certificates; parsing one expiry date from it is
# unreliable. Check that the bundle exists and validate the issued leaf cert.
check_ssl_certificates() {
  local domain="$1"
  log "$(get_msg check_ssl)" "$BLUE"

  if ! command -v openssl &>/dev/null; then
    log "Error: OpenSSL not detected, installing... / 错误：未检测到 OpenSSL，正在安装..." "$RED"
    update_package_index
    timeout 300 apt install -y openssl &>/tmp/apt_install.log || { log "$(get_msg err_ssl)" "$RED"; exit 1; }
    log "OpenSSL installed / OpenSSL 已安装" "$GREEN"
  fi

  local ca_files=("/etc/ssl/certs/ca-certificates.crt" "/etc/pki/tls/certs/ca-bundle.crt")
  local ca_file=""
  for file in "${ca_files[@]}"; do
    if [[ -s "$file" ]]; then
      ca_file="$file"
      break
    fi
  done

  if [[ -z "$ca_file" ]]; then
    log "$(get_msg ssl_ca_missing "${ca_files[0]}")" "$YELLOW"
    update_package_index
    timeout 300 apt install -y ca-certificates &>/tmp/apt_install.log || { log "Warning: Failed to install CA certificates, proceeding anyway / 警告：安装 CA 证书失败，继续执行" "$YELLOW"; return 0; }
    ca_file="${ca_files[0]}"
  fi

  [[ -s "$ca_file" ]] && log "CA bundle found: $ca_file / 已找到 CA 证书包: $ca_file" "$GREEN"

  local cert_path="$CERT_DIR/$domain/fullchain.pem"
  if [[ -n "$domain" && -f "$cert_path" ]]; then
    if openssl x509 -in "$cert_path" -noout -checkend 0 &>/dev/null; then
      log "$(get_msg ssl_ok)" "$GREEN"
    else
      log "Error: Certificate is expired or unreadable: $cert_path / 错误：证书已过期或无法读取: $cert_path" "$RED"
      exit 1
    fi

    if [[ -s "$ca_file" ]]; then
      openssl verify -CAfile "$ca_file" "$cert_path" &>/tmp/hysteria_cert_verify.log || log "Warning: Certificate chain verification did not pass; details in /tmp/hysteria_cert_verify.log / 警告：证书链校验未通过，详情见 /tmp/hysteria_cert_verify.log" "$YELLOW"
    fi
  fi
}

install_hysteria() {
  local max_retries=3 retry_count=0
  local os arch latest_version local_version force_download use_local
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)

  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv7l) arch="arm" ;;
    i386|i686) arch="386" ;;
    *)
      log "Error: Unsupported architecture $arch / 错误：不支持的架构 $arch" "$RED"
      exit 1
      ;;
  esac

  latest_version=$(curl -sL --connect-timeout 10 https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')
  if [[ -x /usr/local/bin/hysteria ]]; then
    local_version=$(/usr/local/bin/hysteria version 2>/dev/null | grep -Eo 'v?[0-9]+(\.[0-9]+){1,3}([-+][A-Za-z0-9._-]+)?' | head -n1 || true)
    [[ -n "$local_version" && "$local_version" != v* ]] && local_version="v$local_version"

    if [[ -n "$latest_version" && "$latest_version" != "null" && -n "$local_version" && "$local_version" == "$latest_version" ]]; then
      log_i18n "检测到本地 Hysteria2 已是最新版: $local_version" "Local Hysteria2 is already the latest version: $local_version" "$GREEN"
      force_download=$(read_yes_no "$(i18n "是否覆盖并重新下载？(默认 N) [y/N]: " "Overwrite and download again? (default N) [y/N]: ")" "N")
      if [[ ! "$force_download" =~ ^[Yy]$ ]]; then
        log_i18n "跳过下载，继续使用本地 Hysteria2" "Skipping download, using local Hysteria2" "$GREEN"
        return 0
      fi
    elif [[ -n "$latest_version" && "$latest_version" != "null" && -n "$local_version" ]]; then
      log_i18n "检测到本地版本 $local_version，最新版本 $latest_version，将下载更新" "Local version $local_version detected; latest is $latest_version, downloading update" "$YELLOW"
    elif [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
      log_i18n "无法获取 Hysteria2 最新版本，但检测到本地文件" "Could not fetch latest Hysteria2 version, but a local binary exists" "$YELLOW"
      use_local=$(read_yes_no "$(i18n "是否继续使用本地文件？(默认 Y) [Y/n]: " "Use the local binary? (default Y) [Y/n]: ")" "Y")
      [[ "$use_local" =~ ^[Yy]$ ]] && return 0
    fi
  fi

  while [[ $retry_count -lt $max_retries ]]; do
    log "$(get_msg download_hy2 "$((retry_count + 1))" "$max_retries")" "$BLUE"
    [[ -z "$latest_version" || "$latest_version" == "null" ]] && latest_version=$(curl -sL --connect-timeout 10 https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')
    [[ -z "$latest_version" || "$latest_version" == "null" ]] && { log "Warning: Failed to get version / 警告：无法获取版本..." "$YELLOW"; retry_count=$((retry_count + 1)); sleep 10; continue; }
    if download_hysteria_binary_to_path "$latest_version" "$os" "$arch" "/usr/local/bin/hysteria"; then
      break
    fi
    retry_count=$((retry_count + 1))
    sleep 10
  done
  [[ $retry_count -eq $max_retries ]] && { log "Error: Download failed! / 错误：下载失败！" "$RED"; exit 1; }
  chmod +x /usr/local/bin/hysteria
}

# 自动续期、证书检查与热升级相关辅助函数
get_config_cert_path() {
  local cert_path=""
  [[ -f "$CONFIG_FILE" ]] || return 1
  cert_path=$(awk '/^[[:space:]]+cert:/ {gsub(/"/, "", $2); print $2; exit}' "$CONFIG_FILE")
  [[ -n "$cert_path" ]] || return 1
  printf "%s" "$cert_path"
}

get_cert_days_remaining() {
  local cert_path="$1" not_after end_ts now_ts
  [[ -f "$cert_path" ]] || return 1
  not_after=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  [[ -n "$not_after" ]] || return 1
  end_ts=$(date -d "$not_after" +%s 2>/dev/null) || return 1
  now_ts=$(date +%s)
  printf "%s" "$(((end_ts - now_ts + 86399) / 86400))"
}

normalize_cert_domain() {
  local cert_path="$1" domain
  domain=$(basename "$(dirname "$cert_path")")
  domain="${domain%_ecc}"
  printf "%s" "$domain"
}

cert_is_ecc() {
  local cert_path="$1"
  openssl x509 -in "$cert_path" -noout -text 2>/dev/null | grep -q 'Public Key Algorithm: id-ecPublicKey'
}

resolve_acme_domain_name() {
  normalize_cert_domain "$1"
}

resolve_acme_ecc_flag() {
  local cert_path="$1" domain_dir
  domain_dir=$(basename "$(dirname "$cert_path")")
  if [[ "$domain_dir" == *_ecc ]] || cert_is_ecc "$cert_path"; then
    printf "%s" "--ecc"
  fi
}

resolve_acme_key_path() {
  local cert_path="$1" domain="$2" domain_dir
  domain_dir=$(basename "$(dirname "$cert_path")")
  if [[ "$cert_path" == "$HOME/.acme.sh/"* ]]; then
    printf "%s" "$HOME/.acme.sh/$domain_dir/$domain.key"
  else
    printf "%s" "$(dirname "$cert_path")/privkey.pem"
  fi
}

show_certificate_expiry() {
  local cert_path domain not_after days_remaining
  cert_path=$(get_config_cert_path 2>/dev/null || true)
  if [[ -z "$cert_path" || ! -f "$cert_path" ]]; then
    log_i18n "未找到可查看的证书文件" "No certificate file found to inspect" "$YELLOW"
    return 1
  fi

  domain=$(normalize_cert_domain "$cert_path")
  not_after=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  days_remaining=$(get_cert_days_remaining "$cert_path" 2>/dev/null || true)

  log_i18n "证书域名: $domain" "Certificate domain: $domain" "$GREEN"
  log_i18n "证书路径: $cert_path" "Certificate path: $cert_path" "$GREEN"
  [[ -n "$not_after" ]] && log_i18n "证书到期时间: $not_after" "Certificate expiry: $not_after" "$GREEN"
  if [[ -n "$days_remaining" ]]; then
    if [[ "$days_remaining" -le 0 ]]; then
      log_i18n "证书已过期" "Certificate has expired" "$RED"
    else
      log_i18n "证书剩余天数: $days_remaining" "Days remaining: $days_remaining" "$GREEN"
    fi
  fi
}

renew_certificate_now() {
  local cert_path domain days_remaining ecc_flag install_ok key_path unit_name
  cert_path=$(get_config_cert_path 2>/dev/null || true)
  if [[ -z "$cert_path" || ! -f "$cert_path" ]]; then
    log_i18n "未找到可续期的证书文件" "No certificate file found to renew" "$YELLOW"
    return 1
  fi

  domain=$(resolve_acme_domain_name "$cert_path")
  ecc_flag=$(resolve_acme_ecc_flag "$cert_path" || true)

  days_remaining=$(get_cert_days_remaining "$cert_path" 2>/dev/null || true)
  log_i18n "开始手动续期证书，当前剩余天数: ${days_remaining:-未知}" "Starting manual certificate renewal, current days remaining: ${days_remaining:-unknown}" "$BLUE"

  if [[ -n "$ecc_flag" ]]; then
    if ! "$ACME_SH" --renew -d "$domain" --force --ecc --days 15; then
      log_i18n "ECC 续期失败，尝试按 RSA 方式重试" "ECC renewal failed, retrying as RSA" "$YELLOW"
      ecc_flag=""
      "$ACME_SH" --renew -d "$domain" --force --days 15 || {
        log_i18n "证书续期失败" "Certificate renewal failed" "$RED"
        return 1
      }
    fi
  else
    if ! "$ACME_SH" --renew -d "$domain" --force --days 15; then
      log_i18n "RSA 续期失败，尝试按 ECC 方式重试" "RSA renewal failed, retrying as ECC" "$YELLOW"
      ecc_flag="--ecc"
      "$ACME_SH" --renew -d "$domain" --force --ecc --days 15 || {
        log_i18n "证书续期失败" "Certificate renewal failed" "$RED"
        return 1
      }
    fi
  fi

  install_ok=false
  if [[ -n "$ecc_flag" ]]; then
    "$ACME_SH" --install-cert -d "$domain" --ecc --force &>/dev/null && install_ok=true
  else
    "$ACME_SH" --install-cert -d "$domain" --force &>/dev/null && install_ok=true
  fi

  if [[ "$install_ok" != "true" ]]; then
    key_path=$(resolve_acme_key_path "$cert_path" "$domain")
    mkdir -p "$(dirname "$cert_path")"
    if [[ -f "$key_path" ]]; then
      if [[ -n "$ecc_flag" ]]; then
        "$ACME_SH" --install-cert -d "$domain" --ecc --cert-file "$cert_path" --key-file "$key_path" --force &>/dev/null || true
      else
        "$ACME_SH" --install-cert -d "$domain" --cert-file "$cert_path" --key-file "$key_path" --force &>/dev/null || true
      fi
      install_ok=true
    fi
  fi

  if [[ "$install_ok" != "true" ]]; then
    log_i18n "证书安装到目标路径失败" "Failed to install renewed certificate to the target path" "$RED"
    return 1
  fi

  if unit_name=$(service_unit_or_warn 2>/dev/null); then
    systemctl restart "${unit_name}.service" &>/dev/null || true
  fi
  log_i18n "证书续期完成，服务已重启" "Certificate renewed and service restarted" "$GREEN"
  return 0
}

probe_hysteria_download_url() {
  local url="$1" result code total
  result=$(curl -L --connect-timeout 5 --max-time 15 --range 0-0 -o /dev/null -s -w '%{http_code} %{time_total}' "$url" 2>/dev/null || true)
  code="${result%% *}"
  total="${result#* }"
  [[ "$code" == "200" || "$code" == "206" ]] || return 1
  printf "%s|%s" "$total" "$url"
}

rank_hysteria_download_urls() {
  local version="$1" os="$2" arch="$3" asset="hysteria-${os}-${arch}"
  local candidates=(
    "https://ghproxy.com/https://github.com/apernet/hysteria/releases/download/${version}/${asset}"
    "https://mirror.ghproxy.com/https://github.com/apernet/hysteria/releases/download/${version}/${asset}"
    "https://github.moeyy.xyz/https://github.com/apernet/hysteria/releases/download/${version}/${asset}"
    "https://github.com/apernet/hysteria/releases/download/${version}/${asset}"
  )
  local scored=() probe
  for probe in "${candidates[@]}"; do
    if probe=$(probe_hysteria_download_url "$probe"); then
      scored+=("$probe")
    fi
  done
  if [[ ${#scored[@]} -eq 0 ]]; then
    printf "%s\n" "https://github.com/apernet/hysteria/releases/download/${version}/${asset}"
    return 0
  fi
  printf "%s\n" "${scored[@]}" | sort -n | cut -d'|' -f2-
}

download_hysteria_binary_to_path() {
  local latest_version="$1" os="$2" arch="$3" output_path="$4"
  local url tmp_path="${output_path}.download.$$"

  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    log_i18n "测速并尝试下载源: $url" "Testing and trying download source: $url" "$BLUE"
    rm -f "$tmp_path"
    if command -v curl >/dev/null 2>&1; then
      curl -fL --connect-timeout 10 --retry 3 --retry-delay 2 -o "$tmp_path" "$url" || {
        log_i18n "当前镜像下载失败，尝试下一个候选源" "Current mirror failed, trying the next candidate" "$YELLOW"
        continue
      }
    else
      wget "$url" -O "$tmp_path" || {
        log_i18n "当前镜像下载失败，尝试下一个候选源" "Current mirror failed, trying the next candidate" "$YELLOW"
        continue
      }
    fi

    chmod +x "$tmp_path"
    if timeout 5s "$tmp_path" version &>/dev/null; then
      mv -f "$tmp_path" "$output_path"
      chmod +x "$output_path"
      return 0
    fi

    log_i18n "下载内容校验失败，继续尝试其他镜像" "Downloaded binary validation failed, trying other mirrors" "$YELLOW"
  done < <(rank_hysteria_download_urls "$latest_version" "$os" "$arch")

  rm -f "$tmp_path"
  return 1
}

upgrade_hysteria() {
  local unit latest_version current_version os arch backup_path tmp_path service_bin="/usr/local/bin/hysteria"

  unit=$(service_unit_or_warn) || return 1
  current_version=$("$service_bin" version 2>/dev/null | grep -ioE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
  latest_version=$(curl -fsSL --connect-timeout 10 https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name // empty' 2>/dev/null || true)
  if [[ -z "$latest_version" ]]; then
    log_i18n "无法获取 GitHub 最新版本信息" "Failed to fetch the latest version from GitHub" "$RED"
    return 1
  fi

  log_i18n "当前版本: ${current_version:-未知}，最新版本: $latest_version" "Current version: ${current_version:-unknown}, latest version: $latest_version" "$BLUE"
  if [[ -n "$current_version" && "$current_version" == "$latest_version" ]]; then
    log_i18n "当前已经是最新版本，无需升级" "Already on the latest version, no upgrade needed" "$GREEN"
    return 0
  fi

  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv7l) arch="arm" ;;
    i386|i686) arch="386" ;;
    *)
      log_i18n "不支持的系统架构: $arch" "Unsupported architecture: $arch" "$RED"
      return 1
      ;;
  esac

  tmp_path="/tmp/hysteria_new_core.$$"
  backup_path="${service_bin}.bak.$(date +%Y%m%d%H%M%S)"

  if ! download_hysteria_binary_to_path "$latest_version" "$os" "$arch" "$tmp_path"; then
    log_i18n "热升级下载失败" "Hot upgrade download failed" "$RED"
    rm -f "$tmp_path"
    return 1
  fi

  if ! systemctl stop "${unit}.service"; then
    log_i18n "停止服务失败，已中止升级" "Failed to stop the service, aborting upgrade" "$RED"
    rm -f "$tmp_path"
    return 1
  fi

  cp -f "$service_bin" "$backup_path" || {
    log_i18n "备份当前核心失败，已恢复服务" "Failed to back up current binary, service restored" "$RED"
    systemctl start "${unit}.service" &>/dev/null || true
    rm -f "$tmp_path"
    return 1
  }

  if mv -f "$tmp_path" "$service_bin" && chmod +x "$service_bin" && systemctl daemon-reload && systemctl start "${unit}.service"; then
    rm -f "$backup_path"
    log_i18n "热升级完成，服务已恢复" "Hot upgrade complete and service is back up" "$GREEN"
    return 0
  fi

  log_i18n "升级失败，正在回滚到旧版本" "Upgrade failed, rolling back to the previous version" "$YELLOW"
  mv -f "$backup_path" "$service_bin" 2>/dev/null
  chmod +x "$service_bin" 2>/dev/null
  systemctl daemon-reload
  systemctl start "${unit}.service" &>/dev/null || true
  rm -f "$tmp_path"
  return 1
}

# Resolve the actual installed service name when distros differ on unit naming.
resolve_service_name() {
  local svc
  for svc in "${HYSTERIA_SERVICES[@]}"; do
    if systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q "${svc}.service" ||
       systemctl list-units --all "${svc}.service" --no-legend 2>/dev/null | grep -q "${svc}.service"; then
      printf "%s" "$svc"
      return 0
    fi
  done
  return 1
}

service_unit_or_warn() {
  local unit
  unit=$(resolve_service_name) || {
    log "Warning: Unable to locate installed Hysteria service unit / 警告：未找到已安装的 Hysteria 服务单元" "$YELLOW"
    return 1
  }
  printf "%s" "$unit"
}

dump_service_diagnostics() {
  local unit
  unit=$(service_unit_or_warn) || return 1
  log "Hysteria service status / Hysteria 服务状态:" "$YELLOW"
  systemctl status "${unit}.service" --no-pager -l 2>&1 | tee -a "$LOG_FILE" || true
  log "Recent Hysteria service logs / 最近的 Hysteria 服务日志:" "$YELLOW"
  journalctl -u "${unit}.service" -n 80 --no-pager 2>&1 | tee -a "$LOG_FILE" || true
  [[ -f "$CONFIG_FILE" ]] && log "Config file: $CONFIG_FILE / 配置文件: $CONFIG_FILE" "$YELLOW"
}

# 验证代理地址格式
validate_proxy_addr() {
  local addr="$1"
  local host="${addr%:*}" port="${addr##*:}"
  [[ "$addr" == "$host" ]] && return 1
  [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || return 1
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    local a b c d
    IFS=. read -r a b c d <<< "$host"
    ((10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255)) && return 0
    return 1
  fi
  [[ "$host" =~ ^([A-Za-z0-9-]+\.)*[A-Za-z0-9-]+$ ]] && return 0
  return 1
}

# Overrides the earlier implementation so failed starts show the real cause.
setup_service() {
  log "$(get_msg create_service)" "$BLUE"
  cat <<EOF > "$SYSTEMD_SERVICE"
[Unit]
Description=Hysteria2 Service
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server --config $CONFIG_FILE
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl reset-failed "$SERVICE_NAME" &>/dev/null || true
  systemctl start "$SERVICE_NAME" || { log "Error: Service start failed! / 错误：服务启动失败！" "$RED"; dump_service_diagnostics; exit 1; }
}

# Overrides the earlier implementation so a quick crash prints status and logs.
check_health() {
  local domain="$1" main_port="$2"
  local unit
  log "$(get_msg check_health)" "$BLUE"
  sleep 2
  unit=$(service_unit_or_warn) || return 1
  if ! systemctl is-active --quiet "${unit}.service"; then
    log "Error: Service not running! / 错误：服务未运行！" "$RED"
    dump_service_diagnostics
    return 1
  fi
  if command -v ss &>/dev/null; then
    if ss -lunH "sport = :$main_port" | grep -q .; then
      log "Service UDP listener detected on port $main_port / 已检测到服务在 $main_port 端口监听 UDP" "$GREEN"
    else
      log "Warning: No UDP listener found on port $main_port / 警告：未检测到 $main_port 端口的 UDP 监听" "$YELLOW"
    fi
  fi
  log "$(get_msg service_ok)" "$GREEN"
  return 0
}

view_service_status() {
  local unit
  unit=$(service_unit_or_warn) || return 1
  log "$(get_msg service_status)" "$BLUE"
  systemctl status "${unit}.service" --no-pager
}

# 查看最近 30 条日志
view_service_logs() {
  local unit
  unit=$(service_unit_or_warn) || return 1
  log "$(get_msg service_logs)" "$BLUE"
  journalctl -u "${unit}.service" -n 30 --no-pager
}

# 重启服务
restart_service() {
  local unit
  unit=$(service_unit_or_warn) || return 1
  log "$(get_msg service_restart)" "$BLUE"
  systemctl restart "${unit}.service" && log "Service restarted successfully / 服务重启成功" "$GREEN" || log "Error: Failed to restart service! / 错误：重启服务失败！" "$RED"
}

# 停止服务
stop_service() {
  local unit
  unit=$(service_unit_or_warn) || return 1
  log "$(get_msg service_stop)" "$BLUE"
  systemctl stop "${unit}.service" && log "Service stopped successfully / 服务停止成功" "$GREEN" || log "Error: Failed to stop service! / 错误：停止服务失败！" "$RED"
}

# 显示配置信息
show_config_info() {
  log "$(get_msg service_config)" "$BLUE"
  if [[ -f "$CONFIG_FILE" ]]; then
    cat "$CONFIG_FILE"
  else
    log "Error: Config file $CONFIG_FILE not found! / 错误：配置文件 $CONFIG_FILE 未找到！" "$RED"
  fi
}

# 服务管理菜单
manage_service() {
  while true; do
    clear
    echo -e "${RED}$(get_msg manage_menu)${NC}"
    read -p "$(get_msg input_manage_option)" choice
    case "$choice" in
      1) view_service_status ;;
      2) view_service_logs ;;
      3) restart_service ;;
      4) stop_service ;;
      5) show_config_info ;;
      6) show_certificate_expiry ;;
      7) renew_certificate_now ;;
      8) upgrade_hysteria ;;
      0) return 0 ;;
      *) log_i18n "无效选项，请选择 0-8" "Invalid option, please choose 0-8" "$YELLOW" ;;
    esac
    read -p "$(get_msg continue_prompt)" cont
  done
  return 0
}

# 安装 Hysteria2
# Install-state helpers used by the final install flow.
load_existing_install_info() {
  EXISTING_DOMAIN=""
  EXISTING_CERT_PATH=""
  EXISTING_KEY_PATH=""
  EXISTING_MAIN_PORT=""
  EXISTING_PASSWORD=""
  EXISTING_MASQUERADE_URL=""
  EXISTING_OBFS_ENABLED="false"
  EXISTING_OBFS_PASSWORD=""

  if [[ -f "$CONFIG_FILE" ]]; then
    EXISTING_MAIN_PORT=$(awk '/^listen:/ {gsub(/^:/, "", $2); print $2; exit}' "$CONFIG_FILE")
    EXISTING_CERT_PATH=$(awk '/^[[:space:]]+cert:/ {gsub(/"/, "", $2); print $2; exit}' "$CONFIG_FILE")
    EXISTING_KEY_PATH=$(awk '/^[[:space:]]+key:/ {gsub(/"/, "", $2); print $2; exit}' "$CONFIG_FILE")
    EXISTING_PASSWORD=$(awk 'BEGIN{in_auth=0} /^auth:/{in_auth=1; next} /^[^[:space:]]/{if(in_auth) exit} in_auth && /^[[:space:]]+password:/ {gsub(/"/, "", $2); print $2; exit}' "$CONFIG_FILE")
    EXISTING_MASQUERADE_URL=$(awk '/^[[:space:]]+url:/ {gsub(/"/, "", $2); print $2; exit}' "$CONFIG_FILE")
    EXISTING_OBFS_PASSWORD=$(awk 'BEGIN{in_obfs=0} /^obfs:/{in_obfs=1; next} /^[^[:space:]]/{if(in_obfs) exit} in_obfs && /^[[:space:]]+password:/ {gsub(/"/, "", $2); print $2; exit}' "$CONFIG_FILE")
    [[ -n "$EXISTING_OBFS_PASSWORD" ]] && EXISTING_OBFS_ENABLED="true"
  fi

  case "$EXISTING_CERT_PATH" in
    "$CERT_DIR"/*/fullchain.pem)
      EXISTING_DOMAIN=$(basename "$(dirname "$EXISTING_CERT_PATH")")
      ;;
  esac

  if [[ -z "$EXISTING_DOMAIN" ]]; then
    local certs=("$CERT_DIR"/*/fullchain.pem)
    if [[ ${#certs[@]} -eq 1 && -f "${certs[0]}" ]]; then
      EXISTING_CERT_PATH="${certs[0]}"
      EXISTING_KEY_PATH="$(dirname "${certs[0]}")/privkey.pem"
      EXISTING_DOMAIN=$(basename "$(dirname "${certs[0]}")")
    fi
  fi

  if [[ -n "$EXISTING_DOMAIN" ]]; then
    log_i18n "检测到旧域名: $EXISTING_DOMAIN" "Detected previous domain: $EXISTING_DOMAIN" "$GREEN"
    [[ -n "$EXISTING_CERT_PATH" ]] && log_i18n "检测到旧证书: $EXISTING_CERT_PATH" "Detected previous certificate: $EXISTING_CERT_PATH" "$GREEN"
  fi
}

get_domain_with_existing() {
  if [[ -n "$EXISTING_DOMAIN" ]]; then
    reuse_domain=$(read_yes_no "$(i18n "检测到旧域名 $EXISTING_DOMAIN，是否沿用？(默认 Y) [Y/n]: " "Detected previous domain $EXISTING_DOMAIN. Reuse it? (default Y) [Y/n]: ")" "Y")
    if [[ "$reuse_domain" =~ ^[Yy]$ ]]; then
      if validate_domain_format "$EXISTING_DOMAIN"; then
        echo "$EXISTING_DOMAIN"
        return 0
      fi
      log_i18n "旧域名格式无效，需要重新输入" "Previous domain is invalid; please enter a new one" "$YELLOW"
    fi
  fi
  get_domain
}

get_main_port_with_existing() {
  local raw_main_port main_port
  if [[ -n "$EXISTING_MAIN_PORT" ]]; then
    reuse_port=$(read_yes_no "$(i18n "检测到旧主端口 $EXISTING_MAIN_PORT，是否沿用？(默认 Y) [Y/n]: " "Detected previous main port $EXISTING_MAIN_PORT. Reuse it? (default Y) [Y/n]: ")" "Y")
    if [[ "$reuse_port" =~ ^[Yy]$ ]]; then
      if [[ "$EXISTING_MAIN_PORT" =~ ^[0-9]+$ && "$EXISTING_MAIN_PORT" -ge 1 && "$EXISTING_MAIN_PORT" -le 65535 ]]; then
        echo "$EXISTING_MAIN_PORT"
        return 0
      fi
      log_i18n "旧主端口无效，需要重新输入" "Previous main port is invalid; please enter a new one" "$YELLOW"
    fi
  fi

  read -p "$(get_msg input_port)" raw_main_port
  main_port=${raw_main_port:-443}
  until [[ "$main_port" =~ ^[0-9]+$ && "$main_port" -ge 1 && "$main_port" -le 65535 ]]; do
    log "Error: Invalid port! Must be 1-65535 / 错误：无效端口，必须为 1-65535" "$RED"
    read -p "$(get_msg input_port)" raw_main_port
    main_port=${raw_main_port:-443}
  done
  echo "$main_port"
}

normalize_port_range() {
  local raw_port_range="${1:-40000-62000}"
  local formatted=$(echo "$raw_port_range" | sed 's/[-,]/:/g')
  local start_port=$(echo "$formatted" | cut -d':' -f1)
  local end_port=$(echo "$formatted" | cut -d':' -f2)
  [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ && "$start_port" -ge 1 && "$end_port" -le 65535 && "$start_port" -le "$end_port" ]] || return 1
  echo "$start_port:$end_port"
}

prompt_obfs_settings() {
  local obfs_choice obfs_password reuse_obfs
  if [[ "$EXISTING_OBFS_ENABLED" == "true" && -n "$EXISTING_OBFS_PASSWORD" ]]; then
    reuse_obfs=$(read_yes_no "$(i18n "检测到旧 Salamander 混淆，是否沿用？(默认 Y) [Y/n]: " "Detected previous Salamander obfuscation. Reuse it? (default Y) [Y/n]: ")" "Y")
    if [[ "$reuse_obfs" =~ ^[Yy]$ ]]; then
      if validate_hysteria_secret "$EXISTING_OBFS_PASSWORD"; then
        HYSTERIA_ENABLE_OBFS="true"
        HYSTERIA_OBFS_PASSWORD="$EXISTING_OBFS_PASSWORD"
        HYSTERIA_OBFS_PROMPTED="true"
        log_i18n "沿用旧 Salamander 混淆" "Using previous Salamander obfuscation" "$GREEN"
        return 0
      fi
      log_i18n "旧混淆密码包含不安全字符，需要重新输入" "Previous obfuscation password contains unsafe characters; please enter a new one" "$YELLOW"
    fi
  fi

  obfs_choice=$(read_yes_no "$(i18n "是否启用 Salamander 混淆？(推荐，默认 Y) [Y/n]: " "Enable Salamander obfuscation? (recommended, default Y) [Y/n]: ")" "Y")
  if [[ "$obfs_choice" =~ ^[Yy]$ ]]; then
    while true; do
      read -s -p "$(i18n "请输入混淆密码 (默认自动生成): " "Enter obfuscation password (default auto-generated): ")" obfs_password; echo
      obfs_password=${obfs_password:-$(uuidgen)}
      validate_hysteria_secret "$obfs_password" && break
      log_i18n "错误：混淆密码长度需为 6-128，且不能包含空白或 @:/?#[]" "Error: Obfuscation password must be 6-128 chars and cannot contain whitespace or @:/?#[]" "$RED"
    done
    HYSTERIA_ENABLE_OBFS="true"
    HYSTERIA_OBFS_PASSWORD="$obfs_password"
    log_i18n "已启用 Salamander 混淆" "Salamander obfuscation enabled" "$GREEN"
    log_i18n "使用混淆密码: $obfs_password" "Using obfs password: $obfs_password" "$GREEN"
  else
    HYSTERIA_ENABLE_OBFS="false"
    HYSTERIA_OBFS_PASSWORD=""
    log_i18n "未启用 Salamander 混淆" "Salamander obfuscation disabled" "$YELLOW"
  fi
  HYSTERIA_OBFS_PROMPTED="true"
}

prompt_port_hopping_settings() {
  local hop_choice raw_port_range formatted
  HYSTERIA_PORT_HOP_ENABLED="false"
  HYSTERIA_PORT_RANGE=""

  if [[ "$HYSTERIA_ENABLE_OBFS" == "true" ]]; then
    log_i18n "已启用混淆，自动禁用端口跳跃" "Port hopping disabled because Salamander obfuscation is enabled" "$YELLOW"
    return 0
  fi

  hop_choice=$(read_yes_no "$(i18n "是否启用端口跳跃？(默认 N) [y/N]: " "Enable port hopping? (default N) [y/N]: ")" "N")
  if [[ ! "$hop_choice" =~ ^[Yy]$ ]]; then
    log_i18n "未启用端口跳跃" "Port hopping disabled" "$GREEN"
    return 0
  fi

  read -p "$(i18n "端口跳跃范围 (默认 40000-62000): " "Port hopping range (default 40000-62000): ")" raw_port_range
  raw_port_range=${raw_port_range:-"40000-62000"}
  until formatted=$(normalize_port_range "$raw_port_range"); do
    log_i18n "错误：无效范围，必须为 1-65535 且起始端口 <= 结束端口" "Error: Invalid range! Must be 1-65535 and start <= end" "$RED"
    read -p "$(i18n "端口跳跃范围 (默认 40000-62000): " "Port hopping range (default 40000-62000): ")" raw_port_range
    raw_port_range=${raw_port_range:-"40000-62000"}
  done
  HYSTERIA_PORT_HOP_ENABLED="true"
  HYSTERIA_PORT_RANGE="$formatted"
  log_i18n "已启用端口跳跃: $HYSTERIA_PORT_RANGE" "Port hopping enabled: $HYSTERIA_PORT_RANGE" "$GREEN"
}

configure_main_port_firewall() {
  local main_port="$1"
  log "$(get_msg config_firewall)" "$BLUE"
  iptables -C INPUT -p udp --dport "$main_port" -j ACCEPT &>/dev/null || iptables -A INPUT -p udp --dport "$main_port" -j ACCEPT
  if command -v ip6tables &>/dev/null && ip -6 route list | grep -q "default"; then
    ip6tables -C INPUT -p udp --dport "$main_port" -j ACCEPT &>/dev/null || ip6tables -A INPUT -p udp --dport "$main_port" -j ACCEPT
  fi
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
  systemctl enable netfilter-persistent &>/dev/null || log "Warning: Failed to enable netfilter-persistent / 警告：无法启用 netfilter-persistent" "$YELLOW"
  systemctl start netfilter-persistent &>/dev/null || log "Warning: Failed to start netfilter-persistent / 警告：无法启动 netfilter-persistent" "$YELLOW"
}

issue_certificate() {
  local domain="$1" email="$2"
  local cert_path="$CERT_DIR/$domain/fullchain.pem"
  local key_path="$CERT_DIR/$domain/privkey.pem"

  if [[ -f "$cert_path" && -f "$key_path" ]]; then
    if openssl x509 -in "$cert_path" -noout -checkend $((30 * 86400)) &>/dev/null; then
      log_i18n "现有证书有效期超过 30 天，继续沿用" "Existing certificate is valid for more than 30 days, keeping it" "$GREEN"
      return 0
    fi

    if openssl x509 -in "$cert_path" -noout -checkend 0 &>/dev/null; then
      reissue_cert=$(read_yes_no "$(i18n "证书剩余有效期不足 30 天，是否重新申请？(默认 N) [y/N]: " "Certificate has less than 30 days remaining. Reissue it? (default N) [y/N]: ")" "N")
      if [[ ! "$reissue_cert" =~ ^[Yy]$ ]]; then
        log_i18n "按用户选择继续沿用现有证书" "Keeping existing certificate by user choice" "$YELLOW"
        return 0
      fi
    else
      log_i18n "现有证书已过期，必须重新申请" "Existing certificate is expired, reissue is required" "$YELLOW"
    fi
  fi

  log_i18n "正在申请证书..." "Issuing certificate..." "$BLUE"
  while true; do
    read -p "$(get_msg select_cert)" cert_option
    [[ "$cert_option" =~ ^[123]$ ]] && break
    log_i18n "错误：无效选项，请输入 1、2 或 3" "Error: Invalid option, enter 1, 2, or 3" "$RED"
  done
  case "$cert_option" in
    1)
      if lsof -i :80 >/dev/null 2>&1; then
        log "Warning: Port 80 occupied, releasing... / 警告：80 端口被占用，正在释放..." "$YELLOW"
        systemctl stop nginx &>/dev/null || true
        systemctl stop apache2 &>/dev/null || true
      fi
      iptables -A INPUT -p tcp --dport 80 -j ACCEPT &>/dev/null
      "$ACME_SH" --issue -d "$domain" --standalone -m "$email" --days 15 || { log "Error: Failed to issue certificate via Standalone! / 错误：通过 Standalone 申请证书失败！" "$RED"; exit 1; }
      iptables -D INPUT -p tcp --dport 80 -j ACCEPT &>/dev/null
      ;;
    2)
      while true; do
        read -p "$(i18n "Cloudflare 账号邮箱: " "Cloudflare account email: ")" cf_email
        validate_email "$cf_email" && break
        log_i18n "错误：Cloudflare 邮箱格式无效" "Error: Invalid Cloudflare email format" "$RED"
      done
      while true; do
        read -s -p "$(i18n "Cloudflare API Token: " "Cloudflare API Token: ")" cf_token; echo
        validate_non_empty_no_space "$cf_token" && break
        log_i18n "错误：Cloudflare API Token 不能为空且不能包含空白" "Error: Cloudflare API Token cannot be empty or contain whitespace" "$RED"
      done
      export CF_Email="$cf_email" CF_Token="$cf_token"
      "$ACME_SH" --issue --dns dns_cf -d "$domain" -m "$email" --days 15 || { log "Error: Failed to issue certificate via Cloudflare token! / 错误：通过 Cloudflare Token 申请证书失败！" "$RED"; unset CF_Email CF_Token; exit 1; }
      unset CF_Email CF_Token
      ;;
    3)
      while true; do
        read -p "$(i18n "阿里云 AccessKey ID: " "Aliyun AccessKey ID: ")" ali_key
        validate_non_empty_no_space "$ali_key" && break
        log_i18n "错误：阿里云 AccessKey ID 不能为空且不能包含空白" "Error: Aliyun AccessKey ID cannot be empty or contain whitespace" "$RED"
      done
      while true; do
        read -s -p "$(i18n "阿里云 AccessKey Secret: " "Aliyun AccessKey Secret: ")" ali_secret; echo
        validate_non_empty_no_space "$ali_secret" && break
        log_i18n "错误：阿里云 AccessKey Secret 不能为空且不能包含空白" "Error: Aliyun AccessKey Secret cannot be empty or contain whitespace" "$RED"
      done
      export Ali_Key="$ali_key" Ali_Secret="$ali_secret"
      "$ACME_SH" --issue --dns dns_ali -d "$domain" -m "$email" --days 15 || { log "Error: Failed to issue certificate via Aliyun! / 错误：通过 Aliyun 申请证书失败！" "$RED"; unset Ali_Key Ali_Secret; exit 1; }
      unset Ali_Key Ali_Secret
      ;;
    *)
      log "Error: Invalid option! / 错误：无效选项！" "$RED"
      exit 1
      ;;
  esac

  mkdir -p "$CERT_DIR/$domain"
  "$ACME_SH" --install-cert -d "$domain" --ecc --cert-file "$cert_path" --key-file "$key_path" --force || { log "Error: Failed to install certificate! / 错误：安装证书失败！" "$RED"; exit 1; }
  ensure_acme_renewal_job
}

create_config() {
  local domain="$1" main_port="$2"
  local masquerade_url password enable_split proxy_addr proxy_user proxy_pass
  local reuse_password reuse_masquerade

  if [[ -n "$EXISTING_MASQUERADE_URL" ]]; then
    reuse_masquerade=$(read_yes_no "$(i18n "检测到旧伪装 URL $EXISTING_MASQUERADE_URL，是否沿用？(默认 Y) [Y/n]: " "Detected previous masquerade URL $EXISTING_MASQUERADE_URL. Reuse it? (default Y) [Y/n]: ")" "Y")
    if [[ "$reuse_masquerade" =~ ^[Yy]$ ]]; then
      if validate_url "$EXISTING_MASQUERADE_URL"; then
        masquerade_url="$EXISTING_MASQUERADE_URL"
      else
        log_i18n "旧伪装 URL 格式无效，需要重新输入" "Previous masquerade URL is invalid; please enter a new one" "$YELLOW"
      fi
    fi
  fi
  if [[ -z "$masquerade_url" ]]; then
    while true; do
      read -p "$(get_msg input_url)" masquerade_url
      masquerade_url=${masquerade_url:-"https://wx.qq.com"}
      validate_url "$masquerade_url" && break
      log_i18n "错误：伪装 URL 必须以 http:// 或 https:// 开头，且不能包含空白" "Error: Masquerade URL must start with http:// or https:// and cannot contain whitespace" "$RED"
    done
  fi

  if [[ -n "$EXISTING_PASSWORD" ]]; then
    reuse_password=$(read_yes_no "$(i18n "检测到旧连接密码，是否沿用？(默认 Y) [Y/n]: " "Detected previous connection password. Reuse it? (default Y) [Y/n]: ")" "Y")
    if [[ "$reuse_password" =~ ^[Yy]$ ]]; then
      if validate_hysteria_secret "$EXISTING_PASSWORD"; then
        password="$EXISTING_PASSWORD"
      else
        log_i18n "旧连接密码包含不安全字符，需要重新输入" "Previous connection password contains unsafe characters; please enter a new one" "$YELLOW"
      fi
    fi
  fi
  if [[ -z "$password" ]]; then
    while true; do
      read -p "$(get_msg input_pwd)" password
      password=${password:-$(uuidgen)}
      validate_hysteria_secret "$password" && break
      log_i18n "错误：连接密码长度需为 6-128，且不能包含空白或 @:/?#[]" "Error: Password must be 6-128 chars and cannot contain whitespace or @:/?#[]" "$RED"
    done
  fi
  HYSTERIA_PASSWORD="$password"

  if [[ "$HYSTERIA_OBFS_PROMPTED" != "true" ]]; then
    prompt_obfs_settings
  fi

  log_i18n "使用伪装 URL: $masquerade_url" "Using masquerade URL: $masquerade_url" "$GREEN"
  log_i18n "使用密码: $password" "Using password: $password" "$GREEN"

  mkdir -p "$CONFIG_DIR"
  cat <<EOF > "$CONFIG_FILE"
listen: :$main_port
tls:
  cert: "$CERT_DIR/$domain/fullchain.pem"
  key: "$CERT_DIR/$domain/privkey.pem"
auth:
  type: password
  password: "$password"
EOF

  if [[ "$HYSTERIA_ENABLE_OBFS" == "true" && -n "$HYSTERIA_OBFS_PASSWORD" ]]; then
    cat <<EOF >> "$CONFIG_FILE"
obfs:
  type: salamander
  salamander:
    password: "$HYSTERIA_OBFS_PASSWORD"
EOF
  fi

  cat <<EOF >> "$CONFIG_FILE"
quic:
  initStreamReceiveWindow: 67108864
  maxStreamReceiveWindow: 268435456
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 1073741824
bandwidth:
  up: 1000 mbps
  down: 1000 mbps
masquerade:
  type: proxy
  proxy:
    url: $masquerade_url
    rewriteHost: true
speedTest: true
EOF

  printf "$(get_msg confirm_split)"
  enable_split=$(read_yes_no "" "N")
  if [[ "${enable_split:-N}" =~ ^[Yy]$ ]]; then
    read -p "$(get_msg input_proxy_addr)" proxy_addr
    proxy_addr=${proxy_addr:-"127.0.0.1:1080"}
    until validate_proxy_addr "$proxy_addr"; do
      log "$(get_msg err_proxy_addr)" "$RED"
      read -p "$(get_msg input_proxy_addr)" proxy_addr
      proxy_addr=${proxy_addr:-"127.0.0.1:1080"}
    done
    while true; do
      read -p "$(get_msg input_proxy_user)" proxy_user
      proxy_user=${proxy_user:-"cntink"}
      validate_proxy_credential "$proxy_user" && break
      log_i18n "错误：代理用户名只能包含字母、数字、点、下划线和短横线" "Error: Proxy username can only contain letters, numbers, dot, underscore, and hyphen" "$RED"
    done
    while true; do
      read -p "$(get_msg input_proxy_pass)" proxy_pass
      proxy_pass=${proxy_pass:-"cntink"}
      validate_proxy_credential "$proxy_pass" && break
      log_i18n "错误：代理密码只能包含字母、数字、点、下划线和短横线" "Error: Proxy password can only contain letters, numbers, dot, underscore, and hyphen" "$RED"
    done
    log_i18n "使用代理地址: $proxy_addr" "Using proxy address: $proxy_addr" "$GREEN"
    log_i18n "使用代理用户名: $proxy_user" "Using proxy username: $proxy_user" "$GREEN"
    log_i18n "使用代理密码: $proxy_pass" "Using proxy password: $proxy_pass" "$GREEN"

    cat <<EOF >> "$CONFIG_FILE"
outbounds:
  - name: "xray"
    type: socks5
    socks5:
      addr: $proxy_addr
      username: $proxy_user
      password: $proxy_pass
EOF
  else
    log_i18n "未启用分流" "Traffic splitting disabled" "$GREEN"
  fi

  [[ ! -f "$CONFIG_FILE" ]] && { log "Error: Failed to create config file / 错误：无法创建配置文件！" "$RED"; exit 1; }
}

generate_configs() {
  local domain="$1" main_port="$2" port_range="$3" password="$4" obfs_password="$5"
  local hostname=$(hostname -s)
  local query_params=("insecure=1")
  local clash_port_block="  port: $main_port"
  local clash_obfs_block=""
  local transport_block=""
  local port_part="$main_port"

  if [[ "$HYSTERIA_PORT_HOP_ENABLED" == "true" && -n "$port_range" ]]; then
    while true; do
      read -p "$(get_msg input_hop)" hop_interval
      hop_interval=${hop_interval:-300}
      validate_hop_interval "$hop_interval" && break
      log_i18n "错误：跳跃间隔必须为 1-86400 秒" "Error: Hop interval must be 1-86400 seconds" "$RED"
    done
    HYSTERIA_HOP_INTERVAL="$hop_interval"
    query_params+=("hopPorts=$(echo "$port_range" | tr ':' '-')")
    clash_port_block="  ports: $(echo "$port_range" | tr ':' '-')"
    transport_block=$(cat <<EOF
  transport:
    type: udp
    udp:
      hopInterval: ${hop_interval}s
EOF
)
  fi

  if [[ -n "$obfs_password" ]]; then
    query_params+=("obfs=salamander" "obfs-password=$obfs_password")
    clash_obfs_block=$(cat <<EOF
  obfs: salamander
  obfs-password: $obfs_password
EOF
)
  fi

  local query_string=$(IFS='&'; echo "${query_params[*]}")
  local sub_link="hysteria2://$password@$domain:$port_part/?$query_string#[DIY_Hy2]$hostname"
  local clash_config=$(cat <<EOF
- name: "[DIY_Hy2]$hostname"
  type: hysteria2
  server: $domain
$clash_port_block
  password: $password
  sni: $domain
  skip-cert-verify: false
$clash_obfs_block
$transport_block
EOF
)

  log_i18n "订阅链接: $sub_link" "Subscription link: $sub_link" "$GREEN"
  [[ -n "$obfs_password" ]] && log_i18n "混淆: Salamander ($obfs_password)" "Obfuscation: Salamander ($obfs_password)" "$GREEN"
  [[ "$HYSTERIA_PORT_HOP_ENABLED" == "true" ]] && log_i18n "端口跳跃: $port_range" "Port hopping: $port_range" "$GREEN"
  log_i18n "Clash 配置:" "Clash config:" "$GREEN"
  echo "$clash_config"
  command -v qrencode &>/dev/null && { log_i18n "生成二维码" "Generating QR code" "$GREEN"; echo "$sub_link" | qrencode -t ansiutf8; }
}

install_hysteria2() {
  check_dependencies

  load_existing_install_info

  local domain=$(get_domain_with_existing)
  log_i18n "使用域名: $domain" "Using domain: $domain" "$GREEN"
  local email=$(get_email "$domain")
  local main_port=$(get_main_port_with_existing)
  log_i18n "使用主端口: $main_port" "Using main port: $main_port" "$GREEN"
  local port_range=""

  prompt_obfs_settings
  prompt_port_hopping_settings
  port_range="$HYSTERIA_PORT_RANGE"

  check_existing_hysteria
  install_acme_sh
  configure_main_port_firewall "$main_port"
  if [[ "$HYSTERIA_PORT_HOP_ENABLED" == "true" ]]; then
    manage_firewall_rules "$port_range"
  fi
  issue_certificate "$domain" "$email"
  check_ssl_certificates "$domain"
  install_hysteria
  create_config "$domain" "$main_port"
  setup_service
  check_health "$domain" "$main_port" || exit 1
  generate_configs "$domain" "$main_port" "$port_range" "$HYSTERIA_PASSWORD" "$HYSTERIA_OBFS_PASSWORD"
}

# 主菜单循环
main_menu() {
  while true; do
    clear
    echo -e "${RED}$(get_msg service_exists)${NC}"
    read -p "$(get_msg input_option)" action
    case "$action" in
      1) manage_service ;;
      2) install_hysteria2; break ;;
      3) uninstall_hysteria && exit 0 ;;
      0) log_i18n "退出脚本" "Exiting script" "$GREEN"; exit 0 ;;
      *) log_i18n "无效选项，请选择 0-3" "Invalid option, please choose 0-3" "$YELLOW" ;;
    esac
  done
}

# 主逻辑
main() {
  check_root
  init_logging
  check_disk_space
  select_language

  if hysteria_exists; then
    main_menu
  else
    install_hysteria2
  fi

  log "$(get_msg install_done "$CONFIG_FILE")" "$GREEN"
}

# 捕获中断信号
trap 'log "Script interrupted, exiting... / 脚本中断，正在退出..." "$YELLOW"; exit 1' INT TERM
main
