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

# 初始化日志文件并检查权限
init_logging() {
  local log_dir=$(dirname "$LOG_FILE")
  mkdir -p "$log_dir" || { echo -e "${RED}Cannot create log directory $log_dir${NC}"; exit 1; }
  touch "$LOG_FILE" 2>/dev/null || { echo -e "${RED}Cannot create log file $LOG_FILE${NC}"; exit 1; }
}

# 日志记录函数，支持轮转
log() {
  local message="$1"
  local color="${2:-$NC}"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  if [[ -f "$LOG_FILE" && $(stat -c%s "$LOG_FILE") -ge $LOG_MAX_SIZE ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.$(date '+%Y%m%d%H%M%S').bak"
    touch "$LOG_FILE"
    echo "$timestamp - ${YELLOW}$(get_msg log_rotated)${NC}" >> "$LOG_FILE"
  fi
  echo -e "$timestamp - ${color}${message}${NC}" | tee -a "$LOG_FILE"
}

# 语言选择函数
select_language() {
  clear  # 清屏
  if [ "$SCRIPT_LANG" == "zh" ]; then
    echo -e "${RED}请选择语言:${NC}"
    echo -e "${GREEN}1) 中文${NC}"
    echo -e "${GREEN}2) 英文${NC}"
    read -p "输入选项 (1/2): " lang_choice
  else
    echo -e "${RED}Select language:${NC}"
    echo -e "${GREEN}1) Chinese${NC}"
    echo -e "${GREEN}2) English${NC}"
    read -p "Enter option (1/2): " lang_choice
  fi
  case "$lang_choice" in
    1) SCRIPT_LANG="zh" ;;
    2) SCRIPT_LANG="en" ;;
    *) SCRIPT_LANG="zh" ; log "$(get_msg invalid_lang)" "$YELLOW" ;;
  esac
  log "$(get_msg using_lang): $SCRIPT_LANG"
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
MESSAGES[zh_select_cert]="选择证书申请方式:\n${GREEN}1) Standalone${NC}\n${GREEN}2) Cloudflare${NC}\n${GREEN}3) Aliyun${NC}\n选项 (1/2/3): "
MESSAGES[zh_confirm_uninstall]="检测到已有 Hysteria2，是否卸载旧版本？(默认 Y)\n${GREEN}Y) 是${NC}\n${GREEN}n) 否${NC}\n输入选项 (Y/n): "
MESSAGES[zh_confirm_backup]="是否备份旧版本配置？(默认 N)\n${GREEN}y) 是${NC}\n${GREEN}N) 否${NC}\n输入选项 (y/N): "
MESSAGES[zh_confirm_reissue]="现有证书剩余 %d 天，是否重新获取？(默认 N)\n${GREEN}y) 是${NC}\n${GREEN}N) 否${NC}\n输入选项 (y/N): "
MESSAGES[zh_err_root]="错误：请以 root 用户运行此脚本！"
MESSAGES[zh_err_domain]="错误：无效的域名格式或解析不正确！"
MESSAGES[zh_err_ssl]="错误：OpenSSL 或 CA 证书安装失败！"
MESSAGES[zh_err_cert]="错误：无法解析证书有效期，请检查文件 %s"
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
MESSAGES[zh_service_exists]="检测到 Hysteria2 服务已存在，请选择操作:\n${GREEN}1) 管理服务${NC}\n${GREEN}2) 安装新 Hysteria2${NC}"
MESSAGES[zh_manage_menu]="请选择管理操作:\n${GREEN}1) 查看服务状态${NC}\n${GREEN}2) 查看最近 30 条日志${NC}\n${GREEN}3) 重启服务${NC}\n${GREEN}4) 停止服务${NC}\n${GREEN}5) 显示配置信息${NC}\n${GREEN}6) 返回上级菜单${NC}\n${GREEN}7) 退出脚本${NC}"
MESSAGES[zh_service_status]="Hysteria2 服务状态:"
MESSAGES[zh_service_logs]="Hysteria2 服务最近 30 条日志:"
MESSAGES[zh_service_restart]="正在重启 Hysteria2 服务..."
MESSAGES[zh_service_stop]="正在停止 Hysteria2 服务..."
MESSAGES[zh_service_config]="Hysteria2 服务配置信息:"
MESSAGES[zh_continue_prompt]="按回车继续管理，或输入 q 退出: "
MESSAGES[zh_input_option]="输入选项 (1/2): "
MESSAGES[zh_input_manage_option]="输入选项 (1-7): "
# 英文提示
MESSAGES[en_input_domain]="Please enter the domain: "
MESSAGES[en_input_email]="Email for certificate application (default auto-generated): "
MESSAGES[en_input_port]="Main port (default 443): "
MESSAGES[en_input_range]="Port hopping range (default 40000-62000): "
MESSAGES[en_input_url]="Masquerade URL (default https://wx.qq.com): "
MESSAGES[en_input_pwd]="Password (default UUID generated): "
MESSAGES[en_input_hop]="Port hopping interval (seconds, default 30): "
MESSAGES[en_select_cert]="Select certificate issuance method:\n${GREEN}1) Standalone${NC}\n${GREEN}2) Cloudflare${NC}\n${GREEN}3) Aliyun${NC}\nOption (1/2/3): "
MESSAGES[en_confirm_uninstall]="Existing Hysteria2 detected, uninstall old version? (default Y)\n${GREEN}Y) Yes${NC}\n${GREEN}n) No${NC}\nEnter option (Y/n): "
MESSAGES[en_confirm_backup]="Backup old version config? (default N)\n${GREEN}y) Yes${NC}\n${GREEN}N) No${NC}\nEnter option (y/N): "
MESSAGES[en_confirm_reissue]="Current certificate has %d days remaining, reissue? (default N)\n${GREEN}y) Yes${NC}\n${GREEN}N) No${NC}\nEnter option (y/N): "
MESSAGES[en_err_root]="Error: Please run this script as root!"
MESSAGES[en_err_domain]="Error: Invalid domain format or resolution!"
MESSAGES[en_err_ssl]="Error: Failed to install OpenSSL or CA certificates!"
MESSAGES[en_err_cert]="Error: Unable to parse certificate validity, check file %s"
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
MESSAGES[en_service_exists]="Hysteria2 service detected, choose action:\n${GREEN}1) Manage service${NC}\n${GREEN}2) Install new Hysteria2${NC}"
MESSAGES[en_manage_menu]="Select management action:\n${GREEN}1) View service status${NC}\n${GREEN}2) View last 30 log entries${NC}\n${GREEN}3) Restart service${NC}\n${GREEN}4) Stop service${NC}\n${GREEN}5) Show config info${NC}\n${GREEN}6) Return to previous menu${NC}\n${GREEN}7) Exit script${NC}"
MESSAGES[en_service_status]="Hysteria2 service status:"
MESSAGES[en_service_logs]="Last 30 log entries for Hysteria2 service:"
MESSAGES[en_service_restart]="Restarting Hysteria2 service..."
MESSAGES[en_service_stop]="Stopping Hysteria2 service..."
MESSAGES[en_service_config]="Hysteria2 service configuration info:"
MESSAGES[en_continue_prompt]="Press Enter to continue managing, or enter 'q' to quit: "
MESSAGES[en_input_option]="Enter option (1/2): "
MESSAGES[en_input_manage_option]="Enter option (1-7): "

# 获取语言特定消息
get_msg() {
  local key="$1"
  shift
  printf "${MESSAGES[${SCRIPT_LANG}_${key}]}" "$@"
}

# 检查是否以 root 用户运行
check_root() {
  [[ $EUID -ne 0 ]] && { log "$(get_msg err_root)" "$RED"; exit 1; }
}

# 更新包索引（全局执行一次）
update_package_index() {
  if ! $APT_UPDATED; then
    log "$(get_msg update_index)"
    timeout 30 apt update &>/dev/null || log "Warning: Failed to update package index, possible network issue" "$YELLOW"
    APT_UPDATED=true
  fi
}

# 检查并安装依赖项
check_dependencies() {
  local required_deps=("curl" "wget" "jq" "iptables" "dnsutils" "uuid-runtime")
  local optional_deps=("ip6tables" "netfilter-persistent")
  log "$(get_msg check_deps)"

  update_package_index

  for dep in "${required_deps[@]}"; do
    if ! dpkg -s "$dep" &>/dev/null; then
      log "$(get_msg install_dep "$dep")"
      timeout 60 apt install -y "$dep" &>/dev/null
      if [[ $? -ne 0 ]]; then
        log "$(get_msg err_install "$dep" "$(apt install -y "$dep" 2>&1)")" "$RED"
        exit 1
      fi
    fi
  done

  for dep in "${optional_deps[@]}"; do
    if ! dpkg -s "$dep" &>/dev/null; then
      log "$(get_msg install_opt_dep "$dep")"
      timeout 60 apt install -y "$dep" &>/dev/null || log "$(get_msg warn_install "$dep")" "$YELLOW"
    fi
  done
  log "$(get_msg deps_done)"
}

# 获取用户输入的域名并验证
get_domain() {
  read -p "$(get_msg input_domain)" domain
  until validate_domain_format "$domain" && validate_domain_resolution "$domain"; do
    log "$(get_msg err_domain)" "$RED"
    read -p "$(get_msg input_domain)" domain
  done
  echo "$domain"
}

# 验证域名格式
validate_domain_format() {
  local domain="$1"
  [[ "$domain" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]] && return 0
  return 1
}

# 验证域名解析是否匹配本地公网 IP
validate_domain_resolution() {
  local domain="$1"
  local server_ip=$(dig +short "$domain" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
  local local_ip=$(curl -s http://api4.ipify.org/)
  [[ -z "$server_ip" || -z "$local_ip" ]] && return 1
  echo "$server_ip" | grep -q "$local_ip" || return 1
  return 0
}

# 获取用户邮箱，默认为 admin@domain
get_email() {
  local domain="$1"
  read -p "$(get_msg input_email)" email
  email=${email:-"admin@$domain"}
  log "Using email: $email"
  echo "$email"
}

# 安装 acme.sh（如果未安装）
install_acme_sh() {
  [[ -f "$ACME_SH" ]] && return 0
  log "Installing acme.sh..."
  curl https://get.acme.sh | sh || { log "Error: Failed to install acme.sh!" "$RED"; exit 1; }
}

# 检查并备份已有 Hysteria2 配置
check_existing_hysteria() {
  read -p "$(get_msg confirm_uninstall)" confirm_uninstall
  confirm_uninstall=${confirm_uninstall:-Y}
  if [[ "$confirm_uninstall" =~ ^[Yy]$ ]]; then
    read -p "$(get_msg confirm_backup)" confirm_backup
    confirm_backup=${confirm_backup:-N}
    if [[ "$confirm_backup" =~ ^[Yy]$ ]]; then
      log "$(get_msg backup_uninstall)"
      mkdir -p "$BACKUP_DIR"
      local backup_file="$BACKUP_DIR/hysteria_backup_$(date '+%Y%m%d%H%M%S').tar.gz"
      tar -czf "$backup_file" /usr/local/bin/hysteria "$CONFIG_DIR" "$SYSTEMD_SERVICE" 2>/dev/null
      log "$(get_msg backup_done "$backup_file")" "$GREEN"
    fi
    systemctl stop "$SERVICE_NAME" &>/dev/null || true
    systemctl disable "$SERVICE_NAME" &>/dev/null || true
    rm -f /usr/local/bin/hysteria "$SYSTEMD_SERVICE"
    rm -rf "$CONFIG_DIR"
  else
    log "Canceled installation"
    exit 0
  fi
}

# 获取主端口，默认 443
get_main_port() {
  read -p "$(get_msg input_port)" raw_main_port
  main_port=${raw_main_port:-443}
  until [[ "$main_port" =~ ^[0-9]+$ && "$main_port" -ge 1 && "$main_port" -le 65535 ]]; do
    log "Error: Invalid port!" "$RED"
    read -p "$(get_msg input_port)" raw_main_port
    main_port=${raw_main_port:-443}
  done
  echo "$main_port"
}

# 获取端口跳跃范围，默认 40000-62000
get_port_range() {
  read -p "$(get_msg input_range)" raw_port_range
  raw_port_range=${raw_port_range:-"40000-62000"}
  local formatted=$(echo "$raw_port_range" | sed 's/[-,:]/:/g')
  local start_port=$(echo "$formatted" | cut -d':' -f1)
  local end_port=$(echo "$formatted" | cut -d':' -f2)
  until [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ && "$start_port" -ge 1 && "$end_port" -le 65535 && "$start_port" -le "$end_port" ]]; do
    log "Error: Invalid range!" "$RED"
    read -p "$(get_msg input_range)" raw_port_range
    raw_port_range=${raw_port_range:-"40000-62000"}
    formatted=$(echo "$raw_port_range" | sed 's/[-,:]/:/g')
    start_port=$(echo "$formatted" | cut -d':' -f1)
    end_port=$(echo "$formatted" | cut -d':' -f2)
  done
  echo "$formatted"
}

# 配置防火墙规则
manage_firewall_rules() {
  local port_range="$1"
  local interface=$(ip -o -4 route show to default | awk '{print $5}')
  [[ -z "$interface" ]] && { log "Error: Cannot detect network interface!" "$RED"; exit 1; }

  log "$(get_msg config_firewall)"

  iptables -t nat -L PREROUTING -n --line-numbers | grep -E "udp.*$port_range" | awk '{print $1}' | sort -r | while read line; do
    iptables -t nat -D PREROUTING "$line" &>/dev/null
  done
  iptables -L INPUT -n --line-numbers | grep -E "udp.*multiport.*$port_range" | awk '{print $1}' | sort -r | while read line; do
    iptables -D INPUT "$line" &>/dev/null
  done
  if command -v ip6tables &>/dev/null && ip -6 route list | grep -q "default"; then
    ip6tables -t nat -L PREROUTING -n --line-numbers | grep -E "udp.*$port_range" | awk '{print $1}' | sort -r | while read line; do
      ip6tables -t nat -D PREROUTING "$line" &>/dev/null
    done
    ip6tables -L INPUT -n --line-numbers | grep -E "udp.*multiport.*$port_range" | awk '{print $1}' | sort -r | while read line; do
      ip6tables -D INPUT "$line" &>/dev/null
    done
  fi

  iptables -t nat -A PREROUTING -i "$interface" -p udp --dport "$port_range" -j REDIRECT --to-ports "$main_port"
  iptables -A INPUT -p udp -m multiport --dports "$port_range" -j ACCEPT
  if command -v ip6tables &>/dev/null && ip -6 route list | grep -q "default"; then
    ip6tables -t nat -A PREROUTING -i "$interface" -p udp --dport "$port_range" -j REDIRECT --to-ports "$main_port"
    ip6tables -A INPUT -p udp -m multiport --dports "$port_range" -j ACCEPT
  fi

  if ! iptables -C INPUT -p tcp --dport 22 -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    log "Added SSH rule (TCP 22) to INPUT chain" "$GREEN"
  fi

  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
  netfilter-persistent save &>/dev/null || log "Warning: Failed to save firewall rules" "$YELLOW"
}

# 获取并安装 SSL 证书
issue_certificate() {
  local domain="$1" email="$2"
  local cert_path="$CERT_DIR/$domain/fullchain.pem"
  local key_path="$CERT_DIR/$domain/privkey.pem"

  if [[ -f "$cert_path" && -f "$key_path" ]]; then
    local expiry_date=$(openssl x509 -in "$cert_path" -noout -enddate | sed 's/notAfter=//')
    if [[ -n "$expiry_date" ]]; then
      local expiry_ts=$(date -d "$expiry_date" +%s 2>/dev/null)
      local current_ts=$(date +%s 2>/dev/null)
      if [[ -n "$expiry_ts" && -n "$current_ts" ]]; then
        local days_left=$(( (expiry_ts - current_ts) / 86400 ))
        log "Current certificate has $days_left days remaining"
        read -p "$(printf "$(get_msg confirm_reissue)" "$days_left")" reissue
        if [[ "${reissue:-N}" =~ ^[Yy]$ ]]; then
          log "User chose to reissue certificate"
        else
          log "User chose to keep existing certificate"
          return 0
        fi
      else
        log "$(get_msg err_cert "$cert_path")" "$RED"
        log "Unable to parse certificate validity, will attempt to reissue"
      fi
    else
      log "$(get_msg err_cert "$cert_path")" "$RED"
      log "Unable to read certificate expiry, will attempt to reissue"
    fi
  fi

  log "Issuing certificate..."
  echo -e "${RED}$(get_msg select_cert)${NC}"
  read -p "$(get_msg input_option)" cert_option
  case "$cert_option" in
    1)
      if lsof -i :80 >/dev/null 2>&1; then
        log "Warning: Port 80 occupied, releasing..." "$YELLOW"
        systemctl stop nginx &>/dev/null || true
        systemctl stop apache2 &>/dev/null || true
      fi
      iptables -A INPUT -p tcp --dport 80 -j ACCEPT &>/dev/null
      "$ACME_SH" --issue -d "$domain" --standalone -m "$email" --force || { log "Error: Failed to issue certificate via Standalone!" "$RED"; exit 1; }
      iptables -D INPUT -p tcp --dport 80 -j ACCEPT &>/dev/null
      ;;
    2)
      read -p "Cloudflare API Key: " cf_key
      read -s -p "Cloudflare Email: " cf_email; echo
      export CF_Key="$cf_key" CF_Email="$cf_email"
      "$ACME_SH" --issue --dns dns_cf -d "$domain" -m "$email" --force || { log "Error: Failed to issue certificate via Cloudflare!" "$RED"; exit 1; }
      unset CF_Key CF_Email
      ;;
    3)
      read -p "Aliyun AccessKey ID: " ali_key
      read -s -p "Aliyun AccessKey Secret: " ali_secret; echo
      export Ali_Key="$ali_key" Ali_Secret="$ali_secret"
      "$ACME_SH" --issue --dns dns_ali -d "$domain" -m "$email" --force || { log "Error: Failed to issue certificate via Aliyun!" "$RED"; exit 1; }
      unset Ali_Key Ali_Secret
      ;;
    *)
      log "Error: Invalid option!" "$RED"; exit 1
      ;;
  esac

  mkdir -p "$CERT_DIR/$domain"
  "$ACME_SH" --installcert -d "$domain" --cert-file "$cert_path" --key-file "$key_path" --force || { log "Error: Failed to install certificate!" "$RED"; exit 1; }
}

# 检查 SSL 证书环境
check_ssl_certificates() {
  log "$(get_msg check_ssl)"

  if ! command -v openssl &>/dev/null; then
    log "Error: OpenSSL not detected, installing..." "$RED"
    update_package_index
    timeout 60 apt install -y openssl &>/dev/null || { log "$(get_msg err_ssl)" "$RED"; exit 1; }
    log "OpenSSL installed" "$GREEN"
  fi

  local ca_files=("/etc/ssl/certs/ca-certificates.crt" "/etc/pki/tls/certs/ca-bundle.crt")
  local ca_file=""
  for file in "${ca_files[@]}"; do
    if [[ -f "$file" ]]; then
      ca_file="$file"
      break
    fi
  done

  if [[ -z "$ca_file" ]]; then
    log "$(get_msg ssl_ca_missing "$ca_files[0]")" "$YELLOW"
    update_package_index
    timeout 60 apt install -y ca-certificates &>/dev/null || { log "Warning: Failed to install CA certificates, proceeding anyway" "$YELLOW"; return 0; }
    log "CA certificates installed" "$GREEN"
    ca_file="${ca_files[0]}"
  fi

  if [[ -f "$ca_file" ]]; then
    local expiry_date=$(openssl crl2pkcs7 -nocrl -certfile "$ca_file" | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -m 1 "notAfter" | cut -d'=' -f2)
    if [[ -n "$expiry_date" ]]; then
      local expiry_ts=$(date -d "$expiry_date" +%s 2>/dev/null)
      local current_ts=$(date +%s)
      if [[ $expiry_ts -gt $current_ts ]]; then
        log "$(get_msg ssl_ok)" "$GREEN"
      else
        log "$(get_msg ssl_ca_invalid)" "$YELLOW"
        update_package_index
        timeout 60 apt install -y --reinstall ca-certificates &>/dev/null || log "Warning: Failed to update CA certificates, proceeding anyway" "$YELLOW"
        log "CA certificates updated" "$GREEN"
      fi
    else
      log "Warning: Unable to verify CA certificate validity, assuming valid" "$YELLOW"
    fi
  fi
}

# 下载并安装 Hysteria2
install_hysteria() {
  local max_retries=3 retry_count=0
  while [[ $retry_count -lt $max_retries ]]; do
    log "$(get_msg download_hy2 "$((retry_count + 1))" "$max_retries")"
    local version=$(curl -sL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')
    [[ -z "$version" ]] && { log "Warning: Failed to get version..." "$YELLOW"; retry_count=$((retry_count + 1)); sleep 10; continue; }
    local url="https://github.com/apernet/hysteria/releases/download/${version}/hysteria-linux-amd64"
    wget -q "$url" -O /usr/local/bin/hysteria && break
    retry_count=$((retry_count + 1))
    sleep 10
  done
  [[ $retry_count -eq $max_retries ]] && { log "Error: Download failed!" "$RED"; exit 1; }
  chmod +x /usr/local/bin/hysteria
}

# 创建 Hysteria2 配置文件
create_config() {
  local domain="$1" main_port="$2"
  read -p "$(get_msg input_url)" masquerade_url
  read -p "$(get_msg input_pwd)" password
  masquerade_url=${masquerade_url:-"https://wx.qq.com"}
  password=${password:-$(uuidgen)}
  log "Using password: $password"

  mkdir -p "$CONFIG_DIR"
  cat <<EOF > "$CONFIG_FILE"
listen: :$main_port
tls:
  cert: "$CERT_DIR/$domain/fullchain.pem"
  key: "$CERT_DIR/$domain/privkey.pem"
auth:
  type: password
  password: "$password"
quic:
  initStreamReceiveWindow: 67108864
  maxStreamReceiveWindow: 268435456
  maxConnectionReceiveWindow: 1073741824
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
}

# 创建并启动 systemd 服务
setup_service() {
  log "$(get_msg create_service)"
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
  systemctl start "$SERVICE_NAME" || { log "Error: Service start failed!" "$RED"; exit 1; }
}

# 健康检查 Hysteria2 服务
check_health() {
  local domain="$1" main_port="$2"
  log "$(get_msg check_health)"
  sleep 2
  if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Error: Service not running!" "$RED"
    return 1
  fi
  if command -v nc &>/dev/null; then
    nc -z -u "$domain" "$main_port" &>/dev/null
    if [[ $? -eq 0 ]]; then
      log "$(get_msg service_ok)" "$GREEN"
    else
      log "Warning: Port $main_port not responding" "$YELLOW"
      return 1
    fi
  else
    log "Note: NC not installed, skipping port check" "$YELLOW"
  fi
  return 0
}

# 生成订阅链接和 Clash 配置
generate_configs() {
  local domain="$1" main_port="$2" port_range="$3" password="$4"
  read -p "$(get_msg input_hop)" hop_interval
  hop_interval=${hop_interval:-30}
  local hostname=$(hostname -s)

  local sub_link="hysteria2://$password@$domain:$main_port/?insecure=1&hopPorts=$port_range#[DIY_Hy2]$hostname"
  local clash_config=$(cat <<EOF
- name: "[DIY_Hy2]$hostname"
  type: hysteria2
  server: $domain
  ports: $(echo "$port_range" | tr ':' '-')
  password: $password
  sni: $domain
  skip-cert-verify: false
  transport:
    type: udp
    udp:
      hopInterval: ${hop_interval}s
EOF
)

  log "Subscription link: $sub_link" "$GREEN"
  log "Clash config:" "$GREEN"
  echo "$clash_config"
  command -v qrencode &>/dev/null && { log "Generating QR code:" "$GREEN"; echo "$sub_link" | qrencode -t ansiutf8; }
}

# 查看服务状态
view_service_status() {
  log "$(get_msg service_status)"
  systemctl status "$SERVICE_NAME" --no-pager
}

# 查看最近 30 条日志
view_service_logs() {
  log "$(get_msg service_logs)"
  journalctl -u "$SERVICE_NAME" -n 30 --no-pager
}

# 重启服务
restart_service() {
  log "$(get_msg service_restart)"
  systemctl restart "$SERVICE_NAME" && log "Service restarted successfully" "$GREEN" || log "Error: Failed to restart service!" "$RED"
}

# 停止服务
stop_service() {
  log "$(get_msg service_stop)"
  systemctl stop "$SERVICE_NAME" && log "Service stopped successfully" "$GREEN" || log "Error: Failed to stop service!" "$RED"
}

# 显示配置信息
show_config_info() {
  log "$(get_msg service_config)"
  if [[ -f "$CONFIG_FILE" ]]; then
    cat "$CONFIG_FILE"
  else
    log "Error: Config file $CONFIG_FILE not found!" "$RED"
  fi
}

# 服务管理菜单
manage_service() {
  while true; do
    clear  # 每次选择后清屏
    echo -e "${RED}$(get_msg manage_menu)${NC}"
    read -p "$(get_msg input_manage_option)" choice
    case "$choice" in
      1) view_service_status ;;
      2) view_service_logs ;;
      3) restart_service ;;
      4) stop_service ;;
      5) show_config_info ;;
      6) return 0 ;;  # 返回上级菜单
      7) log "Exiting script" "$GREEN"; exit 0 ;;  # 退出脚本
      *) log "Invalid option, please choose 1-7" "$YELLOW" ;;
    esac
    read -p "$(get_msg continue_prompt)" cont
    [[ "$cont" == "q" || "$cont" == "Q" ]] && break
  done
  return 0  # 确保退出循环后返回
}

# 安装 Hysteria2
install_hysteria2() {
  local domain=$(get_domain)
  local email=$(get_email "$domain")
  local main_port=$(get_main_port)
  local port_range=$(get_port_range)

  check_existing_hysteria
  install_acme_sh
  manage_firewall_rules "$port_range"
  issue_certificate "$domain" "$email"
  check_ssl_certificates
  install_hysteria
  create_config "$domain" "$main_port"
  setup_service
  check_health "$domain" "$main_port" || exit 1
  generate_configs "$domain" "$main_port" "$port_range" "$(grep 'password:' "$CONFIG_FILE" | awk '{print $2}')"
}

# 主菜单循环
main_menu() {
  while true; do
    clear  # 每次循环清屏
    echo -e "${RED}$(get_msg service_exists)${NC}"
    read -p "$(get_msg input_option)" action
    case "$action" in
      1) manage_service ;;
      2) install_hysteria2; break ;;
      *) log "Invalid option, please choose 1-2" "$YELLOW" ;;
    esac
  done
}

# 主逻辑
main() {
  init_logging
  select_language
  check_root

  # 检查是否已存在 Hysteria2 服务
  if [[ -f "$SYSTEMD_SERVICE" && -f /usr/local/bin/hysteria ]]; then
    main_menu
  else
    install_hysteria2
  fi

  log "$(get_msg install_done "$CONFIG_FILE")" "$GREEN"
}

# 捕获中断信号
trap 'log "Script interrupted, exiting..." "$YELLOW"; exit 1' INT TERM
main
