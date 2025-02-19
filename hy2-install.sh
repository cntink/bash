#!/bin/bash
# 定义颜色变量
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 定义日志文件
LOG_FILE="/var/log/install_hysteria.log"

# 初始化日志文件 
mkdir -p "$(dirname "$LOG_FILE")"
if ! touch "$LOG_FILE" 2>/dev/null; then
  log "错误：无法创建日志文件，请检查权限！"
  exit 1
fi

# 记录日志函数
log() {
  local message="$1"
  if ! touch "$LOG_FILE" 2>/dev/null; then
    echo "错误：日志文件不可写！"
    exit 1
  fi
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
}

# 检查是否以 root 用户运行
[[ $EUID -ne 0 ]] && echo -e "${RED}错误：请以 root 用户运行此脚本！${NC}" && exit 1

# 检查依赖项
check_dependencies() {
  local dependencies=("curl" "wget" "jq" "iptables" "ip6tables" "netfilter-persistent" "dnsutils" "uuid-runtime")
  for dep in "${dependencies[@]}"; do
    dpkg -s "$dep" &>/dev/null || sudo apt install -y "$dep" &>/dev/null
  done
}
check_dependencies

# 询问用户输入域名
read -p "请输入域名: " domain

# 检查域名格式是否正确
validate_domain_format() {
  local domain="$1"
  if [[ "$domain" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
    return 0
  else
    return 1
  fi
}

# 检查域名解析是否正确
validate_domain_resolution() {
  local domain="$1"
  local server_ip=$(dig +short "$domain" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
  local local_ip=$(curl -s http://api4.ipify.org/)

  if [[ -z "$server_ip" || -z "$local_ip" ]]; then
    log "错误：无法获取域名解析或本地 IP 地址！"
    return 1
  fi
  
  # Check if any of the resolved IPs match the local IP
  if ! grep -q "$local_ip" <<< "$server_ip"; then
    log "错误：域名解析 IP ($server_ip) 与本机公网 IP ($local_ip) 不匹配！"
    return 1
  fi
  return 0
}

if ! validate_domain_format "$domain"; then
  log "错误：无效的域名格式！"
  exit 1 
fi

if ! validate_domain_resolution "$domain"; then
  log "错误：域名解析不正确！请确保 $domain 解析到当前服务器的公网 IP 地址。"
  exit 1 
fi

log "域名解析成功，开始安装 Hysteria2..."

# 自动生成邮箱地址（如果用户没有输入）
read -p "域名证书申请邮箱 (默认自动生成): " email
if [[ -z "$email" ]]; then
  email="admin@$domain"
  log "未提供邮箱，已使用默认邮箱：$email"
fi

# 处理证书申请
# 确保 acme.sh 已经安装并设置路径
if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
  log "未检测到 acme.sh 脚本，正在安装..."
  curl https://get.acme.sh | sh
fi
ACME_SH="$HOME/.acme.sh/acme.sh"  # 设置正确的 acme.sh 路径

# 检查是否已安装 Hysteria2
check_existing_hysteria() {
  if [[ -f /usr/local/bin/hysteria ]]; then
    read -p "卸载旧版本 Hysteria2？(默认卸载)(Y/n): " confirm
    confirm=${confirm:-Y}
    if [[ "$confirm" == "Y" || "$confirm" == "y" ]]; then
      systemctl stop hysteria || true
      systemctl disable hysteria || true
      rm -f /usr/local/bin/hysteria
      rm -rf /etc/hysteria
      rm -f /etc/systemd/system/hysteria.service
      log "已卸载旧版本 Hysteria2。"
    else
      log "取消安装。"
      exit 1
    fi
  fi
}
check_existing_hysteria

# 获取主端口（如果用户未输入，则使用默认值 443）
read -p "主端口 (默认 443): " raw_main_port
main_port=${raw_main_port:-443}
until [[ "$main_port" =~ ^[0-9]+$ && "$main_port" -ge 1 && "$main_port" -le 65535 ]]; do
  log "错误：无效的主端口号，请输入 1-65535 之间的数字！"
  read -p "请重新输入主端口 (默认 443，直接回车使用默认值): " raw_main_port
  main_port=${raw_main_port:-443}
done

# 获取端口范围（如果用户未输入，则使用默认值 40000-62000）
read -p "端口跳跃范围 (默认 40000-62000): " raw_port_range
format_port_range() {
  local input="$1"
    
  # 替换 '-' 或 ',' 为 ':'
  local formatted=$(echo "$input" | sed -E 's/[-,]/:/g')
  
  # 检查格式是否合法
  if [[ "$formatted" =~ ^[0-9]+:[0-9]+$ ]]; then
    local start_port=$(echo "$formatted" | cut -d ':' -f 1)
    local end_port=$(echo "$formatted" | cut -d ':' -f 2)
    
    # 验证端口范围是否有效
    if [[ "$start_port" -ge 1 && "$end_port" -le 65535 && "$start_port" -le "$end_port" ]]; then
      echo "$formatted"
      return 0
    fi
  fi
  
  # 如果格式无效，返回错误
  echo ""
  return 1
}
formatted_port_range=$(format_port_range "${raw_port_range:-40000-62000}")
if [[ -z "$formatted_port_range" ]]; then
  log "错误：无效的端口范围格式，请使用 '起始端口-结束端口' 或 '起始端口:结束端口' 格式！"
  exit 1
fi

# 获取网络接口名称
network_interface=$(ip -o -4 route show to default | awk '{print $5}')
if [[ -z "$network_interface" ]]; then
  log "错误：无法检测到默认网络接口，请手动指定！"
  exit 1
fi

# 检查系统是否支持 IPv6
check_ipv6_support() {
  if ip -6 route list | grep -q "default"; then
    return 0
  else
    return 1
  fi
}

# 配置防火墙规则
manage_firewall_rules() {
  local port_range="$1"
  local interface="$2"

  # 删除所有可能的端口跳跃规则
  for rule in $(sudo iptables -t nat -L PREROUTING -n --line-numbers | grep "REDIRECT" | awk '{print $1}'); do
    sudo iptables -t nat -D PREROUTING $rule
  done

  for rule in $(sudo iptables -L INPUT -n --line-numbers | grep "multiport" | awk '{print $1}'); do
    sudo iptables -D INPUT $rule
  done

  if command -v ip6tables &>/dev/null; then
    for rule in $(sudo ip6tables -t nat -L PREROUTING -n --line-numbers | grep "REDIRECT" | awk '{print $1}'); do
      sudo ip6tables -t nat -D PREROUTING $rule
    done

    for rule in $(sudo ip6tables -L INPUT -n --line-numbers | grep "multiport" | awk '{print $1}'); do
      sudo ip6tables -D INPUT $rule
    done
  fi

  # 添加新的规则
  sudo iptables -t nat -A PREROUTING -i "$interface" -p udp --dport "$port_range" -j REDIRECT --to-ports $main_port
  sudo iptables -A INPUT -p udp -m multiport --dports "$port_range" -j ACCEPT

  if command -v ip6tables &>/dev/null; then
    sudo ip6tables -t nat -A PREROUTING -i "$interface" -p udp --dport "$port_range" -j REDIRECT --to-ports $main_port
    sudo ip6tables -A INPUT -p udp -m multiport --dports "$port_range" -j ACCEPT
  fi

  # 保存规则
  mkdir -p /etc/iptables
  sudo iptables-save > /etc/iptables/rules.v4
  if command -v ip6tables-save &>/dev/null; then
    sudo ip6tables-save > /etc/iptables/rules.v6
  fi
  sudo netfilter-persistent save
}
log "配置防火墙规则 ..."
manage_firewall_rules "$formatted_port_range" "$network_interface"

# 安装证书
log "检查现有证书..."
existing_cert="/etc/ssl/certs/$domain/fullchain.pem"
existing_key="/etc/ssl/certs/$domain/privkey.pem"

# 检查证书
if [[ -f "$existing_cert" && -f "$existing_key" ]]; then
  expiry_date=$(openssl x509 -in "$existing_cert" -noout -enddate | cut -d'=' -f2)
  current_date=$(date -u +%s)
  expiry_timestamp=$(date -ud "$expiry_date" +%s)
  days_until_expiry=$(( (expiry_timestamp - current_date) / 86400 ))

  if [[ $days_until_expiry -gt 30 ]]; then
    read -p "证书有效，$days_until_expiry 天后过期。是否重新获取？(默认否)(y/N): " reissue_cert
    reissue_cert=${reissue_cert:-N}
    if [[ "$reissue_cert" == "y" || "$reissue_cert" == "Y" ]]; then
      skip_certificate_issue=false
    else
      skip_certificate_issue=true
    fi
  else
    log "检测到的证书即将过期或已过期，将重新获取证书。"
    skip_certificate_issue=false
  fi
else
  log "未检测到现有证书，将重新获取证书。"
  skip_certificate_issue=false
fi

if [[ "$skip_certificate_issue" == false ]]; then
# 选择证书申请方式
  echo -e "${BLUE}选择证书申请方式:${NC}"
  echo "1) Standalone 2) Cloudflare 3) Aliyun"
  read -p "选项 (1/2/3): " cert_option
  case $cert_option in
    1)
      # Standalone 模式的证书申请
      # 检查 80 端口是否被占用
      if sudo lsof -i :80 >/dev/null 2>&1; then
        log "警告：80 端口已被占用，尝试停止相关服务..."
        if systemctl list-units --type=service | grep -q nginx; then
          sudo systemctl stop nginx || true
        fi
        if systemctl list-units --type=service | grep -q apache2; then
          sudo systemctl stop apache2 || true
        fi
      fi
      # 允许 80 端口流量
      if ! sudo iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; then
        sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        sudo iptables-save > /etc/iptables/rules.v4
        sudo netfilter-persistent save
      fi
      # 创建 webroot 目录
      sudo mkdir -p /var/www/html/.well-known/acme-challenge
      sudo chmod -R 755 /var/www/html
      # 增加重试机制
      max_retries=3
      retry_interval=20
      retry_count=0
      while [[ $retry_count -lt $max_retries ]]; do
        log "正在尝试通过 Standalone 模式申请证书，第 $((retry_count + 1)) 次尝试..."
        if "$ACME_SH" --issue -d "$domain" --standalone -m "$email" --force --debug; then
          log "域名验证成功！"
          break
        else
          retry_count=$((retry_count + 1))
          sleep $retry_interval
        fi
      done
      if [[ $retry_count -eq $max_retries ]]; then
        log "错误：域名验证失败，请检查日志！"
        exit 1
      fi
      
      # 关闭80端口的流量
      sudo iptables -D INPUT -p tcp --dport 80 -j ACCEPT
      sudo iptables-save > /etc/iptables/rules.v4
      sudo netfilter-persistent save
      log "已关闭 80 端口的流量。"
      ;;
    2)
      read -p "请输入 Cloudflare API Key: " cloudflare_api_key
      read -s -p "请输入 Cloudflare Email: " cloudflare_email
      export CF_Key="$cloudflare_api_key"
      export CF_Email="$cloudflare_email"
      if ! "$ACME_SH" --issue --dns dns_cf -d "$domain" -m "$email" --force --debug; then
        log "错误：Cloudflare API 密钥无效或域名配置错误，请检查！"
        unset CF_Key
        unset CF_Email
        exit 1
      fi
      unset CF_Key
      unset CF_Email
      ;;
    3)
      read -p "请输入阿里云 AccessKey ID: " aliyun_access_key_id
      read -s -p "请输入阿里云 AccessKey Secret: " aliyun_access_key_secret
      export Ali_Key="$aliyun_access_key_id"
      export Ali_Secret="$aliyun_access_key_secret"
      if ! "$ACME_SH" --issue --dns dns_ali -d "$domain" -m "$email" --force --debug; then
        log "错误：Aliyun API 密钥无效或域名配置错误，请检查！"
        unset Ali_Key
        unset Ali_Secret
        exit 1
      fi
      unset Ali_Key
      unset Ali_Secret
      ;;
    *)
      log "${RED}无效选项，退出安装"
      exit 1
      ;;
  esac

  # 创建证书目录（如果不存在）
  mkdir -p "/etc/ssl/certs/$domain"

  # 安装证书
  log "正在安装证书..."
  "$ACME_SH" --installcert -d "$domain" \
    --cert-file "/etc/ssl/certs/$domain/fullchain.pem" \
    --key-file "/etc/ssl/certs/$domain/privkey.pem" \
    --force

  # 验证证书文件是否存在
  if [[ ! -f "/etc/ssl/certs/$domain/fullchain.pem" || ! -f "/etc/ssl/certs/$domain/privkey.pem" ]]; then
    log "${RED}错误：证书安装失败，请检查 acme.sh 的配置！"
    exit 1
  fi
fi

# 检查 SSL 证书路径或相关文件是否有问题
check_ssl_certificates() {
  local openssl_check=$(command -v openssl)
  if [[ -z "$openssl_check" ]]; then
    echo -e "${RED}错误：未检测到 OpenSSL，正在安装...${NC}"
    if ! apt update && apt install -y openssl &>/dev/null; then
      echo -e "${RED}错误：OpenSSL 安装失败，请手动安装！${NC}"
      exit 1
    fi
  fi

  # 检查CA证书包是否支持HTTPS和TLS连接
  local cert_check=$(echo | openssl s_client -connect github.com:443 -CAfile /etc/ssl/certs/ca-certificates.crt 2>/dev/null | grep -q 'Verify return code: 0 (ok)' && echo "OK" || echo "FAIL")
  
  if [[ "$cert_check" != "OK" ]]; then
    echo -e "${RED}警告：CA 证书包可能有问题，无法验证TLS连接，正在更新...${NC}"
    if ! apt update && apt install -y --reinstall ca-certificates &>/dev/null; then
      echo -e "${RED}错误：更新 CA 证书包失败，请手动检查！${NC}"
      exit 1
    fi
  fi
}

check_ssl_certificates

# 下载并安装 Hysteria2
download_hysteria() {
  local max_retries=3
  local retry_interval=10
  local retry_count=0
  while [[ $retry_count -lt $max_retries ]]; do
    log "正在尝试下载 Hysteria2，第 $((retry_count + 1)) 次尝试..."
    latest_version=$(curl -sL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')
    if [[ -z "$latest_version" ]]; then
      log "${RED}警告：无法获取 Hysteria2 最新版本，重试中..."
      retry_count=$((retry_count + 1))
      sleep $retry_interval
      continue
    fi
    download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-amd64"
    log "下载链接: $download_url"
    wget -q "$download_url" -O /usr/local/bin/hysteria
    if [[ $? -eq 0 ]]; then
      log "Hysteria2 下载成功！"
      break
    else
      log "${RED}警告：Hysteria2 下载失败，重试中..."
      retry_count=$((retry_count + 1))
      sleep $retry_interval
    fi
  done
  if [[ $retry_count -eq $max_retries ]]; then
    log "错误：Hysteria2 下载失败，请检查网络连接！"
    exit 1
  fi
}

download_hysteria
chmod +x /usr/local/bin/hysteria

# 检查文件是否成功安装
if [[ ! -f /usr/local/bin/hysteria ]]; then
  log "${RED}错误：Hysteria2 安装失败，请检查网络连接或权限！"
  exit 1
fi

# 创建 Hysteria2 配置文件
mkdir -p /etc/hysteria
read -p "伪装 URL (默认 https://wx.qq.com): " masquerade_url
read -p "密码 (默认生成 UUID): " password
if [[ -z "$password" ]]; then
  password=$(uuidgen)
  echo -e "${RED}密码: $password${NC}"
fi
[[ -z "$masquerade_url" ]] && masquerade_url="https://wx.qq.com"
cat <<EOF > /etc/hysteria/config.yaml
listen: :$main_port
tls:
  cert: "/etc/ssl/certs/$domain/fullchain.pem"
  key: "/etc/ssl/certs/$domain/privkey.pem"
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

# 创建 systemd 服务文件
log "创建 systemd 服务文件..."
cat <<EOF > /etc/systemd/system/hysteria.service
[Unit]
Description=Hysteria2 Service
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# 启动并启用服务
log "启动并启用 Hysteria2 服务..."
systemctl daemon-reload
systemctl enable hysteria
systemctl start hysteria

# 检查 Hysteria2 服务是否启动成功
if systemctl is-active --quiet hysteria; then
  echo -e "${GREEN}Hysteria2 已成功安装并启动！${NC}"
  
  # 设置端口跳跃间隔时间
  read -p "端口跳跃间隔 (秒, 默认 30): " hop_interval
  hop_interval=${hop_interval:-30}
  
# 获取当前计算机名
hostname=$(hostname | tr -d '[:space:]' | tr -cd '[:alnum:]-_')

generate_subscription_and_clash() {
  # 解析端口范围（确保格式正确）
  local start_port=$(echo "$formatted_port_range" | cut -d ':' -f 1)
  local end_port=$(echo "$formatted_port_range" | cut -d ':' -f 2)
  local ports_range="$start_port-$end_port"
  
  # 生成订阅链接，符合 Hysteria2 官方文档并添加名称信息
  local subscription_link="hysteria2://$password@$domain:$main_port/?insecure=1&hopPorts=$formatted_port_range#[DIY_Hy2]$hostname"
  local clash_config=$(cat <<EOF
  - name: "[DIY_Hy2]$hostname"
    type: hysteria2
    server: $domain
    ports: $ports_range
    password: $password
    sni: $domain
    skip-cert-verify: false
    transport:
      type: udp
      udp:
        hopInterval: ${hop_interval}s
EOF
)

  echo -e "${GREEN}订阅链接:${NC} $subscription_link"
  echo -e "${GREEN}注意:${NC} 请在您的客户端配置中手动设置端口跳跃间隔时间为 $hop_interval 秒。"
  echo -e "${GREEN}生成订阅链接的二维码:${NC}"
  echo -e "$subscription_link" | qrencode -t ansiutf8
  echo -e "${GREEN}Clash节点配置模板:${NC}"
  echo "$clash_config"
}
  
  generate_subscription_and_clash

else
  echo -e "${RED}错误：Hysteria2 启动失败，请检查日志！${NC}"
  exit 1
fi
