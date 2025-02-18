#!/bin/bash
exec </dev/tty

# 定义颜色代码
GREEN='\033[0;32m'  # 绿色
BLUE='\033[0;34m'   # 蓝色
YELLOW='\033[0;33m' # 黄色
RED='\033[0;31m'    # 红色
NC='\033[0m'        # 无颜色（重置）

# 确保依赖已安装
sudo apt-get update
sudo apt-get install -y iptables iptables-persistent openssl curl wget dnsutils jq net-tools socat

# 安装 acme.sh
if [[ ! -f ~/.acme.sh/acme.sh ]]; then
  curl https://get.acme.sh | sh
fi

# 加载 acme.sh 环境变量
source "$HOME/.acme.sh/acme.sh.env"

# 确定 acme.sh 的路径
ACME_SH=~/.acme.sh/acme.sh
if [[ ! -f "$ACME_SH" ]]; then
  echo -e "${RED}错误：无法找到 acme.sh，请检查安装是否成功！${NC}"
  exit 1
fi

# 获取用户输入
read -p "请输入主端口 (默认 4488, 直接回车使用默认值): " main_port
[[ -z "$main_port" ]] && main_port="4488"

read -p "请输入密码 (默认 123b8bd2-cec7-4c7a-1234-350a56d1fa8b, 直接回车使用默认值): " password
[[ -z "$password" ]] && password="123b8bd2-cec7-4c7a-1234-350a56d1fa8b"

read -p "请输入跳跃端口范围 (默认 40000-62000, 直接回车使用默认值): " port_range
[[ -z "$port_range" ]] && port_range="40000-62000"

# 解析端口范围
if [[ "$port_range" =~ ^([0-9]+)[-:,]([0-9]+)$ ]]; then
  port_start="${BASH_REMATCH[1]}"
  port_end="${BASH_REMATCH[2]}"
else
  echo -e "${RED}错误：端口范围格式无效，请确保格式为 '起始端口-终止端口'（例如 40000-62000）。${NC}"
  exit 1
fi

# 确保端口范围有效
if [[ "$port_start" -ge "$port_end" || "$port_start" -lt 1 || "$port_end" -gt 65535 ]]; then
  echo -e "${RED}错误：端口范围无效，请确保起始端口小于终止端口，且在 1-65535 范围内。${NC}"
  exit 1
fi

# 将端口范围转换为防火墙支持的格式
formatted_port_range="${port_start}:${port_end}"

read -p "请输入绑定域名: " domain
[[ -z "$domain" ]] && { echo -e "${RED}错误：域名不能为空！${NC}"; exit 1; }

# 判断是否为根域名
is_root_domain=$(echo "$domain" | grep -E '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
is_subdomain=$(echo "$domain" | grep -E '^([a-zA-Z0-9-]+\.)+([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')

read -p "请输入用于申请证书的邮箱 (默认随机生成): " email
if [[ -z "$email" ]]; then
  email_user=$(openssl rand -hex 8)
  email="${email_user}@poijsdfwe.com"
  echo -e "${BLUE}随机生成的邮箱地址: ${YELLOW}${email}${NC}"
fi

# 检查域名解析是否正确
server_ip=$(dig +short "$domain" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | tail -n 1)
local_ip=$(curl -s http://api4.ipify.org/)
if [[ "$server_ip" != "$local_ip" ]]; then
  echo -e "${RED}错误：域名解析 IP ($server_ip) 与本机公网 IP ($local_ip) 不匹配！${NC}"
  exit 1
fi
echo -e "${GREEN}域名解析成功，开始安装 Hysteria2...${NC}"

# 设置防火墙规则
if ! sudo iptables -C INPUT -p udp --dport "$main_port" -j ACCEPT 2>/dev/null; then
  sudo iptables -A INPUT -p udp --dport "$main_port" -j ACCEPT
fi

if ! sudo iptables -C INPUT -p udp -m multiport --dports "$formatted_port_range" -j ACCEPT 2>/dev/null; then
  sudo iptables -A INPUT -p udp -m multiport --dports "$formatted_port_range" -j ACCEPT
fi

sudo iptables -t nat -A PREROUTING -p udp -m multiport --dports "$formatted_port_range" -j DNAT --to-destination :"$main_port"
sudo iptables-save > /etc/iptables/rules.v4
sudo netfilter-persistent save

# 检查防火墙规则是否生效
echo -e "${BLUE}正在检查防火墙规则是否生效...${NC}"
if sudo iptables -L -n -v | grep -q "$main_port" && sudo iptables -L -n -v | grep -q "$formatted_port_range"; then
  echo -e "${GREEN}防火墙规则已正确配置！${NC}"
else
  echo -e "${RED}错误：防火墙规则未正确配置，请检查！${NC}"
  exit 1
fi

# 强制刷新并重新申请证书
cert_dir="/etc/ssl/certs/$domain"
if [[ -d "$cert_dir" ]]; then
  echo -e "${YELLOW}检测到已有证书，正在删除旧证书以强制刷新...${NC}"
  sudo rm -rf "$cert_dir"
fi

mkdir -p "$cert_dir"

# 申请证书
echo -e "${BLUE}请选择证书申请方式:${NC}"
echo "1) Standalone 模式（无 Web 服务器运行，自动监听 80 端口）"
echo "2) 使用 Cloudflare API 申请证书（推荐）"
echo "3) 使用 Aliyun API 申请证书"
read -p "请输入选项 (1/2/3): " cert_option

case $cert_option in
  1)
    # 检查 80 端口是否被占用
    if sudo lsof -i :80 >/dev/null 2>&1; then
      echo -e "${YELLOW}警告：80 端口已被占用，尝试停止相关服务...${NC}"
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
    max_retries=5
    retry_interval=60
    retry_count=0

    while [[ $retry_count -lt $max_retries ]]; do
      echo -e "${BLUE}正在尝试通过 Standalone 模式申请证书，第 $((retry_count + 1)) 次尝试...${NC}"
      
      if "$ACME_SH" --issue -d "$domain" --standalone -m "$email" --force --debug; then
        echo -e "${GREEN}域名验证成功！${NC}"
        break
      else
        retry_count=$((retry_count + 1))
        sleep $retry_interval
      fi
    done

    if [[ $retry_count -eq $max_retries ]]; then
      echo -e "${RED}错误：域名验证失败，请检查日志！${NC}"
      exit 1
    fi

    # 恢复 80 端口服务（如果之前停止了）
    if systemctl list-units --type=service | grep -q nginx; then
      sudo systemctl start nginx || true
    fi
    if systemctl list-units --type=service | grep -q apache2; then
      sudo systemctl start apache2 || true
    fi
    ;;
  2)
    read -p "请输入 Cloudflare API Key: " cloudflare_api_key
    read -p "请输入 Cloudflare Email: " cloudflare_email
    export CF_Key="$cloudflare_api_key"
    export CF_Email="$cloudflare_email"
    
    if [[ -n "$is_root_domain" ]]; then
      # 根域名申请泛用证书
      if ! "$ACME_SH" --issue --dns dns_cf -d "$domain" -d "*.$domain" -m "$email" --force --debug; then
        echo -e "${RED}错误：Cloudflare API 密钥无效或域名配置错误，请检查！${NC}"
        unset CF_Key
        unset CF_Email
        exit 1
      fi
    else
      # 二级域名只申请单域名证书
      if ! "$ACME_SH" --issue --dns dns_cf -d "$domain" -m "$email" --force --debug; then
        echo -e "${RED}错误：Cloudflare API 密钥无效或域名配置错误，请检查！${NC}"
        unset CF_Key
        unset CF_Email
        exit 1
      fi
    fi
    
    unset CF_Key
    unset CF_Email
    ;;
  3)
    read -p "请输入阿里云 AccessKey ID: " aliyun_access_key_id
    read -p "请输入阿里云 AccessKey Secret: " aliyun_access_key_secret
    export Ali_Key="$aliyun_access_key_id"
    export Ali_Secret="$aliyun_access_key_secret"
    
    if [[ -n "$is_root_domain" ]]; then
      # 根域名申请泛用证书
      if ! "$ACME_SH" --issue --dns dns_ali -d "$domain" -d "*.$domain" -m "$email" --force --debug; then
        echo -e "${RED}错误：Aliyun API 密钥无效或域名配置错误，请检查！${NC}"
        unset Ali_Key
        unset Ali_Secret
        exit 1
      fi
        else
      # 二级域名只申请单域名证书
      if ! "$ACME_SH" --issue --dns dns_ali -d "$domain" -m "$email" --force --debug; then
        echo -e "${RED}错误：Aliyun API 密钥无效或域名配置错误，请检查！${NC}"
        unset Ali_Key
        unset Ali_Secret
        exit 1
      fi
    fi
    
    unset Ali_Key
    unset Ali_Secret
    ;;
  *)
    echo -e "${RED}无效选项，退出安装${NC}"
    exit 1
    ;;
esac

# 安装证书
"$ACME_SH" --installcert -d "$domain" \
  --cert-file "$cert_dir/fullchain.pem" \
  --key-file "$cert_dir/privkey.pem" \
  --force

# 验证证书文件是否存在
if [[ ! -f "$cert_dir/fullchain.pem" || ! -f "$cert_dir/privkey.pem" ]]; then
  echo -e "${RED}错误：证书安装失败，请检查 acme.sh 的配置！${NC}"
  exit 1
fi

# 删除旧版本的 Hysteria2 文件（如果存在）
if [[ -f /usr/local/bin/hysteria ]]; then
  sudo rm -f /usr/local/bin/hysteria
fi

# 下载并安装 Hysteria2
latest_version=$(curl -sL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')
if [[ -z "$latest_version" ]]; then
  echo -e "${RED}错误：无法获取 Hysteria2 最新版本，安装中止。${NC}"
  exit 1
fi

wget "https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-amd64" -O /usr/local/bin/hysteria
chmod +x /usr/local/bin/hysteria

# 检查文件是否成功安装
if [[ ! -f /usr/local/bin/hysteria ]]; then
  echo -e "${RED}错误：Hysteria2 安装失败，请检查网络连接或权限！${NC}"
  exit 1
fi

# 创建 Hysteria2 配置文件
mkdir -p /etc/hysteria
read -p "请输入伪装目标 URL (默认 https://wx.qq.com, 直接回车使用默认值): " masquerade_url
[[ -z "$masquerade_url" ]] && masquerade_url="https://wx.qq.com"
echo -e "${BLUE}使用伪装目标 URL: ${YELLOW}${masquerade_url}${NC}"

cat <<EOF > /etc/hysteria/config.yaml
listen: :$main_port
tls:
  cert: "$cert_dir/fullchain.pem"
  key: "$cert_dir/privkey.pem"
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
cat <<EOF | sudo tee /etc/systemd/system/hysteria.service
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# 启动 Hysteria2 服务
sudo systemctl daemon-reload
sudo systemctl enable hysteria
sudo systemctl restart hysteria

# 检查服务状态
if ! systemctl is-active --quiet hysteria; then
  echo -e "${RED}错误：Hysteria2 启动失败，请检查日志！${NC}"
  journalctl -u hysteria --no-pager --lines=50
  exit 1
fi

echo -e "${GREEN}Hysteria2 安装成功！${NC}"

# 获取服务器名称
read -p "请输入服务器名称 (用于订阅链接结尾，默认 Hysteria2): " server_name
[[ -z "$server_name" ]] && server_name="Hysteria2"

# 生成 Hysteria2 客户端配置链接
hysteria_link="hysteria2://${password}@${domain}:${main_port}?&alpn=h3&insecure=0&mport=${main_port},${port_range}&sni=${domain}#${server_name}"

# 输出 Hysteria2 配置链接
echo -e "${BLUE}Hysteria2 客户端配置链接：${NC}"
echo -e "${YELLOW}${hysteria_link}${NC}"

# 生成 Clash 节点配置信息
clash_config=$(cat <<EOF
- name: "${server_name}"
  password: ${password}
  ports: ${port_range}
  server: ${domain}
  skip-cert-verify: false
  sni: ${domain}
  transport:
    type: udp
    udp:
      hopInterval: 30s
  type: hysteria2
EOF
)

# 输出 Clash 节点配置信息
echo -e "${BLUE}Clash 节点配置信息：${NC}"
echo -e "${YELLOW}${clash_config}${NC}"
