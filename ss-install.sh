#!/usr/bin/env bash
#
# 一键安装 Shadowsocks-Libev（彻底修复，订阅链接 100% 正确）
#

# 检测是否 root
if [[ $EUID -ne 0 ]]; then
  echo "本脚本需要以 root 身份执行，请切换到 root 用户或在命令前加 sudo."
  exit 1
fi

# 确保所有依赖已安装
echo "🔹 安装必要依赖..."
apt update -y
apt install -y ufw iptables shadowsocks-libev rng-tools jq curl wget openssl net-tools


# 卸载旧版本 Shadowsocks
if dpkg -l | grep -q shadowsocks-libev; then
  echo "🔸 检测到 Shadowsocks-Libev 已安装。"
  read -p "是否卸载原版本？(y/n, 默认: y): " REMOVE_SS
  REMOVE_SS=${REMOVE_SS:-y}
  if [[ "$REMOVE_SS" == "y" ]]; then
    echo "🛑 正在卸载 Shadowsocks-Libev..."
    systemctl stop shadowsocks-libev
    apt remove --purge -y shadowsocks-libev simple-obfs
    rm -rf /etc/shadowsocks-libev
    echo "✅ Shadowsocks 已卸载。"
  fi
fi

# 安装 Shadowsocks 及依赖
echo "🔹 安装 Shadowsocks 及依赖..."
apt install -y shadowsocks-libev rng-tools jq curl wget openssl

# 用户输入端口
read -p "请输入 Shadowsocks 端口（默认: 44333）: " SHADOWSOCKS_PORT
SHADOWSOCKS_PORT=${SHADOWSOCKS_PORT:-44333}

# 用户输入密码
read -p "请输入 Shadowsocks 密码（默认: 随机生成）: " SHADOWSOCKS_PASSWORD
SHADOWSOCKS_PASSWORD=${SHADOWSOCKS_PASSWORD:-$(openssl rand -base64 16)}

# 选择加密方式
echo "🔹 请选择 Shadowsocks 加密方式："
ENCRYPTION_OPTIONS=("aes-256-gcm" "aes-192-gcm" "aes-128-gcm" "chacha20-ietf-poly1305" "xchacha20-ietf-poly1305" "aes-256-cfb" "aes-192-cfb" "aes-128-cfb" "aes-256-ctr" "aes-192-ctr" "aes-128-ctr" "rc4-md5")
for i in "${!ENCRYPTION_OPTIONS[@]}"; do
  echo "$(($i+1))) ${ENCRYPTION_OPTIONS[$i]}"
done
read -p "输入加密方式序号（默认: xchacha20-ietf-poly1305）: " ENC_INDEX
if [[ "$ENC_INDEX" =~ ^[0-9]+$ ]] && (( ENC_INDEX >= 1 && ENC_INDEX <= ${#ENCRYPTION_OPTIONS[@]} )); then
  SHADOWSOCKS_ENCRYPTION="${ENCRYPTION_OPTIONS[$((ENC_INDEX-1))]}"
else
  SHADOWSOCKS_ENCRYPTION="xchacha20-ietf-poly1305"
fi

# 获取服务器公网 IP
SERVER_IP=$(curl -s https://api.ipify.org)

# 配置文件路径
SS_CONFIG_PATH="/etc/shadowsocks-libev/config.json"

# 生成 Shadowsocks 配置文件
cat > "${SS_CONFIG_PATH}" <<-EOF
{
    "server": "0.0.0.0",
    "server_port": ${SHADOWSOCKS_PORT},
    "password": "${SHADOWSOCKS_PASSWORD}",
    "method": "${SHADOWSOCKS_ENCRYPTION}",
    "timeout": 300,
    "fast_open": false,
    "reuse_port": true,
    "no_delay": true,
    "mode": "tcp_and_udp",
    "udp": true
}
EOF

# **确保 config.json 权限正确**
chmod 644 "${SS_CONFIG_PATH}"
chown root:root "${SS_CONFIG_PATH}"

# 确保 Shadowsocks 以 root 运行，防止 "Permission denied"
sed -i 's/User=nobody/User=root/' /lib/systemd/system/shadowsocks-libev.service
sed -i 's/Group=nobody/Group=root/' /lib/systemd/system/shadowsocks-libev.service

# 重新加载 systemd 配置
systemctl daemon-reload

# 启用并启动 Shadowsocks-Libev 服务
systemctl enable shadowsocks-libev
systemctl restart shadowsocks-libev

# 确保 Shadowsocks 正常运行
if ! systemctl is-active --quiet shadowsocks-libev; then
  echo "❌ Shadowsocks 启动失败，请检查日志：journalctl -xe -u shadowsocks-libev"
  exit 1
fi

# **✅ 生成 Shadowsocks 订阅链接（修正为官方标准格式）**
ENCODED_METHOD_PASSWORD=$(echo -n "${SHADOWSOCKS_ENCRYPTION}:${SHADOWSOCKS_PASSWORD}" | base64 -w 0 | tr -d '=' | tr '/+' '_-')
SS_LINK="ss://${ENCODED_METHOD_PASSWORD}@${SERVER_IP}:${SHADOWSOCKS_PORT}#Shadowsocks"
SS_SUBSCRIPTION=$(echo -n "${SS_LINK}" | base64 -w 0)

# **📌 显示配置信息**
echo "------------------------------------------------"
echo "✅ Shadowsocks 已安装并启动，默认配置如下："
echo "  地址(IPv4)：${SERVER_IP}"
echo "  端口：     ${SHADOWSOCKS_PORT}"
echo "  密码：     ${SHADOWSOCKS_PASSWORD}"
echo "  加密：     ${SHADOWSOCKS_ENCRYPTION}"
echo
echo "🔗 Shadowsocks 订阅链接（官方标准格式）"
echo "  SS 链接： ${SS_LINK}"
echo "  Base64 订阅链接（适用于订阅）:"
echo "  ${SS_SUBSCRIPTION}"
echo "------------------------------------------------"
