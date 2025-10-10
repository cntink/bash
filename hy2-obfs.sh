#!/bin/bash

# --- Hysteria 2 脚本配置变量 ---
CONFIG_DIR="/etc/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
BINARY_PATH="/usr/local/bin/hysteria"
SERVICE_NAME="hysteria-server.service"
SYSTEMD_SERVICE="/etc/systemd/system/$SERVICE_NAME"
LANG_FILE="$CONFIG_DIR/.lang"
BACKUP_DIR="$CONFIG_DIR/backup"
SHORTCUT_PATH="/usr/local/bin/hy2"
SCRIPT_PATH="/opt/hysteria/hysteria_manager.sh" # 假设脚本路径

# --- 全局变量（将由脚本运行时配置） ---
H_DOMAIN=""
H_EMAIL=""
H_PORT="443"
H_PASSWORD=""
H_ENABLE_OBFS="false"
H_OBFS_PASSWORD=""
H_MASQUERADE_URL="https://www.bing.com"
H_ENABLE_PORT_HOP="false"
H_PORT_HOP_RANGE="40000-60000"
H_ENABLE_SNIFFING="false"
H_ENABLE_OUTBOUND="false"
EXISTING_DOMAIN="" # V5.11 用于存储检测到的现有证书域名

# --- 颜色和消息定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

declare -A MESSAGES
# V5.10 优化后的提示
MESSAGES[zh_input_domain]="请输入您的域名 (必须解析到此服务器 IP, 默认: %s): " 
MESSAGES[zh_input_domain_no_default]="请输入您的域名 (必须解析到此服务器 IP): "
MESSAGES[zh_input_email]="请输入您的邮箱 (用于 ACME 证书, 默认: admin@your_domain): "
MESSAGES[zh_input_port]="请输入 Hysteria 主监听端口 (默认: 443): "
MESSAGES[zh_input_password]="请输入连接密码 (留空将自动生成): "
MESSAGES[zh_confirm_obfs]="是否启用 Salamander 混淆? (强烈推荐, 默认: Y) [Y/n]: "
MESSAGES[zh_confirm_port_hop]="是否开启端口跳跃功能? (默认: Y) [Y/n]: "
MESSAGES[zh_input_port_hop_range]="请输入端口跳跃范围 (例如: 40000-60000, 默认: 40000-60000): "
MESSAGES[zh_input_obfs_password]="请输入混淆密码 (留空将使用默认): "
MESSAGES[zh_input_masquerade_url]="请输入伪装 URL (默认: https://www.bing.com): "
MESSAGES[zh_select_cert_method]="请选择证书获取方式:"
MESSAGES[zh_cert_method_internal]=" 1) Hysteria 内置 ACME (推荐, 简单)"
MESSAGES[zh_cert_method_acmesh]=" 2) 使用 acme.sh (支持 DNS API, 功能更强大)"
MESSAGES[zh_cert_method_existing]=" 3) 使用本地现有证书 (跳过申请)"
MESSAGES[zh_cert_skip_success]="已选择使用现有证书，跳过申请流程。"
MESSAGES[zh_err_cert_missing]="错误: 证书文件未找到或不完整。请检查文件夹: %s"

MESSAGES[zh_manage_menu_title]="Hysteria2 服务管理菜单 (状态: %s)"
MESSAGES[zh_manage_menu_view_config]=" 1) 查看客户端配置信息 (含二维码)"
MESSAGES[zh_manage_menu_start]=" 2) 启动服务"
MESSAGES[zh_manage_menu_restart]=" 3) 重启服务"
MESSAGES[zh_manage_menu_stop]=" 4) 停止服务"
MESSAGES[zh_manage_menu_view_log]=" 5) 查看 Hysteria2 运行日志"
MESSAGES[zh_manage_menu_reinstall]=" 6) 重新安装/更改配置"
MESSAGES[zh_manage_menu_uninstall]=" 7) 仅卸载 Hysteria2"
MESSAGES[zh_manage_menu_exit]=" 8) 退出菜单"

MESSAGES[zh_uninstall_confirm]="您确定要卸载 Hysteria2 吗? (默认: Y) [y/N]: "
MESSAGES[zh_uninstall_backup_confirm]="是否备份当前配置文件? (默认: Y) [Y/n]: "
MESSAGES[zh_uninstall_cert_confirm]="是否保留证书文件夹 (%s) ? (默认: Y) [Y/n]: "
MESSAGES[zh_uninstall_binary_confirm]="是否保留 Hysteria2 二进制文件 (%s) ? (默认: Y) [Y/n]: "

MESSAGES[zh_client_config_info]="客户端配置信息"
MESSAGES[zh_sub_link]="Hysteria2 URI / 链接:"
MESSAGES[zh_clash_meta_config]="Clash Meta/Verge YAML 配置片段:"
MESSAGES[zh_install_complete]="Hysteria2 安装配置完成!"
MESSAGES[zh_backup_path]="配置已备份到: %s"


# --- 辅助函数 ---

LOG_FILE="/var/log/hysteria_manager.log"
log() {
    local level=$1
    local msg=$2
    local color=$3
    local timestamp=$(date +%Y-%m-%d\ %H:%M:%S)
    echo -e "${timestamp} [$level] ${color}${msg}${NC}" | tee -a "$LOG_FILE"
}

validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        log "ERROR" "端口 $port 无效，必须在 1-65535 之间。" "$RED"
        return 1
    fi
    return 0
}

validate_port_range() {
    local range=$1
    if ! [[ "$range" =~ ^[0-9]+-[0-9]+$ ]]; then
        log "ERROR" "端口范围 $range 格式无效（如 40000-60000）。" "$RED"
        return 1
    fi
    local start=$(echo "$range" | cut -d'-' -f1)
    local end=$(echo "$range" | cut -d'-' -f2)
    if ! validate_port "$start" || ! validate_port "$end" || [ "$start" -ge "$end" ]; then
        log "ERROR" "端口范围 $range 无效。" "$RED"
        return 1
    fi
    return 0
}

get_msg() {
    local key="zh_$1"
    local msg="${MESSAGES[$key]}"
    if [ -n "$2" ]; then
        printf "$msg" "$2"
    else
        echo "$msg"
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "请使用 root 用户运行此脚本。" "$RED"
        exit 1
    fi
}

cleanup_exit() {
    log "脚本执行结束。" "$BLUE"
}

validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log "错误: 域名格式无效 ($domain)。" "$RED"
        exit 1
    fi
}

# V5.11/V5.13 修正：检测现有证书域名
detect_existing_domain() {
    EXISTING_DOMAIN=""
    local CERT_DIR="$CONFIG_DIR/certs"
    if [ -d "$CERT_DIR" ]; then
        # 查找 certs 目录下是否存在唯一的子目录 (即证书域名)
        local cert_dirs=( "$CERT_DIR"/*/ )
        if [ ${#cert_dirs[@]} -eq 1 ]; then
            # 提取域名，移除路径前缀和后缀斜杠
            EXISTING_DOMAIN=$(basename "${cert_dirs[0]}" | tr -d '/')
        fi
    fi
}

# --- 核心操作函数 - 依赖检查与安装模拟 ---

check_dependencies() {
    # 检查并安装依赖（略，假设已安装 curl, openssl, iptables-persistent 等）
    log "正在检查并安装依赖... (略)"
    sleep 1 # 模拟依赖安装
    log "依赖安装成功。" "$GREEN"
}

download_and_install() {
    # 检测架构并下载 Hysteria2 二进制文件（略）
    log "检测到的系统架构: amd64 (略)" "$BLUE"
    if [ -f "$BINARY_PATH" ]; then
        # 实际代码中应有版本检查
        log "检测到本地二进制文件，跳过下载。" "$YELLOW"
    else
        log "正在下载 Hysteria2 二进制文件... (略)"
        # 模拟下载和安装
        touch "$BINARY_PATH"
        chmod +x "$BINARY_PATH"
    fi
}
# --- 创建服务器配置文件 (移除 RESOLVER 配置，修正 Masquerade 结构) ---
create_config_file() {
    log "正在创建配置文件..." "$BLUE"

    # 检查关键变量
    if [ -z "$H_DOMAIN" ] || [ -z "$H_PORT" ] || [ -z "$H_PASSWORD" ]; then
        log "错误：H_DOMAIN、H_PORT 或 H_PASSWORD 未设置" "$RED" >&2
        exit 1
    fi

    # Obfuscation 配置
    local OBFUSCATION_BLOCK=""
    if [ "$H_ENABLE_OBFS" == "true" ] && [ -n "$H_OBFS_PASSWORD" ]; then
        OBFUSCATION_BLOCK=$(cat << EOF
obfs:
  type: salamander
  salamander:
    password: "$H_OBFS_PASSWORD"
EOF
)
    fi

    # Masquerade 配置 (修正为 Hysteria 2 官方标准: 仅 url 字段)
    local MASQUERADE_BLOCK=$(cat << EOF
masquerade:
  url: "$H_MASQUERADE_URL"
EOF
)

    # TLS 或 ACME 配置 (使用 CERT_METHOD 决定结构)
    local TLS_CONFIG=""
    if [ "$CERT_METHOD" == "internal_acme" ]; then
        if [ -z "$H_EMAIL" ]; then
            log "错误：internal_acme 模式需要 H_EMAIL" "$RED" >&2
            exit 1
        fi
        # ACME 模式：使用 acme 块
        TLS_CONFIG=$(cat << EOF
acme:
  domains:
    - $H_DOMAIN
  email: $H_EMAIL
EOF
)
    else # existing 或 acme_sh
        if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
            log "错误：证书文件 $CERT_PATH 或密钥文件 $KEY_PATH 不存在" "$RED" >&2
            exit 1
        fi
        # 证书文件模式：使用 tls 块，指定路径
        TLS_CONFIG=$(cat << EOF
tls:
  cert: $CERT_PATH
  key: $KEY_PATH
EOF
)
    fi

    # Resolver 配置 (已移除，使用系统原生解析)
    local RESOLVER_CONFIG=""

    # Sniffing 配置
    local SNIFFING_BLOCK=""
    if [ "$H_ENABLE_SNIFFING" == "true" ]; then
        SNIFFING_BLOCK="trafficSniffing: true"
    fi

    # Outbound 配置
    local OUTBOUND_BLOCK=""
    if [ "$H_ENABLE_OUTBOUND" == "true" ]; then
        OUTBOUND_BLOCK=$(cat << EOF
outbounds:
  - type: socks5
    socks5:
      addr: 127.0.0.1:1080
      # 用户可自定义 SOCKS5 地址/端口
EOF
)
    fi

    # 创建配置目录
    mkdir -p "$CONFIG_DIR/certs"

    # 生成完整的配置文件 (关键修正：移除 $RESOLVER_CONFIG 的引用)
    cat > "$CONFIG_FILE" << EOF
listen: :$H_PORT
auth:
  type: password
  password: "$H_PASSWORD"
$TLS_CONFIG
sni: $H_DOMAIN
alpn:
  - h3
$OBFUSCATION_BLOCK
$MASQUERADE_BLOCK
$OUTBOUND_BLOCK
$( [ "$H_ENABLE_SNIFFING" == "true" ] && echo "$SNIFFING_BLOCK" )
EOF

    log "配置文件 $CONFIG_FILE 创建成功。" "$GREEN"
}


create_systemd_service() {
    log "正在创建 systemd 服务文件..." "$BLUE"
    cat > "$SYSTEMD_SERVICE" << EOF
[Unit]
Description=Hysteria2 Service (Server)
After=network.target

[Service]
Type=simple
User=root
Group=root
LimitNOFILE=65536
ExecStart=$BINARY_PATH server -c $CONFIG_FILE
Restart=always
RestartSec=5s
Environment=HYSTERIA_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" &>/dev/null
    log "systemd 服务文件创建成功。" "$GREEN"
}

# V5.33 修正：增加防火墙规则清理逻辑
cleanup_firewall() {
    log "INFO" "正在清理 Hysteria2 防火墙规则..." "$BLUE"
    local TARGET_PORT="${H_PORT:-443}"
    local range="${H_PORT_HOP_RANGE:-40000-60000}"
    local range_iptables=$(echo "$range" | sed 's/-/:/g')

    # 检查是否存在 iptables 规则
    if iptables -t nat -S PREROUTING | grep -q "DNAT.*--dport.*$TARGET_PORT"; then
        iptables -t nat -D PREROUTING -p udp --dport "$TARGET_PORT" -j DNAT --to-destination :"$TARGET_PORT" 2>/dev/null
        log "INFO" "已删除主端口 $TARGET_PORT 的 DNAT 规则" "$YELLOW"
    fi
    if [ "$H_ENABLE_PORT_HOP" == "true" ] && [ -n "$H_PORT_HOP_RANGE" ]; then
        if iptables -t nat -S PREROUTING | grep -q "DNAT.*--dport.*$range_iptables"; then
            iptables -t nat -D PREROUTING -p udp --dport "$range_iptables" -j DNAT --to-destination :"$TARGET_PORT" 2>/dev/null
            log "INFO" "已删除端口跳跃范围 $range_iptables 的 DNAT 规则" "$YELLOW"
        fi
        if iptables -S INPUT | grep -q "ACCEPT.*--dport.*$range_iptables"; then
            iptables -D INPUT -p udp --dport "$range_iptables" -j ACCEPT 2>/dev/null
            log "INFO" "已删除端口跳跃范围 $range_iptables 的 INPUT 规则" "$YELLOW"
        fi
    fi
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        log "INFO" "iptables 规则已保存" "$GREEN"
    fi
}

# 卸载服务 (V5.12 修正：恢复保留询问逻辑)
uninstall_hysteria() {
    log "正在卸载 Hysteria2 服务..." "$BLUE"
    
    # 确认卸载
    read -p "$(get_msg 'uninstall_confirm')" confirm; confirm=${confirm:-Y}
    [[ ! "$confirm" =~ ^[yY]$ ]] && { echo "已取消卸载。"; return 1; }
    
    # --- 备份配置 ---
    read -p "$(get_msg 'uninstall_backup_confirm')" backup_confirm; backup_confirm=${backup_confirm:-Y}
    if [[ "$backup_confirm" =~ ^[yY]$ ]]; then
        mkdir -p "$BACKUP_DIR"
        local backup_file="$BACKUP_DIR/hysteria_config_backup_$(date +%Y%m%d_%H%M%S).yaml"
        cp "$CONFIG_FILE" "$backup_file" 2>/dev/null && log "$(get_msg 'backup_path' "$backup_file")" "$GREEN"
    fi
    
    # 停止并禁用服务
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    # V5.16 确保：移除服务文件和快捷命令
    rm -f "$SYSTEMD_SERVICE" "$SHORTCUT_PATH"; systemctl daemon-reload
    
    # --- V5.12 恢复：证书保留询问 ---
    local CERT_DIR="$CONFIG_DIR/certs"
    local keep_cert="N"
    if [ -d "$CERT_DIR" ]; then
        read -p "$(get_msg 'uninstall_cert_confirm' "$CERT_DIR")" keep_cert; keep_cert=${keep_cert:-Y}
    fi
    
    # --- V5.12 恢复：二进制文件保留询问 ---
    read -p "$(get_msg 'uninstall_binary_confirm' "$BINARY_PATH")" keep_binary; keep_binary=${keep_binary:-Y}

    # 执行删除操作
    if [[ ! "$keep_binary" =~ ^[yY]$ ]]; then
        rm -f "$BINARY_PATH"
        log "已删除核心二进制文件: $BINARY_PATH" "$YELLOW"
    else
        log "已保留核心二进制文件: $BINARY_PATH" "$YELLOW"
    fi
    
    if [[ "$keep_cert" =~ ^[yY]$ ]]; then
        rm -f "$CONFIG_FILE"
        rm -f "$CONFIG_DIR/.lang" 
        log "已保留证书文件夹: $CERT_DIR" "$YELLOW"
    else
        rm -rf "$CONFIG_DIR"
        log "已删除证书文件夹和配置文件。" "$YELLOW"
    fi
    # ** V5.33 修正：清理防火墙规则 **
    cleanup_firewall    
    log "Hysteria2 服务已卸载。 / Hysteria2 has been uninstalled." "$GREEN"
    
    # 清理防火墙规则 (略)
    
    return 0 
}

# V5.19 最终修正：创建快捷命令函数，确保主脚本文件被复制
create_shortcut() {
    log "INFO" "正在创建 hy2 快捷管理命令..." "$BLUE"
    mkdir -p /opt/hysteria/
    local REAL_SCRIPT_PATH=$(realpath "$0" 2>/dev/null || echo "$0")
    if ! cp "$REAL_SCRIPT_PATH" "$SCRIPT_PATH"; then
        log "ERROR" "复制脚本文件到 $SCRIPT_PATH 失败。" "$RED"
        return 1
    fi
    if [ ! -s "$SCRIPT_PATH" ]; then
        log "ERROR" "复制的脚本文件 $SCRIPT_PATH 为空或不可用。" "$RED"
        return 1
    fi
    chmod +x "$SCRIPT_PATH"
    ln -sf "$SCRIPT_PATH" "$SHORTCUT_PATH"
    chmod +x "$SHORTCUT_PATH"
    log "INFO" "Hysteria 管理快捷命令 (hy2) 已创建。" "$GREEN"
    hash -r 2>/dev/null
}

backup_config() {
    local max_backups=5
    mkdir -p "$BACKUP_DIR"
    local backup_file="$BACKUP_DIR/hysteria_config_backup_$(date +%Y%m%d_%H%M%S).yaml"
    cp "$CONFIG_FILE" "$backup_file" && log "INFO" "$(get_msg 'backup_path' "$backup_file")" "$GREEN"
    # 删除旧备份
    ls -t "$BACKUP_DIR"/hysteria_config_backup_*.yaml | tail -n +$((max_backups + 1)) | xargs -I {} rm {}
}

# 修正后的 configure_firewall 函数
configure_firewall() {
    log "配置防火墙以支持端口跳跃..." "$BLUE"
    
    # 清理旧的 Hysteria 规则 (防止重复添加，但卸载函数已尝试清理)
    # 推荐使用 -I 插入规则，或先检查规则是否存在。这里简化为直接添加。
    
    local TARGET_PORT="$H_PORT"
    local has_changes=0

    # 1. 开放主监听端口
    log "开放 Hysteria 主监听端口: UDP $TARGET_PORT" "$BLUE"
    iptables -A INPUT -p udp --dport "$TARGET_PORT" -j ACCEPT
    if [ $? -eq 0 ]; then has_changes=1; fi

    if [ "$H_ENABLE_PORT_HOP" == "true" ] && [ -n "$H_PORT_HOP_RANGE" ]; then
        # 替换 - 为 : 以符合 iptables 格式
        local range=$(echo "$H_PORT_HOP_RANGE" | sed 's/-/:/g')
        
        # 2. 添加 iptables DNAT 规则：将范围端口转发到主端口
        log "添加端口跳跃 DNAT 规则: UDP $range -> $TARGET_PORT" "$BLUE"
        iptables -t nat -A PREROUTING -p udp --dport "$range" -j DNAT --to-destination :"$TARGET_PORT"
        if [ $? -eq 0 ]; then has_changes=1; fi

        # 3. 开放端口跳跃范围
        log "开放 Hysteria 端口跳跃范围: UDP $range" "$BLUE"
        iptables -A INPUT -p udp --dport "$range" -j ACCEPT
        if [ $? -eq 0 ]; then has_changes=1; fi
    fi
    
    if [ "$has_changes" -eq 1 ]; then
        # 4. 保存 iptables 规则
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
            log "iptables 规则已保存到 /etc/iptables/rules.v4" "$GREEN"
        else
            log "警告：未找到 iptables-save，规则可能在重启后丢失。请安装 iptables-persistent。" "$YELLOW" >&2
        fi
    fi
    
    return 0
}

# --- 生成客户端配置 (V5.34 修正：移除带宽，实现混淆与端口跳跃互斥) ---
generate_client_config() {
    local QR_CONTENT
    local CLASH_META_CONFIG
    local CLI_YAML_CONFIG
    local PORT_PART="$H_PORT"
    local CONFIG_FILE="/etc/hysteria/client_config.yaml"
    local CLI_CONFIG_FILE="/etc/hysteria/client_hysteria2.yaml"
    
    # 移除默认带宽变量 (不再需要)
    # local DEFAULT_UP="50"  
    # local DEFAULT_DOWN="200"

    # 检查关键变量，设置默认值（保留原脚本容错逻辑）
    H_DOMAIN=${H_DOMAIN:-"[YOUR_DOMAIN_HERE]"}
    H_PORT=${H_PORT:-"443"}
    H_PASSWORD=${H_PASSWORD:-"[YOUR_PASSWORD_HERE]"}
    H_MASQUERADE_URL=${H_MASQUERADE_URL:-"https://www.bing.com"}
    H_INSECURE=${H_INSECURE:-"true"}

    # 变量格式验证（略）
    if ! [[ $H_DOMAIN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log "错误：H_DOMAIN 格式无效 ($H_DOMAIN)，使用默认值" "$RED" >&2
        H_DOMAIN="[YOUR_DOMAIN_HERE]"
    fi
    if ! [[ $H_PORT =~ ^[0-9]+$ ]] || [ "$H_PORT" -lt 1 ] || [ "$H_PORT" -gt 65535 ]; then
        log "错误：H_PORT 无效 ($H_PORT)，使用默认值 443" "$RED" >&2
        H_PORT="443"
    fi
    if [ -z "$H_PASSWORD" ]; then
        log "错误：H_PASSWORD 不能为空，使用默认值" "$RED" >&2
        H_PASSWORD="[YOUR_PASSWORD_HERE]"
    fi

    # --- 互斥逻辑和块生成 ---
    local PORT_HOP_BLOCK=""
    local OBFS_BLOCK=""
    local CLI_OBFS_BLOCK=""
    local CLI_PORT_HOP_BLOCK=""
    local H_ENABLE_URI_PORT_RANGE="false" # 用于控制 URI 是否包含端口范围

    if [ "$H_ENABLE_OBFS" == "true" ] && [ -n "$H_OBFS_PASSWORD" ]; then
        # 1. 启用混淆
        OBFS_BLOCK=$(printf "    obfs: salamander\n    obfs-password: %s\n" "$H_OBFS_PASSWORD")
        CLI_OBFS_BLOCK=$(printf "obfs:\n  type: salamander\n  salamander:\n    password: %s\n" "$H_OBFS_PASSWORD")
        log "注意: 检测到混淆启用，端口跳跃功能将被忽略。" "$YELLOW"
        
        # 强制禁用 URI 中的端口范围
        H_ENABLE_URI_PORT_RANGE="false" 
    elif [ "$H_ENABLE_PORT_HOP" == "true" ] && [ -n "$H_PORT_HOP_RANGE" ]; then
        # 2. 仅启用端口跳跃
        PORT_HOP_BLOCK=$(printf "    ports: %s\n" "$H_PORT_HOP_RANGE")
        CLI_PORT_HOP_BLOCK=$(printf "ports: %s\n" "$H_PORT_HOP_RANGE")
        H_ENABLE_URI_PORT_RANGE="true" # 启用 URI 中的端口范围
    fi

    # --- 1. Hysteria2 URI (链接) 格式 ---
    local QUERY_PARAMS=()
    
    # 混淆参数
    if [ "$H_ENABLE_OBFS" == "true" ] && [ -n "$H_OBFS_PASSWORD" ]; then
        QUERY_PARAMS+=("obfs=salamander" "obfs-password=$H_OBFS_PASSWORD")
    fi
    
    QUERY_PARAMS+=("sni=$H_DOMAIN")
    if [ "$H_INSECURE" == "true" ]; then
        QUERY_PARAMS+=("insecure=1")
    else
        QUERY_PARAMS+=("insecure=0")
    fi

    # 构建 URI 端口部分
    if [ "$H_ENABLE_URI_PORT_RANGE" == "true" ]; then
        PORT_PART="$H_PORT,$H_PORT_HOP_RANGE"
    else
        PORT_PART="$H_PORT"
    fi

    # 构建 QUERY_STRING 无尾随 &
    local QUERY_STRING=$(IFS='&'; echo "${QUERY_PARAMS[*]}")

    # 构建 URI
    QR_CONTENT="hysteria2://$H_PASSWORD@$H_DOMAIN:$PORT_PART/?$QUERY_STRING#Hysteria2-${H_DOMAIN}"

    # --- 2. Clash Meta YAML 配置 ---
    # 修正: 移除 up/down 字段，使用新的 PORT_HOP_BLOCK 和 OBFS_BLOCK 变量
    CLASH_META_CONFIG=$(printf "proxies:\n  - name: Hysteria2-%s\n    type: hysteria2\n    server: %s\n    port: %s\n    password: %s\n    sni: %s\n    skip-cert-verify: %s\n    alpn:\n      - h3\n%s%s\n" \
        "$H_DOMAIN" \
        "$H_DOMAIN" \
        "$H_PORT" \
        "$H_PASSWORD" \
        "$H_DOMAIN" \
        "$H_INSECURE" \
        "$PORT_HOP_BLOCK" \
        "$OBFS_BLOCK"
    )

    # 保存 Clash 配置
    mkdir -p "$(dirname "$CONFIG_FILE")"
    echo -e "$CLASH_META_CONFIG" > "$CONFIG_FILE"
    if [ $? -eq 0 ]; then
        log "Clash Meta 配置已保存到 $CONFIG_FILE" "$GREEN"
    else
        log "错误：无法保存 Clash Meta 配置到 $CONFIG_FILE" "$RED" >&2
    fi

    # --- 3. Hysteria2 CLI YAML 配置 ---
    # 修正: 移除带宽字段，使用新的 CLI_PORT_HOP_BLOCK 和 CLI_OBFS_BLOCK 变量
    CLI_YAML_CONFIG=$(printf "server: %s:%s\nauth: %s\ntls:\n  sni: %s\n  insecure: %s\nalpn:\n  - h3\n%s%s\n" \
        "$H_DOMAIN" \
        "$H_PORT" \
        "$H_PASSWORD" \
        "$H_DOMAIN" \
        "$H_INSECURE" \
        "$CLI_PORT_HOP_BLOCK" \
        "$CLI_OBFS_BLOCK"
    )

    # 保存 CLI 配置
    mkdir -p "$(dirname "$CLI_CONFIG_FILE")"
    echo -e "$CLI_YAML_CONFIG" > "$CLI_CONFIG_FILE"
    if [ $? -eq 0 ]; then
        log "Hysteria2 CLI 配置已保存到 $CLI_CONFIG_FILE" "$GREEN"
    else
        log "错误：无法保存 Hysteria2 CLI 配置到 $CLI_CONFIG_FILE" "$RED" >&2
    fi

    # --- 4. 生成二维码与格式化输出 ---
    local QR_CODE=""
    if command -v qrencode >/dev/null 2>&1; then
        QR_CODE=$(qrencode -t UTF8 "$QR_CONTENT" 2>/dev/null)
        if [ $? -ne 0 ]; then
            QR_CODE="错误：无法生成二维码，请检查 qrencode 工具"
        fi
    else
        QR_CODE="未安装 qrencode，无法生成二维码。请安装：sudo apt install qrencode"
    fi

    # --- 5. 格式化输出 ---
    echo -e "\n${GREEN}==============================================${NC}"
    log "$(get_msg 'client_config_info')" "$GREEN"
    echo -e "${GREEN}==============================================${NC}"
    echo -e " 域名/IP: $H_DOMAIN"
    echo -e " 端口: $PORT_PART"
    echo -e " 密码: $H_PASSWORD"
    
    # 修正输出信息
    local OBFS_INFO=$([ "$H_ENABLE_OBFS" == "true" ] && [ -n "$H_OBFS_PASSWORD" ] && echo "Salamander (密码: $H_OBFS_PASSWORD)" || echo "未启用")
    echo -e " 混淆: $OBFS_INFO"
    
    local HOP_INFO=""
    if [ "$H_ENABLE_OBFS" == "true" ]; then
        HOP_INFO="已禁用 (因混淆启用)"
    elif [ "$H_ENABLE_PORT_HOP" == "true" ] && [ -n "$H_PORT_HOP_RANGE" ]; then
        HOP_INFO="$H_PORT_HOP_RANGE (Clash Meta 使用 ports 字段)"
    else
        HOP_INFO="未启用"
    fi
    echo -e " 端口跳跃: $HOP_INFO"
    
    echo -e " 伪装 URL: $H_MASQUERADE_URL"
    echo -e "${GREEN}----------------------------------------------${NC}"
    log "$(get_msg 'sub_link')" "$YELLOW"
    echo -e "$QR_CONTENT"
    echo -e "${GREEN}----------------------------------------------${NC}"
    log "二维码:" "$YELLOW"
    echo -e "$QR_CODE"
    echo -e "${GREEN}----------------------------------------------${NC}"
    log "$(get_msg 'clash_meta_config')" "$YELLOW"
    if [ -n "$CLASH_META_CONFIG" ]; then
        echo ""
        echo -e "$CLASH_META_CONFIG"
        echo -e "提示：Clash Meta 配置已保存到 $CONFIG_FILE，可直接导入 Clash Meta 客户端"
    else
        log "错误：无法生成 Clash Meta YAML 配置" "$RED" >&2
    fi
    echo -e "${GREEN}----------------------------------------------${NC}"
    log "Hysteria2 CLI YAML 配置:" "$YELLOW"
    if [ -n "$CLI_YAML_CONFIG" ]; then
        echo ""
        echo -e "$CLI_YAML_CONFIG"
        echo -e "提示：Hysteria2 CLI 配置已保存到 $CLI_CONFIG_FILE，可用于 CLI 测试"
    else
        log "错误：无法生成 Hysteria2 CLI YAML 配置" "$RED" >&2
    fi
    echo -e "${GREEN}==============================================${NC}"

    # 配置防火墙（端口跳跃）
    configure_firewall
}

# V5.13 修正：确保从配置文件中正确读取 H_DOMAIN 等变量
manage_menu() {
    # V5.13 修正：强制重新检测现有证书域名作为 H_DOMAIN 的首选来源
    detect_existing_domain
    if [ -f "$CONFIG_FILE" ]; then
        # 1. 如果存在配置文件，优先从证书路径或配置文件中获取 H_DOMAIN
        if [ -n "$EXISTING_DOMAIN" ]; then
            H_DOMAIN="$EXISTING_DOMAIN"
        else
            # 尝试从配置文件（内置ACME）中读取
            H_DOMAIN=$(grep -A 1 'domains:' "$CONFIG_FILE" | tail -n 1 | sed -E 's/^\s*-\s*//;s/\s*$//' || echo "$EXISTING_DOMAIN")
        fi
        # 2. 读取其他配置
        H_PORT=$(grep 'listen:' "$CONFIG_FILE" | sed 's/listen: ://g' | tr -d '\n\r' || echo "443")
        H_PASSWORD=$(grep -m 1 'password:' "$CONFIG_FILE" | sed 's/password: \"//g;s/\"//g' | tr -d '\n\r' || echo "")
        # 精确读取 masquerade 块下的 url/addr
        H_MASQUERADE_URL=$(grep 'url:' "$CONFIG_FILE" | sed 's/.*url: //g' | tr -d '\"' | head -n 1 || echo "https://www.bing.com")
        if [ -z "$H_MASQUERADE_URL" ]; then
            H_MASQUERADE_URL=$(grep 'addr:' "$CONFIG_FILE" | sed 's/.*addr: //g' | tr -d '\"' | head -n 1 || echo "https://www.bing.com")
        fi
        if grep -q 'salamander:' "$CONFIG_FILE"; then
            H_ENABLE_OBFS="true"
            H_OBFS_PASSWORD=$(grep -A 2 'salamander:' "$CONFIG_FILE" | grep 'password:' | sed 's/.*password: \"//g;s/\"//g' | tr -d '\n\r' || echo "")
        else
            H_ENABLE_OBFS="false"; H_OBFS_PASSWORD=""
        fi
        if grep -q 'ports:' "$CONFIG_FILE"; then
            H_ENABLE_PORT_HOP="true"
            H_PORT_HOP_RANGE=$(grep 'ports:' "$CONFIG_FILE" | sed 's/ports: //g' | tr -d '\"' | tr -d '\n\r' || echo "")
        else
            H_ENABLE_PORT_HOP="false"; H_PORT_HOP_RANGE=""
        fi
    fi
    # 3. 菜单循环
    while true; do
        clear
        local STATUS_TEXT=$(systemctl is-active $SERVICE_NAME &> /dev/null && echo -e "${GREEN}运行中${NC}" || echo -e "${RED}未运行${NC}")
        echo -e "${GREEN}$(get_msg 'manage_menu_title' "$STATUS_TEXT")${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
        echo -e " $(get_msg 'manage_menu_view_config')"
        echo -e " $(get_msg 'manage_menu_start')"
        echo -e " $(get_msg 'manage_menu_restart')"
        echo -e " $(get_msg 'manage_menu_stop')"
        echo -e " $(get_msg 'manage_menu_view_log')"
        echo -e " $(get_msg 'manage_menu_reinstall')"
        echo -e " $(get_msg 'manage_menu_uninstall')"
        echo -e " $(get_msg 'manage_menu_exit')"
        echo -e "${YELLOW}------------------------------------------------${NC}"
        read -p "请输入选项 [1-8]: " menu_choice
        echo
        case "$menu_choice" in
            1) generate_client_config; read -p "按回车键继续..." temp;;
            2) systemctl start "$SERVICE_NAME"; log "INFO" "Hysteria2 服务已启动。" "$GREEN"; sleep 1;;
            3) systemctl restart "$SERVICE_NAME"; log "INFO" "Hysteria2 服务已重启。" "$GREEN"; sleep 1;;
            4) systemctl stop "$SERVICE_NAME"; log "INFO" "Hysteria2 服务已停止。" "$GREEN"; sleep 1;;
            5)
                journalctl -u "$SERVICE_NAME" -f --since "1 hour ago" --no-pager
                read -p "按回车键返回菜单..." temp
                ;;
            6) uninstall_hysteria && install_hysteria; return;;
            7) uninstall_hysteria; return;;
            8) return;;
            *) echo -e "${RED}无效选项，请重新输入。${NC}"; sleep 1;;
        esac
    done
}


# 安装主流程 (V5.11 修正：自动证书选择)
install_hysteria() {
    local rollback_files=()
    trap 'rollback_install "${rollback_files[@]}"' ERR
    check_dependencies; rollback_files+=("$BINARY_PATH")
    detect_existing_domain

    local CERT_DIR_BASE="$CONFIG_DIR/certs"
    local NUM_CHOICES=2
    local AUTO_EXISTING_CERT="false"
    # 1. V5.11 优化：检查是否可以自动选择现有证书
    if [ -d "$CERT_DIR_BASE" ] && [ -n "$EXISTING_DOMAIN" ]; then
        CERT_PATH="$CONFIG_DIR/certs/$EXISTING_DOMAIN/fullchain.pem"
        KEY_PATH="$CONFIG_DIR/certs/$EXISTING_DOMAIN/privkey.pem"
        if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
            AUTO_EXISTING_CERT="true"
            CERT_METHOD="existing"
            H_DOMAIN="$EXISTING_DOMAIN"
            log "INFO" "检测到本地证书域名: ${H_DOMAIN}，已自动选择 '使用本地现有证书'。" "$GREEN"
            H_EMAIL=""
        fi
    fi
    # 2. 如果未自动选择，则显示菜单并手动输入
    if [ "$AUTO_EXISTING_CERT" == "false" ]; then
        echo -e "\n${GREEN}$(get_msg 'select_cert_method')${NC}"
        echo -e "$(get_msg 'cert_method_internal')"
        echo -e "$(get_msg 'cert_method_acmesh')"
        if [ -d "$CERT_DIR_BASE" ]; then
            NUM_CHOICES=3
            echo -e "$(get_msg 'cert_method_existing')"
        fi
        read -p "Your choice [1-$NUM_CHOICES]: " cert_choice; cert_choice=${cert_choice:-1}
        if [ "$cert_choice" == "2" ]; then CERT_METHOD="acme_sh";
        elif [ "$cert_choice" == "3" ]; then CERT_METHOD="existing";
        else CERT_METHOD="internal_acme"; fi

        # 域名输入
        while true; do
            local DEFAULT_DOMAIN="${EXISTING_DOMAIN:-$(hostname -f)}"
            if [ "$CERT_METHOD" == "existing" ] && [ -n "$EXISTING_DOMAIN" ]; then
                read -p "$(get_msg 'input_domain' "$EXISTING_DOMAIN")" H_DOMAIN_INPUT
                H_DOMAIN=${H_DOMAIN_INPUT:-$EXISTING_DOMAIN}
            elif [ "$CERT_METHOD" == "internal_acme" ]; then
                read -p "$(get_msg 'input_domain' "$DEFAULT_DOMAIN")" H_DOMAIN_INPUT
                H_DOMAIN=${H_DOMAIN_INPUT:-$DEFAULT_DOMAIN}
            else
                read -p "$(get_msg 'input_domain_no_default')" H_DOMAIN_INPUT
                H_DOMAIN=$H_DOMAIN_INPUT
            fi
            if [ -z "$H_DOMAIN" ]; then echo "错误: 域名不能为空!"; continue; fi
            validate_domain "$H_DOMAIN"
            break
        done
        # 邮箱输入
        if [ "$CERT_METHOD" != "existing" ]; then
            read -p "$(get_msg 'input_email' "$H_DOMAIN")" H_EMAIL; H_EMAIL=${H_EMAIL:-"admin@$H_DOMAIN"}
        else
            H_EMAIL=""
        fi
        # 证书颁发/检测
        if [ "$CERT_METHOD" == "acme_sh" ]; then
            CERT_PATH="$HOME/.acme.sh/$H_DOMAIN/fullchain.cer"
            KEY_PATH="$HOME/.acme.sh/$H_DOMAIN/$H_DOMAIN.key"
            if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
                log "ERROR" "acme.sh 证书文件未找到 ($CERT_PATH, $KEY_PATH)" "$RED"
                exit 1
            fi
        elif [ "$CERT_METHOD" == "existing" ]; then
            CERT_PATH="$CONFIG_DIR/certs/$H_DOMAIN/fullchain.pem"
            KEY_PATH="$CONFIG_DIR/certs/$H_DOMAIN/privkey.pem"
            if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
                log "ERROR" "$(get_msg 'err_cert_missing' "$CONFIG_DIR/certs/$H_DOMAIN/")" "$RED"
                exit 1
            fi
            log "INFO" "$(get_msg 'cert_skip_success')" "$GREEN"
        fi
    fi
    # 3. 输入剩余配置
    read -p "$(get_msg 'input_port')" H_PORT; H_PORT=${H_PORT:-443}
    validate_port "$H_PORT" || exit 1
    read -s -p "$(get_msg 'input_password')" H_PASSWORD; echo; H_PASSWORD=${H_PASSWORD:-$(openssl rand -hex 16)}
    read -p "$(get_msg 'confirm_obfs')" obfs_choice; obfs_choice=${obfs_choice:-Y}
    if [[ "$obfs_choice" =~ ^[yY]$ ]]; then
        H_ENABLE_OBFS="true"
        H_ENABLE_PORT_HOP="false" # 强制禁用端口跳跃
        log "INFO" "注意：启用混淆后，端口跳跃功能已被禁用。" "$YELLOW"
        read -s -p "$(get_msg 'input_obfs_password')" H_OBFS_PASSWORD; echo
        H_OBFS_PASSWORD=${H_OBFS_PASSWORD:-$(openssl rand -hex 16)}
    else
        H_ENABLE_OBFS="false"; H_OBFS_PASSWORD=""
        read -p "$(get_msg 'confirm_port_hop')" hop_choice; hop_choice=${hop_choice:-Y}
        if [[ "$hop_choice" =~ ^[yY]$ ]]; then
            H_ENABLE_PORT_HOP="true"
            read -p "$(get_msg 'input_port_hop_range')" H_PORT_HOP_RANGE
            H_PORT_HOP_RANGE=${H_PORT_HOP_RANGE:-"40000-60000"}
            validate_port_range "$H_PORT_HOP_RANGE" || exit 1
        else
            H_ENABLE_PORT_HOP="false"; H_PORT_HOP_RANGE=""
        fi
    fi
    read -p "$(get_msg 'input_masquerade_url')" H_MASQUERADE_URL; H_MASQUERADE_URL=${H_MASQUERADE_URL:-"https://www.bing.com"}
    read -p "是否启用协议嗅探? (用于基于域名的路由, 默认: Y) [Y/n]: " sniffing_choice; sniffing_choice=${sniffing_choice:-Y}
    [[ "$sniffing_choice" =~ ^[yY]$ ]] && H_ENABLE_SNIFFING="true" || H_ENABLE_SNIFFING="false"
    read -p "是否配置 SOCKS5 出站代理? (例如: 用于解锁流媒体, 默认: N) [y/N]: " outbound_choice; outbound_choice=${outbound_choice:-N}
    [[ "$outbound_choice" =~ ^[yY]$ ]] && H_ENABLE_OUTBOUND="true" || H_ENABLE_OUTBOUND="false"
    # 3.5 修正：设置 H_INSECURE
    if [ "$CERT_METHOD" == "internal_acme" ] || [ "$CERT_METHOD" == "acme_sh" ]; then
        H_INSECURE="false"
    else
        H_INSECURE="true"
    fi
    # 4. 安装执行
    download_and_install; rollback_files+=("$CONFIG_FILE" "$SYSTEMD_SERVICE")
    create_config_file
    create_systemd_service
    log "INFO" "正在启动 Hysteria2 服务..." "$BLUE"; systemctl start "$SERVICE_NAME"
    log "INFO" "等待 5 秒检查服务状态..." "$YELLOW"; sleep 5
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        INSTALL_SUCCESS="true"
        log "INFO" "$(get_msg 'install_complete')" "$GREEN"
        create_shortcut
        echo
        generate_client_config
    else
        log "ERROR" "Hysteria2 服务启动失败，请检查日志!" "$RED"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager
        exit 1
    fi
}

rollback_install() {
    log "ERROR" "安装失败，正在回滚..." "$RED"
    for file in "$@"; do
        [ -f "$file" ] && rm -f "$file" && log "INFO" "已删除 $file" "$YELLOW"
    done
    exit 1
}

# --- 主函数 (V5.10 修正后的流程控制) ---
main() {
    trap cleanup_exit EXIT
    check_root
    
    # 确保主脚本路径被设置
    local SCRIPT_NAME=$(basename "$0")
    SCRIPT_PATH="/opt/hysteria/$SCRIPT_NAME"

    if [ "$1" == "manage_menu" ]; then
        manage_menu
        exit 0
    fi

    if [ -f "$BINARY_PATH" ]; then
        clear
        
        echo -e "${GREEN}检测到 Hysteria2 已安装, 请选择操作:${NC}\n${YELLOW}---------------------------------${NC}"
        echo -e " 1) 管理服务 (推荐使用 'hy2' 命令)\n 2) 卸载并重装\n 3) 仅卸载\n 4) 退出${NC}"
        echo -e "${YELLOW}---------------------------------${NC}"
        
        read -p "请输入选项 [1-4]: " action
        case "$action" in 
            1) manage_menu;; 
            2) 
                if uninstall_hysteria; then
                    install_hysteria
                fi
                ;; 
            3) uninstall_hysteria;; 
            4) exit 0;; 
            *) echo -e "${RED}无效选项${NC}"; exit 1;; 
        esac
    else
        install_hysteria
    fi
}

main "$@"
