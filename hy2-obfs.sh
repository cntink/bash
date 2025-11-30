#!/bin/bash

# ==============================================================================
# Hysteria 2 服务端安装与管理脚本 (最终修正版)
# 修复: 配置文件YAML结构、ACME DNS API 交互逻辑、socat依赖、完整性保留
# ==============================================================================

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
H_MASQUERADE_URL="https://www.tencent.com"
H_ENABLE_PORT_HOP="false"
H_PORT_HOP_RANGE="40000-60000"
H_ENABLE_SNIFFING="false"
H_ENABLE_OUTBOUND="false"
H_INSECURE="false" # V5.35: 添加并初始化 H_INSECURE
EXISTING_DOMAIN="" # V5.11 用于存储检测到的现有证书域名
# 初始化原脚本可能漏掉初始化的变量，防止 set -u 报错
H_ENABLE_QUIC_OPT="false"
H_ENABLE_SPEED_TEST="false"
H_OUTBOUND_ADDR=""
H_OUTBOUND_USER=""
H_OUTBOUND_PASS=""

# --- 颜色和消息定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

declare -A MESSAGES
# V5.10 优化后的提示
MESSAGES[input_domain]="请输入您的域名 (必须解析到此服务器 IP, 默认: %s): "
MESSAGES[input_domain_no_default]="请输入您的域名 (必须解析到此服务器 IP): "
MESSAGES[input_email]="请输入您的邮箱 (用于 ACME 证书, 默认: admin@your_domain): "
MESSAGES[input_port]="请输入 Hysteria 主监听端口 (默认: 443): "
MESSAGES[input_password]="请输入连接密码 (留空将自动生成): "
MESSAGES[confirm_obfs]="是否启用 Salamander 混淆? (强烈推荐, 默认: Y) [Y/n]: "
MESSAGES[confirm_port_hop]="是否开启端口跳跃功能? (默认: Y) [Y/n]: "
MESSAGES[input_port_hop_range]="请输入端口跳跃范围 (例如: 40000-60000, 默认: 40000-60000): "
MESSAGES[input_obfs_password]="请输入混淆密码 (留空将使用默认): "
MESSAGES[input_masquerade_url]="请输入伪装 URL (默认: https://www.tencent.com): "
MESSAGES[select_cert_method]="请选择证书获取方式:"
MESSAGES[cert_method_internal]=" 1) Hysteria 内置 ACME (推荐, 简单)"
MESSAGES[cert_method_acmesh]=" 2) 使用 acme.sh (支持 DNS API, 功能更强大)"
MESSAGES[cert_method_existing]=" 3) 使用本地现有证书 (跳过申请)"
MESSAGES[cert_skip_success]="已选择使用现有证书，跳过申请流程。"
MESSAGES[err_cert_missing]="错误: 证书文件未找到或不完整。请检查文件夹: %s"

MESSAGES[manage_menu_title]="Hysteria2 服务管理菜单 (状态: %s)"
MESSAGES[manage_menu_view_config]=" 1) 查看客户端配置信息 (含二维码)"
MESSAGES[manage_menu_start]=" 2) 启动服务"
MESSAGES[manage_menu_restart]=" 3) 重启服务"
MESSAGES[manage_menu_stop]=" 4) 停止服务"
MESSAGES[manage_menu_view_log]=" 5) 查看 Hysteria2 运行日志"
MESSAGES[manage_menu_reinstall]=" 6) 重新安装/更改配置"
MESSAGES[manage_menu_uninstall]=" 7) 仅卸载 Hysteria2"
MESSAGES[manage_menu_exit]=" 8) 退出菜单"

MESSAGES[uninstall_confirm]="您确定要卸载 Hysteria2 吗? (默认: Y) [y/N]: "
MESSAGES[uninstall_backup_confirm]="是否备份当前配置文件? (默认: Y) [Y/n]: "
MESSAGES[uninstall_cert_confirm]="是否保留证书文件夹 (%s) ? (默认: Y) [Y/n]: "
MESSAGES[uninstall_binary_confirm]="是否保留 Hysteria2 二进制文件 (%s) ? (默认: Y) [Y/n]: "

MESSAGES[client_config_info]="客户端配置信息"
MESSAGES[sub_link]="Hysteria2 URI / 链接:"
MESSAGES[clash_meta_config]="Clash Meta/Verge YAML 配置片段:"
MESSAGES[install_complete]="Hysteria2 安装配置完成!"
MESSAGES[backup_path]="配置已备份到: %s"


# --- 辅助函数 ---

LOG_FILE="/var/log/hysteria_manager.log"
log() {
    local level=$1
    local msg=$2
    local color=$3
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [$level] ${color}${msg}${NC}" | tee -a "$LOG_FILE"
}

validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
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
    local key="$1"
    local msg="${MESSAGES[$key]}"
    if [ -n "$2" ]; then
        printf "$msg" "$2"
    else
        echo "$msg"
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "ERROR" "请使用 root 用户运行此脚本。" "$RED"
        exit 1
    fi
}

cleanup_exit() {
    log "INFO" "脚本执行结束。" "$BLUE"
}

validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log "ERROR" "域名格式无效 ($domain)。" "$RED"
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

# --- 核心操作函数 - 依赖检查与安装 ---
# V5.47: 完善 check_dependencies 函数，实现自动安装缺失依赖
check_dependencies() {
    log "INFO" "正在检查并安装依赖..." "$BLUE"

    local deps_missing=0
    local deps_to_install=()

    # 检查基础工具 (curl, wget, openssl, qrencode)
    if ! command -v curl >/dev/null 2>&1; then
        deps_missing=1
        deps_to_install+=("curl")
    else
        log "INFO" "找到 curl。" "$GREEN"
    fi

    if ! command -v wget >/dev/null 2>&1; then
        deps_missing=1
        deps_to_install+=("wget")
    else
        log "INFO" "找到 wget。" "$GREEN"
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        deps_missing=1
        deps_to_install+=("openssl")
    else
        log "INFO" "找到 openssl。" "$GREEN"
    fi

    if ! command -v qrencode >/dev/null 2>&1; then
        deps_missing=1
        deps_to_install+=("qrencode")
    else
        log "INFO" "找到 qrencode。" "$GREEN"
    fi

    if ! command -v iptables >/dev/null 2>&1; then
        deps_missing=1
        deps_to_install+=("iptables")
    else
        log "INFO" "找到 iptables。" "$GREEN"
    fi

    # [新增] 检查 socat (acme.sh Standalone 模式必需)
    if ! command -v socat >/dev/null 2>&1; then
        deps_missing=1
        deps_to_install+=("socat")
    else
        log "INFO" "找到 socat。" "$GREEN"
    fi

    # 检查包管理器并安装缺失的依赖
    if [ $deps_missing -eq 1 ]; then
        log "INFO" "检测到以下依赖项缺失: ${deps_to_install[*]}" "$YELLOW"

        if command -v apt >/dev/null 2>&1; then
            # Debian/Ubuntu
            log "INFO" "检测到 apt 包管理器，正在更新软件包列表并安装缺失的依赖项..." "$BLUE"
            if ! apt update; then
                log "ERROR" "apt update 失败，无法安装依赖项。" "$RED"
                exit 1
            fi
            if ! apt install -y "${deps_to_install[@]}"; then
                log "ERROR" "安装依赖项失败。" "$RED"
                exit 1
            fi
            log "INFO" "apt 依赖项安装完成。" "$GREEN"
        elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
            # RHEL/CentOS/Fedora
            local pkg_manager=""
            if command -v dnf >/dev/null 2>&1; then
                pkg_manager="dnf"
            elif command -v yum >/dev/null 2>&1; then
                pkg_manager="yum"
            fi
            log "INFO" "检测到 $pkg_manager 包管理器，正在安装缺失的依赖项..." "$BLUE"
            if ! $pkg_manager install -y "${deps_to_install[@]}"; then
                log "ERROR" "安装依赖项失败。" "$RED"
                exit 1
            fi
            log "INFO" "$pkg_manager 依赖项安装完成。" "$GREEN"
        else
            log "ERROR" "未找到支持的包管理器 (apt, yum, dnf)，无法自动安装缺失的依赖项: ${deps_to_install[*]}" "$RED"
            log "INFO" "请手动安装这些依赖项后重试。" "$BLUE"
            exit 1
        fi
    else
        log "INFO" "所有核心依赖项均已存在。" "$GREEN"
    fi

    # 检查防火墙规则持久化工具
    if ! command -v iptables-persistent >/dev/null 2>&1 && ! (command -v iptables-save >/dev/null 2>&1 && command -v iptables-restore >/dev/null 2>&1); then
        log "WARN" "未找到 iptables-persistent 或 iptables-save/iptables-restore。防火墙规则可能在重启后丢失。" "$YELLOW"
        log "INFO" "尝试安装防火墙持久化工具..." "$BLUE"

        local persist_pkg=""
        if command -v apt >/dev/null 2>&1; then
            persist_pkg="iptables-persistent"
        elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
            persist_pkg="iptables-services"
        else
            log "INFO" "无法自动安装防火墙持久化工具，请手动安装相关软件包。" "$BLUE"
            persist_pkg="" # 标记为不安装
        fi

        if [ -n "$persist_pkg" ]; then
            log "INFO" "尝试安装 $persist_pkg..." "$BLUE"
            if command -v apt >/dev/null 2>&1; then
                if apt install -y "$persist_pkg"; then
                    log "INFO" "$persist_pkg 安装成功。" "$GREEN"
                else
                    log "WARN" "$persist_pkg 安装失败，防火墙规则重启后可能丢失。" "$YELLOW"
                fi
            elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
                if $pkg_manager install -y "$persist_pkg"; then
                    log "INFO" "$persist_pkg 安装成功，防火墙规则将被持久化。" "$GREEN"
                    # 启用服务 (适用于 iptables-services)
                    systemctl enable iptables --now 2>/dev/null || true
                else
                    log "WARN" "$persist_pkg 安装失败，防火墙规则重启后可能丢失。" "$YELLOW"
                fi
            fi
        fi
    else
        if command -v iptables-persistent >/dev/null 2>&1; then
            log "INFO" "找到 iptables-persistent，防火墙规则将被持久化。" "$GREEN"
        elif command -v iptables-save >/dev/null 2>&1 && command -v iptables-restore >/dev/null 2>&1; then
            log "INFO" "找到 iptables-save/iptables-restore，防火墙规则将被持久化。" "$GREEN"
        fi
    fi

    log "INFO" "依赖检查与安装完成。" "$GREEN"
}

# V5.45: 修正 download_and_install 函数以正确下载二进制文件
# V5.49: 改进二进制文件验证逻辑
download_and_install() {
    log "INFO" "检测系统架构并下载 Hysteria2 二进制文件..." "$BLUE"

    # 1. 检测操作系统和架构
    local OS_NAME
    local ARCH_NAME
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH_NAME=$(uname -m)

    # 2. 映射架构名称到 Hysteria 发布版的命名
    case $ARCH_NAME in
        x86_64|amd64) ARCH_NAME="amd64" ;;
        aarch64|arm64) ARCH_NAME="arm64" ;;
        armv7l) ARCH_NAME="arm" ;;
        i386|i686) ARCH_NAME="386" ;;
        *) log "ERROR" "不支持的系统架构: $ARCH_NAME" "$RED"; exit 1 ;;
    esac

    # 3. 构建下载 URL
    local DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/latest/download/hysteria-${OS_NAME}-${ARCH_NAME}"

    # 4. 检查本地二进制文件
    if [ -f "$BINARY_PATH" ]; then
        log "INFO" "检测到本地二进制文件: $BINARY_PATH" "$YELLOW"
        # V5.45: 检查文件是否可执行且非空
        if [ -x "$BINARY_PATH" ] && [ -s "$BINARY_PATH" ]; then
            log "INFO" "本地二进制文件存在、非空且可执行，跳过下载。" "$GREEN"
            # V5.49: 在跳过下载时也进行基本验证
            if timeout 5s "$BINARY_PATH" --version >/dev/null 2>&1; then
                log "INFO" "本地二进制文件验证通过 (--version)。" "$GREEN"
                return 0
            else
                log "WARN" "本地二进制文件 $BINARY_PATH 存在但 --version 验证失败，可能已损坏或不兼容，将重新下载。" "$YELLOW"
                rm -f "$BINARY_PATH" # 删除无效文件
            fi
        else
            log "WARN" "本地二进制文件 $BINARY_PATH 存在但不可执行或为空，将重新下载。" "$YELLOW"
            rm -f "$BINARY_PATH" # 删除无效文件
        fi
    fi

    # 5. 下载二进制文件
    log "INFO" "正在下载 Hysteria2 二进制文件 ($DOWNLOAD_URL) 到 $BINARY_PATH..." "$BLUE"
    if command -v curl >/dev/null 2>&1; then
        if ! curl -L "$DOWNLOAD_URL" -o "$BINARY_PATH"; then
            log "ERROR" "使用 curl 下载失败！" "$RED"
            exit 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget "$DOWNLOAD_URL" -O "$BINARY_PATH"; then
            log "ERROR" "使用 wget 下载失败！" "$RED"
            exit 1
        fi
    else
        log "ERROR" "系统中没有找到 curl 或 wget，无法下载 Hysteria2。" "$RED"
        exit 1
    fi

    # 6. 设置执行权限
    chmod +x "$BINARY_PATH"

    # 7. 验证下载的文件
    if [ ! -f "$BINARY_PATH" ] || [ ! -x "$BINARY_PATH" ] || [ ! -s "$BINARY_PATH" ]; then
        log "ERROR" "下载的二进制文件 $BINARY_PATH 不存在、不可执行或为空！" "$RED"
        exit 1
    fi

    # 8. V5.49: 改进验证逻辑
    # 首先检查文件类型 (可选，提供更多信息)
    if command -v file >/dev/null 2>&1; then
        local file_type
        file_type=$(file -b "$BINARY_PATH" 2>/dev/null)
        log "INFO" "下载的二进制文件类型: $file_type" "$BLUE"
    fi

    # 尝试运行 --help 作为更简单的验证，它通常不涉及网络或复杂初始化
    if timeout 5s "$BINARY_PATH" --help >/dev/null 2>&1; then
        log "INFO" "Hysteria2 二进制文件下载并基本验证成功 (--help)。" "$GREEN"
    else
        # --help 失败，再尝试 --version
        if timeout 5s "$BINARY_PATH" --version >/dev/null 2>&1; then
            log "INFO" "Hysteria2 二进制文件下载并验证成功 (--version)。" "$GREEN"
        else
            # 两个命令都失败，检查文件是否为ELF格式 (Linux可执行文件)
            if command -v file >/dev/null 2>&1 && file "$BINARY_PATH" 2>/dev/null | grep -q "ELF"; then
                log "WARN" "下载的二进制文件是ELF格式，但 --help 和 --version 均失败。可能存在兼容性问题。" "$YELLOW"
                # 可以选择在此处退出，或者尝试启动服务（让服务启动失败来最终确认）
                # 这里我们选择记录警告并继续，因为 --help/--version 失败不一定代表服务无法启动
                # exit 1 # Uncomment this line if you want to be strict
            else
                log "ERROR" "下载的二进制文件 $BINARY_PATH 不是有效的ELF可执行文件或验证失败。" "$RED"
            fi
            rm -f "$BINARY_PATH" # 删除无效文件
            exit 1
        fi
    fi

    log "INFO" "Hysteria2 二进制文件下载并验证成功: $BINARY_PATH" "$GREEN"
}
# --- 创建服务器配置文件 (移除 RESOLVER 配置，修正 Masquerade 结构) ---
# V5.51: 修正 Outbound 配置，确保 name 字段存在
# V5.52: 增加 QUIC 优化、SpeedTest、Sniff 详细配置、Outbound 认证
# V5.53: 修正变量赋值以去除首尾空格，修正 masquerade 配置格式
# V5.54: 增加 masquerade 额外设置 (listenHTTP, listenHTTPS, forceHTTPS)，修正 internal_acme 格式
# V5.55: 移除 alpn 块，修正 password 引号问题，确保 outbounds 认证信息被使用
create_config_file() {
    log "INFO" "正在创建配置文件..." "$BLUE"

    # 检查关键变量
    if [ -z "$H_DOMAIN" ] || [ -z "$H_PORT" ] || [ -z "$H_PASSWORD" ]; then
        log "ERROR" "错误：H_DOMAIN、H_PORT 或 H_PASSWORD 未设置" "$RED"
        exit 1
    fi

    # --- V5.52: 添加 QUIC 优化块 ---
    local QUIC_BLOCK=""
    if [ "$H_ENABLE_QUIC_OPT" = "true" ]; then
        QUIC_BLOCK=$(cat << EOF
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 16777216
  maxConnReceiveWindow: 33554432
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false
EOF
)
    fi

    # --- V5.52: 修正 Sniff 配置块 ---
    local SNIFF_BLOCK=""
    if [ "$H_ENABLE_SNIFFING" = "true" ]; then
        SNIFF_BLOCK=$(cat << EOF
sniff:
  enable: true
  timeout: 2s
EOF
)
    else
        SNIFF_BLOCK=""
    fi

    # Obfuscation 配置
    local OBFUSCATION_BLOCK=""
    if [ "$H_ENABLE_OBFS" = "true" ] && [ -n "$H_OBFS_PASSWORD" ]; then
        OBFUSCATION_BLOCK=$(cat << EOF
obfs:
  type: salamander
  salamander:
    password: $H_OBFS_PASSWORD
EOF
)
    fi

    # Masquerade 配置 (V5.53 & V5.54: 修正格式，增加额外设置)
    # [修正]：将 listenHTTP/HTTPS 移出 masquerade 块，因为它们是顶层配置
    # 确保缩进正确 (2空格)
    local MASQUERADE_BLOCK=$(cat << EOF
masquerade:
  type: proxy
  proxy:
    url: $H_MASQUERADE_URL
    rewriteHost: true
listenHTTP: :80
listenHTTPS: :443
forceHTTPS: true
EOF
)

    # TLS 或 ACME 配置 (使用 CERT_METHOD 决定结构)
    local TLS_CONFIG=""
    if [ "$CERT_METHOD" = "internal_acme" ]; then
        if [ -z "$H_EMAIL" ]; then
            log "ERROR" "错误：internal_acme 模式需要 H_EMAIL" "$RED"
            exit 1
        fi
        # V5.54: 修正 internal_acme 格式，匹配期望配置
        TLS_CONFIG=$(cat << EOF
acme:
  domains:
    - $H_DOMAIN
  email: $H_EMAIL
  ca: letsencrypt
  dir: $CONFIG_DIR/acme
EOF
)
    else # existing 或 acme_sh
        if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
            log "ERROR" "错误：证书文件 $CERT_PATH 或密钥文件 $KEY_PATH 不存在" "$RED"
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

    # Outbound 配置
    local OUTBOUND_BLOCK=""
    if [ "$H_ENABLE_OUTBOUND" = "true" ]; then
        OUTBOUND_BLOCK=$(cat << EOF
outbounds:
  - name: socks
    type: socks5
    socks5:
      addr: $H_OUTBOUND_ADDR
      username: $H_OUTBOUND_USER
      password: $H_OUTBOUND_PASS
EOF
)
    fi

    # --- V5.52: 添加 SpeedTest 配置 ---
    local SPEED_TEST_BLOCK=""
    if [ "$H_ENABLE_SPEED_TEST" = "true" ]; then
        SPEED_TEST_BLOCK="speedTest: true"
    fi

    # 创建配置目录
    mkdir -p "$CONFIG_DIR/certs"

    # 生成完整的配置文件 (关键修正：移除 $RESOLVER_CONFIG 的引用，移除 alpn 块)
    cat > "$CONFIG_FILE" << EOF
listen: :$H_PORT
auth:
  type: password
  password: $H_PASSWORD
$TLS_CONFIG
$OBFUSCATION_BLOCK
$MASQUERADE_BLOCK
$QUIC_BLOCK
$SNIFF_BLOCK
$OUTBOUND_BLOCK
$SPEED_TEST_BLOCK
EOF

    log "INFO" "配置文件 $CONFIG_FILE 创建成功。" "$GREEN"
}


create_systemd_service() {
    log "INFO" "正在创建 systemd 服务文件..." "$BLUE"
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
    log "INFO" "systemd 服务文件创建成功。" "$GREEN"
}

# V5.33 修正：增加防火墙规则清理逻辑
cleanup_firewall() {
    log "INFO" "正在清理 Hysteria2 防火墙规则..." "$BLUE"
    local TARGET_PORT="${H_PORT:-443}"
    local range="${H_PORT_HOP_RANGE:-40000-60000}"
    local range_iptables=$(echo "$range" | sed 's/-/:/g')

    # 检查是否存在 iptables 规则
    if iptables -t nat -S PREROUTING 2>/dev/null | grep -q "DNAT.*--dport.*$TARGET_PORT"; then
        iptables -t nat -D PREROUTING -p udp --dport "$TARGET_PORT" -j DNAT --to-destination :"$TARGET_PORT" 2>/dev/null
        log "INFO" "已删除主端口 $TARGET_PORT 的 DNAT 规则" "$YELLOW"
    fi
    if [ "$H_ENABLE_PORT_HOP" = "true" ] && [ -n "$H_PORT_HOP_RANGE" ]; then
        if iptables -t nat -S PREROUTING 2>/dev/null | grep -q "DNAT.*--dport.*$range_iptables"; then
            iptables -t nat -D PREROUTING -p udp --dport "$range_iptables" -j DNAT --to-destination :"$TARGET_PORT" 2>/dev/null
            log "INFO" "已删除端口跳跃范围 $range_iptables 的 DNAT 规则" "$YELLOW"
        fi
        if iptables -S INPUT 2>/dev/null | grep -q "ACCEPT.*--dport.*$range_iptables"; then
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
    log "INFO" "正在卸载 Hysteria2 服务..." "$BLUE"

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
        log "INFO" "已删除核心二进制文件: $BINARY_PATH" "$YELLOW"
    else
        log "INFO" "已保留核心二进制文件: $BINARY_PATH" "$YELLOW"
    fi

    if [[ "$keep_cert" =~ ^[yY]$ ]]; then
        rm -f "$CONFIG_FILE"
        rm -f "$CONFIG_DIR/.lang"
        log "INFO" "已保留证书文件夹: $CERT_DIR" "$YELLOW"
    else
        rm -rf "$CONFIG_DIR"
        log "INFO" "已删除证书文件夹和配置文件。" "$YELLOW"
    fi
    # ** V5.33 修正：清理防火墙规则 **
    cleanup_firewall
    log "INFO" "Hysteria2 服务已卸载。 / Hysteria2 has been uninstalled." "$GREEN"

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
    log "INFO" "配置防火墙以支持端口跳跃..." "$BLUE"

    # 清理旧的 Hysteria 规则 (防止重复添加，但卸载函数已尝试清理)
    # 推荐使用 -I 插入规则，或先检查规则是否存在。这里简化为直接添加。

    local TARGET_PORT="$H_PORT"
    local has_changes=0

    # 1. 开放主监听端口
    log "INFO" "开放 Hysteria 主监听端口: UDP $TARGET_PORT" "$BLUE"
    iptables -A INPUT -p udp --dport "$TARGET_PORT" -j ACCEPT
    if [ $? -eq 0 ]; then has_changes=1; fi

    if [ "$H_ENABLE_PORT_HOP" = "true" ] && [ -n "$H_PORT_HOP_RANGE" ]; then
        # 替换 - 为 : 以符合 iptables 格式
        local range=$(echo "$H_PORT_HOP_RANGE" | sed 's/-/:/g')

        # 2. 添加 iptables DNAT 规则：将范围端口转发到主端口
        log "INFO" "添加端口跳跃 DNAT 规则: UDP $range -> $TARGET_PORT" "$BLUE"
        iptables -t nat -A PREROUTING -p udp --dport "$range" -j DNAT --to-destination :"$TARGET_PORT"
        if [ $? -eq 0 ]; then has_changes=1; fi

        # 3. 开放端口跳跃范围
        log "INFO" "开放 Hysteria 端口跳跃范围: UDP $range" "$BLUE"
        iptables -A INPUT -p udp --dport "$range" -j ACCEPT
        if [ $? -eq 0 ]; then has_changes=1; fi
    fi

    if [ "$has_changes" -eq 1 ]; then
        # 4. 保存 iptables 规则
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
            log "INFO" "iptables 规则已保存到 /etc/iptables/rules.v4" "$GREEN"
        else
            log "WARN" "警告：未找到 iptables-save，规则可能在重启后丢失。请安装 iptables-persistent。" "$YELLOW"
        fi
    fi

    return 0
}

# [关键修正]：补全缺失的 rollback_install 函数，防止安装失败时二次报错
rollback_install() {
    local files=("$@")
    log "WARN" "安装过程出错，正在执行回滚操作..." "$YELLOW"
    
    # 尝试停止服务
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    
    # 删除生成的文件
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
            log "INFO" "已删除回滚文件: $file" "$YELLOW"
        fi
    done
    
    # 清理防火墙
    cleanup_firewall
    log "INFO" "回滚完成。" "$BLUE"
}

# --- 生成客户端配置 (V5.34 修正：移除带宽，实现混淆与端口跳跃互斥) ---
generate_client_config() {
    local QR_CONTENT
    local CLASH_META_CONFIG
    local CLI_YAML_CONFIG
    local PORT_PART="$H_PORT"
    local CONFIG_FILE_CLIENT="/etc/hysteria/client_config.yaml"
    local CLI_CONFIG_FILE="/etc/hysteria/client_hysteria2.yaml"

    # 移除默认带宽变量 (不再需要)
    # local DEFAULT_UP="50"
    # local DEFAULT_DOWN="200"

    # 检查关键变量，设置默认值（保留原脚本容错逻辑）
    H_DOMAIN=${H_DOMAIN:-"[YOUR_DOMAIN_HERE]"}
    H_PORT=${H_PORT:-"443"}
    H_PASSWORD=${H_PASSWORD:-"[YOUR_PASSWORD_HERE]"}
    H_MASQUERADE_URL=${H_MASQUERADE_URL:-"https://www.tencent.com"}
    # H_INSECURE 在 install_hysteria 中已设置，此处无需默认值

    # 变量格式验证（略）
    if ! [[ $H_DOMAIN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log "ERROR" "错误：H_DOMAIN 格式无效 ($H_DOMAIN)，使用默认值" "$RED"
        H_DOMAIN="[YOUR_DOMAIN_HERE]"
    fi
    if ! [[ $H_PORT =~ ^[0-9]+$ ]] || [ "$H_PORT" -lt 1 ] || [ "$H_PORT" -gt 65535 ]; then
        log "ERROR" "错误：H_PORT 无效 ($H_PORT)，使用默认值 443" "$RED"
        H_PORT="443"
    fi
    if [ -z "$H_PASSWORD" ]; then
        log "ERROR" "错误：H_PASSWORD 不能为空，使用默认值" "$RED"
        H_PASSWORD="[YOUR_PASSWORD_HERE]"
    fi

    # --- 互斥逻辑和块生成 ---
    local PORT_HOP_BLOCK=""
    local OBFS_BLOCK=""
    local CLI_OBFS_BLOCK=""
    local CLI_PORT_HOP_BLOCK=""
    local H_ENABLE_URI_PORT_RANGE="false" # 用于控制 URI 是否包含端口范围

    if [ "$H_ENABLE_OBFS" = "true" ] && [ -n "$H_OBFS_PASSWORD" ]; then
        # 1. 启用混淆
        OBFS_BLOCK=$(printf "    obfs: salamander\n    obfs-password: %s\n" "$H_OBFS_PASSWORD")
        CLI_OBFS_BLOCK=$(printf "obfs:\n  type: salamander\n  salamander:\n    password: %s\n" "$H_OBFS_PASSWORD")
        log "WARN" "注意: 检测到混淆启用，端口跳跃功能将被忽略。" "$YELLOW"

        # 强制禁用 URI 中的端口范围
        H_ENABLE_URI_PORT_RANGE="false"
    elif [ "$H_ENABLE_PORT_HOP" = "true" ] && [ -n "$H_PORT_HOP_RANGE" ]; then
        # 2. 仅启用端口跳跃
        PORT_HOP_BLOCK=$(printf "    ports: %s\n" "$H_PORT_HOP_RANGE")
        CLI_PORT_HOP_BLOCK=$(printf "ports: %s\n" "$H_PORT_HOP_RANGE")
        H_ENABLE_URI_PORT_RANGE="true" # 启用 URI 中的端口范围
    fi

    # --- 1. Hysteria2 URI (链接) 格式 ---
    local QUERY_PARAMS=()

    # 混淆参数
    if [ "$H_ENABLE_OBFS" = "true" ] && [ -n "$H_OBFS_PASSWORD" ]; then
        QUERY_PARAMS+=("obfs=salamander" "obfs-password=$H_OBFS_PASSWORD")
    fi

    QUERY_PARAMS+=("sni=$H_DOMAIN")
    if [ "$H_INSECURE" = "true" ]; then
        QUERY_PARAMS+=("insecure=1")
    else
        QUERY_PARAMS+=("insecure=0")
    fi

    # 构建 URI 端口部分
    if [ "$H_ENABLE_URI_PORT_RANGE" = "true" ]; then
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
    mkdir -p "$(dirname "$CONFIG_FILE_CLIENT")"
    echo -e "$CLASH_META_CONFIG" > "$CONFIG_FILE_CLIENT"
    if [ $? -eq 0 ]; then
        log "INFO" "Clash Meta 配置已保存到 $CONFIG_FILE_CLIENT" "$GREEN"
    else
        log "ERROR" "错误：无法保存 Clash Meta 配置到 $CONFIG_FILE_CLIENT" "$RED"
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
        log "INFO" "Hysteria2 CLI 配置已保存到 $CLI_CONFIG_FILE" "$GREEN"
    else
        log "ERROR" "错误：无法保存 Hysteria2 CLI 配置到 $CLI_CONFIG_FILE" "$RED"
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
    local OBFS_INFO=$([ "$H_ENABLE_OBFS" = "true" ] && [ -n "$H_OBFS_PASSWORD" ] && echo "Salamander (密码: $H_OBFS_PASSWORD)" || echo "未启用")
    echo -e " 混淆: $OBFS_INFO"

    local HOP_INFO=""
    if [ "$H_ENABLE_OBFS" = "true" ]; then
        HOP_INFO="已禁用 (因混淆启用)"
    elif [ "$H_ENABLE_PORT_HOP" = "true" ] && [ -n "$H_PORT_HOP_RANGE" ]; then
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
        echo -e "提示：Clash Meta 配置已保存到 $CONFIG_FILE_CLIENT，可直接导入 Clash Meta 客户端"
    else
        log "ERROR" "错误：无法生成 Clash Meta YAML 配置" "$RED"
    fi
    echo -e "${GREEN}----------------------------------------------${NC}"
    log "Hysteria2 CLI YAML 配置:" "$YELLOW"
    if [ -n "$CLI_YAML_CONFIG" ]; then
        echo ""
        echo -e "$CLI_YAML_CONFIG"
        echo -e "提示：Hysteria2 CLI 配置已保存到 $CLI_CONFIG_FILE，可用于 CLI 测试"
    else
        log "ERROR" "错误：无法生成 Hysteria2 CLI YAML 配置" "$RED"
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
        # V5.35: 修正 masquerade URL 读取逻辑，适应新格式
        H_MASQUERADE_URL=$(grep -A 10 'masquerade:' "$CONFIG_FILE" | grep 'url:' | sed 's/.*url: //g' | tr -d '\"' | head -n 1 || echo "https://www.tencent.com")
        if [ -z "$H_MASQUERADE_URL" ]; then
            H_MASQUERADE_URL=$(grep -A 10 'masquerade:' "$CONFIG_FILE" | grep 'addr:' "$CONFIG_FILE" | sed 's/.*addr: //g' | tr -d '\"' | head -n 1 || echo "https://www.tencent.com")
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
        # V5.35: 从配置文件推断 H_INSECURE
        if grep -q 'acme:' "$CONFIG_FILE" || grep -q 'tls:' "$CONFIG_FILE"; then
             # 如果配置文件中有 acme 或 tls 块，通常意味着证书有效，H_INSECURE 应为 false
             # 但更准确的方式是检查证书类型或是否使用了本地证书路径
             # 这里假设如果使用了本地证书路径，H_INSECURE 为 true
             if grep -q 'cert:.*pem' "$CONFIG_FILE" && grep -q 'key:.*pem' "$CONFIG_FILE"; then
                 H_INSECURE="true" # 本地证书，可能需要 insecure
             else
                 H_INSECURE="false" # ACME 证书，通常不需要 insecure
             fi
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

install_hysteria() {
    check_dependencies
    detect_existing_domain
    local CERT_DIR_BASE="$CONFIG_DIR/certs"
    local NUM_CHOICES=2
    local AUTO_EXISTING_CERT="false"

    # --- 自动使用现有证书 ---
    if [ -d "$CERT_DIR_BASE" ] && [ -n "$EXISTING_DOMAIN" ]; then
        CERT_PATH="$CONFIG_DIR/certs/$EXISTING_DOMAIN/fullchain.pem"
        KEY_PATH="$CONFIG_DIR/certs/$EXISTING_DOMAIN/privkey.pem"
        if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
            AUTO_EXISTING_CERT="true"
            CERT_METHOD="existing"
            H_DOMAIN="$EXISTING_DOMAIN"
            log "INFO" "检测到本地证书域名: ${H_DOMAIN}，已自动选择 '使用本地现有证书'。" "$GREEN"
            H_EMAIL=""
            H_INSECURE="true"
        fi
    fi

    if [ "$AUTO_EXISTING_CERT" = "false" ]; then
        echo -e "\n${GREEN}$(get_msg 'select_cert_method')${NC}"
        echo -e "$(get_msg 'cert_method_internal')"
        echo -e "$(get_msg 'cert_method_acmesh')"
        if [ -d "$CERT_DIR_BASE" ]; then
            NUM_CHOICES=3
            echo -e "$(get_msg 'cert_method_existing')"
        fi
        # [修复] 修正之前的 read 换行错误
        read -p "Your choice [1-${NUM_CHOICES}]: " cert_choice
        cert_choice=${cert_choice:-1}
        
        case "$cert_choice" in
            2) CERT_METHOD="acme_sh" ;;
            3) CERT_METHOD="existing" ;;
            *) CERT_METHOD="internal_acme" ;;
        esac

        # --- 域名输入 ---
        while true; do
            local DEFAULT_DOMAIN="${EXISTING_DOMAIN:-$(hostname -f)}"
            if [ "$CERT_METHOD" = "existing" ] && [ -n "$EXISTING_DOMAIN" ]; then
                read -p "$(get_msg 'input_domain' "$EXISTING_DOMAIN")" H_DOMAIN_INPUT
                H_DOMAIN=${H_DOMAIN_INPUT:-$EXISTING_DOMAIN}
            elif [ "$CERT_METHOD" = "internal_acme" ]; then
                read -p "$(get_msg 'input_domain' "$DEFAULT_DOMAIN")" H_DOMAIN_INPUT
                H_DOMAIN=${H_DOMAIN_INPUT:-$DEFAULT_DOMAIN}
            else
                read -p "$(get_msg 'input_domain_no_default')" H_DOMAIN_INPUT
                H_DOMAIN=$H_DOMAIN_INPUT
            fi
            [ -z "$H_DOMAIN" ] && { echo "错误: 域名不能为空!"; continue; }
            validate_domain "$H_DOMAIN"
            break
        done

        # --- 邮箱输入 ---
        if [ "$CERT_METHOD" != "existing" ]; then
            read -p "$(get_msg 'input_email' "$H_DOMAIN")" H_EMAIL
            H_EMAIL=${H_EMAIL:-"admin@$H_DOMAIN"}
        else
            H_EMAIL=""
        fi
        # 证书颁发/检测
        if [ "$CERT_METHOD" = "acme_sh" ]; then
            CERT_PATH="$HOME/.acme.sh/$H_DOMAIN/fullchain.cer"
            KEY_PATH="$HOME/.acme.sh/$H_DOMAIN/$H_DOMAIN.key"
            # 若证书不存在 → 自动安装 acme.sh 并申请
            if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
                log "INFO" "正在使用 acme.sh 为 $H_DOMAIN 申请 Let's Encrypt 证书…" "$BLUE"
                # 1. 自动安装 acme.sh（只执行一次）
                if [ ! -d "$HOME/.acme.sh" ]; then
                    log "INFO" "未检测到 acme.sh，正在自动安装…" "$BLUE"
                    local install_success=false
                    if command -v curl >/dev/null 2>&1 && curl https://get.acme.sh | sh -s email="$H_EMAIL"; then
                        install_success=true
                    elif command -v wget >/dev/null 2>&1 && wget -O - https://get.acme.sh | sh -s email="$H_EMAIL"; then
                        install_success=true
                    else
                        log "ERROR" "acme.sh 安装失败！请检查网络连接。" "$RED"
                        exit 1
                    fi
                    if [ "$install_success" = "true" ]; then
                        # 自动验证安装
                        if [ -x "$HOME/.acme.sh/acme.sh" ]; then
                            log "INFO" "acme.sh 安装并验证成功。" "$GREEN"
                            # 强制加载环境
                            source "$HOME/.bashrc" 2>/dev/null || source "$HOME/.acme.sh/acme.sh" 2>/dev/null || true
                            alias acme.sh="$HOME/.acme.sh/acme.sh" 2>/dev/null || true
                        else
                            log "ERROR" "acme.sh 安装后验证失败：脚本文件不可执行 ($HOME/.acme.sh/acme.sh)。" "$RED"
                            exit 1
                        fi
                    fi
                else
                    log "INFO" "检测到已安装的 acme.sh，跳过安装。" "$GREEN"
                fi
                
                # [核心修正] 询问 ACME 验证模式
                echo -e "\n${YELLOW}请选择 acme.sh 验证模式:${NC}"
                echo " 1) HTTP 独立模式 (Standalone) - 需要 80 端口空闲，自动完成 (推荐)"
                echo " 2) DNS API 模式 - 需要手动输入 API Key，支持通配符"
                read -p "选择模式 [1-2] (默认 1): " acme_mode
                acme_mode=${acme_mode:-1}

                local ACME_ISSUE_CMD=""
                if [ "$acme_mode" == "1" ]; then
                    # Standalone 模式
                    # 停止可能占用 80 端口的旧进程
                    log "INFO" "确保 80 端口可用..." "$BLUE"
                    systemctl stop "$SERVICE_NAME" 2>/dev/null
                    ~/.acme.sh/acme.sh --stop --home ~/.acme.sh &>/dev/null
                    ACME_ISSUE_CMD="~/.acme.sh/acme.sh --issue -d \"$H_DOMAIN\" --standalone --keylength ec-256 --force --pre-hook \"systemctl stop hysteria-server.service 2>/dev/null || true\" --post-hook \"systemctl start hysteria-server.service 2>/dev/null || true\""
                else
                    # DNS API 模式 - 增强交互
                    echo -e "\n${BLUE}--- DNS API 配置向导 ---${NC}"
                    echo "请选择您的 DNS 提供商:"
                    echo " 1) Cloudflare (dns_cf)"
                    echo " 2) Aliyun (dns_ali)"
                    echo " 3) 其他 (手动输入)"
                    read -p "选择 [1-3]: " dns_choice
                    
                    local dns_plugin=""
                    case "$dns_choice" in
                        1)
                            dns_plugin="dns_cf"
                            echo -e "\n${YELLOW}提示: Cloudflare 推荐使用 API Token。${NC}"
                            read -p "请输入 Cloudflare Email (留空则使用 Token): " cf_email
                            if [ -z "$cf_email" ]; then
                                read -p "请输入 Cloudflare API Token: " cf_token
                                export CF_Token="$cf_token"
                            else
                                read -p "请输入 Cloudflare Global API Key: " cf_key
                                export CF_Key="$cf_key"
                                export CF_Email="$cf_email"
                            fi
                            ;;
                        2)
                            dns_plugin="dns_ali"
                            read -p "请输入 Aliyun AccessKey ID: " ali_key
                            read -p "请输入 Aliyun AccessKey Secret: " ali_secret
                            export Ali_Key="$ali_key"
                            export Ali_Secret="$ali_secret"
                            ;;
                        *)
                            echo "请输入您的 DNS 插件代码 (例如: dns_dp, dns_aws)"
                            echo "参考: https://github.com/acmesh-official/acme.sh/wiki/dnsapi"
                            read -p "DNS 插件代码: " dns_plugin
                            echo -e "\n${YELLOW}请依次输入需要的环境变量导出命令 (每行一条，输入空行结束)${NC}"
                            echo "例如: export AWS_ACCESS_KEY_ID=\"...\""
                            while true; do
                                read -p "CMD> " env_cmd
                                [ -z "$env_cmd" ] && break
                                eval "$env_cmd"
                            done
                            ;;
                    esac
                    
                    log "INFO" "正在使用 DNS API ($dns_plugin) 申请证书..." "$BLUE"
                    ACME_ISSUE_CMD="~/.acme.sh/acme.sh --issue -d \"$H_DOMAIN\" --dns \"$dns_plugin\" --keylength ec-256 --force"
                fi

                # 3. 正式申请
                log "INFO" "开始申请证书..." "$BLUE"
                local ACME_OUTPUT
                ACME_OUTPUT=$(eval $ACME_ISSUE_CMD 2>&1)
                local ACME_EXIT_CODE=$?
                
                # 重新设计 acme.sh 状态判断逻辑
                if echo "$ACME_OUTPUT" | grep -q "Skipping\|already\|renew"; then
                    log "WARN" "acme.sh 指示证书已存在且无需更新，申请被跳过 (退出码: $ACME_EXIT_CODE)。" "$YELLOW"
                elif [ $ACME_EXIT_CODE -ne 0 ]; then
                    log "ERROR" "acme.sh 申请失败！命令返回码: $ACME_EXIT_CODE" "$RED"
                    log "DEBUG" "acme.sh 输出:\n$ACME_OUTPUT" "$YELLOW"
                    exit 1
                else
                    log "INFO" "acme.sh 证书申请/更新成功。" "$GREEN"
                fi
                
                # 4. 安装证书到指定路径（生成 fullchain.cer 与 .key）
                log "INFO" "正在安装证书到指定路径..." "$BLUE"
                local TARGET_CERT_DIR=$(dirname "$CERT_PATH")
                if [ ! -d "$TARGET_CERT_DIR" ]; then
                    log "INFO" "目标证书目录 $TARGET_CERT_DIR 不存在，正在创建..." "$BLUE"
                    mkdir -p "$TARGET_CERT_DIR"
                fi
                ~/.acme.sh/acme.sh --install-cert -d "$H_DOMAIN" \
                    --ecc \
                    --fullchain-file "$CERT_PATH" \
                    --key-file "$KEY_PATH" \
                    --reloadcmd "true"
                if [ $? -ne 0 ]; then
                    log "ERROR" "acme.sh 安装证书到指定路径失败！" "$RED"
                    exit 1
                fi
                log "INFO" "acme.sh 证书申请+安装完成！" "$GREEN"
                log "INFO" "证书路径：$CERT_PATH" "$GREEN"
                log "INFO" "私钥路径：$KEY_PATH" "$GREEN"
            else
                log "INFO" "检测到已有 acme.sh 证书文件，直接使用。" "$GREEN"
            fi
            # V5.35: 对于 acme.sh 证书，设置 H_INSECURE
            H_INSECURE="false"
        elif [ "$CERT_METHOD" = "existing" ]; then
            # V5.50: Clarify the path for existing certificates
            log "INFO" "您选择了使用本地现有证书。" "$BLUE"
            log "INFO" "请确保以下证书文件已存在于指定路径:" "$BLUE"
            log "INFO" " 证书链文件: $CONFIG_DIR/certs/$H_DOMAIN/fullchain.pem" "$BLUE"
            log "INFO" " 私钥文件: $CONFIG_DIR/certs/$H_DOMAIN/privkey.pem" "$BLUE"
            log "INFO" "如果文件不存在，脚本将退出。" "$BLUE"
            CERT_PATH="$CONFIG_DIR/certs/$H_DOMAIN/fullchain.pem"
            KEY_PATH="$CONFIG_DIR/certs/$H_DOMAIN/privkey.pem"
            if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
                log "ERROR" "$(get_msg 'err_cert_missing' "$CONFIG_DIR/certs/$H_DOMAIN/")" "$RED"
                log "INFO" "请将正确的证书文件放置到上述路径后重试。" "$BLUE"
                exit 1
            fi
            log "INFO" "$(get_msg 'cert_skip_success')" "$GREEN"
            # V5.35: 对于现有证书，设置 H_INSECURE
            H_INSECURE="true"
        else # internal_acme
            # V5.35: 对于内置 ACME 证书，设置 H_INSECURE
            H_INSECURE="false"
        fi
    fi
    # 3. 输入剩余配置
    read -p "$(get_msg 'input_port')" H_PORT
    H_PORT=${H_PORT:-443}
    validate_port "$H_PORT" || exit 1
    read -s -p "$(get_msg 'input_password')" H_PASSWORD; echo
    H_PASSWORD=${H_PASSWORD:-$(openssl rand -hex 16)}
    read -p "$(get_msg 'confirm_obfs')" obfs_choice
    obfs_choice=${obfs_choice:-Y}
    if [[ "$obfs_choice" =~ ^[yY]$ ]]; then
        H_ENABLE_OBFS="true"
        H_ENABLE_PORT_HOP="false" # 强制禁用端口跳跃
        log "INFO" "注意：启用混淆后，端口跳跃功能已被禁用。" "$YELLOW"
        read -s -p "$(get_msg 'input_obfs_password')" H_OBFS_PASSWORD; echo
        echo
        H_OBFS_PASSWORD=${H_OBFS_PASSWORD:-$(openssl rand -hex 16)}
    else
        H_ENABLE_OBFS="false"; H_OBFS_PASSWORD=""
        read -p "$(get_msg 'confirm_port_hop')" hop_choice
        hop_choice=${hop_choice:-Y}
        if [[ "$hop_choice" =~ ^[yY]$ ]]; then
            H_ENABLE_PORT_HOP="true"
            read -p "$(get_msg 'input_port_hop_range')" H_PORT_HOP_RANGE
            H_PORT_HOP_RANGE=${H_PORT_HOP_RANGE:-"40000-60000"}
            validate_port_range "$H_PORT_HOP_RANGE" || exit 1
        else
            H_ENABLE_PORT_HOP="false"; H_PORT_HOP_RANGE=""
        fi
    fi
    read -p "$(get_msg 'input_masquerade_url')" H_MASQUERADE_URL
    H_MASQUERADE_URL=${H_MASQUERADE_URL:-"https://www.tencent.com"}
    # V5.52: 询问 QUIC 优化
    read -p "是否启用 QUIC 优化参数? (默认: Y) [Y/n]: " quic_opt_choice; quic_opt_choice=${quic_opt_choice:-Y}
    [[ "$quic_opt_choice" =~ ^[yY]$ ]] && H_ENABLE_QUIC_OPT="true" || H_ENABLE_QUIC_OPT="false"
    # V5.52: 询问 SpeedTest
    read -p "是否启用 SpeedTest 功能? (默认: N) [y/N]: " speed_test_choice; speed_test_choice=${speed_test_choice:-N}
    [[ "$speed_test_choice" =~ ^[yY]$ ]] && H_ENABLE_SPEED_TEST="true" || H_ENABLE_SPEED_TEST="false"
    read -p "是否启用协议嗅探? (用于基于域名的路由, 默认: N) [Y/n]: " sniffing_choice; sniffing_choice=${sniffing_choice:-N} # V5.50: 默认为 N
    [[ "$sniffing_choice" =~ ^[yY]$ ]] && H_ENABLE_SNIFFING="true" || H_ENABLE_SNIFFING="false"
    read -p "是否配置 SOCKS5 出站代理? (例如: 用于解锁流媒体, 默认: N) [y/N]: " outbound_choice; outbound_choice=${outbound_choice:-N}
    if [[ "$outbound_choice" =~ ^[yY]$ ]]; then
        H_ENABLE_OUTBOUND="true"
        read -p "请输入 SOCKS5 代理地址 (默认: 127.0.0.1:1080): " H_OUTBOUND_ADDR_INPUT
        H_OUTBOUND_ADDR=${H_OUTBOUND_ADDR_INPUT:-"127.0.0.1:1080"}
        read -s -p "请输入 SOCKS5 用户名 (留空则无认证): " H_OUTBOUND_USER_INPUT; echo
        H_OUTBOUND_USER=${H_OUTBOUND_USER_INPUT:-""} # 可以为空
        read -s -p "请输入 SOCKS5 密码 (留空则无认证): " H_OUTBOUND_PASS_INPUT; echo
        H_OUTBOUND_PASS=${H_OUTBOUND_PASS_INPUT:-""} # 可以为空
    else
        H_ENABLE_OUTBOUND="false"
        H_OUTBOUND_ADDR=""
        H_OUTBOUND_USER=""
        H_OUTBOUND_PASS=""
    fi
    # 4. 安装执行 - V5.39: 为这部分设置 trap
    local rollback_files=()
    # V5.39: 在安装执行部分开始时设置 trap
    # [修正] 调用已定义的 rollback_install
    trap 'rollback_install "${rollback_files[@]}"; exit 1' ERR
    download_and_install; rollback_files+=("$BINARY_PATH")
    create_config_file; rollback_files+=("$CONFIG_FILE")
    create_systemd_service; rollback_files+=("$SYSTEMD_SERVICE")
    log "INFO" "正在启动 Hysteria2 服务..." "$BLUE"; systemctl start "$SERVICE_NAME"
    log "INFO" "等待 5 秒检查服务状态..." "$YELLOW"; sleep 5
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        # V5.37: 设置一个标志表示安装成功，这样 trap 不会错误触发
        INSTALL_SUCCESS="true"
        log "INFO" "$(get_msg 'install_complete')" "$GREEN"
        create_shortcut
        echo
        generate_client_config
    else
        log "ERROR" "Hysteria2 服务启动失败，请检查日志!" "$RED"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager
        # V5.39: 如果服务启动失败，手动触发回滚
        rollback_install "${rollback_files[@]}"
        exit 1
    fi
    # V5.39: 清除 trap，避免在函数正常结束时误触发
    trap - ERR
}

# --- 主函数 (V5.10 修正后的流程控制) ---
# V5.38: 修正 main 函数，将语言选择和流程控制放在最前面
# V5.48: 确保语言选择在流程最开始执行，即使 .lang 文件存在
main() {
    trap cleanup_exit EXIT
    check_root

    # 确保主脚本路径被设置
    local SCRIPT_NAME=$(basename "$0")
    SCRIPT_PATH="/opt/hysteria/$SCRIPT_NAME"

    # --- V5.48: 强制检查语言文件，如果不存在则选择语言 ---
    # 检查 /etc/hysteria 目录是否存在
    if [ ! -d "$CONFIG_DIR" ]; then
        # 如果整个配置目录都不存在，说明是全新安装，必须选择语言
        log "INFO" "检测到全新安装，开始语言选择。" "$BLUE"
        mkdir -p "$CONFIG_DIR"
        echo -e "${GREEN}请选择语言 / Please select language:${NC}"
        echo -e "${YELLOW}1) 中文 (Chinese)${NC}"
        echo -e "${YELLOW}2) English${NC}"
        read -p "Enter choice [1-2] (default: 1): " lang_choice
        case $lang_choice in
            2) echo "en" > "$LANG_FILE" ;;
            *) echo "zh" > "$LANG_FILE" ;; # 默认中文
        esac
    else
        # 目录存在，检查语言文件是否存在
        if [ ! -f "$LANG_FILE" ]; then
            # 目录存在但语言文件不存在，提示用户选择语言
            log "INFO" "未找到语言配置文件，开始语言选择。" "$BLUE"
            echo -e "${GREEN}请选择语言 / Please select language:${NC}"
            echo -e "${YELLOW}1) 中文 (Chinese)${NC}"
            echo -e "${YELLOW}2) English${NC}"
            read -p "Enter choice [1-2] (default: 1): " lang_choice
            case $lang_choice in
                2) echo "en" > "$LANG_FILE" ;;
                *) echo "zh" > "$LANG_FILE" ;; # 默认中文
            esac
        else
            # 语言文件存在，读取并使用
            log "INFO" "已加载语言配置: $(cat $LANG_FILE)" "$BLUE"
        fi
    fi

    # --- V5.38: 检查是否是管理菜单调用 ---
    if [ "$1" = "manage_menu" ]; then
        manage_menu
        exit 0
    fi

    # --- V5.38: 检查是否已安装 ---
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
        # --- V5.38: 如果未安装，则开始安装流程 ---
        log "INFO" "未检测到 Hysteria2 二进制文件，开始安装流程。" "$BLUE"
        install_hysteria
    fi
}

main "$@"
