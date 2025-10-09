#!/bin/bash

#====================================================================================
# Hysteria 2 自动化安装管理脚本 (v3.1 - 修复 acme.sh 证书时序问题)
#
# 功能列表:
# - [✓] Hysteria 2 ACME 证书申请 (内置或 acme.sh DNS API) 
# - [✓] 端口跳跃功能 (基于 iptables nat)
# - [✓] 支持 Salamander 混淆 (高度推荐)
# - [✓] 自动识别 CPU 架构 (amd64/arm64)
# - [✓] 自动配置防火墙 (firewalld/ufw/iptables)
# - [✓] 一键生成客户端配置和 Clash Meta 配置片段
# - [✓] 服务管理菜单 / 卸载备份
# - [✓] 多语言支持
#====================================================================================

# --- 颜色和变量 ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
CONFIG_DIR="/etc/hysteria"; CONFIG_FILE="$CONFIG_DIR/config.yaml"; SERVICE_NAME="hysteria-server"
SYSTEMD_SERVICE="/etc/systemd/system/$SERVICE_NAME.service"; BINARY_PATH="/usr/local/bin/hysteria"
BACKUP_DIR="/root/hysteria_backup"; LOG_FILE="/var/log/hysteria_install.log"; ACME_SH_PATH="$HOME/.acme.sh/acme.sh"
SCRIPT_LANG="zh"
INSTALL_SUCCESS="false" # 标记安装是否成功
CERT_PATH="" # acme.sh 模式下的证书路径
KEY_PATH=""  # acme.sh 模式下的密钥路径

# --- 消息定义 ---
declare -A MESSAGES
# 中文消息 (zh)
MESSAGES[zh_select_language]="请选择语言 / Select Language"
MESSAGES[zh_select_cert_method]="请选择证书获取方式:"
MESSAGES[zh_cert_method_internal]="1) Hysteria 内置 ACME (推荐, 简单)"
MESSAGES[zh_cert_method_acmesh]="2) 使用 acme.sh (支持 DNS API, 功能更强大)"
MESSAGES[zh_select_acmesh_challenge]="请选择 acme.sh 证书验证方式:"
MESSAGES[zh_acmesh_challenge_standalone]="1) Standalone (需要确保 80 端口可用)"
MESSAGES[zh_acmesh_challenge_cf]="2) Cloudflare DNS API"
MESSAGES[zh_acmesh_challenge_ali]="3) Aliyun DNS API"
MESSAGES[zh_input_cf_key]="请输入 Cloudflare Global API Key: "
MESSAGES[zh_input_cf_email]="请输入 Cloudflare 账户邮箱: "
MESSAGES[zh_input_ali_key]="请输入 Aliyun AccessKey ID: "
MESSAGES[zh_input_ali_secret]="请输入 Aliyun AccessKey Secret: "
MESSAGES[zh_confirm_port_hop]="是否开启端口跳跃功能? (默认: N) [y/N]: "
MESSAGES[zh_input_port_hop_range]="请输入端口跳跃范围 (例如: 40000-60000, 默认: 40000-60000): "
MESSAGES[zh_input_domain]="请输入您的域名 (必须解析到此服务器 IP): "
MESSAGES[zh_input_email]="请输入您的邮箱 (用于 ACME 证书, 默认: admin@your_domain): "
MESSAGES[zh_input_port]="请输入 Hysteria 主监听端口 (默认: 443): "
MESSAGES[zh_input_password]="请输入连接密码 (留空将自动生成): "
MESSAGES[zh_confirm_obfs]="是否启用 Salamander 混淆? (强烈推荐, 默认: Y) [Y/n]: "
MESSAGES[zh_input_obfs_password]="请输入混淆密码 (留空将使用默认): "
MESSAGES[zh_input_masquerade_url]="请输入伪装 URL (默认: https://www.bing.com): "
MESSAGES[zh_err_root]="错误: 此脚本必须以 root 身份运行!"
MESSAGES[zh_err_domain_resolve]="错误: 域名无法正确解析到此服务器的公网 IP!"
MESSAGES[zh_manage_menu_title]="Hysteria2 服务管理菜单"
MESSAGES[zh_install_acmesh]="正在安装 acme.sh..."
MESSAGES[zh_err_install_acmesh]="acme.sh 安装失败!"
MESSAGES[zh_issue_cert]="正在使用 acme.sh 申请证书..."
MESSAGES[zh_issue_cert_success]="证书申请成功。"
MESSAGES[zh_err_issue_cert]="证书申请失败!"
MESSAGES[zh_err_cert_file_missing]="错误: 您选择了 acme.sh 模式，但证书文件 (%s) 不存在。请检查 acme.sh 颁发日志。"
MESSAGES[zh_firewall_hop_rules]="端口跳跃防火墙规则 (iptables) 已配置。"
MESSAGES[zh_confirm_sniffing]="是否启用协议嗅探? (用于基于域名的路由, 默认: Y) [Y/n]: "
MESSAGES[zh_confirm_outbound]="是否配置 SOCKS5 出站代理? (例如: 用于解锁流媒体) [y/N]: "
MESSAGES[zh_input_outbound_addr]="请输入 SOCKS5 代理地址 (格式 IP:端口, 例如 127.0.0.1:1080): "
MESSAGES[zh_input_outbound_user]="请输入 SOCKS5 代理用户名 (留空则无): "
MESSAGES[zh_input_outbound_pass]="请输入 SOCKS5 代理密码 (留空则无): "
MESSAGES[zh_err_domain_format]="错误: 域名格式不正确!"
MESSAGES[zh_detect_existing]="检测到 Hysteria2 已安装, 请选择操作:"
MESSAGES[zh_action_manage]="管理服务"
MESSAGES[zh_action_reinstall]="卸载并重装"
MESSAGES[zh_action_uninstall]="仅卸载"
MESSAGES[zh_action_exit]="退出"
MESSAGES[zh_uninstall_confirm]="您确定要卸载 Hysteria2 吗? [y/N]: "
MESSAGES[zh_uninstall_backup_confirm]="是否备份当前配置文件? [Y/n]: "
MESSAGES[zh_backup_path]="备份文件已保存至: %s"
MESSAGES[zh_manage_menu_status]="查看服务状态"
MESSAGES[zh_manage_menu_log]="查看实时日志"
MESSAGES[zh_manage_menu_restart]="重启服务"
MESSAGES[zh_manage_menu_stop]="停止服务"
MESSAGES[zh_manage_menu_start]="启动服务"
MESSAGES[zh_manage_menu_config]="显示客户端配置"
MESSAGES[zh_manage_menu_exit]="返回主菜单"
MESSAGES[zh_install_deps]="正在检查并安装依赖..."
MESSAGES[zh_install_success]="依赖安装成功。"
MESSAGES[zh_detect_arch]="正在检测系统架构..."
MESSAGES[zh_arch_detected]="检测到的系统架构: %s"
MESSAGES[zh_downloading]="正在从 GitHub 下载 Hysteria2 最新版本 (架构: %s)..."
MESSAGES[zh_download_success]="Hysteria2 下载成功。"
MESSAGES[zh_err_download]="错误: Hysteria2 下载失败, 请检查您的网络或 Github 连通性!"
MESSAGES[zh_installing_binary]="正在安装 Hysteria2 二进制文件..."
MESSAGES[zh_creating_config]="正在创建配置文件..."
MESSAGES[zh_creating_service]="正在创建 systemd 服务..."
MESSAGES[zh_configuring_firewall]="正在配置防火墙..."
MESSAGES[zh_firewall_opened]="端口 %s (TCP/UDP) 和 80 (TCP) 已开放。"
MESSAGES[zh_service_starting]="正在启动 Hysteria2 服务..."
MESSAGES[zh_service_check_wait]="等待 5 秒检查服务状态..."
MESSAGES[zh_install_complete]="Hysteria2 安装配置完成!"
MESSAGES[zh_err_service_start]="错误: Hysteria2 服务启动失败, 请检查日志!"
MESSAGES[zh_client_config_info]="客户端配置信息"
MESSAGES[zh_sub_link]="订阅链接 (URL):"
MESSAGES[zh_clash_meta_config]="Clash Meta 配置片段:"
MESSAGES[zh_qrcode]="二维码 (请使用兼容客户端扫描):"
MESSAGES[zh_log_tip]="安装或错误日志文件路径: %s\n查看命令: tail -f %s"
MESSAGES[zh_input_prompt]="请输入选项 [1-4]: "

# 英文消息 (en)
# ... (英文消息定义省略，与原代码保持一致)
MESSAGES[en_select_language]="Select Language / "
MESSAGES[en_select_cert_method]="Select certificate management method:"
MESSAGES[en_cert_method_internal]="1) Hysteria's Built-in ACME (Recommended, Simple)"
MESSAGES[en_cert_method_acmesh]="2) Use acme.sh (Supports DNS API, More Powerful)"
MESSAGES[en_select_acmesh_challenge]="Select acme.sh certificate challenge method:"
MESSAGES[en_acmesh_challenge_standalone]="1) Standalone (requires port 80 to be open)"
MESSAGES[en_acmesh_challenge_cf]="2) Cloudflare DNS API"
MESSAGES[en_acmesh_challenge_ali]="3) Aliyun DNS API"
MESSAGES[en_input_cf_key]="Enter your Cloudflare Global API Key: "
MESSAGES[en_input_cf_email]="Enter your Cloudflare account email: "
MESSAGES[en_input_ali_key]="Enter your Aliyun AccessKey ID: "
MESSAGES[en_input_ali_secret]="Enter your Aliyun AccessKey Secret: "
MESSAGES[en_confirm_port_hop]="Enable Port Hopping feature? (default: N) [y/N]: "
MESSAGES[en_input_port_hop_range]="Enter port hopping range (e.g., 40000-60000, default: 40000-60000): "
MESSAGES[en_input_domain]="Enter your domain (must resolve to this server's IP): "
MESSAGES[en_input_email]="Enter your email (for ACME certificate, default: admin@your_domain): "
MESSAGES[en_input_port]="Enter Hysteria main listen port (default: 443): "
MESSAGES[en_input_password]="Enter connection password (leave blank to generate): "
MESSAGES[en_confirm_obfs]="Enable Salamander obfuscation? (highly recommended, default: Y) [Y/n]: "
MESSAGES[en_input_obfs_password]="Enter obfuscation password (leave blank for default): "
MESSAGES[en_input_masquerade_url]="Enter masquerade URL (default: https://www.bing.com): "
MESSAGES[en_err_root]="Error: This script must be run as root!"
MESSAGES[en_err_domain_resolve]="Error: Domain does not resolve to this server's public IP!"
MESSAGES[en_manage_menu_title]="Hysteria2 Service Management"
MESSAGES[en_install_acmesh]="Installing acme.sh..."
MESSAGES[en_err_install_acmesh]="acme.sh installation failed!"
MESSAGES[en_issue_cert]="Issuing certificate via acme.sh..."
MESSAGES[en_issue_cert_success]="Certificate issued successfully."
MESSAGES[en_err_issue_cert]="Certificate issuance failed!"
MESSAGES[en_err_cert_file_missing]="Error: You chose acme.sh mode, but the certificate file (%s) does not exist. Please check acme.sh issuance logs."
MESSAGES[en_firewall_hop_rules]="Port hopping firewall rules (iptables) have been configured."
MESSAGES[en_confirm_sniffing]="Enable protocol sniffing? (for domain-based routing, default: Y) [Y/n]: "
MESSAGES[en_confirm_outbound]="Configure a SOCKS5 outbound proxy? (e.g., for unlocking streaming) [y/N]: "
MESSAGES[en_input_outbound_addr]="Enter SOCKS5 proxy address (format IP:port, e.g., 127.0.0.1:1080): "
MESSAGES[en_input_outbound_user]="Enter SOCKS5 proxy username (leave blank if none): "
MESSAGES[en_input_outbound_pass]="Enter SOCKS5 proxy password (leave blank if none): "
MESSAGES[en_err_domain_format]="Error: Invalid domain format!"
MESSAGES[en_detect_existing]="Hysteria2 is already installed. Please choose an action:"
MESSAGES[en_action_manage]="Manage Service"
MESSAGES[en_action_reinstall]="Uninstall and Reinstall"
MESSAGES[en_action_uninstall]="Uninstall Only"
MESSAGES[en_action_exit]="Exit"
MESSAGES[en_uninstall_confirm]="Are you sure you want to uninstall Hysteria2? [y/N]: "
MESSAGES[en_uninstall_backup_confirm]="Backup current configuration file? [Y/n]: "
MESSAGES[en_backup_path]="Backup file saved to: %s"
MESSAGES[en_manage_menu_status]="View Status"
MESSAGES[en_manage_menu_log]="View Real-time Log"
MESSAGES[en_manage_menu_restart]="Restart Service"
MESSAGES[en_manage_menu_stop]="Stop Service"
MESSAGES[en_manage_menu_start]="Start Service"
MESSAGES[en_manage_menu_config]="Show Client Config"
MESSAGES[en_manage_menu_exit]="Return to Main Menu"
MESSAGES[en_install_deps]="Checking and installing dependencies..."
MESSAGES[en_install_success]="Dependencies installed successfully."
MESSAGES[en_detect_arch]="Detecting system architecture..."
MESSAGES[en_arch_detected]="System architecture: %s"
MESSAGES[en_downloading]="Downloading the latest version of Hysteria2 from GitHub (Arch: %s)..."
MESSAGES[en_download_success]="Hysteria2 downloaded successfully."
MESSAGES[en_err_download]="Error: Failed to download Hysteria2. Please check your network or GitHub connectivity."
MESSAGES[en_installing_binary]="Installing Hysteria2 binary..."
MESSAGES[en_creating_config]="Creating configuration file..."
MESSAGES[en_creating_service]="Creating systemd service..."
MESSAGES[en_configuring_firewall]="Configuring firewall..."
MESSAGES[en_firewall_opened]="Ports %s (TCP/UDP) and 80 (TCP) have been opened."
MESSAGES[en_service_starting]="Starting Hysteria2 service..."
MESSAGES[en_service_check_wait]="Waiting 5 seconds to check service status..."
MESSAGES[en_install_complete]="Hysteria2 installation complete!"
MESSAGES[en_err_service_start]="Error: Hysteria2 service failed to start. Please check the logs!"
MESSAGES[en_client_config_info]="Client Configuration Info"
MESSAGES[en_sub_link]="Subscription Link (URL):"
MESSAGES[en_clash_meta_config]="Clash Meta Config Snippet:"
MESSAGES[en_qrcode]="QR Code (scan with a compatible client):"
MESSAGES[en_log_tip]="Installation or error log file path: %s\nView command: tail -f %s"
MESSAGES[en_input_prompt]="Enter your choice [1-4]: "


# --- 基础工具函数 ---
log() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${2:-$NC}${1}${NC}" | tee -a "$LOG_FILE"; }
get_msg() { local key="$1"; shift; printf "${MESSAGES[${SCRIPT_LANG}_${key}]}" "$@"; }
check_root() { [[ $EUID -ne 0 ]] && { log "$(get_msg 'err_root')" "$RED"; exit 1; }; }
cleanup_exit() {
    local exit_code=$?
    if [ "$INSTALL_SUCCESS" == "false" ] || [ "$exit_code" -ne 0 ]; then
        log "------------------------------------------------------" "$RED"
        log "$(get_msg 'log_tip' "$LOG_FILE" "$LOG_FILE")" "$YELLOW"
        log "------------------------------------------------------" "$RED"
    fi
    exit $exit_code
}

# --- 语言选择 ---
select_language() {
    clear; echo -e "${BLUE}=====================================${NC}\n${GREEN} Hysteria 2 Installer & Manager ${NC}\n${BLUE}=====================================${NC}\n\n ${YELLOW}1) 简体中文 (Chinese)${NC}\n ${YELLOW}2) English${NC}\n"
    read -p " $(get_msg 'select_language') (1/2): " lang_choice
    [[ "$lang_choice" == "2" ]] && SCRIPT_LANG="en" || SCRIPT_LANG="zh"
}

# --- 依赖检查和安装 (保持不变) ---
check_dependencies() {
    log "$(get_msg 'install_deps')" "$BLUE"
    local deps="curl jq qrencode socat wget dig"
    local pm=""

    if command -v apt >/dev/null 2>&1; then
        pm="apt"
    elif command -v yum >/dev/null 2>&1; then
        pm="yum"
    elif command -v dnf >/dev/null 2>&1; then
        pm="dnf"
    fi

    if [ -n "$pm" ]; then
        if ! command -v dig >/dev/null 2>&1; then
            if [ "$pm" = "apt" ]; then deps="$deps dnsutils"; else deps="$deps bind-utils"; fi
        fi
        
        for dep in $deps; do
            if ! command -v "$dep" >/dev/null 2>&1; then
                log "Installing $dep..." "$YELLOW"
                if [ "$pm" = "apt" ]; then
                    $pm update -y >/dev/null 2>&1 || log "Warning: apt update failed." "$YELLOW"
                fi
                $pm install -y "$dep" >/dev/null 2>&1
                
                local check_name="$dep"
                if [ "$dep" = "dnsutils" ] || [ "$dep" = "bind-utils" ]; then check_name="dig"; fi

                if ! command -v "$check_name" >/dev/null 2>&1; then
                    log "Failed to install required dependency: $dep" "$RED"
                    exit 1
                fi
            fi
        done
    else
        log "无法自动安装依赖，请手动安装 curl, jq, qrencode, socat, wget, dig / Cannot auto-install dependencies, please install them manually." "$RED"; exit 1
    fi
    log "$(get_msg 'install_success')" "$GREEN"
}

# --- 域名验证、架构检测、下载安装等函数（保持不变） ---
validate_domain() {
    local domain="$1"
    local local_ip_v4=$(curl -s4 api.ip.sb)
    if [ -z "$local_ip_v4" ]; then
        log "无法获取服务器 IPv4 地址" "$RED"
        return 1
    fi
    local resolved_ip=$(dig +short "$domain" A | head -n 1)
    
    if [[ "$resolved_ip" != "$local_ip_v4" ]]; then
        log "$(get_msg 'err_domain_resolve')\n 服务器 IPv4: $local_ip_v4\n 域名解析 IP: $resolved_ip" "$RED"; return 1
    fi
    return 0
}

get_arch() {
    ARCH=$(uname -m); case $ARCH in x86_64) ARCH="amd64";; aarch64) ARCH="arm64";; *) log "不支持的架构: $ARCH" "$RED"; exit 1;; esac
    log "$(get_msg 'arch_detected' "$ARCH")" "$GREEN"
}

download_and_install() {
    get_arch; log "$(get_msg 'downloading' "$ARCH")" "$BLUE"
    LATEST_URL=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r ".assets[] | select(.name == \"hysteria-linux-${ARCH}\") | .browser_download_url")
    [[ -z "$LATEST_URL" ]] && { log "$(get_msg 'err_download')" "$RED"; exit 1; }
    
    wget -c --show-progress -O "$BINARY_PATH" "$LATEST_URL" 2>&1 | tee -a "$LOG_FILE" | grep -v 'ETA' | grep -E '\[|%|MB' || { log "$(get_msg 'err_download')" "$RED"; exit 1; }
    
    log "$(get_msg 'download_success')" "$GREEN"; chmod +x "$BINARY_PATH"
}

install_acme_sh() {
    if [ ! -f "$ACME_SH_PATH" ]; then
        log "$(get_msg 'install_acmesh')" "$BLUE"
        curl -s https://get.acme.sh | sh -s install --debug 2>&1 | tee -a "$LOG_FILE"
        if [ $? -ne 0 ] || [ ! -f "$ACME_SH_PATH" ]; then
            log "$(get_msg 'err_install_acmesh')" "$RED"; exit 1
        fi
        . "$HOME/.acme.sh/acme.sh.env"
        log "acme.sh $(get_msg 'install_success')" "$GREEN"
    fi
}

# --- 修复后的证书颁发函数：设置全局路径变量 ---
issue_cert_acmesh() {
    log "$(get_msg 'issue_cert')" "$BLUE"
    local cmd_params=""
    # 确保路径变量设置在全局或后续函数可见
    CERT_PATH="$CONFIG_DIR/certs/$H_DOMAIN/fullchain.pem"
    KEY_PATH="$CONFIG_DIR/certs/$H_DOMAIN/privkey.pem"

    case $ACMESH_CHALLENGE_METHOD in
        1) # Standalone
        cmd_params="--standalone --listen-port 80"
        ;;
        2) # Cloudflare
        read -p "$(get_msg 'input_cf_email')" CF_Email
        read -s -p "$(get_msg 'input_cf_key')" CF_Key; echo
        export CF_Key CF_Email
        cmd_params="--dns dns_cf"
        ;;
        3) # Aliyun
        read -p "$(get_msg 'input_ali_key')" Ali_Key
        read -s -p "$(get_msg 'input_ali_secret')" Ali_Secret; echo
        export Ali_Key Ali_Secret
        cmd_params="--dns dns_ali"
        ;;
        *) log "无效的 acme.sh 验证方式 / Invalid acme.sh challenge method." "$RED"; exit 1;;
    esac
    
    # 申请证书
    "$ACME_SH_PATH" --issue -d "$H_DOMAIN" $cmd_params --keylength ec-256 --force 2>&1 | tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then log "$(get_msg 'err_issue_cert')" "$RED"; exit 1; fi
    
    mkdir -p "$(dirname "$CERT_PATH")"
    # 安装证书
    "$ACME_SH_PATH" --install-cert -d "$H_DOMAIN" --ecc \
        --fullchain-file "$CERT_PATH" \
        --key-file "$KEY_PATH" \
        --reloadcmd "systemctl reload $SERVICE_NAME" 2>&1 | tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then log "$(get_msg 'err_issue_cert')" "$RED"; exit 1; fi
    
    unset CF_Key CF_Email Ali_Key Ali_Secret
    log "$(get_msg 'issue_cert_success')" "$GREEN"
}

# --- 修复后的防火墙配置函数 ---
configure_firewall() {
    log "$(get_msg 'configuring_firewall')" "$BLUE"
    local PM="" # 包管理器

    if command -v apt >/dev/null 2>&1; then PM="apt";
    elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then PM="yum_dnf";
    fi
    
    # 1. 清理旧的端口跳跃规则
    # 查找并删除旧的 REDIRECT 规则
    local old_nat_rules=$(iptables -t nat -L PREROUTING -n --line-numbers | grep "REDIRECT.*to-ports $H_PORT" | awk '{print $1,$NF}' | sort -nr)
    for line in $old_nat_rules; do
        local line_num=$(echo $line | awk '{print $1}')
        iptables -t nat -D PREROUTING $line_num 2>/dev/null
    done
    
    # 查找并删除旧的 INPUT ACCEPT 规则（基于端口范围的）
    local old_input_rules=$(iptables -L INPUT -n --line-numbers | grep "dports.*:$H_PORT_HOP_RANGE" | awk '{print $1}' | sort -nr)
    for line_num in $old_input_rules; do
        iptables -D INPUT $line_num 2>/dev/null
    done
    
    # 清理旧的 INPUT 443/80 规则（避免重复）
    iptables -D INPUT -p tcp --dport "$H_PORT" -j ACCEPT 2>/dev/null
    iptables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null


    if [ "$H_ENABLE_PORT_HOP" == "true" ]; then
        log "端口跳跃功能已启用，正在配置 iptables 转发和防火墙..." "$YELLOW"
        
        # 2. 🚨 核心修复：添加 PREROUTING (NAT) 和 INPUT (FILTER) 规则
        local port_range_formatted=$(echo "$H_PORT_HOP_RANGE" | sed 's/-/:/')
        
        # NAT 规则：将跳跃范围内的 UDP 转发到 Hysteria 监听端口
        iptables -t nat -A PREROUTING -p udp -m multiport --dports "$port_range_formatted" -j REDIRECT --to-port "$H_PORT"
        
        # FILTER 规则：允许跳跃范围内的 UDP 流量进入（修复您遇到的问题）
        iptables -A INPUT -p udp -m multiport --dports "$port_range_formatted" -j ACCEPT
        
        # 同时放行 Hysteria 实际监听的端口（用于 TCP 流量和客户端测试）
        iptables -A INPUT -p tcp --dport "$H_PORT" -j ACCEPT
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        
        log "$(get_msg 'firewall_hop_rules')" "$GREEN"
    else
        # 仅放行 Hysteria 主端口和 80 端口（用于 ACME 验证）
        if command -v firewalld &>/dev/null; then
            firewall-cmd --add-port=${H_PORT}/tcp --permanent &>/dev/null
            firewall-cmd --add-port=${H_PORT}/udp --permanent &>/dev/null
            firewall-cmd --add-port=80/tcp --permanent &>/dev/null
            firewall-cmd --reload &>/dev/null
        elif command -v ufw &>/dev/null; then
            ufw allow ${H_PORT}/tcp >/dev/null
            ufw allow ${H_PORT}/udp >/dev/null
            ufw allow 80/tcp >/dev/null
            ufw reload &>/dev/null
        elif command -v iptables &>/dev/null; then
            iptables -A INPUT -p tcp --dport ${H_PORT} -j ACCEPT
            iptables -A INPUT -p udp --dport ${H_PORT} -j ACCEPT
            iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        fi
        log "$(get_msg 'firewall_opened' "$H_PORT")" "$GREEN"
    fi
    
    # 3. 强制持久化规则 (适用于 Debian/Ubuntu，确保规则重启不丢失)
    if [ -n "$PM" ]; then
        if [ "$PM" == "apt" ]; then
            log "正在安装 iptables-persistent 以保存规则..." "$YELLOW"
            # 确保安装了持久化工具
            apt install iptables-persistent -y >/dev/null 2>&1
        fi
        
        if command -v iptables-save &>/dev/null; then
            log "正在保存 iptables 规则..." "$BLUE"
            # 确保规则保存到正确的位置
            if [ -f /etc/sysconfig/iptables ]; then 
                iptables-save > /etc/sysconfig/iptables;
            elif [ -f /etc/iptables/rules.v4 ]; then 
                iptables-save > /etc/iptables/rules.v4;
            # 尝试通过服务保存（Debian/Ubuntu 的推荐方式）
            elif systemctl is-active --quiet netfilter-persistent; then
                 systemctl restart netfilter-persistent;
            fi
            log "iptables 规则已持久化保存。" "$GREEN"
        fi
    fi
}

# --- 修复后的创建配置文件函数：加入证书文件存在性检查 ---
create_config_file() {
    log "$(get_msg 'creating_config')" "$BLUE"; mkdir -p "$CONFIG_DIR"
    local tls_config=""
    
    if [ "$CERT_METHOD" == "internal_acme" ]; then
        tls_config=$(cat <<EOF
acme:
  domains:
  - $H_DOMAIN
  email: $H_EMAIL
EOF
)
    else # acme_sh
        # 🚨 核心修复：检查证书文件是否已存在
        if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
             log "$(get_msg 'err_cert_file_missing' "$CERT_PATH")" "$RED"
             exit 1
        fi
        
        tls_config=$(cat <<EOF
tls:
  cert: $CERT_PATH
  key: $KEY_PATH
EOF
)
    fi

    cat > "$CONFIG_FILE" << EOF
listen: :$H_PORT

$tls_config

auth:
  type: password
  password: "$H_PASSWORD"

$H_OBFS_CONFIG

masquerade:
  type: proxy
  proxy:
    url: $H_MASQUERADE_URL
    rewriteHost: true

$H_SNIFFING_CONFIG
$H_OUTBOUND_CONFIG

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 16777216
  maxConnReceiveWindow: 33554432
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

speedTest: true
EOF
}

# --- 创建 systemd 服务（保持不变） ---
create_systemd_service() {
    log "$(get_msg 'creating_service')" "$BLUE"
    cat > "$SYSTEMD_SERVICE" << EOF
[Unit]
Description=Hysteria2 Service (Server)
After=network.target
[Service]
Type=simple
ExecStart=$BINARY_PATH server --config $CONFIG_FILE
WorkingDirectory=$CONFIG_DIR
User=root
Group=root
Restart=on-failure
RestartSec=3s
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
}

# --- 客户端配置生成（保持不变） ---
generate_client_config() {
    clear
    local obfs_param="" hop_param="" obfs_clash_config="" hop_clash_config=""
    if [ "$H_ENABLE_OBFS" == "true" ]; then
        obfs_param="&obfs=salamander&obfs-password=$H_OBFS_PASSWORD"
        obfs_clash_config=$(printf "  obfs:\n    type: salamander\n    password: %s" "$H_OBFS_PASSWORD")
    fi
    if [ "$H_ENABLE_PORT_HOP" == "true" ]; then
        local hop_ports=$(iptables -t nat -L PREROUTING -n | grep "REDIRECT.*to-ports $H_PORT" | head -n 1 | sed -E 's/.*dports ([0-9]+:[0-9]+).*/\1/' | sed 's/:/-/g')
        H_PORT_HOP_RANGE=${hop_ports:-$H_PORT_HOP_RANGE}
        hop_param="&hopPorts=$H_PORT_HOP_RANGE"
        hop_clash_config=$(printf "  ports: %s" "$H_PORT_HOP_RANGE")
    fi
    
    local sub_link="hysteria2://$H_PASSWORD@$H_DOMAIN:$H_PORT/?insecure=0&sni=$H_DOMAIN${obfs_param}${hop_param}#$(hostname)-hysteria"
    local clash_config=$(cat <<EOF
- name: "$(hostname)-hysteria"
  type: hysteria2
  server: $H_DOMAIN
  port: $H_PORT
  password: "$H_PASSWORD"
  sni: $H_DOMAIN
  skip-cert-verify: false
$( [ -n "$hop_clash_config" ] && echo "$hop_clash_config" )
$( [ -n "$obfs_clash_config" ] && echo "$obfs_clash_config" )
EOF
)
    
    echo -e "${BLUE}===============================================${NC}"
    echo -e "${GREEN} $(get_msg 'client_config_info') ${NC}"
    echo -e "${BLUE}===============================================${NC}\n"
    echo -e "${YELLOW}$(get_msg 'sub_link')${NC}\n${GREEN}$sub_link${NC}\n"
    echo -e "${YELLOW}$(get_msg 'clash_meta_config')${NC}\n${GREEN}$clash_config${NC}\n"
    echo -e "${YELLOW}$(get_msg 'qrcode')${NC}"; qrencode -t ansiutf8 "$sub_link"
    echo -e "\n${BLUE}===============================================${NC}"
}

# --- 安装主流程 (调整证书颁发和配置文件的时序) ---
install_hysteria() {
    # --- 依赖检查/域名/模式选择 ---
    check_dependencies

    echo -e "\n${GREEN}$(get_msg 'select_cert_method')${NC}"
    echo -e " $(get_msg 'cert_method_internal')"
    echo -e " $(get_msg 'cert_method_acmesh')"
    read -p "Your choice [1-2]: " cert_choice
    [[ "$cert_choice" == "2" ]] && CERT_METHOD="acme_sh" || CERT_METHOD="internal_acme"
    
    while true; do
        read -p "$(get_msg 'input_domain')" H_DOMAIN
        if [ -z "$H_DOMAIN" ]; then log "$(get_msg 'err_domain_format')" "$RED"; continue; fi
        if validate_domain "$H_DOMAIN"; then break; else exit 1; fi
    done
    read -p "$(get_msg 'input_email')" H_EMAIL; H_EMAIL=${H_EMAIL:-"admin@$H_DOMAIN"}


    # --- 证书颁发 ---
    # 🚨 无论哪种方式，都必须在创建配置文件之前完成
    if [ "$CERT_METHOD" == "acme_sh" ]; then
        install_acme_sh
        echo -e "\n${GREEN}$(get_msg 'select_acmesh_challenge')${NC}"
        echo -e " $(get_msg 'acmesh_challenge_standalone')"
        echo -e " $(get_msg 'acmesh_challenge_cf')"
        echo -e " $(get_msg 'acmesh_challenge_ali')"
        read -p "Your choice [1-3]: " ACMESH_CHALLENGE_METHOD
        issue_cert_acmesh # 必须成功，否则脚本会在 create_config_file 中退出
    fi

    # --- 端口、密码、混淆配置 ---
    read -p "$(get_msg 'input_port')" H_PORT; H_PORT=${H_PORT:-443}; log "Hysteria 监听端口: $H_PORT" "$GREEN"
    read -s -p "$(get_msg 'input_password')" H_PASSWORD; echo; H_PASSWORD=${H_PASSWORD:-$(openssl rand -hex 16)}; log "连接密码已设置" "$GREEN"

    read -p "$(get_msg 'confirm_port_hop')" hop_choice
    if [[ "$hop_choice" =~ ^[yY]$ ]]; then
        H_ENABLE_PORT_HOP="true"
        read -p "$(get_msg 'input_port_hop_range')" H_PORT_HOP_RANGE
        H_PORT_HOP_RANGE=${H_PORT_HOP_RANGE:-"40000-60000"}; log "端口跳跃范围: $H_PORT_HOP_RANGE" "$GREEN"
    else
        H_ENABLE_PORT_HOP="false"
    fi

    read -p "$(get_msg 'confirm_obfs')" obfs_choice; obfs_choice=${obfs_choice:-Y}
    if [[ "$obfs_choice" =~ ^[yY]$ ]]; then
        H_ENABLE_OBFS="true"
        read -s -p "$(get_msg 'input_obfs_password')" H_OBFS_PASSWORD; echo
        H_OBFS_PASSWORD=${H_OBFS_PASSWORD:-"eb204618-ee3e-4831-8e21-5645b2cb"}
        H_OBFS_CONFIG=$(printf "obfs:\n  type: salamander\n  salamander:\n    password: %s" "$H_OBFS_PASSWORD"); log "混淆密码已设置" "$GREEN"
    else
        H_ENABLE_OBFS="false"; H_OBFS_CONFIG=""
    fi
    
    read -p "$(get_msg 'input_masquerade_url')" H_MASQUERADE_URL; H_MASQUERADE_URL=${H_MASQUERADE_URL:-"https://www.bing.com"}; log "伪装 URL: $H_MASQUERADE_URL" "$GREEN"
    
    H_SNIFFING_CONFIG=""; H_SNIFFING_TIMEOUT="2s" # 新增默认超时时间
    read -p "$(get_msg 'confirm_sniffing')" H_CONFIRM_SNIFFING; H_CONFIRM_SNIFFING=${H_CONFIRM_SNIFFING:-Y}
    if [[ "$H_CONFIRM_SNIFFING" =~ ^[yY]$ ]]; then
        # 修复后的 H_SNIFFING_CONFIG 变量，包含正确的缩进和 timeout 参数
        H_SNIFFING_CONFIG=$(cat <<EOF
sniff:
  enable: true
  timeout: ${H_SNIFFING_TIMEOUT}
EOF
)
        log "协议嗅探已开启 (超时: ${H_SNIFFING_TIMEOUT})" "$GREEN"
    fi
    
    read -p "$(get_msg 'confirm_outbound')" H_CONFIRM_OUTBOUND
    if [[ "$H_CONFIRM_OUTBOUND" =~ ^[yY]$ ]]; then
        read -p "$(get_msg 'input_outbound_addr')" H_OUTBOUND_ADDR; read -p "$(get_msg 'input_outbound_user')" H_OUTBOUND_USER
        read -s -p "$(get_msg 'input_outbound_pass')" H_OUTBOUND_PASS; echo
        local user_pass_config=""; [[ -n "$H_OUTBOUND_USER" && -n "$H_OUTBOUND_PASS" ]] && user_pass_config="username: $H_OUTBOUND_USER\n    password: $H_OUTBOUND_PASS"
        H_OUTBOUND_CONFIG=$(printf "outbounds:\n  - name: socks\n    type: socks5\n    socks5:\n    addr: %s\n    %s" "$H_OUTBOUND_ADDR" "$user_pass_config"); log "SOCKS5 出站代理已配置" "$GREEN"
    fi

    # --- 安装执行 ---
    download_and_install
    
    # 🚨 时序：在创建配置文件时，会检查 acme.sh 证书是否存在
    create_config_file
    
    create_systemd_service
    configure_firewall

    log "$(get_msg 'service_starting')" "$BLUE"; systemctl start "$SERVICE_NAME"
    log "$(get_msg 'service_check_wait')" "$YELLOW"; sleep 5

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        INSTALL_SUCCESS="true"
        log "$(get_msg 'install_complete')" "$GREEN"
        echo
        generate_client_config
    else
        log "$(get_msg 'err_service_start')" "$RED"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager | tee -a "$LOG_FILE"
        exit 1
    fi
}

# --- 卸载和管理菜单函数（保持不变） ---
uninstall_hysteria() {
    read -p "$(get_msg 'uninstall_confirm')" confirm; [[ ! "$confirm" =~ ^[yY]$ ]] && return
    read -p "$(get_msg 'uninstall_backup_confirm')" backup_confirm; backup_confirm=${backup_confirm:-Y}
    if [[ "$backup_confirm" =~ ^[yY]$ ]]; then
        mkdir -p "$BACKUP_DIR"
        local backup_file="$BACKUP_DIR/hysteria_config_backup_$(date +%Y%m%d_%H%M%S).yaml"
        cp "$CONFIG_FILE" "$backup_file" 2>/dev/null && log "$(get_msg 'backup_path' "$backup_file")" "$GREEN"
    fi
    systemctl stop "$SERVICE_NAME"; systemctl disable "$SERVICE_NAME"
    rm -f "$SYSTEMD_SERVICE" "$BINARY_PATH"; rm -rf "$CONFIG_DIR"; systemctl daemon-reload
    log "Hysteria2 服务已卸载。 / Hysteria2 has been uninstalled." "$GREEN"
}

manage_menu() {
    while true; do
        clear; echo -e "${BLUE}=====================================${NC}\n${GREEN} $(get_msg 'manage_menu_title') ${NC}\n${BLUE}=====================================${NC}"
        echo -e " ${YELLOW}1) $(get_msg 'manage_menu_status')${NC}\n ${YELLOW}2) $(get_msg 'manage_menu_log')${NC}\n ${YELLOW}3) $(get_msg 'manage_menu_restart')${NC}"
        echo -e " ${YELLOW}4) $(get_msg 'manage_menu_stop')${NC}\n ${YELLOW}5) $(get_msg 'manage_menu_start')${NC}\n ${YELLOW}6) $(get_msg 'manage_menu_config')${NC}\n ${YELLOW}7) $(get_msg 'manage_menu_exit')${NC}\n${BLUE}=====================================${NC}"
        read -p " 请输入选项 [1-7]: " choice
        case "$choice" 在
            1) systemctl status "$SERVICE_NAME" --no-pager ;;
            2) journalctl -u "$SERVICE_NAME" -f ;;
            3) systemctl restart "$SERVICE_NAME" && log "服务已重启" "$GREEN" ;;
            4) systemctl stop "$SERVICE_NAME" && log "服务已停止" "$GREEN" ;;
            5) systemctl start "$SERVICE_NAME" && log "服务已启动" "$GREEN" ;;
            6) 
            H_PORT=$(grep 'listen:' "$CONFIG_FILE" | awk -F ':' '{print $2}' | tr -d ' ')
            H_PASSWORD=$(grep -A 2 'auth:' "$CONFIG_FILE" | grep 'password:' | sed -E 's/^\s*password:\s*"?([^"]+)"?\s*$/\1/')
            if grep -q "acme:" "$CONFIG_FILE"; then H_DOMAIN=$(grep -A 2 'acme:' "$CONFIG_FILE" | grep 'domains:' | awk '{print $2}'); else H_DOMAIN=$(grep -A 2 'tls:' "$CONFIG_FILE" | grep 'cert:' | awk -F'/' '{print $5}'); fi
            if grep -q "obfs:" "$CONFIG_FILE"; then H_ENABLE_OBFS="true"; H_OBFS_PASSWORD=$(grep -A 3 'obfs:' "$CONFIG_FILE" | grep 'password:' | awk '{print $2}'); else H_ENABLE_OBFS="false"; fi
            if iptables -t nat -L PREROUTING -n | grep -q "REDIRECT.*to-ports $H_PORT"; 键，然后 H_ENABLE_PORT_HOP="true"; H_PORT_HOP_RANGE="N/A (已配置)"; else H_ENABLE_PORT_HOP="false"; fi
            H_MASQUERADE_URL=$(grep -A 3 'masquerade:' "$CONFIG_FILE" | grep 'url:' | awk '{print $2}')
            generate_client_config
            ;;
            7) break ;;
            *) echo -e "${RED}无效选项${NC}" ;;
        esac
        [ "$choice" != "2" ] && read -p "按回车键继续... / Press Enter to continue..."
    done
}

# --- 主函数 ---
main() {
    trap cleanup_exit EXIT
    check_root

    if [ -f "$BINARY_PATH" ]; then
        clear
        SCRIPT_LANG="zh" 
        
        echo -e "${GREEN}$(get_msg 'detect_existing')${NC}\n${YELLOW}---------------------------------${NC}"
        echo -e " 1) $(get_msg 'action_manage')${NC}\n 2) $(get_msg 'action_reinstall')${NC}\n 3) $(get_msg 'action_uninstall')${NC}\n 4) $(get_msg 'action_exit')${NC}"

        echo -e "${YELLOW}---------------------------------${NC}"
        
        read -p "$(get_msg 'input_prompt')" action
        case "$action" in 
            1) manage_menu;; 
            2) uninstall_hysteria; install_hysteria;; 
            3) uninstall_hysteria;; 
            4) exit 0;; 
            *) echo -e "${RED}无效选项${NC}"; exit 1;; 
        esac
    else
        select_language
        install_hysteria
    fi
}

main
