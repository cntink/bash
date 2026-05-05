#!/bin/bash

# ====================================================
# Hysteria 2 自动化升级脚本 V2 (防断连/热替换版)
# ====================================================

if [ "$EUID" -ne 0 ]; then
  echo "❌ 请使用 root 权限运行此脚本"
  exit 1
fi

echo "=========================================="
echo "    Hysteria 2 自动化升级脚本 (热替换模式)    "
echo "=========================================="

# 1. 自动检测服务名称
SERVICE_NAME=$(systemctl list-units --type=service --state=running | grep -ioE 'hysteria[-a-z0-9]*\.service' | head -n 1)
if [ -z "$SERVICE_NAME" ]; then
    SERVICE_NAME="hysteria-server.service"
fi
echo "✅ 检测到服务名称: $SERVICE_NAME"

# 2. 提取执行路径
EXEC_START_LINE=$(systemctl cat "$SERVICE_NAME" | grep "^ExecStart=" | head -n 1)
BIN_PATH=$(echo "$EXEC_START_LINE" | awk -F'=' '{print $2}' | awk '{print $1}')
if [ -z "$BIN_PATH" ] || [ ! -f "$BIN_PATH" ]; then
    BIN_PATH=$(command -v hysteria)
fi
if [ -z "$BIN_PATH" ] || [ ! -f "$BIN_PATH" ]; then
    echo "❌ 无法定位 hysteria 路径。升级中止。"
    exit 1
fi

# 3. 备份配置文件
CONFIG_PATH=$(echo "$EXEC_START_LINE" | grep -oE '(-c|--config)\s+[^ ]+' | awk '{print $2}' | sed "s/['\"]//g")
if [ -z "$CONFIG_PATH" ]; then
    [ -f "/etc/hysteria/config.yaml" ] && CONFIG_PATH="/etc/hysteria/config.yaml"
fi
if [ -n "$CONFIG_PATH" ] && [ -f "$CONFIG_PATH" ]; then
    BACKUP_FILE="${CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$CONFIG_PATH" "$BACKUP_FILE"
    echo "📦 配置文件备份至: $BACKUP_FILE"
fi

# 4. 获取版本信息
CURRENT_VERSION=$("$BIN_PATH" version 2>/dev/null | grep -ioE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
LATEST_VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

echo "当前本地版本: ${CURRENT_VERSION:-未知}"
echo "发现最新版本: $LATEST_VERSION"

if [ -z "$LATEST_VERSION" ]; then
    echo "❌ 获取最新版本失败，网络异常。"
    exit 1
fi

if [ "$CURRENT_VERSION" == "$LATEST_VERSION" ]; then
    echo "✅ 当前已是最新版本，无需升级。"
    exit 0
fi

# 5. 匹配架构
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) HY_ARCH="amd64" ;;
    aarch64) HY_ARCH="arm64" ;;
    armv7l) HY_ARCH="arm" ;;
    *) echo "❌ 不支持的架构: $ARCH"; exit 1 ;;
esac
DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${LATEST_VERSION}/hysteria-linux-${HY_ARCH}"

# ================= 核心防断连改造部分 =================

# 6. 先在服务运行状态下下载核心文件 (避免断网)
TMP_BIN_PATH="/tmp/hysteria_new_core"
echo "⬇️  正在后台静默下载最新版核心 (保持当前网络畅通)..."
curl -L -o "$TMP_BIN_PATH" "$DOWNLOAD_URL"

if [ $? -ne 0 ] || [ ! -s "$TMP_BIN_PATH" ]; then
    echo "❌ 下载失败或文件不完整！原服务仍在正常运行，升级终止。"
    rm -f "$TMP_BIN_PATH"
    exit 1
fi
echo "✅ 最新核心下载完成，准备进行毫秒级热替换。"

# 7. 屏蔽 SIGHUP 信号，防止 SSH 断开导致脚本死亡
trap '' HUP

# 8. 连续执行停止、覆盖、启动 (确保在极短时间内完成)
echo "🛑 正在执行原子级替换与重启..."
# 使用连锁命令，任何一步失败都不会卡死
systemctl stop "$SERVICE_NAME" ; \
mv -f "$TMP_BIN_PATH" "$BIN_PATH" ; \
chmod +x "$BIN_PATH" ; \
systemctl daemon-reload ; \
systemctl start "$SERVICE_NAME"

# 恢复默认的信号处理
trap - HUP

# ====================================================

# 9. 状态检查
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "=========================================="
    echo "🎉 升级成功且服务已恢复！"
    echo "当前版本:"
    "$BIN_PATH" version
    echo "=========================================="
else
    echo "=========================================="
    echo "❌ 警告：服务启动异常！"
    echo "请使用 sudo journalctl -u $SERVICE_NAME -n 50 查看日志"
    echo "=========================================="
fi
