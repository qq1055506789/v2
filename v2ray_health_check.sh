#!/bin/bash
LOG="/var/log/v2ray/health.log"
check_service() {
    local service=$1
    systemctl is-active --quiet $service || {
        echo "[$(date)] $service 未运行，尝试重启" >> $LOG
        systemctl restart $service
    }
}
check_service xray
check_service nginx
check_service redis
curl -s http://127.0.0.1:8080 >/dev/null || {
    echo "[$(date)] Web 面板不可用，尝试重启" >> $LOG
    systemctl restart v2ray-panel
}
curl -s http://127.0.0.1:10085/stats >/dev/null || {
    echo "[$(date)] Xray API 不可用，尝试重启 xray" >> $LOG
    systemctl restart xray
}
