#!/bin/bash

echo "=== 检查网关服务启动日志 ==="

# 查找网关服务进程
GATEWAY_PID=$(ps aux | grep java | grep GatewayServerApplication | grep -v grep | awk '{print $2}')

if [ -z "$GATEWAY_PID" ]; then
    echo "❌ 未找到网关服务进程"
    exit 1
fi

echo "✅ 找到网关服务进程 PID: $GATEWAY_PID"

# 检查是否有TokenCheckFilter相关日志
echo ""
echo "=== 检查TokenCheckFilter日志 ==="

# 使用lsof查看进程打开的文件，找到日志文件
LOG_FILES=$(lsof -p $GATEWAY_PID 2>/dev/null | grep -E "\.log|\.out" | awk '{print $9}')

if [ -n "$LOG_FILES" ]; then
    echo "找到日志文件:"
    echo "$LOG_FILES"
    
    for log_file in $LOG_FILES; do
        if [ -f "$log_file" ]; then
            echo ""
            echo "=== 检查日志文件: $log_file ==="
            grep -i "TokenCheckFilter\|CONSTRUCTOR\|FILTER METHOD" "$log_file" | tail -10
        fi
    done
else
    echo "未找到日志文件，尝试从控制台输出获取信息..."
fi

echo ""
echo "=== 检查Spring Boot启动日志 ==="
# 尝试从进程的标准输出获取信息
echo "网关服务启动状态检查完成"
echo "如需查看详细日志，请手动检查启动控制台输出" 