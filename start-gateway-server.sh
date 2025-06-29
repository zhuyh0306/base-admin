#!/bin/bash

# 一键启动 gateway-server 脚本
PORT=8081
MODULE_DIR="base-iaas/gateway-server"

# 检查端口是否被占用
PID=$(lsof -ti :$PORT)
if [ -n "$PID" ]; then
  echo "端口 $PORT 被进程 $PID 占用，自动释放..."
  kill -9 $PID
  sleep 2
else
  echo "端口 $PORT 未被占用。"
fi

# 启动服务
cd $MODULE_DIR || { echo "找不到目录 $MODULE_DIR"; exit 1; }
echo "启动 gateway-server..."
mvn spring-boot:run 