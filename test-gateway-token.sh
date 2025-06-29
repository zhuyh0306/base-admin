#!/bin/bash

# 网关JWT校验自动化测试脚本
echo "=== 网关JWT校验自动化测试 ==="

# 配置
GATEWAY_URL="http://localhost:8081"
AUTH_SERVER_URL="http://localhost:9999"
CLIENT_ID="coin-api"
CLIENT_SECRET="coin-secret"
USERNAME="admin"
PASSWORD="123456"

echo "1. 获取JWT Token..."
TOKEN_RESPONSE=$(curl -s -X POST "$AUTH_SERVER_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n $CLIENT_ID:$CLIENT_SECRET | base64)" \
  -d "grant_type=password&username=$USERNAME&password=$PASSWORD")

echo "Token响应: $TOKEN_RESPONSE"

# 提取access_token
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "❌ 获取Token失败"
    exit 1
fi

echo "✅ 获取Token成功: ${ACCESS_TOKEN:0:50}..."

echo ""
echo "2. 测试受保护接口（带Token）..."
PROTECTED_RESPONSE=$(curl -s -w "\nHTTP状态码: %{http_code}" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$GATEWAY_URL/test/protected")

echo "受保护接口响应: $PROTECTED_RESPONSE"

echo ""
echo "3. 测试受保护接口（不带Token）..."
UNAUTHORIZED_RESPONSE=$(curl -s -w "\nHTTP状态码: %{http_code}" \
  "$GATEWAY_URL/test/protected")

echo "未授权响应: $UNAUTHORIZED_RESPONSE"

echo ""
echo "4. 测试白名单接口（不需要Token）..."
PUBLIC_RESPONSE=$(curl -s -w "\nHTTP状态码: %{http_code}" \
  "$GATEWAY_URL/test/public")

echo "白名单接口响应: $PUBLIC_RESPONSE"

echo ""
echo "5. 测试无效Token..."
INVALID_RESPONSE=$(curl -s -w "\nHTTP状态码: %{http_code}" \
  -H "Authorization: Bearer invalid_token_123" \
  "$GATEWAY_URL/test/protected")

echo "无效Token响应: $INVALID_RESPONSE"

echo ""
echo "=== 测试完成 ==="
echo "请检查上述响应，确认："
echo "1. 带有效Token的请求返回200"
echo "2. 不带Token的请求返回401"
echo "3. 白名单接口直接通过"
echo "4. 无效Token返回401" 