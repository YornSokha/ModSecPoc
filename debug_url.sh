#!/bin/bash

cd /home/godmode/ModSecPoc
echo "=== Testing URL Parameter Detection ==="

# Start the application in background
dotnet run --urls="http://localhost:5000" > app.log 2>&1 &
APP_PID=$!

# Wait for startup
sleep 4

echo "Testing specific patterns..."
echo ""

echo "1. Testing directory traversal pattern directly:"
curl -v "http://localhost:5000/test/traversal?path=../../../etc/passwd" 2>&1 | grep -E "(HTTP|path=)"
echo ""

echo "2. Testing SQL injection pattern directly:"
curl -v "http://localhost:5000/test/traversal?path=' OR '1'='1" 2>&1 | grep -E "(HTTP|path=)"
echo ""

echo "3. Testing simpler traversal:"
curl -v "http://localhost:5000/test/traversal?path=../" 2>&1 | grep -E "(HTTP|path=)"
echo ""

echo "4. Checking app logs for ModSecurity debug info..."
echo "Last few log entries:"
tail -20 app.log

kill $APP_PID
wait $APP_PID 2>/dev/null