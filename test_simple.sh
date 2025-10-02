#!/bin/bash

cd /home/godmode/ModSecPoc

echo "=== Testing Simple Double-Dot Rule ==="
dotnet run --urls="http://localhost:5000" > app.log 2>&1 &
APP_PID=$!

sleep 4

echo "Testing with simple .. pattern:"
RESULT=$(curl -s "http://localhost:5000/test/traversal?path=.." -w "%{http_code}")
echo "Response: $RESULT"

echo ""
echo "Testing with .. pattern in path:"  
RESULT2=$(curl -s "http://localhost:5000/test/traversal?path=../etc" -w "%{http_code}")
echo "Response: $RESULT2"

kill $APP_PID
wait $APP_PID 2>/dev/null

echo ""
echo "Checking logs for our test rule:"
grep "Test Rule" app.log || echo "No test rule matches found"