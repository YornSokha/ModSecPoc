#!/bin/bash

echo "Testing enhanced ModSecurity rules..."

# Start the application in background
cd /home/godmode/ModSecPoc
dotnet run --urls="http://localhost:5000" > /dev/null 2>&1 &
APP_PID=$!
echo "Started application with PID: $APP_PID"

# Wait for application to start
sleep 3

echo "Testing the 3 previously failing patterns..."

echo "1. Testing XSS in POST body..."
curl -s -X POST "http://localhost:5000/api/test/xss-post" \
     -H "Content-Type: application/json" \
     -d '{"input":"<script>alert('\''XSS'\'')</script>"}' \
     -w "Status: %{http_code}\n"

echo "2. Testing Directory Traversal in URL..."
curl -s "http://localhost:5000/api/test/directory-traversal?file=../../../etc/passwd" \
     -w "Status: %{http_code}\n"

echo "3. Testing SQL Injection in URL..."
curl -s "http://localhost:5000/api/test/sql-injection-url?id=' OR '1'='1" \
     -w "Status: %{http_code}\n"

echo "Stopping application..."
kill $APP_PID
wait $APP_PID 2>/dev/null

echo "Test completed!"