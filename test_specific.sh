#!/bin/bash

echo "=== Testing Enhanced ModSecurity Rules ==="

# Start the application in background
cd /home/godmode/ModSecPoc
dotnet run --urls="http://localhost:5000" > app.log 2>&1 &
APP_PID=$!
echo "Started application with PID: $APP_PID"

# Wait for application to start
sleep 4

echo ""
echo "Testing the 3 previously failing patterns:"
echo ""

echo "1. XSS in POST body (should return 403):"
RESPONSE1=$(curl -s -X POST "http://localhost:5000/test/xss" \
     -H "Content-Type: application/json" \
     -d '{"data":"<script>alert('\''XSS'\'')</script>"}' \
     -w "%{http_code}")
echo "Response: $RESPONSE1"
echo ""

echo "2. Directory Traversal in URL (should return 403):"
RESPONSE2=$(curl -s "http://localhost:5000/test/traversal?path=../../../etc/passwd" \
     -w "%{http_code}")
echo "Response: $RESPONSE2"
echo ""

echo "3. SQL Injection in URL (should return 403):"
RESPONSE3=$(curl -s "http://localhost:5000/test/traversal?path=' OR '1'='1" \
     -w "%{http_code}")
echo "Response: $RESPONSE3"
echo ""

echo "4. Testing normal request (should return 200):"
RESPONSE4=$(curl -s "http://localhost:5000/test/modsecurity" -w "%{http_code}")
echo "Response: $RESPONSE4"
echo ""

echo "Stopping application..."
kill $APP_PID
wait $APP_PID 2>/dev/null

echo ""
echo "=== RESULTS ==="
echo "XSS POST:      $(if [[ "$RESPONSE1" == *"403"* ]]; then echo "✓ BLOCKED (403)"; else echo "✗ NOT BLOCKED ($RESPONSE1)"; fi)"
echo "Dir Traversal: $(if [[ "$RESPONSE2" == *"403"* ]]; then echo "✓ BLOCKED (403)"; else echo "✗ NOT BLOCKED ($RESPONSE2)"; fi)"
echo "SQL URL:       $(if [[ "$RESPONSE3" == *"403"* ]]; then echo "✓ BLOCKED (403)"; else echo "✗ NOT BLOCKED ($RESPONSE3)"; fi)"
echo "Normal:        $(if [[ "$RESPONSE4" == *"200"* ]]; then echo "✓ ALLOWED (200)"; else echo "✗ UNEXPECTED ($RESPONSE4)"; fi)"