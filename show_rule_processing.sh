#!/bin/bash

echo "🔍 ModSecurity Rule Processing Flow Demonstration"
echo "================================================"

cd /home/godmode/ModSecPoc
dotnet run --urls="http://localhost:5000" > app.log 2>&1 &
APP_PID=$!

sleep 4

echo ""
echo "Testing Phase 1 Rule Processing (REQUEST_URI):"
echo "----------------------------------------------"
echo "Sending: GET /test/traversal?path=../../../etc/passwd"

curl -v "http://localhost:5000/test/traversal?path=../../../etc/passwd" 2>&1 | \
    grep -E "(GET /test|HTTP/1.1|ModSecurity)"

echo ""
echo ""
echo "Testing Phase 2 Rule Processing (REQUEST_BODY):"
echo "-----------------------------------------------"
echo "Sending: POST with XSS payload in body"

curl -v -X POST "http://localhost:5000/test/xss" \
     -H "Content-Type: application/json" \
     -d '{"data":"<script>alert(\"XSS\")</script>"}' 2>&1 | \
    grep -E "(POST /test|HTTP/1.1|ModSecurity)"

echo ""
echo ""
echo "📋 Rule Processing Summary from logs:"
echo "------------------------------------"
grep -E "(Processing URI|Intervention after|Blocking request)" app.log | tail -10

kill $APP_PID
wait $APP_PID 2>/dev/null

echo ""
echo "🎯 Rule Processing Locations Summary:"
echo "======================================"
echo "Phase 1 (Headers): msc_process_request_headers() → Rules 1003,1004,1006"
echo "Phase 2 (Body):    msc_process_request_body()    → Rules 1001,1002,1005"
echo "Intervention:      msc_intervention()            → Check if rules triggered"