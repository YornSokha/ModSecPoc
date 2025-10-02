#!/bin/bash

# ModSecurity Integration Test Script
# This script tests various attack patterns to validate ModSecurity integration

BASE_URL="https://localhost:5001"
CURL_OPTS="-k -s -w \nHTTP_CODE:%{http_code}\n"

echo "ModSecurity Integration Test Suite"
echo "=================================="
echo ""

# Test 1: Normal request (should pass)
echo "Test 1: Normal request"
curl $CURL_OPTS "$BASE_URL/test/modsecurity"
echo ""

# Test 2: SQL Injection in POST data (should be blocked)
echo "Test 2: SQL Injection in POST data"
curl $CURL_OPTS -X POST "$BASE_URL/test/sqli" \
  -H "Content-Type: application/json" \
  -d '{"data": "1 OR 1=1 UNION SELECT * FROM users"}'
echo ""

# Test 3: XSS in POST data (should be blocked)
echo "Test 3: XSS in POST data"
curl $CURL_OPTS -X POST "$BASE_URL/test/xss" \
  -H "Content-Type: application/json" \
  -d '{"data": "<script>alert(\"XSS\")</script>"}'
echo ""

# Test 4: Directory traversal (should be blocked)
echo "Test 4: Directory traversal"
curl $CURL_OPTS "$BASE_URL/test/traversal?path=../../../etc/passwd"
echo ""

# Test 5: SQL Injection in URL parameter (should be blocked)
echo "Test 5: SQL Injection in URL parameter"
curl $CURL_OPTS "$BASE_URL/test/traversal?path='; DROP TABLE users; --"
echo ""

# Test 6: Suspicious User-Agent (should be blocked)
echo "Test 6: Suspicious User-Agent"
curl $CURL_OPTS -H "User-Agent: sqlmap/1.0" "$BASE_URL/test/modsecurity"
echo ""

# Test 7: Normal weather forecast (should pass)
echo "Test 7: Normal weather forecast endpoint"
curl $CURL_OPTS "$BASE_URL/weatherforecast"
echo ""

echo "Test suite completed."
echo ""
echo "Expected results:"
echo "- Tests 1 and 7 should return HTTP 200"
echo "- Tests 2-6 should be blocked (HTTP 403 or configured block status)"
echo ""
echo "Check ModSecurity logs for detailed information:"
echo "- Debug log: /tmp/modsec_debug.log" 
echo "- Audit log: /tmp/modsec_audit.log"