#!/bin/bash

cd /home/godmode/ModSecPoc
echo "Starting app and running full test suite..."

# Start the application in background
dotnet run --urls="http://localhost:5000" > app.log 2>&1 &
APP_PID=$!

# Wait for startup
sleep 4

echo "Running full test suite..."
RESULT=$(curl -s "http://localhost:5000/api/ModSecurityTest/suite")

echo "Stopping application..."
kill $APP_PID
wait $APP_PID 2>/dev/null

echo ""
echo "=== FULL TEST SUITE RESULTS ==="
echo "$RESULT"