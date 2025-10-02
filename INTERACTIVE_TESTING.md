# ModSecurity Interactive Test Controller API

## 🎯 **Interactive Test Suite**

Your new `InteractiveTestController` provides comprehensive endpoints for testing custom ModSecurity inputs.

### **Available Endpoints:**

#### **1. Custom POST Data Test**
```http
POST /api/InteractiveTest/custom-post
Content-Type: application/json

{
    "data": "your test payload here"
}
```
**Use Case:** Test any POST data for XSS, SQL injection, etc.

#### **2. Custom GET Parameters Test**  
```http
GET /api/InteractiveTest/custom-get?input=value&param1=value&param2=value
```
**Use Case:** Test directory traversal, SQL injection in URL parameters

#### **3. Custom Headers Test**
```http
POST /api/InteractiveTest/custom-headers
User-Agent: your-custom-agent
X-Custom-Test: your-header-value
Content-Type: application/json

{
    "data": "payload"
}
```
**Use Case:** Test suspicious User-Agents and custom headers

#### **4. Advanced Multi-Vector Test**
```http
POST /api/InteractiveTest/advanced-test
Content-Type: application/json

{
    "sqlData": "' OR '1'='1",
    "xssData": "<script>alert('test')</script>",
    "traversalPath": "../../../etc/passwd", 
    "customField": "additional test data"
}
```
**Use Case:** Test multiple attack vectors simultaneously

#### **5. File Upload Test**
```http
POST /api/InteractiveTest/custom-upload
Content-Type: multipart/form-data

file: [binary file data]
description: "file description"
```
**Use Case:** Test file upload security

#### **6. Raw Request Test**
```http
GET|POST|PUT|DELETE /api/InteractiveTest/raw
```
**Use Case:** Send any raw HTTP request and see the complete processing

#### **7. Attack Pattern Suggestions**
```http
GET /api/InteractiveTest/suggestions/{attackType}
```
**Attack Types:** `xss`, `sqli`, `traversal`, `useragent`

**Use Case:** Get example payloads for different attack types

---

## **🌐 Web Interface**

Access the interactive web interface at:
```
http://localhost:5000/interactive-test.html
```

### **Features:**
- ✅ **Visual Form Interface** - Easy input forms for all test types  
- ✅ **Real-time Results** - See ModSecurity responses immediately
- ✅ **Color-coded Status** - Green for allowed, Red for blocked
- ✅ **Attack Suggestions** - Get example payloads for testing
- ✅ **Quick Test Buttons** - One-click common attack tests
- ✅ **Example Data Fillers** - Auto-fill forms with test data

---

## **🚀 How to Use**

### **Method 1: Web Interface (Recommended)**
1. Start your application: `dotnet run`
2. Open browser: `http://localhost:5000/interactive-test.html`  
3. Fill in test data and click test buttons
4. See results in real-time with color coding

### **Method 2: API Calls**
```bash
# Test XSS in POST
curl -X POST http://localhost:5000/api/InteractiveTest/custom-post \
  -H "Content-Type: application/json" \
  -d '{"data": "<script>alert('\'XSS\'')</script>"}'

# Test SQL injection in GET  
curl "http://localhost:5000/api/InteractiveTest/custom-get?input=' OR '1'='1"

# Test directory traversal
curl "http://localhost:5000/api/InteractiveTest/custom-get?input=../../../etc/passwd"

# Test suspicious User-Agent
curl -X POST http://localhost:5000/api/InteractiveTest/custom-headers \
  -H "User-Agent: sqlmap/1.0" \
  -H "Content-Type: application/json" \
  -d '{"data": "test"}'
```

### **Method 3: Using the Original Test Suite**
```bash
# Run comprehensive test suite
curl http://localhost:5000/api/ModSecurityTest/suite
```

---

## **🛡️ Expected Responses**

### **✅ Allowed Request (Status 200)**
```json
{
  "message": "Request processed successfully",
  "received": "normal data",
  "timestamp": "2025-10-02T...",
  "method": "POST"
}
```

### **🚫 Blocked Request (Status 403)**  
```
[client ::1] ModSecurity: Access denied with code 403 (phase 2). 
Matched "Operator `Rx' with parameter `(?i:(<script|javascript:...` 
against variable `REQUEST_BODY` (Value: `{"data":"<script>alert('XSS')</script>"}`) 
[file "./modsecurity/modsecurity.conf"] [line "55"] [id "1002"] 
[msg "XSS Attack Detected"] [tag "attack-xss"]
```

---

## **🎨 Testing Scenarios**

### **XSS Tests:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert(1)>`  
- `javascript:alert('test')`
- `<svg onload=alert(1)>`

### **SQL Injection Tests:**
- `' OR '1'='1`
- `'; DROP TABLE users; --`
- `1' UNION SELECT * FROM users--`

### **Directory Traversal Tests:**
- `../../../etc/passwd`
- `..\\..\\..\\windows\\system32\\drivers\\etc\\hosts`
- `....//....//....//etc/passwd`

### **User-Agent Tests:**
- `sqlmap/1.0`
- `nikto/2.1.6`  
- `nmap scripting engine`

---

Your interactive test suite is now ready! 🎉