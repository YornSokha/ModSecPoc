# ModSecurity Integration for ASP.NET Core

This project demonstrates how to integrate ModSecurity (libmodsecurity.so) with an ASP.NET Core application using P/Invoke.

## Prerequisites

Before running this application, you need to install ModSecurity on your system:

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install libmodsecurity3 libmodsecurity-dev
```

         "./modsecurity/crs-setup.conf"
```bash
      "RulesDirectory": "./modsecurity/rules",
      "AutoLoadCrs": true,
sudo yum install libmodsecurity libmodsecurity-devel
# or for newer versions:
sudo dnf install libmodsecurity libmodsecurity-devel
```

### Building from Source
If packages aren't available for your distribution:
```bash
git clone https://github.com/SpiderLabs/ModSecurity.git
cd ModSecurity
git checkout v3/master
./build.sh
./configure
make
sudo make install
```

## Configuration

The ModSecurity configuration is located in `appsettings.json`:

```json
{
  "ModSecurity": {
    "Enabled": true,
    "RulesFile": "./modsecurity/modsecurity.conf",
    "AdditionalRulesFiles": [
      "./modsecurity/crs-setup.conf"
    ],
      "RulesDirectory": "./modsecurity/rules",
      "AutoLoadCrs": true,
      "ParanoiaLevel": 0,
    "LogLevel": "Info",
    "EnforceMode": false,
    "BlockStatusCode": 403,
    "BlockMessage": "Access Denied by ModSecurity",
    "MaxRequestBodySize": 1048576,
    "MaxResponseBodySize": 1048576
  }
}
```

### Configuration Options

- **Enabled**: Enable/disable ModSecurity processing
- **RulesFile**: Path to the main ModSecurity rules file
- **AdditionalRulesFiles**: Array of additional rule files to load
- **RulesDirectory**: Directory scanned for CRS .conf files when AutoLoadCrs is true
- **AutoLoadCrs**: Automatically load OWASP CRS rule files in the correct order
- **ParanoiaLevel**: Override CRS paranoia/detection level (0 = do not override)
- **EnsureCrsSetupVersion**: Injects crs_setup_version variable if missing to suppress rule 901001 warning
- **Inbound/Outbound/TotalAnomalyScoreThreshold**: Optional overrides for CRS anomaly scoring thresholds

### Rule 901001: "CRS is deployed without configuration"

If you see a message like:

```
ModSecurity: Access denied ... [id "901001"] [msg "CRS is deployed without configuration! ..."]
```

It means `tx.crs_setup_version` was not set. This usually happens if `crs-setup.conf` (or `crs-setup.conf.example` copied to `crs-setup.conf`) is missing or stripped down. The integration will automatically inject a `SecAction` (id 900000) when `EnsureCrsSetupVersion` is true and the variable isn't found. To fix manually:

1. Copy the example file provided by CRS:
   ```bash
   cp crs-setup.conf.example crs-setup.conf
   ```
2. Ensure it contains a line setting `tx.crs_setup_version` (usually done in CRS releases):
   ```
   SecAction "id:900000, phase:1, nolog, pass, t:none, setvar:tx.crs_setup_version=1"
   ```
3. Or rely on the auto-injection by leaving `EnsureCrsSetupVersion` true.

### Adjusting Paranoia and Thresholds

Set `ParanoiaLevel` (1-4). Higher levels add more restrictive rules (and potential false positives). You can also fine-tune anomaly thresholds via the optional fields. Leaving them null keeps CRS defaults from your `crs-setup.conf`.

### Disabling Automatic CRS Loading

Set `AutoLoadCrs` to false and manage rule inclusion manually via `RulesFile` and `AdditionalRulesFiles`.
- **RulesDirectory**: Directory to scan for CRS rule .conf files (default `./modsecurity/rules`)
- **AutoLoadCrs**: If true, automatically loads `crs-setup.conf` then all rule files in `RulesDirectory` in deterministic order
- **LogLevel**: ModSecurity logging level (0-7)
- **EnforceMode**: `true` to block requests, `false` to only log
- **BlockStatusCode**: HTTP status code to return when blocking
- **BlockMessage**: Message to return when blocking requests
- **MaxRequestBodySize**: Maximum request body size to inspect (bytes)
- **MaxResponseBodySize**: Maximum response body size to inspect (bytes)

## Rules Configuration

ModSecurity rules are located in the `modsecurity/` directory:

- `modsecurity.conf`: Main configuration and basic rules
- `crs-setup.conf`: OWASP Core Rule Set setup configuration

You can add OWASP Core Rule Set (CRS) rules for comprehensive protection. Place the CRS rule `.conf` files inside `modsecurity/rules` and optionally the `crs-setup.conf` in `modsecurity/` or the same directory. With `AutoLoadCrs` enabled (default) they will be loaded automatically in this order:

1. `modsecurity.conf` (primary rules file)
2. Any explicitly listed `AdditionalRulesFiles` (e.g., `crs-setup.conf`)
3. `crs-setup.conf` discovered in the rules directory (if not already loaded)
4. All `REQUEST-*.conf` files (sorted alphabetically)
5. All `RESPONSE-*.conf` files (sorted alphabetically)
6. Any other `*.conf` files in the rules directory (sorted alphabetically)

Disable this behavior by setting `"AutoLoadCrs": false` or override the directory using `RulesDirectory`.

```bash
# Download OWASP CRS
cd modsecurity
wget https://github.com/coreruleset/coreruleset/archive/v3.3.4.tar.gz
tar -xzf v3.3.4.tar.gz
mv coreruleset-3.3.4/rules ./
```

## Running the Application

1. **Restore packages**:
   ```bash
   dotnet restore
   ```

2. **Build the application**:
   ```bash
   dotnet build
   ```

3. **Run the application**:
   ```bash
   dotnet run
   ```

The application will start on `https://localhost:5001` and `http://localhost:5000`.

## Testing ModSecurity Integration

### Using the Test Script

Run the provided test script to validate ModSecurity functionality:

```bash
./test_modsecurity.sh
```

### Manual Testing

Test various attack patterns:

1. **Normal request** (should pass):
   ```bash
   curl -k "https://localhost:5001/test/modsecurity"
   ```

2. **SQL Injection** (should be blocked):
   ```bash
   curl -k -X POST "https://localhost:5001/test/sqli" \
     -H "Content-Type: application/json" \
     -d '{"data": "1 OR 1=1 UNION SELECT * FROM users"}'
   ```

3. **XSS Attack** (should be blocked):
   ```bash
   curl -k -X POST "https://localhost:5001/test/xss" \
     -H "Content-Type: application/json" \
     -d '{"data": "<script>alert(\"XSS\")</script>"}'
   ```

4. **Directory Traversal** (should be blocked):
   ```bash
   curl -k "https://localhost:5001/test/traversal?path=../../../etc/passwd"
   ```

## API Endpoints

### Test Endpoints

- `GET /test/modsecurity` - Basic test endpoint
- `POST /test/sqli` - SQL injection test endpoint
- `POST /test/xss` - XSS test endpoint  
- `GET /test/traversal` - Directory traversal test endpoint

### Application Endpoints

- `GET /weatherforecast` - Sample weather forecast API
- `GET /swagger` - Swagger UI (in development mode)

## Monitoring and Logs

ModSecurity logs are written to:
- **Debug log**: `/tmp/modsec_debug.log`
- **Audit log**: `/tmp/modsec_audit.log`

Application logs include ModSecurity events and can be viewed in the console or configured log destinations.

## Architecture

The integration consists of several components:

1. **Native Layer** (`ModSecurity/Native/`):
   - P/Invoke declarations for libmodsecurity.so
   - Native structure definitions

2. **Wrapper Classes** (`ModSecurity/`):
   - `ModSecurityEngine`: Main engine wrapper
   - `ModSecurityRuleSet`: Rules management
   - `ModSecurityTransaction`: Request/response processing

3. **Middleware** (`ModSecurity/Middleware/`):
   - ASP.NET Core middleware for request interception
   - Request/response processing pipeline

4. **Configuration** (`ModSecurity/Configuration/`):
   - Configuration options and binding
   - Service registration extensions

## Deployment Considerations

### Production Deployment

1. **Enable Enforce Mode**:
   ```json
   "EnforceMode": true
   ```

2. **Tune Rule Set**:
   - Use OWASP CRS for comprehensive protection
   - Configure paranoia levels appropriately
   - Test thoroughly before enabling blocking

3. **Performance**:
   - Monitor request processing overhead
   - Adjust body size limits as needed
   - Consider rule optimization

4. **Logging**:
   - Configure appropriate log retention
   - Set up log monitoring and alerting
   - Reduce debug logging in production

### Security Considerations

- Regularly update ModSecurity and rule sets
- Monitor false positives and tune rules accordingly
- Implement proper log analysis and alerting
- Consider rate limiting and DDoS protection
- Ensure ModSecurity library is properly secured

## Troubleshooting

### Common Issues

1. **Library Not Found**:
   ```
   DllNotFoundException: Unable to load DLL 'libmodsecurity.so'
   ```
   - Ensure ModSecurity is installed
   - Check library path in system
   - Verify library compatibility

2. **Rules File Not Found**:
   ```
   FileNotFoundException: Rules file not found
   ```
   - Verify rules file path in configuration
   - Ensure file permissions are correct

3. **Memory Issues**:
   - Monitor memory usage with large rule sets
   - Adjust body size limits
   - Consider rule optimization

### Debug Mode

Enable detailed logging by setting `LogLevel` to `Debug` (7) in configuration and check debug logs for detailed information.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [ModSecurity Documentation](https://github.com/SpiderLabs/ModSecurity/wiki)
- [OWASP Core Rule Set](https://coreruleset.org/)
- [ASP.NET Core Middleware](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/middleware/)
- [P/Invoke Documentation](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)