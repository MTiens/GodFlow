# Burp Suite Integration Guide

This proxy can be used as an upstream proxy for Burp Suite to capture and store all unique requests.

## Setup Options

### Option 1: Simple Proxy → Burp → Target
Use this proxy to capture requests before they go to Burp Suite.

```
Client → Simple Proxy (Port 8080) → Burp Suite (Port 8081) → Target Server
```

**Configuration:**
1. Start Burp Suite on port 8081
2. Start this proxy pointing to Burp:
   ```bash
   python simple_proxy.py --proxy-port 8080 --target-host 127.0.0.1 --target-port 8081
   ```
3. Configure your client to use `127.0.0.1:8080` as proxy

### Option 2: Burp → Simple Proxy → Target
Use this proxy to capture requests after they go through Burp Suite.

```
Client → Burp Suite (Port 8080) → Simple Proxy (Port 8081) → Target Server
```

**Configuration:**
1. Start this proxy on port 8081 pointing to target:
   ```bash
   python simple_proxy.py --proxy-port 8081 --target-host target-server.com --target-port 80
   ```
2. Configure Burp Suite to use `127.0.0.1:8081` as upstream proxy
3. Configure your client to use `127.0.0.1:8080` as proxy

## Burp Suite Configuration

### Setting Upstream Proxy
1. Open Burp Suite
2. Go to **Proxy** → **Options**
3. Under **Upstream Proxy Servers**, click **Add**
4. Enter:
   - **Destination host**: `127.0.0.1`
   - **Port**: `8081` (or your proxy port)
   - **Protocol**: HTTP

### Setting Proxy Listener
1. In **Proxy** → **Options**
2. Under **Proxy Listeners**, ensure you have:
   - **Bind to address**: `127.0.0.1`
   - **Port**: `8080` (or your chosen port)
   - **Running**: ✓

## Example Commands

### Capture requests going TO Burp:
```bash
# Start Burp on port 8081, then:
python simple_proxy.py --proxy-port 8080 --target-host 127.0.0.1 --target-port 8081 --storage requests_to_burp.json
```

### Capture requests going FROM Burp:
```bash
# Start this proxy on port 8081, then configure Burp to use it as upstream:
python simple_proxy.py --proxy-port 8081 --target-host api.example.com --target-port 443 --ssl --storage requests_from_burp.json
```

### With SSL/TLS:
```bash
python simple_proxy.py --ssl --generate-cert --proxy-port 8080 --target-host 127.0.0.1 --target-port 8081
```

## Benefits

- **Dual Capture**: Capture requests both before and after Burp processing
- **Permanent Storage**: All unique requests saved to JSON files
- **Burp Features**: Still get all Burp's analysis, scanning, and manipulation features
- **Request Deduplication**: Avoid storing duplicate requests
- **Easy Analysis**: JSON format makes it easy to analyze captured data

## Use Cases

1. **Security Testing**: Capture all requests during penetration testing
2. **API Documentation**: Automatically document all API calls
3. **Traffic Analysis**: Analyze application behavior and data flow
4. **Compliance**: Keep records of all requests for audit purposes
5. **Debugging**: Track down issues by examining all network traffic

## Notes

- The proxy preserves all headers and request bodies
- Response data is also captured (truncated to 1000 chars)
- Timestamps are included for each captured request
- Works with both HTTP and HTTPS traffic
