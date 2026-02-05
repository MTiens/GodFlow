# Simple HTTP/HTTPS Proxy Server

A simple proxy server that captures and stores unique requests from target servers.

## Features

- HTTP and HTTPS support
- SSL certificate handling (self-signed or custom)
- Request capture and storage
- Unique request deduplication
- Configurable target server
- JSON storage format

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic HTTP Proxy
```bash
python simple_proxy.py --target-host example.com --target-port 80
```

### HTTPS Proxy with Self-Signed Certificate
```bash
python simple_proxy.py --ssl --generate-cert --target-host example.com --target-port 443
```

### Custom SSL Certificate
```bash
python simple_proxy.py --ssl --cert mycert.crt --key mykey.key --target-host example.com --target-port 443
```

### Custom Port and Storage
```bash
python simple_proxy.py --proxy-port 9090 --storage my_requests.json --target-host example.com --target-port 80
```

## Command Line Options

- `--proxy-host`: Proxy server host (default: 0.0.0.0)
- `--proxy-port`: Proxy server port (default: 8080)
- `--target-host`: Target server host (default: localhost)
- `--target-port`: Target server port (default: 80)
- `--ssl`: Enable SSL/HTTPS
- `--cert`: SSL certificate file
- `--key`: SSL private key file
- `--storage`: Storage file for captured requests (default: captured_requests.json)
- `--generate-cert`: Generate self-signed certificate

## Examples

### Capture requests from a local web server
```bash
python simple_proxy.py --target-host 127.0.0.1 --target-port 3000
```

### Capture HTTPS requests with custom port
```bash
python simple_proxy.py --ssl --generate-cert --proxy-port 8443 --target-host api.example.com --target-port 443
```

## Output

Captured requests are stored in JSON format with the following structure:

```json
{
  "request_hash": {
    "timestamp": "2024-01-01T12:00:00",
    "method": "GET",
    "url": "/api/users",
    "headers": {...},
    "body": "",
    "response_code": 200,
    "response_headers": {...},
    "response_body": "..."
  }
}
```

## Notes

- The proxy forwards all HTTP methods (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)
- Requests are deduplicated based on method, URL, headers, and body content
- Response bodies are truncated to 1000 characters to prevent large storage files
- The server runs in multi-threaded mode to handle concurrent requests
