#!/usr/bin/env python3
"""
Simple HTTP/HTTPS Proxy Server
Captures and stores unique requests from target
"""

import socket
import threading
import ssl
import json
import hashlib
import os
import argparse
from datetime import datetime
from urllib.parse import urlparse
import http.server
import socketserver
from http.server import BaseHTTPRequestHandler
import requests

class RequestCapture:
    def __init__(self, storage_file="captured_requests.json"):
        self.storage_file = storage_file
        self.requests = self.load_requests()
        self.lock = threading.Lock()
    
    def load_requests(self):
        """Load existing requests from storage file"""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_requests(self):
        """Save requests to storage file"""
        with self.lock:
            with open(self.storage_file, 'w') as f:
                json.dump(self.requests, f, indent=2)
    
    def add_request(self, method, url, headers, body, response_code=None, response_headers=None, response_body=None):
        """Add a unique request to storage"""
        # Create unique identifier based on method, URL, headers, and body
        request_data = f"{method}|{url}|{json.dumps(headers, sort_keys=True)}|{body}"
        request_hash = hashlib.md5(request_data.encode()).hexdigest()
        
        with self.lock:
            if request_hash not in self.requests:
                self.requests[request_hash] = {
                    'timestamp': datetime.now().isoformat(),
                    'method': method,
                    'url': url,
                    'headers': headers,
                    'body': body,
                    'response_code': response_code,
                    'response_headers': response_headers,
                    'response_body': response_body
                }
                self.save_requests()
                print(f"[CAPTURED] {method} {url}")
                return True
        return False

class ProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, capture=None, **kwargs):
        self.capture = capture
        super().__init__(*args, **kwargs)
    
    def __getattr__(self, name):
        """Handle any HTTP method dynamically"""
        if name.startswith('do_'):
            return lambda: self.handle_request()
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
    
    def handle_request(self):
        """Handle all HTTP methods"""
        try:
            # Get request details
            method = self.command
            url = self.path
            headers = dict(self.headers)
            
            # Read request body
            content_length = int(headers.get('Content-Length', 0))
            body = ""
            if content_length > 0:
                body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            
            # Forward request to target (or upstream proxy like Burp)
            target_url = f"http://{self.server.target_host}:{self.server.target_port}{url}"
            
            try:
                # Prepare headers for forwarding
                forward_headers = {k: v for k, v in headers.items() if k.lower() not in ['host', 'connection']}
                
                # Make the request using the general requests.request method
                response = requests.request(
                    method=method,
                    url=target_url,
                    headers=forward_headers,
                    data=body if method in ['POST', 'PUT', 'PATCH'] else None,
                    timeout=30
                )
                
                # Capture the request
                if self.capture:
                    self.capture.add_request(
                        method=method,
                        url=url,
                        headers=headers,
                        body=body,
                        response_code=response.status_code,
                        response_headers=dict(response.headers),
                        response_body=response.text[:1000]  # Limit response body size
                    )
                
                # Send response back to client
                self.send_response(response.status_code)
                for header, value in response.headers.items():
                    self.send_header(header, value)
                self.end_headers()
                self.wfile.write(response.content)
                
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Failed to forward request: {e}")
                self.send_error(502, "Bad Gateway")
                
        except Exception as e:
            print(f"[ERROR] Request handling error: {e}")
            self.send_error(500, "Internal Server Error")

class ProxyServer:
    def __init__(self, proxy_host="0.0.0.0", proxy_port=8080, target_host="localhost", target_port=80, 
                 use_ssl=False, cert_file=None, key_file=None, storage_file="captured_requests.json"):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.target_host = target_host
        self.target_port = target_port
        self.use_ssl = use_ssl
        self.cert_file = cert_file
        self.key_file = key_file
        self.capture = RequestCapture(storage_file)
        
    def start(self):
        """Start the proxy server"""
        handler = lambda *args, **kwargs: ProxyHandler(*args, capture=self.capture, **kwargs)
        
        with socketserver.ThreadingTCPServer((self.proxy_host, self.proxy_port), handler) as httpd:
            httpd.target_host = self.target_host
            httpd.target_port = self.target_port
            
            if self.use_ssl:
                if not self.cert_file or not self.key_file:
                    print("[ERROR] SSL enabled but certificate files not provided")
                    return
                
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(self.cert_file, self.key_file)
                httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
                print(f"[SSL] Proxy server running on https://{self.proxy_host}:{self.proxy_port}")
            else:
                print(f"[HTTP] Proxy server running on http://{self.proxy_host}:{self.proxy_port}")
            
            print(f"[TARGET] Forwarding requests to {self.target_host}:{self.target_port}")
            print(f"[STORAGE] Capturing unique requests to {self.capture.storage_file}")
            print("[INFO] Press Ctrl+C to stop the server")
            
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n[INFO] Shutting down proxy server...")
                httpd.shutdown()

def generate_self_signed_cert(cert_file="proxy.crt", key_file="proxy.key"):
    """Generate self-signed certificate for SSL"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from datetime import datetime, timedelta
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxy Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate and key files
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"[SSL] Generated self-signed certificate: {cert_file}")
        print(f"[SSL] Generated private key: {key_file}")
        return True
        
    except ImportError:
        print("[ERROR] cryptography library not installed. Install with: pip install cryptography")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to generate certificate: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Simple HTTP/HTTPS Proxy Server")
    parser.add_argument("--proxy-host", default="0.0.0.0", help="Proxy server host (default: 0.0.0.0)")
    parser.add_argument("--proxy-port", type=int, default=8080, help="Proxy server port (default: 8080)")
    parser.add_argument("--target-host", default="localhost", help="Target server host (default: localhost)")
    parser.add_argument("--target-port", type=int, default=80, help="Target server port (default: 80)")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL/HTTPS")
    parser.add_argument("--cert", help="SSL certificate file")
    parser.add_argument("--key", help="SSL private key file")
    parser.add_argument("--storage", default="captured_requests.json", help="Storage file for captured requests")
    parser.add_argument("--generate-cert", action="store_true", help="Generate self-signed certificate")
    
    args = parser.parse_args()
    
    # Generate certificate if requested
    if args.generate_cert:
        cert_file = args.cert or "proxy.crt"
        key_file = args.key or "proxy.key"
        if generate_self_signed_cert(cert_file, key_file):
            args.cert = cert_file
            args.key = key_file
            args.ssl = True
        else:
            return
    
    # Validate SSL settings
    if args.ssl and (not args.cert or not args.key):
        print("[ERROR] SSL enabled but certificate files not provided")
        print("Use --generate-cert to create self-signed certificate or provide --cert and --key")
        return
    
    # Start proxy server
    proxy = ProxyServer(
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        target_host=args.target_host,
        target_port=args.target_port,
        use_ssl=args.ssl,
        cert_file=args.cert,
        key_file=args.key,
        storage_file=args.storage
    )
    
    proxy.start()

if __name__ == "__main__":
    main()
