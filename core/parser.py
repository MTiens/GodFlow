# core/parser.py
import re
from typing import Dict, Any, Tuple
from urllib.parse import urlparse, parse_qsl

class RequestParser:
    def __init__(self, raw_request: str, target_host: str):
        self.raw = raw_request
        self.target_host = target_host

    def parse(self) -> Dict[str, Any]:
        """Parses a raw HTTP request string into a dictionary for httpx."""
        # Normalize line endings to \n for consistent processing
        normalized_request = self.raw.replace('\r\n', '\n').replace('\r', '\n')
        
        try:
            headers_part, body_part = normalized_request.strip().split('\n\n', 1)
        except ValueError:
            headers_part = normalized_request.strip()
            body_part = None

        request_lines = headers_part.split('\n')
        
        # More robust parsing of the request line
        first_line_parts = request_lines[0].split()
        if len(first_line_parts) < 2:
            raise ValueError(f"Invalid HTTP request line: {request_lines[0]}")
        
        method = first_line_parts[0]
        path = first_line_parts[1]
        # HTTP version is optional, we don't need it for httpx

        headers = {}
        for line in request_lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                # We ignore the Host header from the file and use the one from the flow config
                if key.lower().strip() != 'host':
                    headers[key.strip()] = value.strip()

        # Construct the full URL
        url = self.target_host + path

        # Separate path and query params
        parsed_url = urlparse(url)
        params = dict(parse_qsl(parsed_url.query))
        
        # httpx needs the URL without the query string if params are provided separately
        url_without_query = parsed_url._replace(query=None).geturl()

        return {
            "method": method.upper(),
            "url": url_without_query,
            "params": params,
            "headers": headers,
            "content": body_part # We use 'content' for raw body
        }

# Example Usage:
# raw = "POST /api/v1/register HTTP/1.1\r\nHost: ignored.com\r\nContent-Type: application/json\r\n\r\n{\"username\":\"{{username}}\"}"
# parser = RequestParser(raw, "https://abc.com.vn")
# parsed_request = parser.parse()
# print(parsed_request)
# {'method': 'POST', 'url': 'https://abc.com.vn/api/v1/register', 'params': {}, 'headers': {'Content-Type': 'application/json'}, 'content': '{"username":"{{username}}"}'}