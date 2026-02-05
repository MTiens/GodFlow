# core/runner.py
import httpx
import asyncio
import re
import uuid
from typing import Dict, Any, Union, Optional
from core.state import StateManager
from pathlib import Path
from core.colors import format_log_prefix, colored_print

class RequestRunner:
    def __init__(self, is_async: bool = False, proxy_config: Optional[dict] = None, assets_dir: Optional[str] = None, verbose: bool = False, debug: bool = False, timeout: float = 30.0):
        self.is_async = is_async
        self.proxy_config = proxy_config
        self.assets_dir = Path(assets_dir) if assets_dir else None
        self.verbose = verbose
        self.debug = debug
        self.timeout = timeout
        
        # Configure client options
        client_kwargs = {
            'timeout': httpx.Timeout(timeout, connect=10.0)  # Total timeout with 10s connect timeout
        }
        
        if proxy_config:
            # Set up proxy configuration
            proxy_url = proxy_config['url']
            
            # Handle proxy authentication
            if proxy_config.get('auth'):
                # If auth is provided separately, we need to parse it
                auth_parts = proxy_config['auth'].split(':', 1)
                if len(auth_parts) == 2:
                    username, password = auth_parts
                    # httpx expects proxy auth in the URL format
                    if '@' not in proxy_url:
                        # Insert auth into URL
                        url_parts = proxy_url.split('://', 1)
                        if len(url_parts) == 2:
                            scheme, rest = url_parts
                            proxy_url = f"{scheme}://{username}:{password}@{rest}"
            
            client_kwargs['proxies'] = {
                'http://': proxy_url,
                'https://': proxy_url
            }
            
            # Handle SSL verification
            if not proxy_config.get('verify_ssl', True):
                client_kwargs['verify'] = False
        
        if is_async:
            self.client = httpx.AsyncClient(**client_kwargs)
        else:
            self.client = httpx.Client(**client_kwargs)

    def run(self, request_details: Dict[str, Any]) -> httpx.Response:
        """Runs a single request synchronously."""
        if self.is_async:
            raise RuntimeError("Use 'arun' for async mode.")
        # Debug: print raw request body bytes
        # if 'content' in request_details and request_details['content'] is not None:
        #     print("[DEBUG] Raw content bytes:", request_details['content'] if isinstance(request_details['content'], bytes) else request_details['content'].encode('utf-8'))
        # elif 'json' in request_details and request_details['json'] is not None:
        #     import json
        #     print("[DEBUG] Raw JSON bytes:", json.dumps(request_details['json'], ensure_ascii=False).encode('utf-8'))
        if isinstance(self.client, httpx.Client):
            # print(f"[DEBUG] Request details: {request_details}")
            response = self.client.request(**request_details)
            
            # Print X-Trace-Id if verbose mode is enabled
            if self.verbose:
                from core.colors import color_formatter
                status_colored = color_formatter.status_code(response.status_code)
                trace_id = request_details.get('headers', {}).get('X-Trace-Id', 'N/A')
                print(f"  -> {response.request.method} {response.url} - Status: {status_colored} - X-Trace-Id: {trace_id}")
            
            return response
        else:
            raise RuntimeError("Sync client not available in async mode.")

    async def arun(self, request_details: Dict[str, Any]) -> httpx.Response:
        """Runs a single request asynchronously."""
        if not self.is_async:
            raise RuntimeError("Use 'run' for sync mode.")
        # Debug: print raw request body bytes
        # if 'content' in request_details and request_details['content'] is not None:
        #     print("[DEBUG] Raw content bytes:", request_details['content'] if isinstance(request_details['content'], bytes) else request_details['content'].encode('utf-8'))
        # elif 'json' in request_details and request_details['json'] is not None:
        #     import json
            # print("[DEBUG] Raw JSON bytes:", json.dumps(request_details['json'], ensure_ascii=False).encode('utf-8'))
        if isinstance(self.client, httpx.AsyncClient):
            response = await self.client.request(**request_details)
            
            # Print X-Trace-Id if verbose mode is enabled
            if self.verbose:
                from core.colors import color_formatter
                status_colored = color_formatter.status_code(response.status_code)
                trace_id = request_details.get('headers', {}).get('X-Trace-Id', 'N/A')
                print(f"  -> {response.request.method} {response.url} - Status: {status_colored} - X-Trace-Id: {trace_id}")
            
            return response
        else:
            raise RuntimeError("Async client not available in sync mode.")

    def prepare_request(self, parsed_request: Dict, state_manager: 'StateManager', set_headers: Dict = {}, validate_state: bool = True ) -> Dict:
        """Injects state variables into the parsed request."""
        
        # Deep copy to avoid modifying the original parsed request
        import copy
        final_request = copy.deepcopy(parsed_request)
        
        # Check for missing state variables before substitution (optional)
        if validate_state:
            missing_vars = self._check_missing_state_variables(parsed_request, state_manager, set_headers)
            if missing_vars:
                raise ValueError(f"Missing state variables: {missing_vars}. Cannot prepare request.")

        # Ensure 'params' and 'headers' keys exist
        if 'params' not in final_request:
            final_request['params'] = {}
        if 'headers' not in final_request:
            final_request['headers'] = {}
        if 'content' not in final_request:
            final_request['content'] = None

        # Helper for recursive substitution
        def substitute_recursive(obj):
            if isinstance(obj, dict):
                return {k: substitute_recursive(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [substitute_recursive(v) for v in obj]
            elif isinstance(obj, str):
                return state_manager.substitute(obj)
            else:
                return obj

        # Substitute variables in URL, params, headers, and body
        final_request['url'] = state_manager.substitute(final_request['url'])
        
        for k, v in final_request['params'].items():
            final_request['params'][k] = state_manager.substitute(v)
            
        for k, v in final_request['headers'].items():
            final_request['headers'][k] = state_manager.substitute(v)
        
        # Substitute recursively in JSON body if present
        if 'json' in final_request:
            final_request['json'] = substitute_recursive(final_request['json'])
        
        # Handle file injection: {{file:payloads/avatar.png}}
        if final_request['content']:
            # First, substitute all variables in the content string
            substituted_content = state_manager.substitute(final_request['content'])
            # Ensure CRLF line endings for multipart
            substituted_content = re.sub(r'(?<!\r)\n', '\r\n', substituted_content)
            
            # Find ALL file placeholders (supports paths with alphanumeric, /, \, ., -, _)
            file_pattern = r"\{\{file:([^\}]+)\}\}"
            file_matches = list(re.finditer(file_pattern, substituted_content))
            
            if file_matches:
                # Process matches in reverse order to preserve positions
                result_bytes = substituted_content.encode('utf-8')
                
                for file_match in reversed(file_matches):
                    filepath = file_match.group(1).strip()
                    # Try to resolve the file path using assets_dir if available
                    resolved_filepath = None
                    if self.assets_dir:
                        # Try relative to assets_dir first
                        assets_filepath = self.assets_dir / filepath
                        if assets_filepath.exists():
                            resolved_filepath = assets_filepath
                    
                    # If not found in assets_dir, try as absolute path or relative to current directory
                    if not resolved_filepath:
                        # Try as absolute path first
                        if Path(filepath).is_absolute():
                            resolved_filepath = Path(filepath)
                        else:
                            # Try relative to current working directory
                            resolved_filepath = Path.cwd() / filepath
                            if self.debug:
                                colored_print(format_log_prefix("DEBUG", f"Resolved filepath: {resolved_filepath}"), "debug")
                    
                    try:
                        with open(resolved_filepath, 'rb') as f:
                            file_bytes = f.read()
                        # Calculate byte positions for the placeholder
                        placeholder = file_match.group(0)
                        placeholder_bytes = placeholder.encode('utf-8')
                        # Find the placeholder in the result bytes
                        start_pos = result_bytes.find(placeholder_bytes)
                        if start_pos != -1:
                            end_pos = start_pos + len(placeholder_bytes)
                            result_bytes = result_bytes[:start_pos] + file_bytes + result_bytes[end_pos:]
                    except FileNotFoundError:
                        print(f"[ERROR] File not found: {filepath}")
                        if self.debug:
                            colored_print(format_log_prefix("DEBUG", f"Tried paths: {resolved_filepath}"), "debug")
                
                final_request['content'] = result_bytes
            else:
                # No file placeholders, just use substituted content
                if isinstance(substituted_content, str):
                    final_request['content'] = substituted_content
                else:
                    final_request['content'] = substituted_content

        # Apply step-specific headers (e.g., Authorization)
        if set_headers:
            for k, v in set_headers.items():
                final_request['headers'][k] = state_manager.substitute(v)

        # If the request body is JSON, ensure Content-Type includes charset=UTF-8
        if 'json' in final_request and final_request['json'] is not None:
            content_type = final_request['headers'].get('Content-Type', '')
            if 'application/json' in content_type and 'charset' not in content_type.lower():
                final_request['headers']['Content-Type'] = 'application/json'
            elif 'application/json' not in content_type:
                final_request['headers']['Content-Type'] = 'application/json'

        # Generate X-Trace-Id header
        x_trace_id = str(uuid.uuid4())
        final_request['headers']['X-Trace-Id'] = x_trace_id
        if self.debug:
            colored_print(format_log_prefix("DEBUG", f"Generated X-Trace-Id: {x_trace_id}"), "debug")

        return final_request

    def _check_missing_state_variables(self, parsed_request: Dict, state_manager: 'StateManager', set_headers: Dict) -> list:
        """
        Check for any missing state variables that are referenced in the request.
        
        Args:
            parsed_request: The parsed request dictionary
            state_manager: The state manager containing variables
            set_headers: Additional headers to be set
            
        Returns:
            List of missing variable names, empty if all variables are present
        """
        missing_vars = []
        import re
        
        # Helper function to extract variable names from a string
        def extract_variables(text):
            if not isinstance(text, str):
                return []
            # Find all {{variable}} patterns
            matches = re.findall(r'\{\{(\w+)\}\}', text)
            return matches
        
        # Check URL
        if 'url' in parsed_request:
            missing_vars.extend(extract_variables(parsed_request['url']))
        
        # Check params
        if 'params' in parsed_request:
            for value in parsed_request['params'].values():
                missing_vars.extend(extract_variables(value))
        
        # Check headers
        if 'headers' in parsed_request:
            for value in parsed_request['headers'].values():
                missing_vars.extend(extract_variables(value))
        
        # Check JSON body
        if 'json' in parsed_request and parsed_request['json']:
            def check_json_vars(obj):
                vars_found = []
                if isinstance(obj, dict):
                    for value in obj.values():
                        vars_found.extend(check_json_vars(value))
                elif isinstance(obj, list):
                    for item in obj:
                        vars_found.extend(check_json_vars(item))
                elif isinstance(obj, str):
                    vars_found.extend(extract_variables(obj))
                return vars_found
            
            missing_vars.extend(check_json_vars(parsed_request['json']))
        
        # Check content
        if 'content' in parsed_request and parsed_request['content']:
            missing_vars.extend(extract_variables(parsed_request['content']))
        
        # Check set_headers
        for value in set_headers.values():
            missing_vars.extend(extract_variables(value))
        
        # Filter out variables that exist in state (including empty strings)
        existing_vars = []
        for var in set(missing_vars):  # Remove duplicates
            if var in state_manager._state:
                existing_vars.append(var)
        
        # Return only truly missing variables
        return [var for var in set(missing_vars) if var not in existing_vars]

    def close(self):
        """Closes the HTTP client."""
        if isinstance(self.client, httpx.Client):
            self.client.close()

    async def aclose(self):
        """Closes the HTTP client asynchronously."""
        if isinstance(self.client, httpx.AsyncClient):
            await self.client.aclose()
        elif isinstance(self.client, httpx.Client):
            self.client.close()
    
    def load_request_from_file(self, filename: str, target: str, requests_dir: str = "requests") -> dict:
        """
        Load and parse a request from a .txt file.
        
        Args:
            filename: Name of the request file (e.g., "login.txt")
            target: Target URL for the request
            requests_dir: Directory containing request files
            
        Returns:
            Parsed request dictionary ready for httpx
            
        Raises:
            FileNotFoundError: If the request file is not found
        """
        from pathlib import Path
        from core.parser import RequestParser
        
        file_path = Path(requests_dir) / filename
        if not file_path.is_file():
            raise FileNotFoundError(f"Request file not found: {file_path}")
        
        with open(file_path, "r", encoding="utf-8") as f:
            raw_request = f.read()
        
        parser = RequestParser(raw_request, target)
        return parser.parse()