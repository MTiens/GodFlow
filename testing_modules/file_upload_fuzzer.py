# testing_modules/file_upload_fuzzer.py

import os
import mimetypes
import copy
from pathlib import Path
from typing import List, Dict, Any, Optional
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.colors import colored_print, format_log_prefix

class FileUploadFuzzerModule(FuzzingModule):
    """
    Fuzzes file upload endpoints by injecting payload files from a specified folder.
    
    Supports various bypass techniques:
    - Double extension (e.g., shell.php.jpg)
    - Null byte injection (e.g., shell.php%00.jpg)
    - MIME type spoofing (e.g., sending PHP with image/jpeg Content-Type)
    - Content-Type mismatch
    """
    key = "file_upload_fuzzer"
    
    # Common dangerous extensions
    DANGEROUS_EXTENSIONS = ['.php', '.phtml', '.php5', '.php7', '.phar', '.asp', '.aspx', '.jsp', '.jspx', '.exe', '.sh', '.py', '.pl', '.cgi', '.htaccess']
    
    # Common image extensions for bypass
    ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx']
    
    def run(self, parsed_request, step_config, **kwargs):
        """Synchronous run method."""
        results = []
        fuzz_config = step_config.get('fuzz', {}).get(self.key, {})
        
        payload_folder = fuzz_config.get('payload_folder')
        if not payload_folder:
            colored_print(format_log_prefix("ERROR", "payload_folder is required for file_upload_fuzzer"), "error")
            return results
        
        # Resolve path relative to project root or absolute
        if not os.path.isabs(payload_folder):
            # Try to resolve from project directory
            project_root = kwargs.get('project_root', os.getcwd())
            payload_folder = os.path.join(project_root, payload_folder)
        
        if not os.path.isdir(payload_folder):
            colored_print(format_log_prefix("ERROR", f"Payload folder not found: {payload_folder}"), "error")
            return results
        
        # Get configuration
        field_name = fuzz_config.get('field_name', 'file')
        bypass_techniques = fuzz_config.get('bypass_techniques', ['none'])
        matchers = fuzz_config.get('matchers', [])
        
        # Collect payload files
        payload_files = self._collect_payload_files(payload_folder)
        colored_print(format_log_prefix("INFO", f"Found {len(payload_files)} payload files in {payload_folder}"), "info")
        
        if not payload_files:
            colored_print(format_log_prefix("WARN", "No payload files found"), "warning")
            return results
        
        # Process assign block
        self._process_assign(step_config, self.state_manager)
        
        for file_path in payload_files:
            for technique in bypass_techniques:
                result = self._fuzz_with_file(
                    parsed_request, step_config, file_path, 
                    field_name, technique, matchers
                )
                if result:
                    results.append(result)
        
        return results
    
    def _collect_payload_files(self, folder: str) -> List[str]:
        """Collect all files from the payload folder recursively."""
        files = []
        for root, _, filenames in os.walk(folder):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        return files
    
    def _fuzz_with_file(self, parsed_request, step_config, file_path: str, 
                       field_name: str, technique: str, matchers: list) -> Optional[FuzzingResult]:
        """Fuzz with a single file using the specified bypass technique."""
        try:
            original_filename = os.path.basename(file_path)
            file_content = self._read_file(file_path)
            
            # Apply bypass technique
            fuzzed_filename, content_type = self._apply_bypass_technique(
                original_filename, technique
            )
            
            # Construct multipart form data
            fuzzed_request = self._construct_multipart_request(
                parsed_request, field_name, fuzzed_filename, file_content, content_type
            )
            
            # Prepare and send request
            final_request = self.runner.prepare_request(
                fuzzed_request, self.state_manager, step_config.get('set_headers', {}), 
                validate_state=False  # Skip validation as we are replacing body
            )
            
            response = self.runner.run(final_request)
            
            # Check for success indicators
            is_vulnerable = self._check_vulnerability(response, matchers, technique, fuzzed_filename)
            
            description = f"File: {original_filename} | Technique: {technique} | Sent as: {fuzzed_filename}"
            if is_vulnerable:
                description += f" | Status: {response.status_code} [POTENTIAL UPLOAD]"
            
            result = self.create_enhanced_result(
                is_vulnerable=is_vulnerable,
                description=description,
                request=final_request,
                response=response,
                payload=f"{fuzzed_filename} ({technique})",
                step_name=f"upload_{technique}_{original_filename}",
                expected_vulnerable=True if is_vulnerable else False
            )
            
            if is_vulnerable:
                result = self.enhance_result_with_baseline(result)
                colored_print(format_log_prefix("VULN", description), "error")
                return result
            else:
                # Log progress
                colored_print(format_log_prefix("INFO", f"Tested: {fuzzed_filename} ({technique}) - {response.status_code}"), "info")
            
            return None
            
        except Exception as e:
            colored_print(format_log_prefix("ERROR", f"File upload fuzz error: {e}"), "error")
            return None
    
    def _read_file(self, file_path: str) -> bytes:
        """Read file content as bytes."""
        with open(file_path, 'rb') as f:
            return f.read()
    
    def _apply_bypass_technique(self, filename: str, technique: str) -> tuple:
        """Apply a bypass technique to the filename and return (filename, content_type)."""
        base, ext = os.path.splitext(filename)
        
        # Guess the original MIME type
        original_mime, _ = mimetypes.guess_type(filename)
        original_mime = original_mime or 'application/octet-stream'
        
        if technique == 'none':
            return filename, original_mime
        
        elif technique == 'double_extension':
            # e.g., shell.php -> shell.php.jpg
            return f"{filename}.jpg", 'image/jpeg'
        
        elif technique == 'null_byte':
            # e.g., shell.php -> shell.php%00.jpg (URL encoded null byte)
            return f"{filename}%00.jpg", 'image/jpeg'
        
        elif technique == 'null_byte_raw':
            # Raw null byte
            return f"{filename}\x00.jpg", 'image/jpeg'
        
        elif technique == 'mime_spoof':
            # Keep original filename but spoof Content-Type to image
            return filename, 'image/jpeg'
        
        elif technique == 'content_type_mismatch':
            # Send with no extension but original content
            return f"{base}_uploaded", 'application/octet-stream'
        
        elif technique == 'case_manipulation':
            # e.g., shell.php -> shell.pHp
            if ext.lower() in ['.php', '.asp', '.jsp']:
                mixed_case_ext = ''.join(c.upper() if i % 2 else c for i, c in enumerate(ext))
                return f"{base}{mixed_case_ext}", original_mime
            return filename, original_mime
        
        elif technique == 'unicode':
            # e.g., shell.php -> shell.p\u200dh\u200dp (zero-width joiner)
            if ext.lower() == '.php':
                return f"{base}.p\u200dh\u200dp", original_mime
            return filename, original_mime
        
        elif technique == 'alternative_extension':
            # e.g., shell.php -> shell.phtml
            ext_map = {'.php': '.phtml', '.asp': '.asa', '.jsp': '.jspx'}
            new_ext = ext_map.get(ext.lower(), ext)
            return f"{base}{new_ext}", original_mime
        
        else:
            return filename, original_mime
    
    def _construct_multipart_request(self, parsed_request: dict, field_name: str, 
                                     filename: str, content: bytes, content_type: str) -> dict:
        """Construct a multipart/form-data request."""
        fuzzed_request = copy.deepcopy(parsed_request)
        
        # Remove existing body/content
        fuzzed_request.pop('content', None)
        fuzzed_request.pop('json', None)
        
        # Use httpx files parameter for multipart
        # Format: {'field_name': (filename, content, content_type)}
        fuzzed_request['files'] = {
            field_name: (filename, content, content_type)
        }
        
        # httpx will automatically set Content-Type to multipart/form-data with boundary
        # Remove explicit Content-Type if present
        if 'headers' in fuzzed_request and 'Content-Type' in fuzzed_request.get('headers', {}):
            del fuzzed_request['headers']['Content-Type']
        if 'headers' in fuzzed_request and 'content-type' in fuzzed_request.get('headers', {}):
            del fuzzed_request['headers']['content-type']
        
        return fuzzed_request
    
    def _check_vulnerability(self, response, matchers: list, technique: str, filename: str) -> bool:
        """Check if the upload was successful (indicating potential vulnerability)."""
        # Use custom matchers if provided
        if matchers:
            return self.check_custom_matchers(response, matchers)
        
        # Default heuristics:
        # 1. Successful status codes (200, 201, 204)
        # 2. Response contains indicators of success
        
        if response.status_code in [200, 201, 204]:
            response_text = response.text.lower()
            
            # Check for positive indicators
            success_indicators = ['success', 'uploaded', 'saved', 'created', 'complete', 'file_url', 'file_path']
            for indicator in success_indicators:
                if indicator in response_text:
                    return True
            
            # If dangerous technique and 2xx, flag it
            dangerous_techniques = ['double_extension', 'null_byte', 'null_byte_raw', 'case_manipulation', 'unicode', 'alternative_extension']
            if technique in dangerous_techniques:
                # Also check if server didn't explicitly reject
                rejection_indicators = ['invalid', 'reject', 'error', 'not allowed', 'forbidden', 'denied']
                for indicator in rejection_indicators:
                    if indicator in response_text:
                        return False
                return True
        
        return False
