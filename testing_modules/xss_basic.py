import copy
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.utils import find_placeholders
from core.colors import colored_print, format_log_prefix


class XSSBasicModule(FuzzingModule):
    """
    Tests for Cross-Site Scripting (XSS) vulnerabilities using both traditional 
    detection and enhanced baseline comparison.
    """
    
    key = "xss_basic"
    
    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> list[FuzzingResult]:
        """Runs basic XSS tests on the given request."""
        results = []
        
        # Load XSS payloads
        xss_payloads = self.payload_manager.get_payloads('xss')
        if not xss_payloads:
            # Fallback payloads if file doesn't exist
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert('XSS')",
                "'><script>alert(String.fromCharCode(88,83,83))</script>",
                "<svg onload=alert(1)>"
            ]
        
        step_name = step_config.get('name', 'xss_test')
        placeholders = find_placeholders(parsed_request)
        
        for placeholder in placeholders:
            for payload in xss_payloads[:10]:  # Limit to first 10 payloads
                # Create a state manager copy with the payload injected
                fuzz_state = copy.deepcopy(self.state_manager)
                fuzz_state.set(placeholder, payload)
                
                # Create a modified request with the XSS payload
                final_request = self.runner.prepare_request(
                    parsed_request, 
                    fuzz_state, 
                    step_config.get('set_headers', {})
                )

                try:
                    response = self.runner.run(final_request)
                    
                    # Traditional detection: check if payload is reflected
                    is_vulnerable_traditional = payload in response.text
                    
                    # Enhanced detection using baseline comparison
                    result = self.create_enhanced_result(
                        is_vulnerable=is_vulnerable_traditional,
                        description=f"XSS test for '{placeholder}' with payload: {payload[:50]}...",
                        request=final_request,
                        response=response,
                        payload=payload,
                        step_name=step_name,
                        expected_vulnerable=True  # We expect this to be vulnerable if successful
                    )
                    
                    # Add additional context for XSS-specific analysis
                    result = self.enhance_result_with_baseline(result)
                    
                    # Only report if vulnerable or if we want to show all tests
                    if result.is_vulnerable or self.kwargs.get('show_all_tests', False):
                        results.append(result)
                        
                except Exception as e:
                    colored_print(f"XSS module request failed: {e}", "error")

        return results

    async def arun(self, parsed_request: dict, step_config: dict, **kwargs) -> list[FuzzingResult]:
        """Async version of run method."""
        results = []
        
        # Load XSS payloads
        xss_payloads = self.payload_manager.get_payloads('xss')
        if not xss_payloads:
            # Fallback payloads if file doesn't exist
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert('XSS')",
                "'><script>alert(String.fromCharCode(88,83,83))</script>",
                "<svg onload=alert(1)>"
            ]
        
        step_name = step_config.get('name', 'xss_test')
        placeholders = find_placeholders(parsed_request)
        
        for placeholder in placeholders:
            for payload in xss_payloads[:10]:  # Limit to first 10 payloads
                # Create a state manager copy with the payload injected
                fuzz_state = copy.deepcopy(self.state_manager)
                fuzz_state.set(placeholder, payload)
                
                # Create a modified request with the XSS payload
                final_request = self.runner.prepare_request(
                    parsed_request, 
                    fuzz_state, 
                    step_config.get('set_headers', {})
                )

                try:
                    response = await self.runner.arun(final_request)
                    
                    # Traditional detection: check if payload is reflected
                    is_vulnerable_traditional = payload in response.text
                    
                    # Enhanced detection using baseline comparison
                    result = self.create_enhanced_result(
                        is_vulnerable=is_vulnerable_traditional,
                        description=f"XSS test for '{placeholder}' with payload: {payload[:50]}...",
                        request=final_request,
                        response=response,
                        payload=payload,
                        step_name=step_name,
                        expected_vulnerable=True  # We expect this to be vulnerable if successful
                    )
                    
                    # Add additional context for XSS-specific analysis
                    result = self.enhance_result_with_baseline(result)
                    
                    # Only report if vulnerable or if we want to show all tests
                    if result.is_vulnerable or self.kwargs.get('show_all_tests', False):
                        results.append(result)
                        
                except Exception as e:
                    colored_print(f"XSS module request failed: {e}", "error")

        return results