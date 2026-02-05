import copy
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.utils import find_placeholders
from core.colors import colored_print, format_log_prefix

class ClusterBombModule(FuzzingModule):
    key = "cluster_bomb"

    def __init__(self, runner, state_manager, payload_manager):
        super().__init__(runner, state_manager, payload_manager)
        # Load payload sets from files
        self.payload_set_1 = self._load_payloads("cluster_bomb_set1")
        self.payload_set_2 = self._load_payloads("cluster_bomb_set2")
        
        # Fallback payloads if files don't exist
        if not self.payload_set_1:
            self.payload_set_1 = ["admin", "user", "test", "guest", "root"]
        if not self.payload_set_2:
            self.payload_set_2 = ["password", "secret", "token", "key", "auth"]
    
    def _load_payloads(self, category: str) -> list[str]:
        """Load payloads from a category in the payloads directory."""
        try:
            payloads = self.payload_manager.get_payloads(category)
            return payloads
        except Exception as e:
            colored_print(f"Could not load payloads from category {category}: {e}", "warning")
            return []

    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> list[FuzzingResult]:
        """
        Cluster bomb fuzzing: combines two payload sets in the format "payload1: payload2"
        Adds combinations to request headers and tests for interesting responses.
        """
        results = []
        
        # Get custom payload sets from config if provided
        payload_set_1 = step_config.get('payload_set_1', self.payload_set_1)
        payload_set_2 = step_config.get('payload_set_2', self.payload_set_2)
        
        # Find header placeholders for injection
        placeholders = find_placeholders(parsed_request)
        header_placeholders = [p for p in placeholders if 'headers' in p.lower() or 'header' in p.lower()]
        
        if not header_placeholders:
            # If no header placeholders found, add to common header names
            header_placeholders = ['{{X-Custom-Header}}']
            # Add the placeholder to the request if it doesn't exist
            if 'headers' not in parsed_request:
                parsed_request['headers'] = {}
            parsed_request['headers']['X-Custom-Header'] = '{{X-Custom-Header}}'

        for header_placeholder in header_placeholders:
            for payload1 in payload_set_1:
                for payload2 in payload_set_2:
                    # Create cluster bomb combination
                    cluster_payload = f"{payload1}: {payload2}"
                    
                    fuzz_state = copy.deepcopy(self.state_manager)
                    fuzz_state.set(header_placeholder, cluster_payload)
                    
                    set_headers = step_config.get('set_headers', {}) or {}
                    final_request = self.runner.prepare_request(
                        parsed_request, fuzz_state, set_headers
                    )
                    
                    try:
                        response = self.runner.run(final_request)
                        
                        # Check for interesting responses
                        reflected = payload1 in response.text or payload2 in response.text
                        interesting_status = response.status_code >= 400
                        interesting_size = len(response.content) > 0
                        
                        if reflected or interesting_status or interesting_size:
                            result = self.create_enhanced_result(
                                is_vulnerable=reflected or interesting_status,
                                description=f"Cluster bomb payload '{cluster_payload}' in '{header_placeholder}' caused status {response.status_code}. Reflected: {reflected}",
                                request=final_request,
                                response=response,
                                payload=cluster_payload,
                                step_name=header_placeholder,
                                expected_vulnerable=reflected or interesting_status
                            )
                            result = self.enhance_result_with_baseline(result)
                            results.append(result)
                    except Exception as e:
                        colored_print(f"Cluster bomb module request failed: {e}", "error")
                        results.append(FuzzingResult(
                            is_vulnerable=False,
                            description=f"Request failed with payload '{cluster_payload}': {str(e)}",
                            request=final_request,
                            response_status=0,
                            response_size=0,
                            payload=cluster_payload
                        ))
        
        return results 