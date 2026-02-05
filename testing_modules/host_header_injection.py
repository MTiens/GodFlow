import copy
from testing_modules.base_module import FuzzingModule, FuzzingResult
import os
from core.colors import colored_print, format_log_prefix

class HostHeaderInjectionModule(FuzzingModule):
    key = "host_header_injection"

    COMMON_PAYLOADS = [
        "evil.com",
        "127.0.0.1",
        "localhost",
        "internal.example.com",
        "attacker.com",
        "example.com",
        "hostheader.attack",
        "0.0.0.0",
        "malicious.com",
        "admin.local",
        "google.com",
        "bing.com",
        "yahoo.com",
        "amazon.com",
        "facebook.com"
    ]

    def get_payloads(self):
        payload_file = os.path.join(os.path.dirname(__file__), '../payloads/host_header.txt')
        payload_file = os.path.abspath(payload_file)
        if os.path.isfile(payload_file):
            try:
                with open(payload_file, 'r', encoding='utf-8') as f:
                    return [
                        line.strip() for line in f
                        if line.strip() and not line.strip().startswith('#')
                    ]
            except Exception as e:
                colored_print(f"Could not read host_header.txt: {e}", "error")
        return self.COMMON_PAYLOADS

    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> list[FuzzingResult]:
        results = []
        payloads = self.get_payloads()
        original_headers = parsed_request.get('headers', {}).copy()
        for payload in payloads:
            fuzzed_request = copy.deepcopy(parsed_request)
            fuzzed_request.setdefault('headers', {})['Host'] = payload
            final_request = self.runner.prepare_request(
                fuzzed_request, self.state_manager, step_config.get('set_headers', {})
            )
            try:
                response = self.runner.run(final_request)
                # Check if payload is reflected in response or status code is interesting
                reflected = payload in response.text
                interesting_status = response.status_code in [200, 201, 202, 204, 301, 302, 307, 401, 403]
                if reflected or interesting_status:
                    result = self.create_enhanced_result(
                        is_vulnerable=reflected,
                        description=f"Host header '{payload}' reflected or caused status {response.status_code}",
                        request=final_request,
                        response=response,
                        payload=payload,
                        step_name="host_header",
                        expected_vulnerable=reflected or interesting_status
                    )
                    result = self.enhance_result_with_baseline(result)
                    results.append(result)
            except Exception as e:
                colored_print(f"Host header injection request failed: {e}", "error")
        return results 