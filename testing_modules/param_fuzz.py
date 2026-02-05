import copy
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.utils import find_placeholders
from core.colors import colored_print, format_log_prefix

class ParamFuzzModule(FuzzingModule):
    key = "param_fuzz"

    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> list[FuzzingResult]:
        """
        Fuzzes specified parameters (query, body, headers) with payloads loaded from common.txt.
        If no params are specified in step_config, fuzzes all parameters.
        Reports if payload is reflected or causes interesting response (4xx, 5xx, etc).
        """
        # Check if the fuzz module is enabled
        if not step_config.get('enable', False):
            return [FuzzingResult(
                is_vulnerable=False,
                description="Param fuzz module is disabled (enable: false).",
                request=parsed_request, response_status=0, response_size=0
            )]
        
        results = []
        payloads = self.payload_manager.get_payloads("common")
        placeholders = find_placeholders(parsed_request)
        if not placeholders:
            return [FuzzingResult(
                is_vulnerable=False,
                description="No injection points {{...}} found in the request template.",
                request=parsed_request, response_status=0, response_size=0
            )]
        
        # Get specified parameters from step_config, or use all placeholders if not specified
        print(f"Step config: {step_config}")
        if "fuzz" in step_config:
            step_config = step_config['fuzz']
            if "param_fuzz" in step_config:
                step_config = step_config['param_fuzz']
        specified_params = step_config.get('params', [])
        print(f"Specified parameters: {specified_params}")
        if specified_params:
            # Filter placeholders to only include specified parameters
            placeholders = [p for p in placeholders if p in specified_params]
            
            print(f"Placeholders: {placeholders}")
            if not placeholders:
                return [FuzzingResult(
                    is_vulnerable=False,
                    description=f"None of the specified parameters {specified_params} found in the request template.",
                    request=parsed_request, response_status=0, response_size=0
                )]
        
        for placeholder in placeholders:
            for payload in payloads:
                fuzz_state = copy.deepcopy(self.state_manager)
                fuzz_state.set(placeholder, payload)
                set_headers = step_config.get('set_headers', {}) or {}
                final_request = self.runner.prepare_request(
                    parsed_request, fuzz_state, set_headers
                )
                try:
                    response = self.runner.run(final_request)
                    # Interesting if payload is reflected or status is 4xx/5xx
                    reflected = payload in response.text
                    interesting_status = response.status_code >= 400
                    if reflected or interesting_status:
                        result = self.create_enhanced_result(
                            is_vulnerable=reflected or interesting_status,
                            description=f"Payload '{payload}' in '{placeholder}' caused status {response.status_code}. Reflected: {reflected}",
                            request=final_request,
                            response=response,
                            payload=payload,
                            step_name=placeholder,
                            expected_vulnerable=reflected or interesting_status
                        )
                        result = self.enhance_result_with_baseline(result)
                        results.append(result)
                except Exception as e:
                    colored_print(f"Param fuzz module request failed: {e}", "error")
        return results 