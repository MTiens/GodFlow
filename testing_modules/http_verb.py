# testing_modules/http_verb_tamper.py

import copy
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.colors import colored_print, format_log_prefix

class HTTPVerbTamperModule(FuzzingModule):
    key = "http_verb_tamper"
    
    VERBS = [
        "GET", "POST", "HEAD", "CONNECT", "PUT", "TRACE", "OPTIONS", "DELETE",
        "ACL", "ARBITRARY", "BASELINE-CONTROL", "BCOPY", "BDELETE", "BIND",
        "BMOVE", "BPROPFIND", "BPROPPATCH", "CHECKIN", "CHECKOUT", "COPY",
        "DEBUG", "INDEX", "LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY",
        "MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE", "MOVE",
        "NOTIFY", "ORDERPATCH", "PATCH", "POLL", "PROPFIND", "PROPPATCH",
        "REBIND", "REPORT", "RPC_IN_DATA", "RPC_OUT_DATA", "SEARCH",
        "SUBSCRIBE", "TRACK", "UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK",
        "UNSUBSCRIBE", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL",
        "X-MS-ENUMATTS"
    ]

    def run(self, parsed_request, step_config):
        results = []
        original_method = parsed_request['method']
        status_verb_map = {}  # Map status codes to lists of verbs

        for verb in self.VERBS:
            if verb == original_method:
                continue

            fuzzed_request = parsed_request.copy()
            fuzzed_request['method'] = verb

            final_request = self.runner.prepare_request(
                fuzzed_request, self.state_manager, step_config.get('set_headers', {})
            )

            try:
                response = self.runner.run(final_request)
                
                # Group verbs by status code
                status_code = response.status_code
                if status_code not in status_verb_map:
                    status_verb_map[status_code] = []
                status_verb_map[status_code].append(verb)
                
                # Interesting finding if a different verb gives a 2xx or 401/403 (not 404/405)
                if 200 <= response.status_code < 300:
                    result = self.create_enhanced_result(
                        is_vulnerable=True,
                        description=f"Verb '{verb}' returned success status {response.status_code}",
                        request=final_request,
                        response=response,
                        payload=verb,
                        step_name=verb,
                        expected_vulnerable=True
                    )
                    result = self.enhance_result_with_baseline(result)
                    results.append(result)
                        
            except Exception as e:
                colored_print(f"Verb tamper module request failed: {e}", "error")
        
        # Print results in the requested format
        for status_code in sorted(status_verb_map.keys()):
            verbs = status_verb_map[status_code]
            colored_print(f"[{status_code}] : {', '.join(verbs)}", "info")
        
        return results