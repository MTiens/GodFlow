import copy
import asyncio
from typing import List, Dict, Any, Optional
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.utils import find_placeholders, substitute_all
from core.state import StateManager
from core.runner import RequestRunner
from core.payload import PayloadManager
from core.colors import format_log_prefix, colored_print


class FlowFuzzerModule(FuzzingModule):
    """
    Enhanced flow fuzzing module that runs complete flows with payload substitution
    and baseline-enhanced vulnerability detection.
    
    This module supports 4 strategies:
    
    1. complete_flow (Default):
       Injects payload at start, runs entire flow. Good for stored XSS or logic bugs.
       Usage in YAML:
         fuzz:
           flow_fuzzer:
             enable: true
             strategy: "complete_flow"
             payload_category: "xss"
    
    2. single_step:
       Fuzzes just the current step isolated from others. Good for reflected XSS/SQLi.
       Usage in YAML:
         fuzz:
           flow_fuzzer:
             enable: true
             strategy: "single_step"
    
    3. state_mutation:
       Injects payloads into state variables mid-flow (e.g. at step 3) then runs remaining steps.
       Good for testing handling of corrupted state.
       Usage in YAML:
         fuzz:
           flow_fuzzer:
             enable: true
             strategy: "state_mutation"
    
    4. batch_flow:
       Runs N payloads, then resets flow by re-running setup steps (0 to Current-1).
       Good for OTP/CAPTCHA/Rate-limited flows.
       Usage in YAML:
         fuzz:
           flow_fuzzer:
             enable: true
             strategy: "batch_flow"
             batch_size: 5  # Re-run setup every 5 payloads
             payload_category: "numeric_otp"
    """
    
    key = "flow_fuzzer"
    
    def __init__(self, runner: RequestRunner, state_manager: StateManager, payload_manager: PayloadManager, **kwargs):
        super().__init__(runner, state_manager, payload_manager, **kwargs)
    
    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> List[FuzzingResult]:
        """
        Main execution method for flow fuzzing.
        
        Args:
            parsed_request: The parsed request for the current step
            step_config: Configuration for the current step and fuzzing strategy
            **kwargs: Additional arguments including flow context
            
        Returns:
            List of FuzzingResult objects
        """
        # Check if fuzzing is enabled
        fuzz_config = step_config.get("fuzz", {}).get(self.key, {})
        if not fuzz_config or fuzz_config.get("enable") is False:
            return [FuzzingResult(
                is_vulnerable=False,
                description="Flow fuzzing is disabled for this step",
                request=parsed_request,
                response_status=0,
                response_size=0
            )]
        
        # Get flow context from kwargs
        flow_context = kwargs.get('flow_context', {})
        flow_steps = flow_context.get('steps', [])
        current_step_index = flow_context.get('current_step_index', 0)
        
        # Get configuration
        strategy = fuzz_config.get('strategy', 'complete_flow')
        target_params = fuzz_config.get('target_params', [])
        payload_category = fuzz_config.get('payload_category', 'xss')
        max_payloads = fuzz_config.get('max_payloads', 10)
        stop_on_failure = fuzz_config.get('stop_on_failure', True)
        matchers = fuzz_config.get('matchers', None)  # Custom vulnerability matchers
        
        # Load payloads
        payloads = self.payload_manager.get_payloads(payload_category)
        if not payloads:
            return [FuzzingResult(
                is_vulnerable=False,
                description=f"No payloads found for category: {payload_category}",
                request=parsed_request,
                response_status=0,
                response_size=0
            )]
        
        # Limit payloads if specified
        if max_payloads > 0:
            payloads = payloads[:max_payloads]
        
        # Determine target parameters based on configuration
        if not target_params:
            # Auto-detect target parameters from state
            target_params = self._auto_detect_target_params()
        
        colored_print(f"  Flow Fuzzer targeting parameters: {target_params}", "info")
        colored_print(f"  Strategy: {strategy}, Payloads: {len(payloads)}", "info")
        
        if strategy == 'complete_flow':
            results = self._complete_flow_fuzzing(
                flow_steps, current_step_index, payloads, target_params, 
                stop_on_failure, matchers=matchers, **kwargs
            )
        elif strategy == 'single_step':
            results = self._single_step_fuzzing(
                parsed_request, step_config, payloads, target_params, matchers=matchers, **kwargs
            )
        elif strategy == 'state_mutation':
            results = self._state_mutation_fuzzing(
                flow_steps, current_step_index, payloads, target_params,
                stop_on_failure, matchers=matchers, **kwargs
            )
        elif strategy == 'batch_flow':
             batch_size = fuzz_config.get('batch_size', 5)
             results = self._batch_flow_fuzzing(
                flow_steps, current_step_index, payloads, target_params,
                batch_size, stop_on_failure, matchers=matchers, **kwargs
            )
        else:
            results = [FuzzingResult(
                is_vulnerable=False,
                description=f"Unknown strategy: {strategy}",
                request=parsed_request,
                response_status=0,
                response_size=0
            )]
        
        return results
    
    def _complete_flow_fuzzing(self, flow_steps: List[dict], start_step: int, 
                              payloads: List[str], target_params: List[str],
                              stop_on_failure: bool, **kwargs) -> List[FuzzingResult]:
        """
        Runs complete flows for each payload, starting from the beginning (step 0).
        """
        results = []
        
        for payload in payloads:
            for param_name in target_params:
                # print(f"State: {self.state_manager._state}")
                if param_name not in self.state_manager._state:
                    continue
                
                colored_print(f"  Testing payload '{payload[:50]}...' in parameter '{param_name}'", "info")
                
                # Create a fresh state with the payload substituted
                fuzz_state = copy.deepcopy(self.state_manager)
                fuzz_state.set(param_name, payload)
                # print(f"Fuzz state: {fuzz_state._state}")
                # Run the complete flow from the beginning (step 0)
                flow_results = self._run_complete_flow(
                    fuzz_state, flow_steps, 0, payload, param_name,
                    stop_on_failure, **kwargs
                )
                results.extend(flow_results)
        
        return results
        
    def _single_step_fuzzing(self, parsed_request: dict, step_config: dict,
                           payloads: List[str], target_params: List[str], **kwargs) -> List[FuzzingResult]:
        """
        Fuzzes only the current step with payloads.
        """
        results = []
        
        colored_print(f"  Single step fuzzing with {len(payloads)} payloads on {len(target_params)} parameters", "info")
        
        for payload in payloads:
            for param_name in target_params:
                if param_name not in self.state_manager._state:
                    continue
                    
                colored_print(format_log_prefix("INFO", f"Testing payload '{payload[:50]}...' in parameter '{param_name}'"), "info")
                
                # Create a state with the payload
                fuzz_state = copy.deepcopy(self.state_manager)
                fuzz_state.set(param_name, payload)
                
                # Prepare and execute the request
                final_request = self.runner.prepare_request(
                    parsed_request, fuzz_state, step_config.get('set_headers', {})
                )
                
                try:
                    response = self.runner.run(final_request)
                    step_name = step_config.get('name', 'single_step_fuzz')
                    
                    # Enhanced vulnerability detection using baseline comparison
                    result = self.create_enhanced_result(
                        is_vulnerable=self._traditional_vulnerability_check(payload, response, kwargs.get('matchers')),
                        description=f"Single step fuzz: Payload '{payload[:50]}...' in '{param_name}'",
                        request=final_request,
                        response=response,
                        payload=payload,
                        step_name=step_name,
                        expected_vulnerable=True
                    )
                    
                    # Only report if vulnerable or baseline detected something
                    if result.is_vulnerable:
                        results.append(result)
                        
                except Exception as e:
                    colored_print(format_log_prefix("ERROR", f"Error in single step fuzzing: {str(e)}"), "error")
                    results.append(FuzzingResult(
                        is_vulnerable=False,
                        description=f"Single step fuzz error: {str(e)}",
                        request=final_request,
                        response_status=0,
                        response_size=0,
                        payload=payload
                    ))
        
        return results
    
    def _state_mutation_fuzzing(self, flow_steps: List[dict], start_step: int,
                              payloads: List[str], target_params: List[str],
                              stop_on_failure: bool, **kwargs) -> List[FuzzingResult]:
        """
        Mutates state variables at different points in the flow.
        """
        results = []
        
        colored_print(format_log_prefix("INFO", f"State mutation fuzzing across {len(flow_steps)} steps"), "info")
        
        # Try injecting payloads at different steps in the flow
        for injection_step in range(start_step, min(len(flow_steps), start_step + 3)):
            for payload in payloads[:5]:  # Limit for mutation strategy
                for param_name in target_params:
                    colored_print(format_log_prefix("INFO", f"Injecting '{payload[:30]}...' in '{param_name}' at step {injection_step}"), "info")
                    
                    # Run flow until injection point, then inject payload
                    mutation_results = self._run_flow_with_mutation(
                        flow_steps, injection_step, param_name, payload, stop_on_failure, **kwargs
                    )
                    results.extend(mutation_results)
        
        return results
    
    def _run_complete_flow(self, fuzz_state: StateManager, flow_steps: List[dict], 
                          start_step: int, payload: str, param_name: str,
                          stop_on_failure: bool, **kwargs) -> List[FuzzingResult]:
        """
        Runs a complete flow from the specified step onwards with a payload substituted.
        
        Args:
            fuzz_state: StateManager with the payload substituted
            flow_steps: List of flow step configurations
            start_step: Index of the step to start from
            payload: The payload being tested
            param_name: The parameter name where the payload was substituted
            stop_on_failure: Whether to stop the flow on any failure
            **kwargs: Additional context including flow_context
            
        Returns:
            List of FuzzingResult objects from the flow execution
        """
        results = []
        vulnerabilities_found = []
        
        colored_print(format_log_prefix("INFO", f"Running complete flow from step {start_step} with payload in '{param_name}'..."), "info")
        
        # Get flow_context from kwargs
        flow_context = kwargs.get('flow_context', None)
        if not flow_context:
            colored_print(format_log_prefix("ERROR", f"No flow_context found in kwargs"), "error")
            return results
        
        # Get context from flow_context
        requests_dir = flow_context.get('requests_dir', 'requests')
        target = flow_context.get('target', None)
        if not target:
            colored_print(format_log_prefix("ERROR", f"No target found in flow_context"), "error")
            return results
        
        # Store the original payload to preserve it throughout the flow
        original_payload = payload
        
        try:
            # Execute each step in the flow starting from the specified step
            for step_index in range(start_step, len(flow_steps)):
                step = flow_steps[step_index]
                if not step.get('enable', True):
                    continue
                
                step_name = step.get('name', f"Step {step_index}")
                colored_print(format_log_prefix("INFO", f"Executing: {step_name}"), "info")
                
                # Load the request for this step using the runner's method
                try:
                    parsed_request = self.runner.load_request_from_file(
                        step['request'], target, requests_dir
                    )
                except Exception as e:
                    colored_print(format_log_prefix("ERROR", f"Error loading request file '{step['request']}': {str(e)}"), "error")
                    results.append(FuzzingResult(
                        is_vulnerable=False,
                        description=f"Flow error: Failed to load request file '{step['request']}' in step '{step_name}': {str(e)}",
                        request={},
                        response_status=0,
                        response_size=0,
                        payload=original_payload
                    ))
                    if stop_on_failure:
                        colored_print(format_log_prefix("ERROR", f"Stopping flow due to request file loading failure"), "error")
                        break
                    continue
                
                # Prepare the final request
                final_request = self.runner.prepare_request(
                    parsed_request, fuzz_state, step.get('set_headers', {})
                )
                
                try:
                    # Use the existing runner to execute the request
                    response = self.runner.run(final_request)
                    
                    # Enhanced vulnerability detection using baseline comparison
                    traditional_vulnerable = self._traditional_vulnerability_check(original_payload, response, kwargs.get('matchers'))
                    
                    result = self.create_enhanced_result(
                        is_vulnerable=traditional_vulnerable,
                        description=f"Flow step '{step_name}': Payload '{original_payload[:50]}...' in '{param_name}'",
                        request=final_request,
                        response=response,
                        payload=original_payload,
                        step_name=step_name,
                        expected_vulnerable=True
                    )
                    
                    # Check if vulnerability was detected (traditional or baseline)
                    if result.is_vulnerable:
                        vulnerability_info = {
                            'step_index': step_index,
                            'step_name': step_name,
                            'payload': original_payload,
                            'param_name': param_name,
                            'status_code': response.status_code,
                            'response_size': len(response.content),
                            'baseline_analysis': result.baseline_comparison
                        }
                        vulnerabilities_found.append(vulnerability_info)
                        
                        # Add contextual information based on baseline analysis
                        if result.baseline_comparison and result.baseline_comparison.get("baseline_available"):
                            anomalies = result.anomaly_details or []
                            anomaly_types = [a.get("type") for a in anomalies]
                            confidence = result.baseline_comparison.get("confidence", 0.0)
                            
                            enhanced_description = result.description
                            if "unexpected_status_code" in anomaly_types:
                                enhanced_description += f" (Status anomaly detected with {confidence:.1%} confidence)"
                            if "unexpected_response_size" in anomaly_types:
                                enhanced_description += f" (Response size anomaly with {confidence:.1%} confidence)"
                            if "missing_response_patterns" in anomaly_types:
                                enhanced_description += f" (Response pattern disruption with {confidence:.1%} confidence)"
                                
                            result = result._replace(description=enhanced_description)
                        
                        results.append(result)
                    
                    # Extract and update state for next steps (this maintains flow state)
                    # But preserve the fuzzing payload by restoring it after extraction
                    fuzz_state.extract_and_update(response, step.get('extract', {}))
                    
                    # Restore the fuzzing payload if it was overwritten during extraction
                    if param_name in fuzz_state._state:
                        # Check if the value was changed during extraction
                        current_value = fuzz_state._state[param_name]
                        if current_value != original_payload:
                            colored_print(format_log_prefix("INFO", f"Restoring fuzzing payload '{original_payload[:50]}...' in '{param_name}' (was overwritten with '{str(current_value)[:50]}...')"), "info")
                            fuzz_state.set(param_name, original_payload)
                    
                    fuzz_state.clear_request_scoped_vars()
                    
                except Exception as e:
                    colored_print(format_log_prefix("ERROR", f"Error in step {step_name}: {str(e)}"), "error")
                    results.append(FuzzingResult(
                        is_vulnerable=False,
                        description=f"Flow error: Step '{step_name}' failed with payload '{original_payload}' in '{param_name}': {str(e)}",
                        request=parsed_request,
                        response_status=0,
                        response_size=0,
                        payload=original_payload
                    ))
                    
                    if step.get('required', False) or stop_on_failure:
                        colored_print(format_log_prefix("ERROR", f"Step '{step_name}' failed. Stopping flow."), "error")
                        break
                    else:
                        colored_print(format_log_prefix("ERROR", f"Non-required step '{step_name}' failed. Continuing flow."), "error")
            
            # Summary of flow execution with enhanced information
            if vulnerabilities_found:
                colored_print(f"[!] Found {len(vulnerabilities_found)} vulnerabilities across the flow", "vulnerability")
                for vuln in vulnerabilities_found:
                    baseline_info = ""
                    if vuln.get('baseline_analysis') and vuln['baseline_analysis'].get('baseline_available'):
                        confidence = vuln['baseline_analysis'].get('confidence', 0.0)
                        baseline_info = f" (Baseline confidence: {confidence:.1%})"
                    colored_print(f"      - {vuln['step_name']}: Status {vuln['status_code']}, Payload: {vuln['payload'][:30]}...{baseline_info}", "vulnerability")
            else:
                colored_print(f"    -> Flow completed without detected vulnerabilities", "success")
                
        except Exception as e:
            colored_print(format_log_prefix("ERROR", f"Error running flow: {str(e)}"), "error")
            results.append(FuzzingResult(
                is_vulnerable=False,
                description=f"Flow execution failed with payload '{original_payload}' in '{param_name}': {str(e)}",
                request=parsed_request,
                response_status=0,
                response_size=0,
                payload=original_payload
            ))
        
        return results
    
    def _run_flow_with_mutation(self, flow_steps: List[dict], injection_step: int,
                              param_name: str, payload: str, stop_on_failure: bool, **kwargs) -> List[FuzzingResult]:
        """
        Runs a flow and injects a payload at a specific step.
        """
        results = []
        
        # This is a simplified implementation for mutation fuzzing
        # In practice, you might want to run the flow up to the injection point,
        # then inject the payload and continue
        
        fuzz_state = copy.deepcopy(self.state_manager)
        
        # For now, just inject at the beginning and run the flow
        fuzz_state.set(param_name, payload)
        
        # Run a subset of the flow
        mutation_results = self._run_complete_flow(
            fuzz_state, flow_steps, injection_step, payload, param_name, stop_on_failure, **kwargs
        )
        
        return mutation_results
    
    def _traditional_vulnerability_check(self, payload: str, response, matchers: List[Dict] = None) -> bool:
        """
        Vulnerability detection using custom matchers if provided, else fallback to hardcoded patterns.
        
        Args:
            payload: The payload that was tested
            response: The HTTP response object
            matchers: Optional list of matcher configs from YAML
            
        Returns:
            True if vulnerable, False otherwise
        """
        # Use custom matchers if provided
        if matchers:
            return self.check_custom_matchers(response, matchers)
        
        # Fallback: Check if payload is reflected
        reflected = payload in response.text
        
        # Fallback: Check for interesting status codes
        interesting_status = response.status_code >= 400
        
        # Fallback: Check for error patterns
        error_patterns = ['error', 'exception', 'stack trace', 'debug', 'sql', 'syntax']
        error_indicated = any(pattern in response.text.lower() for pattern in error_patterns)
        
        return reflected or interesting_status or error_indicated
    
    def _auto_detect_target_params(self) -> List[str]:
        """
        Automatically detect parameters in the state that are good targets for fuzzing.
        """
        if not self.state_manager or not self.state_manager._state:
            return []
        
        # Skip common authentication/session parameters
        skip_params = {
            'token', 'session', 'auth', 'authorization', 'jwt', 'cookie',
            'username', 'password', 'email', 'user_id', 'session_id'
        }
        
        target_params = []
        for param_name, param_value in self.state_manager._state.items():
            # Skip if it's in the skip list
            if any(skip in param_name.lower() for skip in skip_params):
                continue
                
            # Only include string parameters that might be injectable
            if isinstance(param_value, str) and len(param_value) > 0:
                target_params.append(param_name)
        
        return target_params[:5]  # Limit to first 5 to avoid too many combinations
    
    def _batch_flow_fuzzing(self, flow_steps: List[dict], current_step_index: int,
                          payloads: List[str], target_params: List[str],
                          batch_size: int, stop_on_failure: bool, **kwargs) -> List[FuzzingResult]:
        """
        Runs payloads in batches. For each batch, it re-runs the previous steps (setup)
        to get a fresh state (e.g., new OTP, new Transaction ID), then fuzzes the current step.
        """
        results = []
        flow_context = kwargs.get('flow_context', {})
        requests_dir = flow_context.get('requests_dir', 'requests')
        target = flow_context.get('target', None)
        
        # Calculate number of batches
        total_batches = (len(payloads) + batch_size - 1) // batch_size
        
        colored_print(f"  Batch Flow Fuzzing: {len(payloads)} payloads in {total_batches} batches (size {batch_size})", "info")
        
        for batch_idx, i in enumerate(range(0, len(payloads), batch_size)):
            batch_payloads = payloads[i:i + batch_size]
            colored_print(f"  Processing Batch {batch_idx + 1}/{total_batches} ({len(batch_payloads)} payloads)", "info")
            
            # 1. Setup Phase: Run flow from start to just before current step
            # Create a fresh state for this batch
            batch_state = copy.deepcopy(self.state_manager)
            
            # Execute steps 0 to current_step_index - 1
            setup_success = True
            if current_step_index > 0:
                colored_print(f"    Running setup steps (0 to {current_step_index-1}) for batch...", "info")
                setup_success = self._execute_clean_flow_steps(
                    batch_state, flow_steps, 0, current_step_index, 
                    requests_dir, target
                )
            
            if not setup_success:
                colored_print(f"    Batch setup failed. Skipping batch {batch_idx + 1}", "error")
                results.append(FuzzingResult(
                    is_vulnerable=False,
                    description=f"Batch {batch_idx+1} setup failed",
                    request={},
                    response_status=0,
                    response_size=0
                ))
                continue
            
            # 2. Attack Phase: Fuzz the current step using the prepared batch_state
            # We use the current step configuration
            step_config = flow_steps[current_step_index]
            step_name = step_config.get('name', f"Step {current_step_index}")
            
            for payload in batch_payloads:
                for param_name in target_params:
                    # Note: We check if param exists in the BATCH state, which spans from the setup
                    if param_name not in batch_state._state:
                        continue
                        
                    colored_print(format_log_prefix("INFO", f"Testing payload '{payload[:30]}...' in '{param_name}'"), "info")
                    
                    # Fork state for this specific payload test (don't corrupt the batch_state)
                    test_state = copy.deepcopy(batch_state)
                    test_state.set(param_name, payload)
                    
                    try:
                        # Load request
                        parsed_request = self.runner.load_request_from_file(
                            step_config['request'], target, requests_dir
                        )
                        
                        # Prepare request
                        final_request = self.runner.prepare_request(
                            parsed_request, test_state, step_config.get('set_headers', {})
                        )
                        
                        # Execute
                        response = self.runner.run(final_request)
                        
                        # Check vulnerability
                        result = self.create_enhanced_result(
                            is_vulnerable=self._traditional_vulnerability_check(payload, response, kwargs.get('matchers')),
                            description=f"Batch {batch_idx+1}: Payload '{payload[:30]}...' in '{param_name}'",
                            request=final_request,
                            response=response,
                            payload=payload,
                            step_name=step_name,
                            expected_vulnerable=True
                        )
                        
                        if result.is_vulnerable:
                            results.append(result)
                            colored_print(f"      [!] Vulnerability found: {result.description}", "vulnerability")
                        
                        # Continue flow after injection: extract state and run remaining steps
                        test_state.extract_and_update(response, step_config.get('extract', {}))
                        
                        # Restore the fuzzing payload if it was overwritten during extraction
                        if param_name in test_state._state and test_state._state[param_name] != payload:
                            test_state.set(param_name, payload)
                        
                        test_state.clear_request_scoped_vars()
                        
                        # Run remaining steps (current_step_index + 1 onwards)
                        if current_step_index + 1 < len(flow_steps):
                            remaining_results = self._run_complete_flow(
                                test_state, flow_steps, current_step_index + 1, 
                                payload, param_name, stop_on_failure, **kwargs
                            )
                            results.extend(remaining_results)
                            
                    except Exception as e:
                        colored_print(format_log_prefix("ERROR", f"Error in batch fuzzing: {str(e)}"), "error")
                        
        return results

    def _execute_clean_flow_steps(self, state: StateManager, flow_steps: List[dict], 
                                start_index: int, end_index: int, 
                                requests_dir: str, target: str) -> bool:
        """
        Executes a range of flow steps without fuzzing, purely to build up state.
        
        Args:
            state: The StateManager to update (modified in-place)
            flow_steps: List of all steps
            start_index: Inclusive start index
            end_index: Exclusive end index
            requests_dir: Directory for request files
            target: Target URL base
            
        Returns:
            bool: True if all steps succeeded, False otherwise
        """
        for i in range(start_index, end_index):
            step = flow_steps[i]
            if not step.get('enable', True):
                continue
                
            step_name = step.get('name', f"Step {i}")
            
            try:
                # Load request
                parsed_request = self.runner.load_request_from_file(
                    step['request'], target, requests_dir
                )
                
                # Prepare request (no payload injection here, just normal flow)
                final_request = self.runner.prepare_request(
                    parsed_request, state, step.get('set_headers', {})
                )
                
                # Execute
                response = self.runner.run(final_request)
                
                # Check for failure (simple check: 4xx or 5xx might indicate broken setup)
                # But sometimes 4xx is expected? For setup, we generally expect success (2xx/3xx)
                # We'll validte based on if we can extract what we need.
                
                # Extract variables
                state.extract_and_update(response, step.get('extract', {}))
                state.clear_request_scoped_vars()
                
            except Exception as e:
                colored_print(format_log_prefix("ERROR", f"Setup step '{step_name}' failed: {str(e)}"), "error")
                return False
                
        return True

    async def arun(self, parsed_request: dict, step_config: dict, **kwargs) -> List[FuzzingResult]:
        """
        Async wrapper for the run method.
        """
        return self.run(parsed_request, step_config, **kwargs)
    
 