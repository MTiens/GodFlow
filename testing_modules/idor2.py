import copy
from typing import Dict, List, Union, Optional, Any
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.state import StateManager
from urllib.parse import urlparse, urljoin
from core.colors import colored_print, format_log_prefix, color_formatter

class IdorModule(FuzzingModule):
    """
    IDOR/BOLA Fuzzing Module

    This module tests for Broken Object Level Authorization (BOLA) and Insecure Direct Object References (IDOR)
    by attempting to access resources belonging to a 'victim' user while authenticated as an 'attacker' user.

    Strategy:
    1.  **Multi-Persona State**: It requires defining at least two personas (e.g., 'user1' (attacker) and 'user2' (victim))
        in the `personas` configuration.
    2.  **State Establishment**: Before fuzzing, it establishes valid sessions/states for all personas by running
        the flow up to the current step for each of them.
    3.  **Cross-Account Access**: It then iterates through defined `flow_steps`, injecting the victim's sensitive
        parameters (like `user_id`, `account_id`) into the attacker's request state.
    4.  **Verification**: If the attacker can successfully access the victim's resource (2xx response), a potential
        BOLA vulnerability is reported.

    Configuration (`fuzz.idor2`):
    - `enable` (bool): Enable/disable this module.
    - `personas` (list[str]): List of persona keys to use (must verify `all_personas` in flow context).
    - `attacker_roles` (list[str], optional): Only use personas with these roles as attackers.
    - `victim_roles` (list[str], optional): Only use personas with these roles as victims.
    - `object_id_params` (dict[str, list[str]]): Map of step keys (e.g., 'step1', 'step2') to list of parameter names
      that should be swapped (e.g., `['user_id']`).
    - `flow_steps` (list[str|dict]): List of steps to test. Can be filenames (`request.txt`) or inline dicts.
    - `precondition_step` (str|dict, optional): A step to run for the victim before the attack (e.g., to create a resource).

    Example YAML:
    ```yaml
    fuzz:
      idor2:
        enable: true
        personas: ["user_a", "user_b"]
        object_id_params:
          step1: ["account_id"]
        flow_steps:
          - "requests/get_account_details.txt"
    ```
    """
    key = "idor2"

    def _load_request_from_file(self, filename: str, target: str, requests_dir: str = "requests") -> dict:
        """Load and parse a request from a .txt file using the runner."""
        return self.runner.load_request_from_file(filename, target, requests_dir)

    async def prepare(self, step_config: dict, flow_context: dict) -> bool:
        """Establish valid states for all required personas."""
        import asyncio
        
        fuzz_config = step_config.get("fuzz", {}).get(self.key, {})
        if not fuzz_config.get("enable", True):
            return False

        state_factory = flow_context.get('state_factory')
        if not state_factory:
            # print(f"[{self.key}] No state_factory provided")
            return False

        all_personas = flow_context.get('all_personas', {})
        personas = fuzz_config.get("personas")
        persona_keys = personas if personas else list(all_personas.keys())

        if len(persona_keys) < 2:
            return False

        # Determine target_step_index logic (copied from Orchestrator)
        current_step_index = flow_context.get('current_step_index', 0)
        target_step_index = current_step_index

        flow_steps = fuzz_config.get('flow_steps', [])
        if flow_steps:
            first_flow_step = flow_steps[0]
            # If flow_step is a dict, we might need a way to match?
            # Assuming string for file matching logic usually used
            if isinstance(first_flow_step, str):
                all_steps = flow_context.get('steps', [])
                for step_idx, flow_step in enumerate(all_steps):
                    if flow_step.get('request') == first_flow_step:
                        # Run up to and including this step (so +1?)
                        # Original logic was: target_step_index = step_idx + 1
                        target_step_index = step_idx + 1
                        break
        
        # Run flow for each persona concurrently
        tasks = [state_factory(target_step_index, all_personas.get(key, {})) for key in persona_keys]
        established_states_list = await asyncio.gather(*tasks)
        
        self.established_states = {
            key: state for key, state in zip(persona_keys, established_states_list) if state
        }

        # Need to store flow_context for run usage if needed, or pass it
        # The run method signature expects **kwargs, so we can pass established_states there?
        # Typically run() is called by orchestrator. If we store established_states in self,
        # we can access it in run().
        
        return len(self.established_states) >= 2

    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> List[FuzzingResult]:
        results = []
        fuzz_config = step_config.get("fuzz", {}).get(self.key, {})

        # --- Enable flag support ---
        if fuzz_config.get("enable") is False:
            return []

        established_states: Dict[str, StateManager] = kwargs.get("established_states", {})

        # Support both single parameter (backward compatibility) and multi-parameter configs
        object_id_param: Optional[str] = fuzz_config.get("object_id_param")  # Legacy single param
        object_id_params: Dict[str, List[str]] = fuzz_config.get("object_id_params", {})  # New multi-param per step
        
        attacker_roles: Optional[List[str]] = fuzz_config.get("attacker_roles")
        victim_roles: Optional[List[str]] = fuzz_config.get("victim_roles")
        personas: List[str] = fuzz_config.get("personas", list(established_states.keys()))
        additional_victim_keys: List[str] = fuzz_config.get("additional_victim_keys", [])
        matchers: Optional[List[Dict[str, Any]]] = fuzz_config.get("matchers")  # Custom vulnerability matchers

        # --- Requests dir and target ---
        requests_dir: str = step_config.get("requests_dir", "requests")
        target: str = step_config.get("target", "")

        # --- Multi-step config: support .txt file path or inline dict ---
        precondition_step: Optional[Union[str, dict]] = fuzz_config.get("precondition_step")  # Optional
        if isinstance(precondition_step, str) and precondition_step.endswith(".txt"):
            precondition_step = self._load_request_from_file(precondition_step, target, requests_dir)
        flow_steps: List[Union[str, dict]] = fuzz_config.get("flow_steps", [parsed_request])  # Support multiple steps
        new_flow_steps: List[Any] = []
        for step in flow_steps:
            if isinstance(step, str) and step.endswith(".txt"):
                new_flow_steps.append(self._load_request_from_file(step, target, requests_dir))
            else:
                new_flow_steps.append(step)
        flow_steps = new_flow_steps

        # Validate configuration
        if not object_id_param and not object_id_params:
            return [FuzzingResult(False, "Missing 'object_id_param' or 'object_id_params' in fuzz config.", {}, 0, 0)]
        if len(established_states) < 2:
            return [FuzzingResult(False, "Not enough persona states to test.", {}, 0, 0)]

        def get_role(state: StateManager) -> Optional[str]:
            return state.get("role")

        def get_params_for_step(step_idx: int) -> List[str]:
            """Get the parameters to check for a specific step"""
            if object_id_params:
                # New multi-param format
                step_key = f"step{step_idx + 1}"
                return object_id_params.get(step_key, [])
            else:
                # Legacy single param format
                return [object_id_param] if object_id_param else []

        for attacker_name in personas:
            for victim_name in personas:
                if attacker_name == victim_name:
                    continue
                attacker_state: StateManager = established_states[attacker_name]
                victim_state: StateManager = established_states[victim_name]

                attacker_role: Optional[str] = get_role(attacker_state)
                victim_role: Optional[str] = get_role(victim_state)

                if attacker_roles and attacker_role not in attacker_roles:
                    continue
                if victim_roles and victim_role not in victim_roles:
                    continue

                # Check if victim has all required parameters for any step
                all_required_params: set = set()
                for step_idx in range(len(flow_steps)):
                    step_params = get_params_for_step(step_idx)
                    all_required_params.update(step_params)
                
                # Verify victim has at least one required parameter
                victim_has_params = any(victim_state.get(param) for param in all_required_params)
                if not victim_has_params:
                    continue

                colored_print(f"  -> Testing BOLA: {attacker_name} vs {victim_name}", "info")

                # Step 1: victim performs precondition (e.g., init transaction)
                if precondition_step:
                    pre_step_to_send: dict = copy.deepcopy(precondition_step)  # type: ignore
                    if "body" in pre_step_to_send:
                        pre_step_to_send["json"] = pre_step_to_send.pop("body")
                    if pre_step_to_send.get("url", "").startswith("/"):
                        pre_base_url: Optional[str] = None
                        if 'target' in step_config:
                            pre_base_url = step_config['target']
                        elif 'url' in parsed_request:
                            parsed = urlparse(parsed_request['url'])
                            pre_base_url = f"{parsed.scheme}://{parsed.netloc}"
                        if pre_base_url:
                            pre_step_to_send['url'] = urljoin(pre_base_url, pre_step_to_send['url'])
                    pre_req = self.runner.prepare_request(pre_step_to_send, victim_state)
                    try:
                        pre_resp = self.runner.run(pre_req)
                        print(f"  -> Victim pre-step response: {color_formatter.status_code(pre_resp.status_code)}", "info")
                    except Exception as e:
                        colored_print(f"Pre-step failed: {e}", "error")
                        continue

                # Step 2: attacker tries to hijack each step
                for step_idx, step in enumerate(flow_steps):
                    step_params = get_params_for_step(step_idx)
                    if not step_params:
                        continue

                    attack_state = copy.deepcopy(attacker_state)
                    
                    # Set all victim's parameters for this step into attacker's state
                    params_used = []
                    for param in step_params:
                        victim_value = victim_state.get(param)
                        if victim_value:
                            attack_state.set(param, victim_value)
                            params_used.append(f"{param}={victim_value}")
                    
                    # Set additional victim keys if specified
                    for key in additional_victim_keys:
                        val = victim_state.get(key)
                        if val:
                            attack_state.set(key, val)

                    if not params_used:
                        continue

                    colored_print(f"  -> Step {step_idx + 1}: Testing params {', '.join(params_used)}", "info")

                    # Prepare the request, converting 'body' to 'json' if present
                    step_to_send: dict = copy.deepcopy(step)  # type: ignore
                    if "body" in step_to_send:
                        step_to_send["json"] = step_to_send.pop("body")
                    # Ensure URL is absolute using config's TARGET
                    if step_to_send.get("url", "").startswith("/"):
                        step_base_url: Optional[str] = None
                        if 'target' in step_config:
                            step_base_url = step_config['target']
                        elif 'url' in parsed_request:
                            parsed = urlparse(parsed_request['url'])
                            step_base_url = f"{parsed.scheme}://{parsed.netloc}"
                        if step_base_url:
                            step_to_send['url'] = urljoin(step_base_url, step_to_send['url'])
                    request_to_send = self.runner.prepare_request(step_to_send, attack_state)
                    try:
                        response = self.runner.run(request_to_send)

                        # Determine vulnerability using matchers if defined, else fallback
                        if matchers:
                            is_vuln = self.check_custom_matchers(response, matchers)
                        else:
                            is_vuln = 200 <= response.status_code < 300

                        if is_vuln:
                            result = self.create_enhanced_result(
                                is_vulnerable=True,
                                description=f"BOLA Detected (Step {step_idx + 1}): Attacker {attacker_name} accessed victim {victim_name}'s resource using params: {', '.join(params_used)}",
                                request=request_to_send,
                                response=response,
                                payload=f"Step {step_idx + 1} params: {', '.join(params_used)}",
                                step_name=f"Step {step_idx + 1}",
                                expected_vulnerable=True
                            )
                            # Append baseline anomaly conclusions to description
                            result = self.enhance_result_with_baseline(result)
                            results.append(result)
                        else:
                            result = self.create_enhanced_result(
                                is_vulnerable=False,
                                description=f"Access blocked (Step {step_idx + 1}): Attacker {attacker_name} -> Victim {victim_name} using params: {', '.join(params_used)} (status {response.status_code})",
                                request=request_to_send,
                                response=response,
                                payload=f"Step {step_idx + 1} params: {', '.join(params_used)}",
                                step_name=f"Step {step_idx + 1}",
                                expected_vulnerable=False
                            )
                            # Append baseline anomaly conclusions to description
                            result = self.enhance_result_with_baseline(result)
                            results.append(result)

                    except Exception as e:
                        colored_print(f"BOLA step {step_idx + 1} failed: {e}", "error")
        return results
