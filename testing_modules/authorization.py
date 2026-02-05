import copy
from typing import Dict, List, Optional
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.state import StateManager
from core.colors import colored_print, format_log_prefix

class AuthorizationModule(FuzzingModule):
    """
    Authorization testing module for role-based access control (RBAC) vulnerabilities.
    Tests if users without proper roles can access protected resources.
    """
    key = "authorization"

    async def prepare(self, step_config: dict, flow_context: dict) -> bool:
        """Establish valid states for all required personas."""
        import asyncio
        
        fuzz_config = step_config.get("fuzz", {}).get(self.key, {})
        if not fuzz_config.get("enable", True):
            return False

        # Get the callback function to run the flow
        state_factory = flow_context.get('state_factory')
        if not state_factory:
            return False

        personas = fuzz_config.get("personas")
        # If no specific personas listed, we might need a way to know all available personas.
        # But usually strict config is better. Alternatively get from flow_context if available.
        # For now, let's assume we need to access all known personas if not specified.
        # Orchestrator's 'personas' dict should be in flow_context if we want to default to "all".
        all_personas = flow_context.get('all_personas', {})
        persona_keys = personas if personas else list(all_personas.keys())
        
        if len(persona_keys) < 2:
            return False
            
        current_step_index = flow_context.get('current_step_index', 0)
        
        # Run flow for each persona concurrently
        tasks = [state_factory(current_step_index, all_personas.get(key, {})) for key in persona_keys]
        established_states_list = await asyncio.gather(*tasks)
        
        self.established_states = {
            key: state for key, state in zip(persona_keys, established_states_list) if state
        }
        
        return len(self.established_states) >= 1

    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> List[FuzzingResult]:
        """
        Performs authorization testing by checking if users can access resources
        they shouldn't have access to based on their roles.
        """
        results = []
        fuzz_config = step_config.get("fuzz", {}).get(self.key, {})

        # Check if the module is enabled
        if not fuzz_config.get("enable", True):
            return [FuzzingResult(False, "Authorization module is disabled for this step.", {}, 0, 0)]

        # Get the established states from the orchestrator
        established_states: Dict[str, StateManager] = kwargs.get("established_states", {})

        # Configuration parameters
        required_roles = fuzz_config.get("required_roles", [])  # Roles that should have access
        forbidden_roles = fuzz_config.get("forbidden_roles", [])  # Roles that should NOT have access
        personas = fuzz_config.get("personas")  # Optional: restrict testing to specific personas
        
        if not established_states:
            return [FuzzingResult(False, "No established persona states available for testing.", {}, 0, 0)]

        # Filter personas by config if provided
        persona_names = personas if personas else list(established_states.keys())

        # Test 1: Users with forbidden roles should not have access
        if forbidden_roles:
            results.extend(self._test_forbidden_roles(
                parsed_request, step_config, established_states, 
                persona_names, forbidden_roles
            ))

        # Test 2: Users with insufficient roles should not have access
        if required_roles:
            results.extend(self._test_insufficient_roles(
                parsed_request, step_config, established_states,
                persona_names, required_roles
            ))

        # Test 3: Role escalation attempts
        # results.extend(self._test_role_escalation(
        #     parsed_request, step_config, established_states, persona_names
        # ))

        return results

    def _test_forbidden_roles(self, parsed_request: dict, step_config: dict, 
                            established_states: Dict[str, StateManager], 
                            persona_names: List[str], forbidden_roles: List[str]) -> List[FuzzingResult]:
        """Test that users with forbidden roles cannot access the resource."""
        results = []
        
        for persona_name in persona_names:
            persona_state = established_states[persona_name]
            persona_role = self._get_role(persona_state)
            
            if persona_role in forbidden_roles:
                colored_print(f"  -> Testing forbidden role access: '{persona_name}' (role={persona_role})", "info")
                
                final_request = self.runner.prepare_request(
                    parsed_request, persona_state, step_config.get('set_headers', {})
                )
                
                try:
                    response = self.runner.run(final_request)
                    
                    if 200 <= response.status_code < 300:
                        result = self.create_enhanced_result(
                            is_vulnerable=True,
                            description=f"Authorization bypass! User '{persona_name}' with forbidden role '{persona_role}' successfully accessed the resource.",
                            request=final_request,
                            response=response,
                            payload=f"Forbidden role: {persona_role}",
                            step_name=persona_name,
                            expected_vulnerable=True
                        )
                        result = self.enhance_result_with_baseline(result)
                        results.append(result)
                    else:
                        result = self.create_enhanced_result(
                            is_vulnerable=False,
                            description=f"Access correctly denied for user '{persona_name}' with forbidden role '{persona_role}' (Status: {response.status_code}).",
                            request=final_request,
                            response=response,
                            payload=f"Forbidden role: {persona_role}",
                            step_name=persona_name,
                            expected_vulnerable=False
                        )
                        result = self.enhance_result_with_baseline(result)
                        results.append(result)
                        
                except Exception as e:
                    colored_print(f"Authorization module request failed for {persona_name}: {e}", "error")
        
        return results

    def _test_insufficient_roles(self, parsed_request: dict, step_config: dict,
                               established_states: Dict[str, StateManager],
                               persona_names: List[str], required_roles: List[str]) -> List[FuzzingResult]:
        """Test that users without required roles cannot access the resource."""
        results = []
        
        for persona_name in persona_names:
            persona_state = established_states[persona_name]
            persona_role = self._get_role(persona_state)
            
            # Skip if user has one of the required roles
            if persona_role in required_roles:
                continue
                
            colored_print(f"  -> Testing insufficient role access: '{persona_name}' (role={persona_role})", "info")
            
            final_request = self.runner.prepare_request(
                parsed_request, persona_state, step_config.get('set_headers', {})
            )
            
            try:
                response = self.runner.run(final_request)
                
                if 200 <= response.status_code < 300:
                    results.append(FuzzingResult(
                        is_vulnerable=True,
                        description=f"Authorization bypass! User '{persona_name}' with insufficient role '{persona_role}' successfully accessed resource requiring roles: {required_roles}.",
                        request=final_request,
                        response_status=response.status_code,
                        response_size=len(response.content),
                        payload=f"Insufficient role: {persona_role}, required: {required_roles}"
                    ))
                else:
                    results.append(FuzzingResult(
                        is_vulnerable=False,
                        description=f"Access correctly denied for user '{persona_name}' with insufficient role '{persona_role}' (Status: {response.status_code}).",
                        request=final_request,
                        response_status=response.status_code,
                        response_size=len(response.content)
                    ))
                    
            except Exception as e:
                colored_print(f"Authorization module request failed for {persona_name}: {e}", "error")
        
        return results



    def _test_role_escalation(self, parsed_request: dict, step_config: dict,
                            established_states: Dict[str, StateManager],
                            persona_names: List[str]) -> List[FuzzingResult]:
        """Test role escalation by modifying role claims in tokens or headers."""
        results = []
        
        # Common role escalation attempts
        escalation_roles = ["admin", "administrator", "root", "superuser", "system"]
        
        for persona_name in persona_names:
            persona_state = established_states[persona_name]
            original_role = self._get_role(persona_state)
            
            # Skip if already has high privileges
            if original_role in escalation_roles:
                continue
                
            for escalation_role in escalation_roles:
                if escalation_role == original_role:
                    continue
                    
                colored_print(f"  -> Testing role escalation: '{persona_name}' (role={original_role}) -> {escalation_role}", "info")
                
                # Create modified state with escalated role
                escalated_state = copy.deepcopy(persona_state)
                escalated_state.set("role", escalation_role)
                
                # Try to modify role in headers/tokens if possible
                modified_headers = self._modify_role_in_headers(
                    step_config.get('set_headers', {}), escalation_role
                )
                
                final_request = self.runner.prepare_request(
                    parsed_request, escalated_state, modified_headers
                )
                
                try:
                    response = self.runner.run(final_request)
                    
                    if 200 <= response.status_code < 300:
                        results.append(FuzzingResult(
                            is_vulnerable=True,
                            description=f"Role escalation successful! User '{persona_name}' escalated from '{original_role}' to '{escalation_role}'.",
                            request=final_request,
                            response_status=response.status_code,
                            response_size=len(response.content),
                            payload=f"Role escalation: {original_role} -> {escalation_role}"
                        ))
                    else:
                        results.append(FuzzingResult(
                            is_vulnerable=False,
                            description=f"Role escalation correctly prevented for user '{persona_name}' ({original_role} -> {escalation_role}) (Status: {response.status_code}).",
                            request=final_request,
                            response_status=response.status_code,
                            response_size=len(response.content)
                        ))
                        
                except Exception as e:
                    colored_print(f"Authorization module request failed for role escalation {persona_name}: {e}", "error")
        
        return results

    def _modify_role_in_headers(self, headers: dict, new_role: str) -> dict:
        """Attempt to modify role in headers (e.g., custom role headers)."""
        modified_headers = copy.deepcopy(headers)
        
        # Add common role headers that might be trusted by the application
        role_headers = {
            "X-User-Role": new_role,
            "X-Role": new_role,
            "User-Role": new_role,
            "Role": new_role
        }
        
        modified_headers.update(role_headers)
        return modified_headers

    def _get_role(self, state: StateManager) -> Optional[str]:
        """Extract role from state manager."""
        return state.get("role") 