import copy
from typing import Dict
from testing_modules.base_module import FuzzingModule, FuzzingResult
from core.state import StateManager
from core.parser import RequestParser
from core.colors import colored_print, format_log_prefix

class IdorModule(FuzzingModule):
    key = "idor"

    async def prepare(self, step_config: dict, flow_context: dict) -> bool:
        """Establish valid states for all required personas."""
        import asyncio
        
        fuzz_config = step_config.get("fuzz", {}).get(self.key, {})
        if not fuzz_config.get("enable", True):
            return False

        state_factory = flow_context.get('state_factory')
        if not state_factory:
            print(f"[{self.key}] No state_factory provided")
            return False

        all_personas = flow_context.get('all_personas', {})
        personas = fuzz_config.get("personas")
        persona_keys = personas if personas else list(all_personas.keys())
        
        if len(persona_keys) < 2:
            # print(f"[{self.key}] Not enough personas: {len(persona_keys)}")
            return False
            
        current_step_index = flow_context.get('current_step_index', 0)
        
        tasks = [state_factory(current_step_index, all_personas.get(key, {})) for key in persona_keys]
        established_states_list = await asyncio.gather(*tasks)
        
        self.established_states = {
            key: state for key, state in zip(persona_keys, established_states_list) if state
        }
        
        return len(self.established_states) >= 2

    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> list[FuzzingResult]:
        """
        Performs IDOR testing (Insecure Direct Object Reference) between multiple user personas and roles.
        Supports complex flows by using established states for each persona.
        """
        results = []
        fuzz_config = step_config.get("fuzz", {}).get(self.key, {})

        # Get the established states from the orchestrator
        established_states: Dict[str, StateManager] = kwargs.get("established_states", {})

        # Get the parameter that identifies the object, e.g., "userId"
        object_id_param = fuzz_config.get("object_id_param")
        attacker_roles = fuzz_config.get("attacker_roles")  # Optional: restrict attackers by role
        victim_roles = fuzz_config.get("victim_roles")      # Optional: restrict victims by role
        personas = fuzz_config.get("personas")              # Optional: restrict personas

        if not object_id_param:
            return [FuzzingResult(False, "Missing 'object_id_param' in fuzz config.", {}, 0, 0)]
        if not established_states or len(established_states) < 2:
            return [FuzzingResult(False, "Not enough established persona states to test.", {}, 0, 0)]

        # Filter personas by config if provided
        persona_names = personas if personas else list(established_states.keys())

        # Helper to get role from state (if present)
        def get_role(state: StateManager):
            return state.get("role")

        # Create all pairs of (attacker, victim) with role filtering
        for attacker_name in persona_names:
            for victim_name in persona_names:
                if attacker_name == victim_name:
                    continue
                attacker_state = established_states[attacker_name]
                victim_state = established_states[victim_name]
                attacker_role = get_role(attacker_state)
                victim_role = get_role(victim_state)
                # Role-based filtering
                if attacker_roles and attacker_role not in attacker_roles:
                    continue
                if victim_roles and victim_role not in victim_roles:
                    continue
                colored_print(f"  -> Testing: Attacker '{attacker_name}' (role={attacker_role}) vs Victim '{victim_name}' (role={victim_role})", "info")
                # Get the victim's actual resource ID value from their state
                victim_object_id = victim_state.get(object_id_param)
                if not victim_object_id:
                    colored_print(f"Victim '{victim_name}' has no value for '{object_id_param}'. Skipping.", "warning")
                    continue
                # Create a temporary state for the attacker.
                # Inject the VICTIM'S ID into the ATTACKER'S context.
                attack_state = copy.deepcopy(attacker_state)
                attack_state.set(object_id_param, victim_object_id)
                # Prepare the request using the attacker's credentials but the victim's ID
                final_request = self.runner.prepare_request(
                    parsed_request, attack_state, step_config.get('set_headers', {})
                )
                try:
                    response = self.runner.run(final_request)
                    # Analyze the response
                    # A 2xx status code is a clear sign of a vulnerability.
                    if 200 <= response.status_code < 300:
                        result = self.create_enhanced_result(
                            is_vulnerable=True,
                            description=f"IDOR Found! Attacker '{attacker_name}' (role={attacker_role}) accessed resource of '{victim_name}' (role={victim_role}) (ID: {victim_object_id}).",
                            request=final_request,
                            response=response,
                            payload=f"Victim ID: {victim_object_id}",
                            step_name=f"{attacker_name}->{victim_name}",
                            expected_vulnerable=True
                        )
                        result = self.enhance_result_with_baseline(result)
                        results.append(result)
                    else:
                        result = self.create_enhanced_result(
                            is_vulnerable=False,
                            description=f"Access correctly denied for Attacker '{attacker_name}' (role={attacker_role}) to Victim '{victim_name}' (role={victim_role}) (Status: {response.status_code}).",
                            request=final_request,
                            response=response,
                            payload=f"Victim ID: {victim_object_id}",
                            step_name=f"{attacker_name}->{victim_name}",
                            expected_vulnerable=False
                        )
                        result = self.enhance_result_with_baseline(result)
                        results.append(result)
                except Exception as e:
                    colored_print(f"IDOR module request failed: {e}", "error")
        return results