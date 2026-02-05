import json
import asyncio
from pathlib import Path
from typing import Dict, Any

# Core component imports
from core.parser import RequestParser
from core.state import StateManager
from core.runner import RequestRunner
from core.payload import PayloadManager
from core.baseline import BaselineManager, BaselineCollection
from core.colors import format_log_prefix, colored_print, color_formatter
from core.utils import substitute_all
from core.orches_utils import (
    load_config_with_inheritance,
    load_fuzzing_modules,
    report_fuzzing_results,
    extract_project_name,
    extract_flow_name,
    load_available_baselines,
)
import config


class Orchestrator:
    """
    The main engine for running API flows and fuzzing tests.

    This class reads a flow definition file, manages state, discovers and
    runs testing modules, and orchestrates the entire testing process.
    """

    def __init__(self, flow_file_path: str, requests_dir: str, payloads_dir: str, is_async: bool, verbose: bool, persona: str | None = None, proxy_config: dict | None = None, debug: bool = False, configs_dir: str | None = None):
        """
        Initializes the Orchestrator.

        Args:
            flow_file_path: Path to the JSON flow definition file.
            requests_dir: Directory containing request template files.
            payloads_dir: Directory containing payload files.
            is_async: Flag to run in asynchronous mode.
            verbose: Flag for detailed logging output.
            persona: Optional persona name to use for authentication.
            proxy_config: Optional proxy configuration dictionary.
            debug: Flag for debug mode.
            configs_dir: Directory containing config files (optional, for project-based structure).
        """
        self.flow_file_path = Path(flow_file_path)
        self.requests_dir = Path(requests_dir)
        self.configs_dir = Path(configs_dir) if configs_dir else None
        self.is_async = is_async
        self.verbose = verbose or config.VERBOSE_MODE
        self.debug = debug

        # --- Load Flow Configuration with Inheritance ---
        try:
            self.flow = load_config_with_inheritance(self.flow_file_path, self.debug, self.verbose)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load or parse flow file {flow_file_path}: {e}")

        # --- Initialize Core Components ---
        # Determine assets directory from flow file path
        assets_dir = None
        if "projects" in self.flow_file_path.parts:
            try:
                idx = self.flow_file_path.parts.index("projects")
                project_root = Path(*self.flow_file_path.parts[:idx+2])  # .../projects/<project>
                inferred_assets_dir = project_root / "assets"
                if inferred_assets_dir.exists():
                    assets_dir = str(inferred_assets_dir)
                # Initialize baseline manager for project
                self.baseline_manager = BaselineManager(str(project_root))
            except Exception:
                self.baseline_manager = BaselineManager(".")
        else:
            self.baseline_manager = BaselineManager(".")
        
        # Get timeout from config (default 30 seconds)
        timeout = self.flow.get('TIMEOUT', 30.0)
        
        self.runner = RequestRunner(is_async=self.is_async, proxy_config=proxy_config, assets_dir=assets_dir, verbose=self.verbose, debug=self.debug, timeout=timeout)
        self.payload_manager = PayloadManager(str(payloads_dir))
        self.fuzzing_modules = load_fuzzing_modules()

        # --- Extract Configuration from Flow ---
        self.target = self.flow['TARGET']
        self.variable_config = self.flow.get('VARIABLE_CONFIG', {})
        self.initial_state = self.flow.get('state', {})
        self.personas = self.flow.get('personas', {})
        self.steps = self.flow.get('steps', [])
        
        # Merge states field with state field if present
        states_field = self.flow.get('states', {})
        if states_field and isinstance(states_field, dict):
            # Merge all persona states into the initial state
            for persona_name, persona_state in states_field.items():
                if isinstance(persona_state, dict) and isinstance(self.initial_state, dict):
                    self.initial_state.update(persona_state)
        
        # Ensure initial_state is a dictionary
        if not isinstance(self.initial_state, dict):
            self.initial_state = {}
        
        # Resolve placeholders in the state first (e.g., {{util.randomNumbers(4)}})
        resolved_state = substitute_all(self.initial_state, self.initial_state)

        # Debug output if in debug mode
        if self.debug:
            colored_print(format_log_prefix("DEBUG", f"Target: {self.target}"), "debug")
            colored_print(format_log_prefix("DEBUG", f"Resolved initial state: {resolved_state}"), "debug")

        # Update with the resolved state - ensure it's a dict
        if isinstance(resolved_state, dict):
            self.initial_state = resolved_state
        else:
            self.initial_state = {}
        
        # --- Extract Project and Flow Names for Baseline Management ---
        self.project_name = extract_project_name(self.flow_file_path)
        self.flow_name = extract_flow_name(self.flow_file_path)

        # Merge persona data with initial state if specified
        self.active_persona_name = None
        if persona and persona in self.personas:
            self.active_persona_name = persona
            persona_data = self.personas[persona]
            # Substitute placeholders in persona data using the resolved state
            resolved_persona = substitute_all(persona_data, self.initial_state)
            if isinstance(resolved_persona, dict):
                self.initial_state.update(resolved_persona)
            print(f"[INFO] Using persona '{persona}' for authentication")
            if self.debug:
                colored_print(format_log_prefix("DEBUG", f"Initial state after persona merge: {self.initial_state}"), "debug")
        elif self.personas:
            # Use the first persona if none specified
            first_persona_name = list(self.personas.keys())[0]
            self.active_persona_name = first_persona_name
            persona_data = self.personas[first_persona_name]
            # Substitute placeholders in persona data using the resolved state
            resolved_persona = substitute_all(persona_data, self.initial_state)
            if isinstance(resolved_persona, dict):
                self.initial_state.update(resolved_persona)
            print(format_log_prefix("INFO", f"Using first persona '{first_persona_name}' for authentication"))
            if self.debug:
                colored_print(format_log_prefix("DEBUG", f"Initial state after persona merge: {self.initial_state}"), "debug")

        self._request_cache: Dict[str, str] = {}
        print(format_log_prefix("INFO", f"Loaded {len(self.fuzzing_modules)} fuzzing modules: {list(self.fuzzing_modules.keys())}"))

    # --- Public Methods for Lifecycle Management ---

    def close(self):
        """Closes the synchronous HTTPX client."""
        if not self.is_async:
            self.runner.close()

    async def aclose(self):
        """Closes the asynchronous HTTPX client."""
        if self.is_async:
            await self.runner.aclose()

    # --- Public Methods for Execution ---

    def run_simple_flow(self):
        """Executes the simple flow synchronously."""
        try:
            asyncio.get_running_loop()
            raise RuntimeError("run_simple_flow() called from async context. Use arun_simple_flow() instead.")
        except RuntimeError:
            asyncio.run(self._arun_simple_flow_logic())

    async def arun_simple_flow(self):
        """Executes the simple flow asynchronously."""
        await self._arun_simple_flow_logic()

    def run_baseline_collection(self):
        """Executes flow to collect baseline responses synchronously."""
        try:
            asyncio.get_running_loop()
            raise RuntimeError("run_baseline_collection() called from async context. Use arun_baseline_collection() instead.")
        except RuntimeError:
            asyncio.run(self._arun_baseline_collection_logic())

    async def arun_baseline_collection(self):
        """Executes flow to collect baseline responses asynchronously."""
        await self._arun_baseline_collection_logic()

    def run_fuzzing_in_flow(self):
        """Executes the fuzzing flow synchronously."""
        try:
            asyncio.get_running_loop()
            raise RuntimeError("run_fuzzing_in_flow() called from async context. Use arun_fuzzing_in_flow() instead.")
        except RuntimeError:
            asyncio.run(self._arun_fuzzing_in_flow_logic())

    async def arun_fuzzing_in_flow(self):
        """Executes the fuzzing flow asynchronously."""
        await self._arun_fuzzing_in_flow_logic()
    
    # --- Private Core Logic Methods ---

    async def _arun_simple_flow_logic(self):
        print("--- Running Simple Flow ---")
        state_manager = await self._arun_flow_until(len(self.steps), self.initial_state)
        if state_manager:
            print("\n--- Flow finished successfully ---")
        else:
            print("\n--- Flow failed at a required step ---")

    async def _arun_baseline_collection_logic(self):
        """Collects baseline responses by running the complete flow."""
        print("--- Running Baseline Collection ---")
        
        # Start baseline collection
        self.baseline_manager.start_collection(self.project_name, self.flow_name)
        
        # Run the complete flow and record all successful responses
        state_manager = await self._arun_flow_until(len(self.steps), self.initial_state, collect_baselines=True)
        
        if state_manager:
            # Save the collected baselines
            baseline_file = self.baseline_manager.save_collection()
            print(f"\n--- Baseline collection completed successfully ---")
            print(format_log_prefix("INFO", f"Baselines saved to: {baseline_file}"))
            
            if self.baseline_manager.current_collection and self.baseline_manager.current_collection.baselines:
                print(f"Collected {len(self.baseline_manager.current_collection.baselines)} endpoint baselines")
                
                # List the collected endpoints
                for endpoint_id, baseline in self.baseline_manager.current_collection.baselines.items():
                    print(f"  - {endpoint_id}: {baseline.method} {baseline.url_pattern} "
                          f"(success_count: {baseline.success_count})")
        else:
            print("\n--- Baseline collection failed at a required step ---")

    async def _arun_fuzzing_in_flow_logic(self):
        """The main fuzzing logic that uses the modular system."""
        print("--- Running Fuzzing in Flow ---")

        # Try to load existing baselines for enhanced detection
        baseline_collection = load_available_baselines(self.baseline_manager, self.project_name, self.flow_name)
        if baseline_collection and baseline_collection.baselines:
            print(format_log_prefix("BASELINE", f"Loaded baselines with {len(baseline_collection.baselines)} endpoints"))
        else:
            print(format_log_prefix("BASELINE", "No baselines found - using traditional detection methods"))

        for i, step in enumerate(self.steps):
            if not step.get('enable', True) or not isinstance(step.get('fuzz'), dict):
                continue
            
            step_name = step.get('name', step['request'])
            print(f"\n[+] Fuzzing Step: {step_name}")

            # Parse the request template once for this step
            raw_request = self._load_request_file(step['request'])
            # Use step-level host if defined, otherwise use default target
            step_target = step.get('host', self.target)
            parser = RequestParser(raw_request, step_target)
            parsed_request = parser.parse()
            
            # Inject requests_dir and assets_dir into step config for the module
            step['requests_dir'] = str(self.requests_dir)

            for module_key, fuzz_config in step.get('fuzz', {}).items():
                if module_key not in self.fuzzing_modules:
                    print(format_log_prefix("WARN", f"Fuzzing module '{module_key}' not found. Skipping."))
                    continue

                # Check if module is enabled (default to True if not specified)
                if not fuzz_config.get('enable', True):
                    print(f"  -> Skipping disabled module: '{module_key}'")
                    continue

                print(f"  -> Running module: '{module_key}'")
                module_class = self.fuzzing_modules[module_key]
                
                # Define flow context for module preparation
                flow_context = {
                    'requests_dir': str(self.requests_dir),
                    'target': self.target,
                    'steps': self.steps,
                    'current_step_index': i,
                    'debug': self.debug,
                    'state_factory': self._arun_flow_until,
                    'all_personas': self.personas,
                    'initial_state': self.initial_state,
                    'active_persona_name': self.active_persona_name
                }

                # Initialize module with None state manager initially
                module_instance = module_class(self.runner, None, self.payload_manager, **step)
                
                # Set baseline context if available
                if baseline_collection:
                    module_instance.set_baseline_context(self.baseline_manager, baseline_collection)

                # Prepare the module (establish state, etc.)
                should_run = await module_instance.prepare(step, flow_context)
                if not should_run:
                    if self.verbose:
                        print(format_log_prefix("INFO", f"Skipping module '{module_key}' (prepare returned False)"))
                    continue

                # If module needs standard state and didn't set up special states, provide it
                if not getattr(module_instance, 'established_states', None):
                     fresh_state_manager = await self._arun_flow_until(i, self.initial_state)
                     if not fresh_state_manager:
                         print(format_log_prefix("ERROR", f"Failed to establish valid state for fuzzing '{module_key}'. Skipping."))
                         continue
                     module_instance.state_manager = fresh_state_manager
                
                # Prepare execution arguments
                exec_kwargs = {'flow_context': flow_context}
                if hasattr(module_instance, 'established_states'):
                    exec_kwargs['established_states'] = module_instance.established_states

                results = await module_instance.arun(parsed_request, step, **exec_kwargs)

                report_fuzzing_results(module_key, results, self.verbose)

    async def _arun_flow_until(self, target_index: int, initial_state_override: dict, collect_baselines: bool = False) -> 'StateManager | None':
        """Runs the flow up to a step, establishing state along the way."""
        state_manager = StateManager(initial_state_override, self.variable_config, debug=self.debug)

        for i in range(target_index):
            step = self.steps[i]
            if not step.get('enable', True):
                continue
            
            response = await self._execute_step(step, state_manager, collect_baselines=collect_baselines)
            
            # If a required step fails (no response or failed assert), abort this path
            if step.get('required', False) and (not response or not self._perform_asserts(response, step)):
                print(format_log_prefix("ERROR", f"Required step '{step.get('name', step['request'])}' failed. Aborting flow path."))
                return None
        
        return state_manager

    async def _execute_step(self, step: dict, state_manager: 'StateManager', collect_baselines: bool = False):
        """Parses, prepares, and executes a single request step."""
        step_name = step.get('name', step['request'])
        if self.verbose:
            print(f"  {color_formatter.step(f'Executing step: {step_name}')}")

        raw_request = self._load_request_file(step['request'])
        # Use step-level host if defined, otherwise use default target
        step_target = step.get('host', self.target)
        parser = RequestParser(raw_request, step_target)
        parsed_request = parser.parse()

        final_request = self.runner.prepare_request(
            parsed_request, state_manager, step.get('set_headers', {})
        )
        
        try:
            if self.is_async:
                response = await self.runner.arun(final_request)
            else:
                response = self.runner.run(final_request)

            # Record baseline if collecting
            if collect_baselines:
                is_successful = self._perform_asserts(response, step) and (200 <= response.status_code < 300)
                self.baseline_manager.record_response(step_name, final_request, response, is_successful)
            
            state_manager.extract_and_update(response, step.get('extract', {}))
            state_manager.clear_request_scoped_vars()
            
            if 'delay' in step:
                await asyncio.sleep(step['delay'] / 1000)
            
            return response
        except Exception as e:
            print(format_log_prefix("ERROR", f"Request failed for step '{step_name}': {e}"))
            return None

    def _perform_asserts(self, response, step_config: dict) -> bool:
        """Checks assertions against a response. Returns True if all pass."""
        asserts = step_config.get('asserts', {})
        if not asserts:
            return True # No assertions means it passes by default
        
        if 'status_code' in asserts and response.status_code != asserts['status_code']:
            if self.verbose:
                expected_colored = color_formatter.status_code(asserts['status_code'])
                actual_colored = color_formatter.status_code(response.status_code)
                print(f"  {color_formatter.error('[ASSERT FAIL]')} Expected status {expected_colored}, got {actual_colored}")
            return False
        
        return True
    
    def _load_request_file(self, filename: str) -> str:
        """Loads a request template file, using a cache."""
        if filename in self._request_cache:
            return self._request_cache[filename]
        
        file_path = self.requests_dir / filename
        try:
            content = file_path.read_text()
            self._request_cache[filename] = content
            return content
        except FileNotFoundError:
            raise FileNotFoundError(f"Request file not found: {file_path}")