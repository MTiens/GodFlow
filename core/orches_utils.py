# core/orches_utils.py
"""
Utility functions for the Orchestrator.
Extracted to keep the main Orchestrator class focused on core flow logic.
"""

import json
import yaml
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, Any, List

from core.colors import format_log_prefix, color_formatter
from testing_modules.base_module import FuzzingModule, FuzzingResult


def load_config_with_inheritance(config_path: Path, debug: bool = False, verbose: bool = False) -> Dict[str, Any]:
    """
    Loads a configuration file with support for inheritance via 'extends' field.
    
    Args:
        config_path: Path to the configuration file to load.
        debug: Flag for debug output.
        verbose: Flag for verbose output.
        
    Returns:
        Merged configuration dictionary.
    """
    # Load the base configuration based on file extension
    with config_path.open('r', encoding='utf-8') as f:
        if config_path.suffix.lower() in ('.yaml', '.yml'):
            config_data = yaml.safe_load(f)
        else:
            config_data = json.load(f)
    
    # Check if this config extends another config
    extends_path = config_data.get('extends')
    if extends_path:
        # Resolve the path relative to the current config file
        if extends_path.startswith('/'):
            # Absolute path
            base_path = Path(extends_path)
        elif extends_path.startswith('../'):
            # Relative path from current config
            base_path = config_path.parent / extends_path
        else:
            # Relative path from current working directory (not from config file)
            base_path = Path.cwd() / extends_path
        
        if debug:
            print(format_log_prefix("DEBUG", f"Resolving extends path: {extends_path}"))
            print(format_log_prefix("DEBUG", f"Config file location: {config_path.parent}"))
            print(format_log_prefix("DEBUG", f"Current working directory: {Path.cwd()}"))
            print(format_log_prefix("DEBUG", f"Resolved base path: {base_path}"))
        
        if not base_path.exists():
            raise FileNotFoundError(f"Base configuration file not found: {base_path}")
        
        # Recursively load the base configuration
        base_config = load_config_with_inheritance(base_path, debug, verbose)
        
        # Remove the 'extends' field from the current config
        config_data.pop('extends', None)
        
        # Merge configurations (current config overrides base config)
        merged_config = deep_merge(base_config, config_data)
        
        if verbose:
            print(format_log_prefix("INFO", f"Loaded configuration from {config_path} (extends {base_path})"))
        if debug:
            print(format_log_prefix("DEBUG", f"Base config personas: {list(base_config.get('personas', {}).keys())}"))
            print(format_log_prefix("DEBUG", f"Flow config personas: {list(config_data.get('personas', {}).keys())}"))
            print(format_log_prefix("DEBUG", f"Merged config personas: {list(merged_config.get('personas', {}).keys())}"))
        
        return merged_config
    else:
        if verbose:
            print(format_log_prefix("INFO", f"Loaded configuration from {config_path}"))
        return config_data


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merges two dictionaries, with override values taking precedence.
    
    Args:
        base: Base dictionary
        override: Override dictionary
        
    Returns:
        Merged dictionary
    """
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursively merge nested dictionaries
            result[key] = deep_merge(result[key], value)
        else:
            # Override the value
            result[key] = value
    
    return result


def load_fuzzing_modules() -> Dict[str, type]:
    """Dynamically loads all FuzzingModule classes."""
    modules = {}
    # Adjust path to be relative to this file's location
    module_dir = Path(__file__).parent.parent / "testing_modules"
    
    for file_path in module_dir.glob("*.py"):
        if file_path.name in ("__init__.py", "base_module.py"):
            continue
        
        spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, FuzzingModule) and obj is not FuzzingModule:
                # We need to add an async 'arun' method to each module if it doesn't exist
                if not hasattr(obj, 'arun'):
                    # This wraps the sync 'run' in an async function
                    async def async_run_wrapper(self_obj, *args, **kwargs):
                        return self_obj.run(*args, **kwargs)
                    setattr(obj, 'arun', async_run_wrapper)
                modules[obj.key] = obj
    return modules


def report_fuzzing_results(module_key: str, results: List[FuzzingResult], verbose: bool = False):
    """Prints fuzzing results in a structured format."""
    vulnerabilities = [r for r in results if r.is_vulnerable]
    if vulnerabilities:
        vuln_header = color_formatter.vulnerability(f"[!] VULNERABILITIES FOUND by '{module_key}': {len(vulnerabilities)}")
        print(f"  {vuln_header}")
        for res in vulnerabilities:
            print(f"    - Description: {res.description}")
            if res.payload:
                payload_colored = color_formatter.payload(res.payload[:100])
                print(f"      Payload: {payload_colored}")
            status_colored = color_formatter.status_code(res.response_status)
            print(f"      Response: {status_colored} / {res.response_size} bytes")
            if res.x_trace_id:
                trace_colored = color_formatter.info(f"X-Trace-Id: {res.x_trace_id}")
                print(f"      {trace_colored}")
    else:
        if verbose:
            success_msg = color_formatter.success(f"Module '{module_key}' completed. No issues found.")
            print(f"  -> {success_msg}")


def extract_project_name(flow_file_path: Path) -> str:
    """Extract project name from flow file path."""
    if "projects" in flow_file_path.parts:
        try:
            idx = flow_file_path.parts.index("projects")
            return flow_file_path.parts[idx + 1]
        except IndexError:
            pass
    return "default_project"


def extract_flow_name(flow_file_path: Path) -> str:
    """Extract flow name from flow file path."""
    return flow_file_path.stem


def enhance_result_with_baseline(result: FuzzingResult) -> FuzzingResult:
    """
    Enhance a FuzzingResult with baseline comparison information.
    
    This function extracts the repeated baseline comparison logic that appears
    in all testing modules and provides a centralized way to enhance results
    with baseline analysis information.
    
    Args:
        result: The FuzzingResult to enhance
        
    Returns:
        Enhanced FuzzingResult with baseline information added to description
    """
    if not result.baseline_comparison or not result.baseline_comparison.get("baseline_available"):
        return result
        
    anomalies = result.anomaly_details or []
    anomaly_types = [a.get("type") for a in anomalies]
    confidence = result.baseline_comparison.get("confidence", 0.0)
    enhanced_description = result.description
    
    # Add baseline insights to the description
    if "unexpected_status_code" in anomaly_types:
        enhanced_description += f" (Status anomaly detected with {confidence:.1%} confidence)"
    if "unexpected_response_size" in anomaly_types:
        enhanced_description += f" (Response size anomaly with {confidence:.1%} confidence)"
    if "missing_response_patterns" in anomaly_types:
        enhanced_description += f" (Response pattern disruption with {confidence:.1%} confidence)"
    if "missing_critical_header" in anomaly_types:
        enhanced_description += f" (Missing security headers with {confidence:.1%} confidence)"
    if "unexpected_response_patterns" in anomaly_types:
        enhanced_description += f" (Response pattern anomaly with {confidence:.1%} confidence)"
        
    return result._replace(description=enhanced_description)


def load_available_baselines(baseline_manager, project_name: str, flow_name: str):
    """Try to load existing baselines for the current project/flow."""
    from core.baseline import BaselineCollection
    
    # Try specific flow baseline first
    filename = f"{project_name}_{flow_name}_baselines.json"
    try:
        return baseline_manager.load_collection(filename)
    except FileNotFoundError:
        pass
    
    # Try general project baseline
    filename = f"{project_name}_general_baselines.json"
    try:
        return baseline_manager.load_collection(filename)
    except FileNotFoundError:
        pass
    
    # List available baselines and use the most recent one for this project
    available_baselines = baseline_manager.list_available_baselines()
    project_baselines = [f for f in available_baselines if f.startswith(f"{project_name}_")]
    
    if project_baselines:
        # Use the most recent one (lexicographically last should be most recent)
        latest_baseline = sorted(project_baselines)[-1]
        try:
            print(format_log_prefix("BASELINE", f"Using available baseline: {latest_baseline}"))
            return baseline_manager.load_collection(latest_baseline)
        except Exception as e:
            print(format_log_prefix("BASELINE", f"Failed to load {latest_baseline}: {e}"))
    
    return None
