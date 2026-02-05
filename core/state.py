# core/state.py
import time
import re
from typing import Dict, Any
import json
import httpx
from core.utils import DynamicVariableResolver
from core.colors import format_log_prefix, colored_print

class StateManager:
    def __init__(self, initial_state: Dict, variable_config: Dict, debug: bool = False):
        self._state = initial_state.copy()
        self._variable_config = variable_config
        self.debug = debug

    def get(self, key: str) -> Any:
        """Get a variable's value, handling special cases like 'timestamp'."""
        var_type = self._variable_config.get(key)
        
        if var_type == "always":
            if key == "timestamp":
                return int(time.time() * 1000)
            # Add other 'always' generated values here
        
        return self._state.get(key)

    def set(self, key: str, value: Any):
        """Set a variable's value."""
        self._state[key] = value

    def extract_and_update(self, response: httpx.Response, extract_rules: Dict):
        """Extracts values from a response and updates the state."""
        for var_name, rule in extract_rules.items():
            if "json" in rule:
                try:
                    data = json.loads(response.content.decode('utf-8'))
                    if self.debug:
                        colored_print(format_log_prefix("DEBUG", f"Response JSON for '{var_name}': {data}"), "debug")
                    
                    # Handle dot notation paths like "accounts[0].accountId"
                    json_path = rule["json"]
                    value = self._get_nested_value(data, json_path)
                    
                    if value is not None:
                        self.set(var_name, value)
                        if self.debug:
                            colored_print(format_log_prefix("STATE", f"Extracted '{var_name}' = '{value}'"), "state")
                    else:
                        print(format_log_prefix("WARN", f"Could not extract '{var_name}' using path '{json_path}' from response"))
                except json.JSONDecodeError:
                    print(format_log_prefix("WARN", f"Failed to decode JSON to extract '{var_name}'"))
                    if self.debug:
                        colored_print(format_log_prefix("DEBUG", f"Response text for '{var_name}': {response.text}"), "debug")
            
            if "header" in rule:
                header_name = rule["header"]
                # httpx headers are case-insensitive
                header_value = response.headers.get(header_name)
                
                if header_value is not None:
                    # Optionally apply regex to header value
                    if "regex" in rule:
                        pattern = rule["regex"]
                        match = re.search(pattern, header_value)
                        if match:
                            value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                            self.set(var_name, value)
                            if self.debug:
                                colored_print(format_log_prefix("STATE", f"Extracted header+regex '{var_name}' = '{value}'"), "state")
                        else:
                            print(format_log_prefix("WARN", f"Regex '{pattern}' not found in header '{header_name}' value for '{var_name}'"))
                    else:
                        self.set(var_name, header_value)
                        if self.debug:
                            colored_print(format_log_prefix("STATE", f"Extracted header '{var_name}' = '{header_value}'"), "state")
                else:
                    print(format_log_prefix("WARN", f"Header '{header_name}' not found in response for variable '{var_name}'"))
            
            if "regex" in rule and "header" not in rule:
                pattern = rule["regex"]
                match = re.search(pattern, response.text)
                
                if match:
                    # Default to first group if available, otherwise entire match
                    value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    self.set(var_name, value)
                    if self.debug:
                        colored_print(format_log_prefix("STATE", f"Extracted regex '{var_name}' = '{value}'"), "state")
                else: 
                     print(format_log_prefix("WARN", f"Regex pattern '{pattern}' not found in response for variable '{var_name}'"))

    def _get_nested_value(self, data: Any, path: str) -> Any:
        """Extracts a value from nested data using dot notation with array support."""
        if not path:
            return data
            
        parts = path.split('.')
        current = data
        
        for part in parts:
            if '[' in part and ']' in part:
                # Handle array access like "accounts[0]"
                key_part = part[:part.index('[')]
                index_part = part[part.index('[')+1:part.index(']')]
                
                if key_part not in current:
                    return None
                current = current[key_part]
                
                try:
                    index = int(index_part)
                    if isinstance(current, list) and 0 <= index < len(current):
                        current = current[index]
                    else:
                        return None
                except (ValueError, TypeError):
                    return None
            else:
                # Handle regular key access
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
                    
        return current

    def substitute(self, text: str) -> str:
        """Substitutes all placeholders {{var}} in a string, supporting dynamic variables."""
        if not text:
            return text
        resolver = DynamicVariableResolver(self._state)
        return resolver.resolve(text)

    def clear_request_scoped_vars(self):
        """Clears variables with 'request' scope after a request."""
        for var, scope in self._variable_config.items():
            if scope == 'request' and var in self._state:
                del self._state[var]