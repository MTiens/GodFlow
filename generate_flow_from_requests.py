#!/usr/bin/env python3
"""
Script to generate JSON flow files from request file patterns.
Analyzes request files in a directory and creates corresponding flow JSON files
based on the naming pattern: {function}_{step}_{mid}.txt
"""

import os
import re
import json
import yaml
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

class FlowGenerator:
    def __init__(self, requests_dir: str, config_file: str, output_dir: str = None, output_format: str = 'json'):
        self.requests_dir = Path(requests_dir)
        self.config_file = Path(config_file)
        self.output_dir = Path(output_dir) if output_dir else self.requests_dir.parent / "flows"
        self.output_dir.mkdir(exist_ok=True)
        self.output_format = output_format.lower()
        
        # Load base config (supports JSON or YAML)
        with open(self.config_file, 'r', encoding='utf-8') as f:
            if self.config_file.suffix.lower() in ('.yaml', '.yml'):
                self.base_config = yaml.safe_load(f)
            else:
                self.base_config = json.load(f)
    
    def extract_variables_from_request(self, request_file: Path) -> List[str]:
        """Extract template variables from a request file."""
        variables = []
        try:
            with open(request_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Find all {{variable}} patterns
                pattern = r'\{\{([^}]+)\}\}'
                matches = re.findall(pattern, content)
                variables = list(set(matches))  # Remove duplicates
        except Exception as e:
            print(f"Error reading {request_file}: {e}")
        return variables
    
    def parse_request_filename(self, filename: str) -> Optional[Tuple[str, int, str]]:
        """
        Parse request filename to extract function name, step number, and mid.
        Pattern: {function}_{step}_{mid}.txt (e.g., Topup_1_mid41.txt)
        This script focuses on the topup pattern specifically.
        """
        # Remove .txt extension
        name = filename.replace('.txt', '')
        
        # Pattern: function_step_mid (e.g., Topup_1_mid41)
        pattern = r'^([a-zA-Z_]+)_(\d+)_([a-zA-Z0-9_]+)$'
        match = re.match(pattern, name)
        
        if match:
            function, step, mid = match.groups()
            return function, int(step), mid
        
        return None
    
    def group_requests_by_function(self) -> Dict[str, List[Tuple[int, str, Path]]]:
        """Group request files by function name and sort by step number."""
        functions = defaultdict(list)
        
        for request_file in self.requests_dir.glob("*.txt"):
            parsed = self.parse_request_filename(request_file.name)
            if parsed:
                function, step, mid = parsed
                functions[function].append((step, mid, request_file))
        
        # Sort each function's requests by step number
        for function in functions:
            functions[function].sort(key=lambda x: x[0])
        
        return functions
    
    def generate_step_config(self, step_num: int, mid: str, request_file: Path, 
                           function_name: str, is_first: bool = False) -> Dict:
        """Generate step configuration for a request file."""
        variables = self.extract_variables_from_request(request_file)
        
        step_config = {
            "name": f"Step {step_num}: {function_name.title()} - {mid}",
            "request": request_file.name,
            "required": True,
            "enable": True,
            "extract": {},
            "fuzz": {}
        }
        
        # For first step, extract common session variables
        if is_first:
            session_vars = ['sessionid', 'clientid', 'deviceid']
            for var in session_vars:
                if var in variables:
                    step_config["extract"][var] = {"json": var}
        
        return step_config
    
    def generate_flow_variables(self, all_variables: List[str]) -> Dict[str, str]:
        """Generate VARIABLE_CONFIG for the flow - kept empty for manual configuration."""
        return {}
    
    def generate_flow_json(self, function_name: str, requests: List[Tuple[int, str, Path]]) -> Dict:
        """Generate complete flow JSON for a function."""
        # Collect all variables from all requests
        all_variables = set()
        for _, _, request_file in requests:
            variables = self.extract_variables_from_request(request_file)
            all_variables.update(variables)
        
        # Generate flow configuration
        flow_config = {
            "extends": "../configs/base_config.json",
            "name": f"{function_name.title()} Flow",
            "description": f"Automated flow for {function_name} functionality",
            "VARIABLE_CONFIG": {},
            "state": {},
            "steps": []
        }
        
        # Generate steps
        for i, (step_num, mid, request_file) in enumerate(requests):
            is_first = (i == 0)
            step_config = self.generate_step_config(step_num, mid, request_file, function_name, is_first)
            flow_config["steps"].append(step_config)
        
        return flow_config
    
    def generate_all_flows(self):
        """Generate flow JSON files for all functions found in requests directory."""
        functions = self.group_requests_by_function()
        
        print(f"Found {len(functions)} functions:")
        for function_name, requests in functions.items():
            print(f"  - {function_name}: {len(requests)} requests")
        
        for function_name, requests in functions.items():
            print(f"\nGenerating flow for {function_name}...")
            
            # Generate flow JSON
            flow_json = self.generate_flow_json(function_name, requests)
            
            # Save to file
            ext = 'yaml' if self.output_format in ('yaml', 'yml') else 'json'
            output_file = self.output_dir / f"{function_name.lower()}.{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                if self.output_format in ('yaml', 'yml'):
                    yaml.safe_dump(flow_json, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                else:
                    json.dump(flow_json, f, indent=2, ensure_ascii=False)
            
            print(f"  Saved: {output_file}")
    
    def generate_specific_flow(self, function_name: str):
        """Generate flow JSON for a specific function."""
        functions = self.group_requests_by_function()
        
        if function_name not in functions:
            print(f"Function '{function_name}' not found in requests directory.")
            print(f"Available functions: {', '.join(functions.keys())}")
            return
        
        requests = functions[function_name]
        print(f"Generating flow for {function_name} with {len(requests)} requests...")
        
        # Generate flow JSON
        flow_json = self.generate_flow_json(function_name, requests)
        
        # Save to file
        ext = 'yaml' if self.output_format in ('yaml', 'yml') else 'json'
        output_file = self.output_dir / f"{function_name.lower()}.{ext}"
        with open(output_file, 'w', encoding='utf-8') as f:
            if self.output_format in ('yaml', 'yml'):
                yaml.safe_dump(flow_json, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            else:
                json.dump(flow_json, f, indent=2, ensure_ascii=False)
        
        print(f"Saved: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Generate JSON/YAML flow files from request file patterns')
    parser.add_argument('--requests-dir', required=True, help='Directory containing request files')
    parser.add_argument('--config-file', required=True, help='Base config JSON/YAML file')
    parser.add_argument('--output-dir', help='Output directory for flow files (default: flows/)')
    parser.add_argument('--function', help='Generate flow for specific function only')
    parser.add_argument('--format', choices=['json', 'yaml', 'yml'], default='json', help='Output format (default: json)')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.requests_dir):
        print(f"Error: Requests directory '{args.requests_dir}' does not exist")
        return 1
    
    if not os.path.exists(args.config_file):
        print(f"Error: Config file '{args.config_file}' does not exist")
        return 1
    
    # Create generator
    generator = FlowGenerator(args.requests_dir, args.config_file, args.output_dir, args.format)
    
    # Generate flows
    if args.function:
        generator.generate_specific_flow(args.function)
    else:
        generator.generate_all_flows()
    
    return 0

if __name__ == "__main__":
    exit(main())
