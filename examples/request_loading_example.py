#!/usr/bin/env python3
"""
Example demonstrating the centralized request loading functionality in RequestRunner.

This example shows how the RequestRunner now provides a unified method for loading
and parsing request files, which is used by both the flow_fuzzer and idor2 modules.
"""

import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.runner import RequestRunner
from core.state import StateManager


def demonstrate_request_loading():
    """Demonstrate the centralized request loading functionality."""
    
    print("=== Centralized Request Loading Demonstration ===")
    
    # 1. Initialize the runner
    runner = RequestRunner(is_async=False, verbose=True, debug=False)
    
    # 2. Sample configuration
    target = "http://localhost:8000"
    requests_dir = "projects/test_1/requests"
    
    # 3. Demonstrate loading different request files
    request_files = [
        "1_login.txt",
        "2_get_profile.txt", 
        "3_update_description.txt"
    ]
    
    print("Loading and parsing request files using runner.load_request_from_file():")
    print()
    
    for filename in request_files:
        try:
            print(f"Loading: {filename}")
            parsed_request = runner.load_request_from_file(filename, target, requests_dir)
            
            print(f"  Method: {parsed_request.get('method', 'GET')}")
            print(f"  URL: {parsed_request.get('url', 'N/A')}")
            print(f"  Headers: {len(parsed_request.get('headers', {}))} headers")
            if 'json' in parsed_request:
                print(f"  JSON Body: {parsed_request['json']}")
            elif 'content' in parsed_request:
                print(f"  Content: {parsed_request['content'][:100]}...")
            print()
            
        except FileNotFoundError as e:
            print(f"  Error: {e}")
            print()
        except Exception as e:
            print(f"  Error parsing {filename}: {e}")
            print()
    
    # 4. Show how this integrates with state substitution
    print("=== Integration with State Substitution ===")
    
    # Create a sample state
    state_manager = StateManager({
        "session_id": "abc123",
        "userId": "user456",
        "description": "Test description"
    }, {})
    
    try:
        # Load a request file
        parsed_request = runner.load_request_from_file("3_update_description.txt", target, requests_dir)
        print("Original parsed request:")
        print(f"  URL: {parsed_request.get('url', 'N/A')}")
        print(f"  JSON: {parsed_request.get('json', 'N/A')}")
        print()
        
        # Prepare the request with state substitution
        prepared_request = runner.prepare_request(parsed_request, state_manager)
        print("After state substitution:")
        print(f"  URL: {prepared_request.get('url', 'N/A')}")
        print(f"  JSON: {prepared_request.get('json', 'N/A')}")
        print()
        
    except Exception as e:
        print(f"Error in state substitution demo: {e}")
    
    # 5. Show benefits of centralized loading
    print("=== Benefits of Centralized Request Loading ===")
    print("1. Consistency: Same loading logic across all modules")
    print("2. Error Handling: Unified error handling for missing files")
    print("3. Parsing: Centralized RequestParser usage")
    print("4. Maintenance: Single point of request loading logic")
    print("5. Reusability: All modules can use the same method")
    print("6. Caching: Potential for future caching improvements")
    
    # Clean up
    runner.close()


def compare_old_vs_new_approach():
    """Compare the old approach vs the new centralized approach."""
    
    print("\n=== Old vs New Approach Comparison ===")
    
    print("OLD APPROACH (before centralization):")
    print("  - Each module had its own _load_request_from_file() method")
    print("  - Duplicated file loading and parsing logic")
    print("  - Inconsistent error handling")
    print("  - Hard to maintain and update")
    print()
    
    print("NEW APPROACH (centralized in RequestRunner):")
    print("  - Single runner.load_request_from_file() method")
    print("  - Consistent file loading and parsing logic")
    print("  - Unified error handling")
    print("  - Easy to maintain and extend")
    print("  - All modules reuse the same functionality")
    print()
    
    print("Modules that now use the centralized approach:")
    print("  ✓ flow_fuzzer.py - Uses runner.load_request_from_file()")
    print("  ✓ idor2.py - Uses runner.load_request_from_file()")
    print("  ✓ Future modules can easily adopt the same pattern")


if __name__ == "__main__":
    demonstrate_request_loading()
    compare_old_vs_new_approach() 