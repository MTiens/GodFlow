#!/usr/bin/env python3
"""
Example demonstrating how the FlowFuzzerModule reuses RequestRunner functionality.

This example shows how the flow fuzzer leverages the existing RequestRunner
for consistent request handling, state substitution, and HTTP execution.
"""

import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from testing_modules.flow_fuzzer import FlowFuzzerModule
from core.state import StateManager
from core.runner import RequestRunner
from core.payload import PayloadManager
from core.parser import RequestParser


def demonstrate_runner_reuse():
    """Demonstrate how the flow fuzzer reuses RequestRunner functionality."""
    
    print("=== RequestRunner Reuse Demonstration ===")
    
    # 1. Initialize components (same as orchestrator)
    runner = RequestRunner(is_async=False, verbose=True, debug=False)
    payload_manager = PayloadManager("payloads")
    
    # 2. Create state with variables that will be substituted
    initial_state = {
        "session_id": "abc123",
        "userId": "user456",
        "description": "Original description",
        "profileId": "profile789"
    }
    
    state_manager = StateManager(initial_state, {}, debug=True)
    
    # 3. Create flow fuzzer module (passes runner for reuse)
    flow_fuzzer = FlowFuzzerModule(runner, state_manager, payload_manager)
    
    # 4. Sample request with placeholders (will be processed by runner)
    sample_request = {
        "method": "POST",
        "url": "http://localhost:8000/api/profile/{{userId}}",
        "headers": {
            "Authorization": "Bearer {{session_id}}",
            "Content-Type": "application/json"
        },
        "json": {
            "description": "{{description}}",
            "profileId": "{{profileId}}"
        }
    }
    
    print("Original request with placeholders:")
    print(f"  URL: {sample_request['url']}")
    print(f"  Headers: {sample_request['headers']}")
    print(f"  JSON: {sample_request['json']}")
    print()
    
    # 5. Demonstrate how runner.prepare_request() handles substitution
    print("After runner.prepare_request() substitution:")
    prepared_request = runner.prepare_request(sample_request, state_manager)
    print(f"  URL: {prepared_request['url']}")
    print(f"  Headers: {prepared_request['headers']}")
    print(f"  JSON: {prepared_request['json']}")
    print()
    
    # 6. Show how flow fuzzer uses the same runner
    print("Flow fuzzer uses the same runner for:")
    print("  ✓ State substitution ({{variable}} placeholders)")
    print("  ✓ Request preparation and execution")
    print("  ✓ Header management and authentication")
    print("  ✓ File uploads ({{file:path}} syntax)")
    print("  ✓ Error handling and response processing")
    print()
    
    # 7. Demonstrate payload substitution in state
    print("Payload substitution in state:")
    original_description = state_manager._state["description"]
    print(f"  Original description: {original_description}")
    
    # Simulate what happens during fuzzing
    import copy
    fuzz_state = copy.deepcopy(state_manager)
    test_payload = "<script>alert('XSS')</script>"
    fuzz_state.set("description", test_payload)
    print(f"  After payload substitution: {fuzz_state._state['description']}")
    print()
    
    # 8. Show how the prepared request changes with payload
    print("Request after payload substitution:")
    payload_request = runner.prepare_request(sample_request, fuzz_state)
    print(f"  JSON: {payload_request['json']}")
    print()
    
    print("=== Benefits of Runner Reuse ===")
    print("1. Consistency: Same request handling across all modules")
    print("2. State Management: Automatic {{variable}} substitution")
    print("3. File Support: {{file:path}} syntax for uploads")
    print("4. Headers: Proper authentication and custom headers")
    print("5. Error Handling: Consistent error processing")
    print("6. Maintenance: Single point of request logic")
    
    # Clean up
    runner.close()


if __name__ == "__main__":
    demonstrate_runner_reuse() 