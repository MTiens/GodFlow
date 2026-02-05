# Flow Fuzzer Example

This example demonstrates how to use the optimized flow fuzzer module with different strategies and configurations.

## Overview

The flow fuzzer module has been simplified to focus on core requirements:
1. **Run complete flows** for each payload if no errors occur
2. **Define target parameters** to perform fuzzing via state substitution
3. **Support different strategies** (complete_flow, single_step, state_mutation)
4. **Reuse existing functions** from runner and orchestrator

## Configuration Options

### Basic Configuration
```json
{
  "flow_fuzzer": {
    "enable": true,
    "strategy": "complete_flow",
    "target_params": ["accountId", "phoneNumber"],
    "payload_category": "xss",
    "max_payloads": 10,
    "stop_on_failure": true
  }
}
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable` | boolean | false | Enable/disable flow fuzzing |
| `strategy` | string | "complete_flow" | Fuzzing strategy to use |
| `target_params` | array | [] | List of state parameters to fuzz |
| `payload_category` | string | "xss" | Payload category to use |
| `max_payloads` | integer | 10 | Maximum number of payloads to test |
| `stop_on_failure` | boolean | true | Stop flow execution on any failure |

## Strategies

### 1. Complete Flow Strategy (`complete_flow`)
Runs the complete flow from the beginning for each payload.

```json
{
  "flow_fuzzer": {
    "enable": true,
    "strategy": "complete_flow",
    "target_params": ["session_id", "userId", "accountId"],
    "payload_category": "xss",
    "max_payloads": 5
  }
}
```

**Behavior:**
- For each payload, substitutes it into each target parameter
- Runs the complete flow from step 0 to end
- Tracks vulnerabilities across all steps
- Maintains flow state between steps

### 2. Single Step Strategy (`single_step`)
Fuzzes only the current step with payloads.

```json
{
  "flow_fuzzer": {
    "enable": true,
    "strategy": "single_step",
    "target_params": ["accountId", "phoneNumber"],
    "payload_category": "sql",
    "max_payloads": 10
  }
}
```

**Behavior:**
- Tests payloads only on the current step
- Does not continue to subsequent steps
- Faster execution for quick vulnerability assessment

### 3. State Mutation Strategy (`state_mutation`)
Mutates state variables and tests how it affects the flow from the beginning.

```json
{
  "flow_fuzzer": {
    "enable": true,
    "strategy": "state_mutation",
    "target_params": ["session_id", "token"],
    "payload_category": "xss",
    "max_payloads": 8
  }
}
```

**Behavior:**
- Substitutes payloads into state variables
- Runs complete flow from step 0 with mutated state
- Tests how state mutations affect flow execution

## Example Flow Configuration

```json
{
  "extends": "../configs/base_config.json",
  "personas": {
    "test_user": {
      "username": "test@example.com",
      "password": "password123",
      "accountId": "ACC_001",
      "phoneNumber": "+1234567890"
    }
  },
  "steps": [
    {
      "name": "Step 1: Login",
      "request": "login.txt",
      "required": true,
      "enable": true,
      "extract": {
        "session_id": { "json": "token" },
        "userId": { "json": "userId" }
      }
    },
    {
      "name": "Step 2: Get Account Info",
      "request": "get_account.txt",
      "set_headers": {
        "Authorization": "Bearer {{session_id}}"
      },
      "enable": true,
      "extract": {
        "accountId": { "json": "accountId" }
      },
      "fuzz": {
        "flow_fuzzer": {
          "enable": true,
          "strategy": "complete_flow",
          "target_params": ["accountId", "phoneNumber", "session_id"],
          "payload_category": "xss",
          "max_payloads": 5,
          "stop_on_failure": true
        }
      }
    },
    {
      "name": "Step 3: Update Profile",
      "request": "update_profile.txt",
      "set_headers": {
        "Authorization": "Bearer {{session_id}}"
      },
      "enable": true,
      "fuzz": {
        "flow_fuzzer": {
          "enable": true,
          "strategy": "single_step",
          "target_params": ["phoneNumber"],
          "payload_category": "sql",
          "max_payloads": 3
        }
      }
    }
  ]
}
```

## Usage Notes

1. **Target Parameters**: If `target_params` is empty, the module will automatically use all state variables except common ones (username, password, email, phone, name).

2. **Payload Categories**: Available categories depend on your payload files. Common ones include:
   - `xss` - Cross-site scripting payloads
   - `sql` - SQL injection payloads
   - `lfi` - Local file inclusion payloads
   - `rfi` - Remote file inclusion payloads

3. **Flow Context**: The module automatically receives flow context from the orchestrator, including:
   - `steps` - List of flow steps
   - `current_step_index` - Current step being executed
   - `requests_dir` - Directory containing request files
   - `target` - Target URL

4. **Error Handling**: The module handles various error scenarios:
   - Missing request files
   - Network errors
   - Invalid payloads
   - State variable issues

5. **Performance**: The module limits payloads by default to avoid excessive execution time. Adjust `max_payloads` based on your needs.

## Output

The module returns `FuzzingResult` objects with:
- `is_vulnerable`: Boolean indicating if vulnerability was found
- `description`: Detailed description of the finding
- `request`: The request that was sent
- `response_status`: HTTP status code
- `response_size`: Size of response
- `payload`: The payload that was tested

Example output:
```
Flow fuzzing: Testing 5 payloads against 3 parameters
Strategy: complete_flow, Starting from step 1
  Testing payload '<script>alert(1)</script>' in parameter 'accountId'
    Running complete flow from step 1 with payload in 'accountId'...
      Executing: Step 2: Get Account Info
      Executing: Step 3: Update Profile
    [!] Found 1 vulnerabilities across the flow
      - Step 2: Get Account Info: Status 500, Reflected: True
``` 