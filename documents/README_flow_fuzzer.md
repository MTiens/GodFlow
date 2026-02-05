# Flow Fuzzer Module - Full Flow Testing

## Overview

The Flow Fuzzer Module is an advanced testing component that can perform comprehensive fuzzing across multiple steps in an API flow. The latest addition includes a **Full Flow Fuzzing** strategy that substitutes payloads into state variables and runs the complete flow to identify vulnerabilities that may manifest in later steps.

## Key Features

### Full Flow Fuzzing Strategy

The new `full_flow` strategy provides the following capabilities:

- **State Substitution**: Takes each payload and substitutes it into specified state variables
- **Complete Flow Execution**: Runs the entire flow from start to finish with the modified state
- **Cross-Step Vulnerability Detection**: Identifies vulnerabilities that may appear in later steps
- **Comprehensive Tracking**: Monitors all steps in the flow for payload reflection, error patterns, and unusual responses

## Configuration

### Basic Configuration

```json
{
  "fuzz": {
    "flow_fuzzer": {
      "enable": true,
      "strategy": "full_flow",
      "payload_category": "xss",
      "max_payloads": 20,
      "target_variables": ["description", "profileId"],
      "flow_steps": [
        {
          "name": "Login Step",
          "request": "1_login.txt",
          "enable": true,
          "extract": {
            "session_id": {"json": "token"},
            "userId": {"json": "userId"}
          }
        },
        {
          "name": "Get Profile Step",
          "request": "2_get_profile.txt",
          "set_headers": {
            "Authorization": "Bearer {{session_id}}"
          },
          "enable": true,
          "extract": {
            "profileId": {"json": "profile.id"},
            "description": {"json": "profile.description"}
          }
        },
        {
          "name": "Update Description Step",
          "request": "3_update_description.txt",
          "set_headers": {
            "Authorization": "Bearer {{session_id}}"
          },
          "enable": true
        }
      ]
    }
  }
}
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `strategy` | string | `sequential` | Fuzzing strategy to use (`full_flow`, `sequential`, `state_mutation`, `cross_step`, `exhaustive`) |
| `payload_category` | string | `xss` | Category of payloads to use for testing |
| `max_payloads` | integer | 20 | Maximum number of payloads to test (prevents excessive execution time) |
| `target_variables` | array | `[]` | List of state variables to inject payloads into. If empty, uses all available variables except common non-injection ones |
| `flow_steps` | array | `[]` | Complete flow definition with all steps to execute |
| `stop_on_failure` | boolean | `true` | Whether to stop flow execution when a step fails (required steps always stop the flow) |

### Flow Steps Definition

Each step in the `flow_steps` array should include:

```json
{
  "name": "Step Name",
  "request": "request_file.txt",
  "enable": true,
  "set_headers": {
    "Authorization": "Bearer {{session_id}}"
  },
  "extract": {
    "variable_name": {"json": "response.path"}
  }
}
```

## Usage Examples

### Example 1: Basic Full Flow Fuzzing

```json
{
  "steps": [
    {
      "name": "Full Flow Fuzzing Test",
      "request": "update_profile.txt",
      "fuzz": {
        "flow_fuzzer": {
          "strategy": "full_flow",
          "payload_category": "xss",
          "max_payloads": 10,
          "target_variables": ["description", "profileId"],
          "flow_steps": [
            {
              "name": "Login",
              "request": "login.txt",
              "extract": {"session_id": {"json": "token"}}
            },
            {
              "name": "Update Profile",
              "request": "update_profile.txt",
              "set_headers": {"Authorization": "Bearer {{session_id}}"}
            }
          ]
        }
      }
    }
  ]
}
```

### Example 2: Comprehensive Testing with Failure Handling

```json
{
  "steps": [
    {
      "name": "Comprehensive Flow Testing",
      "request": "api_endpoint.txt",
      "fuzz": {
        "flow_fuzzer": {
          "strategy": "full_flow",
          "payload_category": "sql",
          "max_payloads": 15,
          "target_variables": ["userId", "productId", "searchTerm"],
          "stop_on_failure": true,
          "flow_steps": [
            {
              "name": "Authentication",
              "request": "auth.txt",
              "required": true,
              "extract": {"token": {"json": "access_token"}}
            },
            {
              "name": "Search Products",
              "request": "search.txt",
              "set_headers": {"Authorization": "Bearer {{token}}"},
              "extract": {"productId": {"json": "products[0].id"}}
            },
            {
              "name": "Get Product Details",
              "request": "product_details.txt",
              "set_headers": {"Authorization": "Bearer {{token}}"}
            }
          ]
        }
      }
    }
  ]
}
```

### Example 3: Continue on Non-Critical Failures

```json
{
  "steps": [
    {
      "name": "Resilient Flow Testing",
      "request": "api_endpoint.txt",
      "fuzz": {
        "flow_fuzzer": {
          "strategy": "full_flow",
          "payload_category": "xss",
          "max_payloads": 10,
          "target_variables": ["description"],
          "stop_on_failure": false,
          "flow_steps": [
            {
              "name": "Login",
              "request": "login.txt",
              "required": true,
              "extract": {"session_id": {"json": "token"}}
            },
            {
              "name": "Update Profile",
              "request": "update_profile.txt",
              "set_headers": {"Authorization": "Bearer {{session_id}}"}
            },
            {
              "name": "Optional Feature",
              "request": "optional_feature.txt",
              "set_headers": {"Authorization": "Bearer {{session_id}}"}
            }
          ]
        }
      }
    }
  ]
}
```

## How It Works

### 1. Payload Selection
- Loads payloads from the specified category (e.g., XSS, SQL injection)
- Limits the number of payloads to prevent excessive execution time

### 2. State Variable Selection
- Uses specified target variables or automatically selects from available state variables
- Excludes common non-injection variables (username, password, email, etc.)

### 3. Flow Execution
For each payload and target variable combination:

1. **State Preparation**: Creates a copy of the current state and substitutes the payload
2. **Step Execution**: Runs each step in the flow with the modified state
3. **Vulnerability Detection**: Checks for:
   - Payload reflection in response
   - Error status codes (4xx, 5xx)
   - Error patterns in response body
4. **Failure Handling**: Stops flow execution on failures based on configuration:
   - Required steps always stop the flow on failure
   - Non-required steps stop based on `stop_on_failure` setting
   - File loading failures stop the flow if `stop_on_failure` is true
5. **State Propagation**: Extracts and updates state between steps
6. **Result Collection**: Records any vulnerabilities found across the flow

### 4. Result Analysis
- Tracks vulnerabilities across all steps
- Provides detailed information about where and how vulnerabilities manifest
- Summarizes findings for each payload-variable combination

## Output and Results

The module returns `FuzzingResult` objects with detailed information:

```python
FuzzingResult(
    is_vulnerable=True,
    description="Full flow vulnerability: Payload '<script>alert(1)</script>' in 'description' caused issue in Update Profile Step (Step 2). Status: 500, Reflected: True, Error: True",
    request=final_request,
    response_status=500,
    response_size=1024,
    payload="<script>alert(1)</script>"
)
```

## Best Practices

### 1. Payload Selection
- Start with a small number of payloads (`max_payloads: 5-10`) for initial testing
- Use specific payload categories based on the target application
- Consider the application's technology stack when choosing payloads

### 2. Variable Selection
- Focus on user-controlled variables that flow through multiple steps
- Include variables that are used in database queries, file operations, or output rendering
- Exclude authentication tokens and session identifiers unless specifically testing for token manipulation

### 3. Flow Design
- Ensure the flow steps are realistic and represent actual user workflows
- Include proper authentication and authorization steps
- Test both positive and negative scenarios

### 4. Performance Considerations
- Limit the number of payloads to avoid excessive execution time
- Use targeted variable selection instead of testing all variables
- Consider running tests during off-peak hours for production systems

## Integration with Orchestrator

The Flow Fuzzer Module integrates seamlessly with the main Orchestrator and reuses existing components:

### RequestRunner Integration
The module leverages the existing `RequestRunner` class for:
- **Request Preparation**: Uses `runner.prepare_request()` to handle state substitution
- **Request Execution**: Uses `runner.run()` or `runner.arun()` for HTTP requests
- **Request Loading**: Uses `runner.load_request_from_file()` to load and parse request files
- **State Management**: Maintains consistency with the orchestrator's state handling

```python
# The orchestrator automatically provides flow context
flow_context = {
    'steps': flow_steps,
    'current_step_index': current_index,
    'requests_dir': requests_directory,
    'target': target_url
}

# Module receives this context via kwargs and reuses the runner
results = await flow_fuzzer.arun(parsed_request, step_config, **kwargs)
```

### Benefits of Reusing RequestRunner
- **Consistency**: Same request handling logic across all modules
- **State Substitution**: Automatic handling of `{{variable}}` placeholders
- **File Uploads**: Support for `{{file:path}}` syntax for file uploads
- **Request Loading**: Centralized file loading and parsing logic
- **Headers Management**: Proper handling of authentication and custom headers
- **Error Handling**: Consistent error handling and response processing

## Testing

To test the full flow fuzzing functionality:

1. **Start the test server**:
   ```bash
   cd projects/test_1/fakeserver
   python fake_api.py
   ```

2. **Run the test script**:
   ```bash
   python test_flow_fuzzer.py
   ```

3. **Use with a real flow**:
   ```bash
   python run.py fuzz projects/test_1/flows/flow_fuzzer_demo.json
   ```

## Troubleshooting

### Common Issues

1. **No flow steps provided**: Ensure `flow_steps` is defined in the configuration or `flow_context` is passed via kwargs
2. **Payload category not found**: Verify the payload category exists in the payloads directory
3. **Request file not found**: Check that request files are in the correct directory and accessible
4. **State variable not found**: Ensure the target variables exist in the current state

### Debug Mode

Enable debug mode for detailed logging:

```json
{
  "fuzz": {
    "flow_fuzzer": {
      "strategy": "full_flow",
      "debug": true
    }
  }
}
```

## Future Enhancements

Planned improvements for the Flow Fuzzer Module:

1. **Parallel Execution**: Run multiple payload combinations concurrently
2. **Intelligent Payload Selection**: Use machine learning to select the most effective payloads
3. **State Mutation Strategies**: Advanced techniques for state manipulation
4. **Custom Vulnerability Detection**: User-defined patterns for vulnerability identification
5. **Flow Templates**: Pre-defined flow patterns for common application types 