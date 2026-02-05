# State Validation in RequestRunner

## Overview

The `RequestRunner` now includes automatic state validation to detect missing or empty state variables before preparing requests. This helps prevent runtime errors and ensures that all required state variables are available before making HTTP requests.

## How It Works

When `prepare_request()` is called, the runner automatically scans the request for any state variable references (using the `{{variable}}` syntax) and checks if those variables exist in the state manager and are not empty.

### Validation Scope

The validation checks for state variables in:
- **URL**: `http://api.example.com/users/{{userId}}`
- **Headers**: `Authorization: Bearer {{token}}`
- **Query Parameters**: `?filter={{filterType}}`
- **JSON Body**: `{"user": "{{username}}", "data": [{{item1}}, {{item2}}]}`
- **Content**: Raw request body content
- **Set Headers**: Additional headers passed to `prepare_request()`

### Validation Rules

1. **Variable Existence**: The variable must exist in the state manager
2. **Non-Empty Values**: The variable must have a non-empty value (not `None`, empty string, etc.)
3. **Template Syntax**: Only variables using `{{variable}}` syntax are checked

## Usage

### Basic Usage (Validation Enabled by Default)

```python
from core.runner import RequestRunner
from core.state import StateManager

runner = RequestRunner()
state = StateManager({}, {})

# Add some variables
state.set("token", "abc123")
state.set("userId", "12345")

request = {
    "method": "GET",
    "url": "http://api.example.com/users/{{userId}}",
    "headers": {
        "Authorization": "Bearer {{token}}",
        "X-Custom": "{{missingVar}}"  # This will cause an error
    }
}

try:
    prepared_request = runner.prepare_request(request, state)
except ValueError as e:
    print(f"Missing variables: {e}")
    # Output: Missing variables: Missing state variables: ['missingVar']. Cannot prepare request.
```

### Disable Validation

```python
# Disable validation for this request
prepared_request = runner.prepare_request(request, state, validate_state=False)
```

### Handle Missing Variables Gracefully

```python
def safe_prepare_request(runner, request, state):
    try:
        return runner.prepare_request(request, state)
    except ValueError as e:
        print(f"State validation failed: {e}")
        # Handle the error - maybe set default values or skip the request
        return None
```

## Benefits

1. **Early Error Detection**: Catch missing variables before making HTTP requests
2. **Better Debugging**: Clear error messages indicate exactly which variables are missing
3. **Flow Control**: Stop execution when critical state is missing
4. **Consistent Behavior**: All modules using RequestRunner benefit from this validation
5. **Optional**: Can be disabled when needed

## Error Handling

When validation fails, a `ValueError` is raised with a descriptive message:

```
ValueError: Missing state variables: ['token', 'userId']. Cannot prepare request.
```

## Integration with Modules

All testing modules that use `RequestRunner.prepare_request()` automatically benefit from this validation:

- **Flow Fuzzer**: Stops flow execution when state variables are missing
- **IDOR Module**: Validates state before making requests
- **XSS Module**: Ensures required variables are present
- **All Other Modules**: Consistent validation across the framework

## Configuration

The validation is enabled by default but can be controlled:

```python
# Enable validation (default)
runner.prepare_request(request, state, validate_state=True)

# Disable validation
runner.prepare_request(request, state, validate_state=False)
```

## Best Practices

1. **Set Required Variables Early**: Ensure critical state variables are set before making requests
2. **Handle Validation Errors**: Catch `ValueError` exceptions and handle them appropriately
3. **Use Descriptive Variable Names**: Make it clear what each variable represents
4. **Test State Dependencies**: Verify that your flows set all required variables
5. **Disable When Appropriate**: Use `validate_state=False` for optional variables or testing scenarios

## Example Flow with Validation

```python
# Initialize state
state = StateManager({}, {})
state.set("baseUrl", "http://api.example.com")
state.set("apiKey", "your-api-key")

# Step 1: Login (sets session token)
login_request = {
    "method": "POST",
    "url": "{{baseUrl}}/login",
    "headers": {"X-API-Key": "{{apiKey}}"},
    "json": {"username": "user", "password": "pass"}
}

try:
    prepared_login = runner.prepare_request(login_request, state)
    # Execute login request...
    # Extract token from response and set in state
    state.set("sessionToken", "extracted-token")
except ValueError as e:
    print(f"Login failed due to missing state: {e}")
    return

# Step 2: Use session token (will be validated)
user_request = {
    "method": "GET", 
    "url": "{{baseUrl}}/users/me",
    "headers": {"Authorization": "Bearer {{sessionToken}}"}
}

try:
    prepared_user = runner.prepare_request(user_request, state)
    # Execute user request...
except ValueError as e:
    print(f"User request failed due to missing state: {e}")
    return
```

This ensures that each step has the required state variables before proceeding, making your flows more robust and easier to debug. 