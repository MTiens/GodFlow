# Authorization Testing Module Documentation

## Overview

The `authorization` testing module is designed to test role-based access control (RBAC) vulnerabilities in API endpoints. It checks if users without proper roles can access protected resources, helping identify authorization bypasses and privilege escalation vulnerabilities.

## Module Key

```json
"authorization"
```

## Features

The authorization module performs the following types of tests:

1. **Forbidden Role Testing**: Ensures users with explicitly forbidden roles cannot access resources
2. **Insufficient Role Testing**: Verifies users without required roles are denied access
3. **Role Escalation Testing**: Attempts to escalate privileges by modifying role claims

> **Note**: Unauthenticated access testing is handled by the `authentication` module and is not included in this authorization module to avoid duplication.

## Configuration Parameters

### Required Parameters

- `personas`: Array of persona names to test with (optional - defaults to all available personas)

### Optional Parameters

- `enable`: Boolean flag to enable/disable the authorization module for this step (default: `true`)
- `required_roles`: Array of roles that should have access to the resource
- `forbidden_roles`: Array of roles that should NOT have access to the resource

## Example Usage

### Basic Configuration

```json
{
  "name": "Admin Resource Test",
  "request": "admin_endpoint.txt",
  "set_headers": {
    "Authorization": "Bearer {{session_id}}"
  },
  "fuzz": {
    "authorization": {
      "enable": true,
      "personas": ["user_A", "user_B", "admin_A", "admin_B", "viewer_A"],
      "required_roles": ["admin"],
      "forbidden_roles": ["user", "viewer"]
    }
  }
}
```

### Advanced Configuration

```json
{
  "name": "Multi-Role Resource Test",
  "request": "protected_resource.txt",
  "set_headers": {
    "Authorization": "Bearer {{session_id}}"
  },
  "fuzz": {
    "authorization": {
      "enable": true,
      "personas": ["user_A", "user_B", "admin_A", "manager_A"],
      "required_roles": ["admin", "manager"],
      "forbidden_roles": ["user", "guest"]
    }
  }
}
```

### Disabled Configuration

```json
{
  "name": "Skip Authorization Testing",
  "request": "some_endpoint.txt",
  "set_headers": {
    "Authorization": "Bearer {{session_id}}"
  },
  "fuzz": {
    "authorization": {
      "enable": false
    }
  }
}
```

## Testing Scenarios

### 1. Forbidden Role Testing

Tests that users with explicitly forbidden roles cannot access the resource:

```json
"forbidden_roles": ["user", "viewer"]
```

- If a user with role "user" or "viewer" can access the resource, it's flagged as vulnerable
- Tests each persona with forbidden roles and expects access to be denied

### 2. Insufficient Role Testing

Tests that users without required roles cannot access the resource:

```json
"required_roles": ["admin", "manager"]
```

- Users without "admin" or "manager" roles should be denied access
- Tests each persona that doesn't have the required roles

### 3. Role Escalation Testing

Attempts to escalate privileges by:
- Modifying role claims in the user's state
- Adding role-related headers to requests
- Testing common privilege escalation role names: `admin`, `administrator`, `root`, `superuser`, `system`

## Prerequisites

### Persona Configuration

Personas must be defined in the base configuration with role information:

```json
"personas": {
  "user_A": {
    "username": "user_A@test.com",
    "password": "UserAPassword123"
  },
  "admin_A": {
    "username": "admin_A@test.com",
    "password": "AdminAPassword!"
  },
  "viewer_A": {
    "username": "viewer_A@test.com",
    "password": "ViewerAPassword!"
  }
}
```

### Role Extraction

The module expects role information to be extracted from the login response:

```json
{
  "name": "Login Step",
  "request": "login.txt",
  "extract": {
    "session_id": { "json": "token" },
    "userId": { "json": "userId" },
    "role": { "json": "role" }
  }
}
```

## Example Test Flow

```json
{
  "extends": "../configs/base_config.json",
  "name": "Authorization Test Flow",
  "steps": [
    {
      "name": "Step 1: Login",
      "request": "1_login.txt",
      "required": true,
      "extract": {
        "session_id": { "json": "token" },
        "userId": { "json": "userId" },
        "role": { "json": "role" }
      }
    },
    {
      "name": "Step 2: Admin Only Resource",
      "request": "admin_endpoint.txt",
      "set_headers": {
        "Authorization": "Bearer {{session_id}}"
      },
      "fuzz": {
        "authorization": {
          "enable": true,
          "personas": ["user_A", "user_B", "admin_A", "admin_B", "viewer_A"],
          "required_roles": ["admin"],
          "forbidden_roles": ["user", "viewer"]
        }
      }
    }
  ]
}
```

## Expected Output

The module will output detailed results for each test:

### Vulnerable Finding
```
Authorization bypass! User 'user_A' with forbidden role 'user' successfully accessed the resource.
```

### Secure Finding
```
Access correctly denied for user 'user_A' with forbidden role 'user' (Status: 403).
```

### Role Escalation Finding
```
Role escalation successful! User 'user_A' escalated from 'user' to 'admin'.
```

## Best Practices

1. **Define Clear Roles**: Ensure personas have clearly defined roles in your system
2. **Test All Combinations**: Include all relevant persona and role combinations
3. **Use Realistic Scenarios**: Test actual business logic endpoints, not just test endpoints
4. **Combine with IDOR Testing**: Authorization issues often combine with IDOR vulnerabilities
5. **Regular Testing**: Run authorization tests regularly as part of your security testing suite
6. **Selective Testing**: Use the `enable` parameter to selectively enable/disable authorization testing on specific endpoints

## Troubleshooting

### Common Issues

1. **Missing Role Information**: Ensure roles are properly extracted from login responses
2. **Insufficient Personas**: The module requires multiple personas with different roles
3. **State Management**: Verify that established states contain proper authentication data

### Debug Mode

Enable debug mode to see detailed state information:

```bash
python main.py --debug
```

This will show role extraction and state management details during testing. 