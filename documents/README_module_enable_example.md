# Module Enable/Disable Feature Example

This example demonstrates how to use the new module enable/disable functionality in AuPen flow files.

## Overview

You can now control which fuzzing modules are executed by adding an `enable` field to each module's configuration. This allows you to:

- Temporarily disable modules without removing them from the configuration
- Create different testing profiles (e.g., "quick test" vs "comprehensive test")
- Focus on specific vulnerability types during development

## Basic Usage

### Enable a Module (Default Behavior)
```json
{
  "fuzz": {
    "authentication": {
      "enable": true,
      "personas": ["user_A", "user_B"]
    }
  }
}
```

### Disable a Module
```json
{
  "fuzz": {
    "xss_basic": {
      "enable": false
    }
  }
}
```

### Omit Enable Field (Defaults to True)
```json
{
  "fuzz": {
    "param_fuzz": {}
  }
}
```

## Complete Example

Here's a complete flow step showing mixed enable/disable settings:

```json
{
  "name": "Step 2: Test with Mixed Module Settings",
  "request": "3_update_description.txt",
  "set_headers": {
    "Authorization": "Bearer {{session_id}}"
  },
  "enable": true,
  "fuzz": {
    "authentication": {
      "enable": true,
      "personas": ["user_A", "user_B"],
      "test_types": ["brute_force", "credential_stuffing"]
    },
    "xss_basic": {
      "enable": false
    },
    "param_fuzz": {
      "enable": true
    },
    "http_verb_tamper": {
      "enable": false
    }
  }
}
```

## Expected Output

When running this flow, you should see output like:

```
[+] Fuzzing Step: Step 2: Test with Mixed Module Settings
  -> Running module: 'authentication'
  -> Skipping disabled module: 'xss_basic'
  -> Running module: 'param_fuzz'
  -> Skipping disabled module: 'http_verb_tamper'
```

## Use Cases

### 1. Quick Testing
Disable time-consuming modules for rapid testing:
```json
{
  "fuzz": {
    "authentication": { "enable": true },
    "xss_basic": { "enable": false },
    "param_fuzz": { "enable": false },
    "cluster_bomb": { "enable": false }
  }
}
```

### 2. Focused Testing
Enable only specific vulnerability types:
```json
{
  "fuzz": {
    "authentication": { "enable": true },
    "xss_basic": { "enable": true },
    "param_fuzz": { "enable": false },
    "idor2": { "enable": false }
  }
}
```

### 3. Development Mode
Disable modules that are still under development:
```json
{
  "fuzz": {
    "authentication": { "enable": true },
    "flow_fuzzer": { "enable": false },
    "new_experimental_module": { "enable": false }
  }
}
```

## Backward Compatibility

- If no `enable` field is specified, the module defaults to enabled (`true`)
- Existing flow files without the `enable` field will continue to work unchanged
- The feature is completely optional and doesn't break existing configurations

## Best Practices

1. **Use descriptive comments** in your flow files to explain why modules are disabled
2. **Group related modules** together for easier management
3. **Create different flow variants** for different testing scenarios
4. **Document your testing strategy** in flow file descriptions

## Testing the Feature

You can test this feature using the provided test files:

```bash
# Run the basic test
python test_module_enable.py

# Run the integration test
python test_module_enable_integration.py
```

## Troubleshooting

- **Module still runs despite being disabled**: Check that the `enable` field is set to `false` (boolean, not string)
- **Module doesn't run when enabled**: Check that the `enable` field is set to `true` (boolean, not string)
- **Unexpected behavior**: Ensure the module name matches exactly (case-sensitive) 