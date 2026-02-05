# API Fuzzer: Flow and Config File Documentation

## Overview
This document explains how to set up and use flow JSON files and config files for the API Fuzzer project. It covers the structure, key fields, and best practices for defining API test flows and fuzzing scenarios.

---

## Directory Structure

- `flows/` — Contains flow definition JSON files (e.g., `banking_topup_flow.json`)
- `configs/` — Contains base and custom config JSON files (e.g., `base_config.json`)
- `requests/` — Contains raw HTTP request templates as `.txt` files
- `payloads/` — Contains payload files for fuzzing
- `documents/` — (this folder) Documentation and usage guides

---

## Flow JSON File Structure
A flow file defines the sequence of API steps and optional fuzzing modules to run.

### Key Sections
- `extends`: (optional) Path to a base config file to inherit settings from
- `personas`: Defines test users and their credentials/attributes
- `steps`: List of steps (API calls) in the flow

### Example
```json
{
  "extends": "../configs/base_config.json",
  "personas": {
    "user_A": {"username": "user_A@test.com", "password": "UserAPassword123"}
  },
  "steps": [
    {
      "name": "Login",
      "request": "1_login.txt",
      "extract": {"session_id": {"json": "token"}}
    },
    {
      "name": "Get Profile",
      "request": "2_get_profile.txt",
      "set_headers": {"Authorization": "Bearer {{session_id}}"},
      "fuzz": {
        "idor2": {
          "personas": ["user_A", "user_B"],
          "object_id_param": "userId"
        }
      }
    }
  ]
}
```

---

## Config JSON File Structure
A config file provides global settings, default personas, and variable configuration.

### Example
```json
{
  "TARGET": "http://127.0.0.1:5000",
  "personas": {
    "user_A": {"username": "user_A@test.com", "password": "UserAPassword123"}
  },
  "VARIABLE_CONFIG": {
    "session_id": "flow",
    "userId": "flow"
  },
  "state": {
    "description": "default description"
  }
}
```

---

## Defining Personas
- Each persona is a named user with credentials and optional attributes (e.g., accountId, phoneNumber).
- Use persona names in fuzzing modules to simulate attacks between users.

---

## Defining Steps
- Each step represents an API call.
- `request`: Name of the request template file in `requests/`.
- `set_headers`: (optional) Headers to add, with placeholders for state variables.
- `extract`: (optional) How to extract variables from the response.
- `fuzz`: (optional) Fuzzing modules to run on this step.

---

## Fuzzing Modules and `flow_steps`
- Fuzzing modules (e.g., `idor2`, `xss_basic`) can be attached to steps via the `fuzz` field.
- `flow_steps` (inside a fuzz config) allow you to define custom requests for fuzzing, with support for placeholder substitution.
- Always use placeholders (e.g., `{{session_id}}`) in headers, params, or body to have them replaced by the current persona's state.

### Module Enable/Disable
- Each fuzzing module can be individually enabled or disabled using the `enable` field:
```json
{
  "fuzz": {
    "authentication": {
      "enable": true,
      "personas": ["user_A", "user_B"]
    },
    "xss_basic": {
      "enable": false
    }
  }
}
```
- If `enable` is not specified, the module defaults to enabled (`true`).
- Disabled modules will be skipped during execution with a log message.

---

## Placeholder Substitution
- Placeholders like `{{session_id}}` are replaced at runtime with values from the current state.
- Placeholders work in URLs, headers, params, and recursively in JSON bodies.
- Make sure to define all needed variables in `extract` or persona/state.

---

## Running the Tool
- To run a flow without fuzzing:
  ```sh
  python main.py run flows/your_flow.json
  ```
- To run a flow with fuzzing:
  ```sh
  python main.py fuzz flows/your_flow.json
  ```
- Use `-v` before the subcommand for verbose output:
  ```sh
  python main.py -v fuzz flows/your_flow.json
  ```

---

## Troubleshooting
- **Placeholders not replaced:** Ensure the variable is extracted or present in persona/state.
- **Headers/params missing:** Add them explicitly in the step or flow_steps with placeholders.
- **Relative URLs in flow_steps:** These are automatically converted to absolute URLs using the config's TARGET.
- **KeyError for params/headers/content:** Make sure your step or flow_step includes these keys, or update the code to handle missing keys.

---

For more advanced usage, see the code comments and examples in the `flows/` and `configs/` folders. 