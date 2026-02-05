# Cluster Bomb Fuzzing Module

## Overview

The Cluster Bomb module implements fuzzing similar to Burp Intruder's cluster bomb mode. It combines two payload sets to create combinations in the format `<payload_from_set_1>: <payload_from_set_2>` and injects them into request headers.

## How It Works

1. **Two Payload Sets**: The module uses two separate payload sets, each containing multiple strings
2. **Combination Format**: Creates combinations in the format `payload1: payload2`
3. **Header Injection**: Injects these combinations into request headers
4. **Response Analysis**: Monitors for interesting responses (reflection, error codes, etc.)

## Default Payload Sets

### Set 1 (Authentication/User related):
- admin
- user
- test
- guest
- root

### Set 2 (Credential/Secret related):
- password
- secret
- token
- key
- auth

## Usage

### In Flow Configuration

```json
{
  "name": "Cluster Bomb Header Fuzzing",
  "module": "cluster_bomb",
  "request": "your_request.txt",
  "config": {
    "description": "Test cluster bomb fuzzing on headers",
    "payload_set_1": ["admin", "user", "test", "guest", "root"],
    "payload_set_2": ["password", "secret", "token", "key", "auth"]
  }
}
```

### Custom Payload Sets

You can override the default payload sets by providing them in the step configuration:

```json
{
  "config": {
    "payload_set_1": ["custom1", "custom2", "custom3", "custom4", "custom5"],
    "payload_set_2": ["value1", "value2", "value3", "value4", "value5"]
  }
}
```

## Payload Files

The module automatically loads payloads from:
- `payloads/cluster_bomb_set1.txt` - First payload set
- `payloads/cluster_bomb_set2.txt` - Second payload set

If these files don't exist, it falls back to the default payload sets.

## Example Combinations

With the default payload sets, the module will test combinations like:
- `admin: password`
- `admin: secret`
- `admin: token`
- `user: password`
- `user: secret`
- ... and so on (25 total combinations)

## Detection

The module reports findings when:
- Payloads are reflected in the response
- Response status codes are 4xx or 5xx
- Any interesting response is received

## Output

Each finding includes:
- Vulnerability status
- Description with payload and response details
- Original request with injected payload
- Response status and size
- The specific payload combination used 