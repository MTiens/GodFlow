# File Upload Fuzzer Module

Fuzz file upload endpoints by injecting malicious payload files with various bypass techniques.

## Usage in Flow YAML

```yaml
steps:
  - name: upload_step
    request: upload.txt
    fuzz:
      file_upload_fuzzer:
        enable: true
        payload_folder: payloads/upload  # Required
        field_name: file                  # Optional, default: 'file'
        bypass_techniques:                # Optional, default: ['none']
          - none
          - double_extension
          - null_byte
          - null_byte_raw
          - mime_spoof
          - content_type_mismatch
          - case_manipulation
          - unicode
          - alternative_extension
        matchers:                         # Optional
          - type: status
            value: [200, 201]
          - type: contains
            value: "success"
```

## Configuration

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `payload_folder` | Yes | - | Path to folder containing payload files |
| `field_name` | No | `file` | Form field name for file upload |
| `bypass_techniques` | No | `['none']` | List of techniques to apply |
| `matchers` | No | - | Custom matchers for vulnerability detection |

## Bypass Techniques

| Technique | Example | Description |
|-----------|---------|-------------|
| `none` | `shell.php` | Upload as-is |
| `double_extension` | `shell.php.jpg` | Add allowed extension |
| `null_byte` | `shell.php%00.jpg` | URL-encoded null byte |
| `null_byte_raw` | `shell.php\x00.jpg` | Raw null byte |
| `mime_spoof` | `shell.php` with `image/jpeg` | Spoof Content-Type |
| `content_type_mismatch` | `shell_uploaded` | Remove extension |
| `case_manipulation` | `shell.pHp` | Mixed case extension |
| `unicode` | `shell.p\u200dh\u200dp` | Zero-width joiner |
| `alternative_extension` | `shell.phtml` | Alternative PHP ext |
