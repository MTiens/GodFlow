# config.py
"""
Global configuration settings for the API Fuzzer.
Modify these values to change the default behavior of the tool.
"""

# --- Network Settings ---
# Default timeout for all HTTP requests in seconds.
# DEFAULT_TIMEOUT = 10.0

# User-Agent string to use for all requests.
# Set to a common browser User-Agent to blend in, or a custom one for tracking.
# USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36"

# Whether to verify SSL/TLS certificates.
# Set to False when testing against development environments with self-signed certs.
# WARNING: Setting this to False in production is a security risk.
VERIFY_SSL = False

# --- Proxy Settings ---
# Set to True to route all traffic through the defined proxy.
# Useful for debugging requests with tools like Burp Suite or OWASP ZAP.
USE_PROXY = True

# The proxy URLs to use if USE_PROXY is True.
HTTP_PROXIES = {
    "http://": "http://127.0.0.1:8082",
    "https://": "http://127.0.0.1:8082",
}

# --- Concurrency Settings ---
# The number of concurrent requests to make when running in asynchronous mode.
# A higher number can speed up fuzzing but may overload the target server.
ASYNC_CONCURRENCY = 10

# --- Logging and Verbosity ---
# Set to True for more detailed output during execution.
# Can be overridden by the --verbose command-line flag.
VERBOSE_MODE = True

# --- Fuzzing Defaults ---
# Default delay between fuzzing requests in milliseconds.
# Can be overridden by individual module configuration.
FUZZ_DELAY = 500

# Default max concurrent requests for fuzzing.
# Set to 1 for serial execution (safe mode).
FUZZ_CONCURRENCY = 1
