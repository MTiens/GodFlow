# main.py
"""
Main entry point for the API Fuzzing and Testing Tool.
This script provides a command-line interface to run and fuzz API flows.

Example Usage:
  # Run a flow definition without fuzzing
  > python main.py run flows/register_flow.json

  # Collect baseline responses for future fuzzing comparison
  > python main.py baseline flows/register_flow.json

  # Run the full fuzzing test suite defined in the flow
  > python main.py fuzz flows/register_flow.json

  # Run in asynchronous mode for faster execution
  > python main.py fuzz flows/register_flow.json --async

  # Run with proxy support
  > python main.py fuzz flows/register_flow.json --proxy http://proxy.example.com:8080
  > python main.py fuzz flows/register_flow.json --proxy http://user:pass@proxy.example.com:8080
"""

import argparse
import asyncio
from pathlib import Path
from run import run

def main():
    """The main asynchronous function that sets up and runs the tool."""
    
    parser = argparse.ArgumentParser(
        description="A Python tool for fuzzing and testing APIs using httpx.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # --- Global arguments that apply to all sub-commands ---
    parser.add_argument(
        "--requests-dir",
        type=str,
        default="requests",
        help="Directory where request template files are stored (default: 'requests')."
    )
    parser.add_argument(
        "--payloads-dir",
        type=str,
        default="payloads",
        help="Directory where fuzzing payload files are stored (default: 'payloads')."
    )
    parser.add_argument(
        "--configs-dir",
        type=str,
        default="configs",
        help="Directory where config files are stored (default: 'configs')."
    )
    parser.add_argument(
        "--proxy",
        type=str,
        help="Proxy URL to use for all requests (e.g., http://proxy.example.com:8080 or http://user:pass@proxy.example.com:8080)."
    )
    parser.add_argument(
        "--proxy-auth",
        type=str,
        help="Proxy authentication in format 'username:password' (alternative to embedding in proxy URL)."
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification for proxy connections."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for detailed logging."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output for [DEBUG] messages."
    )

    # --- Sub-commands for different modes of operation ---
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # 'run' command: Executes the flow without fuzzing.
    parser_run = subparsers.add_parser(
        "run",
        help="Run a simple flow of API calls without any fuzzing.",
        description="Executes the steps in a flow file sequentially to test a standard API workflow."
    )
    parser_run.add_argument(
        "flow_file",
        type=Path,
        help="Path to the JSON flow definition file."
    )
    parser_run.add_argument(
        "--async",
        dest="is_async",
        action="store_true",
        help="Run the flow asynchronously (faster for flows with many independent steps)."
    )
    parser_run.add_argument(
        "--output", "-o",
        nargs="?",
        const=True,
        help="Output file to save results. Use --output to auto-generate filename, or --output filename.txt for specific file."
    )
    parser_run.add_argument(
        "--persona",
        type=str,
        help="Specify which persona to use for authentication (default: first persona in flow)."
    )

    # 'baseline' command: Collects baseline responses for later comparison during fuzzing
    parser_baseline = subparsers.add_parser(
        "baseline",
        help="Collect baseline responses from a normal flow execution for enhanced vulnerability detection.",
        description="Executes the flow to capture 'golden' responses that will be used as baselines for anomaly detection during fuzzing."
    )
    parser_baseline.add_argument(
        "flow_file",
        type=Path,
        help="Path to the JSON flow definition file."
    )
    parser_baseline.add_argument(
        "--async",
        dest="is_async",
        action="store_true",
        help="Run the baseline collection asynchronously for faster execution."
    )
    parser_baseline.add_argument(
        "--output", "-o",
        nargs="?",
        const=True,
        help="Output file to save results. Use --output to auto-generate filename, or --output filename.txt for specific file."
    )
    parser_baseline.add_argument(
        "--persona",
        type=str,
        help="Specify which persona to use for authentication (default: first persona in flow)."
    )

    # 'fuzz' command: Executes the flow with all defined fuzzing tests.
    parser_fuzz = subparsers.add_parser(
        "fuzz",
        help="Run a flow and execute all defined fuzzing tests.",
        description="Executes the flow, running specified fuzzing modules (e.g., for SQLi, XSS, IDOR) on targeted steps."
    )
    parser_fuzz.add_argument(
        "flow_file",
        type=Path,
        help="Path to the JSON flow definition file containing fuzzing configurations."
    )
    parser_fuzz.add_argument(
        "--async",
        dest="is_async",
        action="store_true",
        help="Run the fuzzing tests asynchronously for significant speed improvements."
    )
    parser_fuzz.add_argument(
        "--output", "-o",
        nargs="?",
        const=True,
        help="Output file to save results. Use --output to auto-generate filename, or --output filename.txt for specific file."
    )
    parser_fuzz.add_argument(
        "--persona",
        type=str,
        help="Specify which persona to use for authentication (default: first persona in flow)."
    )
    
    args = parser.parse_args()

    if not args.flow_file.is_file():
        print(f"Error: Flow file not found at '{args.flow_file}'")
        return

    # --- Infer requests_dir, payloads_dir, and configs_dir from flow file path if not explicitly set ---
    flow_path = args.flow_file.resolve()
    # If the flow file is in .../projects/<project>/flows/..., set requests_dir/configs_dir to .../projects/<project>/requests/configs
    if args.requests_dir == "requests":
        if "projects" in flow_path.parts:
            try:
                idx = flow_path.parts.index("projects")
                project_root = Path(*flow_path.parts[:idx+2])  # .../projects/<project>
                inferred_requests_dir = project_root / "requests"
                if inferred_requests_dir.exists():
                    args.requests_dir = str(inferred_requests_dir)
            except Exception:
                pass
    if args.payloads_dir == "payloads":
        if "projects" in flow_path.parts:
            try:
                idx = flow_path.parts.index("projects")
                project_root = Path(*flow_path.parts[:idx+2])
                inferred_payloads_dir = project_root / "payloads"
                if inferred_payloads_dir.exists():
                    args.payloads_dir = str(inferred_payloads_dir)
            except Exception:
                pass
    if args.configs_dir == "configs":
        if "projects" in flow_path.parts:
            try:
                idx = flow_path.parts.index("projects")
                project_root = Path(*flow_path.parts[:idx+2])
                inferred_configs_dir = project_root / "configs"
                if inferred_configs_dir.exists():
                    args.configs_dir = str(inferred_configs_dir)
            except Exception:
                pass

    # Validate proxy configuration
    import config
    
    proxy_config = None
    proxy_url = args.proxy
    proxy_auth = args.proxy_auth
    # CLI arg is "no_verify_ssl" (True means disable), Config is "VERIFY_SSL" (True means enable)
    # If generic default is True (Verify), no-verify makes it False.
    # We start with default from config if not specified? 
    # Actually args.no_verify_ssl is False by default.
    verify_ssl = config.VERIFY_SSL if not args.no_verify_ssl else False
    
    # If no proxy arg, check global config
    if not proxy_url and config.USE_PROXY:
        # Pick a default proxy URL from the config dict (httpx usually allows specific dicts, 
        # but our Runner expects a single 'url' in proxy_config to map to both)
        # We'll default to the http one for the general 'url' field
        proxy_url = config.HTTP_PROXIES.get("http://") or config.HTTP_PROXIES.get("https://")
        
    if proxy_url:
        proxy_config = {
            'url': proxy_url,
            'auth': proxy_auth,
            'verify_ssl': verify_ssl
        }
        
        # Validate proxy URL format
        if not proxy_url.startswith(('http://', 'https://')):
            print(f"Error: Proxy URL must start with 'http://' or 'https://': {proxy_url}")
            return

    # Determine output file name if needed
    output_file = None
    if hasattr(args, 'output') and args.output:
        if args.output:
            # Auto-generate name
            import datetime
            project = None
            flow = args.flow_file.stem
            project_dir = None
            if "projects" in args.flow_file.parts:
                try:
                    idx = args.flow_file.parts.index("projects")
                    project = args.flow_file.parts[idx+1]
                    # project_dir = .../projects/<project>
                    project_dir = Path(*args.flow_file.parts[:idx+2])
                except Exception:
                    project = "project"
                    project_dir = Path(".")
            else:
                project = "project"
                project_dir = Path(".")
            now = datetime.datetime.now()
            date_str = now.strftime("%d%m%Y")
            stimestamp = str(int(now.timestamp()))
            results_dir = project_dir / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            output_file = str(results_dir / f"{project}_{flow}_{date_str}_{stimestamp}.txt")
        else:
            output_file = args.output
    print("--- API Fuzzer Starting ---")
    print(f"Mode:         {args.command.upper()}")
    print(f"Flow File:    {args.flow_file}")
    if proxy_config:
        print(f"Proxy:        {proxy_config['url']}")
        print(f"Proxy Auth:   {proxy_config['auth']}")
        print(f"SSL Verify:   {'Enabled' if proxy_config['verify_ssl'] else 'Disabled'}")
    print(f"Requests:     {args.requests_dir}/")
    print(f"Payloads:     {args.payloads_dir}/")
    print(f"Configs:      {args.configs_dir}/")
    print(f"Async Mode:   {'Enabled' if args.is_async else 'Disabled'}")
    if args.persona:
        print(f"Persona:      {args.persona}")
    else:
        print(f"Persona:      (will use first available)")
    if proxy_config:
        print(f"Proxy:        {proxy_config['url']}")
        if proxy_config['auth']:
            print(f"Proxy Auth:   {proxy_config['auth']}")
        print(f"SSL Verify:   {'Enabled' if proxy_config['verify_ssl'] else 'Disabled'}")
    else:
        print(f"Proxy:        (not configured)")
    print(f"Output File:  {output_file}")
    print("---------------------------\n")

    asyncio.run(run(args.flow_file, args.requests_dir, args.payloads_dir, args.is_async, args.verbose, args.command, args.persona, proxy_config, args.debug, args.configs_dir, output_file))   
    
if __name__ == "__main__":
    main()