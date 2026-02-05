import time
from pathlib import Path

# We assume the Orchestrator will be the main class to interact with.
# Make sure to create this file and class in your core directory.
from core.orchestrator import Orchestrator

async def run(flow_file, requests_dir, payloads_dir, is_async, verbose, command, persona=None, proxy_config=None, debug=False, configs_dir=None, output_file=None):
    import sys
    import io

    class Tee(io.StringIO):
        def __init__(self, *streams):
            super().__init__()
            self.streams = streams
        def write(self, s):
            for stream in self.streams:
                stream.write(s)
            super().write(s)
        def flush(self):
            for stream in self.streams:
                stream.flush()
            super().flush()

    start_time = time.perf_counter()
    orchestrator = None
    output_buffer = io.StringIO() if output_file else None
    orig_stdout = sys.stdout
    if output_buffer:
        sys.stdout = Tee(orig_stdout, output_buffer)
    try:
        # --- Instantiate the Orchestrator with all necessary context ---
        orchestrator = Orchestrator(
            flow_file_path=str(flow_file),
            requests_dir=requests_dir,
            payloads_dir=payloads_dir,
            is_async=is_async,
            verbose=verbose,
            persona=persona,
            proxy_config=proxy_config,
            debug=debug,
            configs_dir=configs_dir
        )
        # --- Execute the chosen command ---
        if command == "run":
            await orchestrator.arun_simple_flow()
        elif command == "baseline":
            await orchestrator.arun_baseline_collection()
        elif command == "fuzz":
            await orchestrator.arun_fuzzing_in_flow()

    except FileNotFoundError as e:
        print(f"[FATAL ERROR] A required file or directory was not found: {e}")
    except Exception as e:
        print(f"[UNHANDLED EXCEPTION] An unexpected error occurred: {e}")
        # In verbose mode, you might want to print the full traceback
        if verbose:
            import traceback
            traceback.print_exc()
    finally:
        # --- Graceful shutdown ---
        # Ensure the httpx client is always closed properly
        if orchestrator:
            print("\n--- Shutting down... ---")
            await orchestrator.aclose()
        end_time = time.perf_counter()
        print(f"Execution finished in {end_time - start_time:.2f} seconds.")
        if output_buffer:
            sys.stdout = orig_stdout
            banner = (
                "="*60 + "\n" +
                "  N3utr1n0x\n" +
                "="*60 + "\n"
            )
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(banner)
                f.write(output_buffer.getvalue())