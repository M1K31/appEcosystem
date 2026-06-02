#!/usr/bin/env python3
"""
Ecosystem Process Supervisor & Daemon Manager (process_manager.py)
Provides bulletproof Unix signal interception (SIGINT, SIGTERM),
clean child process propagation, state cleanup, and SIGKILL escalation.
"""

import sys
import os
import time
import signal
import subprocess
import shlex
import argparse
from pathlib import Path

# Setup paths
ECOSYSTEM_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ECOSYSTEM_DIR / "data"
PID_FILE = DATA_DIR / "registry.pid"

# Global state for signal handler
active_process = None
is_shutting_down = False

def log(msg: str):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [Supervisor] {msg}", flush=True)

def handle_signals(signum, frame):
    """Intercept termination signals and perform a clean shutdown cascade."""
    global active_process, is_shutting_down
    if is_shutting_down:
        return
    is_shutting_down = True
    
    signame = signal.Signals(signum).name
    log(f"Intercepted {signame} signal. Initiating graceful shutdown cascade...")

    if not active_process:
        log("No child process running. Exiting immediately.")
        sys.exit(0)

    pid = active_process.pid
    log(f"Propagating SIGTERM (signal 15) to child process (PID {pid})...")
    
    try:
        # Send SIGTERM to the process group (handles spawned sub-processes)
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except OSError as e:
        log(f"Failed to send SIGTERM to process group: {e}. Trying direct SIGTERM to PID...")
        try:
            active_process.terminate()
        except OSError:
            pass

    # Grace period polling loop (timeout = 5 seconds)
    grace_timeout = 5.0
    poll_interval = 0.2
    elapsed = 0.0
    
    log(f"Waiting up to {grace_timeout}s for graceful process exit and resource cleanup...")
    while elapsed < grace_timeout:
        if active_process.poll() is not None:
            log(f"Child process (PID {pid}) exited cleanly with code {active_process.returncode}")
            cleanup_state()
            sys.exit(active_process.returncode)
        time.sleep(poll_interval)
        elapsed += poll_interval

    # Timeout exceeded - escalate to SIGKILL
    log(f"Grace timeout of {grace_timeout}s exceeded. Process group {pid} is unresponsive.")
    log(f"Escalating to SIGKILL (signal 9) to prevent orphaned processes and memory leaks...")
    
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
        active_process.wait(timeout=2.0)
        log("Process group successfully terminated via SIGKILL.")
    except Exception as e:
        log(f"Error during SIGKILL escalation: {e}")
        # Last-ditch attempt on the parent PID directly
        try:
            active_process.kill()
        except Exception:
            pass

    cleanup_state()
    sys.exit(1)

def cleanup_state():
    """Clean up shared lock files, PIDs, and release sockets."""
    log("Releasing lockfiles and cleaning up supervisor state...")
    if PID_FILE.exists():
        try:
            PID_FILE.unlink()
            log(f"Successfully deleted registry PID file: {PID_FILE}")
        except Exception as e:
            log(f"Failed to delete PID file: {e}")
    log("Cleanup complete. Supervisor shut down.")

def monitor_process(cmd_str: str, cwd: str, log_file: str = None):
    """Launch the subprocess in a new process group and monitor its lifecycle."""
    global active_process
    
    # Setup log destination
    stdout_fh = sys.stdout
    stderr_fh = sys.stderr
    
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_fh = open(log_path, "a")
        stderr_fh = subprocess.STDOUT
        log(f"Redirecting subprocess output to log file: {log_path}")

    # Parse command using shlex to prevent shell injection and handle quotes
    args = shlex.split(cmd_str)
    log(f"Launching subprocess: {args} in cwd: {cwd}")
    
    # Register Unix signal traps
    signal.signal(signal.SIGTERM, handle_signals)
    signal.signal(signal.SIGINT, handle_signals)

    try:
        # start_new_session=True creates a new process group, so that we can signal
        # all spawned sub-processes together and prevent detached zombies.
        active_process = subprocess.Popen(
            args,
            cwd=cwd,
            stdout=stdout_fh,
            stderr=stderr_fh,
            start_new_session=True
        )
        
        # Write PID file
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()))
        log(f"Supervisor started. Child Process PID: {active_process.pid}. Supervisor PID: {os.getpid()}")

        # Keep supervisor alive and monitor child process
        while True:
            retcode = active_process.poll()
            if retcode is not None:
                log(f"Subprocess terminated unexpectedly with exit code {retcode}")
                cleanup_state()
                sys.exit(retcode)
            time.sleep(1.0)
            
    except Exception as e:
        log(f"Failed to execute process: {e}")
        cleanup_state()
        sys.exit(1)
    finally:
        if log_file and stdout_fh is not sys.stdout:
            stdout_fh.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ecosystem Process Supervisor & Signal Wrapper")
    parser.add_argument("--cmd", required=True, help="Command to run")
    parser.add_argument("--cwd", default=str(ECOSYSTEM_DIR), help="Working directory")
    parser.add_argument("--log", default=None, help="Log file path for stdout/stderr redirect")
    
    args = parser.parse_args()
    monitor_process(args.cmd, args.cwd, args.log)
