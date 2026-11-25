"""CLI entry point: python -m ecosystem"""

from __future__ import annotations

import argparse
import sys

from .commands import (
    cmd_apps, cmd_compact, cmd_doctor, cmd_install, cmd_logs, cmd_monitor, cmd_partner, cmd_provider,
    cmd_restart, cmd_scan, cmd_secret, cmd_start, cmd_start_all, cmd_status, cmd_stop,
    cmd_stop_all, cmd_totp_recover, cmd_uninstall,
)


def main():
    parser = argparse.ArgumentParser(
        prog="ecosystem",
        description="App Ecosystem management CLI",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    sub.add_parser("start", help="Start the ecosystem registry only")
    sub.add_parser("stop", help="Stop the ecosystem registry only")
    sub.add_parser("restart", help="Restart the ecosystem registry")
    sub.add_parser("start-all", help="Start registry and all projects")
    sub.add_parser("stop-all", help="Stop all projects and registry")
    sub.add_parser("status", help="Show health status of all services")

    monitor_parser = sub.add_parser("monitor", help="Live health dashboard")
    monitor_parser.add_argument("-i", "--interval", type=int, default=5,
                                help="Refresh interval in seconds (default: 5)")
    monitor_parser.add_argument("--once", action="store_true",
                                help="Render a single snapshot and exit")

    logs_parser = sub.add_parser("logs", help="View project logs")
    logs_parser.add_argument("project", nargs="?", default=None,
                             help="Project key (omit to list available logs)")
    logs_parser.add_argument("-n", "--lines", type=int, default=50,
                             help="Number of lines to show (default: 50)")

    sub.add_parser("install", help="Install ecosystem as a system service (launchd)")
    sub.add_parser("uninstall", help="Remove ecosystem system service")

    apps_parser = sub.add_parser("apps", help="List which ecosystem apps are installed on this device")
    apps_parser.add_argument("--json", action="store_true", dest="as_json",
                             help="Output the per-device app record as JSON")

    secret_parser = sub.add_parser("secret", help="Manage the shared ecosystem HMAC secret")
    secret_parser.add_argument("action", choices=["generate", "show", "import", "path"],
                               help="generate (if absent), show (to copy elsewhere), import <value>, path")
    secret_parser.add_argument("value", nargs="?", default=None,
                               help="secret value (for 'import')")

    provider_parser = sub.add_parser("provider", help="Manage cloud AI provider API keys")
    provider_parser.add_argument("action", choices=["list", "set", "delete"])
    provider_parser.add_argument("name", nargs="?", help="anthropic | openai | gemini")
    provider_parser.add_argument("value", nargs="?", help="key (omit to be prompted without echo)")

    partner_parser = sub.add_parser("partner", help="Manage third-party partner app credentials")
    partner_parser.add_argument("action",
                                choices=["add", "approve", "reject", "list", "show",
                                         "suspend", "resume", "remove"])
    partner_parser.add_argument("app_id", nargs="?", default=None)
    partner_parser.add_argument("--name", default=None, help="Display name (add)")
    partner_parser.add_argument("--owner", default=None, help="Owner contact (add)")
    partner_parser.add_argument("--service-names", dest="service_names", default=None,
                                help="Comma-separated service names the app may manage (add/approve)")
    partner_parser.add_argument("--scopes", default=None,
                                help="Comma-separated scopes to grant (add/approve), e.g. "
                                     "commands:dispatch,commands:read,camera:record")
    partner_parser.add_argument("--first-party", dest="first_party", action="store_true",
                                help="Treat as a first-party app: may own a reserved service name (add/approve)")

    scan_parser = sub.add_parser("scan", help="Manage and run Zero-Breach-Toolkit endpoint scans")
    scan_sub = scan_parser.add_subparsers(dest="scan_action")

    scan_run_p = scan_sub.add_parser("run", help="Run an endpoint scan")
    scan_run_p.add_argument("--device-id", default="local", help="Target device ID (default: local)")
    scan_run_p.add_argument("--profile", choices=["quick", "full"], default="quick", help="Scan profile (default: quick)")
    scan_run_p.add_argument("--no-feeds", action="store_true", help="Scan with built-in indicators only (offline)")

    scan_status_p = scan_sub.add_parser("status", help="Show status of a scan")
    scan_status_p.add_argument("scan_id", nargs="?", default=None, help="Scan ID (default: most recent)")

    scan_list_p = scan_sub.add_parser("list", help="List recent scans")
    scan_list_p.add_argument("--device-id", default=None, help="Filter by device ID")

    scan_targets_p = scan_sub.add_parser("targets", help="List enrolled scan targets and auto-scan eligibility")

    doctor_parser = sub.add_parser("doctor", help="Hardware, GPU, and runtime diagnostic inspector")
    doctor_parser.add_argument("component", nargs="?", default="gpu", choices=["gpu"], help="Component to diagnose (default: gpu)")

    totp_parser = sub.add_parser(
        "totp-recover",
        help="Local-only recovery for a lost TOTP second factor",
    )
    totp_parser.add_argument("operator_id", nargs="?", default=None, help="Operator ID to recover (omit to list)")
    totp_parser.add_argument("--list", action="store_true", dest="list_only", help="List enrolled operators and factor counts")
    totp_parser.add_argument("--yes", action="store_true", dest="confirm", help="Confirm removing the operator's TOTP secret")
    totp_parser.add_argument("--store-path", dest="store_path", default=None, help="Optional override path to step_up_credentials.json")

    compact_parser = sub.add_parser(
        "compact",
        help="Compact SQLite WAL files and archive offline event logs",
    )
    compact_parser.add_argument("--data-dir", dest="data_dir", default=None, help="Data directory to compact (default: ecosystem data dir)")
    compact_parser.add_argument("--vacuum", action="store_true", help="Force SQLite VACUUM in addition to WAL checkpoint")
    compact_parser.add_argument("--codec", choices=["auto", "zstd", "gzip"], default="auto", help="Archive compression codec (default: auto)")

    args = parser.parse_args()

    commands = {
        "start": cmd_start,
        "stop": cmd_stop,
        "restart": cmd_restart,
        "start-all": cmd_start_all,
        "stop-all": cmd_stop_all,
        "status": cmd_status,
        "install": cmd_install,
        "uninstall": cmd_uninstall,
    }

    if args.command == "logs":
        sys.exit(cmd_logs(args.project, args.lines))
    elif args.command == "monitor":
        sys.exit(cmd_monitor(args.interval, args.once))
    elif args.command == "secret":
        sys.exit(cmd_secret(args.action, args.value))
    elif args.command == "apps":
        sys.exit(cmd_apps(args.as_json))
    elif args.command == "provider":
        sys.exit(cmd_provider(args.action, args.name, args.value))
    elif args.command == "partner":
        sys.exit(cmd_partner(args.action, args.app_id, args.name, args.owner, args.service_names,
                             scopes=getattr(args, "scopes", None),
                             first_party=getattr(args, "first_party", False)))
    elif args.command == "scan":
        sys.exit(cmd_scan(
            args.scan_action,
            device_id=getattr(args, "device_id", None),
            profile=getattr(args, "profile", "quick"),
            no_feeds=getattr(args, "no_feeds", False),
            scan_id=getattr(args, "scan_id", None),
        ))
    elif args.command == "doctor":
        sys.exit(cmd_doctor(getattr(args, "component", "gpu")))
    elif args.command == "totp-recover":
        sys.exit(cmd_totp_recover(
            getattr(args, "operator_id", None),
            list_only=getattr(args, "list_only", False),
            confirm=getattr(args, "confirm", False),
            store_path=getattr(args, "store_path", None),
        ))
    elif args.command == "compact":
        sys.exit(cmd_compact(
            getattr(args, "data_dir", None),
            vacuum=getattr(args, "vacuum", False),
            codec=getattr(args, "codec", "auto"),
        ))
    elif args.command in commands:
        sys.exit(commands[args.command]())
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
