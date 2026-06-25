"""CLI entry point: python -m ecosystem"""

import argparse
import sys

from .commands import (
    cmd_apps, cmd_install, cmd_logs, cmd_monitor, cmd_restart, cmd_secret,
    cmd_start, cmd_start_all, cmd_status, cmd_stop, cmd_stop_all, cmd_uninstall,
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
    elif args.command in commands:
        sys.exit(commands[args.command]())
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
