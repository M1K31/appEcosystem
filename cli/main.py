"""CLI entry point: python -m ecosystem"""

import argparse
import sys

from .commands import cmd_install, cmd_start, cmd_status, cmd_stop, cmd_uninstall


def main():
    parser = argparse.ArgumentParser(
        prog="ecosystem",
        description="App Ecosystem management CLI",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    sub.add_parser("start", help="Start the ecosystem registry and services")
    sub.add_parser("stop", help="Stop the ecosystem registry and services")
    sub.add_parser("status", help="Show health status of all services")
    sub.add_parser("install", help="Install ecosystem as a system service (launchd)")
    sub.add_parser("uninstall", help="Remove ecosystem system service")

    args = parser.parse_args()

    commands = {
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "install": cmd_install,
        "uninstall": cmd_uninstall,
    }

    if args.command in commands:
        sys.exit(commands[args.command]())
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
