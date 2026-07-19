#!/usr/bin/env bash
# Uninstall the ecosystem registry — FULL removal of everything the installer added.
#
# Removes: the launchd/systemd service, the internal-disk runtime
# (~/.local/share/ecosystem: venv + data), registry state in the repo (data/*.json,
# *.pid, *.log), the shared config dir (~/.config/ecosystem: secret.env + partner
# apps.json), and the log dir (~/Library/Logs/Ecosystem).
#
# This DELETES the shared HMAC secret and the partner credential store. Every other
# app in the ecosystem authenticates with that secret — only run this if you are
# tearing the whole ecosystem down. To keep credentials/partners, use the sibling
# script instead:
#
#   ./scripts/uninstall.sh              # FULL purge (asks to confirm)
#   ./scripts/uninstall.sh --yes        # FULL purge, no prompt (CI/automation)
#   ./scripts/uninstall.sh --dry-run    # print what would be removed
#   ./scripts/uninstall-keep-data.sh    # remove service+runtime, KEEP secret/partners
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
OS="$(uname -s)"

PREFIX="${ECOSYSTEM_PREFIX:-$HOME/.local/share/ecosystem}"
CONFIG_DIR="$HOME/.config/ecosystem"
LOG_DIR="$HOME/Library/Logs/Ecosystem"
PLIST="$HOME/Library/LaunchAgents/com.ecosystem.registry.plist"

KEEP_DATA=false
DRY=false
NONINTERACTIVE="${ECOSYSTEM_NONINTERACTIVE:-${CI:-}}"
for arg in "$@"; do
    case "$arg" in
        --keep-data)                 KEEP_DATA=true ;;
        -y|--yes|--non-interactive)  NONINTERACTIVE=1 ;;
        --dry-run)                   DRY=true ;;
        -h|--help)                   grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

run() { echo "  $*"; $DRY || eval "$@"; }

if $KEEP_DATA; then
    echo "=== Uninstalling ecosystem registry ($OS) — keeping user data ==="
else
    echo "=== Uninstalling ecosystem registry ($OS) — FULL purge ==="
    echo "This deletes the shared secret (~/.config/ecosystem/secret.env) and the"
    echo "partner credential store (apps.json). Other ecosystem apps will fail to"
    echo "authenticate until re-provisioned."
    if [ -z "$NONINTERACTIVE" ] && ! $DRY; then
        read -rp "Type 'yes' to permanently remove all registry data: " confirm
        [ "$confirm" = "yes" ] || { echo "Aborted."; exit 1; }
    fi
fi

# 1. Stop + remove the OS service.
case "$OS" in
  Darwin)
    if [ -f "$PREFIX/venv/bin/python" ]; then
        run "\"$PREFIX/venv/bin/python\" -m cli.main stop || true"
    fi
    if [ -f "$PLIST" ]; then
        run "launchctl bootout gui/\$(id -u)/com.ecosystem.registry 2>/dev/null || launchctl unload \"$PLIST\" 2>/dev/null || true"
        run "rm -f \"$PLIST\""
    else
        echo "  (no launchd plist found)"
    fi
    ;;
  Linux)
    if [ -x "$SCRIPT_DIR/uninstall_systemd.sh" ]; then
        run "sudo \"$SCRIPT_DIR/uninstall_systemd.sh\" || echo 'systemd uninstall skipped — run scripts/uninstall_systemd.sh manually.'"
    fi
    ;;
  *) echo "  Unknown OS '$OS' — no service to remove." ;;
esac

# 2. Remove the internal-disk runtime (venv + prefix data).
run "rm -rf \"$PREFIX\""

# 3. Remove registry state / logs / pids inside the repo.
run "rm -f \"$ROOT_DIR/data/\"*.pid \"$ROOT_DIR/data/\"*.log 2>/dev/null || true"
if ! $KEEP_DATA; then
    run "rm -f \"$ROOT_DIR/data/registry.json\" \"$ROOT_DIR/data/ai_profile.json\" 2>/dev/null || true"
fi

# 4. Remove log dir.
run "rm -rf \"$LOG_DIR\""

# 5. User data: shared secret + partner credentials.
if $KEEP_DATA; then
    echo "==> Kept user data: $CONFIG_DIR (secret.env, apps.json) and registry.json"
else
    run "rm -rf \"$CONFIG_DIR\""
    echo "==> Removed shared secret + partner store ($CONFIG_DIR)"
fi

echo "Done. Reinstall with: ./scripts/install-local.sh"
