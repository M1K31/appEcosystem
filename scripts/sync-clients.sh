#!/usr/bin/env bash
# sync-clients.sh — Copy ecosystem client libraries to all projects.
# Run from the appEcosystem repo root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Source directories
PY_CLIENT="$REPO_ROOT/ecosystem_client"
PY_AUTH="$REPO_ROOT/auth/python/ecosystem_auth"

# Target projects. Default to this repo's own parent directory so the script
# follows the checkout wherever it lives — the ecosystem moved off an external
# volume to ~/GitHub, and hardcoded absolute defaults silently SKIP every
# project once that path stops resolving (the skip is not an error, so a sync
# could report success having copied nothing).
ECOSYSTEM_BASE_PATH="${ECOSYSTEM_BASE_PATH:-$(dirname "$REPO_ROOT")}"
OPENEYE="${ECOSYSTEM_OPENEYE_PATH:-$ECOSYSTEM_BASE_PATH/OpenEye-OpenCV_Home_Security}"
LOGANALYSIS="${ECOSYSTEM_LOGANALYSIS_PATH:-$ECOSYSTEM_BASE_PATH/LogAnalysis}"
AI_SURVIVAL="${ECOSYSTEM_AI_SURVIVAL_PATH:-$ECOSYSTEM_BASE_PATH/AI-for-Survival}"

sync_python() {
    local target="$1"
    local name="$2"

    if [ ! -d "$target" ]; then
        echo "SKIP $name — directory not found: $target"
        return
    fi

    local dest
    case "$name" in
        openeye)     dest="$target/opencv_surveillance/ecosystem_client" ;;
        loganalysis) dest="$target/src/aegissiem/ecosystem_client" ;;
        ai_survival) dest="$target/backend/src/ecosystem_client" ;;
    esac

    echo "SYNC $name (Python) → $dest"
    rm -rf "$dest"
    cp -r "$PY_CLIENT" "$dest"

    # Also sync auth library
    local auth_dest
    case "$name" in
        openeye)     auth_dest="$target/opencv_surveillance/ecosystem_auth" ;;
        loganalysis) auth_dest="$target/src/aegissiem/ecosystem_auth" ;;
        ai_survival) auth_dest="$target/backend/src/ecosystem_auth" ;;
    esac
    echo "SYNC $name (Auth)   → $auth_dest"
    rm -rf "$auth_dest"
    cp -r "$PY_AUTH" "$auth_dest"
}

# The JS half of this script is gone. MagicMirror used to receive copies of the
# JS client and auth libraries here; it now depends on the published packages
# @smartindustriesllc/ecosystem-client and @smartindustriesllc/ecosystem-auth,
# so npm handles distribution and versioning. scripts/check-js-client-parity.sh,
# which existed only to detect drift between source and those copies, is gone
# for the same reason.

echo "=== Ecosystem Client Sync ==="
echo ""

sync_python "$OPENEYE" "openeye"
sync_python "$LOGANALYSIS" "loganalysis"
sync_python "$AI_SURVIVAL" "ai_survival"

echo ""
echo "=== Sync complete ==="
