#!/usr/bin/env bash
# sync-clients.sh — Copy ecosystem client libraries to all projects.
# Run from the appEcosystem repo root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Source directories
PY_CLIENT="$REPO_ROOT/ecosystem_client"
JS_CLIENT="$REPO_ROOT/ecosystem_client_js"
PY_AUTH="$REPO_ROOT/auth/python/ecosystem_auth"
JS_AUTH="$REPO_ROOT/auth/js/src"

# Target projects — update these paths for your environment
OPENEYE="${ECOSYSTEM_OPENEYE_PATH:-/Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security}"
LOGANALYSIS="${ECOSYSTEM_LOGANALYSIS_PATH:-/Volumes/Locker2/GitHub/LogAnalysis}"
AI_SURVIVAL="${ECOSYSTEM_AI_SURVIVAL_PATH:-/Volumes/Locker2/GitHub/AI-for-Survival}"
MAGICMIRROR="${ECOSYSTEM_MAGICMIRROR_PATH:-/Volumes/Locker2/GitHub/MagicMirror-Custom}"

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

sync_js() {
    if [ ! -d "$JS_CLIENT" ]; then
        echo "SKIP JS client — not yet created: $JS_CLIENT"
        return
    fi
    if [ ! -d "$MAGICMIRROR" ]; then
        echo "SKIP MagicMirror — directory not found: $MAGICMIRROR"
        return
    fi

    local dest="$MAGICMIRROR/js/ecosystem-client"
    echo "SYNC MagicMirror (JS) → $dest"
    rm -rf "$dest"
    cp -r "$JS_CLIENT/src" "$dest"

    # Also sync auth library
    local auth_dest="$MAGICMIRROR/js/ecosystem-auth"
    echo "SYNC MagicMirror (Auth) → $auth_dest"
    rm -rf "$auth_dest"
    mkdir -p "$auth_dest"
    cp "$JS_AUTH"/*.js "$auth_dest/"
}

echo "=== Ecosystem Client Sync ==="
echo ""

sync_python "$OPENEYE" "openeye"
sync_python "$LOGANALYSIS" "loganalysis"
sync_python "$AI_SURVIVAL" "ai_survival"
sync_js

echo ""
echo "=== Sync complete ==="
