#!/usr/bin/env bash
# sync-ui-assets.sh — Build the shared UI controls bundle and copy it, with the
# shared theme, into projects that vendor a copy.
#
#   scripts/sync-ui-assets.sh [--check] [TARGET_DIR...]
#
# Default target: ../MagicMirror-Custom/modules/default/ecosystem
#
# The vendored files are BUILD OUTPUT. Never edit them in the target project:
# change packages/ecosystem-ui-controls/src or theme/ecosystem-theme.css here
# and re-run this script.
#
#   --check   Copy nothing. Print a unified diff for every vendored file that
#             differs from the freshly built source and exit 1 if any differ.
#
# Exit codes: 0 in sync / synced, 1 drift found (--check), 2 usage or missing target.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

PKG_DIR="$REPO_ROOT/packages/ecosystem-ui-controls"
BUNDLE_SRC="$PKG_DIR/dist/ecosystem-ui-controls.js"
THEME_SRC="$REPO_ROOT/theme/ecosystem-theme.css"

CHECK=0
TARGETS=()
for arg in "$@"; do
    case "$arg" in
        --check) CHECK=1 ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "sync-ui-assets: unknown option: $arg" >&2; exit 2 ;;
        *) TARGETS+=("$arg") ;;
    esac
done
if [ "${#TARGETS[@]}" -eq 0 ]; then
    TARGETS=("$REPO_ROOT/../MagicMirror-Custom/modules/default/ecosystem")
fi

# Validate every target before building or copying anything, so a typo cannot
# leave some projects refreshed and others silently skipped.
for target in "${TARGETS[@]}"; do
    if [ ! -d "$target" ]; then
        echo "sync-ui-assets: target directory not found: $target" >&2
        exit 2
    fi
done

(cd "$PKG_DIR" && npm run --silent build >/dev/null)

for src in "$BUNDLE_SRC" "$THEME_SRC"; do
    if [ ! -f "$src" ]; then
        echo "sync-ui-assets: source file missing: $src" >&2
        exit 2
    fi
done

drift=0
for target in "${TARGETS[@]}"; do
    for src in "$BUNDLE_SRC" "$THEME_SRC"; do
        dest="$target/$(basename "$src")"
        if [ "$CHECK" -eq 1 ]; then
            if [ ! -f "$dest" ]; then
                echo "sync-ui-assets: missing in target: $dest"
                drift=1
            elif ! diff -u "$dest" "$src"; then
                drift=1
            fi
        else
            cp "$src" "$dest"
            echo "synced $(basename "$src") -> $target"
        fi
    done
done

if [ "$CHECK" -eq 1 ] && [ "$drift" -ne 0 ]; then
    echo "sync-ui-assets: vendored UI assets differ from source; run scripts/sync-ui-assets.sh" >&2
    exit 1
fi
