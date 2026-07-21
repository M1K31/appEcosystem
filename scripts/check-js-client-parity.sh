#!/usr/bin/env bash
# The JS ecosystem client is vendored into MagicMirror (js/ecosystem-client/) and
# also lives here as the source package (ecosystem_client_js/src/). The two copies
# drifted once already: the vendored copy had a fail-closed secret resolver while
# the source still defaulted hmacSecret to the committed development secret, which
# silently broke registry auth for anyone using the source package.
#
# This guard fails on two things:
#   1. shared modules differing between the source and the vendored copy
#   2. EITHER copy falling back to the known dev secret
#
# Exits 0 (SKIP) when the vendored copy is not checked out beside this repo, so it
# is safe to run in CI where only appEcosystem is present.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/ecosystem_client_js/src"
VENDOR="${MAGICMIRROR_PATH:-$(cd "$REPO_ROOT/.." && pwd)/MagicMirror-Custom}/js/ecosystem-client"

DEV_SECRET='dev-ecosystem-secret-change-in-production'

if [ ! -d "$SRC" ]; then
    echo "FAIL: source JS client missing at $SRC"; exit 1
fi
if [ ! -d "$VENDOR" ]; then
    echo "SKIP: vendored copy not checked out at $VENDOR"; exit 0
fi

status=0

# Modules that must stay byte-identical between the two copies.
for f in secret.js; do
    if [ ! -f "$SRC/$f" ]; then
        echo "FAIL: $f missing from source ($SRC)"; status=1; continue
    fi
    if [ ! -f "$VENDOR/$f" ]; then
        echo "FAIL: $f missing from vendored copy ($VENDOR)"; status=1; continue
    fi
    if diff -q "$SRC/$f" "$VENDOR/$f" >/dev/null 2>&1; then
        echo "OK: $f in sync"
    else
        echo "FAIL: $f differs between source and vendored copy"
        diff -u "$SRC/$f" "$VENDOR/$f" || true
        status=1
    fi
done

# Neither copy may FALL BACK to the committed development secret — the registry
# rejects it outright, so that silently breaks inter-service auth.
#
# Declaring it as a named constant is correct and expected: secret.js defines
# DEFAULT_DEV_SECRET precisely so resolveSecret() can recognise and refuse it.
# So we exclude that declaration and flag any OTHER appearance, which in practice
# means a literal `... || "dev-ecosystem-..."` fallback — the original bug.
for dir in "$SRC" "$VENDOR"; do
    bad="$(grep -rn "$DEV_SECRET" "$dir" 2>/dev/null | grep -v 'DEFAULT_DEV_SECRET[[:space:]]*=' || true)"
    if [ -n "$bad" ]; then
        echo "FAIL: $dir uses the development secret as a fallback value:"
        echo "$bad" | sed 's/^/    /'
        status=1
    fi
done

if [ $status -eq 0 ]; then
    echo "JS client parity OK"
fi
exit $status
