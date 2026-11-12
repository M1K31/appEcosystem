#!/usr/bin/env bash
# release-pypi.sh — Build, verify and (only when asked) publish the ecosystem's
# Python packages.
#
#   scripts/release-pypi.sh                 build + verify only (the default; publishes nothing)
#   scripts/release-pypi.sh --testpypi      as above, then upload to TestPyPI
#   scripts/release-pypi.sh --publish       as above, then upload to PyPI
#
# What "verify" means:
#   1. every package builds an sdist and a wheel
#   2. `twine check` passes on all of them
#   3. the whole set installs into a brand-new virtualenv using ONLY these
#      artifacts for the ecosystem packages, and every module imports from a
#      directory that is not this checkout
#   4. each version is compared with PyPI: a package whose version is already
#      published is skipped at upload time (PyPI never allows re-uploading a version)
#
# Credentials are never read or stored by this script. Uploading uses whatever
# twine finds: TWINE_USERNAME=__token__ and TWINE_PASSWORD=<api token> in the
# environment, or ~/.pypirc. See docs/PUBLISHING.md.
#
# Exit codes: 0 ok, 1 build/verify/upload failure, 2 usage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Dependency order: a package appears after everything it depends on, so a
# half-finished upload never leaves PyPI with a package whose requirement is missing.
PACKAGES=(
    "auth/python"                 # appecosystem-auth
    "packages/ecosystem-ai"       # appecosystem-ai
    "packages/ecosystem-client"   # appecosystem-client   (needs auth)
    "packages/ecosystem-policy"   # appecosystem-policy   (needs auth, client)
    "packages/ecosystem-hub"      # appecosystem-hub      (needs auth, client)
    "packages/ecosystem-compute"  # appecosystem-compute
    "packages/ecosystem-voice"    # appecosystem-voice
    "."                           # appecosystem          (needs all of the above)
)
IMPORT_CHECK=(
    ecosystem_auth ecosystem_client ecosystem_client.ulid ecosystem_client.contracts
    ecosystem_ai ecosystem_policy ecosystem_hub ecosystem_compute ecosystem_voice
    agents.scan_agent registry.app cli.main
)

MODE="verify"
for arg in "$@"; do
    case "$arg" in
        --publish)  MODE="pypi" ;;
        --testpypi) MODE="testpypi" ;;
        -h|--help)  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "release-pypi: unknown option: $arg" >&2; exit 2 ;;
    esac
done

PY="${PYTHON_BIN:-}"
if [ -z "$PY" ]; then
    for c in python3.12 python3.13 python3.11 python3.10 python3; do
        if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
            PY="$c"; break
        fi
    done
fi
[ -n "$PY" ] || { echo "release-pypi: no Python >= 3.10 found (set PYTHON_BIN)" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/eco-release.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
OUT="$REPO_ROOT/dist/release"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> Tooling venv ($PY)"
"$PY" -m venv "$WORK/tools"
"$WORK/tools/bin/pip" install --quiet --upgrade pip build twine

echo "==> Building ${#PACKAGES[@]} packages into dist/release/"
for pkg in "${PACKAGES[@]}"; do
    "$WORK/tools/bin/python" -m build --outdir "$OUT" "$REPO_ROOT/$pkg" >"$WORK/build.log" 2>&1 \
        || { echo "BUILD FAILED: $pkg" >&2; tail -20 "$WORK/build.log" >&2; exit 1; }
    echo "    built $pkg"
done

echo "==> twine check"
"$WORK/tools/bin/twine" check "$OUT"/* >"$WORK/twine.log" 2>&1 \
    || { cat "$WORK/twine.log" >&2; exit 1; }

echo "==> Clean-environment install (no checkout on the path)"
"$PY" -m venv "$WORK/clean"
"$WORK/clean/bin/pip" install --quiet --upgrade pip
# --find-links lets pip take the ecosystem packages from dist/release even when
# those versions are not on PyPI yet; third-party packages still come from PyPI.
"$WORK/clean/bin/pip" install --quiet --find-links "$OUT" "appecosystem" >"$WORK/install.log" 2>&1 \
    || { echo "CLEAN INSTALL FAILED" >&2; tail -20 "$WORK/install.log" >&2; exit 1; }
mkdir -p "$WORK/empty"
(
    cd "$WORK/empty"
    ECOSYSTEM_HMAC_SECRET="release-check-secret-0123456789abcdef0123456789abcdef" \
    ECOSYSTEM_POLICY_KEY_DIR="$WORK/state/keys" \
    ECOSYSTEM_POLICY_STATE_FILE="$WORK/state/policy.json" \
    ECOSYSTEM_STEP_UP_FILE="$WORK/state/step_up.json" \
    ECOSYSTEM_APPROVALS_DB="$WORK/state/approvals.db" \
    ECOSYSTEM_REGISTRY_FILE="$WORK/state/registry.json" \
    ECOSYSTEM_CAPABILITIES_FILE="$WORK/state/caps.json" \
    ECOSYSTEM_NOTIFICATIONS_DB="$WORK/state/notify.db" \
    ECOSYSTEM_AI_PROFILE_FILE="$WORK/state/ai.json" \
    "$WORK/clean/bin/python" - "${IMPORT_CHECK[@]}" <<'PYCHECK'
import importlib, os, sys
failed = []
for name in sys.argv[1:]:
    try:
        mod = importlib.import_module(name)
    except Exception as exc:  # report every failure, not just the first
        failed.append(f"{name}: {type(exc).__name__}: {exc}")
        continue
    origin = getattr(mod, "__file__", "") or ""
    if "site-packages" not in origin:
        failed.append(f"{name}: imported from {origin}, not from the installed package")
if failed:
    print("IMPORT CHECK FAILED:\n  " + "\n  ".join(failed), file=sys.stderr)
    sys.exit(1)
print(f"    {len(sys.argv) - 1} modules import from the installed packages")
PYCHECK
) 2>"$WORK/import.err" || { grep -v " INFO \|Deprecat" "$WORK/import.err" >&2; exit 1; }

echo "==> Versions (local vs PyPI)"
TO_UPLOAD=()
for whl in "$OUT"/*.whl; do
    base="$(basename "$whl")"
    dist="${base%%-*}"
    version="$(echo "$base" | cut -d- -f2)"
    name="$(echo "$dist" | tr '_' '-')"
    if "$WORK/tools/bin/pip" download --quiet --no-deps --dest "$WORK/probe" "$name==$version" >/dev/null 2>&1; then
        echo "    $name $version — already on PyPI, will be skipped"
    else
        echo "    $name $version — NOT on PyPI, to upload"
        TO_UPLOAD+=("$OUT/$dist-$version"*)
    fi
done

if [ "$MODE" = "verify" ]; then
    echo
    echo "Verified. Nothing was uploaded. Artifacts: dist/release/"
    echo "To publish: scripts/release-pypi.sh --testpypi   (rehearsal)"
    echo "            scripts/release-pypi.sh --publish    (PyPI)"
    exit 0
fi

if [ "${#TO_UPLOAD[@]}" -eq 0 ]; then
    echo "Nothing to upload: every version is already published."
    exit 0
fi

REPO_FLAG=()
[ "$MODE" = "testpypi" ] && REPO_FLAG=(--repository testpypi)
echo "==> Uploading to $MODE (in dependency order)"
# Upload package by package in dependency order, so a failure stops before a
# dependent package is published without its requirement.
for pkg in "${PACKAGES[@]}"; do
    name="$(grep -m1 '^name' "$REPO_ROOT/$pkg/pyproject.toml" | sed 's/.*"\(.*\)".*/\1/')"
    dist="$(echo "$name" | tr '-' '_')"
    files=()
    for f in "${TO_UPLOAD[@]}"; do
        case "$(basename "$f")" in "$dist"-[0-9]*) files+=("$f") ;; esac
    done
    [ "${#files[@]}" -eq 0 ] && continue
    echo "    $name"
    "$WORK/tools/bin/twine" upload ${REPO_FLAG[@]+"${REPO_FLAG[@]}"} --skip-existing "${files[@]}"
done
echo "Uploaded. Next steps are in docs/PUBLISHING.md (\"After publishing\")."
