#!/usr/bin/env bash
# release-npm.sh — Verify and (only when asked) publish the ecosystem's npm packages.
#
#   scripts/release-npm.sh             verify only (the default; publishes nothing)
#   scripts/release-npm.sh --publish   verify, then `npm publish` every package whose
#                                      version is not on the registry yet
#
# Packages, in dependency order:
#   auth/js               @smartindustriesllc/ecosystem-auth
#   ecosystem_client_js   @smartindustriesllc/ecosystem-client   (depends on ecosystem-auth)
#
# Verify means: the package's tests pass, the tarball contains the files a
# consumer needs (the client must ship src/hub.js — the 0.1.0 release did not,
# which is why MagicMirror had no HubClient), and the packed tarball can be
# installed into an empty project and required from there.
#
# Publishing uses your own npm login (`npm login`, or an automation token in
# ~/.npmrc). This script never reads or stores credentials. See docs/PUBLISHING.md.
#
# Exit codes: 0 ok, 1 verify/publish failure, 2 usage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
PACKAGES=("auth/js" "ecosystem_client_js")

PUBLISH=0
for arg in "$@"; do
    case "$arg" in
        --publish) PUBLISH=1 ;;
        -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "release-npm: unknown option: $arg" >&2; exit 2 ;;
    esac
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/eco-npm.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

field() { node -e 'console.log(require(process.argv[1])[process.argv[2]])' "$1/package.json" "$2"; }

TO_PUBLISH=()
TARBALLS=()
for pkg in "${PACKAGES[@]}"; do
    dir="$REPO_ROOT/$pkg"
    name="$(field "$dir" name)"
    version="$(field "$dir" version)"
    echo "==> $name $version"

    if node -e 'process.exit(require(process.argv[1]).scripts?.test ? 0 : 1)' "$dir/package.json"; then
        (cd "$dir" && npm test --silent >"$WORK/test.log" 2>&1) \
            || { echo "TESTS FAILED: $name" >&2; tail -20 "$WORK/test.log" >&2; exit 1; }
        echo "    tests pass"
    fi

    tarball="$(cd "$dir" && npm pack --silent --pack-destination "$WORK" | tail -1)"
    TARBALLS+=("$WORK/$tarball")
    listing="$(tar -tzf "$WORK/$tarball")"
    main="$(field "$dir" main)"
    for required in package/package.json package/README.md package/LICENSE "package/${main#./}"; do
        echo "$listing" | grep -qx "$required" || { echo "MISSING from tarball: $required" >&2; exit 1; }
    done
    if [ "$name" = "@smartindustriesllc/ecosystem-client" ]; then
        echo "$listing" | grep -qx "package/src/hub.js" || { echo "MISSING from tarball: package/src/hub.js" >&2; exit 1; }
    fi
    echo "    tarball has $(echo "$listing" | wc -l | tr -d ' ') files"

    if npm view "$name@$version" version >/dev/null 2>&1; then
        echo "    already on npm — will be skipped"
    else
        echo "    NOT on npm — to publish"
        TO_PUBLISH+=("$pkg")
    fi
done

echo "==> Install the packed tarballs into an empty project and require them"
mkdir -p "$WORK/consumer"
(
    cd "$WORK/consumer"
    npm init -y >/dev/null 2>&1
    npm install --silent --no-audit --no-fund "${TARBALLS[@]}" >"$WORK/install.log" 2>&1 \
        || { echo "CONSUMER INSTALL FAILED" >&2; tail -20 "$WORK/install.log" >&2; exit 1; }
    node -e '
        const client = require("@smartindustriesllc/ecosystem-client");
        const auth = require("@smartindustriesllc/ecosystem-auth");
        const missing = ["EcosystemClient", "HubClient"].filter((k) => typeof client[k] !== "function");
        if (missing.length) { console.error("client is missing exports: " + missing.join(", ")); process.exit(1); }
        if (!auth || !Object.keys(auth).length) { console.error("auth exports nothing"); process.exit(1); }
        console.log("    client exports EcosystemClient and HubClient; auth loads");
    '
)

if [ "$PUBLISH" -eq 0 ]; then
    echo
    echo "Verified. Nothing was published."
    echo "To publish: scripts/release-npm.sh --publish"
    exit 0
fi

if [ "${#TO_PUBLISH[@]}" -eq 0 ]; then
    echo "Nothing to publish: every version is already on npm."
    exit 0
fi

npm whoami >/dev/null 2>&1 || { echo "Not logged in to npm. Run: npm login" >&2; exit 1; }
for pkg in "${TO_PUBLISH[@]}"; do
    echo "==> npm publish $pkg"
    (cd "$REPO_ROOT/$pkg" && npm publish --access public)
done
echo "Published. Next steps are in docs/PUBLISHING.md (\"After publishing\")."
