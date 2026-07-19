#!/usr/bin/env bash
# Uninstall the ecosystem registry but KEEP user data:
#   - the shared HMAC secret (~/.config/ecosystem/secret.env)
#   - the partner credential store (~/.config/ecosystem/apps.json)
#   - the persisted registry + AI profile (data/registry.json, data/ai_profile.json)
#
# Removes only the service and the internal-disk runtime, so you can reinstall
# without re-provisioning credentials or re-pairing partner apps.
#
# For a complete wipe (including the secret and partners) use ./scripts/uninstall.sh
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/uninstall.sh" --keep-data "$@"
