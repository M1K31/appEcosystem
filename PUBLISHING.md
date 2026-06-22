# Publishing the Ecosystem Packages — Review Guide

**Prepared for:** Smart Industries LLC
**Status:** For review. We are **not** publishing yet — apps use a **path
install** of the local packages (see §6). This document is the plan for when we
decide to publish.

---

## 1. What would be published

| Package | Location | Registry | Consumers |
|---------|----------|----------|-----------|
| `ecosystem-ai` | `packages/ecosystem-ai` | PyPI | AFS, LogAnalysis, OpenEye |
| `ecosystem-client` | `packages/ecosystem-client` | PyPI | AFS, LogAnalysis, OpenEye |
| `ecosystem-auth` (Python) | `auth/python` | PyPI | all Python apps |
| `@smartindustries/ecosystem-client` (JS) | `ecosystem_client_js` | npm | MagicMirror |
| `@smartindustries/ecosystem-auth` (JS) | `auth/js` | npm | MagicMirror |
| `@smartindustries/ecosystem-theme` (JS) | `theme` | npm (optional) | UIs |

> Recommendation: publish under an **org namespace** — `smartindustries-ecosystem-ai`
> on PyPI and a `@smartindustries/*` scope on npm — to avoid name squatting and
> make ownership obvious.

---

## 2. Prerequisites (one-time)

- **PyPI**: an account + an **API token** (or, preferred, **Trusted Publishing**
  via GitHub OIDC — no long-lived secret). Test against **TestPyPI** first.
- **npm**: an account in the `@smartindustries` org + an **automation token**
  (or npm Trusted Publishing / OIDC).
- Tooling: `python -m pip install --upgrade build twine`; Node ≥18 for `npm publish`.
- Each package needs: a unique `name`, a `version`, a `LICENSE`, a `README`,
  and accurate `dependencies` in its `pyproject.toml` / `package.json`.

---

## 3. Versioning

- **SemVer** (`MAJOR.MINOR.PATCH`). Breaking API change → MAJOR.
- **Single source of truth** per package (the `version` in `pyproject.toml` /
  `package.json`). Tag releases `ecosystem-ai-vX.Y.Z` (per-package tags) so each
  package versions independently.
- Member apps **pin** a compatible range (e.g. `ecosystem-ai>=0.3,<0.4`).

---

## 4. Manual publish (Python)

```bash
cd packages/ecosystem-ai
python -m build                      # builds sdist + wheel into dist/
python -m twine check dist/*         # validate metadata/README
# Dry-run on TestPyPI first:
python -m twine upload --repository testpypi dist/*
pip install -i https://test.pypi.org/simple/ ecosystem-ai   # verify install
# Then production:
python -m twine upload dist/*
```

## 4b. Manual publish (npm)

```bash
cd ecosystem_client_js
npm version patch                    # bump + git tag
npm publish --access public          # scoped pkgs need --access public the first time
```

---

## 5. Automated publish (recommended)

A tag-triggered GitHub Actions workflow per package, using **Trusted Publishing
(OIDC)** so no tokens are stored:

```yaml
# .github/workflows/publish-ecosystem-ai.yml
name: Publish ecosystem-ai
on:
  push:
    tags: ["ecosystem-ai-v*"]
permissions:
  id-token: write            # required for OIDC trusted publishing
jobs:
  build-and-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install build && python -m build packages/ecosystem-ai
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          packages-dir: packages/ecosystem-ai/dist
```

(Configure the PyPI project to trust this repo/workflow under
*Publishing → Trusted Publishers*.)

---

## 6. Interim: path install (current approach)

Until we publish, member apps install the packages **editable, by path**, from
the sibling `appEcosystem` checkout. Installers must therefore be able to find
those files (the apps live under a common `ECOSYSTEM_BASE_PATH`).

```bash
# In each app's installer / venv setup:
ECO="${ECOSYSTEM_BASE_PATH:-..}/appEcosystem"
pip install -e "$ECO/packages/ecosystem-ai"
pip install -e "$ECO/packages/ecosystem-client"
```

Notes:
- Apps already **guard** these imports, so they run standalone even if the
  packages aren't installed — installing them simply **activates** ecosystem
  sync + the shared AI layer.
- For air-gapped/offline installers, **vendor a copy** (or a built wheel) of the
  packages alongside the app and `pip install ./vendor/ecosystem_ai-*.whl`.
- This is the step that "requires the files to be included in any installer."

---

## 7. Cutover checklist (when we publish)

1. Finalize names/namespace and reserve them on PyPI/npm.
2. Add `LICENSE` + `README` to each package; verify `twine check`.
3. Publish to TestPyPI / npm dry-run; install-test in a clean venv.
4. Publish production; tag per-package releases.
5. Switch member apps from `pip install -e <path>` to pinned versions.
6. **Retire the vendored copies** (`ecosystem_client`/`ecosystem_auth` inside
   each app) — the recurring source of drift — and depend on the published
   package only. Add a CI check that fails if a vendored copy reappears.
7. Wire the automated publish workflows (§5).

---

*Guide by Smart Industries LLC.*
