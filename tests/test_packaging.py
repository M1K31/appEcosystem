"""Guards the packaging metadata PyPI requires.

There was no metadata at all before publishing was set up, so these tests
started life all-red. They exist now to stop a future edit silently dropping a
field: the failure would otherwise surface at upload time, when the version
number has already been burned (PyPI versions are immutable — a bad release can
only be yanked, never replaced).
"""
from pathlib import Path

import pytest

try:  # tomllib is stdlib from 3.11; CI still runs 3.10.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - depends on interpreter
    tomllib = pytest.importorskip(
        "tomli", reason="needs tomllib (3.11+) or tomli to parse pyproject.toml"
    )

REPO = Path(__file__).resolve().parents[1]

# Distribution name -> its pyproject. The names are the PyPI projects that
# trusted publishing is configured against; changing one here means changing it
# on PyPI too, or the upload is rejected.
DISTRIBUTIONS = {
    "appecosystem-auth": REPO / "auth/python/pyproject.toml",
    "appecosystem-client": REPO / "packages/ecosystem-client/pyproject.toml",
    "appecosystem-ai": REPO / "packages/ecosystem-ai/pyproject.toml",
    "appecosystem": REPO / "pyproject.toml",
}

REQUIRED_FIELDS = (
    "name",
    "version",
    "description",
    "readme",
    "license",
    "authors",
    "classifiers",
    "urls",
    "requires-python",
)


def _project(path: Path) -> dict:
    return tomllib.loads(path.read_text())["project"]


@pytest.mark.parametrize("dist_name,path", sorted(DISTRIBUTIONS.items()))
def test_metadata_is_complete(dist_name, path):
    missing = [f for f in REQUIRED_FIELDS if f not in _project(path)]
    assert not missing, f"{dist_name} is missing PyPI metadata: {missing}"


@pytest.mark.parametrize("dist_name,path", sorted(DISTRIBUTIONS.items()))
def test_name_matches_the_configured_pypi_project(dist_name, path):
    """The distribution name must equal the PyPI project trusted publishing
    was configured for. `appEcosystem` normalizes to `appecosystem`, which is
    NOT the same project as the old `app-ecosystem`."""
    assert _project(path)["name"] == dist_name


@pytest.mark.parametrize("dist_name,path", sorted(DISTRIBUTIONS.items()))
def test_readme_file_exists(dist_name, path):
    """A `readme` pointing at a missing file fails the build, not the check."""
    readme = _project(path)["readme"]
    name = readme if isinstance(readme, str) else readme.get("file", "")
    assert (path.parent / name).is_file(), f"{dist_name}: {name} not found"


def test_client_declares_its_auth_dependency():
    """ecosystem-client imports ecosystem_auth at runtime for request signing.
    That was carried as a comment while both were path-installed; publishing is
    exactly the condition the comment named for making it real."""
    deps = _project(DISTRIBUTIONS["appecosystem-client"])["dependencies"]
    assert any(d.startswith("appecosystem-auth") for d in deps), (
        f"appecosystem-client must depend on appecosystem-auth; got {deps}"
    )


def test_declared_version_matches_the_runtime_version():
    """ecosystem_client.__version__ drifted from its pyproject once already
    (0.1.0 vs 0.3.1), so anything reporting the runtime version named a release
    that never shipped."""
    declared = _project(DISTRIBUTIONS["appecosystem-client"])["version"]
    init = (REPO / "ecosystem_client/__init__.py").read_text()
    for line in init.splitlines():
        if line.startswith("__version__"):
            runtime = line.split("=", 1)[1].strip().strip('"').strip("'")
            assert runtime == declared, (
                f"pyproject says {declared}, __init__ says {runtime}"
            )
            return
    pytest.fail("no __version__ found in ecosystem_client/__init__.py")
