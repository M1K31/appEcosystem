import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "auth" / "python"))

# Secrets are fail-closed (no default). Provide one for the whole test session so
# components that resolve the secret at construction don't raise. Tests that
# exercise the resolver itself override/delete this via monkeypatch.
os.environ.setdefault("ECOSYSTEM_HMAC_SECRET", "test-ecosystem-secret")
