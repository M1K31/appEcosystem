"""Tests for cross-language HMAC auth compatibility."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "auth" / "python"))

from ecosystem_auth.tokens import (
    DEFAULT_DEV_SECRET,
    NONCE_HEADER,
    NonceStore,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    generate_secure_token,
    get_ecosystem_secret,
    hash_token,
    sign_payload,
    sign_request,
    verify_request,
    verify_signature,
    verify_token_hash,
    create_ecosystem_token,
    verify_ecosystem_token,
)


class TestSecretResolution:
    def test_explicit_override_wins(self):
        assert get_ecosystem_secret("explicit-secret") == "explicit-secret"

    def test_env_secret_used(self, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "from-env")
        assert get_ecosystem_secret() == "from-env"

    def test_unset_raises(self, monkeypatch, tmp_path):
        # Fail-closed: no default anywhere (including dev). Isolate the secret
        # file so a real ~/.config/ecosystem/secret.env doesn't satisfy it.
        monkeypatch.delenv("ECOSYSTEM_HMAC_SECRET", raising=False)
        monkeypatch.setenv("ECOSYSTEM_SECRET_FILE", str(tmp_path / "none.env"))
        monkeypatch.setenv("ECOSYSTEM_ENV", "dev")
        with pytest.raises(RuntimeError, match="No ecosystem secret"):
            get_ecosystem_secret()

    def test_known_default_rejected(self, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", DEFAULT_DEV_SECRET)
        with pytest.raises(RuntimeError, match="development default"):
            get_ecosystem_secret()

    def test_real_secret_allowed(self, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "a-real-secret")
        assert get_ecosystem_secret() == "a-real-secret"


class TestSecretFile:
    """File-backed secret: override -> env -> ~/.config/ecosystem/secret.env."""

    @pytest.fixture(autouse=True)
    def isolate(self, monkeypatch, tmp_path):
        from ecosystem_auth import tokens
        self.tokens = tokens
        monkeypatch.setenv("ECOSYSTEM_SECRET_FILE", str(tmp_path / "secret.env"))
        monkeypatch.delenv("ECOSYSTEM_HMAC_SECRET", raising=False)
        yield

    def test_unset_everywhere_raises(self):
        with pytest.raises(RuntimeError, match="No ecosystem secret"):
            self.tokens.get_ecosystem_secret()

    def test_file_fallback(self):
        self.tokens.write_secret("filesecret123")
        assert self.tokens.get_ecosystem_secret() == "filesecret123"

    def test_env_beats_file(self, monkeypatch):
        self.tokens.write_secret("filesecret")
        monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "envsecret")
        assert self.tokens.get_ecosystem_secret() == "envsecret"

    def test_override_beats_all(self, monkeypatch):
        self.tokens.write_secret("filesecret")
        monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "envsecret")
        assert self.tokens.get_ecosystem_secret("explicit") == "explicit"

    def test_write_secret_chmod_600(self):
        import stat
        p = self.tokens.write_secret("abc123")
        assert (p.stat().st_mode & 0o777) == 0o600

    def test_write_rejects_dev_default(self):
        with pytest.raises(RuntimeError, match="development default"):
            self.tokens.write_secret(self.tokens.DEFAULT_DEV_SECRET)

    def test_ensure_generates_and_persists(self):
        s1 = self.tokens.ensure_ecosystem_secret()
        assert s1 and len(s1) >= 32
        # second call reuses the persisted value (idempotent)
        assert self.tokens.ensure_ecosystem_secret() == s1
        assert self.tokens.get_ecosystem_secret() == s1

    def test_export_prefixed_line_parsed(self):
        p = self.tokens.secret_file_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("export ECOSYSTEM_HMAC_SECRET=prefixed\n")
        assert self.tokens.get_ecosystem_secret() == "prefixed"


class TestNonceStore:
    def test_first_use_accepted(self):
        store = NonceStore()
        assert store.add_if_new("abc") is True

    def test_replay_rejected(self):
        store = NonceStore()
        store.add_if_new("abc")
        assert store.add_if_new("abc") is False

    def test_expired_nonce_reusable(self):
        # Negative TTL forces every prior entry to be purged on the next call.
        store = NonceStore(ttl_seconds=-1)
        store.add_if_new("abc")
        assert store.add_if_new("abc") is True


class TestRequestSigning:
    SECRET = "request-test-secret"

    def test_sign_request_headers_present(self):
        headers = sign_request("POST", "http://h/register", self.SECRET, {"a": 1})
        assert SIGNATURE_HEADER in headers
        assert TIMESTAMP_HEADER in headers
        assert NONCE_HEADER in headers

    def test_roundtrip_valid(self):
        body = {"name": "svc", "port": 8000}
        headers = sign_request("POST", "http://h/register", self.SECRET, body)
        assert verify_request(
            "POST", "http://h/register", self.SECRET,
            headers[SIGNATURE_HEADER], headers[TIMESTAMP_HEADER], headers[NONCE_HEADER],
            body,
        )

    def test_path_is_host_independent(self):
        body = {"x": 1}
        headers = sign_request("POST", "http://host-a:8500/register", self.SECRET, body)
        # Same path on a different host/interface must still verify.
        assert verify_request(
            "POST", "http://host-b:9000/register", self.SECRET,
            headers[SIGNATURE_HEADER], headers[TIMESTAMP_HEADER], headers[NONCE_HEADER],
            body,
        )

    def test_tampered_body_fails(self):
        headers = sign_request("POST", "http://h/register", self.SECRET, {"a": 1})
        assert not verify_request(
            "POST", "http://h/register", self.SECRET,
            headers[SIGNATURE_HEADER], headers[TIMESTAMP_HEADER], headers[NONCE_HEADER],
            {"a": 2},
        )

    def test_stale_timestamp_fails(self):
        headers = sign_request("POST", "http://h/register", self.SECRET, {"a": 1}, ts=1)
        assert not verify_request(
            "POST", "http://h/register", self.SECRET,
            headers[SIGNATURE_HEADER], headers[TIMESTAMP_HEADER], headers[NONCE_HEADER],
            {"a": 1},
        )

    def test_replay_fails_with_nonce_store(self):
        store = NonceStore()
        body = {"a": 1}
        headers = sign_request("POST", "http://h/register", self.SECRET, body)
        args = (
            "POST", "http://h/register", self.SECRET,
            headers[SIGNATURE_HEADER], headers[TIMESTAMP_HEADER], headers[NONCE_HEADER],
            body,
        )
        assert verify_request(*args, nonce_store=store)
        assert not verify_request(*args, nonce_store=store)


class TestTokenGeneration:
    def test_generate_secure_token_length(self):
        token = generate_secure_token(32)
        assert len(token) == 64  # hex encoding doubles length

    def test_generate_secure_token_uniqueness(self):
        t1 = generate_secure_token()
        t2 = generate_secure_token()
        assert t1 != t2


class TestTokenHashing:
    def test_hash_token_deterministic(self):
        token = "test-token-123"
        h1 = hash_token(token)
        h2 = hash_token(token)
        assert h1 == h2

    def test_verify_token_hash_valid(self):
        token = "my-secret-token"
        h = hash_token(token)
        assert verify_token_hash(token, h)

    def test_verify_token_hash_invalid(self):
        assert not verify_token_hash("token", "wrong-hash")


class TestPayloadSigning:
    def test_sign_payload_deterministic(self):
        payload = {"action": "test", "value": 42}
        secret = "test-secret"
        sig1 = sign_payload(payload, secret)
        sig2 = sign_payload(payload, secret)
        assert sig1 == sig2

    def test_sign_payload_key_order_independent(self):
        """Sorted keys means order shouldn't matter."""
        secret = "test-secret"
        sig1 = sign_payload({"b": 2, "a": 1}, secret)
        sig2 = sign_payload({"a": 1, "b": 2}, secret)
        assert sig1 == sig2

    def test_verify_signature_valid(self):
        payload = {"event": "security.alert", "source": "openeye"}
        secret = "hmac-secret"
        sig = sign_payload(payload, secret)
        assert verify_signature(payload, sig, secret)

    def test_verify_signature_tampered(self):
        payload = {"event": "security.alert"}
        secret = "hmac-secret"
        sig = sign_payload(payload, secret)
        payload["event"] = "security.tampered"
        assert not verify_signature(payload, sig, secret)

    def test_verify_signature_wrong_secret(self):
        payload = {"data": "test"}
        sig = sign_payload(payload, "secret1")
        assert not verify_signature(payload, sig, "secret2")


class TestEcosystemTokens:
    def test_create_and_verify(self):
        secret = "test-ecosystem-secret"
        token_data = create_ecosystem_token(secret, "openeye")
        assert verify_ecosystem_token(token_data, secret)

    def test_expired_token(self):
        secret = "test-secret"
        token_data = create_ecosystem_token(secret, "openeye", ttl_seconds=-1)
        assert not verify_ecosystem_token(token_data, secret)

    def test_wrong_secret(self):
        token_data = create_ecosystem_token("secret1", "openeye")
        assert not verify_ecosystem_token(token_data, "secret2")

    def test_tampered_token_payload(self):
        secret = "test-secret"
        token_data = create_ecosystem_token(secret, "openeye")
        # Change the token value itself - must invalidate signature now
        token_data["token"] = "tampered-token-value"
        assert not verify_ecosystem_token(token_data, secret)

    def test_overlong_lifetime_rejected(self):
        """A correctly signed but implausibly long-lived token is rejected."""
        secret = "test-secret"
        token_data = create_ecosystem_token(secret, "openeye", ttl_seconds=10 * 365 * 86400)
        assert not verify_ecosystem_token(token_data, secret)

    def test_future_issued_at_rejected(self):
        secret = "test-secret"
        token_data = create_ecosystem_token(secret, "openeye")
        future = token_data["issued_at"] + 10_000
        token_data["issued_at"] = future
        token_data["expires_at"] = future + 3600
        # Re-sign so the signature itself is valid; the time check must still fail.
        token_data["signature"] = sign_payload(
            {k: token_data[k] for k in ("token", "service", "issued_at", "expires_at")},
            secret,
        )
        assert not verify_ecosystem_token(token_data, secret)


class TestCrossLanguageCompatibility:
    """Verify Python and JS produce identical HMAC signatures."""

    JS_TOKEN_PATH = Path(__file__).parent.parent / "auth" / "js" / "src" / "tokens.js"

    @pytest.fixture
    def node_available(self):
        try:
            subprocess.run(["node", "--version"], capture_output=True, check=True)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            pytest.skip("Node.js not available")

    def test_sign_payload_matches_js(self, node_available):
        payload = {"action": "test", "number": 42, "nested": {"key": "value"}}
        secret = "cross-language-test-secret"

        py_sig = sign_payload(payload, secret)

        js_code = f"""
        const {{ signPayload }} = require('{self.JS_TOKEN_PATH}');
        const payload = {json.dumps(payload)};
        console.log(signPayload(payload, '{secret}'));
        """
        result = subprocess.run(
            ["node", "-e", js_code], capture_output=True, text=True
        )
        js_sig = result.stdout.strip()

        assert py_sig == js_sig, f"Python: {py_sig}, JS: {js_sig}"

    def test_hash_token_matches_js(self, node_available):
        token = "test-token-for-hashing"

        py_hash = hash_token(token)

        js_code = f"""
        const {{ hashToken }} = require('{self.JS_TOKEN_PATH}');
        console.log(hashToken('{token}'));
        """
        result = subprocess.run(
            ["node", "-e", js_code], capture_output=True, text=True
        )
        js_hash = result.stdout.strip()

        assert py_hash == js_hash

    def test_sign_request_matches_js(self, node_available):
        """Python sign_request and JS signRequest must agree for the same ts/nonce."""
        method = "POST"
        url = "http://registry:8500/register?b=2&a=1"
        secret = "cross-language-request-secret"
        body = {"name": "svc", "port": 8000, "nested": {"k": "v"}}
        ts = 1781000000
        nonce = "fixednonce123456"

        py_headers = sign_request(method, url, secret, body, ts=ts, nonce=nonce)
        py_sig = py_headers[SIGNATURE_HEADER]

        js_code = f"""
        const {{ signRequest, SIGNATURE_HEADER }} = require('{self.JS_TOKEN_PATH}');
        const body = {json.dumps(body)};
        const h = signRequest('{method}', '{url}', '{secret}', body, {ts}, '{nonce}');
        console.log(h[SIGNATURE_HEADER]);
        """
        result = subprocess.run(["node", "-e", js_code], capture_output=True, text=True)
        js_sig = result.stdout.strip()

        assert py_sig == js_sig, f"Python: {py_sig}, JS: {js_sig}\nstderr: {result.stderr}"
