"""
Tests for reconhound/code_leak.py (ReconHound Module 3, per context.md's
catalog item 3; built under a temporary, user-approved build-order
deviation ahead of surface_mapper.py — see the module docstring for
details).

Run with:  ./.venv/bin/python -m pytest tests/test_code_leak.py -v

All tests mock the `requests.get` boundary so the suite is deterministic
and offline-safe; no external network access (including to GitHub) is
required or performed anywhere in this file. Several tests additionally
assert on the *captured* request URLs/hosts to verify the passive
boundary: this module must never send a request to the target itself,
never fetch a matched file's raw contents, and must always filter out
private-repository hits before evidencing them.
"""

import json
import os
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import code_leak as cl


SAFE_TARGET = "example.com"


def _fake_response(status_code=200, json_data=None, headers=None, raise_json_error=False):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    if raise_json_error:
        resp.json.side_effect = ValueError("bad json")
    else:
        resp.json.return_value = json_data
    return resp


def _code_item(
    path="config/settings.py",
    repo_full_name="acme/webapp",
    private=False,
    fragments=None,
    html_url="https://github.com/acme/webapp/blob/main/config/settings.py",
    repo_html_url="https://github.com/acme/webapp",
):
    text_matches = None
    if fragments is not None:
        text_matches = [{"fragment": f, "matches": []} for f in fragments]
    return {
        "name": path.rsplit("/", 1)[-1],
        "path": path,
        "html_url": html_url,
        "repository": {
            "full_name": repo_full_name,
            "html_url": repo_html_url,
            "private": private,
            "owner": {"login": repo_full_name.split("/")[0]},
            "fork": False,
        },
        "text_matches": text_matches,
    }


def _repo_item(full_name="acme/webapp", private=False, description="Acme web app"):
    return {
        "full_name": full_name,
        "html_url": f"https://github.com/{full_name}",
        "description": description,
        "owner": {"login": full_name.split("/")[0]},
        "private": private,
        "fork": False,
        "language": "Python",
        "stargazers_count": 3,
    }


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def test_accepts_plain_domain(self):
        assert cl.validate_target("example.com") == "example.com"

    def test_normalizes_case_and_trailing_dot(self):
        assert cl.validate_target("EXAMPLE.com.") == "example.com"

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(cl.ScopeError):
            cl.validate_target(bad)

    def test_rejects_url(self):
        with pytest.raises(cl.ScopeError):
            cl.validate_target("https://example.com/path")

    def test_rejects_ip_literal(self):
        with pytest.raises(cl.ScopeError):
            cl.validate_target("93.184.216.34")

    def test_rejects_wildcard(self):
        with pytest.raises(cl.ScopeError):
            cl.validate_target("*.example.com")

    def test_rejects_malformed_domain(self):
        with pytest.raises(cl.ScopeError):
            cl.validate_target("-bad-.com")


# ---------------------------------------------------------------------------
# make_finding / PendingAssetsStore
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_shape(self):
        finding = cl.make_finding("code_leak_exposure", SAFE_TARGET, {"a": 1}, ["evidence"], cl.CONFIDENCE_LOW)
        assert finding["type"] == "code_leak_exposure"
        assert finding["target"] == SAFE_TARGET
        assert finding["value"] == {"a": 1}
        assert finding["evidence"] == ["evidence"]
        assert finding["confidence"] == cl.CONFIDENCE_LOW
        assert finding["source"] == cl.MODULE_NAME
        assert "timestamp" in finding
        assert finding["metadata"] == {}

    def test_json_safe(self):
        finding = cl.make_finding("code_leak_exposure", SAFE_TARGET, {"a": [1, 2]}, ["e"], cl.CONFIDENCE_HIGH)
        json.dumps(finding)  # must not raise


class TestPendingAssetsStore:
    def test_creates_output_dir_and_file(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = cl.make_finding("code_leak_exposure", SAFE_TARGET, {}, ["e"], cl.CONFIDENCE_LOW)
        store.add(finding)
        assert os.path.exists(store.path)
        with open(store.path) as f:
            data = json.load(f)
        assert data == [finding]

    def test_appends_without_losing_previous_entries(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        f1 = cl.make_finding("code_leak_repository", SAFE_TARGET, {"n": 1}, ["e"], cl.CONFIDENCE_LOW)
        f2 = cl.make_finding("code_leak_exposure", SAFE_TARGET, {"n": 2}, ["e"], cl.CONFIDENCE_MEDIUM)
        store.add(f1)
        store.add(f2)
        assert store.all() == [f1, f2]

    def test_preserves_other_modules_existing_entries(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        existing = [{"type": "dns_record", "target": SAFE_TARGET, "value": {}, "source": "passive_recon.py"}]
        (output_dir / "pending_assets.json").write_text(json.dumps(existing))
        store = cl.PendingAssetsStore(output_dir=str(output_dir))
        new_finding = cl.make_finding("code_leak_repository", SAFE_TARGET, {}, ["e"], cl.CONFIDENCE_LOW)
        store.add(new_finding)
        records = store.all()
        assert existing[0] in records
        assert new_finding in records

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not valid json")
        store = cl.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(cl.PersistenceError):
            store.all()

    def test_safe_store_add_captures_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not valid json")
        store = cl.PendingAssetsStore(output_dir=str(output_dir))
        finding = cl.make_finding("code_leak_repository", SAFE_TARGET, {}, ["e"], cl.CONFIDENCE_LOW)
        err = cl._safe_store_add(store, finding)
        assert err is not None
        assert "corrupt" in err

    def test_safe_store_add_none_store_is_noop(self):
        finding = cl.make_finding("code_leak_repository", SAFE_TARGET, {}, ["e"], cl.CONFIDENCE_LOW)
        assert cl._safe_store_add(None, finding) is None


# ---------------------------------------------------------------------------
# Redaction / fingerprinting (secrets are never stored verbatim)
# ---------------------------------------------------------------------------

class TestRedactSecret:
    def test_short_value_partially_masked(self):
        redacted = cl._redact_secret("abcd")
        assert redacted != "abcd"
        assert redacted.startswith("a")

    def test_long_value_keeps_prefix_and_suffix_only(self):
        value = "AKIA1234567890ABCDEF"
        redacted = cl._redact_secret(value)
        assert redacted.startswith(value[:4])
        assert redacted.endswith(value[-4:])
        assert value[4:-4] not in redacted
        assert "*" in redacted

    def test_never_returns_the_raw_value(self):
        value = "supersecretpassword123"
        assert cl._redact_secret(value) != value

    def test_empty_string(self):
        assert cl._redact_secret("") == ""


class TestFingerprint:
    def test_deterministic(self):
        assert cl._fingerprint("hello") == cl._fingerprint("hello")

    def test_distinguishes_different_values(self):
        assert cl._fingerprint("hello") != cl._fingerprint("world")

    def test_is_sha256_hex(self):
        fp = cl._fingerprint("hello")
        assert len(fp) == 64
        int(fp, 16)  # must be valid hex


class TestTruncate:
    def test_short_text_unchanged(self):
        assert cl._truncate("short", 300) == "short"

    def test_long_text_truncated(self):
        text = "a" * 500
        out = cl._truncate(text, 300)
        assert len(out) <= 301
        assert out.endswith("…")

    def test_none_returns_empty(self):
        assert cl._truncate(None) == ""


# ---------------------------------------------------------------------------
# Config-file path matching (category: config_file)
# ---------------------------------------------------------------------------

class TestMatchConfigFilePattern:
    @pytest.mark.parametrize("path", [
        ".env",
        ".env.production",
        "backend/.env",
        "app/config/config.json",
        "project/settings.py",
        "src/main/resources/application.yml",
        "docker-compose.prod.yaml",
        ".aws/credentials",
        "server/credentials",
        "k8s/secrets.yaml",
        "ssh/id_rsa",
        "certs/server.pem",
        "certs/server.key",
        "wp-config.php",
        ".npmrc",
        ".pypirc",
        "infra/terraform.tfvars",
        "auth/.htpasswd",
    ])
    def test_matches_known_sensitive_paths(self, path):
        assert cl._match_config_file_pattern(path) is not None

    @pytest.mark.parametrize("path", [
        "README.md",
        "src/main.py",
        "package.json",
        "index.html",
        "",
    ])
    def test_does_not_match_ordinary_paths(self, path):
        # package.json isn't in the sensitive set (only config.json/.env/etc are)
        assert cl._match_config_file_pattern(path) is None

    def test_none_path(self):
        assert cl._match_config_file_pattern(None) is None


# ---------------------------------------------------------------------------
# Secret-pattern catalog (category coverage: api_key, token, credential,
# db_connection_string, internal_url, infrastructure_reference)
# ---------------------------------------------------------------------------

class TestSecretPatterns:
    def _find(self, name):
        return next(p for p in cl.SECRET_PATTERNS if p["name"] == name)

    def test_aws_access_key_id(self):
        pat = self._find("aws_access_key_id")
        m = pat["regex"].search("aws_key = AKIA1234567890ABCDEF")
        assert m is not None
        assert pat["category"] == cl.CATEGORY_API_KEY
        assert pat["confidence"] == cl.CONFIDENCE_HIGH

    def test_github_token(self):
        pat = self._find("github_token")
        m = pat["regex"].search("token: ghp_" + "a" * 36)
        assert m is not None
        assert pat["category"] == cl.CATEGORY_TOKEN

    def test_slack_token(self):
        pat = self._find("slack_token")
        m = pat["regex"].search("SLACK_TOKEN=xoxb-" + "TESTTOKEN-" + "a" * 20)
        assert m is not None

    def test_google_api_key(self):
        pat = self._find("google_api_key")
        m = pat["regex"].search("key=AIza" + "S" * 35)
        assert m is not None

    def test_stripe_live_key(self):
        pat = self._find("stripe_live_key")
        m = pat["regex"].search("sk_live_" + "a" * 24)
        assert m is not None

    def test_private_key_block(self):
        pat = self._find("private_key_block")
        m = pat["regex"].search("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...")
        assert m is not None
        assert pat["category"] == cl.CATEGORY_CREDENTIAL

    def test_db_connection_string_postgres(self):
        pat = self._find("db_connection_string")
        m = pat["regex"].search("DATABASE_URL=postgres://user:pass@db.example.com:5432/prod")
        assert m is not None
        assert pat["category"] == cl.CATEGORY_DB_CONNECTION

    def test_db_connection_string_mongodb(self):
        pat = self._find("db_connection_string")
        m = pat["regex"].search("mongodb+srv://admin:hunter2@cluster0.mongodb.net/app")
        assert m is not None

    def test_generic_api_key_assignment(self):
        pat = self._find("generic_api_key_assignment")
        m = pat["regex"].search('api_key = "sk_test_abcdefghijklmnop"')
        assert m is not None
        assert pat["confidence"] == cl.CONFIDENCE_MEDIUM  # generic keyword match, not high-confidence

    def test_generic_secret_assignment(self):
        pat = self._find("generic_secret_assignment")
        m = pat["regex"].search('password: "Sup3rSecretPass!"')
        assert m is not None

    def test_generic_secret_assignment_ambiguous_variable_name(self):
        # A variable literally named "token" holding a public, rotating
        # CSRF nonce (not a real secret) is the false-positive/ambiguous
        # match case the assignment asks to verify: it will match
        # structurally but must stay capped at MEDIUM confidence and never
        # be reported as a confirmed secret.
        pat = self._find("generic_secret_assignment")
        m = pat["regex"].search('token = "csrf-nonce-regenerated-per-request-000111"')
        assert m is not None
        assert pat["confidence"] == cl.CONFIDENCE_MEDIUM

    def test_generic_secret_assignment_does_not_match_compound_identifier(self):
        # "password_reset_token" is a compound identifier, not the literal
        # keyword "password"/"token" immediately followed by an assignment
        # operator — the pattern must not match inside it (avoids an even
        # noisier false-positive rate from substring matches).
        pat = self._find("generic_secret_assignment")
        assert pat["regex"].search('password_reset_token = "abc123"') is None

    def test_internal_hostname_reference(self):
        pat = self._find("internal_hostname_reference")
        m = pat["regex"].search("fetch('https://internal-api.example.com/v1/status')")
        assert m is not None
        assert pat["category"] == cl.CATEGORY_INTERNAL_URL

    def test_private_ip_reference(self):
        pat = self._find("private_ip_reference")
        assert pat["regex"].search("db_host = 10.0.5.12") is not None
        assert pat["regex"].search("proxy = 192.168.1.1") is not None
        assert pat["regex"].search("gw = 172.16.0.1") is not None

    def test_private_ip_reference_does_not_match_public_ip(self):
        pat = self._find("private_ip_reference")
        assert pat["regex"].search("dns = 8.8.8.8") is None

    def test_all_patterns_have_valid_category_and_confidence(self):
        for pat in cl.SECRET_PATTERNS:
            assert pat["category"] in cl.CATEGORIES
            assert pat["confidence"] in (cl.CONFIDENCE_LOW, cl.CONFIDENCE_MEDIUM, cl.CONFIDENCE_HIGH)


# ---------------------------------------------------------------------------
# Private-repository safeguard
# ---------------------------------------------------------------------------

class TestIsPrivateRepo:
    def test_private_true(self):
        assert cl._is_private_repo({"private": True}) is True

    def test_private_false(self):
        assert cl._is_private_repo({"private": False}) is False

    def test_missing_private_key_defaults_public(self):
        assert cl._is_private_repo({}) is False

    def test_non_dict_fails_closed(self):
        assert cl._is_private_repo(None) is True
        assert cl._is_private_repo("not a dict") is True


# ---------------------------------------------------------------------------
# search_github_code
# ---------------------------------------------------------------------------

class TestSearchGithubCode:
    def test_missing_query(self):
        r = cl.search_github_code("", token="tok")
        assert r["status"] == "error"
        assert "query" in r["error"]

    def test_missing_token_is_reported_not_raised(self):
        r = cl.search_github_code('"example.com"', token=None)
        assert r["status"] == "missing_credentials"
        assert cl.GITHUB_TOKEN_ENV in r["error"]

    @mock.patch("reconhound.code_leak.requests.get")
    def test_success_with_items(self, mock_get):
        mock_get.return_value = _fake_response(200, {
            "total_count": 1, "incomplete_results": False,
            "items": [_code_item()],
        })
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "found"
        assert len(r["items"]) == 1
        assert r["total_count"] == 1

    @mock.patch("reconhound.code_leak.requests.get")
    def test_request_targets_github_api_only(self, mock_get):
        mock_get.return_value = _fake_response(200, {"total_count": 0, "items": []})
        cl.search_github_code('"example.com"', token="tok")
        called_url = mock_get.call_args[0][0]
        assert called_url == cl.GITHUB_CODE_SEARCH_API
        assert "github.com" in called_url
        assert SAFE_TARGET not in called_url.replace("api.github.com", "")  # never contacts the target host

    @mock.patch("reconhound.code_leak.requests.get")
    def test_sends_bearer_auth_and_text_match_header(self, mock_get):
        mock_get.return_value = _fake_response(200, {"total_count": 0, "items": []})
        cl.search_github_code('"example.com"', token="tok123")
        headers = mock_get.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer tok123"
        assert "text-match" in headers["Accept"]

    @mock.patch("reconhound.code_leak.requests.get")
    def test_empty_results_not_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"total_count": 0, "items": []})
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "not_found"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_unauthorized(self, mock_get):
        mock_get.return_value = _fake_response(401)
        r = cl.search_github_code('"example.com"', token="badtok")
        assert r["status"] == "unauthorized"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_primary_rate_limit(self, mock_get):
        mock_get.return_value = _fake_response(403, headers={"X-RateLimit-Remaining": "0"})
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "rate_limited"
        assert "primary" in r["error"]

    @mock.patch("reconhound.code_leak.requests.get")
    def test_secondary_rate_limit_via_retry_after(self, mock_get):
        mock_get.return_value = _fake_response(403, headers={"Retry-After": "30"})
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "rate_limited"
        assert "30" in r["error"]

    @mock.patch("reconhound.code_leak.requests.get")
    def test_generic_403_forbidden(self, mock_get):
        mock_get.return_value = _fake_response(403, headers={})
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "unauthorized"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_invalid_query_422(self, mock_get):
        mock_get.return_value = _fake_response(422, {"errors": [{"message": "bad qualifier"}]})
        r = cl.search_github_code('"example.com" filename:', token="tok")
        assert r["status"] == "invalid_query"
        assert "bad qualifier" in r["error"]

    @mock.patch("reconhound.code_leak.requests.get")
    def test_invalid_query_422_malformed_body(self, mock_get):
        mock_get.return_value = _fake_response(422, raise_json_error=True)
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "invalid_query"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_429_rate_limited(self, mock_get):
        mock_get.return_value = _fake_response(429)
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "rate_limited"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_server_error(self, mock_get):
        mock_get.return_value = _fake_response(503)
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "error"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_malformed_json(self, mock_get):
        mock_get.return_value = _fake_response(200, raise_json_error=True)
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "error"
        assert "malformed" in r["error"]

    @mock.patch("reconhound.code_leak.requests.get")
    def test_unexpected_structure_missing_items(self, mock_get):
        mock_get.return_value = _fake_response(200, {"total_count": 0})
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "error"
        assert "unexpected" in r["error"]

    @mock.patch("reconhound.code_leak.requests.get")
    def test_unexpected_structure_non_dict(self, mock_get):
        mock_get.return_value = _fake_response(200, ["not", "a", "dict"])
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "error"

    @mock.patch("reconhound.code_leak.requests.get", side_effect=requests.exceptions.Timeout())
    def test_timeout(self, mock_get):
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "error"
        assert r["error"] == "timeout"

    @mock.patch("reconhound.code_leak.requests.get", side_effect=requests.exceptions.ConnectionError("dns fail"))
    def test_connection_error(self, mock_get):
        r = cl.search_github_code('"example.com"', token="tok")
        assert r["status"] == "error"
        assert "connection error" in r["error"]


# ---------------------------------------------------------------------------
# search_github_repositories
# ---------------------------------------------------------------------------

class TestSearchGithubRepositories:
    def test_missing_query(self):
        r = cl.search_github_repositories("")
        assert r["status"] == "error"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_works_without_token(self, mock_get):
        mock_get.return_value = _fake_response(200, {"total_count": 1, "items": [_repo_item()]})
        r = cl.search_github_repositories('"example.com" in:name,description,readme')
        assert r["status"] == "found"
        headers = mock_get.call_args.kwargs["headers"]
        assert "Authorization" not in headers

    @mock.patch("reconhound.code_leak.requests.get")
    def test_adds_auth_header_when_token_given(self, mock_get):
        mock_get.return_value = _fake_response(200, {"total_count": 0, "items": []})
        cl.search_github_repositories('"example.com"', token="tok")
        headers = mock_get.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer tok"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_empty_results_not_found(self, mock_get):
        mock_get.return_value = _fake_response(200, {"total_count": 0, "items": []})
        r = cl.search_github_repositories('"example.com"')
        assert r["status"] == "not_found"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_rate_limited(self, mock_get):
        mock_get.return_value = _fake_response(403, headers={"X-RateLimit-Remaining": "0"})
        r = cl.search_github_repositories('"example.com"')
        assert r["status"] == "rate_limited"

    @mock.patch("reconhound.code_leak.requests.get")
    def test_malformed_json(self, mock_get):
        mock_get.return_value = _fake_response(200, raise_json_error=True)
        r = cl.search_github_repositories('"example.com"')
        assert r["status"] == "error"

    @mock.patch("reconhound.code_leak.requests.get", side_effect=requests.exceptions.RequestException("boom"))
    def test_request_exception(self, mock_get):
        r = cl.search_github_repositories('"example.com"')
        assert r["status"] == "error"
        assert "request failed" in r["error"]


# ---------------------------------------------------------------------------
# extract_findings_from_code_item
# ---------------------------------------------------------------------------

class TestExtractFindingsFromCodeItem:
    def test_private_repo_yields_nothing(self):
        item = _code_item(private=True, fragments=["AKIA1234567890ABCDEF"])
        assert cl.extract_findings_from_code_item(item) == []

    def test_config_file_path_match(self):
        item = _code_item(path="backend/.env", fragments=None)
        findings = cl.extract_findings_from_code_item(item)
        assert any(f["category"] == cl.CATEGORY_CONFIG_FILE for f in findings)

    def test_secret_pattern_match_in_fragment(self):
        item = _code_item(path="infra/deploy.py", fragments=["AWS_KEY = 'AKIA1234567890ABCDEF'"])
        findings = cl.extract_findings_from_code_item(item)
        assert any(f["pattern_name"] == "aws_access_key_id" for f in findings)
        secret_finding = next(f for f in findings if f["pattern_name"] == "aws_access_key_id")
        assert secret_finding["redacted_value"] != "AKIA1234567890ABCDEF"
        assert secret_finding["fingerprint_sha256"] == cl._fingerprint("AKIA1234567890ABCDEF")

    def test_no_fragments_no_secrets(self):
        item = _code_item(path="src/main.py", fragments=None)
        findings = cl.extract_findings_from_code_item(item)
        assert findings == []

    def test_generic_pattern_carries_verification_note(self):
        item = _code_item(path="src/config.py", fragments=['password = "hunter2xyz!"'])
        findings = cl.extract_findings_from_code_item(item)
        generic = [f for f in findings if f["pattern_name"] == "generic_secret_assignment"]
        assert generic
        assert generic[0]["note"] is not None
        assert generic[0]["confidence"] == cl.CONFIDENCE_MEDIUM

    def test_malformed_item_does_not_raise(self):
        assert cl.extract_findings_from_code_item({}) == []
        assert cl.extract_findings_from_code_item(None) == []

    def test_carries_source_and_repo_metadata(self):
        item = _code_item(
            path="infra/deploy.py",
            repo_full_name="acme/infra",
            fragments=["AWS_KEY = 'AKIA1234567890ABCDEF'"],
        )
        f = cl.extract_findings_from_code_item(item)[0]
        assert f["repo_full_name"] == "acme/infra"
        assert f["path"] == "infra/deploy.py"
        assert f["source_url"] == item["html_url"]


# ---------------------------------------------------------------------------
# normalize_repo_item / aggregation
# ---------------------------------------------------------------------------

class TestNormalizeRepoItem:
    def test_normalizes_public_repo(self):
        rec = cl.normalize_repo_item(_repo_item(), "repo_search")
        assert rec["full_name"] == "acme/webapp"
        assert rec["discovered_via"] == {"repo_search"}

    def test_private_repo_returns_none(self):
        assert cl.normalize_repo_item(_repo_item(private=True), "repo_search") is None

    def test_missing_full_name_returns_none(self):
        assert cl.normalize_repo_item({"private": False}, "repo_search") is None

    def test_non_dict_returns_none(self):
        assert cl.normalize_repo_item(None, "repo_search") is None


class TestAggregateRepo:
    def test_merges_discovered_via_across_sources(self):
        agg = {}
        cl._aggregate_repo(agg, cl.normalize_repo_item(_repo_item(), "repo_search"))
        cl._aggregate_repo(agg, cl.normalize_repo_item(_repo_item(), "code_search"))
        assert agg["acme/webapp"]["discovered_via"] == {"repo_search", "code_search"}

    def test_none_record_is_noop(self):
        agg = {}
        cl._aggregate_repo(agg, None)
        assert agg == {}


class TestAggregateCodeFinding:
    def test_same_sighting_from_two_queries_merges(self):
        agg = {}
        finding = {
            "category": cl.CATEGORY_API_KEY, "pattern_name": "aws_access_key_id",
            "confidence": cl.CONFIDENCE_HIGH, "redacted_value": "AKIA****CDEF",
            "fingerprint_sha256": "abc123", "context": "...", "path": "infra/deploy.py",
            "repo_full_name": "acme/infra", "repo_html_url": "https://github.com/acme/infra",
            "source_url": "https://github.com/acme/infra/blob/main/infra/deploy.py", "note": None,
        }
        cl._aggregate_code_finding(agg, finding, "generic_mention")
        cl._aggregate_code_finding(agg, dict(finding), "api_key_keyword")
        assert len(agg) == 1
        key = next(iter(agg))
        assert agg[key]["matched_via_queries"] == {"generic_mention", "api_key_keyword"}

    def test_different_paths_do_not_merge(self):
        agg = {}
        base = {
            "category": cl.CATEGORY_CONFIG_FILE, "pattern_name": ".env file",
            "confidence": cl.CONFIDENCE_MEDIUM, "redacted_value": None,
            "fingerprint_sha256": None, "context": None, "repo_full_name": "acme/infra",
            "repo_html_url": "u", "source_url": "u", "note": None,
        }
        cl._aggregate_code_finding(agg, {**base, "path": ".env"}, "q1")
        cl._aggregate_code_finding(agg, {**base, "path": "other/.env"}, "q1")
        assert len(agg) == 2


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

class TestPersistRepositoryFindings:
    def test_persists_one_finding_per_repo(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        agg = {"acme/webapp": {**cl.normalize_repo_item(_repo_item(), "repo_search"), "discovered_via": {"repo_search"}}}
        errors = cl.persist_repository_findings(agg, SAFE_TARGET, store)
        assert errors == []
        records = store.all()
        assert len(records) == 1
        assert records[0]["type"] == "code_leak_repository"
        assert records[0]["value"]["full_name"] == "acme/webapp"
        assert records[0]["confidence"] == cl.CONFIDENCE_MEDIUM

    def test_multi_source_repo_gets_high_confidence(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        agg = {"acme/webapp": {**cl.normalize_repo_item(_repo_item(), "repo_search"),
                                "discovered_via": {"repo_search", "code_search"}}}
        cl.persist_repository_findings(agg, SAFE_TARGET, store)
        assert store.all()[0]["confidence"] == cl.CONFIDENCE_HIGH

    def test_json_serializable(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        agg = {"acme/webapp": {**cl.normalize_repo_item(_repo_item(), "repo_search"), "discovered_via": {"repo_search"}}}
        cl.persist_repository_findings(agg, SAFE_TARGET, store)
        json.dumps(store.all())


class TestPersistCodeFindings:
    def test_persists_and_escalates_confidence_on_convergence(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        agg = {}
        finding = {
            "category": cl.CATEGORY_CREDENTIAL, "pattern_name": "generic_secret_assignment",
            "confidence": cl.CONFIDENCE_MEDIUM, "redacted_value": "hunt****r2xy",
            "fingerprint_sha256": "deadbeef", "context": "password = ...", "path": "app.py",
            "repo_full_name": "acme/webapp", "repo_html_url": "https://github.com/acme/webapp",
            "source_url": "https://github.com/acme/webapp/blob/main/app.py", "note": "verify manually",
        }
        cl._aggregate_code_finding(agg, finding, "generic_mention")
        cl._aggregate_code_finding(agg, dict(finding), "secret_keyword")
        errors = cl.persist_code_findings(agg, SAFE_TARGET, store)
        assert errors == []
        rec = store.all()[0]
        assert rec["type"] == "code_leak_exposure"
        assert rec["confidence"] == cl.CONFIDENCE_HIGH  # 2 converging queries escalate MEDIUM -> HIGH
        assert rec["value"]["matched_via_queries"] == ["generic_mention", "secret_keyword"]
        assert "hunt" not in rec["value"]["redacted_value"] or rec["value"]["redacted_value"] != "hunter2xyz"

    def test_single_query_keeps_base_confidence(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        agg = {}
        finding = {
            "category": cl.CATEGORY_API_KEY, "pattern_name": "aws_access_key_id",
            "confidence": cl.CONFIDENCE_HIGH, "redacted_value": "AKIA****CDEF",
            "fingerprint_sha256": "abc", "context": "...", "path": "infra.py",
            "repo_full_name": "acme/infra", "repo_html_url": "u", "source_url": "u", "note": None,
        }
        cl._aggregate_code_finding(agg, finding, "generic_mention")
        cl.persist_code_findings(agg, SAFE_TARGET, store)
        assert store.all()[0]["confidence"] == cl.CONFIDENCE_HIGH


class TestPersistNoMatchFindings:
    def test_persists_negative_result_memory(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        errors = cl.persist_no_match_findings([("generic_mention", '"example.com"')], SAFE_TARGET, store)
        assert errors == []
        rec = store.all()[0]
        assert rec["type"] == "code_leak_checked_no_match"
        assert rec["confidence"] == cl.CONFIDENCE_LOW
        assert "does not prove" in rec["metadata"]["note"]


# ---------------------------------------------------------------------------
# run_code_leak (integration)
# ---------------------------------------------------------------------------

def _route_github(repo_response=None, code_responses=None):
    """
    Build a requests.get side_effect that routes by URL: repository search
    vs code search, returning canned responses in sequence for code search.
    """
    code_responses = list(code_responses or [])

    def _side_effect(url, *args, **kwargs):
        if url == cl.GITHUB_REPO_SEARCH_API:
            return repo_response if repo_response is not None else _fake_response(200, {"total_count": 0, "items": []})
        if url == cl.GITHUB_CODE_SEARCH_API:
            if code_responses:
                return code_responses.pop(0)
            return _fake_response(200, {"total_count": 0, "items": []})
        raise AssertionError(f"unexpected URL contacted: {url}")

    return _side_effect


class TestRunCodeLeak:
    def test_rejects_bad_target(self, tmp_path):
        with pytest.raises(cl.ScopeError):
            cl.run_code_leak("not a domain", output_dir=str(tmp_path / "output"))

    @mock.patch("reconhound.code_leak.requests.get")
    def test_missing_token_skips_code_search_but_runs_repo_search(self, mock_get, tmp_path):
        mock_get.side_effect = _route_github(repo_response=_fake_response(200, {"total_count": 1, "items": [_repo_item()]}))
        result = cl.run_code_leak(SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token=None, request_delay=0)
        assert result["source_status"]["code_search"]["status"] == "missing_credentials"
        assert len(result["repositories"]) == 1
        # only the repository-search endpoint should ever have been hit
        called_urls = {c.args[0] for c in mock_get.call_args_list}
        assert called_urls == {cl.GITHUB_REPO_SEARCH_API}

    @mock.patch("reconhound.code_leak.time.sleep", return_value=None)
    @mock.patch("reconhound.code_leak.requests.get")
    def test_full_run_persists_repos_secrets_and_no_match(self, mock_get, mock_sleep, tmp_path):
        output_dir = tmp_path / "output"
        code_item_with_secret = _code_item(
            path="infra/deploy.py", repo_full_name="acme/infra",
            fragments=["AWS_KEY = 'AKIA1234567890ABCDEF'"],
        )
        code_item_private = _code_item(path="infra/secret.py", repo_full_name="acme/private-infra", private=True,
                                        fragments=["AKIA0000000000000000"])
        code_responses = [
            _fake_response(200, {"total_count": 1, "items": [code_item_with_secret, code_item_private]}),
        ]
        # remaining queries return no results
        code_responses += [_fake_response(200, {"total_count": 0, "items": []})] * (len(cl.DEFAULT_CODE_SEARCH_QUERIES) - 1)

        mock_get.side_effect = _route_github(
            repo_response=_fake_response(200, {"total_count": 1, "items": [_repo_item(full_name="acme/infra")]}),
            code_responses=code_responses,
        )

        result = cl.run_code_leak(SAFE_TARGET, output_dir=str(output_dir), github_token="tok", request_delay=0)

        assert result["stats"]["private_repos_skipped"] == 1
        assert result["stats"]["repositories_found"] == 1
        assert result["stats"]["code_findings_found"] >= 1
        assert result["stats"]["code_queries_no_match"] >= 1

        store = cl.PendingAssetsStore(output_dir=str(output_dir))
        records = store.all()
        types = {r["type"] for r in records}
        assert "code_leak_repository" in types
        assert "code_leak_exposure" in types
        assert "code_leak_checked_no_match" in types
        # never persist anything from the private repo
        assert all("private-infra" not in json.dumps(r) for r in records)
        # secrets are never stored raw
        assert all("AKIA1234567890ABCDEF" not in json.dumps(r) for r in records)
        json.dumps(result)  # whole summary must be JSON-safe

    @mock.patch("reconhound.code_leak.time.sleep", return_value=None)
    @mock.patch("reconhound.code_leak.requests.get")
    def test_rate_limited_mid_run_stops_remaining_queries(self, mock_get, mock_sleep, tmp_path):
        code_responses = [_fake_response(403, headers={"X-RateLimit-Remaining": "0"})]
        mock_get.side_effect = _route_github(code_responses=code_responses)
        result = cl.run_code_leak(
            SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="tok",
            include_repo_search=False, request_delay=0,
        )
        assert result["stats"]["code_queries_run"] == 1
        assert len(result["stats"]["code_queries_skipped"]) == len(cl.DEFAULT_CODE_SEARCH_QUERIES) - 1

    @mock.patch("reconhound.code_leak.requests.get")
    def test_repo_search_error_does_not_abort_run(self, mock_get, tmp_path):
        mock_get.side_effect = requests.exceptions.ConnectionError("boom")
        result = cl.run_code_leak(
            SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token=None,
            include_code_search=False,
        )
        assert result["source_status"]["repo_search"]["status"] == "error"
        assert result["stats"]["repositories_found"] == 0

    @mock.patch("reconhound.code_leak.requests.get")
    def test_max_code_queries_caps_query_count(self, mock_get, tmp_path):
        mock_get.side_effect = _route_github(
            repo_response=_fake_response(200, {"total_count": 0, "items": []}),
            code_responses=[_fake_response(200, {"total_count": 0, "items": []})] * 3,
        )
        result = cl.run_code_leak(
            SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="tok",
            max_code_queries=3, request_delay=0,
        )
        assert result["stats"]["code_queries_run"] == 3

    @mock.patch("reconhound.code_leak.requests.get")
    def test_custom_queries_override_defaults(self, mock_get, tmp_path):
        mock_get.side_effect = _route_github(
            repo_response=_fake_response(200, {"total_count": 0, "items": []}),
            code_responses=[_fake_response(200, {"total_count": 0, "items": []})],
        )
        result = cl.run_code_leak(
            SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="tok",
            code_queries=[("custom_label", '"{target}" custom_dork')], request_delay=0,
        )
        assert result["stats"]["code_queries_run"] == 1
        assert result["source_status"]["code_search_queries"][0]["label"] == "custom_label"
        assert result["source_status"]["code_search_queries"][0]["query"] == f'"{SAFE_TARGET}" custom_dork'

    @mock.patch("reconhound.code_leak.requests.get")
    def test_never_contacts_target_host(self, mock_get, tmp_path):
        mock_get.side_effect = _route_github(
            repo_response=_fake_response(200, {"total_count": 0, "items": []}),
            code_responses=[_fake_response(200, {"total_count": 0, "items": []})] * len(cl.DEFAULT_CODE_SEARCH_QUERIES),
        )
        cl.run_code_leak(SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="tok", request_delay=0)
        for c in mock_get.call_args_list:
            url = c.args[0]
            assert "api.github.com" in url
            assert url in (cl.GITHUB_CODE_SEARCH_API, cl.GITHUB_REPO_SEARCH_API)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
