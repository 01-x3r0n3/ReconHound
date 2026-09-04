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
    def test_convergent_queries_are_recorded_but_do_not_raise_confidence(self, tmp_path):
        """
        Replaces an earlier test that asserted MEDIUM -> HIGH escalation when
        >=2 dorks surfaced the same sighting. That behaviour was wrong, not
        merely obsolete: DEFAULT_CODE_SEARCH_QUERIES' unqualified `"{target}"`
        query is a strict SUPERSET of every keyword-qualified query in the
        list, so a second matching query is guaranteed by construction rather
        than being the independent corroboration context.md §8 requires. The
        escalation therefore promoted essentially every generic keyword match
        to HIGH, and risk_engine.py's CONFIDENCE_SEVERITY_CAP reports HIGH
        confidence as CRITICAL severity.

        The stronger assertion: the converging queries are still recorded as
        evidence (nothing is lost), and the confidence stays the pattern's own.
        """
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
        assert len(store.all()) == 1, "the same sighting must persist once, not once per query"
        rec = store.all()[0]
        assert rec["type"] == "code_leak_exposure"
        assert rec["confidence"] == cl.CONFIDENCE_MEDIUM
        # The convergence itself is preserved as evidence, just not as confidence.
        assert rec["value"]["matched_via_queries"] == ["generic_mention", "secret_keyword"]
        assert rec["metadata"]["matched_query_count"] == 2
        assert rec["value"]["redacted_value"] == "hunt****r2xy"

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


# ===========================================================================
# Remediation regression tests
#
# Each class below pins one confirmed defect found during the Module 3
# remediation audit. The docstrings record the reproduction, because the
# behaviours they forbid all looked reasonable in isolation and several were
# only visible once the finding reached risk_engine.py.
# ===========================================================================

class TestContextNeverLeaksCoLocatedSecrets:
    """
    A fragment routinely holds several secrets (a .env excerpt). Redacting only
    the span belonging to the finding being built left every OTHER secret in
    that fragment stored verbatim in `context` -- and `context` is persisted to
    pending_assets.json, ingested into the asset graph, and rendered into the
    HTML report's raw-data appendix. Input-contract decision #3 says secrets
    are never stored verbatim; this makes that true of co-located secrets too.
    """

    MULTI_SECRET_FRAGMENT = (
        'AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I\n'
        'password = "Tr0ub4dor&3xKq"\n'
        'GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n'
    )
    RAW_SECRETS = (
        "AKIA1B2C3D4E5F6G7H8I",
        "Tr0ub4dor&3xKq",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    )

    def _findings(self):
        item = _code_item(path="app/config.py", fragments=[self.MULTI_SECRET_FRAGMENT])
        return cl.extract_findings_from_code_item(item)

    def test_all_three_secrets_are_still_detected(self):
        """The fix must not cost coverage: every secret is still a finding."""
        names = {f["pattern_name"] for f in self._findings()}
        assert {"aws_access_key_id", "github_token", "generic_secret_assignment"} <= names

    def test_no_finding_context_contains_any_raw_secret(self):
        for finding in self._findings():
            context = finding.get("context") or ""
            for raw in self.RAW_SECRETS:
                assert raw not in context, (
                    f"{finding['pattern_name']} stored raw secret {raw!r} in its context"
                )

    def test_every_secret_is_redacted_in_the_shared_context(self):
        findings = [f for f in self._findings() if f.get("context")]
        assert findings
        # All secret findings share one fully-redacted excerpt of the fragment.
        assert len({f["context"] for f in findings}) == 1
        context = findings[0]["context"]
        assert context.count("«") == 3, context

    def test_raw_secret_never_reaches_persisted_output(self, tmp_path):
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        agg = {}
        for finding in self._findings():
            cl._aggregate_code_finding(agg, finding, "generic_mention")
        assert cl.persist_code_findings(agg, SAFE_TARGET, store) == []
        blob = json.dumps(store.all())
        for raw in self.RAW_SECRETS:
            assert raw not in blob


class TestMarkerPatternsEmitNoValueFingerprint:
    """
    `private_key_block` matches a constant PEM armour header, not key material.
    Hashing it gave every private key ever found the identical
    fingerprint_sha256 -- and risk_engine.py discriminates
    `leaked_credential_in_public_code` signals by that field, so N distinct
    leaked keys collapsed into one signal and N-1 disappeared from the risk
    assessment entirely. Reproduced end-to-end before the fix.
    """

    def _finding_for(self, repo, path, body):
        item = _code_item(
            path=path, repo_full_name=repo,
            html_url=f"https://github.com/{repo}/blob/main/{path}",
            repo_html_url=f"https://github.com/{repo}",
            fragments=[f"-----BEGIN RSA PRIVATE KEY-----\n{body}"],
        )
        return [f for f in cl.extract_findings_from_code_item(item)
                if f["pattern_name"] == "private_key_block"][0]

    def test_private_key_finding_has_no_fingerprint(self):
        finding = self._finding_for("acme/infra", "deploy/id_rsa", "MIIEowIBAAKCAQEA1111")
        assert finding["fingerprint_sha256"] is None
        # The evidence that a key was seen is still fully present.
        assert finding["confidence"] == cl.CONFIDENCE_HIGH
        assert finding["category"] == cl.CATEGORY_CREDENTIAL
        assert finding["source_url"].endswith("deploy/id_rsa")

    def test_two_distinct_private_keys_stay_two_findings(self, tmp_path):
        agg = {}
        cl._aggregate_code_finding(
            agg, self._finding_for("acme/infra", "deploy/id_rsa", "MIIEowIBAAKCAQEA1111"), "q1")
        cl._aggregate_code_finding(
            agg, self._finding_for("acme/other", "keys/server.pem", "MIIEowIBAAKCAQEA2222"), "q1")
        assert len(agg) == 2

        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert cl.persist_code_findings(agg, SAFE_TARGET, store) == []
        creds = [r for r in store.all() if r["value"]["category"] == cl.CATEGORY_CREDENTIAL]
        assert len(creds) == 2
        # risk_engine.py falls back to source_url when there is no fingerprint,
        # so the two signals must remain distinguishable by it.
        assert len({r["value"]["source_url"] for r in creds}) == 2

    def test_real_secret_values_still_get_a_fingerprint(self):
        """The marker exemption must not disable fingerprinting generally."""
        item = _code_item(fragments=["AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I"])
        finding = [f for f in cl.extract_findings_from_code_item(item)
                   if f["pattern_name"] == "aws_access_key_id"][0]
        assert finding["fingerprint_sha256"] == cl._fingerprint("AKIA1B2C3D4E5F6G7H8I")

    def test_same_key_in_the_same_file_from_two_queries_still_dedupes(self):
        agg = {}
        finding = self._finding_for("acme/infra", "deploy/id_rsa", "MIIEowIBAAKCAQEA1111")
        cl._aggregate_code_finding(agg, dict(finding), "generic_mention")
        cl._aggregate_code_finding(agg, dict(finding), "private_key_file")
        assert len(agg) == 1


class TestPlaceholderAssessment:
    """
    Documentation filler matched the generic patterns and reached the operator
    as a leaked credential. Findings are downgraded and annotated, never
    dropped -- suppressing them would trade a false positive for a false
    negative, which is the worse error for credential exposure.
    """

    @pytest.mark.parametrize("value", [
        "your_password_here", "YOUR_API_KEY_HERE", "changeme", "xxxxxxxxxxxx",
        "aaaaaaaaaaaaaaaa", "EXAMPLE_TOKEN_VALUE", "<your-password>", "${DB_PASSWORD}",
        "{{ vault_password }}", "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ])
    def test_flags_documentation_filler(self, value):
        assert cl.assess_placeholder(value) is not None

    @pytest.mark.parametrize("value", [
        "Tr0ub4dor&3xKq", "AKIA1B2C3D4E5F6G7H8I", "hunter2CorrectHorseBattery",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a", "sk_live_51HxYzAbCdEfGhIjKl",
        "Sup3rS3cretDbPass",
    ])
    def test_does_not_flag_plausible_secrets(self, value):
        assert cl.assess_placeholder(value) is None

    @pytest.mark.parametrize("value", [None, "", "   ", 12345, [], {}])
    def test_non_string_and_empty_input_is_safe(self, value):
        assert cl.assess_placeholder(value) is None

    def test_placeholder_finding_is_kept_but_downgraded_and_explained(self):
        item = _code_item(path="README.md", fragments=['password = "your_password_here"'])
        findings = [f for f in cl.extract_findings_from_code_item(item)
                    if f["pattern_name"] == "generic_secret_assignment"]
        assert len(findings) == 1, "the finding must be kept, not suppressed"
        finding = findings[0]
        assert finding["confidence"] == cl.CONFIDENCE_LOW
        assert any("placeholder" in note for note in finding["quality_notes"])
        # Full evidence survives the downgrade.
        assert finding["redacted_value"]
        assert finding["source_url"]

    def test_genuine_secret_keeps_its_pattern_confidence(self):
        item = _code_item(path="app/settings.py", fragments=['password = "Tr0ub4dor&3xKq"'])
        finding = [f for f in cl.extract_findings_from_code_item(item)
                   if f["pattern_name"] == "generic_secret_assignment"][0]
        assert finding["confidence"] == cl.CONFIDENCE_MEDIUM
        assert finding["quality_notes"] == []

    def test_downgrade_reason_travels_into_the_persisted_evidence(self, tmp_path):
        item = _code_item(path="README.md", fragments=['password = "your_password_here"'])
        agg = {}
        for finding in cl.extract_findings_from_code_item(item):
            cl._aggregate_code_finding(agg, finding, "password_keyword")
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert cl.persist_code_findings(agg, SAFE_TARGET, store) == []
        rec = [r for r in store.all() if r["value"]["category"] == cl.CATEGORY_CREDENTIAL][0]
        assert rec["confidence"] == cl.CONFIDENCE_LOW
        assert any("Confidence reduced" in line for line in rec["evidence"])
        assert rec["metadata"]["quality_notes"]


class TestPathAuthorityAssessment:
    @pytest.mark.parametrize("path", [
        "node_modules/aws-sdk/lib/config.json", "vendor/acme/.env",
        "bower_components/x/config.json", "third_party/lib/secrets.yml",
        ".env.example", "config/settings.example.py", "templates/app.yml",
        "deploy/docker-compose.sample.yml",
    ])
    def test_flags_template_and_vendored_paths(self, path):
        assert cl.assess_path_authority(path) is not None

    @pytest.mark.parametrize("path", [
        "src/app/config.json", "deploy/id_rsa", ".env", "wp-config.php",
        # Deliberately NOT flagged: real credentials are genuinely committed
        # into test fixtures, so downgrading them would be a false negative.
        "tests/fixtures/credentials", "test/config.json",
    ])
    def test_does_not_flag_ordinary_or_test_paths(self, path):
        assert cl.assess_path_authority(path) is None

    def test_vendored_path_downgrades_one_step_and_is_recorded(self):
        item = _code_item(path="node_modules/aws-sdk/creds.py",
                          fragments=["AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I"])
        finding = [f for f in cl.extract_findings_from_code_item(item)
                   if f["pattern_name"] == "aws_access_key_id"][0]
        assert finding["confidence"] == cl.CONFIDENCE_MEDIUM  # HIGH downgraded one step
        assert any("vendored" in note for note in finding["quality_notes"])

    def test_placeholder_and_path_downgrades_compose_to_low(self):
        item = _code_item(path=".env.example", fragments=['password = "changeme"'])
        finding = [f for f in cl.extract_findings_from_code_item(item)
                   if f["pattern_name"] == "generic_secret_assignment"][0]
        assert finding["confidence"] == cl.CONFIDENCE_LOW
        assert len(finding["quality_notes"]) == 2


class TestPrivateRepoSafeguardFailsClosed:
    """
    `_is_private_repo` documents a fail-closed branch for a non-dict repository
    object, but all three call sites coerced a missing/non-dict `repository` to
    `{}` first -- which reads as public. An item whose public/private state
    could not be established was therefore evidenced and persisted.
    """

    @pytest.mark.parametrize("repository", [None, "acme/webapp", 42, ["acme"]])
    def test_unverifiable_repository_object_yields_no_findings(self, repository):
        item = {"path": ".env", "html_url": "u", "repository": repository,
                "text_matches": [{"fragment": "AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I"}]}
        assert cl.extract_findings_from_code_item(item) == []

    def test_missing_repository_key_yields_no_findings(self):
        item = {"path": ".env", "html_url": "u",
                "text_matches": [{"fragment": "AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I"}]}
        assert cl.extract_findings_from_code_item(item) == []

    def test_repo_object_returns_raw_value_without_substituting(self):
        assert cl._repo_object({"repository": None}) is None
        assert cl._repo_object({"repository": "x"}) == "x"
        assert cl._repo_object({}) is None
        assert cl._repo_object("not a dict") is None
        assert cl._repo_object({"repository": {"private": False}}) == {"private": False}

    def test_ordinary_public_repository_is_unaffected(self):
        item = _code_item(fragments=["AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I"])
        assert cl.extract_findings_from_code_item(item)

    def test_withheld_items_are_counted_not_silently_dropped(self, tmp_path):
        item = {"path": ".env", "html_url": "u", "repository": "malformed",
                "text_matches": [{"fragment": "AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I"}]}
        responses = [_fake_response(json_data={"total_count": 1, "items": [item]})]
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=responses)), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=1,
            )
        assert summary["stats"]["items_unverifiable_repo"] == 1
        assert summary["stats"]["private_repos_skipped"] == 0
        assert summary["stats"]["code_findings_found"] == 0


class TestMalformedFieldsDoNotDestroyEvidence:
    """
    A non-string `path` raised TypeError inside the config-file matcher; the
    extractor's outer guard swallowed it and returned an empty list, so one bad
    field silently discarded every genuine secret in that item.
    """

    @pytest.mark.parametrize("path", [12345, 3.5, True])
    def test_non_string_path_still_yields_secret_findings(self, path):
        item = {"path": path, "html_url": "u",
                "repository": {"full_name": "acme/webapp", "private": False},
                "text_matches": [{"fragment":
                                  "AKIA1B2C3D4E5F6G7H8I and ghp_16C7e42F292c6912E7710c838347Ae178B4a"}]}
        names = {f["pattern_name"] for f in cl.extract_findings_from_code_item(item)}
        assert {"aws_access_key_id", "github_token"} <= names

    @pytest.mark.parametrize("path", [None, [], {}])
    def test_unusable_path_degrades_to_empty_string_not_a_crash(self, path):
        item = {"path": path, "name": None, "html_url": "u",
                "repository": {"full_name": "acme/webapp", "private": False},
                "text_matches": [{"fragment": "AKIA1B2C3D4E5F6G7H8I"}]}
        findings = cl.extract_findings_from_code_item(item)
        assert [f["pattern_name"] for f in findings] == ["aws_access_key_id"]
        assert findings[0]["path"] == ""

    @pytest.mark.parametrize("text_matches", [
        {"fragment": "AKIA1B2C3D4E5F6G7H8I"}, "not a list", 7, None,
        [None], [{"fragment": None}], [{"fragment": b"AKIA1B2C3D4E5F6G7H8I"}], [{}],
    ])
    def test_malformed_text_matches_never_raise(self, text_matches):
        item = {"path": "a.py", "html_url": "u",
                "repository": {"full_name": "acme/webapp", "private": False},
                "text_matches": text_matches}
        assert cl.extract_findings_from_code_item(item) == []

    def test_as_text_coercion(self):
        assert cl._as_text("x") == "x"
        assert cl._as_text(None) == ""
        assert cl._as_text(12) == "12"
        assert cl._as_text([1]) == ""


class TestFragmentSizeCeiling:
    """
    A single 1.4 MB fragment of repeated `token="..."` assignments took ~25 s
    of regex time and produced 20,000 findings, each of which
    PendingAssetsStore rewrites the whole output file for. GitHub's real
    fragments are a few hundred bytes; the ceiling only bounds a
    non-conforming response, and it reports itself when it bites.
    """

    def test_oversized_fragment_is_bounded_and_flagged(self):
        fragment = ('token="' + "A" * 60 + '" ') * 20000
        assert len(fragment) > cl.MAX_FRAGMENT_CHARS
        item = _code_item(fragments=[fragment])
        findings = cl.extract_findings_from_code_item(item)
        secret_findings = [f for f in findings if f["category"] != cl.CATEGORY_CONFIG_FILE]
        assert secret_findings
        assert len(secret_findings) <= cl.MAX_FINDINGS_PER_FRAGMENT
        assert all(f["fragment_truncated"] for f in secret_findings)

    def test_oversized_fragment_completes_quickly(self):
        import time as _time
        fragment = ('token="' + "A" * 60 + '" ') * 20000
        started = _time.perf_counter()
        cl.extract_findings_from_code_item(_code_item(fragments=[fragment]))
        assert _time.perf_counter() - started < 5.0

    def test_ordinary_fragment_is_not_flagged_as_truncated(self):
        item = _code_item(fragments=["AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I"])
        finding = [f for f in cl.extract_findings_from_code_item(item)
                   if f["pattern_name"] == "aws_access_key_id"][0]
        assert finding["fragment_truncated"] is False

    def test_truncation_is_reported_in_persisted_evidence(self, tmp_path):
        fragment = ('token="' + "A" * 60 + '" ') * 20000
        agg = {}
        for finding in cl.extract_findings_from_code_item(_code_item(fragments=[fragment])):
            cl._aggregate_code_finding(agg, finding, "token_keyword")
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert cl.persist_code_findings(agg, SAFE_TARGET, store) == []
        rec = [r for r in store.all() if r["value"]["fragment_truncated"]][0]
        assert any("truncated" in line for line in rec["evidence"])


class TestTargetAssociationIsRecordedNotAsserted:
    """
    Every query is anchored on the target string, but a GitHub text match is a
    textual link, never proof of ownership. Whether the target string was
    actually near the match is recorded as an observation so a weak association
    is visible instead of implied.
    """

    def test_target_present_in_fragment(self):
        item = _code_item(fragments=['# db for example.com\npassword = "Tr0ub4dor&3xKq"'])
        finding = [f for f in cl.extract_findings_from_code_item(item, target=SAFE_TARGET)
                   if f["pattern_name"] == "generic_secret_assignment"][0]
        assert finding["target_string_in_fragment"] is True

    def test_target_absent_from_fragment(self):
        item = _code_item(fragments=['password = "Tr0ub4dor&3xKq"'])
        finding = [f for f in cl.extract_findings_from_code_item(item, target=SAFE_TARGET)
                   if f["pattern_name"] == "generic_secret_assignment"][0]
        assert finding["target_string_in_fragment"] is False

    def test_unknown_when_no_target_supplied(self):
        item = _code_item(fragments=['password = "Tr0ub4dor&3xKq"'])
        finding = [f for f in cl.extract_findings_from_code_item(item)
                   if f["pattern_name"] == "generic_secret_assignment"][0]
        assert finding["target_string_in_fragment"] is None

    def test_weak_association_is_spelled_out_in_the_evidence(self, tmp_path):
        item = _code_item(fragments=['password = "Tr0ub4dor&3xKq"'])
        agg = {}
        for finding in cl.extract_findings_from_code_item(item, target=SAFE_TARGET):
            cl._aggregate_code_finding(agg, finding, "password_keyword")
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert cl.persist_code_findings(agg, SAFE_TARGET, store) == []
        rec = [r for r in store.all() if r["value"]["category"] == cl.CATEGORY_CREDENTIAL][0]
        assert any("only by the search query" in line for line in rec["evidence"])
        # It stays an observation: the finding is not suppressed or reclassified.
        assert rec["confidence"] == cl.CONFIDENCE_MEDIUM

    def test_association_is_true_if_any_converging_observation_saw_it(self):
        agg = {}
        base = {"category": cl.CATEGORY_CREDENTIAL, "pattern_name": "p", "confidence": "MEDIUM",
                "redacted_value": "r", "fingerprint_sha256": "fp", "context": "c", "path": "a.py",
                "repo_full_name": "acme/webapp", "repo_html_url": "u", "source_url": "u",
                "note": None, "quality_notes": [], "fragment_truncated": False}
        cl._aggregate_code_finding(agg, {**base, "target_string_in_fragment": False}, "q1")
        cl._aggregate_code_finding(agg, {**base, "target_string_in_fragment": True}, "q2")
        assert list(agg.values())[0]["target_string_in_fragment"] is True


class TestSearchCompletenessIsReported:
    """
    `search_github_code` parsed GitHub's `incomplete_results` flag and then
    dropped it, and the module examines exactly one page per query while
    reporting GitHub's full `total_count`. A consumer could not tell
    "checked everything, found nothing" from "checked 30 of 8,742".
    """

    def test_helper_reports_truncation_against_total_count(self):
        resp = _fake_response(json_data={
            "total_count": 8742, "incomplete_results": True,
            "items": [_code_item()] * 30,
        })
        with mock.patch("reconhound.code_leak.requests.get", return_value=resp):
            result = cl.search_github_code('"example.com"', token="t")
        assert result["status"] == "found"
        assert result["total_count"] == 8742
        assert result["items_examined"] == 30
        assert result["total_count_reported"] is True
        assert result["results_truncated"] is True
        assert result["incomplete_results"] is True

    def test_complete_single_page_is_not_marked_truncated(self):
        resp = _fake_response(json_data={
            "total_count": 2, "incomplete_results": False, "items": [_code_item()] * 2})
        with mock.patch("reconhound.code_leak.requests.get", return_value=resp):
            result = cl.search_github_code('"example.com"', token="t")
        assert result["results_truncated"] is False
        assert result["incomplete_results"] is False

    def test_missing_total_count_is_recorded_as_unknown_not_assumed_complete(self):
        resp = _fake_response(json_data={"items": [_code_item()]})
        with mock.patch("reconhound.code_leak.requests.get", return_value=resp):
            result = cl.search_github_code('"example.com"', token="t")
        assert result["total_count_reported"] is False
        # An unreported count must not be dressed up as a verified truncation
        # verdict in either direction.
        assert result["results_truncated"] is False
        assert result["items_examined"] == 1

    @pytest.mark.parametrize("total", ["8742", None, {"n": 1}, 3.5])
    def test_non_integer_total_count_is_not_trusted(self, total):
        resp = _fake_response(json_data={"total_count": total, "items": [_code_item()]})
        with mock.patch("reconhound.code_leak.requests.get", return_value=resp):
            result = cl.search_github_code('"example.com"', token="t")
        assert result["total_count_reported"] is False
        assert result["total_count"] == 1

    def test_repository_search_reports_completeness_too(self):
        resp = _fake_response(json_data={
            "total_count": 400, "incomplete_results": False, "items": [_repo_item()]})
        with mock.patch("reconhound.code_leak.requests.get", return_value=resp):
            result = cl.search_github_repositories('"example.com"')
        assert result["results_truncated"] is True
        assert result["items_examined"] == 1

    def test_run_surfaces_per_query_completeness(self, tmp_path):
        responses = [_fake_response(json_data={
            "total_count": 8742, "incomplete_results": True, "items": [_code_item()]})]
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=responses)), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=1)
        status = summary["source_status"]["code_search_queries"][0]
        assert status["items_examined"] == 1
        assert status["total_count"] == 8742
        assert status["results_truncated"] is True
        assert status["incomplete_results"] is True
        assert summary["stats"]["code_queries_incomplete"] == 1


class TestInconclusiveIsNotANegativeResult:
    """
    surface_mapper.py stores `code_leak_checked_no_match` as a CHECK_NOT_FOUND
    state that suppresses repeated work. A search whose every result was
    withheld as private, or which GitHub reported as incomplete, is not
    "checked and not found" -- it is inconclusive, and recording it as a
    negative result writes a false conclusion into the graph's memory.
    """

    def _run(self, tmp_path, code_json):
        responses = [_fake_response(json_data=code_json)]
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=responses)), \
             mock.patch("reconhound.code_leak.time.sleep"):
            return cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=1)

    def _persisted_types(self, tmp_path):
        path = os.path.join(str(tmp_path / "output"), "pending_assets.json")
        if not os.path.exists(path):
            return []
        with open(path) as handle:
            return [r["type"] for r in json.load(handle)]

    def test_all_private_page_with_reported_matches_is_inconclusive(self, tmp_path):
        summary = self._run(tmp_path, {
            "total_count": 9000, "incomplete_results": True,
            "items": [_code_item(private=True, fragments=["AKIA1B2C3D4E5F6G7H8I"])]})
        assert summary["stats"]["code_queries_inconclusive"] == ["generic_mention"]
        assert summary["stats"]["code_queries_no_match"] == 0
        assert "code_leak_checked_no_match" not in self._persisted_types(tmp_path)
        status = summary["source_status"]["code_search_queries"][0]
        assert status["conclusive"] is False
        assert "withheld" in status["inconclusive_reason"]

    def test_zero_results_flagged_incomplete_by_provider_is_inconclusive(self, tmp_path):
        summary = self._run(tmp_path, {
            "total_count": 0, "incomplete_results": True, "items": []})
        assert summary["stats"]["code_queries_inconclusive"] == ["generic_mention"]
        assert "code_leak_checked_no_match" not in self._persisted_types(tmp_path)

    def test_genuine_zero_result_search_is_still_negative_result_memory(self, tmp_path):
        summary = self._run(tmp_path, {
            "total_count": 0, "incomplete_results": False, "items": []})
        assert summary["stats"]["code_queries_no_match"] == 1
        assert summary["stats"]["code_queries_inconclusive"] == []
        assert "code_leak_checked_no_match" in self._persisted_types(tmp_path)

    def test_negative_result_finding_states_how_far_the_check_reached(self, tmp_path):
        self._run(tmp_path, {"total_count": 0, "incomplete_results": False, "items": []})
        with open(os.path.join(str(tmp_path / "output"), "pending_assets.json")) as handle:
            rec = [r for r in json.load(handle) if r["type"] == "code_leak_checked_no_match"][0]
        assert "truncated" in rec["metadata"]["scope"]

    @pytest.mark.parametrize("status_code", [500, 502, 503, 401, 422])
    def test_provider_failure_is_never_a_negative_result(self, tmp_path, status_code):
        responses = [_fake_response(status_code=status_code, json_data={"message": "boom"})]
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=responses)), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=1)
        assert summary["stats"]["code_queries_no_match"] == 0
        assert summary["errors"]
        assert "code_leak_checked_no_match" not in self._persisted_types(tmp_path)

    @pytest.mark.parametrize("exc", [
        requests.exceptions.Timeout(), requests.exceptions.ConnectionError("down")])
    def test_transport_failure_is_never_a_negative_result(self, tmp_path, exc):
        with mock.patch("reconhound.code_leak.requests.get", side_effect=exc), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=2)
        assert summary["stats"]["code_queries_no_match"] == 0
        assert "code_leak_checked_no_match" not in self._persisted_types(tmp_path)


class TestSecondaryRateLimitClassification:
    """
    GitHub's secondary rate limit can arrive as a 403 with no Retry-After
    header, identifiable only from the body message. Calling that
    "unauthorized" sends the operator off to reissue a working token.
    """

    def test_secondary_rate_limit_without_retry_after(self):
        resp = _fake_response(status_code=403, headers={"X-RateLimit-Remaining": "28"}, json_data={
            "message": "You have exceeded a secondary rate limit. Please wait a few minutes.",
        })
        status, error = cl._classify_github_status(resp)
        assert status == "rate_limited"
        assert "secondary rate limit" in error

    def test_abuse_detection_message(self):
        resp = _fake_response(status_code=403, json_data={
            "message": "You have triggered an abuse detection mechanism."})
        assert cl._classify_github_status(resp)[0] == "rate_limited"

    def test_genuine_403_is_still_unauthorized_and_quotes_the_reason(self):
        resp = _fake_response(status_code=403, json_data={
            "message": "Resource not accessible by personal access token"})
        status, error = cl._classify_github_status(resp)
        assert status == "unauthorized"
        assert "not accessible" in error

    def test_403_with_unreadable_body_is_still_classified(self):
        resp = _fake_response(status_code=403, raise_json_error=True)
        assert cl._classify_github_status(resp)[0] == "unauthorized"

    @pytest.mark.parametrize("body", [None, [], "text", {"message": 42}])
    def test_403_with_unexpected_body_shape_does_not_raise(self, body):
        resp = _fake_response(status_code=403, json_data=body)
        assert cl._classify_github_status(resp)[0] == "unauthorized"

    def test_primary_rate_limit_header_still_wins(self):
        resp = _fake_response(status_code=403, headers={"X-RateLimit-Remaining": "0"})
        status, error = cl._classify_github_status(resp)
        assert status == "rate_limited"
        assert "primary rate limit" in error


class TestQueryTemplateGuard:
    """
    `template.format(target=...)` sat outside the per-query try, so a caller
    template containing a stray brace aborted the whole run -- discarding every
    repository already discovered, because persistence happens after the loop.
    """

    def test_bad_template_costs_one_query_not_the_run(self, tmp_path):
        responses = [_fake_response(json_data={"total_count": 0, "items": []})]
        repo_response = _fake_response(json_data={"total_count": 1, "items": [_repo_item()]})
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(repo_response=repo_response,
                                                  code_responses=responses)), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                code_queries=[("broken", '"{target}" {"password":'), ("ok", '"{target}"')])
        assert summary["stats"]["repositories_found"] == 1
        assert "broken" in summary["stats"]["code_queries_skipped"]
        assert summary["stats"]["code_queries_run"] == 1
        assert any(e["stage"] == "code_search_query_template" for e in summary["errors"])

    @pytest.mark.parametrize("template", ['"{target}" {oops}', '"{target}" {0}', '"{target}" {'])
    def test_every_template_failure_mode_is_contained(self, tmp_path, template):
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=[])), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, code_queries=[("bad", template)])
        assert summary["stats"]["code_queries_run"] == 0
        assert summary["stats"]["code_queries_skipped"] == ["bad"]


class TestRepositoryTemporalState:
    """
    `normalize_repo_item` dropped GitHub's lifecycle fields, so an archived
    repository last pushed a decade ago was indistinguishable from a live one
    and the only timestamp downstream was this module's own discovery time.
    """

    def test_lifecycle_fields_are_preserved(self):
        raw = dict(_repo_item(), archived=True, pushed_at="2014-01-02T00:00:00Z",
                   updated_at="2015-01-02T00:00:00Z", created_at="2013-01-02T00:00:00Z")
        record = cl.normalize_repo_item(raw, "repo_search")
        assert record["archived"] is True
        assert record["pushed_at"] == "2014-01-02T00:00:00Z"
        assert record["updated_at"] == "2015-01-02T00:00:00Z"
        assert record["created_at"] == "2013-01-02T00:00:00Z"

    def test_absent_lifecycle_fields_are_none_not_invented(self):
        record = cl.normalize_repo_item(_repo_item(), "repo_search")
        assert record["archived"] is None
        assert record["pushed_at"] is None

    def test_lifecycle_survives_aggregation_from_the_endpoint_that_has_it(self):
        agg = {}
        # /search/code's embedded repository objects carry no lifecycle fields.
        cl._aggregate_repo(agg, cl.normalize_repo_item(_repo_item(), "code_search"))
        cl._aggregate_repo(agg, cl.normalize_repo_item(
            dict(_repo_item(), archived=True, pushed_at="2014-01-02T00:00:00Z"), "repo_search"))
        record = agg["acme/webapp"]
        assert record["archived"] is True
        assert record["pushed_at"] == "2014-01-02T00:00:00Z"
        assert record["discovered_via"] == {"code_search", "repo_search"}

    def test_lifecycle_reaches_the_persisted_finding(self, tmp_path):
        agg = {"acme/webapp": {
            **cl.normalize_repo_item(dict(_repo_item(), archived=True,
                                          pushed_at="2014-01-02T00:00:00Z"), "repo_search"),
            "discovered_via": {"repo_search"}}}
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert cl.persist_repository_findings(agg, SAFE_TARGET, store) == []
        value = store.all()[0]["value"]
        assert value["archived"] is True
        assert value["pushed_at"] == "2014-01-02T00:00:00Z"


class TestRedactionSurvivesAdversarialFragments:
    """
    Regressions found by adversarially attacking the redaction fix itself.

    1. Distinct patterns overlap constantly (`generic_secret_assignment`
       matches the `password=` inside a connection string that
       `db_connection_string` already matched whole). Rewriting both by raw
       offsets corrupted the excerpt and could re-expose part of a value.
    2. The per-fragment findings cap originally returned early, so patterns
       that had not run yet contributed no redaction spans and their secrets
       stayed verbatim in the shared context -- reintroducing the exact leak
       the fix exists to prevent.
    """

    def _contexts(self, fragment):
        item = _code_item(fragments=[fragment])
        return [f["context"] for f in cl.extract_findings_from_code_item(item) if f.get("context")]

    def test_overlapping_matches_do_not_corrupt_or_leak(self):
        fragment = ('DATABASE_URL=postgres://admin:Sup3rS3cretPw@db.acme.com:5432/'
                    'prod?password=OtherSecret99')
        contexts = self._contexts(fragment)
        assert contexts
        for context in contexts:
            assert "Sup3rS3cretPw" not in context
            assert "OtherSecret99" not in context
            # One merged redaction interval, not a nested rewrite that leaves
            # stray delimiters behind.
            assert context.count("«") == context.count("»") == 1

    def test_secret_matched_by_a_late_pattern_is_redacted_when_the_cap_trips(self):
        fragment = ('password = "EarlyLeakSecret1"\n'
                    + " ".join(f"AKIA{str(i).zfill(6)}ABCDEFGHIJ" for i in range(250)))
        contexts = self._contexts(fragment)
        assert contexts
        for context in contexts:
            assert "EarlyLeakSecret1" not in context

    def test_cap_is_reported_on_the_findings_it_limited(self):
        fragment = " ".join(f"AKIA{str(i).zfill(6)}ABCDEFGHIJ" for i in range(250))
        findings = cl.extract_findings_from_code_item(_code_item(fragments=[fragment]))
        secrets = [f for f in findings if f["category"] != cl.CATEGORY_CONFIG_FILE]
        assert len(secrets) == cl.MAX_FINDINGS_PER_FRAGMENT
        assert all(f["findings_capped"] for f in secrets)
        assert all(f["fragment_truncated"] is False for f in secrets)

    def test_uncapped_fragment_is_not_flagged_as_capped(self):
        findings = cl.extract_findings_from_code_item(
            _code_item(fragments=["AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I"]))
        assert all(f["findings_capped"] is False for f in findings)

    def test_cap_is_reported_in_persisted_evidence(self, tmp_path):
        fragment = " ".join(f"AKIA{str(i).zfill(6)}ABCDEFGHIJ" for i in range(250))
        agg = {}
        for finding in cl.extract_findings_from_code_item(_code_item(fragments=[fragment])):
            cl._aggregate_code_finding(agg, finding, "generic_mention")
        store = cl.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert cl.persist_code_findings(agg, SAFE_TARGET, store) == []
        rec = [r for r in store.all() if r["value"].get("findings_capped")][0]
        assert any("beyond that cap" in line for line in rec["evidence"])

    def test_redact_spans_ignores_impossible_offsets(self):
        fragment = "abcdef"
        assert cl._redact_spans(fragment, []) == fragment
        assert cl._redact_spans(fragment, [(None, 2, "x")]) == fragment
        assert cl._redact_spans(fragment, [(-1, 2, "x")]) == fragment
        assert cl._redact_spans(fragment, [(4, 2, "x")]) == fragment
        assert cl._redact_spans(fragment, [(2, 99, "x")]) == fragment
        assert cl._redact_spans(fragment, [(0, 3, "R")]) == "«R»def"

    def test_redact_spans_merges_adjacent_and_nested_intervals(self):
        assert cl._redact_spans("0123456789", [(2, 8, "OUT"), (4, 6, "IN")]) == "01«OUT + IN»89"
        assert cl._redact_spans("0123456789", [(0, 4, "A"), (6, 9, "B")]) == "«A»45«B»9"

    def test_every_matched_value_is_gone_from_a_dense_multi_secret_fragment(self):
        raws = ["AKIA1B2C3D4E5F6G7H8I", "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
                "AIzaSyA1234567890abcdefghijklmnopqrstuv", "sk_live_51HxYzAbCdEfGhIjKl",
                "Tr0ub4dor&3xKq"]
        fragment = (f"aws={raws[0]}\ngh={raws[1]}\ngoogle={raws[2]}\n"
                    f"stripe={raws[3]}\npassword = \"{raws[4]}\"\n")
        contexts = self._contexts(fragment)
        assert contexts
        for context in contexts:
            for raw in raws:
                assert raw not in context


class TestWithheldResultsAreClassifiedByCause:
    def _run(self, tmp_path, code_json):
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=[_fake_response(json_data=code_json)])), \
             mock.patch("reconhound.code_leak.time.sleep"):
            return cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=1)

    def test_withheld_page_is_inconclusive_even_when_total_count_is_zero(self, tmp_path):
        """
        A malformed response can report total_count 0 while still returning
        withheld items. Classifying by what was actually withheld, rather than
        by total_count alone, keeps that out of negative-result memory.
        """
        summary = self._run(tmp_path, {
            "total_count": 0, "incomplete_results": False,
            "items": [_code_item(private=True, fragments=["AKIA1B2C3D4E5F6G7H8I"])]})
        assert summary["stats"]["code_queries_inconclusive"] == ["generic_mention"]
        assert summary["stats"]["code_queries_no_match"] == 0
        assert summary["stats"]["private_repos_skipped"] == 1

    def test_unverifiable_repo_object_also_makes_the_query_inconclusive(self, tmp_path):
        item = {"path": ".env", "html_url": "u", "repository": None,
                "text_matches": [{"fragment": "AKIA1B2C3D4E5F6G7H8I"}]}
        summary = self._run(tmp_path, {"total_count": 1, "items": [item]})
        assert summary["stats"]["code_queries_inconclusive"] == ["generic_mention"]
        assert summary["stats"]["items_unverifiable_repo"] == 1

    def test_conclusive_flag_is_present_on_every_query_status(self, tmp_path):
        summary = self._run(tmp_path, {"total_count": 0, "incomplete_results": False, "items": []})
        status = summary["source_status"]["code_search_queries"][0]
        assert status["conclusive"] is True

    def test_error_status_is_marked_not_conclusive(self, tmp_path):
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=[_fake_response(status_code=503)])), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=1)
        assert summary["source_status"]["code_search_queries"][0]["conclusive"] is False

    def test_repo_search_unverifiable_item_is_not_counted_as_private(self, tmp_path):
        repo_response = _fake_response(json_data={"total_count": 2, "items": ["malformed", _repo_item()]})
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(repo_response=repo_response)), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token=None,
                include_code_search=False)
        assert summary["stats"]["items_unverifiable_repo"] == 1
        assert summary["stats"]["private_repos_skipped"] == 0
        assert summary["stats"]["repositories_found"] == 1


class TestInconclusiveSignalReachesTheOrchestrator:
    """
    core/orchestrator.py's `_compact_stats` keeps only scalar entries from a
    module's nested `stats`, so a list-valued stat never reaches the execution
    record. The "this run reached no conclusion" signal is the one that must
    not be lost, so it is emitted as a scalar too.
    """

    def test_scalar_count_accompanies_the_inconclusive_list(self, tmp_path):
        code_json = {"total_count": 9000, "incomplete_results": True,
                     "items": [_code_item(private=True, fragments=["AKIA1B2C3D4E5F6G7H8I"])]}
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=[_fake_response(json_data=code_json)])), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=1)
        stats = summary["stats"]
        assert stats["code_queries_inconclusive"] == ["generic_mention"]
        assert stats["code_queries_inconclusive_count"] == 1

    def test_orchestrator_compact_stats_preserves_it(self, tmp_path):
        from reconhound.core.orchestrator import _compact_stats
        code_json = {"total_count": 9000, "incomplete_results": True,
                     "items": [_code_item(private=True, fragments=["AKIA1B2C3D4E5F6G7H8I"])]}
        with mock.patch("reconhound.code_leak.requests.get",
                        side_effect=_route_github(code_responses=[_fake_response(json_data=code_json)])), \
             mock.patch("reconhound.code_leak.time.sleep"):
            summary = cl.run_code_leak(
                SAFE_TARGET, output_dir=str(tmp_path / "output"), github_token="t",
                include_repo_search=False, max_code_queries=1)
        compact = _compact_stats(summary)
        assert compact["stats.code_queries_inconclusive_count"] == 1
        assert compact["stats.code_queries_incomplete"] == 1
        assert compact["stats.code_queries_no_match"] == 0
