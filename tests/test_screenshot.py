"""
Tests for reconhound/screenshot.py (ReconHound Module 18, per context.md's
module catalog — catalog item 18, "Visual asset triage").

Run with:  ./.venv/bin/python -m pytest tests/test_screenshot.py -v

All tests mock the `requests.get` and `subprocess.run` boundaries so the
suite is deterministic and offline-safe; no external network access and no
real browser process is required anywhere in this file. (A separate,
manual, real-Chromium end-to-end smoke test was performed during
development against a local test server — see the implementation report —
but is intentionally not part of this automated, hermetic suite.)
"""

import json
import os
import subprocess
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import screenshot as ss


SAFE_URL = "https://example.com/"
SAFE_TARGET = "example.com"


def _fake_response(status_code=200, headers=None, body=b"", final_url=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = dict(headers or {})
    resp.encoding = "utf-8"
    resp.content = body
    resp.url = final_url or SAFE_URL
    resp.elapsed.total_seconds.return_value = 0.05
    resp.raw.read.return_value = body
    return resp


# ---------------------------------------------------------------------------
# validate_url_target (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateUrlTarget:
    def test_accepts_https_url(self):
        assert ss.validate_url_target("https://example.com/path") == "https://example.com/path"

    def test_accepts_in_scope_subdomain(self):
        assert ss.validate_url_target("https://admin.example.com/", target="example.com")

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(ss.ScopeError):
            ss.validate_url_target("https://evil.com/", target="example.com")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(ss.ScopeError):
            ss.validate_url_target("file:///etc/passwd")

    def test_rejects_missing_hostname(self):
        with pytest.raises(ss.ScopeError):
            ss.validate_url_target("https:///path")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(ss.ScopeError):
            ss.validate_url_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        assert ss.validate_url_target("http://93.184.216.34/", target="example.com")


# ---------------------------------------------------------------------------
# make_finding / make_screenshot_finding / PendingAssetsStore
# ---------------------------------------------------------------------------

class TestFindingsAndStore:
    def test_finding_structure_and_source(self):
        finding = ss.make_finding("screenshot_captured", SAFE_URL, {"a": 1}, ["e"], ss.CONFIDENCE_HIGH)
        assert finding["source"] == "screenshot.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_make_screenshot_finding_preserves_all_fields(self):
        finding = ss.make_screenshot_finding(
            url=SAFE_URL, target=SAFE_TARGET, subdomain="example.com",
            screenshot_path="screenshots/example.com/root_abc123.png",
            status_code=200, page_title="Home", byte_length=4096,
            capture_duration_seconds=1.23,
            triage=[{"category": ss.TRIAGE_LOGIN_PAGE, "confidence": ss.CONFIDENCE_HIGH, "evidence": ["e"]}],
        )
        assert finding["type"] == "screenshot_captured"
        assert finding["confidence"] == ss.CONFIDENCE_HIGH
        assert finding["value"]["url"] == SAFE_URL
        assert finding["value"]["subdomain"] == "example.com"
        assert finding["value"]["screenshot_path"] == "screenshots/example.com/root_abc123.png"
        assert finding["metadata"]["byte_length"] == 4096
        assert finding["metadata"]["triage"][0]["category"] == ss.TRIAGE_LOGIN_PAGE
        json.dumps(finding)

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = ss.PendingAssetsStore(output_dir=str(output_dir))
        store.add(ss.make_finding("screenshot_captured", SAFE_URL, {}, ["e"], ss.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = ss.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(ss.PersistenceError):
            store.add(ss.make_finding("screenshot_captured", SAFE_URL, {}, ["e"], ss.CONFIDENCE_HIGH))

    def test_safe_store_add_returns_none_when_store_is_none(self):
        assert ss._safe_store_add(None, ss.make_finding("x", SAFE_URL, {}, [], ss.CONFIDENCE_LOW)) is None

    def test_safe_store_add_returns_error_string_on_persistence_failure(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("not json at all")
        store = ss.PendingAssetsStore(output_dir=str(output_dir))
        err = ss._safe_store_add(store, ss.make_finding("x", SAFE_URL, {}, [], ss.CONFIDENCE_LOW))
        assert err is not None


# ---------------------------------------------------------------------------
# fetch_url / extract_page_title
# ---------------------------------------------------------------------------

class TestFetchUrl:
    def test_successful_fetch(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "text/html"}, body=b"<html>hi</html>")
        with mock.patch("requests.get", return_value=resp):
            result = ss.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["status_code"] == 200
        assert result["body"] == "<html>hi</html>"

    def test_timeout_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = ss.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_connection_error_handled(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = ss.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_json_serializable(self):
        resp = _fake_response(headers={"X-Test": "1"}, body=b"ok")
        with mock.patch("requests.get", return_value=resp):
            result = ss.fetch_url(SAFE_URL)
        json.dumps(result)


class TestExtractPageTitle:
    def test_extracts_title(self):
        assert ss.extract_page_title("<html><head><title>Hello World</title></head></html>") == "Hello World"

    def test_normalizes_whitespace(self):
        assert ss.extract_page_title("<title>\n  Hello\n  World  </title>") == "Hello World"

    def test_no_title_returns_none(self):
        assert ss.extract_page_title("<html><body>hi</body></html>") is None

    def test_empty_body_returns_none(self):
        assert ss.extract_page_title(None) is None
        assert ss.extract_page_title("") is None


# ---------------------------------------------------------------------------
# sanitize_path_component / build_screenshot_paths
# ---------------------------------------------------------------------------

class TestSanitizePathComponent:
    def test_lowercases_and_keeps_safe_chars(self):
        assert ss.sanitize_path_component("API.Example.COM") == "api.example.com"

    def test_replaces_unsafe_chars(self):
        assert ss.sanitize_path_component("weird/host name!") == "weird_host_name"

    def test_empty_falls_back(self):
        assert ss.sanitize_path_component("", fallback="unknown") == "unknown"
        assert ss.sanitize_path_component("///", fallback="unknown") == "unknown"


class TestBuildScreenshotPaths:
    def test_organizes_by_subdomain(self):
        paths = ss.build_screenshot_paths("output", "https://admin.example.com/dashboard")
        assert paths["subdomain"] == "admin.example.com"
        assert paths["directory"] == os.path.join("output", "screenshots", "admin.example.com")
        assert paths["relative_path"].startswith(os.path.join("screenshots", "admin.example.com"))

    def test_non_default_port_gets_suffix(self):
        paths = ss.build_screenshot_paths("output", "http://example.com:8080/")
        assert paths["subdomain"] == "example.com_8080"

    def test_default_ports_no_suffix(self):
        assert ss.build_screenshot_paths("output", "http://example.com:80/")["subdomain"] == "example.com"
        assert ss.build_screenshot_paths("output", "https://example.com:443/")["subdomain"] == "example.com"

    def test_deterministic_filename_by_default(self):
        p1 = ss.build_screenshot_paths("output", SAFE_URL)
        p2 = ss.build_screenshot_paths("output", SAFE_URL)
        assert p1["filename"] == p2["filename"]

    def test_unique_filenames_include_timestamp(self):
        with mock.patch("time.time", return_value=1234567890.0):
            paths = ss.build_screenshot_paths("output", SAFE_URL, unique_filenames=True)
        assert paths["filename"].endswith("_1234567890.png")

    def test_unique_filenames_differ_across_calls(self):
        with mock.patch("time.time", return_value=1000.0):
            p1 = ss.build_screenshot_paths("output", SAFE_URL, unique_filenames=True)
        with mock.patch("time.time", return_value=2000.0):
            p2 = ss.build_screenshot_paths("output", SAFE_URL, unique_filenames=True)
        assert p1["filename"] != p2["filename"]

    def test_root_path_uses_root_placeholder(self):
        paths = ss.build_screenshot_paths("output", "https://example.com/")
        assert paths["filename"].startswith("root_")

    def test_different_urls_hash_differently(self):
        p1 = ss.build_screenshot_paths("output", "https://example.com/login")
        p2 = ss.build_screenshot_paths("output", "https://example.com/admin")
        assert p1["filename"] != p2["filename"]


# ---------------------------------------------------------------------------
# locate_browser_binary
# ---------------------------------------------------------------------------

class TestLocateBrowserBinary:
    def test_finds_first_candidate_on_path(self):
        with mock.patch("shutil.which", side_effect=lambda name: "/usr/bin/chromium" if name == "chromium" else None):
            assert ss.locate_browser_binary() == "/usr/bin/chromium"

    def test_returns_none_when_nothing_found(self):
        with mock.patch("shutil.which", return_value=None):
            assert ss.locate_browser_binary() is None

    def test_explicit_path_used_when_valid(self, tmp_path):
        binary = tmp_path / "fake-chrome"
        binary.write_text("#!/bin/sh\n")
        os.chmod(binary, 0o755)
        assert ss.locate_browser_binary(explicit_path=str(binary)) == str(binary)

    def test_explicit_path_rejected_when_not_executable(self, tmp_path):
        binary = tmp_path / "not-executable"
        binary.write_text("nope")
        assert ss.locate_browser_binary(explicit_path=str(binary)) is None

    def test_explicit_path_rejected_when_missing(self):
        assert ss.locate_browser_binary(explicit_path="/no/such/binary") is None


# ---------------------------------------------------------------------------
# capture_screenshot
# ---------------------------------------------------------------------------

class TestCaptureScreenshot:
    def test_rejects_non_http_scheme(self, tmp_path):
        result = ss.capture_screenshot(
            "file:///etc/passwd", str(tmp_path / "out.png"), binary_path="/usr/bin/chromium",
        )
        assert result["status"] == "error"
        assert "non-http" in result["error"]

    def test_successful_capture(self, tmp_path):
        output_path = str(tmp_path / "shots" / "out.png")

        def fake_run(argv, capture_output, text, timeout):
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(b"\x89PNG\r\n\x1a\nfakepngbytes")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            result = ss.capture_screenshot(SAFE_URL, output_path, binary_path="/usr/bin/chromium", no_sandbox=False)
        assert result["status"] == "captured"
        assert result["byte_length"] > 0
        assert os.path.isfile(output_path)

    def test_no_file_produced_is_error(self, tmp_path):
        output_path = str(tmp_path / "out.png")
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")):
            result = ss.capture_screenshot(SAFE_URL, output_path, binary_path="/usr/bin/chromium", no_sandbox=False)
        assert result["status"] == "error"
        assert "no screenshot file" in result["error"]

    def test_timeout_handled(self, tmp_path):
        output_path = str(tmp_path / "out.png")
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="chromium", timeout=5)):
            result = ss.capture_screenshot(SAFE_URL, output_path, binary_path="/usr/bin/chromium", timeout=5, no_sandbox=False)
        assert result["status"] == "timeout"

    def test_launch_failure_handled(self, tmp_path):
        output_path = str(tmp_path / "out.png")
        with mock.patch("subprocess.run", side_effect=OSError("no such file or directory")):
            result = ss.capture_screenshot(SAFE_URL, output_path, binary_path="/nonexistent/chromium", no_sandbox=False)
        assert result["status"] == "error"
        assert "failed to launch" in result["error"]

    def test_no_sandbox_flag_included_when_true(self, tmp_path):
        output_path = str(tmp_path / "out.png")
        captured_argv = {}

        def fake_run(argv, capture_output, text, timeout):
            captured_argv["argv"] = argv
            with open(output_path, "wb") as f:
                f.write(b"data")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            ss.capture_screenshot(SAFE_URL, output_path, binary_path="/usr/bin/chromium", no_sandbox=True)
        assert "--no-sandbox" in captured_argv["argv"]

    def test_no_shell_true_used(self, tmp_path):
        # subprocess.run must always be called with an argv list, never shell=True
        # (module docstring, implementation decision #5 — no shell injection surface).
        output_path = str(tmp_path / "out.png")
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")) as m:
            ss.capture_screenshot(SAFE_URL, output_path, binary_path="/usr/bin/chromium", no_sandbox=False)
        args, kwargs = m.call_args
        assert isinstance(args[0], list)
        assert "shell" not in kwargs


# ---------------------------------------------------------------------------
# classify_visual_triage
# ---------------------------------------------------------------------------

class TestClassifyVisualTriage:
    def test_login_page_password_field(self):
        body = '<html><body><form><input type="password" name="password"><button>Sign in</button></form></body></html>'
        result = ss.classify_visual_triage(body, "https://example.com/login", "Login")
        categories = {c["category"] for c in result}
        assert ss.TRIAGE_LOGIN_PAGE in categories
        login = next(c for c in result if c["category"] == ss.TRIAGE_LOGIN_PAGE)
        assert login["confidence"] == ss.CONFIDENCE_HIGH

    def test_admin_panel_detected(self):
        body = "<html><body><h1>Admin Panel</h1><div>Dashboard</div></body></html>"
        result = ss.classify_visual_triage(body, "https://example.com/admin", "Admin Dashboard")
        categories = {c["category"] for c in result}
        assert ss.TRIAGE_ADMIN_PANEL in categories

    def test_default_nginx_page(self):
        body = "<html><body><h1>Welcome to nginx!</h1></body></html>"
        result = ss.classify_visual_triage(body, "https://example.com/", "Welcome to nginx!")
        categories = {c["category"] for c in result}
        assert ss.TRIAGE_DEFAULT_PLACEHOLDER in categories
        default = next(c for c in result if c["category"] == ss.TRIAGE_DEFAULT_PLACEHOLDER)
        assert default["confidence"] == ss.CONFIDENCE_HIGH

    def test_apache_default_page(self):
        body = "<html><body>Apache2 Ubuntu Default Page: It works</body></html>"
        result = ss.classify_visual_triage(body, "https://example.com/", None)
        assert any(c["category"] == ss.TRIAGE_DEFAULT_PLACEHOLDER for c in result)

    def test_ordinary_page_no_matches(self):
        body = "<html><body><h1>Our Products</h1><p>Buy things here.</p></body></html>"
        result = ss.classify_visual_triage(body, "https://example.com/products", "Our Products")
        assert result == []

    def test_url_path_alone_gives_weak_login_signal(self):
        body = "<html><body>Nothing special here</body></html>"
        result = ss.classify_visual_triage(body, "https://example.com/login", None)
        login = next((c for c in result if c["category"] == ss.TRIAGE_LOGIN_PAGE), None)
        assert login is not None
        assert login["confidence"] == ss.CONFIDENCE_LOW

    def test_multiple_categories_can_match_same_page(self):
        body = (
            '<html><head><title>Admin Login</title></head><body>'
            '<h1>Admin Panel</h1><form><input type="password" name="password">'
            '<button>Sign in</button></form></body></html>'
        )
        result = ss.classify_visual_triage(body, "https://example.com/admin/login", "Admin Login")
        categories = {c["category"] for c in result}
        assert ss.TRIAGE_LOGIN_PAGE in categories
        assert ss.TRIAGE_ADMIN_PANEL in categories

    def test_empty_body_no_crash(self):
        assert ss.classify_visual_triage(None, "https://example.com/", None) == []

    def test_result_is_json_serializable(self):
        body = '<input type="password">'
        result = ss.classify_visual_triage(body, "https://example.com/login", "Login")
        json.dumps(result)


# ---------------------------------------------------------------------------
# run_screenshot (full single-target orchestration, network + subprocess mocked)
# ---------------------------------------------------------------------------

class TestRunScreenshot:
    def _mock_capture_success(self, monkeypatch, output_dir):
        def fake_capture(url, output_path, binary_path, **kwargs):
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(b"fakepng")
            return {
                "status": "captured", "output_path": output_path, "command": [],
                "returncode": 0, "stderr_tail": "", "duration_seconds": 0.5,
                "byte_length": 7, "error": None,
            }
        monkeypatch.setattr(ss, "capture_screenshot", fake_capture)
        monkeypatch.setattr(ss, "locate_browser_binary", lambda **kw: "/usr/bin/chromium")

    def test_successful_capture_persists_finding(self, tmp_path, monkeypatch):
        output_dir = str(tmp_path / "output")
        self._mock_capture_success(monkeypatch, output_dir)
        resp = _fake_response(status_code=200, body=b"<html><head><title>Home</title></head></html>")
        with mock.patch("requests.get", return_value=resp):
            result = ss.run_screenshot(SAFE_URL, target=SAFE_TARGET, output_dir=output_dir)

        assert result["status"] == "captured"
        assert result["screenshot_path"] is not None
        assert result["errors"] == []
        json.dumps(result)

        store = ss.PendingAssetsStore(output_dir=output_dir)
        records = store.all()
        assert len(records) == 1
        assert records[0]["type"] == "screenshot_captured"
        assert records[0]["value"]["url"] == SAFE_URL
        json.dumps(records[0])

    def test_unreachable_target_no_capture_attempted(self, tmp_path, monkeypatch):
        output_dir = str(tmp_path / "output")
        capture_spy = mock.MagicMock()
        monkeypatch.setattr(ss, "capture_screenshot", capture_spy)
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = ss.run_screenshot(SAFE_URL, target=SAFE_TARGET, output_dir=output_dir)

        assert result["status"] == "unreachable"
        assert result["errors"][0]["stage"] == "precheck"
        capture_spy.assert_not_called()
        store = ss.PendingAssetsStore(output_dir=output_dir)
        assert store.all() == []

    def test_browser_unavailable(self, tmp_path, monkeypatch):
        output_dir = str(tmp_path / "output")
        monkeypatch.setattr(ss, "locate_browser_binary", lambda **kw: None)
        resp = _fake_response(status_code=200, body=b"<html></html>")
        with mock.patch("requests.get", return_value=resp):
            result = ss.run_screenshot(SAFE_URL, target=SAFE_TARGET, output_dir=output_dir)

        assert result["status"] == "browser_unavailable"
        assert result["errors"][0]["stage"] == "locate_binary"
        store = ss.PendingAssetsStore(output_dir=output_dir)
        assert store.all() == []

    def test_capture_failure_recorded_not_persisted(self, tmp_path, monkeypatch):
        output_dir = str(tmp_path / "output")
        monkeypatch.setattr(ss, "locate_browser_binary", lambda **kw: "/usr/bin/chromium")
        monkeypatch.setattr(ss, "capture_screenshot", lambda *a, **kw: {
            "status": "timeout", "error": "screenshot capture timed out after 25.0s",
            "returncode": None, "stderr_tail": None, "byte_length": 0,
        })
        resp = _fake_response(status_code=200, body=b"<html></html>")
        with mock.patch("requests.get", return_value=resp):
            result = ss.run_screenshot(SAFE_URL, target=SAFE_TARGET, output_dir=output_dir)

        assert result["status"] == "capture_failed"
        assert result["errors"][0]["stage"] == "capture"
        store = ss.PendingAssetsStore(output_dir=output_dir)
        assert store.all() == []

    def test_non_2xx_response_still_captured(self, tmp_path, monkeypatch):
        # A reached-but-erroring response (e.g. 404/500) is still worth a
        # screenshot for triage purposes — see module docstring decision #2.
        output_dir = str(tmp_path / "output")
        self._mock_capture_success(monkeypatch, output_dir)
        resp = _fake_response(status_code=404, body=b"<html>not found</html>")
        with mock.patch("requests.get", return_value=resp):
            result = ss.run_screenshot(SAFE_URL, target=SAFE_TARGET, output_dir=output_dir)
        assert result["status"] == "captured"
        assert result["status_code"] == 404

    def test_scope_error_propagates(self, tmp_path):
        with pytest.raises(ss.ScopeError):
            ss.run_screenshot("https://evil.com/", target=SAFE_TARGET, output_dir=str(tmp_path / "output"))

    def test_triage_disabled(self, tmp_path, monkeypatch):
        output_dir = str(tmp_path / "output")
        self._mock_capture_success(monkeypatch, output_dir)
        resp = _fake_response(status_code=200, body=b'<input type="password">')
        with mock.patch("requests.get", return_value=resp):
            result = ss.run_screenshot(SAFE_URL, target=SAFE_TARGET, output_dir=output_dir, classify=False)
        assert result["triage"] == []


# ---------------------------------------------------------------------------
# run_screenshot_batch
# ---------------------------------------------------------------------------

class TestRunScreenshotBatch:
    def test_mixed_results_grouped_by_subdomain(self, tmp_path, monkeypatch):
        output_dir = str(tmp_path / "output")

        def fake_run_screenshot(url, target=None, output_dir=None, **kwargs):
            if "fails" in url:
                return {"url": url, "target": target, "module": ss.MODULE_NAME, "status": "unreachable",
                        "subdomain": "a.example.com", "screenshot_path": None, "status_code": None,
                        "page_title": None, "triage": [], "errors": [{"stage": "precheck", "error": "x"}]}
            return {"url": url, "target": target, "module": ss.MODULE_NAME, "status": "captured",
                    "subdomain": "b.example.com", "screenshot_path": "screenshots/b.example.com/root.png",
                    "status_code": 200, "page_title": "Home", "triage": [], "errors": []}

        monkeypatch.setattr(ss, "run_screenshot", fake_run_screenshot)
        urls = ["https://a.example.com/fails", "https://b.example.com/", "https://b.example.com/login"]
        result = ss.run_screenshot_batch(urls, target=SAFE_TARGET, output_dir=output_dir)

        assert result["total"] == 3
        assert result["counts"]["captured"] == 2
        assert result["counts"]["unreachable"] == 1
        assert len(result["by_subdomain"]["a.example.com"]) == 1
        assert len(result["by_subdomain"]["b.example.com"]) == 2
        json.dumps(result)

    def test_scope_error_isolated_per_url(self, tmp_path, monkeypatch):
        output_dir = str(tmp_path / "output")

        def fake_run_screenshot(url, target=None, output_dir=None, **kwargs):
            if "evil" in url:
                raise ss.ScopeError("out of scope")
            return {"url": url, "target": target, "module": ss.MODULE_NAME, "status": "captured",
                    "subdomain": "example.com", "screenshot_path": "p.png", "status_code": 200,
                    "page_title": None, "triage": [], "errors": []}

        monkeypatch.setattr(ss, "run_screenshot", fake_run_screenshot)
        urls = ["https://evil.com/", "https://example.com/"]
        result = ss.run_screenshot_batch(urls, target=SAFE_TARGET, output_dir=output_dir)

        assert result["counts"]["scope_rejected"] == 1
        assert result["counts"]["captured"] == 1

    def test_unexpected_exception_does_not_abort_batch(self, tmp_path, monkeypatch):
        output_dir = str(tmp_path / "output")
        calls = []

        def fake_run_screenshot(url, target=None, output_dir=None, **kwargs):
            calls.append(url)
            if "boom" in url:
                raise RuntimeError("kaboom")
            return {"url": url, "target": target, "module": ss.MODULE_NAME, "status": "captured",
                    "subdomain": "example.com", "screenshot_path": "p.png", "status_code": 200,
                    "page_title": None, "triage": [], "errors": []}

        monkeypatch.setattr(ss, "run_screenshot", fake_run_screenshot)
        urls = ["https://example.com/boom", "https://example.com/fine"]
        result = ss.run_screenshot_batch(urls, target=SAFE_TARGET, output_dir=output_dir)

        assert calls == urls
        assert result["counts"]["unexpected_error"] == 1
        assert result["counts"]["captured"] == 1

    def test_empty_url_list(self, tmp_path):
        result = ss.run_screenshot_batch([], target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert result["total"] == 0
        assert result["results"] == []
