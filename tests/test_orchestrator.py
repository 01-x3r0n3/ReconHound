"""
Tests for reconhound/core/orchestrator.py (ReconHound Module 22 — core
adaptive execution coordination).

Run with:  ./.venv/bin/python -m pytest tests/test_orchestrator.py -v

No network access anywhere in this file. Every producer module's run_*
entry point is replaced by a fake that writes the *real* finding shapes its
module emits (built with that module's own make_finding()) into the real
`output/pending_assets.json` via that module's real PendingAssetsStore, and
returns a summary in the real shape. The orchestrator therefore runs against
genuine producer structures, the real SurfaceMapper, and the real RiskEngine
— only the network I/O is removed.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound.core import orchestrator as orch
from reconhound import active_recon
from reconhound import code_leak
from reconhound import crawler
from reconhound import endpoint_discovery
from reconhound import exposure_scan
from reconhound import http_analyzer
from reconhound import js_analyzer
from reconhound import passive_recon
from reconhound import surface_mapper
from reconhound import tech_fingerprint
from reconhound import vhost_scanner
from reconhound import vuln_intel

TARGET = "example.com"
IP = "203.0.113.10"

# context.md §10 item 22 / §11 place this module at core/orchestrator.py.
ORCHESTRATOR_SOURCE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reconhound", "core", "orchestrator.py")


# ---------------------------------------------------------------------------
# Fake producers — real finding shapes, real stores, no network
# ---------------------------------------------------------------------------


def _store(module, output_dir):
    return module.PendingAssetsStore(output_dir=output_dir)


class Recorder:
    """Records which module ran against which subject, in order."""

    def __init__(self):
        self.calls = []

    def log(self, module, subject):
        self.calls.append((module, subject))

    def modules(self):
        return [m for m, _ in self.calls]

    def subjects_for(self, module):
        return [s for m, s in self.calls if m == module]


@pytest.fixture
def rec():
    return Recorder()


@pytest.fixture
def outdir(tmp_path):
    return str(tmp_path / "output")


def install_fakes(monkeypatch, rec, *, failing=(), empty=(), malformed=(),
                  raising_scope=(), interrupt_at=None):
    """
    Replace every producer entry point with a no-network fake.

    `failing`      -> modules that raise a generic exception
    `empty`        -> modules that persist nothing and return an empty summary
    `malformed`    -> modules that persist structurally invalid records
    `raising_scope`-> modules that raise their own ScopeError
    `interrupt_at` -> module name that raises KeyboardInterrupt
    """

    def guard(name):
        if name == interrupt_at:
            raise KeyboardInterrupt()
        if name in failing:
            raise RuntimeError(f"{name} exploded")
        if name in raising_scope:
            raise _scope_error_for(name)

    # -- passive ------------------------------------------------------

    def fake_passive_recon(target, output_dir="output", timeout=5.0, enable_asn=True):
        rec.log("passive_recon", target)
        guard("passive_recon")
        store = _store(passive_recon, output_dir)
        if "passive_recon" in empty:
            return {"target": target, "module": "passive_recon.py", "dns": {}, "errors": []}
        if "passive_recon" in malformed:
            store.add({"not_a_finding": True})
            store.add("a bare string")
            return {"target": target, "module": "passive_recon.py", "errors": []}
        store.add(passive_recon.make_finding(
            "dns_record", target, {"record_type": "A", "records": [IP]},
            [f"A record for {target}"], passive_recon.CONFIDENCE_HIGH))
        store.add(passive_recon.make_finding(
            "dns_record", f"www.{TARGET}", {"record_type": "A", "records": [IP]},
            [f"A record for www.{TARGET}"], passive_recon.CONFIDENCE_HIGH))
        # passive_recon.py emits tls_san with the bare SAN hostname as `value`.
        store.add(passive_recon.make_finding(
            "tls_san", target, f"api.{TARGET}",
            [f"Certificate SAN entry from {target}:443 leaf certificate"],
            passive_recon.CONFIDENCE_HIGH,
            metadata={"port": 443, "in_scope": True}))
        # An out-of-scope SAN: recorded, but must never become a scan target.
        store.add(passive_recon.make_finding(
            "tls_san", target, "cdn.thirdparty.net",
            [f"Certificate SAN entry from {target}:443 leaf certificate"],
            passive_recon.CONFIDENCE_MEDIUM,
            metadata={"port": 443, "in_scope": False}))
        return {
            "target": target, "module": "passive_recon.py",
            "dns": {"A": {"records": [IP]}}, "whois": {}, "tls_certificate": {},
            "asn": [], "email_security": {}, "organization": {}, "errors": [],
        }

    def fake_passive_intel(target, output_dir="output", seed_ips=None, timeout=8.0, **kw):
        rec.log("passive_intel", tuple(seed_ips or ()))
        guard("passive_intel")
        return {"target": target, "module": "passive_intel.py", "seed_ips": list(seed_ips or []),
                "source_status": {}, "hosts": [], "stats": {}, "errors": []}

    def fake_code_leak(target, output_dir="output", timeout=8.0, **kw):
        rec.log("code_leak", target)
        guard("code_leak")
        store = _store(code_leak, output_dir)
        store.add(code_leak.make_finding(
            "code_leak_exposure", target,
            {"category": "api_key", "repository": "acme/www", "path": "config.py"},
            ["hardcoded key in public repo"], code_leak.CONFIDENCE_MEDIUM))
        return {"target": target, "module": "code_leak.py", "repositories": [],
                "findings": [], "source_status": {}, "stats": {}, "errors": []}

    def fake_osint(target, output_dir="output", seed_ip=None, timeout=8.0, **kw):
        rec.log("osint_engine", seed_ip)
        guard("osint_engine")
        return {"target": target, "module": "osint_engine.py", "emails": [],
                "source_status": {}, "stats": {}, "errors": []}

    def fake_wayback(target, output_dir="output", timeout=8.0, **kw):
        rec.log("wayback_intel", target)
        guard("wayback_intel")
        return {
            "target": target, "module": "wayback_intel.py",
            "historical_urls": [f"https://{target}/old"],
            "historical_data": [{"url": f"https://{target}/old", "parameters": ["id"]}],
            "cdx_query": {}, "stats": {}, "errors": [],
        }

    # -- active network -----------------------------------------------

    def fake_active_recon(ip, target=None, tcp_ports=None, output_dir="output",
                          timeout=2.0, max_workers=20, **kw):
        rec.log("active_recon", ip)
        guard("active_recon")
        store = _store(active_recon, output_dir)
        for port in (80, 443):
            store.add(active_recon.make_finding(
                "open_tcp_port", ip, {"ip": ip, "port": port, "protocol": "tcp"},
                [f"TCP connect to {ip}:{port} succeeded"], active_recon.CONFIDENCE_HIGH))
        store.add(active_recon.make_finding(
            "banner", ip, {"ip": ip, "port": 22, "protocol": "tcp", "banner": "OpenSSH_8.4p1"},
            ["banner grabbed"], active_recon.CONFIDENCE_MEDIUM))
        return {"ip": ip, "target": target, "module": "active_recon.py",
                "tcp": {"open_ports": [80, 443]}, "udp": {}, "errors": []}

    def fake_ssl(host, port=443, target=None, output_dir="output", timeout=8.0, **kw):
        rec.log("ssl_analyzer", f"{host}:{port}")
        guard("ssl_analyzer")
        return {"host": host, "port": port, "target": target, "module": "ssl_analyzer.py",
                "status": "found", "discovered_hostnames": [], "errors": []}

    def fake_vhost(ip, target, output_dir="output", timeout=8.0, **kw):
        rec.log("vhost_scanner", ip)
        guard("vhost_scanner")
        store = _store(vhost_scanner, output_dir)
        store.add(vhost_scanner.make_finding(
            "vhost_discovered", target,
            {"ip": ip, "hostname": f"internal.{target}", "port": 80,
             "connect_url": f"http://{ip}:80/", "scheme": "http"},
            ["Host-header probe returned a distinct application"],
            vhost_scanner.CONFIDENCE_HIGH))
        return {"ip": ip, "target": target, "module": "vhost_scanner.py",
                "port_results": [], "vhost_summary": {}, "status": "completed", "errors": []}

    # -- active web ---------------------------------------------------

    def fake_http(url, target=None, output_dir="output", timeout=8.0, **kw):
        rec.log("http_analyzer", url)
        guard("http_analyzer")
        store = _store(http_analyzer, output_dir)
        store.add(http_analyzer.make_finding(
            "security_headers", target or url,
            {"missing": ["Strict-Transport-Security"], "present": {}},
            ["HSTS absent"], http_analyzer.CONFIDENCE_HIGH, metadata={"url": url}))
        return {"url": url, "target": target, "module": "http_analyzer.py",
                "fetch_status": "found", "security_headers": {}, "cookies": [], "errors": []}

    def fake_tech(url, target=None, output_dir="output", timeout=8.0, **kw):
        rec.log("tech_fingerprint", url)
        guard("tech_fingerprint")
        store = _store(tech_fingerprint, output_dir)
        store.add(tech_fingerprint.make_finding(
            "tech_fingerprint_detected", target or url,
            {"technology": "WordPress", "category": "cms", "version": "6.4.1", "url": url},
            ["/wp-login.php returned 200"], tech_fingerprint.CONFIDENCE_HIGH))
        store.add(tech_fingerprint.make_finding(
            "tech_fingerprint_detected", target or url,
            {"technology": "nginx", "category": "server", "version": "1.18.0", "url": url},
            ["Server header"], tech_fingerprint.CONFIDENCE_HIGH))
        return {
            "url": url, "target": target, "module": "tech_fingerprint.py",
            "fetch_status": "found",
            "technology_summary": {
                "cms": ["WordPress"], "frameworks": [], "servers": ["nginx"], "wafs": [],
                "detections": [
                    {"technology": "WordPress", "category": "cms", "version": "6.4.1",
                     "confidence": "HIGH", "evidence": ["/wp-login.php"]},
                    {"technology": "nginx", "category": "server", "version": "1.18.0",
                     "confidence": "HIGH", "evidence": ["Server header"]},
                ],
            },
            "recommended_next_actions": [], "errors": [],
        }

    def fake_crawler(url, target=None, output_dir="output", timeout=8.0, max_workers=10, **kw):
        rec.log("crawler", url)
        guard("crawler")
        store = _store(crawler, output_dir)
        page = f"{url.rstrip('/')}/about"
        store.add(crawler.make_finding(
            finding_type="crawled_url", target=target or url,
            value={"url": page, "status_code": 200, "method": "GET", "depth": 1},
            evidence=[f"GET {page} returned HTTP 200"], confidence=crawler.CONFIDENCE_HIGH))
        js_url = f"{url.rstrip('/')}/static/app.js"
        store.add(crawler.make_finding(
            finding_type="javascript_reference", target=target or url,
            value={"url": js_url, "source_page": page, "in_scope": True, "fetched": False},
            evidence=[f"<script src> on {page}"], confidence=crawler.CONFIDENCE_HIGH,
            metadata={"source_page": page, "for_module": "js_analyzer.py"}))
        # An out-of-scope script reference must never be handed to js_analyzer.
        store.add(crawler.make_finding(
            finding_type="javascript_reference", target=target or url,
            value={"url": "https://cdn.thirdparty.net/t.js", "source_page": page,
                   "in_scope": False, "fetched": False},
            evidence=[f"<script src> on {page}"], confidence=crawler.CONFIDENCE_HIGH,
            metadata={"source_page": page, "for_module": "js_analyzer.py"}))
        return {"target": target, "module": "crawler.py", "base_url": url,
                "pages": [{"url": page, "status_code": 200}], "parameters": [],
                "requests_made": 2, "errors": []}

    def fake_js(js_files, target=None, output_dir="output", timeout=10.0, **kw):
        rec.log("js_analyzer", tuple(js_files))
        guard("js_analyzer")
        store = _store(js_analyzer, output_dir)
        for ref in js_files:
            url = ref if isinstance(ref, str) else ref.get("url")
            store.add(js_analyzer.make_js_finding(
                "js_analyzer_endpoint_reference", target or url,
                {"url": f"https://{target}/api/v1/users", "js_url": url},
                [f"string literal in {url}"], js_analyzer.CONFIDENCE_MEDIUM,
                parent_js_url=url))
        return {"module": "js_analyzer.py", "target": target,
                "files_requested": len(js_files), "files_analyzed": len(js_files),
                "files_skipped_out_of_scope": 0, "files_failed": 0, "results": [],
                "js_data_for_endpoint_discovery": [
                    {"url": f"https://{target}/api/v1/users", "parameters": ["id"]}],
                "websocket_endpoints": [], "errors": []}

    captured_endpoint_kwargs = {}

    def fake_endpoint(base_url, target=None, output_dir="output", technology=None,
                      historical_data=None, js_data=None, timeout=8.0, **kw):
        rec.log("endpoint_discovery", base_url)
        captured_endpoint_kwargs[base_url] = {
            "technology": technology, "historical_data": historical_data, "js_data": js_data,
            "endpoints": kw.get("endpoints"),
        }
        guard("endpoint_discovery")
        store = _store(endpoint_discovery, output_dir)
        found = f"{base_url.rstrip('/')}/wp-admin/"
        store.add(endpoint_discovery.make_finding(
            "endpoint_discovered", target or base_url,
            {"url": found, "status_code": 200, "method": "GET", "category": "admin"},
            [f"GET {found} returned 200"], endpoint_discovery.CONFIDENCE_HIGH))
        return {"target": target, "module": "endpoint_discovery.py", "base_url": base_url,
                "endpoints": [{"url": found}], "parameters": [], "errors": []}

    def fake_api(base_url, target=None, output_dir="output", timeout=8.0, **kw):
        rec.log("api_recon", base_url)
        guard("api_recon")
        return {"target": target, "module": "api_recon.py", "base_url": base_url,
                "versions": {}, "specifications": {}, "graphql": {}, "errors": []}

    captured_exposure_kwargs = {}

    def fake_exposure(base_url, target=None, output_dir="output", endpoints=None,
                      timeout=8.0, **kw):
        rec.log("exposure_scan", base_url)
        captured_exposure_kwargs[base_url] = {"endpoints": endpoints}
        guard("exposure_scan")
        store = _store(exposure_scan, output_dir)
        store.add(exposure_scan.make_finding(
            "exposure_finding", target or base_url,
            {"category": "vcs_exposure", "url": f"{base_url.rstrip('/')}/.git/config",
             "status_code": 200},
            ["/.git/config is readable"], exposure_scan.CONFIDENCE_HIGH))
        return {"target": target, "module": "exposure_scan.py", "base_url": base_url,
                "sensitive_resources": {}, "errors": []}

    captured_supply_kwargs = {}

    def fake_supply(pages=None, subdomains=None, target=None, output_dir="output",
                    timeout=10.0, **kw):
        rec.log("supply_chain", (tuple(pages or ()), tuple(subdomains or ())))
        captured_supply_kwargs["pages"] = list(pages or [])
        captured_supply_kwargs["subdomains"] = list(subdomains or [])
        guard("supply_chain")
        return {"module": "supply_chain.py", "target": target,
                "pages_requested": len(pages or []), "pages_analyzed": len(pages or []),
                "subdomains_requested": len(subdomains or []), "page_results": [],
                "subdomain_results": [], "errors": []}

    captured_vuln_kwargs = {}

    def fake_vuln(output_dir="output", technology_observations=None, timeout=8.0, **kw):
        rec.log("vuln_intel", tuple(
            (o.get("technology"), o.get("version")) for o in (technology_observations or [])))
        captured_vuln_kwargs["observations"] = list(technology_observations or [])
        guard("vuln_intel")
        store = _store(vuln_intel, output_dir)
        for obs in (technology_observations or []):
            store.add(vuln_intel.make_finding(
                "vulnerability_intelligence", obs.get("target") or TARGET,
                {"technology": obs["technology"], "version": obs.get("version"),
                 "cve_id": "CVE-2021-23017", "cvss_severity": "HIGH",
                 "summary": "possible match", "confirmed": False},
                [f"{obs['technology']} {obs.get('version')} MAY be affected"],
                vuln_intel.CONFIDENCE_MEDIUM))
        return {"module": "vuln_intel.py", "results": [], "stats": {}, "errors": []}

    monkeypatch.setattr(orch.passive_recon, "run_passive_recon", fake_passive_recon)
    monkeypatch.setattr(orch.passive_intel, "run_passive_intel", fake_passive_intel)
    monkeypatch.setattr(orch.code_leak, "run_code_leak", fake_code_leak)
    monkeypatch.setattr(orch.osint_engine, "run_osint_engine", fake_osint)
    monkeypatch.setattr(orch.wayback_intel, "run_wayback_intel", fake_wayback)
    monkeypatch.setattr(orch.active_recon, "run_active_recon", fake_active_recon)
    monkeypatch.setattr(orch.ssl_analyzer, "run_ssl_analysis", fake_ssl)
    monkeypatch.setattr(orch.vhost_scanner, "run_vhost_scan", fake_vhost)
    monkeypatch.setattr(orch.http_analyzer, "run_http_analysis", fake_http)
    monkeypatch.setattr(orch.tech_fingerprint, "run_tech_fingerprint", fake_tech)
    monkeypatch.setattr(orch.crawler, "run_crawler", fake_crawler)
    monkeypatch.setattr(orch.js_analyzer, "run_js_analyzer", fake_js)
    monkeypatch.setattr(orch.endpoint_discovery, "run_endpoint_discovery", fake_endpoint)
    monkeypatch.setattr(orch.api_recon, "run_api_recon", fake_api)
    monkeypatch.setattr(orch.exposure_scan, "run_exposure_scan", fake_exposure)
    monkeypatch.setattr(orch.supply_chain, "run_supply_chain_analysis", fake_supply)
    monkeypatch.setattr(orch.vuln_intel, "run_vuln_intel", fake_vuln)

    return {
        "endpoint_kwargs": captured_endpoint_kwargs,
        "exposure_kwargs": captured_exposure_kwargs,
        "supply_kwargs": captured_supply_kwargs,
        "vuln_kwargs": captured_vuln_kwargs,
    }


def _scope_error_for(name):
    module = {
        "passive_recon": passive_recon, "active_recon": active_recon,
        "http_analyzer": http_analyzer, "crawler": crawler,
        "tech_fingerprint": tech_fingerprint, "js_analyzer": js_analyzer,
    }[name]
    return module.ScopeError(f"{name} refused an out-of-scope subject")


# ===========================================================================
# Configuration and scope validation
# ===========================================================================


class TestConfiguration:
    def test_rejects_url_as_target(self, outdir):
        with pytest.raises(orch.ScopeViolationError):
            orch.Orchestrator(target="https://example.com/x", output_dir=outdir)

    def test_rejects_ip_as_target(self, outdir):
        with pytest.raises(orch.ScopeViolationError):
            orch.Orchestrator(target="203.0.113.10", output_dir=outdir)

    def test_rejects_wildcard_target(self, outdir):
        with pytest.raises(orch.ScopeViolationError):
            orch.Orchestrator(target="*.example.com", output_dir=outdir)

    def test_rejects_empty_target(self, outdir):
        with pytest.raises((orch.ScopeViolationError, orch.ConfigurationError)):
            orch.Orchestrator(target="", output_dir=outdir)

    def test_rejects_unknown_mode(self, outdir):
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir, mode="turbo")

    def test_rejects_unknown_module(self, outdir):
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir,
                              mode=orch.MODE_MODULE, modules=["nmap"])

    def test_removed_screenshot_module_is_not_registered(self, outdir):
        # screenshot.py was removed from the architecture (context.md §18.1):
        # it must be gone from every module set, from the phase map, and from
        # the orchestrator's own namespace — not merely disabled.
        assert "screenshot" not in orch.ALL_MODULES
        assert "screenshot" not in orch.MODULE_PHASE
        assert "screenshot" not in orch.PHASE_MODULES[orch.PHASE_ACTIVE_WEB]
        assert not hasattr(orch, "screenshot")
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir,
                              mode=orch.MODE_MODULE, modules=["screenshot"])

    def test_removed_screenshot_budget_is_not_a_settable_limit(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        assert "max_screenshots" not in o.limits
        with pytest.raises(TypeError):
            orch.Orchestrator(target=TARGET, output_dir=outdir, max_screenshots=5)

    def test_module_mode_requires_a_module(self, outdir):
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir, mode=orch.MODE_MODULE)

    def test_module_names_accept_py_suffix(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir,
                              mode=orch.MODE_MODULE, modules=["js_analyzer.py"])
        assert o.selected_modules == ["js_analyzer"]

    def test_rejects_active_module_in_passive_mode(self, outdir):
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir,
                              mode=orch.MODE_PASSIVE, modules=["crawler"])

    def test_rejects_bad_numeric_settings(self, outdir):
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir, timeout=0)
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir, threads=0)
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir, max_web_targets=0)
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir, max_adaptive_rounds=-1)

    def test_rejects_invalid_min_severity(self, outdir):
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir, min_risk_severity="URGENT")

    def test_mode_module_sets(self, outdir):
        passive = orch.Orchestrator(target=TARGET, output_dir=outdir, mode=orch.MODE_PASSIVE)
        assert "crawler" not in passive.selected_modules
        assert "passive_recon" in passive.selected_modules
        # vuln_intel/risk_engine never touch the target, so they belong here.
        assert "vuln_intel" in passive.selected_modules
        assert "risk_engine" in passive.selected_modules

        active = orch.Orchestrator(target=TARGET, output_dir=outdir, mode=orch.MODE_ACTIVE)
        assert "passive_recon" not in active.selected_modules
        assert "crawler" in active.selected_modules


class TestPreflight:
    def test_corrupt_pending_assets_is_fatal_before_any_work(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "pending_assets.json"), "w") as f:
            f.write("{not json")
        with pytest.raises(orch.OrchestratorError) as exc:
            orch.Orchestrator(target=TARGET, output_dir=outdir)
        assert "pending_assets.json" in str(exc.value)

    def test_pending_assets_wrong_root_type_is_fatal(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "pending_assets.json"), "w") as f:
            json.dump({"a": 1}, f)
        with pytest.raises(orch.OrchestratorError):
            orch.Orchestrator(target=TARGET, output_dir=outdir)

    def test_corrupt_surface_graph_is_fatal_and_preserved(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        path = os.path.join(outdir, "surface_graph.json")
        with open(path, "w") as f:
            f.write("]]not json[[")
        with pytest.raises(orch.OrchestratorError):
            orch.Orchestrator(target=TARGET, output_dir=outdir)
        # The unreadable graph must not have been silently replaced.
        with open(path) as f:
            assert f.read() == "]]not json[["

    def test_empty_pending_assets_is_fine(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "pending_assets.json"), "w") as f:
            f.write("")
        orch.Orchestrator(target=TARGET, output_dir=outdir)


# ===========================================================================
# End-to-end orchestration
# ===========================================================================


class TestEndToEnd:
    def test_full_scan_runs_the_whole_pipeline(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        assert result["status"] == orch.RUN_COMPLETED
        assert result["target"] == TARGET
        assert result["mode"] == orch.MODE_FULL

        ran = rec.modules()
        for expected in ("passive_recon", "passive_intel", "code_leak", "osint_engine",
                         "wayback_intel", "active_recon", "ssl_analyzer", "vhost_scanner",
                         "http_analyzer", "tech_fingerprint", "crawler", "js_analyzer",
                         "endpoint_discovery", "api_recon", "exposure_scan",
                         "supply_chain", "vuln_intel"):
            assert expected in ran, f"{expected} never ran"

    def test_legacy_screenshot_findings_still_ingest_after_module_removal(
            self, monkeypatch, rec, outdir):
        """
        An output directory written before screenshot.py was removed
        (context.md §18.1) still holds `screenshot_captured` records in
        pending_assets.json. Resuming into that directory must correlate them
        through the generic finding handler rather than crashing or silently
        dropping them — persisted evidence is never discarded because its
        producing module is gone.
        """
        os.makedirs(outdir, exist_ok=True)
        legacy = [{
            "type": "screenshot_captured",
            "target": TARGET,
            "value": {"url": f"https://{TARGET}/login", "subdomain": TARGET,
                      "screenshot_path": f"screenshots/{TARGET}/login_abc123.png",
                      "status_code": 200, "page_title": "Login"},
            "evidence": [f"Headless browser navigation to https://{TARGET}/login returned HTTP 200"],
            "confidence": "HIGH",
            "source": "screenshot.py",
            "timestamp": "2026-09-01T00:00:00+00:00",
            "metadata": {"triage": [{"category": "login_page", "confidence": "HIGH",
                                     "evidence": ["response body matches password field"]}]},
        }]
        with open(os.path.join(outdir, "pending_assets.json"), "w", encoding="utf-8") as f:
            json.dump(legacy, f)

        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        assert result["status"] == orch.RUN_COMPLETED
        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        legacy_observations = [o for o in graph["observations"].values()
                               if o.get("type") == "screenshot_captured"]
        assert len(legacy_observations) == 1, "legacy evidence was dropped"
        assert legacy_observations[0]["source"] == "screenshot.py"
        # It was correlated onto a real asset, not left orphaned...
        assert any(a.get("asset_type") == surface_mapper.ASSET_FINDING
                   and isinstance(a.get("value"), dict)
                   and a["value"].get("finding_type") == "screenshot_captured"
                   for a in graph["assets"].values())
        # ...and no module was scheduled to produce more of them.
        assert "screenshot" not in rec.modules()

    def test_dependency_order_is_respected(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        ran = rec.modules()

        def first(name):
            return ran.index(name)

        # Passive precedes active; discovery precedes intelligence.
        assert first("passive_recon") < first("active_recon")
        assert first("active_recon") < first("http_analyzer")
        # tech_fingerprint feeds endpoint_discovery's wordlist selection.
        assert first("tech_fingerprint") < first("endpoint_discovery")
        # crawler produces the JS references js_analyzer consumes...
        assert first("crawler") < first("js_analyzer")
        # ...and js_analyzer produces the js_data endpoint_discovery consumes.
        assert first("js_analyzer") < first("endpoint_discovery")
        # vuln_intel is last before risk scoring.
        assert first("vuln_intel") == max(first(m) for m in set(ran))

    def test_producer_outputs_are_passed_through_real_interfaces(self, monkeypatch, rec, outdir):
        captured = install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)

        # wayback -> endpoint_discovery(historical_data=...)
        # js_analyzer -> endpoint_discovery(js_data=...)
        # tech_fingerprint -> endpoint_discovery(technology=...)
        assert captured["endpoint_kwargs"], "endpoint_discovery never ran"
        for kwargs in captured["endpoint_kwargs"].values():
            assert kwargs["historical_data"], "wayback historical_data not forwarded"
            assert kwargs["js_data"], "js_analyzer js_data not forwarded"
            assert kwargs["technology"], "tech_fingerprint summary not forwarded"
            # The forwarded technology dict must actually drive wordlist choice.
            selected = endpoint_discovery.select_wordlists_for_technology(kwargs["technology"])
            assert any(name == "wordpress_paths.txt" for name, _ in selected)

        # graph endpoints -> exposure_scan(endpoints=...)
        assert any(v["endpoints"] for v in captured["exposure_kwargs"].values())

        # tech versions from the graph -> vuln_intel(technology_observations=...)
        observed = {(o["technology"], o["version"]) for o in captured["vuln_kwargs"]["observations"]}
        assert ("nginx", "1.18.0") in observed
        assert ("WordPress", "6.4.1") in observed
        for obs in captured["vuln_kwargs"]["observations"]:
            assert vuln_intel.normalize_technology_observation(obs) is not None

    def test_seed_ips_reach_passive_intel_and_osint(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        # passive_recon ran first, so its A record is already correlated.
        assert rec.subjects_for("passive_intel") == [(IP,)]
        assert rec.subjects_for("osint_engine") == [IP]

    def test_surface_mapper_ingested_every_producer(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        summary = result["correlation"]["summary"]
        assert summary["observations"] > 0
        assert summary["assets"] > 0
        assert summary["relationships"] > 0

        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        sources = {o["source"] for o in graph["observations"].values()}
        for expected in ("passive_recon.py", "active_recon.py", "vhost_scanner.py",
                         "tech_fingerprint.py", "crawler.py", "endpoint_discovery.py",
                         "exposure_scan.py", "code_leak.py", "js_analyzer.py",
                         "vuln_intel.py", "http_analyzer.py"):
            assert expected in sources, f"{expected} output never reached the graph"

        # Every execution's ingestion count is accounted for.
        ingested = sum(e["observations_ingested"] for e in result["executions"])
        assert ingested > 0

    def test_risk_engine_runs_last_on_the_live_graph(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        modules_in_order = [e["module"] for e in result["executions"]]
        assert modules_in_order[-1] == "risk_engine"
        assert modules_in_order.index("vuln_intel") < modules_in_order.index("risk_engine")

        assert result["risk"]["status"] in (orch.STATUS_SUCCESS, orch.STATUS_NO_RESULTS)
        assert result["risk"]["output_path"] == os.path.join(outdir, "risk_assessment.json")

        assessment = json.load(open(os.path.join(outdir, "risk_assessment.json")))
        assert assessment["target"] == TARGET
        assert assessment["summary"]["signals"] > 0
        # The CVE match vuln_intel persisted must be visible to the engine,
        # which proves ingestion happened before the handoff.
        categories = {s["category"] for s in assessment["signals"]}
        assert any("vuln" in c or "cve" in c for c in categories), categories

    def test_decision_queue_justifies_every_action(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        queue = result["decision_queue"]
        assert queue
        for entry in queue:
            assert entry["reason"].startswith("[REASON: ")
            assert entry["reason"].endswith("]")
            assert len(entry["reason"]) > len("[REASON: ]")
        assert any(e["action"] == "start run" for e in queue)
        assert any(e["action"].startswith("run ") for e in queue)

    def test_result_is_json_safe(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        # No default= fallback: the document must already be serializable.
        json.dumps(result, sort_keys=True)

    def test_execution_record_persisted_and_json_safe(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        path = os.path.join(outdir, "orchestrator_run.json")
        assert result["output_paths"]["execution_record"] == path
        record = json.load(open(path))
        assert record["status"] == result["status"]
        assert record["target"] == TARGET

    def test_execution_record_excludes_bulky_module_summaries(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        for execution in result["executions"]:
            assert "result" not in execution
            assert isinstance(execution["stats"], dict)

    def test_no_competing_persistence_files(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        written = {n for n in os.listdir(outdir) if n.endswith(".json")}
        assert written == {"pending_assets.json", "surface_graph.json",
                           "risk_assessment.json", "orchestrator_run.json"}


# ===========================================================================
# Scope enforcement and propagation
# ===========================================================================


class TestScope:
    def test_out_of_scope_hosts_are_recorded_but_never_scanned(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        assert "cdn.thirdparty.net" in result["scope"]["out_of_scope_hostnames_observed"]
        for module, subject in rec.calls:
            assert "thirdparty.net" not in str(subject), (module, subject)

    def test_out_of_scope_javascript_never_reaches_js_analyzer(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        js_subjects = rec.subjects_for("js_analyzer")
        assert js_subjects
        for urls in js_subjects:
            for url in urls:
                assert "thirdparty.net" not in url
                assert TARGET in url

    def test_only_ips_owned_by_in_scope_hosts_are_scanned(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)

        # An IP that only a third-party hostname resolves to must not be scannable.
        mapper = o.mapper
        finding = passive_recon.make_finding(
            "dns_record", "cdn.thirdparty.net",
            {"record_type": "A", "records": ["198.51.100.5"]},
            ["third-party A record"], passive_recon.CONFIDENCE_HIGH)
        mapper.ingest_finding(finding)
        mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", TARGET, {"record_type": "A", "records": [IP]},
            ["A record"], passive_recon.CONFIDENCE_HIGH))

        assert IP in o.scannable_ips()
        assert "198.51.100.5" not in o.scannable_ips()

    def test_ipv6_addresses_are_excluded_from_active_recon(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", TARGET, {"record_type": "AAAA", "records": ["2001:db8::1"]},
            ["AAAA record"], passive_recon.CONFIDENCE_HIGH))
        assert o.scannable_ips() == []

    def test_web_urls_stay_in_scope(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.run()
        for url in o.web_base_urls():
            host = orch._hostname_of(url)
            assert surface_mapper.is_in_scope(host, TARGET), url

    def test_adaptive_actions_never_target_out_of_scope_assets(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        for consumed in result["adaptive"]["consumed"]:
            subject = str(consumed["subject"])
            host = orch._hostname_of(subject) or subject
            assert surface_mapper.is_in_scope(host, TARGET), consumed


# ===========================================================================
# Failure isolation
# ===========================================================================


class TestFailureHandling:
    def test_single_module_failure_does_not_stop_the_run(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, failing={"code_leak"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        assert result["status"] == orch.RUN_COMPLETED_WITH_ERRORS
        failed = [e for e in result["executions"] if e["status"] == orch.STATUS_FAILED]
        assert [e["module"] for e in failed] == ["code_leak"]
        assert failed[0]["error_type"] == "RuntimeError"
        assert "exploded" in failed[0]["error"]
        # Everything downstream still ran.
        assert "risk_engine" in [e["module"] for e in result["executions"]]
        assert result["risk"]["status"] != orch.STATUS_FAILED

    def test_multiple_module_failures_are_all_isolated(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec,
                      failing={"code_leak", "osint_engine", "api_recon", "supply_chain"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        failed = {e["module"] for e in result["executions"] if e["status"] == orch.STATUS_FAILED}
        assert failed == {"code_leak", "osint_engine", "api_recon", "supply_chain"}
        assert result["status"] == orch.RUN_COMPLETED_WITH_ERRORS
        # Independent work still produced a graph and an assessment.
        assert result["correlation"]["summary"]["assets"] > 0
        assert os.path.exists(os.path.join(outdir, "risk_assessment.json"))

    def test_failure_preserves_earlier_discoveries(self, monkeypatch, rec, outdir):
        # passive_recon persists, then everything after it fails.
        install_fakes(monkeypatch, rec, failing={
            "passive_intel", "code_leak", "osint_engine", "wayback_intel",
            "active_recon", "ssl_analyzer", "vhost_scanner", "http_analyzer",
            "tech_fingerprint", "crawler", "js_analyzer", "endpoint_discovery",
            "api_recon", "exposure_scan", "supply_chain", "vuln_intel"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        sources = {o["source"] for o in graph["observations"].values()}
        assert sources == {"passive_recon.py"}
        assert result["correlation"]["summary"]["assets"] > 0

    def test_partial_module_failure_keeps_what_it_persisted(self, monkeypatch, rec, outdir):
        """A module that persists findings and *then* raises loses nothing."""
        def half_then_fail(target, output_dir="output", timeout=5.0, enable_asn=True):
            rec.log("passive_recon", target)
            store = _store(passive_recon, output_dir)
            store.add(passive_recon.make_finding(
                "dns_record", target, {"record_type": "A", "records": [IP]},
                ["A record"], passive_recon.CONFIDENCE_HIGH))
            raise RuntimeError("network died mid-module")

        install_fakes(monkeypatch, rec)
        monkeypatch.setattr(orch.passive_recon, "run_passive_recon", half_then_fail)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        execution = next(e for e in result["executions"] if e["module"] == "passive_recon")
        assert execution["status"] == orch.STATUS_FAILED
        # The finding persisted before the exception was still correlated.
        assert execution["observations_ingested"] == 1
        assert IP in result["scope"]["scanned_ips"]

    def test_scope_rejection_is_classified_separately(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, raising_scope={"crawler"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        rejected = [e for e in result["executions"] if e["status"] == orch.STATUS_SCOPE_REJECTED]
        assert rejected and all(e["module"] == "crawler" for e in rejected)
        assert all("ScopeError" in e["error_type"] for e in rejected)

    def test_empty_result_is_not_a_failure(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, empty={"passive_recon"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir,
                                       mode=orch.MODE_MODULE, modules=["passive_recon"])
        execution = next(e for e in result["executions"] if e["module"] == "passive_recon")
        assert execution["status"] == orch.STATUS_NO_RESULTS
        assert execution["error"] is None
        assert result["status"] == orch.RUN_COMPLETED

    def test_malformed_producer_output_does_not_corrupt_the_pipeline(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, malformed={"passive_recon"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        assert result["status"] in (orch.RUN_COMPLETED, orch.RUN_COMPLETED_WITH_ERRORS)
        # The bad records were recorded as ingestion errors, not silently dropped.
        assert result["correlation"]["ingestion_errors"] >= 2
        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert len(graph["ingestion_errors"]) >= 2
        # ...and the rest of the pipeline still ran.
        assert "risk_engine" in [e["module"] for e in result["executions"]]

    def test_no_web_targets_skips_web_modules_with_a_reason(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, empty={"passive_recon"})
        result = orch.run_orchestrator(
            TARGET, output_dir=outdir, mode=orch.MODE_MODULE,
            modules=["passive_recon", "js_analyzer"])
        skipped = [e for e in result["executions"] if e["status"] == orch.STATUS_SKIPPED]
        assert any(e["module"] == "js_analyzer" for e in skipped)
        assert all(e["skip_reason"] for e in skipped)

    def test_progress_callback_failure_never_aborts_a_run(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)

        def broken(_event):
            raise ValueError("UI is on fire")

        result = orch.run_orchestrator(TARGET, output_dir=outdir, progress_callback=broken)
        assert result["status"] == orch.RUN_COMPLETED_WITH_ERRORS
        assert any(e["stage"] == "progress_callback" for e in result["errors"])
        assert result["correlation"]["summary"]["assets"] > 0


class TestInterruption:
    def test_keyboard_interrupt_saves_and_returns_partial_result(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, interrupt_at="crawler")
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        assert result["status"] == orch.RUN_INTERRUPTED
        assert result["interrupted"] is True
        json.dumps(result)

        # Everything discovered before the interrupt is correlated and saved.
        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        sources = {o["source"] for o in graph["observations"].values()}
        assert "passive_recon.py" in sources
        assert "active_recon.py" in sources
        assert "tech_fingerprint.py" in sources
        # Nothing after the interrupt point ran.
        assert "endpoint_discovery" not in rec.modules()

        # The execution record explains what it was doing when it stopped.
        record = json.load(open(os.path.join(outdir, "orchestrator_run.json")))
        assert record["status"] == orch.RUN_INTERRUPTED
        assert any(e["action"] == "abort run" for e in record["decision_queue"])

    def test_interrupted_run_can_be_resumed(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, interrupt_at="crawler")
        first = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert first["status"] == orch.RUN_INTERRUPTED
        observations_after_first = first["correlation"]["summary"]["observations"]

        rec2 = Recorder()
        install_fakes(monkeypatch, rec2)
        second = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert second["status"] == orch.RUN_COMPLETED
        # The resumed run started from the earlier state, not from zero.
        assert second["correlation"]["summary"]["observations"] >= observations_after_first
        assert "endpoint_discovery" in rec2.modules()


# ===========================================================================
# Idempotency / repeated execution
# ===========================================================================


class TestIdempotency:
    def test_repeated_execution_never_replaces_or_duplicates_assets(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)

        graph_before = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assets_before = set(graph_before["assets"])
        observations_before = set(graph_before["observations"])

        rec2 = Recorder()
        install_fakes(monkeypatch, rec2)
        second = orch.run_orchestrator(TARGET, output_dir=outdir)

        graph_after = json.load(open(os.path.join(outdir, "surface_graph.json")))
        # Nothing already known is dropped or renamed...
        assert assets_before <= set(graph_after["assets"])
        assert observations_before <= set(graph_after["observations"])
        # ...and no two assets describe the same underlying thing.
        values = [(a["asset_type"], json.dumps(a["value"], sort_keys=True))
                  for a in graph_after["assets"].values()]
        assert len(values) == len(set(values)), "an asset was duplicated"
        assert second["status"] == orch.RUN_COMPLETED

    def test_repeated_execution_converges(self, monkeypatch, rec, outdir):
        """
        A second run may legitimately investigate what the first discovered
        too late to act on (an in-scope hostname learned from a certificate
        SAN only resolves once passive_recon has adaptively run against it).
        After that the graph must stop growing: further runs add fresh
        observations of known assets, never new assets.
        """
        sizes = []
        for _ in range(4):
            recorder = Recorder()
            install_fakes(monkeypatch, recorder)
            result = orch.run_orchestrator(TARGET, output_dir=outdir)
            summary = result["correlation"]["summary"]
            sizes.append((summary["assets"], summary["relationships"]))

        assert sizes[-1] == sizes[-2], f"graph never converged: {sizes}"
        assert result["adaptive"]["actions"] == 0
        assert summary["pending_opportunities"] == 0
        # Observations still accumulate — a re-observation is real evidence.
        assert summary["observations"] > summary["assets"]

    def test_re_ingesting_the_same_pending_file_adds_nothing(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)

        mapper = surface_mapper.SurfaceMapper(target=TARGET, output_dir=outdir)
        before = len(mapper.state["observations"])
        summary = mapper.ingest_pending_assets_file()
        assert summary["ingested"] == 0
        assert len(mapper.state["observations"]) == before

    def test_consumed_opportunities_are_not_refired_on_a_second_run(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        first = orch.run_orchestrator(TARGET, output_dir=outdir)
        consumed_first = {c["id"] for c in first["adaptive"]["consumed"]}
        assert consumed_first, "no adaptive action fired on the first run"

        rec2 = Recorder()
        install_fakes(monkeypatch, rec2)
        second = orch.run_orchestrator(TARGET, output_dir=outdir)
        consumed_second = {c["id"] for c in second["adaptive"]["consumed"]}
        assert consumed_first.isdisjoint(consumed_second)

    def test_pre_existing_graph_state_is_reused_not_replaced(self, monkeypatch, rec, outdir):
        mapper = surface_mapper.SurfaceMapper(target=TARGET, output_dir=outdir)
        mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", f"legacy.{TARGET}", {"record_type": "A", "records": ["203.0.113.99"]},
            ["pre-existing evidence"], passive_recon.CONFIDENCE_HIGH))
        mapper.save()
        legacy_asset_ids = set(mapper.state["assets"])

        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert legacy_asset_ids <= set(graph["assets"])
        assert f"legacy.{TARGET}" in result["scope"]["in_scope_hostnames"]

    def test_another_targets_graph_is_never_repurposed(self, monkeypatch, rec, outdir):
        """
        Previously this test let the run proceed and only checked that the
        other target's IP was not scanned. That was insufficient: SurfaceMapper
        starts a fresh in-memory graph at the same path, so the first save of
        the run *overwrote* other-target.test's surface_graph.json (verified:
        after the run the file's `target` was example.com and the other
        target's assets were gone), and the other target's pending_assets.json
        records were correlated into example.com's graph as out-of-scope
        noise. The orchestrator now refuses to start in that directory, and
        every file of the other engagement must be byte-for-byte intact.
        """
        other = surface_mapper.SurfaceMapper(target="other-target.test", output_dir=outdir)
        other.ingest_finding(passive_recon.make_finding(
            "dns_record", "other-target.test", {"record_type": "A", "records": ["198.51.100.1"]},
            ["other target"], passive_recon.CONFIDENCE_HIGH))
        other.save()
        _store(passive_recon, outdir).add(passive_recon.make_finding(
            "dns_record", "other-target.test", {"record_type": "A", "records": ["198.51.100.1"]},
            ["other target"], passive_recon.CONFIDENCE_HIGH))
        graph_path = os.path.join(outdir, "surface_graph.json")
        pending_path = os.path.join(outdir, "pending_assets.json")
        graph_before = open(graph_path, "rb").read()
        pending_before = open(pending_path, "rb").read()

        install_fakes(monkeypatch, rec)
        with pytest.raises(orch.ConfigurationError) as exc:
            orch.run_orchestrator(TARGET, output_dir=outdir)
        assert "other-target.test" in str(exc.value)
        assert "--output-dir" in str(exc.value)
        assert rec.calls == [], "no module may run against a foreign output directory"
        assert open(graph_path, "rb").read() == graph_before
        assert open(pending_path, "rb").read() == pending_before
        assert not os.path.exists(os.path.join(outdir, "orchestrator_run.json"))


# ===========================================================================
# Execution modes
# ===========================================================================


class TestModes:
    def test_passive_only_never_touches_an_active_module(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir, mode=orch.MODE_PASSIVE)
        ran = set(rec.modules())
        assert ran <= set(orch.PASSIVE_MODULES)
        assert "active_recon" not in ran
        assert "crawler" not in ran
        # Correlation and risk still happen.
        assert result["correlation"]["summary"]["assets"] > 0
        assert result["risk"]["status"] in (orch.STATUS_SUCCESS, orch.STATUS_NO_RESULTS)

    def test_passive_only_adaptive_actions_stay_passive(self, monkeypatch, rec, outdir):
        """An opportunity can never talk a passive-only run into an active module."""
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir, mode=orch.MODE_PASSIVE)
        for consumed in result["adaptive"]["consumed"]:
            assert consumed["module"] in orch.PASSIVE_MODULES, consumed
        assert set(rec.modules()) <= set(orch.PASSIVE_MODULES)

    def test_passive_only_still_adapts_to_new_hostnames(self, monkeypatch, rec, outdir):
        """A cert-SAN hostname is resolvable passively, so it should be resolved."""
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir, mode=orch.MODE_PASSIVE)
        # passive_recon ran once for the target and again for the SAN hostname.
        assert f"api.{TARGET}" in rec.subjects_for("passive_recon")

    def test_active_only_skips_passive_modules(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir, mode=orch.MODE_ACTIVE)
        ran = set(rec.modules())
        assert "passive_recon" not in ran
        assert "wayback_intel" not in ran

    def test_active_only_on_an_existing_graph_uses_its_seeds(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir, mode=orch.MODE_PASSIVE)

        rec2 = Recorder()
        install_fakes(monkeypatch, rec2)
        orch.run_orchestrator(TARGET, output_dir=outdir, mode=orch.MODE_ACTIVE)
        assert rec2.subjects_for("active_recon") == [IP]

    def test_single_module_mode_runs_only_that_module(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir,
                                       mode=orch.MODE_MODULE, modules=["passive_recon"])
        # passive_recon runs for the target, then adaptively for the in-scope
        # hostname its own certificate SAN revealed — but nothing else.
        assert set(rec.modules()) == {"passive_recon"}
        assert f"api.{TARGET}" in rec.subjects_for("passive_recon")
        assert result["risk"]["status"] == orch.STATUS_SKIPPED
        assert not os.path.exists(os.path.join(outdir, "risk_assessment.json"))
        # Correlation is continuous and still ran.
        assert result["correlation"]["summary"]["assets"] > 0

    def test_module_mode_can_request_the_risk_engine(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir,
                              mode=orch.MODE_MODULE, modules=["passive_recon"])
        result = orch.run_orchestrator(TARGET, output_dir=outdir,
                                       mode=orch.MODE_MODULE, modules=["risk_engine"])
        assert result["risk"]["status"] in (orch.STATUS_SUCCESS, orch.STATUS_NO_RESULTS)


# ===========================================================================
# Adaptive discovery
# ===========================================================================


class TestAdaptive:
    def test_opportunities_are_consumed_and_acted_on(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert result["adaptive"]["actions"] > 0
        types = {c["opportunity_type"] for c in result["adaptive"]["consumed"]}
        assert types, "no opportunity was consumed"
        adaptive_executions = [e for e in result["executions"] if e["phase"] == orch.PHASE_ADAPTIVE]
        assert adaptive_executions
        for execution in adaptive_executions:
            assert execution["module"] in orch.ALL_MODULES

    def test_adaptive_actions_are_justified_by_the_mapper_reason(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        adaptive_decisions = [d for d in result["decision_queue"]
                              if d["phase"] == orch.PHASE_ADAPTIVE]
        assert adaptive_decisions
        assert any("surface_mapper raised" in d["reason"] for d in adaptive_decisions)

    def test_manual_review_opportunities_stay_pending(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        # A dangling CNAME raises an opportunity with no automatable module.
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", f"gone.{TARGET}",
            {"record_type": "CNAME", "records": ["bucket.s3.amazonaws.com"]},
            ["dangling CNAME"], passive_recon.CONFIDENCE_HIGH))
        result = o.run()

        manual = result["opportunities"]["manual_review"]
        if manual:  # only if the mapper classified it as takeover-suspect
            ids = {m["id"] for m in manual}
            pending = {p["id"] for p in result["opportunities"]["pending"]}
            assert ids <= pending, "manual-review opportunities must not be consumed"

    def test_adaptive_can_be_disabled(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir, max_adaptive_rounds=0)
        assert result["adaptive"]["actions"] == 0
        assert not any(e["phase"] == orch.PHASE_ADAPTIVE for e in result["executions"])

    def test_adaptive_action_budget_is_enforced(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir, max_adaptive_actions=1)
        assert result["adaptive"]["actions"] <= 1

    def test_failing_adaptive_action_is_not_retried(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, failing={"http_analyzer", "passive_recon"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir, max_adaptive_rounds=3)
        consumed_ids = [c["id"] for c in result["adaptive"]["consumed"]]
        assert len(consumed_ids) == len(set(consumed_ids)), "an opportunity fired twice"


# ===========================================================================
# Determinism and derivation helpers
# ===========================================================================


class TestDerivation:
    def test_derivations_are_deterministic(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        for _ in range(3):
            assert o.web_base_urls() == o.web_base_urls()
            assert o.scannable_ips() == o.scannable_ips()
            assert o.javascript_urls() == o.javascript_urls()
            assert o.ssl_targets() == o.ssl_targets()
            assert o.technology_observations() == o.technology_observations()

    def test_target_origin_is_ordered_first(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        urls = o.web_base_urls()
        assert urls
        assert orch._hostname_of(urls[0]) == TARGET

    def test_budgets_bound_every_derivation(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, max_web_targets=1,
                              max_ssl_targets=1, max_js_files=1, max_scan_ips=1)
        assert len(o.web_base_urls()) <= 1
        assert len(o.ssl_targets()) <= 1
        assert len(o.javascript_urls()) <= 1
        assert len(o.scannable_ips()[:1]) <= 1

    def test_versionless_technologies_are_not_sent_to_vuln_intel(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.mapper.ingest_finding(tech_fingerprint.make_finding(
            "tech_fingerprint_detected", TARGET,
            {"technology": "Cloudflare", "category": "waf", "version": None,
             "url": f"https://{TARGET}/"},
            ["cf-ray header"], tech_fingerprint.CONFIDENCE_HIGH))
        assert o.technology_observations() == []

    def test_web_urls_fall_back_to_https_without_port_evidence(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", TARGET, {"record_type": "A", "records": [IP]},
            ["A record"], passive_recon.CONFIDENCE_HIGH))
        assert o.web_base_urls() == [f"https://{TARGET}/"]

    def test_open_web_ports_drive_base_urls(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", TARGET, {"record_type": "A", "records": [IP]},
            ["A record"], passive_recon.CONFIDENCE_HIGH))
        for port in (80, 8443):
            o.mapper.ingest_finding(active_recon.make_finding(
                "open_tcp_port", IP, {"ip": IP, "port": port, "protocol": "tcp"},
                [f"open {port}"], active_recon.CONFIDENCE_HIGH))
        urls = o.web_base_urls()
        assert f"http://{TARGET}/" in urls
        assert f"https://{TARGET}:8443/" in urls

    def test_non_web_ports_do_not_produce_base_urls(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", TARGET, {"record_type": "A", "records": [IP]},
            ["A record"], passive_recon.CONFIDENCE_HIGH))
        o.mapper.ingest_finding(active_recon.make_finding(
            "open_tcp_port", IP, {"ip": IP, "port": 3306, "protocol": "tcp"},
            ["open 3306"], active_recon.CONFIDENCE_HIGH))
        assert o.web_base_urls() == [f"https://{TARGET}/"]


class TestProducerContracts:
    """Regression cover for producer/consumer assumptions the orchestrator makes."""

    def test_vuln_intel_observations_carry_a_hostname_not_a_url(self, monkeypatch, rec, outdir):
        """
        vuln_intel.py copies an observation's `target` verbatim onto the
        finding it persists, and surface_mapper.py resolves a finding's
        `target` as a hostname. Handing it a URL mints a hostname asset
        named after a URL and flags it out of scope.
        """
        captured = install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)

        observations = captured["vuln_kwargs"]["observations"]
        assert observations
        for obs in observations:
            assert "://" not in obs["target"], obs
            assert surface_mapper.is_in_scope(obs["target"], TARGET), obs

    def test_no_hostname_asset_is_ever_named_after_a_url(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        for asset_id, asset in graph["assets"].items():
            if asset["asset_type"] == surface_mapper.ASSET_HOSTNAME:
                assert "://" not in str(asset["value"]), asset_id

    def test_out_of_scope_report_lists_only_real_hostnames(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        observed = result["scope"]["out_of_scope_hostnames_observed"]
        assert "cdn.thirdparty.net" in observed
        for host in observed:
            assert "://" not in host and "/" not in host, host

    def test_out_of_scope_technologies_are_not_sent_to_vuln_intel(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.mapper.ingest_finding(tech_fingerprint.make_finding(
            "tech_fingerprint_detected", TARGET,
            {"technology": "nginx", "category": "server", "version": "1.18.0",
             "url": "https://cdn.thirdparty.net/"},
            ["Server header"], tech_fingerprint.CONFIDENCE_HIGH))
        assert o.technology_observations() == []


class TestSequentialExecution:
    def test_producers_never_run_concurrently(self, monkeypatch, rec, outdir):
        """
        Every producer builds its own PendingAssetsStore whose read/append/
        rewrite cycle is only lock-protected per instance, so two producers
        writing the same pending_assets.json at once would lose findings.
        """
        state = {"in_flight": 0, "max_in_flight": 0}

        def wrap(fn):
            def wrapped(*a, **kw):
                state["in_flight"] += 1
                state["max_in_flight"] = max(state["max_in_flight"], state["in_flight"])
                try:
                    return fn(*a, **kw)
                finally:
                    state["in_flight"] -= 1
            return wrapped

        install_fakes(monkeypatch, rec)
        for module, name in (
            (orch.passive_recon, "run_passive_recon"),
            (orch.active_recon, "run_active_recon"),
            (orch.http_analyzer, "run_http_analysis"),
            (orch.crawler, "run_crawler"),
            (orch.endpoint_discovery, "run_endpoint_discovery"),
        ):
            monkeypatch.setattr(module, name, wrap(getattr(module, name)))

        orch.run_orchestrator(TARGET, output_dir=outdir)
        assert state["max_in_flight"] == 1

    def test_orchestrator_starts_no_thread_or_process_of_its_own(self):
        source = open(ORCHESTRATOR_SOURCE_PATH).read()
        for forbidden in ("ThreadPoolExecutor", "ProcessPoolExecutor",
                          "threading.Thread", "multiprocessing", "asyncio"):
            assert forbidden not in source, forbidden

    def test_orchestrator_performs_no_network_io_itself(self):
        source = open(ORCHESTRATOR_SOURCE_PATH).read()
        for forbidden in ("import requests", "^import socket", "^import ssl",
                          "urllib.request", "http.client", "requests.get", "socket.socket"):
            pattern = forbidden.lstrip("^")
            if forbidden.startswith("^"):
                assert not any(line.strip().startswith(pattern)
                               for line in source.splitlines()), forbidden
            else:
                assert pattern not in source, forbidden


class TestNoExploitation:
    def test_orchestrator_invokes_no_exploitation_capability(self):
        source = open(ORCHESTRATOR_SOURCE_PATH).read()
        for forbidden in ("subprocess", "os.system", "eval(", "exec(", "pickle"):
            assert forbidden not in source, forbidden


# ===========================================================================
# Execution identity — the same work is never repeated within one run
# ===========================================================================


class TestExecutionIdentity:
    def test_adaptive_round_never_repeats_work_the_phases_did(self, monkeypatch, rec, outdir):
        """
        The web phase runs endpoint_discovery against every base URL with
        tech_fingerprint's WordPress-aware summary; the mapper then raises
        `technology_specific_enumeration` for the very same URLs. Before the
        identity registry, 4 of 9 adaptive actions in this harness were exact
        repeats of the run's most expensive module.
        """
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        seen = {}
        for module, subject in rec.calls:
            seen[(module, str(subject))] = seen.get((module, str(subject)), 0) + 1
        repeated = {k: v for k, v in seen.items() if v > 1}
        assert not repeated, f"same module ran twice against the same subject: {repeated}"

        satisfied = result["adaptive"]["satisfied"]
        assert satisfied, "the phases' work must be recognised as satisfying the mapper's opportunities"
        execution_ids = {e["execution_id"] for e in result["executions"]}
        for item in satisfied:
            assert item["satisfied_by"] in execution_ids, item
        # Satisfied opportunities are consumed, not left pending for the next run.
        pending = {p["id"] for p in result["opportunities"]["pending"]}
        assert not any(item["id"] in pending for item in satisfied)
        assert result["opportunities"]["satisfied_this_run"] == satisfied
        # ...and every satisfaction is a justified decision.
        assert any(d["action"] == "satisfy opportunity" and d["status"] == "satisfied"
                   for d in result["decision_queue"])

    def test_the_full_run_converges_in_one_pass(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert result["opportunities"]["pending"] == []
        assert result["adaptive"]["deferred"] == []
        assert result["adaptive"]["not_actionable"] == []

    def test_satisfaction_never_suppresses_uncovered_work(self, monkeypatch, rec, outdir):
        """
        With a web budget of 1 the phase fingerprints only the target's
        origin; the open-port opportunity must then act on the hostname the
        phase did not cover rather than being written off as satisfied.
        """
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir, max_web_targets=1)
        phase_subjects = [e["subject"] for e in result["executions"]
                          if e["module"] == "tech_fingerprint" and e["phase"] == orch.PHASE_ACTIVE_WEB]
        assert phase_subjects == ["http://example.com/"]
        adaptive_subjects = [e["subject"] for e in result["executions"]
                             if e["module"] == "tech_fingerprint" and e["phase"] == orch.PHASE_ADAPTIVE]
        assert adaptive_subjects, "uncovered hostname was never fingerprinted"
        # Each follow-up hits an origin the phase did not: port 443 of the
        # target, and port 80 of the second hostname on the same IP.
        assert sorted(adaptive_subjects) == ["http://www.example.com/", "https://example.com/"]
        assert not set(adaptive_subjects) & set(phase_subjects)

    def test_failed_phase_execution_is_not_retried_by_an_opportunity(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, failing={"tech_fingerprint"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        per_subject = {}
        for module, subject in rec.calls:
            if module == "tech_fingerprint":
                per_subject[subject] = per_subject.get(subject, 0) + 1
        assert per_subject and all(n == 1 for n in per_subject.values()), per_subject
        assert result["status"] == orch.RUN_COMPLETED_WITH_ERRORS

    def test_endpoint_identity_follows_wordlist_selection(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        url = f"https://{TARGET}/"
        rich = {"cms": ["WordPress"], "detections": [{"technology": "WordPress", "version": "6.4"}]}
        bare = {"technology": "WordPress"}
        assert o._endpoint_discovery_identity(url, rich) == o._endpoint_discovery_identity(url, bare)
        assert o._endpoint_discovery_identity(url, rich) != o._endpoint_discovery_identity(url, None)
        assert o._endpoint_discovery_identity(url, bare) != o._endpoint_discovery_identity(
            url, {"technology": "Laravel"})
        assert o._endpoint_discovery_identity(url, bare)[1]["wordlists"] == ["wordpress_paths.txt"]
        # New JavaScript-derived input is new work.
        o._js_data = [{"url": f"https://{TARGET}/api"}]
        assert o._endpoint_discovery_identity(url, bare) != orch.Orchestrator(
            target=TARGET, output_dir=outdir)._endpoint_discovery_identity(url, bare)

    def test_superset_enumeration_satisfies_a_narrower_opportunity(self, outdir):
        """
        A phase run whose summary selected the WordPress *and* Laravel
        wordlists covers a later WordPress-only opportunity on the same URL;
        a generic run covers neither; a WordPress run does not cover Laravel.
        """
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        url = f"https://{TARGET}/"
        both = o._endpoint_discovery_identity(url, {"cms": ["WordPress"], "frameworks": ["Laravel"]})
        wp = o._endpoint_discovery_identity(url, {"technology": "WordPress"})
        laravel = o._endpoint_discovery_identity(url, {"technology": "Laravel"})
        generic = o._endpoint_discovery_identity(url, None)
        o._executed[both[0]] = [(both[1], "exec:0001:endpoint_discovery")]
        assert o._satisfied_by(wp) == "exec:0001:endpoint_discovery"
        assert o._satisfied_by(laravel) == "exec:0001:endpoint_discovery"
        assert o._satisfied_by(generic) == "exec:0001:endpoint_discovery"
        o._executed[both[0]] = [(generic[1], "exec:0002:endpoint_discovery")]
        assert o._satisfied_by(generic) == "exec:0002:endpoint_discovery"
        assert o._satisfied_by(wp) is None
        o._executed[both[0]] = [(wp[1], "exec:0003:endpoint_discovery")]
        assert o._satisfied_by(laravel) is None
        # More JavaScript-derived input than before is new work.
        o._js_data = [{"url": f"https://{TARGET}/api"}]
        assert o._satisfied_by(o._endpoint_discovery_identity(url, {"technology": "WordPress"})) is None
        # A different subject is never covered.
        assert o._satisfied_by(o._endpoint_discovery_identity(f"https://www.{TARGET}/", None)) is None

    def test_identity_is_registered_for_every_outcome_but_skips(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, failing={"code_leak"}, raising_scope={"crawler"})
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.run()
        registered = {execution_id for entries in o._executed.values() for _, execution_id in entries}
        for execution in o.executions:
            if execution["status"] == orch.STATUS_SKIPPED:
                assert execution["execution_id"] not in registered
            elif execution["module"] != "risk_engine":
                assert execution["execution_id"] in registered, execution

    def test_non_web_port_followup_is_satisfied_by_the_discovering_scan(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)

        def active_recon_with_ssh(ip, target=None, tcp_ports=None, output_dir="output",
                                  timeout=2.0, max_workers=20, **kw):
            rec.log("active_recon", ip)
            store = _store(active_recon, output_dir)
            for port in (22, 80):
                store.add(active_recon.make_finding(
                    "open_tcp_port", ip, {"ip": ip, "port": port, "protocol": "tcp"},
                    [f"TCP connect to {ip}:{port} succeeded"], active_recon.CONFIDENCE_HIGH))
            return {"ip": ip, "target": target, "module": "active_recon.py",
                    "tcp": {"open_ports": [22, 80]}, "udp": {}, "errors": []}

        monkeypatch.setattr(orch.active_recon, "run_active_recon", active_recon_with_ssh)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        ssh = [s for s in result["adaptive"]["satisfied"]
               if s["opportunity_type"] == "open_port_followup" and s["module"] == "active_recon"]
        assert ssh and ssh[0]["subject"] == IP
        assert ssh[0]["satisfied_by"].endswith(":active_recon")
        assert not any(p["opportunity_type"] == "open_port_followup"
                       for p in result["opportunities"]["pending"])
        assert rec.subjects_for("active_recon") == [IP], "the scan must not be repeated"

        # Passive-only afterwards: nothing may act on the port opportunity, and
        # the reason is reported instead of the id being labelled budget-deferred.
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, mode=orch.MODE_PASSIVE)
        o.mapper.ingest_finding(active_recon.make_finding(
            "open_tcp_port", IP, {"ip": IP, "port": 3306, "protocol": "tcp"},
            ["open 3306"], active_recon.CONFIDENCE_HIGH))
        rec2 = Recorder()
        install_fakes(monkeypatch, rec2)
        result = o.run()
        assert "active_recon" not in rec2.modules()
        assert result["adaptive"]["deferred"] == []
        reasons = {n["id"]: n["reason"] for n in result["adaptive"]["not_actionable"]}
        assert any("3306" in i and "enabled" in r for i, r in reasons.items()), reasons
        assert result["adaptive"]["not_actionable_count"] == len(reasons)


# ===========================================================================
# Adaptive scheduling — priority, budget semantics
# ===========================================================================


class TestAdaptiveScheduling:
    def test_high_priority_opportunities_are_acted_on_before_medium(self, monkeypatch, rec, outdir):
        """
        Opportunity ids sort `opp:hostname:...` before `opp:port:...`, so with
        a budget of one the MEDIUM cert-SAN follow-up used to win over the
        HIGH open-port follow-up purely by string order.
        """
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir, max_web_targets=1,
                                       max_adaptive_actions=1)
        consumed = result["adaptive"]["consumed"]
        assert len(consumed) == 1
        assert consumed[0]["opportunity_type"] == "open_port_followup", consumed
        deferred = set(result["adaptive"]["deferred"])
        assert any("new_hostname_via_cert_san" in d for d in deferred), deferred
        pending = {p["id"] for p in result["opportunities"]["pending"]}
        assert deferred <= pending, "a deferred opportunity must stay pending for the next run"
        assert len(result["adaptive"]["deferred"]) == len(deferred)

    def test_deferred_holds_only_budget_deferrals(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, max_adaptive_rounds=3)
        # A port on an IP no in-scope hostname resolves to: never actionable.
        o.mapper.ingest_finding(active_recon.make_finding(
            "open_tcp_port", "198.51.100.77", {"ip": "198.51.100.77", "port": 8080, "protocol": "tcp"},
            ["open 8080"], active_recon.CONFIDENCE_HIGH))
        result = o.run()
        assert result["adaptive"]["deferred"] == []
        reasons = [n["reason"] for n in result["adaptive"]["not_actionable"]]
        assert any("198.51.100.77" in r for r in reasons), reasons
        ids = [n["id"] for n in result["adaptive"]["not_actionable"]]
        assert len(ids) == len(set(ids)), "multi-round runs must not repeat ids"
        assert "198.51.100.77" not in str(rec.calls)

    def test_manual_review_is_recorded_once_across_rounds(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, max_adaptive_rounds=4)
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", f"gone.{TARGET}",
            {"record_type": "CNAME", "records": ["bucket.s3.amazonaws.com"]},
            ["dangling CNAME"], passive_recon.CONFIDENCE_HIGH))
        result = o.run()
        ids = [m["id"] for m in result["adaptive"]["manual_review"]]
        assert len(ids) == len(set(ids))
        decisions = [d for d in result["decision_queue"] if d["action"] == "defer to manual review"]
        assert len(decisions) == len(ids)

    def test_consumption_is_persisted_before_the_action_runs(self, monkeypatch, rec, outdir):
        """A crash mid-action must not resurrect the opportunity on the next run."""
        install_fakes(monkeypatch, rec)
        seen = {}

        def passive_recon_checking_graph(target, output_dir="output", timeout=5.0, enable_asn=True):
            rec.log("passive_recon", target)
            if target != TARGET:
                graph = json.load(open(os.path.join(output_dir, "surface_graph.json")))
                seen[target] = [o["status"] for o in graph["opportunities"].values()
                                if o["opportunity_type"] == "new_hostname_via_cert_san"]
            store = _store(passive_recon, output_dir)
            store.add(passive_recon.make_finding(
                "dns_record", target, {"record_type": "A", "records": [IP]},
                ["A record"], passive_recon.CONFIDENCE_HIGH))
            if target == TARGET:
                store.add(passive_recon.make_finding(
                    "tls_san", target, f"api.{TARGET}", ["SAN"], passive_recon.CONFIDENCE_HIGH,
                    metadata={"port": 443, "in_scope": True}))
            return {"target": target, "module": "passive_recon.py", "errors": []}

        monkeypatch.setattr(orch.passive_recon, "run_passive_recon", passive_recon_checking_graph)
        orch.run_orchestrator(TARGET, output_dir=outdir, mode=orch.MODE_MODULE, modules=["passive_recon"])
        assert seen == {f"api.{TARGET}": ["consumed"]}


# ===========================================================================
# Interruption — every path leaves an honest record
# ===========================================================================


class TestInterruptionSemantics:
    def test_module_reported_interrupt_stops_the_run(self, monkeypatch, rec, outdir):
        """
        crawler.py, endpoint_discovery.py and api_recon.py absorb a Ctrl+C
        themselves (they cancel their worker batch and return their partial
        summary with `status: "interrupted"`). The orchestrator used to record
        that as `no_results`, run every remaining module, and finish
        `completed` with `interrupted: False`.
        """
        install_fakes(monkeypatch, rec)

        def crawler_absorbing_interrupt(url, target=None, output_dir="output", **kw):
            rec.log("crawler", url)
            return {"target": target, "module": "crawler.py", "base_url": url, "pages": [],
                    "status": "interrupted", "cancelled": True,
                    "errors": [{"stage": "cancelled", "error": "interrupted by user"}]}

        monkeypatch.setattr(orch.crawler, "run_crawler", crawler_absorbing_interrupt)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        assert result["status"] == orch.RUN_INTERRUPTED
        assert result["interrupted"] is True
        crawls = [e for e in result["executions"] if e["module"] == "crawler"]
        assert len(crawls) == 1 and crawls[0]["status"] == orch.STATUS_INTERRUPTED
        assert crawls[0]["error_type"] == "KeyboardInterrupt"
        assert not any(m in rec.modules() for m in
                       ("js_analyzer", "endpoint_discovery", "api_recon", "exposure_scan",
                        "supply_chain", "vuln_intel"))
        assert result["risk"]["status"] == orch.STATUS_SKIPPED
        # What the module persisted before it was cut short is correlated.
        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert "tech_fingerprint.py" in {o["source"] for o in graph["observations"].values()}
        record = json.load(open(os.path.join(outdir, "orchestrator_run.json")))
        assert record["status"] == orch.RUN_INTERRUPTED

    def test_ordinary_interrupted_string_elsewhere_is_not_an_interrupt(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)

        def http_with_odd_fields(url, target=None, output_dir="output", timeout=8.0, **kw):
            rec.log("http_analyzer", url)
            return {"url": url, "module": "http_analyzer.py", "fetch_status": "found",
                    "note": "interrupted", "errors": [{"stage": "x", "error": "interrupted"}]}

        monkeypatch.setattr(orch.http_analyzer, "run_http_analysis", http_with_odd_fields)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert result["status"] == orch.RUN_COMPLETED
        assert result["interrupted"] is False

    def test_second_interrupt_during_final_correlation_leaves_interrupted_record(
            self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, interrupt_at="crawler")
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        real_ingest = o.mapper.ingest_pending_assets_file
        state = {"interrupted": False}

        def ingest_then_second_ctrl_c(*a, **kw):
            if o.interrupted and not state["interrupted"]:
                state["interrupted"] = True
                raise KeyboardInterrupt()
            return real_ingest(*a, **kw)

        monkeypatch.setattr(o.mapper, "ingest_pending_assets_file", ingest_then_second_ctrl_c)
        with pytest.raises(KeyboardInterrupt):
            o.run()
        record = json.load(open(os.path.join(outdir, "orchestrator_run.json")))
        assert record["status"] == orch.RUN_INTERRUPTED, "record must not claim the run is still running"
        assert record["interrupted"] is True
        assert any(e["action"] == "abort run" for e in record["decision_queue"])

    def test_system_exit_from_a_module_is_never_recorded_as_success(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)

        def exiting_code_leak(target, output_dir="output", timeout=8.0, **kw):
            rec.log("code_leak", target)
            raise SystemExit(3)

        monkeypatch.setattr(orch.code_leak, "run_code_leak", exiting_code_leak)
        with pytest.raises(SystemExit):
            orch.run_orchestrator(TARGET, output_dir=outdir)
        record = json.load(open(os.path.join(outdir, "orchestrator_run.json")))
        assert record["status"] == orch.RUN_FAILED
        execution = next(e for e in record["executions"] if e["module"] == "code_leak")
        assert execution["status"] == orch.STATUS_FAILED
        assert execution["error_type"] == "SystemExit"
        assert any(e["stage"] == "orchestration" and e["error_type"] == "SystemExit"
                   for e in record["errors"])
        # Evidence collected before the exit was still correlated and saved.
        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert "passive_recon.py" in {o["source"] for o in graph["observations"].values()}


# ===========================================================================
# Persistence — one save per step, failures recorded, nothing lost
# ===========================================================================


class TestGraphPersistence:
    def test_graph_is_written_once_per_execution(self, monkeypatch, rec, outdir):
        """
        The mapper's autosave wrote the whole graph inside every ingest and
        again on every consumed opportunity, on top of the orchestrator's own
        save: 104 full-graph writes for 47 executions in this harness.
        """
        install_fakes(monkeypatch, rec)
        saves = {"n": 0}
        real_save = surface_mapper.GraphStore.save

        def counting_save(self, state):
            saves["n"] += 1
            return real_save(self, state)

        monkeypatch.setattr(surface_mapper.GraphStore, "save", counting_save)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        module_executions = [e for e in result["executions"]
                             if e["status"] != orch.STATUS_SKIPPED and e["module"] != "risk_engine"]
        changed = [e for e in module_executions
                   if e["observations_ingested"] or e["ingestion"]["ingestion_errors"]]
        assert changed and len(changed) < len(module_executions), "harness must include empty modules"
        consumed = len(result["adaptive"]["consumed"]) + len(result["adaptive"]["satisfied"])
        # One write per invocation that changed the graph, one per consumed
        # opportunity, one final write at shutdown — and none for a module
        # that produced nothing (fresh directory: the startup ingest is empty).
        assert saves["n"] == len(changed) + consumed + 1, (saves, len(changed), consumed)
        assert result["status"] == orch.RUN_COMPLETED
        assert all(e["ingestion"]["graph_saved"] is True for e in module_executions)

    def test_graph_write_failure_is_recorded_and_recovered_by_the_next_run(
            self, monkeypatch, rec, outdir):
        """A full disk used to raise OSError straight out of run()."""
        install_fakes(monkeypatch, rec)
        writes = {"n": 0}
        real_write = surface_mapper.GraphStore._atomic_write

        def failing_write(self, state):
            writes["n"] += 1
            if writes["n"] >= 3:
                raise OSError(28, "No space left on device")
            return real_write(self, state)

        monkeypatch.setattr(surface_mapper.GraphStore, "_atomic_write", failing_write)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert result["status"] == orch.RUN_COMPLETED_WITH_ERRORS
        failures = [e for e in result["errors"] if e["stage"] == "graph_persistence"]
        assert len(failures) == 1 and failures[0]["error_type"] == "OSError"
        assert failures[0]["occurrences"] > 1, "every later attempt is counted, not listed"
        assert not any(e["stage"] == "orchestration" for e in result["errors"])
        # Every module still ran and the in-memory correlation was complete...
        assert "risk_engine" in [e["module"] for e in result["executions"]]
        assert result["correlation"]["summary"]["assets"] > 0
        # Once a write has failed the graph stays dirty, so every later
        # execution reports the graph as unsaved until a write succeeds.
        flags = [e["ingestion"]["graph_saved"] for e in result["executions"] if e.get("ingestion")]
        assert False in flags
        assert all(f is False for f in flags[flags.index(False):])
        # ...the on-disk graph is simply older, never corrupt...
        stale = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert stale["target"] == TARGET
        # ...and a healthy re-run recovers everything from pending_assets.json.
        monkeypatch.setattr(surface_mapper.GraphStore, "_atomic_write", real_write)
        rec2 = Recorder()
        install_fakes(monkeypatch, rec2)
        second = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert second["status"] == orch.RUN_COMPLETED
        graph = json.load(open(os.path.join(outdir, "surface_graph.json")))
        assert {o["source"] for o in graph["observations"].values()} >= {
            "passive_recon.py", "active_recon.py", "crawler.py", "vuln_intel.py"}

    def test_pending_assets_corrupted_mid_run_is_not_a_no_result(self, monkeypatch, rec, outdir):
        """
        A module that persisted findings and whose file then became
        unreadable did not "find nothing": the execution keeps its success
        status and carries the correlation error instead.
        """
        install_fakes(monkeypatch, rec)

        def wayback_then_corrupt(target, output_dir="output", timeout=8.0, **kw):
            rec.log("wayback_intel", target)
            with open(os.path.join(output_dir, "pending_assets.json"), "w") as f:
                f.write("{corrupt")
            return {"target": target, "module": "wayback_intel.py", "historical_data": [], "errors": []}

        monkeypatch.setattr(orch.wayback_intel, "run_wayback_intel", wayback_then_corrupt)
        result = orch.run_orchestrator(TARGET, output_dir=outdir, mode=orch.MODE_MODULE,
                                       modules=["passive_recon", "wayback_intel"])
        execution = next(e for e in result["executions"] if e["module"] == "wayback_intel")
        assert execution["status"] == orch.STATUS_SUCCESS
        assert execution["ingestion"]["error"]
        assert any(e["stage"] == "correlation" for e in result["errors"])
        assert result["status"] == orch.RUN_COMPLETED_WITH_ERRORS

    def test_malformed_only_output_is_not_a_no_result(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, malformed={"passive_recon"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir,
                                       mode=orch.MODE_MODULE, modules=["passive_recon"])
        execution = next(e for e in result["executions"] if e["module"] == "passive_recon")
        assert execution["status"] == orch.STATUS_SUCCESS
        assert execution["ingestion"]["ingestion_errors"] == 2

    def test_stale_execution_record_of_another_target_is_refused(self, outdir):
        store = orch.ExecutionRecordStore(output_dir=outdir)
        store.save({"module": orch.MODULE_NAME, "target": "other-target.test", "status": "running"})
        with pytest.raises(orch.ConfigurationError):
            orch.Orchestrator(target=TARGET, output_dir=outdir)
        # The same target may of course resume into its own directory.
        store.save({"module": orch.MODULE_NAME, "target": TARGET, "status": "running"})
        orch.Orchestrator(target=TARGET, output_dir=outdir)

    def test_execution_record_temp_files_never_linger(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        assert not [n for n in os.listdir(outdir) if n.startswith(".orchestrator_run_")]


# ===========================================================================
# State integrity — corrupted or hostile persisted state
# ===========================================================================


class TestStateIntegrity:
    def _poison(self, outdir):
        path = os.path.join(outdir, "surface_graph.json")
        graph = json.load(open(path))
        graph["assets"]["hostname:zzz"] = "not a dict"
        graph["relationships"]["rel:zzz"] = ["not", "a", "dict"]
        host_key = next(k for k, a in graph["assets"].items()
                        if isinstance(a, dict) and a.get("asset_type") == "hostname")
        graph["assets"][host_key]["attributes"] = "corrupt"
        port_key = next(k for k, a in graph["assets"].items()
                        if isinstance(a, dict) and a.get("asset_type") == "port")
        graph["assets"][port_key]["attributes"] = ["corrupt"]
        graph["assets"]["hostname:{'x': 1}"] = {
            "id": "hostname:{'x': 1}", "asset_type": "hostname", "value": {"x": 1},
            "in_scope": True, "attributes": {}}
        json.dump(graph, open(path, "w"))
        return path

    def test_malformed_graph_records_are_ignored_and_reported(self, monkeypatch, rec, outdir):
        """Every derivation used to raise AttributeError and fail the whole run."""
        install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        self._poison(outdir)

        rec2 = Recorder()
        install_fakes(monkeypatch, rec2)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert result["status"] == orch.RUN_COMPLETED_WITH_ERRORS
        anomalies = [e for e in result["errors"] if e["stage"] == "graph_state"]
        assert len(anomalies) == 1 and anomalies[0]["count"] >= 4
        assert not any(e["stage"] == "orchestration" for e in result["errors"])
        assert "risk_engine" in [e["module"] for e in result["executions"]]
        assert "{'x': 1}" not in str(rec2.calls)
        assert IP in result["scope"]["scanned_ips"]
        for host in result["scope"]["in_scope_hostnames"]:
            assert orch._valid_hostname(host)

    def test_malformed_in_scope_hostnames_never_become_subjects(self, monkeypatch, rec, outdir):
        """
        Twenty poisoned SAN names that pass the mapper's suffix check would
        otherwise fill the whole TLS-target budget and starve the real
        subdomain of its inspection.
        """
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, max_ssl_targets=3)
        hostile = [f"evil{i}.net/#.{TARGET}" for i in range(10)] + [
            f"a b{i}.{TARGET}" for i in range(5)] + [f"-bad{i}-.{TARGET}" for i in range(5)]
        for name in hostile:
            o.mapper.ingest_finding(passive_recon.make_finding(
                "tls_san", TARGET, name, ["san"], passive_recon.CONFIDENCE_HIGH,
                metadata={"port": 443}))
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", f"real.{TARGET}", {"record_type": "A", "records": [IP]},
            ["A record"], passive_recon.CONFIDENCE_HIGH))
        assert o.in_scope_hostnames() == [TARGET, f"real.{TARGET}"]
        assert (f"real.{TARGET}", 443) in o.ssl_targets()
        assert not any("evil" in h or " " in h or "-bad" in h for h, _ in o.ssl_targets())
        assert not any("evil" in u for u in o.web_base_urls())
        # Declining a name is not a corrupted-state error: it is reported
        # under scope, and the run stays clean.
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", f"_dmarc.{TARGET}", {"record_type": "TXT", "records": ["v=DMARC1"]},
            ["txt"], passive_recon.CONFIDENCE_HIGH))
        install_fakes(monkeypatch, rec)
        result = o.run()
        assert not any(e["stage"] == "graph_state" for e in result["errors"])
        unusable = result["scope"]["unusable_in_scope_hostnames"]
        assert unusable["count"] == len(hostile) + 1
        assert any(h["hostname"] == f"_dmarc.{TARGET}" for h in unusable["sample"])
        assert f"_dmarc.{TARGET}" not in str(rec.calls)

    def test_hostile_opportunity_values_are_not_actionable(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.mapper.ingest_finding(passive_recon.make_finding(
            "tls_san", TARGET, f"evil.net#.{TARGET}", ["san"], passive_recon.CONFIDENCE_HIGH,
            metadata={"port": 443}))
        result = o.run()
        assert "evil.net" not in str(rec.calls)
        assert any("evil.net" in n["reason"] for n in result["adaptive"]["not_actionable"])

    def test_target_ip_is_scanned_first_under_the_ip_budget(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, max_scan_ips=1)
        o.mapper.ingest_finding(passive_recon.make_finding(
            "dns_record", TARGET, {"record_type": "A", "records": ["203.0.113.250"]},
            ["A record"], passive_recon.CONFIDENCE_HIGH))
        for i in range(5):
            o.mapper.ingest_finding(passive_recon.make_finding(
                "dns_record", f"s{i}.{TARGET}", {"record_type": "A", "records": [f"10.0.0.{i}"]},
                ["A record"], passive_recon.CONFIDENCE_HIGH))
        assert o.scannable_ips()[0] == "203.0.113.250"
        assert o.scan_ips() == ["203.0.113.250"]
        assert o._hostnames_for_ip("203.0.113.250") == [TARGET]
        assert o.scannable_ips() == o.scannable_ips()


# ===========================================================================
# Coverage — budgets are accounted for, never hidden
# ===========================================================================


class TestCoverage:
    def test_budget_truncation_is_reported_honestly(self, monkeypatch, rec, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, max_web_targets=3,
                              max_ssl_targets=2)
        for i in range(12):
            o.mapper.ingest_finding(passive_recon.make_finding(
                "dns_record", f"h{i:02d}.{TARGET}", {"record_type": "A", "records": [f"10.0.0.{i}"]},
                ["A record"], passive_recon.CONFIDENCE_HIGH))
        install_fakes(monkeypatch, rec)
        result = o.run()
        coverage = result["coverage"]
        assert coverage["complete"] is False
        web = coverage["budgets"]["web_base_urls"]
        assert web["limit"] == 3 and web["selected"] == 3 and web["omitted"] == web["derived"] - 3
        assert len(web["omitted_subjects"]) == min(web["omitted"], orch.MAX_RECORDED_OMITTED_SUBJECTS)
        assert all("://" in u for u in web["omitted_subjects"])
        assert coverage["budgets"]["ssl_targets"]["omitted"] > 0
        # 12 seeded hosts plus the fake passive_recon's own A record for the target.
        assert coverage["budgets"]["scan_ips"]["derived"] == 13
        # Bounded-but-complete budgets read as complete.
        assert coverage["budgets"]["supply_chain_pages"]["omitted"] == 0
        # The truncation is not an error: nothing failed.
        assert result["status"] == orch.RUN_COMPLETED

    def test_coverage_is_complete_when_nothing_is_truncated(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert result["coverage"]["complete"] is True
        assert all(b["omitted"] == 0 and b["omitted_subjects"] == []
                   for b in result["coverage"]["budgets"].values())
        json.dumps(result["coverage"])


# ===========================================================================
# Downstream hand-offs
# ===========================================================================


class TestHandoffs:
    def test_endpoints_are_probed_once_per_origin(self, monkeypatch, rec, outdir):
        """
        Every base URL of a host used to receive the host's whole endpoint
        list, so http:// and https:// bases each OPTIONS-probed the same URLs.
        """
        captured = install_fakes(monkeypatch, rec)
        orch.run_orchestrator(TARGET, output_dir=outdir)
        handed = captured["exposure_kwargs"]
        assert handed
        all_endpoints = [e for v in handed.values() for e in (v["endpoints"] or [])]
        assert all_endpoints
        assert len(all_endpoints) == len(set(all_endpoints)), "an endpoint was handed to two base URLs"
        for base, kwargs in handed.items():
            for endpoint in kwargs["endpoints"] or []:
                assert orch._hostname_of(endpoint) == orch._hostname_of(base)
                assert orch._origin_of(endpoint) == orch._origin_of(base)

    def test_endpoints_without_a_base_url_of_their_origin_fall_back_to_the_host(self, outdir):
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)
        o.mapper.ingest_finding(endpoint_discovery.make_finding(
            "endpoint_discovered", TARGET,
            {"url": f"http://{TARGET}/legacy", "status_code": 200, "method": "GET"},
            ["historical"], endpoint_discovery.CONFIDENCE_MEDIUM))
        o.mapper.ingest_finding(endpoint_discovery.make_finding(
            "endpoint_discovered", TARGET,
            {"url": f"https://{TARGET}:8443/admin/", "status_code": 200, "method": "GET"},
            ["alt port"], endpoint_discovery.CONFIDENCE_MEDIUM))
        assigned = o._endpoints_by_base_url([f"https://{TARGET}/", f"https://{TARGET}:8443/"])
        assert assigned[f"https://{TARGET}/"] == [f"http://{TARGET}/legacy"]
        assert assigned[f"https://{TARGET}:8443/"] == [f"https://{TARGET}:8443/admin/"]

    def test_skip_reasons_cite_upstream_failures(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec, failing={"passive_recon"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir,
                                       mode=orch.MODE_MODULE, modules=["passive_recon", "active_recon"])
        skipped = next(e for e in result["executions"] if e["module"] == "active_recon")
        assert skipped["status"] == orch.STATUS_SKIPPED
        assert "passive_recon" in skipped["skip_reason"] and "RuntimeError" in skipped["skip_reason"]

    def test_result_schema_keeps_every_field_downstream_consumers_read(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        for key in ("module", "target", "mode", "status", "started_at", "finished_at", "interrupted",
                    "settings", "modules_selected", "phases", "executions", "executions_by_status",
                    "decision_queue", "adaptive", "correlation", "opportunities", "risk", "scope",
                    "coverage", "errors", "output_paths", "notes"):
            assert key in result, key
        for key in ("rounds", "actions", "consumed", "satisfied", "manual_review", "deferred",
                    "not_actionable", "not_actionable_count"):
            assert key in result["adaptive"], key
        for execution in result["executions"]:
            for key in ("execution_id", "module", "phase", "subject", "status", "started_at",
                        "finished_at", "duration_seconds", "error", "error_type",
                        "module_error_count", "observations_ingested", "stats"):
                assert key in execution, (execution["module"], key)


# ===========================================================================
# Credentials — nothing secret reaches persisted state
# ===========================================================================


class TestCredentialHygiene:
    SECRET = "sk_live_SUPERSECRETVALUE123"

    def test_escaped_exception_text_is_redacted_everywhere(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)

        def leaky_passive_intel(target, output_dir="output", seed_ips=None, timeout=8.0, **kw):
            rec.log("passive_intel", target)
            raise RuntimeError(
                f"HTTPSConnectionPool(host='api.shodan.io', port=443): Max retries exceeded with "
                f"url: /shodan/host/{IP}?key={self.SECRET}&minify=true (Authorization: Bearer {self.SECRET})")

        monkeypatch.setattr(orch.passive_intel, "run_passive_intel", leaky_passive_intel)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert self.SECRET not in json.dumps(result)
        assert self.SECRET not in open(os.path.join(outdir, "orchestrator_run.json")).read()
        execution = next(e for e in result["executions"] if e["module"] == "passive_intel")
        assert execution["status"] == orch.STATUS_FAILED
        assert "key=<redacted>" in execution["error"]
        assert "api.shodan.io" in execution["error"], "redaction must keep the diagnostic"

    def test_orchestration_and_persistence_errors_are_redacted(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir)

        def leaky_ingest(*a, **kw):
            raise OSError(f"cannot read token={self.SECRET}")

        monkeypatch.setattr(o.mapper, "ingest_pending_assets_file", leaky_ingest)
        result = o.run()
        assert self.SECRET not in json.dumps(result)

    def test_redaction_patterns(self):
        assert orch._redact_secrets("x-api-key: abcdefgh12345 rest") == "x-api-key: <redacted> rest"
        assert orch._redact_secrets("?apikey=abc&query=host") == "?apikey=<redacted>&query=host"
        assert orch._redact_secrets("plain message with no secret") == "plain message with no secret"
        assert orch._redact_secrets("port=443 and host=x") == "port=443 and host=x"
        assert orch._redact_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig") == \
            "Authorization: Bearer <redacted>"
        # Ordinary diagnostics keep their words.
        for text in ("bearer token expired", "basic authentication required",
                     "token refresh failed for host", "HTTP 401 unauthorized"):
            assert orch._redact_secrets(text) == text, text


# ===========================================================================
# Resource behaviour — orchestration cost stays linear
# ===========================================================================


class TestResourceBehaviour:
    def test_derivations_scale_linearly_with_graph_size(self, outdir):
        import time
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, max_web_targets=1000,
                              max_ssl_targets=1000, max_scan_ips=1000)
        timings = []
        for size in (200, 800):
            for i in range(size):
                o.mapper.ingest_finding(passive_recon.make_finding(
                    "dns_record", f"h{i}.{TARGET}", {"record_type": "A", "records": [f"10.{i // 250}.{(i // 5) % 50}.{i % 5}"]},
                    ["A record"], passive_recon.CONFIDENCE_HIGH))
                if i % 3 == 0:
                    o.mapper.ingest_finding(active_recon.make_finding(
                        "open_tcp_port", f"10.{i // 250}.{(i // 5) % 50}.{i % 5}",
                        {"ip": f"10.{i // 250}.{(i // 5) % 50}.{i % 5}", "port": 443, "protocol": "tcp"},
                        ["open"], active_recon.CONFIDENCE_HIGH))
            started = time.perf_counter()
            for _ in range(3):
                o.web_base_urls(); o.ssl_targets(); o.scannable_ips(); o.in_scope_hostnames()
            timings.append(time.perf_counter() - started)
        assert timings[1] < timings[0] * 20, timings  # 5x the data must not cost 25x (quadratic)

    def test_bookkeeping_lists_are_bounded(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        o = orch.Orchestrator(target=TARGET, output_dir=outdir, mode=orch.MODE_PASSIVE)
        for i in range(orch.MAX_RECORDED_NOT_ACTIONABLE + 50):
            o.mapper.ingest_finding(active_recon.make_finding(
                "open_tcp_port", IP, {"ip": IP, "port": 1000 + i, "protocol": "tcp"},
                ["open"], active_recon.CONFIDENCE_HIGH))
        result = o.run()
        assert len(result["adaptive"]["not_actionable"]) == orch.MAX_RECORDED_NOT_ACTIONABLE
        assert result["adaptive"]["not_actionable_count"] >= orch.MAX_RECORDED_NOT_ACTIONABLE + 50

    def test_progress_callback_errors_are_collapsed(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)

        def broken(_event):
            raise ValueError("UI is on fire")

        result = orch.run_orchestrator(TARGET, output_dir=outdir, progress_callback=broken)
        entries = [e for e in result["errors"] if e["stage"] == "progress_callback"]
        assert len(entries) == 1
        assert entries[0]["occurrences"] > 10
        assert result["status"] == orch.RUN_COMPLETED_WITH_ERRORS

    def test_interrupt_inside_the_adaptive_round_keeps_fired_actions_in_the_result(
            self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        real = orch.passive_recon.run_passive_recon

        def interrupt_on_san_host(target, **kw):
            if target != TARGET:
                rec.log("passive_recon", target)
                raise KeyboardInterrupt()
            return real(target, **kw)

        monkeypatch.setattr(orch.passive_recon, "run_passive_recon", interrupt_on_san_host)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert result["status"] == orch.RUN_INTERRUPTED
        fired = [e for e in result["executions"] if e["phase"] == orch.PHASE_ADAPTIVE]
        assert fired, "the interrupted action itself is an adaptive execution"
        assert result["adaptive"]["rounds"] == 1
        assert {c["id"] for c in result["adaptive"]["consumed"]}, "consumed actions must not vanish"
        assert len(result["adaptive"]["consumed"]) + len(result["adaptive"]["satisfied"]) >= len(fired)


# ===========================================================================
# Origin reachability
#
# Reproduces the integration defect found in the 2026-09-12 whole-system
# audit: http_analyzer.py reported an origin `unreachable` after one request,
# and the orchestrator then handed the same dead origin to tech_fingerprint,
# crawler, endpoint_discovery, api_recon and exposure_scan, which each spent
# their whole request budget on transport failures. Measured on a real run
# against example.com:8080/8443 (ports that accept TCP but never answer HTTP):
# 1,866 seconds — 31 of the run's 42 minutes — for zero observations. The
# executions were then recorded as `no_results`, which reads as "checked and
# found nothing" about an origin that was never checked at all.
# ===========================================================================


class TestOriginReachability:
    """An origin proven dead is not enumerated, and is not reported as clean."""

    WEB_URLS = ("http://example.com/", "https://example.com/")

    def _install_unreachable_http(self, monkeypatch, rec, dead_urls):
        """http_analyzer reports its real `unreachable` summary for dead_urls."""
        real_http = orch.http_analyzer.run_http_analysis

        def http(url, target=None, output_dir="output", timeout=8.0, **kw):
            if url in dead_urls:
                rec.log("http_analyzer", url)
                # The exact shape http_analyzer.run_http_analysis returns when
                # its one baseline fetch does not complete.
                return {"url": url, "target": target, "module": "http_analyzer.py",
                        "status": "unreachable", "fetch_status": "error",
                        "completeness": "not_performed", "requests_made": 1,
                        "findings_persisted": 0, "findings_produced": 0,
                        "errors": [{"stage": "fetch", "error": "timeout"}]}
            return real_http(url, target=target, output_dir=output_dir, timeout=timeout, **kw)

        monkeypatch.setattr(orch.http_analyzer, "run_http_analysis", http)

    def test_dead_origin_is_probed_once_and_never_enumerated(
            self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        dead = "https://example.com/"
        self._install_unreachable_http(monkeypatch, rec, {dead})

        orch.run_orchestrator(TARGET, output_dir=outdir)

        for module in orch.WEB_MODULES_NEEDING_A_LIVE_ORIGIN:
            assert dead not in rec.subjects_for(module), (
                f"{module} was run against an origin http_analyzer proved dead")
        assert rec.subjects_for("http_analyzer").count(dead) == 1, (
            "the reachability probe itself must still happen, exactly once")

    def test_the_skip_is_recorded_with_its_reason_not_silently_omitted(
            self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        dead = "https://example.com/"
        self._install_unreachable_http(monkeypatch, rec, {dead})

        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        skips = [e for e in result["executions"]
                 if e["status"] == orch.STATUS_SKIPPED and e.get("subject") == dead]
        assert {e["module"] for e in skips} == set(orch.WEB_MODULES_NEEDING_A_LIVE_ORIGIN)
        for entry in skips:
            assert "unreachable" in entry["skip_reason"]
            # Decision transparency (design principle 8): the reason is also
            # in the decision queue, not only on the execution record.
            assert any(d.get("subject") == dead and d.get("module") == entry["module"]
                       for d in result["decision_queue"])

    def test_unreachable_is_not_reported_as_a_negative_result(
            self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        dead = "https://example.com/"
        self._install_unreachable_http(monkeypatch, rec, {dead})

        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        probe = [e for e in result["executions"]
                 if e["module"] == "http_analyzer" and e.get("subject") == dead]
        assert len(probe) == 1
        assert probe[0]["status"] == orch.STATUS_UNREACHABLE, (
            "'no_results' means checked and found nothing; this origin was never checked")
        assert probe[0]["subject_unreachable"] is True
        assert orch.STATUS_UNREACHABLE in result["executions_by_status"]

    def test_a_live_origin_is_still_fully_enumerated(self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        dead = "https://example.com/"
        self._install_unreachable_http(monkeypatch, rec, {dead})

        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        # Only the web phase's own base URLs; a hostname learned during the
        # adaptive round is covered by the next run's phases by design.
        live = {e["subject"] for e in result["executions"]
                if e["module"] == "http_analyzer" and e["phase"] == orch.PHASE_ACTIVE_WEB
                and e["subject"] != dead}
        assert live, "the fixture must leave at least one live origin"
        for module in orch.WEB_MODULES_NEEDING_A_LIVE_ORIGIN:
            covered = {e["subject"] for e in result["executions"]
                       if e["module"] == module and e["status"] != orch.STATUS_SKIPPED}
            assert live <= covered, (
                f"{module} lost coverage of an origin that answered")

    def test_one_answer_makes_an_origin_reachable_for_the_rest_of_the_run(self, outdir):
        # A single later timeout against a host that has demonstrably served a
        # response is a transient failure, not proof the origin is gone.
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        url = "https://example.com/"
        orchestrator._note_reachability("http_analyzer", url, {"status": "found"})
        assert orchestrator._unreachable_reason(url) is None
        orchestrator._note_reachability("http_analyzer", url, {"status": "unreachable"})
        assert orchestrator._unreachable_reason(url) is None, (
            "an origin that answered once must never be demoted to unreachable")

    def test_reachability_is_per_origin_not_per_host(self, outdir):
        # http://host:8080 being dead says nothing about https://host/.
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        orchestrator._note_reachability(
            "http_analyzer", "http://example.com:8080/", {"status": "unreachable"})
        assert orchestrator._unreachable_reason("http://example.com:8080/") is not None
        assert orchestrator._unreachable_reason("http://example.com:8080/anything") is not None
        for other in ("https://example.com/", "http://example.com/",
                      "https://example.com:8443/", "http://www.example.com:8080/"):
            assert orchestrator._unreachable_reason(other) is None, other

    def test_only_http_analyzer_establishes_reachability(self, outdir):
        # No other module reports reachability as a first-class outcome; a
        # crawler that merely errored must not silence the rest of the run.
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        url = "https://example.com/"
        for module in ("crawler", "endpoint_discovery", "api_recon", "exposure_scan"):
            assert orchestrator._note_reachability(module, url, {"status": "unreachable"}) is False
        assert orchestrator._unreachable_reason(url) is None

    @pytest.mark.parametrize("result", [None, {}, [], "unreachable", {"status": None},
                                        {"status": 7}, {"status": ["unreachable"]}])
    def test_a_malformed_summary_never_marks_an_origin_dead(self, outdir, result):
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        url = "https://example.com/"
        assert orchestrator._note_reachability("http_analyzer", url, result) is False
        assert orchestrator._unreachable_reason(url) is None

    @pytest.mark.parametrize("subject", [None, "", "not a url", 12, ["https://x/"],
                                         "https://", "javascript:alert(1)"])
    def test_a_subject_with_no_origin_is_ignored(self, outdir, subject):
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        assert orchestrator._note_reachability(
            "http_analyzer", subject, {"status": "unreachable"}) is False
        assert orchestrator._unreachable_reason(subject) is None

    def test_an_adaptive_opportunity_on_a_dead_origin_is_left_pending_with_a_reason(
            self, outdir):
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        url = "https://example.com/"
        orchestrator._note_reachability("http_analyzer", url, {"status": "unreachable"})
        for module in orch.WEB_MODULES_NEEDING_A_LIVE_ORIGIN:
            action, reason = orchestrator._call_for(module, url, "example.com")
            assert action is None, f"{module} was scheduled against a dead origin"
            assert "unreachable" in reason
        # http_analyzer is the probe, so it is never gated by its own result.
        action, reason = orchestrator._call_for("http_analyzer", url, "example.com")
        assert action is not None, reason

    def test_not_checked_also_counts_as_unreachable(self, outdir):
        # http_analyzer distinguishes "not_checked" (the fetch was never made)
        # from "unreachable" (it was made and failed). Neither checked anything.
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        url = "https://example.com/"
        assert orchestrator._note_reachability(
            "http_analyzer", url, {"status": "not_checked"}) is True
        assert "not_checked" in (orchestrator._unreachable_reason(url) or "")

    def test_the_run_result_names_unreachable_origins_as_a_coverage_hole(
            self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        dead = "https://example.com/"
        self._install_unreachable_http(monkeypatch, rec, {dead})

        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        coverage = result["coverage"]
        assert coverage["complete"] is False, (
            "a run that could not reach an origin is not complete coverage")
        origins = [e["origin"] for e in coverage["unreachable_origins"]]
        assert "https://example.com" in origins

    def test_supply_chain_pages_on_a_dead_origin_are_omitted_and_reported(
            self, monkeypatch, rec, outdir):
        install_fakes(monkeypatch, rec)
        dead = "https://example.com/"
        self._install_unreachable_http(monkeypatch, rec, {dead})

        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        omitted = result["coverage"]["unreachable_pages_omitted"]
        assert dead in omitted
        pages = rec.subjects_for("supply_chain")
        assert pages, "supply_chain must still run for the reachable pages and the DNS half"


# ===========================================================================
# Scan-subject IP boundary
#
# Reproduces the security issue found in the 2026-09-12 whole-system audit:
# an in-scope hostname's A record is target-controlled data, and one naming
# 169.254.169.254 made the orchestrator hand that address to active_recon and
# vhost_scanner as a scan subject — pointing the tool at the cloud
# instance-metadata service of the machine running it. endpoint_discovery.py
# already refuses exactly this for hostnames learned from response bodies
# ("an authorisation boundary violation, not a bug in taste"); a hostile or
# hijacked DNS answer is the same untrusted input by another route.
# ===========================================================================


class TestScanSubjectIpBoundary:

    def _graph_with_a_records(self, outdir, records):
        mapper = surface_mapper.SurfaceMapper(target=TARGET, output_dir=outdir)
        mapper.ingest_finding({
            "type": "dns_record", "target": TARGET,
            "value": {"record_type": "A", "records": list(records)},
            "evidence": ["A record"], "confidence": "HIGH",
            "source": "passive_recon.py", "timestamp": "2026-02-01T00:00:00+00:00",
            "metadata": {}})
        mapper.save()
        return orch.Orchestrator(target=TARGET, output_dir=outdir)

    @pytest.mark.parametrize("address", [
        "169.254.169.254",   # cloud instance metadata
        "169.254.1.1",       # link-local generally
        "127.0.0.1", "127.1.2.3",
        "0.0.0.0", "0.1.2.3",   # RFC 1122 "this network": source address only
        "224.0.0.1",         # multicast
        "255.255.255.255",   # broadcast
        "240.0.0.1",         # reserved
    ])
    def test_an_address_that_cannot_denote_a_remote_target_is_never_scanned(
            self, outdir, address):
        orchestrator = self._graph_with_a_records(outdir, [address])
        assert address not in orchestrator.scannable_ips()
        assert address not in orchestrator.scan_ips()
        assert not any(address in url for url in orchestrator.web_base_urls())

    def test_the_refusal_is_reported_not_silently_dropped(self, outdir):
        orchestrator = self._graph_with_a_records(outdir, ["169.254.169.254"])
        orchestrator.scannable_ips()
        refused = {e["ip"]: e["reason"] for e in
                   orchestrator._build_result({}, {})["scope"]["refused_scan_ips"]}
        assert "169.254.169.254" in refused
        assert "instance-metadata" in refused["169.254.169.254"]

    @pytest.mark.parametrize("address", [
        "10.0.0.5", "172.16.9.9", "192.168.1.10",   # RFC1918: internal engagements
        "100.64.0.1",                                # CGNAT
        "203.0.113.10", "8.8.8.8",                   # ordinary global unicast
    ])
    def test_an_ordinary_or_internal_address_is_still_scanned(self, outdir, address):
        # Refusing RFC1918 would remove the internal reconnaissance this tool
        # exists for; only addresses that name the scanner itself are excluded.
        orchestrator = self._graph_with_a_records(outdir, [address])
        assert orchestrator.scannable_ips() == [address]

    def test_a_mixed_answer_keeps_the_usable_addresses(self, outdir):
        orchestrator = self._graph_with_a_records(
            outdir, ["169.254.169.254", "203.0.113.10", "127.0.0.1", "10.0.0.5"])
        assert orchestrator.scannable_ips() == ["10.0.0.5", "203.0.113.10"]

    @pytest.mark.parametrize("value,expected_none", [
        ("203.0.113.1", True), ("10.0.0.1", True), ("8.8.8.8", True),
        ("169.254.169.254", False), ("127.0.0.1", False), ("0.0.0.0", False),
        ("::1", False), ("fe80::1", False),
        ("", False), ("not-an-ip", False), (None, False), (12, False),
        (" 203.0.113.1 ", True),
    ])
    def test_the_gate_itself_never_raises(self, value, expected_none):
        result = orch._not_a_remote_host(value)
        assert (result is None) is expected_none


class TestEndpointOwnerAssignment:
    """
    exposure_scan probes each discovered endpoint with OPTIONS through
    exactly one base URL. An endpoint whose own origin has no base URL falls
    back to its host's — and if that fallback is an origin the run proved
    dead, the endpoint is assigned to an execution that is then skipped, so
    it is never probed at all. Found in the 2026-09-12 whole-system audit as
    a follow-on of the reachability skip.
    """

    def test_the_host_fallback_prefers_a_reachable_base_url(self, outdir):
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        dead, live = "http://example.com/", "https://example.com/"
        orchestrator._note_reachability("http_analyzer", dead, {"status": "unreachable"})
        # An http:// endpoint learned from history, whose own origin is dead.
        orchestrator.endpoint_urls = lambda: ["https://example.com/api/v1/users"]
        assigned = orchestrator._endpoints_by_base_url([dead, live])
        assert assigned[live] == ["https://example.com/api/v1/users"]
        assert assigned[dead] == []

    def test_an_endpoint_on_its_own_live_origin_is_unaffected(self, outdir):
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        a, b = "http://example.com/", "https://example.com/"
        orchestrator.endpoint_urls = lambda: ["http://example.com/x", "https://example.com/y"]
        assigned = orchestrator._endpoints_by_base_url([a, b])
        assert assigned[a] == ["http://example.com/x"]
        assert assigned[b] == ["https://example.com/y"]

    def test_an_endpoint_whose_only_origin_is_dead_still_goes_nowhere_else(self, outdir):
        # It must not be smuggled onto a different origin's scan.
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        dead, live = "http://example.com:8080/", "https://example.com/"
        orchestrator._note_reachability("http_analyzer", dead, {"status": "unreachable"})
        orchestrator.endpoint_urls = lambda: ["http://example.com:8080/admin"]
        assigned = orchestrator._endpoints_by_base_url([dead, live])
        assert assigned[dead] == ["http://example.com:8080/admin"]
        assert assigned[live] == []


class TestOriginKeyHygiene:
    """
    An origin is a scheduling key that is echoed into the decision queue, the
    persisted execution record and the CLI. Self-attack finding from the
    2026-09-12 audit: an opportunity subject originates in crawled response
    bodies, so it can carry `user:password@`, and the skip reason wrote that
    password to orchestrator_run.json (CLAUDE.md rule 16). It also keyed one
    origin as two.
    """

    @pytest.mark.parametrize("url,expected", [
        ("https://u:p4ssw0rd@example.com/", "https://example.com"),
        ("https://user@example.com:8443/x", "https://example.com:8443"),
        ("https://example.com/", "https://example.com"),
        ("HTTPS://EXAMPLE.COM:8443/", "https://example.com:8443"),
        ("https://u:p@[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
        ("https://@/", None),
        ("not a url", None),
    ])
    def test_userinfo_is_never_part_of_an_origin(self, url, expected):
        assert orch._origin_of(url) == expected

    def test_a_credential_bearing_subject_does_not_leak_into_the_skip_reason(self, outdir):
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        url = "https://admin:hunter2@example.com/"
        orchestrator._note_reachability("http_analyzer", url, {"status": "unreachable"})
        reason = orchestrator._unreachable_reason(url)
        assert reason and "hunter2" not in reason and "admin:" not in reason

    def test_the_same_origin_with_and_without_credentials_is_one_key(self, outdir):
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        orchestrator._note_reachability(
            "http_analyzer", "https://u:p@example.com/", {"status": "unreachable"})
        assert orchestrator._unreachable_reason("https://example.com/") is not None
        assert len(orchestrator._unreachable_origins) == 1

    def test_an_answered_credential_bearing_url_clears_the_bare_origin_too(self, outdir):
        orchestrator = orch.Orchestrator(target=TARGET, output_dir=outdir)
        orchestrator._note_reachability(
            "http_analyzer", "https://example.com/", {"status": "unreachable"})
        orchestrator._note_reachability(
            "http_analyzer", "https://u:p@example.com/", {"status": "found"})
        assert orchestrator._unreachable_reason("https://example.com/") is None
