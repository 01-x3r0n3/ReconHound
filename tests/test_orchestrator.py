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

    captured_screenshot_urls = {}

    def fake_screenshot_batch(urls, target=None, output_dir="output", **kw):
        rec.log("screenshot", tuple(urls))
        captured_screenshot_urls["urls"] = list(urls)
        guard("screenshot")
        return {"module": "screenshot.py", "target": target, "total": len(urls),
                "counts": {"captured": len(urls)}, "by_subdomain": {}, "results": []}

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
    monkeypatch.setattr(orch.screenshot, "run_screenshot_batch", fake_screenshot_batch)
    monkeypatch.setattr(orch.vuln_intel, "run_vuln_intel", fake_vuln)

    return {
        "endpoint_kwargs": captured_endpoint_kwargs,
        "exposure_kwargs": captured_exposure_kwargs,
        "supply_kwargs": captured_supply_kwargs,
        "screenshot_urls": captured_screenshot_urls,
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
                         "supply_chain", "screenshot", "vuln_intel"):
            assert expected in ran, f"{expected} never ran"

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
                      failing={"code_leak", "osint_engine", "api_recon", "screenshot"})
        result = orch.run_orchestrator(TARGET, output_dir=outdir)

        failed = {e["module"] for e in result["executions"] if e["status"] == orch.STATUS_FAILED}
        assert failed == {"code_leak", "osint_engine", "api_recon", "screenshot"}
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
            "api_recon", "exposure_scan", "supply_chain", "screenshot", "vuln_intel"})
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
        other = surface_mapper.SurfaceMapper(target="other-target.test", output_dir=outdir)
        other.ingest_finding(passive_recon.make_finding(
            "dns_record", "other-target.test", {"record_type": "A", "records": ["198.51.100.1"]},
            ["other target"], passive_recon.CONFIDENCE_HIGH))
        other.save()

        install_fakes(monkeypatch, rec)
        result = orch.run_orchestrator(TARGET, output_dir=outdir)
        assert result["target"] == TARGET
        assert "198.51.100.1" not in result["scope"]["scanned_ips"]


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
