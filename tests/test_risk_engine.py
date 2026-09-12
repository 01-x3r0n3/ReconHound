"""
Tests for reconhound/risk_engine.py (ReconHound Module 20, per context.md's
build order — catalog item 20, build-order position 11).

Run with:  ./.venv/bin/python -m pytest tests/test_risk_engine.py -v

No network access anywhere in this file, and none is mocked, because
risk_engine.py never makes a request: it only evaluates evidence other
modules already produced.

Integration tests build their graphs by feeding realistic finding records —
the exact shapes the producing modules' make_finding() calls emit — through
the real surface_mapper.SurfaceMapper, rather than hand-writing graph
documents. That keeps the tests honest about the structures the engine
actually has to consume.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import risk_engine as risk
from reconhound.surface_mapper import SurfaceMapper

TARGET = "example.com"


def finding(finding_type, value, target=TARGET, evidence=None, confidence="HIGH",
            source="test_module.py", timestamp="2026-08-20T00:00:00+00:00", metadata=None):
    """A raw finding record in the exact shape every module's make_finding() produces."""
    return {
        "type": finding_type,
        "target": target,
        "value": value,
        "evidence": evidence if evidence is not None else [f"{finding_type} evidence"],
        "confidence": confidence,
        "source": source,
        "timestamp": timestamp,
        "metadata": metadata or {},
    }


@pytest.fixture
def build(tmp_path):
    """Ingest findings through the real surface mapper and return (mapper, output_dir)."""
    def _build(records, target=TARGET):
        mapper = SurfaceMapper(target=target, output_dir=str(tmp_path))
        mapper.ingest_many(records)
        return mapper, str(tmp_path)
    return _build


@pytest.fixture
def assess(build):
    def _assess(records, target=TARGET, **kwargs):
        mapper, output_dir = build(records, target=target)
        return risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False, **kwargs)
    return _assess


def signals_of(assessment, category):
    return [s for s in assessment["signals"] if s["category"] == category]


def asset_record(assessment, asset_id):
    for record in assessment["assessed_assets"]:
        if record["asset_id"] == asset_id:
            return record
    return None


# Reusable realistic producer records ---------------------------------------

def db_exposure_finding():
    """active_recon.py check_database_exposure — annotates metadata severity CRITICAL."""
    return finding(
        "db_exposure", {"ip": "93.184.216.34", "exposed_ports": [3306], "details": {"3306": {"service": "mysql"}}},
        source="active_recon.py",
        evidence=["TCP connect() to 93.184.216.34:3306 succeeded (mysql)"],
        metadata={"ip": "93.184.216.34", "severity": "CRITICAL"},
    )


def missing_headers_finding(url="https://example.com/"):
    """http_analyzer.analyze_security_headers output shape."""
    return finding(
        "http_security_headers",
        {"url": url, "headers": {
            "Content-Security-Policy": {"present": False, "value": None, "notes": ["header not present"]},
            "Strict-Transport-Security": {"present": False, "value": None, "notes": ["header not present"]},
            "X-Frame-Options": {"present": True, "value": "DENY", "notes": []},
        }},
        source="http_analyzer.py", metadata={"url": url},
    )


def self_signed_and_old_tls_finding(host=TARGET):
    """ssl_analyzer.run_ssl_analyzer's `tls_certificate_analysis` value shape."""
    return finding(
        "tls_certificate_analysis",
        {"host": host, "port": 443,
         "certificate": {"subject": {"CN": host}, "issuer": {"CN": host}, "serial_number": "1"},
         "validity": {"is_expired": False},
         "tls_version": {"version": "TLSv1.0", "is_outdated": True},
         "self_signed": {"self_signed": True, "confidence": "HIGH", "evidence": ["issuer==subject"]},
         "sans": {"sans": [host], "count": 1}},
        source="ssl_analyzer.py", timestamp="2026-08-20T00:00:01+00:00",
    )


def cve_finding(technology="nginx", version="1.18.0", applicability="version_range_confirmed",
                score=9.4, kev=None, exploitdb=None, confidence="HIGH", cve_id="CVE-2021-23017",
                summaries=None, timestamp="2026-08-20T00:00:05+00:00"):
    """vuln_intel.map_technology_to_cves' `vulnerability_intelligence` value shape."""
    return finding(
        "vulnerability_intelligence",
        {"cve_id": cve_id, "technology": technology, "version": version, "target": TARGET,
         "statement": f"Detected {technology} {version} — MAY be affected by {cve_id}.",
         "applicability": applicability, "confidence": confidence,
         "summaries": summaries if summaries is not None else ["Off-by-one in resolver allows remote code execution"],
         "cvss": [{"source": "nvd", "score": score, "severity": "CRITICAL", "vector": "AV:N"}] if score else [],
         "references": [], "published": "2021-05-25",
         "matched_sources": [{"source": "nvd", "version_match": "range_confirmed"}],
         "cisa_kev": kev, "exploitdb_references": exploitdb or [],
         "detection_evidence": ["Server header"],
         "note": "Technology/version-to-CVE match is vulnerability intelligence, not confirmed exploitability."},
        source="vuln_intel.py", confidence=confidence, timestamp=timestamp,
        metadata={"technology": technology, "version": version, "cve_id": cve_id,
                  "applicability": applicability, "cisa_kev_listed": bool(kev),
                  "exploitdb_reference_count": len(exploitdb or [])},
    )


def tech_finding(technology="nginx", version="1.18.0", source="tech_fingerprint.py",
                 confidence="HIGH", timestamp="2026-08-20T00:00:02+00:00"):
    return finding("tech_fingerprint_detected",
                   {"technology": technology, "category": "server", "version": version,
                    "url": "https://example.com/"},
                   source=source, confidence=confidence, timestamp=timestamp)


def exposure_finding(url, category, discovery_type="confirmed_exposure", confidence="HIGH",
                     timestamp="2026-08-20T00:00:03+00:00"):
    """exposure_scan.py's `exposure_finding` value shape."""
    return finding("exposure_finding",
                   {"url": url, "path": "/x", "method": "GET", "status_code": 200,
                    "exposure_category": category, "discovery_type": discovery_type,
                    "confidence": confidence, "excerpt": "", "error_page_indicators": []},
                   source="exposure_scan.py", confidence=confidence, timestamp=timestamp,
                   metadata={"exposure_category": category, "discovery_type": discovery_type, "url": url})


# ---------------------------------------------------------------------------
# Severity vocabulary and arithmetic
# ---------------------------------------------------------------------------

class TestSeverityModel:
    def test_severity_ladder_matches_context_md(self):
        assert sorted(risk.VALID_SEVERITIES, key=risk.severity_rank) == \
            ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_shift_severity_clamps_at_both_ends(self):
        assert risk.shift_severity("CRITICAL", 3) == "CRITICAL"
        assert risk.shift_severity("INFO", -3) == "INFO"
        assert risk.shift_severity("MEDIUM", 2) == "CRITICAL"

    def test_cap_severity_never_raises(self):
        assert risk.cap_severity("CRITICAL", "MEDIUM") == "MEDIUM"
        assert risk.cap_severity("LOW", "CRITICAL") == "LOW"

    def test_unknown_confidence_is_treated_as_low_not_favourably(self):
        assert risk.normalize_confidence(None) == "LOW"
        assert risk.normalize_confidence("VERY HIGH") == "LOW"

    def test_confidence_aggregation_matches_context_md_section_8(self):
        # A single weak signal stays LOW; independent converging signals raise it.
        assert risk.aggregate_confidence([{"source": "a", "confidence": "LOW"}]) == "LOW"
        assert risk.aggregate_confidence([{"source": "a", "confidence": "LOW"},
                                          {"source": "b", "confidence": "LOW"}]) == "MEDIUM"
        assert risk.aggregate_confidence([{"source": "a", "confidence": "MEDIUM"},
                                          {"source": "b", "confidence": "MEDIUM"}]) == "HIGH"
        assert risk.aggregate_confidence([]) == "LOW"


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

class TestIngestion:
    def test_accepts_a_live_surface_mapper(self, build):
        mapper, output_dir = build([db_exposure_finding()])
        assessment = risk.RiskEngine(graph=mapper, output_dir=output_dir).assess()
        assert assessment["target"] == TARGET
        assert assessment["summary"]["signals"] > 0

    def test_accepts_a_state_dict_and_a_file_path(self, build, tmp_path):
        mapper, output_dir = build([db_exposure_finding()])
        mapper.save()
        from_dict = risk.RiskEngine(graph=mapper.state, output_dir=output_dir).assess()
        from_file = risk.RiskEngine(graph=os.path.join(output_dir, "surface_graph.json"),
                                     output_dir=output_dir).assess()
        assert from_dict["summary"]["signals"] == from_file["summary"]["signals"]

    def test_missing_graph_is_a_clear_fatal_error(self, tmp_path):
        with pytest.raises(risk.RiskEngineError, match="does not exist"):
            risk.RiskEngine(output_dir=str(tmp_path))

    def test_corrupt_graph_is_a_clear_fatal_error(self, tmp_path):
        path = os.path.join(str(tmp_path), "surface_graph.json")
        with open(path, "w") as handle:
            handle.write("{not json")
        with pytest.raises(risk.RiskEngineError, match="not valid JSON"):
            risk.RiskEngine(output_dir=str(tmp_path))

    def test_empty_graph_produces_an_empty_but_valid_assessment(self, tmp_path):
        assessment = risk.RiskEngine(graph={}, output_dir=str(tmp_path)).assess()
        assert assessment["summary"]["assets_assessed"] == 0
        assert assessment["investigation_queue"] == []
        assert assessment["errors"] == []

    def test_wrong_typed_graph_containers_are_recorded_not_accepted(self, tmp_path):
        assessment = risk.RiskEngine(
            graph={"target": TARGET, "assets": ["bogus"], "conflicts": 42},
            output_dir=str(tmp_path)).assess()
        errors = " ".join(e["error"] for e in assessment["errors"])
        assert "assets" in errors and "conflicts" in errors
        assert assessment["summary"]["assets_assessed"] == 0

    def test_invalid_settings_are_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="min_queue_severity"):
            risk.RiskEngine(graph={}, output_dir=str(tmp_path), min_queue_severity="URGENT")
        with pytest.raises(ValueError, match="negative"):
            risk.RiskEngine(graph={}, output_dir=str(tmp_path), stale_after_days=-1)


# ---------------------------------------------------------------------------
# Signal extraction against real producer shapes
# ---------------------------------------------------------------------------

class TestSignalExtraction:
    def test_db_exposure_is_critical_and_confirmed(self, assess):
        assessment = assess([db_exposure_finding()])
        signal = signals_of(assessment, "database_port_exposure")[0]
        assert signal["severity"] == "CRITICAL"
        assert signal["kind"] == risk.KIND_CONFIRMED
        assert signal["confirmed"] is True
        assert "exposed DB ports" in signal["severity_basis"]

    def test_producer_severity_annotation_is_honoured(self, assess):
        """active_recon.py annotates metadata severity, deferring correlation to this module."""
        record = finding("ipmi_exposure", {"ip": "10.0.0.1", "port": 623, "exposed": True},
                         source="active_recon.py", metadata={"severity": "CRITICAL"})
        signal = signals_of(assess([record]), "ipmi_exposure")[0]
        assert signal["severity"] == "CRITICAL"

    def test_missing_security_headers_is_medium(self, assess):
        signal = signals_of(assess([missing_headers_finding()]), "missing_security_headers")[0]
        assert signal["severity"] == "MEDIUM"
        assert "Content-Security-Policy" in signal["summary"]
        assert "Strict-Transport-Security" in signal["summary"]
        # A header that is present must not be reported as missing.
        assert "X-Frame-Options" not in signal["summary"]

    def test_present_headers_alone_produce_no_signal(self, assess):
        record = finding("http_security_headers",
                         {"url": "https://example.com/", "headers": {
                             "Content-Security-Policy": {"present": True, "value": "default-src 'self'"}}},
                         source="http_analyzer.py", metadata={"url": "https://example.com/"})
        assert signals_of(assess([record]), "missing_security_headers") == []

    def test_ssl_analyzer_dict_shapes_yield_tls_signals(self, assess):
        assessment = assess([self_signed_and_old_tls_finding()])
        assert signals_of(assessment, "self_signed_certificate")[0]["severity"] == "MEDIUM"
        assert signals_of(assessment, "outdated_tls_version")[0]["severity"] == "MEDIUM"

    def test_admin_panel_is_high_and_env_file_is_critical(self, assess):
        assessment = assess([
            exposure_finding("https://example.com/admin/", "administrative_panel"),
            exposure_finding("https://example.com/.env", "environment_file",
                             timestamp="2026-08-20T00:00:04+00:00"),
        ])
        assert signals_of(assessment, "exposed_administrative_panel")[0]["severity"] == "HIGH"
        assert signals_of(assessment, "exposed_credential_material")[0]["severity"] == "CRITICAL"

    def test_unconfirmed_exposure_is_an_indicator_at_low_severity(self, assess):
        """exposure_scan.py's own discovery_type vocabulary distinguishes confirmed from restricted."""
        assessment = assess([exposure_finding("https://example.com/.env", "environment_file",
                                               discovery_type="access_restricted")])
        assert signals_of(assessment, "exposed_credential_material") == []
        signal = signals_of(assessment, "sensitive_resource_present_not_readable")[0]
        assert signal["severity"] == "LOW"
        assert signal["kind"] == risk.KIND_INDICATOR

    def test_technology_detection_is_info(self, assess):
        signal = signals_of(assess([tech_finding()]), "technology_observation")[0]
        assert signal["severity"] == "INFO"
        assert signal["kind"] == risk.KIND_OBSERVATION

    def test_unrecognized_finding_type_is_preserved_as_info_not_dropped(self, assess):
        assessment = assess([finding("some_future_module_finding", {"detail": "x"}, source="future.py")])
        unclassified = [s for s in assessment["signals"] if s["category"].startswith("unclassified:")]
        assert len(unclassified) == 1
        assert unclassified[0]["severity"] == "INFO"
        assert "no risk rule matched" in " ".join(unclassified[0]["notes"])

    def test_negative_results_do_not_become_risk_signals(self, assess):
        """A 'checked and found nothing' record is negative-result memory, not a finding."""
        assessment = assess([
            finding("tech_fingerprint_checked_no_match", {"category": "cms", "url": "https://example.com/"},
                    source="tech_fingerprint.py", confidence="LOW"),
        ])
        assert assessment["summary"]["signals"] == 0

    def test_third_party_service_assets_produce_low_signals(self, assess):
        assessment = assess([
            finding("js_analyzer_external_service_reference",
                    {"vendor": "Stripe", "category": "payment", "host": "js.stripe.com",
                     "example_url": "https://js.stripe.com/v3"},
                    source="js_analyzer.py", confidence="MEDIUM",
                    metadata={"parent_js_url": "https://example.com/app.js"}),
        ])
        signal = signals_of(assessment, "third_party_dependency")[0]
        assert signal["severity"] == "LOW"
        assert signal["in_scope"] is False


# ---------------------------------------------------------------------------
# Evidence classes: observation / indicator / vuln intel / confirmed
# ---------------------------------------------------------------------------

class TestEvidenceClasses:
    def test_all_four_classes_are_representable(self, assess):
        assessment = assess([
            db_exposure_finding(),                                   # confirmed
            tech_finding(),                                          # observation
            cve_finding(),                                           # vulnerability intelligence
            finding("code_leak_exposure",
                    {"category": "api_key", "pattern_name": "aws_access_key_id",
                     "repository": "acme/app", "path": "prod.yml", "fingerprint_sha256": "abc",
                     "matched_via_queries": ["q1"]},
                    source="code_leak.py", confidence="MEDIUM",
                    timestamp="2026-08-20T00:00:06+00:00"),           # indicator
        ])
        classes = assessment["summary"]["signals_by_evidence_class"]
        assert classes[risk.KIND_CONFIRMED] >= 1
        assert classes[risk.KIND_OBSERVATION] >= 1
        assert classes[risk.KIND_VULN_INTEL] == 1
        assert classes[risk.KIND_INDICATOR] >= 1

    def test_a_cve_match_is_never_reported_as_confirmed(self, assess):
        signal = signals_of(assess([cve_finding(kev={"dateAdded": "2021-11-03"})]),
                            "vulnerability_intelligence")[0]
        assert signal["kind"] == risk.KIND_VULN_INTEL
        assert signal["confirmed"] is False

    def test_an_indicator_is_never_reported_as_confirmed(self, assess):
        record = finding("js_analyzer_secret_indicator",
                         {"category": "credential", "pattern_name": "private_key_block",
                          "redacted_value": "***", "fingerprint_sha256": "f1", "context": "..."},
                         source="js_analyzer.py", confidence="MEDIUM",
                         metadata={"parent_js_url": "https://example.com/app.js"})
        signal = signals_of(assess([record]), "secret_indicator_in_client_side_js")[0]
        assert signal["kind"] == risk.KIND_INDICATOR
        assert signal["confirmed"] is False

    def test_corroboration_never_promotes_an_indicator_to_confirmed(self, assess):
        """Two modules reporting the same leaked key raise confidence, not evidence class."""
        base = {"category": "api_key", "pattern_name": "aws_access_key_id", "repository": "acme/app",
                "path": "prod.yml", "fingerprint_sha256": "same-secret", "matched_via_queries": ["q1"]}
        assessment = assess([
            finding("code_leak_exposure", dict(base), source="code_leak.py", confidence="MEDIUM"),
            finding("code_leak_exposure", dict(base), source="code_leak.py", confidence="MEDIUM",
                    timestamp="2026-08-21T00:00:00+00:00"),
        ])
        signal = signals_of(assessment, "leaked_credential_in_public_code")[0]
        assert signal["kind"] == risk.KIND_INDICATOR
        assert signal["confirmed"] is False


# ---------------------------------------------------------------------------
# Confidence handling (context.md §8)
# ---------------------------------------------------------------------------

class TestConfidenceHandling:
    def test_low_confidence_indicator_cannot_be_presented_above_medium(self, assess):
        record = finding("code_leak_exposure",
                         {"category": "credential", "pattern_name": "generic_password",
                          "repository": "acme/x", "path": "a.yml", "fingerprint_sha256": "z",
                          "matched_via_queries": ["q"]},
                         source="code_leak.py", confidence="LOW")
        signal = signals_of(assess([record]), "leaked_credential_in_public_code")[0]
        assert signal["base_severity"] == "CRITICAL"
        assert signal["severity"] == "MEDIUM"
        assert any("capped at MEDIUM" in line for line in signal["rationale"])

    def test_high_confidence_evidence_is_not_capped(self, assess):
        signal = signals_of(assess([db_exposure_finding()]), "database_port_exposure")[0]
        assert signal["severity"] == "CRITICAL"

    def test_cap_is_applied_after_every_escalation(self, assess):
        """CVSS 10 + KEV + RCE wording still cannot outrun unknown-version evidence."""
        signal = signals_of(assess([cve_finding(
            version=None, applicability="version_unknown_cannot_confirm", score=10.0,
            kev={"dateAdded": "2021-01-01"}, exploitdb=[{"id": "1"}],
            summaries=["unauthenticated remote code execution"])]), "vulnerability_intelligence")[0]
        assert signal["confidence"] == "LOW"
        assert signal["severity"] == "MEDIUM"
        assert signal["confirmed"] is False


# ---------------------------------------------------------------------------
# Vulnerability intelligence
# ---------------------------------------------------------------------------

class TestVulnerabilityIntelligence:
    def test_cvss_score_maps_on_the_standard_scale(self):
        for score, expected in ((9.8, "CRITICAL"), (7.5, "HIGH"), (5.0, "MEDIUM"), (2.0, "LOW")):
            result = risk.classify_vulnerability_intelligence(
                {"cvss": [{"source": "nvd", "score": score}], "applicability": "version_range_confirmed",
                 "confidence": "HIGH", "summaries": []}, {})
            assert result["base_severity"] == expected

    def test_unknown_severity_is_held_at_medium_and_flagged(self):
        result = risk.classify_vulnerability_intelligence(
            {"cvss": [], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "summaries": []}, {})
        assert result["base_severity"] == "MEDIUM"
        assert result["severity_unknown"] is True
        assert any("explicitly unknown severity" in note for note in result["notes"])

    def test_kev_and_exploitdb_are_not_counted_twice(self):
        result = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "cisa_kev": {"dateAdded": "x"}, "exploitdb_references": [{"id": "1"}, {"id": "2"}],
             "summaries": []}, {})
        assert sum(f["steps"] for f in result["factors"]) == 1
        assert any("not counted twice" in note for note in result["notes"])

    def test_exploitdb_alone_still_counts_once(self):
        result = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "cisa_kev": None, "exploitdb_references": [{"id": "1"}], "summaries": []}, {})
        assert [f["factor"] for f in result["factors"]] == ["public_exploit_exists"]

    def test_rce_wording_escalates_only_when_the_version_is_confirmed(self):
        confirmed = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "summaries": ["allows remote code execution"]}, {})
        unconfirmed = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "keyword_match_version_unconfirmed",
             "confidence": "MEDIUM", "summaries": ["allows remote code execution"]}, {})
        assert any(f["factor"] == "rce_class_vulnerability" for f in confirmed["factors"])
        assert not any(f["factor"] == "rce_class_vulnerability" for f in unconfirmed["factors"])
        assert any("without escalation" in note for note in unconfirmed["notes"])

    def test_applicability_ceilings_bound_confidence(self):
        for applicability, expected in (("version_range_confirmed", "HIGH"),
                                        ("keyword_match_version_unconfirmed", "MEDIUM"),
                                        ("version_unknown_cannot_confirm", "LOW"),
                                        ("something_new", "LOW")):
            result = risk.classify_vulnerability_intelligence(
                {"cvss": [{"score": 9.8}], "applicability": applicability, "confidence": "HIGH",
                 "summaries": []}, {})
            assert result["confidence"] == expected


# ---------------------------------------------------------------------------
# Conflict preservation (context.md §8)
# ---------------------------------------------------------------------------

class TestConflictHandling:
    def test_version_conflict_suspends_the_dependent_cve_assessment(self, assess):
        assessment = assess([
            tech_finding(version="1.18.0", source="tech_fingerprint.py"),
            tech_finding(version="1.25.3", source="http_analyzer.py", confidence="MEDIUM",
                         timestamp="2026-08-20T00:00:03+00:00"),
            cve_finding(technology="nginx", version="1.18.0"),
        ])
        suspended = assessment["suspended_signals"]
        assert len(suspended) == 1
        assert suspended[0]["category"] == "vulnerability_intelligence"
        assert "suspended" in suspended[0]["reason"]
        # Preserved and reported, but driving nothing.
        assert signals_of(assessment, "vulnerability_intelligence")[0]["suspended"] is True
        assert assessment["investigation_queue"] == []

    def test_the_suspended_finding_and_its_conflict_are_both_preserved(self, assess):
        assessment = assess([
            tech_finding(version="1.18.0", source="tech_fingerprint.py"),
            tech_finding(version="1.25.3", source="http_analyzer.py", confidence="MEDIUM",
                         timestamp="2026-08-20T00:00:03+00:00"),
            cve_finding(technology="nginx", version="1.18.0"),
        ])
        signal = signals_of(assessment, "vulnerability_intelligence")[0]
        assert signal["cve_id"] == "CVE-2021-23017"
        assert signal["conflicts"] and signal["conflicts"][0]["attribute"] == "version"
        assert assessment["unresolved_conflicts"]
        # Both disputed values survive.
        values = {o["value"] for o in assessment["unresolved_conflicts"][0]["observations"]}
        assert values == {"1.18.0", "1.25.3"}

    def test_without_a_conflict_the_same_cve_drives_the_score(self, assess):
        assessment = assess([tech_finding(version="1.18.0"), cve_finding(technology="nginx")])
        assert assessment["suspended_signals"] == []
        assert signals_of(assessment, "vulnerability_intelligence")[0]["severity"] == "CRITICAL"
        assert any(entry["severity"] == "CRITICAL" for entry in assessment["investigation_queue"])

    def test_a_conflict_on_an_unrelated_technology_does_not_suspend(self, assess):
        assessment = assess([
            tech_finding(technology="WordPress", version="6.4", source="tech_fingerprint.py"),
            tech_finding(technology="WordPress", version="5.1", source="http_analyzer.py",
                         confidence="MEDIUM", timestamp="2026-08-20T00:00:03+00:00"),
            cve_finding(technology="nginx", version="1.18.0"),
        ])
        assert assessment["suspended_signals"] == []


# ---------------------------------------------------------------------------
# Relationship-based correlation (context.md §9)
# ---------------------------------------------------------------------------

class TestRelationshipCorrelation:
    def test_named_transport_cluster_escalates_once(self, assess):
        """context.md's own example: missing headers + self-signed + outdated TLS."""
        assessment = assess([missing_headers_finding(), self_signed_and_old_tls_finding(),
                             finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                                      source="passive_recon.py", timestamp="2026-08-20T00:00:09+00:00")])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "HIGH"           # MEDIUM + exactly one step
        assert any("weak_transport_security_cluster" in line for line in host["rationale"])

    def test_overlapping_escalation_reasons_are_not_summed(self, assess):
        assessment = assess([missing_headers_finding(), self_signed_and_old_tls_finding()])
        host = asset_record(assessment, "hostname:example.com")
        applied = [line for line in host["rationale"] if "one escalation of" in line]
        assert len(applied) == 1
        assert "1 step(s)" in applied[0]

    def test_many_converging_medium_signals_combine_into_critical(self, assess):
        """context.md §9: several MEDIUM/LOW signals converging on one asset can combine into CRITICAL."""
        records = [
            missing_headers_finding(),
            self_signed_and_old_tls_finding(),
            finding("http_cookie_flags",
                    {"url": "https://example.com/",
                     "cookies": [{"name": "sid", "http_only": False, "secure": False,
                                  "samesite": None, "issues": ["missing HttpOnly", "missing Secure"]}]},
                    source="http_analyzer.py", metadata={"url": "https://example.com/"},
                    timestamp="2026-08-20T00:00:10+00:00"),
            finding("error_page_intelligence",
                    {"url": "https://example.com/x", "indicators": ["stack trace", "framework version"]},
                    source="exposure_scan.py", metadata={"url": "https://example.com/x"},
                    timestamp="2026-08-20T00:00:11+00:00"),
            finding("snmp_exposure", {"ip": "93.184.216.34", "port": 161,
                                       "accepted": [{"community": "public"}], "communities_tried": ["public"]},
                    source="active_recon.py", timestamp="2026-08-20T00:00:12+00:00"),
            finding("smtp_enumeration", {"ip": "93.184.216.34", "port": 25,
                                          "vrfy_supported": True, "expn_supported": False},
                    source="active_recon.py", timestamp="2026-08-20T00:00:13+00:00"),
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py", timestamp="2026-08-20T00:00:14+00:00"),
        ]
        host = asset_record(assess(records), "hostname:example.com")
        assert host["severity"] == "CRITICAL"
        assert host["contributing_signal_count"] >= 6
        assert any("converge on this asset" in line for line in host["rationale"])

    def test_port_level_signals_roll_up_through_the_ip_to_the_hostname(self, assess):
        """context.md §7's hierarchy runs Domain -> IP -> Port; a port weakness belongs to the host."""
        assessment = assess([
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py"),
            db_exposure_finding(),
        ])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "CRITICAL"
        assert host["related_signal_count"] >= 1
        assert any("hostname_to_ip" in line for line in host["rationale"])

    def test_explanation_names_the_relationship_a_signal_arrived_through(self, assess):
        assessment = assess([
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py"),
            finding("snmp_exposure", {"ip": "93.184.216.34", "port": 161,
                                       "accepted": [{"community": "public"}]},
                    source="active_recon.py", timestamp="2026-08-20T00:00:15+00:00"),
        ])
        host = asset_record(assessment, "hostname:example.com")
        assert any("via ip_to_service -> hostname_to_ip" in line for line in host["rationale"])

    def test_a_single_signal_asset_is_not_escalated(self, assess):
        host = asset_record(assess([missing_headers_finding()]), "endpoint:https://example.com/")
        assert host["severity"] == "MEDIUM"
        assert not any("escalation" in line for line in host["rationale"])


# ---------------------------------------------------------------------------
# Double-counting / duplicate handling
# ---------------------------------------------------------------------------

class TestNoDoubleCounting:
    def test_the_same_fact_from_two_modules_is_one_signal_with_two_sources(self, assess):
        assessment = assess([
            missing_headers_finding(),
            finding("http_security_headers",
                    {"url": "https://example.com/", "headers": {
                        "Content-Security-Policy": {"present": False},
                        "Strict-Transport-Security": {"present": False},
                        "X-Frame-Options": {"present": True, "value": "DENY"}}},
                    source="tech_fingerprint.py", metadata={"url": "https://example.com/"},
                    timestamp="2026-08-21T00:00:00+00:00"),
        ])
        signals = signals_of(assessment, "missing_security_headers")
        assert len(signals) == 1
        assert set(signals[0]["corroborating_sources"]) == {"http_analyzer.py", "tech_fingerprint.py"}

    def test_corroboration_raises_confidence_rather_than_convergence_count(self, assess):
        assessment = assess([
            missing_headers_finding(),
            finding("http_security_headers",
                    {"url": "https://example.com/", "headers": {
                        "Content-Security-Policy": {"present": False},
                        "Strict-Transport-Security": {"present": False},
                        "X-Frame-Options": {"present": True, "value": "DENY"}}},
                    source="crawler.py", confidence="MEDIUM",
                    metadata={"url": "https://example.com/"}, timestamp="2026-08-21T00:00:00+00:00"),
        ])
        endpoint = asset_record(assessment, "endpoint:https://example.com/")
        assert endpoint["contributing_signal_count"] == 1
        assert endpoint["severity"] == "MEDIUM"
        signal = signals_of(assessment, "missing_security_headers")[0]
        assert any("corroborated" in line for line in signal["rationale"])

    def test_an_exact_duplicate_finding_cannot_inflate_a_score(self, assess):
        once = assess([db_exposure_finding()])
        twice = assess([db_exposure_finding(), db_exposure_finding()])
        assert once["summary"]["signals"] == twice["summary"]["signals"]
        assert (asset_record(once, "ip:93.184.216.34")["severity"]
                == asset_record(twice, "ip:93.184.216.34")["severity"])


# ---------------------------------------------------------------------------
# Prioritization
# ---------------------------------------------------------------------------

class TestPrioritization:
    def test_queue_is_ordered_critical_first(self, assess):
        assessment = assess([
            db_exposure_finding(),
            missing_headers_finding(),
            exposure_finding("https://example.com/admin/", "administrative_panel"),
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py", timestamp="2026-08-20T00:00:20+00:00"),
        ])
        ranks = [risk.severity_rank(entry["severity"]) for entry in assessment["investigation_queue"]]
        assert ranks == sorted(ranks, reverse=True)
        assert assessment["investigation_queue"][0]["rank"] == 1

    def test_every_queue_entry_explains_its_score(self, assess):
        assessment = assess([db_exposure_finding(), missing_headers_finding()])
        for entry in assessment["investigation_queue"]:
            assert entry["explanation"]
            assert entry["top_signals"]
            assert "prioritization assessment" in entry["note"]

    def test_min_severity_filters_the_queue_without_dropping_evidence(self, assess):
        records = [db_exposure_finding(), missing_headers_finding()]
        low = assess(records)
        high = assess(records, min_queue_severity="CRITICAL")
        low_severities = {e["severity"] for e in low["investigation_queue"]}
        high_severities = {e["severity"] for e in high["investigation_queue"]}
        assert "MEDIUM" in low_severities and high_severities == {"CRITICAL"}
        assert len(high["investigation_queue"]) < len(low["investigation_queue"])
        # Filtering the queue must not remove any evidence from the assessment.
        assert high["summary"]["signals"] == low["summary"]["signals"]
        assert len(high["assessed_assets"]) == len(low["assessed_assets"])

    def test_info_only_assets_are_not_queued(self, assess):
        assessment = assess([tech_finding()])
        assert assessment["investigation_queue"] == []
        assert any(r["asset_type"] == "technology" for r in assessment["assessed_assets"])

    def test_queue_reports_contributing_and_total_signal_counts_separately(self, assess):
        assessment = assess([
            finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                    source="passive_recon.py"),
            db_exposure_finding(),
        ])
        entry = [e for e in assessment["investigation_queue"] if e["asset_id"] == "ip:93.184.216.34"][0]
        assert entry["total_signal_count"] >= entry["contributing_signal_count"]

    def test_ordering_is_deterministic_across_runs(self, build):
        mapper, output_dir = build([db_exposure_finding(), missing_headers_finding(),
                                     exposure_finding("https://example.com/admin/", "administrative_panel")])
        first = risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False)
        second = risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False)
        first.pop("generated_at")
        second.pop("generated_at")
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------------------------------------------------------------------------
# Scope enforcement (context.md §16)
# ---------------------------------------------------------------------------

class TestScopeEnforcement:
    def test_out_of_scope_asset_is_never_placed_in_the_queue(self, assess):
        assessment = assess([exposure_finding("https://evil-cdn.net/.env", "environment_file")])
        out_of_scope = [r for r in assessment["assessed_assets"] if r["in_scope"] is False]
        assert out_of_scope
        queued = {entry["asset_id"] for entry in assessment["investigation_queue"]}
        assert not queued & {r["asset_id"] for r in out_of_scope}

    def test_out_of_scope_evidence_is_still_assessed_and_reported(self, assess):
        assessment = assess([exposure_finding("https://evil-cdn.net/.env", "environment_file")])
        assert signals_of(assessment, "exposed_credential_material")
        assert assessment["out_of_scope_assets"]
        assert assessment["summary"]["out_of_scope_assets"] >= 1

    def test_in_scope_equivalent_finding_is_queued(self, assess):
        assessment = assess([exposure_finding("https://example.com/.env", "environment_file")])
        assert any(entry["severity"] == "CRITICAL" for entry in assessment["investigation_queue"])


# ---------------------------------------------------------------------------
# Staleness
# ---------------------------------------------------------------------------

class TestStaleness:
    def _records(self):
        return [
            exposure_finding("https://example.com/admin/", "administrative_panel",
                             timestamp="2026-01-01T00:00:00+00:00"),
            exposure_finding("https://example.com/.git/config", "version_control",
                             timestamp="2026-08-20T00:00:00+00:00"),
        ]

    def test_age_is_reported_even_without_a_staleness_policy(self, assess):
        assessment = assess(self._records())
        ages = {s["category"]: s["age_days"] for s in assessment["signals"]}
        assert ages["exposed_administrative_panel"] > 200
        assert all(not s["stale"] for s in assessment["signals"])

    def test_stale_signals_are_flagged_and_stop_driving_the_score(self, assess):
        assessment = assess(self._records(), stale_after_days=30)
        stale = [s for s in assessment["signals"] if s["stale"]]
        assert [s["category"] for s in stale] == ["exposed_administrative_panel"]
        queued = {entry["asset_id"] for entry in assessment["investigation_queue"]}
        assert "endpoint:https://example.com/admin/" not in queued

    def test_stale_evidence_is_preserved_and_explained(self, assess):
        assessment = assess(self._records(), stale_after_days=30)
        endpoint = asset_record(assessment, "endpoint:https://example.com/admin/")
        assert endpoint["severity"] == "INFO"
        assert any("stale, not scored" in line for line in endpoint["rationale"])
        assert endpoint["stale_signal_ids"]

    def test_staleness_is_measured_against_the_graph_not_the_clock(self, assess):
        """Two runs of the same graph must agree regardless of when they run."""
        first = assess(self._records(), stale_after_days=30)
        second = assess(self._records(), stale_after_days=30)
        assert [s["age_days"] for s in first["signals"]] == [s["age_days"] for s in second["signals"]]


# ---------------------------------------------------------------------------
# Malformed and unexpected input
# ---------------------------------------------------------------------------

class TestMalformedInput:
    def test_one_malformed_asset_does_not_destroy_the_assessment(self, tmp_path):
        state = {
            "target": TARGET,
            "assets": {
                "broken": "not-a-dict",
                "hostname:example.com": {
                    "id": "hostname:example.com", "asset_type": "hostname", "value": TARGET,
                    "attributes": {"tls_self_signed": {"value": True, "confidence": "HIGH",
                                                        "sources": ["ssl_analyzer.py"]}},
                    "in_scope": True, "sources": ["ssl_analyzer.py"], "observation_ids": [],
                    "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00",
                },
            },
            "relationships": {}, "observations": {}, "conflicts": {},
            "updated_at": "2026-08-20T00:00:00+00:00",
        }
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        assert any("not a JSON object" in e.get("error", "") for e in assessment["errors"])
        assert signals_of(assessment, "self_signed_certificate")

    def test_finding_detail_of_the_wrong_type_degrades_to_unclassified(self, tmp_path):
        state = {
            "target": TARGET,
            "assets": {"finding:x:1": {
                "id": "finding:x:1", "asset_type": "finding",
                "value": {"finding_type": "exposure_finding", "detail": "a-string-not-a-dict"},
                "attributes": {}, "sources": ["exposure_scan.py"], "observation_ids": [],
                "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {}, "conflicts": {},
        }
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        assert [s["category"] for s in assessment["signals"]] == ["unclassified:exposure_finding"]

    def test_missing_optional_fields_degrade_gracefully(self, assess):
        record = {"type": "db_exposure", "value": {"ip": "1.2.3.4", "exposed_ports": [3306]},
                  "source": "active_recon.py"}
        assessment = assess([record])
        assert signals_of(assessment, "database_port_exposure")

    def test_invalid_confidence_in_the_graph_is_treated_as_low(self, assess):
        record = finding("code_leak_exposure",
                         {"category": "api_key", "pattern_name": "p", "repository": "r",
                          "path": "a", "fingerprint_sha256": "f", "matched_via_queries": ["q"]},
                         source="code_leak.py", confidence="EXTREMELY HIGH")
        signal = signals_of(assess([record]), "leaked_credential_in_public_code")[0]
        assert signal["confidence"] == "LOW"
        assert signal["severity"] == "MEDIUM"

    def test_a_finding_with_no_observations_still_yields_a_signal(self, tmp_path):
        state = {
            "target": TARGET,
            "assets": {"finding:db:1": {
                "id": "finding:db:1", "asset_type": "finding",
                "value": {"finding_type": "db_exposure", "detail": {"ip": "1.2.3.4", "exposed_ports": [3306]}},
                "attributes": {}, "sources": ["active_recon.py"], "observation_ids": ["gone"],
                "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {}, "conflicts": {},
        }
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        signal = signals_of(assessment, "database_port_exposure")[0]
        assert signal["sources"] == ["active_recon.py"]
        assert signal["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# JSON safety and persistence
# ---------------------------------------------------------------------------

class TestJsonSafetyAndPersistence:
    def test_assessment_is_pure_json_with_no_default_fallback(self, assess):
        assessment = assess([db_exposure_finding(), cve_finding(), missing_headers_finding()])
        json.dumps(assessment, default=None)

    def test_non_json_safe_graph_values_are_coerced(self, tmp_path):
        import datetime

        class Weird:
            def __repr__(self):
                return "<weird>"

        state = {
            "target": TARGET,
            "assets": {"endpoint:x": {
                "id": "endpoint:x", "asset_type": "endpoint", "value": Weird(),
                "attributes": {"category": {"value": "admin", "confidence": "HIGH",
                                             "sources": {"exposure_scan.py"},
                                             "timestamp": datetime.datetime(2026, 8, 20)}},
                "in_scope": True, "sources": [Weird()], "observation_ids": [],
                "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {}, "conflicts": {},
        }
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        json.dumps(assessment, default=None)
        assert signals_of(assessment, "administrative_endpoint")

    def test_nan_and_infinity_are_not_emitted(self, tmp_path):
        state = {"target": TARGET, "assets": {"finding:v:1": {
            "id": "finding:v:1", "asset_type": "finding", "value": {
                "finding_type": "vulnerability_intelligence",
                "detail": {"cve_id": "CVE-1", "technology": "x", "applicability": "version_range_confirmed",
                            "confidence": "HIGH", "cvss": [{"score": float("nan")}], "summaries": []}},
            "attributes": {}, "sources": ["vuln_intel.py"], "observation_ids": [], "confidence": "HIGH",
            "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {}, "conflicts": {}}
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        blob = json.dumps(assessment, default=None)
        assert "NaN" not in blob and "Infinity" not in blob

    def test_run_persists_valid_json_atomically(self, build):
        mapper, output_dir = build([db_exposure_finding()])
        assessment = risk.RiskEngine(graph=mapper, output_dir=output_dir).run()
        path = assessment["output_path"]
        with open(path) as handle:
            reloaded = json.load(handle)
        assert reloaded["module"] == "risk_engine.py"
        assert not [f for f in os.listdir(output_dir) if f.startswith(".risk_assessment_")]

    def test_repeated_runs_do_not_accumulate_state(self, build):
        mapper, output_dir = build([db_exposure_finding(), missing_headers_finding()])
        engine = risk.RiskEngine(graph=mapper, output_dir=output_dir)
        first = engine.run()
        second = engine.run()
        for record in (first, second):
            record.pop("generated_at")
            record.pop("output_path")
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

class TestProvenance:
    def test_every_signal_carries_source_evidence_and_observation_ids(self, assess):
        assessment = assess([db_exposure_finding(), missing_headers_finding()])
        for signal in assessment["signals"]:
            assert signal["sources"]
            assert signal["provenance"]
            assert signal["severity_basis"]
            assert signal["rationale"]

    def test_original_module_evidence_strings_survive_into_the_signal(self, assess):
        signal = signals_of(assess([db_exposure_finding()]), "database_port_exposure")[0]
        assert any("TCP connect()" in item for item in signal["evidence"])

    def test_observation_ids_link_back_to_the_graph(self, build):
        mapper, output_dir = build([db_exposure_finding()])
        assessment = risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False)
        signal = signals_of(assessment, "database_port_exposure")[0]
        assert signal["observation_ids"]
        for observation_id in signal["observation_ids"]:
            assert observation_id in mapper.state["observations"]

    def test_severity_basis_cites_the_architecture(self, assess):
        assessment = assess([db_exposure_finding(), missing_headers_finding(),
                             exposure_finding("https://example.com/admin/", "administrative_panel")])
        for signal in assessment["signals"]:
            assert "context.md" in signal["severity_basis"] or "annotated" in signal["severity_basis"]


# ---------------------------------------------------------------------------
# Security posture
# ---------------------------------------------------------------------------

class TestSecurityPosture:
    def test_module_has_no_network_or_execution_capability(self):
        source = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    "reconhound", "risk_engine.py")).read()
        for forbidden in ("import socket", "import requests", "import urllib", "import subprocess",
                          "os.system", "eval(", "exec("):
            assert forbidden not in source, f"risk_engine.py must not contain {forbidden!r}"

    def test_assessment_never_claims_exploitability(self, assess):
        assessment = assess([cve_finding(kev={"dateAdded": "x"}, exploitdb=[{"id": "1"}]),
                             db_exposure_finding()])
        blob = json.dumps(assessment).lower()
        assert "confirmed exploitable" not in blob
        assert "prioritization assessment" in blob

    def test_no_signal_is_marked_confirmed_unless_directly_observed(self, assess):
        assessment = assess([cve_finding(), tech_finding(),
                             finding("code_leak_exposure",
                                      {"category": "token", "pattern_name": "p", "repository": "r",
                                       "path": "a", "fingerprint_sha256": "f", "matched_via_queries": ["q"]},
                                      source="code_leak.py")])
        for signal in assessment["signals"]:
            if signal["kind"] in (risk.KIND_INDICATOR, risk.KIND_VULN_INTEL):
                assert signal["confirmed"] is False


# ===========================================================================
# Hardening regression tests (audit of 2026-09-10/11). Each class below pins
# a defect that was reproduced against the original implementation.
# ===========================================================================

def assess_fresh(records, target=TARGET, **kwargs):
    """
    Assess `records` in a brand-new graph.

    The `assess` fixture builds its SurfaceMapper on the test's single
    tmp_path, and SurfaceMapper adopts a surface_graph.json it finds there —
    so a second call inside one test assesses the *union* of both calls'
    records. Comparisons between two independent graphs must use this.
    """
    import tempfile
    output_dir = tempfile.mkdtemp()
    mapper = SurfaceMapper(target=target, output_dir=output_dir)
    mapper.ingest_many(records)
    return risk.run_risk_engine(graph=mapper, output_dir=output_dir, persist=False, **kwargs)


def admin_panel_on(host, timestamp="2026-08-20T00:00:03+00:00"):
    return finding("exposure_finding",
                   {"url": f"https://{host}/admin/", "path": "/admin/", "method": "GET", "status_code": 200,
                    "exposure_category": "administrative_panel", "discovery_type": "confirmed_exposure",
                    "confidence": "HIGH"},
                   target=host, source="exposure_scan.py", timestamp=timestamp,
                   metadata={"url": f"https://{host}/admin/"})


def dns_a(host, ip, timestamp="2026-08-20T00:00:00+00:00"):
    return finding("dns_record", {"record_type": "A", "records": [ip]}, target=host,
                   source="passive_recon.py", timestamp=timestamp)


def third_party_ref(i):
    return finding("js_analyzer_external_service_reference",
                   {"vendor": f"Vendor{i}", "category": "analytics", "host": f"cdn{i}.example.net"},
                   source="js_analyzer.py", confidence="HIGH",
                   metadata={"parent_js_url": "https://example.com/app.js"},
                   timestamp=f"2026-08-20T00:00:{10 + i:02d}+00:00")


class TestConvergenceCountsCategoriesNotInstances:
    """Repeated evidence of one class, or pure observations, must not escalate an asset."""

    def test_six_pages_missing_the_same_header_do_not_make_a_host_critical(self, assess):
        assessment = assess([missing_headers_finding(f"https://example.com/p{i}") for i in range(6)])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "MEDIUM"
        assert host["contributing_signal_count"] == 6
        assert host["convergent_categories"] == ["missing_security_headers"]
        assert host["escalation"] is None
        assert any("count once toward convergence" in line for line in host["rationale"])

    def test_thirty_cves_against_one_technology_do_not_escalate_by_count(self, assess):
        records = [tech_finding()] + [
            cve_finding(cve_id=f"CVE-2020-{1000 + i}", score=5.0,
                        summaries=["denial of service"], timestamp=f"2026-08-20T00:01:{i:02d}+00:00")
            for i in range(30)
        ]
        assessment = assess(records)
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "MEDIUM"
        assert host["vulnerability_intelligence_count"] == 30

    def test_third_party_dependencies_are_observations_and_never_converge(self, assess):
        assessment = assess([missing_headers_finding()] + [third_party_ref(i) for i in range(6)])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "MEDIUM"
        assert host["convergent_categories"] == ["missing_security_headers"]
        assert any("not counted as converging risk" in line for line in host["rationale"])

    def test_a_high_severity_observation_still_sets_the_peak(self, assess):
        record = finding("crawled_form",
                         {"action": "https://example.com/upload", "resolved_action": "https://example.com/upload",
                          "method": "POST", "classification": "file_upload", "inputs": []},
                         source="crawler.py", metadata={"source_page": "https://example.com/"})
        endpoint = asset_record(assess([record]), "endpoint:https://example.com/upload")
        assert endpoint["severity"] == "HIGH"
        assert endpoint["convergent_categories"] == []

    def test_distinct_categories_still_converge_as_context_md_requires(self, assess):
        """The original context.md example must keep working after the change."""
        assessment = assess([missing_headers_finding(), self_signed_and_old_tls_finding(),
                             dns_a(TARGET, "93.184.216.34", "2026-08-20T00:00:09+00:00")])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "HIGH"
        assert host["escalation"]["steps"] == 1
        assert set(host["convergent_categories"]) == {
            "missing_security_headers", "self_signed_certificate", "outdated_tls_version"}


class TestEscalationIsBoundedByItsOwnEvidence:
    def _low_leak(self, i):
        return finding("code_leak_exposure",
                       {"category": "api_key", "pattern_name": f"p{i}", "repository": "r", "path": f"f{i}",
                        "fingerprint_sha256": f"fp{i}", "matched_via_queries": ["q"]},
                       source="code_leak.py", confidence="LOW",
                       timestamp=f"2026-08-20T00:00:{i:02d}+00:00")

    def test_weak_indicators_cannot_borrow_confidence_from_an_unrelated_strong_signal(self, tmp_path):
        """Five LOW-confidence categories plus one HIGH-confidence LOW signal is not HIGH-confidence convergence."""
        graph = {"target": TARGET, "assets": {}, "relationships": {}, "observations": {}, "conflicts": {}}
        host = "hostname:example.com"
        graph["assets"][host] = {"id": host, "asset_type": "hostname", "value": TARGET, "in_scope": True,
                                 "attributes": {}, "sources": [], "observation_ids": [], "confidence": "HIGH",
                                 "last_seen": "2026-08-20T00:00:00+00:00"}
        low_categories = [
            ("http_security_headers", {"url": "https://example.com/", "headers": {
                "Content-Security-Policy": {"present": False}}}),
            ("http_cookie_flags", {"url": "https://example.com/", "cookies": [{"name": "s", "issues": ["missing Secure"]}]}),
            ("error_page_intelligence", {"url": "https://example.com/x", "indicators": ["stack trace"]}),
            ("smtp_enumeration", {"ip": "1.2.3.4", "port": 25, "vrfy_supported": True}),
            ("snmp_exposure", {"ip": "1.2.3.4", "port": 161, "accepted": [{"community": "public"}]}),
        ]
        for i, (ftype, detail) in enumerate(low_categories):
            fid = f"finding:{ftype}:{i}"
            graph["assets"][fid] = {"id": fid, "asset_type": "finding",
                                    "value": {"finding_type": ftype, "detail": detail},
                                    "attributes": {}, "sources": ["m.py"], "observation_ids": [],
                                    "confidence": "LOW", "last_seen": "2026-08-20T00:00:00+00:00"}
            graph["relationships"][f"rel:asset_to_finding:{host}->{fid}"] = {
                "rel_type": "asset_to_finding", "from_asset": host, "to_asset": fid}
        graph["assets"][host]["attributes"]["discovered_via_vhost_scan"] = {
            "value": True, "confidence": "HIGH", "sources": ["vhost_scanner.py"], "source": "vhost_scanner.py",
            "timestamp": "2026-08-20T00:00:00+00:00"}
        assessment = risk.RiskEngine(graph=graph, output_dir=str(tmp_path)).assess()
        record = asset_record(assessment, host)
        assert len(record["convergent_categories"]) == 6
        assert record["severity"] == "MEDIUM"
        assert record["confidence"] == "LOW"
        assert any("held at MEDIUM" in line for line in record["rationale"])

    def test_named_rule_is_bounded_by_its_weakest_required_category(self, assess):
        deprecated = finding("api_endpoint_deprecated",
                             {"url": "https://example.com/api/v1/x", "basis": "path_probe"},
                             source="api_recon.py", confidence="HIGH", timestamp="2026-08-20T00:00:07+00:00")
        weak_cve = cve_finding(version=None, applicability="version_unknown_cannot_confirm", score=7.5,
                               confidence="LOW", summaries=["dos"])
        host = asset_record(assess([deprecated, weak_cve, tech_finding()]), "hostname:example.com")
        assert host["severity"] == "MEDIUM"          # deprecated API is MEDIUM; the +1 rests on LOW evidence
        assert any("deprecated_api_with_known_cve' matched" in line for line in host["rationale"])
        assert any("held at MEDIUM" in line for line in host["rationale"])

    def test_escalation_from_a_medium_confidence_peak_cannot_reach_critical(self, assess):
        """HIGH-confidence MEDIUM signals converging around a MEDIUM-confidence HIGH peak stop at HIGH."""
        records = [missing_headers_finding(), self_signed_and_old_tls_finding(),
                   finding("http_cookie_flags",
                           {"url": "https://example.com/", "cookies": [{"name": "s", "issues": ["missing Secure"]}]},
                           source="http_analyzer.py", metadata={"url": "https://example.com/"},
                           timestamp="2026-08-20T00:00:10+00:00"),
                   finding("subdomain_takeover_indicator",
                           {"hostname": TARGET, "final_target": "x.s3.amazonaws.com", "provider": "AWS S3"},
                           source="surface_mapper.py", confidence="MEDIUM", timestamp="2026-08-20T00:00:11+00:00")]
        host = asset_record(assess(records), "hostname:example.com")
        assert host["severity"] == "HIGH"
        assert host["confidence"] == "MEDIUM"

    def test_asset_confidence_reflects_the_evidence_driving_its_severity(self, assess):
        records = [self._low_leak(0), tech_finding(confidence="HIGH")]
        host = asset_record(assess(records), "hostname:example.com")
        assert host["severity"] == "MEDIUM"
        assert host["confidence"] == "LOW"


class TestCorrelationRuleStructure:
    def test_two_credential_indicators_without_a_deprecated_api_do_not_match_the_rule(self, assess):
        assessment = assess([
            finding("code_leak_exposure", {"category": "api_key", "pattern_name": "aws", "repository": "acme/app",
                                           "path": "p.yml", "fingerprint_sha256": "abc", "matched_via_queries": ["q"]},
                    source="code_leak.py", confidence="HIGH"),
            finding("js_analyzer_secret_indicator", {"category": "token", "pattern_name": "jwt", "fingerprint_sha256": "f1"},
                    source="js_analyzer.py", confidence="HIGH", metadata={"parent_js_url": "https://example.com/app.js"}),
        ])
        host = asset_record(assessment, "hostname:example.com")
        assert not any("deprecated_api_with_leaked_credential" in line for line in host["rationale"])

    def test_deprecated_api_with_either_credential_indicator_matches(self, assess):
        deprecated = finding("api_endpoint_deprecated", {"url": "https://example.com/api/v1/x", "basis": "path_probe"},
                             source="api_recon.py", confidence="HIGH", timestamp="2026-08-20T00:00:07+00:00")
        secret = finding("js_analyzer_secret_indicator", {"category": "token", "pattern_name": "jwt", "fingerprint_sha256": "f1"},
                         source="js_analyzer.py", confidence="HIGH", metadata={"parent_js_url": "https://example.com/app.js"})
        host = asset_record(assess([deprecated, secret]), "hostname:example.com")
        assert any("deprecated_api_with_leaked_credential" in line for line in host["rationale"])

    def test_rule_matching_is_all_required_plus_any_alternative(self):
        rule = risk.CorrelationRule("r", required=("a", "b"), any_of=("c", "d"), steps=1, reason="")
        assert rule.matches(["a", "b", "c"]) == ["a", "b", "c"]
        assert rule.matches(["a", "b"]) == []
        assert rule.matches(["a", "c", "d"]) == []
        plain = risk.CorrelationRule("p", required=("a", "b"), steps=1, reason="")
        assert plain.matches(["b", "a"]) == ["a", "b"]


class TestAttributionFollowsContainmentOnly:
    """Cross-asset contamination through identity/reference links and shared infrastructure."""

    def test_a_vhosts_finding_never_crosses_a_shared_ip_onto_a_sibling_hostname(self, assess):
        assessment = assess([
            dns_a("a.example.com", "10.0.0.5"),
            finding("vhost_discovered", {"ip": "10.0.0.5", "port": 80, "hostname": "b.example.com"},
                    target="b.example.com", source="vhost_scanner.py"),
            admin_panel_on("b.example.com"),
        ])
        assert asset_record(assessment, "hostname:b.example.com")["severity"] == "HIGH"
        assert asset_record(assessment, "ip:10.0.0.5")["severity"] == "HIGH"
        sibling = asset_record(assessment, "hostname:a.example.com")
        assert sibling is None or sibling["severity"] == "INFO"

    def test_a_certificate_san_does_not_inherit_the_named_hosts_findings(self, assess):
        assessment = assess([
            finding("tls_san", "admin.example.com", target="api.example.com", source="passive_recon.py"),
            admin_panel_on("admin.example.com"),
        ])
        assert asset_record(assessment, "hostname:admin.example.com")["severity"] == "HIGH"
        observing = asset_record(assessment, "hostname:api.example.com")
        assert observing is None or observing["severity"] == "INFO"

    def test_a_cname_alias_does_not_inherit_its_targets_findings(self, assess):
        assessment = assess([
            finding("dns_record", {"record_type": "CNAME", "records": ["lb.example.com"]},
                    target="www.example.com", source="passive_recon.py"),
            admin_panel_on("lb.example.com"),
        ])
        www = asset_record(assessment, "hostname:www.example.com")
        assert www is None or www["severity"] == "INFO"

    def test_a_javascript_reference_does_not_import_a_foreign_hosts_exposure(self, assess):
        """An out-of-scope partner's exposed file referenced from our JS must not score our host."""
        assessment = assess([
            finding("js_analyzer_endpoint_reference", {"url": "https://api.partner.net/v1/x"},
                    source="js_analyzer.py", metadata={"parent_js_url": "https://example.com/app.js"}),
            finding("exposure_finding", {"url": "https://api.partner.net/v1/x", "path": "/v1/x", "method": "GET",
                                         "status_code": 200, "exposure_category": "environment_file",
                                         "discovery_type": "confirmed_exposure", "confidence": "HIGH"},
                    target="api.partner.net", source="exposure_scan.py", timestamp="2026-08-20T00:00:09+00:00"),
        ])
        ours = asset_record(assessment, "hostname:example.com")
        assert ours is None or ours["severity"] == "INFO"
        assert asset_record(assessment, "endpoint:https://api.partner.net/v1/x")["severity"] == "CRITICAL"
        assert "hostname:example.com" not in {e["asset_id"] for e in assessment["investigation_queue"]}

    def test_ip_level_signals_still_reach_every_resolving_hostname_below_the_bound(self, assess):
        records = [dns_a(f"h{i}.example.com", "10.0.0.1") for i in range(5)] + [
            finding("db_exposure", {"ip": "10.0.0.1", "exposed_ports": [3306]}, source="active_recon.py",
                    metadata={"severity": "CRITICAL"})]
        assessment = assess(records)
        for i in range(5):
            record = asset_record(assessment, f"hostname:h{i}.example.com")
            assert record["severity"] == "CRITICAL"
            assert any("attribution is ambiguous" in line and "5 hostnames" in line for line in record["rationale"])

    def test_ip_shared_beyond_the_bound_keeps_the_signal_on_the_ip_and_records_it(self, assess):
        n = risk.MAX_SHARED_IP_ROLLUP_HOSTNAMES + 1
        records = [dns_a(f"h{i}.example.com", "10.0.0.1") for i in range(n)] + [
            finding("db_exposure", {"ip": "10.0.0.1", "exposed_ports": [3306]}, source="active_recon.py",
                    metadata={"severity": "CRITICAL"})]
        assessment = assess(records)
        ip = asset_record(assessment, "ip:10.0.0.1")
        assert ip["severity"] == "CRITICAL"
        assert ip["shared_infrastructure"]["hostname_count"] == n
        assert ip["shared_infrastructure"]["rollup_to_hostnames"] == "suppressed"
        assert any("shared infrastructure" in line for line in ip["rationale"])
        signal = signals_of(assessment, "database_port_exposure")[0]
        assert any("not attributed to the" in note for note in signal["notes"])
        assert assessment["summary"]["shared_infrastructure_ips"] == 1
        queued = {e["asset_id"] for e in assessment["investigation_queue"]}
        assert "ip:10.0.0.1" in queued
        assert not any(a.startswith("hostname:h") for a in queued)

    def test_an_ips_finding_never_crosses_a_hostname_onto_the_other_ip_serving_it(self, assess):
        """A resolves to IP1 (DB port exposed) and is also a vhost on IP2: IP2 is not CRITICAL."""
        assessment = assess([
            dns_a("a.example.com", "10.0.0.1"),
            finding("vhost_discovered", {"ip": "10.0.0.2", "port": 80, "hostname": "a.example.com"},
                    target="a.example.com", source="vhost_scanner.py"),
            finding("db_exposure", {"ip": "10.0.0.1", "exposed_ports": [3306]}, source="active_recon.py",
                    metadata={"severity": "CRITICAL"}),
        ])
        assert asset_record(assessment, "ip:10.0.0.1")["severity"] == "CRITICAL"
        assert asset_record(assessment, "hostname:a.example.com")["severity"] == "CRITICAL"
        other_ip = asset_record(assessment, "ip:10.0.0.2")
        assert other_ip is None or "database_port_exposure" not in other_ip["categories"]

    def test_a_missing_ip_record_is_not_a_way_around_the_sibling_guard(self, build):
        mapper, output_dir = build([
            dns_a("a.example.com", "10.0.0.9"),
            finding("vhost_discovered", {"ip": "10.0.0.9", "port": 80, "hostname": "b.example.com"},
                    target="b.example.com", source="vhost_scanner.py"),
            admin_panel_on("b.example.com"),
        ])
        state = json.loads(json.dumps(mapper.state))
        del state["assets"]["ip:10.0.0.9"]
        assessment = risk.RiskEngine(graph=state, output_dir=output_dir).assess()
        assert asset_record(assessment, "hostname:b.example.com")["severity"] == "HIGH"
        assert asset_record(assessment, "hostname:a.example.com") is None

    def test_one_signal_reaching_an_asset_by_two_chains_counts_once(self, assess):
        assessment = assess([
            dns_a(TARGET, "1.2.3.4"),
            finding("vhost_discovered", {"ip": "1.2.3.4", "port": 80, "hostname": TARGET}, source="vhost_scanner.py"),
            finding("db_exposure", {"ip": "1.2.3.4", "exposed_ports": [3306]}, source="active_recon.py",
                    metadata={"severity": "CRITICAL"}),
        ])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "CRITICAL"
        assert host["signal_ids"].count(signals_of(assessment, "database_port_exposure")[0]["signal_id"]) == 1

    def test_cname_cycles_terminate_and_stay_local(self, assess):
        records = [finding("dns_record", {"record_type": "CNAME", "records": [f"c{(i + 1) % 20}.example.com"]},
                           target=f"c{i}.example.com", source="passive_recon.py") for i in range(20)]
        records.append(admin_panel_on("c0.example.com"))
        assessment = assess(records)
        assert sum(1 for r in assessment["assessed_assets"] if r["severity"] == "HIGH") == 2  # endpoint + c0

    def test_unknown_relationship_types_are_never_followed(self, tmp_path):
        graph = {"target": TARGET, "assets": {
            "hostname:a.example.com": {"id": "hostname:a.example.com", "asset_type": "hostname", "value": "a.example.com",
                                       "in_scope": True, "attributes": {}, "sources": [], "observation_ids": []},
            "hostname:b.example.com": {"id": "hostname:b.example.com", "asset_type": "hostname", "value": "b.example.com",
                                       "in_scope": True, "attributes": {"tls_self_signed": {
                                           "value": True, "confidence": "HIGH", "sources": ["ssl_analyzer.py"],
                                           "timestamp": "2026-08-20T00:00:00+00:00"}},
                                       "sources": [], "observation_ids": []},
        }, "relationships": {"rel:x": {"rel_type": "mystery_link", "from_asset": "hostname:a.example.com",
                                       "to_asset": "hostname:b.example.com"}},
            "observations": {}, "conflicts": {}}
        assessment = risk.RiskEngine(graph=graph, output_dir=str(tmp_path)).assess()
        assert asset_record(assessment, "hostname:a.example.com") is None


class TestTakeoverIndicatorConfidence:
    def test_indicator_confidence_is_the_mappers_indicator_level_not_the_dns_records(self, assess):
        assessment = assess([finding("dns_record", {"record_type": "CNAME", "records": ["foo.s3.amazonaws.com"]},
                                     target="assets.example.com", source="passive_recon.py", confidence="HIGH")])
        signal = signals_of(assessment, "subdomain_takeover_indicator")[0]
        assert signal["confidence"] == "MEDIUM"
        assert signal["confidence_ceiling"] == "MEDIUM"
        assert signal["severity"] == "HIGH"
        assert signal["kind"] == risk.KIND_INDICATOR
        # One body of evidence, one source — the mapper's derived attribute is not a second corroboration.
        assert signal["corroborating_sources"] == ["passive_recon.py"]

    def test_a_high_level_indicator_keeps_high_confidence(self, tmp_path):
        host = "hostname:assets.example.com"
        graph = {"target": TARGET, "assets": {host: {
            "id": host, "asset_type": "hostname", "value": "assets.example.com", "in_scope": True,
            "attributes": {"takeover_indicator": {"value": {
                "provider": "AWS S3", "final_target": "x.s3.amazonaws.com", "indicator_level": "HIGH",
                "fingerprint_matches": ["nosuchbucket"], "note": "fingerprint observed"},
                "source": "surface_mapper.py", "confidence": "HIGH", "observation_id": "o1",
                "timestamp": "2026-08-20T00:00:00+00:00"}},
            "sources": [], "observation_ids": []}},
            "relationships": {}, "observations": {"o1": {"source": "passive_recon.py", "confidence": "HIGH"}},
            "conflicts": {}}
        assessment = risk.RiskEngine(graph=graph, output_dir=str(tmp_path)).assess()
        signal = signals_of(assessment, "subdomain_takeover_indicator")[0]
        assert signal["confidence"] == "HIGH" and signal["sources"] == ["passive_recon.py"]

    def test_a_superseded_indicator_finding_is_held_down_when_the_cname_moved_on(self, tmp_path):
        host = "hostname:assets.example.com"
        graph = {"target": TARGET, "assets": {
            host: {"id": host, "asset_type": "hostname", "value": "assets.example.com", "in_scope": True,
                   "attributes": {"takeover_indicator": {"value": {
                       "provider": None, "final_target": "safe.example.com", "indicator_level": "LOW"},
                       "source": "surface_mapper.py", "confidence": "LOW", "timestamp": "2026-08-21T00:00:00+00:00"}},
                   "sources": [], "observation_ids": []},
            "finding:t:1": {"id": "finding:t:1", "asset_type": "finding", "value": {
                "finding_type": "subdomain_takeover_indicator",
                "detail": {"hostname": "assets.example.com", "final_target": "x.s3.amazonaws.com", "provider": "AWS S3"}},
                "attributes": {}, "sources": ["passive_recon.py"], "observation_ids": [], "confidence": "HIGH",
                "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {"r": {"rel_type": "asset_to_finding", "from_asset": host, "to_asset": "finding:t:1"}},
            "observations": {}, "conflicts": {}}
        assessment = risk.RiskEngine(graph=graph, output_dir=str(tmp_path)).assess()
        signal = signals_of(assessment, "subdomain_takeover_indicator")[0]
        assert signal["confidence"] == "LOW" and signal["severity"] == "MEDIUM"
        assert any("no longer points at this target" in note for note in signal["notes"])


class TestVulnerabilityIntelligenceSemantics:
    def _classify(self, score, **extra):
        detail = {"cvss": [{"score": score}], "applicability": "version_range_confirmed",
                  "confidence": "HIGH", "summaries": []}
        detail.update(extra)
        return risk.classify_vulnerability_intelligence(detail, {})

    @pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf"), 999, -5, 10.01, True])
    def test_invalid_cvss_values_are_rejected_not_mapped(self, score):
        result = self._classify(score)
        assert result["base_severity"] == "MEDIUM" and result["severity_unknown"] is True
        assert result["cvss_score"] is None
        assert any("outside the published" in note for note in result["notes"])

    def test_a_valid_score_alongside_an_invalid_one_still_counts(self):
        result = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": float("nan")}, {"score": 7.5}], "applicability": "version_range_confirmed",
             "confidence": "HIGH", "summaries": []}, {})
        assert result["base_severity"] == "HIGH" and result["cvss_score"] == 7.5

    def test_kev_provider_outage_is_reported_as_unknown_never_as_not_listed(self, assess):
        record = cve_finding(kev=None)
        record["metadata"].update({
            "cisa_kev_checked": False,
            "cisa_kev_status": {"checked": False, "listed": None, "reason": "KEV feed unavailable"},
            "exploitdb_checked": False,
            "exploitdb_status": {"checked": False, "count": None, "reason": "index unavailable"},
            "epss_checked": False, "epss": {"checked": False, "score": None, "reason": "EPSS API unavailable"},
        })
        signal = signals_of(assess([record]), "vulnerability_intelligence")[0]
        status = signal["intelligence_status"]
        assert status["cisa_kev"] == "not_checked" and status["exploitdb"] == "not_checked"
        assert status["epss"]["status"] == "not_checked"
        assert any("KEV status is UNKNOWN" in note for note in signal["notes"])
        assert any("not evidence that no public exploit exists" in note for note in signal["notes"])
        assert not any(f["factor"] == "known_exploited_vulnerability" for f in signal["factors"])
        # Severity is neither raised nor lowered by an outage.
        baseline = signals_of(assess_fresh([cve_finding(kev=None)]), "vulnerability_intelligence")[0]
        assert signal["severity"] == baseline["severity"] and signal["confidence"] == baseline["confidence"]

    def test_kev_checked_and_not_listed_is_a_negative_result(self, assess):
        record = cve_finding(kev=None)
        record["metadata"].update({"cisa_kev_checked": True,
                                   "cisa_kev_status": {"checked": True, "listed": False, "reason": None}})
        signal = signals_of(assess([record]), "vulnerability_intelligence")[0]
        assert signal["intelligence_status"]["cisa_kev"] == "not_listed"
        assert not any("UNKNOWN" in note for note in signal["notes"])

    def test_epss_is_carried_as_context_and_never_escalates(self, assess):
        record = cve_finding(kev=None, score=5.0, summaries=["dos"])
        record["metadata"].update({"epss_checked": True, "epss_score": 0.97,
                                   "epss": {"checked": True, "score": 0.97, "percentile": 0.999, "date": "2026-09-01"}})
        signal = signals_of(assess([record]), "vulnerability_intelligence")[0]
        assert signal["intelligence_status"]["epss"] == {
            "status": "scored", "score": 0.97, "percentile": 0.999, "date": "2026-09-01", "reason": None}
        epss_factor = [f for f in signal["factors"] if f["factor"] == "epss_exploitation_likelihood"][0]
        assert epss_factor["steps"] == 0
        assert signal["severity"] == "MEDIUM"

    @pytest.mark.parametrize("bad", [float("nan"), 1.5, -0.1, "high", True])
    def test_malformed_epss_scores_are_not_scores(self, bad):
        status = risk._intelligence_status({}, {"epss": {"checked": True, "score": bad}}, None, [])
        assert status["epss"]["status"] == "no_score" and status["epss"]["score"] is None

    def test_older_graphs_with_status_in_the_value_are_still_understood(self):
        detail = {"cisa_kev": None, "cisa_kev_status": {"checked": False, "reason": "down"},
                  "exploitdb_references": [], "exploitdb_status": {"checked": True},
                  "epss": {"checked": True, "score": 0.2}}
        status = risk._intelligence_status(detail, {}, None, [])
        assert (status["cisa_kev"], status["exploitdb"], status["epss"]["status"]) == ("not_checked", "none", "scored")

    def test_no_status_at_all_is_unknown_not_negative(self):
        status = risk._intelligence_status({}, {}, None, [])
        assert status["cisa_kev"] == "unknown" and status["exploitdb"] == "unknown"
        assert status["epss"]["status"] == "unknown"

    def test_confidence_dimensions_are_preserved_alongside_the_scored_value(self, assess):
        record = cve_finding()
        record["value"]["confidence_model"] = {"technology_confidence": "HIGH", "mapping_confidence": "MEDIUM",
                                               "source_confidence": "HIGH", "final_confidence": "MEDIUM"}
        record["value"]["confidence"] = "MEDIUM"
        signal = signals_of(assess([record]), "vulnerability_intelligence")[0]
        assert signal["confidence_dimensions"]["version_mapping"] == "MEDIUM"
        assert signal["confidence_dimensions"]["scored"] == "MEDIUM"

    def test_two_records_of_one_cve_merge_onto_the_stronger_one_regardless_of_order(self, assess):
        strong = cve_finding(version="1.18.0", applicability="version_range_confirmed", confidence="HIGH")
        weak = cve_finding(version=None, applicability="version_unknown_cannot_confirm", confidence="LOW",
                           timestamp="2026-08-21T00:00:00+00:00")
        for order in ((strong, weak), (weak, strong)):
            signals = signals_of(assess_fresh(list(order)), "vulnerability_intelligence")
            assert len(signals) == 1
            assert signals[0]["applicability"] == "version_range_confirmed"
            assert signals[0]["confidence"] == "HIGH"
            assert any("alternate record of the same CVE" in note for note in signals[0]["notes"])
            assert len(signals[0]["source_asset_ids"]) == 2


class TestTemporalQualification:
    def test_attribute_signals_age_by_the_attributes_own_timestamp(self, assess):
        assessment = assess([self_signed_and_old_tls_finding(),
                             dns_a(TARGET, "93.184.216.34", "2026-12-01T00:00:00+00:00")],
                            stale_after_days=30)
        for category in ("self_signed_certificate", "outdated_tls_version"):
            signal = signals_of(assessment, category)[0]
            assert signal["age_days"] >= 100 and signal["stale"] is True

    def test_a_garbage_timestamp_cannot_disable_staleness_for_the_graph(self, assess):
        assessment = assess([
            exposure_finding("https://example.com/admin/", "administrative_panel", timestamp="2026-01-01T00:00:00+00:00"),
            exposure_finding("https://example.com/.git/config", "version_control", timestamp="2026-08-20T00:00:00+00:00"),
            dns_a(TARGET, "1.2.3.4", timestamp="yesterday-ish"),
        ], stale_after_days=30)
        assert assessment["newest_evidence_at"] != "yesterday-ish"
        assert signals_of(assessment, "exposed_administrative_panel")[0]["stale"] is True
        assert any("could not be parsed" in e["error"] for e in assessment["errors"])

    def test_non_finite_staleness_policy_is_rejected(self, tmp_path):
        for bad in (float("nan"), float("inf")):
            with pytest.raises(ValueError, match="finite"):
                risk.RiskEngine(graph={}, output_dir=str(tmp_path), stale_after_days=bad)


class TestNegativeAndInconclusiveEvidence:
    def test_a_failed_fetch_record_is_an_inconclusive_check_not_a_finding(self, assess):
        record = finding("js_analyzer_fetch_failed", {"url": "https://example.com/app.js", "error": "timeout", "hops": []},
                         source="js_analyzer.py", confidence="LOW", metadata={"parent_js_url": "https://example.com/app.js"})
        assessment = assess([record])
        signal = assessment["signals"][0]
        assert signal["category"] == "inconclusive_check:js_analyzer_fetch_failed"
        assert signal["check_outcome"] == "failed"
        assert signal["severity"] == "INFO" and signal["kind"] == risk.KIND_OBSERVATION
        assert any("not evidence of absence" in text for text in signal["notes"] + [signal["severity_basis"]])
        assert assessment["summary"]["inconclusive_checks"] == 1
        assert assessment["investigation_queue"] == []

    @pytest.mark.parametrize("finding_type,expected", [
        ("wayback_intel_check_inconclusive", "inconclusive"),
        ("cloud_candidate_not_probed", "not_checked"),
        ("supply_chain_dns_lookup_failed", "failed"),
        ("js_analyzer_skipped_out_of_scope", "not_checked"),
    ])
    def test_recognized_inconclusive_types(self, finding_type, expected):
        assert risk._inconclusive_outcome(finding_type, {}) == expected

    def test_an_errored_exposure_probe_is_inconclusive_not_clean_and_not_exposed(self, assess):
        record = exposure_finding("https://example.com/.env", "environment_file", discovery_type="server_error_response")
        assessment = assess([record])
        assert signals_of(assessment, "exposed_credential_material") == []
        assert assessment["signals"][0]["check_outcome"] == "inconclusive"

    def test_a_stray_status_field_cannot_suppress_a_confirmed_exposure(self, assess):
        record = exposure_finding("https://example.com/.env", "environment_file")
        record["value"]["status"] = "error"
        assessment = assess([record])
        assert signals_of(assessment, "exposed_credential_material")[0]["severity"] == "CRITICAL"
        assert not any(s.get("check_outcome") for s in assessment["signals"])

    def test_only_explicit_out_of_scope_skip_types_are_not_checked(self):
        assert risk._inconclusive_outcome("some_module_skipped_items", {}) is None
        assert risk._inconclusive_outcome("supply_chain_page_skipped_out_of_scope", {}) == "not_checked"

    def test_contradictory_outcomes_for_one_resource_are_both_kept_and_cross_referenced(self, assess):
        assessment = assess([
            exposure_finding("https://example.com/.env", "environment_file", discovery_type="confirmed_exposure"),
            exposure_finding("https://example.com/.env", "environment_file", discovery_type="access_restricted",
                             timestamp="2026-08-25T00:00:00+00:00"),
        ])
        confirmed = signals_of(assessment, "exposed_credential_material")[0]
        restricted = signals_of(assessment, "sensitive_resource_present_not_readable")[0]
        assert confirmed["outcome_conflict"] is True and restricted["outcome_conflict"] is True
        assert any("'access_restricted'" in n for n in confirmed["notes"])
        assert any("'confirmed_exposure'" in n for n in restricted["notes"])
        # Neither observation is discarded and the score is unchanged by the annotation.
        assert confirmed["severity"] == "CRITICAL" and restricted["severity"] == "LOW"

    def test_genuine_findings_are_never_misread_as_inconclusive(self):
        for ftype, detail in (("db_exposure", {"exposed_ports": [3306]}), ("vulnerability_intelligence", {"cve_id": "x"}),
                              ("exposure_finding", {"discovery_type": "confirmed_exposure"}),
                              ("cloud_resource_finding", {"discovery_type": "confirmed_exposure", "status": "checked"})):
            assert risk._inconclusive_outcome(ftype, detail) is None

    def test_an_unhandled_discovery_outcome_of_a_known_type_says_so(self, assess):
        record = exposure_finding("https://example.com/x", "backup_file", discovery_type="something_new")
        signal = assess([record])["signals"][0]
        assert signal["category"] == "unclassified:exposure_finding"
        assert any("matches no risk rule" in note for note in signal["notes"])


class TestProducerVocabularyCoverage:
    """Catalog rules that surface_mapper.py never materialized as finding assets now read the attributes it does write."""

    def test_vhost_discovery_yields_its_low_signal(self, assess):
        assessment = assess([finding("vhost_discovered", {"ip": "1.2.3.4", "port": 80, "hostname": "hidden.example.com"},
                                     target="hidden.example.com", source="vhost_scanner.py")])
        signal = signals_of(assessment, "virtual_host_expands_surface")[0]
        assert signal["severity"] == "LOW" and signal["subject_asset_id"] == "hostname:hidden.example.com"

    def test_historical_endpoint_yields_its_indicator(self, assess):
        assessment = assess([finding("historical_endpoint_reference", {"url": "https://example.com/old-admin/"},
                                     source="wayback_intel.py", confidence="MEDIUM")])
        signal = signals_of(assessment, "historical_endpoint_reference")[0]
        assert signal["severity"] == "LOW" and signal["kind"] == risk.KIND_INDICATOR

    def test_crawler_administrative_form_is_an_indicator_not_a_confirmed_panel(self, assess):
        record = finding("crawled_form", {"action": "https://example.com/admin/login", "method": "POST",
                                          "classification": "administrative", "inputs": []},
                         source="crawler.py", confidence="MEDIUM", metadata={"source_page": "https://example.com/"})
        signal = signals_of(assess([record]), "administrative_endpoint")[0]
        assert signal["severity"] == "HIGH" and signal["kind"] == risk.KIND_INDICATOR and signal["confirmed"] is False

    def test_interesting_unconfirmed_exposure_is_a_low_indicator(self, assess):
        record = exposure_finding("https://example.com/.env", "environment_file", discovery_type="interesting_unconfirmed")
        signal = signals_of(assess([record]), "sensitive_resource_present_not_readable")[0]
        assert signal["severity"] == "LOW" and "not confirmed by content" in signal["summary"]

    def test_region_redirected_bucket_is_an_existence_observation_not_listable(self, assess):
        record = finding("cloud_resource_finding",
                         {"provider": "aws_s3", "identifier": "acme-backups", "url": "https://acme-backups.s3.amazonaws.com/",
                          "status": "checked", "discovery_type": "bucket_exists_region_redirect", "confidence": "MEDIUM",
                          "ownership_attribution": "operator_asserted_scope"},
                         source="exposure_scan.py", confidence="MEDIUM")
        assessment = assess([record])
        assert signals_of(assessment, "listable_cloud_storage") == []
        signal = signals_of(assessment, "cloud_storage_exists_restricted")[0]
        assert "listability was not tested" in signal["summary"]
        assert any("ownership attribution" in note for note in signal["notes"])

    def test_producer_provenance_notes_survive_into_the_signal(self, assess):
        record = missing_headers_finding()
        record["value"]["provenance"] = {"served_from_cache": True, "note": "headers are a cached copy"}
        signal = signals_of(assess([record]), "missing_security_headers")[0]
        assert any("cached copy" in note for note in signal["notes"])

    def test_lower_producer_annotation_is_recorded_not_silently_ignored(self, assess):
        record = exposure_finding("https://example.com/.env", "environment_file")
        record["metadata"]["severity"] = "LOW"
        signal = signals_of(assess([record]), "exposed_credential_material")[0]
        assert signal["severity"] == "CRITICAL"
        assert any("below the catalog severity" in note for note in signal["notes"])


class TestProvenanceIntegrity:
    def test_a_finding_about_two_subjects_is_attributed_to_both(self, assess):
        detail = {"port": 8443, "host_count": 2, "hosts": ["a", "b"]}
        assessment = assess([
            finding("cross_host_port_pattern", dict(detail), target="a.example.com", source="active_recon.py"),
            finding("cross_host_port_pattern", dict(detail), target="b.example.com", source="active_recon.py"),
        ])
        subjects = sorted(s["subject_asset_id"] for s in signals_of(assessment, "cross_host_port_pattern"))
        assert subjects == ["hostname:a.example.com", "hostname:b.example.com"]

    def test_every_signal_names_the_finding_assets_it_came_from(self, assess):
        assessment = assess([db_exposure_finding(), missing_headers_finding(), self_signed_and_old_tls_finding()])
        for signal in assessment["signals"]:
            assert signal["source_asset_ids"]

    def test_metadata_latest_wins_means_newest_timestamp_not_ingestion_order(self, assess):
        newer = cve_finding(kev=None, timestamp="2026-08-22T00:00:00+00:00")
        newer["metadata"].update({"cisa_kev_checked": True, "cisa_kev_status": {"checked": True, "listed": False}})
        older = cve_finding(kev=None, timestamp="2026-08-20T00:00:05+00:00")
        older["metadata"].update({"cisa_kev_checked": False, "cisa_kev_status": {"checked": False, "reason": "down"}})
        signal = signals_of(assess([newer, older]), "vulnerability_intelligence")[0]
        assert signal["intelligence_status"]["cisa_kev"] == "not_listed"

    def test_derived_scores_never_feed_back_as_evidence(self, build):
        """Assessing the assessment's own graph twice is a fixed point: nothing derived is re-ingested."""
        mapper, output_dir = build([db_exposure_finding(), missing_headers_finding(), self_signed_and_old_tls_finding()])
        engine = risk.RiskEngine(graph=mapper, output_dir=output_dir)
        first = engine.assess()
        second = engine.assess()
        for doc in (first, second):
            doc.pop("generated_at")
        assert first == second
        blob = json.dumps(first)
        assert "risk_engine.py" not in {s for sig in first["signals"] for s in sig["sources"]}
        assert blob.count('"module": "risk_engine.py"') == 1


class TestGraphIsReadOnly:
    def test_assessing_a_live_mapper_never_mutates_its_state(self, build):
        """The orchestrator hands over the live graph; scoring must leave it byte-identical."""
        mapper, output_dir = build([db_exposure_finding(), missing_headers_finding(), self_signed_and_old_tls_finding(),
                                    cve_finding(kev={"listed": True}), admin_panel_on(TARGET),
                                    dns_a(TARGET, "93.184.216.34", "2026-08-20T00:00:09+00:00"),
                                    finding("dns_record", {"record_type": "CNAME", "records": ["foo.s3.amazonaws.com"]},
                                            target="assets.example.com", source="passive_recon.py")])
        before = json.dumps(mapper.state, sort_keys=True, default=str)
        engine = risk.RiskEngine(graph=mapper, output_dir=output_dir)
        engine.run()
        engine.assess()
        assert json.dumps(mapper.state, sort_keys=True, default=str) == before

    def test_signal_detail_is_the_producers_value_not_a_rewritten_copy(self, assess):
        assessment = assess([db_exposure_finding()])
        detail = signals_of(assessment, "database_port_exposure")[0]["detail"]
        assert detail == db_exposure_finding()["value"]


class TestHostileInput:
    def test_control_characters_and_bidi_overrides_are_escaped_in_human_facing_text(self, assess):
        hostile = "evil\x00\x1b]0;pwned\x07 ‮drowssap\r\nforged line"
        record = finding("error_page_intelligence", {"url": "https://example.com/x", "indicators": [hostile]},
                         source="exposure_scan.py", evidence=[hostile])
        signal = signals_of(assess([record]), "error_page_information_disclosure")[0]
        for text in [signal["summary"]] + signal["evidence"]:
            assert "\x00" not in text and "\x1b" not in text and "‮" not in text and "\r" not in text
            assert "\\x1b" in text and "\\u202e" in text

    def test_huge_strings_are_bounded_and_not_amplified(self, assess):
        big = "A" * 200_000
        records = [finding("banner", {"ip": "1.2.3.4", "port": 22, "banner": big}, source="active_recon.py",
                           evidence=[big, big + "b", big + "c"]),
                   dns_a(TARGET, "1.2.3.4")]
        assessment = assess(records)
        signal = signals_of(assessment, "technology_observation")[0]
        assert len(signal["summary"]) < risk.MAX_SUMMARY_CHARS + 64
        assert all(len(e) < risk.MAX_EVIDENCE_ITEM_CHARS + 64 for e in signal["evidence"])
        blob = json.dumps(assessment)
        assert len(blob) < 2 * len(big)

    def test_evidence_lists_are_count_bounded_with_an_honest_marker(self, assess):
        record = finding("db_exposure", {"ip": "1.2.3.4", "exposed_ports": [3306]}, source="active_recon.py",
                         evidence=[f"line {i}" for i in range(risk.MAX_EVIDENCE_ITEMS + 10)])
        signal = signals_of(assess([record]), "database_port_exposure")[0]
        assert len(signal["evidence"]) == risk.MAX_EVIDENCE_ITEMS
        assert signal["evidence_truncated"] == 10

    def test_forged_confidence_and_severity_strings_are_normalized(self, assess):
        record = exposure_finding("https://example.com/.env", "environment_file")
        record["confidence"] = "CRITICAL"
        record["metadata"]["severity"] = "ULTRA\x00"
        signal = signals_of(assess([record]), "exposed_credential_material")[0]
        assert signal["confidence"] == "LOW" and signal["severity"] == "MEDIUM"
        assert "ULTRA" not in json.dumps(signal["severity_basis"])

    def test_malformed_cve_records_degrade_without_crashing(self, tmp_path):
        graph = {"target": TARGET, "assets": {}, "relationships": {}, "observations": {}, "conflicts": {}}
        weird = [{"cvss": "not-a-list"}, {"cvss": [None, 42, "x", {"score": {"nested": True}}]},
                 {"cve_id": ["list"], "applicability": {"d": 1}, "summaries": {"a": "b"}, "cisa_kev": "yes",
                  "exploitdb_references": "refs", "confidence": None}]
        for i, detail in enumerate(weird):
            graph["assets"][f"finding:v:{i}"] = {
                "id": f"finding:v:{i}", "asset_type": "finding",
                "value": {"finding_type": "vulnerability_intelligence", "detail": detail},
                "attributes": {}, "sources": ["vuln_intel.py"], "observation_ids": [], "confidence": "HIGH",
                "last_seen": "2026-08-20T00:00:00+00:00"}
        assessment = risk.RiskEngine(graph=graph, output_dir=str(tmp_path)).assess()
        json.dumps(assessment, default=None)
        assert len(signals_of(assessment, "vulnerability_intelligence")) == len(weird)
        for signal in signals_of(assessment, "vulnerability_intelligence"):
            assert signal["severity"] in risk.VALID_SEVERITIES and signal["confidence"] in risk.VALID_CONFIDENCES

    def test_deeply_nested_and_cyclic_graph_values_are_bounded(self, tmp_path):
        cyclic: dict = {"a": 1}
        cyclic["self"] = cyclic
        graph = {"target": TARGET, "assets": {"finding:x:1": {
            "id": "finding:x:1", "asset_type": "finding",
            "value": {"finding_type": "mystery", "detail": {"loop": cyclic}},
            "attributes": {}, "sources": ["m.py"], "observation_ids": [], "confidence": "LOW"}},
            "relationships": {}, "observations": {}, "conflicts": {}}
        assessment = risk.RiskEngine(graph=graph, output_dir=str(tmp_path)).assess()
        json.dumps(assessment, default=None)
        assert assessment["summary"]["signals"] == 1

    def test_dangling_relationships_and_missing_subjects_are_tolerated(self, tmp_path):
        graph = {"target": TARGET, "assets": {"finding:x:1": {
            "id": "finding:x:1", "asset_type": "finding",
            "value": {"finding_type": "db_exposure", "detail": {"ip": "1.2.3.4", "exposed_ports": [3306]}},
            "attributes": {}, "sources": ["active_recon.py"], "observation_ids": [], "confidence": "HIGH"}},
            "relationships": {"r1": {"rel_type": "asset_to_finding", "from_asset": "port:gone", "to_asset": "finding:x:1"},
                              "r2": {"rel_type": "hostname_to_ip", "from_asset": "hostname:gone", "to_asset": "port:gone"},
                              "r3": "not-a-dict", "r4": {"rel_type": "asset_to_finding"}},
            "observations": {}, "conflicts": {}}
        assessment = risk.RiskEngine(graph=graph, output_dir=str(tmp_path)).assess()
        signal = signals_of(assessment, "database_port_exposure")[0]
        assert signal["subject_asset_id"] == "port:gone" and signal["severity"] == "CRITICAL"


class TestFinalGateRceWording:
    @pytest.mark.parametrize("text", [
        "This is not a remote code execution vulnerability; it discloses memory.",
        "No remote code execution is possible; denial of service only.",
        "does not allow arbitrary code execution",
        "Unlike CVE-2020-1, this cannot lead to remote code execution.",
        "without remote code execution", "prevents remote code execution",
    ])
    def test_negated_rce_wording_never_escalates(self, text):
        result = risk.classify_vulnerability_intelligence(
            {"cvss": [{"score": 7.5}], "applicability": "version_range_confirmed", "confidence": "HIGH",
             "summaries": [text]}, {})
        assert not any(f["factor"] == "rce_class_vulnerability" for f in result["factors"])
        assert result["base_severity"] == "HIGH"
        assert any("negated clause" in note for note in result["notes"])

    @pytest.mark.parametrize("text", [
        "does not properly validate input, leading to remote code execution",
        "allows remote attackers to execute arbitrary code via a crafted request",
        "allows remote attackers to execute arbitrary OS commands",
        "is not restricted, resulting in arbitrary command execution",
        "(RCE) in the admin console", "unauthenticated RCE",
        "The vulnerability is not a remote code execution. Instead it allows arbitrary code execution via plugins.",
    ])
    def test_affirmative_rce_wording_including_nvd_phrasing_is_recognized(self, text):
        assert risk._looks_rce({"summaries": [text]}) is True

    @pytest.mark.parametrize("text", ["FORCE upgrade", "remote code executi\u03bfn", "", None, 12345,
                                      {"a": "rce"}, "sourced from", "pierced"])
    def test_substring_and_confusable_collisions_do_not_match(self, text):
        assert risk._looks_rce({"summaries": [text] if not isinstance(text, list) else text}) is False

    def test_rce_escalation_is_capped_by_applicability_and_confidence(self, assess):
        signal = signals_of(assess([cve_finding(version=None, applicability="version_unknown_cannot_confirm",
                                                score=7.5, confidence="LOW",
                                                summaries=["allows remote attackers to execute arbitrary code"])]),
                            "vulnerability_intelligence")[0]
        assert signal["severity"] == "MEDIUM"
        assert not any(f["factor"] == "rce_class_vulnerability" for f in signal["factors"])


class TestFinalGateDeprecatedApiCorrelation:
    def _deprecated(self):
        return finding("api_endpoint_deprecated", {"url": "https://example.com/api/v1/x", "basis": "path_probe"},
                       source="api_recon.py", confidence="HIGH", timestamp="2026-08-20T00:00:07+00:00")

    def test_a_cve_on_an_unrelated_service_does_not_relate_to_the_deprecated_api(self, assess):
        ssh_cve = cve_finding(technology="openssh", version="7.4", cve_id="CVE-2018-15473", score=5.3,
                              summaries=["user enumeration"])
        host = asset_record(assess([self._deprecated(), ssh_cve]), "hostname:example.com")
        assert host["severity"] == "MEDIUM"
        assert host["escalation"] is None
        assert any("NOT applied" in line and "co-location alone" in line for line in host["rationale"])

    def test_a_cve_on_the_web_technology_serving_the_host_does_relate(self, assess):
        host = asset_record(assess([self._deprecated(), tech_finding(), cve_finding(score=5.0, summaries=["dos"])]),
                            "hostname:example.com")
        assert host["severity"] == "HIGH"
        assert host["escalation"]["name"] == "deprecated_api_with_known_cve"
        assert any("observed serving HTTP content" in line for line in host["rationale"])

    def test_the_rule_raises_to_high_and_never_past_it(self, assess):
        """context.md names the combination HIGH; a HIGH CVE + deprecated API must not become CRITICAL."""
        host = asset_record(assess([self._deprecated(), tech_finding(), cve_finding(score=7.5, summaries=["dos"])]),
                            "hostname:example.com")
        assert host["severity"] == "HIGH"
        # and a CVE that is CRITICAL on its own keeps its own severity
        host = asset_record(assess([self._deprecated(), tech_finding(), cve_finding(score=9.8, summaries=["dos"])]),
                            "hostname:example.com")
        assert host["severity"] == "CRITICAL"

    def test_a_cve_on_a_sibling_vhost_never_relates_across_the_shared_ip(self, assess):
        records = [self._deprecated(), dns_a(TARGET, "10.0.0.1"),
                   finding("vhost_discovered", {"ip": "10.0.0.1", "port": 80, "hostname": "b.example.com"},
                           target="b.example.com", source="vhost_scanner.py"),
                   finding("tech_fingerprint_detected", {"technology": "nginx", "category": "server", "version": "1.18.0",
                                                         "url": "https://b.example.com/"},
                           target="b.example.com", source="tech_fingerprint.py"),
                   finding("vulnerability_intelligence", dict(cve_finding()["value"], target="b.example.com"),
                           target="b.example.com", source="vuln_intel.py", confidence="HIGH")]
        host = asset_record(assess(records), "hostname:example.com")
        assert host["severity"] == "MEDIUM" and host["escalation"] is None

    def test_a_vhost_that_did_not_observe_the_web_technology_is_not_linked(self, assess):
        """nginx observed on example.com must not link a CVE to a deprecated API on other.example.com."""
        deprecated = finding("api_endpoint_deprecated", {"url": "https://other.example.com/api/v1/x", "basis": "path_probe"},
                             target="other.example.com", source="api_recon.py", confidence="HIGH")
        other_cve = finding("vulnerability_intelligence", dict(cve_finding(score=5.0, summaries=["dos"])["value"],
                                                               target="other.example.com"),
                            target="other.example.com", source="vuln_intel.py", confidence="HIGH")
        host = asset_record(assess([deprecated, other_cve, tech_finding()]), "hostname:other.example.com")
        assert host["severity"] == "MEDIUM" and host["escalation"] is None


class TestFinalGateEpss:
    def test_epss_changes_neither_severity_nor_queue_order(self, assess):
        plain = cve_finding(kev=None, score=5.0, summaries=["dos"])
        scored = cve_finding(kev=None, score=5.0, summaries=["dos"])
        scored["metadata"].update({"epss_checked": True, "epss_score": 0.99,
                                   "epss": {"checked": True, "score": 0.99, "percentile": 1.0, "date": "2026-09-01"}})
        a, b = assess_fresh([tech_finding(), plain]), assess_fresh([tech_finding(), scored])
        sa, sb = signals_of(a, "vulnerability_intelligence")[0], signals_of(b, "vulnerability_intelligence")[0]
        assert sa["severity"] == sb["severity"] and sa["confidence"] == sb["confidence"]
        assert [e["asset_id"] for e in a["investigation_queue"]] == [e["asset_id"] for e in b["investigation_queue"]]
        assert [(e["severity"], e["confidence"]) for e in a["investigation_queue"]] == \
            [(e["severity"], e["confidence"]) for e in b["investigation_queue"]]
        line = [l for l in sb["rationale"] if "EPSS" in l][0]
        assert line.startswith("factor recorded:") and "without escalation" in line
        assert sb["intelligence_status"]["epss"]["score"] == 0.99

    def test_context_md_defines_no_epss_weighting(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "context.md"), encoding="utf-8") as handle:
            assert "epss" not in handle.read().lower()


class TestFinalGateProducerAnnotations:
    @pytest.mark.parametrize("value", ["ULTRA", 5, None, float("nan"), float("inf"), ["CRITICAL"], {"s": "CRITICAL"},
                                       "CRITICAL\x00", True, "", " "])
    def test_malformed_annotations_are_ignored_not_honoured(self, assess, value):
        record = exposure_finding("https://example.com/x.log", "log_file", discovery_type="access_restricted")
        record["metadata"]["severity"] = value
        signal = signals_of(assess([record]), "sensitive_resource_present_not_readable")[0]
        assert signal["severity"] == "LOW" and "annotated" not in signal["severity_basis"]

    def test_annotation_cannot_bypass_the_confidence_cap(self, assess):
        record = exposure_finding("https://example.com/x.log", "log_file", discovery_type="access_restricted",
                                  confidence="LOW")
        record["metadata"]["severity"] = "CRITICAL"
        signal = signals_of(assess([record]), "sensitive_resource_present_not_readable")[0]
        assert signal["base_severity"] == "CRITICAL" and signal["severity"] == "MEDIUM"

    def test_annotation_cannot_bypass_applicability_or_inconclusive_semantics(self, assess):
        cve = cve_finding(version=None, applicability="version_unknown_cannot_confirm", score=10.0)
        cve["metadata"]["severity"] = "CRITICAL"
        assert signals_of(assess_fresh([cve]), "vulnerability_intelligence")[0]["severity"] == "MEDIUM"
        failed = finding("js_analyzer_fetch_failed", {"url": "https://example.com/a.js", "error": "x"},
                         source="js_analyzer.py", metadata={"severity": "CRITICAL"})
        assert assess_fresh([failed])["signals"][0]["severity"] == "INFO"

    def test_disagreeing_annotations_across_observations_are_surfaced(self, assess):
        first = exposure_finding("https://example.com/x.log", "log_file", discovery_type="access_restricted",
                                 timestamp="2026-08-20T00:00:00+00:00")
        first["metadata"]["severity"] = "CRITICAL"
        second = exposure_finding("https://example.com/x.log", "log_file", discovery_type="access_restricted",
                                  timestamp="2026-08-21T00:00:00+00:00")
        second["metadata"]["severity"] = "INFO"
        signal = signals_of(assess([first, second]), "sensitive_resource_present_not_readable")[0]
        assert any("annotations differ across observations" in n and "CRITICAL" in n for n in signal["notes"])


class TestFinalGateTemporal:
    def test_unrelated_later_evidence_never_makes_old_evidence_fresher(self, assess):
        old_admin = exposure_finding("https://example.com/admin/", "administrative_panel",
                                     timestamp="2026-01-01T00:00:00+00:00")
        alone = signals_of(assess_fresh([old_admin], stale_after_days=30), "exposed_administrative_panel")[0]
        with_other = signals_of(assess_fresh([old_admin, dns_a("other.example.com", "1.2.3.4", "2026-08-01T00:00:00+00:00")],
                                             stale_after_days=30), "exposed_administrative_panel")[0]
        assert alone["stale"] and with_other["stale"]
        assert with_other["age_days"] >= alone["age_days"]

    def test_touching_the_host_with_unrelated_evidence_does_not_refresh_its_certificate_attributes(self, assess):
        assessment = assess([self_signed_and_old_tls_finding(),
                             finding("whois", {"org": "x"}, source="passive_recon.py",
                                     timestamp="2026-12-01T00:00:00+00:00")], stale_after_days=30)
        assert signals_of(assessment, "self_signed_certificate")[0]["stale"] is True

    def test_a_genuine_re_observation_does_refresh(self, assess):
        old_admin = exposure_finding("https://example.com/admin/", "administrative_panel",
                                     timestamp="2026-01-01T00:00:00+00:00")
        again = exposure_finding("https://example.com/admin/", "administrative_panel",
                                 timestamp="2026-08-20T00:00:00+00:00")
        signal = signals_of(assess([old_admin, again], stale_after_days=30), "exposed_administrative_panel")[0]
        assert signal["stale"] is False and len(signal["observation_ids"]) == 2


class TestFinalGateContradictions:
    def _tls(self, self_signed, version, timestamp):
        return finding("tls_certificate_analysis",
                       {"host": TARGET, "port": 443, "certificate": {"subject": {"CN": TARGET}, "issuer": {"CN": "R3"}},
                        "self_signed": {"self_signed": self_signed}, "tls_version": {"version": version}},
                       source="ssl_analyzer.py", timestamp=timestamp)

    def test_true_then_false_is_flagged_disputed_and_held_at_medium_confidence(self, assess):
        assessment = assess([self._tls(True, "TLSv1.0", "2026-08-20T00:00:00+00:00"),
                             self._tls(False, "TLSv1.3", "2026-08-25T00:00:00+00:00")])
        for category in ("self_signed_certificate", "outdated_tls_version"):
            signal = signals_of(assessment, category)[0]
            assert signal["confidence"] == "MEDIUM" and signal["attribute_conflict"].startswith("conflict:")
            assert any("unresolved conflict" in n and "also observed as" in n for n in signal["notes"])
            assert signal["corroborating_sources"] == ["ssl_analyzer.py"]

    def test_false_then_true_does_not_make_the_finding_disappear(self, assess):
        assessment = assess([self._tls(False, "TLSv1.3", "2026-08-20T00:00:00+00:00"),
                             self._tls(True, "TLSv1.0", "2026-08-25T00:00:00+00:00")])
        for category in ("self_signed_certificate", "outdated_tls_version"):
            signal = signals_of(assessment, category)[0]
            assert signal["severity"] == "MEDIUM" and signal["confidence"] == "MEDIUM"
            assert signal["attribute_conflict"]

    def test_disputed_attribute_is_not_counted_as_corroboration(self, assess):
        assessment = assess([self._tls(True, "TLSv1.0", "2026-08-20T00:00:00+00:00"),
                             finding("tls_certificate_analysis",
                                     {"host": TARGET, "port": 443, "self_signed": {"self_signed": False},
                                      "tls_version": {"version": "TLSv1.3"}},
                                     source="passive_recon.py", timestamp="2026-08-25T00:00:00+00:00")])
        signal = signals_of(assessment, "self_signed_certificate")[0]
        assert signal["confidence"] != "HIGH" and signal["corroborating_sources"] == ["ssl_analyzer.py"]

    def _kev(self, state, timestamp, confidence="HIGH", version="1.18.0"):
        record = cve_finding(kev={"listed": True, "date_added": "2026-08-22"} if state == "listed" else None,
                             timestamp=timestamp, confidence=confidence, version=version,
                             applicability="version_range_confirmed" if version else "version_unknown_cannot_confirm")
        status = {"listed": {"checked": True, "listed": True},
                  "not_listed": {"checked": True, "listed": False},
                  "failed": {"checked": False, "listed": None, "reason": "feed down"}}[state]
        record["metadata"].update({"cisa_kev_checked": status["checked"], "cisa_kev_listed": bool(status["listed"]),
                                   "cisa_kev_status": status})
        return record

    @pytest.mark.parametrize("sequence,expected", [
        (("not_listed", "listed"), "listed"),
        (("listed", "failed"), "listed"),
        (("failed", "listed"), "listed"),
        (("failed", "not_listed"), "not_listed"),
        (("not_listed", "failed"), "not_listed"),
        (("failed", "failed"), "not_checked"),
    ])
    def test_provider_failure_never_subtracts_established_kev_knowledge(self, assess, sequence, expected):
        records = [self._kev(state, f"2026-08-2{i}T00:00:00+00:00") for i, state in enumerate(sequence)]
        for order in (records, list(reversed(records))):
            signal = signals_of(assess_fresh(list(order)), "vulnerability_intelligence")[0]
            assert signal["intelligence_status"]["cisa_kev"] == expected
            has_factor = any(f["factor"] == "known_exploited_vulnerability" for f in signal["factors"])
            assert has_factor == (expected == "listed")
            assert signal["corroborating_sources"] == ["vuln_intel.py"]

    def test_kev_listing_survives_merge_with_a_weaker_newer_record(self, assess):
        listed_weak = self._kev("listed", "2026-08-23T00:00:00+00:00", confidence="LOW", version=None)
        not_listed_strong = self._kev("not_listed", "2026-08-20T00:00:00+00:00")
        signal = signals_of(assess([not_listed_strong, listed_weak]), "vulnerability_intelligence")[0]
        assert signal["applicability"] == "version_range_confirmed"      # stronger record stays primary
        assert signal["intelligence_status"]["cisa_kev"] == "listed"      # CVE-level knowledge is unioned
        assert any(f["factor"] == "known_exploited_vulnerability" for f in signal["factors"])
        assert signal["severity"] == "CRITICAL"

    def test_contradictory_outcomes_for_one_resource_count_once_toward_convergence(self, assess):
        assessment = assess([exposure_finding("https://example.com/.env", "environment_file"),
                             exposure_finding("https://example.com/.env", "environment_file",
                                              discovery_type="access_restricted", timestamp="2026-08-25T00:00:00+00:00"),
                             missing_headers_finding()])
        host = asset_record(assessment, "hostname:example.com")
        assert host["convergent_categories"] == ["exposed_credential_material", "missing_security_headers"]
        assert host["escalation"] is None and host["severity"] == "CRITICAL"

    def test_combined_attack_across_all_gate_areas_stays_bounded(self, assess):
        """Negated RCE + unrelated SSH CVE + deprecated API + disputed cert + KEV outage + forged annotation."""
        ssh = cve_finding(technology="openssh", version="7.4", cve_id="CVE-2018-15473", score=7.5,
                          summaries=["does not allow arbitrary code execution; user enumeration only"])
        ssh["metadata"].update({"severity": "CRITICAL", "cisa_kev_checked": False,
                                "cisa_kev_status": {"checked": False, "reason": "down"},
                                "epss_checked": True, "epss": {"checked": True, "score": 0.99}})
        records = [ssh,
                   finding("api_endpoint_deprecated", {"url": "https://example.com/api/v1/x", "basis": "path_probe"},
                           source="api_recon.py", confidence="HIGH", timestamp="2026-08-20T00:00:07+00:00"),
                   self._tls(True, "TLSv1.0", "2026-08-20T00:00:00+00:00"),
                   self._tls(False, "TLSv1.3", "2026-08-25T00:00:00+00:00"),
                   missing_headers_finding()]
        assessment = assess_fresh(records)
        host = asset_record(assessment, "hostname:example.com")
        cve = signals_of(assessment, "vulnerability_intelligence")[0]
        assert cve["severity"] == "HIGH" and not any(f["factor"] == "rce_class_vulnerability" for f in cve["factors"])
        assert cve["intelligence_status"]["cisa_kev"] == "not_checked"
        assert not any("deprecated_api_with_known_cve' matched" in line for line in host["rationale"])
        for category in ("self_signed_certificate", "outdated_tls_version"):
            assert signals_of(assessment, category)[0]["confidence"] == "MEDIUM"
        # Three HIGH-confidence categories (CVE, deprecated API, headers) genuinely converge:
        # context.md §9 permits CRITICAL, and the bound records that it rests on HIGH evidence.
        assert host["severity"] == "CRITICAL" and host["escalation"]["ceiling_confidence"] == "HIGH"
        # Without the headers only two HIGH-confidence categories remain; the third-best
        # is a disputed MEDIUM attribute, so the same escalation must be held at HIGH.
        assessment = assess_fresh(records[:-1])
        host = asset_record(assessment, "hostname:example.com")
        assert host["severity"] == "HIGH" and host["escalation"]["ceiling_confidence"] == "MEDIUM"
        assert any("held at HIGH" in line for line in host["rationale"])
        assert all(s["severity"] in risk.VALID_SEVERITIES and s["confidence"] in risk.VALID_CONFIDENCES
                   for s in assessment["signals"])


class TestDiagnostics:
    def test_unresolvable_observation_references_are_reported_not_ignored(self, tmp_path):
        state = {"target": TARGET, "assets": {"finding:db:1": {
            "id": "finding:db:1", "asset_type": "finding",
            "value": {"finding_type": "db_exposure", "detail": {"ip": "1.2.3.4", "exposed_ports": [3306]}},
            "attributes": {}, "sources": ["active_recon.py"], "observation_ids": ["gone", 7, None, "junk"],
            "confidence": "HIGH", "last_seen": "2026-08-20T00:00:00+00:00"}},
            "relationships": {}, "observations": {"junk": "not-a-record"}, "conflicts": {}}
        assessment = risk.RiskEngine(graph=state, output_dir=str(tmp_path)).assess()
        assert signals_of(assessment, "database_port_exposure")[0]["severity"] == "CRITICAL"
        assert any("4 of 4 referenced observation" in e["error"] for e in assessment["errors"])

    def test_cli_reports_a_missing_graph_cleanly(self, tmp_path):
        import subprocess
        result = subprocess.run([sys.executable, "-m", "reconhound.risk_engine", "--graph",
                                 os.path.join(str(tmp_path), "nope.json"), "--no-persist"],
                                capture_output=True, text=True,
                                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        assert result.returncode == 1
        assert "does not exist" in result.stderr and "Traceback" not in result.stderr

    def test_cli_queue_only_and_no_persist_are_honoured(self, build):
        import subprocess
        mapper, output_dir = build([db_exposure_finding()])
        mapper.save()
        result = subprocess.run([sys.executable, "-m", "reconhound.risk_engine", "--output-dir", output_dir,
                                 "--queue-only", "--no-persist"], capture_output=True, text=True,
                                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        assert result.returncode == 0
        assert json.loads(result.stdout)[0]["severity"] == "CRITICAL"
        assert not os.path.exists(os.path.join(output_dir, "risk_assessment.json"))


class TestDeterminismAndPerformance:
    def _wide_records(self, hosts, per_host):
        records = []
        for i in range(hosts):
            records.append(dns_a(f"h{i}.example.com", f"10.{i // 250 % 256}.{i % 250}.{i % 7 + 1}"))
            for j in range(per_host):
                records.append(missing_headers_finding(f"https://h{i}.example.com/p{j}"))
        return records

    def test_identical_graphs_produce_identical_substantive_output(self, tmp_path):
        records = [db_exposure_finding(), missing_headers_finding(), self_signed_and_old_tls_finding(),
                   cve_finding(kev={"listed": True}), admin_panel_on(TARGET), third_party_ref(1),
                   finding("dns_record", {"record_type": "CNAME", "records": ["foo.s3.amazonaws.com"]},
                           target="assets.example.com", source="passive_recon.py")]
        outputs = []
        for _ in range(3):
            mapper = SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
            mapper.ingest_many(records)
            doc = risk.run_risk_engine(graph=mapper.state, output_dir=str(tmp_path), persist=False)
            doc.pop("generated_at")
            doc.pop("graph_updated_at")
            doc.pop("newest_evidence_at")
            for signal in doc["signals"]:
                signal.pop("age_days")
            outputs.append(json.dumps(doc, sort_keys=True))
        assert len(set(outputs)) == 1

    def test_signal_order_and_merge_do_not_depend_on_ingestion_order(self, tmp_path):
        records = [missing_headers_finding(), self_signed_and_old_tls_finding(), db_exposure_finding(),
                   cve_finding(), tech_finding(), admin_panel_on(TARGET)]
        docs = []
        for order in (records, list(reversed(records))):
            mapper = SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
            mapper.ingest_many(order)
            doc = risk.run_risk_engine(graph=mapper.state, output_dir=str(tmp_path), persist=False)
            docs.append([(s["signal_id"], s["severity"], s["confidence"], s["summary"]) for s in doc["signals"]])
        assert docs[0] == docs[1]

    def test_wide_graph_scales_linearly_enough(self, tmp_path):
        import time
        mapper = SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        mapper.autosave = False
        mapper.ingest_many(self._wide_records(1500, 2))
        started = time.perf_counter()
        assessment = risk.RiskEngine(graph=mapper.state, output_dir=str(tmp_path)).assess()
        elapsed = time.perf_counter() - started
        assert assessment["summary"]["signals"] == 3000
        assert elapsed < 20.0, f"1500 hosts x 2 signals took {elapsed:.1f}s"

    def test_wildcard_dns_fan_out_is_bounded(self, tmp_path):
        import time
        n = 2000
        records = [dns_a(f"h{i}.example.com", "10.0.0.1") for i in range(n)]
        records += [finding("open_tcp_port", {"ip": "10.0.0.1", "port": p, "protocol": "tcp"}, source="active_recon.py")
                    for p in range(1, 31)]
        records.append(finding("db_exposure", {"ip": "10.0.0.1", "exposed_ports": [3306]}, source="active_recon.py",
                               metadata={"severity": "CRITICAL"}))
        mapper = SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        mapper.autosave = False
        mapper.ingest_many(records)
        started = time.perf_counter()
        assessment = risk.RiskEngine(graph=mapper.state, output_dir=str(tmp_path)).assess()
        elapsed = time.perf_counter() - started
        assert elapsed < 10.0, f"took {elapsed:.1f}s"
        assert assessment["summary"]["assets_assessed"] < 100     # ports + IP, not 2000 hostnames
        assert asset_record(assessment, "ip:10.0.0.1")["severity"] == "CRITICAL"
        assert assessment["investigation_queue"][0]["asset_id"] == "ip:10.0.0.1"


class TestPersistenceHardening:
    def test_save_survives_a_directory_that_cannot_be_fsynced(self, tmp_path, monkeypatch):
        store = risk.RiskAssessmentStore(output_dir=str(tmp_path))
        monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("no fsync")))
        # Directory fsync failures are tolerated; the file fsync failure is not silently swallowed.
        with pytest.raises(OSError):
            store.save({"a": 1})
        assert not [f for f in os.listdir(str(tmp_path)) if f.startswith(".risk_assessment_")]

    def test_repeated_persistence_replaces_rather_than_duplicates(self, build):
        mapper, output_dir = build([db_exposure_finding()])
        engine = risk.RiskEngine(graph=mapper, output_dir=output_dir)
        engine.run()
        engine.run()
        with open(os.path.join(output_dir, "risk_assessment.json")) as handle:
            reloaded = json.load(handle)
        assert reloaded["summary"]["signals"] == 1
        assert len([f for f in os.listdir(output_dir) if "risk_assessment" in f]) == 1


# ===========================================================================
# Conflict kinds and protocol context
#
# Both reproduce defects found in the 2026-09-12 whole-system audit.
# ===========================================================================


class TestTemporalConflictsDoNotSuspendAssessments:
    """
    context.md §8's "suspended pending resolution of a fingerprint conflict"
    is about *modules disagreeing*. Before this fix, one module observing an
    upgraded nginx on a later run produced a permanent unresolved `version`
    conflict, and every CVE for that technology was suspended — so the second
    scan of any target that patches anything silently lost its whole CVE
    queue. Measured: the investigation queue went from 2 entries to 0 with no
    other change.
    """

    def test_a_version_change_between_runs_does_not_suspend_the_cve(self, assess):
        assessment = assess([
            tech_finding(version="1.20.1", timestamp="2026-08-20T00:00:02+00:00"),
            # the same module's observation from an earlier run
            tech_finding(version="1.18.0", timestamp="2026-07-01T00:00:00+00:00"),
            cve_finding(version="1.20.1"),
        ])
        vuln = signals_of(assessment, "vulnerability_intelligence")
        assert vuln, "the CVE signal must still exist"
        assert all(not s["suspended"] for s in vuln)
        assert assessment["investigation_queue"], "the queue must not be emptied by an upgrade"

    def test_two_modules_disagreeing_still_suspends_the_cve(self, assess):
        # The §8 capability itself must be intact.
        assessment = assess([
            tech_finding(version="1.20.1", source="tech_fingerprint.py"),
            tech_finding(version="1.18.0", source="active_recon.py",
                         timestamp="2026-08-20T00:00:03+00:00"),
            cve_finding(version="1.20.1"),
        ])
        vuln = signals_of(assessment, "vulnerability_intelligence")
        assert vuln and all(s["suspended"] for s in vuln)
        assert assessment["suspended_signals"]

    def test_a_temporal_conflict_is_still_attached_to_the_signal(self, assess):
        # Not suspending it is not the same as hiding it: the operator must
        # still see that the version changed.
        assessment = assess([
            tech_finding(version="1.20.1", timestamp="2026-08-20T00:00:02+00:00"),
            tech_finding(version="1.18.0", timestamp="2026-07-01T00:00:00+00:00"),
            cve_finding(version="1.20.1"),
        ])
        attached = [c for s in assessment["signals"] for c in s["conflicts"]]
        assert attached, "the conflict must still be reported"
        assert all(c["kind"] == risk.CONFLICT_TEMPORAL for c in attached
                   if c["attribute"] == "version")

    def test_conflict_kind_is_derived_when_a_persisted_record_predates_the_field(self):
        # A graph written before `kind` existed must classify the same way,
        # not default to whichever answer happens to be convenient.
        assert risk.conflict_kind({"observations": [
            {"source": "tech_fingerprint.py"}, {"source": "tech_fingerprint.py"}]}
        ) == risk.CONFLICT_TEMPORAL
        assert risk.conflict_kind({"observations": [
            {"source": "tech_fingerprint.py"}, {"source": "active_recon.py"}]}
        ) == risk.CONFLICT_CROSS_SOURCE
        # sources survives truncation of observations, so it wins
        assert risk.conflict_kind({
            "sources": ["a.py", "b.py"], "observations": [{"source": "a.py"}]}
        ) == risk.CONFLICT_CROSS_SOURCE

    @pytest.mark.parametrize("conflict", [
        {}, {"kind": None}, {"kind": 7}, {"kind": "nonsense"},
        {"observations": None}, {"observations": "x"}, {"sources": None},
        {"observations": [None, "x", 3]},
    ])
    def test_conflict_kind_never_raises_on_a_malformed_record(self, conflict):
        assert risk.conflict_kind(conflict) in (risk.CONFLICT_CROSS_SOURCE,
                                                 risk.CONFLICT_TEMPORAL)


class TestSecurityHeaderProtocolContext:
    """
    RFC 6797 §7.2/§8.1: a host MUST NOT send Strict-Transport-Security over
    non-secure transport and a user agent MUST ignore one that arrives that
    way. Reporting its absence from an http:// response was therefore a
    finding no server change could ever clear, and it put a MEDIUM signal at
    the top of the investigation queue for every plaintext origin.
    """

    def test_hsts_is_not_reported_missing_over_plaintext_http(self, assess):
        assessment = assess([missing_headers_finding(url="http://example.com/")])
        headers = signals_of(assessment, "missing_security_headers")
        assert headers, "the other missing headers are still reported"
        assert "Strict-Transport-Security" not in headers[0]["summary"]
        assert "Content-Security-Policy" in headers[0]["summary"]

    def test_hsts_is_still_reported_missing_over_https(self, assess):
        assessment = assess([missing_headers_finding(url="https://example.com/")])
        headers = signals_of(assessment, "missing_security_headers")
        assert headers and "Strict-Transport-Security" in headers[0]["summary"]

    def test_the_other_five_headers_are_not_scheme_dependent(self):
        # Browsers honour CSP/XFO/XCTO/Referrer-Policy/Permissions-Policy over
        # HTTP as well as HTTPS; only HSTS is protocol-gated.
        detail = {"url": "http://example.com/", "headers": {
            name: {"present": False} for name in risk._TRACKED_SECURITY_HEADERS}}
        missing = risk._missing_security_headers(detail)
        assert set(missing) == set(risk._TRACKED_SECURITY_HEADERS) - {"Strict-Transport-Security"}

    def test_an_http_origin_with_no_other_gap_produces_no_header_signal(self, assess):
        present = {name: {"present": True, "value": "x", "notes": []}
                   for name in risk._TRACKED_SECURITY_HEADERS}
        present["Strict-Transport-Security"] = {"present": False, "value": None, "notes": []}
        assessment = assess([finding(
            "http_security_headers", {"url": "http://example.com/", "headers": present},
            source="http_analyzer.py", metadata={"url": "http://example.com/"})])
        assert signals_of(assessment, "missing_security_headers") == []

    @pytest.mark.parametrize("url", [
        "HTTP://example.com/", "http://example.com:8080/", "http://example.com/a/b?x=1",
    ])
    def test_the_scheme_gate_is_case_and_port_insensitive(self, url):
        detail = {"url": url, "headers": {
            name: {"present": False} for name in risk._TRACKED_SECURITY_HEADERS}}
        assert "Strict-Transport-Security" not in risk._missing_security_headers(detail)

    @pytest.mark.parametrize("detail", [
        {"headers": {"Strict-Transport-Security": {"present": False}}},
        {"url": None, "headers": {"Strict-Transport-Security": {"present": False}}},
        {"url": "not a url", "headers": {"Strict-Transport-Security": {"present": False}}},
        {"url": "https://example.com/", "headers": {"Strict-Transport-Security": {"present": False}}},
    ])
    def test_hsts_is_reported_whenever_the_scheme_is_not_known_to_be_plaintext(self, detail):
        # Fail safe: an unknown scheme keeps the finding rather than dropping it.
        assert "Strict-Transport-Security" in risk._missing_security_headers(detail)

    def test_a_redirect_response_carries_its_provenance_into_the_signal(self, assess):
        # http_analyzer records that the analysed response was a redirector,
        # whose headers describe the redirector and not the application.
        note = ("the analysed response is a 301 redirect; its headers describe the "
                "redirector, not the application the redirect points at")
        assessment = assess([finding(
            "http_security_headers",
            {"url": "https://example.com/",
             "headers": {n: {"present": False} for n in risk._TRACKED_SECURITY_HEADERS},
             "provenance": {"status_code": 301, "analyzed_response_is_redirect": True,
                            "note": note}},
            source="http_analyzer.py", metadata={"url": "https://example.com/"})])
        headers = signals_of(assessment, "missing_security_headers")
        assert headers
        assert any(note in n for n in headers[0]["notes"])


if __name__ == "__main__":
    import subprocess
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v"])
