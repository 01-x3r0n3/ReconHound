"""
Tests for reconhound/surface_mapper.py (ReconHound Module 6, per
context.md's build order — catalog item 6, build-order position 8).

Run with:  ./.venv/bin/python -m pytest tests/test_surface_mapper.py -v

No network access anywhere in this file: surface_mapper.py never talks to
the network itself, it only ingests finding records already produced by
other modules (either handed in directly, or read back from a
pending_assets.json fixture file), so nothing needs to be mocked.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import surface_mapper as sm

TARGET = "example.com"


def finding(finding_type, value, target=TARGET, evidence=None, confidence="MEDIUM",
            source="test_module.py", timestamp=None, metadata=None):
    """Build a raw finding record in the exact shape every module's make_finding() produces."""
    return {
        "type": finding_type,
        "target": target,
        "value": value,
        "evidence": evidence if evidence is not None else [f"{finding_type} evidence"],
        "confidence": confidence,
        "source": source,
        "timestamp": timestamp or sm._now(),
        "metadata": metadata or {},
    }


@pytest.fixture
def mapper(tmp_path):
    return sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# Normalization of representative module outputs
# ---------------------------------------------------------------------------

class TestNormalization:
    def test_dns_a_record_creates_hostname_and_ip_with_relationship(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["93.184.216.34"]},
                                       source="passive_recon.py", confidence="HIGH"))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "example.com")
        ip_id = sm._aid(sm.ASSET_IP, "93.184.216.34")
        assert mapper.get_asset(host_id) is not None
        assert mapper.get_asset(ip_id) is not None
        rels = mapper.relationships_for(host_id)
        assert any(r["rel_type"] == sm.REL_HOSTNAME_TO_IP and r["to_asset"] == ip_id for r in rels)

    def test_open_port_creates_ip_to_service_relationship(self, mapper):
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
                                       source="active_recon.py", confidence="HIGH"))
        ip_id = sm._aid(sm.ASSET_IP, "1.2.3.4")
        port_id = sm._aid(sm.ASSET_PORT, "1.2.3.4", 443, "tcp")
        rels = mapper.relationships_for(ip_id)
        assert any(r["rel_type"] == sm.REL_IP_TO_SERVICE and r["to_asset"] == port_id for r in rels)
        assert mapper.get_asset(port_id)["attributes"]["status"]["value"] == "open"

    def test_endpoint_discovered_links_hostname_to_endpoint(self, mapper):
        mapper.ingest_finding(finding(
            "endpoint_discovered",
            {"url": "https://example.com/admin", "method": "GET", "status_code": 200,
             "category": "admin", "discovery_type": "wordlist"},
            source="endpoint_discovery.py",
        ))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "example.com")
        endpoint_id = sm._aid(sm.ASSET_ENDPOINT, sm._norm_url("https://example.com/admin"))
        endpoint_asset = mapper.get_asset(endpoint_id)
        assert endpoint_asset is not None
        assert endpoint_asset["attributes"]["status_code"]["value"] == 200
        rels = mapper.relationships_for(host_id)
        assert any(r["rel_type"] == sm.REL_ASSET_TO_ENDPOINT and r["to_asset"] == endpoint_id for r in rels)

    def test_endpoint_parameter_links_endpoint_to_parameter(self, mapper):
        mapper.ingest_finding(finding(
            "endpoint_parameter",
            {"name": "id", "location": "query", "method": "GET", "endpoint": "https://example.com/item",
             "data_type": "integer", "source": "url_query"},
            source="endpoint_discovery.py",
        ))
        endpoint_id = sm._aid(sm.ASSET_ENDPOINT, "https://example.com/item")
        param_id = sm._aid(sm.ASSET_PARAMETER, "https://example.com/item", "query", "id")
        assert mapper.get_asset(param_id)["attributes"]["data_type"]["value"] == "integer"
        rels = mapper.relationships_for(endpoint_id)
        assert any(r["rel_type"] == sm.REL_ENDPOINT_TO_PARAMETER and r["to_asset"] == param_id for r in rels)

    def test_tech_fingerprint_detected_creates_technology_relationship(self, mapper):
        mapper.ingest_finding(finding(
            "tech_fingerprint_detected",
            {"technology": "Nginx", "category": "server", "version": "1.18.0", "url": "https://example.com/"},
            source="tech_fingerprint.py",
        ))
        url_id = sm._aid(sm.ASSET_ENDPOINT, sm._norm_url("https://example.com/"))
        tech_id = sm._aid(sm.ASSET_TECHNOLOGY, sm._norm_url("https://example.com/"), "nginx")
        rels = mapper.relationships_for(url_id)
        assert any(r["rel_type"] == sm.REL_ASSET_TO_TECHNOLOGY and r["to_asset"] == tech_id for r in rels)
        assert mapper.get_asset(tech_id)["attributes"]["version"]["value"] == "1.18.0"

    def test_javascript_endpoint_reference_builds_js_to_endpoint_chain(self, mapper):
        mapper.ingest_finding(finding(
            "javascript_endpoint_reference",
            {"url": "https://example.com/api/v2/users", "js_url": "https://example.com/app.js"},
            source="endpoint_discovery.py",
        ))
        js_id = sm._aid(sm.ASSET_JAVASCRIPT, sm._norm_url("https://example.com/app.js"))
        endpoint_id = sm._aid(sm.ASSET_ENDPOINT, sm._norm_url("https://example.com/api/v2/users"))
        rels = mapper.relationships_for(js_id)
        assert any(r["rel_type"] == sm.REL_JAVASCRIPT_TO_ENDPOINT and r["to_asset"] == endpoint_id for r in rels)

    def test_supply_chain_third_party_dns_creates_subdomain_relationship(self, mapper):
        mapper.ingest_finding(finding(
            "supply_chain_subdomain_third_party_dns",
            {"subdomain": "cdn.example.com", "cname_chain": ["cdn.example.com", "d123.cloudfront.net"],
             "third_party": {"category": "cdn", "category_source": "catalog_match"}},
            source="supply_chain.py",
        ))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "cdn.example.com")
        tp_id = sm._aid(sm.ASSET_THIRD_PARTY, "d123.cloudfront.net")
        rels = mapper.relationships_for(host_id)
        assert any(r["rel_type"] == sm.REL_SUBDOMAIN_TO_THIRD_PARTY and r["to_asset"] == tp_id for r in rels)
        assert mapper.get_asset(tp_id)["attributes"]["category"]["value"] == "cdn"

    def test_unknown_finding_type_falls_back_to_generic_asset_to_finding(self, mapper):
        result = mapper.ingest_finding(finding("some_future_module_finding_type", {"note": "unseen shape"}))
        assert result["status"] == "ingested"
        host_id = sm._aid(sm.ASSET_HOSTNAME, TARGET)
        rels = mapper.relationships_for(host_id)
        assert any(r["rel_type"] == sm.REL_ASSET_TO_FINDING for r in rels)


# ---------------------------------------------------------------------------
# Duplicate discovery correlation (multiple sources -> one asset)
# ---------------------------------------------------------------------------

class TestDeduplicationAndCorrelation:
    def test_same_hostname_from_two_modules_correlates_to_one_asset(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]},
                                       target="example.com", source="passive_recon.py", confidence="HIGH"))
        mapper.ingest_finding(finding("vhost_discovered",
                                       {"ip": "1.2.3.4", "port": 443, "scheme": "https", "hostname": "example.com",
                                        "host_header": "example.com", "connect_url": "https://1.2.3.4:443/"},
                                       target="example.com", source="vhost_scanner.py", confidence="MEDIUM"))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "example.com")
        assert len(mapper.state["assets"]) == 2  # hostname, ip -- exactly one hostname asset (correlated, not duplicated)
        host = mapper.get_asset(host_id)
        assert set(host["sources"]) == {"passive_recon.py", "vhost_scanner.py"}

    def test_ip_case_and_whitespace_normalization_dedupes(self, mapper):
        mapper.ingest_finding(finding("open_tcp_port", {"ip": " 10.0.0.1", "port": 22, "protocol": "tcp"}))
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "10.0.0.1 ", "port": 80, "protocol": "tcp"}))
        assert len([a for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_IP]) == 1

    def test_hostname_case_and_trailing_dot_normalization_dedupes(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.1.1.1"]}, target="EXAMPLE.com."))
        mapper.ingest_finding(finding("dns_record", {"record_type": "AAAA", "records": ["::1"]}, target="example.com"))
        assert len([a for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_HOSTNAME]) == 1

    def test_exact_duplicate_finding_record_is_skipped(self, mapper):
        f = finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}, timestamp="2026-01-01T00:00:00+00:00")
        r1 = mapper.ingest_finding(f)
        r2 = mapper.ingest_finding(dict(f))
        assert r1["status"] == "ingested"
        assert r2["status"] == "duplicate_skipped"
        assert len(mapper.state["observations"]) == 1


# ---------------------------------------------------------------------------
# Evidence preservation
# ---------------------------------------------------------------------------

class TestEvidencePreservation:
    def test_evidence_and_source_and_timestamp_retrievable_from_asset(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["9.9.9.9"]},
                                       evidence=["DNS A query for example.com returned 1 record(s)"],
                                       source="passive_recon.py"))
        host_id = sm._aid(sm.ASSET_HOSTNAME, TARGET)
        ev = mapper.get_evidence(host_id)
        assert len(ev) == 1
        assert ev[0]["evidence"] == ["DNS A query for example.com returned 1 record(s)"]
        assert ev[0]["source"] == "passive_recon.py"
        assert "timestamp" in ev[0]

    def test_multiple_observations_accumulate_full_evidence_trail(self, mapper):
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 80, "protocol": "tcp"},
                                       source="active_recon.py"))
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
                                       source="active_recon.py"))
        ip_id = sm._aid(sm.ASSET_IP, "1.2.3.4")
        assert len(mapper.get_evidence(ip_id)) == 2


# ---------------------------------------------------------------------------
# Confidence handling / aggregation
# ---------------------------------------------------------------------------

class TestConfidence:
    def test_single_low_signal_stays_low(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "TXT", "records": ["v=spf1 ~all"]},
                                       confidence="LOW", source="passive_recon.py"))
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, TARGET))
        assert host["confidence"] == "LOW"

    def test_high_confidence_observation_wins(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]},
                                       confidence="HIGH", source="passive_recon.py"))
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, TARGET))
        assert host["confidence"] == "HIGH"

    def test_two_independent_medium_sources_escalate_to_high(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "MX", "records": ["mx1.example.com"]},
                                       confidence="MEDIUM", source="passive_recon.py"))
        mapper.ingest_finding(finding("email_security",
                                       {"spf": {"status": "found"}, "dmarc": {"status": "not_found"},
                                        "dkim": {"status": "not_found"}, "mx": {"status": "found"}},
                                       confidence="MEDIUM", source="osint_engine.py"))
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, TARGET))
        assert host["confidence"] == "HIGH"

    def test_invalid_confidence_value_defaults_to_low(self, mapper):
        f = finding("dns_record", {"record_type": "NS", "records": ["ns1.example.com"]})
        f["confidence"] = "SUPER_DUPER_HIGH"
        mapper.ingest_finding(f)
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, TARGET))
        assert host["confidence"] == "LOW"


# ---------------------------------------------------------------------------
# Conflicting observations — must be preserved, never silently overwritten
# ---------------------------------------------------------------------------

class TestConflictPreservation:
    def test_disagreeing_technology_versions_create_conflict_and_preserve_first_value(self, mapper):
        mapper.ingest_finding(finding("tech_fingerprint_detected",
                                       {"technology": "Nginx", "category": "server", "version": "1.18.0",
                                        "url": "https://example.com/"}, source="tech_fingerprint.py"))
        mapper.ingest_finding(finding("tech_fingerprint_detected",
                                       {"technology": "Nginx", "category": "server", "version": "1.20.1",
                                        "url": "https://example.com/"}, source="active_recon.py"))
        tech_id = sm._aid(sm.ASSET_TECHNOLOGY, sm._norm_url("https://example.com/"), "nginx")
        tech = mapper.get_asset(tech_id)
        assert tech["attributes"]["version"]["value"] == "1.18.0"  # first-observed value preserved, not overwritten
        assert tech["attributes"]["version"]["has_conflict"] is True

        conflicts = mapper.get_conflicts(tech_id)
        assert len(conflicts) == 1
        values_seen = {o["value"] for o in conflicts[0]["observations"]}
        assert values_seen == {"1.18.0", "1.20.1"}

    def test_agreeing_observations_do_not_create_a_conflict(self, mapper):
        mapper.ingest_finding(finding("tech_fingerprint_detected",
                                       {"technology": "Apache", "category": "server", "version": "2.4.41",
                                        "url": "https://example.com/"}, source="tech_fingerprint.py"))
        mapper.ingest_finding(finding("tech_fingerprint_detected",
                                       {"technology": "Apache", "category": "server", "version": "2.4.41",
                                        "url": "https://example.com/"}, source="active_recon.py", timestamp=sm._now()))
        tech_id = sm._aid(sm.ASSET_TECHNOLOGY, sm._norm_url("https://example.com/"), "apache")
        assert mapper.get_conflicts(tech_id) == []

    def test_active_recon_service_conflict_is_preserved(self, mapper):
        mapper.ingest_finding(finding("service_conflict",
                                       {"ip": "5.6.7.8", "port": 8080, "protocol": "tcp", "service": None,
                                        "port_guess": "http-alt", "banner_guess": "ssh"},
                                       source="active_recon.py"))
        port_id = sm._aid(sm.ASSET_PORT, "5.6.7.8", 8080, "tcp")
        conflicts = mapper.get_conflicts(port_id)
        assert len(conflicts) == 1
        assert conflicts[0]["attribute"] == "service"
        values_seen = {o["value"] for o in conflicts[0]["observations"]}
        assert values_seen == {"http-alt", "ssh"}


# ---------------------------------------------------------------------------
# Negative-result state memory
# ---------------------------------------------------------------------------

class TestNegativeResultMemory:
    def test_checked_no_match_is_recorded_as_negative_result_not_a_finding(self, mapper):
        mapper.ingest_finding(finding("tech_fingerprint_checked_no_match",
                                       {"category": "cms", "url": "https://example.com/"},
                                       confidence="LOW", source="tech_fingerprint.py"))
        url_id = sm._aid(sm.ASSET_ENDPOINT, sm._norm_url("https://example.com/"))
        assert mapper.has_been_checked(url_id, "tech_fingerprint_checked_no_match") is True
        record = mapper.get_negative_result(url_id, "tech_fingerprint_checked_no_match")
        assert record["state"] == "checked_not_found"
        # must not also create an asset_to_finding relationship for a negative result
        rels = mapper.relationships_for(url_id)
        assert not any(r["rel_type"] == sm.REL_ASSET_TO_FINDING for r in rels)

    def test_negative_result_persists_across_reload(self, mapper, tmp_path):
        mapper.ingest_finding(finding("vhost_checked_no_distinct_response",
                                       {"ip": "1.2.3.4", "port": 443, "scheme": "https", "hostname": "staging.example.com",
                                        "connect_url": "https://1.2.3.4:443/"},
                                       source="vhost_scanner.py", confidence="LOW"))
        mapper.save()
        reloaded = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "staging.example.com")
        assert reloaded.has_been_checked(host_id, "vhost_checked_no_distinct_response") is True

    def test_repeated_negative_checks_increment_check_count(self, mapper):
        f1 = finding("passive_intel_checked_no_data", {"ip": "1.2.3.4", "sources_checked": ["shodan"]},
                      source="passive_intel.py", timestamp="2026-01-01T00:00:00+00:00")
        f2 = finding("passive_intel_checked_no_data", {"ip": "1.2.3.4", "sources_checked": ["censys"]},
                      source="passive_intel.py", timestamp="2026-01-02T00:00:00+00:00")
        mapper.ingest_finding(f1)
        mapper.ingest_finding(f2)
        ip_id = sm._aid(sm.ASSET_IP, "1.2.3.4")
        record = mapper.get_negative_result(ip_id, "passive_intel_checked_no_data")
        assert record["check_count"] == 2
        assert record["first_checked_at"] == "2026-01-01T00:00:00+00:00"
        assert record["last_checked_at"] == "2026-01-02T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Discovery-state transitions
# ---------------------------------------------------------------------------

class TestDiscoveryState:
    def test_new_asset_starts_discovered(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, TARGET))
        assert host["state"] == sm.STATE_DISCOVERED

    def test_valid_transitions_recorded_with_history(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        host_id = sm._aid(sm.ASSET_HOSTNAME, TARGET)
        mapper.set_asset_state(host_id, sm.STATE_QUEUED, reason="scheduled by orchestrator")
        mapper.set_asset_state(host_id, sm.STATE_INVESTIGATED, reason="active recon run started")
        mapper.set_asset_state(host_id, sm.STATE_COMPLETED, reason="all modules finished")
        host = mapper.get_asset(host_id)
        assert host["state"] == sm.STATE_COMPLETED
        states = [h["state"] for h in host["state_history"]]
        assert states == [sm.STATE_DISCOVERED, sm.STATE_QUEUED, sm.STATE_INVESTIGATED, sm.STATE_COMPLETED]
        assert host["state_history"][-1]["reason"] == "all modules finished"

    def test_failed_state_is_tracked(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        host_id = sm._aid(sm.ASSET_HOSTNAME, TARGET)
        mapper.set_asset_state(host_id, sm.STATE_FAILED, reason="module crashed")
        assert mapper.get_asset(host_id)["state"] == sm.STATE_FAILED

    def test_invalid_state_rejected(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        host_id = sm._aid(sm.ASSET_HOSTNAME, TARGET)
        with pytest.raises(ValueError):
            mapper.set_asset_state(host_id, "not_a_real_state")

    def test_unknown_asset_id_raises(self, mapper):
        with pytest.raises(KeyError):
            mapper.set_asset_state("hostname:doesnotexist.example.com", sm.STATE_QUEUED)


# ---------------------------------------------------------------------------
# Relationship / attack-surface path construction
# ---------------------------------------------------------------------------

class TestAttackSurfacePaths:
    def test_explain_path_from_root_hostname_to_deep_asset(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["9.9.9.9"]},
                                       source="passive_recon.py"))
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "9.9.9.9", "port": 443, "protocol": "tcp"},
                                       source="active_recon.py"))
        mapper.ingest_finding(finding("service_identification",
                                       {"ip": "9.9.9.9", "port": 443, "protocol": "tcp", "service": "https"},
                                       source="active_recon.py"))
        port_id = sm._aid(sm.ASSET_PORT, "9.9.9.9", 443, "tcp")
        path = mapper.explain_asset_path(port_id)
        asset_types = [hop["asset_type"] for hop in path]
        assert asset_types == [sm.ASSET_HOSTNAME, sm.ASSET_IP, sm.ASSET_PORT]
        assert path[0]["via"] is None
        assert path[1]["via"]["relationship_type"] == sm.REL_HOSTNAME_TO_IP
        assert path[2]["via"]["relationship_type"] == sm.REL_IP_TO_SERVICE

    def test_no_path_returns_empty_list_for_unreachable_asset(self, mapper):
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "203.0.113.5", "port": 22, "protocol": "tcp"},
                                       target="unrelated-host.example.com"))
        # unrelated-host.example.com's hostname asset was never linked from the root example.com asset
        unrelated_host_id = sm._aid(sm.ASSET_HOSTNAME, "unrelated-host.example.com")
        assert mapper.explain_asset_path(unrelated_host_id) == []

    def test_attack_surface_tree_builds_nested_structure(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["9.9.9.9"]}))
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "9.9.9.9", "port": 80, "protocol": "tcp"}))
        tree = mapper.build_attack_surface_tree()
        assert tree["asset_type"] == sm.ASSET_HOSTNAME
        assert tree["children"][0]["asset_type"] == sm.ASSET_IP
        assert tree["children"][0]["children"][0]["asset_type"] == sm.ASSET_PORT


# ---------------------------------------------------------------------------
# Vhost relationships
# ---------------------------------------------------------------------------

class TestVhostRelationships:
    def test_vhost_discovered_links_ip_to_vhost_hostname(self, mapper):
        mapper.ingest_finding(finding("vhost_discovered",
                                       {"ip": "4.4.4.4", "port": 443, "scheme": "https", "hostname": "internal.example.com",
                                        "host_header": "internal.example.com", "connect_url": "https://4.4.4.4:443/"},
                                       source="vhost_scanner.py", confidence="MEDIUM"))
        ip_id = sm._aid(sm.ASSET_IP, "4.4.4.4")
        vhost_id = sm._aid(sm.ASSET_HOSTNAME, "internal.example.com")
        rels = mapper.relationships_for(ip_id)
        assert any(r["rel_type"] == sm.REL_IP_TO_VHOST and r["to_asset"] == vhost_id for r in rels)
        assert mapper.get_asset(vhost_id)["attributes"]["discovered_via_vhost_scan"]["value"] is True

    def test_new_vhost_raises_web_recon_opportunity(self, mapper):
        mapper.ingest_finding(finding("vhost_discovered",
                                       {"ip": "4.4.4.4", "port": 443, "scheme": "https", "hostname": "internal.example.com",
                                        "host_header": "internal.example.com", "connect_url": "https://4.4.4.4:443/"},
                                       source="vhost_scanner.py"))
        opps = [o for o in mapper.get_pending_opportunities() if o["opportunity_type"] == "vhost_web_followup"]
        assert len(opps) == 1
        assert "http_analyzer.py" in opps[0]["suggested_modules"]

    def test_negative_vhost_result_recorded_and_no_vhost_asset_created(self, mapper):
        mapper.ingest_finding(finding("vhost_checked_no_distinct_response",
                                       {"ip": "4.4.4.4", "port": 443, "scheme": "https", "hostname": "nope.example.com",
                                        "connect_url": "https://4.4.4.4:443/"},
                                       source="vhost_scanner.py", confidence="LOW"))
        vhost_id = sm._aid(sm.ASSET_HOSTNAME, "nope.example.com")
        assert mapper.has_been_checked(vhost_id, "vhost_checked_no_distinct_response")


# ---------------------------------------------------------------------------
# Dangling-CNAME / subdomain-takeover indicators
# ---------------------------------------------------------------------------

class TestTakeoverIndicators:
    def test_cname_to_known_vulnerable_provider_raises_medium_indicator(self, mapper):
        mapper.ingest_finding(finding("dns_record",
                                       {"record_type": "CNAME", "records": ["old-app.herokuapp.com"]},
                                       target="staging.example.com", source="passive_recon.py"))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "staging.example.com")
        indicator = mapper.get_asset(host_id)["attributes"]["takeover_indicator"]["value"]
        assert indicator["provider"] == "Heroku"
        assert indicator["indicator_level"] == sm.CONFIDENCE_MEDIUM
        assert indicator["confirmed"] is False

    def test_cname_to_ordinary_hostname_raises_no_indicator(self, mapper):
        mapper.ingest_finding(finding("dns_record",
                                       {"record_type": "CNAME", "records": ["mail.example.com"]},
                                       target="www.example.com", source="passive_recon.py"))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "www.example.com")
        indicator = mapper.get_asset(host_id)["attributes"]["takeover_indicator"]["value"]
        assert indicator["provider"] is None
        assert indicator["indicator_level"] == sm.CONFIDENCE_LOW

    def test_fingerprint_match_escalates_to_high_confidence(self, mapper):
        mapper.ingest_finding(finding("dns_record",
                                       {"record_type": "CNAME", "records": ["myproject.herokuapp.com"]},
                                       target="old.example.com", source="passive_recon.py"))
        # A later exposure_scan finding on the same hostname observes the provider's "unclaimed" page text
        mapper.ingest_finding(finding("exposure_finding",
                                       {"url": "https://old.example.com/", "status_code": 404},
                                       target="old.example.com", source="exposure_scan.py",
                                       evidence=["GET https://old.example.com/ returned HTTP 404: no such app"]))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "old.example.com")
        indicator = mapper.get_asset(host_id)["attributes"]["takeover_indicator"]["value"]
        assert indicator["provider"] == "Heroku"
        assert indicator["indicator_level"] == sm.CONFIDENCE_HIGH
        assert "no such app" in indicator["fingerprint_matches"]

    def test_medium_or_higher_indicator_creates_manual_verification_opportunity(self, mapper):
        mapper.ingest_finding(finding("dns_record",
                                       {"record_type": "CNAME", "records": ["myproject.herokuapp.com"]},
                                       target="old.example.com", source="passive_recon.py"))
        opps = [o for o in mapper.get_pending_opportunities()
                if o["opportunity_type"] == "subdomain_takeover_manual_verification"]
        assert len(opps) == 1
        assert opps[0]["priority"] == "MEDIUM"
        assert "not confirmed" in opps[0]["reason"]

    def test_never_claims_confirmed_takeover(self, mapper):
        mapper.ingest_finding(finding("dns_record",
                                       {"record_type": "CNAME", "records": ["myproject.herokuapp.com"]},
                                       target="old.example.com", source="passive_recon.py"))
        host_id = sm._aid(sm.ASSET_HOSTNAME, "old.example.com")
        indicator = mapper.get_asset(host_id)["attributes"]["takeover_indicator"]["value"]
        assert indicator["confirmed"] is False
        finding_asset_id = sm._aid(sm.ASSET_FINDING, "subdomain_takeover_indicator",
                                    sm._short_hash({"hostname": "old.example.com",
                                                    "final_target": "myproject.herokuapp.com", "provider": "Heroku"}))
        assert mapper.get_asset(finding_asset_id) is not None


# ---------------------------------------------------------------------------
# Downstream reconnaissance opportunities
# ---------------------------------------------------------------------------

class TestOpportunities:
    def test_new_web_port_generates_high_priority_followup(self, mapper):
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
                                       source="active_recon.py"))
        opps = mapper.get_pending_opportunities()
        assert any(o["opportunity_type"] == "open_port_followup" and o["priority"] == "HIGH" for o in opps)

    def test_non_web_port_generates_low_priority_followup(self, mapper):
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 5432, "protocol": "tcp"},
                                       source="active_recon.py"))
        opps = mapper.get_pending_opportunities()
        match = [o for o in opps if o["opportunity_type"] == "open_port_followup"]
        assert match and match[0]["priority"] == "LOW"

    def test_duplicate_port_observation_does_not_duplicate_opportunity(self, mapper):
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
                                       source="active_recon.py", timestamp="2026-01-01T00:00:00+00:00"))
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
                                       source="active_recon.py", timestamp="2026-01-02T00:00:00+00:00"))
        matches = [o for o in mapper.get_pending_opportunities() if o["opportunity_type"] == "open_port_followup"]
        assert len(matches) == 1

    def test_wordpress_detection_triggers_cms_enumeration_opportunity(self, mapper):
        mapper.ingest_finding(finding("tech_fingerprint_detected",
                                       {"technology": "WordPress", "category": "cms", "version": None,
                                        "url": "https://example.com/"},
                                       source="tech_fingerprint.py"))
        opps = [o for o in mapper.get_pending_opportunities() if o["opportunity_type"] == "technology_specific_enumeration"]
        assert len(opps) == 1
        assert "endpoint_discovery.py" in opps[0]["suggested_modules"]

    def test_consume_opportunity_marks_it_consumed(self, mapper):
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"}))
        opp = mapper.get_pending_opportunities()[0]
        mapper.consume_opportunity(opp["id"])
        assert mapper.state["opportunities"][opp["id"]]["status"] == "consumed"
        assert opp["id"] not in [o["id"] for o in mapper.get_pending_opportunities()]

    def test_consuming_unknown_opportunity_raises(self, mapper):
        with pytest.raises(KeyError):
            mapper.consume_opportunity("opp:does-not-exist")

    def test_js_referenced_endpoint_raises_verification_opportunity(self, mapper):
        mapper.ingest_finding(finding("javascript_endpoint_reference",
                                       {"url": "https://example.com/api/v3/secret", "js_url": "https://example.com/app.js"},
                                       source="endpoint_discovery.py"))
        opps = [o for o in mapper.get_pending_opportunities()
                if o["opportunity_type"] == "js_referenced_endpoint_verification"]
        assert len(opps) == 1

    def test_new_in_scope_cert_san_raises_opportunity_but_out_of_scope_does_not(self, mapper):
        mapper.ingest_finding(finding("tls_san", "vault.example.com", target="example.com",
                                       source="passive_recon.py", metadata={"in_scope": True}))
        mapper.ingest_finding(finding("tls_san", "unrelated-external.org", target="example.com",
                                       source="passive_recon.py", metadata={"in_scope": False}))
        opp_targets = {o["target_value"] for o in mapper.get_pending_opportunities()
                       if o["opportunity_type"] == "new_hostname_via_cert_san"}
        assert "vault.example.com" in opp_targets
        assert "unrelated-external.org" not in opp_targets


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

class TestJsonSerialization:
    def test_full_state_is_pure_json_serializable(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        mapper.ingest_finding(finding("tech_fingerprint_detected",
                                       {"technology": "Nginx", "category": "server", "version": "1.2",
                                        "url": "https://example.com/"}))
        mapper.ingest_finding(finding("tech_fingerprint_detected",
                                       {"technology": "Nginx", "category": "server", "version": "1.3",
                                        "url": "https://example.com/"}))
        serialized = json.dumps(mapper.state, sort_keys=True)
        restored = json.loads(serialized)
        assert restored["target"] == TARGET

    def test_saved_state_file_is_valid_json(self, mapper, tmp_path):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        mapper.save()
        path = tmp_path / "surface_graph.json"
        assert path.exists()
        with open(path) as f:
            data = json.load(f)
        assert data["target"] == TARGET


# ---------------------------------------------------------------------------
# Persistence and preservation of existing state
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_reload_preserves_assets_relationships_and_opportunities(self, tmp_path):
        m1 = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        m1.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        m1.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"}))
        m1.save()

        m2 = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        assert m2.summary() == m1.summary()
        assert sm._aid(sm.ASSET_IP, "1.2.3.4") in m2.state["assets"]
        assert len(m2.get_pending_opportunities()) == len(m1.get_pending_opportunities())

    def test_reingesting_same_pending_assets_file_is_idempotent(self, tmp_path):
        pending_path = tmp_path / "pending_assets.json"
        records = [finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}, timestamp="2026-01-01T00:00:00+00:00")]
        pending_path.write_text(json.dumps(records))

        m = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        r1 = m.ingest_pending_assets_file()
        r2 = m.ingest_pending_assets_file()
        assert r1["ingested"] == 1
        assert r2["duplicates"] == 1
        assert len(m.state["assets"]) == len(sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path)).state["assets"])

    def test_second_mapper_instance_never_clobbers_first_instances_unsaved_additions(self, tmp_path):
        m1 = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        m1.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        m1.save()

        m2 = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        m2.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 22, "protocol": "tcp"}))
        m2.save()

        m3 = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        assert sm._aid(sm.ASSET_HOSTNAME, TARGET) in m3.state["assets"]
        assert sm._aid(sm.ASSET_PORT, "1.2.3.4", 22, "tcp") in m3.state["assets"]

    def test_mismatched_target_does_not_reuse_others_persisted_graph(self, tmp_path):
        m1 = sm.SurfaceMapper(target="example.com", output_dir=str(tmp_path))
        m1.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}, target="example.com"))
        m1.save()

        m2 = sm.SurfaceMapper(target="other-target.com", output_dir=str(tmp_path), state_filename="surface_graph.json")
        assert m2.state["target"] == "other-target.com"
        assert sm._aid(sm.ASSET_HOSTNAME, "example.com") not in m2.state["assets"]


# ---------------------------------------------------------------------------
# Malformed / unexpected input handling
# ---------------------------------------------------------------------------

class TestMalformedInput:
    def test_non_dict_finding_raises_malformed_error(self, mapper):
        with pytest.raises(sm.MalformedFindingError):
            mapper.ingest_finding("not a finding")

    def test_missing_type_raises_malformed_error(self, mapper):
        with pytest.raises(sm.MalformedFindingError):
            mapper.ingest_finding({"target": "example.com", "value": {}})

    def test_missing_optional_fields_degrade_gracefully(self, mapper):
        result = mapper.ingest_finding({"type": "dns_record"})
        assert result["status"] == "ingested"
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, TARGET))
        assert host is not None
        assert host["confidence"] == sm.CONFIDENCE_LOW

    def test_value_is_a_bare_string_does_not_crash(self, mapper):
        result = mapper.ingest_finding(finding("tls_san", "sub.example.com"))
        assert result["status"] == "ingested"

    def test_endpoint_finding_missing_url_falls_back_to_generic(self, mapper):
        result = mapper.ingest_finding(finding("endpoint_discovered", {"status_code": 200}))
        assert result["status"] == "ingested"

    def test_ingest_many_isolates_bad_records_from_good_ones(self, mapper):
        records = [
            "garbage",
            {"no_type_field": True},
            finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}),
        ]
        summary = mapper.ingest_many(records)
        assert summary["total"] == 3
        assert summary["ingested"] == 1
        assert summary["errors"] == 2
        assert sm._aid(sm.ASSET_HOSTNAME, TARGET) in mapper.state["assets"]

    def test_corrupt_pending_assets_file_raises_persistence_error(self, mapper, tmp_path):
        bad = tmp_path / "pending_assets.json"
        bad.write_text("{not valid json")
        with pytest.raises(sm.PersistenceError):
            mapper.ingest_pending_assets_file(str(bad))

    def test_missing_pending_assets_file_returns_empty_summary_not_error(self, mapper, tmp_path):
        result = mapper.ingest_pending_assets_file(str(tmp_path / "does_not_exist.json"))
        assert result["total"] == 0


# ---------------------------------------------------------------------------
# Failure handling — one bad observation never breaks the whole ingest
# ---------------------------------------------------------------------------

class TestFailureHandling:
    def test_handler_exception_is_isolated_and_recorded(self, mapper, monkeypatch):
        def boom(finding_record, obs_id):
            raise RuntimeError("simulated handler failure")

        monkeypatch.setitem(mapper._dispatch, "dns_record", boom)
        result = mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        assert result["status"] == "handler_error"
        assert len(mapper.state["ingestion_errors"]) == 1
        assert "simulated handler failure" in mapper.state["ingestion_errors"][0]["error"]
        # the observation itself is still preserved even though correlation failed
        assert len(mapper.state["observations"]) == 1

    def test_ingest_finding_still_saves_after_handler_error(self, mapper, monkeypatch, tmp_path):
        def boom(finding_record, obs_id):
            raise RuntimeError("boom")

        monkeypatch.setitem(mapper._dispatch, "dns_record", boom)
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        reloaded = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        assert len(reloaded.state["observations"]) == 1


# ---------------------------------------------------------------------------
# Scope helper
# ---------------------------------------------------------------------------

class TestScope:
    def test_is_in_scope(self):
        assert sm.is_in_scope("www.example.com", "example.com") is True
        assert sm.is_in_scope("example.com", "example.com") is True
        assert sm.is_in_scope("evilexample.com", "example.com") is False
        assert sm.is_in_scope("example.com.evil.com", "example.com") is False

    def test_out_of_scope_hostname_is_still_recorded_but_tagged(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "CNAME", "records": ["cdn.thirdparty.net"]},
                                       target="assets.example.com"))
        cname_asset = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, "cdn.thirdparty.net"))
        assert cname_asset is not None
        assert cname_asset["in_scope"] is False


# ---------------------------------------------------------------------------
# Regression tests against the *actual* value shapes the producing modules
# emit (verified by reading each producer's make_finding() call sites), rather
# than shapes invented for the mapper's convenience. Every case below failed
# before the corresponding fix.
# ---------------------------------------------------------------------------

class TestRealProducerValueShapes:
    def test_passive_recon_flat_certificate_records_subject_issuer_and_sans(self, mapper):
        """passive_recon.py's `tls_certificate` value IS the parsed cert, not {"certificate": ...}."""
        mapper.ingest_finding(finding(
            "tls_certificate",
            {"subject": {"CN": "example.com"}, "issuer": {"CN": "R3"},
             "not_valid_before": "2026-01-01", "not_valid_after": "2027-01-01",
             "serial_number": "1", "sans": ["api.example.com"]},
            source="passive_recon.py", confidence="HIGH"))
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, "example.com"))
        assert host["attributes"]["tls_cert_subject"]["value"] == {"CN": "example.com"}
        assert host["attributes"]["tls_cert_issuer"]["value"] == {"CN": "R3"}
        assert mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, "api.example.com")) is not None

    def test_ssl_analyzer_dict_shaped_sans_do_not_create_phantom_hostnames(self, mapper):
        """ssl_analyzer.extract_sans() returns {"sans": [...], "count": n} — never iterate the dict."""
        mapper.ingest_finding(finding(
            "tls_certificate_analysis",
            {"host": "example.com", "port": 443,
             "certificate": {"subject": {"CN": "example.com"}, "issuer": {"CN": "R3"}},
             "sans": {"sans": ["a.example.com", "b.example.com"], "count": 2}},
            source="ssl_analyzer.py", confidence="HIGH"))
        hostnames = {a["value"] for a in mapper.state["assets"].values()
                     if a["asset_type"] == sm.ASSET_HOSTNAME}
        assert hostnames == {"example.com", "a.example.com", "b.example.com"}
        assert "sans" not in hostnames and "count" not in hostnames

    def test_ssl_analyzer_dict_shaped_self_signed_is_unwrapped_to_a_bool(self, mapper):
        """detect_self_signed() returns a dict; stored whole, "not self-signed" reads as truthy."""
        mapper.ingest_finding(finding(
            "tls_certificate_analysis",
            {"host": "example.com", "certificate": {"subject": {}, "issuer": {}},
             "self_signed": {"self_signed": False, "confidence": "LOW", "evidence": []}},
            source="ssl_analyzer.py", confidence="HIGH"))
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, "example.com"))
        assert host["attributes"]["tls_self_signed"]["value"] is False

    def test_http_analyzer_list_shaped_waf_vendors_are_recorded(self, mapper):
        """detect_waf() returns {"vendors": [{"vendor": ..., "evidence": [...]}]} — a list."""
        mapper.ingest_finding(finding(
            "waf_detected",
            {"detected": True, "vendors": [{"vendor": "Cloudflare", "evidence": ["header 'server'"]},
                                            {"vendor": "Akamai", "evidence": ["header 'x-akamai'"]}]},
            source="http_analyzer.py", confidence="MEDIUM",
            metadata={"url": "https://example.com/"}))
        techs = {a["value"]["name"] for a in mapper.state["assets"].values()
                 if a["asset_type"] == sm.ASSET_TECHNOLOGY}
        assert techs == {"Cloudflare", "Akamai"}
        for tech in (a for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_TECHNOLOGY):
            assert tech["attributes"]["category"]["value"] == "waf"

    def test_crawler_file_upload_category_raises_high_priority_opportunity(self, mapper):
        """crawler.classify_form() labels this "file_upload", not "upload"."""
        mapper.ingest_finding(finding(
            "crawled_form",
            {"method": "POST", "action": "/upload", "resolved_action": "https://example.com/upload",
             "classification": "file_upload", "not_fetched": True},
            source="crawler.py", confidence="HIGH",
            metadata={"category": "file_upload", "source_page": "https://example.com/"}))
        endpoint = mapper.get_asset(sm._aid(sm.ASSET_ENDPOINT, "https://example.com/upload"))
        assert endpoint["attributes"]["file_upload_surface"]["value"] is True
        opps = [o for o in mapper.get_pending_opportunities()
                if o["opportunity_type"] == "file_upload_surface_review"]
        assert len(opps) == 1 and opps[0]["priority"] == "HIGH"

    def test_dns_records_given_as_a_bare_string_do_not_mint_per_character_assets(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": "1.2.3.4"},
                                       source="passive_recon.py"))
        ips = {a["value"] for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_IP}
        assert ips == {"1.2.3.4"}


class TestIdempotency:
    def test_record_without_a_timestamp_is_not_re_ingested_on_every_run(self, mapper):
        """A substituted timestamp must not become part of the observation identity."""
        record = {"type": "exposure_finding", "target": TARGET, "source": "exposure_scan.py",
                  "value": {"url": "https://example.com/.env"}}
        statuses = [mapper.ingest_finding(dict(record))["status"] for _ in range(3)]
        assert statuses == ["ingested", "duplicate_skipped", "duplicate_skipped"]
        assert len(mapper.state["observations"]) == 1

    def test_distinct_timestamps_remain_distinct_observations(self, mapper):
        base = {"type": "exposure_finding", "target": TARGET, "source": "exposure_scan.py",
                "value": {"url": "https://example.com/.env"}}
        mapper.ingest_finding({**base, "timestamp": "2026-01-01T00:00:00+00:00"})
        mapper.ingest_finding({**base, "timestamp": "2026-01-01T00:00:00+00:00"})
        mapper.ingest_finding({**base, "timestamp": "2026-01-02T00:00:00+00:00"})
        assert len(mapper.state["observations"]) == 2

    def test_repeated_file_ingestion_leaves_the_graph_unchanged(self, mapper, tmp_path):
        records = [
            finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}, source="passive_recon.py",
                    timestamp="2026-01-01T00:00:00+00:00"),
            {"type": "exposure_finding", "target": TARGET, "source": "exposure_scan.py",
             "value": {"url": "https://example.com/.env"}},   # no timestamp
        ]
        path = os.path.join(str(tmp_path), "pending_assets.json")
        with open(path, "w") as handle:
            json.dump(records, handle)

        first = mapper.ingest_pending_assets_file(path)
        baseline = mapper.summary()
        second = mapper.ingest_pending_assets_file(path)
        assert first["ingested"] == 2 and first["duplicates"] == 0
        assert second["ingested"] == 0 and second["duplicates"] == 2
        assert mapper.summary() == baseline


class TestGenericSubjectAssetsStayConnected:
    """
    A finding routed through the generic handler mints its own subject asset.
    That asset must be attached to the asset that owns it, or it is unreachable
    from the target root and drops out of explain_asset_path() and
    build_attack_surface_tree() — context.md §7's single connected graph and
    §9's attack-surface paths both depend on the edge existing.
    """

    def test_url_subject_is_linked_to_its_owning_hostname(self, mapper):
        mapper.ingest_finding(finding(
            "exposure_finding",
            {"url": "https://example.com/.env", "exposure_category": "environment_file",
             "discovery_type": "confirmed_exposure", "status_code": 200},
            source="exposure_scan.py"))
        endpoint_id = sm._aid(sm.ASSET_ENDPOINT, "https://example.com/.env")
        rel_types = {r["rel_type"] for r in mapper.relationships_for(endpoint_id)}
        assert sm.REL_ASSET_TO_ENDPOINT in rel_types
        assert sm.REL_ASSET_TO_FINDING in rel_types

    def test_generic_finding_subject_is_reachable_from_the_target_root(self, mapper):
        mapper.ingest_finding(finding(
            "exposure_finding",
            {"url": "https://example.com/admin/", "exposure_category": "administrative_panel",
             "discovery_type": "confirmed_exposure", "status_code": 200},
            source="exposure_scan.py"))
        path = mapper.explain_asset_path(sm._aid(sm.ASSET_ENDPOINT, "https://example.com/admin/"))
        assert [hop["asset_id"] for hop in path][0] == sm._aid(sm.ASSET_HOSTNAME, TARGET)
        assert path[-1]["asset_type"] == sm.ASSET_ENDPOINT

    def test_ip_and_port_subject_is_linked_to_its_ip(self, mapper):
        mapper.ingest_finding(finding(
            "http_options_result", {"ip": "1.2.3.4", "port": 8080, "protocol": "tcp"},
            source="exposure_scan.py"))
        port_id = sm._aid(sm.ASSET_PORT, "1.2.3.4", 8080, "tcp")
        assert sm.REL_IP_TO_SERVICE in {r["rel_type"] for r in mapper.relationships_for(port_id)}

    def test_technology_subject_is_linked_to_its_host(self, mapper):
        mapper.ingest_finding(finding(
            "vulnerability_intelligence",
            {"cve_id": "CVE-1", "technology": "nginx", "version": "1.18.0"},
            source="vuln_intel.py"))
        tech_id = sm._aid(sm.ASSET_TECHNOLOGY, TARGET, "nginx")
        assert sm.REL_ASSET_TO_TECHNOLOGY in {r["rel_type"] for r in mapper.relationships_for(tech_id)}
        assert mapper.explain_asset_path(tech_id)

    def test_out_of_scope_url_subject_is_still_linked_and_tagged(self, mapper):
        mapper.ingest_finding(finding(
            "exposure_finding",
            {"url": "https://evil-cdn.net/.env", "exposure_category": "environment_file",
             "discovery_type": "confirmed_exposure", "status_code": 200},
            source="exposure_scan.py"))
        endpoint = mapper.get_asset(sm._aid(sm.ASSET_ENDPOINT, "https://evil-cdn.net/.env"))
        host = mapper.get_asset(sm._aid(sm.ASSET_HOSTNAME, "evil-cdn.net"))
        assert endpoint["in_scope"] is False and host["in_scope"] is False
        assert sm.REL_ASSET_TO_ENDPOINT in {r["rel_type"] for r in mapper.relationships_for(endpoint["id"])}


class TestReferenceHostQualification:
    def test_same_path_on_two_subdomains_stays_two_endpoints(self, mapper):
        """wayback_intel.py emits {"endpoint": "/search", "url": "https://<host>/search?..."}."""
        for host in ("shop", "blog"):
            mapper.ingest_finding(finding(
                "historical_parameter",
                {"name": "id", "location": "query", "endpoint": "/search",
                 "url": f"https://{host}.example.com/search?id=1"},
                source="wayback_intel.py", confidence="LOW",
                timestamp=f"2026-01-01T00:00:0{len(host)}+00:00"))
        endpoints = {a["id"] for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_ENDPOINT}
        params = {a["id"] for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_PARAMETER}
        assert endpoints == {"endpoint:https://shop.example.com/search", "endpoint:https://blog.example.com/search"}
        assert len(params) == 2

    def test_path_only_endpoint_reference_correlates_with_its_absolute_observation(self, mapper):
        """A path-only historical reference must merge with the crawler's absolute URL for the same endpoint."""
        mapper.ingest_finding(finding("crawled_url", {"url": "https://example.com/legacy/api", "status_code": 200},
                                       source="crawler.py"))
        mapper.ingest_finding(finding("historical_endpoint_reference",
                                       {"url": "/legacy/api", "path": "/legacy/api", "historical": True},
                                       source="endpoint_discovery.py", confidence="LOW"))
        endpoints = [a for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_ENDPOINT]
        assert len(endpoints) == 1
        assert endpoints[0]["attributes"]["historical"]["value"] is True
        assert set(endpoints[0]["sources"]) == {"crawler.py", "endpoint_discovery.py"}

    def test_relative_js_reference_resolves_against_the_scripts_own_host(self, mapper):
        mapper.ingest_finding(finding(
            "js_analyzer_endpoint_reference", {"url": "/v2/users", "kind": "api_endpoint"},
            source="js_analyzer.py", confidence="MEDIUM",
            metadata={"parent_js_url": "https://api.example.com/static/app.js"}))
        assert mapper.get_asset("endpoint:https://api.example.com/v2/users") is not None

    def test_url_case_variants_produce_one_endpoint_and_one_parameter(self, mapper):
        for url, ts in (("https://example.com/a", "2026-01-01T00:00:00+00:00"),
                        ("HTTPS://Example.COM/a", "2026-01-02T00:00:00+00:00")):
            mapper.ingest_finding(finding("endpoint_parameter",
                                           {"name": "q", "location": "query", "endpoint": url},
                                           source="endpoint_discovery.py", timestamp=ts))
        assert len([a for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_ENDPOINT]) == 1
        assert len([a for a in mapper.state["assets"].values() if a["asset_type"] == sm.ASSET_PARAMETER]) == 1


class TestOpportunityScopeEnforcement:
    def test_no_opportunity_is_emitted_for_an_out_of_scope_asset(self, mapper):
        mapper.ingest_finding(finding(
            "js_analyzer_endpoint_reference",
            {"url": "https://api.thirdparty-cdn.net/v1/users", "kind": "api_endpoint"},
            source="js_analyzer.py", confidence="MEDIUM",
            metadata={"parent_js_url": "https://example.com/app.js"}))
        assert mapper.get_pending_opportunities() == []

    def test_out_of_scope_asset_and_its_suppression_are_still_recorded(self, mapper):
        """Scope suppression must be visible, never a silent drop (design principle 11)."""
        mapper.ingest_finding(finding(
            "js_analyzer_endpoint_reference",
            {"url": "https://api.thirdparty-cdn.net/v1/users", "kind": "api_endpoint"},
            source="js_analyzer.py", confidence="MEDIUM",
            metadata={"parent_js_url": "https://example.com/app.js"}))
        asset = mapper.get_asset("endpoint:https://api.thirdparty-cdn.net/v1/users")
        assert asset is not None and asset["in_scope"] is False
        suppressed = asset["suppressed_opportunities"]["js_referenced_endpoint_verification"]
        assert "outside the authorized target scope" in suppressed["suppressed_because"]

    def test_in_scope_reference_still_raises_its_opportunity(self, mapper):
        mapper.ingest_finding(finding(
            "js_analyzer_endpoint_reference",
            {"url": "https://api.example.com/v1/users", "kind": "api_endpoint"},
            source="js_analyzer.py", confidence="MEDIUM",
            metadata={"parent_js_url": "https://example.com/app.js"}))
        assert [o["opportunity_type"] for o in mapper.get_pending_opportunities()] == \
            ["js_referenced_endpoint_verification"]


class TestOpportunityIdempotency:
    def test_consumed_opportunity_is_not_resurrected_by_a_later_observation(self, mapper):
        def upload_form(ts):
            return finding("crawled_form",
                            {"resolved_action": "https://example.com/upload", "classification": "file_upload"},
                            source="crawler.py", confidence="HIGH", timestamp=ts,
                            metadata={"category": "file_upload"})

        mapper.ingest_finding(upload_form("2026-01-01T00:00:00+00:00"))
        opp = mapper.get_pending_opportunities()[0]
        mapper.consume_opportunity(opp["id"])

        mapper.ingest_finding(upload_form("2026-01-02T00:00:00+00:00"))
        assert mapper.get_pending_opportunities() == []
        assert mapper.state["opportunities"][opp["id"]]["status"] == "consumed"

    def test_repeated_observation_of_a_pending_opportunity_records_the_new_evidence(self, mapper):
        def form(ts):
            return finding("crawled_form",
                            {"resolved_action": "https://example.com/upload", "classification": "file_upload"},
                            source="crawler.py", confidence="HIGH", timestamp=ts,
                            metadata={"category": "file_upload"})

        mapper.ingest_finding(form("2026-01-01T00:00:00+00:00"))
        mapper.ingest_finding(form("2026-01-02T00:00:00+00:00"))
        opps = mapper.get_pending_opportunities()
        assert len(opps) == 1 and len(opps[0]["observation_ids"]) == 2


class TestCheckStateMemory:
    def test_unchecked_pair_reports_not_checked(self, mapper):
        assert mapper.get_check_state("hostname:example.com", "tls_certificate") == sm.CHECK_NOT_CHECKED

    def test_confident_positive_observation_records_found(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]},
                                       source="passive_recon.py", confidence="HIGH"))
        assert mapper.get_check_state(sm._aid(sm.ASSET_HOSTNAME, "example.com"), "dns_record") == sm.CHECK_FOUND

    def test_low_confidence_positive_records_found_with_uncertainty(self, mapper):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]},
                                       source="passive_recon.py", confidence="LOW"))
        assert mapper.get_check_state(sm._aid(sm.ASSET_HOSTNAME, "example.com"), "dns_record") \
            == sm.CHECK_FOUND_UNCERTAIN

    def test_negative_result_records_checked_not_found(self, mapper):
        mapper.ingest_finding(finding("tech_fingerprint_checked_no_match",
                                       {"category": "cms", "url": "https://example.com/"},
                                       source="tech_fingerprint.py", confidence="LOW"))
        url_id = sm._aid(sm.ASSET_ENDPOINT, sm._norm_url("https://example.com/"))
        assert mapper.get_check_state(url_id, "tech_fingerprint_checked_no_match") == sm.CHECK_NOT_FOUND

    def test_distinct_check_scopes_are_preserved_not_overwritten(self, mapper):
        """tech_fingerprint.py emits one negative per signature category; all of them matter."""
        for index, category in enumerate(("cms", "framework", "server", "waf")):
            mapper.ingest_finding(finding("tech_fingerprint_checked_no_match",
                                           {"category": category, "url": "https://example.com/"},
                                           source="tech_fingerprint.py", confidence="LOW",
                                           timestamp=f"2026-01-0{index + 1}T00:00:00+00:00"))
        url_id = sm._aid(sm.ASSET_ENDPOINT, sm._norm_url("https://example.com/"))
        record = mapper.get_negative_result(url_id, "tech_fingerprint_checked_no_match")
        assert record["check_count"] == 4
        assert [c["value"]["category"] for c in record["checks"]] == ["cms", "framework", "server", "waf"]

    def test_check_state_survives_a_reload(self, mapper, tmp_path):
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]},
                                       source="passive_recon.py", confidence="HIGH"))
        mapper.save()
        reloaded = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        assert reloaded.get_check_state(sm._aid(sm.ASSET_HOSTNAME, "example.com"), "dns_record") == sm.CHECK_FOUND


class TestStateFileRobustness:
    def _write_state(self, tmp_path, mutate):
        mapper = sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        mapper.save()
        path = os.path.join(str(tmp_path), "surface_graph.json")
        with open(path) as handle:
            state = json.load(handle)
        mutate(state)
        with open(path, "w") as handle:
            json.dump(state, handle)
        return sm.SurfaceMapper(target=TARGET, output_dir=str(tmp_path))

    def test_state_file_missing_a_container_still_loads(self, tmp_path):
        def drop(state):
            del state["opportunities"]
        reloaded = self._write_state(tmp_path, drop)
        assert reloaded.summary()["assets"] == 2
        assert reloaded.get_pending_opportunities() == []

    def test_container_of_the_wrong_type_is_replaced_and_the_original_preserved(self, tmp_path):
        def corrupt(state):
            state["conflicts"] = ["not-an-object"]
        reloaded = self._write_state(tmp_path, corrupt)
        assert reloaded.get_conflicts() == []
        errors = [e for e in reloaded.state["ingestion_errors"] if "conflicts" in e.get("error", "")]
        assert len(errors) == 1 and errors[0]["raw"] == ["not-an-object"]

    def test_recovered_state_still_ingests_and_saves(self, tmp_path):
        def drop(state):
            del state["check_states"]
        reloaded = self._write_state(tmp_path, drop)
        reloaded.ingest_finding(finding("open_tcp_port", {"ip": "5.6.7.8", "port": 443, "protocol": "tcp"},
                                         source="active_recon.py"))
        reloaded.save()
        with open(os.path.join(str(tmp_path), "surface_graph.json")) as handle:
            json.load(handle)
        assert reloaded.get_asset(sm._aid(sm.ASSET_IP, "5.6.7.8")) is not None


class TestConcurrency:
    def test_parallel_ingestion_loses_no_observation(self, mapper):
        """core/orchestrator.py coordinates threading; the shared graph is the contended state."""
        import threading

        errors = []

        def worker(worker_id):
            try:
                for index in range(40):
                    mapper.ingest_finding(finding(
                        "dns_record", {"record_type": "A", "records": [f"10.{worker_id}.0.{index}"]},
                        target=f"h{worker_id}-{index}.example.com", source=f"module{worker_id}.py",
                        timestamp=f"2026-01-01T00:00:{index:02d}+00:00"))
            except Exception as exc:  # pragma: no cover - only on a real race
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert len(mapper.state["observations"]) == 6 * 40
        assert len(mapper.state["ingestion_errors"]) == 0

    def test_parallel_batch_ingestion_restores_autosave(self, mapper):
        import threading

        def worker(worker_id):
            mapper.ingest_many([
                finding("open_tcp_port", {"ip": f"10.{worker_id}.0.{index}", "port": 443, "protocol": "tcp"},
                        source=f"module{worker_id}.py", timestamp=f"2026-01-01T00:00:{index:02d}+00:00")
                for index in range(30)])

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert mapper.autosave is True
        assert len(mapper.state["observations"]) == 4 * 30


class TestAttackSurfacePathTruncation:
    def test_truncated_path_does_not_fabricate_a_root_hop(self, mapper):
        """A chain longer than max_hops must report the ancestor it reached, not the root."""
        mapper.ingest_finding(finding("dns_record", {"record_type": "A", "records": ["1.2.3.4"]}))
        mapper.ingest_finding(finding("open_tcp_port", {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
                                       source="active_recon.py"))
        mapper.ingest_finding(finding("service_identification",
                                       {"ip": "1.2.3.4", "port": 443, "protocol": "tcp", "service": "https"},
                                       source="active_recon.py"))
        port_id = sm._aid(sm.ASSET_PORT, "1.2.3.4", 443, "tcp")
        full = mapper.explain_asset_path(port_id)
        assert [hop["asset_id"] for hop in full][0] == sm._aid(sm.ASSET_HOSTNAME, TARGET)

        truncated = mapper.explain_asset_path(port_id, max_hops=1)
        assert truncated[0]["asset_id"] != sm._aid(sm.ASSET_HOSTNAME, TARGET)
        assert truncated[0]["truncated"] is True


if __name__ == "__main__":
    import subprocess
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v"])
