"""
Tests for reconhound/api_recon.py (ReconHound Module 11, per context.md's
build order — catalog item 11, build-order position 21).

Run with:  ./.venv/bin/python -m pytest tests/test_api_recon.py -v

All tests mock the `requests.get`/`requests.post`/`requests.options`/
`requests.head` boundary so the suite is deterministic and offline-safe; no
external network access is required or performed anywhere in this file.
"""

import json
import os
import sys
from unittest import mock

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import api_recon as ar


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


def _not_found_response():
    return _fake_response(status_code=404, body=b"not found")


def _dispatcher(mapping, default=None):
    """
    Build a side_effect callable for requests.get/post/etc. that returns a
    canned _fake_response based on the request URL, so multi-candidate
    discovery functions (which issue many requests to different URLs) can
    be tested deterministically without depending on call order.
    """
    default_resp = default if default is not None else _not_found_response()

    def _side_effect(url, **kwargs):
        for needle, resp in mapping.items():
            if needle in url:
                return resp
        return default_resp

    return _side_effect


# ---------------------------------------------------------------------------
# validate_api_target (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateApiTarget:
    def test_accepts_https_url(self):
        assert ar.validate_api_target("https://example.com/path") == "https://example.com/path"

    def test_accepts_in_scope_subdomain(self):
        assert ar.validate_api_target("https://api.example.com/", target="example.com")

    def test_rejects_out_of_scope_host(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_api_target("https://evil.com/", target="example.com")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_api_target("ftp://example.com/")

    def test_rejects_missing_hostname(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_api_target("https:///path")

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(ar.ScopeError):
            ar.validate_api_target(bad)

    def test_allows_ip_literal_host_without_scope_check(self):
        assert ar.validate_api_target("http://93.184.216.34/", target="example.com")


# ---------------------------------------------------------------------------
# make_finding / PendingAssetsStore (shared conventions)
# ---------------------------------------------------------------------------

class TestFindingsAndStore:
    def test_finding_structure_and_source(self):
        finding = ar.make_finding("api_version_discovered", SAFE_URL, {"a": 1}, ["e"], ar.CONFIDENCE_HIGH)
        assert finding["source"] == "api_recon.py"
        assert finding["metadata"] == {}
        json.dumps(finding)

    def test_store_preserves_prior_data(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [{"type": "dns_record", "source": "passive_recon.py"}]
        pending.write_text(json.dumps(pre_existing))

        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        store.add(ar.make_finding("api_version_discovered", SAFE_URL, {}, ["e"], ar.CONFIDENCE_HIGH))
        assert store.all() == pre_existing + [store.all()[-1]]

    def test_corrupt_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not json")
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(ar.PersistenceError):
            store.add(ar.make_finding("api_version_discovered", SAFE_URL, {}, ["e"], ar.CONFIDENCE_HIGH))

    def test_safe_store_add_returns_none_when_store_is_none(self):
        assert ar._safe_store_add(None, ar.make_finding("x", SAFE_URL, {}, [], ar.CONFIDENCE_LOW)) is None

    def test_safe_store_add_returns_error_string_on_persistence_failure(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("not json at all")
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        err = ar._safe_store_add(store, ar.make_finding("x", SAFE_URL, {}, [], ar.CONFIDENCE_LOW))
        assert err is not None


# ---------------------------------------------------------------------------
# Shared HTTP client: fetch_url / fetch_url_post / fetch_url_options /
# fetch_url_head
# ---------------------------------------------------------------------------

class TestFetchHelpers:
    def test_fetch_url_success(self):
        resp = _fake_response(status_code=200, headers={"Content-Type": "application/json"}, body=b'{"a":1}')
        with mock.patch("requests.get", return_value=resp):
            result = ar.fetch_url(SAFE_URL)
        assert result["status"] == "found"
        assert result["status_code"] == 200
        assert result["body"] == '{"a":1}'
        json.dumps(result)

    def test_fetch_url_body_truncated(self):
        resp = _fake_response(body=b"x" * 100)
        with mock.patch("requests.get", return_value=resp):
            result = ar.fetch_url(SAFE_URL, max_body_bytes=10)
        assert result["body_truncated"] is True
        assert len(result["body"]) == 10

    def test_fetch_url_timeout(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = ar.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert result["error"] == "timeout"

    def test_fetch_url_connection_error(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = ar.fetch_url(SAFE_URL)
        assert result["status"] == "error"
        assert "connection error" in result["error"]

    def test_fetch_url_generic_request_exception(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.RequestException("boom")):
            result = ar.fetch_url(SAFE_URL)
        assert result["status"] == "error"

    def test_fetch_url_post_sends_json_body(self):
        resp = _fake_response(status_code=200, body=b'{"data":{"__typename":"Query"}}')
        with mock.patch("requests.post", return_value=resp) as mock_post:
            result = ar.fetch_url_post(SAFE_URL, json_body={"query": "{ __typename }"})
        assert result["status"] == "found"
        assert mock_post.call_args.kwargs.get("json") == {"query": "{ __typename }"}

    def test_fetch_url_options_uses_requests_options(self):
        resp = _fake_response(status_code=200, headers={"Allow": "GET, POST"})
        with mock.patch("requests.options", return_value=resp):
            result = ar.fetch_url_options(SAFE_URL)
        assert result["status"] == "found"
        assert result["headers"]["Allow"] == "GET, POST"

    def test_fetch_url_head_uses_requests_head(self):
        resp = _fake_response(status_code=200, body=b"")
        with mock.patch("requests.head", return_value=resp):
            result = ar.fetch_url_head(SAFE_URL)
        assert result["status"] == "found"
        assert result["status_code"] == 200


# ---------------------------------------------------------------------------
# classify_response
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def test_404_is_not_found(self):
        discovery_type, confidence, _ = ar.classify_response({"status_code": 404}, None)
        assert discovery_type == "not_found"
        assert confidence == ar.CONFIDENCE_HIGH

    def test_200_is_content_confirmed_without_baseline(self):
        discovery_type, confidence, _ = ar.classify_response({"status_code": 200, "body": "hi"}, None)
        assert discovery_type == "content_confirmed"

    def test_soft_404_match_downgrades_confidence(self):
        baseline = {"available": True, "status_code": 200, "content_length": 2, "body_hash": ar._content_signature("hi")[1]}
        discovery_type, confidence, _ = ar.classify_response({"status_code": 200, "body": "hi"}, baseline)
        assert discovery_type == "possible_soft_404_match"
        assert confidence == ar.CONFIDENCE_LOW

    def test_401_is_access_restricted(self):
        discovery_type, confidence, _ = ar.classify_response({"status_code": 401}, None)
        assert discovery_type == "access_restricted"

    def test_405_is_method_not_allowed(self):
        discovery_type, _, _ = ar.classify_response({"status_code": 405}, None)
        assert discovery_type == "method_not_allowed"

    def test_missing_status_code_is_error(self):
        discovery_type, confidence, notes = ar.classify_response({"status_code": None}, None)
        assert discovery_type == "error"
        assert notes


# ---------------------------------------------------------------------------
# parse_openapi_spec
# ---------------------------------------------------------------------------

class TestParseOpenApiSpec:
    def test_parses_valid_openapi_json(self):
        body = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Demo API", "version": "2.1.0"},
            "paths": {"/a": {}, "/b": {}},
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        })
        result = ar.parse_openapi_spec(body, "application/json")
        assert result["spec_type"] == "openapi"
        assert result["version"] == "2.1.0"
        assert result["title"] == "Demo API"
        assert result["path_count"] == 2
        assert result["security_schemes"][0]["scheme"] == "bearer"
        assert result["parse_error"] is None

    def test_parses_valid_swagger2_json_with_security_definitions(self):
        body = json.dumps({
            "swagger": "2.0",
            "info": {"title": "Legacy", "version": "1.0"},
            "paths": {"/x": {}},
            "securityDefinitions": {"apiKeyAuth": {"type": "apiKey", "name": "X-API-Key", "in": "header"}},
        })
        result = ar.parse_openapi_spec(body, "application/json")
        assert result["spec_type"] == "swagger"
        assert result["security_schemes"][0]["type"] == "apiKey"

    def test_oauth2_flows_extracted(self):
        body = json.dumps({
            "openapi": "3.0.0", "info": {"version": "1.0"}, "paths": {},
            "components": {"securitySchemes": {"oauth": {
                "type": "oauth2", "flows": {"clientCredentials": {}, "authorizationCode": {}},
            }}},
        })
        result = ar.parse_openapi_spec(body, "application/json")
        assert result["security_schemes"][0]["flows"] == ["authorizationCode", "clientCredentials"]

    def test_invalid_json_yields_parse_error_not_exception(self):
        result = ar.parse_openapi_spec("{not valid json", "application/json")
        assert result["parse_error"] is not None
        assert result["spec_type"] is None

    def test_json_root_not_object(self):
        result = ar.parse_openapi_spec("[1,2,3]", "application/json")
        assert result["parse_error"] == "JSON root is not an object"

    def test_best_effort_yaml_extraction(self):
        body = "openapi: 3.0.1\ninfo:\n  title: Demo API\n  version: 1.2.3\npaths:\n  /x: {}\n"
        result = ar.parse_openapi_spec(body, "text/yaml")
        assert result["format"] == "yaml"
        assert result["spec_type"] == "openapi"
        assert result["version"] == "1.2.3"
        assert result["title"] == "Demo API"
        assert result["parse_error"] is not None  # best-effort, always labeled as such

    def test_unrecognized_content_yields_parse_error(self):
        result = ar.parse_openapi_spec("<html>not a spec</html>", "text/html")
        assert result["spec_type"] is None
        assert result["parse_error"] is not None

    def test_empty_body(self):
        result = ar.parse_openapi_spec("", None)
        assert result["parse_error"] == "empty body"

    def test_result_always_json_serializable(self):
        for body in ["{bad", "[1,2]", "openapi: 3.0.0\ninfo:\n  version: 1\n", "", "plain text"]:
            json.dumps(ar.parse_openapi_spec(body, None))


# ---------------------------------------------------------------------------
# 1. discover_api_versions
# ---------------------------------------------------------------------------

class TestDiscoverApiVersions:
    def test_identifies_existing_versions_and_skips_missing(self):
        mapping = {
            "api/v1/": _fake_response(200, {"Content-Type": "application/json"}, b'{"version":"1.0"}'),
            "api/v2/": _fake_response(200, {"Content-Type": "application/json"}, b'{"version":"2.0"}'),
        }
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            result = ar.discover_api_versions(SAFE_URL, target=SAFE_TARGET, version_range=range(1, 4))

        identified_paths = {r["path_template"] for r in result["versions_identified"]}
        assert "api/v1/" in identified_paths
        assert "api/v2/" in identified_paths
        assert "api/v3/" not in identified_paths  # 404 -> not identified

    def test_version_string_hint_extracted_from_body(self):
        mapping = {"api/v1/": _fake_response(200, {"Content-Type": "application/json"}, b'{"api_version":"1.4.2"}')}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            result = ar.discover_api_versions(SAFE_URL, target=SAFE_TARGET, version_range=range(1, 2))
        v1_records = [r for r in result["versions_identified"] if r["path_template"] == "api/v1/"]
        assert v1_records and v1_records[0]["version_string_hint"] == "1.4.2"

    def test_persists_findings(self, tmp_path):
        output_dir = tmp_path / "output"
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        mapping = {"api/v1/": _fake_response(200, body=b"{}")}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            ar.discover_api_versions(SAFE_URL, target=SAFE_TARGET, store=store, version_range=range(1, 2))
        stored_types = {f["type"] for f in store.all()}
        assert "api_version_discovered" in stored_types

    def test_request_errors_are_recorded_not_raised(self):
        with mock.patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = ar.discover_api_versions(SAFE_URL, target=SAFE_TARGET, version_range=range(1, 2))
        assert result["versions_identified"] == []
        assert result["errors"]

    def test_result_json_serializable(self):
        mapping = {"api/v1/": _fake_response(200, body=b'{"version":"1.0"}')}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            result = ar.discover_api_versions(SAFE_URL, target=SAFE_TARGET, version_range=range(1, 2))
        json.dumps(result)


# ---------------------------------------------------------------------------
# 2. discover_openapi_specs
# ---------------------------------------------------------------------------

class TestDiscoverOpenApiSpecs:
    def test_discovers_canonical_swagger_json(self):
        spec_body = json.dumps({"swagger": "2.0", "info": {"version": "1.0", "title": "T"}, "paths": {}})
        mapping = {"swagger.json": _fake_response(200, {"Content-Type": "application/json"}, spec_body.encode())}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            result = ar.discover_openapi_specs(SAFE_URL, target=SAFE_TARGET)
        urls = [s["url"] for s in result["specs_discovered"]]
        assert any("swagger.json" in u for u in urls)
        matched = [s for s in result["specs_discovered"] if "swagger.json" in s["url"]][0]
        assert matched["spec_type"] == "swagger"
        assert matched["version"] == "1.0"

    def test_generic_200_at_non_canonical_path_is_ignored(self):
        mapping = {"openapi.json": _fake_response(200, {"Content-Type": "text/html"}, b"<html>unrelated</html>")}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            result = ar.discover_openapi_specs(SAFE_URL, target=SAFE_TARGET)
        assert result["specs_discovered"] == []

    def test_canonical_path_restricted_is_recorded_medium_confidence(self, tmp_path):
        output_dir = tmp_path / "output"
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        mapping = {"api-docs": _fake_response(401)}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            result = ar.discover_openapi_specs(SAFE_URL, target=SAFE_TARGET, store=store)
        matched = [s for s in result["specs_discovered"] if "api-docs" in s["url"]]
        assert matched and matched[0]["discovery_type"] == "access_restricted"

    def test_no_specs_found_returns_empty_list_gracefully(self):
        with mock.patch("requests.get", return_value=_not_found_response()):
            result = ar.discover_openapi_specs(SAFE_URL, target=SAFE_TARGET)
        assert result["specs_discovered"] == []
        assert result["errors"] == []

    def test_result_json_serializable(self):
        spec_body = json.dumps({"openapi": "3.0.0", "info": {"version": "1.0"}, "paths": {}})
        mapping = {"openapi.json": _fake_response(200, body=spec_body.encode())}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            result = ar.discover_openapi_specs(SAFE_URL, target=SAFE_TARGET)
        json.dumps(result)


# ---------------------------------------------------------------------------
# 6. discover_documentation_pages
# ---------------------------------------------------------------------------

class TestDiscoverDocumentationPages:
    def test_detects_swagger_ui_markers_high_confidence(self):
        mapping = {"swagger-ui.html": _fake_response(200, body=b"<html><script src='swagger-ui-bundle.js'></script></html>")}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            result = ar.discover_documentation_pages(SAFE_URL, target=SAFE_TARGET)
        matched = [p for p in result["pages_discovered"] if "swagger-ui.html" in p["url"]]
        assert matched and matched[0]["markers_found"]

    def test_generic_page_without_markers_medium_confidence(self, tmp_path):
        output_dir = tmp_path / "output"
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        mapping = {"docs": _fake_response(200, body=b"<html>hello</html>")}
        with mock.patch("requests.get", side_effect=_dispatcher(mapping)):
            ar.discover_documentation_pages(SAFE_URL, target=SAFE_TARGET, store=store)
        findings = [f for f in store.all() if f["type"] == "api_documentation_page_discovered"]
        assert findings and findings[0]["confidence"] == ar.CONFIDENCE_MEDIUM

    def test_not_found_everywhere_returns_empty(self):
        with mock.patch("requests.get", return_value=_not_found_response()):
            result = ar.discover_documentation_pages(SAFE_URL, target=SAFE_TARGET)
        assert result["pages_discovered"] == []


# ---------------------------------------------------------------------------
# 3. detect_graphql_endpoints
# ---------------------------------------------------------------------------

class TestDetectGraphqlEndpoints:
    def test_confirms_via_typename_post_probe(self):
        get_mapping = {"graphql": _fake_response(400, body=b"must provide query string")}
        post_mapping = {"graphql": _fake_response(200, body=b'{"data":{"__typename":"Query"}}')}
        with mock.patch("requests.get", side_effect=_dispatcher(get_mapping)), \
             mock.patch("requests.post", side_effect=_dispatcher(post_mapping)):
            result = ar.detect_graphql_endpoints(SAFE_URL, target=SAFE_TARGET)
        confirmed = [e for e in result["endpoints_detected"] if e["confirmed_via"] == "post_typename_probe"]
        assert confirmed
        assert confirmed[0]["confidence"] == ar.CONFIDENCE_HIGH

    def test_no_graphql_present_returns_empty(self):
        with mock.patch("requests.get", return_value=_not_found_response()), \
             mock.patch("requests.post", return_value=_not_found_response()):
            result = ar.detect_graphql_endpoints(SAFE_URL, target=SAFE_TARGET)
        assert result["endpoints_detected"] == []

    def test_weak_get_heuristic_used_when_post_inconclusive(self):
        get_mapping = {"graphiql": _fake_response(200, body=b"<html>GraphiQL Playground</html>")}
        with mock.patch("requests.get", side_effect=_dispatcher(get_mapping)), \
             mock.patch("requests.post", return_value=_not_found_response()):
            result = ar.detect_graphql_endpoints(SAFE_URL, target=SAFE_TARGET)
        matched = [e for e in result["endpoints_detected"] if "graphiql" in e["url"]]
        assert matched and matched[0]["confidence"] == ar.CONFIDENCE_LOW

    def test_persists_finding(self, tmp_path):
        output_dir = tmp_path / "output"
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        post_mapping = {"graphql": _fake_response(200, body=b'{"data":{"__typename":"Query"}}')}
        with mock.patch("requests.get", return_value=_not_found_response()), \
             mock.patch("requests.post", side_effect=_dispatcher(post_mapping)):
            ar.detect_graphql_endpoints(SAFE_URL, target=SAFE_TARGET, store=store)
        assert any(f["type"] == "graphql_endpoint_detected" for f in store.all())


# ---------------------------------------------------------------------------
# 4. introspect_graphql_schema
# ---------------------------------------------------------------------------

class TestIntrospectGraphqlSchema:
    GRAPHQL_URL = "https://example.com/graphql"

    def test_disabled_by_caller_returns_skipped(self):
        result = ar.introspect_graphql_schema(self.GRAPHQL_URL, target=SAFE_TARGET, enabled=False)
        assert result["status"] == "skipped"

    def test_successful_introspection_extracts_schema_summary(self):
        schema_payload = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": None,
                    "types": [
                        {"kind": "OBJECT", "name": "Query", "fields": [{"name": "users"}, {"name": "posts"}]},
                        {"kind": "OBJECT", "name": "Mutation", "fields": [{"name": "createUser"}]},
                        {"kind": "SCALAR", "name": "String", "fields": None},
                    ],
                }
            }
        }
        resp = _fake_response(200, body=json.dumps(schema_payload).encode())
        with mock.patch("requests.post", return_value=resp):
            result = ar.introspect_graphql_schema(self.GRAPHQL_URL, target=SAFE_TARGET)
        assert result["status"] == "introspected"
        assert result["query_type"] == "Query"
        assert result["mutation_type"] == "Mutation"
        assert "users" in result["query_fields"]
        assert "createUser" in result["mutation_fields"]
        assert result["type_count"] == 3

    def test_introspection_disabled_by_server_is_recorded(self, tmp_path):
        output_dir = tmp_path / "output"
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        payload = {"errors": [{"message": "GraphQL introspection is not allowed"}]}
        resp = _fake_response(200, body=json.dumps(payload).encode())
        with mock.patch("requests.post", return_value=resp):
            result = ar.introspect_graphql_schema(self.GRAPHQL_URL, target=SAFE_TARGET, store=store)
        assert result["status"] == "disabled"
        assert any(f["type"] == "graphql_introspection_disabled" for f in store.all())

    def test_non_json_response_is_error_not_exception(self):
        resp = _fake_response(200, body=b"<html>not json</html>")
        with mock.patch("requests.post", return_value=resp):
            result = ar.introspect_graphql_schema(self.GRAPHQL_URL, target=SAFE_TARGET)
        assert result["status"] == "error"

    def test_request_failure_is_error_not_exception(self):
        with mock.patch("requests.post", side_effect=requests.exceptions.ConnectionError("refused")):
            result = ar.introspect_graphql_schema(self.GRAPHQL_URL, target=SAFE_TARGET)
        assert result["status"] == "error"

    def test_never_sends_a_mutation(self):
        resp = _fake_response(200, body=b'{"data":{"__schema":null}}')
        with mock.patch("requests.post", return_value=resp) as mock_post:
            ar.introspect_graphql_schema(self.GRAPHQL_URL, target=SAFE_TARGET)
        sent_query = mock_post.call_args.kwargs["json"]["query"]
        assert "mutation" not in sent_query.lower().split("mutationtype")[0].replace("mutationtype", "")
        # the introspection query only ever *asks about* mutationType; it never issues one
        assert sent_query.strip().startswith("query IntrospectionQuery")

    def test_scope_enforced(self):
        with pytest.raises(ar.ScopeError):
            ar.introspect_graphql_schema("https://evil.com/graphql", target=SAFE_TARGET)


# ---------------------------------------------------------------------------
# 5. classify_api_protocol
# ---------------------------------------------------------------------------

class TestClassifyApiProtocol:
    def test_graphql_confirmed(self):
        result = ar.classify_api_protocol("https://example.com/graphql", {}, graphql_confirmed=True)
        assert result["protocols"][0]["protocol"] == "graphql"
        assert result["protocols"][0]["confidence"] == ar.CONFIDENCE_HIGH

    def test_grpc_content_type(self):
        result = ar.classify_api_protocol("https://example.com/svc", {"Content-Type": "application/grpc+proto"})
        assert result["protocols"][0]["protocol"] == "grpc"

    def test_rest_json_under_api_path(self):
        result = ar.classify_api_protocol("https://example.com/api/v1/users", {"Content-Type": "application/json"})
        assert result["protocols"][0]["protocol"] == "rest"

    def test_unknown_when_no_signal(self):
        result = ar.classify_api_protocol("https://example.com/", {})
        assert result["protocols"][0]["protocol"] == "unknown"

    def test_result_json_serializable(self):
        json.dumps(ar.classify_api_protocol("https://example.com/graphql", {}, graphql_confirmed=True))


# ---------------------------------------------------------------------------
# 7. detect_deprecated_endpoints
# ---------------------------------------------------------------------------

class TestDetectDeprecatedEndpoints:
    def test_explicit_deprecation_header_is_high_confidence(self):
        records = [{
            "url": "https://example.com/api/v1/", "version_label": "v1",
            "relevant_headers": {"Deprecation": "true"},
        }]
        result = ar.detect_deprecated_endpoints(records)
        assert result["deprecated_endpoints"][0]["basis"] == "explicit_header"
        assert result["deprecated_endpoints"][0]["confidence"] == ar.CONFIDENCE_HIGH

    def test_older_version_inferred_low_confidence(self):
        records = [
            {"url": "https://example.com/api/v1/", "version_label": "v1", "relevant_headers": {}},
            {"url": "https://example.com/api/v2/", "version_label": "v2", "relevant_headers": {}},
        ]
        result = ar.detect_deprecated_endpoints(records)
        flagged = {d["url"]: d for d in result["deprecated_endpoints"]}
        assert "https://example.com/api/v1/" in flagged
        assert flagged["https://example.com/api/v1/"]["basis"] == "inferred_older_version"
        assert flagged["https://example.com/api/v1/"]["confidence"] == ar.CONFIDENCE_LOW
        assert "https://example.com/api/v2/" not in flagged  # highest version not flagged

    def test_single_version_not_flagged(self):
        records = [{"url": "https://example.com/api/v1/", "version_label": "v1", "relevant_headers": {}}]
        result = ar.detect_deprecated_endpoints(records)
        assert result["deprecated_endpoints"] == []

    def test_empty_input_returns_empty(self):
        result = ar.detect_deprecated_endpoints([])
        assert result["deprecated_endpoints"] == []
        assert result["errors"] == []

    def test_persists_findings(self, tmp_path):
        output_dir = tmp_path / "output"
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        records = [{"url": SAFE_URL, "version_label": "v1", "relevant_headers": {"Sunset": "2025-01-01"}}]
        ar.detect_deprecated_endpoints(records, store=store, target=SAFE_TARGET)
        assert any(f["type"] == "api_endpoint_deprecated" for f in store.all())


# ---------------------------------------------------------------------------
# 8. discover_http_methods
# ---------------------------------------------------------------------------

class TestDiscoverHttpMethods:
    def test_allow_header_present(self):
        resp = _fake_response(200, {"Allow": "GET, POST, OPTIONS"})
        with mock.patch("requests.options", return_value=resp):
            result = ar.discover_http_methods(SAFE_URL, target=SAFE_TARGET)
        assert result["discovery_type"] == "options_supported"
        assert result["methods"] == ["GET", "POST", "OPTIONS"]
        assert result["confidence"] == ar.CONFIDENCE_HIGH

    def test_not_found(self):
        resp = _fake_response(404)
        with mock.patch("requests.options", return_value=resp):
            result = ar.discover_http_methods(SAFE_URL, target=SAFE_TARGET)
        assert result["discovery_type"] == "not_found"
        assert result["methods"] == []

    def test_405_falls_back_to_head_for_get_confirmation(self):
        options_resp = _fake_response(405)
        head_resp = _fake_response(200)
        with mock.patch("requests.options", return_value=options_resp), \
             mock.patch("requests.head", return_value=head_resp):
            result = ar.discover_http_methods(SAFE_URL, target=SAFE_TARGET)
        assert result["discovery_type"] == "method_not_allowed"
        assert result["methods"] == ["GET"]

    def test_never_sends_state_changing_verb(self):
        options_resp = _fake_response(403)
        head_resp = _fake_response(200)
        with mock.patch("requests.options", return_value=options_resp), \
             mock.patch("requests.head", return_value=head_resp), \
             mock.patch("requests.post") as mock_post, \
             mock.patch("requests.put") as mock_put, \
             mock.patch("requests.delete") as mock_delete:
            ar.discover_http_methods(SAFE_URL, target=SAFE_TARGET)
        mock_post.assert_not_called()
        mock_put.assert_not_called()
        mock_delete.assert_not_called()

    def test_request_error_handled(self):
        with mock.patch("requests.options", side_effect=requests.exceptions.Timeout("timed out")):
            result = ar.discover_http_methods(SAFE_URL, target=SAFE_TARGET)
        assert result["status"] == "error"

    def test_result_json_serializable(self):
        resp = _fake_response(200, {"Allow": "GET"})
        with mock.patch("requests.options", return_value=resp):
            result = ar.discover_http_methods(SAFE_URL, target=SAFE_TARGET)
        json.dumps(result)


# ---------------------------------------------------------------------------
# 9. fingerprint_authentication
# ---------------------------------------------------------------------------

class TestFingerprintAuthentication:
    def test_www_authenticate_bearer_detected(self):
        observations = [{"url": SAFE_URL, "headers": {"WWW-Authenticate": "Bearer realm=api"}, "body": ""}]
        result = ar.fingerprint_authentication(observations)
        assert result["bearer"]["detected"] is True

    def test_www_authenticate_basic_detected(self):
        observations = [{"url": SAFE_URL, "headers": {"WWW-Authenticate": "Basic realm=api"}, "body": ""}]
        result = ar.fingerprint_authentication(observations)
        assert result["basic"]["detected"] is True

    def test_api_key_header_detected(self):
        observations = [{"url": SAFE_URL, "headers": {"X-API-Key": "somevalue"}, "body": ""}]
        result = ar.fingerprint_authentication(observations)
        assert result["api_key"]["detected"] is True
        assert "X-API-Key" in result["api_key"]["header_names"]

    def test_oauth_keyword_detected(self):
        observations = [{"url": SAFE_URL, "headers": {}, "body": "redirect to /oauth2/authorize?client_id=abc"}]
        result = ar.fingerprint_authentication(observations)
        assert result["oauth"]["detected"] is True

    def test_jwt_detected_and_token_never_stored_in_full(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        observations = [{"url": SAFE_URL, "headers": {}, "body": f"token={token}"}]
        result = ar.fingerprint_authentication(observations)
        assert result["jwt"]["detected"] is True
        assert result["jwt"]["tokens"][0]["alg"] == "HS256"
        assert token not in json.dumps(result)  # full raw token never persisted

    def test_openapi_security_scheme_bearer(self):
        schemes = [{"name": "bearerAuth", "type": "http", "scheme": "bearer"}]
        result = ar.fingerprint_authentication([], security_schemes=schemes)
        assert result["bearer"]["detected"] is True

    def test_openapi_security_scheme_apikey(self):
        schemes = [{"name": "apiKeyAuth", "type": "apiKey", "in": "header", "name_field_unused": True, "name": "X-Custom-Key"}]
        result = ar.fingerprint_authentication([], security_schemes=schemes)
        assert result["api_key"]["detected"] is True

    def test_openapi_security_scheme_oauth2(self):
        schemes = [{"name": "oauth", "type": "oauth2", "flows": ["clientCredentials"]}]
        result = ar.fingerprint_authentication([], security_schemes=schemes)
        assert result["oauth"]["detected"] is True

    def test_nothing_detected_returns_all_false(self):
        result = ar.fingerprint_authentication([{"url": SAFE_URL, "headers": {}, "body": "hello world"}])
        assert all(result[m]["detected"] is False for m in ("bearer", "api_key", "basic", "oauth", "jwt"))

    def test_persists_only_when_something_detected(self, tmp_path):
        output_dir = tmp_path / "output"
        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        ar.fingerprint_authentication([{"url": SAFE_URL, "headers": {}, "body": "nothing here"}], store=store, target=SAFE_TARGET)
        assert store.all() == []

        ar.fingerprint_authentication(
            [{"url": SAFE_URL, "headers": {"WWW-Authenticate": "Bearer"}, "body": ""}], store=store, target=SAFE_TARGET,
        )
        assert any(f["type"] == "api_authentication_method_fingerprint" for f in store.all())

    def test_result_json_serializable(self):
        observations = [{"url": SAFE_URL, "headers": {"WWW-Authenticate": "Bearer"}, "body": "api_key=1"}]
        json.dumps(ar.fingerprint_authentication(observations))


# ---------------------------------------------------------------------------
# run_api_recon (single-target orchestration)
# ---------------------------------------------------------------------------

class TestRunApiRecon:
    def test_scope_enforced(self, tmp_path):
        with pytest.raises(ar.ScopeError):
            ar.run_api_recon("https://evil.com/", target=SAFE_TARGET, output_dir=str(tmp_path / "output"))

    def test_completes_with_no_findings_when_nothing_present(self, tmp_path):
        with mock.patch("requests.get", return_value=_not_found_response()), \
             mock.patch("requests.post", return_value=_not_found_response()), \
             mock.patch("requests.options", return_value=_not_found_response()), \
             mock.patch("requests.head", return_value=_not_found_response()):
            result = ar.run_api_recon(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"), version_range=range(1, 2),
            )
        assert result["status"] == "completed"
        assert result["versions"]["versions_identified"] == []
        assert result["graphql"]["endpoints_detected"] == []
        json.dumps(result)

    def test_full_pipeline_wires_together_and_persists(self, tmp_path):
        get_mapping = {
            "api/v1/": _fake_response(200, {"Content-Type": "application/json"}, b'{"version":"1.0"}'),
            "swagger.json": _fake_response(200, {"Content-Type": "application/json"},
                                            json.dumps({"swagger": "2.0", "info": {"version": "1.0"}, "paths": {},
                                                        "securityDefinitions": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}).encode()),
        }
        post_mapping = {"graphql": _fake_response(200, body=b'{"data":{"__typename":"Query"}}')}
        options_resp = _fake_response(200, {"Allow": "GET"})

        output_dir = tmp_path / "output"
        with mock.patch("requests.get", side_effect=_dispatcher(get_mapping)), \
             mock.patch("requests.post", side_effect=_dispatcher(post_mapping)), \
             mock.patch("requests.options", return_value=options_resp), \
             mock.patch("requests.head", return_value=_fake_response(200)):
            result = ar.run_api_recon(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(output_dir), version_range=range(1, 2),
            )

        assert result["status"] in ("completed", "completed_with_errors")
        assert result["versions"]["versions_identified"]
        assert result["specifications"]["specs_discovered"]
        assert result["graphql"]["endpoints_detected"]
        assert result["graphql_introspections"]  # introspection attempted on the confirmed endpoint
        assert result["protocol_classifications"]
        assert result["http_methods"]

        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        stored_types = {f["type"] for f in store.all()}
        assert "api_version_discovered" in stored_types
        assert "api_specification_discovered" in stored_types
        assert "graphql_endpoint_detected" in stored_types
        json.dumps(result)

    def test_sub_stage_exception_does_not_abort_run(self, tmp_path):
        with mock.patch("reconhound.api_recon.discover_api_versions", side_effect=RuntimeError("boom")), \
             mock.patch("requests.get", return_value=_not_found_response()), \
             mock.patch("requests.post", return_value=_not_found_response()), \
             mock.patch("requests.options", return_value=_not_found_response()), \
             mock.patch("requests.head", return_value=_not_found_response()):
            result = ar.run_api_recon(SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"))
        assert result["status"] == "completed_with_errors"
        assert any(e.get("stage") == "versions" for e in result["errors"])
        # every other stage still ran despite the versions failure
        assert "graphql" in result and result["graphql"] is not None

    def test_graphql_introspection_can_be_disabled(self, tmp_path):
        post_mapping = {"graphql": _fake_response(200, body=b'{"data":{"__typename":"Query"}}')}
        with mock.patch("requests.get", return_value=_not_found_response()), \
             mock.patch("requests.post", side_effect=_dispatcher(post_mapping)), \
             mock.patch("requests.options", return_value=_not_found_response()), \
             mock.patch("requests.head", return_value=_not_found_response()):
            result = ar.run_api_recon(
                SAFE_URL, target=SAFE_TARGET, output_dir=str(tmp_path / "output"),
                version_range=range(1, 2), enable_graphql_introspection=False,
            )
        assert result["graphql_introspections"]
        assert all(i.get("status") == "skipped" for i in result["graphql_introspections"])
