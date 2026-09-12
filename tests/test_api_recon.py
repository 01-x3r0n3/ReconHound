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


# ===========================================================================
# Adversarial / regression tests added by the Module 21 forensic audit.
#
# Every test below pins a defect that was reproduced against the previous
# implementation, or a self-attack regression found while fixing one. The
# docstrings name the observed behaviour rather than the fix, so a future
# change that reintroduces the defect fails with a legible reason.
# ===========================================================================

import base64
import threading


def _resp(status_code=200, headers=None, body="", body_truncated=False):
    """A fetch_url()-shaped result dict (not a requests mock)."""
    return {
        "status": "found", "status_code": status_code, "headers": dict(headers or {}),
        "body": body, "body_truncated": body_truncated, "final_url": SAFE_URL,
        "elapsed_seconds": 0.01, "error": None,
    }


def _catch_all_host(body_for=lambda url: "<html>Not found</html>", status=200, headers=None):
    """requests.get side effect for a host that answers every path the same way."""
    def _side_effect(url, **kwargs):
        return _fake_response(status_code=status, headers=headers or {"Content-Type": "text/html"},
                              body=body_for(url).encode(), final_url=url)
    return _side_effect


def _jwt(header, payload, signature="A" * 32):
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{enc(header)}.{enc(payload)}.{signature}"


class TestScopeHardening:
    """validate_api_target let through inputs that then reached the network layer."""

    @pytest.mark.parametrize("bad", [
        "https://example.com/a\r\nX-Injected: 1",
        "https://example.com/a\nb",
        "https://example.com/a\tb",
        "https://example.com/a\x00b",
    ])
    def test_control_characters_are_rejected(self, bad):
        # urlsplit silently strips these, so the URL validated in one form and
        # was handed to requests in another.
        with pytest.raises(ar.ScopeError):
            ar.validate_api_target(bad, target="example.com")

    @pytest.mark.parametrize("bad", ["http://[::1", "http://example.com:99999/", "http://[::1]:70000/"])
    def test_unparseable_url_raises_scope_error_not_bare_value_error(self, bad):
        # urlsplit raises a plain ValueError for these; the CLI and callers
        # only name ScopeError, so the original exception escaped them.
        with pytest.raises(ar.ScopeError):
            ar.validate_api_target(bad)

    def test_idn_a_label_and_u_label_compare_equal(self):
        assert ar.validate_api_target("https://xn--mnchen-3ya.de/api", target="münchen.de")
        assert ar.validate_api_target("https://münchen.de/api", target="xn--mnchen-3ya.de")
        with pytest.raises(ar.ScopeError):
            ar.validate_api_target("https://xn--mnchen-3ya.de/api", target="berlin.de")

    def test_userinfo_is_stripped_from_the_validated_url(self):
        assert ar.validate_api_target("https://u:p@example.com/a", target="example.com") == "https://example.com/a"

    def test_userinfo_never_reaches_the_origin_or_a_probe_url(self):
        assert ar._origin_of("https://u:s3cr3t@example.com/a") == "https://example.com"
        sent = []
        with mock.patch.object(ar.requests, "get", side_effect=lambda u, **k: sent.append(u) or _not_found_response()):
            ar.discover_api_versions("https://u:s3cr3t@example.com/", target="example.com",
                                     version_range=range(1, 2))
        assert sent, "no requests were sent"
        assert not any("s3cr3t" in u for u in sent)

    def test_userinfo_never_reaches_persisted_findings(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        ok = _fake_response(status_code=200, headers={"Content-Type": "application/json"}, body=b'{"a":1}')
        with mock.patch.object(ar.requests, "get", return_value=ok):
            ar.discover_api_versions("https://u:s3cr3t@example.com/", target="example.com",
                                     store=store, version_range=range(1, 2),
                                     baseline={"available": False})
        assert "s3cr3t" not in json.dumps(store.all())

    def test_ipv6_literal_and_explicit_port_survive_normalisation(self):
        url = ar.validate_api_target("https://[2001:db8::1]:8443/api")
        assert ar._origin_of(url) == "https://[2001:db8::1]:8443"


class TestPersistenceHardening:
    def test_unserializable_values_are_coerced_not_raised(self, tmp_path):
        # A set in a caller-supplied record raised TypeError inside
        # store.add(), which _safe_store_add did not catch, which killed the
        # stage and discarded every completed discovery in it.
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        finding = ar.make_finding("t", "example.com", {"bad": {1, 2}, "n": float("nan")}, ["e"], ar.CONFIDENCE_LOW)
        assert ar._safe_store_add(store, finding) is None
        assert json.loads(json.dumps(store.all()))

    def test_os_error_is_reported_not_raised(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        with mock.patch.object(ar.tempfile, "mkstemp", side_effect=OSError("disk full")):
            err = ar._safe_store_add(store, ar.make_finding("t", "x", 1, ["e"], ar.CONFIDENCE_LOW))
        assert err and "disk full" in err

    def test_concurrent_adds_do_not_lose_records(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        errors = []

        def worker(i):
            for j in range(10):
                err = ar._safe_store_add(store, ar.make_finding("t", "example.com", {"i": i, "j": j},
                                                                ["e"], ar.CONFIDENCE_LOW))
                if err:
                    errors.append(err)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(store.all()) == 60

    def test_corrupt_store_does_not_discard_the_discovery(self, tmp_path):
        (tmp_path / "pending_assets.json").write_text("{not json")
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        ok = _fake_response(status_code=200, headers={"Content-Type": "application/json"},
                            body=b'{"openapi":"3.0.0","info":{"title":"T","version":"1"},"paths":{}}')
        with mock.patch.object(ar.requests, "get", side_effect=_dispatcher({"swagger.json": ok})):
            result = ar.discover_openapi_specs("https://example.com/", target="example.com", store=store)
        assert result["specs_discovered"], "the discovery was discarded because persistence failed"
        assert any(e["stage"] == "persistence" for e in result["errors"])


class TestCatchAllBaseline:
    """A response is only evidence when it differs from how the origin answers a certainly-absent path."""

    def test_dynamic_catch_all_produces_no_phantom_versions(self):
        # Reproduced against the previous implementation: 31 phantom
        # HIGH-confidence api_version_discovered findings.
        echo = lambda url: f"Sorry, the page {url} could not be found. Please contact support."
        with mock.patch.object(ar.requests, "get", side_effect=_catch_all_host(echo)):
            result = ar.discover_api_versions("https://example.com/", target="example.com")
        assert result["versions_identified"] == []

    def test_static_catch_all_produces_no_phantom_versions(self):
        with mock.patch.object(ar.requests, "get", side_effect=_catch_all_host()):
            result = ar.discover_api_versions("https://example.com/", target="example.com")
        assert result["versions_identified"] == []

    def test_blanket_redirect_produces_no_phantom_versions(self):
        # Reproduced: 31 phantom MEDIUM-confidence findings from a host that
        # redirects every unknown path to /login.
        def redirect(url, **kwargs):
            return _fake_response(status_code=302, headers={"Location": "https://example.com/login"},
                                  body=b"", final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=redirect):
            result = ar.discover_api_versions("https://example.com/", target="example.com")
        assert result["versions_identified"] == []

    def test_a_real_endpoint_behind_a_catch_all_is_still_found(self):
        """The catch-all filter must not become a false-negative machine."""
        real = _fake_response(status_code=200, headers={"Content-Type": "application/json"},
                              body=b'{"resources":["orders","invoices"],"version":"2.0"}')
        def side_effect(url, **kwargs):
            if url.rstrip("/").endswith("/api/v2"):
                return real
            return _fake_response(status_code=200, headers={"Content-Type": "text/html"},
                                  body=f"Sorry, {url} was not found. Contact support.".encode(),
                                  final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=side_effect):
            result = ar.discover_api_versions("https://example.com/", target="example.com")
        found = [r["url"] for r in result["versions_identified"]]
        assert found == ["https://example.com/api/v2/"]

    def test_baseline_built_from_refusals_is_marked_unusable(self):
        with mock.patch.object(ar.requests, "get", side_effect=_catch_all_host(status=429)):
            baseline = ar._probe_catch_all("https://example.com/", 1.0)
        assert baseline["available"] is True
        assert baseline["usable"] is False
        assert 429 in baseline["error_mode_statuses"]

    def test_baseline_with_inconsistent_statuses_is_unusable(self):
        seq = [404, 500]
        def side_effect(url, **kwargs):
            return _fake_response(status_code=seq.pop(0) if seq else 404, body=b"x", final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=side_effect):
            baseline = ar._probe_catch_all("https://example.com/", 1.0)
        assert baseline["usable"] is False

    def test_unreachable_baseline_is_not_treated_as_clean(self):
        with mock.patch.object(ar.requests, "get", side_effect=requests.exceptions.ConnectionError("no route")):
            baseline = ar._probe_catch_all("https://example.com/", 1.0)
        assert baseline["available"] is False


class TestClassifyResponseSemantics:
    def test_status_the_origin_gives_to_random_paths_is_blocked_not_present(self):
        baseline = {"available": True, "usable": False, "error_mode_statuses": [503]}
        dt, conf, notes = ar.classify_response(_resp(503, body="down"), baseline)
        assert dt == ar.DT_BLOCKED and conf == ar.CONFIDENCE_LOW
        assert "not effectively tested" in notes[0]

    def test_200_with_application_error_is_not_content_confirmed(self):
        dt, conf, _ = ar.classify_response(
            _resp(200, {"Content-Type": "application/json"},
                  json.dumps({"success": False, "error": "Not Found", "code": 404})), None)
        assert dt == ar.DT_CONTENT_APP_ERROR and conf == ar.CONFIDENCE_MEDIUM

    @pytest.mark.parametrize("body", [
        '{"success": false}', '{"ok": false}', '{"status": "error"}',
        '{"errors": [{"message": "nope"}]}', '{"statusCode": 403}', '{"error": {"code": "X"}}',
    ])
    def test_application_error_envelope_shapes(self, body):
        assert ar.detect_application_error(body, "application/json") is not None

    @pytest.mark.parametrize("body", [
        '{"success": true}', '{"errors": []}', '{"error": null}', '{"data": {"id": 1}}',
        '{"code": 200}', '{"status": "ok"}',
    ])
    def test_healthy_envelopes_are_not_flagged(self, body):
        assert ar.detect_application_error(body, "application/json") is None

    def test_html_prose_containing_error_is_not_an_application_error(self):
        # Keyword matching on prose is exactly the false positive this must avoid.
        assert ar.detect_application_error("<html><p>If you see an error, contact support</p></html>",
                                           "text/html") is None

    def test_missing_baseline_caps_2xx_confidence(self):
        dt, conf, notes = ar.classify_response(_resp(200, body="real content"), None)
        assert dt == ar.DT_CONTENT_CONFIRMED and conf == ar.CONFIDENCE_MEDIUM
        assert any("confidence is capped" in n for n in notes)

    def test_dynamic_baseline_caps_2xx_confidence(self):
        baseline = {"available": True, "usable": True, "dynamic": True, "status_codes": [200],
                    "body_hashes": ["a"], "normalized_bodies": []}
        dt, conf, _ = ar.classify_response(_resp(200, body="genuinely different content here"), baseline)
        assert dt == ar.DT_CONTENT_CONFIRMED and conf == ar.CONFIDENCE_MEDIUM

    def test_503_with_retry_after_is_a_refusal_but_plain_503_is_not(self):
        dt_throttled, _, _ = ar.classify_response(_resp(503, {"Retry-After": "30"}), None)
        dt_broken, _, _ = ar.classify_response(_resp(503), None)
        assert dt_throttled == ar.DT_RATE_LIMITED
        assert dt_broken == ar.DT_SERVER_ERROR

    def test_429_never_claims_the_candidate_exists(self):
        dt, conf, notes = ar.classify_response(_resp(429), None)
        assert dt == ar.DT_RATE_LIMITED and conf == ar.CONFIDENCE_LOW
        assert "says nothing" in notes[0]

    def test_401_evidence_does_not_claim_an_application_auth_mechanism(self):
        _, _, notes = ar.classify_response(_resp(401), {"available": True, "usable": True,
                                                        "status_codes": [404], "body_hashes": ["x"]})
        assert "not proof of an application authentication mechanism" in " ".join(notes)


class TestRequestBudgetAndRateLimiting:
    def test_consecutive_refusals_stop_the_run(self, tmp_path):
        # Reproduced: a host answering 429 to everything still received all 70
        # requests and produced 58 persisted findings derived from refusals.
        calls = []
        def refuse(url, **kwargs):
            calls.append(url)
            return _fake_response(status_code=429, headers={"Retry-After": "120"}, body=b"slow down", final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=refuse), \
             mock.patch.object(ar.requests, "post", side_effect=refuse), \
             mock.patch.object(ar.requests, "options", side_effect=refuse), \
             mock.patch.object(ar.requests, "head", side_effect=refuse):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        assert len(calls) <= ar.RATE_LIMIT_TRIP_THRESHOLD
        assert summary["rate_limited"] is True
        assert summary["retry_after"] == "120"
        assert summary["conclusive"] is False
        assert summary["status"] == "completed_with_errors"
        assert not (tmp_path / "pending_assets.json").exists() or store_empty(tmp_path)

    def test_intermittent_refusals_do_not_trip_the_wire(self):
        state = ar.ApiReconState()
        for status in (429, 200, 429, 200, 429, 200):
            state.note_response(_resp(status))
        assert state.rate_limited is False
        assert state.blocked_probes == 3

    def test_request_budget_is_enforced(self, tmp_path):
        calls = []
        def ok(url, **kwargs):
            calls.append(url)
            return _fake_response(status_code=404, body=b"nothing here at all", final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=ok), \
             mock.patch.object(ar.requests, "post", side_effect=ok), \
             mock.patch.object(ar.requests, "options", side_effect=ok), \
             mock.patch.object(ar.requests, "head", side_effect=ok):
            summary = ar.run_api_recon("https://example.com/", target="example.com",
                                       output_dir=str(tmp_path), max_requests=5)
        assert len(calls) == 5
        assert summary["request_budget_exhausted"] is True
        assert summary["conclusive"] is False

    def test_unsent_candidates_are_reported_not_silently_skipped(self):
        state = ar.ApiReconState(max_requests=4)
        with mock.patch.object(ar.requests, "get", side_effect=lambda u, **k: _not_found_response()):
            result = ar.discover_api_versions("https://example.com/", target="example.com", state=state)
        assert result["candidates_not_probed"], "candidates that were never sent must be reported"

    def test_conclusive_requires_a_usable_baseline_and_a_completed_run(self):
        state = ar.ApiReconState()
        for _ in range(10):
            assert state.reserve() is True
            state.note_response(_resp(404))
        assert state.conclusive() is True
        state.rate_limited = True
        assert state.conclusive() is False

    def test_a_run_of_mostly_unanswered_probes_is_not_conclusive(self):
        state = ar.ApiReconState()
        for index in range(10):
            state.reserve()
            state.note_response(_resp(404) if index < 4 else {"status": "error", "error": "timeout"})
        assert state.conclusive() is False


def store_empty(tmp_path):
    return json.loads((tmp_path / "pending_assets.json").read_text()) == []


class TestGraphqlCorrectness:
    def test_rest_error_envelope_is_not_a_graphql_endpoint(self):
        # Reproduced: a plain REST API answering
        # {"errors":[{"message":"Invalid query parameter 'q'"}]} was recorded
        # as a MEDIUM-confidence GraphQL endpoint at all 5 probed paths.
        rest_error = _fake_response(status_code=400, headers={"Content-Type": "application/json"},
                                    body=json.dumps({"errors": [{"message": "Invalid query parameter 'q'"}]}).encode())
        with mock.patch.object(ar.requests, "get", side_effect=lambda u, **k: _not_found_response()), \
             mock.patch.object(ar.requests, "post", return_value=rest_error):
            result = ar.detect_graphql_endpoints("https://example.com/", target="example.com")
        assert result["endpoints_detected"] == []

    @pytest.mark.parametrize("payload", [
        {"data": None, "errors": [{"message": "whatever"}]},
        {"errors": [{"message": "boom", "locations": [{"line": 1}]}]},
        {"errors": [{"message": "Cannot query field \"x\" on type \"Query\""}]},
        {"errors": [{"message": "Must provide query string"}]},
    ])
    def test_genuine_graphql_error_envelopes_are_still_detected(self, payload):
        assert ar._graphql_error_signal(payload) is not None

    @pytest.mark.parametrize("payload", [
        {"errors": 5}, {"errors": "boom"}, {"errors": {}}, {"errors": []}, [], None, "x",
    ])
    def test_malformed_errors_field_never_raises(self, payload):
        # A non-list "errors" raised TypeError and aborted the whole stage.
        assert ar._graphql_error_signal(payload) is None

    def test_non_list_errors_does_not_abort_detection(self):
        bad = _fake_response(status_code=200, headers={"Content-Type": "application/json"},
                             body=json.dumps({"errors": 5}).encode())
        with mock.patch.object(ar.requests, "get", side_effect=lambda u, **k: _not_found_response()), \
             mock.patch.object(ar.requests, "post", return_value=bad):
            result = ar.detect_graphql_endpoints("https://example.com/", target="example.com")
        assert result["endpoints_detected"] == []

    def test_typename_must_be_a_string_to_confirm(self):
        weird = _fake_response(status_code=200, headers={"Content-Type": "application/json"},
                               body=json.dumps({"data": {"__typename": {"nested": 1}}}).encode())
        with mock.patch.object(ar.requests, "get", side_effect=lambda u, **k: _not_found_response()), \
             mock.patch.object(ar.requests, "post", return_value=weird):
            result = ar.detect_graphql_endpoints("https://example.com/", target="example.com")
        assert result["endpoints_detected"] == []

    def test_introspection_name_truncation_is_reported(self):
        types = [{"kind": "OBJECT", "name": f"T{i}", "fields": [{"name": "f"}]} for i in range(1000)]
        body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": None,
                                                 "subscriptionType": None, "types": types}}}).encode()
        with mock.patch.object(ar.requests, "post",
                               return_value=_fake_response(200, {"Content-Type": "application/json"}, body)):
            result = ar.introspect_graphql_schema("https://example.com/graphql", target="example.com")
        assert result["type_count"] == 1000
        assert len(result["type_names"]) == ar.MAX_INTROSPECTION_NAMES
        assert result["names_truncated"], "a silently truncated list is indistinguishable from a complete one"

    def test_suggestion_mining_sends_exactly_one_read_only_query(self, tmp_path):
        sent = []
        def post(url, **kwargs):
            sent.append((kwargs.get("json") or {}).get("query", ""))
            return _fake_response(200, {"Content-Type": "application/json"}, json.dumps({"errors": [
                {"message": 'Cannot query field "x" on type "Query". Did you mean "user", "orders", or "invoices"?',
                 "locations": [{"line": 1}]}]}).encode())
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        with mock.patch.object(ar.requests, "post", side_effect=post):
            result = ar.mine_graphql_field_suggestions("https://example.com/graphql", target="example.com", store=store)
        assert len(sent) == 1
        assert not any(q.strip().lower().startswith("mutation") for q in sent)
        assert result["suggested_field_names"] == ["user", "orders", "invoices"]
        persisted = [f for f in store.all() if f["type"] == "graphql_schema_suggestions_inferred"]
        assert persisted and persisted[0]["confidence"] == ar.CONFIDENCE_LOW
        assert any("INFERRED" in e for e in persisted[0]["evidence"])

    def test_suggestion_mining_is_bounded(self):
        names = ", ".join(f'"f{i}"' for i in range(500))
        body = json.dumps({"errors": [{"message": f"Did you mean {names}?", "locations": []}]}).encode()
        with mock.patch.object(ar.requests, "post",
                               return_value=_fake_response(200, {"Content-Type": "application/json"}, body)):
            result = ar.mine_graphql_field_suggestions("https://example.com/graphql", target="example.com")
        assert len(result["suggested_field_names"]) == ar.MAX_GRAPHQL_SUGGESTIONS

    def test_duplicate_graphql_urls_are_introspected_once(self, tmp_path):
        # /graphql and /graphql/ are one endpoint; each was earning its own
        # introspection query and its own suggestion probe.
        def post(url, **kwargs):
            return _fake_response(200, {"Content-Type": "application/json"},
                                  json.dumps({"data": {"__typename": "Query"}}).encode())
        with mock.patch.object(ar.requests, "get", side_effect=lambda u, **k: _not_found_response()), \
             mock.patch.object(ar.requests, "post", side_effect=post), \
             mock.patch.object(ar.requests, "options", side_effect=lambda u, **k: _not_found_response()), \
             mock.patch.object(ar.requests, "head", side_effect=lambda u, **k: _not_found_response()):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        introspected = [i for i in summary["graphql_introspections"] if i.get("status") != "skipped"]
        identities = {ar._endpoint_identity(i["url"]) for i in introspected}
        assert len(introspected) == len(identities) <= ar.MAX_GRAPHQL_INTROSPECTIONS

    def test_weak_get_heuristic_endpoints_are_never_introspected(self, tmp_path):
        # Sending a schema query to something only suspected of being GraphQL
        # is how a REST endpoint ends up with a "schema" record.
        posts = []
        def post(url, **kwargs):
            posts.append((kwargs.get("json") or {}).get("query", ""))
            return _fake_response(404, body=b"nope")
        def get(url, **kwargs):
            if url.endswith("graphiql"):
                return _fake_response(200, {"Content-Type": "text/html"}, b"<html>GraphiQL playground</html>")
            return _not_found_response()
        with mock.patch.object(ar.requests, "get", side_effect=get), \
             mock.patch.object(ar.requests, "post", side_effect=post), \
             mock.patch.object(ar.requests, "options", side_effect=lambda u, **k: _not_found_response()), \
             mock.patch.object(ar.requests, "head", side_effect=lambda u, **k: _not_found_response()):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        assert [e["confidence"] for e in summary["graphql"]["endpoints_detected"]] == [ar.CONFIDENCE_LOW]
        assert summary["graphql_introspections"] == []
        assert not any("IntrospectionQuery" in q for q in posts)


class TestOpenApiRobustness:
    def test_truncated_specification_is_recorded_not_dropped(self):
        # A >128 KB spec at a non-canonical path parsed as invalid JSON and was
        # dropped entirely, with nothing recorded anywhere.
        big = b'{"openapi":"3.0.0","info":{"title":"Big","version":"1.0"},"paths":{' + b'"a":1,' * 40000 + b'"z":1}}'
        ok = _fake_response(200, {"Content-Type": "application/json"}, big)
        with mock.patch.object(ar.requests, "get", side_effect=_dispatcher({"openapi.json": ok})):
            result = ar.discover_openapi_specs("https://example.com/", target="example.com")
        assert result["specs_discovered"]
        record = result["specs_discovered"][0]
        assert record["truncated"] is True
        assert "truncated" in record["parse_error"]

    def test_circular_and_deep_refs_cannot_recurse(self):
        spec = {"openapi": "3.0.0", "info": {"version": "1"},
                "paths": {"/x": {"get": {"parameters": [{"$ref": "#/components/schemas/A"}]}}},
                "components": {"schemas": {"A": {"$ref": "#/components/schemas/B"},
                                           "B": {"$ref": "#/components/schemas/A"}}}}
        parsed = ar.parse_openapi_spec(json.dumps(spec), "application/json")
        assert parsed["unresolved_refs"] == 1
        assert parsed["spec_type"] == "openapi"

    def test_json_nesting_bomb_is_rejected_before_the_parser(self):
        bomb = "[" * 80000 + "]" * 80000
        value, err = ar.safe_json_loads(bomb)
        assert value is None and "nesting bomb" in err
        assert ar.parse_openapi_spec(bomb, "application/json")["parse_error"]

    def test_legitimately_nested_json_still_parses(self):
        value, err = ar.safe_json_loads("[" * 20 + "]" * 20)
        assert err is None and value is not None

    def test_enormous_path_and_scheme_counts_are_capped(self):
        spec = {"openapi": "3.0.0", "info": {"version": "1"},
                "paths": {f"/p{i}": {"get": {"parameters": [{"name": "q", "in": "query"}] * 500}}
                          for i in range(ar.MAX_SPEC_PATHS + 50)},
                "components": {"securitySchemes": {f"s{i}": {"type": "apiKey", "in": "header", "name": f"H{i}"}
                                                   for i in range(ar.MAX_SPEC_SECURITY_SCHEMES + 20)}}}
        parsed = ar.parse_openapi_spec(json.dumps(spec), "application/json")
        assert len(parsed["security_schemes"]) == ar.MAX_SPEC_SECURITY_SCHEMES
        assert parsed["limits_hit"]
        assert parsed["operation_count"] <= ar.MAX_SPEC_PATHS

    @pytest.mark.parametrize("spec", [
        {"openapi": "3.0.0", "paths": "not-a-dict"},
        {"openapi": "3.0.0", "paths": {"/x": "not-a-dict"}},
        {"openapi": "3.0.0", "paths": {"/x": {"get": "not-a-dict"}}},
        {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": "not-a-list"}}}},
        {"openapi": "3.0.0", "info": "not-a-dict"},
        {"openapi": "3.0.0", "servers": [{"nourl": 1}, "string"]},
        {"openapi": "3.0.0", "components": {"securitySchemes": {"a": "not-a-dict"}}},
    ])
    def test_malformed_specifications_never_raise(self, spec):
        parsed = ar.parse_openapi_spec(json.dumps(spec), "application/json")
        assert json.loads(json.dumps(parsed))

    def test_deprecated_operations_and_servers_are_extracted(self):
        spec = {"openapi": "3.0.0", "info": {"version": "2.1"},
                "servers": [{"url": "https://example.com/api/v2"}],
                "paths": {"/orders": {"get": {}, "post": {"deprecated": True, "operationId": "legacyCreate"}}}}
        parsed = ar.parse_openapi_spec(json.dumps(spec), "application/json")
        assert parsed["servers"] == ["https://example.com/api/v2"]
        assert parsed["deprecated_operations"] == [
            {"path": "/orders", "method": "POST", "operation_id": "legacyCreate", "summary": None}]


class TestDeprecationSemantics:
    def test_specification_declared_deprecation_is_detected(self):
        specs = [{"url": "https://example.com/swagger.json",
                  "deprecated_operations": [{"path": "/orders", "method": "POST",
                                             "operation_id": "legacyCreate", "summary": None}]}]
        result = ar.detect_deprecated_endpoints([], spec_records=specs, target="example.com")
        record = result["deprecated_endpoints"][0]
        assert record["basis"] == "specification_declared"
        assert record["confidence"] == ar.CONFIDENCE_HIGH

    def test_deprecated_is_never_reported_as_inactive(self):
        """context.md's semantics: a deprecated endpoint is frequently still live."""
        versions = [{"url": "https://example.com/api/v1/", "version_label": "v1",
                     "status_code": 200, "discovery_type": ar.DT_CONTENT_CONFIRMED,
                     "relevant_headers": {"Deprecation": "true"}}]
        result = ar.detect_deprecated_endpoints(versions, target="example.com")
        record = result["deprecated_endpoints"][0]
        assert record["runtime_state"] == "responding"
        joined = " ".join(record["evidence"]).lower()
        assert "not a statement that the endpoint is inactive" in joined
        assert "inactive" not in joined.replace("not a statement that the endpoint is inactive", "")

    def test_specification_declared_deprecation_is_marked_unverified_at_runtime(self):
        specs = [{"url": "https://example.com/swagger.json",
                  "deprecated_operations": [{"path": "/legacy", "method": "GET"}]}]
        record = ar.detect_deprecated_endpoints([], spec_records=specs)["deprecated_endpoints"][0]
        assert record["runtime_state"] == "unverified"

    def test_inferred_tier_stays_low_and_says_so(self):
        versions = [
            {"url": "https://example.com/api/v1/", "version_label": "v1", "discovery_type": ar.DT_CONTENT_CONFIRMED},
            {"url": "https://example.com/api/v2/", "version_label": "v2", "discovery_type": ar.DT_CONTENT_CONFIRMED},
        ]
        result = ar.detect_deprecated_endpoints(versions, target="example.com")
        assert [r["basis"] for r in result["deprecated_endpoints"]] == ["inferred_older_version"]
        assert result["deprecated_endpoints"][0]["confidence"] == ar.CONFIDENCE_LOW
        assert "not a confirmed deprecation" in " ".join(result["deprecated_endpoints"][0]["evidence"])

    @pytest.mark.parametrize("records", [
        [{"url": "u", "version_label": {1, 2}, "relevant_headers": {"Deprecation": "true"}}],
        [{"url": "u", "version_label": 3}],
        [{"version_label": "v1", "relevant_headers": {"Sunset": "x"}}],
        [{"url": "u", "version_label": "v1", "relevant_headers": "not-a-dict"}],
        ["junk", None, 5],
        [],
    ])
    def test_caller_supplied_garbage_never_raises(self, records):
        # detect_deprecated_endpoints is a public entry point other modules
        # call; a set, an int, and a missing "url" each raised.
        assert isinstance(ar.detect_deprecated_endpoints(records)["deprecated_endpoints"], list)


class TestHttpMethodSanitation:
    def test_hostile_allow_header_is_capped_and_validated(self):
        # Reproduced: 5000 "methods" parsed from one Allow header and persisted.
        allow = ",".join(f"M{i}" for i in range(5000))
        with mock.patch.object(ar.requests, "options",
                               return_value=_fake_response(200, {"Allow": allow}, b"")):
            result = ar.discover_http_methods("https://example.com/api/", target="example.com")
        assert len(result["methods"]) == ar.MAX_ALLOW_METHODS

    def test_allow_entries_are_deduplicated_and_stripped(self):
        with mock.patch.object(ar.requests, "options",
                               return_value=_fake_response(200, {"Allow": "get, GET , ,POST,  post"}, b"")):
            result = ar.discover_http_methods("https://example.com/api/", target="example.com")
        assert result["methods"] == ["GET", "POST"]

    def test_invalid_method_tokens_are_reported_not_silently_kept(self):
        with mock.patch.object(ar.requests, "options",
                               return_value=_fake_response(200, {"Allow": "GET, <script>, PO ST"}, b"")):
            result = ar.discover_http_methods("https://example.com/api/", target="example.com")
        assert result["methods"] == ["GET"]
        assert any("not valid HTTP method tokens" in e for e in result["evidence"])

    def test_a_refusal_is_not_a_method_discovery(self):
        with mock.patch.object(ar.requests, "options",
                               return_value=_fake_response(429, {"Retry-After": "60"}, b"")):
            result = ar.discover_http_methods("https://example.com/api/", target="example.com")
        assert result["discovery_type"] == ar.DT_RATE_LIMITED
        assert result["methods"] == []

    def test_still_never_sends_a_state_changing_verb(self):
        with mock.patch.object(ar.requests, "options",
                               return_value=_fake_response(405, {}, b"")) as opts, \
             mock.patch.object(ar.requests, "head", return_value=_fake_response(200, {}, b"")), \
             mock.patch.object(ar.requests, "put") as put, mock.patch.object(ar.requests, "delete") as delete, \
             mock.patch.object(ar.requests, "patch") as patch_, mock.patch.object(ar.requests, "post") as post:
            ar.discover_http_methods("https://example.com/api/", target="example.com")
        assert opts.called
        for verb in (put, delete, patch_, post):
            assert not verb.called


class TestAuthenticationFingerprintHonesty:
    def test_uninformative_observations_are_not_mined(self):
        # A custom 404 page mentioning "api_key" and "/oauth2/authorize"
        # manufactured authentication evidence out of an error page.
        obs = [{"url": "https://example.com/x", "headers": {}, "discovery_type": ar.DT_NOT_FOUND,
                "body": "404: see api_key docs at /oauth2/authorize"}]
        result = ar.fingerprint_authentication(obs)
        assert result["api_key"]["detected"] is False
        assert result["oauth"]["detected"] is False

    def test_keyword_only_evidence_stays_low_confidence(self):
        obs = [{"url": "https://example.com/docs", "headers": {}, "discovery_type": ar.DT_CONTENT_CONFIRMED,
                "body": "pass your api_key to /oauth2/authorize"}]
        result = ar.fingerprint_authentication(obs)
        assert result["api_key"]["confidence"] == ar.CONFIDENCE_LOW
        assert result["api_key"]["bases"] == [ar.AUTH_BASIS_INFERRED]

    def test_declared_beats_challenged_beats_inferred(self):
        result = ar.fingerprint_authentication(
            [{"url": "u", "headers": {"WWW-Authenticate": 'Bearer realm="x"'},
              "discovery_type": ar.DT_ACCESS_RESTRICTED, "body": ""}],
            security_schemes=[{"type": "apiKey", "in": "header", "name": "X-API-Key"}])
        assert result["api_key"]["confidence"] == ar.CONFIDENCE_HIGH
        assert result["bearer"]["confidence"] == ar.CONFIDENCE_MEDIUM

    def test_challenge_records_the_layer_and_does_not_claim_the_application(self):
        obs = [{"url": "u", "discovery_type": ar.DT_ACCESS_RESTRICTED, "body": "",
                "headers": {"WWW-Authenticate": 'Basic realm="x"', "CF-Ray": "abc", "Server": "cloudflare"}}]
        result = ar.fingerprint_authentication(obs)
        item = result["basic"]["evidence"][0]
        assert item["layer"] == "perimeter_or_application"
        assert "not necessarily the application" in item["detail"]

    def test_jwt_claims_are_extracted_but_never_the_whole_payload(self):
        token = _jwt({"alg": "RS256", "typ": "JWT", "kid": "k1"},
                     {"iss": "https://id.example.com", "aud": "orders", "sub": "u1", "exp": 1900000000,
                      "scope": "orders:read", "tid": "t-9", "roles": ["admin"], "ssn": "SENSITIVE-PII"})
        result = ar.fingerprint_authentication(
            [{"url": "u", "headers": {"Authorization": "Bearer " + token},
              "discovery_type": ar.DT_CONTENT_CONFIRMED, "body": ""}])
        entry = result["jwt"]["tokens"][0]
        assert entry["claims"]["iss"] == "https://id.example.com"
        assert entry["claims"]["roles"] == ["admin"]
        assert "ssn" not in entry["claims"]
        blob = json.dumps(result)
        assert "SENSITIVE-PII" not in blob
        assert token not in blob, "the raw token must never be persisted"

    def test_alg_none_is_intelligence_never_a_vulnerability_claim(self):
        token = _jwt({"alg": "none", "typ": "JWT"}, {"iss": "x"})
        result = ar.fingerprint_authentication(
            [{"url": "u", "headers": {}, "discovery_type": ar.DT_CONTENT_CONFIRMED, "body": token}])
        entry = result["jwt"]["tokens"][0]
        assert entry["alg"] == "none"
        assert entry["signature_verified"] is False
        blob = json.dumps(result).lower()
        for forbidden in ("vulnerab", "critical", "exploit", "weak secret", "bypass",
                          "algorithm confusion", "accepts unsigned"):
            assert forbidden not in blob
        # The only mention of compromise must be the explicit denial of one.
        assert blob.count("compromis") == blob.count("not evidence of compromised authentication")

    def test_expiry_is_derived_without_asserting_anything_about_the_server(self):
        entry = ar._decode_jwt_intelligence(_jwt({"alg": "HS256"}, {"exp": 1000000000}))
        assert entry["expired"] is True
        assert entry["signature_verified"] is False

    @pytest.mark.parametrize("token", ["notajwt", "a.b", "eyJ.eyJ", "...", ""])
    def test_malformed_tokens_never_raise(self, token):
        assert ar._decode_jwt_intelligence(token)["signature_verified"] is False

    def test_token_and_evidence_counts_are_bounded(self):
        tokens = " ".join(_jwt({"alg": "HS256"}, {"sub": f"u{i}"}, "S" * 40) for i in range(200))
        obs = [{"url": f"https://example.com/{i}", "headers": {}, "body": tokens,
                "discovery_type": ar.DT_CONTENT_CONFIRMED} for i in range(20)]
        result = ar.fingerprint_authentication(obs)
        assert len(result["jwt"]["tokens"]) <= ar.MAX_JWT_TOKENS
        assert len(result["jwt"]["evidence"]) <= ar.MAX_EVIDENCE_ITEMS

    @pytest.mark.parametrize("obs", [
        [{"url": "u", "headers": "notadict", "body": 123}],
        ["junk", None, 5],
        [{"url": None, "headers": None, "body": None}],
    ])
    def test_caller_supplied_garbage_never_raises(self, obs):
        assert isinstance(ar.fingerprint_authentication(obs), dict)

    def test_openidconnect_scheme_is_recognised(self):
        result = ar.fingerprint_authentication([], security_schemes=[{"type": "openIdConnect", "name": "oidc"}])
        assert result["oauth"]["detected"] is True


class TestOAuthMetadataDiscovery:
    def test_metadata_document_is_parsed_and_recorded(self, tmp_path):
        meta = json.dumps({"issuer": "https://example.com",
                           "authorization_endpoint": "https://example.com/oauth2/authorize",
                           "token_endpoint": "https://example.com/oauth2/token",
                           "jwks_uri": "https://example.com/jwks",
                           "scopes_supported": ["openid", "profile"]}).encode()
        ok = _fake_response(200, {"Content-Type": "application/json"}, meta)
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        with mock.patch.object(ar.requests, "get", side_effect=_dispatcher({"openid-configuration": ok})):
            result = ar.discover_oauth_metadata("https://example.com/", target="example.com", store=store)
        doc = result["documents_discovered"][0]
        assert doc["issuer"] == "https://example.com"
        assert doc["scopes_supported"] == ["openid", "profile"]
        assert "did not probe them" in doc["note"]

    def test_a_json_document_without_an_issuer_is_not_metadata(self):
        ok = _fake_response(200, {"Content-Type": "application/json"}, b'{"hello":"world"}')
        with mock.patch.object(ar.requests, "get", side_effect=_dispatcher({"openid-configuration": ok})):
            result = ar.discover_oauth_metadata("https://example.com/", target="example.com")
        assert result["documents_discovered"] == []

    def test_no_oauth_flow_is_ever_performed(self):
        ok = _fake_response(200, {"Content-Type": "application/json"},
                            json.dumps({"issuer": "https://example.com",
                                        "token_endpoint": "https://example.com/oauth2/token"}).encode())
        with mock.patch.object(ar.requests, "get", side_effect=_dispatcher({"openid-configuration": ok})) as get, \
             mock.patch.object(ar.requests, "post") as post:
            ar.discover_oauth_metadata("https://example.com/", target="example.com")
        assert not post.called
        assert all("oauth2/token" not in c.args[0] for c in get.call_args_list)


class TestProtocolClassification:
    def test_a_url_path_alone_is_not_a_protocol_signal(self):
        # Self-attack regression: every 404 at /graphql on a catch-all host was
        # classified as GraphQL, including in runs that simultaneously reported
        # "no API surface found".
        result = ar.classify_api_protocol("https://example.com/graphql", {"Content-Type": "text/html"})
        assert [p["protocol"] for p in result["protocols"]] == ["unknown"]
        assert any("naming convention" in e for e in result["evidence"])

    def test_confirmed_graphql_endpoint_is_classified(self):
        result = ar.classify_api_protocol("https://example.com/graphql", {}, graphql_confirmed=True)
        assert result["protocols"][0] == {"protocol": "graphql", "confidence": ar.CONFIDENCE_HIGH}

    @pytest.mark.parametrize("content_type", ["application/grpc", "application/grpc-web+proto", "application/grpc+json"])
    def test_grpc_variants_are_detected_over_http1(self, content_type):
        result = ar.classify_api_protocol("https://example.com/svc", {"Content-Type": content_type})
        assert result["protocols"][0]["protocol"] == "grpc"
        assert "HTTP/1.1" in " ".join(result["evidence"])

    def test_grpc_absence_is_not_claimed_as_absence_of_grpc(self):
        result = ar.classify_api_protocol("https://example.com/x", {"Content-Type": "text/html"})
        assert "absence of a signal is not evidence" in " ".join(result["evidence"])

    def test_unknown_classifications_are_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        ar.persist_protocol_classification(
            ar.classify_api_protocol("https://example.com/x", {}), target="example.com", store=store)
        assert store.all() == []

    def test_named_classifications_reach_the_asset_store(self, tmp_path):
        # Responsibility #5's output previously existed only in the returned
        # summary and never became a finding, so surface_mapper never saw it.
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        ar.persist_protocol_classification(
            ar.classify_api_protocol("https://example.com/graphql", {}, graphql_confirmed=True),
            target="example.com", store=store)
        assert [f["type"] for f in store.all()] == ["api_protocol_observed"]


class TestRunApiReconHardening:
    def _silent_host(self, body=b"nothing here at all", status=404):
        resp = lambda url, **kwargs: _fake_response(status, {"Content-Type": "text/plain"}, body, final_url=url)
        return resp

    def test_negative_result_is_emitted_only_when_the_run_was_conclusive(self, tmp_path):
        host = self._silent_host()
        with mock.patch.object(ar.requests, "get", side_effect=host), \
             mock.patch.object(ar.requests, "post", side_effect=host), \
             mock.patch.object(ar.requests, "options", side_effect=host), \
             mock.patch.object(ar.requests, "head", side_effect=host):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        types = [f["type"] for f in json.loads((tmp_path / "pending_assets.json").read_text())]
        assert summary["conclusive"] is True
        assert types == ["api_recon_checked_no_api_surface"]

    def test_no_negative_result_after_a_throttled_run(self, tmp_path):
        refuse = lambda url, **kwargs: _fake_response(429, {"Retry-After": "60"}, b"slow", final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=refuse), \
             mock.patch.object(ar.requests, "post", side_effect=refuse), \
             mock.patch.object(ar.requests, "options", side_effect=refuse), \
             mock.patch.object(ar.requests, "head", side_effect=refuse):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        assert summary["conclusive"] is False
        assert not (tmp_path / "pending_assets.json").exists()

    def test_keyboard_interrupt_reports_an_interrupted_run(self, tmp_path):
        calls = [0]
        def get(url, **kwargs):
            calls[0] += 1
            if calls[0] > 6:
                raise KeyboardInterrupt()
            return _fake_response(404, {}, b"nothing here at all", final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=get), \
             mock.patch.object(ar.requests, "post", side_effect=lambda u, **k: _not_found_response()), \
             mock.patch.object(ar.requests, "options", side_effect=lambda u, **k: _not_found_response()), \
             mock.patch.object(ar.requests, "head", side_effect=lambda u, **k: _not_found_response()):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        assert summary["status"] == "interrupted"
        assert summary["cancelled"] is True
        assert summary["conclusive"] is False

    def test_every_request_stays_on_the_authorised_origin(self, tmp_path):
        sent = []
        def redirecting(url, **kwargs):
            sent.append(url)
            return _fake_response(302, {"Location": "https://attacker.example.net/pwn"}, b"", final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=redirecting), \
             mock.patch.object(ar.requests, "post", side_effect=redirecting), \
             mock.patch.object(ar.requests, "options", side_effect=redirecting), \
             mock.patch.object(ar.requests, "head", side_effect=redirecting):
            ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        assert sent and all(u.startswith("https://example.com/") for u in sent)

    def test_declared_versions_are_recorded_without_extra_requests(self, tmp_path):
        versions = [{"url": "https://example.com/api/", "version_label": None,
                     "relevant_headers": {"API-Version": "2024-05-01"}}]
        specs = [{"url": "https://example.com/swagger.json", "version": "3.2",
                  "servers": ["https://example.com/api/v7"]}]
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        with mock.patch.object(ar.requests, "get", side_effect=AssertionError("no request may be sent")):
            result = ar.discover_declared_api_versions(versions, spec_records=specs,
                                                       target="example.com", store=store)
        bases = {(r["version_label"], r["basis"]) for r in result["declared_versions"]}
        assert ("2024-05-01", "declared_response_header") in bases
        assert ("3.2", "declared_specification") in bases
        assert ("v7", "declared_specification_server") in bases

    def test_declared_versions_do_not_duplicate_path_probed_ones(self):
        versions = [{"url": "https://example.com/api/v2/", "version_label": "v2",
                     "relevant_headers": {"API-Version": "v2"}}]
        result = ar.discover_declared_api_versions(versions, target="example.com")
        assert result["declared_versions"] == []

    def test_summary_is_json_serializable_and_bounded(self, tmp_path):
        big = b"A" * 500000
        host = lambda url, **kwargs: _fake_response(200, {"Content-Type": "application/json",
                                                          "X-Huge": "z" * 100000}, big, final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=host), \
             mock.patch.object(ar.requests, "post", side_effect=host), \
             mock.patch.object(ar.requests, "options", side_effect=host), \
             mock.patch.object(ar.requests, "head", side_effect=host):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        blob = json.dumps(summary)
        assert len(blob) < 4_000_000
        for section in ("versions", "specifications", "documentation", "graphql", "oauth_metadata"):
            for obs in summary[section].get("observations", []):
                assert len(obs["body"]) <= ar.MAX_OBSERVATION_BODY_BYTES
                for value in obs["headers"].values():
                    assert not isinstance(value, str) or len(value) <= ar.MAX_OBSERVATION_HEADER_CHARS

    def test_a_stage_failure_is_recorded_once_not_twice(self, tmp_path):
        host = lambda url, **kwargs: _fake_response(404, {}, b"nothing here at all", final_url=url)
        with mock.patch.object(ar.requests, "get", side_effect=host), \
             mock.patch.object(ar.requests, "post", side_effect=host), \
             mock.patch.object(ar.requests, "options", side_effect=host), \
             mock.patch.object(ar.requests, "head", side_effect=host), \
             mock.patch.object(ar, "discover_documentation_pages", side_effect=RuntimeError("boom")):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))
        boom = [e for e in summary["errors"] if "boom" in str(e.get("error"))]
        assert len(boom) == 1


class TestFindingContractForDownstream:
    """Every finding this module emits must survive surface_mapper's contract."""

    def test_all_finding_types_carry_the_required_fields(self, tmp_path):
        spec = json.dumps({"openapi": "3.0.0", "info": {"title": "T", "version": "2.1"},
                           "paths": {"/orders": {"post": {"deprecated": True}}},
                           "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}}}).encode()
        oidc = json.dumps({"issuer": "https://example.com",
                           "token_endpoint": "https://example.com/oauth2/token"}).encode()

        def get(url, **kwargs):
            if url.endswith("/swagger.json"):
                return _fake_response(200, {"Content-Type": "application/json"}, spec, final_url=url)
            if "openid-configuration" in url:
                return _fake_response(200, {"Content-Type": "application/json"}, oidc, final_url=url)
            if url.rstrip("/").endswith("/api/v1"):
                return _fake_response(200, {"Content-Type": "application/json", "Deprecation": "true"},
                                      b'{"version":"1.4","resources":["orders"]}', final_url=url)
            if url.endswith("/docs"):
                return _fake_response(200, {"Content-Type": "text/html"},
                                      b"<html><div id='swagger-ui'>API Documentation</div></html>", final_url=url)
            return _fake_response(404, {"Content-Type": "text/html"},
                                  b"<html>404 - not found on this server</html>", final_url=url)

        def post(url, **kwargs):
            if url.rstrip("/").endswith("/graphql"):
                return _fake_response(200, {"Content-Type": "application/json"},
                                      json.dumps({"data": {"__typename": "Query"}}).encode(), final_url=url)
            return _fake_response(404, {}, b"<html>404 - not found on this server</html>", final_url=url)

        with mock.patch.object(ar.requests, "get", side_effect=get), \
             mock.patch.object(ar.requests, "post", side_effect=post), \
             mock.patch.object(ar.requests, "options",
                               side_effect=lambda u, **k: _fake_response(200, {"Allow": "GET, POST"}, b"", final_url=u)), \
             mock.patch.object(ar.requests, "head",
                               side_effect=lambda u, **k: _fake_response(200, {}, b"", final_url=u)):
            summary = ar.run_api_recon("https://example.com/", target="example.com", output_dir=str(tmp_path))

        records = json.loads((tmp_path / "pending_assets.json").read_text())
        assert records, "the run produced no findings to check the contract against"
        for record in records:
            assert isinstance(record.get("type"), str) and record["type"]
            assert record["source"] == ar.MODULE_NAME
            assert record["confidence"] in (ar.CONFIDENCE_LOW, ar.CONFIDENCE_MEDIUM, ar.CONFIDENCE_HIGH)
            assert isinstance(record["evidence"], list) and all(isinstance(e, str) for e in record["evidence"])
            assert isinstance(record["metadata"], dict)
            assert record["timestamp"] and record["target"] == "example.com"
        # The whole file must round-trip: surface_mapper reads it with json.load.
        assert json.loads(json.dumps(records)) == records
        assert summary["status"] in ("completed", "completed_with_errors")

    def test_findings_are_ingestible_by_surface_mapper(self, tmp_path):
        from reconhound import surface_mapper as sm
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        ar._safe_store_add(store, ar.make_finding(
            "api_version_discovered", "example.com",
            {"url": "https://example.com/api/v1/", "version_label": "v1"},
            ["evidence"], ar.CONFIDENCE_HIGH, metadata={"url": "https://example.com/api/v1/"}))
        mapper = sm.SurfaceMapper(target="example.com", output_dir=str(tmp_path))
        result = mapper.ingest_pending_assets_file()
        assert result["ingested"] == 1 and result["errors"] == 0
        assert mapper.state["ingestion_errors"] == []


class TestHttpLayerRobustness:
    """Transport-level adversarial inputs found in self-attack pass 6."""

    class _Raw:
        def __init__(self, body, exc=None):
            self.body, self.exc = body, exc

        def read(self, n, decode_content=True):
            if self.exc:
                raise self.exc
            return self.body[:n]

    def _resp_obj(self, body=b"", headers=None, raw_exc=None, iter_exc=None, encoding="utf-8", status=200):
        outer = self

        class _Resp:
            def __init__(self):
                self.status_code = status
                self.headers = dict(headers or {})
                self.encoding = encoding
                self.url = SAFE_URL
                self.elapsed = mock.MagicMock()
                self.elapsed.total_seconds.return_value = 0.01
                self.raw = outer._Raw(body, raw_exc)

            @property
            def content(self):
                return body

            def iter_content(self, chunk_size=8192):
                if iter_exc:
                    raise iter_exc
                for i in range(0, len(body), chunk_size):
                    yield body[i:i + chunk_size]

            def close(self):
                pass

        return _Resp()

    def test_unreadable_raw_falls_back_to_a_bounded_stream_read(self):
        # `resp.content` materialises the whole body before the slice runs, so
        # a decompression bomb was fully resident in memory per request.
        huge = b"A" * 5_000_000
        with mock.patch.object(ar.requests, "get",
                               return_value=self._resp_obj(huge, raw_exc=OSError("no raw"))):
            result = ar.fetch_url("https://example.com/")
        assert len(result["body"]) == ar.DEFAULT_MAX_BODY_BYTES
        assert result["body_truncated"] is True

    def test_an_oversized_declared_body_is_reported_not_swallowed(self):
        with mock.patch.object(ar.requests, "get",
                               return_value=self._resp_obj(b"x" * 1000, headers={"Content-Length": "999999999"},
                                                           raw_exc=OSError("x"), iter_exc=OSError("y"))):
            result = ar.fetch_url("https://example.com/")
        assert result["body"] == ""
        assert "exceeds the read cap" in result["body_read_error"]

    def test_a_bogus_declared_encoding_does_not_raise(self):
        with mock.patch.object(ar.requests, "get",
                               return_value=self._resp_obj(b"\xff\xfe\x00binary", encoding="not-a-codec")):
            result = ar.fetch_url("https://example.com/")
        assert result["status"] == "found" and isinstance(result["body"], str)

    @pytest.mark.parametrize("exc", [
        requests.exceptions.Timeout(),
        requests.exceptions.ConnectionError("reset by peer"),
        requests.exceptions.SSLError("cert verify failed"),
        requests.exceptions.ChunkedEncodingError("bad chunk"),
        requests.exceptions.ContentDecodingError("bad gzip"),
        requests.exceptions.TooManyRedirects("loop"),
    ])
    def test_every_transport_failure_returns_an_error_result(self, exc):
        with mock.patch.object(ar.requests, "get", side_effect=exc):
            result = ar.fetch_url("https://example.com/")
        assert result["status"] == "error" and result["error"]

    def test_a_garbage_retry_after_is_recorded_but_bounded(self):
        state = ar.ApiReconState()
        for _ in range(ar.RATE_LIMIT_TRIP_THRESHOLD):
            state.note_response(_resp(429, {"Retry-After": "z" * 5000}))
        assert state.rate_limited is True
        assert len(state.retry_after) <= 120

    def test_a_truncated_metadata_document_is_reported_not_dropped(self):
        huge = b'{"issuer":"https://example.com","x":"' + b"y" * 400000 + b'"}'
        ok = _fake_response(200, {"Content-Type": "application/json"}, huge)
        with mock.patch.object(ar.requests, "get", side_effect=_dispatcher({"openid-configuration": ok})):
            result = ar.discover_oauth_metadata("https://example.com/", target="example.com")
        assert result["documents_discovered"] == []
        assert any("truncated" in str(e["error"]) for e in result["errors"])

    @pytest.mark.parametrize("url", [
        "", "not a url", "https://example.com", "http://[::1]:8080/x", "https://example.com/%2e%2e%2f",
    ])
    def test_structural_signature_never_raises(self, url):
        assert isinstance(ar._structural_signature("body text here", url), str)


class TestJsonNestingGuard:
    """Self-attack pass 7: the first nesting guard was a regex, and one line defeated it."""

    @pytest.mark.parametrize("bomb", [
        '{"a":' * 5000 + "1" + "}" * 5000,      # keys between every brace — defeated the regex guard
        "[" * 5000 + "]" * 5000,
        '[{"a":' * 3000 + "1" + "}]" * 3000,
    ])
    def test_nesting_bombs_are_rejected_before_the_parser(self, bomb):
        value, err = ar.safe_json_loads(bomb)
        assert value is None and "nesting bomb" in err

    def test_brackets_inside_a_string_are_data_not_structure(self):
        assert ar._exceeds_json_nesting('{"k":"' + "[" * 5000 + '"}') is False

    def test_escapes_do_not_confuse_the_scanner(self):
        assert ar.safe_json_loads(r'{"k":"a\"b[[["}')[0] == {"k": 'a"b[[['}

    def test_legitimate_nesting_still_parses(self):
        value, err = ar.safe_json_loads("[" * 20 + "]" * 20)
        assert err is None and value is not None
        assert ar.parse_openapi_spec('{"openapi":"3.0.0","info":{"version":"1"}}',
                                     "application/json")["spec_type"] == "openapi"

    def test_a_declared_version_without_a_source_url_still_has_a_target(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path))
        ar.discover_declared_api_versions([], spec_records=[{"url": None, "version": "9.9"}],
                                          target=None, store=store)
        assert store.all()[0]["target"] == "unknown"


class TestDeprecationWatermark:
    """Found in end-to-end testing: an unavailable version was setting the watermark."""

    def test_a_version_that_reports_itself_unavailable_does_not_deprecate_the_current_one(self):
        # /api/v3/ replied 200 {"success": false, "error": "v3 is not yet
        # available"}. It is real routed surface, but it is not evidence that
        # the live v2 is superseded.
        records = [
            {"url": "https://example.com/api/v2/", "version_label": "v2",
             "discovery_type": ar.DT_CONTENT_CONFIRMED},
            {"url": "https://example.com/api/v3/", "version_label": "v3",
             "discovery_type": ar.DT_CONTENT_APP_ERROR},
        ]
        result = ar.detect_deprecated_endpoints(records, target="example.com")
        assert result["deprecated_endpoints"] == []

    def test_a_version_that_only_answered_401_does_not_set_the_watermark(self):
        records = [
            {"url": "https://example.com/api/v1/", "version_label": "v1",
             "discovery_type": ar.DT_CONTENT_CONFIRMED},
            {"url": "https://example.com/api/v2/", "version_label": "v2",
             "discovery_type": ar.DT_ACCESS_RESTRICTED},
        ]
        assert ar.detect_deprecated_endpoints(records)["deprecated_endpoints"] == []

    def test_an_unavailable_version_can_still_be_flagged_by_a_live_newer_one(self):
        records = [
            {"url": "https://example.com/api/v1/", "version_label": "v1",
             "discovery_type": ar.DT_CONTENT_APP_ERROR},
            {"url": "https://example.com/api/v2/", "version_label": "v2",
             "discovery_type": ar.DT_CONTENT_CONFIRMED},
        ]
        flagged = ar.detect_deprecated_endpoints(records)["deprecated_endpoints"]
        assert [f["version_label"] for f in flagged] == ["v1"]
        assert "observed responding successfully" in " ".join(flagged[0]["evidence"])

    def test_the_live_watermark_still_flags_genuinely_older_versions(self):
        records = [
            {"url": "https://example.com/api/v1/", "version_label": "v1",
             "discovery_type": ar.DT_CONTENT_CONFIRMED},
            {"url": "https://example.com/api/v2/", "version_label": "v2",
             "discovery_type": ar.DT_CONTENT_CONFIRMED},
            {"url": "https://example.com/api/v3/", "version_label": "v3",
             "discovery_type": ar.DT_CONTENT_CONFIRMED},
        ]
        flagged = ar.detect_deprecated_endpoints(records)["deprecated_endpoints"]
        assert sorted(f["version_label"] for f in flagged) == ["v1", "v2"]
        assert all(f["confidence"] == ar.CONFIDENCE_LOW for f in flagged)

    def test_records_without_a_discovery_type_are_taken_at_face_value(self):
        # Self-attack regression: restricting the watermark to explicitly
        # successful responses silently stopped flagging anything for external
        # callers, whose records carry no discovery_type at all.
        records = [
            {"url": "https://example.com/api/v1/", "version_label": "v1", "relevant_headers": {}},
            {"url": "https://example.com/api/v2/", "version_label": "v2", "relevant_headers": {}},
        ]
        flagged = ar.detect_deprecated_endpoints(records)["deprecated_endpoints"]
        assert [f["version_label"] for f in flagged] == ["v1"]


# ---------------------------------------------------------------------------
# Dead-origin tripwire (TRANSPORT_FAILURE_TRIP_THRESHOLD)
#
# Reproduces the performance defect found in the 2026-09-12 whole-system
# audit. This module probes sequentially by design, so against a port that
# accepts TCP and never answers HTTP every candidate cost a full `timeout`:
# 73 probes / 147s at timeout=2 and 552s at the orchestrator's default
# timeout=8, for zero observations. It was the single most expensive module
# in a 42-minute run, and all of it was spent on origins that answered nothing.
# ---------------------------------------------------------------------------


class TestDeadOriginTripwire:

    def _run_against_dead_origin(self, tmp_path, exc):
        sent = []

        def fail(url, **kwargs):
            sent.append(url)
            raise exc

        with mock.patch("requests.get", side_effect=fail), \
             mock.patch("requests.post", side_effect=fail), \
             mock.patch("requests.options", side_effect=fail), \
             mock.patch("requests.head", side_effect=fail):
            summary = ar.run_api_recon(SAFE_URL, target=SAFE_TARGET,
                                       output_dir=str(tmp_path / "output"))
        return summary, sent

    def test_probing_stops_once_the_origin_stops_answering(self, tmp_path):
        summary, sent = self._run_against_dead_origin(
            tmp_path, requests.exceptions.Timeout("timed out"))
        assert summary["origin_unreachable"] is True
        assert len(sent) <= ar.TRANSPORT_FAILURE_TRIP_THRESHOLD, (
            f"kept probing a dead origin: {len(sent)} requests")

    def test_a_tripped_run_is_never_conclusive_and_writes_no_negative_result(self, tmp_path):
        out = tmp_path / "output"
        summary, _ = self._run_against_dead_origin(
            out.parent, requests.exceptions.ConnectionError("refused"))
        assert summary["origin_unreachable"] is True
        assert summary["conclusive"] is False
        pending = out / "pending_assets.json"
        blob = pending.read_text() if pending.exists() else ""
        assert "api_recon_checked_no_api_surface" not in blob

    def test_the_reason_is_reported_in_the_run_notes(self, tmp_path):
        summary, _ = self._run_against_dead_origin(
            tmp_path, requests.exceptions.Timeout("x"))
        notes = [n for n in summary["state_notes"] if "transport failures" in n]
        assert len(notes) == 1
        assert "not evidence" in notes[0]

    def test_one_answered_probe_disarms_the_tripwire_permanently(self, tmp_path):
        state = ar.ApiReconState(max_requests=10_000)
        for _ in range(ar.TRANSPORT_FAILURE_TRIP_THRESHOLD - 1):
            state.note_response({"status": "error"})
        assert state.origin_unreachable is False
        state.note_response({"status": "found", "status_code": 404, "headers": {}})
        for _ in range(ar.TRANSPORT_FAILURE_TRIP_THRESHOLD * 5):
            state.note_response({"status": "error"})
        assert state.origin_unreachable is False
        assert state.should_stop() is False

    def test_a_refusal_is_an_answer_and_belongs_to_the_rate_limiter(self, tmp_path):
        # A 429 proves the origin is answering. It must trip the rate limiter,
        # never the dead-origin wire — the two mean opposite things.
        state = ar.ApiReconState(max_requests=10_000)
        for _ in range(ar.TRANSPORT_FAILURE_TRIP_THRESHOLD * 2):
            state.note_response({"status": "found", "status_code": 429, "headers": {}})
        assert state.origin_unreachable is False
        assert state.rate_limited is True

    def test_a_live_origin_answering_404_is_probed_in_full(self, tmp_path):
        sent = []

        def not_found(url, **kwargs):
            sent.append(url)
            return _not_found_response()

        with mock.patch("requests.get", side_effect=not_found), \
             mock.patch("requests.post", side_effect=not_found), \
             mock.patch("requests.options", side_effect=not_found), \
             mock.patch("requests.head", side_effect=not_found):
            summary = ar.run_api_recon(SAFE_URL, target=SAFE_TARGET,
                                       output_dir=str(tmp_path / "output"))
        assert summary["origin_unreachable"] is False
        assert len(sent) > ar.TRANSPORT_FAILURE_TRIP_THRESHOLD * 2, (
            "a live origin must still receive the full probe set")
