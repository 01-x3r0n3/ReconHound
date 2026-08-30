"""
reconhound/api_recon.py — ReconHound Module 11 (api_recon.py), per
context.md's build order — catalog item 11 in §10's module list,
build-order position 21 (context.md §13).

Phase: Active. See context.md §10 (module 11, "Dedicated API recon") for
the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Dedicated API recon. API version discovery (all identifiable versions,
  not just current), Swagger/OpenAPI discovery (/swagger.json,
  /openapi.yaml, /api-docs), GraphQL detection + authorized schema
  introspection, REST vs GraphQL vs gRPC detection, API doc discovery,
  deprecated endpoint detection, HTTP method discovery, auth-method
  fingerprinting (Bearer/API-Key/Basic/OAuth/JWT)."

That is nine discrete responsibilities, each implemented as its own
function below, plus shared HTTP-client plumbing and a single-target
orchestrator (mirroring the run_http_analysis/run_endpoint_discovery
precedent — not itself a listed context.md responsibility):

  1. API version discovery       -> discover_api_versions
  2. Swagger/OpenAPI discovery   -> discover_openapi_specs (+ parse_openapi_spec)
  3. GraphQL detection           -> detect_graphql_endpoints
  4. GraphQL schema introspection-> introspect_graphql_schema
  5. REST/GraphQL/gRPC detection -> classify_api_protocol
  6. API documentation discovery -> discover_documentation_pages
  7. Deprecated endpoint detect. -> detect_deprecated_endpoints
  8. HTTP method discovery       -> discover_http_methods
  9. Auth-method fingerprinting  -> fingerprint_authentication
  (shared HTTP client)           -> fetch_url / fetch_url_post /
                                     fetch_url_options / fetch_url_head
  (single-target orchestrator)   -> run_api_recon

Scope boundaries (deliberately preserved, not incidental):

  - Every URL this module probes is derived from the caller-supplied
    `base_url`/`target` and validated by validate_api_target the same way
    every other Active-phase module validates its input. GraphQL schema
    introspection is therefore inherently bound to the authorized target —
    it can never reach outside it. `enable_graphql_introspection` is an
    additional explicit opt-out a caller/orchestrator can set if a given
    engagement's authorization excludes introspection even within scope.
  - GraphQL probing sends only read-only queries (a minimal
    `{ __typename }` confirmation probe and the standard introspection
    query). No mutation is ever constructed or sent — this module
    discovers API surface, it does not exercise or modify it.
  - HTTP method discovery (#8) uses only OPTIONS plus a safe HEAD
    fallback (mirroring exposure_scan.py's own OPTIONS-based approach,
    context.md module 15's "per-endpoint HTTP OPTIONS discovery" — a
    similar mechanism serving this module's own named responsibility, not
    a call into that module). No state-changing verb (POST/PUT/PATCH/
    DELETE) is ever sent to probe support, mirroring endpoint_discovery.py's
    GET-only discipline: this module discovers method *support signaling*,
    it never exercises those methods.
  - "REST vs GraphQL vs gRPC detection" is implemented as an evidence
    list per URL, not a single forced label — an API surface can
    genuinely mix protocols (e.g. a GraphQL endpoint alongside a REST
    surface), so multiple observed protocols are preserved rather than
    arbitrarily resolved to one, consistent with context.md §8's
    conflict-preservation principle.
  - Authentication-method fingerprinting inspects headers/content/OpenAPI
    security-scheme declarations already fetched by this module's own
    probes. JWT "detection" decodes only the unsigned header segment of
    any JWT-shaped string observed (base64url, not encrypted — always
    possible, not a cryptographic attack); no signature verification,
    cracking, or forgery is performed, and only a short token preview
    plus the declared `alg` are kept — never the full token — mirroring
    http_analyzer.py's detect_jwts. Discovered auth material is never used
    to authenticate, exploit, or access anything.

Implementation decisions (ambiguities resolved so implementation can
proceed without redesigning anything context.md defines):

  1. No new dependency is added for YAML parsing. `openapi.yaml`/
     `swagger.yaml` responses are parsed with a best-effort regex
     extraction (spec type + declared version/title from the `info:`
     block) rather than a full YAML parser — PyYAML is not currently an
     approved dependency and a JSON-capable OpenAPI/Swagger discovery
     already covers the common case. This is a documented, known
     limitation (see parse_openapi_spec), not an oversight: exotic YAML
     formatting (anchors, flow style, multi-document files) will not be
     captured beyond "a spec-shaped file was found here".
  2. Every fetch in this module is sequential, not threaded. Unlike
     endpoint_discovery.py (thousands of wordlist entries), this module's
     candidate lists are small and bounded (version templates, a short
     canonical spec/doc-path list, a handful of GraphQL paths), so the
     added complexity of a thread pool is not justified here.
  3. API version discovery (#1) probes `v{1..10}` under three common path
     templates (`api/v{n}/`, `v{n}/`, `api/{n}/`) plus the unversioned
     `api/` root (mined for an embedded version string). This is a
     bounded, documented approximation of "all identifiable versions" —
     it will not find non-numeric or header/subdomain-only versioning
     schemes it has no path pattern for.
  4. GraphQL schema introspection (#4) uses a bounded introspection query
     (root operation type names, all type names, and each type's field
     names) rather than the exhaustive standard introspection query
     (nested field arguments/descriptions/interfaces/enum values). This
     keeps the request/response and persisted-finding size bounded while
     still delivering a genuinely useful schema map; extracted type/field
     name lists are also capped (MAX_INTROSPECTION_NAMES) as a safety
     bound against very large schemas.
  5. Deprecated-endpoint detection (#7) has two confidence tiers: HIGH
     when an explicit `Deprecation`/`Sunset` header or a `Warning` header
     mentioning deprecation is observed, and LOW ("inferred, not
     confirmed") when an older numeric API version coexists with a newer
     one this run also identified. The LOW tier is a heuristic, not a
     server-stated fact, and is always labeled as such in its evidence.
  6. Swagger/OpenAPI discovery (#2) and API documentation discovery (#6)
     are implemented as separate functions per context.md's line, which
     lists them as distinct responsibilities: the former probes
     machine-readable spec files at their canonical locations and parses
     their structure; the latter probes human-oriented documentation
     surfaces (Swagger UI/ReDoc/GraphiQL pages, `/docs`, `/documentation`)
     and only checks for documentation markers in already-fetched content.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every earlier module, sharing the same output file). Output is intended to
feed surface_mapper.py (not yet implemented) — this module does not
implement or call into surface_mapper, vhost_scanner, supply_chain,
vuln_intel, risk_engine, orchestrator, report_generator, or any other
module not already implemented.

DISCOVERY != CONFIRMED VULNERABILITY / EXPLOIT: every record here is an
observation (a version path responded, a spec file was found, an auth
scheme was declared). None of this module's output should be read as
"vulnerable" or "exploitable" — that assessment belongs to vuln_intel.py /
risk_engine.py. This module never uses discovered authentication material
to authenticate against anything.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
import threading
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

MODULE_NAME = "api_recon.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-APIRecon/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
MAX_INTROSPECTION_NAMES = 300

# 1. API version discovery
VERSION_PATH_TEMPLATES = ["api/v{n}/", "v{n}/", "api/{n}/"]
DEFAULT_VERSION_RANGE = range(1, 11)  # v1..v10 — see module docstring, decision #3

# 2. Swagger/OpenAPI discovery — context.md names swagger.json, openapi.yaml,
# api-docs explicitly (CANONICAL_SPEC_PATHS); the rest are common conventions.
OPENAPI_SPEC_PATHS = [
    "swagger.json", "openapi.yaml", "api-docs",
    "openapi.json", "swagger.yaml", "v2/api-docs", "v3/api-docs",
]
CANONICAL_SPEC_PATHS = {"swagger.json", "openapi.yaml", "api-docs"}
SPEC_DISCOVERY_PREFIXES = ["", "api/"]

# 6. API documentation discovery (human-oriented, distinct from #2's
# machine-readable spec files — see module docstring, decision #6)
DOCUMENTATION_PATHS = [
    "docs", "documentation", "redoc", "swagger-ui", "swagger-ui.html",
    "developer", "developers",
]
DOC_MARKERS_RE = re.compile(
    r"swagger-ui|redoc|graphiql|api reference|api documentation|developer portal|apidoc",
    re.IGNORECASE,
)

# 3. GraphQL detection
GRAPHQL_PATHS = ["graphql", "graphql/", "api/graphql", "v1/graphql", "graphiql"]
GRAPHQL_WEAK_RE = re.compile(
    r"graphiql|graphql playground|apollo|must provide query|graphql-ws", re.IGNORECASE
)
GRAPHQL_TYPENAME_QUERY = {"query": "{ __typename }"}

# 4. GraphQL schema introspection (bounded — see module docstring, decision #4)
INTROSPECTION_QUERY = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) { name }
    }
  }
}"""

# 5. REST vs GraphQL vs gRPC detection
GRPC_CONTENT_TYPE_RE = re.compile(r"application/grpc", re.IGNORECASE)
GRPC_HEADER_NAMES = ["grpc-status", "grpc-message", "grpc-encoding"]

# 9. Auth-method fingerprinting
_API_KEY_HEADER_NAMES = ["X-API-Key", "Api-Key", "Apikey", "X-Auth-Token", "X-Access-Token"]
_API_KEY_KEYWORD_RE = re.compile(r"\bapi[_-]?key\b", re.IGNORECASE)
_OAUTH_KEYWORD_RE = re.compile(r"/oauth2?/(?:authorize|token)\b|grant_type=|client_id=|\boauth2?\b", re.IGNORECASE)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")

_RELEVANT_HEADER_NAMES = [
    "WWW-Authenticate", "Deprecation", "Sunset", "Warning",
    "Content-Type", "API-Version", "X-API-Version", "Allow",
]


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors endpoint_discovery.py's/http_analyzer.py's
# validate_*_target; duplicated per modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = hostname.strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    return hostname == target or hostname.endswith("." + target)


def validate_api_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, mirroring every earlier Active-phase module's
    rationale: IP scope is enforced upstream, not by a domain comparison
    here).
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()
    parsed = urllib.parse.urlsplit(candidate)

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if target and not _is_ip_literal(hostname) and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    return candidate


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors every earlier module's model; kept local
# per modular independence)
# ---------------------------------------------------------------------------

def make_finding(
    finding_type: str,
    target: str,
    value: Any,
    evidence: List[str],
    confidence: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a structured, evidence-carrying discovery record (context.md §8)."""
    return {
        "type": finding_type,
        "target": target,
        "value": value,
        "evidence": list(evidence),
        "confidence": confidence,
        "source": MODULE_NAME,
        "timestamp": _now(),
        "metadata": metadata or {},
    }


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as every earlier module's
# PendingAssetsStore, duplicated here per modular independence)
# ---------------------------------------------------------------------------

class PendingAssetsStore:
    """
    Crash-safe, append-oriented persistence for <output_dir>/pending_assets.json.

    Every call to add() re-reads the current file, appends the new finding,
    and atomically rewrites the file (write-to-temp + os.replace) so a
    crash mid-write can never corrupt previously persisted discoveries, and
    pre-existing discoveries from other modules/runs are always preserved.
    """

    def __init__(self, output_dir: str = "output", filename: str = "pending_assets.json"):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, filename)
        self._lock = threading.Lock()
        os.makedirs(self.output_dir, exist_ok=True)

    def _read_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
            if not isinstance(data, list):
                raise ValueError("pending_assets.json root must be a JSON array")
            return data
        except (json.JSONDecodeError, ValueError) as exc:
            raise PersistenceError(
                f"Existing pending_assets.json is corrupt and cannot be safely "
                f"appended to: {exc}"
            ) from exc

    def add(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Append one finding and persist immediately. Returns the finding."""
        with self._lock:
            records = self._read_all()
            records.append(finding)
            self._atomic_write(records)
        return finding

    def _atomic_write(self, records: List[Dict[str, Any]]) -> None:
        dir_name = os.path.dirname(self.path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".pending_assets_", dir=dir_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._read_all()


def _safe_store_add(store: Optional["PendingAssetsStore"], finding: Dict[str, Any]) -> Optional[str]:
    """
    store.add() wrapped so a single persistence failure doesn't abort a
    recon run. Returns None on success, or an error message the caller is
    responsible for recording (never silently discarded).
    """
    if store is None:
        return None
    try:
        store.add(finding)
        return None
    except PersistenceError as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ci_get(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup (requests preserves server casing)."""
    if not headers:
        return None
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _relevant_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Extract only the header names this module cares about, for compact persisted records."""
    out: Dict[str, str] = {}
    for name in _RELEVANT_HEADER_NAMES:
        value = _ci_get(headers, name)
        if value is not None:
            out[name] = value
    return out


def _origin_of(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def _url_for_path(root: str, entry: str) -> str:
    root = _ensure_trailing_slash(root)
    return urllib.parse.urljoin(root, entry.lstrip("/"))


def _hostname_of(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or url


# ---------------------------------------------------------------------------
# Shared HTTP client (GET/POST/OPTIONS/HEAD — no state-changing verb is ever
# used; see module docstring)
# ---------------------------------------------------------------------------

def _perform_request(
    method_name: str,
    url: str,
    timeout: float,
    headers: Optional[Dict[str, str]],
    json_body: Optional[Dict[str, Any]],
    max_body_bytes: int,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "body": None,
        "body_truncated": False, "final_url": url, "elapsed_seconds": None, "error": None,
    }
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)

    resp = None
    try:
        request_fn = getattr(requests, method_name)
        kwargs: Dict[str, Any] = {
            "timeout": timeout, "headers": req_headers, "allow_redirects": False, "stream": True,
        }
        if json_body is not None:
            kwargs["json"] = json_body
        resp = request_fn(url, **kwargs)
        try:
            raw = resp.raw.read(max_body_bytes + 1, decode_content=True)
        except Exception:
            raw = resp.content[:max_body_bytes + 1]
        truncated = len(raw) > max_body_bytes
        body_bytes = raw[:max_body_bytes]
        try:
            body_text = body_bytes.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            body_text = body_bytes.decode("utf-8", errors="replace")

        result.update({
            "status": "found",
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": body_text,
            "body_truncated": truncated,
            "final_url": resp.url,
            "elapsed_seconds": resp.elapsed.total_seconds(),
        })
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
    except requests.exceptions.TooManyRedirects as exc:
        result["error"] = f"too many redirects: {exc}"
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request failed: {exc}"
    finally:
        if resp is not None:
            resp.close()
    return result


def fetch_url(
    url: str, timeout: float = DEFAULT_TIMEOUT, headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """Perform a single HTTP GET against `url`."""
    return _perform_request("get", url, timeout, headers, None, max_body_bytes)


def fetch_url_post(
    url: str, json_body: Optional[Dict[str, Any]] = None, timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None, max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single HTTP POST against `url` with a JSON body. Used only
    for read-only GraphQL query probes (typename confirmation, schema
    introspection) — never a mutation.
    """
    return _perform_request("post", url, timeout, headers, json_body, max_body_bytes)


def fetch_url_options(url: str, timeout: float = DEFAULT_TIMEOUT, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Perform a single HTTP OPTIONS request against `url` (responsibility #8)."""
    return _perform_request("options", url, timeout, headers, None, DEFAULT_MAX_BODY_BYTES)


def fetch_url_head(url: str, timeout: float = DEFAULT_TIMEOUT, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Perform a single HTTP HEAD request against `url` (safe method-discovery fallback)."""
    return _perform_request("head", url, timeout, headers, None, DEFAULT_MAX_BODY_BYTES)


# ---------------------------------------------------------------------------
# Response classification (soft-404-aware; mirrors endpoint_discovery.py's
# classify_response, duplicated per modular independence)
# ---------------------------------------------------------------------------

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


def _content_signature(body: str) -> tuple:
    import hashlib
    normalized = re.sub(r"\s+", " ", body).strip()
    digest = hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()
    return len(normalized), digest


def _lengths_close(a: Optional[int], b: Optional[int], tolerance: int = 25) -> bool:
    if a is None or b is None:
        return False
    return abs(a - b) <= tolerance


def _probe_soft_404(origin: str, timeout: float) -> Dict[str, Any]:
    """Fingerprint `origin`'s "not found" response via one random, near-certainly-absent path."""
    probe_path = f"reconhound-nonexistent-check-{uuid.uuid4().hex[:12]}"
    resp = fetch_url(_ensure_trailing_slash(origin) + probe_path, timeout=timeout)
    if resp["status"] != "found":
        return {"available": False}
    length, digest = _content_signature(resp.get("body") or "")
    return {"available": True, "status_code": resp["status_code"], "content_length": length, "body_hash": digest}


def classify_response(resp: Dict[str, Any], baseline: Optional[Dict[str, Any]]):
    """
    Classify a fetch_url()-style result into a discovery_type + confidence
    + supporting notes. Never claims "confirmed" for a soft-404 look-alike.
    """
    status = resp.get("status_code")
    if status is None:
        return "error", CONFIDENCE_LOW, ["no status code available (request failed)"]
    if status == 404:
        return "not_found", CONFIDENCE_HIGH, []
    if status == 429:
        return "rate_limited", CONFIDENCE_LOW, ["HTTP 429 Too Many Requests — enumeration may be incomplete beyond this point"]
    if status in _REDIRECT_STATUS_CODES:
        return "redirect", CONFIDENCE_MEDIUM, [f"HTTP {status} redirect response"]
    if status in (401, 403):
        return "access_restricted", CONFIDENCE_MEDIUM, [f"HTTP {status} access-restricted response"]
    if status == 405:
        return "method_not_allowed", CONFIDENCE_MEDIUM, ["HTTP 405 Method Not Allowed — path pattern appears to exist"]
    if 500 <= status < 600:
        return "server_error_response", CONFIDENCE_LOW, [f"HTTP {status} server error — existence uncertain"]
    if 200 <= status < 300:
        if baseline and baseline.get("available"):
            length, digest = _content_signature(resp.get("body") or "")
            if status == baseline.get("status_code") and (
                digest == baseline.get("body_hash") or _lengths_close(length, baseline.get("content_length"))
            ):
                return (
                    "possible_soft_404_match", CONFIDENCE_LOW,
                    ["response closely matches this host's baseline not-found fingerprint "
                     "(same status + similar body); likely a soft-404, not confirmed content"],
                )
        return "content_confirmed", CONFIDENCE_HIGH, []
    return "unexpected_status", CONFIDENCE_LOW, [f"unexpected HTTP status {status}"]


# ---------------------------------------------------------------------------
# 1. API version discovery
# ---------------------------------------------------------------------------

def discover_api_versions(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    baseline: Optional[Dict[str, Any]] = None,
    version_range: Optional[range] = None,
) -> Dict[str, Any]:
    """
    Discover every identifiable API version by probing common
    path-versioning templates for v1..v10 (see module docstring, decision
    #3), plus the unversioned "api/" root for an embedded version string.
    Every non-404 candidate is recorded (not only the "current" one).
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    version_range = version_range or DEFAULT_VERSION_RANGE
    baseline = baseline if baseline is not None else _probe_soft_404(origin, timeout)

    candidates = [
        (f"v{n}", template.format(n=n))
        for template in VERSION_PATH_TEMPLATES
        for n in version_range
    ]
    candidates.append((None, "api/"))

    identified: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for version_label, rel_path in candidates:
        url = _url_for_path(origin, rel_path)
        resp = fetch_url(url, timeout=timeout)
        if resp["status"] != "found":
            errors.append({"stage": "version_probe", "url": url, "error": resp.get("error")})
            continue

        headers = resp["headers"]
        body = resp.get("body") or ""
        observations.append({"url": url, "headers": headers, "body": body[:4000], "source": "version_probe"})

        discovery_type, confidence, notes = classify_response(resp, baseline)
        if discovery_type == "not_found":
            continue

        relevant_headers = _relevant_headers(headers)
        version_string_hint = None
        m = re.search(r'"(?:api_)?version"\s*:\s*"([^"]{1,32})"', body)
        if m:
            version_string_hint = m.group(1)
        elif relevant_headers.get("API-Version"):
            version_string_hint = relevant_headers["API-Version"]
        elif relevant_headers.get("X-API-Version"):
            version_string_hint = relevant_headers["X-API-Version"]

        record = {
            "url": url, "version_label": version_label, "path_template": rel_path,
            "status_code": resp["status_code"], "discovery_type": discovery_type,
            "confidence": confidence, "version_string_hint": version_string_hint,
            "relevant_headers": relevant_headers, "content_type": relevant_headers.get("Content-Type"),
            "evidence": [f"GET {url} returned HTTP {resp['status_code']} ({discovery_type})"] + notes,
            "timestamp": _now(),
        }
        identified.append(record)
        err = _safe_store_add(store, make_finding(
            "api_version_discovered", target, dict(record), record["evidence"], confidence,
            metadata={"url": url, "version_label": version_label, "version_string_hint": version_string_hint},
        ))
        if err:
            errors.append({"stage": "persistence", "url": url, "error": err})

    return {
        "target": target, "base_url": base_url, "candidates_checked": len(candidates),
        "versions_identified": identified, "observations": observations, "errors": errors,
    }


# ---------------------------------------------------------------------------
# 2. Swagger/OpenAPI discovery
# ---------------------------------------------------------------------------

def parse_openapi_spec(body: str, content_type: Optional[str]) -> Dict[str, Any]:
    """
    Parse a fetched body as an OpenAPI/Swagger specification. JSON specs
    are fully structurally parsed; YAML specs use a best-effort regex
    extraction (see module docstring, decision #1) since no YAML parser is
    an approved dependency. Malformed/unrecognized content degrades to a
    result with `parse_error` set, never raises.
    """
    result: Dict[str, Any] = {
        "format": None, "spec_type": None, "version": None, "title": None,
        "path_count": None, "security_schemes": [], "parse_error": None,
    }
    if not body or not body.strip():
        result["parse_error"] = "empty body"
        return result

    stripped = body.strip()
    looks_json = stripped.startswith("{") or (content_type and "json" in content_type.lower())

    if looks_json:
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, ValueError) as exc:
            result["parse_error"] = f"invalid JSON: {exc}"
            return result
        if not isinstance(data, dict):
            result["parse_error"] = "JSON root is not an object"
            return result

        result["format"] = "json"
        if "openapi" in data:
            result["spec_type"] = "openapi"
        elif "swagger" in data:
            result["spec_type"] = "swagger"

        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        result["version"] = info.get("version")
        result["title"] = info.get("title")

        paths = data.get("paths")
        result["path_count"] = len(paths) if isinstance(paths, dict) else None

        schemes: Dict[str, Any] = {}
        if isinstance(data.get("components"), dict) and isinstance(data["components"].get("securitySchemes"), dict):
            schemes = data["components"]["securitySchemes"]
        elif isinstance(data.get("securityDefinitions"), dict):
            schemes = data["securityDefinitions"]

        for name, scheme in schemes.items():
            if not isinstance(scheme, dict):
                continue
            flows: List[str] = []
            if (scheme.get("type") or "").lower() == "oauth2":
                if isinstance(scheme.get("flows"), dict):
                    flows = sorted(scheme["flows"].keys())
                elif scheme.get("flow"):
                    flows = [scheme["flow"]]
            result["security_schemes"].append({
                "name": name, "type": scheme.get("type"), "scheme": scheme.get("scheme"),
                "in": scheme.get("in"), "flows": flows,
            })
        return result

    if re.search(r'^(openapi|swagger)\s*:', stripped, re.MULTILINE):
        result["format"] = "yaml"
        m = re.search(r'^(openapi|swagger)\s*:\s*[\'"]?([\w.]+)', stripped, re.MULTILINE)
        if m:
            result["spec_type"] = "openapi" if m.group(1) == "openapi" else "swagger"
        info_match = re.search(r'^info\s*:\s*\n((?:[ \t]+.+\n?)+)', stripped, re.MULTILINE)
        info_block = info_match.group(1) if info_match else stripped
        v = re.search(r'version\s*:\s*[\'"]?([\w.\-]+)', info_block)
        if v:
            result["version"] = v.group(1)
        t = re.search(r'title\s*:\s*[\'"]?([^\n\'"]+)', info_block)
        if t:
            result["title"] = t.group(1).strip()
        result["parse_error"] = "YAML parsed via best-effort regex extraction, not a full YAML parser"
        return result

    result["parse_error"] = "content did not match a recognizable OpenAPI/Swagger JSON or YAML structure"
    return result


def discover_openapi_specs(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    baseline: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Probe the canonical Swagger/OpenAPI spec locations context.md names
    (swagger.json, openapi.yaml, api-docs) plus common variants, at the
    origin root and under an "api/" prefix.
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    baseline = baseline if baseline is not None else _probe_soft_404(origin, timeout)

    discovered: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for prefix in SPEC_DISCOVERY_PREFIXES:
        root = origin if not prefix else _url_for_path(origin, prefix)
        for rel_path in OPENAPI_SPEC_PATHS:
            url = _url_for_path(root, rel_path)
            resp = fetch_url(url, timeout=timeout)
            if resp["status"] != "found":
                errors.append({"stage": "spec_probe", "url": url, "error": resp.get("error")})
                continue

            headers = resp["headers"]
            body = resp.get("body") or ""
            observations.append({"url": url, "headers": headers, "body": body[:4000], "source": "spec"})

            discovery_type, _, notes = classify_response(resp, baseline)
            if discovery_type == "not_found":
                continue

            content_type = _ci_get(headers, "Content-Type")
            is_canonical_path = rel_path in CANONICAL_SPEC_PATHS

            if discovery_type == "content_confirmed":
                parsed = parse_openapi_spec(body, content_type)
                recognized = parsed["spec_type"] is not None
                if not recognized and not is_canonical_path:
                    continue  # generic 200 unrelated to an API spec — not meaningful evidence
                record_confidence = CONFIDENCE_HIGH if recognized else CONFIDENCE_MEDIUM
            elif discovery_type == "access_restricted" and is_canonical_path:
                parsed = {
                    "format": None, "spec_type": None, "version": None, "title": None,
                    "path_count": None, "security_schemes": [],
                    "parse_error": "endpoint exists but access is restricted",
                }
                record_confidence = CONFIDENCE_MEDIUM
            else:
                continue

            record = {
                "url": url, "path": rel_path, "discovery_type": discovery_type,
                "status_code": resp["status_code"], "content_type": content_type,
                "spec_type": parsed["spec_type"], "format": parsed["format"],
                "version": parsed["version"], "title": parsed["title"],
                "path_count": parsed["path_count"], "security_schemes": parsed["security_schemes"],
                "parse_error": parsed["parse_error"],
                "evidence": [f"GET {url} returned HTTP {resp['status_code']} ({discovery_type})"] + notes,
                "timestamp": _now(),
            }
            discovered.append(record)
            err = _safe_store_add(store, make_finding(
                "api_specification_discovered", target, dict(record), record["evidence"], record_confidence,
                metadata={"url": url, "spec_type": parsed["spec_type"], "version": parsed["version"]},
            ))
            if err:
                errors.append({"stage": "persistence", "url": url, "error": err})

    return {
        "target": target, "base_url": base_url, "specs_discovered": discovered,
        "observations": observations, "errors": errors,
    }


# ---------------------------------------------------------------------------
# 6. API documentation discovery (human-oriented; see module docstring,
# decision #6)
# ---------------------------------------------------------------------------

def discover_documentation_pages(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    baseline: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Probe common human-oriented API documentation surfaces."""
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    baseline = baseline if baseline is not None else _probe_soft_404(origin, timeout)

    discovered: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for prefix in SPEC_DISCOVERY_PREFIXES:
        root = origin if not prefix else _url_for_path(origin, prefix)
        for rel_path in DOCUMENTATION_PATHS:
            url = _url_for_path(root, rel_path)
            resp = fetch_url(url, timeout=timeout)
            if resp["status"] != "found":
                errors.append({"stage": "doc_probe", "url": url, "error": resp.get("error")})
                continue

            headers = resp["headers"]
            body = resp.get("body") or ""
            observations.append({"url": url, "headers": headers, "body": body[:4000], "source": "doc_page"})

            discovery_type, _, notes = classify_response(resp, baseline)
            if discovery_type == "not_found":
                continue

            if discovery_type == "content_confirmed":
                markers_found = sorted(set(m.lower() for m in DOC_MARKERS_RE.findall(body)))
                confidence = CONFIDENCE_HIGH if markers_found else CONFIDENCE_MEDIUM
            elif discovery_type == "access_restricted":
                markers_found = []
                confidence = CONFIDENCE_LOW
            else:
                continue

            record = {
                "url": url, "path": rel_path, "discovery_type": discovery_type,
                "status_code": resp["status_code"], "markers_found": markers_found,
                "evidence": [f"GET {url} returned HTTP {resp['status_code']} ({discovery_type})"] + notes,
                "timestamp": _now(),
            }
            discovered.append(record)
            err = _safe_store_add(store, make_finding(
                "api_documentation_page_discovered", target, dict(record), record["evidence"], confidence,
                metadata={"url": url, "markers_found": markers_found},
            ))
            if err:
                errors.append({"stage": "persistence", "url": url, "error": err})

    return {
        "target": target, "base_url": base_url, "pages_discovered": discovered,
        "observations": observations, "errors": errors,
    }


# ---------------------------------------------------------------------------
# 3. GraphQL detection
# ---------------------------------------------------------------------------

def detect_graphql_endpoints(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    baseline: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Detect GraphQL endpoints at common paths using a GET heuristic and a
    minimal, read-only `{ __typename }` POST confirmation probe (never a
    mutation).
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    baseline = baseline if baseline is not None else _probe_soft_404(origin, timeout)

    detected: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for rel_path in GRAPHQL_PATHS:
        url = _url_for_path(origin, rel_path)

        get_resp = fetch_url(url, timeout=timeout)
        get_discovery_type = None
        if get_resp["status"] == "found":
            get_discovery_type, _, _ = classify_response(get_resp, baseline)
            observations.append({
                "url": url, "headers": get_resp["headers"],
                "body": (get_resp.get("body") or "")[:4000], "source": "graphql_get",
            })
        else:
            errors.append({"stage": "graphql_get", "url": url, "error": get_resp.get("error")})

        post_resp = fetch_url_post(
            url, json_body=GRAPHQL_TYPENAME_QUERY, timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        confirmed_via = None
        confidence = None
        evidence: List[str] = []

        if post_resp["status"] == "found":
            post_body = post_resp.get("body") or ""
            observations.append({
                "url": url, "headers": post_resp["headers"], "body": post_body[:4000], "source": "graphql_post",
            })
            try:
                data = json.loads(post_body)
            except (json.JSONDecodeError, ValueError):
                data = None

            if isinstance(data, dict) and isinstance(data.get("data"), dict) and "__typename" in data["data"]:
                confirmed_via, confidence = "post_typename_probe", CONFIDENCE_HIGH
                evidence.append(
                    f'POST {url} with a read-only "{{ __typename }}" probe returned a '
                    f'GraphQL-shaped {{"data": {{"__typename": ...}}}} response'
                )
            elif isinstance(data, dict) and data.get("errors"):
                messages = " ".join(str(e.get("message", "")) for e in data["errors"] if isinstance(e, dict))
                if re.search(r"graphql|query|schema", messages, re.IGNORECASE):
                    confirmed_via, confidence = "post_graphql_error_envelope", CONFIDENCE_MEDIUM
                    evidence.append(f"POST {url} returned a GraphQL-style errors envelope: {messages[:200]!r}")
        else:
            errors.append({"stage": "graphql_post", "url": url, "error": post_resp.get("error")})

        if confidence is None and get_discovery_type not in (None, "not_found"):
            get_body = get_resp.get("body") or ""
            content_type = _ci_get(get_resp["headers"], "Content-Type") or ""
            if GRAPHQL_WEAK_RE.search(get_body) or "graphql" in content_type.lower():
                confirmed_via, confidence = "get_heuristic", CONFIDENCE_LOW
                evidence.append(f"GET {url} content/content-type weakly suggests a GraphQL endpoint")

        if confidence is None:
            continue

        record = {
            "url": url, "confirmed_via": confirmed_via, "confidence": confidence,
            "get_status_code": get_resp.get("status_code"), "post_status_code": post_resp.get("status_code"),
            "evidence": evidence, "timestamp": _now(),
        }
        detected.append(record)
        err = _safe_store_add(store, make_finding(
            "graphql_endpoint_detected", target, dict(record), evidence, confidence,
            metadata={"url": url, "confirmed_via": confirmed_via},
        ))
        if err:
            errors.append({"stage": "persistence", "url": url, "error": err})

    return {
        "target": target, "base_url": base_url, "endpoints_detected": detected,
        "observations": observations, "errors": errors,
    }


# ---------------------------------------------------------------------------
# 4. GraphQL schema introspection (authorized-scope only — see module
# docstring)
# ---------------------------------------------------------------------------

def introspect_graphql_schema(
    url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    enabled: bool = True,
) -> Dict[str, Any]:
    """
    Run a bounded, read-only introspection query (module docstring,
    decision #4) against a GraphQL endpoint already confirmed in-scope.
    `enabled=False` lets a caller/orchestrator opt out even within scope.
    """
    url = validate_api_target(url, target=target)
    if not enabled:
        return {"url": url, "status": "skipped", "reason": "GraphQL introspection disabled by caller"}

    resp = fetch_url_post(
        url, json_body={"query": INTROSPECTION_QUERY}, timeout=timeout,
        headers={"Content-Type": "application/json"},
    )
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}

    body = resp.get("body") or ""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"url": url, "status": "error", "error": f"non-JSON introspection response: {exc}"}
    if not isinstance(data, dict):
        return {"url": url, "status": "error", "error": "introspection response JSON root is not an object"}

    schema = None
    if isinstance(data.get("data"), dict):
        schema = data["data"].get("__schema")

    if not isinstance(schema, dict):
        if data.get("errors"):
            messages = " ".join(str(e.get("message", "")) for e in data["errors"] if isinstance(e, dict))
            evidence = [f"Introspection query against {url} was rejected: {messages[:200]!r}"]
            err = _safe_store_add(store, make_finding(
                "graphql_introspection_disabled", target or url, {"url": url, "messages": messages},
                evidence, CONFIDENCE_LOW, metadata={"url": url},
            ))
            result = {"url": url, "status": "disabled", "messages": messages}
            if err:
                result["persistence_error"] = err
            return result
        return {"url": url, "status": "error", "error": "introspection response did not contain __schema"}

    def _type_name(entry: Any) -> Optional[str]:
        return entry.get("name") if isinstance(entry, dict) else None

    query_type = _type_name(schema.get("queryType"))
    mutation_type = _type_name(schema.get("mutationType"))
    subscription_type = _type_name(schema.get("subscriptionType"))
    types = schema.get("types") if isinstance(schema.get("types"), list) else []

    field_map: Dict[str, List[str]] = {}
    type_names: List[str] = []
    for t in types:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        name = t["name"]
        type_names.append(name)
        fields = t.get("fields") if isinstance(t.get("fields"), list) else []
        field_map[name] = [f["name"] for f in fields if isinstance(f, dict) and f.get("name")]

    type_names = sorted(set(type_names))
    query_fields = sorted(field_map.get(query_type, [])) if query_type else []
    mutation_fields = sorted(field_map.get(mutation_type, [])) if mutation_type else []

    result = {
        "url": url, "status": "introspected", "query_type": query_type,
        "mutation_type": mutation_type, "subscription_type": subscription_type,
        "type_count": len(type_names), "type_names": type_names[:MAX_INTROSPECTION_NAMES],
        "query_fields": query_fields[:MAX_INTROSPECTION_NAMES],
        "mutation_fields": mutation_fields[:MAX_INTROSPECTION_NAMES],
        "timestamp": _now(),
    }
    evidence = [
        f"Introspection query against {url} succeeded: {len(type_names)} type(s), "
        f"query type {query_type!r}, mutation type {mutation_type!r}"
    ]
    err = _safe_store_add(store, make_finding(
        "graphql_schema_introspected", target or url, dict(result), evidence, CONFIDENCE_HIGH,
        metadata={"url": url, "type_count": len(type_names)},
    ))
    if err:
        result["persistence_error"] = err
    return result


# ---------------------------------------------------------------------------
# 5. REST vs GraphQL vs gRPC detection
# ---------------------------------------------------------------------------

def classify_api_protocol(
    url: str, headers: Optional[Dict[str, str]], body: Optional[str] = None, graphql_confirmed: bool = False,
) -> Dict[str, Any]:
    """
    Classify observed protocol signals for one URL. Multiple protocols may
    be reported for the same URL/surface rather than forcing a single
    label (see module docstring) — this is an evidence list, not a verdict.
    """
    headers = headers or {}
    content_type = _ci_get(headers, "Content-Type") or ""
    path = urllib.parse.urlsplit(url).path.lower()
    protocols: List[Dict[str, str]] = []
    evidence: List[str] = []

    if graphql_confirmed or "graphql" in content_type.lower() or "/graphql" in path:
        confidence = CONFIDENCE_HIGH if graphql_confirmed else CONFIDENCE_MEDIUM
        protocols.append({"protocol": "graphql", "confidence": confidence})
        evidence.append(
            "GraphQL indicators present" + (" (confirmed endpoint)" if graphql_confirmed else " (path/content-type match)")
        )

    if GRPC_CONTENT_TYPE_RE.search(content_type) or any(_ci_get(headers, h) is not None for h in GRPC_HEADER_NAMES):
        confidence = CONFIDENCE_HIGH if GRPC_CONTENT_TYPE_RE.search(content_type) else CONFIDENCE_MEDIUM
        protocols.append({"protocol": "grpc", "confidence": confidence})
        evidence.append("gRPC content-type or grpc-* header observed")

    if not protocols and "json" in content_type.lower() and "/api" in path:
        protocols.append({"protocol": "rest", "confidence": CONFIDENCE_MEDIUM})
        evidence.append("JSON response under an /api path — consistent with a REST-style API")

    if not protocols:
        protocols.append({"protocol": "unknown", "confidence": CONFIDENCE_LOW})
        evidence.append("no distinguishing REST/GraphQL/gRPC signal observed")

    return {"url": url, "protocols": protocols, "evidence": evidence}


# ---------------------------------------------------------------------------
# 7. Deprecated API endpoint detection
# ---------------------------------------------------------------------------

def detect_deprecated_endpoints(
    version_records: List[Dict[str, Any]],
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Flag deprecated endpoints: HIGH confidence when an explicit
    Deprecation/Sunset header or a deprecation-mentioning Warning header
    was observed; LOW confidence, clearly labeled as inferred, when an
    older numeric version coexists with a newer one this run identified
    (see module docstring, decision #5).
    """
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    numeric_versions: Dict[int, List[Dict[str, Any]]] = {}

    for r in version_records:
        label = r.get("version_label")
        if not label:
            continue
        m = re.search(r"(\d+)", label)
        if m:
            numeric_versions.setdefault(int(m.group(1)), []).append(r)

    explicit_flagged_urls = set()
    for r in version_records:
        headers = r.get("relevant_headers") or {}
        deprecation = headers.get("Deprecation")
        sunset = headers.get("Sunset")
        warning = headers.get("Warning") or ""
        if not (deprecation or sunset or "deprecat" in warning.lower()):
            continue

        evidence = []
        if deprecation:
            evidence.append(f"Deprecation header present: {deprecation!r}")
        if sunset:
            evidence.append(f"Sunset header present: {sunset!r}")
        if "deprecat" in warning.lower():
            evidence.append(f"Warning header mentions deprecation: {warning!r}")

        record = {
            "url": r["url"], "version_label": r.get("version_label"), "basis": "explicit_header",
            "confidence": CONFIDENCE_HIGH, "evidence": evidence,
        }
        results.append(record)
        explicit_flagged_urls.add(r["url"])
        err = _safe_store_add(store, make_finding(
            "api_endpoint_deprecated", target or r["url"], dict(record), evidence, CONFIDENCE_HIGH,
            metadata={"url": r["url"], "basis": "explicit_header"},
        ))
        if err:
            errors.append({"stage": "persistence", "url": r["url"], "error": err})

    max_version = max(numeric_versions) if numeric_versions else None
    if max_version is not None:
        for version_num, records in numeric_versions.items():
            if version_num == max_version:
                continue
            for r in records:
                if r["url"] in explicit_flagged_urls:
                    continue
                evidence = [
                    f"Version {r.get('version_label')} coexists with a newer identified version v{max_version}; "
                    f"older API versions are commonly, but not always, deprecated — this is an inference, "
                    f"not a confirmed deprecation"
                ]
                record = {
                    "url": r["url"], "version_label": r.get("version_label"),
                    "basis": "inferred_older_version", "confidence": CONFIDENCE_LOW, "evidence": evidence,
                }
                results.append(record)
                err = _safe_store_add(store, make_finding(
                    "api_endpoint_deprecated", target or r["url"], dict(record), evidence, CONFIDENCE_LOW,
                    metadata={"url": r["url"], "basis": "inferred_older_version"},
                ))
                if err:
                    errors.append({"stage": "persistence", "url": r["url"], "error": err})

    return {"deprecated_endpoints": results, "errors": errors}


# ---------------------------------------------------------------------------
# 8. HTTP method discovery (OPTIONS + safe HEAD fallback only — no
# state-changing verb is ever sent; see module docstring)
# ---------------------------------------------------------------------------

def discover_http_methods(
    url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Discover which HTTP methods a discovered API endpoint advertises via OPTIONS (+ safe HEAD fallback)."""
    url = validate_api_target(url, target=target)
    resp = fetch_url_options(url, timeout=timeout)
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}

    status_code = resp["status_code"]
    allow_header = _ci_get(resp["headers"], "Allow")
    methods = [m.strip().upper() for m in allow_header.split(",")] if allow_header else []

    if status_code == 404:
        return {"url": url, "status": "found", "discovery_type": "not_found", "methods": [], "evidence": []}

    if allow_header:
        discovery_type, confidence = "options_supported", CONFIDENCE_HIGH
        evidence = [f"OPTIONS {url} returned HTTP {status_code} with Allow: {allow_header!r}"]
    elif status_code in (200, 204):
        discovery_type, confidence = "options_response_no_allow_header", CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned HTTP {status_code} without an Allow header"]
    elif status_code in (401, 403):
        discovery_type, confidence = "access_restricted", CONFIDENCE_MEDIUM
        evidence = [f"OPTIONS {url} returned HTTP {status_code}"]
    elif status_code == 405:
        discovery_type, confidence = "method_not_allowed", CONFIDENCE_MEDIUM
        evidence = [f"OPTIONS {url} returned HTTP 405 — OPTIONS itself is not permitted here"]
    else:
        discovery_type, confidence = "unexpected_status", CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned unexpected HTTP {status_code}"]

    if not methods and discovery_type in ("access_restricted", "method_not_allowed", "options_response_no_allow_header"):
        head_resp = fetch_url_head(url, timeout=timeout)
        if head_resp["status"] == "found" and head_resp.get("status_code") is not None and head_resp["status_code"] < 400:
            methods = ["GET"]
            evidence.append(
                f"HEAD {url} returned HTTP {head_resp['status_code']} — GET support inferred "
                f"(safe fallback probe; no state-changing verb attempted)"
            )

    record = {
        "url": url, "discovery_type": discovery_type, "status_code": status_code,
        "allow_header": allow_header, "methods": methods, "confidence": confidence,
        "evidence": evidence, "timestamp": _now(),
        "note": "Only OPTIONS and a safe HEAD fallback are used; no state-changing verb is ever sent to probe support.",
    }
    err = _safe_store_add(store, make_finding(
        "api_http_methods_discovered", target or url, dict(record), evidence, confidence,
        metadata={"url": url, "methods": methods},
    ))
    result = {"url": url, "status": "found", **record}
    if err:
        result["persistence_error"] = err
    return result


# ---------------------------------------------------------------------------
# 9. Authentication-method fingerprinting (Bearer/API-Key/Basic/OAuth/JWT)
# ---------------------------------------------------------------------------

def _decode_jwt_header_only(token: str) -> Dict[str, Any]:
    """
    Decode (not verify) only the header segment of a JWT-shaped string.
    JWTs are base64url-encoded, not encrypted, so no key/secret is
    required — this is not a cryptographic attack. Only the declared
    algorithm/type is kept; the raw token is never persisted in full.
    """
    import base64
    entry: Dict[str, Any] = {
        "token_preview": (token[:12] + "..." + token[-6:]) if len(token) > 24 else "***",
        "alg": None, "typ": None,
    }
    parts = token.split(".")
    if len(parts) != 3:
        return entry
    padded = parts[0] + "=" * (-len(parts[0]) % 4)
    try:
        header_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
        header_json = json.loads(header_bytes.decode("utf-8", errors="replace"))
        if isinstance(header_json, dict):
            entry["alg"] = header_json.get("alg")
            entry["typ"] = header_json.get("typ")
    except Exception:
        pass
    return entry


def fingerprint_authentication(
    observations: List[Dict[str, Any]],
    security_schemes: Optional[List[Dict[str, Any]]] = None,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Aggregate authentication-method signals (Bearer/API-Key/Basic/OAuth/
    JWT) observed across every response this module already fetched, plus
    any OpenAPI/Swagger security-scheme declarations already parsed by
    discover_openapi_specs. Read-only: no discovered credential material
    is ever used to authenticate against anything.
    """
    result: Dict[str, Any] = {
        "bearer": {"detected": False, "evidence": []},
        "api_key": {"detected": False, "evidence": [], "header_names": []},
        "basic": {"detected": False, "evidence": []},
        "oauth": {"detected": False, "evidence": []},
        "jwt": {"detected": False, "evidence": [], "tokens": []},
    }

    for scheme in security_schemes or []:
        stype = (scheme.get("type") or "").lower()
        sscheme = (scheme.get("scheme") or "").lower()
        name = scheme.get("name")
        if stype == "http" and sscheme == "bearer":
            result["bearer"]["detected"] = True
            result["bearer"]["evidence"].append(f"OpenAPI securityScheme {name!r} declares HTTP bearer authentication")
        elif stype == "http" and sscheme == "basic":
            result["basic"]["detected"] = True
            result["basic"]["evidence"].append(f"OpenAPI securityScheme {name!r} declares HTTP basic authentication")
        elif stype == "apikey":
            result["api_key"]["detected"] = True
            if name:
                result["api_key"]["header_names"].append(name)
            result["api_key"]["evidence"].append(
                f"OpenAPI securityScheme declares an API key in {scheme.get('in')!r}: {name!r}"
            )
        elif stype == "oauth2":
            result["oauth"]["detected"] = True
            result["oauth"]["evidence"].append(
                f"OpenAPI securityScheme {name!r} declares OAuth2 flow(s): {scheme.get('flows')}"
            )

    seen_tokens = set()
    for obs in observations or []:
        headers = obs.get("headers") or {}
        body = obs.get("body") or ""
        url = obs.get("url")

        www_auth = _ci_get(headers, "WWW-Authenticate")
        if www_auth:
            lowered = www_auth.lower()
            if "bearer" in lowered:
                result["bearer"]["detected"] = True
                result["bearer"]["evidence"].append(f"WWW-Authenticate header on {url}: {www_auth!r}")
            if "basic" in lowered:
                result["basic"]["detected"] = True
                result["basic"]["evidence"].append(f"WWW-Authenticate header on {url}: {www_auth!r}")

        for header_name in _API_KEY_HEADER_NAMES:
            if _ci_get(headers, header_name) is not None:
                result["api_key"]["detected"] = True
                if header_name not in result["api_key"]["header_names"]:
                    result["api_key"]["header_names"].append(header_name)
                result["api_key"]["evidence"].append(f"Header {header_name!r} present in response from {url}")

        if _API_KEY_KEYWORD_RE.search(body):
            result["api_key"]["detected"] = True
            result["api_key"]["evidence"].append(f"Content on {url} references an API key parameter/header")

        if _OAUTH_KEYWORD_RE.search(body):
            result["oauth"]["detected"] = True
            result["oauth"]["evidence"].append(f"Content on {url} references an OAuth2 authorization/token endpoint or parameter")

        haystack_tokens = set(_JWT_RE.findall(body))
        for value in headers.values():
            if isinstance(value, str):
                haystack_tokens.update(_JWT_RE.findall(value))
        for token in haystack_tokens:
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            decoded = _decode_jwt_header_only(token)
            result["jwt"]["detected"] = True
            result["jwt"]["tokens"].append(decoded)
            result["jwt"]["evidence"].append(f"JWT-shaped token observed on {url} (alg={decoded.get('alg')!r})")

    result["api_key"]["header_names"] = sorted(set(n for n in result["api_key"]["header_names"] if n))

    evidence_flat = [e for method in result.values() for e in method["evidence"]]
    if evidence_flat:
        structural = any("OpenAPI securityScheme" in e or "WWW-Authenticate" in e for e in evidence_flat)
        confidence = CONFIDENCE_HIGH if structural else CONFIDENCE_MEDIUM
        methods_detected = [m for m in result if result[m]["detected"]]
        err = _safe_store_add(store, make_finding(
            "api_authentication_method_fingerprint", target or "unknown", dict(result), evidence_flat, confidence,
            metadata={"methods_detected": methods_detected},
        ))
        if err:
            result["persistence_error"] = err

    return result


# ---------------------------------------------------------------------------
# Module orchestration (single target)
# ---------------------------------------------------------------------------

def run_api_recon(
    base_url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    enable_graphql_introspection: bool = True,
    version_range: Optional[range] = None,
) -> Dict[str, Any]:
    """
    Run every Module 11 responsibility against `base_url` and persist
    every completed discovery immediately to
    <output_dir>/pending_assets.json (crash-safe). A failure in one stage
    does not prevent the others from running.
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "target": target, "module": MODULE_NAME, "base_url": base_url,
        "started_at": _now(),
        "versions": {}, "specifications": {}, "documentation": {}, "graphql": {},
        "graphql_introspections": [], "protocol_classifications": [],
        "deprecated_endpoints": {}, "http_methods": [],
        "authentication_fingerprint": {}, "errors": [],
    }

    baseline = _probe_soft_404(origin, timeout)

    try:
        summary["versions"] = discover_api_versions(
            base_url, target=target, store=store, timeout=timeout, baseline=baseline, version_range=version_range,
        )
    except Exception as exc:
        summary["errors"].append({"stage": "versions", "error": str(exc)})
        summary["versions"] = {"versions_identified": [], "observations": [], "errors": [str(exc)]}

    try:
        summary["specifications"] = discover_openapi_specs(base_url, target=target, store=store, timeout=timeout, baseline=baseline)
    except Exception as exc:
        summary["errors"].append({"stage": "specifications", "error": str(exc)})
        summary["specifications"] = {"specs_discovered": [], "observations": [], "errors": [str(exc)]}

    try:
        summary["documentation"] = discover_documentation_pages(base_url, target=target, store=store, timeout=timeout, baseline=baseline)
    except Exception as exc:
        summary["errors"].append({"stage": "documentation", "error": str(exc)})
        summary["documentation"] = {"pages_discovered": [], "observations": [], "errors": [str(exc)]}

    try:
        summary["graphql"] = detect_graphql_endpoints(base_url, target=target, store=store, timeout=timeout, baseline=baseline)
    except Exception as exc:
        summary["errors"].append({"stage": "graphql", "error": str(exc)})
        summary["graphql"] = {"endpoints_detected": [], "observations": [], "errors": [str(exc)]}

    for ep in summary["graphql"].get("endpoints_detected", []):
        if ep.get("confidence") in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM):
            try:
                intro = introspect_graphql_schema(
                    ep["url"], target=target, store=store, timeout=timeout, enabled=enable_graphql_introspection,
                )
            except Exception as exc:
                intro = {"url": ep["url"], "status": "error", "error": str(exc)}
            summary["graphql_introspections"].append(intro)

    all_observations = (
        summary["versions"].get("observations", []) + summary["specifications"].get("observations", [])
        + summary["documentation"].get("observations", []) + summary["graphql"].get("observations", [])
    )
    graphql_confirmed_urls = {ep["url"] for ep in summary["graphql"].get("endpoints_detected", [])}
    classified_urls = set()
    for obs in all_observations:
        if obs["url"] in classified_urls:
            continue
        classified_urls.add(obs["url"])
        try:
            classification = classify_api_protocol(
                obs["url"], obs.get("headers"), obs.get("body"), graphql_confirmed=obs["url"] in graphql_confirmed_urls,
            )
            summary["protocol_classifications"].append(classification)
        except Exception as exc:
            summary["errors"].append({"stage": "protocol_classification", "url": obs["url"], "error": str(exc)})

    try:
        summary["deprecated_endpoints"] = detect_deprecated_endpoints(
            summary["versions"].get("versions_identified", []), store=store, target=target,
        )
    except Exception as exc:
        summary["errors"].append({"stage": "deprecated_endpoints", "error": str(exc)})
        summary["deprecated_endpoints"] = {"deprecated_endpoints": [], "errors": [str(exc)]}

    method_candidate_urls: List[str] = []
    method_candidate_urls.extend(
        r["url"] for r in summary["versions"].get("versions_identified", []) if r.get("discovery_type") == "content_confirmed"
    )
    method_candidate_urls.extend(ep["url"] for ep in summary["graphql"].get("endpoints_detected", []))
    method_candidate_urls.extend(
        s["url"] for s in summary["specifications"].get("specs_discovered", []) if s.get("discovery_type") == "content_confirmed"
    )
    for url in dict.fromkeys(method_candidate_urls):
        try:
            summary["http_methods"].append(discover_http_methods(url, target=target, store=store, timeout=timeout))
        except Exception as exc:
            summary["errors"].append({"stage": "http_methods", "url": url, "error": str(exc)})

    security_schemes = [
        s for spec in summary["specifications"].get("specs_discovered", []) for s in spec.get("security_schemes", [])
    ]
    try:
        summary["authentication_fingerprint"] = fingerprint_authentication(
            all_observations, security_schemes=security_schemes, store=store, target=target,
        )
    except Exception as exc:
        summary["errors"].append({"stage": "authentication_fingerprint", "error": str(exc)})
        summary["authentication_fingerprint"] = {}

    for section_key in ("versions", "specifications", "documentation", "graphql"):
        summary["errors"].extend(summary[section_key].get("errors", []))
    summary["errors"].extend(summary["deprecated_endpoints"].get("errors", []))

    summary["status"] = "completed_with_errors" if summary["errors"] else "completed"
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="api_recon.py",
        description="ReconHound Module 11 — dedicated API reconnaissance (standalone test entry point).",
    )
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://example.com/")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument(
        "--no-graphql-introspection", action="store_true",
        help="Disable GraphQL schema introspection even for confirmed in-scope endpoints",
    )
    args = parser.parse_args()

    try:
        result = run_api_recon(
            args.url, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
            enable_graphql_introspection=not args.no_graphql_introspection,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
