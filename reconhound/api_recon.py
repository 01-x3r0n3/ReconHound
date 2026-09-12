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
                                     + discover_declared_api_versions
  2. Swagger/OpenAPI discovery   -> discover_openapi_specs (+ parse_openapi_spec)
  3. GraphQL detection           -> detect_graphql_endpoints
  4. GraphQL schema introspection-> introspect_graphql_schema
                                     + mine_graphql_field_suggestions
  5. REST/GraphQL/gRPC detection -> classify_api_protocol
                                     + persist_protocol_classification
  6. API documentation discovery -> discover_documentation_pages
  7. Deprecated endpoint detect. -> detect_deprecated_endpoints
  8. HTTP method discovery       -> discover_http_methods
  9. Auth-method fingerprinting  -> fingerprint_authentication
                                     + discover_oauth_metadata
  (shared HTTP client)           -> fetch_url / fetch_url_post /
                                     fetch_url_options / fetch_url_head
  (differential classification)  -> _probe_catch_all / matches_catch_all /
                                     classify_response / detect_application_error
  (run accounting)               -> ApiReconState
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
  7. Existence is judged **differentially**, never from a status code alone.
     Before probing anything, `_probe_catch_all` fingerprints how the origin
     answers two random, certainly-absent paths of different lengths; a
     candidate is only recorded when its response differs from that
     fingerprint. Where no usable baseline exists, confidence is capped and
     the reason is stated rather than assumed away. This is what separates
     "this API version responded" from "this host answers 200 to everything",
     and it is the single largest correctness difference in the module: a
     path-echoing 200 catch-all previously produced 31 HIGH-confidence
     phantom API versions, a blanket redirect 31 MEDIUM ones, and a host
     answering 429 to everything produced 58 persisted findings out of pure
     refusals. Blocked is not absent, and it is certainly not present.
  8. The whole run shares one `ApiReconState`: a hard request budget
     (DEFAULT_MAX_REQUESTS), a consecutive-refusal tripwire, and a
     cancellation flag. context.md gives *global* scheduling and throttling
     to core/orchestrator.py and this module does not duplicate that; what it
     owns is its own footprint and the decision to stop probing a host that
     is refusing to answer. A refusal is never recorded as a discovery, and a
     run that was throttled, budget-capped or interrupted reports itself as
     inconclusive rather than as a clean negative result.
  9. Two bounded additions consume evidence the module already has, rather
     than expanding the probe surface:
       * `discover_declared_api_versions` records versions the target
         *declared* (an API-Version response header, an OpenAPI `info.version`
         or a version segment in a declared server URL) with a distinct
         `basis`, at zero additional requests.
       * `mine_graphql_field_suggestions` sends exactly ONE read-only query,
         naming one field that deliberately does not exist, and parses the
         server's own "Did you mean ...?" reply. No field name is guessed,
         iterated or fuzzed, and the result is recorded as LOW-confidence
         INFERRED evidence that is explicitly not a schema.
     `discover_oauth_metadata` adds two GETs for the two standard
     authorization-server metadata documents (OpenID Connect Discovery,
     RFC 8414) — published metadata, never an authorization flow.

Known limitations (deliberate v1 boundaries, not oversights)

  L1. **No YAML parser.** `openapi.yaml`/`swagger.yaml` responses are parsed
      by best-effort regex (decision #1). Anchors, flow style and
      multi-document files are not captured beyond "a spec-shaped file was
      found here".
  L2. **gRPC is detected, not spoken.** This module speaks HTTP/1.1 through
      `requests`. An explicit `application/grpc` content type, a gRPC-Web
      endpoint and proxy-surfaced `grpc-*` headers are detectable; a native
      HTTP/2 gRPC service is not. No HTTP/2 client, Protobuf decoder or
      server-reflection query exists here, and none is added merely to close
      the gap — "gRPC not detected" therefore does not mean "no gRPC service
      is present", and classify_api_protocol says so in its evidence.
  L3. **GraphQL schema inference is partial.** Introspection yields a bounded
      map (type names and field names, capped and flagged when capped). When
      introspection is refused, only the server's own volunteered suggestions
      are recorded. Reconstructing a schema from error behaviour is a v2
      concern.
  L4. **Version discovery covers path templates plus declared versions.**
      Query-parameter versioning (`?version=`), `Accept` media-type
      versioning (`application/vnd.x.v2+json`) and subdomain versioning are
      not probed. Probing them means multiplying candidate versions by
      candidate headers by discovered endpoints — the combinatorial explosion
      this module exists to avoid — and subdomain discovery belongs to
      passive_recon.py.
  L5. **Stateful and authenticated APIs are out of reach.** No session,
      cookie jar, CSRF handling, login flow or browser execution exists here;
      crawler.py owns session workflows. An API that requires authentication
      is observed only through its unauthenticated surface, and the module
      never invents or replays a credential to get past that.
  L6. **`$ref` is never resolved.** parse_openapi_spec reads `paths` and each
      operation's flat `parameters` list only. Circular and deeply nested
      `$ref` chains are structurally unreachable rather than defended
      against; the cost is that `$ref`-indirect parameters are counted as
      `unresolved_refs` instead of being followed.
  L7. **CORS/Origin behaviour is not probed.** Comparing responses with and
      without a fabricated Origin header would mean injecting an origin into
      requests, and CORS configuration is not by itself a finding. Where a
      genuinely discovered frontend origin exists, that correlation belongs
      to surface_mapper.py.
  L8. **Runtime state is observed, never verified on demand.** A deprecated
      endpoint's `runtime_state` comes only from responses this run already
      received. No request is ever sent purely to check whether a deprecated
      endpoint still works, and no state-changing verb is ever sent at all.

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

Specifically, and non-negotiably:

  * A decoded JWT is intelligence about an issuer, audience, lifetime and
    scope. It is not evidence of compromised authentication. `alg: none` in
    an observed token is a declaration *inside that token* and says nothing
    about what the server would accept; HS256 is a correct algorithm, not a
    weakness. No signature is verified, no secret is attacked, no token is
    modified, forged or replayed, and the raw token is never persisted.
  * A 401/403 or a `WWW-Authenticate` header is a challenge from whatever
    answered the request — application, gateway or WAF. Each is recorded with
    the layer it plausibly came from and never asserted as "the application
    uses this mechanism".
  * `deprecated: true` is a lifecycle declaration about support, not a
    statement that an endpoint is inactive. Specification metadata and
    observed runtime state are recorded separately and never merged.
  * Discovered OAuth/OIDC endpoints are *declared* metadata. This module does
    not probe them and performs no authorization flow.
  * An `X-Amz-*`-style provider header is technology evidence owned by
    tech_fingerprint.py, and is not inferred here into a claim about
    serverless or ephemeral hosting.
  * A GraphQL field suggestion is inferred from an error message. It is not a
    schema, not necessarily complete, and not necessarily queryable.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import threading
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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

# ---------------------------------------------------------------------------
# Resource bounds
#
# Every value here is derived from this module's own measured behaviour, not
# picked for roundness. A full run against a host that answers every probe was
# measured at 106 requests (65 GET + 5 POST + 36 OPTIONS); the additions in
# this module (two OAuth/OIDC metadata documents, one GraphQL field-suggestion
# probe, one extra catch-all baseline sample per root) add at most a handful
# more. DEFAULT_MAX_REQUESTS therefore sits at roughly twice the measured
# worst case: high enough that no legitimate target is ever truncated, low
# enough that a pathological target — one whose every response manufactures a
# new candidate — cannot let this module dominate a pipeline run.
# ---------------------------------------------------------------------------

DEFAULT_MAX_REQUESTS = 250

# Two catch-all samples with deliberately different path lengths, so a
# *dynamic* not-found page (one that echoes the requested path) is
# distinguishable from a static one. One sample cannot tell those apart, and
# mistaking a dynamic catch-all for real content is what produced 31
# HIGH-confidence phantom API versions in the reproduction that motivated it.
BASELINE_PROBE_COUNT = 2
BASELINE_SAMPLE_BYTES = 2048

# Consecutive refusals (429, or 503 carrying Retry-After) before a stage stops
# probing. Three is enough to distinguish a single throttled request from a
# host that is refusing this client outright, and small enough that a
# rate-limited target is not hammered for another 60+ requests.
RATE_LIMIT_TRIP_THRESHOLD = 3

# Consecutive transport-level failures (timeout, connection refused, DNS
# failure — never an HTTP response of any status) before the run stops, and
# only while no probe in this run has ever been answered.
#
# This module probes sequentially by design, so an origin that accepts TCP
# connections and never replies costs one full `timeout` per candidate:
# measured at 73 probes / 147s at timeout=2, and 552s at the orchestrator's
# default timeout=8, for zero observations. One answered probe disarms the
# tripwire permanently, and a tripped run is never `conclusive()`, so nothing
# is written into shared negative-result memory and a later run against a
# healthy origin repeats the work in full.
TRANSPORT_FAILURE_TRIP_THRESHOLD = 12

# Observations are held in memory for the whole run and returned in the
# summary, which the orchestrator may serialise. 200 x 4 KB caps that at
# ~800 KB; the un-capped version measured 304 KB for a 69-observation run and
# grew linearly with the candidate list.
MAX_OBSERVATIONS = 200
MAX_OBSERVATION_BODY_BYTES = 4000
# Header values are attacker-controlled and were the one un-capped part of a
# retained observation: a server sending one very large header value put it in
# memory once per observation and again in the returned summary.
MAX_OBSERVATION_HEADERS = 60
MAX_OBSERVATION_HEADER_CHARS = 4096

# A hostile Allow header parsed 5000 "methods" in reproduction. HTTP defines
# far fewer than 24 methods a real endpoint would advertise.
MAX_ALLOW_METHODS = 24
_HTTP_METHOD_TOKEN_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,20}$")

# Specification bounds. This module never resolves "$ref", so no recursion is
# possible here at all (see parse_openapi_spec) — these bound breadth only.
MAX_SPEC_SECURITY_SCHEMES = 50
MAX_SPEC_PATHS = 500
MAX_SPEC_OPERATIONS = 2000
MAX_SPEC_PARAMETERS_PER_OPERATION = 100
MAX_SPEC_DEPRECATED_OPERATIONS = 200
MAX_SPEC_SERVERS = 20

# JWT intelligence bounds (see _decode_jwt_intelligence).
MAX_JWT_TOKENS = 25
MAX_JWT_CLAIM_CHARS = 120
MAX_JWT_LIST_CLAIM_ITEMS = 40

# Bounded GraphQL field-suggestion mining (see mine_graphql_field_suggestions).
MAX_GRAPHQL_SUGGESTIONS = 50

# Introspection is the most expensive probe this module sends (a large query
# and a potentially large response), and GRAPHQL_PATHS deliberately contains
# near-duplicates ("graphql" and "graphql/"). Endpoints are de-duplicated by
# slash-normalised identity first, and the remainder is capped: a host routing
# every path to one GraphQL server otherwise received five introspection
# queries and five suggestion probes for one endpoint.
MAX_GRAPHQL_INTROSPECTIONS = 3

# Per-method evidence cap in the authentication fingerprint. Without it a
# 200-observation run appends one evidence line per (observation, API-key
# header name) pair.
MAX_EVIDENCE_ITEMS = 50

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

# 4b. Bounded GraphQL field-suggestion mining (introspection-disabled
# endpoints only — see module docstring, decision #9)
GRAPHQL_SUGGESTION_PROBE = {
    "query": "{ reconhoundNonexistentField__probe }"
}
# "Did you mean \"a\", \"b\", or \"c\"?" — the suggestion list a schema-aware
# GraphQL server volunteers in its own error message. Parsed, never guessed.
# The capture deliberately has no length bound of its own. An earlier bound of
# 400 characters made a *large* suggestion list yield zero suggestions rather
# than a capped subset — the closing "?" fell outside the window, so the whole
# pattern failed to match. The scan is already bounded upstream:
# _graphql_error_messages caps the joined messages at 2000 characters, and the
# extracted names are capped at MAX_GRAPHQL_SUGGESTIONS. Terminating on "?" or
# end-of-text means a truncated message still yields the names it does carry.
_GRAPHQL_SUGGESTION_RE = re.compile(r'Did you mean\s+(.*?)(?:\?|\Z)', re.IGNORECASE | re.DOTALL)
_GRAPHQL_SUGGESTION_ITEM_RE = re.compile(r'[\'"`]([A-Za-z_][A-Za-z0-9_]{0,63})[\'"`]')

# 5. REST vs GraphQL vs gRPC detection
#
# Detection only. This module speaks HTTP/1.1 through `requests`, so a native
# HTTP/2 gRPC service cannot be spoken to at all; what *is* detectable over
# HTTP/1.1 is a gRPC-Web endpoint, a proxy that leaks grpc-* trailers into
# headers, and an explicit application/grpc content type. Full HTTP/2 +
# Protobuf + server-reflection discovery is a documented v2 boundary, not
# something this module pretends to cover (see module docstring, limitation L2).
GRPC_CONTENT_TYPE_RE = re.compile(r"application/grpc(?:-web)?(?:\+(?:proto|json|text))?", re.IGNORECASE)
GRPC_HEADER_NAMES = ["grpc-status", "grpc-message", "grpc-encoding", "grpc-accept-encoding"]

# 9b. OAuth/OIDC authorization-server metadata (RFC 8414 / OpenID Connect
# Discovery). Two well-known documents, fetched read-only under the
# already-authorized origin — metadata discovery, never an authorization flow.
OAUTH_METADATA_PATHS = [
    ".well-known/openid-configuration",
    ".well-known/oauth-authorization-server",
]
_OAUTH_METADATA_FIELDS = [
    "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
    "userinfo_endpoint", "introspection_endpoint", "revocation_endpoint",
    "registration_endpoint", "end_session_endpoint",
]
_OAUTH_METADATA_LIST_FIELDS = [
    "scopes_supported", "grant_types_supported", "response_types_supported",
    "token_endpoint_auth_methods_supported", "id_token_signing_alg_values_supported",
    "code_challenge_methods_supported",
]

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


def _idna_normalize(host: str) -> str:
    """
    Reduce a hostname to the single form scope comparisons are made in.

    Without this, a target written as "münchen.de" and a hostname arriving as
    "xn--mnchen-3ya.de" compare unequal even though they are the same host —
    reproduced against this module: the A-label form of an in-scope IDN target
    was rejected as out of scope, so an authorized host was silently skipped.
    Both sides are folded to lowercase A-label form; anything that will not
    encode is returned lowercased unchanged so the comparison is still
    deterministic. Mirrors endpoint_discovery.py's helper of the same name.
    """
    host = host.strip().rstrip(".").lower()
    if not host or host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return host


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = _idna_normalize(hostname)
    target = _idna_normalize(target)
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def _strip_userinfo(url: str) -> str:
    """
    Remove any `user:password@` component from a URL.

    Reproduced against this module: a base_url of
    `https://user:s3cr3t@example.com/` put the credential into `_origin_of()`,
    therefore into every one of the ~100 probe URLs this module builds, into
    every evidence string ("GET https://user:s3cr3t@example.com/swagger.json
    returned ..."), and therefore into pending_assets.json — a plain-text file
    shared with every other module and included in the report appendix. That
    is a direct CLAUDE.md rule 16 violation. The netloc is rebuilt from the
    parsed host/port so the result is also the canonical probe form.
    """
    parsed = urllib.parse.urlsplit(url)
    if "@" not in parsed.netloc:
        return url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"          # bare IPv6 literal
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def validate_api_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, mirroring every earlier Active-phase module's
    rationale: IP scope is enforced upstream, not by a domain comparison
    here).

    Every rejection path raises ScopeError. That matters because ScopeError is
    the only exception the CLI and the orchestrator's callers name: a bare
    ValueError escaping from urlsplit (which it does for a malformed IPv6
    literal such as "http://[::1") bypassed both and aborted the caller.
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()
    # A CR, LF, NUL or tab inside a URL is never legitimate. urlsplit silently
    # *removes* newlines and tabs, so the URL would be validated in its
    # stripped form and then handed to requests still carrying the raw bytes —
    # a request-splitting shape that must be named here, not discovered as an
    # opaque transport error later.
    if any(ch in candidate for ch in "\r\n\t\x00"):
        raise ScopeError(f"URL contains control characters: {url!r}")

    try:
        parsed = urllib.parse.urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port  # raises ValueError for an out-of-range port
    except ValueError as exc:
        raise ScopeError(f"URL cannot be parsed: {url!r} ({exc})") from exc

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if target and not _is_ip_literal(hostname) and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    # Credentials embedded in an operator-supplied URL are dropped rather than
    # rejected: the URL is legitimate, re-sending and persisting the
    # credential is not (see _strip_userinfo).
    return _strip_userinfo(candidate)


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors every earlier module's model; kept local
# per modular independence)
# ---------------------------------------------------------------------------

def _jsonify(value: Any, _depth: int = 0) -> Any:
    """
    Coerce a value into something json.dump can definitely write.

    Findings carry data this module did not create: `version_records` and
    `observations` are public parameters other modules and the orchestrator can
    supply, and OpenAPI/GraphQL payloads are attacker-controlled. Reproduced:
    a single un-encodable value (a set in a caller-supplied record) raised
    TypeError *inside* store.add(), which _safe_store_add did not catch, which
    aborted the stage and discarded every already-completed discovery in it —
    exactly what context.md §12.11 forbids. Coercing at construction time makes
    every finding this module emits writable by definition.

    Mirrors endpoint_discovery.py/passive_recon.py, which share this file.
    """
    if _depth > 12:
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        # NaN/Infinity are accepted by json.dump but produce invalid JSON that
        # a strict reader (including this module's own _read_all) rejects.
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, dict):
        return {str(k): _jsonify(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(v, _depth + 1) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


# A JSON document nested thousands of levels deep is a few kilobytes of text
# that drives json.loads into the C recursion limit. Reproduced: an 80,000-deep
# array body raised RecursionError inside classify_response and
# parse_openapi_spec. Both caught it, but recovering from RecursionError leaves
# the interpreter close to its limit, and every response body this module parses
# is attacker-controlled.
#
# A first attempt matched a *run* of consecutive opening brackets with a regex.
# Self-attack defeated it in one line: `{"a":{"a":{"a":...` nests just as deeply
# with a key between every brace, so no run exists and the bomb went straight
# to json.loads. Depth is therefore measured exactly, by a single linear scan
# that tracks string state and stops the moment the cap is passed.
MAX_JSON_NESTING = 200


def _exceeds_json_nesting(text: str, limit: int = MAX_JSON_NESTING) -> bool:
    """
    True if `text` nests deeper than `limit`. One O(n) pass, early-exit.

    String contents are skipped so a body containing "[[[[[" as *data* is not
    mistaken for structure.
    """
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def safe_json_loads(text: Optional[str]) -> Tuple[Any, Optional[str]]:
    """
    Parse JSON from an untrusted response body. Returns (value, error_message);
    `value` is None whenever `error_message` is set. Never raises.
    """
    if not text:
        return None, "empty body"
    stripped = text.strip()
    if not stripped:
        return None, "empty body"
    if _exceeds_json_nesting(stripped):
        return None, (
            f"document nests deeper than the {MAX_JSON_NESTING}-level cap and was not parsed "
            f"(rejected as a nesting bomb, not as invalid JSON)"
        )
    try:
        return json.loads(stripped), None
    except (json.JSONDecodeError, ValueError, RecursionError, TypeError) as exc:
        return None, str(exc)


def _as_text(value: Any) -> str:
    """
    Coerce a possibly-non-string caller value to text for regex/`in` use.

    Reproduced: a `version_label` of `3` (or of a set) raised TypeError out of
    detect_deprecated_endpoints, and a non-dict `headers` entry raised
    AttributeError out of fingerprint_authentication. Both are public entry
    points other modules call with data this module did not build.
    """
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


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
        "target": _as_text(target),
        "value": _jsonify(value),
        "evidence": [_as_text(_jsonify(e)) for e in (evidence or [])],
        "confidence": confidence,
        "source": MODULE_NAME,
        "timestamp": _now(),
        "metadata": _jsonify(metadata or {}),
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
            self._fsync_dir(dir_name)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    @staticmethod
    def _fsync_dir(dir_name: str) -> None:
        """
        Durably commit the os.replace() rename itself.

        Without this the replacement file's *contents* are on disk but the
        directory entry pointing at them may not be, so a power loss can still
        resurrect the pre-replace file and lose every discovery appended since.
        Best-effort: some platforms/filesystems refuse to fsync a directory.
        Mirrors endpoint_discovery.py/passive_recon.py, which share this file.
        """
        try:
            fd = os.open(dir_name, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._read_all()


# A persistence attempt can fail in more ways than PersistenceError: the disk
# fills or the output path loses permissions (OSError), or a caller-supplied
# record carries a value json.dump cannot serialise (TypeError/ValueError).
# Catching only PersistenceError meant those escaped _safe_store_add, killed
# the enclosing stage, and took every *completed discovery* in that stage down
# with them — reproduced with both a read-only output directory and a set in a
# caller-supplied record. The discovery is now always returned to the caller
# and the failure is reported. Mirrors endpoint_discovery.py.
_PERSISTENCE_FAILURES = (PersistenceError, OSError, TypeError, ValueError)


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
    except _PERSISTENCE_FAILURES as exc:
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
    """
    scheme://host[:port] for `url`, with any userinfo removed.

    Using `parsed.netloc` directly carried `user:password@` into every probe
    URL this module builds and into every persisted evidence string (see
    _strip_userinfo).
    """
    parsed = urllib.parse.urlsplit(_strip_userinfo(url))
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return f"{parsed.scheme}://{netloc}"


def _ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def _url_for_path(root: str, entry: str) -> str:
    root = _ensure_trailing_slash(root)
    return urllib.parse.urljoin(root, entry.lstrip("/"))


def _hostname_of(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or url


def _endpoint_identity(url: str) -> str:
    """
    Slash-normalised identity for an endpoint URL.

    "https://h/graphql" and "https://h/graphql/" are one endpoint on the great
    majority of servers, and both are probed because on a minority they are
    not. They must not, however, each earn their own introspection query and
    their own suggestion probe.
    """
    try:
        parsed = urllib.parse.urlsplit(_as_text(url))
    except ValueError:
        return _as_text(url)
    path = (parsed.path or "/").rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}".lower()


def _add_observation(observations: List[Dict[str, Any]], entry: Dict[str, Any]) -> None:
    """
    Append one observation, bounded in both count and per-body size.

    Observations live for the whole run and are returned in the summary, which
    the orchestrator may serialise. Un-capped, a 69-observation run already
    produced a 304 KB summary and grew linearly with the candidate list.
    """
    if len(observations) >= MAX_OBSERVATIONS:
        return
    body = entry.get("body") or ""
    entry["body"] = body[:MAX_OBSERVATION_BODY_BYTES]
    headers = entry.get("headers")
    if isinstance(headers, dict):
        entry["headers"] = {
            str(k)[:200]: (v[:MAX_OBSERVATION_HEADER_CHARS] if isinstance(v, str) else v)
            for k, v in list(headers.items())[:MAX_OBSERVATION_HEADERS]
        }
    observations.append(entry)


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
            # Fallback for adapters/mocks without a usable .raw. It must stay
            # bounded: `resp.content` materialises the *entire* body before the
            # slice runs, so a multi-megabyte response — or a decompression
            # bomb, which this module invites by parsing every JSON body it
            # gets — was fully resident in memory before being truncated to
            # 128 KB. iter_content stops as soon as the cap is reached.
            # Mirrors endpoint_discovery.py's fetch_url.
            raw = b""
            try:
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    raw += chunk
                    if len(raw) > max_body_bytes:
                        break
                raw = raw[: max_body_bytes + 1]
            except Exception:
                # Last resort for adapters exposing neither a readable .raw nor
                # a working iter_content. `.content` materialises the whole
                # body, so it is used only when the server declared a size that
                # is safe to hold; an undeclared or oversized body is reported
                # as unread rather than swallowed whole.
                declared = _ci_get(dict(getattr(resp, "headers", {}) or {}), "Content-Length")
                hard_cap = max_body_bytes * 8
                try:
                    if declared is not None and int(declared) > hard_cap:
                        raise ValueError(f"declared body of {declared} bytes exceeds the read cap")
                    raw = resp.content[: max_body_bytes + 1]
                except Exception as body_exc:
                    raw = b""
                    result["body_read_error"] = str(body_exc)
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
# Run state: request budget, rate-limit tripwire, cancellation
#
# context.md gives global scheduling/throttling to core/orchestrator.py, and
# this module does not try to own that. What it owns is its own footprint: a
# hard ceiling on how many requests one invocation may send, and the decision
# to stop probing a host that is refusing to answer. Measured before this
# existed: against a host answering 429 to everything, a single run still sent
# all 70 requests AND persisted 58 findings derived from those refusals.
# ---------------------------------------------------------------------------

class ApiReconState:
    """Per-run request accounting. Not a global throttler (orchestrator owns that)."""

    def __init__(self, max_requests: int = DEFAULT_MAX_REQUESTS):
        try:
            self.max_requests = max(1, int(max_requests))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        self.request_count = 0
        self.budget_exhausted = False
        self.rate_limited = False
        self.cancelled = False
        self.consecutive_refusals = 0
        self.blocked_probes = 0
        self.failed_probes = 0
        self.answered_probes = 0
        self.retry_after: Optional[str] = None
        self.notes: List[str] = []
        # Dead-origin tripwire (TRANSPORT_FAILURE_TRIP_THRESHOLD).
        self.consecutive_transport_failures = 0
        self.origin_unreachable = False

    # -- budget ------------------------------------------------------------
    def budget_remaining(self) -> int:
        return max(0, self.max_requests - self.request_count)

    def should_stop(self) -> bool:
        return (self.cancelled or self.rate_limited or self.budget_exhausted
                or self.origin_unreachable)

    def reserve(self) -> bool:
        """Claim one request from the budget. False means the caller must not send it."""
        if self.should_stop():
            return False
        if self.request_count >= self.max_requests:
            if not self.budget_exhausted:
                self.budget_exhausted = True
                self.notes.append(
                    f"request budget of {self.max_requests} exhausted; remaining candidates were not probed"
                )
            return False
        self.request_count += 1
        return True

    # -- refusal tripwire --------------------------------------------------
    def note_response(self, resp: Dict[str, Any]) -> None:
        """
        Update the refusal tripwire from one response.

        A refusal is a 429, or a 503 that carries Retry-After (a 503 without
        one is far more often a broken backend than throttling, and conflating
        the two would stop a run against a merely-unhealthy host). Only
        *consecutive* refusals trip the wire, so one throttled request in the
        middle of a healthy run does not abort it.
        """
        if resp.get("status") != "found":
            self.failed_probes += 1
            self.consecutive_transport_failures += 1
            if (self.answered_probes == 0
                    and not self.origin_unreachable
                    and self.consecutive_transport_failures >= TRANSPORT_FAILURE_TRIP_THRESHOLD):
                self.origin_unreachable = True
                self.notes.append(
                    f"stopped probing after {self.consecutive_transport_failures} consecutive "
                    f"transport failures with no request ever answered; the origin is not "
                    f"responding. The remaining candidates were NOT tested, and their absence "
                    f"from the results is not evidence that this host exposes no API surface"
                )
            return
        status = resp.get("status_code")
        retry_after = _ci_get(resp.get("headers") or {}, "Retry-After")
        refused = status == 429 or (status == 503 and retry_after is not None)
        if refused:
            self.blocked_probes += 1
            self.consecutive_refusals += 1
            if retry_after and not self.retry_after:
                # Recorded as an observation only — never parsed into a sleep,
                # and clipped because the value is attacker-controlled text
                # that ends up in the run summary.
                self.retry_after = _as_text(retry_after)[:120]
            if self.consecutive_refusals >= RATE_LIMIT_TRIP_THRESHOLD and not self.rate_limited:
                self.rate_limited = True
                self.notes.append(
                    f"stopped probing after {self.consecutive_refusals} consecutive HTTP "
                    f"{status} refusals"
                    + (f" (Retry-After: {self.retry_after!r})" if self.retry_after else "")
                    + "; results from this point on are incomplete, and a refusal is not "
                      "evidence that a path is absent"
                )
        else:
            self.consecutive_refusals = 0
            self.answered_probes += 1
        # An HTTP response of any status — a refusal included — proves the
        # origin is answering, so it permanently disarms the dead-origin
        # tripwire. Refusals remain the rate limiter's business.
        self.consecutive_transport_failures = 0

    def conclusive(self) -> bool:
        """
        Whether this run probed enough to make "nothing found" mean anything.

        Deliberately conservative: a run that was cancelled, throttled, cut
        short by the budget, or in which most probes never got a usable answer
        is inconclusive, because the alternative is writing an authoritative
        "checked and not found" into shared negative-result memory and
        suppressing a later, unblocked attempt.
        """
        if (self.cancelled or self.rate_limited or self.budget_exhausted
                or self.origin_unreachable):
            return False
        unusable = self.failed_probes + self.blocked_probes
        if self.request_count == 0:
            return False
        return (self.request_count - unusable) > self.request_count * 0.5


def _budgeted(state: Optional[ApiReconState], fetch_fn, url: str, **kwargs) -> Optional[Dict[str, Any]]:
    """
    Run one fetch through the run's budget/tripwire. None means "not sent".

    None is distinct from an error result on purpose: callers must be able to
    tell "this candidate was never tested" from "this candidate was tested and
    failed", because only the second is a negative result.
    """
    if state is None:
        return fetch_fn(url, **kwargs)
    if not state.reserve():
        return None
    resp = fetch_fn(url, **kwargs)
    state.note_response(resp)
    return resp


# ---------------------------------------------------------------------------
# Response classification
#
# Existence is judged *differentially* — against how the origin answers a path
# that certainly does not exist — not by mapping a status code straight to a
# verdict. Mirrors endpoint_discovery.py's classify_response/matches_catch_all,
# duplicated per modular independence (context.md §12.2).
# ---------------------------------------------------------------------------

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)

# Discovery-type vocabulary. The names existing consumers already read
# ("not_found", "content_confirmed", "possible_soft_404_match", ...) are kept
# verbatim; the additions are purely new vocabulary.
DT_ERROR = "error"
DT_NOT_FOUND = "not_found"
DT_RATE_LIMITED = "rate_limited"
DT_BLOCKED = "blocked"
DT_CATCH_ALL_MATCH = "catch_all_match"
DT_POSSIBLE_SOFT_404 = "possible_soft_404_match"
DT_REDIRECT = "redirect"
DT_ACCESS_RESTRICTED = "access_restricted"
DT_METHOD_NOT_ALLOWED = "method_not_allowed"
DT_SERVER_ERROR = "server_error_response"
DT_CONTENT_CONFIRMED = "content_confirmed"
DT_CONTENT_APP_ERROR = "content_with_application_error"
DT_UNEXPECTED = "unexpected_status"

# Types that mean "this candidate was never effectively tested". Nothing may
# be recorded as a discovery from one of these.
_UNINFORMATIVE_TYPES = frozenset({
    DT_ERROR, DT_NOT_FOUND, DT_RATE_LIMITED, DT_BLOCKED,
    DT_CATCH_ALL_MATCH, DT_POSSIBLE_SOFT_404,
})

# Types that mean "something is routed here, but it did not successfully
# answer". Such a record is real surface and is recorded as such, but it may
# not stand in for a working service — see detect_deprecated_endpoints, where
# an /api/v3/ replying `{"success": false, "error": "v3 is not yet available"}`
# was otherwise enough to mark the live v2 as superseded.
_NOT_SUCCESSFULLY_ANSWERED = _UNINFORMATIVE_TYPES | frozenset({
    DT_CONTENT_APP_ERROR, DT_ACCESS_RESTRICTED, DT_REDIRECT,
    DT_SERVER_ERROR, DT_METHOD_NOT_ALLOWED, DT_UNEXPECTED,
})

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_SIMILARITY_MAX_TOKENS = 4000
CATCH_ALL_SIMILARITY = 0.9
CATCH_ALL_MAX_NOVELTY = 0.25
CATCH_ALL_MIN_TOKENS = 4

_VOLATILE_PATTERNS = [
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\b\d{10,}\b"),
    re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|milliseconds|seconds)\b", re.IGNORECASE),
]


def _digest(text: str) -> str:
    """
    Content digest for response comparison only — never a security decision.

    `usedforsecurity=False` is required for this to work at all on a
    FIPS-enforcing build, where the plain md5() constructor raises.
    """
    data = text.encode("utf-8", errors="ignore")
    try:
        return hashlib.md5(data, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover - Python builds without the keyword
        return hashlib.md5(data).hexdigest()


def _content_signature(body: str) -> Tuple[int, str]:
    normalized = re.sub(r"\s+", " ", body or "").strip()
    return len(normalized), _digest(normalized)


def _structural_signature(body: str, url: str) -> str:
    """
    A digest of a response body with the two things that legitimately vary
    between two renderings of the same page removed: anything derived from the
    *requested path*, and per-request volatile values (request ids, nonces,
    timestamps).

    This is the fix for dynamic catch-all pages. The previous heuristic hashed
    the raw body and compared lengths with a fixed ±25-byte tolerance, so a
    catch-all that echoed the requested path differed from the baseline in both
    hash and length. Measured against such a host: all 31 version candidates
    came back `content_confirmed`/HIGH, and each one then produced a persisted
    `api_version_discovered` finding plus a cascading inferred-deprecation
    finding.
    """
    normalized = re.sub(r"\s+", " ", body or "").strip()
    try:
        path = urllib.parse.urlsplit(url).path or ""
    except ValueError:
        path = ""
    tokens = [path, urllib.parse.quote(path), urllib.parse.unquote(path)]
    tokens.extend(seg for seg in path.split("/") if len(seg) >= 3)
    for token in sorted({t for t in tokens if t}, key=len, reverse=True):
        normalized = normalized.replace(token, "\x00PATH\x00")
    for pattern in _VOLATILE_PATTERNS:
        normalized = pattern.sub("\x00VAR\x00", normalized)
    return _digest(normalized)


def _lengths_close(a: Optional[int], b: Optional[int], tolerance: int = 25) -> bool:
    """
    Whether two body lengths are close enough to be the same page. The window
    is the larger of `tolerance` bytes and 2% of the compared length: a fixed
    absolute window is an eighth of a short JSON envelope and a rounding error
    on a large page.
    """
    if a is None or b is None:
        return False
    allowed = max(tolerance, int(max(a, b) * 0.02))
    return abs(a - b) <= allowed


def _token_similarity(a: str, b: str) -> float:
    """Jaccard overlap of the word tokens in two bodies, 0.0-1.0 (bounded)."""
    if not a or not b:
        return 1.0 if a == b else 0.0
    tokens_a = set(_TOKEN_RE.findall(a)[:_SIMILARITY_MAX_TOKENS])
    tokens_b = set(_TOKEN_RE.findall(b)[:_SIMILARITY_MAX_TOKENS])
    if not tokens_a and not tokens_b:
        return 1.0
    union = tokens_a | tokens_b
    return (len(tokens_a & tokens_b) / len(union)) if union else 0.0


def _content_matches_samples(normalized: str, samples: List[str]) -> bool:
    """
    True if `normalized` is another rendering of the baseline's catch-all.

    Taking two baseline samples means the origin itself shows which words are
    fixed and which vary: the intersection of the samples is the wording the
    error page ALWAYS uses. A body that contains all of it and introduces
    almost no vocabulary of its own is the same page again.
    """
    if not normalized:
        return False
    tokens = set(_TOKEN_RE.findall(normalized)[:_SIMILARITY_MAX_TOKENS])
    if not tokens:
        return False

    core: Optional[set] = None
    vocabulary: set = set()
    for sample in samples:
        sample_tokens = set(_TOKEN_RE.findall(sample)[:_SIMILARITY_MAX_TOKENS])
        union = tokens | sample_tokens
        if union and len(tokens & sample_tokens) / len(union) >= CATCH_ALL_SIMILARITY:
            return True                       # near-identical to one sample
        core = sample_tokens if core is None else (core & sample_tokens)
        vocabulary |= sample_tokens

    if not core or len(core) < CATCH_ALL_MIN_TOKENS or len(tokens) < CATCH_ALL_MIN_TOKENS:
        return False
    if not core.issubset(tokens):
        return False                          # omits wording the error page always uses
    return (len(tokens - vocabulary) / len(tokens)) <= CATCH_ALL_MAX_NOVELTY


def _normalized_location(resp: Dict[str, Any], request_url: str) -> Optional[str]:
    """A redirect target with the requested path factored out, so a blanket
    "everything redirects to /login" is recognisable across probes."""
    location = _ci_get(resp.get("headers") or {}, "Location")
    if not location:
        return None
    try:
        absolute = urllib.parse.urljoin(request_url, location)
    except ValueError:
        return location
    return _structural_signature(absolute, request_url)


def _probe_catch_all(
    origin: str, timeout: float, state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Fingerprint how `origin` answers paths that certainly do not exist.

    Sends BASELINE_PROBE_COUNT probes with deliberately different path lengths.
    Two rather than one is what makes the result trustworthy: identical answers
    mean a static catch-all a hash can match; differing answers mean a dynamic
    one, where only the structural signature and the shared vocabulary are
    comparable; differing *status codes*, or statuses that are themselves
    refusals (429/5xx), mean the origin's behaviour is not stable enough to
    judge anything against, and the baseline is marked unusable rather than
    trusted.

    `available: False` is emphatically not "this origin has no catch-all" —
    callers must degrade confidence, not assume a clean baseline.
    """
    origin = _ensure_trailing_slash(origin)
    samples: List[Dict[str, Any]] = []
    errors: List[str] = []
    for index in range(max(1, BASELINE_PROBE_COUNT)):
        token = uuid.uuid4().hex[: 12 + index * 20]
        probe_url = f"{origin}reconhound-nonexistent-check-{token}"
        resp = _budgeted(state, fetch_url, probe_url, timeout=timeout)
        if resp is None:
            errors.append("baseline probe not sent (request budget exhausted or run stopped)")
            break
        if resp["status"] != "found":
            errors.append(resp.get("error") or "request failed")
            continue
        body = resp.get("body") or ""
        normalized = re.sub(r"\s+", " ", body).strip()
        length, digest = _content_signature(body)
        samples.append({
            "status_code": resp["status_code"],
            "content_length": length,
            "body_hash": digest,
            "normalized_body": normalized[:BASELINE_SAMPLE_BYTES],
            "structural_hash": _structural_signature(body, probe_url),
            "location_hash": _normalized_location(resp, probe_url),
            "content_type": (_ci_get(resp["headers"], "Content-Type") or "").split(";")[0].strip().lower(),
        })

    if not samples:
        return {"available": False, "origin": origin, "probe_errors": errors}

    statuses = {s["status_code"] for s in samples}
    stable_status = len(statuses) == 1
    # A baseline built from responses the origin refused (429) or failed to
    # produce (5xx) is not a "this path does not exist" fingerprint — it is a
    # snapshot of the origin declining to answer. Trusting one inverts the
    # whole differential test.
    unusable_status = any(s == 429 or 500 <= s < 600 for s in statuses)
    return {
        "available": True,
        "usable": stable_status and not unusable_status,
        "error_mode_statuses": sorted(statuses) if unusable_status else [],
        "unusable_reason": (
            "baseline probes were rate-limited or failed server-side" if unusable_status
            else (None if stable_status else "baseline probes returned inconsistent status codes")
        ),
        "origin": origin,
        # Scalar keys kept for compatibility with the older single-sample shape
        # that callers and sibling modules may still supply.
        "status_code": samples[0]["status_code"],
        "content_length": samples[0]["content_length"],
        "body_hash": samples[0]["body_hash"],
        "status_codes": sorted(statuses),
        "dynamic": len({s["body_hash"] for s in samples}) > 1,
        "structural_hashes": sorted({s["structural_hash"] for s in samples}),
        "body_hashes": sorted({s["body_hash"] for s in samples}),
        "content_lengths": sorted({s["content_length"] for s in samples}),
        "normalized_bodies": [s["normalized_body"] for s in samples],
        "location_hashes": sorted({s["location_hash"] for s in samples if s["location_hash"]}),
        "content_types": sorted({s["content_type"] for s in samples if s["content_type"]}),
        "probe_errors": errors,
    }


def matches_catch_all(resp: Dict[str, Any], baseline: Optional[Dict[str, Any]], url: str = "") -> bool:
    """
    True if `resp` looks like the origin's catch-all "nothing here" response.

    Applies at *every* status code, not only 2xx: an origin that redirects
    every unknown path to /login, or that answers 401 to everything, otherwise
    produced one MEDIUM-confidence phantom record per candidate (31 of them in
    the blanket-redirect reproduction).
    """
    if not baseline or not baseline.get("available") or not baseline.get("usable", True):
        return False

    def _multi(plural: str, singular: str) -> set:
        values = baseline.get(plural)
        if values:
            return set(values)
        value = baseline.get(singular)
        return {value} if value is not None else set()

    status = resp.get("status_code")
    if status is None or status not in _multi("status_codes", "status_code"):
        return False

    body = resp.get("body") or ""
    length, digest = _content_signature(body)

    if digest in _multi("body_hashes", "body_hash"):
        return True
    if _structural_signature(body, url) in set(baseline.get("structural_hashes") or []):
        return True

    if status in _REDIRECT_STATUS_CODES:
        location_hashes = set(baseline.get("location_hashes") or [])
        if location_hashes:
            return _normalized_location(resp, url) in location_hashes

    normalized = re.sub(r"\s+", " ", body).strip()
    samples = baseline.get("normalized_bodies") or []
    if samples and _content_matches_samples(normalized, samples):
        return True

    # Length agreement alone is never sufficient — it discards genuine
    # endpoints that merely happen to be about as long as the error page — so
    # it survives only for an externally supplied baseline carrying no body
    # sample, and only for a body too short to carry distinguishing content.
    if not baseline.get("dynamic") and not samples and length <= 64:
        return any(_lengths_close(length, b) for b in _multi("content_lengths", "content_length"))
    return False


_APP_ERROR_STATUS_WORDS = {"error", "fail", "failure", "failed", "ko"}


def detect_application_error(body: Optional[str], content_type: Optional[str] = None) -> Optional[str]:
    """
    Recognise an HTTP 200 that is actually an application-level failure.

    "200 == it exists" is the single most common way an API scanner
    manufactures confidence it has not earned: a great many APIs answer
    `200 {"success": false, "error": "not found"}`. This is deliberately
    *structural* rather than keyword-based — it parses the JSON envelope and
    looks at the fields an envelope uses to report failure — because keyword
    matching on prose ("error" appearing anywhere in an HTML page) produces
    exactly the false positives it is supposed to prevent.

    Returns a short reason string, or None. The endpoint still *exists* (the
    application answered structurally); what it does not support is a HIGH
    confidence claim that the probe succeeded.
    """
    if not body:
        return None
    stripped = body.strip()
    if not stripped:
        return None
    is_jsonish = stripped.startswith("{") or (content_type and "json" in content_type.lower())
    if not is_jsonish:
        return None
    data, _ = safe_json_loads(stripped)
    if not isinstance(data, dict):
        return None

    for key in ("success", "ok", "isSuccess"):
        if data.get(key) is False:
            return f'envelope reports {key}=false'
    status_value = data.get("status")
    if isinstance(status_value, str) and status_value.strip().lower() in _APP_ERROR_STATUS_WORDS:
        return f'envelope reports status={status_value.strip().lower()!r}'
    for key in ("code", "statusCode", "status", "errorCode"):
        value = data.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and 400 <= value < 600:
            return f"envelope carries an application status code of {value}"
    error_value = data.get("error")
    if isinstance(error_value, (str, dict)) and error_value:
        return "envelope carries a non-empty 'error' object"
    errors_value = data.get("errors")
    if isinstance(errors_value, list) and errors_value:
        return "envelope carries a non-empty 'errors' list"
    if isinstance(errors_value, dict) and errors_value:
        return "envelope carries a non-empty 'errors' object"
    return None


def classify_response(
    resp: Dict[str, Any], baseline: Optional[Dict[str, Any]], url: str = "",
) -> Tuple[str, str, List[str]]:
    """
    Classify a fetch_url()-style result into a discovery_type + confidence +
    supporting notes.

    A response only says something about a candidate when it differs from what
    the origin returns for a path that certainly does not exist. Where no
    usable baseline exists that judgement cannot be made, so confidence is
    capped and the reason is stated rather than assumed away.
    """
    status = resp.get("status_code")
    if status is None:
        return DT_ERROR, CONFIDENCE_LOW, ["no status code available (request failed)"]

    baseline_available = bool(baseline and baseline.get("available") and baseline.get("usable", True))
    headers = resp.get("headers") or {}
    retry_after = _ci_get(headers, "Retry-After")

    # Checked first: if the origin hands out this same status to random,
    # certainly-absent paths, the response carries no information about *this*
    # candidate. Blocked is not absent, and it is certainly not present.
    error_mode = set((baseline or {}).get("error_mode_statuses") or [])
    if status in error_mode:
        return DT_BLOCKED, CONFIDENCE_LOW, [
            f"this origin returns HTTP {status} to random, certainly-absent paths as well, "
            f"so the candidate was not effectively tested (blocked, not checked-and-absent)",
        ]

    if matches_catch_all(resp, baseline, url):
        note = (
            f"response matches this origin's catch-all fingerprint (HTTP {status}"
            + (", dynamic body" if baseline and baseline.get("dynamic") else "")
            + "); the candidate is not evidenced as existing"
        )
        if status == 404:
            return DT_NOT_FOUND, CONFIDENCE_HIGH, [note]
        if 200 <= status < 300:
            return DT_POSSIBLE_SOFT_404, CONFIDENCE_LOW, [note]
        return DT_CATCH_ALL_MATCH, CONFIDENCE_LOW, [note]

    if status == 404:
        return DT_NOT_FOUND, CONFIDENCE_HIGH, []

    if status == 429:
        return DT_RATE_LIMITED, CONFIDENCE_LOW, [
            "HTTP 429 Too Many Requests — the server declined to answer, which says nothing "
            "about whether this candidate exists; enumeration is incomplete here"
            + (f" (Retry-After: {retry_after!r})" if retry_after else ""),
        ]

    if status == 503 and retry_after is not None:
        # A 503 *with* Retry-After is a throttle/maintenance signal. A 503
        # without one is far more often a broken backend, and is handled by
        # the 5xx branch below — conflating the two would report an unhealthy
        # host as a rate-limiting one.
        return DT_RATE_LIMITED, CONFIDENCE_LOW, [
            f"HTTP 503 with Retry-After: {retry_after!r} — the server declined to answer; "
            f"this is a refusal, not evidence about the candidate",
        ]

    unbaselined = [] if baseline_available else [
        "no usable catch-all baseline for this origin "
        f"({(baseline or {}).get('unusable_reason') or (baseline or {}).get('probe_errors') or 'baseline responses were unstable'}); "
        "a catch-all response cannot be ruled out, so confidence is capped"
    ]

    if status in _REDIRECT_STATUS_CODES:
        conf = CONFIDENCE_MEDIUM if baseline_available else CONFIDENCE_LOW
        return DT_REDIRECT, conf, [f"HTTP {status} redirect response"] + unbaselined
    if status in (401, 403):
        conf = CONFIDENCE_MEDIUM if baseline_available else CONFIDENCE_LOW
        return DT_ACCESS_RESTRICTED, conf, [
            f"HTTP {status} access-restricted response — something is routed here, but this is "
            f"a challenge from whatever answered (application, gateway or WAF), not proof of an "
            f"application authentication mechanism",
        ] + unbaselined
    if status == 405:
        conf = CONFIDENCE_MEDIUM if baseline_available else CONFIDENCE_LOW
        return DT_METHOD_NOT_ALLOWED, conf, [
            "HTTP 405 Method Not Allowed — the path is routed, but GET is not accepted",
        ] + unbaselined
    if 500 <= status < 600:
        return DT_SERVER_ERROR, CONFIDENCE_LOW, [
            f"HTTP {status} server error — the request failed on the server side; existence is "
            f"uncertain and this is not confirmation the candidate exists",
        ] + unbaselined
    if 200 <= status < 300:
        app_error = detect_application_error(resp.get("body"), _ci_get(headers, "Content-Type"))
        if app_error:
            # The application answered structurally, so something is routed
            # here — but the operation did not succeed, and treating that as
            # HIGH-confidence confirmed content is exactly the "200 means it
            # works" error this classification exists to avoid.
            return DT_CONTENT_APP_ERROR, CONFIDENCE_MEDIUM, [
                f"HTTP {status} carrying an application-level error ({app_error}); the path is "
                f"routed, but the response is a failure, not a successful API operation",
            ] + unbaselined
        if not baseline_available:
            return DT_CONTENT_CONFIRMED, CONFIDENCE_MEDIUM, list(unbaselined)
        if (baseline or {}).get("dynamic"):
            return DT_CONTENT_CONFIRMED, CONFIDENCE_MEDIUM, [
                "this origin returns a different body to each request for a certainly-absent "
                "path, so a dynamic catch-all cannot be fully ruled out",
            ]
        return DT_CONTENT_CONFIRMED, CONFIDENCE_HIGH, []
    return DT_UNEXPECTED, CONFIDENCE_LOW, [f"unexpected HTTP status {status}"] + unbaselined


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
    state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Discover identifiable API versions by probing common path-versioning
    templates for v1..v10 (see module docstring, decision #3), plus the
    unversioned "api/" root. Every candidate that differs from this origin's
    catch-all behaviour is recorded — not only the "current" one.

    Candidates whose response cannot be distinguished from how the origin
    answers a path that certainly does not exist, and candidates the origin
    refused to answer, are deliberately NOT recorded: measured against a
    path-echoing 200 catch-all, and again against a host answering 429 to
    everything, the previous version emitted 31 phantom `api_version_discovered`
    findings in each case.
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    state = state if state is not None else ApiReconState()
    version_range = version_range or DEFAULT_VERSION_RANGE
    baseline = baseline if baseline is not None else _probe_catch_all(origin, timeout, state)

    candidates = [
        (f"v{n}", template.format(n=n))
        for template in VERSION_PATH_TEMPLATES
        for n in version_range
    ]
    candidates.append((None, "api/"))

    identified: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    not_probed: List[str] = []

    for version_label, rel_path in candidates:
        url = _url_for_path(origin, rel_path)
        resp = _budgeted(state, fetch_url, url, timeout=timeout)
        if resp is None:
            not_probed.append(url)
            continue
        if resp["status"] != "found":
            errors.append({"stage": "version_probe", "url": url, "error": resp.get("error")})
            continue

        headers = resp["headers"]
        body = resp.get("body") or ""
        discovery_type, confidence, notes = classify_response(resp, baseline, url)
        _add_observation(observations, {
            "url": url, "headers": headers, "body": body,
            "source": "version_probe", "discovery_type": discovery_type,
        })

        if discovery_type in _UNINFORMATIVE_TYPES:
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
            "basis": "path_probe",
            "relevant_headers": relevant_headers, "content_type": relevant_headers.get("Content-Type"),
            "evidence": [f"GET {url} returned HTTP {resp['status_code']} ({discovery_type})"] + notes,
            "timestamp": _now(),
        }
        identified.append(record)
        err = _safe_store_add(store, make_finding(
            "api_version_discovered", target, dict(record), record["evidence"], confidence,
            metadata={"url": url, "version_label": version_label,
                      "version_string_hint": version_string_hint, "basis": "path_probe"},
        ))
        if err:
            errors.append({"stage": "persistence", "url": url, "error": err})

    return {
        "target": target, "base_url": base_url, "candidates_checked": len(candidates) - len(not_probed),
        "candidates_not_probed": not_probed,
        "versions_identified": identified, "observations": observations, "errors": errors,
        "baseline_usable": bool(baseline and baseline.get("available") and baseline.get("usable", True)),
    }


def discover_declared_api_versions(
    version_records: List[Dict[str, Any]],
    spec_records: Optional[List[Dict[str, Any]]] = None,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
) -> Dict[str, Any]:
    """
    Record versions the target *declared* rather than versions found by
    probing a path template — from an `API-Version`/`X-API-Version` response
    header, or from an OpenAPI/Swagger `info.version` and `servers[].url`.

    This closes half of the "path-versioning only" limitation without adding a
    single request and without any combinatorial candidate generation: it reads
    only what this module already fetched. A declared version is evidence about
    *what the service calls itself*, which is not the same claim as "this
    versioned path responded", so the two are recorded with different `basis`
    values and never merged into one.

    Header/media-type *probing* (sending `Accept: application/vnd.x.v2+json`,
    or `?version=` query candidates, against every discovered endpoint) is
    deliberately not done: it is the combinatorial explosion the audit brief
    warns about, and it is a documented v1 boundary (module docstring, L4).
    """
    declared: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    seen: set = set()
    for r in version_records or []:
        label = _as_text(r.get("version_label")).strip()
        if label:
            seen.add(label.lower())

    def _emit(value: str, basis: str, source_url: Optional[str], evidence: str, confidence: str) -> None:
        value = _as_text(value).strip()[:64]
        if not value or value.lower() in seen:
            return
        seen.add(value.lower())
        record = {
            "url": source_url, "version_label": value, "basis": basis,
            "confidence": confidence, "evidence": [evidence], "timestamp": _now(),
        }
        declared.append(record)
        err = _safe_store_add(store, make_finding(
            # An empty target would make surface_mapper fall back to its own
            # target silently; "unknown" says the producing record had none.
            "api_version_discovered",
            target or (_hostname_of(source_url) if source_url else None) or "unknown", dict(record),
            [evidence], confidence,
            metadata={"url": source_url, "version_label": value, "basis": basis},
        ))
        if err:
            errors.append({"stage": "persistence", "url": source_url, "error": err})

    for r in version_records or []:
        headers = r.get("relevant_headers")
        headers = headers if isinstance(headers, dict) else {}
        for header_name in ("API-Version", "X-API-Version"):
            value = headers.get(header_name)
            if value:
                _emit(value, "declared_response_header", r.get("url"),
                      f"{header_name} response header on {r.get('url')} declares version "
                      f"{_as_text(value).strip()[:64]!r}",
                      CONFIDENCE_MEDIUM)

    for spec in spec_records or []:
        if not isinstance(spec, dict):
            continue
        version = spec.get("version")
        if version:
            _emit(version, "declared_specification", spec.get("url"),
                  f"OpenAPI/Swagger specification at {spec.get('url')} declares "
                  f"info.version {_as_text(version).strip()[:64]!r}",
                  CONFIDENCE_MEDIUM)
        for server_url in (spec.get("servers") or [])[:MAX_SPEC_SERVERS]:
            m = re.search(r"/(v\d+(?:\.\d+)*)(?:/|$)", _as_text(server_url))
            if m:
                _emit(m.group(1), "declared_specification_server", spec.get("url"),
                      f"OpenAPI/Swagger specification at {spec.get('url')} declares a server URL "
                      f"{_as_text(server_url)[:120]!r} carrying version segment {m.group(1)!r}",
                      CONFIDENCE_LOW)

    return {"declared_versions": declared, "errors": errors}


# ---------------------------------------------------------------------------
# 2. Swagger/OpenAPI discovery
# ---------------------------------------------------------------------------

_SPEC_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)


def parse_openapi_spec(
    body: str, content_type: Optional[str], truncated: bool = False,
) -> Dict[str, Any]:
    """
    Parse a fetched body as an OpenAPI/Swagger specification.

    JSON specs are structurally parsed; YAML specs use a best-effort regex
    extraction (see module docstring, decision #1) since no YAML parser is an
    approved dependency. Malformed/unrecognized content degrades to a result
    with `parse_error` set, never raises.

    Bounded by construction rather than by a recursion guard: this parser
    reads `paths[path][method]` and the flat `parameters` list on each
    operation, and **never resolves `$ref`**. That is why the pathological
    documents an OpenAPI parser is normally vulnerable to — circular `$ref`,
    deeply nested `$ref` chains, recursive component schemas — cannot reach it
    at all; there is no traversal to make cyclic. The trade-off is explicit:
    parameters declared only through a `$ref` are counted as unresolved rather
    than followed (`unresolved_refs`), and component schemas are not inspected.
    Breadth is what needs bounding, and it is: MAX_SPEC_PATHS,
    MAX_SPEC_OPERATIONS, MAX_SPEC_PARAMETERS_PER_OPERATION,
    MAX_SPEC_DEPRECATED_OPERATIONS, MAX_SPEC_SECURITY_SCHEMES, MAX_SPEC_SERVERS.

    `truncated=True` (the fetch hit DEFAULT_MAX_BODY_BYTES) is recorded rather
    than hidden: a spec larger than the read cap will almost always fail to
    parse as JSON, and reporting that as an ordinary "invalid JSON" caused a
    genuine, large specification to be dropped from the results entirely.
    """
    result: Dict[str, Any] = {
        "format": None, "spec_type": None, "version": None, "title": None,
        "path_count": None, "security_schemes": [], "parse_error": None,
        "truncated": bool(truncated), "servers": [], "operation_count": None,
        "parameter_count": None, "deprecated_operations": [],
        "unresolved_refs": 0, "limits_hit": [],
    }
    if not body or not body.strip():
        result["parse_error"] = "empty body"
        return result

    stripped = body.strip()
    looks_json = stripped.startswith("{") or (content_type and "json" in content_type.lower())

    if looks_json:
        data, parse_exc = safe_json_loads(stripped)
        if parse_exc is not None:
            exc = parse_exc
            result["parse_error"] = (
                f"body was truncated at the {DEFAULT_MAX_BODY_BYTES}-byte read cap, so the JSON "
                f"is incomplete and could not be parsed ({exc}); the document is a specification "
                f"candidate whose contents are unknown, not an absent one"
                if truncated else f"JSON could not be parsed: {exc}"
            )
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
        result["version"] = info.get("version") if isinstance(info.get("version"), (str, int, float)) else None
        result["title"] = info.get("title") if isinstance(info.get("title"), (str, int, float)) else None

        # servers (OpenAPI 3) / host+basePath (Swagger 2)
        servers: List[str] = []
        if isinstance(data.get("servers"), list):
            for entry in data["servers"][:MAX_SPEC_SERVERS]:
                if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                    servers.append(entry["url"][:300])
        elif isinstance(data.get("host"), str):
            servers.append((data["host"] + _as_text(data.get("basePath") or ""))[:300])
        result["servers"] = servers

        paths = data.get("paths") if isinstance(data.get("paths"), dict) else None
        if paths is not None:
            result["path_count"] = len(paths)
            operation_count = 0
            parameter_count = 0
            unresolved_refs = 0
            deprecated_ops: List[Dict[str, Any]] = []
            for index, (path_key, path_item) in enumerate(paths.items()):
                if index >= MAX_SPEC_PATHS:
                    result["limits_hit"].append(
                        f"only the first {MAX_SPEC_PATHS} of {len(paths)} declared paths were inspected"
                    )
                    break
                if not isinstance(path_item, dict):
                    continue
                for method, operation in path_item.items():
                    if not isinstance(method, str) or method.lower() not in _SPEC_HTTP_METHODS:
                        continue
                    if not isinstance(operation, dict):
                        continue
                    operation_count += 1
                    if operation_count > MAX_SPEC_OPERATIONS:
                        result["limits_hit"].append(
                            f"operation inspection stopped at the {MAX_SPEC_OPERATIONS}-operation cap"
                        )
                        break
                    params = operation.get("parameters")
                    if isinstance(params, list):
                        for param in params[:MAX_SPEC_PARAMETERS_PER_OPERATION]:
                            if isinstance(param, dict) and "$ref" in param:
                                unresolved_refs += 1
                            parameter_count += 1
                        if len(params) > MAX_SPEC_PARAMETERS_PER_OPERATION:
                            result["limits_hit"].append(
                                f"an operation declared more than "
                                f"{MAX_SPEC_PARAMETERS_PER_OPERATION} parameters; the excess was not counted"
                            )
                    if operation.get("deprecated") is True and len(deprecated_ops) < MAX_SPEC_DEPRECATED_OPERATIONS:
                        deprecated_ops.append({
                            "path": _as_text(path_key)[:300],
                            "method": method.upper(),
                            "operation_id": _as_text(operation.get("operationId"))[:120] or None,
                            "summary": _as_text(operation.get("summary"))[:200] or None,
                        })
                else:
                    continue
                break
            result["operation_count"] = operation_count
            result["parameter_count"] = parameter_count
            result["unresolved_refs"] = unresolved_refs
            result["deprecated_operations"] = deprecated_ops
            if len(deprecated_ops) >= MAX_SPEC_DEPRECATED_OPERATIONS:
                result["limits_hit"].append(
                    f"only the first {MAX_SPEC_DEPRECATED_OPERATIONS} deprecated operations were recorded"
                )

        schemes: Dict[str, Any] = {}
        if isinstance(data.get("components"), dict) and isinstance(data["components"].get("securitySchemes"), dict):
            schemes = data["components"]["securitySchemes"]
        elif isinstance(data.get("securityDefinitions"), dict):
            schemes = data["securityDefinitions"]

        for name, scheme in list(schemes.items())[:MAX_SPEC_SECURITY_SCHEMES]:
            if not isinstance(scheme, dict):
                continue
            flows: List[str] = []
            if _as_text(scheme.get("type")).lower() == "oauth2":
                if isinstance(scheme.get("flows"), dict):
                    flows = sorted(str(k) for k in scheme["flows"].keys())
                elif scheme.get("flow"):
                    flows = [_as_text(scheme["flow"])]
            result["security_schemes"].append({
                "name": _as_text(name)[:120], "type": scheme.get("type"), "scheme": scheme.get("scheme"),
                "in": scheme.get("in"), "flows": flows,
            })
        if len(schemes) > MAX_SPEC_SECURITY_SCHEMES:
            result["limits_hit"].append(
                f"only the first {MAX_SPEC_SECURITY_SCHEMES} of {len(schemes)} security schemes were recorded"
            )
        if truncated:
            result["parse_error"] = (
                f"specification parsed, but the body was truncated at the "
                f"{DEFAULT_MAX_BODY_BYTES}-byte read cap — counts and lists below are lower bounds"
            )
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
        result["parse_error"] = (
            "YAML parsed via best-effort regex extraction, not a full YAML parser"
            + (f"; body was also truncated at the {DEFAULT_MAX_BODY_BYTES}-byte read cap" if truncated else "")
        )
        return result

    result["parse_error"] = (
        "content did not match a recognizable OpenAPI/Swagger JSON or YAML structure"
        + (f" (body was truncated at the {DEFAULT_MAX_BODY_BYTES}-byte read cap)" if truncated else "")
    )
    return result


def discover_openapi_specs(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    baseline: Optional[Dict[str, Any]] = None,
    state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Probe the canonical Swagger/OpenAPI spec locations context.md names
    (swagger.json, openapi.yaml, api-docs) plus common variants, at the
    origin root and under an "api/" prefix.
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    state = state if state is not None else ApiReconState()
    baseline = baseline if baseline is not None else _probe_catch_all(origin, timeout, state)

    discovered: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    not_probed: List[str] = []

    for prefix in SPEC_DISCOVERY_PREFIXES:
        root = origin if not prefix else _url_for_path(origin, prefix)
        for rel_path in OPENAPI_SPEC_PATHS:
            url = _url_for_path(root, rel_path)
            resp = _budgeted(state, fetch_url, url, timeout=timeout)
            if resp is None:
                not_probed.append(url)
                continue
            if resp["status"] != "found":
                errors.append({"stage": "spec_probe", "url": url, "error": resp.get("error")})
                continue

            headers = resp["headers"]
            body = resp.get("body") or ""
            discovery_type, _, notes = classify_response(resp, baseline, url)
            _add_observation(observations, {
                "url": url, "headers": headers, "body": body,
                "source": "spec", "discovery_type": discovery_type,
            })
            if discovery_type in _UNINFORMATIVE_TYPES:
                continue

            content_type = _ci_get(headers, "Content-Type")
            is_canonical_path = rel_path in CANONICAL_SPEC_PATHS

            if discovery_type in (DT_CONTENT_CONFIRMED, DT_CONTENT_APP_ERROR):
                parsed = parse_openapi_spec(body, content_type, truncated=bool(resp.get("body_truncated")))
                recognized = parsed["spec_type"] is not None
                # A body cut off at the read cap cannot be recognised as a spec
                # even when it is one. Dropping it — which is what happened
                # before, silently, for every non-canonical path — discards a
                # genuine discovery. It is kept, flagged, and given the
                # confidence its uncertainty deserves.
                if not recognized and resp.get("body_truncated"):
                    record_confidence = CONFIDENCE_LOW
                elif not recognized and not is_canonical_path:
                    continue  # generic 200 unrelated to an API spec — not meaningful evidence
                elif recognized:
                    record_confidence = CONFIDENCE_MEDIUM if discovery_type == DT_CONTENT_APP_ERROR else CONFIDENCE_HIGH
                else:
                    record_confidence = CONFIDENCE_MEDIUM
            elif discovery_type == DT_ACCESS_RESTRICTED and is_canonical_path:
                parsed = parse_openapi_spec("", None)
                parsed["parse_error"] = "endpoint exists but access is restricted"
                record_confidence = CONFIDENCE_MEDIUM
            else:
                continue

            record = {
                "url": url, "path": rel_path, "discovery_type": discovery_type,
                "status_code": resp["status_code"], "content_type": content_type,
                "spec_type": parsed["spec_type"], "format": parsed["format"],
                "version": parsed["version"], "title": parsed["title"],
                "path_count": parsed["path_count"], "security_schemes": parsed["security_schemes"],
                "parse_error": parsed["parse_error"], "truncated": parsed["truncated"],
                "servers": parsed["servers"], "operation_count": parsed["operation_count"],
                "parameter_count": parsed["parameter_count"],
                "deprecated_operations": parsed["deprecated_operations"],
                "unresolved_refs": parsed["unresolved_refs"], "limits_hit": parsed["limits_hit"],
                "evidence": [f"GET {url} returned HTTP {resp['status_code']} ({discovery_type})"] + notes,
                "timestamp": _now(),
            }
            if parsed["limits_hit"]:
                record["evidence"].extend(parsed["limits_hit"])
            discovered.append(record)
            err = _safe_store_add(store, make_finding(
                "api_specification_discovered", target, dict(record), record["evidence"], record_confidence,
                metadata={"url": url, "spec_type": parsed["spec_type"], "version": parsed["version"],
                          "truncated": parsed["truncated"]},
            ))
            if err:
                errors.append({"stage": "persistence", "url": url, "error": err})

    return {
        "target": target, "base_url": base_url, "specs_discovered": discovered,
        "observations": observations, "errors": errors, "candidates_not_probed": not_probed,
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
    state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Probe common human-oriented API documentation surfaces.

    A page is only recorded when its response is distinguishable from how this
    origin answers a certainly-absent path; a documentation marker in the body
    is what separates HIGH from MEDIUM. Without the differential test, a host
    with a 200 catch-all produced a documentation "discovery" for all 14
    candidates.
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    state = state if state is not None else ApiReconState()
    baseline = baseline if baseline is not None else _probe_catch_all(origin, timeout, state)

    discovered: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    not_probed: List[str] = []

    for prefix in SPEC_DISCOVERY_PREFIXES:
        root = origin if not prefix else _url_for_path(origin, prefix)
        for rel_path in DOCUMENTATION_PATHS:
            url = _url_for_path(root, rel_path)
            resp = _budgeted(state, fetch_url, url, timeout=timeout)
            if resp is None:
                not_probed.append(url)
                continue
            if resp["status"] != "found":
                errors.append({"stage": "doc_probe", "url": url, "error": resp.get("error")})
                continue

            headers = resp["headers"]
            body = resp.get("body") or ""
            discovery_type, _, notes = classify_response(resp, baseline, url)
            _add_observation(observations, {
                "url": url, "headers": headers, "body": body,
                "source": "doc_page", "discovery_type": discovery_type,
            })
            if discovery_type in _UNINFORMATIVE_TYPES:
                continue

            if discovery_type in (DT_CONTENT_CONFIRMED, DT_CONTENT_APP_ERROR):
                markers_found = sorted(set(m.lower() for m in DOC_MARKERS_RE.findall(body)))
                if markers_found:
                    confidence = CONFIDENCE_HIGH if discovery_type == DT_CONTENT_CONFIRMED else CONFIDENCE_MEDIUM
                else:
                    confidence = CONFIDENCE_MEDIUM if discovery_type == DT_CONTENT_CONFIRMED else CONFIDENCE_LOW
            elif discovery_type == DT_ACCESS_RESTRICTED:
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
        "observations": observations, "errors": errors, "candidates_not_probed": not_probed,
    }


# ---------------------------------------------------------------------------
# 3. GraphQL detection
# ---------------------------------------------------------------------------

# A GraphQL server rejecting a malformed request says something specific. The
# previous heuristic accepted any error message containing "graphql", "query"
# or "schema", which a plain REST API answering
# {"errors":[{"message":"Invalid query parameter \'q\'"}]} satisfies — measured:
# all 5 probed paths on a non-GraphQL host were recorded as
# MEDIUM-confidence GraphQL endpoints, and each then received an introspection
# POST it should never have received.
_GRAPHQL_ERROR_PHRASE_RE = re.compile(
    r"must provide (?:a )?query|cannot query field|graphql|syntax error|"
    r"unknown operation|operation name|no operations? (?:defined|found)|"
    r"query (?:is )?(?:required|not provided)|expected name|"
    r"field .{0,80} doesn't exist|unknown argument",
    re.IGNORECASE,
)


def _graphql_error_signal(data: Any) -> Optional[str]:
    """
    Whether a JSON body is a GraphQL *error* envelope, as opposed to any API
    that happens to answer with an "errors" key.

    Three independent signals, any of which is specific to GraphQL:
      * the spec-mandated response shape (`data` present alongside `errors`),
      * an error object carrying `locations`/`path`/`extensions` (GraphQL
        error fields; a REST envelope has no reason to emit them), or
      * an error message using GraphQL's own vocabulary.

    Returns a short description of the signal, or None.
    """
    if not isinstance(data, dict):
        return None
    errors = data.get("errors")
    # Only a list of error objects is the GraphQL shape. Iterating whatever
    # happened to be under "errors" raised TypeError on an int and aborted the
    # whole detection stage.
    if not isinstance(errors, list) or not errors:
        return None

    if "data" in data:
        return "response carries both 'data' and 'errors', the GraphQL response shape"
    for entry in errors:
        if isinstance(entry, dict) and any(k in entry for k in ("locations", "path", "extensions")):
            return "error object carries GraphQL error fields (locations/path/extensions)"
    messages = " ".join(
        _as_text(e.get("message")) for e in errors if isinstance(e, dict)
    )[:2000]
    if messages and _GRAPHQL_ERROR_PHRASE_RE.search(messages):
        return f"error message uses GraphQL vocabulary: {messages[:200]!r}"
    return None


def _graphql_error_messages(data: Any) -> str:
    """Join the error messages of a GraphQL-shaped envelope, bounded."""
    if not isinstance(data, dict) or not isinstance(data.get("errors"), list):
        return ""
    return " ".join(
        _as_text(e.get("message")) for e in data["errors"] if isinstance(e, dict)
    )[:2000]


def detect_graphql_endpoints(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    baseline: Optional[Dict[str, Any]] = None,
    state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Detect GraphQL endpoints at common paths using a GET heuristic and a
    minimal, read-only `{ __typename }` POST confirmation probe (never a
    mutation).
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    state = state if state is not None else ApiReconState()
    baseline = baseline if baseline is not None else _probe_catch_all(origin, timeout, state)

    detected: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    not_probed: List[str] = []

    for rel_path in GRAPHQL_PATHS:
        url = _url_for_path(origin, rel_path)

        get_resp = _budgeted(state, fetch_url, url, timeout=timeout)
        get_discovery_type = None
        if get_resp is None:
            not_probed.append(url)
            continue
        if get_resp["status"] == "found":
            get_discovery_type, _, _ = classify_response(get_resp, baseline, url)
            _add_observation(observations, {
                "url": url, "headers": get_resp["headers"],
                "body": get_resp.get("body") or "", "source": "graphql_get",
                "discovery_type": get_discovery_type,
            })
        else:
            errors.append({"stage": "graphql_get", "url": url, "error": get_resp.get("error")})

        post_resp = _budgeted(
            state, fetch_url_post, url, json_body=GRAPHQL_TYPENAME_QUERY, timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        if post_resp is None:
            not_probed.append(url)
            continue
        confirmed_via = None
        confidence = None
        evidence: List[str] = []

        if post_resp["status"] == "found":
            post_body = post_resp.get("body") or ""
            post_discovery_type, _, _ = classify_response(post_resp, baseline, url)
            _add_observation(observations, {
                "url": url, "headers": post_resp["headers"], "body": post_body,
                "source": "graphql_post", "discovery_type": post_discovery_type,
            })
            data, _ = safe_json_loads(post_body)

            if (
                isinstance(data, dict) and isinstance(data.get("data"), dict)
                and isinstance(data["data"].get("__typename"), str)
            ):
                confirmed_via, confidence = "post_typename_probe", CONFIDENCE_HIGH
                evidence.append(
                    f'POST {url} with a read-only "{{ __typename }}" probe returned a '
                    f'GraphQL-shaped {{"data": {{"__typename": ...}}}} response'
                )
            else:
                signal = _graphql_error_signal(data)
                if signal:
                    confirmed_via, confidence = "post_graphql_error_envelope", CONFIDENCE_MEDIUM
                    evidence.append(f"POST {url} returned a GraphQL error envelope: {signal}")
        else:
            errors.append({"stage": "graphql_post", "url": url, "error": post_resp.get("error")})

        if confidence is None and get_discovery_type is not None and get_discovery_type not in _UNINFORMATIVE_TYPES:
            get_body = get_resp.get("body") or ""
            content_type = _ci_get(get_resp["headers"], "Content-Type") or ""
            if GRAPHQL_WEAK_RE.search(get_body) or "graphql" in content_type.lower():
                confirmed_via, confidence = "get_heuristic", CONFIDENCE_LOW
                evidence.append(
                    f"GET {url} content/content-type weakly suggests a GraphQL endpoint; the "
                    f"read-only {{ __typename }} probe did not confirm it, so this is a "
                    f"suggestion, not a confirmed GraphQL endpoint"
                )

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
        "observations": observations, "errors": errors, "candidates_not_probed": not_probed,
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
    state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Run a bounded, read-only introspection query (module docstring,
    decision #4) against a GraphQL endpoint already confirmed in-scope.
    `enabled=False` lets a caller/orchestrator opt out even within scope.
    """
    url = validate_api_target(url, target=target)
    if not enabled:
        return {"url": url, "status": "skipped", "reason": "GraphQL introspection disabled by caller"}

    resp = _budgeted(
        state, fetch_url_post, url, json_body={"query": INTROSPECTION_QUERY}, timeout=timeout,
        headers={"Content-Type": "application/json"},
    )
    if resp is None:
        return {"url": url, "status": "not_probed",
                "reason": "request budget exhausted or run stopped before introspection"}
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}

    body = resp.get("body") or ""
    data, exc = safe_json_loads(body)
    if exc is not None:
        # A schema larger than the read cap lands here. Saying so is the
        # difference between "this endpoint answered with garbage" and "the
        # schema is bigger than we are willing to read".
        return {
            "url": url, "status": "error",
            "error": (
                f"introspection response was truncated at the {DEFAULT_MAX_BODY_BYTES}-byte read "
                f"cap and could not be parsed ({exc}); the schema is larger than this module reads"
                if resp.get("body_truncated") else f"non-JSON introspection response: {exc}"
            ),
            "body_truncated": bool(resp.get("body_truncated")),
        }
    if not isinstance(data, dict):
        return {"url": url, "status": "error", "error": "introspection response JSON root is not an object"}

    schema = None
    if isinstance(data.get("data"), dict):
        schema = data["data"].get("__schema")

    if not isinstance(schema, dict):
        if isinstance(data.get("errors"), list) and data["errors"]:
            messages = _graphql_error_messages(data)
            evidence = [
                f"Introspection query against {url} was rejected: {messages[:200]!r}",
                "introspection being disabled is a server configuration observation, not a "
                "vulnerability and not proof that no schema exists",
            ]
            err = _safe_store_add(store, make_finding(
                "graphql_introspection_disabled", target or url, {"url": url, "messages": messages},
                evidence, CONFIDENCE_MEDIUM, metadata={"url": url},
            ))
            result = {"url": url, "status": "disabled", "messages": messages}
            if err:
                result["persistence_error"] = err
            return result
        return {"url": url, "status": "error", "error": "introspection response did not contain __schema"}

    def _type_name(entry: Any) -> Optional[str]:
        return entry.get("name") if isinstance(entry, dict) and isinstance(entry.get("name"), str) else None

    query_type = _type_name(schema.get("queryType"))
    mutation_type = _type_name(schema.get("mutationType"))
    subscription_type = _type_name(schema.get("subscriptionType"))
    types = schema.get("types") if isinstance(schema.get("types"), list) else []

    field_map: Dict[str, List[str]] = {}
    type_names: List[str] = []
    for t in types:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str) or not t["name"]:
            continue
        name = t["name"]
        type_names.append(name)
        fields = t.get("fields") if isinstance(t.get("fields"), list) else []
        field_map[name] = [
            f["name"] for f in fields if isinstance(f, dict) and isinstance(f.get("name"), str)
        ]

    type_names = sorted(set(type_names))
    query_fields = sorted(field_map.get(query_type, [])) if query_type else []
    mutation_fields = sorted(field_map.get(mutation_type, [])) if mutation_type else []

    # Truncation was previously silent: a 1000-type schema was reported with
    # type_count=1000 and exactly 300 names, with nothing saying the list was
    # cut. A downstream consumer reading the list as the schema would be wrong
    # and have no way to know it.
    names_truncated = {
        key: total for key, total in (
            ("type_names", len(type_names)),
            ("query_fields", len(query_fields)),
            ("mutation_fields", len(mutation_fields)),
        ) if total > MAX_INTROSPECTION_NAMES
    }

    result = {
        "url": url, "status": "introspected", "query_type": query_type,
        "mutation_type": mutation_type, "subscription_type": subscription_type,
        "type_count": len(type_names), "type_names": type_names[:MAX_INTROSPECTION_NAMES],
        "query_fields": query_fields[:MAX_INTROSPECTION_NAMES],
        "mutation_fields": mutation_fields[:MAX_INTROSPECTION_NAMES],
        "names_truncated": names_truncated,
        "name_cap": MAX_INTROSPECTION_NAMES,
        "body_truncated": bool(resp.get("body_truncated")),
        "timestamp": _now(),
    }
    evidence = [
        f"Introspection query against {url} succeeded: {len(type_names)} type(s), "
        f"query type {query_type!r}, mutation type {mutation_type!r}"
    ]
    if names_truncated:
        evidence.append(
            "name lists were capped at "
            f"{MAX_INTROSPECTION_NAMES} entries ({names_truncated}); the recorded lists are "
            f"partial, not the complete schema"
        )
    if resp.get("body_truncated"):
        evidence.append(
            f"the introspection response was truncated at the {DEFAULT_MAX_BODY_BYTES}-byte read "
            f"cap, so the schema below is partial"
        )
    err = _safe_store_add(store, make_finding(
        "graphql_schema_introspected", target or url, dict(result), evidence, CONFIDENCE_HIGH,
        metadata={"url": url, "type_count": len(type_names), "partial": bool(names_truncated or resp.get("body_truncated"))},
    ))
    if err:
        result["persistence_error"] = err
    return result


def mine_graphql_field_suggestions(
    url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Recover a *partial, inferred* view of a schema whose introspection is
    disabled, from the server's own "Did you mean ...?" suggestions.

    Exactly one read-only query is sent, naming one field that deliberately
    does not exist. Whatever the server volunteers in reply is parsed. This is
    not fuzzing: no field name is guessed, iterated, or tried in sequence, and
    no mutation is ever constructed. Bounded at one request and
    MAX_GRAPHQL_SUGGESTIONS names.

    The result is explicitly inferred, LOW confidence, and never described as
    a schema: a suggestion list is what the server was willing to hint at, not
    an enumeration of the schema's root fields. Full schema inference from
    error behaviour is a documented v2 boundary (module docstring, L3).
    """
    url = validate_api_target(url, target=target)
    resp = _budgeted(
        state, fetch_url_post, url, json_body=GRAPHQL_SUGGESTION_PROBE, timeout=timeout,
        headers={"Content-Type": "application/json"},
    )
    if resp is None:
        return {"url": url, "status": "not_probed",
                "reason": "request budget exhausted or run stopped before suggestion probe"}
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}

    data, exc = safe_json_loads(resp.get("body"))
    if exc is not None:
        return {"url": url, "status": "error", "error": f"non-JSON suggestion response: {exc}"}

    messages = _graphql_error_messages(data)
    if not messages:
        return {"url": url, "status": "no_suggestions",
                "reason": "the endpoint did not return a GraphQL error envelope for the probe"}

    suggestions: List[str] = []
    for block in _GRAPHQL_SUGGESTION_RE.findall(messages):
        for name in _GRAPHQL_SUGGESTION_ITEM_RE.findall(block):
            if name not in suggestions:
                suggestions.append(name)
            if len(suggestions) >= MAX_GRAPHQL_SUGGESTIONS:
                break
        if len(suggestions) >= MAX_GRAPHQL_SUGGESTIONS:
            break

    result = {
        "url": url,
        "status": "suggestions_found" if suggestions else "no_suggestions",
        "suggested_field_names": suggestions,
        "suggestion_cap": MAX_GRAPHQL_SUGGESTIONS,
        "error_message_excerpt": messages[:400],
        "timestamp": _now(),
    }
    if not suggestions:
        return result

    evidence = [
        f"POST {url} with a single read-only query naming one non-existent field returned "
        f"{len(suggestions)} server-volunteered field-name suggestion(s)",
        "these names are INFERRED from the server's own error message, not introspected; they "
        "are not a schema, not necessarily complete, and not necessarily queryable",
    ]
    err = _safe_store_add(store, make_finding(
        "graphql_schema_suggestions_inferred", target or url, dict(result), evidence, CONFIDENCE_LOW,
        metadata={"url": url, "suggestion_count": len(suggestions), "basis": "error_message_suggestion"},
    ))
    if err:
        result["persistence_error"] = err
    return result


# ---------------------------------------------------------------------------
# 5. REST vs GraphQL vs gRPC detection
# ---------------------------------------------------------------------------

def classify_api_protocol(
    url: str, headers: Optional[Dict[str, str]], body: Optional[str] = None,
    graphql_confirmed: bool = False,
) -> Dict[str, Any]:
    """
    Classify observed protocol signals for one URL. Multiple protocols may be
    reported for the same URL/surface rather than forcing a single label (see
    module docstring) — this is an evidence list, not a verdict.

    gRPC support here is *detection over HTTP/1.1 only*. A native HTTP/2 gRPC
    service cannot be spoken to by this module at all, so what is detectable is
    an explicit application/grpc content type, a gRPC-Web endpoint, or grpc-*
    trailers a proxy has surfaced as headers. That boundary is stated in the
    evidence rather than left for a reader to assume, because "gRPC not
    detected" here does not mean "no gRPC service is present".
    """
    headers = headers if isinstance(headers, dict) else {}
    content_type = _ci_get(headers, "Content-Type") or ""
    try:
        path = urllib.parse.urlsplit(_as_text(url)).path.lower()
    except ValueError:
        path = ""
    protocols: List[Dict[str, str]] = []
    evidence: List[str] = []

    graphql_content_type = "graphql" in content_type.lower()
    path_hint = "/graphql" in path
    if graphql_confirmed or graphql_content_type:
        confidence = CONFIDENCE_HIGH if graphql_confirmed else CONFIDENCE_MEDIUM
        protocols.append({"protocol": "graphql", "confidence": confidence})
        evidence.append(
            "endpoint confirmed by a read-only { __typename } probe" if graphql_confirmed
            else f"GraphQL content-type observed: {content_type!r}"
        )
    elif path_hint:
        # A URL containing "/graphql" is a naming convention, not an observed
        # protocol signal. Treating it as one produced a "graphql" verdict for
        # every 404 at /graphql on a catch-all host — including runs that
        # simultaneously reported "no API surface found". It is kept as a hint
        # in the evidence and deliberately does not create a protocol entry.
        evidence.append(
            f"URL path contains '/graphql', a naming convention only — no GraphQL response "
            f"signal was observed here and the read-only {{ __typename }} probe did not confirm it"
        )

    grpc_content_type = bool(GRPC_CONTENT_TYPE_RE.search(content_type))
    grpc_headers = [h for h in GRPC_HEADER_NAMES if _ci_get(headers, h) is not None]
    if grpc_content_type or grpc_headers:
        confidence = CONFIDENCE_HIGH if grpc_content_type else CONFIDENCE_MEDIUM
        protocols.append({"protocol": "grpc", "confidence": confidence})
        evidence.append(
            (f"gRPC content-type observed: {content_type!r}" if grpc_content_type
             else f"gRPC header(s) observed: {grpc_headers}")
            + " — detected over HTTP/1.1; no HTTP/2 or Protobuf negotiation was attempted and "
              "server reflection was not queried"
        )

    if not protocols and "json" in content_type.lower() and "/api" in path:
        protocols.append({"protocol": "rest", "confidence": CONFIDENCE_MEDIUM})
        evidence.append("JSON response under an /api path — consistent with a REST-style API")

    if not protocols:
        protocols.append({"protocol": "unknown", "confidence": CONFIDENCE_LOW})
        evidence.append(
            "no distinguishing REST/GraphQL/gRPC signal observed over HTTP/1.1 (absence of a "
            "signal is not evidence that no such API exists here)"
        )

    return {"url": url, "protocols": protocols, "evidence": evidence}


def _named_protocols(classification: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The protocol entries that constitute an actual observation ("unknown" is not one)."""
    protocols = (classification or {}).get("protocols") or []
    return [p for p in protocols if isinstance(p, dict) and p.get("protocol") != "unknown"]


def persist_protocol_classification(
    classification: Dict[str, Any],
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
) -> Optional[str]:
    """
    Persist one protocol classification as a finding.

    context.md names "REST vs GraphQL vs gRPC detection" as one of this
    module's responsibilities, and its output is meant to reach
    surface_mapper.py. It previously existed only in the returned summary and
    never became a finding at all, so nothing downstream ever saw it. Only
    classifications carrying an actual signal are persisted — an "unknown"
    verdict is the absence of evidence and is kept in the summary rather than
    written into the shared asset store as if it were a discovery.

    Returns a persistence error message, or None.
    """
    named = _named_protocols(classification)
    if not named:
        return None
    confidence = CONFIDENCE_LOW
    for level in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM):
        if any(p.get("confidence") == level for p in named):
            confidence = level
            break
    return _safe_store_add(store, make_finding(
        "api_protocol_observed", target or _as_text(classification.get("url")),
        dict(classification), list(classification.get("evidence") or []), confidence,
        metadata={"url": classification.get("url"),
                  "protocols": sorted({_as_text(p.get("protocol")) for p in named})},
    ))


# ---------------------------------------------------------------------------
# 7. Deprecated API endpoint detection
# ---------------------------------------------------------------------------

def detect_deprecated_endpoints(
    version_records: List[Dict[str, Any]],
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    spec_records: Optional[List[Dict[str, Any]]] = None,
    live_urls: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Flag deprecated endpoints across three bases, each carrying its own
    confidence and each explicitly labelled:

      * `specification_declared` (HIGH) — an OpenAPI/Swagger operation carries
        `deprecated: true`. This is the canonical source and was not consulted
        at all before, even though this module already fetched and parsed the
        specifications it lives in.
      * `explicit_header` (HIGH) — a Deprecation/Sunset header, or a Warning
        header mentioning deprecation, was observed on a live response.
      * `inferred_older_version` (LOW) — an older numeric version coexists with
        a newer one this run identified. A heuristic, never a server statement.

    **Deprecated is a lifecycle declaration, not a statement that the endpoint
    is inactive.** A deprecated endpoint is very often fully operational, and
    frequently the more interesting one. Every record therefore carries
    `runtime_state`, derived from what this run actually observed — never from
    the deprecation flag — and no record asserts that a deprecated endpoint is
    gone. No state-changing request is ever sent to "verify" a deprecated
    endpoint; runtime state comes only from responses this module already has.
    """
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    numeric_versions: Dict[int, List[Dict[str, Any]]] = {}
    live_urls = set(live_urls or ())

    version_records = [r for r in (version_records or []) if isinstance(r, dict)]

    _LIFECYCLE_NOTE = (
        "'deprecated' is a lifecycle declaration about support, not a statement that the "
        "endpoint is inactive: a deprecated endpoint is frequently still fully operational"
    )

    def _emit(record: Dict[str, Any], evidence: List[str], confidence: str) -> None:
        results.append(record)
        err = _safe_store_add(store, make_finding(
            "api_endpoint_deprecated", target or _as_text(record.get("url")), dict(record),
            evidence, confidence,
            metadata={"url": record.get("url"), "basis": record.get("basis"),
                      "runtime_state": record.get("runtime_state")},
        ))
        if err:
            errors.append({"stage": "persistence", "url": record.get("url"), "error": err})

    # --- specification-declared -------------------------------------------
    for spec in spec_records or []:
        if not isinstance(spec, dict):
            continue
        spec_url = _as_text(spec.get("url"))
        for operation in (spec.get("deprecated_operations") or [])[:MAX_SPEC_DEPRECATED_OPERATIONS]:
            if not isinstance(operation, dict):
                continue
            op_path = _as_text(operation.get("path"))
            method = _as_text(operation.get("method")) or "?"
            try:
                op_url = urllib.parse.urljoin(spec_url, op_path) if spec_url and op_path else op_path
            except ValueError:
                op_url = op_path
            evidence = [
                f"OpenAPI/Swagger specification at {spec_url} declares operation "
                f"{method} {op_path} as deprecated: true",
                _LIFECYCLE_NOTE,
                "declared in a specification document; this run did not probe the operation, so "
                "its runtime state is unverified",
            ]
            _emit({
                "url": op_url or None, "spec_url": spec_url, "path": op_path, "method": method,
                "operation_id": operation.get("operation_id"),
                "version_label": None, "basis": "specification_declared",
                "confidence": CONFIDENCE_HIGH, "runtime_state": "unverified",
                "evidence": evidence,
            }, evidence, CONFIDENCE_HIGH)

    # --- numeric version index --------------------------------------------
    # Only versions that actually *answered* may set the "newest version"
    # watermark. Found in end-to-end testing: /api/v3/ replied
    # `200 {"success": false, "error": "v3 is not yet available"}`, which is
    # correctly recorded as routed surface — but treating it as the newest
    # live version then marked the genuinely current v2 as
    # "inferred_older_version". A version the application itself says is not
    # available cannot be evidence that an older one is superseded. Such
    # records are still eligible to *be* flagged; they just cannot do the
    # flagging.
    for r in version_records:
        label = _as_text(r.get("version_label"))
        if not label:
            continue
        m = re.search(r"(\d+)", label)
        if not m:
            continue
        entry = numeric_versions.setdefault(int(m.group(1)), {"live": [], "all": []})
        entry["all"].append(r)
        # A record carrying no discovery_type at all comes from a caller that
        # did not qualify it; it is taken at face value, exactly as before.
        # Only an explicitly unsuccessful response is disqualified.
        if r.get("discovery_type") not in _NOT_SUCCESSFULLY_ANSWERED:
            entry["live"].append(r)

    # --- explicit response headers ----------------------------------------
    explicit_flagged_urls = set()
    for r in version_records:
        headers = r.get("relevant_headers")
        headers = headers if isinstance(headers, dict) else {}
        deprecation = headers.get("Deprecation")
        sunset = headers.get("Sunset")
        warning = _as_text(headers.get("Warning"))
        if not (deprecation or sunset or "deprecat" in warning.lower()):
            continue

        evidence = []
        if deprecation:
            evidence.append(f"Deprecation header present: {deprecation!r}")
        if sunset:
            evidence.append(f"Sunset header present: {sunset!r}")
        if "deprecat" in warning.lower():
            evidence.append(f"Warning header mentions deprecation: {warning!r}")
        evidence.append(_LIFECYCLE_NOTE)

        url = r.get("url")
        # The header came from a response this run received, so the endpoint
        # was demonstrably answering at that moment. That is the whole point of
        # recording runtime state separately from the deprecation flag.
        runtime_state = "responding" if r.get("discovery_type") not in _UNINFORMATIVE_TYPES else "unverified"
        if runtime_state == "responding":
            evidence.append(
                f"observed responding in this run: GET {url} returned HTTP {r.get('status_code')} "
                f"({r.get('discovery_type')}) while advertising deprecation"
            )
        record = {
            "url": url, "version_label": r.get("version_label"), "basis": "explicit_header",
            "confidence": CONFIDENCE_HIGH, "runtime_state": runtime_state, "evidence": evidence,
        }
        if url is not None:
            explicit_flagged_urls.add(url)
        _emit(record, evidence, CONFIDENCE_HIGH)

    # --- inferred from version coexistence --------------------------------
    live_versions = [n for n, entry in numeric_versions.items() if entry["live"]]
    max_version = max(live_versions) if live_versions else None
    if max_version is not None:
        for version_num, entry in numeric_versions.items():
            if version_num >= max_version:
                continue
            for r in entry["all"]:
                url = r.get("url")
                if url is not None and url in explicit_flagged_urls:
                    continue
                evidence = [
                    f"Version {r.get('version_label')} coexists with a newer version v{max_version} "
                    f"that this run observed responding successfully; older API versions are "
                    f"commonly, but not always, deprecated — this is an inference, not a confirmed "
                    f"deprecation and not a server statement",
                    _LIFECYCLE_NOTE,
                ]
                runtime_state = "responding" if r.get("discovery_type") not in _UNINFORMATIVE_TYPES else "unverified"
                record = {
                    "url": url, "version_label": r.get("version_label"),
                    "basis": "inferred_older_version", "confidence": CONFIDENCE_LOW,
                    "runtime_state": runtime_state, "evidence": evidence,
                }
                _emit(record, evidence, CONFIDENCE_LOW)

    return {"deprecated_endpoints": results, "errors": errors}


# ---------------------------------------------------------------------------
# 8. HTTP method discovery (OPTIONS + safe HEAD fallback only — no
# state-changing verb is ever sent; see module docstring)
# ---------------------------------------------------------------------------

def _parse_allow_header(allow_header: Optional[str]) -> Tuple[List[str], List[str]]:
    """
    Parse an Allow header into a clean, bounded method list.

    A hostile or broken server can send anything here; measured, a header of
    5000 comma-separated tokens produced a 5000-entry "methods" list that was
    persisted verbatim into the shared asset store. Entries are trimmed,
    upper-cased, de-duplicated, checked against the RFC 9110 token grammar,
    and capped. Rejected entries are returned separately rather than dropped
    silently, so the record can say the header was malformed.
    """
    if not allow_header:
        return [], []
    methods: List[str] = []
    rejected: List[str] = []
    for raw in _as_text(allow_header).split(","):
        token = raw.strip()
        if not token:
            continue
        if not _HTTP_METHOD_TOKEN_RE.match(token):
            if len(rejected) < 10:
                rejected.append(token[:40])
            continue
        upper = token.upper()
        if upper not in methods:
            methods.append(upper)
        if len(methods) >= MAX_ALLOW_METHODS:
            rejected.append(f"... Allow header capped at {MAX_ALLOW_METHODS} methods")
            break
    return methods, rejected


def discover_http_methods(
    url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Discover which HTTP methods a discovered API endpoint advertises, via
    OPTIONS plus a safe HEAD fallback. No state-changing verb is ever sent to
    probe support — this discovers method *signalling*, it never exercises the
    methods it finds.
    """
    url = validate_api_target(url, target=target)
    resp = _budgeted(state, fetch_url_options, url, timeout=timeout)
    if resp is None:
        return {"url": url, "status": "not_probed",
                "reason": "request budget exhausted or run stopped before OPTIONS probe"}
    if resp["status"] != "found":
        return {"url": url, "status": "error", "error": resp.get("error")}

    status_code = resp["status_code"]
    allow_header = _ci_get(resp["headers"], "Allow")
    methods, rejected_tokens = _parse_allow_header(allow_header)
    retry_after = _ci_get(resp["headers"], "Retry-After")

    if status_code == 404:
        return {"url": url, "status": "found", "discovery_type": DT_NOT_FOUND, "methods": [], "evidence": []}

    if status_code == 429 or (status_code == 503 and retry_after is not None):
        # A refusal says nothing about which methods the endpoint supports,
        # and recording one as an "unexpected status" discovery turned a
        # throttled request into a persisted finding.
        return {
            "url": url, "status": "found", "discovery_type": DT_RATE_LIMITED, "methods": [],
            "evidence": [f"OPTIONS {url} was refused with HTTP {status_code}"
                         + (f" (Retry-After: {retry_after!r})" if retry_after else "")
                         + "; method support was not determined"],
        }

    if methods:
        discovery_type, confidence = "options_supported", CONFIDENCE_HIGH
        evidence = [f"OPTIONS {url} returned HTTP {status_code} with Allow: {allow_header!r}"]
    elif allow_header:
        discovery_type, confidence = "options_response_no_allow_header", CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned HTTP {status_code} with an unparseable Allow header: "
                    f"{_as_text(allow_header)[:120]!r}"]
    elif status_code in (200, 204):
        discovery_type, confidence = "options_response_no_allow_header", CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned HTTP {status_code} without an Allow header"]
    elif status_code in (401, 403):
        discovery_type, confidence = DT_ACCESS_RESTRICTED, CONFIDENCE_MEDIUM
        evidence = [f"OPTIONS {url} returned HTTP {status_code}"]
    elif status_code == 405:
        discovery_type, confidence = DT_METHOD_NOT_ALLOWED, CONFIDENCE_MEDIUM
        evidence = [f"OPTIONS {url} returned HTTP 405 — OPTIONS itself is not permitted here"]
    else:
        discovery_type, confidence = DT_UNEXPECTED, CONFIDENCE_LOW
        evidence = [f"OPTIONS {url} returned unexpected HTTP {status_code}"]

    if rejected_tokens:
        evidence.append(f"Allow header contained entries that are not valid HTTP method tokens: {rejected_tokens}")

    if not methods and discovery_type in (DT_ACCESS_RESTRICTED, DT_METHOD_NOT_ALLOWED, "options_response_no_allow_header"):
        head_resp = _budgeted(state, fetch_url_head, url, timeout=timeout)
        if head_resp is None:
            evidence.append("HEAD fallback not sent (request budget exhausted or run stopped)")
        elif head_resp["status"] == "found" and head_resp.get("status_code") is not None and head_resp["status_code"] < 400:
            methods = ["GET"]
            evidence.append(
                f"HEAD {url} returned HTTP {head_resp['status_code']} — GET support inferred "
                f"(safe fallback probe; no state-changing verb attempted)"
            )

    record = {
        "url": url, "discovery_type": discovery_type, "status_code": status_code,
        "allow_header": _as_text(allow_header)[:512] if allow_header else None,
        "methods": methods, "confidence": confidence,
        "evidence": evidence, "timestamp": _now(),
        "note": "Only OPTIONS and a safe HEAD fallback are used; no state-changing verb is ever "
                "sent to probe support, and an advertised method is what the server signals, not "
                "a method this module exercised.",
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

def _b64url_decode(segment: str) -> Optional[bytes]:
    import base64
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return None


def _clip_claim(value: Any) -> Any:
    """Bound one decoded claim so a hostile token cannot inflate a finding."""
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_JWT_CLAIM_CHARS]
    if isinstance(value, (list, tuple)):
        return [_clip_claim(v) for v in list(value)[:MAX_JWT_LIST_CLAIM_ITEMS]]
    if isinstance(value, dict):
        return {str(k)[:64]: _clip_claim(v) for k, v in list(value.items())[:MAX_JWT_LIST_CLAIM_ITEMS]}
    return _as_text(value)[:MAX_JWT_CLAIM_CHARS]


# Registered/common claims that are API *intelligence* — who issues tokens,
# for which audience, with what lifetime, under which tenant, carrying which
# coarse authorisation labels. Deliberately an allow-list: a JWT payload can
# carry anything, including personal data, and copying it wholesale into a
# plain-text file shared with every other module is not acceptable.
_JWT_INTEL_CLAIMS = [
    "iss", "aud", "sub", "exp", "iat", "nbf", "jti", "azp", "client_id",
    "scope", "scp", "roles", "role", "permissions", "groups",
    "tid", "tenant", "tenant_id", "org", "org_id", "realm",
]


def _decode_jwt_intelligence(token: str) -> Dict[str, Any]:
    """
    Decode (never verify) a JWT-shaped string into bounded intelligence.

    JWTs are base64url-encoded, not encrypted, so no key or secret is required
    and nothing here is a cryptographic attack. What is extracted is the
    declared header (`alg`/`typ`/`kid`) and an allow-listed subset of payload
    claims: issuer, audience, subject, lifetime, tenant identifiers and coarse
    authorisation labels.

    What this deliberately does NOT do, and must never do:

      * verify, crack, brute-force or otherwise attack the signature,
      * forge or modify a token, or replay one anywhere,
      * treat `alg: none` as proof the server accepts unsigned tokens — it is
        a declaration *inside a token this module merely observed*, and says
        nothing about what the server would accept,
      * treat HS256 as inherently weak — it is a standard, correct algorithm
        whose safety depends on a secret this module does not have and does
        not try to obtain,
      * assign severity. `signature_verified` is always False and stated as
        such; risk_engine.py owns prioritisation.

    The raw token is never persisted; only a short preview is kept.
    """
    entry: Dict[str, Any] = {
        "token_preview": (token[:12] + "..." + token[-6:]) if len(token) > 24 else "***",
        "alg": None, "typ": None, "kid": None,
        "claims": {}, "claims_decoded": False,
        "signature_verified": False,
        "note": "decoded, not verified — no signature check, no secret recovery, no token was "
                "modified, forged or replayed; a declared algorithm is a property of this "
                "observed token, not proof of what the server accepts",
    }
    parts = _as_text(token).split(".")
    if len(parts) != 3:
        return entry

    header_bytes = _b64url_decode(parts[0])
    if header_bytes is not None:
        header_json, _ = safe_json_loads(header_bytes.decode("utf-8", errors="replace"))
        if isinstance(header_json, dict):
            entry["alg"] = _clip_claim(header_json.get("alg"))
            entry["typ"] = _clip_claim(header_json.get("typ"))
            entry["kid"] = _clip_claim(header_json.get("kid"))

    payload_bytes = _b64url_decode(parts[1])
    if payload_bytes is not None:
        payload, _ = safe_json_loads(payload_bytes.decode("utf-8", errors="replace"))
        if isinstance(payload, dict):
            entry["claims_decoded"] = True
            for claim in _JWT_INTEL_CLAIMS:
                if claim in payload:
                    entry["claims"][claim] = _clip_claim(payload[claim])
            exp = payload.get("exp")
            if isinstance(exp, (int, float)) and not isinstance(exp, bool):
                try:
                    entry["expires_at"] = datetime.fromtimestamp(float(exp), timezone.utc).isoformat()
                    entry["expired"] = float(exp) < datetime.now(timezone.utc).timestamp()
                except (OverflowError, OSError, ValueError):
                    entry["expires_at"] = None
    return entry


# Kept as a thin wrapper: the header-only decode is still the whole answer for
# callers that only want the declared algorithm.
def _decode_jwt_header_only(token: str) -> Dict[str, Any]:
    """Decode only the header segment of a JWT-shaped string (see _decode_jwt_intelligence)."""
    full = _decode_jwt_intelligence(token)
    return {"token_preview": full["token_preview"], "alg": full["alg"], "typ": full["typ"]}


def discover_oauth_metadata(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    baseline: Optional[Dict[str, Any]] = None,
    state: Optional[ApiReconState] = None,
) -> Dict[str, Any]:
    """
    Fetch the two standard authorization-server metadata documents
    (OpenID Connect Discovery, RFC 8414) from the already-authorized origin.

    Two read-only GETs for two well-known JSON documents whose entire purpose
    is to be published. This is metadata discovery, not an authorization flow:
    no authorization request is constructed, no token endpoint is called, no
    client is registered, and nothing is authenticated. Discovered endpoint
    URLs are recorded as *declared* metadata — the document says these
    endpoints exist; this module did not verify that any of them respond.
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    state = state if state is not None else ApiReconState()

    discovered: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    not_probed: List[str] = []

    for rel_path in OAUTH_METADATA_PATHS:
        url = _url_for_path(origin, rel_path)
        resp = _budgeted(state, fetch_url, url, timeout=timeout)
        if resp is None:
            not_probed.append(url)
            continue
        if resp["status"] != "found":
            errors.append({"stage": "oauth_metadata_probe", "url": url, "error": resp.get("error")})
            continue

        body = resp.get("body") or ""
        discovery_type, _, notes = classify_response(resp, baseline, url)
        _add_observation(observations, {
            "url": url, "headers": resp["headers"], "body": body,
            "source": "oauth_metadata", "discovery_type": discovery_type,
        })
        if discovery_type in _UNINFORMATIVE_TYPES:
            continue

        data, parse_error = safe_json_loads(body)
        if parse_error is not None and resp.get("body_truncated"):
            # Consistent with discover_openapi_specs: a document cut off at the
            # read cap is a candidate whose contents are unknown, not an absent
            # one, and saying nothing about it is the silent discard CLAUDE.md
            # rule 8 forbids.
            errors.append({
                "stage": "oauth_metadata_probe", "url": url,
                "error": f"a document at {url} was truncated at the {DEFAULT_MAX_BODY_BYTES}-byte "
                         f"read cap and could not be parsed; it was not recorded as metadata",
            })
            continue
        if not isinstance(data, dict) or "issuer" not in data:
            # Without an `issuer` this is not an authorization-server metadata
            # document, whatever else answered at the well-known path.
            continue

        record: Dict[str, Any] = {
            "url": url, "path": rel_path, "discovery_type": discovery_type,
            "status_code": resp["status_code"], "timestamp": _now(),
            "note": "declared metadata: the document states these endpoints exist; this module "
                    "did not probe them and did not perform any OAuth/OIDC flow",
        }
        for field in _OAUTH_METADATA_FIELDS:
            value = data.get(field)
            if isinstance(value, str) and value:
                record[field] = value[:400]
        for field in _OAUTH_METADATA_LIST_FIELDS:
            value = data.get(field)
            if isinstance(value, list) and value:
                record[field] = [_as_text(v)[:120] for v in value[:MAX_JWT_LIST_CLAIM_ITEMS]]

        evidence = [
            f"GET {url} returned an OAuth/OIDC authorization-server metadata document "
            f"(issuer {record.get('issuer')!r})",
        ] + notes
        discovered.append(record)
        err = _safe_store_add(store, make_finding(
            "api_oauth_metadata_discovered", target, dict(record), evidence, CONFIDENCE_HIGH,
            metadata={"url": url, "issuer": record.get("issuer")},
        ))
        if err:
            errors.append({"stage": "persistence", "url": url, "error": err})

    return {
        "target": target, "documents_discovered": discovered, "observations": observations,
        "errors": errors, "candidates_not_probed": not_probed,
    }


# Evidence bases, from strongest to weakest. Kept explicit on every evidence
# item because "an API key is used here" earns very different trust depending
# on whether a specification declared it, a server challenged for it, or the
# word appeared in a page's prose.
AUTH_BASIS_DECLARED = "declared"        # an OpenAPI/OIDC document says so
AUTH_BASIS_CHALLENGED = "challenged"    # the server issued a challenge/header
AUTH_BASIS_INFERRED = "inferred"        # a keyword appeared in content

_AUTH_BASIS_CONFIDENCE = {
    AUTH_BASIS_DECLARED: CONFIDENCE_HIGH,
    AUTH_BASIS_CHALLENGED: CONFIDENCE_MEDIUM,
    AUTH_BASIS_INFERRED: CONFIDENCE_LOW,
}

# Response headers that identify a CDN/WAF/proxy. Their presence does not prove
# the challenge came from the perimeter, but it means the observed behaviour
# cannot be attributed to the application either — and claiming an application
# authentication mechanism from a gateway's 401 is precisely the inference this
# module must not make.
_PERIMETER_HEADER_NAMES = [
    "CF-Ray", "CF-Cache-Status", "X-Amz-Cf-Id", "X-Akamai-Transformed",
    "X-Sucuri-ID", "X-Iinfo", "Server-Timing-Proxy", "X-Cache", "Via",
]
_PERIMETER_SERVER_RE = re.compile(
    r"cloudflare|cloudfront|akamai|fastly|sucuri|incapsula|imperva|varnish|envoy|awselb",
    re.IGNORECASE,
)


def _response_layer(headers: Dict[str, str]) -> str:
    """
    Which layer plausibly produced this response: "perimeter_or_application"
    when a CDN/WAF/proxy is in front, "application_or_unknown" otherwise.

    Never "application": nothing observable from outside proves that a 401 came
    from the application rather than from something in front of it.
    """
    if not isinstance(headers, dict):
        return "application_or_unknown"
    if any(_ci_get(headers, name) is not None for name in _PERIMETER_HEADER_NAMES):
        return "perimeter_or_application"
    server = _ci_get(headers, "Server") or ""
    if _PERIMETER_SERVER_RE.search(server):
        return "perimeter_or_application"
    return "application_or_unknown"


def fingerprint_authentication(
    observations: List[Dict[str, Any]],
    security_schemes: Optional[List[Dict[str, Any]]] = None,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    oauth_metadata: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Aggregate authentication-method signals (Bearer/API-Key/Basic/OAuth/JWT)
    from responses this module already fetched, plus OpenAPI/Swagger security
    schemes and OAuth/OIDC metadata it already parsed. Read-only: no discovered
    credential material is ever used to authenticate against anything.

    Three things this deliberately does not conflate:

      * **Declared vs challenged vs inferred.** Every evidence item carries its
        basis, and per-method confidence follows the strongest basis behind it.
        A specification declaring `bearerAuth` and the word "api key" appearing
        in a documentation page are not the same claim.
      * **Perimeter vs application.** A `WWW-Authenticate` header or a 401 is a
        challenge from *whatever answered* — a gateway, a WAF or the
        application. Each challenge records the layer it plausibly came from
        and never asserts "the application uses this mechanism".
      * **Observed vs absent.** Observations that were not-found, blocked or
        catch-all matches are skipped entirely. Mining a custom 404 page for
        "api_key" and "/oauth/authorize" manufactured authentication evidence
        out of an error page.
    """
    result: Dict[str, Any] = {
        "bearer": {"detected": False, "evidence": [], "bases": []},
        "api_key": {"detected": False, "evidence": [], "bases": [], "header_names": []},
        "basic": {"detected": False, "evidence": [], "bases": []},
        "oauth": {"detected": False, "evidence": [], "bases": []},
        "jwt": {"detected": False, "evidence": [], "bases": [], "tokens": []},
    }
    method_keys = list(result.keys())

    def _note(method: str, basis: str, text: str, extra: Optional[Dict[str, Any]] = None) -> None:
        entry = result[method]
        entry["detected"] = True
        if basis not in entry["bases"]:
            entry["bases"].append(basis)
        if len(entry["evidence"]) < MAX_EVIDENCE_ITEMS:
            item = {"basis": basis, "detail": text}
            if extra:
                item.update(extra)
            entry["evidence"].append(item)

    for scheme in security_schemes or []:
        if not isinstance(scheme, dict):
            continue
        stype = _as_text(scheme.get("type")).lower()
        sscheme = _as_text(scheme.get("scheme")).lower()
        name = scheme.get("name")
        if stype == "http" and sscheme == "bearer":
            _note("bearer", AUTH_BASIS_DECLARED,
                  f"OpenAPI securityScheme {name!r} declares HTTP bearer authentication")
        elif stype == "http" and sscheme == "basic":
            _note("basic", AUTH_BASIS_DECLARED,
                  f"OpenAPI securityScheme {name!r} declares HTTP basic authentication")
        elif stype == "apikey":
            if name and _as_text(name) not in result["api_key"]["header_names"]:
                result["api_key"]["header_names"].append(_as_text(name))
            _note("api_key", AUTH_BASIS_DECLARED,
                  f"OpenAPI securityScheme declares an API key in {scheme.get('in')!r}: {name!r}")
        elif stype in ("oauth2", "openidconnect"):
            _note("oauth", AUTH_BASIS_DECLARED,
                  f"OpenAPI securityScheme {name!r} declares {stype} flow(s): {scheme.get('flows')}")

    for document in oauth_metadata or []:
        if not isinstance(document, dict):
            continue
        _note("oauth", AUTH_BASIS_DECLARED,
              f"authorization-server metadata at {document.get('url')} declares issuer "
              f"{document.get('issuer')!r}"
              + (f", token endpoint {document.get('token_endpoint')!r}" if document.get("token_endpoint") else ""))
        if document.get("jwks_uri"):
            _note("jwt", AUTH_BASIS_DECLARED,
                  f"authorization-server metadata at {document.get('url')} publishes a JWKS URI "
                  f"({document.get('jwks_uri')!r}), so this issuer signs JWTs")

    seen_tokens = set()
    for obs in observations or []:
        if not isinstance(obs, dict):
            continue
        # Blocked/not-found/catch-all responses are not evidence about
        # authentication; they are evidence that nothing was learned.
        if obs.get("discovery_type") in _UNINFORMATIVE_TYPES:
            continue
        headers = obs.get("headers")
        headers = headers if isinstance(headers, dict) else {}
        body = _as_text(obs.get("body"))
        url = obs.get("url")
        layer = _response_layer(headers)

        www_auth = _ci_get(headers, "WWW-Authenticate")
        if www_auth:
            www_auth = _as_text(www_auth)
            lowered = www_auth.lower()
            for keyword, method in (("bearer", "bearer"), ("basic", "basic")):
                if keyword in lowered:
                    _note(method, AUTH_BASIS_CHALLENGED,
                          f"WWW-Authenticate challenge on {url}: {www_auth[:200]!r} — issued by "
                          f"whatever answered this request, which is not necessarily the "
                          f"application itself",
                          {"layer": layer, "url": url})

        for header_name in _API_KEY_HEADER_NAMES:
            if _ci_get(headers, header_name) is not None:
                if header_name not in result["api_key"]["header_names"]:
                    result["api_key"]["header_names"].append(header_name)
                _note("api_key", AUTH_BASIS_CHALLENGED,
                      f"Header {header_name!r} present in response from {url}",
                      {"layer": layer, "url": url})

        if _API_KEY_KEYWORD_RE.search(body):
            _note("api_key", AUTH_BASIS_INFERRED,
                  f"Content on {url} mentions an API key parameter/header — a textual mention, "
                  f"not an observed authentication mechanism",
                  {"url": url})

        if _OAUTH_KEYWORD_RE.search(body):
            _note("oauth", AUTH_BASIS_INFERRED,
                  f"Content on {url} references an OAuth2 authorization/token endpoint or "
                  f"parameter — a textual reference, not an observed flow",
                  {"url": url})

        haystack_tokens = set(_JWT_RE.findall(body))
        for value in headers.values():
            if isinstance(value, str):
                haystack_tokens.update(_JWT_RE.findall(value))
        for token in sorted(haystack_tokens):
            if token in seen_tokens:
                continue
            if len(seen_tokens) >= MAX_JWT_TOKENS:
                if "token_cap_reached" not in result["jwt"]:
                    result["jwt"]["token_cap_reached"] = MAX_JWT_TOKENS
                break
            seen_tokens.add(token)
            decoded = _decode_jwt_intelligence(token)
            result["jwt"]["tokens"].append(decoded)
            _note("jwt", AUTH_BASIS_CHALLENGED,
                  f"JWT-shaped token observed on {url} (declared alg={decoded.get('alg')!r}, "
                  f"iss={decoded.get('claims', {}).get('iss')!r}); decoded, never verified — "
                  f"observing a token is not evidence of compromised authentication",
                  {"url": url})

    result["api_key"]["header_names"] = sorted(set(n for n in result["api_key"]["header_names"] if n))

    for key in method_keys:
        bases = result[key]["bases"]
        result[key]["confidence"] = max(
            (_AUTH_BASIS_CONFIDENCE[b] for b in bases),
            key=lambda c: (CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH).index(c),
            default=None,
        ) if bases else None

    evidence_flat = [
        f"[{item['basis']}] {item['detail']}"
        for key in method_keys for item in result[key]["evidence"]
    ]
    if evidence_flat:
        all_bases = {b for key in method_keys for b in result[key]["bases"]}
        # Overall confidence follows the strongest basis present, and a
        # fingerprint resting only on prose keywords stays LOW rather than
        # being promoted to MEDIUM by volume.
        if AUTH_BASIS_DECLARED in all_bases:
            confidence = CONFIDENCE_HIGH
        elif AUTH_BASIS_CHALLENGED in all_bases:
            confidence = CONFIDENCE_MEDIUM
        else:
            confidence = CONFIDENCE_LOW
        methods_detected = [m for m in method_keys if result[m]["detected"]]
        err = _safe_store_add(store, make_finding(
            "api_authentication_method_fingerprint", target or "unknown",
            {k: result[k] for k in method_keys}, evidence_flat, confidence,
            metadata={"methods_detected": methods_detected, "bases": sorted(all_bases)},
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
    max_requests: int = DEFAULT_MAX_REQUESTS,
) -> Dict[str, Any]:
    """
    Run every Module 11 responsibility against `base_url` and persist every
    completed discovery immediately to <output_dir>/pending_assets.json
    (crash-safe). A failure in one stage does not prevent the others running.

    The whole run shares one ApiReconState, so the request budget, the
    rate-limit tripwire and the catch-all baseline are computed once and
    respected by every stage. Ctrl-C stops the run and reports it as
    interrupted with the partial results intact — every finding reached before
    the interrupt is already on disk.
    """
    base_url = validate_api_target(base_url, target=target)
    target = target or _hostname_of(base_url)
    origin = _ensure_trailing_slash(_origin_of(base_url))
    store = PendingAssetsStore(output_dir=output_dir)
    state = ApiReconState(max_requests=max_requests)

    summary: Dict[str, Any] = {
        "target": target, "module": MODULE_NAME, "base_url": base_url,
        "started_at": _now(),
        "versions": {}, "declared_versions": {}, "specifications": {}, "documentation": {},
        "graphql": {}, "graphql_introspections": [], "graphql_suggestions": [],
        "oauth_metadata": {}, "protocol_classifications": [],
        "deprecated_endpoints": {}, "http_methods": [],
        "authentication_fingerprint": {}, "errors": [],
    }

    def _stage(key: str, empty: Dict[str, Any], fn, *args, **kwargs) -> Dict[str, Any]:
        """Run one stage; a stage failure is recorded once and never aborts the run."""
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            summary["errors"].append({"stage": key, "error": str(exc)})
            result = dict(empty)
            # The stage's own error list stays empty so the merge below cannot
            # double-count what has already been recorded here.
            result["errors"] = []
            result["stage_error"] = str(exc)
            return result

    try:
        baseline = _probe_catch_all(origin, timeout, state)
        summary["baseline"] = {
            "available": baseline.get("available"), "usable": baseline.get("usable"),
            "dynamic": baseline.get("dynamic"), "status_codes": baseline.get("status_codes"),
            "error_mode_statuses": baseline.get("error_mode_statuses"),
            "unusable_reason": baseline.get("unusable_reason"),
            "probe_errors": baseline.get("probe_errors"),
        }

        summary["versions"] = _stage(
            "versions", {"versions_identified": [], "observations": []},
            discover_api_versions, base_url, target=target, store=store, timeout=timeout,
            baseline=baseline, version_range=version_range, state=state,
        )
        summary["specifications"] = _stage(
            "specifications", {"specs_discovered": [], "observations": []},
            discover_openapi_specs, base_url, target=target, store=store, timeout=timeout,
            baseline=baseline, state=state,
        )
        summary["documentation"] = _stage(
            "documentation", {"pages_discovered": [], "observations": []},
            discover_documentation_pages, base_url, target=target, store=store, timeout=timeout,
            baseline=baseline, state=state,
        )
        summary["graphql"] = _stage(
            "graphql", {"endpoints_detected": [], "observations": []},
            detect_graphql_endpoints, base_url, target=target, store=store, timeout=timeout,
            baseline=baseline, state=state,
        )
        summary["oauth_metadata"] = _stage(
            "oauth_metadata", {"documents_discovered": [], "observations": []},
            discover_oauth_metadata, base_url, target=target, store=store, timeout=timeout,
            baseline=baseline, state=state,
        )

        # Introspection, then — only where the server refused it — one bounded
        # field-suggestion probe. Weak (get_heuristic/LOW) detections are not
        # introspected: sending a schema query to something only suspected of
        # being GraphQL is how a REST endpoint ends up with a "schema" record.
        introspected_identities: set = set()
        for ep in summary["graphql"].get("endpoints_detected", []):
            if ep.get("confidence") not in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM):
                continue
            identity = _endpoint_identity(ep["url"])
            if identity in introspected_identities:
                summary["graphql_introspections"].append({
                    "url": ep["url"], "status": "skipped",
                    "reason": f"same endpoint as an already-introspected URL ({identity})",
                })
                continue
            if len(introspected_identities) >= MAX_GRAPHQL_INTROSPECTIONS:
                summary["graphql_introspections"].append({
                    "url": ep["url"], "status": "skipped",
                    "reason": f"per-run introspection cap of {MAX_GRAPHQL_INTROSPECTIONS} reached",
                })
                continue
            introspected_identities.add(identity)
            try:
                intro = introspect_graphql_schema(
                    ep["url"], target=target, store=store, timeout=timeout,
                    enabled=enable_graphql_introspection, state=state,
                )
            except Exception as exc:
                intro = {"url": ep["url"], "status": "error", "error": str(exc)}
            summary["graphql_introspections"].append(intro)

            if intro.get("status") == "disabled" and enable_graphql_introspection:
                try:
                    summary["graphql_suggestions"].append(mine_graphql_field_suggestions(
                        ep["url"], target=target, store=store, timeout=timeout, state=state,
                    ))
                except Exception as exc:
                    summary["errors"].append(
                        {"stage": "graphql_suggestions", "url": ep["url"], "error": str(exc)})

        all_observations = (
            summary["versions"].get("observations", [])
            + summary["specifications"].get("observations", [])
            + summary["documentation"].get("observations", [])
            + summary["graphql"].get("observations", [])
            + summary["oauth_metadata"].get("observations", [])
        )

        graphql_confirmed_urls = {
            ep["url"] for ep in summary["graphql"].get("endpoints_detected", [])
            if ep.get("confidence") in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM)
        }
        classified_urls = set()
        for obs in all_observations:
            url = obs.get("url")
            if not url or url in classified_urls:
                continue
            # A not-found / blocked / catch-all response describes the origin's
            # error handling, not a protocol. Classifying those produced a
            # "graphql (MEDIUM)" verdict for a 404 at /graphql.
            if obs.get("discovery_type") in _UNINFORMATIVE_TYPES:
                continue
            classified_urls.add(url)
            try:
                classification = classify_api_protocol(
                    url, obs.get("headers"), obs.get("body"),
                    graphql_confirmed=url in graphql_confirmed_urls,
                )
                summary["protocol_classifications"].append(classification)
                err = persist_protocol_classification(classification, target=target, store=store)
                if err:
                    summary["errors"].append({"stage": "persistence", "url": url, "error": err})
            except Exception as exc:
                summary["errors"].append({"stage": "protocol_classification", "url": url, "error": str(exc)})

        spec_records = summary["specifications"].get("specs_discovered", [])
        version_records = summary["versions"].get("versions_identified", [])

        summary["declared_versions"] = _stage(
            "declared_versions", {"declared_versions": []},
            discover_declared_api_versions, version_records, spec_records=spec_records,
            target=target, store=store,
        )

        summary["deprecated_endpoints"] = _stage(
            "deprecated_endpoints", {"deprecated_endpoints": []},
            detect_deprecated_endpoints, version_records, store=store, target=target,
            spec_records=spec_records,
            live_urls={r.get("url") for r in version_records},
        )

        method_candidate_urls: List[str] = []
        method_candidate_urls.extend(
            r["url"] for r in version_records
            if r.get("discovery_type") in (DT_CONTENT_CONFIRMED, DT_CONTENT_APP_ERROR)
        )
        method_candidate_urls.extend(ep["url"] for ep in summary["graphql"].get("endpoints_detected", []))
        method_candidate_urls.extend(
            s["url"] for s in spec_records
            if s.get("discovery_type") in (DT_CONTENT_CONFIRMED, DT_CONTENT_APP_ERROR)
        )
        for url in dict.fromkeys(method_candidate_urls):
            if state.should_stop():
                break
            try:
                summary["http_methods"].append(
                    discover_http_methods(url, target=target, store=store, timeout=timeout, state=state))
            except Exception as exc:
                summary["errors"].append({"stage": "http_methods", "url": url, "error": str(exc)})

        security_schemes = [s for spec in spec_records for s in (spec.get("security_schemes") or [])]
        summary["authentication_fingerprint"] = _stage(
            "authentication_fingerprint", {},
            fingerprint_authentication, all_observations, security_schemes=security_schemes,
            store=store, target=target,
            oauth_metadata=summary["oauth_metadata"].get("documents_discovered", []),
        )
    except KeyboardInterrupt:
        # Everything discovered so far is already persisted; say the run was
        # cut short rather than reporting a partial run as a complete one.
        state.cancelled = True
        summary["errors"].append({"stage": "run", "error": "interrupted by user (KeyboardInterrupt)"})

    for section_key in ("versions", "declared_versions", "specifications", "documentation",
                        "graphql", "oauth_metadata", "deprecated_endpoints"):
        section = summary.get(section_key)
        if isinstance(section, dict):
            summary["errors"].extend(section.get("errors", []))

    findings_found = bool(
        summary["versions"].get("versions_identified")
        or summary["declared_versions"].get("declared_versions")
        or summary["specifications"].get("specs_discovered")
        or summary["documentation"].get("pages_discovered")
        or summary["graphql"].get("endpoints_detected")
        or summary["oauth_metadata"].get("documents_discovered")
        # A *persisted* protocol observation is API surface too. Without this a
        # run could persist protocol findings and, in the same breath, write an
        # authoritative "no API surface here" into negative-result memory. Only
        # classifications that actually name a protocol count — counting the
        # "unknown" ones (which are never persisted) suppressed the
        # negative-result finding on a clean 404 host.
        or any(_named_protocols(c) for c in summary["protocol_classifications"])
    )

    summary["requests_sent"] = state.request_count
    summary["request_budget"] = state.max_requests
    summary["request_budget_exhausted"] = state.budget_exhausted
    summary["rate_limited"] = state.rate_limited
    summary["retry_after"] = state.retry_after
    summary["blocked_probes"] = state.blocked_probes
    summary["failed_probes"] = state.failed_probes
    summary["cancelled"] = state.cancelled
    summary["origin_unreachable"] = state.origin_unreachable
    summary["state_notes"] = list(state.notes)
    summary["conclusive"] = bool(
        state.conclusive() and summary["baseline"].get("available") and summary["baseline"].get("usable")
    ) if summary.get("baseline") else False

    # Negative-result memory (context.md §8/§12.6), emitted ONLY when the run
    # was actually conclusive. surface_mapper treats a "_checked_no" type as
    # authoritative "checked and not found" state for the (asset, check) pair,
    # so writing one after a throttled, budget-capped, interrupted or
    # baseline-less run would poison that memory and suppress a later, better
    # attempt. Mirrors endpoint_discovery.py's guard.
    if summary["conclusive"] and not findings_found:
        err = _safe_store_add(store, make_finding(
            "api_recon_checked_no_api_surface", target,
            {"base_url": base_url, "origin": origin, "requests_sent": state.request_count},
            [f"Probed {state.request_count} API version/specification/documentation/GraphQL/"
             f"OAuth-metadata candidate(s) under {origin} against a usable catch-all baseline; "
             f"none produced a response distinguishable from this origin's not-found behaviour"],
            CONFIDENCE_MEDIUM,
            metadata={"base_url": base_url, "conclusive": True},
        ))
        if err:
            summary["errors"].append({"stage": "persistence", "error": err})

    # A run that was throttled or hit its budget did not complete, and must not
    # be reported as if it had: reproduced, a run stopped after 3 requests by
    # the rate-limit tripwire still reported status "completed".
    if state.rate_limited:
        summary["errors"].append({
            "stage": "run",
            "error": "stopped early by the rate-limit tripwire; the API surface was not fully "
                     "probed and absence of findings is not evidence of absence"
                     + (f" (Retry-After: {state.retry_after!r})" if state.retry_after else ""),
        })
    if state.budget_exhausted:
        summary["errors"].append({
            "stage": "run",
            "error": f"request budget of {state.max_requests} exhausted; remaining candidates "
                     f"were not probed",
        })

    if state.cancelled:
        summary["status"] = "interrupted"
    elif summary["errors"]:
        summary["status"] = "completed_with_errors"
    else:
        summary["status"] = "completed"
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
    parser.add_argument(
        "--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
        help="Total request budget for the run",
    )
    args = parser.parse_args()

    try:
        result = run_api_recon(
            args.url, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
            enable_graphql_introspection=not args.no_graphql_introspection,
            max_requests=args.max_requests,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
