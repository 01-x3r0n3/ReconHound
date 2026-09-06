"""
reconhound/endpoint_discovery.py — ReconHound Module 10 (endpoint_discovery.py),
build-order position 5.

Phase: Active. See context.md §10 (module 10, "Web/API attack-surface
enumeration") for the authoritative responsibilities, and §8 for the
evidence/confidence data model this module implements. This file only
documents implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Web/API attack-surface enumeration. Dir/file enumeration with tech-aware
  wordlists (WordPress/Laravel/Django path lists), API endpoint discovery
  (/api/, /api/v1/, /api/v2/, /graphql/), parameter discovery
  (query/body/path/header/form) with full parameter intelligence
  (name/location/method/endpoint/type/source), historical + JS parameter
  correlation, recursive endpoint discovery."

That expands (per the assignment brief) into ten discrete responsibilities,
each implemented below:

  1. Directory enumeration        -> enumerate_directories
  2. File enumeration             -> enumerate_files
  3. Tech-aware wordlist selection-> select_wordlists_for_technology
  4. Framework-specific paths     -> enumerate_framework_paths
  5. API endpoint discovery       -> discover_api_endpoints
  6/7. Parameter discovery+intel  -> discover_parameters (+ extract_*)
  8. Historical param correlation -> correlate_historical_parameters
  9. JS param correlation         -> correlate_javascript_parameters
  10. Recursive endpoint discovery-> run_endpoint_discovery (BFS engine)

Plus shared plumbing: fetch_url, classify_response, PendingAssetsStore,
make_finding/make_parameter_finding, load_wordlist, and a single-target
orchestrator run_endpoint_discovery (mirroring the run_passive_recon /
run_active_recon / run_http_analysis precedent — not itself a listed
context.md responsibility).

Implementation decisions (ambiguities resolved so implementation can
proceed without redesigning anything context.md defines):

  1. Technology-aware selection (#3), historical correlation (#8), and
     JavaScript correlation (#9) all name modules that do not exist yet at
     this point in the build order (tech_fingerprint.py is build-order
     item 17; wayback_intel.py is item 9, run right after this module;
     js_analyzer.py is item 18). There is therefore no established
     interface yet to "consume". Rather than invent one by reading
     undocumented finding "type" strings out of pending_assets.json, this
     module accepts each as an explicit, optional, caller-supplied
     parameter (`technology`, `historical_data`, `js_data`) with a
     documented expected shape (see each function's docstring). The
     orchestrator (core/orchestrator.py) now passes those modules' real
     output straight through these parameters. Caller-supplied references
     are *not* trusted for scope: each is re-checked against `target`
     before it is persisted or requested, because they originate in
     third-party archives and in JavaScript.
  2. EXISTENCE IS JUDGED DIFFERENTIALLY. A response says something about a
     path only insofar as it differs from what the same routing subtree
     returns for a path that certainly does not exist. Before enumerating
     under a root, this module fingerprints that root's catch-all
     behaviour (BASELINE_PROBE_COUNT random paths of differing lengths),
     and every candidate is then compared against it:

       * Baselines are per *directory root*, not per host, because an app
         routinely serves an HTML 404 under "/" and a JSON error envelope
         under "/api/".
       * Two probes, not one, so a *static* catch-all (identical bodies)
         is distinguishable from a *dynamic* one (per-request ids, echoed
         paths). Dynamic catch-alls are matched on a structural signature
         with the requested path and volatile values normalised out.
       * The comparison applies at every status code, not only 2xx: a
         blanket redirect to /login and an authentication wall answering
         401 to everything are catch-alls just as much as a soft 404.
       * A match is a NEGATIVE result. It is counted, never emitted as an
         `endpoint_discovered` record, and never recursed into.
       * With no usable baseline the judgement cannot be made, so
         confidence is capped, the reason is stated in the evidence, and
         the run is marked `enumeration_conclusive: False`.

     Still a heuristic, not a guarantee: a catch-all that varies its whole
     layout per request can defeat it. As a backstop, a run in which most
     unbaselined hits share one response fingerprint raises an explicit
     `endpoint_discovery_catch_all_suspected` conflict finding rather than
     silently reporting them as discoveries.
  3. `beautifulsoup4` is added as a new dependency (requirements.txt). It
     is already part of context.md §5's approved tech stack; no earlier
     module needed real HTML structure parsing (http_analyzer.py's
     auth/JWT detection uses plain regex over already-fetched content).
     This is the first module doing structured form/link extraction, so
     it is added now, the same way `requests` was added when
     http_analyzer.py first needed it.
  4. Recursive discovery (#10) is implemented as depth-bounded breadth-
     first search, not unbounded recursion: every discovered
     directory-like hit (URL ending in "/") that is not a 404 re-seeds the
     same directory/API wordlists rooted at that new path, one depth level
     at a time, until `max_depth` or `max_requests` is reached. Links/API
     references extracted from already-fetched response bodies (HTML
     href/src/action attributes and inline fetch()/axios-style JS calls)
     are queued the same way. A single normalized-URL visited-set (shared
     across both mechanisms) prevents duplicate requests and loops.
  5. FAILURE IS NEITHER PRESENCE NOR ABSENCE. Outcomes are kept in three
     distinct classes and never collapsed:

       * found      — the response differs from the root's catch-all.
       * not found  — a 404, or a match against that catch-all. This is a
                      real negative result and is counted as one.
       * not tested — a transport failure, an HTTP 429, or a status the
                      root hands out to random paths anyway (a 503 from a
                      failing gateway). None of these is evidence about
                      the path, so none produces an endpoint record.

     After RATE_LIMIT_TRIP_THRESHOLD consecutive 429s a root is dropped
     from enumeration: past that point every further request returns 429
     regardless of what exists, so continuing only adds load. Retry-After
     is recorded, not slept on — throttling belongs to the orchestrator
     (context.md §10 item 22). Crucially, a run that was blocked,
     truncated, interrupted or left unbaselined NEVER writes the
     `endpoint_discovery_checked_no_endpoints` negative-result finding,
     because surface_mapper treats a "_checked_no" type as authoritative
     "checked and not found" memory and it would suppress a later,
     unblocked attempt.
  6. Only GET requests are made. No OPTIONS probing (that is
     exposure_scan.py's named responsibility), no state-changing
     methods — this module discovers surface, it does not exercise it.

Wordlists consumed (context.md §11's `wordlists/` folder, resolved as a
top-level directory alongside `output/`, sibling to the `reconhound/`
package — matching how `output/pending_assets.json` is already resolved
relative to the process' working directory, not nested inside the
package): `directories.txt` (combined directory + file wordlist —
context.md's folder structure defines one `directories.txt`, not a
separate files list, so responsibilities #1 and #2 share it, split by
whether an entry ends in "/"), `api_endpoints.txt`, `wordpress_paths.txt`,
`laravel_paths.txt`, `django_paths.txt`. `subdomains.txt` also lives in
that folder per context.md but is not this module's concern.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store and shared
output file used by the other modules), one read+write per probed endpoint
rather than per finding. Output feeds surface_mapper.py; this module does
not implement or call into surface_mapper, crawler, exposure_scan,
api_recon, js_analyzer, wayback_intel, vuln_intel, risk_engine,
orchestrator or report_generator.

Resource behaviour is bounded and measurable rather than merely intended:
the request budget covers baseline probes as well as candidates, recursion
re-seeds only on confirmed content, the frontier and per-page link fan-out
are capped, and one baseline is taken per root even under concurrency. A
KeyboardInterrupt cancels outstanding work and returns the partial summary
with `status: "interrupted"` instead of discarding the run (context.md §23).

Known limitation carried forward: pending_assets.json is a single JSON
array shared by all modules, so each append rewrites the whole file and a
run stays quadratic in total bytes written. Serialization is incremental
here (already-written records are not re-encoded), which took a
600-request/566-endpoint run from 74.4s to 6.7s, but the format itself is
an architectural decision outside this module's scope.

DISCOVERY != CONFIRMED VULNERABILITY: every record here is an observation
(a path responded a certain way, a parameter name was observed). None of
this module's output should be read as "vulnerable" or "exploitable" —
that assessment belongs to vuln_intel.py / risk_engine.py.
"""

from __future__ import annotations

import argparse
import concurrent.futures
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
from bs4 import BeautifulSoup

MODULE_NAME = "endpoint_discovery.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-EndpointDiscovery/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_REQUESTS = 500
DEFAULT_MAX_WORKERS = 10

# Resource ceilings for the recursive engine. Each exists because an actual
# adversarial workload was measured against this module without it:
#
#  * MAX_BASELINES  — one catch-all fingerprint costs BASELINE_PROBE_COUNT
#    requests, and baselines are per directory root, so an unbounded cache
#    turns "many discovered directories" into a request multiplier of its own.
#    Beyond the cap, deeper roots reuse their nearest cached ancestor baseline.
#  * MAX_LINK_CANDIDATES_PER_PAGE — a single page with tens of thousands of
#    <a> tags otherwise queues one task per link.
#  * MAX_FRONTIER — next_frontier is built before the budget is consumed, so a
#    wide depth-1 level can allocate far more task tuples than the run could
#    ever spend requests on.
DEFAULT_MAX_BASELINES = 64
DEFAULT_MAX_LINK_CANDIDATES_PER_PAGE = 200
DEFAULT_MAX_FRONTIER = 20000

# Number of random probes used to fingerprint one root's "this does not exist"
# response. Two is the minimum that can tell a *static* catch-all (both probes
# identical) from a *dynamic* one (bodies differ per request), and the two
# probe paths are deliberately different lengths so a catch-all page that
# echoes the requested path shows up as a length difference rather than
# looking stable. See _probe_catch_all.
BASELINE_PROBE_COUNT = 2

# How many times a *failed* baseline probe is retried before its failure is
# accepted for the rest of the run. A successful baseline is never re-probed.
BASELINE_MAX_ATTEMPTS = 3

# How much of each baseline probe's body is retained for content-overlap
# comparison. Bounded because up to DEFAULT_MAX_BASELINES baselines are held
# for the life of a run.
_BASELINE_SAMPLE_BYTES = 8192

# Retrospective catch-all detection (see _detect_dominant_catch_all): when no
# usable baseline could be taken, a run in which this fraction or more of the
# confirmed hits share one response fingerprint is reporting a catch-all, not
# that many discoveries. Requires at least MIN_SAMPLES hits so a small,
# genuinely uniform result set is not second-guessed.
CATCH_ALL_DOMINANCE_RATIO = 0.8
CATCH_ALL_DOMINANCE_MIN_SAMPLES = 5

# Consecutive HTTP 429 responses from one root after which enumeration of that
# root stops. Continuing past this point produces no information (every further
# path returns 429 regardless of whether it exists) while still generating
# load, so the run is marked incomplete instead — see _EnumerationState.
RATE_LIMIT_TRIP_THRESHOLD = 3

# Explicit API roots named by context.md, plus the no-trailing-slash "graphql"
# sibling: real GraphQL deployments are mounted at /graphql far more often than
# at /graphql/, and probing only the slashed form missed them entirely. This
# module discovers *that the path responds*; GraphQL schema/introspection
# intelligence remains api_recon.py's responsibility.
API_ROOTS: List[str] = ["api/", "api/v1/", "api/v2/", "graphql/", "graphql"]

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)

# Discovery-type vocabulary. Kept as named constants because both the
# recursion gate and the persistence gate below key on these strings, and a
# typo in either silently changes what the module reports as "discovered".
DT_NOT_FOUND = "not_found"
DT_CATCH_ALL_MATCH = "catch_all_match"
DT_CONTENT_CONFIRMED = "content_confirmed"
DT_REDIRECT = "redirect"
DT_ACCESS_RESTRICTED = "access_restricted"
DT_METHOD_NOT_ALLOWED = "method_not_allowed"
DT_SERVER_ERROR = "server_error_response"
DT_RATE_LIMITED = "rate_limited"
DT_UNEXPECTED_STATUS = "unexpected_status"
DT_ERROR = "error"
# The root answers 429/5xx indiscriminately — to the random baseline probes as
# well as to real candidates — so this path was never actually tested. The
# explicit "blocked / not tested" state of context.md §8, kept distinct from
# both "found" and "checked and not found".
DT_BLOCKED = "blocked_not_tested"

# Retained for API compatibility: the pre-hardening name for DT_CATCH_ALL_MATCH
# when the catch-all happened to be an HTTP 200 soft 404.
DT_POSSIBLE_SOFT_404 = "possible_soft_404_match"

# Only a response that differs from its root's catch-all baseline AND carries
# real content is worth re-seeding the wordlists under. Previously `redirect`,
# `access_restricted` and `method_not_allowed` recursed too, which is pure
# amplification: a directory that answers 401 answers 401 for every child, so
# every child response is uninformative and the wordlist is re-spent per level.
# Measured on a 40-directory/20-API-entry wordlist against an all-401 host,
# depth 2: 100k+ requests and 2,400+ phantom endpoint records. A redirect's
# Location target is queued directly instead (see _probe_and_record), which is
# the part of a redirect that actually carries new surface.
_RECURSION_WORTHY_TYPES = {DT_CONTENT_CONFIRMED}

# Outcomes that are NOT evidence that a path exists and must therefore never
# become an `endpoint_discovered` record. 429 means the server refused to
# answer; `error` means no answer arrived at all. Recording either as a
# discovery is the "request failure == endpoint presence" bug: against a
# rate-limiting or unhealthy host it minted one phantom endpoint asset per
# wordlist entry, which surface_mapper then fed to exposure_scan as real
# surface. Catch-all matches and 404s are genuine *negative* results and are
# accounted for separately.
_NON_EVIDENTIAL_TYPES = {DT_RATE_LIMITED, DT_ERROR, DT_BLOCKED}
_NEGATIVE_TYPES = {DT_NOT_FOUND, DT_CATCH_ALL_MATCH, DT_POSSIBLE_SOFT_404}

# Technology keyword -> framework-specific wordlist (responsibility #4).
_FRAMEWORK_WORDLISTS: Dict[str, str] = {
    "wordpress": "wordpress_paths.txt",
    "laravel": "laravel_paths.txt",
    "django": "django_paths.txt",
}

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_OBJECT_ID_RE = re.compile(r"^[0-9a-fA-F]{24}$")

_HEADER_HINT_TOKENS = ["X-Api-Key", "X-Auth-Token", "X-CSRF-Token", "X-Access-Token"]

_FORM_FIELD_TYPE_MAP = {
    "number": "integer", "range": "integer", "checkbox": "boolean", "radio": "string",
    "email": "string", "password": "string", "hidden": "string", "file": "file",
    "date": "string", "datetime-local": "string", "tel": "string", "url": "string",
    "text": "string", "search": "string", "select": "string", "textarea": "string",
}

_LINK_ATTR_TAGS = {"a": "href", "link": "href", "script": "src", "img": "src", "iframe": "src", "form": "action"}
_JS_CALL_RE = re.compile(
    r'(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\.open)\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_QUOTED_API_PATH_RE = re.compile(r'["\'](/(?:api|graphql)[A-Za-z0-9_\-./]*)["\']', re.IGNORECASE)


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class WordlistError(RuntimeError):
    """Raised when a required wordlist file cannot be loaded or contains no usable entries."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors http_analyzer.py's validate_url_target;
# duplicated per modular independence, context.md §12.2)
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
    "xn--mnchen-3ya.de" (or the reverse) compare unequal even though they are
    the same host — a Unicode/IDN mismatch that silently drops in-scope assets
    in one direction and, more importantly, would let a homograph host look
    "different" from the target it is impersonating. Both sides are folded to
    lowercase A-label form; anything that will not encode is returned
    lowercased unchanged so the caller still gets a deterministic comparison.
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

    URLs reach this module from response bodies and from caller-supplied
    historical/JS records, so credentials genuinely turn up in them. They must
    not be re-sent, must not become part of an asset identity, and above all
    must never be written into pending_assets.json — which is a plain-text
    file shared with every other module and included in the report appendix
    (CLAUDE.md rule 16). The netloc is rebuilt from the parsed host/port so
    the result is also the canonical form for the visited set.
    """
    parsed = urllib.parse.urlsplit(url)
    if "@" not in parsed.netloc:
        return url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"          # bare IPv6 literal
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _host_allowed(hostname: str, target: Optional[str]) -> bool:
    """
    Scope gate for a host learned from *content* (a link, a historical record,
    a JS reference) rather than supplied by the operator.

    validate_endpoint_target() lets a bare IP literal through unchecked,
    because an operator naming an IP has authorised that IP upstream. That
    reasoning does not carry over to a hostname this module read out of a
    response body: a page can link to any address it likes, and following one
    unconditionally meant an in-scope page could steer the scanner at
    169.254.169.254 (cloud instance metadata), at RFC1918 hosts, or at any
    other third party — an authorisation boundary violation, not a bug in
    taste. An IP literal from content is therefore accepted only when it *is*
    the operator-supplied target.
    """
    if not hostname:
        return False
    if not target:
        return False
    if _is_ip_literal(hostname):
        return _idna_normalize(hostname) == _idna_normalize(target)
    return _in_scope_host(hostname, target)


def validate_endpoint_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check, mirroring http_analyzer.py's rationale: IP scope is
    enforced upstream, not by a domain comparison here).
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()
    # A CR, LF, NUL or tab inside a URL is never legitimate. urlsplit silently
    # *removes* newlines and tabs, so a wordlist entry or an extracted link
    # containing them would be validated in its stripped form and then handed
    # to requests still containing the raw bytes. requests does reject such a
    # URL, but only as an opaque transport error late in the run; rejecting it
    # here names the real problem and keeps request construction unambiguous.
    if any(ch in candidate for ch in "\r\n\t\x00"):
        raise ScopeError(f"URL contains control characters: {url!r}")

    try:
        parsed = urllib.parse.urlsplit(candidate)
        hostname = parsed.hostname
    except ValueError as exc:
        # urlsplit raises on malformed IPv6 brackets and out-of-range ports.
        raise ScopeError(f"URL cannot be parsed: {url!r} ({exc})") from exc

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if target and not _is_ip_literal(hostname) and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    # Credentials embedded in an operator-supplied URL are dropped rather than
    # rejected: the URL is legitimate, but re-sending and persisting the
    # credential is not (see _strip_userinfo).
    return _strip_userinfo(candidate)


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors passive_recon.py's/active_recon.py's/
# http_analyzer.py's model; kept local per modular independence)
# ---------------------------------------------------------------------------

def _jsonify(value: Any, _depth: int = 0) -> Any:
    """
    Coerce a value into something json.dump can definitely write.

    Findings carry data this module did not create: `evidence` lists,
    parameter dicts and technology structures supplied by the caller
    (wayback_intel/js_analyzer output routed through the orchestrator). A
    single value json.dump cannot serialise used to fail the whole write —
    and once persistence was batched, it took every other finding in that
    batch down with it, so one malformed historical record could discard a
    probe's entire result. Coercing at construction time means every finding
    this module emits is writable by definition.

    Mirrors passive_recon.py's `_jsonify`, which shares this output file.
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
        "value": _jsonify(value),
        "evidence": [_jsonify(e) for e in evidence],
        "confidence": confidence,
        "source": MODULE_NAME,
        "timestamp": _now(),
        "metadata": _jsonify(metadata or {}),
    }


def make_parameter_finding(param: Dict[str, Any], target: str) -> Dict[str, Any]:
    """
    Wrap a raw parameter dict (see extract_* functions below) into the
    structured evidence record required by responsibility #7 ("parameter
    intelligence"): name, location, method, endpoint, data type, source —
    each explicitly preserved (not collapsed to just a name).
    """
    return make_finding(
        finding_type="endpoint_parameter",
        target=target,
        value={
            "name": param.get("name"),
            "location": param.get("location"),
            "method": param.get("method"),
            "endpoint": param.get("endpoint"),
            "data_type": param.get("data_type"),
            "source": param.get("source"),
        },
        evidence=param.get("evidence") or [],
        confidence=param.get("confidence", CONFIDENCE_LOW),
        metadata={
            "name": param.get("name"),
            "location": param.get("location"),
            "method": param.get("method"),
            "endpoint": param.get("endpoint"),
            "data_type": param.get("data_type"),
            "source": param.get("source"),
            "historical": param.get("historical", False),
            "js_derived": param.get("js_derived", False),
            # Whether this run independently observed the endpoint live. Only
            # meaningful for historical/JS-derived parameters, and previously
            # dropped on the floor here even though the correlation functions
            # had computed it — leaving downstream unable to tell a parameter
            # seen in a 2019 archive from one on a currently reachable path.
            "currently_verified": param.get("currently_verified"),
        },
    )


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as the other modules'
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
        # Serialized body of everything this store has written, kept so an
        # append does not have to re-encode the whole file (see _atomic_write).
        # `_stamp` is the (mtime_ns, size) of the file as this store last left
        # it; anything else means somebody else wrote it and the cache is void.
        self._serialized: Optional[str] = None
        self._stamp: Optional[Tuple[int, int]] = None
        os.makedirs(self.output_dir, exist_ok=True)

    def _current_stamp(self) -> Optional[Tuple[int, int]]:
        try:
            info = os.stat(self.path)
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size)

    def _cache_is_current(self) -> bool:
        return self._serialized is not None and self._stamp == self._current_stamp()

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
        self.add_many([finding])
        return finding

    def add_many(self, findings: List[Dict[str, Any]]) -> int:
        """
        Append a batch of findings in ONE read + ONE atomic write.

        add() rewrites the whole shared file per finding, which is quadratic in
        the number of records already on disk. Endpoint discovery is the worst
        case in the pipeline for that: one probed path can yield an endpoint
        record plus a dozen parameter records, and pending_assets.json already
        holds every earlier module's output by the time this module runs.
        Measured on this repository with add(): 100 findings 0.10s, 300 0.60s,
        600 2.20s, 1000 5.85s. Batching one probe's records into a single write
        keeps a full 500-request run linear in practice.

        Crash-safety is unchanged and slightly stronger: still one
        write-to-temp + os.replace, so the batch is all-or-nothing rather than
        half-applied. Mirrors active_recon.py/wayback_intel.py, which share
        this output file. Returns the number of findings written.
        """
        if not findings:
            return 0
        with self._lock:
            if not self._cache_is_current():
                # First write of this run, or the file changed underneath us:
                # re-encode from what is actually on disk.
                self._serialized = self._encode_body(self._read_all())
            addition = self._encode_body(findings)
            body = f"{self._serialized},\n{addition}" if self._serialized else addition
            self._atomic_write_body(body)
            self._serialized = body
        return len(findings)

    @staticmethod
    def _encode_body(records: List[Dict[str, Any]]) -> str:
        """Serialize records as the *inside* of the JSON array (no brackets)."""
        if not records:
            return ""
        return ",\n".join("  " + json.dumps(r, indent=2).replace("\n", "\n  ") for r in records)

    def _atomic_write_body(self, body: str) -> None:
        """
        Write "[<body>]" via write-to-temp + os.replace + directory fsync.

        The file format, the indentation and the crash-safety guarantee are
        exactly as before; what changed is that already-written records are no
        longer re-encoded on every append. Rewriting the whole array per probe
        made a run quadratic in *serialization* as well as in bytes written:
        profiling a 600-request run showed 63.7s of 74.4s inside json.dump,
        24M encoder calls to persist 566 endpoints. Only the new records are
        encoded now; the write itself is still a full rewrite, because the
        on-disk format is a single JSON array shared with every other module
        and changing that is an architectural decision, not a local one.
        """
        dir_name = os.path.dirname(self.path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".pending_assets_", dir=dir_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("[\n" + body + "\n]" if body else "[]")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
            self._fsync_dir(dir_name)
            self._stamp = self._current_stamp()
        except BaseException:
            self._serialized = None
            self._stamp = None
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def _atomic_write(self, records: List[Dict[str, Any]]) -> None:
        """Replace the file with exactly `records` (kept for direct callers)."""
        self._atomic_write_body(self._encode_body(records))
        self._serialized = self._encode_body(records)

    @staticmethod
    def _fsync_dir(dir_name: str) -> None:
        """
        Durably commit the os.replace() rename itself.

        Without this the replacement file's *contents* are on disk but the
        directory entry pointing at them may not be, so a power loss can still
        resurrect the pre-replace file and lose every discovery appended since.
        Best-effort: some platforms/filesystems refuse to fsync a directory.
        Mirrors passive_recon.py/active_recon.py, which share this file.
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
# fills or the path loses permissions (OSError), or a caller-supplied
# historical/JS payload carries a value json.dump cannot serialise
# (TypeError/ValueError). Catching only PersistenceError meant those escaped
# _probe_and_record, killed the worker task, and took the *completed
# discovery* down with them — the one outcome context.md §12.11 forbids. The
# discovery is now always returned to the caller and the failure is reported.
_PERSISTENCE_FAILURES = (PersistenceError, OSError, TypeError, ValueError)


def _safe_store_add(store: Optional["PendingAssetsStore"], finding: Dict[str, Any]) -> Optional[str]:
    """
    store.add() wrapped so a single persistence failure doesn't abort
    enumeration. Returns None on success, or an error message the caller
    is responsible for recording (never silently discarded).
    """
    if store is None:
        return None
    try:
        store.add(finding)
        return None
    except _PERSISTENCE_FAILURES as exc:
        return str(exc)


def _safe_store_add_many(
    store: Optional["PendingAssetsStore"], findings: List[Dict[str, Any]],
) -> Optional[str]:
    """
    store.add_many() wrapped identically to _safe_store_add. Returns None on
    success, or an error message; the in-memory findings are never discarded
    because persistence failed.
    """
    if store is None or not findings:
        return None
    try:
        store.add_many(findings)
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


def _origin_of(url: str) -> str:
    """
    scheme://host[:port] for `url`, with any userinfo removed.

    The credential strip matters: this value keys the catch-all baseline cache
    and is joined with a random path to build the probe URL, so leaving it in
    would both send the credential to the probe and split the cache per
    credential.
    """
    parsed = urllib.parse.urlsplit(_strip_userinfo(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def _directory_root_of(url: str) -> str:
    """
    The directory a URL denotes, as an absolute URL ending in "/".

    "https://h/app/v2/" -> "https://h/app/v2/"; "https://h/app/x" -> "https://h/app/".
    Used where a URL *names* a directory to work under (see _enumeration_root).
    """
    parsed = urllib.parse.urlsplit(_strip_userinfo(url))
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _candidate_root_of(url: str) -> str:
    """
    The root a *candidate* was enumerated under — i.e. its parent directory.

    Catch-all behaviour is a property of a routing subtree, not of a host: an
    application commonly serves an HTML 404 under "/" while its "/api/"
    subtree answers unknown paths with a JSON envelope, so baselines and the
    rate-limit tripwire are both keyed per subtree.

    The parent, specifically, is what that key must be. Keying a
    directory-shaped candidate on *itself* ("https://h/admin/" -> ".../admin/")
    gave every single candidate its own private root, which broke both users
    of the key at once: one baseline was probed per candidate rather than per
    subtree (a large, silent request multiplier), and the consecutive-429
    counter was spread one-per-root so the rate-limit tripwire could never
    reach its threshold and never fired at all.

    "https://h/admin/" -> "https://h/"; "https://h/api/v1/users" -> "https://h/api/v1/".
    """
    parsed = urllib.parse.urlsplit(_strip_userinfo(url))
    path = parsed.path or "/"
    if path.endswith("/"):
        path = path[:-1]
    path = path.rsplit("/", 1)[0] + "/"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def _is_directory_like(url: str) -> bool:
    return urllib.parse.urlsplit(url).path.endswith("/")


def _entry_kind(entry: str) -> str:
    """Wordlist convention: entries ending in '/' are directory candidates."""
    return "directory" if entry.endswith("/") else "file"


def _url_for_path(root: str, entry: str) -> str:
    """
    Join a wordlist entry under `root`, never above or outside it.

    urljoin honours an absolute reference, so a wordlist line reading
    "http://elsewhere.example/" or "//elsewhere.example/" would otherwise
    resolve to a different origin entirely — a scope escape sourced from a
    file rather than from the network, but a scope escape all the same. The
    entry is reduced to a relative path and dot segments are removed so it
    also cannot climb out of `root` with "../".
    """
    root = _ensure_trailing_slash(root)
    entry = (entry or "").strip()
    # Strip any scheme/authority so the entry can only ever be relative.
    entry = re.sub(r"^[A-Za-z][A-Za-z0-9+.\-]*:", "", entry)
    entry = entry.lstrip("/")
    joined = urllib.parse.urljoin(root, entry)
    parsed = urllib.parse.urlsplit(joined)
    root_parsed = urllib.parse.urlsplit(root)
    if (parsed.scheme, parsed.netloc) != (root_parsed.scheme, root_parsed.netloc):
        # Defensive: the sanitising above should make this unreachable.
        return root
    safe_path = _remove_dot_segments(parsed.path or "/")
    if not safe_path.startswith(root_parsed.path):
        safe_path = root_parsed.path
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, safe_path, parsed.query, ""))


def _enumeration_root(base_url: str) -> str:
    """
    The directory under which a base URL's enumeration is rooted.

    Previously every entry point rebuilt this as `_origin_of(base_url) + "/"`,
    which silently discarded any path the caller supplied: asking to enumerate
    "https://example.com/app/v2/" probed "/admin/", "/api/" and so on at the
    origin and never touched anything under /app/v2/. For an origin-only base
    URL the result is identical to the old behaviour.
    """
    return _directory_root_of(base_url)


# Characters RFC 3986 defines as "unreserved": percent-encoding them is
# permitted but carries no meaning, so "%61dmin" and "admin" are the same
# path. Every *other* escape is left exactly as written, because decoding it
# would change the request: "%2F" inside a segment is a literal slash in that
# segment, not a path separator, and collapsing the two would merge genuinely
# distinct endpoints.
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_PCT_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def _normalize_percent_encoding(value: str) -> str:
    """Decode only unreserved escapes; uppercase the hex digits of the rest."""
    def _sub(match: "re.Match[str]") -> str:
        try:
            char = bytes.fromhex(match.group(1)).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return "%" + match.group(1).upper()
        if char in _UNRESERVED:
            return char
        return "%" + match.group(1).upper()
    return _PCT_ESCAPE_RE.sub(_sub, value)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4 dot-segment removal, so /a/./b and /a/x/../b converge."""
    out: List[str] = []
    for segment in path.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if out and out[-1] not in ("", ".."):
                out.pop()
            continue
        out.append(segment)
    result = "/".join(out)
    if path.startswith("/") and not result.startswith("/"):
        result = "/" + result
    return result or "/"


def _normalize_url(url: str) -> str:
    """
    Canonical form of a URL, used as the visited-set key so the same resource
    is never requested twice (responsibility #10: "duplicate processing /
    obvious loops").

    Normalizes scheme/host casing, IDN form, the hostname's trailing root dot,
    default ports, userinfo, duplicate slashes, dot segments, redundant
    percent-encoding, query-parameter order, and the fragment (which is never
    sent to a server and so can never distinguish two requests).

    Trailing-slash presence on the path is intentionally preserved: it
    distinguishes directory- from file-kind candidates, which is meaningful
    here rather than noise.
    """
    try:
        parsed = urllib.parse.urlsplit(_strip_userinfo(url))
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        # Unparseable input still needs a deterministic, collision-free key
        # rather than an exception out of the dedup path.
        return url.strip()

    scheme = (parsed.scheme or "").lower()
    host = _idna_normalize(hostname)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"          # bare IPv6 literal
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"

    path = _remove_dot_segments(re.sub(r"/{2,}", "/", parsed.path or "/"))
    path = _normalize_percent_encoding(path)
    query = urllib.parse.urlencode(
        sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    )
    return urllib.parse.urlunsplit((scheme, host, path, query, ""))


def _looks_textual(content_type: Optional[str], body: Optional[str]) -> bool:
    """Best-effort textual-content check so binary responses aren't parsed as HTML/forms."""
    if not body:
        return False
    if content_type:
        ct = content_type.lower()
        if any(t in ct for t in ("html", "json", "xml", "javascript", "text", "graphql")):
            return True
        if any(
            t in ct for t in (
                "image/", "video/", "audio/", "font/", "application/octet-stream",
                "application/zip", "application/pdf", "application/gzip",
            )
        ):
            return False
    return True


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
    normalized = re.sub(r"\s+", " ", body).strip()
    return len(normalized), _digest(normalized)


# Volatile fragments that change on every single response and therefore make
# two renderings of the *same* page hash differently: request/trace IDs, CSRF
# nonces, timestamps, cache-buster query strings, elapsed times. Removing them
# before hashing is what lets a *dynamic* catch-all page still be recognised
# as the same catch-all page across probes.
_VOLATILE_PATTERNS = [
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\b\d{10,}\b"),
    re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|milliseconds|seconds)\b", re.IGNORECASE),
]


def _structural_signature(body: str, url: str) -> str:
    """
    A digest of a response body with the two things that legitimately vary
    between two renderings of the same page removed:

      1. anything derived from the *requested path* — a custom error page that
         says "Sorry, /admin was not found" is the same page as one that says
         "Sorry, /backup was not found", and
      2. per-request volatile values (request IDs, nonces, timestamps).

    This is the fix for dynamic catch-all pages. The previous heuristic hashed
    the raw body and compared lengths with a fixed ±25-byte tolerance, so a
    catch-all that echoed the requested path differed from the baseline in
    both hash and length and was reported as HIGH-confidence confirmed
    content. Measured against a path-echoing 200 catch-all with a per-request
    id: 35 of 116 probed paths came back as `content_confirmed`/HIGH.

    Best-effort by construction — it cannot recognise a catch-all that varies
    its whole layout per request — so a match still yields LOW confidence and
    an explicit note rather than certainty.
    """
    normalized = re.sub(r"\s+", " ", body or "").strip()
    try:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path or ""
    except ValueError:
        path = ""
    # Longest first, so "/api/v1/users" is removed before its "users" segment.
    tokens = [path, urllib.parse.quote(path), urllib.parse.unquote(path)]
    tokens.extend(seg for seg in path.split("/") if len(seg) >= 3)
    for token in sorted({t for t in tokens if t}, key=len, reverse=True):
        normalized = normalized.replace(token, "\x00PATH\x00")
    for pattern in _VOLATILE_PATTERNS:
        normalized = pattern.sub("\x00VAR\x00", normalized)
    return _digest(normalized)


def _lengths_close(a: Optional[int], b: Optional[int], tolerance: int = 25) -> bool:
    """
    Whether two body lengths are close enough to be the same page.

    The tolerance is the larger of `tolerance` bytes and 2% of the compared
    length. A fixed absolute window is wrong in both directions: on a 200-byte
    JSON error envelope 25 bytes is an eighth of the document, while on a
    200 KB page two responses differing by 25 bytes are obviously the same
    template and a strict window rejects them.
    """
    if a is None or b is None:
        return False
    allowed = max(tolerance, int(max(a, b) * 0.02))
    return abs(a - b) <= allowed


# Token-overlap threshold above which two bodies are the same page. Used to
# corroborate the length pre-filter; see _token_similarity.
CATCH_ALL_SIMILARITY = 0.9
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_SIMILARITY_MAX_TOKENS = 4000


def _token_similarity(a: str, b: str) -> float:
    """
    Jaccard overlap of the word tokens in two bodies, 0.0-1.0.

    This exists because *length* alone is not evidence that two responses are
    the same page, and using it as such caused real endpoints to be discarded.
    Concretely: a catch-all baseline of `{"error":"resource not found",
    "code":404}` (41 bytes) and a genuine hit of `{"orders":[{"id":7},
    {"id":8}],"total":2}` (40 bytes) are one byte apart, so a length
    comparison called them identical and the real API endpoint was silently
    dropped as a soft 404 — a false negative caused by the suppression logic
    itself. Their token overlap is near zero.

    Bounded to the first _SIMILARITY_MAX_TOKENS tokens so comparing two large
    documents stays cheap.
    """
    if not a or not b:
        return 1.0 if a == b else 0.0
    tokens_a = set(_TOKEN_RE.findall(a)[:_SIMILARITY_MAX_TOKENS])
    tokens_b = set(_TOKEN_RE.findall(b)[:_SIMILARITY_MAX_TOKENS])
    if not tokens_a and not tokens_b:
        return 1.0
    union = tokens_a | tokens_b
    if not union:
        return 0.0
    return len(tokens_a & tokens_b) / len(union)


# Second test, for a catch-all that varies per request. Taking two baseline
# samples means the root itself shows which words are fixed and which vary:
# the intersection of the samples is the wording the error page ALWAYS uses.
# A response is another rendering of that page when it repeats all of that
# fixed wording (`core`) and adds little of its own.
#
# Both halves are load-bearing. Core containment alone would be disastrous on
# a site whose 404 page shares the ordinary chrome — nav, footer, boilerplate
# — because every real page contains that chrome too and would be suppressed.
# The novelty ceiling is what separates them: a real page adds a page's worth
# of its own words, a re-rendered error page adds a reference number.
CATCH_ALL_MAX_NOVELTY = 0.25
CATCH_ALL_MIN_TOKENS = 8


def _content_matches_samples(normalized: str, samples: List[str]) -> bool:
    """
    True if `normalized` is another rendering of the baseline's catch-all.

    The candidate is tokenised once and every test is computed from the same
    sets — this runs on every probed response, so re-tokenising per sample
    would put avoidable cost in the hot path.
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
    novelty = len(tokens - vocabulary) / len(tokens)
    return novelty <= CATCH_ALL_MAX_NOVELTY


def _infer_data_type(value: str) -> str:
    """LOW-confidence-by-nature type inference from an observed string value."""
    if value == "":
        return "unknown"
    if re.fullmatch(r"[+-]?\d+", value):
        return "integer"
    if re.fullmatch(r"[+-]?\d+\.\d+", value):
        return "float"
    if value.lower() in ("true", "false"):
        return "boolean"
    if _UUID_RE.match(value):
        return "uuid"
    if "@" in value and "." in value.split("@")[-1]:
        return "email"
    return "string"


# ---------------------------------------------------------------------------
# Wordlist loading
# ---------------------------------------------------------------------------

def _default_wordlists_dir() -> str:
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wordlists"))


def load_wordlist(name: str, wordlists_dir: Optional[str] = None) -> List[str]:
    """
    Load a newline-delimited wordlist file (blank lines and '#' comments
    ignored, duplicates dropped, order preserved).
    """
    directory = wordlists_dir or _default_wordlists_dir()
    path = os.path.join(directory, name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as exc:
        raise WordlistError(f"Unable to read wordlist {name!r} from {directory!r}: {exc}") from exc

    entries: List[str] = []
    seen = set()
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#") or entry in seen:
            continue
        seen.add(entry)
        entries.append(entry)

    if not entries:
        raise WordlistError(f"Wordlist {name!r} at {path!r} contains no usable entries.")
    return entries


# ---------------------------------------------------------------------------
# 3. Technology-aware wordlist selection
# ---------------------------------------------------------------------------

def _flatten_technology_values(
    value: Any, _depth: int = 0, _seen: Optional[set] = None,
) -> List[str]:
    """
    Every string anywhere inside a caller-supplied technology structure.

    Depth- and cycle-guarded: the shape comes from another module's output, and
    a self-referential or deeply nested dict previously raised RecursionError
    straight out of wordlist selection, failing the whole run over a malformed
    input that should simply have matched nothing.
    """
    if _depth > 12:
        return []
    if _seen is None:
        _seen = set()
    out: List[str] = []
    if isinstance(value, (dict, list, tuple, set)):
        if id(value) in _seen:
            return []
        _seen = _seen | {id(value)}
    if isinstance(value, dict):
        for v in value.values():
            out.extend(_flatten_technology_values(v, _depth + 1, _seen))
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            out.extend(_flatten_technology_values(v, _depth + 1, _seen))
    elif isinstance(value, str):
        out.append(value.lower())
    return out


def select_wordlists_for_technology(technology: Optional[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """
    Given a caller-supplied technology-intelligence dict (see module
    docstring, decision #1 — this is the eventual tech_fingerprint.py
    output, not yet buildable against a real interface), return
    [(wordlist_filename, framework_label), ...] for every recognized
    framework/CMS mentioned anywhere in it. Matching is a case-insensitive
    substring search across every string value found in the structure, so
    callers can pass shapes as simple as {"cms": "WordPress"} or as rich as
    {"frameworks": [{"name": "Laravel", "confidence": "HIGH"}]}.
    """
    if not technology:
        return []
    haystack = " ".join(_flatten_technology_values(technology))
    # Word-boundary rather than bare substring matching: a WAF product named
    # "Djangoshield" or a library called "wordpressify" is not evidence the
    # target runs Django or WordPress, and each false match spends a whole
    # framework wordlist of requests on the target for nothing. Compound names
    # that genuinely do imply the framework ("laravel-mix") still match,
    # because a hyphen is a word boundary.
    return [
        (wordlist_name, keyword)
        for keyword, wordlist_name in _FRAMEWORK_WORDLISTS.items()
        if re.search(rf"\b{re.escape(keyword)}\b", haystack)
    ]


# ---------------------------------------------------------------------------
# Shared HTTP client (GET only — see module docstring, decision #6)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single HTTP GET against `url` without following redirects
    (redirects are inspected, not silently followed — see
    classify_response / _RECURSION_WORTHY_TYPES).
    """
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "body": None,
        "body_truncated": False, "final_url": url, "elapsed_seconds": None, "error": None,
    }
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)

    resp = None
    try:
        resp = requests.get(url, timeout=timeout, headers=req_headers, allow_redirects=False, stream=True)
        try:
            raw = resp.raw.read(max_body_bytes + 1, decode_content=True)
        except Exception:
            # Fallback for adapters/mocks without a usable .raw. It must stay
            # bounded: `resp.content` materialises the *entire* body before the
            # slice runs, so a 5 MB response (or a decompression bomb) was
            # fully resident in memory per worker before being truncated to
            # 128 KB. iter_content stops as soon as the cap is reached.
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
                # body, so it is used only when the server declared a size
                # that is safe to hold; an undeclared or oversized body is
                # reported as unread rather than swallowed whole.
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
    # No TooManyRedirects clause: allow_redirects=False, so requests never
    # follows a chain and can never raise it. RequestException below covers it
    # regardless, should that ever change.
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request failed: {exc}"
    finally:
        if resp is not None:
            resp.close()
    return result


# ---------------------------------------------------------------------------
# Response classification (avoids treating every non-404 as confirmed
# content — see module docstring, decision #2)
# ---------------------------------------------------------------------------

def _normalized_location(resp: Dict[str, Any], request_url: str) -> Optional[str]:
    """
    A redirect target with the requested path factored out, so a catch-all
    "everything redirects to /login" is recognisable across probes and a
    "/admin -> /admin/" style self-redirect is not mistaken for one.
    """
    location = _ci_get(resp.get("headers") or {}, "Location")
    if not location:
        return None
    try:
        absolute = urllib.parse.urljoin(request_url, location)
    except ValueError:
        return location
    return _structural_signature(absolute, request_url)


def _probe_catch_all(root: str, timeout: float) -> Dict[str, Any]:
    """
    Fingerprint how `root` answers a path that does not exist.

    Sends BASELINE_PROBE_COUNT random probes with deliberately *different path
    lengths*. Two probes rather than one is what makes the result trustworthy:

      * If both answers are byte-identical, the catch-all is static and a hash
        comparison is enough.
      * If they differ, the catch-all is dynamic. Comparing a candidate
        against a single dynamic sample is meaningless, so the structural
        signature (requested path and volatile values removed) is used
        instead, and `dynamic` is recorded so the caller can say so in
        evidence.
      * If the two answers disagree on *status code*, the root's behaviour is
        not stable enough to judge anything against; the baseline is marked
        unusable rather than being trusted.

    Returns a dict describing the root's not-found behaviour. `available` is
    False when no probe got an answer at all — which is emphatically not the
    same as "this root has no catch-all", and callers must degrade confidence
    rather than assume a clean baseline (see classify_response).
    """
    root = _ensure_trailing_slash(root)
    samples: List[Dict[str, Any]] = []
    errors: List[str] = []
    for index in range(max(1, BASELINE_PROBE_COUNT)):
        # Alternating lengths: a catch-all page that echoes the requested path
        # then produces two different body lengths, which is precisely the
        # signal that tells a dynamic catch-all from a static one.
        token = uuid.uuid4().hex[: 12 + index * 20]
        probe_url = f"{root}reconhound-nonexistent-check-{token}"
        resp = fetch_url(probe_url, timeout=timeout)
        if resp["status"] != "found":
            errors.append(resp.get("error") or "request failed")
            continue
        normalized = re.sub(r"\s+", " ", resp.get("body") or "").strip()
        length, digest = _content_signature(resp.get("body") or "")
        samples.append({
            "status_code": resp["status_code"],
            "content_length": length,
            "body_hash": digest,
            # Kept (bounded) so a candidate can be compared to the baseline by
            # content overlap rather than by length alone — see matches_catch_all.
            "normalized_body": normalized[:_BASELINE_SAMPLE_BYTES],
            "structural_hash": _structural_signature(resp.get("body") or "", probe_url),
            "location_hash": _normalized_location(resp, probe_url),
            "content_type": (_ci_get(resp["headers"], "Content-Type") or "").split(";")[0].strip().lower(),
        })

    if not samples:
        return {"available": False, "root": root, "probe_errors": errors}

    statuses = {s["status_code"] for s in samples}
    stable_status = len(statuses) == 1
    # A baseline built from responses the server refused (429) or failed to
    # produce (5xx) is not a "this path does not exist" fingerprint — it is a
    # snapshot of the server declining to answer. Trusting one inverts the
    # whole differential test: against a rate-limiting host the baseline came
    # back "everything is 429", so every subsequent 429 matched it and was
    # counted as an authoritative negative result. Blocked is not absent.
    unusable_status = any(s == 429 or 500 <= s < 600 for s in statuses)
    return {
        "available": True,
        "usable": stable_status and not unusable_status,
        # The statuses this root hands out to *random, certainly-absent*
        # paths while in an error mode. A candidate answering with one of
        # these was not tested — the root is failing or throttling
        # indiscriminately — so it must be reported as blocked rather than as
        # either a discovery or a negative result.
        "error_mode_statuses": sorted(statuses) if unusable_status else [],
        "unusable_reason": (
            "baseline probes were rate-limited or failed server-side"
            if unusable_status else
            (None if stable_status else "baseline probes returned inconsistent status codes")
        ),
        "root": root,
        # Kept for backwards compatibility with the single-probe shape.
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
    True if `resp` looks like the root's catch-all "nothing here" response.

    Applies at *every* status code, not only 2xx. That generalisation is the
    substantive fix: an application that redirects every unknown path to
    /login, or that sits behind an authentication wall answering 401 to
    everything, previously produced one MEDIUM-confidence endpoint record per
    wordlist entry — 116 phantom endpoints in a 4-entry-wordlist reproduction,
    each of which surface_mapper turned into an endpoint asset and handed on
    to exposure_scan as real surface to probe.
    """
    if not baseline or not baseline.get("available") or not baseline.get("usable", True):
        return False

    # A baseline may also arrive in the older single-sample shape (scalar
    # status_code/body_hash/content_length), either from a caller that built
    # one itself or from a sibling module sharing this vocabulary, so every
    # lookup falls back to the scalar key.
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

    # A redirect carries almost no body; the target is the identifying part.
    if status in _REDIRECT_STATUS_CODES:
        location_hashes = set(baseline.get("location_hashes") or [])
        if location_hashes:
            return _normalized_location(resp, url) in location_hashes

    normalized = re.sub(r"\s+", " ", body).strip()
    samples = baseline.get("normalized_bodies") or []

    # Content-overlap comparison. This runs for dynamic baselines too: a
    # catch-all whose body genuinely differs per request is exactly the case
    # the structural signature can miss, and comparing *what the page says*
    # rather than how long it is, is the only thing left that distinguishes
    # "another rendering of the error page" from "a real response".
    if samples and _content_matches_samples(normalized, samples):
        return True

    # Length agreement alone is never sufficient (it discarded genuine
    # endpoints that merely happened to be about as long as the error page),
    # and for a dynamic catch-all it is not even suggestive. It survives only
    # as a fallback for an externally supplied baseline that carries no body
    # sample, and only for a body too short to carry distinguishing content.
    if not baseline.get("dynamic") and not samples and length <= 64:
        return any(_lengths_close(length, b) for b in _multi("content_lengths", "content_length"))
    return False


def classify_response(
    resp: Dict[str, Any], baseline: Optional[Dict[str, Any]], url: str = "",
) -> Tuple[str, str, List[str]]:
    """
    Classify a fetch_url() result into a discovery_type + confidence +
    supporting notes.

    Existence is judged *differentially*, against the root's catch-all
    baseline, rather than by mapping a status code straight to a verdict. A
    response only says something about a path when it differs from what the
    root returns for a path that certainly does not exist. Where no usable
    baseline exists, that judgement cannot be made, so confidence is capped
    and the reason is stated in the notes instead of being assumed away.
    """
    status = resp.get("status_code")
    if status is None:
        return DT_ERROR, CONFIDENCE_LOW, ["no status code available (request failed)"]

    baseline_available = bool(baseline and baseline.get("available") and baseline.get("usable", True))

    # Checked before anything else: if the root returns this same status to
    # random paths that certainly do not exist, the response carries no
    # information about *this* path. Without this, a host answering 503 (or a
    # gateway answering 502) to everything produced one `server_error_response`
    # endpoint record per wordlist entry — request failure read as endpoint
    # presence, the very thing the differential test exists to prevent.
    error_mode = set((baseline or {}).get("error_mode_statuses") or [])
    if status in error_mode:
        return DT_BLOCKED, CONFIDENCE_LOW, [
            f"this directory root returns HTTP {status} to random, certainly-absent paths as "
            f"well, so the path was not effectively tested (blocked, not checked-and-absent)",
        ]

    if matches_catch_all(resp, baseline, url):
        note = (
            "response matches this directory root's catch-all fingerprint "
            f"(HTTP {status}"
            + (", dynamic body" if baseline and baseline.get("dynamic") else "")
            + "); the path is not evidenced as existing"
        )
        if status == 404:
            return DT_NOT_FOUND, CONFIDENCE_HIGH, [note]
        if 200 <= status < 300:
            # The classic HTTP-200 soft 404 keeps its established name: it is
            # shared vocabulary with exposure_scan.py/api_recon.py and is
            # already stored as an endpoint attribute by surface_mapper.
            return DT_POSSIBLE_SOFT_404, CONFIDENCE_LOW, [note]
        # Catch-alls on other statuses (a blanket redirect to /login, an
        # authentication wall answering 401 to every path) had no
        # representation at all before and are new, purely additive vocabulary.
        return DT_CATCH_ALL_MATCH, CONFIDENCE_LOW, [note]

    if status == 404:
        return DT_NOT_FOUND, CONFIDENCE_HIGH, []

    if status == 429:
        return DT_RATE_LIMITED, CONFIDENCE_LOW, [
            "HTTP 429 Too Many Requests — the server declined to answer, which says "
            "nothing about whether this path exists; enumeration is incomplete here",
        ]

    # Notes/confidence below are deliberately weaker without a baseline: with
    # no reference point, "this response differs from not-found" is unproven.
    unbaselined = [] if baseline_available else [
        "no usable catch-all baseline for this directory root "
        f"({(baseline or {}).get('probe_errors') or 'baseline responses were unstable'}); "
        "a catch-all response cannot be ruled out, so confidence is capped"
    ]

    if status in _REDIRECT_STATUS_CODES:
        conf = CONFIDENCE_MEDIUM if baseline_available else CONFIDENCE_LOW
        return DT_REDIRECT, conf, [f"HTTP {status} redirect response"] + unbaselined
    if status in (401, 403):
        conf = CONFIDENCE_MEDIUM if baseline_available else CONFIDENCE_LOW
        return DT_ACCESS_RESTRICTED, conf, [f"HTTP {status} access-restricted response"] + unbaselined
    if status == 405:
        conf = CONFIDENCE_MEDIUM if baseline_available else CONFIDENCE_LOW
        return DT_METHOD_NOT_ALLOWED, conf, [
            "HTTP 405 Method Not Allowed — the path is routed, but GET is not accepted",
        ] + unbaselined
    if 500 <= status < 600:
        return DT_SERVER_ERROR, CONFIDENCE_LOW, [
            f"HTTP {status} server error — the request failed on the server side; "
            f"existence is uncertain and this is not confirmation the path exists",
        ] + unbaselined
    if 200 <= status < 300:
        if not baseline_available:
            return DT_CONTENT_CONFIRMED, CONFIDENCE_MEDIUM, list(unbaselined)
        if (baseline or {}).get("dynamic"):
            # The root's own not-found response differs between two identical
            # probes. Catch-all matching still runs (and this response did not
            # match), but a body that varies per request is inherently harder
            # to rule out than a fixed template, so HIGH would overstate what
            # the baseline can actually support.
            return DT_CONTENT_CONFIRMED, CONFIDENCE_MEDIUM, [
                "this directory root returns a different body to each request for a "
                "certainly-absent path, so a catch-all cannot be excluded with certainty",
            ]
        return DT_CONTENT_CONFIRMED, CONFIDENCE_HIGH, []
    return DT_UNEXPECTED_STATUS, CONFIDENCE_LOW, [f"unexpected HTTP status {status}"] + unbaselined


# ---------------------------------------------------------------------------
# 6/7. Parameter discovery + parameter intelligence
# ---------------------------------------------------------------------------

def extract_query_parameters(
    url: str, endpoint: Optional[str] = None, method: str = "GET", source: str = "url_query_string",
) -> List[Dict[str, Any]]:
    """Query-location parameters observed directly in a real, fetched URL."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return []
    endpoint = endpoint or (parsed.path or "/")
    out: List[Dict[str, Any]] = []
    seen = set()
    for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if name in seen:
            continue
        seen.add(name)
        out.append({
            "name": name, "location": "query", "method": method, "endpoint": endpoint,
            "data_type": _infer_data_type(value), "source": source,
            "confidence": CONFIDENCE_MEDIUM,
            "evidence": [f"Observed in the query string of {url}"],
        })
    return out


def infer_path_parameters(url: str) -> List[Dict[str, Any]]:
    """
    LOW-confidence, explicitly inferential: path segments that look like a
    dynamic identifier (numeric, UUID, Mongo-style ObjectId) rather than a
    confirmed URL template — this is pattern inference, not a discovered
    route definition, so confidence and evidence say so explicitly.
    """
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    segments = [s for s in path.split("/") if s]
    out: List[Dict[str, Any]] = []
    for idx, segment in enumerate(segments):
        if re.fullmatch(r"\d+", segment):
            data_type = "integer"
        elif _UUID_RE.match(segment):
            data_type = "uuid"
        elif _OBJECT_ID_RE.match(segment):
            data_type = "object_id"
        else:
            continue
        out.append({
            "name": f"path_segment_{idx}", "location": "path", "method": "GET", "endpoint": path,
            "data_type": data_type, "source": "endpoint_pattern_inference",
            "confidence": CONFIDENCE_LOW,
            "evidence": [f"Path segment {idx} of {path!r} ({segment!r}) matches a dynamic-identifier pattern; "
                         f"inferred, not a confirmed route template"],
        })
    return out


def _parse_soup(body: Optional[str]) -> Optional["BeautifulSoup"]:
    """
    Parse a response body once, returning None on empty or unparseable input.

    Sharing one parse between form extraction and link extraction matters:
    profiling a 237-page recursive run showed html.parser being invoked 474
    times — twice per response — for 25.8s of a 62s run, purely because the
    two extractors each built their own soup from the same body.
    """
    if not body:
        return None
    try:
        return BeautifulSoup(body, "html.parser")
    except Exception:
        return None


def extract_form_parameters(
    body: str, page_url: str, soup: Optional["BeautifulSoup"] = None,
) -> List[Dict[str, Any]]:
    """
    HTML <form> field extraction (query-location for GET forms,
    body-location for everything else). Malformed HTML degrades to an
    empty result rather than raising.

    `soup` optionally supplies an already-parsed document (see _parse_soup);
    when omitted the body is parsed here, so direct callers are unaffected.
    """
    if not body:
        return []
    try:
        soup = soup if soup is not None else _parse_soup(body)
        if soup is None:
            return []
        forms = soup.find_all("form")
    except Exception:
        return []

    out: List[Dict[str, Any]] = []
    for form in forms:
        method = (form.get("method") or "GET").strip().upper()
        if method not in ("GET", "POST"):
            method = "GET"
        location = "query" if method == "GET" else "body"
        action = form.get("action") or page_url
        try:
            endpoint = urllib.parse.urlsplit(urllib.parse.urljoin(page_url, action)).path or "/"
        except Exception:
            endpoint = page_url

        try:
            fields = form.find_all(["input", "select", "textarea"])
        except Exception:
            fields = []
        for field in fields:
            name = field.get("name")
            if not name:
                continue
            field_type = (field.get("type") or ("select" if field.name == "select" else "text")).lower()
            data_type = _FORM_FIELD_TYPE_MAP.get(field_type, "string")
            out.append({
                "name": name, "location": location, "method": method, "endpoint": endpoint,
                "data_type": data_type, "source": "html_form",
                "confidence": CONFIDENCE_MEDIUM,
                "evidence": [f"<{field.name}> field named {name!r} (type={field_type!r}) found in a "
                             f"<form method={method}> on {page_url}"],
            })
    return out


def extract_header_parameter_hints(
    body: Optional[str],
    headers: Optional[Dict[str, str]],
    page_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Header-location parameter hints: known auth/API header names literally
    referenced in fetched content, plus a WWW-Authenticate challenge if
    present. LOW/MEDIUM confidence — a name being mentioned does not
    confirm the server requires or accepts it.

    `page_url` names the endpoint the hint was observed on. It used to be
    omitted entirely, leaving `endpoint=None`; surface_mapper then fell back
    to the bare target, so every page mentioning "X-Api-Key" collapsed onto
    one host-level pseudo-endpoint and *which* endpoint the header belonged to
    was lost — an evidence-loss bug, and a source of duplicate observations.
    """
    haystack = body or ""
    endpoint = None
    if page_url:
        try:
            endpoint = urllib.parse.urlsplit(page_url).path or "/"
        except ValueError:
            endpoint = None

    out: List[Dict[str, Any]] = []
    for token in _HEADER_HINT_TOKENS:
        if re.search(rf"\b{re.escape(token)}\b", haystack, re.IGNORECASE):
            out.append({
                "name": token, "location": "header", "method": "GET", "endpoint": endpoint,
                "data_type": "string", "source": "content_reference",
                "confidence": CONFIDENCE_LOW,
                "evidence": [f"Header name {token!r} referenced in fetched response content"
                             + (f" at {page_url}" if page_url else "")],
            })

    www_auth = _ci_get(headers or {}, "WWW-Authenticate")
    if www_auth:
        out.append({
            "name": "Authorization", "location": "header", "method": "GET", "endpoint": endpoint,
            "data_type": "string", "source": "http_response_challenge",
            "confidence": CONFIDENCE_MEDIUM,
            "evidence": [f"WWW-Authenticate challenge observed: {www_auth}"],
        })
    return out


def discover_parameters(
    url: str,
    target: Optional[str] = None,
    body: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    store: Optional[PendingAssetsStore] = None,
) -> Dict[str, Any]:
    """
    Standalone parameter discovery for a single endpoint (responsibility
    #6, independently testable). If `body`/`headers` are not supplied, the
    URL is fetched live; if they are supplied (e.g. a fixture, or content
    already fetched by run_endpoint_discovery), no network request is
    made. Combines query/path/form/header parameter locations.
    """
    url = validate_endpoint_target(url, target=target)
    target = target or (urllib.parse.urlsplit(url).hostname or url)

    if body is None or headers is None:
        resp = fetch_url(url, timeout=timeout)
        if resp["status"] != "found":
            return {"url": url, "status": "error", "error": resp.get("error"), "parameters": []}
        body = resp.get("body")
        headers = resp["headers"]

    params: List[Dict[str, Any]] = []
    params.extend(extract_query_parameters(url))
    params.extend(infer_path_parameters(url))
    if _looks_textual(_ci_get(headers or {}, "Content-Type"), body):
        params.extend(extract_form_parameters(body, url))
        params.extend(extract_header_parameter_hints(body, headers, page_url=url))

    persistence_errors: List[str] = []
    err = _safe_store_add_many(store, [make_parameter_finding(p, target) for p in params])
    if err:
        persistence_errors.append(err)

    result: Dict[str, Any] = {"url": url, "status": "found", "parameters": params}
    if persistence_errors:
        result["persistence_errors"] = persistence_errors
    return result


# ---------------------------------------------------------------------------
# Link / API-reference extraction (bounded — feeds recursion, not a
# general-purpose crawler; see module docstring, decision #4, and
# context.md's crawler.py module boundary)
# ---------------------------------------------------------------------------

def extract_link_candidates(
    body: str, page_url: str, target: Optional[str] = None,
    soup: Optional["BeautifulSoup"] = None,
) -> List[str]:
    """
    Extract in-scope, http(s) candidate URLs from href/src/action
    attributes (structured, via BeautifulSoup) and from inline
    fetch()/axios-style JS calls plus quoted "/api/..." or "/graphql..."
    string literals (regex, since this also needs to catch references
    inside <script> blocks without a full JS parse — that depth belongs to
    js_analyzer.py, not here).
    """
    if not body:
        return []

    raw_refs: List[str] = []
    try:
        soup = soup if soup is not None else _parse_soup(body)
        if soup is not None:
            for tag_name, attr in _LINK_ATTR_TAGS.items():
                for tag in soup.find_all(tag_name):
                    value = tag.get(attr)
                    if value:
                        raw_refs.append(value)
    except Exception:
        pass

    raw_refs.extend(_JS_CALL_RE.findall(body))
    raw_refs.extend(_QUOTED_API_PATH_RE.findall(body))

    resolved = set()
    for ref in raw_refs:
        ref = ref.strip()
        if not ref or ref.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue
        try:
            abs_url = urllib.parse.urljoin(page_url, ref)
            parsed = urllib.parse.urlsplit(abs_url)
            host = parsed.hostname or ""
        except (ValueError, Exception):
            continue
        if parsed.scheme not in ("http", "https"):
            continue
        # Scope gate for content-derived hosts. _host_allowed (unlike
        # validate_endpoint_target) refuses an arbitrary IP literal, because a
        # page can link anywhere: without this an in-scope page could aim the
        # scanner at 169.254.169.254 or at any RFC1918 host it named.
        # `target=None` keeps the documented "no scope filtering requested"
        # behaviour for direct callers extracting links from a fixture.
        if target and not _host_allowed(host, target):
            continue
        # The fragment is never sent to a server, so keeping it only produced
        # duplicate requests and fragment-bearing endpoint identities
        # downstream; credentials in a link must not be re-sent or persisted.
        abs_url = _strip_userinfo(
            urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        )
        resolved.add(abs_url)
    return sorted(resolved)


# ---------------------------------------------------------------------------
# Correlation support: scope filtering and host-aware verification
# ---------------------------------------------------------------------------

def _live_path_index(current_endpoints: List[Dict[str, Any]]) -> Dict[str, set]:
    """
    Map hostname -> set of paths confirmed live in this run.

    Verification used to compare bare paths with no regard for host, so a
    historical "/admin" on blog.example.com was reported `currently_verified`
    because *some other* subdomain answered on "/admin" this run — a
    correlation claiming evidence it does not have. The key ("" for a
    path-only record) keeps the host qualification.
    """
    index: Dict[str, set] = {}
    for endpoint in current_endpoints:
        url = endpoint.get("url")
        if not url:
            continue
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        index.setdefault(_idna_normalize(parsed.hostname or ""), set()).add(parsed.path or "/")
    return index


def _evidence_list(value: Any, fallback: str) -> List[str]:
    """
    Coerce a caller-supplied `evidence` field into a list of strings.

    `list(value)` is wrong for the single most likely mistake a producing
    module can make: a bare string. It iterates the string character by
    character, so one evidence sentence became two dozen single-character
    "evidence" entries in the asset graph — evidence corruption from a
    perfectly reasonable input shape. Mirrors surface_mapper's `_as_str_list`,
    which exists for the same reason.
    """
    if value is None or value == []:
        return [fallback]
    if isinstance(value, str):
        return [value] if value.strip() else [fallback]
    if isinstance(value, (list, tuple, set)):
        items = [str(v) for v in value if v is not None and str(v).strip()]
        return items or [fallback]
    return [str(value)]


def _correlation_reference(
    raw_url: str, target: str, live_index: Dict[str, set],
) -> Optional[Tuple[str, str, bool]]:
    """
    Resolve one caller-supplied historical/JS reference to (path, host,
    currently_verified), or None when it is out of scope.

    The scope check is the important half. These records come from other
    modules' output, which in turn came from third-party archives (Wayback)
    and from JavaScript. Persisting them unfiltered meant a single
    "https://attacker.invalid/pwn" entry became a `historical_endpoint_reference`
    attributed to the engagement's target, and surface_mapper duly minted
    `attacker.invalid` as a hostname asset of an example.com engagement.
    A reference with no host at all (a bare "/path") is attributed to the
    target, which is the only host it can sensibly belong to.
    """
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError:
        return None
    host = parsed.hostname or ""
    if host and not _host_allowed(host, target):
        return None
    path = parsed.path or (raw_url if not host else "/")
    host_key = _idna_normalize(host) if host else ""
    if host_key:
        verified = path in live_index.get(host_key, set())
    else:
        # Host-less reference: verified if ANY in-scope host answered on it,
        # since the record itself does not say which host it belonged to.
        verified = any(path in paths for paths in live_index.values())
    return path, host, verified


# ---------------------------------------------------------------------------
# 8. Historical parameter correlation (wayback_intel.py boundary — see
# module docstring, decision #1; this module implements none of
# wayback_intel.py's own responsibilities)
# ---------------------------------------------------------------------------

def correlate_historical_parameters(
    current_endpoints: List[Dict[str, Any]],
    historical_data: Optional[List[Dict[str, Any]]],
    target: str,
    store: Optional[PendingAssetsStore] = None,
) -> Dict[str, Any]:
    """
    Correlate caller-supplied historical endpoint/parameter records
    against this run's live discoveries. Expected shape per item (the
    eventual wayback_intel.py output — see module docstring):

        {"url" or "endpoint": str, "parameters": [{"name": str,
         "location": str, "method": str, "data_type": str}, ...],
         "evidence": [str, ...], "observed_at": str, "source": str}

    Historical items are never presented as currently live: each derived
    record carries `currently_verified` (True only if the same path also
    appears in `current_endpoints` from this run) and confidence is capped
    at MEDIUM even then — historical presence plus a live discovery is
    still not proof the historical parameter/behavior still applies.
    """
    if not historical_data:
        return {"endpoints": [], "parameters": [], "out_of_scope_skipped": 0,
                "note": "no historical_data supplied"}

    live_index = _live_path_index(current_endpoints)
    endpoints_out: List[Dict[str, Any]] = []
    params_out: List[Dict[str, Any]] = []
    pending: List[Dict[str, Any]] = []
    out_of_scope = 0

    for item in historical_data:
        if not isinstance(item, dict):
            continue
        raw_url = item.get("url") or item.get("endpoint")
        if not raw_url or not isinstance(raw_url, str):
            continue
        resolved = _correlation_reference(raw_url, target, live_index)
        if resolved is None:
            out_of_scope += 1
            continue
        path, host, currently_verified = resolved
        raw_url = _strip_userinfo(raw_url)
        source = item.get("source", "wayback_intel.py")

        endpoint_record = {
            "url": raw_url, "path": path, "host": host or None, "historical": True,
            "currently_verified": currently_verified,
            "confidence": CONFIDENCE_MEDIUM if currently_verified else CONFIDENCE_LOW,
            "evidence": _evidence_list(item.get("evidence"), f"Historical reference from {source}"),
            "observed_at": item.get("observed_at"),
            "source": source,
        }
        endpoints_out.append(endpoint_record)
        pending.append(make_finding(
            finding_type="historical_endpoint_reference", target=target, value=endpoint_record,
            evidence=endpoint_record["evidence"], confidence=endpoint_record["confidence"],
            metadata={"historical": True, "currently_verified": currently_verified, "path": path},
        ))

        for p in item.get("parameters") or []:
            if not isinstance(p, dict) or not p.get("name"):
                continue
            param_record = {
                "name": p["name"], "location": p.get("location", "query"),
                "method": p.get("method", "GET"), "endpoint": path,
                "data_type": p.get("data_type", "unknown"), "source": "historical_intelligence",
                "confidence": CONFIDENCE_LOW, "historical": True,
                "currently_verified": currently_verified,
                "evidence": [f"Parameter {p['name']!r} observed historically at {raw_url} (via {source})"],
            }
            params_out.append(param_record)
            pending.append(make_parameter_finding(param_record, target))

    result: Dict[str, Any] = {
        "endpoints": endpoints_out, "parameters": params_out,
        "out_of_scope_skipped": out_of_scope,
    }
    err = _safe_store_add_many(store, pending)
    if err:
        result["errors"] = [err]
    return result


# ---------------------------------------------------------------------------
# 9. JavaScript parameter correlation (js_analyzer.py boundary — see
# module docstring, decision #1; this module implements none of
# js_analyzer.py's own responsibilities)
# ---------------------------------------------------------------------------

def correlate_javascript_parameters(
    current_endpoints: List[Dict[str, Any]],
    js_data: Optional[List[Dict[str, Any]]],
    target: str,
    store: Optional[PendingAssetsStore] = None,
) -> Dict[str, Any]:
    """
    Correlate caller-supplied JS-derived endpoint/parameter references
    against this run's live discoveries. Expected shape per item (the
    eventual js_analyzer.py output — see module docstring):

        {"url" or "endpoint": str, "parameters": [{"name": str,
         "location": str, "method": str, "data_type": str}, ...],
         "evidence": [str, ...], "source_file": str}

    JS-sourced references come from code the target itself currently
    serves, so they default to MEDIUM confidence (stronger signal than
    historical-only data) — but are still marked `currently_verified` only
    when independently confirmed live in this run's own enumeration.
    """
    if not js_data:
        return {"endpoints": [], "parameters": [], "out_of_scope_skipped": 0,
                "note": "no js_data supplied"}

    live_index = _live_path_index(current_endpoints)
    endpoints_out: List[Dict[str, Any]] = []
    params_out: List[Dict[str, Any]] = []
    pending: List[Dict[str, Any]] = []
    out_of_scope = 0

    for item in js_data:
        if not isinstance(item, dict):
            continue
        raw_url = item.get("url") or item.get("endpoint")
        if not raw_url or not isinstance(raw_url, str):
            continue
        resolved = _correlation_reference(raw_url, target, live_index)
        if resolved is None:
            out_of_scope += 1
            continue
        path, host, currently_verified = resolved
        raw_url = _strip_userinfo(raw_url)
        source_file = item.get("source_file", "js_analyzer.py")

        endpoint_record = {
            "url": raw_url, "path": path, "host": host or None, "js_derived": True,
            "currently_verified": currently_verified, "confidence": CONFIDENCE_MEDIUM,
            "evidence": _evidence_list(item.get("evidence"), f"JavaScript reference from {source_file}"),
            "source_file": source_file,
        }
        endpoints_out.append(endpoint_record)
        pending.append(make_finding(
            finding_type="javascript_endpoint_reference", target=target, value=endpoint_record,
            evidence=endpoint_record["evidence"], confidence=endpoint_record["confidence"],
            metadata={"js_derived": True, "currently_verified": currently_verified, "path": path},
        ))

        for p in item.get("parameters") or []:
            if not isinstance(p, dict) or not p.get("name"):
                continue
            param_record = {
                "name": p["name"], "location": p.get("location", "query"),
                "method": p.get("method", "GET"), "endpoint": path,
                "data_type": p.get("data_type", "unknown"), "source": "javascript_reference",
                "confidence": CONFIDENCE_MEDIUM, "js_derived": True,
                "currently_verified": currently_verified,
                "evidence": [f"Parameter {p['name']!r} referenced in JS from {source_file} for {raw_url}"],
            }
            params_out.append(param_record)
            pending.append(make_parameter_finding(param_record, target))

    result: Dict[str, Any] = {
        "endpoints": endpoints_out, "parameters": params_out,
        "out_of_scope_skipped": out_of_scope,
    }
    err = _safe_store_add_many(store, pending)
    if err:
        result["errors"] = [err]
    return result


# ---------------------------------------------------------------------------
# Enumeration state (visited-set, request budget, error log, soft-404
# cache — shared by every enumeration entry point below)
# ---------------------------------------------------------------------------

class _EnumerationState:
    """
    Shared, thread-safe state for one enumeration: visited set, request
    budget, per-root catch-all baselines, error log and the rate-limit
    tripwire.

    Every counter is mutated from worker threads, so all of them are behind
    the lock. `negative_results` in particular used to be a bare `+= 1` from
    N workers — a read-modify-write that is not atomic and silently
    under-counted the negative-result total the summary reports.
    """

    def __init__(
        self,
        target: str,
        store: Optional[PendingAssetsStore],
        max_requests: int,
        max_depth: int,
        dir_entries: List[str],
        api_entries: List[str],
        max_baselines: int = DEFAULT_MAX_BASELINES,
    ):
        self.target = target
        self.store = store
        self.max_requests = max_requests
        self.max_depth = max_depth
        self.dir_entries = dir_entries
        self.api_entries = api_entries
        self.max_baselines = max_baselines
        self._lock = threading.Lock()
        self._visited = set()
        self.request_count = 0
        self.negative_results = 0
        self.catch_all_matches = 0
        self.blocked_probes = 0
        self.failed_probes = 0
        self.budget_exhausted = False
        self.cancelled = False
        self.errors: List[Dict[str, Any]] = []
        self._baseline_lock = threading.RLock()
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}
        self._baseline_locks: Dict[str, threading.Lock] = {}
        self._rate_limited_roots: Dict[str, int] = {}
        self.rate_limited_roots: set = set()
        self.retry_after_seen: List[str] = []

    # -- visited set / budget -------------------------------------------

    def mark_visited(self, normalized_url: str) -> bool:
        with self._lock:
            if normalized_url in self._visited:
                return False
            self._visited.add(normalized_url)
            return True

    def unmark_visited(self, normalized_url: str) -> None:
        """
        Undo a mark_visited() for a URL that was never actually requested.

        Submission marks a URL visited and *then* reserves budget; when the
        reservation fails the URL was neither probed nor probeable, so leaving
        it in the visited set records it as "already handled" and would
        suppress it on a later, better-budgeted pass.
        """
        with self._lock:
            self._visited.discard(normalized_url)

    def budget_remaining(self) -> int:
        with self._lock:
            return max(0, self.max_requests - self.request_count)

    def reserve_request(self) -> bool:
        with self._lock:
            if self.request_count >= self.max_requests:
                self.budget_exhausted = True
                return False
            self.request_count += 1
            return True

    def release_request(self) -> None:
        """
        Return a reservation for a probe that was never actually sent.

        Budget is reserved at *submission* time, before a worker discovers
        that the candidate is out of scope or that its root has been tripped
        by the rate limiter. Without a release, `requests_made` counts
        requests that were never issued — so a working tripwire looked as
        though it had saved nothing — and the unspent budget could not be
        used on roots that were still answering.
        """
        with self._lock:
            if self.request_count > 0:
                self.request_count -= 1

    # -- counters --------------------------------------------------------

    def count_negative(self, catch_all: bool = False) -> None:
        with self._lock:
            self.negative_results += 1
            if catch_all:
                self.catch_all_matches += 1

    def count_blocked(self) -> None:
        with self._lock:
            self.blocked_probes += 1

    def count_failed(self) -> None:
        with self._lock:
            self.failed_probes += 1

    def record_error(self, stage: str, url: str, message: str) -> None:
        with self._lock:
            # The error log is bounded: a host that refuses every connection
            # otherwise produces one dict per probed path, and the summary is
            # serialised into the report. The count is preserved separately.
            if len(self.errors) < 500:
                self.errors.append({"stage": stage, "url": url, "error": message, "timestamp": _now()})
            elif len(self.errors) == 500:
                self.errors.append({"stage": "errors_truncated", "url": "",
                                    "error": "further per-request errors suppressed", "timestamp": _now()})

    # -- rate-limit tripwire ---------------------------------------------

    def note_rate_limited(self, root: str, retry_after: Optional[str]) -> None:
        """
        Record an HTTP 429 for `root` and trip the root out of enumeration
        once RATE_LIMIT_TRIP_THRESHOLD consecutive 429s have arrived.

        Past that point every further request returns 429 regardless of
        whether the path exists, so continuing produces no information while
        still generating load on the target. The run is instead marked
        incomplete for that root — an explicit "blocked, not tested" outcome
        rather than a false "nothing found there".
        """
        with self._lock:
            count = self._rate_limited_roots.get(root, 0) + 1
            self._rate_limited_roots[root] = count
            if retry_after and retry_after not in self.retry_after_seen and len(self.retry_after_seen) < 10:
                self.retry_after_seen.append(retry_after)
            if count >= RATE_LIMIT_TRIP_THRESHOLD:
                self.rate_limited_roots.add(root)

    def note_answered(self, root: str) -> None:
        """A non-429 answer resets that root's consecutive-429 counter."""
        with self._lock:
            if self._rate_limited_roots.get(root):
                self._rate_limited_roots[root] = 0

    def is_rate_limited(self, root: str) -> bool:
        with self._lock:
            return root in self.rate_limited_roots

    # -- catch-all baselines ---------------------------------------------

    def get_baseline(self, url: str, timeout: float) -> Dict[str, Any]:
        """
        The catch-all fingerprint for the directory root `url` lives in.

        Baselines are per directory root, not per origin: an app that serves
        an HTML error page under "/" commonly answers "/api/" with a JSON
        error envelope, and judging "/api/v1/users" against the HTML baseline
        classified every API path as confirmed content.

        Cost is capped two ways. The number of distinct baselines is bounded
        by `max_baselines` — beyond it, the nearest already-cached ancestor
        root is reused, and failing that the origin's — and each probe is
        charged to the same request budget as any other request, so
        fingerprinting can never silently exceed the caller's limit.
        """
        root = _candidate_root_of(url)

        def _resolve_cached() -> Optional[Dict[str, Any]]:
            """Cached baseline for `root` if it is final. Caller holds the lock."""
            cached = self._baseline_cache.get(root)
            if cached is None:
                return None
            # A *failed* baseline is retried a bounded number of times rather
            # than cached as final. One transient timeout on the very first
            # probe otherwise disabled catch-all detection for that root for
            # the rest of the run, turning every subsequent soft-404 into a
            # reported discovery — a transient provider failure becoming an
            # authoritative judgement, which is exactly what must not happen.
            if cached.get("available") or cached.get("attempts", 1) >= BASELINE_MAX_ATTEMPTS:
                return cached
            return None

        with self._baseline_lock:
            resolved = _resolve_cached()
            if resolved is not None:
                return resolved
            if root not in self._baseline_cache and len(self._baseline_cache) >= self.max_baselines:
                fallback = self._nearest_cached_ancestor(root)
                if fallback is not None:
                    return fallback
                return {"available": False, "root": root,
                        "probe_errors": ["baseline cache limit reached"]}
            # One lock per root, so N workers arriving at the same new root
            # take one baseline between them instead of N. Without it, eight
            # threads hitting one root sent eight independent fingerprints
            # (16 requests) — a request multiplier proportional to the worker
            # count, charged to the operator's budget for no extra information.
            root_lock = self._baseline_locks.setdefault(root, threading.Lock())

        # Probed outside the shared lock so one slow root cannot serialise the
        # whole pool; the per-root lock still admits exactly one prober.
        with root_lock:
            with self._baseline_lock:
                resolved = _resolve_cached()
                if resolved is not None:
                    return resolved
                attempts = self._baseline_cache.pop(root, {}).get("attempts", 0)

            if not self.reserve_request():
                result = {"available": False, "root": root,
                          "probe_errors": ["request budget exhausted before baseline probe"]}
            else:
                # BASELINE_PROBE_COUNT requests are made; the first was
                # reserved above, so reserve the remainder rather than
                # overrunning the caller's budget.
                for _ in range(max(0, BASELINE_PROBE_COUNT - 1)):
                    self.reserve_request()
                result = _probe_catch_all(root, timeout)
            result["attempts"] = attempts + 1

            with self._baseline_lock:
                self._baseline_cache[root] = result
                return result

    def baselines(self) -> List[Dict[str, Any]]:
        """Snapshot of every catch-all baseline taken during this enumeration."""
        with self._baseline_lock:
            return list(self._baseline_cache.values())

    def _nearest_cached_ancestor(self, root: str) -> Optional[Dict[str, Any]]:
        """Closest cached parent-directory baseline of `root` (caller holds the lock)."""
        try:
            parsed = urllib.parse.urlsplit(root)
        except ValueError:
            return None
        prefix = f"{parsed.scheme}://{parsed.netloc}"
        segments = [s for s in (parsed.path or "/").split("/") if s]
        while segments:
            segments.pop()
            candidate = prefix + "/" + ("/".join(segments) + "/" if segments else "")
            cached = self._baseline_cache.get(candidate)
            if cached is not None:
                return cached
        return self._baseline_cache.get(prefix + "/")


# Task tuple: (url, category, discovery_source, technology_association)
_Task = Tuple[str, str, str, Optional[str]]


def _probe_and_record(
    state: _EnumerationState,
    url: str,
    category: str,
    discovery_source: str,
    depth: int,
    technology_association: Optional[str],
    timeout: float,
) -> Tuple[Optional[Dict[str, Any]], List[_Task]]:
    """Fetch one candidate, classify it, extract parameters/candidates, persist, and report."""
    # Defence in depth: a task URL can originate from response content or from
    # a wordlist entry, neither of which is trusted to stay in scope. Scope is
    # re-checked immediately before the request rather than only where the URL
    # was produced, so no future queueing path can bypass it.
    try:
        url = validate_endpoint_target(url, target=state.target)
    except ScopeError as exc:
        state.release_request()
        state.record_error("scope", url, str(exc))
        return None, []

    root = _candidate_root_of(url)
    if state.is_rate_limited(root):
        # No request is sent, so the reservation goes back to the budget.
        state.release_request()
        state.count_blocked()
        return None, []

    resp = fetch_url(url, timeout=timeout)
    if resp["status"] != "found":
        # A request that never got an answer is not a negative result: the
        # path may well exist. It is counted separately and never persisted.
        state.count_failed()
        state.record_error("fetch", url, resp.get("error") or "request failed")
        return None, []

    counted_blocked = False
    if resp["status_code"] == 429:
        state.note_rate_limited(root, _ci_get(resp["headers"], "Retry-After"))
        state.count_blocked()
        counted_blocked = True
    else:
        state.note_answered(root)

    baseline = state.get_baseline(url, timeout)
    discovery_type, base_confidence, notes = classify_response(resp, baseline, url=url)

    if discovery_type in _NEGATIVE_TYPES:
        state.count_negative(catch_all=discovery_type != DT_NOT_FOUND)
        return None, []

    # 429 and transport failures are refusals to answer, not evidence about
    # the path. Persisting them as `endpoint_discovered` was the module's
    # single largest false-positive source: against a rate-limiting host every
    # wordlist entry became an endpoint asset in the graph, which exposure_scan
    # then re-probed as if it were real surface.
    if discovery_type in _NON_EVIDENTIAL_TYPES:
        # `counted_blocked` guards the case where a 429 is ALSO the root's
        # error-mode status, which would otherwise be tallied twice and
        # overstate blocked_probes against the request count.
        if discovery_type == DT_BLOCKED and not counted_blocked:
            state.count_blocked()
        return None, []

    headers = resp["headers"]
    body = resp.get("body")
    content_type = _ci_get(headers, "Content-Type")
    path = urllib.parse.urlsplit(url).path or "/"

    parameters: List[Dict[str, Any]] = []
    parameters.extend(extract_query_parameters(url, endpoint=path))
    parameters.extend(infer_path_parameters(url))

    new_candidates: List[_Task] = []
    if _looks_textual(content_type, body):
        # One parse shared by both extractors (see _parse_soup).
        soup = _parse_soup(body)
        parameters.extend(extract_form_parameters(body, url, soup=soup))
        parameters.extend(extract_header_parameter_hints(body, headers, page_url=url))
        links = extract_link_candidates(body, url, target=state.target, soup=soup)
        if len(links) > DEFAULT_MAX_LINK_CANDIDATES_PER_PAGE:
            state.record_error(
                "link_extraction", url,
                f"page yielded {len(links)} in-scope link candidates; only the first "
                f"{DEFAULT_MAX_LINK_CANDIDATES_PER_PAGE} are queued (per-page cap)",
            )
            links = links[:DEFAULT_MAX_LINK_CANDIDATES_PER_PAGE]
        for link in links:
            new_candidates.append((link, "link_extracted", "content_link_extraction", None))

    redirect_location = _ci_get(headers, "Location") if discovery_type == DT_REDIRECT else None
    if redirect_location and depth < state.max_depth:
        # A redirect's target is the part that carries new surface. Queuing it
        # (in scope only) replaces recursing into the redirecting directory,
        # which produced nothing but re-spent the whole wordlist per level.
        try:
            target_url = urllib.parse.urljoin(url, redirect_location)
            if _host_allowed(urllib.parse.urlsplit(target_url).hostname or "", state.target):
                new_candidates.append((target_url, "redirect_target", "redirect_location", None))
        except ValueError:
            pass

    if _is_directory_like(url) and discovery_type in _RECURSION_WORTHY_TYPES and depth < state.max_depth:
        for entry in state.dir_entries:
            new_candidates.append((_url_for_path(url, entry), _entry_kind(entry), "directories.txt(recursive)", technology_association))
        for entry in state.api_entries:
            new_candidates.append((_url_for_path(url, entry), "api", "api_endpoints.txt(recursive)", None))

    record: Dict[str, Any] = {
        "target": state.target,
        "path": path,
        "url": url,
        "normalized_url": _normalize_url(url),
        "method": "GET",
        "status_code": resp["status_code"],
        "content_type": content_type,
        "discovery_type": discovery_type,
        "category": category,
        "discovery_source": discovery_source,
        "technology_association": technology_association,
        "depth": depth,
        "redirect_location": redirect_location,
        # An explicit flag for the states that are observations of a response
        # rather than confirmation the path exists, so downstream never has to
        # re-derive that from the status code.
        "existence_uncertain": discovery_type in (DT_SERVER_ERROR, DT_UNEXPECTED_STATUS),
        "baseline_available": bool(baseline and baseline.get("available") and baseline.get("usable", True)),
        # Whether this hit would have been re-seeded had depth allowed it. The
        # depth gate suppresses candidate *generation* at the deepest level,
        # so "were candidates returned?" cannot detect truncation there — the
        # eligibility has to be reported explicitly.
        "recursion_eligible": _is_directory_like(url) and discovery_type in _RECURSION_WORTHY_TYPES,
        # Path- and volatility-normalised fingerprint of this response, used
        # by the run-level retrospective catch-all check when no usable
        # baseline could be taken (see _detect_dominant_catch_all).
        "response_signature": _structural_signature(body or "", url),
        "confidence": base_confidence,
        "evidence": [f"GET {url} returned HTTP {resp['status_code']}"] + notes,
        "timestamp": _now(),
    }

    deduped_params: List[Dict[str, Any]] = []
    seen_keys = set()
    for p in parameters:
        key = (p["name"], p["location"], p.get("endpoint"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped_params.append(p)

    # One read + one atomic write for this probe's whole result, rather than
    # a full rewrite of the shared file per finding (see add_many).
    pending = [make_finding(
        finding_type="endpoint_discovered", target=state.target, value=dict(record),
        evidence=record["evidence"], confidence=record["confidence"],
        metadata={
            "category": category, "discovery_source": discovery_source, "discovery_type": discovery_type,
            "technology_association": technology_association, "depth": depth, "url": url,
        },
    )]
    pending.extend(make_parameter_finding(p, state.target) for p in deduped_params)
    err = _safe_store_add_many(state.store, pending)
    if err:
        # The discovery is still returned and still reported; only its
        # durability was lost, and that is surfaced rather than swallowed.
        state.record_error("persistence", url, err)
        record["persisted"] = False

    record["parameters"] = deduped_params
    return record, new_candidates


def _run_probe_batch(
    state: _EnumerationState, tasks: List[_Task], depth: int, timeout: float, max_workers: int,
) -> List[Tuple[Optional[Dict[str, Any]], List[_Task]]]:
    """
    Run one depth-level of tasks concurrently, respecting the visited-set and
    request budget.

    Interruption is handled here rather than being allowed to escape: on
    KeyboardInterrupt the queued work is cancelled, the results already
    collected are returned, and `state.cancelled` tells the caller to finish
    and report a partial run. Previously the exception propagated out of
    run_endpoint_discovery, so the whole summary — including everything
    successfully discovered before the interrupt — was lost, and the
    ThreadPoolExecutor context manager first blocked waiting for every
    remaining queued task to run to completion (context.md §23 requires a
    graceful interrupt that saves before exiting).
    """
    results: List[Tuple[Optional[Dict[str, Any]], List[_Task]]] = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers))
    future_map: Dict[Any, str] = {}
    harvested: set = set()
    try:
        for url, category, discovery_source, technology_association in tasks:
            normalized = _normalize_url(url)
            if not state.mark_visited(normalized):
                continue
            if not state.reserve_request():
                # Never requested, so it must not stay recorded as visited.
                state.unmark_visited(normalized)
                break
            future_map[executor.submit(
                _probe_and_record, state, url, category, discovery_source, depth, technology_association, timeout,
            )] = url
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            harvested.add(future)
            try:
                results.append(future.result())
            except Exception as exc:  # a single bad task must not abort the batch
                state.record_error("probe", url, str(exc))
    except KeyboardInterrupt:
        state.cancelled = True
        state.record_error("cancelled", "", "interrupted by user; partial results retained")
        for future in future_map:
            future.cancel()
        # Harvest whatever already finished; nothing discovered is thrown away.
        # `except BaseException` is required, not defensive over-reach: an
        # interrupt delivered inside a worker is stored on that worker's
        # future, so result() re-raises KeyboardInterrupt here too — catching
        # only Exception let it escape the recovery path and lose the very
        # partial results this block exists to preserve.
        for future, url in future_map.items():
            if future in harvested or not future.done() or future.cancelled():
                continue
            harvested.add(future)
            try:
                results.append(future.result())
            except BaseException:
                continue
    finally:
        try:
            executor.shutdown(wait=not state.cancelled, cancel_futures=True)
        except TypeError:  # pragma: no cover - Python < 3.9
            executor.shutdown(wait=not state.cancelled)
    return results


# ---------------------------------------------------------------------------
# 1/2. Directory + file enumeration (single-wordlist, depth-0 convenience
# entry points — independently testable per the assignment's TESTING list)
# ---------------------------------------------------------------------------

def _enumerate_wordlist_kind(
    base_url: str,
    kind_filter: str,
    target: Optional[str],
    store: Optional[PendingAssetsStore],
    wordlists_dir: Optional[str],
    timeout: float,
    max_workers: int,
    max_requests: int,
) -> Dict[str, Any]:
    base_url = validate_endpoint_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)
    root = _enumeration_root(base_url)

    errors: List[Dict[str, Any]] = []
    try:
        entries = [e for e in load_wordlist("directories.txt", wordlists_dir) if _entry_kind(e) == kind_filter]
    except WordlistError as exc:
        errors.append({"stage": "wordlist_load", "wordlist": "directories.txt", "error": str(exc)})
        entries = []

    state = _EnumerationState(target, store, max_requests, 0, [], [])
    tasks: List[_Task] = [(_url_for_path(root, e), kind_filter, "directories.txt", None) for e in entries]
    results = _run_probe_batch(state, tasks, depth=0, timeout=timeout, max_workers=max_workers)

    endpoints = [record for record, _ in results if record is not None]
    return {
        "target": target, "base_url": base_url, "kind": kind_filter,
        "endpoints": endpoints, "negative_results_count": state.negative_results,
        "errors": errors + state.errors, "requests_made": state.request_count,
    }


def enumerate_directories(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    wordlists_dir: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_requests: int = 5000,
) -> Dict[str, Any]:
    """Directory enumeration (responsibility #1): the "directories.txt" entries ending in '/'."""
    return _enumerate_wordlist_kind(base_url, "directory", target, store, wordlists_dir, timeout, max_workers, max_requests)


def enumerate_files(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    wordlists_dir: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_requests: int = 5000,
) -> Dict[str, Any]:
    """File enumeration (responsibility #2): the "directories.txt" entries NOT ending in '/'."""
    return _enumerate_wordlist_kind(base_url, "file", target, store, wordlists_dir, timeout, max_workers, max_requests)


# ---------------------------------------------------------------------------
# 4. Framework-specific enumeration
# ---------------------------------------------------------------------------

def enumerate_framework_paths(
    base_url: str,
    technology: Optional[Dict[str, Any]],
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    wordlists_dir: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_requests: int = 5000,
) -> Dict[str, Any]:
    """
    WordPress/Laravel/Django path enumeration (responsibility #4) — only
    probes the wordlist(s) matching what `technology` actually names
    (select_wordlists_for_technology), never all three unconditionally.
    """
    base_url = validate_endpoint_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)
    root = _enumeration_root(base_url)

    wordlists = select_wordlists_for_technology(technology)
    if not wordlists:
        return {
            "target": target, "base_url": base_url, "technology": technology,
            "wordlists_used": [], "endpoints": [], "negative_results_count": 0,
            "errors": [], "requests_made": 0,
        }

    errors: List[Dict[str, Any]] = []
    tasks: List[_Task] = []
    for wordlist_name, tech_label in wordlists:
        try:
            entries = load_wordlist(wordlist_name, wordlists_dir)
        except WordlistError as exc:
            errors.append({"stage": "wordlist_load", "wordlist": wordlist_name, "error": str(exc)})
            continue
        for entry in entries:
            tasks.append((_url_for_path(root, entry), _entry_kind(entry), wordlist_name, tech_label))

    state = _EnumerationState(target, store, max_requests, 0, [], [])
    results = _run_probe_batch(state, tasks, depth=0, timeout=timeout, max_workers=max_workers)
    endpoints = [record for record, _ in results if record is not None]

    return {
        "target": target, "base_url": base_url, "technology": technology,
        "wordlists_used": [w for w, _ in wordlists],
        "endpoints": endpoints, "negative_results_count": state.negative_results,
        "errors": errors + state.errors, "requests_made": state.request_count,
    }


# ---------------------------------------------------------------------------
# 5. API endpoint discovery
# ---------------------------------------------------------------------------

def discover_api_endpoints(
    base_url: str,
    target: Optional[str] = None,
    store: Optional[PendingAssetsStore] = None,
    wordlists_dir: Optional[str] = None,
    api_roots: Optional[List[str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_requests: int = 5000,
) -> Dict[str, Any]:
    """
    API endpoint discovery (responsibility #5): probes the explicit
    canonical roots context.md names (/api/, /api/v1/, /api/v2/,
    /graphql/) plus every api_endpoints.txt entry under each of them. A
    non-404 root does not by itself claim "an API exists" — see
    classify_response; each hit carries its own confidence/evidence.
    """
    base_url = validate_endpoint_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)
    root = _enumeration_root(base_url)
    api_roots = api_roots or list(API_ROOTS)

    errors: List[Dict[str, Any]] = []
    try:
        api_entries = load_wordlist("api_endpoints.txt", wordlists_dir)
    except WordlistError as exc:
        errors.append({"stage": "wordlist_load", "wordlist": "api_endpoints.txt", "error": str(exc)})
        api_entries = []

    tasks: List[_Task] = []
    for api_root in api_roots:
        root_url = _url_for_path(root, api_root)
        tasks.append((root_url, "api", "api_root", None))
        for entry in api_entries:
            tasks.append((_url_for_path(root_url, entry), "api", "api_endpoints.txt", None))

    state = _EnumerationState(target, store, max_requests, 0, [], [])
    results = _run_probe_batch(state, tasks, depth=0, timeout=timeout, max_workers=max_workers)
    endpoints = [record for record, _ in results if record is not None]

    return {
        "target": target, "base_url": base_url, "api_roots": api_roots,
        "endpoints": endpoints, "negative_results_count": state.negative_results,
        "errors": errors + state.errors, "requests_made": state.request_count,
    }


# ---------------------------------------------------------------------------
# Retrospective catch-all detection (fallback for unbaselineable roots)
# ---------------------------------------------------------------------------

def _detect_dominant_catch_all(endpoints: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Detect, after the fact, that a run's "discoveries" are one catch-all page.

    This is the safety net for the case active probing cannot cover: when
    every baseline probe for a root failed, there is no fingerprint to judge
    against, so each individual 2xx has to be reported (capped at MEDIUM). But
    across the *whole run* a giveaway remains — if 80%+ of the confirmed hits
    return byte-for-byte the same page once the requested path and volatile
    values are normalised out, that is a catch-all, not dozens of distinct
    endpoints.

    Deliberately computed once over the finished result set rather than
    incrementally during the run, so the outcome does not depend on the order
    in which concurrent workers happened to finish.

    Returns a description of the dominant fingerprint, or None. Nothing is
    deleted or rewritten on the strength of it: the affected records keep
    their evidence and are annotated, and a conflict finding is raised
    (context.md §8 — preserve contradictions, never silently pick one answer).
    """
    confirmed = [
        e for e in endpoints
        if e.get("discovery_type") == DT_CONTENT_CONFIRMED and not e.get("baseline_available")
    ]
    if len(confirmed) < CATCH_ALL_DOMINANCE_MIN_SAMPLES:
        return None
    counts: Dict[str, int] = {}
    for endpoint in confirmed:
        signature = endpoint.get("response_signature")
        if signature:
            counts[signature] = counts.get(signature, 0) + 1
    if not counts:
        return None
    signature, count = max(counts.items(), key=lambda kv: kv[1])
    if count / len(confirmed) < CATCH_ALL_DOMINANCE_RATIO:
        return None
    return {"signature": signature, "matching": count, "considered": len(confirmed),
            "ratio": round(count / len(confirmed), 3)}


# ---------------------------------------------------------------------------
# 10. Full recursive orchestration (single-target)
# ---------------------------------------------------------------------------

def run_endpoint_discovery(
    base_url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    wordlists_dir: Optional[str] = None,
    technology: Optional[Dict[str, Any]] = None,
    historical_data: Optional[List[Dict[str, Any]]] = None,
    js_data: Optional[List[Dict[str, Any]]] = None,
    api_roots: Optional[List[str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> Dict[str, Any]:
    """
    Run every Module 10 responsibility against `base_url` and persist
    every completed discovery immediately to
    <output_dir>/pending_assets.json (crash-safe). Combines directory,
    file, framework-specific, and API enumeration into one bounded,
    depth-first-by-level BFS (see module docstring, decision #4), then
    runs historical/JS correlation against the resulting live discoveries.

    A failure enumerating one path (network error, wordlist error) does
    not stop the rest of the run — see summary["errors"].
    """
    base_url = validate_endpoint_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)
    root = _enumeration_root(base_url)
    api_roots = api_roots or list(API_ROOTS)

    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "target": target,
        "module": MODULE_NAME,
        "base_url": base_url,
        "started_at": _now(),
        "technology_used": technology,
        "endpoints": [],
        "parameters": [],
        "historical_correlation": {},
        "javascript_correlation": {},
        "negative_results_count": 0,
        "catch_all_matches": 0,
        "blocked_probes": 0,
        "failed_probes": 0,
        "requests_made": 0,
        "max_depth": max_depth,
        "max_depth_reached": False,
        "depth_truncated": False,
        "request_budget_exhausted": False,
        "rate_limited": False,
        "cancelled": False,
        # True when the run could not judge existence reliably (no usable
        # catch-all baseline, or the enumeration was blocked/truncated). This
        # is the flag that stops downstream reading an empty `endpoints` list
        # as "this host has no endpoints".
        "enumeration_conclusive": False,
        "errors": [],
    }

    dir_entries: List[str] = []
    try:
        dir_entries = load_wordlist("directories.txt", wordlists_dir)
    except WordlistError as exc:
        summary["errors"].append({"stage": "wordlist_load", "wordlist": "directories.txt", "error": str(exc)})

    api_entries: List[str] = []
    try:
        api_entries = load_wordlist("api_endpoints.txt", wordlists_dir)
    except WordlistError as exc:
        summary["errors"].append({"stage": "wordlist_load", "wordlist": "api_endpoints.txt", "error": str(exc)})

    framework_selection = select_wordlists_for_technology(technology)
    framework_tasks: List[_Task] = []
    for wordlist_name, tech_label in framework_selection:
        try:
            entries = load_wordlist(wordlist_name, wordlists_dir)
        except WordlistError as exc:
            summary["errors"].append({"stage": "wordlist_load", "wordlist": wordlist_name, "error": str(exc)})
            continue
        for entry in entries:
            framework_tasks.append((_url_for_path(root, entry), _entry_kind(entry), wordlist_name, tech_label))

    seed_tasks: List[_Task] = [(_url_for_path(root, e), _entry_kind(e), "directories.txt", None) for e in dir_entries]
    seed_tasks.extend(framework_tasks)
    for api_root in api_roots:
        root_url = _url_for_path(root, api_root)
        seed_tasks.append((root_url, "api", "api_root", None))
        seed_tasks.extend((_url_for_path(root_url, e), "api", "api_endpoints.txt", None) for e in api_entries)

    state = _EnumerationState(target, store, max_requests, max_depth, dir_entries, api_entries)

    depth = 0
    frontier = seed_tasks
    while frontier and depth <= max_depth and not state.budget_exhausted and not state.cancelled:
        results = _run_probe_batch(state, frontier, depth, timeout, max_workers)
        next_frontier: List[_Task] = []
        # Candidates are deduplicated on their raw URL string as the frontier
        # is built, not only later at submission time. Every page in a site
        # links to the same navigation, so a level of N pages each yielding M
        # links produced N*M task tuples of which only ~M were distinct — a
        # 217-page level with 500 links per page built a 109,000-entry
        # frontier and then paid full URL normalisation on every duplicate.
        # Measured on that workload: 20.2s of frontier processing for 239
        # actual requests. A cheap string-level set removes it before the
        # expensive normalisation runs.
        queued_raw: set = set()
        for record, new_candidates in results:
            if record is not None:
                summary["endpoints"].append(record)
                summary["parameters"].extend(record["parameters"])
            if depth < max_depth:
                for candidate in new_candidates:
                    if candidate[0] in queued_raw:
                        continue
                    queued_raw.add(candidate[0])
                    next_frontier.append(candidate)
        # next_frontier is built before its requests are spent, so a wide
        # level can allocate far more task tuples than the run could ever
        # probe. Truncating at the cap bounds memory without changing which
        # candidates are reachable within the request budget.
        if len(next_frontier) > DEFAULT_MAX_FRONTIER:
            summary["errors"].append({
                "stage": "frontier_cap", "wordlist": "",
                "error": f"depth {depth} produced {len(next_frontier)} candidates; truncated to "
                         f"{DEFAULT_MAX_FRONTIER} (frontier cap)",
            })
            next_frontier = next_frontier[:DEFAULT_MAX_FRONTIER]
        # Candidates that exist but were never explored because the level cap
        # stopped the descent — this is what `depth_truncated` reports.
        if depth >= max_depth and any(
            candidates or (record is not None and record.get("recursion_eligible"))
            for record, candidates in results
        ):
            summary["depth_truncated"] = True
        depth += 1
        frontier = next_frontier

    # `max_depth_reached` means the loop actually ran the deepest permitted
    # level. The previous formulation ("frontier left over at the end") could
    # never be true, because the level at max_depth deliberately queues no
    # successors — so the flag reported False on every run that truncated,
    # exactly the case it existed to signal. `depth_truncated` is the separate
    # question of whether unexplored candidates were left behind.
    summary["max_depth_reached"] = depth > max_depth
    summary["request_budget_exhausted"] = state.budget_exhausted
    summary["negative_results_count"] = state.negative_results
    summary["catch_all_matches"] = state.catch_all_matches
    summary["blocked_probes"] = state.blocked_probes
    summary["failed_probes"] = state.failed_probes
    summary["requests_made"] = state.request_count
    summary["cancelled"] = state.cancelled
    summary["rate_limited"] = bool(state.rate_limited_roots)
    if state.rate_limited_roots:
        summary["rate_limited_roots"] = sorted(state.rate_limited_roots)
    if state.retry_after_seen:
        summary["retry_after_seen"] = list(state.retry_after_seen)

    baselines = state.baselines()
    usable = [b for b in baselines if b.get("available") and b.get("usable", True)]
    summary["baselines_probed"] = len(baselines)
    summary["baseline_unavailable"] = bool(baselines) and not usable
    summary["catch_all_detected"] = any(
        b.get("status_code") is not None and b.get("status_code") != 404 for b in usable
    )

    dominant = _detect_dominant_catch_all(summary["endpoints"])
    summary["catch_all_suspected"] = bool(dominant)
    if dominant:
        summary["catch_all_evidence"] = dominant
        note = (
            f"{dominant['matching']} of {dominant['considered']} confirmed hits on this run "
            f"returned an identical response once the requested path and per-request values "
            f"were normalised out, and no usable catch-all baseline could be taken for the "
            f"affected root(s); these are most likely one catch-all page rather than distinct "
            f"endpoints"
        )
        for endpoint in summary["endpoints"]:
            if (endpoint.get("response_signature") == dominant["signature"]
                    and not endpoint.get("baseline_available")):
                endpoint["confidence"] = CONFIDENCE_LOW
                endpoint["catch_all_suspected"] = True
                endpoint["evidence"] = list(endpoint.get("evidence") or []) + [note]
        # The per-endpoint records were already persisted (crash-safe
        # persistence is immediate by design), so the contradiction is
        # recorded as its own finding rather than by rewriting history.
        err = _safe_store_add(store, make_finding(
            finding_type="endpoint_discovery_catch_all_suspected",
            target=target,
            value={"base_url": base_url, "root": root, **dominant},
            evidence=[note],
            confidence=CONFIDENCE_MEDIUM,
            metadata={"base_url": base_url, "conflicts_with": "endpoint_discovered"},
        ))
        if err:
            summary["errors"].append({"stage": "persistence", "wordlist": "", "error": err})

    # An enumeration is conclusive only when it ran to completion with a
    # usable notion of "this path does not exist". Anything else — no
    # baseline, rate limiting, an exhausted budget, an interrupt, or a run in
    # which most probes never got an answer — means absence of results is not
    # evidence of absence of endpoints, and downstream must not read it that way.
    # "Answered" means a response arrived AND was informative. A 429, or a
    # status the root hands out to random paths anyway, is a refusal: the path
    # was never effectively tested. Counting blocked probes here as well as
    # failed ones is deliberate belt-and-braces — a run in which every probe
    # was refused must never be reported as conclusive even if the rate-limit
    # tripwire has not fired, because the consequence of getting this wrong is
    # an authoritative "checked and not found" written into shared
    # negative-result memory, which then suppresses a later, unblocked attempt.
    unusable_probes = state.failed_probes + state.blocked_probes
    answered = state.request_count - unusable_probes
    mostly_unanswered = state.request_count > 0 and answered <= state.request_count * 0.5
    summary["enumeration_conclusive"] = bool(
        usable
        and not state.cancelled
        and not state.budget_exhausted
        and not state.rate_limited_roots
        and not mostly_unanswered
    )

    summary["historical_correlation"] = correlate_historical_parameters(
        summary["endpoints"], historical_data, target=target, store=store,
    )
    summary["javascript_correlation"] = correlate_javascript_parameters(
        summary["endpoints"], js_data, target=target, store=store,
    )

    # Negative-result memory (context.md §8/§12.6). Emitted ONLY when the
    # enumeration was actually conclusive: the finding type contains
    # "_checked_no", which surface_mapper trusts as authoritative
    # "checked and not found" state for this (asset, check) pair, so recording
    # it after a blocked or truncated run would poison that memory and stop a
    # later, unblocked run from being attempted.
    if summary["enumeration_conclusive"] and not summary["endpoints"]:
        err = _safe_store_add(store, make_finding(
            finding_type="endpoint_discovery_checked_no_endpoints",
            target=target,
            value={"base_url": base_url, "root": root,
                   "wordlist_entries_probed": state.request_count,
                   "negative_results": state.negative_results},
            evidence=[
                f"Enumerated {state.request_count} candidate path(s) under {root} with a usable "
                f"catch-all baseline; no path produced a response distinguishable from this "
                f"host's not-found behaviour",
            ],
            confidence=CONFIDENCE_MEDIUM,
            metadata={"base_url": base_url, "conclusive": True},
        ))
        if err:
            summary["errors"].append({"stage": "persistence", "wordlist": "", "error": err})

    summary["errors"].extend(state.errors)
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
        prog="endpoint_discovery.py",
        description="ReconHound Module 10 — web/API attack-surface enumeration (standalone test entry point).",
    )
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://example.com/")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--wordlists-dir", default=None, help="Override wordlists/ directory")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Recursion depth limit")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS, help="Total request budget")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Concurrent worker threads")
    args = parser.parse_args()

    try:
        result = run_endpoint_discovery(
            args.url, target=args.target, output_dir=args.output_dir, wordlists_dir=args.wordlists_dir,
            timeout=args.timeout, max_depth=args.max_depth, max_requests=args.max_requests,
            max_workers=args.max_workers,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
