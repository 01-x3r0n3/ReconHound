"""
reconhound/crawler.py — ReconHound Module 12 (crawler.py), build-order
position 6.

Phase: Active. See context.md §10 (module 12, "Recursive in-scope web app
discovery") for the authoritative responsibilities, and §8 for the
evidence/confidence data model this module implements. This file only
documents implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Recursive in-scope web app discovery. Follows internal links, collects
  URLs/forms/parameters, classifies forms (auth/search/upload/user-input/
  admin), extracts JS refs (sends to js_analyzer), WebSocket detection,
  GraphQL indicator detection, HIGH-priority flag for file-upload
  surfaces. Strict scope enforcement."

That expands (per the assignment brief) into eleven discrete
responsibilities, each implemented below:

  1. Recursive internal-link crawling  -> run_crawler (BFS engine)
  2. URL discovery                     -> extract_page_links + _process_page
  3. Form discovery                    -> extract_forms
  4. Form classification               -> classify_form
  5. Parameter collection              -> extract_query_parameters,
                                           infer_path_parameters,
                                           extract_form_field_parameters,
                                           extract_header_parameter_hints
  6. JavaScript references             -> extract_javascript_references
  7. WebSocket detection                -> detect_websocket_indicators
  8. GraphQL indicators                -> detect_graphql_indicators
  9/10. File-upload surface + HIGH flag -> build_file_upload_surface
  11. Strict scope enforcement          -> validate_crawl_target, _in_scope_host,
                                           _is_disallowed_redirect_ip

Plus shared plumbing: fetch_url, classify_response, PendingAssetsStore,
make_finding/make_parameter_finding, and a single-target orchestrator
run_crawler (mirroring the run_passive_recon/run_active_recon/
run_http_analysis/run_endpoint_discovery precedent — not itself a listed
context.md responsibility).

Implementation decisions (ambiguities resolved so implementation can
proceed without redesigning anything context.md defines):

  1. js_analyzer.py (build-order item 18) does not exist yet, so there is
     no established interface to hand JavaScript references to directly.
     Per context.md's "when that integration is defined and supported"
     framing, the only integration mechanism currently defined by the
     architecture is crash-safe persistence to
     <output_dir>/pending_assets.json (the same mechanism every other
     module already uses to feed surface_mapper.py). This module persists
     each discovered JS reference as a `javascript_reference` finding
     there; once js_analyzer.py exists, the orchestrator (not yet built)
     reads those findings the same way it will read every other module's
     output. No JS-analysis logic (fetching/parsing .js file bodies,
     source maps, secret scanning, etc.) is implemented here — that is
     js_analyzer.py's named responsibility, not this module's.
  2. External JavaScript files referenced via <script src="..."> are
     recorded as references only; their bodies are never fetched by this
     module. Crawling only follows navigable page links (<a href>,
     <iframe src>, in-scope redirect targets) — static assets (script/
     link/img) are discovered, not traversed, keeping "recursive link
     crawling" (#1) and "JS references" (#6) cleanly separated along the
     same boundary context.md draws between crawler.py and js_analyzer.py.
  3. Forms are discovered and classified, but never submitted. No GET or
     POST request is made against a form's action URL by this module —
     doing so risks state-changing side effects (search-index submission,
     login attempts, comment posting) that context.md's "reconnaissance,
     not exploitation" boundary (§4, §16) and this module's explicit
     "SECURITY BOUNDARIES" (no auth bypass, no malicious payloads, no
     brute-force) forbid. A form's action endpoint is still recorded as a
     discovered URL (`crawled_form` finding, `not_fetched: true`) so it
     remains visible to the asset graph without ever being requested.
  4. Response classification (classify_response) is HTTP-status-based
     only — unlike endpoint_discovery.py's soft-404 body-fingerprint
     heuristic (its decision #2), that heuristic exists to compensate for
     *guessed* wordlist paths, which are frequently wrong. This module
     only ever requests URLs that were genuinely observed as real links on
     already-fetched pages, so the guessed-path problem does not apply
     here; adding the same heuristic would be complexity without a
     matching need (CLAUDE.md's "don't add unrequested complexity" rule).
  5. Redirects are inspected, not auto-followed by `requests`
     (`allow_redirects=False`, matching every other module's fetch_url).
     A redirect's Location header is resolved to an absolute URL,
     scope-checked exactly like any other discovered link, and — only if
     in scope — queued as a normal crawl candidate at the next depth
     level. This satisfies "follow links recursively... handle redirects
     without escaping scope" using the same single code path (and the
     same visited-set loop protection) as ordinary link-following, rather
     than a second, parallel redirect-following mechanism.
  6. SSRF safeguard on discovered (not caller-supplied) candidates:
     http_analyzer.py already defines `_is_disallowed_redirect_ip` — a
     private/loopback/link-local/multicast/reserved/unspecified IP-literal
     check — "a lightweight SSRF safeguard for redirect-following". This
     module duplicates that same check (modular independence, as with
     every other shared helper). validate_crawl_target's/_in_scope_host's
     domain-suffix scope check has a long-standing exemption, shared with
     endpoint_discovery.py/http_analyzer.py: an IP-literal hostname skips
     the domain check entirely. Left alone under an autonomously-crawling
     module, that exemption means any page could link to
     "http://169.254.169.254/" (or any other private/reserved address) and
     the crawler would treat it as in scope. `_candidate_in_scope` closes
     exactly that gap: an IP-literal candidate is only allowed through the
     exemption if it is NOT a private/loopback/reserved address. This must
     not, however, reject a candidate that exactly matches an IP-literal
     `target` — an operator who authorized a scan against a private/
     internal IP has already made that address in scope, and every
     same-host link the crawler finds there necessarily resolves back to
     it; that case is an exact-match scope decision, not the exemption
     the safeguard exists to close.
  7. Scope comparison is hostname-based only (target itself or a
     subdomain of it), matching validate_endpoint_target/
     validate_url_target's existing precedent exactly: port is not part
     of the comparison (the asset graph already models Port as a distinct
     level under a Host, context.md §7 — a same-host port change is a new
     *asset*, not an out-of-scope host), and a scheme change (http<->https)
     is allowed (an extremely common, expected redirect pattern). An
     IP-literal host is allowed through target's domain check for the
     same reason validate_endpoint_target allows it (IP scope is enforced
     upstream by the operator's chosen target/base_url, and, for
     discovered candidates, by decision #6 above).
  8. robots.txt/sitemap.xml discovery is exposure_scan.py's named
     responsibility (context.md module 15), not crawler.py's — this
     module does not parse or special-case robots.txt.
  9. Only GET requests are made, identical to endpoint_discovery.py's
     decision #6 and for the same reason: this module discovers surface,
     it does not exercise it.
 10. OPT-IN request safety. Decision #3 refuses to submit forms because of
     state-changing side effects; GET /logout and GET /account/delete?id=7
     are the same class of side effect reached by a different route. When
     the operator passes `avoid_destructive=True`, a *discovered* candidate
     whose whole path segment names such an action, or whose action
     parameter names one, is recorded as discovered surface with
     `fetched: false` and a `skip_reason` and never requested. This is
     evidence-based, never a substring blacklist: matching is on whole path
     segments with any file extension stripped, and a destructive *verb*
     additionally requires corroboration that the URL acts on an object
     (query parameters, an adjacent identifier, or mutable server-side
     state). "/password/reset", "/newsletter/unsubscribe", "/docs/remove"
     and "/blog/how-to-delete-a-file" therefore stay crawlable even when it
     is enabled. The operator-supplied base_url is always exempt: naming it
     as the crawl root IS the authorisation, the same distinction
     validate_crawl_target draws against _candidate_in_scope.
     It is OFF BY DEFAULT (`avoid_destructive=False`). context.md module 12
     requires this module to follow internal links; withholding requests
     narrows that by default, which context.md §2/§3 do not authorise, so
     the reach of every pre-existing caller is preserved and the operator
     opts in. The safety decision itself is crawler-owned — no other module
     issues these requests — but it emits one request-safety reason code and
     no auth taxonomy: identifying login/logout/password-reset/OAuth/SSO
     surfaces as *intelligence* is http_analyzer.py's named responsibility
     (context.md module 16), and this module does not duplicate it.
 11. Anti-bot challenge classification is DETECTION ONLY
     (detect_challenge_indicators). Nothing bypasses, solves or evades a
     challenge and no request is altered in response to one — that would be
     WAF evasion, which context.md §4/§16 forbids. It exists to remove a
     false positive from this module's own output: a Cloudflare
     interstitial is ordinary HTML, so its challenge <form> was persisted
     as a discovered application form and its challenge-platform <script>
     as an application JavaScript reference. Such artefacts are still
     recorded (nothing discovered is discarded) but marked
     `challenge_artifact`, downgraded to LOW confidence, and never allowed
     to raise a HIGH-priority file-upload surface. A CAPTCHA *widget* on an
     otherwise normal page is classified separately and is not a block.

COMPLETENESS: an empty result is not a negative result. The summary
distinguishes a crawl that finished from one that was cut short —
`depth_truncated`, `request_budget_exhausted`, `cancelled`, `rate_limited`,
`challenge_pages`, `truncated_pages`, and the single `crawl_complete` flag
that is False if any of them fired — so downstream can never read "no forms
found" from a run that was blocked, throttled, interrupted or truncated as
"this application has no forms" (context.md §8).

INTENTIONAL v1 LIMITATIONS (deliberate boundaries, not oversights):
  * No headless browser, no JavaScript execution, no SPA runtime route
    discovery, no framework state extraction. Client-side-rendered routes
    and fetch/XHR-constructed endpoints are therefore not discovered by
    this module; JS *files* are discovered and handed to js_analyzer.py,
    whose named responsibility deep JavaScript analysis is.
  * No WebSocket protocol/frame analysis — indicators only (#7).
  * No GraphQL introspection or schema intelligence — indicators only (#8);
    schema work is api_recon.py's named responsibility.
  * No gRPC-Web detection. context.md's line for this module names
    WebSocket and GraphQL detection specifically; adding a third protocol
    detector and its finding type is an architectural addition, not a local
    fix (CLAUDE.md rule 12). API protocol intelligence belongs to
    api_recon.py.
  * No CAPTCHA solving, no WAF evasion, no stealth/human-like browsing —
    prohibited, not deferred.
  * No soft-404/catch-all body fingerprinting: this module only requests
    URLs observed as real links on already-fetched pages, so the
    guessed-path problem that heuristic exists for does not arise here
    (decision #4).

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
Modules 1/2/3/4/10). Output is intended to feed surface_mapper.py (not yet
implemented) and, per decision #1 above, js_analyzer.py (not yet
implemented) — this module does not implement or call into either.

DISCOVERY != CONFIRMED VULNERABILITY: every record here is an observation
(a link existed, a form had a file input, a page mentioned "graphql").
None of this module's output — including HIGH-priority file-upload-surface
flags — should be read as "vulnerable" or "exploitable". A HIGH priority
flag on a file-upload surface means "this attack surface warrants
investigation priority", not "this upload endpoint is exploitable". That
assessment belongs to vuln_intel.py / risk_engine.py.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import tempfile
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup

MODULE_NAME = "crawler.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-Crawler/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 200
DEFAULT_MAX_WORKERS = 10

# Per-page and whole-run resource caps. A single hostile or merely enormous
# page must not be able to allocate unbounded findings, task tuples or
# evidence. Every cap records an error entry when it bites, so a truncated
# page is never mistaken for a fully-parsed one (context.md §8: a bounded
# result must say that it is bounded).
DEFAULT_MAX_LINKS_PER_PAGE = 200
DEFAULT_MAX_FORMS_PER_PAGE = 100
DEFAULT_MAX_JS_REFS_PER_PAGE = 100
DEFAULT_MAX_WS_INDICATORS_PER_PAGE = 50
DEFAULT_MAX_PARAMS_PER_PAGE = 200
#  * MAX_FRONTIER — next_frontier is built before the requests that would
#    consume it are spent, so one wide level can allocate far more task
#    tuples than the run could ever fetch (600 links x 60 pages measured at
#    36,000 queued tuples for a 60-request budget).
DEFAULT_MAX_FRONTIER = 20000
# Attribute values are operator-visible evidence, not payloads: a 500 KB
# placeholder/pattern attribute is persisted in full without this cap.
_MAX_ATTR_VALUE_CHARS = 200

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_OBJECT_ID_RE = re.compile(r"^[0-9a-fA-F]{24}$")

_HEADER_HINT_TOKENS = ["X-Api-Key", "X-Auth-Token", "X-CSRF-Token", "X-Access-Token"]

_FORM_FIELD_TYPE_MAP = {
    "number": "integer", "range": "integer", "checkbox": "boolean", "radio": "string",
    "email": "string", "password": "string", "hidden": "string", "file": "file",
    "date": "string", "datetime-local": "string", "tel": "string", "url": "string",
    "text": "string", "search": "string", "select": "string", "textarea": "string",
}
_FIELD_ATTR_KEYS = ("required", "placeholder", "maxlength", "pattern", "accept", "multiple")

_WS_LITERAL_RE = re.compile(r"""wss?://[^\s'"<>\\]+""", re.IGNORECASE)
_WS_CTOR_RE = re.compile(r"new\s+WebSocket\s*\(", re.IGNORECASE)

_GRAPHQL_PATH_RE = re.compile(r"/graphql\b", re.IGNORECASE)
_GRAPHQL_STRONG_RE = re.compile(
    r"(__APOLLO_STATE__|apollo-client|apolloClient|graphql-ws|application/graphql)", re.IGNORECASE
)
_GRAPHQL_WEAK_RE = re.compile(r"\bgraphql\b", re.IGNORECASE)

# Static-asset tags/attrs discovered but never queued as crawl candidates
# (JS references only — see module docstring, decision #2).
_JS_TAG_ATTR = ("script", "src")
# Navigable page-link tags/attrs that ARE queued as crawl candidates.
_LINK_TAG_ATTRS = {"a": "href", "iframe": "src"}

_ADMIN_TOKENS = ("admin", "wp-admin", "administrator", "dashboard", "manage", "cpanel", "backend", "control-panel")
_AUTH_TOKENS = ("login", "signin", "sign-in", "auth", "sso", "session")
_SEARCH_TOKENS = ("search",)
_SEARCH_FIELD_NAMES = ("q", "query", "search", "s", "keyword", "keywords")
_USERNAME_FIELD_NAMES = ("username", "user", "email", "login", "userid", "user_id")


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors endpoint_discovery.py's validate_endpoint_target
# / http_analyzer.py's validate_url_target; duplicated per modular
# independence, context.md §12.2)
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
    the same host — silently dropping in-scope pages in one direction, and
    making a homograph host look "different" from the target it impersonates
    in the other. Both sides are folded to lowercase A-label form; anything
    that will not encode is returned lowercased unchanged so the caller still
    gets a deterministic comparison. Mirrors endpoint_discovery.py.
    """
    host = host.strip().rstrip(".").lower()
    if not host or host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return host


def _strip_userinfo(url: str) -> str:
    """
    Remove any `user:password@` component from a URL.

    Every URL this module crawls beyond the seed comes out of a response
    body, so credentials genuinely turn up in them. They must not be
    re-sent, must not become part of an asset identity, and above all must
    never be written into pending_assets.json — a plain-text file shared
    with every other module and included in the report appendix (CLAUDE.md
    rule 16). The netloc is rebuilt from the parsed host/port so the result
    is also the canonical form for the visited set. Mirrors
    endpoint_discovery.py.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        if "@" not in parsed.netloc:
            return url
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return url
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"          # bare IPv6 literal
    netloc = f"{host}:{port}" if port else host
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


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


_PRESERVE_UNRESERVED_RE = re.compile(r"%[0-9a-fA-F]{2}")


def _normalize_percent_encoding(path: str) -> str:
    """
    Decode percent-escapes that encode RFC 3986 unreserved characters and
    upper-case the rest, so "/%7Euser" and "/~user" — the same resource —
    produce the same visited-set key instead of two crawls.
    """
    def _repl(match: "re.Match[str]") -> str:
        raw = match.group(0)
        try:
            char = bytes.fromhex(raw[1:]).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return raw.upper()
        if char.isalnum() or char in "-._~":
            return char
        return raw.upper()
    return _PRESERVE_UNRESERVED_RE.sub(_repl, path)


def _is_disallowed_redirect_ip(host: str) -> bool:
    """
    True if `host` is an IP literal in a private/loopback/link-local/
    reserved range. Mirrors http_analyzer.py's `_is_disallowed_redirect_ip`
    exactly (same rationale: a lightweight SSRF safeguard); applied here to
    every *discovered* link/redirect candidate, not to the caller-supplied
    base_url/target — see module docstring, decision #6.
    """
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
    )


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = _idna_normalize(hostname)
    target = _idna_normalize(target)
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def validate_crawl_target(url: str, target: Optional[str] = None) -> str:
    """
    Validate that `url` is a syntactically valid http(s) URL, and — if
    `target` is supplied — that its hostname is the target itself or a
    subdomain of it (an IP-literal host is allowed through without an
    in-scope check — see module docstring, decision #7).
    """
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")

    candidate = url.strip()
    # A CR, LF, NUL or tab inside a URL is never legitimate. urlsplit silently
    # *removes* newlines and tabs, so "http://exam\tple.com/" was validated as
    # the in-scope host "example.com" and then handed to requests still
    # carrying the raw byte. Rejecting it here names the real problem instead
    # of surfacing an opaque transport error later (mirrors
    # endpoint_discovery.validate_endpoint_target).
    if any(ch in candidate for ch in "\r\n\t\x00"):
        raise ScopeError(f"URL contains control characters: {url!r}")

    try:
        parsed = urllib.parse.urlsplit(candidate)
        hostname = parsed.hostname
    except ValueError as exc:
        # urlsplit raises on malformed IPv6 brackets and out-of-range ports;
        # letting that escape turned a scope decision into an uncaught
        # ValueError the orchestrator records as a module crash rather than a
        # scope rejection.
        raise ScopeError(f"URL cannot be parsed: {url!r} ({exc})") from exc

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if target and not _is_ip_literal(hostname) and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    # Credentials in an operator-supplied URL are dropped rather than
    # rejected: the URL is legitimate, but re-sending and persisting the
    # credential is not (see _strip_userinfo).
    return _strip_userinfo(candidate)


def _candidate_in_scope(url: str, target: Optional[str]) -> bool:
    """
    Scope check for a *discovered* candidate (link/redirect target), as
    opposed to validate_crawl_target's check on the caller-supplied
    base_url. Rejects non-http(s) schemes and out-of-scope hostnames.

    Per decision #6, the private/loopback/reserved-IP safeguard
    (_is_disallowed_redirect_ip) exists specifically to close the "IP
    literals skip the domain-suffix scope check" exemption from being
    abused (e.g. target="example.com", a page links to
    "http://169.254.169.254/") — it must NOT reject a candidate that is an
    exact match for an IP-literal `target` itself: an operator who
    authorized a scan against a private/internal IP has already made that
    an in-scope host, and every same-host link the crawler finds on that
    target necessarily resolves to that same address.
    """
    if not isinstance(url, str) or any(ch in url for ch in "\r\n\t\x00"):
        # Same reasoning as validate_crawl_target: a control character in a
        # discovered link is never legitimate, and urlsplit's silent stripping
        # would scope-check a different string than the one requests is given.
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if not hostname:
        return False

    if target and _is_ip_literal(target):
        # IP-literal target: only an exact match is in scope (mirrors
        # _in_scope_host's exact-match semantics; IP addresses have no
        # subdomain concept). No additional private-range check — the
        # operator already authorized this exact address as the target.
        return _idna_normalize(hostname) == _idna_normalize(target)

    if _is_ip_literal(hostname):
        # IP-literal candidate under a domain-name target (or no target):
        # this is exactly the domain-suffix-check bypass decision #6
        # guards against.
        return not _is_disallowed_redirect_ip(hostname)

    if target and not _in_scope_host(hostname, target):
        return False
    return True


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors the other modules' model; kept local per
# modular independence)
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


def make_parameter_finding(param: Dict[str, Any], target: str) -> Dict[str, Any]:
    """
    Wrap a raw parameter dict (see extract_* functions below) into the
    structured evidence record required by responsibility #5 ("parameter
    intelligence"): name, location, method, endpoint, data type, source —
    each explicitly preserved.
    """
    return make_finding(
        finding_type="crawler_parameter",
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
        # append does not have to re-encode the whole file (see
        # _atomic_write_body). `_stamp` is the (mtime_ns, size) of the file as
        # this store last left it; anything else means somebody else wrote it
        # and the cache is void.
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

        add() rewrites the whole shared file per finding, which is quadratic
        in the number of records already on disk — and one crawled page emits
        a page record plus every form, parameter, JS reference and indicator
        found on it. Measured on this repository with the previous per-finding
        add(): 100 findings 0.05s, 300 0.40s, 600 1.52s, 1000 4.33s, while a
        mocked 60-page crawl spent 15.7s almost entirely in persistence.
        Batching one page's records into a single write keeps a full run
        linear in practice.

        Crash-safety is unchanged and slightly stronger: still one
        write-to-temp + os.replace, so a page's records are all-or-nothing
        rather than half-applied. Mirrors endpoint_discovery.py/
        active_recon.py, which share this output file. Returns the number of
        findings written.
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
        longer re-encoded on every append, and the rename itself is now
        durably committed.
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
        encoded = self._encode_body(records)
        self._atomic_write_body(encoded)
        self._serialized = encoded

    @staticmethod
    def _fsync_dir(dir_name: str) -> None:
        """
        Durably commit the os.replace() rename itself.

        Without this the replacement file's *contents* are on disk but the
        directory entry pointing at them may not be, so a power loss can still
        resurrect the pre-replace file and lose every discovery appended
        since. Best-effort: some platforms/filesystems refuse to fsync a
        directory. Mirrors passive_recon.py/active_recon.py, which share this
        file.
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
# fills or the path loses permissions (OSError), or a value reached the store
# that json.dump cannot serialise (TypeError/ValueError). Catching only
# PersistenceError meant those escaped _persist_form/_process_page, killed the
# worker task, and took the *completed discovery* down with them — a measured
# OSError on one form write lost that page's entire record, its parameters,
# its JS references and its HIGH-priority file-upload surface. That is exactly
# the outcome context.md §12.11 forbids.
_PERSISTENCE_FAILURES = (PersistenceError, OSError, TypeError, ValueError)


def _safe_store_add(store: Optional["PendingAssetsStore"], finding: Dict[str, Any]) -> Optional[str]:
    """
    store.add() wrapped so a single persistence failure doesn't abort the
    crawl. Returns None on success, or an error message the caller is
    responsible for recording (never silently discarded).
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
    parsed = urllib.parse.urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _normalize_url(url: str) -> str:
    """
    Canonical form of a URL, used as the visited-set key so the same resource
    is never crawled twice (responsibility #1: "avoid duplicate URL
    processing" / "prevent infinite crawling loops").

    Normalizes scheme/host casing, IDN form, the hostname's trailing root dot,
    userinfo, default ports, duplicate slashes, dot segments, redundant
    percent-encoding, query-parameter order, and the fragment (which is never
    sent to a server and so can never distinguish two requests).

    Every one of those was a way to re-fetch a page the crawler had already
    seen: "/a/../b" and "/b", "/%7Eu" and "/~u", "example.com." and
    "example.com", and — worst, because it also leaked a secret into the
    visited set and from there into evidence — "user:pass@host" and "host".
    Under a spider trap each is an unbounded duplicate-URL generator.
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

    # Decode-then-remove, in that order: "%2e%2e" is an encoded ".." and has
    # to become one before dot segments are collapsed, or "/a/%2e%2e/b" and
    # "/b" stay two visited-set keys for one resource. Only *unreserved*
    # characters are decoded, so "%2F" never turns into a path separator.
    path = _remove_dot_segments(_normalize_percent_encoding(re.sub(r"/{2,}", "/", parsed.path or "/")))
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    fragment = ""  # fragments never distinguish a distinct server-side resource
    return urllib.parse.urlunsplit((scheme, host, path, query, fragment))


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
# Shared HTTP client (GET only — see module docstring, decision #9)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single HTTP GET against `url` without following redirects
    (redirects are inspected, not silently followed — see module
    docstring, decision #5).
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
            # bounded: `resp.content` materialises the *entire* body before
            # the slice runs, so a 50 MB response (or a decompression bomb)
            # was fully resident in memory per worker before being truncated
            # to 128 KB. iter_content stops as soon as the cap is reached.
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
                # Last resort for adapters exposing neither a readable .raw
                # nor a working iter_content. `.content` materialises the
                # whole body, so it is used only when the server declared a
                # size that is safe to hold; an undeclared or oversized body
                # is reported as unread rather than swallowed whole.
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


# ---------------------------------------------------------------------------
# Response classification (status-based only — see module docstring,
# decision #4)
# ---------------------------------------------------------------------------

def classify_response(resp: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    """
    Classify a fetch_url() result into a discovery_type + confidence +
    supporting notes.

    Status-based only, deliberately (see module docstring, decision #4).
    What it must never do is turn a *refusal to answer* into a statement
    about the application: 503 stays a server error rather than being
    reported as rate limiting (a 503 has many causes), 401/403 stay
    "access_restricted" rather than being read as "an API lives here", and
    only an explicit 429 is called rate limiting.
    """
    status = resp.get("status_code")
    if status is None:
        return "error", CONFIDENCE_LOW, ["no status code available (request failed)"]
    if status == 404:
        return "not_found", CONFIDENCE_HIGH, []
    if status == 429:
        notes = ["HTTP 429 Too Many Requests — crawl may be incomplete beyond this point"]
        retry_after = _ci_get(resp.get("headers") or {}, "Retry-After")
        if retry_after:
            notes.append(f"Retry-After: {retry_after}")
        return "rate_limited", CONFIDENCE_LOW, notes
    if status in _REDIRECT_STATUS_CODES:
        return "redirect", CONFIDENCE_MEDIUM, [f"HTTP {status} redirect response"]
    if status in (401, 403):
        return "access_restricted", CONFIDENCE_MEDIUM, [f"HTTP {status} access-restricted response"]
    if status == 405:
        return "method_not_allowed", CONFIDENCE_MEDIUM, ["HTTP 405 Method Not Allowed"]
    if 500 <= status < 600:
        return "server_error_response", CONFIDENCE_LOW, [f"HTTP {status} server error"]
    if 200 <= status < 300:
        return "content_confirmed", CONFIDENCE_HIGH, []
    return "unexpected_status", CONFIDENCE_LOW, [f"unexpected HTTP status {status}"]


# ---------------------------------------------------------------------------
# 5. Parameter collection
# ---------------------------------------------------------------------------

def extract_query_parameters(
    url: str, endpoint: Optional[str] = None, method: str = "GET", source: str = "crawler_url_query",
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
    confirmed URL template.
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
            "data_type": data_type, "source": "crawler_path_pattern",
            "confidence": CONFIDENCE_LOW,
            "evidence": [f"Path segment {idx} of {path!r} ({segment!r}) matches a dynamic-identifier pattern; "
                         f"inferred, not a confirmed route template"],
        })
    return out


def extract_form_field_parameters(form: Dict[str, Any], target: str) -> List[Dict[str, Any]]:
    """Parameter records derived from an already-extracted form's fields (responsibility #5)."""
    out: List[Dict[str, Any]] = []
    method = form.get("method", "GET")
    location = "query" if method == "GET" else "body"
    endpoint = urllib.parse.urlsplit(form.get("resolved_action") or form.get("source_page") or "").path or "/"
    for field in form.get("fields") or []:
        name = field.get("name")
        if not name:
            continue
        field_type = (field.get("type") or "text").lower()
        data_type = _FORM_FIELD_TYPE_MAP.get(field_type, "string")
        out.append({
            "name": name, "location": location, "method": method, "endpoint": endpoint,
            "data_type": data_type, "source": "crawler_html_form",
            "confidence": CONFIDENCE_MEDIUM,
            "evidence": [f"<{field_type}> field named {name!r} found in a <form method={method}> "
                         f"on {form.get('source_page')}"],
        })
    return out


def extract_header_parameter_hints(body: Optional[str], headers: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Header-location parameter hints: known auth/API header names literally
    referenced in fetched content, plus a WWW-Authenticate challenge if
    present. LOW/MEDIUM confidence — a name being mentioned does not
    confirm the server requires or accepts it.
    """
    haystack = body or ""
    out: List[Dict[str, Any]] = []
    for token in _HEADER_HINT_TOKENS:
        if re.search(rf"\b{re.escape(token)}\b", haystack, re.IGNORECASE):
            out.append({
                "name": token, "location": "header", "method": "GET", "endpoint": None,
                "data_type": "string", "source": "crawler_content_reference",
                "confidence": CONFIDENCE_LOW,
                "evidence": [f"Header name {token!r} referenced in fetched response content"],
            })

    www_auth = _ci_get(headers or {}, "WWW-Authenticate")
    if www_auth:
        out.append({
            "name": "Authorization", "location": "header", "method": "GET", "endpoint": None,
            "data_type": "string", "source": "crawler_http_response_challenge",
            "confidence": CONFIDENCE_MEDIUM,
            "evidence": [f"WWW-Authenticate challenge observed: {www_auth}"],
        })
    return out


# ---------------------------------------------------------------------------
# 2. URL discovery (page-link extraction — navigable candidates only; see
# module docstring, decision #2)
# ---------------------------------------------------------------------------

def _parse_html(body: Optional[str]) -> Optional[Any]:
    """
    Parse `body` once, returning None on empty/unparseable input.

    extract_page_links, extract_forms and extract_javascript_references each
    used to build their own BeautifulSoup — three full parses of the same
    document per page, measured at 3 constructions for a single page. They
    now accept an already-parsed `soup`, and _process_page passes one.
    """
    if not body:
        return None
    try:
        return BeautifulSoup(body, "html.parser")
    except Exception:
        return None


def extract_page_links(
    body: str, page_url: str, target: Optional[str] = None, soup: Optional[Any] = None,
    max_links: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Extract navigable <a href>/<iframe src> links from `body`, resolved to
    absolute URLs. Each entry preserves discovery context (tag/attribute)
    and an `in_scope` flag (candidates are not silently dropped — see
    responsibility #11 and _candidate_in_scope).

    `max_links` stops the scan once that many distinct links have been
    collected. The caller capped the *result* before, which bounded the
    frontier but not the work: a 3,000-link page still cost 3,000 URL
    resolutions, normalizations and scope checks per page, measured at 74s
    and 75 MB for a 100-page crawl. Stopping the scan is the same set of
    links (the cap was always applied to the head of the deduplicated list)
    at a bounded cost.
    """
    soup = soup if soup is not None else _parse_html(body)
    if soup is None:
        return []

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for tag_name, attr in _LINK_TAG_ATTRS.items():
        try:
            tags = soup.find_all(tag_name)
        except Exception:
            continue
        for tag in tags:
            value = tag.get(attr)
            if not value:
                continue
            ref = value.strip()
            if not ref or ref.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                continue
            if any(ch in ref for ch in "\r\n\t\x00"):
                # urlsplit strips these silently, so the URL that gets
                # scope-checked would not be the URL that gets requested.
                continue
            try:
                abs_url = _strip_userinfo(urllib.parse.urljoin(page_url, ref))
            except Exception:
                continue
            parsed = urllib.parse.urlsplit(abs_url)
            if parsed.scheme not in ("http", "https"):
                continue
            normalized = _normalize_url(abs_url)
            if normalized in seen:
                continue
            seen.add(normalized)
            if max_links is not None and len(out) >= max_links:
                return out
            out.append({
                "url": abs_url,
                # Credential-stripped, like `url`: `raw` is descriptive
                # provenance, not a reason to keep a password around.
                "raw": _strip_userinfo(ref) if "@" in ref else ref,
                "tag": f"{tag_name}[{attr}]",
                "in_scope": _candidate_in_scope(abs_url, target),
            })
    return out


# ---------------------------------------------------------------------------
# 3. Form discovery
# ---------------------------------------------------------------------------

def extract_forms(body: str, page_url: str, soup: Optional[Any] = None) -> List[Dict[str, Any]]:
    """
    HTML <form> structure extraction: action, method, enctype, and every
    named field's type + relevant attributes. Malformed HTML degrades to
    an empty result rather than raising.
    """
    soup = soup if soup is not None else _parse_html(body)
    if soup is None:
        return []
    try:
        forms = soup.find_all("form")
    except Exception:
        return []

    out: List[Dict[str, Any]] = []
    for form in forms:
        method = (form.get("method") or "GET").strip().upper()
        if method not in ("GET", "POST"):
            method = "GET"
        raw_action = form.get("action")
        if isinstance(raw_action, str) and "@" in raw_action:
            raw_action = _strip_userinfo(raw_action)
        try:
            resolved_action = _strip_userinfo(
                urllib.parse.urljoin(page_url, raw_action)) if raw_action else page_url
        except Exception:
            resolved_action = page_url
        enctype = (form.get("enctype") or "application/x-www-form-urlencoded").strip().lower()

        try:
            field_tags = form.find_all(["input", "select", "textarea"])
        except Exception:
            field_tags = []

        fields: List[Dict[str, Any]] = []
        for field in field_tags:
            field_type = (field.get("type") or ("select" if field.name == "select" else "text")).lower()
            entry: Dict[str, Any] = {"name": field.get("name"), "type": field_type}
            # Attribute values are operator-visible evidence, not payloads: a
            # page can declare a 500 KB placeholder/pattern and every byte of
            # it was previously persisted into pending_assets.json.
            attrs = {
                k: (str(field.get(k))[:_MAX_ATTR_VALUE_CHARS] if isinstance(field.get(k), str) else field.get(k))
                for k in _FIELD_ATTR_KEYS if field.get(k) is not None
            }
            if field_type in ("hidden", "submit") and field.get("value") is not None:
                attrs["value"] = str(field.get("value"))[:_MAX_ATTR_VALUE_CHARS]
            if attrs:
                entry["attributes"] = attrs
            fields.append(entry)

        out.append({
            "action": raw_action,
            "resolved_action": resolved_action,
            "method": method,
            "enctype": enctype,
            "fields": fields,
            "source_page": page_url,
        })
    return out


# ---------------------------------------------------------------------------
# 4. Form classification (evidence-driven; never overclaims — see module
# docstring / context.md's "do not claim classification with unjustified
# certainty")
# ---------------------------------------------------------------------------

def classify_form(form: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify a form (as extracted by extract_forms) into one of
    authentication/search/file_upload/user_input/administrative, or None
    if no category has supporting evidence. Priority order reflects
    specificity: file_upload and authentication are strong, narrow
    signals; administrative and search are moderate; user_input is the
    generic fallback.
    """
    fields = form.get("fields") or []
    field_names = [(f.get("name") or "").lower() for f in fields if f.get("name")]
    field_types = [(f.get("type") or "").lower() for f in fields]
    action = (form.get("resolved_action") or form.get("action") or "").lower()
    method = form.get("method", "GET")
    enctype = (form.get("enctype") or "").lower()

    has_file = "file" in field_types
    has_multipart = "multipart/form-data" in enctype
    if has_file or has_multipart:
        evidence = []
        if has_file:
            names = [f.get("name") for f in fields if (f.get("type") or "").lower() == "file"]
            evidence.append(f"Form contains file-type input field(s): {names}")
        if has_multipart:
            evidence.append("Form enctype is multipart/form-data")
        return {"category": "file_upload", "confidence": CONFIDENCE_HIGH, "evidence": evidence}

    has_password = "password" in field_types
    if has_password:
        evidence = ["Form contains a password-type input field"]
        confidence = CONFIDENCE_MEDIUM
        has_username_like = any(n in _USERNAME_FIELD_NAMES for n in field_names)
        if has_username_like:
            evidence.append("Form also contains a username/email/login-named field")
            confidence = CONFIDENCE_HIGH
        if any(t in action for t in _AUTH_TOKENS):
            evidence.append(f"Form action path suggests authentication: {action!r}")
            confidence = CONFIDENCE_HIGH
        return {"category": "authentication", "confidence": confidence, "evidence": evidence}

    if any(t in action for t in _ADMIN_TOKENS):
        return {
            "category": "administrative", "confidence": CONFIDENCE_MEDIUM,
            "evidence": [f"Form action path suggests an administrative interface: {action!r}"],
        }

    if method == "GET" and (
        any(t in action for t in _SEARCH_TOKENS) or any(n in _SEARCH_FIELD_NAMES for n in field_names)
    ):
        return {
            "category": "search", "confidence": CONFIDENCE_MEDIUM,
            "evidence": [f"GET form with search-indicative action/field name(s): action={action!r}, "
                         f"fields={field_names}"],
        }

    non_structural_fields = [f for f in fields if (f.get("type") or "text").lower() not in ("hidden", "submit", "button")]
    if non_structural_fields:
        return {
            "category": "user_input", "confidence": CONFIDENCE_LOW,
            "evidence": ["Form accepts user-supplied input but does not match a more specific category "
                         "(generic contact/comment/feedback-style form)"],
        }

    return {
        "category": None, "confidence": CONFIDENCE_LOW,
        "evidence": ["No user-facing input fields observed; insufficient evidence to classify this form"],
    }


# ---------------------------------------------------------------------------
# 9/10. File-upload surface identification + HIGH-priority flag
# ---------------------------------------------------------------------------

def build_file_upload_surface(form: Dict[str, Any], classification: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the attack-surface record for a form classified as file_upload
    (responsibility #9). The caller is responsible for persisting this
    with metadata["severity"] = "HIGH" (responsibility #10) — see
    _process_page.
    """
    fields = form.get("fields") or []
    upload_fields = [f.get("name") for f in fields if (f.get("type") or "").lower() == "file"]
    accept_attributes = {
        f.get("name"): f["attributes"]["accept"]
        for f in fields
        if (f.get("type") or "").lower() == "file" and f.get("attributes", {}).get("accept")
    }
    return {
        "source_page": form.get("source_page"),
        "action": form.get("action"),
        "resolved_action": form.get("resolved_action"),
        "method": form.get("method"),
        "enctype": form.get("enctype"),
        "upload_fields": upload_fields,
        "accept_attributes": accept_attributes,
    }


# ---------------------------------------------------------------------------
# 6. JavaScript references (never fetched/parsed here — see module
# docstring, decision #2)
# ---------------------------------------------------------------------------

def extract_javascript_references(
    body: str, page_url: str, target: Optional[str] = None, soup: Optional[Any] = None,
    max_refs: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Extract <script src> references, resolved to absolute URLs, deduplicated
    per page. `max_refs` bounds the scan itself — see extract_page_links.
    """
    soup = soup if soup is not None else _parse_html(body)
    if soup is None:
        return []
    try:
        script_tags = soup.find_all("script")
    except Exception:
        return []

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for tag in script_tags:
        src = tag.get("src")
        if not src:
            continue
        src = src.strip()
        if not src or any(ch in src for ch in "\r\n\t\x00"):
            continue
        try:
            abs_url = _strip_userinfo(urllib.parse.urljoin(page_url, src))
        except Exception:
            continue
        parsed = urllib.parse.urlsplit(abs_url)
        if parsed.scheme not in ("http", "https"):
            continue
        normalized = _normalize_url(abs_url)
        if normalized in seen:
            continue
        seen.add(normalized)
        if max_refs is not None and len(out) >= max_refs:
            return out
        out.append({
            "url": abs_url,
            "source_page": page_url,
            "in_scope": _candidate_in_scope(abs_url, target),
            # The resolved (credential-stripped) URL, never the raw attribute:
            # a `src` of "https://u:p@host/a.js" put the password verbatim
            # into pending_assets.json and from there into the report.
            "evidence": [f"<script src> referencing {abs_url} found on {page_url}"],
        })
    return out


# ---------------------------------------------------------------------------
# 7. WebSocket detection
# ---------------------------------------------------------------------------

def _ws_endpoint_in_scope(endpoint: Optional[str], target: Optional[str]) -> Optional[bool]:
    """
    Whether a discovered ws(s):// endpoint belongs to the crawl scope.

    Returns None when there is no literal endpoint to judge (a dynamically
    constructed WebSocket URL), which is not the same as False and must not
    be recorded as one. Scope is decided on the hostname exactly as for an
    http(s) candidate; the ws/wss scheme is simply the http/https scheme of
    the same origin under a different name.
    """
    if not endpoint:
        return None
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        hostname = parsed.hostname
    except ValueError:
        return False
    if not hostname:
        return False
    if not target:
        return not _is_disallowed_redirect_ip(hostname)
    if _is_ip_literal(target) or _is_ip_literal(hostname):
        if _is_ip_literal(hostname) and not _is_ip_literal(target):
            return not _is_disallowed_redirect_ip(hostname)
        return _idna_normalize(hostname) == _idna_normalize(target)
    return _in_scope_host(hostname, target)


def detect_websocket_indicators(body: str, page_url: str) -> List[Dict[str, Any]]:
    """
    Detect WebSocket endpoint indicators in fetched page content. Preserves
    the discovered endpoint (when a literal ws(s):// URL is present) and
    evidence, rather than returning a bare boolean — see responsibility #7.
    """
    if not body:
        return []
    out: List[Dict[str, Any]] = []
    # Credential-stripped: a page can carry "wss://user:pass@host/ws", and
    # the endpoint is persisted and rendered in the report appendix.
    literal_matches = sorted(set(
        _strip_userinfo(m.rstrip(").,;'\"")) for m in _WS_LITERAL_RE.findall(body)
    ))
    for endpoint in literal_matches:
        out.append({
            "endpoint": endpoint,
            "source_page": page_url,
            "confidence": CONFIDENCE_HIGH,
            "evidence": [f"Literal WebSocket URL found in page content on {page_url}: {endpoint}"],
        })

    if not literal_matches and _WS_CTOR_RE.search(body):
        out.append({
            "endpoint": None,
            "source_page": page_url,
            "confidence": CONFIDENCE_LOW,
            "evidence": [f"`new WebSocket(...)` constructor call found on {page_url} without a literal "
                         f"endpoint URL (likely constructed dynamically at runtime)"],
        })
    return out


# ---------------------------------------------------------------------------
# 8. GraphQL indicators (no schema introspection/exploitation — that is
# api_recon.py's named responsibility, not this module's)
# ---------------------------------------------------------------------------

def detect_graphql_indicators(
    body: Optional[str],
    page_url: str,
    headers: Optional[Dict[str, str]] = None,
    referenced_urls: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Detect GraphQL indicators: endpoint paths containing "/graphql" (in the
    page URL itself or in referenced link/form/JS URLs), strong
    client-library/content-type signals, and a weak bare-keyword mention.
    """
    out: List[Dict[str, Any]] = []
    seen_values: Set[str] = set()

    def _add(indicator_type: str, value: str, confidence: str, evidence: str) -> None:
        key = f"{indicator_type}:{value}"
        if key in seen_values:
            return
        seen_values.add(key)
        out.append({
            "indicator_type": indicator_type, "value": value, "confidence": confidence,
            "source_page": page_url, "evidence": [evidence],
        })

    if _GRAPHQL_PATH_RE.search(urllib.parse.urlsplit(page_url).path or ""):
        _add("endpoint_path", page_url, CONFIDENCE_HIGH, f"Page URL path contains /graphql: {page_url}")

    for ref_url in referenced_urls or []:
        if _GRAPHQL_PATH_RE.search(urllib.parse.urlsplit(ref_url).path or ""):
            _add("endpoint_path", ref_url, CONFIDENCE_HIGH, f"Referenced URL path contains /graphql: {ref_url}")

    content_type = _ci_get(headers or {}, "Content-Type") or ""
    if "application/graphql" in content_type.lower():
        _add("content_type", content_type, CONFIDENCE_HIGH,
             f"Response Content-Type is {content_type!r} on {page_url}")

    haystack = body or ""
    strong_match = _GRAPHQL_STRONG_RE.search(haystack)
    if strong_match:
        _add("content_reference", strong_match.group(0), CONFIDENCE_MEDIUM,
             f"Strong GraphQL client indicator {strong_match.group(0)!r} found in page content on {page_url}")
    elif _GRAPHQL_WEAK_RE.search(haystack):
        _add("content_reference", "graphql", CONFIDENCE_LOW,
             f"Bare keyword \"graphql\" found in page content on {page_url}; weak signal, not confirmed")

    return out


# ---------------------------------------------------------------------------
# Anti-bot challenge / CAPTCHA surface classification
#
# DETECTION ONLY. Nothing here bypasses, solves, or evades a challenge, and
# no request is altered in response to one — that would be WAF evasion, which
# context.md §4/§16 and this module's SECURITY BOUNDARIES forbid outright.
# The reason it exists is a false positive in this module's own output: a
# Cloudflare interstitial is served as ordinary HTML, so its challenge <form>
# was persisted as a discovered application form and its challenge-platform
# <script> as an application JavaScript reference, while the page record
# claimed a normal response. Downstream then held a form and an endpoint that
# do not exist in the target application.
# ---------------------------------------------------------------------------

# Vendor-specific header names. A header is a far stronger signal than page
# text, because it cannot be produced by the application merely mentioning a
# vendor's name in its own content.
_CHALLENGE_HEADERS = (
    ("cf-mitigated", "cloudflare"),
    ("cf-chl-bypass", "cloudflare"),
    ("x-datadome", "datadome"),
    ("x-datadome-cid", "datadome"),
    ("x-iinfo", "imperva_incapsula"),
    ("x-px-block", "perimeterx"),
)

# Markers that only appear in an actual interstitial, not in a page that
# happens to discuss bot protection. Each is a vendor-specific path or DOM id
# emitted by the challenge itself.
_BOT_CHALLENGE_MARKERS = (
    (re.compile(r"/cdn-cgi/challenge-platform/", re.IGNORECASE), "cloudflare"),
    (re.compile(r"\bcf-challenge-running\b", re.IGNORECASE), "cloudflare"),
    (re.compile(r"\bcf_chl_opt\b", re.IGNORECASE), "cloudflare"),
    (re.compile(r"/cdn-cgi/l/chk_jschl", re.IGNORECASE), "cloudflare"),
    (re.compile(r"\bcaptcha-delivery\.com\b", re.IGNORECASE), "datadome"),
    (re.compile(r"\b_Incapsula_Resource\b", re.IGNORECASE), "imperva_incapsula"),
    (re.compile(r"\bak-challenge\b|/akam/\d+/", re.IGNORECASE), "akamai"),
    (re.compile(r"\b_pxhd\b|/px/captcha", re.IGNORECASE), "perimeterx"),
)

# A CAPTCHA *widget* is not a block: an ordinary signup or contact form can
# carry one. It is recorded as surface intelligence with its own type, and
# never treated as evidence that the crawl was refused.
_CAPTCHA_WIDGET_MARKERS = (
    (re.compile(r"\bg-recaptcha\b|www\.google\.com/recaptcha/", re.IGNORECASE), "recaptcha"),
    (re.compile(r"\bh-captcha\b|\bhcaptcha\.com\b", re.IGNORECASE), "hcaptcha"),
    (re.compile(r"\bcf-turnstile\b|challenges\.cloudflare\.com/turnstile", re.IGNORECASE), "turnstile"),
)


def detect_challenge_indicators(
    body: Optional[str], headers: Optional[Dict[str, str]] = None, status_code: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Classify a response as an anti-bot interstitial, a page carrying a CAPTCHA
    widget, or neither. Returns None when there is no supporting evidence.

    Deliberately evidence-based rather than keyword-based: the bare words
    "captcha", "cloudflare" or "blocked" appearing in page text prove nothing
    (a security blog would match all three), so only vendor headers and
    vendor-emitted markers count. `kind` is "bot_challenge" when the response
    IS the challenge — the crawler was refused and the body is not the
    application's — or "captcha_widget" when a normal page merely embeds one.
    """
    header_map = headers or {}
    evidence: List[str] = []
    vendors: List[str] = []

    for name, vendor in _CHALLENGE_HEADERS:
        value = _ci_get(header_map, name)
        if value is not None:
            evidence.append(f"Anti-bot vendor response header {name!r} present (value: {value!r})")
            vendors.append(vendor)

    haystack = body or ""
    for pattern, vendor in _BOT_CHALLENGE_MARKERS:
        match = pattern.search(haystack)
        if match:
            evidence.append(f"Challenge-interstitial marker {match.group(0)!r} found in response body")
            vendors.append(vendor)

    if evidence:
        # Confidence reflects how the evidence was obtained, not how alarming
        # it is: a vendor header cannot be forged by page content, body
        # markers can in principle appear in a page quoting a challenge.
        from_header = any(_ci_get(header_map, n) is not None for n, _ in _CHALLENGE_HEADERS)
        return {
            "kind": "bot_challenge",
            "vendors": sorted(set(vendors)),
            "confidence": CONFIDENCE_HIGH if from_header else CONFIDENCE_MEDIUM,
            "status_code": status_code,
            "evidence": evidence + [
                "Response is an anti-bot challenge, not application content; forms, links and "
                "scripts parsed from it describe the challenge and not the target application",
            ],
        }

    widget_evidence: List[str] = []
    widget_vendors: List[str] = []
    for pattern, vendor in _CAPTCHA_WIDGET_MARKERS:
        match = pattern.search(haystack)
        if match:
            widget_evidence.append(f"CAPTCHA widget marker {match.group(0)!r} found in page content")
            widget_vendors.append(vendor)
    if widget_evidence:
        return {
            "kind": "captcha_widget",
            "vendors": sorted(set(widget_vendors)),
            "confidence": CONFIDENCE_MEDIUM,
            "status_code": status_code,
            "evidence": widget_evidence + [
                "A CAPTCHA widget on an otherwise normal page is surface intelligence, not a block; "
                "the page content was parsed normally",
            ],
        }
    return None


# ---------------------------------------------------------------------------
# Request safety: state-changing candidates
#
# This module already refuses to submit forms because doing so risks
# state-changing side effects (module docstring, decision #3). GET /logout and
# GET /account/delete?id=7 are the same class of side effect reached by a
# different route, and the crawler was following both unconditionally.
#
# SCOPE OF THIS CODE. It answers exactly one question the crawler alone can
# answer, because the crawler alone issues these requests: "would requesting
# this URL change server-side state?" It is deliberately NOT auth-surface
# analysis. Identifying and reporting login/logout/password-reset/OAuth/SSO
# surfaces as intelligence is http_analyzer.py's named responsibility
# (context.md module 16), so this code emits a single request-safety reason
# code, no auth taxonomy, and no auth-surface finding of its own. The output
# is an ordinary `crawled_url` record that happens to carry fetched=false.
#
# The rule is evidence-based, never a substring blacklist: matching is on
# whole path segments (with a file extension stripped) and on explicit action
# query parameters, so "/blog/how-to-delete-a-file" and "/deleted-items" are
# crawled normally while "/logout" and "?action=delete" are not. Nothing is
# discarded — a skipped URL is still persisted as discovered surface, marked
# as never fetched, with the reason recorded.
#
# Off by default (avoid_destructive=False), preserving the crawler's reach and
# every pre-existing caller's behaviour; the operator opts in.
# ---------------------------------------------------------------------------

# Whole path segments that name an action, never a document. Requesting one
# performs it.
_ALWAYS_UNSAFE_SEGMENTS = frozenset({
    "logout", "log-out", "logoff", "log-off", "signout", "sign-out",
    "disconnect", "deauth", "deauthenticate", "endsession", "end-session",
})
# Destructive verbs. Matched only as a whole segment, AND only with
# corroborating evidence that the URL is an *action* rather than a page named
# after one — see classify_destructive_candidate. Without that second
# requirement this list suppressed "/password/reset", "/newsletter/
# unsubscribe" and "/docs/remove", which are ordinary GET-safe pages and
# valuable reconnaissance surface.
_DESTRUCTIVE_VERB_SEGMENTS = frozenset({
    "delete", "destroy", "remove", "revoke", "purge", "wipe", "truncate",
    "deactivate", "unsubscribe", "unpublish", "reset",
})
# Segments naming server-side state that a request can mutate. A destructive
# verb applied to one of these acts on stored state whatever else the URL
# looks like ("/api/session/destroy", "/auth/tokens/revoke"), so it
# corroborates on its own. Used only to decide whether to send a request —
# never to classify or report the URL as an authentication surface.
_STATE_OBJECT_SEGMENTS = frozenset({
    "session", "sessions", "auth", "authentication", "token", "tokens",
    "credential", "credentials", "cookie", "cookies",
})
# Query parameters that name an action to perform.
_ACTION_PARAM_NAMES = frozenset({"action", "do", "op", "cmd", "task", "mode", "method"})
_DESTRUCTIVE_ACTION_VALUES = _ALWAYS_UNSAFE_SEGMENTS | _DESTRUCTIVE_VERB_SEGMENTS

# One reason code. The crawler records *that* a request was withheld for
# safety and what matched; deciding what the endpoint means is another
# module's job.
_STATE_CHANGING_REASON = "state_changing_endpoint"


def _segment_stem(segment: str) -> str:
    """"logout.php" -> "logout"; "logout-guide.html" -> "logout-guide"."""
    return segment.rsplit(".", 1)[0].lower() if "." in segment else segment.lower()


def _looks_like_identifier(segment: str) -> bool:
    """A path segment that looks like a specific record's id."""
    return bool(
        re.fullmatch(r"\d+", segment) or _UUID_RE.match(segment) or _OBJECT_ID_RE.match(segment)
    )


def _withheld(matched: str, why: str) -> Dict[str, Any]:
    """A uniform request-safety record. Confidence describes the *finding*
    (this URL was discovered and not fetched), which is certain — not a
    graded opinion about what the endpoint does."""
    return {
        "reason": _STATE_CHANGING_REASON,
        "matched": matched,
        "confidence": CONFIDENCE_HIGH,
        "evidence": [
            f"{why}; ReconHound performs discovery, not state change, so this URL was recorded "
            f"as discovered surface and never requested",
        ],
    }


def classify_destructive_candidate(url: str) -> Optional[Dict[str, Any]]:
    """
    Decide whether requesting `url` risks changing server-side state.

    Returns None (safe to fetch) or a record carrying the matched evidence.
    Conservative by construction: only a whole path segment or an explicit
    action parameter counts, so an article *about* deleting things stays
    crawlable while the endpoint that actually deletes does not.

    This is a request-safety decision, not a classification of the endpoint.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    segments = [seg for seg in (parsed.path or "").split("/") if seg]
    stems = [_segment_stem(seg) for seg in segments]

    for stem in stems:
        if stem in _ALWAYS_UNSAFE_SEGMENTS:
            return _withheld(stem, f"URL path segment {stem!r} names an action rather than a "
                                   f"document, so requesting it would perform it")
    for index, stem in enumerate(stems):
        if stem not in _DESTRUCTIVE_VERB_SEGMENTS:
            continue
        # Require evidence that this is an action on a specific object rather
        # than a page whose name contains a verb: the URL carries parameters,
        # an identifier sits next to the verb, or the verb is applied to
        # mutable server-side state. "/password/reset" and "/docs/remove" are
        # pages and stay crawlable; "/account/delete?id=7", "/posts/delete/42"
        # and "/api/session/destroy" are actions and do not.
        neighbours = stems[index - 1:index] + stems[index + 1:index + 2]
        state_objects = [other for other in stems if other in _STATE_OBJECT_SEGMENTS]
        trigger = None
        if state_objects:
            trigger = (f"it is applied to mutable server-side state "
                       f"({state_objects[0]!r} in the path)")
        elif parsed.query:
            trigger = f"the URL carries query parameters ({parsed.query!r})"
        elif any(_looks_like_identifier(seg) for seg in neighbours):
            trigger = "an object identifier sits adjacent to the verb in the path"
        if trigger:
            return _withheld(stem, f"URL path segment {stem!r} names a destructive action and "
                                   f"{trigger}")
    for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if name.lower() in _ACTION_PARAM_NAMES and value.strip().lower() in _DESTRUCTIVE_ACTION_VALUES:
            return _withheld(f"{name}={value}",
                             f"URL carries action parameter {name}={value!r}, naming an "
                             f"operation that changes state")
    return None


# ---------------------------------------------------------------------------
# Crawl state (visited-set, request budget, error log, dedup sets — shared
# by the whole crawl)
# ---------------------------------------------------------------------------

# An error log is evidence, but it is also unbounded input: a site that
# refuses every request would otherwise grow one entry per request forever.
_MAX_RECORDED_ERRORS = 1000


class _CrawlState:
    def __init__(
        self, target: str, store: Optional[PendingAssetsStore], max_pages: int, max_depth: int,
        avoid_destructive: bool = False,
    ):
        self.target = target
        self.store = store
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.avoid_destructive = avoid_destructive
        self._lock = threading.Lock()
        self._visited: Set[str] = set()
        self._seen: Dict[str, Set[str]] = {}
        self.request_count = 0
        self.budget_exhausted = False
        self.cancelled = False
        self.errors: List[Dict[str, Any]] = []
        self._errors_truncated = False
        # Counters for things this run actually observed. Previously the
        # file-upload total was recomputed by re-reading the whole shared
        # pending_assets.json and counting every matching record in it — which
        # included surfaces found by earlier runs and by other modules, so a
        # run that discovered nothing reported three.
        self.upload_surfaces = 0
        self.challenge_pages = 0
        self.captcha_widget_pages = 0
        self.rate_limited_responses = 0
        self.destructive_skipped = 0
        self.truncated_pages = 0

    def mark_visited(self, normalized_url: str) -> bool:
        with self._lock:
            if normalized_url in self._visited:
                return False
            self._visited.add(normalized_url)
            return True

    def unmark_visited(self, normalized_url: str) -> None:
        """
        Undo a reservation that never became a request.

        mark_visited runs before the budget is charged, so a URL rejected by
        the budget would otherwise stay recorded as visited and be suppressed
        on any later, better-budgeted pass.
        """
        with self._lock:
            self._visited.discard(normalized_url)

    def bump(self, attribute: str, amount: int = 1) -> None:
        with self._lock:
            setattr(self, attribute, getattr(self, attribute) + amount)

    def mark_seen(self, bucket: str, key: str) -> bool:
        """Generic dedup for forms/JS refs/websocket/graphql/external-link findings."""
        with self._lock:
            bucket_set = self._seen.setdefault(bucket, set())
            if key in bucket_set:
                return False
            bucket_set.add(key)
            return True

    def reserve_request(self) -> bool:
        with self._lock:
            if self.request_count >= self.max_pages:
                self.budget_exhausted = True
                return False
            self.request_count += 1
            return True

    def record_error(self, stage: str, url: str, message: str) -> None:
        with self._lock:
            if len(self.errors) >= _MAX_RECORDED_ERRORS:
                if not self._errors_truncated:
                    self._errors_truncated = True
                    self.errors.append({
                        "stage": "errors_truncated", "url": "",
                        "error": f"error log capped at {_MAX_RECORDED_ERRORS} entries; "
                                 f"further errors were counted but not recorded",
                        "timestamp": _now(),
                    })
                return
            self.errors.append({"stage": stage, "url": url, "error": message, "timestamp": _now()})


# Task tuple: (url, discovery_source, source_page)
_Task = Tuple[str, str, Optional[str]]


def _persist_form(
    state: _CrawlState, form: Dict[str, Any], page_url: str, sink: List[Dict[str, Any]],
    challenge: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Classify one form and append its findings to `sink` (written by the
    caller in a single batch — see PendingAssetsStore.add_many).

    `challenge` is the page's anti-bot classification, if any. A form parsed
    out of a bot-challenge interstitial belongs to the challenge, not to the
    target application: it is still recorded (nothing discovered is
    discarded) but marked as such, and it never raises the HIGH-priority
    file-upload surface, which would otherwise be a fabricated finding about
    an application the crawler never actually reached.
    """
    classification = classify_form(form)
    form_key = f"{form.get('method')}|{form.get('resolved_action')}|" + \
        ",".join(sorted(f.get("name") or "" for f in form.get("fields") or []))

    is_challenge_artifact = bool(challenge and challenge.get("kind") == "bot_challenge")

    if state.mark_seen("forms", form_key):
        evidence = [f"<form method={form.get('method')} action={form.get('action')!r}> found on {page_url}"] + \
            classification["evidence"]
        value = {**form, "classification": classification["category"], "not_fetched": True}
        confidence = classification["confidence"]
        if is_challenge_artifact:
            value["challenge_artifact"] = True
            value["challenge_vendors"] = challenge.get("vendors")
            evidence.append(
                f"Parsed from an anti-bot challenge interstitial "
                f"({', '.join(challenge.get('vendors') or ['unidentified vendor'])}); this form belongs to "
                f"the challenge, not to the target application"
            )
            # An inference about a page we were refused cannot be a
            # high-confidence statement about the application.
            confidence = CONFIDENCE_LOW
        sink.append(make_finding(
            finding_type="crawled_form", target=state.target,
            value=value, evidence=evidence, confidence=confidence,
            metadata={"category": classification["category"], "source_page": page_url,
                      "method": form.get("method"), "action": form.get("resolved_action"),
                      "challenge_artifact": is_challenge_artifact},
        ))

        for param in extract_form_field_parameters(form, state.target):
            sink.append(make_parameter_finding(param, state.target))

        if classification["category"] == "file_upload" and not is_challenge_artifact:
            surface = build_file_upload_surface(form, classification)
            state.bump("upload_surfaces")
            sink.append(make_finding(
                finding_type="file_upload_surface", target=state.target, value=surface,
                evidence=classification["evidence"] + [f"Observed on page {page_url}"],
                confidence=classification["confidence"],
                metadata={
                    "severity": "HIGH", "source_page": page_url,
                    "note": "Attack-surface observation only — the presence of a file-upload form is not "
                             "a confirmed vulnerability. Manual verification is required before any "
                             "further action; ReconHound performs no exploitation.",
                },
            ))

    return classification


def _process_page(
    state: _CrawlState, url: str, depth: int, discovery_source: str, source_page: Optional[str],
    timeout: float, max_body_bytes: int,
) -> Tuple[Optional[Dict[str, Any]], List[_Task]]:
    """
    Fetch one page, classify it, extract everything, persist, and report new
    crawl candidates.

    Everything this page yields is accumulated into one `findings` list and
    written with a single add_many() at the end. The page record is built
    and returned whether or not that write succeeds: persistence failing must
    never destroy an already-completed discovery (context.md §12.11), which
    is exactly what happened when each finding was written individually and a
    single OSError propagated out of the worker.
    """
    resp = fetch_url(url, timeout=timeout, max_body_bytes=max_body_bytes)
    if resp["status"] != "found":
        state.record_error("fetch", url, resp.get("error") or "request failed")
        return None, []

    discovery_type, confidence, notes = classify_response(resp)
    headers = resp["headers"]
    body = resp.get("body")
    content_type = _ci_get(headers, "Content-Type")
    try:
        path = urllib.parse.urlsplit(url).path or "/"
    except ValueError:
        path = "/"

    findings: List[Dict[str, Any]] = []
    new_tasks: List[_Task] = []

    if discovery_type == "rate_limited":
        state.bump("rate_limited_responses")

    # A truncated body was parsed only up to the cap, so "no links found"
    # here means "no links in the first max_body_bytes", not "no links".
    # Recording it keeps an incomplete parse from reading as a negative
    # result (context.md §8).
    body_truncated = bool(resp.get("body_truncated"))
    if body_truncated:
        state.bump("truncated_pages")
        notes.append(
            f"Response body exceeded the {max_body_bytes}-byte read cap and was truncated; "
            f"links, forms and indicators were extracted from the retained prefix only, so "
            f"absence of a discovery on this page is not evidence of absence"
        )
    if resp.get("body_read_error"):
        notes.append(f"Response body could not be read safely: {resp['body_read_error']}")

    challenge = detect_challenge_indicators(body, headers, resp.get("status_code"))
    if challenge:
        notes.extend(challenge["evidence"])
        if challenge["kind"] == "bot_challenge":
            state.bump("challenge_pages")
            # The crawler was refused. Whatever this page contains describes
            # the challenge, so the response must not be reported as
            # confirmed application content.
            if discovery_type == "content_confirmed":
                discovery_type = "challenge_response"
            confidence = CONFIDENCE_MEDIUM if confidence == CONFIDENCE_HIGH else confidence
        else:
            state.bump("captcha_widget_pages")

    if discovery_type == "redirect":
        location = _ci_get(headers, "Location")
        if location:
            try:
                abs_redirect = urllib.parse.urljoin(url, location)
            except Exception:
                abs_redirect = None
            if abs_redirect:
                # Credentials in a Location header must not be re-sent or
                # persisted, and the scope check must run on the same string
                # the request would use.
                abs_redirect = _strip_userinfo(abs_redirect)
                if _candidate_in_scope(abs_redirect, state.target):
                    new_tasks.append((abs_redirect, f"redirect_from:{url}", url))
                elif state.mark_seen("external", _normalize_url(abs_redirect)):
                    findings.append(make_finding(
                        finding_type="external_link_observed", target=state.target,
                        value={"url": abs_redirect, "referenced_from": url, "reason": "redirect_target_out_of_scope"},
                        evidence=[f"HTTP {resp['status_code']} redirect from {url} points to out-of-scope/"
                                  f"disallowed target {abs_redirect}; not followed"],
                        confidence=CONFIDENCE_HIGH,
                        metadata={"referenced_from": url, "kind": "redirect_target"},
                    ))

    parameters: List[Dict[str, Any]] = []
    parameters.extend(extract_query_parameters(url, endpoint=path))
    parameters.extend(infer_path_parameters(url))

    form_count = 0
    js_ref_count = 0
    ws_count = 0
    graphql_count = 0

    if _looks_textual(content_type, body):
        # One parse for the whole page; the extractors used to build three.
        soup = _parse_html(body)
        parameters.extend(extract_header_parameter_hints(body, headers))

        forms = extract_forms(body, url, soup=soup)
        if len(forms) > DEFAULT_MAX_FORMS_PER_PAGE:
            state.record_error(
                "form_cap", url,
                f"page declared {len(forms)} forms; only the first {DEFAULT_MAX_FORMS_PER_PAGE} "
                f"were classified and persisted (per-page cap)",
            )
            forms = forms[:DEFAULT_MAX_FORMS_PER_PAGE]
        form_count = len(forms)
        for form in forms:
            _persist_form(state, form, url, findings, challenge=challenge)

        js_refs = extract_javascript_references(
            body, url, target=state.target, soup=soup, max_refs=DEFAULT_MAX_JS_REFS_PER_PAGE)
        if len(js_refs) >= DEFAULT_MAX_JS_REFS_PER_PAGE:
            state.record_error(
                "js_ref_cap", url,
                f"script references on this page reached the per-page cap of "
                f"{DEFAULT_MAX_JS_REFS_PER_PAGE}; any beyond it were not recorded",
            )
        js_ref_count = len(js_refs)
        for ref in js_refs:
            if not state.mark_seen("js", _normalize_url(ref["url"])):
                continue
            findings.append(make_finding(
                finding_type="javascript_reference", target=state.target,
                value={"url": ref["url"], "source_page": ref["source_page"], "in_scope": ref["in_scope"], "fetched": False},
                evidence=ref["evidence"], confidence=CONFIDENCE_HIGH,
                metadata={"source_page": ref["source_page"], "for_module": "js_analyzer.py"},
            ))

        ws_indicators = detect_websocket_indicators(body, url)
        if len(ws_indicators) > DEFAULT_MAX_WS_INDICATORS_PER_PAGE:
            state.record_error(
                "websocket_cap", url,
                f"page contained {len(ws_indicators)} WebSocket URL literals; only the first "
                f"{DEFAULT_MAX_WS_INDICATORS_PER_PAGE} were persisted (per-page cap)",
            )
            ws_indicators = ws_indicators[:DEFAULT_MAX_WS_INDICATORS_PER_PAGE]
        ws_count = len(ws_indicators)
        for ws in ws_indicators:
            ws_key = ws["endpoint"] or f"no_literal:{url}"
            if not state.mark_seen("websocket", ws_key):
                continue
            # A page can reference any WebSocket host it likes. Recording
            # "wss://attacker.example/steal" against the target without
            # saying it is off-target attributed a third party's endpoint to
            # the scanned host.
            ws_in_scope = _ws_endpoint_in_scope(ws["endpoint"], state.target)
            ws_evidence = list(ws["evidence"])
            if ws_in_scope is False:
                ws_evidence.append(
                    "WebSocket endpoint host is outside the crawl scope; referenced by the target "
                    "but not part of its own attack surface"
                )
            findings.append(make_finding(
                finding_type="websocket_indicator", target=state.target,
                value={"endpoint": ws["endpoint"], "source_page": ws["source_page"], "in_scope": ws_in_scope},
                evidence=ws_evidence, confidence=ws["confidence"],
                metadata={"source_page": ws["source_page"], "in_scope": ws_in_scope},
            ))

        page_links = extract_page_links(
            body, url, target=state.target, soup=soup, max_links=DEFAULT_MAX_LINKS_PER_PAGE)
        if len(page_links) >= DEFAULT_MAX_LINKS_PER_PAGE:
            state.record_error(
                "link_cap", url,
                f"links on this page reached the per-page cap of {DEFAULT_MAX_LINKS_PER_PAGE}; "
                f"any beyond it were neither queued nor recorded",
            )

        referenced_urls = [l["url"] for l in page_links] + [r["url"] for r in js_refs]
        graphql_indicators = detect_graphql_indicators(body, url, headers=headers, referenced_urls=referenced_urls)
        graphql_count = len(graphql_indicators)
        for gi in graphql_indicators:
            if not state.mark_seen("graphql", f"{gi['indicator_type']}:{gi['value']}"):
                continue
            findings.append(make_finding(
                finding_type="graphql_indicator", target=state.target,
                value={"indicator_type": gi["indicator_type"], "value": gi["value"], "source_page": gi["source_page"]},
                evidence=gi["evidence"], confidence=gi["confidence"],
                metadata={"source_page": gi["source_page"]},
            ))

        for link in page_links:
            if link["in_scope"]:
                new_tasks.append((link["url"], f"{link['tag']}:{url}", url))
            elif state.mark_seen("external", _normalize_url(link["url"])):
                findings.append(make_finding(
                    finding_type="external_link_observed", target=state.target,
                    value={"url": link["url"], "referenced_from": url, "tag": link["tag"]},
                    evidence=[f"{link['tag']} on {url} references out-of-scope/disallowed URL {link['url']}; not crawled"],
                    confidence=CONFIDENCE_MEDIUM,
                    metadata={"referenced_from": url, "kind": "page_link"},
                ))

    deduped_params: List[Dict[str, Any]] = []
    seen_param_keys = set()
    for p in parameters:
        key = (p["name"], p["location"], p.get("endpoint"))
        if key in seen_param_keys:
            continue
        seen_param_keys.add(key)
        deduped_params.append(p)
        if len(deduped_params) > DEFAULT_MAX_PARAMS_PER_PAGE:
            state.record_error(
                "parameter_cap", url,
                f"page yielded more than {DEFAULT_MAX_PARAMS_PER_PAGE} distinct parameters; "
                f"the remainder were not persisted (per-page cap)",
            )
            deduped_params = deduped_params[:DEFAULT_MAX_PARAMS_PER_PAGE]
            break
        findings.append(make_parameter_finding(p, state.target))

    record: Dict[str, Any] = {
        "target": state.target,
        "url": url,
        "normalized_url": _normalize_url(url),
        "path": path,
        "method": "GET",
        "status_code": resp["status_code"],
        "content_type": content_type,
        "discovery_type": discovery_type,
        "discovery_source": discovery_source,
        "source_page": source_page,
        "depth": depth,
        # Credential-stripped: a Location header can carry "user:pass@host",
        # and this field is persisted and rendered in the report appendix.
        "redirect_location": (
            _strip_userinfo(_ci_get(headers, "Location") or "") or None
        ) if discovery_type == "redirect" else None,
        "confidence": confidence,
        "evidence": [f"GET {url} returned HTTP {resp['status_code']}"] + notes,
        "parameters": deduped_params,
        "form_count": form_count,
        "javascript_reference_count": js_ref_count,
        "websocket_indicator_count": ws_count,
        "graphql_indicator_count": graphql_count,
        "body_truncated": body_truncated,
        "content_complete": not body_truncated and not resp.get("body_read_error"),
        "challenge": {
            "kind": challenge["kind"], "vendors": challenge["vendors"],
            "confidence": challenge["confidence"],
        } if challenge else None,
        "timestamp": _now(),
    }
    findings.append(make_finding(
        finding_type="crawled_url", target=state.target, value=dict(record),
        evidence=record["evidence"], confidence=confidence,
        metadata={
            "discovery_source": discovery_source, "source_page": source_page,
            "depth": depth, "discovery_type": discovery_type, "url": url,
            "challenge_kind": challenge["kind"] if challenge else None,
            "content_complete": record["content_complete"],
        },
    ))

    # One write for the whole page. A failure is recorded but never discards
    # the record: the caller still receives everything discovered here.
    err = _safe_store_add_many(state.store, findings)
    if err:
        state.record_error("persistence", url, err)

    return record, new_tasks


def _run_crawl_batch(
    state: _CrawlState, tasks: List[_Task], depth: int, timeout: float, max_body_bytes: int, max_workers: int,
) -> List[Tuple[Optional[Dict[str, Any]], List[_Task]]]:
    """Run one depth-level of tasks concurrently, respecting the visited-set and request budget."""
    results: List[Tuple[Optional[Dict[str, Any]], List[_Task]]] = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers))
    future_map: Dict[Any, str] = {}
    harvested: Set[Any] = set()
    skip_findings: List[Dict[str, Any]] = []
    try:
        for url, discovery_source, source_page in tasks:
            # The seed task was already validated by validate_crawl_target() in
            # run_crawler() — an operator-authorized base_url/target must never be
            # silently rejected by the discovered-candidate SSRF safeguard (module
            # docstring, decision #6). Every other (discovered) candidate is
            # defense-in-depth re-checked here, since extract_page_links/redirect
            # handling already scope-filter but a future caller of this batch
            # runner must not be able to bypass scope enforcement.
            if discovery_source != "seed" and not _candidate_in_scope(url, state.target):
                if state.mark_seen("external", _normalize_url(url)):
                    skip_findings.append(make_finding(
                        finding_type="external_link_observed", target=state.target,
                        value={"url": url, "referenced_from": source_page, "reason": "out_of_scope_candidate"},
                        evidence=[f"Candidate URL {url} rejected by scope enforcement (source: {discovery_source})"],
                        confidence=CONFIDENCE_HIGH,
                        metadata={"referenced_from": source_page, "kind": "rejected_candidate"},
                    ))
                continue

            # Opt-in request safety: with avoid_destructive enabled, a
            # discovered URL that names a state-changing action is recorded
            # as surface and never requested. An operator-supplied seed is
            # exempt — naming it as the crawl root IS the authorisation, the
            # same distinction validate_crawl_target draws against
            # _candidate_in_scope.
            normalized = _normalize_url(url)
            if state.avoid_destructive and discovery_source != "seed":
                destructive = classify_destructive_candidate(url)
                if destructive is not None:
                    if state.mark_visited(normalized):
                        state.bump("destructive_skipped")
                        skip_findings.append(make_finding(
                            finding_type="crawled_url", target=state.target,
                            value={
                                "target": state.target, "url": url, "normalized_url": normalized,
                                "path": urllib.parse.urlsplit(url).path or "/", "method": "GET",
                                "status_code": None, "discovery_type": "not_fetched",
                                "discovery_source": discovery_source, "source_page": source_page,
                                "depth": depth, "fetched": False,
                                "skip_reason": destructive["reason"],
                                "skip_match": destructive["matched"],
                                "content_complete": False,
                            },
                            evidence=destructive["evidence"] + [
                                f"Discovered as {discovery_source} on {source_page}",
                            ],
                            confidence=destructive["confidence"],
                            metadata={
                                "discovery_source": discovery_source, "source_page": source_page,
                                "depth": depth, "discovery_type": "not_fetched", "url": url,
                                "skip_reason": destructive["reason"],
                            },
                        ))
                    continue

            if not state.mark_visited(normalized):
                continue
            if not state.reserve_request():
                # Never requested, so it must not stay recorded as visited.
                state.unmark_visited(normalized)
                break
            future_map[executor.submit(
                _process_page, state, url, depth, discovery_source, source_page, timeout, max_body_bytes,
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
        # Harvest whatever already finished; nothing discovered is thrown
        # away. `except BaseException` is required, not defensive over-reach:
        # an interrupt delivered inside a worker is stored on that worker's
        # future, so result() re-raises KeyboardInterrupt here too — catching
        # only Exception would let it escape the recovery path and lose the
        # very partial results this block exists to preserve.
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
    err = _safe_store_add_many(state.store, skip_findings)
    if err:
        state.record_error("persistence", "", err)
    return results


# ---------------------------------------------------------------------------
# 1. Full recursive orchestration (single-target)
# ---------------------------------------------------------------------------

def run_crawler(
    base_url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    avoid_destructive: bool = False,
) -> Dict[str, Any]:
    """
    Recursively crawl `base_url` within scope and persist every completed
    discovery immediately to <output_dir>/pending_assets.json (crash-safe).
    Bounded, depth-first-by-level BFS (see endpoint_discovery.py precedent).

    A failure fetching one page (network error, malformed response) does
    not stop the rest of the crawl — see summary["errors"].

    COMPLETENESS. The summary distinguishes a crawl that finished from one
    that was cut short, because downstream reads an empty result as evidence:
    `depth_truncated` (candidates existed at the depth limit and were never
    explored), `request_budget_exhausted`, `cancelled`, and `status`
    ("completed" / "completed_with_errors" / "interrupted"). A partial crawl
    must never report itself as a complete one.

    `avoid_destructive` (default False) is an opt-in safety mode. When
    enabled it keeps the crawler from *requesting* discovered URLs that name
    a state-changing action; they are still recorded as discovered surface,
    marked as never fetched. The default preserves the crawler's normal
    reach and every pre-existing caller's behaviour. The operator-supplied
    `base_url` is never suppressed by it.
    """
    base_url = validate_crawl_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)

    store = PendingAssetsStore(output_dir=output_dir)
    state = _CrawlState(target, store, max_pages, max_depth, avoid_destructive=avoid_destructive)

    summary: Dict[str, Any] = {
        "target": target,
        "module": MODULE_NAME,
        "base_url": base_url,
        "started_at": _now(),
        "pages": [],
        "parameters": [],
        "forms_discovered": 0,
        "javascript_references_discovered": 0,
        "websocket_indicators_discovered": 0,
        "graphql_indicators_discovered": 0,
        "file_upload_surfaces_discovered": 0,
        "external_links_observed": 0,
        "requests_made": 0,
        "max_depth": max_depth,
        "max_depth_reached": False,
        "depth_truncated": False,
        "request_budget_exhausted": False,
        "cancelled": False,
        "rate_limited": False,
        "challenge_pages": 0,
        "captcha_widget_pages": 0,
        "truncated_pages": 0,
        "destructive_endpoints_skipped": 0,
        "crawl_complete": False,
        "errors": [],
    }

    depth = 0
    frontier: List[_Task] = [(base_url, "seed", None)]
    while frontier and depth <= max_depth and not state.budget_exhausted and not state.cancelled:
        results = _run_crawl_batch(state, frontier, depth, timeout, max_body_bytes, max_workers)
        next_frontier: List[_Task] = []
        queued_raw: Set[str] = set()
        pending_beyond_depth = False
        for record, new_candidates in results:
            if record is not None:
                summary["pages"].append(record)
                summary["parameters"].extend(record["parameters"])
            if depth < max_depth:
                # Deduplicate as the frontier is built. Previously every page
                # appended every one of its links, so a 600-link page at 60
                # pages queued 36,000 tuples for a 60-request budget; a
                # duplicate-heavy site grew the frontier without bound.
                for candidate in new_candidates:
                    key = _normalize_url(candidate[0])
                    if key in queued_raw:
                        continue
                    queued_raw.add(key)
                    next_frontier.append(candidate)
            elif new_candidates:
                pending_beyond_depth = True
        # next_frontier is built before its requests are spent, so a wide
        # level can allocate far more task tuples than the run could ever
        # fetch. Truncating at the cap bounds memory without changing which
        # candidates are reachable within the request budget.
        if len(next_frontier) > DEFAULT_MAX_FRONTIER:
            state.record_error(
                "frontier_cap", "",
                f"depth {depth} produced {len(next_frontier)} candidates; truncated to "
                f"{DEFAULT_MAX_FRONTIER} (frontier cap)",
            )
            next_frontier = next_frontier[:DEFAULT_MAX_FRONTIER]
        # Candidates that exist but were never explored because the depth
        # limit stopped the descent — this is what `depth_truncated` reports.
        if pending_beyond_depth:
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
    if frontier and state.budget_exhausted:
        summary["depth_truncated"] = True
    summary["request_budget_exhausted"] = state.budget_exhausted
    summary["cancelled"] = state.cancelled
    summary["requests_made"] = state.request_count
    summary["forms_discovered"] = len(state._seen.get("forms", set()))
    summary["javascript_references_discovered"] = len(state._seen.get("js", set()))
    summary["websocket_indicators_discovered"] = len(state._seen.get("websocket", set()))
    summary["graphql_indicators_discovered"] = len(state._seen.get("graphql", set()))
    summary["external_links_observed"] = len(state._seen.get("external", set()))
    # Counted from what this run actually discovered. Re-reading the shared
    # pending_assets.json and counting every matching record in it also
    # counted earlier runs' and other modules' surfaces, so a run that found
    # none could report three.
    summary["file_upload_surfaces_discovered"] = state.upload_surfaces
    summary["challenge_pages"] = state.challenge_pages
    summary["captcha_widget_pages"] = state.captcha_widget_pages
    summary["truncated_pages"] = state.truncated_pages
    summary["destructive_endpoints_skipped"] = state.destructive_skipped
    summary["rate_limited"] = state.rate_limited_responses > 0

    # The single flag downstream can trust for "this crawl saw the whole
    # reachable surface it was asked to". Anything that cut the walk short —
    # the depth limit, the request budget, an interrupt, a rate limit, an
    # anti-bot challenge, or a body too large to parse in full — makes an
    # empty result inconclusive rather than negative (context.md §8).
    # A crawl that requested pages and never got a single one back did not
    # see "the whole reachable surface"; it saw nothing, because the base URL
    # itself never answered. Reporting that as complete told downstream that
    # this host has no pages, no forms and no JavaScript — the absence-as-fact
    # conclusion this flag exists to prevent.
    summary["crawl_complete"] = not (
        summary["depth_truncated"] or summary["request_budget_exhausted"]
        or summary["cancelled"] or summary["rate_limited"]
        or summary["challenge_pages"] or summary["truncated_pages"]
        or (not summary["pages"] and summary["requests_made"] > 0)
    )

    summary["errors"] = state.errors
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
        prog="crawler.py",
        description="ReconHound Module 12 — recursive in-scope web application discovery (standalone test entry point).",
    )
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://example.com/")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Recursion depth limit")
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES, help="Total page-fetch budget")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Concurrent worker threads")
    parser.add_argument(
        "--avoid-destructive-endpoints", action="store_true",
        help="Do not request discovered URLs that name a state-changing action "
             "(logout, delete, ...); record them as surface with fetched=false instead. "
             "Off by default, preserving the crawler's normal reach.",
    )
    args = parser.parse_args()

    try:
        result = run_crawler(
            args.url, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
            max_depth=args.max_depth, max_pages=args.max_pages, max_workers=args.max_workers,
            avoid_destructive=args.avoid_destructive_endpoints,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
