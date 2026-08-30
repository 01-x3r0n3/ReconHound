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
    hostname = hostname.strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
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
    parsed = urllib.parse.urlsplit(candidate)

    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"URL must use http:// or https://, not {parsed.scheme!r}: {url!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ScopeError(f"URL must include a hostname: {url!r}")

    if target and not _is_ip_literal(hostname) and not _in_scope_host(hostname, target):
        raise ScopeError(f"URL host {hostname!r} is not in scope for target {target!r}: {url!r}")

    return candidate


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
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    hostname = parsed.hostname
    if not hostname:
        return False

    if target and _is_ip_literal(target):
        # IP-literal target: only an exact match is in scope (mirrors
        # _in_scope_host's exact-match semantics; IP addresses have no
        # subdomain concept). No additional private-range check — the
        # operator already authorized this exact address as the target.
        return hostname.strip().rstrip(".").lower() == target.strip().rstrip(".").lower()

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
    store.add() wrapped so a single persistence failure doesn't abort the
    crawl. Returns None on success, or an error message the caller is
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


def _origin_of(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _normalize_url(url: str) -> str:
    """
    Normalize scheme/host casing, default ports, duplicate slashes, and
    query-parameter order, for visited-set dedup (responsibility #1:
    "avoid duplicate URL processing" / "prevent infinite crawling loops").
    """
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if ":" in netloc:
        host, _, port = netloc.rpartition(":")
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    fragment = ""  # fragments never distinguish a distinct server-side resource
    return urllib.parse.urlunsplit((scheme, netloc, path, query, fragment))


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


# ---------------------------------------------------------------------------
# Response classification (status-based only — see module docstring,
# decision #4)
# ---------------------------------------------------------------------------

def classify_response(resp: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    """Classify a fetch_url() result into a discovery_type + confidence + supporting notes."""
    status = resp.get("status_code")
    if status is None:
        return "error", CONFIDENCE_LOW, ["no status code available (request failed)"]
    if status == 404:
        return "not_found", CONFIDENCE_HIGH, []
    if status == 429:
        return "rate_limited", CONFIDENCE_LOW, ["HTTP 429 Too Many Requests — crawl may be incomplete beyond this point"]
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

def extract_page_links(body: str, page_url: str, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Extract navigable <a href>/<iframe src> links from `body`, resolved to
    absolute URLs. Each entry preserves discovery context (tag/attribute)
    and an `in_scope` flag (candidates are not silently dropped — see
    responsibility #11 and _candidate_in_scope).
    """
    if not body:
        return []
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
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
            try:
                abs_url = urllib.parse.urljoin(page_url, ref)
            except Exception:
                continue
            parsed = urllib.parse.urlsplit(abs_url)
            if parsed.scheme not in ("http", "https"):
                continue
            normalized = _normalize_url(abs_url)
            if normalized in seen:
                continue
            seen.add(normalized)
            out.append({
                "url": abs_url,
                "raw": ref,
                "tag": f"{tag_name}[{attr}]",
                "in_scope": _candidate_in_scope(abs_url, target),
            })
    return out


# ---------------------------------------------------------------------------
# 3. Form discovery
# ---------------------------------------------------------------------------

def extract_forms(body: str, page_url: str) -> List[Dict[str, Any]]:
    """
    HTML <form> structure extraction: action, method, enctype, and every
    named field's type + relevant attributes. Malformed HTML degrades to
    an empty result rather than raising.
    """
    if not body:
        return []
    try:
        soup = BeautifulSoup(body, "html.parser")
        forms = soup.find_all("form")
    except Exception:
        return []

    out: List[Dict[str, Any]] = []
    for form in forms:
        method = (form.get("method") or "GET").strip().upper()
        if method not in ("GET", "POST"):
            method = "GET"
        raw_action = form.get("action")
        try:
            resolved_action = urllib.parse.urljoin(page_url, raw_action) if raw_action else page_url
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
            attrs = {k: field.get(k) for k in _FIELD_ATTR_KEYS if field.get(k) is not None}
            if field_type in ("hidden", "submit") and field.get("value") is not None:
                attrs["value"] = str(field.get("value"))[:200]
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

def extract_javascript_references(body: str, page_url: str, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """Extract <script src> references, resolved to absolute URLs, deduplicated per page."""
    if not body:
        return []
    try:
        soup = BeautifulSoup(body, "html.parser")
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
        if not src:
            continue
        try:
            abs_url = urllib.parse.urljoin(page_url, src)
        except Exception:
            continue
        parsed = urllib.parse.urlsplit(abs_url)
        if parsed.scheme not in ("http", "https"):
            continue
        normalized = _normalize_url(abs_url)
        if normalized in seen:
            continue
        seen.add(normalized)
        out.append({
            "url": abs_url,
            "source_page": page_url,
            "in_scope": _candidate_in_scope(abs_url, target),
            "evidence": [f"<script src={src!r}> referenced on {page_url}"],
        })
    return out


# ---------------------------------------------------------------------------
# 7. WebSocket detection
# ---------------------------------------------------------------------------

def detect_websocket_indicators(body: str, page_url: str) -> List[Dict[str, Any]]:
    """
    Detect WebSocket endpoint indicators in fetched page content. Preserves
    the discovered endpoint (when a literal ws(s):// URL is present) and
    evidence, rather than returning a bare boolean — see responsibility #7.
    """
    if not body:
        return []
    out: List[Dict[str, Any]] = []
    literal_matches = sorted(set(m.rstrip(").,;'\"") for m in _WS_LITERAL_RE.findall(body)))
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
# Crawl state (visited-set, request budget, error log, dedup sets — shared
# by the whole crawl)
# ---------------------------------------------------------------------------

class _CrawlState:
    def __init__(self, target: str, store: Optional[PendingAssetsStore], max_pages: int, max_depth: int):
        self.target = target
        self.store = store
        self.max_pages = max_pages
        self.max_depth = max_depth
        self._lock = threading.Lock()
        self._visited: Set[str] = set()
        self._seen: Dict[str, Set[str]] = {}
        self.request_count = 0
        self.budget_exhausted = False
        self.errors: List[Dict[str, Any]] = []

    def mark_visited(self, normalized_url: str) -> bool:
        with self._lock:
            if normalized_url in self._visited:
                return False
            self._visited.add(normalized_url)
            return True

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
            self.errors.append({"stage": stage, "url": url, "error": message, "timestamp": _now()})


# Task tuple: (url, discovery_source, source_page)
_Task = Tuple[str, str, Optional[str]]


def _persist_form(state: _CrawlState, form: Dict[str, Any], page_url: str) -> Dict[str, Any]:
    """Classify + persist one form, plus its parameters and file-upload surface if applicable."""
    classification = classify_form(form)
    form_key = f"{form.get('method')}|{form.get('resolved_action')}|" + \
        ",".join(sorted(f.get("name") or "" for f in form.get("fields") or []))

    if state.mark_seen("forms", form_key):
        evidence = [f"<form method={form.get('method')} action={form.get('action')!r}> found on {page_url}"] + \
            classification["evidence"]
        err = _safe_store_add(state.store, make_finding(
            finding_type="crawled_form", target=state.target,
            value={**form, "classification": classification["category"], "not_fetched": True},
            evidence=evidence, confidence=classification["confidence"],
            metadata={"category": classification["category"], "source_page": page_url,
                      "method": form.get("method"), "action": form.get("resolved_action")},
        ))
        if err:
            state.record_error("persistence", page_url, err)

        for param in extract_form_field_parameters(form, state.target):
            err = _safe_store_add(state.store, make_parameter_finding(param, state.target))
            if err:
                state.record_error("persistence", page_url, err)

        if classification["category"] == "file_upload":
            surface = build_file_upload_surface(form, classification)
            err = _safe_store_add(state.store, make_finding(
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
            if err:
                state.record_error("persistence", page_url, err)

    return classification


def _process_page(
    state: _CrawlState, url: str, depth: int, discovery_source: str, source_page: Optional[str],
    timeout: float, max_body_bytes: int,
) -> Tuple[Optional[Dict[str, Any]], List[_Task]]:
    """Fetch one page, classify it, extract everything, persist, and report new crawl candidates."""
    resp = fetch_url(url, timeout=timeout, max_body_bytes=max_body_bytes)
    if resp["status"] != "found":
        state.record_error("fetch", url, resp.get("error") or "request failed")
        return None, []

    discovery_type, confidence, notes = classify_response(resp)
    headers = resp["headers"]
    body = resp.get("body")
    content_type = _ci_get(headers, "Content-Type")
    path = urllib.parse.urlsplit(url).path or "/"

    new_tasks: List[_Task] = []

    if discovery_type == "redirect":
        location = _ci_get(headers, "Location")
        if location:
            try:
                abs_redirect = urllib.parse.urljoin(url, location)
            except Exception:
                abs_redirect = None
            if abs_redirect:
                if _candidate_in_scope(abs_redirect, state.target):
                    new_tasks.append((abs_redirect, f"redirect_from:{url}", url))
                elif state.mark_seen("external", _normalize_url(abs_redirect)):
                    err = _safe_store_add(state.store, make_finding(
                        finding_type="external_link_observed", target=state.target,
                        value={"url": abs_redirect, "referenced_from": url, "reason": "redirect_target_out_of_scope"},
                        evidence=[f"HTTP {resp['status_code']} redirect from {url} points to out-of-scope/"
                                  f"disallowed target {abs_redirect}; not followed"],
                        confidence=CONFIDENCE_HIGH,
                        metadata={"referenced_from": url, "kind": "redirect_target"},
                    ))
                    if err:
                        state.record_error("persistence", url, err)

    parameters: List[Dict[str, Any]] = []
    parameters.extend(extract_query_parameters(url, endpoint=path))
    parameters.extend(infer_path_parameters(url))

    form_count = 0
    js_ref_count = 0
    ws_count = 0
    graphql_count = 0

    if _looks_textual(content_type, body):
        parameters.extend(extract_header_parameter_hints(body, headers))

        forms = extract_forms(body, url)
        form_count = len(forms)
        for form in forms:
            _persist_form(state, form, url)

        js_refs = extract_javascript_references(body, url, target=state.target)
        js_ref_count = len(js_refs)
        for ref in js_refs:
            if not state.mark_seen("js", _normalize_url(ref["url"])):
                continue
            err = _safe_store_add(state.store, make_finding(
                finding_type="javascript_reference", target=state.target,
                value={"url": ref["url"], "source_page": ref["source_page"], "in_scope": ref["in_scope"], "fetched": False},
                evidence=ref["evidence"], confidence=CONFIDENCE_HIGH,
                metadata={"source_page": ref["source_page"], "for_module": "js_analyzer.py"},
            ))
            if err:
                state.record_error("persistence", url, err)

        ws_indicators = detect_websocket_indicators(body, url)
        ws_count = len(ws_indicators)
        for ws in ws_indicators:
            ws_key = ws["endpoint"] or f"no_literal:{url}"
            if not state.mark_seen("websocket", ws_key):
                continue
            err = _safe_store_add(state.store, make_finding(
                finding_type="websocket_indicator", target=state.target,
                value={"endpoint": ws["endpoint"], "source_page": ws["source_page"]},
                evidence=ws["evidence"], confidence=ws["confidence"],
                metadata={"source_page": ws["source_page"]},
            ))
            if err:
                state.record_error("persistence", url, err)

        page_links = extract_page_links(body, url, target=state.target)
        referenced_urls = [l["url"] for l in page_links] + [r["url"] for r in js_refs]
        graphql_indicators = detect_graphql_indicators(body, url, headers=headers, referenced_urls=referenced_urls)
        graphql_count = len(graphql_indicators)
        for gi in graphql_indicators:
            if not state.mark_seen("graphql", f"{gi['indicator_type']}:{gi['value']}"):
                continue
            err = _safe_store_add(state.store, make_finding(
                finding_type="graphql_indicator", target=state.target,
                value={"indicator_type": gi["indicator_type"], "value": gi["value"], "source_page": gi["source_page"]},
                evidence=gi["evidence"], confidence=gi["confidence"],
                metadata={"source_page": gi["source_page"]},
            ))
            if err:
                state.record_error("persistence", url, err)

        for link in page_links:
            if link["in_scope"]:
                new_tasks.append((link["url"], f"{link['tag']}:{url}", url))
            elif state.mark_seen("external", _normalize_url(link["url"])):
                err = _safe_store_add(state.store, make_finding(
                    finding_type="external_link_observed", target=state.target,
                    value={"url": link["url"], "referenced_from": url, "tag": link["tag"]},
                    evidence=[f"{link['tag']} on {url} references out-of-scope/disallowed URL {link['url']}; not crawled"],
                    confidence=CONFIDENCE_MEDIUM,
                    metadata={"referenced_from": url, "kind": "page_link"},
                ))
                if err:
                    state.record_error("persistence", url, err)

    deduped_params: List[Dict[str, Any]] = []
    seen_param_keys = set()
    for p in parameters:
        key = (p["name"], p["location"], p.get("endpoint"))
        if key in seen_param_keys:
            continue
        seen_param_keys.add(key)
        deduped_params.append(p)
        err = _safe_store_add(state.store, make_parameter_finding(p, state.target))
        if err:
            state.record_error("persistence", url, err)

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
        "redirect_location": _ci_get(headers, "Location") if discovery_type == "redirect" else None,
        "confidence": confidence,
        "evidence": [f"GET {url} returned HTTP {resp['status_code']}"] + notes,
        "parameters": deduped_params,
        "form_count": form_count,
        "javascript_reference_count": js_ref_count,
        "websocket_indicator_count": ws_count,
        "graphql_indicator_count": graphql_count,
        "timestamp": _now(),
    }
    err = _safe_store_add(state.store, make_finding(
        finding_type="crawled_url", target=state.target, value=dict(record),
        evidence=record["evidence"], confidence=confidence,
        metadata={
            "discovery_source": discovery_source, "source_page": source_page,
            "depth": depth, "discovery_type": discovery_type, "url": url,
        },
    ))
    if err:
        state.record_error("persistence", url, err)

    return record, new_tasks


def _run_crawl_batch(
    state: _CrawlState, tasks: List[_Task], depth: int, timeout: float, max_body_bytes: int, max_workers: int,
) -> List[Tuple[Optional[Dict[str, Any]], List[_Task]]]:
    """Run one depth-level of tasks concurrently, respecting the visited-set and request budget."""
    results: List[Tuple[Optional[Dict[str, Any]], List[_Task]]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_map = {}
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
                    err = _safe_store_add(state.store, make_finding(
                        finding_type="external_link_observed", target=state.target,
                        value={"url": url, "referenced_from": source_page, "reason": "out_of_scope_candidate"},
                        evidence=[f"Candidate URL {url} rejected by scope enforcement (source: {discovery_source})"],
                        confidence=CONFIDENCE_HIGH,
                        metadata={"referenced_from": source_page, "kind": "rejected_candidate"},
                    ))
                    if err:
                        state.record_error("persistence", url, err)
                continue
            if not state.mark_visited(_normalize_url(url)):
                continue
            if not state.reserve_request():
                break
            future_map[executor.submit(
                _process_page, state, url, depth, discovery_source, source_page, timeout, max_body_bytes,
            )] = url
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:  # a single bad task must not abort the batch
                state.record_error("probe", url, str(exc))
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
) -> Dict[str, Any]:
    """
    Recursively crawl `base_url` within scope and persist every completed
    discovery immediately to <output_dir>/pending_assets.json (crash-safe).
    Bounded, depth-first-by-level BFS (see endpoint_discovery.py precedent).

    A failure fetching one page (network error, malformed response) does
    not stop the rest of the crawl — see summary["errors"].
    """
    base_url = validate_crawl_target(base_url, target=target)
    target = target or (urllib.parse.urlsplit(base_url).hostname or base_url)

    store = PendingAssetsStore(output_dir=output_dir)
    state = _CrawlState(target, store, max_pages, max_depth)

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
        "max_depth_reached": False,
        "request_budget_exhausted": False,
        "errors": [],
    }

    depth = 0
    frontier: List[_Task] = [(base_url, "seed", None)]
    while frontier and depth <= max_depth and not state.budget_exhausted:
        results = _run_crawl_batch(state, frontier, depth, timeout, max_body_bytes, max_workers)
        next_frontier: List[_Task] = []
        for record, new_candidates in results:
            if record is not None:
                summary["pages"].append(record)
                summary["parameters"].extend(record["parameters"])
            if depth < max_depth:
                next_frontier.extend(new_candidates)
        depth += 1
        frontier = next_frontier

    if frontier and not state.budget_exhausted:
        summary["max_depth_reached"] = True
    summary["request_budget_exhausted"] = state.budget_exhausted
    summary["requests_made"] = state.request_count
    summary["forms_discovered"] = len(state._seen.get("forms", set()))
    summary["javascript_references_discovered"] = len(state._seen.get("js", set()))
    summary["websocket_indicators_discovered"] = len(state._seen.get("websocket", set()))
    summary["graphql_indicators_discovered"] = len(state._seen.get("graphql", set()))
    summary["external_links_observed"] = len(state._seen.get("external", set()))
    summary["file_upload_surfaces_discovered"] = sum(
        1 for f in store.all()
        if f.get("type") == "file_upload_surface" and f.get("target") == target
    ) if store is not None else 0

    summary["errors"] = state.errors
    summary["status"] = "completed_with_errors" if summary["errors"] else "completed"
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
    args = parser.parse_args()

    try:
        result = run_crawler(
            args.url, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
            max_depth=args.max_depth, max_pages=args.max_pages, max_workers=args.max_workers,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
