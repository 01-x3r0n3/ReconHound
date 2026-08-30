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
     documented expected shape (see each function's docstring). Once those
     modules exist, the orchestrator (core/orchestrator.py, not yet built)
     passes their real output straight through these parameters — no
     change to this module's logic is required. This mirrors how
     http_analyzer.py's `target` parameter and active_recon.py's IP inputs
     are already caller-supplied rather than self-discovered.
  2. "Avoid treating every non-404 response as automatically confirmed
     content" (soft-404 handling): before enumerating, this module probes
     one random, near-certainly-nonexistent path per origin to fingerprint
     that host's "not found" response (many apps return HTTP 200 with a
     custom error page instead of a real 404). Any 2xx hit whose status
     code and body closely match that fingerprint is classified
     `possible_soft_404_match` (LOW confidence) instead of
     `content_confirmed` (HIGH confidence). This is a best-effort
     heuristic (body-length + hash comparison, not exhaustive), documented
     as such — it is not a guarantee against all soft-404 patterns.
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
  5. HTTP 429 responses are detected and classified (`rate_limited`) so
     the caller/evidence trail can see enumeration may be incomplete, but
     no backoff/retry/throttling is implemented — a known, documented
     limitation, not an oversight (kept out to avoid unnecessary
     complexity per context.md §3/§12; a future orchestrator-level rate
     limiter, mentioned in context.md §10 item 22, is the natural home for
     that).
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
via PendingAssetsStore (the same crash-safe, atomic-write store used by
Modules 1-3, sharing the same output file). Output is intended to feed
surface_mapper.py (module 6, not yet implemented) — this module does not
implement or call into surface_mapper, crawler, exposure_scan, api_recon,
js_analyzer, wayback_intel, vuln_intel, risk_engine, orchestrator,
report_generator, or any other module not already implemented.

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

# Explicit API roots named by context.md.
API_ROOTS: List[str] = ["api/", "api/v1/", "api/v2/", "graphql/"]

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)
_RECURSION_WORTHY_TYPES = {"content_confirmed", "redirect", "access_restricted", "method_not_allowed"}

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


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = hostname.strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    return hostname == target or hostname.endswith("." + target)


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
# Evidence-model helpers (mirrors passive_recon.py's/active_recon.py's/
# http_analyzer.py's model; kept local per modular independence)
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
    store.add() wrapped so a single persistence failure doesn't abort
    enumeration. Returns None on success, or an error message the caller
    is responsible for recording (never silently discarded).
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


def _ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def _is_directory_like(url: str) -> bool:
    return urllib.parse.urlsplit(url).path.endswith("/")


def _entry_kind(entry: str) -> str:
    """Wordlist convention: entries ending in '/' are directory candidates."""
    return "directory" if entry.endswith("/") else "file"


def _url_for_path(root: str, entry: str) -> str:
    root = _ensure_trailing_slash(root)
    return urllib.parse.urljoin(root, entry.lstrip("/"))


def _normalize_url(url: str) -> str:
    """
    Normalize scheme/host casing, default ports, duplicate slashes, and
    query-parameter order, for visited-set dedup (responsibility #10:
    "duplicate processing / obvious loops"). Trailing-slash presence is
    intentionally preserved (it distinguishes directory- vs file-kind
    candidates, which is meaningful here, not noise).
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
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


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


def _content_signature(body: str) -> Tuple[int, str]:
    normalized = re.sub(r"\s+", " ", body).strip()
    digest = hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()
    return len(normalized), digest


def _lengths_close(a: Optional[int], b: Optional[int], tolerance: int = 25) -> bool:
    if a is None or b is None:
        return False
    return abs(a - b) <= tolerance


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

def _flatten_technology_values(value: Any) -> List[str]:
    out: List[str] = []
    if isinstance(value, dict):
        for v in value.values():
            out.extend(_flatten_technology_values(v))
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            out.extend(_flatten_technology_values(v))
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
    return [
        (wordlist_name, keyword)
        for keyword, wordlist_name in _FRAMEWORK_WORDLISTS.items()
        if keyword in haystack
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
# Response classification (avoids treating every non-404 as confirmed
# content — see module docstring, decision #2)
# ---------------------------------------------------------------------------

def _probe_soft_404(origin: str, timeout: float) -> Dict[str, Any]:
    """Fingerprint `origin`'s "not found" response via one random, near-certainly-absent path."""
    probe_path = f"reconhound-nonexistent-check-{uuid.uuid4().hex[:12]}"
    resp = fetch_url(_ensure_trailing_slash(origin) + probe_path, timeout=timeout)
    if resp["status"] != "found":
        return {"available": False}
    length, digest = _content_signature(resp.get("body") or "")
    return {"available": True, "status_code": resp["status_code"], "content_length": length, "body_hash": digest}


def classify_response(resp: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> Tuple[str, str, List[str]]:
    """
    Classify a fetch_url() result into a discovery_type + confidence +
    supporting notes. Never claims "confirmed" for a soft-404 look-alike.
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


def extract_form_parameters(body: str, page_url: str) -> List[Dict[str, Any]]:
    """
    HTML <form> field extraction (query-location for GET forms,
    body-location for everything else). Malformed HTML degrades to an
    empty result rather than raising.
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
                "data_type": "string", "source": "content_reference",
                "confidence": CONFIDENCE_LOW,
                "evidence": [f"Header name {token!r} referenced in fetched response content"],
            })

    www_auth = _ci_get(headers or {}, "WWW-Authenticate")
    if www_auth:
        out.append({
            "name": "Authorization", "location": "header", "method": "GET", "endpoint": None,
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
        params.extend(extract_header_parameter_hints(body, headers))

    persistence_errors: List[str] = []
    for param in params:
        err = _safe_store_add(store, make_parameter_finding(param, target))
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

def extract_link_candidates(body: str, page_url: str, target: Optional[str] = None) -> List[str]:
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
        soup = BeautifulSoup(body, "html.parser")
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
        except Exception:
            continue
        parsed = urllib.parse.urlsplit(abs_url)
        if parsed.scheme not in ("http", "https"):
            continue
        host = parsed.hostname or ""
        if target and not _is_ip_literal(host) and not _in_scope_host(host, target):
            continue
        resolved.add(abs_url)
    return sorted(resolved)


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
        return {"endpoints": [], "parameters": [], "note": "no historical_data supplied"}

    current_paths = {urllib.parse.urlsplit(e["url"]).path for e in current_endpoints if e.get("url")}
    endpoints_out: List[Dict[str, Any]] = []
    params_out: List[Dict[str, Any]] = []
    persistence_errors: List[str] = []

    for item in historical_data:
        if not isinstance(item, dict):
            continue
        raw_url = item.get("url") or item.get("endpoint")
        if not raw_url:
            continue
        path = urllib.parse.urlsplit(raw_url).path or raw_url
        currently_verified = path in current_paths
        source = item.get("source", "wayback_intel.py")

        endpoint_record = {
            "url": raw_url, "path": path, "historical": True,
            "currently_verified": currently_verified,
            "confidence": CONFIDENCE_MEDIUM if currently_verified else CONFIDENCE_LOW,
            "evidence": list(item.get("evidence") or [f"Historical reference from {source}"]),
            "observed_at": item.get("observed_at"),
            "source": source,
        }
        endpoints_out.append(endpoint_record)
        err = _safe_store_add(store, make_finding(
            finding_type="historical_endpoint_reference", target=target, value=endpoint_record,
            evidence=endpoint_record["evidence"], confidence=endpoint_record["confidence"],
            metadata={"historical": True, "currently_verified": currently_verified, "path": path},
        ))
        if err:
            persistence_errors.append(err)

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
            err = _safe_store_add(store, make_parameter_finding(param_record, target))
            if err:
                persistence_errors.append(err)

    result: Dict[str, Any] = {"endpoints": endpoints_out, "parameters": params_out}
    if persistence_errors:
        result["errors"] = persistence_errors
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
        return {"endpoints": [], "parameters": [], "note": "no js_data supplied"}

    current_paths = {urllib.parse.urlsplit(e["url"]).path for e in current_endpoints if e.get("url")}
    endpoints_out: List[Dict[str, Any]] = []
    params_out: List[Dict[str, Any]] = []
    persistence_errors: List[str] = []

    for item in js_data:
        if not isinstance(item, dict):
            continue
        raw_url = item.get("url") or item.get("endpoint")
        if not raw_url:
            continue
        path = urllib.parse.urlsplit(raw_url).path or raw_url
        currently_verified = path in current_paths
        source_file = item.get("source_file", "js_analyzer.py")

        endpoint_record = {
            "url": raw_url, "path": path, "js_derived": True,
            "currently_verified": currently_verified, "confidence": CONFIDENCE_MEDIUM,
            "evidence": list(item.get("evidence") or [f"JavaScript reference from {source_file}"]),
            "source_file": source_file,
        }
        endpoints_out.append(endpoint_record)
        err = _safe_store_add(store, make_finding(
            finding_type="javascript_endpoint_reference", target=target, value=endpoint_record,
            evidence=endpoint_record["evidence"], confidence=endpoint_record["confidence"],
            metadata={"js_derived": True, "currently_verified": currently_verified, "path": path},
        ))
        if err:
            persistence_errors.append(err)

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
            err = _safe_store_add(store, make_parameter_finding(param_record, target))
            if err:
                persistence_errors.append(err)

    result: Dict[str, Any] = {"endpoints": endpoints_out, "parameters": params_out}
    if persistence_errors:
        result["errors"] = persistence_errors
    return result


# ---------------------------------------------------------------------------
# Enumeration state (visited-set, request budget, error log, soft-404
# cache — shared by every enumeration entry point below)
# ---------------------------------------------------------------------------

class _EnumerationState:
    def __init__(
        self,
        target: str,
        store: Optional[PendingAssetsStore],
        max_requests: int,
        max_depth: int,
        dir_entries: List[str],
        api_entries: List[str],
    ):
        self.target = target
        self.store = store
        self.max_requests = max_requests
        self.max_depth = max_depth
        self.dir_entries = dir_entries
        self.api_entries = api_entries
        self._lock = threading.Lock()
        self._visited = set()
        self.request_count = 0
        self.negative_results = 0
        self.budget_exhausted = False
        self.errors: List[Dict[str, Any]] = []
        self._baseline_lock = threading.Lock()
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}

    def mark_visited(self, normalized_url: str) -> bool:
        with self._lock:
            if normalized_url in self._visited:
                return False
            self._visited.add(normalized_url)
            return True

    def reserve_request(self) -> bool:
        with self._lock:
            if self.request_count >= self.max_requests:
                self.budget_exhausted = True
                return False
            self.request_count += 1
            return True

    def record_error(self, stage: str, url: str, message: str) -> None:
        with self._lock:
            self.errors.append({"stage": stage, "url": url, "error": message, "timestamp": _now()})

    def get_baseline(self, origin: str, timeout: float) -> Dict[str, Any]:
        with self._baseline_lock:
            if origin not in self._baseline_cache:
                self._baseline_cache[origin] = _probe_soft_404(origin, timeout)
            return self._baseline_cache[origin]


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
    resp = fetch_url(url, timeout=timeout)
    if resp["status"] != "found":
        state.record_error("fetch", url, resp.get("error") or "request failed")
        return None, []

    baseline = state.get_baseline(_origin_of(url), timeout)
    discovery_type, base_confidence, notes = classify_response(resp, baseline)

    if discovery_type == "not_found":
        state.negative_results += 1
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
        parameters.extend(extract_form_parameters(body, url))
        parameters.extend(extract_header_parameter_hints(body, headers))
        for link in extract_link_candidates(body, url, target=state.target):
            new_candidates.append((link, "link_extracted", "content_link_extraction", None))

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
        "redirect_location": _ci_get(headers, "Location") if discovery_type == "redirect" else None,
        "confidence": base_confidence,
        "evidence": [f"GET {url} returned HTTP {resp['status_code']}"] + notes,
        "timestamp": _now(),
    }
    err = _safe_store_add(state.store, make_finding(
        finding_type="endpoint_discovered", target=state.target, value=dict(record),
        evidence=record["evidence"], confidence=record["confidence"],
        metadata={
            "category": category, "discovery_source": discovery_source, "discovery_type": discovery_type,
            "technology_association": technology_association, "depth": depth, "url": url,
        },
    ))
    if err:
        state.record_error("persistence", url, err)

    deduped_params: List[Dict[str, Any]] = []
    seen_keys = set()
    for p in parameters:
        key = (p["name"], p["location"], p.get("endpoint"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped_params.append(p)
        err = _safe_store_add(state.store, make_parameter_finding(p, state.target))
        if err:
            state.record_error("persistence", url, err)
    record["parameters"] = deduped_params

    return record, new_candidates


def _run_probe_batch(
    state: _EnumerationState, tasks: List[_Task], depth: int, timeout: float, max_workers: int,
) -> List[Tuple[Optional[Dict[str, Any]], List[_Task]]]:
    """Run one depth-level of tasks concurrently, respecting the visited-set and request budget."""
    results: List[Tuple[Optional[Dict[str, Any]], List[_Task]]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_map = {}
        for url, category, discovery_source, technology_association in tasks:
            if not state.mark_visited(_normalize_url(url)):
                continue
            if not state.reserve_request():
                break
            future_map[executor.submit(
                _probe_and_record, state, url, category, discovery_source, depth, technology_association, timeout,
            )] = url
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:  # a single bad task must not abort the batch
                state.record_error("probe", url, str(exc))
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
    root = _ensure_trailing_slash(_origin_of(base_url))

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
    root = _ensure_trailing_slash(_origin_of(base_url))

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
    root = _ensure_trailing_slash(_origin_of(base_url))
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
    root = _ensure_trailing_slash(_origin_of(base_url))
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
        "requests_made": 0,
        "max_depth_reached": False,
        "request_budget_exhausted": False,
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
    while frontier and depth <= max_depth and not state.budget_exhausted:
        results = _run_probe_batch(state, frontier, depth, timeout, max_workers)
        next_frontier: List[_Task] = []
        for record, new_candidates in results:
            if record is not None:
                summary["endpoints"].append(record)
                summary["parameters"].extend(record["parameters"])
            if depth < max_depth:
                next_frontier.extend(new_candidates)
        depth += 1
        frontier = next_frontier

    if frontier and not state.budget_exhausted:
        summary["max_depth_reached"] = True
    summary["request_budget_exhausted"] = state.budget_exhausted
    summary["negative_results_count"] = state.negative_results
    summary["requests_made"] = state.request_count

    summary["historical_correlation"] = correlate_historical_parameters(
        summary["endpoints"], historical_data, target=target, store=store,
    )
    summary["javascript_correlation"] = correlate_javascript_parameters(
        summary["endpoints"], js_data, target=target, store=store,
    )

    summary["errors"].extend(state.errors)
    summary["status"] = "completed_with_errors" if summary["errors"] else "completed"
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
