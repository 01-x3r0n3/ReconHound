"""
reconhound/js_analyzer.py — ReconHound Module 13 (js_analyzer.py), per
context.md §13's build order (position 18 — after surface_mapper.py,
position 8, which is not yet implemented; this repository is already
operating under the same explicit, user-approved build-order deviation
documented in code_leak.py's/tech_fingerprint.py's/wayback_intel.py's
module docstrings).

Phase: Active. See context.md §10 (module 13, "Deep client-side intel")
for the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Deep client-side intel. Downloads + analyzes JS files, extracts API
  URLs/routes/internal endpoints/external service refs, config-value
  detection, secret-indicator flagging (for manual verification, never
  confirmed), source-map detection + `.js.map` parsing + original-source
  reconstruction, client-side sources/sinks/data-flows/postMessage/
  localStorage mapping, WebSocket endpoint detection, correlates JS refs
  to API endpoints via surface_mapper/api_recon. Key differentiator."

That expands into these discrete responsibilities, each implemented below:

  1. JavaScript acquisition (download, redirects handled safely,
     scope-enforced)                          -> fetch_javascript_file
  2. Content analysis:
       API URLs/routes/internal endpoints      -> extract_api_references
       external service references             -> extract_external_service_references
       config-value detection                  -> extract_config_values
       secret-indicator flagging                -> extract_secret_indicators
       WebSocket endpoints                      -> detect_websocket_references
  3. Source maps:
       detection (.js.map / sourceMappingURL)   -> detect_source_map_reference
       retrieval                                -> fetch_source_map
       safe parsing                             -> parse_source_map
       original-source reconstruction           -> reconstruct_original_sources
       (all four orchestrated per-file, with
        recursive re-analysis of reconstructed
        sources)                                -> process_source_map
  4. Client-side attack-surface intelligence:
       sources/sinks/possible data flows        -> extract_client_side_signals
       postMessage                              -> extract_postmessage_signals
       localStorage                             -> extract_localstorage_signals
  5. API correlation, normalized for the
     ALREADY-BUILT endpoint_discovery.py
     interface (see NO-CROSS-MODULE-CALLS
     PRECEDENT below)                           -> build_endpoint_discovery_js_data
                                                    (assembled inline by
                                                    persist_analysis_findings)

Plus shared plumbing: make_finding/make_js_finding, PendingAssetsStore,
_safe_store_add, fetch_url (duplicated per modular independence, same as
every other implemented module), analyze_javascript_content (bundles
responsibilities #2/#4 for one already-fetched script — independently
testable), persist_analysis_findings (persistence + js_data assembly for
one analyzed unit), and a multi-file orchestrator run_js_analyzer
(mirroring the run_http_analysis/run_endpoint_discovery/run_crawler
precedent — not itself a listed context.md responsibility).

NO-CROSS-MODULE-CALLS PRECEDENT (important for responsibility #5, "API
correlation... via surface_mapper/api_recon", and for this module's own
input): every already-implemented module in this repository documents
that it does not import or call into any sibling module — integration is
deferred to core/orchestrator.py (not yet built). This module follows the
same precedent from both ends:

  a. INPUT: crawler.py (already implemented) persists each discovered
     `<script src>` reference as a `javascript_reference` finding with
     value `{"url":, "source_page":, "in_scope":, "fetched": False}` and
     explicitly tags it `metadata={"for_module": "js_analyzer.py"}` — but
     crawler.py never calls this module directly (see crawler.py's own
     module docstring, decision #1). This module's `run_js_analyzer`
     therefore accepts `js_files` as caller-supplied input, and its
     normalization (`_normalize_js_reference`) accepts crawler.py's raw
     persisted finding records verbatim (as well as a plain list of URL
     strings, or `{"url":, "source_page":}` dicts) — no adaptation layer
     is required to wire the two together once an orchestrator exists.
  b. OUTPUT: `build_endpoint_discovery_js_data` (assembled per-file inside
     `persist_analysis_findings`) normalizes every discovered
     API/route/internal-endpoint reference into the EXACT shape
     endpoint_discovery.py's `correlate_javascript_parameters` function
     ALREADY documents as its expected `js_data` input —
     `{"url":, "parameters": [{"name":,"location":,"method":,"data_type":}],
     "evidence": [...], "source_file": str}` (see endpoint_discovery.py's
     own module docstring, decision #1, and its `correlate_javascript_
     parameters` docstring, which literally names this as "the eventual
     js_analyzer.py output"). This module never imports or calls
     endpoint_discovery.py itself — it only produces data shaped for that
     already-built, already-caller-supplied parameter, exactly as
     tech_fingerprint.py does for `technology`. The "JavaScript reference
     → API endpoint → surface_mapper.py → api_recon" chain the assignment
     describes is therefore satisfied by producing evidence-rich,
     correctly-shaped output at each existing seam, not by building a
     second, competing correlation engine inside this file.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). This module
does not implement or call into surface_mapper, active_recon,
tech_fingerprint, vhost_scanner, endpoint_discovery, api_recon, crawler,
supply_chain, exposure_scan, http_analyzer, ssl_analyzer, screenshot,
vuln_intel, risk_engine, report_generator, orchestrator, osint_engine, or
any other module.

SECURITY BOUNDARIES (context.md §4/§16, assignment's explicit "ACTIVE
SCOPE" instructions):

  - Every fetch this module performs — the JS file itself, redirect hops,
    and any discovered source map — is scope-validated the same way as
    every other active module (`validate_url_target`, plus the same
    `_is_disallowed_redirect_ip` SSRF safeguard http_analyzer.py/
    crawler.py already define, duplicated per modular independence). A
    reference to an out-of-scope host is recorded as a
    `js_analyzer_skipped_out_of_scope` finding — never silently dropped,
    and never fetched.
  - External service references (a JS file referencing
    `https://js.stripe.com/...`, `https://www.google-analytics.com/...`,
    etc.) are recorded as OBSERVATIONS ONLY from content already fetched
    for the JS file itself — this module never issues a request to any
    out-of-scope host, including a source map hosted on a third-party CDN
    (that reference is recorded, never fetched, mirroring the
    out-of-scope-JS-reference handling above).
  - Secret-pattern matches (`extract_secret_indicators`) are OBSERVATIONS,
    never confirmed credentials: every matched value is reduced to a
    partially-masked representation (`_redact_secret`) plus a SHA-256
    fingerprint (for downstream exact-match correlation without
    re-exposing the value) before it is ever persisted or returned — the
    raw matched string is never stored. No matched value is ever used in
    a subsequent request (no "does this credential authenticate"
    verification of any kind).
  - Client-side source/sink "possible data flow" observations
    (`extract_client_side_signals`) are an explicitly-labeled PROXIMITY
    HEURISTIC (a source pattern and a sink pattern found within a few
    lines of each other in the raw, often-minified script) — not a taint
    analysis, and never persisted above LOW confidence. Every such finding
    states in its own evidence that it is unverified and requires manual
    review; none claims an exploitable vulnerability.

Implementation decisions (ambiguities resolved so implementation can
proceed without inventing requirements):

  1. Extraction throughout this module is regex-based over the raw script
     text, matching every other already-implemented module's approach for
     JS/HTML content (endpoint_discovery.py's `_JS_CALL_RE`/
     `_QUOTED_API_PATH_RE`, http_analyzer.py's JWT/auth-surface patterns).
     A full JavaScript AST parse is not implemented — this is a
     documented, deliberate scope limitation (not an oversight): it keeps
     the module dependency-free and consistent with the codebase's
     existing precedent, at the cost of missing references only
     expressible via runtime string construction (dynamically built URLs,
     computed property names, etc.).
  2. Source-map original-source reconstruction (#3) relies on the
     standard, commonly-embedded `sourcesContent` array — when a source
     map embeds each original file's full text there (the common case for
     maps meant to be publicly debuggable), reconstruction is exact. Full
     VLQ `mappings` decoding (byte-for-byte token-to-original-position
     mapping per the Source Map v3 spec) is NOT implemented — that is a
     substantial, separate parsing task disproportionate to this
     assignment's scope, and is not required to satisfy "reconstruct/
     inspect original source" when `sourcesContent` is present, which is
     the overwhelming common case for maps an attacker/analyst could
     obtain at all. When `sourcesContent` is absent, only the referenced
     original filenames (`sources`) are recorded — a real, documented
     limitation, not silently hidden.
  3. `.js.map` discovery has two tiers: an EXPLICIT `//# sourceMappingURL=`
     (or the equivalent block-comment form) reference is trusted and
     always recorded once source-map processing runs. An IMPLICIT guess —
     probing the conventional `<script-url>.map` sibling when no explicit
     comment exists — is also attempted (a very common real-world
     convention many build tools still emit even without the comment),
     but is only ever persisted as a finding once it has actually been
     fetched and confirmed (a non-2xx/parse-failure result for an
     unconfirmed guess is simply not recorded — persisting "we guessed a
     URL that turned out to be wrong" for every script would be noise,
     not evidence).
  4. Body-parameter hints (`extract_body_parameter_hints`, feeding the
     `parameters` list of #5's `js_data` output) are a best-effort,
     file-wide regex scan for `JSON.stringify({...})` object-literal keys
     near a fetch/axios call — this cannot reliably associate a specific
     key set to a specific endpoint URL without a real parser (decision
     #1), so when present they are attached to every API-reference finding
     from the same file with an explicit "file-wide heuristic, not
     confirmed specific to this endpoint" evidence note, rather than
     silently asserting a precise per-endpoint association the extraction
     method cannot actually support.
  5. `requests` is reused, no new dependency (same pattern as every other
     active module). JS files and source maps are fetched with a larger
     default body-size ceiling than HTML-oriented modules
     (`DEFAULT_MAX_BODY_BYTES` / `DEFAULT_MAX_SOURCE_MAP_BYTES`), since
     production JS bundles and their maps are routinely megabytes —
     content beyond the ceiling is truncated, not rejected, and
     `body_truncated` is preserved so downstream consumers know analysis
     may be incomplete.
  6. Only GET requests are made, and only to the JS file's own scope
     (itself, its redirect targets, and its own source map) — this module
     discovers client-side surface, it never exercises or authenticates
     to anything it finds (assignment's explicit "do not exploit... do
     not authenticate using extracted values" instruction).

DISCOVERY != CONFIRMED VULNERABILITY: every record here is an observation
with explicit evidence and confidence. None of this module's output —
including secret-pattern matches and source/sink proximity observations —
should be read as "vulnerable", "exploitable", or "confirmed" absent
independent, human verification.
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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

MODULE_NAME = "js_analyzer.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"
_CONF_ORDER = [CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH]

DEFAULT_USER_AGENT = "ReconHound-JSAnalyzer/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BODY_BYTES = 2_000_000
DEFAULT_MAX_SOURCE_MAP_BYTES = 5_000_000
DEFAULT_MAX_REDIRECT_HOPS = 5

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors http_analyzer.py's/endpoint_discovery.py's/
# crawler.py's validate_url_target and SSRF safeguard; duplicated per
# modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_disallowed_redirect_ip(host: str) -> bool:
    """Private/loopback/link-local/multicast/reserved/unspecified IP-literal check (SSRF safeguard)."""
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
    )


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = (hostname or "").strip().rstrip(".").lower()
    target = (target or "").strip().rstrip(".").lower()
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def validate_url_target(url: str, target: Optional[str] = None) -> str:
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
# Evidence-model helpers (mirrors every other implemented module's model;
# kept local per modular independence, context.md §12.2)
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


def make_js_finding(
    finding_type: str,
    target: str,
    value: Any,
    evidence: List[str],
    confidence: str,
    parent_js_url: str,
    source_page: Optional[str] = None,
    derived_from_source_map: bool = False,
    original_source_file: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Wrap one discovery with the OUTPUT section's required "relationship to
    the originating JavaScript file" — every finding this module persists
    goes through this helper so `parent_js_url`/`source_page`/source-map
    provenance is never lost.
    """
    metadata: Dict[str, Any] = {
        "parent_js_url": parent_js_url,
        "source_page": source_page,
        "derived_from_source_map": derived_from_source_map,
        "original_source_file": original_source_file,
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    return make_finding(finding_type, target, value, evidence, confidence, metadata)


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as every other module's
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
    rest of this module's work. Returns None on success, or an error
    message the caller is responsible for recording (never silently
    discarded).
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


def _truncate(text: Optional[str], limit: int = 300) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "…"


def _looks_textual(content_type: Optional[str], body: Optional[str]) -> bool:
    """Best-effort textual-content check so binary responses aren't parsed as JS."""
    if not body:
        return False
    if content_type:
        ct = content_type.lower()
        if any(t in ct for t in ("javascript", "ecmascript", "json", "text")):
            return True
        if any(
            t in ct for t in (
                "image/", "video/", "audio/", "font/", "application/octet-stream",
                "application/zip", "application/pdf", "application/gzip", "application/wasm",
            )
        ):
            return False
    return True


def _infer_data_type(value: str) -> str:
    """LOW-confidence-by-nature type inference from an observed query-parameter value."""
    if value == "":
        return "unknown"
    if re.fullmatch(r"[+-]?\d+", value):
        return "integer"
    if re.fullmatch(r"[+-]?\d+\.\d+", value):
        return "float"
    if value.lower() in ("true", "false"):
        return "boolean"
    return "string"


def _confidence_from_count(n: int, floor: str = CONFIDENCE_LOW) -> str:
    """Multiple independent converging signals raise confidence (context.md §8)."""
    idx = max(_CONF_ORDER.index(floor), min(n - 1, 2))
    return _CONF_ORDER[idx]


# ---------------------------------------------------------------------------
# Secret-redaction helpers (mirrors code_leak.py's model; duplicated per
# modular independence — see module docstring, SECURITY BOUNDARIES)
# ---------------------------------------------------------------------------

def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _redact_secret(value: str) -> str:
    """Return a partially-masked representation of `value`; never the raw secret."""
    if not value:
        return ""
    if len(value) <= 8:
        return value[0] + "*" * (len(value) - 1) if len(value) > 1 else "*"
    stars = min(len(value) - 8, 24)
    return f"{value[:4]}{'*' * stars}{value[-4:]}"


def _context_snippet(body: str, start: int, end: int, redacted_value: str, window: int = 40) -> str:
    """A short, already-redacted excerpt around a matched span — never the raw secret span."""
    s = max(0, start - window)
    e = min(len(body), end + window)
    return f"{body[s:start]}«{redacted_value}»{body[end:e]}"


# ---------------------------------------------------------------------------
# Shared HTTP client (not itself a listed context.md responsibility, but
# necessary plumbing — mirrors every other module's fetch_url)
# ---------------------------------------------------------------------------

def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """Perform a single HTTP GET against `url` without auto-following redirects."""
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
# 1. JavaScript acquisition (redirects handled hop-by-hop, scope-enforced
# between hops — mirrors http_analyzer.py's map_redirect_chain technique)
# ---------------------------------------------------------------------------

def fetch_javascript_file(
    url: str,
    target: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    max_redirect_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
) -> Dict[str, Any]:
    """
    Download one JS file, following redirects hop-by-hop (never via
    `requests`' `allow_redirects=True`) so scope — including the SSRF
    safeguard against private/loopback/reserved IP redirect targets — is
    enforced at every hop, not just the initial request.
    """
    current = url
    hops: List[Dict[str, Any]] = []
    for _ in range(max_redirect_hops):
        resp = fetch_url(current, timeout=timeout, max_body_bytes=max_body_bytes)
        hop_entry: Dict[str, Any] = {"url": current, "status_code": resp.get("status_code"), "error": resp.get("error")}
        hops.append(hop_entry)

        if resp["status"] != "found":
            return {"status": "error", "error": resp.get("error"), "hops": hops, "final_url": current}
        if resp["status_code"] not in _REDIRECT_STATUS_CODES:
            result = dict(resp)
            result["hops"] = hops
            result["final_url"] = resp.get("final_url", current)
            return result

        location = _ci_get(resp["headers"], "Location")
        if not location:
            return {"status": "error", "error": "redirect response without Location header", "hops": hops, "final_url": current}

        next_url = urllib.parse.urljoin(current, location)
        next_host = urllib.parse.urlsplit(next_url).hostname or ""
        if _is_disallowed_redirect_ip(next_host):
            return {
                "status": "error",
                "error": f"redirect target {next_host!r} is a private/loopback/reserved IP (SSRF safeguard)",
                "hops": hops, "final_url": current,
            }
        if target and not _is_ip_literal(next_host) and not _in_scope_host(next_host, target):
            return {
                "status": "error",
                "error": f"redirect target host {next_host!r} is out of scope for target {target!r}",
                "hops": hops, "final_url": current,
            }
        hop_entry["location"] = next_url
        current = next_url

    return {"status": "error", "error": f"exceeded max_redirect_hops ({max_redirect_hops})", "hops": hops, "final_url": current}


# ---------------------------------------------------------------------------
# 2a. API URLs / routes / internal endpoints
# ---------------------------------------------------------------------------

_ABS_URL_RE = re.compile(r'https?://[^\s"\'<>()\\]+', re.IGNORECASE)
_JS_CALL_RE = re.compile(
    r'(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|\.open)\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_REL_PATH_RE = re.compile(r'["\'](/(?:api|graphql|rest|internal|v[0-9]+)[A-Za-z0-9_\-./]*)["\']', re.IGNORECASE)


def _looks_api_path(url: str) -> bool:
    path = (urllib.parse.urlsplit(url).path or "").lower()
    if any(tok in path for tok in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/", "/internal/")):
        return True
    return path.startswith(("/api", "/graphql"))


def extract_api_references(body: str, js_url: str, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Extract in-scope API URLs, routes, and internal endpoints (responsibility
    #2). Absolute URLs, fetch()/axios()/XHR call targets, and relative
    API-shaped path literals are all considered; results are deduplicated
    by resolved URL and every matching mechanism's evidence is preserved.
    An explicit `target` may be supplied; otherwise the JS file's own
    hostname is used as the implicit scope (a script's own origin is
    always "in scope" for the purposes of interpreting its own references).
    """
    if not body:
        return []
    effective_target = target or (urllib.parse.urlsplit(js_url).hostname or "")
    found: Dict[str, Dict[str, Any]] = {}

    def add(raw: str, resolved: str, kind: str, evidence_text: str) -> None:
        entry = found.setdefault(resolved, {"url": resolved, "raw": raw, "kind": kind, "evidence": []})
        if kind == "api_endpoint":
            entry["kind"] = "api_endpoint"
        entry["evidence"].append(evidence_text)

    for m in _ABS_URL_RE.finditer(body):
        raw = m.group(0).rstrip(").,;'\"\\")
        host = urllib.parse.urlsplit(raw).hostname or ""
        if not _in_scope_host(host, effective_target):
            continue
        kind = "api_endpoint" if _looks_api_path(raw) else "internal_route"
        add(raw, raw, kind, f"Absolute URL referenced in JS: {raw!r}")

    for m in _JS_CALL_RE.finditer(body):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("data:", "javascript:", "blob:")):
            continue
        try:
            resolved = urllib.parse.urljoin(js_url, raw)
        except Exception:
            continue
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.scheme not in ("http", "https"):
            continue
        if not _in_scope_host(parsed.hostname or "", effective_target):
            continue
        kind = "api_endpoint" if _looks_api_path(resolved) else "internal_route"
        add(raw, resolved, kind, f"fetch()/axios()/XHR call target: {raw!r}")

    for m in _REL_PATH_RE.finditer(body):
        raw = m.group(1)
        try:
            resolved = urllib.parse.urljoin(js_url, raw)
        except Exception:
            continue
        add(raw, resolved, "api_endpoint", f"Relative API-shaped path literal found in JS: {raw!r}")

    return sorted(found.values(), key=lambda r: r["url"])


# ---------------------------------------------------------------------------
# 2b. External service references (observation only — never fetched)
# ---------------------------------------------------------------------------

_EXTERNAL_SERVICE_DOMAINS: Dict[str, "tuple[str, str]"] = {
    "google-analytics.com": ("Google Analytics", "analytics"),
    "googletagmanager.com": ("Google Tag Manager", "analytics"),
    "doubleclick.net": ("Google DoubleClick", "advertising"),
    "connect.facebook.net": ("Facebook Pixel/SDK", "analytics"),
    "facebook.net": ("Facebook Pixel/SDK", "analytics"),
    "sentry.io": ("Sentry", "error_tracking"),
    "ingest.sentry.io": ("Sentry", "error_tracking"),
    "stripe.com": ("Stripe", "payment"),
    "js.stripe.com": ("Stripe", "payment"),
    "paypal.com": ("PayPal", "payment"),
    "cloudflareinsights.com": ("Cloudflare Insights", "analytics"),
    "segment.io": ("Segment", "analytics"),
    "segment.com": ("Segment", "analytics"),
    "mixpanel.com": ("Mixpanel", "analytics"),
    "hotjar.com": ("Hotjar", "analytics"),
    "intercom.io": ("Intercom", "support"),
    "auth0.com": ("Auth0", "auth"),
    "amazonaws.com": ("AWS", "cloud_infrastructure"),
    "cloudfront.net": ("AWS CloudFront", "cdn"),
    "googleapis.com": ("Google APIs", "cloud_infrastructure"),
    "firebaseio.com": ("Firebase", "backend_as_a_service"),
    "firebaseapp.com": ("Firebase", "backend_as_a_service"),
}


def _match_external_service_domain(host: str) -> Optional["tuple[str, str]"]:
    for domain, info in _EXTERNAL_SERVICE_DOMAINS.items():
        if host == domain or host.endswith("." + domain):
            return info
    return None


def extract_external_service_references(body: str, js_url: str, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Identify known third-party service domains referenced in already-
    fetched JS content (responsibility #2). These are OBSERVATIONS ONLY —
    this function never issues a network request; deeper third-party
    trust-mapping is supply_chain.py's (module 14) named responsibility,
    not this module's.
    """
    if not body:
        return []
    effective_target = target or (urllib.parse.urlsplit(js_url).hostname or "")
    found: Dict[Any, Dict[str, Any]] = {}
    for m in _ABS_URL_RE.finditer(body):
        raw = m.group(0).rstrip(").,;'\"\\")
        host = (urllib.parse.urlsplit(raw).hostname or "").lower()
        if not host or _in_scope_host(host, effective_target):
            continue
        vendor = _match_external_service_domain(host)
        if not vendor:
            continue
        name, category = vendor
        key = (name, host)
        entry = found.setdefault(key, {"vendor": name, "category": category, "host": host, "example_url": raw, "evidence": []})
        entry["evidence"].append(f"Reference to {host!r} found in JS ({name})")
    return sorted(found.values(), key=lambda r: (r["vendor"], r["host"]))


# ---------------------------------------------------------------------------
# 2c. Configuration-value detection
# ---------------------------------------------------------------------------

CONFIG_KEY_PATTERNS = [
    ("api_base_url", CONFIDENCE_LOW,
     re.compile(r'(?i)\b(?:api[_-]?base[_-]?url|apiurl|base[_-]?url)["\']?\s*[:=]\s*["\']([^"\']{3,200})["\']')),
    ("environment", CONFIDENCE_LOW,
     re.compile(r'(?i)\benv(?:ironment)?["\']?\s*[:=]\s*["\'](production|staging|development|dev|prod|test)["\']')),
    ("app_version", CONFIDENCE_LOW,
     re.compile(r'(?i)\bapp[_-]?version["\']?\s*[:=]\s*["\'](\d+\.\d+(?:\.\d+)?)["\']')),
    ("sentry_dsn", CONFIDENCE_MEDIUM,
     re.compile(r'https://[a-f0-9]{32}@[a-z0-9.\-]*sentry[a-z0-9.\-]*/[0-9]+', re.IGNORECASE)),
    ("stripe_publishable_key", CONFIDENCE_MEDIUM,
     re.compile(r'\bpk_(?:live|test)_[0-9a-zA-Z]{16,}\b')),
    ("google_maps_key_reference", CONFIDENCE_LOW,
     re.compile(r'(?i)\bgoogle[_-]?maps[_-]?(?:api[_-]?)?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,60})["\']')),
]


def extract_config_values(body: str) -> List[Dict[str, Any]]:
    """
    Detect benign, non-secret configuration-value indicators (responsibility
    #3). These are informational observations (API base URLs, environment
    labels, publishable keys that are, by design, not sensitive) — kept
    entirely separate from `extract_secret_indicators`.
    """
    if not body:
        return []
    out: List[Dict[str, Any]] = []
    for name, confidence, pattern in CONFIG_KEY_PATTERNS:
        for m in pattern.finditer(body):
            value = m.group(1) if m.groups() else m.group(0)
            out.append({
                "key": name, "value": _truncate(value, 200), "confidence": confidence,
                "evidence": [f"Config pattern {name!r} matched: {_truncate(m.group(0), 200)!r}"],
            })
    return out


# ---------------------------------------------------------------------------
# 2d. Secret-indicator flagging (never confirmed — see module docstring,
# SECURITY BOUNDARIES; mirrors code_leak.py's model, duplicated per
# modular independence)
# ---------------------------------------------------------------------------

JS_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {"name": "aws_access_key_id", "category": "api_key", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "value_group": 0},
    {"name": "aws_secret_access_key", "category": "credential", "confidence": CONFIDENCE_MEDIUM,
     "regex": re.compile(r'(?i)aws_?secret_?(?:access_?)?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'),
     "value_group": 1},
    {"name": "github_token", "category": "token", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "value_group": 0},
    {"name": "slack_token", "category": "token", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"), "value_group": 0},
    {"name": "google_api_key", "category": "api_key", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "value_group": 0},
    {"name": "stripe_live_secret_key", "category": "api_key", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"\bsk_live_[0-9a-zA-Z]{16,64}\b"), "value_group": 0},
    {"name": "private_key_block", "category": "credential", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "value_group": 0},
    {"name": "jwt_token", "category": "token", "confidence": CONFIDENCE_LOW,
     "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "value_group": 0},
    {"name": "db_connection_string", "category": "db_connection_string", "confidence": CONFIDENCE_HIGH,
     "regex": re.compile(r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s"\'<>]+'),
     "value_group": 0},
    {"name": "generic_api_key_assignment", "category": "api_key", "confidence": CONFIDENCE_MEDIUM,
     "regex": re.compile(r'(?i)\bapi[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,64})["\']?'), "value_group": 1},
    {"name": "generic_secret_assignment", "category": "credential", "confidence": CONFIDENCE_MEDIUM,
     "regex": re.compile(
         r'(?i)\b(?:secret|token|password|passwd|pwd)["\']?\s*[:=]\s*["\']?([A-Za-z0-9!@#$%^&*_\-/+=]{8,64})["\']?'
     ), "value_group": 1},
]


def extract_secret_indicators(body: str) -> List[Dict[str, Any]]:
    """
    Match known secret/credential patterns (responsibility #3). Every
    result is an unverified pattern match — see module docstring, SECURITY
    BOUNDARIES. The raw matched value is NEVER returned: only a partially-
    masked representation and a SHA-256 fingerprint (for downstream exact-
    match correlation without re-exposing the value).
    """
    if not body:
        return []
    out: List[Dict[str, Any]] = []
    for pat in JS_SECRET_PATTERNS:
        for m in pat["regex"].finditer(body):
            group_idx = pat["value_group"]
            try:
                value = m.group(group_idx) if group_idx else m.group(0)
            except IndexError:
                continue
            if not value:
                continue
            redacted = _redact_secret(value)
            note = None
            if pat["confidence"] != CONFIDENCE_HIGH:
                note = "Generic keyword/pattern-based match; elevated false-positive risk. Verify manually before acting on it."
            start, end = m.span(group_idx) if group_idx else m.span(0)
            out.append({
                "category": pat["category"], "pattern_name": pat["name"], "confidence": pat["confidence"],
                "redacted_value": redacted, "fingerprint_sha256": _fingerprint(value),
                "context": _context_snippet(body, start, end, redacted), "note": note,
            })
    return out


# ---------------------------------------------------------------------------
# 2e / 6. WebSocket endpoint detection (mirrors crawler.py's
# detect_websocket_indicators, duplicated per modular independence)
# ---------------------------------------------------------------------------

_WS_LITERAL_RE = re.compile(r"""wss?://[^\s'"<>\\]+""", re.IGNORECASE)
_WS_CTOR_RE = re.compile(r"new\s+WebSocket\s*\(", re.IGNORECASE)


def detect_websocket_references(body: str, js_url: str) -> List[Dict[str, Any]]:
    """Detect ws(s):// literals and bare `new WebSocket(...)` constructor calls (responsibility #6)."""
    if not body:
        return []
    out: List[Dict[str, Any]] = []
    literal_matches = sorted(set(m.rstrip(").,;'\"") for m in _WS_LITERAL_RE.findall(body)))
    for endpoint in literal_matches:
        out.append({
            "endpoint": endpoint, "confidence": CONFIDENCE_HIGH,
            "evidence": [f"Literal WebSocket URL found in JS from {js_url}: {endpoint}"],
        })
    if not literal_matches and _WS_CTOR_RE.search(body):
        out.append({
            "endpoint": None, "confidence": CONFIDENCE_LOW,
            "evidence": [f"`new WebSocket(...)` constructor call found in JS from {js_url} without a literal "
                         f"endpoint URL (likely constructed dynamically at runtime)"],
        })
    return out


# ---------------------------------------------------------------------------
# 3. Source maps
# ---------------------------------------------------------------------------

_SOURCEMAP_LINE_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_SOURCEMAP_BLOCK_RE = re.compile(r"/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/")


def detect_source_map_reference(body: str, js_url: str, try_implicit_sibling: bool = True) -> Dict[str, Any]:
    """
    Detect a `.js.map` reference (responsibility #3, detection). An
    explicit `//# sourceMappingURL=` (or block-comment equivalent) comment
    is trusted directly; otherwise, if `try_implicit_sibling`, the
    conventional `<url>.map` sibling is offered as an unconfirmed guess
    (see module docstring, decision #3 — it is only ever persisted as a
    finding once confirmed by an actual fetch).
    """
    if body:
        m = _SOURCEMAP_LINE_RE.search(body) or _SOURCEMAP_BLOCK_RE.search(body)
        if m:
            raw = m.group(1).strip()
            try:
                resolved = urllib.parse.urljoin(js_url, raw)
            except Exception:
                resolved = None
            if resolved:
                return {
                    "status": "explicit", "map_url": resolved, "raw": raw,
                    "evidence": [f"sourceMappingURL comment found in {js_url}: {raw!r}"],
                }
    if try_implicit_sibling:
        implicit = js_url + ".map"
        return {
            "status": "implicit_guess", "map_url": implicit, "raw": None,
            "evidence": [f"No explicit sourceMappingURL comment in {js_url}; probing the conventional "
                         f"sibling {implicit!r} (unconfirmed until fetched)"],
        }
    return {"status": "not_found", "map_url": None, "raw": None, "evidence": []}


def fetch_source_map(map_url: str, target: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Retrieve a source map (responsibility #3, retrieval) — scope-enforced exactly like any other fetch."""
    try:
        validated = validate_url_target(map_url, target=target)
    except ScopeError as exc:
        return {"status": "out_of_scope", "error": str(exc), "status_code": None}
    return fetch_url(validated, timeout=timeout, max_body_bytes=DEFAULT_MAX_SOURCE_MAP_BYTES)


def parse_source_map(raw_text: Optional[str]) -> Dict[str, Any]:
    """
    Safely parse a source map (responsibility #3, safe parsing). Never
    raises: malformed/empty/non-object input degrades to a `status`
    describing the problem, so a scan is never terminated by a bad map.
    """
    if not raw_text or not raw_text.strip():
        return {"status": "empty", "error": "empty source map body"}
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return {"status": "malformed", "error": f"invalid JSON: {exc}"}
    if not isinstance(data, dict):
        return {"status": "malformed", "error": "source map root is not a JSON object"}

    sources = data.get("sources") if isinstance(data.get("sources"), list) else []
    sources_content = data.get("sourcesContent") if isinstance(data.get("sourcesContent"), list) else []
    names = data.get("names") if isinstance(data.get("names"), list) else []
    return {
        "status": "parsed",
        "version": data.get("version"),
        "file": data.get("file"),
        "sources": [s for s in sources if isinstance(s, str)],
        "sources_content": sources_content,
        "sources_content_available": any(isinstance(c, str) and c.strip() for c in sources_content),
        "names_count": len(names),
        "has_mappings": bool(data.get("mappings")),
    }


def reconstruct_original_sources(parsed_map: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Reconstruct original source files from an already-parsed source map's
    embedded `sourcesContent` (responsibility #3, reconstruction — see
    module docstring, decision #2 for the documented VLQ-`mappings`
    limitation). Returns [] for a map with no embedded content, or one
    that failed to parse.
    """
    if parsed_map.get("status") != "parsed":
        return []
    sources = parsed_map.get("sources") or []
    contents = parsed_map.get("sources_content") or []
    out: List[Dict[str, str]] = []
    for idx, name in enumerate(sources):
        content = contents[idx] if idx < len(contents) else None
        if isinstance(content, str) and content.strip():
            out.append({"source": name, "content": content})
    return out


# ---------------------------------------------------------------------------
# 4a. Client-side sources / sinks / possible data flows (proximity
# heuristic ONLY — see module docstring, SECURITY BOUNDARIES)
# ---------------------------------------------------------------------------

_SOURCE_PATTERNS = {
    "location.hash": re.compile(r"\blocation\.hash\b"),
    "location.search": re.compile(r"\blocation\.search\b"),
    "document.URL": re.compile(r"\bdocument\.URL\b"),
    "document.referrer": re.compile(r"\bdocument\.referrer\b"),
    "window.name": re.compile(r"\bwindow\.name\b"),
    "URLSearchParams": re.compile(r"\bnew\s+URLSearchParams\s*\("),
}
_SINK_PATTERNS = {
    "innerHTML": re.compile(r"\.innerHTML\s*="),
    "outerHTML": re.compile(r"\.outerHTML\s*="),
    "document.write": re.compile(r"\bdocument\.write(?:ln)?\s*\("),
    "eval": re.compile(r"\beval\s*\("),
    "Function_constructor": re.compile(r"\bnew\s+Function\s*\("),
    "insertAdjacentHTML": re.compile(r"\.insertAdjacentHTML\s*\("),
    "setTimeout_string_arg": re.compile(r"\bsetTimeout\s*\(\s*[\"']"),
    "dangerouslySetInnerHTML": re.compile(r"\bdangerouslySetInnerHTML\b"),
}


def _line_number_at(body: str, index: int) -> int:
    return body.count("\n", 0, index)


def _line_text(body: str, line_no: int) -> str:
    lines = body.splitlines()
    return lines[line_no] if 0 <= line_no < len(lines) else ""


def extract_client_side_signals(body: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract client-side sources/sinks and a PROXIMITY-HEURISTIC "possible
    data flow" observation (responsibility #4). Never claims an
    exploitable vulnerability from a source/sink/flow's presence alone —
    every possible-data-flow entry is explicitly labeled unverified.
    """
    if not body:
        return {"sources": [], "sinks": [], "possible_data_flows": []}

    sources: List[Dict[str, Any]] = []
    for name, pattern in _SOURCE_PATTERNS.items():
        for m in pattern.finditer(body):
            line_no = _line_number_at(body, m.start())
            sources.append({
                "kind": name, "line": line_no,
                "evidence": f"Source pattern {name!r} found near: {_truncate(_line_text(body, line_no), 160)!r}",
            })

    sinks: List[Dict[str, Any]] = []
    for name, pattern in _SINK_PATTERNS.items():
        for m in pattern.finditer(body):
            line_no = _line_number_at(body, m.start())
            sinks.append({
                "kind": name, "line": line_no,
                "evidence": f"Sink pattern {name!r} found near: {_truncate(_line_text(body, line_no), 160)!r}",
            })

    possible_flows: List[Dict[str, Any]] = []
    for s in sources:
        for k in sinks:
            distance = abs(s["line"] - k["line"])
            if distance <= 2:
                possible_flows.append({
                    "source_kind": s["kind"], "sink_kind": k["kind"],
                    "source_line": s["line"], "sink_line": k["line"],
                    "evidence": [
                        f"Source {s['kind']!r} (line {s['line']}) and sink {k['kind']!r} (line {k['line']}) "
                        f"appear within {distance} line(s) of each other in the (often minified) script — "
                        f"PROXIMITY HEURISTIC ONLY, not a verified taint/data-flow analysis; requires manual review "
                        f"before treating this as an actual data-flow relationship."
                    ],
                })

    return {"sources": sources, "sinks": sinks, "possible_data_flows": possible_flows}


# ---------------------------------------------------------------------------
# 4b. postMessage
# ---------------------------------------------------------------------------

_POSTMESSAGE_LISTENER_RE = re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.IGNORECASE)
_POSTMESSAGE_SEND_RE = re.compile(r"\.postMessage\s*\(", re.IGNORECASE)
_ORIGIN_CHECK_RE = re.compile(r"\.origin\s*(?:===|==|!==|!=)", re.IGNORECASE)


def extract_postmessage_signals(body: str, lookahead_window: int = 400) -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect `window.addEventListener('message', ...)` receivers and
    `.postMessage(...)` senders (responsibility #4). For each listener, a
    nearby (best-effort, textual) origin-check is noted as an OBSERVATION
    only — its absence is not itself claimed as a vulnerability.
    """
    if not body:
        return {"listeners": [], "sends": []}

    listeners: List[Dict[str, Any]] = []
    for m in _POSTMESSAGE_LISTENER_RE.finditer(body):
        window_text = body[m.end(): m.end() + lookahead_window]
        has_origin_check = bool(_ORIGIN_CHECK_RE.search(window_text))
        listeners.append({
            "origin_check_observed": has_origin_check,
            "evidence": [
                "addEventListener('message', ...) found"
                + (" with a nearby origin check" if has_origin_check else
                   " with no nearby origin check observed (textual heuristic only — not a confirmed absence)")
            ],
        })

    sends: List[Dict[str, Any]] = []
    for _ in _POSTMESSAGE_SEND_RE.finditer(body):
        sends.append({"evidence": [".postMessage(...) call found"]})

    return {"listeners": listeners, "sends": sends}


# ---------------------------------------------------------------------------
# 4c. localStorage
# ---------------------------------------------------------------------------

_LOCALSTORAGE_RE = re.compile(r'\blocalStorage\.(getItem|setItem|removeItem)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)


def extract_localstorage_signals(body: str) -> List[Dict[str, Any]]:
    """Detect literal-keyed localStorage access (responsibility #4)."""
    if not body:
        return []
    out: List[Dict[str, Any]] = []
    for m in _LOCALSTORAGE_RE.finditer(body):
        method, key = m.group(1), m.group(2)
        out.append({"method": method, "key": key, "evidence": [f"localStorage.{method}({key!r}) call found"]})
    return out


# ---------------------------------------------------------------------------
# Body-parameter hints (supports responsibility #5's `parameters` field —
# see module docstring, decision #4 for its documented, honest limitation)
# ---------------------------------------------------------------------------

_FETCH_BODY_RE = re.compile(r"JSON\.stringify\(\s*\{([^}]{0,500})\}", re.IGNORECASE)
_OBJECT_KEY_RE = re.compile(r'["\']?([A-Za-z_][A-Za-z0-9_]*)["\']?\s*:')


def extract_body_parameter_hints(body: str) -> List[Dict[str, Any]]:
    """
    Best-effort, file-wide extraction of likely request-body parameter
    names from `JSON.stringify({...})` object literals. See module
    docstring, decision #4: this cannot be reliably tied to one specific
    endpoint without a real parser, so results are file-wide, not
    per-endpoint.
    """
    if not body:
        return []
    out: List[Dict[str, Any]] = []
    seen = set()
    for m in _FETCH_BODY_RE.finditer(body):
        for key in _OBJECT_KEY_RE.findall(m.group(1)):
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": key, "location": "body", "method": "POST", "data_type": "unknown"})
    return out


# ---------------------------------------------------------------------------
# Single-file analysis (bundles responsibilities #2/#4/#6 — independently
# testable per the assignment's TESTING list)
# ---------------------------------------------------------------------------

def analyze_javascript_content(body: Optional[str], js_url: str, target: Optional[str] = None) -> Dict[str, Any]:
    """Run every content-analysis responsibility against one already-fetched script body."""
    body = body or ""
    return {
        "js_url": js_url,
        "api_references": extract_api_references(body, js_url, target),
        "external_services": extract_external_service_references(body, js_url, target),
        "config_values": extract_config_values(body),
        "secret_indicators": extract_secret_indicators(body),
        "websocket_references": detect_websocket_references(body, js_url),
        "client_side_signals": extract_client_side_signals(body),
        "postmessage_signals": extract_postmessage_signals(body),
        "localstorage_signals": extract_localstorage_signals(body),
        "body_parameter_hints": extract_body_parameter_hints(body),
    }


# ---------------------------------------------------------------------------
# Persistence + API correlation output (responsibility #5 — see module
# docstring, NO-CROSS-MODULE-CALLS PRECEDENT item (b))
# ---------------------------------------------------------------------------

def build_endpoint_discovery_js_data(
    api_references: List[Dict[str, Any]], body_parameter_hints: List[Dict[str, Any]], parent_js_url: str,
) -> List[Dict[str, Any]]:
    """
    Normalize extracted API references into the EXACT shape
    endpoint_discovery.py's `correlate_javascript_parameters` already
    documents as its expected `js_data` input:
    `{"url":, "parameters": [...], "evidence": [...], "source_file":}`.
    """
    out: List[Dict[str, Any]] = []
    for ref in api_references:
        params: List[Dict[str, Any]] = []
        query = urllib.parse.urlsplit(ref["url"]).query
        for name, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
            params.append({"name": name, "location": "query", "method": "GET", "data_type": _infer_data_type(value)})

        evidence = list(ref["evidence"])
        if body_parameter_hints:
            evidence.append(
                "Additional body-parameter hints observed file-wide in this script "
                "(not confirmed specific to this endpoint) — see corresponding js_analyzer_endpoint_reference finding."
            )
            params.extend(
                {"name": h["name"], "location": h["location"], "method": h["method"], "data_type": h["data_type"]}
                for h in body_parameter_hints
            )

        out.append({"url": ref["url"], "parameters": params, "evidence": evidence, "source_file": parent_js_url})
    return out


def persist_analysis_findings(
    analysis: Dict[str, Any],
    target: str,
    store: Optional[PendingAssetsStore],
    parent_js_url: str,
    source_page: Optional[str] = None,
    derived_from_source_map: bool = False,
    original_source_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Persist every finding produced by `analyze_javascript_content` for one
    analyzed unit (a fetched JS file, or one reconstructed original
    source), and assemble the `js_data`/`websocket_endpoints` accumulators
    `run_js_analyzer` aggregates across the whole run.
    """
    errors: List[str] = []
    counts: Dict[str, int] = {}
    websocket_endpoints: List[Dict[str, Any]] = []

    def _add(finding_type: str, value: Any, evidence: List[str], confidence: str,
              extra_metadata: Optional[Dict[str, Any]] = None) -> None:
        err = _safe_store_add(store, make_js_finding(
            finding_type, target, value, evidence, confidence, parent_js_url=parent_js_url,
            source_page=source_page, derived_from_source_map=derived_from_source_map,
            original_source_file=original_source_file, extra_metadata=extra_metadata,
        ))
        if err:
            errors.append(err)

    api_refs = analysis["api_references"]
    counts["api_references"] = len(api_refs)
    for ref in api_refs:
        floor = CONFIDENCE_MEDIUM if any("call target" in e for e in ref["evidence"]) else CONFIDENCE_LOW
        confidence = _confidence_from_count(len(ref["evidence"]), floor=floor)
        _add("js_analyzer_endpoint_reference", {"url": ref["url"], "kind": ref["kind"], "raw": ref["raw"]},
             ref["evidence"], confidence)

    ext = analysis["external_services"]
    counts["external_services"] = len(ext)
    for e in ext:
        confidence = _confidence_from_count(len(e["evidence"]), floor=CONFIDENCE_MEDIUM)
        _add("js_analyzer_external_service_reference",
             {"vendor": e["vendor"], "category": e["category"], "host": e["host"], "example_url": e["example_url"]},
             e["evidence"], confidence)

    cfg = analysis["config_values"]
    counts["config_values"] = len(cfg)
    for c in cfg:
        _add("js_analyzer_config_value", {"key": c["key"], "value": c["value"]}, c["evidence"], c["confidence"])

    secrets = analysis["secret_indicators"]
    counts["secret_indicators"] = len(secrets)
    for s in secrets:
        evidence = [f"JS secret-pattern match ({s['pattern_name']}, category={s['category']}): {s['context']!r}"]
        if s.get("note"):
            evidence.append(s["note"])
        _add("js_analyzer_secret_indicator", {
            "category": s["category"], "pattern_name": s["pattern_name"], "redacted_value": s["redacted_value"],
            "fingerprint_sha256": s["fingerprint_sha256"], "context": s["context"],
        }, evidence, s["confidence"])

    ws = analysis["websocket_references"]
    counts["websocket_references"] = len(ws)
    for w in ws:
        _add("js_analyzer_websocket_endpoint", {"endpoint": w["endpoint"]}, w["evidence"], w["confidence"])
        if w["endpoint"]:
            websocket_endpoints.append({"endpoint": w["endpoint"], "source_file": parent_js_url, "evidence": w["evidence"]})

    sig = analysis["client_side_signals"]
    counts["client_side_signals"] = len(sig["sources"]) + len(sig["sinks"]) + len(sig["possible_data_flows"])
    for s in sig["sources"]:
        _add("js_analyzer_client_side_signal", {"signal_category": "source", "kind": s["kind"], "line": s["line"]},
             [s["evidence"]], CONFIDENCE_MEDIUM)
    for k in sig["sinks"]:
        _add("js_analyzer_client_side_signal", {"signal_category": "sink", "kind": k["kind"], "line": k["line"]},
             [k["evidence"]], CONFIDENCE_MEDIUM)
    for f in sig["possible_data_flows"]:
        _add("js_analyzer_client_side_signal", {
            "signal_category": "possible_data_flow", "source_kind": f["source_kind"], "sink_kind": f["sink_kind"],
            "source_line": f["source_line"], "sink_line": f["sink_line"],
        }, f["evidence"], CONFIDENCE_LOW)

    pm = analysis["postmessage_signals"]
    counts["postmessage_signals"] = len(pm["listeners"]) + len(pm["sends"])
    for listener in pm["listeners"]:
        _add("js_analyzer_client_side_signal",
             {"signal_category": "postmessage_listener", "origin_check_observed": listener["origin_check_observed"]},
             listener["evidence"], CONFIDENCE_MEDIUM)
    for send in pm["sends"]:
        _add("js_analyzer_client_side_signal", {"signal_category": "postmessage_send"}, send["evidence"], CONFIDENCE_MEDIUM)

    ls = analysis["localstorage_signals"]
    counts["localstorage_signals"] = len(ls)
    for entry in ls:
        _add("js_analyzer_client_side_signal",
             {"signal_category": "localstorage_access", "method": entry["method"], "key": entry["key"]},
             entry["evidence"], CONFIDENCE_MEDIUM)

    js_data = build_endpoint_discovery_js_data(api_refs, analysis["body_parameter_hints"], parent_js_url)

    return {
        "counts": counts, "total": sum(counts.values()), "errors": errors,
        "js_data": js_data, "websocket_endpoints": websocket_endpoints,
    }


# ---------------------------------------------------------------------------
# Source-map orchestration for one already-fetched file (responsibility #3,
# end to end — never terminates the caller's per-file loop on failure)
# ---------------------------------------------------------------------------

def process_source_map(
    body: str,
    js_url: str,
    target: Optional[str],
    target_effective: str,
    source_page: Optional[str],
    store: Optional[PendingAssetsStore],
    retrieve_source_maps: bool,
    analyze_reconstructed_sources: bool,
    try_implicit_sibling: bool,
    timeout: float,
) -> Dict[str, Any]:
    """
    Detect -> (optionally) retrieve -> parse -> reconstruct -> (optionally)
    recursively analyze reconstructed sources, for one already-fetched JS
    file. Malformed/missing source maps degrade to a recorded outcome,
    never an exception.
    """
    result: Dict[str, Any] = {"info": None, "js_data": [], "websocket_endpoints": [], "errors": []}
    if not retrieve_source_maps and not try_implicit_sibling:
        return result

    ref_info = detect_source_map_reference(body, js_url, try_implicit_sibling=try_implicit_sibling)
    if not ref_info.get("map_url"):
        return result

    info: Dict[str, Any] = {
        "reference_type": ref_info["status"], "map_url": ref_info["map_url"],
        "fetch_status": "not_attempted", "parse_status": None, "reconstructed_sources": [],
    }
    result["info"] = info

    if not retrieve_source_maps:
        if ref_info["status"] == "explicit":
            err = _safe_store_add(store, make_js_finding(
                "js_analyzer_source_map_reference", target_effective,
                {"js_url": js_url, "map_url": ref_info["map_url"], "reference_type": "explicit", "fetch_status": "not_attempted"},
                ref_info["evidence"], CONFIDENCE_HIGH, parent_js_url=js_url, source_page=source_page,
            ))
            if err:
                result["errors"].append(err)
        return result

    map_resp = fetch_source_map(ref_info["map_url"], target=target, timeout=timeout)
    info["fetch_status"] = map_resp.get("status")
    info["status_code"] = map_resp.get("status_code")

    fetched_ok = (
        map_resp.get("status") == "found"
        and map_resp.get("status_code") is not None
        and 200 <= map_resp["status_code"] < 300
    )
    if not fetched_ok:
        if ref_info["status"] == "explicit":
            err = _safe_store_add(store, make_js_finding(
                "js_analyzer_source_map_reference", target_effective,
                {"js_url": js_url, "map_url": ref_info["map_url"], "reference_type": "explicit",
                 "fetch_status": map_resp.get("status"), "status_code": map_resp.get("status_code")},
                ref_info["evidence"] + [
                    f"Source map retrieval did not succeed (status={map_resp.get('status')}, "
                    f"http_status={map_resp.get('status_code')}, error={map_resp.get('error')})"
                ],
                CONFIDENCE_HIGH, parent_js_url=js_url, source_page=source_page,
            ))
            if err:
                result["errors"].append(err)
        # An unconfirmed implicit guess that doesn't pan out is not recorded
        # (module docstring, decision #3) — avoids noise, not a silent drop
        # of real evidence (nothing was actually discovered).
        return result

    parsed = parse_source_map(map_resp.get("body"))
    info["parse_status"] = parsed.get("status")
    sm_confidence = (
        CONFIDENCE_HIGH if ref_info["status"] == "explicit"
        else (CONFIDENCE_MEDIUM if parsed.get("status") == "parsed" else CONFIDENCE_LOW)
    )
    err = _safe_store_add(store, make_js_finding(
        "js_analyzer_source_map_reference", target_effective,
        {"js_url": js_url, "map_url": ref_info["map_url"], "reference_type": ref_info["status"],
         "fetch_status": "found", "parse_status": parsed.get("status")},
        ref_info["evidence"] + [
            f"Source map fetched; parse status: {parsed.get('status')}"
            + (f" ({parsed['error']})" if parsed.get("error") else "")
        ],
        sm_confidence, parent_js_url=js_url, source_page=source_page,
    ))
    if err:
        result["errors"].append(err)

    if parsed.get("status") != "parsed":
        return result

    for rec in reconstruct_original_sources(parsed):
        preview = _truncate(rec["content"], 500)
        err = _safe_store_add(store, make_js_finding(
            "js_analyzer_reconstructed_source", target_effective,
            {"js_url": js_url, "map_url": ref_info["map_url"], "original_source": rec["source"],
             "content_preview": preview, "content_length": len(rec["content"])},
            [f"Reconstructed original source {rec['source']!r} from source map {ref_info['map_url']} "
             f"(via embedded sourcesContent)"],
            CONFIDENCE_HIGH, parent_js_url=js_url, source_page=source_page,
            extra_metadata={"original_source_file": rec["source"]},
        ))
        if err:
            result["errors"].append(err)
        info["reconstructed_sources"].append(rec["source"])

        if analyze_reconstructed_sources:
            nested_analysis = analyze_javascript_content(rec["content"], js_url, target=target)
            nested = persist_analysis_findings(
                nested_analysis, target_effective, store, parent_js_url=js_url, source_page=source_page,
                derived_from_source_map=True, original_source_file=rec["source"],
            )
            result["js_data"].extend(nested["js_data"])
            result["websocket_endpoints"].extend(nested["websocket_endpoints"])
            result["errors"].extend(nested["errors"])

    return result


# ---------------------------------------------------------------------------
# Input normalization — accepts a plain URL string, a
# {"url":, "source_page":} dict, OR crawler.py's raw persisted
# `javascript_reference` finding record verbatim (see module docstring,
# NO-CROSS-MODULE-CALLS PRECEDENT item (a))
# ---------------------------------------------------------------------------

def _normalize_js_reference(item: Any) -> Dict[str, Optional[str]]:
    if isinstance(item, str):
        return {"url": item, "source_page": None}
    if isinstance(item, dict):
        value = item.get("value")
        if isinstance(value, dict) and value.get("url"):
            return {"url": value.get("url"), "source_page": value.get("source_page")}
        return {"url": item.get("url"), "source_page": item.get("source_page")}
    return {"url": None, "source_page": None}


# ---------------------------------------------------------------------------
# Module orchestration (multiple JS files)
# ---------------------------------------------------------------------------

def run_js_analyzer(
    js_files: List[Any],
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    max_redirect_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    retrieve_source_maps: bool = True,
    analyze_reconstructed_sources: bool = True,
    try_implicit_source_map_sibling: bool = True,
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run every Module 13 responsibility across `js_files` and persist every
    completed discovery immediately to <output_dir>/pending_assets.json.
    `js_files` accepts plain URL strings, `{"url":, "source_page":}`
    dicts, or crawler.py's raw `javascript_reference` finding records. A
    failure analyzing one file (scope, fetch, parse) never aborts the rest
    of the run.
    """
    store = PendingAssetsStore(output_dir=output_dir)
    summary: Dict[str, Any] = {
        "module": MODULE_NAME, "target": target, "started_at": _now(),
        "files_requested": 0, "files_analyzed": 0, "files_skipped_out_of_scope": 0, "files_failed": 0,
        "results": [], "js_data_for_endpoint_discovery": [], "websocket_endpoints": [], "errors": [],
    }

    refs = [_normalize_js_reference(item) for item in (js_files or [])]
    refs = [r for r in refs if r.get("url")]
    if max_files is not None:
        refs = refs[:max_files]
    summary["files_requested"] = len(refs)

    for ref in refs:
        url = ref["url"]
        source_page = ref.get("source_page")
        file_result: Dict[str, Any] = {"url": url, "source_page": source_page, "status": None}

        try:
            validated_url = validate_url_target(url, target=target)
        except ScopeError as exc:
            summary["files_skipped_out_of_scope"] += 1
            file_result["status"] = "skipped_out_of_scope"
            file_result["error"] = str(exc)
            _safe_store_add(store, make_js_finding(
                "js_analyzer_skipped_out_of_scope", target or url, {"url": url, "reason": str(exc)},
                [f"JS reference {url!r} is out of scope for target {target!r}"], CONFIDENCE_LOW,
                parent_js_url=url, source_page=source_page,
            ))
            summary["results"].append(file_result)
            continue

        target_effective = target or (urllib.parse.urlsplit(validated_url).hostname or validated_url)

        fetch_result = fetch_javascript_file(
            validated_url, target=target, timeout=timeout, max_body_bytes=max_body_bytes,
            max_redirect_hops=max_redirect_hops,
        )
        if fetch_result["status"] != "found":
            summary["files_failed"] += 1
            file_result["status"] = "fetch_failed"
            file_result["error"] = fetch_result.get("error")
            _safe_store_add(store, make_js_finding(
                "js_analyzer_fetch_failed", target_effective,
                {"url": validated_url, "error": fetch_result.get("error"), "hops": fetch_result.get("hops", [])},
                [f"Failed to fetch JS file {validated_url}: {fetch_result.get('error')}"], CONFIDENCE_LOW,
                parent_js_url=validated_url, source_page=source_page,
            ))
            summary["results"].append(file_result)
            continue

        final_url = fetch_result.get("final_url", validated_url)
        body = fetch_result.get("body") or ""
        content_type = _ci_get(fetch_result.get("headers", {}), "Content-Type")

        if not _looks_textual(content_type, body):
            file_result["status"] = "non_textual_content_skipped"
            file_result["final_url"] = final_url
            summary["results"].append(file_result)
            continue

        analysis = analyze_javascript_content(body, final_url, target=target)
        persisted = persist_analysis_findings(analysis, target_effective, store, parent_js_url=final_url, source_page=source_page)

        _safe_store_add(store, make_js_finding(
            "javascript_file_analyzed", target_effective,
            {
                "url": final_url, "content_type": content_type, "byte_length": len(body),
                "body_truncated": fetch_result.get("body_truncated", False), "counts": persisted["counts"],
            },
            [f"Fetched and analyzed JS file {final_url} ({len(body)} bytes)"],
            CONFIDENCE_HIGH, parent_js_url=final_url, source_page=source_page,
        ))

        if persisted["total"] == 0:
            _safe_store_add(store, make_js_finding(
                "js_analyzer_checked_no_findings", target_effective, {"url": final_url},
                [f"No API references, secrets, config values, WebSocket endpoints, or client-side "
                 f"signals detected in {final_url}"],
                CONFIDENCE_LOW, parent_js_url=final_url, source_page=source_page,
            ))

        summary["js_data_for_endpoint_discovery"].extend(persisted["js_data"])
        summary["websocket_endpoints"].extend(persisted["websocket_endpoints"])
        summary["errors"].extend(persisted["errors"])

        sm_result = process_source_map(
            body, final_url, target, target_effective, source_page, store,
            retrieve_source_maps, analyze_reconstructed_sources, try_implicit_source_map_sibling, timeout,
        )
        summary["js_data_for_endpoint_discovery"].extend(sm_result["js_data"])
        summary["websocket_endpoints"].extend(sm_result["websocket_endpoints"])
        summary["errors"].extend(sm_result["errors"])

        file_result["status"] = "analyzed"
        file_result["final_url"] = final_url
        file_result["source_map"] = sm_result["info"]
        summary["files_analyzed"] += 1
        summary["results"].append(file_result)

    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="js_analyzer.py",
        description="ReconHound Module 13 — deep client-side JavaScript intelligence (standalone test entry point).",
    )
    parser.add_argument("--url", action="append", required=True, dest="urls",
                         help="JS file URL to analyze (repeatable)")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--no-source-maps", action="store_true", help="Skip source-map retrieval/parsing")
    parser.add_argument("--no-reconstructed-analysis", action="store_true",
                         help="Skip re-analyzing reconstructed original sources")
    parser.add_argument("--no-implicit-map-guess", action="store_true",
                         help="Only follow explicit sourceMappingURL comments, never guess the .map sibling")
    args = parser.parse_args()

    result = run_js_analyzer(
        args.urls, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
        retrieve_source_maps=not args.no_source_maps,
        analyze_reconstructed_sources=not args.no_reconstructed_analysis,
        try_implicit_source_map_sibling=not args.no_implicit_map_guess,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
