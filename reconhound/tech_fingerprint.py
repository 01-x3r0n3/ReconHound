"""
reconhound/tech_fingerprint.py — ReconHound Module 8 (tech_fingerprint.py),
build-order position 17 (per context.md §13; this repository, like
code_leak.py/passive_intel.py/wayback_intel.py/vuln_intel.py before it, is
operating under an explicit deviation from the numeric build order —
surface_mapper.py, core/orchestrator.py, and reconhound.py are not yet
implemented; see BUILD-ORDER NOTE below).

Phase: Active. See context.md §10 (module 8, "Technology ID") for the
authoritative responsibilities, and §8 for the evidence/confidence data
model this module implements. This file only documents implementation-
specific detail, not the architecture itself.

context.md's exact line for this module:

  "Active — Technology ID. CMS (WordPress/Drupal/Joomla/Magento),
  frameworks (Django/Flask/FastAPI/Laravel/Express/Next.js/React/Angular/
  Vue), servers (Nginx/Apache/IIS/Caddy), WAFs (Cloudflare/Akamai/AWS WAF/
  F5/Imperva). Signals: headers, cookies, HTML, JS, URLs, error pages,
  favicon hashes, known paths. Should trigger downstream recon
  automatically. Evidence+confidence required per detection."

That expands into these discrete responsibilities, each implemented below:

  1. Server identification (header-based)      -> detect_servers
  2. WAF signature detection                    -> detect_wafs
  3. CMS + framework signature detection
     (headers/cookies/HTML/JS/URL markers)      -> detect_technologies_from_content
  4. Error-page signal correlation               -> fetch_error_page_sample
                                                     (fed back into #3)
  5. Favicon hash computation + matching         -> compute_favicon_hash,
                                                     match_favicon_hash
  6. Known technology-specific path probing
     (confirmatory, bounded, signal-driven)      -> probe_known_paths
  7. Multi-signal correlation / confidence        -> _merge_scan_maps,
     scoring                                        _finalize_detections
  8. Normalization for surface_mapper.py          -> build_technology_summary
  9. Downstream-recon trigger integration         -> build_recommended_actions

Plus shared plumbing: make_finding/make_tech_finding, PendingAssetsStore,
_safe_store_add, fetch_url (duplicated per modular independence, same as
every other implemented module), and a single-target orchestrator
run_tech_fingerprint (mirroring the run_http_analysis/run_endpoint_discovery
precedent).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
17, after surface_mapper.py (position 8) and after endpoint_discovery.py
(position 5). Per code_leak.py's/passive_intel.py's/wayback_intel.py's/
vuln_intel.py's module docstrings, this repository is already operating
under an explicit, user-approved deviation from that order —
surface_mapper.py has not been implemented yet. This module continues
under the same deviation: it is a fully standalone producer that does not
implement, replace, or depend on surface_mapper.py's correlation engine.

NO-CROSS-MODULE-CALLS PRECEDENT (important for responsibility #9,
"downstream recon trigger"): every already-implemented module in this
repository (http_analyzer.py, endpoint_discovery.py, code_leak.py, etc.)
explicitly documents that it does NOT import or call into any sibling
module, even ones already implemented — integration is deferred to
core/orchestrator.py (not yet built), which is meant to route data
between modules via surface_mapper.py. This module follows that same
precedent rather than inventing a new "tech_fingerprint calls
endpoint_discovery directly" pattern, which would be a competing
orchestration mechanism (assignment's explicit "do not create a competing
orchestration system" instruction). Instead, responsibility #9 is
satisfied by:

  a. Producing `technology_summary`, a normalized dict shaped to be passed
     straight into endpoint_discovery.py's ALREADY-BUILT, ALREADY-CALLER-
     SUPPLIED `technology` parameter (see endpoint_discovery.py's
     `select_wordlists_for_technology` / `enumerate_framework_paths` /
     `run_endpoint_discovery(technology=...)`) with zero adaptation
     required — `select_wordlists_for_technology` does a case-insensitive
     substring search over every string value in the structure, and this
     module's category buckets ("cms"/"frameworks"/"servers"/"wafs") plus
     plain technology-name strings satisfy that contract directly. This is
     "using the existing project interface", not building a new one.
  b. Producing `recommended_next_actions`: an explicit, evidence-justified
     decision-queue-shaped list (context.md §9's "decision queue with
     justification" concept) naming which existing module/function should
     be invoked next and why. These are recommendations for the future
     orchestrator to execute — this module never invokes them itself.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). This module
does not implement or call into surface_mapper, active_recon, vhost_scanner,
endpoint_discovery, api_recon, crawler, js_analyzer, supply_chain,
exposure_scan, http_analyzer, ssl_analyzer, vuln_intel,
risk_engine, report_generator, orchestrator, osint_engine, or any other
module.

DISCOVERY != CONFIRMED VULNERABILITY: every record here is an observation
("this signal was seen, matching this technology's known signature") with
an explicit confidence level. None of this module's output should be read
as "vulnerable" or "exploitable" — CVE mapping is vuln_intel.py's job, risk
scoring is risk_engine.py's job. A detected version is only ever reported
when the evidence itself carries a version string (a declared meta
generator tag, a `Server:`/`X-Powered-By:` header version token, a version
attribute in markup) — this module never guesses or infers a version from
absence of a patch-specific marker.

Implementation decisions (ambiguities resolved so implementation can
proceed without inventing requirements):

  1. Signal correlation / confidence scoring: each matched signal is
     weighted "strong" (2 points — a direct, hard-to-accidentally-trigger
     declaration: a meta generator tag, a vendor-specific header value, a
     confirmed known-path match with a content marker, a matched favicon
     hash) or "weak" (1 point — a generic cookie name, a generic HTML
     marker, an unconfirmed known-path 2xx with no content marker).
     Confidence = HIGH at score >= 3, MEDIUM at score == 2, LOW at score
     == 1 (context.md §8: "multiple independent converging signals raise
     confidence; a single weak signal should generally stay LOW" — two
     converging weak signals reach MEDIUM, a single strong signal alone
     also lands at MEDIUM since it is still one source, and any
     combination reaching 3+ points reaches HIGH).
  2. Known-path probing (#6) is bounded and signal-driven, not a fresh
     wordlist scan: only technologies that already have at least one
     header/cookie/HTML/error-page signal are corroborated via known
     paths (a handful of well-documented, technology-specific paths, e.g.
     `/wp-login.php`, `/CHANGELOG.txt`), capped by `max_known_path_probes`.
     This is deliberately NOT endpoint_discovery.py's wordlist-driven
     directory/file enumeration — it exists only to raise or confirm
     confidence in an already-suspected technology, using a small,
     hardcoded, well-known path list per technology, not a general
     wordlist.
  3. Favicon hashing (#5): computes both MD5 and SHA-256 of the fetched
     favicon's raw bytes. This project does not bundle a verified
     mmm3/Shodan-style favicon-hash signature database (fabricating one
     with unverified hash values would plant false "evidence" — CLAUDE.md
     rule "do not invent requirements/data"). Instead, `favicon_signatures`
     is an explicit, optional, caller-supplied
     `{hash_hex: {"technology":, "category":, "version": Optional,
     "hash_type": "md5"|"sha256"}}` mapping — the mechanism is fully
     implemented and tested, and a real signature database can be plugged
     in later without changing this module. When no match is found (or no
     signatures are supplied), the computed hash is still persisted as a
     `tech_fingerprint_favicon_observed` finding (negative-result memory —
     "checked, hash computed, no known signature yet" — so a future
     signature-database update can be correlated retroactively without
     re-fetching).
  4. Error-page correlation (#4): one near-certainly-nonexistent path is
     fetched per run (mirrors endpoint_discovery.py's soft-404 probe
     technique, but for a different purpose — content inspection, not
     soft-404 fingerprinting) and scanned with the exact same signature
     matchers as the baseline response. Some frameworks (Laravel's
     "Whoops", Django's DEBUG traceback, Werkzeug's debugger) reveal
     themselves distinctly on an error/404 response even when the
     homepage gives no signal. Evidence from the baseline and error-page
     scans are merged (union), not treated as independent detections.
  5. `requests` and no new dependency: this module reuses the same
     `requests`-based fetch pattern as http_analyzer.py/
     endpoint_discovery.py; no additional third-party dependency is
     introduced (HTML markers are matched via targeted regex over the
     already-fetched body, same approach as http_analyzer.py — full DOM
     parsing is not required for the marker/attribute patterns used here).
  6. Only GET requests are made, to the target's own origin (the base URL
     plus a small number of well-known, same-origin relative paths:
     favicon, error-page probe, known-path corroboration). No new hosts
     are ever contacted. This module discovers technology signals; it
     never exercises or exploits anything it detects.
  7. Confidence is scored over *distinct signals*, not over repetitions of
     one signal (see _scan_signature/_merge_scan_maps). Every matched signal
     carries a source-independent key; evidence for repeated observations is
     always preserved, but the same underlying signal seen again — the same
     HTML marker on the error page as on the homepage, a second Set-Cookie
     matching the same cookie pattern — does not raise the score. context.md
     §8 raises confidence for "multiple independent converging signals";
     re-reading one signal is not independent convergence.
  8. A response's fitness to support a *negative* result is assessed
     separately from its fitness to support a detection (see
     assess_response_representativeness). Positive evidence on a 500 page is
     still evidence; "checked and not found" derived from a redirect stub,
     an error/block page, an empty body or a truncated body is not, so it is
     not recorded and the check stays in the honest "not checked" state.
  9. This module reports what a *response* contained, not what an origin
     runs. Where the response proves an intermediary was involved (see
     detect_intermediaries) that fact is attached to the detections as
     evidence. No fixed numeric confidence penalty is applied for it: the
     evidence model has no basis for a specific discount, and inventing one
     would make confidence unexplainable.

LIMITATIONS (known, deliberate, and not silently hidden):

  * No JavaScript execution. Every signal here comes from the raw HTTP
    response. A single-page application whose framework only becomes visible
    after hydration, whose bundle is minified/tree-shaken past its version
    strings, or whose markers are injected at runtime, is invisible to this
    module. Adding a headless browser would change this module into
    something else; the gap is real and belongs to js_analyzer.py
    territory, not to a silent pretence of coverage. A run
    that finds nothing therefore records "not checked", not "not present"
    (implementation decision #8).
  * Redirects are not followed (allow_redirects=False, deliberate — redirect
    chains are http_analyzer.py's responsibility). Fingerprinting a URL whose
    root 301s therefore inspects the redirect stub. That is why a redirect
    response is classified non-representative and produces no negative-result
    memory.
  * Evidence is response-scoped, never origin-scoped. A CDN/WAF/reverse proxy
    can add, replace or strip every header, cookie and body marker used here,
    and a cached body can describe a deployment that no longer exists. Where
    the response proves an intermediary was involved this is recorded
    (implementation decision #9); where it does not, absence of proof is not
    proof of a direct origin response.
  * Deception is only partially detectable. A target that emits a fake
    `X-Powered-By`, a decoy `/wp-content/` path or a borrowed favicon will be
    reported as evidence of that technology, because that is what was
    observed. Contradictions between such signals are surfaced as conflicts
    (detect_detection_conflicts) rather than resolved.
  * The signature catalogue covers exactly the products context.md §10 names
    for this module. openresty, LiteSpeed, Tomcat, Cloudfront-origin servers
    and everything else are out of catalogue, and their absence from the
    output is a catalogue gap, not evidence of absence.
  * No favicon-hash signature database is bundled (implementation decision
    #3), so favicon matching only works with a caller-supplied map.
  * Response bodies are inspected up to DEFAULT_MAX_BODY_BYTES. A marker
    beyond that point is missed, which is why a truncated body also blocks
    negative-result memory.
  * pending_assets.json is shared with every other module. Writes from *this*
    module are serialised per output path within one process, but the file
    has no cross-process or cross-module lock; coordinating that is
    core/orchestrator.py's and surface_mapper.py's responsibility.
  * Contradictory detections are reported with a `conflicts_with` annotation
    on each finding. surface_mapper.py's `_h_tech_detected` does not yet read
    that annotation, so a contradictory fingerprint still queues one
    enumeration opportunity per contradicting technology. That is a
    surface_mapper.py behaviour, recorded here rather than worked around.
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

MODULE_NAME = "tech_fingerprint.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

# Technology categories (context.md §10, module 8)
CATEGORY_CMS = "cms"
CATEGORY_FRAMEWORK = "framework"
CATEGORY_SERVER = "server"
CATEGORY_WAF = "waf"

DEFAULT_USER_AGENT = "ReconHound-TechFingerprint/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
DEFAULT_MAX_FAVICON_BYTES = 65536
DEFAULT_MAX_KNOWN_PATH_PROBES = 12

# Compressed responses are read in chunks this size (see _read_bounded_body).
_DECODE_CHUNK_BYTES = 8192

# Hard ceiling on how many evidence strings one detection may carry. Evidence
# is target-controlled in volume (one entry per matching Set-Cookie name, per
# matching marker, per probed path), and every entry is persisted to
# pending_assets.json and re-rendered by report_generator.py.
DEFAULT_MAX_EVIDENCE_PER_DETECTION = 40

# A version token no real product emits is not evidence, it is target-supplied
# text (see _plausible_version).
_MAX_VERSION_COMPONENTS = 4
_MAX_VERSION_COMPONENT_DIGITS = 5

# Signal-scoring weights (implementation decision #1)
_SCORE_STRONG = 2
_SCORE_WEAK = 1
_HIGH_THRESHOLD = 3
_MEDIUM_THRESHOLD = 2


class ScopeError(ValueError):
    """Raised when a URL/target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors http_analyzer.py's/endpoint_discovery.py's
# validate_url_target; duplicated per modular independence, context.md §12.2)
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


def make_tech_finding(
    technology: str,
    category: str,
    version: Optional[str],
    evidence: List[str],
    confidence: str,
    target: str,
    url: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Wrap one technology detection into the structured evidence record
    required by the assignment's "for every technology detection preserve"
    list: technology, category, version (nullable — never invented),
    evidence, source/URL, confidence, timestamp (timestamp is added by
    make_finding).
    """
    return make_finding(
        finding_type="tech_fingerprint_detected",
        target=target,
        value={
            "technology": technology,
            "category": category,
            "version": version,
            "url": url,
        },
        evidence=evidence,
        confidence=confidence,
        metadata={**(metadata or {}), "technology": technology, "category": category, "version": version, "url": url},
    )


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as every other module's
# PendingAssetsStore, duplicated here per modular independence)
# ---------------------------------------------------------------------------

# One lock per pending_assets.json path, shared by every PendingAssetsStore
# instance in this process. add() is a read-modify-write of a whole-file JSON
# array, so a per-instance lock does not serialise anything: run_tech_fingerprint
# builds a fresh store per call, and eight concurrent runs against one output
# directory were measured losing 5 of 32 findings to interleaved writes.
# Cross-process and cross-module interleaving of the shared file remains outside
# one module's reach (see LIMITATIONS in the module docstring).
_STORE_LOCKS: Dict[str, threading.Lock] = {}
_STORE_LOCKS_GUARD = threading.Lock()


def _lock_for_path(path: str) -> threading.Lock:
    key = os.path.abspath(path)
    with _STORE_LOCKS_GUARD:
        lock = _STORE_LOCKS.get(key)
        if lock is None:
            lock = _STORE_LOCKS[key] = threading.Lock()
        return lock


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


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
        self._lock = _lock_for_path(self.path)
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except OSError as exc:
            # A read-only or otherwise unusable output directory previously
            # surfaced as a bare PermissionError escaping run_tech_fingerprint
            # before any check ran. It is a persistence problem and must be
            # reported as one.
            raise PersistenceError(
                f"Cannot create/access output directory {self.output_dir!r}: {exc}"
            ) from exc

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
        except OSError as exc:
            raise PersistenceError(
                f"Cannot read {self.path!r}: {exc}"
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
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=".pending_assets_", dir=dir_name)
        except OSError as exc:
            raise PersistenceError(
                f"Cannot create a temporary file next to {self.path!r}: {exc}"
            ) from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except OSError as exc:
            _remove_quietly(tmp_path)
            raise PersistenceError(f"Cannot write {self.path!r}: {exc}") from exc
        except BaseException:
            _remove_quietly(tmp_path)
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
    except OSError as exc:
        # Anything the store did not already classify (a disk filling up
        # mid-run, an fsync failure, the directory being removed underneath
        # the process) previously escaped this helper and aborted the whole
        # run, discarding every not-yet-persisted detection. It is reported,
        # not swallowed, and the remaining detections still get their chance.
        return f"Persistence failed for {finding.get('type')!r}: {exc}"


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


def parse_cookie_names(set_cookie_headers: List[str]) -> List[str]:
    """Extract just the cookie names from raw Set-Cookie header strings."""
    names: List[str] = []
    for raw in set_cookie_headers or []:
        # A non-string entry is not a cookie header; it must not abort the
        # whole cookie scan (this is a public helper and urllib3's getlist is
        # not the only possible caller).
        if not isinstance(raw, str):
            continue
        first = raw.split(";", 1)[0]
        name = first.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


# ---------------------------------------------------------------------------
# Shared HTTP client (not itself a listed context.md responsibility, but
# necessary plumbing — mirrors http_analyzer.py's/endpoint_discovery.py's
# fetch_url, extended to also return raw bytes for favicon hashing)
# ---------------------------------------------------------------------------

def _read_bounded_body(resp: Any, max_body_bytes: int) -> Tuple[bytes, Optional[str]]:
    """
    Read at most `max_body_bytes` + 1 *decoded* bytes from an already-issued
    streaming response.

    `urllib3.HTTPResponse.read(amt, decode_content=True)` treats `amt` as a
    count of **compressed** bytes and returns the decompressed result, so a
    single `read(max_body_bytes + 1)` against a `Content-Encoding: gzip`
    response materialises the entire decompressed payload before the cap is
    ever applied. Measured: a 203 KB gzip body declaring 200 MB of content
    peaked at 270 MB of allocation inside one fetch_url call, and this module
    issues up to 15 fetches per run.

    Compressed responses are therefore drained in small *compressed* chunks
    and abandoned as soon as enough decoded bytes are in hand, which bounds
    peak allocation to roughly one chunk's expansion. Identity-encoded
    responses (the overwhelming majority) keep the original single bounded
    read — with no decoder in the path, `amt` is already a decoded-byte cap,
    so nothing about their behaviour changes.
    """
    limit = max_body_bytes + 1
    encoding = ""
    try:
        encoding = str(_ci_get(dict(resp.headers or {}), "Content-Encoding") or "").strip().lower()
    except Exception:
        encoding = ""

    first_error: Optional[str] = None
    if encoding in ("", "identity"):
        try:
            return resp.raw.read(limit, decode_content=True) or b"", None
        except Exception as exc:
            first_error = f"{type(exc).__name__}: {exc}"
    else:
        try:
            chunks: List[bytes] = []
            total = 0
            while total < limit:
                chunk = resp.raw.read(_DECODE_CHUNK_BYTES, decode_content=True)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            return b"".join(chunks)[:limit], None
        except Exception as exc:
            first_error = f"{type(exc).__name__}: {exc}"

    # Last resort only: resp.content materialises the whole (decompressed)
    # body, so it is reached only when the bounded reads above failed.
    try:
        return resp.content[:limit], first_error
    except Exception as exc:
        # An undecodable body (e.g. a response that declares
        # `Content-Encoding: gzip` and then sends plain text) must not look
        # like an empty page that was successfully inspected.
        return b"", first_error or f"{type(exc).__name__}: {exc}"


def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single HTTP GET against `url` without following redirects
    (this module inspects one response at a time; it does not need to
    traverse redirect chains — that is http_analyzer.py's job).
    """
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "set_cookie_headers": [],
        "body": None, "body_bytes": b"", "body_truncated": False, "final_url": url,
        "elapsed_seconds": None, "error": None, "body_error": None,
    }
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)

    resp = None
    try:
        resp = requests.get(url, timeout=timeout, headers=req_headers, allow_redirects=False, stream=True)
        raw, body_error = _read_bounded_body(resp, max_body_bytes)
        truncated = len(raw) > max_body_bytes
        body_bytes = raw[:max_body_bytes]
        try:
            body_text = body_bytes.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            body_text = body_bytes.decode("utf-8", errors="replace")

        try:
            set_cookie_headers = list(resp.raw.headers.getlist("Set-Cookie"))
        except AttributeError:
            single = resp.headers.get("Set-Cookie")
            set_cookie_headers = [single] if single else []

        result.update({
            "status": "found",
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "set_cookie_headers": set_cookie_headers,
            "body": body_text,
            "body_bytes": body_bytes,
            "body_truncated": truncated,
            "final_url": resp.url,
            "elapsed_seconds": resp.elapsed.total_seconds(),
            "body_error": body_error,
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
# Signature catalogs
# ---------------------------------------------------------------------------

def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


# 1. Servers (context.md: Nginx, Apache, IIS, Caddy)
_SERVER_SIGNATURES: List[Dict[str, Any]] = [
    # The trailing (?![\w-]) guard is load-bearing: without it "Apache-Coyote/1.1"
    # (Tomcat's connector) was reported as Apache, and any "<product>-nginx"-style
    # token was reported as Nginx.
    {"name": "Nginx", "regex": _rx(r"\bnginx(?:/(\d+(?:\.\d+)*))?(?![\w-])")},
    {"name": "Apache", "regex": _rx(r"\bapache(?:/(\d+(?:\.\d+)*))?(?![\w-])")},
    {"name": "Microsoft IIS", "regex": _rx(r"\bmicrosoft-iis(?:/(\d+(?:\.\d+)*))?(?![\w-])")},
    {"name": "Caddy", "regex": _rx(r"\bcaddy(?:/(\d+(?:\.\d+)*))?(?![\w-])")},
]

# 2. WAFs (context.md: Cloudflare, Akamai, AWS WAF, F5, Imperva). Each
# marker is (weight, matcher) where matcher is None (presence-only) or a
# list of case-insensitive substrings. Passive signature matching only —
# no probes crafted to provoke a WAF (mirrors http_analyzer.py's
# detect_waf boundary).
_WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "Cloudflare": {
        "headers": {"server": (_SCORE_STRONG, ["cloudflare"]), "cf-ray": (_SCORE_STRONG, None),
                    "cf-cache-status": (_SCORE_WEAK, None)},
        "cookies": [(_SCORE_WEAK, "__cfduid"), (_SCORE_WEAK, "cf_clearance"), (_SCORE_WEAK, "__cf_bm")],
        "body": [(_SCORE_WEAK, "cloudflare ray id"), (_SCORE_WEAK, "attention required! | cloudflare")],
    },
    "Akamai": {
        "headers": {"server": (_SCORE_STRONG, ["akamaighost"]), "x-akamai-transformed": (_SCORE_STRONG, None)},
        "cookies": [(_SCORE_WEAK, "akamai")],
        "body": [],
    },
    "AWS WAF": {
        "headers": {"x-amzn-waf-action": (_SCORE_STRONG, None)},
        "cookies": [(_SCORE_WEAK, "aws-waf-token")],
        "body": [],
    },
    "F5": {
        "headers": {"server": (_SCORE_STRONG, ["big-ip"])},
        "cookies": [(_SCORE_WEAK, "bigipserver"), (_SCORE_WEAK, "ts01")],
        "body": [(_SCORE_WEAK, "the requested url was rejected"), (_SCORE_WEAK, "support id:")],
    },
    "Imperva": {
        "headers": {"x-iinfo": (_SCORE_STRONG, None), "x-cdn": (_SCORE_STRONG, ["incapsula"])},
        "cookies": [(_SCORE_WEAK, "incap_ses"), (_SCORE_WEAK, "visid_incap")],
        "body": [(_SCORE_WEAK, "incapsula incident id"), (_SCORE_WEAK, "request unsuccessful. incapsula")],
    },
}

# 3. CMS + framework signatures. Each entry:
#   name, category, meta_generator_product (str|None), version_attr_regex
#   (compiled|None, group(1)=version), html_markers (weak, list[str]),
#   cookie_patterns (weak, list[compiled]), header_markers
#   ({header_lower: (weight, None|[substrings])}), header_version_regex
#   (compiled|None, applied to the matching header value),
#   known_paths (list[(path, marker|None)]).
_TECH_SIGNATURES: List[Dict[str, Any]] = [
    # --- CMS ---
    {
        "name": "WordPress", "category": CATEGORY_CMS,
        "meta_generator_product": "WordPress",
        "version_attr_regex": None,
        "html_markers": ["wp-content/", "wp-includes/", "wp-json"],
        "cookie_patterns": [_rx(r"^wordpress_"), _rx(r"^wp-settings-")],
        "header_markers": {"link": (_SCORE_WEAK, ["wp-json", 'rel="https://api.w.org/"'])},
        "header_version_regex": None,
        "known_paths": [
            ("wp-login.php", "user_login"),
            ("wp-json/", '"name"'),
            ("xmlrpc.php", "XML-RPC server accepts POST requests only"),
        ],
    },
    {
        "name": "Drupal", "category": CATEGORY_CMS,
        "meta_generator_product": "Drupal",
        "version_attr_regex": None,
        "html_markers": ["/sites/default/files/", "/sites/all/modules/", "Drupal.settings"],
        "cookie_patterns": [_rx(r"^SESS[a-f0-9]{32}$"), _rx(r"^SSESS[a-f0-9]{32}$")],
        "header_markers": {"x-generator": (_SCORE_STRONG, ["drupal"]), "x-drupal-cache": (_SCORE_STRONG, None),
                            "x-drupal-dynamic-cache": (_SCORE_STRONG, None)},
        "header_version_regex": None,
        "known_paths": [
            ("CHANGELOG.txt", "Drupal"),
            ("core/CHANGELOG.txt", "Drupal"),
            ("user/login", "Log in"),
        ],
    },
    {
        "name": "Joomla", "category": CATEGORY_CMS,
        "meta_generator_product": "Joomla",
        "version_attr_regex": None,
        "html_markers": ["/media/system/js/", "/media/jui/", "Joomla!"],
        "cookie_patterns": [_rx(r"^joomla_user_state$")],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [
            ("administrator/", "Joomla"),
            ("administrator/manifests/files/joomla.xml", "<version>"),
        ],
    },
    {
        "name": "Magento", "category": CATEGORY_CMS,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["/skin/frontend/", "/static/frontend/", "Mage.Cookies", "Magento_Store", "/js/mage/"],
        "cookie_patterns": [_rx(r"^form_key$")],
        "header_markers": {"x-magento-cache-debug": (_SCORE_STRONG, None), "x-magento-tags": (_SCORE_STRONG, None)},
        "header_version_regex": None,
        "known_paths": [
            ("errors/report.php", None),
            ("admin/", None),
        ],
    },
    # --- Frameworks ---
    {
        "name": "Django", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["csrfmiddlewaretoken", "you're seeing this because you have debug = true"],
        "cookie_patterns": [_rx(r"^csrftoken$"), _rx(r"^sessionid$")],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Flask", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["werkzeug debugger"],
        "cookie_patterns": [],
        "header_markers": {"server": (_SCORE_STRONG, ["werkzeug"])},
        "header_version_regex": _rx(r"werkzeug/([\d]+(?:\.[\d]+)*)"),
        "known_paths": [],
    },
    {
        "name": "FastAPI", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": [],
        "cookie_patterns": [],
        "header_markers": {"server": (_SCORE_WEAK, ["uvicorn"])},
        "header_version_regex": None,
        "known_paths": [
            ("openapi.json", '"openapi"'),
            ("docs", "swagger-ui"),
        ],
    },
    {
        "name": "Laravel", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["whoops, looks like something went wrong", "illuminate\\\\"],
        "cookie_patterns": [_rx(r"^laravel_session$"), _rx(r"^XSRF-TOKEN$")],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Express", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": [],
        "cookie_patterns": [_rx(r"^connect\.sid$")],
        "header_markers": {"x-powered-by": (_SCORE_STRONG, ["express"])},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Next.js", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        "html_markers": ["__next_data__", "/_next/static/"],
        "cookie_patterns": [],
        "header_markers": {"x-powered-by": (_SCORE_STRONG, ["next.js"])},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "React", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        # Bare "react-dom" matched any page that merely *mentions* the package
        # (documentation, a changelog, a job ad). Requiring a bundle/URL
        # delimiter keeps every real script reference — "/react-dom.production
        # .min.js", "react-dom@18/umd/...", "react-dom/client" — and drops prose.
        "html_markers": ["data-reactroot", "_reactrootcontainer", _rx(r"react-dom[@./\"']")],
        "cookie_patterns": [],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Angular", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": _rx(r'ng-version=["\'](\d+(?:\.\d+)*)["\']'),
        # "ng-app" as a bare substring matched ordinary words such as
        # "training-app" and "booking-app"; it is an HTML attribute, so it is
        # matched as one.
        "html_markers": ["ng-version", _rx(r"<[^<>]{0,200}\bng-app\b")],
        "cookie_patterns": [],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
    {
        "name": "Vue", "category": CATEGORY_FRAMEWORK,
        "meta_generator_product": None,
        "version_attr_regex": None,
        # Vue's scoped-style attribute is "data-v-<hash>"; the bare "data-v-"
        # prefix also matched any custom "data-v-model"/"data-view" style
        # attribute, including inside JSON API responses.
        "html_markers": [_rx(r"data-v-[0-9a-f]{6,10}\b"), "__vue__", "__nuxt__"],
        "cookie_patterns": [],
        "header_markers": {},
        "header_version_regex": None,
        "known_paths": [],
    },
]

# `select_wordlists_for_technology`-compatible keys (endpoint_discovery.py,
# already-built consumption interface) — used to annotate which detections
# have direct tech-aware wordlist coverage downstream.
_ENDPOINT_DISCOVERY_WORDLIST_TECHS = frozenset({"wordpress", "laravel", "django"})


# ---------------------------------------------------------------------------
# 1. Server identification
# ---------------------------------------------------------------------------

def detect_servers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Server header signature matching (responsibility #1). A single Server
    header claim is a direct declaration but from one, spoofable source —
    scored MEDIUM (score=_SCORE_STRONG=2), never HIGH on its own.
    """
    value = _ci_get(headers, "Server")
    scan: Dict[str, Any] = {}
    if not value:
        return scan
    for sig in _SERVER_SIGNATURES:
        m = sig["regex"].search(value)
        if not m:
            continue
        version = _plausible_version(m.group(1)) if m.groups() and m.group(1) else None
        scan[sig["name"]] = {
            "category": CATEGORY_SERVER,
            "evidence": [f"Server header value {value!r} matches {sig['name']}"],
            "signals": {f"server_header:{sig['name']}": _SCORE_STRONG},
            "score": _SCORE_STRONG,
            "version": version,
        }
    return scan


# ---------------------------------------------------------------------------
# 2. WAF signature detection
# ---------------------------------------------------------------------------

def detect_wafs(headers: Dict[str, str], set_cookie_headers: Optional[List[str]], body: Optional[str]) -> Dict[str, Any]:
    """Passive WAF signature matching against headers/cookies/body of an already-fetched response."""
    lower_headers = {k.lower(): (v or "") for k, v in (headers or {}).items()}
    # Cookie markers are matched against cookie NAMES only. Matching the whole
    # raw Set-Cookie string meant any cookie whose *value* happened to contain
    # "akamai", "ts01" or "incap_ses" produced a WAF detection — reproduced
    # with `pref=my-akamai-favourite-thing` (Akamai) and `sid=ts01abcdef` (F5).
    cookie_names_lower = [n.lower() for n in parse_cookie_names(set_cookie_headers or [])]
    body_lower = (body or "").lower()

    scan: Dict[str, Any] = {}
    for vendor, sig in _WAF_SIGNATURES.items():
        evidence: List[str] = []
        signals: Dict[str, int] = {}

        def record(key: str, weight: int, text: str) -> None:
            evidence.append(text)
            signals[key] = max(signals.get(key, 0), weight)

        for header_name, (weight, subs) in sig["headers"].items():
            value = lower_headers.get(header_name)
            if value is None:
                continue
            if subs is None:
                record(f"waf_header:{header_name}", weight,
                        f"header {header_name!r} present: {value!r}")
            else:
                for sub in subs:
                    if sub in value.lower():
                        record(f"waf_header:{header_name}:{sub}", weight,
                                f"header {header_name!r} contains {sub!r}")
        for weight, marker in sig["cookies"]:
            matched = [n for n in cookie_names_lower if marker in n]
            if matched:
                shown = ", ".join(repr(n) for n in matched[:5])
                if len(matched) > 5:
                    shown += f" (+{len(matched) - 5} more)"
                record(f"waf_cookie:{marker}", weight,
                        f"Set-Cookie name(s) {shown} contain marker {marker!r}")
        for weight, marker in sig["body"]:
            if marker in body_lower:
                record(f"waf_body:{marker}", weight,
                        f"response body contains marker {marker!r}")
        if evidence:
            scan[vendor] = {"category": CATEGORY_WAF, "evidence": evidence,
                             "signals": signals, "score": sum(signals.values()), "version": None}
    return scan


# ---------------------------------------------------------------------------
# 3. CMS + framework signature detection (headers/cookies/HTML/JS/URLs)
# ---------------------------------------------------------------------------

# `<meta ...>` tag scanner. `[^<>]` (not `[^>]`) is deliberate: with `[^>]`,
# a body consisting of many `<meta ` tokens lets the engine consume the
# remainder of the body from every candidate start position and backtrack —
# measured at 21.3 s for one 128 KB body, i.e. ~25 s per signature scan and
# ~50 s per run, from a single HTTP response. Excluding `<` confines each
# attempt to one tag, and the bounded repetition caps one pathological tag.
_META_TAG_RE = re.compile(r"<meta\b([^<>]{0,4096})>", re.IGNORECASE)
_ATTR_RE = re.compile(
    r"""([a-zA-Z_:][-\w:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+))"""
)


def _meta_attrs(tag_body: str) -> Dict[str, str]:
    """Parse one `<meta ...>` tag's attributes (first occurrence of each name wins)."""
    attrs: Dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag_body):
        name = m.group(1).lower()
        if name in attrs:
            continue
        value = m.group(2)
        if value is None:
            value = m.group(3)
        if value is None:
            value = m.group(4) or ""
        attrs[name] = value
    return attrs


def extract_generator_declarations(body: Optional[str]) -> List[str]:
    """
    Return the `content` of every `<meta name="generator">` tag in document
    order, regardless of attribute order.

    The previous single regex required `content=` to appear *after* `name=`,
    so the equally valid `<meta content="WordPress 6.4.2" name="generator">`
    produced no detection at all.
    """
    declarations: List[str] = []
    for m in _META_TAG_RE.finditer(body or ""):
        attrs = _meta_attrs(m.group(1))
        if attrs.get("name", "").strip().lower() != "generator":
            continue
        content = attrs.get("content")
        if content:
            declarations.append(content)
    return declarations


def _plausible_version(token: Optional[str]) -> Optional[str]:
    """
    Reject version strings no real product emits.

    A version reported by this module is consumed by vuln_intel.py as a fact
    to match CVEs against, so a target-supplied token such as
    `ng-version="99999999999999.1.1"` must not be reproduced verbatim as a
    detected version. Only dotted numeric tokens of at most
    _MAX_VERSION_COMPONENTS components, each at most
    _MAX_VERSION_COMPONENT_DIGITS digits, are accepted.
    """
    if not token:
        return None
    parts = token.split(".")
    if len(parts) > _MAX_VERSION_COMPONENTS:
        return None
    for part in parts:
        if not part.isdigit() or len(part) > _MAX_VERSION_COMPONENT_DIGITS:
            return None
    return token


def _version_after_product(content: str, product_name: str) -> Optional[str]:
    """
    Extract a version only when a numeric token *immediately follows* the
    product name in the declared string.

    Scanning the whole declaration for the first number anywhere turned
    `<meta name="generator" content="Powered by WordPress since 2003">` into
    a reported "WordPress 2003" — precisely the invented version this
    module's own contract ("never guesses or infers a version") forbids, and
    exactly the kind of false precision vuln_intel.py would then look up.
    """
    m = re.search(re.escape(product_name) + r"[\s!:_/v-]*?v?(\d+(?:\.\d+)*)", content, re.IGNORECASE)
    if not m:
        return None
    # The token must genuinely follow the name, not sit further along in prose:
    # re.escape(name) + a short separator run is already anchored, but reject a
    # match whose separator swallowed a word (e.g. "WordPress since 2003").
    separator = content[m.start() + len(product_name): m.start(1)]
    if separator.strip(" \t!:_/-vV"):
        return None
    return _plausible_version(m.group(1))


def _extract_meta_generator(
    body: str, product_name: str, declarations: Optional[List[str]] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (declared_content, version) if a `<meta name="generator">` tag
    mentions `product_name`, else (None, None). Version is only returned when
    a numeric version token actually follows the product name in the declared
    content — never invented.

    `declarations` lets a caller that already scanned the body reuse the
    result: the tag scan is body-wide and was previously re-run once per
    signature carrying a `meta_generator_product`.
    """
    if declarations is None:
        declarations = extract_generator_declarations(body)
    for content in declarations:
        if product_name.lower() in content.lower():
            return content, _version_after_product(content, product_name)
    return None, None


def _marker_matches(marker: Any, body: str, body_lower: str) -> bool:
    """
    Match one html_marker, which may be a plain substring or a compiled
    pattern. Patterns exist for markers whose bare substring form collides
    with ordinary prose (see _TECH_SIGNATURES).
    """
    if hasattr(marker, "search"):
        return marker.search(body) is not None
    return marker.lower() in body_lower


def _marker_label(marker: Any) -> str:
    return marker.pattern if hasattr(marker, "pattern") else str(marker)


def _scan_signature(
    sig: Dict[str, Any],
    headers: Dict[str, str],
    cookie_names: List[str],
    body: Optional[str],
    source_label: str,
    body_lower: Optional[str] = None,
    generator_declarations: Optional[List[str]] = None,
) -> Optional[Tuple[List[str], Dict[str, int], Optional[str]]]:
    """
    Match one technology signature against one (headers, cookies, body)
    triple. Returns (evidence, signals, version) if anything matched, else
    None, where `signals` maps each distinct signal key to its weight. Signal weighting: see implementation decision #1 in the module
    docstring.

    Scoring is keyed per *distinct underlying signal* (see
    implementation decision #7). Two Set-Cookie headers matching the same
    cookie pattern, or the same HTML marker seen again on the error page,
    are the same signal observed twice — evidence for both is preserved,
    but the score is counted once.
    """
    body = body or ""
    if body_lower is None:
        body_lower = body.lower()
    evidence: List[str] = []
    signals: Dict[str, int] = {}
    version: Optional[str] = None

    def record(key: str, weight: int, text: str) -> None:
        evidence.append(text)
        signals[key] = max(signals.get(key, 0), weight)

    if sig.get("meta_generator_product"):
        content, ver = _extract_meta_generator(
            body, sig["meta_generator_product"], declarations=generator_declarations,
        )
        if content:
            record(f"meta_generator:{sig['meta_generator_product']}", _SCORE_STRONG,
                    f"{source_label}: <meta name=\"generator\"> declares {content!r}")
            version = ver

    if sig.get("version_attr_regex"):
        m = sig["version_attr_regex"].search(body)
        if m:
            record(f"version_attr:{sig['name']}", _SCORE_STRONG,
                    f"{source_label}: version attribute matched {m.group(0)!r}")
            if not version:
                version = _plausible_version(m.group(1))

    for marker in sig.get("html_markers", []):
        if _marker_matches(marker, body, body_lower):
            label = _marker_label(marker)
            record(f"html:{label}", _SCORE_WEAK,
                    f"{source_label}: content contains marker {label!r}")

    for pattern in sig.get("cookie_patterns", []):
        matched_names = [name for name in cookie_names if pattern.match(name)]
        if matched_names:
            shown = ", ".join(repr(n) for n in matched_names[:5])
            if len(matched_names) > 5:
                shown += f" (+{len(matched_names) - 5} more)"
            record(f"cookie:{sig['name']}:{pattern.pattern}", _SCORE_WEAK,
                    f"Set-Cookie name(s) {shown} match {sig['name']} cookie pattern "
                    f"{pattern.pattern!r}")

    for header_name, (weight, subs) in sig.get("header_markers", {}).items():
        value = _ci_get(headers, header_name)
        if value is None:
            continue
        if subs is None:
            record(f"header:{header_name}", weight,
                    f"header {header_name!r} present: {value!r}")
            if sig.get("header_version_regex") and not version:
                vm = sig["header_version_regex"].search(value)
                if vm:
                    version = _plausible_version(vm.group(1))
        else:
            for sub in subs:
                if sub.lower() in value.lower():
                    record(f"header:{header_name}:{sub}", weight,
                            f"header {header_name!r} contains {sub!r} (value={value!r})")
                    if sig.get("header_version_regex") and not version:
                        vm = sig["header_version_regex"].search(value)
                        if vm:
                            version = _plausible_version(vm.group(1))

    if not evidence:
        return None
    return evidence, signals, version


def detect_technologies_from_content(
    headers: Dict[str, str], cookie_names: List[str], body: Optional[str], source_label: str = "baseline_response",
) -> Dict[str, Dict[str, Any]]:
    """
    Run every CMS/framework signature (responsibility #3) against one
    (headers, cookies, body) source. Returns {tech_name: {"category":,
    "evidence": [...], "signals": {key: weight}, "score": int,
    "version": Optional[str]}}, where `score` is the sum of the *distinct*
    signal weights (implementation decision #7).
    """
    body = body or ""
    # Both are body-wide and were previously recomputed inside every
    # signature (13 lowercase copies of up to 128 KB, and one full
    # <meta> scan per generator-carrying signature, per scan source).
    body_lower = body.lower()
    generator_declarations = extract_generator_declarations(body)

    scan: Dict[str, Any] = {}
    for sig in _TECH_SIGNATURES:
        result = _scan_signature(
            sig, headers, cookie_names, body, source_label,
            body_lower=body_lower, generator_declarations=generator_declarations,
        )
        if result is None:
            continue
        evidence, signals, version = result
        scan[sig["name"]] = {
            "category": sig["category"], "evidence": evidence,
            "signals": signals, "score": sum(signals.values()), "version": version,
        }
    return scan


def _merge_scan_maps(*maps: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Union evidence for the same technology across multiple scan sources, and
    score the union by *distinct signal*, not by repetition.

    The previous implementation summed the per-source scores. Because the
    baseline scan and the error-page scan run the identical matchers, any
    site whose 404 page shares the homepage's theme (a WordPress theme
    footer) or returns the homepage outright (an SPA catch-all) had every
    marker counted twice, so two genuine weak markers reached HIGH. Measured:
    a soft-404 site carrying two Magento markers scored 6 (HIGH) on two real
    signals. Scoring the merged signal set keeps converging *independent*
    evidence raising confidence (context.md §8) while repeated observation of
    the same signal no longer does.

    Records without a `signals` map (hand-built maps, and any future caller
    that builds a scan entry directly) keep the old additive behaviour: each
    such record contributes its own opaque key.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    for index, m in enumerate(maps):
        for name, rec in m.items():
            entry = merged.get(name)
            if entry is None:
                entry = merged[name] = {
                    "category": rec.get("category"), "evidence": [], "signals": {},
                    "score": 0, "version": rec.get("version"),
                    "corroborating_urls": [],
                }
            for text in rec.get("evidence", []):
                if text not in entry["evidence"]:
                    entry["evidence"].append(text)
            signals = rec.get("signals")
            if not signals:
                signals = {f"_unkeyed:{index}:{name}": rec.get("score", 0)}
            for key, weight in signals.items():
                entry["signals"][key] = max(entry["signals"].get(key, 0), weight)
            for url in rec.get("corroborating_urls", []) or []:
                if url not in entry["corroborating_urls"]:
                    entry["corroborating_urls"].append(url)
            confirmed = rec.get("confirmed_url")
            if confirmed and confirmed not in entry["corroborating_urls"]:
                entry["corroborating_urls"].append(confirmed)
            if not entry.get("version") and rec.get("version"):
                entry["version"] = rec["version"]
    for entry in merged.values():
        entry["score"] = sum(entry["signals"].values())
    return merged


# ---------------------------------------------------------------------------
# 4. Error-page signal correlation
# ---------------------------------------------------------------------------

def fetch_error_page_sample(origin: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Fetch one near-certainly-nonexistent path so its response can be
    scanned for technology-specific error/debug output (some frameworks —
    Laravel's "Whoops", Django's DEBUG traceback, Werkzeug's debugger —
    reveal themselves only on an error response). Mirrors
    endpoint_discovery.py's soft-404 probe technique for a different
    purpose (content inspection, not soft-404 fingerprinting).
    """
    probe_path = f"reconhound-tech-probe-{uuid.uuid4().hex[:12]}"
    url = origin.rstrip("/") + "/" + probe_path
    return fetch_url(url, timeout=timeout)


# ---------------------------------------------------------------------------
# 5. Favicon hashing
# ---------------------------------------------------------------------------

_MARKUP_PREFIXES = (b"<!doctype", b"<html", b"<?xml", b"<head", b"<body", b"<!--")


def _looks_like_markup(content_type: Optional[str], raw: bytes) -> bool:
    """
    True when a response is positively identified as HTML/XML rather than an
    icon. Deliberately conservative — an unknown or absent Content-Type is
    *not* treated as markup, so servers that serve icons with no/odd
    Content-Type keep working.

    `<svg` is excluded on purpose: an SVG favicon is a legitimate icon.
    """
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct in ("text/html", "application/xhtml+xml"):
        return True
    if ct.startswith("image/"):
        return False
    head = raw[:512].lstrip()[:64].lower()
    return any(head.startswith(prefix) for prefix in _MARKUP_PREFIXES)


def compute_favicon_hash(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Fetch <origin>/favicon.ico and compute MD5 + SHA-256 of its raw bytes.
    See module docstring, implementation decision #3, for why no bundled
    signature database is shipped.
    """
    origin = _origin_of(base_url)
    url = origin.rstrip("/") + "/favicon.ico"
    resp = fetch_url(url, timeout=timeout, max_body_bytes=DEFAULT_MAX_FAVICON_BYTES)
    result: Dict[str, Any] = {
        "status": resp["status"], "url": url, "error": resp.get("error"),
        "status_code": resp.get("status_code"), "content_type": None,
        "byte_length": 0, "md5": None, "sha256": None,
    }
    if resp["status"] != "found" or not resp.get("status_code") or resp["status_code"] >= 400:
        if resp["status"] == "found":
            result["status"] = "not_found"
        return result

    raw = resp.get("body_bytes") or b""
    if not raw:
        result["status"] = "empty"
        return result

    result["content_type"] = _ci_get(resp.get("headers") or {}, "Content-Type")
    if _looks_like_markup(result["content_type"], raw):
        # A site that answers /favicon.ico with its HTML soft-404 page has no
        # favicon. Hashing that page produced a `tech_fingerprint_favicon_observed`
        # record whose hash is the soft-404 page's, poisoning the stored hash
        # corpus that exists precisely so a future signature database can be
        # correlated against it retroactively.
        result["status"] = "not_an_icon"
        return result

    result["byte_length"] = len(raw)
    result["md5"] = hashlib.md5(raw).hexdigest()
    result["sha256"] = hashlib.sha256(raw).hexdigest()
    return result


def match_favicon_hash(
    favicon_result: Dict[str, Any], favicon_signatures: Optional[Dict[str, Dict[str, Any]]],
) -> Optional[Dict[str, Any]]:
    """
    Look up a computed favicon hash against a caller-supplied signature
    map: {hash_hex: {"technology":, "category":, "version": Optional}}.
    Checks both md5 and sha256. Returns a single-entry scan-map value
    (same shape as _scan_signature's output) if matched, else None.
    """
    if not favicon_signatures or not favicon_result.get("md5"):
        return None
    for hash_hex in (favicon_result.get("md5"), favicon_result.get("sha256")):
        sig = favicon_signatures.get(hash_hex) if hash_hex else None
        if sig:
            return {
                "technology": sig["technology"],
                "category": sig.get("category", CATEGORY_CMS),
                "evidence": [f"favicon hash {hash_hex} matched known signature for {sig['technology']}"],
                "signals": {f"favicon:{hash_hex}": _SCORE_STRONG},
                "score": _SCORE_STRONG,
                "version": sig.get("version"),
            }
    return None


# ---------------------------------------------------------------------------
# 6. Known technology-specific path probing (bounded, signal-driven —
# see module docstring, implementation decision #2)
# ---------------------------------------------------------------------------

def _catch_all_probe_result(soft_404: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Decide, from the random-path probe already fetched by
    fetch_error_page_sample(), whether this origin answers *any* path with a
    success status (an SPA/catch-all router, a soft-404 front controller, or
    an edge that rewrites every miss).

    Returns (is_catch_all, normalized_body_of_the_catch_all_response).
    """
    if not soft_404 or soft_404.get("status") != "found":
        return False, None
    code = soft_404.get("status_code")
    if not isinstance(code, int) or code >= 400 or code in (301, 302, 303, 307, 308):
        return False, None
    return True, _normalize_body_for_compare(soft_404.get("body"))


def _normalize_body_for_compare(body: Optional[str]) -> str:
    """Collapse whitespace so two renders of the same shell compare equal."""
    return " ".join((body or "").split())


def probe_known_paths(
    origin: str,
    candidate_names: List[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_probes: int = DEFAULT_MAX_KNOWN_PATH_PROBES,
    soft_404: Optional[Dict[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    For each already-signaled technology in `candidate_names` that has a
    known_paths list, probe up to `max_probes` (total, across all
    candidates) well-known paths to corroborate the detection. A 404
    contributes no evidence (absence isn't proof against other signals). A
    non-404 response with a matching content marker is strong evidence; a
    non-404 response with no marker configured is weak evidence.

    `soft_404` is the already-fetched random-path response from
    fetch_error_page_sample(). It is used as a control, because on an origin
    that answers every path with 200 a known-path 200 proves nothing:

      * a marker-less known path (Magento's `admin/`, `errors/report.php`)
        contributes no evidence at all when the origin is a catch-all —
        previously it contributed weak evidence per path, which took a
        soft-404 site carrying two generic Magento markers to HIGH; and
      * any known-path response whose body is identical to the random-path
        control is the same generic page, so it contributes nothing even
        when a marker matched — the marker came from the shell, and the
        baseline scan has already counted it.

    Omitting `soft_404` preserves the original behaviour exactly.
    """
    sig_by_name = {s["name"]: s for s in _TECH_SIGNATURES}
    scan: Dict[str, Any] = {}
    probes_used = 0
    is_catch_all, catch_all_body = _catch_all_probe_result(soft_404)

    for name in candidate_names:
        sig = sig_by_name.get(name)
        if not sig or not sig.get("known_paths"):
            continue
        for path, marker in sig["known_paths"]:
            if probes_used >= max_probes:
                return scan
            url = origin.rstrip("/") + "/" + path.lstrip("/")
            resp = fetch_url(url, timeout=timeout)
            probes_used += 1
            if resp["status"] != "found" or resp.get("status_code") in (None, 404):
                continue
            if resp.get("status_code") in (401, 403):
                continue

            body = resp.get("body") or ""
            if is_catch_all and catch_all_body is not None and \
                    _normalize_body_for_compare(body) == catch_all_body:
                continue

            if marker is not None:
                if marker.lower() not in body.lower():
                    continue
                evidence = [f"known path {url} returned HTTP {resp['status_code']} containing marker {marker!r}"]
                key = f"path:{path}:{marker}"
                score = _SCORE_STRONG
            else:
                if is_catch_all:
                    continue
                evidence = [f"known path {url} returned HTTP {resp['status_code']} (no content marker configured)"]
                key = f"path:{path}"
                score = _SCORE_WEAK

            entry = scan.setdefault(name, {"category": sig["category"], "evidence": [], "signals": {},
                                            "score": 0, "version": None, "confirmed_url": None,
                                            "corroborating_urls": []})
            entry["evidence"].extend(evidence)
            entry["signals"][key] = max(entry["signals"].get(key, 0), score)
            entry["score"] = sum(entry["signals"].values())
            entry["confirmed_url"] = url
            if url not in entry["corroborating_urls"]:
                entry["corroborating_urls"].append(url)

    return scan


# ---------------------------------------------------------------------------
# 7. Finalize detections (confidence scoring, context.md §8)
# ---------------------------------------------------------------------------

def _confidence_for_score(score: int) -> str:
    if score >= _HIGH_THRESHOLD:
        return CONFIDENCE_HIGH
    if score == _MEDIUM_THRESHOLD:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def _cap_evidence(evidence: List[str], limit: int = DEFAULT_MAX_EVIDENCE_PER_DETECTION) -> List[str]:
    """
    Bound one detection's evidence list, never silently.

    Evidence volume is target-controlled (one entry per matching cookie name,
    marker and probed path) and every entry is persisted to
    pending_assets.json and re-rendered downstream, so the overflow is
    reported rather than dropped without trace.
    """
    if len(evidence) <= limit:
        return list(evidence)
    kept = list(evidence[: limit - 1])
    kept.append(f"[{len(evidence) - (limit - 1)} further evidence entries omitted "
                f"— evidence volume capped at {limit} per detection]")
    return kept


def _finalize_detections(scan: Dict[str, Dict[str, Any]], base_url: str) -> List[Dict[str, Any]]:
    """
    Turn a merged scan map into a sorted list of final detection dicts
    (technology/category/version/evidence/confidence/url).

    `url` is deliberately the URL that was fingerprinted, not a corroborating
    probe path: surface_mapper.py keys a technology asset by
    (scope_url, technology), so emitting `https://host/wp-login.php` for a
    corroborated run and `https://host/` for an uncorroborated one split the
    same WordPress install into two technology assets, duplicating the
    downstream enumeration opportunity. The corroborating paths are preserved
    in their own field instead of being folded into asset identity.
    """
    detections = []
    for name in sorted(scan):
        rec = scan[name]
        if rec["score"] <= 0:
            continue
        corroborating = list(rec.get("corroborating_urls") or [])
        confirmed = rec.get("confirmed_url")
        if confirmed and confirmed not in corroborating:
            corroborating.append(confirmed)
        detections.append({
            "technology": name,
            "category": rec["category"],
            "version": rec.get("version"),
            "evidence": _cap_evidence(rec["evidence"]),
            "confidence": _confidence_for_score(rec["score"]),
            "url": base_url,
            "corroborating_urls": corroborating,
        })
    return detections


# ---------------------------------------------------------------------------
# 8. Normalization for surface_mapper.py (and direct pass-through
# compatibility with endpoint_discovery.py's existing `technology` param —
# see module docstring, NO-CROSS-MODULE-CALLS PRECEDENT, item (a))
# ---------------------------------------------------------------------------

def build_technology_summary(detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize detections into the shape surface_mapper.py (not yet
    implemented) is expected to consume, and which is ALREADY directly
    consumable by endpoint_discovery.py's `technology` parameter today
    (its `select_wordlists_for_technology` substring-searches every string
    value in this structure).
    """
    summary: Dict[str, Any] = {
        "cms": sorted(d["technology"] for d in detections if d["category"] == CATEGORY_CMS),
        "frameworks": sorted(d["technology"] for d in detections if d["category"] == CATEGORY_FRAMEWORK),
        "servers": sorted(d["technology"] for d in detections if d["category"] == CATEGORY_SERVER),
        "wafs": sorted(d["technology"] for d in detections if d["category"] == CATEGORY_WAF),
        "detections": detections,
    }
    return summary


# ---------------------------------------------------------------------------
# 9. Downstream-recon trigger integration — see module docstring,
# NO-CROSS-MODULE-CALLS PRECEDENT, item (b). This module never calls
# endpoint_discovery.py itself; it only produces justified recommendations
# for the future orchestrator to execute.
# ---------------------------------------------------------------------------

def build_recommended_actions(detections: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
    """
    Build a decision-queue-shaped list of recommended next actions
    (context.md §9) for CMS/framework detections at MEDIUM+ confidence.
    Never executed here — status is always "queued_for_orchestrator".
    """
    actions: List[Dict[str, Any]] = []
    for d in detections:
        if d["category"] not in (CATEGORY_CMS, CATEGORY_FRAMEWORK):
            continue
        if d["confidence"] not in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH):
            continue

        tech_key = d["technology"].lower()
        has_wordlist = tech_key in _ENDPOINT_DISCOVERY_WORDLIST_TECHS
        if has_wordlist:
            note = (
                f"endpoint_discovery.py has a dedicated wordlist for {d['technology']} — "
                f"passing this module's technology_summary into "
                f"endpoint_discovery.enumerate_framework_paths()/run_endpoint_discovery(technology=...) "
                f"will select it automatically."
            )
        else:
            note = (
                f"No dedicated wordlist exists for {d['technology']} yet — "
                f"endpoint_discovery.discover_api_endpoints() and standard directory/file enumeration "
                f"remain applicable."
            )

        actions.append({
            "action": "endpoint_discovery.run_endpoint_discovery",
            "target_module": "endpoint_discovery.py",
            # Without these the orchestrator receives an action with no subject:
            # `target` was accepted by this function and then never used.
            "target": target,
            "url": d.get("url"),
            "technology": d["technology"],
            "category": d["category"],
            "confidence": d["confidence"],
            "reason": note,
            "justification": (
                f"[REASON: {d['technology']} fingerprinted with {d['confidence']} confidence "
                f"({len(d['evidence'])} converging signal(s)) — technology-aware endpoint discovery "
                f"is the adaptive-discovery next step per context.md §6]"
            ),
            "status": "queued_for_orchestrator",
        })
    return actions


# ---------------------------------------------------------------------------
# Response representativeness, intermediary attribution, conflict detection
# ---------------------------------------------------------------------------

# Headers that prove the observed response passed through (or was produced by)
# a cache/CDN/proxy rather than coming straight from the origin application.
_INTERMEDIARY_HEADERS = (
    "via", "x-cache", "x-cache-hits", "age", "cf-ray", "cf-cache-status",
    "x-served-by", "x-amz-cf-id", "x-amz-cf-pop", "x-varnish", "x-fastly-request-id",
    "x-akamai-transformed", "x-azure-ref", "x-iinfo", "x-cdn",
)


def assess_response_representativeness(fetch_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decide whether a fetched response is a fair basis for the statement
    "this technology is not present".

    context.md §8's negative-result memory records a *completed* check so
    other modules can skip repeating it. Recording "checked and not found"
    from a 301 stub, a WAF block page, a 5xx, an empty body or a truncated
    body turns a failed observation into an asserted absence — the exact
    failure-becomes-absence error. Detections are unaffected: a Laravel
    "Whoops" 500 page is excellent positive evidence, it is just not proof of
    anything's absence.
    """
    reasons: List[str] = []
    status_code = fetch_result.get("status_code")
    body = fetch_result.get("body") or ""
    headers = fetch_result.get("headers") or {}

    if fetch_result.get("status") != "found":
        reasons.append(f"request did not complete ({fetch_result.get('error')})")
    if not isinstance(status_code, int):
        reasons.append("no HTTP status code observed")
    elif 300 <= status_code < 400:
        reasons.append(f"HTTP {status_code} redirect stub — the represented content lives elsewhere")
    elif status_code >= 400:
        reasons.append(f"HTTP {status_code} error/blocked response — origin content was not served")
    if fetch_result.get("body_error"):
        reasons.append(f"response body could not be read/decoded ({fetch_result['body_error']})")
    if not body.strip() and not _ci_get(headers, "Server") and not _ci_get(headers, "X-Powered-By"):
        reasons.append("empty body and no identifying response headers")
    if fetch_result.get("body_truncated"):
        reasons.append(f"body truncated at {DEFAULT_MAX_BODY_BYTES} bytes — the remainder was not inspected")

    return {
        "representative": not reasons,
        "reasons": reasons,
        "status_code": status_code,
        "content_type": _ci_get(headers, "Content-Type"),
        "body_truncated": bool(fetch_result.get("body_truncated")),
        "final_url": fetch_result.get("final_url"),
    }


def detect_intermediaries(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Report whether the response demonstrably passed through a cache/CDN/proxy.

    This module can observe "this response contains evidence of technology X".
    It cannot observe "the origin runs technology X" — an edge can add,
    replace or strip every signal it uses, and a cached response may describe
    a deployment that no longer exists. Where the response itself says an
    intermediary was involved, that is recorded as evidence rather than
    guessed at, and no numeric confidence penalty is invented for it.
    """
    present = [h for h in _INTERMEDIARY_HEADERS if _ci_get(headers, h) is not None]
    cache_status = _ci_get(headers, "X-Cache") or _ci_get(headers, "CF-Cache-Status")
    age = _ci_get(headers, "Age")
    return {
        "observed": bool(present),
        "headers": present,
        "cache_status": cache_status,
        "age": age,
        "note": (
            "Response demonstrably traversed a cache/CDN/proxy: header-derived "
            "evidence may describe the intermediary rather than the origin, and "
            "a cached body may predate the current deployment."
        ) if present else None,
    }


# Only one of these can be the CMS serving a given URL, so more than one at
# MEDIUM+ is a contradiction worth surfacing rather than four confident answers.
_MUTUALLY_EXCLUSIVE_CATEGORIES = (CATEGORY_CMS, CATEGORY_SERVER)


def detect_detection_conflicts(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Surface contradictions *within* one fingerprint (context.md §8, conflict
    preservation).

    Nothing is dropped or downgraded — a host genuinely can front two
    products, and preserving both is the architecture's rule. What was
    missing was any signal that they contradict each other: a soft-404 origin
    echoing four CMS marker sets produced four HIGH-confidence CMS detections
    and, once ingested, four separate `technology_specific_enumeration`
    opportunities, with `conflicts` empty in the graph.
    """
    conflicts: List[Dict[str, Any]] = []
    for category in _MUTUALLY_EXCLUSIVE_CATEGORIES:
        names = sorted({
            d["technology"] for d in detections
            if d["category"] == category and d["confidence"] in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH)
        })
        if len(names) > 1:
            conflicts.append({
                "kind": f"multiple_{category}_detected",
                "category": category,
                "technologies": names,
                "explanation": (
                    f"{len(names)} distinct {category} products were fingerprinted on the same URL "
                    f"({', '.join(names)}). Possible explanations: several applications behind one "
                    f"hostname, a reverse proxy or CDN contributing its own signature, a catch-all/"
                    f"soft-404 origin echoing unrelated markers, or deliberately planted decoy "
                    f"signatures. All detections are preserved; none is authoritative on its own."
                ),
            })
    return conflicts


def annotate_detections(
    detections: List[Dict[str, Any]],
    intermediary: Dict[str, Any],
    conflicts: List[Dict[str, Any]],
    representativeness: Dict[str, Any],
) -> None:
    """Attach observation context to each detection, in place."""
    conflicting: Dict[str, List[str]] = {}
    for conflict in conflicts:
        for name in conflict["technologies"]:
            conflicting.setdefault(name, []).extend(n for n in conflict["technologies"] if n != name)

    for d in detections:
        d["observed_through_intermediary"] = bool(intermediary.get("observed"))
        d["cache_status"] = intermediary.get("cache_status")
        d["response_status_code"] = representativeness.get("status_code")
        d["conflicts_with"] = sorted(set(conflicting.get(d["technology"], [])))
        if intermediary.get("observed") and d["category"] in (CATEGORY_SERVER, CATEGORY_WAF):
            d["evidence"] = list(d["evidence"]) + [
                f"ATTRIBUTION: response traversed an intermediary "
                f"({', '.join(intermediary['headers'])}) — this {d['category']} signature may belong "
                f"to the edge rather than to the origin."
            ]
        elif intermediary.get("observed"):
            d["evidence"] = list(d["evidence"]) + [
                f"ATTRIBUTION: response traversed an intermediary "
                f"({', '.join(intermediary['headers'])}); cached or edge-rewritten content can carry "
                f"signals the current origin no longer emits."
            ]


# ---------------------------------------------------------------------------
# Negative-result memory (context.md §8/§12.6)
# ---------------------------------------------------------------------------

def persist_no_match_findings(
    categories_with_detections: set, target: str, url: str, store: Optional[PendingAssetsStore],
    observation: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Persist a negative-result-memory finding for every category with zero
    detections.

    `observation` carries the audit trail of *what was actually inspected*
    (HTTP status, content type, whether the body was truncated, which probe
    stages ran) so a downstream consumer can tell a thorough negative from a
    thin one. Whether a negative may be recorded at all is decided by the
    caller via assess_response_representativeness().
    """
    errors: List[str] = []
    observation = observation or {}
    for category in (CATEGORY_CMS, CATEGORY_FRAMEWORK, CATEGORY_SERVER, CATEGORY_WAF):
        if category in categories_with_detections:
            continue
        err = _safe_store_add(store, make_finding(
            finding_type="tech_fingerprint_checked_no_match",
            target=target,
            value={"category": category, "url": url},
            evidence=[f"No {category} signature matched headers/cookies/HTML/error-page content for {url}"
                      + (f" (HTTP {observation['status_code']})" if observation.get("status_code") else "")],
            confidence=CONFIDENCE_LOW,
            metadata={
                "category": category, "url": url,
                "observation": observation,
                "note": (
                    "Negative-result-memory: absence of a matching signature does not prove no such "
                    "technology is present — signatures are inherently incomplete, and some "
                    "technologies deliberately suppress identifying headers/markers."
                ),
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# Module orchestration (single URL)
# ---------------------------------------------------------------------------

def run_tech_fingerprint(
    url: str,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
    check_error_page: bool = True,
    check_favicon: bool = True,
    probe_known_paths_enabled: bool = True,
    favicon_signatures: Optional[Dict[str, Dict[str, Any]]] = None,
    max_known_path_probes: int = DEFAULT_MAX_KNOWN_PATH_PROBES,
) -> Dict[str, Any]:
    """
    Run all Module 8 technology-identification checks against a single URL
    and persist every completed detection immediately to
    <output_dir>/pending_assets.json. A failure in one stage does not
    prevent the others from running.
    """
    url = validate_url_target(url, target=target)
    target = target or (urllib.parse.urlsplit(url).hostname or url)
    origin = _origin_of(url)
    # Every derived request goes through the same scope gate as the entry URL,
    # so a future change to origin derivation cannot silently reach a host the
    # caller never authorised.
    validate_url_target(origin + "/", target=target)

    summary: Dict[str, Any] = {
        "url": url,
        "target": target,
        "module": MODULE_NAME,
        "started_at": _now(),
        "fetch_status": None,
        "status_code": None,
        "final_url": None,
        "content_type": None,
        "body_truncated": False,
        "baseline_representative": None,
        "intermediary": None,
        "conflicts": [],
        "persistence_available": True,
        "negative_result_memory": {"persisted": False, "reason": None},
        "technology_summary": {"cms": [], "frameworks": [], "servers": [], "wafs": [], "detections": []},
        "recommended_next_actions": [],
        "favicon": None,
        "errors": [],
    }

    store: Optional[PendingAssetsStore]
    try:
        store = PendingAssetsStore(output_dir=output_dir)
    except PersistenceError as exc:
        # An unusable output directory is a loud, recorded degradation, not an
        # unhandled traceback that discards the reconnaissance entirely.
        store = None
        summary["persistence_available"] = False
        summary["errors"].append({"stage": "persistence_init", "error": str(exc)})

    baseline = fetch_url(url, timeout=timeout)
    summary["fetch_status"] = baseline["status"]
    summary["status_code"] = baseline.get("status_code")
    summary["final_url"] = baseline.get("final_url")
    summary["body_truncated"] = bool(baseline.get("body_truncated"))
    if baseline["status"] != "found":
        summary["errors"].append({"stage": "fetch", "error": baseline.get("error")})
        summary["negative_result_memory"]["reason"] = "baseline request did not complete"
        summary["finished_at"] = _now()
        return summary

    headers = baseline["headers"]
    body = baseline.get("body")
    cookie_names = parse_cookie_names(baseline.get("set_cookie_headers", []))

    representativeness = assess_response_representativeness(baseline)
    summary["baseline_representative"] = representativeness
    summary["content_type"] = representativeness.get("content_type")
    intermediary = detect_intermediaries(headers)
    summary["intermediary"] = intermediary

    scans: List[Dict[str, Any]] = []

    try:
        scans.append(detect_technologies_from_content(headers, cookie_names, body, "baseline_response"))
    except Exception as exc:
        summary["errors"].append({"stage": "detect_technologies_from_content", "error": str(exc)})

    server_scan: Dict[str, Any] = {}
    try:
        server_scan = detect_servers(headers)
    except Exception as exc:
        summary["errors"].append({"stage": "detect_servers", "error": str(exc)})

    waf_scan: Dict[str, Any] = {}
    try:
        waf_scan = detect_wafs(headers, baseline.get("set_cookie_headers", []), body)
    except Exception as exc:
        summary["errors"].append({"stage": "detect_wafs", "error": str(exc)})

    error_resp: Optional[Dict[str, Any]] = None
    error_page_ok = not check_error_page
    if check_error_page:
        try:
            error_resp = fetch_error_page_sample(origin, timeout=timeout)
            if error_resp["status"] == "found":
                error_page_ok = True
                error_cookie_names = parse_cookie_names(error_resp.get("set_cookie_headers", []))
                scans.append(detect_technologies_from_content(
                    error_resp["headers"], error_cookie_names, error_resp.get("body"), "error_page_response",
                ))
            else:
                summary["errors"].append({"stage": "error_page_fetch", "error": error_resp.get("error")})
        except Exception as exc:
            summary["errors"].append({"stage": "error_page_fetch", "error": str(exc)})

    content_scan = _merge_scan_maps(*scans) if scans else {}

    if check_favicon:
        try:
            favicon_result = compute_favicon_hash(url, timeout=timeout)
            summary["favicon"] = favicon_result
            match = match_favicon_hash(favicon_result, favicon_signatures)
            if match:
                tech_name = match.pop("technology")
                content_scan = _merge_scan_maps(content_scan, {tech_name: match})
            elif favicon_result.get("md5"):
                err = _safe_store_add(store, make_finding(
                    finding_type="tech_fingerprint_favicon_observed",
                    target=target,
                    value={"url": favicon_result["url"], "md5": favicon_result["md5"], "sha256": favicon_result["sha256"]},
                    evidence=[f"Computed favicon hash for {favicon_result['url']} "
                              f"(md5={favicon_result['md5']}); no known signature matched"],
                    confidence=CONFIDENCE_LOW,
                    metadata={"url": favicon_result["url"], "md5": favicon_result["md5"],
                              "sha256": favicon_result["sha256"],
                              "note": "Negative-result memory: hash computed for future correlation "
                                      "once a signature database entry exists."},
                ))
                if err:
                    summary["errors"].append({"stage": "persist_favicon", "error": err})
        except Exception as exc:
            summary["errors"].append({"stage": "favicon", "error": str(exc)})

    if probe_known_paths_enabled and content_scan:
        try:
            corroboration = probe_known_paths(
                origin, list(content_scan.keys()), timeout=timeout,
                max_probes=max_known_path_probes, soft_404=error_resp,
            )
            content_scan = _merge_scan_maps(content_scan, corroboration)
        except Exception as exc:
            summary["errors"].append({"stage": "probe_known_paths", "error": str(exc)})

    all_scan = _merge_scan_maps(content_scan, server_scan, waf_scan)
    detections = _finalize_detections(all_scan, url)

    conflicts = detect_detection_conflicts(detections)
    summary["conflicts"] = conflicts
    annotate_detections(detections, intermediary, conflicts, representativeness)

    persistence_errors: List[str] = []
    for d in detections:
        err = _safe_store_add(store, make_tech_finding(
            technology=d["technology"], category=d["category"], version=d["version"],
            evidence=d["evidence"], confidence=d["confidence"], target=target, url=d["url"],
            metadata={
                "corroborating_urls": d.get("corroborating_urls", []),
                "conflicts_with": d.get("conflicts_with", []),
                "observed_through_intermediary": d.get("observed_through_intermediary", False),
                "cache_status": d.get("cache_status"),
                "response_status_code": d.get("response_status_code"),
            },
        ))
        if err:
            persistence_errors.append(err)
    if persistence_errors:
        summary["errors"].append({"stage": "persist_detections", "errors": persistence_errors})

    # Negative-result memory is an assertion that a check *completed*, so it is
    # only recorded when the response it is derived from could actually have
    # carried the signatures. Otherwise the honest state is "not checked",
    # which is surface_mapper.py's default for an unrecorded check — recording
    # "checked and not found" instead would let a redirect stub or a WAF block
    # page suppress a later, real check.
    blockers = list(representativeness["reasons"])
    if not error_page_ok:
        blockers.append("error-page correlation probe did not complete")
    if blockers:
        summary["negative_result_memory"] = {
            "persisted": False,
            "reason": "inconclusive observation: " + "; ".join(blockers),
        }
    else:
        observation = {
            **{k: representativeness[k] for k in ("status_code", "content_type", "body_truncated", "final_url")},
            "error_page_checked": bool(check_error_page),
            "favicon_checked": bool(check_favicon),
            "known_paths_probed": bool(probe_known_paths_enabled),
            "intermediary_observed": bool(intermediary.get("observed")),
        }
        categories_found = {d["category"] for d in detections}
        negmem_errors = persist_no_match_findings(categories_found, target, url, store, observation=observation)
        summary["negative_result_memory"] = {"persisted": True, "reason": None}
        if negmem_errors:
            summary["errors"].append({"stage": "negative_result_memory", "errors": negmem_errors})

    summary["technology_summary"] = build_technology_summary(detections)
    summary["recommended_next_actions"] = build_recommended_actions(detections, target)
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="tech_fingerprint.py",
        description="ReconHound Module 8 — technology identification (standalone test entry point).",
    )
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://example.com/")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--no-error-page", action="store_true", help="Skip the error-page correlation probe")
    parser.add_argument("--no-favicon", action="store_true", help="Skip favicon hash computation")
    parser.add_argument("--no-known-paths", action="store_true", help="Skip known-path corroboration probing")
    args = parser.parse_args()

    try:
        result = run_tech_fingerprint(
            args.url, target=args.target, output_dir=args.output_dir, timeout=args.timeout,
            check_error_page=not args.no_error_page, check_favicon=not args.no_favicon,
            probe_known_paths_enabled=not args.no_known_paths,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
