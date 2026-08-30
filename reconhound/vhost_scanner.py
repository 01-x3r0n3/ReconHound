"""
reconhound/vhost_scanner.py — ReconHound Module 9 (vhost_scanner.py), per
context.md's build order — catalog item 9 in §10's module list,
build-order position 22 (context.md §13; this repository, like
code_leak.py/passive_intel.py/wayback_intel.py/vuln_intel.py/
tech_fingerprint.py/api_recon.py before it, is operating under an explicit
deviation from the numeric build order — surface_mapper.py,
core/orchestrator.py, and reconhound.py are not yet implemented; see
BUILD-ORDER NOTE below).

Phase: Active. See context.md §10 (module 9, "Virtual-host discovery") for
the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Active — Virtual-host discovery via Host-header variation against
  discovered IPs; surfaces hidden apps not visible via DNS; each
  discovered vhost triggers web recon. Key differentiator."

The assignment's module contract expands that into these discrete
responsibilities, each implemented below:

  1. Controlled Host-header probing against an already-discovered,
     in-scope IP                              -> fetch_with_host_header
  2. Candidate vhost hostname construction
     (wordlist-driven + caller-supplied,
     scope-filtered)                          -> build_candidate_hostnames
  3. Baseline fingerprinting (what "no distinct
     application" looks like on this IP)      -> probe_baselines
  4. Meaningful-difference scoring (never claim
     a vhost from a bare 2xx alone)           -> score_vhost_candidate
  5. Per-IP/port/scheme vhost discovery
     orchestration + negative-result memory   -> discover_vhosts_for_target,
                                                  persist_no_distinct_response
  6. Shaping each discovered vhost into a
     downstream web-recon target              -> build_downstream_recon_target
  7. Decision-queue-shaped next-action
     recommendations (feeds surface_mapper.py) -> build_recommended_actions
  8. Normalization for surface_mapper.py        -> build_vhost_summary
  (single-target orchestrator)                  -> run_vhost_scan

Plus shared plumbing: make_finding/make_vhost_finding, PendingAssetsStore,
_safe_store_add, validate_scan_ip, load_wordlist (duplicated per modular
independence, same as every other implemented module).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
22, after surface_mapper.py (position 8). Per every already-implemented
later module's precedent, this repository is operating under an explicit,
user-approved deviation from that order — surface_mapper.py has not been
implemented yet. This module continues under the same deviation: it is a
fully standalone producer that does not implement, replace, or depend on
surface_mapper.py's correlation engine.

NO-CROSS-MODULE-CALLS PRECEDENT (responsibilities #6/#7, "each discovered
vhost triggers web recon" / "feed vhost intelligence into
surface_mapper.py"): every already-implemented Active-phase module in this
repository documents that it does NOT import or call into any sibling
module — integration is deferred to core/orchestrator.py (not yet built),
which is meant to route data between modules via surface_mapper.py. This
module follows the same precedent rather than inventing a competing
orchestration mechanism. Responsibility #6/#7 is satisfied by:

  a. build_downstream_recon_target: a normalized, JSON-safe record naming
     exactly what a downstream module needs to reach a hidden vhost — the
     already-authorized `connect_url` (IP-based, never the unresolvable
     hostname itself) plus the explicit `host_header_override` a caller
     must send. No existing module's fetch_url() accepts a Host-header
     override parameter today, so this module does not silently assume
     one does; it documents the requirement in the record's own `note`
     field for the future orchestrator/surface_mapper integration layer.
  b. build_recommended_actions: an explicit, evidence-justified
     decision-queue-shaped list (context.md §9) naming which
     already-implemented modules are appropriate next steps for a newly
     confirmed vhost. These are recommendations for the future
     orchestrator to execute — this module never invokes them itself.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). This module
does not implement or call into surface_mapper, active_recon,
tech_fingerprint, endpoint_discovery, api_recon, crawler, js_analyzer,
supply_chain, exposure_scan, http_analyzer, ssl_analyzer, screenshot,
vuln_intel, risk_engine, report_generator, orchestrator, osint_engine,
passive_recon, passive_intel, code_leak, wayback_intel, or any other module.

DISCOVERY != EXPLOITATION: this module only ever issues read-only GET
requests with a modified Host header against an IP the caller has already
identified as in-scope (e.g. via active_recon.py/passive_recon.py). It
never brute-forces credentials, never sends a state-changing request, and
never expands the scanned surface beyond that one supplied IP — every
candidate Host-header string is either derived from the authorized target
domain or explicitly scope-filtered (build_candidate_hostnames).

Implementation decisions (ambiguities resolved so implementation can
proceed without inventing requirements):

  1. Candidate hostname source: context.md §11's folder structure names
     `wordlists/subdomains.txt` explicitly as part of the locked
     architecture, but no file existed yet at that path (only
     directories.txt/api_endpoints.txt/*_paths.txt did). This module adds
     that already-specified wordlist file and loads it the same way
     endpoint_discovery.py loads directories.txt (load_wordlist,
     duplicated here per modular independence) — this fills in an
     already-approved architectural gap, it does not invent a new one.
     Each wordlist label is combined with the caller's `target` domain
     (e.g. "admin" + "example.com" -> "admin.example.com"). Callers may
     also supply `extra_hostnames` (e.g. hostnames already observed
     elsewhere — cert SANs, wayback history, OSINT — that are worth
     testing against a newly discovered IP to see if it also serves them).
  2. Scope enforcement for candidate hostnames: every constructed or
     caller-supplied candidate is checked against `target` (exact match or
     subdomain) before being probed; anything out of scope is recorded in
     `skipped_out_of_scope` (never silently dropped) rather than probed,
     unless the caller explicitly opts in via `allow_out_of_scope_hostnames`
     (default False) — mirrors CLAUDE.md rule 9's "strict target-scope
     enforcement" default. The IP itself is validated separately
     (validate_scan_ip) as a syntactically valid IP address; this module
     trusts that the caller (e.g. active_recon.py's output) already
     confirmed the IP itself belongs to the authorized engagement, the
     same trust boundary active_recon.py/tech_fingerprint.py already rely
     on for their own inputs.
  3. Two-baseline differencing (responsibility #4, the assignment's "avoid
     reporting a hostname as a discovered vhost solely because a request
     succeeded" requirement): every IP/port/scheme is first probed twice —
     once with the Host header set to the bare IP itself (approximates
     "what a client hitting this IP directly, with no vhost knowledge,
     sees") and once with a random, near-certainly-unrecognized Host value
     (approximates "what this server does with any Host it doesn't
     recognize"). A candidate is only ever reported as a discovered vhost
     when its response differs *from both* baselines on at least one
     meaningful signal (HTTP status code, response-body content hash,
     redirect Location target, or page `<title>`). A candidate that merely
     succeeds but matches either baseline exactly is recorded as a
     negative result (persist_no_distinct_response), not a discovery —
     this directly implements context.md §12.6's negative-result-memory
     principle for this module's own (potentially large) candidate list.
  4. Confidence scoring mirrors tech_fingerprint.py's weighted-signal
     model for consistency across the codebase: a status-code difference,
     a content-hash difference, or a redirect-target difference from both
     baselines is "strong" (2 points each); a `<title>` difference alone
     is "weak" (1 point). Confidence = HIGH at score >= 3, MEDIUM at
     score == 2, LOW at score == 1 (context.md §8: multiple independent
     converging signals raise confidence; a single weak signal stays LOW,
     a single strong signal reaches MEDIUM on its own). A LOW-confidence
     result is still reported (never silently dropped) but is explicitly
     flagged as uncertain, per the assignment's "represent uncertainty
     appropriately" requirement — it is only a *non-discovery* (negative
     result) when the score is exactly 0.
  5. HTTPS handling: the whole point of vhost scanning is deliberately
     sending a Host header that does not match the connection's actual
     target. For HTTPS this means the TLS layer's SNI still targets the
     bare IP (Python's `ssl`/`requests`/`urllib3` derive SNI from the
     connection host, not from a caller-supplied Host header — overriding
     that would require a custom SNI-aware HTTPAdapter, which is out of
     scope for "one module at a time" and not requested by the module
     contract). Certificate hostname validation is therefore also
     meaningless here and is disabled (`verify=False`, with the resulting
     urllib3 InsecureRequestWarning suppressed) — this mirrors
     passive_recon.py's/ssl_analyzer.py's own conscious, documented
     decision to skip certificate validation for reconnaissance purposes.
     This is a real, documented limitation: differentiation over HTTPS
     happens only at the post-TLS HTTP layer (which is exactly what many
     real deployments key their vhost routing on regardless of SNI), not
     a claim that SNI itself was spoofed.
  6. Sequential, not threaded, candidate probing: mirrors api_recon.py's
     decision #2 and its stated rationale — this module's candidate lists
     are bounded (a wordlist of common vhost labels plus a small,
     caller-supplied extra-hostnames list), so a thread pool's added
     complexity (and, more concretely, the loss of deterministic
     mock-based testability that every other implemented module's test
     suite relies on for `requests.get` call ordering) is not justified
     here. `max_candidates` lets a caller/orchestrator bound the work
     explicitly. Multiple discovered IPs are expected to be parallelized
     by the future orchestrator across separate run_vhost_scan() calls,
     not within a single call's candidate loop.
  7. "No override" baseline approximation: a real client connecting
     directly to an IP with no vhost-fuzzing intent would typically send
     `Host: <ip>` (or `Host: <ip>:<port>` for a non-default port) —
     port-qualification is not modeled separately here; the baseline Host
     header is always the bare IP string. This is a documented
     simplification, not a gap: the second baseline (an explicitly
     unrecognized random Host) exists precisely to catch cases where this
     approximation alone would be misleading.
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
import urllib3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

MODULE_NAME = "vhost_scanner.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-VhostScanner/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY_BYTES = 131072
DEFAULT_WORDLIST_NAME = "subdomains.txt"

# (port, scheme) pairs probed when the caller does not supply its own list.
DEFAULT_PORTS: Tuple[Tuple[int, str], ...] = ((80, "http"), (443, "https"))

# Signal-scoring weights (implementation decision #4)
_SCORE_STRONG = 2
_SCORE_WEAK = 1
_HIGH_THRESHOLD = 3
_MEDIUM_THRESHOLD = 2

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class ScopeError(ValueError):
    """Raised when a scan target/hostname falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class WordlistError(ValueError):
    """Raised when a required wordlist file cannot be loaded."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors active_recon.py's validate_scan_target for the
# IP, and tech_fingerprint.py's/api_recon.py's _in_scope_host for hostnames;
# duplicated per modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

def validate_scan_ip(ip: str) -> str:
    """
    Validate that `ip` is a syntactically valid IPv4 or IPv6 address.

    vhost_scanner operates on IP addresses already discovered and
    confirmed in-scope by upstream modules (e.g. active_recon.py); it never
    resolves or expands a hostname/CIDR range into an IP itself.
    """
    if not isinstance(ip, str) or not ip.strip():
        raise ScopeError("Scan target must be a non-empty IP address string.")

    candidate = ip.strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        raise ScopeError(
            f"Scan target must be a single valid IP address, not {ip!r} "
            f"(hostnames and CIDR ranges are not accepted by this function)."
        ) from None

    return candidate


def _format_host_for_url(ip: str) -> str:
    """Bracket an IPv6 literal for use in a URL; IPv4 is returned unchanged."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return f"[{ip}]" if obj.version == 6 else ip


def _in_scope_host(hostname: str, target: str) -> bool:
    hostname = hostname.strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    return hostname == target or hostname.endswith("." + target)


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


def make_vhost_finding(
    ip: str,
    port: int,
    scheme: str,
    hostname: str,
    evidence: List[str],
    confidence: str,
    target: str,
    signals: Optional[Dict[str, bool]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Wrap one discovered-vhost detection into the structured evidence record:
    ip, hostname/Host-header used, response/discovery information, and
    source — everything the assignment's provenance requirement asks for.
    """
    connect_url = f"{scheme}://{_format_host_for_url(ip)}:{port}/"
    value = {
        "ip": ip,
        "port": port,
        "scheme": scheme,
        "hostname": hostname,
        "host_header": hostname,
        "connect_url": connect_url,
    }
    return make_finding(
        finding_type="vhost_discovered",
        target=target,
        value=value,
        evidence=evidence,
        confidence=confidence,
        metadata={
            **(metadata or {}),
            "ip": ip, "port": port, "scheme": scheme, "hostname": hostname,
            "signals": signals or {},
        },
    )


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


def _content_signature(body: str) -> Tuple[int, str]:
    """Whitespace-normalized (length, md5) signature for content-diffing (mirrors api_recon.py)."""
    normalized = re.sub(r"\s+", " ", body or "").strip()
    return len(normalized), hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _extract_title(body: str) -> Optional[str]:
    if not body:
        return None
    m = _TITLE_RE.search(body)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title or None


def _confidence_for_score(score: int) -> str:
    if score >= _HIGH_THRESHOLD:
        return CONFIDENCE_HIGH
    if score == _MEDIUM_THRESHOLD:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


# ---------------------------------------------------------------------------
# Wordlist loading (mirrors endpoint_discovery.py's load_wordlist,
# duplicated here per modular independence)
# ---------------------------------------------------------------------------

def _default_wordlists_dir() -> str:
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wordlists"))


def load_wordlist(name: str, wordlists_dir: Optional[str] = None) -> List[str]:
    """Load a newline-delimited wordlist file (blank lines and '#' comments ignored, duplicates dropped, order preserved)."""
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
        if not entry or entry.startswith("#"):
            continue
        if entry not in seen:
            seen.add(entry)
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# 1. Controlled Host-header HTTP client
# ---------------------------------------------------------------------------

def fetch_with_host_header(
    ip: str,
    port: int,
    scheme: str,
    host_header: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Perform a single, read-only HTTP GET directly against `ip:port`,
    explicitly overriding the Host header to `host_header`. Certificate
    validation is disabled for `scheme="https"` — see module docstring,
    implementation decision #5, for why this is necessary rather than a
    security shortcut.
    """
    url = f"{scheme}://{_format_host_for_url(ip)}:{port}/"
    result: Dict[str, Any] = {
        "status": "error", "status_code": None, "headers": {}, "body": None,
        "body_truncated": False, "url": url, "host_header_sent": host_header,
        "elapsed_seconds": None, "error": None,
    }
    req_headers = {"Host": host_header, "User-Agent": DEFAULT_USER_AGENT}

    resp = None
    try:
        verify = scheme != "https"
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        resp = requests.get(
            url, timeout=timeout, headers=req_headers, allow_redirects=False, stream=True, verify=verify,
        )
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
# 2. Candidate vhost hostname construction
# ---------------------------------------------------------------------------

def build_candidate_hostnames(
    target: str,
    extra_hostnames: Optional[List[str]] = None,
    wordlists_dir: Optional[str] = None,
    wordlist_name: str = DEFAULT_WORDLIST_NAME,
    allow_out_of_scope: bool = False,
) -> Dict[str, Any]:
    """
    Build the candidate Host-header list: every wordlist label combined
    with `target` (e.g. "admin" -> "admin.example.com"), plus any
    caller-supplied `extra_hostnames`. Deduplicated, order-preserved, and
    scope-filtered against `target` (see module docstring, decision #2).
    """
    result: Dict[str, Any] = {
        "candidates": [], "skipped_out_of_scope": [], "wordlist_error": None, "labels_loaded": 0,
    }

    labels: List[str] = []
    try:
        labels = load_wordlist(wordlist_name, wordlists_dir)
    except WordlistError as exc:
        result["wordlist_error"] = str(exc)
    result["labels_loaded"] = len(labels)

    generated = [f"{label}.{target}".strip(".").lower() for label in labels]
    extra = [h.strip().rstrip(".").lower() for h in (extra_hostnames or []) if h and h.strip()]
    combined = generated + extra

    seen = set()
    for hostname in combined:
        if not hostname or hostname in seen:
            continue
        seen.add(hostname)
        if allow_out_of_scope or _in_scope_host(hostname, target):
            result["candidates"].append(hostname)
        else:
            result["skipped_out_of_scope"].append(hostname)

    return result


# ---------------------------------------------------------------------------
# 3. Baseline fingerprinting
# ---------------------------------------------------------------------------

def probe_baselines(ip: str, port: int, scheme: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Fetch two baseline responses for this ip/port/scheme (module docstring,
    decision #3): one with the Host header set to the bare IP (approximates
    a client hitting the IP directly), one with a random,
    near-certainly-unrecognized Host header. A candidate is only ever
    reported as a discovered vhost when it differs from *both*.
    """
    random_host = f"reconhound-vhost-baseline-{uuid.uuid4().hex[:12]}.invalid"
    ip_resp = fetch_with_host_header(ip, port, scheme, ip, timeout=timeout)
    random_resp = fetch_with_host_header(ip, port, scheme, random_host, timeout=timeout)
    return {
        "ip_host_response": ip_resp,
        "random_host_response": random_resp,
        "random_host_used": random_host,
    }


# ---------------------------------------------------------------------------
# 4. Meaningful-difference scoring
# ---------------------------------------------------------------------------

def score_vhost_candidate(
    candidate_resp: Dict[str, Any],
    ip_baseline: Dict[str, Any],
    random_baseline: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Score how strongly `candidate_resp` diverges from both baseline
    responses. Never scores above 0 from a bare successful fetch alone —
    only concrete, observable differences count (module docstring,
    decisions #3/#4).
    """
    if candidate_resp.get("status") != "found":
        return {"score": 0, "evidence": [], "signals": {}, "reason": "candidate_fetch_failed"}

    ip_ok = ip_baseline.get("status") == "found"
    rand_ok = random_baseline.get("status") == "found"
    if not ip_ok and not rand_ok:
        return {"score": 0, "evidence": [], "signals": {}, "reason": "both_baselines_unavailable"}

    evidence: List[str] = []
    signals: Dict[str, bool] = {}
    score = 0

    c_status = candidate_resp.get("status_code")
    c_body = candidate_resp.get("body") or ""
    c_headers = candidate_resp.get("headers") or {}
    _, c_hash = _content_signature(c_body)
    c_location = _ci_get(c_headers, "Location")
    c_title = _extract_title(c_body)

    ip_status = ip_baseline.get("status_code")
    rand_status = random_baseline.get("status_code")
    status_differs_from_ip = (not ip_ok) or (c_status != ip_status)
    status_differs_from_rand = (not rand_ok) or (c_status != rand_status)
    if status_differs_from_ip and status_differs_from_rand:
        score += _SCORE_STRONG
        evidence.append(
            f"HTTP status {c_status} differs from both the direct-IP baseline "
            f"({ip_status if ip_ok else 'unavailable'}) and the unrecognized-Host baseline "
            f"({rand_status if rand_ok else 'unavailable'})"
        )
        signals["status_diff"] = True

    _, ip_hash = _content_signature(ip_baseline.get("body") or "") if ip_ok else (0, None)
    _, rand_hash = _content_signature(random_baseline.get("body") or "") if rand_ok else (0, None)
    content_differs_from_ip = (not ip_ok) or (c_hash != ip_hash)
    content_differs_from_rand = (not rand_ok) or (c_hash != rand_hash)
    if c_body.strip() and content_differs_from_ip and content_differs_from_rand:
        score += _SCORE_STRONG
        evidence.append("Response body content differs from both baseline responses (distinct content hash)")
        signals["content_diff"] = True

    ip_location = _ci_get(ip_baseline.get("headers") or {}, "Location") if ip_ok else None
    rand_location = _ci_get(random_baseline.get("headers") or {}, "Location") if rand_ok else None
    if c_location and c_location != ip_location and c_location != rand_location:
        score += _SCORE_STRONG
        evidence.append(f"Redirect target {c_location!r} differs from both baseline redirect behaviors")
        signals["redirect_diff"] = True

    ip_title = _extract_title(ip_baseline.get("body") or "") if ip_ok else None
    rand_title = _extract_title(random_baseline.get("body") or "") if rand_ok else None
    if c_title and c_title != ip_title and c_title != rand_title:
        score += _SCORE_WEAK
        evidence.append(f"Page title {c_title!r} differs from both baseline page titles")
        signals["title_diff"] = True

    return {"score": score, "evidence": evidence, "signals": signals, "reason": None}


# ---------------------------------------------------------------------------
# Negative-result memory (context.md §8/§12.6)
# ---------------------------------------------------------------------------

def persist_no_distinct_response(
    hostname: str, ip: str, port: int, scheme: str, target: str, store: Optional[PendingAssetsStore],
) -> Optional[str]:
    """Persist a negative-result-memory finding: this Host header was checked and produced no distinguishing signal."""
    connect_url = f"{scheme}://{_format_host_for_url(ip)}:{port}/"
    return _safe_store_add(store, make_finding(
        finding_type="vhost_checked_no_distinct_response",
        target=target,
        value={"ip": ip, "port": port, "scheme": scheme, "hostname": hostname, "connect_url": connect_url},
        evidence=[
            f"Host header {hostname!r} against {connect_url} produced a response indistinguishable "
            f"from both the direct-IP baseline and the unrecognized-Host baseline"
        ],
        confidence=CONFIDENCE_LOW,
        metadata={
            "ip": ip, "port": port, "hostname": hostname,
            "note": (
                "Negative-result-memory: absence of a distinguishing signal does not prove no "
                "application is bound to this Host header — some servers deliberately normalize "
                "responses across virtual hosts, or the candidate hostname genuinely has no vhost here."
            ),
        },
    ))


# ---------------------------------------------------------------------------
# 5. Per-IP/port/scheme vhost discovery orchestration
# ---------------------------------------------------------------------------

def discover_vhosts_for_target(
    ip: str,
    port: int,
    scheme: str,
    target: str,
    candidates: List[str],
    store: Optional[PendingAssetsStore] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_candidates: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run Host-header vhost discovery for one ip/port/scheme against every
    candidate hostname. A failure on one candidate (timeout, connection
    error, malformed response) never aborts the remaining candidates.
    """
    connect_url = f"{scheme}://{_format_host_for_url(ip)}:{port}/"
    result: Dict[str, Any] = {
        "ip": ip, "port": port, "scheme": scheme, "target": target, "connect_url": connect_url,
        "candidates_checked": 0, "discovered_vhosts": [], "negative_results_count": 0,
        "baseline": None, "errors": [],
    }

    try:
        baselines = probe_baselines(ip, port, scheme, timeout=timeout)
    except Exception as exc:
        result["errors"].append({"stage": "baseline", "ip": ip, "port": port, "error": str(exc)})
        return result

    ip_baseline = baselines["ip_host_response"]
    random_baseline = baselines["random_host_response"]
    result["baseline"] = {
        "ip_host_status": ip_baseline.get("status"),
        "ip_host_status_code": ip_baseline.get("status_code"),
        "ip_host_error": ip_baseline.get("error"),
        "random_host_status": random_baseline.get("status"),
        "random_host_status_code": random_baseline.get("status_code"),
        "random_host_error": random_baseline.get("error"),
        "random_host_used": baselines["random_host_used"],
    }

    if ip_baseline.get("status") != "found" and random_baseline.get("status") != "found":
        result["errors"].append({
            "stage": "baseline", "ip": ip, "port": port,
            "error": "both baseline probes failed; cannot reliably distinguish vhosts on this ip/port/scheme",
        })
        return result

    candidate_list = candidates if max_candidates is None else candidates[:max_candidates]

    for hostname in candidate_list:
        result["candidates_checked"] += 1
        try:
            resp = fetch_with_host_header(ip, port, scheme, hostname, timeout=timeout)
        except Exception as exc:
            result["errors"].append({"stage": "candidate_fetch", "hostname": hostname, "error": str(exc)})
            continue

        if resp.get("status") != "found":
            result["errors"].append({"stage": "candidate_fetch", "hostname": hostname, "error": resp.get("error")})
            continue

        try:
            scoring = score_vhost_candidate(resp, ip_baseline, random_baseline)
        except Exception as exc:
            result["errors"].append({"stage": "scoring", "hostname": hostname, "error": str(exc)})
            continue

        if scoring["score"] <= 0:
            result["negative_results_count"] += 1
            err = persist_no_distinct_response(hostname, ip, port, scheme, target, store)
            if err:
                result["errors"].append({"stage": "persist_negative", "hostname": hostname, "error": err})
            continue

        confidence = _confidence_for_score(scoring["score"])
        record = {
            "ip": ip, "port": port, "scheme": scheme, "hostname": hostname, "connect_url": connect_url,
            "status_code": resp.get("status_code"), "confidence": confidence, "score": scoring["score"],
            "evidence": scoring["evidence"], "signals": scoring["signals"], "timestamp": _now(),
        }
        result["discovered_vhosts"].append(record)

        err = _safe_store_add(store, make_vhost_finding(
            ip=ip, port=port, scheme=scheme, hostname=hostname, evidence=scoring["evidence"],
            confidence=confidence, target=target, signals=scoring["signals"],
        ))
        if err:
            result["errors"].append({"stage": "persist_vhost", "hostname": hostname, "error": err})

    return result


# ---------------------------------------------------------------------------
# 6/7. Downstream web-recon target shaping + decision-queue recommendations
# — see module docstring, NO-CROSS-MODULE-CALLS PRECEDENT. This module
# never calls tech_fingerprint.py/http_analyzer.py/endpoint_discovery.py/
# crawler.py/ssl_analyzer.py itself; it only produces justified
# recommendations for the future orchestrator to execute.
# ---------------------------------------------------------------------------

_SUGGESTED_DOWNSTREAM_MODULES: Tuple[str, ...] = (
    "tech_fingerprint.py", "http_analyzer.py", "endpoint_discovery.py", "crawler.py",
)


def build_downstream_recon_target(vhost_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Shape one discovered vhost as an appropriate downstream
    web-reconnaissance target (responsibility #6). The hostname may not be
    resolvable via DNS at all — that's the entire point of vhost
    discovery — so downstream modules must connect to `connect_url` (the
    already-authorized IP) while explicitly sending `host_header_override`.
    """
    return {
        "hostname": vhost_record["hostname"],
        "ip": vhost_record["ip"],
        "port": vhost_record["port"],
        "scheme": vhost_record["scheme"],
        "connect_url": vhost_record["connect_url"],
        "host_header_override": vhost_record["hostname"],
        "confidence": vhost_record["confidence"],
        "note": (
            "This hostname was discovered via Host-header variation and may not resolve via DNS. "
            "Downstream reconnaissance modules must connect to `connect_url` (the already-authorized "
            "IP) while explicitly sending an HTTP Host header equal to `host_header_override` to reach "
            "this specific virtual host."
        ),
    }


def build_recommended_actions(discovered_vhosts: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
    """
    Build a decision-queue-shaped list of recommended next actions
    (context.md §9) for every MEDIUM+ confidence discovered vhost. Never
    executed here — status is always "queued_for_orchestrator".
    """
    actions: List[Dict[str, Any]] = []
    for v in discovered_vhosts:
        if v["confidence"] not in (CONFIDENCE_MEDIUM, CONFIDENCE_HIGH):
            continue

        recommended_modules = list(_SUGGESTED_DOWNSTREAM_MODULES)
        if v["scheme"] == "https":
            recommended_modules.append("ssl_analyzer.py")

        actions.append({
            "action": "vhost_scanner.discovered_vhost_recon",
            "hostname": v["hostname"], "ip": v["ip"], "port": v["port"], "scheme": v["scheme"],
            "recommended_modules": recommended_modules,
            "downstream_target": build_downstream_recon_target(v),
            "justification": (
                f"[REASON: Host header {v['hostname']!r} against {v['ip']}:{v['port']} produced a "
                f"response distinguishable from both baseline probes with {v['confidence']} confidence "
                f"({len(v['evidence'])} converging signal(s)) — this is a newly discovered application "
                f"surface not exposed via primary DNS, per context.md §6's adaptive-discovery loop]"
            ),
            "status": "queued_for_orchestrator",
        })
    return actions


# ---------------------------------------------------------------------------
# 8. Normalization for surface_mapper.py
# ---------------------------------------------------------------------------

def build_vhost_summary(discovered_vhosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize every discovered vhost into the shape surface_mapper.py (not
    yet implemented) is expected to consume — JSON-safe, evidence-carrying,
    and grouped by IP for the "one IP can host multiple distinct
    applications" relationship (module contract responsibility #3).
    """
    by_ip: Dict[str, List[str]] = {}
    for v in discovered_vhosts:
        hostnames = by_ip.setdefault(v["ip"], [])
        if v["hostname"] not in hostnames:
            hostnames.append(v["hostname"])

    return {
        "vhosts": discovered_vhosts,
        "count": len(discovered_vhosts),
        "by_ip": by_ip,
        "downstream_targets": [build_downstream_recon_target(v) for v in discovered_vhosts],
    }


# ---------------------------------------------------------------------------
# Module orchestration (single IP, all configured ports)
# ---------------------------------------------------------------------------

def run_vhost_scan(
    ip: str,
    target: str,
    output_dir: str = "output",
    ports: Optional[List[Tuple[int, str]]] = None,
    extra_hostnames: Optional[List[str]] = None,
    wordlist_name: str = DEFAULT_WORDLIST_NAME,
    wordlists_dir: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_candidates: Optional[int] = None,
    allow_out_of_scope_hostnames: bool = False,
) -> Dict[str, Any]:
    """
    Run Module 9's full virtual-host discovery flow against a single,
    already-discovered IP and persist every completed discovery
    immediately to <output_dir>/pending_assets.json. A failure on one
    port/scheme does not prevent the others from running.
    """
    ip = validate_scan_ip(ip)
    store = PendingAssetsStore(output_dir=output_dir)
    port_list = list(ports) if ports else list(DEFAULT_PORTS)

    summary: Dict[str, Any] = {
        "ip": ip, "target": target, "module": MODULE_NAME, "started_at": _now(),
        "candidate_build": {}, "port_results": [], "vhost_summary": {},
        "recommended_next_actions": [], "errors": [],
    }

    candidate_build = build_candidate_hostnames(
        target, extra_hostnames=extra_hostnames, wordlists_dir=wordlists_dir,
        wordlist_name=wordlist_name, allow_out_of_scope=allow_out_of_scope_hostnames,
    )
    summary["candidate_build"] = candidate_build
    if candidate_build["wordlist_error"]:
        summary["errors"].append({"stage": "wordlist_load", "error": candidate_build["wordlist_error"]})

    all_discovered: List[Dict[str, Any]] = []
    for port, scheme in port_list:
        try:
            port_result = discover_vhosts_for_target(
                ip, port, scheme, target, candidate_build["candidates"], store=store,
                timeout=timeout, max_candidates=max_candidates,
            )
        except Exception as exc:
            summary["errors"].append({"stage": "discover_vhosts", "port": port, "scheme": scheme, "error": str(exc)})
            continue
        summary["port_results"].append(port_result)
        summary["errors"].extend(port_result.get("errors", []))
        all_discovered.extend(port_result.get("discovered_vhosts", []))

    summary["vhost_summary"] = build_vhost_summary(all_discovered)
    summary["recommended_next_actions"] = build_recommended_actions(all_discovered, target)
    summary["status"] = "completed_with_errors" if summary["errors"] else "completed"
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _parse_ports_arg(raw: str) -> List[Tuple[int, str]]:
    ports: List[Tuple[int, str]] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        port_str, _, scheme = entry.partition("/")
        ports.append((int(port_str), scheme or "http"))
    return ports


def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="vhost_scanner.py",
        description="ReconHound Module 9 — virtual-host discovery via Host-header variation (standalone test entry point).",
    )
    parser.add_argument("--ip", required=True, help="Target IP already confirmed in-scope, e.g. 93.184.216.34")
    parser.add_argument("--target", required=True, help="Authorized target domain (used to build in-scope candidate hostnames)")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--ports", default="80/http,443/https", help="Comma-separated port/scheme pairs, e.g. 80/http,8443/https")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST_NAME, help="Wordlist filename under wordlists/")
    parser.add_argument("--extra-hostnames", default=None, help="Comma-separated extra hostnames to test against this IP")
    parser.add_argument("--max-candidates", type=int, default=None, help="Cap the number of candidate hostnames probed")
    parser.add_argument(
        "--allow-out-of-scope-hostnames", action="store_true",
        help="Probe caller-supplied extra hostnames even if they are not a subdomain of --target",
    )
    args = parser.parse_args()

    extra_hostnames = [h.strip() for h in args.extra_hostnames.split(",") if h.strip()] if args.extra_hostnames else None

    try:
        result = run_vhost_scan(
            args.ip, target=args.target, output_dir=args.output_dir,
            ports=_parse_ports_arg(args.ports) or None, extra_hostnames=extra_hostnames,
            wordlist_name=args.wordlist, timeout=args.timeout, max_candidates=args.max_candidates,
            allow_out_of_scope_hostnames=args.allow_out_of_scope_hostnames,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
