"""
reconhound/passive_intel.py — ReconHound Module 2 (passive_intel.py).

Phase: Passive. See context.md §10 (module 2, "External intel DBs") for
the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "External intel DBs. Shodan + Censys integration, historical services,
  exposed infra, hosts/ports/banners/certs. No direct target interaction."

That expands (per the assignment brief) into eight discrete
responsibilities, each implemented below:

  1. Shodan API integration              -> query_shodan_host,
                                             search_shodan_by_hostname
  2. Censys API integration              -> query_censys_host,
                                             search_censys_by_hostname
  3. Historically observed services/     -> normalize_shodan_host,
     infrastructure                         normalize_censys_host
                                             (each service carries its own
                                             observation timestamp)
  4. Known/previously observed hosts     -> load_seed_hosts (DNS-resolved
                                             IPs already on record) PLUS
                                             search_shodan_by_hostname /
                                             search_censys_by_hostname
                                             (hosts the provider has
                                             indexed under the target's
                                             hostname that DNS alone would
                                             not have surfaced)
  5. Previously observed ports           -> the `ports` field of every
                                             normalized/merged host record
  6. Service banners                     -> the `banner` field of every
                                             normalized service record
  7. Certificate intelligence            -> extract_shodan_certificate
     (from Shodan and Censys)               (via normalize_shodan_host),
                                             extract_censys_certificate
                                             (via normalize_censys_host)
  8. Normalize for surface_mapper.py     -> merge_host_records +
                                             persist_host_intel (the
                                             `passive_intel_host` /
                                             `passive_intel_service` /
                                             `passive_intel_certificate`
                                             findings)

Plus shared plumbing: make_finding, PendingAssetsStore, _safe_store_add,
and a single-target orchestrator run_passive_intel (mirroring the
run_passive_recon / run_wayback_intel / run_vuln_intel precedent).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order
position 15, after surface_mapper.py (position 8). Per wayback_intel.py's
and vuln_intel.py's module docstrings, this repository is already
operating under an explicit, user-approved deviation from that order —
surface_mapper.py has not been implemented yet. This module continues
under the same deviation, for the same reason: it is implemented as a
fully standalone producer that does not implement, replace, or depend on
surface_mapper.py's correlation engine, and does not touch any other
unimplemented module (risk_engine.py, core/orchestrator.py, reconhound.py,
tech_fingerprint.py, code_leak.py, osint_engine.py, etc.).

PASSIVE BOUNDARY: this module's only network interactions are with
Shodan's public REST API (api.shodan.io) and Censys's public REST API
(search.censys.io) — third-party intelligence databases that have
already, independently, observed the target's infrastructure at some
point in the past. This module never sends a request to the target
itself: no port scanning, no HTTP requests to target hosts, no DNS
enumeration against the target, no banner grabbing, no service probing.
Even the seed IPs used as Shodan/Censys lookup keys (see
INPUT-CONTRACT DECISION #1 below) are only ever used as query parameters
sent *to Shodan/Censys*, never contacted directly by this module. Every
returned record is therefore a HISTORICAL OBSERVATION made by the
provider's own infrastructure, not a live, current-state confirmation —
callers must not read a passive_intel_* finding as "currently reachable."

CREDENTIAL HANDLING (context.md: "Handle missing credentials ... using
the project's established conventions"): Shodan requires a mandatory API
key (SHODAN_API_KEY env var, or the shodan_api_key parameter); Censys
requires a mandatory API ID + secret pair (CENSYS_API_ID / CENSYS_API_SECRET
env vars, or the censys_api_id/censys_api_secret parameters), sent as HTTP
Basic auth. Unlike vuln_intel.py's NVD/GitHub tokens (which merely raise a
rate-limit ceiling on an otherwise-usable unauthenticated endpoint),
neither Shodan's nor Censys's host-lookup/search endpoints function at
all without credentials. A missing credential is therefore reported as
its own explicit status, "missing_credentials", for that source only —
never raised as an exception, never silently treated as "not_found", and
never allowed to abort the other configured source. Running this module
with zero credentials configured (e.g. during early-development testing)
completes successfully with an empty result set and a `source_status`
that clearly explains why.

NEGATIVE-RESULT MEMORY (context.md §8/§12.6): Shodan and Censys only
index what their own scanners have already observed; the absence of a
record for a given IP is NOT proof that the host doesn't exist or runs no
services — it may simply not have been scanned/indexed yet, or may sit
behind infrastructure those scanners can't reach. Every seed IP checked
against at least one configured source with no resulting record gets an
explicit `passive_intel_checked_no_data` finding (mirroring vuln_intel.py's
`vuln_intel_checked_no_match` precedent) rather than silence, and that
finding's metadata explicitly documents this limitation so no downstream
consumer mistakes "no data" for "confirmed absent."

INPUT-CONTRACT DECISIONS (ambiguities resolved so implementation can
proceed without inventing a competing asset model, mirroring
wayback_intel.py's decision #3 and vuln_intel.py's decision #1 for the
same surface_mapper.py gap):

  1. Seed IPs (the hosts to look up in Shodan/Censys) are read from
     passive_recon.py's already-persisted `dns_record` findings (A/AAAA
     records) in <output_dir>/pending_assets.json — the closest thing this
     repository has to "known current hosts for this target" until
     surface_mapper.py exists. See load_seed_hosts(). A caller-supplied
     `seed_ips` list is also accepted (mirroring wayback_intel.py's
     `current_urls` / vuln_intel.py's `technology_observations` precedent)
     for standalone testing or callers that already know specific IPs.
  2. Discovering hosts NOT already known via DNS (context.md's "known/
     previously observed hosts" responsibility, read as broader than just
     "the IPs we already resolved") is handled by a separate hostname
     search against each provider (Shodan's `hostname:<target>` query
     filter, Censys's `dns.names: <target>` query), scoped exactly to the
     target hostname — never a broader/unscoped query.
  3. Every normalized host/service/certificate record is tagged with
     `discovered_via` ("seed_ip_lookup" or "hostname_search") and, for
     hostnames present on the record, `in_scope_hostnames`
     (context.md §9/§12.10: strict target-scope enforcement). A record is
     considered in-scope if it carries an in-scope hostname, OR it was
     found via a DNS-resolved seed IP, OR it was found via a
     target-scoped hostname search — all three are legitimate,
     scope-respecting discovery paths.
  4. Shodan/Censys API response shapes below reflect each provider's
     public documentation as of this implementation (Shodan's
     /shodan/host/{ip} `data[]` entries with a `ssl.cert` block; Censys
     v2's /hosts/{ip} `services[]` entries with `software[]` and
     `certificate`). Every parser is deliberately defensive (`.get()`
     with fallbacks, try/except around each entry) so an unexpected or
     evolving field layout degrades a single record, never the whole run.
     Where Censys returns only a certificate fingerprint reference
     (rather than full parsed certificate data — full detail requires a
     separate /api/v2/certificates lookup, out of this module's scope),
     that is recorded explicitly via a `note` field rather than silently
     treated as "no certificate."

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). Output is
intended to feed surface_mapper.py (module 6, not yet implemented) — this
module does not implement or call into surface_mapper, active_recon,
tech_fingerprint, vhost_scanner, api_recon, js_analyzer, supply_chain,
http_analyzer, ssl_analyzer, screenshot, vuln_intel, risk_engine,
report_generator, orchestrator, or any other module not already
implemented.

DISCOVERY != CONFIRMED CURRENT STATE: every record here is a historical
observation made by a third-party intelligence provider. None of this
module's output should be read as "currently live," "currently
vulnerable," or "exploitable" — that assessment belongs to active modules
and/or vuln_intel.py / risk_engine.py.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import requests

MODULE_NAME = "passive_intel.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-PassiveIntel/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 15.0

SHODAN_API_KEY_ENV = "SHODAN_API_KEY"
CENSYS_API_ID_ENV = "CENSYS_API_ID"
CENSYS_API_SECRET_ENV = "CENSYS_API_SECRET"

# Shodan returns at most 100 matches per search page and bills one query
# credit per page requested.
SHODAN_PAGE_SIZE = 100

SHODAN_HOST_API_BASE = "https://api.shodan.io/shodan/host"
SHODAN_SEARCH_API_BASE = "https://api.shodan.io/shodan/host/search"
CENSYS_HOST_API_BASE = "https://search.censys.io/api/v2/hosts"
CENSYS_SEARCH_API_BASE = "https://search.censys.io/api/v2/hosts/search"

# Finding types already written to pending_assets.json by
# already-implemented modules that carry DNS-resolved IPs — the closest
# thing this repository has to "known current hosts" until
# surface_mapper.py exists (module docstring, input-contract decision #1).
_SEED_HOST_FINDING_TYPE = "dns_record"
_SEED_HOST_RECORD_TYPES = ("A", "AAAA")

# ---------------------------------------------------------------------------
# Per-IP check outcomes (context.md §8 negative-result memory)
#
# Only an authoritative provider answer ("we have no record for this IP",
# HTTP 404) is a negative RESULT. A refused, throttled, unpaid, or timed-out
# request produced no answer at all, and a record we received but could not
# parse is evidence that data EXISTS. Collapsing any of those into "checked
# and not found" writes a false negative into negative-result memory, which
# other modules then trust to skip re-checking.
# ---------------------------------------------------------------------------

# Provider statuses that constitute an authoritative "no record for this IP".
_AUTHORITATIVE_ABSENT_STATUSES = frozenset({"not_found"})

# Provider statuses meaning "no answer was obtained" — never a negative result.
_PROVIDER_UNAVAILABLE_STATUSES = frozenset({
    "error", "rate_limited", "unauthorized", "forbidden",
    "insufficient_credits", "missing_credentials",
})

# The provider returned a record, but this module could not normalize it.
# Evidence that data exists, so the opposite of an absence result.
CHECK_UNPARSABLE = "unparsable_response"


class ScopeError(ValueError):
    """Raised when a target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors passive_recon.py's validate_target/is_in_scope;
# duplicated per modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_target(target: str) -> str:
    """
    Validate that `target` is a syntactically valid, explicit domain name.

    passive_intel operates on exactly one explicit target domain per
    invocation and never expands to unrelated hosts. Raises ScopeError on
    anything that is not a plausible bare domain name (URLs, IPs,
    wildcards, empty input).
    """
    if not isinstance(target, str) or not target.strip():
        raise ScopeError("Target must be a non-empty domain string.")

    candidate = target.strip().rstrip(".").lower()

    if "://" in candidate or "/" in candidate:
        raise ScopeError(f"Target must be a bare domain name, not a URL/path: {target!r}")

    is_ip_literal = True
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        is_ip_literal = False
    if is_ip_literal:
        raise ScopeError(f"Target must be a domain name, not a raw IP address: {target!r}")

    if "*" in candidate:
        raise ScopeError(f"Wildcard targets are not permitted: {target!r}")

    if not _DOMAIN_RE.match(candidate):
        raise ScopeError(f"Target is not a syntactically valid domain: {target!r}")

    return candidate


def is_in_scope(hostname: str, target: str) -> bool:
    """True if `hostname` is the target itself or a subdomain of it."""
    hostname = (hostname or "").strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    if not hostname:
        return False
    return hostname == target or hostname.endswith("." + target)


def _valid_ip(value: Any) -> Optional[str]:
    """Return a normalized IP string if `value` is a valid IPv4/IPv6 literal, else None."""
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors every other implemented module's model;
# kept local per modular independence)
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
# Seed host discovery (module docstring, input-contract decision #1)
# ---------------------------------------------------------------------------

def load_seed_hosts(store: Optional[PendingAssetsStore], target: str, extra_ips: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Build the set of IPs to look up in Shodan/Censys from passive_recon.py's
    already-persisted `dns_record` findings (A/AAAA) for this target, plus
    any caller-supplied `extra_ips`. Never contacts the target itself —
    this only reads already-persisted, already-passively-obtained data.
    """
    ips: Set[str] = set()

    if store is not None:
        try:
            records = store.all()
        except PersistenceError:
            records = []
        for rec in records:
            if not isinstance(rec, dict) or rec.get("type") != _SEED_HOST_FINDING_TYPE:
                continue
            if rec.get("target") and rec["target"] != target:
                continue
            value = rec.get("value") or {}
            if not isinstance(value, dict) or value.get("record_type") not in _SEED_HOST_RECORD_TYPES:
                continue
            for addr in value.get("records") or []:
                normalized = _valid_ip(addr)
                if normalized:
                    ips.add(normalized)

    for addr in extra_ips or []:
        normalized = _valid_ip(addr)
        if normalized:
            ips.add(normalized)

    return {"ips": sorted(ips)}


# ---------------------------------------------------------------------------
# 1. Shodan API integration
# ---------------------------------------------------------------------------

def query_shodan_host(
    ip: str,
    api_key: Optional[str],
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = SHODAN_HOST_API_BASE,
) -> Dict[str, Any]:
    """
    Look up a single IP's historically observed Shodan host record via
    GET /shodan/host/{ip}. This module's only network interaction is with
    Shodan's public API — never the target itself (passive boundary, see
    module docstring).

    Returns {"status": "found"|"not_found"|"missing_credentials"|
             "unauthorized"|"rate_limited"|"error", "host": dict|None,
             "error": str|None}.
    """
    result: Dict[str, Any] = {"status": "error", "host": None, "error": None}

    normalized_ip = _valid_ip(ip)
    if normalized_ip is None:
        result["error"] = f"not a valid IP address: {ip!r}"
        return result

    if not api_key:
        result["status"] = "missing_credentials"
        result["error"] = f"Shodan API key not configured (set {SHODAN_API_KEY_ENV} or pass api_key)"
        return result

    resp = None
    try:
        resp = requests.get(
            f"{base_url}/{normalized_ip}",
            params={"key": api_key},
            timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        return result
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request failed: {exc}"
        return result
    finally:
        if resp is not None:
            resp.close()

    if resp.status_code == 404:
        result["status"] = "not_found"
        return result
    if resp.status_code == 401:
        result["status"] = "unauthorized"
        result["error"] = "Shodan API rejected the configured API key (HTTP 401)"
        return result
    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["error"] = "HTTP 429 Too Many Requests from Shodan API"
        return result
    if resp.status_code >= 500:
        result["error"] = f"Shodan API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"Shodan API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from Shodan API: {exc}"
        return result

    if not isinstance(data, dict):
        result["error"] = "unexpected Shodan API response structure (not a JSON object)"
        return result

    result["status"] = "found"
    result["host"] = data
    return result


def search_shodan_by_hostname(
    hostname: str,
    api_key: Optional[str],
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = SHODAN_SEARCH_API_BASE,
    extra_query: Optional[str] = None,
    max_pages: int = 1,
) -> Dict[str, Any]:
    """
    Search Shodan for hosts it has indexed under `hostname` via
    GET /shodan/host/search?query=hostname:<hostname>, scoped exactly to
    the target hostname (module docstring, input-contract decision #2).
    Shodan search consumes query credits; a 402 is reported distinctly as
    "insufficient_credits" rather than a generic error.

    PAGINATION: Shodan returns 100 matches per page and reports the full
    result count in `total`. `max_pages` defaults to 1, which preserves this
    module's original single-request behaviour and its exact query-credit
    cost (Shodan bills one credit per page); raise it deliberately to fetch
    more. `truncated` says whether results were left behind, so a caller can
    never mistake a first page for the complete result set. If a later page
    fails, every match already retrieved is kept and the failure is reported
    in `page_error` rather than discarding good data.

    Returns {"status": "found"|"not_found"|"missing_credentials"|
             "unauthorized"|"insufficient_credits"|"rate_limited"|"error",
             "matches": [...], "total": int, "retrieved": int,
             "truncated": bool, "pages_fetched": int,
             "page_error": str|None, "error": str|None}.

    NOTE: `total` is the provider's count for the whole result set; use
    `retrieved` for how many records this call actually returned.
    """
    result: Dict[str, Any] = {
        "status": "error", "matches": [], "total": 0, "retrieved": 0,
        "truncated": False, "pages_fetched": 0, "page_error": None, "error": None,
    }

    if not hostname or not hostname.strip():
        result["error"] = "hostname is required"
        return result

    if not api_key:
        result["status"] = "missing_credentials"
        result["error"] = f"Shodan API key not configured (set {SHODAN_API_KEY_ENV} or pass api_key)"
        return result

    query = f"hostname:{hostname.strip()}"
    if extra_query:
        query = f"{query} {extra_query}"

    matches: List[Any] = []
    provider_total: Optional[int] = None
    # Shodan has no end-of-results cursor, so a full final page is the only
    # completeness hint available when `total` is missing or not an integer.
    last_page_was_full = False
    page_limit = max(1, int(max_pages))

    for page in range(1, page_limit + 1):
        params: Dict[str, Any] = {"key": api_key, "query": query}
        if page > 1:
            params["page"] = page

        page_result = _shodan_search_page(base_url, params, timeout)

        if page_result["error_status"] is not None:
            if page == 1:
                result["status"] = page_result["error_status"]
                result["error"] = page_result["error"]
                return result
            # A later page failed. Everything already retrieved is real data
            # and is kept; only the completeness claim changes.
            result["page_error"] = f"page {page}: {page_result['error']}"
            result["truncated"] = True
            break

        page_matches = page_result["matches"]
        if provider_total is None:
            provider_total = page_result["total"]
        matches.extend(page_matches)
        result["pages_fetched"] = page
        last_page_was_full = len(page_matches) >= SHODAN_PAGE_SIZE

        if not page_matches or len(page_matches) < SHODAN_PAGE_SIZE:
            break  # short page means the result set is exhausted

    result["matches"] = matches
    result["retrieved"] = len(matches)
    total_known = isinstance(provider_total, int)
    result["total"] = provider_total if total_known else len(matches)

    if total_known:
        # Shodan reported the size of the whole result set: it governs.
        if result["total"] > len(matches):
            result["truncated"] = True
    elif last_page_was_full:
        # No usable `total`, and the last page came back full. Completeness is
        # unknown, and `truncated=False` would assert that nothing was left
        # behind — the exact claim this flag exists to prevent a caller from
        # making. A short final page is still treated as exhaustion, so this
        # never fires merely because a page size was reached mid-stream.
        result["truncated"] = True
        if result["page_error"] is None:
            result["page_error"] = (
                "Shodan returned no usable 'total'; the final page was full, so "
                "whether more results exist could not be determined"
            )
    result["status"] = "found" if matches else "not_found"
    return result


def _shodan_search_page(base_url: str, params: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    """
    Fetch and validate one Shodan search page.

    Returns {"matches": [...], "total": int|None, "error_status": str|None,
    "error": str|None}. `error_status` is None on success; otherwise it is the
    status the caller should surface for a first-page failure.
    """
    out: Dict[str, Any] = {"matches": [], "total": None, "error_status": None, "error": None}

    resp = None
    try:
        resp = requests.get(
            base_url, params=params, timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
    except requests.exceptions.Timeout:
        out["error_status"], out["error"] = "error", "timeout"
        return out
    except requests.exceptions.ConnectionError as exc:
        out["error_status"], out["error"] = "error", f"connection error: {exc}"
        return out
    except requests.exceptions.RequestException as exc:
        out["error_status"], out["error"] = "error", f"request failed: {exc}"
        return out
    finally:
        if resp is not None:
            resp.close()

    if resp.status_code == 401:
        out["error_status"] = "unauthorized"
        out["error"] = "Shodan API rejected the configured API key (HTTP 401)"
        return out
    if resp.status_code == 402:
        out["error_status"] = "insufficient_credits"
        out["error"] = "Shodan search requires query credits (HTTP 402 Payment Required)"
        return out
    if resp.status_code == 429:
        out["error_status"] = "rate_limited"
        out["error"] = "HTTP 429 Too Many Requests from Shodan API"
        return out
    if resp.status_code >= 500:
        out["error_status"] = "error"
        out["error"] = f"Shodan API returned HTTP {resp.status_code}"
        return out
    if resp.status_code != 200:
        out["error_status"] = "error"
        out["error"] = f"Shodan API returned unexpected HTTP {resp.status_code}"
        return out

    try:
        data = resp.json()
    except ValueError as exc:
        out["error_status"] = "error"
        out["error"] = f"malformed JSON from Shodan API: {exc}"
        return out

    if not isinstance(data, dict) or "matches" not in data:
        out["error_status"] = "error"
        out["error"] = "unexpected Shodan search API response structure"
        return out

    page_matches = data.get("matches")
    if not isinstance(page_matches, list):
        out["error_status"] = "error"
        out["error"] = "unexpected Shodan search API response structure (matches is not a list)"
        return out

    out["matches"] = page_matches
    out["total"] = data.get("total") if isinstance(data.get("total"), int) else None
    return out


# ---------------------------------------------------------------------------
# 2. Censys API integration
# ---------------------------------------------------------------------------

def query_censys_host(
    ip: str,
    api_id: Optional[str],
    api_secret: Optional[str],
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = CENSYS_HOST_API_BASE,
) -> Dict[str, Any]:
    """
    Look up a single IP's historically observed Censys host record via
    GET /api/v2/hosts/{ip} (HTTP Basic auth). This module's only network
    interaction is with Censys's public API — never the target itself.

    Returns {"status": "found"|"not_found"|"missing_credentials"|
             "unauthorized"|"forbidden"|"rate_limited"|"error",
             "host": dict|None, "error": str|None}.
    """
    result: Dict[str, Any] = {"status": "error", "host": None, "error": None}

    normalized_ip = _valid_ip(ip)
    if normalized_ip is None:
        result["error"] = f"not a valid IP address: {ip!r}"
        return result

    if not api_id or not api_secret:
        result["status"] = "missing_credentials"
        result["error"] = (
            f"Censys API credentials not configured (set {CENSYS_API_ID_ENV} and "
            f"{CENSYS_API_SECRET_ENV}, or pass api_id/api_secret)"
        )
        return result

    resp = None
    try:
        resp = requests.get(
            f"{base_url}/{normalized_ip}",
            auth=(api_id, api_secret),
            timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
        )
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        return result
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request failed: {exc}"
        return result
    finally:
        if resp is not None:
            resp.close()

    if resp.status_code == 404:
        result["status"] = "not_found"
        return result
    if resp.status_code == 401:
        result["status"] = "unauthorized"
        result["error"] = "Censys API rejected the configured credentials (HTTP 401)"
        return result
    if resp.status_code == 403:
        result["status"] = "forbidden"
        result["error"] = "Censys API returned HTTP 403 (quota exhausted or insufficient permissions)"
        return result
    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["error"] = "HTTP 429 Too Many Requests from Censys API"
        return result
    if resp.status_code >= 500:
        result["error"] = f"Censys API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"Censys API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from Censys API: {exc}"
        return result

    if not isinstance(data, dict):
        result["error"] = "unexpected Censys API response structure (not a JSON object)"
        return result

    host = data.get("result") if isinstance(data.get("result"), dict) else data
    if not isinstance(host, dict) or not host.get("ip"):
        result["error"] = "unexpected Censys API response structure (missing result/ip)"
        return result

    result["status"] = "found"
    result["host"] = host
    return result


def search_censys_by_hostname(
    hostname: str,
    api_id: Optional[str],
    api_secret: Optional[str],
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = CENSYS_SEARCH_API_BASE,
    query: Optional[str] = None,
    per_page: int = 50,
    max_pages: int = 1,
) -> Dict[str, Any]:
    """
    Search Censys for hosts it has indexed under `hostname` via
    GET /api/v2/hosts/search?q=dns.names:<hostname>, scoped exactly to the
    target hostname (module docstring, input-contract decision #2).

    PAGINATION: Censys v2 pages via an opaque cursor at
    `result.links.next`. `max_pages` defaults to 1, preserving this module's
    original single-request behaviour and per-run quota cost; raise it
    deliberately to follow the cursor further. `truncated` reports whether
    more results remained. A failure on a later page keeps every hit already
    retrieved and is reported via `page_error` instead of discarding it.

    Returns {"status": "found"|"not_found"|"missing_credentials"|
             "unauthorized"|"forbidden"|"rate_limited"|"error",
             "hits": [...], "total": int, "retrieved": int,
             "truncated": bool, "pages_fetched": int,
             "page_error": str|None, "error": str|None}.

    NOTE: `total` is Censys's count for the whole result set; use `retrieved`
    for how many records this call actually returned.
    """
    result: Dict[str, Any] = {
        "status": "error", "hits": [], "total": 0, "retrieved": 0,
        "truncated": False, "pages_fetched": 0, "page_error": None, "error": None,
    }

    if not hostname or not hostname.strip():
        result["error"] = "hostname is required"
        return result

    if not api_id or not api_secret:
        result["status"] = "missing_credentials"
        result["error"] = (
            f"Censys API credentials not configured (set {CENSYS_API_ID_ENV} and "
            f"{CENSYS_API_SECRET_ENV}, or pass api_id/api_secret)"
        )
        return result

    resolved_query = query or f"dns.names: {hostname.strip()}"
    resolved_per_page = max(1, min(per_page, 100))

    hits: List[Any] = []
    provider_total: Optional[int] = None
    cursor: Optional[str] = None
    # Guards against a provider that returns the same cursor repeatedly, which
    # would otherwise replay one page into duplicate observations and inflate
    # every downstream service/certificate count.
    seen_cursors: Set[str] = set()
    page_limit = max(1, int(max_pages))

    for page in range(1, page_limit + 1):
        params: Dict[str, Any] = {"q": resolved_query, "per_page": resolved_per_page}
        if cursor:
            params["cursor"] = cursor

        page_result = _censys_search_page(base_url, params, (api_id, api_secret), timeout)

        if page_result["error_status"] is not None:
            if page == 1:
                result["status"] = page_result["error_status"]
                result["error"] = page_result["error"]
                return result
            result["page_error"] = f"page {page}: {page_result['error']}"
            result["truncated"] = True
            break

        if provider_total is None:
            provider_total = page_result["total"]
        hits.extend(page_result["hits"])
        result["pages_fetched"] = page

        cursor = page_result["next_cursor"]
        if not cursor:
            break  # no further cursor means the result set is exhausted
        if cursor in seen_cursors:
            result["page_error"] = (
                f"page {page}: Censys repeated a previously seen pagination cursor; "
                f"stopped to avoid duplicating results"
            )
            result["truncated"] = True
            cursor = None
            break
        seen_cursors.add(cursor)
    else:
        # Ran out of allowed pages while Censys still offered a next cursor.
        if cursor:
            result["truncated"] = True

    result["hits"] = hits
    result["retrieved"] = len(hits)
    result["total"] = provider_total if isinstance(provider_total, int) else len(hits)
    if result["total"] > len(hits):
        result["truncated"] = True
    result["status"] = "found" if hits else "not_found"
    return result


def _censys_search_page(base_url: str, params: Dict[str, Any], auth, timeout: float) -> Dict[str, Any]:
    """
    Fetch and validate one Censys search page.

    Returns {"hits": [...], "total": int|None, "next_cursor": str|None,
    "error_status": str|None, "error": str|None}.
    """
    out: Dict[str, Any] = {
        "hits": [], "total": None, "next_cursor": None, "error_status": None, "error": None,
    }

    resp = None
    try:
        resp = requests.get(
            base_url, params=params, auth=auth, timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
        )
    except requests.exceptions.Timeout:
        out["error_status"], out["error"] = "error", "timeout"
        return out
    except requests.exceptions.ConnectionError as exc:
        out["error_status"], out["error"] = "error", f"connection error: {exc}"
        return out
    except requests.exceptions.RequestException as exc:
        out["error_status"], out["error"] = "error", f"request failed: {exc}"
        return out
    finally:
        if resp is not None:
            resp.close()

    if resp.status_code == 401:
        out["error_status"] = "unauthorized"
        out["error"] = "Censys API rejected the configured credentials (HTTP 401)"
        return out
    if resp.status_code == 403:
        out["error_status"] = "forbidden"
        out["error"] = "Censys API returned HTTP 403 (quota exhausted or insufficient permissions)"
        return out
    if resp.status_code == 429:
        out["error_status"] = "rate_limited"
        out["error"] = "HTTP 429 Too Many Requests from Censys API"
        return out
    if resp.status_code >= 500:
        out["error_status"] = "error"
        out["error"] = f"Censys API returned HTTP {resp.status_code}"
        return out
    if resp.status_code != 200:
        out["error_status"] = "error"
        out["error"] = f"Censys API returned unexpected HTTP {resp.status_code}"
        return out

    try:
        data = resp.json()
    except ValueError as exc:
        out["error_status"] = "error"
        out["error"] = f"malformed JSON from Censys API: {exc}"
        return out

    if not isinstance(data, dict):
        out["error_status"] = "error"
        out["error"] = "unexpected Censys search API response structure"
        return out

    outer = data.get("result") if isinstance(data.get("result"), dict) else data
    page_hits = outer.get("hits")
    if not isinstance(page_hits, list):
        out["error_status"] = "error"
        out["error"] = "unexpected Censys search API response structure (hits is not a list)"
        return out

    out["hits"] = page_hits
    total = outer.get("total")
    out["total"] = total if isinstance(total, int) else None

    links = outer.get("links") if isinstance(outer.get("links"), dict) else {}
    next_cursor = links.get("next")
    out["next_cursor"] = next_cursor if isinstance(next_cursor, str) and next_cursor else None
    return out


# ---------------------------------------------------------------------------
# 3/5/6/7. Normalization: historical services, ports, banners, certificates
# ---------------------------------------------------------------------------

def extract_shodan_certificate(service_entry: Dict[str, Any], port: Any, source_ip: str) -> Optional[Dict[str, Any]]:
    """Extract certificate intelligence from one Shodan `data[]` entry's `ssl.cert` block, if present."""
    ssl_block = service_entry.get("ssl")
    if not isinstance(ssl_block, dict):
        return None
    cert = ssl_block.get("cert")
    if not isinstance(cert, dict):
        return None

    subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
    issuer = cert.get("issuer") if isinstance(cert.get("issuer"), dict) else {}
    fingerprint = cert.get("fingerprint") if isinstance(cert.get("fingerprint"), dict) else {}

    return {
        "port": port,
        "subject_cn": subject.get("CN"),
        "issuer_cn": issuer.get("CN"),
        "serial": cert.get("serial"),
        "expires": cert.get("expires"),
        # Shodan's own expiry verdict AT THE TIME IT SCANNED, not now. Kept as
        # provider-reported evidence alongside `observed_at` so downstream can
        # re-evaluate against the current date rather than trusting a stale
        # boolean (context.md §8: preserve the observation, not a conclusion).
        "expired": cert.get("expired"),
        "expired_evaluated_by": "shodan_at_observation_time",
        # When the provider observed this certificate. Without it a historical
        # certificate is indistinguishable from a current one.
        "observed_at": service_entry.get("timestamp"),
        "fingerprint_sha256": fingerprint.get("sha256"),
        "fingerprint_sha1": fingerprint.get("sha1"),
        "sig_alg": cert.get("sig_alg"),
        "cert_version": cert.get("version"),
        "source": "shodan",
        "source_ip": source_ip,
    }


def normalize_shodan_host(raw: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
    """
    Normalize one raw Shodan /shodan/host/{ip} response (or a host-like
    wrapper built from a single /shodan/host/search match, see
    normalize_shodan_search_match) into the common host schema shared with
    Censys (see merge_host_records).

    Returns None (never raises) when `raw` has no usable `ip_str` — a
    malformed/unexpected record is skipped, not fatal to the whole run.
    """
    if not isinstance(raw, dict):
        return None
    ip = _valid_ip(raw.get("ip_str"))
    if ip is None:
        return None

    hostnames = {h for h in (raw.get("hostnames") or []) if isinstance(h, str) and h}
    hostnames |= {d for d in (raw.get("domains") or []) if isinstance(d, str) and d}

    services: List[Dict[str, Any]] = []
    certificates: List[Dict[str, Any]] = []
    ports_seen: Set[int] = set()

    for entry in raw.get("data") or []:
        if not isinstance(entry, dict):
            continue
        try:
            port = entry.get("port")
            if isinstance(port, int):
                ports_seen.add(port)
            services.append({
                "port": port,
                "transport": entry.get("transport"),
                "service_name": (entry.get("_shodan") or {}).get("module") if isinstance(entry.get("_shodan"), dict) else None,
                "product": entry.get("product"),
                "version": entry.get("version"),
                "banner": entry.get("data"),
                "timestamp": entry.get("timestamp"),
                "hostnames": [h for h in (entry.get("hostnames") or []) if isinstance(h, str)],
                "source": "shodan",
            })
            cert = extract_shodan_certificate(entry, port, ip)
            if cert:
                certificates.append(cert)
        except Exception:
            continue  # one malformed service entry must not abort the rest

    if not ports_seen:
        ports_seen = {p for p in (raw.get("ports") or []) if isinstance(p, int)}

    location = raw.get("location") if isinstance(raw.get("location"), dict) else {}

    return {
        "ip": ip,
        "hostnames": sorted(hostnames),
        "ports": sorted(ports_seen),
        "services": services,
        "certificates": certificates,
        "org": raw.get("org"),
        "isp": raw.get("isp"),
        "asn": raw.get("asn"),
        "country": location.get("country_name"),
        "city": location.get("city"),
        "last_observed_at": raw.get("last_update"),
        "source": "shodan",
    }


def normalize_shodan_search_match(match: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
    """
    Normalize one /shodan/host/search `matches[]` entry. A search match is
    shaped like a single Shodan `data[]` entry plus a handful of
    host-level fields, so it is wrapped into the same host-like shape
    normalize_shodan_host() already knows how to parse, avoiding a
    duplicate implementation.
    """
    if not isinstance(match, dict):
        return None
    ip = _valid_ip(match.get("ip_str"))
    if ip is None:
        return None

    host_like = {
        "ip_str": ip,
        "hostnames": match.get("hostnames") or [],
        "domains": match.get("domains") or [],
        "org": match.get("org"),
        "isp": match.get("isp"),
        "asn": match.get("asn"),
        "location": match.get("location") or {},
        "last_update": match.get("timestamp"),
        "ports": [match.get("port")] if isinstance(match.get("port"), int) else [],
        "data": [match],
    }
    return normalize_shodan_host(host_like, target)


def extract_censys_certificate(service_entry: Dict[str, Any], source_ip: str) -> Optional[Dict[str, Any]]:
    """
    Extract certificate intelligence from one Censys `services[]` entry's
    `certificate` field. Censys v2 host responses may return either a full
    parsed certificate object or (commonly, by default) just the
    certificate's SHA-256 fingerprint string (see module docstring,
    input-contract decision #4) — both shapes are handled.
    """
    cert = service_entry.get("certificate")
    port = service_entry.get("port")

    if isinstance(cert, dict):
        subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
        issuer = cert.get("issuer") if isinstance(cert.get("issuer"), dict) else {}
        sans = cert.get("names")
        if not isinstance(sans, list):
            san_block = cert.get("subject_alt_name") if isinstance(cert.get("subject_alt_name"), dict) else {}
            sans = san_block.get("dns_names") if isinstance(san_block.get("dns_names"), list) else []
        validity = cert.get("validity_period") if isinstance(cert.get("validity_period"), dict) else {}
        return {
            "port": port,
            "subject_cn": subject.get("common_name") or subject.get("CN"),
            "issuer_cn": issuer.get("common_name") or issuer.get("CN"),
            "sans": [s for s in sans if isinstance(s, str)],
            "fingerprint_sha256": cert.get("fingerprint_sha256") or cert.get("fingerprint"),
            "not_before": validity.get("not_before") or cert.get("not_before"),
            "not_after": validity.get("not_after") or cert.get("not_after"),
            "observed_at": service_entry.get("observed_at"),
            "source": "censys",
            "source_ip": source_ip,
        }

    if isinstance(cert, str) and cert:
        return {
            "port": port,
            "subject_cn": None,
            "issuer_cn": None,
            "sans": [],
            "fingerprint_sha256": cert,
            "not_before": None,
            "not_after": None,
            "observed_at": service_entry.get("observed_at"),
            "note": (
                "Censys returned only a certificate fingerprint reference; full "
                "certificate detail was not expanded (out of this module's scope)."
            ),
            "source": "censys",
            "source_ip": source_ip,
        }

    return None


def normalize_censys_host(raw: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
    """
    Normalize one raw Censys /api/v2/hosts/{ip} `result` object, or one
    /api/v2/hosts/search `hits[]` entry (both share the same nested field
    names in Censys v2 — see module docstring, input-contract decision #4)
    into the common host schema shared with Shodan.

    Returns None (never raises) when `raw` has no usable `ip`.
    """
    if not isinstance(raw, dict):
        return None
    ip = _valid_ip(raw.get("ip"))
    if ip is None:
        return None

    hostnames: Set[str] = set()
    dns_block = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
    for name in dns_block.get("names") or []:
        if isinstance(name, str):
            hostnames.add(name)
    reverse_dns = dns_block.get("reverse_dns") if isinstance(dns_block.get("reverse_dns"), dict) else {}
    for name in reverse_dns.get("names") or []:
        if isinstance(name, str):
            hostnames.add(name)

    services: List[Dict[str, Any]] = []
    certificates: List[Dict[str, Any]] = []
    ports_seen: Set[int] = set()

    for entry in raw.get("services") or []:
        if not isinstance(entry, dict):
            continue
        try:
            port = entry.get("port")
            if isinstance(port, int):
                ports_seen.add(port)

            product, version = None, None
            software_list = entry.get("software")
            if isinstance(software_list, list) and software_list:
                first_sw = software_list[0] if isinstance(software_list[0], dict) else {}
                product = first_sw.get("product")
                version = first_sw.get("version")

            services.append({
                "port": port,
                "transport": entry.get("transport_protocol"),
                "service_name": entry.get("service_name"),
                "product": product,
                "version": version,
                "banner": entry.get("banner"),
                "timestamp": entry.get("observed_at") or raw.get("last_updated_at"),
                "hostnames": [],
                "source": "censys",
            })

            cert = extract_censys_certificate(entry, ip)
            if cert:
                certificates.append(cert)
        except Exception:
            continue  # one malformed service entry must not abort the rest

    asn_block = raw.get("autonomous_system") if isinstance(raw.get("autonomous_system"), dict) else {}
    location_block = raw.get("location") if isinstance(raw.get("location"), dict) else {}

    return {
        "ip": ip,
        "hostnames": sorted(hostnames),
        "ports": sorted(ports_seen),
        "services": services,
        "certificates": certificates,
        "org": asn_block.get("name") or asn_block.get("description"),
        "isp": None,
        "asn": asn_block.get("asn"),
        "country": location_block.get("country"),
        "city": location_block.get("city"),
        "last_observed_at": raw.get("last_updated_at"),
        "source": "censys",
    }


# ---------------------------------------------------------------------------
# 8. Normalize for surface_mapper.py: merge + persist
# ---------------------------------------------------------------------------

def merge_host_records(records: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
    """
    Merge normalized Shodan/Censys host records by IP into one record per
    host. Independent discoveries describing the same underlying asset
    must be merged, not duplicated (context.md §7). When multiple sources
    converge on the same host, that is a converging signal that raises
    confidence from MEDIUM to HIGH (context.md §8).

    Each input record must additionally carry a `discovered_via` key
    ("seed_ip_lookup" or "hostname_search") set by the caller before
    merging (see run_passive_intel).
    """
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    for rec in records:
        if not rec or not rec.get("ip"):
            continue
        ip = rec["ip"]
        if ip not in merged:
            merged[ip] = {
                "ip": ip,
                "hostnames": set(),
                "ports": set(),
                "services": [],
                "certificates": [],
                "org": None, "isp": None, "asn": None, "country": None, "city": None,
                "last_observed_at": None,
                "sources": set(),
                "discovered_via": set(),
            }
            order.append(ip)
        m = merged[ip]
        m["hostnames"].update(h for h in rec.get("hostnames") or [] if isinstance(h, str))
        m["ports"].update(p for p in rec.get("ports") or [] if isinstance(p, int))
        m["services"].extend(rec.get("services") or [])
        m["certificates"].extend(rec.get("certificates") or [])
        if rec.get("source"):
            m["sources"].add(rec["source"])
        if rec.get("discovered_via"):
            m["discovered_via"].add(rec["discovered_via"])
        for field in ("org", "isp", "asn", "country", "city"):
            if not m[field] and rec.get(field):
                m[field] = rec[field]
        last = rec.get("last_observed_at")
        if last and (m["last_observed_at"] is None or str(last) > str(m["last_observed_at"])):
            m["last_observed_at"] = last

    results: List[Dict[str, Any]] = []
    for ip in order:
        m = merged[ip]
        all_hostnames = sorted(m["hostnames"])
        in_scope_hostnames = sorted(h for h in all_hostnames if is_in_scope(h, target))
        out_of_scope_hostnames = [h for h in all_hostnames if h not in set(in_scope_hostnames)]

        # An IP is attributable to the target when the target's own DNS
        # resolved to it, or when the provider record actually carries an
        # in-scope hostname.
        #
        # Discovery via hostname search is NOT on its own sufficient: Shodan's
        # `hostname:` filter is a substring match, so a search for
        # "example.com" can return "notexample.com". Treating the search path
        # itself as proof of scope marked every such host in-scope with zero
        # in-scope hostnames — manufacturing an ownership claim from a
        # provider's fuzzy match. The record is still kept in full; only the
        # unsupported attribution claim is withdrawn.
        dns_attested = "seed_ip_lookup" in m["discovered_via"]
        in_scope = bool(in_scope_hostnames) or dns_attested

        if dns_attested:
            basis = "dns_resolved_seed_ip"
        elif in_scope_hostnames:
            basis = "in_scope_hostname_on_record"
        else:
            basis = "provider_hostname_match_only"

        attribution = {
            "basis": basis,
            "dns_attested": dns_attested,
            "hostname_count": len(all_hostnames),
            "in_scope_hostname_count": len(in_scope_hostnames),
            "out_of_scope_hostname_count": len(out_of_scope_hostnames),
            "note": (
                "External providers index infrastructure, not ownership. An IP "
                "carrying hostnames for unrelated organizations is shared/CDN/"
                "multi-tenant infrastructure; out_of_scope_hostname_count is "
                "reported raw so downstream correlation decides attribution."
            ),
        }

        multi_source = len(m["sources"]) > 1
        results.append({
            "ip": m["ip"],
            "hostnames": all_hostnames,
            "in_scope_hostnames": in_scope_hostnames,
            "out_of_scope_hostnames": out_of_scope_hostnames,
            "in_scope": in_scope,
            "attribution": attribution,
            "ports": sorted(m["ports"]),
            "services": m["services"],
            "certificates": m["certificates"],
            "org": m["org"], "isp": m["isp"], "asn": m["asn"],
            "country": m["country"], "city": m["city"],
            "last_observed_at": m["last_observed_at"],
            "sources": sorted(m["sources"]),
            "discovered_via": sorted(m["discovered_via"]),
            # Two providers converging raises confidence in the OBSERVATION
            # (context.md §8) — but only once the host is actually attributable
            # to the target. Corroborating an observation about someone else's
            # host does not make it more likely to be the target's.
            "confidence": CONFIDENCE_HIGH if (multi_source and in_scope) else CONFIDENCE_MEDIUM,
        })
    return sorted(results, key=lambda r: r["ip"])


def persist_host_intel(merged_records: List[Dict[str, Any]], target: str, store: Optional[PendingAssetsStore]) -> List[str]:
    """Persist one `passive_intel_host` finding per host, plus one `passive_intel_service`/`passive_intel_certificate` per observed service/cert. Never aborts on a single failure."""
    errors: List[str] = []

    for rec in merged_records:
        evidence = [
            f"Observed via {', '.join(rec['sources']) or 'unknown source'} (external passive "
            f"intelligence database): {len(rec['services'])} service(s) across "
            f"{len(rec['ports'])} port(s), last observed at {rec['last_observed_at']}"
        ]
        attribution = rec.get("attribution") or {}
        if attribution.get("basis") == "provider_hostname_match_only":
            evidence.append(
                f"Not attributed to {target}: the provider returned this host for a "
                f"hostname search but the record carries no in-scope hostname, and "
                f"{target}'s DNS does not resolve to this IP"
            )
        if attribution.get("out_of_scope_hostname_count"):
            evidence.append(
                f"Host also carries {attribution['out_of_scope_hostname_count']} hostname(s) "
                f"outside {target} — possible shared/CDN/multi-tenant infrastructure, so "
                f"services observed here are not necessarily the target's"
            )
        err = _safe_store_add(store, make_finding(
            finding_type="passive_intel_host",
            target=target,
            value=rec,
            evidence=evidence,
            confidence=rec["confidence"],
            metadata={
                "ip": rec["ip"],
                "sources": rec["sources"],
                "discovered_via": rec["discovered_via"],
                "in_scope": rec["in_scope"],
                "attribution_basis": rec.get("attribution", {}).get("basis"),
                "out_of_scope_hostname_count": rec.get("attribution", {}).get(
                    "out_of_scope_hostname_count", 0),
                "port_count": len(rec["ports"]),
                "service_count": len(rec["services"]),
                "certificate_count": len(rec["certificates"]),
            },
        ))
        if err:
            errors.append(err)

        for svc in rec["services"]:
            err = _safe_store_add(store, make_finding(
                finding_type="passive_intel_service",
                target=target,
                value={**svc, "ip": rec["ip"]},
                evidence=[
                    f"{svc.get('source')} observed a service on {rec['ip']}:{svc.get('port')} "
                    f"({svc.get('product') or 'unknown product'} {svc.get('version') or ''}".rstrip() + ") "
                    f"at {svc.get('timestamp')}"
                ],
                confidence=CONFIDENCE_MEDIUM,
                metadata={"ip": rec["ip"], "port": svc.get("port"), "source": svc.get("source")},
            ))
            if err:
                errors.append(err)

        for cert in rec["certificates"]:
            err = _safe_store_add(store, make_finding(
                finding_type="passive_intel_certificate",
                target=target,
                value={**cert, "ip": rec["ip"]},
                evidence=[
                    f"{cert.get('source')} observed a certificate on {rec['ip']}:{cert.get('port')} "
                    f"(subject CN={cert.get('subject_cn')!r}, fingerprint_sha256={cert.get('fingerprint_sha256')!r})"
                ],
                confidence=CONFIDENCE_MEDIUM,
                metadata={"ip": rec["ip"], "port": cert.get("port"), "source": cert.get("source")},
            ))
            if err:
                errors.append(err)

    return errors


def classify_ip_check(source_statuses: Dict[str, str]) -> Dict[str, Any]:
    """
    Decide what a set of per-source lookup statuses for one IP actually proves.

    `source_statuses` maps a source name ("shodan"/"censys") to the status that
    source returned for this IP. Returns::

        {"outcome": "not_found" | "inconclusive",
         "confirming": [sources that authoritatively reported no record],
         "unavailable": [sources that never answered],
         "unparsable": [sources that answered with data we could not parse]}

    "not_found" requires at least one source to have authoritatively answered.
    Anything else is inconclusive: a throttled, unpaid, refused or timed-out
    request is not evidence of absence, and a record we failed to parse is
    evidence that data exists.
    """
    confirming = sorted(src for src, st in source_statuses.items()
                        if st in _AUTHORITATIVE_ABSENT_STATUSES)
    unavailable = sorted(src for src, st in source_statuses.items()
                         if st in _PROVIDER_UNAVAILABLE_STATUSES)
    unparsable = sorted(src for src, st in source_statuses.items() if st == CHECK_UNPARSABLE)
    return {
        "outcome": "not_found" if (confirming and not unparsable) else "inconclusive",
        "confirming": confirming,
        "unavailable": unavailable,
        "unparsable": unparsable,
    }


def persist_no_data_findings(
    no_data_ips: List[str],
    target: str,
    sources_checked: List[str],
    store: Optional[PendingAssetsStore],
    ip_source_statuses: Optional[Dict[str, Dict[str, str]]] = None,
) -> List[str]:
    """
    Persist negative-result memory for seed IPs that produced no host record.

    Each IP is classified first (see classify_ip_check). Only IPs a provider
    authoritatively reported as unknown get `passive_intel_checked_no_data`;
    IPs whose lookups failed, were throttled, or returned unparsable data get
    `passive_intel_check_inconclusive` instead, so nothing downstream reads a
    provider outage as "checked and confirmed absent".

    `ip_source_statuses` maps ip -> {source: status}. When omitted the caller
    is treated as having no per-source detail and every IP is recorded as
    inconclusive — the safe direction, never a fabricated absence.
    """
    errors: List[str] = []
    ip_source_statuses = ip_source_statuses or {}

    for ip in no_data_ips:
        verdict = classify_ip_check(ip_source_statuses.get(ip, {}))
        confirming = verdict["confirming"]
        unavailable = verdict["unavailable"]
        unparsable = verdict["unparsable"]

        if verdict["outcome"] == "not_found":
            evidence = [
                f"No historical record found for {ip}; "
                f"{', '.join(confirming)} authoritatively reported no data for this IP"
            ]
            if unavailable:
                evidence.append(
                    f"Not corroborated by {', '.join(unavailable)} — "
                    f"that source did not answer, so its silence proves nothing"
                )
            finding_type = "passive_intel_checked_no_data"
            note = (
                "Negative-result-memory: absence of external intelligence does not "
                "prove the host/service does not exist — Shodan/Censys only index "
                "what their own scanners have already observed."
            )
        else:
            reasons = []
            if unavailable:
                reasons.append(f"{', '.join(unavailable)} did not answer")
            if unparsable:
                reasons.append(
                    f"{', '.join(unparsable)} returned a record this module could not parse"
                )
            if not reasons:
                reasons.append("no source produced an authoritative answer")
            evidence = [
                f"Check of {ip} was INCONCLUSIVE, not negative: {'; '.join(reasons)}"
            ]
            # NAMING CONTRACT: surface_mapper._is_negative_result() treats any
            # finding type containing "_checked_no" as negative-result memory,
            # which other modules trust to skip re-checking. This type must
            # therefore NEVER contain that substring — an inconclusive check is
            # not a negative result and must not suppress a future re-check.
            finding_type = "passive_intel_check_inconclusive"
            note = (
                "This is NOT a negative result. No provider authoritatively reported "
                "the absence of a record for this IP, so this check must not be used "
                "to skip re-checking or to conclude the host is unknown to the provider."
            )

        err = _safe_store_add(store, make_finding(
            finding_type=finding_type,
            target=target,
            value={
                "ip": ip,
                "sources_checked": sources_checked,
                "outcome": verdict["outcome"],
                "sources_confirming_absence": confirming,
                "sources_unavailable": unavailable,
                "sources_unparsable": unparsable,
            },
            evidence=evidence,
            confidence=CONFIDENCE_LOW,
            metadata={
                "ip": ip,
                "sources_checked": sources_checked,
                "outcome": verdict["outcome"],
                "sources_confirming_absence": confirming,
                "sources_unavailable": unavailable,
                "sources_unparsable": unparsable,
                "checked_at": _now(),
                "note": note,
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# Module orchestration
# ---------------------------------------------------------------------------

def run_passive_intel(
    target: str,
    output_dir: str = "output",
    shodan_api_key: Optional[str] = None,
    censys_api_id: Optional[str] = None,
    censys_api_secret: Optional[str] = None,
    seed_ips: Optional[List[str]] = None,
    include_shodan: bool = True,
    include_censys: bool = True,
    include_hostname_search: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    max_search_pages: int = 1,
) -> Dict[str, Any]:
    """
    Run all Module 2 passive-intel checks against `target` and persist
    every discovery immediately to <output_dir>/pending_assets.json.

    Missing credentials for a source never raise — that source is skipped
    and clearly reported in `source_status` (module docstring, credential
    handling). Running with zero credentials configured completes
    successfully with an empty result set.

    `max_search_pages` bounds hostname-search pagination (default 1, which
    preserves the original single-request behaviour and provider quota cost).
    Whenever results were left behind, `source_status[...]["truncated"]` says
    so explicitly.
    """
    target = validate_target(target)
    store = PendingAssetsStore(output_dir=output_dir)

    shodan_api_key = shodan_api_key if shodan_api_key is not None else os.environ.get(SHODAN_API_KEY_ENV)
    censys_api_id = censys_api_id if censys_api_id is not None else os.environ.get(CENSYS_API_ID_ENV)
    censys_api_secret = censys_api_secret if censys_api_secret is not None else os.environ.get(CENSYS_API_SECRET_ENV)

    summary: Dict[str, Any] = {
        "target": target,
        "module": MODULE_NAME,
        "started_at": _now(),
        "seed_ips": [],
        "source_status": {},
        "hosts": [],
        "stats": {},
        "errors": [],
    }

    seed = load_seed_hosts(store, target, extra_ips=seed_ips)
    seed_ip_list = seed["ips"]
    summary["seed_ips"] = seed_ip_list

    shodan_available = include_shodan and bool(shodan_api_key)
    censys_available = include_censys and bool(censys_api_id and censys_api_secret)

    if include_shodan and not shodan_api_key:
        summary["source_status"]["shodan"] = {
            "status": "missing_credentials",
            "error": f"Shodan API key not configured (set {SHODAN_API_KEY_ENV})",
        }
    if include_censys and not (censys_api_id and censys_api_secret):
        summary["source_status"]["censys"] = {
            "status": "missing_credentials",
            "error": f"Censys API credentials not configured (set {CENSYS_API_ID_ENV}/{CENSYS_API_SECRET_ENV})",
        }

    sources_checked: List[str] = []
    if shodan_available:
        sources_checked.append("shodan")
    if censys_available:
        sources_checked.append("censys")

    normalized_records: List[Dict[str, Any]] = []
    ips_with_data: Set[str] = set()
    shodan_host_lookups: List[Dict[str, Any]] = []
    censys_host_lookups: List[Dict[str, Any]] = []
    # ip -> {source: status}. Drives negative-result memory: only an
    # authoritative provider answer may be recorded as "checked, not found".
    ip_source_statuses: Dict[str, Dict[str, str]] = {}

    def _record_status(ip_addr: str, source: str, status: str) -> None:
        ip_source_statuses.setdefault(ip_addr, {})[source] = status

    for ip in seed_ip_list:
        if shodan_available:
            try:
                r = query_shodan_host(ip, shodan_api_key, timeout=timeout)
            except Exception as exc:  # a single host lookup must not abort the rest
                r = {"status": "error", "error": str(exc), "host": None}
            shodan_host_lookups.append({"ip": ip, "status": r["status"], "error": r.get("error")})
            effective = r["status"]
            if r["status"] == "found":
                try:
                    norm = normalize_shodan_host(r["host"], target)
                except Exception as exc:
                    norm = None
                    summary["errors"].append({"stage": "normalize_shodan_host", "ip": ip, "error": str(exc)})
                if norm:
                    norm["discovered_via"] = "seed_ip_lookup"
                    normalized_records.append(norm)
                    ips_with_data.add(ip)
                else:
                    # Shodan HAD a record; this module could not normalize it.
                    # Recording that as "no data" would be a false negative and
                    # would silently discard the fact that data exists.
                    effective = CHECK_UNPARSABLE
                    summary["errors"].append({
                        "stage": "normalize_shodan_host", "ip": ip,
                        "error": "Shodan returned a record that could not be normalized "
                                 "(no usable ip_str); record not persisted",
                    })
            _record_status(ip, "shodan", effective)

        if censys_available:
            try:
                r = query_censys_host(ip, censys_api_id, censys_api_secret, timeout=timeout)
            except Exception as exc:
                r = {"status": "error", "error": str(exc), "host": None}
            censys_host_lookups.append({"ip": ip, "status": r["status"], "error": r.get("error")})
            effective = r["status"]
            if r["status"] == "found":
                try:
                    norm = normalize_censys_host(r["host"], target)
                except Exception as exc:
                    norm = None
                    summary["errors"].append({"stage": "normalize_censys_host", "ip": ip, "error": str(exc)})
                if norm:
                    norm["discovered_via"] = "seed_ip_lookup"
                    normalized_records.append(norm)
                    ips_with_data.add(ip)
                else:
                    effective = CHECK_UNPARSABLE
                    summary["errors"].append({
                        "stage": "normalize_censys_host", "ip": ip,
                        "error": "Censys returned a record that could not be normalized "
                                 "(no usable ip); record not persisted",
                    })
            _record_status(ip, "censys", effective)

    if shodan_host_lookups:
        summary["source_status"]["shodan_host_lookups"] = shodan_host_lookups
    if censys_host_lookups:
        summary["source_status"]["censys_host_lookups"] = censys_host_lookups

    if include_hostname_search:
        if shodan_available:
            try:
                r = search_shodan_by_hostname(
                    target, shodan_api_key, timeout=timeout, max_pages=max_search_pages)
            except Exception as exc:
                r = {"status": "error", "error": str(exc), "matches": [], "total": 0}
            # `total` alone silently implied completeness: a run reporting
            # total=5000 while holding 100 matches looked like a full result.
            summary["source_status"]["shodan_hostname_search"] = {
                "status": r["status"], "error": r.get("error"), "total": r.get("total", 0),
                "retrieved": r.get("retrieved", len(r.get("matches") or [])),
                "truncated": r.get("truncated", False),
                "pages_fetched": r.get("pages_fetched", 0),
                "page_error": r.get("page_error"),
            }
            if r["status"] == "found":
                for match in r["matches"]:
                    try:
                        norm = normalize_shodan_search_match(match, target)
                    except Exception as exc:
                        norm = None
                        summary["errors"].append({"stage": "normalize_shodan_search_match", "error": str(exc)})
                    if norm:
                        norm["discovered_via"] = "hostname_search"
                        normalized_records.append(norm)
                        ips_with_data.add(norm["ip"])

        if censys_available:
            try:
                r = search_censys_by_hostname(
                    target, censys_api_id, censys_api_secret, timeout=timeout,
                    max_pages=max_search_pages)
            except Exception as exc:
                r = {"status": "error", "error": str(exc), "hits": [], "total": 0}
            summary["source_status"]["censys_hostname_search"] = {
                "status": r["status"], "error": r.get("error"), "total": r.get("total", 0),
                "retrieved": r.get("retrieved", len(r.get("hits") or [])),
                "truncated": r.get("truncated", False),
                "pages_fetched": r.get("pages_fetched", 0),
                "page_error": r.get("page_error"),
            }
            if r["status"] == "found":
                for hit in r["hits"]:
                    try:
                        norm = normalize_censys_host(hit, target)
                    except Exception as exc:
                        norm = None
                        summary["errors"].append({"stage": "normalize_censys_search_hit", "error": str(exc)})
                    if norm:
                        norm["discovered_via"] = "hostname_search"
                        normalized_records.append(norm)
                        ips_with_data.add(norm["ip"])

    merged = merge_host_records(normalized_records, target)
    persist_errors = persist_host_intel(merged, target, store)
    if persist_errors:
        summary["errors"].append({"stage": "persistence", "errors": persist_errors})

    no_data_ips = [ip for ip in seed_ip_list if ip not in ips_with_data]
    if sources_checked and no_data_ips:
        negmem_errors = persist_no_data_findings(
            no_data_ips, target, sources_checked, store,
            ip_source_statuses=ip_source_statuses,
        )
        if negmem_errors:
            summary["errors"].append({"stage": "negative_result_memory", "errors": negmem_errors})

    # Split the counters so a run against a throttled/unpaid provider can never
    # be read as "we checked these hosts and they had nothing".
    confirmed_absent_ips = [
        ip for ip in no_data_ips
        if classify_ip_check(ip_source_statuses.get(ip, {}))["outcome"] == "not_found"
    ]
    inconclusive_ips = [ip for ip in no_data_ips if ip not in set(confirmed_absent_ips)]

    summary["hosts"] = merged
    summary["stats"] = {
        "seed_ip_count": len(seed_ip_list),
        "hosts_found": len(merged),
        "services_found": sum(len(h["services"]) for h in merged),
        "certificates_found": sum(len(h["certificates"]) for h in merged),
        "hosts_checked_no_data": len(confirmed_absent_ips) if sources_checked else 0,
        "hosts_check_inconclusive": len(inconclusive_ips) if sources_checked else 0,
        "sources_used": sources_checked,
    }
    summary["ip_check_outcomes"] = {
        ip: classify_ip_check(statuses) for ip, statuses in sorted(ip_source_statuses.items())
    }
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="passive_intel.py",
        description="ReconHound Module 2 — external intelligence databases (Shodan/Censys) "
                     "(standalone test entry point).",
    )
    parser.add_argument("--target", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--shodan-api-key", default=None, help=f"Shodan API key (or set {SHODAN_API_KEY_ENV})")
    parser.add_argument("--censys-api-id", default=None, help=f"Censys API ID (or set {CENSYS_API_ID_ENV})")
    parser.add_argument("--censys-api-secret", default=None, help=f"Censys API secret (or set {CENSYS_API_SECRET_ENV})")
    parser.add_argument("--seed-ip", action="append", default=None, help="Extra IP to look up (repeatable)")
    parser.add_argument("--no-shodan", action="store_true", help="Skip Shodan entirely")
    parser.add_argument("--no-censys", action="store_true", help="Skip Censys entirely")
    parser.add_argument("--no-hostname-search", action="store_true", help="Skip hostname-scoped search queries")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-query network timeout (seconds)")
    args = parser.parse_args()

    try:
        result = run_passive_intel(
            args.target,
            output_dir=args.output_dir,
            shodan_api_key=args.shodan_api_key,
            censys_api_id=args.censys_api_id,
            censys_api_secret=args.censys_api_secret,
            seed_ips=args.seed_ip,
            include_shodan=not args.no_shodan,
            include_censys=not args.no_censys,
            include_hostname_search=not args.no_hostname_search,
            timeout=args.timeout,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
