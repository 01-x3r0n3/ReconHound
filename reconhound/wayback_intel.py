"""
reconhound/wayback_intel.py — ReconHound Module 5 (wayback_intel.py).

Phase: Passive. See context.md §10 (module 5, "Historical web intel") for
the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Historical web intel. Wayback Machine API, historical URLs/deleted
  paths/old endpoints/params, diff against current surface, flag
  removed-but-maybe-still-accessible assets."

That expands (per the assignment brief) into seven discrete
responsibilities, each implemented below:

  1. Wayback Machine API queries        -> fetch_cdx_snapshots (+ build_cdx_query_url)
  2. Historical URL discovery           -> group_historical_urls
  3. Historical/deleted path discovery  -> correlate_against_current_surface
                                            (STATE_HISTORICALLY_REMOVED)
  4. Historical endpoint discovery      -> classify_historical_url
  5. Historical parameter discovery     -> extract_historical_parameters (+
                                            build_historical_data_export)
  6. Current-surface comparison         -> load_current_surface (+
                                            correlate_against_current_surface)
  7. Removed-but-maybe-still-accessible -> correlate_against_current_surface
                                            (STATE_POTENTIALLY_RELEVANT)

Plus shared plumbing: make_finding, PendingAssetsStore, _safe_store_add,
and a single-target orchestrator run_wayback_intel (mirroring the
run_passive_recon / run_endpoint_discovery precedent).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order
position 9 (after surface_mapper.py at position 8). This implementation
was done under an explicit, temporary, user-approved deviation from that
order — surface_mapper.py has NOT been implemented yet. context.md is
unmodified and the documented build order is unchanged; this module is
implemented as a fully standalone producer that does not implement,
replace, or depend on surface_mapper.py's correlation engine, and does
not touch any other unimplemented central module (risk_engine.py,
core/orchestrator.py, reconhound.py).

PASSIVE BOUNDARY: this module's only network interaction is with the
Wayback Machine's public CDX Server API (archive.org's historical index).
It never sends a request to the target itself — no port scanning, no
active service detection, no live crawling, no OPTIONS/HEAD/GET probes
against discovered historical URLs. Consequently it can never confirm
that a historical asset is *currently* accessible; every historical
record's `current_accessibility` is explicitly reported as "unverified"
with a note explaining that confirming liveness is an active module's
job (e.g. endpoint_discovery.py), not this one's.

Implementation decisions (ambiguities resolved so implementation can
proceed without redesigning anything context.md defines):

  1. CDX API endpoint: https://web.archive.org/cdx/search/cdx (public,
     unauthenticated, no API key/credential dependency — so, unlike
     passive_intel.py/code_leak.py/osint_engine.py, this module has no
     "missing configuration" precondition beyond a syntactically valid
     base URL, which is itself validated and reported as a configuration
     error rather than assumed).
  2. Default query shape: matchType=domain (captures the target and its
     subdomains — consistent with is_in_scope()'s subdomain model used
     throughout the codebase, e.g. passive_recon.py's SAN tagging) and
     collapse=urlkey (one representative capture per canonical URL,
     matching how established Wayback-URL recon tooling avoids returning
     every single capture of a frequently-crawled URL, which for a busy
     site can be in the tens of thousands and would make `limit` alone an
     unreliable bound). Both are overridable per call; passing
     collapse=None returns full, unbounded per-capture history instead.
  3. "Current attack surface" source: surface_mapper.py (the architecture's
     eventual owner of a unified asset graph) does not exist yet. Rather
     than invent a second asset model to stand in for it, this module
     reads the URL-bearing findings already persisted to this run's
     output/pending_assets.json by the already-implemented producer
     modules (endpoint_discovery.py's `endpoint_discovered`, crawler.py's
     `crawled_url`, exposure_scan.py's `exposure_finding` /
     `robots_txt_discovered` / `sitemap_xml_discovered` /
     `http_options_result`) — see CURRENT_SURFACE_FINDING_TYPES and
     load_current_surface(). An optional `current_urls` parameter is also
     accepted (mirroring endpoint_discovery.py's caller-supplied
     `historical_data`/`js_data` pattern) for standalone testing/callers
     that want to supply a known-asset list directly rather than via a
     populated store.
  4. Output includes a `historical_data` list shaped to match exactly what
     endpoint_discovery.py's `correlate_historical_parameters()` already
     declares it expects to consume (see that function's docstring:
     {"url", "parameters": [...], "evidence": [...], "observed_at",
     "source"}) — a pre-existing hand-off point in the codebase, not a
     new interface invented here.
  5. HTTP 429 from the CDX API is classified `rate_limited` (mirroring
     endpoint_discovery.py/exposure_scan.py's own rate-limit handling for
     the target) so the caller/evidence trail can see results may be
     incomplete; no retry/backoff is implemented, matching those modules'
     documented scope decision.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). Output is
intended to feed surface_mapper.py (module 6, not yet implemented) — this
module does not implement or call into surface_mapper, active_recon,
tech_fingerprint, vhost_scanner, api_recon, js_analyzer, supply_chain,
http_analyzer, ssl_analyzer, screenshot, vuln_intel, risk_engine,
report_generator, orchestrator, or any other module not already
implemented.

DISCOVERY != CONFIRMED VULNERABILITY / != CONFIRMED LIVE: every record
here is a historical observation (a URL was captured by the Wayback
Machine at some point, optionally with a status code from that capture).
None of this module's output should be read as "vulnerable", "exploitable",
or "currently live" — that assessment belongs to active modules and/or
vuln_intel.py / risk_engine.py.
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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import requests

MODULE_NAME = "wayback_intel.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-WaybackIntel/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 15.0
DEFAULT_CDX_BASE_URL = "https://web.archive.org/cdx/search/cdx"
DEFAULT_LIMIT = 5000
DEFAULT_MATCH_TYPE = "domain"
DEFAULT_COLLAPSE = "urlkey"

CDX_FIELDS = ["timestamp", "original", "statuscode", "mimetype", "digest"]
_VALID_MATCH_TYPES = ("exact", "prefix", "host", "domain")

# Finding `type` values already written to pending_assets.json by
# already-implemented modules that carry a currently-known URL. This is
# the closest thing this repository has to "known current assets" until
# surface_mapper.py exists (see module docstring, decision #3).
CURRENT_SURFACE_FINDING_TYPES = {
    "endpoint_discovered",
    "crawled_url",
    "exposure_finding",
    "robots_txt_discovered",
    "sitemap_xml_discovered",
    "http_options_result",
}

# Historical-asset relationship states (context.md-required distinction
# between historically observed / currently known / historically removed /
# potentially still relevant / unverified current accessibility).
STATE_CURRENTLY_KNOWN = "currently_known"
STATE_HISTORICALLY_REMOVED = "historically_removed"
STATE_POTENTIALLY_RELEVANT = "historically_removed_potentially_relevant"
ACCESSIBILITY_UNVERIFIED = "unverified"
_ACCESSIBILITY_NOTE = (
    "wayback_intel.py is passive-only and never sends requests to the live "
    "target; confirming whether this historical asset currently responds "
    "requires an active module (e.g. endpoint_discovery.py) and is "
    "explicitly out of scope here."
)

_STATIC_ASSET_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|map)(?:$)", re.IGNORECASE
)
_ENDPOINT_HINT_RE = re.compile(r"/(?:api|graphql|rest|v[0-9]+)(?:/|$)", re.IGNORECASE)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class ScopeError(ValueError):
    """Raised when a target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class ConfigurationError(ValueError):
    """Raised when the CDX API configuration (base URL, matchType) is missing/invalid."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors passive_recon.py's validate_target/is_in_scope;
# duplicated per modular independence, context.md §12.2)
# ---------------------------------------------------------------------------

def validate_target(target: str) -> str:
    """
    Validate that `target` is a syntactically valid, explicit domain name.

    wayback_intel operates on exactly one explicit target domain per
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
# URL normalization (mirrors endpoint_discovery.py's _normalize_url so
# historical/current-surface comparisons use a consistent key)
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
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


def _url_path(url: str) -> str:
    try:
        path = urllib.parse.urlsplit(url).path
    except Exception:
        return "/"
    return path or "/"


# ---------------------------------------------------------------------------
# 1. Wayback Machine API queries
# ---------------------------------------------------------------------------

def build_cdx_query_url(
    target: str,
    base_url: str = DEFAULT_CDX_BASE_URL,
    match_type: str = DEFAULT_MATCH_TYPE,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: Optional[int] = None,
    collapse: Optional[str] = DEFAULT_COLLAPSE,
) -> str:
    """Build the CDX Server API query URL for `target`. Raises ConfigurationError on invalid config."""
    if not isinstance(base_url, str) or not base_url.strip():
        raise ConfigurationError("CDX API base URL must be a non-empty string.")
    parsed_base = urllib.parse.urlsplit(base_url.strip())
    if parsed_base.scheme not in ("http", "https") or not parsed_base.netloc:
        raise ConfigurationError(f"CDX API base URL is not a valid http(s) URL: {base_url!r}")

    if match_type not in _VALID_MATCH_TYPES:
        raise ConfigurationError(
            f"Unsupported CDX matchType {match_type!r}; must be one of {_VALID_MATCH_TYPES}"
        )

    params: Dict[str, str] = {
        "url": target,
        "output": "json",
        "fl": ",".join(CDX_FIELDS),
        "matchType": match_type,
    }
    if collapse:
        params["collapse"] = collapse
    if from_date:
        params["from"] = from_date
    if to_date:
        params["to"] = to_date
    if limit:
        try:
            params["limit"] = str(int(limit))
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"limit must be an integer: {limit!r}") from exc

    return f"{base_url.rstrip('/')}?{urllib.parse.urlencode(params)}"


def normalize_snapshot(row: Dict[str, str], base_archive_url: str = "https://web.archive.org/web") -> Dict[str, Any]:
    """Normalize one raw CDX row (already zipped into a dict by field name) into a JSON-safe record."""
    timestamp = row.get("timestamp") or ""
    original = row.get("original") or ""
    if not timestamp or not original:
        raise ValueError("snapshot row is missing timestamp/original")

    try:
        dt = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        observed_at = dt.isoformat()
    except ValueError:
        observed_at = None  # keep the raw timestamp as a fallback sort/display key

    status_raw = row.get("statuscode") or "-"
    status_code: Optional[int] = None
    if status_raw and status_raw != "-":
        try:
            status_code = int(status_raw)
        except ValueError:
            status_code = None

    return {
        "timestamp": timestamp,
        "observed_at": observed_at,
        "original_url": original,
        "status_code": status_code,
        "status_code_raw": status_raw,
        "mime_type": row.get("mimetype") or None,
        "digest": row.get("digest") or None,
        "archive_url": f"{base_archive_url}/{timestamp}/{original}",
    }


def fetch_cdx_snapshots(
    target: str,
    base_url: str = DEFAULT_CDX_BASE_URL,
    match_type: str = DEFAULT_MATCH_TYPE,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
    collapse: Optional[str] = DEFAULT_COLLAPSE,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Query the Wayback Machine CDX Server API for `target`'s capture
    history. This is the module's ONLY network interaction, and it talks
    exclusively to archive.org's historical index — never the target
    itself (passive boundary, see module docstring).

    Returns {"status": "found"|"not_found"|"rate_limited"|"error",
             "snapshots": [...], "raw_row_count": int, "row_errors": [...],
             "truncated": bool, "error": str|None, "query_url": str|None}.
    """
    target = validate_target(target)
    result: Dict[str, Any] = {
        "status": "not_found",
        "snapshots": [],
        "raw_row_count": 0,
        "row_errors": [],
        "truncated": False,
        "error": None,
        "query_url": None,
    }

    try:
        query_url = build_cdx_query_url(
            target, base_url=base_url, match_type=match_type,
            from_date=from_date, to_date=to_date, limit=limit, collapse=collapse,
        )
    except ConfigurationError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result
    result["query_url"] = query_url

    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    resp = None
    try:
        resp = requests.get(query_url, timeout=timeout, headers=req_headers)
    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["error"] = "timeout"
        return result
    except requests.exceptions.ConnectionError as exc:
        result["status"] = "error"
        result["error"] = f"connection error: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["status"] = "error"
        result["error"] = f"request failed: {exc}"
        return result
    finally:
        if resp is not None:
            resp.close()

    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["error"] = "HTTP 429 Too Many Requests from Wayback CDX API"
        return result
    if resp.status_code >= 500:
        result["status"] = "error"
        result["error"] = f"Wayback CDX API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["status"] = "error"
        result["error"] = f"Wayback CDX API returned unexpected HTTP {resp.status_code}"
        return result

    body = (resp.text or "").strip()
    if not body:
        result["status"] = "not_found"
        return result

    try:
        rows = json.loads(body)
    except json.JSONDecodeError as exc:
        result["status"] = "error"
        result["error"] = f"malformed JSON from Wayback CDX API: {exc}"
        return result

    if not isinstance(rows, list):
        result["status"] = "error"
        result["error"] = "unexpected CDX response structure (root is not a JSON array)"
        return result

    if len(rows) < 2:
        result["status"] = "not_found"
        return result

    header = rows[0]
    if not isinstance(header, list) or not all(isinstance(h, str) for h in header):
        result["status"] = "error"
        result["error"] = "unexpected CDX response structure (missing/invalid header row)"
        return result

    result["raw_row_count"] = len(rows) - 1
    result["truncated"] = bool(limit) and result["raw_row_count"] >= int(limit)

    snapshots: List[Dict[str, Any]] = []
    row_errors: List[str] = []
    for i, row in enumerate(rows[1:], start=1):
        try:
            if not isinstance(row, list) or len(row) != len(header):
                raise ValueError("row does not match header shape")
            snapshots.append(normalize_snapshot(dict(zip(header, row))))
        except Exception as exc:  # a single malformed row must not abort the rest
            row_errors.append(f"row {i}: {exc}")
            continue

    result["snapshots"] = snapshots
    result["row_errors"] = row_errors
    result["status"] = "found" if snapshots else "not_found"
    return result


# ---------------------------------------------------------------------------
# 2. Historical URL discovery
# ---------------------------------------------------------------------------

def group_historical_urls(snapshots: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
    """
    Dedup normalized CDX snapshots into one aggregated record per unique
    URL, preserving evidence across every capture rather than collapsing
    to a single boolean (first/last observed, all status codes and MIME
    types seen, full per-capture list retained under "snapshots").
    """
    groups: Dict[str, Dict[str, Any]] = {}

    for snap in snapshots:
        try:
            url = snap["original_url"]
            norm = _normalize_url(url)
        except Exception:
            continue  # malformed entry; skip this one, keep processing the rest

        group = groups.get(norm)
        if group is None:
            group = {
                "url": url,
                "normalized_url": norm,
                "path": _url_path(url),
                "in_scope": False,
                "snapshots": [],
                "first_observed_at": None,
                "last_observed_at": None,
                "status_codes_seen": set(),
                "mime_types_seen": set(),
            }
            groups[norm] = group

        group["snapshots"].append(snap)
        if snap.get("status_code") is not None:
            group["status_codes_seen"].add(snap["status_code"])
        if snap.get("mime_type"):
            group["mime_types_seen"].add(snap["mime_type"])

        marker = snap.get("observed_at") or snap.get("timestamp")
        if marker:
            if group["first_observed_at"] is None or marker < group["first_observed_at"]:
                group["first_observed_at"] = marker
            if group["last_observed_at"] is None or marker > group["last_observed_at"]:
                group["last_observed_at"] = marker

    records: List[Dict[str, Any]] = []
    for group in groups.values():
        try:
            hostname = urllib.parse.urlsplit(group["url"]).hostname or ""
        except Exception:
            hostname = ""
        group["in_scope"] = is_in_scope(hostname, target)
        group["status_codes_seen"] = sorted(group["status_codes_seen"])
        group["mime_types_seen"] = sorted(group["mime_types_seen"])
        group["capture_count"] = len(group["snapshots"])
        group["historically_observed"] = True
        records.append(group)

    return sorted(records, key=lambda r: r["url"])


# ---------------------------------------------------------------------------
# 3/4. Historical/deleted path discovery + historical endpoint discovery
# ---------------------------------------------------------------------------

def classify_historical_url(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tag a grouped historical-URL record with a discovery_type: an
    API/GraphQL/versioned-looking path is `historical_endpoint`, a
    static-asset extension is `historical_static_asset`, everything else
    is `historical_path` (context.md's "old endpoints" vs. "deleted
    paths" distinction).
    """
    path = record.get("path") or "/"
    is_static_asset = bool(_STATIC_ASSET_EXT_RE.search(path))
    is_endpoint_like = bool(_ENDPOINT_HINT_RE.search(path)) or path.rstrip("/").endswith((".json", ".xml"))

    try:
        has_query_parameters = bool(urllib.parse.urlsplit(record["url"]).query)
    except Exception:
        has_query_parameters = False

    if is_endpoint_like:
        discovery_type = "historical_endpoint"
    elif is_static_asset:
        discovery_type = "historical_static_asset"
    else:
        discovery_type = "historical_path"

    return {
        **record,
        "is_static_asset": is_static_asset,
        "is_endpoint_like": is_endpoint_like,
        "has_query_parameters": has_query_parameters,
        "discovery_type": discovery_type,
    }


# ---------------------------------------------------------------------------
# 5. Historical parameter discovery
# ---------------------------------------------------------------------------

def extract_historical_parameters(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract query-string parameter names observed on a historical URL."""
    try:
        query = urllib.parse.urlsplit(record["url"]).query
    except Exception:
        return []
    if not query:
        return []

    params: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except Exception:
        return []

    for name, _value in pairs:
        if not name or name in seen:
            continue
        seen.add(name)
        params.append({
            "name": name,
            "location": "query",
            "method": "GET",
            "data_type": "unknown",
        })
    return params


# ---------------------------------------------------------------------------
# 6/7. Current-attack-surface comparison + removed-but-maybe-still-relevant
# flagging
# ---------------------------------------------------------------------------

def load_current_surface(
    store: Optional[PendingAssetsStore] = None,
    extra_urls: Optional[List[str]] = None,
) -> Dict[str, Set[str]]:
    """
    Build the set of currently-known URLs/paths from the existing central
    persistence file (pending_assets.json), produced by already-implemented
    modules. See module docstring, decision #3: this reuses the
    established representation of current assets rather than inventing a
    second asset model — surface_mapper.py does not exist yet, so the
    shared persisted findings are the closest thing this repository has
    to "known current assets" until it does.
    """
    normalized_urls: Set[str] = set()
    paths: Set[str] = set()

    if store is not None:
        try:
            records = store.all()
        except PersistenceError:
            records = []
        for rec in records:
            if not isinstance(rec, dict) or rec.get("type") not in CURRENT_SURFACE_FINDING_TYPES:
                continue
            value = rec.get("value")
            if not isinstance(value, dict):
                continue
            candidates: List[Any] = []
            if value.get("url"):
                candidates.append(value["url"])
            if isinstance(value.get("urls"), list):  # sitemap_xml_discovered's listed URLs
                candidates.extend(value["urls"])
            for u in candidates:
                if isinstance(u, str) and u:
                    normalized_urls.add(_normalize_url(u))
                    paths.add(_url_path(u))

    if extra_urls:
        for u in extra_urls:
            if isinstance(u, str) and u:
                normalized_urls.add(_normalize_url(u))
                paths.add(_url_path(u))

    return {"normalized_urls": normalized_urls, "paths": paths}


def correlate_against_current_surface(
    historical_records: List[Dict[str, Any]],
    current_surface: Dict[str, Set[str]],
) -> List[Dict[str, Any]]:
    """
    Enrich each classified historical-URL record with its relationship to
    the current attack surface. Never claims current accessibility —
    current_accessibility is always "unverified" (see module docstring's
    passive-boundary note).
    """
    enriched: List[Dict[str, Any]] = []
    for rec in historical_records:
        currently_known = (
            rec["normalized_url"] in current_surface["normalized_urls"]
            or rec["path"] in current_surface["paths"]
        )
        looked_live_historically = any(
            isinstance(s, int) and 200 <= s < 400 for s in rec.get("status_codes_seen", [])
        )

        if currently_known:
            relationship = STATE_CURRENTLY_KNOWN
            confidence = CONFIDENCE_MEDIUM if rec.get("is_static_asset") else CONFIDENCE_HIGH
        elif looked_live_historically:
            relationship = STATE_POTENTIALLY_RELEVANT
            confidence = CONFIDENCE_LOW
        else:
            relationship = STATE_HISTORICALLY_REMOVED
            confidence = CONFIDENCE_LOW

        enriched.append({
            **rec,
            "relationship_to_current_surface": relationship,
            "current_accessibility": ACCESSIBILITY_UNVERIFIED,
            "current_accessibility_note": _ACCESSIBILITY_NOTE,
            "confidence": confidence,
        })
    return enriched


def build_historical_data_export(enriched_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build the `historical_data` export shape that endpoint_discovery.py's
    correlate_historical_parameters() already declares it expects to
    consume (see module docstring, decision #4).
    """
    export: List[Dict[str, Any]] = []
    for rec in enriched_records:
        evidence = [
            f"Wayback Machine captured {rec['capture_count']} snapshot(s) of {rec['url']} "
            f"between {rec['first_observed_at']} and {rec['last_observed_at']} "
            f"(status codes seen: {rec['status_codes_seen']})"
        ]
        export.append({
            "url": rec["url"],
            "parameters": extract_historical_parameters(rec),
            "evidence": evidence,
            "observed_at": rec["last_observed_at"],
            "source": MODULE_NAME,
        })
    return export


# ---------------------------------------------------------------------------
# Persistence of enriched historical findings
# ---------------------------------------------------------------------------

def persist_historical_findings(
    enriched_records: List[Dict[str, Any]],
    target: str,
    store: Optional[PendingAssetsStore],
) -> List[str]:
    """Persist one finding per historical URL and one per historical parameter. Never aborts on a single failure."""
    errors: List[str] = []

    for rec in enriched_records:
        evidence = [
            f"Wayback CDX: {rec['capture_count']} capture(s) of {rec['url']} "
            f"(first {rec['first_observed_at']}, last {rec['last_observed_at']}, "
            f"status codes seen: {rec['status_codes_seen']})"
        ]
        err = _safe_store_add(store, make_finding(
            finding_type=rec["discovery_type"],  # historical_endpoint | historical_static_asset | historical_path
            target=target,
            value=rec,
            evidence=evidence,
            confidence=rec["confidence"],
            metadata={
                "relationship_to_current_surface": rec["relationship_to_current_surface"],
                "current_accessibility": rec["current_accessibility"],
                "path": rec["path"],
                "in_scope": rec["in_scope"],
                "capture_count": rec["capture_count"],
            },
        ))
        if err:
            errors.append(err)

        for param in extract_historical_parameters(rec):
            err = _safe_store_add(store, make_finding(
                finding_type="historical_parameter",
                target=target,
                value={**param, "endpoint": rec["path"], "url": rec["url"]},
                evidence=[f"Query parameter {param['name']!r} observed in a historical capture of {rec['url']}"],
                confidence=CONFIDENCE_LOW,
                metadata={"url": rec["url"], "endpoint": rec["path"], "name": param["name"]},
            ))
            if err:
                errors.append(err)

    return errors


# ---------------------------------------------------------------------------
# Module orchestration
# ---------------------------------------------------------------------------

def run_wayback_intel(
    target: str,
    output_dir: str = "output",
    base_url: str = DEFAULT_CDX_BASE_URL,
    match_type: str = DEFAULT_MATCH_TYPE,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
    collapse: Optional[str] = DEFAULT_COLLAPSE,
    timeout: float = DEFAULT_TIMEOUT,
    current_urls: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run all Module 5 wayback-intel checks against `target` and persist
    every discovery immediately to <output_dir>/pending_assets.json.

    Returns a structured summary, including `historical_data` — directly
    consumable by endpoint_discovery.py's
    correlate_historical_parameters(current_endpoints, historical_data=...,
    target=target, store=store).
    """
    target = validate_target(target)
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "target": target,
        "module": MODULE_NAME,
        "started_at": _now(),
        "cdx_query": {},
        "historical_urls": [],
        "historical_data": [],
        "stats": {},
        "errors": [],
    }

    try:
        cdx_result = fetch_cdx_snapshots(
            target, base_url=base_url, match_type=match_type,
            from_date=from_date, to_date=to_date, limit=limit,
            collapse=collapse, timeout=timeout,
        )
    except ScopeError:
        raise
    except Exception as exc:  # never let an unexpected exception abort the whole module
        summary["errors"].append({"stage": "cdx_query", "error": str(exc)})
        cdx_result = {
            "status": "error", "snapshots": [], "error": str(exc),
            "row_errors": [], "raw_row_count": 0, "truncated": False, "query_url": None,
        }

    summary["cdx_query"] = {k: v for k, v in cdx_result.items() if k != "snapshots"}
    if cdx_result.get("row_errors"):
        summary["errors"].append({"stage": "snapshot_normalization", "row_errors": cdx_result["row_errors"]})
    if cdx_result.get("truncated"):
        summary["errors"].append({
            "stage": "cdx_query",
            "error": f"result set truncated at limit={limit}; historical intelligence may be incomplete",
        })
    if cdx_result.get("status") in ("error", "rate_limited"):
        summary["errors"].append({"stage": "cdx_query", "error": cdx_result.get("error")})

    if cdx_result.get("status") != "found":
        summary["stats"] = {"total_snapshots": cdx_result.get("raw_row_count", 0), "unique_urls": 0}
        summary["finished_at"] = _now()
        return summary

    try:
        grouped = group_historical_urls(cdx_result["snapshots"], target)
        classified = [classify_historical_url(r) for r in grouped]
    except Exception as exc:
        summary["errors"].append({"stage": "grouping", "error": str(exc)})
        classified = []

    try:
        current_surface = load_current_surface(store=store, extra_urls=current_urls)
    except Exception as exc:
        summary["errors"].append({"stage": "current_surface_load", "error": str(exc)})
        current_surface = {"normalized_urls": set(), "paths": set()}

    enriched = correlate_against_current_surface(classified, current_surface)

    persist_errors = persist_historical_findings(enriched, target, store)
    if persist_errors:
        summary["errors"].append({"stage": "persistence", "errors": persist_errors})

    summary["historical_urls"] = enriched
    summary["historical_data"] = build_historical_data_export(enriched)
    summary["stats"] = {
        "total_snapshots": cdx_result.get("raw_row_count", 0),
        "unique_urls": len(enriched),
        "currently_known": sum(1 for r in enriched if r["relationship_to_current_surface"] == STATE_CURRENTLY_KNOWN),
        "historically_removed_potentially_relevant": sum(
            1 for r in enriched if r["relationship_to_current_surface"] == STATE_POTENTIALLY_RELEVANT
        ),
        "historically_removed": sum(
            1 for r in enriched if r["relationship_to_current_surface"] == STATE_HISTORICALLY_REMOVED
        ),
    }
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="wayback_intel.py",
        description="ReconHound Module 5 — historical web intelligence via the Wayback Machine "
                     "(standalone test entry point).",
    )
    parser.add_argument("--target", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-query network timeout (seconds)")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Max CDX rows to request")
    parser.add_argument("--from-date", default=None, help="CDX 'from' filter, e.g. 20200101")
    parser.add_argument("--to-date", default=None, help="CDX 'to' filter, e.g. 20231231")
    parser.add_argument("--match-type", default=DEFAULT_MATCH_TYPE, choices=_VALID_MATCH_TYPES)
    args = parser.parse_args()

    try:
        result = run_wayback_intel(
            args.target, output_dir=args.output_dir, timeout=args.timeout, limit=args.limit,
            from_date=args.from_date, to_date=args.to_date, match_type=args.match_type,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
