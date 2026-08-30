"""
reconhound/vuln_intel.py — ReconHound Module 19 (vuln_intel.py).

Phase: Intelligence. See context.md §10 (module 19, "Technology-to-CVE
mapping") for the authoritative responsibilities, and §8 for the
evidence/confidence data model this module implements. This file only
documents implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "Technology-to-CVE mapping. Consumes versions from tech_fingerprint.py
  and active_recon.py, queries NVD + public vuln DBs, maps versions to
  known CVEs. Output style: 'Detected Nginx 1.18.0 — MAY be affected by
  CVE-XXXX.' Never claim 'confirmed exploitable' without actual evidence.
  Detection != confirmed vulnerability." -> risk_engine.py

THE CENTRAL RULE OF THIS MODULE: a technology/version match to a CVE is
vulnerability INTELLIGENCE, never proof of exploitability. Nothing in this
file ever emits the phrase "confirmed exploitable", and every persisted
finding/statement distinguishes:

  detected technology/version -> matching/possibly-applicable CVE ->
  supporting evidence -> confidence/applicability -> source -> timestamp.

Responsibility -> implementation map:

  - Consume tech/version observations
    (tech_fingerprint.py + active_recon.py) -> normalize_technology_observation,
                                                extract_observations_from_active_recon
  - Query the NVD API                        -> query_nvd
  - Query CISA KEV                           -> query_cisa_kev
  - Query OSV                                -> query_osv
  - Query GitHub Security Advisories         -> query_github_advisories
  - Query Exploit-DB                         -> fetch_exploitdb_index
  - Map technology/version to known CVEs     -> map_technology_to_cves
                                                 (+ query_all_sources)
  - Normalized vuln-intelligence output for
    risk_engine.py                           -> the "vulnerability_intelligence"
                                                 findings persisted by
                                                 map_technology_to_cves
  - Single-run orchestration                 -> run_vuln_intel

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
10, immediately after surface_mapper.py (position 8) and wayback_intel.py
(position 9). Per its own module docstring, wayback_intel.py was already
built under an explicit, user-approved deviation from that order because
surface_mapper.py does not exist yet. This module continues under the
same deviation for the same reason, plus one more: tech_fingerprint.py
(build-order position 17) — the module context.md names as this module's
PRIMARY input — also does not exist yet. context.md is unmodified and the
documented build order is unchanged; this module is implemented as a
fully standalone consumer/producer that does not implement, replace, or
depend on surface_mapper.py's correlation engine or tech_fingerprint.py's
detection logic, and does not touch any other unimplemented module
(risk_engine.py, core/orchestrator.py, reconhound.py, tech_fingerprint.py).

INPUT-CONTRACT DECISION (resolves the tech_fingerprint.py gap without
inventing a competing technology model, mirroring wayback_intel.py's
decision #3 for the surface_mapper.py gap):

  1. Every already-implemented module in this repo persists findings via
     the same {type, target, value, evidence, confidence, source,
     timestamp, metadata} shape (context.md §8). Rather than inventing a
     second, vuln_intel-specific technology model, this module reads that
     existing shape directly: normalize_technology_observation() accepts
     any dict carrying a recognizable technology-name key (technology /
     product / name / software / framework) and an optional version key
     (version / product_version) — a deliberately liberal contract so
     that whatever shape tech_fingerprint.py eventually emits for its
     technology/version findings needs no adapter here, as long as it
     uses one of those key names (documented as
     TECH_FINGERPRINT_INPUT_CONTRACT below).
  2. Until tech_fingerprint.py exists, the only current producer of
     technology/version signal is active_recon.py, which persists two
     finding types with parseable software/version text:
     "ssh_fingerprint" (its own already-parsed `software` field) and
     "banner" (raw banner text, parsed best-effort via
     parse_name_version_from_text). active_recon.py's
     "service_identification"/"service_conflict" findings are
     deliberately NOT used as technology observations: they only ever
     carry a generic protocol name (e.g. "ssh", "ftp", "mysql"), never a
     vendor/product name, so a CVE keyword search built from them would
     be too broad to be useful and would burn API quota on noise — this
     is a documented, deliberate exclusion, not an oversight.
  3. A caller-supplied `technology_observations` list (run_vuln_intel /
     map_technology_to_cves) is the forward-compatible hand-off point for
     tech_fingerprint.py, mirroring the existing
     historical_data/current_urls caller-supplied-list precedent already
     used between wayback_intel.py <-> endpoint_discovery.py.

TECH_FINGERPRINT_INPUT_CONTRACT (declared here so a future
tech_fingerprint.py implementation has an explicit, already-agreed
consumption contract — not a new interface invented in isolation, per the
same precedent as wayback_intel.py's decision #4):

  {"technology": str, "version": Optional[str], "category": Optional[str],
   "target": str, "confidence": "LOW"|"MEDIUM"|"HIGH",
   "evidence": [str, ...], "source": "tech_fingerprint.py"}

VERSION-MATCH HONESTY (context.md's "do not manufacture precise version
matches" requirement): every CVE match this module produces is tagged
with an `applicability`:

  - "version_range_confirmed"       — an authoritative source's own
    version-range/version-filter data (NVD CPE versionStart/EndIncluding/
    Excluding, OSV's server-side version filtering, or a parsed GitHub
    Advisory vulnerable_version_range) places the observed version inside
    the documented vulnerable range.
  - "keyword_match_version_unconfirmed" — the product name matched, but
    no source's range data could confirm (or deny) that the specific
    observed version is affected.
  - "version_unknown_cannot_confirm" — no version was observed at all
    (context.md's "handle ... versionless technology observations
    safely"); every resulting CVE reference is a bare product-name
    keyword match.

  Confidence is capped by BOTH the strength of that applicability tag AND
  the confidence of the underlying technology/version observation itself
  (see _cap_confidence) — a HIGH-confidence CPE range match built on a
  LOW-confidence banner guess is still reported at LOW, never HIGH
  (context.md §8: "Never present insufficient evidence as certainty").
  Independently converging sources (e.g. NVD + OSV + GHSA agreeing on the
  same CVE) raise a keyword-only match from LOW to MEDIUM confidence
  (context.md §8's converging-signal rule) — but applicability language
  never escalates past "MAY be affected"/"POSSIBLY related to"; nothing in
  this module ever asserts confirmed exploitability.

PER-SOURCE DOCUMENTED LIMITATIONS:

  - NVD: unauthenticated requests are aggressively rate-limited by NVD
    itself; supply an API key (env var NVD_API_KEY, or the `api_key`
    parameter) to raise that ceiling. A 403/429 is reported as
    status="rate_limited", never silently retried/hidden.
  - OSV: OSV's package-query endpoint requires a known package ecosystem
    (npm, PyPI, Go, WordPress, ...). A small, explicit hint table
    (_OSV_ECOSYSTEM_HINTS) covers common cases; when no ecosystem can be
    inferred and none is supplied, OSV is reported as status="skipped"
    with an explanit error — no ecosystem is ever guessed/fabricated.
  - GitHub Security Advisories: only advisories carrying a GitHub-assigned
    `cve_id` are used (this module maps to CVEs specifically, per
    context.md); GHSA-only advisories without a CVE are counted in
    `skipped_no_cve_advisories` for transparency, never silently dropped
    without a trace. Works unauthenticated (lower GitHub rate limit); set
    GITHUB_TOKEN (or pass `github_token`) to raise it.
  - Exploit-DB: there is no official Exploit-DB query API. This module
    fetches the public, community-maintained files_exploits.csv index
    (a multi-megabyte download) and looks up CVE IDs in its `codes`
    column. This means: (a) network cost is nontrivial versus the other
    JSON APIs — run_vuln_intel fetches it once per run and shares the
    parsed index across every observation, never once per technology; (b)
    presence of an Exploit-DB entry means a public PoC/exploit exists
    somewhere for that CVE — it is NOT evidence that PoC works against
    the specific asset being assessed, and is annotated as such.
  - CISA KEV: a CVE's presence on the KEV catalog means CISA has evidence
    it has been exploited in the wild against SOME target — this is
    real, valuable intelligence, but explicitly not target-specific
    confirmation, and is annotated as such everywhere it is surfaced.

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

MODULE_NAME = "vuln_intel.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"
_CONFIDENCE_ORDER = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}

DEFAULT_USER_AGENT = "ReconHound-VulnIntel/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 15.0

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE = "https://api.osv.dev/v1/query"
GITHUB_ADVISORIES_API = "https://api.github.com/advisories"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

NVD_API_KEY_ENV = "NVD_API_KEY"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

NVD_DEFAULT_RESULTS_PER_PAGE = 20

DEFAULT_SOURCES: Tuple[str, ...] = ("nvd", "osv", "github_advisories")
_VALID_SOURCES = set(DEFAULT_SOURCES)

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$")


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class ConfigurationError(ValueError):
    """Raised when source selection or API configuration is missing/invalid."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
# Confidence helpers
# ---------------------------------------------------------------------------

def _cap_confidence(a: Optional[str], b: Optional[str]) -> str:
    """Return the lower (less certain) of two confidence levels. Unknown/missing values default to MEDIUM."""
    a = a if a in _CONFIDENCE_ORDER else CONFIDENCE_MEDIUM
    b = b if b in _CONFIDENCE_ORDER else CONFIDENCE_MEDIUM
    return a if _CONFIDENCE_ORDER[a] <= _CONFIDENCE_ORDER[b] else b


# ---------------------------------------------------------------------------
# Best-effort version comparison (no external dependency; deliberately
# conservative — see compare_versions' docstring)
# ---------------------------------------------------------------------------

_VERSION_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def _version_key(v: str) -> List[Tuple[int, Any]]:
    key: List[Tuple[int, Any]] = []
    for token in _VERSION_TOKEN_RE.findall(v or ""):
        if token.isdigit():
            key.append((0, int(token)))
        else:
            key.append((1, token.lower()))
    return key


def compare_versions(v1: Optional[str], v2: Optional[str]) -> Optional[int]:
    """
    Best-effort version comparison: tokenizes into (numeric | alpha) runs
    and compares them positionally (e.g. "8.9p1" -> [8, 9, "p", 1]). This
    is not a full semver/CPE version-comparison implementation — it is
    intentionally simple, with no external dependency, matching this
    module's "no unnecessary dependency" convention. Returns -1/0/1, or
    None if either input is empty (never guesses).
    """
    if not v1 or not v2:
        return None
    k1, k2 = _version_key(v1), _version_key(v2)
    if k1 < k2:
        return -1
    if k1 > k2:
        return 1
    return 0


def _version_in_range(
    version: str,
    start_including: Optional[str] = None,
    start_excluding: Optional[str] = None,
    end_including: Optional[str] = None,
    end_excluding: Optional[str] = None,
) -> Optional[bool]:
    """
    True/False if `version` can be conclusively placed against the given
    bounds, or None if there are no bounds to check, or a bound could not
    be compared (never manufactures a match out of an incomparable bound).
    """
    checks: List[bool] = []
    for bound, op in (
        (start_including, ">="), (start_excluding, ">"),
        (end_including, "<="), (end_excluding, "<"),
    ):
        if not bound:
            continue
        cmp = compare_versions(version, bound)
        if cmp is None:
            return None
        if op == ">=":
            checks.append(cmp >= 0)
        elif op == ">":
            checks.append(cmp > 0)
        elif op == "<=":
            checks.append(cmp <= 0)
        elif op == "<":
            checks.append(cmp < 0)
    if not checks:
        return None
    return all(checks)


_RANGE_COND_RE = re.compile(r"(>=|<=|>|<|=)\s*([\w.\-]+)")


def _parse_version_range_string(range_str: str) -> Dict[str, str]:
    """Parse a GitHub Advisory-style range string (e.g. '>= 4.0.0, < 4.18.0') into bound kwargs for _version_in_range."""
    bounds: Dict[str, str] = {}
    for op, ver in _RANGE_COND_RE.findall(range_str or ""):
        if op == ">=":
            bounds["start_including"] = ver
        elif op == ">":
            bounds["start_excluding"] = ver
        elif op == "<=":
            bounds["end_including"] = ver
        elif op == "<":
            bounds["end_excluding"] = ver
        elif op == "=":
            bounds["start_including"] = ver
            bounds["end_including"] = ver
    return bounds


# ---------------------------------------------------------------------------
# Technology/version observation normalization
# (context.md: "Use the existing normalized technology/version data
# structures produced by the repository. Do not create a competing
# technology model.")
# ---------------------------------------------------------------------------

_TECH_NAME_KEYS = ("technology", "product", "name", "software", "framework")
_TECH_VERSION_KEYS = ("version", "product_version")


def normalize_technology_observation(obs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normalize a caller-supplied (or extracted) technology observation into
    this module's internal shape. Liberal about input key names (see
    module docstring's TECH_FINGERPRINT_INPUT_CONTRACT + _TECH_NAME_KEYS/
    _TECH_VERSION_KEYS) so this works both for active_recon.py-derived
    observations and for tech_fingerprint.py's eventual output.

    Returns None (never raises) when no usable technology name is present
    — "insufficient data" is a normal, expected outcome for versionless or
    malformed observations, not an error.
    """
    if not isinstance(obs, dict):
        return None

    technology = None
    for key in _TECH_NAME_KEYS:
        val = obs.get(key)
        if isinstance(val, str) and val.strip():
            technology = val.strip()
            break
    if not technology:
        return None

    version = None
    for key in _TECH_VERSION_KEYS:
        val = obs.get(key)
        if isinstance(val, str) and val.strip():
            version = val.strip()
            break

    confidence = obs.get("confidence")
    if confidence not in _CONFIDENCE_ORDER:
        confidence = CONFIDENCE_MEDIUM

    evidence = obs.get("evidence")
    evidence = list(evidence) if isinstance(evidence, list) else []

    return {
        "technology": technology,
        "version": version,
        "category": obs.get("category"),
        "target": obs.get("target"),
        "confidence": confidence,
        "evidence": evidence,
        "source_module": obs.get("source") or obs.get("source_module"),
        "raw_finding_type": obs.get("raw_finding_type") or obs.get("type"),
    }


# Protocol/scheme tokens that are never themselves a "product" — excluded
# from banner-derived observations so a bare "SSH"/"HTTP" match doesn't
# trigger an unusably broad, noisy CVE keyword search (module docstring,
# decision #2).
_GENERIC_PROTOCOL_TOKENS = {
    "http", "https", "ftp", "ftps", "sftp", "ssh", "smtp", "esmtp",
    "ssl", "tls", "pop3", "imap", "imap4", "ldap",
}

_LEADING_RESPONSE_CODE_RE = re.compile(r"^\d{3}[ \-]?")
_NAME_VERSION_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9.+]{1,30})[/_ ]v?(\d[\w.\-]*)")


def parse_name_version_from_text(text: Optional[str]) -> Optional[Tuple[str, str]]:
    """
    Best-effort extraction of a (product_name, version) pair from raw
    protocol banner text (e.g. "220 ProFTPD 1.3.5e Server ready.",
    "OpenSSH_8.9p1", "220 (vsFTPd 3.0.3)"). Deliberately conservative: a
    bare protocol/scheme token (see _GENERIC_PROTOCOL_TOKENS) is never
    accepted as the product name, and returns None rather than guessing
    when no plausible name/version pair is found.
    """
    if not text:
        return None
    cleaned = _LEADING_RESPONSE_CODE_RE.sub("", text.strip())
    for match in _NAME_VERSION_RE.finditer(cleaned):
        name, version = match.group(1), match.group(2)
        if name.lower() in _GENERIC_PROTOCOL_TOKENS:
            continue
        return name, version
    return None


# Finding types already written to pending_assets.json by
# already-implemented modules that carry technology/version signal, until
# tech_fingerprint.py exists (module docstring, decision #2).
_ACTIVE_RECON_TECH_FINDING_TYPES = {"ssh_fingerprint", "banner"}


def extract_observations_from_active_recon(
    store: "PendingAssetsStore",
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Read active_recon.py's already-persisted findings out of
    pending_assets.json and derive technology/version observations from
    the ones that carry parseable software/version text. Returns
    (observations, skipped_notes) — a finding that couldn't be parsed into
    a technology/version pair is recorded in skipped_notes, never silently
    dropped.
    """
    observations: List[Dict[str, Any]] = []
    skipped: List[str] = []

    try:
        records = store.all()
    except PersistenceError as exc:
        return [], [f"could not read pending_assets.json: {exc}"]

    for rec in records:
        if not isinstance(rec, dict) or rec.get("type") not in _ACTIVE_RECON_TECH_FINDING_TYPES:
            continue

        value = rec.get("value") or {}
        raw_target = rec.get("target")
        finding_type = rec["type"]
        parsed: Optional[Tuple[str, str]] = None

        if finding_type == "ssh_fingerprint" and isinstance(value.get("software"), str) and value["software"]:
            parsed = parse_name_version_from_text(value["software"])
        elif finding_type == "banner" and isinstance(value.get("banner"), str) and value["banner"]:
            parsed = parse_name_version_from_text(value["banner"])

        if parsed is None:
            skipped.append(
                f"{finding_type} finding for target {raw_target!r} did not yield a "
                f"parseable technology name/version"
            )
            continue

        name, version = parsed
        normalized = normalize_technology_observation({
            "technology": name,
            "version": version,
            "target": raw_target,
            "confidence": rec.get("confidence", CONFIDENCE_MEDIUM),
            "evidence": list(rec.get("evidence") or []) + [
                f"Derived from active_recon.py {finding_type!r} finding"
            ],
            "source": "active_recon.py",
            "raw_finding_type": finding_type,
        })
        if normalized:
            observations.append(normalized)

    return observations, skipped


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def _cpe_field(criteria: str, index: int) -> Optional[str]:
    parts = criteria.split(":")
    if len(parts) <= index:
        return None
    val = parts[index]
    return None if val in ("*", "-", "") else val


def _nvd_cve_version_match(cve_obj: Dict[str, Any], technology: str, version: Optional[str]) -> str:
    """Returns 'range_confirmed' | 'keyword_only' | 'unknown' for one NVD CVE object."""
    if not version:
        return "unknown"

    tech_norm = technology.lower().replace(" ", "").replace("-", "").replace("_", "")
    for config in cve_obj.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria") or ""
                product = _cpe_field(criteria, 4)
                if not product:
                    continue
                product_norm = product.lower().replace(" ", "").replace("-", "").replace("_", "")
                if tech_norm not in product_norm and product_norm not in tech_norm:
                    continue

                cpe_version = _cpe_field(criteria, 5)
                if cpe_version:
                    if compare_versions(version, cpe_version) == 0:
                        return "range_confirmed"
                    continue  # this cpeMatch entry names one specific, different version

                in_range = _version_in_range(
                    version,
                    start_including=match.get("versionStartIncluding"),
                    start_excluding=match.get("versionStartExcluding"),
                    end_including=match.get("versionEndIncluding"),
                    end_excluding=match.get("versionEndExcluding"),
                )
                if in_range:
                    return "range_confirmed"
    return "keyword_only"


def _extract_nvd_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {}) or {}
            severity = entries[0].get("baseSeverity") or data.get("baseSeverity")
            return data.get("baseScore"), data.get("vectorString"), severity
    return None, None, None


def query_nvd(
    technology: str,
    version: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    results_per_page: int = NVD_DEFAULT_RESULTS_PER_PAGE,
    base_url: str = NVD_API_BASE,
) -> Dict[str, Any]:
    """
    Query the NVD CVE API 2.0 via keywordSearch=<technology>, then inspect
    each returned CVE's CPE configuration data (when present) to determine
    whether `version` falls within its documented vulnerable range.
    """
    result: Dict[str, Any] = {"status": "error", "vulnerabilities": [], "error": None, "total_results": 0}
    if not technology or not technology.strip():
        result["error"] = "technology name is required"
        return result

    api_key = api_key if api_key is not None else os.environ.get(NVD_API_KEY_ENV)
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    params = {"keywordSearch": technology.strip(), "resultsPerPage": max(1, min(results_per_page, 200))}

    resp = None
    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=timeout)
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

    if resp.status_code in (403, 429):
        result["status"] = "rate_limited"
        result["error"] = f"NVD API returned HTTP {resp.status_code} (rate limited; consider supplying an API key)"
        return result
    if resp.status_code >= 500:
        result["error"] = f"NVD API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"NVD API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from NVD API: {exc}"
        return result

    if not isinstance(data, dict) or "vulnerabilities" not in data:
        result["error"] = "unexpected NVD API response structure"
        return result

    result["total_results"] = data.get("totalResults", 0)
    vulns: List[Dict[str, Any]] = []
    for item in data.get("vulnerabilities") or []:
        try:
            cve_obj = item.get("cve") or {}
            cve_id = cve_obj.get("id")
            if not cve_id:
                continue
            description = next(
                (d.get("value") for d in cve_obj.get("descriptions", []) if d.get("lang") == "en"),
                None,
            )
            cvss_score, cvss_vector, severity = _extract_nvd_cvss(cve_obj.get("metrics") or {})
            references = [r.get("url") for r in cve_obj.get("references", []) if r.get("url")]
            version_match = _nvd_cve_version_match(cve_obj, technology, version)
            evidence = f"NVD keywordSearch={technology!r} matched {cve_id}"
            if version_match == "range_confirmed":
                evidence += f"; version {version!r} falls within the CVE's documented vulnerable CPE range"
            vulns.append({
                "cve_id": cve_id,
                "summary": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "published": cve_obj.get("published"),
                "references": references,
                "source": "nvd",
                "version_match": version_match,
                "raw_evidence": evidence,
            })
        except Exception:
            continue  # one malformed entry must not abort the rest

    result["vulnerabilities"] = vulns
    result["status"] = "found" if vulns else "not_found"
    return result


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

_OSV_ECOSYSTEM_HINTS = {
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
    "jquery": "npm", "lodash": "npm", "express": "npm", "react": "npm",
    "vue": "npm", "angular": "npm", "next.js": "npm", "nextjs": "npm",
    "django": "PyPI", "flask": "PyPI", "requests": "PyPI", "fastapi": "PyPI",
    "rails": "RubyGems", "ruby on rails": "RubyGems",
    "spring": "Maven", "struts": "Maven", "log4j": "Maven",
    "laravel": "Packagist", "symfony": "Packagist",
}


def _infer_osv_ecosystem(technology: str, hint: Optional[str] = None) -> Optional[str]:
    if hint:
        return hint
    return _OSV_ECOSYSTEM_HINTS.get(technology.strip().lower())


def _extract_cve_id(primary_id: Optional[str], aliases: List[str]) -> Optional[str]:
    if primary_id and _CVE_ID_RE.match(primary_id):
        return primary_id
    for alias in aliases:
        if isinstance(alias, str) and _CVE_ID_RE.match(alias):
            return alias
    return None


def query_osv(
    technology: str,
    version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = OSV_API_BASE,
) -> Dict[str, Any]:
    """
    Query OSV's package endpoint. Requires a known package ecosystem (see
    module docstring's per-source limitations) — never guesses one.
    """
    result: Dict[str, Any] = {"status": "skipped", "vulnerabilities": [], "error": None}
    if not technology or not technology.strip():
        result["status"] = "error"
        result["error"] = "technology name is required"
        return result

    resolved_ecosystem = _infer_osv_ecosystem(technology, ecosystem)
    if not resolved_ecosystem:
        result["error"] = (
            f"OSV requires a known package ecosystem (e.g. npm, PyPI, Go, WordPress); "
            f"none could be inferred for {technology!r}"
        )
        return result

    body: Dict[str, Any] = {"package": {"name": technology.strip(), "ecosystem": resolved_ecosystem}}
    if version:
        body["version"] = version

    resp = None
    try:
        resp = requests.post(base_url, json=body, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT})
    except requests.exceptions.Timeout:
        result["status"], result["error"] = "error", "timeout"
        return result
    except requests.exceptions.ConnectionError as exc:
        result["status"], result["error"] = "error", f"connection error: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["status"], result["error"] = "error", f"request failed: {exc}"
        return result
    finally:
        if resp is not None:
            resp.close()

    if resp.status_code == 429:
        result["status"], result["error"] = "rate_limited", "HTTP 429 from OSV API"
        return result
    if resp.status_code >= 500:
        result["status"], result["error"] = "error", f"OSV API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["status"], result["error"] = "error", f"OSV API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["status"], result["error"] = "error", f"malformed JSON from OSV API: {exc}"
        return result

    if not isinstance(data, dict):
        result["status"], result["error"] = "error", "unexpected OSV API response structure"
        return result

    vulns_raw = data.get("vulns") or []
    version_match_default = "range_confirmed" if version else "unknown"
    parsed: List[Dict[str, Any]] = []
    skipped_non_cve = 0
    for v in vulns_raw:
        try:
            cve_id = _extract_cve_id(v.get("id"), v.get("aliases") or [])
            if not cve_id:
                skipped_non_cve += 1
                continue
            severities = v.get("severity") or []
            cvss_vector = severities[0].get("score") if severities else None
            references = [r.get("url") for r in (v.get("references") or []) if r.get("url")]
            evidence = f"OSV package query ({technology}, ecosystem={resolved_ecosystem}) matched {cve_id} via {v.get('id')}"
            if version:
                evidence += f"; OSV's own version filtering confirmed {version!r} is within the affected range"
            parsed.append({
                "cve_id": cve_id,
                "summary": v.get("summary") or ((v.get("details") or "")[:300] or None),
                "severity": None,
                "cvss_score": None,
                "cvss_vector": cvss_vector,
                "published": v.get("published"),
                "references": references,
                "source": "osv",
                "version_match": version_match_default,
                "raw_evidence": evidence,
            })
        except Exception:
            continue

    result["vulnerabilities"] = parsed
    result["skipped_non_cve_advisories"] = skipped_non_cve
    result["status"] = "found" if parsed else "not_found"
    return result


# ---------------------------------------------------------------------------
# GitHub Security Advisories
# ---------------------------------------------------------------------------

def query_github_advisories(
    technology: str,
    version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    token: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    per_page: int = 20,
    base_url: str = GITHUB_ADVISORIES_API,
) -> Dict[str, Any]:
    """Query GitHub's public Security Advisories REST API, filtered to advisories that carry an assigned CVE ID."""
    result: Dict[str, Any] = {"status": "error", "vulnerabilities": [], "error": None}
    if not technology or not technology.strip():
        result["error"] = "technology name is required"
        return result

    token = token if token is not None else os.environ.get(GITHUB_TOKEN_ENV)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": DEFAULT_USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params: Dict[str, Any] = {"affects": technology.strip(), "per_page": max(1, min(per_page, 100))}
    if ecosystem:
        params["ecosystem"] = ecosystem.lower()

    resp = None
    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=timeout)
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

    if resp.status_code in (401, 403):
        if resp.headers.get("X-RateLimit-Remaining") == "0":
            result["status"] = "rate_limited"
            result["error"] = "GitHub Advisories API rate limit exceeded"
        else:
            result["error"] = f"GitHub Advisories API returned HTTP {resp.status_code} (check token/auth)"
        return result
    if resp.status_code >= 500:
        result["error"] = f"GitHub Advisories API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"GitHub Advisories API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from GitHub Advisories API: {exc}"
        return result

    if not isinstance(data, list):
        result["error"] = "unexpected GitHub Advisories API response structure"
        return result

    vulns: List[Dict[str, Any]] = []
    skipped_no_cve = 0
    for advisory in data:
        try:
            cve_id = advisory.get("cve_id")
            if not cve_id:
                skipped_no_cve += 1
                continue

            version_match = "unknown"
            if version:
                version_match = "keyword_only"  # default once a version is known but unconfirmed
                for pkg_vuln in advisory.get("vulnerabilities") or []:
                    pkg_name = ((pkg_vuln.get("package") or {}).get("name") or "")
                    if pkg_name.lower() != technology.strip().lower():
                        continue
                    bounds = _parse_version_range_string(pkg_vuln.get("vulnerable_version_range") or "")
                    in_range = _version_in_range(version, **bounds) if bounds else None
                    if in_range:
                        version_match = "range_confirmed"
                        break

            cvss = advisory.get("cvss") or {}
            references = list(advisory.get("references") or [])
            if advisory.get("html_url") and advisory["html_url"] not in references:
                references.append(advisory["html_url"])

            vulns.append({
                "cve_id": cve_id,
                "summary": advisory.get("summary"),
                "severity": advisory.get("severity"),
                "cvss_score": cvss.get("score"),
                "cvss_vector": cvss.get("vector_string"),
                "published": advisory.get("published_at"),
                "references": references,
                "source": "github_advisories",
                "version_match": version_match,
                "raw_evidence": f"GitHub Security Advisory {advisory.get('ghsa_id')} (affects={technology!r}) maps to {cve_id}",
            })
        except Exception:
            continue

    result["vulnerabilities"] = vulns
    result["skipped_no_cve_advisories"] = skipped_no_cve
    result["status"] = "found" if vulns else "not_found"
    return result


# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities (KEV) catalog
# ---------------------------------------------------------------------------

def query_cisa_kev(timeout: float = DEFAULT_TIMEOUT, base_url: str = CISA_KEV_URL) -> Dict[str, Any]:
    """Fetch and normalize the full CISA KEV catalog. Intended to be fetched once per run and shared (see run_vuln_intel)."""
    result: Dict[str, Any] = {"status": "error", "entries": [], "error": None}

    resp = None
    try:
        resp = requests.get(base_url, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT})
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

    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["error"] = "HTTP 429 from CISA KEV feed"
        return result
    if resp.status_code != 200:
        result["error"] = f"CISA KEV feed returned HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from CISA KEV feed: {exc}"
        return result

    if not isinstance(data, dict) or "vulnerabilities" not in data:
        result["error"] = "unexpected CISA KEV feed structure"
        return result

    entries: List[Dict[str, Any]] = []
    for item in data.get("vulnerabilities") or []:
        if not isinstance(item, dict) or not item.get("cveID"):
            continue
        entries.append({
            "cve_id": item["cveID"],
            "vendor_project": item.get("vendorProject"),
            "product": item.get("product"),
            "vulnerability_name": item.get("vulnerabilityName"),
            "date_added": item.get("dateAdded"),
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
        })

    result["entries"] = entries
    result["status"] = "found" if entries else "not_found"
    return result


def _kev_lookup(kev_entries: List[Dict[str, Any]], cve_id: str) -> Optional[Dict[str, Any]]:
    return next((e for e in kev_entries if e.get("cve_id") == cve_id), None)


# ---------------------------------------------------------------------------
# Exploit-DB (public CSV index — see module docstring's per-source limitations)
# ---------------------------------------------------------------------------

def fetch_exploitdb_index(
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = EXPLOITDB_CSV_URL,
    preloaded_csv_text: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fetch (or accept pre-fetched, for tests/offline use) Exploit-DB's
    public files_exploits.csv index and build a {cve_id: [entry, ...]}
    lookup table from its `codes` column.
    """
    result: Dict[str, Any] = {"status": "error", "index": {}, "error": None}

    text = preloaded_csv_text
    if text is None:
        resp = None
        try:
            resp = requests.get(base_url, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT})
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
        if resp.status_code != 200:
            result["error"] = f"Exploit-DB CSV index returned HTTP {resp.status_code}"
            return result
        text = resp.text

    index: Dict[str, List[Dict[str, Any]]] = {}
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            codes = (row.get("codes") or "").split(";")
            cve_ids = [c.strip() for c in codes if _CVE_ID_RE.match(c.strip())]
            if not cve_ids:
                continue
            entry = {
                "edb_id": row.get("id"),
                "title": row.get("description"),
                "date_published": row.get("date_published"),
                "verified": row.get("verified") == "1",
            }
            for cve_id in cve_ids:
                index.setdefault(cve_id, []).append(entry)
    except Exception as exc:
        result["error"] = f"malformed Exploit-DB CSV index: {exc}"
        return result

    result["index"] = index
    result["status"] = "found" if index else "not_found"
    return result


# ---------------------------------------------------------------------------
# Multi-source aggregation
# ---------------------------------------------------------------------------

def query_all_sources(
    technology: str,
    version: Optional[str] = None,
    sources: Optional[List[str]] = None,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    osv_ecosystem: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Query every configured CVE-intelligence source for one technology +
    version pair. One source failing/erroring never prevents the others
    from being queried (context.md: "One unavailable intelligence source
    should not unnecessarily prevent other available sources from being
    processed").
    """
    sources = list(sources) if sources is not None else list(DEFAULT_SOURCES)
    invalid = [s for s in sources if s not in _VALID_SOURCES]
    if invalid:
        raise ConfigurationError(f"Unsupported source(s) {invalid}; must be a subset of {sorted(_VALID_SOURCES)}")

    all_records: List[Dict[str, Any]] = []
    source_status: Dict[str, Dict[str, Any]] = {}

    if "nvd" in sources:
        try:
            r = query_nvd(technology, version, api_key=nvd_api_key, timeout=timeout)
        except Exception as exc:
            r = {"status": "error", "vulnerabilities": [], "error": str(exc)}
        source_status["nvd"] = {"status": r["status"], "error": r.get("error")}
        all_records.extend(r.get("vulnerabilities", []))

    if "osv" in sources:
        try:
            r = query_osv(technology, version, ecosystem=osv_ecosystem, timeout=timeout)
        except Exception as exc:
            r = {"status": "error", "vulnerabilities": [], "error": str(exc)}
        source_status["osv"] = {"status": r["status"], "error": r.get("error")}
        all_records.extend(r.get("vulnerabilities", []))

    if "github_advisories" in sources:
        try:
            r = query_github_advisories(technology, version=version, ecosystem=osv_ecosystem, token=github_token, timeout=timeout)
        except Exception as exc:
            r = {"status": "error", "vulnerabilities": [], "error": str(exc)}
        source_status["github_advisories"] = {"status": r["status"], "error": r.get("error")}
        all_records.extend(r.get("vulnerabilities", []))

    return {"records": all_records, "source_status": source_status}


def _merge_vulnerability_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Merge per-source normalized vuln records by CVE ID, preserving each
    source's own evidence/version-match/CVSS data separately rather than
    silently picking one (context.md §8 conflict-preservation: sources
    disagreeing on severity is itself worth keeping visible).
    """
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    for rec in records:
        cve_id = rec.get("cve_id")
        if not cve_id:
            continue
        if cve_id not in merged:
            merged[cve_id] = {
                "cve_id": cve_id,
                "summaries": [],
                "cvss": [],
                "references": set(),
                "sources": [],
                "published": None,
                "cisa_kev": None,
                "exploitdb_references": [],
            }
            order.append(cve_id)
        m = merged[cve_id]

        if rec.get("summary") and rec["summary"] not in m["summaries"]:
            m["summaries"].append(rec["summary"])
        if rec.get("cvss_score") is not None or rec.get("cvss_vector"):
            m["cvss"].append({
                "source": rec.get("source"), "score": rec.get("cvss_score"),
                "severity": rec.get("severity"), "vector": rec.get("cvss_vector"),
            })
        for ref in rec.get("references") or []:
            if ref:
                m["references"].add(ref)
        m["sources"].append({
            "source": rec.get("source"),
            "version_match": rec.get("version_match", "unknown"),
            "evidence": rec.get("raw_evidence"),
        })
        published = rec.get("published")
        if published and (m["published"] is None or published < m["published"]):
            m["published"] = published

    results = []
    for cve_id in order:
        m = merged[cve_id]
        m["references"] = sorted(m["references"])
        results.append(m)
    return results


def annotate_kev(record: Dict[str, Any], kev_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    hit = _kev_lookup(kev_entries, record["cve_id"])
    if not hit:
        record["cisa_kev"] = None
        return record
    record["cisa_kev"] = {
        "listed": True,
        "date_added": hit.get("date_added"),
        "vulnerability_name": hit.get("vulnerability_name"),
        "known_ransomware_campaign_use": hit.get("known_ransomware_campaign_use"),
        "note": (
            "Listed in CISA's Known Exploited Vulnerabilities catalog — real-world "
            "exploitation evidence exists for this CVE against some target, but this "
            "does NOT confirm exploitability against the specific asset observed here."
        ),
    }
    return record


def annotate_exploitdb(record: Dict[str, Any], exploitdb_index: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    hits = exploitdb_index.get(record["cve_id"]) or []
    record["exploitdb_references"] = [
        {"edb_id": h.get("edb_id"), "title": h.get("title"), "verified": h.get("verified"),
         "date_published": h.get("date_published")}
        for h in hits
    ]
    return record


def _assess_applicability(record: Dict[str, Any]) -> Tuple[str, str]:
    """Returns (applicability, match_confidence) for one merged CVE record — see module docstring's VERSION-MATCH HONESTY section."""
    matches = [s.get("version_match") for s in record["sources"]]
    if "range_confirmed" in matches:
        return "version_range_confirmed", CONFIDENCE_HIGH
    if matches and all(m == "unknown" for m in matches):
        return "version_unknown_cannot_confirm", CONFIDENCE_LOW
    distinct_sources = {s.get("source") for s in record["sources"]}
    confidence = CONFIDENCE_MEDIUM if len(distinct_sources) >= 2 else CONFIDENCE_LOW
    return "keyword_match_version_unconfirmed", confidence


def format_vuln_intel_statement(technology: str, version: Optional[str], cve_id: str, applicability: str) -> str:
    """Builds the context.md-mandated 'Detected X 1.2.3 — MAY be affected by CVE-XXXX.' style statement. Never asserts confirmed exploitability."""
    version_part = f" {version}" if version else " (version unknown)"
    if applicability == "version_range_confirmed":
        return f"Detected {technology}{version_part} — MAY be affected by {cve_id} (version falls within the CVE's documented vulnerable range)."
    if applicability == "keyword_match_version_unconfirmed":
        return f"Detected {technology}{version_part} — POSSIBLY related to {cve_id} (product name matched; version applicability not confirmed)."
    return f"Detected {technology}{version_part} — {cve_id} references this product, but insufficient version information is available to assess applicability."


# ---------------------------------------------------------------------------
# Per-observation mapping (technology/version -> CVEs), persisted
# ---------------------------------------------------------------------------

def map_technology_to_cves(
    observation: Dict[str, Any],
    store: Optional[PendingAssetsStore] = None,
    source_results: Optional[Dict[str, Any]] = None,
    kev_entries: Optional[List[Dict[str, Any]]] = None,
    exploitdb_index: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    sources: Optional[List[str]] = None,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    osv_ecosystem: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    include_kev: bool = True,
    include_exploitdb: bool = True,
) -> Dict[str, Any]:
    """
    Map one normalized technology observation to known CVEs across every
    configured source, and persist one "vulnerability_intelligence"
    finding per matched CVE. `source_results`/`kev_entries`/
    `exploitdb_index` may be pre-fetched by the caller (see
    run_vuln_intel) to share one shared-feed fetch across many
    observations instead of re-querying per call.
    """
    result: Dict[str, Any] = {
        "technology": None, "version": None, "target": None,
        "status": "insufficient_data", "vulnerabilities": [],
        "source_status": {}, "errors": [],
    }

    norm = normalize_technology_observation(observation)
    if norm is None:
        result["errors"].append("observation has no usable technology/product name; skipped")
        return result

    technology, version, target = norm["technology"], norm.get("version"), norm.get("target")
    result.update({"technology": technology, "version": version, "target": target})

    if source_results is None:
        try:
            source_results = query_all_sources(
                technology, version, sources=sources, nvd_api_key=nvd_api_key,
                github_token=github_token, osv_ecosystem=osv_ecosystem, timeout=timeout,
            )
        except ConfigurationError as exc:
            result["errors"].append(str(exc))
            return result
    result["source_status"] = dict(source_results.get("source_status", {}))

    if kev_entries is None and include_kev:
        kev_result = query_cisa_kev(timeout=timeout)
        kev_entries = kev_result.get("entries", [])
        result["source_status"]["cisa_kev"] = {"status": kev_result["status"], "error": kev_result.get("error")}
    kev_entries = kev_entries or []

    if exploitdb_index is None and include_exploitdb:
        exploitdb_result = fetch_exploitdb_index(timeout=timeout)
        exploitdb_index = exploitdb_result.get("index", {})
        result["source_status"]["exploitdb"] = {"status": exploitdb_result["status"], "error": exploitdb_result.get("error")}
    exploitdb_index = exploitdb_index or {}

    merged = _merge_vulnerability_records(source_results.get("records", []))

    for rec in merged:
        applicability, match_confidence = _assess_applicability(rec)
        final_confidence = _cap_confidence(norm.get("confidence"), match_confidence)
        rec = annotate_kev(rec, kev_entries)
        rec = annotate_exploitdb(rec, exploitdb_index)
        statement = format_vuln_intel_statement(technology, version, rec["cve_id"], applicability)

        vuln_record = {
            "cve_id": rec["cve_id"],
            "technology": technology,
            "version": version,
            "target": target,
            "statement": statement,
            "applicability": applicability,
            "confidence": final_confidence,
            "summaries": rec["summaries"],
            "cvss": rec["cvss"],
            "references": rec["references"],
            "published": rec["published"],
            "matched_sources": rec["sources"],
            "cisa_kev": rec["cisa_kev"],
            "exploitdb_references": rec["exploitdb_references"],
            "detection_evidence": norm.get("evidence", []),
            "note": "Technology/version-to-CVE match is vulnerability intelligence, not confirmed exploitability against this target.",
        }
        result["vulnerabilities"].append(vuln_record)

        evidence = [f"{s['source']} matched {rec['cve_id']} ({s['version_match']})" for s in rec["sources"]]
        if rec["cisa_kev"]:
            evidence.append("Listed in CISA KEV catalog (exploited in the wild for some target; not target-specific confirmation)")
        if rec["exploitdb_references"]:
            evidence.append(
                f"{len(rec['exploitdb_references'])} Exploit-DB reference(s) exist for this CVE "
                f"(a public PoC/exploit is known to exist; this is not evidence it was used against this target)"
            )
        err = _safe_store_add(store, make_finding(
            finding_type="vulnerability_intelligence",
            target=target or technology,
            value=vuln_record,
            evidence=evidence,
            confidence=final_confidence,
            metadata={
                "technology": technology, "version": version, "cve_id": rec["cve_id"],
                "applicability": applicability, "cisa_kev_listed": bool(rec["cisa_kev"]),
                "exploitdb_reference_count": len(rec["exploitdb_references"]),
            },
        ))
        if err:
            result["errors"].append(err)

    all_sources_unusable = bool(result["source_status"]) and all(
        s.get("status") in ("error", "rate_limited", "unavailable", "skipped")
        for s in result["source_status"].values()
    )

    if merged:
        result["status"] = "found"
    elif all_sources_unusable:
        result["status"] = "sources_unavailable"
    else:
        result["status"] = "not_found"
        err = _safe_store_add(store, make_finding(
            finding_type="vuln_intel_checked_no_match",
            target=target or technology,
            value={"technology": technology, "version": version},
            evidence=[
                f"No known CVE found for {technology} {version or '(version unknown)'} "
                f"across queried sources as of this check"
            ],
            confidence=CONFIDENCE_LOW,
            metadata={
                "technology": technology, "version": version, "checked_at": _now(),
                "note": (
                    "Negative-result-memory: absence of a match today does not guarantee no "
                    "future match, since vulnerability databases are updated continuously."
                ),
            },
        ))
        if err:
            result["errors"].append(err)

    return result


# ---------------------------------------------------------------------------
# Module orchestration
# ---------------------------------------------------------------------------

def run_vuln_intel(
    output_dir: str = "output",
    technology_observations: Optional[List[Dict[str, Any]]] = None,
    include_active_recon: bool = True,
    sources: Optional[List[str]] = None,
    include_kev: bool = True,
    include_exploitdb: bool = True,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Run Module 19 across every available technology/version observation
    and persist every match immediately to <output_dir>/pending_assets.json.

    Observations come from two places (module docstring, input-contract
    decision): active_recon.py's already-persisted findings (when
    `include_active_recon`), and/or a caller-supplied
    `technology_observations` list — the hand-off point tech_fingerprint.py
    will use once it exists.

    CISA KEV and the Exploit-DB index are each fetched at most ONCE per
    run and shared across every observation (module docstring's
    per-source Exploit-DB limitation) rather than re-fetched per
    technology. External CVE-source queries (NVD/OSV/GHSA) are cached
    per unique (technology, version) pair within the run to avoid
    redundant API calls when multiple observations name the same
    technology/version on different targets.
    """
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "module": MODULE_NAME,
        "started_at": _now(),
        "extraction_errors": [],
        "skipped_observations": [],
        "results": [],
        "cisa_kev_status": None,
        "exploitdb_status": None,
        "stats": {},
        "errors": [],
    }

    observations: List[Dict[str, Any]] = []

    if include_active_recon:
        extracted, extraction_errors = extract_observations_from_active_recon(store)
        observations.extend(extracted)
        summary["extraction_errors"] = extraction_errors

    for raw_obs in (technology_observations or []):
        norm = normalize_technology_observation(raw_obs)
        if norm is None:
            summary["skipped_observations"].append(raw_obs)
            continue
        observations.append(norm)

    if not observations:
        summary["finished_at"] = _now()
        summary["stats"] = {"observations": 0, "vulnerabilities_found": 0}
        return summary

    kev_entries: List[Dict[str, Any]] = []
    if include_kev:
        kev_result = query_cisa_kev(timeout=timeout)
        kev_entries = kev_result.get("entries", [])
        summary["cisa_kev_status"] = {"status": kev_result["status"], "error": kev_result.get("error")}
        if kev_result["status"] == "error":
            summary["errors"].append({"stage": "cisa_kev", "error": kev_result.get("error")})

    exploitdb_index: Dict[str, List[Dict[str, Any]]] = {}
    if include_exploitdb:
        exploitdb_result = fetch_exploitdb_index(timeout=timeout)
        exploitdb_index = exploitdb_result.get("index", {})
        summary["exploitdb_status"] = {"status": exploitdb_result["status"], "error": exploitdb_result.get("error")}
        if exploitdb_result["status"] == "error":
            summary["errors"].append({"stage": "exploitdb", "error": exploitdb_result.get("error")})

    query_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}
    vulnerabilities_found = 0

    for obs in observations:
        cache_key = (obs["technology"].lower(), obs.get("version") or "")
        if cache_key not in query_cache:
            try:
                query_cache[cache_key] = query_all_sources(
                    obs["technology"], obs.get("version"), sources=sources,
                    nvd_api_key=nvd_api_key, github_token=github_token, timeout=timeout,
                )
            except ConfigurationError as exc:
                summary["errors"].append({"stage": "query_all_sources", "error": str(exc)})
                continue

        outcome = map_technology_to_cves(
            obs, store=store, source_results=query_cache[cache_key],
            kev_entries=kev_entries, exploitdb_index=exploitdb_index,
            include_kev=include_kev, include_exploitdb=include_exploitdb, timeout=timeout,
        )
        summary["results"].append(outcome)
        vulnerabilities_found += len(outcome.get("vulnerabilities", []))

    summary["stats"] = {
        "observations": len(observations),
        "unique_technology_version_pairs": len(query_cache),
        "vulnerabilities_found": vulnerabilities_found,
    }
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="vuln_intel.py",
        description="ReconHound Module 19 — technology-to-CVE mapping (standalone test entry point).",
    )
    parser.add_argument("--output-dir", default="output", help="Directory containing/for pending_assets.json")
    parser.add_argument("--technology", default=None, help="Query a single technology directly (e.g. 'nginx')")
    parser.add_argument("--version", default=None, help="Version for --technology (optional)")
    parser.add_argument("--no-active-recon", action="store_true", help="Skip auto-extraction from active_recon.py findings")
    parser.add_argument("--no-kev", action="store_true", help="Skip the CISA KEV cross-check")
    parser.add_argument("--no-exploitdb", action="store_true", help="Skip the Exploit-DB cross-check")
    parser.add_argument("--sources", default=None, help=f"Comma-separated subset of {sorted(_VALID_SOURCES)}")
    parser.add_argument("--nvd-api-key", default=None, help=f"NVD API key (or set {NVD_API_KEY_ENV})")
    parser.add_argument("--github-token", default=None, help=f"GitHub token (or set {GITHUB_TOKEN_ENV})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-query network timeout (seconds)")
    args = parser.parse_args()

    sources = [s.strip() for s in args.sources.split(",")] if args.sources else None
    technology_observations = None
    if args.technology:
        technology_observations = [{"technology": args.technology, "version": args.version, "source": "cli"}]

    result = run_vuln_intel(
        output_dir=args.output_dir,
        technology_observations=technology_observations,
        include_active_recon=not args.no_active_recon,
        sources=sources,
        include_kev=not args.no_kev,
        include_exploitdb=not args.no_exploitdb,
        nvd_api_key=args.nvd_api_key,
        github_token=args.github_token,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
