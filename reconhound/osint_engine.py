"""
reconhound/osint_engine.py — ReconHound Module 4 (osint_engine.py, catalog
position 4; build-order position 20).

Phase: Passive. See context.md §10 (module 4, "OSINT/digital footprint")
for the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "OSINT/digital footprint. Email harvesting (search engines + CT logs),
  email pattern inference, naming-convention inference, inferred employee
  lists, Google dorking, HIBP breach correlation, DNS history, reverse IP
  intel, paste intel, job-posting tech-stack inference, ASN neighbor
  analysis. Inferred data must be clearly marked as inferred, not fact."

That expands into eleven discrete responsibilities, each implemented below:

  1.  Email harvesting — search engines   -> harvest_search_engine_emails
  1.  Email harvesting — CT logs          -> harvest_ct_emails (+
                                              query_crtsh_certificates,
                                              fetch_crtsh_certificate_pem,
                                              extract_emails_from_certificate_pem)
  2.  Email-pattern inference             -> infer_email_patterns,
                                              persist_email_pattern_findings
  3.  Naming-convention inference         -> persist_naming_convention_finding
  4.  Employee-list generation (inferred) -> generate_employee_inferences,
                                              persist_employee_findings
  5.  Google dork automation              -> DEFAULT_DORK_QUERIES,
                                              _run_query_batch, persist_search_hits
  6.  HIBP breach correlation             -> query_hibp_domain_breaches,
                                              query_hibp_account_breaches
  7.  DNS history                         -> query_securitytrails_dns_history
  8.  Reverse-IP intelligence             -> query_hackertarget_reverse_ip
  9.  Paste/public-text intelligence      -> DEFAULT_PASTE_QUERIES (reuses
                                              the Google dork mechanism,
                                              scoped to known paste-site
                                              domains)
  10. Job-posting tech-stack inference    -> DEFAULT_JOB_SEARCH_QUERIES,
                                              infer_tech_from_hits
  11. ASN neighbor analysis               -> query_bgpview_asn_peers

Plus shared plumbing: make_finding, PendingAssetsStore, _safe_store_add
(duplicated per modular independence, same as every other implemented
module), and a single-target orchestrator run_osint_engine (mirroring the
run_passive_recon / run_wayback_intel / run_passive_intel / run_code_leak
precedent).

BUILD-ORDER NOTE: context.md §13 lists this module at build-order position
20, after surface_mapper.py (position 8) and after passive_intel.py (15),
code_leak.py (16), tech_fingerprint.py (17), js_analyzer.py (18) and
screenshot.py (19) — all of which already exist in this repository except
surface_mapper.py. Per those modules' docstrings, this repository is
already operating under an explicit, user-approved deviation from the
surface_mapper-first ordering — surface_mapper.py has not been implemented
yet. This module continues under the same deviation, for the same reason:
it is implemented as a fully standalone producer that does not implement,
replace, or depend on surface_mapper.py's correlation engine, and does not
touch any other unimplemented module (risk_engine.py, core/orchestrator.py,
reconhound.py, vhost_scanner.py, api_recon.py, supply_chain.py).

PASSIVE BOUNDARY: this module's only network interactions are with public,
third-party intelligence services — crt.sh (Certificate Transparency log
aggregator), Google's Custom Search JSON API, the HIBP breach-notification
API, SecurityTrails' passive-DNS history API, HackerTarget's reverse-IP
lookup API, and BGPView's public BGP/ASN metadata API. This module never
sends a request to the target itself: no port scanning, no HTTP requests
to target-owned hosts, no DNS enumeration against target nameservers, no
crawling of target-owned pages. Every discovery is therefore either (a) a
historical/third-party-indexed OBSERVATION made by one of those services,
or (b) an explicitly labeled INFERENCE this module derives from those
observations — never a live probe of the target's own infrastructure.

CRITICAL DATA DISTINCTION (context.md, assignment brief): every finding
below carries `metadata.observed` (True) XOR `metadata.inferred` (True).
Observed: an email directly returned by a CT-log certificate or a search
engine result; a dork/paste hit a search engine actually indexed; a HIBP
breach record; a DNS-history record; a reverse-IP co-hosted domain; a BGP
peer ASN. Inferred: an email-format pattern, an org naming convention, an
"employee" identity guessed from an email's local part, or a technology
mention scraped from a job posting. Inferred findings are never persisted
with a confidence above LOW for individual-identity claims (employees) —
see input-contract decision #5 below — and every inferred finding's
metadata/evidence text says "inferred"/"probable"/"guess", never "is".

CREDENTIAL HANDLING (mirrors passive_intel.py/code_leak.py's established
convention): every third-party API below is independently, optionally
configured. A missing credential is reported as its own explicit
"missing_credentials" status for that source only — never raised as an
exception, never silently treated as "not_found", and never allowed to
abort any other source. Running this module with zero credentials
configured still completes successfully: CT-log email harvesting (no
credential required) and HIBP domain-breach lookup (no credential
required) still run; everything gated on Google/HIBP-account/
SecurityTrails credentials is skipped with a clear reason.

  - crt.sh (CT logs):           no credential — always usable.
  - Google Custom Search:       GOOGLE_API_KEY + GOOGLE_CSE_ID (both
                                 mandatory; the API does not function
                                 without them). Gates responsibilities 1
                                 (search-engine email harvesting), 5
                                 (dorking), 9 (paste intel) and 10
                                 (job-posting tech inference) — see
                                 input-contract decision #1.
  - HIBP domain breaches:       no credential — always usable.
  - HIBP account breaches:      HIBP_API_KEY (mandatory; HIBP does not
                                 serve unauthenticated account lookups).
  - SecurityTrails DNS history: SECURITYTRAILS_API_KEY (mandatory).
  - HackerTarget reverse-IP:    no credential required for the free tier;
                                 HACKERTARGET_API_KEY optionally raises the
                                 rate limit.
  - BGPView ASN peers:          no credential — always usable.

NEGATIVE-RESULT MEMORY (context.md §8/§12.6): every check that completes
successfully but yields zero results is recorded via one
`osint_engine_checked_no_result` finding per check (mirroring
passive_intel.py's `passive_intel_checked_no_data` /
code_leak.py's `code_leak_checked_no_match` precedent) rather than silence
— absence of a hit from any one of these third-party indexes/services is
never proof the underlying fact doesn't exist.

INPUT-CONTRACT DECISIONS (ambiguities resolved so implementation can
proceed without inventing a competing asset model or an unapproved new
architecture component, mirroring the precedent set by
passive_intel.py/code_leak.py/wayback_intel.py for the same
surface_mapper.py gap):

  1. A single search-engine provider (Google's Custom Search JSON API) is
     used to satisfy four distinct contract responsibilities — search-
     engine email harvesting, Google dork automation, paste-site
     intelligence (dorks scoped to known paste-site domains), and
     job-posting tech-stack inference (dorks scoped to known job-board
     domains). All four are read-only, indexed-result queries against the
     *same* API; introducing a second/third search API (e.g. Bing, a
     dedicated Pastebin scraper) for what is architecturally the same
     "run a scoped search query, read back indexed results" operation
     would be an unnecessary dependency (CLAUDE.md rule 11) for no
     functional gain. This module never scrapes a search engine's raw
     HTML results page directly (fragile, ToS-risk, no structured
     status/error signal) — only the documented JSON API.
  2. Certificate Transparency email harvesting parses each candidate
     certificate's Subject `emailAddress` attribute and Subject
     Alternative Name `rfc822Name` (RFC822/email SAN) entries using the
     `cryptography` library already a project dependency (see
     ssl_analyzer.py's identical `x509`/`NameOID` usage) — crt.sh's JSON
     listing endpoint does not itself expose parsed email fields, only
     `name_value` (hostnames), so each candidate cert's PEM is fetched
     individually via crt.sh's `?d=<id>` endpoint. This is bounded by
     `max_ct_certs` (default 15) to keep runtime and crt.sh load
     reasonable for popular domains that may have thousands of logged
     certificates; a per-certificate parse failure is skipped, never
     fatal to the run.
  3. Reverse-IP intelligence and ASN neighbor analysis need a
     representative seed IP/ASN for the target. Rather than invent a
     second asset model to stand in for surface_mapper.py (not yet
     implemented), `load_seed_data()` reads the first usable IP from
     passive_recon.py's already-persisted `dns_record` (A/AAAA) findings,
     and the first usable ASN from passive_recon.py's already-persisted
     `asn` findings, in <output_dir>/pending_assets.json — mirroring
     passive_intel.py's `load_seed_hosts` precedent. A caller-supplied
     `seed_ip`/`seed_asn` always takes precedence. Only a single
     representative IP/ASN is used (not every discovered IP) to keep this
     module's scope and third-party call volume bounded; callers needing
     broader coverage can invoke `query_hackertarget_reverse_ip` /
     `query_bgpview_asn_peers` directly per IP/ASN.
  4. ASN "neighbor" is read as its literal BGP meaning — a directly
     peering Autonomous System (BGPView's `/asn/{asn}/peers` endpoint) —
     rather than "every other prefix announced under the same ASN"
     (`/asn/{asn}/prefixes`), since the assignment brief's wording ("ASN
     neighbor analysis") maps directly onto that established networking
     term and BGPView exposes it as a first-class, free, unauthenticated
     endpoint.
  5. Employee-identity inference (context.md's explicit "Employee identity
     inferred from public sources → inferred" example) is always
     persisted at CONFIDENCE_LOW, regardless of how consistent the
     underlying naming-convention signal is — unlike a naming-convention
     finding (a statistical/organizational statement, which *can* reach
     HIGH confidence with enough converging examples), an employee record
     is a claim about one specific real person. Overclaiming there is a
     materially different and more sensitive kind of error, so this
     module deliberately never escalates it. This module never attempts
     to extract candidate person-names from free-text search snippets
     (unreliable NER without a dedicated model, high false-positive
     rate) — every employee record is derived solely by splitting an
     already-observed email's local part according to the inferred
     naming-convention pattern; local parts that cannot be reliably split
     (e.g. concatenated `flast`/`firstlast` forms) still produce an
     employee record, with `probable_name: null` and a note explaining
     why, rather than being silently dropped.
  6. Reverse-IP results are, by construction, mostly OTHER organizations'
     domains sharing the same host — that is the entire point of the
     technique (identifying shared-hosting risk/neighbors). Every
     `osint_engine_reverse_ip` finding is therefore explicitly tagged
     `in_scope` (True only if the returned domain is the target itself or
     a subdomain) so downstream consumers never mistake a co-hosted
     third-party domain for a target-owned asset (context.md §9, strict
     scope enforcement).

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store used by
every other implemented module, sharing the same output file). Output is
intended to feed surface_mapper.py (module 6, not yet implemented) — this
module does not implement or call into surface_mapper, active_recon,
tech_fingerprint, vhost_scanner, api_recon, js_analyzer, supply_chain,
http_analyzer, ssl_analyzer, screenshot, vuln_intel, risk_engine,
report_generator, orchestrator, or any other module not already
implemented.

DISCOVERY != EXPLOITATION: this module never authenticates to a
discovered service, never validates a breached credential against any
live system, never fetches/downloads the full content of a discovered
paste or dorked document, and never follows a discovered URL beyond what
the search engine/CT-log/breach-database API itself already returned.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

MODULE_NAME = "osint_engine.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_USER_AGENT = "ReconHound-OSINTEngine/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 15.0
DEFAULT_REQUEST_DELAY = 1.2  # seconds between successive third-party API calls (courtesy rate limiting)

GOOGLE_API_KEY_ENV = "GOOGLE_API_KEY"
GOOGLE_CSE_ID_ENV = "GOOGLE_CSE_ID"
HIBP_API_KEY_ENV = "HIBP_API_KEY"
SECURITYTRAILS_API_KEY_ENV = "SECURITYTRAILS_API_KEY"
HACKERTARGET_API_KEY_ENV = "HACKERTARGET_API_KEY"

CRTSH_API_BASE = "https://crt.sh/"
GOOGLE_CSE_API_BASE = "https://www.googleapis.com/customsearch/v1"
HIBP_BREACHES_API = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_BREACHED_ACCOUNT_API = "https://haveibeenpwned.com/api/v3/breachedaccount"
SECURITYTRAILS_HISTORY_API = "https://api.securitytrails.com/v1/history"
HACKERTARGET_REVERSE_IP_API = "https://api.hackertarget.com/reverseiplookup/"
BGPVIEW_API_BASE = "https://api.bgpview.io"

DEFAULT_DNS_HISTORY_RECORD_TYPES: Tuple[str, ...] = ("a", "mx", "ns")

# Target-scoped Google dork queries (input-contract decision #1, responsibility 5).
DEFAULT_DORK_QUERIES: Tuple[Tuple[str, str], ...] = (
    ("exposed_pdf", "site:{target} filetype:pdf"),
    ("exposed_spreadsheets", "site:{target} filetype:xls OR filetype:xlsx"),
    ("exposed_documents", "site:{target} filetype:doc OR filetype:docx"),
    ("exposed_sql", "site:{target} filetype:sql"),
    ("exposed_log", "site:{target} filetype:log"),
    ("exposed_env", "site:{target} filetype:env"),
    ("directory_listing", 'site:{target} intitle:"index of"'),
    ("admin_panel", "site:{target} inurl:admin"),
    ("login_pages", "site:{target} inurl:login"),
    ("backup_files", "site:{target} (inurl:backup OR inurl:.bak)"),
    ("confidential_docs", 'site:{target} intext:"confidential" filetype:pdf'),
    ("swagger_docs", "site:{target} inurl:swagger"),
)

# Known paste-site domains (responsibility 9, input-contract decision #1).
PASTE_SITE_DOMAINS: Tuple[str, ...] = (
    "pastebin.com", "paste.ee", "ghostbin.com", "justpaste.it", "controlc.com",
)
DEFAULT_PASTE_QUERIES: Tuple[Tuple[str, str], ...] = tuple(
    (f"paste_{d.split('.')[0]}", f'site:{d} "{{target}}"') for d in PASTE_SITE_DOMAINS
)

# Known job-board domains (responsibility 10, input-contract decision #1).
JOB_BOARD_DOMAINS: Tuple[str, ...] = (
    "indeed.com", "linkedin.com/jobs", "lever.co", "greenhouse.io", "glassdoor.com",
)
DEFAULT_JOB_SEARCH_QUERIES: Tuple[Tuple[str, str], ...] = tuple(
    (f"job_{d.split('.')[0]}", f'site:{d} "{{target}}"') for d in JOB_BOARD_DOMAINS
)

# Curated technology keyword catalog for job-posting tech-stack inference.
TECH_KEYWORDS: Tuple[str, ...] = tuple(sorted(set([
    "Python", "Django", "Flask", "FastAPI", "Java", "Spring", "Kotlin", "Go", "Golang",
    "Ruby", "Rails", "PHP", "Laravel", "Node.js", "Express", "React", "Angular", "Vue",
    "TypeScript", "AWS", "Azure", "GCP", "Google Cloud", "Kubernetes", "Docker",
    "Terraform", "PostgreSQL", "MySQL", "MongoDB", "Redis", "Elasticsearch", "Kafka",
    "GraphQL", "gRPC", "Jenkins", "Salesforce", "SAP", "Oracle", "Snowflake", "Spark",
    "Hadoop", "TensorFlow", "PyTorch",
])))

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Finding types already written to pending_assets.json by passive_recon.py,
# used as seed data (input-contract decision #3).
_SEED_HOST_FINDING_TYPE = "dns_record"
_SEED_HOST_RECORD_TYPES = ("A", "AAAA")
_SEED_ASN_FINDING_TYPE = "asn"


class ScopeError(ValueError):
    """Raised when a target falls outside this module's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truncate(text: str, limit: int = 300) -> str:
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit] + "…"


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors passive_recon.py's/passive_intel.py's/
# code_leak.py's validate_target/is_in_scope; duplicated per modular
# independence, context.md §12.2)
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_target(target: str) -> str:
    """
    Validate that `target` is a syntactically valid, explicit domain name.

    osint_engine operates on exactly one explicit target domain per
    invocation and never expands to unrelated hosts/orgs. Raises
    ScopeError on anything that is not a plausible bare domain name (URLs,
    IPs, wildcards, empty input).
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
# Seed data (input-contract decision #3)
# ---------------------------------------------------------------------------

def load_seed_data(
    store: Optional[PendingAssetsStore],
    target: str,
    extra_ip: Optional[str] = None,
    extra_asn: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """
    Resolve one representative seed IP and one representative seed ASN for
    `target`, used by reverse-IP intelligence and ASN neighbor analysis.
    Caller-supplied values always take precedence; otherwise the first
    usable value is read from passive_recon.py's already-persisted
    `dns_record` (A/AAAA) and `asn` findings. Never contacts the target.
    """
    ip = _valid_ip(extra_ip) if extra_ip else None
    asn = str(extra_asn).strip() if extra_asn else None

    if (ip is None or asn is None) and store is not None:
        try:
            records = store.all()
        except PersistenceError:
            records = []
        for rec in records:
            if not isinstance(rec, dict) or rec.get("target") != target:
                continue
            if ip is None and rec.get("type") == _SEED_HOST_FINDING_TYPE:
                value = rec.get("value") or {}
                if isinstance(value, dict) and value.get("record_type") in _SEED_HOST_RECORD_TYPES:
                    for addr in value.get("records") or []:
                        cand = _valid_ip(addr)
                        if cand:
                            ip = cand
                            break
            if asn is None and rec.get("type") == _SEED_ASN_FINDING_TYPE:
                value = rec.get("value") or {}
                if isinstance(value, dict) and value.get("asn"):
                    asn = str(value["asn"]).strip()
            if ip is not None and asn is not None:
                break

    return {"ip": ip, "asn": asn}


# ---------------------------------------------------------------------------
# Email extraction / normalization helpers
# ---------------------------------------------------------------------------

def extract_emails_from_text(text: Optional[str], domain: str) -> List[str]:
    """Extract in-scope (target or subdomain) email addresses from free text."""
    if not text:
        return []
    found: Set[str] = set()
    for m in EMAIL_RE.finditer(text):
        email = m.group(0).lower()
        email_domain = email.rsplit("@", 1)[-1]
        if is_in_scope(email_domain, domain):
            found.add(email)
    return sorted(found)


def merge_email_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Dedupe raw {"email", "source"} records by lowercase email address.
    Convergence across independent sources raises confidence from MEDIUM
    to HIGH (context.md §8).
    """
    merged: Dict[str, Set[str]] = {}
    order: List[str] = []
    for r in records:
        email = (r.get("email") or "").strip().lower()
        if not email or "@" not in email:
            continue
        if email not in merged:
            merged[email] = set()
            order.append(email)
        merged[email].add(r.get("source") or "unknown")

    results = []
    for email in order:
        sources = sorted(merged[email])
        results.append({
            "email": email,
            "sources": sources,
            "confidence": CONFIDENCE_HIGH if len(sources) > 1 else CONFIDENCE_MEDIUM,
        })
    return sorted(results, key=lambda r: r["email"])


def persist_emails(merged: List[Dict[str, Any]], target: str, store: Optional[PendingAssetsStore]) -> List[str]:
    """Persist one `osint_engine_email` finding per observed email address."""
    errors: List[str] = []
    for rec in merged:
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_email",
            target=target,
            value={
                "email": rec["email"],
                "local_part": rec["email"].split("@")[0],
                "domain": rec["email"].rsplit("@", 1)[-1],
                "discovered_via": rec["sources"],
            },
            evidence=[f"Email address {rec['email']} directly observed via: {', '.join(rec['sources'])}"],
            confidence=rec["confidence"],
            metadata={"observed": True, "inferred": False, "discovered_via": rec["sources"]},
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# 1a. Email harvesting — Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

def query_crtsh_certificates(
    domain: str, timeout: float = DEFAULT_TIMEOUT, base_url: str = CRTSH_API_BASE
) -> Dict[str, Any]:
    """
    List certificates crt.sh has logged for `%.{domain}` via its public
    JSON search endpoint. No credential required.

    Returns {"status": "found"|"not_found"|"error", "entries": [...], "error": str|None}.
    """
    result: Dict[str, Any] = {"status": "error", "entries": [], "error": None}
    resp = None
    try:
        resp = requests.get(
            base_url, params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT},
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

    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["error"] = "HTTP 429 Too Many Requests from crt.sh"
        return result
    if resp.status_code >= 500:
        result["error"] = f"crt.sh returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"crt.sh returned unexpected HTTP {resp.status_code}"
        return result

    text = (resp.text or "").strip()
    if not text:
        result["status"] = "not_found"
        return result

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result["error"] = f"malformed JSON from crt.sh: {exc}"
        return result

    if not isinstance(data, list):
        result["error"] = "unexpected crt.sh response structure (not a JSON array)"
        return result

    result["entries"] = data
    result["status"] = "found" if data else "not_found"
    return result


def fetch_crtsh_certificate_pem(
    cert_id: Any, timeout: float = DEFAULT_TIMEOUT, base_url: str = CRTSH_API_BASE
) -> Dict[str, Any]:
    """Fetch one certificate's PEM text from crt.sh via ?d=<id>."""
    result: Dict[str, Any] = {"status": "error", "pem": None, "error": None}
    resp = None
    try:
        resp = requests.get(
            base_url, params={"d": cert_id}, timeout=timeout,
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
    if resp.status_code >= 500:
        result["error"] = f"crt.sh returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"crt.sh returned unexpected HTTP {resp.status_code}"
        return result

    text = resp.text or ""
    if "BEGIN CERTIFICATE" not in text:
        result["error"] = "crt.sh did not return a PEM certificate"
        return result

    result["status"] = "found"
    result["pem"] = text
    return result


def extract_emails_from_certificate_pem(pem_text: str, domain: str) -> List[str]:
    """
    Parse a certificate's Subject emailAddress attribute and Subject
    Alternative Name rfc822Name entries (input-contract decision #2).
    Never raises — a malformed/unparseable certificate yields [].
    """
    try:
        cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"), default_backend())
    except Exception:
        return []

    emails: Set[str] = set()
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS):
            if isinstance(attr.value, str) and attr.value:
                emails.add(attr.value.lower())
    except Exception:
        pass

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value.get_values_for_type(x509.RFC822Name):
            if name:
                emails.add(name.lower())
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    return sorted(e for e in emails if is_in_scope(e.rsplit("@", 1)[-1], domain))


def harvest_ct_emails(domain: str, timeout: float = DEFAULT_TIMEOUT, max_certs: int = 15) -> Dict[str, Any]:
    """
    Orchestrate CT-log email harvesting: list candidate certificates, fetch
    up to `max_certs` unique certificate PEMs, and extract in-scope emails.
    A single certificate fetch/parse failure is skipped, never fatal.
    """
    result: Dict[str, Any] = {"status": "error", "emails": [], "error": None, "certs_inspected": 0}

    try:
        listing = query_crtsh_certificates(domain, timeout=timeout)
    except Exception as exc:
        result["error"] = str(exc)
        return result

    result["status"] = listing["status"]
    result["error"] = listing.get("error")
    if listing["status"] != "found":
        return result

    seen_ids: List[Any] = []
    for entry in listing["entries"]:
        if not isinstance(entry, dict):
            continue
        cid = entry.get("id")
        if cid is None or cid in seen_ids:
            continue
        seen_ids.append(cid)
        if len(seen_ids) >= max_certs:
            break

    emails: Set[str] = set()
    inspected = 0
    for cid in seen_ids:
        try:
            pem_result = fetch_crtsh_certificate_pem(cid, timeout=timeout)
        except Exception:
            continue
        if pem_result["status"] != "found":
            continue
        inspected += 1
        try:
            for e in extract_emails_from_certificate_pem(pem_result["pem"], domain):
                emails.add(e)
        except Exception:
            continue

    result["certs_inspected"] = inspected
    result["emails"] = sorted(emails)
    result["status"] = "found" if emails else "not_found"
    return result


# ---------------------------------------------------------------------------
# Google Custom Search JSON API (input-contract decision #1) — shared by
# responsibilities 1 (search-engine email harvesting), 5 (dorking),
# 9 (paste intel) and 10 (job-posting tech inference).
# ---------------------------------------------------------------------------

def _classify_google_status(resp: "requests.Response") -> Optional[Tuple[str, Optional[str]]]:
    if resp.status_code == 400:
        msg = "Google Custom Search API rejected the request (HTTP 400)"
        try:
            body = resp.json()
            err = body.get("error") if isinstance(body, dict) else None
            if isinstance(err, dict) and err.get("message"):
                msg = f"Google Custom Search API rejected the request: {err['message']}"
        except ValueError:
            pass
        return "invalid_query", msg

    if resp.status_code == 403:
        reason = None
        try:
            body = resp.json()
            errs = (body.get("error") or {}).get("errors") if isinstance(body, dict) else None
            if isinstance(errs, list) and errs and isinstance(errs[0], dict):
                reason = errs[0].get("reason")
        except ValueError:
            pass
        if reason in ("dailyLimitExceeded", "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"):
            return "rate_limited", f"Google Custom Search API quota/rate limit exceeded (reason={reason})"
        return "forbidden", "Google Custom Search API returned HTTP 403 (check API key/CSE restrictions)"

    if resp.status_code == 429:
        return "rate_limited", "HTTP 429 Too Many Requests from Google Custom Search API"
    if resp.status_code >= 500:
        return "error", f"Google Custom Search API returned HTTP {resp.status_code}"
    if resp.status_code != 200:
        return "error", f"Google Custom Search API returned unexpected HTTP {resp.status_code}"
    return None


def query_google_custom_search(
    query: str,
    api_key: Optional[str],
    cse_id: Optional[str],
    timeout: float = DEFAULT_TIMEOUT,
    num: int = 10,
    start: int = 1,
    base_url: str = GOOGLE_CSE_API_BASE,
) -> Dict[str, Any]:
    """
    Run one query against Google's Custom Search JSON API. Both
    GOOGLE_API_KEY and GOOGLE_CSE_ID are mandatory (module docstring,
    CREDENTIAL HANDLING).

    Returns {"status": "found"|"not_found"|"missing_credentials"|
             "invalid_query"|"forbidden"|"rate_limited"|"error",
             "items": [...], "total_results": int, "error": str|None}.
    """
    result: Dict[str, Any] = {"status": "error", "items": [], "total_results": 0, "error": None}

    if not query or not query.strip():
        result["error"] = "query is required"
        return result

    if not api_key or not cse_id:
        result["status"] = "missing_credentials"
        result["error"] = (
            f"Google Custom Search requires {GOOGLE_API_KEY_ENV} and {GOOGLE_CSE_ID_ENV} "
            f"to be configured"
        )
        return result

    resp = None
    try:
        resp = requests.get(
            base_url,
            params={"key": api_key, "cx": cse_id, "q": query, "num": max(1, min(num, 10)), "start": max(1, start)},
            timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT},
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

    status = _classify_google_status(resp)
    if status is not None:
        result["status"], result["error"] = status
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from Google Custom Search API: {exc}"
        return result

    if not isinstance(data, dict):
        result["error"] = "unexpected Google Custom Search API response structure"
        return result

    items = data.get("items")
    if items is None:
        items = []  # Google omits "items" entirely for zero results — not an error.
    if not isinstance(items, list):
        result["error"] = "unexpected Google Custom Search API response structure (items is not a list)"
        return result

    result["items"] = items
    search_info = data.get("searchInformation") if isinstance(data.get("searchInformation"), dict) else {}
    try:
        result["total_results"] = int(search_info.get("totalResults") or 0)
    except (TypeError, ValueError):
        result["total_results"] = len(items)
    result["status"] = "found" if items else "not_found"
    return result


def _run_query_batch(
    query_templates: Tuple[Tuple[str, str], ...],
    target: str,
    api_key: Optional[str],
    cse_id: Optional[str],
    timeout: float,
    num: int,
    request_delay: float,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Tuple[str, str]]]:
    """
    Shared batch-query runner for dorking/paste/job-posting/email-search
    responsibilities, all of which are "run N scoped queries, collect
    indexed results" against the same Google Custom Search provider.

    Returns (per_query_status, hits, no_result_queries).
    """
    status_list: List[Dict[str, Any]] = []
    hits: List[Dict[str, Any]] = []
    no_result: List[Tuple[str, str]] = []

    for idx, (label, template) in enumerate(query_templates):
        q = template.format(target=target)
        try:
            r = query_google_custom_search(q, api_key, cse_id, timeout=timeout, num=num)
        except Exception as exc:
            r = {"status": "error", "error": str(exc), "items": [], "total_results": 0}

        status_list.append({
            "label": label, "query": q, "status": r["status"],
            "error": r.get("error"), "total_results": r.get("total_results", 0),
        })

        if r["status"] == "found":
            for item in r["items"]:
                if not isinstance(item, dict):
                    continue
                hits.append({
                    "label": label, "query": q,
                    "title": item.get("title"), "link": item.get("link"),
                    "snippet": item.get("snippet"), "display_link": item.get("displayLink"),
                })
        elif r["status"] == "not_found":
            no_result.append((label, q))
        elif r["status"] in ("missing_credentials", "unauthorized", "forbidden", "rate_limited"):
            # Every remaining query in this batch would fail identically or
            # burn the same quota — stop rather than retry blindly.
            break

        if request_delay > 0 and idx < len(query_templates) - 1:
            time.sleep(request_delay)

    return status_list, hits, no_result


def persist_search_hits(
    hits: List[Dict[str, Any]],
    target: str,
    store: Optional[PendingAssetsStore],
    finding_type: str,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Persist one finding per unique (query_label, url) search-engine hit."""
    errors: List[str] = []
    seen: Set[Tuple[Any, Any]] = set()
    for h in hits:
        link = h.get("link")
        if not link:
            continue
        key = (h.get("label"), link)
        if key in seen:
            continue
        seen.add(key)

        meta: Dict[str, Any] = {
            "observed": True, "source": "google_custom_search",
            "query_label": h.get("label"), "query": h.get("query"),
        }
        if extra_metadata:
            meta.update(extra_metadata)

        err = _safe_store_add(store, make_finding(
            finding_type=finding_type,
            target=target,
            value={
                "url": link, "title": h.get("title"),
                "snippet": _truncate(h.get("snippet") or ""),
                "query_label": h.get("label"), "query": h.get("query"),
            },
            evidence=[f"Google Custom Search returned this result for dork query [{h.get('label')}]: {h.get('query')}"],
            confidence=CONFIDENCE_MEDIUM,
            metadata=meta,
        ))
        if err:
            errors.append(err)
    return errors


def harvest_search_engine_emails(
    domain: str, api_key: Optional[str], cse_id: Optional[str],
    timeout: float = DEFAULT_TIMEOUT, num: int = 10,
) -> Dict[str, Any]:
    """Search-engine email harvesting via a single scoped Google CSE query."""
    query = f'site:{domain} "@{domain}"'
    r = query_google_custom_search(query, api_key, cse_id, timeout=timeout, num=num)
    emails: Set[str] = set()
    if r["status"] == "found":
        for item in r["items"]:
            if not isinstance(item, dict):
                continue
            text = " ".join(filter(None, [item.get("title"), item.get("snippet")]))
            emails.update(extract_emails_from_text(text, domain))
    return {"status": r["status"], "error": r.get("error"), "emails": sorted(emails), "query": query}


# ---------------------------------------------------------------------------
# 2/3. Email-pattern inference & naming-convention inference
# ---------------------------------------------------------------------------

def classify_local_part(local_part: str) -> Dict[str, Optional[str]]:
    """
    Classify one email local-part into a naming-pattern category. Returns
    {"category": str, "first": str|None, "last": str|None} — first/last are
    only populated when the split is unambiguous.
    """
    lp = (local_part or "").strip().lower()
    if not lp or not re.match(r"^[a-z0-9._-]+$", lp):
        return {"category": "other", "first": None, "last": None}

    for sep, base_cat in ((".", "first.last"), ("_", "first_last"), ("-", "first-last")):
        if sep in lp:
            parts = [p for p in lp.split(sep) if p]
            if len(parts) == 2 and all(p.isalpha() for p in parts):
                a, b = parts
                if len(a) == 1:
                    return {"category": f"finitial{sep}last", "first": a, "last": b}
                if len(b) == 1:
                    return {"category": f"first{sep}linitial", "first": a, "last": b}
                return {"category": base_cat, "first": a, "last": b}
            return {"category": "other", "first": None, "last": None}

    if lp.isalpha() and 3 <= len(lp) <= 20:
        # No separator: could be "flast" (initial+surname) or a fully
        # concatenated "firstlast" — not reliably distinguishable without
        # a name dictionary, so both are grouped as "concatenated".
        return {"category": "concatenated", "first": None, "last": None}

    return {"category": "other", "first": None, "last": None}


def infer_email_patterns(emails: List[str], domain: str) -> Dict[str, Any]:
    """
    Bucket observed emails by local-part naming-pattern category and rank
    candidates by frequency (context.md's "email pattern inferred from
    observed addresses -> inferred" example).
    """
    buckets: Dict[str, Dict[str, Any]] = {}
    for email in emails:
        local = email.split("@")[0]
        cls = classify_local_part(local)
        cat = cls["category"]
        b = buckets.setdefault(cat, {"category": cat, "count": 0, "examples": []})
        b["count"] += 1
        if len(b["examples"]) < 3:
            b["examples"].append(email)

    total = len(emails)
    candidates = sorted(buckets.values(), key=lambda b: (-b["count"], b["category"]))
    for c in candidates:
        c["share"] = round(c["count"] / total, 3) if total else 0.0

    return {"total_observed": total, "candidates": candidates}


def _pattern_confidence(count: int, share: float) -> str:
    if share >= 0.75 and count >= 3:
        return CONFIDENCE_HIGH
    if share > 0.5 and count >= 2:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def persist_email_pattern_findings(
    pattern_info: Dict[str, Any], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `osint_engine_email_pattern` finding per observed local-part category."""
    errors: List[str] = []
    total = pattern_info["total_observed"]
    if total < 1:
        return errors
    for c in pattern_info["candidates"]:
        confidence = _pattern_confidence(c["count"], c["share"])
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_email_pattern",
            target=target,
            value={
                "pattern_category": c["category"], "match_count": c["count"],
                "total_observed": total, "share": c["share"], "examples": c["examples"],
            },
            evidence=[f"{c['count']} of {total} observed email(s) for {target} follow the '{c['category']}' local-part pattern"],
            confidence=confidence,
            metadata={
                "inferred": True, "observed": False,
                "note": "A local-part pattern is a statistical inference from observed addresses, not a confirmed organizational policy.",
            },
        ))
        if err:
            errors.append(err)
    return errors


def persist_naming_convention_finding(
    pattern_info: Dict[str, Any], target: str, store: Optional[PendingAssetsStore]
) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Persist the single org-level `osint_engine_naming_convention` finding —
    the best-supported pattern candidate, or an explicit
    "insufficient_data" result when fewer than two emails were observed.
    """
    total = pattern_info["total_observed"]
    candidates = pattern_info["candidates"]

    if total < 2 or not candidates:
        value = {"status": "insufficient_data", "total_observed": total}
        finding = make_finding(
            "osint_engine_naming_convention", target, value,
            [f"Only {total} email(s) observed for {target}; insufficient data to infer a reliable naming convention (need >=2)."],
            CONFIDENCE_LOW,
            metadata={"inferred": True, "observed": False},
        )
        return finding["value"], _safe_store_add(store, finding)

    top = candidates[0]
    confidence = _pattern_confidence(top["count"], top["share"])
    value = {
        "status": "inferred", "convention": top["category"], "match_count": top["count"],
        "total_observed": total, "share": top["share"], "examples": top["examples"],
    }
    finding = make_finding(
        "osint_engine_naming_convention", target, value,
        [f"The most common observed pattern ({top['category']}) covers {top['count']} of {total} observed email(s) ({top['share'] * 100:.0f}%)"],
        confidence,
        metadata={
            "inferred": True, "observed": False,
            "note": "Best-supported hypothesis only; a minority of employees may not follow this convention.",
        },
    )
    return finding["value"], _safe_store_add(store, finding)


# ---------------------------------------------------------------------------
# 4. Employee-list generation (inferred intelligence) — input-contract
# decision #5: always CONFIDENCE_LOW, never claims a confirmed identity.
# ---------------------------------------------------------------------------

def generate_employee_inferences(emails: List[str]) -> List[Dict[str, Any]]:
    """Derive speculative employee identity records from observed emails' local parts."""
    employees = []
    for email in emails:
        local = email.split("@")[0]
        cls = classify_local_part(local)
        cat = cls["category"]
        probable_name = None
        if cat in ("first.last", "first_last", "first-last") and cls["first"] and cls["last"]:
            probable_name = f"{cls['first'].capitalize()} {cls['last'].capitalize()}"
        elif cat in ("finitial.last", "finitial_last", "finitial-last") and cls["first"] and cls["last"]:
            probable_name = f"{cls['first'].upper()}. {cls['last'].capitalize()}"
        elif cat in ("first.linitial", "first_linitial", "first-linitial") and cls["first"] and cls["last"]:
            probable_name = f"{cls['first'].capitalize()} {cls['last'].upper()}."

        employees.append({
            "source_email": email,
            "local_part_category": cat,
            "probable_name": probable_name,
        })
    return employees


def persist_employee_findings(
    employees: List[Dict[str, Any]], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `osint_engine_employee` finding per speculative employee identity."""
    errors: List[str] = []
    for emp in employees:
        note = (
            f"probable name guess: {emp['probable_name']}" if emp["probable_name"]
            else "local part could not be reliably split into a name"
        )
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_employee",
            target=target,
            value={
                "source_email": emp["source_email"],
                "probable_name": emp["probable_name"],
                "local_part_category": emp["local_part_category"],
            },
            evidence=[
                f"Inferred from observed mailbox {emp['source_email']} using local-part "
                f"pattern '{emp['local_part_category']}'; {note}"
            ],
            confidence=CONFIDENCE_LOW,
            metadata={
                "inferred": True, "observed": False,
                "note": (
                    "Speculative identity inference derived purely from an email address's "
                    "local-part format. NOT a confirmed employee record and must never be "
                    "treated as verified personal data."
                ),
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# 10. Job-posting technology-stack inference
# ---------------------------------------------------------------------------

def infer_tech_from_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scan job-posting search-hit title/snippet text for known technology keyword mentions."""
    agg: Dict[str, Dict[str, Any]] = {}
    for h in hits:
        text = " ".join(filter(None, [h.get("title"), h.get("snippet")]))
        if not text:
            continue
        for kw in TECH_KEYWORDS:
            if re.search(r"(?<![A-Za-z0-9])" + re.escape(kw) + r"(?![A-Za-z0-9])", text, re.IGNORECASE):
                rec = agg.setdefault(kw, {"keyword": kw, "count": 0, "examples": []})
                rec["count"] += 1
                if len(rec["examples"]) < 3:
                    rec["examples"].append({"url": h.get("link"), "query_label": h.get("label")})
    return sorted(agg.values(), key=lambda r: (-r["count"], r["keyword"]))


def persist_job_tech_findings(
    agg: List[Dict[str, Any]], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `osint_engine_job_tech_inference` finding per matched technology keyword."""
    errors: List[str] = []
    for rec in agg:
        confidence = CONFIDENCE_MEDIUM if rec["count"] >= 2 else CONFIDENCE_LOW
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_job_tech_inference",
            target=target,
            value={"technology": rec["keyword"], "mention_count": rec["count"], "examples": rec["examples"]},
            evidence=[f"Keyword '{rec['keyword']}' appeared in {rec['count']} job-posting search result(s) for {target}"],
            confidence=confidence,
            metadata={
                "inferred": True, "observed": False,
                "note": "Technology mention in a public job posting is a hiring-intent signal, not confirmed current production usage.",
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# 6. HIBP breach correlation
# ---------------------------------------------------------------------------

def query_hibp_domain_breaches(
    domain: str, timeout: float = DEFAULT_TIMEOUT, base_url: str = HIBP_BREACHES_API
) -> Dict[str, Any]:
    """List breaches HIBP associates with `domain`. No credential required."""
    result: Dict[str, Any] = {"status": "error", "breaches": [], "error": None}
    resp = None
    try:
        resp = requests.get(
            base_url, params={"domain": domain}, timeout=timeout,
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

    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["error"] = "HTTP 429 Too Many Requests from HIBP API"
        return result
    if resp.status_code >= 500:
        result["error"] = f"HIBP API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"HIBP API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from HIBP API: {exc}"
        return result

    if not isinstance(data, list):
        result["error"] = "unexpected HIBP API response structure (not a JSON array)"
        return result

    result["breaches"] = data
    result["status"] = "found" if data else "not_found"
    return result


def query_hibp_account_breaches(
    email: str, api_key: Optional[str], timeout: float = DEFAULT_TIMEOUT,
    base_url: str = HIBP_BREACHED_ACCOUNT_API,
) -> Dict[str, Any]:
    """
    Check whether `email` appears in a known breach via HIBP's account
    lookup. Requires HIBP_API_KEY (mandatory — HIBP does not serve
    unauthenticated account lookups). Never validates the account
    credential against any live service.

    Returns {"status": "found"|"not_found"|"missing_credentials"|
             "unauthorized"|"rate_limited"|"error", "breaches": [...], "error": str|None}.
    """
    result: Dict[str, Any] = {"status": "error", "breaches": [], "error": None}

    if not email:
        result["error"] = "email is required"
        return result

    if not api_key:
        result["status"] = "missing_credentials"
        result["error"] = f"HIBP account lookup requires {HIBP_API_KEY_ENV}"
        return result

    encoded = urllib.parse.quote(email, safe="")
    url = f"{base_url}/{encoded}"

    resp = None
    try:
        resp = requests.get(
            url, params={"truncateResponse": "false"}, timeout=timeout,
            headers={"hibp-api-key": api_key, "User-Agent": DEFAULT_USER_AGENT},
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
        result["error"] = "HIBP API rejected the configured API key (HTTP 401)"
        return result
    if resp.status_code == 429:
        result["status"] = "rate_limited"
        retry_after = resp.headers.get("Retry-After")
        result["error"] = f"HTTP 429 Too Many Requests from HIBP API (Retry-After={retry_after})"
        return result
    if resp.status_code >= 500:
        result["error"] = f"HIBP API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"HIBP API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from HIBP API: {exc}"
        return result

    if not isinstance(data, list):
        result["error"] = "unexpected HIBP API response structure (not a JSON array)"
        return result

    result["breaches"] = data
    result["status"] = "found" if data else "not_found"
    return result


def persist_breach_domain_findings(
    breaches: List[Dict[str, Any]], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `osint_engine_breach_domain` finding per breach HIBP associates with the target's domain."""
    errors: List[str] = []
    for b in breaches:
        if not isinstance(b, dict):
            continue
        name = b.get("Name") or b.get("Title")
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_breach_domain",
            target=target,
            value={
                "name": name, "title": b.get("Title"), "domain": b.get("Domain"),
                "breach_date": b.get("BreachDate"), "pwn_count": b.get("PwnCount"),
                "data_classes": b.get("DataClasses"), "is_verified": b.get("IsVerified"),
            },
            evidence=[f"HIBP records a breach named '{name}' associated with domain {b.get('Domain')!r} (breach date {b.get('BreachDate')})"],
            confidence=CONFIDENCE_HIGH,
            metadata={
                "observed": True, "inferred": False, "source": "hibp",
                "note": "Reflects a historical breach HIBP associates with the organization's domain; does not confirm any specific account credential is currently valid.",
            },
        ))
        if err:
            errors.append(err)
    return errors


def persist_breach_account_findings(
    email: str, email_provenance: str, breaches: List[Dict[str, Any]],
    target: str, store: Optional[PendingAssetsStore],
) -> List[str]:
    """Persist one `osint_engine_breach_account` finding per breach a specific email was found in."""
    errors: List[str] = []
    for b in breaches:
        if not isinstance(b, dict):
            continue
        name = b.get("Name")
        data_classes = b.get("DataClasses") or []
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_breach_account",
            target=target,
            value={
                "email": email, "breach_name": name, "breach_date": b.get("BreachDate"),
                "data_classes": data_classes, "is_verified": b.get("IsVerified"),
            },
            evidence=[f"HIBP records that {email} appears in the '{name}' breach (data classes: {', '.join(data_classes)})"],
            confidence=CONFIDENCE_HIGH,
            metadata={
                "observed": True, "inferred": False, "source": "hibp",
                "email_provenance": email_provenance,
                "note": "Breach membership only; this module never validates the leaked credential against any live service.",
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# 7. DNS history (SecurityTrails)
# ---------------------------------------------------------------------------

def query_securitytrails_dns_history(
    domain: str, record_type: str, api_key: Optional[str],
    timeout: float = DEFAULT_TIMEOUT, base_url: str = SECURITYTRAILS_HISTORY_API,
) -> Dict[str, Any]:
    """
    Fetch historical DNS records of one `record_type` for `domain` via
    SecurityTrails' passive-DNS history API. SECURITYTRAILS_API_KEY is
    mandatory (module docstring, CREDENTIAL HANDLING).
    """
    result: Dict[str, Any] = {"status": "error", "records": [], "error": None}

    if not api_key:
        result["status"] = "missing_credentials"
        result["error"] = f"DNS history requires {SECURITYTRAILS_API_KEY_ENV}"
        return result

    url = f"{base_url}/{domain}/dns/{record_type}"
    resp = None
    try:
        resp = requests.get(
            url, timeout=timeout,
            headers={"APIKEY": api_key, "User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
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
        result["error"] = "SecurityTrails API rejected the configured API key (HTTP 401)"
        return result
    if resp.status_code == 403:
        result["status"] = "forbidden"
        result["error"] = "SecurityTrails API returned HTTP 403 (quota exhausted or insufficient plan)"
        return result
    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["error"] = "HTTP 429 Too Many Requests from SecurityTrails API"
        return result
    if resp.status_code >= 500:
        result["error"] = f"SecurityTrails API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"SecurityTrails API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from SecurityTrails API: {exc}"
        return result

    if not isinstance(data, dict):
        result["error"] = "unexpected SecurityTrails API response structure"
        return result

    records = data.get("records")
    if not isinstance(records, list):
        result["error"] = "unexpected SecurityTrails API response structure (missing records[])"
        return result

    result["records"] = records
    result["status"] = "found" if records else "not_found"
    return result


def _normalize_dns_history_values(values: Any) -> List[str]:
    normalized: List[str] = []
    for v in values or []:
        if isinstance(v, str) and v:
            normalized.append(v)
        elif isinstance(v, dict):
            candidate = v.get("ip") or v.get("host") or v.get("value") or v.get("nameserver") or v.get("mail_exchanger")
            if candidate:
                normalized.append(str(candidate))
    return normalized


def persist_dns_history_findings(
    record_type: str, records: List[Dict[str, Any]], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `osint_engine_dns_history` finding per historical DNS record."""
    errors: List[str] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        values = _normalize_dns_history_values(rec.get("values"))
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_dns_history",
            target=target,
            value={
                "record_type": record_type.upper(), "values": values,
                "first_seen": rec.get("first_seen"), "last_seen": rec.get("last_seen"),
            },
            evidence=[
                f"SecurityTrails historical {record_type.upper()} record for {target}: {values} "
                f"(first seen {rec.get('first_seen')}, last seen {rec.get('last_seen')})"
            ],
            confidence=CONFIDENCE_MEDIUM,
            metadata={"observed": True, "inferred": False, "source": "securitytrails", "record_type": record_type.upper()},
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# 8. Reverse-IP intelligence (HackerTarget)
# ---------------------------------------------------------------------------

def query_hackertarget_reverse_ip(
    ip: str, api_key: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT,
    base_url: str = HACKERTARGET_REVERSE_IP_API,
) -> Dict[str, Any]:
    """
    List domains co-hosted on `ip` via HackerTarget's free reverse-IP
    lookup API. No credential required for the free tier; an optional
    HACKERTARGET_API_KEY raises the rate limit. Errors/rate-limits are
    returned as plain-text bodies with HTTP 200, so the response text is
    inspected for known markers rather than relying on status codes alone.
    """
    result: Dict[str, Any] = {"status": "error", "domains": [], "error": None}

    normalized_ip = _valid_ip(ip)
    if normalized_ip is None:
        result["error"] = f"not a valid IP address: {ip!r}"
        return result

    params: Dict[str, Any] = {"q": normalized_ip}
    if api_key:
        params["apikey"] = api_key

    resp = None
    try:
        resp = requests.get(base_url, params=params, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT})
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
        result["error"] = "HTTP 429 Too Many Requests from HackerTarget API"
        return result
    if resp.status_code >= 500:
        result["error"] = f"HackerTarget API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"HackerTarget API returned unexpected HTTP {resp.status_code}"
        return result

    text = (resp.text or "").strip()
    lower = text.lower()

    if not text:
        result["status"] = "not_found"
        return result
    if "api count exceeded" in lower or "quota" in lower:
        result["status"] = "rate_limited"
        result["error"] = text
        return result
    if lower.startswith("error"):
        result["status"] = "error"
        result["error"] = text
        return result
    if lower.startswith("no ") or "no records found" in lower or "no dns a records" in lower:
        result["status"] = "not_found"
        return result

    domains = [line.strip() for line in text.splitlines() if line.strip()]
    result["domains"] = domains
    result["status"] = "found" if domains else "not_found"
    return result


def persist_reverse_ip_findings(
    domains: List[str], ip: str, target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """
    Persist one `osint_engine_reverse_ip` finding per co-hosted domain.
    Most results are third-party domains (input-contract decision #6) —
    every finding carries an explicit `in_scope` flag.
    """
    errors: List[str] = []
    for d in domains:
        d_clean = d.strip().lower().rstrip(".")
        if not d_clean:
            continue
        in_scope = is_in_scope(d_clean, target)
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_reverse_ip",
            target=target,
            value={"domain": d_clean, "ip": ip, "in_scope": in_scope},
            evidence=[f"HackerTarget reverse-IP lookup found {d_clean!r} co-hosted on {ip}"],
            confidence=CONFIDENCE_MEDIUM,
            metadata={
                "observed": True, "inferred": False, "source": "hackertarget", "in_scope": in_scope,
                "note": None if in_scope else (
                    "This co-hosted domain does not belong to the target's own domain — it is a "
                    "third-party asset sharing the same host/IP, not part of the target's asset inventory."
                ),
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# 11. ASN neighbor analysis (BGPView) — input-contract decision #4
# ---------------------------------------------------------------------------

def query_bgpview_asn_peers(
    asn: str, timeout: float = DEFAULT_TIMEOUT, base_url: str = BGPVIEW_API_BASE
) -> Dict[str, Any]:
    """List an ASN's directly peering (BGP-neighbor) Autonomous Systems via BGPView. No credential required."""
    result: Dict[str, Any] = {"status": "error", "peers": [], "error": None}

    asn_clean = re.sub(r"(?i)^as", "", str(asn or "").strip())
    if not asn_clean.isdigit():
        result["error"] = f"not a valid ASN: {asn!r}"
        return result

    url = f"{base_url}/asn/{asn_clean}/peers"
    resp = None
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT})
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
    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["error"] = "HTTP 429 Too Many Requests from BGPView API"
        return result
    if resp.status_code >= 500:
        result["error"] = f"BGPView API returned HTTP {resp.status_code}"
        return result
    if resp.status_code != 200:
        result["error"] = f"BGPView API returned unexpected HTTP {resp.status_code}"
        return result

    try:
        data = resp.json()
    except ValueError as exc:
        result["error"] = f"malformed JSON from BGPView API: {exc}"
        return result

    if not isinstance(data, dict):
        result["error"] = "unexpected BGPView API response structure"
        return result

    if data.get("status") != "ok":
        result["status"] = "not_found" if data.get("status_message") else "error"
        result["error"] = data.get("status_message") or "BGPView API reported a non-ok status"
        return result

    inner = data.get("data") if isinstance(data.get("data"), dict) else {}
    peers: List[Dict[str, Any]] = []
    for key in ("ipv4_peers", "ipv6_peers"):
        for p in inner.get(key) or []:
            if isinstance(p, dict) and p.get("asn"):
                peers.append(p)

    result["peers"] = peers
    result["status"] = "found" if peers else "not_found"
    return result


def persist_asn_neighbor_findings(
    peers: List[Dict[str, Any]], source_asn: str, target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `osint_engine_asn_neighbor` finding per BGP peer ASN."""
    errors: List[str] = []
    for p in peers:
        peer_asn = p.get("asn")
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_asn_neighbor",
            target=target,
            value={
                "source_asn": source_asn, "peer_asn": peer_asn,
                "name": p.get("name"), "description": p.get("description"),
                "country_code": p.get("country_code"),
            },
            evidence=[f"BGPView records AS{peer_asn} ({p.get('name')}) as a BGP peer/neighbor of AS{source_asn}"],
            confidence=CONFIDENCE_MEDIUM,
            metadata={
                "observed": True, "inferred": False, "source": "bgpview",
                "note": "A BGP peer relationship indicates shared network adjacency, not necessarily shared organizational ownership.",
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# Negative-result memory
# ---------------------------------------------------------------------------

def persist_no_result_findings(
    checks: List[Tuple[str, str]], target: str, store: Optional[PendingAssetsStore]
) -> List[str]:
    """Persist one `osint_engine_checked_no_result` finding per check that completed with zero results."""
    errors: List[str] = []
    for label, detail in checks:
        err = _safe_store_add(store, make_finding(
            finding_type="osint_engine_checked_no_result",
            target=target,
            value={"check": label, "detail": detail},
            evidence=[detail],
            confidence=CONFIDENCE_LOW,
            metadata={
                "checked_at": _now(),
                "note": "Negative-result-memory: absence of a result from this source does not prove the underlying data doesn't exist.",
            },
        ))
        if err:
            errors.append(err)
    return errors


# ---------------------------------------------------------------------------
# Module orchestration
# ---------------------------------------------------------------------------

def run_osint_engine(
    target: str,
    output_dir: str = "output",
    google_api_key: Optional[str] = None,
    google_cse_id: Optional[str] = None,
    hibp_api_key: Optional[str] = None,
    securitytrails_api_key: Optional[str] = None,
    hackertarget_api_key: Optional[str] = None,
    seed_ip: Optional[str] = None,
    seed_asn: Optional[str] = None,
    include_ct: bool = True,
    include_search_email: bool = True,
    include_dorking: bool = True,
    include_paste: bool = True,
    include_job_tech: bool = True,
    include_hibp_domain: bool = True,
    include_hibp_account: bool = True,
    include_dns_history: bool = True,
    include_reverse_ip: bool = True,
    include_asn_neighbors: bool = True,
    max_ct_certs: int = 15,
    max_hibp_accounts: int = 10,
    dns_history_record_types: Tuple[str, ...] = DEFAULT_DNS_HISTORY_RECORD_TYPES,
    timeout: float = DEFAULT_TIMEOUT,
    request_delay: float = DEFAULT_REQUEST_DELAY,
) -> Dict[str, Any]:
    """
    Run all Module 4 OSINT/digital-footprint checks against `target` and
    persist every discovery immediately to <output_dir>/pending_assets.json.

    Every source is independently optional. A missing credential for a
    gated source never raises — that source is skipped and clearly
    reported in `source_status` (module docstring, CREDENTIAL HANDLING).
    Running this module with zero credentials configured still completes
    successfully (CT-log harvesting and HIBP domain-breach lookup need no
    credential at all).
    """
    target = validate_target(target)
    store = PendingAssetsStore(output_dir=output_dir)

    google_api_key = google_api_key if google_api_key is not None else os.environ.get(GOOGLE_API_KEY_ENV)
    google_cse_id = google_cse_id if google_cse_id is not None else os.environ.get(GOOGLE_CSE_ID_ENV)
    hibp_api_key = hibp_api_key if hibp_api_key is not None else os.environ.get(HIBP_API_KEY_ENV)
    securitytrails_api_key = (
        securitytrails_api_key if securitytrails_api_key is not None else os.environ.get(SECURITYTRAILS_API_KEY_ENV)
    )
    hackertarget_api_key = (
        hackertarget_api_key if hackertarget_api_key is not None else os.environ.get(HACKERTARGET_API_KEY_ENV)
    )
    google_configured = bool(google_api_key and google_cse_id)
    google_missing_msg = f"Google Custom Search requires {GOOGLE_API_KEY_ENV} and {GOOGLE_CSE_ID_ENV}"

    summary: Dict[str, Any] = {
        "target": target, "module": MODULE_NAME, "started_at": _now(),
        "source_status": {}, "emails": [], "email_patterns": [], "naming_convention": None,
        "employees": [], "dork_results": [], "paste_references": [], "job_tech_inferences": [],
        "breach_domain_records": [], "breach_account_records": [], "dns_history": [],
        "reverse_ip": [], "asn_neighbors": [], "stats": {}, "errors": [],
    }

    no_result_checks: List[Tuple[str, str]] = []
    email_records: List[Dict[str, Any]] = []

    # --- 1a. CT-log email harvesting ---
    if include_ct:
        try:
            ct = harvest_ct_emails(target, timeout=timeout, max_certs=max_ct_certs)
        except Exception as exc:
            ct = {"status": "error", "error": str(exc), "emails": [], "certs_inspected": 0}
        summary["source_status"]["ct_log"] = {
            "status": ct["status"], "error": ct.get("error"), "certs_inspected": ct.get("certs_inspected", 0),
        }
        if ct["status"] == "found":
            email_records.extend({"email": e, "source": "ct_log"} for e in ct["emails"])
        elif ct["status"] == "not_found":
            no_result_checks.append(("ct_log_email_harvest", f"crt.sh CT-log inspection found no emails in certificates for {target}"))

    # --- 1b. Search-engine email harvesting ---
    if include_search_email:
        if not google_configured:
            summary["source_status"]["search_engine_email"] = {"status": "missing_credentials", "error": google_missing_msg}
        else:
            try:
                se = harvest_search_engine_emails(target, google_api_key, google_cse_id, timeout=timeout)
            except Exception as exc:
                se = {"status": "error", "error": str(exc), "emails": []}
            summary["source_status"]["search_engine_email"] = {"status": se["status"], "error": se.get("error")}
            if se["status"] == "found":
                email_records.extend({"email": e, "source": "search_engine"} for e in se["emails"])
            elif se["status"] == "not_found":
                no_result_checks.append(("search_engine_email_harvest", f"Google Custom Search found no emails for {target}"))

    merged_emails = merge_email_records(email_records)
    persist_errors = persist_emails(merged_emails, target, store)
    if persist_errors:
        summary["errors"].append({"stage": "persist_emails", "errors": persist_errors})
    summary["emails"] = merged_emails
    all_emails = [e["email"] for e in merged_emails]

    # --- 2/3. Email-pattern & naming-convention inference ---
    pattern_info = infer_email_patterns(all_emails, target)
    summary["email_patterns"] = pattern_info["candidates"]
    pattern_errors = persist_email_pattern_findings(pattern_info, target, store)
    if pattern_errors:
        summary["errors"].append({"stage": "persist_email_patterns", "errors": pattern_errors})

    naming_conv, nc_error = persist_naming_convention_finding(pattern_info, target, store)
    summary["naming_convention"] = naming_conv
    if nc_error:
        summary["errors"].append({"stage": "persist_naming_convention", "error": nc_error})

    # --- 4. Employee-list generation ---
    employees = generate_employee_inferences(all_emails)
    emp_errors = persist_employee_findings(employees, target, store)
    if emp_errors:
        summary["errors"].append({"stage": "persist_employees", "errors": emp_errors})
    summary["employees"] = employees

    # --- 5. Google dorking ---
    if include_dorking:
        if not google_configured:
            summary["source_status"]["dorking"] = {"status": "missing_credentials", "error": google_missing_msg}
        else:
            status_list, hits, no_res = _run_query_batch(
                DEFAULT_DORK_QUERIES, target, google_api_key, google_cse_id, timeout, 10, request_delay
            )
            summary["source_status"]["dorking_queries"] = status_list
            dork_errors = persist_search_hits(hits, target, store, "osint_engine_dork_result")
            if dork_errors:
                summary["errors"].append({"stage": "persist_dork_results", "errors": dork_errors})
            summary["dork_results"] = hits
            no_result_checks.extend(
                (f"dork_{lbl}", f"Google dork [{lbl}] ({q}) returned no results") for lbl, q in no_res
            )

    # --- 9. Paste/public-text intelligence ---
    if include_paste:
        if not google_configured:
            summary["source_status"]["paste_intel"] = {"status": "missing_credentials", "error": google_missing_msg}
        else:
            status_list, hits, no_res = _run_query_batch(
                DEFAULT_PASTE_QUERIES, target, google_api_key, google_cse_id, timeout, 10, request_delay
            )
            summary["source_status"]["paste_queries"] = status_list
            paste_errors = persist_search_hits(
                hits, target, store, "osint_engine_paste_reference", extra_metadata={"category": "paste_site"}
            )
            if paste_errors:
                summary["errors"].append({"stage": "persist_paste_references", "errors": paste_errors})
            summary["paste_references"] = hits
            no_result_checks.extend(
                (f"paste_{lbl}", f"Paste-site dork [{lbl}] returned no results") for lbl, q in no_res
            )

    # --- 10. Job-posting technology-stack inference ---
    if include_job_tech:
        if not google_configured:
            summary["source_status"]["job_tech"] = {"status": "missing_credentials", "error": google_missing_msg}
        else:
            status_list, hits, no_res = _run_query_batch(
                DEFAULT_JOB_SEARCH_QUERIES, target, google_api_key, google_cse_id, timeout, 10, request_delay
            )
            summary["source_status"]["job_queries"] = status_list
            tech_agg = infer_tech_from_hits(hits)
            tech_errors = persist_job_tech_findings(tech_agg, target, store)
            if tech_errors:
                summary["errors"].append({"stage": "persist_job_tech", "errors": tech_errors})
            summary["job_tech_inferences"] = tech_agg
            no_result_checks.extend(
                (f"job_{lbl}", f"Job-posting dork [{lbl}] returned no results") for lbl, q in no_res
            )

    # --- 6a. HIBP breach correlation: domain ---
    if include_hibp_domain:
        try:
            hb = query_hibp_domain_breaches(target, timeout=timeout)
        except Exception as exc:
            hb = {"status": "error", "error": str(exc), "breaches": []}
        summary["source_status"]["hibp_domain"] = {"status": hb["status"], "error": hb.get("error")}
        if hb["status"] == "found":
            errs = persist_breach_domain_findings(hb["breaches"], target, store)
            if errs:
                summary["errors"].append({"stage": "persist_breach_domain", "errors": errs})
            summary["breach_domain_records"] = hb["breaches"]
        elif hb["status"] == "not_found":
            no_result_checks.append(("hibp_domain_breach", f"HIBP recorded no breaches associated with domain {target}"))

    # --- 6b. HIBP breach correlation: accounts ---
    if include_hibp_account:
        if not hibp_api_key:
            summary["source_status"]["hibp_account"] = {
                "status": "missing_credentials", "error": f"HIBP account lookup requires {HIBP_API_KEY_ENV}",
            }
        else:
            candidates = [(e["email"], "observed") for e in merged_emails][:max_hibp_accounts]
            per_account_status = []
            for idx, (email, provenance) in enumerate(candidates):
                try:
                    r = query_hibp_account_breaches(email, hibp_api_key, timeout=timeout)
                except Exception as exc:
                    r = {"status": "error", "error": str(exc), "breaches": []}
                per_account_status.append({"email": email, "status": r["status"], "error": r.get("error")})
                if r["status"] == "found":
                    errs = persist_breach_account_findings(email, provenance, r["breaches"], target, store)
                    if errs:
                        summary["errors"].append({"stage": "persist_breach_account", "email": email, "errors": errs})
                    summary["breach_account_records"].extend(r["breaches"])
                elif r["status"] == "not_found":
                    no_result_checks.append((f"hibp_account_{email}", f"HIBP recorded no breaches for {email}"))
                elif r["status"] in ("unauthorized", "rate_limited"):
                    summary["errors"].append({"stage": "hibp_account", "email": email, "error": r.get("error")})
                    break
                if request_delay > 0 and idx < len(candidates) - 1:
                    time.sleep(max(request_delay, 1.6))  # HIBP's own strict per-key rate limit
            summary["source_status"]["hibp_account_checks"] = per_account_status

    seed = load_seed_data(store, target, extra_ip=seed_ip, extra_asn=seed_asn)

    # --- 7. DNS history ---
    if include_dns_history:
        if not securitytrails_api_key:
            summary["source_status"]["dns_history"] = {
                "status": "missing_credentials", "error": f"DNS history requires {SECURITYTRAILS_API_KEY_ENV}",
            }
        else:
            per_type_status = []
            for idx, rt in enumerate(dns_history_record_types):
                try:
                    r = query_securitytrails_dns_history(target, rt, securitytrails_api_key, timeout=timeout)
                except Exception as exc:
                    r = {"status": "error", "error": str(exc), "records": []}
                per_type_status.append({"record_type": rt, "status": r["status"], "error": r.get("error")})
                if r["status"] == "found":
                    errs = persist_dns_history_findings(rt, r["records"], target, store)
                    if errs:
                        summary["errors"].append({"stage": "persist_dns_history", "record_type": rt, "errors": errs})
                    summary["dns_history"].extend(r["records"])
                elif r["status"] == "not_found":
                    no_result_checks.append((f"dns_history_{rt}", f"SecurityTrails recorded no historical {rt.upper()} data for {target}"))
                elif r["status"] in ("unauthorized", "rate_limited", "forbidden"):
                    summary["errors"].append({"stage": "dns_history", "record_type": rt, "error": r.get("error")})
                    break
                if request_delay > 0 and idx < len(dns_history_record_types) - 1:
                    time.sleep(request_delay)
            summary["source_status"]["dns_history_queries"] = per_type_status

    # --- 8. Reverse-IP intelligence ---
    if include_reverse_ip:
        if not seed["ip"]:
            summary["source_status"]["reverse_ip"] = {
                "status": "no_seed_ip",
                "error": "No DNS-resolved IP available (from passive_recon.py dns_record findings or seed_ip parameter)",
            }
        else:
            try:
                r = query_hackertarget_reverse_ip(seed["ip"], api_key=hackertarget_api_key, timeout=timeout)
            except Exception as exc:
                r = {"status": "error", "error": str(exc), "domains": []}
            summary["source_status"]["reverse_ip"] = {"status": r["status"], "error": r.get("error"), "ip": seed["ip"]}
            if r["status"] == "found":
                errs = persist_reverse_ip_findings(r["domains"], seed["ip"], target, store)
                if errs:
                    summary["errors"].append({"stage": "persist_reverse_ip", "errors": errs})
                summary["reverse_ip"] = r["domains"]
            elif r["status"] == "not_found":
                no_result_checks.append(("reverse_ip", f"No co-hosted domains found for {seed['ip']}"))

    # --- 11. ASN neighbor analysis ---
    if include_asn_neighbors:
        if not seed["asn"]:
            summary["source_status"]["asn_neighbors"] = {
                "status": "no_seed_asn",
                "error": "No ASN available (from passive_recon.py asn findings or seed_asn parameter)",
            }
        else:
            try:
                r = query_bgpview_asn_peers(seed["asn"], timeout=timeout)
            except Exception as exc:
                r = {"status": "error", "error": str(exc), "peers": []}
            summary["source_status"]["asn_neighbors"] = {"status": r["status"], "error": r.get("error"), "asn": seed["asn"]}
            if r["status"] == "found":
                errs = persist_asn_neighbor_findings(r["peers"], seed["asn"], target, store)
                if errs:
                    summary["errors"].append({"stage": "persist_asn_neighbors", "errors": errs})
                summary["asn_neighbors"] = r["peers"]
            elif r["status"] == "not_found":
                no_result_checks.append(("asn_neighbors", f"No BGP peer/neighbor ASNs found for AS{seed['asn']}"))

    if no_result_checks:
        nr_errors = persist_no_result_findings(no_result_checks, target, store)
        if nr_errors:
            summary["errors"].append({"stage": "negative_result_memory", "errors": nr_errors})

    summary["stats"] = {
        "emails_found": len(merged_emails),
        "employees_inferred": len(employees),
        "dork_results_found": len(summary["dork_results"]),
        "paste_references_found": len(summary["paste_references"]),
        "job_tech_inferences_found": len(summary["job_tech_inferences"]),
        "breach_domain_records_found": len(summary["breach_domain_records"]),
        "breach_account_records_found": len(summary["breach_account_records"]),
        "dns_history_records_found": len(summary["dns_history"]),
        "reverse_ip_domains_found": len(summary["reverse_ip"]),
        "asn_neighbors_found": len(summary["asn_neighbors"]),
        "no_result_checks": len(no_result_checks),
        "seed_ip": seed["ip"],
        "seed_asn": seed["asn"],
    }
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="osint_engine.py",
        description="ReconHound Module 4 — OSINT / digital-footprint intelligence "
                     "(standalone test entry point).",
    )
    parser.add_argument("--target", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--google-api-key", default=None, help=f"Google API key (or set {GOOGLE_API_KEY_ENV})")
    parser.add_argument("--google-cse-id", default=None, help=f"Google Custom Search Engine ID (or set {GOOGLE_CSE_ID_ENV})")
    parser.add_argument("--hibp-api-key", default=None, help=f"HIBP API key (or set {HIBP_API_KEY_ENV})")
    parser.add_argument("--securitytrails-api-key", default=None, help=f"SecurityTrails API key (or set {SECURITYTRAILS_API_KEY_ENV})")
    parser.add_argument("--hackertarget-api-key", default=None, help=f"HackerTarget API key (or set {HACKERTARGET_API_KEY_ENV})")
    parser.add_argument("--seed-ip", default=None, help="Override the seed IP used for reverse-IP lookup")
    parser.add_argument("--seed-asn", default=None, help="Override the seed ASN used for ASN neighbor analysis")
    parser.add_argument("--no-ct", action="store_true", help="Skip Certificate Transparency email harvesting")
    parser.add_argument("--no-search-email", action="store_true", help="Skip search-engine email harvesting")
    parser.add_argument("--no-dorking", action="store_true", help="Skip Google dork automation")
    parser.add_argument("--no-paste", action="store_true", help="Skip paste-site intelligence")
    parser.add_argument("--no-job-tech", action="store_true", help="Skip job-posting tech-stack inference")
    parser.add_argument("--no-hibp-domain", action="store_true", help="Skip HIBP domain-breach lookup")
    parser.add_argument("--no-hibp-account", action="store_true", help="Skip HIBP account-breach correlation")
    parser.add_argument("--no-dns-history", action="store_true", help="Skip DNS history lookup")
    parser.add_argument("--no-reverse-ip", action="store_true", help="Skip reverse-IP intelligence")
    parser.add_argument("--no-asn-neighbors", action="store_true", help="Skip ASN neighbor analysis")
    parser.add_argument("--max-ct-certs", type=int, default=15, help="Max certificates to inspect for CT-log email harvesting")
    parser.add_argument("--max-hibp-accounts", type=int, default=10, help="Max emails to check against HIBP's account endpoint")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-query network timeout (seconds)")
    parser.add_argument("--request-delay", type=float, default=DEFAULT_REQUEST_DELAY, help="Delay between successive third-party API calls (seconds)")
    args = parser.parse_args()

    try:
        result = run_osint_engine(
            args.target,
            output_dir=args.output_dir,
            google_api_key=args.google_api_key,
            google_cse_id=args.google_cse_id,
            hibp_api_key=args.hibp_api_key,
            securitytrails_api_key=args.securitytrails_api_key,
            hackertarget_api_key=args.hackertarget_api_key,
            seed_ip=args.seed_ip,
            seed_asn=args.seed_asn,
            include_ct=not args.no_ct,
            include_search_email=not args.no_search_email,
            include_dorking=not args.no_dorking,
            include_paste=not args.no_paste,
            include_job_tech=not args.no_job_tech,
            include_hibp_domain=not args.no_hibp_domain,
            include_hibp_account=not args.no_hibp_account,
            include_dns_history=not args.no_dns_history,
            include_reverse_ip=not args.no_reverse_ip,
            include_asn_neighbors=not args.no_asn_neighbors,
            max_ct_certs=args.max_ct_certs,
            max_hibp_accounts=args.max_hibp_accounts,
            timeout=args.timeout,
            request_delay=args.request_delay,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
