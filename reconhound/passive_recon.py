"""
reconhound/passive_recon.py — ReconHound Module 1 (passive_recon.py).

Phase: Passive. See context.md §10 (module 1) for the authoritative
responsibilities, and §8 for the evidence/confidence data model this
module implements. This file only documents implementation-specific
detail, not the architecture itself.

Scope of this module:
  - DNS enumeration (A, AAAA, CNAME, MX, TXT, NS, SOA)
  - WHOIS lookup
  - TLS certificate discovery + SAN extraction (single lightweight
    handshake to grab the presented leaf certificate; deep TLS/cert
    security analysis is ssl_analyzer.py's job, not this module's)
  - Passive ASN / IP-range lookup (via Team Cymru's public DNS-based
    IP-to-ASN service, not the target)
  - Lightweight organization-infrastructure aggregation
  - Email security posture (SPF, DMARC, best-effort DKIM, MX analysis)

Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (crash-safe, atomic writes). Output feeds
surface_mapper.py (module 6).

Result semantics (context.md §8): this module never collapses fundamentally
different outcomes into one status. A provider failure is not a negative
result, and a check that could only sample a bounded set of possibilities
(DKIM selectors) never reports global absence.
"""

from __future__ import annotations

import argparse
import inspect
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver
import whois as python_whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend

MODULE_NAME = "passive_recon.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]

# A small set of widely-used DKIM selectors. Passive DKIM discovery cannot
# reliably enumerate the actual selector a domain uses without additional
# OSINT (e.g. leaked email headers), so this is explicitly a best-effort,
# low-confidence check rather than an authoritative negative result.
_COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "dkim", "mail"]

# DKIM result vocabulary. "not_found_among_tested" deliberately does not read
# as "this domain has no DKIM" — a domain may publish any selector name, so a
# bounded probe can never establish global absence (see analyze_email_security).
DKIM_FOUND = "found"
DKIM_NOT_FOUND_AMONG_TESTED = "not_found_among_tested"
DKIM_INCONCLUSIVE = "inconclusive"
DKIM_NOT_TESTED = "not_tested"

# ---------------------------------------------------------------------------
# WHOIS provider-failure classification
#
# python-whois raises a typed exception hierarchy, but the pinned range
# (>=0.9,<1) does not guarantee every class exists, so resolve them
# defensively rather than importing names that may be absent.
# ---------------------------------------------------------------------------

WHOIS_ERROR_NO_MATCH = "no_match"
WHOIS_ERROR_RATE_LIMITED = "rate_limited"
WHOIS_ERROR_TIMEOUT = "timeout"
WHOIS_ERROR_UNSUPPORTED_TLD = "unsupported_tld"
WHOIS_ERROR_PARSE_FAILED = "parse_failed"
WHOIS_ERROR_PROVIDER_UNAVAILABLE = "provider_unavailable"

# Only transient provider-side conditions are retried. A domain that does not
# exist, an unsupported TLD, or an unparseable response will return the same
# answer to an identical second query, so retrying those is pure load on the
# provider with no chance of a better result.
_WHOIS_RETRYABLE = frozenset({
    WHOIS_ERROR_RATE_LIMITED,
    WHOIS_ERROR_TIMEOUT,
    WHOIS_ERROR_PROVIDER_UNAVAILABLE,
})

_WHOIS_TIMEOUT_RE = re.compile(r"time[d]?\s*out|timeout", re.I)
_WHOIS_RATE_LIMIT_RE = re.compile(
    r"quota|rate.?limit|too many|exceeded|throttl|try again later|"
    r"temporarily unavailable|access denied", re.I
)
_WHOIS_NO_MATCH_RE = re.compile(
    r"no match|no data found|no entries found|no object found|"
    r"domain not found|not registered", re.I
)

# Registrars and privacy services return placeholder strings rather than
# omitting withheld fields. Treating those placeholders as real registrant
# data puts values like "REDACTED FOR PRIVACY" into the asset graph as an
# Organization, so they are classified as redacted instead of dropped.
_WHOIS_REDACTION_RE = re.compile(
    r"redact|privacy|data\s*protected|not\s*disclosed|withheld|gdpr|"
    r"statutory\s*masking|non-public\s*data|anonymi[sz]ed|"
    r"domains\s*by\s*proxy", re.I
)

# Redaction screening applies ONLY to registrant-attribution fields — the ones
# privacy services actually mask, and the ones a placeholder would corrupt
# downstream (`org` becomes an Organization asset; `country` becomes a host
# attribute). It must NOT touch registration/infrastructure fields: a real
# nameserver "ns1.privacyprotect.org", a real registrar "Domains By Proxy,
# LLC", or a real "whois.privacyprotect.org" all match the placeholder wording
# while being genuine, load-bearing infrastructure data. Screening those would
# delete true assets from the graph — a worse error than the one this fixes.
_WHOIS_REDACTABLE_FIELDS = frozenset({"org", "country", "emails"})

try:
    _WHOIS_SUPPORTS_TIMEOUT = "timeout" in inspect.signature(python_whois.whois).parameters
except (TypeError, ValueError):  # pragma: no cover - defensive, C-implemented callable
    _WHOIS_SUPPORTS_TIMEOUT = False

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class ScopeError(ValueError):
    """Raised when a target/input falls outside this module's authorized scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def validate_target(target: str) -> str:
    """
    Validate that `target` is a syntactically valid, explicit domain name.

    passive_recon operates on exactly one explicit target domain per
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
    """
    True if `hostname` is the target itself or a subdomain of it.

    Used to flag discovered hostnames (e.g. certificate SAN entries) that
    fall outside the authorized target — such hostnames are still recorded
    (never silently dropped, per the evidence model) but tagged so nothing
    downstream mistakes them for in-scope assets.
    """
    hostname = hostname.strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    return hostname == target or hostname.endswith("." + target)


# ---------------------------------------------------------------------------
# Evidence-model helpers
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


def _jsonify(value: Any) -> Any:
    """Recursively coerce WHOIS-library return values into JSON-safe types."""
    if isinstance(value, dict):
        return {str(k): _jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _classify_whois_error(exc: BaseException) -> str:
    """
    Map a WHOIS failure onto a stable, actionable error class.

    The distinction that matters downstream is "the registry answered and the
    domain has no record" (a genuine negative result) versus "the provider
    refused, throttled, or never answered" (no result at all). Collapsing the
    second into the first would report a false absence.
    """
    exceptions = getattr(python_whois, "exceptions", None)
    if exceptions is not None:
        for name, code in (
            ("WhoisQuotaExceededError", WHOIS_ERROR_RATE_LIMITED),
            ("WhoisDomainNotFoundError", WHOIS_ERROR_NO_MATCH),
            ("UnknownTldError", WHOIS_ERROR_UNSUPPORTED_TLD),
            ("FailedParsingWhoisOutputError", WHOIS_ERROR_PARSE_FAILED),
            ("WhoisCommandFailedError", WHOIS_ERROR_PROVIDER_UNAVAILABLE),
        ):
            cls = getattr(exceptions, name, None)
            if isinstance(cls, type) and isinstance(exc, cls):
                return code

    message = str(exc)
    if isinstance(exc, (socket.timeout, TimeoutError)) or _WHOIS_TIMEOUT_RE.search(message):
        return WHOIS_ERROR_TIMEOUT
    if _WHOIS_RATE_LIMIT_RE.search(message):
        return WHOIS_ERROR_RATE_LIMITED
    # Transport-level failures are checked before the no-match wording so that
    # e.g. a socket error mentioning "not found" is not mistaken for a registry
    # answer of "this domain does not exist".
    if isinstance(exc, OSError):
        return WHOIS_ERROR_PROVIDER_UNAVAILABLE
    if _WHOIS_NO_MATCH_RE.search(message):
        return WHOIS_ERROR_NO_MATCH
    return WHOIS_ERROR_PROVIDER_UNAVAILABLE


def _is_redacted_value(value: Any) -> bool:
    """
    True if `value` is a privacy/GDPR placeholder rather than real data.

    Only meaningful for the registrant-attribution fields in
    `_WHOIS_REDACTABLE_FIELDS`; the same wording occurs legitimately inside
    registrar names and nameserver hostnames.
    """
    if isinstance(value, str):
        return bool(_WHOIS_REDACTION_RE.search(value))
    if isinstance(value, list):
        return bool(value) and all(_is_redacted_value(v) for v in value)
    return False


def _whois_query(target: str, timeout: float) -> Any:
    """Single WHOIS query, honouring a timeout when the library supports one."""
    if _WHOIS_SUPPORTS_TIMEOUT:
        return python_whois.whois(target, timeout=int(max(1, round(timeout))))
    return python_whois.whois(target)


def _name_to_dict(name: "x509.Name") -> Dict[str, str]:
    result: Dict[str, str] = {}
    for attr in name:
        key = attr.oid._name if attr.oid._name else attr.oid.dotted_string
        result[key] = attr.value
    return result


# ---------------------------------------------------------------------------
# Crash-safe persistence
# ---------------------------------------------------------------------------

class PendingAssetsStore:
    """
    Crash-safe, append-oriented persistence for <output_dir>/pending_assets.json.

    Every call to add() re-reads the current file, appends the new finding,
    and atomically rewrites the file (write-to-temp + os.replace) so a
    crash mid-write can never corrupt previously persisted discoveries, and
    pre-existing discoveries from other runs/modules are always preserved.
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
            self._fsync_dir(dir_name)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    @staticmethod
    def _fsync_dir(dir_name: str) -> None:
        """
        Durably commit the os.replace() rename itself.

        Without this the replacement file's *contents* are on disk but the
        directory entry pointing at them may not be, so a power loss can still
        resurrect the pre-replace file and lose the discoveries appended since.
        Best-effort: some platforms/filesystems refuse to fsync a directory.
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


# ---------------------------------------------------------------------------
# DNS enumeration
# ---------------------------------------------------------------------------

def enumerate_dns(
    target: str,
    store: Optional[PendingAssetsStore] = None,
    record_types: Optional[List[str]] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Query A/AAAA/CNAME/MX/TXT/NS/SOA records for `target`.

    Returns {record_type: {"status": "found"|"not_found"|"error",
                            "records": [...], "error": str|None}}.
    Persists one finding per record type that returns results.
    """
    target = validate_target(target)
    record_types = record_types or DNS_RECORD_TYPES

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results: Dict[str, Any] = {}

    for rtype in record_types:
        entry: Dict[str, Any] = {"status": "not_found", "records": [], "error": None}
        try:
            answer = resolver.resolve(target, rtype)
            values = sorted({rdata.to_text() for rdata in answer})
            entry["status"] = "found"
            entry["records"] = values
            if store is not None:
                store.add(make_finding(
                    finding_type="dns_record",
                    target=target,
                    value={"record_type": rtype, "records": values},
                    evidence=[f"DNS {rtype} query for {target} returned {len(values)} record(s)"],
                    confidence=CONFIDENCE_HIGH,
                    metadata={"record_type": rtype},
                ))
        except dns.resolver.NXDOMAIN:
            entry["status"] = "not_found"
            entry["error"] = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            entry["status"] = "not_found"
            entry["error"] = "no answer"
        except dns.exception.Timeout as exc:
            entry["status"] = "error"
            entry["error"] = f"timeout: {exc}"
        except Exception as exc:  # never let one record type kill the whole module
            entry["status"] = "error"
            entry["error"] = str(exc)
        results[rtype] = entry

    return results


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

_WHOIS_FIELDS = (
    "domain_name", "registrar", "whois_server", "creation_date",
    "expiration_date", "updated_date", "name_servers", "status",
    "emails", "org", "country",
)


def whois_lookup(
    target: str,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = 10.0,
    max_attempts: int = 3,
    backoff: float = 2.0,
) -> Dict[str, Any]:
    """
    WHOIS registration lookup for `target`.

    WHOIS providers throttle, refuse, and intermittently fail; transient
    failures are retried a small, bounded number of times with conservative
    exponential backoff. Non-transient outcomes (domain does not exist,
    unsupported TLD, unparseable response) are never retried — the answer
    would not change and repeating the query only adds provider load. This is
    resilience, not rate-limit evasion: there is no proxying, no rotation, and
    at most `max_attempts` queries per lookup.

    Privacy-protected WHOIS is a first-class outcome, not a failure. Registrar
    placeholders ("REDACTED FOR PRIVACY", "Data Protected", ...) are recorded
    under `redacted_fields` instead of being presented as real registrant
    data, so nothing downstream mistakes a privacy placeholder for an
    organization name.

    Returns::

        {"status": "found"|"not_found"|"error",
         "data": {...},                  # fields carrying real values
         "redacted_fields": {...},       # fields the registrar withheld
         "completeness": "full"|"partial_redacted"|"empty"|None,
         "error": str|None,
         "error_class": str|None,        # WHOIS_ERROR_* when known
         "attempts": int}
    """
    target = validate_target(target)
    result: Dict[str, Any] = {
        "status": "not_found",
        "data": {},
        "redacted_fields": {},
        "completeness": None,
        "error": None,
        "error_class": None,
        "attempts": 0,
    }

    attempts = max(1, int(max_attempts))
    raw: Any = None
    for attempt in range(1, attempts + 1):
        result["attempts"] = attempt
        try:
            raw = _whois_query(target, timeout=timeout)
            result["error"] = None
            result["error_class"] = None
            break
        except Exception as exc:
            error_class = _classify_whois_error(exc)
            result["error"] = str(exc)
            result["error_class"] = error_class
            if error_class == WHOIS_ERROR_NO_MATCH:
                # The registry answered: this domain genuinely has no record.
                # That is a negative result, not a provider failure.
                result["status"] = "not_found"
                result["completeness"] = "empty"
                return result
            if error_class not in _WHOIS_RETRYABLE or attempt >= attempts:
                result["status"] = "error"
                return result
            time.sleep(backoff * (2 ** (attempt - 1)))

    data: Dict[str, Any] = {}
    redacted: Dict[str, Any] = {}
    if raw:
        for key in _WHOIS_FIELDS:
            value = raw.get(key) if hasattr(raw, "get") else getattr(raw, key, None)
            if value is None:
                continue
            coerced = _jsonify(value)
            if key in _WHOIS_REDACTABLE_FIELDS and _is_redacted_value(coerced):
                redacted[key] = coerced
            else:
                data[key] = coerced

    if not data and not redacted:
        # The provider answered but carried nothing usable. Distinct from an
        # error (nobody answered) and from a redacted response (answered, but
        # withheld).
        result["status"] = "not_found"
        result["completeness"] = "empty"
        return result

    result["status"] = "found"
    result["completeness"] = "partial_redacted" if redacted else "full"
    result["redacted_fields"] = redacted
    if redacted:
        # Preserved inside the persisted value so the withholding itself stays
        # traceable evidence; the key is namespaced so downstream consumers
        # reading specific WHOIS fields never pick a placeholder up as data.
        data["redacted_fields"] = redacted
    result["data"] = data

    if store is not None:
        evidence = [f"WHOIS lookup for {target} returned registration data"]
        if redacted:
            evidence.append(
                "Registrar/privacy service withheld: "
                + ", ".join(sorted(redacted))
                + " — the underlying registrant data is not observable here, "
                  "which is not evidence that it does not exist"
            )
        if result["attempts"] > 1:
            evidence.append(
                f"WHOIS provider required {result['attempts']} attempt(s) "
                f"before responding"
            )
        store.add(make_finding(
            finding_type="whois",
            target=target,
            value=data,
            evidence=evidence,
            # A privacy-protected record is a partial observation: the
            # registration facts are solid, the registrant attribution is
            # provably withheld, so it must not be presented as certainty.
            confidence=CONFIDENCE_MEDIUM if redacted else CONFIDENCE_HIGH,
            metadata={
                "completeness": result["completeness"],
                "redacted_fields": sorted(redacted),
                "attempts": result["attempts"],
            },
        ))
    return result


# ---------------------------------------------------------------------------
# TLS certificate discovery + SAN extraction
# ---------------------------------------------------------------------------

def discover_tls_certificate(
    target: str,
    port: int = 443,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Perform a single TLS handshake against target:port to retrieve the
    presented leaf certificate and extract Subject Alternative Names.

    This is one minimal, non-intrusive connection (no port scanning, no
    brute forcing) used purely to bootstrap hostname discovery via SAN
    entries. Certificate/chain validation is intentionally skipped
    (verify_mode=CERT_NONE) so that self-signed, expired, or
    hostname-mismatched certificates — common on real-world recon
    targets — are still captured; the certificate is parsed directly
    from its DER bytes via `cryptography` rather than relying on
    Python's ssl.getpeercert(), which only returns parsed fields for a
    *validated* chain. Deep certificate/TLS security analysis (validity
    windows, cipher suites, chain trust, downgrade checks) is out of
    scope here and belongs to ssl_analyzer.py.
    """
    target = validate_target(target)
    result: Dict[str, Any] = {
        "status": "not_found",
        "certificate": None,
        "sans": [],
        "error": None,
        "error_class": None,
    }

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
    # ssl.SSLError is a subclass of OSError, so it must be caught first or the
    # broader clause below swallows it and a TLS negotiation failure becomes
    # indistinguishable from a refused connection.
    except ssl.SSLError as exc:
        result["status"] = "error"
        result["error"] = f"TLS handshake failed: {exc}"
        result["error_class"] = "tls_handshake_failed"
        return result
    except (socket.timeout, TimeoutError) as exc:
        result["status"] = "error"
        result["error"] = f"timeout: {exc}"
        result["error_class"] = "timeout"
        return result
    except socket.gaierror as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        result["error_class"] = "name_resolution_failed"
        return result
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        result["error_class"] = "connection_failed"
        return result

    if not der:
        result["status"] = "not_found"
        result["error"] = "server presented no certificate"
        return result

    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"failed to parse certificate: {exc}"
        result["error_class"] = "certificate_parse_failed"
        return result

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    parsed = {
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "serial_number": str(cert.serial_number),
        "sans": sans,
    }

    result["status"] = "found"
    result["certificate"] = parsed
    result["sans"] = sans

    if store is not None:
        store.add(make_finding(
            finding_type="tls_certificate",
            target=target,
            value=parsed,
            evidence=[f"TLS handshake to {target}:{port} returned a leaf certificate"],
            confidence=CONFIDENCE_HIGH,
            metadata={"port": port},
        ))
        for san in sans:
            store.add(make_finding(
                finding_type="tls_san",
                target=target,
                value=san,
                evidence=[f"Certificate SAN entry from {target}:{port} leaf certificate"],
                confidence=CONFIDENCE_HIGH if is_in_scope(san, target) else CONFIDENCE_MEDIUM,
                metadata={"port": port, "in_scope": is_in_scope(san, target)},
            ))

    return result


# ---------------------------------------------------------------------------
# Passive ASN / IP-range intelligence
# ---------------------------------------------------------------------------

def discover_asn(
    ip: str,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Passive ASN / IP-range lookup via Team Cymru's public DNS-based
    IP-to-ASN service. This queries Cymru's DNS infrastructure only —
    never the target itself — keeping the check fully passive.
    """
    result: Dict[str, Any] = {"status": "not_found", "data": {}, "error": None, "error_class": None}

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        result["status"] = "error"
        result["error"] = f"not a valid IP address: {ip!r}"
        result["error_class"] = "invalid_input"
        return result

    if ip_obj.version != 4:
        result["status"] = "error"
        result["error"] = "ASN discovery currently supports IPv4 only"
        result["error_class"] = "unsupported_address_family"
        return result

    if not ip_obj.is_global:
        # Cymru only maps publicly announced address space, so querying it for
        # private/reserved/loopback addresses is a guaranteed-empty request.
        # Skipping it avoids needless lookups and, more importantly, reports
        # the true outcome instead of a spurious resolver error.
        result["status"] = "not_found"
        result["error"] = (
            "IP is not globally routable (private/reserved/loopback); "
            "Team Cymru maps publicly announced address space only"
        )
        result["error_class"] = "not_globally_routable"
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    reversed_ip = ".".join(reversed(ip.split(".")))
    origin_query = f"{reversed_ip}.origin.asn.cymru.com"

    try:
        answer = resolver.resolve(origin_query, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Cymru answered authoritatively: this IP sits in no publicly
        # announced prefix. A negative result, not a failed lookup.
        result["status"] = "not_found"
        result["error"] = "no Team Cymru origin record; IP is not in an announced BGP prefix"
        result["error_class"] = "not_announced"
        return result
    except dns.exception.Timeout as exc:
        result["status"] = "error"
        result["error"] = f"timeout: {exc}"
        result["error_class"] = "timeout"
        return result
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        result["error_class"] = "lookup_failed"
        return result

    txt = answer[0].to_text().strip('"')
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 5:
        result["status"] = "error"
        result["error"] = f"unexpected Cymru response format: {txt!r}"
        result["error_class"] = "unexpected_response"
        return result

    asn, prefix, country, registry, allocated = parts[:5]
    data = {
        "ip": ip,
        "asn": asn,
        "bgp_prefix": prefix,
        "country": country,
        "registry": registry,
        "allocated": allocated,
        "as_name": None,
    }

    try:
        as_answer = resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
        as_txt = as_answer[0].to_text().strip('"')
        as_parts = [p.strip() for p in as_txt.split("|")]
        if len(as_parts) >= 5:
            data["as_name"] = as_parts[4]
    except Exception:
        pass  # AS-name enrichment is best-effort; ASN/prefix already satisfy the check

    result["status"] = "found"
    result["data"] = data

    if store is not None:
        store.add(make_finding(
            finding_type="asn",
            target=target or ip,
            value=data,
            evidence=[f"Team Cymru DNS ASN lookup for {ip} resolved to AS{asn}"],
            confidence=CONFIDENCE_MEDIUM,
            metadata={"ip": ip},
        ))

    return result


# ---------------------------------------------------------------------------
# Email security posture
# ---------------------------------------------------------------------------

def analyze_email_security(
    target: str,
    store: Optional[PendingAssetsStore] = None,
    timeout: float = 5.0,
    dkim_selectors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    SPF, DMARC, best-effort DKIM, and MX analysis for `target`.

    DKIM is inherently a *sampled* check: a domain may publish a record under
    any selector name it likes, and there is no way to enumerate selectors
    from DNS. This function therefore probes a bounded list of widely used
    selectors and reports what it actually observed:

      found                   at least one probed selector has a record
      not_found_among_tested  every probed selector answered authoritatively
                              with no record — this is NOT "the domain has no
                              DKIM", because untested selectors may exist
      inconclusive            one or more probes failed (timeout/SERVFAIL), so
                              no authoritative negative was established at all
      not_tested              no selectors were probed

    Selector brute forcing is deliberately not performed; `exhaustive` is
    always False so no consumer can read the result as proof of absence.
    """
    target = validate_target(target)

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    selectors = list(_COMMON_DKIM_SELECTORS if dkim_selectors is None else dkim_selectors)

    result: Dict[str, Any] = {
        "spf": {"status": "not_found", "record": None, "records": []},
        "dmarc": {"status": "not_found", "record": None, "records": []},
        "dkim": {
            "status": DKIM_NOT_TESTED,  # replaced once the probes below complete
            "selectors_checked": selectors,
            "found_selectors": [],
            "selectors_without_record": [],
            "selectors_errored": [],
            "exhaustive": False,
        },
        "mx": {"status": "not_found", "records": []},
    }

    try:
        answer = resolver.resolve(target, "TXT")
        txts = [rdata.to_text().strip('"') for rdata in answer]
        spf_records = [t for t in txts if t.lower().startswith("v=spf1")]
        if spf_records:
            result["spf"]["status"] = "found"
            result["spf"]["record"] = spf_records[0]
            result["spf"]["records"] = spf_records
            if len(spf_records) > 1:
                # More than one SPF record is itself a misconfiguration.
                # Surface the conflict rather than silently keeping the first
                # (context.md §8, conflict detection).
                result["spf"]["conflict"] = (
                    f"{len(spf_records)} SPF records published; RFC 7208 permits one"
                )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as exc:
        result["spf"]["status"] = "error"
        result["spf"]["error"] = str(exc)

    try:
        answer = resolver.resolve(f"_dmarc.{target}", "TXT")
        txts = [rdata.to_text().strip('"') for rdata in answer]
        dmarc_records = [t for t in txts if t.lower().startswith("v=dmarc1")]
        if dmarc_records:
            result["dmarc"]["status"] = "found"
            result["dmarc"]["record"] = dmarc_records[0]
            result["dmarc"]["records"] = dmarc_records
            if len(dmarc_records) > 1:
                result["dmarc"]["conflict"] = (
                    f"{len(dmarc_records)} DMARC records published; RFC 7489 permits one"
                )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as exc:
        result["dmarc"]["status"] = "error"
        result["dmarc"]["error"] = str(exc)

    found_selectors: List[Dict[str, Any]] = []
    absent_selectors: List[str] = []
    errored_selectors: List[Dict[str, str]] = []
    for selector in selectors:
        try:
            answer = resolver.resolve(f"{selector}._domainkey.{target}", "TXT")
            txts = [rdata.to_text().strip('"') for rdata in answer]
            if txts:
                found_selectors.append({"selector": selector, "record": txts[0]})
            else:
                absent_selectors.append(selector)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Authoritative negative for this selector specifically.
            absent_selectors.append(selector)
        except Exception as exc:
            # A resolver/provider failure is not evidence that the selector is
            # unused. Treating it as "not found" is exactly how a failed lookup
            # turns into a false absence claim.
            errored_selectors.append({"selector": selector, "error": str(exc)})

    if found_selectors:
        dkim_status = DKIM_FOUND
    elif not selectors:
        dkim_status = DKIM_NOT_TESTED
    elif errored_selectors:
        dkim_status = DKIM_INCONCLUSIVE
    else:
        dkim_status = DKIM_NOT_FOUND_AMONG_TESTED

    result["dkim"]["status"] = dkim_status
    result["dkim"]["found_selectors"] = found_selectors
    result["dkim"]["selectors_without_record"] = absent_selectors
    result["dkim"]["selectors_errored"] = errored_selectors

    try:
        answer = resolver.resolve(target, "MX")
        mx_records = sorted(
            [{"priority": r.preference, "exchange": str(r.exchange).rstrip(".")} for r in answer],
            key=lambda r: r["priority"],
        )
        if mx_records:
            result["mx"]["status"] = "found"
            result["mx"]["records"] = mx_records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as exc:
        result["mx"]["status"] = "error"
        result["mx"]["error"] = str(exc)

    if store is not None:
        evidence = []
        if result["spf"]["status"] == "found":
            evidence.append("SPF TXT record present on apex domain")
        if result["dmarc"]["status"] == "found":
            evidence.append("DMARC TXT record present on _dmarc subdomain")
        if result["spf"].get("conflict"):
            evidence.append(f"Conflict: {result['spf']['conflict']}")
        if result["dmarc"].get("conflict"):
            evidence.append(f"Conflict: {result['dmarc']['conflict']}")
        if dkim_status == DKIM_FOUND:
            selector_names = ", ".join(s["selector"] for s in found_selectors)
            evidence.append(f"DKIM TXT record present for selector(s): {selector_names}")
        elif dkim_status == DKIM_INCONCLUSIVE:
            evidence.append(
                f"DKIM inconclusive: {len(errored_selectors)} of {len(selectors)} "
                f"selector lookup(s) failed, so no authoritative negative was established"
            )
        elif dkim_status == DKIM_NOT_FOUND_AMONG_TESTED:
            evidence.append(
                f"No DKIM record among the {len(absent_selectors)} common selector(s) "
                f"tested; a domain may publish any selector name, so this is not "
                f"evidence that DKIM is unconfigured"
            )
        if result["mx"]["status"] == "found":
            evidence.append(f"{len(result['mx']['records'])} MX record(s) found")
        if all(result[k]["status"] != "found" for k in ("spf", "dmarc", "dkim", "mx")):
            evidence.append("No SPF or DMARC record observed on this domain")

        confidence = (
            CONFIDENCE_HIGH
            if result["spf"]["status"] == "found" or result["dmarc"]["status"] == "found"
            else CONFIDENCE_LOW
        )

        store.add(make_finding(
            finding_type="email_security",
            target=target,
            value=result,
            evidence=evidence,
            confidence=confidence,
            metadata={
                "dkim_status": dkim_status,
                "dkim_selectors_tested": len(selectors),
                "dkim_selectors_errored": len(errored_selectors),
                "dkim_exhaustive": False,
                "dkim_note": (
                    "DKIM checked against a fixed list of common selectors only; "
                    "absence of a match does not confirm DKIM is unconfigured."
                ),
            },
        ))

    return result


# ---------------------------------------------------------------------------
# Organization infrastructure aggregation (lightweight)
# ---------------------------------------------------------------------------

def _build_organization_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    """
    Lightweight aggregation of organization-identifying fields already
    collected by this module (WHOIS registrant org, ASN organization
    names). Deep cross-asset organization mapping across the whole asset
    graph is surface_mapper.py's responsibility, not this module's.
    """
    org_names = set()
    whois_org = summary.get("whois", {}).get("data", {}).get("org")
    if whois_org:
        if isinstance(whois_org, list):
            org_names.update(str(o) for o in whois_org if o)
        else:
            org_names.add(str(whois_org))

    asn_orgs = set()
    for entry in summary.get("asn", []):
        name = entry.get("data", {}).get("as_name")
        if name:
            asn_orgs.add(name)

    return {
        "whois_organizations": sorted(org_names),
        "asn_organizations": sorted(asn_orgs),
    }


# ---------------------------------------------------------------------------
# Module orchestration
# ---------------------------------------------------------------------------

def run_passive_recon(
    target: str,
    output_dir: str = "output",
    timeout: float = 5.0,
    enable_asn: bool = True,
) -> Dict[str, Any]:
    """
    Run all Module 1 passive-recon checks against `target` and persist
    every discovery immediately to <output_dir>/pending_assets.json.

    Returns a structured summary of everything discovered in this run, in
    addition to (not instead of) the crash-safe persisted store.
    """
    target = validate_target(target)
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "target": target,
        "module": MODULE_NAME,
        "started_at": _now(),
        "dns": {},
        "whois": {},
        "tls_certificate": {},
        "asn": [],
        "email_security": {},
        "organization": {},
        "errors": [],
    }

    try:
        summary["dns"] = enumerate_dns(target, store=store, timeout=timeout)
    except ScopeError:
        raise
    except Exception as exc:
        summary["errors"].append({"stage": "dns", "error": str(exc)})

    try:
        summary["whois"] = whois_lookup(target, store=store)
    except Exception as exc:
        summary["errors"].append({"stage": "whois", "error": str(exc)})

    try:
        summary["tls_certificate"] = discover_tls_certificate(target, store=store, timeout=timeout)
    except Exception as exc:
        summary["errors"].append({"stage": "tls_certificate", "error": str(exc)})

    if enable_asn:
        a_records = summary["dns"].get("A", {}).get("records", [])
        for ip in sorted(set(a_records)):
            try:
                summary["asn"].append(discover_asn(ip, store=store, target=target, timeout=timeout))
            except Exception as exc:
                summary["errors"].append({"stage": "asn", "ip": ip, "error": str(exc)})

    try:
        summary["email_security"] = analyze_email_security(target, store=store, timeout=timeout)
    except Exception as exc:
        summary["errors"].append({"stage": "email_security", "error": str(exc)})

    summary["organization"] = _build_organization_summary(summary)
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="passive_recon.py",
        description="ReconHound Module 1 — passive infrastructure reconnaissance "
                     "(standalone test entry point).",
    )
    parser.add_argument("--target", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-query network timeout (seconds)")
    args = parser.parse_args()

    try:
        result = run_passive_recon(args.target, output_dir=args.output_dir, timeout=args.timeout)
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
