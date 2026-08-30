"""
reconhound/ssl_analyzer.py — ReconHound Module 4 per context.md's build
order (§13); catalog item 17 in §10's module list.

Phase: Active. See context.md §10 (module 17, "TLS/cert intelligence") for
the authoritative responsibilities, and §8 for the evidence/confidence
data model this module implements. This file only documents
implementation-specific detail, not the architecture itself.

context.md's exact line for this module:

  "TLS/cert intelligence. Cert validity/expiration, TLS version detection
  (flag TLS 1.0/1.1 as outdated), cipher-suite analysis, hostname
  validation, SAN extraction (feeds new hostnames back to surface_mapper),
  cert-chain analysis, self-signed detection."

That is seven discrete responsibilities. Unlike active_recon.py's
independent per-protocol probes, all seven come from ONE TLS handshake, so
this module follows http_analyzer.py's fetch-once/analyze-many pattern: a
single low-level negotiation helper (`_negotiate_tls`) does the one I/O
operation, and seven pure functions (no network access) analyze its
result — directly testable with real certificates built via the
`cryptography` library, without mocking sockets at all:

  - Certificate validity/expiration -> analyze_certificate_validity
  - TLS version detection            -> analyze_tls_version
  - Cipher-suite analysis            -> analyze_cipher_suite
  - Hostname validation              -> validate_hostname_against_cert
  - SAN extraction                   -> extract_sans
  - Certificate-chain analysis       -> analyze_certificate_chain
  - Self-signed detection            -> detect_self_signed
  - (shared TLS handshake)           -> _negotiate_tls
  - (single-host orchestrator)       -> run_ssl_analysis

Relationship to passive_recon.py: Module 1's discover_tls_certificate()
already does a single lightweight handshake (CERT_NONE, no hostname
verification) purely to bootstrap SAN discovery; its own docstring
explicitly defers "deep certificate/TLS security analysis (validity
windows, cipher suites, chain trust, downgrade checks)" to this module.
This module does that deeper analysis. It is a separate handshake (its own
independent discovery, evidence-wise) rather than a call into Module 1 —
consistent with "modular independence" (context.md §12.2) and with how
Modules 2/3 already duplicate small conventions locally rather than
importing across module boundaries.

Implementation decisions:

  1. `ssl.match_hostname()` was removed in Python 3.12+ (this project runs
     3.13), so hostname matching (RFC 6125-style: exact match or a single
     leftmost wildcard label) is implemented locally in
     `_hostname_matches` using the certificate's parsed SAN/CN — no new
     dependency; `cryptography` (already a dependency since Module 1)
     supplies the parsed names.
  2. Certificate-chain analysis uses `SSLSocket.get_unverified_chain()`
     (stdlib, Python 3.13+) to obtain the chain exactly as presented by
     the server, then does structural analysis (subject/issuer linkage,
     self-signed root detection) via `cryptography` — the same library
     Module 1 already uses to parse the leaf certificate.
     `get_verified_chain()` was evaluated and rejected: empirically (see
     test suite) it can return a populated chain even under
     `CERT_NONE`/an untrusted chain, so its success/failure is not a
     reliable validity signal here; this module does its own explicit
     validity/hostname/self-signed analysis instead of trusting that API.
  3. TLS version detection reports the single actually-negotiated
     protocol from one default handshake — it does not attempt to force
     older protocol versions to probe what else the server might accept.
     That kind of multi-connection downgrade *testing* would start to
     resemble vulnerability scanning, which context.md and this task both
     explicitly say this module must not become; context.md's own wording
     ("TLS version detection ... flag TLS 1.0/1.1 as outdated") describes
     observing what's negotiated, not enumerating everything a server
     might support.
  4. No arbitrary "expiring soon" day-count threshold is invented (per
     explicit instruction). `days_until_expiry` (an integer, possibly
     negative) and `is_expired` (a direct fact: now vs. not_valid_after)
     are reported as data; any urgency judgment is left to the caller /
     a later module, not decided here.
  5. Self-signed detection uses issuer==subject name equality (the
     standard heuristic) as the primary signal, and additionally attempts
     genuine cryptographic self-signature verification (RSA/EC/Ed25519/
     Ed448 — all already supported by the `cryptography` dependency) as a
     confidence booster when the key type supports it. This is a passive,
     non-destructive verification of a public signature — not
     exploitation of anything.
  6. This module accepts either a domain name or an IPv4 literal as `host`
     (validate_ssl_host), covering both Module 1's domain-based and Module
     2's IP-based discovery styles — hostname validation is simply skipped
     (reported as such, not silently omitted) when there is no hostname to
     validate against.

Scope discipline: SAN hostnames discovered here are recorded as
discoveries only (finding_type "tls_san", reusing passive_recon.py's
established type name so future surface_mapper.py correlation can group
them regardless of which module produced them) — this module never
automatically connects to or analyzes a newly discovered SAN hostname.
Every discovery is persisted immediately to <output_dir>/pending_assets.json
via PendingAssetsStore (the same crash-safe, atomic-write store shared by
Modules 1-3). This module does not implement or call into surface_mapper.py,
endpoint_discovery.py, or any other later module.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, padding
from cryptography.x509.oid import NameOID

MODULE_NAME = "ssl_analyzer.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_TIMEOUT = 8.0
DEFAULT_PORT = 443

# context.md explicitly names TLS 1.0/1.1 as outdated; SSLv2/SSLv3 predate
# TLS entirely and are an uncontroversial superset of the same concept.
_OUTDATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

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

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _in_scope_host(hostname: str, target: str) -> bool:
    """Mirrors passive_recon.py's is_in_scope; duplicated per modular independence."""
    hostname = hostname.strip().rstrip(".").lower()
    target = target.strip().rstrip(".").lower()
    return hostname == target or hostname.endswith("." + target)


def validate_ssl_host(host: str, target: Optional[str] = None) -> str:
    """
    Validate that `host` is a syntactically valid bare hostname or IPv4
    address (never a URL/path/wildcard). If `target` is supplied and
    `host` is a domain name (not an IP literal), enforce that it is the
    target itself or a subdomain of it.
    """
    if not isinstance(host, str) or not host.strip():
        raise ScopeError("Host must be a non-empty string.")

    candidate = host.strip().rstrip(".").lower()

    if "://" in candidate or "/" in candidate:
        raise ScopeError(f"Host must be a bare hostname or IP, not a URL/path: {host!r}")
    if "*" in candidate:
        raise ScopeError(f"Wildcard hosts are not permitted: {host!r}")

    if _is_ip_literal(candidate):
        return candidate

    if not _DOMAIN_RE.match(candidate):
        raise ScopeError(f"Host is not a syntactically valid hostname or IP address: {host!r}")

    if target and not _in_scope_host(candidate, target):
        raise ScopeError(f"Host {candidate!r} is not in scope for target {target!r}")

    return candidate


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors passive_recon.py's/active_recon.py's/
# http_analyzer.py's model; kept local per the "modular independence"
# design principle, context.md §12.2)
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


def _name_to_dict(name: "x509.Name") -> Dict[str, str]:
    """Mirrors passive_recon.py's _name_to_dict; duplicated per modular independence."""
    result: Dict[str, str] = {}
    for attr in name:
        key = attr.oid._name if attr.oid._name else attr.oid.dotted_string
        result[key] = attr.value
    return result


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as Modules 1-3's
# PendingAssetsStore, duplicated here per modular independence rather than
# imported, so this module works standalone)
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


# ---------------------------------------------------------------------------
# Shared TLS handshake (not itself a listed context.md responsibility, but
# necessary plumbing — see module docstring)
# ---------------------------------------------------------------------------

def _negotiate_tls(
    host: str, port: int, sni_hostname: Optional[str], timeout: float,
) -> Dict[str, Any]:
    """
    Perform a single TLS handshake against host:port.

    Certificate/chain validation is intentionally skipped
    (verify_mode=CERT_NONE), exactly as passive_recon.py's
    discover_tls_certificate does, so that self-signed, expired, or
    hostname-mismatched certificates are still captured for this module's
    own analysis rather than causing the connection itself to fail.

    status is one of:
      "found"            - handshake completed, certificate obtained.
      "unavailable"       - the TLS service could not be reached at all
                             (DNS failure, connection refused, TCP-level
                             timeout) — a network/availability problem,
                             not a certificate/protocol problem.
      "handshake_failed"  - TCP connected, but the TLS handshake itself
                             failed (protocol mismatch, no shared cipher,
                             etc.).
      "error"             - an unexpected condition (e.g. no certificate
                             presented despite a completed handshake).
    """
    result: Dict[str, Any] = {
        "status": "error", "version": None, "cipher": None,
        "leaf_der": None, "chain_der": [], "error": None,
    }

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        result["status"] = "unavailable"
        result["error"] = f"connection timed out to {host}:{port}"
        return result
    except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
        result["status"] = "unavailable"
        result["error"] = str(exc)
        return result

    try:
        with sock:
            with context.wrap_socket(sock, server_hostname=sni_hostname) as tls_sock:
                leaf_der = tls_sock.getpeercert(binary_form=True)
                if not leaf_der:
                    result["status"] = "error"
                    result["error"] = "TLS handshake completed but server presented no certificate"
                    return result
                result["version"] = tls_sock.version()
                result["cipher"] = tls_sock.cipher()
                result["leaf_der"] = leaf_der
                try:
                    result["chain_der"] = list(tls_sock.get_unverified_chain() or [])
                except Exception:
                    result["chain_der"] = []
                result["status"] = "found"
    except ssl.SSLError as exc:
        result["status"] = "handshake_failed"
        result["error"] = f"TLS handshake failed: {exc}"
    except socket.timeout:
        result["status"] = "unavailable"
        result["error"] = "timeout during TLS handshake"
    except OSError as exc:
        result["status"] = "unavailable"
        result["error"] = str(exc)
    return result


# ---------------------------------------------------------------------------
# 1. Certificate validity / expiration
# ---------------------------------------------------------------------------

def analyze_certificate_validity(cert: "x509.Certificate") -> Dict[str, Any]:
    """
    Report the certificate's validity window as direct, objective facts.
    No "expiring soon" threshold is invented — `days_until_expiry` (which
    may be negative) is reported as data for the caller to judge urgency.
    """
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    is_expired = now > not_after
    is_not_yet_valid = now < not_before
    return {
        "not_valid_before": not_before.isoformat(),
        "not_valid_after": not_after.isoformat(),
        "is_currently_valid_period": not is_expired and not is_not_yet_valid,
        "is_expired": is_expired,
        "is_not_yet_valid": is_not_yet_valid,
        "days_until_expiry": (not_after - now).days,
    }


# ---------------------------------------------------------------------------
# 2. TLS version detection
# ---------------------------------------------------------------------------

def analyze_tls_version(version: Optional[str]) -> Dict[str, Any]:
    """Report the negotiated protocol version and whether it's outdated (TLS 1.0/1.1 or older)."""
    return {
        "version": version,
        "is_outdated": (version in _OUTDATED_TLS_VERSIONS) if version else None,
    }


# ---------------------------------------------------------------------------
# 3. Cipher-suite analysis
# ---------------------------------------------------------------------------

def analyze_cipher_suite(cipher: Optional[Tuple[str, str, int]]) -> Dict[str, Any]:
    """Report the negotiated cipher suite as returned by ssl.SSLSocket.cipher()."""
    if not cipher:
        return {"name": None, "protocol": None, "secret_bits": None}
    name, protocol, secret_bits = cipher
    return {"name": name, "protocol": protocol, "secret_bits": secret_bits}


# ---------------------------------------------------------------------------
# 4. Hostname validation
# ---------------------------------------------------------------------------

def _hostname_matches(cert_name: str, hostname: str) -> bool:
    """
    RFC 6125-style comparison: exact match, or a single leftmost wildcard
    label (`*.example.com` matches `foo.example.com` but not
    `example.com` or `a.b.example.com`). Implemented locally because
    ssl.match_hostname() was removed in Python 3.12+.
    """
    cert_name = (cert_name or "").strip().rstrip(".").lower()
    hostname = (hostname or "").strip().rstrip(".").lower()
    if not cert_name or not hostname:
        return False
    if cert_name == hostname:
        return True
    if cert_name.startswith("*."):
        wildcard_parent = cert_name[2:]
        if not wildcard_parent:
            return False
        host_parts = hostname.split(".")
        if len(host_parts) < 2:
            return False
        host_leftmost, host_rest = host_parts[0], ".".join(host_parts[1:])
        return bool(host_leftmost) and host_rest == wildcard_parent
    return False


def validate_hostname_against_cert(cert: "x509.Certificate", hostname: str) -> Dict[str, Any]:
    """Check whether `hostname` matches any SAN DNSName (or, failing that, the CN) on `cert`."""
    candidate_names: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        candidate_names.extend(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    try:
        candidate_names.extend(
            a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        )
    except Exception:
        pass

    matched_names = [n for n in candidate_names if _hostname_matches(n, hostname)]
    return {
        "hostname": hostname,
        "matched": bool(matched_names),
        "matched_names": matched_names,
        "candidate_names": candidate_names,
    }


# ---------------------------------------------------------------------------
# 5. SAN extraction
# ---------------------------------------------------------------------------

def extract_sans(cert: "x509.Certificate") -> Dict[str, Any]:
    """Extract and normalize (lowercase, no trailing dot) DNSName SAN entries."""
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        raw_sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        raw_sans = []
    normalized = sorted({s.strip().rstrip(".").lower() for s in raw_sans if s and s.strip()})
    return {"sans": normalized, "count": len(normalized)}


# ---------------------------------------------------------------------------
# 6. Certificate-chain analysis
# ---------------------------------------------------------------------------

def analyze_certificate_chain(chain_der: List[bytes]) -> Dict[str, Any]:
    """
    Structurally analyze the chain as presented by the server (via
    get_unverified_chain()): per-certificate summary, subject/issuer
    linkage between consecutive certs, and whether the chain terminates
    in a self-signed certificate. This is not full trust-path validation
    against a root store — see module docstring decision #2.
    """
    result: Dict[str, Any] = {
        "length": len(chain_der), "certificates": [],
        "properly_linked": None, "terminates_in_self_signed": None,
        "notes": [], "error": None,
    }
    certs = []
    for der in chain_der:
        try:
            certs.append(x509.load_der_x509_certificate(der, default_backend()))
        except Exception as exc:
            result["error"] = f"failed to parse a chain certificate: {exc}"

    for cert in certs:
        result["certificates"].append({
            "subject": _name_to_dict(cert.subject),
            "issuer": _name_to_dict(cert.issuer),
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
        })

    if len(certs) >= 2:
        result["properly_linked"] = all(
            certs[i].issuer == certs[i + 1].subject for i in range(len(certs) - 1)
        )
    if certs:
        last = certs[-1]
        result["terminates_in_self_signed"] = last.issuer == last.subject
    if len(certs) < 2:
        result["notes"].append(
            "chain has fewer than 2 certificates; an intermediate may be missing, "
            "or the server sent only the leaf certificate"
        )

    return result


# ---------------------------------------------------------------------------
# 7. Self-signed detection
# ---------------------------------------------------------------------------

def detect_self_signed(cert: "x509.Certificate") -> Dict[str, Any]:
    """
    Detect a self-signed certificate: issuer==subject name equality (the
    standard heuristic) as the primary signal, plus a genuine
    cryptographic self-signature verification (a passive check of a
    public signature, not exploitation of anything) when the key type
    supports it, as a confidence booster.
    """
    result: Dict[str, Any] = {"self_signed": False, "confidence": CONFIDENCE_LOW, "evidence": []}

    if cert.issuer != cert.subject:
        result["evidence"].append("issuer and subject names differ")
        return result
    result["evidence"].append("issuer and subject names are identical")

    try:
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature, cert.tbs_certificate_bytes,
                padding.PKCS1v15(), cert.signature_hash_algorithm,
            )
            result["self_signed"] = True
            result["confidence"] = CONFIDENCE_HIGH
            result["evidence"].append("signature cryptographically self-verified (RSA)")
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            result["self_signed"] = True
            result["confidence"] = CONFIDENCE_HIGH
            result["evidence"].append("signature cryptographically self-verified (EC)")
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
            result["self_signed"] = True
            result["confidence"] = CONFIDENCE_HIGH
            result["evidence"].append("signature cryptographically self-verified (EdDSA)")
        else:
            result["self_signed"] = True
            result["confidence"] = CONFIDENCE_MEDIUM
            result["evidence"].append(
                "issuer/subject match but signature verification not attempted for this key type"
            )
    except Exception:
        result["self_signed"] = True
        result["confidence"] = CONFIDENCE_MEDIUM
        result["evidence"].append(
            "issuer/subject match but cryptographic self-verification failed or was inconclusive"
        )
    return result


# ---------------------------------------------------------------------------
# Module orchestration (single host:port)
# ---------------------------------------------------------------------------

def run_ssl_analysis(
    host: str,
    port: int = DEFAULT_PORT,
    sni_hostname: Optional[str] = None,
    target: Optional[str] = None,
    output_dir: str = "output",
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Run all seven Module 4 checks against a single host:port and persist
    the result immediately to <output_dir>/pending_assets.json.

    `sni_hostname` defaults to `host` when `host` is a domain name, or to
    None (no SNI, no hostname validation performed) when `host` is an IP
    literal and no override is supplied.

    Returns a structured summary in addition to (not instead of) the
    crash-safe persisted store. `status` distinguishes "found" (handshake
    succeeded — inspect the sub-fields for any certificate/TLS problems,
    which do NOT change this status) from "unavailable" (TLS service
    unreachable), "handshake_failed" (TLS negotiation itself failed), and
    "error" (unexpected condition, e.g. unparseable certificate).
    """
    host = validate_ssl_host(host, target=target)
    store = PendingAssetsStore(output_dir=output_dir)

    effective_sni = sni_hostname if sni_hostname else (None if _is_ip_literal(host) else host)

    summary: Dict[str, Any] = {
        "host": host, "port": port, "sni_hostname": effective_sni,
        "target": target or host, "module": MODULE_NAME,
        "started_at": _now(),
        "status": None,
        "certificate": {}, "tls_version": {}, "cipher": {}, "validity": {},
        "hostname_validation": {}, "sans": {}, "chain": {}, "self_signed": {},
        "discovered_hostnames": [], "has_certificate_or_tls_problems": None,
        "error": None,
    }

    negotiation = _negotiate_tls(host, port, effective_sni, timeout)
    summary["status"] = negotiation["status"]

    if negotiation["status"] != "found":
        summary["error"] = negotiation["error"]
        summary["finished_at"] = _now()
        return summary

    try:
        cert = x509.load_der_x509_certificate(negotiation["leaf_der"], default_backend())
    except Exception as exc:
        summary["status"] = "error"
        summary["error"] = f"failed to parse leaf certificate: {exc}"
        summary["finished_at"] = _now()
        return summary

    summary["certificate"] = {
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "serial_number": str(cert.serial_number),
    }
    summary["tls_version"] = analyze_tls_version(negotiation["version"])
    summary["cipher"] = analyze_cipher_suite(negotiation["cipher"])
    summary["validity"] = analyze_certificate_validity(cert)
    summary["self_signed"] = detect_self_signed(cert)
    summary["sans"] = extract_sans(cert)
    summary["chain"] = analyze_certificate_chain(negotiation["chain_der"])

    if effective_sni:
        summary["hostname_validation"] = validate_hostname_against_cert(cert, effective_sni)
    else:
        summary["hostname_validation"] = {
            "hostname": None, "matched": None, "matched_names": [],
            "candidate_names": summary["sans"]["sans"],
            "note": "no hostname available to validate against "
                    "(IP-literal host, no sni_hostname override supplied)",
        }

    summary["has_certificate_or_tls_problems"] = bool(
        summary["validity"]["is_expired"]
        or summary["validity"]["is_not_yet_valid"]
        or summary["tls_version"]["is_outdated"]
        or summary["self_signed"]["self_signed"]
        or summary["hostname_validation"].get("matched") is False
    )

    scope_target = target or (host if not _is_ip_literal(host) else None)
    discovered = [
        {"hostname": san, "in_scope": _in_scope_host(san, scope_target) if scope_target else None}
        for san in summary["sans"]["sans"]
    ]
    summary["discovered_hostnames"] = discovered

    store.add(make_finding(
        finding_type="tls_certificate_analysis",
        target=target or host,
        value={
            "host": host, "port": port, "sni_hostname": effective_sni,
            "certificate": summary["certificate"],
            "validity": summary["validity"],
            "tls_version": summary["tls_version"],
            "cipher": summary["cipher"],
            "hostname_validation": summary["hostname_validation"],
            "self_signed": summary["self_signed"],
            "chain": summary["chain"],
            "sans": summary["sans"],
        },
        evidence=[
            f"TLS handshake to {host}:{port} negotiated {summary['tls_version']['version']}",
            f"Certificate subject={summary['certificate']['subject']}, "
            f"issuer={summary['certificate']['issuer']}",
        ],
        confidence=CONFIDENCE_HIGH,
        metadata={
            "host": host, "port": port,
            "is_expired": summary["validity"]["is_expired"],
            "is_outdated_tls": summary["tls_version"]["is_outdated"],
            "self_signed": summary["self_signed"]["self_signed"],
            "has_certificate_or_tls_problems": summary["has_certificate_or_tls_problems"],
        },
    ))

    # SAN surface expansion (context.md: "feeds new hostnames back to
    # surface_mapper") — recorded as discoveries only; never auto-probed.
    for entry in discovered:
        store.add(make_finding(
            finding_type="tls_san",
            target=target or host,
            value=entry["hostname"],
            evidence=[f"Certificate SAN entry from {host}:{port} leaf certificate (ssl_analyzer.py deep analysis)"],
            confidence=CONFIDENCE_HIGH if entry["in_scope"] else CONFIDENCE_MEDIUM,
            metadata={"host": host, "port": port, "in_scope": entry["in_scope"]},
        ))

    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="ssl_analyzer.py",
        description="ReconHound Module 4 — TLS/certificate intelligence (standalone test entry point).",
    )
    parser.add_argument("--host", required=True, help="Target hostname or IPv4 address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TLS port (default 443)")
    parser.add_argument("--sni-hostname", default=None, help="Override SNI/hostname-validation value")
    parser.add_argument("--target", default=None, help="Logical target domain to enforce scope against")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Connection/handshake timeout (seconds)")
    args = parser.parse_args()

    try:
        result = run_ssl_analysis(
            args.host, port=args.port, sni_hostname=args.sni_hostname, target=args.target,
            output_dir=args.output_dir, timeout=args.timeout,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
