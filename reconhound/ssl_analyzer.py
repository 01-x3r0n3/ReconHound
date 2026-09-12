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
     might support. `analyze_tls_version` states that limitation in its
     own output (`observation: "negotiated_only"`) so nothing downstream
     can read a TLS 1.3 negotiation as proof that TLS 1.0 is refused.
  4. No arbitrary "expiring soon" day-count threshold is invented (per
     explicit instruction). `days_until_expiry` (an integer, possibly
     negative) and `is_expired` (a direct fact: now vs. not_valid_after)
     are reported as data; any urgency judgment is left to the caller /
     risk_engine.py, not decided here.
  5. Self-signed detection uses issuer==subject name equality (the
     standard heuristic) as the primary signal, and additionally attempts
     genuine cryptographic self-signature verification (RSA/EC/Ed25519/
     Ed448 — all already supported by the `cryptography` dependency). A
     signature that verifies raises confidence to HIGH; a signature that
     is *definitively invalid* (InvalidSignature) means the certificate is
     self-ISSUED but not self-SIGNED, which is reported as such rather
     than as a self-signed certificate — risk_engine.py turns
     `tls_self_signed is True` into a MEDIUM signal, so conflating the two
     manufactured a false finding on every cross-signed CA certificate.
     This is a passive, non-destructive verification of a public
     signature — not exploitation of anything.
  6. This module accepts either a domain name or an IP literal (v4 or v6)
     as `host` (validate_ssl_host), covering both Module 1's domain-based
     and Module 2's IP-based discovery styles. For an IP-literal host no
     SNI is sent (RFC 6066 forbids an IP literal in server_name) and DNS
     hostname validation is skipped — reported as such, not silently
     omitted — but the IP is still validated against the certificate's IP
     SANs when it has any.

Scope discipline: identities discovered here are recorded as discoveries
only (finding_type "tls_san", reusing passive_recon.py's established type
name so future surface_mapper.py correlation can group them regardless of
which module produced them) — this module never automatically connects to
or analyzes a newly discovered SAN identity. Out-of-scope SAN hostnames are
retained as passive intelligence, tagged `in_scope: False`, exactly as
Module 1 does; surface_mapper.py marks them out of scope and the
orchestrator's in_scope_hostnames() therefore never schedules an active
module against them.

Only a *concrete, syntactically valid* DNS hostname is emitted as a
`tls_san` discovery. Wildcard names (`*.example.com`), IP SANs, and DNS
entries that are not usable hostnames are kept — under `wildcard_sans`,
`ip_sans` and `other_names` inside the analysis finding — but are never
minted as hostname discoveries. They previously were: surface_mapper.py
created a hostname asset literally named `*.example.com`, marked it in
scope (it *is* a suffix match), and the orchestrator's ssl_targets() then
scheduled an active TLS scan of `*.example.com`, which this module's own
validate_ssl_host() rejects. That is a phantom asset plus a guaranteed
scope-rejected execution, on every wildcard certificate in existence.

Every discovery is persisted to <output_dir>/pending_assets.json via
PendingAssetsStore in ONE batched, crash-safe write (write-to-temp +
os.replace + directory fsync). This module does not implement or call into
surface_mapper.py, endpoint_discovery.py, or any other later module.

KNOWN LIMITATIONS (stated rather than hidden — context.md §14/§8):

  * Negotiated, not supported. One handshake proves what the server chose
    with this client's default preferences. It proves nothing about the
    full set of protocol versions, cipher suites, curves or signature
    algorithms the server would accept. Enumerating that needs repeated
    handshakes (see decision #3) and is deliberately not done.
  * Chain trust is NOT validated against a root store. The chain analysis
    is structural: linkage, ordering, duplication, self-signed
    termination. "The server did not send a complete chain" and "the
    chain is untrusted" are different statements, and only the first is
    something this module observes.
  * Revocation (OCSP, CRL, stapling) and Certificate Transparency/SCT are
    not checked. Revocation checking means contacting a third-party CA
    responder, and CT means querying an external log aggregator — neither
    is a property of the observed handshake, and neither appears in
    context.md's line for this module. osint_engine.py already owns the
    crt.sh/CT-log integration. Absence of an SCT/OCSP observation here is
    therefore "not tested", never "not present".
  * Mutual TLS is not inferred. Under TLS 1.3 a server that requires a
    client certificate still completes the handshake from the client's
    point of view (verified in the test suite); the rejection surfaces
    later, at the application layer. Reporting "mTLS" from a handshake
    that succeeded, or from an HTTP 400/403, would be a guess.
  * ALPN is not offered, so no ALPN selection is reported. HTTP protocol
    posture (HTTP/1.1 vs h2) is http_analyzer.py's responsibility.
  * Session resumption, ECH, DH parameters and per-connection certificate
    rotation are not observable from a single handshake through the
    stdlib `ssl` API and are not claimed.
  * Edge vs. origin: a TLS endpoint behind a CDN/WAF/load balancer
    presents the *edge's* certificate. This module records the observed
    endpoint (hostname, resolved peer IP, port, SNI) so surface_mapper.py
    can correlate it with http_analyzer.py's CDN/intermediary evidence.
    It never claims the observation describes an origin server.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa, ec, ed25519, ed448, padding, rsa,
)
from cryptography.x509.oid import NameOID

MODULE_NAME = "ssl_analyzer.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

DEFAULT_TIMEOUT = 8.0
DEFAULT_PORT = 443

# ---------------------------------------------------------------------------
# Bounds. Everything below is derived from a certificate, i.e. from data the
# *server* chose. A hostile or merely unusual certificate can carry a 100 KB
# common name, tens of thousands of SAN entries, or a pathological chain, and
# all of it used to be written verbatim into pending_assets.json — the shared
# file every other module reads and the report appendix renders.
# ---------------------------------------------------------------------------
MAX_NAME_VALUE_CHARS = 512      # one RDN attribute value (CN, O, OU, ...)
MAX_NAME_ATTRIBUTES = 32        # distinct RDN attributes kept per Name
MAX_NAME_VALUES_PER_OID = 8     # repeated RDNs of the same OID (e.g. two OUs)
MAX_SAN_HOSTNAMES = 1000        # concrete DNS hostnames emitted as discoveries
MAX_SAN_OTHER_ENTRIES = 200     # per non-hostname SAN bucket
MAX_CANDIDATE_NAMES = 200       # identity candidates recorded per validation
MAX_CHAIN_CERTIFICATES = 20     # chain certificates summarized
MAX_EVIDENCE_ITEMS = 24
MAX_EVIDENCE_CHARS = 512
MAX_NOTES = 40
MAX_NOTE_CHARS = 400
MAX_ERROR_CHARS = 512

# context.md explicitly names TLS 1.0/1.1 as outdated; SSLv2/SSLv3 predate
# TLS entirely and are an uncontroversial superset of the same concept.
_OUTDATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# C0/C1 control characters plus the Unicode bidirectional formatting controls.
# Certificate subject/issuer text and SAN entries are attacker-controlled and
# end up in pending_assets.json, in terminal output and in the HTML report; a
# raw ANSI escape there can rewrite the operator's terminal and a bidi
# override can make `evil.com` render as something else entirely.
_UNSAFE_TEXT_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]"
)


class ScopeError(ValueError):
    """Raised when a target/input falls outside this module's authorized scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clip(value: Any, limit: int) -> Any:
    """Length-clip a string for persistence, marking that it was clipped."""
    if not isinstance(value, str) or len(value) <= limit:
        return value
    return value[:limit] + f"...[clipped {len(value) - limit} chars]"


def _escape_unsafe(match: "re.Match[str]") -> str:
    ch = match.group(0)
    code = ord(ch)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def _safe_text(value: Any, limit: int = MAX_NAME_VALUE_CHARS) -> Any:
    """
    Make server-supplied text safe to persist, display and report.

    Control characters and Unicode bidi-formatting overrides are replaced
    with their literal `\\xNN`/`\\uNNNN` spelling, then the value is clipped.

    Escaping rather than deleting matters here. A certificate common name
    of "ex<U+202B>ample.com\\r\\nInjected: yes" is hostile input that reaches
    pending_assets.json, the operator's terminal and the HTML report. Deleting
    the control characters silently rewrites it into the plausible-looking
    "example.comInjected: yes"; escaping keeps the operator able to see
    exactly what the server sent while making it inert — a `\\x1b` in the
    output is four ordinary characters, not an ANSI escape.
    """
    if not isinstance(value, str):
        return value
    cleaned = _UNSAFE_TEXT_RE.sub(_escape_unsafe, value)
    return _clip(cleaned, limit)


def _bound_notes(notes: List[str], limit: int = MAX_NOTES) -> List[str]:
    """Cap a notes list, and every note in it, before it is persisted."""
    bounded = [_safe_text(n, MAX_NOTE_CHARS) for n in notes[:limit]]
    if len(notes) > limit:
        bounded.append(f"...[{len(notes) - limit} further note(s) omitted]")
    return bounded


def _jsonify(value: Any, _depth: int = 0) -> Any:
    """
    Coerce a value into something json.dump can definitely write.

    Findings carry data this module did not create. `cryptography` types an
    RDN attribute value as `str | bytes`, and a certificate carrying, say, an
    x500UniqueIdentifier yields real `bytes` — which json.dump cannot
    serialise. That TypeError escaped PendingAssetsStore, escaped
    run_ssl_analysis, and destroyed an otherwise complete analysis.

    Mirrors passive_recon.py's/http_analyzer.py's `_jsonify`, which share
    this output file.
    """
    if _depth > 12:
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): _jsonify(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(v, _depth + 1) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _idna_normalize(host: str) -> str:
    """
    Reduce a hostname to the single form scope comparisons are made in.

    Without this, a target written as "münchen.de" and a certificate SAN
    arriving as "xn--mnchen-3ya.de" (or the reverse) compare unequal even
    though they name the same host — an IDN mismatch that silently drops
    in-scope assets in one direction and, worse, would let a homograph host
    look "different" from the target it is impersonating. Both sides are
    folded to lowercase A-label form; anything that will not encode is
    returned lowercased unchanged so the caller still gets a deterministic
    comparison.

    Mirrors http_analyzer.py/endpoint_discovery.py/exposure_scan.py, which
    share this file's scope vocabulary.
    """
    if not isinstance(host, str):
        return ""
    host = host.strip().rstrip(".").lower()
    if not host or host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return host


def _in_scope_host(hostname: str, target: str) -> bool:
    """Mirrors passive_recon.py's is_in_scope; duplicated per modular independence."""
    hostname = _idna_normalize(hostname)
    target = _idna_normalize(target)
    if not hostname or not target:
        return False
    return hostname == target or hostname.endswith("." + target)


def _is_hostname_shaped(name: str) -> bool:
    """
    True if `name` is a concrete DNS hostname this module could legitimately
    treat as an asset — i.e. exactly what validate_ssl_host() would accept.

    Deliberately identical to validate_ssl_host()'s own domain test so that a
    name emitted as a discovery here can never be rejected as un-scannable
    there. A wildcard, an empty label, a space, an over-long label or a
    single-label name is not hostname-shaped.
    """
    if not isinstance(name, str) or not name.strip():
        return False
    candidate = _idna_normalize(name)
    if not candidate or "*" in candidate or "/" in candidate or "://" in candidate:
        return False
    if _is_ip_literal(candidate):
        return False
    return bool(_DOMAIN_RE.match(candidate))


def validate_ssl_host(host: str, target: Optional[str] = None) -> str:
    """
    Validate that `host` is a syntactically valid bare hostname or IP
    address (v4 or v6, never a URL/path/wildcard). If `target` is supplied
    and `host` is a domain name (not an IP literal), enforce that it is the
    target itself or a subdomain of it.
    """
    if not isinstance(host, str) or not host.strip():
        raise ScopeError("Host must be a non-empty string.")

    candidate = host.strip().rstrip(".").lower()

    for ch in "\r\n\t\x00 ":
        if ch in candidate:
            raise ScopeError(f"Host contains whitespace or a control character: {host!r}")
    if "://" in candidate or "/" in candidate:
        raise ScopeError(f"Host must be a bare hostname or IP, not a URL/path: {host!r}")
    if "*" in candidate:
        raise ScopeError(f"Wildcard hosts are not permitted: {host!r}")

    try:
        # Canonical form: "2001:0DB8::0001" and "2001:db8::1" are one address,
        # and identity comparisons (and surface_mapper.py's own `_norm_ip`)
        # only agree if both sides are canonicalized the same way.
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    candidate = _idna_normalize(candidate)
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
        "value": _jsonify(value),
        "evidence": [_clip(_jsonify(e), MAX_EVIDENCE_CHARS)
                     for e in list(evidence)[:MAX_EVIDENCE_ITEMS]],
        "confidence": confidence,
        "source": MODULE_NAME,
        "timestamp": _now(),
        "metadata": _jsonify(metadata or {}),
    }


def _name_to_dict(name: "x509.Name") -> Dict[str, Any]:
    """
    Render an X.509 Name as a JSON-safe dict.

    Mirrors passive_recon.py's _name_to_dict (duplicated per modular
    independence), with three corrections this module needs because its
    output is persisted and rendered:

      * A repeated OID (`OU=Engineering, OU=EU` is ordinary in enterprise
        and government PKI) no longer silently overwrites the earlier
        value — repeated attributes collapse to a list.
      * `attr.value` is typed `str | bytes` by `cryptography`; a bytes
        value is hex-encoded rather than left to break json.dump.
      * Values are control-character-stripped and length-clipped.
    """
    collected: Dict[str, List[Any]] = {}
    for attr in name:
        # `oid._name` is the literal string "Unknown OID" for anything outside
        # cryptography's registry, so every unregistered attribute in a subject
        # collapsed onto one key and all but one value was lost.
        key = attr.oid._name
        if not key or key == "Unknown OID":
            key = attr.oid.dotted_string
        if key not in collected and len(collected) >= MAX_NAME_ATTRIBUTES:
            continue
        value = attr.value
        if isinstance(value, bytes):
            value = value.hex()
        bucket = collected.setdefault(str(key), [])
        if len(bucket) < MAX_NAME_VALUES_PER_OID:
            bucket.append(_safe_text(value))
    return {k: (v[0] if len(v) == 1 else v) for k, v in collected.items()}


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _spki_sha256(cert: "x509.Certificate") -> Optional[str]:
    """
    SHA-256 over the DER SubjectPublicKeyInfo.

    The stable identity of the *key* rather than of the certificate: it
    survives renewal and rotation, so surface_mapper.py can correlate "the
    same key served on two endpoints" across observations that have
    different certificate fingerprints. Purely local computation.
    """
    try:
        return _sha256_hex(cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    except Exception:
        return None


def _public_key_summary(cert: "x509.Certificate") -> Dict[str, Any]:
    """Key algorithm/size as observed. No judgement — risk_engine.py owns that."""
    summary: Dict[str, Any] = {"algorithm": None, "size_bits": None, "curve": None}
    try:
        key = cert.public_key()
    except Exception as exc:
        summary["error"] = _safe_text(str(exc), MAX_ERROR_CHARS)
        return summary
    if isinstance(key, rsa.RSAPublicKey):
        summary["algorithm"], summary["size_bits"] = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        summary["algorithm"] = "EC"
        summary["size_bits"] = key.key_size
        summary["curve"] = getattr(key.curve, "name", None)
    elif isinstance(key, dsa.DSAPublicKey):
        summary["algorithm"], summary["size_bits"] = "DSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        summary["algorithm"], summary["size_bits"] = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        summary["algorithm"], summary["size_bits"] = "Ed448", 448
    else:
        summary["algorithm"] = type(key).__name__
    return summary


def _signature_algorithm_name(cert: "x509.Certificate") -> Optional[str]:
    try:
        oid = cert.signature_algorithm_oid
        return oid._name or oid.dotted_string
    except Exception:
        return None


def _certificate_summary(cert: "x509.Certificate", der: Optional[bytes] = None) -> Dict[str, Any]:
    """
    The identity/provenance block every certificate observation carries.

    `fingerprint_sha256` is the correlation key: it is what makes "the same
    certificate was observed on these two endpoints" answerable downstream
    without re-deriving it from subject/issuer/serial heuristics.
    """
    summary: Dict[str, Any] = {
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "serial_number": None,
        "version": None,
        "fingerprint_sha256": None,
        "spki_sha256": _spki_sha256(cert),
        "signature_algorithm": _signature_algorithm_name(cert),
        "public_key": _public_key_summary(cert),
    }
    try:
        summary["serial_number"] = str(cert.serial_number)
    except Exception:
        pass
    try:
        summary["version"] = cert.version.name
    except Exception:
        pass
    try:
        summary["fingerprint_sha256"] = _sha256_hex(
            der if der is not None else cert.public_bytes(serialization.Encoding.DER))
    except Exception:
        pass
    return summary


# ---------------------------------------------------------------------------
# Crash-safe persistence (same file/format as Modules 1-3's
# PendingAssetsStore, duplicated here per modular independence rather than
# imported, so this module works standalone)
# ---------------------------------------------------------------------------

class PendingAssetsStore:
    """
    Crash-safe, append-oriented persistence for <output_dir>/pending_assets.json.

    A write re-reads the current file (or reuses a cached serialization of
    what this store last left there), appends the new findings, and
    atomically rewrites the file (write-to-temp + os.replace + directory
    fsync) so a crash mid-write can never corrupt previously persisted
    discoveries, and pre-existing discoveries from other modules/runs are
    always preserved.
    """

    def __init__(self, output_dir: str = "output", filename: str = "pending_assets.json"):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, filename)
        self._lock = threading.Lock()
        # Serialized body of everything this store has written, kept so an
        # append does not have to re-encode the whole file. `_stamp` is the
        # (mtime_ns, size) of the file as this store last left it; anything
        # else means somebody else wrote it and the cache is void.
        self._serialized: Optional[str] = None
        self._stamp: Optional[Tuple[int, int]] = None
        os.makedirs(self.output_dir, exist_ok=True)

    def _current_stamp(self) -> Optional[Tuple[int, int]]:
        try:
            info = os.stat(self.path)
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size)

    def _cache_is_current(self) -> bool:
        return self._serialized is not None and self._stamp == self._current_stamp()

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
        self.add_many([finding])
        return finding

    def add_many(self, findings: List[Dict[str, Any]]) -> int:
        """
        Append a batch of findings in ONE read + ONE atomic write.

        add() rewrites the whole shared file per finding, which is quadratic
        in the number of records already on disk. This module emits one
        finding per SAN entry, and a shared/multi-tenant certificate
        routinely carries hundreds: measured on this repository, a
        2000-SAN certificate cost 27.3 s and 2001 whole-file rewrites with
        per-finding add(), against one write batched.

        Crash-safety is unchanged and slightly stronger: still one
        write-to-temp + os.replace, so the batch is all-or-nothing rather
        than half-applied. Returns the number of findings written.
        """
        if not findings:
            return 0
        with self._lock:
            if not self._cache_is_current():
                self._serialized = self._encode_body(self._read_all())
            addition = self._encode_body(findings)
            body = f"{self._serialized},\n{addition}" if self._serialized else addition
            self._atomic_write_body(body)
            self._serialized = body
        return len(findings)

    @staticmethod
    def _encode_body(records: List[Dict[str, Any]]) -> str:
        """Serialize records as the *inside* of the JSON array (no brackets)."""
        if not records:
            return ""
        return ",\n".join("  " + json.dumps(r, indent=2).replace("\n", "\n  ") for r in records)

    def _atomic_write_body(self, body: str) -> None:
        dir_name = os.path.dirname(self.path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".pending_assets_", dir=dir_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("[\n" + body + "\n]" if body else "[]")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
            self._fsync_dir(dir_name)
            self._stamp = self._current_stamp()
        except BaseException:
            self._serialized = None
            self._stamp = None
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def _atomic_write(self, records: List[Dict[str, Any]]) -> None:
        """Replace the file with exactly `records` (kept for direct callers)."""
        body = self._encode_body(records)
        self._atomic_write_body(body)
        self._serialized = body

    @staticmethod
    def _fsync_dir(dir_name: str) -> None:
        """
        Durably commit the os.replace() rename itself.

        Without this the replacement file's *contents* are on disk but the
        directory entry pointing at them may not be, so a power loss can
        still resurrect the pre-replace file and lose every discovery
        appended since. Best-effort: some platforms/filesystems refuse to
        fsync a directory.
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


# A persistence attempt can fail in more ways than PersistenceError: the disk
# fills or the path loses permissions (OSError), or a value slips through that
# json.dump cannot serialise (TypeError/ValueError). Catching only
# PersistenceError meant those escaped and took the *completed analysis* down
# with them — the one outcome context.md §12.11 forbids.
_PERSISTENCE_FAILURES = (PersistenceError, OSError, TypeError, ValueError)


def _safe_store_add_many(
    store: Optional["PendingAssetsStore"], findings: List[Dict[str, Any]],
) -> Optional[str]:
    """
    store.add_many() wrapped so a persistence failure never discards the
    in-memory results. Returns None on success, or an error message the
    caller is responsible for recording (never silently discarded).
    """
    if store is None or not findings:
        return None
    try:
        store.add_many(findings)
        return None
    except _PERSISTENCE_FAILURES as exc:
        return str(exc)


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
                             SNI required and not supplied, etc.).
      "error"             - an unexpected condition (e.g. no certificate
                             presented despite a completed handshake).

    `peer_ip`/`peer_port` record which endpoint actually answered. Without
    them a hostname that resolves to several addresses, or several
    hostnames sharing one address, produce observations that cannot be told
    apart downstream — the provenance surface_mapper.py needs in order to
    correlate a TLS observation with the right IP asset, and the only way
    to notice that two SNI values on one IP returned different
    certificates.
    """
    result: Dict[str, Any] = {
        "status": "error", "version": None, "cipher": None,
        "leaf_der": None, "chain_der": [], "error": None,
        "peer_ip": None, "peer_port": None,
        "sni_sent": bool(sni_hostname),
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
        try:
            peer = sock.getpeername()
            if isinstance(peer, tuple) and len(peer) >= 2:
                result["peer_ip"], result["peer_port"] = str(peer[0]), peer[1]
        except OSError:
            pass

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
    except (TypeError, ValueError, UnicodeError) as exc:
        # ssl.wrap_socket() rejects some server_hostname values with plain
        # TypeError/ValueError/UnicodeEncodeError (NUL bytes, an empty
        # string, a label over 63 bytes). Those are not OSError and used to
        # escape this function entirely, turning a bad SNI value into an
        # unhandled module crash instead of a recorded failure.
        result["status"] = "error"
        result["error"] = f"TLS handshake could not be attempted: {exc}"

    if result["status"] == "handshake_failed" and not result["sni_sent"]:
        result["error"] = (
            f"{result['error']} (no SNI was sent for this connection, so a server that "
            f"requires SNI would refuse the handshake regardless of its TLS configuration)"
        )
    return result


# ---------------------------------------------------------------------------
# 1. Certificate validity / expiration
# ---------------------------------------------------------------------------

def analyze_certificate_validity(cert: "x509.Certificate") -> Dict[str, Any]:
    """
    Report the certificate's validity window as direct, objective facts.
    No "expiring soon" threshold is invented — `days_until_expiry` (which
    may be negative) is reported as data for the caller to judge urgency.

    Both bounds come from the certificate's own timezone-aware UTC
    accessors and are compared against a timezone-aware UTC "now", so the
    local clock's timezone cannot shift the result. The local clock being
    *wrong* is a different matter and is not detectable from here; the
    observation timestamp is recorded alongside so a later reader can tell
    when the comparison was made.
    """
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    is_expired = now > not_after
    is_not_yet_valid = now < not_before
    lifetime_days = (not_after - not_before).days
    return {
        "not_valid_before": not_before.isoformat(),
        "not_valid_after": not_after.isoformat(),
        "is_currently_valid_period": not is_expired and not is_not_yet_valid,
        "is_expired": is_expired,
        "is_not_yet_valid": is_not_yet_valid,
        "days_until_expiry": (not_after - now).days,
        "lifetime_days": lifetime_days,
        "window_is_inverted": not_after < not_before,
        "evaluated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 2. TLS version detection
# ---------------------------------------------------------------------------

def analyze_tls_version(version: Optional[str]) -> Dict[str, Any]:
    """
    Report the negotiated protocol version and whether it's outdated
    (TLS 1.0/1.1 or older).

    `observation` states the scope of the claim explicitly: this is the one
    version negotiated with this client's default preferences, not the set
    of versions the server supports. A TLS 1.3 result is not evidence that
    TLS 1.0 is refused (see module docstring decision #3).
    """
    return {
        "version": version,
        "is_outdated": (version in _OUTDATED_TLS_VERSIONS) if version else None,
        "observation": "negotiated_only",
        "supported_versions": None,
        "note": ("the single protocol version negotiated by one default handshake; "
                 "the server's full set of accepted versions was not enumerated"),
    }


# ---------------------------------------------------------------------------
# 3. Cipher-suite analysis
# ---------------------------------------------------------------------------

# Leading key-exchange tokens in OpenSSL's TLS 1.2-and-earlier cipher names.
# `ECDH`/`DH` without the trailing E are STATIC key exchange: no forward
# secrecy. `ADH`/`AECDH` are anonymous — ephemeral, but unauthenticated.
_KEY_EXCHANGE_TOKENS = {
    "ECDHE": ("ECDHE", True, False),
    "EECDH": ("ECDHE", True, False),
    "DHE": ("DHE", True, False),
    "EDH": ("DHE", True, False),
    "AECDH": ("ECDH-anon", True, True),
    "ADH": ("DH-anon", True, True),
    "ECDH": ("ECDH (static)", False, False),
    "DH": ("DH (static)", False, False),
    "SRP": ("SRP", False, False),
    "PSK": ("PSK", False, False),
    "RSA": ("RSA", False, False),
    "GOST": ("GOST", False, False),
}

_AUTH_TOKENS = {"RSA": "RSA", "ECDSA": "ECDSA", "DSS": "DSA", "PSK": "PSK", "NULL": "none"}

# Cipher-name tokens that name a long-obsolete or deliberately-null
# primitive. Presence is an observation, not a severity: risk_engine.py owns
# the judgement (context.md §10 item 20).
_WEAK_CIPHER_TOKENS = {
    "NULL": "no encryption (NULL cipher)",
    "EXP": "export-grade cipher",
    "EXPORT": "export-grade cipher",
    "RC4": "RC4 stream cipher",
    "RC2": "RC2 cipher",
    "IDEA": "IDEA cipher",
    "SEED": "SEED cipher",
    "MD5": "MD5 MAC",
}

# OpenSSL spells Triple DES as "DES-CBC3-..." and single DES as "DES-CBC-...",
# so a bare "DES" token is ambiguous and must be resolved by looking for the
# 3DES marker first.
_TRIPLE_DES_TOKENS = ("CBC3", "3DES", "DES3")
_ANON_INDICATOR = "anonymous key exchange (no server authentication)"

# Leading bulk-cipher tokens. OpenSSL omits the key-exchange prefix entirely
# for plain-RSA suites, so a name beginning with one of these (possibly with a
# key size appended, e.g. "AES256") is an RSA key exchange.
_BULK_CIPHER_PREFIXES = ("AES", "CAMELLIA", "ARIA", "DES", "RC4", "RC2",
                         "SEED", "IDEA", "NULL", "CHACHA20")

_AEAD_TOKENS = ("GCM", "CCM", "POLY1305", "CHACHA20")


def _classify_cipher_name(name: str) -> Dict[str, Any]:
    """
    Derive what an OpenSSL cipher-suite name states about the negotiated
    connection. Pure string analysis of data already collected — no extra
    handshake, no severity decision.
    """
    result: Dict[str, Any] = {
        "key_exchange": None, "authentication": None, "forward_secrecy": None,
        "aead": None, "anonymous": None, "weak_indicators": [], "basis": None,
    }
    if not name:
        return result
    upper = name.upper()
    tokens = [t for t in re.split(r"[-_]", upper) if t]

    if upper.startswith("TLS_"):
        # TLS 1.3 suite names describe only the AEAD + hash; the key exchange
        # is negotiated separately and a full TLS 1.3 handshake is always
        # (EC)DHE. That is an inference from the protocol, not a reading of
        # the cipher name, and is labelled as such.
        result["key_exchange"] = "(EC)DHE"
        result["forward_secrecy"] = True
        result["authentication"] = "certificate"
        result["anonymous"] = False
        result["basis"] = ("inferred from TLS 1.3: a full TLS 1.3 handshake mandates an "
                           "ephemeral (EC)DHE key exchange, so the suite name does not "
                           "carry a key-exchange component")
    else:
        head = tokens[0] if tokens else ""
        kx = _KEY_EXCHANGE_TOKENS.get(head)
        if kx is None and any(head.startswith(p) for p in _BULK_CIPHER_PREFIXES):
            # "AES256-GCM-SHA384" / "DES-CBC3-SHA" carry no key-exchange
            # prefix: OpenSSL omits it for plain RSA key exchange.
            kx = _KEY_EXCHANGE_TOKENS["RSA"]
        if kx:
            result["key_exchange"], result["forward_secrecy"], result["anonymous"] = kx
        auth_token = tokens[1] if len(tokens) > 1 else None
        if result["anonymous"]:
            result["authentication"] = "none"
        elif auth_token in _AUTH_TOKENS:
            result["authentication"] = _AUTH_TOKENS[auth_token]
        elif result["key_exchange"] == "RSA":
            result["authentication"] = "RSA"
        result["basis"] = "derived from the negotiated OpenSSL cipher-suite name"

    result["aead"] = any(t in upper for t in _AEAD_TOKENS)

    def _mark(description: str) -> None:
        if description not in result["weak_indicators"]:
            result["weak_indicators"].append(description)

    for token, description in _WEAK_CIPHER_TOKENS.items():
        if token in tokens or (token in ("EXP", "EXPORT") and upper.startswith("EXP")):
            _mark(description)
    if any(t in tokens for t in _TRIPLE_DES_TOKENS):
        _mark("Triple DES")
    elif "DES" in tokens:
        _mark("single DES")
    if result["anonymous"]:
        _mark(_ANON_INDICATOR)
    return result


def analyze_cipher_suite(cipher: Optional[Sequence[Any]]) -> Dict[str, Any]:
    """
    Report the negotiated cipher suite as returned by
    ssl.SSLSocket.cipher(), plus what its name states about key exchange,
    authentication, forward secrecy and AEAD use.

    The three original keys (`name`, `protocol`, `secret_bits`) keep exactly
    their previous meaning; the classification is additive and carries an
    explicit `basis`. Nothing here is a severity judgement — that belongs to
    risk_engine.py — and nothing describes cipher suites the server merely
    *supports*, only the one it actually chose.
    """
    empty = {"name": None, "protocol": None, "secret_bits": None}
    if not cipher:
        return {**empty, **_classify_cipher_name(""), "malformed": False}
    if isinstance(cipher, (str, bytes)) or len(cipher) < 3:
        # ssl.SSLSocket.cipher() always returns a 3-tuple, but this function
        # is also fed replayed/serialized data; a bare unpack raised
        # ValueError straight out of the analysis.
        return {**empty, **_classify_cipher_name(""), "malformed": True,
                "raw": _safe_text(str(cipher), MAX_NAME_VALUE_CHARS)}
    name, protocol, secret_bits = cipher[0], cipher[1], cipher[2]
    name = name if isinstance(name, str) else (None if name is None else str(name))
    return {
        "name": name,
        "protocol": protocol if isinstance(protocol, str) or protocol is None else str(protocol),
        "secret_bits": secret_bits if isinstance(secret_bits, int) else None,
        **_classify_cipher_name(name or ""),
        "malformed": False,
    }


# ---------------------------------------------------------------------------
# 4. Hostname validation
# ---------------------------------------------------------------------------

def _hostname_matches(cert_name: str, hostname: str) -> bool:
    """
    RFC 6125-style comparison: exact match, or a single leftmost wildcard
    label (`*.example.com` matches `foo.example.com` but not
    `example.com` or `a.b.example.com`). Implemented locally because
    ssl.match_hostname() was removed in Python 3.12+.

    Both sides are IDNA-normalized so an A-label certificate entry and a
    U-label hostname (or the reverse) compare as the same name.

    A wildcard never matches an IP-literal hostname: `*.1.2.3` looks like a
    textual match for `4.1.2.3` under plain label arithmetic, but a DNS
    wildcard cannot authorise an IP identity — only an iPAddress SAN can.
    """
    cert_name = (cert_name or "").strip().rstrip(".").lower()
    hostname_raw = (hostname or "").strip().rstrip(".").lower()
    if not cert_name or not hostname_raw:
        return False

    # Two IP literals are the same identity only by numeric value: comparing
    # the strings makes "2001:0DB8::0001" and "2001:db8::1" different hosts.
    try:
        cert_ip = ipaddress.ip_address(cert_name)
        host_ip = ipaddress.ip_address(hostname_raw)
        return cert_ip == host_ip
    except ValueError:
        pass

    hostname_norm = _idna_normalize(hostname_raw)
    if _idna_normalize(cert_name) == hostname_norm:
        return True
    if not cert_name.startswith("*."):
        return False
    if _is_ip_literal(hostname_raw):
        return False

    wildcard_parent = _idna_normalize(cert_name[2:])
    if not wildcard_parent or "*" in wildcard_parent:
        return False
    host_parts = hostname_norm.split(".")
    if len(host_parts) < 2:
        return False
    host_leftmost, host_rest = host_parts[0], ".".join(host_parts[1:])
    return bool(host_leftmost) and host_rest == wildcard_parent


def _cert_dns_names(cert: "x509.Certificate") -> List[str]:
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (x509.ExtensionNotFound, ValueError):
        return []
    try:
        return list(san_ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        return []


def _cert_ip_names(cert: "x509.Certificate") -> List[str]:
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (x509.ExtensionNotFound, ValueError):
        return []
    try:
        return [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
    except Exception:
        return []


def _has_san_extension(cert: "x509.Certificate") -> bool:
    try:
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return True
    except (x509.ExtensionNotFound, ValueError):
        return False


def validate_hostname_against_cert(cert: "x509.Certificate", hostname: str) -> Dict[str, Any]:
    """
    Check whether `hostname` matches any SAN entry (or, failing that, the CN)
    on `cert`.

    `matched` keeps its original meaning — SAN match OR CN match — because
    downstream consumers already read it. What is new is *how* it matched:

      * `matched_via` is "subject_alternative_name", "common_name" or None.
      * `rfc6125_matched` is the stricter answer a modern client gives.
        RFC 6125 §6.4.4 and the CA/Browser Forum baseline requirements say
        the CN must be ignored whenever a SAN extension is present, so a
        CN-only match on a certificate that HAS a SAN extension is
        reported as matched=True / rfc6125_matched=False, with a note.

    An IP-literal hostname is matched against iPAddress SANs (and an
    IP-shaped commonName), never against DNS names or wildcards. When the
    certificate carries no IP identity at all there is nothing to compare
    against, so the result is `matched: None` — "not tested" — rather than
    a mismatch. Reporting False there would flag every ordinary certificate
    as a problem the moment an IP-addressed endpoint is inspected, when in
    fact no identity was asserted on the connection (no SNI is sent for an
    IP literal).

    A mismatch is a mismatch — a certificate that does not carry the name is
    routine on shared hosting, on default/fallback vhosts and behind CDNs.
    It is never, on its own, evidence of interception.
    """
    notes: List[str] = []
    hostname_is_ip = _is_ip_literal((hostname or "").strip())
    san_present = _has_san_extension(cert)

    dns_names = _cert_dns_names(cert)
    ip_names = _cert_ip_names(cert)
    try:
        cn_names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if isinstance(a.value, str)]
    except Exception:
        cn_names = []

    if hostname_is_ip:
        cn_names = [n for n in cn_names if _is_ip_literal(n.strip().rstrip("."))]
        if not ip_names and not cn_names:
            return {
                "hostname": _safe_text(hostname, MAX_NAME_VALUE_CHARS),
                "hostname_is_ip": True,
                "matched": None,
                "matched_names": [],
                "matched_via": None,
                "rfc6125_matched": None,
                "san_extension_present": san_present,
                "candidate_names": [_safe_text(n, MAX_NAME_VALUE_CHARS)
                                    for n in dns_names[:MAX_CANDIDATE_NAMES]],
                "candidate_names_truncated": len(dns_names) > MAX_CANDIDATE_NAMES,
                "candidate_name_count": len(dns_names),
                "note": "the host is an IP literal and the certificate carries no IP identity "
                        "(no iPAddress SAN, no IP-shaped commonName), so there is nothing to "
                        "validate the connection's identity against — not tested, not a mismatch",
                "notes": _bound_notes([
                    "no SNI is sent for an IP-literal host (RFC 6066), so the server was not "
                    "asked for a specific identity",
                ]),
            }

    san_candidates = ip_names if hostname_is_ip else dns_names
    matched_san = [n for n in san_candidates if _hostname_matches(n, hostname)]
    matched_cn = [n for n in cn_names if _hostname_matches(n, hostname)]

    if matched_san:
        matched_via: Optional[str] = "subject_alternative_name"
    elif matched_cn:
        matched_via = "common_name"
    else:
        matched_via = None

    rfc6125_matched = bool(matched_san) or (bool(matched_cn) and not san_present)
    if matched_via == "common_name" and san_present:
        notes.append(
            "the hostname matched only the certificate's commonName while a "
            "subjectAltName extension is present; RFC 6125 and the CA/Browser Forum "
            "baseline requirements say clients must ignore the CN in that case, so a "
            "browser would treat this as a name mismatch")
    if not san_present:
        notes.append("the certificate has no subjectAltName extension")

    # Deterministic, de-duplicated, bounded candidate list.
    ordered: List[str] = []
    for name in list(san_candidates) + list(dns_names if hostname_is_ip else []) + cn_names:
        safe = _safe_text(name, MAX_NAME_VALUE_CHARS)
        if isinstance(safe, str) and safe not in ordered:
            ordered.append(safe)
    truncated = len(ordered) > MAX_CANDIDATE_NAMES

    return {
        "hostname": _safe_text(hostname, MAX_NAME_VALUE_CHARS),
        "hostname_is_ip": hostname_is_ip,
        "matched": bool(matched_san or matched_cn),
        "matched_names": [_safe_text(n, MAX_NAME_VALUE_CHARS)
                          for n in (matched_san + matched_cn)[:MAX_CANDIDATE_NAMES]],
        "matched_via": matched_via,
        "rfc6125_matched": rfc6125_matched,
        "san_extension_present": san_present,
        "candidate_names": ordered[:MAX_CANDIDATE_NAMES],
        "candidate_names_truncated": truncated,
        "candidate_name_count": len(ordered),
        "notes": _bound_notes(notes),
    }


# ---------------------------------------------------------------------------
# 5. SAN extraction
# ---------------------------------------------------------------------------

_SAN_TYPE_LABELS = (
    (x509.RFC822Name, "rfc822Name"),
    (x509.UniformResourceIdentifier, "uniformResourceIdentifier"),
    (x509.DirectoryName, "directoryName"),
    (x509.RegisteredID, "registeredID"),
    (x509.OtherName, "otherName"),
)


def extract_sans(cert: "x509.Certificate") -> Dict[str, Any]:
    """
    Extract and normalize the certificate's subjectAltName entries.

    `sans` holds ONLY concrete, syntactically valid DNS hostnames — the
    entries this module is willing to hand onward as discovered hostnames.
    Nothing is discarded: everything else is preserved in a labelled bucket
    of its own so the evidence trail is complete (context.md §12.11).

      sans           concrete DNS hostnames, lowercased, trailing dot
                     stripped, de-duplicated, sorted
      count          len(sans) — unchanged meaning
      wildcard_sans  names containing '*' (e.g. "*.example.com"). Real
                     intelligence about the certificate; NOT a host. Emitting
                     these as hostnames made surface_mapper.py create an
                     asset called "*.example.com", marked in scope, which the
                     orchestrator then scheduled an active TLS scan against.
      ip_sans        iPAddress SAN entries, normalized through `ipaddress`
      other_names    DNS-type entries that are not usable hostnames
                     (single-label, embedded spaces, over-long labels,
                     empty) — kept verbatim-ish (sanitized) as evidence
      other_san_types counts of non-DNS, non-IP entry types
      truncated / total_dns_names / *_count  explicit truncation accounting,
                     so a capped list can never read as a complete one
    """
    result: Dict[str, Any] = {
        "sans": [], "count": 0, "hostname_count": 0,
        "wildcard_sans": [], "wildcard_san_count": 0,
        "ip_sans": [], "ip_san_count": 0,
        "other_names": [], "other_name_count": 0,
        "other_san_types": {}, "truncated": False,
        "total_dns_names": 0, "error": None,
    }

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return result
    except Exception as exc:
        result["error"] = _safe_text(str(exc), MAX_ERROR_CHARS)
        return result

    try:
        raw_dns = list(san_ext.value.get_values_for_type(x509.DNSName))
    except Exception as exc:
        raw_dns = []
        result["error"] = _safe_text(str(exc), MAX_ERROR_CHARS)
    result["total_dns_names"] = len(raw_dns)

    hostnames, wildcards, others = set(), set(), set()
    for raw in raw_dns:
        if not isinstance(raw, str) or not raw.strip():
            others.add("")
            continue
        name = raw.strip().rstrip(".").lower()
        if "*" in name:
            wildcards.add(_safe_text(name, MAX_NAME_VALUE_CHARS))
        elif _is_ip_literal(name):
            # A DNS-type SAN holding an IP literal is malformed but real.
            others.add(_safe_text(name, MAX_NAME_VALUE_CHARS))
        elif _is_hostname_shaped(name):
            hostnames.add(_idna_normalize(name))
        else:
            others.add(_safe_text(name, MAX_NAME_VALUE_CHARS))

    try:
        raw_ips = san_ext.value.get_values_for_type(x509.IPAddress)
        all_ips = sorted({str(ip) for ip in raw_ips})
    except Exception:
        all_ips = []
    result["ip_sans"] = all_ips[:MAX_SAN_OTHER_ENTRIES]
    result["ip_san_count"] = len(all_ips)

    type_counts: Dict[str, int] = {}
    for cls, label in _SAN_TYPE_LABELS:
        try:
            entries = san_ext.value.get_values_for_type(cls)
        except Exception:
            continue
        if entries:
            type_counts[label] = len(entries)
    result["other_san_types"] = type_counts

    ordered = sorted(hostnames)
    result["truncated"] = len(ordered) > MAX_SAN_HOSTNAMES
    result["sans"] = ordered[:MAX_SAN_HOSTNAMES]
    result["count"] = len(result["sans"])
    result["hostname_count"] = len(ordered)
    result["wildcard_sans"] = sorted(wildcards)[:MAX_SAN_OTHER_ENTRIES]
    result["wildcard_san_count"] = len(wildcards)
    result["other_names"] = sorted(others)[:MAX_SAN_OTHER_ENTRIES]
    result["other_name_count"] = len(others)
    return result


# ---------------------------------------------------------------------------
# 6. Certificate-chain analysis
# ---------------------------------------------------------------------------

def analyze_certificate_chain(chain_der: List[bytes]) -> Dict[str, Any]:
    """
    Structurally analyze the chain as presented by the server (via
    get_unverified_chain()): per-certificate summary, subject/issuer
    linkage between consecutive certs, duplicate detection, and whether
    the chain terminates in a self-signed certificate.

    This is NOT full trust-path validation against a root store (see module
    docstring decision #2 and KNOWN LIMITATIONS). "The server did not send
    a complete chain" is what this function can observe; "the chain is
    untrusted" is a different claim it never makes.

    `properly_linked` is only asserted when every certificate in the chain
    parsed. If any element failed to parse, the linkage of the remainder
    says nothing about the chain the server actually sent, so it stays
    None and the parse failures are listed.
    """
    result: Dict[str, Any] = {
        "length": len(chain_der), "certificates": [],
        "properly_linked": None, "terminates_in_self_signed": None,
        "notes": [], "error": None,
        "parsed_count": 0, "parse_errors": [], "analyzed_count": 0,
        "truncated": False, "duplicate_certificates": 0,
        "includes_leaf": None,
    }

    considered = list(chain_der)[:MAX_CHAIN_CERTIFICATES]
    result["truncated"] = len(chain_der) > MAX_CHAIN_CERTIFICATES
    if result["truncated"]:
        result["notes"].append(
            f"the server presented {len(chain_der)} certificates; only the first "
            f"{MAX_CHAIN_CERTIFICATES} were analyzed")

    # (certificate, its own DER) pairs. Keeping them paired matters: a
    # compacted cert list zipped against the uncompacted DER list assigned
    # every certificate after a parse failure the *wrong* bytes, and so the
    # wrong SHA-256 fingerprint — the field downstream correlation keys on.
    parsed: List[Tuple[x509.Certificate, bytes]] = []
    parse_failures = 0
    for index, der in enumerate(considered):
        try:
            parsed.append((x509.load_der_x509_certificate(der, default_backend()), der))
        except Exception as exc:
            parse_failures += 1
            if len(result["parse_errors"]) < MAX_NOTES:
                result["parse_errors"].append(
                    {"index": index, "error": _safe_text(str(exc), MAX_ERROR_CHARS)})
    certs: List[x509.Certificate] = [c for c, _ in parsed]

    result["analyzed_count"] = len(considered)
    result["parsed_count"] = len(certs)
    if parse_failures:
        result["error"] = (f"failed to parse {parse_failures} of {len(considered)} "
                           f"chain certificate(s)")

    fingerprints: List[str] = []
    for cert, der in parsed:
        summary = _certificate_summary(cert, der if isinstance(der, bytes) else None)
        try:
            summary["not_valid_before"] = cert.not_valid_before_utc.isoformat()
            summary["not_valid_after"] = cert.not_valid_after_utc.isoformat()
        except Exception:
            summary["not_valid_before"] = None
            summary["not_valid_after"] = None
        summary["is_self_issued"] = cert.issuer == cert.subject
        if summary.get("fingerprint_sha256"):
            fingerprints.append(summary["fingerprint_sha256"])
        result["certificates"].append(summary)

    result["duplicate_certificates"] = len(fingerprints) - len(set(fingerprints))
    if result["duplicate_certificates"]:
        result["notes"].append(
            f"{result['duplicate_certificates']} certificate(s) appear more than once in "
            f"the chain the server presented")

    if len(certs) >= 2 and parse_failures == 0:
        result["properly_linked"] = all(
            certs[i].issuer == certs[i + 1].subject for i in range(len(certs) - 1)
        )
        if result["properly_linked"] is False:
            result["notes"].append(
                "consecutive certificates do not chain by subject/issuer name; the chain may "
                "be out of order or may contain an unrelated certificate")
    elif parse_failures:
        result["notes"].append(
            "chain linkage was not evaluated because at least one certificate did not parse")

    if certs:
        last = certs[-1]
        result["terminates_in_self_signed"] = last.issuer == last.subject
    if result["length"] < 2:
        result["notes"].append(
            "chain has fewer than 2 certificates; an intermediate may be missing, "
            "or the server sent only the leaf certificate")
        result["notes"].append(
            "this describes what the server transmitted, not whether the certificate is "
            "trusted; many clients complete an incomplete chain themselves")

    result["notes"] = _bound_notes(result["notes"])
    return result


# ---------------------------------------------------------------------------
# 7. Self-signed detection
# ---------------------------------------------------------------------------

def detect_self_signed(cert: "x509.Certificate") -> Dict[str, Any]:
    """
    Detect a self-signed certificate.

    Two distinct properties are reported, because conflating them produced
    a false positive on every self-issued-but-cross-signed CA certificate —
    and risk_engine.py turns `tls_self_signed is True` into a MEDIUM signal:

      self_issued        issuer name == subject name (the usual heuristic)
      signature_verified True  — the certificate's own public key verifies
                                 its signature: genuinely self-signed
                         False — the signature is definitively NOT its own
                                 key's: self-issued, but signed by someone
                                 else (cross-signing, re-issuance)
                         None  — not attempted or inconclusive (unsupported
                                 key type, RSA-PSS, unknown hash)
      self_signed        True only when the name check holds AND the
                         signature did not definitively fail

    The signature check is a passive verification of a public signature —
    not exploitation of anything.
    """
    result: Dict[str, Any] = {
        "self_signed": False, "confidence": CONFIDENCE_LOW, "evidence": [],
        "self_issued": False, "signature_verified": None,
    }

    if cert.issuer != cert.subject:
        result["evidence"].append("issuer and subject names differ")
        result["confidence"] = CONFIDENCE_HIGH
        return result

    result["self_issued"] = True
    result["evidence"].append("issuer and subject names are identical")

    try:
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            # RSASSA-PSS certificates verify under PSS, never under PKCS#1 v1.5.
            # Hard-coding PKCS1v15 made a genuinely self-signed RSA-PSS
            # certificate raise InvalidSignature, which — now that an invalid
            # signature is treated as a definitive "not self-signed" — would
            # have inverted the answer. `signature_algorithm_parameters`
            # reports the certificate's actual padding.
            rsa_padding = getattr(cert, "signature_algorithm_parameters", None)
            if not isinstance(rsa_padding, padding.AsymmetricPadding):
                rsa_padding = padding.PKCS1v15()
            public_key.verify(
                cert.signature, cert.tbs_certificate_bytes,
                rsa_padding, cert.signature_hash_algorithm,
            )
            label = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes,
                              ec.ECDSA(cert.signature_hash_algorithm))
            label = "EC"
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
            label = "EdDSA"
        else:
            result["self_signed"] = True
            result["confidence"] = CONFIDENCE_MEDIUM
            result["evidence"].append(
                "issuer/subject match but signature verification not attempted for this key type"
            )
            return result
        result["self_signed"] = True
        result["signature_verified"] = True
        result["confidence"] = CONFIDENCE_HIGH
        result["evidence"].append(f"signature cryptographically self-verified ({label})")
    except InvalidSignature:
        # Definitive: the subject's own key did NOT produce this signature.
        # The certificate is self-ISSUED (names match) but not self-SIGNED.
        result["self_signed"] = False
        result["signature_verified"] = False
        result["confidence"] = CONFIDENCE_HIGH
        result["evidence"].append(
            "issuer and subject names are identical but the certificate's own public key does "
            "NOT verify its signature: the certificate is self-issued and signed by a different "
            "key (e.g. a cross-signed or re-issued CA certificate), not self-signed"
        )
    except Exception as exc:
        # Inconclusive: unsupported padding (RSA-PSS), an unknown hash, a
        # missing signature_hash_algorithm. Name equality still stands.
        result["self_signed"] = True
        result["confidence"] = CONFIDENCE_MEDIUM
        result["evidence"].append(
            "issuer/subject match but cryptographic self-verification was inconclusive "
            f"({_safe_text(type(exc).__name__, 64)}); the name-equality heuristic alone supports this"
        )
    return result


# ---------------------------------------------------------------------------
# Module orchestration (single host:port)
# ---------------------------------------------------------------------------

def _stage(summary: Dict[str, Any], name: str, fn, default: Any) -> Any:
    """
    Run one analysis stage in isolation.

    All seven analyses used to run unguarded, so a single unexpected
    exception in any of them destroyed the whole run — including the six
    that had already succeeded and everything that would have been
    persisted. context.md §12.11: one failure must not break unrelated work.
    """
    try:
        return fn()
    except Exception as exc:
        summary["errors"].append({"stage": name, "error": _safe_text(str(exc), MAX_ERROR_CHARS)})
        return default


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
    the results to <output_dir>/pending_assets.json in one batched,
    crash-safe write.

    `sni_hostname` defaults to `host` when `host` is a domain name, or to
    None (no SNI — RFC 6066 forbids an IP literal in server_name) when
    `host` is an IP literal and no override is supplied. An explicit
    `sni_hostname` is validated and scope-checked exactly like `host`: it
    is an identity this module actively asserts to a server, so an
    out-of-scope value is refused rather than sent.

    Returns a structured summary in addition to (not instead of) the
    crash-safe persisted store. `status` distinguishes "found" (handshake
    succeeded — inspect the sub-fields for any certificate/TLS problems,
    which do NOT change this status) from "unavailable" (TLS service
    unreachable), "handshake_failed" (TLS negotiation itself failed), and
    "error" (unexpected condition, e.g. unparseable certificate). `errors`
    is the per-stage failure list the orchestrator counts.
    """
    host = validate_ssl_host(host, target=target)

    # socket.create_connection() raises a bare TypeError on a non-integer port,
    # and TypeError is not an OSError, so it escaped _negotiate_tls's handlers
    # entirely. A ScopeError is both accurate and the exception type callers
    # (including the orchestrator) already guard for.
    if isinstance(port, bool) or not isinstance(port, (int, str)):
        raise ScopeError(f"Port must be an integer, got {port!r}")
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise ScopeError(f"Port must be an integer, got {port!r}") from exc
    if not 1 <= port <= 65535:
        raise ScopeError(f"Port {port} is outside the valid range 1-65535")

    # An empty/blank override has always meant "no override"; keep it that way
    # rather than turning it into a ScopeError.
    if isinstance(sni_hostname, str) and not sni_hostname.strip():
        sni_hostname = None
    if sni_hostname is not None:
        sni_hostname = validate_ssl_host(sni_hostname, target=target)

    if sni_hostname:
        # An IP literal must not be sent as SNI, but it is still a usable
        # identity to validate the certificate against.
        effective_sni = None if _is_ip_literal(sni_hostname) else sni_hostname
        identity = sni_hostname
    elif _is_ip_literal(host):
        effective_sni = None
        identity = host
    else:
        effective_sni = host
        identity = host

    summary: Dict[str, Any] = {
        "host": host, "port": port, "sni_hostname": effective_sni,
        "identity_validated": identity,
        "target": target or host, "module": MODULE_NAME,
        "started_at": _now(),
        "status": None,
        "certificate": {}, "tls_version": {}, "cipher": {}, "validity": {},
        "hostname_validation": {}, "sans": {}, "chain": {}, "self_signed": {},
        "discovered_hostnames": [], "has_certificate_or_tls_problems": None,
        "observation": {},
        "findings_produced": 0, "findings_persisted": 0,
        "errors": [],
        "error": None,
    }

    try:
        store: Optional[PendingAssetsStore] = PendingAssetsStore(output_dir=output_dir)
    except OSError as exc:
        # A run whose output directory cannot be created still produces
        # useful analysis; losing it entirely to an unhandled OSError does not.
        store = None
        summary["errors"].append({"stage": "persistence_setup",
                                  "error": _safe_text(str(exc), MAX_ERROR_CHARS)})

    negotiation = _negotiate_tls(host, port, effective_sni, timeout)
    summary["status"] = negotiation["status"]
    summary["observation"] = {
        "host": host, "port": port,
        "peer_ip": negotiation.get("peer_ip"),
        "peer_port": negotiation.get("peer_port"),
        "sni_sent": negotiation.get("sni_sent", bool(effective_sni)),
        "sni_hostname": effective_sni,
        "observed_at": _now(),
        "endpoint_attribution": (
            "the TLS endpoint that answered this connection; behind a CDN, WAF or load "
            "balancer this is the edge, not the origin server"),
        "chain_trust_validated": False,
        "revocation_checked": False,
        "certificate_transparency_checked": False,
    }

    if negotiation["status"] != "found":
        summary["error"] = _safe_text(negotiation["error"], MAX_ERROR_CHARS)
        # Honest failure semantics: a host that did not complete a handshake
        # is "not checked", never "checked and clean". Nothing is persisted,
        # so nothing downstream can read this as a negative result.
        summary["completeness"] = "not_performed"
        summary["finished_at"] = _now()
        return summary

    try:
        cert = x509.load_der_x509_certificate(negotiation["leaf_der"], default_backend())
    except Exception as exc:
        summary["status"] = "error"
        summary["error"] = _safe_text(f"failed to parse leaf certificate: {exc}", MAX_ERROR_CHARS)
        summary["completeness"] = "not_performed"
        summary["finished_at"] = _now()
        return summary

    summary["certificate"] = _stage(
        summary, "certificate_summary",
        lambda: _certificate_summary(cert, negotiation["leaf_der"]),
        {"subject": {}, "issuer": {}, "serial_number": None})
    summary["tls_version"] = _stage(
        summary, "tls_version", lambda: analyze_tls_version(negotiation["version"]),
        analyze_tls_version(None))
    summary["cipher"] = _stage(
        summary, "cipher_suite", lambda: analyze_cipher_suite(negotiation["cipher"]),
        analyze_cipher_suite(None))
    summary["validity"] = _stage(
        summary, "certificate_validity", lambda: analyze_certificate_validity(cert), {})
    summary["self_signed"] = _stage(
        summary, "self_signed", lambda: detect_self_signed(cert),
        {"self_signed": None, "confidence": CONFIDENCE_LOW, "evidence": []})
    summary["sans"] = _stage(
        summary, "san_extraction", lambda: extract_sans(cert),
        {"sans": [], "count": 0, "hostname_count": 0, "wildcard_sans": [],
         "wildcard_san_count": 0, "ip_sans": [], "ip_san_count": 0,
         "other_names": [], "other_name_count": 0, "other_san_types": {},
         "truncated": False, "total_dns_names": 0, "error": None})
    summary["chain"] = _stage(
        summary, "certificate_chain",
        lambda: analyze_certificate_chain(negotiation["chain_der"]),
        {"length": 0, "certificates": [], "notes": [], "error": None})

    leaf_fp = (summary["certificate"] or {}).get("fingerprint_sha256")
    chain_certs = (summary["chain"] or {}).get("certificates") or []
    if isinstance(summary["chain"], dict):
        summary["chain"]["includes_leaf"] = (
            bool(leaf_fp) and any(c.get("fingerprint_sha256") == leaf_fp for c in chain_certs))

    # `identity` is always set (validate_ssl_host() guarantees a non-empty
    # host). For an IP-literal identity with no IP entry on the certificate,
    # validate_hostname_against_cert() itself returns the "not tested" shape
    # with an explanatory `note`, so there is no unvalidated case to special-
    # case here.
    summary["hostname_validation"] = _stage(
        summary, "hostname_validation",
        lambda: validate_hostname_against_cert(cert, identity),
        {"hostname": identity, "matched": None, "matched_names": [],
         "candidate_names": [], "note": "hostname validation did not complete"})

    summary["has_certificate_or_tls_problems"] = bool(
        summary["validity"].get("is_expired")
        or summary["validity"].get("is_not_yet_valid")
        or summary["tls_version"].get("is_outdated")
        or summary["self_signed"].get("self_signed")
        or summary["hostname_validation"].get("matched") is False
    )

    scope_target = target or (host if not _is_ip_literal(host) else None)
    discovered = [
        {"hostname": san, "in_scope": _in_scope_host(san, scope_target) if scope_target else None}
        for san in summary["sans"].get("sans", [])
    ]
    summary["discovered_hostnames"] = discovered

    findings: List[Dict[str, Any]] = []
    evidence = [
        f"TLS handshake to {host}:{port} negotiated {summary['tls_version'].get('version')}",
        f"Certificate subject={summary['certificate'].get('subject')}, "
        f"issuer={summary['certificate'].get('issuer')}",
        "The negotiated protocol/cipher describe this one handshake; the server's full set "
        "of supported versions and suites was not enumerated.",
        "Chain trust was not validated against a root store, and revocation (OCSP/CRL) and "
        "Certificate Transparency were not checked.",
    ]
    if summary["observation"].get("peer_ip"):
        evidence.append(f"Observed TLS endpoint {summary['observation']['peer_ip']}:"
                        f"{summary['observation'].get('peer_port')} "
                        f"(SNI={effective_sni or 'not sent'})")
    hv_notes = summary["hostname_validation"].get("notes") or []
    evidence.extend(hv_notes)

    findings.append(make_finding(
        finding_type="tls_certificate_analysis",
        target=target or host,
        value={
            "host": host, "port": port, "sni_hostname": effective_sni,
            "observation": summary["observation"],
            "certificate": summary["certificate"],
            "validity": summary["validity"],
            "tls_version": summary["tls_version"],
            "cipher": summary["cipher"],
            "hostname_validation": summary["hostname_validation"],
            "self_signed": summary["self_signed"],
            "chain": summary["chain"],
            "sans": summary["sans"],
        },
        evidence=evidence,
        confidence=CONFIDENCE_HIGH,
        metadata={
            "host": host, "port": port,
            "peer_ip": summary["observation"].get("peer_ip"),
            "fingerprint_sha256": leaf_fp,
            "is_expired": summary["validity"].get("is_expired"),
            "is_outdated_tls": summary["tls_version"].get("is_outdated"),
            "self_signed": summary["self_signed"].get("self_signed"),
            "has_certificate_or_tls_problems": summary["has_certificate_or_tls_problems"],
        },
    ))

    # SAN surface expansion (context.md: "feeds new hostnames back to
    # surface_mapper") — recorded as discoveries only; never auto-probed.
    # Only concrete hostnames reach this loop (see extract_sans).
    for entry in discovered:
        findings.append(make_finding(
            finding_type="tls_san",
            target=target or host,
            value=entry["hostname"],
            evidence=[f"Certificate SAN entry from {host}:{port} leaf certificate "
                      f"(ssl_analyzer.py deep analysis)"],
            confidence=CONFIDENCE_HIGH if entry["in_scope"] else CONFIDENCE_MEDIUM,
            metadata={"host": host, "port": port, "in_scope": entry["in_scope"],
                      "fingerprint_sha256": leaf_fp},
        ))

    err = _safe_store_add_many(store, findings)
    if err:
        summary["errors"].append({"stage": "persistence", "error": _safe_text(err, MAX_ERROR_CHARS)})
    elif store is not None:
        summary["findings_persisted"] = len(findings)
    summary["findings_produced"] = len(findings)

    summary["completeness"] = "complete" if not summary["errors"] else "partial"
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
    parser.add_argument("--host", required=True, help="Target hostname or IP address")
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
