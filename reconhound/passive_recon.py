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
via PendingAssetsStore (crash-safe, atomic writes). Output is intended to
feed surface_mapper.py (module 6, not yet implemented).
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
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


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
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

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


def whois_lookup(target: str, store: Optional[PendingAssetsStore] = None) -> Dict[str, Any]:
    """WHOIS registration lookup for `target`."""
    target = validate_target(target)
    result: Dict[str, Any] = {"status": "not_found", "data": {}, "error": None}

    try:
        raw = python_whois.whois(target)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    data: Dict[str, Any] = {}
    if raw:
        for key in _WHOIS_FIELDS:
            value = raw.get(key) if hasattr(raw, "get") else getattr(raw, key, None)
            if value is not None:
                data[key] = _jsonify(value)

    if not data:
        result["status"] = "not_found"
        return result

    result["status"] = "found"
    result["data"] = data

    if store is not None:
        store.add(make_finding(
            finding_type="whois",
            target=target,
            value=data,
            evidence=[f"WHOIS lookup for {target} returned registration data"],
            confidence=CONFIDENCE_HIGH,
            metadata={},
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
    result: Dict[str, Any] = {"status": "not_found", "certificate": None, "sans": [], "error": None}

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result
    except ssl.SSLError as exc:
        result["status"] = "error"
        result["error"] = f"TLS handshake failed: {exc}"
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
    result: Dict[str, Any] = {"status": "not_found", "data": {}, "error": None}

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        result["status"] = "error"
        result["error"] = f"not a valid IP address: {ip!r}"
        return result

    if ip_obj.version != 4:
        result["status"] = "error"
        result["error"] = "ASN discovery currently supports IPv4 only"
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    reversed_ip = ".".join(reversed(ip.split(".")))
    origin_query = f"{reversed_ip}.origin.asn.cymru.com"

    try:
        answer = resolver.resolve(origin_query, "TXT")
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    txt = answer[0].to_text().strip('"')
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 5:
        result["status"] = "error"
        result["error"] = f"unexpected Cymru response format: {txt!r}"
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
) -> Dict[str, Any]:
    """SPF, DMARC, best-effort DKIM, and MX analysis for `target`."""
    target = validate_target(target)

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    result: Dict[str, Any] = {
        "spf": {"status": "not_found", "record": None},
        "dmarc": {"status": "not_found", "record": None},
        "dkim": {
            "status": "not_found",
            "selectors_checked": list(_COMMON_DKIM_SELECTORS),
            "found_selectors": [],
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
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as exc:
        result["dmarc"]["status"] = "error"
        result["dmarc"]["error"] = str(exc)

    found_selectors = []
    for selector in _COMMON_DKIM_SELECTORS:
        try:
            answer = resolver.resolve(f"{selector}._domainkey.{target}", "TXT")
            txts = [rdata.to_text().strip('"') for rdata in answer]
            if txts:
                found_selectors.append({"selector": selector, "record": txts[0]})
        except Exception:
            continue
    if found_selectors:
        result["dkim"]["status"] = "found"
        result["dkim"]["found_selectors"] = found_selectors

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
        if result["dkim"]["status"] == "found":
            selector_names = ", ".join(s["selector"] for s in found_selectors)
            evidence.append(f"DKIM TXT record present for selector(s): {selector_names}")
        if result["mx"]["status"] == "found":
            evidence.append(f"{len(result['mx']['records'])} MX record(s) found")
        if not evidence:
            evidence.append(
                "No SPF/DMARC record found; DKIM checked against common selectors only"
            )

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
