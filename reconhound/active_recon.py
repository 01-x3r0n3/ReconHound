"""
reconhound/active_recon.py — ReconHound Module 2 (active_recon.py).

Phase: Active. See context.md §10 (module 7 in the module list, "Network-level
recon") for the authoritative responsibilities, and §8 for the
evidence/confidence data model this module implements. This file only
documents implementation-specific detail, not the architecture itself.

STATUS: complete per the current context.md contract, within the
documented limitations below.

Full Module 2 responsibility set per context.md, and where each lives:

  - TCP scanning                          -> tcp_connect_scan
  - IPv6 scanning                         -> ipv6_tcp_connect_scan
  - UDP scanning (53/161/500/623)         -> udp_scan
  - Service detection                     -> identify_service
  - Banner grabbing                       -> grab_banner
  - SMTP VRFY/EXPN (25/587)               -> smtp_probe
  - SNMP community strings (161)          -> snmp_community_probe
  - FTP anon login (21)                  -> ftp_anonymous_login_check
  - SSH fingerprinting (22)               -> ssh_fingerprint
  - IPMI exposure -> auto CRITICAL (623)  -> check_ipmi_exposure
  - DB exposure -> auto CRITICAL          -> check_database_exposure
    (3306/5432)
  - OS fingerprinting via TTL/TCP-window  -> fingerprint_os_ttl (TTL only;
                                             see limitation below)
  - Cross-host pattern detection          -> detect_cross_host_port_pattern
  - Single-host orchestration             -> run_active_recon (ties the
                                             above together; not itself a
                                             listed context.md
                                             responsibility, but follows the
                                             run_passive_recon precedent in
                                             passive_recon.py)

Confirmed implementation decisions (ambiguities in context.md resolved with
the project owner before implementation):

  1. "TCP scanning (raw sockets)" is implemented as a standard
     `socket.connect()`-based scan, not a privileged SOCK_RAW/SYN packet
     scan. Nothing elsewhere in context.md (§5 tech stack, §16 security
     rules) calls for a packet-crafting dependency or root/CAP_NET_RAW
     requirement, so the parenthetical is treated as descriptive rather
     than a hard implementation mandate. This keeps the module dependency-
     free, cross-platform, and unprivileged, consistent with
     passive_recon.py. The same decision applies to every scan/probe in
     this file: no scapy, no raw sockets, no elevated privileges anywhere.
  2. Unlike UDP scanning, context.md defines no default TCP port list (and
     the project's wordlists/ folder has no ports.txt). No default TCP
     port list is invented: callers must supply the exact TCP ports to
     scan. UDP scanning, by contrast, has an explicit default port list in
     context.md (53/161/500/623), so udp_scan uses it as a genuine default
     when the caller doesn't override it.

Known, deliberate limitations (not oversights — see each function's
docstring for detail):

  - SSH fingerprinting is limited to parsing the plaintext SSH
    identification banner (RFC 4253 §4.2: protocol version + software
    string). Host-key fingerprint extraction would require a full SSH
    key-exchange implementation (e.g. the `paramiko` dependency), which is
    out of scope given decision #1 above.
  - OS fingerprinting is TTL-only, sampled over UDP, not TCP. During
    implementation this was verified empirically: Linux does not attach
    per-packet IP_TTL ancillary data to a TCP stream socket's recvmsg()
    (ancdata came back empty in testing), only to datagram sockets. The
    TCP-window signal that tools like p0f use additionally requires
    inspecting the raw TCP header of the peer's SYN-ACK via packet
    capture, which decision #1 rules out. Both limitations are therefore
    consequences of the confirmed no-raw-socket decision, not gaps.
  - IPv6 support in this pass covers `ipv6_tcp_connect_scan` only. The
    protocol-specific checks (SMTP/SNMP/FTP/SSH/IPMI/DB exposure/OS
    fingerprint) and `run_active_recon` operate on IPv4 targets only, and
    `udp_scan` is IPv4-only. context.md lists "IPv6 scanning" as its own
    single bullet rather than requiring every other item to be
    IPv6-capable, so this is treated as a bounded, separate capability
    rather than a blanket requirement.
  - Every protocol-specific check here (SMTP VRFY/EXPN, SNMP community
    strings, FTP anonymous login, IPMI presence, DB port reachability)
    tests only well-known/default values explicitly named by context.md
    (e.g. SNMP community strings "public"/"private", FTP user
    "anonymous"). None of this is exploitation, credential brute-forcing,
    or authentication bypass — each check either observes protocol
    behavior (VRFY/EXPN response codes, RMCP presence) or logs in using a
    protocol-defined public access mechanism (anonymous FTP).

Evidence/confidence/persistence conventions (see context.md §8, §12.1,
§12.6): every discovery is persisted immediately to
<output_dir>/pending_assets.json via PendingAssetsStore (the same
crash-safe, atomic-write store used by passive_recon.py, sharing the same
output file).

Two persistence patterns are used, matching the two patterns already
established in passive_recon.py:

  - "Simple/many-valued" results (one discovery per port/host — e.g. open
    TCP/UDP ports, banners, service identifications, cross-host patterns,
    OS fingerprint) are persisted only when something is actually found,
    mirroring passive_recon.py's enumerate_dns/discover_tls_certificate/
    discover_asn (found-only; negative results are returned to the caller
    but not written to disk).
  - "Composite protocol checks" (the six items context.md's own sentence
    groups together as "protocol-specific enumeration": SMTP, SNMP, FTP,
    SSH, IPMI, DB exposure) are always persisted when the check actually
    completes — found or not — mirroring passive_recon.py's
    analyze_email_security. This directly implements the negative-result-
    memory principle (context.md §12.6): a completed "checked, not
    exposed" result on an expensive/active protocol check is itself worth
    remembering so it isn't needlessly repeated. Checks that errored out
    before completing (network unreachable, timeout before any protocol
    exchange, etc.) are NOT persisted, consistent with passive_recon.py's
    treatment of its own "error" states.

Output is intended to feed surface_mapper.py (module 6, not yet
implemented) — this module does not implement or call into surface_mapper,
risk_engine, or any other later module.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

MODULE_NAME = "active_recon.py"

# Confidence levels (context.md §8)
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

# UDP scanning has an explicit default port list in context.md (unlike TCP).
DEFAULT_UDP_PORTS: List[int] = [53, 161, 500, 623]

# DB exposure ports named explicitly by context.md.
_DB_PORT_SERVICE: Dict[int, str] = {3306: "mysql", 5432: "postgresql"}

# Well-known/default SNMP community strings (context.md: "SNMP community strings").
_DEFAULT_SNMP_COMMUNITIES: List[str] = ["public", "private"]


class ScopeError(ValueError):
    """Raised when a scan target falls outside this function's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def validate_scan_target(ip: str) -> str:
    """
    Validate that `ip` is a syntactically valid IPv4 address.

    active_recon operates on explicit IP addresses already discovered (e.g.
    by passive_recon.py) rather than domain names, and never expands a
    single scan into a range: CIDR notation and hostnames are rejected, not
    resolved. IPv6 is intentionally rejected here (not silently ignored):
    use ipv6_tcp_connect_scan / validate_ipv6_scan_target for IPv6 targets.
    """
    if not isinstance(ip, str) or not ip.strip():
        raise ScopeError("Scan target must be a non-empty IP address string.")

    candidate = ip.strip()

    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        raise ScopeError(
            f"Scan target must be a single valid IP address, not {ip!r} "
            f"(hostnames and CIDR ranges are not accepted by this function)."
        ) from None

    if ip_obj.version != 4:
        raise ScopeError(
            f"This function requires an IPv4 address; use ipv6_tcp_connect_scan "
            f"for IPv6 targets: {ip!r}"
        )

    return str(ip_obj)


def validate_ipv6_scan_target(ip: str) -> str:
    """
    Validate that `ip` is a syntactically valid IPv6 address, for use with
    ipv6_tcp_connect_scan. Mirrors validate_scan_target's rules — a single
    literal address only, no hostnames, no CIDR ranges.
    """
    if not isinstance(ip, str) or not ip.strip():
        raise ScopeError("Scan target must be a non-empty IP address string.")

    candidate = ip.strip()

    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        raise ScopeError(
            f"Scan target must be a single valid IP address, not {ip!r} "
            f"(hostnames and CIDR ranges are not accepted by this function)."
        ) from None

    if ip_obj.version != 6:
        raise ScopeError(
            f"ipv6_tcp_connect_scan requires an IPv6 address; use tcp_connect_scan "
            f"for IPv4 targets: {ip!r}"
        )

    return str(ip_obj)


# ---------------------------------------------------------------------------
# Evidence-model helpers (mirrors passive_recon.py's model; kept local per
# the "modular independence" design principle, context.md §12.2)
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
# Crash-safe persistence (same file/format as passive_recon.py's
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
# TCP connect() scanning (IPv4 + IPv6)
# ---------------------------------------------------------------------------

def _scan_one_tcp_port(
    ip: str, port: int, timeout: float, family: int = socket.AF_INET
) -> Dict[str, Any]:
    """
    Attempt a single TCP connect() to ip:port.

    status is one of:
      "open"     - the TCP handshake completed.
      "closed"   - the connection was actively refused (or otherwise failed
                   to establish) — a response was received, just not an
                   accept.
      "filtered" - no response was received within `timeout` (consistent
                   with a firewall silently dropping the packet).
      "error"    - the attempt could not be completed for a reason unrelated
                   to the port's open/closed state (e.g. invalid port
                   number).
    """
    entry: Dict[str, Any] = {"port": port, "status": "error", "error": None}
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        addr = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
        result = sock.connect_ex(addr)
        entry["status"] = "open" if result == 0 else "closed"
    except socket.timeout:
        entry["status"] = "filtered"
        entry["error"] = "timeout"
    except OverflowError as exc:
        entry["status"] = "error"
        entry["error"] = f"invalid port number: {exc}"
    except OSError as exc:
        entry["status"] = "error"
        entry["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()
    return entry


def tcp_connect_scan(
    ip: str,
    ports: List[int],
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 1.0,
    max_workers: int = 20,
) -> Dict[str, Any]:
    """
    TCP connect() scan of the explicit `ports` list against an IPv4 `ip`.

    Ports are scanned concurrently via a thread pool (threading is part of
    context.md's §5 tech stack). No default port list is assumed — `ports`
    must be supplied by the caller (see module docstring). Only
    successfully-open ports are persisted as findings (closed/filtered
    results are returned in the summary but are negative results, not
    discoveries, so they are not written to pending_assets.json).

    `target` is the logical target this IP belongs to (e.g. the domain
    passed to passive_recon.py), used to tag persisted findings; if
    omitted, `ip` itself is used as the finding's target.
    """
    ip = validate_scan_target(ip)

    if not isinstance(ports, list) or not ports:
        raise ValueError("`ports` must be a non-empty list of TCP port numbers to scan.")

    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_to_port = {
            executor.submit(_scan_one_tcp_port, ip, port, timeout): port for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                results.append(future.result())
            except Exception as exc:  # _scan_one_tcp_port already contains its own errors
                results.append({"port": port, "status": "error", "error": str(exc)})

    results.sort(key=lambda r: r["port"])
    open_ports = [r["port"] for r in results if r["status"] == "open"]

    if store is not None:
        for port in open_ports:
            store.add(make_finding(
                finding_type="open_tcp_port",
                target=target or ip,
                value={"ip": ip, "port": port, "protocol": "tcp"},
                evidence=[f"TCP connect() handshake to {ip}:{port} succeeded"],
                confidence=CONFIDENCE_HIGH,
                metadata={"ip": ip, "port": port, "protocol": "tcp", "ip_version": 4},
            ))

    return {
        "ip": ip,
        "protocol": "tcp",
        "ip_version": 4,
        "ports_scanned": sorted(ports),
        "open_ports": sorted(open_ports),
        "results": results,
    }


def ipv6_tcp_connect_scan(
    ip: str,
    ports: List[int],
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 1.0,
    max_workers: int = 20,
) -> Dict[str, Any]:
    """
    TCP connect() scan of `ports` against an IPv6 host.

    Same technique and contract as tcp_connect_scan, restricted to IPv6
    addresses — context.md lists "IPv6 scanning" as its own Module 2
    responsibility, separate from the base TCP scan.
    """
    ip = validate_ipv6_scan_target(ip)

    if not isinstance(ports, list) or not ports:
        raise ValueError("`ports` must be a non-empty list of TCP port numbers to scan.")

    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_to_port = {
            executor.submit(_scan_one_tcp_port, ip, port, timeout, socket.AF_INET6): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"port": port, "status": "error", "error": str(exc)})

    results.sort(key=lambda r: r["port"])
    open_ports = [r["port"] for r in results if r["status"] == "open"]

    if store is not None:
        for port in open_ports:
            store.add(make_finding(
                finding_type="open_tcp_port",
                target=target or ip,
                value={"ip": ip, "port": port, "protocol": "tcp"},
                evidence=[f"TCP connect() handshake to [{ip}]:{port} succeeded"],
                confidence=CONFIDENCE_HIGH,
                metadata={"ip": ip, "port": port, "protocol": "tcp", "ip_version": 6},
            ))

    return {
        "ip": ip,
        "protocol": "tcp",
        "ip_version": 6,
        "ports_scanned": sorted(ports),
        "open_ports": sorted(open_ports),
        "results": results,
    }


# ---------------------------------------------------------------------------
# UDP scanning
# ---------------------------------------------------------------------------

def _scan_one_udp_port(ip: str, port: int, timeout: float, probe: bytes = b"") -> Dict[str, Any]:
    """
    Attempt a single UDP probe to ip:port using a connected UDP socket (so
    an ICMP port-unreachable response surfaces as ConnectionRefusedError —
    standard technique, no raw sockets required).

    status is one of:
      "open"          - a response datagram was received.
      "closed"        - an ICMP port-unreachable was received.
      "open_filtered" - no response and no ICMP error within `timeout` —
                        UDP's fundamental ambiguity: silence could mean the
                        port is open and simply didn't reply to this probe,
                        or that it's filtered by a firewall.
      "error"         - the attempt could not be completed for an unrelated
                        reason.
    """
    entry: Dict[str, Any] = {"port": port, "status": "error", "error": None, "response_hex": None}
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(probe)
        try:
            data = sock.recv(2048)
            entry["status"] = "open"
            entry["response_hex"] = data.hex()
        except socket.timeout:
            entry["status"] = "open_filtered"
        except ConnectionRefusedError:
            entry["status"] = "closed"
    except OSError as exc:
        entry["status"] = "error"
        entry["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()
    return entry


def udp_scan(
    ip: str,
    ports: Optional[List[int]] = None,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 1.5,
    max_workers: int = 10,
) -> Dict[str, Any]:
    """
    UDP scan of `ports` against an IPv4 `ip`. Unlike TCP, context.md gives
    UDP scanning an explicit default port list (53/161/500/623); if
    `ports` is omitted, that default is used.

    Each port is probed with an empty datagram (no protocol-specific
    payload) — a real response confirms "open" with HIGH confidence; a
    genuine ICMP port-unreachable confirms "closed" (not persisted, like a
    closed TCP port); silence is reported as "open_filtered" and persisted
    at LOW confidence as a "found with uncertainty" negative-result-memory
    entry (context.md §8/§12.6), since UDP scanning cannot otherwise
    distinguish open-but-silent from filtered. The protocol-specific checks
    (snmp_community_probe, check_ipmi_exposure) supplement this generic
    scan with real, protocol-correct probes for ports 161 and 623.
    """
    ip = validate_scan_target(ip)
    ports = ports if ports is not None else list(DEFAULT_UDP_PORTS)

    if not ports:
        raise ValueError(
            "`ports` must be a non-empty list of UDP port numbers "
            "(or omit to use the default 53/161/500/623)."
        )

    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_to_port = {
            executor.submit(_scan_one_udp_port, ip, port, timeout): port for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append(
                    {"port": port, "status": "error", "error": str(exc), "response_hex": None}
                )

    results.sort(key=lambda r: r["port"])
    open_ports = [r["port"] for r in results if r["status"] == "open"]
    open_filtered_ports = [r["port"] for r in results if r["status"] == "open_filtered"]

    if store is not None:
        for r in results:
            if r["status"] == "open":
                store.add(make_finding(
                    finding_type="open_udp_port",
                    target=target or ip,
                    value={"ip": ip, "port": r["port"], "protocol": "udp", "response_hex": r["response_hex"]},
                    evidence=[f"UDP probe to {ip}:{r['port']} received a response"],
                    confidence=CONFIDENCE_HIGH,
                    metadata={"ip": ip, "port": r["port"], "protocol": "udp"},
                ))
            elif r["status"] == "open_filtered":
                store.add(make_finding(
                    finding_type="open_or_filtered_udp_port",
                    target=target or ip,
                    value={"ip": ip, "port": r["port"], "protocol": "udp"},
                    evidence=[
                        f"No response and no ICMP unreachable from {ip}:{r['port']}/udp "
                        f"within {timeout}s — cannot distinguish open from filtered"
                    ],
                    confidence=CONFIDENCE_LOW,
                    metadata={"ip": ip, "port": r["port"], "protocol": "udp", "ambiguous": True},
                ))

    return {
        "ip": ip,
        "protocol": "udp",
        "ports_scanned": sorted(ports),
        "open_ports": sorted(open_ports),
        "open_or_filtered_ports": sorted(open_filtered_ports),
        "results": results,
    }


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

def grab_banner(
    ip: str,
    port: int,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 2.0,
    family: int = socket.AF_INET,
    probe: Optional[bytes] = None,
    max_bytes: int = 1024,
) -> Dict[str, Any]:
    """
    Connect to ip:port and capture whatever bytes the service sends first
    (optionally after sending `probe`, for protocols that wait for the
    client to speak first). Protocol-agnostic — this is deliberately just
    "read the first thing said", not a specific protocol parser (those
    live in the protocol-specific functions below).
    """
    result: Dict[str, Any] = {"status": "no_data", "banner": None, "error": None}
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        addr = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
        sock.connect(addr)
        if probe:
            sock.sendall(probe)
        data = sock.recv(max_bytes)
        if data:
            result["status"] = "found"
            result["banner"] = data.decode("utf-8", errors="replace").strip()
    except socket.timeout:
        result["status"] = "no_data"
        result["error"] = "timeout waiting for banner"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()

    if store is not None and result["status"] == "found":
        store.add(make_finding(
            finding_type="banner",
            target=target or ip,
            value={"ip": ip, "port": port, "banner": result["banner"]},
            evidence=[f"TCP connection to {ip}:{port} returned a banner on connect"],
            confidence=CONFIDENCE_HIGH,
            metadata={"ip": ip, "port": port},
        ))
    return result


# ---------------------------------------------------------------------------
# Service detection
# ---------------------------------------------------------------------------

# Deliberately scoped to the ports this module's own protocol-specific
# enumeration cares about (context.md's active_recon list), not a general
# ports database — broader web/app service ID is tech_fingerprint.py's job.
_TCP_SERVICE_SIGNATURES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 25: "smtp", 587: "smtp-submission",
    3306: "mysql", 5432: "postgresql",
}
_UDP_SERVICE_SIGNATURES: Dict[int, str] = {53: "dns", 161: "snmp", 500: "ike", 623: "ipmi-rmcp"}


def _banner_based_service_guess(banner: Optional[str]) -> Optional[str]:
    if not banner:
        return None
    b = banner.strip()
    bl = b.lower()
    if b.startswith("SSH-"):
        return "ssh"
    if bl.startswith("220") and "ftp" in bl:
        return "ftp"
    if bl.startswith("220") and ("smtp" in bl or "esmtp" in bl):
        return "smtp"
    if "mysql" in bl or "mariadb" in bl:
        return "mysql"
    return None


def identify_service(
    ip: str,
    port: int,
    banner: Optional[str] = None,
    protocol: str = "tcp",
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Identify the probable service on ip:port from two independent signals:
    the port number (a weak, LOW-confidence prior) and banner content (a
    strong, HIGH-confidence signal when it matches a known signature).

    If the two signals disagree, that disagreement is preserved and
    surfaced as a conflict (context.md §8 conflict-preservation), not
    silently resolved in favor of one signal.
    """
    port_map = _TCP_SERVICE_SIGNATURES if protocol == "tcp" else _UDP_SERVICE_SIGNATURES
    port_guess = port_map.get(port)
    banner_guess = _banner_based_service_guess(banner)

    conflict = bool(port_guess and banner_guess and port_guess != banner_guess)
    if conflict:
        service = None
        confidence = CONFIDENCE_LOW
        evidence = [
            f"port {port}/{protocol} is commonly associated with {port_guess!r}, "
            f"but the banner matches the {banner_guess!r} signature instead"
        ]
    elif banner_guess:
        service = banner_guess
        confidence = CONFIDENCE_HIGH
        evidence = [f"banner content matched the {banner_guess!r} signature"]
    elif port_guess:
        service = port_guess
        confidence = CONFIDENCE_LOW
        evidence = [f"port {port}/{protocol} is commonly associated with {port_guess!r} (no banner confirmation)"]
    else:
        service = None
        confidence = CONFIDENCE_LOW
        evidence = ["no port-based or banner-based service signature matched"]

    result: Dict[str, Any] = {
        "ip": ip, "port": port, "protocol": protocol,
        "service": service, "port_guess": port_guess, "banner_guess": banner_guess,
        "conflict": conflict, "confidence": confidence,
    }

    if store is not None and (service or conflict):
        store.add(make_finding(
            finding_type="service_conflict" if conflict else "service_identification",
            target=target or ip,
            value={
                "ip": ip, "port": port, "protocol": protocol, "service": service,
                "port_guess": port_guess, "banner_guess": banner_guess,
            },
            evidence=evidence,
            confidence=confidence,
            metadata={"ip": ip, "port": port, "protocol": protocol},
        ))
    return result


# ---------------------------------------------------------------------------
# Shared line-oriented protocol helpers (SMTP/FTP both use CRLF + 3-digit
# response codes)
# ---------------------------------------------------------------------------

def _recv_line(sock: socket.socket, max_bytes: int = 512) -> Optional[str]:
    """
    Read one line of a protocol reply. A timeout is deliberately NOT
    caught here — it propagates to the caller so a target that never
    responds is treated as an incomplete/failed check (status "error",
    not persisted), rather than silently faked into a "checked, negative"
    result built from empty responses.
    """
    data = sock.recv(max_bytes)
    if not data:
        return None
    return data.decode("utf-8", errors="replace").strip()


def _send_line(sock: socket.socket, text: str) -> None:
    sock.sendall((text + "\r\n").encode("utf-8"))


def _parse_response_code(line: Optional[str]) -> Optional[int]:
    if not line or len(line) < 3 or not line[:3].isdigit():
        return None
    return int(line[:3])


# ---------------------------------------------------------------------------
# Protocol-specific enumeration: SMTP VRFY/EXPN
# ---------------------------------------------------------------------------

def smtp_probe(
    ip: str,
    port: int = 25,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 3.0,
    probe_user: str = "root",
) -> Dict[str, Any]:
    """
    Check whether an SMTP server has VRFY/EXPN enabled — a well-known
    information-exposure posture check, not an exploitation or credential
    attack (no authentication is attempted; `probe_user` is a single
    generic placeholder used only to observe the server's protocol
    behavior, not to harvest a real user list).
    """
    result: Dict[str, Any] = {
        "status": "error", "banner": None,
        "vrfy": {"supported": None, "response": None},
        "expn": {"supported": None, "response": None},
        "error": None,
    }
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        result["banner"] = _recv_line(sock)

        _send_line(sock, "EHLO reconhound.local")
        _recv_line(sock)

        _send_line(sock, f"VRFY {probe_user}")
        vrfy_resp = _recv_line(sock)
        result["vrfy"]["response"] = vrfy_resp
        result["vrfy"]["supported"] = _parse_response_code(vrfy_resp) in (250, 251, 252)

        _send_line(sock, f"EXPN {probe_user}")
        expn_resp = _recv_line(sock)
        result["expn"]["response"] = expn_resp
        result["expn"]["supported"] = _parse_response_code(expn_resp) in (250, 251, 252)

        _send_line(sock, "QUIT")
        result["status"] = "checked"
    except socket.timeout:
        result["status"] = "error"
        result["error"] = "timeout during SMTP conversation"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()

    if store is not None and result["status"] == "checked":
        exposed = bool(result["vrfy"]["supported"] or result["expn"]["supported"])
        store.add(make_finding(
            finding_type="smtp_enumeration",
            target=target or ip,
            value={"ip": ip, "port": port, "vrfy": result["vrfy"], "expn": result["expn"]},
            evidence=[
                f"SMTP VRFY response: {result['vrfy']['response']!r}",
                f"SMTP EXPN response: {result['expn']['response']!r}",
            ],
            confidence=CONFIDENCE_HIGH if exposed else CONFIDENCE_LOW,
            metadata={"ip": ip, "port": port, "exposed": exposed},
        ))
    return result


# ---------------------------------------------------------------------------
# Protocol-specific enumeration: SNMP community strings
# ---------------------------------------------------------------------------

# Minimal hand-rolled BER/DER encoder/decoder for a single SNMPv1
# GetRequest/GetResponse exchange targeting sysDescr.0 (1.3.6.1.2.1.1.1.0).
# No external SNMP dependency is added, consistent with the module's
# no-extra-dependency decision.

_SYSDESCR_OID = bytes.fromhex("2b06010201010100")  # 1.3.6.1.2.1.1.1.0


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    encoded = []
    while n:
        encoded.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(encoded)]) + bytes(encoded)


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(n: int) -> bytes:
    if n == 0:
        value = b"\x00"
    else:
        length = max(1, (n.bit_length() + 7) // 8)
        value = n.to_bytes(length, "big")
        if value[0] & 0x80:
            value = b"\x00" + value
    return _ber_tlv(0x02, value)


def _ber_read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first & 0x80:
        n = first & 0x7F
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        length = first
    value = data[offset:offset + length]
    offset += length
    return tag, value, offset


def _snmp_build_get_request(community: str, request_id: int) -> bytes:
    varbind = _ber_tlv(0x30, _ber_tlv(0x06, _SYSDESCR_OID) + _ber_tlv(0x05, b""))
    varbindlist = _ber_tlv(0x30, varbind)
    pdu_body = _ber_int(request_id) + _ber_int(0) + _ber_int(0) + varbindlist
    pdu = _ber_tlv(0xA0, pdu_body)  # GetRequest-PDU
    return _ber_tlv(0x30, _ber_int(0) + _ber_tlv(0x04, community.encode("utf-8")) + pdu)


def _snmp_parse_get_response(data: bytes) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {"error_status": None, "sysdescr": None}
    _, body, _ = _ber_read_tlv(data, 0)
    pos = 0
    _, _, pos = _ber_read_tlv(body, pos)  # version
    _, _, pos = _ber_read_tlv(body, pos)  # community
    pdu_tag, pdu_val, _ = _ber_read_tlv(body, pos)
    if pdu_tag != 0xA2:  # GetResponse-PDU
        return parsed
    p = 0
    _, _, p = _ber_read_tlv(pdu_val, p)  # request-id
    _, err_val, p = _ber_read_tlv(pdu_val, p)  # error-status
    _, _, p = _ber_read_tlv(pdu_val, p)  # error-index
    _, vbl_val, _ = _ber_read_tlv(pdu_val, p)  # variable-bindings
    parsed["error_status"] = int.from_bytes(err_val, "big") if err_val else 0
    if vbl_val:
        _, vb_val, _ = _ber_read_tlv(vbl_val, 0)
        _, _, p2 = _ber_read_tlv(vb_val, 0)  # oid
        val_tag, val_val, _ = _ber_read_tlv(vb_val, p2)
        if val_tag == 0x04:
            parsed["sysdescr"] = val_val.decode("utf-8", errors="replace")
    return parsed


def snmp_community_probe(
    ip: str,
    port: int = 161,
    communities: Optional[List[str]] = None,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Test well-known/default SNMP community strings ("public", "private" by
    default) with a real SNMPv1 GetRequest for sysDescr.0. A community
    string is treated as accepted if the agent replies at all — SNMP
    agents conventionally do not respond to a GetRequest carrying an
    unrecognized community string, so any reply demonstrates the community
    was accepted (this mirrors how established SNMP scanners like
    onesixtyone work).
    """
    communities = communities or list(_DEFAULT_SNMP_COMMUNITIES)
    result: Dict[str, Any] = {
        "status": "checked", "accepted": [], "communities_tried": list(communities), "error": None,
    }
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        for idx, community in enumerate(communities):
            packet = _snmp_build_get_request(community, request_id=idx + 1)
            try:
                sock.sendto(packet, (ip, port))
                data, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            try:
                parsed = _snmp_parse_get_response(data)
            except Exception:
                parsed = {"error_status": None, "sysdescr": None}
            result["accepted"].append({
                "community": community,
                "error_status": parsed.get("error_status"),
                "sysdescr": parsed.get("sysdescr"),
            })
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()

    if store is not None and result["status"] == "checked":
        exposed = bool(result["accepted"])
        if exposed:
            evidence = [
                f"SNMP GetRequest with community {a['community']!r} received a response"
                for a in result["accepted"]
            ]
        else:
            evidence = [f"No SNMP response for community strings: {', '.join(communities)}"]
        store.add(make_finding(
            finding_type="snmp_exposure",
            target=target or ip,
            value={"ip": ip, "port": port, "accepted": result["accepted"], "communities_tried": communities},
            evidence=evidence,
            confidence=CONFIDENCE_HIGH if exposed else CONFIDENCE_LOW,
            metadata={"ip": ip, "port": port, "exposed": exposed},
        ))
    return result


# ---------------------------------------------------------------------------
# Protocol-specific enumeration: FTP anonymous login
# ---------------------------------------------------------------------------

def ftp_anonymous_login_check(
    ip: str,
    port: int = 21,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """
    Check whether the FTP server accepts the standard anonymous-access
    login (USER anonymous / PASS anonymous@) — a protocol-defined public
    access mechanism, not a credential attack against a real account.
    """
    result: Dict[str, Any] = {
        "status": "error", "banner": None, "login_successful": None, "response": None, "error": None,
    }
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        result["banner"] = _recv_line(sock)

        _send_line(sock, "USER anonymous")
        user_resp = _recv_line(sock)
        code = _parse_response_code(user_resp)

        if code == 331:
            _send_line(sock, "PASS anonymous@")
            login_resp = _recv_line(sock)
        else:
            login_resp = user_resp

        result["response"] = login_resp
        result["login_successful"] = _parse_response_code(login_resp) == 230
        _send_line(sock, "QUIT")
        result["status"] = "checked"
    except socket.timeout:
        result["status"] = "error"
        result["error"] = "timeout during FTP conversation"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()

    if store is not None and result["status"] == "checked":
        store.add(make_finding(
            finding_type="ftp_anonymous_access",
            target=target or ip,
            value={"ip": ip, "port": port, "login_successful": result["login_successful"], "banner": result["banner"]},
            evidence=[f"FTP anonymous login attempt response: {result['response']!r}"],
            confidence=CONFIDENCE_HIGH if result["login_successful"] else CONFIDENCE_LOW,
            metadata={"ip": ip, "port": port, "exposed": bool(result["login_successful"])},
        ))
    return result


# ---------------------------------------------------------------------------
# Protocol-specific enumeration: SSH fingerprinting
# ---------------------------------------------------------------------------

_SSH_BANNER_RE = re.compile(r"^SSH-(?P<protoversion>\d+\.\d+)-(?P<software>\S+)(?:\s+(?P<comments>.*))?$")


def ssh_fingerprint(
    ip: str,
    port: int = 22,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """
    Parse the plaintext SSH identification banner (RFC 4253 §4.2) into
    protocol version + software/version string.

    LIMITATION: this does not perform an SSH key exchange, so it cannot
    extract a host-key fingerprint. Doing so would require a full SSH
    client implementation (e.g. paramiko), which conflicts with this
    module's confirmed no-extra-dependency decision. What this function
    calls a "fingerprint" is the server's self-reported identification
    string, evidence-labeled as such (not a cryptographic host-key
    fingerprint).
    """
    result: Dict[str, Any] = {
        "status": "not_found", "banner": None, "protocol_version": None,
        "software": None, "comments": None, "error": None,
    }
    banner_result = grab_banner(ip, port, timeout=timeout)
    if banner_result["status"] == "found" and banner_result["banner"]:
        banner = banner_result["banner"]
        result["banner"] = banner
        result["status"] = "found"
        match = _SSH_BANNER_RE.match(banner)
        if match:
            result["protocol_version"] = match.group("protoversion")
            result["software"] = match.group("software")
            result["comments"] = match.group("comments")
    elif banner_result["status"] == "error":
        result["status"] = "error"
        result["error"] = banner_result["error"]
    else:
        result["status"] = "not_found"
        result["error"] = banner_result["error"]

    if store is not None and result["status"] in ("found", "not_found"):
        if result["status"] == "found":
            confidence = CONFIDENCE_HIGH if result["software"] else CONFIDENCE_MEDIUM
            evidence = [f"TCP connection to {ip}:{port} returned banner: {result['banner']!r}"]
        else:
            confidence = CONFIDENCE_LOW
            evidence = [f"SSH fingerprint check against {ip}:{port} produced no banner: {result['error']}"]
        store.add(make_finding(
            finding_type="ssh_fingerprint",
            target=target or ip,
            value={
                "ip": ip, "port": port, "banner": result["banner"],
                "protocol_version": result["protocol_version"], "software": result["software"],
            },
            evidence=evidence,
            confidence=confidence,
            metadata={
                "ip": ip, "port": port,
                "note": "Limited to the plaintext SSH identification banner; no key-exchange "
                        "performed, so no cryptographic host-key fingerprint is produced.",
            },
        ))
    return result


# ---------------------------------------------------------------------------
# IPMI exposure check (auto CRITICAL per context.md)
# ---------------------------------------------------------------------------

# RMCP Presence Ping (ASF, RFC-less but widely documented / used by
# nmap's ipmi-version and similar tools): no authentication, just a
# presence probe.
_RMCP_PRESENCE_PING = bytes([0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x80, 0x00, 0x00, 0x00])


def check_ipmi_exposure(
    ip: str,
    port: int = 623,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Send an unauthenticated RMCP Presence Ping and check for a Presence
    Pong. This detects exposure only — no IPMI session/authentication is
    attempted. context.md marks IPMI exposure as auto-CRITICAL severity;
    that severity is recorded in this finding's metadata (a single-finding
    annotation, distinct from risk_engine.py's later relationship-based
    scoring, which this module does not implement).
    """
    result: Dict[str, Any] = {"status": "checked", "exposed": False, "raw_response_hex": None, "error": None}
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_RMCP_PRESENCE_PING, (ip, port))
        try:
            data, _ = sock.recvfrom(256)
            if len(data) >= 4 and data[0] == 0x06 and data[3] == 0x06:
                result["exposed"] = True
                result["raw_response_hex"] = data.hex()
        except socket.timeout:
            result["exposed"] = False
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()

    if store is not None and result["status"] == "checked":
        metadata = {"ip": ip, "port": port}
        if result["exposed"]:
            evidence = [f"RMCP Presence Pong received from {ip}:{port}/udp confirming IPMI exposure"]
            confidence = CONFIDENCE_HIGH
            metadata["severity"] = "CRITICAL"
        else:
            evidence = [f"No RMCP Presence Pong received from {ip}:{port}/udp within {timeout}s"]
            confidence = CONFIDENCE_LOW
        store.add(make_finding(
            finding_type="ipmi_exposure",
            target=target or ip,
            value={"ip": ip, "port": port, "exposed": result["exposed"]},
            evidence=evidence,
            confidence=confidence,
            metadata=metadata,
        ))
    return result


# ---------------------------------------------------------------------------
# Database exposure check (auto CRITICAL per context.md)
# ---------------------------------------------------------------------------

def check_database_exposure(
    ip: str,
    ports: Optional[List[int]] = None,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Check whether well-known database ports (3306/5432 by default) are
    directly reachable. Reachability of a raw DB port from the scanning
    host is itself the exposure context.md calls out — no authentication
    or query is attempted against the database. context.md marks this
    auto-CRITICAL; recorded as a metadata severity annotation (see
    check_ipmi_exposure's docstring for why this isn't risk_engine.py
    scoring).
    """
    ports = ports or sorted(_DB_PORT_SERVICE)
    result: Dict[str, Any] = {"status": "checked", "exposed_ports": [], "details": {}, "error": None}

    for port in ports:
        entry: Dict[str, Any] = {
            "port": port, "service": _DB_PORT_SERVICE.get(port, "unknown"),
            "open": False, "banner": None,
        }
        scan_entry = _scan_one_tcp_port(ip, port, timeout)
        if scan_entry["status"] == "open":
            entry["open"] = True
            banner_result = grab_banner(ip, port, timeout=timeout)
            if banner_result["status"] == "found":
                entry["banner"] = banner_result["banner"]
            result["exposed_ports"].append(port)
        result["details"][str(port)] = entry

    if store is not None and result["status"] == "checked":
        exposed = bool(result["exposed_ports"])
        metadata = {"ip": ip, "ports_checked": ports}
        if exposed:
            evidence = [
                f"TCP port {p} ({_DB_PORT_SERVICE.get(p, 'unknown')}) reachable on {ip}"
                for p in result["exposed_ports"]
            ]
            confidence = CONFIDENCE_HIGH
            metadata["severity"] = "CRITICAL"
        else:
            evidence = [f"No database ports ({', '.join(str(p) for p in ports)}) reachable on {ip}"]
            confidence = CONFIDENCE_LOW
        store.add(make_finding(
            finding_type="db_exposure",
            target=target or ip,
            value={"ip": ip, "exposed_ports": result["exposed_ports"], "details": result["details"]},
            evidence=evidence,
            confidence=confidence,
            metadata=metadata,
        ))
    return result


# ---------------------------------------------------------------------------
# OS fingerprinting (TTL only — see module docstring for why TCP-window
# fingerprinting is not implemented)
# ---------------------------------------------------------------------------

_TTL_BASELINES: List[Tuple[int, str]] = [
    (64, "Linux/Unix-like (initial TTL <= 64)"),
    (128, "Windows (initial TTL <= 128)"),
    (255, "Network device/Solaris/other (initial TTL <= 255)"),
]


def _guess_os_from_ttl(ttl: int) -> Optional[str]:
    for baseline, label in _TTL_BASELINES:
        if ttl <= baseline:
            return label
    return None


def fingerprint_os_ttl(
    ip: str,
    port: int,
    probe: bytes = b"",
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Best-effort OS hint from the IP TTL of a UDP response, using the
    IP_RECVTTL ancillary-data mechanism (Linux, standard sockets, no
    root/raw-socket privilege required).

    UDP is used rather than TCP because this was verified empirically
    during implementation: Linux does not attach per-packet IP_TTL
    ancillary data to a TCP stream socket's recvmsg() (confirmed via a
    local test — ancdata came back empty every time), only to datagram
    sockets, where it works reliably (also confirmed via a local test).

    `port`/`probe` should target something known/likely to reply within
    `timeout` (e.g. a UDP port where snmp_community_probe or
    check_ipmi_exposure already observed a response) — this function
    cannot produce a result if the target never sends a UDP response.

    LIMITATION: TCP-window-based OS fingerprinting (as used by tools like
    p0f) additionally requires inspecting the raw TCP header of the peer's
    SYN-ACK via packet capture (raw socket / scapy), which this module's
    confirmed no-raw-socket decision rules out. This function is
    deliberately TTL-only.
    """
    result: Dict[str, Any] = {"status": "not_found", "ttl": None, "os_guess": None, "error": None}

    if not sys.platform.startswith("linux"):
        result["status"] = "unsupported"
        result["error"] = "TTL-based OS fingerprinting is only implemented for Linux"
        return result

    ip_recvttl = getattr(socket, "IP_RECVTTL", 12)  # 12 is IP_RECVTTL on Linux (linux/in.h)

    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, ip_recvttl, 1)
        sock.connect((ip, port))
        sock.send(probe)
        _, ancdata, _, _ = sock.recvmsg(2048, socket.CMSG_SPACE(4))
        for level, cmsg_type, cmsg_data in ancdata:
            if level == socket.IPPROTO_IP and cmsg_type == socket.IP_TTL:
                if len(cmsg_data) >= 4:
                    result["ttl"] = int.from_bytes(cmsg_data[:4], sys.byteorder)
                elif len(cmsg_data) == 1:
                    result["ttl"] = cmsg_data[0]
        if result["ttl"] is not None:
            result["status"] = "found"
            result["os_guess"] = _guess_os_from_ttl(result["ttl"])
        else:
            result["status"] = "not_found"
            result["error"] = "response received but no IP_TTL ancillary data was attached"
    except socket.timeout:
        result["status"] = "not_found"
        result["error"] = "no UDP response received within timeout to sample TTL from"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()

    if store is not None and result["status"] == "found":
        store.add(make_finding(
            finding_type="os_fingerprint",
            target=target or ip,
            value={"ip": ip, "ttl": result["ttl"], "os_guess": result["os_guess"]},
            evidence=[f"Inbound IP TTL from {ip}:{port}/udp observed as {result['ttl']}"],
            confidence=CONFIDENCE_LOW,
            metadata={
                "ip": ip, "port": port, "method": "ttl_only_udp",
                "note": "TCP-window-based fingerprinting not implemented (requires raw packet capture).",
            },
        ))
    return result


# ---------------------------------------------------------------------------
# Cross-host pattern detection
# ---------------------------------------------------------------------------

# Baseline of very common ports; anything outside this set is treated as
# "unusual" for pattern-detection purposes.
_DEFAULT_COMMON_PORTS = frozenset({
    20, 21, 22, 23, 25, 37, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 464, 465, 500,
    514, 515, 520, 523, 546, 547, 587, 623, 631, 636, 873, 902, 989, 990, 993,
    995, 1080, 1194, 1433, 1434, 1521, 1723, 1900, 2049, 2082, 2083, 2181,
    2375, 2376, 3128, 3268, 3269, 3306, 3389, 3690, 4369, 5000, 5060, 5061,
    5432, 5601, 5672, 5900, 5985, 5986, 6379, 6443, 6660, 6666, 6667, 6697,
    7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9042, 9092, 9200, 9300,
    11211, 15672, 20000, 27017, 27018, 50000,
})


def detect_cross_host_port_pattern(
    host_scan_results: List[Dict[str, Any]],
    common_ports: Optional[set] = None,
    min_hosts: int = 2,
    store: Optional[PendingAssetsStore] = None,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Given a list of {"ip": ..., "open_ports": [...]} summaries — the shape
    returned by tcp_connect_scan/ipv6_tcp_connect_scan/udp_scan — identify
    ports outside the common-ports baseline that are open across at least
    `min_hosts` distinct hosts: a signal of an organization-wide
    configuration pattern (e.g. a non-standard management port deployed
    fleet-wide) rather than coincidence.

    This operates only on already-collected results from this module's own
    scan functions; it does not query surface_mapper.py's asset graph
    (module 6 is not implemented yet) and is not itself a general
    correlation engine.
    """
    common_ports = common_ports if common_ports is not None else _DEFAULT_COMMON_PORTS
    port_to_ips: Dict[int, List[str]] = {}

    for entry in host_scan_results:
        ip = entry.get("ip")
        if not ip:
            continue
        for port in entry.get("open_ports", []):
            if port in common_ports:
                continue
            ips = port_to_ips.setdefault(port, [])
            if ip not in ips:
                ips.append(ip)

    patterns = {port: sorted(ips) for port, ips in port_to_ips.items() if len(ips) >= min_hosts}

    if store is not None:
        for port, ips in patterns.items():
            store.add(make_finding(
                finding_type="cross_host_port_pattern",
                target=target or "multiple_hosts",
                value={"port": port, "hosts": ips, "host_count": len(ips)},
                evidence=[f"Unusual port {port} is open on {len(ips)} distinct hosts: {', '.join(ips)}"],
                confidence=CONFIDENCE_MEDIUM,
                metadata={"port": port, "host_count": len(ips)},
            ))

    return {"patterns": {str(p): ips for p, ips in patterns.items()}, "min_hosts": min_hosts}


# ---------------------------------------------------------------------------
# Module orchestration (single host)
# ---------------------------------------------------------------------------

def run_active_recon(
    ip: str,
    target: Optional[str] = None,
    tcp_ports: Optional[List[int]] = None,
    udp_ports: Optional[List[int]] = None,
    output_dir: str = "output",
    timeout: float = 2.0,
    max_workers: int = 20,
    snmp_communities: Optional[List[str]] = None,
    smtp_probe_user: str = "root",
    check_db_exposure_enabled: bool = True,
    check_ipmi_enabled: bool = True,
    fingerprint_os_enabled: bool = True,
) -> Dict[str, Any]:
    """
    Run Module 2's active-recon checks against a single IPv4 host and
    persist every discovery immediately to <output_dir>/pending_assets.json.

    TCP scanning only runs if `tcp_ports` is supplied (no invented default,
    per this module's TCP-port decision); UDP scanning always runs, using
    context.md's default port list unless `udp_ports` overrides it. Follow-
    on protocol checks (FTP/SSH/SMTP) only run against ports confirmed
    open by the TCP scan; IPMI/DB-exposure checks always run (they target
    fixed, context.md-specified ports); the OS TTL fingerprint only runs if
    a UDP port already confirmed to respond (SNMP or IPMI) is available to
    sample from.

    Returns a structured summary of everything discovered in this run, in
    addition to (not instead of) the crash-safe persisted store. IPv6 hosts
    and cross-host pattern detection are out of scope for this
    orchestrator — call ipv6_tcp_connect_scan / detect_cross_host_port_pattern
    directly for those.
    """
    ip = validate_scan_target(ip)
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "ip": ip,
        "target": target or ip,
        "module": MODULE_NAME,
        "started_at": _now(),
        "tcp": {},
        "udp": {},
        "banners": {},
        "services": {},
        "smtp": None,
        "snmp": None,
        "ftp": None,
        "ssh": None,
        "ipmi": None,
        "db_exposure": None,
        "os_fingerprint": None,
        "errors": [],
    }

    open_tcp_ports: List[int] = []
    if tcp_ports:
        try:
            summary["tcp"] = tcp_connect_scan(
                ip, tcp_ports, store=store, target=target, timeout=timeout, max_workers=max_workers,
            )
            open_tcp_ports = summary["tcp"].get("open_ports", [])
        except Exception as exc:
            summary["errors"].append({"stage": "tcp_scan", "error": str(exc)})

    for port in open_tcp_ports:
        try:
            banner_result = grab_banner(ip, port, store=store, target=target, timeout=timeout)
            summary["banners"][str(port)] = banner_result
            summary["services"][str(port)] = identify_service(
                ip, port, banner=banner_result.get("banner"), protocol="tcp",
                store=store, target=target,
            )
        except Exception as exc:
            summary["errors"].append({"stage": "banner_service", "port": port, "error": str(exc)})

    if 21 in open_tcp_ports:
        try:
            summary["ftp"] = ftp_anonymous_login_check(ip, store=store, target=target, timeout=timeout)
        except Exception as exc:
            summary["errors"].append({"stage": "ftp", "error": str(exc)})

    if 22 in open_tcp_ports:
        try:
            summary["ssh"] = ssh_fingerprint(ip, store=store, target=target, timeout=timeout)
        except Exception as exc:
            summary["errors"].append({"stage": "ssh", "error": str(exc)})

    smtp_ports = [p for p in (25, 587) if p in open_tcp_ports]
    if smtp_ports:
        try:
            summary["smtp"] = smtp_probe(
                ip, port=smtp_ports[0], store=store, target=target, timeout=timeout,
                probe_user=smtp_probe_user,
            )
        except Exception as exc:
            summary["errors"].append({"stage": "smtp", "error": str(exc)})

    udp_ports = udp_ports if udp_ports is not None else list(DEFAULT_UDP_PORTS)
    try:
        summary["udp"] = udp_scan(ip, udp_ports, store=store, target=target, timeout=timeout, max_workers=max_workers)
    except Exception as exc:
        summary["errors"].append({"stage": "udp_scan", "error": str(exc)})

    if 161 in udp_ports:
        try:
            summary["snmp"] = snmp_community_probe(
                ip, store=store, target=target, timeout=timeout, communities=snmp_communities,
            )
        except Exception as exc:
            summary["errors"].append({"stage": "snmp", "error": str(exc)})

    if check_ipmi_enabled:
        try:
            summary["ipmi"] = check_ipmi_exposure(ip, store=store, target=target, timeout=timeout)
        except Exception as exc:
            summary["errors"].append({"stage": "ipmi", "error": str(exc)})

    if check_db_exposure_enabled:
        try:
            summary["db_exposure"] = check_database_exposure(ip, store=store, target=target, timeout=timeout)
        except Exception as exc:
            summary["errors"].append({"stage": "db_exposure", "error": str(exc)})

    if fingerprint_os_enabled:
        os_port = None
        os_probe = b""
        if summary["snmp"] and summary["snmp"].get("accepted"):
            os_port = 161
            os_probe = _snmp_build_get_request(summary["snmp"]["accepted"][0]["community"], request_id=999)
        elif summary["ipmi"] and summary["ipmi"].get("exposed"):
            os_port = 623
            os_probe = _RMCP_PRESENCE_PING
        if os_port:
            try:
                summary["os_fingerprint"] = fingerprint_os_ttl(
                    ip, os_port, probe=os_probe, store=store, target=target, timeout=timeout,
                )
            except Exception as exc:
                summary["errors"].append({"stage": "os_fingerprint", "error": str(exc)})

    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _parse_ports(raw: Optional[str]) -> Optional[List[int]]:
    if not raw:
        return None
    ports: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        ports.append(int(part))
    return ports


def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="active_recon.py",
        description="ReconHound Module 2 — active network reconnaissance (standalone test entry point).",
    )
    parser.add_argument("--ip", required=True, help="Target IPv4 address, e.g. 93.184.216.34")
    parser.add_argument("--tcp-ports", default=None, help="Comma-separated TCP ports, e.g. 21,22,25,80")
    parser.add_argument("--udp-ports", default=None, help="Comma-separated UDP ports (default: 53,161,500,623)")
    parser.add_argument("--target", default=None, help="Logical target domain to tag findings with")
    parser.add_argument("--output-dir", default="output", help="Directory for pending_assets.json")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe network timeout (seconds)")
    parser.add_argument("--no-ipmi", action="store_true", help="Skip the IPMI exposure check")
    parser.add_argument("--no-db-exposure", action="store_true", help="Skip the DB exposure check")
    parser.add_argument("--no-os-fingerprint", action="store_true", help="Skip OS TTL fingerprinting")
    args = parser.parse_args()

    try:
        result = run_active_recon(
            args.ip,
            target=args.target,
            tcp_ports=_parse_ports(args.tcp_ports),
            udp_ports=_parse_ports(args.udp_ports),
            output_dir=args.output_dir,
            timeout=args.timeout,
            check_ipmi_enabled=not args.no_ipmi,
            check_db_exposure_enabled=not args.no_db_exposure,
            fingerprint_os_enabled=not args.no_os_fingerprint,
        )
    except ScopeError as exc:
        print(f"[scope error] {exc}")
        raise SystemExit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
