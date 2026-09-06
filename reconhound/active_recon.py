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

Result semantics (context.md §8) — added by the Module 2 forensic audit:

  - FAILURE IS NOT ABSENCE. Port results distinguish "open"/"closed" (the
    peer answered) from "filtered" (silence), "unreachable" (the host or
    network could not be reached), "permission_denied" (the local system
    blocked the probe) and "error". Only "open" and "closed" assert anything
    about the port itself; everything else means the port's state was not
    established. connect_ex() reports these as errno return values rather
    than exceptions, so they are classified from the errno.
  - PARTIAL IS NOT EMPTY. Scan summaries carry `complete`,
    `not_conclusive_ports` and `failed_ports`; run_active_recon() carries a
    `status` ("completed" / "completed_with_errors" / "interrupted") and a
    per-stage `stages` map recording completed / inconclusive / failed /
    skipped / not_reached with a reason. A run in which nothing could be
    tested is therefore never shape-identical to one that tested everything
    and found nothing.
  - CORRELATED REPLIES ONLY. The UDP-based checks (SNMP community strings,
    IPMI presence) validate that a datagram came from the address that was
    probed, and SNMP additionally requires a well-formed GetResponse whose
    request-id matches the request just sent. An unconnected UDP socket
    accepts datagrams from anyone, and probes sharing one socket can
    otherwise credit a slow reply to the wrong community string.
  - DISCOVERIES SURVIVE A CTRL-C. Findings are persisted as they are
    established, not after the whole scan; an interrupt persists what has
    already been observed (including probes that finished but were not yet
    collected) and then re-raises, because core/orchestrator.py relies on
    KeyboardInterrupt propagating. ActiveReconInterrupted subclasses
    KeyboardInterrupt so that contract still holds while carrying the
    partial summary.
  - BOUNDED RESOURCES. Concurrency is capped at MAX_WORKERS_CAP threads
    regardless of the caller's `max_workers`, and never exceeds the number
    of ports. Persistence uses one batched read+write per scan rather than
    one per finding, which was quadratic in the size of the shared
    pending_assets.json.
  - ATTACKER-CONTROLLED TEXT IS SANITIZED. Banners and SMTP/FTP reply lines
    have control characters stripped before they are stored or displayed
    (the raw bytes are kept as `banner_hex`), because that text reaches the
    operator's terminal and the HTML report.

Output feeds surface_mapper.py (module 6) — this module does not implement
or call into surface_mapper, risk_engine, or any other later module.

KNOWN LIMITATIONS retained deliberately (not defects):

  - TCP scanning is connect()-based. SYN/FIN/XMAS/NULL scanning requires
    raw sockets and root/CAP_NET_RAW, which decision #1 above rules out.
    ReconHound is an authorized-reconnaissance framework, not an evasion
    framework, so no stealth/decoy/fragmentation techniques are offered.
  - UDP "open_filtered" is irreducible without raw ICMP visibility. A
    connected UDP socket surfaces only ICMP port-unreachable (as
    ConnectionRefusedError); every other ICMP condition, and any ICMP the
    network drops, is invisible. Silence is therefore never reported as
    "open".
  - Retries are not performed. A single lost UDP datagram is reported as
    ambiguous rather than retried, which keeps traffic bounded and
    predictable; retry policy is an orchestration concern.
  - Service identification reports a port-number prior at LOW confidence
    and a matched greeting at HIGH confidence, and preserves genuine
    disagreement between the two as a conflict rather than resolving it.
    A port number alone is never treated as a confirmed service.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
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

# ---------------------------------------------------------------------------
# Port-probe result vocabulary (context.md §8: a failure is not a negative
# result). These statuses deliberately keep "the peer told us the port is
# shut" separate from "we never learned anything about this port", so that
# nothing downstream can read a network/permission failure as a confirmed
# closed port.
# ---------------------------------------------------------------------------

PORT_OPEN = "open"                       # handshake completed
PORT_CLOSED = "closed"                   # peer actively refused/reset: a real answer
PORT_FILTERED = "filtered"               # silence within the timeout
PORT_UNREACHABLE = "unreachable"         # host/net unreachable: nothing learned about the port
PORT_PERMISSION_DENIED = "permission_denied"  # local policy blocked the probe
PORT_ERROR = "error"                     # could not be completed for an unrelated reason

# UDP-only status. UDP silence is fundamentally ambiguous: an open port that
# simply does not answer this probe is indistinguishable from a filtered one.
UDP_OPEN_FILTERED = "open_filtered"

# Statuses that represent a genuine observation of the port's state. Anything
# outside this set means the port's state was not established.
_CONCLUSIVE_PORT_STATUSES = frozenset({PORT_OPEN, PORT_CLOSED})

# Statuses meaning the probe itself never completed, so nothing at all was
# learned. This is a narrower set than "not conclusive": silence ("filtered",
# and UDP's "open_filtered") is an ambiguous *observation* — the probe ran and
# the target said nothing — whereas an unreachable network or a locally
# blocked socket means the check did not happen. Collapsing the two would
# report a firewalled-but-reachable host as a failed scan.
_PROBE_FAILURE_STATUSES = frozenset({PORT_UNREACHABLE, PORT_PERMISSION_DENIED, PORT_ERROR})

# errno -> status. connect_ex() reports the failure reason as an errno instead
# of raising, so without this mapping every non-zero return collapses into
# "closed" — turning an unreachable network or a blocked probe into a
# confirmed-shut port. Only a refusal or a reset is an answer from the peer.
_ERRNO_PORT_STATUS: Dict[int, str] = {
    errno.ECONNREFUSED: PORT_CLOSED,
    errno.ECONNRESET: PORT_CLOSED,
    errno.ETIMEDOUT: PORT_FILTERED,
    errno.EAGAIN: PORT_FILTERED,
    errno.EWOULDBLOCK: PORT_FILTERED,
    errno.EINPROGRESS: PORT_FILTERED,
    errno.EALREADY: PORT_FILTERED,
    errno.EHOSTUNREACH: PORT_UNREACHABLE,
    errno.ENETUNREACH: PORT_UNREACHABLE,
    errno.EHOSTDOWN: PORT_UNREACHABLE,
    errno.ENETDOWN: PORT_UNREACHABLE,
    errno.ENETRESET: PORT_UNREACHABLE,
    errno.EACCES: PORT_PERMISSION_DENIED,
    errno.EPERM: PORT_PERMISSION_DENIED,
}

# Upper bound on concurrent probe threads, regardless of what a caller asks
# for. Each worker holds a socket and an OS thread; an unbounded max_workers
# lets one call create thousands of both (measured: max_workers=2000 produced
# ~900 live threads). Reconnaissance is network-bound, so raising concurrency
# past this buys nothing while risking file-descriptor and thread exhaustion.
MAX_WORKERS_CAP = 100

# Valid TCP/UDP port range. Port 0 is excluded deliberately: it is not an
# addressable service port, and connect() to it does not test a real service.
MIN_PORT = 1
MAX_PORT = 65535

# run_active_recon outcome vocabulary. A run that failed everywhere must not
# be shape-identical to a clean run that genuinely found nothing
# (context.md §8: a failure is not a negative result).
RUN_COMPLETED = "completed"
RUN_COMPLETED_WITH_ERRORS = "completed_with_errors"
RUN_INTERRUPTED = "interrupted"

# Per-stage outcome vocabulary used by run_active_recon()["stages"].
STAGE_COMPLETED = "completed"
STAGE_FAILED = "failed"
STAGE_SKIPPED = "skipped"
STAGE_NOT_REACHED = "not_reached"
STAGE_INTERRUPTED_MARK = "interrupted"
# A stage that ran to completion without establishing anything. Distinct from
# STAGE_COMPLETED, because the probe helpers deliberately absorb network
# failures into their result payloads instead of raising: without this, a host
# that was completely unreachable produced a stage map reading "completed"
# everywhere and a run status of "completed", which is precisely the
# "partial scan presented as a complete empty scan" this module must avoid.
STAGE_INCONCLUSIVE = "inconclusive"

# The fixed stages run_active_recon() always accounts for. Per-port
# banner/service stages are added dynamically and are not listed here.
_ALL_STAGE_NAMES: Tuple[str, ...] = (
    "tcp_scan", "ftp", "ssh", "smtp", "udp_scan", "snmp",
    "ipmi", "db_exposure", "os_fingerprint",
)


class ScopeError(ValueError):
    """Raised when a scan target falls outside this function's authorized/supported scope."""


class PersistenceError(RuntimeError):
    """Raised when output/pending_assets.json cannot be safely read or written."""


class ActiveReconInterrupted(KeyboardInterrupt):
    """
    A scan stopped by KeyboardInterrupt, carrying the partial summary.

    Subclasses KeyboardInterrupt deliberately: core/orchestrator.py catches
    KeyboardInterrupt to mark the run interrupted and re-raise it, so this
    must still satisfy `except KeyboardInterrupt` everywhere it already does.
    The `summary` attribute is purely additive, for callers that want the
    partial results. Every discovery made before the interrupt is already on
    disk in pending_assets.json regardless of whether a caller reads it.
    """

    def __init__(self, summary: Dict[str, Any]):
        super().__init__("active recon interrupted")
        self.summary = summary


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


def normalize_ports(ports: Any, what: str = "ports") -> List[int]:
    """
    Validate and normalize a caller-supplied port list.

    Returns the ports de-duplicated and sorted. Rejects anything that is not a
    real port number rather than passing it down to the socket layer, where a
    str/float/None raises an uncaught TypeError out of the probe helpers and a
    value like 0 or 99999 either silently probes nothing useful or is reported
    with a status it never actually earned.

    De-duplication matters beyond tidiness: a repeated port would otherwise be
    scanned once per occurrence and persisted once per occurrence, inflating
    both the traffic sent to the target and the evidence recorded about it.
    """
    if isinstance(ports, (str, bytes)) or not isinstance(ports, (list, tuple, set, frozenset)):
        raise ValueError(f"`{what}` must be a list of integer port numbers, not {type(ports).__name__}.")

    normalized: List[int] = []
    for raw in ports:
        # bool is an int subclass; True would silently become port 1.
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ValueError(f"`{what}` contains a non-integer port: {raw!r}")
        if not (MIN_PORT <= raw <= MAX_PORT):
            raise ValueError(
                f"`{what}` contains {raw!r}, outside the valid port range {MIN_PORT}-{MAX_PORT}."
            )
        if raw not in normalized:
            normalized.append(raw)

    if not normalized:
        raise ValueError(f"`{what}` must be a non-empty list of port numbers to scan.")
    return sorted(normalized)


def _bounded_workers(max_workers: Any, work_items: int) -> int:
    """
    Clamp a caller's requested worker count to something the host can sustain.

    Never more threads than there is work to do, never more than
    MAX_WORKERS_CAP, never fewer than one.
    """
    try:
        requested = int(max_workers)
    except (TypeError, ValueError):
        requested = 1
    return max(1, min(requested, MAX_WORKERS_CAP, max(1, work_items)))


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

    def add_many(self, findings: List[Dict[str, Any]]) -> int:
        """
        Append a batch of findings in ONE read + ONE atomic write.

        add() re-reads and rewrites the entire file per finding, which is
        correct but quadratic in the number of records already on disk. That
        cost is invisible for a handful of findings and severe for a port
        scan: pending_assets.json is shared with every other module, so by the
        time active_recon runs it already holds the passive phase's records,
        and each open port then rewrites that whole file again. Measured on
        this repository: 100 findings 0.11s, 400 findings 1.90s, 800 findings
        5.48s — roughly 3x the cost for 2x the input.

        Crash-safety is unchanged and arguably stronger: the write is still a
        single write-to-temp + os.replace, so a crash mid-batch leaves the
        previous complete file intact and the batch is all-or-nothing rather
        than half-applied. Returns the number of findings written.
        """
        if not findings:
            return 0
        with self._lock:
            records = self._read_all()
            records.extend(findings)
            self._atomic_write(records)
        return len(findings)

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
        Mirrors passive_recon.py's store, which shares this output file.
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


def _safe_store_add_many(store: Optional["PendingAssetsStore"],
                         findings: List[Dict[str, Any]]) -> Optional[str]:
    """
    store.add_many() wrapped so one persistence failure cannot discard the
    in-memory results of a completed scan. Returns None on success, or an
    error string to be surfaced in the caller's result (context.md §12.11: no
    silent failures).
    """
    if store is None or not findings:
        return None
    try:
        store.add_many(findings)
        return None
    except (PersistenceError, OSError) as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# TCP connect() scanning (IPv4 + IPv6)
# ---------------------------------------------------------------------------

def _scan_one_tcp_port(
    ip: str, port: int, timeout: float, family: int = socket.AF_INET
) -> Dict[str, Any]:
    """
    Attempt a single TCP connect() to ip:port.

    status is one of:
      "open"              - the TCP handshake completed.
      "closed"            - the peer actively refused or reset the connection.
                            This is an answer from the target, and the only
                            non-open status that asserts anything about the
                            port itself.
      "filtered"          - no usable response within `timeout` (consistent
                            with a firewall silently dropping the packet).
      "unreachable"       - the host or network could not be reached, so
                            nothing at all was learned about this port.
      "permission_denied" - the local system refused to send the probe.
      "error"             - the attempt could not be completed for a reason
                            unrelated to the port's state.

    connect_ex() reports failures as an errno return value rather than an
    exception, so the errno is what distinguishes "the peer said no" from
    "the packet never got there". Treating every non-zero return as "closed"
    would record an unreachable network as a confirmed-shut port; the
    `_ERRNO_PORT_STATUS` mapping is what prevents that (context.md §8).
    """
    entry: Dict[str, Any] = {"port": port, "status": PORT_ERROR, "error": None}
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        addr = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
        result = sock.connect_ex(addr)
        if result == 0:
            entry["status"] = PORT_OPEN
        else:
            entry["status"] = _ERRNO_PORT_STATUS.get(result, PORT_ERROR)
            entry["error"] = f"{errno.errorcode.get(result, result)}: {os.strerror(result)}"
    except socket.timeout:
        entry["status"] = PORT_FILTERED
        entry["error"] = "timeout"
    except OverflowError as exc:
        entry["status"] = PORT_ERROR
        entry["error"] = f"invalid port number: {exc}"
    except OSError as exc:
        # An errno-bearing OSError carries the same distinction as the
        # connect_ex return value; a bare OSError stays an unclassified error.
        entry["status"] = _ERRNO_PORT_STATUS.get(exc.errno, PORT_ERROR) if exc.errno else PORT_ERROR
        entry["error"] = str(exc)
    except (TypeError, ValueError) as exc:
        # Reachable only when a caller bypasses normalize_ports() and hands a
        # probe helper a non-integer port directly.
        entry["status"] = PORT_ERROR
        entry["error"] = f"invalid port value {port!r}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return entry


def _run_port_probes(
    probe_one: Any,
    ports: List[int],
    max_workers: int,
    sink: List[Dict[str, Any]],
    error_entry: Any,
) -> None:
    """
    Run `probe_one(port)` across `ports` with bounded concurrency, appending
    each result into the caller-owned `sink` list.

    `sink` is caller-owned on purpose. If the scan is interrupted, the caller
    still holds every result collected before the interrupt and can persist
    those discoveries before the KeyboardInterrupt continues on its way —
    which is what stops a Ctrl-C from throwing away confirmed open ports
    (context.md §12.1: discoveries are written immediately, not at the end).

    KeyboardInterrupt is deliberately re-raised rather than swallowed:
    core/orchestrator.py records the interrupt and re-raises it to stop the
    run, so absorbing it here would break that contract. Pending futures are
    cancelled first so an interrupted scan stops issuing new probes instead of
    draining the whole queue.
    """
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=_bounded_workers(max_workers, len(ports))
    )
    interrupted = False
    drained: set = set()
    try:
        future_to_port = {executor.submit(probe_one, port): port for port in ports}
        try:
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                drained.add(future)
                try:
                    sink.append(future.result())
                except Exception as exc:  # probe helpers already carry their own errors
                    sink.append(error_entry(port, exc))
        except KeyboardInterrupt:
            interrupted = True
            # as_completed() yields in completion order, so at the moment of
            # the interrupt there are usually probes that already finished but
            # were never yielded. Harvest those before unwinding: they are
            # completed observations, and discarding them would throw away
            # confirmed open ports the scan had genuinely established.
            for pending, port in future_to_port.items():
                if pending in drained:
                    continue
                if pending.done() and not pending.cancelled():
                    try:
                        if pending.exception() is None:
                            sink.append(pending.result())
                    except BaseException:
                        pass  # nothing usable from this probe; keep unwinding
                else:
                    pending.cancel()
            raise
    finally:
        # On interrupt, don't block the exit waiting for in-flight probes to
        # time out; a plain shutdown() would wait for every running worker.
        executor.shutdown(wait=not interrupted, cancel_futures=True)


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

    The returned summary reports coverage explicitly: `complete` says whether
    every requested port was actually tested, and `not_conclusive_ports`
    lists ports whose state was never established (filtered/unreachable/
    permission-denied/error). A port missing from `open_ports` therefore
    never has to be read as "confirmed closed".
    """
    ip = validate_scan_target(ip)
    ports = normalize_ports(ports)

    results: List[Dict[str, Any]] = []
    try:
        _run_port_probes(
            lambda port: _scan_one_tcp_port(ip, port, timeout),
            ports, max_workers, results,
            lambda port, exc: {"port": port, "status": PORT_ERROR, "error": str(exc)},
        )
    except KeyboardInterrupt:
        _persist_open_tcp_ports(results, store, ip, target, ip_version=4)
        raise
    return _summarize_tcp_scan(results, store, ip, ports, target, ip_version=4)


def _persist_open_tcp_ports(
    results: List[Dict[str, Any]],
    store: Optional[PendingAssetsStore],
    ip: str,
    target: Optional[str],
    ip_version: int,
) -> Optional[str]:
    """Persist the open ports among `results` in a single batched write."""
    if store is None:
        return None
    host_repr = ip if ip_version == 4 else f"[{ip}]"
    findings = [
        make_finding(
            finding_type="open_tcp_port",
            target=target or ip,
            value={"ip": ip, "port": r["port"], "protocol": "tcp"},
            evidence=[f"TCP connect() handshake to {host_repr}:{r['port']} succeeded"],
            confidence=CONFIDENCE_HIGH,
            metadata={"ip": ip, "port": r["port"], "protocol": "tcp", "ip_version": ip_version},
        )
        for r in results if r["status"] == PORT_OPEN
    ]
    return _safe_store_add_many(store, findings)


def _summarize_tcp_scan(
    results: List[Dict[str, Any]],
    store: Optional[PendingAssetsStore],
    ip: str,
    ports: List[int],
    target: Optional[str],
    ip_version: int,
) -> Dict[str, Any]:
    results.sort(key=lambda r: (r["port"], r["status"]))
    open_ports = sorted({r["port"] for r in results if r["status"] == PORT_OPEN})
    closed_ports = sorted({r["port"] for r in results if r["status"] == PORT_CLOSED})
    inconclusive = sorted({
        r["port"] for r in results if r["status"] not in _CONCLUSIVE_PORT_STATUSES
    })
    failed = sorted({r["port"] for r in results if r["status"] in _PROBE_FAILURE_STATUSES})
    persist_error = _persist_open_tcp_ports(results, store, ip, target, ip_version)

    summary: Dict[str, Any] = {
        "ip": ip,
        "protocol": "tcp",
        "ip_version": ip_version,
        "ports_scanned": list(ports),
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "not_conclusive_ports": inconclusive,
        "failed_ports": failed,
        "ports_tested": len(results),
        "complete": len(results) == len(ports),
        "results": results,
    }
    if persist_error:
        summary["persistence_error"] = persist_error
    return summary


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
    ports = normalize_ports(ports)

    results: List[Dict[str, Any]] = []
    try:
        _run_port_probes(
            lambda port: _scan_one_tcp_port(ip, port, timeout, socket.AF_INET6),
            ports, max_workers, results,
            lambda port, exc: {"port": port, "status": PORT_ERROR, "error": str(exc)},
        )
    except KeyboardInterrupt:
        _persist_open_tcp_ports(results, store, ip, target, ip_version=6)
        raise
    return _summarize_tcp_scan(results, store, ip, ports, target, ip_version=6)


# ---------------------------------------------------------------------------
# UDP scanning
# ---------------------------------------------------------------------------

def _scan_one_udp_port(ip: str, port: int, timeout: float, probe: bytes = b"") -> Dict[str, Any]:
    """
    Attempt a single UDP probe to ip:port using a connected UDP socket (so
    an ICMP port-unreachable response surfaces as ConnectionRefusedError —
    standard technique, no raw sockets required).

    status is one of:
      "open"              - a response datagram was received.
      "closed"            - an ICMP port-unreachable was received.
      "open_filtered"     - no response and no ICMP error within `timeout` —
                            UDP's fundamental ambiguity: silence could mean
                            the port is open and simply didn't reply to this
                            probe, or that it's filtered by a firewall.
      "unreachable"       - the host or network could not be reached.
      "permission_denied" - the local system refused to send the probe.
      "error"             - the attempt could not be completed for an
                            unrelated reason.

    LIMITATION: the only ICMP condition a connected UDP socket surfaces is
    port-unreachable (as ConnectionRefusedError). Other ICMP types, and any
    ICMP the network filters before it reaches us, are invisible without raw
    packet capture, which this module's no-raw-socket decision rules out.
    Absence of an ICMP error is therefore never evidence that a port is open.
    """
    entry: Dict[str, Any] = {"port": port, "status": PORT_ERROR, "error": None, "response_hex": None}
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        try:
            sock.send(probe)
        except ConnectionRefusedError:
            # A queued ICMP port-unreachable from a previous datagram can be
            # reported on the next send rather than on recv.
            entry["status"] = PORT_CLOSED
            return entry
        try:
            data = sock.recv(2048)
            entry["status"] = PORT_OPEN
            entry["response_hex"] = data.hex()
        except socket.timeout:
            entry["status"] = UDP_OPEN_FILTERED
        except ConnectionRefusedError:
            entry["status"] = PORT_CLOSED
    except OSError as exc:
        entry["status"] = _ERRNO_PORT_STATUS.get(exc.errno, PORT_ERROR) if exc.errno else PORT_ERROR
        # ECONNREFUSED maps to "closed", which for UDP is the ICMP
        # port-unreachable case and stays correct here.
        entry["error"] = str(exc)
    except (TypeError, ValueError) as exc:
        entry["status"] = PORT_ERROR
        entry["error"] = f"invalid port value {port!r}: {exc}"
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
    ports = normalize_ports(
        ports if ports is not None else list(DEFAULT_UDP_PORTS), what="udp ports"
    )

    results: List[Dict[str, Any]] = []
    try:
        _run_port_probes(
            lambda port: _scan_one_udp_port(ip, port, timeout),
            ports, max_workers, results,
            lambda port, exc: {"port": port, "status": PORT_ERROR,
                               "error": str(exc), "response_hex": None},
        )
    except KeyboardInterrupt:
        _persist_udp_results(results, store, ip, target, timeout)
        raise
    return _summarize_udp_scan(results, store, ip, ports, target, timeout)


def _persist_udp_results(
    results: List[Dict[str, Any]],
    store: Optional[PendingAssetsStore],
    ip: str,
    target: Optional[str],
    timeout: float,
) -> Optional[str]:
    """Persist responsive and ambiguous UDP results in a single batched write."""
    if store is None:
        return None
    findings: List[Dict[str, Any]] = []
    for r in results:
        if r["status"] == PORT_OPEN:
            findings.append(make_finding(
                finding_type="open_udp_port",
                target=target or ip,
                value={"ip": ip, "port": r["port"], "protocol": "udp",
                       "response_hex": r["response_hex"]},
                evidence=[f"UDP probe to {ip}:{r['port']} received a response"],
                confidence=CONFIDENCE_HIGH,
                metadata={"ip": ip, "port": r["port"], "protocol": "udp"},
            ))
        elif r["status"] == UDP_OPEN_FILTERED:
            findings.append(make_finding(
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
    return _safe_store_add_many(store, findings)


def _summarize_udp_scan(
    results: List[Dict[str, Any]],
    store: Optional[PendingAssetsStore],
    ip: str,
    ports: List[int],
    target: Optional[str],
    timeout: float,
) -> Dict[str, Any]:
    results.sort(key=lambda r: (r["port"], r["status"]))
    open_ports = sorted({r["port"] for r in results if r["status"] == PORT_OPEN})
    open_filtered_ports = sorted({r["port"] for r in results if r["status"] == UDP_OPEN_FILTERED})
    closed_ports = sorted({r["port"] for r in results if r["status"] == PORT_CLOSED})
    inconclusive = sorted({
        r["port"] for r in results if r["status"] not in _CONCLUSIVE_PORT_STATUSES
    })
    failed = sorted({r["port"] for r in results if r["status"] in _PROBE_FAILURE_STATUSES})
    persist_error = _persist_udp_results(results, store, ip, target, timeout)

    summary: Dict[str, Any] = {
        "ip": ip,
        "protocol": "udp",
        "ports_scanned": list(ports),
        "open_ports": open_ports,
        "open_or_filtered_ports": open_filtered_ports,
        "closed_ports": closed_ports,
        "not_conclusive_ports": inconclusive,
        "failed_ports": failed,
        "ports_tested": len(results),
        "complete": len(results) == len(ports),
        "results": results,
    }
    if persist_error:
        summary["persistence_error"] = persist_error
    return summary


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

# Control characters are stripped from banner text before it is stored or
# displayed. A banner is attacker-controlled input that ends up in
# pending_assets.json, in the Rich terminal output, and in the HTML report;
# raw ANSI escape sequences there can rewrite or clear the operator's
# terminal, and NUL/control bytes corrupt downstream text handling. The exact
# bytes are never lost — grab_banner keeps them verbatim as `banner_hex`.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _sanitize_banner(raw: bytes, max_chars: int = 2048) -> Tuple[str, bool]:
    """
    Decode banner bytes to display-safe text.

    Returns (text, was_sanitized). Tab/CR/LF survive as whitespace; every
    other control character is removed rather than escaped, so nothing
    downstream can re-interpret it as a terminal control sequence.
    """
    decoded = raw.decode("utf-8", errors="replace")
    cleaned = _CONTROL_CHARS_RE.sub("", decoded).strip()
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars]
    return cleaned, cleaned != decoded.strip()


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
    result: Dict[str, Any] = {
        "status": "no_data", "banner": None, "banner_hex": None,
        "sanitized": False, "error": None,
    }
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
            banner, sanitized = _sanitize_banner(data)
            result["banner_hex"] = data.hex()
            result["sanitized"] = sanitized
            # Bytes that reduce to nothing printable are not a banner. Saying
            # "found" with banner "" would assert a service identity that the
            # response does not actually support.
            if banner:
                result["status"] = "found"
                result["banner"] = banner
            else:
                result["status"] = "no_data"
                result["error"] = "response contained no printable characters"
    except socket.timeout:
        result["status"] = "no_data"
        result["error"] = "timeout waiting for banner"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    except (TypeError, ValueError) as exc:
        result["status"] = "error"
        result["error"] = f"invalid port value {port!r}: {exc}"
    finally:
        if sock is not None:
            sock.close()

    if store is not None and result["status"] == "found":
        evidence = [f"TCP connection to {ip}:{port} returned a banner on connect"]
        if result["sanitized"]:
            evidence.append(
                "banner contained control characters; they were stripped for display "
                "(raw bytes preserved in metadata.banner_hex)"
            )
        store.add(make_finding(
            finding_type="banner",
            target=target or ip,
            value={"ip": ip, "port": port, "banner": result["banner"]},
            evidence=evidence,
            confidence=CONFIDENCE_HIGH,
            metadata={"ip": ip, "port": port, "banner_hex": result["banner_hex"],
                      "sanitized": result["sanitized"]},
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

# Port-heuristic and banner-signature names that describe the SAME protocol at
# different levels of specificity. A conflict means the two signals disagree
# about what the service IS — not that one is more specific than the other.
# Port 587 is the concrete case: its port name is "smtp-submission" while any
# real server there greets with a generic SMTP banner, so without this the
# module reported a permanent unresolved conflict for every correctly
# configured mail submission server (context.md §8: conflicts must be real,
# because surface_mapper.py preserves them and surfaces them downstream).
_SERVICE_FAMILY: Dict[str, str] = {
    "smtp": "smtp",
    "smtp-submission": "smtp",
}


def _same_service_family(a: Optional[str], b: Optional[str]) -> bool:
    """True when two service labels describe the same underlying protocol."""
    if not a or not b:
        return False
    return _SERVICE_FAMILY.get(a, a) == _SERVICE_FAMILY.get(b, b)


# A response that is plainly HTTP or HTML is a web page, not a database
# greeting. Without this guard, an HTTP 500 page containing the words "MySQL
# connection failed" was identified as a MySQL service at HIGH confidence and
# written into the graph as the port's service.
_LOOKS_HTTP_RE = re.compile(r"^(HTTP/\d|<!doctype|<html)", re.I)


def _banner_based_service_guess(banner: Optional[str]) -> Optional[str]:
    """
    Map a service's own greeting onto a protocol name.

    Every rule here keys off the *greeting form* a server actually emits, not
    on a keyword appearing anywhere in the response: a keyword match is
    satisfied just as easily by an error message that names the technology as
    by the service itself.
    """
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
    if _LOOKS_HTTP_RE.match(b):
        return None
    # A MySQL/MariaDB server greeting leads with the version string, so the
    # product name appears at the very start. Requiring that position keeps a
    # web page that merely mentions the database from being identified as one.
    if re.match(r"^[\x00-\x20]*[\d.]*[\w.\-]*(mysql|mariadb)", bl):
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

    conflict = bool(
        port_guess and banner_guess
        and port_guess != banner_guess
        and not _same_service_family(port_guess, banner_guess)
    )
    if conflict:
        service = None
        confidence = CONFIDENCE_LOW
        evidence = [
            f"port {port}/{protocol} is commonly associated with {port_guess!r}, "
            f"but the banner matches the {banner_guess!r} signature instead"
        ]
    elif banner_guess and _same_service_family(port_guess, banner_guess):
        # Two independent signals agreeing on the protocol (context.md §8:
        # converging signals raise confidence). Keep the port's more specific
        # label — 587 is SMTP submission, not plain SMTP.
        service = port_guess
        confidence = CONFIDENCE_HIGH
        evidence = [
            f"port {port}/{protocol} is commonly associated with {port_guess!r} and the "
            f"banner matched the compatible {banner_guess!r} signature"
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
    # SMTP/FTP greetings and reply text are attacker-controlled and are stored
    # in findings and rendered to the operator's terminal, exactly like the
    # banners grab_banner() handles. Strip control characters here too, so the
    # protection does not depend on which code path read the bytes. The
    # leading 3-digit reply code that _parse_response_code() needs is
    # unaffected.
    text, _ = _sanitize_banner(data, max_chars=max_bytes)
    return text


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
            # `vrfy_supported`/`expn_supported` are flattened alongside the
            # nested structures, not instead of them. risk_engine.py's
            # smtp_user_enumeration rule reads the finding value directly and
            # matches on these flat keys; with only the nested form, a
            # confirmed VRFY/EXPN exposure reached the risk engine as an
            # "unclassified" signal and was never scored (verified end-to-end
            # against risk_engine.extract_signals). The nested keys are kept
            # so any existing consumer of value["vrfy"]["supported"] is
            # unaffected.
            value={
                "ip": ip, "port": port,
                "vrfy": result["vrfy"], "expn": result["expn"],
                "vrfy_supported": bool(result["vrfy"]["supported"]),
                "expn_supported": bool(result["expn"]["supported"]),
            },
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
    """
    Read one BER TLV, rejecting truncated input explicitly.

    Bounds are checked rather than left to slicing, because Python silently
    returns a short slice for an over-long length. Unchecked, a truncated or
    hostile datagram would yield a plausible-looking parse instead of an
    error, and this parser's output decides whether an SNMP community string
    is reported as accepted.
    """
    if offset + 2 > len(data):
        raise ValueError("truncated BER TLV header")
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or offset + n > len(data):
            raise ValueError("truncated or indefinite BER length")
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        length = first
    if offset + length > len(data):
        raise ValueError("BER TLV length exceeds available data")
    value = data[offset:offset + length]
    offset += length
    return tag, value, offset


def _snmp_build_get_request(community: str, request_id: int) -> bytes:
    varbind = _ber_tlv(0x30, _ber_tlv(0x06, _SYSDESCR_OID) + _ber_tlv(0x05, b""))
    varbindlist = _ber_tlv(0x30, varbind)
    pdu_body = _ber_int(request_id) + _ber_int(0) + _ber_int(0) + varbindlist
    pdu = _ber_tlv(0xA0, pdu_body)  # GetRequest-PDU
    return _ber_tlv(0x30, _ber_int(0) + _ber_tlv(0x04, community.encode("utf-8")) + pdu)


def _snmp_parse_get_response(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse an SNMP GetResponse, returning None when `data` is not one.

    Returning None (rather than a default-filled dict) is what lets the caller
    distinguish "a valid SNMP agent answered" from "some datagram arrived".
    The parsed request-id is returned so the caller can correlate the reply
    with the request that produced it.
    """
    try:
        _, body, _ = _ber_read_tlv(data, 0)
        pos = 0
        _, _, pos = _ber_read_tlv(body, pos)  # version
        _, community_val, pos = _ber_read_tlv(body, pos)  # community
        pdu_tag, pdu_val, _ = _ber_read_tlv(body, pos)
        if pdu_tag != 0xA2:  # not a GetResponse-PDU
            return None
        p = 0
        _, req_val, p = _ber_read_tlv(pdu_val, p)  # request-id
        _, err_val, p = _ber_read_tlv(pdu_val, p)  # error-status
        _, _, p = _ber_read_tlv(pdu_val, p)  # error-index
        _, vbl_val, _ = _ber_read_tlv(pdu_val, p)  # variable-bindings
    except (ValueError, IndexError):
        return None

    parsed: Dict[str, Any] = {
        "request_id": int.from_bytes(req_val, "big") if req_val else None,
        "error_status": int.from_bytes(err_val, "big") if err_val else 0,
        "community_echo": community_val.decode("utf-8", errors="replace") if community_val else "",
        "sysdescr": None,
    }
    if vbl_val:
        try:
            _, vb_val, _ = _ber_read_tlv(vbl_val, 0)
            _, _, p2 = _ber_read_tlv(vb_val, 0)  # oid
            val_tag, val_val, _ = _ber_read_tlv(vb_val, p2)
            if val_tag == 0x04:
                parsed["sysdescr"] = val_val.decode("utf-8", errors="replace")
        except (ValueError, IndexError):
            pass  # a valid PDU whose varbind we could not read is still a real reply
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
    string is treated as accepted if the agent returns a valid GetResponse
    correlated to that specific request — SNMP agents conventionally do not
    respond to a GetRequest carrying an unrecognized community string, so a
    correlated reply demonstrates the community was accepted (this mirrors
    how established SNMP scanners like onesixtyone work).

    Three correlation rules keep that inference honest, because the probes
    share one socket and UDP gives no delivery ordering:

      1. The reply must come from the address that was probed. An unconnected
         UDP socket will happily accept a datagram from anyone.
      2. The reply's request-id must match the request just sent. Without
         this, a slow answer to "public" is read by the next recv and
         credited to "private" — reporting a community the agent never
         accepted, and missing the one it did.
      3. The datagram must parse as a real GetResponse PDU. Without this, any
         unrelated UDP noise on port 161 is reported as a default community
         string being accepted.

    Datagrams that arrive but fail these rules are recorded under
    `unverified_responses` as evidence rather than discarded, and never count
    as acceptance.
    """
    communities = communities or list(_DEFAULT_SNMP_COMMUNITIES)
    result: Dict[str, Any] = {
        "status": "checked", "accepted": [], "communities_tried": list(communities),
        "unverified_responses": [], "error": None,
    }
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        for idx, community in enumerate(communities):
            request_id = idx + 1
            packet = _snmp_build_get_request(community, request_id=request_id)
            sock.sendto(packet, (ip, port))

            # Read until this request is answered or its own time budget runs
            # out, rather than accepting the first datagram that shows up.
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    sock.settimeout(remaining)
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                except ConnectionRefusedError:
                    break  # ICMP port-unreachable: nothing is listening

                if addr[0] != ip:
                    result["unverified_responses"].append(
                        {"community": community, "reason": "source address mismatch",
                         "from": addr[0]})
                    continue
                parsed = _snmp_parse_get_response(data)
                if parsed is None:
                    result["unverified_responses"].append(
                        {"community": community, "reason": "not a valid SNMP GetResponse",
                         "response_hex": data[:64].hex()})
                    continue
                if parsed.get("request_id") != request_id:
                    # A late reply to an earlier community; do not credit it here.
                    result["unverified_responses"].append(
                        {"community": community, "reason": "request-id mismatch",
                         "expected": request_id, "received": parsed.get("request_id")})
                    continue

                result["accepted"].append({
                    "community": community,
                    "error_status": parsed.get("error_status"),
                    "sysdescr": parsed.get("sysdescr"),
                })
                break
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
    result: Dict[str, Any] = {
        "status": "checked", "exposed": False, "raw_response_hex": None,
        "unverified_responses": [], "error": None,
    }
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_RMCP_PRESENCE_PING, (ip, port))
        # The socket is unconnected, so it will accept a datagram from ANY
        # source. Without checking the sender, an unrelated host's reply would
        # be recorded as IPMI exposure on this target — and context.md marks
        # IPMI exposure auto-CRITICAL, so that false positive is expensive.
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                sock.settimeout(remaining)
                data, addr = sock.recvfrom(256)
            except socket.timeout:
                break
            except ConnectionRefusedError:
                break  # ICMP port-unreachable: nothing is listening
            if addr[0] != ip:
                result["unverified_responses"].append(
                    {"reason": "source address mismatch", "from": addr[0]})
                continue
            if len(data) >= 4 and data[0] == 0x06 and data[3] == 0x06:
                result["exposed"] = True
                result["raw_response_hex"] = data.hex()
                break
            result["unverified_responses"].append(
                {"reason": "not an RMCP presence pong", "response_hex": data[:32].hex()})
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
    ip = validate_scan_target(ip)
    ports = normalize_ports(ports if ports else sorted(_DB_PORT_SERVICE), what="db ports")
    result: Dict[str, Any] = {
        "status": "checked", "exposed_ports": [], "inconclusive_ports": [],
        "details": {}, "error": None,
    }

    for port in ports:
        entry: Dict[str, Any] = {
            "port": port, "service": _DB_PORT_SERVICE.get(port, "unknown"),
            "open": False, "banner": None, "status": None,
        }
        scan_entry = _scan_one_tcp_port(ip, port, timeout)
        entry["status"] = scan_entry["status"]
        if scan_entry["status"] == PORT_OPEN:
            entry["open"] = True
            banner_result = grab_banner(ip, port, timeout=timeout)
            if banner_result["status"] == "found":
                entry["banner"] = banner_result["banner"]
            result["exposed_ports"].append(port)
        elif scan_entry["status"] not in _CONCLUSIVE_PORT_STATUSES:
            # Never learned whether this port is reachable. Recording it as
            # "not exposed" would turn a failed probe into a clean bill of
            # health for a port context.md treats as auto-CRITICAL.
            result["inconclusive_ports"].append(port)
        result["details"][str(port)] = entry

    if store is not None and result["status"] == "checked":
        exposed = bool(result["exposed_ports"])
        metadata: Dict[str, Any] = {"ip": ip, "ports_checked": ports}
        if result["inconclusive_ports"]:
            metadata["inconclusive_ports"] = list(result["inconclusive_ports"])
        if exposed:
            evidence = [
                f"TCP port {p} ({_DB_PORT_SERVICE.get(p, 'unknown')}) reachable on {ip}"
                for p in result["exposed_ports"]
            ]
            confidence = CONFIDENCE_HIGH
            metadata["severity"] = "CRITICAL"
        else:
            tested = [p for p in ports if p not in result["inconclusive_ports"]]
            evidence = []
            if tested:
                evidence.append(
                    f"No database ports ({', '.join(str(p) for p in tested)}) reachable on {ip}"
                )
            if result["inconclusive_ports"]:
                evidence.append(
                    f"Port(s) {', '.join(str(p) for p in result['inconclusive_ports'])} could not "
                    f"be conclusively tested on {ip} "
                    f"({', '.join(sorted({result['details'][str(p)]['status'] for p in result['inconclusive_ports']}))})"
                    " — this is not evidence that they are closed"
                )
            confidence = CONFIDENCE_LOW
        store.add(make_finding(
            finding_type="db_exposure",
            target=target or ip,
            value={"ip": ip, "exposed_ports": result["exposed_ports"],
                   "inconclusive_ports": result["inconclusive_ports"],
                   "details": result["details"]},
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


def _ttl_observation(ttl: int) -> Dict[str, Any]:
    """
    Describe what an observed TTL actually supports.

    A received TTL is the initial TTL minus the hop count, so it identifies an
    initial-TTL baseline, not an operating system, and only if no intermediary
    rewrote it. The hop estimate is reported alongside the family so the
    inference stays auditable, and `may_be_intermediary` records that the
    responder may be a NAT, load balancer, proxy or firewall answering on the
    host's behalf rather than the host itself.
    """
    baseline = next((b for b, _ in _TTL_BASELINES if ttl <= b), None)
    return {
        "initial_ttl_baseline": baseline,
        "estimated_hops": (baseline - ttl) if baseline is not None else None,
        "may_be_intermediary": True,
    }


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
        observation = _ttl_observation(result["ttl"])
        result["observation"] = observation
        store.add(make_finding(
            finding_type="os_fingerprint",
            target=target or ip,
            value={"ip": ip, "ttl": result["ttl"], "os_guess": result["os_guess"]},
            evidence=[
                f"Inbound IP TTL from {ip}:{port}/udp observed as {result['ttl']}",
                f"consistent with an initial TTL of {observation['initial_ttl_baseline']} "
                f"about {observation['estimated_hops']} hop(s) away",
                "the responding device may be a NAT/proxy/load balancer rather than the "
                "target host itself, and a single TTL cannot distinguish the two",
            ],
            confidence=CONFIDENCE_LOW,
            metadata={
                "ip": ip, "port": port, "method": "ttl_only_udp",
                "initial_ttl_baseline": observation["initial_ttl_baseline"],
                "estimated_hops": observation["estimated_hops"],
                "may_be_intermediary": True,
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

    if not isinstance(host_scan_results, (list, tuple)):
        host_scan_results = []

    # Correlation runs over results accumulated from many scans, any one of
    # which may be malformed. A bad entry is skipped rather than allowed to
    # abort correlation of every other host (context.md §12.11).
    for entry in host_scan_results:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip")
        if not ip or not isinstance(ip, str):
            continue
        ports = entry.get("open_ports")
        if not isinstance(ports, (list, tuple, set, frozenset)):
            continue
        for port in ports:
            if isinstance(port, bool) or not isinstance(port, int):
                continue
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

    COMPLETENESS: the summary carries `status` ("completed",
    "completed_with_errors" or "interrupted") and a per-stage `stages` map.
    Without them, a run in which every stage failed is indistinguishable from
    a run that completed cleanly and found nothing — the caller sees the same
    empty `tcp`/`udp`/`banners` structures either way. Callers that need to
    know whether "nothing found" means "nothing is there" must read `status`
    and `stages`, not just the result payloads.

    A KeyboardInterrupt is re-raised after the partial summary has been
    recorded and every discovery so far persisted, because
    core/orchestrator.py relies on the interrupt propagating to stop the run.
    """
    ip = validate_scan_target(ip)
    store = PendingAssetsStore(output_dir=output_dir)

    summary: Dict[str, Any] = {
        "ip": ip,
        "target": target or ip,
        "module": MODULE_NAME,
        "started_at": _now(),
        "status": RUN_COMPLETED,
        "stages": {},
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

    def _stage_outcome(value: Any) -> Tuple[str, Optional[str]]:
        """
        Decide whether a stage that returned normally actually learned anything.

        Returns (status, reason). The probe helpers report network failures in
        their return value rather than by raising, so "did not raise" is not
        evidence that a check succeeded.
        """
        if not isinstance(value, dict):
            return STAGE_COMPLETED, None
        if value.get("status") == "error":
            return STAGE_INCONCLUSIVE, str(value.get("error") or "check reported an error status")
        scanned = value.get("ports_scanned")
        if scanned is not None:
            if not value.get("complete", True):
                return STAGE_INCONCLUSIVE, "not every requested port was tested"
            # Only probe *failures* make a scan stage inconclusive. A port that
            # answered "closed", or stayed silent ("filtered"/"open_filtered"),
            # was successfully probed — silence is an ambiguous observation,
            # not a failed check.
            failed = value.get("failed_ports") or []
            if scanned and len(failed) == len(scanned):
                return STAGE_INCONCLUSIVE, (
                    f"every one of the {len(scanned)} port(s) probed failed before a "
                    f"result could be observed"
                )
        # check_database_exposure reports per-port status under "details"
        # rather than as a port scan summary.
        details = value.get("details")
        if isinstance(details, dict) and details:
            statuses = [d.get("status") for d in details.values() if isinstance(d, dict)]
            if statuses and all(s in _PROBE_FAILURE_STATUSES for s in statuses):
                return STAGE_INCONCLUSIVE, (
                    "every database port probe failed before a result could be observed"
                )
        return STAGE_COMPLETED, None

    def _stage(name: str, fn: Any, *, skipped_reason: Optional[str] = None) -> Any:
        """
        Run one recon stage, recording its outcome.

        Every stage records completed / failed / skipped, so the caller can
        tell an empty result that means "checked, nothing there" from one that
        means "this check never ran". A stage failure is contained (context.md
        §12.11: one failure must not abort unrelated work); KeyboardInterrupt
        is not contained, because the run is being stopped.
        """
        if skipped_reason is not None:
            summary["stages"][name] = {"status": STAGE_SKIPPED, "reason": skipped_reason}
            return None
        try:
            value = fn()
            status, reason = _stage_outcome(value)
            record: Dict[str, Any] = {"status": status}
            if reason:
                record["reason"] = reason
            # A scan can succeed while its findings fail to persist. That is a
            # real failure of this module's crash-safety guarantee, so it must
            # degrade the run rather than be buried in the payload.
            if isinstance(value, dict) and value.get("persistence_error"):
                record["persistence_error"] = value["persistence_error"]
                summary["errors"].append(
                    {"stage": name, "error": f"persistence failed: {value['persistence_error']}"}
                )
            summary["stages"][name] = record
            return value
        except KeyboardInterrupt:
            summary["stages"][name] = {"status": STAGE_INTERRUPTED_MARK}
            raise
        except Exception as exc:
            summary["errors"].append({"stage": name, "error": str(exc)})
            summary["stages"][name] = {"status": STAGE_FAILED, "error": str(exc)}
            return None

    try:
        if tcp_ports:
            tcp_result = _stage("tcp_scan", lambda: tcp_connect_scan(
                ip, tcp_ports, store=store, target=target,
                timeout=timeout, max_workers=max_workers,
            ))
            if tcp_result is not None:
                summary["tcp"] = tcp_result
                open_tcp_ports = tcp_result.get("open_ports", [])
        else:
            _stage("tcp_scan", None, skipped_reason=(
                "no tcp_ports supplied; active_recon ships no default TCP port list "
                "(see module docstring decision 2)"
            ))

        for port in open_tcp_ports:
            def _banner_and_service(port: int = port) -> None:
                banner_result = grab_banner(ip, port, store=store, target=target, timeout=timeout)
                summary["banners"][str(port)] = banner_result
                summary["services"][str(port)] = identify_service(
                    ip, port, banner=banner_result.get("banner"), protocol="tcp",
                    store=store, target=target,
                )
            _stage(f"banner_service:{port}", _banner_and_service)

        if 21 in open_tcp_ports:
            summary["ftp"] = _stage("ftp", lambda: ftp_anonymous_login_check(
                ip, store=store, target=target, timeout=timeout))
        else:
            _stage("ftp", None, skipped_reason="port 21/tcp was not observed open")

        if 22 in open_tcp_ports:
            summary["ssh"] = _stage("ssh", lambda: ssh_fingerprint(
                ip, store=store, target=target, timeout=timeout))
        else:
            _stage("ssh", None, skipped_reason="port 22/tcp was not observed open")

        smtp_ports = [p for p in (25, 587) if p in open_tcp_ports]
        if smtp_ports:
            summary["smtp"] = _stage("smtp", lambda: smtp_probe(
                ip, port=smtp_ports[0], store=store, target=target, timeout=timeout,
                probe_user=smtp_probe_user))
        else:
            _stage("smtp", None, skipped_reason="neither port 25/tcp nor 587/tcp was observed open")

        effective_udp_ports = udp_ports if udp_ports is not None else list(DEFAULT_UDP_PORTS)
        udp_result = _stage("udp_scan", lambda: udp_scan(
            ip, effective_udp_ports, store=store, target=target,
            timeout=timeout, max_workers=max_workers))
        if udp_result is not None:
            summary["udp"] = udp_result

        if 161 in effective_udp_ports:
            summary["snmp"] = _stage("snmp", lambda: snmp_community_probe(
                ip, store=store, target=target, timeout=timeout, communities=snmp_communities))
        else:
            _stage("snmp", None, skipped_reason="port 161 is not in the UDP port list for this run")

        if check_ipmi_enabled:
            summary["ipmi"] = _stage("ipmi", lambda: check_ipmi_exposure(
                ip, store=store, target=target, timeout=timeout))
        else:
            _stage("ipmi", None, skipped_reason="disabled by caller (check_ipmi_enabled=False)")

        if check_db_exposure_enabled:
            summary["db_exposure"] = _stage("db_exposure", lambda: check_database_exposure(
                ip, store=store, target=target, timeout=timeout))
        else:
            _stage("db_exposure", None,
                   skipped_reason="disabled by caller (check_db_exposure_enabled=False)")

        if fingerprint_os_enabled:
            os_port = None
            os_probe = b""
            if summary["snmp"] and summary["snmp"].get("accepted"):
                os_port = 161
                os_probe = _snmp_build_get_request(
                    summary["snmp"]["accepted"][0]["community"], request_id=999)
            elif summary["ipmi"] and summary["ipmi"].get("exposed"):
                os_port = 623
                os_probe = _RMCP_PRESENCE_PING
            if os_port:
                summary["os_fingerprint"] = _stage("os_fingerprint", lambda: fingerprint_os_ttl(
                    ip, os_port, probe=os_probe, store=store, target=target, timeout=timeout))
            else:
                _stage("os_fingerprint", None, skipped_reason=(
                    "no UDP port confirmed to respond (SNMP/IPMI) was available to sample a TTL from"
                ))
        else:
            _stage("os_fingerprint", None,
                   skipped_reason="disabled by caller (fingerprint_os_enabled=False)")
    except KeyboardInterrupt:
        # Everything discovered so far is already persisted; record the
        # partial outcome, then let the interrupt continue to the orchestrator.
        summary["status"] = RUN_INTERRUPTED
        for name in _ALL_STAGE_NAMES:
            summary["stages"].setdefault(name, {"status": STAGE_NOT_REACHED})
        summary["finished_at"] = _now()
        summary["interrupted"] = True
        raise ActiveReconInterrupted(summary)

    # A run is only "completed" if nothing failed and nothing came back
    # inconclusive. Otherwise the caller must not read empty results as
    # "nothing is there".
    degraded = summary["errors"] or any(
        stage.get("status") in (STAGE_FAILED, STAGE_INCONCLUSIVE)
        for stage in summary["stages"].values()
    )
    summary["status"] = RUN_COMPLETED_WITH_ERRORS if degraded else RUN_COMPLETED
    summary["finished_at"] = _now()
    return summary


# ---------------------------------------------------------------------------
# Standalone entry point (manual/independent testing only — the full CLI
# experience with the ASCII banner and Rich output belongs to reconhound.py)
# ---------------------------------------------------------------------------

def _parse_ports(raw: Optional[str]) -> Optional[List[int]]:
    """
    Parse a comma-separated port list, accepting "N" and "A-B" ranges.

    Raises ValueError with an actionable message rather than letting int()'s
    raw "invalid literal" surface out of the CLI.
    """
    if not raw:
        return None
    ports: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part.lstrip("-"):
            lo_raw, _, hi_raw = part.partition("-")
            try:
                lo, hi = int(lo_raw), int(hi_raw)
            except ValueError:
                raise ValueError(f"invalid port range {part!r}; expected LOW-HIGH, e.g. 20-25") from None
            if lo > hi:
                raise ValueError(f"invalid port range {part!r}: {lo} is greater than {hi}")
            ports.extend(range(lo, hi + 1))
            continue
        try:
            ports.append(int(part))
        except ValueError:
            raise ValueError(f"invalid port {part!r}; ports must be integers between "
                             f"{MIN_PORT} and {MAX_PORT}") from None
    return normalize_ports(ports)


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
    except ValueError as exc:
        print(f"[input error] {exc}")
        raise SystemExit(2)
    except ActiveReconInterrupted as exc:
        # Discoveries are already persisted; report the partial run rather
        # than exiting as if nothing had been found.
        print(json.dumps(exc.summary, indent=2))
        raise SystemExit(130)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
