"""
Tests for reconhound/active_recon.py (ReconHound Module 2, complete).

Run with:  ./.venv/bin/python -m pytest tests/test_active_recon.py -v

Covers every Module 2 function (see active_recon.py's module docstring for
the full responsibility list and documented limitations). Nearly all tests
mock the socket boundary so the suite is deterministic and offline-safe.
A handful of "live-ish" tests use real loopback sockets (127.0.0.1) started
by the test itself, rather than mocks, specifically where the behavior
being verified is a real OS/kernel interaction (e.g. IP_RECVTTL ancillary
data) that a mock can't meaningfully stand in for; no external network
access is required or performed anywhere in this file.
"""

import json
import os
import socket
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconhound import active_recon as ar


SAFE_IP = "93.184.216.34"  # example.com's documented IP (RFC 2606 domain); not actually contacted


# ---------------------------------------------------------------------------
# validate_scan_target (scope enforcement)
# ---------------------------------------------------------------------------

class TestValidateScanTarget:
    def test_accepts_valid_ipv4(self):
        assert ar.validate_scan_target("93.184.216.34") == "93.184.216.34"

    def test_strips_surrounding_whitespace(self):
        assert ar.validate_scan_target("  93.184.216.34  ") == "93.184.216.34"

    @pytest.mark.parametrize("bad", ["", "   ", None, 123])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(ar.ScopeError):
            ar.validate_scan_target(bad)

    def test_rejects_hostname(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_scan_target("example.com")

    def test_rejects_cidr_range(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_scan_target("93.184.216.0/24")

    def test_rejects_ipv6(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_scan_target("::1")

    def test_rejects_malformed_ip(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_scan_target("999.999.999.999")


# ---------------------------------------------------------------------------
# make_finding / evidence model
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_structure_and_source(self):
        finding = ar.make_finding(
            finding_type="open_tcp_port",
            target="93.184.216.34",
            value={"ip": "93.184.216.34", "port": 80},
            evidence=["evidence line"],
            confidence=ar.CONFIDENCE_HIGH,
        )
        assert finding["type"] == "open_tcp_port"
        assert finding["source"] == "active_recon.py"
        assert finding["confidence"] == ar.CONFIDENCE_HIGH
        assert "timestamp" in finding and finding["timestamp"]
        assert finding["metadata"] == {}

    def test_is_json_serializable(self):
        finding = ar.make_finding("open_tcp_port", "1.2.3.4", {"port": 22}, ["e"], ar.CONFIDENCE_HIGH)
        json.dumps(finding)  # must not raise


# ---------------------------------------------------------------------------
# PendingAssetsStore (shared file/format with passive_recon.py)
# ---------------------------------------------------------------------------

class TestPendingAssetsStore:
    def test_creates_output_dir_and_file(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        finding = ar.make_finding("open_tcp_port", "1.2.3.4", {}, ["e"], ar.CONFIDENCE_HIGH)
        store.add(finding)
        assert os.path.exists(store.path)
        with open(store.path) as f:
            data = json.load(f)
        assert data == [finding]

    def test_preserves_existing_data_from_prior_module_run(self, tmp_path):
        # Simulates passive_recon.py having already written findings to the
        # same pending_assets.json before active_recon.py runs.
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pending = output_dir / "pending_assets.json"
        pre_existing = [
            {"type": "dns_record", "target": "example.com", "value": {}, "evidence": ["prior"],
             "confidence": "HIGH", "source": "passive_recon.py", "timestamp": "t", "metadata": {}}
        ]
        pending.write_text(json.dumps(pre_existing))

        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        new_finding = ar.make_finding("open_tcp_port", "1.2.3.4", {}, ["new"], ar.CONFIDENCE_HIGH)
        store.add(new_finding)

        assert store.all() == pre_existing + [new_finding]

    def test_corrupt_existing_file_raises_persistence_error(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "pending_assets.json").write_text("{not valid json")

        store = ar.PendingAssetsStore(output_dir=str(output_dir))
        with pytest.raises(ar.PersistenceError):
            store.add(ar.make_finding("open_tcp_port", "1.2.3.4", {}, ["e"], ar.CONFIDENCE_HIGH))

    def test_write_is_atomic_no_temp_file_left_behind(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add(ar.make_finding("open_tcp_port", "1.2.3.4", {}, ["e"], ar.CONFIDENCE_HIGH))
        leftovers = [p for p in os.listdir(store.output_dir) if p.startswith(".pending_assets_")]
        assert leftovers == []


# ---------------------------------------------------------------------------
# _scan_one_tcp_port (mocked socket)
# ---------------------------------------------------------------------------

class TestScanOneTcpPort:
    def test_open_port(self):
        fake_sock = mock.MagicMock()
        fake_sock.connect_ex.return_value = 0
        with mock.patch("socket.socket", return_value=fake_sock):
            entry = ar._scan_one_tcp_port("1.2.3.4", 80, 1.0)
        assert entry == {"port": 80, "status": "open", "error": None}
        fake_sock.close.assert_called_once()

    def test_closed_port(self):
        fake_sock = mock.MagicMock()
        fake_sock.connect_ex.return_value = 111  # ECONNREFUSED
        with mock.patch("socket.socket", return_value=fake_sock):
            entry = ar._scan_one_tcp_port("1.2.3.4", 81, 1.0)
        assert entry["status"] == "closed"

    def test_filtered_on_timeout(self):
        fake_sock = mock.MagicMock()
        fake_sock.connect_ex.side_effect = socket.timeout("timed out")
        with mock.patch("socket.socket", return_value=fake_sock):
            entry = ar._scan_one_tcp_port("1.2.3.4", 82, 1.0)
        assert entry["status"] == "filtered"
        assert entry["error"] == "timeout"

    def test_error_on_os_error(self):
        fake_sock = mock.MagicMock()
        fake_sock.connect_ex.side_effect = OSError("network unreachable")
        with mock.patch("socket.socket", return_value=fake_sock):
            entry = ar._scan_one_tcp_port("1.2.3.4", 83, 1.0)
        assert entry["status"] == "error"
        assert "network unreachable" in entry["error"]

    def test_socket_always_closed_even_on_error(self):
        fake_sock = mock.MagicMock()
        fake_sock.connect_ex.side_effect = OSError("boom")
        with mock.patch("socket.socket", return_value=fake_sock):
            ar._scan_one_tcp_port("1.2.3.4", 84, 1.0)
        fake_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# tcp_connect_scan (end-to-end, mocked socket boundary)
# ---------------------------------------------------------------------------

class TestTcpConnectScan:
    def test_open_ports_are_persisted_closed_are_not(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 111
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.tcp_connect_scan(SAFE_IP, [80, 81, 82], store=store)

        assert result["ip"] == SAFE_IP
        assert result["open_ports"] == [80]
        assert sorted(result["ports_scanned"]) == [80, 81, 82]
        statuses = {r["port"]: r["status"] for r in result["results"]}
        assert statuses == {80: "open", 81: "closed", 82: "closed"}

        persisted = store.all()
        assert len(persisted) == 1
        assert persisted[0]["type"] == "open_tcp_port"
        assert persisted[0]["value"]["port"] == 80
        assert persisted[0]["confidence"] == ar.CONFIDENCE_HIGH
        assert persisted[0]["source"] == "active_recon.py"

    def test_no_store_means_no_persistence(self):
        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.return_value = 0
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.tcp_connect_scan(SAFE_IP, [80])
        assert result["open_ports"] == [80]

    def test_target_tag_used_when_provided(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.return_value = 0
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            ar.tcp_connect_scan(SAFE_IP, [443], store=store, target="example.com")

        assert store.all()[0]["target"] == "example.com"

    def test_defaults_to_ip_as_target_when_not_provided(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.return_value = 0
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            ar.tcp_connect_scan(SAFE_IP, [443], store=store)

        assert store.all()[0]["target"] == SAFE_IP

    def test_all_ports_closed_persists_nothing(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.return_value = 111
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.tcp_connect_scan(SAFE_IP, [1, 2, 3], store=store)

        assert result["open_ports"] == []
        assert store.all() == []

    def test_one_port_error_does_not_abort_scan(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            def connect_ex(addr):
                if addr[1] == 22:
                    raise OSError("boom")
                return 0
            s.connect_ex.side_effect = connect_ex
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.tcp_connect_scan(SAFE_IP, [22, 80], store=store)

        statuses = {r["port"]: r["status"] for r in result["results"]}
        assert statuses[22] == "error"
        assert statuses[80] == "open"
        assert result["open_ports"] == [80]

    def test_invalid_ip_raises_scope_error_before_scanning(self):
        with mock.patch("socket.socket") as mocked_socket:
            with pytest.raises(ar.ScopeError):
                ar.tcp_connect_scan("not-an-ip", [80])
        mocked_socket.assert_not_called()

    def test_empty_ports_raises_value_error(self):
        with pytest.raises(ValueError):
            ar.tcp_connect_scan(SAFE_IP, [])

    def test_results_are_json_serializable(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.return_value = 0
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.tcp_connect_scan(SAFE_IP, [80, 443], store=store)

        json.dumps(result)
        json.dumps(store.all())


# ---------------------------------------------------------------------------
# validate_ipv6_scan_target / ipv6_tcp_connect_scan
# ---------------------------------------------------------------------------

SAFE_IPV6 = "2606:2800:220:1:248:1893:25c8:1946"  # example.com's documented IPv6


class TestValidateIpv6ScanTarget:
    def test_accepts_valid_ipv6(self):
        assert ar.validate_ipv6_scan_target("::1") == "::1"

    def test_rejects_ipv4(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_ipv6_scan_target("93.184.216.34")

    def test_rejects_hostname(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_ipv6_scan_target("example.com")

    def test_rejects_cidr(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_ipv6_scan_target("2606:2800:220::/48")

    @pytest.mark.parametrize("bad", ["", "   ", None])
    def test_rejects_empty_or_non_string(self, bad):
        with pytest.raises(ar.ScopeError):
            ar.validate_ipv6_scan_target(bad)


class TestIpv6TcpConnectScan:
    def test_open_and_closed_ports(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.side_effect = lambda addr: 0 if addr[1] == 443 else 111
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.ipv6_tcp_connect_scan(SAFE_IPV6, [80, 443], store=store)

        assert result["ip_version"] == 6
        assert result["open_ports"] == [443]
        persisted = store.all()
        assert len(persisted) == 1
        assert persisted[0]["metadata"]["ip_version"] == 6

    def test_rejects_ipv4_target(self):
        with pytest.raises(ar.ScopeError):
            ar.ipv6_tcp_connect_scan(SAFE_IP, [80])

    def test_empty_ports_raises_value_error(self):
        with pytest.raises(ValueError):
            ar.ipv6_tcp_connect_scan(SAFE_IPV6, [])


# ---------------------------------------------------------------------------
# udp_scan / _scan_one_udp_port
# ---------------------------------------------------------------------------

class TestScanOneUdpPort:
    def test_open_with_response(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b"\x01\x02"
        with mock.patch("socket.socket", return_value=fake_sock):
            entry = ar._scan_one_udp_port("1.2.3.4", 53, 1.0)
        assert entry["status"] == "open"
        assert entry["response_hex"] == "0102"

    def test_closed_on_connection_refused(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = ConnectionRefusedError("refused")
        with mock.patch("socket.socket", return_value=fake_sock):
            entry = ar._scan_one_udp_port("1.2.3.4", 53, 1.0)
        assert entry["status"] == "closed"

    def test_open_filtered_on_timeout(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = socket.timeout("timed out")
        with mock.patch("socket.socket", return_value=fake_sock):
            entry = ar._scan_one_udp_port("1.2.3.4", 53, 1.0)
        assert entry["status"] == "open_filtered"

    def test_error_on_connect_failure(self):
        fake_sock = mock.MagicMock()
        fake_sock.connect.side_effect = OSError("network unreachable")
        with mock.patch("socket.socket", return_value=fake_sock):
            entry = ar._scan_one_udp_port("1.2.3.4", 53, 1.0)
        assert entry["status"] == "error"


class TestUdpScan:
    def test_default_ports_are_context_md_list(self):
        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.recv.side_effect = socket.timeout("timed out")
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.udp_scan(SAFE_IP)
        assert result["ports_scanned"] == sorted(ar.DEFAULT_UDP_PORTS)

    def test_open_persisted_high_confidence_open_filtered_low(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            def recv(n):
                if s.connect.call_args[0][0][1] == 53:
                    return b"resp"
                raise socket.timeout("timed out")
            s.recv.side_effect = recv
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.udp_scan(SAFE_IP, [53, 161], store=store)

        assert result["open_ports"] == [53]
        assert result["open_or_filtered_ports"] == [161]
        persisted = store.all()
        types = {p["type"]: p for p in persisted}
        assert types["open_udp_port"]["confidence"] == ar.CONFIDENCE_HIGH
        assert types["open_or_filtered_udp_port"]["confidence"] == ar.CONFIDENCE_LOW

    def test_closed_ports_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.recv.side_effect = ConnectionRefusedError("refused")
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            ar.udp_scan(SAFE_IP, [53], store=store)
        assert store.all() == []

    def test_empty_ports_list_raises(self):
        with pytest.raises(ValueError):
            ar.udp_scan(SAFE_IP, [])


# ---------------------------------------------------------------------------
# grab_banner
# ---------------------------------------------------------------------------

class TestGrabBanner:
    def test_found_banner_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b"220 ftp.example.com FTP ready\r\n"
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.grab_banner(SAFE_IP, 21, store=store)
        assert result["status"] == "found"
        assert "FTP ready" in result["banner"]
        assert len(store.all()) == 1
        assert store.all()[0]["type"] == "banner"

    def test_no_data_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b""
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.grab_banner(SAFE_IP, 80, store=store)
        assert result["status"] == "no_data"
        assert store.all() == []

    def test_timeout_is_no_data_not_error(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = socket.timeout("timed out")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.grab_banner(SAFE_IP, 80)
        assert result["status"] == "no_data"

    def test_sends_probe_when_given(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b"reply"
        with mock.patch("socket.socket", return_value=fake_sock):
            ar.grab_banner(SAFE_IP, 80, probe=b"GET / HTTP/1.0\r\n\r\n")
        fake_sock.sendall.assert_called_once_with(b"GET / HTTP/1.0\r\n\r\n")

    def test_connection_error_is_error_status(self):
        fake_sock = mock.MagicMock()
        fake_sock.connect.side_effect = ConnectionRefusedError("refused")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.grab_banner(SAFE_IP, 80)
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# identify_service
# ---------------------------------------------------------------------------

class TestIdentifyService:
    def test_banner_confirms_ssh_high_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        result = ar.identify_service(SAFE_IP, 22, banner="SSH-2.0-OpenSSH_9.6", store=store)
        assert result["service"] == "ssh"
        assert result["confidence"] == ar.CONFIDENCE_HIGH
        assert not result["conflict"]
        assert store.all()[0]["type"] == "service_identification"

    def test_port_only_guess_low_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        result = ar.identify_service(SAFE_IP, 22, banner=None, store=store)
        assert result["service"] == "ssh"
        assert result["confidence"] == ar.CONFIDENCE_LOW
        assert len(store.all()) == 1

    def test_conflicting_signals_flagged_not_silently_resolved(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        # Port 3306 (mysql) but banner clearly looks like SSH.
        result = ar.identify_service(SAFE_IP, 3306, banner="SSH-2.0-OpenSSH_9.6", store=store)
        assert result["conflict"] is True
        assert result["service"] is None
        assert result["port_guess"] == "mysql"
        assert result["banner_guess"] == "ssh"
        persisted = store.all()
        assert persisted[0]["type"] == "service_conflict"

    def test_no_signal_matched_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        result = ar.identify_service(SAFE_IP, 9999, banner="garbage", store=store)
        assert result["service"] is None
        assert not result["conflict"]
        assert store.all() == []


# ---------------------------------------------------------------------------
# smtp_probe (SMTP VRFY/EXPN)
# ---------------------------------------------------------------------------

class TestSmtpProbe:
    def test_vrfy_expn_enabled_high_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        responses = iter([
            b"220 mail.example.com ESMTP\r\n",  # banner
            b"250-mail.example.com\r\n",        # EHLO
            b"250 2.1.5 root <root@example.com>\r\n",  # VRFY
            b"250 2.1.5 root <root@example.com>\r\n",  # EXPN
        ])
        fake_sock.recv.side_effect = lambda n: next(responses, b"")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.smtp_probe(SAFE_IP, store=store)
        assert result["vrfy"]["supported"] is True
        assert result["expn"]["supported"] is True
        persisted = store.all()
        assert len(persisted) == 1
        assert persisted[0]["confidence"] == ar.CONFIDENCE_HIGH
        assert persisted[0]["metadata"]["exposed"] is True

    def test_vrfy_expn_disabled_low_confidence_still_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        responses = iter([
            b"220 mail.example.com ESMTP\r\n",
            b"250-mail.example.com\r\n",
            b"502 5.5.1 VRFY command is disabled\r\n",
            b"502 5.5.1 EXPN command is disabled\r\n",
        ])
        fake_sock.recv.side_effect = lambda n: next(responses, b"")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.smtp_probe(SAFE_IP, store=store)
        assert result["vrfy"]["supported"] is False
        assert result["expn"]["supported"] is False
        persisted = store.all()
        assert len(persisted) == 1
        assert persisted[0]["confidence"] == ar.CONFIDENCE_LOW
        assert persisted[0]["metadata"]["exposed"] is False

    def test_connection_error_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.connect.side_effect = OSError("refused")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.smtp_probe(SAFE_IP, store=store)
        assert result["status"] == "error"
        assert store.all() == []


# ---------------------------------------------------------------------------
# snmp_community_probe (SNMP community strings)
# ---------------------------------------------------------------------------

def _fake_snmp_response(community: bytes, sysdescr: bytes, request_id: int = 1) -> bytes:
    """
    Build an SNMP GetResponse.

    `request_id` must match the GetRequest being answered. snmp_community_probe
    numbers its requests 1..N in the order communities are tried, and credits a
    reply only to the request whose id it carries, so a fixture that hardcodes
    an id answers whichever community was tried in that position.
    """
    oid = ar._ber_tlv(0x06, ar._SYSDESCR_OID)
    val = ar._ber_tlv(0x04, sysdescr)
    varbind = ar._ber_tlv(0x30, oid + val)
    vbl = ar._ber_tlv(0x30, varbind)
    pdu_body = ar._ber_int(request_id) + ar._ber_int(0) + ar._ber_int(0) + vbl
    pdu = ar._ber_tlv(0xA2, pdu_body)
    return ar._ber_tlv(0x30, ar._ber_int(0) + ar._ber_tlv(0x04, community) + pdu)


class TestSnmpCommunityProbe:
    def test_accepted_community_extracts_sysdescr(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        # "private" is tried first (request-id 1) and times out; "public" is
        # tried second, so its answer must carry request-id 2.
        resp = _fake_snmp_response(b"public", b"Linux router 5.10", request_id=2)
        fake_sock.recvfrom.side_effect = [socket.timeout("t"), (resp, (SAFE_IP, 161))]
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.snmp_community_probe(SAFE_IP, communities=["private", "public"], store=store)

        assert len(result["accepted"]) == 1
        assert result["accepted"][0]["community"] == "public"
        assert result["accepted"][0]["sysdescr"] == "Linux router 5.10"
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_HIGH
        assert persisted[0]["metadata"]["exposed"] is True

    def test_no_community_accepted_low_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.recvfrom.side_effect = socket.timeout("timed out")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.snmp_community_probe(SAFE_IP, store=store)
        assert result["accepted"] == []
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_LOW
        assert persisted[0]["metadata"]["exposed"] is False

    def test_default_communities_are_public_private(self):
        fake_sock = mock.MagicMock()
        fake_sock.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.snmp_community_probe(SAFE_IP)
        assert result["communities_tried"] == ["public", "private"]

    def test_socket_error_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("socket.socket", side_effect=OSError("boom")):
            result = ar.snmp_community_probe(SAFE_IP, store=store)
        assert result["status"] == "error"
        assert store.all() == []


# ---------------------------------------------------------------------------
# ftp_anonymous_login_check
# ---------------------------------------------------------------------------

class TestFtpAnonymousLoginCheck:
    def test_login_succeeds_high_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        responses = iter([
            b"220 ftp.example.com FTP server ready\r\n",
            b"331 Please specify the password\r\n",
            b"230 Login successful\r\n",
        ])
        fake_sock.recv.side_effect = lambda n: next(responses, b"")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.ftp_anonymous_login_check(SAFE_IP, store=store)
        assert result["login_successful"] is True
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_HIGH
        assert persisted[0]["metadata"]["exposed"] is True

    def test_login_disabled_low_confidence_still_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        responses = iter([
            b"220 ftp.example.com FTP server ready\r\n",
            b"530 Login incorrect\r\n",
        ])
        fake_sock.recv.side_effect = lambda n: next(responses, b"")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.ftp_anonymous_login_check(SAFE_IP, store=store)
        assert result["login_successful"] is False
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_LOW
        assert persisted[0]["metadata"]["exposed"] is False

    def test_timeout_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = socket.timeout("timed out")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.ftp_anonymous_login_check(SAFE_IP, store=store)
        assert result["status"] == "error"
        assert store.all() == []


# ---------------------------------------------------------------------------
# ssh_fingerprint
# ---------------------------------------------------------------------------

class TestSshFingerprint:
    def test_parses_protocol_version_and_software(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.ssh_fingerprint(SAFE_IP, store=store)
        assert result["status"] == "found"
        assert result["protocol_version"] == "2.0"
        assert result["software"] == "OpenSSH_9.6p1"
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_HIGH

    def test_non_ssh_banner_still_found_medium_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b"not an ssh banner"
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.ssh_fingerprint(SAFE_IP, store=store)
        assert result["status"] == "found"
        assert result["software"] is None
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_MEDIUM

    def test_no_banner_not_found_still_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = socket.timeout("timed out")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.ssh_fingerprint(SAFE_IP, store=store)
        assert result["status"] == "not_found"
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_LOW

    def test_connection_error_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.connect.side_effect = OSError("refused")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.ssh_fingerprint(SAFE_IP, store=store)
        assert result["status"] == "error"
        assert store.all() == []


# ---------------------------------------------------------------------------
# check_ipmi_exposure
# ---------------------------------------------------------------------------

class TestCheckIpmiExposure:
    def test_presence_pong_confirms_exposure_critical(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        pong = bytes([0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x40, 0x00, 0x00, 0x10])
        fake_sock.recvfrom.return_value = (pong, (SAFE_IP, 623))
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.check_ipmi_exposure(SAFE_IP, store=store)
        assert result["exposed"] is True
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_HIGH
        assert persisted[0]["metadata"]["severity"] == "CRITICAL"

    def test_no_response_not_exposed_low_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        fake_sock.recvfrom.side_effect = socket.timeout("timed out")
        with mock.patch("socket.socket", return_value=fake_sock):
            result = ar.check_ipmi_exposure(SAFE_IP, store=store)
        assert result["exposed"] is False
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_LOW
        assert "severity" not in persisted[0]["metadata"]

    def test_socket_error_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("socket.socket", side_effect=OSError("boom")):
            result = ar.check_ipmi_exposure(SAFE_IP, store=store)
        assert result["status"] == "error"
        assert store.all() == []


# ---------------------------------------------------------------------------
# check_database_exposure
# ---------------------------------------------------------------------------

class TestCheckDatabaseExposure:
    def test_open_db_port_flagged_critical(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.side_effect = lambda addr: 0 if addr[1] == 3306 else 111
            s.recv.return_value = b"\x0a5.7.34-log\x00extra-handshake-bytes"
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.check_database_exposure(SAFE_IP, store=store)

        assert result["exposed_ports"] == [3306]
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_HIGH
        assert persisted[0]["metadata"]["severity"] == "CRITICAL"

    def test_no_open_db_ports_low_confidence_no_severity(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.return_value = 111
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.check_database_exposure(SAFE_IP, store=store)

        assert result["exposed_ports"] == []
        persisted = store.all()
        assert persisted[0]["confidence"] == ar.CONFIDENCE_LOW
        assert "severity" not in persisted[0]["metadata"]

    def test_default_ports_are_3306_and_5432(self):
        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.return_value = 111
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.check_database_exposure(SAFE_IP)
        assert sorted(int(p) for p in result["details"]) == [3306, 5432]


# ---------------------------------------------------------------------------
# fingerprint_os_ttl
# ---------------------------------------------------------------------------

class TestFingerprintOsTtl:
    def test_real_loopback_udp_ttl_sampling(self, tmp_path):
        """
        Uses a real UDP loopback socket (no mocking) because this
        specifically verifies a real kernel/ancillary-data interaction
        (IP_RECVTTL) that was empirically confirmed during implementation
        to behave differently for UDP vs TCP sockets. Loopback-only,
        no external network access.
        """
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(2.0)
        port = srv.getsockname()[1]

        import threading as _threading

        def respond():
            data, addr = srv.recvfrom(1024)
            srv.sendto(b"pong", addr)

        t = _threading.Thread(target=respond, daemon=True)
        t.start()

        result = ar.fingerprint_os_ttl("127.0.0.1", port, store=store, timeout=2.0)
        t.join(timeout=2.0)
        srv.close()

        assert result["status"] == "found"
        assert isinstance(result["ttl"], int)
        assert result["os_guess"] is not None
        persisted = store.all()
        assert len(persisted) == 1
        assert persisted[0]["confidence"] == ar.CONFIDENCE_LOW

    def test_no_response_not_found_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        # An unused loopback port: nothing listens, so no response arrives
        # and the call times out (no ICMP-refused path here since UDP
        # "connect" doesn't fail immediately without a prior response).
        result = ar.fingerprint_os_ttl("127.0.0.1", 1, store=store, timeout=0.3)
        assert result["status"] in ("not_found", "error")
        assert store.all() == []

    def test_unsupported_on_non_linux(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("sys.platform", "darwin"):
            result = ar.fingerprint_os_ttl(SAFE_IP, 623, store=store)
        assert result["status"] == "unsupported"
        assert store.all() == []


# ---------------------------------------------------------------------------
# detect_cross_host_port_pattern
# ---------------------------------------------------------------------------

class TestDetectCrossHostPortPattern:
    def test_unusual_shared_port_flagged(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        results = [
            {"ip": "10.0.0.1", "open_ports": [22, 80, 31337]},
            {"ip": "10.0.0.2", "open_ports": [22, 31337]},
            {"ip": "10.0.0.3", "open_ports": [22, 80]},
        ]
        pattern = ar.detect_cross_host_port_pattern(results, store=store)
        assert "31337" in pattern["patterns"]
        assert sorted(pattern["patterns"]["31337"]) == ["10.0.0.1", "10.0.0.2"]
        persisted = store.all()
        assert len(persisted) == 1
        assert persisted[0]["confidence"] == ar.CONFIDENCE_MEDIUM

    def test_common_ports_excluded(self):
        results = [
            {"ip": "10.0.0.1", "open_ports": [22, 80, 443]},
            {"ip": "10.0.0.2", "open_ports": [22, 80, 443]},
        ]
        pattern = ar.detect_cross_host_port_pattern(results)
        assert pattern["patterns"] == {}

    def test_below_min_hosts_not_flagged(self):
        results = [{"ip": "10.0.0.1", "open_ports": [31337]}]
        pattern = ar.detect_cross_host_port_pattern(results, min_hosts=2)
        assert pattern["patterns"] == {}

    def test_ignores_entries_without_ip(self):
        results = [{"open_ports": [31337]}, {"ip": "10.0.0.1", "open_ports": [31337]}]
        pattern = ar.detect_cross_host_port_pattern(results, min_hosts=2)
        assert pattern["patterns"] == {}


# ---------------------------------------------------------------------------
# run_active_recon (single-host orchestration)
# ---------------------------------------------------------------------------

class TestRunActiveRecon:
    def test_full_run_wires_tcp_findings_into_followups(self, tmp_path):
        output_dir = tmp_path / "output"

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            # socket.socket(family, type) — must key off the *type* (index 1),
            # not family: on Linux socket.AF_INET and socket.SOCK_DGRAM are
            # both numerically 2, so checking family alone misidentifies TCP
            # sockets as UDP.
            sock_type = a[1] if len(a) > 1 else kw.get("type")
            if sock_type == socket.SOCK_DGRAM:
                s.recvfrom.side_effect = socket.timeout("t")
                s.recv.side_effect = socket.timeout("t")
            else:
                s.connect_ex.side_effect = lambda addr: 0 if addr[1] == 22 else 111
                s.recv.return_value = b"SSH-2.0-OpenSSH_9.6\r\n"
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            summary = ar.run_active_recon(
                SAFE_IP, target="example.com", tcp_ports=[22, 80], output_dir=str(output_dir),
                timeout=0.5,
            )

        assert summary["ip"] == SAFE_IP
        assert summary["tcp"]["open_ports"] == [22]
        assert summary["ssh"] is not None
        assert summary["ssh"]["status"] == "found"
        assert summary["udp"]["ports_scanned"] == sorted(ar.DEFAULT_UDP_PORTS)
        assert os.path.exists(output_dir / "pending_assets.json")

        with open(output_dir / "pending_assets.json") as f:
            persisted = json.load(f)
        json.dumps(persisted)  # full store must be JSON-serializable
        assert len(persisted) >= 2  # at least open_tcp_port(22) + ssh_fingerprint

    def test_invalid_ip_raises_before_any_persistence(self, tmp_path):
        output_dir = tmp_path / "output"
        with pytest.raises(ar.ScopeError):
            ar.run_active_recon("not-an-ip", output_dir=str(output_dir))
        assert not (output_dir / "pending_assets.json").exists()

    def test_no_tcp_ports_skips_tcp_but_still_runs_udp_ipmi_db(self, tmp_path):
        output_dir = tmp_path / "output"

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.return_value = 111
            s.recv.side_effect = socket.timeout("t")
            s.recvfrom.side_effect = socket.timeout("t")
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            summary = ar.run_active_recon(SAFE_IP, output_dir=str(output_dir), timeout=0.3)

        assert summary["tcp"] == {}
        assert summary["udp"] != {}
        assert summary["ipmi"] is not None
        assert summary["db_exposure"] is not None

    def test_single_stage_failure_does_not_abort_run(self, tmp_path):
        output_dir = tmp_path / "output"
        with mock.patch("socket.socket", side_effect=RuntimeError("boom")):
            summary = ar.run_active_recon(
                SAFE_IP, tcp_ports=[22], output_dir=str(output_dir), timeout=0.3,
                check_ipmi_enabled=False, check_db_exposure_enabled=False,
            )
        assert summary["ip"] == SAFE_IP
        assert summary["finished_at"]
        assert len(summary["errors"]) >= 1


# ===========================================================================
# Regression coverage added by the Module 2 forensic audit.
#
# Each class below pins behaviour that was demonstrably wrong before the
# audit. Where a test encodes a *changed* semantic, its docstring states what
# the old behaviour was and why it was incorrect.
# ===========================================================================

import errno
import threading
import time


# ---------------------------------------------------------------------------
# Failure vs absence: connect_ex() errno classification
# ---------------------------------------------------------------------------

class TestTcpFailureIsNotAbsence:
    """
    connect_ex() reports failures as an errno return value instead of raising.
    Previously every non-zero return became "closed", so an unreachable
    network, a timeout, or a locally blocked probe was recorded as a
    confirmed-shut port — a failure silently presented as a negative result.
    """

    @pytest.mark.parametrize("code,expected", [
        (errno.ECONNREFUSED, ar.PORT_CLOSED),
        (errno.ECONNRESET, ar.PORT_CLOSED),
        (errno.ETIMEDOUT, ar.PORT_FILTERED),
        (errno.EAGAIN, ar.PORT_FILTERED),
        (errno.EHOSTUNREACH, ar.PORT_UNREACHABLE),
        (errno.ENETUNREACH, ar.PORT_UNREACHABLE),
        (errno.EHOSTDOWN, ar.PORT_UNREACHABLE),
        (errno.EACCES, ar.PORT_PERMISSION_DENIED),
        (errno.EPERM, ar.PORT_PERMISSION_DENIED),
    ])
    def test_errno_maps_to_distinct_status(self, code, expected):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = code
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_tcp_port("1.2.3.4", 80, 1.0)
        assert entry["status"] == expected

    def test_unreachable_is_never_reported_as_closed(self):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.EHOSTUNREACH
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_tcp_port("1.2.3.4", 80, 1.0)
        assert entry["status"] != ar.PORT_CLOSED
        assert entry["error"]  # the reason is preserved, not discarded

    def test_unknown_errno_is_error_not_closed(self):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ENOSYS
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_tcp_port("1.2.3.4", 80, 1.0)
        assert entry["status"] == ar.PORT_ERROR

    def test_oserror_with_errno_is_classified(self):
        fake = mock.MagicMock()
        fake.connect_ex.side_effect = OSError(errno.EHOSTUNREACH, "no route to host")
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_tcp_port("1.2.3.4", 80, 1.0)
        assert entry["status"] == ar.PORT_UNREACHABLE

    def test_bare_oserror_stays_error(self):
        """A failure with no errno carries no evidence about the port's state."""
        fake = mock.MagicMock()
        fake.connect_ex.side_effect = OSError("boom")
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_tcp_port("1.2.3.4", 80, 1.0)
        assert entry["status"] == ar.PORT_ERROR

    def test_summary_separates_closed_from_inconclusive(self):
        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.side_effect = lambda addr: {
                80: 0, 81: errno.ECONNREFUSED, 82: errno.EHOSTUNREACH,
                83: errno.ETIMEDOUT,
            }[addr[1]]
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.tcp_connect_scan(SAFE_IP, [80, 81, 82, 83])

        assert result["open_ports"] == [80]
        assert result["closed_ports"] == [81]
        assert result["not_conclusive_ports"] == [82, 83]
        # 82 failed outright; 83 was probed and stayed silent.
        assert result["failed_ports"] == [82]
        assert result["complete"] is True

    def test_probe_failure_ports_are_not_counted_as_closed(self):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.EHOSTUNREACH
        with mock.patch("socket.socket", return_value=fake):
            result = ar.tcp_connect_scan(SAFE_IP, [80, 443])
        assert result["closed_ports"] == []
        assert result["not_conclusive_ports"] == [80, 443]


# ---------------------------------------------------------------------------
# Port normalization / input validation
# ---------------------------------------------------------------------------

class TestNormalizePorts:
    def test_deduplicates_and_sorts(self):
        assert ar.normalize_ports([443, 80, 443, 80, 22]) == [22, 80, 443]

    @pytest.mark.parametrize("bad", [[0], [-1], [65536], [99999999]])
    def test_rejects_out_of_range(self, bad):
        with pytest.raises(ValueError):
            ar.normalize_ports(bad)

    @pytest.mark.parametrize("bad", [["80"], [80.5], [None], [b"80"], [{"port": 80}]])
    def test_rejects_non_integer(self, bad):
        with pytest.raises(ValueError):
            ar.normalize_ports(bad)

    def test_rejects_bool_disguised_as_int(self):
        """bool is an int subclass; True must not silently become port 1."""
        with pytest.raises(ValueError):
            ar.normalize_ports([True])

    @pytest.mark.parametrize("bad", ["80", 80, None, {"a": 1}])
    def test_rejects_non_list_container(self, bad):
        with pytest.raises(ValueError):
            ar.normalize_ports(bad)

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            ar.normalize_ports([])

    def test_accepts_boundary_ports(self):
        assert ar.normalize_ports([1, 65535]) == [1, 65535]


class TestDuplicatePortHandling:
    def test_duplicate_ports_are_scanned_and_persisted_once(self, tmp_path):
        """
        Previously a repeated port was probed once per occurrence and persisted
        once per occurrence, inflating both traffic to the target and the
        evidence recorded about it.
        """
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        calls = []

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            def connect_ex(addr):
                calls.append(addr[1])
                return 0
            s.connect_ex.side_effect = connect_ex
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.tcp_connect_scan(SAFE_IP, [80, 80, 80, 443], store=store)

        assert calls.count(80) == 1
        assert result["ports_scanned"] == [80, 443]
        assert result["open_ports"] == [80, 443]
        assert len(store.all()) == 2

    def test_invalid_port_type_raises_before_any_socket_is_opened(self):
        with mock.patch("socket.socket") as mocked:
            with pytest.raises(ValueError):
                ar.tcp_connect_scan(SAFE_IP, ["80"])
        mocked.assert_not_called()

    def test_probe_helper_does_not_raise_on_non_integer_port(self):
        """
        _scan_one_tcp_port is called directly by check_database_exposure, so a
        non-integer port must degrade to an error entry rather than raising an
        uncaught TypeError out of the module.
        """
        entry = ar._scan_one_tcp_port("127.0.0.1", "80", 0.2)
        assert entry["status"] == ar.PORT_ERROR
        assert "invalid port value" in entry["error"]


# ---------------------------------------------------------------------------
# Bounded concurrency / resource safety
# ---------------------------------------------------------------------------

class TestBoundedConcurrency:
    def test_worker_count_is_capped(self):
        assert ar._bounded_workers(100000, 5000) == ar.MAX_WORKERS_CAP
        assert ar._bounded_workers(10, 5000) == 10
        assert ar._bounded_workers(0, 5000) == 1
        assert ar._bounded_workers(-5, 5000) == 1

    def test_never_more_workers_than_ports(self):
        assert ar._bounded_workers(50, 3) == 3

    def test_non_numeric_worker_count_degrades_safely(self):
        assert ar._bounded_workers("many", 10) == 1

    def test_concurrent_sockets_stay_within_cap(self):
        live = {"n": 0}
        peak = {"n": 0}
        lock = threading.Lock()

        class CountingSocket:
            def __init__(self, *a, **kw):
                with lock:
                    live["n"] += 1
                    peak["n"] = max(peak["n"], live["n"])
                self._closed = False

            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                time.sleep(0.01)
                return errno.ECONNREFUSED

            def close(self):
                if not self._closed:
                    self._closed = True
                    with lock:
                        live["n"] -= 1

        with mock.patch("socket.socket", CountingSocket):
            ar.tcp_connect_scan(SAFE_IP, list(range(1, 401)), timeout=0.1, max_workers=100000)

        assert peak["n"] <= ar.MAX_WORKERS_CAP
        assert live["n"] == 0, "every socket must be closed"

    def test_worker_exception_does_not_lose_other_results(self):
        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            def connect_ex(addr):
                if addr[1] == 81:
                    raise RuntimeError("unexpected worker failure")
                return 0
            s.connect_ex.side_effect = connect_ex
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.tcp_connect_scan(SAFE_IP, [80, 81, 82])

        statuses = {r["port"]: r["status"] for r in result["results"]}
        assert statuses[80] == ar.PORT_OPEN
        assert statuses[82] == ar.PORT_OPEN
        assert statuses[81] == ar.PORT_ERROR
        assert result["ports_tested"] == 3

    def test_large_port_set_is_fully_accounted_for(self):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        with mock.patch("socket.socket", return_value=fake):
            result = ar.tcp_connect_scan(SAFE_IP, list(range(1, 1001)), max_workers=50)
        assert result["ports_tested"] == 1000
        assert result["complete"] is True
        assert len(result["closed_ports"]) == 1000


# ---------------------------------------------------------------------------
# Interruption / partial-result preservation
# ---------------------------------------------------------------------------

class TestInterruptionPreservesDiscoveries:
    """
    Persistence used to happen only after a scan finished, so a Ctrl-C threw
    away every confirmed open port the scan had already established.
    """

    @staticmethod
    def _interrupting_socket(after_n_calls):
        state = {"n": 0}

        class KISocket:
            def __init__(self, *a, **kw):
                pass

            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                state["n"] += 1
                if state["n"] > after_n_calls:
                    raise KeyboardInterrupt("user pressed ctrl-c")
                return 0

            def close(self):
                pass

        return KISocket

    def test_partial_findings_are_persisted_before_interrupt_propagates(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("socket.socket", self._interrupting_socket(5)):
            with pytest.raises(KeyboardInterrupt):
                ar.tcp_connect_scan(SAFE_IP, list(range(1, 60)),
                                    store=store, timeout=0.1, max_workers=2)
        persisted = store.all()
        assert persisted, "discoveries made before the interrupt must survive it"
        assert all(f["type"] == "open_tcp_port" for f in persisted)

    def test_keyboard_interrupt_still_propagates(self, tmp_path):
        """core/orchestrator.py relies on the interrupt reaching it."""
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("socket.socket", self._interrupting_socket(2)):
            with pytest.raises(KeyboardInterrupt):
                ar.tcp_connect_scan(SAFE_IP, list(range(1, 30)),
                                    store=store, timeout=0.1, max_workers=2)

    def test_udp_scan_persists_partial_results_on_interrupt(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        state = {"n": 0}

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            def recv(n):
                state["n"] += 1
                if state["n"] > 2:
                    raise KeyboardInterrupt()
                return b"response"
            s.recv.side_effect = recv
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            with pytest.raises(KeyboardInterrupt):
                ar.udp_scan(SAFE_IP, list(range(1, 40)), store=store,
                            timeout=0.1, max_workers=2)
        assert store.all()

    def test_run_active_recon_interrupt_carries_partial_summary(self, tmp_path):
        out = str(tmp_path / "output")
        with mock.patch("socket.socket", self._interrupting_socket(4)):
            with pytest.raises(ar.ActiveReconInterrupted) as excinfo:
                ar.run_active_recon("1.2.3.4", tcp_ports=list(range(1, 50)),
                                    output_dir=out, timeout=0.1)
        summary = excinfo.value.summary
        assert summary["status"] == ar.RUN_INTERRUPTED
        assert summary["interrupted"] is True
        # Stages that never ran are explicitly marked, not silently absent.
        assert any(s["status"] == ar.STAGE_NOT_REACHED for s in summary["stages"].values())
        assert ar.PendingAssetsStore(output_dir=out).all()

    def test_interrupt_exception_is_a_keyboard_interrupt(self):
        """
        core/orchestrator.py catches KeyboardInterrupt to mark a run
        interrupted and re-raise; the richer exception must still satisfy it.
        """
        assert issubclass(ar.ActiveReconInterrupted, KeyboardInterrupt)
        with pytest.raises(KeyboardInterrupt):
            raise ar.ActiveReconInterrupted({"status": ar.RUN_INTERRUPTED})


# ---------------------------------------------------------------------------
# Persistence: batching, durability, failure containment
# ---------------------------------------------------------------------------

class TestPersistenceHardening:
    def test_add_many_writes_all_records_once(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        findings = [ar.make_finding("open_tcp_port", "1.2.3.4", {"port": p}, ["e"], "HIGH")
                    for p in range(100)]
        assert store.add_many(findings) == 100
        assert len(store.all()) == 100

    def test_add_many_preserves_prior_records(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        first = ar.make_finding("dns_record", "example.com", {}, ["prior"], "HIGH")
        store.add(first)
        store.add_many([ar.make_finding("open_tcp_port", "1.2.3.4", {"port": 80}, ["e"], "HIGH")])
        records = store.all()
        assert len(records) == 2
        assert records[0] == first

    def test_add_many_empty_is_a_noop(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        assert store.add_many([]) == 0
        assert store.all() == []

    def test_add_many_is_all_or_nothing_on_write_failure(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add(ar.make_finding("dns_record", "example.com", {}, ["prior"], "HIGH"))
        findings = [ar.make_finding("open_tcp_port", "1.2.3.4", {"port": p}, ["e"], "HIGH")
                    for p in range(10)]
        with mock.patch("os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                store.add_many(findings)
        # The previous complete file is intact; the batch was not half-applied.
        assert len(store.all()) == 1

    def test_no_temp_file_left_behind_after_failed_batch(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                store.add_many([ar.make_finding("x", "y", {}, ["e"], "HIGH")])
        leftovers = [p for p in os.listdir(store.output_dir) if p.startswith(".pending_assets_")]
        assert leftovers == []

    def test_corrupt_state_blocks_batch_write_rather_than_overwriting(self, tmp_path):
        out = tmp_path / "output"
        out.mkdir()
        (out / "pending_assets.json").write_text("{not valid json")
        store = ar.PendingAssetsStore(output_dir=str(out))
        with pytest.raises(ar.PersistenceError):
            store.add_many([ar.make_finding("x", "y", {}, ["e"], "HIGH")])
        # The unreadable file is left untouched for an operator to inspect.
        assert (out / "pending_assets.json").read_text() == "{not valid json"

    def test_persistence_failure_does_not_discard_scan_results(self, tmp_path):
        class FailingStore(ar.PendingAssetsStore):
            def add_many(self, findings):
                raise ar.PersistenceError("disk full")

        store = FailingStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.connect_ex.return_value = 0
        with mock.patch("socket.socket", return_value=fake):
            result = ar.tcp_connect_scan(SAFE_IP, [80, 443], store=store)

        assert result["open_ports"] == [80, 443]
        assert "persistence_error" in result
        assert "disk full" in result["persistence_error"]

    def test_findings_remain_json_serializable(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        store.add_many([ar.make_finding("open_tcp_port", "1.2.3.4", {"port": 80}, ["e"], "HIGH")])
        json.dumps(store.all())


# ---------------------------------------------------------------------------
# SNMP correlation: response misattribution and false acceptance
# ---------------------------------------------------------------------------

class TestSnmpResponseCorrelation:
    """
    Acceptance of a community string used to be inferred from "a datagram
    arrived". Because all probes shared one socket and UDP has no ordering
    guarantee, a slow reply to the first community was read by the next
    recv and credited to the wrong community; and any non-SNMP noise counted
    as acceptance outright.
    """

    def test_late_reply_is_not_credited_to_the_next_community(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        # A GetResponse for request-id 1 ("public") arriving while request-id 2
        # ("private") is being awaited.
        stale = _fake_snmp_response(b"public", b"Only public works", request_id=1)
        fake = mock.MagicMock()
        fake.recvfrom.side_effect = [
            socket.timeout("t"),          # "public" itself times out
            (stale, (SAFE_IP, 161)),      # late reply lands in "private"'s window
            socket.timeout("t"),          # "private" then times out for real
        ]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.snmp_community_probe(SAFE_IP, communities=["public", "private"], store=store)

        assert [a["community"] for a in result["accepted"]] == []
        reasons = [u["reason"] for u in result["unverified_responses"]]
        assert "request-id mismatch" in reasons

    def test_non_snmp_datagram_is_not_acceptance(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recvfrom.side_effect = [
            (b"\xff\xff\xff\xff\x00 not snmp at all", (SAFE_IP, 161)),
            socket.timeout("t"),
            socket.timeout("t"),
        ]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.snmp_community_probe(SAFE_IP, communities=["public"], store=store)

        assert result["accepted"] == []
        assert result["unverified_responses"]
        assert result["unverified_responses"][0]["reason"] == "not a valid SNMP GetResponse"
        assert store.all()[0]["metadata"]["exposed"] is False

    def test_reply_from_a_different_host_is_rejected(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        resp = _fake_snmp_response(b"public", b"impostor", request_id=1)
        fake = mock.MagicMock()
        fake.recvfrom.side_effect = [
            (resp, ("203.0.113.9", 161)),   # not the host we probed
            socket.timeout("t"),
        ]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.snmp_community_probe(SAFE_IP, communities=["public"], store=store)

        assert result["accepted"] == []
        assert result["unverified_responses"][0]["reason"] == "source address mismatch"

    def test_correlated_reply_is_accepted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        resp = _fake_snmp_response(b"public", b"Linux router 5.10", request_id=1)
        fake = mock.MagicMock()
        fake.recvfrom.side_effect = [(resp, (SAFE_IP, 161)), socket.timeout("t")]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.snmp_community_probe(SAFE_IP, communities=["public", "private"], store=store)

        assert [a["community"] for a in result["accepted"]] == ["public"]
        assert result["accepted"][0]["sysdescr"] == "Linux router 5.10"
        assert store.all()[0]["confidence"] == ar.CONFIDENCE_HIGH

    def test_truncated_ber_does_not_raise(self):
        assert ar._snmp_parse_get_response(b"\x30\x82\xff\xff") is None
        assert ar._snmp_parse_get_response(b"") is None
        assert ar._snmp_parse_get_response(b"\x30") is None

    def test_non_getresponse_pdu_is_rejected(self):
        """A GetRequest echoed back is not a GetResponse."""
        packet = ar._snmp_build_get_request("public", request_id=1)
        assert ar._snmp_parse_get_response(packet) is None

    def test_ber_reader_rejects_length_beyond_buffer(self):
        with pytest.raises(ValueError):
            ar._ber_read_tlv(b"\x04\x10ab", 0)


# ---------------------------------------------------------------------------
# Banner handling: control characters, binary, oversized, empty
# ---------------------------------------------------------------------------

class TestBannerSanitization:
    @staticmethod
    def _serving_socket(payload):
        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.recv.return_value = payload
            return s
        return fake_socket

    def test_ansi_and_control_characters_are_stripped(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        payload = b"\x1b[2J\x1b[31mSSH-2.0-OpenSSH_8.9\x07\x00"
        with mock.patch("socket.socket", side_effect=self._serving_socket(payload)):
            result = ar.grab_banner(SAFE_IP, 22, store=store)

        assert "\x1b" not in result["banner"]
        assert "\x00" not in result["banner"]
        assert "\x07" not in result["banner"]
        assert "SSH-2.0-OpenSSH_8.9" in result["banner"]
        assert result["sanitized"] is True

    def test_raw_bytes_are_preserved_as_evidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        payload = b"\x1b[31mred"
        with mock.patch("socket.socket", side_effect=self._serving_socket(payload)):
            ar.grab_banner(SAFE_IP, 22, store=store)
        finding = store.all()[0]
        assert finding["metadata"]["banner_hex"] == payload.hex()
        assert finding["metadata"]["sanitized"] is True
        assert any("control characters" in e for e in finding["evidence"])

    def test_clean_banner_is_not_flagged_as_sanitized(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("socket.socket", side_effect=self._serving_socket(b"220 ESMTP ready\r\n")):
            result = ar.grab_banner(SAFE_IP, 25, store=store)
        assert result["banner"] == "220 ESMTP ready"
        assert result["sanitized"] is False

    def test_binary_only_response_is_not_reported_as_a_banner(self):
        """
        Bytes that reduce to nothing printable are not a service banner;
        reporting status "found" with an empty banner would assert an identity
        the response does not support.
        """
        with mock.patch("socket.socket", side_effect=self._serving_socket(b"\x00\x01\x02\x03")):
            result = ar.grab_banner(SAFE_IP, 22)
        assert result["status"] == "no_data"
        assert result["banner"] is None

    def test_empty_response_is_no_data(self):
        with mock.patch("socket.socket", side_effect=self._serving_socket(b"")):
            result = ar.grab_banner(SAFE_IP, 22)
        assert result["status"] == "no_data"

    def test_oversized_banner_is_bounded(self):
        with mock.patch("socket.socket", side_effect=self._serving_socket(b"A" * 100000)):
            result = ar.grab_banner(SAFE_IP, 22)
        assert len(result["banner"]) <= 2048

    def test_unicode_banner_survives(self):
        payload = "220 mail.münchen.example ESMTP".encode("utf-8")
        with mock.patch("socket.socket", side_effect=self._serving_socket(payload)):
            result = ar.grab_banner(SAFE_IP, 25)
        assert "münchen" in result["banner"]

    def test_invalid_utf8_does_not_raise(self):
        with mock.patch("socket.socket", side_effect=self._serving_socket(b"220 \xff\xfe ESMTP")):
            result = ar.grab_banner(SAFE_IP, 25)
        assert result["status"] == "found"
        json.dumps(result)

    def test_sanitized_banner_is_json_serializable(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        with mock.patch("socket.socket", side_effect=self._serving_socket(b"\x1b[2Jx\x00")):
            ar.grab_banner(SAFE_IP, 22, store=store)
        json.dumps(store.all())


# ---------------------------------------------------------------------------
# Service identification: real vs spurious conflicts
# ---------------------------------------------------------------------------

class TestServiceConflictAccuracy:
    def test_smtp_submission_banner_is_not_a_conflict(self, tmp_path):
        """
        Port 587's port-heuristic name is "smtp-submission" while every real
        server there greets with a generic SMTP banner. Previously that
        mismatch was recorded as an unresolved service conflict for every
        correctly configured mail submission host, polluting the graph's
        conflict model (context.md §8) with a non-conflict.
        """
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        result = ar.identify_service(SAFE_IP, 587, banner="220 mail.example.com ESMTP Postfix",
                                     store=store, target="example.com")
        assert result["conflict"] is False
        assert result["service"] == "smtp-submission"
        assert result["confidence"] == ar.CONFIDENCE_HIGH
        assert store.all()[0]["type"] == "service_identification"

    def test_genuine_mismatch_is_still_a_conflict(self, tmp_path):
        """SSH answering on the FTP port is a real disagreement and must survive."""
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        result = ar.identify_service(SAFE_IP, 21, banner="SSH-2.0-OpenSSH_8.9",
                                     store=store, target="example.com")
        assert result["conflict"] is True
        assert result["service"] is None
        assert result["confidence"] == ar.CONFIDENCE_LOW
        assert store.all()[0]["type"] == "service_conflict"

    def test_port_25_smtp_banner_agrees(self):
        result = ar.identify_service(SAFE_IP, 25, banner="220 mail ESMTP Postfix")
        assert result["conflict"] is False
        assert result["service"] == "smtp"

    def test_port_only_guess_stays_low_confidence(self):
        """A port number alone is a weak prior, never a confirmed service."""
        result = ar.identify_service(SAFE_IP, 3306, banner=None)
        assert result["service"] == "mysql"
        assert result["confidence"] == ar.CONFIDENCE_LOW
        assert result["banner_guess"] is None

    def test_unknown_port_without_banner_identifies_nothing(self):
        result = ar.identify_service(SAFE_IP, 47111, banner=None)
        assert result["service"] is None
        assert result["confidence"] == ar.CONFIDENCE_LOW

    def test_service_family_helper(self):
        assert ar._same_service_family("smtp", "smtp-submission") is True
        assert ar._same_service_family("smtp", "ssh") is False
        assert ar._same_service_family(None, "smtp") is False


# ---------------------------------------------------------------------------
# Database exposure: failure is not a clean bill of health
# ---------------------------------------------------------------------------

class TestDatabaseExposureSemantics:
    def test_unreachable_db_port_is_inconclusive_not_absent(self, tmp_path):
        """
        A DB port that could not be probed must not be reported as "not
        reachable" — context.md treats exposed DB ports as auto-CRITICAL, so a
        false negative here is the most costly kind.
        """
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.EHOSTUNREACH
        with mock.patch("socket.socket", return_value=fake):
            result = ar.check_database_exposure(SAFE_IP, store=store, target="example.com")

        assert result["exposed_ports"] == []
        assert result["inconclusive_ports"] == [3306, 5432]
        finding = store.all()[0]
        assert finding["metadata"]["inconclusive_ports"] == [3306, 5432]
        assert any("not evidence that they are closed" in e for e in finding["evidence"])

    def test_closed_db_ports_are_a_genuine_negative_result(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        with mock.patch("socket.socket", return_value=fake):
            result = ar.check_database_exposure(SAFE_IP, store=store)

        assert result["inconclusive_ports"] == []
        finding = store.all()[0]
        assert "inconclusive_ports" not in finding["metadata"]
        assert finding["confidence"] == ar.CONFIDENCE_LOW

    def test_exposed_db_port_is_critical(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def fake_socket(*a, **kw):
            s = mock.MagicMock()
            s.connect_ex.side_effect = lambda addr: 0 if addr[1] == 3306 else errno.ECONNREFUSED
            s.recv.return_value = b"5.7.30-log"
            return s

        with mock.patch("socket.socket", side_effect=fake_socket):
            result = ar.check_database_exposure(SAFE_IP, store=store)

        assert result["exposed_ports"] == [3306]
        finding = store.all()[0]
        assert finding["metadata"]["severity"] == "CRITICAL"
        assert finding["confidence"] == ar.CONFIDENCE_HIGH

    def test_rejects_out_of_scope_target(self):
        with pytest.raises(ar.ScopeError):
            ar.check_database_exposure("example.com")

    def test_rejects_invalid_port_type(self):
        with pytest.raises(ValueError):
            ar.check_database_exposure(SAFE_IP, ports=["3306"])


# ---------------------------------------------------------------------------
# run_active_recon completeness semantics
# ---------------------------------------------------------------------------

class TestRunActiveReconCompleteness:
    def test_total_failure_is_not_reported_as_a_clean_empty_scan(self, tmp_path):
        """
        The probe helpers absorb network failures into their return values, so
        "did not raise" is not evidence a check succeeded. Without stage
        accounting, a wholly unreachable host produced the same empty summary
        as a healthy host with nothing exposed.
        """
        with mock.patch("socket.socket", side_effect=OSError("network is down")):
            summary = ar.run_active_recon("1.2.3.4", tcp_ports=[22, 80],
                                          output_dir=str(tmp_path / "o"), timeout=0.1)
        assert summary["status"] == ar.RUN_COMPLETED_WITH_ERRORS
        assert summary["stages"]["tcp_scan"]["status"] == ar.STAGE_INCONCLUSIVE
        assert summary["stages"]["udp_scan"]["status"] == ar.STAGE_INCONCLUSIVE
        assert summary["stages"]["tcp_scan"]["reason"]

    def test_clean_scan_with_no_findings_is_reported_completed(self, tmp_path):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        fake.recv.side_effect = socket.timeout("t")
        fake.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            summary = ar.run_active_recon("1.2.3.4", tcp_ports=[22, 80],
                                          output_dir=str(tmp_path / "o"), timeout=0.1)
        assert summary["status"] == ar.RUN_COMPLETED
        assert summary["stages"]["tcp_scan"]["status"] == ar.STAGE_COMPLETED

    def test_udp_silence_is_an_observation_not_a_stage_failure(self, tmp_path):
        """
        UDP silence is ambiguous by nature ("open_filtered"), but the probe did
        run. Treating it as a failed stage would mark almost every real scan
        of a firewalled host as degraded.
        """
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        fake.recv.side_effect = socket.timeout("t")
        fake.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            summary = ar.run_active_recon("1.2.3.4", output_dir=str(tmp_path / "o"), timeout=0.1)
        assert summary["stages"]["udp_scan"]["status"] == ar.STAGE_COMPLETED
        assert summary["udp"]["open_or_filtered_ports"] == sorted(ar.DEFAULT_UDP_PORTS)

    def test_skipped_stages_record_why(self, tmp_path):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        fake.recv.side_effect = socket.timeout("t")
        fake.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            summary = ar.run_active_recon("1.2.3.4", output_dir=str(tmp_path / "o"),
                                          timeout=0.1, check_ipmi_enabled=False)
        assert summary["stages"]["tcp_scan"]["status"] == ar.STAGE_SKIPPED
        assert "no tcp_ports supplied" in summary["stages"]["tcp_scan"]["reason"]
        assert summary["stages"]["ipmi"]["status"] == ar.STAGE_SKIPPED
        assert summary["stages"]["ftp"]["status"] == ar.STAGE_SKIPPED
        # A skipped check is not a failure.
        assert summary["status"] == ar.RUN_COMPLETED

    def test_stage_failure_is_recorded_and_contained(self, tmp_path):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        fake.recv.side_effect = socket.timeout("t")
        fake.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            with mock.patch.object(ar, "check_ipmi_exposure", side_effect=RuntimeError("boom")):
                summary = ar.run_active_recon("1.2.3.4", output_dir=str(tmp_path / "o"), timeout=0.1)
        assert summary["stages"]["ipmi"]["status"] == ar.STAGE_FAILED
        assert summary["status"] == ar.RUN_COMPLETED_WITH_ERRORS
        # Unrelated work still ran.
        assert summary["stages"]["db_exposure"]["status"] == ar.STAGE_COMPLETED
        assert any(e["stage"] == "ipmi" for e in summary["errors"])

    def test_summary_is_json_serializable(self, tmp_path):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        fake.recv.side_effect = socket.timeout("t")
        fake.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            summary = ar.run_active_recon("1.2.3.4", tcp_ports=[80],
                                          output_dir=str(tmp_path / "o"), timeout=0.1)
        json.dumps(summary)

    def test_scope_is_enforced_before_any_socket_is_created(self, tmp_path):
        with mock.patch("socket.socket") as mocked:
            with pytest.raises(ar.ScopeError):
                ar.run_active_recon("example.com", output_dir=str(tmp_path / "o"))
        mocked.assert_not_called()


# ---------------------------------------------------------------------------
# Downstream integration: Surface Mapper -> Risk Engine -> Report Generator
#
# These exercise the real downstream modules rather than mocks, because the
# defect they pin was invisible to every unit test on either side: each module
# was self-consistent and the contract between them was not.
# ---------------------------------------------------------------------------

from reconhound import surface_mapper as sm
from reconhound import risk_engine as rk


def _signals_for(findings, target="example.com", output_dir=None):
    mapper = sm.SurfaceMapper(target=target, output_dir=output_dir)
    mapper.ingest_many(findings)
    return mapper, rk.extract_signals(mapper.state, [])


class TestSmtpFindingReachesRiskEngine:
    def test_vrfy_exposure_produces_a_scored_signal(self, tmp_path):
        """
        risk_engine.py's smtp_user_enumeration rule matches on flat
        `vrfy_supported`/`expn_supported` keys. active_recon emitted only the
        nested {"vrfy": {"supported": ...}} form, so a confirmed VRFY/EXPN
        exposure arrived as an "unclassified" signal and was never scored.
        Verified against the real risk engine, not a fixture.
        """
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recv.side_effect = [
            b"220 mail.example.com ESMTP\r\n",
            b"250 ok\r\n",
            b"250 root@example.com\r\n",   # VRFY accepted
            b"250 root@example.com\r\n",   # EXPN accepted
        ]
        with mock.patch("socket.socket", return_value=fake):
            ar.smtp_probe(SAFE_IP, store=store, target="example.com")

        finding = store.all()[0]
        assert finding["value"]["vrfy_supported"] is True
        # The nested form is preserved for existing consumers.
        assert finding["value"]["vrfy"]["supported"] is True

        _, signals = _signals_for([finding], output_dir=str(tmp_path / "sm"))
        categories = {s.get("category") for s in signals}
        assert "smtp_user_enumeration" in categories
        assert not any(str(c).startswith("unclassified") for c in categories)

    def test_smtp_without_exposure_produces_no_enumeration_signal(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recv.side_effect = [
            b"220 mail ESMTP\r\n", b"250 ok\r\n",
            b"502 VRFY disabled\r\n", b"502 EXPN disabled\r\n",
        ]
        with mock.patch("socket.socket", return_value=fake):
            ar.smtp_probe(SAFE_IP, store=store)
        finding = store.all()[0]
        assert finding["value"]["vrfy_supported"] is False
        _, signals = _signals_for([finding], output_dir=str(tmp_path / "sm"))
        assert "smtp_user_enumeration" not in {s.get("category") for s in signals}


class TestActiveReconFindingsIngestCleanly:
    """Every finding type this module emits must survive the real graph."""

    def _all_finding_types(self):
        return [
            ar.make_finding("open_tcp_port", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 22, "protocol": "tcp"}, ["e"], "HIGH",
                            {"ip": "1.2.3.4", "port": 22, "protocol": "tcp", "ip_version": 4}),
            ar.make_finding("open_udp_port", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 161, "protocol": "udp", "response_hex": "30"},
                            ["e"], "HIGH", {"ip": "1.2.3.4", "port": 161, "protocol": "udp"}),
            ar.make_finding("open_or_filtered_udp_port", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 500, "protocol": "udp"}, ["e"], "LOW",
                            {"ip": "1.2.3.4", "port": 500, "protocol": "udp", "ambiguous": True}),
            ar.make_finding("banner", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9"},
                            ["e"], "HIGH",
                            {"ip": "1.2.3.4", "port": 22, "banner_hex": "5353", "sanitized": False}),
            ar.make_finding("service_identification", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 587, "protocol": "tcp",
                             "service": "smtp-submission", "port_guess": "smtp-submission",
                             "banner_guess": "smtp"}, ["e"], "HIGH",
                            {"ip": "1.2.3.4", "port": 587, "protocol": "tcp"}),
            ar.make_finding("ssh_fingerprint", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9",
                             "protocol_version": "2.0", "software": "OpenSSH_8.9"},
                            ["e"], "HIGH", {"ip": "1.2.3.4", "port": 22}),
            ar.make_finding("ftp_anonymous_access", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 21, "login_successful": True,
                             "banner": "220 ftp"}, ["e"], "HIGH",
                            {"ip": "1.2.3.4", "port": 21, "exposed": True}),
            ar.make_finding("snmp_exposure", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 161,
                             "accepted": [{"community": "public", "error_status": 0,
                                           "sysdescr": "Linux"}],
                             "communities_tried": ["public", "private"]}, ["e"], "HIGH",
                            {"ip": "1.2.3.4", "port": 161, "exposed": True}),
            ar.make_finding("ipmi_exposure", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 623, "exposed": True}, ["e"], "HIGH",
                            {"ip": "1.2.3.4", "port": 623, "severity": "CRITICAL"}),
            ar.make_finding("db_exposure", "1.2.3.4",
                            {"ip": "1.2.3.4", "exposed_ports": [3306],
                             "inconclusive_ports": [5432], "details": {}}, ["e"], "HIGH",
                            {"ip": "1.2.3.4", "ports_checked": [3306, 5432],
                             "severity": "CRITICAL", "inconclusive_ports": [5432]}),
            ar.make_finding("os_fingerprint", "1.2.3.4",
                            {"ip": "1.2.3.4", "ttl": 54, "os_guess": "Linux/Unix-like"},
                            ["e"], "LOW",
                            {"ip": "1.2.3.4", "port": 161, "method": "ttl_only_udp",
                             "initial_ttl_baseline": 64, "estimated_hops": 10,
                             "may_be_intermediary": True}),
            ar.make_finding("smtp_enumeration", "1.2.3.4",
                            {"ip": "1.2.3.4", "port": 25,
                             "vrfy": {"supported": True, "response": "250"},
                             "expn": {"supported": False, "response": "502"},
                             "vrfy_supported": True, "expn_supported": False},
                            ["e"], "HIGH", {"ip": "1.2.3.4", "port": 25, "exposed": True}),
            ar.make_finding("cross_host_port_pattern", "multiple_hosts",
                            {"port": 44818, "hosts": ["1.2.3.4", "1.2.3.5"], "host_count": 2},
                            ["e"], "MEDIUM", {"port": 44818, "host_count": 2}),
        ]

    def test_surface_mapper_ingests_every_type_without_error(self, tmp_path):
        mapper, _ = _signals_for(self._all_finding_types(), output_dir=str(tmp_path / "sm"))
        summary = mapper.summary()
        assert summary  # graph built
        json.dumps(mapper.state)

    def test_risk_engine_scores_the_critical_findings(self, tmp_path):
        _, signals = _signals_for(self._all_finding_types(), output_dir=str(tmp_path / "sm"))
        categories = {s.get("category") for s in signals}
        assert "ipmi_exposure" in categories
        assert "database_port_exposure" in categories
        assert "anonymous_ftp_access" in categories
        assert "snmp_default_community" in categories
        assert "smtp_user_enumeration" in categories

    def test_no_active_recon_finding_arrives_unclassified(self, tmp_path):
        _, signals = _signals_for(self._all_finding_types(), output_dir=str(tmp_path / "sm"))
        unclassified = sorted(
            s.get("category") for s in signals
            if str(s.get("category", "")).startswith("unclassified")
        )
        assert unclassified == [], f"unclassified signals reaching risk engine: {unclassified}"

    def test_ambiguous_udp_finding_keeps_low_confidence_downstream(self, tmp_path):
        """
        A UDP port that only produced silence must not gain confidence on its
        way through the graph.
        """
        finding = ar.make_finding(
            "open_or_filtered_udp_port", "1.2.3.4",
            {"ip": "1.2.3.4", "port": 500, "protocol": "udp"},
            ["no response and no ICMP unreachable"], ar.CONFIDENCE_LOW,
            {"ip": "1.2.3.4", "port": 500, "protocol": "udp", "ambiguous": True})
        mapper, _ = _signals_for([finding], output_dir=str(tmp_path / "sm"))
        asset = mapper.get_asset("port:1.2.3.4:500:udp")
        assert asset["attributes"]["status"]["confidence"] == ar.CONFIDENCE_LOW

    def test_report_generator_renders_active_recon_findings(self, tmp_path):
        from reconhound import report_generator as rg
        out = tmp_path / "out"
        out.mkdir()
        mapper = sm.SurfaceMapper(target="example.com", output_dir=str(out))
        mapper.ingest_many(self._all_finding_types())
        mapper.save()
        rk.run_risk_engine(output_dir=str(out))
        result = rg.generate_report(output_dir=str(out))

        assert not result["errors"], result["errors"]
        paths = result["output_paths"]
        html_path = paths["html"]
        assert os.path.exists(html_path)
        html = open(html_path, encoding="utf-8").read()
        # The auto-CRITICAL findings this module produces must be present.
        assert "ipmi" in html.lower()
        assert "3306" in html
        # And the JSON export must round-trip.
        with open(paths["json"], encoding="utf-8") as fh:
            json.load(fh)

    def test_banner_control_characters_never_reach_the_report(self, tmp_path):
        """
        A banner is attacker-controlled text that ends up in the terminal, the
        JSON state file and the HTML report.
        """
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recv.return_value = b"\x1b[2J\x1b[31mEVIL\x00\x07 SSH-2.0-x"
        with mock.patch("socket.socket", return_value=fake):
            ar.grab_banner(SAFE_IP, 22, store=store, target="example.com")
        mapper, _ = _signals_for(store.all(), output_dir=str(tmp_path / "sm"))
        serialized = json.dumps(mapper.state)
        assert "\\u001b" not in serialized
        assert "\\u0000" not in serialized


# ---------------------------------------------------------------------------
# UDP semantics — only what a connected UDP socket can actually observe
# ---------------------------------------------------------------------------

class TestUdpObservableSemantics:
    def test_icmp_port_unreachable_on_recv_is_closed(self):
        fake = mock.MagicMock()
        fake.recv.side_effect = ConnectionRefusedError("port unreachable")
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_udp_port(SAFE_IP, 53, 0.5)
        assert entry["status"] == ar.PORT_CLOSED

    def test_icmp_reported_on_send_is_also_closed(self):
        """A queued ICMP error can surface on the next send rather than recv."""
        fake = mock.MagicMock()
        fake.send.side_effect = ConnectionRefusedError("port unreachable")
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_udp_port(SAFE_IP, 53, 0.5)
        assert entry["status"] == ar.PORT_CLOSED

    def test_silence_is_ambiguous_not_open(self):
        fake = mock.MagicMock()
        fake.recv.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_udp_port(SAFE_IP, 500, 0.5)
        assert entry["status"] == ar.UDP_OPEN_FILTERED

    def test_unreachable_host_is_not_open_filtered(self):
        fake = mock.MagicMock()
        fake.connect.side_effect = OSError(errno.EHOSTUNREACH, "no route")
        with mock.patch("socket.socket", return_value=fake):
            entry = ar._scan_one_udp_port(SAFE_IP, 500, 0.5)
        assert entry["status"] == ar.PORT_UNREACHABLE

    def test_ambiguous_result_is_persisted_at_low_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recv.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            result = ar.udp_scan(SAFE_IP, [500], store=store)
        finding = store.all()[0]
        assert finding["type"] == "open_or_filtered_udp_port"
        assert finding["confidence"] == ar.CONFIDENCE_LOW
        assert finding["metadata"]["ambiguous"] is True
        assert result["open_ports"] == []

    def test_responding_udp_port_is_high_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recv.return_value = b"\x30\x82"
        with mock.patch("socket.socket", return_value=fake):
            result = ar.udp_scan(SAFE_IP, [161], store=store)
        finding = store.all()[0]
        assert finding["type"] == "open_udp_port"
        assert finding["confidence"] == ar.CONFIDENCE_HIGH
        assert result["open_ports"] == [161]

    def test_default_ports_match_context_md(self):
        assert ar.DEFAULT_UDP_PORTS == [53, 161, 500, 623]

    def test_udp_ports_are_normalized(self):
        fake = mock.MagicMock()
        fake.recv.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            result = ar.udp_scan(SAFE_IP, [53, 53, 161])
        assert result["ports_scanned"] == [53, 161]

    def test_udp_rejects_invalid_ports(self):
        with pytest.raises(ValueError):
            ar.udp_scan(SAFE_IP, [0])


# ---------------------------------------------------------------------------
# Scope enforcement (security boundary)
# ---------------------------------------------------------------------------

class TestScopeEnforcementBoundary:
    @pytest.mark.parametrize("bad", [
        "example.com", "93.184.216.0/24", "::1", "", "   ", None, 123,
        "999.999.999.999", "1.2.3.4:80", "1.2.3.4 8.8.8.8",
    ])
    def test_ipv4_entry_points_reject_out_of_scope_targets(self, bad):
        with mock.patch("socket.socket") as mocked:
            for fn in (ar.tcp_connect_scan, ar.udp_scan):
                with pytest.raises((ar.ScopeError, ValueError, TypeError)):
                    fn(bad, [80])
        mocked.assert_not_called()

    def test_cidr_is_never_expanded_into_a_range(self):
        """A single call must never fan out into scanning a whole network."""
        with pytest.raises(ar.ScopeError):
            ar.validate_scan_target("10.0.0.0/8")

    def test_hostname_is_rejected_rather_than_resolved(self):
        with mock.patch("socket.gethostbyname") as resolver:
            with pytest.raises(ar.ScopeError):
                ar.validate_scan_target("example.com")
        resolver.assert_not_called()

    def test_ipv6_helper_rejects_ipv4_and_vice_versa(self):
        with pytest.raises(ar.ScopeError):
            ar.validate_ipv6_scan_target("1.2.3.4")
        with pytest.raises(ar.ScopeError):
            ar.validate_scan_target("2606:2800:220:1:248:1893:25c8:1946")

    def test_no_socket_is_created_for_a_rejected_target(self):
        calls = [
            (ar.check_database_exposure, ("not-an-ip",)),
            (ar.udp_scan, ("not-an-ip",)),
            (ar.tcp_connect_scan, ("not-an-ip", [80])),
            (ar.ipv6_tcp_connect_scan, ("not-an-ip", [80])),
            (ar.run_active_recon, ("not-an-ip",)),
        ]
        with mock.patch("socket.socket") as mocked:
            for fn, args in calls:
                with pytest.raises(ar.ScopeError):
                    fn(*args)
        mocked.assert_not_called()

    def test_scope_is_checked_before_port_validation(self):
        """An out-of-scope target must be refused even with invalid ports."""
        with pytest.raises(ar.ScopeError):
            ar.tcp_connect_scan("not-an-ip", ["bogus"])


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------

class TestIpv6ScanHardening:
    def test_ipv6_scan_normalizes_and_reports_completeness(self):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        with mock.patch("socket.socket", return_value=fake):
            result = ar.ipv6_tcp_connect_scan(SAFE_IPV6, [443, 443, 80])
        assert result["ports_scanned"] == [80, 443]
        assert result["closed_ports"] == [80, 443]
        assert result["complete"] is True
        assert result["ip_version"] == 6

    def test_ipv6_unreachable_is_not_closed(self):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ENETUNREACH
        with mock.patch("socket.socket", return_value=fake):
            result = ar.ipv6_tcp_connect_scan(SAFE_IPV6, [443])
        assert result["closed_ports"] == []
        assert result["not_conclusive_ports"] == [443]

    def test_ipv6_findings_are_tagged_ip_version_6(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.connect_ex.return_value = 0
        with mock.patch("socket.socket", return_value=fake):
            ar.ipv6_tcp_connect_scan(SAFE_IPV6, [443], store=store)
        finding = store.all()[0]
        assert finding["metadata"]["ip_version"] == 6
        assert f"[{SAFE_IPV6}]" in finding["evidence"][0]

    def test_ipv6_rejects_invalid_ports(self):
        with pytest.raises(ValueError):
            ar.ipv6_tcp_connect_scan(SAFE_IPV6, [70000])


# ---------------------------------------------------------------------------
# OS fingerprint honesty
# ---------------------------------------------------------------------------

class TestOsFingerprintHonesty:
    def test_ttl_observation_reports_hops_and_intermediary_caveat(self):
        obs = ar._ttl_observation(54)
        assert obs["initial_ttl_baseline"] == 64
        assert obs["estimated_hops"] == 10
        assert obs["may_be_intermediary"] is True

    def test_finding_stays_low_confidence(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recvmsg.return_value = (b"data", [(socket.IPPROTO_IP, socket.IP_TTL, (54).to_bytes(4, sys.byteorder))], 0, None)
        with mock.patch("sys.platform", "linux"), mock.patch("socket.socket", return_value=fake):
            result = ar.fingerprint_os_ttl(SAFE_IP, 161, store=store)
        if result["status"] == "found":
            finding = store.all()[0]
            assert finding["confidence"] == ar.CONFIDENCE_LOW
            assert finding["metadata"]["may_be_intermediary"] is True
            assert any("NAT/proxy/load balancer" in e for e in finding["evidence"])

    def test_no_response_is_not_a_fingerprint(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recvmsg.side_effect = socket.timeout("t")
        with mock.patch("sys.platform", "linux"), mock.patch("socket.socket", return_value=fake):
            result = ar.fingerprint_os_ttl(SAFE_IP, 161, store=store)
        assert result["status"] == "not_found"
        assert store.all() == []


# ---------------------------------------------------------------------------
# CLI argument robustness
# ---------------------------------------------------------------------------

class TestCliPortParsing:
    def test_parses_list_and_ranges(self):
        assert ar._parse_ports("80,443") == [80, 443]
        assert ar._parse_ports("20-23") == [20, 21, 22, 23]
        assert ar._parse_ports("80,20-22,80") == [20, 21, 22, 80]

    def test_empty_is_none(self):
        assert ar._parse_ports("") is None
        assert ar._parse_ports(None) is None

    @pytest.mark.parametrize("bad", ["abc", "80,abc", "80,-1", "0", "70000", "25-20"])
    def test_invalid_input_raises_actionable_value_error(self, bad):
        with pytest.raises(ValueError):
            ar._parse_ports(bad)


# ---------------------------------------------------------------------------
# Cross-host correlation
# ---------------------------------------------------------------------------

class TestCrossHostPatternHardening:
    def test_duplicate_hosts_do_not_inflate_a_pattern(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        results = [
            {"ip": "1.2.3.4", "open_ports": [44818]},
            {"ip": "1.2.3.4", "open_ports": [44818]},   # same host reported twice
        ]
        out = ar.detect_cross_host_port_pattern(results, store=store)
        assert out["patterns"] == {}
        assert store.all() == []

    def test_pattern_across_distinct_hosts_is_reported(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        results = [
            {"ip": "1.2.3.4", "open_ports": [44818]},
            {"ip": "1.2.3.5", "open_ports": [44818]},
        ]
        out = ar.detect_cross_host_port_pattern(results, store=store)
        assert out["patterns"] == {"44818": ["1.2.3.4", "1.2.3.5"]}
        assert store.all()[0]["confidence"] == ar.CONFIDENCE_MEDIUM

    def test_common_ports_are_not_a_pattern(self):
        results = [
            {"ip": "1.2.3.4", "open_ports": [443]},
            {"ip": "1.2.3.5", "open_ports": [443]},
        ]
        assert ar.detect_cross_host_port_pattern(results)["patterns"] == {}

    def test_malformed_entries_do_not_abort_correlation(self):
        results = [
            {"open_ports": [44818]},          # no ip
            {"ip": "1.2.3.4"},                # no open_ports
            {"ip": "1.2.3.4", "open_ports": [44818]},
            {"ip": "1.2.3.5", "open_ports": [44818]},
        ]
        assert ar.detect_cross_host_port_pattern(results)["patterns"] == {
            "44818": ["1.2.3.4", "1.2.3.5"]
        }


# ---------------------------------------------------------------------------
# Orchestrator integration (real orchestrator, real module)
# ---------------------------------------------------------------------------

class TestOrchestratorIntegration:
    @staticmethod
    def _orchestrator(tmp_path):
        from reconhound.core import orchestrator as orch
        return orch, orch.Orchestrator(target="example.com", output_dir=str(tmp_path),
                                       persist_execution_record=False)

    def test_orchestrator_invokes_active_recon_successfully(self, tmp_path):
        orch, o = self._orchestrator(tmp_path)
        fake = mock.MagicMock()
        fake.connect_ex.return_value = errno.ECONNREFUSED
        fake.recv.side_effect = socket.timeout("t")
        fake.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            o._invoke("active_recon", "1.2.3.4", "regression test",
                      ar.run_active_recon, "1.2.3.4", target="example.com",
                      tcp_ports=[22, 80], output_dir=str(tmp_path), timeout=0.1)
        assert o.executions[-1]["status"] in (orch.STATUS_SUCCESS, orch.STATUS_NO_RESULTS)
        assert o.executions[-1]["error"] is None

    def test_interrupt_is_recorded_as_interrupted_not_failed(self, tmp_path):
        """
        ActiveReconInterrupted subclasses KeyboardInterrupt precisely so the
        orchestrator's `except KeyboardInterrupt` still classifies it as an
        interrupted run rather than a module failure.
        """
        orch, o = self._orchestrator(tmp_path)
        state = {"n": 0}

        class KISocket:
            def __init__(self, *a, **kw):
                pass
            def settimeout(self, t):
                pass
            def connect_ex(self, addr):
                state["n"] += 1
                if state["n"] > 3:
                    raise KeyboardInterrupt()
                return 0
            def close(self):
                pass

        with mock.patch("socket.socket", KISocket):
            with pytest.raises(KeyboardInterrupt):
                o._invoke("active_recon", "1.2.3.4", "regression test",
                          ar.run_active_recon, "1.2.3.4",
                          tcp_ports=list(range(1, 60)), output_dir=str(tmp_path), timeout=0.1)

        assert o.executions[-1]["status"] == orch.STATUS_INTERRUPTED
        assert o.executions[-1]["error_type"] == "KeyboardInterrupt"

    def test_scope_rejection_is_recorded_as_scope_rejected(self, tmp_path):
        orch, o = self._orchestrator(tmp_path)
        o._invoke("active_recon", "example.com", "regression test",
                  ar.run_active_recon, "example.com", output_dir=str(tmp_path))
        assert o.executions[-1]["status"] == orch.STATUS_SCOPE_REJECTED

    def test_persistence_failure_degrades_the_run(self, tmp_path):
        """A scan whose findings could not be saved is not a clean run."""
        fake = mock.MagicMock()
        fake.connect_ex.return_value = 0
        fake.recv.side_effect = socket.timeout("t")
        fake.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            with mock.patch.object(ar.PendingAssetsStore, "add_many",
                                   side_effect=ar.PersistenceError("disk full")):
                summary = ar.run_active_recon("1.2.3.4", tcp_ports=[80],
                                              output_dir=str(tmp_path / "o"), timeout=0.1)
        assert summary["status"] == ar.RUN_COMPLETED_WITH_ERRORS
        assert any("persistence failed" in e["error"] for e in summary["errors"])


# ---------------------------------------------------------------------------
# Concurrency-safety of the shared store
# ---------------------------------------------------------------------------

class TestStoreConcurrency:
    def test_concurrent_batches_lose_no_records(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def writer(k):
            store.add_many([
                ar.make_finding("open_tcp_port", "1.2.3.4", {"port": k * 10 + i}, ["e"], "HIGH")
                for i in range(10)
            ])

        threads = [threading.Thread(target=writer, args=(k,)) for k in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(store.all()) == 200

    def test_mixed_add_and_add_many_are_serialized(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))

        def single():
            for i in range(50):
                store.add(ar.make_finding("a", "t", {"i": i}, ["e"], "HIGH"))

        def batch():
            for i in range(10):
                store.add_many([ar.make_finding("b", "t", {"i": i}, ["e"], "HIGH")] * 5)

        t1, t2 = threading.Thread(target=single), threading.Thread(target=batch)
        t1.start(); t2.start(); t1.join(); t2.join()
        assert len(store.all()) == 100


# ---------------------------------------------------------------------------
# Protocol-probe hardening found by adversarial self-review
# ---------------------------------------------------------------------------

class TestProtocolResponseSanitization:
    """
    grab_banner() strips control characters, but SMTP/FTP read their greetings
    through _recv_line(), which did not. The protection must not depend on
    which code path happened to read the bytes.
    """

    def test_ftp_banner_is_sanitized(self):
        fake = mock.MagicMock()
        fake.recv.side_effect = [b"220 \x1b[31mftp\x00\r\n", b"530 denied\r\n", b"221 bye\r\n"]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.ftp_anonymous_login_check(SAFE_IP)
        assert "\x1b" not in result["banner"]
        assert "\x00" not in result["banner"]

    def test_smtp_responses_are_sanitized(self):
        fake = mock.MagicMock()
        fake.recv.side_effect = [
            b"220 \x1b[2Jmail ESMTP\r\n", b"250 ok\r\n",
            b"250 \x07root\x00\r\n", b"502 no\r\n",
        ]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.smtp_probe(SAFE_IP)
        assert "\x1b" not in result["banner"]
        assert "\x07" not in result["vrfy"]["response"]
        assert "\x00" not in result["vrfy"]["response"]

    def test_reply_code_parsing_survives_sanitization(self):
        """Stripping control characters must not disturb the 3-digit code."""
        fake = mock.MagicMock()
        fake.recv.side_effect = [b"220 ftp\r\n", b"331 \x1b[0mneed password\r\n",
                                 b"230 \x00ok\r\n", b"221 bye\r\n"]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.ftp_anonymous_login_check(SAFE_IP)
        assert result["login_successful"] is True


class TestIpmiSourceValidation:
    """
    check_ipmi_exposure uses an unconnected UDP socket, which accepts a
    datagram from any sender. Crediting one to the target produced a false
    auto-CRITICAL finding.
    """

    def test_pong_from_another_host_is_not_exposure(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        pong = bytes([0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x40, 0x00, 0x00, 0x00])
        fake = mock.MagicMock()
        fake.recvfrom.side_effect = [(pong, ("203.0.113.9", 623)), socket.timeout("t")]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.check_ipmi_exposure(SAFE_IP, store=store)

        assert result["exposed"] is False
        assert result["unverified_responses"][0]["reason"] == "source address mismatch"
        finding = store.all()[0]
        assert finding["confidence"] == ar.CONFIDENCE_LOW
        assert "severity" not in finding["metadata"]

    def test_pong_from_the_target_is_exposure(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        pong = bytes([0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x40, 0x00, 0x00, 0x00])
        fake = mock.MagicMock()
        fake.recvfrom.return_value = (pong, (SAFE_IP, 623))
        with mock.patch("socket.socket", return_value=fake):
            result = ar.check_ipmi_exposure(SAFE_IP, store=store)

        assert result["exposed"] is True
        finding = store.all()[0]
        assert finding["metadata"]["severity"] == "CRITICAL"
        assert finding["confidence"] == ar.CONFIDENCE_HIGH

    def test_non_rmcp_datagram_is_not_exposure(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recvfrom.side_effect = [(b"\x00\x01\x02\x03garbage", (SAFE_IP, 623)),
                                     socket.timeout("t")]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.check_ipmi_exposure(SAFE_IP, store=store)
        assert result["exposed"] is False
        assert result["unverified_responses"][0]["reason"] == "not an RMCP presence pong"

    def test_silence_is_not_exposure(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recvfrom.side_effect = socket.timeout("t")
        with mock.patch("socket.socket", return_value=fake):
            result = ar.check_ipmi_exposure(SAFE_IP, store=store)
        assert result["exposed"] is False
        assert store.all()[0]["confidence"] == ar.CONFIDENCE_LOW


class TestSmtpFtpFailureSemantics:
    def test_incomplete_smtp_conversation_is_not_persisted(self, tmp_path):
        """
        A check that never completed is not a negative result and must not be
        remembered as one (context.md §8 negative-result memory).
        """
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recv.side_effect = [b"220 mail\r\n", socket.timeout("t")]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.smtp_probe(SAFE_IP, store=store)
        assert result["status"] == "error"
        assert store.all() == []

    def test_incomplete_ftp_conversation_is_not_persisted(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake = mock.MagicMock()
        fake.recv.side_effect = [b"220 ftp\r\n", socket.timeout("t")]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.ftp_anonymous_login_check(SAFE_IP)
        assert result["status"] == "error"
        assert store.all() == []

    def test_server_closing_early_does_not_fabricate_support(self):
        """Empty responses must not be read as VRFY/EXPN being available."""
        fake = mock.MagicMock()
        fake.recv.side_effect = [b"220 mail\r\n", b"", b"", b""]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.smtp_probe(SAFE_IP)
        assert result["vrfy"]["supported"] is False
        assert result["expn"]["supported"] is False

    def test_ftp_immediate_230_is_login_success(self):
        fake = mock.MagicMock()
        fake.recv.side_effect = [b"220 ftp\r\n", b"230 Logged in\r\n", b"221 bye\r\n"]
        with mock.patch("socket.socket", return_value=fake):
            result = ar.ftp_anonymous_login_check(SAFE_IP)
        assert result["login_successful"] is True


class TestBannerServiceGuessPrecision:
    """
    The MySQL rule matched the substring "mysql"/"mariadb" anywhere in a
    response, so an HTTP error page naming the database was identified as a
    MySQL service at HIGH confidence and written into the graph as such.
    """

    @pytest.mark.parametrize("banner", [
        "HTTP/1.1 500 Internal Server Error\r\n\r\nError: MySQL connection failed",
        "<html><body>Powered by MariaDB</body></html>",
        "<!DOCTYPE html><p>mysql error</p>",
        "HTTP/1.0 200 OK\r\nX-Powered-By: mysql",
    ])
    def test_web_response_naming_a_database_is_not_a_database(self, banner):
        assert ar._banner_based_service_guess(banner) is None

    def test_real_mariadb_greeting_is_still_detected(self):
        assert ar._banner_based_service_guess("10.3.23-MariaDB-0+deb10u1") == "mysql"

    def test_identify_service_does_not_mislabel_a_web_port(self):
        result = ar.identify_service(SAFE_IP, 80,
                                     banner="HTTP/1.1 500 Error\r\n\r\nMySQL connection failed")
        assert result["service"] is None
        assert result["confidence"] == ar.CONFIDENCE_LOW

    @pytest.mark.parametrize("banner,expected", [
        ("SSH-2.0-OpenSSH_8.9", "ssh"),
        ("220 ProFTPD Server ready", "ftp"),
        ("220 mail.example.com ESMTP Postfix", "smtp"),
        ("", None),
        (None, None),
    ])
    def test_known_greetings_unchanged(self, banner, expected):
        assert ar._banner_based_service_guess(banner) == expected


class TestCrossHostCorrelationRobustness:
    """Correlation runs over accumulated results; one malformed entry must not
    abort correlation of every other host."""

    @pytest.mark.parametrize("bad", [
        None, "a string", 42, [None], ["not a dict"],
        [{"ip": 123, "open_ports": [44818]}],
        [{"ip": "1.2.3.4", "open_ports": None}],
        [{"ip": "1.2.3.4", "open_ports": "80"}],
        [{"ip": "1.2.3.4", "open_ports": [[1, 2]]}],
        [{"ip": "1.2.3.4", "open_ports": [None, True]}],
    ])
    def test_malformed_input_does_not_raise(self, bad):
        result = ar.detect_cross_host_port_pattern(bad)
        assert isinstance(result["patterns"], dict)

    def test_good_entries_survive_alongside_bad_ones(self):
        results = [
            None,
            "garbage",
            {"ip": "1.2.3.4", "open_ports": None},
            {"ip": "1.2.3.4", "open_ports": [44818]},
            {"ip": "1.2.3.5", "open_ports": [44818, [9]]},
        ]
        assert ar.detect_cross_host_port_pattern(results)["patterns"] == {
            "44818": ["1.2.3.4", "1.2.3.5"]
        }
