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

def _fake_snmp_response(community: bytes, sysdescr: bytes) -> bytes:
    oid = ar._ber_tlv(0x06, ar._SYSDESCR_OID)
    val = ar._ber_tlv(0x04, sysdescr)
    varbind = ar._ber_tlv(0x30, oid + val)
    vbl = ar._ber_tlv(0x30, varbind)
    pdu_body = ar._ber_int(1) + ar._ber_int(0) + ar._ber_int(0) + vbl
    pdu = ar._ber_tlv(0xA2, pdu_body)
    return ar._ber_tlv(0x30, ar._ber_int(0) + ar._ber_tlv(0x04, community) + pdu)


class TestSnmpCommunityProbe:
    def test_accepted_community_extracts_sysdescr(self, tmp_path):
        store = ar.PendingAssetsStore(output_dir=str(tmp_path / "output"))
        fake_sock = mock.MagicMock()
        resp = _fake_snmp_response(b"public", b"Linux router 5.10")

        def fake_recvfrom(bufsize):
            return resp, (SAFE_IP, 161)

        fake_sock.recvfrom.side_effect = [socket.timeout("t"), fake_recvfrom(2048)]
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
