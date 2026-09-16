"""Tests for recon-mapper target expansion, scanning, and reporting."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

import recon_mapper
from recon_mapper import (COMMON_PORTS, build_report, expand_targets,
                          is_port_open, parse_ports, scan_host)
from tests.support.fakes import capture_cli, closed_port, tcp_listener


class TestParsePorts(unittest.TestCase):
    def test_empty_spec_uses_the_common_list(self):
        self.assertEqual(parse_ports(None), COMMON_PORTS)

    def test_comma_separated_list(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_ports("20-23"), [20, 21, 22, 23])

    def test_mixed_list_and_range(self):
        self.assertEqual(parse_ports("22,80-82,443"), [22, 80, 81, 82, 443])

    def test_duplicates_are_removed_and_sorted(self):
        self.assertEqual(parse_ports("443,22,22,443"), [22, 443])

    def test_out_of_range_ports_are_dropped(self):
        self.assertEqual(parse_ports("0,22,70000"), [22])

    def test_whitespace_is_tolerated(self):
        self.assertEqual(parse_ports(" 22 , 80 "), [22, 80])


class TestExpandTargets(unittest.TestCase):
    def test_single_ip_stays_one_target(self):
        self.assertEqual(expand_targets("10.0.0.1"), ["10.0.0.1"])

    def test_hostname_passes_through(self):
        self.assertEqual(expand_targets("example.internal"),
                         ["example.internal"])

    def test_cidr_expands_to_usable_hosts(self):
        hosts = expand_targets("10.0.0.0/30")
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2"])

    def test_slash_32_is_a_single_host(self):
        self.assertEqual(expand_targets("10.0.0.5/32"), ["10.0.0.5"])

    def test_larger_subnet_has_expected_size(self):
        self.assertEqual(len(expand_targets("192.168.1.0/24")), 254)


class TestPortProbe(unittest.TestCase):
    def test_open_port_is_detected(self):
        with tcp_listener() as (host, port):
            is_open, _ = is_port_open(host, port, timeout=2.0)
        self.assertTrue(is_open)

    def test_closed_port_is_detected(self):
        host, port = closed_port()
        is_open, banner = is_port_open(host, port, timeout=2.0)
        self.assertFalse(is_open)
        self.assertEqual(banner, "")

    def test_banner_is_captured(self):
        with tcp_listener(banner=b"SSH-2.0-OpenSSH_9.6\r\n") as (host, port):
            is_open, banner = is_port_open(host, port, timeout=2.0)
        self.assertTrue(is_open)
        self.assertIn("OpenSSH", banner)

    def test_silent_service_yields_empty_banner(self):
        with tcp_listener() as (host, port):
            is_open, banner = is_port_open(host, port, timeout=1.0)
        self.assertTrue(is_open)
        self.assertEqual(banner, "")

    def test_unresolvable_host_is_not_open(self):
        is_open, _ = is_port_open("no-such-host.invalid", 80, timeout=2.0)
        self.assertFalse(is_open)


class TestScanHost(unittest.TestCase):
    def test_host_with_an_open_port_is_alive(self):
        with tcp_listener() as (host, port):
            closed_host, closed_p = closed_port()
            result = scan_host(host, [port, closed_p], timeout=2.0, workers=4)
        self.assertTrue(result.alive)
        self.assertEqual([p.port for p in result.open_ports], [port])

    def test_host_with_no_open_ports_is_not_alive(self):
        host, port = closed_port()
        result = scan_host(host, [port], timeout=1.0, workers=4)
        self.assertFalse(result.alive)
        self.assertEqual(result.open_ports, [])

    def test_open_ports_are_sorted(self):
        with tcp_listener() as (host, first):
            with tcp_listener() as (_, second):
                ports = sorted([first, second], reverse=True)
                result = scan_host(host, ports, timeout=2.0, workers=4)
        found = [p.port for p in result.open_ports]
        self.assertEqual(found, sorted(found))

    def test_well_known_port_gets_a_service_name(self):
        self.assertEqual(recon_mapper.WELL_KNOWN[22], "ssh")
        self.assertEqual(recon_mapper.WELL_KNOWN[443], "https")

    def test_unknown_port_is_labelled_unknown(self):
        with tcp_listener() as (host, port):
            result = scan_host(host, [port], timeout=2.0, workers=2)
        # An ephemeral port is never in the well-known table.
        self.assertEqual(result.open_ports[0].service, "unknown")


class TestReport(unittest.TestCase):
    def test_report_only_includes_alive_hosts(self):
        with tcp_listener() as (host, port):
            alive = scan_host(host, [port], timeout=2.0, workers=2)
        dead_host, dead_port = closed_port()
        dead = scan_host(dead_host, [dead_port], timeout=1.0, workers=2)
        report = build_report([alive, dead], "test", 1.0)
        self.assertEqual(report["hosts_alive"], 1)
        self.assertEqual(len(report["hosts"]), 1)

    def test_report_has_the_documented_shape(self):
        report = build_report([], "10.0.0.0/30", 2.345)
        for key in ("target", "scanned_at", "duration_seconds",
                    "hosts_alive", "hosts"):
            self.assertIn(key, report)
        self.assertEqual(report["duration_seconds"], 2.35)

    def test_report_is_json_serialisable(self):
        with tcp_listener() as (host, port):
            result = scan_host(host, [port], timeout=2.0, workers=2)
        json.dumps(build_report([result], "t", 1.0))  # must not raise


class TestCli(unittest.TestCase):
    def test_refuses_to_scan_without_authorization(self):
        """The authorization gate is the point — it must not be bypassable."""
        code, out = capture_cli(recon_mapper.main, ["127.0.0.1", "-p", "22"])
        self.assertEqual(code, 2)
        self.assertIn("--authorized", out)

    def test_runs_when_authorized(self):
        host, port = closed_port()
        code, _ = capture_cli(
            recon_mapper.main, [host, "-p", str(port), "-t", "0.5",
                                "--authorized"])
        self.assertEqual(code, 0)

    def test_writes_a_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = os.path.join(tmp, "report.json")
            with tcp_listener() as (host, port):
                capture_cli(recon_mapper.main,
                            [host, "-p", str(port), "-o", out_file,
                             "--authorized"])
            with open(out_file, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["hosts_alive"], 1)
            self.assertEqual(data["hosts"][0]["open_ports"][0]["port"], port)


if __name__ == "__main__":
    unittest.main()
