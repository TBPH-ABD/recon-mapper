#!/usr/bin/env python3
"""recon-mapper — authorized network asset & service discovery.

A lightweight, dependency-free reconnaissance helper for penetration testers
and system administrators. It discovers live hosts, maps open TCP ports,
grabs service banners, and writes a structured report.

Standard library only. For AUTHORIZED testing and educational use.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# A small, sensible default set of TCP ports to probe.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
]

WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
    995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}


@dataclass
class PortResult:
    port: int
    service: str
    banner: str = ""


@dataclass
class HostResult:
    host: str
    alive: bool = False
    open_ports: list[PortResult] = field(default_factory=list)


def is_port_open(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """Return (open, banner) for a single TCP port using a connect scan."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) != 0:
                return False, ""
        except (socket.gaierror, OSError):
            return False, ""
        banner = ""
        try:
            sock.settimeout(min(timeout, 1.5))
            data = sock.recv(128)
            banner = data.decode("utf-8", "replace").strip()
        except OSError:
            pass
        return True, banner


def scan_host(host: str, ports: list[int], timeout: float, workers: int) -> HostResult:
    result = HostResult(host=host)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(is_port_open, host, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            is_open, banner = future.result()
            if is_open:
                svc = WELL_KNOWN.get(port, "unknown")
                result.open_ports.append(PortResult(port, svc, banner))
    result.open_ports.sort(key=lambda p: p.port)
    result.alive = bool(result.open_ports)
    return result


def expand_targets(target: str) -> list[str]:
    """Expand a hostname, single IP, or CIDR range into a list of hosts."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 1:
            return [str(ip) for ip in network.hosts()]
        return [str(network.network_address)]
    except ValueError:
        return [target]  # treat as hostname


def parse_ports(spec: str | None) -> list[int]:
    if not spec:
        return COMMON_PORTS
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p <= 65535)


def build_report(hosts: list[HostResult], target: str, elapsed: float) -> dict:
    return {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(elapsed, 2),
        "hosts_alive": sum(1 for h in hosts if h.alive),
        "hosts": [asdict(h) for h in hosts if h.alive],
    }


def print_summary(report: dict) -> None:
    print(f"\nTarget: {report['target']}")
    print(f"Alive hosts: {report['hosts_alive']}  |  {report['duration_seconds']}s\n")
    for host in report["hosts"]:
        print(f"  {host['host']}")
        for p in host["open_ports"]:
            banner = f"  [{p['banner'][:60]}]" if p["banner"] else ""
            print(f"    {p['port']:>5}/tcp  {p['service']}{banner}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authorized network asset & service discovery.")
    parser.add_argument("target", help="hostname, IP, or CIDR (e.g. 10.0.0.0/24)")
    parser.add_argument("-p", "--ports", help="ports: '22,80,443' or '1-1024'")
    parser.add_argument("-t", "--timeout", type=float, default=0.6,
                        help="per-port timeout in seconds (default 0.6)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="concurrent connections per host (default 100)")
    parser.add_argument("-o", "--output", help="write JSON report to this file")
    parser.add_argument("--authorized", action="store_true",
                        help="confirm you are authorized to scan the target")
    args = parser.parse_args(argv)

    if not args.authorized:
        print("Refusing to scan: pass --authorized to confirm you have "
              "explicit permission to test the target.", file=sys.stderr)
        return 2

    ports = parse_ports(args.ports)
    targets = expand_targets(args.target)
    print(f"Scanning {len(targets)} host(s) x {len(ports)} port(s)...")

    start = time.time()
    hosts: list[HostResult] = []
    for host in targets:
        hosts.append(scan_host(host, ports, args.timeout, args.workers))
    report = build_report(hosts, args.target, time.time() - start)

    print_summary(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
