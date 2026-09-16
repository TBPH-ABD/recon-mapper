# recon-mapper

Authorized network asset and service discovery. A dependency-free reconnaissance
helper that finds live hosts, maps open TCP ports, grabs service banners, and
writes a structured JSON report.

Built for the enumeration phase of an authorized penetration test, and for
system administrators who need a quick inventory of what is actually listening
on their network.

## Features

- **Host discovery** across a single host, an IP, or a full CIDR range
- **Concurrent TCP connect scan** with a configurable worker pool
- **Service identification** for the common well-known ports
- **Banner grabbing** to fingerprint the software behind an open port
- **JSON reporting** for handoff into other tooling or a written report
- **Authorization gate** — the scan refuses to run without explicit confirmation
- **Zero dependencies** — Python 3 standard library only

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
# Scan a single host on the default common-ports list
python3 recon_mapper.py 192.168.1.10 --authorized

# Scan a whole subnet
python3 recon_mapper.py 192.168.1.0/24 --authorized

# Scan a custom port range and save the report
python3 recon_mapper.py example.internal -p 1-1024 -o report.json --authorized
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `-p`, `--ports` | Ports to probe: `22,80,443` or `1-1024` | common ports |
| `-t`, `--timeout` | Per-port connect timeout in seconds | `0.6` |
| `-w`, `--workers` | Concurrent connections per host | `100` |
| `-o`, `--output` | Write the JSON report to this file | none |
| `--authorized` | Required. Confirms you have permission to scan | off |

## Example output

```
Target: 192.168.1.10
Alive hosts: 1  |  1.84s

  192.168.1.10
       22/tcp  ssh  [SSH-2.0-OpenSSH_9.6]
       80/tcp  http
      443/tcp  https
```

## Report format

```json
{
  "target": "192.168.1.10",
  "scanned_at": "2026-09-16T21:04:11+00:00",
  "duration_seconds": 1.84,
  "hosts_alive": 1,
  "hosts": [
    {
      "host": "192.168.1.10",
      "alive": true,
      "open_ports": [
        { "port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.6" }
      ]
    }
  ]
}
```

## How it works

A host is considered alive when at least one TCP port answers a connect probe.
This avoids requiring root privileges for raw ICMP, so the tool runs unprivileged
on Linux, macOS, and Windows. Each port is probed by a thread from a bounded
pool; on a successful connect the tool reads up to 128 bytes to capture a banner.

## Responsible use

This tool is intended for networks you own or have written permission to test.
Port scanning systems without authorization is illegal in most jurisdictions.
The `--authorized` flag exists to make that decision explicit and deliberate.

## License

MIT — see [LICENSE](LICENSE).
