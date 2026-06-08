# 🔍 PortScanner

A fast, multi-threaded TCP/UDP port scanner written in Python — with service version detection, OS fingerprinting, banner grabbing, and structured export. Built as a hands-on demonstration of socket programming, TCP/IP fundamentals, and penetration testing recon techniques.

---

## Features

- **Multi-threaded scanning** — configurable thread pool for high-speed sweeps
- **TCP & UDP** — full connect scan (TCP) and datagram probe (UDP)
- **Service version detection (`-sV`)** — protocol-aware probes for SSH, FTP, SMTP, HTTP/S, MySQL, Redis, PostgreSQL, Elasticsearch, VNC, RDP, SMB, Memcached, MongoDB and more
- **Banner grabbing (`--banner`)** — raw first-response capture for any open port
- **OS fingerprinting (`--os`)** — TTL-based heuristic to guess Linux / Windows / IoT
- **Flexible port ranges** — supports `22,80,443`, `1-1024`, `80,100-200,8080` syntax
- **CSV & JSON export** — structured output ready for reports or downstream tooling
- **Verbose mode** — optionally show closed ports too
- **Cross-platform** — works on Linux, macOS, and Windows (Windows Terminal recommended)

---

## Requirements

- Python **3.10+** (uses `match`-free union type hints — `3.10` for `X | Y`)
- No third-party dependencies — pure stdlib only

```bash
python --version   # confirm 3.10+
```

---

## Installation

```bash
git clone https://github.com/ameya/port-scanner.git
cd port-scanner
```

That's it. No `pip install` needed.

---

## Usage

```
python port_scanner.py -t <target> [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-t`, `--target` | *(required)* | Target IP or hostname |
| `-p`, `--ports` | `1-1024` | Port range/list e.g. `22,80,443` or `1-65535` |
| `-sV`, `--version` | off | Enable service version detection |
| `--udp` | off | Also scan UDP ports (requires root/admin) |
| `--banner` | off | Capture raw service banner |
| `--os` | off | OS fingerprinting via TTL heuristic |
| `-T`, `--timeout` | `1.5` | Socket timeout in seconds |
| `--threads` | `100` | Number of concurrent worker threads |
| `-v`, `--verbose` | off | Show closed ports in output |
| `--json FILE` | — | Export results to JSON |
| `--csv FILE` | — | Export results to CSV |

---

## Examples

```bash
# Basic scan — top 1024 ports
python port_scanner.py -t 10.10.10.1

# Version detection on common ports
python port_scanner.py -t 10.10.10.1 -p 21,22,80,443,3306,6379 -sV

# Full recon — version detection + OS guess + export
python port_scanner.py -t 10.10.10.1 -p 1-1024 -sV --os --json results.json --csv results.csv

# Fast full-port sweep
python port_scanner.py -t 10.10.10.1 -p 1-65535 --threads 300 -T 0.5

# Include UDP + verbose output (requires sudo)
sudo python port_scanner.py -t 10.10.10.1 -p 53,161,500 --udp -v

# Targeted recon with banner + version
python port_scanner.py -t 192.168.1.1 -p 22,80,443,8080 -sV --banner
```

---

## Sample Output

```
  Target   : 10.10.10.1 (10.10.10.1)
  Ports    : 1024 ports [1–1024]
  Flags    : version os
  Threads  : 100   Timeout: 1.5s
  Started  : 2025-06-09 14:22:01

  PROTO    PORT     STATE          SERVICE          VERSION
  ──────────────────────────────────────────────────────────────────────
  [TCP] :22     open           SSH              SSH 2.0 / OpenSSH_8.9p1
  [TCP] :80     open           HTTP             nginx/1.24.0
  [TCP] :443    open           HTTPS            Apache/2.4.57
  [TCP] :3306   open           MySQL            MySQL 8.0.33
  [TCP] :6379   open           Redis            Redis 7.0.11

  ──────────────────────────────────────────────────────────────────────
  Scan complete in 3.41s
  5 open  |  0 open|filtered  |  1019 closed

  [OS Fingerprint]
  Linux / Android / macOS (TTL 64–128) (TTL=64)
```

---

## Export Formats

**JSON** (`--json results.json`)
```json
[
  {
    "host": "10.10.10.1",
    "port": 22,
    "proto": "TCP",
    "state": "open",
    "service": "SSH",
    "version": "SSH 2.0 / OpenSSH_8.9p1",
    "banner": ""
  }
]
```

**CSV** (`--csv results.csv`)
```
host,port,proto,state,service,version,banner
10.10.10.1,22,TCP,open,SSH,SSH 2.0 / OpenSSH_8.9p1,
10.10.10.1,80,TCP,open,HTTP,nginx/1.24.0,
```

---

## Version Detection — Supported Protocols

| Protocol | Ports | Method |
|---|---|---|
| SSH | 22 | Connect banner (`SSH-2.0-OpenSSH_x.x`) |
| FTP | 21 | Connect banner (`220 vsftpd 3.0.5`) |
| SMTP | 25, 587, 465 | `EHLO` probe — Postfix, Exim, Exchange |
| HTTP | 80, 8080, 8000 | `HEAD /` — Apache, nginx, IIS, Caddy |
| HTTPS | 443, 8443 | TLS + `HEAD /` — same as HTTP |
| MySQL | 3306 | Binary handshake packet parsing |
| PostgreSQL | 5432 | Connect banner |
| Redis | 6379 | `INFO` command → `redis_version:` |
| Memcached | 11211 | `version` command |
| Elasticsearch | 9200 | HTTP GET `/` → JSON `"number"` field |
| VNC | 5900–5902 | `RFB xxx.xxx` connect banner |
| RDP | 3389 | TPKT/X.224 probe |
| SMB | 445 | SMBv1 negotiate probe |
| MongoDB | 27017 | Connect banner |
| Generic | any | Pattern match on connect response |

---

## Platform Notes

| OS | Support | Notes |
|---|---|---|
| Linux | ✅ Full | All features including UDP and OS fingerprint |
| macOS | ✅ Full | Same as Linux |
| Windows | ✅ Full | Use **Windows Terminal** for ANSI colours; run as Administrator for UDP/OS flags |

For legacy `cmd.exe` / old PowerShell, add this near the top of the script to enable ANSI colour rendering:
```python
if sys.platform == "win32":
    os.system("")
```

---

## Disclaimer

This tool is intended for **authorised security testing and educational use only**. Always obtain explicit written permission before scanning any system or network you do not own. Unauthorised port scanning may be illegal in your jurisdiction.

---

## Skills Demonstrated

- Socket programming — TCP connect scan, UDP datagram probes, TLS wrapping
- Protocol-level interaction — crafting and parsing SSH, FTP, SMTP, MySQL, Redis handshakes
- Concurrent programming — thread pool with `Queue`-based work distribution
- Penetration testing recon — service enumeration, version fingerprinting, OS detection
- Structured output — Pydantic-ready JSON schema for integration with downstream tooling

---

## License

MIT License — see `LICENSE` for details.
