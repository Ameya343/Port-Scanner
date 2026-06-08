#!/usr/bin/env python3
"""
port_scanner.py — Multi-threaded TCP/UDP Port Scanner

"""

import socket
import threading
import argparse
import json
import csv
import re
import sys
import time
import ssl
import struct
import os
from datetime import datetime
from queue import Queue

# ──────────────────────────────────────────────
# ANSI colour codes
# ──────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.DIM}  Multi-threaded TCP/UDP Port Scanner  |  github.com/Ameya343{C.RESET}
""")

# ──────────────────────────────────────────────
# Well-known port → service name mapping
# ──────────────────────────────────────────────
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP-TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker",
    2376: "Docker-TLS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 6443: "K8s-API",
}

# ──────────────────────────────────────────────
# VERSION DETECTION ENGINE
# ──────────────────────────────────────────────
#
# Each entry is a dict:
#   ports    – list of port numbers this probe targets ([] = all ports)
#   probe    – bytes to send (None = just read the connect banner)
#   patterns – list of (regex, template) tuples
#              regex groups are referenced as \1 \2 … in template
#   tls      – if True, wrap the socket in TLS before probing
#
VERSION_PROBES = [

    # ── SSH ──────────────────────────────────
    {
        "name": "SSH",
        "ports": [22],
        "probe": None,          # SSH sends version on connect
        "patterns": [
            (r"SSH-(\S+)-(\S+)", r"SSH \1 / \2"),
            (r"SSH-(\d[\d.]+)",  r"SSH \1"),
        ],
        "tls": False,
    },

    # ── FTP ──────────────────────────────────
    {
        "name": "FTP",
        "ports": [21],
        "probe": None,
        "patterns": [
            (r"220[- ].*?([Ff][Tt][Pp][Dd]?\S*)\s+([\d.]+\S*)", r"FTP \1 \2"),
            (r"220[- ](vsftpd\s+[\d.]+)",  r"FTP \1"),
            (r"220[- ](ProFTPD\s+[\d.]+)", r"FTP \1"),
            (r"220[- ](FileZilla[^\r\n]+)", r"FTP \1"),
            (r"220[- ]([^\r\n]{5,60})",    r"FTP [\1]"),
        ],
        "tls": False,
    },

    # ── SMTP ─────────────────────────────────
    {
        "name": "SMTP",
        "ports": [25, 587, 465],
        "probe": b"EHLO scanner\r\n",
        "patterns": [
            (r"220[- ].*?(Postfix[^\r\n]*)",   r"SMTP Postfix \1"),
            (r"220[- ].*?(Exim\s+[\d.]+)",     r"SMTP Exim \1"),
            (r"220[- ].*?(Sendmail[^\r\n]*)",   r"SMTP Sendmail \1"),
            (r"220[- ].*?(Microsoft ESMTP\s+MAIL[^\r\n]*)", r"SMTP Microsoft Exchange"),
            (r"220[- ]([^\r\n]{5,60})",        r"SMTP [\1]"),
        ],
        "tls": False,
    },

    # ── HTTP ─────────────────────────────────
    {
        "name": "HTTP",
        "ports": [80, 8080, 8000, 8008],
        "probe": None,   # built with host below; handled specially
        "patterns": [
            (r"Server:\s*(Apache/[\d.]+[^\r\n]*)",  r"\1"),
            (r"Server:\s*(nginx/[\d.]+[^\r\n]*)",   r"\1"),
            (r"Server:\s*(Microsoft-IIS/[\d.]+)",   r"\1"),
            (r"Server:\s*(lighttpd/[\d.]+)",        r"\1"),
            (r"Server:\s*(Caddy[^\r\n]*)",          r"\1"),
            (r"Server:\s*(openresty[^\r\n]*)",      r"OpenResty \1"),
            (r"Server:\s*(([^\r\n]{3,60}))",        r"HTTP Server: \2"),
            (r"X-Powered-By:\s*([^\r\n]{3,40})",   r"Powered-By: \1"),
        ],
        "tls": False,
    },

    # ── HTTPS ────────────────────────────────
    {
        "name": "HTTPS",
        "ports": [443, 8443],
        "probe": None,
        "patterns": [
            (r"Server:\s*(Apache/[\d.]+[^\r\n]*)",  r"\1"),
            (r"Server:\s*(nginx/[\d.]+[^\r\n]*)",   r"\1"),
            (r"Server:\s*(Microsoft-IIS/[\d.]+)",   r"\1"),
            (r"Server:\s*(([^\r\n]{3,60}))",        r"HTTPS Server: \2"),
        ],
        "tls": True,
    },

    # ── MySQL ────────────────────────────────
    {
        "name": "MySQL",
        "ports": [3306],
        "probe": None,   # MySQL sends handshake on connect
        "patterns": [
            # MySQL initial handshake: null-terminated version string at offset 5
            (r"[\x00-\xff]{4}\x0a([\d.]+[^\x00]*)\x00", r"MySQL \1"),
            (r"([\d]+\.[\d]+\.[\d]+[^\x00\r\n]*)",       r"MySQL \1"),
        ],
        "tls": False,
        "binary": True,
    },

    # ── PostgreSQL ───────────────────────────
    {
        "name": "PostgreSQL",
        "ports": [5432],
        "probe": None,
        "patterns": [
            (r"PostgreSQL\s+([\d.]+)",              r"PostgreSQL \1"),
            (r"FATAL.*?PostgreSQL\s+([\d.]+)",      r"PostgreSQL \1"),
        ],
        "tls": False,
    },

    # ── Redis ────────────────────────────────
    {
        "name": "Redis",
        "ports": [6379],
        "probe": b"*1\r\n$4\r\nINFO\r\n",
        "patterns": [
            (r"redis_version:([\d.]+)",             r"Redis \1"),
            (r"\+PONG",                             r"Redis (auth required or no auth)"),
            (r"-NOAUTH",                            r"Redis (auth required)"),
        ],
        "tls": False,
    },

    # ── MongoDB ──────────────────────────────
    {
        "name": "MongoDB",
        "ports": [27017],
        "probe": None,
        "patterns": [
            (r"MongoDB",                            r"MongoDB"),
            (r"ismaster",                           r"MongoDB (wire protocol)"),
        ],
        "tls": False,
    },

    # ── Memcached ────────────────────────────
    {
        "name": "Memcached",
        "ports": [11211],
        "probe": b"version\r\n",
        "patterns": [
            (r"VERSION\s+([\d.]+)",                 r"Memcached \1"),
        ],
        "tls": False,
    },

    # ── Elasticsearch ────────────────────────
    {
        "name": "Elasticsearch",
        "ports": [9200],
        "probe": b"GET / HTTP/1.0\r\n\r\n",
        "patterns": [
            (r'"number"\s*:\s*"([\d.]+)"',          r"Elasticsearch \1"),
        ],
        "tls": False,
    },

    # ── VNC ──────────────────────────────────
    {
        "name": "VNC",
        "ports": [5900, 5901, 5902],
        "probe": None,
        "patterns": [
            (r"RFB ([\d.]+)",                       r"VNC RFB \1"),
        ],
        "tls": False,
    },

    # ── RDP ──────────────────────────────────
    {
        "name": "RDP",
        "ports": [3389],
        "probe": bytes.fromhex(
            "030000130ee00000000000010008000b000000"
        ),
        "patterns": [
            (r".",                                  r"RDP (port open)"),
        ],
        "tls": False,
    },

    # ── SMB ──────────────────────────────────
    {
        "name": "SMB",
        "ports": [445],
        "probe": bytes.fromhex(
            "00000085"  # NetBIOS length
            "ff534d4272000000001843c80000000000000000000000000000fffe00000000"  # SMBv1 negotiate
            "3100000008fdf30009000100000000002a000000000000004100000000ffff0000"
            "00000000000000000000000000000000000000000000000000000000"
        ),
        "patterns": [
            (r"SMB",                                r"SMB (open)"),
            (r".",                                  r"SMB / NetBIOS"),
        ],
        "tls": False,
    },

    # ── Generic fallback (any port, any banner) ──
    {
        "name": "generic",
        "ports": [],        # matches any port not matched above
        "probe": b"\r\n",
        "patterns": [
            (r"([\w/][\w.\-/]+\s[\d.]+[\d])",      r"\1"),  # "ServiceName X.Y.Z"
        ],
        "tls": False,
    },
]

def _build_http_probe(host: str) -> bytes:
    return (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: PortScanner/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

def detect_version(host: str, port: int, timeout: float) -> tuple[str, str]:
    """
    Returns (service_name, version_string).
    Tries every probe whose port list matches; falls back to generic.
    """
    matching = [p for p in VERSION_PROBES if port in p["ports"]]
    if not matching:
        # try generic
        matching = [p for p in VERSION_PROBES if not p["ports"]]

    for probe_def in matching:
        try:
            raw = _run_probe(host, port, probe_def, timeout)
            if not raw:
                continue
            # Try to decode; keep raw bytes for binary probes
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = str(raw)

            for pattern, template in probe_def["patterns"]:
                m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if m:
                    version = re.sub(
                        r"\\(\d)",
                        lambda x: (m.group(int(x.group(1))) or "").strip(),
                        template
                    )
                    version = " ".join(version.split())  # collapse whitespace
                    svc = COMMON_SERVICES.get(port, probe_def["name"])
                    return svc, version
        except Exception:
            continue

    # Could not detect version; return service name only
    svc = COMMON_SERVICES.get(port, "")
    if not svc:
        try:
            svc = socket.getservbyport(port, "tcp")
        except OSError:
            svc = "unknown"
    return svc, ""


def _run_probe(host: str, port: int, probe_def: dict, timeout: float) -> bytes | None:
    """Open a TCP connection, send the probe, and return the raw response."""
    use_tls = probe_def.get("tls", False)

    # Build probe bytes
    probe = probe_def["probe"]
    if probe is None and probe_def["name"] in ("HTTP", "HTTPS"):
        probe = _build_http_probe(host)
    elif probe is None:
        probe = b""   # just connect and read

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((host, port))

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        if probe:
            sock.sendall(probe)

        chunks = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if len(b"".join(chunks)) > 8192:
                    break
        except (socket.timeout, OSError):
            pass

        sock.close()
        return b"".join(chunks) if chunks else None

    except Exception:
        return None

# ──────────────────────────────────────────────
# Banner grabbing (legacy – kept for --banner flag)
# ──────────────────────────────────────────────
def grab_banner(host: str, port: int, timeout: float) -> str:
    """Raw banner grab — first 200 chars of connect response."""
    probes = {
        80:  _build_http_probe(host),
        443: _build_http_probe(host),
        8080: _build_http_probe(host),
    }
    probe = probes.get(port, b"\r\n")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if probe:
                s.sendall(probe)
            data = s.recv(2048)
            return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""

# ──────────────────────────────────────────────
# TCP scan
# ──────────────────────────────────────────────
def scan_tcp(host: str, port: int, timeout: float, grab: bool, verscan: bool) -> dict | None:
    """Return a result dict if port is open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((host, port))

        if code != 0:
            return None

        service = ""
        version = ""
        raw_banner = ""

        if verscan:
            service, version = detect_version(host, port, timeout)
        else:
            service = COMMON_SERVICES.get(port, "")
            if not service:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"

        if grab:
            raw_banner = grab_banner(host, port, timeout)

        return {
            "host":    host,
            "port":    port,
            "proto":   "TCP",
            "state":   "open",
            "service": service,
            "version": version,
            "banner":  raw_banner,
        }

    except Exception:
        pass
    return None

# ──────────────────────────────────────────────
# UDP scan
# ──────────────────────────────────────────────
def scan_udp(host: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (host, port))
            try:
                s.recvfrom(1024)
                state = "open"
            except socket.timeout:
                state = "open|filtered"
            except ConnectionRefusedError:
                return None
        service = COMMON_SERVICES.get(port, "")
        if not service:
            try:
                service = socket.getservbyport(port, "udp")
            except OSError:
                service = "unknown"
        return {
            "host": host, "port": port, "proto": "UDP",
            "state": state, "service": service, "version": "", "banner": ""
        }
    except PermissionError:
        print(f"{C.YELLOW}[!] UDP scan requires elevated privileges.{C.RESET}")
        sys.exit(1)
    except Exception:
        pass
    return None

# ──────────────────────────────────────────────
# OS fingerprinting (TTL-based)
# ──────────────────────────────────────────────
def os_fingerprint(host: str, timeout: float) -> str:
    ttl_map = {
        range(0,   65):  "Network device / IoT (TTL ≤ 64)",
        range(65,  129): "Linux / Android / macOS (TTL 64–128)",
        range(129, 256): "Windows (TTL 128–255)",
    }
    candidates = [80, 22, 443, 8080, 21, 25]
    open_port = next((p for p in candidates if _is_port_open(host, p, timeout)), None)
    if not open_port:
        return "OS fingerprint failed (no open TCP port reachable)"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, open_port))
            try:
                ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                for r, label in ttl_map.items():
                    if ttl in r:
                        return f"{label} (TTL={ttl})"
                return f"Unknown (TTL={ttl})"
            except OSError:
                return "TTL unavailable (try elevated privileges)"
    except Exception:
        return "OS fingerprint failed"

def _is_port_open(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

# ──────────────────────────────────────────────
# Worker thread
# ──────────────────────────────────────────────
print_lock = threading.Lock()

def worker(queue: Queue, results: list, args):
    while True:
        item = queue.get()
        if item is None:
            break
        proto, host, port = item

        if proto == "TCP":
            res = scan_tcp(host, port, args.timeout, args.banner, args.version)
        else:
            res = scan_udp(host, port, args.timeout)

        if res:
            results.append(res)
            with print_lock:
                state_colour = C.GREEN if res["state"] == "open" else C.YELLOW
                svc     = res.get("service", "")
                ver     = res.get("version", "")
                bnr     = res.get("banner", "")

                ver_str = f"  {C.MAGENTA}{ver}{C.RESET}" if ver else ""
                bnr_str = f"  {C.DIM}» {bnr[:60]}{C.RESET}" if bnr and not ver else ""

                print(f"  {state_colour}[{res['proto']}]{C.RESET} "
                    f"{C.BOLD}:{res['port']:<6}{C.RESET} "
                    f"{state_colour}{res['state']:<14}{C.RESET} "
                    f"{C.CYAN}{svc:<16}{C.RESET}"
                    f"{ver_str}{bnr_str}")

        elif args.verbose:
            with print_lock:
                print(f"  {C.DIM}[{proto}] :{port:<6} closed{C.RESET}")

        queue.task_done()

# ──────────────────────────────────────────────
# Port range parser
# ──────────────────────────────────────────────
def parse_ports(port_str: str) -> list[int]:
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ──────────────────────────────────────────────
# Export helpers
# ──────────────────────────────────────────────
def export_json(results: list, path: str):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n{C.GREEN}[+]{C.RESET} JSON saved → {path}")

def export_csv(results: list, path: str):
    if not results:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"{C.GREEN}[+]{C.RESET} CSV  saved → {path}")

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP/UDP Port Scanner with Version Detection",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
python port_scanner.py -t 10.10.10.1
python port_scanner.py -t 10.10.10.1 -p 1-1000 -sV -v
python port_scanner.py -t 10.10.10.1 -p 22,80,443,3306 -sV --banner
python port_scanner.py -t 192.168.1.1 -p 1-65535 -sV --threads 200 --json out.json
"""
    )
    parser.add_argument("-t", "--target",   required=True,
                        help="Target host (IP or hostname)")
    parser.add_argument("-p", "--ports",    default="1-1024",
                        help="Port range/list  (default: 1-1024)\n"
                            "Examples: 22,80,443  |  1-65535  |  80,100-200,443")
    parser.add_argument("-sV", "--version", action="store_true",
                        help="Enable service version detection (like nmap -sV)")
    parser.add_argument("--udp",            action="store_true",
                        help="Also run UDP scan (requires root)")
    parser.add_argument("--banner",         action="store_true",
                        help="Include raw banner in output (alongside -sV)")
    parser.add_argument("--os",             action="store_true",
                        help="Attempt basic OS fingerprinting via TTL")
    parser.add_argument("-T", "--timeout",  type=float, default=1.5,
                        help="Socket timeout in seconds (default: 1.5)")
    parser.add_argument("--threads",        type=int,   default=100,
                        help="Number of worker threads (default: 100)")
    parser.add_argument("-v", "--verbose",  action="store_true",
                        help="Show closed ports too")
    parser.add_argument("--json",           metavar="FILE",
                        help="Export results to JSON file")
    parser.add_argument("--csv",            metavar="FILE",
                        help="Export results to CSV file")

    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{C.RED}[-]{C.RESET} Cannot resolve host: {args.target}")
        sys.exit(1)

    ports = parse_ports(args.ports)

    print(f"{C.BOLD}  Target   :{C.RESET} {args.target} ({ip})")
    print(f"{C.BOLD}  Ports    :{C.RESET} {len(ports)} ports  [{ports[0]}–{ports[-1]}]")
    print(f"{C.BOLD}  Protocols:{C.RESET} TCP{'  UDP' if args.udp else ''}")
    print(f"{C.BOLD}  Flags    :{C.RESET} "
        f"{'version ' if args.version else ''}"
        f"{'banner ' if args.banner else ''}"
        f"{'os ' if args.os else ''}"
        f"{'verbose' if args.verbose else ''}" or "default")
    print(f"{C.BOLD}  Threads  :{C.RESET} {args.threads}   Timeout: {args.timeout}s")
    print(f"{C.BOLD}  Started  :{C.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n  {'PROTO':<8} {'PORT':<8} {'STATE':<14} {'SERVICE':<16} VERSION\n"
        f"  {'─'*70}")

    results = []
    queue   = Queue()
    threads = []
    t_start = time.time()

    for _ in range(args.threads):
        th = threading.Thread(target=worker, args=(queue, results, args), daemon=True)
        th.start()
        threads.append(th)

    for port in ports:
        queue.put(("TCP", ip, port))
    if args.udp:
        for port in ports:
            queue.put(("UDP", ip, port))

    queue.join()

    for _ in threads:
        queue.put(None)
    for th in threads:
        th.join()

    elapsed = time.time() - t_start

    open_res   = [r for r in results if r["state"] == "open"]
    filter_res = [r for r in results if r["state"] != "open"]

    print(f"\n  {'─'*70}")
    print(f"{C.BOLD}  Scan complete{C.RESET} in {elapsed:.2f}s")
    print(f"  {C.GREEN}{len(open_res)} open{C.RESET}  |  "
        f"{C.YELLOW}{len(filter_res)} open|filtered{C.RESET}  |  "
        f"{len(ports) - len(results)} closed")

    if args.os:
        print(f"\n{C.BOLD}  [OS Fingerprint]{C.RESET}")
        guess = os_fingerprint(ip, args.timeout)
        print(f"  {C.CYAN}{guess}{C.RESET}")

    if args.json:
        export_json(results, args.json)
    if args.csv:
        export_csv(results, args.csv)

    if not args.json and not args.csv and results:
        print(f"\n{C.DIM}  Tip: use --json results.json --csv results.csv to export{C.RESET}")

if __name__ == "__main__":
    main()
