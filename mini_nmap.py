#!/usr/bin/env python3

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

DEFAULT_PORTS = sorted(COMMON_PORTS.keys())


@dataclass
class PortResult:
    port: int
    status: str          # "OPEN" | "CLOSED" | "FILTERED"
    service: str
    response_ms: float | None
    banner: str | None = None


def parse_ports(spec: str | None) -> list[int]:
    """Parse a port spec like '22,80,443' or '1-1024' or a mix of both."""
    if not spec:
        return DEFAULT_PORTS

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 1 <= p <= 65535)


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address, or pass through if already an IP."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise SystemExit(f"[!] Could not resolve target '{target}': {exc}")


def grab_banner(sock: socket.socket, port: int) -> str | None:
    """
    Best-effort banner grab for a couple of chatty text protocols.
    Real Nmap does this far more thoroughly via probes; this is a
    lightweight illustration of the concept for learning purposes.
    """
    try:
        sock.settimeout(0.6)
        if port in (80, 8080, 8443, 443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(128)
        if data:
            text = data.decode(errors="replace").strip().splitlines()[0]
            return text[:80]
    except Exception:
        return None
    return None


def scan_port(ip: str, port: int, timeout: float, do_banner: bool) -> PortResult:
    """Attempt a TCP connect() to a single port and time the result."""
    service = COMMON_PORTS.get(port, "unknown")
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = None
    try:
        result = sock.connect_ex((ip, port))
        elapsed_ms = (time.perf_counter() - start) * 1000

        if result == 0:
            status = "OPEN"
            if do_banner:
                banner = grab_banner(sock, port)
        else:
            status = "CLOSED"
    except socket.timeout:
        elapsed_ms = (time.perf_counter() - start) * 1000
        status = "FILTERED"  # no response at all within timeout -> likely firewalled
    except OSError:
        elapsed_ms = (time.perf_counter() - start) * 1000
        status = "FILTERED"
    finally:
        sock.close()

    return PortResult(port=port, status=status, service=service,
                       response_ms=round(elapsed_ms, 2), banner=banner)


def run_scan(ip: str, ports: list[int], timeout: float, threads: int,
             do_banner: bool) -> list[PortResult]:
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(scan_port, ip, port, timeout, do_banner): port
            for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)


def print_report(target: str, ip: str, results: list[PortResult],
                  show_closed: bool, elapsed: float) -> None:
    print(f"\nTarget: {target}" + (f" ({ip})" if ip != target else ""))
    print(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Ports scanned: {len(results)}\n")

    visible = results if show_closed else [r for r in results if r.status != "CLOSED"]

    if not visible:
        print("No open ports found in the scanned range.\n")
    else:
        header = f"{'PORT':<8} {'STATUS':<10} {'SERVICE':<14} {'TIME (ms)':<10}"
        print(header)
        print("-" * len(header))
        for r in visible:
            print(f"{r.port:<8} {r.status:<10} {r.service:<14} {r.response_ms:<10}")
            if r.banner:
                print(f"         └─ banner: {r.banner}")

    open_count = sum(1 for r in results if r.status == "OPEN")
    closed_count = sum(1 for r in results if r.status == "CLOSED")
    filtered_count = sum(1 for r in results if r.status == "FILTERED")
    print(f"\nSummary: {open_count} open, {closed_count} closed, "
          f"{filtered_count} filtered/unreachable")
    print(f"Scan completed in {elapsed:.2f}s\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A simplified, educational Nmap-style TCP port scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--ports", help="Ports to scan, e.g. '22,80,443' or '1-1024'. "
                                         "Defaults to a common-port list.")
    parser.add_argument("--timeout", type=float, default=0.8,
                         help="Per-port connect timeout in seconds (default: 0.8)")
    parser.add_argument("--threads", type=int, default=100,
                         help="Number of concurrent worker threads (default: 100)")
    parser.add_argument("--closed", action="store_true",
                         help="Also display closed ports (default shows open/filtered only)")
    parser.add_argument("--no-banner", action="store_true",
                         help="Disable basic banner grabbing on open ports")
    parser.add_argument("--json", metavar="FILE",
                         help="Also write results to a JSON file")
    args = parser.parse_args()

    ip = resolve_target(args.target)
    ports = parse_ports(args.ports)

    print(f"[*] Scanning {args.target} ({ip}) — {len(ports)} ports "
          f"(timeout={args.timeout}s, threads={args.threads})")

    start = time.perf_counter()
    try:
        results = run_scan(ip, ports, args.timeout, args.threads, not args.no_banner)
    except KeyboardInterrupt:
        sys.exit("\n[!] Scan interrupted by user.")
    elapsed = time.perf_counter() - start

    print_report(args.target, ip, results, args.closed, elapsed)

    if args.json:
        payload = {
            "target": args.target,
            "resolved_ip": ip,
            "scanned_at": datetime.now().isoformat(),
            "duration_seconds": round(elapsed, 2),
            "results": [asdict(r) for r in results],
        }
        with open(args.json, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"[*] Results saved to {args.json}")


if __name__ == "__main__":
    main()
