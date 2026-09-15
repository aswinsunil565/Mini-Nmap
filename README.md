# Mini-Nmap
A simplified, educational TCP port scanner written in pure Python — built as a
portfolio project to demonstrate core networking and cybersecurity concepts:
TCP connect scanning, concurrency, response-time measurement, and basic
service/banner identification.

It's not a replacement for real [Nmap](https://nmap.org/) — it's a from-scratch
reimplementation of a small slice of what Nmap does, written to show an
understanding of *how* port scanning actually works under the hood.

## Features

- 🔍 Scan a target IP or hostname across common ports (or a custom range)
- ⚡ Concurrent scanning via a thread pool — 25+ ports scan in under a second
- 🟢 Classifies each port as `OPEN`, `CLOSED`, or `FILTERED`
- ⏱ Measures real per-port response time (ms)
- 🏷 Identifies ~25 common services by port (SSH, HTTP, MySQL, RDP, etc.)
- 📡 Lightweight banner grabbing on open ports (reads what the service sends back)
- 📄 Optional JSON export for feeding results into other tooling
- 🧵 Zero third-party dependencies — pure Python standard library

## Example run

Tested against [`scanme.nmap.org`](https://nmap.org/), the official public
target Nmap's own project provides for people to practice scanning against:

```
$ python3 mini_nmap.py scanme.nmap.org
[*] Scanning scanme.nmap.org (45.33.32.156) — 25 ports (timeout=0.8s, threads=100)

Target: scanme.nmap.org (45.33.32.156)
Scan started: 2026-09-15 12:07:44
Ports scanned: 25

PORT     STATUS     SERVICE        TIME (ms)
---------------------------------------------
22       OPEN       SSH            250.43
         └─ banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80       OPEN       HTTP           249.07
         └─ banner: HTTP/1.1 200 OK

Summary: 2 open, 23 closed, 0 filtered/unreachable
Scan completed in 0.85s
```

25 ports scanned concurrently in well under a second, with real service
banners pulled back from both open ports — despite each individual
connection taking ~250ms round-trip.

## Installation

No dependencies to install — just Python 3.10+.

```bash
git clone https://github.com/aswinsunil565/Mini-Nmap.git
cd Mini-Nmap
python3 mini_nmap.py --help
```

## Usage

```bash
# Basic scan of common ports
python3 mini_nmap.py 192.168.1.10

# Scan a custom port range
python3 mini_nmap.py 192.168.1.10 --ports 1-1024

# Scan specific ports
python3 mini_nmap.py 192.168.1.10 --ports 22,80,443,3306

# Show closed ports too (default only shows open/filtered)
python3 mini_nmap.py 192.168.1.10 --closed

# Tune speed vs. accuracy
python3 mini_nmap.py 192.168.1.10 --timeout 0.5 --threads 200

# Save machine-readable results
python3 mini_nmap.py 192.168.1.10 --json results.json
```

### All flags

| Flag          | Description                                                      | Default        |
|---------------|-------------------------------------------------------------------|----------------|
| `--ports`     | Ports to scan: `22,80,443` and/or `1-1024`                       | common port list |
| `--timeout`   | Per-port connect timeout, in seconds                              | `0.8`          |
| `--threads`   | Concurrent worker threads                                         | `100`          |
| `--closed`    | Also display closed ports                                         | off            |
| `--no-banner` | Disable banner grabbing on open ports                             | off (banners on) |
| `--json FILE` | Write results to a JSON file as well as printing the report       | none           |

## How it works

- **Scan technique**: Uses a full TCP `connect()` (via Python's `socket.connect_ex`)
  rather than a raw SYN scan. Real Nmap defaults to a SYN ("half-open") scan
  because it's stealthier and faster, but that requires raw sockets and root
  privileges. A connect scan is the accessible, portable equivalent and
  produces the same `OPEN`/`CLOSED` classification.
- **Concurrency**: Each port is scanned in its own thread via a
  `ThreadPoolExecutor`, so 25+ ports complete in roughly the time of one
  slow connection rather than the sum of all of them.
- **Status classification**:
  - `OPEN` — the TCP handshake completed successfully.
  - `CLOSED` — the target actively refused the connection (RST).
  - `FILTERED` — no response at all within the timeout, which usually means
    a firewall is silently dropping the packets.
- **Banner grabbing**: On open ports, the scanner reads the first bytes the
  service sends back (or, for HTTP-like ports, sends a minimal `HEAD /`
  request first). This is a simplified version of what Nmap's much larger
  service/version detection database does.

## Responsible use

**Only scan systems you own or have explicit written permission to test.**
Unauthorized scanning of networks or hosts you don't control may violate laws
such as the U.S. Computer Fraud and Abuse Act (or equivalent laws elsewhere)
and most organizations' acceptable-use policies.

Safe targets for practice:
- `127.0.0.1` / `localhost` — your own machine
- `scanme.nmap.org` — Nmap's official public test target
- A VM or container you control on an isolated network

## Roadmap / possible extensions

- [ ] Basic OS fingerprinting via TTL/TCP window size heuristics
- [ ] UDP scanning support
- [ ] Colorized/`rich`-based terminal output with a live progress bar
- [ ] Export to CSV/HTML report formats

## License

MIT — do whatever you like with it, just scan responsibly.
