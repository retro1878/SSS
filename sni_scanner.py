#!/usr/bin/env python3
"""
SNI Spoofing Scanner
Tests Cloudflare-hosted domains via specific IPs to check accessibility.
Useful for verifying domain reachability through censorship (e.g., Iran/Irancell).

Usage:
    python3 sni_scanner.py [--workers N] [--timeout S] [--output FILE] [--domains FILE]

Curl technique:
    curl https://<domain>:<port> --resolve '<domain>:<port>:<ip>' -sk -o /dev/null -w "%{http_code}"

IP list entries support plain IPs, CIDR ranges, and mixed files:
    104.21.53.76:443
    104.21.53.0/24:443        (expands to 256 IPs on port 443)
    172.67.0.0/16:443,8443    (expands range across multiple ports)
"""

import argparse
import concurrent.futures
import ipaddress
import json
import random
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path


# ── Default target data ──────────────────────────────────────────────────────

DEFAULT_IPS_PORTS = [
    "104.21.92.207:8443",
    "104.21.92.207:2053",
    "104.21.53.224:8443",
    "104.21.53.224:443",
    "172.67.179.179:8443",
    "172.67.179.179:443",
    "172.67.179.179:2053",
    "172.67.179.179:2083",
    "172.67.179.179:2096",
    "172.67.209.68:443",
    "172.67.209.68:8443",
    "172.67.209.68:2053",
    "172.67.209.68:2096",
    "172.67.209.68:2083",
    "104.21.53.76:2053",
    "104.21.53.76:443",
    "104.21.53.76:8443",
    "104.21.53.76:2096",
]

DEFAULT_DOMAINS = [
    "hcaptcha.com",
    "api.hcaptcha.com",
    "assets.hcaptcha.com",
    "imgs.hcaptcha.com",
    "js.hcaptcha.com",
    "newassets.hcaptcha.com",
    "dashboard.hcaptcha.com",
    "health-check.hcaptcha.com",
    "www.hcaptcha.com",
    "three-cust.hcaptcha.com",
    "accounts.hcaptcha.com",
    "jobs.hcaptcha.com",
    "sni-cloudflare.com",
]

# Cloudflare's published IPv4 ranges (source: cloudflare.com/ips-v4)
CLOUDFLARE_RANGES = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

# HTTP codes that indicate the SNI trick is working (server responded)
SUCCESS_CODES = {200, 204, 301, 302, 307, 308, 400, 403, 404, 405, 429}
# 403/404/400 from the origin still means the connection went through


# ── IP range expansion ───────────────────────────────────────────────────────

def expand_entry(entry: str, sample: int) -> list[tuple[str, int]]:
    """
    Parse one IP list entry into (ip, port) tuples.

    Supported formats:
        1.2.3.4:443               → single IP, single port
        1.2.3.0/24:443            → CIDR range, single port
        1.2.3.0/24:443,8443,2053  → CIDR range, multiple ports
    """
    # Split off port(s) — last colon-separated token(s) after the IP/CIDR
    # CIDR contains '/', so split on the last ':' only when no '/' in port part
    last_colon = entry.rfind(":")
    ip_part = entry[:last_colon]
    port_part = entry[last_colon + 1:]
    ports = [int(p.strip()) for p in port_part.split(",") if p.strip().isdigit()]

    if "/" in ip_part:
        network = ipaddress.IPv4Network(ip_part, strict=False)
        all_hosts = [str(h) for h in network.hosts()] or [str(network.network_address)]
        if sample and len(all_hosts) > sample:
            hosts = random.sample(all_hosts, sample)
        else:
            hosts = all_hosts
    else:
        hosts = [ip_part]

    return [(ip, port) for ip in hosts for port in ports]


def expand_ip_ports(entries: list[str], sample: int) -> list[tuple[str, int]]:
    result = []
    for entry in entries:
        try:
            result.extend(expand_entry(entry, sample))
        except Exception as e:
            print(f"  [WARN] Skipping invalid entry '{entry}': {e}", file=sys.stderr)
    # Deduplicate while preserving order
    seen: set[tuple[str, int]] = set()
    deduped = []
    for item in result:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def build_cloudflare_entries(ports: list[int]) -> list[str]:
    return [f"{cidr}:{','.join(str(p) for p in ports)}" for cidr in CLOUDFLARE_RANGES]


# ── Data types ───────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    domain: str
    ip: str
    port: int
    http_code: int
    success: bool
    latency_ms: float
    error: str = ""

    def label(self) -> str:
        if self.success:
            return f"✅ {self.http_code}"
        if self.error:
            return f"❌ ERR"
        return f"⛔ {self.http_code}"


# ── Core scanning logic ──────────────────────────────────────────────────────

def probe(domain: str, ip: str, port: int, timeout: int) -> ScanResult:
    url = f"https://{domain}:{port}"
    resolve = f"{domain}:{port}:{ip}"
    cmd = [
        "curl",
        url,
        "--resolve", resolve,
        "-sk",                   # -s silent, -k ignore cert errors (IP ≠ domain cert)
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "--max-time", str(timeout),
        "--connect-timeout", str(min(timeout, 10)),
    ]

    t0 = time.monotonic()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        latency = (time.monotonic() - t0) * 1000
        code_str = result.stdout.strip()
        code = int(code_str) if code_str.isdigit() else 0
        success = code in SUCCESS_CODES
        return ScanResult(domain=domain, ip=ip, port=port, http_code=code,
                          success=success, latency_ms=latency)
    except subprocess.TimeoutExpired:
        latency = (time.monotonic() - t0) * 1000
        return ScanResult(domain=domain, ip=ip, port=port, http_code=0,
                          success=False, latency_ms=latency, error="timeout")
    except Exception as e:
        latency = (time.monotonic() - t0) * 1000
        return ScanResult(domain=domain, ip=ip, port=port, http_code=0,
                          success=False, latency_ms=latency, error=str(e))


def build_tasks(domains: list[str], ip_port_pairs: list[tuple[str, int]]) -> list[tuple]:
    return [(domain, ip, port) for domain in domains for ip, port in ip_port_pairs]


# ── Output helpers ───────────────────────────────────────────────────────────

def print_result(r: ScanResult, verbose: bool = False) -> None:
    status = r.label()
    latency = f"{r.latency_ms:.0f}ms"
    line = f"  {status:12s} {r.domain:40s} {r.ip}:{r.port:<6} {latency}"
    if verbose and r.error:
        line += f"  [{r.error}]"
    print(line)


def print_summary(results: list[ScanResult], elapsed: float) -> None:
    ok = [r for r in results if r.success]
    fail = [r for r in results if not r.success]

    print("\n" + "═" * 72)
    print(f"  SCAN COMPLETE  —  {len(results)} probes in {elapsed:.1f}s")
    print(f"  ✅ Reachable: {len(ok)}   ❌ Unreachable: {len(fail)}")
    print("═" * 72)

    if ok:
        print("\n  Working combinations:")
        for r in sorted(ok, key=lambda x: (x.domain, x.ip, x.port)):
            print(f"    {r.domain}  →  {r.ip}:{r.port}  ({r.http_code}, {r.latency_ms:.0f}ms)")

    print("\n  Per-domain reachability:")
    domains = sorted({r.domain for r in results})
    for d in domains:
        dr = [r for r in results if r.domain == d]
        ok_count = sum(1 for r in dr if r.success)
        mark = "✅" if ok_count else "❌"
        print(f"    {mark} {d:42s} {ok_count}/{len(dr)} IPs reachable")
    print()


def save_json(results: list[ScanResult], path: str) -> None:
    data = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "total": len(results),
        "reachable": sum(1 for r in results if r.success),
        "results": [asdict(r) for r in results],
    }
    Path(path).write_text(json.dumps(data, indent=2))
    print(f"  Results saved → {path}")


def save_working_curl(results: list[ScanResult], path: str) -> None:
    ok = [r for r in results if r.success]
    lines = ["#!/usr/bin/env bash", "# Working SNI combinations\n"]
    for r in sorted(ok, key=lambda x: (x.domain, x.ip, x.port)):
        cmd = (f"curl https://{r.domain}:{r.port} "
               f"--resolve '{r.domain}:{r.port}:{r.ip}' -sk -o /dev/null -w '%{{http_code}}'")
        lines.append(cmd)
    Path(path).write_text("\n".join(lines) + "\n")
    Path(path).chmod(0o755)
    print(f"  Working curls → {path}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def load_lines(path: str) -> list[str]:
    return [l.strip() for l in Path(path).read_text().splitlines()
            if l.strip() and not l.startswith("#")]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SNI Spoofing Scanner — test Cloudflare IPs against domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--workers", "-w", type=int, default=20,
                        help="Parallel workers (default: 20)")
    parser.add_argument("--timeout", "-t", type=int, default=15,
                        help="Per-probe timeout in seconds (default: 15)")
    parser.add_argument("--output", "-o", default="",
                        help="Save JSON results to FILE")
    parser.add_argument("--domains", "-d", default="",
                        help="File with one domain per line (default: built-in list)")
    parser.add_argument("--ips", "-i", default="",
                        help="File with IP:PORT entries; supports CIDR ranges (default: built-in list)")
    parser.add_argument("--cloudflare-ranges", "-c", metavar="PORTS",
                        help="Scan all Cloudflare IP ranges on given ports, e.g. 443 or 443,8443")
    parser.add_argument("--sample", "-s", type=int, default=20, metavar="N",
                        help="Max IPs to randomly sample per CIDR range (default: 20, 0 = unlimited)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show errors inline")
    parser.add_argument("--working-only", action="store_true",
                        help="Print only successful results during scan")
    args = parser.parse_args()

    domains = load_lines(args.domains) if args.domains else DEFAULT_DOMAINS
    raw_entries = load_lines(args.ips) if args.ips else list(DEFAULT_IPS_PORTS)

    if args.cloudflare_ranges:
        ports = [int(p.strip()) for p in args.cloudflare_ranges.split(",") if p.strip().isdigit()]
        if not ports:
            print("--cloudflare-ranges requires at least one valid port, e.g. --cloudflare-ranges 443")
            sys.exit(1)
        raw_entries = build_cloudflare_entries(ports)
        print(f"\n  Using {len(CLOUDFLARE_RANGES)} Cloudflare ranges × {len(ports)} port(s): {ports}")

    sample = args.sample if args.sample > 0 else 0
    ip_port_pairs = expand_ip_ports(raw_entries, sample)

    tasks = build_tasks(domains, ip_port_pairs)
    total = len(tasks)

    print(f"\n{'═'*72}")
    print(f"  SNI Spoofing Scanner")
    print(f"  Domains: {len(domains)}   IP:Port combos: {len(ip_port_pairs)}   Total probes: {total}")
    print(f"  Workers: {args.workers}   Timeout: {args.timeout}s", end="")
    if sample:
        print(f"   Sample: {sample} IPs/range", end="")
    print(f"\n{'═'*72}\n")

    results: list[ScanResult] = []
    done = 0
    t_start = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(probe, domain, ip, port, args.timeout): (domain, ip, port)
            for domain, ip, port in tasks
        }
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            results.append(r)
            done += 1
            if not args.working_only or r.success:
                print_result(r, verbose=args.verbose)
            if done % 50 == 0:
                print(f"\n  [{done}/{total} done, {sum(1 for x in results if x.success)} working so far]\n")

    elapsed = time.monotonic() - t_start
    print_summary(results, elapsed)

    if args.output:
        save_json(results, args.output)
        base = args.output.rsplit(".", 1)[0]
        save_working_curl(results, base + "_working.sh")
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_json = f"scan_{ts}.json"
        out_sh = f"scan_{ts}_working.sh"
        save_json(results, out_json)
        save_working_curl(results, out_sh)


if __name__ == "__main__":
    main()
