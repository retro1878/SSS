#!/usr/bin/env python3
"""
SNI Spoofing Scanner
Tests Cloudflare-hosted domains via specific IPs to check accessibility.
Useful for verifying domain reachability through censorship (e.g., Iran/Irancell).

Usage:
    python3 sni_scanner.py [--workers N] [--timeout S] [--output FILE] [--domains FILE]

Curl technique:
    curl https://<domain>:<port> --resolve '<domain>:<port>:<ip>' -sk -o /dev/null -w "%{http_code}"
"""

import argparse
import concurrent.futures
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
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

# HTTP codes that indicate the SNI trick is working (server responded)
SUCCESS_CODES = {200, 204, 301, 302, 307, 308, 400, 403, 404, 405, 429}
# 403/404/400 from the origin still means the connection went through


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


def build_tasks(domains: list[str], ip_ports: list[str]) -> list[tuple]:
    tasks = []
    for domain in domains:
        for ip_port in ip_ports:
            ip, port_str = ip_port.rsplit(":", 1)
            tasks.append((domain, ip, int(port_str)))
    return tasks


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

    # Per-domain summary
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
                        help="File with one IP:PORT per line (default: built-in list)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show errors inline")
    parser.add_argument("--working-only", action="store_true",
                        help="Print only successful results during scan")
    args = parser.parse_args()

    domains = load_lines(args.domains) if args.domains else DEFAULT_DOMAINS
    ip_ports = load_lines(args.ips) if args.ips else DEFAULT_IPS_PORTS

    tasks = build_tasks(domains, ip_ports)
    total = len(tasks)

    print(f"\n{'═'*72}")
    print(f"  SNI Spoofing Scanner")
    print(f"  Domains: {len(domains)}   IP:Port combos: {len(ip_ports)}   Total probes: {total}")
    print(f"  Workers: {args.workers}   Timeout: {args.timeout}s")
    print(f"{'═'*72}\n")

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
        # Always save by default
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_json = f"scan_{ts}.json"
        out_sh = f"scan_{ts}_working.sh"
        save_json(results, out_json)
        save_working_curl(results, out_sh)


if __name__ == "__main__":
    main()
