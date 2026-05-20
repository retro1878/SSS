# SSS — SNI Spoofing Scanner

Tests whether Cloudflare-hosted domains are reachable via specific Cloudflare IPs by spoofing the SNI/Host header using `curl --resolve`. Useful for checking domain accessibility under ISP-level censorship (e.g. Iran/Irancell).

A successful probe (HTTP 2xx–4xx response) means the IP:port path is open — the SNI trick is working.

---

## Requirements

- Python 3.9+
- `curl`

---

## Installation

```bash
git clone https://github.com/retro1878/SSS.git
cd SSS
./install.sh
```

This copies `sni_scanner` to `/usr/local/bin` so you can run it from anywhere.  
To install to a custom location:

```bash
INSTALL_DIR=~/.local/bin ./install.sh
```

**Behind a SOCKS5 proxy?** Pass it to git before cloning:

```bash
# Proxy without authentication
git clone -c "http.proxy=socks5h://127.0.0.1:1080" \
  https://github.com/retro1878/SSS.git

# Proxy with username and password
git clone -c "http.proxy=socks5h://user:password@127.0.0.1:1080" \
  https://github.com/retro1878/SSS.git

cd SSS
./install.sh
```

`socks5h` routes DNS through the proxy too — use `socks5` if you want local DNS resolution.

---

## Usage

```bash
# Run with built-in domains and IPs
sni_scanner

# Show only working results during the scan
sni_scanner --working-only

# Increase speed with more parallel workers
sni_scanner --workers 30

# Adjust per-probe timeout (seconds)
sni_scanner --timeout 10

# Save results to a file (also generates a _working.sh curl script)
sni_scanner --output results.json

# Use custom domain and IP:port lists
sni_scanner --domains domains.txt --ips ips.txt

# Scan all of Cloudflare's published IP ranges on port 443
sni_scanner --cloudflare-ranges 443

# Scan Cloudflare ranges on multiple ports, sample 50 IPs per range
sni_scanner --cloudflare-ranges 443,8443,2053 --sample 50

# Show errors inline (timeouts, connection refused, etc.)
sni_scanner --verbose
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--workers`, `-w` | `20` | Parallel probes |
| `--timeout`, `-t` | `15` | Per-probe timeout in seconds |
| `--output`, `-o` | auto | JSON output file (also saves `_working.sh`) |
| `--domains`, `-d` | built-in | File with one domain per line |
| `--ips`, `-i` | built-in | File with `IP:PORT` entries; supports CIDR ranges |
| `--cloudflare-ranges`, `-c` | off | Scan all Cloudflare IP ranges on given ports (e.g. `443` or `443,8443`) |
| `--sample`, `-s` | `20` | Max IPs randomly sampled per CIDR range (`0` = unlimited) |
| `--working-only` | off | Only print successful probes during scan |
| `--verbose`, `-v` | off | Show error reason next to failed probes |

---

## Input File Format

**domains.txt** — one domain per line:
```
hcaptcha.com
api.hcaptcha.com
www.example.com
```

**ips.txt** — one entry per line; plain IPs, CIDR ranges, and multiple ports are all supported:
```
# Plain IP, single port
104.21.53.76:443

# CIDR range — expanded to all IPs in the subnet on port 443
104.21.53.0/24:443

# CIDR range on multiple ports (comma-separated)
172.67.0.0/16:443,8443,2053
```

Lines starting with `#` are treated as comments.

> **Tip:** Large ranges (e.g. `/13`) can produce hundreds of thousands of IPs.
> Use `--sample N` to randomly pick N IPs per range and keep the scan manageable.

---

## Output

After the scan, two files are saved automatically:

- `scan_<timestamp>.json` — full results for every probe
- `scan_<timestamp>_working.sh` — executable script with working `curl` commands

Example working curl command:
```bash
curl https://hcaptcha.com:443 --resolve 'hcaptcha.com:443:104.21.53.76' -sk -o /dev/null -w '%{http_code}'
```

---

## Sample Results

Scan of 13 hcaptcha.com subdomains × 18 Cloudflare IP:port combos (234 probes):

```
✅ Reachable: 52   ❌ Unreachable: 182

Per-domain reachability:
  ✅ hcaptcha.com              4/18 IPs reachable
  ✅ api.hcaptcha.com          4/18 IPs reachable
  ✅ assets.hcaptcha.com       4/18 IPs reachable
  ...
```

Working IPs (port 443 only):
- `104.21.53.76:443`
- `104.21.53.224:443`
- `172.67.179.179:443`
- `172.67.209.68:443`
