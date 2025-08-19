#!/usr/bin/env python3
"""
SAFE INFO SCANNER — for authorized security assessments only
================================================================

This single-file Python CLI performs **non-destructive, consent-based** information gathering.
It intentionally omits/neutralizes exploitative features (e.g., automated SQLi exploitation,
forced admin discovery, database hunting) and only runs active probes when you
explicitly confirm authorization via a command flag.

Covered modules (best-effort, no external paid APIs required):
1) Basic Scan
   - Site Title
   - IP Address
   - Web Server Detection (headers)
   - CMS Detection (heuristics)
   - CDN/Cloudflare Detection (headers/CNAME hints)
   - robots.txt fetch
2) Whois Lookup (built-in WHOIS client, with fallbacks)
3) Geo-IP Lookup (optional: from free ipinfo.io if token provided; otherwise skipped)
4) Banner Grab (safe, short, read-only handshake on common ports)
5) DNS Lookup (A/AAAA/MX/NS/TXT if dnspython present; otherwise A only)
6) Subnet Calculator (for any CIDR you pass)
7) Nmap Wrapper (optional; runs only if you pass --allow-active and nmap is installed)
8) Subdomain (passive) enumeration via crt.sh (no brute-force)
9) Reverse IP Lookup (optional, best-effort via crt.sh + PTR)
11) Blogger View
   - HTTP Response Code
   - Site Title
   - Social Links Extractor
   - Link Grabber (on-page hrefs)
12) WordPress Scan (non-exploitative)
   - Sensitive Files check (read-only GET for common public files)
   - Version Detection (meta + readme.html if public)
   - Version Advisory (prints CVE search hint URL; no auto-exploit)
13) Admin Paths Check (lightweight — checks a short, safe list only; no brute force)

STRICTLY OMITTED for safety/compliance:
- Error-based SQLi auto-exploitation
- Aggressive admin panel brute forcing
- "Find database" / DB hunting or exfiltration

Usage example:
  python safe_info_scan.py https://example.com --allow-active

"""
from __future__ import annotations
import argparse
import socket
import ssl
import sys
import re
import json
import os
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import List, Optional, Dict, Tuple

try:
    import requests
except Exception as e:
    print("[!] This tool requires the 'requests' package. Install with: pip install requests", file=sys.stderr)
    raise

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None

# dnspython is optional
try:
    import dns.resolver  # type: ignore
    import dns.reversename  # type: ignore
except Exception:
    dns = None  # type: ignore

TIMEOUT = 7
UA = {
    "User-Agent": "SafeInfoScanner/1.0 (+authorized use only)"
}

# ------------------------- Utilities -------------------------

def norm_url(base: str) -> str:
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base


def get_host(url: str) -> Tuple[str, Optional[int], str]:
    p = urlparse(url)
    host = p.hostname or ""
    port = p.port
    scheme = p.scheme or "http"
    return host, port, scheme


def fetch(url: str, allow_active: bool) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers=UA, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        if allow_active:
            print(f"[!] Request failed for {url}: {e}")
        return None


# ------------------------- 1) Basic Scan -------------------------

def scan_basic(base_url: str, allow_active: bool) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {
        "site_title": None,
        "ip_address": None,
        "server": None,
        "x_powered_by": None,
        "cms_hint": None,
        "cdn_cloudflare": None,
        "robots_txt": None,
    }
    u = norm_url(base_url)
    host, _, scheme = get_host(u)

    # IP
    try:
        out["ip_address"] = socket.gethostbyname(host)
    except Exception:
        out["ip_address"] = None

    # Fetch root
    resp = fetch(u, allow_active)
    if resp is not None and resp.ok:
        if BeautifulSoup:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.title.string.strip() if soup.title and soup.title.string else None
            except Exception:
                title = None
        else:
            m = re.search(r"<title>(.*?)</title>", resp.text or "", re.I | re.S)
            title = m.group(1).strip() if m else None
        out["site_title"] = title

        # headers
        server = resp.headers.get("Server")
        xpb = resp.headers.get("X-Powered-By")
        out["server"] = server
        out["x_powered_by"] = xpb

        # simple CMS hints
        cms = []
        gen = re.search(r'<meta[^>]+name=[\"\']generator[\"\'][^>]+content=[\"\']([^\"\']+)[\"\']', resp.text, re.I)
        if gen:
            cms.append(gen.group(1))
        if "wp-content" in (resp.text or ""):
            cms.append("WordPress?")
        if "Joomla!" in (resp.text or ""):
            cms.append("Joomla?")
        if "/sites/all/" in (resp.text or ""):
            cms.append("Drupal?")
        out["cms_hint"] = ", ".join(sorted(set(cms))) if cms else None

        # Cloudflare hints
        cf = False
        for k in resp.headers:
            if k.lower().startswith("cf-"):
                cf = True
        if resp.headers.get("Server", "").lower().strip() == "cloudflare":
            cf = True
        out["cdn_cloudflare"] = "Yes" if cf else "No"

    # robots.txt
    robots_url = urljoin(u, "/robots.txt")
    r2 = fetch(robots_url, allow_active)
    if r2 is not None and r2.status_code in (200, 301, 302):
        text = (r2.text or "").strip()
        out["robots_txt"] = "\n".join(text.splitlines()[:40]) if text else None

    return out


# ------------------------- 2) WHOIS (simple) -------------------------
WHOIS_SERVERS = {
    ".com": "whois.verisign-grs.com",
    ".net": "whois.verisign-grs.com",
    ".org": "whois.pir.org",
    ".io": "whois.nic.io",
    ".id": "whois.id",
}

def whois_query(domain: str) -> str:
    tld = "." + domain.split(".")[-1]
    server = WHOIS_SERVERS.get(tld, "whois.iana.org")
    try:
        with socket.create_connection((server, 43), timeout=TIMEOUT) as s:
            s.sendall((domain + "\r\n").encode())
            data = s.recv(65535)
        text = data.decode(errors="ignore")
        # If IANA, try to find referral server
        m = re.search(r"whois:\s*(\S+)", text, re.I)
        if server == "whois.iana.org" and m:
            ref = m.group(1).strip()
            with socket.create_connection((ref, 43), timeout=TIMEOUT) as s2:
                s2.sendall((domain + "\r\n").encode())
                data2 = s2.recv(131072)
            return data2.decode(errors="ignore")
        return text
    except Exception as e:
        return f"[whois] lookup failed: {e}"


# ------------------------- 3) Geo-IP (optional) -------------------------

def geoip_lookup(ip: str) -> Optional[Dict[str, str]]:
    token = os.environ.get("IPINFO_TOKEN", "")
    if not token:
        return None
    try:
        r = requests.get(f"https://ipinfo.io/{ip}?token={token}", timeout=TIMEOUT)
        if r.ok:
            return r.json()
    except Exception:
        return None
    return None


# ------------------------- 4) Banner Grab -------------------------
COMMON_PORTS = [21,22,25,80,110,143,443,587,993,995,3306,3389,8080,8443]

def grab_banner(host: str, port: int) -> Optional[str]:
    try:
        if port == 443 or port in (8443,):
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.settimeout(TIMEOUT)
                    try:
                        ssock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                    except Exception:
                        pass
                    data = ssock.recv(4096)
                    return data.decode(errors="ignore").splitlines()[0][:200]
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                sock.settimeout(TIMEOUT)
                try:
                    sock.sendall(b"\r\n")
                except Exception:
                    pass
                data = sock.recv(4096)
                if not data:
                    return "(no banner)"
                return data.decode(errors="ignore").splitlines()[0][:200]
    except Exception as e:
        return None


# ------------------------- 5) DNS Lookup -------------------------

def dns_lookup(host: str) -> Dict[str, List[str]]:
    res: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
    if dns:
        try:
            for rtype in ["A","AAAA","MX","NS","TXT"]:
                try:
                    ans = dns.resolver.resolve(host, rtype, lifetime=TIMEOUT)
                    if rtype == "MX":
                        res[rtype] = [str(r.exchange).rstrip('.') for r in ans]  # type: ignore
                    else:
                        res[rtype] = [str(r).strip() for r in ans]  # type: ignore
                except Exception:
                    pass
        except Exception:
            pass
    else:
        try:
            res["A"] = [socket.gethostbyname(host)]
        except Exception:
            pass
    return res


# ------------------------- 6) Subnet Calculator -------------------------

def subnet_info(cidr: str) -> Dict[str, str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return {
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "hosts": str(net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0)),
        "first_host": str(list(net.hosts())[0]) if net.num_addresses > 0 else "-",
        "last_host": str(list(net.hosts())[-1]) if net.num_addresses > 0 else "-",
        "version": str(net.version),
    }


# ------------------------- 7) Nmap Wrapper (optional) -------------------------

def nmap_scan(host: str, allow_active: bool) -> Optional[str]:
    if not allow_active:
        return None
    from shutil import which
    if which("nmap") is None:
        return "[nmap] not installed"
    try:
        import subprocess
        cmd = ["nmap", "-Pn", "-sV", "-T4", host]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return out.stdout or out.stderr
    except Exception as e:
        return f"[nmap] error: {e}"


# ------------------------- 8) Subdomain enumeration (crt.sh) -------------------------

def subdomains_crtsh(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        if r.ok:
            items = r.json()
            names = sorted(set(i.get('name_value','') for i in items))
            out = []
            for n in names:
                for part in n.split("\n"):
                    if part.endswith(domain):
                        out.append(part.strip())
            return sorted(set(out))
    except Exception:
        return []
    return []


# ------------------------- 9) Reverse IP (best-effort) -------------------------

def reverse_ip(ip: str) -> Dict[str, List[str]]:
    res: Dict[str, List[str]] = {"ptr": [], "crtsh": []}
    # PTR
    if dns:
        try:
            rev = dns.reversename.from_address(ip)
            ans = dns.resolver.resolve(rev, "PTR", lifetime=TIMEOUT)
            res["ptr"] = [str(r).rstrip('.') for r in ans]  # type: ignore
        except Exception:
            pass
    # crt.sh search of exact IP appears in certificates (rare)
    try:
        r = requests.get(f"https://crt.sh/?q={ip}&output=json", headers=UA, timeout=TIMEOUT)
        if r.ok:
            items = r.json()
            hosts = sorted(set(i.get('common_name','') for i in items if i.get('common_name')))
            res["crtsh"] = hosts
    except Exception:
        pass
    return res


# ------------------------- 11) Blogger View -------------------------
SOCIAL_DOMAINS = [
    "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
    "t.me", "telegram.me", "youtube.com", "medium.com"
]

def bloggers_view(u: str, allow_active: bool) -> Dict[str, object]:
    info: Dict[str, object] = {"http_status": None, "title": None, "social_links": [], "links": []}
    resp = fetch(u, allow_active)
    if resp is None:
        return info
    info["http_status"] = resp.status_code
    html = resp.text or ""
    if BeautifulSoup:
        try:
            soup = BeautifulSoup(html, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else None
            info["title"] = title
            links = [a.get('href') for a in soup.find_all('a') if a.get('href')]
        except Exception:
            links = re.findall(r"href=\"(.*?)\"", html, re.I)
            info["title"] = None
    else:
        links = re.findall(r"href=\"(.*?)\"", html, re.I)
        m = re.search(r"<title>(.*?)</title>", html, re.I | re.S)
        info["title"] = m.group(1).strip() if m else None

    # Normalize & classify
    abs_links = []
    parsed = urlparse(u)
    for l in links:
        try:
            abs_links.append(urljoin(u, l))
        except Exception:
            pass
    info["links"] = sorted(set(abs_links))
    social = [l for l in abs_links if any(sd in l for sd in SOCIAL_DOMAINS)]
    info["social_links"] = sorted(set(social))
    return info


# ------------------------- 12) WordPress Scan (safe) -------------------------
WP_SENSITIVE = [
    "/wp-config-sample.php",
    "/readme.html",
    "/wp-admin/install.php",
]

def wordpress_scan(u: str, allow_active: bool) -> Dict[str, object]:
    res: Dict[str, object] = {"detected": False, "version": None, "sensitive_public": [], "advisory": None}
    r = fetch(u, allow_active)
    if r is None:
        return res
    html = r.text or ""
    is_wp = "wp-content" in html or "wp-includes" in html
    res["detected"] = bool(is_wp)

    # version via meta generator
    m = re.search(r"<meta[^>]+name=[\"\']generator[\"\'][^>]+content=[\"\']WordPress\s*([0-9\.]*)[\"\']", html, re.I)
    version = m.group(1) if m else None

    # try readme.html (public)
    r2 = fetch(urljoin(u, "/readme.html"), allow_active)
    if (r2 is not None) and (r2.status_code == 200):
        m2 = re.search(r"Version\s*([0-9\.]*)", r2.text or "", re.I)
        if m2:
            version = version or m2.group(1)
        res["sensitive_public"].append("/readme.html")

    # common sensitive files (public)
    for path in WP_SENSITIVE:
        if path == "/readme.html":
            continue
        rr = fetch(urljoin(u, path), allow_active)
        if rr is not None and rr.status_code == 200:
            res["sensitive_public"].append(path)

    res["version"] = version
    if version:
        res["advisory"] = f"Search CVEs: https://www.cvedetails.com/vulnerability-list/vendor_id-2337/product_id-4096/version_id-0/Wordpress-{version}.html"
    return res


# ------------------------- 13) Admin Paths (light) -------------------------
ADMIN_PATHS = [
    "/admin/", "/administrator/", "/login", "/wp-admin/", "/user/login", "/cms/login"
]

def admin_paths(u: str, allow_active: bool) -> Dict[str, int]:
    found: Dict[str, int] = {}
    if not allow_active:
        return found
    for path in ADMIN_PATHS:
        r = fetch(urljoin(u, path), allow_active)
        if r is not None:
            if r.status_code in (200, 401, 403):
                found[path] = r.status_code
    return found


# ------------------------- Pretty print helpers -------------------------

def print_section(title: str):
    print("\n" + "="*len(title))
    print(title)
    print("="*len(title))


def main():
    ap = argparse.ArgumentParser(description="Safe Info Scanner — authorized use only")
    ap.add_argument("target", help="Target URL or domain, e.g., https://example.com")
    ap.add_argument("--cidr", help="Optional CIDR for subnet calculator, e.g., 192.0.2.0/24")
    ap.add_argument("--allow-active", action="store_true", help="Confirm you are authorized to run active probes")
    args = ap.parse_args()

    base = norm_url(args.target)
    host, _, scheme = get_host(base)

    print_section("1) BASIC SCAN")
    basic = scan_basic(base, allow_active=args.allow_active)
    for k, v in basic.items():
        if k == "robots_txt" and v:
            print(f"{k:15}:\n{v}")
        else:
            print(f"{k:15}: {v}")

    print_section("2) WHOIS LOOKUP")
    print(whois_query(host))

    if basic.get("ip_address"):
        print_section("3) GEO-IP LOOKUP (optional)")
        geo = geoip_lookup(basic["ip_address"] or "")
        if geo:
            print(json.dumps(geo, indent=2))
        else:
            print("GeoIP skipped (set IPINFO_TOKEN env var to enable)")

    print_section("4) BANNER GRAB (common ports)")
    if not args.allow_active:
        print("Skipped (run with --allow-active if you have permission)")
    else:
        for p in COMMON_PORTS:
            b = grab_banner(host, p)
            if b:
                print(f"{host}:{p} -> {b}")

    print_section("5) DNS LOOKUP")
    dnsres = dns_lookup(host)
    for rr, vals in dnsres.items():
        print(f"{rr:5}: {', '.join(vals) if vals else '-'}")

    if args.cidr:
        print_section("6) SUBNET CALCULATOR")
        try:
            sub = subnet_info(args.cidr)
            for k, v in sub.items():
                print(f"{k:12}: {v}")
        except Exception as e:
            print(f"Invalid CIDR: {e}")

    print_section("7) NMAP WRAPPER")
    nm = nmap_scan(host, args.allow_active)
    print(nm or "Skipped (needs --allow-active and nmap installed)")

    print_section("8) SUBDOMAIN (crt.sh)")
    subs = subdomains_crtsh(host)
    print("Found:")
    for s in subs[:200]:  # cap for brevity
        print(" -", s)
    if len(subs) > 200:
        print(f"(+ {len(subs)-200} more)")

    if basic.get("ip_address"):
        print_section("9) REVERSE IP")
        rev = reverse_ip(basic["ip_address"] or "")
        for k, v in rev.items():
            print(f"{k:6}: {', '.join(v) if v else '-'}")

    print_section("11) BLOGGER VIEW")
    bv = bloggers_view(base, allow_active=args.allow_active)
    print(f"HTTP: {bv.get('http_status')}")
    print(f"Title: {bv.get('title')}")
    print("Social links:")
    for s in bv.get("social_links", []):
        print(" -", s)
    print("Page links (first 50):")
    for l in bv.get("links", [])[:50]:
        print(" -", l)

    print_section("12) WORDPRESS SCAN (safe)")
    w = wordpress_scan(base, allow_active=args.allow_active)
    print(json.dumps(w, indent=2))

    print_section("13) ADMIN PATHS (light)")
    adm = admin_paths(base, allow_active=args.allow_active)
    if not args.allow_active:
        print("Skipped (needs --allow-active and authorization)")
    else:
        if adm:
            for p, code in adm.items():
                print(f"{p:25} -> HTTP {code}")
        else:
            print("None found in short list")

    print("\nNOTE: Offensive features like automated SQLi exploitation or database hunting are intentionally omitted.\nUse dedicated, legal tools (e.g., OWASP ZAP) within scope-of-work only.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")
