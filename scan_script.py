import re
import base64
import requests
from datetime import datetime
import zipfile
import io
from collections import Counter, defaultdict
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Constants
LOG_FILE = "scan_log.txt"
VAR_FILE = "variabel_list.txt"

# Configuration
suspect_vars = ['private_key', 'mnemonic', 'seed', 'password', 'proxy', 'token']
rpc_patterns = [r'https?://[^\s"\']+']

suspicious_api_patterns = [
    r'telegram\.org',
    r'discord\.com',
    r'webhook',
    r'pastebin\.com',
    r'hastebin\.com',
    r'termbin\.com',
    r'anonfiles\.com',
    r'0x[a-fA-F0-9]{40}',
    r'\.onion',
]

messages = {
    "start_scan": {"id": "Masukkan URL repositori GitHub tampa .git", "en": "Enter the GitHub repository URL without .git"},
    "log_started": {"id": "=== Pemindaian dimulai ===", "en": "=== Scan started ==="},
    "log_completed": {"id": "=== Pemindaian selesai ===", "en": "=== Scan completed ==="},
    "url_stats": {"id": "=== Statistik URL API/RPC ===", "en": "=== API/RPC URL Statistics ==="},
    "no_urls": {"id": "Tidak ditemukan URL API/RPC dalam repositori.", "en": "No API/RPC URLs found in the repository."},
    "process_file": {"id": "📂 Memproses file", "en": "📂 Processing file"},
    "sensitive_data": {"id": "👩‍💻 Deteksi pengiriman data sensitif:", "en": "👩‍💻 Sensitive data transmission detected:"},
    "suspicious_base64": {"id": "☢️ Base64 mencurigakan terdeteksi:", "en": "☢️ Suspicious base64 detected:"},
    "repo_download_success": {"id": "✔️ Berhasil mengunduh repositori", "en": "✔️ Successfully downloaded repository"},
    "repo_download_failed": {"id": "❌ Gagal mengunduh repositori", "en": "❌ Failed to download repository"},
}

def show_banner():
    print(Fore.MAGENTA + """
========================================
  █████╗ ██╗   ██╗████████╗ ██████╗ 
 ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
 ███████║██║   ██║   ██║   ██║   ██║
 ██╔══██║██║   ██║   ██║   ██║   ██║
 ██║  ██║╚██████╔╝   ██║   ╚██████╔╝
 ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ 
""" + Fore.LIGHTYELLOW_EX + "sat set" + Fore.WHITE + "                            [by Chandra]" + Fore.MAGENTA + """
========================================
""")

def log(message_key, lang, additional=""):
    if message_key:
        message = messages[message_key][lang] + (" " + additional if additional else "")
    else:
        message = additional
    print(message)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(message + "\n")

def try_decode_base64(line):
    suspicious_decoded = []
    for match in re.findall(r'"([^"]+)"', line):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(k in decoded.lower() for k in ['http', 'rpc', 'token', 'key', 'discord', 'telegram', '0x']):
                suspicious_decoded.append((match, decoded.strip()))
        except Exception:
            continue
    return suspicious_decoded

def detect_custom_sensitive_vars(repo_zip):
    custom_vars = set()
    var_patterns = [
        r'PRIVATE[_\-]?KEY[_\d]*',
        r'PVKEY',
        r'SECRET[_\d]*',
        r'TOKEN[_\d]*',
        r'API[_\-]?KEY[_\d]*',
    ]
    for fname in repo_zip.namelist():
        lower_fname = fname.lower()
        if 'pvkey' in lower_fname or '.env' in lower_fname:
            custom_vars.add(fname.lower())
    for fname in repo_zip.namelist():
        if not fname.endswith(('.py', '.js', '.env', '.txt', '.json')):
            continue
        try:
            with repo_zip.open(fname) as f:
                content = f.read().decode('utf-8', errors='ignore')
                for pattern in var_patterns:
                    found_vars = re.findall(pattern, content, re.IGNORECASE)
                    for v in found_vars:
                        custom_vars.add(v.lower())
        except Exception:
            continue
    return custom_vars

def analyze_code(content, file_path, suspect_vars_dynamic):
    alerts = []
    urls = []
    data_send_alerts = []
    variables_found = set()

    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        for pattern in rpc_patterns:
            matches = re.findall(pattern, line)
            for u in matches:
                if any(x in u.lower() for x in ['rpc', 'api']):
                    urls.append((u.strip(), file_path))

        if re.search(r'(fetch|requests\.post|axios\.post|curl|http\.post)', line, re.IGNORECASE):
            if any(re.search(key, line, re.IGNORECASE) for key in suspect_vars_dynamic):
                data_send_alerts.append((i, file_path, "👩‍💻📤 Data sensitif dikirim ke web"))
                for key in suspect_vars_dynamic:
                    if key in line:
                        variables_found.add(key)
            if 'api.telegram.org' in line:
                data_send_alerts.append((i, file_path, "👩‍💻📤 Data dikirim ke Telegram"))
            if 'discord.com/api/webhooks' in line:
                data_send_alerts.append((i, file_path, "👩‍💻📤 Data dikirim ke Discord"))

        base64_hits = try_decode_base64(line)
        for encoded, decoded in base64_hits:
            alerts.append((i, file_path, f"☢️ {encoded} → {decoded}"))

        # Tambahan: Deteksi script terenkripsi / obfuscated
        if re.search(r'(eval|exec|Function|atob|btoa)', line, re.IGNORECASE):
            alerts.append((i, file_path, "⚠️ Terindikasi obfuscation/encryption: penggunaan eval/exec/Function"))
        if re.search(r'evalfunctionp,a,c,k,e,d', line):
            alerts.append((i, file_path, "⚠️ Terindikasi JavaScript obfuscation (eval-packer)"))
        if re.search(r'[A-Za-z0-9+/=]{80,}', line):
            alerts.append((i, file_path, "⚠️ Terindikasi string base64 panjang (kemungkinan terenkripsi)"))

    return alerts, urls, data_send_alerts, variables_found

def fetch_repo_zip(url, lang):
    try:
        repo_name = url.rstrip('/').split('/')[-1]
        zip_url = f"{url}/archive/refs/heads/main.zip"
        r = requests.get(zip_url)
        r.raise_for_status()
        log("repo_download_success", lang, repo_name)
        return zipfile.ZipFile(io.BytesIO(r.content))
    except Exception as e:
        log("repo_download_failed", lang, str(e))
        return None

def process_repo(repo_zip, lang, suspect_vars_dynamic):
    all_urls = []
    all_vars = defaultdict(set)
    for file_name in repo_zip.namelist():
        if file_name.endswith(('.py', '.js')):
            with repo_zip.open(file_name) as f:
                content = f.read().decode('utf-8', errors='ignore')
                log("process_file", lang, file_name)
                alerts, found_urls, data_alerts, vars_found = analyze_code(content, file_name, suspect_vars_dynamic)
                if data_alerts:
                    log("sensitive_data", lang)
                    for line_num, fpath, detail in data_alerts:
                        log("", lang, f"  Line {line_num} (file: {fpath}): {detail}")
                    all_vars[fpath].update(vars_found)
                if alerts:
                    log("suspicious_base64", lang)
                    for line_num, fpath, detail in alerts:
                        log("", lang, f"  Line {line_num} (file: {fpath}): {detail}")
                all_urls.extend(found_urls)
    with open(VAR_FILE, 'w', encoding='utf-8') as vf:
        for fpath, varset in all_vars.items():
            vf.write(f"[{fpath}]\n")
            for v in varset:
                vf.write(f"- {v}\n")
            vf.write("\n")
    return all_urls

def print_url_statistics(urls, lang):
    if not urls:
        log("no_urls", lang)
        return
    log("url_stats", lang)
    url_counter = Counter([url for url, _ in urls])
    url_sources = defaultdict(set)
    for url, file in urls:
        url_sources[url].add(file)
    total = sum(url_counter.values())
    max_bar = 40
    colors = [Fore.GREEN, Fore.YELLOW, Fore.MAGENTA, Fore.CYAN, Fore.RED, Fore.WHITE]
    for idx, (url, count) in enumerate(url_counter.most_common()):
        percent = (count / total) * 100
        bar_len = int((count / total) * max_bar)
        color = colors[idx % len(colors)]
        bar = color + '█' * bar_len + Style.RESET_ALL
        log("", lang, f"{bar} {Fore.BLUE}{url}{Style.RESET_ALL} ({count}x - {percent:.2f}%)")
        for src in sorted(url_sources[url]):
            log("", lang, f"     ↳ Found in: {src}")

def main():
    lang = input("Pilih bahasa / Choose language (id/en): ").strip().lower()
    if lang not in ["id", "en"]:
        print("Invalid language choice. Defaulting to English.")
        lang = "en"
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"{messages['log_started'][lang]}\n")
    log("start_scan", lang)
    url = input(messages["start_scan"][lang] + ":\n").strip()
    repo_zip = fetch_repo_zip(url, lang)
    if repo_zip:
        custom_vars = detect_custom_sensitive_vars(repo_zip)
        all_suspect_vars = list(set(suspect_vars) | set(custom_vars))
        log("", lang, f"⏳ Variabel sensitif yang dipakai untuk scan: {', '.join(sorted(all_suspect_vars))}")
        urls = process_repo(repo_zip, lang, all_suspect_vars)
        print_url_statistics(urls, lang)
        is_suspicious = False
        suspicious_urls = [
            u for u, _ in urls
            if any(re.search(p, u, re.IGNORECASE) for p in suspicious_api_patterns)
            and [x for x, __ in urls].count(u) == 1
        ]
        if suspicious_urls:
            is_suspicious = True
        elif any('☢️' in line or '👩‍💻📤' in line or '⚠️' in line for line in open(LOG_FILE, encoding='utf-8').readlines()):
            is_suspicious = True
        if is_suspicious:
            log("", lang, "☢️ STATUS: SCRIPT MENCURIGAKAN — Ada indikasi pengiriman data sensitif atau API mencurigakan.")
        else:
            log("", lang, "✅ STATUS: SCRIPT AMAN — Tidak ditemukan aktivitas mencurigakan.")
    log("log_completed", lang)

if __name__ == "__main__":
    show_banner()
    main()
