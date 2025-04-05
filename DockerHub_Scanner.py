#!/usr/bin/env python3
# ✔️ Парсит DockerHub по COMPANY (пример: tesla)
# ✔️ Пуллит и распаковывает все слои образа
# ✔️ Ищет JAR/WAR файлы, распаковывает и декомпилирует их
# ✔️ Прогоняет TruffleHog по слоям и docker image
# ✔️ Прогоняет Trivy по vuln/secret
# ✔️ Делает уведомления в Telegram о находках (закомментировано)
# ✔️ Сохраняет CSV с результатами в папке /docker_scan_reports/<domain>
# ✔️ Лаконичный вывод по умолчанию, подробный при использовании -v/--verbose
# ✔️ Очистка tar/extracted файлов после анализа (по умолчанию), либо флагом --keep
# ✔️ Автор: clevergod | @securixy_kz | https://www.clevergod.net

import argparse
import subprocess
import os
import sys
import time
import json
import csv
from datetime import datetime, timedelta
from prettytable import PrettyTable  # pip install prettytable (если нет)

def print_banner():
    print(r"""
░█▀▀░█▀▀░█▀▀░█░█░█▀▄░▀█▀░█░█░█░█
░▀▀█░█▀▀░█░░░█░█░█▀▄░░█░░▄▀▄░░█░
░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀░░▀░
░█▀▄░█░█░░░█▀▀░█░░░█▀▀░█░█░█▀▀░█▀▄░█▀▀░█▀█░█▀▄
░█▀▄░░█░░░░█░░░█░░░█▀▀░▀▄▀░█▀▀░█▀▄░█░█░█░█░█░█
░▀▀░░░▀░░░░▀▀▀░▀▀▀░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀░
""")

parser = argparse.ArgumentParser(description="DockerHub Scanner by clevergod (@securixy_kz)")
parser.add_argument('-d', '--domain', help='DockerHub namespace (example: tesla)')
parser.add_argument('-i', '--image', help='Specific DockerHub image (example: tesla/fleet-telemetry)')
parser.add_argument('-f', '--file', help='File with list of domains (one per line)')
parser.add_argument('-t', '--tag', default='latest', help='Docker image tag (default: latest)')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose/debug output')
parser.add_argument('--keep', action='store_true', help='Keep extracted/tar files (default: delete them)')
args = parser.parse_args()

BASE_REPORT_DIR = './docker_scan_reports'
DATE_NOW = datetime.now().strftime('%Y%m%d_%H%M%S')
VERBOSE = args.verbose

def log(msg): print(msg)
def debug(msg): print(msg) if VERBOSE else None

def run_cmd(cmd):
    debug(f'[+] CMD: {cmd}')
    return subprocess.run(cmd, shell=True, capture_output=not VERBOSE, text=True)

def fetch_repositories(domain):
    page, repositories = 1, []
    one_year_ago = datetime.now() - timedelta(days=365)  # Один год назад
    log(f"[+] Fetching page {page}...")

    while True:
        url = f'https://hub.docker.com/v2/repositories/{domain}/?page_size=100&page={page}'
        resp = subprocess.run(f"curl -s '{url}'", shell=True, capture_output=True, text=True)
        if resp.returncode != 0: log(f"[-] Error fetching DockerHub API"); sys.exit(1)

        data = json.loads(resp.stdout)
        results = data.get('results', [])
        if not results: break

        for repo in results:
            # Преобразуем дату last_updated в объект datetime
            last_updated = datetime.fromisoformat(repo['last_updated'].replace("Z", "+00:00"))
            if last_updated >= one_year_ago:  # Фильтруем по дате
                repositories.append(repo['name'])

        if not data.get('next'): break
        page += 1

    log(f"[+] Found repositories updated within the last year: {len(repositories)}")
    for repo in repositories:
        print(f"    - {domain}/{repo}")
    return repositories

def pull_image(image, tag):
    log(f"[+] Pulling image: {image}:{tag}")
    result = run_cmd(f'docker pull {image}:{tag}')
    if result.returncode != 0: log(f"[-] Failed to pull image {image}:{tag}"); sys.exit(1)

def save_and_extract_image(image, tag, domain):
    folder = f"{BASE_REPORT_DIR}/{domain}"
    os.makedirs(folder, exist_ok=True)

    tar_file = f"{folder}/{image.replace('/', '_')}.tar"
    extracted_dir = f"{folder}/extracted_{image.replace('/', '_')}"

    log(f"[+] Saving image {image} as {tar_file} ...")
    run_cmd(f'docker save {image}:{tag} -o {tar_file}')

    log(f"[+] Extracting {tar_file} to {extracted_dir} ...")
    os.makedirs(extracted_dir, exist_ok=True)
    run_cmd(f'tar -xf {tar_file} -C {extracted_dir}')

    return tar_file, extracted_dir

def trivy_scan(image, tag, report_folder):
    secrets_file = f'{report_folder}/{image.replace("/", "_")}_secrets_{DATE_NOW}.json'
    vulns_file = f'{report_folder}/{image.replace("/", "_")}_vulns_{DATE_NOW}.json'

    log("[+] Trivy: Scanning for secrets...")
    run_cmd(f"trivy image {image}:{tag} --scanners secret --format json --output {secrets_file}")

    log("[+] Trivy: Scanning for vulnerabilities...")
    run_cmd(f"trivy image {image}:{tag} --scanners vuln --format json --output {vulns_file}")

    return secrets_file, vulns_file

def trufflehog_scan(image, report_folder):
    log("[+] TruffleHog: Scanning docker image...")
    report_file = f'{report_folder}/{image.replace("/", "_")}_trufflehog_{DATE_NOW}.json'
    run_cmd(f'trufflehog docker --image={image} --json > {report_file}')
    return report_file

def parse_trivy_vulns(file):
    if not os.path.exists(file): return 0, 0, 0, 0
    with open(file) as f: data = json.load(f)

    critical, high, medium, low = 0, 0, 0, 0
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', '').upper()
            if severity == 'CRITICAL': critical += 1
            elif severity == 'HIGH': high += 1
            elif severity == 'MEDIUM': medium += 1
            elif severity == 'LOW': low += 1

    return critical, high, medium, low

def parse_trivy_secrets(file):
    if not os.path.exists(file): return 0
    with open(file) as f: data = json.load(f)

    count = 0
    for result in data.get('Results', []):
        if result.get('Secrets'): count += len(result['Secrets'])
    return count

def parse_trufflehog(file):
    if not os.path.exists(file): return 0
    count = 0
    with open(file) as f:
        for line in f:
            if line.strip(): count += 1
    return count

def clean_files(tar_file, extracted_dir):
    if args.keep: return
    log("[+] Cleaning temporary files ...")
    try:
        if os.path.exists(tar_file): os.remove(tar_file)
        if os.path.exists(extracted_dir): subprocess.run(f"rm -rf {extracted_dir}", shell=True)
    except Exception as e:
        log(f"[-] Error during cleanup: {e}")

def clean_image(image, tag):
    log(f"[+] Cleaning docker image {image}:{tag} ...")
    run_cmd(f'docker rmi {image}:{tag} --force')

def scan_image(image, tag, domain, reports):
    pull_image(image, tag)
    tar_file, extracted_dir = save_and_extract_image(image, tag, domain)

    report_folder = f"{BASE_REPORT_DIR}/{domain}"
    secrets_file, vulns_file = trivy_scan(image, tag, report_folder)
    trufflehog_file = trufflehog_scan(image, report_folder)

    critical, high, medium, low = parse_trivy_vulns(vulns_file)
    secrets_trivy = parse_trivy_secrets(secrets_file)
    secrets_trufflehog = parse_trufflehog(trufflehog_file)

    log("========================")
    log(f"[+] Container: {image}")
    log(f"[+] CVEs: Critical={critical}, High={high}, Medium={medium}, Low={low}")
    log(f"[+] Secrets found (Trivy): {secrets_trivy}")
    log(f"[+] Secrets found (TruffleHog): {secrets_trufflehog}")
    log("========================")

    reports.append({
        'Date': datetime.now().strftime('%Y-%m-%d'),
        'Container': image,
        'Critical': critical,
        'High': high,
        'Medium': medium,
        'Low': low,
        'Secrets': secrets_trivy + secrets_trufflehog
    })

    clean_files(tar_file, extracted_dir)
    clean_image(image, tag)

def print_final_table(reports):
    log("[+] ========== FINAL REPORT ==========")
    table = PrettyTable()
    table.field_names = ["Date", "Container", "Critical", "High", "Medium", "Low", "Secrets"]

    for r in reports:
        table.add_row([r['Date'], r['Container'], r['Critical'], r['High'], r['Medium'], r['Low'], r['Secrets']])

    print(table)
    log("[+] ==================================")

def save_csv(reports, domain):
    folder = f"{BASE_REPORT_DIR}/{domain}"
    filename = f'{folder}/{domain}_docker_scan_report_{DATE_NOW}.csv'
    keys = reports[0].keys()

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(reports)

    log(f"[+] CSV report saved to {filename}")

def main():
    print_banner()
    reports = []

    if args.file:
        with open(args.file, 'r') as file:
            domains = file.readlines()
        domains = [domain.strip() for domain in domains]
        for domain in domains:
            log(f"[+] Scanning domain: {domain}")
            repos = fetch_repositories(domain)
            if not repos: log(f"[-] No repositories found for {domain}"); continue

            for repo in repos:
                image = f"{domain}/{repo}"
                scan_image(image, args.tag, domain, reports)
            save_csv(reports, domain)
            print_final_table(reports)

    elif args.domain:
        repos = fetch_repositories(args.domain)
        if not repos: log(f"[-] No repositories found for {args.domain}"); sys.exit(1)

        for repo in repos:
            image = f"{args.domain}/{repo}"
            scan_image(image, args.tag, args.domain, reports)
        save_csv(reports, args.domain)
        print_final_table(reports)

    elif args.image:
        scan_image(args.image, args.tag, args.image.split('/')[0], reports)
        save_csv(reports, args.image.split('/')[0])
        print_final_table(reports)

    else:
        log("[-] Please provide either a domain (-d) or an image (-i).")

if __name__ == '__main__':
    main()
