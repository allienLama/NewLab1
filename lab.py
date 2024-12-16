import re
import json
import csv
from selenium import webdriver
from selenium.webdriver.common.by import By
from collections import defaultdict

# Çıxış fayllarının yolları
LOG_FILE = "server_logs.txt"
FAILED_LOGINS_FILE = "failed_logins.json"
LOG_ANALYSIS_FILE = "log_analysis.txt"
LOG_ANALYSIS_CSV = "log_analysis.csv"
THREAT_IPS_FILE = "threat_ips.json"
COMBINED_SECURITY_DATA_FILE = "combined_security_data.json"


def parse_logs(file_path):
    """Server loglarını parse edir."""
    parsed_data = []
    log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"(.*?) (.*?) HTTP/.*?\" (\d+) (\d+)')
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = log_pattern.search(line)
                if match:
                    ip, date, method, endpoint, status, _ = match.groups()
                    parsed_data.append((ip, date, method, status))
        print(f"{len(parsed_data)} giriş qeydi parse edildi.")
    except Exception as e:
        print(f"Girişləri parse edərkən səhv: {e}")
    return parsed_data


def analyze_failed_logins(parsed_data):
    """Uğursuz giriş cəhdlərini analiz edir."""
    failed_attempts = defaultdict(int)
    for ip, _, _, status in parsed_data:
        if status.startswith("40"):
            failed_attempts[ip] += 1
    return {ip: count for ip, count in failed_attempts.items() if count >= 5}


def save_to_file(data, file_path, format_type="json"):
    """Verilən məlumatları JSON və ya TXT formatında fayla saxlayır."""
    try:
        if format_type == "json":
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
        elif format_type == "txt":
            with open(file_path, 'w') as file:
                for key, value in data.items():
                    file.write(f"{key}: {value}\n")
        print(f"Məlumat {file_path} faylına saxlanıldı.")
    except Exception as e:
        print(f"Fayla yazma zamanı səhv: {e}")


def write_to_csv(parsed_data, file_path):
    """Parse edilmiş log məlumatlarını CSV faylında yazır."""
    try:
        with open(file_path, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["IP Ünvanı", "Tarix", "HTTP Metodu", "Status Kodu"])
            writer.writerows(parsed_data)
        print(f"Log məlumatları {file_path} faylında yazıldı.")
    except Exception as e:
        print(f"CSV faylına yazma zamanı səhv: {e}")


def scrape_threat_intelligence(url):
    """Veb səhifədən təhlükə məlumatlarını əldə edir."""
    try:
        driver = webdriver.Firefox()
        driver.get(url)

        rows = driver.find_elements(By.XPATH, "//table//tr")
        threat_ips = {
            row.find_elements(By.TAG_NAME, "td")[0].text.strip(): row.find_elements(By.TAG_NAME, "td")[1].text.strip()
            for row in rows[1:] if len(row.find_elements(By.TAG_NAME, "td")) >= 2
        }

        driver.quit()
        return threat_ips
    except Exception as e:
        print(f"Təhlükə məlumatlarını əldə edərkən səhv: {e}")
        return {}


def match_threat_ips(parsed_data, threat_ips):
    """Giriş məlumatlarını təhlükə IP-ləri ilə uyğunlaşdırır."""
    return {
        ip: {
            "date": date,
            "method": method,
            "status": status,
            "description": threat_ips[ip]
        }
        for ip, date, method, status in parsed_data if ip in threat_ips
    }


def combine_data(failed_logins, matched_threats, output_file):
    """Uğursuz girişləri və təhlükə məlumatlarını birləşdirir."""
    combined_data = {
        "failed_logins": failed_logins,
        "matched_threats": matched_threats
    }
    save_to_file(combined_data, output_file, format_type="json")


def main():
    parsed_data = parse_logs(LOG_FILE)
    if not parsed_data:
        print("Log məlumatları parse edilə bilmədi. Çıxılır.")
        return

    failed_logins = analyze_failed_logins(parsed_data)
    if failed_logins:
        save_to_file(failed_logins, FAILED_LOGINS_FILE)
        save_to_file(failed_logins, LOG_ANALYSIS_FILE, format_type="txt")
    else:
        print("5-dən çox uğursuz cəhd edən IP-lər tapılmadı.")

    write_to_csv(parsed_data, LOG_ANALYSIS_CSV)

    threat_intelligence_url = "http://127.0.0.1:5500/"
    threat_ips = scrape_threat_intelligence(threat_intelligence_url)

    matched_threats = match_threat_ips(parsed_data, threat_ips)
    save_to_file(matched_threats, THREAT_IPS_FILE)

    combine_data(failed_logins, matched_threats, COMBINED_SECURITY_DATA_FILE)


if __name__ == "__main__":
    main()
