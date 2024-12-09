import re
import json
import csv


log_file = 'server_logs.txt'


log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>[^\]]+)\] "(?P<method>[A-Z]+) /login HTTP/1.1" (?P<status>\d+) \d+'


failed_attempts = {}
logs = []


with open(log_file, 'r') as file:
    for line in file:
        match = re.search(log_pattern, line)
        if match:
            ip = match.group('ip')
            status = int(match.group('status'))
            
            if status == 401:
                if ip in failed_attempts:
                    failed_attempts[ip] += 1
                else:
                    failed_attempts[ip] = 1
            logs.append(match.groupdict())


failed_logins = {ip: count for ip, count in failed_attempts.items() if count > 5}
with open('failed_logins.json', 'w') as f:
    json.dump(failed_logins, f, indent=4)


with open('log_analysis.csv', 'w', newline='') as csvfile:
    fieldnames = ['IP', 'Date', 'HTTP Method', 'Failed Attempts']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for log in logs:
        ip = log['ip']
        date = log['date']
        method = log['method']
        failed_attempt_count = failed_attempts.get(ip, 0)
        writer.writerow({'IP': ip, 'Date': date, 'HTTP Method': method, 'Failed Attempts': failed_attempt_count})


with open('log_analysis.txt', 'w') as file:
    for ip, count in failed_attempts.items():
        file.write(f"IP: {ip}, Failed Attempts: {count}\n")


threat_ips = ['192.168.1.11', '10.0.0.15']  


with open('threat_ips.json', 'w') as f:
    json.dump(threat_ips, f, indent=4)

combined_data = {
    'failed_logins': failed_logins,
    'threat_ips': threat_ips
}


with open('combined_security_data.json', 'w') as f:
    json.dump(combined_data, f, indent=4)

print("Proses başa çatdı.")
