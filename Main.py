import re
import json
from collections import Counter, defaultdict
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+)'
)

def parse_status_group(status):
    status = int(status)
    if 200 <= status < 300:
        return '2xx'
    elif 300 <= status < 400:
        return '3xx'
    elif 400 <= status < 500:
        return '4xx'
    elif 500 <= status < 600:
        return '5xx'
    return 'other'

def parse_time(ts):
    # Example: 10/Oct/2023:13:55:36 +0000
    try:
        return datetime.strptime(ts.split()[0], '%d/%b/%Y:%H:%M:%S')
    except Exception:
        return None

class LogAnalyzer:
    def __init__(self):
        self.entries = []
        self.malformed_lines = 0

    def parse_log_line(self, line: str) -> dict:
        match = LOG_PATTERN.match(line)
        if not match:
            self.malformed_lines += 1
            return None
        data = match.groupdict()
        data['status'] = int(data['status'])
        data['size'] = int(data['size'])
        data['timestamp'] = data['timestamp']
        return data

    def analyze_file(self, filepath: str):
        self.entries = []
        self.malformed_lines = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = self.parse_log_line(line)
                    if data:
                        self.entries.append(data)
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            exit(1)

    def generate_report(self, format='console'):
        if not self.entries:
            print("No data to report.")
            return
        # Time range
        timestamps = [parse_time(e['timestamp']) for e in self.entries if parse_time(e['timestamp'])]
        if timestamps:
            min_time = min(timestamps)
            max_time = max(timestamps)
        else:
            min_time = max_time = "N/A"

        total_requests = len(self.entries)
        unique_ips = set(e['ip'] for e in self.entries)
        avg_resp_size = round(sum(e['size'] for e in self.entries) / total_requests) if total_requests else 0

        # Status code groups
        status_counter = defaultdict(int)
        error_count = 0
        for e in self.entries:
            group = parse_status_group(e['status'])
            status_counter[group] += 1
            if group in ['4xx', '5xx']:
                error_count += 1

        error_rate = round((error_count / total_requests) * 100, 1) if total_requests else 0.0

        ip_counter = Counter(e['ip'] for e in self.entries)
        top_ips = ip_counter.most_common(5)
        endpoint_counter = Counter(e['path'] for e in self.entries)
        top_endpoints = endpoint_counter.most_common(10)

        # Prepare for both console and JSON
        status_dist = {}
        for group in ['2xx', '3xx', '4xx', '5xx']:
            count = status_counter.get(group, 0)
            rate = round((count / total_requests) * 100, 1) if total_requests else 0.0
            status_dist[group] = {"count": count, "rate": rate}

        if format == 'console':
            print("=== Log Analysis Report ===")
            print("File: access.log")
            if isinstance(min_time, datetime):
                print(f"Analysis Period: {min_time} to {max_time}")
            else:
                print("Analysis Period: N/A")
            print("\nSUMMARY:")
            print(f"- Total Requests: {total_requests}")
            print(f"- Unique IP Addresses: {len(unique_ips)}")
            print(f"- Average Response Size: {avg_resp_size} bytes")
            print(f"- Error Rate: {error_rate}%")
            print("\nTOP IP ADDRESSES:")
            for i, (ip, count) in enumerate(top_ips, 1):
                print(f"{i}. {ip} ({count} requests)")
            print("\nSTATUS CODE DISTRIBUTION:")
            for group, data in status_dist.items():
                label = {
                    '2xx': 'Success',
                    '3xx': 'Redirect',
                    '4xx': 'Client Error',
                    '5xx': 'Server Error'
                }.get(group, group)
                print(f"- {group} {label}: {data['count']} ({data['rate']}%)")
            print("\nTOP ENDPOINTS:")
            for i, (ep, count) in enumerate(top_endpoints, 1):
                print(f"{i}. {ep} ({count} requests)")
            if self.malformed_lines:
                print(f"\nMalformed lines skipped: {self.malformed_lines}")

            # Save output
            with open("output.txt", "w") as out:
                import sys
                sys.stdout = out
                self.generate_report('console_print')
                sys.stdout = sys.__stdout__

        elif format == 'console_print':
            # For redirecting to output.txt
            print("=== Log Analysis Report ===")
            print("File: access.log")
            if isinstance(min_time, datetime):
                print(f"Analysis Period: {min_time} to {max_time}")
            else:
                print("Analysis Period: N/A")
            print("\nSUMMARY:")
            print(f"- Total Requests: {total_requests}")
            print(f"- Unique IP Addresses: {len(unique_ips)}")
            print(f"- Average Response Size: {avg_resp_size} bytes")
            print(f"- Error Rate: {error_rate}%")
            print("\nTOP IP ADDRESSES:")
            for i, (ip, count) in enumerate(top_ips, 1):
                print(f"{i}. {ip} ({count} requests)")
            print("\nSTATUS CODE DISTRIBUTION:")
            for group, data in status_dist.items():
                label = {
                    '2xx': 'Success',
                    '3xx': 'Redirect',
                    '4xx': 'Client Error',
                    '5xx': 'Server Error'
                }.get(group, group)
                print(f"- {group} {label}: {data['count']} ({data['rate']}%)")
            print("\nTOP ENDPOINTS:")
            for i, (ep, count) in enumerate(top_endpoints, 1):
                print(f"{i}. {ep} ({count} requests)")
            if self.malformed_lines:
                print(f"\nMalformed lines skipped: {self.malformed_lines}")

        elif format == 'json':
            result = {
                "total_requests": total_requests,
                "unique_ip": len(unique_ips),
                "average_response_size": avg_resp_size,
                "error_rate": error_rate,
                "top_ips": [{"ip": ip, "requests": count} for ip, count in top_ips],
                "status_distribution": {
                    group: {
                        "count": status_dist[group]["count"],
                        "rate": status_dist[group]["rate"]
                    } for group in status_dist
                },
                "top_endpoints": [{"endpoint": ep, "count": count} for ep, count in top_endpoints]
            }
            with open("output.json", "w") as f:
                json.dump(result, f, indent=2)
            print("JSON report written to output.json")

def main():
    analyzer = LogAnalyzer()
    analyzer.analyze_file('logs-small.txt')  # Use logs-small.txt for sample test
    analyzer.generate_report('console')
    analyzer.generate_report('json')

if __name__ == "__main__":
    main()
