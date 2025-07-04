import re
import json
from collections import Counter, defaultdict
from datetime import datetime

# Define the regex pattern to match Apache Common Log Format
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] '  # Capture IP address and timestamp
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '  # Capture HTTP method, path, and protocol
    r'(?P<status>\d{3}) (?P<size>\d+)'  # Capture status code and response size
)

# Function to classify the status code into 2xx, 3xx, 4xx, 5xx categories
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
    return 'other'  # If the status code is not in the expected range

# Function to parse the timestamp and return a datetime object
def parse_time(ts):
    # Example timestamp format: 10/Oct/2023:13:55:36 +0000
    try:
        # Only take the date and time part, ignoring the timezone
        return datetime.strptime(ts.split()[0], '%d/%b/%Y:%H:%M:%S')
    except Exception:
        return None  # Return None if parsing fails

class LogAnalyzer:
    def __init__(self):
        self.entries = []  # List to store parsed log entries
        self.malformed_lines = 0  # Counter for malformed log lines

    # Function to parse a single log line using regex
    def parse_log_line(self, line: str) -> dict:
        match = LOG_PATTERN.match(line)  # Try to match the line with the regex pattern
        if not match:
            self.malformed_lines += 1  # Increment malformed line count if no match is found
            return None  # Return None if the line doesn't match the pattern
        data = match.groupdict()  # Convert matched groups into a dictionary
        data['status'] = int(data['status'])  # Convert status code to integer
        data['size'] = int(data['size'])  # Convert response size to integer
        data['timestamp'] = data['timestamp']  # Keep timestamp as string
        return data

    # Function to analyze a log file
    def analyze_file(self, filepath: str):
        self.entries = []  # Reset entries list
        self.malformed_lines = 0  # Reset malformed lines counter
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()  # Remove leading/trailing whitespace
                    if not line:
                        continue  # Skip empty lines
                    data = self.parse_log_line(line)  # Parse the line
                    if data:
                        self.entries.append(data)  # Append valid log entries to list
        except FileNotFoundError:
            print(f"File not found: {filepath}")  # Handle file not found error
            exit(1)  # Exit if the file cannot be opened

    # Function to generate the report in the specified format (console or JSON)
    def generate_report(self, format='console'):
        if not self.entries:
            print("No data to report.")  # If no entries, print a message
            return
        # Calculate time range (from the first to the last timestamp)
        timestamps = [parse_time(e['timestamp']) for e in self.entries if parse_time(e['timestamp'])]
        if timestamps:
            min_time = min(timestamps)
            max_time = max(timestamps)
        else:
            min_time = max_time = "N/A"  # If no timestamps found, mark as "N/A"

        total_requests = len(self.entries)  # Total number of log entries
        unique_ips = set(e['ip'] for e in self.entries)  # Set of unique IP addresses
        avg_resp_size = round(sum(e['size'] for e in self.entries) / total_requests) if total_requests else 0  # Average response size

        # Count status codes by group (2xx, 3xx, 4xx, 5xx)
        status_counter = defaultdict(int)
        error_count = 0
        for e in self.entries:
            group = parse_status_group(e['status'])  # Classify the status code
            status_counter[group] += 1  # Increment the respective group count
            if group in ['4xx', '5xx']:  # Count errors (4xx and 5xx)
                error_count += 1

        error_rate = round((error_count / total_requests) * 100, 1) if total_requests else 0.0  # Calculate error rate

        # Count occurrences of each IP and endpoint
        ip_counter = Counter(e['ip'] for e in self.entries)  # Count IP occurrences
        top_ips = ip_counter.most_common(5)  # Get top 5 IP addresses by request count
        endpoint_counter = Counter(e['path'] for e in self.entries)  # Count endpoint occurrences
        top_endpoints = endpoint_counter.most_common(10)  # Get top 10 requested endpoints

        # Prepare status distribution with count and rate for each group
        status_dist = {}
        for group in ['2xx', '3xx', '4xx', '5xx']:
            count = status_counter.get(group, 0)  # Get count for each group
            rate = round((count / total_requests) * 100, 1) if total_requests else 0.0  # Calculate rate
            status_dist[group] = {"count": count, "rate": rate}

        # Console output format
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

            # Save console output to a file
            with open("output.txt", "w") as out:
                import sys
                sys.stdout = out
                self.generate_report('console_print')  # Call the same function to redirect output to file
                sys.stdout = sys.__stdout__  # Reset stdout back to default

        # Console print (for redirecting to output.txt)
        elif format == 'console_print':
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

        # JSON output format
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
            # Save JSON output to a file
            with open("output.json", "w") as f:
                json.dump(result, f, indent=2)
            print("JSON report written to output.json")

# Main function to execute the script
def main():
    analyzer = LogAnalyzer()  # Create an instance of LogAnalyzer
    analyzer.analyze_file('logs-small.txt')  # Analyze the log file
    analyzer.generate_report('console')  # Generate the console report
    analyzer.generate_report('json')  # Generate the JSON report

# Run the script if executed as a standalone program
if __name__ == "__main__":
    main()
