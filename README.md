Apache Log Analyzer
This project is a Python-based log analysis tool for parsing and analyzing Apache web server logs in the Common Log Format (CLF).
It generates insights such as total requests, unique IP addresses, status code distribution, top endpoints, and error rates.
The tool can output results in both console and JSON formats.

📂 Project Structure
graphql
Copy
Edit
log_analyzer.py       # Main script
logs-small.txt        # Sample log file (input)
output.txt            # Generated console output (report)
output.json           # Generated JSON output (report)
🛠️ Features
Parses Apache logs using a regex pattern matching the Common Log Format.

Counts:

Total requests

Unique IP addresses

Error rates (4xx and 5xx responses)

Status code grouping into:

2xx Success

3xx Redirect

4xx Client Error

5xx Server Error

Top:

5 IP addresses

10 most requested endpoints

Handles malformed lines gracefully.

Outputs:

Console report (output.txt)

JSON report (output.json)

📜 Input Format
The script expects Apache logs in the Common Log Format:

swift
Copy
Edit
127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326
🚀 Usage
1. Clone the repository
bash
Copy
Edit
git clone https://github.com/yourusername/apache-log-analyzer.git
cd apache-log-analyzer
2. Place your log file
Ensure you have a log file (e.g., logs-small.txt) in the project directory.

3. Run the script
bash
Copy
Edit
python log_analyzer.py
4. View Reports
Console output saved to: output.txt

JSON report saved to: output.json

📊 Example Console Output
yaml
Copy
Edit
=== Log Analysis Report ===
File: access.log
Analysis Period: 2023-10-10 13:55:36 to 2023-10-10 14:05:12

SUMMARY:
- Total Requests: 250
- Unique IP Addresses: 32
- Average Response Size: 532 bytes
- Error Rate: 12.4%

TOP IP ADDRESSES:
1. 192.168.1.5 (23 requests)
2. 203.0.113.45 (19 requests)
...

STATUS CODE DISTRIBUTION:
- 2xx Success: 210 (84.0%)
- 3xx Redirect: 10 (4.0%)
- 4xx Client Error: 20 (8.0%)
- 5xx Server Error: 10 (4.0%)

TOP ENDPOINTS:
1. /index.html (34 requests)
2. /login (29 requests)
...
⚙️ Configuration
You can change:

Log file path in:

python
Copy
Edit
analyzer.analyze_file('logs-small.txt')
Output format by calling:

python
Copy
Edit
analyzer.generate_report('console')  # Console + output.txt
analyzer.generate_report('json')     # JSON output.json
📌 Requirements
Python 3.7+

No additional packages required (uses Python standard library)

👤 Author
Nasif Rafidi
📧 rafidinasif117@gmail.com
🔗 (https://github.com/Nasif17)
🔗(https://www.linkedin.com/in/md-nasif-rafidi-63a13b265/)
