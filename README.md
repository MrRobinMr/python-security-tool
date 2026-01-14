PYTHON SECURITY TOOL

Log analysis and IP reputation OSINT tool

This is a Python-based security tool that analyzes server logs and verifies IP addresses using open-source intelligence (OSINT) services such as VirusTotal and AbuseIPDB.

The project simulates how a Security Operations Center (SOC) analyst investigates suspicious activity using log data and threat intelligence.

------------------------------------------------------------

FEATURES

- Supports Apache and SSH log formats
- Detects suspicious behavior such as brute-force attacks, scanning, and admin access attempts
- Integrates with VirusTotal and AbuseIPDB APIs
- Calculates a risk score for each IP address
- Generates clear and readable security reports

------------------------------------------------------------

REQUIREMENTS

- Python 3.10 or newer
- Python packages:
  requests
  python-dotenv
  rich

Sample log files are included in the sample_logs directory.

------------------------------------------------------------

API KEYS SETUP

This tool uses OSINT services that require API keys.

Create a file called .env in the project root directory and add:

VT_API_KEY=your_virustotal_api_key
ABUSE_API_KEY=your_abuseipdb_api_key

The .env file is ignored by Git, so your API keys will never be uploaded to GitHub.

------------------------------------------------------------

HOW TO RUN

To analyze Apache logs:
python main.py --log sample_logs/apache.log

To analyze SSH logs:
python main.py --log sample_logs/ssh.log

------------------------------------------------------------

WHAT THE TOOL ANALYZES

From log data:
- Number of requests from an IP
- Failed login attempts
- Attempts to access admin panels or login pages

From OSINT:
- Abuse confidence score from AbuseIPDB
- Malicious detection count from VirusTotal

These signals are combined into a final risk score and a risk level.

------------------------------------------------------------

RISK SCORE AND RISK LEVEL

The tool calculates a risk score based on multiple security signals:

- High number of requests from one IP
- Multiple failed login attempts
- Attempts to access admin or login pages
- High AbuseIPDB reputation score
- Malicious detections in VirusTotal
- High-risk country of origin

Each factor adds points to the total score.  
The final score is mapped to a risk level:

0–29   LOW  
30–69  MEDIUM  
70–119 HIGH  
120+   CRITICAL  

This method is similar to how SIEM systems evaluate threats in real SOC environments.

------------------------------------------------------------

EXAMPLE OUTPUT

IP: 203.0.113.5
Requests: 54
Failed logins: 18
Abuse score: 95
VirusTotal malicious: 8
Country: RU

Risk score: 160
Risk level: CRITICAL

------------------------------------------------------------

PROJECT STRUCTURE

python-security-tool
main.py
log_parser.py
ip_detector.py
osint.py
report.py
sample_logs
apache.log
ssh.log
.env
.gitignore
README.txt

------------------------------------------------------------

WHY THIS PROJECT

This tool demonstrates:
- Log analysis
- Attack detection logic
- OSINT integration
- Secure API key handling
- Risk scoring similar to SIEM systems

It is designed as a portfolio project for cybersecurity, SOC, and Python positions.

------------------------------------------------------------

AUTHOR

MrRobinMr
GitHub: https://github.com/MrRobinMr
