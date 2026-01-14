from log_parser import parse_log_type
from ip_detector import ip_detector
from osint import OSINTTool
from dotenv import load_dotenv
import os
import time

def calculate_risk(ip_data):
    score = 0

    if ip_data["requests"] > 20:
        score += 20

    if ip_data.get("failed_logins", 0) > 10:
        score += 30

    if ip_data.get("admin_attempts", 0) > 0:
        score += 30

    if ip_data.get("abuse_score", 0) > 80:
        score += 40

    if ip_data.get("vt_malicious", 0) > 3:
        score += 40

    if ip_data.get("country") in ["RU", "CN", "IR", "KP"]:
        score += 20

    # Risk level
    if score >= 120:
        risk = "CRITICAL"
    elif score >= 70:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk

def get_report(log_file):
    finale_report = []

    # selecting and loading log file
    data, log_type = parse_log_type(log_file)

    # requests report
    requests_report = ip_detector(log_type, data)

    # env data import
    load_dotenv()
    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSE_API_KEY")
    osTool = OSINTTool(vt_key, abuse_key)

    # checking suspicious ip with apis
    suspicious = []
    for ip, info in requests_report.items():
        if info["suspicious"]:
            suspicious.append(osTool.check_ip(ip))
            osinttool_data = osTool.check_ip(ip)
            country = osinttool_data.get("country")
            if not country:
                country = "Unknown"

            score, risk = calculate_risk(requests_report[ip])

            finale_report.append(
                {
                    "IP": ip,
                    "Requests": requests_report[ip].get("requests", 0),
                    "AdminRequests": requests_report[ip].get("admin_attempts", 0),
                    "FailedLogins": requests_report[ip].get("failed_logins", 0),
                    "AbuseScore": osinttool_data["abuse_score"],
                    "VT": osinttool_data["vt_malicious"],
                    "Country": country,
                    "Risk": risk,
                    "Score": score
                }
            )
            time.sleep(15)
        else:
            continue

    return finale_report