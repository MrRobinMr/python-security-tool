from log_parser import parse_log_type
from ip_detector import ip_detector
from osint import OSINTTool
from dotenv import load_dotenv
import os

# env data import
load_dotenv()
vt_key = os.getenv("VT_API_KEY")
abuse_key = os.getenv("ABUSE_API_KEY")


data, log_type = parse_log_type("sample_logs/apache.log")

report = ip_detector(log_type, data)
