from dotenv import load_dotenv
import os

load_dotenv()

vt_key = os.getenv("VT_API_KEY")
abuse_key = os.getenv("ABUSE_API_KEY")