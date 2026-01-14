import requests

class OSINTTool:
    def __init__(self, vt_api_key, abuse_api_key):
        self.vt_api_key = vt_api_key
        self.abuse_api_key = abuse_api_key

    def get_virustotal_data(self, ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_api_key}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                attr = response.json()['data']['attributes']

                return {
                    "country": attr.get('country'),
                    "asn": f"AS{attr.get('asn')} ({attr.get('as_owner')})",
                    "vt_malicious": attr.get('last_analysis_stats', {}).get('malicious', 0),
                    "reputation": attr.get('reputation', 0)
                }
        except Exception as e:
            print(f"Error VT {ip}: {e}")
        return {}

    def get_abuseipdb_data(self, ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
        headers = {
            'Accept': 'application/json',
            'Key': self.abuse_api_key
        }

        try:
            response = requests.get(url, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    "abuse_score": data.get('abuseConfidenceScore'),
                    "total_reports": data.get('totalReports')
                }
        except Exception as e:
            print(f"Error AbuseDB {ip}: {e}")
        return {}

    def check_ip(self, ip):
        vt = self.get_virustotal_data(ip)
        abuse = self.get_abuseipdb_data(ip)

        return {
            "ip": ip,
            "country": vt.get("country", "Unknown"),
            "asn": vt.get("asn", "Unknown"),
            "reputation": vt.get("reputation", 0),
            "abuse_score": abuse.get("abuse_score", 0),
            "vt_malicious": vt.get("vt_malicious", 0),
            "total_reports": abuse.get("total_reports", 0)
        }