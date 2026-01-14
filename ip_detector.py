from collections import Counter

# Counting all requests
def request_counter(ip_list):
    count = Counter(ip_list)

    return count

# Counting admin requests
def admin_counter(log_type, data):
    ip_list=[]

    if log_type == "sshd":
        for item in data:
            if item.get("user") in ["root", "admin"]:
                ip_list.append(item["ip"])
    elif log_type == "apache":
        for item in data:
            if item.get("path") in ["/admin", "/login", "/wp-login"]:
                ip_list.append(item["ip"])
    else:
        raise ValueError("Unknown log type")

    admin_count = Counter(ip_list)
    return admin_count

# Main if filter
def ip_detector(log_type, data):
    final_data = {}
    ip_list = [item["ip"] for item in data]

    all_requests = request_counter(ip_list)
    admin_request = admin_counter(log_type, data)

    for ip in all_requests:
        requests = all_requests[ip]
        admin_attempts = admin_request.get(ip, 0)
        is_suspicious = requests > 20

        final_data[ip] = {
            "requests": requests,
            "admin_attempts": admin_attempts,
            "suspicious": is_suspicious
        }

    return final_data