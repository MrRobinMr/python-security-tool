import re

# Detecting log type
def detect_log_type(lines):
    if "sshd" in lines[0]:
        return "sshd"
    elif "HTTP" in lines[1]:
        return "apache"
    else:
        return "unknown"

# Apache log parse
def parse_apache_log(lines):
    result = []

    pattern = r"(\d+\.\d+\.\d+\.\d+).+\"(GET|POST|PUT|DELETE)\s([^ ]+)"

    for line in lines:
        match = re.match(pattern, line)
        if match:
            ip = match.group(1)
            method = match.group(2)
            path = match.group(3)

            result.append(
                {
                    "ip": ip,
                    "method": method,
                    "path": path,
                    "raw": line.strip()
                }
            )

    return result

# SSHD log parse
def parse_ssh_log(lines):
    result = []

    pattern = r"from (\d+\.\d+\.\d+\.\d+)"

    for line in lines:
        match = re.search(pattern, line)
        if not match:
            continue

        ip = match.group(1)

        if "Failed password" in line:
            event = "failed_login"
        elif "Accepted password" in line:
            event = "success_login"
        else:
            event = "other"

        result.append(
            {
                "ip": ip,
                "event": event,
                "raw": line.strip()
            }
        )

    return result

# Main detecting and parser function
def parse_log_type(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()

    log_type = detect_log_type(lines)

    if log_type == "sshd":
        data = parse_ssh_log(lines)
    elif log_type == "apache":
        data = parse_apache_log(lines)
    else:
        raise ValueError("Unknown log type")

    return data, log_type