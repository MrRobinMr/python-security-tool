from log_parser import parse_log_type

data, log_type = parse_log_type("sample_logs/ssh.log")

print(log_type)
for entry in data:
    print(entry)