from report import get_report
from print_table import print_table
import export
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Security Log Analyzer & OSINT Scanner")

    parser.add_argument(
        "--log",
        "-l",
        type=str,
        help="Path to the log file (e.g., sample_logs/apache.log)",
        required=True
    )

    args = parser.parse_args()

    log_path = args.log

    try:
        report = get_report(log_path)

        if report:
            print_table(report)
            export.save_to_csv(report)
            export.save_to_json(report)
        else:
            print("No suspicious data found.")

    except FileNotFoundError:
        print(f"Error: File '{log_path}' not found.")
        sys.exit(1)


if __name__ == "__main__":
    main()