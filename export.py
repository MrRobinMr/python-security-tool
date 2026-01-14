import csv
import json
from datetime import datetime

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

def save_to_csv(report, filename=f"report_{timestamp}.csv"):
    if not report:
        return

    headers = report[0].keys()

    try:
        with open(filename, 'w', newline='', encoding='utf-8-sig') as output_file:
            writer = csv.DictWriter(output_file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(report)

        print(f"✅ CSV report saved successfully: {filename}")
    except Exception as e:
        print(f"❌ Error saving CSV: {e}")


def save_to_json(report, filename=f"report_{timestamp}.json"):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)

        print(f"✅ JSON data saved successfully: {filename}")
    except Exception as e:
        print(f"❌ Error saving JSON: {e}")