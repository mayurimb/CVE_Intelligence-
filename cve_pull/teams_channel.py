import os
import json
import requests
from dotenv import load_dotenv
from pull_data import pull_cves

load_dotenv()

TEAMS_URL = os.getenv("TEAMS_FLOW_URL")

def format_message(cves):
    if not cves:
        return "🛡️ No new CVEs found in the past 1 day."

    message = "**🛡️ Daily CVE Updates** \n"
    for cve in cves:
        message += f"- **{cve['cve_id']}**: {cve['description'] or 'No description'}\n"
        if cve["severity"]:
            message += f"  - Severity: `{cve['severity']}` | Score: `{cve['score']}` | Source: `{cve['source']}`\n"
        elif cve["source"] == "Unavailable":
            message += f"  - ⚠️ CVE Info Unavailable from GitHub and NVD.\n"
        message += "\n"
    return message

def send_to_teams():
    cves = pull_cves(days=7)
    payload = {
        "text": format_message(cves)
    }

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(TEAMS_URL, headers=headers, json=payload)

    if response.status_code in [200, 202]:
        print("✅ CVE message posted to Teams successfully.")
    else:
        print(f"❌ Failed to post message. Status: {response.status_code}, Details: {response.text}")

if __name__ == "__main__":
    send_to_teams()
