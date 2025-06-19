import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import requests
import datetime
import json
import time
from utils import get_env_variable  
from dateutil.parser import isoparse
from datetime import timezone

# Load environment variables
CLASSIC_TOKEN_GITHUB = get_env_variable("CLASSIC_TOKEN_GITHUB")
CVE_GITHUB_API_URL = get_env_variable("CVE_GITHUB_API_URL")
NVD_API_KEY = get_env_variable("NVD_API_KEY")

github_headers = {
    "Accept": "application/vnd.github.v3+json",
    "Authorization": f"token {CLASSIC_TOKEN_GITHUB}"
}

def fetch_from_nvd(cve_id):
    # print(f"NVD API Key: {NVD_API_KEY}")  
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "apiKey": NVD_API_KEY
    }
    params = {
        "cveId": cve_id
    }

    try:
        res = requests.get(url, headers=headers, params=params)
        if res.status_code == 200:
            data = res.json()
            vuln_items = data.get("vulnerabilities", [])
            if not vuln_items:
                return None

            cvss_data = vuln_items[0].get("cve", {}).get("metrics", {})
            # Prefer CVSS v3.1, fallback to CVSS v3.0 or v2
            if "cvssMetricV31" in cvss_data:
                metric = cvss_data["cvssMetricV31"][0]["cvssData"]
                severity = vuln_items[0]["cve"]["metrics"]["cvssMetricV31"][0].get("baseSeverity")
            elif "cvssMetricV30" in cvss_data:
                metric = cvss_data["cvssMetricV30"][0]["cvssData"]
                severity = vuln_items[0]["cve"]["metrics"]["cvssMetricV30"][0].get("baseSeverity")
            elif "cvssMetricV2" in cvss_data:
                metric = cvss_data["cvssMetricV2"][0]["cvssData"]
                severity = vuln_items[0]["cve"]["metrics"]["cvssMetricV2"][0].get("baseSeverity")
            else:
                return None

            return {
                "severity": severity,
                "score": metric.get("baseScore"),
                "vector": metric.get("vectorString")
            }
        else:
            print(f"❌ NVD API failed for {cve_id}: {res.status_code} | {res.text[:100]}")
            return None
    except Exception as e:
        print(f"⚠️ Exception while fetching {cve_id} from NVD: {e}")
        return None


def pull_cves(days=1):
    since_date = datetime.datetime.now(timezone.utc) - datetime.timedelta(days=days)
    print(f"⏳ Pulling CVEs published after {since_date.isoformat()}")

    res = requests.get(CVE_GITHUB_API_URL, headers=github_headers)

    try:
        file_list = res.json()
        if not isinstance(file_list, list):
            print("❌ Unexpected response from GitHub:", file_list)
            return []
    except Exception as e:
        print("❌ Failed to parse JSON from GitHub:", e)
        print("Response content was:", res.text[:300])
        return []

    cves = []
    for file in file_list:
        if not file.get("name", "").endswith(".json"):
            continue

        cve_url = file.get("download_url")
        if not cve_url:
            continue

        r = requests.get(cve_url)
        if r.status_code != 200:
            continue

        try:
            data = r.json()
            meta = data.get("cveMetadata", {}) 
            cna = data.get("containers", {}).get("cna", {})

            cve_id = meta.get("cveId")

            published = (
                meta.get("datePublished")
                or meta.get("dateUpdated")
                or cna.get("datePublished")
                or cna.get("dateUpdated")
            )

            if not published:
                continue

            published_dt = isoparse(published)
            if published_dt < since_date:
                continue

            desc = ""
            for d in cna.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value")

            source = "CVE GitHub repo"
            cvss_data = cna.get("metrics", [])
            if cvss_data and "cvssV3_1" in cvss_data[0]:
                cvss = cvss_data[0]["cvssV3_1"]
                severity = cvss.get("baseSeverity")
                score = cvss.get("baseScore")
                vector = cvss.get("vectorString")
            else:
                nvd = fetch_from_nvd(cve_id)
                time.sleep(1)
                if nvd:
                    source = "NVD data"
                    severity, score, vector = nvd["severity"], nvd["score"], nvd["vector"]
                else:
                    source = "Unavailable"
                    severity = score = vector = None

            cves.append({
                "cve_id": cve_id,
                "published_date": published,
                "description": desc,
                "severity": severity,
                "score": score,
                "vector": vector,
                "source": source
            })

        except Exception as e:
            print(f"⚠️ Error processing {file.get('name', 'unknown')}: {e}")
            continue

        time.sleep(0.2)

    return cves

if __name__ == "__main__":
    data = pull_cves(days=7)
    if __name__ == "__main__":

        print(f"\n✅ Found {len(data)} CVEs\n")
        for cve in data:
            print(json.dumps(cve, indent=2))
