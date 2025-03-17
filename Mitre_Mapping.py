import json
import os
import requests
import time
from attackcti import attack_client
from github import Github
from github.GithubException import GithubException

# Initialize MITRE ATT&CK client
client = attack_client()

# Retrieve API keys from environment variables (matching YAML)
NVD_API_KEY = os.getenv("API_TOKEN")  # Changed from "NVD_API_KEY" to "API_TOKEN"
GITHUB_TOKEN = os.getenv("MY_PAT_TOKEN")  # Changed from "GITHUB_TOKEN" to "MY_PAT_TOKEN"
REPO_NAME = "alhelmyjhr98/mitre-attack-mapping-automation"

# Ensure API keys are set
if not NVD_API_KEY:
    raise ValueError("❌ Missing API_TOKEN! Set it as an environment variable.")
if not GITHUB_TOKEN:
    raise ValueError("❌ Missing MY_PAT_TOKEN! Set it as an environment variable.")

# Fetch latest vulnerabilities from NVD
def fetch_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0"
    headers = {"apiKey": NVD_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching CVEs: {e}")
        return None

# Fetch MITRE ATT&CK techniques
def fetch_attack_techniques():
    techniques = client.get_techniques()
    technique_mapping = {tech["name"]: tech["external_references"][0]["external_id"] for tech in techniques}
    return technique_mapping

# Map CVEs to MITRE ATT&CK Techniques
def map_cves_to_mitre(cve_data, attack_techniques):
    mappings = []
    if not cve_data or "vulnerabilities" not in cve_data:
        print("⚠️ No CVE data available.")
        return mappings

    for item in cve_data["vulnerabilities"]:
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]

        for keyword, attack_id in attack_techniques.items():
            if keyword.lower() in description.lower():
                mappings.append({"CVE": cve_id, "Technique": f"{attack_id} - {keyword}"})
                break  # Stop at the first match

    return mappings

# Save the mappings to a JSON file
def save_to_json(data, filename="cve_mitre_mapping.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"✅ Mapping saved to {filename}")

# Push the file to GitHub
def push_to_github(repo_name, filename):
    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(repo_name)
        
        try:
            contents = repo.get_contents(filename)
            repo.update_file(contents.path, "Updated CVE mappings", open(filename, "r").read(), contents.sha)
            print("🚀 Updated file on GitHub!")
        except GithubException as e:
            if e.status == 404:
                repo.create_file(filename, "Initial CVE mappings", open(filename, "r").read())
                print("✅ Created new file on GitHub!")
            else:
                print(f"❌ GitHub Error: {e}")

    except Exception as e:
        print(f"❌ Failed to push to GitHub: {e}")

# Run the script
if __name__ == "__main__":
    cve_data = fetch_cves()
    attack_techniques = fetch_attack_techniques()
    mapped_cves = map_cves_to_mitre(cve_data, attack_techniques)
    save_to_json(mapped_cves)

    push_to_github(REPO_NAME, "cve_mitre_mapping.json")
