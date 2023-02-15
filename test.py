import requests

url = "https://localhost:8834"

# Set Nessus credentials
username = "bulletproof"
password = "BulletH@x"
policy_id = "Custom_Nessus_Policy-Pn_pAll_AllSSLTLS-Web-NoLocalCheck-NoDOS"
targets_file = "up.txt"

try:
    # Authenticate with Nessus API and get session token
    response = requests.post(url + "/session", json={"username": username, "password": password})
    response.raise_for_status()
    session_token = response.headers["x-cookie"]

    # Start a scan with the specified policy and targets
    response = requests.post(url + "/scans", json={"uuid": policy_id, "settings": {"name": "Scan Name", "text_targets": open(targets_file).read()}})
    response.raise_for_status()
    scan_id = response.json()["scan"]["id"]

    # Wait for the scan to finish
    while True:
        response = requests.get(url + f"/scans/{scan_id}")
        response.raise_for_status()
        if response.json()["info"]["status"] == "completed":
            break

    # Export the scan results in CSV format
    response = requests.get(url + f"/scans/{scan_id}/export", headers={"X-Cookie": session_token}, params={"format": "csv"})
    response.raise_for_status()
    with open("scan_results.csv", "wb") as f:
        f.write(response.content)

    print("Scan completed successfully!")
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")