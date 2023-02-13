#!/bin/bash
read -p "Nessus Username: " username
read -sp "Nessus Password: " password

# set your Nessus hostname
host="https://localhost:8834"

# set the name of the policy to export
policy_name="Custom_Nessus_Policy-Pn_pAll_AllSSLTLS-Web-NoLocalCheck-NoDOS" ## FIXME

# set the name of the CSV file to download
csv_file="nessus_scan_results.csv"

# authenticate and get the session token
response=$(curl -s -k -H "Content-Type: application/json" -X POST -d "{\"username\":\"$username\",\"password\":\"$password\"}" "$host/session")
token=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); print(data['token'] if 'token' in data else '')")

if [ -z "$token" ]; then
  echo "Error: authentication failed"
  exit 1
else
  echo "Authentication Successful"
fi

# get the policy ID for the specified policy name
response=$(curl -s -k -H "X-Cookie: token=$token" "$host/policies")
policy_id=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); policies = [p['id'] for p in data['policies'] if p['name'] == '$policy_name']; print(policies[0] if policies else '')")

if [ -z "$policy_id" ]; then
  echo "Error: policy not found"
  exit 1
else
  echo "Found policy"
fi

# get the most recent completed scan for the policy
response=$(curl -s -k -H "X-Cookie: token=$token" "$host/scans?policy_id=$policy_id")
scan_id=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); scans = [s['id'] for s in data['scans'] if s['status'] == 'completed']; print(scans[0] if scans else '')")

if [ -z "$scan_id" ]; then
  echo "Error: no completed scans found for policy"
  exit 1
fi

# export the CSV file of the scan results
response=$(curl -s -k -H "X-Cookie: token=$token" -X POST -d "format=csv&all_columns=1" "$host/scans/$scan_id/export")
file_id=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); print(data['file'] if 'file' in data else '')")

if [ -z "$file_id" ]; then
  echo "Error: export failed"
  exit 1
else
  echo "Export successful - waiting to download"
fi

# download the exported CSV file
status="running"
while [ "$status" == "running" ]; do
  response=$(curl -s -k -H "X-Cookie: token=$token" "$host/scans/$scan_id/export/$file_id/status")
  status=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); print(data['status'] if 'status' in data else '')")
  sleep 5
done

# download the export
curl -s -k -o "$csv_file" -H "X-Cookie: token=$token" "$host/scans/$scan_id/export/$file_id/download"

# log out
curl -s -k -X DELETE -H "X-Cookie: token=$token" "$host/session"

echo "File saved to: " $PWD/$csv_file