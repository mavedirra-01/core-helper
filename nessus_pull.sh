#!/bin/bash

function cleanup {
    # log out
    curl -s -k -X DELETE -H "X-Cookie: token=$token" "$NESSUS_URL/session"
    echo "Logged out"
}

# Trap errors and exit gracefully
trap cleanup EXIT INT TERM

# set your Nessus NESSUS_URLname
NESSUS_URL="https://localhost:8834"

# set the name of the policy to export
POLICY_FILE="Custom_Nessus_Policy-Pn_pAll_AllSSLTLS-Web-NoLocalCheck-NoDOS" ## FIXME
TARGETS_FILE="up.txt"

# set the name of the CSV file to download
csv_file="nessus_scan_results.csv"

# Get creds
read -p "Nessus Username: " username
read -sp "Nessus Password: " password
echo

# authenticate and get the session token
response=$(curl -s -k -H "Content-Type: application/json" -X POST -d "{\"username\":\"$username\",\"password\":\"$password\"}" "$NESSUS_URL/session")
token=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); print(data['token'] if 'token' in data else '')")

if [ -z "$token" ]; then
  echo "Error: authentication failed"
  exit 1
else
  echo "Authentication Successful"
fi

# get the policy ID for the specified policy name
response=$(curl -s -k -H "X-Cookie: token=$token" "$NESSUS_URL/policies")
policy_id=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); policies = [p['id'] for p in data['policies'] if p['name'] == '$POLICY_FILE']; print(policies[0] if policies else '')")

if [ -z "$policy_id" ]; then
  echo "Error: policy not found"
  exit 1
else
  echo "Found policy"
fi

scan_id=$(curl -s -k -X POST -H "X-Cookie: token=$token" "Content-Type: application/json" -d "{\"uuid\":\"\",\"settings\":{\"name\":\"Scan Name\",\"description\":\"Scan Description\",\"text_targets\":\"$(cat $TARGETS_FILE)\",\"policy_id\":\"$(curl -s -k -H "X-Cookie: token=$token" -X GET $NESSUS_URL/policies | jq -r ".policies[] | select(.name == \"$(basename $POLICY_FILE)\") | .id")\",\"scanner_id\":\"1\",\"text_targets_type\":\"default\"},\"uuid\":\"\"}" $NESSUS_URL/scans | jq -r '.scan.id')

# # get the most recent completed scan for the policy
# response=$(curl -s -k -H "X-Cookie: token=$token" "$NESSUS_URL/scans?policy_id=$policy_id")
# scan_id=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); scans = [s['id'] for s in data['scans'] if s['status'] == 'completed']; print(scans[0] if scans else '')")

if [ -z "$scan_id" ]; then
  echo "Error ... "
  exit 1
fi

# export the CSV file of the scan results
# response=$(curl -s -k -H "X-Cookie: token=$token" -X POST -d "format=csv&all_columns=1" "$NESSUS_URL/scans/$scan_id/export")
# file_id=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); print(data['file'] if 'file' in data else '')")
EXPORT_ID=$(curl -s -k -H "X-Cookie: token=$token" -X POST -d "{\"format\":\"csv\",\"history_id\":\"0\",\"scanner_id\":\"1\",\"scan_id\":\"$SCAN_ID\",\"chapter\":\"vuln_hosts_summary\",\"report\":\"vuln_scan\",\"description\":\"\",\"filters\":[],\"targets\":\"\",\"timezone\":\"UTC\"}" $NESSUS_URL/reports | jq -r '.file')
# if [ -z "$file_id" ]; then
#   echo "Error: export failed"
#   exit 1
# else
#   echo "Export successful - waiting to download"
# fi


SCAN_STATUS=""
while [ "$SCAN_STATUS" != "completed" ]
do
    sleep 10
    SCAN_STATUS=$(curl -s -k -H "X-Cookie: token=$token" -X GET $NESSUS_URL/scans/$SCAN_ID | jq -r '.info.status')
done

EXPORT_ID=$(curl -s -k -H "X-Cookie: token=$token" -X POST -d "{\"format\":\"csv\",\"history_id\":\"0\",\"scanner_id\":\"1\",\"scan_id\":\"$SCAN_ID\",\"chapter\":\"vuln_hosts_summary\",\"report\":\"vuln_scan\",\"description\":\"\",\"filters\":[],\"targets\":\"\",\"timezone\":\"UTC\"}" $NESSUS_URL/reports | jq -r '.file')
if [ -z "$EXPORT_ID" ]; then
  echo "Error: export failed"
  exit 1
else
  echo "Export successful - waiting to download"
fi
# download the exported CSV file
status="running"
while [ "$status" == "running" ]; do
  response=$(curl -s -k -H "X-Cookie: token=$token" "$NESSUS_URL/scans/$scan_id/export/$EXPORT_ID/status")
  status=$(echo "$response" | python -c "import sys, json; data = json.load(sys.stdin); print(data['status'] if 'status' in data else '')")
  sleep 5
done

# download the export
curl -s -k -o "$csv_file" -H "X-Cookie: token=$token" "$NESSUS_URL/reports/$EXPORT_ID/download"


echo "File saved to: " $PWD/$csv_file