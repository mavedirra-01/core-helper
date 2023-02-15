# Nmap Manual Boring (nmb)
The purpose of this tool is to parse nessus CSV files and run the manual checks assoisated with the PluginID

## Example:
```python
# Context - If host is vulnerable to SWEET32 the script will run:
nmap --script ssl-enum-ciphers -p (port) (ip)

# The script will parse the nessus findings and iderate through each ip to remove non-unique values
# If an IP is found to be down or the port is filtered, it will scan the next IP until there are no more in the list
# 
```

To use the script, simply run it from the command line with the following arguments:

    file: The path to the Nessus scan results in CSV format.
    -m, --metasploit: (Optional) Run script with Metasploit checks enabled (much slower).
    -q, --query: (Optional) Print list of supported plugins based on the CSV file.

For example:
```python
python nessus_csv_parse_tool.py /path/to/nessus_scan_results.csv -m
```

## Nessus Pull
nessus_pull.sh will autheticate using user provided credentials and nessus policy. 

It will then pull the most recent usage of the policy and save it as a .csv file with all fields enabled.

### Example Usage:
```bash

bash nessus_pull.sh

# Script will prompt for username and password - you will also have to select between core or non-core for the policy
```