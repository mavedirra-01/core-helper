# Nmap Manual Boring (nmb)
The purpose of this tool is to parse nessus CSV files and run the manual checks assoisated with the PluginID.

## Current features:
- Reads a csv file, extracts the pluginID, name, ip and port
- The script will iderate through each ip to remove non-unique values
- If an IP is found to be down or the port is filtered, it will scan the next IP until there are no more in the list
- Checks the pluginID against the "plugin_config.json" file which contains a list of plugins and their respective manual check
- Exports the manual check output in a textfile within the "evidence" folder with the corresponding name for easy verification and taking a screenshot
- Merged with "deployer.py" to provide a complete solution to start/stop/monitor/analyze/export nessus scans. Once the report is exported, the user can provide the csv file and select the "manual" mode within deployer.py

## Running within Deployer.py
- The original script has been migrated within deployer.py
- To use; select the "manual" mode within deployer.py 

#### Example within Deployer.py
```python
# Default method
python deployer.py -m manual -d <DRONE-NAME> -f <PATH/TO/REQUIRED-CSV-FILE.CSV>

# Checking the list of supported plugins and add any missing ones with FIXME as the script
python deployer.py -m manual -f <REQUIRED-CSV-FILE.CSV> -q

# Checking external findings with pendrone
python deployer.py -m manual -d pendrone -f <PATH/TO/REQUIRED-CSV-FILE.CSV> --external

# Running manual checks locally (Onsite engagment) runs commands with subprocess rather than over SSH
python deployer.py -m manual -d localhost -f <PATH/TO/REQUIRED-CSV-FILE.CSV> --local
```

## Flags and other options
-f, --csv-file : path to nessus CSV file, this is a required argument.

-l, --local : Used if verifiying findings on your local machine (Onsite engagments, etc.) Will run the manual checks with subprocesses instead of over ssh.

-x, --external : Used to add the "external-" name to the evidence file names so the user can tell which is internal vs external. Only really used if connecting to pendrone. 

-q, --supported : checks the "plugin_config.json" file against the user provided csv file, it will then print a list of plugins that match both the json and the csv files, creating a list of plugins that will be checked. If a plugin does not exist in the file it will create a new entry in the following format:
```json
"ip_forwarding_enabled": {
            "ids": [
                "50686"
            ],
            "option": "FIXME"
        },
```
You can then replace the FIXME with the manual script used to verify the finding or leave it as a FIXME and the script will skip that finding. 

## Coming soon
- keywords to seperate new plugin imports (-q) and automate the process so no manual changing of "FIXME" is required
- fix the "deploy" mode issue 

## Known issues
- "deploy" mode will fail once reauthentication with nessus is required but the "monitor" mode works perfectly fine.
    - if deploy mode fails at the monitor scan phase just rerun the script with the "monitor" mode instead of deploy.