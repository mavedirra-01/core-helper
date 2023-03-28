# Nmap Manual Boring (nmb)
The purpose of this tool is to parse nessus CSV files and run the manual checks assoisated with the PluginID. This script has been incorperated into Joey's 'deployer.py' to create a complete project solution and limit the amount of interaction with the drone. 

This was created with CORE projects in-mind, I was tired of running the same nmap scans against almost identical networks over and over again. But it could be used for non-core as well if desired.

## Current features:
- Reads a csv file, extracts the pluginID, name, ip and port
- The script will iderate through each ip to remove non-unique values
- If an IP is found to be down or the port is filtered, it will scan the next IP until there are no more in the list
- Checks the nessus pluginID against the "plugin_config.json" file which contains a list of plugins and their respective manual checks
- Exports the manual check output in a textfile within the "evidence" folder with the corresponding name for easy verification and taking a screenshot
- Merged with "deployer.py" to provide a complete solution to start/stop/monitor/analyze/export nessus scans. Once the report is exported, the user can provide the csv file and select the "manual" mode within deployer.py

## Running within Deployer.py
- The original script has been migrated within Joey's 'deployer.py'
- To use; select the "manual" mode within nmb.py 

#### Example within Deployer.py
```python
# Default method
python3 nmb.py -m manual -d <DRONE-NAME> -f <PATH/TO/REQUIRED-CSV-FILE.CSV>

# Checking the list of supported plugins and add any missing ones with FIXME as the script
python3 nmb.py -m manual -f <REQUIRED-CSV-FILE.CSV> -q

# Checking external findings with pendrone
python3 nmb.py -m manual -d pendrone -f <PATH/TO/REQUIRED-CSV-FILE.CSV> --external

# Running manual checks locally (Onsite engagment) runs commands with subprocess rather than over SSH
python3 nmb.py -m manual -d localhost -f <PATH/TO/REQUIRED-CSV-FILE.CSV> --local
```

## Flags and other options
-f, --csv-file : path to nessus CSV file, this is a required argument.

-l, --local : Used if verifiying findings on your local Kali machine (Onsite engagments, etc.) Will run the manual checks with subprocesses instead of over ssh.

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

## plugin_config.json Guide

You can then replace the FIXME with the command used to verify the finding or leave it as a FIXME and the script will skip that finding. 
I have a few plugins added that I commonly see to get started with but, I suggest each user maintains their own version of "plugin_config.json" and update based off user requirements. 

To reduce the amount of repition, the plugin_config.json file has a few variables which are replaced during the script execution for example:
#### NMB code snip:
```python
self.serviceVersion = config.get('serviceVersion', '-sC -sV')
option = option.replace("{{serviceVersion}}", self.serviceVersion)
```
#### plugin_config.json snip:
```json
"splunk_version": {
            "ids": [
                "164076",
                "171550",
                "164329"
            ],
            "option": "{{serviceVersion}}"
        },
```
If the script detects the corresponding plugin ID it will then run `nmap -sC -sV -p (PORT) (IP)` (as the nmap, port and IP are filled in during the manual check) against the target, this makes it easier to add entries with the same nmap script instead of having to reenter the nmap command for each plugin.


## Eventually!
- Keywords to seperate new plugin imports (-q) and automate the process so no manual changing of "FIXME" is required
- Option to decom drone once done with project

## Known issues
- "deploy" mode will sometimes fail if reauthentication with nessus is required but the "monitor" mode can be used to reattach.
    - If deploy mode fails at the monitor scan phase just rerun the script with the "monitor" mode instead of deploy.