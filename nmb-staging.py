#!/usr/bin/env python3
# A nessus utility to deploy scans and analyses
# version: v1.0.1
import argparse
import ipaddress
import getpass
import json
import signal
import os
import paramiko
import pathlib
import colorlog
import re
import requests, urllib3
import sys
import csv
import logging
import time
#import zipfile
import subprocess
import xml.etree.ElementTree as XML
requests.packages.urllib3.disable_warnings()
# 

# import xml.etree.ElementTree as ET



## TO DO 
# add metasploit checks
# Improve json appending to also include nmap/custom command use a list of keywords to create catagories
# Option to decom drone once done with project
# add ability for 'deploy' mode to run the manual checks once the scan has exported

# Done
# made ctrl+c able to be used everywhere
# improve logging and error handling
# added -Pn nmap functionality and better confirmation
# added tag to files user has to manually check
# allow for local scans with subproccess 
# improve readme
# fix nessus html template issue - workaround is writing output to csv file then reading the csv to see if string matches
# no idea why this is the fix but it appears to be working as intended now
# add query functionality

log = logging.getLogger()
log.setLevel(logging.INFO)


# Define log formats with color
formatter = colorlog.ColoredFormatter(
    '%(log_color)s - %(message)s',
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'WARNING': 'yellow',
        'INFO': 'blue',
        'ERROR': 'red',
        'CRITICAL': 'bold_green'
    },
    secondary_log_colors={},
    style='%'
)

# Add file handler
file_handler = logging.FileHandler('nmb-logfile.log')
file_handler.setFormatter(formatter)
log.addHandler(file_handler)

# Add console handler with color
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
log.addHandler(console_handler)


def signal_handler(signal, frame):
    # Handle the Ctrl+C signal here
    log.warning("\nCtrl+C detected. Exiting...")
    sys.exit(0)



class Drone():
    ssh = None  # class attribute to store the SSH connection
    def __init__(self, hostname, username, password):
        if args.local:
            pass
        else:
            try:
                if not Drone.ssh:  # if no SSH connection exists, create one
                    Drone.ssh = paramiko.SSHClient()
                    Drone.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    Drone.ssh.connect(hostname=hostname, username=username, password=password)
                    Drone.ssh.exec_command('export TERM=xterm')

            except Exception as e:
                log.error(f"Can't connect to the drone, do you have the VPN connection enabled?\n{e}")
                exit()
    
    def download(self, remote_file):
        try:
            sftp = Drone.ssh.open_sftp()
            local_file = os.path.basename(remote_file)
            sftp.get(remote_file, local_file)
            sftp.close()
            return local_file

        except Exception as e:
            log.error(e)
            self.close()
            exit()

    def upload(self, local_file):
        remote_file = "/tmp/" + local_file
        try:
            # upload
            sftp = Drone.ssh.open_sftp()
            sftp.put(local_file, remote_file)
            sftp.close()
            return remote_file

        except Exception as e:
            log.error(e)
            self.close()
            exit()

    def execute(self, cmd):
        try:
            stdin, stdout, stderr = Drone.ssh.exec_command(cmd)
            err = stderr.read().decode()
            if err != "" and "TERM" not in err:
                log.error(err)
                raise Exception

            return stdout.read().decode()

        except:
            self.close()
            exit()
        
    def close(self):
        # don't close the SSH connection here
        pass


def get_supported_plugins():
    # TO DO Keywords to catogorize findings, this is the best method i can currently think of. 
    
    
    #
    plugin_ids_not_in_json = []
    all_plugin_ids = set()
    with open(args.file, 'r', encoding="utf8") as csv_file:
        csv_reader = csv.reader(csv_file)
        # Skip the header row
        next(csv_reader)
        # Create a dictionary to store the plugin names by ID
        plugin_names = {}
        # Loop through each row in the CSV file
        for row in csv_reader:
            # Get the plugin ID, name, and severity from the row
            plugin_id = row[0]
            plugin_name = row[7]
            severity = row[3]
            # Add the plugin name to the dictionary with the ID as the key
            plugin_names[plugin_id] = plugin_name
            # Check if the plugin ID is not in the JSON file and severity is at least low
            if plugin_id not in all_plugin_ids and severity in ['Low', 'Medium', 'High', 'Critical']:
                plugin_ids_not_in_json.append(plugin_id)

    # Open the JSON file
    with open('plugin_config.json', 'r+') as json_file:
        # Load the JSON data into a dictionary
        data = json.load(json_file)
        # Get the "ids" key from each plugin in the "plugins" dictionary
        plugin_id_sets = [set(plugin["ids"]) for plugin in data["plugins"].values()]
        # Flatten the list of sets into a single set of all plugin IDs
        all_plugin_ids = set().union(*plugin_id_sets)
        # Find the intersection between the plugin IDs from the CSV file and the plugin IDs in the JSON file
        matching_plugin_ids = all_plugin_ids.intersection(plugin_names.keys())
        plugin_ids_not_in_json = list(set(plugin_ids_not_in_json))
        # Add missing plugin IDs to the JSON file
        added_plugin_ids = []
        for plugin_id in plugin_ids_not_in_json:
            plugin_name = plugin_names[plugin_id].replace(' ', '_').lower()
            # Check if the plugin ID is already in the JSON file
            if plugin_id in all_plugin_ids:
                continue
            # Create a new dictionary for the missing plugin ID
            missing_plugin = {"ids": [plugin_id], "option": "FIXME"}
            # Add the missing plugin to the "plugins" dictionary in the JSON file
            if plugin_name in data["plugins"]:
                data["plugins"][plugin_name]["ids"].append(plugin_id)
            else:
                data["plugins"][plugin_name] = missing_plugin
                added_plugin_ids.append(plugin_id)
                log.info(f"Added plugin {plugin_name} with ID {plugin_id} to JSON file.")

        # Write the updated JSON data back to the file
        json_file.seek(0)
        json.dump(data, json_file, indent=4)

    # Print the matching plugin names
    log.info("Supported plugins:")
    for plugin_id in matching_plugin_ids:
        plugin_name = plugin_names[plugin_id]
        log.info(plugin_name)

    # Print the plugin IDs with at least low severity that were added to the JSON file
    if added_plugin_ids:
        log.info("Plugin IDs with at least low severity that were added to the JSON file:")
        for plugin_id in added_plugin_ids:
            plugin_name = plugin_names.get(plugin_id)
            if plugin_name:
                log.info(f"{plugin_id} - {plugin_name}")
    else:
        log.warning("No plugins were added to the file!")





class PluginConfig:
    def __init__(self):
        config_file = "plugin_config.json"
        nmap_base = "nmap -T4"
        with open(config_file) as f:
            config = json.load(f)
        self.serviceVersion = config.get('serviceVersion', f'{nmap_base} -sC -sV')
        self.osVersion = config.get('osVersion', 'sudo nmap -T4 -sC -sV -O {ip}')
        self.sslCert = config.get('sslCert', f'{nmap_base} --script ssl-cert')
        self.sshCiphers = config.get('sshCiphers', f'{nmap_base} --script ssh2-enum-algos')
        self.sslCiphers = config.get('sslCiphers', f'{nmap_base} --script ssl-enum-ciphers')
        self.redisInfo = config.get('redisInfo', 'redis-cli -h {ip} info && sleep 1 && echo -e "quit\n"')
        self.plugins = config.get('plugins', {})
        for plugin_name, plugin_config in self.plugins.items():
            if "option" in plugin_config:
                option = plugin_config["option"]
                option = option.replace("{{serviceVersion}}", self.serviceVersion)
                option = option.replace("{{osVersion}}", self.osVersion)
                option = option.replace("{{sslCert}}", self.sslCert)
                option = option.replace("{{sshCiphers}}", self.sshCiphers)
                option = option.replace("{{sslCiphers}}", self.sslCiphers)
                option = option.replace("{{redisInfo}}", self.redisInfo)
                plugin_config["option"] = option
    

class Lackey:
    def __init__(self, file_path, drone, username, password, mode):
        self.file_path = file_path
        self.drone = drone
        self.args = parser.parse_args()
        self.plugin_config = PluginConfig()
        self.username = username
        self.password = password
        self.make_evidence = "evidence"
        if not os.path.exists(self.make_evidence):
            os.makedirs(self.make_evidence)
        self.unknown_files = []


    
    def parse_user_csv(self, plugin_ids):
        if not plugin_ids:
            return None, [], []
        ips = []
        ports = []
        name = ''
        with open(self.file_path, 'r', encoding="utf8") as f:
            reader = csv.reader(f)
            for row in reader:
                if row[0] in plugin_ids:
                    name = row[7]
                    # Extract the IP from column 4 and the port from column 6
                    ip = row[4]
                    port = row[6]
                    # Append the IP and port to the respective lists
                    ips.append(ip)
                    ports.append(port)
        #ips = list(set(ips))
        return name, ips, ports

    def verify_scans(self, plugin_id, script, plugin_name=None):
        name, ips, ports = self.parse_user_csv(plugin_id)
        valid_scan_found = False
        try:
            for i, (ip, port) in enumerate(zip(ips, ports)):
                status = self.execute_checks(ip, port, name, script, plugin_name=plugin_name)
                if status == "down":
                    if i == len(ips) - 1:
                        log.error(f"Error: All IP addresses are down - {name}")
                        break
                if status == "skip":
                    log.warning(f"FIXME script detected, no check will be executed for: {name}")
                    valid_scan_found = True
                    break
                if status == "unknown":
                    log.warning(f"Host may be down, unable to verify - {name}")
                    # break
                if status == "up":
                    log.critical(f"Finding: {name} - Verified")
                    valid_scan_found = True
                    break
                    

        except Exception as e:
            log.error(f"Error: All IP addresses are down - {name}")
            log.error(f"Error message: {e}")
            exit()

    def manual_tests(self):
        for plugin_name in self.plugin_config.plugins.keys():
            self.execute_plugin(plugin_name)
        
                    
    def execute_plugin(self, plugin_name):
        plugin_id = self.plugin_config.plugins[plugin_name]["ids"]
        script = self.plugin_config.plugins[plugin_name]["option"]
        self.verify_scans(plugin_id, script, plugin_name=plugin_name)
    


    def execute_checks(self, ip, port, name, script, plugin_name=None):
        unknown_files = []
        try:
            output_file = os.path.join("evidence", f"{plugin_name}.txt")
            if self.args.external:
                log.warning("Evidence output files will be marked with the external flag")
                output_file = os.path.join("evidence-external", f"{plugin_name}.txt")

            if script == "FIXME":
                return "skip"

            if self.args.local:
                output = self.execute_local(ip, port, script, name)
            else:
                output = self.execute_ssh(ip, port, script, name)

            state_pattern = re.compile(r"\d+\/\w+\s+(open|closed|filtered)\s+\w+")
            match = state_pattern.search(output)
            if match:
                state = match.group(1)

            if output:
                    if state == "filtered":
                        output_file = os.path.join("evidence", f"UNCONFIRMED-{plugin_name}.txt")
                        write_output_to_file(output_file, output)
                        content = read_output_from_file(output_file)
                        self.unknown_files.append(output_file)
                        return "unknown"
                    if state == "closed":
                        return "down"
                    else:
                        write_output_to_file(output_file, output)
                        content = read_output_from_file(output_file)
                        if "Unknown" in plugin_name and output_file not in unknown_files:
                            unknown_files.append(output_file)
                    return "up"
            else:
                return "down"
        except Exception as e:
            log.error(f"Error executing plugin {name}: {e}")
            return "error"


    def execute_local(self, ip, port, script, name):
        log.info(f"Testing {ip}:{port} for {name}")
        try:
            if "{ip}" in script:
                script = script.format(ip=ip)
                output = subprocess.check_output([f'{script}'], shell=True, universal_newlines=True)
            else:
                output = subprocess.check_output([f'{script} -p {port} {ip}'], shell=True, universal_newlines=True)
            if not output or "Host is up" not in output:
                output = self.retry_nmap(ip, port, script)
            return output

        except Exception as e:
            log.error(f"Error message: {e}")

    def execute_ssh(self, ip, port, script, name):
        log.info(f"Testing {ip}:{port} for {name}")
        drone = Drone(self.drone, self.username, self.password)
        try:
            if "{ip}" in script:
                cmd = script.format(ip=ip)
            else:
                cmd = (f"{script} -p {port} {ip}")
            output = drone.execute(cmd)
            if "Host is up" not in output:
                output = self.retry_nmap(ip, port, script, drone)
            return output

        except Exception as e:
            log.error(f"Error message: {e}")

    def retry_nmap(self, ip, port, script, drone=None):
        for i in range(2):
            try:
                log.warning(f"Host {ip} is down. Retrying nmap with -Pn option. Retry: {i+1}")
                if drone is not None:
                    cmd = f"{script} -Pn -p {port} {ip}"
                    cmd = drone.execute(cmd)
                output = subprocess.check_output([f"{script} -Pn -p {port} {ip}"], shell=True, universal_newlines=True)
                return output

            except Exception as e:
                log.error(f"Error message: {e}")
        return ""


    def print_unknown_files(self):
        if self.unknown_files:
            unique_files = sorted(list(set(self.unknown_files)))
            log.error("The following files were unable to be verified and require manual review:")
            for file in unique_files:
                log.warning(f"{file}")
        else:
            log.critical("No files require manual review.")




def write_output_to_file(output_file, output):
    with open(output_file, "w") as f:
        f.write(output)


def read_output_from_file(output_file):
    with open(output_file, "r") as f:
        return f.read()

        

class Nessus:
    def __init__(self, drone, username, password, mode, project_name, policy_file, targets_file, scan_file, exclude_file, output_folder):
        self.args = parser.parse_args()
        self.output_folder = output_folder
        self.drone = drone
        self.username = username
        self.password = password
        # if scan_file:
        #     self.analyze_results(scan_file)
        #     exit()

        self.url = "https://" + drone + ":8834"
        self.project_name = project_name
        self.auth = {
            "username": username,
            "password": password
        }
        # if not auth:
        if self.args.mode == "manual": 
            pass
        else:
            self.get_auth()
           
        
        if policy_file: 
            self.policy_file = policy_file.read()
            self.policy_file_name = policy_file.name

            # Parse the XML policy file
            tree = XML.parse(self.policy_file_name)
            root = tree.getroot()
            name_element = root.find('./Policy/policyName')
            self.policy_name = name_element.text

        if targets_file:
            self.targets_file = targets_file.read()

        if exclude_file:
            self.exclude_file = exclude_file.readlines()

        if scan_file:
            self.scan_file = scan_file

    # Auth handlers
    def get_auth(self, verbose=True):
        log.info("Retrieving API tokens")
        try:
            self.token_keys = self.get_tokens()
            self.token_auth = {
                "X-Cookie": f"token={self.token_keys['cookie_token']}",
                "X-API-Token": self.token_keys["api_token"]
            }

            self.api_keys = self.get_api_keys()
            self.api_auth = {
                "X-ApiKeys": "accessKey="+self.api_keys["accessKey"]+"; secretKey="+self.api_keys["secretKey"]
            }

            if verbose:
                log.info("API tokens retrieved successfully.")

        except Exception as e:
            if verbose:
                log.error(f"Failed to retrieve API tokens: {e.args[0]}")
            exit()

    def get_tokens(self):
        # get X-Cookie token
        tokens = {}
        response = requests.post(self.url + "/session", data=self.auth, verify=False)
        tokens["cookie_token"] = json.loads(response.text)["token"]

        # cheat api restrictions and get X-Api-Token:
        response = requests.get(self.url + "/nessus6.js", verify=False)
        tokens["api_token"] = re.search(r'{key:"getApiToken",value:function\(\){return"(.*)"}},{key', response.text)[1]
        tokens["scan_uuid"] = re.search(r'CUSTOM_SCAN_TEMPLATE="(.*)",this\.CUSTOM_AGENT_TEMPLATE', response.text)[1] # for creating scans later, so we don't need to make this slow request again

        return tokens

    def get_api_keys(self):
        # get accessKey and secretKey to interact with api		
        response = requests.put(self.url + "/session/keys", headers=self.token_auth, verify=False)
        keys = {
            "accessKey": json.loads(response.text)["accessKey"],
            "secretKey": json.loads(response.text)["secretKey"]
        }
        return keys

    # Engine
    def exclude_targets(self):
        log.info("Adding targets to reject list")
        try:
            # Connect to the SSH server
            log.info("Connecting to the ssh server")
            drone = Drone(self.drone, self.username, self.password)
            
            log.info("Getting drone device name")
            cmd = "ip a | awk '/^[0-9]+:/{print $2}' | sed 's/://' | grep -v lo"
            drone_device = drone.execute(cmd).split("\n")[0]
            
            # Fetch drone IP
            log.info("Getting drone IP")
            cmd = f'ip a s {drone_device} | grep -o "inet .* brd" | grep -o "[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*"'
            drone_ip = drone.execute(cmd).split("\n")[0]

            # Add drone IP to nessus rules
            log.info(f"Adding drone IP {drone_ip} to reject list")
            cmd = f"echo 'reject {drone_ip}' | sudo tee -a /opt/nessus/etc/nessus/nessusd.rules"
            drone.execute(cmd)

            # Add targets provided from -e to nessus rules
            try:
                log.info(f"Adding exclude targets from to reject list")
                for exclude_target in self.exclude_file:
                    exclude_target = exclude_target.rstrip()
                    cmd = f"echo 'reject {exclude_target}' | sudo tee -a /opt/nessus/etc/nessus/nessusd.rules"
                    drone.execute(cmd)
            except:
                pass

            drone.close()
            log.info(f"Exclusion targets added to reject list on /opt/nessus/etc/nessus/nessusd.rules")
            log.info("Targets added to reject list successfully.")

        except Exception as e:
            log.error(f"Failed to add targets to reject list: {e.args[0]}")
            exit()


    def update_settings(self):
        log.info("Updating settings")
            # bulletproof standard settings as per policy
        settings = {
            "scan_vulnerability_groups": "no",
            "scan_vulnerability_groups_mixed": "no",
            "port_range": "all",
            "severity_basis": "cvss_v3"
        }

        try:
            # nessus requires settings to be updated one by one
            for name, value in settings.items():
                data = {
                    "setting.0.action": "edit",
                    "setting.0.name": name,
                    "setting.0.value": value
                }
                response = requests.put(self.url + "/settings/advanced", headers=self.api_auth, data=data, verify=False)
                if response.status_code != 200:
                    raise Exception("Could not update settings.")

        except Exception as e:
            log.error(str(e))
            exit()

    def import_policies(self):
        log.info("Importing policies")
        try:
            # check if policy file already exists:
            policy_name = self.policy_file_name.rsplit(".", 1)[0]
            if "\\" in policy_name:
                policy_name = policy_name.split("\\")[-1]
            elif "/" in policy_name:
                policy_name = policy_name.split("/")[-1]
            response = requests.get(self.url + "/policies", headers=self.api_auth, verify=False)
            if policy_name in response.text:
                log.error("Policy file already exists, skipping import")
                return

            # first, upload the policies file to nessus
            file = {
                "Filedata": (self.policy_file_name, self.policy_file)
            }
            response = requests.post(self.url + "/file/upload", headers=self.api_auth, files=file, verify=False)

            # then, retrieve the file and post it to policies
            fileuploaded = json.loads(response.text)["fileuploaded"]
            data = {
                "file": fileuploaded
            }
            response = requests.post(self.url + "/policies/import", headers=self.api_auth, data=data, verify=False)
            if response.status_code == 200:
                log.info("Imported policies")

            else:
                raise Exception("Could not import policies.")

        except Exception as e:
            log.error(e)
            exit()


    def create_scan(self, launch):
        log.info("Creating new scan")
        try:
            # check if scan name already exists first:
            if self.get_scan_info() is not None:
                log.error("Scan name already exists")
                return

            project_name = self.project_name

            # get policy id
            policies = json.loads(requests.get(self.url + "/policies", headers=self.api_auth, verify=False).text)["policies"]
            policy = next((p for p in policies if p["name"] == self.policy_name), None)
            if policy is None:
                raise Exception(f"No policy found with name {self.policy_name}")
            policy_id = policy["id"]
            file = {
                    "Filedata": ("targets.txt", self.targets_file)
                }
            response = requests.post(self.url + "/file/upload", headers=self.api_auth, files=file, verify=False)
            if response.status_code != 200:
                raise Exception("Failed to upload targets file")

            # send "create scan" request
            data = {
                "uuid": self.token_keys["scan_uuid"],
                "settings": {
                    "name": project_name,
                    "policy_id": policy_id,
                    "launch_now": launch,
                    "enabled": False,
                    "scanner_id": "1",
                    "folder_id": 3,
                    "file_targets": "targets.txt",
                    "description": "No host Discovery\nAll TCP port\nAll Service Discovery\nDefault passwords being tested\nGeneric Web Test\nNo compliance or local Check\nNo DOS plugins\n",
                }
            }
            response = requests.post(self.url + "/scans", headers=self.token_auth, json=data, verify=False)
            if response.status_code != 200:
                raise Exception("Failed to create scan")
            else:
                log.info("Scan created")

        except Exception as e:
            log.error(str(e))
            exit()


    def get_scan_info(self):
        try:
            response = requests.get(self.url + "/scans?folder_id=3", headers=self.token_auth, verify=False)
            scans = json.loads(response.text)["scans"]
            
            if scans == None:
                return

            for scan in scans:
                if scan["name"] == self.project_name:
                    return scan
        
        except Exception as e:
            log.error("Could not get scan info")
            exit()

    def scan_action(self, action):
        log.info(f"Sending {action} request to \"{self.project_name}\"")
        try:
            scan_id = self.get_scan_info()["id"]
            response = requests.post(self.url + f"/scans/{scan_id}/{action}", headers=self.token_auth, verify=False)
            if response.status_code == 200:
                log.info(f"Scan {action} completed successfully")
            else:
                raise Exception("Could not complete scan action")

        except Exception as e:
            log.error(e.args[0])
            exit()

    def monitor_scan(self):
        status = self.get_scan_info()["status"]
        time_elapsed = 0
        log.info(f"Scan status")
        while status == "running":
            log.info(status)
            status = self.get_scan_info()["status"]           
            time.sleep(60)
            time_elapsed += 1
            if time_elapsed == 5:
                with log.info("Reauthenticating"):
                    self.get_auth(verbose=False)
                time_elapsed = 0

            log.info(status)


    def export_scan(self):
        try:
            scan_id = self.get_scan_info()["id"]
            # nessus_version = requests.get(self.url + "/server/properties", headers=self.token_auth, verify=False)
            # version_info = nessus_version.json()
            # ui_version = version_info.get("nessus_ui_version")
            # if re.match(r"^8(\.|$)", ui_version):
            #     template_id = "Vulnerabilites By Plugin" # Detailed vulns by plugin 
            #     # 214
            # else:
            
            ## This is the best way I could think of going about this, sooooo many issues with the template name 
            response = requests.get(self.url + f"/reports/custom/templates", headers=self.token_auth, verify=False)
            templates = json.loads(response.text)
            with open("tmp.csv", "w") as f:
                for template in templates:
                    template_id = template['id']
                    output = f"{template_id},{template['name']}"
                    f.write(output)
                    f.write('\n')

            # Open the file for reading
            with open('tmp.csv', 'r') as f:
                csv_reader = csv.reader(f)
                # Read the file line by line
                for row in csv_reader:
                    if row[1] == 'Detailed Vulnerabilities By Plugin':
                        template_id = row[0]

            os.remove('tmp.csv')
                
                
                

            # format handlers
            formats = {
                "nessus": {
                    "format": "nessus"
                },
                "html": {
                    "format": "html",
                    "template_id": template_id,
                    "csvColumns": {},
                    "formattingOptions": {},
                    "extraFilters": {
                        "host_ids": [],
                        "plugin_ids": []
                    }
                }, 
                "csv": {
                    "format": "csv",
                    "template_id": "",
                    "reportContents": {
                        "csvColumns": {
                            "id": True,
                            "cve": True,
                            "cvss": True,
                            "risk": True,
                            "hostname": True,
                            "protocol": True,
                            "port": True,
                            "plugin_name": True,
                            "synopsis": True,
                            "description": True,
                            "solution": True,
                            "see_also": True,
                            "plugin_output": True,
                            "stig_severity": True,
                            "cvss3_base_score": True,
                            "cvss_temporal_score": True,
                            "cvss3_temporal_score": True,
                            "risk_factor": True,
                            "references": True,
                            "plugin_information": True,
                            "exploitable_with": True
                        }
                    },
                    "extraFilters": {
                        "host_ids": [],
                        "plugin_ids": []
                    }
                }
            }

            for k,v in formats.items():
            
                log.info(f"Exporting {k} file")
                # get scan token
                data = v
                response = requests.post(self.url + "/scans/" + str(scan_id) + "/export", headers=self.token_auth, json=data, verify=False)
                if response.status_code != 200:
                    raise Exception(f"Exporting {k} file failed with status code {response.status_code}")
                scan_token = json.loads(response.text)["token"]

                # download file
                while True:
                    response = requests.get(self.url + "/tokens/" + scan_token + "/download", headers=self.token_auth, verify=False)
                    if "not ready" in response.text:
                        time.sleep(5)

                    elif response.status_code == 200:
                        file_path = os.path.join(self.output_folder, self.project_name + f".{k}")
                        open(file_path, "wb").write(response.content)
                        log.info(f"Done. Scan file exported to \"{file_path}\"")
                        break

                    else:
                        raise Exception(f"Downloading {k} file failed with status code {response.status_code}")

            return self.project_name + ".nessus"

        except Exception as e:
            log.error(e.args[0])
            exit()
                

    # def initialize(self):
    #     if self.mode == 'manual':
    #         execute = Lackey(
    #             drone=self.drone,
    #             username=self.username,
    #             password=self.password,
    #             file_path=self.file_path,
    #             mode=self.mode
    #         )

    # Mode handlers
    def deploy(self):
        self.exclude_targets()
        self.update_settings()
        self.import_policies()
        self.create_scan(True)
        self.monitor_scan()
        file_path = self.export_scan()
        # self.analyze_results(scan_file)

    def trigger(self):
        self.exclude_targets()
        self.update_settings()
        self.import_policies()
        self.create_scan(False)

    def launch(self):
        self.scan_action("launch")
        self.monitor_scan()
        scan_file = self.export_scan()
        # self.analyze_results(scan_file)

    def pause(self):
        self.scan_action("pause")

    def resume(self):
        self.scan_action("resume")
        self.monitor_scan()
        scan_file = self.export_scan()
        # self.analyze_results(scan_file)

    def export(self):
        self.export_scan()
        # scan_file = self.export_scan()
        # self.analyze_results(scan_file)




def get_creds():
    username = input("username: ").rstrip()
    password = getpass.getpass("password: ")
    print("\n")
    return username, password


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(
        usage = "deployer.py [OPTIONS]",
        formatter_class = argparse.RawTextHelpFormatter,
        epilog = "Examples:\n" \
                 "deployer.py -d storm -c myclient -m deploy -p mypolicy.nessus -t targets.txt\n" \
                 "deployer.py -d localhost -c myclient -m trigger -p custompolicy.nessus -t targets.txt\n" \
                 "deployer.py -d 10.88.88.101 -c myclient -m pause\n" \
                 "deployer.py -d strange -c myclient -m resume -o /home/drone/Downloads\n" \
                 "deployer.py -d ironman -m manual -f nessus_file.csv\n" \
                 "deployer.py -d localhost -m manual -f nessus_file.csv --local\n" \
                 "deployer.py -d pendrone -m manual -f nessus_file.csv --external"
    )
    parser.add_argument("-m", "--mode", required=True, choices=["deploy","trigger","launch","pause","resume","monitor","export","manual"], help="" \
        "choose mode to run Nessus:\n" \
        "deploy: update settings, upload policy file, upload targets file, launch scan, monitor scan, export results, analyze results\n" \
        "trigger: update settings, upload policy file, upload targets files\n" \
        "launch: launch scan, export results, analyze results\n" \
        "pause: pause scan\n" \
        "resume: resume scan, export results, analyze results\n" \
        "monitor: monitor scan\n" \
        "export: export scan results, analyze results\n" \
        "manual: perform nmap scans and manual finding verification"
    )
    parser.add_argument("-d", "--drone", required=False, help="drone name or IP")
    parser.add_argument("-c", "--client-name", dest="client", required=False, help="client name or project name (used to name the scan and output files)")
    parser.add_argument("-p", "--policy-file", dest="policy", required=False, help="nessus policy file", type=argparse.FileType('rb'))
    parser.add_argument("-t", "--targets-file", dest="targets", required=False, help="targets file", type=argparse.FileType('r'))
    parser.add_argument("-e", "--exclude-file", dest="exclude_file", required=False, help="exclude targets file", type=argparse.FileType('r'))
    parser.add_argument("-o", "--output-path", dest="output", required=False, help="output path to store exported files", type=pathlib.Path, default=os.getcwd())
    parser.add_argument("-s", "--scan-file", dest="scan_file", required=False, help="scan results file")
    parser.add_argument("-f ", "--csv-file", dest="file", required=False, help="Path/to/nessus_scan_results.csv")
    parser.add_argument("-x", "--external", dest="external", required=False, action="store_const", const=True, help="used if drone is 'pendrone'")
    parser.add_argument("-q", "--supported", dest="supported", required=False, action="store_const", const=True, help="prints a list of supported plugins based off user provided csv")
    parser.add_argument("-l", "--local", dest="local", required=False, action="store_const", const=True, help="run manual checks on your local machine instead of over ssh")
    args = parser.parse_args()

    # Check args requirements for each mode
    if args.mode == "analyze":
        if not args.scan_file:
            log.error("You must provide a scan file (-s)")
            exit()
        username, password = get_creds()
        
        
    if args.mode == "manual":
        if args.supported and os.path.getsize(args.file) != 0:
            get_supported_plugins()
            exit()
            
        if args.file:
            if os.path.getsize(args.file) == 0:
                log.error("CSV file is empty!")
                exit()
            if not args.file.endswith(".csv"):
                log.error("The file must be of type .csv")
                exit()
            if not os.path.isfile(args.file):
                log.error("File does not exist")
            else:
                pass

        if not args.file:
            log.error("You must provide a csv file (-f)")
            exit()

        if args.supported and not args.file:
            log.error("You must provide a csv file (-f)")
            exit()
        

        elif os.path.isfile(args.file) and args.file.endswith(".csv") and args.local:
            log.info(f"File exists: {args.file}")
            log.info("Running script with local checks enabled")
            username = None
            password = None
            drone = None
            
        elif os.path.isfile(args.file) and args.file.endswith(".csv") and not args.supported:
            log.info(f"File exists: {args.file}")
            username, password = get_creds()
        else:
            log.error(f"File does not exist - {args.file}")
            exit()
        
        
        
    else:
        if args.drone is None or args.client is None:
            log.error("You must provide the drone name (-d) and the client name (-c)")
            exit()
        if args.mode == "deploy" or args.mode == "trigger":
            if not args.policy or not args.targets:
                log.error("You must provide a policy file (-p) and a targets file (-t) for this mode")
                exit()
        # Check drone name/ip and create url (for nessus) 
        if "http" in args.drone:
            log.error("You must provide only the drone name/dns, or IP. Do not use http link")
            exit()
        username, password = get_creds()

    # execute checks
    if args.mode == 'manual':
        execute = Lackey(
            drone=args.drone,
            username=username,
            password=password,
            file_path=args.file,
            mode=args.mode
        )
    # # Initialize nessus
    else:
        nessus = Nessus(
            drone=args.drone,
            username=username,
            password=password,
            mode=args.mode,
            project_name=args.client,
            policy_file=args.policy,
            targets_file=args.targets,
            scan_file=args.scan_file,
            exclude_file=args.exclude_file,
            output_folder=args.output,
        )
    
    
    # Mode handler
    if args.mode == "deploy":
        log.info("Deploying nessus")
        nessus.deploy()

    elif args.mode == "trigger":
        nessus.trigger()
        
    elif args.mode == "launch":
        log.info("Launching scan")
        nessus.launch()

    elif args.mode == "pause":
        log.info("Pausing scan")
        nessus.pause()

    elif args.mode == "resume":
        log.info("Resuming scan")
        nessus.resume()

    elif args.mode == "monitor":
        log.info("Monitoring scan")
        nessus.monitor_scan()

    elif args.mode == "export":
        log.info("Exporting scan results")
        nessus.export()

    elif args.mode == "manual":
        log.info(f"Performing manual testing - All scan output will be saved in the evidence directoy")
        execute.manual_tests()		
        log.info("Script finished running")
        execute.print_unknown_files()