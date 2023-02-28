#!/usr/bin/env python3
# Deployer - A nessus utility to deploy scans and analyses
# author: Joey Melo, Connor Fancy
# version: v1.0.0
import argparse
import ipaddress
import getpass
import json
import signal
# import msvcrt
import os
import paramiko
import pathlib
import re
import requests, urllib3
import sys
import csv
import io
import logging as log
import time
import zipfile
import subprocess
import xml.etree.ElementTree as XML
requests.packages.urllib3.disable_warnings()
log.basicConfig(level=log.INFO)
# import xml.etree.ElementTree as ET
## TO DO 
# nessus reathentication
# improve readme 
# use scan file instead of file
# add metasploit checks
# add query functionality
# improve logging and colours
# fix nessus html template issue

# Done
# allow for local scans with subproccess 

class Colours:
    def __init__(self):
        self.green = "\033[32m[+]\033[0m"
        self.red = "\033[91m[-]\033[0m"
        self.bold = '\033[1m'
        self.blue = '\033[94m[-->]\033[0m'
        self.yellow = '\033[93m[!]\033[0m'
        self.rc = '\033[0m'

class LogContext:
    def __init__(self, message):
        self.message = message

    def __enter__(self):
        log.info(self.message)
        return self

    def failure(self, message):
        log.error(message)

    def status(self, message):
        log.info(f"[STATUS] {message}")

    def success(self, message=None):
        log.info(f"[SUCCESS] {message}" if message else "[SUCCESS]")

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:
            self.failure(exc_value)
        else:
            self.success()    

class Drone():
    ssh = None  # class attribute to store the SSH connection

    def __init__(self, hostname, username, password):
        try:
            if not Drone.ssh:  # if no SSH connection exists, create one
                Drone.ssh = paramiko.SSHClient()
                Drone.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                Drone.ssh.connect(hostname=hostname, username=username, password=password)
                Drone.ssh.exec_command('export TERM=xterm')

        except Exception as e:
            log.error(e.args[0])
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



class PluginConfig:
    def __init__(self):
        config_file = "plugin_config.json"
        with open(config_file) as f:
            config = json.load(f)
        
        self.serviceVersion = config.get('serviceVersion', '-sC -sV')
        self.osVersion = config.get('osVersion', 'sudo nmap -sC -sV -O')
        self.sslCert = config.get('sslCert', '--script ssl-cert')
        self.sshCiphers = config.get('sshCiphers', '--script ssh2-enum-algos')
        self.sslCiphers = config.get('sslCiphers', '--script ssl-enum-ciphers')
        self.redisInfo = config.get('redisInfo', 'redis-cli -h {} info && sleep 1 && echo -e "quit\n"')
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
        signal.signal(signal.SIGINT, self.signal_handler)
        self.file_path = file_path
        self.drone = drone
        self.args = parser.parse_args()
        self.plugin_config = PluginConfig()
        self.username = username
        self.password = password
        self.make_evidence = "evidence"
        if not os.path.exists(self.make_evidence):
            os.makedirs(self.make_evidence)
        

    def signal_handler(self, signal, frame):
        # Handle the Ctrl+C signal here
        print("Ctrl+C detected. Exiting...")
        sys.exit(0)
    
    def parse_user_csv(self, plugin_ids):
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

    def verify_scans(self, plugin_id, script, execute_custom=False, execute_nmap=False, plugin_name=None):
        c = Colours()
        name, ips, ports = self.parse_user_csv(plugin_id)
        valid_scan_found = False
        with LogContext("Verifying IP addresses") as p:
            try:
                for i in range(len(ips)):
                    if valid_scan_found:
                        break
                    ip = ips[i]
                    port = ports[i]
                    status = self.execute_checks(ip, port, name, script, execute_custom, execute_nmap, plugin_name=plugin_name)
                    if status == "down":
                        if i == len(ips) - 1:
                            print(c.red,"Error: All IP addresses are down -", name)
                            break
                    elif status == "unknown":
                        print(c.yellow,"Host may be down, unable to verify -", name)
                        # valid_scan_found = True
                        # break
                    else:
                        print(c.green,"Finding:", name, f"{c.bold}Verified{c.rc}")
                        # Set the flag variable to indicate that a valid scan has been found
                        valid_scan_found = True
                        break
            except Exception as e:
                print(e)
                exit()
            
        
                    
    def execute_plugin(self, plugin_name):
        plugin_id = self.plugin_config.plugins[plugin_name]["ids"]
        script = self.plugin_config.plugins[plugin_name]["option"]
        if plugin_name.startswith("custom"):
            self.verify_scans(plugin_id, script, execute_custom=True, plugin_name=plugin_name)
        elif self.args.local:
            if plugin_name.startswith("custom"):
                self.verify_scans(plugin_id, script, execute_custom=True, plugin_name=plugin_name)
            else:
                self.verify_scans(plugin_id, script, execute_nmap=True, plugin_name=plugin_name)
        else:
            self.verify_scans(plugin_id, script, execute_nmap=True, plugin_name=plugin_name)

    
    def zip_evidence(self):
        directory = self.make_evidence
        zip_name = "evidence.zip"
        zip_file = zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED)
        print("Zipping evidence ...")
        for file_name in os.listdir(directory):
        # Ignore subdirectories
            if not os.path.isdir(file_name):
            # Add the file to the zip file
                zip_file.write(os.path.join(directory, file_name), file_name)
        zip_file.close() 
    
            
            
    def execute_checks(self, ip, port, name, script, execute_custom=False, execute_nmap=False, plugin_name=None):
        with LogContext("Analyzing results") as p:
            nmap = "nmap -T4"
            c = Colours()
            try:
                
                output_file = "evidence/{}.txt".format(plugin_name)
                if self.args.external:
                    print(c.yellow,"Evidence output files will be marked with the external flag")
                    output_file = "evidence/external-{}.txt".format(plugin_name)
                print(c.blue,f"Testing {ip}:{port} for {name}")

                if self.args.local:
                    if execute_custom and self.args.local:
                        output = subprocess.run([f'{script} {ip} '], capture_output=True, shell=True, check=True)
                    elif execute_nmap and self.args.local:
                        output = subprocess.run([f"{nmap} {script} -p {port} {ip} "], capture_output=True, shell=True, check=True)
                    with open(output_file, "w") as f:
                        f.write(output.stdout.decode())
                    with open(output_file, "r") as f:
                        content = f.read()
                

                if not self.args.local:
                    drone = Drone(self.drone, self.username, self.password)
                    if execute_custom:
                        cmd = f'{script} {ip} '
                        output = drone.execute(cmd)
                        with open(output_file, "w") as f:
                            f.write(output)
                        with open(output_file, "r") as f:
                            content = f.read()
                    elif execute_nmap:
                        cmd = f'{nmap} {script} -p {port} {ip} '
                        output = drone.execute(cmd)
                        with open(output_file, "w") as f:
                            f.write(output)
                        with open(output_file, "r") as f:
                            content = f.read()
                    if plugin_name == "redis_info":
                        cmd = f"{script.format(ip)}"
                        output = drone.execute(cmd)
                        with open(output_file, "w") as f:
                            f.write(output)
                        with open(output_file, "r") as f:
                            content = f.read()

                
                
                
                if "Host seems down" in content or "0 hosts up" in content or "closed" in content:
                    return "down"
                elif "filtered" in content or "ERROR" in content:
                    return "unknown"
                if "SNMP request timeout" in content or "request timed out" in content:
                    return "down"
                else:
                    return "up"

            except Exception as e:
                p.failure(e)
        # self.zip_evidence()
        # drone.close()
        
    def manual_tests(self):
        for plugin_name in self.plugin_config.plugins.keys():
            self.execute_plugin(plugin_name)
        


class Analyzer:
    def __init__(self, scan_file, output_folder):
        self.tree = XML.parse(scan_file)
        self.root = self.tree.getroot()
        self.output_folder = output_folder

    def vulnerabilities(self):
        findings = {}
        hosts = self.root.findall(".//ReportHost")

        for host in hosts:
            ip = host.get("name")
            vulnerabilities = host.findall(".//ReportItem")

            for vulnerability in vulnerabilities:
                try:
                    # ignore info findings
                    if vulnerability.get("severity") == "0": continue

                    # fetch data
                    name = vulnerability.find(".//plugin_name").text
                    exploitable = vulnerability.find(".//exploit_available").text
                    plugin_id = vulnerability.get("pluginID")
                    port = vulnerability.get("port")
                    cves = vulnerability.findall(".//cve")
                    cve_list = []
                    for cve in cves:
                        cve_list.append(cve.text)

                    # only care about findings with publicly available exploits
                    if exploitable == "true":
                        if plugin_id in findings:
                            findings[plugin_id]["hosts"].append(ip + ":" + port)

                        else:
                            findings[plugin_id] = {
                                "name": name,
                                "cves": cve_list,
                                "hosts": [ip + ":" + port]
                            }

                except Exception as e:
                    continue

        file_path = os.path.join(self.output_folder / "exploitable-findings.txt")
        with open(file_path, "a") as f:
            f.write("Findings identified in Nessus file with publicly available exploits:\n\n")
            for k,v in findings.items():
                f.write(f'Finding: {v["name"]}\n')
                f.write(f'Plugin ID: {k}\n')
                f.write(f'CVEs: {v["cves"]}\n')
                f.write(f'Hosts: {v["hosts"]}\n\n')

            f.close()

    def web_directories(self):
        hosts = self.root.findall(".//ReportHost")
        web_directories = {}
        for host in hosts:
            for item in host.findall(".//ReportItem"):
                plugin_id = item.get("pluginID")
                if plugin_id == "11032":
                    ip = host.get("name")
                    plugin_output = item.find(".//plugin_output").text
                    try:
                        clean_output = re.search(r"(/.*)", plugin_output)[1]
                    except:
                        continue
                    port = item.get("port")
                    hostname = ip + ":" + port
                    clean_output = clean_output.replace("//", "") # FIX THIS
                    web_directories[hostname] = clean_output.split(", ")

        file_path = os.path.join(self.output_folder / "web-directories.json")
        with open(file_path, "w") as f:
            json.dump(web_directories, f, indent=4)

    def run_eyewitness(self):
        # we don't interact with the drone in this class
        pass

class Nessus:
    def __init__(self, drone, username, password, mode, project_name, policy_file, targets_file, scan_file, exclude_file, output_folder):
        self.args = parser.parse_args()
        self.output_folder = output_folder
        self.drone = drone
        self.username = username
        self.password = password
        if scan_file:
            self.analyze_results(scan_file)
            exit()

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
        with LogContext("Retrieving API tokens") as p:
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
                if p is not None:
                    p.failure(e.args[0])
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
        with LogContext("Adding targets to reject list") as p:
            try:
                # Connect to the SSH server
                p.status("Connecting to the ssh server")
                drone = Drone(self.drone, self.username, self.password)

                # Fetch drone IP
                p.status("Getting drone IP")
                cmd = 'ip a s eth0 | grep -o "inet .* brd" | grep -o "[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*"'
                drone_ip = drone.execute(cmd).split("\n")[0]

                # Add drone IP to nessus rules
                p.status(f"Adding drone IP {drone_ip} to reject list")
                cmd = f"echo 'reject {drone_ip}' | sudo tee -a /opt/nessus/etc/nessus/nessusd.rules"
                drone.execute(cmd)

                # Add targets provided from -e to nessus rules
                try:
                    p.status(f"Adding exclude targets from to reject list")
                    for exclude_target in self.exclude_file:
                        exclude_target = exclude_target.rstrip()
                        cmd = f"echo 'reject {exclude_target}' | sudo tee -a /opt/nessus/etc/nessus/nessusd.rules"
                        drone.execute(cmd)
                except:
                    pass

                drone.close()
                p.success(f"Exclusion targets added to reject list on /opt/nessus/etc/nessus/nessusd.rules")
                log.info("Targets added to reject list successfully.")

            except Exception as e:
                if p is not None:
                    p.failure(e.args[0])
                log.error(f"Failed to add targets to reject list: {e.args[0]}")
                exit()


    def update_settings(self):
        with LogContext("Updating settings") as p:
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

                p.success()

            except Exception as e:
                p.failure(str(e))
                exit()

    def import_policies(self):
        with LogContext("Importing policies") as p:
            try:
                # check if policy file already exists:
                policy_name = self.policy_file_name.rsplit(".", 1)[0]
                if "\\" in policy_name:
                    policy_name = policy_name.split("\\")[-1]
                elif "/" in policy_name:
                    policy_name = policy_name.split("/")[-1]
                response = requests.get(self.url + "/policies", headers=self.api_auth, verify=False)
                if policy_name in response.text:
                    p.failure("Policy file already exists, skipping import")
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
                    p.success()

                else:
                    raise Exception("Could not import policies.")

            except Exception as e:
                p.failure(e.args[0])
                exit()


    def create_scan(self, launch):
        with LogContext("Creating new scan") as p:
            try:
                # check if scan name already exists first:
                if self.get_scan_info() is not None:
                    p.failure("Scan name already exists")
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

                p.success()

            except Exception as e:
                p.failure(str(e))
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
        with LogContext(f"Sending {action} request to \"{self.project_name}\"") as p:
            try:
                scan_id = self.get_scan_info()["id"]
                response = requests.post(self.url + f"/scans/{scan_id}/{action}", headers=self.token_auth, verify=False)
                if response.status_code == 200:
                    p.success()
                else:
                    raise Exception("Could not complete scan action")

            except Exception as e:
                p.failure(e.args[0])
                exit()

    def monitor_scan(self):
        status = self.get_scan_info()["status"]
        time_elapsed = 0
        with LogContext(f"Scan status") as p:
            while status == "running":
                p.status(status)
                status = self.get_scan_info()["status"]           
                time.sleep(60)
                time_elapsed += 1
                if time_elapsed == 5:
                    with LogContext("Reauthenticating"):
                        self.get_auth(verbose=False)
                    time_elapsed = 0

            p.success(status)


    def export_scan(self):
        try:
            # get scan id
            scan_id = self.get_scan_info()["id"]
            # template_id = "49"
            # nessus_version = requests.get(self.url + "/server/properties", headers=self.token_auth, verify=False)
            # version_info = nessus_version.json()
            # ui_version = version_info.get("nessus_ui_version")
            # if re.match(r"^8(\.|$)", ui_version):
            #     template_id = "Vulnerabilites By Plugin" # Detailed vulns by plugin 
            #     # 214
            # else:
                
# ############ Removed the below code as the url is different between nessus 8 and nessus 10 but the template ID is the same
            response = requests.get(self.url + f"/reports/custom/templates", headers=self.token_auth, verify=False)
            templates = json.loads(response.text)
            for template in templates:
                
                
            #     # if "Detailed Vulnerabilites By Plugin" in template["name"]:
                if template["name"] == "Detailed Vulnerabilites By Plugin":
                    template_id = template["id"]
                    print(template_id, template["name"])
                    break	


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
            
                with LogContext(f"Exporting {k} file") as p:
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
                            p.success(f"Done. Scan file exported to \"{file_path}\"")
                            break

                        else:
                            raise Exception(f"Downloading {k} file failed with status code {response.status_code}")

            return self.project_name + ".nessus"

        except Exception as e:
            with LogContext("Exporting scan failed") as p:
                p.failure(e.args[0])
                exit()
                
    def analyze_results(self, scan_file):
            with LogContext("Analyzing results") as p:
                try:
                    analyze = Analyzer(scan_file, self.output_folder)
                    drone = Drone(self.drone, self.username, self.password)

                    p.status(f"Parsing exploitable vulnerabilities")
                    analyze.vulnerabilities()
                    p.status(f"Parsing web directories found")
                    analyze.web_directories()
                    p.status(f"Running eyewitness (results in /tmp/eyewitness on drone)")
                    remote_file = drone.upload(scan_file)
                    drone.execute(f"eyewitness -x {remote_file} -d /tmp/eyewitness --no-prompt")
                    drone.close()

                    p.success()

                except Exception as e:
                    log.error(e.args[0])
                    exit()

    # Mode handlers
    def deploy(self):
        self.exclude_targets()
        self.update_settings()
        self.import_policies()
        self.create_scan(True)
        self.monitor_scan()
        scan_file = self.export_scan()
        self.analyze_results(scan_file)

    def trigger(self):
        self.exclude_targets()
        self.update_settings()
        self.import_policies()
        self.create_scan(False)

    def launch(self):
        self.scan_action("launch")
        self.monitor_scan()
        scan_file = self.export_scan()
        self.analyze_results(scan_file)

    def pause(self):
        self.scan_action("pause")

    def resume(self):
        self.scan_action("resume")
        self.monitor_scan()
        scan_file = self.export_scan()
        self.analyze_results(scan_file)

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
    parser.add_argument("-m", "--mode", required=True, choices=["deploy","trigger","launch","pause","resume","monitor","export","analyze", "manual"], help="" \
        "choose mode to run Nessus:\n" \
        "deploy: update settings, upload policy file, upload targets file, launch scan, monitor scan, export results, analyze results\n" \
        "trigger: update settings, upload policy file, upload targets files\n" \
        "launch: launch scan, export results, analyze results\n" \
        "pause: pause scan\n" \
        "resume: resume scan, export results, analyze results\n" \
        "monitor: monitor scan\n" \
        "export: export scan results, analyze results\n" \
        "analyze: analyze scan file (output exploitable findings, ports matrix, and web directories found)\n"
        "manual: perform nmap scans and manual finding verification"
    )
    parser.add_argument("-d", "--drone", required=True, help="drone name or IP")
    parser.add_argument("-c", "--client-name", dest="client", required=False, help="client name or project name (used to name the scan and output files)")
    parser.add_argument("-p", "--policy-file", dest="policy", required=False, help="nessus policy file", type=argparse.FileType('rb'))
    parser.add_argument("-t", "--targets-file", dest="targets", required=False, help="targets file", type=argparse.FileType('r'))
    parser.add_argument("-e", "--exclude-file", dest="exclude_file", required=False, help="exclude targets file", type=argparse.FileType('r'))
    parser.add_argument("-o", "--output-path", dest="output", required=False, help="output path to store exported files", type=pathlib.Path, default=os.getcwd())
    parser.add_argument("-s", "--scan-file", dest="scan_file", required=False, help="scan results file")
    parser.add_argument("-f ", "--csv-file", dest="file", required=False, help="Path/to/nessus_scan_results.csv")
    parser.add_argument("-x", "--external", dest="external", required=False, action="store_const", const=True, help="used if drone is 'pendrone'")
    parser.add_argument("-l", "--local", dest="local", required=False, action="store_const", const=True, help="run manual checks on your local machine instead of over ssh")
    args = parser.parse_args()
    c = Colours()
    # Check args requirements for each mode
    if args.mode == "analyze":
        if not args.scan_file:
            log.error("You must provide a scan file (-s)")
            exit()
        username, password = get_creds()
        
        
    if args.mode == "manual":
        # Nessus.get_auth = True
        if not args.file:
            log.error("You must provide a csv file (-f)")
            exit()
        if not args.file.endswith(".csv"):
            print(c.red,"Error: The file must be of type .csv")
            exit()
        if os.path.isfile(args.file) and args.file.endswith(".csv") and args.local:
            print(c.green,"File exists:", args.file)
            print(c.blue,"Running script with local checks enabled")
            username = None
            password = None
        elif os.path.isfile(args.file) and args.file.endswith(".csv"):
            print(c.green,"File exists:", args.file)
            username, password = get_creds()
        else:
            print(c.red,"File does not exist:", args.file)
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

    # Initialize nessus
    execute = Lackey(
        drone=args.drone,
        username=username,
        password=password,
        file_path=args.file,
        mode=args.mode
    )
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

    elif args.mode == "analyze":
        log.info("Analyzing scan results")
        nessus.analyze_results()

    elif args.mode == "manual":
        print(c.green,f"Performing manual testing\n{c.yellow} All scan output will be saved in the {c.bold}evidence{c.rc} directoy{c.rc}")
        execute.manual_tests()		
