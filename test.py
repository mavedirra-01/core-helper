#!/usr/bin/env python3
# Deployer - A nessus utility to deploy scans and analyses
# author: Joey Melo
# version: v1.0.0

## NEW:

## TO DO:
# -o options not working properly. Debug.
# Check regex on tokens["api_token"] with different drones. May have to tweak it to properly get the token.


import argparse
import ipaddress
import getpass
import json
import os
import paramiko
import pathlib
import re
import requests, urllib3
import sys
import logging as log
import time
import xml.etree.ElementTree as XML
requests.packages.urllib3.disable_warnings()
log.basicConfig(level=log.DEBUG)
# class LogContext:
#     def __init__(self, message):
#         self.message = message

#     def __enter__(self):
#         log.info(self.message)

#     def __exit__(self, exc_type, exc_value, traceback):
#         if exc_type is not None:
#             log.error(f"{self.message}: {exc_type.__name__} - {exc_value}")
#         else:
#             log.info(f"{self.message} completed successfully.")

#     def status(self, status_message):
#         log.info(f"{self.message}: {status_message}")

#     def success(self, success_message=None):
#         if success_message is None:
#             success_message = f"{self.message} completed successfully."
#         log.info(success_message)

#     def failure(self, failure_message=None):
#         if failure_message is None:
#             failure_message = f"{self.message} failed."
#         log.error(failure_message)
 
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
	def __init__(self, hostname, username, password):
		try:
			self.ssh = paramiko.SSHClient()
			self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			self.ssh.connect(hostname=hostname, username=username, password=password)
			self.ssh.exec_command('export TERM=xterm')

		except Exception as e:
			log.error(e.args[0])
			exit()

	def upload(self, local_file):
		remote_file = "/tmp/" + local_file
		try:
			# upload
			sftp = self.ssh.open_sftp()
			sftp.put(local_file, remote_file)
			sftp.close()
			return remote_file

		except Exception as e:
			log.error(e)
			self.close()
			exit()

	def execute(self, cmd):
		try:
			stdin, stdout, stderr = self.ssh.exec_command(cmd)
			err = stderr.read().decode()
			if err != "" and "TERM" not in err:
				log.error(err)
				raise Exception

			return stdout.read().decode()

		except:
			self.close()
			exit()

	def close(self):
		self.ssh.close()

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

				# upload targets file
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
						"text_targets": "targets.txt",
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
			log.error()
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

			# get html template id
			response = requests.get(self.url + f"/reports/custom/templates", headers=self.token_auth, verify=False)
			templates = json.loads(response.text)
			template_id = None
			for template in templates:
				if template["name"] == "Complete List of Vulnerabilities by Host":
					template_id = template["id"]
					break

			if template_id is None:
				raise Exception("HTML template not found")

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
				p.failure(str(e))
			exit()

	def analyze_results(self, scan_file):
			with LogContext("Analyzing results") as p:
				try:
					analyze = Analyzer(scan_file, self.output_folder)
					
					p.status(f"Parsing exploitable vulnerabilities")
					analyze.vulnerabilities()
					p.status(f"Parsing web directories found")
					analyze.web_directories()
					p.status(f"Running eyewitness (results in /tmp/eyewitness on drone)")
					with Drone(self.drone, self.username, self.password) as drone:
						remote_file = drone.upload(scan_file)
						drone.execute(f"eyewitness -x {remote_file} -d /tmp/eyewitness --no-prompt")

					p.success()

				except Exception as e:
					log.error(e.args[0])
					sys.exit()
					
				finally:
					drone.close()  # ensure that drone object is closed even if there's an exception

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
		scan_file = self.export_scan()
		self.analyze_results(scan_file)

def get_creds():
	username = input("username: ").rstrip()
	password = getpass.getpass("password: ")
	print("\n")
	return username, password

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		usage = "deployer.py nessus [OPTIONS]",
		formatter_class = argparse.RawTextHelpFormatter,
		epilog = "Examples:\n" \
				 "deployer.py nessus -d storm -c myclient -m deploy -p mypolicy.nessus -t targets.txt\n" \
				 "deployer.py nessus -d localhost -c myclient -m trigger -p custompolicy.nessus -t targets.txt\n" \
				 "deployer.py nessus -d 10.88.88.101 -c myclient -m pause\n" \
				 "deployer.py nessus -d strange -c myclient -m resume -o /home/drone/Downloads"
	)
	parser.add_argument("-m", "--mode", required=True, choices=["deploy","trigger","launch","pause","resume","monitor","export","analyze"], help="" \
		"choose mode to run Nessus:\n" \
		"deploy: update settings, upload policy file, upload targets file, launch scan, monitor scan, export results, analyze results\n" \
		"trigger: update settings, upload policy file, upload targets files\n" \
		"launch: launch scan, export results, analyze results\n" \
		"pause: pause scan\n" \
		"resume: resume scan, export results, analyze results\n" \
		"monitor: monitor scan\n" \
		"export: export scan results, analyze results\n" \
		"analyze: analyze scan file (output exploitable findings, ports matrix, and web directories found)"
	)
	parser.add_argument("-d", "--drone", required=True, help="drone name or IP")
	parser.add_argument("-c", "--client-name", dest="client", required=False, help="client name or project name (used to name the scan and output files)")
	parser.add_argument("-p", "--policy-file", dest="policy", required=False, help="nessus policy file", type=argparse.FileType('rb'))
	parser.add_argument("-t", "--targets-file", dest="targets", required=False, help="targets file", type=argparse.FileType('r'))
	parser.add_argument("-e", "--exclude-file", dest="exclude_file", required=False, help="exclude targets file", type=argparse.FileType('r'))
	parser.add_argument("-o", "--output-path", dest="output", required=False, help="output path to store exported files", type=pathlib.Path, default=os.getcwd())
	parser.add_argument("-s", "--scan-file", dest="scan_file", required=False, help="scan results file")
	args = parser.parse_args()
	
	# Check args requirements for each mode
	if args.mode == "analyze":
		if not args.scan_file:
			log.error("You must provide a scan file (-s)")
			exit()
		username, password = get_creds()

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
		output_folder=args.output
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
