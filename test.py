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
		if not verbose: log.error()
		with log.info("Retrieving api tokens") as p:
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
				p.success()
				log.info()

			except Exception as e:
				p.failure(e.args[0])
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
	def update_settings(self):
		with log.info("Updating settings") as p:
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
				p.failure(e.args[0])
				exit()

	def create_scan(self, launch):
		with log.info("Creating new scan") as p:
			# check if scan name already exists first:
			if self.get_scan_info() is not None:
				p.failure("Scan name already exists")
				exit()

			try:
				project_name = self.project_name

				# get policy id
				policies = json.loads(requests.get(self.url + "/policies", headers=self.api_auth, verify=False).text)["policies"]
				for policy in policies:
					if policy["name"] == self.policy_name:
						policy_id = policy["id"]
			
					# upload targets file
				file = {
					"Filedata": ("targets.txt", self.targets_file)
				}
				requests.post(self.url + "/file/upload", headers=self.api_auth, files=file, verify=False)

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
				requests.post(self.url + "/scans", headers=self.token_auth, json=data, verify=False)
				p.success()

			except Exception as e:
				p.failure()
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
		with log.info(f"Sending {action} request to \"{self.project_name}\"") as p:
			try:
				scan_id = self.get_scan_info()["id"]
				response = requests.post(self.url + "/scans/" + str(scan_id) + "/" + action, headers=self.token_auth, verify=False)
				p.success()

			except Exception as e:
				log.error(e)
				exit()

	def monitor_scan(self):
		status = self.get_scan_info()["status"]
		time_elapsed = 0
		with log.info(f"Scan status") as p:
			while status == "running":
				p.status(status)
				status = self.get_scan_info()["status"]			
				time.sleep(60)
				time_elapsed += 1
				if time_elapsed == 5:
					p.status("Reauthenticating to keep session alive")
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
			for template in templates:
				if template["name"] == "Complete List of Vulnerabilities by Host":
					template_id = template["id"]
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
				with log.info(f"Exporting {k} file") as p:
					# get scan token
					data = v
					response = requests.post(self.url + "/scans/" + str(scan_id) + "/export", headers=self.token_auth, json=data, verify=False)
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
							raise Exception
			
			return self.project_name + ".nessus"

		except Exception as e:
			p.failure(e.args[0])
			exit()

	# Mode handlers
	def trigger(self):
		self.export_scan(True)
		self.create_scan(True)

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
		# if args.drone is None or args.client is None:
		# 	log.error("You must provide the drone name (-d) and the client name (-c)")
		# 	exit()
		# if args.mode == "deploy" or args.mode == "trigger":
		# 	if not args.policy or not args.targets:
		# 		log.error("You must provide a policy file (-p) and a targets file (-t) for this mode")
		# 		exit()
		# # Check drone name/ip and create url (for nessus) 
		# if "http" in args.drone:
		# 	log.error("You must provide only the drone name/dns, or IP. Do not use http link")
		# 	exit()
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
    