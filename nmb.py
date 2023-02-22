import csv
import subprocess
import argparse
import os
# import xml.etree.ElementTree as ET
import subprocess
class Colours:
    def __init__(self):
        self.green = "\033[32m[+]\033[0m"
        self.red = "\033[91m[-]\033[0m"
        self.bold = '\033[1m'
        self.blue = '\033[94m[-->]\033[0m'
        self.yellow = '\033[93m[!]\033[0m'
        self.rc = '\033[0m'


def execute_checks(ip, port, name, script, execute_custom=False, execute_nmap=False):
    nmap = "nmap -T4"
    c = Colours()
    print(c.blue,f"Testing {ip}:{port} for {name}")
    try:
        output_file = "{}.txt".format(name)
        if execute_custom:
            output = subprocess.run([f'{script} {ip} '], capture_output=True, shell=True, check=True)
        if execute_nmap:
            output = subprocess.run([f'{nmap} {script} -p {port} {ip} '], capture_output=True, shell=True, check=True)
        with open(output_file, "w") as f:
            f.write(output.stdout.decode())
        with open(output_file, "r") as f:
            content = f.read()
        if "Host seems down" in content or "0 hosts up" in content:
            return "down"
        elif "filtered" in content or "closed" in content:
            return "unknown"
        if "SNMP request timeout" in content or "request timed out" in content:
            return "down"
        else:
            return "up"
    except subprocess.CalledProcessError as e:
        print(f"Error occurred during execution: {e}")

class PluginConfig:
    def __init__(self):
        self.serviceVersion = "-sC -sV"
        self.osVersion = "sudo nmap -sC -sV -O"
        self.sslCert = "--script ssl-cert"
        self.sshCiphers = "--script ssh2-enum-algos"
        self.sslCiphers = "--script ssl-enum-ciphers"
        self.plugins = {
    "splunk_version": {
        "ids": [
            "164076", "171550", "164329"
        ],
        "option": self.serviceVersion
    },
    "custom_snmp_check": {
        "ids": [
            "41028"
        ],
        "option": "snmp-check -v 2c -c public -w"
    },
    "custom_ntp_mode6": {
        "ids": [
            "97861"
        ],
        "option": "ntpq -c rv"
    },
    "custom_smb_targets": {
        "ids": [
            "57608"
        ],
        "option": "crackmapexec smb --gen-relay-list smb_targets"
    },
    "tls_version": {
        "ids": [
            "104743", "157288"
        ],
        "option": self.sslCiphers
    },
    "ssl_cert": {
        "ids": [
            '51192', '20007', '57582', '15901'
        ],
        "option": self.sslCert
    },
    "ssh_ciphers": {
        "ids": [
            "70658", "153953", "71049"
        ],
        "option": self.sshCiphers
    },
    "esxi_version": {
        "ids": [
            "13847", "168828"
        ],
        "option": self.serviceVersion
    },
    "vcenter_version": {
        "ids": [
            "168746"
        ],
        "option": self.serviceVersion
    },
    "php_version": {
        "ids": [
            "58987","166901", "161971", "165545"
        ],
        "option": self.serviceVersion
    },
    "apache_version": {
        "ids": [
            "150280", "153583", "156255", "158900", "161454", "161948", "170113", "153585", "153586"
        ],
        "option": self.serviceVersion
    },
    "openssl_version": {
        "ids": [
            "152782", "160477", "162420", "148125", "148402", "158974", "144047", "157228", "162721"
        ],
        "option": self.serviceVersion
    },
    "tomcat_version": {
        "ids": [
            "72692", "95438", "121119", "133845", "66428", "72691", "74247", "74246", "77475", "83764", "88936", "88936", "94578", "96003", "99367", "100681", "103329", "103329", "103698", "103782", "106975", "118035", "12116", "12117", "12118", "121120", "121121", "136770", "138851", "147163", "148405", "151502"
        ],
        "option": self.serviceVersion
    },
    "unix_os_version": {
        "ids": [
            "33850"
        ],
        "option": self.osVersion
    },
    "windows_os_version": {
        "ids": [
            "108797"
        ],
        "option": self.osVersion
    }
}
    

class Lackey:
    def __init__(self, file_path):
        self.file_path = file_path

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
        ips = list(set(ips))
        return name, ips, ports

    def verify_scans(self, plugin_id, script, execute_custom=False, execute_nmap=False):
        c = Colours()
        name, ips, ports = self.parse_user_csv(plugin_id)
        valid_scan_found = False
        for i in range(len(ips)):
            if valid_scan_found:
                break
            ip = ips[i]
            port = ports[i]
            status = execute_checks(ip, port, name, script, execute_custom, execute_nmap)
            if status == "down":
                if i == len(ips) - 1:
                    print(c.red,"Error: All IP addresses are down -", name)
                    break
            elif status == "unknown":
                print(c.yellow,"Host may be down, unable to verify -", name)
                valid_scan_found = True
                break
            else:
                print(c.green,"Finding:", name, "Verified")
                # Set the flag variable to indicate that a valid scan has been found
                valid_scan_found = True
                break
        
    

class Grunt:
    def __init__(self, file_path):
        self.lackey = Lackey(file_path)
        self.plugin_config = PluginConfig()
    
    def execute_plugin(self, plugin_name):
        plugin_id = self.plugin_config.plugins[plugin_name]["ids"]
        script = self.plugin_config.plugins[plugin_name]["option"]
        if plugin_name.startswith("custom"):
            self.lackey.verify_scans(plugin_id, script, execute_custom=True)
        else:
            self.lackey.verify_scans(plugin_id, script, execute_nmap=True)

    def run_all(self):
        for plugin_name in self.plugin_config.plugins.keys():
            self.execute_plugin(plugin_name)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        usage = "nmb.py [OPTIONS]",
        formatter_class = argparse.RawTextHelpFormatter,
        epilog = "Examples:\n" \
                 "nmb.py file.csv --msf\n" \
                 "nmb.py file.csv -q\n" \
                 "nmb.py file.csv -q --msf\n" \
                 "nmb.py file.csv"
    )
    parser.add_argument("file", type=str, help="Path/to/nessus_scan_results.csv")
    parser.add_argument("-q", dest="query", required=False, help="check for supported plugins", action="store_true")
    parser.add_argument("--msf", dest="metasploit", required=False, help="Start with metasploit checks enabled", action="store_true")
    args = parser.parse_args()
    c = Colours()
    # if args.query:
    #     execute = Tester(args.file)
    #     plugin_id = Tester.parse_user_csv
    #     execute.parse_user_csv()
    if not args.file.endswith(".csv"):
        print(c.red,"Error: The file must be of type .csv")
        exit()
    if os.path.isfile(args.file):
        print(c.green,"File exists:", args.file)
        execute = Grunt(args.file)
        execute.run_all()
    else:
        print(c.red,"File does not exist:", args.file)
        exit()