#!/usr/bin/python3
# Author: Connor Fancy
# Version: 1.0
# https://www.tenable.com/plugins for a full list of plugins
# Submit an issue request if you want a certain plugin added
import sys
import csv
import subprocess
import os
import shutil
import time

### Colours
green = "\033[32m[+]\033[0m"
red = "\033[91m[-]\033[0m"
bold = '\033[1m'
blue = '\033[94m[-->]\033[0m'
yellow = '\033[93m[!]\033[0m'
rc = '\033[0m'
"""
## To do
- optional convert output text files to html or an easier read format (aquatone)
- add more varations of pluginIDs (this will always be a work in progress)
- Expand upon usage/help  
- condense nmap functions into one

## Done
- created bash script to pull latest nessus scan in csv format 
- less functions, added custom command function
- add capabilites to scan next ip in list if the first one is filtered or no longer alive
- find a better way to catalog pluginIDs
- fixed arguments and error handling : 
    - if file exists but does not have contents == no error
    - if file exists but only has 2 findings == no error 
    - if file exists and metasploit checks are enabled == no error
    - if file exists and metasploit checks are enabled but no msf findings == no error 
    - if file does not exist == error 
    - if path to file is not valid == error 
    - if path to file is valid but file is not .csv == error 
    - if user inputs incorrect arg == error
"""
# Globals
found = False
run_msf = 0
msf_check = 0
query = 0
####################################################################
argc = len(sys.argv)
if argc == 1:
    print(yellow,bold,"Usage",rc,": nmb.py /path/to/nessus.csv","\n")
    print(bold,"Additional options:", rc)
    print(blue,bold,"-m\t",rc," run script with metasploit checks enabled (this will be much slower)")
    print("",blue, bold,"-q\t",rc," Print list of supported plugins based off CSV file")
    sys.exit()
file = sys.argv[1]
if os.path.isfile(file):
    print(green, "File exists:", file)
else:
    print(red, "File does not exist:", file)
    print(yellow, "Did you run the nessus_pull.sh script?")
    sys.exit()
if not file.endswith(".csv"):
    print(red, "Error: The file must be of type .csv")
    print(yellow,bold,"Usage",rc,": nmb.py /path/to/nessus.csv","\n")
    print(bold,"Additional options:", rc)
    print(blue,bold,"-m\t",rc," run script with metasploit checks enabled (this will be much slower)")
    print("",blue, bold,"-q\t",rc," Print list of supported plugins based off CSV file")
    exit()
if argc == 2:
    print(green, "File exists and is in correct format:", file)
else:
    options_arg = sys.argv[2]
    if options_arg == '-m':
        msf_check = 1
        print(green, "Starting script with metasploit options enabled ...")
    elif options_arg == "-q":
        query = 1
    else:
        print("\n",yellow,bold,"Usage",rc,": nmb.py /path/to/nessus.csv -OptionalArg")
        print(bold,"Additional options:", rc)
        print("",blue, bold,"-m\t",rc," Run script with metasploit checks enabled", bold, "Note:", rc, "this will be much slower")
        print("",blue, bold,"-q\t",rc," Print list of supported plugins based off CSV file")
        exit()
make_evidence = "evidence"
if not os.path.exists(make_evidence):
    os.makedirs(make_evidence)
cwd = os.getcwd()
print(blue,"Evidence will be saved to: " + cwd + "/" + make_evidence)
print(blue,"Script started at:", time.ctime())
#####################################################################

def custom_verify(plugin_id, script_args, output_file):
# Open the Nessus .csv file and read it
    ips = []
    ports = []
    global found
    with open(file, 'r', encoding="utf8") as f:
        reader = csv.reader(f)
        # Iterate through each row
        for row in reader:
            # Check if the plugin ID in column 1 matches the specified value
            if row[0] in plugin_id:
                name = row[7]
                # Extract the IP from column 4 and the port from column 6
                ip = row[4]
                port = row[6]
                # Append the IP and port to the respective lists
                ips.append(ip)
                ports.append(port)
                # Delete all ips except the first
                # ips = [ips[0]]

    # Iterate through the ips and ports
    for i in range(len(ips)):
        ip = ips[i]
        port = ports[i]
        # Pass the ip and port to nmap
        scan_output = subprocess.run([f'{script_args} {ip}'], capture_output=True, shell=True)
        with open(output_file, "w") as f:
                f.write(scan_output.stdout.decode())
        with open(output_file, "r") as f:
            content = f.read()
        if "SNMP request timeout" in content:
            if i == len(ips) - 1:
                print(red, "Error: All IP addresses are down -", name)
                break
        elif not content:
            print(yellow, "Unable to verify content please review manually -", name)
            break
        else:
            found = True
            print(green, "Finding:", name, bold,"Verified",rc)
            break
    # Removal of empty lines 
    if os.path.isfile(output_file):
        tmp_file="tmp.txt"
        with open(output_file, "r") as original, open(tmp_file, "w") as temp:
        # iterate over the lines in the original file
            for line in original:
            # check if the line is not empty
                if line.strip():
                # write the non-empty line to the temporary file
                    temp.write(line)
    # remove the original file
        os.remove(output_file)
    # move the temporary file to the original file's location
        dst_file = os.path.join(make_evidence, os.path.basename(output_file))
        shutil.move(tmp_file, dst_file)

#############################################################
def nmap_verify(plugin_id, args, output_file):
    # Open the Nessus .csv file and read it
    ips = []
    ports = []
    global found
    with open(file, 'r', encoding="utf8") as f:
        reader = csv.reader(f)

        # Iterate through each row
        for row in reader:
            # Check if the plugin ID in column 1 matches the specified value
            #matching_plugin_id = "153953" ### weak key exchange SSH
            if row[0] in plugin_id:
                name = row[7]
                # Extract the IP from column 4 and the port from column 6
                ip = row[4]
                port = row[6]
                # Append the IP and port to the respective lists
                ips.append(ip)
                ports.append(port)
                # Delete all ips except the first
                # ips = [ips[0]]
                # print(ips)

    # Iterate through the ips and ports
    for i in range(len(ips)):
        ip = ips[i]
        port = ports[i]
        # Pass the ip and port to nmap
        nmap_output = subprocess.run([f'nmap -Pn -T4 {args} {port} {ip} '], capture_output=True, shell=True)
        with open(output_file, "w") as f:
                f.write(nmap_output.stdout.decode())
        with open(output_file, "r") as f:
            content = f.read()
        if "filtered" in content:
            if i == len(ips) - 1:
                print(red, "Error: All IP addresses might be down, please review results manually -", name)
                break
        else:
            print(green, "Finding:", name, bold,"Verified",rc)
            found = True
            break
    if os.path.isfile(output_file):
        # Removal of empty lines 
        tmp_file="tmp.txt"
        with open(output_file, "r") as original, open(tmp_file, "w") as temp:
        # iterate over the lines in the original file
            for line in original:
            # check if the line is not empty
                if line.strip():
                # write the non-empty line to the temporary file
                    temp.write(line)
    # remove the original file
        os.remove(output_file)
    # move the temporary file to the original file's location
        dst_file = os.path.join(make_evidence, os.path.basename(output_file))
        shutil.move(tmp_file, dst_file)


###################################################################################################################################

def nmap_verify_sudo(plugin_id, args, output_file):
    # Open the Nessus .csv file and read it
    ips = []
    ports = []
    global found
    with open(file, 'r', encoding="utf8") as f:
        reader = csv.reader(f)

        # Iterate through each row
        for row in reader:
            # Check if the plugin ID in column 1 matches the specified value
            #matching_plugin_id = "153953" ### weak key exchange SSH
            if row[0] in plugin_id:
                name = row[7]
                # Extract the IP from column 4 and the port from column 6
                ip = row[4]
                port = row[6]
                # Append the IP and port to the respective lists
                ips.append(ip)
                ports.append(port)
                # Delete all ips except the first
                # ips = [ips[0]]


    # Iterate through the ips and ports
    for i in range(len(ips)):
        ip = ips[i]
        port = ports[i]
        # Pass the ip and port to nmap
        nmap_output = subprocess.run([f'sudo nmap -T4 -Pn {args} {ip} '], capture_output=True, shell=True)
        with open(output_file, "w") as f:
                f.write(nmap_output.stdout.decode())
        with open(output_file, "r") as f:
            content = f.read()
        if "No exact OS matches for host" or "Too many fingerprints match this host" in content:
            if i == len(ips) - 1:
                print(yellow, "Error: All IP addresses might be down, please review results manually -", name)
                break
        else:
            print(green, "Finding:", name, bold,"Verified",rc)
            found = True
            break
    if os.path.isfile(output_file):
        # Removal of empty lines 
        tmp_file="tmp.txt"
        with open(output_file, "r") as original, open(tmp_file, "w") as temp:
        # iterate over the lines in the original file
            for line in original:
            # check if the line is not empty
                if line.strip():
                # write the non-empty line to the temporary file
                    temp.write(line)
    # remove the original file
        os.remove(output_file)
    # move the temporary file to the original file's location
        dst_file = os.path.join(make_evidence, os.path.basename(output_file))
        shutil.move(tmp_file, dst_file)

#############################################################################################################


def msfconsole_verify(plugin_id, module, output_file):
# Open the Nessus .csv file and read it
    ips = []
    ports = []
    with open(file, 'r', encoding="utf8") as f:
        reader = csv.reader(f)

        # Iterate through each row
        for row in reader:
            # Check if the plugin ID in column 1 matches the specified value
            if row[0] in plugin_id:
                global run_msf
                run_msf = 1
                name = row[7]
                # Extract the IP from column 4 and the port from column 6
                ip = row[4]
                port = row[6]
                # Append the IP and port to the respective lists
                ips.append(ip)
                ports.append(port)
                # Delete all ips except the first
                ips = [ips[0]]
    # Iterate through the ips and ports
    for i in range(len(ips)):
        ip = ips[i]
        port = ports[i]
        # Pass the ip and port to nmap

# Run Metasploit command
    if run_msf == 1:
        cmd = f"sudo msfconsole -x 'use {module}; set RHOST {ip}; set RPORT {port}; run; exit -y' > {output_file}"
        subprocess.run(cmd, shell=True)
        dst_file = os.path.join(make_evidence, os.path.basename(output_file))
        shutil.move(output_file, dst_file)

# Check for a certain string in the output file
        if os.path.isfile(dst_file):
            with open(dst_file, 'r') as f:
                output = f.read()
                if "Hash found" or "Opened" in output:
                    print(green, "Exploit", name, bold,"successful!",rc)
                else:
                    print(red, "Error: ", name, "Exploit failed. Check the output file for more information.")

        
############################################################################################

def get_supported_plugins(file, plugin_ids):
    supported_plugins = set()
    with open(file, 'r', encoding="utf8") as f:
        reader = csv.reader(f)
        header = next(reader)
        # Find the index of the plugin ID and plugin name columns
        plugin_id_index = header.index("Plugin ID")
        plugin_name_index = header.index("Name")
        # Iterate through each row
        for row in reader:
            # Extract the plugin ID and name from the current row
            plugin_id = row[plugin_id_index]
            plugin_name = row[plugin_name_index]
            # Check if the plugin ID is in the list of plugin IDs
            if plugin_id in plugin_ids:
                # Add the plugin name to the set of supported plugins
                supported_plugins.add(plugin_name)
    return supported_plugins

# Call the function and print the list of supported plugins
if query == 1:
    supported_plugins = get_supported_plugins(file, ["41028", "97861", "57608", "104743", "150280", "153583", "156255", "158900", "161454", "161948", "170113", "153585", "153586", "51192", "20007", "57582", "15901", "70658", "153953", "71049", "138475", "58987","166901", "161971", "165545", "152782", "160477", "162420", "148125", "148402", "158974", "144047", "157228", "162721", "72692", "95438", "121119", "133845", "66428", "72691", "74247", "74246", "77475", "83764", "88936", "88936", "94578", "96003", "99367", "100681", "103329", "103329", "103698", "103782", "106975", "118035", "12116", "12117", "12118", "121120", "121121", "136770", "138851", "147163", "148405", "151502", "108797", "33850" ])
    print("Supported plugins:")
    for plugin in supported_plugins:
        print("- {}".format(plugin))
    sys.exit()

#############################################################################################


#############################################################################################
custom_verify("41028", "snmp-check -v 2c -c public -w", "snmp_check.txt") # snmp public write test and info gather
custom_verify("57608", "crackmapexec smb --gen-relay-list smb_targets.txt", "smb_targets.txt") # SMB signing not required
custom_verify("97861", "sudo ntpd -c monlist", "ntp_mode6.txt") # NTP Mode 6 scanner
nmap_verify("104743", "--script ssl-enum-ciphers -p", "tls_version.txt") # tls version
nmap_verify(['51192', '20007', '57582', '15901'], "--script ssl-cert -p", "ssl_cert.txt") # ssl cant be trusted, SSL v2/3, self-signed ssl, ssl cert expiry
nmap_verify(["70658", "153953", "71049"], "--script ssh2-enum-algos -p", "ssh_ciphers.txt") # SSH cbc ciphers, SSH weak-keyx, SSH MAC algos
nmap_verify("138475", "-sC -sV -p", "esxi_version.txt") # esxi version
nmap_verify("168746", "-sC -sV -p", "vcenter_version.txt") # VMware vcenter version
nmap_verify(["58987","166901", "161971", "165545"], "-sC -sV -p", "php_version.txt") # PHP unsupported version detection
nmap_verify(["150280", "153583", "156255", "158900", "161454", "161948", "170113", "153585", "153586"], "-sC -sV -p", "apache_version.txt") # Apache version
nmap_verify(["152782", "160477", "162420", "148125", "148402", "158974", "144047", "157228", "162721"], "-sC -sV -p", "openssl_version.txt") # Openssl version
nmap_verify(["72692", "95438", "121119", "133845", "66428", "72691", "74247", "74246", "77475", "83764", "88936", "88936", "94578", "96003", "99367", "100681", "103329", "103329", "103698", "103782", "106975", "118035", "12116", "12117", "12118", "121120", "121121", "136770", "138851", "147163", "148405", "151502"], "-sC -sV -p", "tomcat_version.txt")
nmap_verify_sudo("33850", "-sC -sV -O -p", "unix_os_version.txt") # Unsupported unix OS
nmap_verify_sudo("108797", "-sC -sV -O", "windows_os_version.txt") # Unsupported windows OS

#########################################################################################
if msf_check == 1:
    msfconsole_verify(["80101", "72063"], "auxiliary/scanner/ipmi/ipmi_dumphashes", "ipmi_output.txt") # IPMI
    msfconsole_verify("117615", "exploit/linux/http/hadoop_unauth_exec", "hadoop_shell.txt") # Apache Hadoop YARN

##############################################################################################



###############################################################################################

print(blue,"Script finished at:", time.ctime())