import csv
import subprocess

def run_nmap(ip, port, name, args, output_file):
    print(f"Currently testing {ip}:{port} for {name}")
    nmap_output = subprocess.run([f'nmap -T4 {args} {port} {ip} '], capture_output=True, shell=True)
    with open(output_file, "w") as f:
        f.write(nmap_output.stdout.decode())
    with open(output_file, "r") as f:
        content = f.read()
    if "Host seems down" in content:
        return "down"
    elif "filtered" in content or "closed" in content:
        return "unknown"
    else:
        return "up"

class NessusCSVParser:
    def __init__(self, file_path):
        self.file_path = file_path
    
    def parse(self, plugin_ids):
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
    
    def nmap_verify(self, plugin_ids, args, output_file):
        name, ips, ports = self.parse(plugin_ids)
        valid_scan_found = False
        for i in range(len(ips)):
            if valid_scan_found:
                break
            ip = ips[i]
            port = ports[i]
            status = run_nmap(ip, port, name, args, output_file)
            if status == "down":
                if i == len(ips) - 1:
                    print("Error: All IP addresses are down -", name)
                    break
            elif status == "unknown":
                print("Host may be down, unable to verify -", name)
                valid_scan_found = True
                break
            else:
                print("Finding:", name, "Verified")
                # Set the flag variable to indicate that a valid scan has been found
                valid_scan_found = True
                break
    
    def tls_version(self):
        plugin_ids = ["104743", "157288"]
        args = "--script ssl-enum-ciphers -p"
        output_file = "tls_version.txt"
        self.nmap_verify(plugin_ids, args, output_file)
    def manual(self):
        self.tls_version()
parser = NessusCSVParser('file.csv')
parser.manual()