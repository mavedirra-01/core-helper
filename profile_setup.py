import paramiko
import argparse
import socket
import scp
import getpass
import webbrowser
import subprocess

def forward_local_port(local_port, remote_port):
    ip_address = socket.gethostbyname(hostname)
    print(f"Connected to {hostname} - with localport {local_port}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=ip_address, username=username, password=password)

    # command = 'sudo systemctl start nessusd'
    command = 'ls -la /'
    stdin, stdout, stderr = ssh.exec_command(command)

# Wait for the command to finish
    print("Waiting for nessus to start ...")
    exit_status = stdout.channel.recv_exit_status()

# Print the output of the command
    print(stdout.read().decode())

    # ssh.close()
    webbrowser.open(f"http://localhost:{local_port}")
    subprocess.run(f"ssh -N {username}@{hostname} -L {local_port}:localhost:{remote_port} &")
    

def upload_file_to_host(hostname, username, password, lp=None, rp=None):
    
    try:
        # Resolve the hostname to an IP address
        ip_address = socket.gethostbyname(hostname)

        # Connect to the host using SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=ip_address, username=username, password=password)

        # Open an SCP connection to upload the file
        with scp.SCPClient(ssh.get_transport()) as scp_conn:
            # Upload the file to the remote host
            if lp and rp:
                scp_conn.put(lp, rp)
    except Exception as e:
        print(f'Error uploading file to {hostname}: {e}')
    print(f'Successfully uploaded file to {hostname}')
    # print(f'Connection to {hostname} is now open and forwarding local port 8834 to the remote host')
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Upload a file to a remote host via SCP')
    parser.add_argument('hostname', type=str, help='Short name of the target machine. EX: antman')
    parser.add_argument('-lp', type=str, default=None, help='Path to the local file to upload')
    parser.add_argument('-rp', type=str, default=None, help='Path to the remote file on the target machine')
    parser.add_argument('-u', action='store_true', help='Upload the file to the remote machine')
    parser.add_argument('-pf', action='store_true', help='Tunnel nessus port to localhost')
    args = parser.parse_args()
    # username = "drone"
    # domain = "kevlar.bulletproofsi.net"
    # hostname = f'{args.hostname}.{domain}'
    username = "root"
    hostname = f'{args.hostname}'
    password = getpass.getpass(prompt=f'Enter password for {username}@{hostname}: ')
    # hostname = f'{args.hostname}'
    if args.u and (not args.lp or not args.rp):
        print('Error: Both local and remote paths are required to upload a file')
    elif args.u:
        upload_file_to_host(hostname, username, password, args.lp, args.rp)
    elif args.pf:
        local_port = 11111
        remote_port = 11111
        forward_local_port(local_port, remote_port)
        
    else:
        print("")

