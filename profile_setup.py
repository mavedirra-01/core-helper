import paramiko
import sys
import argparse
import socket
import scp
import getpass

def upload_file_to_host(hostname, username, password, local_path=None, remote_path=None):
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
            if local_path and remote_path:
                scp_conn.put(local_path, remote_path)

        stdin, stdout, stderr = ssh.exec_command('while true; do sleep 600; done')
    except Exception as e:
        print(f'Error uploading file to {hostname}: {e}')
    remote_port = 8834
    local_port = 8834
    transport = ssh.get_transport()
    channel = transport.open_channel('direct-tcpip', ('localhost', remote_port), ('localhost', local_port))
    print(f'Successfully uploaded file to {hostname}')
    print(f'Connection to {hostname} is now open and forwarding local port 8834 to the remote host')
    try:
        while True:
            command = input('$ ')
            if command.strip() == 'exit':
                break
            channel.send(command + '\n')
            output = channel.recv(1024).decode('utf-8')
            sys.stdout.write(output)
    except KeyboardInterrupt:
        pass
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Upload a file to a remote host via SCP')
    parser.add_argument('hostname', type=str, help='Short name of the target machine. EX: antman')
    parser.add_argument('--local-path', type=str, default=None, help='Path to the local file to upload')
    parser.add_argument('--remote-path', type=str, default=None, help='Path to the remote file on the target machine')
    parser.add_argument('--upload', action='store_true', help='Upload the file to the remote machine')
    args = parser.parse_args()
    username = "drone"
    domain = "kevlar.bulletproofsi.net"
    hostname = f'{args.hostname}.{domain}'
    password = getpass.getpass(prompt=f'Enter password for {username}@{hostname}: ')
    # hostname = f'{args.hostname}'
    if args.upload and (not args.local_path or not args.remote_path):
        print('Error: Both local and remote paths are required to upload a file')
    elif args.upload:
        upload_file_to_host(hostname, username, password, args.local_path, args.remote_path)
    else:
        print(f'Connected to {hostname} with username {args.username} and password {args.password}')
