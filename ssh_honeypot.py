# Import library dependencies.
import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import time
from pathlib import Path
# Constants.
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# Constants.
# Get base directory of where user is running honeypy from.
base_dir = base_dir = Path(__file__).parent.parent
# Source creds_audits.log & cmd_audits.log file path.
server_key = base_dir / 'ssh_honeypy' / 'static' / 'server.key'

creds_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'creds_audits.log'
cmd_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'cmd_audits.log'

# SSH Server Host Key.
host_key = paramiko.RSAKey(filename=server_key)

# Logging Format.
logging_format = logging.Formatter('%(message)s')

# Funnel (catch all) Logger.
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(cmd_audits_log_local_file_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Credentials Logger. Captures IP Address, Username, Password.
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(creds_audits_log_local_file_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

 
# SSH Server Class. This establishes the options for the SSH server.
class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
    
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with ' + f'username: {username}, ' + f'password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def emulated_shell(channel, client_ip):
    channel.send(b"corporate-jumpbox2$ ")
    command = b""
    while True:  
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()

        command += char
        # Emulate common shell commands.
        if char == b"\r":
            if command.strip() == b'exit':
                response = b"\n Goodbye!\n"
                channel.close()
            elif command.strip() == b'pwd':
                response = b"\n" + b"\\usr\\local" + b"\r\n"
                funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')

            elif command.strip() == b'id':
                response = b"\n" + b"uid=1000(corpuser1) gid=1000(the_corpusers) groups=1000(the_corpusers),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),125(sambashare)" + b"\r\n"
                funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')

            elif command.strip() == b'whoami':
                response = b"\n" + b"corpuser1" + b"\r\n"
                funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')

            elif command.strip() == b'ls':
                response = b"\n" + b"jumpbox1.conf\t passwd\t rsa_id" + b"\r\n"
                funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')

            elif command.strip() == b'cat passwd':
                response = b"\n" + b"root:x:0:0:root:/root:/bin/bash\rcorpuser1:x:1001:1001:Corporate User 1:/home/corpuser1:/bin/bash\rjohndoe:x:1002:1002:John Doe:/home/johndoe:/bin/bash\rjanedoe:x:1003:1003:Jane Doe:/home/janedoe:/bin/bash\rguest:x:1004:1004:Guest User:/home/guest:/bin/bash" + b"\r\n"
                funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')

            elif command.strip() == b'cat jumpbox1.conf':
                response = b"\n" + b"Go to deeboodah.com" + b"\r\n"
                funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')

            elif command.strip() == b'ls -l':
                response = (
                    b"total 0\n"
                    b"-rw-r--r-- 1 corpuser1 thecorpusers  1234 Dec 22 12:34 jumpbox1.conf\n"
                    b"-rw-r--r-- 1 root root   456 Dec 22 12:34 passwd\n"
                    b"-rw----r-- 1 corpuser1 thecorpusers  7890 Dec 22 12:34 rsa_id\n"
                )
                funnel_logger.info(f'Command {command.strip()}' + " executed by " f'{client_ip}')

            elif command.strip() == b'ps aux':
                response = (
                    b"\nUSER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                    b"root         1  0.0  0.1  22556  1256 ?        Ss   10:00   0:00 /sbin/init\n"
                    b"root       256  0.1  0.3  42312  2456 pts/0    S    10:01   0:00 sshd\n"
                    b"user       300  0.0  0.1  20248  1368 pts/1    Ss   10:02   0:00 bash\n"
                )
                funnel_logger.info(f'Command {command.strip()}' + " executed by " f'{client_ip}')

            elif command.strip() == b'uname -a':
                response = b"\n" + b"Linux honeypot 5.15.0-0-generic #1 SMP x86_64 GNU/Linux" + b"\r\n"
                funnel_logger.info(f'Command {command.strip()}' + " executed by " f'{client_ip}')
                
            elif command.strip() == b'top':
                response = (
                    b"\ntop - 10:15:30 up  5 days,  3:20,  1 user,  load average: 0.01, 0.05, 0.00\n"
                    b"Tasks:  10 total,   1 running,   9 sleeping,   0 stopped,   0 zombie\n"
                    b"%Cpu(s):  0.3 us,  0.1 sy,  0.0 ni, 99.6 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n"
                )
                funnel_logger.info(f'Command {command.strip()}' + " executed by " f'{client_ip}')
                
            elif command.strip() == b'netstat':
                response = (
                    b"\nActive Internet connections (w/o servers)\n"
                    b"Proto Recv-Q Send-Q Local Address           Foreign Address         State      \n"
                    b"tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN     \n"
                    b"tcp        0      0 192.168.1.5:80         0.0.0.0:*               ESTABLISHED\n"
                    b"tcp        0      0 192.168.1.5:443        0.0.0.0:*               ESTABLISHED\n"
                    b"udp        0      0 192.168.1.5:123        0.0.0.0:*                           \n"
                    b"udp        0      0 192.168.1.5:5353       0.0.0.0:*                           \n"
                    b"Proto Recv-Q Send-Q Local Address           Foreign Address         State      \n"
                    b"tcp        0      0 192.168.1.6:22         0.0.0.0:*               LISTEN     \n"
                    b"tcp        0      0 192.168.1.6:8080       0.0.0.0:*               ESTABLISHED\n"
                    b"udp        0      0 127.0.0.1:5353         0.0.0.0:*                           \n"
                    b"udp        0      0 127.0.0.1:1900         0.0.0.0:*                           \n"
                )
                funnel_logger.info(f'Command {command.strip()}' + " executed by " f'{client_ip}')

            elif command.strip() == b'ifconfig':
                response = (
		                b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
		                b"        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
		                b"        inet6 fe80::a00:27ff:fe4e:66b2  prefixlen 64  scopeid 0x20<link>\n"
		                b"        ether 08:00:27:4e:66:b2  txqueuelen 1000  (Ethernet)\n"
		                b"        RX packets 105123  bytes 14228754 (14.2 MB)\n"
		                b"        TX packets 50012  bytes 5634823 (5.6 MB)\n"
                    ) 
                funnel_logger.info(f'Command {command.strip()}' + " executed by " f'{client_ip}')
                
            elif command.strip() == b'ip addr':
                    response = ( b"\n" +
                        b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000\n"
                        b"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                        b"    inet 127.0.0.1/8 scope host lo\n"
                        b"       valid_lft forever preferred_lft forever\n\n"
                        b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP qlen 1000\n"
                        b"    link/ether 08:00:27:4e:66:b2 brd ff:ff:ff:ff:ff:ff\n"
                        b"    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0\n"
                        b"       valid_lft 600sec preferred_lft 600sec\n"
                    )
                    funnel_logger.info(f'Command {command.strip()}' + " executed by " f'{client_ip}')
            else:
                response = b"\n" + bytes(command.strip()) + b"\r\n"
                funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')
            channel.send(response)
            channel.send(b"corporate-jumpbox2$ ")
            command = b""

def client_handle(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")
    try:
    
        # Initlizes a Transport object using the socket connection from client.
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        # Creates an instance of the SSH server, adds the host key to prove its identity, starts SSH server.
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        # Establishes an encrypted tunnel for bidirectional communication between the client and server.
        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
        
        try:
            # Endless Banner: If tarpit option is passed, then send 'endless' ssh banner.
            if tarpit:
                endless_banner = standard_banner * 100
                for char in endless_banner:
                    channel.send(char)
                    time.sleep(8)
            # Standard Banner: Send generic welcome banner to impersonate server.
            else:
                channel.send(standard_banner)
            # Send channel connection to emulated shell for interpretation.
            emulated_shell(channel, client_ip=client_ip)

        except Exception as error:
            print(error)
    # Generic catch all exception error code.
    except Exception as error:
        print(error)
        print("!!! Exception !!!")
    
    # Once session has completed, close the transport connection.
    finally:
        try:
            transport.close()
        except Exception:
            pass
        
        client.close()

def honeypot(address, port, username, password, tarpit=False):
    
    # Open a new socket using TCP, bind to port.
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    # Can handle 100 concurrent connections.
    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True: 
        try:
            # Accept connection from client and address.
            client, addr = socks.accept()
            # Start a new thread to handle the client connection.
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password, tarpit))
            ssh_honeypot_thread.start()

        except Exception as error:
            # Generic catch all exception error code.
            print("!!! Exception - Could not open new client connection !!!")
            print(error)