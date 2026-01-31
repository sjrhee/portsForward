import paramiko
import threading
import logging
import os
import hashlib
import time

class SSHManager:
    def __init__(self):
        self.gateway_client = None
        self.target_client = None
        self.transport = None
        self.connected = False

    def connect(self, host, port, user, key_file):
        """Standard direct connection."""
        self.gateway_client = None
        self.target_client = paramiko.SSHClient()
        self.target_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.target_client.connect(
                hostname=host,
                port=port,
                username=user,
                key_filename=key_file
            )
            self.transport = self.target_client.get_transport()
            self.connected = True
            logging.info(f"Connected to {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"SSH Connection failed: {e}")
            self.connected = False
            return False

    def connect_chained(self, gateway_conf, target_conf):
        """
        Connects to Gateway first, then tunnels to Target.
        gateway_conf: dict(host, port, user, key_file)
        target_conf: dict(host, port, user, key_file)
        """
        self.gateway_client = paramiko.SSHClient()
        self.gateway_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # 1. Connect to Gateway
            logging.info(f"Connecting to Gateway {gateway_conf['host']}...")
            self.gateway_client.connect(
                hostname=gateway_conf['host'],
                port=gateway_conf['port'],
                username=gateway_conf['user'],
                key_filename=gateway_conf['key_file']
            )
            
            # 2. Open Channel for Target
            logging.info(f"Opening tunnel to Target {target_conf['host']}...")
            dest_addr = (target_conf['host'], target_conf['port'])
            local_addr = ('127.0.0.1', 0)
            vm_channel = self.gateway_client.get_transport().open_channel("direct-tcpip", dest_addr, local_addr)
            
            # 3. Connect to Target using the channel
            self.target_client = paramiko.SSHClient()
            self.target_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.target_client.connect(
                hostname=target_conf['host'],
                port=target_conf['port'],
                username=target_conf['user'],
                key_filename=target_conf['key_file'],
                sock=vm_channel
            )
            
            self.transport = self.target_client.get_transport()
            self.connected = True
            logging.info(f"Connected to Target via Gateway.")
            return True
            
        except Exception as e:
            logging.error(f"Chained SSH Connection failed: {e}")
            self.disconnect()
            return False

    def connect_gateway_only(self, gateway_conf):
        """
        Connects ONLY to the Gateway and treats it as the endpoint.
        """
        self.gateway_client = paramiko.SSHClient()
        self.gateway_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            logging.info(f"Connecting to Gateway {gateway_conf['host']} (as Daemon Host)...")
            self.gateway_client.connect(
                hostname=gateway_conf['host'],
                port=gateway_conf['port'],
                username=gateway_conf['user'],
                key_filename=gateway_conf['key_file']
            )
            
            self.transport = self.gateway_client.get_transport()
            self.connected = True
            logging.info(f"Connected to Gateway.")
            return True
        except Exception as e:
            logging.error(f"Gateway Connection failed: {e}")
            self.disconnect()
            return False

    def deploy_and_run(self, local_path, remote_filename="port-daemon", client=None):
        """
        Checks version, uploads if needed, and runs the daemon.
        Assumes client is connected.
        """
        target_client = client
        if not target_client:
            target_client = self.target_client if self.target_client else self.gateway_client

        if not self.connected or not target_client:
            raise Exception("Client not connected")

        try:
            sftp = target_client.open_sftp()
            
            # Ensure ~/.ports exists
            home_dir = target_client.exec_command("echo $HOME")[1].read().decode().strip()
            remote_dir = f"{home_dir}/.ports"
            remote_path = f"{remote_dir}/{remote_filename}"
            
            try:
                sftp.stat(remote_dir)
            except IOError:
                sftp.mkdir(remote_dir)

            # Calculate Local Hash
            local_hash = self._calculate_file_hash(local_path)
            logging.info(f"Local Hash: {local_hash}")

            # Check Remote Hash (if file exists)
            upload_needed = True
            try:
                sftp.stat(remote_path)
                # Run md5sum on remote
                stdin, stdout, stderr = target_client.exec_command(f"md5sum {remote_path}")
                remote_output = stdout.read().decode().strip()
                if remote_output:
                    remote_hash = remote_output.split()[0]
                    logging.info(f"Remote Hash: {remote_hash}")
                    if local_hash == remote_hash:
                        upload_needed = False
                        logging.info("Hashes match. Skipping upload.")
            except IOError:
                logging.info("Remote file not found. Uploading...")
            except Exception as e:
                logging.warning(f"Could not check remote hash: {e}")

            if upload_needed:
                # Attempt to stop existing daemon to avoid "Text file busy"
                logging.info("Stopping existing daemon (if any)...")
                try:
                    target_client.exec_command("pkill -f port-daemon")
                    time.sleep(1) # Wait for exit
                except:
                    pass

                logging.info(f"Uploading {local_path} to {remote_path}...")
                sftp.put(local_path, remote_path)
                sftp.chmod(remote_path, 0o755) # Make executable
                logging.info("Upload complete.")

            sftp.close()

            # Run Daemon
            # Check if running first? (Optional optimization)
            # Just try to run it. If port is in use, it might fail or just work if it's the same instance.
            # Ideally we should kill old one or check. For now, simple run.
            # Using background execution without nohup so it dies when session closes
            logging.info("Starting daemon...")
            # Redirect to log file for debugging
            log_file = f"{remote_dir}/gateway.log"
            cmd = f"{remote_path} > {log_file} 2>&1 &"
            target_client.exec_command(cmd)
            
            # Give it a moment to start
            time.sleep(1)
            return True

        except Exception as e:
            logging.error(f"Deploy failed: {e}")
            return False

    def _calculate_file_hash(self, filepath):
        hasher = hashlib.md5()
        with open(filepath, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()

    def open_tunnel(self, remote_host, remote_port):
        """
        Opens a direct-tcpip channel on the TARGET session.
        """
        if not self.connected or not self.transport:
            raise Exception("SSH Client not connected")
        
        try:
            # src_addr is dummy
            channel = self.transport.open_channel(
                'direct-tcpip',
                dest_addr=(remote_host, remote_port),
                src_addr=('127.0.0.1', 0)
            )
            return channel
        except Exception as e:
            logging.error(f"Failed to open tunnel: {e}")
            raise

    def disconnect(self):
        if self.target_client:
            self.target_client.close()
        if self.gateway_client:
            self.gateway_client.close()
        self.connected = False
        self.gateway_client = None
        self.target_client = None
        self.transport = None
        logging.info("SSH Disconnected")
