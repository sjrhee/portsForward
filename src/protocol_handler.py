import json
import struct
import threading
import socket
import logging

# Daemon Default Port
DAEMON_PORT = 15432

class DaemonProtocol:
    def __init__(self, ssh_manager, event_callback):
        self.ssh_manager = ssh_manager
        self.control_channel = None
        self.event_callback = event_callback # Function to handle UI updates or Logic
        self.running = False
        self.listen_thread = None
        self.response_listeners = {} # type -> queue.Queue
        self.local_listeners = {} # local_port -> socket

    def start_control_session(self):
        """Establishes the initial Control Connection."""
        try:
            # Connect to Daemon on 127.0.0.1:15432 (On Remote)
            self.control_channel = self.ssh_manager.open_tunnel('127.0.0.1', DAEMON_PORT)
            self.running = True
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()
            logging.info("Control session established.")
            return True
        except Exception as e:
            logging.error(f"Failed to start control session: {e}")
            return False

    def stop_local_forwarding(self, local_port):
        """Stops the local listener for the given port."""
        port = int(local_port)
        if port in self.local_listeners:
            sock = self.local_listeners[port]
            try:
                sock.close()
            except Exception as e:
                logging.warning(f"Error closing listener on {port}: {e}")
            del self.local_listeners[port]
            logging.info(f"Stopped local forwarding on port {port}")
            return True
        return False

    def add_response_listener(self, msg_type, queue_obj):
        self.response_listeners[msg_type] = queue_obj

    def send_request(self, payload):
        """Sends a JSON payload with Length-Prefix."""
        if not self.control_channel:
            return False
        
        json_bytes = json.dumps(payload).encode('utf-8')
        length = len(json_bytes)
        # Big Endian Int
        header = struct.pack('>I', length)
        
        try:
            self.control_channel.sendall(header + json_bytes)
            return True
        except Exception as e:
            logging.error(f"Send failed: {e}")
            self._handle_disconnect()
            return False

    def _listen_loop(self):
        """Reads messages from Control Connection."""
        while self.running and self.control_channel:
            try:
                # Read Length (4 bytes)
                length_bytes = self._recv_exact(4)
                if not length_bytes:
                    break
                
                length = struct.unpack('>I', length_bytes)[0]
                
                # Read Payload
                payload_bytes = self._recv_exact(length)
                if not payload_bytes:
                    break
                
                message = json.loads(payload_bytes.decode('utf-8'))
                self._handle_message(message)
                
            except Exception as e:
                logging.error(f"Error in listen loop: {e}")
                break
        
        self._handle_disconnect()

    def _recv_exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.control_channel.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _handle_disconnect(self):
        logging.info("Control connection lost.")
        self.running = False
        if self.control_channel:
            try:
                self.control_channel.close()
            except:
                pass
            self.control_channel = None
        
        # Close all listeners
        for port, sock in list(self.local_listeners.items()):
            try:
                sock.close()
            except:
                pass
        self.local_listeners.clear()

    def _handle_message(self, message):
        """Dispatch based on message type."""
        msg_type = message.get('type')
        logging.info(f"Received: {msg_type}")
        
        if msg_type == 'NEW_CONNECTION':
            # Handle new incoming connection from Daemon
            threading.Thread(target=self._handle_data_tunnel, args=(message,), daemon=True).start()
        
        # Check Listeners
        if msg_type in self.response_listeners:
            try:
                self.response_listeners[msg_type].put(message)
            except:
                pass
        
        # Pass to UI/External callback
        if self.event_callback:
            self.event_callback(message)

    def _handle_data_tunnel(self, message):
        """
        1. Open new SSH tunnel to Daemon.
        2. Send CONNECT_DATA.
        3. Connect to Local Target Port.
        4. Pipe data.
        """
        conn_id = message.get('connection_id')
        remote_port = message.get('remote_port')
        
        # User must have defined where to forward this REMOTE port TO (Local Port)
        # We need a lookup mechanism. For now, assume a lookup function exists passed in __init__ or similar.
        # But wait, self.event_callback might handle only UI. 
        # I need a "Rule Manager". For simplicity, let's look up a global or shared dictionary provided by UI/Main.
        
        target_local_port = self.event_callback('GET_LOCAL_PORT', remote_port)
        if not target_local_port:
            logging.error(f"No local target found for remote port {remote_port}")
            return

        try:
            # 1. Open Tunnel to Daemon
            tunnel = self.ssh_manager.open_tunnel('127.0.0.1', DAEMON_PORT)
            
            # 2. Send CONNECT_DATA
            req = {
                "type": "CONNECT_DATA",
                "connection_id": conn_id
            }
            json_bytes = json.dumps(req).encode('utf-8')
            header = struct.pack('>I', len(json_bytes))
            tunnel.sendall(header + json_bytes)
            
            # Wait for DATA_READY (or just assume it switches, but protocol says it responds)
            # Actually Protocol says: "Response (JSON): DATA_READY".
            # We need to read this response BEFORE piping.
            
            # Read Length
            resp_len_bytes = b''
            while len(resp_len_bytes) < 4:
                c = tunnel.recv(4 - len(resp_len_bytes))
                if not c: raise Exception("Closed during handshake")
                resp_len_bytes += c
            
            resp_len = struct.unpack('>I', resp_len_bytes)[0]
            
            resp_bytes = b''
            while len(resp_bytes) < resp_len:
                c = tunnel.recv(resp_len - len(resp_bytes))
                if not c: raise Exception("Closed during handshake body")
                resp_bytes += c
            
            resp = json.loads(resp_bytes.decode('utf-8'))
            if resp.get('type') != 'DATA_READY' or not resp.get('success'):
                logging.error(f"Data handshake failed: {resp}")
                tunnel.close()
                return

            # 3. Connect to Local Application
            local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_sock.connect(('127.0.0.1', int(target_local_port)))
            
            logging.info(f"Tunnel established: Remote {remote_port} -> Local {target_local_port}")
            
            # 4. Pipe
            self._pipe_sockets(tunnel, local_sock)
            
        except Exception as e:
            logging.error(f"Data tunnel error: {e}")

    def _pipe_sockets(self, s1, s2):
        """Bidirectional copy."""
        def forward(source, dest, name):
            try:
                while True:
                    data = source.recv(4096)
                    if not data: break
                    dest.sendall(data)
            except:
                pass
            finally:
                try: dest.shutdown(socket.SHUT_WR)
                except: pass
                try: dest.close()
                except: pass
                # try: source.close() # Don't close source yet, let other thread handle it or close both?
                # Usually closing one socket makes recv return empty in the other direction eventually? 
                # No, sockets are independent.
                
        t1 = threading.Thread(target=forward, args=(s1, s2, "Remote->Local"), daemon=True)
        t2 = threading.Thread(target=forward, args=(s2, s1, "Local->Remote"), daemon=True)
        t1.start()
        t2.start()

    def start_local_forwarding(self, local_port, remote_host, remote_port):
        """
        Starts a local TCP listener. 
        On connection, tunnels to Daemon and requests connection to remote_host:remote_port.
        """
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_sock.bind(('0.0.0.0', int(local_port)))
            server_sock.listen(5)
            
            # Store listener
            self.local_listeners[int(local_port)] = server_sock
            
            logging.info(f"Local Proxy Listening on {local_port} -> {remote_host}:{remote_port}")
            
            threading.Thread(target=self._local_listen_loop, args=(server_sock, remote_host, int(remote_port)), daemon=True).start()
            return True, "Listening"
        except Exception as e:
            return False, str(e)

    def _local_listen_loop(self, server_sock, remote_host, remote_port):
        while self.running:
            try:
                client_sock, addr = server_sock.accept()
                logging.info(f"Accepted local connection from {addr}")
                threading.Thread(target=self._handle_local_proxy_conn, args=(client_sock, remote_host, remote_port), daemon=True).start()
            except Exception as e:
                # logging.error(f"Local listener error: {e}")
                # If closed, it will raise exception, which is expected on stop.
                break
        try:
            server_sock.close()
        except:
            pass

    def _handle_local_proxy_conn(self, client_sock, remote_host, remote_port):
        tunnel = None
        try:
            # 1. Open Tunnel to Daemon
            tunnel = self.ssh_manager.open_tunnel('127.0.0.1', DAEMON_PORT)
            
            # 2. Send PROXY_REQUEST
            req = {
                "type": "PROXY_REQUEST",
                "host": remote_host,
                "port": remote_port
            }
            json_bytes = json.dumps(req).encode('utf-8')
            header = struct.pack('>I', len(json_bytes))
            tunnel.sendall(header + json_bytes)
            
            # 3. Read DATA_READY Response
            resp_len_bytes = b''
            while len(resp_len_bytes) < 4:
                c = tunnel.recv(4 - len(resp_len_bytes))
                if not c: raise Exception("Closed during handshake")
                resp_len_bytes += c
            
            resp_len = struct.unpack('>I', resp_len_bytes)[0]
            
            resp_bytes = b''
            while len(resp_bytes) < resp_len:
                c = tunnel.recv(resp_len - len(resp_bytes))
                if not c: raise Exception("Closed during handshake body")
                resp_bytes += c
            
            resp = json.loads(resp_bytes.decode('utf-8'))
            if not resp.get('success'):
                logging.error(f"Proxy Request Failed: {resp.get('message')}")
                client_sock.close()
                tunnel.close()
                return

            # 4. Pipe
            self._pipe_sockets(client_sock, tunnel)
            
        except Exception as e:
            logging.error(f"Local proxy handler error: {e}")
            client_sock.close()
            if tunnel: tunnel.close()
