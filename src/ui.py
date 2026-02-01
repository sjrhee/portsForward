import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import logging
import queue
import os
import json
import time
from ssh_manager import SSHManager
from protocol_handler import DaemonProtocol

class TextHandler(logging.Handler):
    """Refreshes a text widget with log messages."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.configure(state='disabled')
            self.text_widget.see(tk.END)
        self.text_widget.after(0, append)

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Forwarding Client (Jump Host Supported)")
        self.root.geometry("700x850")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.config_file = "config.json"
        self.config = self._load_config()
        self.saved_config = self.config
        
        self.ssh_manager = SSHManager()

        self.protocol = None
        self.forwards = {} # remote_port -> local_port

        # Auto-detect daemon binary
        self.default_daemon_path = self._find_daemon_binary()
        
        self._setup_ui()
        self._setup_logging()

    def _load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
        return {}

    def _save_config(self):
        try:
            # Gather current values
            gw_conf = self._get_ssh_config(self.gw_entries)
            target_conf = self._get_ssh_config(self.target_entries)
            
            # Ensure history structures exist
            if "gateway_history" not in self.config: self.config["gateway_history"] = {}
            if "target_history" not in self.config: self.config["target_history"] = {}

            # Update History
            if gw_conf['host']:
                self.config["gateway_history"][gw_conf['host']] = gw_conf
            if target_conf['host']:
                self.config["target_history"][target_conf['host']] = target_conf

            # Save Current as Last Used
            self.config["gateway"] = gw_conf
            self.config["target"] = target_conf
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

    def _find_daemon_binary(self):
        # Look in known locations
        candidates = [
            os.path.join(os.getcwd(), 'port-daemon'),
            os.path.join(os.path.dirname(os.getcwd()), 'daemon', 'port-daemon'),
            os.path.join(os.getcwd(), 'daemon', 'port-daemon'),
            r"d:\Work\Ports\daemon\port-daemon" # Fallback absolute
        ]
        for p in candidates:
            if os.path.exists(p):
                return os.path.abspath(p)
        return None

    def _setup_ui(self):
        # --- Step 1: Gateway Connection ---
        gw_frame = ttk.LabelFrame(self.root, text="Step 1: Gateway (Jump Host) Connection", padding=10)
        gw_frame.pack(fill="x", padx=10, pady=5)

        gw_defaults = self.config.get("gateway", {
            "host": "192.168.0.101", "port": "10022", "user": "root", "key_file": r"C:\Users\sjrhee\.ssh\id_rsa"
        })
        self.gw_entries = self._create_ssh_form(gw_frame, start_row=0, defaults=gw_defaults, section_key="gateway")
        
        # Gateway Status & Connect Button
        self.gw_status_label = ttk.Label(gw_frame, text="Status: Not Connected", foreground="red")
        self.gw_status_label.grid(row=4, column=0, columnspan=2, sticky="w", pady=5)

        self.gw_connect_btn = ttk.Button(gw_frame, text="Connect Gateway & Deploy", command=self._connect_gateway)
        self.gw_connect_btn.grid(row=4, column=2, columnspan=2, pady=5, sticky="e")
        
        gw_frame.columnconfigure(1, weight=1)

        # --- Step 2: Target Connection ---
        target_frame = ttk.LabelFrame(self.root, text="Step 2: Target Server Connection", padding=10)
        target_frame.pack(fill="x", padx=10, pady=5)

        target_defaults = self.config.get("target", {
            "host": "192.168.0.101", "port": "10022", "user": "root", "key_file": r"C:\Users\sjrhee\.ssh\id_rsa"
        })
        
        # Checkbox for Jump Server Only Mode
        self.use_gateway_as_target = tk.BooleanVar(value=False)
        self.chk_use_gw = ttk.Checkbutton(target_frame, text="Use Gateway as Target (Disable Remote Connection)", 
                                          variable=self.use_gateway_as_target, command=self._toggle_target_mode)
        self.chk_use_gw.grid(row=0, column=0, columnspan=4, sticky="w", padx=5, pady=5)
        
        self.target_entries = self._create_ssh_form(target_frame, start_row=1, defaults=target_defaults, section_key="target")

        # Target Status & Connect Button (Initially Disabled)
        self.target_status_label = ttk.Label(target_frame, text="Status: Waiting for Gateway...", foreground="gray")
        self.target_status_label.grid(row=5, column=0, columnspan=2, sticky="w", pady=5)

        self.target_connect_btn = ttk.Button(target_frame, text="Connect Target (via Gateway)", command=self._connect_target, state="disabled")
        self.target_connect_btn.grid(row=5, column=2, columnspan=2, pady=5, sticky="e")

        target_frame.columnconfigure(1, weight=1)

        # --- Step 3: Forwarding Rules ---
        self.fw_frame = ttk.LabelFrame(self.root, text="Step 3: Port Forwarding Rules", padding=10)
        self.fw_frame.pack(fill="both", expand=True, padx=10, pady=5)
        # (Content added in helper or below)

        # Add Rule Input
        input_frame = ttk.Frame(self.fw_frame)
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="Remote Port:").pack(side="left", padx=5)
        self.remote_port_entry = ttk.Entry(input_frame, width=10)
        self.remote_port_entry.pack(side="left", padx=5)
        
        ttk.Label(input_frame, text="-> Local Port:").pack(side="left", padx=5)
        self.local_port_entry = ttk.Entry(input_frame, width=10)
        self.local_port_entry.pack(side="left", padx=5)
        
        self.add_btn = ttk.Button(input_frame, text="Add Rule", command=self._add_forward, state="disabled")
        self.add_btn.pack(side="left", padx=10)

        # List
        columns = ("remote", "local", "status")
        self.tree = ttk.Treeview(self.fw_frame, columns=columns, show="headings", height=5)
        self.tree.heading("remote", text="Remote Port")
        self.tree.heading("local", text="Local Port")
        self.tree.heading("status", text="Status")
        self.tree.column("remote", width=100)
        self.tree.column("local", width=100)
        self.tree.pack(fill="both", expand=True)

        # Delete Button
        ttk.Button(self.fw_frame, text="Remove Selected", command=self._remove_forward).pack(pady=5)

        # --- Logs ---
        log_frame = ttk.LabelFrame(self.root, text="Logs", padding=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = tk.Text(log_frame, state='disabled', height=6)
        self.log_text.pack(fill="both", expand=True)

    def _create_ssh_form(self, parent, start_row, defaults, section_key):
        entries = {}
        # Host
        ttk.Label(parent, text="Host:").grid(row=start_row, column=0, sticky="w")
        dest_entry = ttk.Entry(parent)
        dest_entry.insert(0, defaults.get("host", ""))
        dest_entry.grid(row=start_row, column=1, padx=5, pady=2, sticky="ew")
        entries["host"] = dest_entry
        
        # Bind FocusOut for History Lookup
        dest_entry.bind("<FocusOut>", lambda e: self._on_host_change(section_key, entries))

        # Port
        ttk.Label(parent, text="Port:").grid(row=start_row, column=2, sticky="w")
        port_entry = ttk.Entry(parent, width=10)
        port_entry.insert(0, defaults.get("port", "22"))
        port_entry.grid(row=start_row, column=3, padx=5, pady=2)
        entries["port"] = port_entry

        # User
        ttk.Label(parent, text="User:").grid(row=start_row+1, column=0, sticky="w")
        user_entry = ttk.Entry(parent)
        user_entry.insert(0, defaults.get("user", "root"))
        user_entry.grid(row=start_row+1, column=1, padx=5, pady=2, sticky="ew")
        entries["user"] = user_entry

        # Auth Type Selection
        auth_type_var = tk.StringVar(value=defaults.get("auth_type", "key"))
        entries["auth_type"] = auth_type_var
        
        # Row 2: Auth Type (Label + RadioButtons)
        ttk.Label(parent, text="Auth Type:").grid(row=start_row+2, column=0, sticky="w")
        
        auth_frame = ttk.Frame(parent)
        auth_frame.grid(row=start_row+2, column=1, columnspan=3, sticky="w", pady=2)
        
        rb_key = ttk.Radiobutton(auth_frame, text="Key File", variable=auth_type_var, value="key")
        rb_key.pack(side="left", padx=5)
        rb_pass = ttk.Radiobutton(auth_frame, text="Password", variable=auth_type_var, value="password")
        rb_pass.pack(side="left", padx=5)

        # Row 3: Dynamic Input (Key or Password)
        # We prepare both widgets but toggle their visibility using grid()
        
        # Key Widgets
        lbl_key = ttk.Label(parent, text="Key File:")
        ent_key = ttk.Entry(parent)
        ent_key.insert(0, defaults.get("key_file", ""))
        entries["key"] = ent_key
        
        def browse():
            f = filedialog.askopenfilename()
            if f:
                ent_key.delete(0, tk.END)
                ent_key.insert(0, f)
        btn_browse = ttk.Button(parent, text="...", width=3, command=browse)

        # Password Widgets
        lbl_pass = ttk.Label(parent, text="Password:")
        ent_pass = ttk.Entry(parent, show="*")
        ent_pass.insert(0, defaults.get("password", ""))
        entries["password"] = ent_pass

        def toggle_auth(*args):
             mode = auth_type_var.get()
             if mode == "key":
                 # Hide Password
                 lbl_pass.grid_remove()
                 ent_pass.grid_remove()
                 
                 # Show Key
                 lbl_key.grid(row=start_row+3, column=0, sticky="w")
                 ent_key.grid(row=start_row+3, column=1, columnspan=2, sticky="ew", padx=5, pady=2)
                 btn_browse.grid(row=start_row+3, column=3)
             else:
                 # Hide Key
                 lbl_key.grid_remove()
                 ent_key.grid_remove()
                 btn_browse.grid_remove()
                 
                 # Show Password
                 lbl_pass.grid(row=start_row+3, column=0, sticky="w")
                 ent_pass.grid(row=start_row+3, column=1, columnspan=3, sticky="ew", padx=5, pady=2)
        
        auth_type_var.trace("w", toggle_auth)
        toggle_auth() # Initial State

        parent.columnconfigure(1, weight=1)
        return entries

    def _on_host_change(self, section_key, entries):
        host = entries["host"].get().strip()
        if not host: return

        history_key = f"{section_key}_history"
        history = self.config.get(history_key, {})
        
        if host in history:
            saved = history[host]
            # Update fields
            if "port" in saved:
                entries["port"].delete(0, tk.END)
                entries["port"].insert(0, saved["port"])
            if "user" in saved:
                entries["user"].delete(0, tk.END)
                entries["user"].insert(0, saved["user"])
            
            auth_type = saved.get("auth_type", "key")
            entries["auth_type"].set(auth_type)
            
            if "key_file" in saved:
                entries["key"].delete(0, tk.END)
                entries["key"].insert(0, saved["key_file"])
            if "password" in saved:
                entries["password"].delete(0, tk.END)
                entries["password"].insert(0, saved["password"])
            
            logging.info(f"Loaded config for {host} in {section_key}")

    def _setup_logging(self):
        handler = TextHandler(self.log_text)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

    def _browse_daemon(self):
        filename = filedialog.askopenfilename(initialdir=".", title="Select Daemon Binary")
        if filename:
            self.daemon_path_entry.delete(0, tk.END)
            self.daemon_path_entry.insert(0, filename)

    def _get_ssh_config(self, entries):
        return {
            "host": entries["host"].get().strip(),
            "port": self._safe_int(entries["port"].get(), 22),
            "user": entries["user"].get().strip(),
            "auth_type": entries["auth_type"].get(),
            "key_file": entries["key"].get().strip(),
            "password": entries["password"].get()
        }

    def _safe_int(self, value, default):
        try:
            return int(value)
        except:
            return default

    def _connect_gateway(self):
        self._save_config() # Auto-save
        gw_conf = self._get_ssh_config(self.gw_entries)
        
        # User requested fully automated deployment. Use detected path.
        deploy_path = self.default_daemon_path
        
        if not deploy_path or not os.path.exists(deploy_path):
             messagebox.showerror("Error", "Daemon binary not found. Cannot deploy.")
             return

        # Disable inputs during connection attempt
        self._set_inputs_state(self.gw_entries, "disabled")
        
        threading.Thread(target=self._thread_connect_gateway, args=(gw_conf, deploy_path), daemon=True).start()
        self.gw_status_label.configure(text="Status: Connecting...", foreground="orange")
        self.gw_connect_btn.configure(state="disabled")

    def _disconnect_gateway_action(self):
        # Run disconnect in a thread to avoid UI freeze
        threading.Thread(target=self._thread_disconnect_gateway).start()

    def _thread_disconnect_gateway(self):
        # Just disconnect locally. Daemon will self-terminate on timeout.
        if self.ssh_manager:
             self.ssh_manager.disconnect()
        if self.protocol:
            self.protocol._handle_disconnect()
        
        self.root.after(0, self._reset_ui)
        # Ensure inputs are enabled after disconnect
        self.root.after(0, lambda: self._update_gw_status("Disconnected", "red"))

    def _on_close(self):
        try:
            if self.ssh_manager and self.ssh_manager.connected:
                self.ssh_manager.disconnect()
        except:
            pass
        self.root.destroy()
        os._exit(0)
        
    def _start_heartbeat(self):
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def _heartbeat_loop(self):
        logging.info("Heartbeat loop started.")
        while self.ssh_manager and self.ssh_manager.connected and self.protocol:
            try:
                # logging.debug("Sending Heartbeat...")
                self.protocol.send_request({"type": "HEARTBEAT"})
            except Exception:
                break
            time.sleep(60)

    def _thread_connect_gateway(self, gw_conf, deploy_path):
        try:
            logging.info("Connecting to Gateway...")
            success = self.ssh_manager.connect_gateway_only(gw_conf)
            if not success:
               self.root.after(0, lambda: self._update_gw_status("Connection Failed", "red"))
               return

            logging.info("Deploying Daemon to Gateway...")
            if not self.ssh_manager.deploy_and_run(deploy_path):
                self.root.after(0, lambda: self._update_gw_status("Deployment Failed", "red"))
                self.ssh_manager.disconnect()
                return

            logging.info("Establishing Control Session...")
            self.protocol = DaemonProtocol(self.ssh_manager, self._protocol_callback)
            if not self.protocol.start_control_session():
                 self.root.after(0, lambda: self._update_gw_status("Control Session Failed", "red"))
                 self.ssh_manager.disconnect()
                 return
            
            self._start_heartbeat()
            self.root.after(0, lambda: self._update_gw_status("Connected", "green"))
            self.root.after(0, self._enable_target_step)

        except Exception as e:
            logging.error(f"Gateway Error: {e}")
            self.root.after(0, lambda: self._update_gw_status(f"Error: {e}", "red"))

    def _update_gw_status(self, text, color):
        self.gw_status_label.configure(text=f"Status: {text}", foreground=color)
        self.gw_connect_btn.configure(state="normal")
        
        if color == "green":
            self.gw_connect_btn.configure(text="Disconnect Gateway", command=self._disconnect_gateway_action)
            self._set_inputs_state(self.gw_entries, "disabled")
        else:
            self.gw_connect_btn.configure(text="Connect Gateway & Deploy", command=self._connect_gateway)
            self._set_inputs_state(self.gw_entries, "normal")

    def _set_inputs_state(self, entries, state):
        for key, widget in entries.items():
            if isinstance(widget, ttk.Entry):
                widget.configure(state=state)
            if isinstance(widget, tk.StringVar): # Radiobutton var, skip
                pass
            # Handle hidden password/key entries manually if needed, 
            # but looping through 'entries' dict might catch them if they are in there.
            # My _create_ssh_form puts 'key' and 'password' entries in dict.
            
    def _enable_target_step(self):
        self.target_connect_btn.configure(state="normal", text="Connect Target (via Gateway)")
        self.target_status_label.configure(text="Status: Ready to Connect", foreground="black")
        self._set_inputs_state(self.target_entries, "normal")

    def _connect_target(self):
        try:
            self._save_config() # Auto-save
            target_conf = self._get_ssh_config(self.target_entries)
            
            # Jump Server Only Mode
            if self.use_gateway_as_target.get() or not target_conf['host']:
                logging.info("Jump Server Only Mode Selected.")
                self.current_target_conf = target_conf
                self.root.after(0, lambda: self._update_target_status("Connected (Jump Host)", "green"))
                self.root.after(0, self._enable_forwarding_step)
                return
            
            # Load saved extras (Process ID 7)
            if target_conf['host'] in self.saved_config:
                saved = self.saved_config[target_conf['host']]
                target_conf['last_remote_port'] = saved.get('last_remote_port')
                target_conf['last_local_port'] = saved.get('last_local_port')
    
            self.current_target_conf = target_conf
            
            # Prepare Payload based on Auth Type
            payload = {
                "type": "CONNECT_TARGET",
                "host": target_conf['host'],
                "port": target_conf['port'],
                "user": target_conf['user'],
                "auth_type": target_conf.get('auth_type', 'key')
            }
    
            if payload["auth_type"] == "key":
                try:
                    with open(target_conf['key_file'], 'r') as f:
                        key_content = f.read()
                    payload["key"] = key_content
                except Exception as e:
                    messagebox.showerror("Key Error", f"Failed to read key file: {e}")
                    return
            else:
                 payload["password"] = target_conf.get("password")
    
            self.target_status_label.configure(text="Status: Connecting...", foreground="orange")
            self.target_connect_btn.configure(state="disabled")
            self._set_inputs_state(self.target_entries, "disabled")
            
            threading.Thread(target=self._thread_connect_target, args=(payload,), daemon=True).start()
            
        except Exception as e:
             logging.error(f"Connect Target Error: {e}")
             messagebox.showerror("Connection Error", f"An error occurred: {e}")

    def _disconnect_target_action(self):
        # Notify Gateway to disconnect target
        if self.protocol:
            logging.info("Sending DISCONNECT_TARGET...")
            self.protocol.send_request({"type": "DISCONNECT_TARGET"})
            time.sleep(0.2) # Optional wait

        self._update_target_status("Disconnected", "gray")
        # Step 3 (Forwarding) should probably be cleared too?
        # self.forwards.clear() ...
        logging.info("Target Disconnected (UI Reset)")

    def _thread_connect_target(self, payload):
        response_queue = queue.Queue()
        self.protocol.add_response_listener('CONNECT_TARGET_RESPONSE', response_queue)
        self.protocol.send_request(payload)
        
        try:
            resp = response_queue.get(timeout=30)
            if resp.get('success'):
                 self.root.after(0, lambda: self._update_target_status("Connected", "green"))
                 self.root.after(0, self._enable_forwarding_step)
            else:
                 msg = resp.get('message', 'Unknown Error')
                 self.root.after(0, lambda: self._update_target_status(f"Failed: {msg}", "red"))
        except queue.Empty:
            self.root.after(0, lambda: self._update_target_status("Timeout", "red"))

    def _update_target_status(self, text, color):
        self.target_status_label.configure(text=f"Status: {text}", foreground=color)
        self.target_connect_btn.configure(state="normal")
        
        # Hide button if in Jump Server Only Mode
        if self.use_gateway_as_target.get():
             self.target_connect_btn.grid_remove()
        else:
             self.target_connect_btn.grid()
        
        if color == "green":
             self.target_connect_btn.configure(text="Disconnect Target", command=self._disconnect_target_action)
             self._set_inputs_state(self.target_entries, "disabled")
        else:
             self.target_connect_btn.configure(text="Connect Target (via Gateway)", command=self._connect_target)
             self._set_inputs_state(self.target_entries, "normal")

    def _toggle_target_mode(self):
        is_jump_mode = self.use_gateway_as_target.get()
        state = "disabled" if is_jump_mode else "normal"
        self._set_inputs_state(self.target_entries, state)
        
        if is_jump_mode:
             # Auto-Connect
             self.target_status_label.configure(text="Status: Jump Server Mode Selected", foreground="blue")
             self.target_connect_btn.grid_remove() # Hide immediately
             if self.ssh_manager and self.ssh_manager.connected:
                 self._connect_target() 
        else:
             # Auto-Disconnect (Restore Normal Mode)
             self._disconnect_target_action()
             self.target_status_label.configure(text="Status: Ready to Connect", foreground="black")
             self.target_connect_btn.grid() # Show button

    def _enable_forwarding_step(self):
        self.add_btn.configure(state="normal")
        # Load Last Used Ports
        if hasattr(self, 'current_target_conf'):
            last_remote = self.current_target_conf.get('last_remote_port')
            last_local = self.current_target_conf.get('last_local_port')
            
            if last_remote:
                self.remote_port_entry.delete(0, tk.END)
                self.remote_port_entry.insert(0, str(last_remote))
            if last_local:
                self.local_port_entry.delete(0, tk.END)
                self.local_port_entry.insert(0, str(last_local))

        logging.info("Ready to forward ports.")

    def _disconnect(self):
        self.ssh_manager.disconnect()
        if self.protocol:
            self.protocol._handle_disconnect()
        self.root.after(0, self._reset_ui)

    def _reset_ui(self):
        # Reset Step 1
        self.gw_connect_btn.configure(state="normal", text="Connect Gateway & Deploy")
        self.gw_status_label.configure(text="Status: Not Connected", foreground="red")
        
        # Reset Step 2
        self.target_connect_btn.configure(state="disabled")
        self.target_status_label.configure(text="Status: Waiting for Gateway...", foreground="gray")
        
        # Reset Step 3
        self.add_btn.configure(state="disabled")
        for item in self.tree.get_children():
            self.tree.set(item, "status", "Disconnected")



    def _protocol_callback(self, event, arg=None):
        if event == 'GET_LOCAL_PORT':
            return self.forwards.get(str(arg)) or self.forwards.get(int(arg))
        
        if isinstance(event, dict):
            msg_type = event.get('type')
            if msg_type == 'FORWARD_RESPONSE':
                req_id = event.get('request_id')
                success = event.get('success')
                msg = event.get('message')
                self.root.after(0, lambda: self._update_forward_status(req_id, success, msg))

    def _update_forward_status(self, req_id, success, msg):
        status = "Active" if success else f"Failed: {msg}"
        logging.info(f"Forward Result: {status}")

    def _add_forward(self):
        try:
            r_port = int(self.remote_port_entry.get())
            l_port = int(self.local_port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Ports must be numbers")
            return

        self.forwards[r_port] = l_port
        # Local Port Forwarding: Start Local Listener -> Tunnel -> Daemon -> Remote Target
        success, msg = self.protocol.start_local_forwarding(l_port, "127.0.0.1", r_port)
        
        if success:
            self.tree.insert("", "end", values=(r_port, l_port, "Active"))
            
            # Save Last Used Ports
            if hasattr(self, 'current_target_conf') and self.current_target_conf:
                self.current_target_conf['last_remote_port'] = r_port
                self.current_target_conf['last_local_port'] = l_port
                
                host = self.current_target_conf.get('host')
                if host:
                    if host not in self.saved_config: self.saved_config[host] = {}
                    self.saved_config[host]['last_remote_port'] = r_port
                    self.saved_config[host]['last_local_port'] = l_port
                    try:
                        with open("config.json", 'w') as f:
                            json.dump(self.saved_config, f, indent=4)
                    except Exception as e:
                        logging.warning(f"Failed to save port config: {e}")

            self.remote_port_entry.delete(0, tk.END)
            self.local_port_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", f"Failed to start local listener: {msg}")

    def _remove_forward(self):
        selected_item = self.tree.selection()
        if not selected_item: return
        
        for item in selected_item:
            vals = self.tree.item(item)['values']
            r_port = int(vals[0])
            l_port = int(vals[1])
            
            # Stop listener
            if self.protocol:
                self.protocol.stop_local_forwarding(l_port)

            if r_port in self.forwards:
                del self.forwards[r_port]
            self.tree.delete(item)
