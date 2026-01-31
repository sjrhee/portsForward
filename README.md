# Ports Forwarding Tool

A secure, daemon-based tool for managing double-hop SSH tunneling (Local -> Gateway -> Target) with an easy-to-use GUI.

## Overview
This tool simplifies the process of connecting to a remote target server that is only accessible via a Gateway (Jump Server). It handles SSH connections, daemon deployment, and port forwarding configuration automatically.

## Key Features
- **Gateway (Jump Server) Support**: Seamless connection through intermediate SSH servers.
- **Double Tunneling**: Securely access target servers hidden behind a private network.
- **Auto-Deployment**: Automatically uploads and runs a lightweight Golang daemon (`port-daemon`) on the remote server.
- **Port Forwarding**: Easy UI to map local ports to remote target ports.
- **Session Management**: Remembers host configurations and last used ports for quick reconnection.
- **Robust Connection**: Includes Heartbeat mechanism and auto-cleanup to prevent zombie processes.

## Architecture
- **Client**: Python (`Tkinter`) GUI application running on Windows.
- **Daemon**: Golang executable running on the Gateway/Target Linux servers.

## Prerequisites
- **Client**: Windows OS, Python 3.x
- **Remote**: Linux Server with SSH access

## Installation & Usage

1.  **Clone the repository**
    ```bash
    git clone https://github.com/sjrhee/portsForward.git
    cd portsForward
    ```

2.  **Run the Application**
    ```bash
    python src/ui.py
    ```

3.  **Step 1: Connect Gateway**
    - Enter the Gateway IP, Port, User, and select your Private Key.
    - Click **Connect Gateway**. The daemon will be deployed automatically.

4.  **Step 2: Connect Target**
    - Enter the Target IP, Port, User, and Key/Password.
    - Click **Connect Target**.

5.  **Step 3: Port Forwarding**
    - Enter the **Remote Port** (on Target) and **Local Port** (on your PC).
    - Click **Add Forward**.
    - You can now access `localhost:<Local Port>` to reach the Target's service.

## License
MIT License
