package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	ControlPort = 15432
)

// Protocol Messages
type Message struct {
	Type         string `json:"type"`
	RequestID    string `json:"request_id,omitempty"`
	RemotePort   int    `json:"remote_port,omitempty"`
	Success      bool   `json:"success,omitempty"`
	MessageStr   string `json:"message,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`

	// For CONNECT_TARGET
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Key      string `json:"key,omitempty"` // Helper: Private Key Content
	Password string `json:"password,omitempty"`
}

// Global State
var (
	controlConn net.Conn
	controlLock sync.Mutex
	pendingMap  = make(map[string]net.Conn)
	pendingLock sync.Mutex

	// Target Tunnel
	targetSSHClient *ssh.Client
	targetSession   *ssh.Session // Keep session alive for daemon process
	targetConn      net.Conn     // To Target Daemon
)

func main() {
	// Setup Logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting Port Daemon on 127.0.0.1:15432")

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ControlPort))
	if err != nil {
		log.Fatalf("Failed to bind control port: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handleIncoming(conn)
	}
}

func handleIncoming(conn net.Conn) {
	// Read first message
	header := make([]byte, 4)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		conn.Close()
		return
	}

	length := binary.BigEndian.Uint32(header)
	payload := make([]byte, length)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		conn.Close()
		return
	}

	var msg Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		log.Printf("Invalid JSON: %v", err)
		conn.Close()
		return
	}

	if msg.Type == "CONNECT_DATA" {
		handleDataHandshake(conn, msg)
	} else if msg.Type == "PROXY_REQUEST" {
		handleProxyHandshake(conn, msg)
	} else {
		// Control Connection
		controlLock.Lock()
		if controlConn != nil {
			controlConn.Close()
		}
		controlConn = conn
		controlLock.Unlock()

		log.Println("Control connection established")

		processControlMessage(msg)
		controlLoop(conn)
	}
}

func controlLoop(conn net.Conn) {
	defer conn.Close()
	for {
		// Set heartbeat timeout
		conn.SetReadDeadline(time.Now().Add(180 * time.Second))

		header := make([]byte, 4)
		_, err := io.ReadFull(conn, header)
		if err != nil {
			break
		}
		length := binary.BigEndian.Uint32(header)
		payload := make([]byte, length)
		_, err = io.ReadFull(conn, payload)
		if err != nil {
			break
		}

		var msg Message
		json.Unmarshal(payload, &msg)
		processControlMessage(msg)
	}
	log.Println("[EXIT] Control connection closed or timed out. Exiting Daemon.")
	shutdownTarget()
	os.Exit(0)
}

func shutdownTarget() {
	if targetConn != nil {
		log.Println("Sending SHUTDOWN signal to Target Daemon before exiting...")
		sendJSON(targetConn, Message{Type: "SHUTDOWN"})
		time.Sleep(200 * time.Millisecond) // Give time for message to be sent
	}
}

func processControlMessage(msg Message) {
	switch msg.Type {
	case "FORWARD_REQUEST":
		if targetConn != nil {
			// Forward to Target Daemon
			log.Printf("Forwarding FORWARD_REQUEST to Target Daemon...")
			sendJSON(targetConn, msg)
		} else {
			log.Printf("Received FORWARD_REQUEST for port %d", msg.RemotePort)
			go startForwarding(msg.RemotePort, msg.RequestID)
		}

	case "CONNECT_TARGET":
		log.Printf("Received CONNECT_TARGET request to %s", msg.Host)
		go handleConnectTarget(msg)

	case "HEARTBEAT":
		log.Println("[HEARTBEAT] Received")
		if targetConn != nil {
			sendJSON(targetConn, msg)
		}
		// Heartbeat received, connection is alive.
		// ReadDeadline is reset in controlLoop.

	case "DISCONNECT_TARGET":
		log.Println("Received DISCONNECT_TARGET request.")
		if targetConn != nil {
			log.Println("Sending SHUTDOWN signal to Target Daemon...")
			sendJSON(targetConn, Message{Type: "SHUTDOWN"})
			time.Sleep(200 * time.Millisecond)
		}

		if targetSSHClient != nil {
			targetSSHClient.Close()
			targetSSHClient = nil
			targetConn = nil
			log.Println("Target SSH connection closed.")
		}

	case "SHUTDOWN":
		log.Println("[SHUTDOWN] Received signal. Exiting.")
		shutdownTarget()
		os.Exit(0)

	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
}

func sendControlMessage(msg Message) {
	controlLock.Lock()
	defer controlLock.Unlock()

	if controlConn == nil {
		return
	}
	sendJSON(controlConn, msg)
}

func startForwarding(port int, reqID string) {
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		sendControlMessage(Message{
			Type: "FORWARD_RESPONSE", RequestID: reqID, Success: false, MessageStr: err.Error(),
		})
		return
	}

	sendControlMessage(Message{
		Type: "FORWARD_RESPONSE", RequestID: reqID, Success: true, MessageStr: fmt.Sprintf("Listening on %d", port),
	})

	for {
		clientConn, err := l.Accept()
		if err != nil {
			break
		}
		go handleUserConnection(clientConn, port)
	}
}

func handleUserConnection(conn net.Conn, port int) {
	connID := uuid.New().String()

	pendingLock.Lock()
	pendingMap[connID] = conn
	pendingLock.Unlock()

	sendControlMessage(Message{
		Type: "NEW_CONNECTION", ConnectionID: connID, RemotePort: port,
	})

	time.AfterFunc(10*time.Second, func() {
		pendingLock.Lock()
		if c, ok := pendingMap[connID]; ok {
			c.Close()
			delete(pendingMap, connID)
			log.Printf("Connection %s timed out waiting for handshake", connID)
		}
		pendingLock.Unlock()
	})
}

func handleDataHandshake(tunnelConn net.Conn, msg Message) {
	connID := msg.ConnectionID

	pendingLock.Lock()
	userConn, ok := pendingMap[connID]
	if ok {
		delete(pendingMap, connID)
	}
	pendingLock.Unlock()

	if ok {
		// This is a direct connection case (Daemon on Endpoint)
		sendJSON(tunnelConn, Message{Type: "DATA_READY", Success: true})
		log.Printf("Tunnel established for %s", connID)
		go pipe(tunnelConn, userConn)
		pipe(userConn, tunnelConn)
		return
	}

	// Maybe it's a relayed connection?
	if targetConn != nil {
		// Proxying CONNECT_DATA for %s to Target...
		log.Printf("Proxying CONNECT_DATA for %s to Target...", connID)

		targetDataConn, err := targetSSHClient.Dial("tcp", "127.0.0.1:15432")
		if err != nil {
			log.Printf("Failed to dial Target Daemon for data: %v", err)
			tunnelConn.Close()
			return
		}

		// Send CONNECT_DATA to Target
		sendJSON(targetDataConn, msg)

		go pipe(tunnelConn, targetDataConn)
		pipe(targetDataConn, tunnelConn)
		return
	}

	// If not found and not relaying, error
	tunnelConn.Close()
}

func handleProxyHandshake(tunnelConn net.Conn, msg Message) {
	// Outbound Connection Request (Local -> Remote)

	if targetConn != nil {
		// Relay to Target Daemon
		log.Printf("Relaying PROXY_REQUEST to %s:%d via Target Daemon", msg.Host, msg.Port)

		targetDataConn, err := targetSSHClient.Dial("tcp", "127.0.0.1:15432")
		if err != nil {
			log.Printf("Failed to dial Target Daemon for proxy: %v", err)
			sendJSON(tunnelConn, Message{Type: "DATA_READY", Success: false, MessageStr: "Failed to dial Target Daemon"})
			tunnelConn.Close()
			return
		}

		log.Printf("Dialed Target Daemon. Sending PROXY_REQUEST...")
		sendJSON(targetDataConn, msg)

		go pipe(tunnelConn, targetDataConn)
		pipe(targetDataConn, tunnelConn)
		return
	}

	// End Node: Dial Actual Target
	addr := fmt.Sprintf("%s:%d", msg.Host, msg.Port)
	log.Printf("Dialing Outbound: %s", addr)

	destConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to dial outbound %s: %v", addr, err)
		sendJSON(tunnelConn, Message{Type: "DATA_READY", Success: false, MessageStr: err.Error()})
		tunnelConn.Close()
		return
	}

	sendJSON(tunnelConn, Message{Type: "DATA_READY", Success: true})

	go pipe(tunnelConn, destConn)
	pipe(destConn, tunnelConn)
}

func handleConnectTarget(msg Message) {
	success := false
	defer func() {
		if !success {
			sendControlMessage(Message{
				Type: "CONNECT_TARGET_RESPONSE", Success: false, MessageStr: "Failed to connect/deploy",
			})
		}
	}()

	// Close existing connection if any
	if targetSSHClient != nil {
		log.Println("Closing existing target connection before reconnecting...")
		targetSSHClient.Close()
		targetSSHClient = nil
		targetConn = nil
	}

	var authMethods []ssh.AuthMethod
	if msg.Password != "" {
		authMethods = []ssh.AuthMethod{
			ssh.Password(msg.Password),
		}
	} else {
		signer, err := ssh.ParsePrivateKey([]byte(msg.Key))
		if err != nil {
			log.Printf("Key parse error: %v", err)
			return
		}
		authMethods = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	}

	config := &ssh.ClientConfig{
		User: msg.User,
		Auth: authMethods,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			log.Printf("[SSH] Automatically accepting host key for %s (%s)", hostname, remote)
			return nil
		},
		Timeout: 10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", msg.Host, msg.Port)
	log.Printf("Connecting to Target SSH %s...", addr)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Printf("SSH Dial error: %v", err)
		return
	}

	// Kill existing daemon on Target to avoid "bind: address already in use"
	killSession, err := client.NewSession()
	if err == nil {
		killSession.Run("pkill -f port-daemon")
		killSession.Close()
	}

	// Deploy Self
	if err := deploySelf(client); err != nil {
		log.Printf("Deploy error: %v", err)
		client.Close()
		return
	}

	// Run Daemon
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return
	}
	targetSession = session

	// Start in foreground (goroutine) so checking session remains active.
	go func() {
		// Log to file for debugging
		if err := session.Run("~/.ports/port-daemon > ~/.ports/target.log 2>&1"); err != nil {
			log.Printf("Daemon session ended: %v", err)
		}
	}()
	time.Sleep(1 * time.Second) // Wait for start

	// Connect to Target Daemon via Tunnel
	log.Println("Dialing Target Daemon 127.0.0.1:15432 via SSH...")
	daemonConn, err := client.Dial("tcp", "127.0.0.1:15432")
	if err != nil {
		log.Printf("Daemon Dial error: %v", err)
		client.Close()
		return
	}

	targetSSHClient = client
	targetConn = daemonConn
	success = true

	log.Println("Connected to Target Daemon. Proxy Mode Engaged.")

	// Notify Client of Success
	sendControlMessage(Message{Type: "CONNECT_TARGET_RESPONSE", Success: true})

	// Forward from Target to Client
	go func() {
		defer targetConn.Close()
		for {
			header := make([]byte, 4)
			_, err := io.ReadFull(targetConn, header)
			if err != nil {
				break
			}
			length := binary.BigEndian.Uint32(header)
			payload := make([]byte, length)
			_, err = io.ReadFull(targetConn, payload)
			if err != nil {
				break
			}

			// Forward raw
			controlLock.Lock()
			if controlConn != nil {
				controlConn.Write(header)
				controlConn.Write(payload)
			}
			controlLock.Unlock()
		}
		log.Println("Target Control Connection Closed")
	}()

}

func deploySelf(client *ssh.Client) error {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	// Create dir
	sftpClient.Mkdir(".ports")

	remotePath := ".ports/port-daemon"
	localPath, err := os.Executable()
	if err != nil {
		return err
	}

	// Force upload (removed stat check)

	srcFile, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := sftpClient.Create(remotePath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return sftpClient.Chmod(remotePath, 0755)
}

func sendJSON(conn net.Conn, msg Message) {
	data, _ := json.Marshal(msg)
	length := uint32(len(data))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)
	conn.Write(header)
	conn.Write(data)
}

func pipe(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	io.Copy(dst, src)
}
