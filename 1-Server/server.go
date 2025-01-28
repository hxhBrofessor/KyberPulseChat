package main

import (
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"sync"
)

// Message struct defines the format of messages sent between clients and the server
type Message struct {
	Sender    string `json:"sender"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
	Type      string `json:"type"` // Types: "keyExchange", "message", "keyResponse", "keyRequest"
	PublicKey string `json:"publicKey"`
	Recipient string `json:"recipient"`
}

// upgrader is used to upgrade HTTP connections to WebSocket connections
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all connections
	},
}

// Client represents a connected client with their WebSocket connection and other information
type Client struct {
	conn      *websocket.Conn
	publicKey string
	name      string
}

// clients stores information about connected clients
var clients = struct {
	sync.RWMutex
	m map[*Client]bool
}{
	m: make(map[*Client]bool),
}

// publicKeys stores client names mapped to their public keys
var publicKeys = make(map[string]string)

func main() {
	startServer()
}

// startServer initializes and starts the WebSocket server
func startServer() {
	http.HandleFunc("/ws", handleConnections)
	fmt.Println("Server is running on localhost:8089")
	err := http.ListenAndServe(":8089", nil)
	if err != nil {
		fmt.Println("Server error:", err)
	}
}

// handleConnections handles WebSocket connections from clients
func handleConnections(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading connection:", err)
		return
	}
	defer func(conn *websocket.Conn) {
		err := conn.Close()
		if err != nil {
			// Handle any errors when closing the connection
		}
	}(conn)

	client := &Client{conn: conn}
	clients.Lock()
	clients.m[client] = true
	clients.Unlock()

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			fmt.Println("Error reading message:", err)
			removeClient(client)
			break
		}

		client.name = msg.Sender
		handleMessages(msg, client)
	}
}

// removeClient removes a client from the list of connected clients
func removeClient(client *Client) {
	clients.Lock()
	delete(clients.m, client)
	clients.Unlock()
	fmt.Printf("Client %s disconnected\n", client.name)
}

// handleMessages handles different types of messages received from clients
func handleMessages(msg Message, client *Client) {
	switch msg.Type {
	case "keyExchange":
		publicKeys[msg.Sender] = msg.PublicKey
		fmt.Printf("Key exchanged with %s\n", msg.Sender)

	case "message":
		handleMessageForwarding(msg)

	case "keyRequest":
		handleKeyRequest(msg, client)
	}
}

// handleMessageForwarding forwards a message to the intended recipient
func handleMessageForwarding(msg Message) {
	recipient := getClientByName(msg.Recipient)
	if recipient == nil {
		fmt.Printf("Recipient %s not found\n", msg.Recipient)
		return
	}
	err := recipient.conn.WriteJSON(msg)
	if err != nil {
		fmt.Println("Error forwarding message to recipient:", err)
	}
}

// handleKeyRequest responds to a key request message by sending the requested public key
func handleKeyRequest(msg Message, client *Client) {
	requestedPublicKey, exists := publicKeys[msg.Recipient]
	if !exists {
		fmt.Printf("Public key not found for recipient: %s\n", msg.Recipient)
		return
	}

	keyResponseMsg := Message{
		Sender:    msg.Recipient,
		PublicKey: requestedPublicKey,
		Type:      "keyResponse",
		Recipient: msg.Sender,
	}

	err := client.conn.WriteJSON(keyResponseMsg)
	if err != nil {
		fmt.Println("Error sending public key response:", err)
	}
}

// getClientByName retrieves a client by their name
func getClientByName(name string) *Client {
	clients.RLock()
	defer clients.RUnlock()

	for client := range clients.m {
		if client.name == name {
			return client
		}
	}
	return nil
}
