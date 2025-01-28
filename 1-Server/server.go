package main

import (
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"sync"
)

// Message struct defines the format of messages sent between clients and the server
type Message struct {
	Sender    string `json:"sender"`    // The name of the sender
	Content   string `json:"content"`   // The message content (encrypted or plaintext)
	Timestamp int64  `json:"timestamp"` // Unix timestamp of when the message was sent
	Type      string `json:"type"`      // Type of message: "keyExchange", "message", "keyResponse", "keyRequest"
	PublicKey string `json:"publicKey"` // Public key of the sender (used for key exchange)
	Recipient string `json:"recipient"` // The intended recipient of the message
}

// upgrader is used to upgrade HTTP connections to WebSocket connections
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all connections (insecure for production, refine for security)
	},
}

// Client represents a connected client with their WebSocket connection and other information
type Client struct {
	conn      *websocket.Conn // The WebSocket connection for the client
	publicKey string          // The public key associated with the client
	name      string          // The name of the client
}

// clients stores information about connected clients using a thread-safe map
var clients = struct {
	sync.RWMutex                  // Mutex for safe concurrent access
	m            map[*Client]bool // Map of clients and their connection status
}{
	m: make(map[*Client]bool),
}

// publicKeys stores client names mapped to their public keys
var publicKeys = make(map[string]string)

func main() {
	startServer() // Start the WebSocket server
}

// startServer initializes and starts the WebSocket server
func startServer() {
	http.HandleFunc("/ws", handleConnections) // Define the WebSocket endpoint
	fmt.Println("Server is running on localhost:8089")
	err := http.ListenAndServe(":8089", nil) // Start the server on port 8089
	if err != nil {
		fmt.Println("Server error:", err)
	}
}

// handleConnections handles WebSocket connections from clients
func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP connection to a WebSocket connection
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

	// Create a new client instance and add it to the clients map
	client := &Client{conn: conn}
	clients.Lock()
	clients.m[client] = true
	clients.Unlock()

	// Continuously read messages from the client
	for {
		var msg Message
		err := conn.ReadJSON(&msg) // Read a JSON message from the client
		if err != nil {
			fmt.Println("Error reading message:", err)
			removeClient(client) // Remove the client on error
			break
		}

		// Set the client's name and process the received message
		client.name = msg.Sender
		handleMessages(msg, client)
	}
}

// removeClient removes a client from the list of connected clients
func removeClient(client *Client) {
	clients.Lock()
	delete(clients.m, client) // Remove the client from the map
	clients.Unlock()
	fmt.Printf("Client %s disconnected\n", client.name)
}

// handleMessages handles different types of messages received from clients
func handleMessages(msg Message, client *Client) {
	switch msg.Type {
	case "keyExchange":
		// Store the sender's public key in the publicKeys map
		publicKeys[msg.Sender] = msg.PublicKey
		fmt.Printf("Key exchanged with %s\n", msg.Sender)

	case "message":
		// Forward the message to the intended recipient
		handleMessageForwarding(msg)

	case "keyRequest":
		// Respond to a key request by sending the recipient's public key
		handleKeyRequest(msg, client)
	}
}

// handleMessageForwarding forwards a message to the intended recipient
func handleMessageForwarding(msg Message) {
	// Retrieve the recipient client by their name
	recipient := getClientByName(msg.Recipient)
	if recipient == nil {
		fmt.Printf("Recipient %s not found\n", msg.Recipient)
		return
	}
	// Forward the message to the recipient
	err := recipient.conn.WriteJSON(msg)
	if err != nil {
		fmt.Println("Error forwarding message to recipient:", err)
	}
}

// handleKeyRequest responds to a key request message by sending the requested public key
func handleKeyRequest(msg Message, client *Client) {
	// Check if the requested public key exists
	requestedPublicKey, exists := publicKeys[msg.Recipient]
	if !exists {
		fmt.Printf("Public key not found for recipient: %s\n", msg.Recipient)
		return
	}

	// Construct a key response message and send it to the requester
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
	clients.RLock()         // Acquire read lock for thread-safe access
	defer clients.RUnlock() // Ensure lock is released after function completes

	// Iterate over all connected clients to find the one with the matching name
	for client := range clients.m {
		if client.name == name {
			return client
		}
	}
	return nil // Return nil if no client is found
}
