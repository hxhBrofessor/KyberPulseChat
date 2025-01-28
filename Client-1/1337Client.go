package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/acheong08/crystallize/security"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Message struct defines the format of messages sent between clients and the server
type Message struct {
	Sender    string `json:"sender"`    // The name of the sender
	Content   string `json:"content"`   // The encrypted or plain content of the message
	Timestamp int64  `json:"timestamp"` // Unix timestamp of when the message was sent
	Type      string `json:"type"`      // Message type: "keyExchange", "message", "keyResponse", "keyRequest"
	PublicKey string `json:"publicKey"` // The sender's public key (used for key exchange)
	Recipient string `json:"recipient"` // The intended recipient of the message
}

// otherPublicKeys stores public keys of other clients
var (
	otherPublicKeys = make(map[string]string) // Map to store other clients' public keys
	keyMutex        = sync.Mutex{}            // Mutex for thread-safe access to the public key map
)

func main() {
	// Generate public and private keys for the client named "bryan"
	pubKey, privKey := security.GenerateKyber()
	// Start the client with the generated keys
	startClient("bryan", "localhost:8089", pubKey, privKey)
}

// startClient establishes a WebSocket connection, performs key exchange, and handles message sending/receiving
func startClient(sender, serverAddr string, pubKey, privKey []byte) {
	// Establish a WebSocket connection to the server
	conn, _, err := websocket.DefaultDialer.Dial("ws://"+serverAddr+"/ws", nil)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer func(conn *websocket.Conn) {
		// Close the connection when the function exits
		err := conn.Close()
		if err != nil {
			fmt.Println("Error closing connection:", err)
		}
	}(conn)

	// Send a key exchange message to the server to share the client's public key
	keyExchangeMsg := Message{
		Sender:    sender,
		PublicKey: base64.StdEncoding.EncodeToString(pubKey), // Encode the public key to base64
		Type:      "keyExchange",
	}
	err = conn.WriteJSON(keyExchangeMsg) // Send the key exchange message as JSON
	if err != nil {
		fmt.Println("Error sending key exchange message:", err)
		return
	}

	// Start a goroutine to handle incoming messages
	go handleIncomingMessages(conn, privKey)

	reader := bufio.NewReader(os.Stdin) // Use stdin to read user input
	for {
		// Prompt the user for the recipient's name
		fmt.Print("Enter recipient's name: ")
		recipient, _ := reader.ReadString('\n')
		recipient = strings.TrimSpace(recipient)

		// Request the public key of the recipient from the server
		requestPublicKey(conn, sender, recipient)
		waitForPublicKey(recipient) // Wait until the recipient's public key is available

		// Prompt the user for the message content
		fmt.Print("Enter your message: ")
		messageContent, _ := reader.ReadString('\n')
		messageContent = strings.TrimSpace(messageContent)

		// Encrypt and send the message to the recipient
		sendMessage(conn, sender, recipient, messageContent)
	}
}

// waitForPublicKey waits until the public key of the recipient is available
func waitForPublicKey(recipient string) {
	fmt.Printf("Waiting for public key of %s\n", recipient)
	for {
		keyMutex.Lock()
		_, exists := otherPublicKeys[recipient]
		keyMutex.Unlock()

		if exists {
			break // Exit the loop when the key is available
		}

		time.Sleep(100 * time.Millisecond) // Wait briefly before checking again
	}
}

// handleIncomingMessages handles incoming messages from the server
func handleIncomingMessages(conn *websocket.Conn, privKey []byte) {
	for {
		var receivedMessage Message
		// Read a JSON message from the server
		err := conn.ReadJSON(&receivedMessage)
		if err != nil {
			fmt.Println("Error reading message:", err)
			break
		}

		// Handle the received message based on its type
		switch receivedMessage.Type {
		case "keyResponse":
			handlePublicKeyResponse(receivedMessage)

		case "message":
			// Decode the base64-encoded message content
			decodedMessage, err := base64.StdEncoding.DecodeString(receivedMessage.Content)
			if err != nil {
				fmt.Println("Failed to decode message:", err)
				continue
			}

			// Decrypt the message using the private key
			decryptedMessage := security.Decrypt(privKey, string(decodedMessage))
			if decryptedMessage == "" {
				fmt.Println("Failed to decrypt message or message is empty")
				continue
			}

			// Display the decrypted message to the user
			fmt.Printf("\rReceived message from %s: %s\n", receivedMessage.Sender, decryptedMessage)
			fmt.Print("Enter a message: ")
		}
	}
}

// sendMessage encrypts and sends a message to the recipient
func sendMessage(conn *websocket.Conn, sender, recipient, content string) {
	keyMutex.Lock()
	recipientPublicKeyEncoded, exists := otherPublicKeys[recipient] // Get the recipient's public key
	keyMutex.Unlock()

	if !exists {
		fmt.Println("Public key for recipient not found")
		return
	}

	// Decode the recipient's public key from base64
	recipientPublicKey, err := base64.StdEncoding.DecodeString(recipientPublicKeyEncoded)
	if err != nil {
		fmt.Println("Error decoding public key:", err)
		return
	}

	// Encrypt the message using the recipient's public key
	encryptedMessage := security.Encrypt(recipientPublicKey, content)
	// Encode the encrypted message to base64 for transmission
	encodedMessage := base64.StdEncoding.EncodeToString([]byte(encryptedMessage))

	// Construct the message struct
	message := Message{
		Sender:    sender,
		Content:   encodedMessage,
		Timestamp: time.Now().Unix(),
		Recipient: recipient,
		Type:      "message",
	}

	// Send the message to the server
	err = conn.WriteJSON(message)
	if err != nil {
		fmt.Println("Error sending message:", err)
	}
}

// requestPublicKey sends a public key request message to the server
func requestPublicKey(conn *websocket.Conn, sender, recipient string) {
	keyRequestMsg := Message{
		Sender:    sender,
		Recipient: recipient,
		Type:      "keyRequest",
	}

	err := conn.WriteJSON(keyRequestMsg)
	if err != nil {
		fmt.Println("Error sending public key request:", err)
	}
}

// handlePublicKeyResponse processes a public key response message from the server
func handlePublicKeyResponse(msg Message) {
	keyMutex.Lock()
	// Store the received public key in the map
	otherPublicKeys[msg.Sender] = msg.PublicKey
	keyMutex.Unlock()
	fmt.Printf("Received and stored public key from %s: %s\n", msg.Sender, msg.PublicKey)
}
