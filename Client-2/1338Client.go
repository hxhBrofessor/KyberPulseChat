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
	Sender    string `json:"sender"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
	Type      string `json:"type"` // Types: "keyExchange", "message", "keyResponse", "keyRequest"
	PublicKey string `json:"publicKey"`
	Recipient string `json:"recipient"`
}

// otherPublicKeys stores public keys of other clients
var (
	otherPublicKeys = make(map[string]string) // Map to store other clients' public keys
	keyMutex        = sync.Mutex{}
)

func main() {
	// Generate public and private keys for the client named "gojo"
	pubKey, privKey := security.GenerateKyber()
	// Start the client with the generated keys
	startClient("gojo", "localhost:8089", pubKey, privKey)
}

// startClient establishes a WebSocket connection, performs key exchange, and handles message sending and receiving
func startClient(sender, serverAddr string, pubKey, privKey []byte) {
	// Establish a WebSocket connection to the server
	conn, _, err := websocket.DefaultDialer.Dial("ws://"+serverAddr+"/ws", nil)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer func(conn *websocket.Conn) {
		err := conn.Close()
		if err != nil {
			// Handle any errors when closing the connection
		}
	}(conn)

	// Send a key exchange message to the server to share the client's public key
	keyExchangeMsg := Message{
		Sender:    sender,
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
		Type:      "keyExchange",
	}
	err = conn.WriteJSON(keyExchangeMsg)
	if err != nil {
		fmt.Println("Error sending key exchange message:", err)
		return
	}

	reader := bufio.NewReader(os.Stdin)
	go handleIncomingMessages(conn, privKey)

	for {
		// Read recipient's name from the console
		fmt.Print("Enter recipient's name: ")
		recipient, _ := reader.ReadString('\n')
		recipient = strings.TrimSpace(recipient)

		// Request public key of recipient and wait for response
		requestPublicKey(conn, sender, recipient)
		waitForPublicKey(recipient)

		// Read the message from the console
		fmt.Print("Enter your message: ")
		messageContent, _ := reader.ReadString('\n')
		messageContent = strings.TrimSpace(messageContent)

		// Send the encrypted message to the recipient
		sendMessage(conn, sender, recipient, messageContent)
	}
}

// waitForPublicKey waits for the public key of the recipient to become available
func waitForPublicKey(recipient string) {
	fmt.Printf("Waiting for public key of %s\n", recipient)
	for {
		keyMutex.Lock()
		_, exists := otherPublicKeys[recipient]
		keyMutex.Unlock()

		if exists {
			break
		}

		time.Sleep(100 * time.Millisecond) // Wait for a short duration before checking again
	}
}

// handleIncomingMessages handles incoming messages from the server, including decrypting and displaying messages
func handleIncomingMessages(conn *websocket.Conn, privKey []byte) {
	for {
		var receivedMessage Message
		err := conn.ReadJSON(&receivedMessage)
		if err != nil {
			fmt.Println("Error reading message:", err)
			break
		}

		switch receivedMessage.Type {
		case "keyResponse":
			handlePublicKeyResponse(receivedMessage)

		case "message":
			// Assuming message content is encrypted and base64 encoded
			decodedMessage, err := base64.StdEncoding.DecodeString(receivedMessage.Content)
			if err != nil {
				fmt.Println("Failed to decode message:", err)
				continue
			}

			// Decrypt the received message using the client's private key
			decryptedMessage := security.Decrypt(privKey, string(decodedMessage))
			if decryptedMessage == "" {
				fmt.Println("Failed to decrypt message or message is empty")
				continue
			}

			fmt.Printf("\rReceived message from %s: %s\n", receivedMessage.Sender, decryptedMessage)
			fmt.Print("Enter a message: ")
		}
	}
}

// sendMessage encrypts and sends a message to the recipient
func sendMessage(conn *websocket.Conn, sender, recipient, content string) {
	keyMutex.Lock()
	recipientPublicKeyEncoded, exists := otherPublicKeys[recipient]
	keyMutex.Unlock()

	if !exists {
		fmt.Println("Public key for recipient not found")
		return
	}

	// Decode the base64-encoded public key
	recipientPublicKey, err := base64.StdEncoding.DecodeString(recipientPublicKeyEncoded)
	if err != nil {
		fmt.Println("Error decoding public key:", err)
		return
	}

	fmt.Printf("Encrypting message using public key: %s\n", recipientPublicKey)

	// Encrypt the message using the decoded public key
	// Adjust based on the actual return type of security.Encrypt.
	// Assuming it returns a string encrypted message.
	encryptedMessage := security.Encrypt(recipientPublicKey, content)

	encodedMessage := base64.StdEncoding.EncodeToString([]byte(encryptedMessage))
	message := Message{
		Sender:    sender,
		Content:   encodedMessage,
		Timestamp: time.Now().Unix(),
		Recipient: recipient,
		Type:      "message",
	}

	// Send the encrypted and encoded message
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

// handlePublicKeyResponse handles the response containing the public key of another client
func handlePublicKeyResponse(msg Message) {
	keyMutex.Lock()
	otherPublicKeys[msg.Sender] = msg.PublicKey
	keyMutex.Unlock()
	fmt.Printf("Received and stored public key from %s: %s\n", msg.Sender, msg.PublicKey)
}
