package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	dilithium "github.com/g-utils/crystals-go/dilithium"
	kyber "github.com/g-utils/crystals-go/kyber"
)

// Message represents a structured format for messages.
type Message struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Content   string `json:"content"`
	Signature string `json:"signature,omitempty"`
}

func main() {
	// Load the client's certificate and key
	cert, err := tls.LoadX509KeyPair("C:\\Users\\Bryan\\Documents\\crypto\\KrystalKyber\\Client\\client-cert.pem", "C:\\Users\\Bryan\\Documents\\crypto\\KrystalKyber\\Client\\client.key")
	if err != nil {
		fmt.Println("Error loading client certificate and key:", err.Error())
		os.Exit(1)
	}

	// Load the CA certificate to verify the server
	caCert, err := ioutil.ReadFile("C:\\Users\\Bryan\\Documents\\crypto\\KrystalKyber\\Certs\\ca-cert.pem")
	if err != nil {
		fmt.Println("Error loading CA certificate:", err.Error())
		os.Exit(1)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure TLS settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert}, // Client's certificate and key
		RootCAs:      caCertPool,              // CA certificate
	}

	// Connect to the server using TLS
	conn, err := tls.Dial("tcp", "localhost:8081", tlsConfig)
	if err != nil {
		fmt.Println("Error establishing TLS connection:", err.Error())
		os.Exit(1)
	}
	defer conn.Close()
	// Initialize Kyber and Dilithium instances
	kyberInstance := kyber.NewKyber512()
	dilithiumInstance := dilithium.NewDilithium2()

	// Perform key exchange with the server
	publicKey, _ := kyberInstance.KeyGen(nil)
	_, err = conn.Write(publicKey)
	if err != nil {
		fmt.Println("Error sending public key:", err.Error())
		return
	}

	// Generate Dilithium key pair and send public key to the server
	dilithiumPublicKey, dilithiumPrivateKey := dilithiumInstance.KeyGen(nil)
	_, err = conn.Write(dilithiumPublicKey)
	if err != nil {
		fmt.Println("Error sending Dilithium public key:", err.Error())
		return
	}

	go handleIncomingMessages(conn, dilithiumInstance)

	// Read and send user input messages to the server
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	for {
		fmt.Print("Enter a message: ")
		message, _ := reader.ReadString('\n')
		message = strings.TrimSpace(message)

		// Sign the message using Dilithium
		signature := dilithiumInstance.Sign(dilithiumPrivateKey, []byte(message))

		// Create a message struct with the signature
		msg := Message{
			From:      username,
			To:        "Server",
			Content:   message,
			Signature: string(signature),
		}

		// Serialize the message to JSON and send it to the server
		messageJSON, err := json.Marshal(msg)
		if err != nil {
			fmt.Println("Error serializing message:", err.Error())
			continue
		}

		// Send the message with a newline character to indicate the end of the message
		_, err = conn.Write(append(messageJSON, '\n'))
		if err != nil {
			fmt.Println("Error sending message:", err.Error())
			return
		}
	}
}

func handleIncomingMessages(conn net.Conn, dilithiumInstance *dilithium.Dilithium) {
	reader := bufio.NewReader(conn)
	for {
		messageBytes, err := reader.ReadBytes('\n')
		if err != nil {
			fmt.Println("Error reading:", err.Error())
			return
		}

		// Deserialize the received message
		var msg Message
		err = json.Unmarshal(messageBytes, &msg)
		if err != nil {
			fmt.Println("Error unmarshalling message:", err.Error())
			continue
		}

		// Optionally, verify the message signature using Dilithium
		verified := dilithiumInstance.Verify([]byte(msg.Signature), []byte(msg.Content), nil)
		if !verified {
			fmt.Println("Signature verification failed for message from", msg.From)
			continue
		}

		fmt.Println("Received message from", msg.From, ":", msg.Content)
	}
}
