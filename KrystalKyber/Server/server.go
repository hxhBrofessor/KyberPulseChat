package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	dilithium "github.com/g-utils/crystals-go/dilithium"
	kyber "github.com/g-utils/crystals-go/kyber"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
)

// Message represents a structured format for messages.
type Message struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Content   string `json:"content"`
	Signature string `json:"signature,omitempty"`
}

// Client represents a connected client.
type Client struct {
	Name      string
	Conn      net.Conn
	PublicKey []byte
}

var clients = make(map[net.Conn]*Client)
var mutex = &sync.Mutex{}

func handleClient(conn net.Conn) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("Error closing connection:", err.Error())
		}
	}(conn)

	// Generate Kyber keys for this client.
	kyberInstance := kyber.NewKyber1024()
	publicKey, _ := kyberInstance.PKEKeyGen(nil)

	// Perform key encapsulation using Kyber to create a shared secret.
	sharedSecret, _ := kyberInstance.Encaps(publicKey, nil)

	// Send the shared secret to the client.
	_, _ = conn.Write(sharedSecret)

	// Generate Dilithium keys for this client.
	dilithiumInstance := dilithium.NewDilithium3()
	dilithiumPublicKey, _ := dilithiumInstance.KeyGen(nil) // ignore private key

	// Create a new client structure.
	client := &Client{
		Conn:      conn,
		PublicKey: dilithiumPublicKey,
	}

	mutex.Lock()
	clients[conn] = client
	mutex.Unlock()

	// Read and process messages from the client.
	reader := json.NewDecoder(conn)
	for {
		var msg Message
		if err := reader.Decode(&msg); err != nil {
			fmt.Println("Error decoding message:", err.Error())
			break
		}

		// Trim leading and trailing whitespaces from message content
		msg.Content = strings.TrimSpace(msg.Content)

		// Assuming the received public key is the one from the message sender.
		// Convert the message content and signature from the Message struct into byte slices.
		messageBytes := []byte(msg.Content)
		signatureBytes := []byte(msg.Signature)

		// Verify the signature with the Dilithium public key.
		verified := dilithiumInstance.Verify(dilithiumPublicKey, signatureBytes, messageBytes)
		if !verified {
			fmt.Println("Signature verification failed for message from", msg.From)
			continue
		}

		client.Name = msg.From

		// Route the message to the intended recipient.
		mutex.Lock()
		if recipient, ok := clients[conn]; ok {
			mutex.Unlock()
			// Serialize and send the message back to the sender (echo server)
			messageJSON, err := json.Marshal(msg)
			if err != nil {
				fmt.Println("Error serializing message:", err.Error())
				continue
			}

			_, err = recipient.Conn.Write(messageJSON)
			if err != nil {
				fmt.Println("Error forwarding message:", err.Error())
				continue
			}
		} else {
			mutex.Unlock()
			fmt.Println("Recipient not found:", msg.To)
		}
	}

	// Remove the client from the map when the connection is closed.
	mutex.Lock()
	delete(clients, conn)
	mutex.Unlock()
}

// loadClientCAs loads the CA certificates used to verify client certificates.
func loadClientCAs() *x509.CertPool {
	caCertPool := x509.NewCertPool()

	// Read in the CA certificate file.
	// Replace 'ca-certificates.crt' with the path to your CA certificate file.
	caCert, err := ioutil.ReadFile("C:\\Users\\Bryan\\Documents\\crypto\\KrystalKyber\\Certs\\ca-cert.pem")
	if err != nil {
		log.Fatalf("Could not read CA certificate: %s", err)
	}

	// Append the client CA's certificate so that the server will trust them.
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("Failed to append CA certificate")
	}

	return caCertPool
}

func main() {
	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair("C:\\Users\\Bryan\\Documents\\crypto\\KrystalKyber\\Certs\\server.crt", "C:\\Users\\Bryan\\Documents\\crypto\\KrystalKyber\\Certs\\server.key")
	if err != nil {
		fmt.Println("Error loading server certificate and private key:", err.Error())
		return
	}

	// Create TLS configuration with client certificate verification
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    loadClientCAs(), // Function to load CA pool
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", ":8081", config)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer func(ln net.Listener) {
		err := ln.Close()
		if err != nil {
			fmt.Println("Error closing listener:", err.Error())
		}
	}(ln)

	for {
		// Accept new TLS connections.
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting TLS connection:", err.Error())
			continue
		}

		// Handle each client connection in a new goroutine.
		go handleClient(conn)
	}
}
