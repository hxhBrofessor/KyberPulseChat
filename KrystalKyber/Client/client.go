package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/g-utils/crystals-go/dilithium"
	"github.com/g-utils/crystals-go/kyber"
)

// Message represents a structured format for messages.
type Message struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Content   string `json:"content"`
	Signature string `json:"signature,omitempty"`
}

// loadClientCAs loads the CA certificates used to verify client certificates.
func loadCACert() *x509.CertPool {
	caCertPool := x509.NewCertPool()

	// Read in the CA certificate file.
	// Replace 'ca-certificates.crt' with the path to your CA certificate file.
	caCert, err := ioutil.ReadFile("C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\CA-Server\\caCert.pem")
	if err != nil {
		log.Fatalf("Could not read CA certificate: %s", err)
	}

	// Append the client CA's certificate so that the server will trust them.
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("Failed to append CA certificate")
	}

	return caCertPool
}
func sendCSRToCA(csrBytes []byte) ([]byte, error) {
	caCertPool := loadCACert()

	// Setup TLS configuration with the CA certificate
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	// Create an HTTP client that uses this TLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	caServerURL := "https://127.0.0.1:8084/sign-csr"

	resp, err := client.Post(caServerURL, "application/pem-certificate-chain", bytes.NewReader(csrBytes))
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	signedCertBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return signedCertBytes, nil
}

func main() {

	// Read the CSR from a file
	csrBytes, err := ioutil.ReadFile("C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Client\\client.csr")
	if err != nil {
		log.Fatalf("Failed to read CSR: %v", err)
	}

	// Send the CSR to the CA and get the signed certificate
	signedCertBytes, err := sendCSRToCA(csrBytes)
	if err != nil {
		log.Fatalf("Failed to get signed certificate from CA: %v", err)
	}

	// Write the signed certificate to a file
	err = ioutil.WriteFile("C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Client\\signed-client.crt", signedCertBytes, 0644)
	if err != nil {
		log.Fatalf("Failed to write signed certificate: %v", err)
	}
	// Load the CA certificate for client certificate verification
	caCertPool := loadCACert()

	// Load the signed certificate and private key for TLS
	clientCert, err := tls.LoadX509KeyPair("C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Client\\signed-client.crt", "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Client\\client.key")
	if err != nil {
		log.Fatalf("Failed to load key pair: %v", err)
		return
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert}, // Client's certificate and key
		RootCAs:            caCertPool,                    // CA certificate
		InsecureSkipVerify: false,                         // Allow the use of CN for hostname validation
	}

	// Connect to the server using TLS
	conn, err := tls.Dial("tcp", "localhost:8080", tlsConfig)
	if err != nil {
		log.Printf("Error establishing TLS connection: %v", err)
		os.Exit(1)
	}
	defer func(conn *tls.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("Error closing connection: %v", err)
		}
	}(conn)

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
			log.Printf("Error serializing message: %v", err)
			continue
		}

		// Send the message with a newline character to indicate the end of the message
		_, err = conn.Write(append(messageJSON, '\n'))
		if err != nil {
			log.Printf("Error sending message: %v", err)
			return
		}
	}
}

func handleIncomingMessages(conn net.Conn, dilithiumInstance *dilithium.Dilithium) {
	reader := bufio.NewReader(conn)
	for {
		messageBytes, err := reader.ReadBytes('\n')
		if err != nil {
			log.Printf("Error reading: %v", err)
			return
		}

		// Log raw data for debugging
		log.Printf("Raw data received: %s", string(messageBytes))

		var msg Message
		err = json.Unmarshal(messageBytes, &msg)
		if err != nil {
			log.Printf("Error unmarshalling message: %v, Raw data: %s", err, string(messageBytes))
			continue
		}

		// Log the decoded message
		log.Printf("Received message: %+v", msg)
		// Additional code for handling the received message...
	}
}
