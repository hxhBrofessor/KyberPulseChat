package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

func signCSR(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey, csr *x509.CertificateRequest) ([]byte, error) {
	// Generate a serial number for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Extract CN from the CSR's Subject field
	var isServer bool
	for _, name := range csr.Subject.Names {
		if name.Type.Equal([]int{2, 5, 4, 3}) { // CN OID
			cn := name.Value.(string)
			if strings.ToLower(cn) == "localhost" {
				isServer = true
				break
			}
		}
	}

	// Set the KeyUsage and ExtKeyUsage based on the type of certificate
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	var extKeyUsage []x509.ExtKeyUsage
	if isServer {
		// If it's a server certificate
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		// If it's a client certificate
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// Create a template for the certificate
	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 1 year validity
		KeyUsage:     keyUsage,
		ExtKeyUsage:  extKeyUsage,
	}

	// Extract SANs from the CSR and add them to the certificate template
	var sanExt pkix.Extension
	for _, ext := range csr.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) { // SAN extension OID
			sanExt.Id = ext.Id
			sanExt.Critical = false // You can set this to true if SANs are critical.
			sanExt.Value = ext.Value
			certTemplate.ExtraExtensions = append(certTemplate.ExtraExtensions, sanExt)
		}
	}

	// Create the signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, csr.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	return certBytes, nil
}

// csrHandler handles CSR requests and returns signed certificates.
func csrHandler(caCertPEM []byte, caPrivKeyPEM []byte) http.HandlerFunc {
	// Parse the CA certificate and private key from the PEM encoded data
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		panic("failed to parse CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		panic(err) // Handle error appropriately
	}

	caPrivKeyBlock, _ := pem.Decode(caPrivKeyPEM)
	if caPrivKeyBlock == nil {
		panic("failed to parse CA private key PEM")
	}
	caPrivKey, err := x509.ParsePKCS1PrivateKey(caPrivKeyBlock.Bytes)
	if err != nil {
		panic(err) // Handle error appropriately
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		// Read the CSR from the request body
		csrBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		err = r.Body.Close()
		if err != nil {
			return
		}

		csrBlock, _ := pem.Decode(csrBytes)
		if csrBlock == nil {
			http.Error(w, "Failed to decode CSR from PEM", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			http.Error(w, "Failed to parse CSR", http.StatusBadRequest)
			return
		}

		// Determine if it's a server or client certificate based on the CN
		var _ bool
		for _, name := range csr.Subject.Names {
			if name.Type.Equal([]int{2, 5, 4, 3}) { // CN OID
				cn := name.Value.(string)
				if strings.ToLower(cn) == "localhost" {
					_ = true
					break
				}
			}
		}

		// Sign the CSR, passing the isServer flag
		certBytes, err := signCSR(caCert, caPrivKey, csr)
		if err != nil {
			http.Error(w, "Failed to sign CSR", http.StatusInternalServerError)
			return
		}

		// Return the signed certificate
		w.Header().Set("Content-Type", "application/x-pem-file")
		err = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		if err != nil {
			return
		}
	}
}

func certsetup() (serverTLSConf *tls.Config, clientTLSConf *tls.Config, err error) {
	// Set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Organization:  []string{"Team GI-BILL"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Los Angeles"},
			StreetAddress: []string{"Staples Center"},
			PostalCode:    []string{"90015"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// Create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode the CA certificate and private key
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, nil, err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return nil, nil, err
	}

	// Save the CA certificate and private key to files
	caCertPath := "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\CA-Server\\caCert.pem"
	err = ioutil.WriteFile(caCertPath, caPEM.Bytes(), 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}

	caPrivKeyPath := "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\CA-Server\\caPrivKey.pem"
	err = ioutil.WriteFile(caPrivKeyPath, caPrivKeyPEM.Bytes(), 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write CA private key: %w", err)
	}

	// Set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Organization:  []string{"Team GI-BILL"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Los Angeles"},
			StreetAddress: []string{"Staples Center"},
			PostalCode:    []string{"90015"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode the server certificate and private key
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, nil, err
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, nil, err
	}

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())
	clientTLSConf = &tls.Config{
		RootCAs: certpool,
	}

	return serverTLSConf, clientTLSConf, nil // Ensure both configs are returned
}

func main() {

	// Get our server TLS configuration
	serverTLSConf, _, err := certsetup() // Omit clientTLSConf since it's unused
	if err != nil {
		panic(err)
	}

	// Create a server with TLS configuration
	httpServer := &http.Server{
		Addr:      "127.0.0.1:8084",
		TLSConfig: serverTLSConf,
	}

	// Start the server in a goroutine
	go func() {
		err := httpServer.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Load the CA certificate and private key
	caCertPEM, err := ioutil.ReadFile("C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\CA-Server\\caCert.pem")
	if err != nil {
		panic(err)
	}
	caPrivKeyPEM, err := ioutil.ReadFile("C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\CA-Server\\caPrivKey.pem")
	if err != nil {
		panic(err)
	}

	// Set up HTTP handler for CSR requests using the corrected csrHandler
	http.HandleFunc("/sign-csr", csrHandler(caCertPEM, caPrivKeyPEM))

	// Keep the server running indefinitely
	select {}
}
