package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

// generatePrivateKey creates an RSA private key and saves it to a file.
func generatePrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096) // You can change the key size as needed
	if err != nil {
		return nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	err = pem.Encode(file, privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// generateSelfSignedCert creates a self-signed certificate and saves it to a file.
func generateSelfSignedCert(privateKey *rsa.PrivateKey, filename string, subject pkix.Name) error {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	// Create a certificate template with the provided subject information
	certTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject, // Use the provided subject for the client certificate
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func(certFile *os.File) {
		err := certFile.Close()
		if err != nil {
			// Handle error if needed
		}
	}(certFile)

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	return pem.Encode(certFile, certPEM)
}

// generateCSR creates a CSR from the given private key and saves it to a file.
func generateCSR(privateKey *rsa.PrivateKey, filename string, subject pkix.Name) error {
	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA, // Updated to RSA
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return err
	}

	csrFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func(csrFile *os.File) {
		err := csrFile.Close()
		if err != nil {

		}
	}(csrFile)

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	return pem.Encode(csrFile, csrPEM)
}

func main() {
	keyFilename := "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Client\\client.key"
	certFilename := "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Client\\client.crt"
	csrFilename := "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Client\\client.csr"

	privateKey, err := generatePrivateKey(keyFilename)
	if err != nil {
		panic(err)
	}

	err = generateSelfSignedCert(privateKey, certFilename, pkix.Name{
		CommonName:   "client.hostname",               // Common name for the client certificate
		Organization: []string{"Client Organization"}, // Organization for the client certificate
		// ... other subject fields ...
	})
	if err != nil {
		panic(err)
	}

	err = generateCSR(privateKey, csrFilename, pkix.Name{
		CommonName:   "client.hostname",               // Common name for the client certificate
		Organization: []string{"Client Organization"}, // Organization for the client certificate
		// ... other subject fields ...
	})
	if err != nil {
		panic(err)
	}
}
