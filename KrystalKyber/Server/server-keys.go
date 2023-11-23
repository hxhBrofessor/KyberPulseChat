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
	defer file.Close()

	err = pem.Encode(file, privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// generateSelfSignedCert creates a self-signed certificate and saves it to a file.
func generateSelfSignedCert(privateKey *rsa.PrivateKey, filename string) error {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"TEAM GI-BILL"},
			// ... other subject fields ...
		},
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
	defer certFile.Close()

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
	defer csrFile.Close()

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	return pem.Encode(csrFile, csrPEM)
}

func main() {
	keyFilename := "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Server\\server.key"
	certFilename := "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Server\\server.crt"
	csrFilename := "C:\\Users\\Bryan\\Documents\\School\\Kyber-Mess\\KrystalKyber\\Server\\server.csr"

	privateKey, err := generatePrivateKey(keyFilename)
	if err != nil {
		panic(err)
	}

	err = generateSelfSignedCert(privateKey, certFilename)
	if err != nil {
		panic(err)
	}

	err = generateCSR(privateKey, csrFilename, pkix.Name{
		CommonName:   "localhost",
		Organization: []string{"Team GI-BILL"},
		// ... other subject fields ...
	})
	if err != nil {
		panic(err)
	}
}
