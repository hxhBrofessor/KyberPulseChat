package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

// generatePrivateKey creates an ECDSA private key and saves it to a file.
func generatePrivateKey(filename string) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
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
func generateSelfSignedCert(privateKey *ecdsa.PrivateKey, filename string, keyFilename string) error {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost", // Set the CommonName to "localhost"
			Organization: []string{"Your Organization"},
			// ... other subject fields ...
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false, // Set to false
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

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	return pem.Encode(certFile, csrPEM)
}

// generateCSR creates a CSR from the given private key and saves it to a file.
func generateCSR(privateKey *ecdsa.PrivateKey, filename string) error {
	subject := pkix.Name{
		CommonName:   "Your Common Name",
		Organization: []string{"Your Organization"},
		// ... other subject fields ...
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
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
	certFilename := "client-cert.pem"
	keyFilename := "client.key"
	csrFilename := "client.csr"

	privateKey, err := generatePrivateKey(keyFilename)
	if err != nil {
		panic(err)
	}

	err = generateSelfSignedCert(privateKey, certFilename, keyFilename)
	if err != nil {
		panic(err)
	}
	err = generateCSR(privateKey, csrFilename)
	if err != nil {
		panic(err)
	}
}
