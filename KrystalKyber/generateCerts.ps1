# Define the folder paths for client and server certificates
$clientCertPath = "C:\Users\Bryan\Documents\School\Kyber-Mess\KrystalKyber\Client"
$serverCertPath = "C:\Users\Bryan\Documents\School\Kyber-Mess\KrystalKyber\Server"

# Generate client key
openssl genrsa -out "$clientCertPath\client.key" 4096

# Generate client CSR
openssl req -new -key "$clientCertPath\client.key" -out "$clientCertPath\client.csr" -config "$clientCertPath\san.cnf"

# Display client CSR details
openssl req -text -noout -in "$clientCertPath\client.csr"

# Generate server key
openssl genrsa -out "$serverCertPath\server.key" 4096

# Generate server CSR
openssl req -new -key "$serverCertPath\server.key" -out "$serverCertPath\server.csr" -config "$serverCertPath\san.cnf"

# Display server CSR details
openssl req -text -noout -in "$serverCertPath\server.csr"
