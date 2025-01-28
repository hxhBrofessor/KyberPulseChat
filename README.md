# KyberPulseChat

## Project Overview
This project demonstrates a secure messaging application proof-of-concept using the **CRYSTALS-Kyber Key Encapsulation Mechanism (KEM)**. The application implements quantum-resistant encryption to ensure secure communication in the post-quantum age.

## Features
- **Quantum-Resistant Cryptography**: Utilizes the Kyber KEM for secure key exchange.
- **Public and Private Key Management**: Securely generates and manages cryptographic key pairs.
- **Secure Communication**:
    - Encrypts and decrypts messages using public and private keys.
    - Messages are base64-encoded for safe transmission over the network.
- **Key Exchange Protocol**:
    - Clients exchange public keys with the server upon connection.
    - Public keys are stored by the server and retrieved by other clients as needed.
- **Message Encryption**:
    - Sender encrypts messages with the recipient's public key.
    - Recipient decrypts messages using their private key.

## Technology Stack
- **Language**: Go (Golang) v1.18
- **Libraries**:
    - [Gorilla WebSocket](https://github.com/gorilla/websocket) for WebSocket connections.
    - [Crystallize Security](https://github.com/acheong08/crystallize) for Kyber cryptographic functions.

## How It Works
### 1. Key Generation and Exchange
- Clients generate a public-private key pair using Kyber KEM.
- Upon connection, clients send their public key to the server.
- The server stores public keys and allows clients to request keys of other clients.

### 2. Secure Messaging Workflow
1. **Sender**:
    - Requests the recipient's public key from the server.
    - Encrypts the message using the recipient's public key.
    - Sends the encrypted message to the server.
2. **Server**:
    - Relays the encrypted message to the intended recipient.
3. **Recipient**:
    - Decrypts the message using their private key.

### 3. Base64 Encoding
- Encrypted messages are base64-encoded to ensure compatibility with network transmission.

## Implementation Details
### Server (`server.go`)
- Handles WebSocket connections.
- Manages a list of connected clients and their public keys.
- Facilitates secure communication by forwarding encrypted messages and managing key requests.

### Client (`1337Client.go` and `1338Client.go`)
- Connects to the server via WebSocket.
- Generates Kyber public-private key pairs.
- Performs key exchange with the server.
- Encrypts outgoing messages and decrypts incoming ones.

## Setup and Usage
### Prerequisites
- Install Go v1.18 or later.
- Clone the repository and navigate to the project directory.

### Build and Run
#### Server
```bash
cd /path/to/project
go run server.go
```
#### Clients
For `1337Client.go`:
```bash
cd /path/to/project
go run 1337Client.go
```
For `1338Client.go`:
```bash
cd /path/to/project
go run 1338Client.go
```

### Testing the Application
1. Start the server.
2. Launch both clients in separate terminals.
3. Follow the client prompts to exchange keys and send encrypted messages.

## Demo Video
You can view a demonstration of KyberPulseChat in action by clicking the link below:

[![KyberPulseChat Demo](.media/demo.mp4)

## Security Considerations
- **Man-in-the-Middle Attacks**: Mitigation strategies include using hybrid systems or rolling keys.
- **Side-Channel Attacks**: Potential threats include power analysis. Employing hardware protections or hybrid cryptography may reduce risks.

## References
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber Algorithm Specifications](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
- [Crystallize Security Library](https://github.com/acheong08/crystallize)

---
### Questions?
Feel free to reach out to the project contributors:
- Bryan Angeles
- Erik Swanson
- Amuru Serikyaku