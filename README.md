# Secure Chat App

A secure end-to-end encrypted messaging application built with FastAPI and client-side cryptographic operations.

The project explores the architecture of modern secure messaging systems by keeping sensitive cryptographic operations on the client while using the server only for user management, public key distribution, and encrypted message storage.

## Overview

Secure Chat App is a client-server messaging application designed around end-to-end encryption.

Messages are encrypted before being sent to the server and decrypted only on the receiving client. The server stores encrypted message data and public cryptographic material but does not perform message decryption.

The application uses a pre-key-based architecture to allow users to establish secure communication asynchronously.

## Features

- User registration and authentication
- End-to-end encrypted messaging
- Client-side encryption and decryption
- X25519 key agreement
- Ed25519 digital signatures
- HKDF-based key derivation
- Identity key management
- Signed pre-key management
- One-time pre-key management
- Ephemeral key generation
- Public key bundle distribution
- Encrypted message storage
- Chat history retrieval

## Cryptographic Architecture

The application uses multiple types of cryptographic keys to establish secure communication between users.

### Identity Keys

Each user maintains a long-term identity key pair.

Private key material remains on the client, while the required public key material can be published to the server.

Identity keys provide a persistent cryptographic identity for each user.

### Signed Pre-Keys

Clients generate signed pre-keys and authenticate them using Ed25519 signatures.

The receiving client verifies the signature before using the signed pre-key during session establishment.

This helps protect the integrity of published key material.

### One-Time Pre-Keys

Clients generate one-time pre-keys and publish their public components to the server.

When another user starts a secure conversation, an available one-time pre-key can be retrieved as part of the initial key establishment process.

This allows secure communication to be initiated even when the receiving user is offline.

### Ephemeral Keys

A new ephemeral key is generated when initiating secure communication.

Ephemeral key material is used as part of the X25519 key agreement process.

### Shared Secret Derivation

X25519 is used to perform Diffie-Hellman key agreement between clients.

The resulting shared secret material is processed using HKDF to derive cryptographic keys used by the secure messaging flow.

## Message Flow

The basic encrypted messaging flow is:

```text
Sender Client
     |
     | Encrypt message locally
     v
Encrypted Message
     |
     | Send ciphertext
     v
FastAPI Server
     |
     | Store encrypted data
     v
Receiver Client
     |
     | Retrieve ciphertext
     | Decrypt locally
     v
Plaintext Message
```

The server is responsible for transporting and storing encrypted data but is not responsible for decrypting message content.

## System Architecture

```text
+--------------------+
|      Client A      |
|                    |
| Key Management     |
| Key Agreement      |
| Encryption         |
| Decryption         |
+---------+----------+
          |
          | Encrypted Messages
          | Public Key Material
          |
+---------v----------+
|   FastAPI Server   |
|                    |
| User Management    |
| Public Key Bundles |
| Encrypted Messages |
+---------+----------+
          |
          | Encrypted Messages
          | Public Key Material
          |
+---------v----------+
|      Client B      |
|                    |
| Key Management     |
| Key Agreement      |
| Encryption         |
| Decryption         |
+--------------------+
```

## Client Responsibilities

The client performs sensitive cryptographic operations, including:

- Cryptographic key generation
- Private key management
- Ephemeral key generation
- Signature generation
- Signature verification
- Shared secret derivation
- Key derivation
- Message encryption
- Message decryption

Private cryptographic material is kept on the client side.

## Server Responsibilities

The FastAPI backend is responsible for:

- User registration
- User authentication
- Public key bundle storage
- Public key distribution
- One-time pre-key management
- Encrypted message storage
- Message retrieval

The server acts as a communication and key distribution layer between clients.

## Technologies

### Backend

- Python
- FastAPI
- SQLite

### Cryptography

- X25519
- Ed25519
- HKDF

### Architecture

- Client-server architecture
- End-to-end encryption
- Pre-key-based key establishment
- Client-side cryptographic operations

## Security Design

The project is designed around several core security principles.

### End-to-End Encryption

Message content is encrypted on the sender's client and decrypted on the receiver's client.

### Client-Side Cryptography

Cryptographic operations involving private key material are performed on the client.

### Private Key Isolation

Private cryptographic keys are not intentionally transmitted to the server.

### Authenticated Key Material

Ed25519 signatures are used to authenticate signed pre-key material before it is used during key establishment.

### Encrypted Message Storage

The server stores encrypted message data instead of plaintext message content.

## Project Goals

The main goal of this project is to gain practical experience with secure messaging architecture and applied cryptography.

The project focuses on:

- End-to-end encryption
- Client-server security boundaries
- Asynchronous key establishment
- Identity key management
- Pre-key systems
- Diffie-Hellman key agreement
- Digital signatures
- Cryptographic key derivation

This project is an educational secure messaging prototype and is not intended to replace production-grade secure messaging applications.

## Future Improvements

Planned improvements include:

- Improved session key lifecycle management
- Forward secrecy mechanisms
- Double Ratchet implementation
- Post-compromise security
- Secure local key storage
- Real-time messaging with WebSockets
- Multi-device support
- Improved authentication
- Automated security testing
- Containerized deployment
- Production database integration
- Cloud deployment

## Current Status

The project currently runs locally.

In the coming days, the necessary networking, deployment, and configuration improvements will be implemented to make the application accessible and usable from different environments and devices.
