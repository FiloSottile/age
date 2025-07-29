# SSH Agent Support for age Implementation

This document describes the implementation of SSH agent support for the age encryption tool via plugin architecture and SSH agent extensions.

## Overview

The implementation provides a way to use SSH keys stored in an SSH agent for age decryption operations without requiring direct access to private key files. It consists of two main components:

1. **age-plugin-ssh-agent**: An age plugin that communicates with SSH agents via extensions
2. **simple-age-agent**: A demonstration SSH agent that implements age-specific extensions

## Architecture

### Plugin-Based Approach

The implementation follows age's existing plugin architecture:
- Plugin binary: `age-plugin-ssh-agent`
- Usage: `age -d -j ssh-agent encrypted-file.age`
- Communication: Standard age plugin protocol via stdin/stdout

### SSH Agent Extensions

Uses the SSH agent extension mechanism (RFC draft-miller-ssh-agent):
- Extension names: `age-decrypt-rsa@filippo.io` and `age-decrypt-ed25519@filippo.io`
- Protocol: Binary message format for decryption requests/responses
- Backward compatibility: Falls back gracefully if extensions unsupported

## Components

### 1. age-plugin-ssh-agent (`cmd/age-plugin-ssh-agent/`)

**Files:**
- `main.go`: Plugin protocol implementation and CLI interface
- `sshagent.go`: SSH agent connection and extension communication
- `protocol.go`: Age stanza parsing and extension message formats

**Key Features:**
- Implements age plugin `identity-v1` protocol
- Connects to SSH agent via `SSH_AUTH_SOCK`
- Parses age stanzas (`ssh-rsa` and `ssh-ed25519` types)
- Sends extension requests to SSH agent
- Returns decrypted file keys to age

### 2. simple-age-agent (`cmd/simple-age-agent/`)

**Purpose:** Demonstration SSH agent with age decryption extensions

**Key Features:**
- Implements standard SSH agent interface
- Supports `ExtendedAgent` for custom extensions
- Performs RSA-OAEP decryption for `ssh-rsa` stanzas
- Performs Ed25519/X25519 key agreement for `ssh-ed25519` stanzas
- Generates test keys for demonstration

## Protocol Details

### Extension Message Formats

#### RSA Decryption Request (`age-decrypt-rsa@filippo.io`)
```
4 bytes: fingerprint (SHA256 hash of SSH public key, first 4 bytes)
4 bytes: label length
N bytes: label string ("age-encryption.org/v1/ssh-rsa")
4 bytes: encrypted file key length
N bytes: encrypted file key data
```

#### Ed25519 Decryption Request (`age-decrypt-ed25519@filippo.io`)
```
4 bytes: fingerprint (SHA256 hash of SSH public key, first 4 bytes)
32 bytes: ephemeral public key (Curve25519 point)
4 bytes: encrypted file key length
N bytes: encrypted file key data
```

#### Decryption Response (both types)
```
4 bytes: file key length (should be 16)
16 bytes: decrypted file key
```

### Cryptographic Operations

#### RSA (ssh-rsa stanzas)
- Uses RSA-OAEP with SHA256 hash function
- OAEP label: `"age-encryption.org/v1/ssh-rsa"`
- Minimum key size: 2048 bits

#### Ed25519 (ssh-ed25519 stanzas)
- Converts Ed25519 keys to Curve25519 for ECDH
- Performs X25519 key agreement with ephemeral public key
- Applies HKDF-derived tweak for domain separation
- Uses ChaCha20-Poly1305 for file key decryption
- Zero nonce (safe due to single-use keys)

## Testing

The implementation has been tested with:

1. **Basic Plugin Protocol**: Verified age plugin communication works
2. **SSH Agent Connection**: Successfully connects to SSH agents
3. **Extension Support**: Demonstrates extension mechanism functionality
4. **Key Operations**: Both RSA and Ed25519 cryptographic operations implemented

**Test Results:**
```bash
$ SSH_AUTH_SOCK=/tmp/simple-age-agent.sock ssh-add -l
2048 SHA256:Mpjtz1r0WJyrjjZg9VGmn0l1lAI0e7qG1jXUA2yiJq4 test-rsa-key (RSA)
256 SHA256:BOWGR9IjmEWLOOZcyGzgxU4qBVeJuf07iFURHFbsrNk test-ed25519-key (ED25519)

$ SSH_AUTH_SOCK=/tmp/simple-age-agent.sock ./age-plugin-ssh-agent --age-plugin=identity-v1
DEBUG: Found 2 SSH keys in agent
DEBUG: Key 0: ssh-rsa test-rsa-key
DEBUG: Key 1: ssh-ed25519 test-ed25519-key
```

## Limitations and Considerations

### Current Limitations

1. **Standard SSH Agent Limitation**: The standard SSH agent protocol only supports signing operations, not the direct private key access needed for RSA-OAEP decryption and X25519 key agreement.

2. **Custom Agent Required**: A custom SSH agent implementation is needed to support the age-specific extensions.

3. **Key Storage**: The demonstration agent generates its own keys rather than loading existing SSH keys from files.

### Security Considerations

1. **Extension Security**: SSH agent extensions run with the same privileges as the agent and have access to all stored keys.

2. **Key Fingerprinting**: The protocol includes 32-bit fingerprints, making recipients non-anonymous (consistent with age's SSH recipient behavior).

3. **Domain Separation**: Both RSA and Ed25519 implementations use proper domain separation through labels and different key derivation.

## Future Work

### Production Implementation

1. **Real SSH Agent Integration**: Integrate with OpenSSH agent by:
   - Storing age-compatible private keys separately
   - Extending existing agents with age extensions
   - Using hardware security modules (HSMs) or smart cards

2. **Key Management**: 
   - Load existing SSH private keys for age operations
   - Support key addition/removal through agent interface
   - Implement proper key validation and fingerprint matching

3. **Error Handling**: 
   - Improve error messages and debugging
   - Handle network timeouts and connection failures
   - Validate stanza formats more thoroughly

### Integration

1. **age Integration**: The plugin could be distributed as a separate package that integrates with the main age tool.

2. **Documentation**: Complete user documentation and installation instructions.

3. **Testing**: Comprehensive testing with real SSH keys and encrypted files.

## Usage Example

Once fully implemented, usage would be:

```bash
# Start age-compatible SSH agent
$ age-ssh-agent &
$ export SSH_AUTH_SOCK=/tmp/age-ssh-agent.sock

# Add SSH keys to agent
$ ssh-add ~/.ssh/id_rsa
$ ssh-add ~/.ssh/id_ed25519

# Use with age for decryption
$ age -d -j ssh-agent encrypted-file.age > decrypted-file.txt
```

This would allow users to decrypt age files using SSH keys stored in their agent without exposing private key material to the age process itself.