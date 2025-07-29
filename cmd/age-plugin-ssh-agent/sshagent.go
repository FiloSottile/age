package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

const (
	// SSH agent extension names
	extensionAgeDecryptRSA    = "age-decrypt-rsa@filippo.io"
	extensionAgeDecryptEd25519 = "age-decrypt-ed25519@filippo.io"
)

// SSHAgentClient wraps an SSH agent connection with age-specific extensions
type SSHAgentClient struct {
	conn   net.Conn
	client agent.Agent
}

// NewSSHAgentClient creates a new SSH agent client connection
func NewSSHAgentClient() (*SSHAgentClient, error) {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK environment variable not set")
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSH agent: %v", err)
	}

	client := agent.NewClient(conn)
	
	return &SSHAgentClient{
		conn:   conn,
		client: client,
	}, nil
}

// Close closes the SSH agent connection
func (c *SSHAgentClient) Close() error {
	return c.conn.Close()
}

// ListKeys returns all keys available in the SSH agent
func (c *SSHAgentClient) ListKeys() ([]*agent.Key, error) {
	return c.client.List()
}

// Removed - now using protocol.go types

// RequestRSADecryption requests RSA decryption via SSH agent extension
func (c *SSHAgentClient) RequestRSADecryption(req *RSADecryptionRequest) (*DecryptionResponse, error) {
	// Prepare extension request payload
	payload, err := MarshalRSADecryptionRequest(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling RSA request: %v", err)
	}

	// Check if agent supports extensions
	extAgent, ok := c.client.(agent.ExtendedAgent)
	if !ok {
		return nil, fmt.Errorf("SSH agent does not support extensions")
	}

	// Send extension request
	responseData, err := extAgent.Extension(extensionAgeDecryptRSA, payload)
	if err != nil {
		return nil, fmt.Errorf("RSA extension request failed: %v", err)
	}

	// Parse response
	resp, err := UnmarshalDecryptionResponse(responseData)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling RSA response: %v", err)
	}

	return resp, nil
}

// RequestEd25519Decryption requests Ed25519 decryption via SSH agent extension
func (c *SSHAgentClient) RequestEd25519Decryption(req *Ed25519DecryptionRequest) (*DecryptionResponse, error) {
	// Prepare extension request payload
	payload, err := MarshalEd25519DecryptionRequest(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling Ed25519 request: %v", err)
	}

	// Check if agent supports extensions
	extAgent, ok := c.client.(agent.ExtendedAgent)
	if !ok {
		return nil, fmt.Errorf("SSH agent does not support extensions")
	}

	// Send extension request
	responseData, err := extAgent.Extension(extensionAgeDecryptEd25519, payload)
	if err != nil {
		return nil, fmt.Errorf("Ed25519 extension request failed: %v", err)
	}

	// Parse response
	resp, err := UnmarshalDecryptionResponse(responseData)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling Ed25519 response: %v", err)
	}

	return resp, nil
}


// TestSSHAgentConnection tests if we can connect to SSH agent and list keys
func TestSSHAgentConnection() error {
	client, err := NewSSHAgentClient()
	if err != nil {
		return fmt.Errorf("creating SSH agent client: %v", err)
	}
	defer client.Close()

	keys, err := client.ListKeys()
	if err != nil {
		return fmt.Errorf("listing keys: %v", err)
	}

	fmt.Fprintf(os.Stderr, "DEBUG: Found %d SSH keys in agent\n", len(keys))
	for i, key := range keys {
		fmt.Fprintf(os.Stderr, "DEBUG: Key %d: %s %s\n", i, key.Type(), key.Comment)
	}

	return nil
}