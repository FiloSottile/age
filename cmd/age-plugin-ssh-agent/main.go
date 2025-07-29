package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

const (
	pluginName = "ssh-agent"
)

var (
	sshAgent *SSHAgentClient
	stanzas  []stanzaInfo // Store stanzas for decryption
)

type stanzaInfo struct {
	index      int
	stanzaType string
	args       []string
	body       []byte
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s --age-plugin={recipient-v1|identity-v1}", os.Args[0])
	}

	// Initialize SSH agent connection
	var err error
	sshAgent, err = NewSSHAgentClient()
	if err != nil {
		log.Fatalf("Failed to connect to SSH agent: %v", err)
	}
	defer sshAgent.Close()

	// Test connection and list keys for debugging
	if err := TestSSHAgentConnection(); err != nil {
		log.Fatalf("SSH agent test failed: %v", err)
	}

	switch os.Args[1] {
	case "--age-plugin=recipient-v1":
		if err := runRecipientV1(); err != nil {
			log.Fatalf("recipient-v1 error: %v", err)
		}
	case "--age-plugin=identity-v1":
		if err := runIdentityV1(); err != nil {
			log.Fatalf("identity-v1 error: %v", err)
		}
	default:
		log.Fatalf("Unknown protocol: %s", os.Args[1])
	}
}

func runRecipientV1() error {
	scanner := bufio.NewScanner(os.Stdin)
	
	// Phase 1: Read commands from age
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "add-recipient":
			if len(args) != 1 {
				return fmt.Errorf("add-recipient expects 1 argument, got %d", len(args))
			}
			recipient := args[0]
			
			// Read the base64 encoded data
			if !scanner.Scan() {
				return fmt.Errorf("expected recipient data after add-recipient")
			}
			data := strings.TrimSpace(scanner.Text())
			
			if err := handleAddRecipient(recipient, data); err != nil {
				return fmt.Errorf("handling add-recipient: %v", err)
			}

		case "wrap-file-key":
			// Read the base64 encoded file key
			if !scanner.Scan() {
				return fmt.Errorf("expected file key after wrap-file-key")
			}
			fileKeyB64 := strings.TrimSpace(scanner.Text())
			
			if err := handleWrapFileKey(fileKeyB64); err != nil {
				return fmt.Errorf("handling wrap-file-key: %v", err)
			}

		case "extension-labels":
			// Read empty body
			if !scanner.Scan() {
				return fmt.Errorf("expected empty body after extension-labels")
			}
			
			if err := handleExtensionLabels(); err != nil {
				return fmt.Errorf("handling extension-labels: %v", err)
			}

		case "done":
			// Read empty body
			if !scanner.Scan() {
				return fmt.Errorf("expected empty body after done")
			}
			
			// Phase 1 complete, enter Phase 2
			return handleRecipientPhase2()

		default:
			if strings.HasPrefix(cmd, "grease-") {
				// Read and ignore grease data
				if !scanner.Scan() {
					return fmt.Errorf("expected grease data after %s", cmd)
				}
				// Ignore grease commands
			} else {
				return fmt.Errorf("unknown command: %s", cmd)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading stdin: %v", err)
	}

	return fmt.Errorf("unexpected end of input")
}

func runIdentityV1() error {
	scanner := bufio.NewScanner(os.Stdin)
	
	// Phase 1: Read commands from age
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "add-identity":
			if len(args) != 1 {
				return fmt.Errorf("add-identity expects 1 argument, got %d", len(args))
			}
			identity := args[0]
			
			// Read the base64 encoded data
			if !scanner.Scan() {
				return fmt.Errorf("expected identity data after add-identity")
			}
			data := strings.TrimSpace(scanner.Text())
			
			if err := handleAddIdentity(identity, data); err != nil {
				return fmt.Errorf("handling add-identity: %v", err)
			}

		case "recipient-stanza":
			if len(args) < 2 {
				return fmt.Errorf("recipient-stanza expects at least 2 arguments, got %d", len(args))
			}
			// args[0] is index, args[1] is stanza type, args[2:] are additional args
			
			// Read the base64 encoded stanza body
			if !scanner.Scan() {
				return fmt.Errorf("expected stanza body after recipient-stanza")
			}
			stanzaBody := strings.TrimSpace(scanner.Text())
			
			if err := handleRecipientStanza(args, stanzaBody); err != nil {
				return fmt.Errorf("handling recipient-stanza: %v", err)
			}

		case "done":
			// Read empty body
			if !scanner.Scan() {
				return fmt.Errorf("expected empty body after done")
			}
			
			// Phase 1 complete, enter Phase 2
			return handleIdentityPhase2()

		default:
			return fmt.Errorf("unknown command: %s", cmd)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading stdin: %v", err)
	}

	return fmt.Errorf("unexpected end of input")
}

// Recipient protocol handlers (encryption)
func handleAddRecipient(recipient, data string) error {
	// TODO: Parse and validate SSH agent recipient
	fmt.Fprintf(os.Stderr, "DEBUG: add-recipient %s, data: %s\n", recipient, data[:min(len(data), 20)])
	return nil
}

func handleWrapFileKey(fileKeyB64 string) error {
	// TODO: Wrap file key using SSH agent
	fmt.Fprintf(os.Stderr, "DEBUG: wrap-file-key, key: %s\n", fileKeyB64[:min(len(fileKeyB64), 20)])
	return nil
}

func handleExtensionLabels() error {
	// TODO: Return any extension labels
	fmt.Fprintf(os.Stderr, "DEBUG: extension-labels\n")
	return nil
}

func handleRecipientPhase2() error {
	// TODO: Generate stanzas and respond
	fmt.Fprintf(os.Stderr, "DEBUG: entering recipient phase 2\n")
	
	// For now, just send done
	fmt.Println("done")
	fmt.Println("")
	
	return nil
}

// Identity protocol handlers (decryption)
func handleAddIdentity(identity, data string) error {
	// TODO: Parse and validate SSH agent identity
	fmt.Fprintf(os.Stderr, "DEBUG: add-identity %s, data: %s\n", identity, data[:min(len(data), 20)])
	return nil
}

func handleRecipientStanza(args []string, stanzaBody string) error {
	if len(args) < 2 {
		return fmt.Errorf("recipient-stanza requires at least 2 arguments")
	}

	// Parse index
	index, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid stanza index: %v", err)
	}

	stanzaType := args[1]
	stanzaArgs := args[2:]

	// Decode base64 body
	body, err := base64.StdEncoding.DecodeString(stanzaBody)
	if err != nil {
		return fmt.Errorf("decoding stanza body: %v", err)
	}

	// Store stanza for processing in phase 2
	stanzas = append(stanzas, stanzaInfo{
		index:      index,
		stanzaType: stanzaType,
		args:       stanzaArgs,
		body:       body,
	})

	fmt.Fprintf(os.Stderr, "DEBUG: stored stanza %d type=%s args=%v\n", index, stanzaType, stanzaArgs)
	return nil
}

func handleIdentityPhase2() error {
	fmt.Fprintf(os.Stderr, "DEBUG: entering identity phase 2 with %d stanzas\n", len(stanzas))

	// Process each stanza and try to decrypt
	for _, stanza := range stanzas {
		fileKey, err := processStanza(stanza)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DEBUG: failed to process stanza %d: %v\n", stanza.index, err)
			continue
		}

		if fileKey != nil {
			// Successfully decrypted, return the file key
			fileKeyB64 := base64.StdEncoding.EncodeToString(fileKey)
			fmt.Printf("file-key %d\n", stanza.index)
			fmt.Println(fileKeyB64)
		}
	}

	// Send done to complete the protocol
	fmt.Println("done")
	fmt.Println("")
	
	return nil
}

func processStanza(stanza stanzaInfo) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "DEBUG: processing stanza %d type=%s\n", stanza.index, stanza.stanzaType)

	// Parse the stanza into a decryption request
	req, err := ParseAgeStanza(stanza.stanzaType, stanza.args, stanza.body)
	if err != nil {
		return nil, fmt.Errorf("parsing stanza: %v", err)
	}

	switch typedReq := req.(type) {
	case *RSADecryptionRequest:
		resp, err := sshAgent.RequestRSADecryption(typedReq)
		if err != nil {
			return nil, fmt.Errorf("RSA decryption: %v", err)
		}
		return resp.FileKey, nil

	case *Ed25519DecryptionRequest:
		resp, err := sshAgent.RequestEd25519Decryption(typedReq)
		if err != nil {
			return nil, fmt.Errorf("Ed25519 decryption: %v", err)
		}
		return resp.FileKey, nil

	default:
		return nil, fmt.Errorf("unsupported request type: %T", req)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}