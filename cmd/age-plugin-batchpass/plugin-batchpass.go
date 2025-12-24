package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

const usage = `age-plugin-batchpass is an age plugin that enables non-interactive
passphrase-based encryption and decryption using environment variables.

It is not built into the age CLI because most applications should use
native keys instead of scripting passphrase-based encryption.

Usage:

  AGE_PASSPHRASE=password age -e -j batchpass file.txt > file.txt.age

  AGE_PASSPHRASE=password age -d -j batchpass file.txt.age > file.txt

Alternatively, you can use AGE_PASSPHRASE_FD to read the passphrase from
a file descriptor. Trailing newlines are stripped from the file contents.

When encrypting, you can set AGE_PASSPHRASE_WORK_FACTOR to adjust the scrypt
work factor (between 1 and 30, default 18). Higher values are more secure
but slower.

When decrypting, you can set AGE_PASSPHRASE_MAX_WORK_FACTOR to limit the
maximum scrypt work factor accepted (between 1 and 30, default 30). This can
be used to avoid very slow decryptions.`

func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	p, err := plugin.New("batchpass")
	if err != nil {
		log.Fatal(err)
	}
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		if len(data) != 0 {
			return nil, fmt.Errorf("batchpass identity does not take any payload")
		}
		pass, err := passphrase()
		if err != nil {
			return nil, err
		}
		r, err := age.NewScryptRecipient(pass)
		if err != nil {
			return nil, fmt.Errorf("failed to create scrypt recipient: %v", err)
		}
		if envWorkFactor := os.Getenv("AGE_PASSPHRASE_WORK_FACTOR"); envWorkFactor != "" {
			workFactor, err := strconv.Atoi(envWorkFactor)
			if err != nil {
				return nil, fmt.Errorf("invalid AGE_PASSPHRASE_WORK_FACTOR: %v", err)
			}
			if workFactor > 30 || workFactor < 1 {
				return nil, fmt.Errorf("AGE_PASSPHRASE_WORK_FACTOR must be between 1 and 30")
			}
			r.SetWorkFactor(workFactor)
		}
		return r, nil
	})
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		if len(data) != 0 {
			return nil, fmt.Errorf("batchpass identity does not take any payload")
		}
		pass, err := passphrase()
		if err != nil {
			return nil, err
		}
		maxWorkFactor := 0
		if envMaxWorkFactor := os.Getenv("AGE_PASSPHRASE_MAX_WORK_FACTOR"); envMaxWorkFactor != "" {
			maxWorkFactor, err = strconv.Atoi(envMaxWorkFactor)
			if err != nil {
				return nil, fmt.Errorf("invalid AGE_PASSPHRASE_MAX_WORK_FACTOR: %v", err)
			}
			if maxWorkFactor > 30 || maxWorkFactor < 1 {
				return nil, fmt.Errorf("AGE_PASSPHRASE_MAX_WORK_FACTOR must be between 1 and 30")
			}
		}
		return &batchpassIdentity{password: pass, maxWorkFactor: maxWorkFactor}, nil
	})
	os.Exit(p.Main())
}

type batchpassIdentity struct {
	password      string
	maxWorkFactor int
}

func (i *batchpassIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type == "scrypt" && len(stanzas) != 1 {
			return nil, errors.New("an scrypt recipient must be the only one")
		}
	}
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		// Don't fallback to other identities, this plugin should mostly be used
		// in isolation, from the CLI.
		return nil, fmt.Errorf("file is not passphrase-encrypted")
	}
	ii, err := age.NewScryptIdentity(i.password)
	if err != nil {
		return nil, err
	}
	if i.maxWorkFactor != 0 {
		ii.SetMaxWorkFactor(i.maxWorkFactor)
	}
	fileKey, err := ii.Unwrap(stanzas)
	if errors.Is(err, age.ErrIncorrectIdentity) {
		// ScryptIdentity returns ErrIncorrectIdentity to make it possible to
		// try multiple passphrases from the API. If a user is invoking this
		// plugin, it's safe to say they expect it to be the only mechanism to
		// decrypt a passphrase-protected file.
		return nil, fmt.Errorf("incorrect passphrase")
	}
	return fileKey, err
}

func passphrase() (string, error) {
	envPASSPHRASE := os.Getenv("AGE_PASSPHRASE")
	envFD := os.Getenv("AGE_PASSPHRASE_FD")
	if envPASSPHRASE != "" && envFD != "" {
		return "", fmt.Errorf("AGE_PASSPHRASE and AGE_PASSPHRASE_FD are mutually exclusive")
	}
	if envPASSPHRASE == "" && envFD == "" {
		return "", fmt.Errorf("either AGE_PASSPHRASE or AGE_PASSPHRASE_FD must be set")
	}

	if envPASSPHRASE != "" {
		return envPASSPHRASE, nil
	}

	fd, err := strconv.Atoi(envFD)
	if err != nil {
		return "", fmt.Errorf("invalid AGE_PASSPHRASE_FD: %v", err)
	}
	f := os.NewFile(uintptr(fd), "AGE_PASSPHRASE_FD")
	if f == nil {
		return "", fmt.Errorf("failed to open file descriptor %d", fd)
	}
	defer f.Close()
	const maxPassphraseSize = 1024 * 1024 // 1 MiB
	b, err := io.ReadAll(io.LimitReader(f, maxPassphraseSize+1))
	if err != nil {
		return "", fmt.Errorf("failed to read passphrase from fd %d: %v", fd, err)
	}
	if len(b) > maxPassphraseSize {
		return "", fmt.Errorf("passphrase from fd %d is too long", fd)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
