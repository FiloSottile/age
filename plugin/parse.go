package plugin

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

type gitHubRecipientError struct {
	username string
}

func (gitHubRecipientError) Error() string {
	return `"github:" recipients were removed from the design`
}

func ParseRecipient2(arg string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(arg, "age1") && strings.Count(arg, "1") > 1:
		return NewRecipient(arg, pluginTerminalUI)
	case strings.HasPrefix(arg, "age1"):
		return age.ParseX25519Recipient(arg)
	// case strings.HasPrefix(arg, "ssh-"):
	// 	return agessh.ParseRecipient(arg)
	case strings.HasPrefix(arg, "github:"):
		name := strings.TrimPrefix(arg, "github:")
		return nil, gitHubRecipientError{name}
	}

	return nil, fmt.Errorf("unknown recipient type: %q", arg)
}

func ParseIdentity2(s string) (age.Identity, error) {
	switch {
	case strings.HasPrefix(s, "AGE-PLUGIN-"):
		return NewIdentity(s, pluginTerminalUI)
	case strings.HasPrefix(s, "AGE-SECRET-KEY-1"):
		return age.ParseX25519Identity(s)
	default:
		return nil, fmt.Errorf("unknown identity type")
	}
}

// parseIdentities is like age.ParseIdentities, but supports plugin identities.
func ParseIdentities2(f io.Reader) ([]age.Identity, error) {
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	var ids []age.Identity
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		i, err := ParseIdentity2(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		ids = append(ids, i)

	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read secret keys file: %v", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no secret keys found")
	}
	return ids, nil
}
