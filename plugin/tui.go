package plugin

import (
	"errors"
	"fmt"

	"filippo.io/age/internal/term"
)

// NewTerminalUI returns a [ClientUI] that uses the terminal to request inputs,
// and the provided functions to display messages and errors.
//
// The terminal is reached directly through /dev/tty or CONIN$/CONOUT$,
// bypassing standard input and output, so this UI can be used even when
// standard input or output are redirected.
func NewTerminalUI(printf, warningf func(format string, v ...any)) *ClientUI {
	return &ClientUI{
		DisplayMessage: func(name, message string) error {
			printf("%s plugin: %s", name, message)
			return nil
		},
		RequestValue: func(name, message string, isSecret bool) (s string, err error) {
			defer func() {
				if err != nil {
					warningf("could not read value for age-plugin-%s: %v", name, err)
				}
			}()
			if isSecret {
				secret, err := term.ReadSecret(message)
				if err != nil {
					return "", err
				}
				return string(secret), nil
			} else {
				public, err := term.ReadPublic(message)
				if err != nil {
					return "", err
				}
				return string(public), nil
			}
		},
		Confirm: func(name, message, yes, no string) (choseYes bool, err error) {
			defer func() {
				if err != nil {
					warningf("could not read value for age-plugin-%s: %v", name, err)
				}
			}()
			if no == "" {
				message += fmt.Sprintf(" (press enter for %q)", yes)
				_, err := term.ReadSecret(message)
				if err != nil {
					return false, err
				}
				return true, nil
			}
			message += fmt.Sprintf(" (press [1] for %q or [2] for %q)", yes, no)
			for {
				selection, err := term.ReadCharacter(message)
				if err != nil {
					return false, err
				}
				switch selection {
				case '1':
					return true, nil
				case '2':
					return false, nil
				case '\x03': // CTRL-C
					return false, errors.New("user cancelled prompt")
				default:
					warningf("reading value for age-plugin-%s: invalid selection %q", name, selection)
				}
			}
		},
		WaitTimer: func(name string) {
			printf("waiting on %s plugin...", name)
		},
	}
}
