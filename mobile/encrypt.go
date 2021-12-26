package mobile

import (
	"bytes"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Encrypt encryptes an input for provided recipients seperated with new lines
func Encrypt(recipients string, input string, withArmor bool) (string, error) {
	buff := bytes.NewBuffer(nil)
	var out io.Writer = buff
	var a io.WriteCloser
	if withArmor {
		a = armor.NewWriter(out)
		out = a
	}
	ids, err := age.ParseRecipients(strings.NewReader(recipients))
	if err != nil {
		return "", err
	}
	w, err := age.Encrypt(out, ids...)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(w, input); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if a != nil {
		if err := a.Close(); err != nil {
			return "", err
		}
	}
	return buff.String(), nil
}
