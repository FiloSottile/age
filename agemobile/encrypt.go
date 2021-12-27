package agemobile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Encrypt encryptes an input for provided recipients seperated with new lines
func Encrypt(recipients string, input string, withArmor bool) (string, error) {
	buff := bytes.NewBuffer(nil)
	ids, err := age.ParseRecipients(strings.NewReader(recipients))
	if err != nil {
		return "", err
	}
	err = encrypt(ids, strings.NewReader(input), buff, withArmor)
	return buff.String(), err
}

// EncryptFile encryptes an input file path to output file path for provided recipients seperated with new lines
func EncryptFile(recipients string, input, output string, withArmor bool) error {
	fdin, err := os.Open(input)
	if err != nil {
		return err
	}
	defer fdin.Close()
	if len(output) == 0 {
		output = fmt.Sprintf("%s.age", input)
	}
	fdout, err := os.Create(output)
	if err != nil {
		return err
	}
	defer fdout.Close()
	ids, err := age.ParseRecipients(strings.NewReader(recipients))
	if err != nil {
		return err
	}
	return encrypt(ids, fdin, fdout, withArmor)
}

// encrypt internal helper
func encrypt(recipients []age.Recipient, in io.Reader, out io.Writer, withArmor bool) error {
	var a io.WriteCloser
	if withArmor {
		a = armor.NewWriter(out)
		out = a
	}
	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if a != nil {
		if err := a.Close(); err != nil {
			return err
		}
	}
	return nil
}
