package agemobile

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Decrypt decrypts an input for provided keys seperated with new lines
func Decrypt(keys string, input string) (string, error) {
	ids, err := age.ParseIdentities(strings.NewReader(keys))
	if err != nil {
		return "", err
	}
	buff := bytes.NewBuffer(nil)
	decrypt(ids, strings.NewReader(input), buff)
	return buff.String(), nil
}

// Decrypt decrypts an input file path to output file path for provided keys seperated with new lines
func DecryptFile(keys string, input, output string) error {
	ids, err := age.ParseIdentities(strings.NewReader(keys))
	if err != nil {
		return err
	}
	fdin, err := os.Open(input)
	if err != nil {
		return err
	}
	defer fdin.Close()
	if len(output) == 0 {
		output = strings.Replace(input, ".age", "", -1)
	}
	fdout, err := os.Create(output)
	if err != nil {
		return err
	}
	defer fdout.Close()
	return decrypt(ids, fdin, fdout)
}

// decrypt internal helper
func decrypt(keys []age.Identity, in io.Reader, out io.Writer) error {
	rr := bufio.NewReader(in)
	if start, _ := rr.Peek(len(armor.Header)); string(start) == armor.Header {
		in = armor.NewReader(rr)
	} else {
		in = rr
	}

	r, err := age.Decrypt(in, keys...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		return err
	}
	return nil
}
