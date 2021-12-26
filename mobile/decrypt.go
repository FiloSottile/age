package mobile

import (
	"bufio"
	"bytes"
	"io"
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

	rr := bufio.NewReader(strings.NewReader(input))
	var in io.Reader
	if start, _ := rr.Peek(len(armor.Header)); string(start) == armor.Header {
		in = armor.NewReader(rr)
	} else {
		in = rr
	}

	r, err := age.Decrypt(in, ids...)
	if err != nil {
		return "", nil
	}
	buff := bytes.NewBuffer(nil)
	if _, err := io.Copy(buff, r); err != nil {
		return "", nil
	}
	return buff.String(), nil
}
