package format

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

type Header struct {
	Recipients []*Recipient
	MAC        []byte
}

type Recipient struct {
	Type string
	Args []string
	Body []byte
}

var b64 = base64.RawURLEncoding.Strict()

func DecodeString(s string) ([]byte, error) {
	// CR and LF are ignored by DecodeString. LF is handled by the parser,
	// but CR can introduce malleability.
	if strings.Contains(s, "\r") {
		return nil, errors.New(`invalid character: \r`)
	}
	return b64.DecodeString(s)
}

var EncodeToString = b64.EncodeToString // TODO: wrap lines

const intro = "This is a file encrypted with age-tool.com, version 1\n"

var recipientPrefix = []byte("->")
var footerPrefix = []byte("---")

func (h *Header) MarshalWithoutMAC(w io.Writer) error {
	if _, err := io.WriteString(w, intro); err != nil {
		return err
	}
	for _, r := range h.Recipients {
		if _, err := w.Write(recipientPrefix); err != nil {
			return err
		}
		for _, a := range append([]string{r.Type}, r.Args...) {
			if _, err := io.WriteString(w, " "+a); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		// TODO: check that Body ends with a newline.
		if _, err := w.Write(r.Body); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%s", footerPrefix)
	return err
}

func (h *Header) Marshal(w io.Writer) error {
	if err := h.MarshalWithoutMAC(w); err != nil {
		return err
	}
	mac := b64.EncodeToString(h.MAC)
	_, err := fmt.Fprintf(w, " %s\n", mac)
	return err
}

type ParseError string

func (e ParseError) Error() string {
	return "parsing age header: " + string(e)
}

func errorf(format string, a ...interface{}) error {
	return ParseError(fmt.Sprintf(format, a...))
}

// Parse returns the header and a Reader that begins at the start of the
// payload.
func Parse(input io.Reader) (*Header, io.Reader, error) {
	h := &Header{}
	rr := bufio.NewReader(input)

	line, err := rr.ReadString('\n')
	if err != nil {
		return nil, nil, errorf("failed to read intro: %v", err)
	}
	if line != intro {
		return nil, nil, errorf("unexpected intro: %q", line)
	}

	var r *Recipient
	for {
		line, err := rr.ReadBytes('\n')
		if err != nil {
			return nil, nil, errorf("failed to read header: %v", err)
		}

		if bytes.HasPrefix(line, footerPrefix) {
			prefix, args := splitArgs(line)
			if prefix != string(footerPrefix) || len(args) != 1 {
				return nil, nil, errorf("malformed closing line: %q", line)
			}
			h.MAC, err = DecodeString(args[0])
			if err != nil {
				return nil, nil, errorf("malformed closing line %q: %v", line, err)
			}
			break

		} else if bytes.HasPrefix(line, recipientPrefix) {
			r = &Recipient{}
			prefix, args := splitArgs(line)
			if prefix != string(recipientPrefix) || len(args) < 1 {
				return nil, nil, errorf("malformed recipient: %q", line)
			}
			r.Type = args[0]
			r.Args = args[1:]
			h.Recipients = append(h.Recipients, r)

		} else if r != nil {
			r.Body = append(r.Body, line...)

		} else {
			return nil, nil, errorf("unexpected line: %q", line)
		}
	}

	// Unwind the bufio overread and return the unbuffered input.
	buf, err := rr.Peek(rr.Buffered())
	if err != nil {
		return nil, nil, errorf("internal error: %v", err)
	}
	payload := io.MultiReader(bytes.NewReader(buf), input)

	return h, payload, nil
}

func splitArgs(line []byte) (string, []string) {
	l := strings.TrimSuffix(string(line), "\n")
	parts := strings.Split(l, " ")
	return parts[0], parts[1:]
}
