package inspect

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age/armor"
	"filippo.io/age/internal/format"
	"filippo.io/age/internal/stream"
)

type Metadata struct {
	Version     string   `json:"version"`
	Postquantum string   `json:"postquantum"` // "yes" or "no" or "unknown"
	Armor       bool     `json:"armor"`
	StanzaTypes []string `json:"stanza_types"`
	Sizes       struct {
		Header   int64 `json:"header"`
		Armor    int64 `json:"armor"`
		Overhead int64 `json:"overhead"`
		// Currently, we don't do any padding, not MinPayload == MaxPayload and
		// MinPadding == MaxPadding == 0, but that might change in the future.
		MinPayload int64 `json:"min_payload"`
		MaxPayload int64 `json:"max_payload"`
		MinPadding int64 `json:"min_padding"`
		MaxPadding int64 `json:"max_padding"`
	} `json:"sizes"`
}

func Inspect(r io.Reader, fileSize int64) (*Metadata, error) {
	data := &Metadata{
		Version:     "age-encryption.org/v1",
		Postquantum: "unknown",
	}

	tr := &trackReader{r: r}
	br := bufio.NewReader(tr)
	const maxWhitespace = 1024
	start, _ := br.Peek(maxWhitespace + len(armor.Header))
	if strings.HasPrefix(string(bytes.TrimSpace(start)), armor.Header) {
		r = armor.NewReader(br)
		data.Armor = true
	} else {
		r = br
	}

	hdr, rest, err := format.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	buf := &bytes.Buffer{}
	if err := hdr.Marshal(buf); err != nil {
		return nil, fmt.Errorf("failed to re-serialize header: %w", err)
	}
	data.Sizes.Header = int64(buf.Len())

	for _, s := range hdr.Recipients {
		data.StanzaTypes = append(data.StanzaTypes, s.Type)
		switch s.Type {
		case "X25519", "ssh-rsa", "ssh-ed25519", "age-encryption.org/p256tag", "piv-p256":
			data.Postquantum = "no"
		case "mlkem768x25519", "scrypt", "age-encryption.org/mlkem768p256tag":
			if data.Postquantum != "no" {
				data.Postquantum = "yes"
			}
		}
	}

	// If fileSize is not provided, or if it's the size of the armored file
	// (which can have LF or CRLF line endings, varying its size), read to
	// the end to determine it.
	if fileSize == -1 || data.Armor {
		n, err := io.Copy(io.Discard, rest)
		if err != nil {
			return nil, fmt.Errorf("failed to read rest of file: %w", err)
		}
		fileSize = data.Sizes.Header + n
		if !tr.done {
			panic("trackReader not done after io.Copy")
		}
		if tr.count != fileSize && !data.Armor {
			panic("trackReader count mismatch")
		}
		data.Sizes.Armor = tr.count - fileSize
	}
	data.Sizes.Overhead, err = streamOverhead(fileSize - data.Sizes.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to compute stream overhead: %w", err)
	}
	data.Sizes.MinPayload = fileSize - data.Sizes.Header - data.Sizes.Overhead
	data.Sizes.MaxPayload = data.Sizes.MinPayload
	return data, nil
}

type trackReader struct {
	r     io.Reader
	count int64
	done  bool
}

func (tr *trackReader) Read(p []byte) (int, error) {
	n, err := tr.r.Read(p)
	tr.count += int64(n)
	if err == io.EOF {
		tr.done = true
	} else if tr.done {
		panic("non-EOF read after EOF")
	}
	return n, err
}

func streamOverhead(payloadSize int64) (int64, error) {
	const streamNonceSize = 16
	if payloadSize < streamNonceSize {
		return 0, fmt.Errorf("encrypted size too small: %d", payloadSize)
	}
	encryptedSize := payloadSize - streamNonceSize
	plaintextSize, err := stream.PlaintextSize(encryptedSize)
	if err != nil {
		return 0, err
	}
	return payloadSize - plaintextSize, nil
}
