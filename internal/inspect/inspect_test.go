package inspect

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"filippo.io/age/internal/format"
	"filippo.io/age/internal/stream"
)

type readAfterEOFReader struct {
	data []byte
	read bool
}

// buildFile serializes a header with a single stanza of the given type,
// followed by the minimal valid encrypted payload (a 16-byte stream nonce
// and a single empty ChaCha20-Poly1305 chunk).
func buildFile(t *testing.T, stanzaType string) []byte {
	t.Helper()
	hdr := &format.Header{
		Recipients: []*format.Stanza{{Type: stanzaType}},
		MAC:        make([]byte, 32),
	}
	buf := &bytes.Buffer{}
	if err := hdr.Marshal(buf); err != nil {
		t.Fatalf("Header.Marshal: %v", err)
	}
	// Append nonce (16 bytes) + poly1305 tag for empty chunk (16 bytes).
	buf.Write(make([]byte, 16+16))
	return buf.Bytes()
}

func TestInspectTagStanzas(t *testing.T) {
	tests := []struct {
		stanzaType string
		want       string
	}{
		{stanzaType: "p256tag", want: "no"},
		{stanzaType: "mlkem768p256tag", want: "yes"},
	}
	for _, tt := range tests {
		t.Run(tt.stanzaType, func(t *testing.T) {
			f := buildFile(t, tt.stanzaType)
			md, err := Inspect(bytes.NewReader(f), int64(len(f)))
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if got := md.Postquantum; got != tt.want {
				t.Errorf("Postquantum = %q, want %q", got, tt.want)
			}
			if len(md.StanzaTypes) != 1 || md.StanzaTypes[0] != tt.stanzaType {
				t.Errorf("StanzaTypes = %v, want [%q]", md.StanzaTypes, tt.stanzaType)
			}
		})
	}
}

func (r *readAfterEOFReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		n := copy(p, r.data)
		return n, io.EOF
	}
	return 0, nil
}

func TestInspectReadAfterEOF(t *testing.T) {
	f := buildFile(t, "X25519")
	r := &readAfterEOFReader{data: f}
	md, err := Inspect(r, -1)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if md.Version != "age-encryption.org/v1" {
		t.Errorf("Version = %q, want age-encryption.org/v1", md.Version)
	}
}

func TestStreamOverhead(t *testing.T) {
	tests := []struct {
		payloadSize int64
		want        int64
		wantErr     bool
	}{
		{payloadSize: 0, wantErr: true},
		{payloadSize: 15, wantErr: true},
		{payloadSize: 16, wantErr: true},
		{payloadSize: 16 + 15, wantErr: true},
		{payloadSize: 16 + 16, want: 16 + 16}, // empty plaintext
		{payloadSize: 16 + 1 + 16, want: 16 + 16},
		{payloadSize: 16 + stream.ChunkSize + 16, want: 16 + 16},
		{payloadSize: 16 + stream.ChunkSize + 16 + 1, wantErr: true},
		{payloadSize: 16 + stream.ChunkSize + 16 + 15, wantErr: true},
		{payloadSize: 16 + stream.ChunkSize + 16 + 16, wantErr: true}, // empty final chunk
		{payloadSize: 16 + stream.ChunkSize + 16 + 1 + 16, want: 16 + 16 + 16},
	}
	for _, tt := range tests {
		name := "payloadSize=" + fmt.Sprint(tt.payloadSize)
		t.Run(name, func(t *testing.T) {
			got, gotErr := streamOverhead(tt.payloadSize)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("streamOverhead() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("streamOverhead() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("streamOverhead() = %v, want %v", got, tt.want)
			}
		})
	}
}
