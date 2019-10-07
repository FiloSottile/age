// +build gofuzz

package format

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func Fuzz(data []byte) int {
	h, payload, err := Parse(bytes.NewReader(data))
	if err != nil {
		if h != nil {
			panic("h != nil on error")
		}
		if payload != nil {
			panic("payload != nil on error")
		}
		return 0
	}
	w := &bytes.Buffer{}
	if err := h.Marshal(w); err != nil {
		panic(err)
	}
	if _, err := io.Copy(w, payload); err != nil {
		panic(err)
	}
	if !bytes.Equal(w.Bytes(), data) {
		fmt.Fprintf(os.Stderr, "%s\n%q\n%q\n\n", w, data, w)
		panic("Marshal output different from input")
	}
	return 1
}
