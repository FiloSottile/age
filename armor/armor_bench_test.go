// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package armor_test

import (
	"io"
	"io/ioutil"
	"math/rand"
	"strings"
	"testing"

	"filippo.io/age/armor"
)

func BenchmarkArmorWrite(b *testing.B) {
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	armorWriter := armor.NewWriter(ioutil.Discard)
	defer armorWriter.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := armorWriter.Write(data)
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(int64(n))
	}
}

func BenchmarkArmorRead(b *testing.B) {
	fileContents := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4YWdhZHZ0WG1PZldDT1hD
K3RPRzFkUlJnWlFBQlUwemtjeXFRMFp6V1VFCnRzZFV3a3Vkd1dSUWw2eEtrRkVv
SHcvZnp6Q3lqLy9HMkM4ZjUyUGdDZjQKLS0tIDlpVUpuVUQ5YUJyUENFZ0lNSTB2
ekUvS3E5WjVUN0F5ZWR1ejhpeU5rZUUKsvPGYt7vf0o1kyJ1eVFMz1e4JnYYk1y1
kB/RRusYjn+KVJ+KTioxj0THtzZPXcjFKuQ1
-----END AGE ENCRYPTED FILE-----`
	buf := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := strings.NewReader(fileContents)
		armorReader := armor.NewReader(f)
		for {
			if _, err := armorReader.Read(buf); err == io.EOF {
				break
			} else if err != nil {
				b.Fatal(err)
			}
		}
		b.SetBytes(int64(len(fileContents)))
	}
}
