// Command age-plugin-tagtest is a that decrypts files encrypted to fixed
// age1tag1... or age1tagpq1... recipients for testing purposes.
//
// It can be used with the "-j" flag:
//
//	go install ./tag/internal/age-plugin-tagtest
//	age -d -j tagtest file.age
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag/internal/tagtest"
)

const classicRecipient = "age1tag1qwe0kafsjrar4txm6heqnhpfuggzr0gvznz7fvygxrlq90u5mq2pysxtw6h"

const hybridRecipient = "age1tagpq14h4z7cks9sxftfc8tq4xektt4854ur9rv76tvujdvtzk2fmyywkvh9z2emz3x4epvhz7qdt2v7uksyyq2cdzf3k04ny0g5sc3u4heqh3r9v4cnwhfjw0a2azpgmnk9xk02wvywt5szcq6q3jvwsjxvkn3tsk52vqjczdcvc398ym4j6cvqas4w99gkgt7ur3fmt4g873phr23tgxw3f7wgsz9zxz7m8cp27vpq3h5vc8nssjemtr2etmtmqkg4fzn2u9x9zvtysuya5yrytgx482ftx9864h8a6pprarxd3d0qe8nw2at5ekg3tsahtef7kawasxjamyckw2ans6v933vuypcfrra32f89r2v72mka9hhc55s49xe2khfsq7w9r2zynuzfx4fg6v7jjncsc87rw2yy8qp8hr27edus6zw5xd6m3hax2nxhl2dys9792z3wp5c034sfkrxe86guj7pfdh7sytzrufl9euhuhyf9w6c7z2nwf7v5v8f2s4gplgvfx4jj4le22k2qn242qkqkcwx7llfyrct7jm2wcv0ytypeh6h93ezgtd7q6zr428qze3dec5jxlc5xxjetyephp42fljft3s02p0570kjwyfeyjcnks2vglkvyus5g9l4z6m0gf8wu22ygfm40028txwjlxvvgnn7c36z783c6tmc9k5nef8nucj6u3ustff5vhtnzhnscsvsz79wzrkv3sujtntx4wezucy6lp49flmnyydn3khk2xsesw0ekn4u44nzqw2g2rjyrrl7crshlzttgpe0jvqycjzp9kmtz23t3yu0w9j4n344nnrf88k2jqqfpjxte38pcn0epr879pqsuvajxrkmsas89pvfrzwcewneujn08guj5pvvrtn5hzzg2y6u4wwjqqxx4x8w65yc4dchf750dft8kgcttt2f6j0j5v8s7tkaua78tte7artdfar544vl0rau79h95mc4ghp887z82s6rq93txpkvan86n963kagqkldngnkjcn28zdrh38vdxj002zqs9mx7zjvg3ynzdfhfakkynt9fyqpaxpsdrsqrycuhw5ykwgjz6wldef7xtu6p689234hstxe7v8e5422f2dy8ystn57z3fvy9yfrm4t3lye6ejk5n6x8zqexmql7lx965xcxuuy38xzyt8j9qprnwgfqgx54l4tnjdpzdde6xgmwtnpkfwvyr7rkgnavvjn6a3e56wtvjx3evmhjjxvukpq5zqrj0s4sntkz3yeszs5dty8q0q6m7dgp6mjpvaer0c4343g72eycfqzkjupeaemh0n8e935hqs8fh3jgk7fzyxctzuqlx6d2q9jaf8r9wu4sjxj5w6ppw7m9c3hxrzpcv2uek3kxnndgf2hd99q9v2ux8pjkv29ntslvnvhy09dvcy9578rt89gf4cj4cu79zjxtlj3dpct6rjme02zj3qspsade96njkkufu9zuq2lk3qwvddpxjkqm2hnpqwck54zug7ctvkgvk325lwkg4q5rf73zkgys5e9y8jqc96ntdyl4r78lgtw4k5uljk5ttf46s3gc0rq0jwmddnxt875twwq92505zh3zkse5ag2dhjjxyfzkn7xv3j0kv9r3jzpvgep8fq6z8mar509u4fvnhvthp2ah0r45lsyq0mm6fwkcs30v8k9wzvgt6uvcty6qsjvarjs3htym69zu43m4jd3k4tllrr8c05v6p6spuhup4hkk2p9fp9lxafe3pntcn4nk83gzhjjpcjwyg7jcyz5uancu0fakgz27up7ymzp2xv3sqyqewkkqynskw9qkvysrncxj0cy7dt6q8dsseuwmc2urfmcvkykf82wfa54t85hqx8gywhmhzunm2x0d66a4pwl0xl78fhkces5dpq8pfnp35m5a3u8vdam64zx5s5x9cmnrx3zr066f4f8hlecqnq2fd5quw79ljg3q5nvs6ggmm4gkc"

func init() {
	c := tagtest.NewClassicIdentity("age-plugin-tagtest").Recipient().String()
	if c != classicRecipient {
		log.Fatalf("unexpected classic recipient: %s", c)
	}
	h := tagtest.NewHybridIdentity("age-plugin-tagtest").Recipient().String()
	if h != hybridRecipient {
		log.Fatalf("unexpected hybrid recipient: %s", h)
	}
}

func main() {
	p, err := plugin.New("tagtest")
	if err != nil {
		log.Fatal(err)
	}
	p.HandleIdentity(func(b []byte) (age.Identity, error) {
		if len(b) != 0 {
			return nil, fmt.Errorf("unexpected identity data")
		}
		return &tagtestIdentity{}, nil
	})
	os.Exit(p.Main())
}

type tagtestIdentity struct{}

func (i *tagtestIdentity) Unwrap(ss []*age.Stanza) ([]byte, error) {
	classic := tagtest.NewClassicIdentity("age-plugin-tagtest")
	if key, err := classic.Unwrap(ss); err == nil {
		return key, nil
	} else if !errors.Is(err, age.ErrIncorrectIdentity) {
		return nil, err
	}
	hybrid := tagtest.NewHybridIdentity("age-plugin-tagtest")
	return hybrid.Unwrap(ss)
}
