package plugin_test

import (
	"log"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

type Recipient struct{}

func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	panic("unimplemented")
}

func NewRecipient(data []byte) (*Recipient, error) {
	return &Recipient{}, nil
}

type Identity struct{}

func (i *Identity) Unwrap(s []*age.Stanza) ([]byte, error) {
	panic("unimplemented")
}

func NewIdentity(data []byte) (*Identity, error) {
	return &Identity{}, nil
}

func ExamplePlugin_main() {
	p, err := plugin.New("example")
	if err != nil {
		log.Fatal(err)
	}
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		return NewRecipient(data)
	})
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return NewIdentity(data)
	})
	os.Exit(p.Main())
}
