package yaml

import (
	"bytes"
	"io"
	"strings"
	"sync"

	"filippo.io/age"
	"filippo.io/age/armor"
	goyaml "gopkg.in/yaml.v3"
)

const (
	// YAMLTag ...
	YAMLTag = "!crypto/age"
)

var (
	identities = make([]age.Identity, 0, 1)
	recipients = make([]age.Recipient, 0, 1)
	mux        = sync.RWMutex{}
)

// AddIdentity adds identities which will be used to decrypt age armored data in yaml.
func AddIdentity(identity ...age.Identity) {
	mux.Lock()
	defer mux.Unlock()
	identities = append(identities, identity...)
}

// AddRecipient adds recipients which will be used to crypt data into age armored format.
func AddRecipient(recipient ...age.Recipient) {
	mux.Lock()
	defer mux.Unlock()
	recipients = append(recipients, recipient...)
}

// Wrapper is a struct that allows to decrypt crypted armored data in YAML as long
// that the data is tagged with `!crypto/age`.
//
//     agedata: !cripto/age |
//       -----BEGIN AGE ENCRYPTED FILE-----
//       ...
//       ...
//       -----END AGE ENCRYPTED FILE-----
//
// To Marshal data in a crypted armored format use the ArmoredString type instead
// of string in your structs, e.g.:
//
//     type MyYAMLStruct struc {
//     	AgeData ArmoredString `yaml:"agedata"`
//     }
//
type Wrapper struct {
	Target interface{}
}

// ArmoredString ...
type ArmoredString string

// MarshalYAML ...
func (d ArmoredString) MarshalYAML() (interface{}, error) {
	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)

	mux.RLock()
	w, err := age.Encrypt(armorWriter, recipients...)
	mux.RUnlock()

	if err != nil {
		return nil, err
	}

	io.WriteString(w, string(d))
	w.Close()
	armorWriter.Close()

	node := goyaml.Node{
		Kind:  goyaml.ScalarNode,
		Tag:   YAMLTag,
		Value: string(buf.Bytes()),
	}

	return &node, nil
}

// UnmarshalYAML ...
func (w *Wrapper) UnmarshalYAML(value *goyaml.Node) error {
	resolved, err := w.resolve(value)
	if err != nil {
		return err
	}

	return resolved.Decode(w.Target)
}

func (w *Wrapper) resolve(node *goyaml.Node) (*goyaml.Node, error) {
	if node.Kind == goyaml.SequenceNode || node.Kind == goyaml.MappingNode {
		var err error

		if len(node.Content) > 0 {
			for i := range node.Content {
				node.Content[i], err = w.resolve(node.Content[i])
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if node.Tag != YAMLTag {
		return node, nil
	}

	// Check the absence of armored age header and footer
	valueTrimmed := strings.TrimSpace(node.Value)
	if !strings.HasPrefix(valueTrimmed, armor.Header) || !strings.HasSuffix(valueTrimmed, armor.Footer) {
		return node, nil
	}

	var armoredString string
	node.Decode(&armoredString)
	armoredStringReader := strings.NewReader(armoredString)
	armoredReader := armor.NewReader(armoredStringReader)

	mux.RLock()
	decryptedReader, err := age.Decrypt(armoredReader, identities...)
	mux.RUnlock()

	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(decryptedReader)

	tempTag := node.Tag
	node.SetString(strings.TrimSpace(buf.String()))
	node.Tag = tempTag

	return node, nil
}
