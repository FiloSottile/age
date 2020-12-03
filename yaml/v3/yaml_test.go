package yaml

import (
	"io"
	"os"
	"reflect"
	"testing"

	"filippo.io/age"
	yamlv3 "gopkg.in/yaml.v3"
)

func TestSimpleData(t *testing.T) {
	keyFile, err := os.Open("./testdata/age.key")

	if err != nil {
		t.Fatal(err)
	}

	ids, err := age.ParseIdentities(keyFile)

	if err != nil {
		t.Fatal(err)
	}

	keyFile.Seek(0, io.SeekStart)
	recs, err := age.ParseRecipients(keyFile)

	if err != nil {
		t.Fatal(err)
	}

	AddIdentity(ids...)
	AddRecipient(recs...)

	d1 := struct {
		Data ArmoredString `yaml:"data"`
	}{"this is a test"}

	out, err := yamlv3.Marshal(&d1)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%s", string(out))

	d2 := struct {
		Data ArmoredString `yaml:"data"`
	}{}

	w := Wrapper{&d2}
	err = yamlv3.Unmarshal(out, &w)

	if err != nil {
		t.Fatal(err)
	}

	if d1.Data != d2.Data {
		t.Errorf("Expected `%s` got `%s`", d1.Data, d2.Data)
	}
}

type complexStruct struct {
	RegularData []string        `yaml:"regularData"`
	CryptedData []ArmoredString `yaml:"cryptedData"`
}

func TestComplexData(t *testing.T) {
	keyFile, err := os.Open("./testdata/age.key")

	if err != nil {
		t.Fatal(err)
	}

	ids, err := age.ParseIdentities(keyFile)

	if err != nil {
		t.Fatal(err)
	}

	keyFile.Seek(0, io.SeekStart)
	recs, err := age.ParseRecipients(keyFile)

	if err != nil {
		t.Fatal(err)
	}

	AddIdentity(ids...)
	AddRecipient(recs...)

	d1 := complexStruct{
		RegularData: []string{
			"this is the first pwet",
			"this is the second pwet",
		},
		CryptedData: []ArmoredString{
			"this is supposed to be crypted",
			"this is also supposed to be crypted",
		},
	}

	out, err := yamlv3.Marshal(&d1)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%s", string(out))

	d2 := complexStruct{}

	w := Wrapper{&d2}
	err = yamlv3.Unmarshal(out, &w)

	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(d1, d2) {
		t.Errorf("Expected `%v` got `%v`", d1, d2)
	}
}
