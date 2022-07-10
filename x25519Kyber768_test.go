// Copyright 2019 The age Authors. All rights reserved.

// Use of this source code is governed by a BSD-style

// license that can be found in the LICENSE file.

package age

import (
	"crypto/rand"
	"fmt"
	"log"
	"reflect"
	"testing"
)

func Test_x25519Kyber768Recipient_Wrap(t *testing.T) {
	their, err := Generatex25519Kyber768Identity()
	if err != nil {
		t.Fatal(err)
	}
	theirRecipient := their.Recipient()
	fileKey := make([]byte, fileKeySize)
	rand.Read(fileKey)
	stances, err := theirRecipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	printStances(stances)

	data, err := their.Unwrap(stances)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(data, fileKey) {
		log.Fatalf("Expected %x, got '%x'", fileKey, data)
	}

}

func printStances(stances []*Stanza) {
	for _, stance := range stances {
		fmt.Println("Type:", stance.Type)
		fmt.Println("Body:", len(stance.Body), "bytes")
		for i, s := range stance.Args {
			fmt.Printf("Args[%v] has %v runes\n", i, len(s))
		}
	}
}
