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

	"filippo.io/age/internal/format"
)

var (
	fixedRnd, _ = format.DecodeString("II1ZlNxTYa1CJej8IVc9J4nG4c0XonSfwGdObIiutBWKr0iRligej09dVLJgv8/Lf7vbp0qwa23/8Ul3phsZLg")
	their, _    = newx25519Kyber768IdentityFromScalar(fixedRnd)
)

func Test_x25519Kyber768Recipient_Wrap(t *testing.T) {
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

func Test_x25519Kyber768Recipient_String(t *testing.T) {
	tests := []struct {
		name string
		r    *x25519Kyber768Recipient
		want string
	}{
		{
			name: "",
			r:    their.Recipient(),
			want: "agePQ.92xUC5WfF6lvvZt8TbuBQqc5g6UGmjV310kof8uMAzdb+dQuRUsvVzwqAHsxMUKm2Sp+fIYZSTtp5LWDKxOD",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.String(); got[:len(tt.want)] != tt.want {
				t.Errorf("x25519Kyber768Recipient.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsex25519Kyber768Recipient(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    *x25519Kyber768Recipient
		wantErr bool
	}{
		{
			name: "",
			args: args{
				s: their.Recipient().String(),
			},
			want:    their.Recipient(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parsex25519Kyber768Recipient(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parsex25519Kyber768Recipient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parsex25519Kyber768Recipient() = %v, want %v", got, tt.want)
			}
		})
	}
}
