// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"encoding/hex"
	"crypto/sha256"
	"bytes"
	"io"
	"log"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const mlkemLabel = "age-encryption.org/v1/mlkem"

// Values taken from https://github.com/post-quantum-cryptography/KAT MLKEM 768 testcase 0
// d + z
const zd = "6dbbc4375136df3b07f7c70e639e223e177e7fd53b161b3f4d57791794f12624" + 
		   "f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68"
const pk = "01f60af1dc8e6360ae78b59d4a5042eb9145a269046d6236b8304f305c2d9dcb189fe5a62df89b2f5a7bce3bbc753c1e78f730a99869f809aba856b676b707b26601d1d909bab32451494eb7d0a2153a6350b79789a9b115f83ea12037256562f06a1d5aba378da77039d3bdecaca8e6a22a49050a76300a0267cdb38b7ac77903c50ca53b99283cac6b95fba651b11a4d1a692e4072965060587669f253b1bb182e661446168ac60221894660020e9bb5f5b7124a0303e2543ea3ea6ce97a2482b255ca346fb27a847b33b93f3ab2d33064c6e6632d1a23f1144e907b246b479f4a5c928929a1e24150f5241258a5b67766a66f6a33846495907828ebe44ecc5b73124071ba479073910410a16d5d5696b48b194752979795772a91c348f502b37aa650983ebb89bf3c081ff273544129c9137a6e1834c8f2e7ce14c7870c53c05b9b94ecd38e6645911b0912336863ec168831f811881075cf38a59de4b5c738aa6ef03d779b295588cfb62491cc7b3e08b48473354f9ac8061c152a9e205997499b970b69bce66fe42bca2924ccdf0103d0a4c39193c2df25118d72b17aab26b0c60d4cd2c306ca4696c185de05035f4a09cf970aecc8cc93436f83b1aeaf452c41929a2eabc151938f74c93b858546df2264eeeab602e04a85c522f8fb1a5214afd8d4cae57a47b6f381a23126bd9917173128af917f1d483691c450d1151cfe9a1492d473ed862e27da92500c86a20019e9f975e4f54ad319ba2c5630c4014219d7ba235456fe530140193d662445e6a941d1e238567ba8d4d95ab1c7447d690821876d017270cfb169f2d792f03c800720697b410ab41c66f2b24585125655eb10aa1087ffcb7750cb887ad4467377500a6a7d3a82976b415a54469577b4138d919b03f4c9a4d3390bdcb6f1717a5fa4ab25a34f4ba5039bb22c7f3c234ea4427347aa7251464e631904d7cac4784f78b49d5f4a104a301809a779f6466131f9c62bb67147f4cd4973a6aa1c29ae6a8647b6268be089fe048ce990cd638743d285c889a707f581b63af41731f0246b054bc4b47aab01b6842a2709d02e8158ab90f48b69d136082b34cb0673b74aa3f54508ed029fb8f5045ee0639e150ee3b3c85f68a310ec0441980100b42abf2bad10d4a9e0c7b2bc5bbcaf73cbcdc49dc2c949111936779b178974a0392947745a47189bc3fa8a679c80af964a9f9b1b56577274a2a669d2da6704aa496af407fa1aa964cc3dc3140f5f959a7ea974bdb1b83e48a99c0a3e2d75b0669b5c1278962540609166266da18886fc237af30cefd569dbe399e6652e45f06a5dfc9a758a4987088ff8e38a3cf36b9d988f0e070b68d0b88f7bcc41306080d889780c7e238895ccaa4f3577225cca4c8a9330ce613e717798c9670924b271ac402b51538b8b5967ac490dcab5300e6c54d6a3632f3b973e4186ee1a7e2e85649185b26370c387235c4df28a9937a49d4078bf883f4e6346cb3251d9e13f1bda087b285afaa80e262641c5527b0a184b8bc84a62e577314658e2029d850064f7a7b81f253e7cc124a9c5b039dc9b179a80c2f6aee6ea0815172537331a57b505baa76ff5b4c1f0da754b6194f4b39a9b18730d3cdab925d691ed77a8db9927ea233ac2a12744fdc27e5d221b9369adb325d8"
const ct = "16a61ff84787fd4a5f19ca59b3657db3a106a7329e2d62747a2ef85149163109befff6bcb33df66230b8f6725ce719f58f71196e895befc9754d9f042494648c88a6ed4c4cf13f2faf9f651de79dae077733cb235f9dce448977fd42d5486b7dfdf6d7bd9172b14247655d34f10524d469478d9a9639f34d2acde6e3c048d52b308b66245fe9a28cde7983b9d14c03b37715fe3970cd35734771add7aa9b58cfb0adf8c613deafb2b31f6e5c8364d4334e93af8e4943fa947cc67667447cffd036235afaea7f603cb2ea277b97dadf82ea746f6b27396dd08c85cff9304a2e5ce0571fde2e926716bc9f8e4d474b4e8fd34b0dc28376204ea306d30e9a6dd88250b79823e77319f2ef3a77704f409dde8beb6db1be4a9f25ae2e15939dedf1b11a5aa51fcff04068b46d42fbbafd2498264cca4fb78b0f2ab162c7ef569875a13148b9a4b0b9da1787ca0a7033e3eca13471dbcbbe15e34f2b5065b995fe221c2b7ac150334d14e68edc5e049663de362fae8d35e24c202c5fad2153cd044ea962a388f030cdc5dec1c3423183b173c32b22f5800ae45e8e89c8ee4617ce24e60f278bfd1ea0f8fa92486b6f849127da99be7be4c661e2ba26669d6acf619a33056809683e24a2f29e33be7f5f9ac668697e59488e9b8685956cd87b7c47109d603202c201472ec829ea64922e4d0eadd4a4b5a8fb06e0f4bf25a59ced54557388dcd91b387cb6148597edf84a22595801851ca4b9e9e096fdfc96f2444ac9f1247a5e640787fca23e3eb21ec1059c42a65803441df01279013c448dfc3eedfc3355eee1f510086a115f854c36db797a85ede19a473a33e79a80f6f7f6467e1b0d866fe0e57a8abd379934a6a6a492f5f32594d43de2ec2eea81487981bb6394bfa6df5498d74c6db2202a6348a325fbc906b8e820bb00659a2ee12740b14b2e36f4c5dab411c0cd096c5e63ba4d48aa9e92b31f44dc97c0fef661bcf4db895f174613d9d5ed9e836657745ec9deec7af273cec87ef0eaf805da1bc8401608810b8a86f952c6326d09fc8d1d7fd83b4e862e05058e877c056cc5465ec3192b03a4c33cc6b16558d2482d5f84518cbbc526aae6e8840317efb3a1982c3d1719ef15d10f8b077c5c68680be6d3d92e86aaa6eb378cf0559d493257147b55730f49a042325af066b4f9741b9fff5d47972d5acaf52b6bea4e9e354ef9448b62f6d2a1317675a922e14e31578d6cab5a09a71ab270d865151b8ab4c612b5fd5dcc97e45419a1cfb6b8b9aec60f62602098f91f07c238186657941c7a18e4d7ee220f022d5fffd291853b9c063e561b7176f7a235ce45bc86ce4718086df9536c5a5f0abf04c0a84d82bdf69552ade3135433c10a1ba69d688969e6d9dce54d3b3aae3a7f2ab904e657e3fb05241fac110aa07e62cc3991d7d0d6329b5ab9d69d7336c0d148588c9f0921325b85df5fd30db80a56a3724372153641961aa7e042bf2646ff46022c059d5794c3a4b7f90c410de71a5231dd9b83bbd0e6bdab1bf9e62f"
const ss = "b408d5d115713f0a93047dbbea832e4340787686d59a9a2d106bd662ba0aa035"

// Test file key
const fk = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

func TestMLKEM(t *testing.T) {
	zdBuf, _ := hex.DecodeString(zd)
	pkBuf, _ := hex.DecodeString(pk)
	ctBuf, _ := hex.DecodeString(ct)
	ssBuf, _ := hex.DecodeString(ss)
	fileKey, _ := hex.DecodeString(fk)

	privateKeyString := encodePrivateKey(zdBuf)
	wrappedStanza, err := hackedWrap(fileKey, pkBuf, ctBuf, ssBuf)
	if err != nil {
		log.Fatalf("Failed to wrap stanza: %v", err)
	}

	i, err := age.ParseMLKEMIdentity(privateKeyString)
	if err != nil {
		log.Fatalf("Failed to parse MLKEM Identity: %v", err)
	}

	// if ! bytes.Equal(i.ourPublicKey, pkBuf) {
	// 	log.Fatalf("Failed to derive public key from seed correctly")
	// }

	unwrappedFileKey, err := i.Unwrap(wrappedStanza)
	if err != nil {
		log.Fatalf("Failed to unwrap wrappedStanza: %v", err)
	}

	if ! bytes.Equal(unwrappedFileKey, fileKey) {
		log.Fatalf("Unwrapped fileKey did not equal original fileKey")
	}
}

func encodePrivateKey(privateKey []byte) string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", privateKey)
	privateKeyString := strings.ToUpper(s)

	return privateKeyString
}

func hackedWrap(fileKey []byte, publicKey []byte, ciphertext []byte, sharedSecret []byte) ([]*age.Stanza, error) {
	l := &age.Stanza{
		Type: "MLKEM",
		Args: []string{format.EncodeToString(ciphertext)},
	}

	salt := make([]byte, 0, len(ciphertext)+len(publicKey))
	salt = append(salt, ciphertext...)
	salt = append(salt, publicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(mlkemLabel))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return []*age.Stanza{l}, nil
}

// aeadEncrypt encrypts a message with a one-time key.
func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	// The nonce is fixed because this function is only used in places where the
	// spec guarantees each key is only used once (by deriving it from values
	// that include fresh randomness), allowing us to save the overhead.
	// For the code that encrypts the actual payload, look at the
	// filippo.io/age/internal/stream package.
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}