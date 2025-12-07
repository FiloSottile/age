If you download the pre-built binaries, you can check their
[Sigsum](https://www.sigsum.org) proofs, which are like signatures with extra
transparency: you can cryptographically verify that every proof is logged in a
public append-only log, so you can hold the age project accountable for every
binary release we ever produced. This is similar to what the [Go Checksum
Database](https://go.dev/blog/module-mirror-launch) provides.

```
cat << EOF > age-sigsum-key.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM1WpnEswJLPzvXJDiswowy48U+G+G1kmgwUE2eaRHZG
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAz2WM5CyPLqiNjk7CLl4roDXwKhQ0QExXLebukZEZFS
EOF
cat << EOF > sigsum-trust-policy.txt
log 154f49976b59ff09a123675f58cb3e346e0455753c3c3b15d465dcb4f6512b0b https://poc.sigsum.org/jellyfish
witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806
group  demo-quorum-rule all poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
EOF

curl -JLO "https://dl.filippo.io/age/v1.2.0?for=darwin/arm64"
curl -JLO "https://dl.filippo.io/age/v1.2.0?for=darwin/arm64&proof"

go install sigsum.org/sigsum-go/cmd/sigsum-verify@v0.8.0
sigsum-verify -k age-sigsum-key.pub -p sigsum-trust-policy.txt \
    age-v1.2.0-darwin-arm64.tar.gz.proof < age-v1.2.0-darwin-arm64.tar.gz
```

You can learn more about what's happening above in the [Sigsum
docs](https://www.sigsum.org/getting-started/).
