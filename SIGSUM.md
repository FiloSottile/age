If you download the pre-built binaries of version v1.2.0+, you can check their
[Sigsum](https://www.sigsum.org) proofs, which are like signatures with extra
transparency: you can cryptographically verify that every proof is logged in a
public append-only log, so the age project can be held accountable for every
binary release we ever produced. This is similar to what the [Go Checksum
Database](https://go.dev/blog/module-mirror-launch) provides.

```
cat << EOF > age-sigsum-key.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM1WpnEswJLPzvXJDiswowy48U+G+G1kmgwUE2eaRHZG
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAz2WM5CyPLqiNjk7CLl4roDXwKhQ0QExXLebukZEZFS
EOF

curl -JLO "https://dl.filippo.io/age/v1.3.0?for=darwin/arm64"
curl -JLO "https://dl.filippo.io/age/v1.3.0?for=darwin/arm64&proof"

go install sigsum.org/sigsum-go/cmd/sigsum-verify@v0.13.1
sigsum-verify -k age-sigsum-key.pub -P sigsum-generic-2025-1 \
    age-v1.3.0-darwin-arm64.tar.gz.proof < age-v1.3.0-darwin-arm64.tar.gz
```

You can learn more about what's happening above in the [Sigsum
docs](https://www.sigsum.org/getting-started/).
