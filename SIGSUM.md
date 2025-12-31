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

curl -JLO "https://dl.filippo.io/age/v1.3.1?for=darwin/arm64"
curl -JLO "https://dl.filippo.io/age/v1.3.1?for=darwin/arm64&proof"

go install sigsum.org/sigsum-go/cmd/sigsum-verify@v0.13.1
sigsum-verify -k age-sigsum-key.pub -P sigsum-generic-2025-1 \
    age-v1.3.1-darwin-arm64.tar.gz.proof < age-v1.3.1-darwin-arm64.tar.gz
```

You can learn more about what's happening above in the [Sigsum
docs](https://www.sigsum.org/getting-started/).

### Release playbook

Dear future me, to sign a new release and produce Sigsum proofs, run the following

```
VERSION=v1.3.1
go install sigsum.org/sigsum-go/cmd/sigsum-verify@latest
go install github.com/tillitis/tkey-ssh-agent/cmd/tkey-ssh-agent@latest
tkey-ssh-agent --agent-socket tkey-ssh-agent.sock --uss
SSH_AUTH_SOCK=tkey-ssh-agent.sock ssh-add -L > tkey-ssh-agent.pub
passage other/sigsum-ratelimit > sigsum-ratelimit
gh release download $VERSION --dir artifacts/
SSH_AUTH_SOCK=tkey-ssh-agent.sock sigsum-submit -k tkey-ssh-agent.pub -P sigsum-generic-2025-1 -a sigsum-ratelimit -d filippo.io artifacts/*
gh release upload $VERSION artifacts/*.proof
```

In the future, we will move to reproducing the artifacts locally, and signing
those instead of the ones built by GitHub Actions.
