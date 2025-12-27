module filippo.io/age

go 1.24.0

// Release build version.
toolchain go1.25.5

require (
	filippo.io/edwards25519 v1.1.0
	filippo.io/hpke v0.4.0
	filippo.io/nistec v0.0.4
	golang.org/x/crypto v0.45.0
	golang.org/x/sys v0.38.0
	golang.org/x/term v0.37.0
)

// Test dependencies.
require (
	c2sp.org/CCTV/age v0.0.0-20251208015420-e9274a7bdbfd
	github.com/rogpeppe/go-internal v1.14.1
	golang.org/x/tools v0.39.0 // indirect
)
