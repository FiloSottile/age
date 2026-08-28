module filippo.io/age

go 1.25.0

// Release build version.
toolchain go1.27.0

require (
	filippo.io/edwards25519 v1.2.0
	filippo.io/hpke v0.4.0
	filippo.io/nistec v0.0.4
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
)

// Test dependencies.
require (
	c2sp.org/CCTV/age v0.0.0-20260605191406-1e3d2860d46e
	github.com/rogpeppe/go-internal v1.16.0
	golang.org/x/tools v0.49.0 // indirect
)
