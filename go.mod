module filippo.io/age

go 1.19

require (
	filippo.io/edwards25519 v1.1.0
	golang.org/x/crypto v0.24.0
	golang.org/x/sys v0.21.0
	golang.org/x/term v0.21.0
)

// Test dependencies.
require (
	c2sp.org/CCTV/age v0.0.0-20240306222714-3ec4d716e805
	github.com/rogpeppe/go-internal v1.12.0
	golang.org/x/tools v0.22.0 // indirect
)
