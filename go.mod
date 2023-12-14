module filippo.io/age

go 1.19

require (
	filippo.io/edwards25519 v1.0.0
	golang.org/x/crypto v0.4.0
	golang.org/x/sys v0.11.0
	golang.org/x/term v0.3.0
)

// Test dependencies.
require (
	c2sp.org/CCTV/age v0.0.0-20221230231406-5ea85644bd03
	github.com/rogpeppe/go-internal v1.8.1
	golang.org/x/tools v0.1.12 // indirect
)

// https://github.com/rogpeppe/go-internal/pull/172
replace github.com/rogpeppe/go-internal => github.com/FiloSottile/go-internal v1.8.2-0.20230806172430-94b0f0dc0b1e
