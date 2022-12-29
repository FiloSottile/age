module filippo.io/age

go 1.19

require (
	filippo.io/edwards25519 v1.0.0
	golang.org/x/crypto v0.4.0
	golang.org/x/sys v0.3.0
	golang.org/x/term v0.3.0
)

// Test dependencies.
require (
	c2sp.org/CCTV/age v0.0.0-20221230231406-5ea85644bd03
	github.com/creack/pty v1.1.18 // indirect
	github.com/pkg/diff v0.0.0-20210226163009-20ebb0f2a09e // indirect
	github.com/rogpeppe/go-internal v1.8.1
)

replace github.com/rogpeppe/go-internal => github.com/FiloSottile/go-internal v1.8.2-0.20220728122003-0ced171a3e0e
