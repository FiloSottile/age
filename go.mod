module filippo.io/age

go 1.17

require (
	filippo.io/edwards25519 v1.0.0-rc.1
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/sys v0.0.0-20210903071746-97244b99971b
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b
)

// Test dependencies.
require (
	github.com/creack/pty v1.1.18 // indirect
	github.com/pkg/diff v0.0.0-20210226163009-20ebb0f2a09e // indirect
	github.com/rogpeppe/go-internal v1.8.1
)

replace github.com/rogpeppe/go-internal => github.com/FiloSottile/go-internal v1.8.2-0.20220712170627-21d77b294581
