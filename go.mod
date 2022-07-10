module filippo.io/age

go 1.17

require (
	filippo.io/edwards25519 v1.0.0-rc.1
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	golang.org/x/sys v0.0.0-20220624220833-87e55d714810
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b
)

require github.com/cloudflare/circl v1.2.1-0.20220708165439-f3c1b0d5f66f // indirect

// Test dependencies.
require (
	github.com/creack/pty v1.1.18 // indirect
	github.com/pkg/diff v0.0.0-20210226163009-20ebb0f2a09e // indirect
	github.com/rogpeppe/go-internal v1.8.1
)

replace github.com/rogpeppe/go-internal => github.com/FiloSottile/go-internal v1.8.2-0.20220703103932-d3b1faae2802
