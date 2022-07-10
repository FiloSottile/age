module filippo.io/age

go 1.17

require (
	filippo.io/edwards25519 v1.0.0
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	golang.org/x/sys v0.0.0-20220708085239-5a0f0661e09d
	golang.org/x/term v0.0.0-20220526004731-065cf7ba2467
)

require github.com/cloudflare/circl v1.2.1-0.20220708165439-f3c1b0d5f66f

// Test dependencies.
require (
	github.com/creack/pty v1.1.18 // indirect
	github.com/pkg/diff v0.0.0-20210226163009-20ebb0f2a09e // indirect
	github.com/rogpeppe/go-internal v1.8.1
)

replace github.com/rogpeppe/go-internal => github.com/FiloSottile/go-internal v1.8.2-0.20220703103932-d3b1faae2802
