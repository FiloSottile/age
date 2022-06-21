module filippo.io/age

go 1.17

require (
	filippo.io/edwards25519 v1.0.0-rc.1
	github.com/rogpeppe/go-internal v1.8.1
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/sys v0.0.0-20210903071746-97244b99971b
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b
)

require github.com/pkg/diff v0.0.0-20210226163009-20ebb0f2a09e // indirect

replace github.com/rogpeppe/go-internal v1.8.1 => github.com/FiloSottile/go-internal v1.8.2-0.20220621104300-7a6402ba46b3 // https://github.com/rogpeppe/go-internal/pull/160
