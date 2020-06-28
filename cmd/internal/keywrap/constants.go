package keywrap

const KEY_PREFIX = "AGE-PROTECTED-SECRET-KEY-"

// recommended scrypt parameters for most use case
// https://pkg.go.dev/golang.org/x/crypto/scrypt?tab=doc#Key
const SCRYPT_PARAM_SALT_BYTES = 32
const SCRYPT_PARAM_N int = 32768 // log(N) = 15
const SCRPYT_PARAM_R int = 8
const SCRPYT_PARAM_P int = 1
const SCRPYT_PARAM_BYTES int = 32
