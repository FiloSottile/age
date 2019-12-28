# age

age is a simple, modern and secure file encryption tool.

It features small explicit keys, no config options, and UNIX-style composability.

```
$ age-keygen -o key.txt
Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
$ tar cvz ~/data | age -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p > data.tar.gz.age
$ age -d -i key.txt -o data.tar.gz data.tar.gz.age
```

The format specification is at [age-encryption.org/v1](https://age-encryption.org/v1). To discuss the spec or other age related topics, please email the mailing list at age-dev@googlegroups.com. Subscribe at [groups.google.com/d/forum/age-dev](https://groups.google.com/d/forum/age-dev) or by emailing age-dev+subscribe@googlegroups.com.

## Usage

```
Usage:
    age -r RECIPIENT [-a] [-o OUTPUT] [INPUT]
    age --decrypt [-i KEY] [-o OUTPUT] [INPUT]

Options:
    -o, --output OUTPUT         Write the result to the file at path OUTPUT.
    -a, --armor                 Encrypt to a PEM encoded format.
    -p, --passphrase            Encrypt with a passphrase.
    -r, --recipient RECIPIENT   Encrypt to the specified RECIPIENT. Can be repeated.
    -d, --decrypt               Decrypt the input to the output.
    -i, --identity KEY          Use the private key file at path KEY. Can be repeated.

INPUT defaults to standard input, and OUTPUT defaults to standard output.

RECIPIENT can be an age public key, as generated by age-keygen, ("age1...")
or an SSH public key ("ssh-ed25519 AAAA...", "ssh-rsa AAAA...")

RECIPIENT can also be specified as an https:// or file:// URL to a file 
containing a list of keys (one per line) which are all added as recipients.
(e.g. "-r https://github.com/<user>.keys" will use the public keys for the
associated GitHub user)

KEY is a path to a file with age secret keys, one per line
(ignoring "#" prefixed comments and empty lines), or to an SSH key file.
Multiple keys can be provided, and any unused ones will be ignored.
```

## Installation

On macOS, you can use Homebrew:

```
brew tap filippo.io/age https://filippo.io/age
brew install age
```

On Windows, Linux, and macOS, you can use [the pre-built binaries](https://github.com/FiloSottile/age/releases).

If your system has [Go 1.13+](https://golang.org/dl/), you can build from source:

```
git clone https://filippo.io/age && cd age
go build -o . filippo.io/age/cmd/...
```

Help from new packagers is very welcome.
