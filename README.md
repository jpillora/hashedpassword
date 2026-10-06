# hashedpassword

A small Go package for hashed passwords. Provides an alternate API around [`simple-scrypt`](https://github.com/elithrar/simple-scrypt).

Requires Go 1.26.8 or newer.

[![GoDoc](https://godoc.org/github.com/jpillora/hashedpassword?status.svg)](https://godoc.org/github.com/jpillora/hashedpassword)

### Usage

``` go
package main

import (
	"fmt"

	"github.com/jpillora/hashedpassword"
)

type User struct {
	Password hashedpassword.Pwd //custom string type
}

func main() {
	u := User{}

	//attempt manual set
	u.Password = "1234"
	u.Password.Verify("1234") //false

	//generates rand salt then hashes
	if err := u.Password.Set("helloworld"); err != nil {
		panic(err) // applications should handle this error
	}
	u.Password.Verify("worldhello") //false
	u.Password.Verify("helloworld") //true

	//string value
	fmt.Println(u.Password) // "32768$8$3$<random salt>$<derived key>"
}

```

*Note* This package's API is suited for use with Go structs. For standalone strings, see [`simple-scrypt`](https://github.com/elithrar/simple-scrypt) or [`bcrypt`](https://godoc.org/golang.org/x/crypto/bcrypt).

### Hashing and verification

New hashes use scrypt with `N=32768`, `R=8`, `P=3`, a random 16-byte salt,
and a 32-byte derived key. This uses approximately 32 MiB per call and more CPU
than the previous `N=16384`, `R=8`, `P=1` default. The `N$R$P$salt$key` format
is unchanged; existing hashes use their stored parameters when verified.

`Set` and `SetWithParams` return errors and preserve the previous hash when
hashing fails. `New` retains its single return value and now panics on failure
instead of silently returning an empty hash; use `Set` to handle errors.
`Verify` returns false for mismatches and invalid inputs, while `Check` returns
the underlying error.

`SetParams` safely updates the defaults for concurrent callers. It panics on
invalid configuration and leaves the defaults unchanged; call `params.Check()`
first to handle validation errors. Concurrent changes to the same `Pwd` still
require caller synchronization.

Hash generation and verification enforce these limits before running scrypt:

- Passwords: at most 1 MiB, in bytes; longer passwords return `ErrPasswordTooLong`
  and are never truncated. Empty passwords remain supported; applications own
  their password strength policy.
- Scrypt working memory: at most 256 MiB, including the work buffers.
- Scrypt work factor: `N*R*P <= 2^22`; `N` must be a power of two greater than one.
- Salt length: 8–1024 bytes; derived key length: 16–1024 bytes.
- Encoded hash length: at most 4130 bytes, checked before decoding.

Legacy hashes within these limits remain supported, including the previous
defaults. Custom hashes exceeding them are now rejected. These are per-call
limits; applications should also rate-limit authentication and bound concurrent
hashing. Store hashes in trusted storage, and increase older hashes' costs by
calling `Set` after a successful login.

### Command line

```text
hashedpassword hash [<password>|-]
hashedpassword verify <hash> [<password>|-]
```

Omitting the password or using `-` reads stdin through EOF and removes one
trailing LF or CRLF. Other whitespace is preserved. Piped input keeps passwords
out of process arguments and shell history. For example, in Bash:

```bash
read -rs -p 'Password: ' password
printf '\n' >&2
printf '%s' "$password" | hashedpassword hash
unset password
```

For verification, pipe the password to `hashedpassword verify "$hash"`.
Stdin is read as a stream; the CLI itself does not provide a hidden terminal
prompt. Positional passwords remain supported for compatibility.

The CLI exits with status 0 on success, 1 for a mismatch, invalid hash, or an
input/output/hashing error, and 2 for invalid usage. Failures go to stderr.

### Security checks

```bash
go test -race ./...
go vet ./...
go install golang.org/x/vuln/cmd/govulncheck@v1.7.0
govulncheck ./...
```

GitHub Actions runs these checks on pushes, pull requests, and a weekly schedule.
Dependabot checks Go dependencies and pinned GitHub Actions weekly.

#### MIT License

Copyright © 2015 &lt;dev@jpillora.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
