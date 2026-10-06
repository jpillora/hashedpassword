// Package hashedpassword stores and verifies scrypt password hashes.
package hashedpassword

import (
	"errors"
	"sync"

	"github.com/elithrar/simple-scrypt"
)

// MaxPasswordLen is the maximum password length in bytes. Passwords are never
// truncated; applications should enforce their own password strength policy.
const MaxPasswordLen = 1 << 20

// ErrPasswordTooLong is returned for passwords larger than MaxPasswordLen.
var ErrPasswordTooLong = errors.New("hashedpassword: password exceeds 1 MiB")

const (
	maxSaltLen = 1024
	maxDKLen   = 1024
	// Three 10-digit parameters, four separators, and hex-encoded salt and key.
	maxHashLen = 3*10 + 4 + 2*maxSaltLen + 2*maxDKLen
	maxMemory  = 256 << 20
	maxWork    = 1 << 22
)

// Params configures scrypt. Check validates both algorithm and resource limits.
type Params scrypt.Params

// Check rejects invalid parameters and parameters exceeding the per-call limits:
// 256 MiB of scrypt working memory, N*R*P <= 2^22, and 1024-byte salts and keys.
// Smaller costs remain supported for verifying legacy hashes.
func (p Params) Check() error {
	params := scrypt.Params(p)
	if err := params.Check(); err != nil {
		return err
	}
	if p.N&(p.N-1) != 0 || p.SaltLen > maxSaltLen || p.DKLen > maxDKLen {
		return scrypt.ErrInvalidParams
	}
	// The upstream check bounds each value and their products before this math.
	n, r, parallel := uint64(p.N), uint64(p.R), uint64(p.P)
	// scrypt allocates V (128*N*R), B (128*R*P), and XY (256*R).
	if 128*r*(n+parallel+2) > maxMemory || n*r*parallel > maxWork {
		return scrypt.ErrInvalidParams
	}
	return nil
}

var (
	paramsMu sync.RWMutex
	// Approximately 32 MiB of memory with three mixing passes.
	defaultParams = Params{N: 32768, R: 8, P: 3, SaltLen: 16, DKLen: 32}
)

// SetParams sets the defaults for new hashes. It is safe to call concurrently
// with hashing and panics on invalid parameters. Call params.Check first to
// handle configuration errors without a panic. Existing hashes are unaffected.
func SetParams(params Params) {
	if err := params.Check(); err != nil {
		panic(err)
	}
	paramsMu.Lock()
	defaultParams = params
	paramsMu.Unlock()
}

// New hashes initial and panics if hashing fails. Use Pwd.Set to handle errors.
func New(initial string) Pwd {
	var p Pwd
	if err := p.Set(initial); err != nil {
		panic(err)
	}
	return p
}

// Pwd is a stored scrypt hash in N$R$P$salt$key format.
// Concurrent mutation of the same Pwd requires caller synchronization.
type Pwd string

// SetWithParams hashes password using params and replaces h only on success.
func (h *Pwd) SetWithParams(password string, params Params) error {
	if len(password) > MaxPasswordLen {
		return ErrPasswordTooLong
	}
	if err := params.Check(); err != nil {
		return err
	}
	if hashed, err := scrypt.GenerateFromPassword([]byte(password), scrypt.Params(params)); err != nil {
		return err
	} else {
		*h = Pwd(hashed)
	}
	return nil
}

// Set hashes password using a snapshot of the defaults and replaces h only on
// success. Hashing runs without holding the configuration lock.
func (h *Pwd) Set(password string) error {
	paramsMu.RLock()
	params := defaultParams
	paramsMu.RUnlock()
	return h.SetWithParams(password, params)
}

// Verify reports whether attempt matches the stored hash. Invalid or excessive
// hashes and oversized passwords fail verification.
func (h *Pwd) Verify(attempt string) bool {
	return h.Check(attempt) == nil
}

// Check compares attempt with the stored hash in constant time after validating
// its format and resource requirements. It returns nil only for a matching hash.
func (h *Pwd) Check(attempt string) error {
	if len(attempt) > MaxPasswordLen {
		return ErrPasswordTooLong
	}
	// Bound parsing and decoding allocations before inspecting untrusted hashes.
	if len(*h) > maxHashLen {
		return scrypt.ErrInvalidHash
	}
	hash := []byte(*h)
	params, err := scrypt.Cost(hash)
	if err != nil {
		return err
	}
	if err := Params(params).Check(); err != nil {
		return err
	}
	return scrypt.CompareHashAndPassword(hash, []byte(attempt))
}
