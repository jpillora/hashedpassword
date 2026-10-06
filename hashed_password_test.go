package hashedpassword

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/elithrar/simple-scrypt"
)

type User struct {
	Password Pwd
}

func TestUserPasswordHash(t *testing.T) {
	u := User{}

	//generates rand salt and hashes password
	if err := u.Password.Set("helloworld"); err != nil {
		t.Fatal(err)
	}

	if u.Password.Verify("hellomoon") {
		t.Error("should fail")
	}

	if !u.Password.Verify("helloworld") {
		t.Error("should pass")
	}
	//manual change
	u.Password = "1234"

	if u.Password.Verify("1234") {
		t.Error("should fail after manual change")
	}
}

func TestSetSize(t *testing.T) {
	restoreDefaults(t)
	u1 := User{}
	if err := u1.Password.Set("pass"); err != nil {
		t.Fatal(err)
	}

	SetParams(Params{N: 16384, R: 12, P: 2, SaltLen: 8, DKLen: 16})

	u2 := User{}
	if err := u2.Password.Set("pass"); err != nil {
		t.Fatal(err)
	}

	if len(u1.Password) == len(u2.Password) {
		t.Error("should be different lengths")
	}
}

func restoreDefaults(t *testing.T) {
	t.Helper()
	paramsMu.RLock()
	previous := defaultParams
	paramsMu.RUnlock()
	t.Cleanup(func() { SetParams(previous) })
}

func TestDefaultHashing(t *testing.T) {
	a, b := New("same password"), New("same password")
	if a == b {
		t.Fatal("hashing reused a salt")
	}
	params, err := scrypt.Cost([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	want := Params{N: 32768, R: 8, P: 3, SaltLen: 16, DKLen: 32}
	if Params(params) != want {
		t.Fatalf("default parameters = %+v, want %+v", params, want)
	}
	if err := scrypt.CompareHashAndPassword([]byte(a), []byte("same password")); err != nil {
		t.Fatalf("hash is incompatible with simple-scrypt: %v", err)
	}
}

func TestLegacyHash(t *testing.T) {
	// RFC 7914 section 12, encoded in the existing simple-scrypt format.
	legacy := Pwd("16384$8$1$536f6469756d43686c6f72696465$" +
		"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2" +
		"d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887")
	if err := legacy.Check("pleaseletmein"); err != nil {
		t.Fatalf("legacy hash rejected: %v", err)
	}
	if err := legacy.Check("wrong"); !errors.Is(err, scrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestInvalidParams(t *testing.T) {
	valid := Params{N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32}
	tests := []struct {
		name   string
		change func(*Params)
	}{
		{"zero N", func(p *Params) { p.N = 0 }},
		{"negative N", func(p *Params) { p.N = -2 }},
		{"non-power-of-two N", func(p *Params) { p.N = 6 }},
		{"zero R", func(p *Params) { p.R = 0 }},
		{"negative P", func(p *Params) { p.P = -1 }},
		{"integer overflow", func(p *Params) { p.N, p.R, p.P = 1<<30, 1<<30, 1<<30 }},
		{"memory limit", func(p *Params) { p.N = 1 << 18 }},
		{"work limit", func(p *Params) { p.N, p.P = 32768, 17 }},
		{"short salt", func(p *Params) { p.SaltLen = 7 }},
		{"long salt", func(p *Params) { p.SaltLen = maxSaltLen + 1 }},
		{"short key", func(p *Params) { p.DKLen = 15 }},
		{"long key", func(p *Params) { p.DKLen = maxDKLen + 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := valid
			tt.change(&params)
			pwd := Pwd("existing hash")
			if err := pwd.SetWithParams("password", params); !errors.Is(err, scrypt.ErrInvalidParams) {
				t.Fatalf("expected invalid params, got %v", err)
			}
			if pwd != "existing hash" {
				t.Fatal("failed hashing replaced the stored hash")
			}
		})
	}
	// Standard stronger costs and legacy minimum lengths remain supported.
	for _, params := range []Params{
		{N: 131072, R: 8, P: 1, SaltLen: 16, DKLen: 32},
		{N: 16384, R: 12, P: 2, SaltLen: 8, DKLen: 16},
	} {
		if err := params.Check(); err != nil {
			t.Fatalf("valid parameters rejected: %+v: %v", params, err)
		}
	}
}

func TestRejectUnsafeHashes(t *testing.T) {
	salt, key := strings.Repeat("00", 16), strings.Repeat("00", 32)
	tests := map[string]string{
		"empty":           "",
		"plaintext":       "password",
		"empty key":       "16384$8$1$" + salt + "$",
		"short salt":      "16384$8$1$00$" + key,
		"short key":       "16384$8$1$" + salt + "$00",
		"invalid hex":     "16384$8$1$invalid$" + key,
		"non-power N":     "6$8$1$" + salt + "$" + key,
		"negative cost":   "-2$8$1$" + salt + "$" + key,
		"zero cost":       "16384$0$1$" + salt + "$" + key,
		"overflow":        "99999999999999999999$8$1$" + salt + "$" + key,
		"memory limit":    "262144$8$1$" + salt + "$" + key,
		"work limit":      "32768$8$17$" + salt + "$" + key,
		"long salt":       "16384$8$1$" + strings.Repeat("00", maxSaltLen+1) + "$" + key,
		"long key":        "16384$8$1$" + salt + "$" + strings.Repeat("00", maxDKLen+1),
		"extra field":     "16384$8$1$" + salt + "$" + key + "$extra",
		"oversized input": strings.Repeat("$", maxHashLen+1),
	}
	for name, hash := range tests {
		t.Run(name, func(t *testing.T) {
			pwd := Pwd(hash)
			if err := pwd.Check("password"); err == nil {
				t.Fatal("unsafe hash accepted")
			}
			if pwd.Verify("password") {
				t.Fatal("unsafe hash verified")
			}
		})
	}
}

func TestOversizedPassword(t *testing.T) {
	password := strings.Repeat("x", MaxPasswordLen+1)
	pwd := Pwd("existing hash")
	if err := pwd.Set(password); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Set: %v", err)
	}
	if pwd != "existing hash" {
		t.Fatal("failed hashing replaced the stored hash")
	}
	if err := pwd.Check(password); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Check: %v", err)
	}
	assertPanic(t, func() { New(password) })
}

func TestPasswordNotTruncated(t *testing.T) {
	params := Params{N: 16, R: 1, P: 1, SaltLen: 8, DKLen: 16}
	password := strings.Repeat("x", MaxPasswordLen)
	var pwd Pwd
	if err := pwd.SetWithParams(password, params); err != nil {
		t.Fatal(err)
	}
	if !pwd.Verify(password) || pwd.Verify(password[:len(password)-1]) {
		t.Fatal("password did not retain all bytes")
	}
}

func assertPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	fn()
}

func TestSetParamsRejectsInvalid(t *testing.T) {
	restoreDefaults(t)
	valid := Params{N: 16, R: 1, P: 1, SaltLen: 8, DKLen: 16}
	SetParams(valid)
	assertPanic(t, func() { SetParams(Params{}) })
	pwd := New("password")
	params, err := scrypt.Cost([]byte(pwd))
	if err != nil || Params(params) != valid {
		t.Fatalf("invalid configuration replaced defaults: %+v, %v", params, err)
	}
}

func TestConcurrentSetParams(t *testing.T) {
	restoreDefaults(t)
	a := Params{N: 16, R: 1, P: 1, SaltLen: 8, DKLen: 16}
	b := Params{N: 32, R: 2, P: 2, SaltLen: 16, DKLen: 32}
	SetParams(a)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				SetParams(a)
				SetParams(b)
				var pwd Pwd
				if err := pwd.Set("password"); err != nil {
					t.Error(err)
					return
				}
				params, err := scrypt.Cost([]byte(pwd))
				if err != nil || (Params(params) != a && Params(params) != b) {
					t.Errorf("mixed concurrent configuration: %+v, %v", params, err)
				}
				if !pwd.Verify("password") {
					t.Error("generated hash did not verify")
				}
			}
		}()
	}
	wg.Wait()
}

func FuzzCheck(f *testing.F) {
	f.Add("")
	f.Add("2$1$1$0000000000000000$")
	f.Add(fmt.Sprintf("16$1$1$%s$%s", strings.Repeat("00", 8), strings.Repeat("00", 16)))
	f.Add(fmt.Sprintf("262144$8$1$%s$%s", strings.Repeat("00", 16), strings.Repeat("00", 32)))
	f.Fuzz(func(t *testing.T, hash string) {
		// Exercise malformed inputs and cheap valid hashes without spending the
		// fuzzing budget on valid, deliberately expensive password derivations.
		if len(hash) <= maxHashLen {
			params, err := scrypt.Cost([]byte(hash))
			if err == nil && Params(params).Check() == nil && uint64(params.N)*uint64(params.R)*uint64(params.P) > 1024 {
				return
			}
		}
		pwd := Pwd(hash)
		_ = pwd.Check("password")
	})
}
