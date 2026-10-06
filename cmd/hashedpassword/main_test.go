package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/jpillora/hashedpassword"
)

func TestRun(t *testing.T) {
	var pwd hashedpassword.Pwd
	if err := pwd.SetWithParams("secret", hashedpassword.Params{N: 16, R: 1, P: 1, SaltLen: 8, DKLen: 16}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		args  []string
		input string
		code  int
	}{
		{"match argument", []string{"verify", string(pwd), "secret"}, "", 0},
		{"match stdin", []string{"verify", string(pwd)}, "secret\n", 0},
		{"match explicit stdin", []string{"verify", string(pwd), "-"}, "secret\r\n", 0},
		{"mismatch", []string{"verify", string(pwd), "wrong"}, "", 1},
		{"malformed hash", []string{"verify", "invalid", "secret"}, "", 1},
		{"empty stdin", []string{"hash"}, "", 1},
		{"oversized stdin", []string{"hash"}, strings.Repeat("x", hashedpassword.MaxPasswordLen+1), 1},
		{"no command", nil, "", 2},
		{"unknown command", []string{"unknown"}, "", 2},
		{"missing hash", []string{"verify"}, "", 2},
		{"extra hash argument", []string{"hash", "secret", "extra"}, "", 2},
		{"extra verify argument", []string{"verify", string(pwd), "secret", "extra"}, "", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(tt.input), &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit code = %d, want %d; stderr: %s", code, tt.code, &stderr)
			}
			if code != 0 && (stdout.Len() != 0 || stderr.Len() == 0) {
				t.Fatalf("failure output: stdout=%q stderr=%q", &stdout, &stderr)
			}
			if strings.Contains(stderr.String(), "secret") {
				t.Fatal("error output exposed the password")
			}
		})
	}
}

func TestHashFromStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hash"}, strings.NewReader(" secret \n"), &stdout, &stderr); code != 0 {
		t.Fatalf("hash failed: %d: %s", code, &stderr)
	}
	pwd := hashedpassword.Pwd(strings.TrimSuffix(stdout.String(), "\n"))
	if !pwd.Verify(" secret ") || pwd.Verify("secret") {
		t.Fatal("stdin password was altered beyond removing the newline")
	}
}

func TestReadPassword(t *testing.T) {
	boundary := strings.Repeat("x", hashedpassword.MaxPasswordLen)
	for _, ending := range []string{"", "\n", "\r\n"} {
		password, err := readPassword(nil, strings.NewReader(boundary+ending))
		if err != nil || password != boundary {
			t.Fatalf("maximum-size password with ending %q: %v", ending, err)
		}
	}
	if _, err := readPassword(nil, strings.NewReader(boundary+"x\r\n")); !errors.Is(err, hashedpassword.ErrPasswordTooLong) {
		t.Fatalf("oversized stdin: %v", err)
	}
	if _, err := readPassword([]string{boundary + "x"}, nil); !errors.Is(err, hashedpassword.ErrPasswordTooLong) {
		t.Fatalf("oversized argument: %v", err)
	}
	password, err := readPassword([]string{"literal\n"}, nil)
	if err != nil || password != "literal\n" {
		t.Fatal("argument password was changed")
	}
	password, err = readPassword(nil, strings.NewReader("trailing\r"))
	if err != nil || password != "trailing\r" {
		t.Fatal("bare carriage return was changed")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestInputFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hash"}, failingReader{}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("input failure: exit=%d stdout=%q", code, &stdout)
	}
}

func TestOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"hash", "secret"}, nil, failingWriter{}, &stderr); code != 1 {
		t.Fatalf("output failure: exit=%d", code)
	}
}
