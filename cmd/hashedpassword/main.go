package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jpillora/hashedpassword"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	var passwordArgs []string
	switch args[0] {
	case "hash":
		if len(args) > 2 {
			return usage(stderr)
		}
		passwordArgs = args[1:]
	case "verify":
		if len(args) < 2 || len(args) > 3 {
			return usage(stderr)
		}
		passwordArgs = args[2:]
	default:
		return usage(stderr)
	}
	password, err := readPassword(passwordArgs, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "hashedpassword:", err)
		return 1
	}
	switch args[0] {
	case "hash":
		var pwd hashedpassword.Pwd
		if err := pwd.Set(password); err != nil {
			fmt.Fprintln(stderr, "hashedpassword:", err)
			return 1
		}
		if _, err := fmt.Fprintln(stdout, pwd); err != nil {
			fmt.Fprintln(stderr, "hashedpassword:", err)
			return 1
		}
	case "verify":
		pwd := hashedpassword.Pwd(args[1])
		if !pwd.Verify(password) {
			fmt.Fprintln(stderr, "Password does not match or hash is invalid")
			return 1
		}
		if _, err := fmt.Fprintln(stdout, "Password match"); err != nil {
			fmt.Fprintln(stderr, "hashedpassword:", err)
			return 1
		}
	}
	return 0
}

func readPassword(args []string, stdin io.Reader) (string, error) {
	if len(args) == 1 && args[0] != "-" {
		if len(args[0]) > hashedpassword.MaxPasswordLen {
			return "", hashedpassword.ErrPasswordTooLong
		}
		return args[0], nil
	}
	// Allow a trailing CRLF plus one extra byte to detect oversized input.
	data, err := io.ReadAll(io.LimitReader(stdin, int64(hashedpassword.MaxPasswordLen)+3))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("no password on stdin")
	}
	password := string(data)
	if strings.HasSuffix(password, "\n") {
		password = strings.TrimSuffix(strings.TrimSuffix(password, "\n"), "\r")
	}
	if len(password) > hashedpassword.MaxPasswordLen {
		return "", hashedpassword.ErrPasswordTooLong
	}
	return password, nil
}

func usage(stderr io.Writer) int {
	fmt.Fprint(stderr, "usage:\n"+
		"  hashedpassword hash [<password>|-]\n"+
		"  hashedpassword verify <hash> [<password>|-]\n\n"+
		"Omit the password or use - to read stdin through EOF (one trailing newline is removed).\n"+
		"Prefer piped input: command-line passwords can appear in process lists and shell history.\n")
	return 2
}
