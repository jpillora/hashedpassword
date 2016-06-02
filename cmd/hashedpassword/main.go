package main

import (
	"fmt"
	"os"

	"github.com/jpillora/hashedpassword"
)

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	cmd := os.Args[1]
	switch cmd {
	case "hash":
		var pwd hashedpassword.Pwd
		pwd.Set(os.Args[2])
		fmt.Println(pwd)
	case "verify":
		if len(os.Args) < 4 {
			usage()
		}
		pwd := hashedpassword.Pwd(os.Args[2])
		if pwd.Verify(os.Args[3]) {
			fmt.Println("[\033[32mSuccess\033[0m] Password match \033[32m✓\033[0m")
		} else {
			fmt.Println("[\033[31mFailure\033[0m] Password does not match \033[31m✗\033[0m")
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Println("\n  usage:\n" +
		"    hashedpassword hash <password>\n" +
		"    hashedpassword verify <hash> <password>\n")
	os.Exit(1)
}
