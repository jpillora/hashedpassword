package main

import "github.com/jpillora/hashedpassword"

type User struct {
	Password hashedpassword.Pwd
}

func main() {
	u := User{}

	//attempt manual set
	u.Password = "1234"
	u.Password.Verify("1234") //false

	//generates rand salt then hashes
	u.Password.Set("helloworld")

	u.Password.Verify("worldhello") //false
	u.Password.Verify("helloworld") //true

	//string value
	println(u.Password)
}
