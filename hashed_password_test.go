package hashedpassword

import (
	"log"
	"testing"
)

type User struct {
	Password Pwd
}

func TestUserPasswordHash(t *testing.T) {
	u := User{}

	//generates rand salt and hashes password
	u.Password.Set("helloworld")

	if u.Password.Verify("hellomoon") {
		t.Error("should fail")
	}

	if !u.Password.Verify("helloworld") {
		t.Error("should pass")
	}

	log.Println(u.Password)

	//manual change
	u.Password = "1234"

	if u.Password.Verify("1234") {
		t.Error("should fail after manual change")
	}
}
