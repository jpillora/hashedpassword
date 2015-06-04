package hashedpassword

import "testing"

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
	//manual change
	u.Password = "1234"

	if u.Password.Verify("1234") {
		t.Error("should fail after manual change")
	}
}

func TestSetSize(t *testing.T) {
	u1 := User{}
	u1.Password.Set("pass")

	SetParams(Params{N: 16384, R: 12, P: 2, SaltLen: 8, DKLen: 16})

	u2 := User{}
	u2.Password.Set("pass")

	if len(u1.Password) == len(u2.Password) {
		t.Error("should be different lengths")
	}
}
