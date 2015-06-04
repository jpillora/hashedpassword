package hashedpassword

import "github.com/elithrar/simple-scrypt"

type Params scrypt.Params

var defaultParams = Params(scrypt.DefaultParams)

//Set the
func SetParams(params Params) {
	if params.DKLen < scrypt.MinDKLen {
		panic("Invalid dk length")
	}
	if params.SaltLen < scrypt.MinSaltLen {
		panic("Invalid salt length")
	}
	defaultParams = params
}

type Pwd string

func (h *Pwd) SetWithParams(password string, params Params) error {
	if hashed, err := scrypt.GenerateFromPassword([]byte(password), scrypt.Params(params)); err != nil {
		return err
	} else {
		*h = Pwd(hashed)
	}
	return nil
}

func (h *Pwd) Set(password string) error {
	return h.SetWithParams(password, defaultParams)
}

//Verify compares the password with the attempt and returns a bool
func (h *Pwd) Verify(attempt string) bool {
	return h.Check(attempt) == nil
}

//Verify compares the password with the attempt and returns an error
func (h *Pwd) Check(attempt string) error {
	return scrypt.CompareHashAndPassword([]byte(*h), []byte(attempt))
}
