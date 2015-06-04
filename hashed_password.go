package hashedpassword

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
)

var HashIterations = 2048

var (
	keySize    = 36
	saltSize   = 24
	keyStrlen  = 4 * (keySize / 3)
	saltStrlen = 4 * (saltSize / 3)
)

func SetSizes(key, salt int) {
	//sizes MUST be length%12==0
	//since base64 bytes to raw bytes is 4*n/3
	if key%12 != 0 || salt%12 != 0 {
		panic("Invalid key or salt size")
	}
	keySize = key
	saltSize = salt
	keyStrlen = 4 * (keySize / 3)
	saltStrlen = 4 * (saltSize / 3)
}

type Pwd string

func (h *Pwd) Set(pass string) error {
	b := make([]byte, saltSize)
	_, err := rand.Read(b)
	if err != nil {
		//oh noez, os has run out of randomz
		return err
	}
	salt := base64.StdEncoding.EncodeToString(b)
	*h = Pwd(salt + ":" + key(pass, salt))
	return nil
}

func (h *Pwd) Verify(pass string) bool {
	str := string(*h)
	if len(str) != saltStrlen+1+keyStrlen {
		return false
	}
	salt := str[:saltStrlen]
	return str[saltStrlen+1:] == key(pass, salt)
}

func key(pass, salt string) string {
	return base64.StdEncoding.EncodeToString(pbkdf2.Key([]byte(pass), []byte(salt), HashIterations, keySize, sha1.New))
}
