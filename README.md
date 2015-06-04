# hashedpassword

A small Go package for hashed password. Provides an alternate API around [`simple-scrypt`](https://github.com/elithrar/simple-scrypt).

### Usage

``` go
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
	u.Password //"16384$8$1$b553a4306779af101a75c3e0b085e0e9$4c05fcd11c56ba1560f1b6094e38383b15b9a7ab0126718f7d44a68ab3d53207"
}

```

*Note* This packages API is suited for use with Go structs. For standalone strings, see [`simple-scrypt`](https://github.com/elithrar/simple-scrypt) or [`bcrypt`](https://godoc.org/golang.org/x/crypto/bcrypt).

#### MIT License

Copyright © 2015 &lt;dev@jpillora.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.