# hashedpassword

A small Go package for hashed passwords

### Usage

``` go
package main

type User struct {
	Password Pwd
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
	u.Password //"LCRALThZUJ+C0HI/RRKyHHwCB0+RYUB8:ZskA0uebN7vaTSzA4jsSLJ5t5iYh/7K/OchudH9gvoKgjQU2"
}
```

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