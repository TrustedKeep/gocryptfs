package speed

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

/*
Make the "-speed" benchmarks also accessible to the standard test system.
Example run:

$ go test -bench .
BenchmarkStupidGCM-2   	  100000	     22552 ns/op	 181.62 MB/s
BenchmarkGoGCM-2       	   20000	     81871 ns/op	  50.03 MB/s
PASS
ok  	github.com/rfjakob/gocryptfs/v2/internal/speed	6.022s
*/

func BenchmarkGoGCM(b *testing.B) {
	bGoGCM(b)
}

func BenchmarkGoGCMDecrypt(b *testing.B) {
	gAES, err := aes.NewCipher(randBytes(32))
	if err != nil {
		b.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		b.Fatal(err)
	}
	bDecrypt(b, gGCM)
}

func BenchmarkXchacha(b *testing.B) {
	bXchacha20poly1305(b)
}

func BenchmarkXchachaDecrypt(b *testing.B) {
	c, _ := chacha20poly1305.NewX(randBytes(32))
	bDecrypt(b, c)
}
