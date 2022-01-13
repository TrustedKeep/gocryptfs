package cryptocore

import (
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

// "New" should accept at least these param combinations
func TestCryptoCoreNew(t *testing.T) {
	tkc.Connect("", "", true, true)
	for _, useHKDF := range []bool{true, false} {
		c := New(BackendGoGCM, 96, useHKDF)
		if c.IVLen != 12 {
			t.Fail()
		}
		c = New(BackendGoGCM, 128, useHKDF)
		if c.IVLen != 16 {
			t.Fail()
		}
	}
}
