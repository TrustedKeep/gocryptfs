package cryptocore

import (
	"testing"

	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

// "New" should accept at least these param combinations
func TestCryptoCoreNew(t *testing.T) {
	tkc.Connect("", "", true, true, false)
	id, kem, err := tkc.Get().CreateEnvelopeKey(kem.RSA2048.String(), "")
	if err != nil {
		t.Fatalf("couldnt create env key err: %v\n", err)
	}

	_, wrapped, err := kem.Wrap()
	if err != nil {
		t.Fatalf("wrapping key err: %v\n", err)
	}
	for _, useHKDF := range []bool{true, false} {
		c := New(BackendGoGCM, 96, 0, useHKDF, id, wrapped)
		if c.IVLen != 12 {
			t.Fail()
		}
		c = New(BackendGoGCM, 128, 0, useHKDF, id, wrapped)
		if c.IVLen != 16 {
			t.Fail()
		}
	}
}
