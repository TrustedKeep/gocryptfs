package contentenc

import (
	"fmt"
	"testing"

	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

type testRange struct {
	offset uint64
	length uint64
}

func TestSplitRange(t *testing.T) {
	id, wrapped, err := createTKKeys()
	if err != nil {
		t.Fatalf("Couldn't set up tk: %v", err)
	}
	var ranges []testRange

	ranges = append(ranges, testRange{0, 70000},
		testRange{0, 10},
		testRange{234, 6511},
		testRange{65444, 54},
		testRange{0, 1024 * 1024},
		testRange{0, 65536},
		testRange{6654, 8945})

	cc := cryptocore.New(cryptocore.BackendGoGCM, DefaultIVBits, 0, true, id, wrapped)
	f := New(cc, DefaultBS)

	for _, r := range ranges {
		parts := f.ExplodePlainRange(r.offset, r.length)
		var lastBlockNo uint64 = 1 << 63
		for _, p := range parts {
			if p.BlockNo == lastBlockNo {
				t.Errorf("Duplicate block number %d", p.BlockNo)
			}
			lastBlockNo = p.BlockNo
			if p.Length > DefaultBS || p.Skip >= DefaultBS {
				t.Errorf("Test fail: n=%d, length=%d, offset=%d\n", p.BlockNo, p.Length, p.Skip)
			}
		}
	}
}

func TestCiphertextRange(t *testing.T) {
	id, wrapped, err := createTKKeys()
	if err != nil {
		t.Fatalf("Couldn't set up tk: %v", err)
	}
	var ranges []testRange

	ranges = append(ranges, testRange{0, 70000},
		testRange{0, 10},
		testRange{234, 6511},
		testRange{65444, 54},
		testRange{6654, 8945})

	cc := cryptocore.New(cryptocore.BackendGoGCM, DefaultIVBits, 0, true, id, wrapped)
	f := New(cc, DefaultBS)

	for _, r := range ranges {

		blocks := f.ExplodePlainRange(r.offset, r.length)
		alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
		skipBytes := blocks[0].Skip

		if alignedLength < r.length {
			t.Errorf("alignedLength=%d is smaller than length=%d", alignedLength, r.length)
		}
		if (alignedOffset-HeaderLen)%f.cipherBS != 0 {
			t.Errorf("alignedOffset=%d is not aligned", alignedOffset)
		}
		if r.offset%f.plainBS != 0 && skipBytes == 0 {
			t.Errorf("skipBytes=0")
		}
	}
}

func TestBlockNo(t *testing.T) {
	id, wrapped, err := createTKKeys()
	if err != nil {
		t.Fatalf("Couldn't set up tk: %v", err)
	}
	cc := cryptocore.New(cryptocore.BackendGoGCM, DefaultIVBits, 0, true, id, wrapped)
	f := New(cc, DefaultBS)

	b := f.CipherOffToBlockNo(788)
	if b != 0 {
		t.Errorf("actual: %d", b)
	}
	b = f.CipherOffToBlockNo(HeaderLen + f.cipherBS)
	if b != 1 {
		t.Errorf("actual: %d", b)
	}
	b = f.PlainOffToBlockNo(788)
	if b != 0 {
		t.Errorf("actual: %d", b)
	}
	b = f.PlainOffToBlockNo(f.plainBS)
	if b != 1 {
		t.Errorf("actual: %d", b)
	}
}

func createTKKeys() (id string, wrapped []byte, err error) {
	tkc.Connect("", "", true, true)
	id, kem, err := tkc.Get().CreateEnvelopeKey(kem.RSA2048.String(), "")
	if err != nil {
		err = fmt.Errorf("couldnt create env key err: %v\n", err)
	}

	_, wrapped, err = kem.Wrap()
	if err != nil {
		err = fmt.Errorf("wrapping key err: %v\n", err)
	}
	return
}
