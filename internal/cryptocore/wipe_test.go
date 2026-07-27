package cryptocore

import (
	"bytes"
	"testing"

	"github.com/TrustedKeep/tkutils/v2/lru"
)

func TestWipeCacheZeroizesAndEmpties(t *testing.T) {
	// A nil callback means Remove spawns no async goroutines, so the wipe is fully synchronous
	// and the test stays race-clean. WipeCache does the zeroize itself, not via the callback.
	c := lru.NewLRUCache(4)
	secrets := make([][]byte, 3)
	for i := range secrets {
		b := bytes.Repeat([]byte{byte(0x11 * (i + 1))}, 32)
		secrets[i] = b
		c.Add(string(rune('a'+i)), b)
	}
	if c.Len() != len(secrets) {
		t.Fatalf("precondition: cache len = %d, want %d", c.Len(), len(secrets))
	}

	WipeCache(c)

	if c.Len() != 0 {
		t.Errorf("cache not empty after WipeCache: len = %d", c.Len())
	}
	for i, b := range secrets {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("secret %d not zeroized: %v", i, b)
		}
	}
}

func TestWipeCacheNil(t *testing.T) {
	WipeCache(nil) // must not panic
}
