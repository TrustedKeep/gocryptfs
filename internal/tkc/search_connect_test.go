package tkc

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/TrustedKeep/tkutils/v2/kem"
)

// keyURL must pick the Nexus Search endpoint only in nexus mode, and the keep tenantek
// path otherwise — preserving the keep URLs exactly so existing deployments are unchanged.
func TestKeyURL(t *testing.T) {
	cases := []struct {
		name  string
		nexus bool
		host  string
		keyID string
		want  string
	}{
		{"nexus by id", true, "nexus:9082", "abc-123", "https://nexus:9082/envelopekey/abc-123"},
		{"nexus current", true, "nexus:9082", "", "https://nexus:9082/envelopekey/current"},
		{"keep by id", false, "kms", "abc-123", "https://kms:7070/keepsvc/tenantek/retrieve/abc-123"},
		{"keep current", false, "kms", "", fmt.Sprintf("https://kms:7070/keepsvc/tenantek/current/%d", kem.RSA3072)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := keyURL(tc.nexus, tc.host, tc.keyID); got != tc.want {
				t.Fatalf("keyURL(%v, %q, %q) = %q, want %q", tc.nexus, tc.host, tc.keyID, got, tc.want)
			}
		})
	}
}

// Only an exact, whitespace-trimmed "nexus" enables nexus mode; everything else is keep.
func TestParseProvider(t *testing.T) {
	cases := map[string]bool{
		"nexus":     true,
		"nexus\n":   true,
		"  nexus  ": true,
		"":          false,
		"keep":      false,
		"NEXUS":     false,
		"nexus-x":   false,
	}
	for in, want := range cases {
		if got := parseProvider([]byte(in)); got != want {
			t.Errorf("parseProvider(%q) = %v, want %v", in, got, want)
		}
	}
}

// Run with -race: newClient swaps the shared state (via setState) while fetchKey reads it
// (via snapshot) concurrently. Without the mutex a torn slice read could panic; -race
// also flags the unsynchronized access. Guards against a future lock regression.
func TestSearchConnector_ConcurrentAccess(t *testing.T) {
	sc := &searchConnector{}
	const iters = 2000
	var wg sync.WaitGroup

	writer := func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			hosts := make([]string, (i%5)+1) // varying length to expose torn reads
			for j := range hosts {
				hosts[j] = "h"
			}
			sc.setState(&http.Client{}, "tok", hosts, i%2 == 0, time.Time{})
			sc.SetCurrentKeyID("k")
		}
	}
	reader := func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_, _, _, hosts := sc.snapshot()
			for x := range hosts {
				_ = hosts[x] // index every element; a torn slice header would panic
			}
			_ = sc.GetCurrentKeyID()
		}
	}

	for n := 0; n < 4; n++ {
		wg.Add(2)
		go writer()
		go reader()
	}
	wg.Wait()
}
