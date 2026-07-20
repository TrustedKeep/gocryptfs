package tkc

import "testing"

func TestKeyspace(t *testing.T) {
	tests := []struct {
		dn, nodeID, want string
	}{
		{"", "node-1", "0:/6:node-1"},
		{"CN=tkfs,O=acme", "node-1", "14:CN=tkfs,O=acme/6:node-1"},
	}
	for _, tc := range tests {
		if got := Keyspace(tc.dn, tc.nodeID); got != tc.want {
			t.Errorf("Keyspace(%q, %q) = %q, want %q", tc.dn, tc.nodeID, got, tc.want)
		}
	}
	// Injective even when a component contains the "/" delimiter.
	if Keyspace("a/b", "c") == Keyspace("a", "b/c") {
		t.Error("Keyspace must not collide when a component contains '/'")
	}
}
