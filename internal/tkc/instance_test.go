package tkc

import "testing"

// The identity arrives either from the generate that mints the KEK or from the key ring a later
// mount reads it back from, and nothing may change it afterwards.
func TestInstanceIdentityAdopt(t *testing.T) {
	var i instanceIdentity
	if err := i.adopt(""); err != nil || i.get() != "" {
		t.Errorf("adopting nothing = (%q, %v), want (\"\", nil)", i.get(), err)
	}
	if err := i.adopt("kek-1"); err != nil || i.get() != "kek-1" {
		t.Fatalf("first adopt = (%q, %v), want (kek-1, nil)", i.get(), err)
	}
	// A rotation returns the id it sent, which is what this looks like.
	if err := i.adopt("kek-1"); err != nil {
		t.Errorf("re-adopting the same id: %v", err)
	}
	// An empty id never clears one that is set.
	if err := i.adopt(""); err != nil || i.get() != "kek-1" {
		t.Errorf("adopting nothing over an identity = (%q, %v), want it unchanged", i.get(), err)
	}
	if err := i.adopt("kek-2"); err == nil {
		t.Error("a conflicting id must be an error, not a silently kept first value")
	}
	if i.get() != "kek-1" {
		t.Errorf("identity = %q, want it unchanged after a refused adopt", i.get())
	}
}
