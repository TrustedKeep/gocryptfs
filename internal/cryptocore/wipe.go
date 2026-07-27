package cryptocore

import (
	cryptoutil "github.com/TrustedKeep/tkutils/v2/crypto"
	"github.com/TrustedKeep/tkutils/v2/lru"
)

// WipeCache deterministically empties an lru key cache, zeroizing every []byte value it holds
// before dropping it. It exists because neither lru teardown primitive guarantees the key bytes
// are gone when it returns: Purge/Destory drop entries without firing the eviction callback at
// all, and Remove fires it asynchronously (go c.cb(...)). WipeCache instead zeroizes each value
// synchronously, so the secret is cleared by the time the caller continues — intended for the
// unmount teardown of the KEK-derived key caches (wired in a later phase).
func WipeCache(c *lru.Cache) {
	if c == nil {
		return
	}
	for _, k := range c.Keys() {
		if v, ok := c.Peek(k); ok {
			if b, ok := v.([]byte); ok {
				cryptoutil.Zeroize(b)
			}
		}
		c.Remove(k)
	}
}
