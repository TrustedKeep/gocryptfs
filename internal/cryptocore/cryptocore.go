// Package cryptocore builds the content AEAD and the EME name cipher from a master key.
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// KeyLen is the cipher key length in bytes. All backends use 32 bytes.
	KeyLen = 32
	// AuthTagLen is the length of a authentication tag in bytes.
	// All backends use 16 bytes.
	AuthTagLen = 16
)

// AEADTypeEnum indicates the type of AEAD backend in use.
type AEADTypeEnum struct {
	// Algo is the encryption algorithm. Example: "AES-GCM-256"
	Algo string
	// Lib is the library where Algo is implemented. Either "Go" or "OpenSSL".
	Lib       string
	NonceSize int
}

// String returns something like "AES-GCM-256-OpenSSL"
func (a AEADTypeEnum) String() string {
	return a.Algo + "-" + a.Lib
}

// BackendGoGCM specifies the Go based AES-256-GCM backend.
// "AES-GCM-256-Go" in gocryptfs -speed.
var BackendGoGCM = AEADTypeEnum{"AES-GCM-256", "Go", 12}

// BackendXChaCha20Poly1305 specifies XChaCha20-Poly1305-Go.
// "XChaCha20-Poly1305-Go" in gocryptfs -speed.
var BackendXChaCha20Poly1305 = AEADTypeEnum{"XChaCha20-Poly1305", "Go", chacha20poly1305.NonceSizeX}

// CryptoCore is the low level crypto implementation.
type CryptoCore struct {
	// EME is used for filename encryption.
	EMECipher *eme.EMECipher
	// AEADCipher encrypts file content. Seal draws a random nonce and prepends it, and Open reads
	// it back from the front, so callers pass a nil nonce to both.
	AEADCipher cipher.AEAD
	// Which backend is behind AEADCipher?
	AEADBackend AEADTypeEnum
	// IVLen is the length in bytes of the nonce AEADCipher prepends.
	IVLen int
}

// New returns a new CryptoCore object or panics.
//
// "key" is the master key: in the TKFS KEK model this is the 32-byte AES-256 data key
// unwrapped from the on-disk key ring (gateway-issued). The EME (filename) key and the content
// key are always HKDF-derived from it, so the master key is never used directly for encryption.
// The caller retains ownership of "key" and should zeroize it once the CryptoCore is built.
//
// The derivation is not optional. Upstream gocryptfs can skip it, but only to read filesystems
// created by v0.7 through v1.2; this fork's format is a hard break with no such filesystems, so
// there is nothing to be compatible with. It is also load-bearing rather than ceremonial: EME
// uses its key as a raw AES-ECB key over attacker-chosen filenames, while GCM uses its key for
// AES-CTR keystream. Were they the same key, a filename block that collided with a
// nonce‖counter value would expose that GCM keystream block as EME ciphertext on disk, which
// decrypts file content. Two independent derived keys remove that path entirely.
func New(key []byte, aeadType AEADTypeEnum, IVBitLen int) *CryptoCore {
	tlog.Debug.Printf("cryptocore.New: key=%d bytes, aeadType=%v, IVBitLen=%d",
		len(key), aeadType, IVBitLen)

	if len(key) != KeyLen {
		log.Panicf("Unsupported key length of %d bytes", len(key))
	}
	if IVBitLen != aeadType.NonceSize*8 {
		log.Panicf("%s must use %d-bit IVs, you wanted %d", aeadType, aeadType.NonceSize*8, IVBitLen)
	}

	// Initialize EME for filename encryption.
	var emeCipher *eme.EMECipher
	{
		emeKey := hkdfDerive(key, hkdfInfoEMENames, KeyLen)
		emeBlockCipher, err := aes.NewCipher(emeKey)
		for i := range emeKey {
			emeKey[i] = 0
		}
		if err != nil {
			log.Panic(err)
		}
		emeCipher = eme.New(emeBlockCipher)
	}

	// Initialize an AEAD cipher for file content encryption. The content key is HKDF-derived
	// from the master key and the AEAD is built once — there is no per-block key fetch.
	var aeadCipher cipher.AEAD
	if aeadType == BackendGoGCM {
		gcmKey := hkdfDerive(key, hkdfInfoGCMContent, KeyLen)
		blockCipher, err := aes.NewCipher(gcmKey)
		if err != nil {
			log.Panic(err)
		}
		// The only GCM construction the Go FIPS 140-3 module approves for caller-chosen keys.
		if aeadCipher, err = cipher.NewGCMWithRandomNonce(blockCipher); err != nil {
			log.Panic(err)
		}
		for i := range gcmKey {
			gcmKey[i] = 0
		}
	} else if aeadType == BackendXChaCha20Poly1305 {
		chaKey := hkdfDerive(key, hkdfInfoXChaChaPoly1305Content, chacha20poly1305.KeySize)
		x, err := chacha20poly1305.NewX(chaKey)
		if err != nil {
			log.Panic(err)
		}
		aeadCipher = randomNonceAEAD{x}
		for i := range chaKey {
			chaKey[i] = 0
		}
	} else {
		log.Panicf("unknown cipher backend %q", aeadType)
	}

	if aeadCipher.NonceSize() != 0 || aeadCipher.Overhead() != IVBitLen/8+AuthTagLen {
		log.Panicf("%s: NonceSize=%d Overhead=%d, want 0 and %d",
			aeadType, aeadCipher.NonceSize(), aeadCipher.Overhead(), IVBitLen/8+AuthTagLen)
	}

	return &CryptoCore{
		EMECipher:   emeCipher,
		AEADCipher:  aeadCipher,
		AEADBackend: aeadType,
		IVLen:       IVBitLen / 8,
	}
}

// Wipe drops the references to the ciphers and forces a GC.
func (c *CryptoCore) Wipe() {
	tlog.Debug.Printf("CryptoCore.Wipe: Only nil'ing stdlib refs")
	// We have no access to the keys (or key-equivalents) stored inside the
	// Go stdlib. Best we can is to nil the references and force a GC.
	c.AEADCipher = nil
	c.EMECipher = nil
	runtime.GC()
}
