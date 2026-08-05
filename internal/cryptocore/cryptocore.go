// Package cryptocore wraps OpenSSL and Go GCM crypto and provides
// a nonce generator.
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
var BackendGoGCM = AEADTypeEnum{"AES-GCM-256", "Go", 16}

// BackendXChaCha20Poly1305 specifies XChaCha20-Poly1305-Go.
// "XChaCha20-Poly1305-Go" in gocryptfs -speed.
var BackendXChaCha20Poly1305 = AEADTypeEnum{"XChaCha20-Poly1305", "Go", chacha20poly1305.NonceSizeX}

// CryptoCore is the low level crypto implementation.
type CryptoCore struct {
	// EME is used for filename encryption.
	EMECipher *eme.EMECipher
	// GCM or Chacha - This is used for content encryption.
	AEADCipher cipher.AEAD
	// Which backend is behind AEADCipher?
	AEADBackend AEADTypeEnum
	// GCM needs unique IVs (nonces)
	IVGenerator *nonceGenerator
	// IVLen in bytes
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
//
// Even though the "GCMIV128" feature flag is now mandatory, we must still
// support 96-bit IVs here because they were used for encrypting the master
// key in gocryptfs.conf up to gocryptfs v1.2. v1.3 switched to 128 bits.
func New(key []byte, aeadType AEADTypeEnum, IVBitLen int) *CryptoCore {
	tlog.Debug.Printf("cryptocore.New: key=%d bytes, aeadType=%v, IVBitLen=%d",
		len(key), aeadType, IVBitLen)

	if len(key) != KeyLen {
		log.Panicf("Unsupported key length of %d bytes", len(key))
	}
	if IVBitLen != 96 && IVBitLen != 128 && IVBitLen != chacha20poly1305.NonceSizeX*8 {
		log.Panicf("Unsupported IV length of %d bits", IVBitLen)
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
		if aeadCipher, err = cipher.NewGCMWithNonceSize(blockCipher, IVBitLen/8); err != nil {
			log.Panic(err)
		}
		for i := range gcmKey {
			gcmKey[i] = 0
		}
	} else if aeadType == BackendXChaCha20Poly1305 {
		if IVBitLen != chacha20poly1305.NonceSizeX*8 {
			log.Panicf("XChaCha20-Poly1305 must use 192-bit IVs, you wanted %d", IVBitLen)
		}
		chaKey := hkdfDerive(key, hkdfInfoXChaChaPoly1305Content, chacha20poly1305.KeySize)
		var err error
		if aeadCipher, err = chacha20poly1305.NewX(chaKey); err != nil {
			log.Panic(err)
		}
		for i := range chaKey {
			chaKey[i] = 0
		}
	} else {
		log.Panicf("unknown cipher backend %q", aeadType)
	}

	if aeadCipher.NonceSize()*8 != IVBitLen {
		log.Panicf("Mismatched aeadCipher.NonceSize*8=%d and IVBitLen=%d bits",
			aeadCipher.NonceSize()*8, IVBitLen)
	}

	return &CryptoCore{
		EMECipher:   emeCipher,
		AEADCipher:  aeadCipher,
		AEADBackend: aeadType,
		IVGenerator: newNonceGenerator(IVBitLen / 8),
		IVLen:       IVBitLen / 8,
	}
}

type wiper interface {
	Wipe()
}

// Wipe tries to wipe secret keys from memory by overwriting them with zeros
// and/or setting references to nil.
//
// This is not bulletproof due to possible GC copies, but
// still raises to bar for extracting the key.
func (c *CryptoCore) Wipe() {
	//this is probs just gonna be current change
	tlog.Debug.Printf("CryptoCore.Wipe: Only nil'ing stdlib refs")
	// We have no access to the keys (or key-equivalents) stored inside the
	// Go stdlib. Best we can is to nil the references and force a GC.
	c.AEADCipher = nil
	c.EMECipher = nil
	runtime.GC()
}
