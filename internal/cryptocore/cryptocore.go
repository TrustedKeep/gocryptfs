// Package cryptocore wraps OpenSSL and Go GCM crypto and provides
// a nonce generator.
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
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
// Even though the "GCMIV128" feature flag is now mandatory, we must still
// support 96-bit IVs here because they were used for encrypting the master
// key in gocryptfs.conf up to gocryptfs v1.2. v1.3 switched to 128 bits.
//wrapped key is only used if we are set up to use enveloping (keypool is-1), otherwise it can be nil or empty
func New(aeadType AEADTypeEnum, IVBitLen, keyPool int, useHKDF bool, rootID string, wrappedKey []byte) *CryptoCore {
	tlog.Debug.Printf("cryptocore.New: aeadType=%v, IVBitLen=%d, useHKDF=%v, keyPool=%d",
		aeadType, IVBitLen, useHKDF, keyPool)

	if IVBitLen != 96 && IVBitLen != 128 && IVBitLen != chacha20poly1305.NonceSizeX*8 {
		log.Panicf("Unsupported IV length of %d bits", IVBitLen)
	}

	var key []byte
	var err error
	//keypool -1 means we are using envelope encryption
	if keyPool == -1 {
		var envKey kem.Kem
		envKey, err = tkc.Get().GetEnvelopeKey(rootID)
		if err != nil {
			log.Panicf("Unable to retrieve filename encryption key envelope key: %v", err)
		}
		key, err = envKey.Unwrap(wrappedKey)
		if err != nil {
			log.Panicf("Unable to unwrap encryption key: %v", err)
		}
	} else {
		key, err = tkc.Get().GetKey([]byte(tkc.NameTransformEnvName))
		if err != nil {
			log.Panicf("Unable to retrieve filename encryption key: %v", err)
		}
	}

	// Initialize EME for filename encryption.
	var emeCipher *eme.EMECipher
	{
		var emeBlockCipher cipher.Block
		if useHKDF {
			emeKey := hkdfDerive(key, hkdfInfoEMENames, KeyLen)
			emeBlockCipher, err = aes.NewCipher(emeKey)
			for i := range emeKey {
				emeKey[i] = 0
			}
		} else {
			emeBlockCipher, err = aes.NewCipher(key)
		}
		if err != nil {
			log.Panic(err)
		}
		emeCipher = eme.New(emeBlockCipher)
	}

	// Initialize an AEAD cipher for file content encryption.
	var aeadCipher cipher.AEAD
	if aeadType == BackendGoGCM {
		aeadCipher = newTkAes(IVBitLen/8, keyPool)
	} else if aeadType == BackendXChaCha20Poly1305 {
		// We don't support legacy modes with XChaCha20-Poly1305
		if IVBitLen != chacha20poly1305.NonceSizeX*8 {
			log.Panicf("XChaCha20-Poly1305 must use 192-bit IVs, you wanted %d", IVBitLen)
		}
		aeadCipher = newTkCha(keyPool)
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
