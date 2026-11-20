// Package nametransform encrypts and decrypts filenames.
package nametransform

import (
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// Like ext4, we allow at most 255 bytes for a file name.
	NameMax = 255
)

// emeSet is an immutable snapshot of the name keys this mount holds, indexed by key-ring index.
// A nil entry is a ring entry whose key could not be unwrapped at mount.
type emeSet struct {
	ciphers  []*eme.EMECipher
	writeIdx uint16
}

func newEMESet(ciphers []*eme.EMECipher) *emeSet {
	if len(ciphers) == 0 {
		log.Panic("nametransform: empty cipher set")
	}
	return &emeSet{ciphers: ciphers, writeIdx: uint16(len(ciphers) - 1)}
}

// NameTransform is used to transform filenames.
type NameTransform struct {
	// emeCiphers is swapped wholesale on rotation so the readers on the lookup hot path never
	// take a lock. A name is decrypted under the key that wrote it, selected by the index in
	// the directory's gocryptfs.diriv.
	emeCiphers    atomic.Pointer[emeSet]
	addCipherLock sync.Mutex
	// Names longer than `longNameMax` are hashed. Set to MaxInt when
	// longnames are disabled.
	longNameMax int
	// B64 = either base64.URLEncoding or base64.RawURLEncoding, depending
	// on the Raw64 feature flag
	B64 *base64.Encoding
	// Patterns to bypass decryption
	badnamePatterns    []string
	deterministicNames bool
}

// New returns a new NameTransform instance. "e" holds one EME cipher per key-ring index, with
// nil for an index whose key could not be unwrapped.
//
// If `longNames` is set, names longer than `longNameMax` are hashed to
// `gocryptfs.longname.[sha256]`.
// Pass `longNameMax = 0` to use the default value (255).
func New(e []*eme.EMECipher, longNames bool, longNameMax uint8, raw64 bool, badname []string, deterministicNames bool) *NameTransform {
	tlog.Debug.Printf("nametransform.New: longNameMax=%v, raw64=%v, badname=%q, keys=%d",
		longNameMax, raw64, badname, len(e))
	b64 := base64.URLEncoding
	if raw64 {
		b64 = base64.RawURLEncoding
	}
	b64 = b64.Strict() // Reject non-zero padding bits
	var effectiveLongNameMax int = math.MaxInt32
	if longNames {
		if longNameMax == 0 {
			effectiveLongNameMax = NameMax
		} else {
			effectiveLongNameMax = int(longNameMax)
		}
	}
	n := &NameTransform{
		longNameMax:        effectiveLongNameMax,
		B64:                b64,
		badnamePatterns:    badname,
		deterministicNames: deterministicNames,
	}
	n.emeCiphers.Store(newEMESet(e))
	return n
}

// WriteKeyIdx is the key-ring index new directories are stamped with, and therefore the index
// their filenames are encrypted under.
func (n *NameTransform) WriteKeyIdx() uint16 {
	return n.emeCiphers.Load().writeIdx
}

// AddCipher installs a newly rotated name key as the write key and returns its index. This is
// rotation's entry point on the filename side; existing directories keep the index they were
// created with, so their names stay under the key that wrote them.
func (n *NameTransform) AddCipher(c *eme.EMECipher) uint16 {
	n.addCipherLock.Lock()
	defer n.addCipherLock.Unlock()
	old := n.emeCiphers.Load()
	ciphers := make([]*eme.EMECipher, len(old.ciphers), len(old.ciphers)+1)
	copy(ciphers, old.ciphers)
	es := newEMESet(append(ciphers, c))
	n.emeCiphers.Store(es)
	return es.writeIdx
}

// Wipe drops the references to the EME ciphers. Called at unmount.
//
// It publishes an all-nil snapshot rather than clearing the live one, so a lookup that overlaps a
// wipe sees either the old valid set or a clean hole.
func (n *NameTransform) Wipe() {
	n.addCipherLock.Lock()
	defer n.addCipherLock.Unlock()
	if es := n.emeCiphers.Load(); es != nil {
		n.emeCiphers.Store(newEMESet(make([]*eme.EMECipher, len(es.ciphers))))
	}
}

// ErrKeyMissing reports that this mount holds no name key for a key-ring index. It is separated
// from every other name failure because it says nothing about the name: the names are intact and
// this mount simply cannot read them, so it is an EIO rather than corruption to report to -fsck.
var ErrKeyMissing = errors.New("this mount has no name key for that key-ring index")

// emeCipher selects the EME cipher for a key-ring index. The index comes off disk (a directory's
// gocryptfs.diriv), so an unknown one is an error rather than a panic even on the encrypt side.
func (n *NameTransform) emeCipher(keyIdx uint16) (*eme.EMECipher, error) {
	es := n.emeCiphers.Load()
	if int(keyIdx) >= len(es.ciphers) {
		return nil, fmt.Errorf("%w: names are encrypted under index %d, but this mount holds %d key(s)",
			ErrKeyMissing, keyIdx, len(es.ciphers))
	}
	if c := es.ciphers[keyIdx]; c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("%w: index %d could not be unwrapped at mount", ErrKeyMissing, keyIdx)
}

// DecryptName calls decryptName to try and decrypt a base64-encoded encrypted
// filename "cipherName", and failing that checks if it can be bypassed
func (n *NameTransform) DecryptName(cipherName string, iv []byte, keyIdx uint16) (string, error) {
	res, err := n.decryptName(cipherName, iv, keyIdx)
	if err != nil && n.HaveBadnamePatterns() {
		res, err = n.decryptBadname(cipherName, iv, keyIdx)
	}
	if err != nil {
		return "", err
	}
	if err := IsValidName(res); err != nil {
		tlog.Warn.Printf("DecryptName %q: invalid name after decryption: %v", cipherName, err)
		return "", syscall.EBADMSG
	}
	return res, err
}

// decryptName decrypts a base64-encoded encrypted filename "cipherName" using the
// initialization vector "iv" and the key-ring entry "keyIdx".
func (n *NameTransform) decryptName(cipherName string, iv []byte, keyIdx uint16) (string, error) {
	// From https://pkg.go.dev/encoding/base64#Encoding.Strict :
	// > Note that the input is still malleable, as new line characters
	// > (CR and LF) are still ignored.
	// Check for CR and LF ourselves.
	if strings.ContainsAny(cipherName, "\r\n") {
		return "", errors.New("characters CR or LF in base64")
	}
	bin, err := n.B64.DecodeString(cipherName)
	if err != nil {
		return "", err
	}
	if len(bin) == 0 {
		tlog.Warn.Printf("decryptName: empty input")
		return "", syscall.EBADMSG
	}
	if len(bin)%aes.BlockSize != 0 {
		tlog.Debug.Printf("decryptName %q: decoded length %d is not a multiple of 16", cipherName, len(bin))
		return "", syscall.EBADMSG
	}
	c, err := n.emeCipher(keyIdx)
	if err != nil {
		return "", err
	}
	bin = c.Decrypt(iv, bin)
	bin, err = unPad16(bin)
	if err != nil {
		tlog.Warn.Printf("decryptName %q: unPad16 error: %v", cipherName, err)
		return "", syscall.EBADMSG
	}
	plain := string(bin)
	return plain, err
}

// EncryptName encrypts a file name "plainName" and returns a base64-encoded "cipherName64",
// encrypted using EME (https://github.com/rfjakob/eme).
//
// plainName is checked for null bytes, slashes etc. and such names are rejected
// with an error.
//
// This function is exported because in some cases, fusefrontend needs access
// to the full (not hashed) name if longname is used.
func (n *NameTransform) EncryptName(plainName string, iv []byte, keyIdx uint16) (cipherName64 string, err error) {
	if err := IsValidName(plainName); err != nil {
		tlog.Warn.Printf("EncryptName %q: invalid plainName: %v", plainName, err)
		return "", syscall.EBADMSG
	}
	return n.encryptName(plainName, iv, keyIdx)
}

// encryptName encrypts "plainName" and returns a base64-encoded "cipherName64",
// encrypted using EME (https://github.com/rfjakob/eme).
//
// No checks for null bytes etc are performed against plainName.
func (n *NameTransform) encryptName(plainName string, iv []byte, keyIdx uint16) (cipherName64 string, err error) {
	c, err := n.emeCipher(keyIdx)
	if err != nil {
		return "", err
	}
	bin := []byte(plainName)
	bin = pad16(bin)
	bin = c.Encrypt(iv, bin)
	return n.B64.EncodeToString(bin), nil
}

// EncryptAndHashName encrypts "name" and hashes it to a longname if it is
// too long.
// Returns ENAMETOOLONG if "name" is longer than 255 bytes.
func (be *NameTransform) EncryptAndHashName(name string, iv []byte, keyIdx uint16) (string, error) {
	// Prevent the user from creating files longer than 255 chars.
	if len(name) > NameMax {
		return "", syscall.ENAMETOOLONG
	}
	cName, err := be.EncryptName(name, iv, keyIdx)
	if err != nil {
		return "", err
	}
	if len(cName) > be.longNameMax {
		return be.HashLongName(cName), nil
	}
	return cName, nil
}

// B64EncodeToString returns a Base64-encoded string
func (n *NameTransform) B64EncodeToString(src []byte) string {
	return n.B64.EncodeToString(src)
}

// B64DecodeString decodes a Base64-encoded string
func (n *NameTransform) B64DecodeString(s string) ([]byte, error) {
	return n.B64.DecodeString(s)
}

// Dir is like filepath.Dir but returns "" instead of ".".
func Dir(path string) string {
	d := filepath.Dir(path)
	if d == "." {
		return ""
	}
	return d
}

// GetLongNameMax will return curent `longNameMax`. File name longer than
// this should be hashed.
func (n *NameTransform) GetLongNameMax() int {
	return n.longNameMax
}
