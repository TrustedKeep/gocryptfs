package contentenc

// Per-file header
//
// Format: [ "Version" uint16 big endian ] [ "KeyIdx" uint16 big endian ] [ "Id" 16 random bytes ]

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
)

const (
	// CurrentVersion is the current On-Disk-Format version. TKFS v2 (the KEK wrapped-key model)
	// bumps it from the gocryptfs-v1 value of 2 to 3 as a hard format break: the content AAD no
	// longer carries the per-file envelope tail, and the header gained KeyIdx — so v1/v2
	// filesystems are intentionally unreadable and fail closed. (Distinct from any hypothetical
	// upstream v3.)
	CurrentVersion = 3

	headerVersionLen = 2  // uint16
	headerKeyIdxLen  = 2  // uint16
	headerIDLen      = 16 // 128 bit random file id
	// HeaderLen is the total header length
	HeaderLen = headerVersionLen + headerKeyIdxLen + headerIDLen

	headerKeyIdxOff = headerVersionLen
	headerIDOff     = headerKeyIdxOff + headerKeyIdxLen
)

// FileHeader represents the header stored on each non-empty file.
type FileHeader struct {
	Version uint16
	// KeyIdx selects the key-ring entry this file's content is encrypted under. Phase 2 has a
	// single-entry ring so it is always 0; Phase-3 rotation appends entries and stamps the
	// index of the then-active key into each new file's header, which is what lets old files
	// stay readable under the key they were written with.
	//
	// It is deliberately outside the AAD: the AEAD tag already binds the key that was used, so
	// authenticating the selector would add nothing — a flipped KeyIdx fails authentication
	// either way, exactly like a flipped Version.
	KeyIdx uint16
	ID     []byte
}

// Pack - serialize fileHeader object
func (h *FileHeader) Pack() []byte {
	if len(h.ID) != headerIDLen || h.Version != CurrentVersion {
		log.Panic("FileHeader object not properly initialized")
	}
	buf := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(buf[0:headerVersionLen], h.Version)
	binary.BigEndian.PutUint16(buf[headerKeyIdxOff:headerIDOff], h.KeyIdx)
	copy(buf[headerIDOff:], h.ID)
	return buf

}

// allZeroFileID is preallocated to quickly check if the data read from disk is all zero
var allZeroFileID = make([]byte, headerIDLen)
var allZeroHeader = make([]byte, HeaderLen)

// ParseHeader - parse "buf" into fileHeader object
func ParseHeader(buf []byte) (*FileHeader, error) {
	if len(buf) != HeaderLen {
		return nil, fmt.Errorf("ParseHeader: invalid length, want=%d have=%d", HeaderLen, len(buf))
	}
	if bytes.Equal(buf, allZeroHeader) {
		return nil, fmt.Errorf("ParseHeader: header is all-zero. Header hexdump: %s", hex.EncodeToString(buf))
	}
	var h FileHeader
	h.Version = binary.BigEndian.Uint16(buf[0:headerVersionLen])
	if h.Version != CurrentVersion {
		return nil, fmt.Errorf("ParseHeader: invalid version, want=%d have=%d. Header hexdump: %s",
			CurrentVersion, h.Version, hex.EncodeToString(buf))
	}
	// KeyIdx is range-checked where the key is selected (ContentEnc.aeadForKey), not here: a
	// ring that has shrunk is a key-availability problem, not a malformed header.
	h.KeyIdx = binary.BigEndian.Uint16(buf[headerKeyIdxOff:headerIDOff])
	h.ID = buf[headerIDOff:]
	if bytes.Equal(h.ID, allZeroFileID) {
		return nil, fmt.Errorf("ParseHeader: file id is all-zero. Header hexdump: %s",
			hex.EncodeToString(buf))
	}
	return &h, nil
}

// RandomHeader - create new fileHeader object with random Id, stamped with the key-ring index
// the file's content will be encrypted under.
func RandomHeader(keyIdx uint16) *FileHeader {
	var h FileHeader
	h.Version = CurrentVersion
	h.KeyIdx = keyIdx
	h.ID = cryptocore.RandBytes(headerIDLen)
	return &h
}
