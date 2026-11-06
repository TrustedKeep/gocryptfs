package ctlsock

// RequestStruct is sent by a client (encoded as JSON).
// You cannot perform both encryption and decryption in the same request.
type RequestStruct struct {
	// EncryptPath is the path that should be encrypted.
	EncryptPath string
	// DecryptPath is the path that should be decrypted.
	DecryptPath string
	// Rotate asks the mount to generate a new data key, append it to the key ring and
	// encrypt new data under it. Existing data is not re-encrypted; it stays readable under
	// the key that wrote it. Cannot be combined with the path operations.
	Rotate bool
	// Status asks the mount to report the degraded state it can be in without failing: the
	// key-ring indices it could not unwrap. Cannot be combined with the other operations.
	Status bool
}

// ResponseStruct is sent by the server in response to a request
// (encoded as JSON).
type ResponseStruct struct {
	// Result is the resulting decrypted or encrypted path. Empty on error.
	Result string
	// KeyIdx is the key-ring index of the newly generated key, in response to Rotate. A
	// rotation never produces index 0, so its absence means "not a rotation response".
	KeyIdx uint16 `json:",omitempty"`
	// KeyHoles are the key-ring indices this mount could not unwrap at mount time, in response
	// to Status. Everything written under them fails with EIO, those directories will not list
	// and those symlinks and xattr values will not decrypt, until the mount is remounted with
	// the key service reachable. Absent when there are none.
	KeyHoles []uint16 `json:",omitempty"`
	// ErrNo is the error number as defined in errno.h.
	// 0 means success and -1 means that the error number is not known
	// (look at ErrText in this case).
	ErrNo int32
	// ErrText is a detailed error message.
	ErrText string
	// WarnText contains warnings that may have been encountered while
	// processing the message.
	WarnText string
}
