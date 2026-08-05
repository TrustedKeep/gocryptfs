// Package exitcodes contains all well-defined exit codes that gocryptfs
// can return.
package exitcodes

import (
	"errors"
	"os"
)

const (
	// Usage - usage error like wrong cli syntax, wrong number of parameters.
	Usage = 1
	// 2 is reserved because it is used by Go panic
	// 3 is reserved because it was used by earlier gocryptfs version as a generic
	// "mount" error.

	// CipherDir means that the CIPHERDIR does not exist, is not empty, or is not
	// a directory.
	CipherDir = 6
	// Init is an error on filesystem init
	Init = 7
	// LoadConf is an error while loading gocryptfs.conf
	LoadConf = 8
	// ReadPassword means something went wrong reading the password
	ReadPassword = 9
	// MountPoint error means that the mountpoint is invalid (not empty etc).
	MountPoint = 10
	// Other error - please inspect the message
	Other = 11
	// PasswordIncorrect - the password was incorrect when mounting or when
	// changing the password.
	PasswordIncorrect = 12
	// skip 14 (was MasterKey, "-masterkey" is not supported in this fork)
	// SigInt means we got SIGINT
	SigInt = 15
	// PanicLogNotEmpty means the panic log was not empty when we were unmounted
	PanicLogNotEmpty = 16
	// ForkChild means forking the worker child failed
	ForkChild = 17
	// OpenSSL means you tried to enable OpenSSL, but we were compiled without it.
	OpenSSL = 18
	// FuseNewServer - this exit code means that the call to fuse.NewServer failed.
	// This usually means that there was a problem executing fusermount, or
	// fusermount could not attach the mountpoint to the kernel.
	FuseNewServer = 19
	// CtlSock - the control socket file could not be created.
	CtlSock = 20
	// Downgraded to a warning in gocryptfs v1.4
	//PanicLogCreate = 21

	// PasswordEmpty - we received an empty password
	PasswordEmpty = 22
	// OpenConf - the was an error opening the gocryptfs.conf file for reading
	OpenConf = 23
	// WriteConf - could not write the gocryptfs.conf
	WriteConf = 24
	// Profiler - error occurred when trying to write cpu or memory profile or
	// execution trace
	Profiler = 25
	// FsckErrors - the filesystem check found errors
	FsckErrors = 26
	// DeprecatedFS - this filesystem is deprecated
	DeprecatedFS = 27
	// skip 28
	// skip 29 (was ExcludeError, "-exclude" is not supported in this fork)
	// DevNull means that /dev/null could not be opened
	DevNull = 30
	// HealthCheck - the health-check port could not be bound. Usually another mount already
	// holds it; pass -health-check-port to move it, or a negative value to opt out.
	HealthCheck = 31
)

// Err wraps an error with an associated numeric exit code
type Err struct {
	error
	code int
}

// NewErr returns an error containing "msg" and the exit code "code".
func NewErr(msg string, code int) Err {
	return Err{
		error: errors.New(msg),
		code:  code,
	}
}

// Code returns the exit code carried by the error.
func (e Err) Code() int {
	return e.code
}

// Exit extracts the numeric exit code from "err" (if available) and exits the
// application.
func Exit(err error) {
	err2, ok := err.(Err)
	if !ok {
		os.Exit(Other)
	}
	os.Exit(err2.code)
}
