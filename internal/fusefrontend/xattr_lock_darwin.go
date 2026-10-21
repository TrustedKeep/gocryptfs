package fusefrontend

import "syscall"

// lockXattrStamp is a no-op: -sharedstorage is refused outside Linux.
func (n *Node) lockXattrStamp() (unlock func(), errno syscall.Errno) {
	return func() {}, 0
}
