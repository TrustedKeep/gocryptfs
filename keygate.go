package main

import (
	"maps"
	"os"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// suspendedErrno is what a suspended mount answers file operations with.
const (
	suspendedErrno  = syscall.EACCES
	suspendedStatus = fuse.Status(suspendedErrno)
)

// keyGate suspends a mount's file operations. The key-service monitor sets it; FUSE (gatedFS) and the
// control socket (gatedCtl) check it.
type keyGate struct {
	suspended atomic.Bool
	// halted refuses file operations for the rest of the mount's life, whatever the key service says.
	halted atomic.Bool
	// onHalt, if set, runs on a goroutine of its own when the gate first halts. Set it before serving.
	onHalt func()

	mu sync.Mutex
	// open counts the open file handles per FUSE node.
	open map[uint64]int
	// invalidate is the server's InodeNotify, which drops an inode's cached pages. mountGated sets it
	// before serving, so every reader starts after it; nil without a mount.
	invalidate func(node uint64, off, length int64) fuse.Status
}

// closed reports whether file operations are refused.
func (k *keyGate) closed() bool {
	return k.suspended.Load() || k.halted.Load()
}

// halt suspends file operations until the mount is remounted.
func (k *keyGate) halt() {
	if k.halted.Swap(true) {
		return
	}
	if !k.suspended.Swap(true) {
		k.dropCache()
	}
	if k.onHalt != nil {
		go k.onHalt()
	}
}

// panicHandler answers a FUSE handler's panic by halting gate: serving on from the state the panic left
// is unsafe, and crashing ends the mount, leaving a plain directory for writers to fill. Without a gate it re-panics.
func panicHandler(gate *keyGate, mountpoint string) func(any) fuse.Status {
	return func(r any) fuse.Status {
		if gate == nil {
			panic(r)
		}
		gate.halt()
		tlog.Fatal.Printf("Panic in a file operation: %v\n%s", r, debug.Stack())
		tlog.Fatal.Printf("File operations on %s now fail (%v) until it is remounted.", mountpoint, suspendedErrno)
		return suspendedStatus
	}
}

// opened counts a handle the filesystem just opened. An open that passed the gate before it closed may
// have missed dropCache's snapshot, which is taken under the same lock, so it drops its own pages.
func (k *keyGate) opened(node uint64) {
	k.mu.Lock()
	if k.open == nil {
		k.open = make(map[uint64]int)
	}
	k.open[node]++
	late := k.closed()
	k.mu.Unlock()
	if late {
		k.drop([]uint64{node})
	}
}

func (k *keyGate) released(node uint64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.open[node] > 1 {
		k.open[node]--
	} else {
		delete(k.open, node)
	}
}

// dropCache has the kernel drop, and unmap, the cached pages of every open file, so reading them goes
// through the gate too.
func (k *keyGate) dropCache() {
	k.mu.Lock()
	nodes := slices.Collect(maps.Keys(k.open))
	k.mu.Unlock()
	k.drop(nodes)
}

// drop invalidates each node on a goroutine of its own and returns at once, since the kernel waits out
// any read in flight on the file first, and a read can hang on the backing store.
func (k *keyGate) drop(nodes []uint64) {
	if k.invalidate == nil {
		return
	}
	for _, n := range nodes {
		go func() {
			// ENOENT: the kernel no longer has the inode. EBADF: the mount has ended. Neither has pages.
			if st := k.invalidate(n, 0, 0); st != fuse.OK && st != fuse.ENOENT && st != fuse.EBADF {
				tlog.Warn.Printf("Dropping the cached pages of FUSE node %d failed: %v", n, st)
			}
		}()
	}
}

// gatedFS fails every operation while the gate is suspended, the mountpoint's own stat and statfs
// included, so clients see something is wrong. Only bookkeeping on what is already open or written stays open.
type gatedFS struct {
	fuse.RawFileSystem
	gate *keyGate
	// isIdle is the root's -idle marker, nil if there is none.
	isIdle *atomic.Bool
}

// refused reports whether to fail an operation. A refusal counts as activity, so -idle does not unmount
// a suspended mount that is still being used.
func (g *gatedFS) refused() bool {
	if !g.gate.closed() {
		return false
	}
	if g.isIdle != nil {
		g.isIdle.Store(false)
	}
	return true
}

// gatedCtl refuses the control socket's path translation while suspended, which would otherwise decrypt
// names with the keys still in memory. Status and Rotate stay open.
type gatedCtl struct {
	ctlsocksrv.Interface
	gate *keyGate
}

// gateCtl puts fs behind gatedCtl when gate is non-nil.
func gateCtl(fs ctlsocksrv.Interface, gate *keyGate) ctlsocksrv.Interface {
	if gate == nil {
		return fs
	}
	return gatedCtl{Interface: fs, gate: gate}
}

// The control socket reports an errno only from an *os.PathError.
func (g gatedCtl) EncryptPath(p string) (string, error) {
	if g.gate.closed() {
		return "", &os.PathError{Op: "EncryptPath", Path: p, Err: suspendedErrno}
	}
	return g.Interface.EncryptPath(p)
}

func (g gatedCtl) DecryptPath(p string) (string, error) {
	if g.gate.closed() {
		return "", &os.PathError{Op: "DecryptPath", Path: p, Err: suspendedErrno}
	}
	return g.Interface.DecryptPath(p)
}

// mountGated is fs.Mount, with the raw filesystem behind gatedFS when gate is non-nil.
func mountGated(dir string, root fs.InodeEmbedder, options *fs.Options, gate *keyGate) (*fuse.Server, error) {
	rawFS := fs.NewNodeFS(root, options)
	if gate != nil {
		g := &gatedFS{RawFileSystem: rawFS, gate: gate}
		if rn, ok := root.(*fusefrontend.RootNode); ok {
			g.isIdle = &rn.IsIdle
		}
		rawFS = g
	}
	server, err := fuse.NewServer(rawFS, dir, &options.MountOptions)
	if err != nil {
		return nil, err
	}
	if gate != nil {
		gate.invalidate = server.InodeNotify
	}
	go server.Serve()
	if err := server.WaitMount(); err != nil {
		return nil, err
	}
	return server, nil
}

func (g *gatedFS) Lookup(c <-chan struct{}, h *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Lookup(c, h, name, out)
}

func (g *gatedFS) StatFs(c <-chan struct{}, h *fuse.InHeader, out *fuse.StatfsOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.StatFs(c, h, out)
}

func (g *gatedFS) GetAttr(c <-chan struct{}, in *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.GetAttr(c, in, out)
}

func (g *gatedFS) Statx(c <-chan struct{}, in *fuse.StatxIn, out *fuse.StatxOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Statx(c, in, out)
}

func (g *gatedFS) Access(c <-chan struct{}, in *fuse.AccessIn) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Access(c, in)
}

func (g *gatedFS) SetAttr(c <-chan struct{}, in *fuse.SetAttrIn, out *fuse.AttrOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.SetAttr(c, in, out)
}

func (g *gatedFS) Mknod(c <-chan struct{}, in *fuse.MknodIn, name string, out *fuse.EntryOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Mknod(c, in, name, out)
}

func (g *gatedFS) Mkdir(c <-chan struct{}, in *fuse.MkdirIn, name string, out *fuse.EntryOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Mkdir(c, in, name, out)
}

func (g *gatedFS) Unlink(c <-chan struct{}, h *fuse.InHeader, name string) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Unlink(c, h, name)
}

func (g *gatedFS) Rmdir(c <-chan struct{}, h *fuse.InHeader, name string) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Rmdir(c, h, name)
}

func (g *gatedFS) Rename(c <-chan struct{}, in *fuse.RenameIn, oldName, newName string) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Rename(c, in, oldName, newName)
}

func (g *gatedFS) Link(c <-chan struct{}, in *fuse.LinkIn, name string, out *fuse.EntryOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Link(c, in, name, out)
}

func (g *gatedFS) Symlink(c <-chan struct{}, h *fuse.InHeader, target, name string, out *fuse.EntryOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Symlink(c, h, target, name, out)
}

func (g *gatedFS) Readlink(c <-chan struct{}, h *fuse.InHeader) ([]byte, fuse.Status) {
	if g.refused() {
		return nil, suspendedStatus
	}
	return g.RawFileSystem.Readlink(c, h)
}

func (g *gatedFS) GetXAttr(c <-chan struct{}, h *fuse.InHeader, attr string, dest []byte) (uint32, fuse.Status) {
	if g.refused() {
		return 0, suspendedStatus
	}
	return g.RawFileSystem.GetXAttr(c, h, attr, dest)
}

func (g *gatedFS) ListXAttr(c <-chan struct{}, h *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	if g.refused() {
		return 0, suspendedStatus
	}
	return g.RawFileSystem.ListXAttr(c, h, dest)
}

func (g *gatedFS) SetXAttr(c <-chan struct{}, in *fuse.SetXAttrIn, attr string, data []byte) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.SetXAttr(c, in, attr, data)
}

func (g *gatedFS) RemoveXAttr(c <-chan struct{}, h *fuse.InHeader, attr string) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.RemoveXAttr(c, h, attr)
}

func (g *gatedFS) Create(c <-chan struct{}, in *fuse.CreateIn, name string, out *fuse.CreateOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	st := g.RawFileSystem.Create(c, in, name, out)
	if st.Ok() {
		g.gate.opened(out.NodeId)
	}
	return st
}

func (g *gatedFS) Tmpfile(c <-chan struct{}, in *fuse.CreateIn, out *fuse.CreateOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	st := g.RawFileSystem.Tmpfile(c, in, out)
	if st.Ok() {
		g.gate.opened(out.NodeId)
	}
	return st
}

func (g *gatedFS) Open(c <-chan struct{}, in *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	st := g.RawFileSystem.Open(c, in, out)
	if st.Ok() {
		g.gate.opened(in.NodeId)
	}
	return st
}

// Release is not gated: it only closes a handle.
func (g *gatedFS) Release(c <-chan struct{}, in *fuse.ReleaseIn) {
	g.RawFileSystem.Release(c, in)
	g.gate.released(in.NodeId)
}

func (g *gatedFS) Read(c <-chan struct{}, in *fuse.ReadIn, buf []byte) (fuse.ReadResult, fuse.Status) {
	if g.refused() {
		return nil, suspendedStatus
	}
	return g.RawFileSystem.Read(c, in, buf)
}

func (g *gatedFS) Lseek(c <-chan struct{}, in *fuse.LseekIn, out *fuse.LseekOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Lseek(c, in, out)
}

// writeback reports whether a write flushes pages dirtied through a mapping, which a suspension lets
// through: refusing would only discard them, and with no writeback cache negotiated no other write carries
// the flag. A halted mount refuses them too.
func (g *gatedFS) writeback(in *fuse.WriteIn) bool {
	return in.WriteFlags&fuse.WRITE_CACHE != 0 && !g.gate.halted.Load()
}

func (g *gatedFS) Write(c <-chan struct{}, in *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	if !g.writeback(in) && g.refused() {
		return 0, suspendedStatus
	}
	return g.RawFileSystem.Write(c, in, data)
}

func (g *gatedFS) Writev(c <-chan struct{}, in *fuse.WriteIn, data [][]byte) (uint32, fuse.Status) {
	if !g.writeback(in) && g.refused() {
		return 0, suspendedStatus
	}
	return g.RawFileSystem.Writev(c, in, data)
}

func (g *gatedFS) CopyFileRange(c <-chan struct{}, in *fuse.CopyFileRangeIn) (uint32, fuse.Status) {
	if g.refused() {
		return 0, suspendedStatus
	}
	return g.RawFileSystem.CopyFileRange(c, in)
}

func (g *gatedFS) Fallocate(c <-chan struct{}, in *fuse.FallocateIn) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.Fallocate(c, in)
}

func (g *gatedFS) OpenDir(c <-chan struct{}, in *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.OpenDir(c, in, out)
}

func (g *gatedFS) ReadDir(c <-chan struct{}, in *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.ReadDir(c, in, out)
}

func (g *gatedFS) ReadDirPlus(c <-chan struct{}, in *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	if g.refused() {
		return suspendedStatus
	}
	return g.RawFileSystem.ReadDirPlus(c, in, out)
}
