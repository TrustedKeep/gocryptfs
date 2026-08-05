package main

import (
	"bytes"
	"fmt"
	"log"
	"log/syslog"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/TrustedKeep/tkutils/v2/security"
	"github.com/coreos/go-systemd/daemon"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/openfiletable"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// AfterUnmounter is called after the filesystem has been unmounted.
// This can be used for cleanup and printing statistics.
type AfterUnmounter interface {
	AfterUnmount()
}

// const EnvSetUpFlag = "CEK" //created envelope key, if this file exists, it means the current envelope key has already been created
// doMount mounts an encrypted directory.
// Called from main.
func doMount(args *argContainer) {
	// Check mountpoint
	var err error
	args.mountpoint, err = filepath.Abs(flagSet.Arg(1))
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(exitcodes.MountPoint)
	}
	// A config file is mandatory: it names the key service and carries the NodeID that scopes
	// the keyspace, and there is no password or master-key path to fall back on.
	cf, err := loadConfig(args)
	if err != nil {
		exitcodes.Exit(err)
	}

	// We cannot mount "/home/user/.cipher" at "/home/user" because the mount
	// will hide ".cipher" also for us.
	if args.cipherdir == args.mountpoint || strings.HasPrefix(args.cipherdir, args.mountpoint+"/") {
		tlog.Fatal.Printf("Mountpoint %q would shadow cipherdir %q, this is not supported",
			args.mountpoint, args.cipherdir)
		os.Exit(exitcodes.MountPoint)
	}
	// Reverse-mounting "/foo" at "/foo/mnt" means we would be recursively
	// encrypting ourselves.
	if strings.HasPrefix(args.mountpoint, args.cipherdir+"/") {
		tlog.Fatal.Printf("Mountpoint %q is contained in cipherdir %q, this is not supported",
			args.mountpoint, args.cipherdir)
		os.Exit(exitcodes.MountPoint)
	}
	if args.nonempty {
		err = isDir(args.mountpoint)
	} else if strings.HasPrefix(args.mountpoint, "/dev/fd/") {
		// Magic fuse fd syntax, do nothing and let go-fuse figure it out.
		//
		// See https://github.com/libfuse/libfuse/commit/64e11073b9347fcf9c6d1eea143763ba9e946f70
		// and `drop_privileges` in `man mount.fuse3` for background.
	} else {
		err = isEmptyDir(args.mountpoint)
		// OSXFuse will create the mountpoint for us ( https://github.com/rfjakob/gocryptfs/issues/194 )
		if runtime.GOOS == "darwin" && os.IsNotExist(err) {
			tlog.Info.Printf("Mountpoint %q does not exist, but should be created by OSXFuse",
				args.mountpoint)
			err = nil
		}
	}
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(exitcodes.MountPoint)
	}
	// Bind the health-check port for the same reason the control socket is opened early, one step
	// below: a failure here must happen before anything is mounted, or the fatal exit would leave
	// a live mountpoint attached with no process behind it.
	healthCheckLn := listenHealthCheck(args.healthCheckPort)
	// Open control socket early so we can error out before asking the user
	// for the password
	if args.ctlsock != "" {
		// We must use an absolute path because we cd to / when daemonizing.
		// This messes up the delete-on-close logic in the unix socket object.
		args.ctlsock, _ = filepath.Abs(args.ctlsock)

		args._ctlsockFd, err = ctlsocksrv.Listen(args.ctlsock)
		if err != nil {
			tlog.Fatal.Printf("ctlsock: %v", err)
			os.Exit(exitcodes.CtlSock)
		}
		// Close also deletes the socket file
		defer func() {
			err = args._ctlsockFd.Close()
			if err != nil {
				tlog.Warn.Printf("ctlsock close: %v", err)
			}
		}()
	}

	// connect to KMS
	security.Memlock()
	tkc.Connect(cf.GatewayHost, args.gatewayCertDir, cf.NodeID, cf.MockKMS, cf.MockAWS, cf.IsSearch)

	// Initialize gocryptfs (read config file, ask for password, ...)
	fs, wipeKeys := initFuseFrontend(args)
	// Try to wipe secret keys from memory after unmount
	defer wipeKeys()
	// Initialize go-fuse FUSE server
	srv := initGoFuse(fs, args)
	if x, ok := fs.(AfterUnmounter); ok {
		defer x.AfterUnmount()
	}

	// Start serving before we tell anyone we are ready: a supervisor that probes the moment it
	// sees the ready signal would otherwise race us and get a connection refused. The port was
	// bound long before this, so all that is left is to accept on it.
	serveHealthCheck(healthCheckLn)

	tlog.Info.Println(tlog.ColorGreen + "Filesystem mounted and ready." + tlog.ColorReset)

	// We have been forked into the background, as evidenced by the set
	// "notifypid".
	// Do what daemons should do: https://man7.org/linux/man-pages/man7/daemon.7.html
	if args.notifypid > 0 {
		// Chdir to the root directory so we don't block unmounting the CWD
		os.Chdir("/")
		// Disconnect from the controlling terminal by creating a new session.
		// This prevents us from getting SIGINT when the user presses Ctrl-C
		// to exit a running script that has called gocryptfs, or SIGHUP when
		// xfce4-terminal closes itself ( https://github.com/rfjakob/gocryptfs/issues/660 ).
		_, err = syscall.Setsid()
		if err != nil {
			tlog.Warn.Printf("Setsid: %v", err)
		}
		// Switch to syslog
		if !args.nosyslog {
			// Switch all of our logs and the generic logger to syslog
			tlog.Info.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_INFO)
			tlog.Debug.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_DEBUG)
			tlog.Warn.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
			tlog.Fatal.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_CRIT)
			tlog.SwitchLoggerToSyslog()
			// Daemons should redirect stdin, stdout and stderr
			redirectStdFds()
		}
		// Send SIGUSR1 to our parent
		sendUsr1(args.notifypid)
	}
	// Increase the open file limit to 4096. This is not essential, so do it after
	// we have switched to syslog and don't bother the user with warnings.
	setOpenFileLimit()
	// Wait for SIGINT in the background and unmount ourselves if we get it.
	// This prevents a dangling "Transport endpoint is not connected"
	// mountpoint if the user hits CTRL-C.
	handleSigint(srv, args.mountpoint)
	// Return memory that was allocated for stuff that is no longer needed to the OS
	debug.FreeOSMemory()
	// Set up autounmount, if requested.
	if args.idle > 0 {
		// Not being in reverse mode means we always have a forward file system.
		fwdFs := fs.(*fusefrontend.RootNode)
		go idleMonitor(args.idle, fwdFs, srv, args.mountpoint)
	}
	// Wait for unmount.
	tlog.Info.Printf("Notifying systemd that TKFS is ready.")
	daemon.SdNotify(false, daemon.SdNotifyReady)
	srv.Wait()
}

// defaultHealthCheckPort is where the liveness endpoint lands when -health-check-port is not given.
const defaultHealthCheckPort = 8000

// resolveHealthCheckPort maps a -health-check-port value onto the port to bind.
//
// Zero is treated as unset, not as a request: it is the int zero value, so "-health-check-port=0"
// and passing no flag at all are the same statement, and it would be a trap for one to mean
// something the other does not. Disabling is therefore a **negative** value — out of band, since no
// real port is negative. Zero also does not mean "pick an ephemeral port": an endpoint on a port
// nobody can predict is useless to a supervisor.
func resolveHealthCheckPort(port int) (resolved int, enabled bool) {
	if port < 0 {
		return 0, false
	}
	if port == 0 {
		return defaultHealthCheckPort, true
	}
	return port, true
}

// listenHealthCheck binds the health-check port, or dies trying. A mount nobody can probe is
// invisible to whatever is supervising it, and the usual cause of a bind failure — another mount
// already holding the port — means one of the two is misconfigured; carrying on would leave the
// operator with a filesystem whose liveness answers for a different mount than they think.
//
// A negative port disables the endpoint — the opt-out for stacking several mounts on one host, and
// what the test suite passes.
func listenHealthCheck(portArg int) net.Listener {
	port, enabled := resolveHealthCheckPort(portArg)
	if !enabled {
		tlog.Info.Printf("Health checks disabled (-health-check-port=%d)", portArg)
		return nil
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		tlog.Fatal.Printf("Cannot serve health checks on port %d: %v", port, err)
		os.Exit(exitcodes.HealthCheck)
	}
	return ln
}

// serveHealthCheck answers on the already-bound listener. Split from the bind so the bind can fail
// early, before there is a mount to leave behind.
func serveHealthCheck(ln net.Listener) {
	if ln == nil {
		return
	}
	tlog.Info.Printf("Serving health checks on %v", ln.Addr())
	pingSvr := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() {
		if err := pingSvr.Serve(ln); err != nil {
			tlog.Info.Printf("Health check server stopped: %v", err)
		}
	}()
}

// Based on the EncFS idle monitor:
// https://github.com/vgough/encfs/blob/1974b417af189a41ffae4c6feb011d2a0498e437/encfs/main.cpp#L851
// idleMonitor is a function to be run as a thread that checks for
// filesystem idleness and unmounts if we've been idle for long enough.
const checksDuringTimeoutPeriod = 4

func idleMonitor(idleTimeout time.Duration, fs *fusefrontend.RootNode, srv *fuse.Server, mountpoint string) {
	// sleepNs is the sleep time between checks, in nanoseconds.
	sleepNs := contentenc.MinUint64(
		uint64(idleTimeout/checksDuringTimeoutPeriod),
		uint64(2*time.Minute))
	timeoutCycles := int(math.Ceil(float64(idleTimeout) / float64(sleepNs)))
	idleCount := 0
	idleTime := func() time.Duration {
		return time.Duration(sleepNs * uint64(idleCount))
	}
	for {
		// Atomically check whether the flag is 0 and reset it to 1 if so.
		isIdle := !fs.IsIdle.CompareAndSwap(false, true)
		// Any form of current or recent access resets the idle counter.
		openFileCount := openfiletable.CountOpenFiles()
		if !isIdle || openFileCount > 0 {
			idleCount = 0
		} else {
			idleCount++
		}
		tlog.Debug.Printf(
			"idleMonitor: idle for %v (idleCount = %d, isIdle = %t, open = %d)",
			idleTime(), idleCount, isIdle, openFileCount)
		if idleCount > 0 && idleCount%timeoutCycles == 0 {
			tlog.Info.Printf("idleMonitor: filesystem idle; unmounting: %s", mountpoint)
			err := srv.Unmount()
			if err != nil {
				// We get "Device or resource busy" when a process has its
				// working directory on the mount. Log the event at Info level
				// so the user finds out why their filesystem does not get
				// unmounted.
				tlog.Info.Printf("idleMonitor: unmount failed: %v. Resetting idle time.", err)
				idleCount = 0
			}
		}
		time.Sleep(time.Duration(sleepNs))
	}
}

// setOpenFileLimit tries to increase the open file limit to 4096 (the default hard
// limit on Linux).
func setOpenFileLimit() {
	var lim syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	if err != nil {
		tlog.Warn.Printf("Getting RLIMIT_NOFILE failed: %v", err)
		return
	}
	if lim.Cur >= 4096 {
		return
	}
	lim.Cur = 4096
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	if err != nil {
		tlog.Warn.Printf("Setting RLIMIT_NOFILE to %+v failed: %v", lim, err)
		//         %+v output: "{Cur:4097 Max:4096}" ^
	}
}

// initFuseFrontend - initialize gocryptfs/internal/fusefrontend
// Calls os.Exit on errors
func initFuseFrontend(args *argContainer) (rootNode fs.InodeEmbedder, wipeKeys func()) {
	confFile, err := loadConfig(args)
	if err != nil {
		// Exit with the code the error carries (configfile.Load reports an unsupported
		// on-disk format as DeprecatedFS) rather than panicking. -fsck reaches this path on
		// an old-format filesystem, and a panic there would report exit code 2 and a stack
		// trace instead of the real reason.
		exitcodes.Exit(err)
	}

	// Reconciliate CLI and config file arguments into a fusefrontend.Args struct
	// that is passed to the filesystem implementation
	cryptoBackend := cryptocore.BackendGoGCM
	IVBits := contentenc.DefaultIVBits
	if args.xchacha {
		cryptoBackend = cryptocore.BackendXChaCha20Poly1305
		IVBits = chacha20poly1305.NonceSizeX * 8
	}
	// forceOwner implies allow_other, as documented.
	// Set this early, so args.allow_other can be relied on below this point.
	if args._forceOwner != nil {
		args.allow_other = true
	}
	frontendArgs := fusefrontend.Args{
		Cipherdir:          args.cipherdir,
		PlaintextNames:     args.plaintextnames,
		LongNames:          args.longnames,
		ConfigCustom:       args._configCustom,
		NoPrealloc:         args.noprealloc,
		ForceOwner:         args._forceOwner,
		Suid:               args.suid,
		KernelCache:        args.kernel_cache,
		SharedStorage:      args.sharedstorage,
		OneFileSystem:      args.one_file_system,
		DeterministicNames: args.deterministic_names,
	}
	// Settings from the config file override command line args
	frontendArgs.PlaintextNames = confFile.IsFeatureFlagSet(configfile.FlagPlaintextNames)
	frontendArgs.DeterministicNames = !confFile.IsFeatureFlagSet(configfile.FlagDirIV)
	// Things that don't have to be in frontendArgs are only in args
	args.longnamemax = confFile.LongNameMax
	args.raw64 = confFile.IsFeatureFlagSet(configfile.FlagRaw64)

	// Note: this will always return the non-openssl variant
	cryptoBackend, err = confFile.ContentEncryption()
	if err != nil {
		tlog.Fatal.Printf("%v", err)
		exitcodes.Exit(err)
	}
	IVBits = cryptoBackend.NonceSize * 8
	// If allow_other is set and we run as root, create files as the accessing
	// user.
	// Except when -force_owner is set, because in this case the user may
	// not have write permissions. And the point of -force_owner is to map uids,
	// so we want the files on the backing dir to get the uid the gocryptfs process
	// is running as.
	if args.allow_other && os.Getuid() == 0 && args._forceOwner == nil {
		frontendArgs.PreserveOwner = true
	}
	// Obtain the 32-byte master key through the data-key connector (established by
	// tkc.Connect in doMount). First mount of a freshly initialized filesystem (no key-ring
	// file): generate the data key now and persist its ciphertext. Later mounts: unwrap the
	// active key-ring entry. Either way the gateway holds the KEK and the plaintext never
	// crosses the wire in the clear.
	keyRing, err := configfile.LoadKeyRing(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot read key ring: %v", err)
		exitcodes.Exit(err)
	}
	var masterKey []byte
	if len(keyRing.Keys) == 0 {
		// The first mount has to write the generated key's ciphertext into the cipherdir, which
		// happens before the FUSE mount exists and is therefore outside the kernel's read-only
		// enforcement. Refuse rather than write anyway: that also means a never-mounted
		// filesystem on read-only media fails here with a clear message instead of at the
		// persist call. Mount it writable once first. (fsck sets -ro, so it hits this too.)
		if args.ro {
			tlog.Fatal.Printf("This filesystem has no data key yet, and the first mount must persist one; " +
				"mount it writable once before mounting read-only")
			os.Exit(exitcodes.Usage)
		}
		masterKey, keyRing = generateInitialDataKey(args)
	}
	// masterKey is nil when the ring already has a key (the usual case), or when a concurrent
	// first mount won the generate race while we waited on the lock.
	if masterKey == nil {
		active, err := keyRing.Active()
		if err != nil {
			tlog.Fatal.Printf("%v", err)
			os.Exit(exitcodes.Other)
		}
		if masterKey, err = tkc.DataKey().UnwrapTKFSDataKey(active.KeyID, active.Ciphertext); err != nil {
			tlog.Fatal.Printf("Failed to unwrap the gateway data key: %v", err)
			os.Exit(exitcodes.Other)
		}
	}

	// Init crypto backend, then zeroize our copy of the master key: cryptocore has HKDF-derived
	// and cached the EME/content keys it needs, so the master key is no longer required in memory
	// (a single active key; multi-key retention for rotation is Phase 3).
	cCore := cryptocore.New(masterKey, cryptoBackend, IVBits)
	for i := range masterKey {
		masterKey[i] = 0
	}
	cEnc := contentenc.New(cCore, contentenc.DefaultBS)
	nameTransform := nametransform.New(cCore.EMECipher, frontendArgs.LongNames, args.longnamemax,
		args.raw64, []string(args.badname), frontendArgs.DeterministicNames)
	// Spawn fusefrontend
	tlog.Debug.Printf("frontendArgs: %s", tlog.JSONDump(frontendArgs))
	rootNode = fusefrontend.NewRootNode(frontendArgs, cEnc, nameTransform)

	// We have opened the socket early so that we cannot fail here after
	// asking the user for the password
	if args._ctlsockFd != nil {
		go ctlsocksrv.Serve(args._ctlsockFd, rootNode.(ctlsocksrv.Interface))
	}
	return rootNode, func() {
		cCore.Wipe()
		// Release the data-key connector (network connections / bbolt handle).
		if err := tkc.DataKey().Close(); err != nil {
			tlog.Warn.Printf("Error closing data-key connector: %v", err)
		}
	}
}

// generateInitialDataKey mints and persists the data key for a freshly initialized filesystem
// (no key-ring file) and returns its plaintext, plus the ring as re-loaded under the lock. If the
// ring turns out to be populated once we hold the lock, the returned key is nil and the caller
// unwraps that entry instead. The ciphertext is persisted before the key is used: nothing may be
// encrypted under a key that is not recoverable from disk.
//
// The lock is taken on gocryptfs.conf. Not on the key-ring file, which is the file we are about to
// create — there is nothing to lock yet, and creating it early would expose a zero-length ring to a
// concurrent mount. The config is the one file guaranteed to exist for the life of the filesystem,
// which makes it the natural rendezvous, and Phase-3 rotation can take the same lock.
//
// flock is advisory and conflicts only with another flock() on the same inode, so this blocks
// nothing except a second TKFS first-mount: no read, write, open or readdir anywhere in the
// cipherdir is affected, and the lock is released before the FUSE mount comes up. What it buys:
// two mounts of the same never-mounted cipherdir would otherwise each generate a key, and
// everything the loser of the write race encrypted would be silently orphaned by the winner's ring.
// What it does NOT buy: mounts on different hosts sharing storage (this fork has -sharedstorage),
// where flock does not carry.
func generateInitialDataKey(args *argContainer) ([]byte, *configfile.KeyRing) {
	confFd, err := os.Open(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot open config file for locking: %v", err)
		os.Exit(exitcodes.OpenConf)
	}
	// Close also releases the flock. Flock blocks (no LOCK_NB) — a competing first mount waits
	// here rather than failing, which is the point: the loser then unwraps the winner's entry
	// instead of erroring out of an otherwise valid mount.
	defer confFd.Close()
	if err := syscall.Flock(int(confFd.Fd()), syscall.LOCK_EX); err != nil {
		tlog.Fatal.Printf("Cannot lock config file: %v", err)
		os.Exit(exitcodes.OpenConf)
	}
	// Re-load under the lock: a competing first mount may have generated and persisted while
	// we waited.
	keyRing, err := configfile.LoadKeyRing(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot read key ring: %v", err)
		exitcodes.Exit(err)
	}
	if len(keyRing.Keys) > 0 {
		return nil, keyRing
	}
	ensureCipherdirFresh(args)
	dk, err := tkc.DataKey().GenerateTKFSDataKey()
	if err != nil {
		tlog.Fatal.Printf("Failed to generate the initial data key: %v", err)
		os.Exit(exitcodes.Other)
	}
	keyRing.Keys = []configfile.KeyRingEntry{{
		KeyID:      dk.KeyID,
		Ciphertext: dk.Ciphertext,
		CreatedAt:  time.Now().UTC(),
	}}
	if err := keyRing.WriteFileUnderLock(); err != nil {
		tlog.Fatal.Printf("Failed to persist the initial key-ring entry: %v", err)
		os.Exit(exitcodes.WriteConf)
	}
	return dk.Plaintext, keyRing
}

// ensureCipherdirFresh refuses to mint a new key over existing data: a missing key ring is only
// legitimate while the cipherdir still looks exactly as -init left it (config + diriv, nothing
// else). Encrypted payload with no key ring means the ring was deleted, the cipherdir was
// restored from a pre-first-mount backup, or it was tampered with — generating a fresh key would
// leave the existing files permanently undecryptable while new writes silently succeed, so fail
// closed instead.
func ensureCipherdirFresh(args *argContainer) {
	entries, err := os.ReadDir(args.cipherdir)
	if err != nil {
		tlog.Fatal.Printf("Cannot list cipherdir: %v", err)
		os.Exit(exitcodes.CipherDir)
	}
	for _, e := range entries {
		switch e.Name() {
		case configfile.ConfDefaultName, configfile.KeyRingFileName,
			configfile.KeyRingFileName + ".tmp", nametransform.DirIVFilename:
			continue
		}
		tlog.Fatal.Printf("Cipherdir %q contains %q but there is no key ring; refusing to generate a new key over existing data",
			args.cipherdir, e.Name())
		os.Exit(exitcodes.CipherDir)
	}
}

type RootInoer interface {
	RootIno() uint64
}

// initGoFuse calls into go-fuse to mount `rootNode` on `args.mountpoint`.
// The mountpoint is ready to use when the functions returns.
// On error, it calls os.Exit and does not return.
func initGoFuse(rootNode fs.InodeEmbedder, args *argContainer) *fuse.Server {
	var fuseOpts *fs.Options
	sec := time.Second
	if args.sharedstorage {
		// sharedstorage mode sets all cache timeouts to zero so changes to the
		// backing shared storage show up immediately.
		// Hard links are disabled by using automatically incrementing
		// inode numbers provided by go-fuse.
		fuseOpts = &fs.Options{
			FirstAutomaticIno: 1000,
		}
	} else {
		fuseOpts = &fs.Options{
			// These options are to be compatible with libfuse defaults,
			// making benchmarking easier.
			NegativeTimeout: &sec,
			AttrTimeout:     &sec,
			EntryTimeout:    &sec,
		}
	}
	fuseOpts.NullPermissions = true
	// The inode number for the root node must be manually set on mount
	// https://github.com/hanwen/go-fuse/issues/399
	fuseOpts.RootStableAttr = &fs.StableAttr{Ino: rootNode.(RootInoer).RootIno()}
	// Enable go-fuse warnings
	fuseOpts.Logger = log.New(os.Stderr, "go-fuse: ", log.Lmicroseconds)
	fuseOpts.MountOptions = fuse.MountOptions{
		// Writes and reads are usually capped at 128kiB on Linux through
		// the FUSE_MAX_PAGES_PER_REQ kernel constant in fuse_i.h. Our
		// sync.Pool buffer pools are sized acc. to the default. Users may set
		// the kernel constant higher, and Synology NAS kernels are known to
		// have it >128kiB. We cannot handle more than 128kiB, so we tell
		// the kernel to limit the size explicitly.
		MaxWrite:  fuse.MAX_KERNEL_WRITE,
		Debug:     args.fusedebug,
		EnableAcl: args.acl,
		// Attempt to directly call mount(2) before trying fusermount. This means we
		// can do without fusermount if running as root.
		DirectMount: true,
	}

	mOpts := &fuseOpts.MountOptions
	opts := make(map[string]string)
	if args.allow_other {
		tlog.Info.Printf("%s", tlog.ColorYellow+"The option \"-allow_other\" is set. Make sure the file "+
			"permissions protect your data from unwanted access."+tlog.ColorReset)
		mOpts.AllowOther = true
		// Make the kernel check the file permissions for us
		opts["default_permissions"] = ""
	}
	// fusermount from libfuse 3.x removed the "nonempty" option and exits
	// with an error if it sees it. Only add it to the options on libfuse 2.x.
	if args.nonempty && haveFusermount2() {
		opts["nonempty"] = ""
	}
	// Set values shown in "df -T" and friends
	// First column, "Filesystem"
	fsname := args.cipherdir
	if args.fsname != "" {
		fsname = args.fsname
	}
	fsname2 := strings.Replace(fsname, ",", "_", -1)
	if fsname2 != fsname {
		tlog.Warn.Printf("Warning: %q will be displayed as %q in \"df -T\"", fsname, fsname2)
		fsname = fsname2
	}
	mOpts.FsName = fsname
	// Second column, "Type", will be shown as "fuse." + Name
	mOpts.Name = "gocryptfs"
	// Add a volume name if running osxfuse. Otherwise the Finder will show it as
	// something like "osxfuse Volume 0 (gocryptfs)".
	if runtime.GOOS == "darwin" {
		opts["volname"] = strings.Replace(path.Base(args.mountpoint), ",", "_", -1)
	}
	// The kernel enforces read-only operation, we just have to pass "ro".
	if args.ro {
		opts["ro"] = ""
	} else if args.rw {
		opts["rw"] = ""
	}
	// If both "nosuid" & "suid", "nodev" & "dev", etc were passed, the safer
	// option wins.
	if args.nosuid {
		opts["nosuid"] = ""
	} else if args.suid {
		opts["suid"] = ""
	}
	if args.nodev {
		opts["nodev"] = ""
	} else if args.dev {
		opts["dev"] = ""
	}
	if args.noexec {
		opts["noexec"] = ""
	} else if args.exec {
		opts["exec"] = ""
	}
	if args.context != "" {
		opts["context"] = args.context
	}
	// Add additional mount options (if any) after the stock ones, so the user has
	// a chance to override them.
	if args.ko != "" {
		parts := strings.Split(args.ko, ",")
		tlog.Debug.Printf("Adding -ko mount options: %v", parts)
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				opts[kv[0]] = kv[1]
			} else {
				opts[kv[0]] = ""
			}
		}
	}
	for k, v := range opts {
		if v == "" {
			mOpts.Options = append(mOpts.Options, k)
		} else {
			mOpts.Options = append(mOpts.Options, k+"="+v)
		}
	}

	srv, err := fs.Mount(args.mountpoint, rootNode, fuseOpts)
	if err != nil {
		tlog.Fatal.Printf("fs.Mount failed: %s", strings.TrimSpace(err.Error()))
		if runtime.GOOS == "darwin" {
			tlog.Info.Printf("Maybe you should run: /Library/Filesystems/osxfuse.fs/Contents/Resources/load_osxfuse")
		}
		os.Exit(exitcodes.FuseNewServer)
	}

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	return srv
}

// haveFusermount2 finds out if the "fusermount" binary is from libfuse 2.x.
func haveFusermount2() bool {
	path, err := exec.LookPath("fusermount")
	if err != nil {
		path = "/bin/fusermount"
	}
	cmd := exec.Command(path, "-V")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		tlog.Warn.Printf("warning: haveFusermount2: %v", err)
		return false
	}
	// libfuse 2: fusermount version: 2.9.9
	// libfuse 3: fusermount3 version: 3.9.0
	v := out.String()
	return strings.HasPrefix(v, "fusermount version")
}

func handleSigint(srv *fuse.Server, mountpoint string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		unmount(srv, mountpoint)
		os.Exit(exitcodes.SigInt)
	}()
}

// unmount() calls srv.Unmount(), and if that fails, calls "fusermount -u -z"
// (lazy unmount).
func unmount(srv *fuse.Server, mountpoint string) {
	err := srv.Unmount()
	if err != nil {
		tlog.Warn.Printf("unmount: srv.Unmount returned %v", err)
		if runtime.GOOS == "linux" {
			// MacOSX does not support lazy unmount
			tlog.Info.Printf("Trying lazy unmount")
			cmd := exec.Command("fusermount", "-u", "-z", mountpoint)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
		}
	}
}

// loadConfig loads the config file `args.config`
func loadConfig(args *argContainer) (cf *configfile.ConfFile, err error) {
	// First check if the file can be read at all.
	cf, err = configfile.Load(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot open config file: %v", err)
		return nil, err
	}
	return cf, nil
}
