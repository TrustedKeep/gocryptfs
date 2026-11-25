package main

import (
	"bytes"
	"crypto/cipher"
	"errors"
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
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/TrustedKeep/tkutils/v2/security"
	"github.com/coreos/go-systemd/daemon"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/openfiletable"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
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
	// Before anything that a second mount would collide on, so the lock is the error it reports.
	cf, ringLock := openKeyRing(args)
	defer ringLock.Close()

	// We cannot mount "/home/user/.cipher" at "/home/user" because the mount
	// will hide ".cipher" also for us.
	if args.cipherdir == args.mountpoint || strings.HasPrefix(args.cipherdir, args.mountpoint+"/") {
		tlog.Fatal.Printf("Mountpoint %q would shadow cipherdir %q, this is not supported",
			args.mountpoint, args.cipherdir)
		os.Exit(exitcodes.MountPoint)
	}
	// Mounting "/foo" at "/foo/mnt" means the mountpoint would hide part of
	// our own backing storage.
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

	connectKeyService(args, cf)

	args._keyGate = new(keyGate)
	// Initialize gocryptfs (read config file, ask for password, ...)
	fs, rotator, wipeKeys := initFuseFrontend(args)
	// Try to wipe secret keys from memory after unmount
	defer wipeKeys()

	// One timer for the key-service heartbeat and the op-counter flush.
	hb, _ := tkc.DataKey().(tkc.Heartbeater)
	m := &keyServiceMonitor{
		hb:          hb,
		rotator:     rotator,
		readOnly:    args.ro,
		opThreshold: autoRotateThreshold(args),
		mountpoint:  args.mountpoint,
		exit:        os.Exit,
		gate:        args._keyGate,
	}
	// Registered after the wipe so it runs before it: a mount that lived less than one interval
	// would otherwise contribute nothing to the budget its writes spent.
	defer m.flushOpCountsAtUnmount()
	defer m.reportUnmount()
	// Before anything is mounted: a gateway that will not answer a heartbeat cannot revoke this
	// instance either, and a fatal exit here leaves no mountpoint behind.
	m.verifyKeyService()
	// Also before mounting, so a count earlier mounts left past the threshold rotates now.
	m.flushOpCountsBeforeMount()

	// Initialize go-fuse FUSE server
	// The key service already heard this mount, so a mount that fails takes it back.
	srv := initGoFuse(fs, args, m.reportUnmount)
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
	handleSigint(srv, args.mountpoint, func() {
		m.flushOpCountsAtUnmount()
		m.reportUnmount()
	})
	// Return memory that was allocated for stuff that is no longer needed to the OS
	debug.FreeOSMemory()
	// Set up autounmount, if requested.
	if args.idle > 0 {
		fwdFs := fs.(*fusefrontend.RootNode)
		go idleMonitor(args.idle, fwdFs, srv, args.mountpoint)
	}
	startKeyServiceMonitor(m)
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
func initFuseFrontend(args *argContainer) (rootNode fs.InodeEmbedder, rotator *keyRotator, wipeKeys func()) {
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
	// The first mount of a filesystem generates its data key; later mounts unwrap every retained
	// key-ring entry, so data written under a superseded key stays readable.
	keyRing, err := configfile.LoadKeyRing(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot read key ring: %v", err)
		exitcodes.Exit(err)
	}
	var freshKey []byte
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
		freshKey = generateInitialDataKey(args, keyRing, frontendArgs.PlaintextNames, frontendArgs.DeterministicNames)
	}
	// A mint has already adopted the identity. Every later mount gets it here, or its next generate
	// would mint a second KEK.
	if err := tkc.DataKey().AdoptIdentity(keyRing.KekID()); err != nil {
		tlog.Fatal.Printf("%v", err)
		os.Exit(exitcodes.Other)
	}
	// freshKey is nil when the ring already had a key, which is the usual case.
	ks := buildKeySets(keyRing, freshKey, cryptoBackend, IVBits)

	cEnc := contentenc.New(ks.core, ks.aeads, contentenc.DefaultBS)
	nameTransform := nametransform.New(ks.emeCiphers, frontendArgs.LongNames, args.longnamemax,
		args.raw64, []string(args.badname), frontendArgs.DeterministicNames)
	// Spawn fusefrontend
	tlog.Debug.Printf("frontendArgs: %s", tlog.JSONDump(frontendArgs))
	rootNode = fusefrontend.NewRootNode(frontendArgs, cEnc, nameTransform)

	if rotator, err = newKeyRotator(args.config, keyRing, cryptoBackend, IVBits, cEnc, nameTransform); err != nil {
		tlog.Fatal.Printf("%v", err)
		os.Exit(exitcodes.Other)
	}

	// We have opened the socket early so that we cannot fail here after
	// asking the user for the password
	if args._ctlsockFd != nil {
		var rotate func() (uint16, error)
		//a read only mount will never rotate
		if !args.ro {
			rotate = rotator.rotate
		}
		go ctlsocksrv.Serve(args._ctlsockFd, gateCtl(rootNode.(ctlsocksrv.Interface), args._keyGate), rotate)
	}
	return rootNode, rotator, func() {
		// Names first: cEnc.Wipe() forces the one GC, and it can only collect the EME key
		// schedules if their references are already gone.
		nameTransform.Wipe()
		cEnc.Wipe()
		// Release the data-key connector (network connections / bbolt handle).
		if err := tkc.DataKey().Close(); err != nil {
			tlog.Warn.Printf("Error closing data-key connector: %v", err)
		}
	}
}

// keySets is what a mount's key ring unwraps to.
type keySets struct {
	// core is the newest entry's, which is what contentenc reads IVLen from.
	core *cryptocore.CryptoCore
	// aeads and emeCiphers are indexed by ring index.
	aeads      []cipher.AEAD
	emeCiphers []*eme.EMECipher
}

// unwrapAttempts is how many times a failed unwrap is tried before the mount fails. The budget is
// paid per retained entry, so it is kept small.
const unwrapAttempts = 3

// unwrapRetryDelay is the wait before the first retry, doubled after each one. Tests shorten it.
var unwrapRetryDelay = 500 * time.Millisecond

// unwrapDataKey unwraps one ring entry, retrying anything but a refusal (ErrDenied, or rejected
// credentials): that is the key service deciding, and asking again would only repeat the answer.
func unwrapDataKey(dk tkc.DataKeyConnector, idx uint16, e configfile.KeyRingEntry) (key []byte, err error) {
	for attempt := 1; ; attempt++ {
		key, err = dk.UnwrapTKFSDataKey(e.KeyID, e.Ciphertext)
		if err == nil || errors.Is(err, tkc.ErrDenied) || tkc.CredentialsRejected(err) || attempt >= unwrapAttempts {
			return key, err
		}
		delay := unwrapRetryDelay << (attempt - 1)
		tlog.Info.Printf("Key-ring index %d: unwrap attempt %d of %d failed (%v); retrying in %v",
			idx, attempt, unwrapAttempts, err, delay)
		time.Sleep(delay)
	}
}

// unwrapRing fills each nil slot of keys with its ring entry's key: the first alone, since behind a gateway
// requiring binding it binds an unbound instance, then tkc.MaxConns at a time. Once one fails no more start,
// and it returns that failure, wiping the keys it holds.
func unwrapRing(dk tkc.DataKeyConnector, entries []configfile.KeyRingEntry, keys [][]byte) error {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		started  int
	)
	slots := make(chan struct{}, tkc.MaxConns)
	for i, e := range entries {
		if keys[i] != nil {
			continue
		}
		slots <- struct{}{}
		mu.Lock()
		failed := firstErr != nil
		mu.Unlock()
		if failed {
			<-slots
			break
		}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			key, err := unwrapDataKey(dk, uint16(i), e)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("failed to unwrap key-ring index %d: %w", i, err)
			}
			keys[i] = key
		}()
		if started++; started == 1 {
			wg.Wait()
		}
	}
	wg.Wait()
	if firstErr != nil {
		for _, k := range keys {
			clear(k)
		}
	}
	return firstErr
}

// buildKeySets unwraps every retained key-ring entry into the content AEAD and EME name cipher at its
// ring index, exiting if any entry will not unwrap. freshKey, if non-nil, is the plaintext of the entry
// this mount just generated.
func buildKeySets(kr *configfile.KeyRing, freshKey []byte, backend cryptocore.AEADTypeEnum, ivBits int) *keySets {
	activeIdx, err := kr.ActiveIdx()
	if err != nil {
		tlog.Fatal.Printf("%v", err)
		os.Exit(exitcodes.Other)
	}
	keys := make([][]byte, len(kr.All()))
	keys[activeIdx] = freshKey
	if err := unwrapRing(tkc.DataKey(), kr.All(), keys); err != nil {
		tlog.Fatal.Printf("%v", err)
		os.Exit(outageExit(err))
	}
	ks := &keySets{
		aeads:      make([]cipher.AEAD, int(activeIdx)+1),
		emeCiphers: make([]*eme.EMECipher, int(activeIdx)+1),
	}
	for i, key := range keys {
		idx := uint16(i)
		// cryptocore HKDF-derives and caches the EME/content keys, so the master key is no
		// longer needed in memory once the core exists.
		core := cryptocore.New(key, backend, ivBits)
		clear(key)
		ks.aeads[idx] = core.AEADCipher
		ks.emeCiphers[idx] = core.EMECipher
		if idx == activeIdx {
			ks.core = core
		}
	}
	return ks
}

// keyServiceExit is the exit code for a key-service failure that ends the mount: a refusal is a revocation,
// or SharedStorageRefused for -sharedstorage, and anything else exits code. Rejected credentials (a 401,
// or a TLS alert refusing the client certificate) count as a refusal: a restart presents the same
// credentials, so they exit as revoked, which a systemd unit does not restart, wherever the mount meets
// them. A first mount meets them on generate or unwrap, before its first heartbeat.
func keyServiceExit(err error, code int) int {
	switch {
	case errors.Is(err, tkc.ErrSharedStorageRefused):
		return exitcodes.SharedStorageRefused
	case errors.Is(err, tkc.ErrDenied), tkc.CredentialsRejected(err):
		return exitcodes.Revoked
	}
	return code
}

// generateInitialDataKey mints the data key for a freshly initialized filesystem, persists it in
// keyRing and returns its plaintext. It also writes the root gocryptfs.diriv, which needs the ring
// index and so cannot be written by -init.
func generateInitialDataKey(args *argContainer, keyRing *configfile.KeyRing, plaintextNames, deterministicNames bool) []byte {
	ensureCipherdirFresh(args)
	dk, err := tkc.DataKey().GenerateTKFSDataKey()
	if err != nil {
		tlog.Fatal.Printf("Failed to generate the initial data key: %v", err)
		os.Exit(outageExit(err))
	}
	idx, err := keyRing.Append(configfile.KeyRingEntry{
		KeyID:      dk.KeyID,
		Ciphertext: dk.Ciphertext,
		CreatedAt:  dk.CreatedAt,
	})
	if err != nil {
		tlog.Fatal.Printf("Failed to add the initial data key to the key ring: %v", err)
		os.Exit(exitcodes.Other)
	}
	// Before the ring: once a ring is on disk, no later mount comes back here to write it.
	if !plaintextNames {
		if err := writeRootDirIV(args.cipherdir, idx, deterministicNames); err != nil {
			tlog.Fatal.Printf("Failed to create the root %s: %v", nametransform.DirIVFilename, err)
			os.Exit(exitcodes.Init)
		}
	}
	// Persisted before use: nothing may be encrypted under a key that is not recoverable from disk.
	if err := keyRing.WriteFile(); err != nil {
		tlog.Fatal.Printf("Failed to persist the initial key-ring entry: %v", err)
		os.Exit(exitcodes.WriteConf)
	}
	return dk.Plaintext
}

// writeRootDirIV creates and syncs gocryptfs.diriv in the cipherdir root, stamped with keyIdx. A
// leftover one is discarded first: no ring existed, so no name on disk depends on the old IV.
func writeRootDirIV(cipherdir string, keyIdx uint16, deterministicNames bool) error {
	// Open cipherdir (following symlinks)
	dirfd, err := syscall.Open(cipherdir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)
	syscallcompat.Unlinkat(dirfd, nametransform.DirIVFilename, 0)
	if err := nametransform.WriteDirIVAt(dirfd, keyIdx, deterministicNames); err != nil {
		return err
	}
	fd, err := syscallcompat.Openat(dirfd, nametransform.DirIVFilename, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fsync(fd)
}

// ensureCipherdirFresh refuses to mint a new key over existing data: a missing key ring is only
// legitimate while the cipherdir still holds nothing but the files a first mount is allowed to find
// there — the config -init wrote, and whatever a previous first mount got as far as creating.
// Encrypted payload with no key ring means the ring was deleted, the cipherdir was restored from a
// pre-first-mount backup, or it was tampered with — generating a fresh key would leave the existing
// files permanently undecryptable while new writes silently succeed, so fail closed instead.
func ensureCipherdirFresh(args *argContainer) {
	entries, err := os.ReadDir(args.cipherdir)
	if err != nil {
		tlog.Fatal.Printf("Cannot list cipherdir: %v", err)
		os.Exit(exitcodes.CipherDir)
	}
	for _, e := range entries {
		switch e.Name() {
		case configfile.ConfDefaultName, configfile.KeyRingFileName,
			configfile.KeyRingTmpFileName, nametransform.DirIVFilename:
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
// On error, it calls beforeExit, if any, then os.Exit, and does not return.
func initGoFuse(rootNode fs.InodeEmbedder, args *argContainer, beforeExit func()) *fuse.Server {
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
		// A handler panic crashes the mount, as before go-fuse 2.11, instead of answering EIO and serving
		// on with whatever state the panic left behind.
		PanicHandler: func(r any) fuse.Status { panic(r) },
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

	srv, err := mountGated(args.mountpoint, rootNode, fuseOpts, args._keyGate)
	if err != nil {
		tlog.Fatal.Printf("fs.Mount failed: %s", strings.TrimSpace(err.Error()))
		if runtime.GOOS == "darwin" {
			tlog.Info.Printf("Maybe you should run: /Library/Filesystems/osxfuse.fs/Contents/Resources/load_osxfuse")
		}
		if beforeExit != nil {
			beforeExit()
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

func handleSigint(srv *fuse.Server, mountpoint string, beforeExit func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		unmount(srv, mountpoint)
		// This os.Exit skips every doMount defer, and SIGTERM is how a supervisor stops a
		// mount — so the teardown that has to happen is done here instead.
		beforeExit()
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
			fusermountPath, err := getFusermountPath()
			if err != nil {
				tlog.Warn.Printf("lazy unmount failed: %v", err)
				return
			}
			cmd := exec.Command(fusermountPath, "-u", "-z", mountpoint)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				tlog.Info.Printf("lazy unmount failed: %v", err)
			}
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

// openKeyRing loads the config, which names the key service, and locks the key ring, exiting on
// failure. The wait covers the previous mount of this filesystem, which exits once it has reported its unmount.
func openKeyRing(args *argContainer) (*configfile.ConfFile, *os.File) {
	cf, err := loadConfig(args)
	if err != nil {
		exitcodes.Exit(err)
	}
	if err := checkMockKMS(cf.MockKMS, args.mockKMS); err != nil {
		tlog.Fatal.Printf("%v", err)
		os.Exit(exitcodes.Usage)
	}
	ringLock, err := configfile.LockKeyRing(args.config, unmountReportBudget+time.Second)
	if errors.Is(err, configfile.ErrKeyRingInUse) {
		tlog.Fatal.Printf("%s is already mounted by another TKFS process", args.cipherdir)
		os.Exit(exitcodes.AlreadyMounted)
	} else if err != nil {
		// A read-only mount never writes the ring.
		if !args.ro {
			tlog.Fatal.Printf("Cannot lock the key ring: %v", err)
			os.Exit(exitcodes.Other)
		}
		tlog.Warn.Printf("Cannot lock the key ring, so a second mount of this filesystem would not be refused: %v", err)
	}
	return cf, ringLock
}

// connectKeyService connects to cf's key service without an identity, which initFuseFrontend adopts
// from the key ring.
func connectKeyService(args *argContainer, cf *configfile.ConfFile) {
	security.Memlock()
	tkc.Connect(cf.GatewayHost, args.gatewayCertDir, cf.NodeID, cf.MockKMS, cf.MockAWS, cf.IsSearch, args.sharedstorage)
}

func getFusermountPath() (path string, err error) {
	path, err = exec.LookPath("fusermount3")
	if err == nil {
		return path, nil
	}

	path, err = exec.LookPath("fusermount")
	if err == nil {
		return path, nil
	}

	return "", fmt.Errorf("fusermount binary not found: %v", err)
}

// checkMockKMS refuses to mount a filesystem whose config selects the mock key store unless the mount
// command asks for it too. The mock keeps plaintext KEKs in a local file and has no heartbeat or
// revocation, so a production mount must never land on it because of a field in gocryptfs.conf alone,
// whether it was created with -mock-kms or edited afterwards.
func checkMockKMS(configMock, flagMock bool) error {
	if !configMock {
		return nil
	}
	if !flagMock {
		return errors.New("this filesystem uses the mock key store, which is for development only: it keeps " +
			"plaintext keys on local disk and has no revocation. Pass -mock-kms to mount it anyway")
	}
	// Info, not Warn: -wpanic turns a warning into a panic, and every test mount uses the mock.
	tlog.Info.Printf("Mounting with the mock key store: for development only, with no revocation")
	return nil
}
