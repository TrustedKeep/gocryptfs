File Format
===========

Empty files are stored as empty files.

Non-empty files contain a *Header* and one or more *Data blocks*.

Key-ring indices
----------------

The `KR` key-ring file next to `gocryptfs.conf` holds one entry per data key the filesystem has
ever been given. Rotation appends an entry and switches new writes to it; nothing already on disk
is re-encrypted, so old objects stay readable under the key that wrote them. One gateway KEK wraps every
entry of a filesystem — it is minted once, on the first generate, and every rotation names it again — so
`KeyID` repeats across the whole ring and never identifies an entry; `Ciphertext`, the wrapped data key, is
what does. That repeated `KeyID` is also the filesystem's **identity**: it is the id of the KEK, which is
what the instance reports to the gateway as its `InstanceID`, so `KR` and not `gocryptfs.conf` is where a
filesystem's identity lives. Every entry naming the same KEK is an invariant the ring is validated
against at load. Rotation is triggered by
the `-ctlsock` `Rotate` command, by a rekey the heartbeat carries back from the key service, or by the active
entry's `OpCount` — a persisted count of the encrypt operations performed under the current key,
which the mount accumulates and flushes on the heartbeat timer and once more at unmount. The count is
also checked before a mount serves anything, so a count inherited at or past the threshold rotates first.
An entry's `CreatedAt` is the key service's time for its key, returned by the generate that produced it
and never taken from the local clock. The heartbeat reports the active entry's, and the key service
judges a pending rekey against it: any key created after the request satisfies it, and none before does.

`KR.tmp` is reserved alongside `KR` and `gocryptfs.conf`: the ring is replaced atomically, so it exists
in the cipherdir root for the length of every write. Anything that enumerates that directory has to skip
all three, and `-plaintextnames` reserves all three names in the root.

Every encrypted object therefore carries an explicit **key-ring index**, a big-endian `uint16`,
which is the entry's **position** in `KR`. There is no trial decryption anywhere, and a missing
index is an error, never a default of 0. Because an index is a position, entries are only ever
appended: removing or reordering one would silently remap every object written under a later key.

| Object | Key | Where the index is |
|---|---|---|
| Regular file content | content | `KeyIdx` in the 20-byte file header |
| Symlink target | content | 2-byte prefix inside the base64 blob |
| Xattr value | content | 2-byte prefix on the raw value |
| Filename | name (EME) | the directory's `gocryptfs.diriv` |
| Xattr name | name (EME) | the inode's `user.gocryptfs_keyidx.<n>` marker, see below |
| Long-name `.name` sidecar | name (EME) | inherits its directory's index |

Objects with no ciphertext carry no index: empty xattr values, empty symlink targets, zero-length
files, and all-zero (sparse) ciphertext blocks.

Xattr names carry their index on the inode rather than in the name: an empty backing xattr named
`user.gocryptfs_keyidx.<n>` (decimal), written by the inode's first encrypted xattr and never
changed. A filename is a property of a directory entry, but an xattr name is a property of an
*inode*, and a rename or a hard link moves or shares the inode without touching its xattrs, so no
location-derived index could address them. The index is in the marker's name because listing names
needs no read permission. `Listxattr` hides the marker; an inode with encrypted names and no marker,
or more than one marker, is corrupt.

Header
------

	 2 bytes header version (big endian uint16, currently 3)
	 2 bytes key-ring index (big endian uint16)
	16 bytes file id

The key-ring index is deliberately **not** covered by the AEAD's associated data: the
authentication tag already binds the key that was actually used, so authenticating the selector
would add nothing.

Header version 3 is a TKFS-only format and is a hard break from upstream gocryptfs's version 2
(18-byte header, no key-ring index). Version 2 filesystems are refused, not migrated.

gocryptfs.diriv
---------------

One per directory, in every mode except `-plaintextnames`:

	16 bytes IV (all-zero with -deterministic-names, random otherwise)
	 2 bytes key-ring index (big endian uint16)

A 16-byte file is an error, not "index absent, assume 0". The IV file is where the index for
filenames has to live: a filename *is* its ciphertext, and lookup runs the cipher forward, so the
reader must choose a key before it has anything to test. The directory's IV file is read and
cached before any name in that directory is encrypted.

`-deterministic-names` writes the file too, with the all-zero IV that mode implies, purely so the
index has a carrier. `-plaintextnames` has no diriv at all, and needs none: xattr names are the only
EME-encrypted objects left in that mode, and they carry their index on the inode.

The root diriv is created by the **first mount**, not by `-init`: `-init` never contacts the key
service, so there is no ring yet and no index to write. It is written before the ring, so a ring on disk
implies a root diriv; a leftover diriv with no ring is replaced by the next first mount.

Symlink target
--------------

	base64( key-ring index 2B || nonce 16B || ciphertext || tag 16B )

The index is inside the base64 so the stored target stays a single token with no separator to
parse. The empty target is stored as the empty string and carries no index.

Xattr value
-----------

	key-ring index 2B || nonce 16B || ciphertext || tag 16B

Raw bytes, not base64. The empty value is stored empty and carries no index.

Data block, default AES-GCM mode
--------------------------------

	16 bytes GCM IV (nonce)
	1-4096 bytes encrypted data
	16 bytes GHASH

Overhead = (16+16)/4096 = 1/128 = 0.78125 %

Data block, AES-SIV mode
------------------------

AES-SIV is used in reverse mode, or when explicitly enabled with `-init -aessiv`.

	16 bytes nonce
	16 bytes SIV
	1-4096 bytes encrypted data

Overhead = (16+16)/4096 = 1/128 = 0.78125 %

Data block, XChaCha20-Poly1305
------------------------------

Enabled via `-init -xchacha`

	24 bytes nonce
	1-4096 bytes encrypted data
	16 bytes Poly1305 tag

Overhead = (24+16)/4096 = 0.98 %

Examples
========

0-byte file (all modes)
-----------------------

	(empty)

Total: 0 bytes

1-byte file, AES-GCM and AES-SIV mode
-------------------------------------

	Header     20 bytes
	Data block 33 bytes

Total: 53 bytes

5000-byte file, , AES-GCM and AES-SIV mode
------------------------------------------

	Header       20 bytes
	Data block 4128 bytes
	Data block  936 bytes

Total: 5084 bytes

1-byte file, XChaCha20-Poly1305 mode
------------------------------------

	Header     20 bytes
	Data block 41 bytes

Total: 61 bytes

5000-byte file, XChaCha20-Poly1305 mode
---------------------------------------

	Header       20 bytes
	Data block 4136 bytes
	Data block  944 bytes

Total: 5100 bytes

See Also
========

https://nuetzlich.net/gocryptfs/forward_mode_crypto/ / https://github.com/rfjakob/gocryptfs-website/blob/master/docs/forward_mode_crypto.md
