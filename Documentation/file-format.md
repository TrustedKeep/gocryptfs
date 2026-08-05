File Format
===========

Empty files are stored as empty files.

Non-empty files contain a *Header* and one or more *Data blocks*.

Header
------

	 2 bytes header version (big endian uint16, currently 3)
	 2 bytes key-ring index (big endian uint16)
	16 bytes file id

The key-ring index selects which entry of the `KR` key-ring file this file's content is encrypted
under. TKFS writes 0 today (the ring holds one key); it is reserved so key rotation can retain
several keys without another format break. It is deliberately **not** covered by the AEAD's
associated data: the authentication tag already binds the key that was actually used, so
authenticating the selector would add nothing.

Header version 3 is a TKFS-only format and is a hard break from upstream gocryptfs's version 2
(18-byte header, no key-ring index). Version 2 filesystems are refused, not migrated.

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
