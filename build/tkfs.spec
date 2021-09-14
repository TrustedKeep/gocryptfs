Summary: TrustedKeep Filesystem
Name: tkfs
Version: 0.1
Release: 0
License: Commercial
URL: http://www.trustedkeep.com/
Vendor: Trusted Concepts, Inc.
Requires(post): fuse fuse-libs

%description
Encrypted filesystem powered by TrustedKeep (https://www.trustedkeep.com)

%install
cd $RPM_BUILD_ROOT
mkdir -p usr/local/tkfs/bin
mkdir -p usr/local/tkfs/config
mkdir -p usr/local/tkfs/cipher
mkdir -p usr/local/tkfs/data
mkdir -p usr/lib/systemd/system/

cp /root/build/artifacts/gocryptfs usr/local/tkfs/bin/tkfs
cp /root/build/sample_config.yaml usr/local/tkfs/config
cp /root/build/tkfs.service usr/lib/systemd/system/tkfs.service

%files
/usr/local/tkfs/bin/tkfs
/usr/local/tkfs/config/sample_config.yaml
/usr/lib/systemd/system/tkfs.service

%post
/usr/bin/systemctl enable tkfs
mkdir -p /usr/local/tkfs/cipher
mkdir -p /usr/local/tkfs/data
/usr/local/tkfs/bin/tkfs -init /usr/local/tkfs/cipher