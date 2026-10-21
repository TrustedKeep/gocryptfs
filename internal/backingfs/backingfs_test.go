//go:build linux

package backingfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	rootExt4  = `29 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw,errors=remount-ro`
	rootNFS3  = `29 1 0:40 / / rw,relatime shared:1 - nfs fileserver:/root rw,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=10.0.0.10,mountvers=3,mountport=20048,mountproto=udp,local_lock=none,addr=10.0.0.10`
	proc      = `30 29 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw`
	tmp       = `35 29 0:32 / /tmp rw,nosuid,nodev shared:17 - tmpfs tmpfs rw,size=16384k,nr_inodes=1048576,inode64`
	dataXFS   = `40 29 253:1 / /data rw,noatime shared:20 - xfs /dev/mapper/vg-data rw,attr2,inode64,logbufs=8,logbsize=32k,noquota`
	efs       = `512 29 0:58 / /mnt/efs rw,relatime shared:280 - nfs4 127.0.0.1:/ rw,vers=4.1,rsize=1048576,wsize=1048576,namlen=255,hard,noresvport,proto=tcp,port=20049,timeo=600,retrans=2,sec=sys,clientaddr=127.0.0.1,local_lock=none,addr=127.0.0.1`
	nfs3      = `513 29 0:59 / /mnt/nfs rw,relatime shared:281 - nfs fileserver:/export rw,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=10.0.0.10,mountvers=3,mountport=20048,mountproto=udp,local_lock=none,addr=10.0.0.10`
	cifs      = `514 29 0:60 / /mnt/smb rw,relatime shared:282 - cifs //fileserver/share rw,vers=3.1.1,cache=strict,username=u,uid=1000,noforceuid,gid=1000,noforcegid,addr=10.0.0.10,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1,closetimeo=1`
	smb3      = `514 29 0:60 / /mnt/smb rw,relatime shared:282 - smb3 //fileserver/share rw,vers=3.1.1,cache=strict,username=u,uid=1000,addr=10.0.0.10,soft,nounix,serverino,mapposix`
	s3fs      = `515 29 0:61 / /mnt/s3 rw,nosuid,nodev,relatime shared:283 - fuse.s3fs s3fs rw,user_id=0,group_id=0,allow_other`
	overlay   = `516 29 0:62 / /mnt/ovl rw,relatime shared:284 - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w`
	spaceNFS  = `517 29 0:63 / /mnt/my\040share rw,relatime shared:285 - nfs4 fileserver:/export rw,vers=4.0,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.0.0.5,local_lock=none,addr=10.0.0.10`
	spaceExt4 = `518 29 259:3 / /mnt/my\040disk rw,relatime shared:286 - ext4 /dev/nvme1n1p1 rw`
)

func nfs4(opts string) string {
	return `600 29 0:70 / /mnt/nfs rw,relatime shared:300 - nfs4 fileserver:/export rw,` + opts +
		`,rsize=1048576,wsize=1048576,namlen=255,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.0.0.5,addr=10.0.0.10`
}

func TestCheckShared(t *testing.T) {
	tests := []struct {
		name    string
		mounts  []string
		path    string
		wantErr string // substring of the error; empty means the path passes
	}{
		{"ext4 root", []string{rootExt4, proc, tmp}, "/home/u/cipher", ""},
		{"tmpfs", []string{rootNFS3, proc, tmp}, "/tmp/cipher", ""},
		{"path is the mount point", []string{rootNFS3, tmp}, "/tmp", ""},
		{"nfs4 4.2 hard", []string{rootExt4, nfs4("vers=4.2,hard,local_lock=none")}, "/mnt/nfs/c", ""},
		{"efs", []string{rootExt4, efs}, "/mnt/efs/c", ""},
		{"nfs4 local_lock absent", []string{rootExt4, nfs4("vers=4.1,hard")}, "/mnt/nfs/c", ""},
		{"nfs4 softreval is not soft", []string{rootExt4, nfs4("vers=4.2,hard,softreval,local_lock=none")}, "/mnt/nfs/c", ""},
		{"nfs4 4.0", []string{rootExt4, nfs4("vers=4.0,hard,local_lock=none")}, "/mnt/nfs/c", "nfs4 at \"/mnt/nfs\" is not safe for -sharedstorage: vers=4.0"},
		{"nfs4 4", []string{rootExt4, nfs4("vers=4,hard,local_lock=none")}, "/mnt/nfs/c", "vers=4,"},
		{"nfs4 no vers", []string{rootExt4, nfs4("hard,local_lock=none")}, "/mnt/nfs/c", "no vers"},
		{"nfs4 soft", []string{rootExt4, nfs4("vers=4.2,soft,local_lock=none")}, "/mnt/nfs/c", "nfs4 at \"/mnt/nfs\" is not safe for -sharedstorage: mounted soft"},
		{"nfs4 softerr", []string{rootExt4, nfs4("vers=4.2,softerr,local_lock=none")}, "/mnt/nfs/c", "mounted softerr"},
		{"nfs4 nolock", []string{rootExt4, nfs4("vers=4.2,hard,nolock,local_lock=none")}, "/mnt/nfs/c", "mounted nolock"},
		{"nfs4 nocto", []string{rootExt4, nfs4("vers=4.2,hard,nocto,local_lock=none")}, "/mnt/nfs/c", "mounted nocto"},
		{"nfs4 local_lock=posix", []string{rootExt4, nfs4("vers=4.2,hard,local_lock=posix")}, "/mnt/nfs/c", "local_lock=posix"},
		{"nfs4 local_lock=all", []string{rootExt4, nfs4("vers=4.2,hard,local_lock=all")}, "/mnt/nfs/c", "local_lock=all"},
		{"per-mount option field", []string{rootExt4,
			`600 29 0:70 / /mnt/nfs rw,relatime,soft shared:300 - nfs4 fileserver:/export rw,vers=4.2,hard,local_lock=none`},
			"/mnt/nfs/c", "mounted soft"},
		{"nfs vers=3", []string{rootExt4, nfs3}, "/mnt/nfs/c", "nfs at \"/mnt/nfs\" is not safe for -sharedstorage: NFSv3"},
		{"cifs", []string{rootExt4, cifs}, "/mnt/smb/c", "cifs at \"/mnt/smb\" is not safe for -sharedstorage: SMB"},
		{"smb3", []string{rootExt4, smb3}, "/mnt/smb/c", "smb3 at"},
		{"fuse.s3fs", []string{rootExt4, s3fs}, "/mnt/s3/c", "fuse.s3fs at \"/mnt/s3\" is not safe for -sharedstorage: FUSE"},
		{"unrecognized", []string{rootExt4, overlay}, "/mnt/ovl/c", "overlay at \"/mnt/ovl\" is not safe for -sharedstorage: unrecognized"},
		{"nested mount passes under refused root", []string{rootNFS3, proc, dataXFS}, "/data/x/cipher", ""},
		{"nested mount refused under local root", []string{rootExt4, dataXFS, nfs4("vers=4.0,hard")}, "/mnt/nfs/c", "vers=4.0"},
		{"prefix stops at a path component", []string{rootNFS3, dataXFS}, "/database/c", "nfs at \"/\""},
		{"stacked mount, last wins", []string{rootExt4, nfs3, nfs4("vers=4.2,hard,local_lock=none")}, "/mnt/nfs/c", ""},
		{"stacked mount, last refused", []string{rootExt4, nfs4("vers=4.2,hard,local_lock=none"), nfs3}, "/mnt/nfs/c", "NFSv3"},
		{"escaped mount point refused", []string{rootExt4, spaceNFS}, "/mnt/my share/c", "nfs4 at \"/mnt/my share\""},
		{"escaped mount point passes", []string{rootNFS3, spaceExt4}, "/mnt/my disk/c", ""},
		{"no mount", []string{tmp}, "/home/u/cipher", "no mount found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkShared(tc.path, -1, strings.NewReader(strings.Join(tc.mounts, "\n")+"\n"))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want pass, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCheckSharedMalformed(t *testing.T) {
	if err := checkShared("/x", -1, strings.NewReader("29 1 259:2 / /\n")); err == nil {
		t.Fatal("want parse error")
	}
}

// A cifs mount over /mnt hides the nfs4 mount at /mnt/efs, so only the mount ID finds the right one.
func TestCheckSharedMountID(t *testing.T) {
	cover := `520 29 0:80 / /mnt rw,relatime shared:290 - cifs //fileserver/share rw,vers=3.1.1,soft`
	mi := strings.Join([]string{rootExt4, efs, cover}, "\n") + "\n"
	if err := checkShared("/mnt/efs/c", 520, strings.NewReader(mi)); err == nil || !strings.Contains(err.Error(), `cifs at "/mnt"`) {
		t.Fatalf("want the covering cifs refused, got %v", err)
	}
	if err := checkShared("/mnt/efs/c", 512, strings.NewReader(mi)); err != nil {
		t.Fatalf("want efs to pass, got %v", err)
	}
	if err := checkShared("/mnt/efs/c", 999, strings.NewReader(mi)); err == nil || !strings.Contains(err.Error(), "no mount found") {
		t.Fatalf("want no mount found, got %v", err)
	}
}

func TestCheckSharedReal(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/proc/self", link); err != nil {
		t.Fatal(err)
	}
	if err := CheckShared(link); err == nil || !strings.Contains(err.Error(), `proc at "/proc"`) {
		t.Fatalf("want the symlink target's proc mount refused, got %v", err)
	}
	if err := CheckShared(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("want error for a missing cipherdir")
	}
}
