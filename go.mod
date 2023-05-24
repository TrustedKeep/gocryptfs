module github.com/rfjakob/gocryptfs/v2

go 1.17

require (
	github.com/TrustedKeep/boundary v1.1.5-0.20230501211204-50c8221201bc
	github.com/TrustedKeep/tkutils/v2 v2.9.4
	github.com/google/uuid v1.3.0
	github.com/hanwen/go-fuse/v2 v2.1.1-0.20221117175120-915cf5413cde
	github.com/pkg/xattr v0.4.6
	github.com/rfjakob/eme v1.1.2
	github.com/spf13/pflag v1.0.5
	go.etcd.io/bbolt v1.3.6
	golang.org/x/crypto v0.8.0
	golang.org/x/sys v0.7.0
	golang.org/x/term v0.7.0
)

require (
	github.com/aws/aws-sdk-go v1.44.251 // indirect
	github.com/cloudflare/circl v1.3.2 // indirect
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	google.golang.org/grpc v1.54.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	software.sslmate.com/src/go-pkcs12 v0.2.0 // indirect
)

replace github.com/TrustedKeep/boundary => /home/andrew/go/src/github.com/TrustedKeep/boundary

replace github.com/TrustedKeep/tkutils/v2 => /home/andrew/go/src/github.com/TrustedKeep/tkutils
