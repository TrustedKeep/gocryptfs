# syntax=docker/dockerfile:1

ARG REPO=824638282610.dkr.ecr.us-east-1.amazonaws.com/
ARG GO_VERSION=1.24
FROM ${REPO}trustedkeep/builder:${GO_VERSION} AS builder

RUN --mount=type=ssh \
    --mount=type=secret,id=GH_TOKEN \
    --mount=type=bind,source=.,target=/src \
    --mount=type=cache,sharing=locked,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build <<'EOF'
set -eux
# Setup ssh auth to GOPRIVATE repos
setup_tk_ssh

cd /src
mkdir -p /out
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/gocryptfs .
# The certificate that verifies what -mock-aws proves comes from the tkutils this build uses.
tkutils="$(go list -m -f '{{with .Replace}}{{.Dir}}{{else}}{{.Dir}}{{end}}' github.com/TrustedKeep/tkutils/v2)"
awk '/^const MockCertPEM = `/{p=1; sub(/^.*`/, "")} p && /^`/{exit} p' "${tkutils}"/awsidentity/*.go >/out/aws_mock_identity.crt
test -s /out/aws_mock_identity.crt
EOF

FROM ${REPO}trustedkeep/runner:latest
RUN apt-get update && apt-get install -y --no-install-recommends fuse3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/gocryptfs /usr/local/bin/gocryptfs
COPY --from=builder /out/aws_mock_identity.crt /usr/local/share/tkfs/aws_mock_identity.crt
COPY docker/entry.sh /usr/local/bin/tkfs-mount
ENTRYPOINT ["tkfs-mount"]
