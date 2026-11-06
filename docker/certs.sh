#!/usr/bin/env bash
#
# Makes the TKFS client certs for mounting against the gatehouse docker stack. Rerun it after the stack's
# certs.sh, which replaces the stack CA these certs carry. See README.md.
#
set -euo pipefail

HERE="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
STACK_CERTS="${STACK_CERTS:-$(echo "${GOPATH:-${HOME}/go}" | cut -d: -f1)/src/github.com/TrustedKeep/gatehouse/docker/certs}"
DAYS="${DAYS:-365}"

[ -r "${STACK_CERTS}/ca.crt" ] && [ -r "${STACK_CERTS}/ca.key" ] || {
  echo >&2 "No readable stack CA in ${STACK_CERTS}; run gatehouse's docker/certs.sh, or set STACK_CERTS"
  exit 1
}
STACK_CERTS="$(cd "${STACK_CERTS}" && pwd -P)"
mkdir -p "${HERE}/certs"
cd "${HERE}/certs"

# run shows a command's output only when it fails.
run() {
  local out
  out="$("$@" 2>&1)" || { echo >&2 "${out}"; return 1; }
}

# fresh reports whether a cert exists and is good for at least another day.
fresh() { [ -f "${1}" ] && openssl x509 -checkend 86400 -noout -in "${1}" >/dev/null; }

# tkfs_ca and its client certs are kept across runs, so the CA uploaded to the tenant stays valid.
if ! fresh tkfs_ca.crt; then
  rm -rf tkfs_host1 tkfs_host2
  run openssl req -subj /O=TK-DEV/CN=tkfs_ca -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 \
    -days "${DAYS}" -nodes -x509 -keyout tkfs_ca.key -out tkfs_ca.crt \
    -addext basicConstraints=critical,CA:TRUE,pathlen:0 \
    -addext keyUsage=critical,digitalSignature,cRLSign,keyCertSign
  echo "New tkfs_ca; upload tkfs_ca.crt again"
fi

# client <name> <ca cert> <ca key> writes a gocryptfs -gateway-cert-dir. Its ca.crt is the stack CA, which
# signs the gateway's server cert, so it is refreshed on every run.
client() {
  if ! fresh "${1}/tls.crt"; then
    mkdir -p "${1}"
    run openssl req -subj "/O=TK-DEV/CN=${1}" -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 \
      -days "${DAYS}" -nodes -x509 -keyout "${1}/tls.key" -out "${1}/tls.crt" -CA "${2}" -CAkey "${3}" \
      -addext basicConstraints=critical,CA:FALSE \
      -addext keyUsage=critical,digitalSignature,keyAgreement \
      -addext extendedKeyUsage=clientAuth
    chmod 0600 "${1}/tls.key"
  fi
  cp "${STACK_CERTS}/ca.crt" "${1}/ca.crt"
}

client tkfs_host1 tkfs_ca.crt tkfs_ca.key
client tkfs_host2 tkfs_ca.crt tkfs_ca.key
# Signed by the stack CA, which the gateway trusts for users but not, unless uploaded, for TKFS.
rm -rf tkfs_rogue
client tkfs_rogue "${STACK_CERTS}/ca.crt" "${STACK_CERTS}/ca.key"

# What -mock-aws proves verifies only against tkutils' mock certificate, which the image build extracts.
"${HERE}/build.sh"
docker run --rm --entrypoint cat tkfs-mount:local_dev /usr/local/share/tkfs/aws_mock_identity.crt >aws_mock_identity.crt

echo "Stack CA from ${STACK_CERTS}"
for c in tkfs_host1 tkfs_host2 tkfs_rogue; do
  printf '%-11s %s\n' "${c}" "$(openssl x509 -in "${c}/tls.crt" -noout -subject -nameopt compat)"
done
echo "Upload as a TKFS trusted CA:     ${HERE}/certs/tkfs_ca.crt"
echo "Upload as an identity cert:      ${HERE}/certs/aws_mock_identity.crt"
