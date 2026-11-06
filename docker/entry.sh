#!/bin/sh
#
# Mounts one TKFS filesystem in the foreground, initializing it on first use. Runs in the container; see
# mount.sh.
#
set -eu

NAME="${1:?usage: <name> [cert]}"
CERT="${2:-tkfs_host1}"
STATE="/tkfs/state/${NAME}"
CERT_DIR="/tkfs/certs/${CERT}"

[ -f "${CERT_DIR}/tls.crt" ] || { echo >&2 "No cert dir ${CERT}; run certs.sh"; exit 1; }

mkdir -p "${STATE}/cipher" "${STATE}/mnt"
if [ ! -f "${STATE}/cipher/gocryptfs.conf" ]; then
  gocryptfs -init -gateway-host "${GATEWAY}" -node-id "${NAME}" -mock-aws "${STATE}/cipher"
fi
echo "Mounting ${STATE}/mnt as ${CERT}"
exec gocryptfs -fg -gateway-cert-dir "${CERT_DIR}" "${STATE}/cipher" "${STATE}/mnt"
