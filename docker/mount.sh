#!/usr/bin/env bash
#
# Builds the tkfs-mount image and mounts one TKFS filesystem in its own container, named tkfs-<name>, on the
# gatehouse stack's network. Ctrl-C unmounts. See README.md.
#
#   mount.sh <name> [cert]    cert is a dir under certs/, default tkfs_host1
#
set -euo pipefail

NAME="${1:?usage: mount.sh <name> [cert]}"
CERT="${2:-tkfs_host1}"
HERE="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

[ -f "${HERE}/certs/${CERT}/tls.crt" ] || { echo >&2 "No cert dir ${HERE}/certs/${CERT}; run certs.sh"; exit 1; }
docker network inspect "${STACK_NETWORK:-gw_gw}" >/dev/null 2>&1 || {
  echo >&2 "No network ${STACK_NETWORK:-gw_gw}; start the gatehouse stack, or set STACK_NETWORK"
  exit 1
}
"${HERE}/build.sh"

cd "${HERE}"
exec docker compose run --rm --name "tkfs-${NAME}" mount "${NAME}" "${CERT}"
