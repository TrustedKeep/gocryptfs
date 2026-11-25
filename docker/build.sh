#!/usr/bin/env bash
#
# Builds the tkfs-mount image from this checkout in the TrustedKeep builder image, authenticating to the
# private modules as gatehouse's build_images.sh does. See README.md.
#
set -euo pipefail

HERE="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
cd "${HERE}"

if [[ -n "${GH_TOKEN:-}" ]]; then
  AUTH=(--set '*.secrets=id=GH_TOKEN')
elif ssh-add -l &>/dev/null; then
  AUTH=(--allow=ssh --set '*.ssh=default')
else
  echo >&2 "No SSH agent or GH_TOKEN for the private TrustedKeep modules"
  exit 1
fi

GO_VERSION="$(grep -Eo -m1 '^go +[0-9]+[.][0-9]+' ../go.mod | awk '{print $2}')"
export GO_VERSION
# The build context is the repo root, outside this directory, so bake has to be allowed to read it.
docker buildx bake -f docker-compose.yml --load --allow="fs.read=$(realpath ..)" "${AUTH[@]}" mount
