# TKFS mounts against the gatehouse stack

Mounts TKFS filesystems in containers on the gatehouse docker stack's network. The stack, in gatehouse's
`docker/` directory, runs the gateway, keep and the TKFS admin UI; this directory holds the client side.
[TESTING.md](TESTING.md) has the test steps.

## Requirements

You need Docker with buildx, FUSE on the host (`/dev/fuse`), openssl and the stack running the TKFS
servers. Build both stack images from the gatehouse and keep branches with the same TKFS changes as this
checkout; each is tagged `:local_dev`, which the stack runs:

- the gateway, with gatehouse's `docker/build_images.sh`, which needs the ECR login in gatehouse's
  `docker/README.md`;
- keep, with keep's `docker/build_images.sh`.

`build.sh` builds the `tkfs-mount:local_dev` image from this checkout in ECR's
`trustedkeep/builder:<go.mod major.minor>` and `trustedkeep/runner:latest`, so it needs the same ECR login
as gatehouse. Like gatehouse's `build_images.sh`, it reaches the private
TrustedKeep modules through your SSH agent, or `GH_TOKEN` when that is set. `certs.sh` and `mount.sh` run it
for you; it uses the build cache, so a rebuild with no change takes seconds.

## Start

In gatehouse's `docker/`:

```
./certs.sh     # the stack certs, once a year
docker compose up -V --force-recreate --remove-orphans -d --wait
```

This `up` recreates keep and so loses every KEK, so `mount.sh -k` cannot mount a filesystem made before it.
Resume a stopped stack with the `up` under [Stop](#stop).

Here:

```
./certs.sh
./mount.sh a              # as tkfs_host1, in its own terminal
./mount.sh b tkfs_host2
```

Mounts fail until `tkfs_ca.crt` is a TKFS trusted CA and each mount's DN is allowed: see
[TESTING.md](TESTING.md) steps 2 and 4, and allow `CN=tkfs_host2,O=TK-DEV` too for **b**.

`certs.sh` takes the stack certs from the gatehouse checkout under your GOPATH. When the stack runs from
another checkout or a worktree, set `STACK_CERTS` to that `docker/certs` directory. Rerun it after the
stack's `certs.sh`, which replaces the stack CA.

The admin UI is at https://localhost:7071, under **TKFS** in the side menu. Use the `local_dev_admin1`
certificate.

## Mounts

`mount.sh [-k] <name> [cert]` mounts one filesystem, which is one TKFS instance, in its own container,
`tkfs-<name>`. The cert is a directory under `certs/`, `tkfs_host1` by default. Each mount initializes a fresh
filesystem with `-mock-aws`, replacing the name's earlier one; that is a new instance, so the earlier one stays
on **Instances**. `-k` mounts the earlier filesystem instead. Filesystems live in the `tkfs_state` volume.

- Ctrl-C or `docker stop tkfs-<name>` unmounts it, and a refused mount exits 33.
- Closing the terminal leaves the mount running, so stop it with `docker stop tkfs-<name>` before mounting
  that name again.
- To use the files, run `docker exec -it tkfs-<name> sh`; they are under `/tkfs/state/<name>/mnt`.
- Mounts join the stack's `gw_gw` network. The AWS variant of the stack has only `gw_default`, so set
  `STACK_NETWORK=gw_default` for it.
- `GATEWAY` sets the data-key listener a new filesystem is initialized with, `gateway:7083` by default
  (`gateway2:7083` for the second cluster). It is stored in that filesystem's `gocryptfs.conf`, so `-k`
  mounts ignore it.

Certs in `certs/`:

| File | Use |
| --- | --- |
| `tkfs_ca.crt` | Upload as the TKFS trusted CA |
| `tkfs_host1`, `tkfs_host2` | Client certs from `tkfs_ca`, DNs `CN=tkfs_host1,O=TK-DEV` and `CN=tkfs_host2,O=TK-DEV` |
| `tkfs_rogue` | Client cert from the stack CA, which TKFS does not trust unless you upload it |
| `aws_mock_identity.crt` | Upload as an identity certificate; it verifies the fake machine `-mock-aws` proves |

## API

The stack's stunnel ports need no client cert flags; `13271` is gateway1 management as admin1:

```
curl http://localhost:13271/api/v1/tkfsdatakey/policy
curl http://localhost:13271/api/v1/tkfsdatakey/instances
curl -XPOST --data-binary @certs/tkfs_ca.crt http://localhost:13271/api/v1/tkfsdatakey/ca
curl -XPUT 'http://localhost:13271/api/v1/tkfsdatakey/acl/CN=tkfs_host1,O=TK-DEV'
```

## Rebuild

A gocryptfs change needs only a remount. After a gatehouse or UI change, rebuild the gateway image and
recreate only the gateway, in gatehouse's `docker/`. keep's data, and with it every KEK, survives. Set
`TKFS_REQUIRE_BINDING=true` again if binding was on, or the recreate turns it off.

```
./build_images.sh
docker compose up -d --force-recreate --no-deps --wait gateway
```

keep keeps its data in the container, not a volume, so recreating `kms` is the same as `down -v` below.

## Stop

To pause and keep keep's data, `stop` the stack and bring it back with a plain `up`, in gatehouse's
`docker/`. Prefix the `up` with `TKFS_REQUIRE_BINDING=true` if binding was on, or the gateway comes back
with it off. Recreating only the gateway needs the rest running; on a stopped stack its address lookup for
keep fails and it exits.

```
docker compose stop
docker compose up -d --wait
```

To throw everything away, stop every mount first; `down -v` keeps a volume a running mount uses and still
succeeds.

```
docker ps -q --filter name=tkfs- | xargs -r docker stop
docker compose down -v     # here, which removes the tkfs_state volume
docker compose down -v     # in gatehouse's docker/
```

The stack's `down -v` deletes keep's data, including every filesystem's KEK, so `mount.sh -k` can never
mount the filesystems in `tkfs_state` again. Remove them along with it.
