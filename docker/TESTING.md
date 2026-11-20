# Testing TKFS against the gatehouse stack

These steps follow the test steps on TK-1434 and TK-1394. Start the stack and make the certs as in
[README.md](README.md), with no TKFS trusted CA uploaded yet. Run each `mount.sh` in its own terminal, and remount with
`mount.sh -k`: a plain `mount.sh` makes a fresh filesystem, which is a new instance.

## Timing

A mount heartbeats every 5 minutes. A refusal suspends it at once and three failures in a row suspend it,
so it can take 15 minutes of silence; it resumes on the next heartbeat that gets through. A mount also checks
policy when it starts, so remounting shows the effect of a
policy change immediately, and it picks up a queued rekey at once.

## Steps

1. **No trusted CA.** `mount.sh a` fails: the data-key listener only runs while a TKFS trusted CA exists.
2. **Trusted CA.** On **Trusted CAs**, add `tkfs_ca.crt`. It is listed by fingerprint, and the listener
   starts within about 15 seconds.
3. **DN not allowed.** `mount.sh a` is refused.
4. **Allowed DN.** On **Access Control**, allow `CN=tkfs_host1,O=TK-DEV`. Now `mount.sh a` mounts, and **a**
   shows as Active on **Instances**.
5. **Untrusted CA.** `mount.sh r tkfs_rogue` fails the TLS handshake.
6. **Rekey.** From the instance's menu, choose Rekey, then remount. The key index goes up and the key-created
   time moves past the rekey.
7. **Block.** Block the instance. Its next heartbeat is refused and the mount is suspended: it stays mounted,
   but `ls` and reads in it fail with "Permission denied", and a program that mapped a file before the block
   dies with a bus error on its next read of it. A new mount is refused straight away. Remove the block on
   **Access Control**; the running mount resumes on its next heartbeat.
8. **Revoke.** Remove the DN from the allowed DNs. The mount is suspended on its next heartbeat, and resumes
   on the one after the DN is allowed again.
9. **Unreachable.** Stop the gateway for 15 minutes. The mount stays up and is suspended after three failed
   heartbeats, then resumes on the first heartbeat after the gateway is back.
10. **Binding (Phase 4).** `-mock-aws` proves a fake machine (`i-00000000000000000`, `us-east-1`, account
    `000000000000`).
    - Add `aws_mock_identity.crt` on **Instance Binding**. Mounts then prove the mock machine and **Instances**
      shows it as their Host, but nothing binds while the gateway does not require binding.
    - Binding is gateway startup config, so turn it on by recreating the gateway, in gatehouse's `docker/`:
      `TKFS_REQUIRE_BINDING=true docker compose up -d --force-recreate --no-deps --wait gateway`.
      **Instance Binding** then shows the node as requiring binding, and **Instances** gains a Binding
      column. Each filesystem binds to the machine it proves on its next mount, and shows as Bound. A mount
      that proves no machine is refused, and the next heartbeat of a mount still running unbound suspends
      it; remount it to bind. Forget removes the binding: a running mount is suspended on its next
      heartbeat and binds again when remounted.

`-mock-aws` always proves the same fake machine (`i-00000000000000000`, account `000000000000`). A second
real machine, as TK-1394 describes, needs EC2.
