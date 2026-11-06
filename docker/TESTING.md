# Testing TKFS against the gatehouse stack

These steps follow the test steps on TK-1434 and TK-1394. Start the stack and make the certs as in
[README.md](README.md), with no TKFS trusted CA uploaded yet. Run each `mount.sh` in its own terminal.

## Timing

A mount heartbeats every 5 minutes. Three failures in a row end it, so an instance shows **Unreachable**
after 15 minutes of silence. A mount also checks policy when it starts, so remounting shows the effect of a
policy change immediately, and it picks up a queued rekey at once.

## Steps

1. **No trusted CA.** `mount.sh a` fails: the data-key listener only runs while a TKFS trusted CA exists.
2. **Trusted CA.** On **Trusted CAs**, add `tkfs_ca.crt`. It is listed by fingerprint, and the listener
   starts within about a minute.
3. **DN not allowed.** `mount.sh a` is refused.
4. **Allowed DN.** On **Access Control**, allow `CN=tkfs_host1,O=TK-DEV`. Now `mount.sh a` mounts, and **a**
   shows as Active on **Instances**.
5. **Untrusted CA.** `mount.sh r tkfs_rogue` fails the TLS handshake.
6. **Rekey.** From the instance's menu, choose Rekey, then remount. The key index goes up and the key-created
   time moves past the rekey.
7. **Block.** Block the instance. Its next heartbeat is refused and the mount ends; a remount is refused
   straight away. Remove the block on **Access Control**.
8. **Revoke.** Remove the DN from the allowed DNs. The mount ends on its next heartbeat.
9. **Unreachable.** Ctrl-C a mount and wait 15 minutes.
10. **Binding (Phase 4).** `-mock-aws` proves a fake machine (`i-00000000000000000`, `us-east-1`, account
    `000000000000`).
    - Add `aws_mock_identity.crt` on **Instance Binding**. Mounts then prove the mock machine and **Instances**
      shows it as their Host, but nothing binds while the gateway does not require binding.
    - Binding is gateway startup config, so turn it on by recreating the gateway, in gatehouse's `docker/`:
      `TKFS_REQUIRE_BINDING=true docker compose up -d --force-recreate --no-deps --wait gateway`.
      **Instance Binding** then shows the node as requiring binding, and **Instances** gains a Binding
      column. Each filesystem binds to the machine it proves on its next mount, and shows as Bound. A mount
      that proves no machine is refused, and so is the next heartbeat of a mount still running unbound
      (exit 33); remount it to bind. Forget removes the binding: a running mount unmounts on its next
      heartbeat (exit 33) and binds again when remounted.

`-mock-aws` always proves the same fake machine (`i-00000000000000000`, account `000000000000`). A second
real machine, as TK-1394 describes, needs EC2.
