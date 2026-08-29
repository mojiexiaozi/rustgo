# Task 13 report

Task 13 is complete at commit `dac2930`. Windows formatting, Clippy, workspace tests, locked release build, and process E2E passed. Linux process E2E passed TCP, UDP, direct P2P, and forced relay. The complete namespace matrix passed twice with cleanup audit; restricted UDP and the UDP-pool-pressure-to-NativeTcp regression each passed 10/10.

The deployed `/opt/rustgo/bin/rustgos` SHA-256 is `41b2147b795f9adff30cd7637d0788db52aae5b6a0dd4119e76646a6352dc9c9`. Backup is `/opt/rustgo/backups/v0.2-20260829T130952Z`. Live listeners are `7443/tcp`, `7443/udp`, and `7444/udp`; authenticated V0.1 TCP/UDP relay payloads passed after deployment.

Unrelated `frps` stayed PID `11859`, TCP ports `7000`/`5000`, SHA-256 `126b47526ef158b739e8750727ae3fd537da3509ebc0ecddeb71bb6a421eff35`. UFW is inactive, so no host firewall policy was changed; cloud firewall reachability for the two UDP ports remains an operator requirement.

## Review closure evidence

- `rustgos check -c /etc/rustgo/server.toml` exited zero against the installed binary. `systemctl show` reported `ActiveState=active`, `SubState=running`, `NRestarts=0`, and `MainPID=234440` at the final audit.
- `ss -lntup` correlated PID `234440` with `7443/tcp`, `7443/udp`, and `7444/udp`. It separately correlated unchanged `frps` PID `11859` with TCP `7000` and `5000`.
- Local `git archive dac2930` produced `/root/rustgo-v02-71812f7/provenance/rustgo-dac2930.tar`, SHA-256 `41f59d386ec72256e57b9fc88d0657fdd95fff21a9523bc9cb83857edfc7f617`. The deployed artifact hash remains the value above. An isolated rebuild had a different binary hash because the Rust release is not bit-for-bit reproducible across build paths; no equality claim is made.
- The dereferenced V0.1 rollback binary is `/opt/rustgo/backups/v0.2-20260829T130952Z/rustgos.v0.1`, SHA-256 `dd7a39bcdd3f1f9ab5dd1f5e76b0ca1be318d38e448b1509aa347737cc433d50`; the matching configuration is `server.toml` in the same directory. Rollback uses staged `install`, atomic `mv`, configuration check, then service start.
- A same-host loopback provider/consumer attempt was rejected as public-NAT evidence because UDP observation was not representative. The accepted controlled remote scope used the installed `/opt/rustgo/bin/rustgos` through an isolated netns binary directory. It passed authenticated TCP over `NativeTcp`, UDP over `QuicV4`/`QuicV6`, deliberately forced encrypted `Relay`, payload integrity, and the final namespace/process/rule cleanup audit. This proves the installed artifact in controlled remote topology, not cloud-firewall or public-Internet reachability.
- Temporary V0.2 client authorization was removed, the production configuration restored, and no temporary listener on `28200/28201/28700/28701` remained.
