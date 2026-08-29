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

## Final remediation evidence (supersedes earlier artifact values)

- Final source commit: `e725769`; final client behavior commit: `5f38329`.
- `git archive --format=tar HEAD` produced SHA-256
  `da57d0adcf4b0835f1c7f469960b0e0b3b1f8921764417b838bac3c163b7f227`.
  Clean extraction audited seven shell scripts with zero CR bytes.
- Installed hashes: `rustgos`
  `6903017663a884a5f54668ea1734521630d75337676c23a7648cd25ea3580a3b`;
  `rustgoc` `40ca8af27c994a9c47487b512b44c924e883c10769b4c51c7cf2bab68603cf6a`.
  Backups are `/opt/rustgo/backups/5f38329-20260829T153527Z` and
  `/opt/rustgo/backups/18611b6-20260829T152500Z`. Rollback uses staged
  `install`, atomic `mv`, `rustgos check`, and `systemctl restart rustgos`.
- Mixed-OS acceptance passed exact 16-byte `public-mixed-tcp`,
  `public-mixed-udp`, `forced-relay-tcp`, and `forced-relay-udp` payloads.
  Correlated flows selected Relay; both Windows logs had zero
  WARN/ERROR/ProtocolError/invalid-state matches. Authenticated observation
  used configured public `7443/udp` and `7444/udp`; no direct-path claim is made.
- Durable exit files recorded E2E `0`, netns pass 1 `0`, and netns pass 2 `0`.
  E2E log SHA-256 is
  `95cd0123480d42aa91d6ea0345ee585670dce3bed0c11207d375217e94e5b23f`;
  each netns log is
  `3c8326bb8363aee211fff08161ab678ca6fd668d7baa7cf6b7a142d5de19596e`.
  Cleanup found zero namespaces, scoped rules, and owned test processes.
- Final live audit: `rustgos` active/running, `NRestarts=0`, PID `259725`,
  owning `7443/tcp`, `7443/udp`, and `7444/udp`. `frps` remains PID `11859`,
  ports `7000`/`5000`, SHA-256
  `126b47526ef158b739e8750727ae3fd537da3509ebc0ecddeb71bb6a421eff35`.
