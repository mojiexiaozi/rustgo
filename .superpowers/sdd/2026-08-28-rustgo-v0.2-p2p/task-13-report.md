# Task 13 report

Task 13 is complete at commit `dac2930`. Windows formatting, Clippy, workspace tests, locked release build, and process E2E passed. Linux process E2E passed TCP, UDP, direct P2P, and forced relay. The complete namespace matrix passed twice with cleanup audit; restricted UDP and the UDP-pool-pressure-to-NativeTcp regression each passed 10/10.

The deployed `/opt/rustgo/bin/rustgos` SHA-256 is `41b2147b795f9adff30cd7637d0788db52aae5b6a0dd4119e76646a6352dc9c9`. Backup is `/opt/rustgo/backups/v0.2-20260829T130952Z`. Live listeners are `7443/tcp`, `7443/udp`, and `7444/udp`; authenticated V0.1 TCP/UDP relay payloads passed after deployment.

Unrelated `frps` stayed PID `11859`, TCP ports `7000`/`5000`, SHA-256 `126b47526ef158b739e8750727ae3fd537da3509ebc0ecddeb71bb6a421eff35`. UFW is inactive, so no host firewall policy was changed; cloud firewall reachability for the two UDP ports remains an operator requirement.
