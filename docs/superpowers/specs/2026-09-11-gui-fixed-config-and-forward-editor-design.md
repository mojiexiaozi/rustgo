# GUI Fixed Configuration and Unified Forward Editor Design

## Goal

Simplify the Windows GUI so it starts from one predictable configuration, connects automatically, and edits tunnels and P2P routes in one place.

## Configuration Location and Startup

`rustgoc-gui` resolves `client.toml` from the directory containing the running `rustgoc-gui.exe`. The GUI does not accept or expose an alternate configuration path. Relative certificate and private-key paths continue to resolve relative to that configuration file.

If `client.toml` is missing, the GUI creates a valid default file beside the executable before loading it. The default uses `gui-client`, `8.133.176.172:8443`, dynamic identity, telemetry defaults, and empty tunnel, export, and forward collections. File creation errors are shown in the GUI and prevent connection attempts.

After configuration and enrollment-state checks succeed, the GUI connects automatically. The connection screen does not contain editable server or port fields and does not require a Connect button. It displays the configured endpoint, connection state, traffic counters, and explicit disconnect or reconnect controls.

## Server Address Editing

The configuration screen loads automatically when the application starts. It has no Load Configuration button and no path selector.

The server endpoint is edited as one address value that accepts a host or IP with a port. The adjacent `Save and Apply` action validates the complete configuration, writes it atomically to the fixed file, disconnects the current runtime, and reconnects from the saved configuration. Validation or write failure leaves both the file and current connection unchanged and displays the error.

`server_name` remains separately editable because TLS validation may require a DNS name distinct from the endpoint IP.

## Unified Tunnel and P2P Editor

The existing Tunnels and P2P navigation entries become one `转发` page. Runtime status for tunnels and P2P paths remains visible on this page, followed by the configuration editor.

One unified list projects the three existing TOML collections without changing the configuration format:

- `TCP 隧道` maps to `[[tunnels]]` with `protocol = "tcp"`.
- `UDP 隧道` maps to `[[tunnels]]` with `protocol = "udp"`.
- `P2P 导出` maps to `[[exports]]`.
- `P2P 转发` maps to `[[forwards]]`.

An Add row begins with a type dropdown containing exactly those four choices. Selecting a type shows only fields required by its underlying configuration model. Existing rows show their type, identifying name, source/listen side, destination side, and relevant P2P options. Rows can be edited or removed. Changes remain in memory until `Save and Apply` succeeds.

The global `[p2p]` settings are edited in the same page above the unified list. They use the current `P2pConfig` fields and defaults rather than introducing a second model.

## State and Error Handling

Configuration loading, default generation, atomic saving, and entry conversion live outside egui rendering code so they can be tested directly. The GUI owns one loaded configuration and supplies it to both the settings view and unified editor.

Applying configuration is transactional from the user's perspective: build and validate a candidate, write through a temporary sibling file, then replace `client.toml`. Runtime reconnection occurs only after replacement succeeds. A failed candidate does not alter the running client.

Enrollment-required states continue to interrupt automatic connection and show the existing enrollment panel. Completing enrollment resumes connection from the fixed configuration.

## Compatibility

The TOML schema and wire protocol do not change. Existing `client.toml` files continue to load. The headless `rustgoc` CLI keeps its current `-c` behavior; the fixed-location rule applies only to `rustgoc-gui`.

## Verification

Automated tests cover executable-relative path resolution, missing-file generation, existing-file preservation, atomic validated saves, all four unified entry conversions, and automatic startup/apply decisions. Existing GUI state and configuration tests remain passing. Final checks are `cargo fmt --all -- --check`, `cargo test -p rustgoc-gui`, and `cargo clippy -p rustgoc-gui --all-targets -- -D warnings`.
