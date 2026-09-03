# Rustgo V0.4.0 Release Notes

## Summary

V0.4 adds a cross-platform GUI client (`rustgoc-gui`) with real-time connection monitoring, tunnel display, traffic visualization, P2P path visibility, and bounded resource usage. The GUI shares the same headless `rustgoc` library and connects to V0.1/V0.2/V0.3 servers without modification.

## New Features

### GUI Client (`rustgoc-gui`)

A native desktop application built with eframe/egui 0.36.0 providing:

- **Connection Panel**: Real-time status display with generation counter, connect/disconnect controls, and server address configuration
- **Tunnels Panel**: Live tunnel monitoring showing name, protocol, local port, remote port, and forward target for each registered tunnel
- **Logs Panel**: Bounded ring buffer displaying the 1,000 most recent log lines with automatic scrolling
- **Resource Bounds**: All GUI collections are bounded (1,000 log lines, 300 telemetry chart points, 64 tray events) with drop-oldest behavior
- **Windows System Tray**: Minimize to tray, tray menu with Show/Connect/Disconnect/Quit options, quit from tray terminates the application
- **Cross-Platform**: Builds on Windows and Linux with `#![forbid(unsafe_code)]`; Linux builds contain no GTK or AppIndicator dependencies

### Selfcheck Mode

The `--selfcheck` flag validates configuration and connectivity:

```text
rustgoc-gui --selfcheck -c ./client.toml
```

Selfcheck behavior:
- Loads and validates configuration using production credential loaders
- Starts the client runtime and waits up to 30 seconds for active status
- Prints single-line traffic totals (tx/rx bytes) if telemetry is enabled
- Prints P2P path status snapshots for all active exports
- Exits 0 only on full success (configuration valid, connection established, generation reached)
- Integrated into both `scripts/e2e.ps1` and `scripts/e2e.sh` for automated validation

### API Additions

New public API in `rustgoc::ClientApp`:
- `subscribe() -> watch::Receiver<ClientStatus>`: Subscribe to connection status updates
- `traffic_handle() -> Option<TrafficHandle>`: Get shareable handle for polling traffic totals
- `path_status_store() -> &PathStatusStore`: Access P2P path status for GUI display

## Platform Support

- **Windows**: Full support including system tray integration
- **Linux**: Full support, no GTK/AppIndicator dependencies
- **macOS**: Builds successfully, tray integration untested

## Backward Compatibility

- GUI client connects to V0.1, V0.2, and V0.3 servers without modification
- CLI client (`rustgoc`) unchanged; GUI is an additional binary
- Server (`rustgos`) unchanged
- Configuration format unchanged; GUI uses the same `client.toml` format

## Build and Test

```text
cargo build --workspace --release
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

E2E scripts now include GUI selfcheck validation:

```text
bash scripts/e2e.sh
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1
```

## Resource Usage

The GUI enforces strict resource bounds:
- **Log lines**: 1,000 entry ring buffer (oldest dropped)
- **Telemetry points**: 300 point history (oldest dropped)
- **Tray events**: 64 entry channel (oldest dropped)

These bounds ensure predictable memory usage regardless of uptime.

## Known Limitations

- Telemetry charts and P2P panel UI created but not yet integrated into main tab layout
- Windows tray icon uses default system icon (custom icon support planned)
- Minimize-to-tray behavior on window close is Windows-only
- Full WCAG compliance validation requires manual testing with assistive technologies

## Migration Notes

No migration required. The GUI client is a new binary that coexists with the CLI client. Both use the same configuration format and connect to existing servers.

## What's Next

Future enhancements may include:
- Integration of telemetry charts into the GUI tab layout
- Custom tray icon support
- Enhanced P2P path visualization
- Configuration editor within the GUI
