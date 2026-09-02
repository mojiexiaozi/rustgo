# Rustgo V0.3 Web Dashboard

## Overview

V0.3 adds an optional, embedded, read-only Web dashboard to `rustgos`. The dashboard provides real-time visibility into server resources, authenticated client health, tunnel activity, P2P path selection, and bounded historical trends without requiring a separate database server, administration daemon, or log parsing.

The dashboard is **strictly read-only**. It does not provide configuration editing, process restart, client disconnection, key rotation, command execution, or any control actions.

## Security architecture

### Loopback-only binding

The dashboard **must** bind to a loopback address (`127.0.0.1` or `::1`). `rustgos check` and startup reject non-loopback binds. Remote access is provided through an operator-managed HTTPS reverse proxy (Caddy, Nginx, Apache).

### Authentication

- **Single administrator account** with configurable username and password
- **Constant-time comparison** of credentials (timing-safe against username/password enumeration)
- **HMAC-signed session cookies** with cryptographic random session IDs
- **Session limits**: 32 concurrent sessions maximum
- **Session expiry**: 30 minutes inactive timeout, 8 hours absolute maximum
- **Rate limiting**: per-source and global login attempt limits before expensive work

### Session security

- `HttpOnly` cookies (not accessible to JavaScript)
- `SameSite=Strict` (blocks cross-site requests)
- `Secure` flag when `cookie_secure = true` (HTTPS only)
- Origin validation on login/logout (CSRF protection)
- Session keys regenerated on every `rustgos` restart (all sessions expire)

### HTTP security headers

Every response includes:
- **Content Security Policy**: Restrictive CSP with no inline scripts, no eval
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Cache-Control: no-store` on authenticated pages
- Static assets use content hashes and may be cached

### Redaction

The dashboard never exposes:
- Private keys, full signatures, or authentication challenges
- Complete session IDs (only redacted prefixes)
- Application payloads or tunnel data
- SQL errors, stack traces, or internal filesystem paths
- Directory listings or source maps

## Configuration

### Server configuration

Add to `server.toml`:

```toml
[web]
enabled = true
bind = "127.0.0.1:7450"
admin_username = "admin"
admin_password = "${RUSTGO_ADMIN_PASSWORD}"
cookie_secure = true
external_origin = "https://tunnel.example.com"
history_days = 7
database_path = "./rustgo-metrics.db"
database_max_mib = 256
```

**Field requirements:**

| Field | Required | Constraints | Default |
|-------|----------|-------------|---------|
| `enabled` | No | `true` or `false` | `false` |
| `bind` | Yes (if enabled) | Loopback IPv4/IPv6 + nonzero port | — |
| `admin_username` | Yes | 1-64 printable UTF-8 bytes | — |
| `admin_password` | Yes | 16-256 UTF-8 bytes | — |
| `cookie_secure` | No | `true` for HTTPS proxy, `false` only for loopback HTTP | `true` |
| `external_origin` | Conditional | Required when `cookie_secure=true`; normalized HTTPS origin | — |
| `history_days` | No | 1-30 | `7` |
| `database_path` | No | Relative to config dir; not config/key/cert/device | `./rustgo-metrics.db` |
| `database_max_mib` | No | 16-4096 | `256` |

**CRITICAL PASSWORD SECURITY:**

- Store `admin_password` using environment substitution: `"${RUSTGO_ADMIN_PASSWORD}"`
- **Never commit** a real password to version control
- Use a strong password: minimum 16 characters, recommend 24+ with mixed case, digits, symbols
- On Unix, `rustgos check` enforces that `server.toml` is **not** readable by group/other
- On Windows, `check` emits an ACL review warning (portable ACL checks are unreliable)

### Client configuration

Add to `client.toml`:

```toml
[telemetry]
enabled = true
sample_interval_secs = 10
report_interval_secs = 30
```

**Field requirements:**

| Field | Constraints | Default |
|-------|-------------|---------|
| `enabled` | `true` or `false` | `false` |
| `sample_interval_secs` | 5-300 | `10` |
| `report_interval_secs` | 10-600, must be ≥ `sample_interval_secs` | `30` |

Telemetry is **optional** and negotiated during protocol handshake. V0.2 clients remain compatible and appear in the dashboard with connection state but without host resource fields.

## Reverse proxy setup

### Caddy example

```caddy
tunnel.example.com {
    reverse_proxy 127.0.0.1:7450
}
```

Caddy automatically provisions Let's Encrypt certificates and sets HTTPS headers.

### Nginx example

```nginx
server {
    listen 443 ssl http2;
    server_name tunnel.example.com;
    
    ssl_certificate /etc/letsencrypt/live/tunnel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tunnel.example.com/privkey.pem;
    
    location / {
        proxy_pass http://127.0.0.1:7450;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Set `external_origin = "https://tunnel.example.com"` in `server.toml` to match the browser origin.

## Dashboard features

### Server resource card

Displays every 2 seconds:
- **CPU**: Total host % and `rustgos` process %
- **Memory**: Host used/total GB, `rustgos` RSS MB
- **Disk**: Filesystem capacity/free GB, read/write MB/s (for database path)
- **Network**: Aggregate host RX/TX Mbps from all interfaces
- **Rustgo traffic**: TCP, UDP, QUIC, native TCP, relay bytes and rates

### Client resource cards

One card per authenticated client, updated when telemetry arrives (default 30s):
- **CPU**: Total host % and `rustgoc` process %
- **Memory**: Host used/total GB, `rustgoc` RSS MB
- **Disk**: Capacity/free GB, read/write MB/s
- **Network**: Host RX/TX Mbps
- **Rustgo traffic**: Upload/download bytes and rates (tunnel + P2P)
- **Connection state**: Version, uptime, exports, forwards, active flows, selected paths
- **Last path transition**: Direct promotion, relay fallback, reconnect reason

**Staleness indicator:** Cards turn gray when telemetry has not arrived within `2 × report_interval_secs`. This indicates client disconnection, network partition, or telemetry disabled.

### Client list and search

- **Search**: Filter by client name (case-insensitive substring)
- **Sort**: By name (A-Z), CPU %, memory %, uptime, last seen
- **Status badges**: Connected (green), stale (gray), disconnected (red)

### Session and path details

- **Active sessions**: TCP and UDP session counts per tunnel
- **P2P paths**: Direct QUIC/UDP, direct native TCP, or relay fallback
- **Path quality**: Latency, packet loss (when direct)
- **Handshake exclusions**: Why direct was not attempted

### Historical trends

- **Retention**: Fine-grained (raw samples) for 1 hour, 1-minute buckets for 1-24 hours, 5-minute buckets beyond 24 hours up to configured `history_days`
- **Query range**: Select time window (1h, 6h, 24h, 7d)
- **Metrics**: CPU, memory, disk, network, Rustgo traffic rates over time
- **Per-client history**: Available for all authenticated clients

Charts use browser-native SVG or Canvas rendering (no external dependencies).

## Protocol and telemetry

### Telemetry protocol

- **Version negotiation**: V0.3 clients and servers negotiate telemetry capability; V0.2 peers ignore it
- **Message ID**: 30 (does not renumber V0.1/V0.2 messages)
- **Identity binding**: Reports are attributed to the authenticated control session; client name is not transmitted as authority
- **Sequence numbers**: Monotonically increasing per client; duplicate/stale reports rejected
- **Sample age**: Monotonic clock on client + server receipt timestamp
- **Replay protection**: Server enforces one report per configured interval with bounded jitter allowance

### Telemetry priority

Telemetry is **low-priority** business data:
- Heartbeat, authentication, close, rendezvous, and data frames have higher priority
- Control backpressure **drops telemetry** rather than delaying liveness or relay traffic
- Telemetry failures **never block** tunnel registration, P2P handshake, or data forwarding

### Collected metrics

**Server samples (every 2 seconds):**
- Host and process CPU, memory
- Disk capacity/free/rates for database filesystem
- Aggregate network RX/TX from up to 16 interfaces
- Rustgo traffic: TCP, UDP, QUIC, native, relay bytes
- Runtime state: authenticated clients, control connections, P2P sessions, active relays, exports, forwards, drops, authentication failures, reconnects

**Client samples (configurable interval):**
- Host and process CPU, memory
- Disk capacity/free/rates from up to 16 filesystems
- Aggregate network RX/TX from up to 16 interfaces
- Rustgo upload/download bytes and rates
- Runtime state: version, uptime, exports, forwards, active flows, selected paths, reconnect count, last transition reason

**Counter behavior:**
- Saturating arithmetic (no overflow wraps)
- Reset detection: Interface removal, counter wrap, reboot, sleep/resume, clock jump starts new baseline
- Hard limits: 16 filesystems, 16 interfaces, 256 exports, 256 forwards, 128-byte labels, 256-entry inventories

## SQLite persistence and retention

### Database characteristics

- **Embedded**: SQLite library linked into `rustgos` (no separate server)
- **WAL mode**: Write-ahead logging for concurrent reads during writes
- **Parameterized queries**: All SQL uses bound parameters (no SQL injection)
- **Single writer**: One dedicated task owns all writes
- **Schema migrations**: Versioned, crash-safe upgrades

### Storage layout

- **Main database**: `rustgo-metrics.db` at configured path
- **WAL file**: `-wal` sidecar (temporary write-ahead log)
- **Shared memory**: `-shm` sidecar (coordinated lock state)
- **Cap accounting**: All three files count toward `database_max_mib`

### Retention tiers

| Age | Granularity | Bucket size |
|-----|-------------|-------------|
| 0-1 hour | Raw samples | Server 2s, client configurable (default 30s) |
| 1-24 hours | Aggregated | 1-minute buckets |
| 1 day - `history_days` | Aggregated | 5-minute buckets |

Retention runs every 10 minutes with bounded work budget per pass.

### Capacity management

When approaching `database_max_mib`:
1. Compact eligible old buckets
2. Delete oldest completed buckets until lower watermark reached
3. Preserve active transactions, current snapshots, runtime state

**Never deleted:**
- Credentials or configuration
- Current live snapshot
- Active session summaries

### Failure isolation

**Dashboard failures do not affect core relay functions:**

- SQLite open failure → startup continues with live in-memory state, `history_unavailable` warning
- Write failure → updates health counter, retry internally, live snapshots continue
- Database corruption → moved to timestamped quarantine, fresh database bootstrapped
- History worker exit → makes history API unavailable, relay and P2P continue
- Web listener bind failure → startup fails (requested operator surface unavailable)
- Web task exit → logged and rebound on same address with 50ms-2s exponential backoff

**Bounded resource use:**
- History writer queue: 1,024 batches + 64 MiB memory cap
- Full queue → drops oldest pending batch, increments visible loss counter
- HTTP concurrency, login attempts, response bytes, query duration: hard ceilings

## API endpoints

All endpoints except `/healthz` require authentication.

### Public endpoints

```
GET /healthz
```

Returns `200 OK` with `{"status":"ok"}`. No authentication required. Use for uptime monitoring.

### Authentication

```
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=...
```

Returns session cookie on success. Failed login returns `401 Unauthorized` after rate-limit delay.

```
POST /logout
```

Invalidates current session. Returns `302` redirect to login page.

### Read-only API

```
GET /api/snapshot
```

Returns current server and all client states (JSON). Includes:
- Server resources, traffic, runtime state
- All authenticated client cards with latest telemetry
- Active sessions, P2P paths, staleness indicators

```
GET /api/history/server?from=<unix_ms>&to=<unix_ms>
```

Returns server historical metrics for time range. Query duration and returned points have hard limits.

```
GET /api/history/client?name=<client>&from=<unix_ms>&to=<unix_ms>
```

Returns client historical metrics by authenticated name. Redacted clients return empty/unavailable.

### Limits

- Request body size: capped
- Query duration: bounded timeout
- Returned points: maximum per response
- Concurrent requests: limited
- Response size: hard byte limit

## Mixed-version compatibility

| Server | Client | Behavior |
|--------|--------|----------|
| V0.3 | V0.3 | Full dashboard with host telemetry |
| V0.3 | V0.2 | Client appears with connection state, no host metrics |
| V0.3 | V0.1 | Client appears with basic tunnel state only |
| V0.2 | V0.3 | No dashboard; client does not send telemetry |

Protocol negotiation ensures backward compatibility. Tunnel relay and P2P remain functional across all version combinations.

## Validation and troubleshooting

### Configuration validation

```bash
# Server check (does not bind listener or create database)
rustgos check -c /etc/rustgo/server.toml

# Client check (does not send telemetry)
rustgoc check -c /etc/rustgo/client.toml
```

Both commands validate:
- Configuration syntax and required fields
- File permissions (Unix: no group/other read on server.toml)
- Password length (16+ bytes)
- Bind address is loopback (server only)
- external_origin matches cookie_secure requirement

### Common issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Startup fails with bind error | Port already in use or non-loopback address | Check `bind` value, verify port availability |
| `history_unavailable` warning | SQLite cannot open/write database | Check filesystem permissions, disk space, parent directory exists |
| Login fails | Wrong credentials or rate-limited | Verify password, wait for rate limit cooldown |
| Session expires immediately | Server restarted | Sessions expire on restart; re-login |
| Client card shows stale/gray | Client disconnected or telemetry disabled | Check client connectivity, verify `[telemetry]` enabled |
| No host metrics on client card | Client is V0.2 or telemetry disabled | Upgrade client to V0.3, enable `[telemetry]` |
| History unavailable | Database error, worker exit | Check logs for SQLite errors, verify disk space |
| Web listener restart loop | Bind failure, permission issue | Check logs for exact error, verify loopback bind |

### Log output

Dashboard activity appears in `rustgos` logs:
- Web enabled/disabled status
- Listener bind address (never logs credentials)
- History availability state
- Database quarantine events
- Rate-limit triggers
- Session-cookie name (never logs cookie values)

**Redacted from logs:**
- `admin_username` and `admin_password` fields
- Session cookie values
- Full session IDs (only redacted prefixes)
- Database connection strings with absolute paths

Set `RUST_LOG=rustgos=debug` for detailed Web module diagnostics.

## Operational best practices

### Password management

1. Generate strong passwords: `openssl rand -base64 24` (32 characters)
2. Store in environment, not TOML: `export RUSTGO_ADMIN_PASSWORD='...'`
3. Restrict server.toml permissions: `chmod 600 /etc/rustgo/server.toml`
4. Rotate regularly: stop `rustgos`, update password, restart (all sessions expire)

### Reverse proxy hardening

1. Use automatic HTTPS (Caddy) or Let's Encrypt (Nginx)
2. Set `cookie_secure = true` and `external_origin = "https://..."`
3. Keep proxy updated for security patches
4. Consider IP allowlisting at proxy layer for additional protection
5. Enable proxy access logs for audit trail

### Database maintenance

1. Monitor disk space: `database_max_mib` is a cap, not a reservation
2. Backup: Stop `rustgos`, copy main + WAL + SHM files together, restart
3. Quarantine inspection: Check `.quarantine-*` directories for corruption events
4. Cap tuning: Increase `database_max_mib` if hitting cap frequently with valid retention

### Capacity planning

- **History storage**: ~100-500 KB per client-day (varies with report interval)
- **Live memory**: ~1-2 MB per active client session
- **CPU overhead**: <1% for dashboard, <0.1% per client telemetry
- **Network overhead**: ~1-5 KB per client report (default 30s interval = ~10 KB/min per client)

For large deployments (>100 clients), consider:
- Increasing `database_max_mib` to 512-1024 MiB
- Reducing `history_days` to 3-5 days
- Increasing client `report_interval_secs` to 60-120s

## Limitations and non-goals

V0.3 **does not** provide:

- **Multi-user roles**: Only one administrator account
- **Configuration editing**: TOML remains the source of truth
- **Process control**: No restart, reload, or shutdown buttons
- **Client disconnect**: Cannot force-disconnect clients
- **Key rotation**: Still requires coordinated restart procedure
- **Command execution**: No remote shell or arbitrary commands
- **File browsing**: No access to server filesystem
- **Public API**: Dashboard is operator-only, not a public status page
- **Prometheus export**: No metrics in Prometheus format
- **Multi-server clustering**: Each `rustgos` instance is independent
- **Alert delivery**: No email, SMS, webhook notifications
- **JSON logging**: Logs remain human-readable text

These exclusions keep V0.3 focused on read-only observability with a minimal attack surface.

## Security considerations

### Threat model

The dashboard assumes:
- **Trusted operator**: Administrator has legitimate access to server host
- **Hostile network**: Internet-facing reverse proxy may be attacked
- **Untrusted clients**: Dashboard does not trust client-reported telemetry for authorization

The dashboard protects against:
- Brute-force password attacks (rate limiting)
- CSRF (Origin validation, SameSite cookies)
- XSS (CSP, output encoding, no inline scripts)
- SQL injection (parameterized queries)
- Path traversal (no filesystem access)
- Session hijacking (HttpOnly, Secure cookies, HMAC signing)

The dashboard **does not** protect against:
- Compromised operator credentials (secure password required)
- Compromised server host (attacker can read SQLite directly)
- Side-channel attacks on password comparison (constant-time comparison used)

### Incident response

If credentials are compromised:
1. Stop `rustgos` immediately
2. Rotate `admin_password` in `server.toml`
3. Restart `rustgos` (expires all sessions)
4. Review SQLite database for unauthorized queries (none are logged currently)
5. Review reverse proxy access logs for suspicious activity
6. Consider changing `admin_username` as well

If SQLite is corrupted or contains unexpected data:
1. Dashboard automatically quarantines corrupt database
2. Review quarantine directory for forensics
3. Fresh database bootstraps on next startup
4. Historical data is lost (live monitoring continues)

## Release notes

V0.3 adds:
- Optional embedded Web dashboard (disabled by default)
- Authenticated read-only observability API
- Client host telemetry over existing control connection
- SQLite-backed bounded historical retention
- Real-time server and client resource monitoring
- P2P path selection visibility
- Mixed-version compatibility (V0.2 clients supported)

Breaking changes:
- None. V0.3 is fully backward compatible with V0.2 and V0.1 clients.

For complete V0.3 design and architecture, see `docs/superpowers/specs/2026-09-01-rustgo-v0.3-web-dashboard-design.md`.
