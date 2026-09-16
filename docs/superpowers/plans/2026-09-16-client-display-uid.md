# Client display names and server UID

Goal: Display names may repeat and default to the OS username; server-issued stable UID is the identity, shown alongside the client's local connection IP.

Architecture: Keep existing authenticated routing identifiers as compatibility aliases. New approvals allocate a random server UID as both routing ID and internal ID. Display name is separate metadata, never an authentication lookup key. Existing records retain internal ID, keys and managed configuration. Reapproval targets an explicit UID or an existing public key, never a display-name match. Approval still requires an administrator.

Protocol: RegistrationIntent v2 carries a UTF-8 display name and optional UID, signed as part of the existing enrollment transcript. Preserve v1 decode. Protocol 1.5 adds a profile JSON member to managed configuration exchange; omit it with older peers. Profile is extracted before parsing the existing configuration and is persisted separately. Server sets UID from authenticated identity; IP is the client's TLS socket local address.

Interfaces: rustgo_config::ClientProfile { display_name: String, uid: Option<String>, local_ip: Option<String> }; ClientSection.profile: Option<ClientProfile>. ClientSection::display_name() falls back to legacy name. DynamicClient::display_name(), ::local_ip(), existing ::internal_id() expose server data. RegistrationIntent adds optional uid and a v2/profile marker, with for_profile(display_name, uid, purpose). DynamicClientStore::request_profile_approval(display_name, uid, purpose, key, request_id, now) handles v2. DynamicClientStore::update_profile(internal_id, display_name, local_ip) persists authenticated metadata.

- [ ] Server storage: schema migration, signed request mapping, duplicate-name independence, retry/reapproval invariants, profile read/write. Tests use temporary databases and prove duplicate names have different UID, existing key retains identity and deletion requires fresh approval.
- [ ] Protocol/client: v2 codec, UTF-8 bounds, optional local profile, protocol negotiation, actual socket IP, persisted UID/display name, compatibility and codec tests.
- [ ] Server control/web: authenticated profile exchange, display name/UID/local IP on cards, details and approvals, preserve routing keys for actions, search by all three values. Test HTML escaping and action identity.
- [ ] GUI: editable display label and read-only UID/IP; default system username; migration from legacy name; preserve existing single-instance edits.
- [ ] Verify relevant Rust and web tests, build both binaries, deploy server with rollback, restart current client retaining credentials, verify live metadata. Do not approve production enrollment on user's behalf.

Execution uses the subagent-driven-development skill for the independent storage and protocol components; root integrates GUI and deployment. User's explicit implementation instruction supplies scope and authorization.

## Completion evidence

All five tasks completed. Storage migration/identity tests: 24 passed; server library: 70 passed; GUI library/binary: 41/56 passed; web: 14 passed. Protocol/config/core suites passed through peer tests. The process-level P2P test initially selected relay instead of direct under concurrent builds; isolated rerun passed. Remaining telemetry/traffic tests passed (9). Final approval integration passed with duplicate labels, profile-only servers, legacy pending upgrades, new pending crash recovery, socket IP and CLI persistence.

Review fixes: profile sync independent of managed tunnel configuration; CLI persists learned identity; legacy pending requests preserve signed v1 bytes; fresh pending metadata version prevents crash recovery from downgrading to v1.

Deployed server with binary and identity database backup at `/var/backups/rustgo/uid-20260916112834`. Restarted the currently used GUI executable in `deploy/client/updates - 副本`, preserving its credentials/configuration. Verified live protocol 1.5, unchanged existing UID, IP 192.168.100.204, and one active tunnel. Checked overview and configuration UI visually. Existing unrelated single-instance changes remain outside this change's commit.
