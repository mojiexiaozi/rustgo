# Rustgo V0.2 P2P progress

- Plan base: `08d63b6`
- Task 1: complete (`08d63b6..c41148b`, review clean)
- Task 2: complete (`c41148b..45bbb9e`, review clean)
- Task 3: complete (`45bbb9e..d007a8f`, review clean)
- Task 4: complete (`d007a8f..04ebfc2`, review clean)
- Task 5: complete (`04ebfc2..113501a`, review clean)
- Task 6: complete (`113501a..57454ec`, review clean)
- Task 7: complete (`57454ec..0e1aad4`, review clean)
- Task 8: complete (`0e1aad4..089d46e`, review clean)
- Task 9: complete (`089d46e..f14b520`, review clean)
- Task 10: complete (`f14b520..9e2a133`, review clean)
- Task 11: complete (`9e2a133..5f38329`, review clean)
- Task 12: complete (static review clean; Linux netns `all` twice, cleanup audit clean)
- Task 13: complete (`c9fe605..104131c`, review clean; deployed and verified)
- Final whole-branch review: clean through `104131c`

## Binding rulings

- Task 2 requires an opaque bounded relay frame; `ProviderDecision` carries the provider-authoritative protocol.
- Task 3 stream framing uses a strict sequence; UDP uses a 64-packet replay window. Ephemeral authentication material is opaque, single-issuance, and generated with `OsRng`.
- Task 5 uses separate one-use primary/alternate observation tokens bound to session, role, and expiry.
- Task 6 uses message IDs 23/24 for observation request/grant and distinct ID 25 for `ServerNotice`; rendezvous tombstones live through exact signed expiry.
- Task 7 terminal abort edges are `Discovering/Checking -> Closed`; the first authenticated winner is preserved atomically.
- Task 8 reusable `QuicPathAttempt` creates fresh `OsRng` ephemeral authentication per call. QUIC application payload relies on QUIC encryption, while the mutual Rustgo handshake binds the live TLS exporter to the signed peer transcript, roles, session, and version. Manager cancellation centrally revokes endpoint/connection ownership so retained session clones cannot retain the fixed UDP port.
- Task 9 native TCP frames use Task 3 AEAD, bind and reuse the same local port for simultaneous-open attempts, cap attempts at 8, and expose a fresh connection attempt through the path adapter.
