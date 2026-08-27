# Task 9 Review Fix Round 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. The task owner explicitly requires inline execution and prohibits subagents.

**Goal:** Close the remaining UDP retirement, local-task ownership, and accepted-listener setup races without weakening bounded relay behavior or data-EOF recovery.

**Architecture:** A server UDP listener is either fully prepared before registration acceptance or its later non-cancellation failure ends the whole control generation. Retirement shares the bounded data queue but cannot be silently lost: a full/closed retirement queue terminates the data channel and generation. Rustgoc assigns a local lease to every flow task so an old join result can remove only the table entry it created.

**Tech Stack:** Rust 1.98, Tokio TCP/UDP/TLS tasks, cancellation tokens, bounded MPSC queues, real-process E2E tests.

**Spec:** `.superpowers/sdd/2026-08-27-rustgo-v0.1/task-9-brief.md` and controller review-fix-round-2 requirements.

## Global Constraints

- Work only in `C:\Users\kimi\Desktop\projects\rustgo\.worktrees\v0.1` and do not use subagents.
- Preserve one authenticated TLS data channel per active UDP tunnel generation and strict datagram boundaries.
- Keep all maps, tasks, sockets, payloads, and queues hard bounded; never block a producer on overload.
- Keep relay-only V0.1 behavior; add no P2P path.
- Preserve data-TLS EOF recovery and validity-gated bidirectional lease refresh.

---

### Task 1: Fail closed when retirement cannot enter the bounded queue

**Files:**
- Modify: `tests/e2e/tests/udp.rs`
- Modify: `crates/rustgos/src/udp.rs`
- Modify: `crates/rustgos/src/registry.rs`
- Modify: `crates/rustgos/src/control.rs`

**Interfaces:**
- Consumes: existing bounded server `try_enqueue`, listener generation cancellation, client data-child fatal guard.
- Produces: retirement enqueue failure as a terminal UDP relay error and server control-generation cancellation observed by `run_active_control`.

- [ ] **Step 1: Write the failing real-process test**

Add a local UDP service that delays one marked reply beyond the server idle lease. With `queue_capacity=1`, an 800 ms idle lease, 500 ms server writer delay, and three external flows, hold a data frame in the queue when the first flow expires. Assert `retirement_queue_full`, generation-1 client cleanup, generation-2 registration/channel readiness, and healthy echo after the delayed old reply fires.

- [ ] **Step 2: Run the test to verify RED**

Run: `cargo test -p rustgo-e2e --test udp retirement_queue_full_tears_down_generation_before_a_delayed_old_reply_can_renew_it -- --exact --nocapture`

Expected: FAIL because the server only counts/drops the retirement and the control generation remains active.

- [ ] **Step 3: Implement the minimal fail-closed path**

Return a terminal `UdpRelayError` when a retirement enqueue is full or closed. Wrap `run_listener` so every non-cancellation setup/relay error cancels its `SessionRuntime`; expose that cancellation to `run_active_control`, which returns an explicit listener-generation error and invokes existing guard shutdown/join.

- [ ] **Step 4: Run the focused test to verify GREEN**

Run the exact command from Step 2 and require the restored public mapping to echo after generation replacement.

### Task 2: Make local task completion ownership-safe

**Files:**
- Modify: `crates/rustgoc/src/udp.rs`

**Interfaces:**
- Consumes: `ClientSessionTable`, `JoinSet` local-task results, retirement and local idle removal.
- Produces: a nonzero generation-local lease in each `ClientSession` and `(session_id, lease)` compare-and-remove completion.

- [ ] **Step 1: Write the failing table regression**

Construct session ID 7 with lease 1, retire it, recreate ID 7 with lease 2, then deliver the old lease-1 completion. Assert the lease-2 entry and its cancellation token remain live.

- [ ] **Step 2: Run the test to verify RED**

Run: `cargo test -p rustgoc udp::tests::old_local_task_completion_cannot_remove_a_recreated_session_id -- --exact --nocapture`

Expected: FAIL because completion currently performs unconditional `remove(session_id)`.

- [ ] **Step 3: Implement local leases**

Allocate each spawned task a checked nonzero `u64` local lease, store it in the table, return it from the task, and add `remove_if_lease`. Retirement, sweep, queue-close, and cleanup still remove immediately; only a join completion is compare-and-remove.

- [ ] **Step 4: Run the focused Rustgoc test to verify GREEN**

Run the exact command from Step 2 and then `cargo test -p rustgoc`.

### Task 3: Reject UDP tunnels whose token cannot be prepared

**Files:**
- Modify: `tests/e2e/tests/udp.rs`
- Modify: `crates/rustgos/src/app.rs`
- Modify: `crates/rustgos/src/registry.rs`
- Modify: `crates/rustgos/src/udp.rs`

**Interfaces:**
- Consumes: per-client binding-store capacity and sequential tunnel registration.
- Produces: `UdpListenerTask::spawn(..., PendingUdpOpen, ...)`, where token/channel preparation succeeds before `TunnelResult.accepted=true`.

- [ ] **Step 1: Write the failing two-tunnel process regression**

Set the internal binding-token capacity to one and register two real UDP tunnels. Assert server registration reports exactly one listener, only one UDP channel becomes ready, the accepted mapping echoes, and the second public port has no false-active mapping.

- [ ] **Step 2: Run the test to verify RED**

Run: `cargo test -p rustgo-e2e --test udp token_capacity_rejects_the_unprepared_udp_tunnel_before_registration -- --exact --nocapture`

Expected: FAIL because both listeners are reported accepted before the second task discovers token exhaustion.

- [ ] **Step 3: Move preparation before acceptance**

Add the internal-only binding-capacity environment override. Bind the UDP socket and call `SessionRuntime::prepare_udp` inside `bind_listener`; return a per-tunnel `RegistryError` on failure. Pass the prepared token/receiver into the spawned listener so no later duplicate preparation or leaked token exists.

- [ ] **Step 4: Run the focused E2E to verify GREEN**

Run the exact command from Step 2 and require the first tunnel to remain usable while the second is rejected.

### Task 4: Regression verification, report, and commit

**Files:**
- Modify: `.superpowers/sdd/2026-08-27-rustgo-v0.1/task-9-report.md`

**Interfaces:**
- Consumes: all three GREEN fixes and their diagnostic events.
- Produces: review-round-2 RED/GREEN, timing/ownership invariants, test evidence, commit, and remaining concerns.

- [ ] **Step 1: Run focused and package suites**

Run UDP E2E, protocol, Rustgos, Rustgoc, and TCP E2E. Preserve the existing data-EOF, bidirectional lease, overload, and reconnect regressions.

- [ ] **Step 2: Run repository gates**

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`, and `git diff --check`.

- [ ] **Step 3: Append the Task 9 report**

Record each observed RED/GREEN, the retirement fail-closed rule, server pre-accept preparation, local lease compare-and-remove, drop/cleanup evidence, exact test counts, and unresolved platform/availability boundaries.

- [ ] **Step 4: Commit and verify clean state**

Commit as `fix: close UDP retirement ownership races`, then verify the full commit hash, staged contents, and an empty `git status --short`.
