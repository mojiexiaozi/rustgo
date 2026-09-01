use rustgo_observability::{
    AuthenticatedClientIdentity, BoundedInventory, BoundedLabel, EVENT_QUEUE_CAPACITY, HostMetrics,
    MAX_EVENT_LABEL_BYTES, MAX_INVENTORY_ITEMS, MAX_TERMINAL_SESSIONS, ObservabilityStore,
    ObservationEvent, PublishError, SessionPath, ShortSessionId, TrafficCounters,
};

fn identity(name: &str, generation: u64) -> AuthenticatedClientIdentity {
    AuthenticatedClientIdentity::from_server_authentication(name, generation).unwrap()
}

fn label(value: &str) -> BoundedLabel {
    BoundedLabel::try_from(value).unwrap()
}

fn inventory<const N: usize>(names: [&str; N]) -> BoundedInventory {
    BoundedInventory::try_from_names(names).unwrap()
}

fn metrics(sampled_unix_millis: u64, cpu_basis_points: u16) -> HostMetrics {
    HostMetrics {
        sampled_unix_millis,
        cpu_basis_points: Some(cpu_basis_points),
        process_cpu_basis_points: Some(cpu_basis_points / 2),
        memory_used_bytes: Some(400),
        memory_total_bytes: Some(1_000),
        process_memory_bytes: Some(100),
        disk_used_bytes: Some(2_000),
        disk_total_bytes: Some(10_000),
        disk_read_bytes_per_sec: Some(11),
        disk_write_bytes_per_sec: Some(12),
        network_rx_bytes_per_sec: Some(13),
        network_tx_bytes_per_sec: Some(14),
    }
}

async fn finish(
    sink: rustgo_observability::ObservabilitySink,
    worker: rustgo_observability::ObservabilityWorker,
) {
    let task = tokio::spawn(worker.run());
    drop(sink);
    task.await.unwrap();
}

#[tokio::test]
async fn lifecycle_events_project_one_immutable_overview() {
    let (store, sink, worker) = ObservabilityStore::new();
    let client = identity("office-laptop", 7);
    let tcp_id = ShortSessionId::from_bytes(b"full-private-tcp-session-id");
    let udp_id = ShortSessionId::from_bytes(b"full-private-udp-session-id");
    let p2p_id = ShortSessionId::from_bytes(b"full-private-p2p-session-id");

    sink.try_publish(ObservationEvent::ClientAuthenticated {
        client: client.clone(),
        version: label("0.3.0"),
        authenticated_unix_millis: 1_000,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::Heartbeat {
        client: client.clone(),
        received_unix_millis: 1_100,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ClientTelemetryAccepted {
        client: client.clone(),
        sequence: 3,
        received_unix_millis: 1_200,
        metrics: metrics(1_150, 2_500),
    })
    .unwrap();
    sink.try_publish(ObservationEvent::TunnelInventory {
        client: client.clone(),
        names: inventory(["ssh", "dns"]),
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ExportInventory {
        client: client.clone(),
        names: inventory(["git"]),
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ForwardInventory {
        client: client.clone(),
        names: inventory(["office-db"]),
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ServerSample {
        metrics: metrics(1_250, 1_200),
    })
    .unwrap();
    sink.try_publish(ObservationEvent::TcpSessionOpened {
        client: client.clone(),
        session_id: tcp_id.clone(),
        tunnel: Some(label("ssh")),
        opened_unix_millis: 1_300,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::UdpSessionOpened {
        client: client.clone(),
        session_id: udp_id,
        tunnel: Some(label("dns")),
        opened_unix_millis: 1_310,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::P2pSessionOpened {
        client: client.clone(),
        session_id: p2p_id,
        peer: label("nas"),
        export: Some(label("git")),
        path: SessionPath::P2pDirect,
        opened_unix_millis: 1_320,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ByteCounterDelta {
        client: client.clone(),
        session_id: Some(tcp_id),
        counters: TrafficCounters {
            received_bytes: 40,
            sent_bytes: 60,
        },
    })
    .unwrap();
    sink.try_publish(ObservationEvent::TcpSessionClosed {
        client: client.clone(),
        session_id: ShortSessionId::from_bytes(b"full-private-tcp-session-id"),
        closed_unix_millis: 1_400,
        terminal_reason: Some(label("eof")),
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ClientDisconnected {
        client,
        disconnected_unix_millis: 1_500,
    })
    .unwrap();

    finish(sink, worker).await;

    let snapshot = store.snapshot();
    assert_eq!(snapshot.generated_unix_millis, 1_500);
    assert_eq!(
        snapshot.server.metrics.unwrap().cpu_basis_points,
        Some(1_200)
    );
    assert_eq!(snapshot.server.traffic.received_bytes, 40);
    assert_eq!(snapshot.server.traffic.sent_bytes, 60);
    assert_eq!(snapshot.server.online_clients, 0);
    assert_eq!(snapshot.server.active_tcp_sessions, 0);
    assert_eq!(snapshot.server.active_udp_sessions, 1);
    assert_eq!(snapshot.server.active_p2p_sessions, 1);

    let projected = &snapshot.clients[0];
    assert_eq!(projected.name.as_str(), "office-laptop");
    assert_eq!(projected.generation, 7);
    assert!(!projected.online);
    assert_eq!(projected.version.as_str(), "0.3.0");
    assert_eq!(projected.last_heartbeat_unix_millis, Some(1_100));
    assert_eq!(projected.telemetry_sequence, Some(3));
    assert_eq!(projected.telemetry_received_unix_millis, Some(1_200));
    assert_eq!(
        projected.metrics.as_ref().unwrap().cpu_basis_points,
        Some(2_500)
    );
    assert_eq!(
        projected
            .tunnels
            .as_slice()
            .iter()
            .map(BoundedLabel::as_str)
            .collect::<Vec<_>>(),
        ["dns", "ssh"]
    );
    assert_eq!(projected.exports.as_slice()[0].as_str(), "git");
    assert_eq!(projected.forwards.as_slice()[0].as_str(), "office-db");
    assert_eq!(projected.traffic.received_bytes, 40);
    assert_eq!(projected.traffic.sent_bytes, 60);
    assert_eq!(snapshot.sessions.len(), 3);
    assert_eq!(
        snapshot
            .sessions
            .iter()
            .find(|session| session.id == ShortSessionId::from_bytes(b"full-private-tcp-session-id"))
            .unwrap()
            .terminal_reason
            .as_ref()
            .map(BoundedLabel::as_str),
        Some("eof")
    );
}

#[tokio::test]
async fn newer_generation_replaces_live_state_and_fences_old_events() {
    let (store, sink, worker) = ObservabilityStore::new();
    let generation_one = identity("office-laptop", 1);
    let generation_two = identity("office-laptop", 2);
    let old_session = ShortSessionId::from_bytes(b"old-generation-session");

    sink.try_publish(ObservationEvent::ClientAuthenticated {
        client: generation_one.clone(),
        version: label("0.3.0"),
        authenticated_unix_millis: 100,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ClientTelemetryAccepted {
        client: generation_one.clone(),
        sequence: 9,
        received_unix_millis: 110,
        metrics: metrics(105, 900),
    })
    .unwrap();
    sink.try_publish(ObservationEvent::P2pSessionOpened {
        client: generation_one.clone(),
        session_id: old_session.clone(),
        peer: label("nas"),
        export: None,
        path: SessionPath::Relay,
        opened_unix_millis: 120,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ClientAuthenticated {
        client: generation_two.clone(),
        version: label("0.3.1"),
        authenticated_unix_millis: 200,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ClientTelemetryAccepted {
        client: generation_one,
        sequence: 10,
        received_unix_millis: 210,
        metrics: metrics(205, 1_000),
    })
    .unwrap();
    sink.try_publish(ObservationEvent::ClientTelemetryAccepted {
        client: generation_two,
        sequence: 1,
        received_unix_millis: 220,
        metrics: metrics(215, 200),
    })
    .unwrap();

    finish(sink, worker).await;

    let snapshot = store.snapshot();
    let client = &snapshot.clients[0];
    assert_eq!(client.generation, 2);
    assert_eq!(client.version.as_str(), "0.3.1");
    assert_eq!(client.reconnects, 1);
    assert_eq!(client.telemetry_sequence, Some(1));
    assert_eq!(client.metrics.as_ref().unwrap().cpu_basis_points, Some(200));
    let replaced = snapshot
        .sessions
        .iter()
        .find(|session| session.id == old_session)
        .unwrap();
    assert_eq!(replaced.closed_unix_millis, Some(200));
    assert_eq!(
        replaced.terminal_reason.as_ref().map(BoundedLabel::as_str),
        Some("generation_replaced")
    );
}

#[tokio::test]
async fn duplicate_and_out_of_order_telemetry_do_not_replace_the_latest_sample() {
    let (store, sink, worker) = ObservabilityStore::new();
    let client = identity("field-device", 4);
    sink.try_publish(ObservationEvent::ClientAuthenticated {
        client: client.clone(),
        version: label("0.3.0"),
        authenticated_unix_millis: 1,
    })
    .unwrap();
    for (sequence, cpu) in [(8, 800), (8, 801), (7, 700), (9, 900)] {
        sink.try_publish(ObservationEvent::ClientTelemetryAccepted {
            client: client.clone(),
            sequence,
            received_unix_millis: 10 + sequence,
            metrics: metrics(sequence, cpu),
        })
        .unwrap();
    }

    finish(sink, worker).await;

    let projected = &store.snapshot().clients[0];
    assert_eq!(projected.telemetry_sequence, Some(9));
    assert_eq!(
        projected.metrics.as_ref().unwrap().cpu_basis_points,
        Some(900)
    );
}

async fn publish_while_worker_drains(
    sink: &rustgo_observability::ObservabilitySink,
    event: ObservationEvent,
) {
    loop {
        match sink.try_publish(event.clone()) {
            Ok(()) => return,
            Err(PublishError::Full) => tokio::task::yield_now().await,
            Err(PublishError::Closed) => panic!("observability worker closed unexpectedly"),
        }
    }
}

#[tokio::test]
async fn terminal_session_churn_keeps_all_active_and_only_the_latest_4096_terminal_sessions() {
    let (store, sink, worker) = ObservabilityStore::new();
    let task = tokio::spawn(worker.run());
    let client = identity("session-device", 1);
    publish_while_worker_drains(
        &sink,
        ObservationEvent::ClientAuthenticated {
            client: client.clone(),
            version: label("0.3.0"),
            authenticated_unix_millis: 1,
        },
    )
    .await;

    let active_tcp = ShortSessionId::from_bytes(b"active-tcp");
    let active_p2p = ShortSessionId::from_bytes(b"active-p2p");
    publish_while_worker_drains(
        &sink,
        ObservationEvent::TcpSessionOpened {
            client: client.clone(),
            session_id: active_tcp.clone(),
            tunnel: Some(label("ssh")),
            opened_unix_millis: 10,
        },
    )
    .await;
    publish_while_worker_drains(
        &sink,
        ObservationEvent::P2pSessionOpened {
            client: client.clone(),
            session_id: active_p2p.clone(),
            peer: label("nas"),
            export: Some(label("backup")),
            path: SessionPath::P2pDirect,
            opened_unix_millis: 11,
        },
    )
    .await;

    for index in 0..=MAX_TERMINAL_SESSIONS {
        let raw_id = format!("terminal-session-{index}");
        let session_id = ShortSessionId::from_bytes(raw_id.as_bytes());
        publish_while_worker_drains(
            &sink,
            ObservationEvent::UdpSessionOpened {
                client: client.clone(),
                session_id: session_id.clone(),
                tunnel: Some(label("dns")),
                opened_unix_millis: 100 + index as u64,
            },
        )
        .await;
        publish_while_worker_drains(
            &sink,
            ObservationEvent::UdpSessionClosed {
                client: client.clone(),
                session_id,
                closed_unix_millis: 10_000 + index as u64,
                terminal_reason: Some(label("complete")),
            },
        )
        .await;
    }

    drop(sink);
    task.await.unwrap();

    let snapshot = store.snapshot();
    assert_eq!(snapshot.sessions.len(), MAX_TERMINAL_SESSIONS + 2);
    assert_eq!(snapshot.server.active_tcp_sessions, 1);
    assert_eq!(snapshot.server.active_p2p_sessions, 1);
    assert!(
        snapshot
            .sessions
            .iter()
            .any(|session| session.id == active_tcp)
    );
    assert!(
        snapshot
            .sessions
            .iter()
            .any(|session| session.id == active_p2p)
    );
    assert!(
        !snapshot
            .sessions
            .iter()
            .any(|session| { session.id == ShortSessionId::from_bytes(b"terminal-session-0") })
    );
    assert!(snapshot.sessions.iter().any(|session| {
        session.id
            == ShortSessionId::from_bytes(
                format!("terminal-session-{MAX_TERMINAL_SESSIONS}").as_bytes(),
            )
    }));
}

#[tokio::test]
async fn labels_reject_more_than_128_utf8_bytes_and_inventory_is_bounded_before_publish() {
    let exact = "界".repeat(MAX_EVENT_LABEL_BYTES / "界".len());
    let exact = format!("{exact}ab");
    assert_eq!(exact.len(), MAX_EVENT_LABEL_BYTES);
    assert!(BoundedLabel::try_from(exact).is_ok());

    let oversized = "界".repeat((MAX_EVENT_LABEL_BYTES / "界".len()) + 1);
    let error = BoundedLabel::try_from(oversized).unwrap_err();
    assert_eq!(error.actual_bytes(), 129);
    assert_eq!(error.maximum_bytes(), MAX_EVENT_LABEL_BYTES);

    let names = (0..300).map(|index| format!("tunnel-{index:03}"));
    let inventory = BoundedInventory::try_from_names(names).unwrap();
    assert_eq!(inventory.len(), MAX_INVENTORY_ITEMS);
    assert_eq!(inventory.as_slice()[0].as_str(), "tunnel-000");
    assert_eq!(inventory.as_slice()[255].as_str(), "tunnel-255");

    let (store, sink, worker) = ObservabilityStore::new();
    let client = identity("bounded-device", 1);
    sink.try_publish(ObservationEvent::ClientAuthenticated {
        client: client.clone(),
        version: label("0.3.0"),
        authenticated_unix_millis: 1,
    })
    .unwrap();
    sink.try_publish(ObservationEvent::TunnelInventory {
        client,
        names: inventory,
    })
    .unwrap();
    finish(sink, worker).await;

    let projected = &store.snapshot().clients[0];
    assert_eq!(projected.tunnels.len(), MAX_INVENTORY_ITEMS);
    assert!(
        projected
            .tunnels
            .as_slice()
            .iter()
            .all(|name| name.as_str().len() <= MAX_EVENT_LABEL_BYTES)
    );
}

#[test]
fn session_ids_are_deterministically_shortened_and_never_serialize_raw_input() {
    let raw = b"0123456789abcdef0123456789abcdef";
    let id = ShortSessionId::from_bytes(raw);
    let encoded = serde_json::to_string(&id).unwrap();

    assert_eq!(id, ShortSessionId::from_bytes(raw));
    assert_eq!(id.as_str().len(), 16);
    assert!(id.as_str().bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(!encoded.contains("0123456789abcdef"));
    assert!(!format!("{id:?}").contains("0123456789abcdef"));
}

#[test]
fn saturated_event_queue_returns_immediately_without_awaiting() {
    let (store, sink, _worker) = ObservabilityStore::new();
    let client = identity("queue-device", 1);

    for received_unix_millis in 0..EVENT_QUEUE_CAPACITY as u64 {
        sink.try_publish(ObservationEvent::Heartbeat {
            client: client.clone(),
            received_unix_millis,
        })
        .unwrap();
    }
    let error = sink
        .try_publish(ObservationEvent::Heartbeat {
            client,
            received_unix_millis: u64::MAX,
        })
        .unwrap_err();

    assert_eq!(error, PublishError::Full);
    assert_eq!(store.snapshot().event_queue_depth, EVENT_QUEUE_CAPACITY);
    assert_eq!(store.snapshot().dropped_events, 1);
}
