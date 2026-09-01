use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::{Read as _, Write as _};
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::{TryRngCore as _, rngs::OsRng};
use rusqlite::{Connection, OpenFlags, Transaction, params};
use same_file::Handle as SameFileHandle;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;

use crate::{
    AuthenticatedClientIdentity, BoundedLabel, HistoryPoint, HostMetrics, SessionKind, SessionPath,
    SessionSnapshot, TrafficCounters,
};

pub const HISTORY_BATCH_QUEUE_CAPACITY: usize = 1024;
pub const MAX_HISTORY_QUEUE_BYTES: usize = 64 * 1024 * 1024;
pub const HISTORY_CONTROL_QUEUE_CAPACITY: usize = 128;
pub const MAX_HISTORY_RECORDS_PER_BATCH: usize = 8192;
pub const MAX_HISTORY_POINTS: usize = 2000;
pub const HISTORY_SCHEMA_VERSION: u32 = 5;

const RAW_RETENTION_MILLIS: u64 = 60 * 60 * 1000;
const ONE_MINUTE_RETENTION_MILLIS: u64 = 24 * RAW_RETENTION_MILLIS;
const MINUTE_BUCKET_MILLIS: u64 = 60 * 1000;
const FIVE_MINUTE_BUCKET_MILLIS: u64 = 5 * MINUTE_BUCKET_MILLIS;
const DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAINTENANCE_TIMEOUT: Duration = Duration::from_secs(30);
const INITIAL_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(5);
const WARNING_INTERVAL: Duration = Duration::from_secs(30);
const MAX_BATCH_WRITE_ATTEMPTS: usize = 3;
const MAX_BATCHES_PER_TRANSACTION: usize = 64;
const MAX_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
const RETENTION_DELETE_LIMIT: usize = 256;
const CAP_DELETE_LIMIT: usize = 256;
const VACUUM_PAGE_LIMIT: usize = 64;
const MIB: u64 = 1024 * 1024;
const OWNERSHIP_MARKER_SUFFIX: &str = ".rustgo-owner";
const OWNERSHIP_PENDING_MARKER_SUFFIX: &str = ".rustgo-pending";
const OWNERSHIP_MARKER_HEADER: &str = "rustgo-observability-history-v2";
const OWNERSHIP_PENDING_MARKER_HEADER: &str = "rustgo-observability-history-pending-v1";
const STORE_PROOF_HEADER: &str = "rustgo-observability-private-store-v1";
const STORE_PROOF_FILE_NAME: &str = "rustgo-owner-proof";
const LEGACY_OWNERSHIP_MARKER_CONTENT: &[u8] = b"rustgo-observability-history-v1\n";
const RUSTGO_APPLICATION_ID: i64 = 0x5253_474f;
const OWNER_NONCE_BYTES: usize = 32;
const MAINTENANCE_BUCKET_LIMIT: usize = 64;
const CAP_CANDIDATE_PAGE_LIMIT: usize = 64;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const WAL_AUTOCHECKPOINT_PAGES: i64 = 64;
const WAL_JOURNAL_SIZE_LIMIT_BYTES: i64 = 256 * 1024;
const MAINTENANCE_PROGRESS_GRANULARITY: i32 = 1_000;
const MAX_MAINTENANCE_VM_STEPS: u64 = 250_000;
const MAX_MAINTENANCE_TURN: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryConfig {
    pub database_path: PathBuf,
    pub history_days: u16,
    pub database_max_mib: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryConfigError {
    EmptyDatabasePath,
    InvalidHistoryDays,
    InvalidDatabaseMaximum,
}

impl fmt::Display for HistoryConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDatabasePath => {
                formatter.write_str("history database path must not be empty")
            }
            Self::InvalidHistoryDays => {
                formatter.write_str("history retention must be between 1 and 90 days")
            }
            Self::InvalidDatabaseMaximum => {
                formatter.write_str("history database maximum must be between 1 and 4096 MiB")
            }
        }
    }
}

impl std::error::Error for HistoryConfigError {}

impl HistoryConfig {
    fn validate(&self) -> Result<(), HistoryConfigError> {
        if self.database_path.as_os_str().is_empty() {
            return Err(HistoryConfigError::EmptyDatabasePath);
        }
        if !(1..=90).contains(&self.history_days) {
            return Err(HistoryConfigError::InvalidHistoryDays);
        }
        if !(1..=4096).contains(&self.database_max_mib) {
            return Err(HistoryConfigError::InvalidDatabaseMaximum);
        }
        Ok(())
    }

    fn retention_millis(&self) -> u64 {
        u64::from(self.history_days).saturating_mul(DAY_MILLIS)
    }

    fn maximum_bytes(&self) -> u64 {
        u64::from(self.database_max_mib).saturating_mul(MIB)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerHistorySample {
    pub timestamp_unix_millis: u64,
    pub metrics: HostMetrics,
    pub traffic: TrafficCounters,
}

impl ServerHistorySample {
    pub fn from_metrics(metrics: HostMetrics, traffic: TrafficCounters) -> Self {
        Self {
            timestamp_unix_millis: metrics.sampled_unix_millis,
            metrics,
            traffic,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientHistorySample {
    pub client: AuthenticatedClientIdentity,
    pub timestamp_unix_millis: u64,
    pub metrics: HostMetrics,
    pub traffic: TrafficCounters,
}

impl ClientHistorySample {
    pub fn from_metrics(
        client: AuthenticatedClientIdentity,
        metrics: HostMetrics,
        traffic: TrafficCounters,
    ) -> Self {
        Self {
            client,
            timestamp_unix_millis: metrics.sampled_unix_millis,
            metrics,
            traffic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientLifecycleKind {
    Authenticated,
    Disconnected,
}

impl ClientLifecycleKind {
    fn as_database_value(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::Disconnected => "disconnected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLifecycleRecord {
    pub client: AuthenticatedClientIdentity,
    pub kind: ClientLifecycleKind,
    pub timestamp_unix_millis: u64,
    pub version: Option<BoundedLabel>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HistoryBatch {
    pub server_points: Vec<ServerHistorySample>,
    pub client_points: Vec<ClientHistorySample>,
    pub client_lifecycle: Vec<ClientLifecycleRecord>,
    pub session_summaries: Vec<SessionSnapshot>,
}

impl HistoryBatch {
    pub fn record_count(&self) -> usize {
        self.server_points
            .len()
            .saturating_add(self.client_points.len())
            .saturating_add(self.client_lifecycle.len())
            .saturating_add(self.session_summaries.len())
    }

    pub fn is_empty(&self) -> bool {
        self.record_count() == 0
    }

    fn compact(&mut self) {
        self.server_points.shrink_to_fit();
        self.client_points.shrink_to_fit();
        self.client_lifecycle.shrink_to_fit();
        self.session_summaries.shrink_to_fit();
    }

    fn owned_bytes(&self) -> usize {
        let mut bytes = mem::size_of::<Self>()
            .saturating_add(
                self.server_points
                    .capacity()
                    .saturating_mul(mem::size_of::<ServerHistorySample>()),
            )
            .saturating_add(
                self.client_points
                    .capacity()
                    .saturating_mul(mem::size_of::<ClientHistorySample>()),
            )
            .saturating_add(
                self.client_lifecycle
                    .capacity()
                    .saturating_mul(mem::size_of::<ClientLifecycleRecord>()),
            )
            .saturating_add(
                self.session_summaries
                    .capacity()
                    .saturating_mul(mem::size_of::<SessionSnapshot>()),
            );
        for sample in &self.client_points {
            bytes = bytes.saturating_add(sample.client.name().len());
        }
        for lifecycle in &self.client_lifecycle {
            bytes = bytes
                .saturating_add(lifecycle.client.name().len())
                .saturating_add(
                    lifecycle
                        .version
                        .as_ref()
                        .map_or(0, |version| version.as_str().len()),
                );
        }
        for session in &self.session_summaries {
            bytes = bytes
                .saturating_add(session.id.as_str().len())
                .saturating_add(session.client.as_str().len())
                .saturating_add(
                    session
                        .peer
                        .as_ref()
                        .map_or(0, |value| value.as_str().len()),
                )
                .saturating_add(
                    session
                        .tunnel
                        .as_ref()
                        .map_or(0, |value| value.as_str().len()),
                )
                .saturating_add(
                    session
                        .export
                        .as_ref()
                        .map_or(0, |value| value.as_str().len()),
                )
                .saturating_add(
                    session
                        .terminal_reason
                        .as_ref()
                        .map_or(0, |value| value.as_str().len()),
                );
        }
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryMetric {
    CpuBasisPoints,
    ProcessCpuBasisPoints,
    MemoryUsedBytes,
    MemoryTotalBytes,
    ProcessMemoryBytes,
    DiskUsedBytes,
    DiskTotalBytes,
    DiskReadBytesPerSecond,
    DiskWriteBytesPerSecond,
    NetworkRxBytesPerSecond,
    NetworkTxBytesPerSecond,
    TrafficReceivedBytes,
    TrafficSentBytes,
}

impl HistoryMetric {
    fn as_database_value(self) -> &'static str {
        match self {
            Self::CpuBasisPoints => "cpu_basis_points",
            Self::ProcessCpuBasisPoints => "process_cpu_basis_points",
            Self::MemoryUsedBytes => "memory_used_bytes",
            Self::MemoryTotalBytes => "memory_total_bytes",
            Self::ProcessMemoryBytes => "process_memory_bytes",
            Self::DiskUsedBytes => "disk_used_bytes",
            Self::DiskTotalBytes => "disk_total_bytes",
            Self::DiskReadBytesPerSecond => "disk_read_bytes_per_sec",
            Self::DiskWriteBytesPerSecond => "disk_write_bytes_per_sec",
            Self::NetworkRxBytesPerSecond => "network_rx_bytes_per_sec",
            Self::NetworkTxBytesPerSecond => "network_tx_bytes_per_sec",
            Self::TrafficReceivedBytes => "traffic_received_bytes",
            Self::TrafficSentBytes => "traffic_sent_bytes",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "scope", content = "client")]
pub enum HistoryScope {
    Server,
    Client(BoundedLabel),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HistoryResolution {
    Auto,
    Raw,
    OneMinute,
    FiveMinutes,
}

impl HistoryResolution {
    fn database_value(self) -> Option<i64> {
        match self {
            Self::Auto => None,
            Self::Raw => Some(0),
            Self::OneMinute => Some(1),
            Self::FiveMinutes => Some(2),
        }
    }

    fn select_for_range(self, start: u64, end: u64) -> Self {
        if self != Self::Auto {
            return self;
        }
        let range = end.saturating_sub(start);
        if range <= RAW_RETENTION_MILLIS {
            Self::Raw
        } else if range <= ONE_MINUTE_RETENTION_MILLIS {
            Self::OneMinute
        } else {
            Self::FiveMinutes
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryQuery {
    pub scope: HistoryScope,
    pub metric: HistoryMetric,
    pub start_unix_millis: u64,
    pub end_unix_millis: u64,
    pub resolution: HistoryResolution,
    pub max_points: usize,
}

impl HistoryQuery {
    fn validate(&self) -> Result<(), HistoryQueryError> {
        if self.start_unix_millis > self.end_unix_millis {
            return Err(HistoryQueryError::InvalidRange);
        }
        if !(1..=MAX_HISTORY_POINTS).contains(&self.max_points) {
            return Err(HistoryQueryError::InvalidPointLimit);
        }
        if self.end_unix_millis > i64::MAX as u64 {
            return Err(HistoryQueryError::InvalidRange);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistorySeries {
    pub resolution: HistoryResolution,
    pub points: Vec<HistoryPoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryHealth {
    pub history_available: bool,
    pub pending_batches: usize,
    pub dropped_batches: u64,
    pub recoveries: u64,
    pub total_database_bytes: u64,
    pub size_floor_reached: bool,
    pub pending_batch_bytes: usize,
    pub dropped_batch_bytes: u64,
    pub dropped_late_points: u64,
    pub history_failures: u64,
    pub worker_running: bool,
    pub maximum_maintenance_scan_rows: u64,
    pub maximum_maintenance_vm_steps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryPublishError {
    Closed,
    EmptyBatch,
    BatchTooLarge,
    BatchMemoryTooLarge,
}

impl fmt::Display for HistoryPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("history writer is closed"),
            Self::EmptyBatch => formatter.write_str("history batch is empty"),
            Self::BatchTooLarge => write!(
                formatter,
                "history batch exceeds the {MAX_HISTORY_RECORDS_PER_BATCH}-record limit"
            ),
            Self::BatchMemoryTooLarge => formatter.write_str(
                "history batch exceeds the bounded owned-memory or database-size budget",
            ),
        }
    }
}

impl std::error::Error for HistoryPublishError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryQueryError {
    InvalidRange,
    InvalidPointLimit,
    Overloaded,
    Unavailable,
    TimedOut,
    Closed,
}

impl fmt::Display for HistoryQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange => formatter.write_str("history query range is invalid"),
            Self::InvalidPointLimit => write!(
                formatter,
                "history query point limit must be between 1 and {MAX_HISTORY_POINTS}"
            ),
            Self::Overloaded => formatter.write_str("history query queue is full"),
            Self::Unavailable => formatter.write_str("history is temporarily unavailable"),
            Self::TimedOut => {
                formatter.write_str("history query exceeded its five-second deadline")
            }
            Self::Closed => formatter.write_str("history worker is closed"),
        }
    }
}

impl std::error::Error for HistoryQueryError {}

#[derive(Debug)]
pub enum HistoryWorkerError {
    ThreadSpawn(io::Error),
    ReaperSpawn(io::Error),
    ThreadPanicked,
    JoinTaskCancelled,
}

impl fmt::Display for HistoryWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreadSpawn(error) => {
                write!(formatter, "failed to start history worker: {error}")
            }
            Self::ReaperSpawn(error) => {
                write!(formatter, "failed to start history thread reaper: {error}")
            }
            Self::ThreadPanicked => formatter.write_str("history worker panicked"),
            Self::JoinTaskCancelled => {
                formatter.write_str("history worker join task was cancelled")
            }
        }
    }
}

impl std::error::Error for HistoryWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ThreadSpawn(error) | Self::ReaperSpawn(error) => Some(error),
            Self::ThreadPanicked | Self::JoinTaskCancelled => None,
        }
    }
}

struct QueuedBatch {
    batch: HistoryBatch,
    owned_bytes: usize,
}

enum Command {
    Batch(QueuedBatch),
    Query(
        HistoryQuery,
        oneshot::Sender<Result<HistorySeries, HistoryQueryError>>,
    ),
    Maintain(u64, oneshot::Sender<Result<(), HistoryQueryError>>),
    Checkpoint(oneshot::Sender<Result<(), HistoryQueryError>>),
}

impl Command {
    fn is_batch(&self) -> bool {
        matches!(self, Self::Batch(_))
    }

    fn fail_unavailable(self) -> Option<Self> {
        match self {
            Self::Batch(_) => Some(self),
            Self::Query(_, response) => {
                let _ = response.send(Err(HistoryQueryError::Unavailable));
                None
            }
            Self::Maintain(_, response) | Self::Checkpoint(response) => {
                let _ = response.send(Err(HistoryQueryError::Unavailable));
                None
            }
        }
    }
}

#[derive(Default)]
struct QueueState {
    commands: VecDeque<Command>,
    queued_batches: usize,
    pending_batches: usize,
    pending_controls: usize,
    pending_batch_bytes: usize,
    closed: bool,
}

struct Shared {
    queue: Mutex<QueueState>,
    ready: Condvar,
    handles: AtomicUsize,
    history_available: AtomicBool,
    dropped_batches: AtomicU64,
    recoveries: AtomicU64,
    total_database_bytes: AtomicU64,
    size_floor_reached: AtomicBool,
    dropped_batch_bytes: AtomicU64,
    dropped_late_points: AtomicU64,
    history_failures: AtomicU64,
    worker_running: AtomicBool,
    maximum_maintenance_scan_rows: AtomicU64,
    maximum_maintenance_vm_steps: AtomicU64,
    maximum_database_bytes: u64,
}

impl Shared {
    fn new(maximum_database_bytes: u64) -> Self {
        Self {
            queue: Mutex::new(QueueState::default()),
            ready: Condvar::new(),
            handles: AtomicUsize::new(1),
            history_available: AtomicBool::new(false),
            dropped_batches: AtomicU64::new(0),
            recoveries: AtomicU64::new(0),
            total_database_bytes: AtomicU64::new(0),
            size_floor_reached: AtomicBool::new(false),
            dropped_batch_bytes: AtomicU64::new(0),
            dropped_late_points: AtomicU64::new(0),
            history_failures: AtomicU64::new(0),
            worker_running: AtomicBool::new(false),
            maximum_maintenance_scan_rows: AtomicU64::new(0),
            maximum_maintenance_vm_steps: AtomicU64::new(0),
            maximum_database_bytes,
        }
    }

    fn push_batch(&self, batch: QueuedBatch) -> Result<(), HistoryPublishError> {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if queue.closed {
            return Err(HistoryPublishError::Closed);
        }
        while queue.pending_batches >= HISTORY_BATCH_QUEUE_CAPACITY
            || queue.pending_batch_bytes.saturating_add(batch.owned_bytes) > MAX_HISTORY_QUEUE_BYTES
        {
            let Some(position) = queue.commands.iter().position(Command::is_batch) else {
                self.dropped_batches.fetch_add(1, Ordering::Relaxed);
                self.dropped_batch_bytes
                    .fetch_add(batch.owned_bytes as u64, Ordering::Relaxed);
                return Err(HistoryPublishError::BatchMemoryTooLarge);
            };
            let Some(Command::Batch(evicted)) = queue.commands.remove(position) else {
                unreachable!("the located command is a history batch");
            };
            queue.queued_batches -= 1;
            queue.pending_batches -= 1;
            queue.pending_batch_bytes = queue
                .pending_batch_bytes
                .saturating_sub(evicted.owned_bytes);
            self.dropped_batches.fetch_add(1, Ordering::Relaxed);
            self.dropped_batch_bytes
                .fetch_add(evicted.owned_bytes as u64, Ordering::Relaxed);
        }
        queue.pending_batch_bytes = queue.pending_batch_bytes.saturating_add(batch.owned_bytes);
        queue.commands.push_back(Command::Batch(batch));
        queue.queued_batches += 1;
        queue.pending_batches += 1;
        self.ready.notify_one();
        Ok(())
    }

    fn push_control(&self, command: Command) -> Result<(), HistoryQueryError> {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if queue.closed {
            return Err(HistoryQueryError::Closed);
        }
        if queue.pending_controls >= HISTORY_CONTROL_QUEUE_CAPACITY {
            return Err(HistoryQueryError::Overloaded);
        }
        queue.commands.push_back(command);
        queue.pending_controls += 1;
        self.ready.notify_one();
        Ok(())
    }

    fn pop(&self, wait: Duration) -> Option<Command> {
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut queue = if queue.commands.is_empty() && !queue.closed {
            self.ready
                .wait_timeout(queue, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0
        } else {
            queue
        };
        let command = queue.commands.pop_front()?;
        if command.is_batch() {
            queue.queued_batches -= 1;
        } else {
            queue.pending_controls -= 1;
        }
        Some(command)
    }

    fn pop_control(&self, wait: Duration) -> Option<Command> {
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut queue = if queue.commands.is_empty() && !queue.closed {
            self.ready
                .wait_timeout(queue, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0
        } else {
            queue
        };
        if queue.commands.front().is_some_and(Command::is_batch) {
            return None;
        }
        let command = queue.commands.pop_front()?;
        queue.pending_controls -= 1;
        Some(command)
    }

    fn drain_following_batches(&self, batches: &mut Vec<QueuedBatch>) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut transaction_bytes = batches
            .iter()
            .map(|batch| batch.owned_bytes)
            .fold(0_usize, usize::saturating_add);
        while batches.len() < MAX_BATCHES_PER_TRANSACTION
            && queue.commands.front().is_some_and(Command::is_batch)
        {
            let next_bytes = match queue.commands.front() {
                Some(Command::Batch(batch)) => batch.owned_bytes,
                _ => break,
            };
            if !batches.is_empty()
                && transaction_bytes.saturating_add(next_bytes) > MAX_TRANSACTION_BYTES
            {
                break;
            }
            let Some(Command::Batch(batch)) = queue.commands.pop_front() else {
                break;
            };
            queue.queued_batches -= 1;
            transaction_bytes = transaction_bytes.saturating_add(batch.owned_bytes);
            batches.push(batch);
        }
    }

    fn wait(&self, duration: Duration) {
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !queue.closed {
            drop(
                self.ready
                    .wait_timeout(queue, duration)
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
        }
    }

    fn fail_pending_controls(&self) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut retained = VecDeque::with_capacity(queue.queued_batches);
        while let Some(command) = queue.commands.pop_front() {
            if let Some(batch) = command.fail_unavailable() {
                retained.push_back(batch);
            }
        }
        queue.commands = retained;
        queue.pending_controls = 0;
    }

    fn close(&self) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.closed = true;
        self.ready.notify_all();
    }

    fn discard_batches_when_closed(&self) -> bool {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !queue.closed {
            return false;
        }
        let mut discarded_batches = 0_u64;
        let mut discarded_bytes = 0_usize;
        for command in &queue.commands {
            if let Command::Batch(batch) = command {
                discarded_batches += 1;
                discarded_bytes = discarded_bytes.saturating_add(batch.owned_bytes);
            }
        }
        self.dropped_batches
            .fetch_add(discarded_batches, Ordering::Relaxed);
        self.dropped_batch_bytes
            .fetch_add(discarded_bytes as u64, Ordering::Relaxed);
        queue.commands.clear();
        queue.queued_batches = 0;
        queue.pending_batches = queue
            .pending_batches
            .saturating_sub(discarded_batches as usize);
        queue.pending_controls = 0;
        queue.pending_batch_bytes = queue.pending_batch_bytes.saturating_sub(discarded_bytes);
        true
    }

    fn pending_batches(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_batches
    }

    fn pending_batch_bytes(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_batch_bytes
    }

    fn record_dropped_batch(&self, batch: &QueuedBatch) {
        self.dropped_batches.fetch_add(1, Ordering::Relaxed);
        self.dropped_batch_bytes
            .fetch_add(batch.owned_bytes as u64, Ordering::Relaxed);
    }

    fn release_owned_batch(&self, batch: &QueuedBatch) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.pending_batches = queue.pending_batches.saturating_sub(1);
        queue.pending_batch_bytes = queue.pending_batch_bytes.saturating_sub(batch.owned_bytes);
    }

    fn is_closed(&self) -> bool {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
    }
}

pub struct HistoryService {
    shared: Arc<Shared>,
}

impl Clone for HistoryService {
    fn clone(&self) -> Self {
        self.shared.handles.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl fmt::Debug for HistoryService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoryService")
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

impl Drop for HistoryService {
    fn drop(&mut self) {
        if self.shared.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.close();
        }
    }
}

pub struct HistoryWorker {
    config: HistoryConfig,
    shared: Arc<Shared>,
}

pub struct HistoryWorkerHandle {
    thread: Option<thread::JoinHandle<()>>,
    shared: Arc<Shared>,
    reaper: mpsc::Sender<thread::JoinHandle<()>>,
}

static WORKER_REAPER: OnceLock<mpsc::Sender<thread::JoinHandle<()>>> = OnceLock::new();

struct WorkerRunningFlag(Arc<Shared>);

impl Drop for WorkerRunningFlag {
    fn drop(&mut self) {
        self.0.worker_running.store(false, Ordering::Release);
    }
}

impl fmt::Debug for HistoryWorkerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoryWorkerHandle")
            .field(
                "worker_running",
                &self.shared.worker_running.load(Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl HistoryWorkerHandle {
    pub async fn shutdown(mut self) -> Result<(), HistoryWorkerError> {
        self.shared.close();
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .map_err(|_| HistoryWorkerError::JoinTaskCancelled)?
            .map_err(|_| HistoryWorkerError::ThreadPanicked)
    }
}

impl Drop for HistoryWorkerHandle {
    fn drop(&mut self) {
        self.shared.close();
        if let Some(thread) = self.thread.take() {
            if let Err(error) = self.reaper.send(thread) {
                let worker = error.0;
                let _ = thread::Builder::new()
                    .name("rustgo-sqlite-history-reaper-fallback".to_owned())
                    .spawn(move || {
                        let _ = worker.join();
                    });
            }
        }
    }
}

fn worker_reaper() -> Result<mpsc::Sender<thread::JoinHandle<()>>, HistoryWorkerError> {
    if let Some(sender) = WORKER_REAPER.get() {
        return Ok(sender.clone());
    }
    let (sender, receiver) = mpsc::channel::<thread::JoinHandle<()>>();
    thread::Builder::new()
        .name("rustgo-sqlite-history-reaper".to_owned())
        .spawn(move || {
            while let Ok(worker) = receiver.recv() {
                if worker.join().is_err() {
                    tracing::error!("SQLite history worker panicked during reaped shutdown");
                }
            }
        })
        .map_err(HistoryWorkerError::ReaperSpawn)?;
    if WORKER_REAPER.set(sender.clone()).is_err() {
        return Ok(WORKER_REAPER
            .get()
            .expect("history reaper sender was initialized concurrently")
            .clone());
    }
    Ok(sender)
}

impl fmt::Debug for HistoryWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoryWorker")
            .field("database_path", &self.config.database_path)
            .finish_non_exhaustive()
    }
}

impl HistoryService {
    pub fn new(config: HistoryConfig) -> Result<(Self, HistoryWorker), HistoryConfigError> {
        config.validate()?;
        let shared = Arc::new(Shared::new(config.maximum_bytes()));
        Ok((
            Self {
                shared: Arc::clone(&shared),
            },
            HistoryWorker { config, shared },
        ))
    }

    pub fn try_publish(&self, mut batch: HistoryBatch) -> Result<(), HistoryPublishError> {
        if batch.is_empty() {
            return Err(HistoryPublishError::EmptyBatch);
        }
        if batch.record_count() > MAX_HISTORY_RECORDS_PER_BATCH {
            return Err(HistoryPublishError::BatchTooLarge);
        }
        batch.compact();
        let owned_bytes = batch
            .owned_bytes()
            .saturating_add(mem::size_of::<Command>());
        if owned_bytes > MAX_HISTORY_QUEUE_BYTES
            || owned_bytes as u64 > self.shared.maximum_database_bytes
        {
            self.shared.dropped_batches.fetch_add(1, Ordering::Relaxed);
            self.shared
                .dropped_batch_bytes
                .fetch_add(owned_bytes as u64, Ordering::Relaxed);
            return Err(HistoryPublishError::BatchMemoryTooLarge);
        }
        self.shared.push_batch(QueuedBatch { batch, owned_bytes })
    }

    pub async fn query(&self, query: HistoryQuery) -> Result<HistorySeries, HistoryQueryError> {
        query.validate()?;
        let (response, received) = oneshot::channel();
        self.shared.push_control(Command::Query(query, response))?;
        match tokio::time::timeout(QUERY_TIMEOUT, received).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(HistoryQueryError::Closed),
            Err(_) => Err(HistoryQueryError::TimedOut),
        }
    }

    pub async fn maintain(&self, now_unix_millis: u64) -> Result<(), HistoryQueryError> {
        if now_unix_millis > i64::MAX as u64 {
            return Err(HistoryQueryError::InvalidRange);
        }
        let (response, received) = oneshot::channel();
        self.shared
            .push_control(Command::Maintain(now_unix_millis, response))?;
        match tokio::time::timeout(MAINTENANCE_TIMEOUT, received).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(HistoryQueryError::Closed),
            Err(_) => Err(HistoryQueryError::TimedOut),
        }
    }

    pub async fn checkpoint(&self) -> Result<(), HistoryQueryError> {
        let (response, received) = oneshot::channel();
        self.shared.push_control(Command::Checkpoint(response))?;
        match tokio::time::timeout(QUERY_TIMEOUT, received).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(HistoryQueryError::Closed),
            Err(_) => Err(HistoryQueryError::TimedOut),
        }
    }

    pub fn health(&self) -> HistoryHealth {
        HistoryHealth {
            history_available: self.shared.history_available.load(Ordering::Acquire),
            pending_batches: self.shared.pending_batches(),
            dropped_batches: self.shared.dropped_batches.load(Ordering::Relaxed),
            recoveries: self.shared.recoveries.load(Ordering::Relaxed),
            total_database_bytes: self.shared.total_database_bytes.load(Ordering::Relaxed),
            size_floor_reached: self.shared.size_floor_reached.load(Ordering::Relaxed),
            pending_batch_bytes: self.shared.pending_batch_bytes(),
            dropped_batch_bytes: self.shared.dropped_batch_bytes.load(Ordering::Relaxed),
            dropped_late_points: self.shared.dropped_late_points.load(Ordering::Relaxed),
            history_failures: self.shared.history_failures.load(Ordering::Relaxed),
            worker_running: self.shared.worker_running.load(Ordering::Acquire),
            maximum_maintenance_scan_rows: self
                .shared
                .maximum_maintenance_scan_rows
                .load(Ordering::Relaxed),
            maximum_maintenance_vm_steps: self
                .shared
                .maximum_maintenance_vm_steps
                .load(Ordering::Relaxed),
        }
    }

    pub fn close(&self) {
        self.shared.close();
    }
}

impl HistoryWorker {
    pub fn start(mut self) -> Result<HistoryWorkerHandle, HistoryWorkerError> {
        let reaper = worker_reaper()?;
        let shared = Arc::clone(&self.shared);
        let thread_shared = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("rustgo-sqlite-history".to_owned())
            .spawn(move || {
                thread_shared.worker_running.store(true, Ordering::Release);
                let _running = WorkerRunningFlag(Arc::clone(&thread_shared));
                self.run_blocking();
            })
            .map_err(HistoryWorkerError::ThreadSpawn)?;
        Ok(HistoryWorkerHandle {
            thread: Some(thread),
            shared,
            reaper,
        })
    }

    fn run_blocking(&mut self) {
        let mut connection = None;
        let mut active_database_path: Option<PathBuf> = None;
        let mut retry_backoff = INITIAL_RETRY_BACKOFF;
        let mut next_open_attempt = Instant::now();
        let mut retry_batches: VecDeque<(QueuedBatch, usize)> = VecDeque::new();
        let mut next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
        let mut maintenance: Option<MaintenanceJob> = None;
        let mut cap: Option<CapState> = None;
        let mut background_turn = false;
        let mut warning_limiter = WarningLimiter::default();

        loop {
            if self.shared.is_closed() {
                if let Some(job) = maintenance.take() {
                    job.finish(Err(HistoryQueryError::Closed));
                }
                while let Some((batch, _)) = retry_batches.pop_front() {
                    self.shared.release_owned_batch(&batch);
                    self.shared.record_dropped_batch(&batch);
                }
                self.shared.fail_pending_controls();
                self.shared.discard_batches_when_closed();
                if let (Some(database), Some(database_path)) =
                    (connection.as_ref(), active_database_path.as_ref())
                {
                    let _ = checkpoint_database(database, database_path, &self.shared);
                }
                return;
            }

            if connection.is_none() {
                if self.shared.history_failures.load(Ordering::Relaxed) > 0 {
                    self.shared.fail_pending_controls();
                }
                let now = Instant::now();
                if now < next_open_attempt {
                    self.shared.wait(next_open_attempt.duration_since(now));
                    continue;
                }
                match open_database(&self.config) {
                    Ok(opened) => {
                        if opened.recovered_interrupted_quarantine {
                            self.shared.recoveries.fetch_add(1, Ordering::Relaxed);
                        }
                        if retry_batches.is_empty() {
                            if !self.shared.history_available.swap(true, Ordering::AcqRel)
                                && self.shared.history_failures.load(Ordering::Relaxed) > 0
                            {
                                tracing::info!(
                                    "SQLite history recovered; persisted metrics are available again"
                                );
                            }
                        } else {
                            self.shared
                                .history_available
                                .store(false, Ordering::Release);
                        }
                        active_database_path = Some(opened.database_path);
                        connection = Some(opened.connection);
                        cap.get_or_insert_default();
                        if retry_batches.is_empty() {
                            retry_backoff = INITIAL_RETRY_BACKOFF;
                        }
                        background_turn = true;
                    }
                    Err(error) => {
                        self.database_failed(&error, &mut warning_limiter);
                        active_database_path = None;
                        if error.should_quarantine()
                            && quarantine_database(&self.config.database_path).unwrap_or(false)
                        {
                            self.shared.recoveries.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                "SQLite history file was quarantined; a fresh bounded history database will be created"
                            );
                            next_open_attempt = Instant::now();
                            continue;
                        }
                        next_open_attempt = Instant::now() + retry_backoff;
                        retry_backoff = doubled_backoff(retry_backoff);
                        continue;
                    }
                }
            }

            let database = connection
                .as_mut()
                .expect("history connection is initialized above");

            if let Some((batch, attempts)) = retry_batches.pop_front() {
                match persist_batches(
                    database,
                    std::slice::from_ref(&batch),
                    active_database_path
                        .as_deref()
                        .expect("open history database has a stable private path"),
                    &self.shared,
                ) {
                    Ok(()) => {
                        self.shared.release_owned_batch(&batch);
                        self.shared
                            .history_available
                            .store(retry_batches.is_empty(), Ordering::Release);
                        cap.get_or_insert_default();
                        background_turn = true;
                        retry_backoff = INITIAL_RETRY_BACKOFF;
                    }
                    Err(error) => {
                        self.database_failed(&error, &mut warning_limiter);
                        connection = None;
                        active_database_path = None;
                        self.quarantine_after_failure(&error);
                        if attempts + 1 < MAX_BATCH_WRITE_ATTEMPTS {
                            retry_batches.push_front((batch, attempts + 1));
                        } else {
                            self.shared.release_owned_batch(&batch);
                            self.shared.record_dropped_batch(&batch);
                        }
                        next_open_attempt = Instant::now() + retry_backoff;
                        retry_backoff = doubled_backoff(retry_backoff);
                        continue;
                    }
                }
            }

            if maintenance.as_ref().is_some_and(MaintenanceJob::cancelled) {
                maintenance = None;
            }
            if maintenance.is_none() && Instant::now() >= next_maintenance {
                maintenance = Some(MaintenanceJob::new(unix_millis_now(), None));
                background_turn = true;
            }

            if background_turn {
                if let Some(state) = cap.as_mut() {
                    let database_path = active_database_path
                        .as_deref()
                        .expect("open history database has a stable private path");
                    match bounded_maintenance_turn(database, &self.shared, |database| {
                        enforce_size_cap_step(
                            database,
                            database_path,
                            &self.config,
                            &self.shared,
                            state,
                        )
                    }) {
                        Ok(Some(true)) => cap = None,
                        Ok(Some(false) | None) => {}
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            connection = None;
                            active_database_path = None;
                            self.quarantine_after_failure(&error);
                            next_open_attempt = Instant::now() + retry_backoff;
                            retry_backoff = doubled_backoff(retry_backoff);
                            continue;
                        }
                    }
                    background_turn = false;
                    continue;
                }
                if let Some(job) = maintenance.as_mut() {
                    let database_path = active_database_path
                        .as_deref()
                        .expect("open history database has a stable private path");
                    match bounded_maintenance_turn(database, &self.shared, |database| {
                        maintenance_step(database, database_path, &self.config, job, &self.shared)
                    }) {
                        Ok(Some(true)) => {
                            let completed = maintenance
                                .take()
                                .expect("completed maintenance job remains owned");
                            completed.finish(Ok(()));
                            next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
                        }
                        Ok(Some(false) | None) => {}
                        Err(error) => {
                            if let Some(failed) = maintenance.take() {
                                failed.finish(Err(HistoryQueryError::Unavailable));
                            }
                            self.database_failed(&error, &mut warning_limiter);
                            connection = None;
                            active_database_path = None;
                            self.quarantine_after_failure(&error);
                            next_open_attempt = Instant::now() + retry_backoff;
                            retry_backoff = doubled_backoff(retry_backoff);
                            continue;
                        }
                    }
                    background_turn = false;
                    continue;
                }
            }

            let cap_pending = cap.is_some()
                || maintenance
                    .as_ref()
                    .is_some_and(MaintenanceJob::enforcing_cap);
            let background_pending = cap_pending || maintenance.is_some();
            let wait = if background_pending {
                Duration::ZERO
            } else {
                next_maintenance.saturating_duration_since(Instant::now())
            };
            let command = if cap_pending {
                self.shared.pop_control(wait)
            } else {
                self.shared.pop(wait)
            };
            let Some(command) = command else {
                if background_pending {
                    background_turn = true;
                }
                continue;
            };
            background_turn = true;

            match command {
                Command::Batch(batch) => {
                    let mut batches = vec![batch];
                    self.shared.drain_following_batches(&mut batches);
                    match persist_batches(
                        database,
                        &batches,
                        active_database_path
                            .as_deref()
                            .expect("open history database has a stable private path"),
                        &self.shared,
                    ) {
                        Ok(()) => {
                            for batch in &batches {
                                self.shared.release_owned_batch(batch);
                            }
                            self.shared.history_available.store(true, Ordering::Release);
                            cap.get_or_insert_default();
                            retry_backoff = INITIAL_RETRY_BACKOFF;
                        }
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            retry_batches.extend(batches.into_iter().map(|batch| (batch, 1)));
                            connection = None;
                            active_database_path = None;
                            self.quarantine_after_failure(&error);
                            next_open_attempt = Instant::now() + retry_backoff;
                            retry_backoff = doubled_backoff(retry_backoff);
                        }
                    }
                }
                Command::Query(query, response) => {
                    if response.is_closed() {
                        continue;
                    }
                    match query_database(database, &query) {
                        Ok(series) => {
                            let _ = response.send(Ok(series));
                        }
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            let _ = response.send(Err(HistoryQueryError::Unavailable));
                            connection = None;
                            active_database_path = None;
                            self.quarantine_after_failure(&error);
                            next_open_attempt = Instant::now() + retry_backoff;
                            retry_backoff = doubled_backoff(retry_backoff);
                        }
                    }
                }
                Command::Maintain(now, response) => {
                    if response.is_closed() {
                        continue;
                    }
                    if maintenance.is_some() {
                        let _ = response.send(Err(HistoryQueryError::Overloaded));
                    } else {
                        maintenance = Some(MaintenanceJob::new(now, Some(response)));
                    }
                }
                Command::Checkpoint(response) => {
                    if response.is_closed() {
                        continue;
                    }
                    match checkpoint_database(
                        database,
                        active_database_path
                            .as_deref()
                            .expect("open history database has a stable private path"),
                        &self.shared,
                    ) {
                        Ok(()) => {
                            let _ = response.send(Ok(()));
                        }
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            let _ = response.send(Err(HistoryQueryError::Unavailable));
                            connection = None;
                            active_database_path = None;
                            self.quarantine_after_failure(&error);
                            next_open_attempt = Instant::now() + retry_backoff;
                            retry_backoff = doubled_backoff(retry_backoff);
                        }
                    }
                }
            }
        }
    }

    fn database_failed(&self, error: &DatabaseError, warnings: &mut WarningLimiter) {
        self.shared
            .history_available
            .store(false, Ordering::Release);
        self.shared.history_failures.fetch_add(1, Ordering::Relaxed);
        warnings.warn(error);
    }

    fn quarantine_after_failure(&self, error: &DatabaseError) {
        if error.should_quarantine()
            && quarantine_database(&self.config.database_path).unwrap_or(false)
        {
            self.shared.recoveries.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for HistoryWorker {
    fn drop(&mut self) {
        self.shared.close();
    }
}

#[derive(Default)]
struct WarningLimiter {
    last_warning: Option<Instant>,
}

impl WarningLimiter {
    fn warn(&mut self, error: &DatabaseError) {
        let now = Instant::now();
        if self
            .last_warning
            .is_some_and(|last| now.duration_since(last) < WARNING_INTERVAL)
        {
            return;
        }
        self.last_warning = Some(now);
        tracing::warn!(
            error = %error,
            "SQLite history is unavailable; live observability remains active and history will retry"
        );
    }
}

#[derive(Debug)]
enum DatabaseError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    IncompatibleSchema(u32),
    Integrity(String),
    ValueOutOfRange(&'static str),
    UnsafePath(&'static str),
    SchemaDamage(String),
    Ownership(String),
}

impl DatabaseError {
    fn should_quarantine(&self) -> bool {
        match self {
            Self::IncompatibleSchema(_) | Self::Integrity(_) | Self::SchemaDamage(_) => true,
            Self::Sqlite(rusqlite::Error::SqliteFailure(code, _)) => matches!(
                code.code,
                rusqlite::ffi::ErrorCode::DatabaseCorrupt | rusqlite::ffi::ErrorCode::NotADatabase
            ),
            Self::Sqlite(_)
            | Self::Io(_)
            | Self::ValueOutOfRange(_)
            | Self::UnsafePath(_)
            | Self::Ownership(_) => false,
        }
    }
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite operation failed: {error}"),
            Self::Io(error) => write!(formatter, "history file operation failed: {error}"),
            Self::IncompatibleSchema(version) => write!(
                formatter,
                "history schema version {version} is newer than supported version {HISTORY_SCHEMA_VERSION}"
            ),
            Self::Integrity(result) => {
                write!(
                    formatter,
                    "history database integrity check failed: {result}"
                )
            }
            Self::ValueOutOfRange(field) => {
                write!(
                    formatter,
                    "history {field} is outside SQLite's integer range"
                )
            }
            Self::UnsafePath(reason) => write!(formatter, "unsafe history database path: {reason}"),
            Self::SchemaDamage(reason) => write!(formatter, "history schema is damaged: {reason}"),
            Self::Ownership(reason) => {
                write!(formatter, "history ownership marker is invalid: {reason}")
            }
        }
    }
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<io::Error> for DatabaseError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct OpenedDatabase {
    connection: Connection,
    database_path: PathBuf,
    recovered_interrupted_quarantine: bool,
}

fn open_database(config: &HistoryConfig) -> Result<OpenedDatabase, DatabaseError> {
    if is_protected_history_path(&config.database_path) {
        return Err(DatabaseError::UnsafePath(
            "configuration, key, and certificate-like paths are not valid history databases",
        ));
    }
    let recovered_interrupted_quarantine = resume_interrupted_quarantine(&config.database_path)?;
    validate_database_path(&config.database_path)?;
    let legacy_marker = has_legacy_ownership_marker(&config.database_path)?;
    let ready = if legacy_marker {
        None
    } else {
        read_marker_file_with_handle(&ownership_marker_path(&config.database_path))?
    };
    let pending = read_pending_marker(&config.database_path)?;
    let opened = if let Some((marker, held_marker)) = ready {
        if pending
            .as_ref()
            .is_some_and(|pending| pending.nonce != marker.nonce)
        {
            return Err(DatabaseError::Ownership(
                "ready and pending ownership markers disagree".to_owned(),
            ));
        }
        let opened = open_ready_database(&config.database_path, &marker.nonce, &held_marker)?;
        if let Some(pending) = pending {
            retire_pending_marker(&config.database_path, &pending)?;
        }
        opened
    } else if let Some(pending) = pending {
        resume_pending_database(&config.database_path, &pending)?
    } else if legacy_marker {
        start_legacy_migration(&config.database_path)?
    } else if fs::symlink_metadata(&config.database_path).is_ok() {
        return Err(DatabaseError::Ownership(
            "existing path has no verifiable Rustgo ownership marker".to_owned(),
        ));
    } else {
        start_private_bootstrap(&config.database_path)?
    };
    Ok(OpenedDatabase {
        connection: opened.0,
        database_path: opened.1,
        recovered_interrupted_quarantine,
    })
}

fn open_ready_database(
    path: &Path,
    nonce: &str,
    held_marker: &HeldPath,
) -> Result<(Connection, PathBuf), DatabaseError> {
    validate_owner_nonce(nonce)?;
    let store = private_store_path(path, nonce)?;
    if fs::symlink_metadata(&store).is_err() && fs::symlink_metadata(path).is_ok() {
        validate_current_database_immutable(path, nonce)?;
        ensure_private_store(path, nonce)?;
    } else {
        verify_store_proof(&store, nonce)?;
    }
    let database_path = store_database_path(path, &store)?;
    if fs::symlink_metadata(&database_path).is_err() {
        relocate_ready_family(path, nonce, &store)?;
    }
    let held_database = validate_current_database_immutable(&database_path, nonce)?;
    verify_held_path(
        &ownership_marker_path(path),
        held_marker,
        "ready ownership marker",
    )?;
    let connection = open_private_database_read_write(&database_path, nonce, &held_database)?;
    Ok((connection, database_path))
}

fn open_private_database_read_write(
    database_path: &Path,
    expected_nonce: &str,
    held_database: &HeldPath,
) -> Result<Connection, DatabaseError> {
    run_debug_preflight_replacement_seam(database_path, held_database)?;
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    verify_held_path(
        database_path,
        held_database,
        "private database during writable open",
    )?;
    connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
    let nonce = verify_internal_ownership(&connection)?;
    if nonce != expected_nonce {
        return Err(DatabaseError::Ownership(
            "private database nonce changed before writable open".to_owned(),
        ));
    }
    quick_check(&connection)?;
    validate_schema(&connection)?;
    configure_database(&connection)?;
    write_probe(&connection)?;
    Ok(connection)
}

#[cfg(debug_assertions)]
fn run_debug_preflight_replacement_seam(
    database_path: &Path,
    held_database: &HeldPath,
) -> Result<(), DatabaseError> {
    let directive = sidecar_path(database_path, ".rustgo-test-replace-after-preflight");
    let Some((content, held_directive)) = read_exact_regular_text_with_handle(&directive)? else {
        return Ok(());
    };
    let mut lines = content.lines();
    if lines.next() != Some("rustgo-observability-test-replacement-v1") {
        return Err(DatabaseError::Ownership(
            "replacement seam directive header is invalid".to_owned(),
        ));
    }
    let replacement_name = lines
        .next()
        .and_then(|line| line.strip_prefix("replacement="))
        .ok_or_else(|| DatabaseError::Ownership("replacement seam source is missing".to_owned()))?;
    let backup_name = lines
        .next()
        .and_then(|line| line.strip_prefix("backup="))
        .ok_or_else(|| DatabaseError::Ownership("replacement seam backup is missing".to_owned()))?;
    if lines.next().is_some()
        || !is_literal_file_name(replacement_name)
        || !is_literal_file_name(backup_name)
    {
        return Err(DatabaseError::Ownership(
            "replacement seam paths are not literal file names".to_owned(),
        ));
    }
    let replacement = database_path.with_file_name(replacement_name);
    let backup = database_path.with_file_name(backup_name);
    move_exact_with_held(
        &directive,
        &sidecar_path(&backup, ".seam-consumed"),
        &held_directive,
        "replacement seam directive",
    )?;

    for suffix in ["-journal", "-wal", "-shm"] {
        let source = sidecar_path(database_path, suffix);
        if fs::symlink_metadata(&source).is_ok() {
            move_exact_no_replace(
                &source,
                &sidecar_path(&backup, suffix),
                "owned seam sidecar",
            )?;
        }
    }
    move_exact_with_held(
        database_path,
        &backup,
        held_database,
        "owned database at the deterministic replacement seam",
    )?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let source = sidecar_path(&replacement, suffix);
        if fs::symlink_metadata(&source).is_ok() {
            move_exact_no_replace(
                &source,
                &sidecar_path(database_path, suffix),
                "replacement seam sidecar",
            )?;
        }
    }
    move_exact_no_replace(&replacement, database_path, "replacement seam database")
}

#[cfg(debug_assertions)]
fn is_literal_file_name(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && path
            .file_name()
            .is_some_and(|name| name == path.as_os_str())
}

#[cfg(not(debug_assertions))]
fn run_debug_preflight_replacement_seam(
    _database_path: &Path,
    _held_database: &HeldPath,
) -> Result<(), DatabaseError> {
    Ok(())
}

fn validate_current_database_immutable(
    path: &Path,
    expected_nonce: &str,
) -> Result<HeldPath, DatabaseError> {
    let held = hold_exact_file(path, "private database immutable preflight")?;
    let connection = open_immutable_database(path)?;
    let nonce = verify_internal_ownership(&connection)?;
    if nonce != expected_nonce {
        return Err(DatabaseError::Ownership(
            "private database nonce does not match the external marker".to_owned(),
        ));
    }
    quick_check(&connection)?;
    validate_schema(&connection)?;
    verify_held_path(path, &held, "private database immutable preflight")?;
    Ok(held)
}

fn validate_legacy_database_immutable(path: &Path) -> Result<HeldPath, DatabaseError> {
    let held = hold_exact_file(path, "legacy database immutable preflight")?;
    let connection = open_immutable_database(path)?;
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if version != 4 || application_id != 0 {
        return Err(DatabaseError::Ownership(
            "legacy marker does not name the exact released v4 database".to_owned(),
        ));
    }
    quick_check(&connection)?;
    validate_legacy_v4_schema(&connection)?;
    verify_held_path(path, &held, "legacy database immutable preflight")?;
    Ok(held)
}

fn open_immutable_database(path: &Path) -> Result<Connection, DatabaseError> {
    let uri = immutable_database_uri(path)?;
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::ZERO)?;
    Ok(connection)
}

fn immutable_database_uri(path: &Path) -> Result<String, DatabaseError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let text = absolute.to_str().ok_or(DatabaseError::UnsafePath(
        "immutable SQLite preflight requires a Unicode path",
    ))?;
    let normalized = text.replace('\\', "/");
    let mut uri = String::from("file:");
    if cfg!(windows) && !normalized.starts_with('/') {
        uri.push('/');
    }
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}")
                .expect("writing one percent-encoded path byte cannot fail");
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Ok(uri)
}

fn start_private_bootstrap(path: &Path) -> Result<(Connection, PathBuf), DatabaseError> {
    let nonce = generate_owner_nonce()?;
    let pending = PendingMarker {
        nonce,
        kind: PendingKind::Bootstrap,
    };
    ensure_private_store(path, &pending.nonce)?;
    write_pending_marker(path, &pending)?;
    resume_pending_database(path, &pending)
}

fn resume_pending_database(
    path: &Path,
    pending: &PendingMarker,
) -> Result<(Connection, PathBuf), DatabaseError> {
    validate_owner_nonce(&pending.nonce)?;
    verify_pending_marker(path, pending)?;
    let store = ensure_private_store(path, &pending.nonce)?;
    match &pending.kind {
        PendingKind::Bootstrap => finish_private_bootstrap(path, pending, &store),
        PendingKind::Migration { legacy_sha256 } => {
            finish_legacy_migration(path, pending, &store, legacy_sha256)
        }
    }
}

fn finish_private_bootstrap(
    path: &Path,
    pending: &PendingMarker,
    store: &Path,
) -> Result<(Connection, PathBuf), DatabaseError> {
    verify_pending_marker(path, pending)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(DatabaseError::Ownership(
            "configured database path appeared during private bootstrap".to_owned(),
        ));
    }
    let database_path = store_database_path(path, store)?;
    let connection = match fs::symlink_metadata(&database_path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 0 => {
            initialize_private_database(&database_path, &pending.nonce)?
        }
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Err(DatabaseError::UnsafePath(
                "private bootstrap database is not an exact regular file",
            ));
        }
        Ok(_) => {
            let held_database =
                validate_current_database_immutable(&database_path, &pending.nonce)?;
            open_private_database_read_write(&database_path, &pending.nonce, &held_database)?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            initialize_private_database(&database_path, &pending.nonce)?
        }
        Err(error) => return Err(error.into()),
    };
    write_ready_marker(path, &pending.nonce)?;
    retire_pending_marker(path, pending)?;
    Ok((connection, database_path))
}

fn initialize_private_database(
    database_path: &Path,
    nonce: &str,
) -> Result<Connection, DatabaseError> {
    let reserved = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(database_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(database_path)?;
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.len() != 0
            {
                return Err(DatabaseError::Ownership(
                    "private bootstrap file changed before initialization".to_owned(),
                ));
            }
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(database_path)?
        }
        Err(error) => return Err(error.into()),
    };
    let held = HeldPath {
        handle: SameFileHandle::from_file(reserved.try_clone()?)?,
        kind: ExactPathKind::File,
    };
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    verify_held_path(
        database_path,
        &held,
        "private bootstrap file during SQLite open",
    )?;
    connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
    let objects: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(DatabaseError::Ownership(
            "private bootstrap requires an empty reserved database".to_owned(),
        ));
    }
    connection.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    configure_database(&connection)?;
    initialize_schema(&connection, nonce)?;
    quick_check(&connection)?;
    validate_schema(&connection)?;
    checkpoint_bounded(&connection)?;
    sync_regular_file(database_path)?;
    write_probe(&connection)?;
    Ok(connection)
}

fn start_legacy_migration(path: &Path) -> Result<(Connection, PathBuf), DatabaseError> {
    for member in [
        sidecar_path(path, "-journal"),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        if fs::symlink_metadata(&member).is_ok() {
            return Err(DatabaseError::Ownership(
                "the exact v4 migration fixture must be cleanly closed without sidecars".to_owned(),
            ));
        }
    }
    let held_source = validate_legacy_database_immutable(path)?;
    let legacy_sha256 = sha256_regular_file_with_held(path, &held_source)?;
    let pending = PendingMarker {
        nonce: generate_owner_nonce()?,
        kind: PendingKind::Migration { legacy_sha256 },
    };
    ensure_private_store(path, &pending.nonce)?;
    write_pending_marker(path, &pending)?;
    resume_pending_database(path, &pending)
}

fn finish_legacy_migration(
    path: &Path,
    pending: &PendingMarker,
    store: &Path,
    legacy_sha256: &str,
) -> Result<(Connection, PathBuf), DatabaseError> {
    validate_sha256(legacy_sha256)?;
    verify_pending_marker(path, pending)?;
    let database_path = store_database_path(path, store)?;
    let already_current = match fs::symlink_metadata(&database_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            validate_current_database_immutable(&database_path, &pending.nonce).is_ok()
        }
        Ok(_) => {
            return Err(DatabaseError::UnsafePath(
                "migration destination is not an exact regular file",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !already_current {
        if fs::symlink_metadata(&database_path).is_err() {
            let held_source = validate_legacy_migration_source(path, legacy_sha256)?;
            verify_pending_marker(path, pending)?;
            move_exact_with_held(path, &database_path, &held_source, "legacy database")?;
        }
        let held_database = validate_legacy_database_immutable(&database_path)?;
        if sha256_regular_file_with_held(&database_path, &held_database)? != legacy_sha256 {
            return Err(DatabaseError::Ownership(
                "moved legacy database does not match the durable migration proof".to_owned(),
            ));
        }
        verify_pending_marker(path, pending)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        verify_held_path(
            &database_path,
            &held_database,
            "private migration database during writable open",
        )?;
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        migrate_legacy_v4(&connection, &pending.nonce)?;
        configure_database(&connection)?;
        checkpoint_bounded(&connection)?;
        sync_regular_file(&database_path)?;
        drop(connection);
    }
    validate_current_database_immutable(&database_path, &pending.nonce)?;
    retire_legacy_marker(path, store)?;
    write_ready_marker(path, &pending.nonce)?;
    retire_pending_marker(path, pending)?;
    let held_database = validate_current_database_immutable(&database_path, &pending.nonce)?;
    let connection =
        open_private_database_read_write(&database_path, &pending.nonce, &held_database)?;
    Ok((connection, database_path))
}

fn validate_legacy_migration_source(
    path: &Path,
    expected_sha256: &str,
) -> Result<HeldPath, DatabaseError> {
    if !has_legacy_ownership_marker(path)? {
        return Err(DatabaseError::Ownership(
            "legacy owner marker disappeared before migration relocation".to_owned(),
        ));
    }
    let held = validate_legacy_database_immutable(path)?;
    if sha256_regular_file_with_held(path, &held)? != expected_sha256 {
        return Err(DatabaseError::Ownership(
            "legacy database changed after the durable migration proof".to_owned(),
        ));
    }
    verify_held_path(path, &held, "legacy migration source")?;
    Ok(held)
}

fn configure_database(connection: &Connection) -> Result<(), DatabaseError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "wal_autocheckpoint", WAL_AUTOCHECKPOINT_PAGES)?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(DatabaseError::Integrity(format!(
            "journal mode is {journal_mode}, not WAL"
        )));
    }
    connection.pragma_update(None, "journal_size_limit", WAL_JOURNAL_SIZE_LIMIT_BYTES)?;
    Ok(())
}

fn quick_check(connection: &Connection) -> Result<(), DatabaseError> {
    let integrity: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if integrity.eq_ignore_ascii_case("ok") {
        Ok(())
    } else {
        Err(DatabaseError::Integrity(integrity))
    }
}

const SERVER_METRIC_TABLE_SQL: &str = "CREATE TABLE server_metric_points (
                resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                sample_count INTEGER NOT NULL CHECK (sample_count > 0),
                is_latest INTEGER NOT NULL CHECK (is_latest BETWEEN 0 AND 1),
                PRIMARY KEY (resolution, timestamp_ms, metric)
            ) WITHOUT ROWID";
const CLIENT_METRIC_TABLE_SQL: &str = "CREATE TABLE client_metric_points (
                client_name TEXT NOT NULL,
                resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                sample_count INTEGER NOT NULL CHECK (sample_count > 0),
                is_latest INTEGER NOT NULL CHECK (is_latest BETWEEN 0 AND 1),
                PRIMARY KEY (client_name, resolution, timestamp_ms, metric)
            ) WITHOUT ROWID";
const CLIENT_LIFECYCLE_TABLE_SQL: &str = "CREATE TABLE client_lifecycle (
                id INTEGER PRIMARY KEY,
                client_name TEXT NOT NULL,
                generation TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                version TEXT,
                is_latest INTEGER NOT NULL CHECK (is_latest BETWEEN 0 AND 1),
                UNIQUE (client_name, generation, event_kind, timestamp_ms)
            )";
const SESSION_SUMMARIES_TABLE_SQL: &str = "CREATE TABLE session_summaries (
                session_id TEXT NOT NULL,
                client_name TEXT NOT NULL,
                peer TEXT,
                tunnel TEXT,
                export_name TEXT,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                received_bytes TEXT NOT NULL,
                sent_bytes TEXT NOT NULL,
                opened_ms INTEGER NOT NULL CHECK (opened_ms >= 0),
                closed_ms INTEGER CHECK (closed_ms IS NULL OR closed_ms >= 0),
                terminal_reason TEXT,
                is_latest_closed INTEGER NOT NULL CHECK (is_latest_closed BETWEEN 0 AND 1),
                PRIMARY KEY (session_id, opened_ms)
            )";
const LEGACY_SERVER_METRIC_TABLE_SQL: &str = "CREATE TABLE server_metric_points (
                resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                sample_count INTEGER NOT NULL CHECK (sample_count > 0),
                PRIMARY KEY (resolution, timestamp_ms, metric)
            ) WITHOUT ROWID";
const LEGACY_CLIENT_METRIC_TABLE_SQL: &str = "CREATE TABLE client_metric_points (
                client_name TEXT NOT NULL,
                resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                sample_count INTEGER NOT NULL CHECK (sample_count > 0),
                PRIMARY KEY (client_name, resolution, timestamp_ms, metric)
            ) WITHOUT ROWID";
const LEGACY_CLIENT_LIFECYCLE_TABLE_SQL: &str = "CREATE TABLE client_lifecycle (
                id INTEGER PRIMARY KEY,
                client_name TEXT NOT NULL,
                generation TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                version TEXT,
                UNIQUE (client_name, generation, event_kind, timestamp_ms)
            )";
const LEGACY_SESSION_SUMMARIES_TABLE_SQL: &str = "CREATE TABLE session_summaries (
                session_id TEXT NOT NULL,
                client_name TEXT NOT NULL,
                peer TEXT,
                tunnel TEXT,
                export_name TEXT,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                received_bytes TEXT NOT NULL,
                sent_bytes TEXT NOT NULL,
                opened_ms INTEGER NOT NULL CHECK (opened_ms >= 0),
                closed_ms INTEGER CHECK (closed_ms IS NULL OR closed_ms >= 0),
                terminal_reason TEXT,
                PRIMARY KEY (session_id, opened_ms)
            )";
const HISTORY_HEALTH_TABLE_SQL: &str = "CREATE TABLE history_health (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 owner_nonce TEXT NOT NULL CHECK (
                     length(owner_nonce) = 64
                     AND owner_nonce NOT GLOB '*[^0-9a-f]*'
                 ),
                 last_maintenance_ms INTEGER NOT NULL CHECK (last_maintenance_ms >= 0),
                 probe_nonce INTEGER NOT NULL
             )";
const LEGACY_HISTORY_HEALTH_TABLE_SQL: &str = "CREATE TABLE history_health (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 last_maintenance_ms INTEGER NOT NULL CHECK (last_maintenance_ms >= 0),
                 probe_nonce INTEGER NOT NULL
             )";
const METRIC_TOMBSTONES_TABLE_SQL: &str = "CREATE TABLE metric_deletion_tombstones (
                 scope INTEGER NOT NULL CHECK (scope BETWEEN 0 AND 1),
                 client_name TEXT NOT NULL,
                 resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
                 timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                 deleted_ms INTEGER NOT NULL CHECK (deleted_ms >= 0),
                 CHECK ((scope = 0 AND client_name = '') OR scope = 1),
                 PRIMARY KEY (scope, client_name, resolution, timestamp_ms)
             ) WITHOUT ROWID";

fn initialize_schema(connection: &Connection, owner_nonce: &str) -> Result<(), DatabaseError> {
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(&format!(
        "{SERVER_METRIC_TABLE_SQL};
         {CLIENT_METRIC_TABLE_SQL};
         {CLIENT_LIFECYCLE_TABLE_SQL};
         {SESSION_SUMMARIES_TABLE_SQL};
         {HISTORY_HEALTH_TABLE_SQL};
         {METRIC_TOMBSTONES_TABLE_SQL};
         CREATE INDEX server_metric_query
             ON server_metric_points (resolution, metric, timestamp_ms);
         CREATE INDEX client_metric_query
             ON client_metric_points (resolution, metric, timestamp_ms, client_name);
         CREATE INDEX client_metric_retention
             ON client_metric_points (resolution, timestamp_ms, client_name, metric);
         CREATE INDEX server_metric_cap
             ON server_metric_points (resolution, is_latest, timestamp_ms, metric);
         CREATE INDEX client_metric_cap
             ON client_metric_points (resolution, is_latest, timestamp_ms, client_name, metric);
         CREATE INDEX metric_tombstones_retention
             ON metric_deletion_tombstones (deleted_ms, timestamp_ms, resolution, scope, client_name);
         CREATE INDEX client_lifecycle_time
             ON client_lifecycle (timestamp_ms, id);
         CREATE INDEX client_lifecycle_latest
             ON client_lifecycle (client_name, timestamp_ms DESC, id DESC);
         CREATE INDEX client_lifecycle_cap
             ON client_lifecycle (is_latest, timestamp_ms, id);
         CREATE INDEX session_summaries_time
             ON session_summaries (closed_ms, opened_ms, session_id);
         CREATE INDEX session_summaries_cap
             ON session_summaries (is_latest_closed, closed_ms, opened_ms, session_id);"
    ))?;
    transaction.execute(
        "INSERT INTO history_health
         (id, owner_nonce, last_maintenance_ms, probe_nonce)
         VALUES (1, ?1, 0, 0)",
        [owner_nonce],
    )?;
    transaction.pragma_update(None, "application_id", RUSTGO_APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", HISTORY_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_legacy_v4(connection: &Connection, nonce: &str) -> Result<(), DatabaseError> {
    validate_legacy_v4_schema(connection)?;
    validate_owner_nonce(nonce)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(&format!(
        "ALTER TABLE server_metric_points RENAME TO legacy_server_metric_points;
         ALTER TABLE client_metric_points RENAME TO legacy_client_metric_points;
         ALTER TABLE client_lifecycle RENAME TO legacy_client_lifecycle;
         ALTER TABLE session_summaries RENAME TO legacy_session_summaries;
         ALTER TABLE history_health RENAME TO legacy_history_health;
         {SERVER_METRIC_TABLE_SQL};
         {CLIENT_METRIC_TABLE_SQL};
         {CLIENT_LIFECYCLE_TABLE_SQL};
         {SESSION_SUMMARIES_TABLE_SQL};
         {HISTORY_HEALTH_TABLE_SQL};
         INSERT INTO server_metric_points
             (resolution, timestamp_ms, metric, value, sample_count, is_latest)
             SELECT resolution, timestamp_ms, metric, value, sample_count, 0
             FROM legacy_server_metric_points;
         INSERT INTO client_metric_points
             (client_name, resolution, timestamp_ms, metric, value, sample_count, is_latest)
             SELECT client_name, resolution, timestamp_ms, metric, value, sample_count, 0
             FROM legacy_client_metric_points;
         INSERT INTO client_lifecycle
             (id, client_name, generation, event_kind, timestamp_ms, version, is_latest)
             SELECT id, client_name, generation, event_kind, timestamp_ms, version, 0
             FROM legacy_client_lifecycle;
         INSERT INTO session_summaries
             (session_id, client_name, peer, tunnel, export_name, kind, path,
              received_bytes, sent_bytes, opened_ms, closed_ms, terminal_reason,
              is_latest_closed)
             SELECT session_id, client_name, peer, tunnel, export_name, kind, path,
                    received_bytes, sent_bytes, opened_ms, closed_ms, terminal_reason, 0
             FROM legacy_session_summaries;
         INSERT INTO history_health (id, owner_nonce, last_maintenance_ms, probe_nonce)
             SELECT id, '{nonce}', last_maintenance_ms, probe_nonce
             FROM legacy_history_health;
         DROP TABLE legacy_server_metric_points;
         DROP TABLE legacy_client_metric_points;
         DROP TABLE legacy_client_lifecycle;
         DROP TABLE legacy_session_summaries;
         DROP TABLE legacy_history_health;
         {METRIC_TOMBSTONES_TABLE_SQL};
         CREATE INDEX server_metric_query
             ON server_metric_points (resolution, metric, timestamp_ms);
         CREATE INDEX client_metric_query
             ON client_metric_points (resolution, metric, timestamp_ms, client_name);
         CREATE INDEX client_metric_retention
             ON client_metric_points (resolution, timestamp_ms, client_name, metric);
         CREATE INDEX server_metric_cap
             ON server_metric_points (resolution, is_latest, timestamp_ms, metric);
         CREATE INDEX client_metric_cap
             ON client_metric_points (resolution, is_latest, timestamp_ms, client_name, metric);
         CREATE INDEX metric_tombstones_retention
             ON metric_deletion_tombstones (deleted_ms, timestamp_ms, resolution, scope, client_name);
         CREATE INDEX client_lifecycle_time ON client_lifecycle (timestamp_ms, id);
         CREATE INDEX client_lifecycle_latest
             ON client_lifecycle (client_name, timestamp_ms DESC, id DESC);
         CREATE INDEX client_lifecycle_cap
             ON client_lifecycle (is_latest, timestamp_ms, id);
         CREATE INDEX session_summaries_time
             ON session_summaries (closed_ms, opened_ms, session_id);
         CREATE INDEX session_summaries_cap
             ON session_summaries (is_latest_closed, closed_ms, opened_ms, session_id);
         UPDATE server_metric_points SET is_latest = 1
          WHERE (resolution, timestamp_ms) IN (
              SELECT resolution, MAX(timestamp_ms)
              FROM server_metric_points GROUP BY resolution
          );
         UPDATE client_metric_points SET is_latest = 1
          WHERE (client_name, resolution, timestamp_ms) IN (
              SELECT client_name, resolution, MAX(timestamp_ms)
              FROM client_metric_points GROUP BY client_name, resolution
          );
         UPDATE client_lifecycle SET is_latest = 1
          WHERE id IN (
              SELECT candidate.id FROM client_lifecycle AS candidate
              WHERE NOT EXISTS (
                  SELECT 1 FROM client_lifecycle AS newer
                  WHERE newer.client_name = candidate.client_name
                    AND (newer.timestamp_ms > candidate.timestamp_ms OR
                         (newer.timestamp_ms = candidate.timestamp_ms AND newer.id > candidate.id))
              )
          );
         UPDATE session_summaries SET is_latest_closed = 1
          WHERE rowid = (
              SELECT rowid FROM session_summaries WHERE closed_ms IS NOT NULL
              ORDER BY closed_ms DESC, opened_ms DESC, session_id DESC LIMIT 1
          );"
    ))?;
    transaction.pragma_update(None, "application_id", RUSTGO_APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", HISTORY_SCHEMA_VERSION)?;
    transaction.commit()?;
    quick_check(connection)?;
    validate_schema(connection)?;
    Ok(())
}

fn validate_legacy_v4_schema(connection: &Connection) -> Result<(), DatabaseError> {
    validate_exact_schema_objects(
        connection,
        &[
            ("table", "server_metric_points", "server_metric_points"),
            ("table", "client_metric_points", "client_metric_points"),
            ("table", "client_lifecycle", "client_lifecycle"),
            ("table", "session_summaries", "session_summaries"),
            ("table", "history_health", "history_health"),
            ("index", "server_metric_query", "server_metric_points"),
            ("index", "client_metric_query", "client_metric_points"),
            ("index", "client_metric_retention", "client_metric_points"),
            ("index", "client_lifecycle_time", "client_lifecycle"),
            ("index", "client_lifecycle_latest", "client_lifecycle"),
            ("index", "session_summaries_time", "session_summaries"),
        ],
    )?;
    let auto_vacuum: i64 = connection.pragma_query_value(None, "auto_vacuum", |row| row.get(0))?;
    if auto_vacuum != 2 {
        return Err(DatabaseError::SchemaDamage(
            "legacy incremental auto-vacuum is not enabled".to_owned(),
        ));
    }
    validate_table(
        connection,
        "server_metric_points",
        LEGACY_SERVER_METRIC_TABLE_SQL,
        &[
            column("resolution", "INTEGER", true, 1),
            column("timestamp_ms", "INTEGER", true, 2),
            column("metric", "TEXT", true, 3),
            column("value", "REAL", true, 0),
            column("sample_count", "INTEGER", true, 0),
        ],
    )?;
    validate_table(
        connection,
        "client_metric_points",
        LEGACY_CLIENT_METRIC_TABLE_SQL,
        &[
            column("client_name", "TEXT", true, 1),
            column("resolution", "INTEGER", true, 2),
            column("timestamp_ms", "INTEGER", true, 3),
            column("metric", "TEXT", true, 4),
            column("value", "REAL", true, 0),
            column("sample_count", "INTEGER", true, 0),
        ],
    )?;
    validate_table(
        connection,
        "client_lifecycle",
        LEGACY_CLIENT_LIFECYCLE_TABLE_SQL,
        &[
            column("id", "INTEGER", false, 1),
            column("client_name", "TEXT", true, 0),
            column("generation", "TEXT", true, 0),
            column("event_kind", "TEXT", true, 0),
            column("timestamp_ms", "INTEGER", true, 0),
            column("version", "TEXT", false, 0),
        ],
    )?;
    validate_table(
        connection,
        "session_summaries",
        LEGACY_SESSION_SUMMARIES_TABLE_SQL,
        &[
            column("session_id", "TEXT", true, 1),
            column("client_name", "TEXT", true, 0),
            column("peer", "TEXT", false, 0),
            column("tunnel", "TEXT", false, 0),
            column("export_name", "TEXT", false, 0),
            column("kind", "TEXT", true, 0),
            column("path", "TEXT", true, 0),
            column("received_bytes", "TEXT", true, 0),
            column("sent_bytes", "TEXT", true, 0),
            column("opened_ms", "INTEGER", true, 2),
            column("closed_ms", "INTEGER", false, 0),
            column("terminal_reason", "TEXT", false, 0),
        ],
    )?;
    validate_table(
        connection,
        "history_health",
        LEGACY_HISTORY_HEALTH_TABLE_SQL,
        &[
            column("id", "INTEGER", false, 1),
            column("last_maintenance_ms", "INTEGER", true, 0),
            column("probe_nonce", "INTEGER", true, 0),
        ],
    )?;
    validate_named_index(
        connection,
        "server_metric_points",
        "server_metric_query",
        &[
            index_column("resolution", false),
            index_column("metric", false),
            index_column("timestamp_ms", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_metric_points",
        "client_metric_query",
        &[
            index_column("resolution", false),
            index_column("metric", false),
            index_column("timestamp_ms", false),
            index_column("client_name", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_metric_points",
        "client_metric_retention",
        &[
            index_column("resolution", false),
            index_column("timestamp_ms", false),
            index_column("client_name", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_lifecycle",
        "client_lifecycle_time",
        &[
            index_column("timestamp_ms", false),
            index_column("id", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_lifecycle",
        "client_lifecycle_latest",
        &[
            index_column("client_name", false),
            index_column("timestamp_ms", true),
            index_column("id", true),
        ],
    )?;
    validate_named_index(
        connection,
        "session_summaries",
        "session_summaries_time",
        &[
            index_column("closed_ms", false),
            index_column("opened_ms", false),
            index_column("session_id", false),
        ],
    )
}

fn verify_internal_ownership(connection: &Connection) -> Result<String, DatabaseError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id != RUSTGO_APPLICATION_ID {
        return Err(DatabaseError::Ownership(
            "SQLite application_id does not identify Rustgo history".to_owned(),
        ));
    }
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != HISTORY_SCHEMA_VERSION {
        return Err(DatabaseError::IncompatibleSchema(version));
    }
    let nonce: String = connection
        .query_row(
            "SELECT owner_nonce FROM history_health WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            DatabaseError::Ownership(format!("internal owner nonce is unavailable: {error}"))
        })?;
    validate_owner_nonce(&nonce)?;
    Ok(nonce)
}

fn validate_database_path(path: &Path) -> Result<(), DatabaseError> {
    if is_protected_history_path(path) {
        return Err(DatabaseError::UnsafePath(
            "configuration, key, and certificate-like paths are not valid history databases",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(DatabaseError::UnsafePath(
                "database path is a symbolic link",
            ));
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(DatabaseError::UnsafePath(
                "database path is not a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for member in [
        sidecar_path(path, "-journal"),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
        ownership_marker_path(path),
        ownership_pending_marker_path(path),
    ] {
        match fs::symlink_metadata(member) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(DatabaseError::UnsafePath(
                    "history database family contains a symbolic link",
                ));
            }
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(DatabaseError::UnsafePath(
                    "history database family contains a non-file member",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn is_protected_history_path(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "toml" | "key" | "pem" | "crt" | "cert" | "cer" | "der" | "p12" | "pfx"
    )
}

#[derive(Clone, Copy)]
struct ColumnSpec {
    name: &'static str,
    declared_type: &'static str,
    not_null: bool,
    primary_key_position: i64,
}

#[derive(Clone, Copy)]
struct IndexColumnSpec {
    name: &'static str,
    descending: bool,
}

fn validate_schema(connection: &Connection) -> Result<(), DatabaseError> {
    validate_exact_schema_objects(
        connection,
        &[
            ("table", "server_metric_points", "server_metric_points"),
            ("table", "client_metric_points", "client_metric_points"),
            ("table", "client_lifecycle", "client_lifecycle"),
            ("table", "session_summaries", "session_summaries"),
            ("table", "history_health", "history_health"),
            (
                "table",
                "metric_deletion_tombstones",
                "metric_deletion_tombstones",
            ),
            ("index", "server_metric_query", "server_metric_points"),
            ("index", "client_metric_query", "client_metric_points"),
            ("index", "client_metric_retention", "client_metric_points"),
            ("index", "server_metric_cap", "server_metric_points"),
            ("index", "client_metric_cap", "client_metric_points"),
            (
                "index",
                "metric_tombstones_retention",
                "metric_deletion_tombstones",
            ),
            ("index", "client_lifecycle_time", "client_lifecycle"),
            ("index", "client_lifecycle_latest", "client_lifecycle"),
            ("index", "client_lifecycle_cap", "client_lifecycle"),
            ("index", "session_summaries_time", "session_summaries"),
            ("index", "session_summaries_cap", "session_summaries"),
        ],
    )?;
    let auto_vacuum: i64 = connection.pragma_query_value(None, "auto_vacuum", |row| row.get(0))?;
    if auto_vacuum != 2 {
        return Err(DatabaseError::SchemaDamage(
            "incremental auto-vacuum is not enabled".to_owned(),
        ));
    }
    validate_table(
        connection,
        "server_metric_points",
        SERVER_METRIC_TABLE_SQL,
        &[
            column("resolution", "INTEGER", true, 1),
            column("timestamp_ms", "INTEGER", true, 2),
            column("metric", "TEXT", true, 3),
            column("value", "REAL", true, 0),
            column("sample_count", "INTEGER", true, 0),
            column("is_latest", "INTEGER", true, 0),
        ],
    )?;
    validate_table(
        connection,
        "client_metric_points",
        CLIENT_METRIC_TABLE_SQL,
        &[
            column("client_name", "TEXT", true, 1),
            column("resolution", "INTEGER", true, 2),
            column("timestamp_ms", "INTEGER", true, 3),
            column("metric", "TEXT", true, 4),
            column("value", "REAL", true, 0),
            column("sample_count", "INTEGER", true, 0),
            column("is_latest", "INTEGER", true, 0),
        ],
    )?;
    validate_table(
        connection,
        "client_lifecycle",
        CLIENT_LIFECYCLE_TABLE_SQL,
        &[
            column("id", "INTEGER", false, 1),
            column("client_name", "TEXT", true, 0),
            column("generation", "TEXT", true, 0),
            column("event_kind", "TEXT", true, 0),
            column("timestamp_ms", "INTEGER", true, 0),
            column("version", "TEXT", false, 0),
            column("is_latest", "INTEGER", true, 0),
        ],
    )?;
    validate_table(
        connection,
        "session_summaries",
        SESSION_SUMMARIES_TABLE_SQL,
        &[
            column("session_id", "TEXT", true, 1),
            column("client_name", "TEXT", true, 0),
            column("peer", "TEXT", false, 0),
            column("tunnel", "TEXT", false, 0),
            column("export_name", "TEXT", false, 0),
            column("kind", "TEXT", true, 0),
            column("path", "TEXT", true, 0),
            column("received_bytes", "TEXT", true, 0),
            column("sent_bytes", "TEXT", true, 0),
            column("opened_ms", "INTEGER", true, 2),
            column("closed_ms", "INTEGER", false, 0),
            column("terminal_reason", "TEXT", false, 0),
            column("is_latest_closed", "INTEGER", true, 0),
        ],
    )?;
    validate_table(
        connection,
        "history_health",
        HISTORY_HEALTH_TABLE_SQL,
        &[
            column("id", "INTEGER", false, 1),
            column("owner_nonce", "TEXT", true, 0),
            column("last_maintenance_ms", "INTEGER", true, 0),
            column("probe_nonce", "INTEGER", true, 0),
        ],
    )?;
    validate_table(
        connection,
        "metric_deletion_tombstones",
        METRIC_TOMBSTONES_TABLE_SQL,
        &[
            column("scope", "INTEGER", true, 1),
            column("client_name", "TEXT", true, 2),
            column("resolution", "INTEGER", true, 3),
            column("timestamp_ms", "INTEGER", true, 4),
            column("deleted_ms", "INTEGER", true, 0),
        ],
    )?;

    validate_named_index(
        connection,
        "server_metric_points",
        "server_metric_query",
        &[
            index_column("resolution", false),
            index_column("metric", false),
            index_column("timestamp_ms", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_metric_points",
        "client_metric_query",
        &[
            index_column("resolution", false),
            index_column("metric", false),
            index_column("timestamp_ms", false),
            index_column("client_name", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_metric_points",
        "client_metric_retention",
        &[
            index_column("resolution", false),
            index_column("timestamp_ms", false),
            index_column("client_name", false),
            index_column("metric", false),
        ],
    )?;
    validate_named_index(
        connection,
        "server_metric_points",
        "server_metric_cap",
        &[
            index_column("resolution", false),
            index_column("is_latest", false),
            index_column("timestamp_ms", false),
            index_column("metric", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_metric_points",
        "client_metric_cap",
        &[
            index_column("resolution", false),
            index_column("is_latest", false),
            index_column("timestamp_ms", false),
            index_column("client_name", false),
            index_column("metric", false),
        ],
    )?;
    validate_named_index(
        connection,
        "metric_deletion_tombstones",
        "metric_tombstones_retention",
        &[
            index_column("deleted_ms", false),
            index_column("timestamp_ms", false),
            index_column("resolution", false),
            index_column("scope", false),
            index_column("client_name", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_lifecycle",
        "client_lifecycle_time",
        &[
            index_column("timestamp_ms", false),
            index_column("id", false),
        ],
    )?;
    validate_named_index(
        connection,
        "client_lifecycle",
        "client_lifecycle_latest",
        &[
            index_column("client_name", false),
            index_column("timestamp_ms", true),
            index_column("id", true),
        ],
    )?;
    validate_named_index(
        connection,
        "client_lifecycle",
        "client_lifecycle_cap",
        &[
            index_column("is_latest", false),
            index_column("timestamp_ms", false),
            index_column("id", false),
        ],
    )?;
    validate_named_index(
        connection,
        "session_summaries",
        "session_summaries_time",
        &[
            index_column("closed_ms", false),
            index_column("opened_ms", false),
            index_column("session_id", false),
        ],
    )?;
    validate_named_index(
        connection,
        "session_summaries",
        "session_summaries_cap",
        &[
            index_column("is_latest_closed", false),
            index_column("closed_ms", false),
            index_column("opened_ms", false),
            index_column("session_id", false),
        ],
    )?;
    validate_constraint_index(
        connection,
        "server_metric_points",
        "pk",
        &["resolution", "timestamp_ms", "metric"],
    )?;
    validate_constraint_index(
        connection,
        "client_metric_points",
        "pk",
        &["client_name", "resolution", "timestamp_ms", "metric"],
    )?;
    validate_constraint_index(
        connection,
        "client_lifecycle",
        "u",
        &["client_name", "generation", "event_kind", "timestamp_ms"],
    )?;
    validate_constraint_index(
        connection,
        "session_summaries",
        "pk",
        &["session_id", "opened_ms"],
    )?;
    Ok(())
}

fn validate_exact_schema_objects(
    connection: &Connection,
    expected: &[(&str, &str, &str)],
) -> Result<(), DatabaseError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name FROM sqlite_master
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
    )?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = expected
        .iter()
        .map(|(kind, name, table)| ((*kind).to_owned(), (*name).to_owned(), (*table).to_owned()))
        .collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(DatabaseError::SchemaDamage(format!(
            "schema object whitelist mismatch: expected {expected:?}, found {actual:?}"
        )))
    }
}

const fn column(
    name: &'static str,
    declared_type: &'static str,
    not_null: bool,
    primary_key_position: i64,
) -> ColumnSpec {
    ColumnSpec {
        name,
        declared_type,
        not_null,
        primary_key_position,
    }
}

const fn index_column(name: &'static str, descending: bool) -> IndexColumnSpec {
    IndexColumnSpec { name, descending }
}

fn validate_table(
    connection: &Connection,
    table: &'static str,
    expected_sql: &str,
    expected_columns: &[ColumnSpec],
) -> Result<(), DatabaseError> {
    let actual_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .map_err(|_| DatabaseError::SchemaDamage(format!("required table {table} is missing")))?;
    if normalize_schema_sql(&actual_sql) != normalize_schema_sql(expected_sql) {
        return Err(DatabaseError::SchemaDamage(format!(
            "required table {table} has unexpected constraints or storage semantics"
        )));
    }
    let mut statement = connection.prepare(&format!("PRAGMA table_xinfo({table})"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != expected_columns.len() {
        return Err(DatabaseError::SchemaDamage(format!(
            "required table {table} has an unexpected column count"
        )));
    }
    for (position, (actual, expected)) in actual.iter().zip(expected_columns).enumerate() {
        if actual.0 != position as i64
            || actual.1 != expected.name
            || !actual.2.eq_ignore_ascii_case(expected.declared_type)
            || actual.3 != expected.not_null
            || actual.4.is_some()
            || actual.5 != expected.primary_key_position
            || actual.6 != 0
        {
            return Err(DatabaseError::SchemaDamage(format!(
                "required column {table}.{} has unexpected declared semantics",
                expected.name
            )));
        }
    }
    Ok(())
}

fn validate_named_index(
    connection: &Connection,
    table: &'static str,
    index: &'static str,
    expected_columns: &[IndexColumnSpec],
) -> Result<(), DatabaseError> {
    let mut statement = connection.prepare(&format!("PRAGMA index_list({table})"))?;
    let matching = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|candidate| candidate.0 == index)
        .ok_or_else(|| DatabaseError::SchemaDamage(format!("required index {index} is missing")))?;
    if matching.1 != 0 || matching.2 != "c" || matching.3 != 0 {
        return Err(DatabaseError::SchemaDamage(format!(
            "required index {index} has unexpected uniqueness, origin, or partial semantics"
        )));
    }
    validate_index_columns(connection, index, expected_columns)
}

fn validate_constraint_index(
    connection: &Connection,
    table: &'static str,
    origin: &'static str,
    expected_columns: &[&'static str],
) -> Result<(), DatabaseError> {
    let mut statement = connection.prepare(&format!("PRAGMA index_list({table})"))?;
    let indexes = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let matching = indexes
        .iter()
        .filter(|candidate| candidate.2 == origin)
        .collect::<Vec<_>>();
    if matching.len() != 1 || matching[0].1 != 1 || matching[0].3 != 0 {
        return Err(DatabaseError::SchemaDamage(format!(
            "required {origin} conflict target on {table} is missing or malformed"
        )));
    }
    let expected = expected_columns
        .iter()
        .map(|name| index_column(*name, false))
        .collect::<Vec<_>>();
    validate_index_columns(connection, &matching[0].0, &expected)
}

fn validate_index_columns(
    connection: &Connection,
    index: &str,
    expected_columns: &[IndexColumnSpec],
) -> Result<(), DatabaseError> {
    let mut statement = connection.prepare(&format!("PRAGMA index_xinfo({index})"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)? != 0,
            ))
        })?
        .filter_map(|row| match row {
            Ok(value) if value.4 => Some(Ok(value)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, rusqlite::Error>>()?;
    if actual.len() != expected_columns.len() {
        return Err(DatabaseError::SchemaDamage(format!(
            "required index {index} has an unexpected key count"
        )));
    }
    for (position, (actual, expected)) in actual.iter().zip(expected_columns).enumerate() {
        if actual.0 != position as i64
            || actual.1.as_deref() != Some(expected.name)
            || actual.2 != expected.descending
            || actual.3.as_deref() != Some("BINARY")
        {
            return Err(DatabaseError::SchemaDamage(format!(
                "required index {index} has unexpected key order, collation, or direction"
            )));
        }
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn write_probe(connection: &Connection) -> Result<(), DatabaseError> {
    let transaction = connection.unchecked_transaction()?;
    let changed = transaction.execute(
        "UPDATE history_health SET probe_nonce = probe_nonce + 1 WHERE id = 1",
        [],
    )?;
    if changed != 1 {
        return Err(DatabaseError::SchemaDamage(
            "write probe row is missing".to_owned(),
        ));
    }
    transaction.commit()?;
    Ok(())
}

fn ownership_marker_path(path: &Path) -> PathBuf {
    sidecar_path(path, OWNERSHIP_MARKER_SUFFIX)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnershipMarker {
    nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingMarker {
    nonce: String,
    kind: PendingKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingKind {
    Bootstrap,
    Migration { legacy_sha256: String },
}

fn generate_owner_nonce() -> Result<String, DatabaseError> {
    let mut bytes = [0_u8; OWNER_NONCE_BYTES];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| {
        DatabaseError::Ownership("operating-system randomness is unavailable".to_owned())
    })?;
    let mut nonce = String::with_capacity(OWNER_NONCE_BYTES * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut nonce, "{byte:02x}")
            .expect("writing a fixed hexadecimal byte to String cannot fail");
    }
    Ok(nonce)
}

fn validate_owner_nonce(nonce: &str) -> Result<(), DatabaseError> {
    if nonce.len() == OWNER_NONCE_BYTES * 2
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(DatabaseError::Ownership(
            "owner nonce is not 64 lowercase hexadecimal characters".to_owned(),
        ))
    }
}

fn marker_content(nonce: &str) -> String {
    format!(
        "{OWNERSHIP_MARKER_HEADER}\napplication_id={RUSTGO_APPLICATION_ID:08x}\nnonce={nonce}\n"
    )
}

fn pending_marker_content(marker: &PendingMarker) -> String {
    let mut content = format!(
        "{OWNERSHIP_PENDING_MARKER_HEADER}\napplication_id={RUSTGO_APPLICATION_ID:08x}\nnonce={}\n",
        marker.nonce
    );
    match &marker.kind {
        PendingKind::Bootstrap => content.push_str("state=bootstrap\n"),
        PendingKind::Migration { legacy_sha256 } => {
            content.push_str("state=migration\n");
            content.push_str(&format!("legacy_sha256={legacy_sha256}\n"));
        }
    }
    content
}

fn read_ownership_marker(path: &Path) -> Result<Option<OwnershipMarker>, DatabaseError> {
    read_marker_file(&ownership_marker_path(path))
}

fn ownership_pending_marker_path(path: &Path) -> PathBuf {
    sidecar_path(path, OWNERSHIP_PENDING_MARKER_SUFFIX)
}

fn read_pending_marker(path: &Path) -> Result<Option<PendingMarker>, DatabaseError> {
    Ok(read_pending_marker_with_handle(path)?.map(|(marker, _)| marker))
}

fn read_pending_marker_with_handle(
    path: &Path,
) -> Result<Option<(PendingMarker, HeldPath)>, DatabaseError> {
    read_pending_marker_file_with_handle(&ownership_pending_marker_path(path))
}

fn verify_pending_marker(path: &Path, expected: &PendingMarker) -> Result<HeldPath, DatabaseError> {
    let Some((actual, held)) = read_pending_marker_with_handle(path)? else {
        return Err(DatabaseError::Ownership(
            "durable pending marker is missing".to_owned(),
        ));
    };
    if actual != *expected {
        return Err(DatabaseError::Ownership(
            "durable pending marker changed during recovery".to_owned(),
        ));
    }
    Ok(held)
}

fn parse_pending_marker_content(content: &str) -> Result<PendingMarker, DatabaseError> {
    let mut lines = content.lines();
    let expected_application = format!("application_id={RUSTGO_APPLICATION_ID:08x}");
    if lines.next() != Some(OWNERSHIP_PENDING_MARKER_HEADER)
        || lines.next() != Some(expected_application.as_str())
    {
        return Err(DatabaseError::Ownership(
            "pending marker header or application_id is invalid".to_owned(),
        ));
    }
    let nonce = lines
        .next()
        .and_then(|line| line.strip_prefix("nonce="))
        .ok_or_else(|| DatabaseError::Ownership("pending marker nonce is missing".to_owned()))?
        .to_owned();
    validate_owner_nonce(&nonce)?;
    let state = lines
        .next()
        .and_then(|line| line.strip_prefix("state="))
        .ok_or_else(|| DatabaseError::Ownership("pending marker state is missing".to_owned()))?;
    let kind = match state {
        "bootstrap" if lines.next().is_none() => PendingKind::Bootstrap,
        "migration" => {
            let legacy_sha256 = lines
                .next()
                .and_then(|line| line.strip_prefix("legacy_sha256="))
                .ok_or_else(|| DatabaseError::Ownership("migration proof is missing".to_owned()))?
                .to_owned();
            validate_sha256(&legacy_sha256)?;
            if lines.next().is_some() {
                return Err(DatabaseError::Ownership(
                    "pending migration marker has trailing fields".to_owned(),
                ));
            }
            PendingKind::Migration { legacy_sha256 }
        }
        _ => {
            return Err(DatabaseError::Ownership(
                "pending marker state is invalid".to_owned(),
            ));
        }
    };
    Ok(PendingMarker { nonce, kind })
}

fn read_marker_file(marker: &Path) -> Result<Option<OwnershipMarker>, DatabaseError> {
    Ok(read_marker_file_with_handle(marker)?.map(|(marker, _)| marker))
}

fn read_marker_file_with_handle(
    marker: &Path,
) -> Result<Option<(OwnershipMarker, HeldPath)>, DatabaseError> {
    let Some((content, held)) = read_exact_regular_text_with_handle(marker)? else {
        return Ok(None);
    };
    let mut lines = content.lines();
    let expected_application = format!("application_id={RUSTGO_APPLICATION_ID:08x}");
    if lines.next() != Some(OWNERSHIP_MARKER_HEADER)
        || lines.next() != Some(expected_application.as_str())
    {
        return Err(DatabaseError::Ownership(
            "ownership marker header or application_id is invalid".to_owned(),
        ));
    }
    let nonce = lines
        .next()
        .and_then(|line| line.strip_prefix("nonce="))
        .ok_or_else(|| DatabaseError::Ownership("ownership marker nonce is missing".to_owned()))?
        .to_owned();
    if lines.next().is_some() {
        return Err(DatabaseError::Ownership(
            "ownership marker has unexpected trailing fields".to_owned(),
        ));
    }
    validate_owner_nonce(&nonce)?;
    Ok(Some((OwnershipMarker { nonce }, held)))
}

fn write_ready_marker(path: &Path, nonce: &str) -> Result<(), DatabaseError> {
    validate_owner_nonce(nonce)?;
    let marker = ownership_marker_path(path);
    if let Some(existing) = read_ownership_marker(path)? {
        return if existing.nonce == nonce {
            Ok(())
        } else {
            Err(DatabaseError::Ownership(
                "ready owner marker already belongs to another database".to_owned(),
            ))
        };
    }
    write_new_durable_file(&marker, marker_content(nonce).as_bytes())
}

fn write_pending_marker(path: &Path, marker: &PendingMarker) -> Result<(), DatabaseError> {
    validate_owner_nonce(&marker.nonce)?;
    if let PendingKind::Migration { legacy_sha256 } = &marker.kind {
        validate_sha256(legacy_sha256)?;
    }
    if let Some(existing) = read_pending_marker(path)? {
        return if existing == *marker {
            Ok(())
        } else {
            Err(DatabaseError::Ownership(
                "another pending history operation already exists".to_owned(),
            ))
        };
    }
    write_new_durable_file(
        &ownership_pending_marker_path(path),
        pending_marker_content(marker).as_bytes(),
    )
}

fn has_legacy_ownership_marker(path: &Path) -> Result<bool, DatabaseError> {
    Ok(read_legacy_marker_with_handle(path)?.is_some())
}

fn read_legacy_marker_with_handle(path: &Path) -> Result<Option<HeldPath>, DatabaseError> {
    let marker = ownership_marker_path(path);
    let Some((content, held)) = read_exact_regular_text_with_handle(&marker)? else {
        return Ok(None);
    };
    if content.as_bytes() == LEGACY_OWNERSHIP_MARKER_CONTENT {
        Ok(Some(held))
    } else {
        Ok(None)
    }
}

fn retire_legacy_marker(path: &Path, store: &Path) -> Result<(), DatabaseError> {
    let marker = ownership_marker_path(path);
    let retired = store.join("legacy-owner-marker");
    if fs::symlink_metadata(&marker).is_err() {
        return if fs::read(&retired).ok().as_deref() == Some(LEGACY_OWNERSHIP_MARKER_CONTENT) {
            Ok(())
        } else {
            Err(DatabaseError::Ownership(
                "legacy owner marker disappeared before finalization".to_owned(),
            ))
        };
    }
    let Some(held_marker) = read_legacy_marker_with_handle(path)? else {
        return Err(DatabaseError::Ownership(
            "legacy Rustgo ownership marker changed during migration".to_owned(),
        ));
    };
    move_exact_with_held(&marker, &retired, &held_marker, "legacy owner marker")?;
    Ok(())
}

fn retire_pending_marker(path: &Path, pending: &PendingMarker) -> Result<(), DatabaseError> {
    let source = ownership_pending_marker_path(path);
    let store = private_store_path(path, &pending.nonce)?;
    let target = store.join("completed-pending-marker");
    if fs::symlink_metadata(&source).is_err() {
        return if read_pending_marker_file(&target)?.as_ref() == Some(pending) {
            Ok(())
        } else {
            Err(DatabaseError::Ownership(
                "pending marker disappeared before durable retirement".to_owned(),
            ))
        };
    }
    let Some((current, held_pending)) = read_pending_marker_with_handle(path)? else {
        return Err(DatabaseError::Ownership(
            "pending marker disappeared before durable retirement".to_owned(),
        ));
    };
    if current != *pending {
        return Err(DatabaseError::Ownership(
            "pending marker changed before durable retirement".to_owned(),
        ));
    }
    move_exact_with_held(&source, &target, &held_pending, "pending owner marker")
}

fn read_pending_marker_file(path: &Path) -> Result<Option<PendingMarker>, DatabaseError> {
    Ok(read_pending_marker_file_with_handle(path)?.map(|(marker, _)| marker))
}

fn read_pending_marker_file_with_handle(
    path: &Path,
) -> Result<Option<(PendingMarker, HeldPath)>, DatabaseError> {
    let Some((content, held)) = read_exact_regular_text_with_handle(path)? else {
        return Ok(None);
    };
    Ok(Some((parse_pending_marker_content(&content)?, held)))
}

fn private_store_path(path: &Path, nonce: &str) -> Result<PathBuf, DatabaseError> {
    validate_owner_nonce(nonce)?;
    let file_name = path.file_name().ok_or(DatabaseError::UnsafePath(
        "history database path has no literal file name",
    ))?;
    let mut store_name = file_name.to_os_string();
    store_name.push(".rustgo-store-");
    store_name.push(nonce);
    Ok(path.with_file_name(store_name))
}

fn store_database_path(path: &Path, store: &Path) -> Result<PathBuf, DatabaseError> {
    Ok(store.join(path.file_name().ok_or(DatabaseError::UnsafePath(
        "history database path has no literal file name",
    ))?))
}

fn ensure_private_store(path: &Path, nonce: &str) -> Result<PathBuf, DatabaseError> {
    let store = private_store_path(path, nonce)?;
    match fs::symlink_metadata(&store) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(DatabaseError::UnsafePath(
                "private history store is not an exact directory",
            ));
        }
        Ok(_) => verify_store_proof(&store, nonce)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&store)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
            }
            write_new_durable_file(
                &store.join(STORE_PROOF_FILE_NAME),
                store_proof_content(nonce).as_bytes(),
            )?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(store)
}

fn store_proof_content(nonce: &str) -> String {
    format!("{STORE_PROOF_HEADER}\nnonce={nonce}\n")
}

fn verify_store_proof(store: &Path, nonce: &str) -> Result<(), DatabaseError> {
    let proof = store.join(STORE_PROOF_FILE_NAME);
    let content = read_exact_regular_text(&proof)?.ok_or_else(|| {
        DatabaseError::Ownership("private store ownership proof is missing".to_owned())
    })?;
    if content == store_proof_content(nonce) {
        Ok(())
    } else {
        Err(DatabaseError::Ownership(
            "private store ownership proof does not match the external marker".to_owned(),
        ))
    }
}

fn relocate_ready_family(path: &Path, nonce: &str, store: &Path) -> Result<(), DatabaseError> {
    for sidecar in [
        sidecar_path(path, "-journal"),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        if fs::symlink_metadata(&sidecar).is_ok() {
            return Err(DatabaseError::Ownership(
                "legacy direct-layout v5 relocation requires a cleanly closed database".to_owned(),
            ));
        }
    }
    let held_database = validate_current_database_immutable(path, nonce)?;
    let target = store_database_path(path, store)?;
    move_exact_with_held(
        path,
        &target,
        &held_database,
        "owned direct-layout database",
    )?;
    validate_current_database_immutable(&target, nonce)?;
    Ok(())
}

fn write_new_durable_file(path: &Path, bytes: &[u8]) -> Result<(), DatabaseError> {
    let mut temporary_name = path
        .file_name()
        .ok_or(DatabaseError::UnsafePath(
            "durable file has no literal file name",
        ))?
        .to_os_string();
    temporary_name.push(".write-");
    temporary_name.push(generate_owner_nonce()?);
    let temporary = path.with_file_name(temporary_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    atomicwrites::move_atomic(&temporary, path).map_err(DatabaseError::Io)
}

fn read_exact_regular_text(path: &Path) -> Result<Option<String>, DatabaseError> {
    Ok(read_exact_regular_text_with_handle(path)?.map(|(content, _)| content))
}

fn read_exact_regular_text_with_handle(
    path: &Path,
) -> Result<Option<(String, HeldPath)>, DatabaseError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(DatabaseError::Ownership(
                "ownership metadata is not an exact regular file".to_owned(),
            ))
        }
        Ok(_) => {
            let held = hold_exact_file(path, "ownership metadata")?;
            let content = fs::read_to_string(path)?;
            verify_held_path(path, &held, "ownership metadata")?;
            Ok(Some((content, held)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactPathKind {
    File,
    Directory,
}

struct HeldPath {
    handle: SameFileHandle,
    kind: ExactPathKind,
}

fn hold_exact_path(path: &Path, label: &str) -> Result<HeldPath, DatabaseError> {
    let metadata = fs::symlink_metadata(path)?;
    let kind = if metadata.file_type().is_symlink() {
        return Err(DatabaseError::Ownership(format!(
            "{label} is a symbolic link"
        )));
    } else if metadata.file_type().is_file() {
        ExactPathKind::File
    } else if metadata.file_type().is_dir() {
        ExactPathKind::Directory
    } else {
        return Err(DatabaseError::Ownership(format!(
            "{label} is neither an exact file nor an exact directory"
        )));
    };
    let held = HeldPath {
        handle: SameFileHandle::from_path(path)?,
        kind,
    };
    verify_held_path(path, &held, label)?;
    Ok(held)
}

fn hold_exact_file(path: &Path, label: &str) -> Result<HeldPath, DatabaseError> {
    let held = hold_exact_path(path, label)?;
    if held.kind != ExactPathKind::File {
        return Err(DatabaseError::Ownership(format!(
            "{label} is not an exact regular file"
        )));
    }
    Ok(held)
}

fn hold_exact_directory(path: &Path, label: &str) -> Result<HeldPath, DatabaseError> {
    let held = hold_exact_path(path, label)?;
    if held.kind != ExactPathKind::Directory {
        return Err(DatabaseError::Ownership(format!(
            "{label} is not an exact directory"
        )));
    }
    Ok(held)
}

fn verify_held_path(path: &Path, held: &HeldPath, label: &str) -> Result<(), DatabaseError> {
    let metadata = fs::symlink_metadata(path)?;
    let kind_matches = !metadata.file_type().is_symlink()
        && match held.kind {
            ExactPathKind::File => metadata.file_type().is_file(),
            ExactPathKind::Directory => metadata.file_type().is_dir(),
        };
    if !kind_matches || held.handle != SameFileHandle::from_path(path)? {
        return Err(DatabaseError::Ownership(format!(
            "{label} changed identity"
        )));
    }
    Ok(())
}

fn move_exact_no_replace(source: &Path, target: &Path, label: &str) -> Result<(), DatabaseError> {
    let held = hold_exact_path(source, label)?;
    move_exact_with_held(source, target, &held, label)
}

fn sha256_regular_file_with_held(path: &Path, held: &HeldPath) -> Result<String, DatabaseError> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    if held.handle != SameFileHandle::from_file(file.try_clone()?)? {
        return Err(DatabaseError::Ownership(
            "migration proof source changed before hashing".to_owned(),
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    verify_held_path(path, held, "migration proof source")?;
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_sha256(value: &str) -> Result<(), DatabaseError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(DatabaseError::Ownership(
            "migration proof is not a lowercase SHA-256 digest".to_owned(),
        ))
    }
}

fn persist_batches(
    connection: &mut Connection,
    batches: &[QueuedBatch],
    database_path: &Path,
    shared: &Shared,
) -> Result<(), DatabaseError> {
    let transaction_now_unix_millis = unix_millis_now();
    let transaction = connection.transaction()?;
    let raw_cutoff_unix_millis = raw_admission_cutoff(transaction_now_unix_millis);
    let mut server_minutes = BTreeSet::new();
    let mut server_five_minutes = BTreeSet::new();
    let mut client_minutes = BTreeSet::new();
    let mut client_five_minutes = BTreeSet::new();
    let mut server_latest_resolutions = BTreeSet::new();
    let mut client_latest_scopes = BTreeSet::new();
    let mut lifecycle_latest_clients = BTreeSet::new();
    let mut refresh_latest_closed_session = false;

    for queued in batches {
        let batch = &queued.batch;
        for sample in &batch.server_points {
            if sample.timestamp_unix_millis < raw_cutoff_unix_millis
                || sample_intersects_tombstone(&transaction, 0, "", sample.timestamp_unix_millis)?
            {
                shared.dropped_late_points.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            insert_server_sample(&transaction, sample)?;
            server_latest_resolutions.insert(0_i64);
            server_minutes.insert(bucket_start(
                sample.timestamp_unix_millis,
                MINUTE_BUCKET_MILLIS,
            ));
            server_five_minutes.insert(bucket_start(
                sample.timestamp_unix_millis,
                FIVE_MINUTE_BUCKET_MILLIS,
            ));
        }
        for sample in &batch.client_points {
            if sample.timestamp_unix_millis < raw_cutoff_unix_millis
                || sample_intersects_tombstone(
                    &transaction,
                    1,
                    sample.client.name(),
                    sample.timestamp_unix_millis,
                )?
            {
                shared.dropped_late_points.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            insert_client_sample(&transaction, sample)?;
            client_latest_scopes.insert((sample.client.name().to_owned(), 0_i64));
            client_minutes.insert((
                sample.client.name().to_owned(),
                bucket_start(sample.timestamp_unix_millis, MINUTE_BUCKET_MILLIS),
            ));
            client_five_minutes.insert((
                sample.client.name().to_owned(),
                bucket_start(sample.timestamp_unix_millis, FIVE_MINUTE_BUCKET_MILLIS),
            ));
        }
        for record in &batch.client_lifecycle {
            insert_client_lifecycle(&transaction, record)?;
            lifecycle_latest_clients.insert(record.client.name().to_owned());
        }
        for session in &batch.session_summaries {
            upsert_session_summary(&transaction, session)?;
            refresh_latest_closed_session = true;
        }
    }

    for bucket in server_minutes {
        aggregate_server_bucket(&transaction, 0, 1, bucket, MINUTE_BUCKET_MILLIS)?;
        server_latest_resolutions.insert(1);
    }
    for bucket in server_five_minutes {
        aggregate_server_bucket(&transaction, 0, 2, bucket, FIVE_MINUTE_BUCKET_MILLIS)?;
        server_latest_resolutions.insert(2);
    }
    for (client, bucket) in client_minutes {
        aggregate_client_bucket(&transaction, &client, 0, 1, bucket, MINUTE_BUCKET_MILLIS)?;
        client_latest_scopes.insert((client, 1));
    }
    for (client, bucket) in client_five_minutes {
        aggregate_client_bucket(
            &transaction,
            &client,
            0,
            2,
            bucket,
            FIVE_MINUTE_BUCKET_MILLIS,
        )?;
        client_latest_scopes.insert((client, 2));
    }
    for resolution in server_latest_resolutions {
        refresh_server_latest(&transaction, resolution)?;
    }
    for (client, resolution) in client_latest_scopes {
        refresh_client_latest(&transaction, &client, resolution)?;
    }
    for client in lifecycle_latest_clients {
        refresh_lifecycle_latest(&transaction, &client)?;
    }
    if refresh_latest_closed_session {
        refresh_session_latest_closed(&transaction)?;
    }
    transaction.commit()?;
    let total = database_family_size(database_path)?;
    shared.total_database_bytes.store(total, Ordering::Relaxed);
    if total > shared.maximum_database_bytes {
        shared.size_floor_reached.store(false, Ordering::Relaxed);
    }
    Ok(())
}

fn sample_intersects_tombstone(
    transaction: &Transaction<'_>,
    scope: i64,
    client_name: &str,
    timestamp: u64,
) -> Result<bool, DatabaseError> {
    let raw = sqlite_integer(timestamp, "raw tombstone timestamp")?;
    let minute = sqlite_integer(
        bucket_start(timestamp, MINUTE_BUCKET_MILLIS),
        "minute tombstone timestamp",
    )?;
    let five_minutes = sqlite_integer(
        bucket_start(timestamp, FIVE_MINUTE_BUCKET_MILLIS),
        "five-minute tombstone timestamp",
    )?;
    let mut statement = transaction.prepare_cached(
        "SELECT EXISTS (
             SELECT 1 FROM metric_deletion_tombstones
             WHERE scope = ?1 AND client_name = ?2
               AND ((resolution = 0 AND timestamp_ms = ?3)
                 OR (resolution = 1 AND timestamp_ms = ?4)
                 OR (resolution = 2 AND timestamp_ms = ?5))
         )",
    )?;
    let blocked: i64 = statement.query_row(
        params![scope, client_name, raw, minute, five_minutes],
        |row| row.get(0),
    )?;
    Ok(blocked != 0)
}

fn insert_server_sample(
    transaction: &Transaction<'_>,
    sample: &ServerHistorySample,
) -> Result<(), DatabaseError> {
    let timestamp = sqlite_integer(sample.timestamp_unix_millis, "server timestamp")?;
    let mut statement = transaction.prepare_cached(
        "INSERT INTO server_metric_points
         (resolution, timestamp_ms, metric, value, sample_count, is_latest)
         VALUES (0, ?1, ?2, ?3, 1, 0)
         ON CONFLICT (resolution, timestamp_ms, metric) DO UPDATE SET
             value = excluded.value,
             sample_count = 1",
    )?;
    for (metric, value) in metric_values(&sample.metrics, sample.traffic) {
        statement.execute(params![timestamp, metric.as_database_value(), value])?;
    }
    Ok(())
}

fn insert_client_sample(
    transaction: &Transaction<'_>,
    sample: &ClientHistorySample,
) -> Result<(), DatabaseError> {
    let timestamp = sqlite_integer(sample.timestamp_unix_millis, "client timestamp")?;
    let mut statement = transaction.prepare_cached(
        "INSERT INTO client_metric_points
         (client_name, resolution, timestamp_ms, metric, value, sample_count, is_latest)
         VALUES (?1, 0, ?2, ?3, ?4, 1, 0)
         ON CONFLICT (client_name, resolution, timestamp_ms, metric) DO UPDATE SET
             value = excluded.value,
             sample_count = 1",
    )?;
    for (metric, value) in metric_values(&sample.metrics, sample.traffic) {
        statement.execute(params![
            sample.client.name(),
            timestamp,
            metric.as_database_value(),
            value
        ])?;
    }
    Ok(())
}

fn insert_client_lifecycle(
    transaction: &Transaction<'_>,
    record: &ClientLifecycleRecord,
) -> Result<(), DatabaseError> {
    let timestamp = sqlite_integer(record.timestamp_unix_millis, "client lifecycle timestamp")?;
    transaction.execute(
        "INSERT OR IGNORE INTO client_lifecycle
         (client_name, generation, event_kind, timestamp_ms, version, is_latest)
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![
            record.client.name(),
            record.client.generation().to_string(),
            record.kind.as_database_value(),
            timestamp,
            record.version.as_ref().map(BoundedLabel::as_str),
        ],
    )?;
    Ok(())
}

fn upsert_session_summary(
    transaction: &Transaction<'_>,
    session: &SessionSnapshot,
) -> Result<(), DatabaseError> {
    let opened = sqlite_integer(session.opened_unix_millis, "session open timestamp")?;
    let closed = session
        .closed_unix_millis
        .map(|value| sqlite_integer(value, "session close timestamp"))
        .transpose()?;
    transaction.execute(
        "INSERT INTO session_summaries
         (session_id, client_name, peer, tunnel, export_name, kind, path,
          received_bytes, sent_bytes, opened_ms, closed_ms, terminal_reason,
          is_latest_closed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0)
         ON CONFLICT (session_id, opened_ms) DO UPDATE SET
             client_name = excluded.client_name,
             peer = excluded.peer,
             tunnel = excluded.tunnel,
             export_name = excluded.export_name,
             kind = excluded.kind,
             path = excluded.path,
             received_bytes = excluded.received_bytes,
             sent_bytes = excluded.sent_bytes,
             closed_ms = excluded.closed_ms,
             terminal_reason = excluded.terminal_reason,
             is_latest_closed = 0",
        params![
            session.id.as_str(),
            session.client.as_str(),
            session.peer.as_ref().map(BoundedLabel::as_str),
            session.tunnel.as_ref().map(BoundedLabel::as_str),
            session.export.as_ref().map(BoundedLabel::as_str),
            session_kind_value(session.kind),
            session_path_value(session.path),
            session.traffic.received_bytes.to_string(),
            session.traffic.sent_bytes.to_string(),
            opened,
            closed,
            session.terminal_reason.as_ref().map(BoundedLabel::as_str),
        ],
    )?;
    Ok(())
}

fn aggregate_server_bucket(
    transaction: &Transaction<'_>,
    source_resolution: i64,
    target_resolution: i64,
    bucket: u64,
    width: u64,
) -> Result<(), DatabaseError> {
    let start = sqlite_integer(bucket, "server bucket timestamp")?;
    let end = sqlite_integer(bucket.saturating_add(width), "server bucket end")?;
    transaction.execute(
        "INSERT INTO server_metric_points
         (resolution, timestamp_ms, metric, value, sample_count, is_latest)
         SELECT ?1, ?2, metric,
                SUM(value * sample_count) / SUM(sample_count),
                SUM(sample_count), 0
         FROM server_metric_points
         WHERE resolution = ?3 AND timestamp_ms >= ?2 AND timestamp_ms < ?4
         GROUP BY metric
         ON CONFLICT (resolution, timestamp_ms, metric) DO UPDATE SET
             value = excluded.value,
             sample_count = excluded.sample_count",
        params![target_resolution, start, source_resolution, end],
    )?;
    Ok(())
}

fn aggregate_client_bucket(
    transaction: &Transaction<'_>,
    client: &str,
    source_resolution: i64,
    target_resolution: i64,
    bucket: u64,
    width: u64,
) -> Result<(), DatabaseError> {
    let start = sqlite_integer(bucket, "client bucket timestamp")?;
    let end = sqlite_integer(bucket.saturating_add(width), "client bucket end")?;
    transaction.execute(
        "INSERT INTO client_metric_points
         (client_name, resolution, timestamp_ms, metric, value, sample_count, is_latest)
         SELECT ?1, ?2, ?3, metric,
                SUM(value * sample_count) / SUM(sample_count),
                SUM(sample_count), 0
         FROM client_metric_points
         WHERE client_name = ?1 AND resolution = ?4
           AND timestamp_ms >= ?3 AND timestamp_ms < ?5
         GROUP BY metric
         ON CONFLICT (client_name, resolution, timestamp_ms, metric) DO UPDATE SET
             value = excluded.value,
             sample_count = excluded.sample_count",
        params![client, target_resolution, start, source_resolution, end],
    )?;
    Ok(())
}

fn refresh_server_latest(
    transaction: &Transaction<'_>,
    resolution: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "WITH newest(timestamp_ms) AS (
             SELECT MAX(timestamp_ms) FROM server_metric_points WHERE resolution = ?1
         )
         UPDATE server_metric_points
         SET is_latest = (timestamp_ms = (SELECT timestamp_ms FROM newest))
         WHERE resolution = ?1
           AND (is_latest = 1 OR timestamp_ms = (SELECT timestamp_ms FROM newest))",
        [resolution],
    )?;
    Ok(())
}

fn refresh_client_latest(
    transaction: &Transaction<'_>,
    client: &str,
    resolution: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "WITH newest(timestamp_ms) AS (
             SELECT MAX(timestamp_ms) FROM client_metric_points
             WHERE client_name = ?1 AND resolution = ?2
         )
         UPDATE client_metric_points
         SET is_latest = (timestamp_ms = (SELECT timestamp_ms FROM newest))
         WHERE client_name = ?1 AND resolution = ?2
           AND (is_latest = 1 OR timestamp_ms = (SELECT timestamp_ms FROM newest))",
        params![client, resolution],
    )?;
    Ok(())
}

fn refresh_lifecycle_latest(
    transaction: &Transaction<'_>,
    client: &str,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "WITH newest(id) AS (
             SELECT id FROM client_lifecycle WHERE client_name = ?1
             ORDER BY timestamp_ms DESC, id DESC LIMIT 1
         )
         UPDATE client_lifecycle
         SET is_latest = (id = (SELECT id FROM newest))
         WHERE client_name = ?1
           AND (is_latest = 1 OR id = (SELECT id FROM newest))",
        [client],
    )?;
    Ok(())
}

fn refresh_session_latest_closed(transaction: &Transaction<'_>) -> Result<(), DatabaseError> {
    transaction.execute(
        "WITH newest(row_id) AS (
             SELECT rowid FROM session_summaries WHERE closed_ms IS NOT NULL
             ORDER BY closed_ms DESC, opened_ms DESC, session_id DESC LIMIT 1
         )
         UPDATE session_summaries
         SET is_latest_closed = (rowid = (SELECT row_id FROM newest))
         WHERE is_latest_closed = 1 OR rowid = (SELECT row_id FROM newest)",
        [],
    )?;
    Ok(())
}

fn metric_values(metrics: &HostMetrics, traffic: TrafficCounters) -> Vec<(HistoryMetric, f64)> {
    let mut values = Vec::with_capacity(13);
    push_metric_u16(
        &mut values,
        HistoryMetric::CpuBasisPoints,
        metrics.cpu_basis_points,
    );
    push_metric_u16(
        &mut values,
        HistoryMetric::ProcessCpuBasisPoints,
        metrics.process_cpu_basis_points,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::MemoryUsedBytes,
        metrics.memory_used_bytes,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::MemoryTotalBytes,
        metrics.memory_total_bytes,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::ProcessMemoryBytes,
        metrics.process_memory_bytes,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::DiskUsedBytes,
        metrics.disk_used_bytes,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::DiskTotalBytes,
        metrics.disk_total_bytes,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::DiskReadBytesPerSecond,
        metrics.disk_read_bytes_per_sec,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::DiskWriteBytesPerSecond,
        metrics.disk_write_bytes_per_sec,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::NetworkRxBytesPerSecond,
        metrics.network_rx_bytes_per_sec,
    );
    push_metric_u64(
        &mut values,
        HistoryMetric::NetworkTxBytesPerSecond,
        metrics.network_tx_bytes_per_sec,
    );
    values.push((
        HistoryMetric::TrafficReceivedBytes,
        traffic.received_bytes as f64,
    ));
    values.push((HistoryMetric::TrafficSentBytes, traffic.sent_bytes as f64));
    values
}

fn push_metric_u16(
    values: &mut Vec<(HistoryMetric, f64)>,
    metric: HistoryMetric,
    value: Option<u16>,
) {
    if let Some(value) = value {
        values.push((metric, f64::from(value)));
    }
}

fn push_metric_u64(
    values: &mut Vec<(HistoryMetric, f64)>,
    metric: HistoryMetric,
    value: Option<u64>,
) {
    if let Some(value) = value {
        values.push((metric, value as f64));
    }
}

fn session_kind_value(kind: SessionKind) -> &'static str {
    match kind {
        SessionKind::Tcp => "tcp",
        SessionKind::Udp => "udp",
        SessionKind::P2p => "p2p",
    }
}

fn session_path_value(path: SessionPath) -> &'static str {
    match path {
        SessionPath::Relay => "relay",
        SessionPath::P2pDirect => "p2p-direct",
        SessionPath::P2pFallback => "p2p-fallback",
    }
}

fn query_database(
    connection: &Connection,
    query: &HistoryQuery,
) -> Result<HistorySeries, DatabaseError> {
    let resolution = query
        .resolution
        .select_for_range(query.start_unix_millis, query.end_unix_millis);
    let resolution_value = resolution
        .database_value()
        .expect("automatic history resolution is selected above");
    let start = sqlite_integer(query.start_unix_millis, "query start")?;
    let end = sqlite_integer(query.end_unix_millis, "query end")?;
    let limit = i64::try_from(query.max_points)
        .map_err(|_| DatabaseError::ValueOutOfRange("point limit"))?;
    let mut points = Vec::with_capacity(query.max_points);

    match &query.scope {
        HistoryScope::Server => {
            let mut statement = connection.prepare_cached(
                "SELECT timestamp_ms, value
                 FROM server_metric_points
                 WHERE resolution = ?1 AND metric = ?2
                   AND timestamp_ms >= ?3 AND timestamp_ms <= ?4
                 ORDER BY timestamp_ms ASC
                 LIMIT ?5",
            )?;
            let rows = statement.query_map(
                params![
                    resolution_value,
                    query.metric.as_database_value(),
                    start,
                    end,
                    limit
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?)),
            )?;
            for row in rows {
                let (timestamp, value) = row?;
                points.push(HistoryPoint {
                    timestamp_unix_millis: u64::try_from(timestamp).map_err(|_| {
                        DatabaseError::Integrity("negative metric timestamp".to_owned())
                    })?,
                    value,
                });
            }
        }
        HistoryScope::Client(client) => {
            let mut statement = connection.prepare_cached(
                "SELECT timestamp_ms, value
                 FROM client_metric_points
                 WHERE client_name = ?1 AND resolution = ?2 AND metric = ?3
                   AND timestamp_ms >= ?4 AND timestamp_ms <= ?5
                 ORDER BY timestamp_ms ASC
                 LIMIT ?6",
            )?;
            let rows = statement.query_map(
                params![
                    client.as_str(),
                    resolution_value,
                    query.metric.as_database_value(),
                    start,
                    end,
                    limit
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?)),
            )?;
            for row in rows {
                let (timestamp, value) = row?;
                points.push(HistoryPoint {
                    timestamp_unix_millis: u64::try_from(timestamp).map_err(|_| {
                        DatabaseError::Integrity("negative metric timestamp".to_owned())
                    })?,
                    value,
                });
            }
        }
    }

    Ok(HistorySeries { resolution, points })
}

enum MaintenancePhase {
    Raw,
    OneMinute,
    FiveMinutes,
    Lifecycle,
    Sessions,
    Tombstones,
    RecordCompletion,
    Cap(CapState),
    Done,
}

struct MaintenanceJob {
    now_unix_millis: u64,
    raw_cutoff_unix_millis: u64,
    phase: MaintenancePhase,
    response: Option<oneshot::Sender<Result<(), HistoryQueryError>>>,
}

impl MaintenanceJob {
    fn new(
        now_unix_millis: u64,
        response: Option<oneshot::Sender<Result<(), HistoryQueryError>>>,
    ) -> Self {
        Self {
            now_unix_millis,
            raw_cutoff_unix_millis: raw_admission_cutoff(unix_millis_now()),
            phase: MaintenancePhase::Raw,
            response,
        }
    }

    fn cancelled(&self) -> bool {
        self.response
            .as_ref()
            .is_some_and(oneshot::Sender::is_closed)
    }

    fn enforcing_cap(&self) -> bool {
        matches!(self.phase, MaintenancePhase::Cap(_))
    }

    fn finish(mut self, result: Result<(), HistoryQueryError>) {
        if let Some(response) = self.response.take() {
            let _ = response.send(result);
        }
    }
}

fn maintenance_step(
    connection: &mut Connection,
    database_path: &Path,
    config: &HistoryConfig,
    job: &mut MaintenanceJob,
    shared: &Shared,
) -> Result<bool, DatabaseError> {
    match &mut job.phase {
        MaintenancePhase::Raw => {
            if delete_metric_bucket_chunk(
                connection,
                0,
                job.raw_cutoff_unix_millis,
                job.now_unix_millis,
            )? {
                job.phase = MaintenancePhase::OneMinute;
            }
        }
        MaintenancePhase::OneMinute => {
            if delete_metric_bucket_chunk(
                connection,
                1,
                job.now_unix_millis
                    .saturating_sub(ONE_MINUTE_RETENTION_MILLIS),
                job.now_unix_millis,
            )? {
                job.phase = MaintenancePhase::FiveMinutes;
            }
        }
        MaintenancePhase::FiveMinutes => {
            if delete_metric_bucket_chunk(
                connection,
                2,
                job.now_unix_millis
                    .saturating_sub(config.retention_millis()),
                job.now_unix_millis,
            )? {
                job.phase = MaintenancePhase::Lifecycle;
            }
        }
        MaintenancePhase::Lifecycle => {
            let cutoff = sqlite_integer(
                job.now_unix_millis
                    .saturating_sub(config.retention_millis()),
                "lifecycle retention cutoff",
            )?;
            let deleted = connection.execute(
                "DELETE FROM client_lifecycle
                 WHERE id IN (
                     SELECT id FROM client_lifecycle
                     WHERE timestamp_ms < ?1
                     ORDER BY timestamp_ms ASC, id ASC
                     LIMIT ?2
                 )",
                params![cutoff, RETENTION_DELETE_LIMIT as i64],
            )?;
            if deleted < RETENTION_DELETE_LIMIT {
                job.phase = MaintenancePhase::Sessions;
            }
        }
        MaintenancePhase::Sessions => {
            let cutoff = sqlite_integer(
                job.now_unix_millis
                    .saturating_sub(config.retention_millis()),
                "session retention cutoff",
            )?;
            let deleted = connection.execute(
                "DELETE FROM session_summaries
                 WHERE rowid IN (
                     SELECT rowid FROM session_summaries
                     WHERE closed_ms IS NOT NULL AND closed_ms < ?1
                     ORDER BY closed_ms ASC, opened_ms ASC, session_id ASC
                     LIMIT ?2
                 )",
                params![cutoff, RETENTION_DELETE_LIMIT as i64],
            )?;
            if deleted < RETENTION_DELETE_LIMIT {
                job.phase = MaintenancePhase::Tombstones;
            }
        }
        MaintenancePhase::Tombstones => {
            let deleted = connection.execute(
                "DELETE FROM metric_deletion_tombstones
                 WHERE (scope, client_name, resolution, timestamp_ms) IN (
                     SELECT scope, client_name, resolution, timestamp_ms
                     FROM metric_deletion_tombstones
                     WHERE deleted_ms < ?1 AND timestamp_ms < ?2
                     ORDER BY deleted_ms ASC, timestamp_ms ASC, resolution ASC,
                              scope ASC, client_name ASC
                     LIMIT ?3
                 )",
                params![
                    sqlite_integer(
                        job.now_unix_millis
                            .saturating_sub(config.retention_millis()),
                        "tombstone retention cutoff",
                    )?,
                    sqlite_integer(job.raw_cutoff_unix_millis, "tombstone replay cutoff")?,
                    RETENTION_DELETE_LIMIT as i64,
                ],
            )?;
            if deleted < RETENTION_DELETE_LIMIT {
                job.phase = MaintenancePhase::RecordCompletion;
            }
        }
        MaintenancePhase::RecordCompletion => {
            let now = sqlite_integer(job.now_unix_millis, "maintenance timestamp")?;
            connection.execute(
                "UPDATE history_health SET last_maintenance_ms = ?1 WHERE id = 1",
                [now],
            )?;
            job.phase = MaintenancePhase::Cap(CapState::default());
        }
        MaintenancePhase::Cap(state) => {
            if enforce_size_cap_step(connection, database_path, config, shared, state)? {
                job.phase = MaintenancePhase::Done;
            }
        }
        MaintenancePhase::Done => return Ok(true),
    }
    Ok(matches!(job.phase, MaintenancePhase::Done))
}

fn bounded_maintenance_turn<T>(
    connection: &mut Connection,
    shared: &Shared,
    operation: impl FnOnce(&mut Connection) -> Result<T, DatabaseError>,
) -> Result<Option<T>, DatabaseError> {
    let callbacks = Arc::new(AtomicU64::new(0));
    let callback_count = Arc::clone(&callbacks);
    let deadline = Instant::now() + MAX_MAINTENANCE_TURN;
    connection.progress_handler(
        MAINTENANCE_PROGRESS_GRANULARITY,
        Some(move || {
            let callbacks = callback_count.fetch_add(1, Ordering::Relaxed) + 1;
            callbacks.saturating_mul(MAINTENANCE_PROGRESS_GRANULARITY as u64)
                >= MAX_MAINTENANCE_VM_STEPS
                || Instant::now() >= deadline
        }),
    );
    let result = operation(connection);
    connection.progress_handler(0, None::<fn() -> bool>);
    shared.maximum_maintenance_vm_steps.fetch_max(
        callbacks
            .load(Ordering::Relaxed)
            .saturating_mul(MAINTENANCE_PROGRESS_GRANULARITY as u64)
            .min(MAX_MAINTENANCE_VM_STEPS),
        Ordering::Relaxed,
    );
    match result {
        Err(DatabaseError::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
            if code.code == rusqlite::ffi::ErrorCode::OperationInterrupted =>
        {
            Ok(None)
        }
        result => result.map(Some),
    }
}

fn raw_admission_cutoff(worker_clock_unix_millis: u64) -> u64 {
    let cutoff = worker_clock_unix_millis.saturating_sub(RAW_RETENTION_MILLIS);
    if cutoff == 0 {
        return 0;
    }
    cutoff.saturating_add(FIVE_MINUTE_BUCKET_MILLIS - 1) / FIVE_MINUTE_BUCKET_MILLIS
        * FIVE_MINUTE_BUCKET_MILLIS
}

fn delete_metric_bucket_chunk(
    connection: &mut Connection,
    resolution: i64,
    cutoff: u64,
    deleted_at: u64,
) -> Result<bool, DatabaseError> {
    let cutoff = sqlite_integer(cutoff, "retention cutoff")?;
    let server_buckets = {
        let mut statement = connection.prepare(
            "SELECT DISTINCT timestamp_ms FROM server_metric_points
             WHERE resolution = ?1 AND timestamp_ms < ?2
             ORDER BY timestamp_ms ASC LIMIT ?3",
        )?;
        statement
            .query_map(
                params![resolution, cutoff, MAINTENANCE_BUCKET_LIMIT as i64],
                |row| row.get::<_, i64>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let client_buckets = {
        let mut statement = connection.prepare(
            "SELECT client_name, timestamp_ms FROM client_metric_points
             WHERE resolution = ?1 AND timestamp_ms < ?2
             GROUP BY timestamp_ms, client_name
             ORDER BY timestamp_ms ASC, client_name ASC LIMIT ?3",
        )?;
        statement
            .query_map(
                params![resolution, cutoff, MAINTENANCE_BUCKET_LIMIT as i64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let transaction = connection.transaction()?;
    let deleted_at = sqlite_integer(deleted_at, "metric deletion timestamp")?;
    for timestamp in &server_buckets {
        tombstone_deleted_bucket(&transaction, 0, "", resolution, *timestamp, deleted_at)?;
        transaction.execute(
            "DELETE FROM server_metric_points WHERE resolution = ?1 AND timestamp_ms = ?2",
            params![resolution, timestamp],
        )?;
    }
    for (client, timestamp) in &client_buckets {
        tombstone_deleted_bucket(&transaction, 1, client, resolution, *timestamp, deleted_at)?;
        transaction.execute(
            "DELETE FROM client_metric_points
             WHERE client_name = ?1 AND resolution = ?2 AND timestamp_ms = ?3",
            params![client, resolution, timestamp],
        )?;
    }
    transaction.commit()?;
    Ok(server_buckets.len() < MAINTENANCE_BUCKET_LIMIT
        && client_buckets.len() < MAINTENANCE_BUCKET_LIMIT)
}

fn tombstone_deleted_bucket(
    transaction: &Transaction<'_>,
    scope: i64,
    client_name: &str,
    resolution: i64,
    timestamp: i64,
    deleted_at: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "INSERT INTO metric_deletion_tombstones
         (scope, client_name, resolution, timestamp_ms, deleted_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (scope, client_name, resolution, timestamp_ms) DO UPDATE SET
             deleted_ms = MAX(metric_deletion_tombstones.deleted_ms, excluded.deleted_ms)",
        params![scope, client_name, resolution, timestamp, deleted_at],
    )?;
    if resolution == 0 {
        let minute = timestamp / MINUTE_BUCKET_MILLIS as i64 * MINUTE_BUCKET_MILLIS as i64;
        let five_minutes =
            timestamp / FIVE_MINUTE_BUCKET_MILLIS as i64 * FIVE_MINUTE_BUCKET_MILLIS as i64;
        for (aggregate_resolution, aggregate_timestamp) in [(1_i64, minute), (2, five_minutes)] {
            transaction.execute(
                "INSERT INTO metric_deletion_tombstones
                 (scope, client_name, resolution, timestamp_ms, deleted_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (scope, client_name, resolution, timestamp_ms) DO UPDATE SET
                     deleted_ms = MAX(metric_deletion_tombstones.deleted_ms, excluded.deleted_ms)",
                params![
                    scope,
                    client_name,
                    aggregate_resolution,
                    aggregate_timestamp,
                    deleted_at
                ],
            )?;
        }
    }
    Ok(())
}

fn checkpoint_database(
    connection: &Connection,
    database_path: &Path,
    shared: &Shared,
) -> Result<(), DatabaseError> {
    checkpoint_bounded(connection)?;
    let total = database_family_size(database_path)?;
    shared.total_database_bytes.store(total, Ordering::Relaxed);
    Ok(())
}

#[derive(Default)]
struct CapState {
    active: bool,
    phase: CapPhase,
    prune: CapPruneState,
    vacuum_pending: bool,
}

#[derive(Default)]
enum CapPhase {
    #[default]
    Measure,
    Checkpoint,
    Vacuum,
    VacuumCheckpoint,
    CheckSize,
    Prune,
}

fn enforce_size_cap_step(
    connection: &mut Connection,
    database_path: &Path,
    config: &HistoryConfig,
    shared: &Shared,
    state: &mut CapState,
) -> Result<bool, DatabaseError> {
    let maximum = config.maximum_bytes();
    match state.phase {
        CapPhase::Measure => {
            let total = database_family_size(database_path)?;
            shared.total_database_bytes.store(total, Ordering::Relaxed);
            if !state.active && total <= maximum {
                return Ok(true);
            }
            if !state.active {
                state.active = true;
                shared.size_floor_reached.store(false, Ordering::Relaxed);
            }
            state.phase = CapPhase::Checkpoint;
        }
        CapPhase::Checkpoint => {
            checkpoint_bounded(connection)?;
            state.phase = CapPhase::Vacuum;
        }
        CapPhase::Vacuum => {
            state.vacuum_pending = incremental_vacuum(connection)?;
            state.phase = CapPhase::VacuumCheckpoint;
        }
        CapPhase::VacuumCheckpoint => {
            checkpoint_bounded(connection)?;
            state.phase = CapPhase::CheckSize;
        }
        CapPhase::CheckSize => {
            let total = database_family_size(database_path)?;
            shared.total_database_bytes.store(total, Ordering::Relaxed);
            if total <= maximum {
                return Ok(true);
            }
            state.phase = if state.vacuum_pending {
                CapPhase::Vacuum
            } else {
                CapPhase::Prune
            };
        }
        CapPhase::Prune => {
            match prune_cap_batch_step(connection, config, shared, &mut state.prune)? {
                CapPruneResult::Deleted => state.phase = CapPhase::Checkpoint,
                CapPruneResult::Scanning => {}
                CapPruneResult::Exhausted => {
                    let total = database_family_size(database_path)?;
                    shared.total_database_bytes.store(total, Ordering::Relaxed);
                    shared.size_floor_reached.store(true, Ordering::Relaxed);
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[derive(Debug, Eq, PartialEq)]
struct MetricPruneCandidate {
    timestamp: i64,
    client: Option<String>,
}

impl Ord for MetricPruneCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.client.is_some().cmp(&other.client.is_some()))
            .then_with(|| self.client.cmp(&other.client))
    }
}

impl PartialOrd for MetricPruneCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct CapPruneState {
    tier: usize,
}

enum CapPruneResult {
    Deleted,
    Scanning,
    Exhausted,
}

fn prune_cap_batch_step(
    connection: &mut Connection,
    config: &HistoryConfig,
    shared: &Shared,
    state: &mut CapPruneState,
) -> Result<CapPruneResult, DatabaseError> {
    if state.tier < 3 {
        let resolution = [2_i64, 1, 0][state.tier];
        match prune_metric_tier_step(connection, resolution, shared)? {
            CapPruneResult::Exhausted => {
                state.tier += 1;
                Ok(CapPruneResult::Scanning)
            }
            result => Ok(result),
        }
    } else if state.tier == 3 {
        if prune_lifecycle(connection)? {
            Ok(CapPruneResult::Deleted)
        } else {
            state.tier += 1;
            Ok(CapPruneResult::Scanning)
        }
    } else if state.tier == 4 {
        if prune_sessions(connection)? {
            Ok(CapPruneResult::Deleted)
        } else {
            state.tier += 1;
            Ok(CapPruneResult::Scanning)
        }
    } else if state.tier == 5 {
        let now = unix_millis_now();
        let deleted = connection.execute(
            "DELETE FROM metric_deletion_tombstones
             WHERE (scope, client_name, resolution, timestamp_ms) IN (
                 SELECT scope, client_name, resolution, timestamp_ms
                 FROM metric_deletion_tombstones
                 WHERE deleted_ms < ?1 AND timestamp_ms < ?2
                 ORDER BY deleted_ms ASC, timestamp_ms ASC, resolution ASC,
                          scope ASC, client_name ASC
                 LIMIT ?3
             )",
            params![
                sqlite_integer(
                    now.saturating_sub(config.retention_millis()),
                    "cap tombstone age"
                )?,
                sqlite_integer(raw_admission_cutoff(now), "cap tombstone replay cutoff")?,
                CAP_DELETE_LIMIT as i64,
            ],
        )?;
        if deleted > 0 {
            Ok(CapPruneResult::Deleted)
        } else {
            state.tier += 1;
            Ok(CapPruneResult::Scanning)
        }
    } else {
        Ok(CapPruneResult::Exhausted)
    }
}

fn prune_metric_tier_step(
    connection: &mut Connection,
    resolution: i64,
    shared: &Shared,
) -> Result<CapPruneResult, DatabaseError> {
    let server_rows = {
        let mut statement = connection.prepare(
            "SELECT timestamp_ms FROM server_metric_points
             WHERE resolution = ?1 AND is_latest = 0
             GROUP BY timestamp_ms ORDER BY timestamp_ms ASC LIMIT ?2",
        )?;
        statement
            .query_map(
                params![resolution, CAP_CANDIDATE_PAGE_LIMIT as i64],
                |row| row.get::<_, i64>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let client_rows = {
        let mut statement = connection.prepare(
            "SELECT timestamp_ms, client_name FROM client_metric_points
             WHERE resolution = ?1 AND is_latest = 0
             GROUP BY timestamp_ms, client_name
             ORDER BY timestamp_ms ASC, client_name ASC LIMIT ?2",
        )?;
        statement
            .query_map(
                params![resolution, CAP_CANDIDATE_PAGE_LIMIT as i64],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let scanned = server_rows.len().saturating_add(client_rows.len()) as u64;
    shared
        .maximum_maintenance_scan_rows
        .fetch_max(scanned, Ordering::Relaxed);

    let mut candidates = server_rows
        .into_iter()
        .map(|timestamp| MetricPruneCandidate {
            timestamp,
            client: None,
        })
        .chain(
            client_rows
                .into_iter()
                .map(|(timestamp, client)| MetricPruneCandidate {
                    timestamp,
                    client: Some(client),
                }),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(CapPruneResult::Exhausted);
    }
    let mut safe_count = candidates.len().min((CAP_DELETE_LIMIT / 13).max(1));
    if safe_count > 1 {
        let first_is_client = candidates[0].client.is_some();
        if let Some(scope_boundary) = candidates[1..safe_count]
            .iter()
            .position(|candidate| candidate.client.is_some() != first_is_client)
        {
            safe_count = scope_boundary + 1;
        }
    }
    candidates.truncate(safe_count);
    let deleted_at = sqlite_integer(unix_millis_now(), "cap deletion timestamp")?;
    let transaction = connection.transaction()?;
    for candidate in candidates {
        if let Some(client) = candidate.client {
            tombstone_deleted_bucket(
                &transaction,
                1,
                &client,
                resolution,
                candidate.timestamp,
                deleted_at,
            )?;
            transaction.execute(
                "DELETE FROM client_metric_points WHERE client_name = ?1 AND resolution = ?2 AND timestamp_ms = ?3",
                params![client, resolution, candidate.timestamp],
            )?;
        } else {
            tombstone_deleted_bucket(
                &transaction,
                0,
                "",
                resolution,
                candidate.timestamp,
                deleted_at,
            )?;
            transaction.execute(
                "DELETE FROM server_metric_points WHERE resolution = ?1 AND timestamp_ms = ?2",
                params![resolution, candidate.timestamp],
            )?;
        }
    }
    transaction.commit()?;
    Ok(CapPruneResult::Deleted)
}

fn prune_lifecycle(connection: &mut Connection) -> Result<bool, DatabaseError> {
    let deleted = connection.execute(
        "DELETE FROM client_lifecycle
         WHERE id IN (
             SELECT id FROM client_lifecycle
             WHERE is_latest = 0
             ORDER BY timestamp_ms ASC, id ASC
             LIMIT ?1
         )",
        [CAP_DELETE_LIMIT as i64],
    )?;
    Ok(deleted > 0)
}

fn prune_sessions(connection: &mut Connection) -> Result<bool, DatabaseError> {
    let deleted = connection.execute(
        "DELETE FROM session_summaries
         WHERE rowid IN (
             SELECT rowid FROM session_summaries
             WHERE closed_ms IS NOT NULL AND is_latest_closed = 0
             ORDER BY closed_ms ASC, opened_ms ASC, session_id ASC
             LIMIT ?1
         )",
        [CAP_DELETE_LIMIT as i64],
    )?;
    Ok(deleted > 0)
}

fn checkpoint_bounded(connection: &Connection) -> Result<(), DatabaseError> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 || checkpointed_frames < log_frames {
        tracing::warn!(
            busy,
            log_frames,
            checkpointed_frames,
            "SQLite history passive checkpoint remained busy; size enforcement will retry"
        );
    }
    Ok(())
}

fn incremental_vacuum(connection: &Connection) -> Result<bool, DatabaseError> {
    for _ in 0..VACUUM_PAGE_LIMIT {
        let free_pages: i64 =
            connection.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
        if free_pages == 0 {
            return Ok(false);
        }
        connection.execute_batch("PRAGMA incremental_vacuum(1)")?;
    }
    let free_pages: i64 =
        connection.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
    Ok(free_pages > 0)
}

fn database_family_size(path: &Path) -> Result<u64, DatabaseError> {
    let mut total = 0_u64;
    for candidate in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(DatabaseError::UnsafePath(
                    "history database family contains a symbolic link",
                ));
            }
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(DatabaseError::UnsafePath(
                    "history database family contains a non-file member",
                ));
            }
            Ok(metadata) => {
                total = total.saturating_add(metadata.len());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(total)
}

fn quarantine_database(path: &Path) -> Result<bool, DatabaseError> {
    if is_protected_history_path(path) || has_legacy_ownership_marker(path)? {
        return Ok(false);
    }
    let marker = ownership_marker_path(path);
    let Some((marker_value, held_marker)) = read_marker_file_with_handle(&marker)? else {
        return Ok(false);
    };
    let store = private_store_path(path, &marker_value.nonce)?;
    let held_store = hold_exact_directory(&store, "private history store")?;
    verify_store_proof(&store, &marker_value.nonce)?;
    verify_held_path(&store, &held_store, "private history store")?;
    let pending = read_pending_marker_with_handle(path)?;
    if pending
        .as_ref()
        .is_some_and(|(pending, _)| pending.nonce != marker_value.nonce)
    {
        return Ok(false);
    }
    let quarantine = allocate_quarantine_destination(path)?;
    move_exact_with_held(&store, &quarantine, &held_store, "private history store")?;
    if let Some((pending, held)) = pending.as_ref() {
        let source = ownership_pending_marker_path(path);
        let target = quarantine.join(source.file_name().ok_or(DatabaseError::UnsafePath(
            "pending marker has no literal file name",
        ))?);
        move_exact_with_held(&source, &target, held, "pending history marker")?;
        if read_pending_marker_file(&target)?.as_ref() != Some(pending) {
            return Err(DatabaseError::Ownership(
                "moved pending marker failed exact verification".to_owned(),
            ));
        }
    }
    let quarantined_marker = quarantine.join(marker.file_name().ok_or(
        DatabaseError::UnsafePath("history marker has no literal file name"),
    )?);
    move_exact_with_held(
        &marker,
        &quarantined_marker,
        &held_marker,
        "ready history marker",
    )?;
    let moved_marker = read_marker_file(&quarantined_marker)?.ok_or_else(|| {
        DatabaseError::Ownership("quarantined owner marker is missing".to_owned())
    })?;
    if moved_marker.nonce != marker_value.nonce {
        return Err(DatabaseError::Ownership(
            "quarantined owner marker nonce changed".to_owned(),
        ));
    }
    verify_store_proof(&quarantine, &marker_value.nonce)?;
    Ok(true)
}

fn resume_interrupted_quarantine(path: &Path) -> Result<bool, DatabaseError> {
    if is_protected_history_path(path) || has_legacy_ownership_marker(path)? {
        return Ok(false);
    }
    let marker = ownership_marker_path(path);
    let Some((original_marker, held_marker)) = read_marker_file_with_handle(&marker)? else {
        return Ok(false);
    };
    let store = private_store_path(path, &original_marker.nonce)?;
    if fs::symlink_metadata(&store).is_ok() {
        return Ok(false);
    }
    for counter in 0..1000_u16 {
        let quarantine = path.with_file_name(format!(
            "{}.quarantine-{counter}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        let metadata = match fs::symlink_metadata(&quarantine) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            continue;
        }
        let held_quarantine = hold_exact_directory(&quarantine, "interrupted quarantine")?;
        if verify_store_proof(&quarantine, &original_marker.nonce).is_err() {
            continue;
        }
        verify_held_path(&quarantine, &held_quarantine, "interrupted quarantine")?;
        if let Some((pending, held_pending)) = read_pending_marker_with_handle(path)? {
            if pending.nonce != original_marker.nonce {
                return Err(DatabaseError::Ownership(
                    "interrupted quarantine pending marker has another nonce".to_owned(),
                ));
            }
            let source = ownership_pending_marker_path(path);
            let target = quarantine.join(source.file_name().ok_or(DatabaseError::UnsafePath(
                "pending marker has no literal file name",
            ))?);
            move_exact_with_held(
                &source,
                &target,
                &held_pending,
                "resumed pending history marker",
            )?;
            verify_held_path(&quarantine, &held_quarantine, "interrupted quarantine")?;
        }
        let target = quarantine.join(marker.file_name().ok_or(DatabaseError::UnsafePath(
            "history marker has no literal file name",
        ))?);
        move_exact_with_held(
            &marker,
            &target,
            &held_marker,
            "resumed ready history marker",
        )?;
        verify_held_path(&quarantine, &held_quarantine, "interrupted quarantine")?;
        return Ok(true);
    }
    Ok(false)
}

fn allocate_quarantine_destination(path: &Path) -> Result<PathBuf, DatabaseError> {
    for counter in 0..1000_u16 {
        let candidate = path.with_file_name(format!(
            "{}.quarantine-{counter}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(DatabaseError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique SQLite quarantine name",
    )))
}

fn move_exact_with_held(
    source: &Path,
    target: &Path,
    held: &HeldPath,
    label: &str,
) -> Result<(), DatabaseError> {
    atomicwrites::move_atomic(source, target)?;
    if verify_held_path(target, held, label).is_ok() {
        return Ok(());
    }
    let restored = if fs::symlink_metadata(source).is_err() {
        atomicwrites::move_atomic(target, source).is_ok()
    } else {
        false
    };
    Err(DatabaseError::Ownership(format!(
        "{label} was replaced during atomic move; the moved replacement was {}",
        if restored {
            "restored without overwrite"
        } else {
            "retained safely in quarantine"
        }
    )))
}

fn sync_regular_file(path: &Path) -> Result<(), DatabaseError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn bucket_start(timestamp: u64, width: u64) -> u64 {
    (timestamp / width) * width
}

fn sqlite_integer(value: u64, field: &'static str) -> Result<i64, DatabaseError> {
    i64::try_from(value).map_err(|_| DatabaseError::ValueOutOfRange(field))
}

fn doubled_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(MAX_RETRY_BACKOFF)
}

fn unix_millis_now() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}
