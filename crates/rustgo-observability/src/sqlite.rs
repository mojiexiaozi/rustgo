use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write as _;
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
const RETENTION_DELETE_LIMIT: usize = 1024;
const CAP_DELETE_LIMIT: usize = 512;
const VACUUM_PAGE_LIMIT: usize = 64;
const MIB: u64 = 1024 * 1024;
const OWNERSHIP_MARKER_SUFFIX: &str = ".rustgo-owner";
const OWNERSHIP_MARKER_HEADER: &str = "rustgo-observability-history-v2";
const RUSTGO_APPLICATION_ID: i64 = 0x5253_474f;
const OWNER_NONCE_BYTES: usize = 32;
const MAINTENANCE_BUCKET_LIMIT: usize = 64;

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
                if let Some(database) = connection.as_ref() {
                    let _ = checkpoint_database(database, &self.config, &self.shared);
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
                        connection = Some(opened.connection);
                        cap.get_or_insert_default();
                        if retry_batches.is_empty() {
                            retry_backoff = INITIAL_RETRY_BACKOFF;
                        }
                        background_turn = true;
                    }
                    Err(error) => {
                        self.database_failed(&error, &mut warning_limiter);
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
                    &self.config.database_path,
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
                    match enforce_size_cap_step(database, &self.config, &self.shared, state) {
                        Ok(true) => cap = None,
                        Ok(false) => {}
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            connection = None;
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
                    match maintenance_step(database, &self.config, job, &self.shared) {
                        Ok(true) => {
                            let completed = maintenance
                                .take()
                                .expect("completed maintenance job remains owned");
                            completed.finish(Ok(()));
                            next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            if let Some(failed) = maintenance.take() {
                                failed.finish(Err(HistoryQueryError::Unavailable));
                            }
                            self.database_failed(&error, &mut warning_limiter);
                            connection = None;
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
                        &self.config.database_path,
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
                    match checkpoint_database(database, &self.config, &self.shared) {
                        Ok(()) => {
                            let _ = response.send(Ok(()));
                        }
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            let _ = response.send(Err(HistoryQueryError::Unavailable));
                            connection = None;
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
    let existed = fs::symlink_metadata(&config.database_path).is_ok();
    if !existed && fs::symlink_metadata(ownership_marker_path(&config.database_path)).is_ok() {
        return Err(DatabaseError::Ownership(
            "an owner marker exists without a matching history database".to_owned(),
        ));
    }
    let reserved_database = if existed {
        None
    } else {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&config.database_path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    DatabaseError::Ownership(
                        "database path appeared during safe bootstrap".to_owned(),
                    )
                } else {
                    error.into()
                }
            })?;
        Some(file)
    };
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(&config.database_path, flags)?;
    if let Some(reserved) = &reserved_database {
        let reserved_handle = SameFileHandle::from_file(reserved.try_clone()?)?;
        let path_handle = SameFileHandle::from_path(&config.database_path)?;
        if reserved_handle != path_handle {
            return Err(DatabaseError::Ownership(
                "database path changed during safe bootstrap".to_owned(),
            ));
        }
    }
    connection.busy_timeout(Duration::from_secs(2))?;
    if existed {
        let nonce = verify_internal_ownership(&connection)?;
        quick_check(&connection)?;
        validate_schema(&connection)?;
        match read_ownership_marker(&config.database_path)? {
            Some(marker) if marker.nonce == nonce => {}
            Some(_) => {
                return Err(DatabaseError::Ownership(
                    "external marker nonce does not match the database".to_owned(),
                ));
            }
            None => write_ownership_marker(&config.database_path, &nonce)?,
        }
    } else {
        let objects: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if objects != 0 {
            return Err(DatabaseError::Ownership(
                "safe bootstrap requires a newly created empty SQLite database".to_owned(),
            ));
        }
        connection.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        configure_database(&connection)?;
        let nonce = generate_owner_nonce()?;
        initialize_schema(&connection, &nonce)?;
        quick_check(&connection)?;
        validate_schema(&connection)?;
        checkpoint_truncate(&connection)?;
        sync_regular_file(&config.database_path)?;
        sync_parent_directory(&config.database_path)?;
        write_ownership_marker(&config.database_path, &nonce)?;
    }
    configure_database(&connection)?;
    write_probe(&connection)?;
    Ok(OpenedDatabase {
        connection,
        recovered_interrupted_quarantine,
    })
}

fn configure_database(connection: &Connection) -> Result<(), DatabaseError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "wal_autocheckpoint", 1000)?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(DatabaseError::Integrity(format!(
            "journal mode is {journal_mode}, not WAL"
        )));
    }
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
                PRIMARY KEY (resolution, timestamp_ms, metric)
            ) WITHOUT ROWID";
const CLIENT_METRIC_TABLE_SQL: &str = "CREATE TABLE client_metric_points (
                client_name TEXT NOT NULL,
                resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                sample_count INTEGER NOT NULL CHECK (sample_count > 0),
                PRIMARY KEY (client_name, resolution, timestamp_ms, metric)
            ) WITHOUT ROWID";
const CLIENT_LIFECYCLE_TABLE_SQL: &str = "CREATE TABLE client_lifecycle (
                id INTEGER PRIMARY KEY,
                client_name TEXT NOT NULL,
                generation TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                version TEXT,
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
                PRIMARY KEY (session_id, opened_ms)
            )";
const HISTORY_HEALTH_TABLE_SQL: &str = "CREATE TABLE history_health (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 owner_nonce TEXT NOT NULL CHECK (
                     length(owner_nonce) = 64
                     AND owner_nonce NOT GLOB '*[^0-9a-f]*'
                 ),
                 last_maintenance_ms INTEGER NOT NULL CHECK (last_maintenance_ms >= 0),
                 probe_nonce INTEGER NOT NULL,
                 raw_admission_floor_ms INTEGER NOT NULL CHECK (raw_admission_floor_ms >= 0)
             )";

fn initialize_schema(connection: &Connection, owner_nonce: &str) -> Result<(), DatabaseError> {
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(&format!(
        "{SERVER_METRIC_TABLE_SQL};
         {CLIENT_METRIC_TABLE_SQL};
         {CLIENT_LIFECYCLE_TABLE_SQL};
         {SESSION_SUMMARIES_TABLE_SQL};
         {HISTORY_HEALTH_TABLE_SQL};
         CREATE INDEX server_metric_query
             ON server_metric_points (resolution, metric, timestamp_ms);
         CREATE INDEX client_metric_query
             ON client_metric_points (resolution, metric, timestamp_ms, client_name);
         CREATE INDEX client_metric_retention
             ON client_metric_points (resolution, timestamp_ms, client_name);
         CREATE INDEX client_lifecycle_time
             ON client_lifecycle (timestamp_ms, id);
         CREATE INDEX client_lifecycle_latest
             ON client_lifecycle (client_name, timestamp_ms DESC, id DESC);
         CREATE INDEX session_summaries_time
             ON session_summaries (closed_ms, opened_ms, session_id);"
    ))?;
    transaction.execute(
        "INSERT INTO history_health
         (id, owner_nonce, last_maintenance_ms, probe_nonce, raw_admission_floor_ms)
         VALUES (1, ?1, 0, 0, 0)",
        [owner_nonce],
    )?;
    transaction.pragma_update(None, "application_id", RUSTGO_APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", HISTORY_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
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
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
        ownership_marker_path(path),
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
            column("raw_admission_floor_ms", "INTEGER", true, 0),
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

struct OwnershipMarker {
    nonce: String,
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

fn read_ownership_marker(path: &Path) -> Result<Option<OwnershipMarker>, DatabaseError> {
    read_marker_file(&ownership_marker_path(path))
}

fn read_marker_file(marker: &Path) -> Result<Option<OwnershipMarker>, DatabaseError> {
    match fs::symlink_metadata(marker) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(DatabaseError::Ownership(
                "ownership marker is a symbolic link".to_owned(),
            ));
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(DatabaseError::Ownership(
                "ownership marker is not a regular file".to_owned(),
            ));
        }
        Ok(_) => {
            let content = fs::read_to_string(marker)?;
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
                .ok_or_else(|| {
                    DatabaseError::Ownership("ownership marker nonce is missing".to_owned())
                })?
                .to_owned();
            if lines.next().is_some() {
                return Err(DatabaseError::Ownership(
                    "ownership marker has unexpected trailing fields".to_owned(),
                ));
            }
            validate_owner_nonce(&nonce)?;
            return Ok(Some(OwnershipMarker { nonce }));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
}

fn write_ownership_marker(path: &Path, nonce: &str) -> Result<(), DatabaseError> {
    validate_owner_nonce(nonce)?;
    let marker = ownership_marker_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)?;
    file.write_all(marker_content(nonce).as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    sync_parent_directory(&marker)?;
    Ok(())
}

fn verify_ownership_pair(path: &Path, marker: &Path) -> Result<bool, DatabaseError> {
    let Some(marker) = read_marker_file(marker)? else {
        return Ok(false);
    };
    let connection = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ) {
        Ok(connection) => connection,
        Err(_) => return Ok(false),
    };
    match verify_internal_ownership(&connection) {
        Ok(nonce) => Ok(nonce == marker.nonce),
        Err(_) => Ok(false),
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
    let persisted_floor: i64 = transaction.query_row(
        "SELECT raw_admission_floor_ms FROM history_health WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    let persisted_floor = u64::try_from(persisted_floor)
        .map_err(|_| DatabaseError::SchemaDamage("negative raw admission floor".to_owned()))?;
    let raw_cutoff_unix_millis =
        raw_admission_cutoff(transaction_now_unix_millis).max(persisted_floor);
    let mut server_minutes = BTreeSet::new();
    let mut server_five_minutes = BTreeSet::new();
    let mut client_minutes = BTreeSet::new();
    let mut client_five_minutes = BTreeSet::new();

    for queued in batches {
        let batch = &queued.batch;
        for sample in &batch.server_points {
            if sample.timestamp_unix_millis < raw_cutoff_unix_millis {
                shared.dropped_late_points.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            insert_server_sample(&transaction, sample)?;
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
            if sample.timestamp_unix_millis < raw_cutoff_unix_millis {
                shared.dropped_late_points.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            insert_client_sample(&transaction, sample)?;
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
        }
        for session in &batch.session_summaries {
            upsert_session_summary(&transaction, session)?;
        }
    }

    for bucket in server_minutes {
        aggregate_server_bucket(&transaction, 0, 1, bucket, MINUTE_BUCKET_MILLIS)?;
    }
    for bucket in server_five_minutes {
        aggregate_server_bucket(&transaction, 0, 2, bucket, FIVE_MINUTE_BUCKET_MILLIS)?;
    }
    for (client, bucket) in client_minutes {
        aggregate_client_bucket(&transaction, &client, 0, 1, bucket, MINUTE_BUCKET_MILLIS)?;
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
    }
    transaction.commit()?;
    let total = database_family_size(database_path)?;
    shared.total_database_bytes.store(total, Ordering::Relaxed);
    if total > shared.maximum_database_bytes {
        shared.size_floor_reached.store(false, Ordering::Relaxed);
    }
    Ok(())
}

fn insert_server_sample(
    transaction: &Transaction<'_>,
    sample: &ServerHistorySample,
) -> Result<(), DatabaseError> {
    let timestamp = sqlite_integer(sample.timestamp_unix_millis, "server timestamp")?;
    let mut statement = transaction.prepare_cached(
        "INSERT INTO server_metric_points
         (resolution, timestamp_ms, metric, value, sample_count)
         VALUES (0, ?1, ?2, ?3, 1)
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
         (client_name, resolution, timestamp_ms, metric, value, sample_count)
         VALUES (?1, 0, ?2, ?3, ?4, 1)
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
         (client_name, generation, event_kind, timestamp_ms, version)
         VALUES (?1, ?2, ?3, ?4, ?5)",
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
          received_bytes, sent_bytes, opened_ms, closed_ms, terminal_reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
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
             terminal_reason = excluded.terminal_reason",
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
         (resolution, timestamp_ms, metric, value, sample_count)
         SELECT ?1, ?2, metric,
                SUM(value * sample_count) / SUM(sample_count),
                SUM(sample_count)
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
         (client_name, resolution, timestamp_ms, metric, value, sample_count)
         SELECT ?1, ?2, ?3, metric,
                SUM(value * sample_count) / SUM(sample_count),
                SUM(sample_count)
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
    config: &HistoryConfig,
    job: &mut MaintenanceJob,
    shared: &Shared,
) -> Result<bool, DatabaseError> {
    match &mut job.phase {
        MaintenancePhase::Raw => {
            if delete_metric_bucket_chunk(connection, 0, job.raw_cutoff_unix_millis)? {
                job.phase = MaintenancePhase::OneMinute;
            }
        }
        MaintenancePhase::OneMinute => {
            if delete_metric_bucket_chunk(
                connection,
                1,
                job.now_unix_millis
                    .saturating_sub(ONE_MINUTE_RETENTION_MILLIS),
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
            if enforce_size_cap_step(connection, config, shared, state)? {
                job.phase = MaintenancePhase::Done;
            }
        }
        MaintenancePhase::Done => return Ok(true),
    }
    Ok(matches!(job.phase, MaintenancePhase::Done))
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
) -> Result<bool, DatabaseError> {
    let cutoff_unix_millis = cutoff;
    let cutoff = sqlite_integer(cutoff_unix_millis, "retention cutoff")?;
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
    if resolution == 0 {
        transaction.execute(
            "UPDATE history_health
             SET raw_admission_floor_ms = MAX(raw_admission_floor_ms, ?1)
             WHERE id = 1",
            [sqlite_integer(
                cutoff_unix_millis,
                "retention raw admission floor",
            )?],
        )?;
    }
    for timestamp in &server_buckets {
        transaction.execute(
            "DELETE FROM server_metric_points WHERE resolution = ?1 AND timestamp_ms = ?2",
            params![resolution, timestamp],
        )?;
    }
    for (client, timestamp) in &client_buckets {
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

fn checkpoint_database(
    connection: &Connection,
    config: &HistoryConfig,
    shared: &Shared,
) -> Result<(), DatabaseError> {
    checkpoint_truncate(connection)?;
    let total = database_family_size(&config.database_path)?;
    shared.total_database_bytes.store(total, Ordering::Relaxed);
    Ok(())
}

#[derive(Default)]
struct CapState {
    active: bool,
}

fn enforce_size_cap_step(
    connection: &mut Connection,
    config: &HistoryConfig,
    shared: &Shared,
    state: &mut CapState,
) -> Result<bool, DatabaseError> {
    let maximum = config.maximum_bytes();
    let target = maximum.saturating_mul(9) / 10;
    let mut total = database_family_size(&config.database_path)?;
    if !state.active && total <= maximum {
        shared.total_database_bytes.store(total, Ordering::Relaxed);
        return Ok(true);
    }
    if !state.active {
        state.active = true;
        shared.size_floor_reached.store(false, Ordering::Relaxed);
    }
    checkpoint_truncate(connection)?;
    let vacuumed = incremental_vacuum(connection)?;
    total = database_family_size(&config.database_path)?;
    if total <= target {
        shared.total_database_bytes.store(total, Ordering::Relaxed);
        return Ok(true);
    }
    let deleted = prune_cap_batch(connection)?;
    if !deleted {
        if vacuumed {
            shared.total_database_bytes.store(total, Ordering::Relaxed);
            return Ok(false);
        }
        shared.size_floor_reached.store(true, Ordering::Relaxed);
        shared.total_database_bytes.store(total, Ordering::Relaxed);
        return Ok(true);
    }
    checkpoint_truncate(connection)?;
    let _ = incremental_vacuum(connection)?;
    total = database_family_size(&config.database_path)?;
    shared.total_database_bytes.store(total, Ordering::Relaxed);
    Ok(total <= target)
}

fn prune_cap_batch(connection: &mut Connection) -> Result<bool, DatabaseError> {
    for resolution in [2_i64, 1, 0] {
        if prune_metric_tier(connection, resolution)? {
            return Ok(true);
        }
    }
    if prune_lifecycle(connection)? {
        return Ok(true);
    }
    prune_sessions(connection)
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

fn prune_metric_tier(connection: &mut Connection, resolution: i64) -> Result<bool, DatabaseError> {
    let bucket_limit = (CAP_DELETE_LIMIT / 13).max(1);
    let mut candidates = {
        let mut statement = connection.prepare(
            "SELECT candidate.timestamp_ms
             FROM server_metric_points AS candidate
             WHERE candidate.resolution = ?1
               AND EXISTS (
                   SELECT 1 FROM server_metric_points AS newer
                   WHERE newer.resolution = ?1
                     AND newer.timestamp_ms > candidate.timestamp_ms
               )
             GROUP BY candidate.timestamp_ms
             ORDER BY candidate.timestamp_ms ASC
             LIMIT ?2",
        )?;
        statement
            .query_map(params![resolution, bucket_limit as i64], |row| {
                Ok(MetricPruneCandidate {
                    timestamp: row.get(0)?,
                    client: None,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let client_candidates = {
        let mut statement = connection.prepare(
            "SELECT candidate.client_name, candidate.timestamp_ms
             FROM client_metric_points AS candidate
             WHERE candidate.resolution = ?1
               AND EXISTS (
                   SELECT 1 FROM client_metric_points AS newer
                   WHERE newer.client_name = candidate.client_name
                     AND newer.resolution = ?1
                     AND newer.timestamp_ms > candidate.timestamp_ms
               )
             GROUP BY candidate.timestamp_ms, candidate.client_name
             ORDER BY candidate.timestamp_ms ASC, candidate.client_name ASC
             LIMIT ?2",
        )?;
        statement
            .query_map(params![resolution, bucket_limit as i64], |row| {
                Ok(MetricPruneCandidate {
                    timestamp: row.get(1)?,
                    client: Some(row.get(0)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    candidates.extend(client_candidates);
    candidates.sort();
    candidates.truncate(bucket_limit);
    if candidates.is_empty() {
        return Ok(false);
    }
    let transaction = connection.transaction()?;
    if resolution == 0 {
        let raw_floor = candidates
            .iter()
            .filter_map(|candidate| u64::try_from(candidate.timestamp).ok())
            .map(|timestamp| {
                bucket_start(timestamp, FIVE_MINUTE_BUCKET_MILLIS)
                    .saturating_add(FIVE_MINUTE_BUCKET_MILLIS)
            })
            .max()
            .unwrap_or(0);
        transaction.execute(
            "UPDATE history_health
             SET raw_admission_floor_ms = MAX(raw_admission_floor_ms, ?1)
             WHERE id = 1",
            [sqlite_integer(raw_floor, "cap raw admission floor")?],
        )?;
    }
    for candidate in &candidates {
        if let Some(client) = &candidate.client {
            transaction.execute(
                "DELETE FROM client_metric_points
                 WHERE client_name = ?1 AND resolution = ?2 AND timestamp_ms = ?3",
                params![client, resolution, candidate.timestamp],
            )?;
        } else {
            transaction.execute(
                "DELETE FROM server_metric_points
                 WHERE resolution = ?1 AND timestamp_ms = ?2",
                params![resolution, candidate.timestamp],
            )?;
        }
    }
    transaction.commit()?;
    Ok(true)
}

fn prune_lifecycle(connection: &mut Connection) -> Result<bool, DatabaseError> {
    let deleted = connection.execute(
        "DELETE FROM client_lifecycle
         WHERE id IN (
             SELECT candidate.id
             FROM client_lifecycle AS candidate
             WHERE candidate.id <> (
                 SELECT current.id
                 FROM client_lifecycle AS current
                 WHERE current.client_name = candidate.client_name
                 ORDER BY current.timestamp_ms DESC, current.id DESC
                 LIMIT 1
             )
             ORDER BY candidate.timestamp_ms ASC, candidate.id ASC
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
             WHERE closed_ms IS NOT NULL
               AND rowid <> (
                   SELECT newest.rowid
                   FROM session_summaries AS newest
                   WHERE newest.closed_ms IS NOT NULL
                   ORDER BY newest.closed_ms DESC,
                            newest.opened_ms DESC,
                            newest.session_id DESC
                   LIMIT 1
               )
             ORDER BY closed_ms ASC, opened_ms ASC, session_id ASC
             LIMIT ?1
         )",
        [CAP_DELETE_LIMIT as i64],
    )?;
    Ok(deleted > 0)
}

fn checkpoint_truncate(connection: &Connection) -> Result<(), DatabaseError> {
    let busy: i64 =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    if busy != 0 {
        tracing::warn!(
            busy,
            "SQLite history checkpoint remained busy; size enforcement will retry"
        );
    }
    Ok(())
}

fn incremental_vacuum(connection: &Connection) -> Result<bool, DatabaseError> {
    let mut vacuumed = false;
    for _ in 0..VACUUM_PAGE_LIMIT {
        let free_pages: i64 =
            connection.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
        if free_pages == 0 {
            break;
        }
        connection.execute_batch("PRAGMA incremental_vacuum(1)")?;
        vacuumed = true;
    }
    Ok(vacuumed)
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
    let marker = ownership_marker_path(path);
    if is_protected_history_path(path) || !verify_ownership_pair(path, &marker)? {
        return Ok(false);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Ok(false);
    }

    let mut sources = Vec::new();
    for source in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
        marker.clone(),
    ] {
        match fs::symlink_metadata(&source) {
            Ok(metadata)
                if !metadata.file_type().is_symlink() && metadata.file_type().is_file() =>
            {
                sources.push(source);
            }
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    let mut quarantine = None;
    for counter in 0..1000_u16 {
        let candidate = path.with_file_name(format!(
            "{}.quarantine-{counter}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                quarantine = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let quarantine = quarantine.ok_or_else(|| {
        DatabaseError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique SQLite quarantine name",
        ))
    })?;
    let mut linked = Vec::new();
    for source in &sources {
        let target = quarantine.join(source.file_name().ok_or_else(|| {
            DatabaseError::UnsafePath("history family member has no literal file name")
        })?);
        if let Err(error) = fs::hard_link(source, &target) {
            for created in linked {
                let _ = fs::remove_file(created);
            }
            let _ = fs::remove_dir(&quarantine);
            return Err(error.into());
        }
        sync_regular_file(&target)?;
        linked.push(target);
    }
    sync_directory(&quarantine)?;
    sync_parent_directory(&quarantine)?;
    let quarantined_database =
        quarantine.join(path.file_name().ok_or_else(|| {
            DatabaseError::UnsafePath("history database has no literal file name")
        })?);
    let quarantined_marker = quarantine.join(
        marker
            .file_name()
            .ok_or_else(|| DatabaseError::UnsafePath("history marker has no literal file name"))?,
    );
    if !verify_ownership_pair(&quarantined_database, &quarantined_marker)?
        || !verify_ownership_pair(path, &marker)?
    {
        for created in linked {
            let _ = fs::remove_file(created);
        }
        let _ = fs::remove_dir(&quarantine);
        return Ok(false);
    }

    for source in &sources {
        let target = quarantine.join(source.file_name().ok_or_else(|| {
            DatabaseError::UnsafePath("history family member has no literal file name")
        })?);
        if !same_file_identity(source, &target)? {
            return Err(DatabaseError::Ownership(
                "history family changed during quarantine".to_owned(),
            ));
        }
    }
    for sidecar in [sidecar_path(path, "-wal"), sidecar_path(path, "-shm")] {
        if !sources.contains(&sidecar) && fs::symlink_metadata(&sidecar).is_ok() {
            return Err(DatabaseError::Ownership(
                "a new history sidecar appeared during quarantine".to_owned(),
            ));
        }
    }

    for source in sources
        .iter()
        .filter(|source| source.as_path() != marker.as_path())
    {
        let target = quarantine.join(source.file_name().ok_or_else(|| {
            DatabaseError::UnsafePath("history family member has no literal file name")
        })?);
        if !same_file_identity(source, &target)? {
            return Err(DatabaseError::Ownership(
                "history family changed before quarantine cleanup".to_owned(),
            ));
        }
        fs::remove_file(source)?;
    }
    if !same_file_identity(&marker, &quarantined_marker)? {
        return Err(DatabaseError::Ownership(
            "history owner marker changed before quarantine cleanup".to_owned(),
        ));
    }
    fs::remove_file(&marker)?;
    sync_parent_directory(path)?;
    Ok(true)
}

fn remove_resumed_sidecar(path: &Path, quarantine: &Path) -> Result<(), DatabaseError> {
    let target = quarantine
        .join(path.file_name().ok_or_else(|| {
            DatabaseError::UnsafePath("history sidecar has no literal file name")
        })?);
    let source_metadata = fs::symlink_metadata(path);
    let target_metadata = fs::symlink_metadata(&target);
    match (source_metadata, target_metadata) {
        (Err(source), Err(target))
            if source.kind() == io::ErrorKind::NotFound
                && target.kind() == io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        (Err(source), Ok(_)) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        (Ok(_), Ok(_)) if same_file_identity(path, &target)? => {
            fs::remove_file(path)?;
            Ok(())
        }
        (Ok(_), Err(target)) if target.kind() == io::ErrorKind::NotFound => {
            Err(DatabaseError::Ownership(
                "an unrelated sidecar appeared during interrupted quarantine".to_owned(),
            ))
        }
        (Err(error), _) | (_, Err(error)) => Err(error.into()),
        (Ok(_), Ok(_)) => Err(DatabaseError::Ownership(
            "history sidecar changed during interrupted quarantine".to_owned(),
        )),
    }
}

fn same_file_identity(left: &Path, right: &Path) -> Result<bool, DatabaseError> {
    let left_metadata = fs::symlink_metadata(left)?;
    let right_metadata = fs::symlink_metadata(right)?;
    if left_metadata.file_type().is_symlink()
        || right_metadata.file_type().is_symlink()
        || !left_metadata.file_type().is_file()
        || !right_metadata.file_type().is_file()
    {
        return Ok(false);
    }
    same_file::is_same_file(left, right).map_err(DatabaseError::Io)
}

fn resume_interrupted_quarantine(path: &Path) -> Result<bool, DatabaseError> {
    if fs::symlink_metadata(path).is_ok() {
        return Ok(false);
    }
    let marker = ownership_marker_path(path);
    match fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => {
            return Err(DatabaseError::UnsafePath(
                "interrupted quarantine marker is not a regular file",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    let Some(original_marker) = read_marker_file(&marker)? else {
        return Ok(false);
    };
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
        let quarantined_database = quarantine.join(path.file_name().ok_or_else(|| {
            DatabaseError::UnsafePath("history database has no literal file name")
        })?);
        let quarantined_marker =
            quarantine.join(marker.file_name().ok_or_else(|| {
                DatabaseError::UnsafePath("history marker has no literal file name")
            })?);
        let Some(candidate_marker) = read_marker_file(&quarantined_marker)? else {
            continue;
        };
        if candidate_marker.nonce != original_marker.nonce
            || !verify_ownership_pair(&quarantined_database, &quarantined_marker)?
            || !same_file_identity(&marker, &quarantined_marker)?
        {
            continue;
        }
        remove_resumed_sidecar(&sidecar_path(path, "-wal"), &quarantine)?;
        remove_resumed_sidecar(&sidecar_path(path, "-shm"), &quarantine)?;
        if !same_file_identity(&marker, &quarantined_marker)? {
            return Err(DatabaseError::Ownership(
                "interrupted quarantine marker changed during cleanup".to_owned(),
            ));
        }
        fs::remove_file(&marker)?;
        sync_parent_directory(path)?;
        return Ok(true);
    }
    Ok(false)
}

fn sync_regular_file(path: &Path) -> Result<(), DatabaseError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), DatabaseError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), DatabaseError> {
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), DatabaseError> {
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
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
