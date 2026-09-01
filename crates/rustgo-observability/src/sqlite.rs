use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, Transaction, params};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    AuthenticatedClientIdentity, BoundedLabel, HistoryPoint, HostMetrics, SessionKind, SessionPath,
    SessionSnapshot, TrafficCounters,
};

pub const HISTORY_BATCH_QUEUE_CAPACITY: usize = 1024;
pub const HISTORY_CONTROL_QUEUE_CAPACITY: usize = 128;
pub const MAX_HISTORY_RECORDS_PER_BATCH: usize = 8192;
pub const MAX_HISTORY_POINTS: usize = 2000;
pub const HISTORY_SCHEMA_VERSION: u32 = 2;

const RAW_RETENTION_MILLIS: u64 = 60 * 60 * 1000;
const ONE_MINUTE_RETENTION_MILLIS: u64 = 24 * RAW_RETENTION_MILLIS;
const MINUTE_BUCKET_MILLIS: u64 = 60 * 1000;
const FIVE_MINUTE_BUCKET_MILLIS: u64 = 5 * MINUTE_BUCKET_MILLIS;
const DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(5);
const WARNING_INTERVAL: Duration = Duration::from_secs(30);
const MAX_BATCH_WRITE_ATTEMPTS: usize = 3;
const MAX_BATCHES_PER_TRANSACTION: usize = 64;
const RETENTION_DELETE_LIMIT: usize = 1024;
const RETENTION_DELETE_PASSES: usize = 128;
const CAP_DELETE_LIMIT: usize = 512;
const MIB: u64 = 1024 * 1024;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryPublishError {
    Closed,
    EmptyBatch,
    BatchTooLarge,
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
    ThreadPanicked,
}

impl fmt::Display for HistoryWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreadSpawn(error) => {
                write!(formatter, "failed to start history worker: {error}")
            }
            Self::ThreadPanicked => formatter.write_str("history worker panicked"),
        }
    }
}

impl std::error::Error for HistoryWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ThreadSpawn(error) => Some(error),
            Self::ThreadPanicked => None,
        }
    }
}

enum Command {
    Batch(HistoryBatch),
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
    pending_batches: usize,
    pending_controls: usize,
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
}

impl Shared {
    fn new() -> Self {
        Self {
            queue: Mutex::new(QueueState::default()),
            ready: Condvar::new(),
            handles: AtomicUsize::new(1),
            history_available: AtomicBool::new(false),
            dropped_batches: AtomicU64::new(0),
            recoveries: AtomicU64::new(0),
            total_database_bytes: AtomicU64::new(0),
            size_floor_reached: AtomicBool::new(false),
        }
    }

    fn push_batch(&self, batch: HistoryBatch) -> Result<(), HistoryPublishError> {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if queue.closed {
            return Err(HistoryPublishError::Closed);
        }
        if queue.pending_batches == HISTORY_BATCH_QUEUE_CAPACITY
            && let Some(position) = queue.commands.iter().position(Command::is_batch)
        {
            queue.commands.remove(position);
            queue.pending_batches -= 1;
            self.dropped_batches.fetch_add(1, Ordering::Relaxed);
        }
        queue.commands.push_back(Command::Batch(batch));
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
        if queue.pending_controls == HISTORY_CONTROL_QUEUE_CAPACITY {
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
            queue.pending_batches -= 1;
        } else {
            queue.pending_controls -= 1;
        }
        Some(command)
    }

    fn drain_following_batches(&self, batches: &mut Vec<HistoryBatch>) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while batches.len() < MAX_BATCHES_PER_TRANSACTION
            && queue.commands.front().is_some_and(Command::is_batch)
        {
            let Some(Command::Batch(batch)) = queue.commands.pop_front() else {
                break;
            };
            queue.pending_batches -= 1;
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
        let mut retained = VecDeque::with_capacity(queue.pending_batches);
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

    fn closed_and_empty(&self) -> bool {
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.closed && queue.commands.is_empty()
    }

    fn discard_batches_when_closed(&self) -> bool {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !queue.closed {
            return false;
        }
        self.dropped_batches
            .fetch_add(queue.pending_batches as u64, Ordering::Relaxed);
        queue.commands.clear();
        queue.pending_batches = 0;
        queue.pending_controls = 0;
        true
    }

    fn pending_batches(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_batches
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
        let shared = Arc::new(Shared::new());
        Ok((
            Self {
                shared: Arc::clone(&shared),
            },
            HistoryWorker { config, shared },
        ))
    }

    pub fn try_publish(&self, batch: HistoryBatch) -> Result<(), HistoryPublishError> {
        if batch.is_empty() {
            return Err(HistoryPublishError::EmptyBatch);
        }
        if batch.record_count() > MAX_HISTORY_RECORDS_PER_BATCH {
            return Err(HistoryPublishError::BatchTooLarge);
        }
        self.shared.push_batch(batch)
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
        match tokio::time::timeout(QUERY_TIMEOUT, received).await {
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
        }
    }

    pub fn close(&self) {
        self.shared.close();
    }
}

impl HistoryWorker {
    pub async fn run(mut self) -> Result<(), HistoryWorkerError> {
        let (completed, completion) = oneshot::channel();
        let thread = thread::Builder::new()
            .name("rustgo-sqlite-history".to_owned())
            .spawn(move || {
                self.run_blocking();
                let _ = completed.send(());
            })
            .map_err(HistoryWorkerError::ThreadSpawn)?;

        let _ = completion.await;
        thread
            .join()
            .map_err(|_| HistoryWorkerError::ThreadPanicked)
    }

    fn run_blocking(&mut self) {
        let mut connection = None;
        let mut retry_backoff = INITIAL_RETRY_BACKOFF;
        let mut retry_batch: Option<(Vec<HistoryBatch>, usize)> = None;
        let mut next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
        let mut warning_limiter = WarningLimiter::default();

        loop {
            if connection.is_none() {
                match open_database(&self.config) {
                    Ok(opened) => {
                        if !self.shared.history_available.swap(true, Ordering::AcqRel)
                            && self.shared.recoveries.load(Ordering::Relaxed) > 0
                        {
                            tracing::info!(
                                "SQLite history recovered; persisted metrics are available again"
                            );
                        }
                        connection = Some(opened);
                        retry_backoff = INITIAL_RETRY_BACKOFF;
                    }
                    Err(error) => {
                        self.shared
                            .history_available
                            .store(false, Ordering::Release);
                        warning_limiter.warn(&error);
                        if error.should_quarantine()
                            && quarantine_database(&self.config.database_path).unwrap_or(false)
                        {
                            self.shared.recoveries.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                "SQLite history file was quarantined; a fresh bounded history database will be created"
                            );
                            retry_backoff = INITIAL_RETRY_BACKOFF;
                            continue;
                        }
                        self.shared.fail_pending_controls();
                        if self.shared.discard_batches_when_closed() {
                            if let Some((batches, _)) = retry_batch.take() {
                                self.shared
                                    .dropped_batches
                                    .fetch_add(batches.len() as u64, Ordering::Relaxed);
                            }
                            return;
                        }
                        self.shared.wait(retry_backoff);
                        retry_backoff = doubled_backoff(retry_backoff);
                        continue;
                    }
                }
            }

            let database = connection
                .as_mut()
                .expect("history connection is initialized above");

            if let Some((batches, attempts)) = retry_batch.take() {
                match persist_batches(database, &batches) {
                    Ok(()) => {
                        self.shared.history_available.store(true, Ordering::Release);
                    }
                    Err(error) => {
                        self.database_failed(&error, &mut warning_limiter);
                        connection = None;
                        self.quarantine_after_failure(&error);
                        if attempts + 1 < MAX_BATCH_WRITE_ATTEMPTS {
                            retry_batch = Some((batches, attempts + 1));
                        } else {
                            self.shared
                                .dropped_batches
                                .fetch_add(batches.len() as u64, Ordering::Relaxed);
                        }
                        continue;
                    }
                }
            }

            let now = Instant::now();
            if now >= next_maintenance {
                let wall_clock = unix_millis_now();
                match maintain_database(database, &self.config, wall_clock, &self.shared) {
                    Ok(()) => {
                        self.shared.history_available.store(true, Ordering::Release);
                        next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
                    }
                    Err(error) => {
                        self.database_failed(&error, &mut warning_limiter);
                        connection = None;
                        self.quarantine_after_failure(&error);
                    }
                }
                continue;
            }

            let wait = next_maintenance.saturating_duration_since(Instant::now());
            let Some(command) = self.shared.pop(wait) else {
                if self.shared.closed_and_empty() {
                    let _ = checkpoint_database(database, &self.config, &self.shared);
                    return;
                }
                continue;
            };

            match command {
                Command::Batch(batch) => {
                    let mut batches = vec![batch];
                    self.shared.drain_following_batches(&mut batches);
                    match persist_batches(database, &batches) {
                        Ok(()) => {
                            self.shared.history_available.store(true, Ordering::Release);
                        }
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            retry_batch = Some((batches, 1));
                            connection = None;
                            self.quarantine_after_failure(&error);
                        }
                    }
                }
                Command::Query(query, response) => match query_database(database, &query) {
                    Ok(series) => {
                        self.shared.history_available.store(true, Ordering::Release);
                        let _ = response.send(Ok(series));
                    }
                    Err(error) => {
                        self.database_failed(&error, &mut warning_limiter);
                        let _ = response.send(Err(HistoryQueryError::Unavailable));
                        connection = None;
                        self.quarantine_after_failure(&error);
                    }
                },
                Command::Maintain(now, response) => {
                    match maintain_database(database, &self.config, now, &self.shared) {
                        Ok(()) => {
                            self.shared.history_available.store(true, Ordering::Release);
                            let _ = response.send(Ok(()));
                            next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
                        }
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            let _ = response.send(Err(HistoryQueryError::Unavailable));
                            connection = None;
                            self.quarantine_after_failure(&error);
                        }
                    }
                }
                Command::Checkpoint(response) => {
                    match checkpoint_database(database, &self.config, &self.shared) {
                        Ok(()) => {
                            self.shared.history_available.store(true, Ordering::Release);
                            let _ = response.send(Ok(()));
                        }
                        Err(error) => {
                            self.database_failed(&error, &mut warning_limiter);
                            let _ = response.send(Err(HistoryQueryError::Unavailable));
                            connection = None;
                            self.quarantine_after_failure(&error);
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
}

impl DatabaseError {
    fn should_quarantine(&self) -> bool {
        match self {
            Self::IncompatibleSchema(_) | Self::Integrity(_) => true,
            Self::Sqlite(rusqlite::Error::SqliteFailure(code, _)) => matches!(
                code.code,
                rusqlite::ffi::ErrorCode::DatabaseCorrupt | rusqlite::ffi::ErrorCode::NotADatabase
            ),
            Self::Sqlite(_) | Self::Io(_) | Self::ValueOutOfRange(_) => false,
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

fn open_database(config: &HistoryConfig) -> Result<Connection, DatabaseError> {
    let connection = Connection::open_with_flags(
        &config.database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
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
    migrate(&connection)?;
    let integrity: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if !integrity.eq_ignore_ascii_case("ok") {
        return Err(DatabaseError::Integrity(integrity));
    }
    Ok(connection)
}

fn migrate(connection: &Connection) -> Result<(), DatabaseError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > HISTORY_SCHEMA_VERSION {
        return Err(DatabaseError::IncompatibleSchema(version));
    }
    if version == 0 {
        connection.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS server_metric_points (
                resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                sample_count INTEGER NOT NULL CHECK (sample_count > 0),
                PRIMARY KEY (resolution, timestamp_ms, metric)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS client_metric_points (
                client_name TEXT NOT NULL,
                resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                sample_count INTEGER NOT NULL CHECK (sample_count > 0),
                PRIMARY KEY (client_name, resolution, timestamp_ms, metric)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS client_metric_query
                ON client_metric_points (resolution, metric, timestamp_ms, client_name);
            CREATE TABLE IF NOT EXISTS client_lifecycle (
                id INTEGER PRIMARY KEY,
                client_name TEXT NOT NULL,
                generation TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                version TEXT,
                UNIQUE (client_name, generation, event_kind, timestamp_ms)
            );
            CREATE INDEX IF NOT EXISTS client_lifecycle_time
                ON client_lifecycle (timestamp_ms, id);
            CREATE TABLE IF NOT EXISTS session_summaries (
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
            );
            CREATE INDEX IF NOT EXISTS session_summaries_time
                ON session_summaries (closed_ms, opened_ms, session_id);
            ",
        )?;
        transaction.pragma_update(None, "user_version", 1)?;
        transaction.commit()?;
    }
    if version < 2 {
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(
            "CREATE INDEX IF NOT EXISTS client_lifecycle_latest
             ON client_lifecycle (client_name, timestamp_ms DESC, id DESC);",
        )?;
        transaction.pragma_update(None, "user_version", 2)?;
        transaction.commit()?;
    }
    Ok(())
}

fn persist_batches(
    connection: &mut Connection,
    batches: &[HistoryBatch],
) -> Result<(), DatabaseError> {
    let transaction = connection.transaction()?;
    let mut server_minutes = BTreeSet::new();
    let mut server_five_minutes = BTreeSet::new();
    let mut client_minutes = BTreeSet::new();
    let mut client_five_minutes = BTreeSet::new();

    for batch in batches {
        for sample in &batch.server_points {
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

fn aggregate_all(connection: &Connection) -> Result<(), DatabaseError> {
    aggregate_all_server(connection, 0, 1, MINUTE_BUCKET_MILLIS)?;
    aggregate_all_client(connection, 0, 1, MINUTE_BUCKET_MILLIS)?;
    aggregate_all_server(connection, 1, 2, FIVE_MINUTE_BUCKET_MILLIS)?;
    aggregate_all_client(connection, 1, 2, FIVE_MINUTE_BUCKET_MILLIS)?;
    Ok(())
}

fn aggregate_all_server(
    connection: &Connection,
    source_resolution: i64,
    target_resolution: i64,
    width: u64,
) -> Result<(), DatabaseError> {
    let width = sqlite_integer(width, "aggregation width")?;
    connection.execute(
        "INSERT INTO server_metric_points
         (resolution, timestamp_ms, metric, value, sample_count)
         SELECT ?1, (timestamp_ms / ?2) * ?2, metric,
                SUM(value * sample_count) / SUM(sample_count),
                SUM(sample_count)
         FROM server_metric_points
         WHERE resolution = ?3
         GROUP BY (timestamp_ms / ?2), metric
         ON CONFLICT (resolution, timestamp_ms, metric) DO UPDATE SET
             value = excluded.value,
             sample_count = excluded.sample_count",
        params![target_resolution, width, source_resolution],
    )?;
    Ok(())
}

fn aggregate_all_client(
    connection: &Connection,
    source_resolution: i64,
    target_resolution: i64,
    width: u64,
) -> Result<(), DatabaseError> {
    let width = sqlite_integer(width, "aggregation width")?;
    connection.execute(
        "INSERT INTO client_metric_points
         (client_name, resolution, timestamp_ms, metric, value, sample_count)
         SELECT client_name, ?1, (timestamp_ms / ?2) * ?2, metric,
                SUM(value * sample_count) / SUM(sample_count),
                SUM(sample_count)
         FROM client_metric_points
         WHERE resolution = ?3
         GROUP BY client_name, (timestamp_ms / ?2), metric
         ON CONFLICT (client_name, resolution, timestamp_ms, metric) DO UPDATE SET
             value = excluded.value,
             sample_count = excluded.sample_count",
        params![target_resolution, width, source_resolution],
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

fn maintain_database(
    connection: &mut Connection,
    config: &HistoryConfig,
    now_unix_millis: u64,
    shared: &Shared,
) -> Result<(), DatabaseError> {
    aggregate_all(connection)?;
    let transaction = connection.transaction()?;
    delete_older_metric_rows(
        &transaction,
        0,
        now_unix_millis.saturating_sub(RAW_RETENTION_MILLIS),
    )?;
    delete_older_metric_rows(
        &transaction,
        1,
        now_unix_millis.saturating_sub(ONE_MINUTE_RETENTION_MILLIS),
    )?;
    let history_cutoff = now_unix_millis.saturating_sub(config.retention_millis());
    delete_older_metric_rows(&transaction, 2, history_cutoff)?;
    delete_old_lifecycle(&transaction, history_cutoff)?;
    delete_old_sessions(&transaction, history_cutoff)?;
    transaction.commit()?;
    enforce_size_cap(connection, config, shared)
}

fn delete_older_metric_rows(
    transaction: &Transaction<'_>,
    resolution: i64,
    cutoff: u64,
) -> Result<(), DatabaseError> {
    let cutoff = sqlite_integer(cutoff, "retention cutoff")?;
    for _ in 0..RETENTION_DELETE_PASSES {
        let server_deleted = transaction.execute(
            "DELETE FROM server_metric_points
             WHERE (resolution, timestamp_ms, metric) IN (
                 SELECT resolution, timestamp_ms, metric
                 FROM server_metric_points
                 WHERE resolution = ?1 AND timestamp_ms < ?2
                 ORDER BY timestamp_ms ASC, metric ASC
                 LIMIT ?3
             )",
            params![resolution, cutoff, RETENTION_DELETE_LIMIT as i64],
        )?;
        let client_deleted = transaction.execute(
            "DELETE FROM client_metric_points
             WHERE (client_name, resolution, timestamp_ms, metric) IN (
                 SELECT client_name, resolution, timestamp_ms, metric
                 FROM client_metric_points
                 WHERE resolution = ?1 AND timestamp_ms < ?2
                 ORDER BY timestamp_ms ASC, client_name ASC, metric ASC
                 LIMIT ?3
             )",
            params![resolution, cutoff, RETENTION_DELETE_LIMIT as i64],
        )?;
        if server_deleted < RETENTION_DELETE_LIMIT && client_deleted < RETENTION_DELETE_LIMIT {
            break;
        }
    }
    Ok(())
}

fn delete_old_lifecycle(transaction: &Transaction<'_>, cutoff: u64) -> Result<(), DatabaseError> {
    let cutoff = sqlite_integer(cutoff, "lifecycle retention cutoff")?;
    for _ in 0..RETENTION_DELETE_PASSES {
        let deleted = transaction.execute(
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
            break;
        }
    }
    Ok(())
}

fn delete_old_sessions(transaction: &Transaction<'_>, cutoff: u64) -> Result<(), DatabaseError> {
    let cutoff = sqlite_integer(cutoff, "session retention cutoff")?;
    for _ in 0..RETENTION_DELETE_PASSES {
        let deleted = transaction.execute(
            "DELETE FROM session_summaries
             WHERE rowid IN (
                 SELECT rowid FROM session_summaries
                 WHERE COALESCE(closed_ms, opened_ms) < ?1
                 ORDER BY COALESCE(closed_ms, opened_ms) ASC, rowid ASC
                 LIMIT ?2
             )",
            params![cutoff, RETENTION_DELETE_LIMIT as i64],
        )?;
        if deleted < RETENTION_DELETE_LIMIT {
            break;
        }
    }
    Ok(())
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

fn enforce_size_cap(
    connection: &mut Connection,
    config: &HistoryConfig,
    shared: &Shared,
) -> Result<(), DatabaseError> {
    checkpoint_truncate(connection)?;
    incremental_vacuum(connection)?;
    let maximum = config.maximum_bytes();
    let target = maximum.saturating_mul(9) / 10;
    let mut total = database_family_size(&config.database_path)?;
    shared.size_floor_reached.store(false, Ordering::Relaxed);
    if total <= maximum {
        shared.total_database_bytes.store(total, Ordering::Relaxed);
        return Ok(());
    }

    loop {
        let deleted = prune_cap_batch(connection)?;
        if !deleted {
            shared.size_floor_reached.store(true, Ordering::Relaxed);
            break;
        }
        checkpoint_truncate(connection)?;
        incremental_vacuum(connection)?;
        total = database_family_size(&config.database_path)?;
        if total <= target {
            break;
        }
    }
    shared.total_database_bytes.store(total, Ordering::Relaxed);
    Ok(())
}

fn prune_cap_batch(connection: &mut Connection) -> Result<bool, DatabaseError> {
    for resolution in [2_i64, 1, 0] {
        if prune_metric_table(connection, "server_metric_points", resolution)? {
            return Ok(true);
        }
        if prune_metric_table(connection, "client_metric_points", resolution)? {
            return Ok(true);
        }
    }
    if prune_lifecycle(connection)? {
        return Ok(true);
    }
    prune_sessions(connection)
}

fn prune_metric_table(
    connection: &mut Connection,
    table: &'static str,
    resolution: i64,
) -> Result<bool, DatabaseError> {
    let bucket_limit = (CAP_DELETE_LIMIT / 13).max(1) as i64;
    if table == "server_metric_points" {
        let buckets: usize = connection.query_row(
            "SELECT COUNT(DISTINCT timestamp_ms)
             FROM server_metric_points
             WHERE resolution = ?1",
            [resolution],
            |row| row.get(0),
        )?;
        if buckets <= 1 {
            return Ok(false);
        }
        let limit = (buckets - 1).min(bucket_limit as usize) as i64;
        let deleted = connection.execute(
            "DELETE FROM server_metric_points
             WHERE resolution = ?1 AND timestamp_ms IN (
                 SELECT DISTINCT timestamp_ms
                 FROM server_metric_points
                 WHERE resolution = ?1
                 ORDER BY timestamp_ms ASC
                 LIMIT ?2
             )",
            params![resolution, limit],
        )?;
        return Ok(deleted > 0);
    }

    let deletable: usize = connection.query_row(
        "SELECT COUNT(*) FROM (
             SELECT candidate.client_name, candidate.timestamp_ms
             FROM client_metric_points AS candidate
             WHERE candidate.resolution = ?1
               AND candidate.timestamp_ms < (
                   SELECT MAX(current.timestamp_ms)
                   FROM client_metric_points AS current
                   WHERE current.client_name = candidate.client_name
                     AND current.resolution = ?1
               )
             GROUP BY candidate.client_name, candidate.timestamp_ms
         )",
        [resolution],
        |row| row.get(0),
    )?;
    if deletable == 0 {
        return Ok(false);
    }
    let limit = deletable.min(bucket_limit as usize) as i64;
    let deleted = connection.execute(
        "DELETE FROM client_metric_points
         WHERE resolution = ?1 AND (client_name, timestamp_ms) IN (
             SELECT candidate.client_name, candidate.timestamp_ms
             FROM client_metric_points AS candidate
             WHERE candidate.resolution = ?1
               AND candidate.timestamp_ms < (
                   SELECT MAX(current.timestamp_ms)
                   FROM client_metric_points AS current
                   WHERE current.client_name = candidate.client_name
                     AND current.resolution = ?1
               )
             GROUP BY candidate.client_name, candidate.timestamp_ms
             ORDER BY candidate.timestamp_ms ASC, candidate.client_name ASC
             LIMIT ?2
         )",
        params![resolution, limit],
    )?;
    Ok(deleted > 0)
}

fn prune_lifecycle(connection: &mut Connection) -> Result<bool, DatabaseError> {
    let deletable: usize = connection.query_row(
        "SELECT COUNT(*)
         FROM client_lifecycle AS candidate
         WHERE candidate.id <> (
             SELECT current.id
             FROM client_lifecycle AS current
             WHERE current.client_name = candidate.client_name
             ORDER BY current.timestamp_ms DESC, current.id DESC
             LIMIT 1
         )",
        [],
        |row| row.get(0),
    )?;
    if deletable == 0 {
        return Ok(false);
    }
    let limit = deletable.min(CAP_DELETE_LIMIT) as i64;
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
        [limit],
    )?;
    Ok(deleted > 0)
}

fn prune_sessions(connection: &mut Connection) -> Result<bool, DatabaseError> {
    let count: usize =
        connection.query_row("SELECT COUNT(*) FROM session_summaries", [], |row| {
            row.get(0)
        })?;
    if count <= 1 {
        return Ok(false);
    }
    let limit = (count - 1).min(CAP_DELETE_LIMIT) as i64;
    let deleted = connection.execute(
        "DELETE FROM session_summaries
         WHERE rowid IN (
             SELECT rowid FROM session_summaries
             WHERE closed_ms IS NOT NULL
             ORDER BY closed_ms ASC, rowid ASC
             LIMIT ?1
         )",
        [limit],
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

fn incremental_vacuum(connection: &Connection) -> Result<(), DatabaseError> {
    connection.execute_batch("PRAGMA incremental_vacuum(1024)")?;
    Ok(())
}

fn database_family_size(path: &Path) -> Result<u64, DatabaseError> {
    let mut total = 0_u64;
    for candidate in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        match fs::metadata(candidate) {
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
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Ok(false);
    }

    let timestamp = unix_millis_now();
    let mut quarantine = None;
    for counter in 0..1000_u16 {
        let candidate = path.with_file_name(format!(
            "{}.corrupt-{timestamp}-{counter}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        if !candidate.exists() {
            quarantine = Some(candidate);
            break;
        }
    }
    let quarantine = quarantine.ok_or_else(|| {
        DatabaseError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique SQLite quarantine name",
        ))
    })?;
    fs::rename(path, &quarantine)?;
    for suffix in ["-wal", "-shm"] {
        let source = sidecar_path(path, suffix);
        if source.is_file() {
            let target = sidecar_path(&quarantine, suffix);
            if let Err(error) = fs::rename(&source, &target) {
                tracing::warn!(
                    error = %error,
                    sidecar = suffix,
                    "could not quarantine a SQLite history sidecar"
                );
            }
        }
    }
    Ok(true)
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
