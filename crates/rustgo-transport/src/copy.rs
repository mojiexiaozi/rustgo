use std::io;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub const COPY_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyReport {
    pub first_to_second: u64,
    pub second_to_first: u64,
}

#[derive(Debug, Error)]
pub enum CopyError {
    #[error("stream copy I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("stream copy cancelled")]
    Cancelled,
    #[error("stream copy idle timeout")]
    IdleTimeout,
    #[error("stream byte count overflow")]
    ByteCountOverflow,
}

/// Copies bytes in both directions using two fixed-size buffers.
///
/// EOF in either direction shuts down only the corresponding destination
/// writer; the reverse direction continues until its own EOF. The idle timer
/// is reset only after bytes have been written successfully.
pub async fn copy_bidirectional_bounded<A, B>(
    first: &mut A,
    second: &mut B,
    idle_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<CopyReport, CopyError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (first_reader, first_writer) = tokio::io::split(first);
    let (second_reader, second_writer) = tokio::io::split(second);
    let (activity_sender, mut activity_receiver) = watch::channel(0_u64);

    let first_to_second = copy_one_direction(first_reader, second_writer, activity_sender.clone());
    let second_to_first = copy_one_direction(second_reader, first_writer, activity_sender);
    let copy = async move {
        let (first_to_second, second_to_first) =
            tokio::try_join!(first_to_second, second_to_first)?;
        Ok::<_, CopyError>(CopyReport {
            first_to_second,
            second_to_first,
        })
    };
    tokio::pin!(copy);

    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            result = &mut copy => return result,
            _ = cancellation.cancelled() => return Err(CopyError::Cancelled),
            activity = activity_receiver.changed() => {
                if activity.is_err() {
                    return copy.await;
                }
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            _ = &mut idle => return Err(CopyError::IdleTimeout),
        }
    }
}

async fn copy_one_direction<R, W>(
    mut reader: R,
    mut writer: W,
    activity: watch::Sender<u64>,
) -> Result<u64, CopyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut copied = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        writer.write_all(&buffer[..read]).await?;
        copied = copied
            .checked_add(read as u64)
            .ok_or(CopyError::ByteCountOverflow)?;
        activity.send_modify(|version| *version = version.wrapping_add(1));
    }
}
