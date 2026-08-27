use std::error::Error;
use std::time::Duration;

use rustgo_transport::{COPY_BUFFER_SIZE, CopyError, CopyReport, copy_bidirectional_bounded};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn copies_large_payloads_both_directions_and_reports_byte_counts()
-> Result<(), Box<dyn Error>> {
    let (left_peer, mut left_relay) = tokio::io::duplex(97);
    let (mut right_relay, right_peer) = tokio::io::duplex(113);
    let cancellation = CancellationToken::new();
    let copy_task = tokio::spawn(async move {
        copy_bidirectional_bounded(
            &mut left_relay,
            &mut right_relay,
            Duration::from_secs(2),
            cancellation,
        )
        .await
    });

    let left_payload = vec![0x51; COPY_BUFFER_SIZE * 3 + 17];
    let right_payload = vec![0xa2; COPY_BUFFER_SIZE * 2 + 31];
    let expected_left = left_payload.clone();
    let expected_right = right_payload.clone();

    let (mut left_reader, mut left_writer) = tokio::io::split(left_peer);
    let (mut right_reader, mut right_writer) = tokio::io::split(right_peer);
    let left_send = async move {
        left_writer.write_all(&left_payload).await?;
        left_writer.shutdown().await
    };
    let left_receive = async move {
        let mut received = vec![0; expected_right.len()];
        left_reader.read_exact(&mut received).await?;
        assert_eq!(received, expected_right);
        Ok::<_, std::io::Error>(())
    };
    let right_send = async move {
        right_writer.write_all(&right_payload).await?;
        right_writer.shutdown().await
    };
    let right_receive = async move {
        let mut received = vec![0; expected_left.len()];
        right_reader.read_exact(&mut received).await?;
        assert_eq!(received, expected_left);
        Ok::<_, std::io::Error>(())
    };
    let (left_send, left_receive, right_send, right_receive) =
        tokio::join!(left_send, left_receive, right_send, right_receive);
    left_send?;
    left_receive?;
    right_send?;
    right_receive?;

    assert_eq!(
        timeout(Duration::from_secs(2), copy_task).await???,
        CopyReport {
            first_to_second: (COPY_BUFFER_SIZE * 3 + 17) as u64,
            second_to_first: (COPY_BUFFER_SIZE * 2 + 31) as u64,
        }
    );
    Ok(())
}

#[tokio::test]
async fn propagates_half_close_without_ending_the_reverse_direction() -> Result<(), Box<dyn Error>>
{
    let (mut client, mut client_relay) = tokio::io::duplex(64);
    let (mut service_relay, mut service) = tokio::io::duplex(64);
    let copy_task = tokio::spawn(async move {
        copy_bidirectional_bounded(
            &mut client_relay,
            &mut service_relay,
            Duration::from_secs(2),
            CancellationToken::new(),
        )
        .await
    });

    client.write_all(b"request").await?;
    client.shutdown().await?;

    let mut request = Vec::new();
    timeout(Duration::from_secs(1), service.read_to_end(&mut request)).await??;
    assert_eq!(request, b"request");
    service.write_all(b"response-after-eof").await?;
    service.shutdown().await?;

    let mut response = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut response)).await??;
    assert_eq!(response, b"response-after-eof");
    assert_eq!(
        copy_task.await??,
        CopyReport {
            first_to_second: 7,
            second_to_first: 18,
        }
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_stops_an_idle_copy() -> Result<(), Box<dyn Error>> {
    let (_left_peer, mut left_relay) = tokio::io::duplex(64);
    let (_right_peer, mut right_relay) = tokio::io::duplex(64);
    let cancellation = CancellationToken::new();
    let cancellation_for_task = cancellation.clone();
    let copy_task = tokio::spawn(async move {
        copy_bidirectional_bounded(
            &mut left_relay,
            &mut right_relay,
            Duration::from_secs(30),
            cancellation_for_task,
        )
        .await
    });

    cancellation.cancel();
    assert!(matches!(
        timeout(Duration::from_secs(1), copy_task).await??,
        Err(CopyError::Cancelled)
    ));
    Ok(())
}

#[tokio::test]
async fn inactivity_ends_copy_with_idle_timeout() -> Result<(), Box<dyn Error>> {
    let (_left_peer, mut left_relay) = tokio::io::duplex(64);
    let (_right_peer, mut right_relay) = tokio::io::duplex(64);

    let result = copy_bidirectional_bounded(
        &mut left_relay,
        &mut right_relay,
        Duration::from_millis(20),
        CancellationToken::new(),
    )
    .await;

    assert!(matches!(result, Err(CopyError::IdleTimeout)));
    Ok(())
}

#[tokio::test]
async fn successful_byte_progress_resets_the_idle_deadline() -> Result<(), Box<dyn Error>> {
    let (mut sender, mut left_relay) = tokio::io::duplex(64);
    let (mut right_relay, mut receiver) = tokio::io::duplex(64);
    let cancellation = CancellationToken::new();
    let cancellation_for_task = cancellation.clone();
    let copy_task = tokio::spawn(async move {
        copy_bidirectional_bounded(
            &mut left_relay,
            &mut right_relay,
            Duration::from_millis(80),
            cancellation_for_task,
        )
        .await
    });

    for byte in [1_u8, 2, 3] {
        tokio::time::sleep(Duration::from_millis(50)).await;
        sender.write_all(&[byte]).await?;
        let mut received = [0];
        receiver.read_exact(&mut received).await?;
        assert_eq!(received, [byte]);
        assert!(!copy_task.is_finished());
    }

    cancellation.cancel();
    assert!(matches!(copy_task.await?, Err(CopyError::Cancelled)));
    Ok(())
}

#[tokio::test]
async fn each_partial_write_refreshes_idle_while_a_small_buffer_drains_slowly()
-> Result<(), Box<dyn Error>> {
    let (mut sender, mut source_relay) = tokio::io::duplex(64);
    let (mut destination_relay, destination) = tokio::io::duplex(1);
    let idle_timeout = Duration::from_millis(100);
    let copy_task = tokio::spawn(async move {
        copy_bidirectional_bounded(
            &mut source_relay,
            &mut destination_relay,
            idle_timeout,
            CancellationToken::new(),
        )
        .await
    });
    let (mut receiver, mut reverse_writer) = tokio::io::split(destination);
    reverse_writer.shutdown().await?;

    let payload = [1_u8, 2, 3, 4, 5, 6];
    sender.write_all(&payload).await?;
    sender.shutdown().await?;

    let started = tokio::time::Instant::now();
    for expected in payload {
        let mut received = [0];
        receiver.read_exact(&mut received).await?;
        assert_eq!(received, [expected]);
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(started.elapsed() > idle_timeout);

    assert_eq!(
        timeout(Duration::from_secs(1), copy_task).await???,
        CopyReport {
            first_to_second: payload.len() as u64,
            second_to_first: 0,
        }
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_interrupts_a_copy_blocked_after_partial_write() -> Result<(), Box<dyn Error>>
{
    let (mut sender, mut source_relay) = tokio::io::duplex(64);
    let (mut destination_relay, mut receiver) = tokio::io::duplex(1);
    let cancellation = CancellationToken::new();
    let cancellation_for_task = cancellation.clone();
    let copy_task = tokio::spawn(async move {
        copy_bidirectional_bounded(
            &mut source_relay,
            &mut destination_relay,
            Duration::from_secs(30),
            cancellation_for_task,
        )
        .await
    });

    sender.write_all(&[1, 2, 3, 4]).await?;
    let mut first = [0];
    receiver.read_exact(&mut first).await?;
    assert_eq!(first, [1]);
    tokio::task::yield_now().await;

    cancellation.cancel();

    assert!(matches!(
        timeout(Duration::from_secs(1), copy_task).await??,
        Err(CopyError::Cancelled)
    ));
    Ok(())
}
