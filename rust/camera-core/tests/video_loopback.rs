//! The video transport carries frames end to end over a plain loopback QUIC
//! connection (no proxy): `serve_frames` pushes, `receive_frames` receives.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use camera_core::video::{bind_video_listener, receive_frames, serve_frames};
use msquic_async::{msquic, Registration};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn frames_travel_from_server_to_client() {
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default()).unwrap());
    let shutdown = CancellationToken::new();

    // Server: bind the video listener and serve frames pushed into `frame_tx`.
    let (_reg, listener, addr) =
        bind_video_listener(Some(reg.clone()), "127.0.0.1:0".parse().unwrap()).unwrap();
    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(16);
    let serve = tokio::spawn(serve_frames(listener, frame_rx, shutdown.clone()));

    // Client: dial that address and collect inbound frames.
    let (recv_tx, mut recv_rx) = mpsc::channel::<(u64, Bytes)>(16);
    let client_shutdown = shutdown.clone();
    let receive = tokio::spawn(async move {
        receive_frames(None, addr, recv_tx, client_shutdown)
            .await
            .unwrap();
    });

    // The server fans out only to already-connected clients, and the connection
    // establishes asynchronously — so keep sending until frames arrive.
    let payload = Bytes::from_static(b"jpeg-frame-payload");
    let received = tokio::time::timeout(Duration::from_secs(15), async {
        let mut got = Vec::new();
        loop {
            let _ = frame_tx.send(payload.clone()).await;
            match tokio::time::timeout(Duration::from_millis(200), recv_rx.recv()).await {
                Ok(Some((_seq, data))) => {
                    got.push(data);
                    if got.len() >= 3 {
                        return got;
                    }
                }
                Ok(None) => panic!("receiver closed"),
                Err(_) => {} // no frame yet; loop and resend
            }
        }
    })
    .await
    .expect("frames should arrive within the timeout");

    assert!(
        received.iter().all(|f| f == &payload),
        "payload round-trips intact"
    );

    shutdown.cancel();
    let _ = serve.await;
    let _ = receive.await;
}
