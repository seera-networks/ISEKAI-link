//! The video transport carries frames end to end over a plain loopback QUIC
//! connection (no proxy): `serve_frames` pushes, `receive_frames` receives.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use camera_core::video::{
    bind_video_listener, receive_frames, serve_frames, serve_frames_with, RelayLegs, ServeOptions,
};
use isekai_p2p::agent::ObservedAddress;
use msquic_async::{msquic, Registration};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn frames_travel_from_server_to_client() {
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default()).unwrap());
    let shutdown = CancellationToken::new();

    // Server: bind the video listener (dev cert) and serve frames pushed into
    // `frame_tx`.
    let (_reg, listener, addr) =
        bind_video_listener(Some(reg.clone()), "127.0.0.1:0".parse().unwrap(), None).unwrap();
    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(16);
    let serve = tokio::spawn(serve_frames(listener, frame_rx, shutdown.clone()));

    // Client: dial that address (dev cert → skip validation) and collect frames.
    let (recv_tx, mut recv_rx) = mpsc::channel::<(u64, Bytes)>(16);
    let client_shutdown = shutdown.clone();
    let receive = tokio::spawn(async move {
        receive_frames(
            None,
            "127.0.0.1",
            addr.port(),
            false,
            recv_tx,
            client_shutdown,
        )
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

/// Advertising a direct path must never cost the relay path.
///
/// The server tells each accepted connection about its relay leg's binding so
/// the peer can migrate. Here that address is one this process never bound, so
/// `add_bound_addr` fails — which is exactly the case the code promises to
/// survive: log it and keep streaming. An Endpoint that cannot offer a direct
/// path is still a working Endpoint.
#[tokio::test]
async fn frames_keep_flowing_when_the_direct_path_cannot_be_advertised() {
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default()).unwrap());
    let shutdown = CancellationToken::new();

    let (_reg, listener, addr) =
        bind_video_listener(Some(reg.clone()), "127.0.0.1:0".parse().unwrap(), None).unwrap();

    // An address belonging to nothing in this process, published before the
    // first connection arrives.
    let (observed_tx, observed_rx) = watch::channel(Some(ObservedAddress {
        local: "192.0.2.1:40000".parse().unwrap(),
        observed: "203.0.113.5:40000".parse().unwrap(),
    }));

    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(16);
    let serve = tokio::spawn(serve_frames_with(
        listener,
        frame_rx,
        shutdown.clone(),
        ServeOptions {
            legs: Some(RelayLegs::Single(observed_rx)),
        },
    ));

    let (recv_tx, mut recv_rx) = mpsc::channel::<(u64, Bytes)>(16);
    let client_shutdown = shutdown.clone();
    let receive = tokio::spawn(async move {
        receive_frames(
            None,
            "127.0.0.1",
            addr.port(),
            false,
            recv_tx,
            client_shutdown,
        )
        .await
        .unwrap();
    });

    let payload = Bytes::from_static(b"jpeg-frame-payload");
    let received = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let _ = frame_tx.send(payload.clone()).await;
            if let Ok(Some((_seq, data))) =
                tokio::time::timeout(Duration::from_millis(200), recv_rx.recv()).await
            {
                return data;
            }
        }
    })
    .await
    .expect("frames arrive even though the advertisement failed");
    assert_eq!(received, payload);

    // Keep the sender alive to the end: dropping it would close the watch and
    // let the advertising task exit for the wrong reason.
    drop(observed_tx);
    shutdown.cancel();
    let _ = serve.await;
    let _ = receive.await;
}
