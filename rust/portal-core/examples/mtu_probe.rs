//! What the inner peer connection will actually carry, measured rather than
//! derived (`docs/portal_mtu_plan.md` P0).
//!
//! The plan's arithmetic starts from `MaximumMtu = 1248` and subtracts a QUIC
//! packet plus DATAGRAM frame overhead it calls **42, provisional** — a figure
//! taken from the *outer* connection, whose connection IDs are not the inner
//! one's. Every number after it rides on that, so it is measured here instead.
//!
//! Two families, because the overhead is not the only thing that moves: msquic
//! sizes a datagram from the path MTU less the IP and UDP headers, and IPv6's
//! header is 20 bytes larger. The contract has to hold on both, so it is the
//! smaller of the two.
//!
//!   cargo run -p portal-core --example mtu_probe
//!
//! Nothing here is a test. It stands up a loopback connection with the same
//! `peer::client_config` production uses and reports what msquic says about it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use msquic_async::{msquic, ConnectionEvent, Registration};
use portal_core::datagram::{HEADER, MAX_PAYLOAD};
use portal_core::transport;
use tokio_util::sync::CancellationToken;

/// What `peer::client_config` asks for, and what msquic clamps it to.
const MAXIMUM_MTU: usize = 1248;

/// IP + UDP headers msquic takes off the path MTU before it has a QUIC packet.
const IPV4_UDP: usize = 20 + 8;
const IPV6_UDP: usize = 40 + 8;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<std::convert::Infallible> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // **Only IPv4 can be measured this way, and the reason is the product.**
    // `peer::dial` pins every attempt to `Ipv4Addr::LOCALHOST`: the inner
    // connection's relay path is the local end of the MASQUE tunnel, which is
    // always 127.0.0.1. So a loopback dial cannot produce an IPv6 path, and the
    // IPv6 row below is derived from the same measured overhead rather than
    // observed. The derivation is exact -- `QuicCalculateDatagramLength` takes
    // the family only to choose an IP header size -- but it is a derivation, and
    // this says so rather than printing both as if they were the same kind of
    // number.
    let max_send_length = probe("127.0.0.1:0", "127.0.0.1").await?;
    let overhead = (MAXIMUM_MTU - IPV4_UDP) - max_send_length;

    println!("\n  MaximumMtu (IP level)          {MAXIMUM_MTU}   (msquic clamps to this; asking lower is ignored)");
    println!("  QUIC packet + DATAGRAM + AEAD  {overhead}     <- MEASURED");
    println!("    = short header 5 + CID 9 + datagram frame 3 + encryption 16");
    println!("      CID 9 = server-id 0 (load balancing off) + pid 2 + payload 7\n");

    println!("  family   IP+UDP   MaxUdpPayload   MaxSendLength   portal payload");
    let mut worst = usize::MAX;
    for (label, ip_udp, how) in [
        ("IPv4", IPV4_UDP, "measured"),
        ("IPv6", IPV6_UDP, "derived"),
    ] {
        let udp_payload = MAXIMUM_MTU - ip_udp;
        let send_length = udp_payload - overhead;
        let offered = send_length - HEADER;
        worst = worst.min(offered);
        println!(
            "  {label}     {ip_udp:<8} {udp_payload:<15} {send_length:<15} {offered:<8} ({how})"
        );
    }

    println!("\n  contract A = {worst}, the smaller of the two");
    println!(
        "  MAX_PAYLOAD is {MAX_PAYLOAD}, which is {} too large",
        MAX_PAYLOAD as i64 - worst as i64
    );
    println!(
        "  a payload between {} and {MAX_PAYLOAD} is accepted here and refused by an IPv6 connection",
        worst + 1
    );
    // **Leaves rather than returns**, which is `portal_core::shutdown`'s whole
    // subject: the registration is still holding a live connection, and letting
    // the runtime drop underneath it runs `RegistrationClose` — a blocking,
    // uninterruptible wait that here ends in a core dump on the way out. This
    // is the same exit both portal binaries take.
    portal_core::shutdown::leave(0).await
}

/// Stand one connection up and report the `max_send_length` msquic announces.
async fn probe(listen: &str, dial: &str) -> anyhow::Result<usize> {
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default())?);
    let listen: SocketAddr = listen.parse()?;
    let (_reg, listener, bound) = transport::bind(Some(reg.clone()), listen, None)?;
    let shutdown = CancellationToken::new();

    // **Held, not dropped.** Letting the accepted connection go closes it, and
    // the dialling side then never gets far enough to be told a datagram limit.
    let serving = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = serving.cancelled() => {}
            accepted = listener.accept() => {
                if let Ok(conn) = accepted {
                    serving.cancelled().await;
                    std::mem::forget(conn);
                }
            }
        }
    });

    let session = tokio::time::timeout(
        Duration::from_secs(10),
        transport::connect(
            Some(reg.clone()),
            dial,
            bound.port(),
            transport::ConnectOptions::default(),
            &shutdown,
        ),
    )
    .await??;

    let conn = session.connection().clone();
    if let Ok(stats) = conn.get_stats() {
        println!(
            "  (send_path_mtu reported by msquic: {})",
            stats.Send.PathMtu
        );
    }

    // `DatagramStateChanged` is announced once the peer's transport parameters
    // are in, which is the only place the real limit is stated.
    let answer = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match std::future::poll_fn(|cx| conn.poll_event(cx)).await {
                Ok(ConnectionEvent::DatagramStateChanged {
                    send_enabled,
                    max_send_length,
                }) if send_enabled => return Ok(usize::from(max_send_length)),
                Ok(_) => continue,
                Err(e) => return Err(anyhow::anyhow!("{e}")),
            }
        }
    })
    .await?;

    shutdown.cancel();
    // Leaked deliberately: `RegistrationClose` blocks uninterruptibly while a
    // connection is live, which `portal_core::shutdown` documents at length.
    std::mem::forget(session);
    std::mem::forget(reg);
    answer
}
