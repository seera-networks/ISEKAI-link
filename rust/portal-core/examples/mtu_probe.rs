//! What the inner peer connection will actually carry, measured rather than
//! derived (`docs/portal_mtu_plan.md` §6).
//!
//! **This settled the plan's provisional 42-byte overhead at 33**, which moved
//! contract A from 1154 to 1163. That is done; what it is for now is checking
//! that the constants still describe the connection — run it after touching
//! `PEER_MTU`, `DATAGRAM_OVERHEAD`, or anything in msquic that changes a
//! connection id, and it will say whether `MAX_PAYLOAD` still agrees.
//!
//!   cargo run -p portal-core --example mtu_probe
//!
//! Nothing here is a test. It stands a loopback connection up with the same
//! `peer::client_config` production uses and reports what msquic says about it.
//! The unit test in `datagram` pins the arithmetic; this is what checks the
//! arithmetic against a live connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use msquic_async::{msquic, ConnectionEvent, Registration};
use portal_core::datagram::{HEADER, MAX_PAYLOAD};
use portal_core::transport;
use tokio_util::sync::CancellationToken;

/// Taken from the crate that sets it, so this cannot drift from what is
/// actually configured — which is the whole failure mode it exists to catch.
const MAXIMUM_MTU: usize = isekai_p2p::peer::PEER_MTU as usize;

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
    match MAX_PAYLOAD as i64 - worst as i64 {
        0 => println!("  MAX_PAYLOAD is {MAX_PAYLOAD}, which agrees"),
        over if over > 0 => {
            println!("  MAX_PAYLOAD is {MAX_PAYLOAD}, which is {over} too large");
            println!(
                "  a payload between {} and {MAX_PAYLOAD} is accepted here and refused \
                 by an IPv6 connection",
                worst + 1
            );
        }
        under => println!(
            "  MAX_PAYLOAD is {MAX_PAYLOAD}, {} under the guarantee -- bytes left unused",
            -under
        ),
    }
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
