//! The side with the local ports: a TCP accept in, a QUIC stream out.
//!
//! The UDP half of the same job is [`crate::udp`], which is a different shape —
//! sessions rather than connections, and both of its ends in one module for the
//! reason its header gives.

use std::net::SocketAddr;

use msquic_async::{Connection, StreamType};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::frame::{read_status, write_open, Open, Status};

/// How long to wait for the peer's answer to an open request.
///
/// Longer than the server's own connect deadline, so a target that is merely
/// slow is reported as unreachable by the side that knows why, rather than as a
/// timeout by the side that does not.
///
/// Shared with [`crate::udp`]: it is a property of how long the far side may
/// take to answer, which does not depend on what is being opened.
pub(crate) const STATUS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// Listen on `local` and forward every connection to `service` over `conn`.
///
/// Returns the address actually bound, and accepts until `shutdown` fires.
///
/// **It does not watch the connection.** When the peer goes away the port stays
/// bound and every accept becomes a forward that fails immediately, so an
/// application gets a successful connect and a silent close rather than
/// connection-refused. Phase 1 is where that is fixed, because that is where
/// the session has a lifecycle to hang it on -- here there is nothing that
/// knows the difference between "the peer is gone" and "the peer has not bound
/// its leg yet".
///
/// **The mapping is this side's business.** Which local port stands for which
/// service is a fact about this machine, and nothing about it is sent: the far
/// side is only ever told the name.
pub async fn forward(
    conn: Connection,
    local: SocketAddr,
    service: String,
    shutdown: CancellationToken,
) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(local).await?;
    let bound = listener.local_addr()?;
    tracing::info!(%bound, service = %service, "forwarding a local port");
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            let (tcp, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("stopped accepting on the forwarded port: {e}");
                    return;
                }
            };
            let conn = conn.clone();
            let service = service.clone();
            let forwarding = shutdown.clone();
            tokio::spawn(async move {
                // Cancelling reaches the forwards, not only the accept: they
                // each hold a connection and a stream, and a caller that has
                // cancelled expects those to go rather than to linger until the
                // far side closes.
                let forwarded = tokio::select! {
                    _ = forwarding.cancelled() => return,
                    forwarded = forward_one(conn, tcp, &service) => forwarded,
                };
                if let Err(e) = forwarded {
                    tracing::warn!(%peer, service = %service, "the forward failed: {e:#}");
                }
            });
        }
    });
    Ok(bound)
}

async fn forward_one(conn: Connection, mut tcp: TcpStream, service: &str) -> anyhow::Result<()> {
    let mut stream = conn
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await?;
    write_open(
        &mut stream,
        &Open::Tcp {
            service: service.to_owned(),
        },
    )
    .await?;
    // Waited for before any application bytes move. A refusal that arrived
    // after the local application had already written would leave it believing
    // it had spoken to the service.
    //
    // On a deadline, because the far side's own is longer than nothing: it may
    // be waiting on a target that never answers, and the local application is
    // waiting on this.
    let status = tokio::time::timeout(STATUS_DEADLINE, read_status(&mut stream))
        .await
        .map_err(|_| anyhow::anyhow!("`{service}` did not answer the open request in time"))??;
    match status {
        Status::Ready => {}
        // Dropping `tcp` here is the point: the local application sees the
        // connection close rather than an empty one that stays open, which is
        // what it would get if this were reported only in a log.
        Status::Refused => anyhow::bail!("the peer does not offer `{service}`"),
        Status::Unreachable => anyhow::bail!("the peer could not reach `{service}`"),
    }

    let (from_local, to_local) = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await?;
    tracing::debug!(
        service,
        from_local,
        to_local,
        "a forwarded connection finished"
    );
    Ok(())
}
