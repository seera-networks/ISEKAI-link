//! The side with the local ports: a TCP accept in, a QUIC stream out.

use std::net::SocketAddr;

use msquic_async::{Connection, StreamType};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::frame::{read_status, write_open, Status};

/// Listen on `local` and forward every connection to `service` over `conn`.
///
/// Returns the address actually bound, and runs until `shutdown` fires or the
/// connection ends.
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
            tokio::spawn(async move {
                if let Err(e) = forward_one(conn, tcp, &service).await {
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
    write_open(&mut stream, service).await?;
    // Waited for before any application bytes move. A refusal that arrived
    // after the local application had already written would leave it believing
    // it had spoken to the service.
    match read_status(&mut stream).await? {
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
