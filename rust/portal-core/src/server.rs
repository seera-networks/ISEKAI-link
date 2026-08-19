//! The side with the services: a QUIC stream in, a TCP connection out.

use std::collections::HashMap;
use std::net::SocketAddr;

use msquic_async::Connection;
use tokio::net::TcpStream;

use crate::frame::{read_open, write_status, Status};

/// What may be reached, and under what name.
///
/// **The initiator never names an address.** It asks for `db`; what `db` is
/// stays here. The alternative — letting the caller name a host and port — is
/// an open proxy onto whatever network this process can see, and a Grant says
/// two Endpoints may talk, not what they may reach. See `docs/portal_plan.md`
/// §4.3.
///
/// Phase 0 builds this in code. Phase 2 loads it from a file, and the type does
/// not have to change for that.
#[derive(Debug, Default, Clone)]
pub struct Catalogue(HashMap<String, SocketAddr>);

impl Catalogue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer `target` under `name`.
    pub fn with(mut self, name: &str, target: SocketAddr) -> Self {
        self.0.insert(name.to_owned(), target);
        self
    }

    fn look_up(&self, name: &str) -> Option<SocketAddr> {
        self.0.get(name).copied()
    }
}

/// Serve forwarding requests on `conn` until it ends.
///
/// Each inbound stream is one forwarded TCP connection and gets its own task,
/// so a slow target holds up nothing else.
pub async fn serve(conn: Connection, catalogue: Catalogue) -> anyhow::Result<()> {
    loop {
        let stream = match conn.accept_inbound_stream().await {
            Ok(stream) => stream,
            // The connection ending is how this loop is meant to finish.
            Err(e) => {
                tracing::debug!("no longer accepting portal streams: {e}");
                return Ok(());
            }
        };
        let catalogue = catalogue.clone();
        tokio::spawn(async move {
            if let Err(e) = forward_one(stream, catalogue).await {
                // At debug: a client that goes away mid-forward is ordinary,
                // and the interesting refusals are logged where they are made.
                tracing::debug!("a forwarded connection ended: {e:#}");
            }
        });
    }
}

async fn forward_one(mut stream: msquic_async::Stream, catalogue: Catalogue) -> anyhow::Result<()> {
    let service = read_open(&mut stream).await?;
    let Some(target) = catalogue.look_up(&service) else {
        // Said here rather than sent: the caller gets one answer for every way
        // of being refused, and the operator gets the name that was asked for.
        tracing::warn!(service = %service, "refusing a request for a service that is not offered");
        write_status(&mut stream, Status::Refused).await?;
        return Ok(());
    };

    let target_stream = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(e) => {
            // Apart from `Refused` because it says something about the far side
            // rather than about the request, and asking again is reasonable.
            tracing::warn!(service = %service, %target, "the target did not answer: {e}");
            write_status(&mut stream, Status::Unreachable).await?;
            return Ok(());
        }
    };
    write_status(&mut stream, Status::Ready).await?;

    let mut target_stream = target_stream;
    // The whole forwarder. A QUIC stream is already ordered, reliable,
    // flow-controlled bytes with an independent finish each way, which is what
    // a TCP connection is — so this is a copy rather than a protocol.
    let (from_client, to_client) =
        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await?;
    tracing::debug!(
        service = %service,
        %target,
        from_client,
        to_client,
        "a forwarded connection finished",
    );
    Ok(())
}
