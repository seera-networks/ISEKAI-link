//! The side with the services: a QUIC stream in, a TCP connection out.

use std::collections::HashMap;
use std::net::SocketAddr;

use msquic_async::Connection;
use tokio::net::TcpStream;

use tokio::io::AsyncWriteExt as _;

use crate::frame::{read_open, write_status, Status};

/// How long to wait for a target to accept before answering `Unreachable`.
///
/// A target that blackholes otherwise holds the answer for as long as the
/// platform's TCP retries take -- around two minutes on Linux -- with the
/// caller waiting on a status byte the whole time. The forward is meant to fail
/// faster than the thing it forwards to.
const CONNECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

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
    /// Whether it offers nothing, which is a server with no reason to run.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many services it offers.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Offer `target` under `name`.
    ///
    /// # Panics
    ///
    /// If `name` is one [`crate::frame::write_open`] would refuse to send, which
    /// would leave an entry here that nothing could ever ask for. Loud because
    /// this is built in code; phase 2's file loader validates before it gets
    /// here, so a bad config is a message rather than a panic.
    pub fn with(mut self, name: &str, target: SocketAddr) -> Self {
        assert!(
            !name.is_empty() && name.len() <= crate::frame::MAX_NAME,
            "a service name must be 1..={} bytes, and `{name}` is {}",
            crate::frame::MAX_NAME,
            name.len(),
        );
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

/// Send `status` and finish the stream before dropping it.
///
/// **`write_status` returning does not mean the byte left.** Closing a stream
/// that was never finished aborts both directions, so the status can be reset
/// away and the caller sees "the stream ended before the status" instead of the
/// refusal the byte exists to carry.
async fn refuse(mut stream: msquic_async::Stream, status: Status) -> anyhow::Result<()> {
    write_status(&mut stream, status).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn forward_one(mut stream: msquic_async::Stream, catalogue: Catalogue) -> anyhow::Result<()> {
    let service = read_open(&mut stream).await?;
    let Some(target) = catalogue.look_up(&service) else {
        // Said here rather than sent: the caller gets one answer for every way
        // of being refused, and the operator gets the name that was asked for.
        tracing::warn!(service = %service, "refusing a request for a service that is not offered");
        return refuse(stream, Status::Refused).await;
    };

    let target_stream = match tokio::time::timeout(CONNECT_DEADLINE, TcpStream::connect(target))
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the target did not answer in time",
            ))
        }) {
        Ok(stream) => stream,
        Err(e) => {
            // Apart from `Refused` because it says something about the far side
            // rather than about the request, and asking again is reasonable.
            tracing::warn!(service = %service, %target, "the target did not answer: {e}");
            return refuse(stream, Status::Unreachable).await;
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
