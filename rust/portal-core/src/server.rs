//! The side with the services: a QUIC stream in, a TCP connection out.
//!
//! And since phase 3b, a stream in and a *UDP session* out — the catalogue
//! lookup and the refusal are the same for both, so they are made here, and
//! [`crate::udp`] takes it from the status byte onwards.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use msquic_async::Connection;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use tokio::io::AsyncWriteExt as _;

use crate::frame::{read_open, write_status, Open, Status};
use crate::udp::Sessions;

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
/// Built from a file since phase 2 — see [`crate::config`]. Still buildable in
/// code, which is what the tests do.
#[derive(Debug, Default, Clone)]
pub struct Catalogue(HashMap<String, Service>);

/// What a service speaks.
///
/// Carried per service rather than assumed, because asking for a UDP service
/// over a TCP stream has to be refused — and refused *identically* to asking
/// for a name that does not exist. See [`Catalogue::look_up`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct Service {
    protocol: Protocol,
    target: SocketAddr,
}

/// What the catalogue says about a name, for the operator's log.
///
/// **The wire does not carry this distinction** — every arm but `Found` is one
/// [`Status::Refused`], because telling them apart would let a caller map the
/// catalogue by asking (plan §4.3). The operator gets the reason; the caller
/// gets a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Found(SocketAddr),
    /// The name is offered, over another protocol.
    WrongProtocol(Protocol),
    /// No such name.
    Unknown,
}

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
    /// this is built in code; [`crate::config`] validates before it gets here,
    /// so a bad file is a message rather than a panic.
    pub fn with(mut self, name: &str, protocol: Protocol, target: SocketAddr) -> Self {
        assert!(
            !name.is_empty() && name.len() <= crate::frame::MAX_NAME,
            "a service name must be 1..={} bytes, and `{name}` is {}",
            crate::frame::MAX_NAME,
            name.len(),
        );
        self.0.insert(name.to_owned(), Service { protocol, target });
        self
    }

    /// [`with`](Self::with) for a name that came from outside the program.
    ///
    /// The assertion above is right for a catalogue written in code, where a
    /// bad name is a bug. It is wrong for one read out of a file, where a bad
    /// name is a typo and deserves a message rather than a panic.
    pub fn try_with(
        self,
        name: &str,
        protocol: Protocol,
        target: SocketAddr,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !name.is_empty() && name.len() <= crate::frame::MAX_NAME,
            "a service name must be 1..={} bytes, and `{name}` is {}",
            crate::frame::MAX_NAME,
            name.len(),
        );
        Ok(self.with(name, protocol, target))
    }

    /// What is offered under `name` over `protocol`.
    ///
    /// Takes the protocol rather than leaving the caller to compare, so that a
    /// name offered over the other one cannot be reached by accident — and so
    /// that both ways of missing come back through one function, which is what
    /// keeps their answers on the wire identical.
    pub fn look_up(&self, name: &str, protocol: Protocol) -> Lookup {
        match self.0.get(name) {
            Some(service) if service.protocol == protocol => Lookup::Found(service.target),
            Some(service) => Lookup::WrongProtocol(service.protocol),
            None => Lookup::Unknown,
        }
    }
}

/// Serve forwarding requests on `conn` until it ends or `shutdown` fires.
///
/// Each inbound stream is one forward — a TCP connection or a UDP session — and
/// gets its own task, so a slow target holds up nothing else.
///
/// **`shutdown` is not only tidiness.** The datagram pump and every session task
/// hold a `Connection` clone, and a registration dropped while any of those is
/// live blocks in `RegistrationClose` with nothing to say; cancelling is what
/// lets them go before the wait starts.
pub async fn serve(
    conn: Connection,
    catalogue: Catalogue,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    // One per connection, before the first stream is accepted: msquic-async has
    // a single datagram queue per connection, so this is the only thing that may
    // read it. [`crate::udp`] says more.
    let sessions = Sessions::start(conn.clone(), shutdown.clone());
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            accepted = conn.accept_inbound_stream() => accepted,
        };
        let stream = match accepted {
            Ok(stream) => stream,
            // The connection ending is how this loop is meant to finish.
            Err(e) => {
                tracing::debug!("no longer accepting portal streams: {e}");
                return Ok(());
            }
        };
        let catalogue = catalogue.clone();
        let sessions = Arc::clone(&sessions);
        let forwarding = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = forward_one(stream, catalogue, sessions, forwarding).await {
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
pub(crate) async fn refuse(mut stream: msquic_async::Stream, status: Status) -> anyhow::Result<()> {
    write_status(&mut stream, status).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn forward_one(
    mut stream: msquic_async::Stream,
    catalogue: Catalogue,
    sessions: Arc<Sessions>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let open = read_open(&mut stream).await?;
    let service = open.service().to_owned();
    // **The lookup is protocol-aware and both kinds come through it**, which is
    // what keeps a UDP service unreachable from a TCP request and the other way
    // round. Before 3b this argument was the constant `Tcp` because a stream was
    // the only way to ask for anything; now the request says which.
    let target = match catalogue.look_up(&service, open.protocol()) {
        Lookup::Found(target) => target,
        // Said here rather than sent: the caller gets one answer for every way
        // of being refused, and the operator gets the name and the reason.
        Lookup::WrongProtocol(protocol) => {
            // `?service`, not `%service`: the name is whatever the peer sent
            // -- any UTF-8, newlines and terminal escapes included -- and this
            // is the log the operator reads to tell the two refusals apart. A
            // name that can forge a line in it is a name that can lie about
            // which refusal happened. `Debug` on a `&str` escapes it.
            tracing::warn!(
                ?service,
                asked_for = %open.protocol(),
                offered_as = %protocol,
                "refusing a request for a service offered over another protocol",
            );
            return refuse(stream, Status::Refused).await;
        }
        Lookup::Unknown => {
            tracing::warn!(
                ?service,
                asked_for = %open.protocol(),
                "refusing a request for a service that is not offered"
            );
            return refuse(stream, Status::Refused).await;
        }
    };

    let session = match open {
        Open::Tcp { .. } => return forward_tcp(stream, &service, target).await,
        Open::Udp { session, .. } => session,
    };
    // From here the stream carries no bytes: it is the session's lifetime
    // handle and the payloads are datagrams.
    crate::udp::serve(sessions, session, &service, target, stream, shutdown).await
}

/// One forwarded TCP connection, from the status byte to the last byte copied.
async fn forward_tcp(
    mut stream: msquic_async::Stream,
    service: &str,
    target: SocketAddr,
) -> anyhow::Result<()> {
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
            tracing::warn!(service, %target, "the target did not answer: {e}");
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
        service,
        %target,
        from_client,
        to_client,
        "a forwarded connection finished",
    );
    Ok(())
}
