//! A loopback QUIC connection, so phase 0 can be exercised without a proxy.
//!
//! **This is scaffolding and it is the first thing phase 1 deletes.** The real
//! connection is an `isekai_p2p` session — dialled across the peer's bind gap,
//! pinned to the key the peer signed for, checked against the name and against
//! the Endpoint pairing recorded it. None of that is here, and none of it
//! should be reimplemented here: plan §4.4 is about extracting it from
//! `camera-core` rather than growing a second copy.
//!
//! What is here is the least that lets two halves of this crate talk: a dev
//! certificate, a listener, and a client that does not validate it. Loopback,
//! in one process, in tests.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context as _;
use msquic_async::{msquic, Connection, Listener, Registration};

use crate::PORTAL_ALPN;

/// Bind a portal listener on `addr` with a throwaway certificate.
pub fn bind(
    reg: Option<Arc<Registration>>,
    addr: SocketAddr,
) -> anyhow::Result<(Arc<Registration>, Listener, SocketAddr)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("failed to generate the spike key")?;
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .context("failed to build the spike certificate")?;
    let certificate = params.self_signed(&key).context("failed to self-sign")?;

    let (reg, listener) = isekai_link_utils::make_msquic_async_listener(
        reg,
        PORTAL_ALPN,
        Some(addr),
        &certificate.pem(),
        &key.serialize_pem(),
        None,
    )?;
    let bound = listener
        .local_addr()
        .context("the spike listener has no address")?;
    Ok((reg, listener, bound))
}

/// A connection, and the configuration it is not allowed to outlive.
///
/// **msquic shuts a connection down when the `Configuration` it was started
/// with is dropped**, and the symptom is not a message about configurations —
/// it is `connection shutdown by local` arriving milliseconds after a
/// handshake that plainly succeeded, followed by a `RegistrationClose` that
/// blocks forever on the handle left behind.
///
/// `camera-core` never meets this because its config is a local in the same
/// function as the whole session. Anything that hands a connection back to a
/// caller has to hand this back with it.
pub struct SpikeConnection {
    pub connection: Connection,
    _config: msquic::Configuration,
}

/// Dial a portal listener on loopback.
///
/// Validation is off, which is the whole reason this is not the real
/// transport: the certificate above is self-signed and nothing checks who is
/// on the other end.
pub async fn dial(reg: &Arc<Registration>, port: u16) -> anyhow::Result<SpikeConnection> {
    let alpn = [msquic::BufferRef::from(PORTAL_ALPN)];
    let config = reg.open_configuration(
        &alpn,
        Some(&msquic::Settings::new().set_IdleTimeoutMs(30_000)),
    )?;
    let credential = msquic::CredentialConfig::new_client()
        .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    config.load_credential(&credential)?;

    let conn = Connection::new(reg)?;
    // **Pinned, not resolved.** The listener is on `127.0.0.1` and `localhost`
    // is only the TLS name; left to resolve it, msquic can pick `::1` and the
    // handshake then goes nowhere until the idle timeout. `camera-core` pins
    // the same way for the same reason, and its comment records what loopback
    // names cost on mobile resolvers besides.
    conn.set_remote_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .map_err(|e| anyhow::anyhow!("could not pin the spike address: {e}"))?;
    // **On a deadline.** A handshake that goes nowhere -- the wrong address, an
    // ALPN neither side offers, a listener that never accepted -- otherwise
    // waits on the idle timeout with nothing to say, and a caller with no
    // deadline of its own waits with it. Loopback in one process either answers
    // immediately or is not going to.
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        conn.start(&config, "localhost", port),
    )
    .await
    .context("the spike handshake did not complete within ten seconds")?
    .context("failed to open the spike connection")?;
    Ok(SpikeConnection {
        connection: conn,
        _config: config,
    })
}
