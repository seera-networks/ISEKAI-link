//! What the two ends say to each other before the bytes start.
//!
//! One exchange per stream, at the head of it, and then the stream is the
//! forwarded connection and nothing else — no length prefixes, no keepalives,
//! no framing of any kind. The QUIC stream already carries ordered bytes with
//! an independent finish in each direction, which is what a TCP connection is;
//! wrapping that in a second framing layer would only add a way for the two to
//! disagree.
//!
//! ```text
//!  client → server   [ 2 ][ kind ][ len ][ service name ]           kind 0, TCP
//!  client → server   [ 2 ][ kind ][ len ][ service name ][ u32 ]    kind 1, UDP
//!  server → client   [ status ]
//!  then               raw bytes, both ways      (TCP)
//!  or                 datagrams carrying the u32 (UDP), and the stream stays
//!                     open as the session's lifetime handle
//! ```
//!
//! **The reply is not decoration.** Without it a refused service looks like a
//! target that accepted and immediately hung up, so the local application sees
//! an empty successful connection and reports nothing useful. One byte tells
//! the client to fail the accept instead.
//!
//! # Why the kind byte is here rather than inferred
//!
//! The server has to look a name up *under a protocol*, because `dns` offered
//! over UDP must not be reachable by a TCP request and vice versa — that is the
//! §4.3 property [`crate::server::Catalogue::look_up`] exists to keep. Before
//! phase 3b the server could assume TCP, since a stream was the only way to ask
//! for anything. Now a stream opens both, so which one it is has to be said.
//!
//! The UDP session id rides here for the reason [`crate::datagram`] gives: the
//! datagram header is an id and nothing else, so the binding from id to service
//! is made once, on the stream that opened the session.

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::server::Protocol;

/// The only version this speaks.
///
/// **Two, because phase 3b changed the open frame** — the kind byte above. One
/// spoke the same first two bytes with different meanings, which is the one
/// mismatch worth spending a number to make loud: a v1 client's `[1][len]` would
/// otherwise read here as a kind byte and then a length taken from the first
/// letter of a service name. Nothing has ever shipped that speaks 1, so this
/// costs nobody a migration and buys a message instead of a stall.
const VERSION: u8 = 2;

/// What a stream is opening, on the wire.
///
/// **One numbering for every stream this protocol opens**, the unidirectional
/// ones included. A kind byte that meant one thing on a bidirectional stream
/// and another on a unidirectional one would be a byte whose meaning depends on
/// how you arrived at it, which is the kind of thing [`VERSION`] exists to stop
/// happening by accident.
const KIND_TCP: u8 = 0;
const KIND_UDP: u8 = 1;
/// A UDP session whose opener can also **receive** oversize datagrams on
/// unidirectional streams.
///
/// **The kind is the negotiation**, and `docs/portal_oversize_udp_plan.md` §5.2
/// says why it is the kind rather than a version bump or a trailing byte: a
/// peer that does not know this refuses the one open and leaves the stream at a
/// frame boundary (see [`read_open`]), so the opener can ask again as
/// [`KIND_UDP`] and lose a round trip rather than a forward. Raising [`VERSION`]
/// instead would have failed every open on the connection, `KIND_TCP` included.
const KIND_UDP_BIG: u8 = 2;
/// One oversize UDP datagram, on a unidirectional stream of its own.
///
/// Defined here with the others and **not yet written by anything**: the
/// carriage is phase S2/S3 of the plan. It is here now so that the numbering is
/// settled before two things need it.
#[allow(dead_code)]
pub(crate) const KIND_BIG_DATAGRAM: u8 = 3;

/// The longest a service name may be. Names are configuration, not user input,
/// and a bound here means the read below cannot be made to allocate.
pub const MAX_NAME: usize = 64;

/// What the server thinks of the `Open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// The target accepted; the stream is the connection from here.
    Ready = 0,
    /// **Deliberately one answer for several questions**: no such service, a
    /// service of the wrong protocol, one the caller may not reach. Telling
    /// them apart would let a caller map the catalogue by asking.
    Refused = 1,
    /// The service exists and its target did not answer. Separate from
    /// `Refused` because it says something about the far side rather than
    /// about the request, and retrying is reasonable.
    ///
    /// **This is the one thing probing can learn**, and the trade is
    /// deliberate: a peer that gets this for `db` knows `db` is offered over
    /// TCP. What stays hidden is which *refused* names exist under another
    /// protocol — plan §4.3 states the boundary.
    Unreachable = 2,
}

impl Status {
    fn from_byte(byte: u8) -> anyhow::Result<Self> {
        match byte {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Refused),
            2 => Ok(Self::Unreachable),
            other => anyhow::bail!("unknown status {other} from the portal server"),
        }
    }
}

/// What a stream is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Open {
    /// One forwarded TCP connection; the stream is that connection.
    Tcp { service: String },
    /// One UDP session. The stream carries no bytes after this — it is the
    /// session's lifetime handle, and finishing it ends the session — while the
    /// payloads travel as datagrams tagged with `session`.
    Udp {
        service: String,
        session: u32,
        /// Whether the **opener** can receive oversize datagrams on
        /// unidirectional streams, which is what picks [`KIND_UDP_BIG`] over
        /// [`KIND_UDP`] on the wire.
        ///
        /// **It says what the opener can receive, not what it wants to send**,
        /// and one exchange settles both directions: the answerer learns from
        /// the kind it was asked with, and the opener learns from having been
        /// answered at all.
        ///
        /// Reading this is what records the peer's half — ignore it and a
        /// forward will go on dropping oversize payloads against a peer that
        /// could have taken them.
        oversize_on_stream: bool,
    },
}

impl Open {
    /// The name being asked for.
    pub fn service(&self) -> &str {
        match self {
            Self::Tcp { service } | Self::Udp { service, .. } => service,
        }
    }

    /// Which protocol the catalogue must offer it under.
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Tcp { .. } => Protocol::Tcp,
            Self::Udp { .. } => Protocol::Udp,
        }
    }
}

/// Ask for a service on `stream`.
pub async fn write_open<W>(stream: &mut W, open: &Open) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let service = open.service();
    anyhow::ensure!(
        !service.is_empty() && service.len() <= MAX_NAME,
        "a service name must be 1..={MAX_NAME} bytes, not {}",
        service.len(),
    );
    let mut bytes = Vec::with_capacity(3 + service.len() + 4);
    bytes.push(VERSION);
    bytes.push(match open {
        Open::Tcp { .. } => KIND_TCP,
        Open::Udp {
            oversize_on_stream: false,
            ..
        } => KIND_UDP,
        Open::Udp {
            oversize_on_stream: true,
            ..
        } => KIND_UDP_BIG,
    });
    bytes.push(service.len() as u8);
    bytes.extend_from_slice(service.as_bytes());
    if let Open::Udp { session, .. } = open {
        bytes.extend_from_slice(&session.to_be_bytes());
    }
    // One write, so the whole request lands in one QUIC frame where it fits.
    stream
        .write_all(&bytes)
        .await
        .context("failed to send the open request")
}

/// Read what [`write_open`] wrote.
pub async fn read_open<R>(stream: &mut R) -> anyhow::Result<Open>
where
    R: AsyncReadExt + Unpin,
{
    let mut head = [0_u8; 3];
    stream
        .read_exact(&mut head)
        .await
        .context("the stream ended before the open request")?;
    anyhow::ensure!(
        head[0] == VERSION,
        "unsupported portal protocol version {}",
        head[0],
    );
    let len = usize::from(head[2]);
    anyhow::ensure!(
        len > 0 && len <= MAX_NAME,
        "a service name of {len} bytes is out of range",
    );
    let mut name = vec![0_u8; len];
    stream
        .read_exact(&mut name)
        .await
        .context("the stream ended inside the service name")?;
    let service = String::from_utf8(name).context("the service name is not UTF-8")?;
    // The kind is checked after the name is read rather than before, so an
    // unknown one leaves the stream at a frame boundary. It is refused either
    // way; what this buys is that the error says what was asked for.
    match head[1] {
        KIND_TCP => Ok(Open::Tcp { service }),
        // **The two UDP kinds read the same**, which is the property that makes
        // §5.2's negotiation cost one round trip instead of a protocol version:
        // the only difference is what the kind says about the opener.
        kind @ (KIND_UDP | KIND_UDP_BIG) => {
            let mut session = [0_u8; 4];
            stream
                .read_exact(&mut session)
                .await
                .context("the stream ended before the UDP session id")?;
            Ok(Open::Udp {
                service,
                session: u32::from_be_bytes(session),
                oversize_on_stream: kind == KIND_UDP_BIG,
            })
        }
        other => anyhow::bail!("unknown open kind {other} for service `{service}`"),
    }
}

/// Answer an open request.
pub async fn write_status<W>(stream: &mut W, status: Status) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    stream
        .write_all(&[status as u8])
        .await
        .context("failed to send the status")
}

/// Read the answer.
pub async fn read_status<R>(stream: &mut R) -> anyhow::Result<Status>
where
    R: AsyncReadExt + Unpin,
{
    let mut byte = [0_u8; 1];
    stream
        .read_exact(&mut byte)
        .await
        .context("the stream ended before the status")?;
    Status::from_byte(byte[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ordinary round trip, over something that is not a QUIC stream —
    /// which is the point of taking `AsyncRead`/`AsyncWrite` rather than the
    /// concrete type.
    #[tokio::test]
    async fn an_open_survives_the_round_trip() {
        for open in [
            Open::Tcp {
                service: "db".to_owned(),
            },
            Open::Udp {
                service: "dns".to_owned(),
                session: 0xdead_beef,
                oversize_on_stream: false,
            },
            Open::Udp {
                service: "dns".to_owned(),
                session: 0xdead_beef,
                oversize_on_stream: true,
            },
        ] {
            let (mut a, mut b) = tokio::io::duplex(64);
            write_open(&mut a, &open).await.expect("write");
            assert_eq!(read_open(&mut b).await.expect("read"), open);
        }
    }

    /// **The same name under the two kinds is two different requests.** The
    /// server looks a name up under a protocol, so a kind byte that failed to
    /// cross would silently turn a UDP request into a TCP one — reaching a
    /// service the catalogue offers under the other protocol, which is exactly
    /// what §4.3 says must not be reachable.
    #[tokio::test]
    async fn the_kind_is_what_distinguishes_two_opens_for_one_name() {
        let tcp = Open::Tcp {
            service: "dns".to_owned(),
        };
        let udp = Open::Udp {
            service: "dns".to_owned(),
            session: 1,
            oversize_on_stream: false,
        };
        assert_eq!(tcp.protocol(), Protocol::Tcp);
        assert_eq!(udp.protocol(), Protocol::Udp);

        let mut wire = Vec::new();
        write_open(&mut wire, &tcp).await.expect("write");
        let mut other = Vec::new();
        write_open(&mut other, &udp).await.expect("write");
        assert_ne!(wire, other, "and they are different bytes");
    }

    /// **The capability rides on the kind byte and nothing else.** Both UDP
    /// kinds look the same under the catalogue and differ in one byte, which is
    /// what lets a peer that does not know the second one refuse that open
    /// alone.
    #[tokio::test]
    async fn the_two_udp_kinds_differ_in_one_byte_and_agree_on_everything_else() {
        let plain = Open::Udp {
            service: "dns".to_owned(),
            session: 7,
            oversize_on_stream: false,
        };
        let big = Open::Udp {
            service: "dns".to_owned(),
            session: 7,
            oversize_on_stream: true,
        };

        // The same protocol, so the catalogue cannot tell them apart -- a UDP
        // service must not become reachable a second way by asking differently.
        assert_eq!(plain.protocol(), big.protocol());
        assert_eq!(plain.service(), big.service());

        let mut a = Vec::new();
        write_open(&mut a, &plain).await.expect("write");
        let mut b = Vec::new();
        write_open(&mut b, &big).await.expect("write");
        assert_eq!(a.len(), b.len());
        assert_eq!(a[0], b[0], "the same version");
        assert_eq!(a[2..], b[2..], "and the same everything after the kind");
        assert_eq!((a[1], b[1]), (KIND_UDP, KIND_UDP_BIG));
    }

    /// **An unknown kind leaves the stream at a frame boundary**, which is what
    /// `read_open`'s own comment promises and what §5.2 of the plan builds the
    /// fallback on. Checked rather than assumed, because the fallback is only
    /// cheap if the refusal is this tidy.
    #[tokio::test]
    async fn an_unknown_kind_is_refused_after_the_frame_is_consumed() {
        let mut wire = Vec::new();
        wire.push(VERSION);
        wire.push(KIND_BIG_DATAGRAM); // not an `Open` kind at all
        wire.push(3);
        wire.extend_from_slice(b"dns");
        wire.extend_from_slice(&7_u32.to_be_bytes());
        // Something that follows the frame, standing in for the next thing on a
        // stream that is reused rather than abandoned.
        wire.extend_from_slice(b"after");

        let mut cursor = std::io::Cursor::new(wire);
        let err = read_open(&mut cursor).await.expect_err("refused");
        assert!(
            err.to_string().contains("unknown open kind"),
            "says what was asked for: {err}",
        );
        // The `[u32]` was *not* consumed -- only `KIND_UDP*` reads it -- so the
        // boundary the comment means is the end of the name.
        let read = cursor.position() as usize;
        assert_eq!(read, 3 + 3, "stopped right after the name");
    }

    /// A name arriving in pieces is the normal case on a real stream, and
    /// `read_exact` is what makes it not a bug.
    #[tokio::test]
    async fn a_split_read_still_arrives() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            a.write_all(&[VERSION, KIND_UDP]).await.expect("head");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            a.write_all(&[3]).await.expect("len");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            a.write_all(b"dns").await.expect("name");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            a.write_all(&7_u32.to_be_bytes()).await.expect("session");
        });
        assert_eq!(
            read_open(&mut b).await.expect("read"),
            Open::Udp {
                service: "dns".to_owned(),
                session: 7,
                oversize_on_stream: false,
            },
        );
    }

    /// A length byte can say 255 and the sender is not to be trusted about it.
    #[tokio::test]
    async fn an_oversized_name_is_refused_without_reading_it() {
        let (mut a, mut b) = tokio::io::duplex(512);
        a.write_all(&[VERSION, KIND_TCP, 255]).await.expect("head");
        assert!(read_open(&mut b).await.is_err());
    }

    /// A version this does not speak is an error, not a guess — and version 1
    /// is the one that will actually be met, since its bytes parse as far as
    /// the length before going wrong.
    #[tokio::test]
    async fn another_version_is_refused() {
        for version in [1_u8, 3] {
            let (mut a, mut b) = tokio::io::duplex(64);
            a.write_all(&[version, 2]).await.expect("head");
            a.write_all(b"db").await.expect("name");
            let err = format!("{:#}", read_open(&mut b).await.expect_err("must not read"));
            assert!(err.contains("version"), "says: {err}");
        }
    }

    /// A kind this does not know is refused rather than guessed at, and the
    /// error names the service so an operator can see what was asked for.
    #[tokio::test]
    async fn an_unknown_kind_is_refused() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[VERSION, 9, 2]).await.expect("head");
        a.write_all(b"db").await.expect("name");
        let err = format!("{:#}", read_open(&mut b).await.expect_err("must not read"));
        assert!(err.contains("kind 9") && err.contains("db"), "says: {err}");
    }

    /// Every status the server can send has to survive the trip; a byte it
    /// cannot is an error rather than a silent `Ready`.
    #[tokio::test]
    async fn statuses_round_trip_and_unknown_ones_do_not() {
        for status in [Status::Ready, Status::Refused, Status::Unreachable] {
            let (mut a, mut b) = tokio::io::duplex(8);
            write_status(&mut a, status).await.expect("write");
            assert_eq!(read_status(&mut b).await.expect("read"), status);
        }
        let (mut a, mut b) = tokio::io::duplex(8);
        a.write_all(&[9]).await.expect("write");
        assert!(read_status(&mut b).await.is_err());
    }

    /// An empty name would read as a zero-length string on the far side and
    /// then fail to match anything, which is a worse error than this one.
    #[tokio::test]
    async fn an_empty_name_is_not_sent() {
        let (mut a, _b) = tokio::io::duplex(64);
        assert!(write_open(
            &mut a,
            &Open::Tcp {
                service: String::new()
            }
        )
        .await
        .is_err());
    }
}
