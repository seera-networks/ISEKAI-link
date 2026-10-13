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
/// Whether this build can **receive** oversize UDP datagrams on unidirectional
/// streams.
///
/// **One constant for both halves of the negotiation**, and that is the point.
/// The first attempt at this had two decisions — the opener did not ask, and
/// the answerer answered anyway — so a later release of this code carrying the
/// send side would have been told `Ready` for a [`KIND_UDP_BIG`] open, recorded
/// the capability, and opened unidirectional streams nobody here accepts. An
/// unaccepted one sits in an unbounded queue with its receive window already
/// granted (`docs/portal_oversize_udp_plan.md` §1.3).
///
/// Asking and granting are the same claim, so they read the same flag:
/// [`read_open`] refuses the kind while this is false, and `udp`'s opener does
/// not ask. Because there is one flag the two sides cannot drift apart.
///
/// **True since S2**, which is `Sessions::pump_streams` and
/// `Sessions::read_big_datagram` — the accept loop this claim is about. Sending
/// them is S3 and does not exist yet, which is why this says *receive*: a
/// forward can be told what the peer would take long before it has anything to
/// put on a stream, and advertising the half that works is what lets the other
/// end's S3 be useful the day it lands.
pub(crate) const RECEIVES_OVERSIZE_ON_STREAM: bool = true;

/// A UDP session whose opener can also **receive** oversize datagrams on
/// unidirectional streams.
///
/// **The kind is the negotiation**, and `docs/portal_oversize_udp_plan.md` §5.2
/// says why it is the kind rather than a version bump or a trailing byte: a
/// peer that does not know this refuses **that one open**, so the opener loses
/// a session rather than a forward. Raising [`VERSION`] instead would have
/// failed every open on the connection, `KIND_TCP` included.
///
/// **The stream is not reusable after the refusal**, and an earlier version of
/// this comment said it was. [`read_open`] checks the kind after the name but
/// before the session id, so a refused UDP kind leaves the session id unread —
/// **five bytes for this kind** since the options byte joined it, four for
/// [`KIND_UDP`]. The boundary `read_open`'s own comment means is the end of the
/// name, which is a frame boundary only for [`KIND_TCP`]. Nothing depends on reuse: the opener starts
/// a new stream.
const KIND_UDP_BIG: u8 = 2;
/// One oversize UDP datagram, on a unidirectional stream of its own.
///
/// **Read by [`read_big_datagram_head`] and written by nothing yet**: S2
/// receives these and S3 sends them. Being able to receive before being able
/// to send is the honest order — see [`RECEIVES_OVERSIZE_ON_STREAM`].
pub(crate) const KIND_BIG_DATAGRAM: u8 = 3;

/// Options on a [`KIND_UDP_BIG`] open, as a bit set.
///
/// **One byte on that kind's frame and no other.** [`KIND_UDP`]'s layout is in
/// 0.6.0 and cannot grow; `KIND_UDP_BIG` has never shipped, so adding to it
/// costs nobody a migration — which is why this is a byte rather than the
/// third and fourth UDP kinds a product of options would have needed.
///
/// **Unknown bits are refused, not ignored.** A byte an implementation does not
/// read is the hazard §5.1 names, and the point of an option here is that the
/// *answerer* acts on it: silently dropping one would leave an operator having
/// asked for something that quietly did not happen.
///
/// **The refusal is answered, and getting that wrong twice is why it says so
/// here.** The first version let the refusal kill the stream, which the opener
/// cannot tell from a peer that does not know the kind — so it inferred
/// `PeerOversize::NO` and the second one latched it, losing the capability for
/// the connection's life. [`Status::Unsupported`] fixed that and then cost
/// *more*: a status is sticky evidence that the kind was read, so the opener
/// kept asking the same way and every session failed, forever, carrying
/// nothing.
///
/// What it takes is both halves: an answer the opener can read, **and** the
/// opener giving the option up on receiving one
/// (`udp::Sessions::options_refused`). The option is lost, loudly, and the
/// forward is not. Adding a second bit is safe in that shape and in no other.
const OPTION_NO_RETRANS: u8 = 0x01;
const KNOWN_OPTIONS: u8 = OPTION_NO_RETRANS;

/// Bytes of header on an oversize-datagram stream: version, kind, session id.
///
/// **Six, not seven.** An [`Open`]'s head is three bytes because its third is
/// the name length; there is no name here, so copying the shape would have left
/// a reserved byte nobody reads — and a byte nobody reads is a byte two
/// implementations can disagree about.
pub const BIG_DATAGRAM_HEAD: usize = 2 + 4;

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
    /// The request was read and **cannot be served as asked** — an option on
    /// it that this build does not know.
    ///
    /// **Distinct from `Refused`, and the difference is load-bearing.** That
    /// one is about the service: no such name, wrong protocol, not yours. This
    /// one is about the *request*, and says the kind was understood.
    ///
    /// Without it the answerer could only drop the stream, which the opener
    /// cannot tell from a peer that does not know the kind at all — so
    /// `udp::Sessions` would infer that the peer takes no oversize datagrams
    /// and, on the second one, latch it for the life of the connection. **A
    /// refusal that costs the capability is worse than the option not
    /// happening**, and a status is what stops it: any status at all is already
    /// the opener's evidence that its kind was read.
    Unsupported = 3,
}

impl Status {
    fn from_byte(byte: u8) -> anyhow::Result<Self> {
        match byte {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Refused),
            2 => Ok(Self::Unreachable),
            3 => Ok(Self::Unsupported),
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
        /// `None` when the **opener** cannot receive oversize datagrams on
        /// unidirectional streams, which is what picks [`KIND_UDP`] over
        /// [`KIND_UDP_BIG`] on the wire.
        ///
        /// **It says what the opener can receive, not what it wants to send**,
        /// and one exchange settles both directions: the answerer learns from
        /// the kind it was asked with, and the opener learns from having been
        /// answered at all.
        ///
        /// Reading this is what records the peer's half — ignore it and a
        /// forward will go on dropping oversize payloads against a peer that
        /// could have taken them.
        ///
        /// `Some` carries the opener's choices for the session. An `Option`
        /// rather than two booleans because the options are meaningless
        /// without the capability, and the type is the place to say so once.
        oversize: Option<OversizeOptions>,
    },
}

/// What the opener asked for, for oversize datagrams on this session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OversizeOptions {
    /// **Neither end retransmits them**, in either direction.
    ///
    /// From the opener's `--map udp+no-retrans:`. It travels because the
    /// choice is about the conversation rather than about one end's sends: the
    /// large half of a request/response pair is usually the response, and a
    /// forward whose answers were retransmitted while its questions were not
    /// would have honoured half of what was asked for.
    ///
    /// The answerer holds it for the session's life and applies it to every
    /// reply.
    pub no_retrans: bool,
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
        Open::Udp { oversize: None, .. } => KIND_UDP,
        Open::Udp {
            oversize: Some(_), ..
        } => KIND_UDP_BIG,
    });
    bytes.push(service.len() as u8);
    bytes.extend_from_slice(service.as_bytes());
    if let Open::Udp {
        session, oversize, ..
    } = open
    {
        bytes.extend_from_slice(&session.to_be_bytes());
        // Only on the big kind, whose layout has never shipped. `KIND_UDP`'s
        // is in 0.6.0 and ends at the session id.
        if let Some(options) = oversize {
            let mut byte = 0;
            if options.no_retrans {
                byte |= OPTION_NO_RETRANS;
            }
            bytes.push(byte);
        }
    }
    // One write, so the whole request lands in one QUIC frame where it fits.
    stream
        .write_all(&bytes)
        .await
        .context("failed to send the open request")
}

/// What reading an [`Open`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Something to look up and serve.
    Open(Open),
    /// Read as far as the kind, and **not serveable as asked**.
    ///
    /// **The frame is fully consumed**, which is what makes this different from
    /// every other way [`read_open`] fails: the stream is at a boundary and the
    /// service name is known, so the opener can be answered with
    /// [`Status::Unsupported`] instead of being left to infer from a dead
    /// stream. Everything else leaves the framing in doubt, where there is
    /// nothing to say and nowhere to say it.
    NotAsAsked { service: String, detail: String },
}

/// Read what [`write_open`] wrote.
pub async fn read_open<R>(stream: &mut R) -> anyhow::Result<Request>
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
    // unknown one leaves the stream after the name rather than part-way through
    // it. It is refused either way; what this buys is that the error says what
    // was asked for.
    //
    // **Not the end of the frame for the UDP kinds**, whose session id is read
    // inside the arm below — so a caller must not plan to reuse the stream.
    match head[1] {
        KIND_TCP => Ok(Request::Open(Open::Tcp { service })),
        // **Refused exactly as an unknown kind is**, so that a peer asking
        // this of a build that cannot receive sees what it would see from a
        // 0.6.0 one. See `RECEIVES_OVERSIZE_ON_STREAM`.
        // **Not `NotAsAsked`**, deliberately: the session id is still unread,
        // so the stream is not at a boundary and this must look like the
        // unknown kind it effectively is. §5.2's fallback is what handles it.
        KIND_UDP_BIG if !RECEIVES_OVERSIZE_ON_STREAM => anyhow::bail!(
            "this build does not receive oversize datagrams on streams, \
             asked for service `{service}`"
        ),
        // **The two UDP kinds read almost the same**, and that is the property
        // making §5.2's negotiation cost one session rather than a protocol
        // version: one layout, one extra byte on the newer kind, and the same
        // request as far as the catalogue is concerned.
        //
        // They did read identically until the options byte. The test for this
        // was rewritten when that changed and this comment was not, which is
        // how a sentence outlives what it described.
        kind @ (KIND_UDP | KIND_UDP_BIG) => {
            let mut session = [0_u8; 4];
            stream
                .read_exact(&mut session)
                .await
                .context("the stream ended before the UDP session id")?;
            let oversize = if kind == KIND_UDP_BIG {
                let mut options = [0_u8; 1];
                stream
                    .read_exact(&mut options)
                    .await
                    .context("the stream ended before the oversize options")?;
                // **Answered rather than refused by silence.** The frame ends
                // here, so the opener can be told -- see `Status::Unsupported`
                // for what dropping the stream instead would cost.
                if options[0] & !KNOWN_OPTIONS != 0 {
                    return Ok(Request::NotAsAsked {
                        detail: format!("unknown oversize options {:#04x}", options[0]),
                        service,
                    });
                }
                Some(OversizeOptions {
                    no_retrans: options[0] & OPTION_NO_RETRANS != 0,
                })
            } else {
                None
            };
            Ok(Request::Open(Open::Udp {
                service,
                session: u32::from_be_bytes(session),
                oversize,
            }))
        }
        other => anyhow::bail!("unknown open kind {other} for service `{service}`"),
    }
}

/// Read the head of an oversize-datagram stream and return its session id.
///
/// The rest of the stream is the payload, and **the FIN is its length** — which
/// is why nothing here is a length prefix. See
/// `docs/portal_oversize_udp_plan.md` §2.1.
///
/// The version is here for the same reason it is on an [`Open`], and the
/// session id matches [`crate::datagram`]'s header in meaning and width so the
/// assembled payload can join the same queue. Six bytes in all — see
/// [`BIG_DATAGRAM_HEAD`], which says why not seven.
pub(crate) async fn read_big_datagram_head<R>(stream: &mut R) -> anyhow::Result<u32>
where
    R: AsyncReadExt + Unpin,
{
    let mut head = [0_u8; BIG_DATAGRAM_HEAD];
    stream
        .read_exact(&mut head)
        .await
        .context("the stream ended inside an oversize datagram's head")?;
    anyhow::ensure!(
        head[0] == VERSION,
        "unsupported portal protocol version {} on an oversize datagram",
        head[0],
    );
    // **One kind numbering, and this stream carries exactly one of them.**
    // Anything else here is a peer sending something this protocol does not
    // have.
    anyhow::ensure!(
        head[1] == KIND_BIG_DATAGRAM,
        "kind {} is not an oversize datagram",
        head[1],
    );
    Ok(u32::from_be_bytes(
        head[2..].try_into().expect("four bytes"),
    ))
}

/// Write the head [`read_big_datagram_head`] reads.
///
/// **No sender uses it yet** — S3 is the send side. It is here so both halves
/// of the format are written together, and public so a test can put a real
/// oversize datagram on the wire without hand-rolling bytes that would quietly
/// drift from this.
pub fn big_datagram_head(session: u32) -> [u8; BIG_DATAGRAM_HEAD] {
    let mut head = [0_u8; BIG_DATAGRAM_HEAD];
    head[0] = VERSION;
    head[1] = KIND_BIG_DATAGRAM;
    head[2..].copy_from_slice(&session.to_be_bytes());
    head
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
                oversize: None,
            },
        ] {
            let (mut a, mut b) = tokio::io::duplex(64);
            write_open(&mut a, &open).await.expect("write");
            assert_eq!(read_open(&mut b).await.expect("read"), Request::Open(open));
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
            oversize: None,
        };
        assert_eq!(tcp.protocol(), Protocol::Tcp);
        assert_eq!(udp.protocol(), Protocol::Udp);

        let mut wire = Vec::new();
        write_open(&mut wire, &tcp).await.expect("write");
        let mut other = Vec::new();
        write_open(&mut other, &udp).await.expect("write");
        assert_ne!(wire, other, "and they are different bytes");
    }

    /// **What the catalogue sees is identical.** The two UDP kinds differ in
    /// the kind byte, and since S5 the big one carries an options byte too —
    /// but `protocol()` and `service()` agree, which is the property §4.3
    /// needs: a UDP service must not become reachable a second way by being
    /// asked for differently.
    ///
    /// This test used to assert the frames differed in exactly one byte. That
    /// was true until the options byte, and the claim it was protecting is the
    /// one below rather than the arithmetic.
    #[tokio::test]
    async fn the_two_udp_kinds_are_the_same_request_to_the_catalogue() {
        let plain = Open::Udp {
            service: "dns".to_owned(),
            session: 7,
            oversize: None,
        };
        let big = Open::Udp {
            service: "dns".to_owned(),
            session: 7,
            oversize: Some(OversizeOptions::default()),
        };

        assert_eq!(plain.protocol(), big.protocol());
        assert_eq!(plain.service(), big.service());

        let mut a = Vec::new();
        write_open(&mut a, &plain).await.expect("write");
        let mut b = Vec::new();
        write_open(&mut b, &big).await.expect("write");
        assert_eq!((a[1], b[1]), (KIND_UDP, KIND_UDP_BIG), "the kind differs");
        assert_eq!(a[0], b[0], "the version does not");
        assert_eq!(
            a[2..],
            b[2..a.len()],
            "and everything up to the plain kind's end is the same",
        );
        assert_eq!(b.len(), a.len() + 1, "the big one adds its options byte");
    }

    /// **An unknown kind is refused after the name and before the session
    /// id**, which is less than a whole frame — so a caller must not plan to
    /// reuse the stream. Checked rather than assumed, because the comment on
    /// `read_open` used to say "frame boundary" and the arithmetic below is
    /// what showed it does not.
    #[tokio::test]
    async fn an_unknown_kind_is_refused_after_the_name_not_the_frame() {
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
        // The `[u32]` was *not* consumed -- only `KIND_UDP*` reads it -- so
        // four bytes of the frame are still there and the stream is not
        // reusable. The opener starts a new one instead.
        let read = cursor.position() as usize;
        assert_eq!(read, 3 + 3, "stopped right after the name");
    }

    /// **A build that cannot receive oversize datagrams refuses to be asked
    /// for them**, and that is the whole of the answerer's half of the gate.
    ///
    /// Granting the kind is the same claim as asking for it: a peer told
    /// `Ready` records the capability "from having been answered at all", and
    /// would then open unidirectional streams nobody here accepts. The first
    /// version of this code refused to *ask* and answered anyway, which is the
    /// same trap from the other side.
    #[tokio::test]
    async fn the_big_kind_is_refused_while_this_build_cannot_receive() {
        let open = Open::Udp {
            service: "dns".to_owned(),
            session: 7,
            oversize: Some(OversizeOptions::default()),
        };
        let mut wire = Vec::new();
        write_open(&mut wire, &open).await.expect("write");
        assert_eq!(wire[1], KIND_UDP_BIG, "it is written");

        let read = read_open(&mut std::io::Cursor::new(wire)).await;
        if RECEIVES_OVERSIZE_ON_STREAM {
            assert_eq!(
                read.expect("read"),
                Request::Open(open),
                "and read back once S2 lands",
            );
        } else {
            let err = read.expect_err("refused");
            assert!(
                err.to_string().contains("does not receive oversize"),
                "and says so: {err}",
            );
        }
    }

    /// **The options byte rides on the big kind and nowhere else.** `KIND_UDP`'s
    /// layout is in 0.6.0 and ends at the session id; this kind has never
    /// shipped, which is what makes a byte cheaper than the third and fourth
    /// UDP kinds a product of options would have needed.
    #[tokio::test]
    async fn the_oversize_options_survive_the_round_trip() {
        for no_retrans in [false, true] {
            let open = Open::Udp {
                service: "dns".to_owned(),
                session: 9,
                oversize: Some(OversizeOptions { no_retrans }),
            };
            let mut wire = Vec::new();
            write_open(&mut wire, &open).await.expect("write");
            assert_eq!(wire[1], KIND_UDP_BIG);
            // The session id and then one byte, which `KIND_UDP` does not have.
            assert_eq!(wire.len(), 3 + 3 + 4 + 1);

            if RECEIVES_OVERSIZE_ON_STREAM {
                let read = read_open(&mut std::io::Cursor::new(wire))
                    .await
                    .expect("read");
                assert_eq!(read, Request::Open(open), "no_retrans={no_retrans}");
            }
        }

        // And the plain kind is exactly as long as it was.
        let mut plain = Vec::new();
        write_open(
            &mut plain,
            &Open::Udp {
                service: "dns".to_owned(),
                session: 9,
                oversize: None,
            },
        )
        .await
        .expect("write");
        assert_eq!(plain.len(), 3 + 3 + 4, "0.6.0's layout is untouched");
    }

    /// **An option this build does not know is answerable, not fatal.** The
    /// answerer is what acts on these, so ignoring one would leave an operator
    /// having asked for something that quietly did not happen — and *dropping
    /// the stream* instead would cost the opener the whole capability, because
    /// a dead stream is how it learns that a peer does not know the kind. See
    /// [`Status::Unsupported`].
    ///
    /// **The frame being consumed is what makes answering possible**, so the
    /// arithmetic is part of the assertion.
    #[tokio::test]
    async fn an_unknown_oversize_option_can_be_answered() {
        let mut wire = vec![VERSION, KIND_UDP_BIG, 3];
        wire.extend_from_slice(b"dns");
        wire.extend_from_slice(&9_u32.to_be_bytes());
        wire.push(0x80); // nothing defines this bit
        wire.extend_from_slice(b"after"); // and the stream goes on

        if !RECEIVES_OVERSIZE_ON_STREAM {
            // The gate refuses the kind before the options are ever read, and
            // `the_big_kind_is_refused_while_this_build_cannot_receive` is what
            // covers that. Guarded like its neighbours so flipping the constant
            // back reports the gate rather than a confusing `expect`.
            return;
        }
        let mut cursor = std::io::Cursor::new(wire);
        let read = read_open(&mut cursor).await.expect("readable");
        let Request::NotAsAsked { service, detail } = read else {
            panic!("expected an answerable refusal, got {read:?}");
        };
        assert_eq!(service, "dns", "and the name is known, so it can be logged");
        assert!(
            detail.contains("unknown oversize options"),
            "and says which: {detail}",
        );
        assert_eq!(
            cursor.position() as usize,
            3 + 3 + 4 + 1,
            "the whole frame was read, so the stream is at a boundary",
        );
    }

    /// The new status is on the wire like the others, which is what lets the
    /// opener tell "understood and refused" from a stream that died.
    #[tokio::test]
    async fn the_unsupported_status_crosses() {
        let (mut a, mut b) = tokio::io::duplex(8);
        write_status(&mut a, Status::Unsupported)
            .await
            .expect("write");
        assert_eq!(
            read_status(&mut b).await.expect("read"),
            Status::Unsupported,
        );
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
            Request::Open(Open::Udp {
                service: "dns".to_owned(),
                session: 7,
                oversize: None,
            }),
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
