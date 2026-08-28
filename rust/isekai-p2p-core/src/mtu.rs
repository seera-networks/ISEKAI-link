//! What a peer connection's MTU leaves for a datagram.
//!
//! **Its own module, and unconditionally compiled, because of who needs it.**
//! The dialling half of a peer connection is configured in `isekai-p2p`, the
//! listening half in `isekai-link-utils`, and `portal-core` sizes its
//! datagrams from the result — three crates that must agree. `transport` would
//! have been the natural home next to the outer leg's arithmetic, but it is
//! behind the `msquic` feature and these are integers.
//!
//! `docs/portal_mtu_plan.md` is the plan these came out of, and §6 is the
//! measurement.

/// The MTU a peer connection is capped at, at the IP level.
///
/// msquic clamps `MaximumMtu` up to `QUIC_DPLPMTUD_MIN_MTU`, which is this, so
/// asking for less is silently ignored — stating it keeps the code honest about
/// the cap it is applying rather than the one it wrote down.
///
/// The cap exists so an inner QUIC packet plus CONNECT-UDP encapsulation fits
/// inside the relay tunnel's HTTP datagram. `isekai_p2p_core::transport` sizes
/// the outer `MinimumMtu` to carry it and does that arithmetic there.
pub const PEER_MTU: u16 = 1248;

/// What a QUIC packet plus a DATAGRAM frame costs inside [`PEER_MTU`].
///
/// **Measured, and the source agrees term by term** (`docs/portal_mtu_plan.md`
/// §6.1). msquic's `QuicCalculateDatagramLength` subtracts
/// `QUIC_DATAGRAM_OVERHEAD(CidLength) + CXPLAT_ENCRYPTION_OVERHEAD`, which for
/// this library is:
///
/// | | |
/// | --- | --- |
/// | `MIN_SHORT_HEADER_LENGTH_V1` | 5 (a 1-byte header plus 4 for the packet number) |
/// | connection id | 9 |
/// | `DATAGRAM_FRAME_HEADER_LENGTH` | 3 |
/// | `CXPLAT_ENCRYPTION_OVERHEAD` | 16 |
///
/// **The connection id is the *peer's*, not ours.** msquic sizes a send from
/// `Path->DestCid->CID.Length` (`core/datagram.c`) — the id the far end asked
/// us to put on packets. Ours is 9, because `MsQuicLib.CidTotalLength` is
/// `CidServerIdLength + QUIC_CID_PID_LENGTH + QUIC_CID_PAYLOAD_LENGTH` and the
/// first of those is zero while load balancing is off (`core/library.c`); both
/// ends of a peer connection are this build, so 9 is what arrives.
///
/// That is an assumption, and it is worth naming because there is **no margin
/// left**: `portal_core::datagram::MAX_PAYLOAD + HEADER` is exactly
/// [`GUARANTEED_DATAGRAM`]. A peer that chose a longer id — load balancing
/// switched on at one end, a mixed rollout — would refuse every maximum-size
/// datagram in that direction rather than costing a few bytes.
///
/// It would not be silent. `Drops::refused_too_big` counts exactly this: inside
/// portal's limit, refused by the connection. A non-zero one on a healthy path
/// is the signal that this number is no longer the peer's.
pub const DATAGRAM_OVERHEAD: usize = 33;

/// IP and UDP headers msquic takes off [`PEER_MTU`] before it has a QUIC packet.
///
/// IPv6's, because the guarantee below has to hold on both and this is the
/// larger. An IPv4 connection has 20 bytes spare and they are not offered.
const IPV6_AND_UDP_HEADERS: usize = 40 + 8;

/// The largest QUIC datagram a peer connection is **guaranteed** to carry.
///
/// **A floor, not the current limit.** msquic reports its own per-connection
/// value and it can be larger — on an IPv4 path it is, by 20 bytes — but it is
/// derived from whichever path is `Paths[0]` and follows that path as it
/// changes. Something that must not lose traffic when the connection migrates
/// has to live under the worst case rather than under what it is told today.
///
/// `docs/portal_mtu_plan.md` is where that reasoning lives and where raising
/// this is planned.
pub const GUARANTEED_DATAGRAM: usize = PEER_MTU as usize - IPV6_AND_UDP_HEADERS - DATAGRAM_OVERHEAD;
