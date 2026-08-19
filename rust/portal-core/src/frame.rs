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
//!  client → server   [ 1 ][ len ][ service name ]
//!  server → client   [ status ]
//!  then               raw bytes, both ways
//! ```
//!
//! **The reply is not decoration.** Without it a refused service looks like a
//! target that accepted and immediately hung up, so the local application sees
//! an empty successful connection and reports nothing useful. One byte tells
//! the client to fail the accept instead.

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The only version this speaks.
const VERSION: u8 = 1;

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

/// Ask for `service` on `stream`.
pub async fn write_open<W>(stream: &mut W, service: &str) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    anyhow::ensure!(
        !service.is_empty() && service.len() <= MAX_NAME,
        "a service name must be 1..={MAX_NAME} bytes, not {}",
        service.len(),
    );
    let mut open = Vec::with_capacity(2 + service.len());
    open.push(VERSION);
    open.push(service.len() as u8);
    open.extend_from_slice(service.as_bytes());
    // One write, so the whole request lands in one QUIC frame where it fits.
    stream
        .write_all(&open)
        .await
        .context("failed to send the open request")
}

/// Read what [`write_open`] wrote.
pub async fn read_open<R>(stream: &mut R) -> anyhow::Result<String>
where
    R: AsyncReadExt + Unpin,
{
    let mut head = [0_u8; 2];
    stream
        .read_exact(&mut head)
        .await
        .context("the stream ended before the open request")?;
    anyhow::ensure!(
        head[0] == VERSION,
        "unsupported portal protocol version {}",
        head[0],
    );
    let len = usize::from(head[1]);
    anyhow::ensure!(
        len > 0 && len <= MAX_NAME,
        "a service name of {len} bytes is out of range",
    );
    let mut name = vec![0_u8; len];
    stream
        .read_exact(&mut name)
        .await
        .context("the stream ended inside the service name")?;
    String::from_utf8(name).context("the service name is not UTF-8")
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
        let (mut a, mut b) = tokio::io::duplex(64);
        write_open(&mut a, "db").await.expect("write");
        assert_eq!(read_open(&mut b).await.expect("read"), "db");
    }

    /// A name arriving in pieces is the normal case on a real stream, and
    /// `read_exact` is what makes it not a bug.
    #[tokio::test]
    async fn a_split_read_still_arrives() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            a.write_all(&[1, 2]).await.expect("head");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            a.write_all(b"db").await.expect("name");
        });
        assert_eq!(read_open(&mut b).await.expect("read"), "db");
    }

    /// A length byte can say 255 and the sender is not to be trusted about it.
    #[tokio::test]
    async fn an_oversized_name_is_refused_without_reading_it() {
        let (mut a, mut b) = tokio::io::duplex(512);
        a.write_all(&[1, 255]).await.expect("head");
        assert!(read_open(&mut b).await.is_err());
    }

    /// A version this does not speak is an error, not a guess.
    #[tokio::test]
    async fn another_version_is_refused() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[2, 2]).await.expect("head");
        a.write_all(b"db").await.expect("name");
        assert!(read_open(&mut b).await.is_err());
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
        assert!(write_open(&mut a, "").await.is_err());
    }
}
