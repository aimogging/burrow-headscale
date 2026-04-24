//! Framed stdio protocol for `ShellMode::Interactive`.
//!
//! After the client receives `ServerResp::ShellReady` on the control
//! flow, both sides switch into this protocol for the session
//! lifetime. The framing is simple: one byte tag + 4-byte big-endian
//! payload length + payload bytes.
//!
//! ```text
//! | u8 tag | u32 be len | payload (len bytes) |
//! ```
//!
//! Frames are small (typical keystroke data ≤ a few KiB), so frame
//! boundaries also serve as natural flush points — no nagle-style
//! batching is done here; the kernel's TCP nagle disabled via
//! `set_nodelay` is sufficient for interactive latency.
//!
//! Tags:
//! - `STDIN`      (C→S, 0x10) — raw bytes from the client's stdin.
//! - `STDOUT`     (S→C, 0x11) — raw bytes from the server's PTY output.
//! - `RESIZE`     (C→S, 0x20) — `u16 be cols` + `u16 be rows`.
//! - `STDIN_EOF`  (C→S, 0x30) — client closed its stdin half. No
//!                payload.
//! - `EXIT`       (S→C, 0x40) — `i32 be status`. Server's last frame
//!                on a successful session. Status is the child's exit
//!                code, or a negative sentinel if the child was
//!                terminated by a signal (Unix) or we couldn't get
//!                a status (Windows).
//!
//! Frame size cap: 1 MiB (`MAX_FRAME_LEN`). Keyboard traffic is tiny;
//! PTY output chunks are typically ≤ 64 KiB. The cap exists only to
//! stop a runaway peer from forcing us to allocate.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const TAG_STDIN: u8 = 0x10;
pub const TAG_STDOUT: u8 = 0x11;
pub const TAG_RESIZE: u8 = 0x20;
pub const TAG_STDIN_EOF: u8 = 0x30;
pub const TAG_EXIT: u8 = 0x40;

pub const MAX_FRAME_LEN: u32 = 1 << 20;

/// Decoded frame. `data` borrows from the caller-owned buffer that
/// [`read_frame`] wrote into, to avoid a copy for the hot STDOUT path.
#[derive(Debug)]
pub enum Frame<'a> {
    Stdin(&'a [u8]),
    Stdout(&'a [u8]),
    Resize { cols: u16, rows: u16 },
    StdinEof,
    Exit(i32),
    Unknown { tag: u8, data: &'a [u8] },
}

/// Read one frame's header + body into `scratch`. `scratch` is resized
/// to fit the payload. Returns the decoded `Frame`, which borrows
/// `scratch`. Returns `UnexpectedEof` on clean close mid-frame.
pub async fn read_frame<'a, R: AsyncRead + Unpin>(
    reader: &mut R,
    scratch: &'a mut Vec<u8>,
) -> io::Result<Frame<'a>> {
    let mut hdr = [0u8; 5];
    reader.read_exact(&mut hdr).await?;
    let tag = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds cap {MAX_FRAME_LEN}"),
        ));
    }
    scratch.resize(len as usize, 0);
    if len > 0 {
        reader.read_exact(&mut scratch[..]).await?;
    }
    Ok(match tag {
        TAG_STDIN => Frame::Stdin(&scratch[..]),
        TAG_STDOUT => Frame::Stdout(&scratch[..]),
        TAG_RESIZE => {
            if scratch.len() != 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("RESIZE payload must be 4 bytes, got {}", scratch.len()),
                ));
            }
            let cols = u16::from_be_bytes([scratch[0], scratch[1]]);
            let rows = u16::from_be_bytes([scratch[2], scratch[3]]);
            Frame::Resize { cols, rows }
        }
        TAG_STDIN_EOF => Frame::StdinEof,
        TAG_EXIT => {
            if scratch.len() != 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("EXIT payload must be 4 bytes, got {}", scratch.len()),
                ));
            }
            let v = i32::from_be_bytes([scratch[0], scratch[1], scratch[2], scratch[3]]);
            Frame::Exit(v)
        }
        _ => Frame::Unknown {
            tag,
            data: &scratch[..],
        },
    })
}

/// Emit one frame. Flushes after the write so interactive latency
/// stays small.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    tag: u8,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_FRAME_LEN as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload length {} exceeds cap {}",
                payload.len(),
                MAX_FRAME_LEN
            ),
        ));
    }
    let mut hdr = [0u8; 5];
    hdr[0] = tag;
    hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&hdr).await?;
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

pub async fn write_stdin<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    write_frame(w, TAG_STDIN, data).await
}

pub async fn write_stdout<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    write_frame(w, TAG_STDOUT, data).await
}

pub async fn write_resize<W: AsyncWrite + Unpin>(
    w: &mut W,
    cols: u16,
    rows: u16,
) -> io::Result<()> {
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&cols.to_be_bytes());
    buf[2..4].copy_from_slice(&rows.to_be_bytes());
    write_frame(w, TAG_RESIZE, &buf).await
}

pub async fn write_stdin_eof<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    write_frame(w, TAG_STDIN_EOF, &[]).await
}

pub async fn write_exit<W: AsyncWrite + Unpin>(w: &mut W, status: i32) -> io::Result<()> {
    write_frame(w, TAG_EXIT, &status.to_be_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn stdin_roundtrip() {
        let (mut a, mut b) = duplex(4096);
        write_stdin(&mut a, b"hello").await.unwrap();
        let mut scratch = Vec::new();
        match read_frame(&mut b, &mut scratch).await.unwrap() {
            Frame::Stdin(data) => assert_eq!(data, b"hello"),
            other => panic!("expected Stdin, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resize_roundtrip() {
        let (mut a, mut b) = duplex(64);
        write_resize(&mut a, 132, 43).await.unwrap();
        let mut scratch = Vec::new();
        match read_frame(&mut b, &mut scratch).await.unwrap() {
            Frame::Resize { cols, rows } => {
                assert_eq!(cols, 132);
                assert_eq!(rows, 43);
            }
            other => panic!("expected Resize, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exit_roundtrip() {
        let (mut a, mut b) = duplex(64);
        write_exit(&mut a, -2).await.unwrap();
        let mut scratch = Vec::new();
        match read_frame(&mut b, &mut scratch).await.unwrap() {
            Frame::Exit(s) => assert_eq!(s, -2),
            other => panic!("expected Exit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stdin_eof_roundtrip() {
        let (mut a, mut b) = duplex(64);
        write_stdin_eof(&mut a).await.unwrap();
        let mut scratch = Vec::new();
        match read_frame(&mut b, &mut scratch).await.unwrap() {
            Frame::StdinEof => (),
            other => panic!("expected StdinEof, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let (mut a, b) = duplex(16);
        // Write a bogus header declaring 2 GiB.
        tokio::spawn(async move {
            let _ = a.write_all(&[TAG_STDIN]).await;
            let _ = a.write_all(&(2_000_000_000u32).to_be_bytes()).await;
        });
        let mut reader = b;
        let mut scratch = Vec::new();
        let err = read_frame(&mut reader, &mut scratch).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
