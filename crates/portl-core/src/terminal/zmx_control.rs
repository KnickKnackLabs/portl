use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL: &str = "zmx-control/v1";
pub const TAG_INPUT: u8 = 0;
pub const TAG_OUTPUT: u8 = 1;
pub const TAG_RESIZE: u8 = 2;
pub const TAG_CLOSE: u8 = 3;
pub const TAG_VIEWPORT_SNAPSHOT: u8 = 14;
pub const TAG_LIVE_OUTPUT: u8 = 15;

pub const HEADER_BYTES: usize = 5;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub async fn write_frame<W>(writer: &mut W, tag: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "zmx-control frame too large"))?;
    let mut header = [0_u8; HEADER_BYTES];
    header[0] = tag;
    header[1..].copy_from_slice(&len.to_le_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

pub async fn read_frame<R>(reader: &mut R) -> io::Result<Option<(u8, Vec<u8>)>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; HEADER_BYTES];
    match reader.read_exact(&mut header[..1]).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    reader.read_exact(&mut header[1..]).await?;
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zmx-control frame exceeds maximum payload size",
        ));
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Some((header[0], payload)))
}

#[must_use]
pub fn resize_payload(rows: u16, cols: u16) -> [u8; 4] {
    let mut payload = [0_u8; 4];
    payload[..2].copy_from_slice(&rows.to_le_bytes());
    payload[2..].copy_from_slice(&cols.to_le_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn zmx_control_frames_roundtrip() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, TAG_INPUT, b"hello").await.unwrap();

        assert_eq!(
            read_frame(&mut bytes.as_slice()).await.unwrap(),
            Some((TAG_INPUT, b"hello".to_vec()))
        );
    }

    #[test]
    fn semantic_output_tags_match_zmx_ipc_contract() {
        assert_eq!(TAG_VIEWPORT_SNAPSHOT, 14);
        assert_eq!(TAG_LIVE_OUTPUT, 15);
    }

    #[tokio::test]
    async fn read_frame_errors_on_truncated_header() {
        let mut partial_header = [TAG_OUTPUT, 1, 0].as_slice();
        let err = read_frame(&mut partial_header).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn read_frame_allows_clean_eof_before_header() {
        let mut empty = [].as_slice();
        assert_eq!(read_frame(&mut empty).await.unwrap(), None);
    }
}
