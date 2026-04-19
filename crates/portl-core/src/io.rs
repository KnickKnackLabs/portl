use std::cmp::min;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result, bail};
use iroh::endpoint::RecvStream;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, ReadBuf};

const READ_CHUNK: usize = 1024;

#[derive(Debug)]
pub struct BufferedRecv {
    prefix: Vec<u8>,
    recv: RecvStream,
}

impl BufferedRecv {
    #[must_use]
    pub fn new(recv: RecvStream, prefix: Vec<u8>) -> Self {
        Self { prefix, recv }
    }

    #[must_use]
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    pub fn push_front(&mut self, bytes: &[u8]) {
        let mut prefix = bytes.to_vec();
        prefix.extend_from_slice(&self.prefix);
        self.prefix = prefix;
    }

    pub async fn read_frame<T>(&mut self, max_bytes: usize) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        loop {
            match postcard::take_from_bytes::<T>(&self.prefix) {
                Ok((value, rest)) => {
                    let consumed = self.prefix.len() - rest.len();
                    self.prefix.drain(..consumed);
                    return Ok(Some(value));
                }
                Err(postcard::Error::DeserializeUnexpectedEnd) => {
                    if self.prefix.len() >= max_bytes {
                        bail!("postcard frame exceeds {max_bytes} bytes")
                    }
                    let mut chunk = vec![0; min(READ_CHUNK, max_bytes - self.prefix.len())];
                    match self
                        .recv
                        .read(&mut chunk)
                        .await
                        .context("read framed stream")?
                    {
                        Some(read) => self.prefix.extend_from_slice(&chunk[..read]),
                        None if self.prefix.is_empty() => return Ok(None),
                        None => bail!("truncated postcard frame"),
                    }
                }
                Err(err) => return Err(err).context("decode postcard frame"),
            }
        }
    }
}

impl AsyncRead for BufferedRecv {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let to_copy = min(self.prefix.len(), buf.remaining());
            buf.put_slice(&self.prefix[..to_copy]);
            self.prefix.drain(..to_copy);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

pub async fn read_postcard_prefix<T>(
    recv: RecvStream,
    max_bytes: usize,
) -> Result<(T, BufferedRecv)>
where
    T: DeserializeOwned,
{
    let mut buffered = BufferedRecv::new(recv, Vec::new());
    let frame = buffered
        .read_frame::<T>(max_bytes)
        .await?
        .context("missing postcard frame")?;
    Ok((frame, buffered))
}
