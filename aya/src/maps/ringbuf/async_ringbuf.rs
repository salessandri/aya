use std::borrow::Borrow;
use std::os::fd::{AsRawFd, RawFd};
use std::ptr::drop_in_place;
use thiserror::Error;

use crate::maps::{MapData, MapError, RingBuf, RingBufItem};

#[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
use async_io::Async;

#[cfg(feature = "async_tokio")]
use tokio::io::unix::AsyncFd;
use crate::maps::ringbuf::RingBufError::IO;

#[cfg(feature = "async_tokio")]
type AsyncFdType = AsyncFd<RawFd>;

#[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
type AsyncFdType = Async<RawFd>;

/// Perf buffer error.
#[derive(Error, Debug)]
pub enum RingBufError {
    /// Perf buffer error.
    #[error(transparent)]
    Map(#[from] MapError),

    /// Perf buffer error.
    #[error(transparent)]
    IO(#[from] std::io::Error),

}

///
#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct AsyncRingBuf<T: Borrow<MapData>> {
    ringbuf: RingBuf<T>,
    async_fd: AsyncFdType,
}

impl<T: Borrow<MapData>> AsyncRingBuf<T> {
    pub(crate) fn new(map: T) -> Result<AsyncRingBuf<T>, RingBufError> {
        let ringbuf = RingBuf::new(map)?;
        let async_fd = AsyncFdType::new(ringbuf.as_raw_fd())?;

        Ok(AsyncRingBuf {
            ringbuf,
            async_fd,
        })
    }

    /// Perf buffer error.
    pub async fn next(&mut self) -> Result<RingBufItem<T>, RingBufError> {
        // loop {
        //     {
        //         let mut ret_item = self.ringbuf.next();
        //         if let Some(item) = ret_item.take() {
        //             return Ok(item);
        //         }
        //         drop(ret_item);
        //     }
        //     is_readable(&self.async_fd).await?
        // }
        unimplemented!("not yet...")
    }

}

#[cfg(all(not(feature = "async_tokio"), feature = "async_std"))]
#[inline]
async fn is_readable(async_fd: &Async<RawFd>) -> Result<(), std::io::Error> {
    async_fd.readable().await?;
    Ok(())
}

#[cfg(feature = "async_tokio")]
#[inline]
async fn is_readable(mut async_fd: &AsyncFd<RawFd>) -> Result<(), std::io::Error> {
    let mut guard = async_fd.readable_mut().await?;
    guard.clear_ready();
    Ok(())
}