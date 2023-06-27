//! Ring buffer types used to receive events from eBPF programs using the linux `ringbuf` API.
//!
//! See the [`Ringbuf`](crate::maps::RingBuf) and [`AsyncRingBuf`](crate::maps::AsyncRingBuf).
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
mod async_ringbuf;
mod ringbuf;

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
pub use async_ringbuf::*;
pub use ringbuf::*;
