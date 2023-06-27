//! A [ring buffer map][ringbuf] that may be used to receive events from eBPF programs.
//! As of Linux 5.8, this is the preferred way to transfer per-event data from eBPF
//! programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use std::{
    borrow::Borrow,
    io,
    ops::Deref,
    os::unix::prelude::AsRawFd,
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use libc::{munmap, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};

use crate::{
    generated::{BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT, BPF_RINGBUF_HDR_SZ},
    maps::{MapData, MapError},
    sys::mmap,
    util::page_size,
};

/// A map that can be used to receive events from eBPF programs.
///
/// This is similar to [`PerfEventArray`], but different in a few ways:
/// * It's shared across all CPUs, which allows a strong ordering between events. It also makes the
///   buffer creation easier.
/// * Data notifications are delivered for every event instead of being sampled for every N event;
///   the eBPF program can also control notification delivery if sampling is desired for performance reasons.
/// * On the eBPF side, it supports the reverse-commit pattern where the event can be directly
///   written into the ring without copying from a temporary location.
/// * Dropped sample notifications goes to the eBPF program as the return value of `reserve`/`output`,
///   and not the userspace reader. This might require extra code to handle, but allows for more
///   flexible schemes to handle dropped samples.
///
/// To receive events you need to:
/// * Instantiate it using [`RingBuf::try_from`]
/// * poll the [`RingBuf`] to be notified when events are inserted in the buffer
/// * call [`RingBuf::next`] to read the events until `None` is returned. Only then,
/// poll again
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.8.
///
/// # Examples
///
/// The following example shows how to read samples as well as using an async runtime
/// to wait for samples to be ready:
///
/// ```no_run
/// # use aya::maps::{Map, MapData, RingBuf};
/// # use std::ops::DerefMut;
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #    #[error(transparent)]
/// #    IO(#[from] std::io::Error),
/// #    #[error(transparent)]
/// #    Map(#[from] aya::maps::MapError),
/// #    #[error(transparent)]
/// #    Bpf(#[from] aya::BpfError),
/// # }
/// # async {
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::convert::{TryFrom, TryInto};
///
/// let mut ring = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
///
/// // For tokio
/// let mut ring_fd = AsyncFd::new(ring.as_raw_fd());
/// loop {
///     // Wait for readiness.
///     poll.readable().await;
///
///     while let Some(e) = poll.get_inner_mut().next() {
///         // Do something with the data bytes
///     }
/// }
/// # Ok::<(), Error>(())
/// # };
/// ```
///
/// [`PerfEventArray`]: crate::maps::PerfEventArray
#[doc(alias = "BPF_MAP_TYPE_RINGBUF")]
pub struct RingBuf<T: Borrow<MapData>> {
    _map: T,
    map_fd: i32,
    consumer_pos_ptr: *const AtomicUsize,
    producer_pos_ptr: *const AtomicUsize,
    data_ptr: *const u8,
    page_size: usize,
    mask: usize,
}

unsafe impl<T: Borrow<MapData>> Send for RingBuf<T> {}

impl<T: Borrow<MapData>> RingBuf<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        let data_size = data.obj.max_entries() as usize;

        let page_size = page_size();
        let map_fd = data.fd_or_err().map_err(MapError::from)?;
        let mask = (data_size - 1) as usize;

        // Map writable consumer page
        let consumer_page = unsafe {
            mmap(
                ptr::null_mut(),
                page_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                map_fd,
                0,
            )
        };
        if consumer_page == MAP_FAILED {
            return Err(MapError::SyscallError {
                call: "mmap".to_string(),
                io_error: io::Error::last_os_error(),
            });
        }

        let producer_page = unsafe {
            mmap(
                ptr::null_mut(),
                page_size,
                PROT_READ,
                MAP_SHARED,
                map_fd,
                page_size as _,
            )
        };
        if producer_page == MAP_FAILED {
            return Err(MapError::SyscallError {
                call: "mmap".to_string(),
                io_error: io::Error::last_os_error(),
            });
        }

        // From kernel/bpf/ringbuf.c:
        // Each data page is mapped twice to allow "virtual"
        // continuous read of samples wrapping around the end of ring
        // buffer area:
        // ------------------------------------------------------
        // | meta pages |  real data pages  |  same data pages  |
        // ------------------------------------------------------
        // |            | 1 2 3 4 5 6 7 8 9 | 1 2 3 4 5 6 7 8 9 |
        // ------------------------------------------------------
        // |            | TA             DA | TA             DA |
        // ------------------------------------------------------
        //                               ^^^^^^^
        //                                  |
        // Here, no need to worry about special handling of wrapped-around
        // data due to double-mapped data pages. This works both in kernel and
        // when mmap()'ed in user-space, simplifying both kernel and
        // user-space implementations significantly.
        let data_ptr = unsafe {
            mmap(
                ptr::null_mut(),
                data_size * 2,
                PROT_READ,
                MAP_SHARED,
                map_fd,
                (page_size * 2) as _,
            )
        };
        if data_ptr == MAP_FAILED {
            return Err(MapError::SyscallError {
                call: "mmap".to_string(),
                io_error: io::Error::last_os_error(),
            });
        }

        Ok(RingBuf {
            _map: map,
            map_fd,
            data_ptr: data_ptr as *const u8,
            consumer_pos_ptr: consumer_page as *mut _,
            producer_pos_ptr: producer_page as *mut _,
            page_size,
            mask,
        })
    }

    /// Try to take a new entry from the ringbuf.
    ///
    /// Returns `Some(item)` if the ringbuf is not empty.
    /// Returns `None` if the ringbuf is empty
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<RingBufItem<T>> {
        let mut consumer_pos = unsafe { (*self.consumer_pos_ptr).load(Ordering::Relaxed) };
        let mut producer_pos = unsafe { (*self.producer_pos_ptr).load(Ordering::Acquire) };

        while consumer_pos < producer_pos {
            let sample_ptr = unsafe { self.data_ptr.add(consumer_pos & self.mask) };
            let sample_hdr = unsafe { *(sample_ptr as *const u32) };

            // If the record is busy, we are done
            if sample_hdr & BPF_RINGBUF_BUSY_BIT == 1 {
                return None;
            }
            // If the record is ready, create an Item and return
            if sample_hdr & BPF_RINGBUF_DISCARD_BIT == 0 {
                let sample_data_ptr = unsafe { sample_ptr.add(BPF_RINGBUF_HDR_SZ as usize) };
                let data =
                    unsafe { std::slice::from_raw_parts(sample_data_ptr, sample_hdr as usize) };
                return Some(RingBufItem { owner: self, data });
            }

            // The record needs to be discarded
            self.advance_consumer();
            consumer_pos = unsafe { (*self.consumer_pos_ptr).load(Ordering::Relaxed) };
            producer_pos = unsafe { (*self.producer_pos_ptr).load(Ordering::Acquire) };
        }

        return None;
    }

    fn advance_consumer(&mut self) {
        let consumer_pos = unsafe { (*self.consumer_pos_ptr).load(Ordering::Relaxed) };
        let sample_ptr = unsafe { self.data_ptr.add(consumer_pos & self.mask) };
        let sample_hdr = unsafe { *(sample_ptr as *const u32) };
        let len = sample_hdr & !(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);

        let new_consumer_pos = consumer_pos + align(len + BPF_RINGBUF_HDR_SZ) as usize;
        unsafe {
            (*self.consumer_pos_ptr).store(new_consumer_pos, Ordering::Release);
        }
    }
}

impl<T: Borrow<MapData>> Drop for RingBuf<T> {
    fn drop(&mut self) {
        if !self.data_ptr.is_null() {
            let data_size = self._map.borrow().obj.max_entries() as usize;
            unsafe {
                munmap(self.data_ptr as *mut _, data_size * 2);
            }
        }

        if !self.producer_pos_ptr.is_null() {
            unsafe {
                munmap(self.producer_pos_ptr as *mut _, self.page_size);
            }
        }

        if !self.consumer_pos_ptr.is_null() {
            unsafe {
                munmap(self.consumer_pos_ptr as *mut _, self.page_size);
            }
        }
    }
}

impl<T: Borrow<MapData>> AsRawFd for RingBuf<T> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.map_fd
    }
}

/// An ringbuf item. When this item is dropped, the consumer index in the ringbuf will be updated.
pub struct RingBufItem<'a, T: Borrow<MapData>> {
    owner: &'a mut RingBuf<T>,
    data: &'a [u8],
}

impl<'a, T: Borrow<MapData>> Deref for RingBufItem<'a, T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        return self.data;
    }
}

impl<'a, T: Borrow<MapData>> Drop for RingBufItem<'a, T> {
    fn drop(&mut self) {
        self.owner.advance_consumer();
    }
}

/// Align `len` to the nearest 8 byte
pub(crate) fn align(len: u32) -> u32 {
    (len + 7) & !7
}
