// SPDX-License-Identifier: GPL-2.0

//! Rust miscellaneous device sample

#![no_std]
#![feature(allocator_api, global_asm)]

use alloc::{boxed::Box, sync::Arc};
use core::pin::Pin;
use kernel::prelude::*;
use kernel::{
    cstr,
    file_operations::{File, FileOpener, FileOperations},
    miscdev,
    sync::{CondVar, Mutex},
    user_ptr::{UserSlicePtrReader, UserSlicePtrWriter},
    Error,
};

module! {
    type: RustMiscdev,
    name: b"rust_miscdev",
    author: b"Rust for Linux Contributors",
    description: b"Rust miscellaneous device sample",
    license: b"GPL v2",
    params: {
    },
}

const MAX_TOKENS: usize = 3;

struct SharedStateInner {
    token_count: usize,
}

struct SharedState {
    state_changed: CondVar,
    inner: Mutex<SharedStateInner>,
}

impl SharedState {
    fn try_new() -> KernelResult<Arc<Self>> {
        let state = Arc::try_new(Self {
            // SAFETY: `condvar_init!` is called below.
            state_changed: unsafe { CondVar::new() },
            // SAFETY: `mutex_init!` is called below.
            inner: unsafe { Mutex::new(SharedStateInner { token_count: 0 }) },
        })?;
        // SAFETY: `state_changed` is pinned behind `Arc`.
        let state_changed = unsafe { Pin::new_unchecked(&state.state_changed) };
        kernel::condvar_init!(state_changed, "SharedState::state_changed");
        // SAFETY: `inner` is pinned behind `Arc`.
        let inner = unsafe { Pin::new_unchecked(&state.inner) };
        kernel::mutex_init!(inner, "SharedState::inner");
        Ok(state)
    }
}

struct Token {
    shared: Arc<SharedState>,
}

impl FileOpener<Arc<SharedState>> for Token {
    fn open(shared: &Arc<SharedState>) -> KernelResult<Self::Wrapper> {
        Ok(Box::try_new(Self {
            shared: shared.clone(),
        })?)
    }
}

impl FileOperations for Token {
    type Wrapper = Box<Self>;

    kernel::declare_file_operations!(read, write);

    fn read(&self, _: &File, data: &mut UserSlicePtrWriter, offset: u64) -> KernelResult<usize> {
        // Succeed if the caller doesn't provide a buffer or if not at the start.
        if data.is_empty() || offset != 0 {
            return Ok(0);
        }

        {
            let mut inner = self.shared.inner.lock();

            // Wait until we are allowed to decrement the token count or a signal arrives.
            while inner.token_count == 0 {
                if self.shared.state_changed.wait(&mut inner) {
                    return Err(Error::EINTR);
                }
            }

            // Consume a token.
            inner.token_count -= 1;
        }

        // Notify a possible writer waiting.
        self.shared.state_changed.notify_all();

        // Write a one-byte 1 to the reader.
        data.write_slice(&[1u8; 1])?;
        Ok(1)
    }

    fn write(&self, data: &mut UserSlicePtrReader, _offset: u64) -> KernelResult<usize> {
        {
            let mut inner = self.shared.inner.lock();

            // Wait until we are allowed to increment the token count or a signal arrives.
            while inner.token_count == MAX_TOKENS {
                if self.shared.state_changed.wait(&mut inner) {
                    return Err(Error::EINTR);
                }
            }

            // Increment the number of token so that a reader can be released.
            inner.token_count += 1;
        }

        // Notify a possible reader waiting.
        self.shared.state_changed.notify_all();
        Ok(data.len())
    }
}

struct RustMiscdev {
    _dev: Pin<Box<miscdev::Registration<Arc<SharedState>>>>,
}

impl KernelModule for RustMiscdev {
    fn init() -> KernelResult<Self> {
        pr_info!("Rust miscellaneous device sample (init)\n");

        let state = SharedState::try_new()?;

        Ok(RustMiscdev {
            _dev: miscdev::Registration::new_pinned::<Token>(cstr!("rust_miscdev"), None, state)?,
        })
    }
}

impl Drop for RustMiscdev {
    fn drop(&mut self) {
        pr_info!("Rust miscellaneous device sample (exit)\n");
    }
}
