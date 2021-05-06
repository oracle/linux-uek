// SPDX-License-Identifier: GPL-2.0

//! A kernel mutex.
//!
//! This module allows Rust code to use the kernel's [`struct mutex`].

use super::{Guard, Lock, NeedsLockClass};
use crate::{bindings, CStr};
use core::{cell::UnsafeCell, marker::PhantomPinned, pin::Pin};

/// Safely initialises a [`Mutex`] with the given name, generating a new lock class.
#[macro_export]
macro_rules! mutex_init {
    ($mutex:expr, $name:literal) => {
        $crate::init_with_lockdep!($mutex, $name)
    };
}

/// Exposes the kernel's [`struct mutex`]. When multiple threads attempt to lock the same mutex,
/// only one at a time is allowed to progress, the others will block (sleep) until the mutex is
/// unlocked, at which point another thread will be allowed to wake up and make progress.
///
/// A [`Mutex`] must first be initialised with a call to [`Mutex::init`] before it can be used. The
/// [`mutex_init`] macro is provided to automatically assign a new lock class to a mutex instance.
///
/// Since it may block, [`Mutex`] needs to be used with care in atomic contexts.
///
/// [`struct mutex`]: ../../../include/linux/mutex.h
pub struct Mutex<T: ?Sized> {
    /// The kernel `struct mutex` object.
    mutex: UnsafeCell<bindings::mutex>,

    /// A mutex needs to be pinned because it contains a [`struct list_head`] that is
    /// self-referential, so it cannot be safely moved once it is initialised.
    _pin: PhantomPinned,

    /// The data protected by the mutex.
    data: UnsafeCell<T>,
}

// SAFETY: `Mutex` can be transferred across thread boundaries iff the data it protects can.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

// SAFETY: `Mutex` serialises the interior mutability it provides, so it is `Sync` as long as the
// data it protects is `Send`.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Constructs a new mutex.
    ///
    /// # Safety
    ///
    /// The caller must call [`Mutex::init`] before using the mutex.
    pub unsafe fn new(t: T) -> Self {
        Self {
            mutex: UnsafeCell::new(bindings::mutex::default()),
            data: UnsafeCell::new(t),
            _pin: PhantomPinned,
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Locks the mutex and gives the caller access to the data protected by it. Only one thread at
    /// a time is allowed to access the protected data.
    pub fn lock(&self) -> Guard<Self> {
        self.lock_noguard();
        // SAFETY: The mutex was just acquired.
        unsafe { Guard::new(self) }
    }
}

impl<T: ?Sized> NeedsLockClass for Mutex<T> {
    unsafe fn init(self: Pin<&Self>, name: CStr<'static>, key: *mut bindings::lock_class_key) {
        bindings::__mutex_init(self.mutex.get(), name.as_ptr() as _, key);
    }
}

impl<T: ?Sized> Lock for Mutex<T> {
    type Inner = T;

    #[cfg(not(CONFIG_DEBUG_LOCK_ALLOC))]
    fn lock_noguard(&self) {
        // SAFETY: `mutex` points to valid memory.
        unsafe { bindings::mutex_lock(self.mutex.get()) };
    }

    #[cfg(CONFIG_DEBUG_LOCK_ALLOC)]
    fn lock_noguard(&self) {
        // SAFETY: `mutex` points to valid memory.
        unsafe { bindings::mutex_lock_nested(self.mutex.get(), 0) };
    }

    unsafe fn unlock(&self) {
        bindings::mutex_unlock(self.mutex.get());
    }

    fn locked_data(&self) -> &UnsafeCell<T> {
        &self.data
    }
}
