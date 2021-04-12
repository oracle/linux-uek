// SPDX-License-Identifier: GPL-2.0

//! Synchronisation primitives.
//!
//! This module contains the kernel APIs related to synchronisation that have been ported or
//! wrapped for usage by Rust code in the kernel and is shared by all of them.
//!
//! # Example
//!
//! ```
//! fn test() {
//!     // SAFETY: `init` is called below.
//!     let data = alloc::sync::Arc::pin(unsafe { Mutex::new(0) });
//!     mutex_init!(data.as_ref(), "test::data");
//!     *data.lock() = 10;
//!     pr_info!("{}\n", *data.lock());
//! }
//! ```

use crate::{bindings, CStr};
use core::pin::Pin;

mod arc;
mod condvar;
mod guard;
mod locked_by;
mod mutex;
mod spinlock;

pub use arc::{Ref, RefCount, RefCounted};
pub use condvar::CondVar;
pub use guard::{Guard, Lock};
pub use locked_by::LockedBy;
pub use mutex::Mutex;
pub use spinlock::SpinLock;

/// Safely initialises an object that has an `init` function that takes a name and a lock class as
/// arguments, examples of these are [`Mutex`] and [`SpinLock`]. Each of them also provides a more
/// specialised name that uses this macro.
#[doc(hidden)]
#[macro_export]
macro_rules! init_with_lockdep {
    ($obj:expr, $name:literal) => {{
        static mut CLASS: core::mem::MaybeUninit<$crate::bindings::lock_class_key> =
            core::mem::MaybeUninit::uninit();
        // SAFETY: `CLASS` is never used by Rust code directly; the kernel may change it though.
        #[allow(unused_unsafe)]
        unsafe {
            $crate::sync::NeedsLockClass::init($obj, $crate::cstr!($name), CLASS.as_mut_ptr())
        };
    }};
}

/// A trait for types that need a lock class during initialisation.
///
/// Implementers of this trait benefit from the [`init_with_lockdep`] macro that generates a new
/// class for each initialisation call site.
pub trait NeedsLockClass {
    /// Initialises the type instance so that it can be safely used.
    ///
    /// Callers are encouraged to use the [`init_with_lockdep`] macro as it automatically creates a
    /// new lock class on each usage.
    ///
    /// # Safety
    ///
    /// `key` must point to a valid memory location as it will be used by the kernel.
    unsafe fn init(self: Pin<&Self>, name: CStr<'static>, key: *mut bindings::lock_class_key);
}
