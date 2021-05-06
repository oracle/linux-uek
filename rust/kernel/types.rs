// SPDX-License-Identifier: GPL-2.0

//! Kernel types.
//!
//! C header: [`include/linux/types.h`](../../../../include/linux/types.h)

use core::ops::Deref;

use crate::bindings;

/// Permissions.
///
/// C header: [`include/uapi/linux/stat.h`](../../../../include/uapi/linux/stat.h)
///
/// C header: [`include/linux/stat.h`](../../../../include/linux/stat.h)
pub struct Mode(bindings::umode_t);

impl Mode {
    /// Creates a [`Mode`] from an integer.
    pub fn from_int(m: u16) -> Mode {
        Mode(m)
    }

    /// Returns the mode as an integer.
    pub fn as_int(&self) -> u16 {
        self.0
    }
}

/// A string that is guaranteed to have exactly one `NUL` byte, which is at the
/// end.
///
/// Used for interoperability with kernel APIs that take C strings.
#[repr(transparent)]
pub struct CStr<'a>(&'a str);

impl CStr<'_> {
    /// Creates a [`CStr`] from a [`str`] without performing any additional
    /// checks.
    ///
    /// # Safety
    ///
    /// `data` *must* end with a `NUL` byte, and should only have only a single
    /// `NUL` byte (or the string will be truncated).
    pub const unsafe fn new_unchecked(data: &str) -> CStr {
        CStr(data)
    }
}

impl Deref for CStr<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        self.0
    }
}

/// Creates a new `CStr` from a string literal.
///
/// The string literal should not contain any `NUL` bytes.
///
/// # Examples
///
/// ```rust,no_run
/// const MY_CSTR: CStr<'static> = cstr!("My awesome CStr!");
/// ```
#[macro_export]
macro_rules! cstr {
    ($str:expr) => {{
        let s = concat!($str, "\x00");
        unsafe { $crate::CStr::new_unchecked(s) }
    }};
}
