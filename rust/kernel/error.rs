// SPDX-License-Identifier: GPL-2.0

//! Kernel errors.
//!
//! C header: [`include/uapi/asm-generic/errno-base.h`](../../../include/uapi/asm-generic/errno-base.h)

use crate::{bindings, c_types};
use alloc::{alloc::AllocError, collections::TryReserveError};
use core::{num::TryFromIntError, str::Utf8Error};

/// Generic integer kernel error.
///
/// The kernel defines a set of integer generic error codes based on C and
/// POSIX ones. These codes may have a more specific meaning in some contexts.
pub struct Error(c_types::c_int);

impl Error {
    /// Invalid argument.
    pub const EINVAL: Self = Error(-(bindings::EINVAL as i32));

    /// Out of memory.
    pub const ENOMEM: Self = Error(-(bindings::ENOMEM as i32));

    /// Bad address.
    pub const EFAULT: Self = Error(-(bindings::EFAULT as i32));

    /// Illegal seek.
    pub const ESPIPE: Self = Error(-(bindings::ESPIPE as i32));

    /// Try again.
    pub const EAGAIN: Self = Error(-(bindings::EAGAIN as i32));

    /// Device or resource busy.
    pub const EBUSY: Self = Error(-(bindings::EBUSY as i32));

    /// Restart the system call.
    pub const ERESTARTSYS: Self = Error(-(bindings::ERESTARTSYS as i32));

    /// Operation not permitted.
    pub const EPERM: Self = Error(-(bindings::EPERM as i32));

    /// No such process.
    pub const ESRCH: Self = Error(-(bindings::ESRCH as i32));

    /// No such file or directory.
    pub const ENOENT: Self = Error(-(bindings::ENOENT as i32));

    /// Interrupted system call.
    pub const EINTR: Self = Error(-(bindings::EINTR as i32));

    /// Creates an [`Error`] from a kernel error code.
    pub fn from_kernel_errno(errno: c_types::c_int) -> Error {
        Error(errno)
    }

    /// Returns the kernel error code.
    pub fn to_kernel_errno(&self) -> c_types::c_int {
        self.0
    }
}

impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Error {
        Error::EINVAL
    }
}

impl From<Utf8Error> for Error {
    fn from(_: Utf8Error) -> Error {
        Error::EINVAL
    }
}

impl From<TryReserveError> for Error {
    fn from(_: TryReserveError) -> Error {
        Error::ENOMEM
    }
}

/// A [`Result`] with an [`Error`] error type.
///
/// To be used as the return type for functions that may fail.
///
/// # Error codes in C and Rust
///
/// In C, it is common that functions indicate success or failure through
/// their return value; modifying or returning extra data through non-`const`
/// pointer parameters. In particular, in the kernel, functions that may fail
/// typically return an `int` that represents a generic error code. We model
/// those as [`Error`].
///
/// In Rust, it is idiomatic to model functions that may fail as returning
/// a [`Result`]. Since in the kernel many functions return an error code,
/// [`KernelResult`] is a type alias for a [`Result`] that uses [`Error`] as
/// its error type.
///
/// Note that even if a function does not return anything when it succeeds,
/// it should still be modeled as returning a `KernelResult` rather than
/// just an [`Error`].
pub type KernelResult<T = ()> = Result<T, Error>;

impl From<AllocError> for Error {
    fn from(_: AllocError) -> Error {
        Error::ENOMEM
    }
}
