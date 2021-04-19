// SPDX-License-Identifier: GPL-2.0

//! User pointers.
//!
//! C header: [`include/linux/uaccess.h`](../../../../include/linux/uaccess.h)

use crate::{c_types, error::Error, KernelResult};
use alloc::vec::Vec;
use core::mem::{size_of, MaybeUninit};

extern "C" {
    fn rust_helper_copy_from_user(
        to: *mut c_types::c_void,
        from: *const c_types::c_void,
        n: c_types::c_ulong,
    ) -> c_types::c_ulong;

    fn rust_helper_copy_to_user(
        to: *mut c_types::c_void,
        from: *const c_types::c_void,
        n: c_types::c_ulong,
    ) -> c_types::c_ulong;
}

/// Specifies that a type is safely readable from byte slices.
///
/// Not all types can be safely read from byte slices; examples from
/// <https://doc.rust-lang.org/reference/behavior-considered-undefined.html> include `bool`
/// that must be either `0` or `1`, and `char` that cannot be a surrogate or above `char::MAX`.
///
/// # Safety
///
/// Implementers must ensure that the type is made up only of types that can be safely read from
/// arbitrary byte sequences (e.g., `u32`, `u64`, etc.).
pub unsafe trait ReadableFromBytes {}

// SAFETY: All bit patterns are acceptable values of the types below.
unsafe impl ReadableFromBytes for u8 {}
unsafe impl ReadableFromBytes for u16 {}
unsafe impl ReadableFromBytes for u32 {}
unsafe impl ReadableFromBytes for u64 {}
unsafe impl ReadableFromBytes for usize {}
unsafe impl ReadableFromBytes for i8 {}
unsafe impl ReadableFromBytes for i16 {}
unsafe impl ReadableFromBytes for i32 {}
unsafe impl ReadableFromBytes for i64 {}
unsafe impl ReadableFromBytes for isize {}

/// Specifies that a type is safely writable to byte slices.
///
/// This means that we don't read undefined values (which leads to UB) in preparation for writing
/// to the byte slice. It also ensures that no potentially sensitive information is leaked into the
/// byte slices.
///
/// # Safety
///
/// A type must not include padding bytes and must be fully initialised to safely implement
/// [`WritableToBytes`] (i.e., it doesn't contain [`MaybeUninit`] fields). A composition of
/// writable types in a structure is not necessarily writable because it may result in padding
/// bytes.
pub unsafe trait WritableToBytes {}

// SAFETY: Initialised instances of the following types have no uninitialised portions.
unsafe impl WritableToBytes for u8 {}
unsafe impl WritableToBytes for u16 {}
unsafe impl WritableToBytes for u32 {}
unsafe impl WritableToBytes for u64 {}
unsafe impl WritableToBytes for usize {}
unsafe impl WritableToBytes for i8 {}
unsafe impl WritableToBytes for i16 {}
unsafe impl WritableToBytes for i32 {}
unsafe impl WritableToBytes for i64 {}
unsafe impl WritableToBytes for isize {}

/// A reference to an area in userspace memory, which can be either
/// read-only or read-write.
///
/// All methods on this struct are safe: invalid pointers return
/// `EFAULT`. Concurrent access, *including data races to/from userspace
/// memory*, is permitted, because fundamentally another userspace
/// thread/process could always be modifying memory at the same time
/// (in the same way that userspace Rust's [`std::io`] permits data races
/// with the contents of files on disk). In the presence of a race, the
/// exact byte values read/written are unspecified but the operation is
/// well-defined. Kernelspace code should validate its copy of data
/// after completing a read, and not expect that multiple reads of the
/// same address will return the same value.
///
/// All APIs enforce the invariant that a given byte of memory from userspace
/// may only be read once. By preventing double-fetches we avoid TOCTOU
/// vulnerabilities. This is accomplished by taking `self` by value to prevent
/// obtaining multiple readers on a given [`UserSlicePtr`], and the readers
/// only permitting forward reads.
///
/// Constructing a [`UserSlicePtr`] performs no checks on the provided
/// address and length, it can safely be constructed inside a kernel thread
/// with no current userspace process. Reads and writes wrap the kernel APIs
/// `copy_from_user` and `copy_to_user`, which check the memory map of the
/// current process and enforce that the address range is within the user
/// range (no additional calls to `access_ok` are needed).
///
/// [`std::io`]: https://doc.rust-lang.org/std/io/index.html
pub struct UserSlicePtr(*mut c_types::c_void, usize);

impl UserSlicePtr {
    /// Constructs a user slice from a raw pointer and a length in bytes.
    ///
    /// # Safety
    ///
    /// Callers must be careful to avoid time-of-check-time-of-use
    /// (TOCTOU) issues. The simplest way is to create a single instance of
    /// [`UserSlicePtr`] per user memory block as it reads each byte at
    /// most once.
    pub unsafe fn new(ptr: *mut c_types::c_void, length: usize) -> Self {
        UserSlicePtr(ptr, length)
    }

    /// Reads the entirety of the user slice.
    ///
    /// Returns `EFAULT` if the address does not currently point to
    /// mapped, readable memory.
    pub fn read_all(self) -> KernelResult<Vec<u8>> {
        self.reader().read_all()
    }

    /// Constructs a [`UserSlicePtrReader`].
    pub fn reader(self) -> UserSlicePtrReader {
        UserSlicePtrReader(self.0, self.1)
    }

    /// Writes the provided slice into the user slice.
    ///
    /// Returns `EFAULT` if the address does not currently point to
    /// mapped, writable memory (in which case some data from before the
    /// fault may be written), or `data` is larger than the user slice
    /// (in which case no data is written).
    pub fn write_all(self, data: &[u8]) -> KernelResult {
        self.writer().write_slice(data)
    }

    /// Constructs a [`UserSlicePtrWriter`].
    pub fn writer(self) -> UserSlicePtrWriter {
        UserSlicePtrWriter(self.0, self.1)
    }

    /// Constructs both a [`UserSlicePtrReader`] and a [`UserSlicePtrWriter`].
    pub fn reader_writer(self) -> (UserSlicePtrReader, UserSlicePtrWriter) {
        (
            UserSlicePtrReader(self.0, self.1),
            UserSlicePtrWriter(self.0, self.1),
        )
    }
}

/// A reader for [`UserSlicePtr`].
///
/// Used to incrementally read from the user slice.
pub struct UserSlicePtrReader(*mut c_types::c_void, usize);

impl UserSlicePtrReader {
    /// Returns the number of bytes left to be read from this.
    ///
    /// Note that even reading less than this number of bytes may fail.
    pub fn len(&self) -> usize {
        self.1
    }

    /// Returns `true` if `self.len()` is 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads all data remaining in the user slice.
    ///
    /// Returns `EFAULT` if the address does not currently point to
    /// mapped, readable memory.
    pub fn read_all(&mut self) -> KernelResult<Vec<u8>> {
        let mut data = Vec::<u8>::new();
        data.try_reserve_exact(self.1)?;
        data.resize(self.1, 0);
        // SAFETY: The output buffer is valid as we just allocated it.
        unsafe { self.read_raw(data.as_mut_ptr(), data.len())? };
        Ok(data)
    }

    /// Reads a byte slice from the user slice.
    ///
    /// Returns `EFAULT` if the byte slice is bigger than the remaining size
    /// of the user slice or if the address does not currently point to mapped,
    /// readable memory.
    pub fn read_slice(&mut self, data: &mut [u8]) -> KernelResult {
        // SAFETY: The output buffer is valid as it's coming from a live reference.
        unsafe { self.read_raw(data.as_mut_ptr(), data.len()) }
    }

    /// Reads raw data from the user slice into a raw kernel buffer.
    ///
    /// # Safety
    ///
    /// The output buffer must be valid.
    pub unsafe fn read_raw(&mut self, out: *mut u8, len: usize) -> KernelResult {
        if len > self.1 || len > u32::MAX as usize {
            return Err(Error::EFAULT);
        }
        let res = rust_helper_copy_from_user(out as _, self.0, len as _);
        if res != 0 {
            return Err(Error::EFAULT);
        }
        // Since this is not a pointer to a valid object in our program,
        // we cannot use `add`, which has C-style rules for defined
        // behavior.
        self.0 = self.0.wrapping_add(len);
        self.1 -= len;
        Ok(())
    }

    /// Reads the contents of a plain old data (POD) type from the user slice.
    pub fn read<T: ReadableFromBytes>(&mut self) -> KernelResult<T> {
        let mut out = MaybeUninit::<T>::uninit();
        // SAFETY: The buffer is valid as it was just allocated.
        unsafe { self.read_raw(out.as_mut_ptr() as _, size_of::<T>()) }?;
        // SAFETY: We just initialised the data.
        Ok(unsafe { out.assume_init() })
    }
}

/// A writer for [`UserSlicePtr`].
///
/// Used to incrementally write into the user slice.
pub struct UserSlicePtrWriter(*mut c_types::c_void, usize);

impl UserSlicePtrWriter {
    /// Returns the number of bytes left to be written from this.
    ///
    /// Note that even writing less than this number of bytes may fail.
    pub fn len(&self) -> usize {
        self.1
    }

    /// Returns `true` if `self.len()` is 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Writes a byte slice to the user slice.
    ///
    /// Returns `EFAULT` if the byte slice is bigger than the remaining size
    /// of the user slice or if the address does not currently point to mapped,
    /// writable memory.
    pub fn write_slice(&mut self, data: &[u8]) -> KernelResult {
        // SAFETY: The input buffer is valid as it's coming from a live reference.
        unsafe { self.write_raw(data.as_ptr(), data.len()) }
    }

    /// Writes raw data to the user slice from a raw kernel buffer.
    ///
    /// # Safety
    ///
    /// The input buffer must be valid.
    unsafe fn write_raw(&mut self, data: *const u8, len: usize) -> KernelResult {
        if len > self.1 || len > u32::MAX as usize {
            return Err(Error::EFAULT);
        }
        let res = rust_helper_copy_to_user(self.0, data as _, len as _);
        if res != 0 {
            return Err(Error::EFAULT);
        }
        // Since this is not a pointer to a valid object in our program,
        // we cannot use `add`, which has C-style rules for defined
        // behavior.
        self.0 = self.0.wrapping_add(len);
        self.1 -= len;
        Ok(())
    }

    /// Writes the contents of the given data into the user slice.
    pub fn write<T: WritableToBytes>(&mut self, data: &T) -> KernelResult<()> {
        // SAFETY: The input buffer is valid as it's coming from a live
        // reference to a type that implements `WritableToBytes`.
        unsafe { self.write_raw(data as *const T as _, size_of::<T>()) }
    }
}
