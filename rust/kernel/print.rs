// SPDX-License-Identifier: GPL-2.0

//! Printing facilities.
//!
//! C header: [`include/linux/printk.h`](../../../../include/linux/printk.h)
//!
//! Reference: <https://www.kernel.org/doc/html/latest/core-api/printk-basics.html>

use core::cmp;
use core::fmt;

use crate::bindings;
use crate::c_types::c_int;

/// Format strings.
///
/// Public but hidden since it should only be used from public macros.
#[doc(hidden)]
pub mod format_strings {
    use crate::bindings;

    /// The length we copy from the `KERN_*` kernel prefixes.
    const LENGTH_PREFIX: usize = 2;

    /// The length of the fixed format strings.
    pub const LENGTH: usize = 11;

    /// Generates a fixed format string for the kernel's [`printk`].
    ///
    /// The format string is always the same for a given level, i.e. for a
    /// given `prefix`, which are the kernel's `KERN_*` constants.
    ///
    /// [`printk`]: ../../../../include/linux/printk.h
    const fn generate(is_cont: bool, prefix: &[u8; 3]) -> [u8; LENGTH] {
        // Ensure the `KERN_*` macros are what we expect.
        assert!(prefix[0] == b'\x01');
        if is_cont {
            assert!(prefix[1] == b'c');
        } else {
            assert!(prefix[1] >= b'0' && prefix[1] <= b'7');
        }
        assert!(prefix[2] == b'\x00');

        let suffix: &[u8; LENGTH - LENGTH_PREFIX] = if is_cont {
            b"%.*s\0\0\0\0\0"
        } else {
            b"%s: %.*s\0"
        };

        [
            prefix[0], prefix[1], suffix[0], suffix[1], suffix[2], suffix[3], suffix[4], suffix[5],
            suffix[6], suffix[7], suffix[8],
        ]
    }

    // Generate the format strings at compile-time.
    //
    // This avoids the compiler generating the contents on the fly in the stack.
    //
    // Furthermore, `static` instead of `const` is used to share the strings
    // for all the kernel.
    pub static EMERG: [u8; LENGTH] = generate(false, bindings::KERN_EMERG);
    pub static ALERT: [u8; LENGTH] = generate(false, bindings::KERN_ALERT);
    pub static CRIT: [u8; LENGTH] = generate(false, bindings::KERN_CRIT);
    pub static ERR: [u8; LENGTH] = generate(false, bindings::KERN_ERR);
    pub static WARNING: [u8; LENGTH] = generate(false, bindings::KERN_WARNING);
    pub static NOTICE: [u8; LENGTH] = generate(false, bindings::KERN_NOTICE);
    pub static INFO: [u8; LENGTH] = generate(false, bindings::KERN_INFO);
    pub static DEBUG: [u8; LENGTH] = generate(false, bindings::KERN_DEBUG);
    pub static CONT: [u8; LENGTH] = generate(true, bindings::KERN_CONT);
}

/// Prints a message via the kernel's [`printk`].
///
/// Public but hidden since it should only be used from public macros.
///
/// # Safety
///
/// The format string must be one of the ones in [`format_strings`], and
/// the module name must be null-terminated.
///
/// [`printk`]: ../../../../include/linux/printk.h
#[doc(hidden)]
pub unsafe fn call_printk(
    format_string: &[u8; format_strings::LENGTH],
    module_name: &[u8],
    string: &[u8],
) {
    // `printk` does not seem to fail in any path.
    bindings::printk(
        format_string.as_ptr() as _,
        module_name.as_ptr(),
        string.len() as c_int,
        string.as_ptr(),
    );
}

/// Prints a message via the kernel's [`printk`] for the `CONT` level.
///
/// Public but hidden since it should only be used from public macros.
///
/// [`printk`]: ../../../../include/linux/printk.h
#[doc(hidden)]
pub fn call_printk_cont(string: &[u8]) {
    // `printk` does not seem to fail in any path.
    //
    // SAFETY: The format string is fixed.
    unsafe {
        bindings::printk(
            format_strings::CONT.as_ptr() as _,
            string.len() as c_int,
            string.as_ptr(),
        );
    }
}

/// The maximum size of a log line in the kernel.
///
/// From `kernel/printk/printk.c`.
const LOG_LINE_MAX: usize = 1024 - 32;

/// The maximum size of a log line in our side.
///
/// FIXME: We should be smarter than this, but for the moment, to reduce stack
/// usage, we only allow this much which should work for most purposes.
const LOG_LINE_SIZE: usize = 300;
crate::static_assert!(LOG_LINE_SIZE <= LOG_LINE_MAX);

/// Public but hidden since it should only be used from public macros.
#[doc(hidden)]
pub struct LogLineWriter {
    data: [u8; LOG_LINE_SIZE],
    pos: usize,
}

impl LogLineWriter {
    /// Creates a new [`LogLineWriter`].
    pub fn new() -> LogLineWriter {
        LogLineWriter {
            data: [0u8; LOG_LINE_SIZE],
            pos: 0,
        }
    }

    /// Returns the internal buffer as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.pos]
    }
}

impl Default for LogLineWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Write for LogLineWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let copy_len = cmp::min(LOG_LINE_SIZE - self.pos, s.as_bytes().len());
        self.data[self.pos..self.pos + copy_len].copy_from_slice(&s.as_bytes()[..copy_len]);
        self.pos += copy_len;
        Ok(())
    }
}

/// Helper function for the [`print_macro!`] to reduce stack usage.
///
/// Public but hidden since it should only be used from public macros.
///
/// # Safety
///
/// The format string must be one of the ones in [`format_strings`], and
/// the module name must be null-terminated.
#[doc(hidden)]
pub unsafe fn format_and_call<const CONT: bool>(
    format_string: &[u8; format_strings::LENGTH],
    module_name: &[u8],
    args: fmt::Arguments,
) {
    // Careful: this object takes quite a bit of stack.
    let mut writer = LogLineWriter::new();

    match fmt::write(&mut writer, args) {
        Ok(_) => {
            if CONT {
                call_printk_cont(writer.as_bytes());
            } else {
                call_printk(format_string, module_name, writer.as_bytes());
            }
        }

        Err(_) => {
            call_printk(
                &format_strings::CRIT,
                module_name,
                b"Failure to format string.\n",
            );
        }
    };
}

/// Performs formatting and forwards the string to [`call_printk`].
///
/// Public but hidden since it should only be used from public macros.
#[doc(hidden)]
#[macro_export]
macro_rules! print_macro (
    // Without extra arguments: no need to format anything.
    ($format_string:path, false, $fmt:expr) => (
        // SAFETY: This hidden macro should only be called by the documented
        // printing macros which ensure the format string is one of the fixed
        // ones. All `__MODULE_NAME`s are null-terminated as they are generated
        // by the `module!` proc macro.
        unsafe {
            kernel::print::call_printk(
                &$format_string,
                crate::__MODULE_NAME,
                $fmt.as_bytes(),
            );
        }
    );

    // Without extra arguments: no need to format anything (`CONT` case).
    ($format_string:path, true, $fmt:expr) => (
        kernel::print::call_printk_cont(
            $fmt.as_bytes(),
        );
    );

    // With extra arguments: we need to perform formatting.
    ($format_string:path, $cont:literal, $fmt:expr, $($arg:tt)*) => (
        // Forwarding the call to a function to perform the formatting
        // is needed here to avoid stack overflows in non-optimized builds when
        // invoking the printing macros a lot of times in the same function.
        // Without it, the compiler reserves one `LogLineWriter` per macro
        // invocation, which is a huge type.
        //
        // We could use an immediately-invoked closure for this, which
        // seems to lower even more the stack usage at `opt-level=0` because
        // `fmt::Arguments` objects do not pile up. However, that breaks
        // the `?` operator if used in one of the arguments.
        //
        // At `opt-level=2`, the generated code is basically the same for
        // all alternatives.
        //
        // SAFETY: This hidden macro should only be called by the documented
        // printing macros which ensure the format string is one of the fixed
        // ones. All `__MODULE_NAME`s are null-terminated as they are generated
        // by the `module!` proc macro.
        unsafe {
            kernel::print::format_and_call::<$cont>(
                &$format_string,
                crate::__MODULE_NAME,
                format_args!($fmt, $($arg)*),
            );
        }
    );
);

// We could use a macro to generate these macros. However, doing so ends
// up being a bit ugly: it requires the dollar token trick to escape `$` as
// well as playing with the `doc` attribute. Furthermore, they cannot be easily
// imported in the prelude due to [1]. So, for the moment, we just write them
// manually, like in the C side; while keeping most of the logic in another
// macro, i.e. [`print_macro`].
//
// [1]: https://github.com/rust-lang/rust/issues/52234

/// Prints an emergency-level message (level 0).
///
/// Use this level if the system is unusable.
///
/// Equivalent to the kernel's [`pr_emerg`] macro.
///
/// Mimics the interface of [`std::print!`]. See [`core::fmt`] and
/// [`alloc::format!`] for information about the formatting syntax.
///
/// [`pr_emerg`]: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html#c.pr_emerg
/// [`std::print!`]: https://doc.rust-lang.org/std/macro.print.html
///
/// # Examples
///
/// ```
/// pr_emerg!("hello {}\n", "there");
/// ```
#[macro_export]
macro_rules! pr_emerg (
    ($($arg:tt)*) => (
        $crate::print_macro!($crate::print::format_strings::EMERG, false, $($arg)*)
    )
);

/// Prints an alert-level message (level 1).
///
/// Use this level if action must be taken immediately.
///
/// Equivalent to the kernel's [`pr_alert`] macro.
///
/// Mimics the interface of [`std::print!`]. See [`core::fmt`] and
/// [`alloc::format!`] for information about the formatting syntax.
///
/// [`pr_alert`]: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html#c.pr_alert
/// [`std::print!`]: https://doc.rust-lang.org/std/macro.print.html
///
/// # Examples
///
/// ```
/// pr_alert!("hello {}\n", "there");
/// ```
#[macro_export]
macro_rules! pr_alert (
    ($($arg:tt)*) => (
        $crate::print_macro!($crate::print::format_strings::ALERT, false, $($arg)*)
    )
);

/// Prints a critical-level message (level 2).
///
/// Use this level for critical conditions.
///
/// Equivalent to the kernel's [`pr_crit`] macro.
///
/// Mimics the interface of [`std::print!`]. See [`core::fmt`] and
/// [`alloc::format!`] for information about the formatting syntax.
///
/// [`pr_crit`]: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html#c.pr_crit
/// [`std::print!`]: https://doc.rust-lang.org/std/macro.print.html
///
/// # Examples
///
/// ```
/// pr_crit!("hello {}\n", "there");
/// ```
#[macro_export]
macro_rules! pr_crit (
    ($($arg:tt)*) => (
        $crate::print_macro!($crate::print::format_strings::CRIT, false, $($arg)*)
    )
);

/// Prints an error-level message (level 3).
///
/// Use this level for error conditions.
///
/// Equivalent to the kernel's [`pr_err`] macro.
///
/// Mimics the interface of [`std::print!`]. See [`core::fmt`] and
/// [`alloc::format!`] for information about the formatting syntax.
///
/// [`pr_err`]: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html#c.pr_err
/// [`std::print!`]: https://doc.rust-lang.org/std/macro.print.html
///
/// # Examples
///
/// ```
/// pr_err!("hello {}\n", "there");
/// ```
#[macro_export]
macro_rules! pr_err (
    ($($arg:tt)*) => (
        $crate::print_macro!($crate::print::format_strings::ERR, false, $($arg)*)
    )
);

/// Prints a warning-level message (level 4).
///
/// Use this level for warning conditions.
///
/// Equivalent to the kernel's [`pr_warn`] macro.
///
/// Mimics the interface of [`std::print!`]. See [`core::fmt`] and
/// [`alloc::format!`] for information about the formatting syntax.
///
/// [`pr_warn`]: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html#c.pr_warn
/// [`std::print!`]: https://doc.rust-lang.org/std/macro.print.html
///
/// # Examples
///
/// ```
/// pr_warn!("hello {}\n", "there");
/// ```
#[macro_export]
macro_rules! pr_warn (
    ($($arg:tt)*) => (
        $crate::print_macro!($crate::print::format_strings::WARNING, false, $($arg)*)
    )
);

/// Prints a notice-level message (level 5).
///
/// Use this level for normal but significant conditions.
///
/// Equivalent to the kernel's [`pr_notice`] macro.
///
/// Mimics the interface of [`std::print!`]. See [`core::fmt`] and
/// [`alloc::format!`] for information about the formatting syntax.
///
/// [`pr_notice`]: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html#c.pr_notice
/// [`std::print!`]: https://doc.rust-lang.org/std/macro.print.html
///
/// # Examples
///
/// ```
/// pr_notice!("hello {}\n", "there");
/// ```
#[macro_export]
macro_rules! pr_notice (
    ($($arg:tt)*) => (
        $crate::print_macro!($crate::print::format_strings::NOTICE, false, $($arg)*)
    )
);

/// Prints an info-level message (level 6).
///
/// Use this level for informational messages.
///
/// Equivalent to the kernel's [`pr_info`] macro.
///
/// Mimics the interface of [`std::print!`]. See [`core::fmt`] and
/// [`alloc::format!`] for information about the formatting syntax.
///
/// [`pr_info`]: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html#c.pr_info
/// [`std::print!`]: https://doc.rust-lang.org/std/macro.print.html
///
/// # Examples
///
/// ```
/// pr_info!("hello {}\n", "there");
/// ```
#[macro_export]
#[doc(alias = "print")]
macro_rules! pr_info (
    ($($arg:tt)*) => (
        $crate::print_macro!($crate::print::format_strings::INFO, false, $($arg)*)
    )
);

/// Continues a previous log message in the same line.
///
/// Use only when continuing a previous `pr_*!` macro (e.g. [`pr_info!`]).
///
/// Equivalent to the kernel's [`pr_cont`] macro.
///
/// Mimics the interface of [`std::print!`]. See [`core::fmt`] and
/// [`alloc::format!`] for information about the formatting syntax.
///
/// [`pr_cont`]: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html#c.pr_cont
/// [`std::print!`]: https://doc.rust-lang.org/std/macro.print.html
///
/// # Examples
///
/// ```
/// pr_info!("hello");
/// pr_cont!(" {}\n", "there");
/// ```
#[macro_export]
macro_rules! pr_cont (
    ($($arg:tt)*) => (
        $crate::print_macro!($crate::print::format_strings::CONT, true, $($arg)*)
    )
);
