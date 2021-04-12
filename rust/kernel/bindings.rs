// SPDX-License-Identifier: GPL-2.0

//! Bindings
//!
//! Imports the generated bindings by `bindgen`.

#[allow(
    clippy::all,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    improper_ctypes
)]
mod bindings_raw {
    use crate::c_types;
    include!(env!("RUST_BINDINGS_FILE"));
}
pub use bindings_raw::*;

pub const GFP_KERNEL: gfp_t = BINDINGS_GFP_KERNEL;
pub const __GFP_ZERO: gfp_t = BINDINGS___GFP_ZERO;
pub const __GFP_HIGHMEM: gfp_t = ___GFP_HIGHMEM;
