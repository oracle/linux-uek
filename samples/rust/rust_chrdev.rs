// SPDX-License-Identifier: GPL-2.0

//! Rust character device sample

#![no_std]
#![feature(allocator_api, global_asm)]

use alloc::boxed::Box;
use core::pin::Pin;
use kernel::prelude::*;
use kernel::{
    chrdev, cstr,
    file_operations::{FileOpener, FileOperations},
};

module! {
    type: RustChrdev,
    name: b"rust_chrdev",
    author: b"Rust for Linux Contributors",
    description: b"Rust character device sample",
    license: b"GPL v2",
    params: {
    },
}

struct RustFile;

impl FileOpener<()> for RustFile {
    fn open(_ctx: &()) -> KernelResult<Self::Wrapper> {
        pr_info!("rust file was opened!\n");
        Ok(Box::try_new(Self)?)
    }
}

impl FileOperations for RustFile {
    type Wrapper = Box<Self>;

    kernel::declare_file_operations!();
}

struct RustChrdev {
    _dev: Pin<Box<chrdev::Registration<2>>>,
}

impl KernelModule for RustChrdev {
    fn init() -> KernelResult<Self> {
        pr_info!("Rust character device sample (init)\n");

        let mut chrdev_reg =
            chrdev::Registration::new_pinned(cstr!("rust_chrdev"), 0, &THIS_MODULE)?;

        // Register the same kind of device twice, we're just demonstrating
        // that you can use multiple minors. There are two minors in this case
        // because its type is `chrdev::Registration<2>`
        chrdev_reg.as_mut().register::<RustFile>()?;
        chrdev_reg.as_mut().register::<RustFile>()?;

        Ok(RustChrdev { _dev: chrdev_reg })
    }
}

impl Drop for RustChrdev {
    fn drop(&mut self) {
        pr_info!("Rust character device sample (exit)\n");
    }
}
