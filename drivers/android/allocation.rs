// SPDX-License-Identifier: GPL-2.0

use alloc::sync::Arc;
use core::mem::{size_of, MaybeUninit};
use kernel::{bindings, pages::Pages, prelude::*, user_ptr::UserSlicePtrReader, Error};

use crate::{
    node::NodeRef,
    process::{AllocationInfo, Process},
    thread::{BinderError, BinderResult},
};

pub(crate) struct Allocation<'a> {
    pub(crate) offset: usize,
    size: usize,
    pub(crate) ptr: usize,
    pages: Arc<[Pages<0>]>,
    pub(crate) process: &'a Process,
    allocation_info: Option<AllocationInfo>,
    free_on_drop: bool,
}

impl<'a> Allocation<'a> {
    pub(crate) fn new(
        process: &'a Process,
        offset: usize,
        size: usize,
        ptr: usize,
        pages: Arc<[Pages<0>]>,
    ) -> Self {
        Self {
            process,
            offset,
            size,
            ptr,
            pages,
            allocation_info: None,
            free_on_drop: true,
        }
    }

    fn iterate<T>(&self, mut offset: usize, mut size: usize, mut cb: T) -> KernelResult
    where
        T: FnMut(&Pages<0>, usize, usize) -> KernelResult,
    {
        // Check that the request is within the buffer.
        if offset.checked_add(size).ok_or(Error::EINVAL)? > self.size {
            return Err(Error::EINVAL);
        }
        offset += self.offset;
        let mut page_index = offset >> bindings::PAGE_SHIFT;
        offset &= (1 << bindings::PAGE_SHIFT) - 1;
        while size > 0 {
            let available = core::cmp::min(size, (1 << bindings::PAGE_SHIFT) as usize - offset);
            cb(&self.pages[page_index], offset, available)?;
            size -= available;
            page_index += 1;
            offset = 0;
        }
        Ok(())
    }

    pub(crate) fn copy_into(
        &self,
        reader: &mut UserSlicePtrReader,
        offset: usize,
        size: usize,
    ) -> KernelResult {
        self.iterate(offset, size, |page, offset, to_copy| {
            page.copy_into_page(reader, offset, to_copy)
        })
    }

    pub(crate) fn read<T>(&self, offset: usize) -> KernelResult<T> {
        let mut out = MaybeUninit::<T>::uninit();
        let mut out_offset = 0;
        self.iterate(offset, size_of::<T>(), |page, offset, to_copy| {
            // SAFETY: Data buffer is allocated on the stack.
            unsafe {
                page.read(
                    (out.as_mut_ptr() as *mut u8).add(out_offset),
                    offset,
                    to_copy,
                )
            }?;
            out_offset += to_copy;
            Ok(())
        })?;
        // SAFETY: We just initialised the data.
        Ok(unsafe { out.assume_init() })
    }

    pub(crate) fn write<T>(&self, offset: usize, obj: &T) -> KernelResult {
        let mut obj_offset = 0;
        self.iterate(offset, size_of::<T>(), |page, offset, to_copy| {
            // SAFETY: The sum of `offset` and `to_copy` is bounded by the size of T.
            let obj_ptr = unsafe { (obj as *const T as *const u8).add(obj_offset) };
            // SAFETY: We have a reference to the object, so the pointer is valid.
            unsafe { page.write(obj_ptr, offset, to_copy) }?;
            obj_offset += to_copy;
            Ok(())
        })
    }

    pub(crate) fn keep_alive(mut self) {
        self.process
            .buffer_make_freeable(self.offset, self.allocation_info.take());
        self.free_on_drop = false;
    }

    pub(crate) fn set_info(&mut self, info: AllocationInfo) {
        self.allocation_info = Some(info);
    }

    fn cleanup_object(&self, index_offset: usize, view: &AllocationView) -> KernelResult {
        let offset = self.read(index_offset)?;
        let header = view.read::<bindings::binder_object_header>(offset)?;
        // TODO: Handle other types.
        match header.type_ {
            bindings::BINDER_TYPE_WEAK_BINDER | bindings::BINDER_TYPE_BINDER => {
                let obj = view.read::<bindings::flat_binder_object>(offset)?;
                let strong = header.type_ == bindings::BINDER_TYPE_BINDER;
                // SAFETY: The type is `BINDER_TYPE_{WEAK_}BINDER`, so the `binder` field is
                // populated.
                let ptr = unsafe { obj.__bindgen_anon_1.binder } as usize;
                let cookie = obj.cookie as usize;
                self.process.update_node(ptr, cookie, strong, false);
                Ok(())
            }
            bindings::BINDER_TYPE_WEAK_HANDLE | bindings::BINDER_TYPE_HANDLE => {
                let obj = view.read::<bindings::flat_binder_object>(offset)?;
                let strong = header.type_ == bindings::BINDER_TYPE_HANDLE;
                // SAFETY: The type is `BINDER_TYPE_{WEAK_}HANDLE`, so the `handle` field is
                // populated.
                let handle = unsafe { obj.__bindgen_anon_1.handle } as _;
                self.process.update_ref(handle, false, strong)
            }
            _ => Ok(()),
        }
    }
}

impl Drop for Allocation<'_> {
    fn drop(&mut self) {
        if !self.free_on_drop {
            return;
        }

        if let Some(info) = &self.allocation_info {
            let view = AllocationView::new(self, info.offsets.start);
            for i in info.offsets.clone().step_by(size_of::<usize>()) {
                if self.cleanup_object(i, &view).is_err() {
                    pr_warn!("Error cleaning up object at offset {}\n", i)
                }
            }
        }

        self.process.buffer_raw_free(self.ptr);
    }
}

pub(crate) struct AllocationView<'a> {
    alloc: &'a Allocation<'a>,
    limit: usize,
}

impl<'a> AllocationView<'a> {
    pub(crate) fn new(alloc: &'a Allocation, limit: usize) -> Self {
        AllocationView { alloc, limit }
    }

    pub fn read<T>(&self, offset: usize) -> KernelResult<T> {
        if offset.checked_add(size_of::<T>()).ok_or(Error::EINVAL)? > self.limit {
            return Err(Error::EINVAL);
        }
        self.alloc.read(offset)
    }

    pub fn write<T>(&self, offset: usize, obj: &T) -> KernelResult {
        if offset.checked_add(size_of::<T>()).ok_or(Error::EINVAL)? > self.limit {
            return Err(Error::EINVAL);
        }
        self.alloc.write(offset, obj)
    }

    pub(crate) fn transfer_binder_object<T>(
        &self,
        offset: usize,
        strong: bool,
        get_node: T,
    ) -> BinderResult
    where
        T: FnOnce(&bindings::flat_binder_object) -> BinderResult<NodeRef>,
    {
        // TODO: Do we want this function to take a &mut self?
        let obj = self.read::<bindings::flat_binder_object>(offset)?;
        let node_ref = get_node(&obj)?;

        if core::ptr::eq(&*node_ref.node.owner, self.alloc.process) {
            // The receiving process is the owner of the node, so send it a binder object (instead
            // of a handle).
            let (ptr, cookie) = node_ref.node.get_id();
            let newobj = bindings::flat_binder_object {
                hdr: bindings::binder_object_header {
                    type_: if strong {
                        bindings::BINDER_TYPE_BINDER
                    } else {
                        bindings::BINDER_TYPE_WEAK_BINDER
                    },
                },
                flags: obj.flags,
                __bindgen_anon_1: bindings::flat_binder_object__bindgen_ty_1 { binder: ptr as _ },
                cookie: cookie as _,
            };
            self.write(offset, &newobj)?;

            // Increment the user ref count on the node. It will be decremented as part of the
            // destruction of the buffer, when we see a binder or weak-binder object.
            node_ref.node.update_refcount(true, strong);
        } else {
            // The receiving process is different from the owner, so we need to insert a handle to
            // the binder object.
            let handle = self
                .alloc
                .process
                .insert_or_update_handle(node_ref, false)?;

            let newobj = bindings::flat_binder_object {
                hdr: bindings::binder_object_header {
                    type_: if strong {
                        bindings::BINDER_TYPE_HANDLE
                    } else {
                        bindings::BINDER_TYPE_WEAK_HANDLE
                    },
                },
                flags: obj.flags,
                // TODO: To avoid padding, we write to `binder` instead of `handle` here. We need a
                // better solution though.
                __bindgen_anon_1: bindings::flat_binder_object__bindgen_ty_1 {
                    binder: handle as _,
                },
                ..bindings::flat_binder_object::default()
            };
            if self.write(offset, &newobj).is_err() {
                // Decrement ref count on the handle we just created.
                let _ = self.alloc.process.update_ref(handle, false, strong);
                return Err(BinderError::new_failed());
            }
        }
        Ok(())
    }
}
