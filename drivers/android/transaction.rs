// SPDX-License-Identifier: GPL-2.0

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel::{bindings, linked_list::Links, prelude::*, sync::Ref, user_ptr::UserSlicePtrWriter};

use crate::{
    defs::*,
    node::NodeRef,
    process::Process,
    ptr_align,
    thread::{BinderResult, Thread},
    DeliverToRead, Either,
};

pub(crate) struct Transaction {
    // TODO: Node should be released when the buffer is released.
    node_ref: Option<NodeRef>,
    stack_next: Option<Arc<Transaction>>,
    pub(crate) from: Arc<Thread>,
    to: Ref<Process>,
    free_allocation: AtomicBool,
    code: u32,
    flags: u32,
    data_size: usize,
    offsets_size: usize,
    data_address: usize,
    links: Links<dyn DeliverToRead>,
}

impl Transaction {
    pub(crate) fn new(
        node_ref: NodeRef,
        stack_next: Option<Arc<Transaction>>,
        from: &Arc<Thread>,
        tr: &BinderTransactionData,
    ) -> BinderResult<Self> {
        let to = node_ref.node.owner.clone();
        let alloc = from.copy_transaction_data(&to, tr)?;
        let data_address = alloc.ptr;
        alloc.keep_alive();
        Ok(Self {
            node_ref: Some(node_ref),
            stack_next,
            from: from.clone(),
            to,
            code: tr.code,
            flags: tr.flags,
            data_size: tr.data_size as _,
            data_address,
            offsets_size: tr.offsets_size as _,
            links: Links::new(),
            free_allocation: AtomicBool::new(true),
        })
    }

    pub(crate) fn new_reply(
        from: &Arc<Thread>,
        to: Ref<Process>,
        tr: &BinderTransactionData,
    ) -> BinderResult<Self> {
        let alloc = from.copy_transaction_data(&to, tr)?;
        let data_address = alloc.ptr;
        alloc.keep_alive();
        Ok(Self {
            node_ref: None,
            stack_next: None,
            from: from.clone(),
            to,
            code: tr.code,
            flags: tr.flags,
            data_size: tr.data_size as _,
            data_address,
            offsets_size: tr.offsets_size as _,
            links: Links::new(),
            free_allocation: AtomicBool::new(true),
        })
    }

    /// Determines if the transaction is stacked on top of the given transaction.
    pub(crate) fn is_stacked_on(&self, onext: &Option<Arc<Self>>) -> bool {
        match (&self.stack_next, onext) {
            (None, None) => true,
            (Some(stack_next), Some(next)) => Arc::ptr_eq(stack_next, next),
            _ => false,
        }
    }

    /// Returns a pointer to the next transaction on the transaction stack, if there is one.
    pub(crate) fn clone_next(&self) -> Option<Arc<Self>> {
        let next = self.stack_next.as_ref()?;
        Some(next.clone())
    }

    /// Searches in the transaction stack for a thread that belongs to the target process. This is
    /// useful when finding a target for a new transaction: if the node belongs to a process that
    /// is already part of the transaction stack, we reuse the thread.
    fn find_target_thread(&self) -> Option<Arc<Thread>> {
        let process = &self.node_ref.as_ref()?.node.owner;

        let mut it = &self.stack_next;
        while let Some(transaction) = it {
            if Ref::ptr_eq(&transaction.from.process, process) {
                return Some(transaction.from.clone());
            }
            it = &transaction.stack_next;
        }
        None
    }

    /// Searches in the transaction stack for a transaction originating at the given thread.
    pub(crate) fn find_from(&self, thread: &Thread) -> Option<Arc<Transaction>> {
        let mut it = &self.stack_next;
        while let Some(transaction) = it {
            if core::ptr::eq(thread, transaction.from.as_ref()) {
                return Some(transaction.clone());
            }

            it = &transaction.stack_next;
        }
        None
    }

    /// Submits the transaction to a work queue. Use a thread if there is one in the transaction
    /// stack, otherwise use the destination process.
    pub(crate) fn submit(self: Arc<Self>) -> BinderResult {
        if let Some(thread) = self.find_target_thread() {
            thread.push_work(self)
        } else {
            let process = self.to.clone();
            process.push_work(self)
        }
    }
}

impl DeliverToRead for Transaction {
    fn do_work(
        self: Arc<Self>,
        thread: &Thread,
        writer: &mut UserSlicePtrWriter,
    ) -> KernelResult<bool> {
        /* TODO: Initialise the following fields from tr:
            pub sender_pid: pid_t,
            pub sender_euid: uid_t,
        */
        let mut tr = BinderTransactionData::default();

        if let Some(nref) = &self.node_ref {
            let (ptr, cookie) = nref.node.get_id();
            tr.target.ptr = ptr as _;
            tr.cookie = cookie as _;
        };

        tr.code = self.code;
        tr.flags = self.flags;
        tr.data_size = self.data_size as _;
        tr.data.ptr.buffer = self.data_address as _;
        tr.offsets_size = self.offsets_size as _;
        if tr.offsets_size > 0 {
            tr.data.ptr.offsets = (self.data_address + ptr_align(self.data_size)) as _;
        }

        // When `drop` is called, we don't want the allocation to be freed because it is now the
        // user's reponsibility to free it.
        self.free_allocation.store(false, Ordering::Relaxed);

        let code = if self.node_ref.is_none() {
            BR_REPLY
        } else {
            BR_TRANSACTION
        };

        // Write the transaction code and data to the user buffer. On failure we complete the
        // transaction with an error.
        if let Err(err) = writer.write(&code).and_then(|_| writer.write(&tr)) {
            let reply = Either::Right(BR_FAILED_REPLY);
            self.from.deliver_reply(reply, &self);
            return Err(err);
        }

        // When this is not a reply and not an async transaction, update `current_transaction`. If
        // it's a reply, `current_transaction` has already been updated appropriately.
        if self.node_ref.is_some() && tr.flags & bindings::transaction_flags_TF_ONE_WAY == 0 {
            thread.set_current_transaction(self);
        }

        Ok(false)
    }

    fn cancel(self: Arc<Self>) {
        let reply = Either::Right(BR_DEAD_REPLY);
        self.from.deliver_reply(reply, &self);
    }

    fn get_links(&self) -> &Links<dyn DeliverToRead> {
        &self.links
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if self.free_allocation.load(Ordering::Relaxed) {
            self.to.buffer_get(self.data_address);
        }
    }
}
