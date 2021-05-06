// SPDX-License-Identifier: GPL-2.0

extern crate alloc;

use alloc::sync::Arc;
use core::pin::Pin;
use kernel::{bindings, prelude::*, sync::Mutex, Error};

use crate::{
    node::NodeRef,
    thread::{BinderError, BinderResult},
};

struct Manager {
    node: Option<NodeRef>,
    uid: Option<bindings::kuid_t>,
}

pub(crate) struct Context {
    manager: Mutex<Manager>,
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    pub(crate) fn new() -> KernelResult<Pin<Arc<Self>>> {
        let mut ctx_ref = Arc::try_new(Self {
            // SAFETY: Init is called below.
            manager: unsafe {
                Mutex::new(Manager {
                    node: None,
                    uid: None,
                })
            },
        })?;
        let ctx = Arc::get_mut(&mut ctx_ref).unwrap();

        // SAFETY: `manager` is also pinned when `ctx` is.
        let manager = unsafe { Pin::new_unchecked(&ctx.manager) };
        kernel::mutex_init!(manager, "Context::manager");

        // SAFETY: `ctx_ref` is pinned behind the `Arc` reference.
        Ok(unsafe { Pin::new_unchecked(ctx_ref) })
    }

    pub(crate) fn set_manager_node(&self, node_ref: NodeRef) -> KernelResult {
        let mut manager = self.manager.lock();
        if manager.node.is_some() {
            return Err(Error::EBUSY);
        }
        // TODO: Call security_binder_set_context_mgr.

        // TODO: Get the actual caller id.
        let caller_uid = bindings::kuid_t::default();
        if let Some(ref uid) = manager.uid {
            if uid.val != caller_uid.val {
                return Err(Error::EPERM);
            }
        }

        manager.node = Some(node_ref);
        manager.uid = Some(caller_uid);
        Ok(())
    }

    pub(crate) fn unset_manager_node(&self) {
        let node_ref = self.manager.lock().node.take();
        drop(node_ref);
    }

    pub(crate) fn get_manager_node(&self, strong: bool) -> BinderResult<NodeRef> {
        self.manager
            .lock()
            .node
            .as_ref()
            .ok_or_else(BinderError::new_dead)?
            .clone(strong)
    }
}
