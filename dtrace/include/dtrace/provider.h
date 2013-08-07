#ifndef _DTRACE_PROVIDER_H
#define _DTRACE_PROVIDER_H

/*
 * DTrace Dynamic Tracing Software: DTrace Provider API
 *
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2009 -- 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The following functions are implemented by the DTrace framework and are
 * used to implement separate in-kernel DTrace providers.
 *
 * The provider API has two halves:  the API that the providers consume from
 * DTrace, and the API that providers make available to DTrace.
 *
 * 1 Framework-to-Provider API
 *
 * 1.1  Overview
 *
 * The Framework-to-Provider API is represented by the dtrace_pops structure
 * that the provider passes to the framework when registering itself.  This
 * structure consists of the following members:
 *
 *   dtps_provide()          <-- Provide all probes, all modules
 *   dtps_provide_module()   <-- Provide all probes in specified module
 *   dtps_enable()           <-- Enable specified probe
 *   dtps_disable()          <-- Disable specified probe
 *   dtps_suspend()          <-- Suspend specified probe
 *   dtps_resume()           <-- Resume specified probe
 *   dtps_getargdesc()       <-- Get the argument description for args[X]
 *   dtps_getargval()        <-- Get the value for an argX or args[X] variable
 *   dtps_usermode()         <-- Find out if the probe was fired in user mode
 *   dtps_destroy()          <-- Destroy all state associated with this probe
 *
 * 1.2  void dtps_provide(void *arg, const dtrace_probedesc_t *spec)
 *
 * 1.2.1  Overview
 *
 *   Called to indicate that the provider should provide all probes.  If the
 *   specified description is non-NULL, dtps_provide() is being called because
 *   no probe matched a specified probe -- if the provider has the ability to
 *   create custom probes, it may wish to create a probe that matches the
 *   specified description.
 *
 * 1.2.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register().  The
 *   second argument is a pointer to a probe description that the provider may
 *   wish to consider when creating custom probes.  The provider is expected to
 *   call back into the DTrace framework via dtrace_probe_create() to create
 *   any necessary probes.  dtps_provide() may be called even if the provider
 *   has made available all probes; the provider should check the return value
 *   of dtrace_probe_create() to handle this case.  Note that the provider need
 *   not implement both dtps_provide() and dtps_provide_module(); see
 *   "Arguments and Notes" for dtrace_register(), below.
 *
 * 1.2.3  Return value
 *
 *   None.
 *
 * 1.2.4  Caller's context
 *
 *   dtps_provide() is typically called from open() or ioctl() context, but may
 *   be called from other contexts as well.  The DTrace framework is locked in
 *   such a way that providers may not register or unregister.  This means that
 *   the provider may not call any DTrace API that affects its registration with
 *   the framework, including dtrace_register(), dtrace_unregister(),
 *   dtrace_invalidate(), and dtrace_condense().  However, the context is such
 *   that the provider may (and indeed, is expected to) call probe-related
 *   DTrace routines, including dtrace_probe_create(), dtrace_probe_lookup(),
 *   and dtrace_probe_arg().
 *
 * 1.3  void dtps_provide_module(void *arg, struct modctl *mp)
 *
 * 1.3.1  Overview
 *
 *   Called to indicate that the provider should provide all probes in the
 *   specified module.
 *
 * 1.3.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register().  The
 *   second argument is a pointer to a modctl structure that indicates the
 *   module for which probes should be created.
 *
 * 1.3.3  Return value
 *
 *   None.
 *
 * 1.3.4  Caller's context
 *
 *   dtps_provide_module() may be called from open() or ioctl() context, but
 *   may also be called from a module loading context.  mod_lock is held, and
 *   the DTrace framework is locked in such a way that providers may not
 *   register or unregister.  This means that the provider may not call any
 *   DTrace API that affects its registration with the framework, including
 *   dtrace_register(), dtrace_unregister(), dtrace_invalidate(), and
 *   dtrace_condense().  However, the context is such that the provider may (and
 *   indeed, is expected to) call probe-related DTrace routines, including
 *   dtrace_probe_create(), dtrace_probe_lookup(), and dtrace_probe_arg().  Note
 *   that the provider need not implement both dtps_provide() and
 *   dtps_provide_module(); see "Arguments and Notes" for dtrace_register(),
 *   below.
 *
 * 1.4  int dtps_enable(void *arg, dtrace_id_t id, void *parg)
 *
 * 1.4.1  Overview
 *
 *   Called to enable the specified probe.
 *
 * 1.4.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register().  The
 *   second argument is the identifier of the probe to be enabled.  The third
 *   argument is the probe argument as passed to dtrace_probe_create().
 *   dtps_enable() will be called when a probe transitions from not being
 *   enabled at all to having one or more ECB.  The number of ECBs associated
 *   with the probe may change without subsequent calls into the provider.
 *   When the number of ECBs drops to zero, the provider will be explicitly
 *   told to disable the probe via dtps_disable().  dtrace_probe() should never
 *   be called for a probe identifier that hasn't been explicitly enabled via
 *   dtps_enable().
 *
 * 1.4.3  Return value
 *
 *   On success, dtps_enable() should return 0. On failure, -1 should be
 *   returned.
 *
 * 1.4.4  Caller's context
 *
 *   The DTrace framework is locked in such a way that it may not be called
 *   back into at all.  cpu_lock is held.  mod_lock is not held and may not
 *   be acquired.
 *
 * 1.5  void dtps_disable(void *arg, dtrace_id_t id, void *parg)
 *
 * 1.5.1  Overview
 *
 *   Called to disable the specified probe.
 *
 * 1.5.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register().  The
 *   second argument is the identifier of the probe to be disabled.  The third
 *   argument is the probe argument as passed to dtrace_probe_create().
 *   dtps_disable() will be called when a probe transitions from being enabled
 *   to having zero ECBs.  dtrace_probe() should never be called for a probe
 *   identifier that has been explicitly enabled via dtps_disable().
 *
 * 1.5.3  Return value
 *
 *   None.
 *
 * 1.5.4  Caller's context
 *
 *   The DTrace framework is locked in such a way that it may not be called
 *   back into at all.  cpu_lock is held.  mod_lock is not held and may not
 *   be acquired.
 *
 * 1.6  void dtps_suspend(void *arg, dtrace_id_t id, void *parg)
 *
 * 1.6.1  Overview
 *
 *   Called to suspend the specified enabled probe.  This entry point is for
 *   providers that may need to suspend some or all of their probes when CPUs
 *   are being powered on or when the boot monitor is being entered for a
 *   prolonged period of time.
 *
 * 1.6.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register().  The
 *   second argument is the identifier of the probe to be suspended.  The
 *   third argument is the probe argument as passed to dtrace_probe_create().
 *   dtps_suspend will only be called on an enabled probe.  Providers that
 *   provide a dtps_suspend entry point will want to take roughly the action
 *   that it takes for dtps_disable.
 *
 * 1.6.3  Return value
 *
 *   None.
 *
 * 1.6.4  Caller's context
 *
 *   Interrupts are disabled.  The DTrace framework is in a state such that the
 *   specified probe cannot be disabled or destroyed for the duration of
 *   dtps_suspend().  As interrupts are disabled, the provider is afforded
 *   little latitude; the provider is expected to do no more than a store to
 *   memory.
 *
 * 1.7  void dtps_resume(void *arg, dtrace_id_t id, void *parg)
 *
 * 1.7.1  Overview
 *
 *   Called to resume the specified enabled probe.  This entry point is for
 *   providers that may need to resume some or all of their probes after the
 *   completion of an event that induced a call to dtps_suspend().
 *
 * 1.7.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register().  The
 *   second argument is the identifier of the probe to be resumed.  The
 *   third argument is the probe argument as passed to dtrace_probe_create().
 *   dtps_resume will only be called on an enabled probe.  Providers that
 *   provide a dtps_resume entry point will want to take roughly the action
 *   that it takes for dtps_enable.
 *
 * 1.7.3  Return value
 *
 *   None.
 *
 * 1.7.4  Caller's context
 *
 *   Interrupts are disabled.  The DTrace framework is in a state such that the
 *   specified probe cannot be disabled or destroyed for the duration of
 *   dtps_resume().  As interrupts are disabled, the provider is afforded
 *   little latitude; the provider is expected to do no more than a store to
 *   memory.
 *
 * 1.8  void dtps_getargdesc(void *arg, dtrace_id_t id, void *parg,
 *           dtrace_argdesc_t *desc)
 *
 * 1.8.1  Overview
 *
 *   Called to retrieve the argument description for an args[X] variable.
 *
 * 1.8.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register(). The
 *   second argument is the identifier of the current probe. The third
 *   argument is the probe argument as passed to dtrace_probe_create(). The
 *   fourth argument is a pointer to the argument description.  This
 *   description is both an input and output parameter:  it contains the
 *   index of the desired argument in the dtargd_ndx field, and expects
 *   the other fields to be filled in upon return.  If there is no argument
 *   corresponding to the specified index, the dtargd_ndx field should be set
 *   to DTRACE_ARGNONE.
 *
 * 1.8.3  Return value
 *
 *   None.  The dtargd_ndx, dtargd_native, dtargd_xlate and dtargd_mapping
 *   members of the dtrace_argdesc_t structure are all output values.
 *
 * 1.8.4  Caller's context
 *
 *   dtps_getargdesc() is called from ioctl() context. mod_lock is held, and
 *   the DTrace framework is locked in such a way that providers may not
 *   register or unregister.  This means that the provider may not call any
 *   DTrace API that affects its registration with the framework, including
 *   dtrace_register(), dtrace_unregister(), dtrace_invalidate(), and
 *   dtrace_condense().
 *
 * 1.9  uint64_t dtps_getargval(void *arg, dtrace_id_t id, void *parg,
 *               int argno, int aframes)
 *
 * 1.9.1  Overview
 *
 *   Called to retrieve a value for an argX or args[X] variable.
 *
 * 1.9.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register(). The
 *   second argument is the identifier of the current probe. The third
 *   argument is the probe argument as passed to dtrace_probe_create(). The
 *   fourth argument is the number of the argument (the X in the example in
 *   1.9.1). The fifth argument is the number of stack frames that were used
 *   to get from the actual place in the code that fired the probe to
 *   dtrace_probe() itself, the so-called artificial frames. This argument may
 *   be used to descend an appropriate number of frames to find the correct
 *   values. If this entry point is left NULL, the dtrace_getarg() built-in
 *   function is used.
 *
 * 1.9.3  Return value
 *
 *   The value of the argument.
 *
 * 1.9.4  Caller's context
 *
 *   This is called from within dtrace_probe() meaning that interrupts
 *   are disabled. No locks should be taken within this entry point.
 *
 * 1.10  int dtps_usermode(void *arg, dtrace_id_t id, void *parg)
 *
 * 1.10.1  Overview
 *
 *   Called to determine if the probe was fired in a user context.
 *
 * 1.10.2  Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register(). The
 *   second argument is the identifier of the current probe. The third
 *   argument is the probe argument as passed to dtrace_probe_create().  This
 *   entry point must not be left NULL for providers whose probes allow for
 *   mixed mode tracing, that is to say those probes that can fire during
 *   kernel- _or_ user-mode execution
 *
 * 1.10.3  Return value
 *
 *   A boolean value.
 *
 * 1.10.4  Caller's context
 *
 *   This is called from within dtrace_probe() meaning that interrupts
 *   are disabled. No locks should be taken within this entry point.
 *
 * 1.11 void dtps_destroy(void *arg, dtrace_id_t id, void *parg)
 *
 * 1.11.1 Overview
 *
 *   Called to destroy the specified probe.
 *
 * 1.11.2 Arguments and notes
 *
 *   The first argument is the cookie as passed to dtrace_register().  The
 *   second argument is the identifier of the probe to be destroyed.  The third
 *   argument is the probe argument as passed to dtrace_probe_create().  The
 *   provider should free all state associated with the probe.  The framework
 *   guarantees that dtps_destroy() is only called for probes that have either
 *   been disabled via dtps_disable() or were never enabled via dtps_enable().
 *   Once dtps_disable() has been called for a probe, no further call will be
 *   made specifying the probe.
 *
 * 1.11.3 Return value
 *
 *   None.
 *
 * 1.11.4 Caller's context
 *
 *   The DTrace framework is locked in such a way that it may not be called
 *   back into at all.  mod_lock is held.  cpu_lock is not held, and may not be
 *   acquired.
 *
 *
 * 2 Provider-to-Framework API
 *
 * 2.1  Overview
 *
 * The Provider-to-Framework API provides the mechanism for the provider to
 * register itself with the DTrace framework, to create probes, to lookup
 * probes and (most importantly) to fire probes.  The Provider-to-Framework
 * consists of:
 *
 *   dtrace_register()       <-- Register a provider with the DTrace framework
 *   dtrace_unregister()     <-- Remove a provider's DTrace registration
 *   dtrace_meta_register()  <-- Register a metaprovider with the DTrace framework
 *   dtrace_meta_unregister()<-- Remove a metaprovider's DTrace registration
 *   dtrace_invalidate()     <-- Invalidate the specified provider
 *   dtrace_condense()       <-- Remove a provider's unenabled probes
 *   dtrace_attached()       <-- Indicates whether or not DTrace has attached
 *   dtrace_probe_create()   <-- Create a DTrace probe
 *   dtrace_probe_lookup()   <-- Lookup a DTrace probe based on its name
 *   dtrace_probe_arg()      <-- Return the probe argument for a specific probe
 *   dtrace_probe()          <-- Fire the specified probe
 *
 * 2.2  int dtrace_register(const char *name, const dtrace_pattr_t *pap,
 *          uint32_t priv, cred_t *cr, const dtrace_pops_t *pops, void *arg,
 *          dtrace_provider_id_t *idp)
 *
 * 2.2.1  Overview
 *
 *   dtrace_register() registers the calling provider with the DTrace
 *   framework.  It should generally be called by DTrace providers in their
 *   attach(9E) entry point.
 *
 * 2.2.2  Arguments and Notes
 *
 *   The first argument is the name of the provider.  The second argument is a
 *   pointer to the stability attributes for the provider.  The third argument
 *   is the privilege flags for the provider, and must be some combination of:
 *
 *     DTRACE_PRIV_NONE     <= All users may enable probes from this provider
 *
 *     DTRACE_PRIV_PROC     <= Any user with privilege of PRIV_DTRACE_PROC may
 *                             enable probes from this provider
 *
 *     DTRACE_PRIV_USER     <= Any user with privilege of PRIV_DTRACE_USER may
 *                             enable probes from this provider
 *
 *     DTRACE_PRIV_KERNEL   <= Any user with privilege of PRIV_DTRACE_KERNEL
 *                             may enable probes from this provider
 *
 *     DTRACE_PRIV_OWNER    <= This flag places an additional constraint on
 *                             the privilege requirements above. These probes
 *                             require either (a) a user ID matching the user
 *                             ID of the cred passed in the fourth argument
 *                             or (b) the PRIV_PROC_OWNER privilege.
 *
 *   Note that these flags designate the _visibility_ of the probes, not
 *   the conditions under which they may or may not fire.
 *
 *   The fourth argument is the credential that is associated with the provider.
 *   This argument should be NULL if the privilege flags don't include
 *   DTRACE_PRIV_OWNER. If non-NULL, the framework stashes the uid represented
 *   by this credential for use at probe-time, in implicit predicates. These
 *   limit visibility of the probes to users which have sufficient privilege to
 *   access them.
 *
 *   The fifth argument is a DTrace provider operations vector, which provides
 *   the implementation for the Framework-to-Provider API.  (See Section 1,
 *   above.)  This must be non-NULL, and each member must be non-NULL.  The
 *   exceptions to this are (1) the dtps_provide() and dtps_provide_module()
 *   members (if the provider so desires, _one_ of these members may be left
 *   NULL -- denoting that the provider only implements the other) and (2)
 *   the dtps_suspend() and dtps_resume() members, which must either both be
 *   NULL or both be non-NULL.
 *
 *   The sixth argument is a cookie to be specified as the first argument for
 *   each function in the Framework-to-Provider API.  This argument may have
 *   any value.
 *
 *   The final argument is a pointer to dtrace_provider_id_t.  If
 *   dtrace_register() successfully completes, the provider identifier will be
 *   stored in the memory pointed to be this argument.  This argument must be
 *   non-NULL.
 *
 * 2.2.3  Return value
 *
 *   On success, dtrace_register() returns 0 and stores the new provider's
 *   identifier into the memory pointed to by the idp argument.  On failure,
 *   dtrace_register() returns an errno:
 *
 *     EINVAL   The arguments passed to dtrace_register() were somehow invalid.
 *              This may because a parameter that must be non-NULL was NULL,
 *              because the name was invalid (either empty or an illegal
 *              provider name) or because the attributes were invalid.
 *
 *   No other failure code is returned.
 *
 * 2.2.4  Caller's context
 *
 *   dtrace_register() may induce calls to dtrace_provide(); the provider must
 *   hold no locks across dtrace_register() that may also be acquired by
 *   dtrace_provide().  cpu_lock and mod_lock must not be held.
 *
 * 2.3  int dtrace_unregister(dtrace_provider_t id)
 *
 * 2.3.1  Overview
 *
 *   Unregisters the specified provider from the DTrace framework.  It should
 *   generally be called by DTrace providers in their detach(9E) entry point.
 *
 * 2.3.2  Arguments and Notes
 *
 *   The only argument is the provider identifier, as returned from a
 *   successful call to dtrace_register().  As a result of calling
 *   dtrace_unregister(), the DTrace framework will call back into the provider
 *   via the dtps_destroy() entry point.  Once dtrace_unregister() successfully
 *   completes, however, the DTrace framework will no longer make calls through
 *   the Framework-to-Provider API.
 *
 * 2.3.3  Return value
 *
 *   On success, dtrace_unregister returns 0.  On failure, dtrace_unregister()
 *   returns an errno:
 *
 *     EBUSY    There are currently processes that have the DTrace pseudodevice
 *              open, or there exists an anonymous enabling that hasn't yet
 *              been claimed.
 *
 *   No other failure code is returned.
 *
 * 2.3.4  Caller's context
 *
 *   Because a call to dtrace_unregister() may induce calls through the
 *   Framework-to-Provider API, the caller may not hold any lock across
 *   dtrace_register() that is also acquired in any of the Framework-to-
 *   Provider API functions.  Additionally, mod_lock may not be held.
 *
 * 2.4  void dtrace_invalidate(dtrace_provider_id_t id)
 *
 * 2.4.1  Overview
 *
 *   Invalidates the specified provider.  All subsequent probe lookups for the
 *   specified provider will fail, but its probes will not be removed.
 *
 * 2.4.2  Arguments and note
 *
 *   The only argument is the provider identifier, as returned from a
 *   successful call to dtrace_register().  In general, a provider's probes
 *   always remain valid; dtrace_invalidate() is a mechanism for invalidating
 *   an entire provider, regardless of whether or not probes are enabled or
 *   not.  Note that dtrace_invalidate() will _not_ prevent already enabled
 *   probes from firing -- it will merely prevent any new enablings of the
 *   provider's probes.
 *
 * 2.5 int dtrace_condense(dtrace_provider_id_t id)
 *
 * 2.5.1  Overview
 *
 *   Removes all the unenabled probes for the given provider. This function is
 *   not unlike dtrace_unregister(), except that it doesn't remove the
 *   provider just as many of its associated probes as it can.
 *
 * 2.5.2  Arguments and Notes
 *
 *   As with dtrace_unregister(), the sole argument is the provider identifier
 *   as returned from a successful call to dtrace_register().  As a result of
 *   calling dtrace_condense(), the DTrace framework will call back into the
 *   given provider's dtps_destroy() entry point for each of the provider's
 *   unenabled probes.
 *
 * 2.5.3  Return value
 *
 *   Currently, dtrace_condense() always returns 0.  However, consumers of this
 *   function should check the return value as appropriate; its behavior may
 *   change in the future.
 *
 * 2.5.4  Caller's context
 *
 *   As with dtrace_unregister(), the caller may not hold any lock across
 *   dtrace_condense() that is also acquired in the provider's entry points.
 *   Also, mod_lock may not be held.
 *
 * 2.6 int dtrace_attached()
 *
 * 2.6.1  Overview
 *
 *   Indicates whether or not DTrace has attached.
 *
 * 2.6.2  Arguments and Notes
 *
 *   For most providers, DTrace makes initial contact beyond registration.
 *   That is, once a provider has registered with DTrace, it waits to hear
 *   from DTrace to create probes.  However, some providers may wish to
 *   proactively create probes without first being told by DTrace to do so.
 *   If providers wish to do this, they must first call dtrace_attached() to
 *   determine if DTrace itself has attached.  If dtrace_attached() returns 0,
 *   the provider must not make any other Provider-to-Framework API call.
 *
 * 2.6.3  Return value
 *
 *   dtrace_attached() returns 1 if DTrace has attached, 0 otherwise.
 *
 * 2.7  int dtrace_probe_create(dtrace_provider_t id, const char *mod,
 *	    const char *func, const char *name, int aframes, void *arg)
 *
 * 2.7.1  Overview
 *
 *   Creates a probe with specified module name, function name, and name.
 *
 * 2.7.2  Arguments and Notes
 *
 *   The first argument is the provider identifier, as returned from a
 *   successful call to dtrace_register().  The second, third, and fourth
 *   arguments are the module name, function name, and probe name,
 *   respectively.  Of these, module name and function name may both be NULL
 *   (in which case the probe is considered to be unanchored), or they may both
 *   be non-NULL.  The name must be non-NULL, and must point to a non-empty
 *   string.
 *
 *   The fifth argument is the number of artificial stack frames that will be
 *   found on the stack when dtrace_probe() is called for the new probe.  These
 *   artificial frames will be automatically be pruned should the stack() or
 *   stackdepth() functions be called as part of one of the probe's ECBs.  If
 *   the parameter doesn't add an artificial frame, this parameter should be
 *   zero.
 *
 *   The final argument is a probe argument that will be passed back to the
 *   provider when a probe-specific operation is called.  (e.g., via
 *   dtps_enable(), dtps_disable(), etc.)
 *
 *   Note that it is up to the provider to be sure that the probe that it
 *   creates does not already exist -- if the provider is unsure of the probe's
 *   existence, it should assure its absence with dtrace_probe_lookup() before
 *   calling dtrace_probe_create().
 *
 * 2.7.3  Return value
 *
 *   dtrace_probe_create() always succeeds, and always returns the identifier
 *   of the newly-created probe.
 *
 * 2.7.4  Caller's context
 *
 *   While dtrace_probe_create() is generally expected to be called from
 *   dtps_provide() and/or dtps_provide_module(), it may be called from other
 *   non-DTrace contexts.  Neither cpu_lock nor mod_lock may be held.
 *
 * 2.8  dtrace_id_t dtrace_probe_lookup(dtrace_provider_t id, const char *mod,
 *	    const char *func, const char *name)
 *
 * 2.8.1  Overview
 *
 *   Looks up a probe based on provdider and one or more of module name,
 *   function name and probe name.
 *
 * 2.8.2  Arguments and Notes
 *
 *   The first argument is the provider identifier, as returned from a
 *   successful call to dtrace_register().  The second, third, and fourth
 *   arguments are the module name, function name, and probe name,
 *   respectively.  Any of these may be NULL; dtrace_probe_lookup() will return
 *   the identifier of the first probe that is provided by the specified
 *   provider and matches all of the non-NULL matching criteria.
 *   dtrace_probe_lookup() is generally used by a provider to be check the
 *   existence of a probe before creating it with dtrace_probe_create().
 *
 * 2.8.3  Return value
 *
 *   If the probe exists, returns its identifier.  If the probe does not exist,
 *   return DTRACE_IDNONE.
 *
 * 2.8.4  Caller's context
 *
 *   While dtrace_probe_lookup() is generally expected to be called from
 *   dtps_provide() and/or dtps_provide_module(), it may also be called from
 *   other non-DTrace contexts.  Neither cpu_lock nor mod_lock may be held.
 *
 * 2.9  void *dtrace_probe_arg(dtrace_provider_t id, dtrace_id_t probe)
 *
 * 2.9.1  Overview
 *
 *   Returns the probe argument associated with the specified probe.
 *
 * 2.9.2  Arguments and Notes
 *
 *   The first argument is the provider identifier, as returned from a
 *   successful call to dtrace_register().  The second argument is a probe
 *   identifier, as returned from dtrace_probe_lookup() or
 *   dtrace_probe_create().  This is useful if a probe has multiple
 *   provider-specific components to it:  the provider can create the probe
 *   once with provider-specific state, and then add to the state by looking
 *   up the probe based on probe identifier.
 *
 * 2.9.3  Return value
 *
 *   Returns the argument associated with the specified probe.  If the
 *   specified probe does not exist, or if the specified probe is not provided
 *   by the specified provider, NULL is returned.
 *
 * 2.9.4  Caller's context
 *
 *   While dtrace_probe_arg() is generally expected to be called from
 *   dtps_provide() and/or dtps_provide_module(), it may also be called from
 *   other non-DTrace contexts.  Neither cpu_lock nor mod_lock may be held.
 *
 * 2.10  void dtrace_probe(dtrace_id_t probe, uintptr_t arg0, uintptr_t arg1,
 *		uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
 *
 * 2.10.1  Overview
 *
 *   The epicenter of DTrace:  fires the specified probes with the specified
 *   arguments.
 *
 * 2.10.2  Arguments and Notes
 *
 *   The first argument is a probe identifier as returned by
 *   dtrace_probe_create() or dtrace_probe_lookup().  The second through sixth
 *   arguments are the values to which the D variables "arg0" through "arg4"
 *   will be mapped.
 *
 *   dtrace_probe() should be called whenever the specified probe has fired --
 *   however the provider defines it.
 *
 * 2.10.3  Return value
 *
 *   None.
 *
 * 2.10.4  Caller's context
 *
 *   dtrace_probe() may be called in virtually any context:  kernel, user,
 *   interrupt, high-level interrupt, with arbitrary adaptive locks held, with
 *   dispatcher locks held, with interrupts disabled, etc.  The only latitude
 *   that must be afforded to DTrace is the ability to make calls within
 *   itself (and to its in-kernel subroutines) and the ability to access
 *   arbitrary (but mapped) memory.  On some platforms, this constrains
 *   context.  For example, on UltraSPARC, dtrace_probe() cannot be called
 *   from any context in which TL is greater than zero.  dtrace_probe() may
 *   also not be called from any routine which may be called by dtrace_probe()
 *   -- which includes functions in the DTrace framework and some in-kernel
 *   DTrace subroutines.  All such functions "dtrace_"; providers that
 *   instrument the kernel arbitrarily should be sure to not instrument these
 *   routines.
 */

#include <dtrace/types.h>
#include <linux/module.h>
#include <linux/dtrace/enabling_defines.h>
#include <linux/dtrace/arg_defines.h>
#include <dtrace/provider_defines.h>
#include <linux/dtrace/stability.h>

typedef struct dtrace_pops {
	void (*dtps_provide)(void *, const struct dtrace_probedesc *);
	void (*dtps_provide_module)(void *, struct module *);
	int (*dtps_enable)(void *, dtrace_id_t, void *);
	void (*dtps_disable)(void *, dtrace_id_t, void *);
	void (*dtps_suspend)(void *, dtrace_id_t, void *);
	void (*dtps_resume)(void *, dtrace_id_t, void *);
	void (*dtps_getargdesc)(void *, dtrace_id_t, void *,
				struct dtrace_argdesc *);
	uint64_t (*dtps_getargval)(void *, dtrace_id_t, void *, int, int);
	int (*dtps_usermode)(void *, dtrace_id_t, void *);
	void (*dtps_destroy)(void *, dtrace_id_t, void *);
} dtrace_pops_t;

typedef struct dtrace_helper_probedesc {
	char *dthpb_mod;
	char *dthpb_func;
	char *dthpb_name;
	uint64_t dthpb_base;
	uint32_t *dthpb_offs;
	uint32_t *dthpb_enoffs;
	uint32_t dthpb_noffs;
	uint32_t dthpb_nenoffs;
	uint8_t *dthpb_args;
	uint8_t dthpb_xargc;
	uint8_t dthpb_nargc;
	char *dthpb_xtypes;
	char *dthpb_ntypes;
} dtrace_helper_probedesc_t;

typedef struct dtrace_helper_provdesc {
	char *dthpv_provname;
	struct dtrace_pattr dthpv_pattr;
} dtrace_helper_provdesc_t;

typedef struct dtrace_mops {
	void (*dtms_create_probe)(void *, void *, dtrace_helper_probedesc_t *);
	void *(*dtms_provide_pid)(void *, dtrace_helper_provdesc_t *, pid_t);
	void (*dtms_remove_pid)(void *, dtrace_helper_provdesc_t *, pid_t);
} dtrace_mops_t;

/*
 * DTrace Provider-to-Framework API Functions
 */

typedef struct dtrace_meta {
	dtrace_mops_t dtm_mops;
	char *dtm_name;
	void *dtm_arg;
	uint64_t dtm_count;
} dtrace_meta_t;

typedef struct dtrace_mprovider {
	char			*dtmp_name;
	char			*dtmp_pref;
	dtrace_pattr_t		*dtmp_attr;
	uint32_t		dtmp_priv;
	dtrace_pops_t		*dtmp_pops;
	dtrace_provider_id_t	dtmp_id;
} dtrace_mprovider_t;

typedef struct dtrace_pmod {
	struct module		*mod;
	struct list_head	list;
} dtrace_pmod_t;

#ifdef CONFIG_DT_DEBUG
extern void dtrace_pmod_debug(void);
#endif
extern void dtrace_pmod_register(dtrace_pmod_t *);
extern void dtrace_pmod_add_consumer(void);
extern void dtrace_pmod_del_consumer(void);
extern void dtrace_pmod_unregister(dtrace_pmod_t *);
extern int dtrace_register(const char *, const dtrace_pattr_t *, uint32_t,
			   const cred_t *, const dtrace_pops_t *, void *,
			   dtrace_provider_id_t *);
extern int dtrace_unregister(dtrace_provider_id_t);
extern void dtrace_invalidate(dtrace_provider_id_t);
extern int dtrace_condense(dtrace_provider_id_t);
extern int dtrace_attached(void);

extern int dtrace_meta_register(const char *, const dtrace_mops_t *, void *,
				dtrace_meta_provider_id_t *);
extern int dtrace_meta_unregister(dtrace_meta_provider_id_t);

extern dtrace_id_t dtrace_probe_create(dtrace_provider_id_t, const char *,
				       const char *, const char *, int,
				       void *);
extern void *dtrace_probe_arg(dtrace_provider_id_t, dtrace_id_t);
extern dtrace_id_t dtrace_probe_lookup(dtrace_provider_id_t, const char *,
				       const char *, const char *);
extern void dtrace_probe(dtrace_id_t, uintptr_t, uintptr_t, uintptr_t,
			 uintptr_t, uintptr_t);

/*
 * Provider creation.
 */

#define DT_PROVIDER_POPS(name)						\
  static unsigned int	name##_refc = 0;				\
									\
  static int name##_enable(void *arg, dtrace_id_t id, void *parg)	\
  {									\
	int		rc = 0;						\
									\
	if (name##_refc++ == 0)	{					\
		if ((rc = try_module_get(THIS_MODULE)) == 0)		\
			return 0;					\
	}								\
									\
	if ((rc  = _##name##_enable(arg, id, parg)) != 0) {		\
		if (--name##_refc == 0)					\
			module_put(THIS_MODULE);			\
	}								\
									\
	return rc;							\
  }									\
									\
  static void name##_disable(void *arg, dtrace_id_t id, void *parg)	\
  {									\
	_##name##_disable(arg, id, parg);				\
									\
	if (--name##_refc == 0)						\
		module_put(THIS_MODULE);				\
  }

#define DT_PROVIDER_MODULE(name, priv)					\
  dtrace_provider_id_t	name##_id;					\
  static dtrace_pmod_t	name##_pmod = { THIS_MODULE, };			\
									\
  static int __init name##_init(void)					\
  {									\
	int	ret = 0;						\
									\
	ret = name##_dev_init();					\
	if (ret)							\
		goto failed;						\
									\
	dtrace_pmod_register(&name##_pmod);				\
									\
	ret = dtrace_register(__stringify(name), &name##_attr, priv,	\
			      NULL, &name##_pops, NULL, &name##_id);	\
	if (ret)							\
		goto failed;						\
									\
	return 0;							\
									\
  failed:								\
	return ret;							\
  }									\
									\
  static void __exit name##_exit(void)					\
  {									\
	dtrace_unregister(name##_id);					\
	dtrace_pmod_unregister(&name##_pmod);				\
	name##_dev_exit();						\
  }									\
									\
  module_init(name##_init);						\
  module_exit(name##_exit);

#define DT_META_PROVIDER_MODULE(name)					\
  dtrace_meta_provider_id_t	name##_id;				\
  static dtrace_pmod_t		name##_pmod = { THIS_MODULE, };		\
									\
  static int __init name##_init(void)					\
  {									\
	int	ret = 0;						\
									\
	ret = name##_dev_init();					\
	if (ret)							\
		goto failed;						\
									\
	dtrace_pmod_register(&name##_pmod);				\
									\
	ret = dtrace_meta_register(__stringify(name), &name##_mops,	\
				   NULL, &name##_id);			\
	if (ret)							\
		goto failed;						\
									\
	return 0;							\
									\
  failed:								\
	return ret;							\
  }									\
									\
  static void __exit name##_exit(void)					\
  {									\
	dtrace_meta_unregister(name##_id);				\
	dtrace_pmod_unregister(&name##_pmod);				\
	name##_dev_exit();						\
  }									\
									\
  module_init(name##_init);						\
  module_exit(name##_exit);

#define DT_MULTI_PROVIDER_MODULE(name, plist)				\
  static dtrace_pmod_t		name##_pmod = { THIS_MODULE, };		\
									\
  static int __init name##_init(void)					\
  {									\
	int			ret = 0;				\
	dtrace_mprovider_t	*prov;					\
									\
	ret = name##_dev_init();					\
	if (ret)							\
		goto failed;						\
									\
	dtrace_pmod_register(&name##_pmod);				\
									\
	for (prov = plist; prov->dtmp_name != NULL; prov++) {		\
		if (dtrace_register(prov->dtmp_name, prov->dtmp_attr,	\
				    prov->dtmp_priv, NULL,		\
				    prov->dtmp_pops, prov,		\
				    &prov->dtmp_id) != 0)		\
			pr_warning("Failed to register provider %s",	\
				   prov->dtmp_name);			\
	}								\
									\
	return 0;							\
									\
  failed:								\
	return ret;							\
  }									\
									\
  static void __exit name##_exit(void)					\
  {									\
	int			ret = 0;				\
	dtrace_mprovider_t	*prov;					\
									\
	for (prov = plist; prov->dtmp_name != NULL; prov++) {		\
		if (prov->dtmp_id != DTRACE_PROVNONE) {			\
			ret = dtrace_unregister(prov->dtmp_id);		\
			if (ret != 0)					\
				pr_warning("Failed to unregister "	\
					   "provider %s: %d",		\
					   prov->dtmp_name, ret);	\
									\
			prov->dtmp_id = DTRACE_PROVNONE;		\
		}							\
	}								\
									\
	dtrace_pmod_unregister(&name##_pmod);				\
	name##_dev_exit();						\
  }									\
									\
  module_init(name##_init);						\
  module_exit(name##_exit);


#endif /* _DTRACE_PROVIDER_H */
