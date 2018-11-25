// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018, Mellanox Technologies inc.  All rights reserved.
 */
#include <rdma/uverbs_ioctl.h>
#include "uverbs.h"
#include "rdma_core.h"

static uint32_t *
gather_objects_handle(struct ib_uverbs_file *ufile,
		      const struct uverbs_api_object *uapi_object,
		      ssize_t out_len,
		      u64 *total)
{
	u64 max_count = out_len / sizeof(u32);
	struct ib_uobject *obj;
	u64 count = 0;
	u32 *handles;

	/* Allocated memory that cannot page out where we gather
	 * all object ids under a spin_lock.
	 */
	handles = kvzalloc(out_len, GFP_KERNEL);
	if (!handles)
		return ERR_PTR(-ENOMEM);

	spin_lock_irq(&ufile->uobjects_lock);
	list_for_each_entry(obj, &ufile->uobjects, list) {
		u32 obj_id = obj->id;

		if (obj->uapi_object != uapi_object)
			continue;

		if (count >= max_count)
			break;

		handles[count] = obj_id;
		count++;
	}
	spin_unlock_irq(&ufile->uobjects_lock);

	*total = count;
	return handles;
}

static int UVERBS_HANDLER(UVERBS_METHOD_INFO_HANDLES)(
	struct uverbs_attr_bundle *attrs)
{
	const struct uverbs_api_object *uapi_object;
	ssize_t out_len;
	u64 total = 0;
	u16 object_id;
	u32 *handles;
	int ret;

	out_len = uverbs_attr_get_len(attrs, UVERBS_ATTR_INFO_HANDLES_LIST);
	if (out_len <= 0 || (out_len % sizeof(u32) != 0))
		return -EINVAL;

	ret = uverbs_get_const(&object_id, attrs, UVERBS_ATTR_INFO_OBJECT_ID);
	if (ret)
		return ret;

	uapi_object = uapi_get_object(attrs->ufile->device->uapi, object_id);
	if (!uapi_object)
		return -EINVAL;

	handles = gather_objects_handle(attrs->ufile, uapi_object, out_len, &total);
	if (IS_ERR(handles))
		return PTR_ERR(handles);

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_INFO_HANDLES_LIST, handles,
			     sizeof(u32) * total);
	if (ret)
		goto err;

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_INFO_TOTAL_HANDLES, &total,
			     sizeof(total));
err:
	kvfree(handles);
	return ret;
}

DECLARE_UVERBS_NAMED_METHOD(
	UVERBS_METHOD_INFO_HANDLES,
	/* Also includes any device specific object ids */
	UVERBS_ATTR_CONST_IN(UVERBS_ATTR_INFO_OBJECT_ID,
			     enum uverbs_default_objects, UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_INFO_TOTAL_HANDLES,
			    UVERBS_ATTR_TYPE(u32), UA_OPTIONAL),
	UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_INFO_HANDLES_LIST,
			    UVERBS_ATTR_MIN_SIZE(sizeof(u32)), UA_OPTIONAL));

DECLARE_UVERBS_GLOBAL_METHODS(UVERBS_OBJECT_DEVICE,
	&UVERBS_METHOD(UVERBS_METHOD_INFO_HANDLES),
	);
