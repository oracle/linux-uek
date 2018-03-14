/******************************************************************************
 *
 * Driver for receiving and sending messages for Oracle VM.
 *
 * Copyright (c) 2015, 2020, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/syscore_ops.h>
#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/interface/io/protocols.h>
#include "ovmapi.h"

MODULE_LICENSE("GPL");

static struct kmem_cache *name_cache;
static struct kmem_cache *value_cache;
static struct kmem_cache *parameter_cache;
static struct kmem_cache *event_cache;
static struct notifier_block xenstore_notifier;
static struct ovmapi_information ovmapi_info;

#define DGBLVL_OFF     0
#define DGBLVL_ERROR   1
#define DGBLVL_WARNING 2
#define DGBLVL_INFO    3

static int debug_level = DGBLVL_OFF;

module_param(debug_level, int, S_IRUGO|S_IWUSR);

#define ovmapi_debug_out(l, m, a...) do {	\
	if ((l) <= debug_level)			\
		printk(m, ##a);			\
	} while (0)

#define OVMLOG(lvl, msg, args...) ovmapi_debug_out(lvl, msg, ## args);

static int ovmapi_open(struct inode *inode, struct file *file)
{
	struct ovmapi_app_entry *app;

	OVMLOG(DGBLVL_INFO, "ovmapi_open\n");
	app = kzalloc(sizeof(*app), GFP_KERNEL);
	if (!app)
		return -ENOMEM;

	INIT_LIST_HEAD(&app->list);
	file->private_data = app;

	/* always send these */
	app->event_mask = OVMAPI_EVT_MORE_PROCESSING;
	INIT_LIST_HEAD(&app->events_list);
	init_waitqueue_head(&app->event_waitqueue);
	app->async_queue = 0;

	return 0;
}

static int ovmapi_release(struct inode *inode, struct file *file)
{
	struct ovmapi_app_entry *app = file->private_data;

	mutex_lock(&ovmapi_info.apps_list_mutex);
	list_del(&app->list);
	mutex_unlock(&ovmapi_info.apps_list_mutex);
	kfree(app);

	return 0;
}

static unsigned int ovmapi_poll(struct file *file, poll_table *wait)
{
	struct ovmapi_app_entry *app = file->private_data;
	unsigned int mask = 0;

	OVMLOG(DGBLVL_INFO, "ovmapi_poll\n")
	poll_wait(file, &app->event_waitqueue, wait);
	if (!app->registered) {
		OVMLOG(DGBLVL_ERROR,
		       "ovmapi_poll: app %p not registered\n", app);
		return 0;
	}

	if (!list_empty(&app->events_list))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

static int ovmapi_fasync(int fd, struct file *file, int on)
{
	struct ovmapi_app_entry *app = file->private_data;

	if (fasync_helper(fd, file, on, &app->async_queue) >= 0)
		return 0;
	else
		return -EIO;
}

static int ovmapi_register_app(struct ovmapi_information *p_ovmapi_info,
			       struct ovmapi_app_entry *app)
{
	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	app->registered = true;
	list_add_tail(&app->list, &p_ovmapi_info->registered_apps_list);
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return 0;
}

static int ovmapi_unregister_app(struct ovmapi_information *p_ovmapi_info,
				 struct ovmapi_app_entry *app)
{
	struct ovmapi_event_list *event, *next;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	app->registered = false;
	list_for_each_entry_safe(event, next, &app->events_list, list) {
		list_del(&event->list);
		kmem_cache_free(event_cache, event);
	}
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);
	wake_up(&app->event_waitqueue);
	if (app->async_queue)
		kill_fasync(&app->async_queue, SIGIO, POLL_IN);

	return 0;
}

static int ovmapi_get_all_parameter_names(
			   struct ovmapi_information *p_ovmapi_info,
			   void __user *user_buffer)
{
	struct ovmapi_param *parameter;
	struct ovmapi_param_names names;
	unsigned int total_names = 0;
	char *p_name;

	if (copy_from_user(&names, user_buffer, sizeof(names)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->parameter_mutex);
	p_name = names.name_entries;
	list_for_each_entry(parameter, &p_ovmapi_info->parameter_list, list) {
		if (total_names >= names.total_names)
			break;
		if (copy_to_user(p_name, parameter->name,
				 parameter->name_size)) {
			mutex_unlock(&p_ovmapi_info->parameter_mutex);
			return -EFAULT;
		}
		p_name += OVMM_MAX_NAME_LEN;
		total_names++;
	}
	if (copy_to_user(
		&((struct ovmapi_param_names *)user_buffer)->total_names,
		&total_names, sizeof(u32))) {
		mutex_unlock(&p_ovmapi_info->parameter_mutex);
		return -EFAULT;
	}
	mutex_unlock(&p_ovmapi_info->parameter_mutex);

	return 0;
}

static int ovmapi_get_parameter_by_index(
			   struct ovmapi_information *p_ovmapi_info,
			   void __user *user_buffer)
{
	struct ovmapi_param *parameter;
	struct ovmapi_param_message message;
	unsigned int index = 0;
	bool found = false;
	int err = 0;

	if (copy_from_user(&message, user_buffer, sizeof(message)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->parameter_mutex);
	list_for_each_entry(parameter, &p_ovmapi_info->parameter_list, list) {
		if (index == message.index) {
			if (parameter->value_size > message.value_size) {
				err = -EINVAL;
				goto fail;
			}
			if (copy_to_user(message.value, parameter->value,
					 parameter->value_size)) {
				err = -EFAULT;
				goto fail;
			}
			message.value_size = parameter->value_size;
			memcpy(message.name, parameter->name,
			       parameter->name_size);
			if (copy_to_user(user_buffer, &message,
					sizeof(message))) {
				err = -EFAULT;
				goto fail;
			}
			found = true;
			break;
		}
		index++;
	}
	mutex_unlock(&p_ovmapi_info->parameter_mutex);

	return found ? 0 : -ENOENT;
fail:
	mutex_unlock(&p_ovmapi_info->parameter_mutex);
	return err;
}

static int ovmapi_read_name(const char *pathname, char *name,
			    unsigned long *name_size)
{
	char *name_buff;
	int name_len;

	name_buff = xenbus_read(XBT_NIL, pathname, "", &name_len);
	if (IS_ERR(name_buff)) {
		OVMLOG(DGBLVL_ERROR, "OVMAPI: unable to read %s\n", pathname);
		return PTR_ERR(name_buff);
	}

	*name_size = snprintf(name, *name_size, "%s", name_buff);
	kfree(name_buff);

	return 0;
}

static int ovmapi_read_name_value(const char *pathname, char *value,
				  unsigned long *value_len)
{
	char **dir;
	unsigned int dir_n;
	int name_len, total_len = 0;
	char *name_value;
	int n;
	char num[8];

	dir = xenbus_directory(XBT_NIL, pathname, "", &dir_n);
	if (IS_ERR(dir)) {
		OVMLOG(DGBLVL_ERROR, "OVMAPI: unable to read %s\n", pathname);
		return -ENODEV;
	}

	for (n = 0; n < dir_n; n++) {
		snprintf(num, sizeof(num), "%d", n);
		name_value = xenbus_read(XBT_NIL, pathname, num, &name_len);
		if (IS_ERR(name_value)) {
			kfree(dir);
			return PTR_ERR(name_value);
		}
		if (*value_len < (total_len + name_len)) {
			OVMLOG(DGBLVL_ERROR, "OVMAPI: value buffer is too "
			       "short: value_len=%ld, needs=%d\n",
			       *value_len, total_len + name_len);
			kfree(dir);
			kfree(name_value);
			return -ENOSPC;
		}

		memcpy(value, name_value, name_len);
		value += name_len;
		total_len += name_len;
		kfree(name_value);
	}

	*value = '\0';
	*value_len = total_len;
	kfree(dir);

	return 0;
}

static int ovmapi_delete_events(struct ovmapi_information *p_ovmapi_info,
				struct ovmapi_app_entry *app)
{
	struct ovmapi_event_list *event = NULL, *tmp;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	list_for_each_entry_safe(event, tmp, &app->events_list, list) {
		if (!(app->event_mask & event->event_entry.header.type)) {

			list_del(&event->list);
			kmem_cache_free(event_cache, event);
		}
	}
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return 0;
}

static int ovmapi_post_event(struct ovmapi_information *p_ovmapi_info,
			     struct ovmapi_app_entry *source_app,
			     void __user *user_buffer)
{
	struct ovmapi_event_list *add_event;
	struct ovmapi_app_entry *app;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	list_for_each_entry(app, &p_ovmapi_info->registered_apps_list, list) {
		if (app == source_app) /* do not add event to sending app */
			continue;
		if (!app->registered)
			continue;
		add_event = kmem_cache_zalloc(event_cache, GFP_KERNEL);
		if (!add_event) {
			OVMLOG(DGBLVL_ERROR,
			       "OVMAPI: unable to allocate event.\n");
			mutex_unlock(&p_ovmapi_info->apps_list_mutex);
			return -ENOMEM;
		}
		if (copy_from_user(&add_event->event_entry,
				   (struct ovmapi_event *)user_buffer,
				   sizeof(struct ovmapi_event))) {
			kmem_cache_free(event_cache, add_event);
			mutex_unlock(&p_ovmapi_info->apps_list_mutex);
			return -EFAULT;
		}
		if (!(app->event_mask & add_event->event_entry.header.type)) {
			kmem_cache_free(event_cache, add_event);
			continue;
		}
		add_event->event_entry.header.event_id =
						p_ovmapi_info->event_counter;
		list_add_tail(&add_event->list, &app->events_list);
		wake_up(&app->event_waitqueue);
		if (app->async_queue)
			kill_fasync(&app->async_queue, SIGIO, POLL_IN);
	}
	p_ovmapi_info->event_counter++;
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return 0;
}

static int ovmapi_get_event_header(struct ovmapi_information *p_ovmapi_info,
				   struct ovmapi_app_entry *app,
				   void __user *user_buffer)
{
	struct ovmapi_event_list *event = NULL;
	unsigned long event_id;

	if (copy_from_user(&event_id, user_buffer, sizeof(event_id)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	list_for_each_entry(event, &app->events_list, list) {
		if (event_id == event->event_entry.header.event_id) {
			if (copy_to_user(user_buffer,
					 &event->event_entry.header,
					 sizeof(struct ovmapi_event_header))) {
				mutex_unlock(&p_ovmapi_info->apps_list_mutex);
				return -EFAULT;
			}
			mutex_unlock(&p_ovmapi_info->apps_list_mutex);
			return 0;
		}
	}
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return -EINVAL;
}

static int ovmapi_get_next_event_header(
			   struct ovmapi_information *p_ovmapi_info,
			   struct ovmapi_app_entry *app,
			   void __user *user_buffer)
{
	struct ovmapi_event_list *event = NULL;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	if (!list_empty(&app->events_list)) {
		event = list_entry(app->events_list.next,
				   struct ovmapi_event_list,
				   list);
		if (copy_to_user(user_buffer, &event->event_entry.header,
				 sizeof(struct ovmapi_event_header))) {
			mutex_unlock(&p_ovmapi_info->apps_list_mutex);
			return -EFAULT;
		}
	}
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return 0;
}

static int ovmapi_get_event(struct ovmapi_information *p_ovmapi_info,
			    struct ovmapi_app_entry *app,
			    void __user *user_buffer)
{
	struct ovmapi_event_list *event, *tmp;
	struct ovmapi_event_header kernel_mem_event;
	struct ovmapi_event *user_mem_event =
				(struct ovmapi_event *)user_buffer;

	/* We should only have a valid header from the user. */
	if (copy_from_user(&kernel_mem_event, user_mem_event,
			   sizeof(kernel_mem_event)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	list_for_each_entry_safe(event, tmp, &app->events_list, list) {
		if (kernel_mem_event.event_id ==
			event->event_entry.header.event_id) {
			if (copy_to_user(user_mem_event, &event->event_entry,
					 (sizeof(struct ovmapi_event_header) +
					 event->event_entry.header.size))) {
				mutex_unlock(&p_ovmapi_info->apps_list_mutex);
				return -EFAULT;
			}
			list_del(&event->list);
			kmem_cache_free(event_cache, event);
			mutex_unlock(&p_ovmapi_info->apps_list_mutex);
			return 0;
		}
	}
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return -EINVAL;
}

static int ovmapi_get_next_event(struct ovmapi_information *p_ovmapi_info,
				 struct ovmapi_app_entry *app,
				 void __user *user_buffer)
{
	struct ovmapi_event_list *event = NULL;
	struct ovmapi_event *user_mem_event =
				(struct ovmapi_event *)user_buffer;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	if (!list_empty(&app->events_list)) {
		event = list_entry(app->events_list.next,
				   struct ovmapi_event_list,
				   list);
		if (copy_to_user(user_mem_event, &event->event_entry,
				 (sizeof(struct ovmapi_event_header) +
				 event->event_entry.header.size))){
			mutex_unlock(&p_ovmapi_info->apps_list_mutex);
			return -EFAULT;
		}
		if (user_mem_event->header.type ==
			OVMAPI_EVT_MORE_PROCESSING) {
			struct ovmapi_event_more_processing *emp =
				(struct ovmapi_event_more_processing *)
				user_mem_event;
			emp->event_mask = app->event_mask;
		}
		list_del(&event->list);
		kmem_cache_free(event_cache, event);
	}
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return 0;
}

static int ovmapi_discard_event(struct ovmapi_information *p_ovmapi_info,
				struct ovmapi_app_entry *app,
				void __user *user_buffer)
{
	struct ovmapi_event_list *event = NULL, *tmp;
	unsigned long event_id;

	if (copy_from_user(&event_id, user_buffer, sizeof(event_id)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	list_for_each_entry_safe(event, tmp, &app->events_list, list) {
		if (event_id == event->event_entry.header.event_id) {
			list_del(&event->list);
			kmem_cache_free(event_cache, event);
			mutex_unlock(&p_ovmapi_info->apps_list_mutex);
			return 0;
		}
	}
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return -EINVAL;
}

static int ovmapi_discard_next_event(struct ovmapi_information *p_ovmapi_info,
				     struct ovmapi_app_entry *app,
				     void __user *user_buffer)
{
	struct ovmapi_event_list *event = NULL;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	if (!list_empty(&app->events_list)) {
		event = list_entry(app->events_list.next,
				   struct ovmapi_event_list,
				   list);
		list_del(&event->list);
		kmem_cache_free(event_cache, event);
		mutex_unlock(&p_ovmapi_info->apps_list_mutex);
		return 0;
	}
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return 0;
}

static int ovmapi_send_user_event(struct ovmapi_information *p_ovmapi_info,
				  unsigned short type, unsigned short severity,
				  unsigned short phase, unsigned short size,
				  char *payload)
{
	struct ovmapi_app_entry *app;
	struct ovmapi_event_list *add_event;

	if (size > OVMAPI_EVENT_DATA_MAXSIZE)
		return -EINVAL;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);

	list_for_each_entry(app, &p_ovmapi_info->registered_apps_list, list) {
		if (!app->registered)
			continue;
		if (!(app->event_mask & type))
			continue;
		add_event = kmem_cache_zalloc(event_cache, GFP_KERNEL);
		if (!add_event) {
			mutex_unlock(&p_ovmapi_info->apps_list_mutex);
			return -ENOMEM;
		}
		add_event->event_entry.header.type = type;
		add_event->event_entry.header.severity = severity;
		add_event->event_entry.header.phase = phase;
		add_event->event_entry.header.size = size;
		add_event->event_entry.header.event_id =
						p_ovmapi_info->event_counter;

		/* Since OVMAPI_EVT_MORE_PROCESSING requires that the
		 * application specific event mask be sent to usermode, we do
		 * special handling for this particular event type within this
		 * function.
		 */
		if (type == OVMAPI_EVT_MORE_PROCESSING) {
			struct ovmapi_event_more_processing *emp =
				(struct ovmapi_event_more_processing *)
				&(add_event->event_entry);
			if (size && payload)
				memcpy(emp->data, payload,
				       size - sizeof(unsigned long));
		} else {
			if (size && payload)
				memcpy(add_event->event_entry.payload, payload,
				       size);
		}

		list_add_tail(&add_event->list, &app->events_list);
		wake_up(&app->event_waitqueue);
		if (app->async_queue)
			kill_fasync(&app->async_queue, SIGIO, POLL_IN);
	}

	p_ovmapi_info->event_counter++;
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	return 0;
}

static int ovmapi_modify_event_subscription(
			   struct ovmapi_information *p_ovmapi_info,
			   struct ovmapi_app_entry *app,
			   void __user *user_buffer)
{
	struct ovmapi_event_subscription register_event;

	if (copy_from_user(&register_event, user_buffer,
			   sizeof(register_event)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->apps_list_mutex);
	app->event_mask &= ~(register_event.unsubscribe);
	app->event_mask |= register_event.subscribe;
	mutex_unlock(&p_ovmapi_info->apps_list_mutex);

	if (register_event.unsubscribe)
		ovmapi_delete_events(p_ovmapi_info, app);

	return 0;
}

static int ovmapi_add_parameter(struct ovmapi_information *p_ovmapi_info,
				char *name, char *value, u32 value_size)
{
	struct ovmapi_param *parameter;

	mutex_lock(&p_ovmapi_info->parameter_mutex);

	/* check for duplication */
	list_for_each_entry(parameter, &p_ovmapi_info->parameter_list, list) {
		if (strcmp(name, parameter->name) == 0) {
			kfree(parameter->value);
			parameter->value = value;
			parameter->value_size = value_size;
			mutex_unlock(&p_ovmapi_info->parameter_mutex);
			ovmapi_send_user_event(p_ovmapi_info,
				OVMAPI_EVT_NEW_PARAM, OVMAPI_EVT_SEVERITY_INFO,
				OVMAPI_EVT_PHASE_IMMED, strlen(name) + 1,
				name);
			kmem_cache_free(name_cache, name);
			return 0;
		}
	}

	parameter = kmem_cache_zalloc(parameter_cache, GFP_KERNEL);
	if (!parameter) {
		OVMLOG(DGBLVL_ERROR,
		       "OVMAPI: unable to allocate parameter cache.\n");
		mutex_unlock(&p_ovmapi_info->parameter_mutex);
		return -ENOMEM;
	}

	parameter->name_size = strlen(name);
	parameter->name = name;
	parameter->value = value;
	parameter->value_size = value_size;

	list_add_tail(&parameter->list, &p_ovmapi_info->parameter_list);
	p_ovmapi_info->parameter_count++;
	mutex_unlock(&p_ovmapi_info->parameter_mutex);

	ovmapi_send_user_event(p_ovmapi_info, OVMAPI_EVT_NEW_PARAM,
			       OVMAPI_EVT_SEVERITY_INFO,
			       OVMAPI_EVT_PHASE_IMMED,
			       strlen(name) + 1, name);

	return 0;
}

static int ovmapi_delete_parameter(struct ovmapi_information *p_ovmapi_info,
				   void __user *user_buffer)
{
	struct ovmapi_param *parameter, *next;
	struct ovmapi_param_message message;

	if (copy_from_user(&message, user_buffer, sizeof(message)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->parameter_mutex);
	list_for_each_entry_safe(parameter, next,
				 &p_ovmapi_info->parameter_list, list) {
		if (strcmp(message.name, parameter->name) == 0) {
			list_del(&parameter->list);
			kmem_cache_free(name_cache, parameter->name);
			kfree(parameter->value);
			kmem_cache_free(parameter_cache, parameter);
			p_ovmapi_info->parameter_count--;
			mutex_unlock(&p_ovmapi_info->parameter_mutex);
			return 0;
		}
	}
	mutex_unlock(&p_ovmapi_info->parameter_mutex);

	return 1;
}

static int ovmapi_read_parameter(struct ovmapi_information *p_ovmapi_info,
				 void __user *user_buffer)
{
	struct ovmapi_param *parameter;
	struct ovmapi_param_message message;

	if (copy_from_user(&message, user_buffer, sizeof(message)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->parameter_mutex);
	list_for_each_entry(parameter, &p_ovmapi_info->parameter_list, list) {
		if (strcmp(message.name, parameter->name) == 0) {
			if (parameter->value_size > message.value_size) {
				message.value_size = parameter->value_size;
				mutex_unlock(&p_ovmapi_info->parameter_mutex);
				if (copy_to_user(user_buffer, &message,
					sizeof(message))) {
					return -EFAULT;
				}
				return -EINVAL;
			}
			if (copy_to_user(message.value, parameter->value,
					 parameter->value_size)){
				mutex_unlock(&p_ovmapi_info->parameter_mutex);
				return -EFAULT;
			}
			message.value_size = parameter->value_size;
			mutex_unlock(&p_ovmapi_info->parameter_mutex);
			if (copy_to_user(user_buffer, &message,
				sizeof(message))) {
				return -EFAULT;
			}
			return 0;
		 }
	}
	mutex_unlock(&p_ovmapi_info->parameter_mutex);

	return -ENOENT;
}

static int ovmapi_get_parameter_value_size(
			   struct ovmapi_information *p_ovmapi_info,
			   void __user *user_buffer)
{
	struct ovmapi_param *parameter;
	struct ovmapi_param_message message;

	if (copy_from_user(&message, user_buffer, sizeof(message)))
		return -EFAULT;

	mutex_lock(&p_ovmapi_info->parameter_mutex);
	list_for_each_entry(parameter, &p_ovmapi_info->parameter_list, list) {
		if (strcmp(message.name, parameter->name) == 0) {
			message.value_size = parameter->value_size;
			mutex_unlock(&p_ovmapi_info->parameter_mutex);
			if (copy_to_user(user_buffer, &message,
						sizeof(message)))
				return -EFAULT;
			return 0;
		 }
	}
	mutex_unlock(&p_ovmapi_info->parameter_mutex);

	return -EINVAL;
}

static int ovmapi_send_dom0_message(struct ovmapi_information *p_ovmapi_info,
				    char *name, char *value, u32 value_len)
{
	unsigned long n;
	char number[16];
	char save;
	char pathname[OVMM_MAX_NAME_LEN * 2];

	OVMLOG(DGBLVL_INFO, "ovmapi_send_dom0_message: name:%s, value: %s, "
			    "value_len: %d\n", name, value, value_len);

	p_ovmapi_info->last_write_message++;

	snprintf(pathname, OVMM_MAX_NAME_LEN,
			 "control/oracle-vmapi/from-guest/%ld",
			 p_ovmapi_info->last_write_message);

	xenbus_write(XBT_NIL, pathname, "", name);

	for (n = 0; n <= (value_len / OVMM_MAX_CHARS_PER_SEQUENCE); n++) {
		snprintf(number, sizeof(number), "%ld", n);
		save = '\0';
		if (value_len > ((n + 1) * OVMM_MAX_CHARS_PER_SEQUENCE)) {
			save = value[((n + 1) * OVMM_MAX_CHARS_PER_SEQUENCE)];
			value[((n + 1) * OVMM_MAX_CHARS_PER_SEQUENCE)] = '\0';
		}

		OVMLOG(DGBLVL_INFO, "ovmapi_send_dom0_message: xenbus_write "
		       "pathname: %s, number: %s, value: %s\n", name, number,
		       value + (n * OVMM_MAX_CHARS_PER_SEQUENCE));

		xenbus_write(XBT_NIL, pathname, number,
			     value + (n * OVMM_MAX_CHARS_PER_SEQUENCE));

		if (save != '\0')
			value[((n + 1) * OVMM_MAX_CHARS_PER_SEQUENCE)] = save;
	}

	snprintf(number, sizeof(number), "%ld",
		 p_ovmapi_info->last_write_message);
	xenbus_write(XBT_NIL, "control/oracle-vmapi/from-guest", "last-write",
		     number);
	OVMLOG(DGBLVL_INFO, "ovmapi_send_dom0_message: write name value path:"
	       " %s value: %s\n", name, value);

	return 0;
}

static void ovmapi_receive_dom0_message(struct xenbus_watch *watch,
					const char *path, const char *token)
{
	unsigned long read_to_here = 0;
	char *name = NULL;
	char *tmp_value = NULL;
	char *value = NULL;
	unsigned long name_len;
	unsigned long value_len;
	int status;
	char pathname[OVMM_MAX_NAME_LEN];
	struct ovmapi_information *p_ovmapi_info =
		   container_of(watch, struct ovmapi_information,
				dom0_message_watch);

	status = xenbus_scanf(XBT_NIL, "control/oracle-vmapi/to-guest",
			      "last-write", "%lu", &read_to_here);

	if (status != 1) {
		OVMLOG(DGBLVL_INFO, "OVMAPI: unable to read to-guest\n");
		return;
	}

	OVMLOG(DGBLVL_INFO, "OVMAPI: received messages from Dom0\n");

	tmp_value  = kmem_cache_alloc(value_cache, GFP_KERNEL);

	if (!tmp_value) {
		OVMLOG(DGBLVL_ERROR,
		       "OVMAPI: unable to allocate value cache.\n");
		return;
	}

	while (p_ovmapi_info->last_read_message < read_to_here) {
		p_ovmapi_info->last_read_message++;
		snprintf(pathname, OVMM_MAX_NAME_LEN,
			 "control/oracle-vmapi/to-guest/%ld",
			 p_ovmapi_info->last_read_message);

		name  = kmem_cache_alloc(name_cache,  GFP_KERNEL);
		if (!name) {
			OVMLOG(DGBLVL_ERROR,
			       "OVMAPI: unable to allocate name cache.\n");
			continue;
		}

		name_len = OVMM_MAX_NAME_LEN - 1;
		status = ovmapi_read_name(pathname, name, &name_len);

		if (status) {
			OVMLOG(DGBLVL_ERROR,
			       "OVMAPI: unable to read to-guest name.\n");
			if (name)
				kmem_cache_free(name_cache, name);
			continue;
		}

		value_len = OVMM_MAX_VALUE_LEN - 1;
		status = ovmapi_read_name_value(pathname, tmp_value,
						&value_len);
		if (status) {
			OVMLOG(DGBLVL_ERROR, "OVMAPI: unable to read to-guest "
					     "name_value.\n");
			kmem_cache_free(name_cache, name);
			continue;
		}

		value = kmemdup(tmp_value, value_len + 1, GFP_KERNEL);
		if (!value) {
			OVMLOG(DGBLVL_ERROR,
			       "OVMAPI: unable to allocate value.\n");
			kmem_cache_free(value_cache, tmp_value);
			kmem_cache_free(name_cache, name);
			return;
		}

		memcpy(value, tmp_value, value_len + 1);
		OVMLOG(DGBLVL_INFO,
		       "OVMAPI: read name value path: %s value: %s\n",
		       pathname, value);

		if (!strcmp(name, "VMAPIEvent")) {
			/* Incoming event: send it to userspace with size of
			 * eventMask. */
			ovmapi_send_user_event(p_ovmapi_info,
				OVMAPI_EVT_MORE_PROCESSING,
				OVMAPI_EVT_SEVERITY_SYSTEM,
				OVMAPI_EVT_PHASE_IMMED,
				value_len + 1 + sizeof(unsigned long),
				value);
		} else {
			/* Generate an event and store this as a parameter. */
			status = ovmapi_add_parameter(p_ovmapi_info, name,
					value, value_len + 1);
			if (status != 0) {
				kmem_cache_free(value_cache, tmp_value);
				kmem_cache_free(name_cache, name);
				return;
			}
		}

		snprintf(pathname, OVMM_MAX_NAME_LEN,
			 "control/oracle-vmapi/to-guest/%ld",
			 p_ovmapi_info->last_read_message);

		xenbus_rm(XBT_NIL, pathname, "");
	}

	kmem_cache_free(value_cache, tmp_value);
}

static long ovmapi_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct ovmapi_param_message message;
	char *value = NULL, *name = NULL;
	long status = 0;
	struct ovmapi_app_entry *app = file->private_data;

	if (cmd != IOCTL_XENPCI_REGISTER_EVENT_HANDLER && !app->registered)
		return -EINVAL;

	switch (cmd) {
	case IOCTL_XENPCI_MODIFY_EVENT_FILTER:
		if (!arg)
			return -EINVAL;
		status = ovmapi_modify_event_subscription(&ovmapi_info, app,
							  argp);
		return status;
	case IOCTL_XENPCI_REGISTER_EVENT_HANDLER:
		status = ovmapi_register_app(&ovmapi_info, app);
		return status;
	case IOCTL_XENPCI_UNREGISTER_EVENT_HANDLER:
		status = ovmapi_unregister_app(&ovmapi_info, app);
		return status;
	case IOCTL_XENPCI_GET_PARAM_COUNT:
		if (!arg)
			return -EINVAL;
		if (copy_to_user(argp, &ovmapi_info.parameter_count,
				 sizeof(unsigned long)))
			return -EFAULT;
		return status;
	case IOCTL_XENPCI_GET_PARAM_BY_INDEX:
		if (!arg)
			return -EINVAL;
		status = ovmapi_get_parameter_by_index(&ovmapi_info, argp);
		return status;
	case IOCTL_XENPCI_GET_ALL_PARAM_NAMES:
		if (!arg)
			return -EINVAL;
		status = ovmapi_get_all_parameter_names(&ovmapi_info, argp);
		return status;
	case IOCTL_XENPCI_READ_PARAMETER:
		if (!arg)
			return -EINVAL;
		status = ovmapi_read_parameter(&ovmapi_info, argp);
		return status;
	case IOCTL_XENPCI_GET_PARAM_VALUE_SIZE_BY_NAME:
		if (!arg)
			return -EINVAL;
		status = ovmapi_get_parameter_value_size(&ovmapi_info, argp);
		return status;
	case IOCTL_XENPCI_WRITE_PARAMETER:
	case IOCTL_XENPCI_SEND_MESSAGE:
		if (!arg)
			return -EINVAL;
		if (copy_from_user(&message, argp, sizeof(message)))
			return -EFAULT;
		if (message.value_size > OVMM_MAX_VALUE_LEN ||
		    message.value_size == 0)
			return -EMSGSIZE;
		name  = kmem_cache_alloc(name_cache,  GFP_KERNEL);
		if (!name)
			return -ENOMEM;
		value = kmalloc(message.value_size, GFP_KERNEL);
		if (!value) {
			status = -ENOMEM;
			goto out;
		}
		strncpy(name, message.name, OVMM_MAX_NAME_LEN);
		name[OVMM_MAX_NAME_LEN - 1] = '\0';
		if (copy_from_user(value, message.value, message.value_size)) {
			status = -EFAULT;
			goto out;
		}
		status = ovmapi_send_dom0_message(&ovmapi_info, name, value,
						  message.value_size);
		if (status == 0 && cmd == IOCTL_XENPCI_WRITE_PARAMETER) {
			status = ovmapi_add_parameter(&ovmapi_info, name, value,
					     message.value_size);
			if (status == 0)
				return 0;
		}
out:
		kmem_cache_free(name_cache, name);
		kfree(value);
		return status;
	case IOCTL_XENPCI_DELETE_PARAM:
		if (!arg)
			return -EINVAL;
		status = ovmapi_delete_parameter(&ovmapi_info, argp);
		return status;

	case IOCTL_XENPCI_POST_EVENT:
		if (!arg)
			return -EINVAL;
		/* this goes to all apps */
		status = ovmapi_post_event(&ovmapi_info, app, argp);
		return status;
	case IOCTL_XENPCI_GET_EVENT_HEADER:
		if (!arg)
			return -EINVAL;
		status = ovmapi_get_event_header(&ovmapi_info, app, argp);
		return status;
	case IOCTL_XENPCI_GET_NEXT_EVENT_HEADER:
		if (!arg)
			return -EINVAL;
		status = ovmapi_get_next_event_header(&ovmapi_info, app, argp);
		return status;
	case IOCTL_XENPCI_GET_EVENT:
		if (!arg)
			return -EINVAL;
		status = ovmapi_get_event(&ovmapi_info, app, argp);
		return status;
	case IOCTL_XENPCI_GET_NEXT_EVENT:
		if (!arg)
			return -EINVAL;
		status = ovmapi_get_next_event(&ovmapi_info, app, argp);
		return status;
	case IOCTL_XENPCI_DISCARD_EVENT:
		if (!arg)
			return -EINVAL;
		status = ovmapi_discard_event(&ovmapi_info, app, argp);
		return status;
	case IOCTL_XENPCI_DISCARD_NEXT_EVENT:
		if (!arg)
			return -EINVAL;
		status = ovmapi_discard_next_event(&ovmapi_info, app, argp);
		return status;
	default:
		return -EINVAL;
	}
}

static int ovmapi_init_watcher(struct notifier_block *notifier,
			       unsigned long event, void *data)
{
	int err;

	INIT_LIST_HEAD(&ovmapi_info.dom0_message_watch.list);
	ovmapi_info.dom0_message_watch.node =
			"control/oracle-vmapi/to-guest/last-write";
	ovmapi_info.dom0_message_watch.callback = ovmapi_receive_dom0_message;
	ovmapi_info.last_read_message = 0;
	ovmapi_info.last_write_message = 0;

	err = register_xenbus_watch(&ovmapi_info.dom0_message_watch);
	if (err)
		OVMLOG(DGBLVL_ERROR, "OVMAPI: failed to set to-guest watch\n");

	return NOTIFY_DONE;
}

static int ovmapi_syscore_suspend(void)
{
	return 0;
}

static void ovmapi_syscore_resume(void)
{
    ovmapi_info.last_read_message = 0;
    ovmapi_info.last_write_message = 0;
}

static struct syscore_ops ovmapi_syscore_ops = {
	.suspend = ovmapi_syscore_suspend,
	.resume = ovmapi_syscore_resume,
};

static const struct file_operations ovmapi_fops = {
	.owner          = THIS_MODULE,
	.open           = ovmapi_open,
	.unlocked_ioctl = ovmapi_ioctl,
	.poll           = ovmapi_poll,
	.release        = ovmapi_release,
	.fasync         = ovmapi_fasync,
};

static struct miscdevice ovmapi_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "ovmapi",
	.fops  = &ovmapi_fops,
};

static int __init ovmapi_init(void)
{
	int ret;

	if (!xen_domain())
		return -ENODEV;

	ret = misc_register(&ovmapi_dev);
	if (ret != 0) {
		OVMLOG(DGBLVL_ERROR,
		       "ovmapi_init: unable to register misc device.\n");
		return ret;
	}

	name_cache = kmem_cache_create("name_cache", OVMM_MAX_NAME_LEN,
				       0, 0, NULL);
	value_cache = kmem_cache_create("value_cache", OVMM_MAX_VALUE_LEN,
					0, 0, NULL);
	parameter_cache = kmem_cache_create("parameter_cache",
					    sizeof(struct ovmapi_param),
					    0, 0, NULL);
	event_cache = kmem_cache_create("event_cache",
					sizeof(struct ovmapi_event_list),
					0, 0, NULL);
	memset(&ovmapi_info, 0, sizeof(ovmapi_info));
	memset(&xenstore_notifier, 0, sizeof(xenstore_notifier));
	INIT_LIST_HEAD(&ovmapi_info.parameter_list);
	INIT_LIST_HEAD(&ovmapi_info.registered_apps_list);
	mutex_init(&ovmapi_info.parameter_mutex);
	mutex_init(&ovmapi_info.apps_list_mutex);
	xenstore_notifier.notifier_call = ovmapi_init_watcher;
	ovmapi_info.event_counter = 0;
	register_xenstore_notifier(&xenstore_notifier);
	register_syscore_ops(&ovmapi_syscore_ops);

	return 0;
}

module_init(ovmapi_init);

/* FIXME: this cleanup is not enough
static void __exit ovmapi_exit(void)
{
	unregister_xenstore_notifier(&xenstore_notifier);
	kmem_cache_destroy(name_cache);
	kmem_cache_destroy(parameter_cache);
	kmem_cache_destroy(event_cache);
	misc_deregister(&ovmapi_dev);
}

module_exit(ovmapi_exit);
*/
