// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * vim: noexpandtab ts=8 sts=0 sw=8:
 *
 * configfs_example_macros.c - This file is a demonstration module
 *      containing a number of configfs subsystems.  It uses the helper
 *      macros defined by configfs.h
 *
 * Based on sysfs:
 *      sysfs is Copyright (C) 2001, 2002, 2003 Patrick Mochel
 *
 * configfs Copyright (C) 2005 Oracle.  All rights reserved.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/configfs.h>

/*
 * 01-childless
 *
 * This first example is a childless subsystem.  It cannot create
 * any config_items.  It just has attributes.
 *
 * Note that we are enclosing the configfs_subsystem inside a container.
 * This is not necessary if a subsystem has no attributes directly
 * on the subsystem.  See the next example, 02-simple-children, for
 * such a subsystem.
 */

struct childless {
	struct configfs_subsystem subsys;
	int showme;
	int storeme;
};

static inline struct childless *to_childless(struct config_item *item)
{
	return container_of(to_configfs_subsystem(to_config_group(item)),
			    struct childless, subsys);
}

static ssize_t childless_showme_show(struct config_item *item, char *page)
{
	struct childless *childless = to_childless(item);
	ssize_t pos;

	pos = sprintf(page, "%d\n", childless->showme);
	childless->showme++;

	return pos;
}

static ssize_t childless_storeme_show(struct config_item *item, char *page)
{
	return sprintf(page, "%d\n", to_childless(item)->storeme);
}

static ssize_t childless_storeme_store(struct config_item *item,
		const char *page, size_t count)
{
	struct childless *childless = to_childless(item);
	int ret;

	ret = kstrtoint(page, 10, &childless->storeme);
	if (ret)
		return ret;

	return count;
}

static ssize_t childless_description_show(struct config_item *item, char *page)
{
	return sprintf(page,
"[01-childless]\n"
"\n"
"The childless subsystem is the simplest possible subsystem in\n"
"configfs.  It does not support the creation of child config_items.\n"
"It only has a few attributes.  In fact, it isn't much different\n"
"than a directory in /proc.\n");
}

CONFIGFS_ATTR_RO(childless_, showme);
CONFIGFS_ATTR(childless_, storeme);
CONFIGFS_ATTR_RO(childless_, description);

static struct configfs_attribute *childless_attrs[] = {
	&childless_attr_showme,
	&childless_attr_storeme,
	&childless_attr_description,
	NULL,
};

static const struct config_item_type childless_type = {
	.ct_attrs	= childless_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct childless childless_subsys = {
	.subsys = {
		.su_group = {
			.cg_item = {
				.ci_namebuf = "01-childless",
				.ci_type = &childless_type,
			},
		},
	},
};

/* ----------------------------------------------------------------- */

/*
 * 02-simple-children
 *
 * This example merely has a simple one-attribute child.  Note that
 * there is no extra attribute structure, as the child's attribute is
 * known from the get-go.  Also, there is no container for the
 * subsystem, as it has no attributes of its own.
 */

struct simple_child {
	struct config_item item;
	int storeme;
};

static inline struct simple_child *to_simple_child(struct config_item *item)
{
	return container_of(item, struct simple_child, item);
}

static ssize_t simple_child_storeme_show(struct config_item *item, char *page)
{
	return sprintf(page, "%d\n", to_simple_child(item)->storeme);
}

static ssize_t simple_child_storeme_store(struct config_item *item,
		const char *page, size_t count)
{
	struct simple_child *simple_child = to_simple_child(item);
	int ret;

	ret = kstrtoint(page, 10, &simple_child->storeme);
	if (ret)
		return ret;

	return count;
}

CONFIGFS_ATTR(simple_child_, storeme);

static struct configfs_attribute *simple_child_attrs[] = {
	&simple_child_attr_storeme,
	NULL,
};

static void simple_child_release(struct config_item *item)
{
	kfree(to_simple_child(item));
}

static struct configfs_item_operations simple_child_item_ops = {
	.release	= simple_child_release,
};

static const struct config_item_type simple_child_type = {
	.ct_item_ops	= &simple_child_item_ops,
	.ct_attrs	= simple_child_attrs,
	.ct_owner	= THIS_MODULE,
};

struct simple_children {
	struct config_group group;
};

static inline struct simple_children *to_simple_children(struct config_item *item)
{
	return container_of(to_config_group(item),
			    struct simple_children, group);
}

static struct config_item *simple_children_make_item(struct config_group *group,
		const char *name)
{
	struct simple_child *simple_child;

	simple_child = kzalloc(sizeof(struct simple_child), GFP_KERNEL);
	if (!simple_child)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&simple_child->item, name,
				   &simple_child_type);

	return &simple_child->item;
}

static ssize_t simple_children_description_show(struct config_item *item,
		char *page)
{
	return sprintf(page,
"[02-simple-children]\n"
"\n"
"This subsystem allows the creation of child config_items.  These\n"
"items have only one attribute that is readable and writeable.\n");
}

CONFIGFS_ATTR_RO(simple_children_, description);

static struct configfs_attribute *simple_children_attrs[] = {
	&simple_children_attr_description,
	NULL,
};

static void simple_children_release(struct config_item *item)
{
	kfree(to_simple_children(item));
}

static struct configfs_item_operations simple_children_item_ops = {
	.release	= simple_children_release,
};

/*
 * Note that, since no extra work is required on ->drop_item(),
 * no ->drop_item() is provided.
 */
static struct configfs_group_operations simple_children_group_ops = {
	.make_item	= simple_children_make_item,
};

static const struct config_item_type simple_children_type = {
	.ct_item_ops	= &simple_children_item_ops,
	.ct_group_ops	= &simple_children_group_ops,
	.ct_attrs	= simple_children_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem simple_children_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "02-simple-children",
			.ci_type = &simple_children_type,
		},
	},
};

/* ----------------------------------------------------------------- */

/*
 * 03-group-children
 *
 * This example reuses the simple_children group from above.  However,
 * the simple_children group is not the subsystem itself, it is a
 * child of the subsystem.  Creation of a group in the subsystem creates
 * a new simple_children group.  That group can then have simple_child
 * children of its own.
 */

static struct config_group *group_children_make_group(
		struct config_group *group, const char *name)
{
	struct simple_children *simple_children;

	simple_children = kzalloc(sizeof(struct simple_children),
				  GFP_KERNEL);
	if (!simple_children)
		return ERR_PTR(-ENOMEM);

	config_group_init_type_name(&simple_children->group, name,
				    &simple_children_type);

	return &simple_children->group;
}

static ssize_t group_children_description_show(struct config_item *item,
		char *page)
{
	return sprintf(page,
"[03-group-children]\n"
"\n"
"This subsystem allows the creation of child config_groups.  These\n"
"groups are like the subsystem simple-children.\n");
}

CONFIGFS_ATTR_RO(group_children_, description);

static struct configfs_attribute *group_children_attrs[] = {
	&group_children_attr_description,
	NULL,
};

/*
 * Note that, since no extra work is required on ->drop_item(),
 * no ->drop_item() is provided.
 */
static struct configfs_group_operations group_children_group_ops = {
	.make_group	= group_children_make_group,
};

static const struct config_item_type group_children_type = {
	.ct_group_ops	= &group_children_group_ops,
	.ct_attrs	= group_children_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem group_children_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "03-group-children",
			.ci_type = &group_children_type,
		},
	},
};

/* ----------------------------------------------------------------- */

/*
 * 04-committable-children
 *
 * This is an example of a committable group.  It's similar to the simple
 * children example but each config_item has an additional 'committed'
 * attribute which is read-only and is only modified when the config_item
 * is moved from the 'pending' to the 'live' directory.
 */

struct committable_child {
	struct config_item item;
	int storeme;
	bool committed;
};

static inline struct committable_child *
to_committable_child(struct config_item *item)
{
	return container_of(item, struct committable_child, item);
}

static ssize_t
committable_child_storeme_show(struct config_item *item, char *page)
{
	return sprintf(page, "%d\n", to_committable_child(item)->storeme);
}

static ssize_t committable_child_storeme_store(struct config_item *item,
					       const char *page, size_t count)
{
	struct committable_child *child = to_committable_child(item);
	int ret;

	if (child->committed)
		return -EPERM;

	ret = kstrtoint(page, 10, &child->storeme);
	if (ret)
		return ret;

	return count;
}

CONFIGFS_ATTR(committable_child_, storeme);

static ssize_t
committable_child_committed_show(struct config_item *item, char *page)
{
	return sprintf(page, "%s\n",
		to_committable_child(item)->committed ? "true" : "false");
}

CONFIGFS_ATTR_RO(committable_child_, committed);

static struct configfs_attribute *committable_child_attrs[] = {
	&committable_child_attr_storeme,
	&committable_child_attr_committed,
	NULL,
};

static void committable_child_release(struct config_item *item)
{
	kfree(to_committable_child(item));
}

static struct configfs_item_operations committable_child_item_ops = {
	.release	= committable_child_release,
};

static const struct config_item_type committable_child_type = {
	.ct_item_ops	= &committable_child_item_ops,
	.ct_attrs	= committable_child_attrs,
	.ct_owner	= THIS_MODULE,
};

struct committable_children {
	struct config_group group;
};

static struct config_item *
committable_children_make_item(struct config_group *group, const char *name)
{
	struct committable_child *child;

	child = kzalloc(sizeof(*child), GFP_KERNEL);
	if (!child)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&child->item, name, &committable_child_type);

	return &child->item;
}

static ssize_t
committable_children_description_show(struct config_item *item, char *page)
{
	return sprintf(page,
"[04-committable-children]\n"
"\n"
"This subsystem allows creation of committable config_items.  The subsystem\n"
"has two subdirectories: pending and live.  New config_items can only be\n"
"created in pending/ and they have one writable and readable attribute as\n"
"well as a single read-only attribute.  The latter is only changed once the\n"
"item is 'committed'.  This is done by moving the config_item (using\n"
"rename()) to the live/ directory.  In this example, the storeme attribute\n"
"becomes 'read-only' once committed.\n");
}

CONFIGFS_ATTR_RO(committable_children_, description);

static struct configfs_attribute *committable_children_attrs[] = {
	&committable_children_attr_description,
	NULL,
};

static int committable_children_commit_item(struct config_item *item)
{
	to_committable_child(item)->committed = true;

	return 0;
}

static int committable_children_uncommit_item(struct config_item *item)
{
	to_committable_child(item)->committed = false;

	return 0;
}

static struct configfs_group_operations committable_children_group_ops = {
	.make_item	= committable_children_make_item,
	.commit_item	= committable_children_commit_item,
	.uncommit_item	= committable_children_uncommit_item,
};

static const struct config_item_type committable_children_type = {
	.ct_group_ops	= &committable_children_group_ops,
	.ct_attrs	= committable_children_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem committable_children_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "04-committable-children",
			.ci_type = &committable_children_type,
		},
	},
};

/* ----------------------------------------------------------------- */

/*
 * We're now done with our subsystem definitions.
 * For convenience in this module, here's a list of them all.  It
 * allows the init function to easily register them.  Most modules
 * will only have one subsystem, and will only call register_subsystem
 * on it directly.
 */
static struct configfs_subsystem *example_subsys[] = {
	&childless_subsys.subsys,
	&simple_children_subsys,
	&group_children_subsys,
	&committable_children_subsys,
	NULL,
};

static int __init configfs_example_init(void)
{
	struct configfs_subsystem *subsys;
	int ret, i;

	for (i = 0; example_subsys[i]; i++) {
		subsys = example_subsys[i];

		config_group_init(&subsys->su_group);
		mutex_init(&subsys->su_mutex);
		ret = configfs_register_subsystem(subsys);
		if (ret) {
			pr_err("Error %d while registering subsystem %s\n",
			       ret, subsys->su_group.cg_item.ci_namebuf);
			goto out_unregister;
		}
	}

	return 0;

out_unregister:
	for (i--; i >= 0; i--)
		configfs_unregister_subsystem(example_subsys[i]);

	return ret;
}

static void __exit configfs_example_exit(void)
{
	int i;

	for (i = 0; example_subsys[i]; i++)
		configfs_unregister_subsystem(example_subsys[i]);
}

module_init(configfs_example_init);
module_exit(configfs_example_exit);
MODULE_LICENSE("GPL");
