// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "../mm/slab.h"


static void test_clobber_zone(struct kunit *test)
{
	struct kmem_cache *s = kmem_cache_create("TestSlub_RZ_alloc", 64, 0,
				SLAB_RED_ZONE | SLAB_SILENT_ERRORS, NULL);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	p[64] = 0x12;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 1, s->errors);

	kmem_cache_free(s, p);
	kmem_cache_destroy(s);
}

static void test_next_pointer(struct kunit *test)
{
	struct kmem_cache *s = kmem_cache_create("TestSlub_next_ptr_free", 64, 0,
				SLAB_POISON | SLAB_SILENT_ERRORS, NULL);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);
	unsigned long tmp;
	unsigned long *ptr_addr;

	kmem_cache_free(s, p);

	ptr_addr = (unsigned long *)(p + s->offset);
	tmp = *ptr_addr;
	p[s->offset] = 0x12;

	/*
	 * Expecting two errors.
	 * One for the corrupted freechain and the other one for the wrong
	 * count of objects in use.
	 */
	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, s->errors);

	/*
	 * Try to repair corrupted freepointer.
	 * Still expecting one error for the wrong count of objects in use.
	 */
	*ptr_addr = tmp;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 1, s->errors);

	/*
	 * Previous validation repaired the count of objects in use.
	 * Now expecting no error.
	 */
	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 0, s->errors);

	kmem_cache_destroy(s);
}

static void test_first_word(struct kunit *test)
{
	struct kmem_cache *s = kmem_cache_create("TestSlub_1th_word_free", 64, 0,
				SLAB_POISON | SLAB_SILENT_ERRORS, NULL);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_free(s, p);
	*p = 0x78;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 1, s->errors);

	kmem_cache_destroy(s);
}

static void test_clobber_50th_byte(struct kunit *test)
{
	struct kmem_cache *s = kmem_cache_create("TestSlub_50th_word_free", 64, 0,
				SLAB_POISON | SLAB_SILENT_ERRORS, NULL);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_free(s, p);
	p[50] = 0x9a;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 1, s->errors);
	kmem_cache_destroy(s);
}

static void test_clobber_redzone_free(struct kunit *test)
{
	struct kmem_cache *s = kmem_cache_create("TestSlub_RZ_free", 64, 0,
				SLAB_RED_ZONE | SLAB_SILENT_ERRORS, NULL);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_free(s, p);
	p[64] = 0xab;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 1, s->errors);
	kmem_cache_destroy(s);
}

static struct kunit_case test_cases[] = {
	KUNIT_CASE(test_clobber_zone),
	KUNIT_CASE(test_next_pointer),
	KUNIT_CASE(test_first_word),
	KUNIT_CASE(test_clobber_50th_byte),
	KUNIT_CASE(test_clobber_redzone_free),
	{}
};

static struct kunit_suite test_suite = {
	.name = "slub_test",
	.test_cases = test_cases,
};
kunit_test_suite(test_suite);

MODULE_LICENSE("GPL");
