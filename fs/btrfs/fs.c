// SPDX-License-Identifier: GPL-2.0

#include <linux/crc32c.h>
#include <linux/xxhash.h>
#include <crypto/sha2.h>
#include <crypto/blake2b.h>
#include <linux/unaligned.h>
#include "messages.h"
#include "ctree.h"
#include "fs.h"
#include "accessors.h"

void __btrfs_set_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag,
			     const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info,
				"setting incompat feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
		set_bit(BTRFS_FS_FEATURE_CHANGED, &fs_info->flags);
	}
}

void __btrfs_clear_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag,
			       const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info,
				"clearing incompat feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
		set_bit(BTRFS_FS_FEATURE_CHANGED, &fs_info->flags);
	}
}

void __btrfs_set_fs_compat_ro(struct btrfs_fs_info *fs_info, u64 flag,
			      const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info,
				"setting compat-ro feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
		set_bit(BTRFS_FS_FEATURE_CHANGED, &fs_info->flags);
	}
}

void __btrfs_clear_fs_compat_ro(struct btrfs_fs_info *fs_info, u64 flag,
				const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info,
				"clearing compat-ro feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
		set_bit(BTRFS_FS_FEATURE_CHANGED, &fs_info->flags);
	}
}

void btrfs_csum(u16 csum_type, const u8 *data, size_t len, u8 *out)
{
	switch (csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
		put_unaligned_le32(~crc32c(~0, data, len), out);
		break;
	case BTRFS_CSUM_TYPE_XXHASH:
		put_unaligned_le64(xxh64(data, len, 0), out);
		break;
	case BTRFS_CSUM_TYPE_SHA256:
		sha256(data, len, out);
		break;
	case BTRFS_CSUM_TYPE_BLAKE2:
		blake2b(NULL, 0, data, len, out, 32);
		break;
	default:
		/* Checksum type is validated at mount time. */
		BUG();
	}
}

void btrfs_csum_init(struct btrfs_csum_ctx *ctx, u16 csum_type)
{
	ctx->csum_type = csum_type;
	switch (ctx->csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
		ctx->crc32 = ~0;
		break;
	case BTRFS_CSUM_TYPE_XXHASH:
		xxh64_reset(&ctx->xxh64, 0);
		break;
	case BTRFS_CSUM_TYPE_SHA256:
		sha256_init(&ctx->sha256);
		break;
	case BTRFS_CSUM_TYPE_BLAKE2:
		blake2b_init(&ctx->blake2b, 32);
		break;
	default:
		/* Checksum type is validated at mount time. */
		BUG();
	}
}

void btrfs_csum_update(struct btrfs_csum_ctx *ctx, const u8 *data, size_t len)
{
	switch (ctx->csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
		ctx->crc32 = crc32c(ctx->crc32, data, len);
		break;
	case BTRFS_CSUM_TYPE_XXHASH:
		xxh64_update(&ctx->xxh64, data, len);
		break;
	case BTRFS_CSUM_TYPE_SHA256:
		sha256_update(&ctx->sha256, data, len);
		break;
	case BTRFS_CSUM_TYPE_BLAKE2:
		blake2b_update(&ctx->blake2b, data, len);
		break;
	default:
		/* Checksum type is validated at mount time. */
		BUG();
	}
}

void btrfs_csum_final(struct btrfs_csum_ctx *ctx, u8 *out)
{
	switch (ctx->csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
		put_unaligned_le32(~ctx->crc32, out);
		break;
	case BTRFS_CSUM_TYPE_XXHASH:
		put_unaligned_le64(xxh64_digest(&ctx->xxh64), out);
		break;
	case BTRFS_CSUM_TYPE_SHA256:
		sha256_final(&ctx->sha256, out);
		break;
	case BTRFS_CSUM_TYPE_BLAKE2:
		blake2b_final(&ctx->blake2b, out);
		break;
	default:
		/* Checksum type is validated at mount time. */
		BUG();
	}
}
