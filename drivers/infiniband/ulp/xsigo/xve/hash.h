/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef HASH_H
#define HASH_H 1

/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style. */

#define HASH_ROT(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define HASH_MIX(a, b, c)                       \
	do {					\
		a -= c; a ^= HASH_ROT(c, 4); c += b;	\
		b -= a; b ^= HASH_ROT(a, 6); a += c;	\
		c -= b; c ^= HASH_ROT(b, 8); b += a;	\
		a -= c; a ^= HASH_ROT(c, 16); c += b;	\
		b -= a; b ^= HASH_ROT(a, 19); a += c;	\
		c -= b; c ^= HASH_ROT(b, 4); b += a;	\
	} while (0)

#define HASH_FINAL(a, b, c)			\
	do {					\
		c ^= b; c -= HASH_ROT(b, 14);		\
		a ^= c; a -= HASH_ROT(c, 11);		\
		b ^= a; b -= HASH_ROT(a, 25);		\
		c ^= b; c -= HASH_ROT(b, 16);		\
		a ^= c; a -= HASH_ROT(c,  4);		\
		b ^= a; b -= HASH_ROT(a, 14);		\
		c ^= b; c -= HASH_ROT(b, 24);		\
	} while (0)

static inline uint32_t hash_bytes(const void *p_, size_t n, uint32_t basis)
{
	const uint8_t *p = p_;
	uint32_t a, b, c;
	uint32_t tmp[3];

	a = b = c = 0xdeadbeef + n + basis;

	while (n >= sizeof(tmp)) {
		memcpy(tmp, p, sizeof(tmp));
		a += tmp[0];
		b += tmp[1];
		c += tmp[2];
		HASH_MIX(a, b, c);
		n -= sizeof(tmp);
		p += sizeof(tmp);
	}

	if (n) {
		tmp[0] = tmp[1] = tmp[2] = 0;
		memcpy(tmp, p, n);
		a += tmp[0];
		b += tmp[1];
		c += tmp[2];
		HASH_FINAL(a, b, c);
	}

	return c;
}

#endif /* hash.h */
