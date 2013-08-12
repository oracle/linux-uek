/*
 * Copyright 2009 Cisco Systems, Inc.  All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * [Insert appropriate license here when releasing outside of Cisco]
 * $Id: fnic_kcompat.h 111268 2012-08-27 17:11:40Z atungara $
 */

#ifndef _FNIC_KCOMPAT_H_
#define _FNIC_KCOMPAT_H_

#if BITS_PER_LONG == 64

#define div_u64(divisor, dividend) \
	(divisor) / (dividend); \

#else

/*
 * This is not a generic macro. It is specific to a dividend of 10^6
 */

#define div_u64(divisor, dividend) \
	/* \
	 * To convert to Megabytes, instead of dividing by 10^6, replace \
	 * by multiplying by (2 ^32 / 10^6 which is approx. 4295) \
	 * and then divide by 2^32. \
	 * \
	 * This avoids link break for 32 bit systems where the 64 bit \
	 * divide is not defined and keeps division error low, about 0.00076% \
	 */ \
	((divisor) * 4295) >> 32; \

#endif
typedef irqreturn_t (*isr)(int, void *);
#define scsi_set_tagged_support(sdev)	(sdev->tagged_supported = 1)

#endif /* _FNIC_KCOMPAT_H_ */
