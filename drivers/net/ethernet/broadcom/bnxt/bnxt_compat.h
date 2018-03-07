/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2014-2016 Broadcom Corporation
 * Copyright (c) 2016-2017 Broadcom Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/time.h>
#include <linux/pci.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#if !defined(NEW_FLOW_KEYS) && defined(HAVE_FLOW_KEYS)
#include <net/flow_keys.h>
#endif
#include <linux/sched.h>


#ifndef SWITCHDEV_SET_OPS
#define SWITCHDEV_SET_OPS(netdev, ops) ((netdev)->switchdev_ops = (ops))
#endif

/*
 *  * Nonzero if YEAR is a leap year (every 4 years,
 *   * except every 100th isn't, and every 400th is).
 *    */
static int __isleap(long year)
{
        return (year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0);
}

/* do a mathdiv for long type */
static long math_div(long a, long b)
{
        return a / b - (a % b < 0);
}

/* How many leap years between y1 and y2, y1 must less or equal to y2 */
static long leaps_between(long y1, long y2)
{
        long leaps1 = math_div(y1 - 1, 4) - math_div(y1 - 1, 100)
                + math_div(y1 - 1, 400);
        long leaps2 = math_div(y2 - 1, 4) - math_div(y2 - 1, 100)
                + math_div(y2 - 1, 400);
        return leaps2 - leaps1;
}

/* How many days come before each month (0-12). */
static const unsigned short __mon_yday[2][13] = {
        /* Normal years. */
        {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
        /* Leap years. */
        {0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}
};

#define SECS_PER_HOUR   (60 * 60)
#define SECS_PER_DAY    (SECS_PER_HOUR * 24)

/**
 *  * time64_to_tm - converts the calendar time to local broken-down time
 *   *
 *    * @totalsecs   the number of seconds elapsed since 00:00:00 on January 1, 1970,
 *     *              Coordinated Universal Time (UTC).
 *      * @offset      offset seconds adding to totalsecs.
 *       * @result      pointer to struct tm variable to receive broken-down time
 *        */
void time64_to_tm(time64_t totalsecs, int offset, struct tm *result)
{
        long days, rem, y;
        int remainder;
        const unsigned short *ip;

        days = div_s64_rem(totalsecs, SECS_PER_DAY, &remainder);
        rem = remainder;
        rem += offset;
        while (rem < 0) {
                rem += SECS_PER_DAY;
                --days;
        }
        while (rem >= SECS_PER_DAY) {
                rem -= SECS_PER_DAY;
                ++days;
        }

        result->tm_hour = rem / SECS_PER_HOUR;
        rem %= SECS_PER_HOUR;
        result->tm_min = rem / 60;
        result->tm_sec = rem % 60;

        /* January 1, 1970 was a Thursday. */
        result->tm_wday = (4 + days) % 7;
        if (result->tm_wday < 0)
                result->tm_wday += 7;

        y = 1970;

        while (days < 0 || days >= (__isleap(y) ? 366 : 365)) {
                /* Guess a corrected year, assuming 365 days per year. */
                long yg = y + math_div(days, 365);

                /* Adjust DAYS and Y to match the guessed year. */
                days -= (yg - y) * 365 + leaps_between(y, yg);
                y = yg;
        }

        result->tm_year = y - 1900;

        result->tm_yday = days;

        ip = __mon_yday[__isleap(y)];
        for (y = 11; days < ip[y]; y--)
                continue;
        days -= ip[y];
        result->tm_mon = y;
        result->tm_mday = days + 1;
}

