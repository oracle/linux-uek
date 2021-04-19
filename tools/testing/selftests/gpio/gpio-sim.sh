#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 Bartosz Golaszewski <bgolaszewski@baylibre.com>

BASE_DIR=`dirname $0`
CONFIGFS_DIR="/sys/kernel/config/gpio-sim"
PENDING_DIR=$CONFIGFS_DIR/pending
LIVE_DIR=$CONFIGFS_DIR/live
MODULE="gpio-sim"

fail() {
	echo "$*" >&2
	echo "GPIO $MODULE test FAIL"
	exit 1
}

skip() {
	echo "$*" >&2
	echo "GPIO $MODULE test SKIP"
	exit 4
}

configfs_cleanup() {
	for DIR in `ls $LIVE_DIR`; do
		mv $LIVE_DIR/$DIR $PENDING_DIR
	done

	for DIR in `ls $PENDING_DIR`; do
		rmdir $PENDING_DIR/$DIR
	done
}

create_pending_chip() {
	local NAME="$1"
	local LABEL="$2"
	local NUM_LINES="$3"
	local LINE_NAMES="$4"
	local CHIP_DIR="$PENDING_DIR/$NAME"

	mkdir $CHIP_DIR
	test -n "$LABEL" && echo $LABEL > $CHIP_DIR/label
	test -n "$NUM_LINES" && echo $NUM_LINES > $CHIP_DIR/num_lines
	if [ -n "$LINE_NAMES" ]; then
		echo $LINE_NAMES 2> /dev/null > $CHIP_DIR/line_names
		# This one can fail
		if [ "$?" -ne "0" ]; then
			return 1
		fi
	fi
}

create_live_chip() {
	local CHIP_DIR="$PENDING_DIR/$1"

	create_pending_chip "$@" || fail "unable to create the chip configfs item"
	mv $CHIP_DIR $LIVE_DIR || fail "unable to commit the chip configfs item"
}

remove_pending_chip() {
	local NAME="$1"

	rmdir $PENDING_DIR/$NAME || fail "unable to remove the chip configfs item"
}

remove_live_chip() {
	local NAME="$1"

	mv $LIVE_DIR/$NAME $PENDING_DIR || fail "unable to uncommit the chip configfs item"
	remove_pending_chip "$@"
}

configfs_chip_name() {
	local CHIP="$1"

	cat $LIVE_DIR/$CHIP/chip_name 2> /dev/null || return 1
}

configfs_dev_name() {
	local CHIP="$1"

	cat $LIVE_DIR/$CHIP/dev_name 2> /dev/null || return 1
}

get_chip_num_lines() {
	local CHIP="$1"

	$BASE_DIR/gpio-chip-info /dev/`configfs_chip_name $CHIP` num-lines
}

get_chip_label() {
	local CHIP="$1"

	$BASE_DIR/gpio-chip-info /dev/`configfs_chip_name $CHIP` label
}

get_line_name() {
	local CHIP="$1"
	local OFFSET="$2"

	$BASE_DIR/gpio-line-name /dev/`configfs_chip_name $CHIP` $OFFSET
}

sysfs_set_pull() {
	local CHIP="$1"
	local OFFSET="$2"
	local PULL="$3"
	local SYSFSPATH="/sys/devices/platform/`configfs_dev_name $CHIP`/line-ctrl/gpio$OFFSET"

	echo $PULL > $SYSFSPATH
}

# Load the gpio-sim module. This will pull in configfs if needed too.
modprobe gpio-sim || skip "unable to load the gpio-sim module"
# Make sure configfs is mounted at /sys/kernel/config. Wait a bit if needed.
for IDX in `seq 5`; do
	if [ "$IDX" -eq "5" ]; then
		skip "configfs not mounted at /sys/kernel/config"
	fi

	mountpoint -q /sys/kernel/config && break
	sleep 0.1
done
# If the module was already loaded: remove all previous chips
configfs_cleanup

trap "exit 1" SIGTERM SIGINT
trap configfs_cleanup EXIT

echo "1. chip_name and dev_name attributes"

echo "1.1. Chip name is communicated to user"
create_live_chip chip
test -n `cat $LIVE_DIR/chip/chip_name` || fail "chip_name doesn't work"
remove_live_chip chip

echo "1.2. chip_name returns 'none' if the chip is still pending"
create_pending_chip chip
test "`cat $PENDING_DIR/chip/chip_name`" = "none" || fail "chip_name doesn't return 'none' for a pending chip"
remove_pending_chip chip

echo "1.3. Device name is communicated to user"
create_live_chip chip
test -n `cat $LIVE_DIR/chip/dev_name` || fail "dev_name doesn't work"
remove_live_chip chip

echo "1.4. dev_name returns 'none' if chip is still pending"
create_pending_chip chip
test "`cat $PENDING_DIR/chip/dev_name`" = "none" || fail "dev_name doesn't return 'none' for a pending chip"
remove_pending_chip chip

echo "2. Creating simulated chips"

echo "2.1. Default number of lines is 1"
create_live_chip chip
test "`get_chip_num_lines chip`" = "1" || fail "default number of lines is not 1"
remove_live_chip chip

echo "2.2. Number of lines can be specified"
create_live_chip chip test-label 16
test "`get_chip_num_lines chip`" = "16" || fail "number of lines is not 16"
remove_live_chip chip

echo "2.3. Label can be set"
create_live_chip chip foobar
test "`get_chip_label chip`" = "foobar" || fail "label is incorrect"
remove_live_chip chip

echo "2.4. Label can be left empty"
create_live_chip chip
test -z "`cat $LIVE_DIR/chip/label`" || fail "label is not empty"
remove_live_chip chip

echo "2.5. Line names can be configured"
create_live_chip chip test-label 16 '"foo", "", "bar"'
test "`get_line_name chip 0`" = "foo" || fail "line name is incorrect"
test "`get_line_name chip 2`" = "bar" || fail "line name is incorrect"
remove_live_chip chip

echo "2.6. Errors in line names are detected"
create_pending_chip chip test-label 8 '"foo", bar' && fail "incorrect line name accepted"
remove_pending_chip chip
create_pending_chip chip test-label 8 '"foo" "bar"' && fail "incorrect line name accepted"
remove_pending_chip chip

echo "2.7. Multiple chips can be created"
create_live_chip chip0
create_live_chip chip1
create_live_chip chip2
remove_live_chip chip0
remove_live_chip chip1
remove_live_chip chip2

echo "3. Controlling simulated chips"

echo "3.3. Pull can be set over sysfs"
create_live_chip chip test-label 8
sysfs_set_pull chip 0 1
$BASE_DIR/gpio-mockup-cdev /dev/`configfs_chip_name chip` 0
test "$?" = "1" || fail "pull set incorrectly"
sysfs_set_pull chip 0 0
$BASE_DIR/gpio-mockup-cdev /dev/`configfs_chip_name chip` 1
test "$?" = "0" || fail "pull set incorrectly"
remove_live_chip chip

echo "3.4. Incorrect input in sysfs is rejected"
create_live_chip chip test-label 8
SYSFS_PATH="/sys/devices/platform/`configfs_dev_name chip`/line-ctrl/gpio0"
echo 2 > $SYSFS_PATH 2> /dev/null && fail "invalid input not detectec"
remove_live_chip chip

echo "4. Simulated GPIO chips are functional"

echo "4.1. Values can be read from sysfs"
create_live_chip chip test-label 8
SYSFS_PATH="/sys/devices/platform/`configfs_dev_name chip`/line-ctrl/gpio0"
test `cat $SYSFS_PATH` = "0" || fail "incorrect value read from sysfs"
$BASE_DIR/gpio-mockup-cdev -s 1 /dev/`configfs_chip_name chip` 0 &
sleep 0.1 # FIXME Any better way?
test `cat $SYSFS_PATH` = "1" || fail "incorrect value read from sysfs"
kill $!
remove_live_chip chip

echo "4.2. Bias settings work correctly"
create_live_chip chip test-label 8
$BASE_DIR/gpio-mockup-cdev -b pull-up /dev/`configfs_chip_name chip` 0
test `cat $SYSFS_PATH` = "1" || fail "bias setting does not work"
remove_live_chip chip

echo "GPIO $MODULE test PASS"
