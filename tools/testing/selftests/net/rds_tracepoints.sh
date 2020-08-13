#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2020, Oracle and/or its affiliates.

#
# Test RDS send, receive and drop_ingress tracepoints fire using rds
# echo program.  For send/receive use client/server to send a message from
# client to server which will be echoed back.  For inbound drop we send
# message from client when no server is running; this will generate an
# inbound drop since no listening socket is present.  Sadly there is no simple
# way to generate outbound drops so we avoid that case for now.
#
# Test execution will be skipped if the rds module is not present.
# All communication happens via the RDS loopback and tcp transports.
#

readonly ksft_skip=4
readonly cport=1234
readonly sport=1235
readonly rds_events=/tmp/rds_events.$$
readonly tcplocal=192.168.100.1
readonly tcpremote=192.168.100.2

modprobe rds
have_rds=$?
if [[ $have_rds -ne 0 ]]; then
	echo "RDS not present; skipping."
	exit $ksft_skip
fi

# RDS loopback transport-supported addresses
laddrs="127.0.0.1 ::1"

modprobe rds_tcp
have_rds_tcp=$?
# For rds-tcp add remote address in namespace for us to talk to.
if [[ $have_rds_tcp -eq 0 ]]; then
	ip netns add rdsns
	ip link add dev rdsveth1 mtu 1500 netns rdsns type veth \
		peer name rdsveth2 mtu 1500
	ip addr add ${tcplocal}/24 dev rdsveth2
	ip -netns rdsns addr add ${tcpremote}/24 dev rdsveth1
	ip link set rdsveth2 up
	ip -netns rdsns link set rdsveth1 up
	laddrs="$tcplocal $laddrs"
fi
rmmod rds_tcp
set -e

cleanup() {
	set +e
	if [[ -n $serverprog ]]; then
		kill -TERM $serverprog
	fi
	if [[ -n $tracepipe ]]; then
		kill -TERM $tracepipe
	fi
	sleep 1
	rmmod rds_tcp
	rmmod rds
	rm -f $rds_events
	ip netns delete rdsns
}

trap cleanup EXIT

generic_tracepoints="rds_conn_destroy \
		     rds_queue_work rds_queue_worker rds_queue_flush_work \
		     rds_state_change rds_send rds_receive rds_drop_ingress"

for laddr in $laddrs ; do
	if [[ $laddr == $tcplocal ]]; then
		tracepoints="rds_tcp_state_change rds_tcp_accept \
			     rds_tcp_shutdown \
			     $generic_tracepoints"
	else
		tracepoints="$generic_tracepoints"
	fi

	for testtrace in $tracepoints
	do
		modprobe rds

		case $testtrace in
		rds_drop_ingress)
			# Drop test won't work for rds-tcp; binding client fails
			if [[ $laddr == $tcplocal ]]; then
				continue
			fi
			serverprog=
			;;
		*)
			if [[ $laddr == $tcplocal ]]; then
				modprobe rds_tcp
				sleep 1
				ip netns exec rdsns ./rds_echo -l $tcpremote \
					-p $sport -r $laddr  -P $cport -s &
			else
				./rds_echo -l $laddr -p $sport -r $laddr \
					-P $cport -s &
			fi
			serverprog=$!
			;;
		esac

		echo "Test $testtrace tracepoints for $laddr"

		sleep 1
		echo 1 > \
		    /sys/kernel/debug/tracing/events/rds/${testtrace}/enable

		cat /sys/kernel/debug/tracing/trace_pipe > $rds_events &
		tracepipe=$!

		if [[ $laddr == $tcplocal ]]; then
			raddr=$tcpremote
		else
			raddr=$laddr
		fi
		set +e
		echo test | timeout 5 \
			./rds_echo -l $laddr -p $cport -r $raddr \
					     -P $sport >/dev/null
		set -e

		sleep 1

		if [[ $laddr == $tcplocal ]]; then
			rmmod rds_tcp ||true
		fi
		rmmod rds

		sleep 1

		kill -TERM $tracepipe

		grep $testtrace $rds_events
		rm -f $rds_events

		echo OK

		serverprog=
		tracepipe=
	done
done

echo "OK. All tests passed"

exit 0
