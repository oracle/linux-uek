// SPDX-License-Identifier: GPL-2.0
/*
 * rds echo client/server program used to verify tracepoint firing.
 *
 * Author: Alan Maguire <alan.maguire@oracle.com>
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <unistd.h>

/* needed by linux/rds.h */
typedef __s64 time64_t;

#include <linux/rds.h>

#define RDS_ECHOBUF_MAX	2048

static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -l localIP -p localPort -r remoteIP -P remotePort\n",
		prog);
	return 1;
}

void setup_msg(struct msghdr *msg, struct iovec *iov, char *buf, int buflen,
	       struct sockaddr_storage *addr, int addrlen)
{
	memset(msg, 0, sizeof(*msg));
	memset(iov, 0, sizeof(*iov));
	iov->iov_base = buf;
	iov->iov_len = buflen;
	msg->msg_iov = iov;
	msg->msg_iovlen = 1;
	msg->msg_name = addr;
	msg->msg_namelen = addrlen;
}

int main(int argc, char **argv)
{
	int sock, addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_storage laddr, raddr;
	char buf[RDS_ECHOBUF_MAX];
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	int family = AF_INET;
	struct msghdr msg;
	struct iovec iov;
	int isserver = 0;
	int c, ret = 1;
	void *a;

	memset(&laddr, 0, sizeof(laddr));
	memset(&raddr, 0, sizeof(raddr));

	while ((c = getopt(argc, argv, "l:r:p:P:s")) != -1) {
		switch (c) {
		case 'l':
			a = &((struct sockaddr_in *)&laddr)->sin_addr;
			if (strchr(optarg, ':')) {
				family = AF_INET6;
				addrlen = sizeof(struct sockaddr_in6);
				a = &((struct sockaddr_in6 *)&laddr)->sin6_addr;
			}
			if (inet_pton(family, optarg, a) != 1) {
				fprintf(stderr, "invalid laddr %s\n", optarg);
				return usage(argv[0]);
			}
			laddr.ss_family = family;
			break;
		case 'r':
			sin = (struct sockaddr_in *)&raddr;
			a = &sin->sin_addr;
			if (strchr(optarg, ':')) {
				family = AF_INET6;
				addrlen = sizeof(struct sockaddr_in6);
				sin6 = (struct sockaddr_in6 *)&raddr;
				a = &sin6->sin6_addr;

			}
			if (inet_pton(family, optarg, a) != 1) {
				fprintf(stderr, "invalid raddr %s\n", optarg);
				return usage(argv[0]);
			}
			raddr.ss_family = family;
			break;
		case 'p':
			sin = (struct sockaddr_in *)&laddr;
			sin->sin_port = htons(atoi(optarg));
			break;
		case 'P':
			sin = (struct sockaddr_in *)&raddr;
			sin->sin_port = htons(atoi(optarg));
			break;
		case 's':
			isserver = 1;
			break;
		default:
			return usage(argv[0]);
		}
	}

	if (laddr.ss_family != raddr.ss_family) {
		fprintf(stderr, "IPv4/v6 mismatch in addresses\n");
		return 1;
	}
	if (laddr.ss_family == 0 || raddr.ss_family == 0) {
		fprintf(stderr,
			"local (-l) and remote (-r) addrs must be specified\n");
		return usage(argv[0]);
	}
	if (((struct sockaddr_in *)&laddr)->sin_port == 0 ||
	    ((struct sockaddr_in *)&raddr)->sin_port == 0) {
		fprintf(stderr,
			"local (-p) and remote (-r) ports must be specified\n");
		return usage(argv[0]);
	}

	sock = socket(AF_RDS, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	if (bind(sock, (struct sockaddr *)&laddr, addrlen) < 0) {
		perror("bind");
		goto out;
	}

	/*
	 * Loop until we see an empty message (server), send an empty message
	 * or run out of input (client).
	 */
	for (;;) {
		if (isserver) {
			setup_msg(&msg, &iov, buf, sizeof(buf), NULL, 0);
			if (recvmsg(sock, &msg, 0) < 0) {
				perror("recvmsg");
				break;
			}
			setup_msg(&msg, &iov, buf, strlen(buf) + 1, &raddr,
				  addrlen);
			if (sendmsg(sock, &msg, 0) < 0) {
				perror("sendmsg");
				break;
			}

			if (strlen(buf) == 0) {
				ret = 0;
				break;
			}
		} else {
			if (fgets(buf, sizeof(buf), stdin) == NULL)
				buf[0] = '\0';

			if (buf[strlen(buf) - 1] == '\n')
				buf[strlen(buf) - 1] = '\0';

			setup_msg(&msg, &iov, buf, strlen(buf) + 1, &raddr,
				  addrlen);
			if (sendmsg(sock, &msg, 0) < 0) {
				perror("sendmsg");
				break;
			}
			setup_msg(&msg, &iov, buf, sizeof(buf), NULL, 0);
			if (recvmsg(sock, &msg, 0) < 0) {
				perror("recvmsg");
				break;
			}
			printf("%s\n", buf);

			if (strlen(buf) == 0) {
				ret = 0;
				break;
			}
		}
	}

out:
	close(sock);

	return ret;
}
