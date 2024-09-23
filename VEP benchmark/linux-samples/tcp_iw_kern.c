/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * BPF program to set initial congestion window and initial receive
 * window to 40 packets and send and receive buffers to 1.5MB. This
 * would usually be done after doing appropriate checks that indicate
 * the hosts are far enough away (i.e. large RTT).
 *
 * Use "bpftool cgroup attach $cg sock_ops $prog" to load this BPF program.
 */

#include "../bpf.h"

int bpf_ntohl(unsigned int v)
/*@ Require exists v0, v == v0
    Ensure exists v0, __return == v0
*/;

int bpf_iw(struct bpf_sock_ops *skops)
/*@ Require Sock_ops(skops)
    Ensure exists v, __return == v && TT
*/
{
	int bufsize = 1500000;
	int rwnd_init = 40;
	int iw = 40;
	int rv = 0;
	int op;

	/* For testing purposes, only execute rest of BPF program
	 * if neither port numberis 55601
	 */
  int remote_port_v = bpf_ntohl(skops->remote_port);
	if (remote_port_v != 55601 &&
	    skops->local_port != 55601) {
		skops->reply = (unsigned int)-1;
		return 1;
	}

	op = (int) skops->op;

	/* Usually there would be a check to insure the hosts are far
	 * from each other so it makes sense to increase buffer sizes
	 */
	switch (op) {
	case 2:
		rv = rwnd_init;
		break;
	case 3: {
		/* Set sndbuf and rcvbuf of active connections */
		rv = (int)bpf_setsockopt(skops, 0xffff, 0x1001, &bufsize, sizeof(int));
		rv += (int)bpf_setsockopt(skops, 0xffff, 0x1002,
				     &bufsize, sizeof(int));
		break;
  }
	case 4:
		rv = (int)bpf_setsockopt(skops, 6, 1001, &iw,
				    sizeof(int));
		break;
	case 5:
		/* Set sndbuf and rcvbuf of passive connections */
		rv = (int)bpf_setsockopt(skops, 0xffff, 0x1001, &bufsize,
				    sizeof(int));
		rv +=  (int)bpf_setsockopt(skops, 0xffff, 0x1002,
				      &bufsize, sizeof(int));
		break;
	default:
		rv = -1;
	}
	skops->reply = (unsigned int)rv;
	return 1;
}
