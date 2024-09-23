/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * BPF program to set initial receive window to 40 packets when using IPv6
 * and the first 5.5 bytes of the IPv6 addresses are not the same (in this
 * example that means both hosts are not the same datacenter).
 *
 * Use "bpftool cgroup attach $cg sock_ops $prog" to load this BPF program.
 */

#include "../bpf.h"

int bpf_ntohl(unsigned int v)
/*@ Require exists v0, v == v0
    Ensure exists v0, __return == v0
*/;

int bpf_rwnd(struct bpf_sock_ops *skops)
/*@ Require Sock_ops(skops)
    Ensure exists v, __return == v && TT
*/
{
	int rv = -1;
	int op;

	/* For testing purposes, only execute rest of BPF program
	 * if neither port numberis 55601
	 */
  int remote_val = bpf_ntohl(skops->remote_port);
	if (remote_val !=
	    55601 && skops->local_port != 55601) {
		skops->reply = (unsigned int)-1;
		return 1;
	}

	op = (int) skops->op;

	/* Check for RWND_INIT operation and IPv6 addresses */
	if (op == 2 &&
		skops->family == 10) {

		/* If the first 5.5 bytes of the IPv6 address are not the same
		 * then both hosts are not in the same datacenter
		 * so use a larger initial advertized window (40 packets)
		 */
    unsigned int *local_ip6 = (unsigned int *)&skops->local_ip6;
    unsigned int local_ip6_0 = local_ip6[0];
    unsigned int *remote_ip6 = (unsigned int *)&skops->remote_ip6;
    unsigned int remote_ip6_0 = remote_ip6[0];
		if (local_ip6_0 != remote_ip6_0) 
      rv = 40;
    else {
        unsigned int local_ip6_1 = ((unsigned int)bpf_ntohl(local_ip6[1]));
        unsigned int remote_ip6_1 = ((unsigned int)bpf_ntohl(remote_ip6[1]));
		    if ((local_ip6_1 & ((unsigned int)0xfffff000)) !=
          (remote_ip6_1 & ((unsigned int)0xfffff000)))
			  rv = 40;
    }
	}
	skops->reply = (unsigned int)rv;
	return 1;
}
