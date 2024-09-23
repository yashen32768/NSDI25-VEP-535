/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2018 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program shows how to use bpf_xdp_adjust_tail() by
 * generating ICMPv4 "packet to big" (unreachable/ df bit set frag needed
 * to be more preice in case of v4)" where receiving packets bigger then
 * 600 bytes.
 */
#include "../bpf.h"

struct bpf_map_def icmpcnt  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(unsigned long long),
  .max_entries = 1
};

int handle_ipv4(struct xdp_md *xdp)
/*@ Require emp
    Ensure exists v, __return == v
*/
;

int htons(int x)
/*@ Require emp  
    Ensure exists v, __return == v
*/;

int _xdp_icmp(struct xdp_md *xdp)
/*@ 
  Require XDP_SEP(xdp) && Ebpf_map(icmpcnt, 1, 2, 8)
  Ensure exists v, __return == v && TT
*/
{
  void *data_end;
  data_end = (void *)(long long)xdp->data_end;
  void *data;
  data = (void *)(long long)xdp->data;
  struct eth_hdr *eth;
  eth = data;
  unsigned int h_proto;
  void *eth_end;
  eth_end = (void*)((long long) eth + (long long) sizeof(struct eth_hdr));
  if ((long long) eth_end > (long long) data_end)
    return 1;

  h_proto = eth->h_proto;

  if ((int)h_proto == htons(4096))
    return handle_ipv4(xdp);
  else
    return 2;
}

