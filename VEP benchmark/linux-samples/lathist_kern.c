/* Copyright (c) 2013-2015 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2015 BMW Car IT GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "../bpf.h"

/* We need to stick to static allocated memory (an array instead of
 * hash table) because managing dynamic memory from the
 * trace_preempt_[on|off] tracepoints hooks is not supported.
 */

struct bpf_map_def my_map  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(unsigned long long),
  .max_entries = 4
};

struct bpf_map_def my_lat  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 4 * 20
};

static unsigned int log2(unsigned int v)
/*@ Require v > 0
    Ensure exists v0, __return == v0
*/
{
	unsigned int r;
	unsigned int shift;

	r = (unsigned int)(v > 0xFFFF) << 4; v >>= r;
	shift = (unsigned int)(v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (unsigned int)(v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (unsigned int)(v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (unsigned int)(v >> 1);

	return r;
}

static unsigned int log2l(unsigned int v)
/*@ Require v > 0
    Ensure exists v0, __return == v0
*/
{
	unsigned int hi = v >> 32;

	if (hi)
		return log2(hi) + 32;
	else
		return log2(v);
}

int bpf_prog2(struct pt_regs *ctx)
/*@ Require ctx != 0 && Ebpf_map(my_map, 4, 2, 8) * Ebpf_map(my_lat, 80, 2, 4)
    Ensure exists v, __return == v && TT
*/
{
	unsigned long long *ts, cur_ts, delta;
	int key, cpu;
	int *val;

	cpu = (int)bpf_get_smp_processor_id();
	ts = bpf_map_lookup_elem(&my_map, &cpu);
	if (!ts)
		return 0;

	cur_ts = bpf_ktime_get_ns();
	delta = (unsigned long long)log2l((unsigned int)(cur_ts - *ts));

	if (delta > (unsigned long long)(20 - 1))
		delta = (unsigned long long)(20 - 1);

	key = (int) ((unsigned long long) cpu * 20 + delta);
	val = bpf_map_lookup_elem(&my_lat, &key);
	if (val)
		(*val)++;

	return 0;

}