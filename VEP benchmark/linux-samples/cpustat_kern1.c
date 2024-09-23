// SPDX-License-Identifier: GPL-2.0

#include "../bpf.h"

static int cpu_opps[5] = { 208000, 432000, 729000, 960000, 1200000 };

struct bpf_map_def my_map  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(long long),
  .max_entries = 8 * 4
};

struct bpf_map_def cstate_duration  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(long long),
  .max_entries = 8 * 3
};

struct bpf_map_def pstate_duration  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(long long),
  .max_entries = 8 * 5
};

struct cpu_args {
	unsigned long long pad;
	unsigned int state;
	unsigned int cpu_id;
};

static unsigned int find_cpu_pstate_idx(unsigned int frequency)
/*@ With v l
    Require frequency == v && store_int_array(cpu_opps, 5, l)
    Ensure exists v0, __return == v0 && store_int_array(cpu_opps, 5, l) 
*/
{
	unsigned int i;
  /*@ Inv 
       0 <= i && i <= 5
  */
	for (i = 0; i < 5; i++) {
    unsigned int cpu_opp = (unsigned int)cpu_opps[i];
		if (frequency == cpu_opp)
			return i;
	}

	return i;
}

int bpf_prog1(struct cpu_args *ctx)
/*@ With v1 v2 v3 l
    Require v1 == ctx->cpu_id && v2 == ctx->state && v3 == ctx->pad && Ebpf_map(my_map, 32, 2, 8) * Ebpf_map(cstate_duration, 24, 2, 8) * Ebpf_map(pstate_duration, 40, 2, 8) * store_int_array(cpu_opps, 5, l)
    Ensure exists v, __return == v && TT
*/
{
	unsigned long long *cts, *pts, *cstate, *pstate, prev_state, cur_ts, delta;
	unsigned int key, cpu, pstate_idx;
	unsigned long long *val;

	if (ctx->cpu_id > 8)
		return 0;

	cpu = ctx->cpu_id;

	key = cpu * 4 + 0;
	cts = bpf_map_lookup_elem(&my_map, &key);
	if (!cts)
		return 0;

	key = cpu * 4 + 1;
	cstate = bpf_map_lookup_elem(&my_map, &key);
	if (!cstate)
		return 0;

	key = cpu * 4 + 2;
	pts = bpf_map_lookup_elem(&my_map, &key);
	if (!pts)
		return 0;

	key = cpu * 4 + 3;
	pstate = bpf_map_lookup_elem(&my_map, &key);
	if (!pstate)
		return 0;

	prev_state = *cstate;
	*cstate = (unsigned long long)ctx->state;
  unsigned long long cts_val = *cts;
	if (!cts_val) {
    unsigned long long ktime = bpf_ktime_get_ns();
		*cts = ktime;
		return 0;
	}

	cur_ts = bpf_ktime_get_ns();
	delta = cur_ts - *cts;
	*cts = cur_ts;
  unsigned int state_val = ctx -> state;
	if (state_val != (unsigned int)-1) {
    unsigned long long pts_val = *pts;
		if (!pts_val)
			return 0;

		delta = cur_ts - *pts;

		pstate_idx = find_cpu_pstate_idx((unsigned int)*pstate);
		if (pstate_idx >= 5)
			return 0;

		key = cpu * 5 + pstate_idx;
		val = bpf_map_lookup_elem(&pstate_duration, &key);
		if (val)
			*val += delta;

	} else {

		key = (unsigned int) ((unsigned long long)cpu * 3 + prev_state);
		val = bpf_map_lookup_elem(&cstate_duration, &key);
		if (val)
			*val += delta;
	}
  unsigned long long pts_val = *pts;
	if (pts_val)
		*pts = cur_ts;

	return 0;
}