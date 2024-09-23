// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Facebook
 */
#include "../bpf.h"

struct syscalls_enter_open_args {
	unsigned long long unused;
	int syscall_nr;
	int filename_ptr;
	int flags;
	int mode;
};


struct bpf_map_def enter_open_map  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(unsigned int),
  .max_entries = 1
};

static inline void count(void *map)
/*@
  Require Ebpf_map(*map, 1, 2, 4)
  Ensure Ebpf_map(*map, 1, 2, 4) && TT
*/
{
	unsigned int key = 0;
	unsigned int *value, init_val = 1;

	value = bpf_map_lookup_elem(map, &key);
	if (value)
		*value += 1;
	else
		bpf_map_update_elem(map, &key, &init_val, 1);
  /*@ init_val == 1 */
}

int trace_enter_open(struct syscalls_enter_open_args *ctx)
/*@ Require ctx != 0 && Ebpf_map(enter_open_map, 1, 2, 4) 
   Ensure __return == 0 && TT
*/
{
	count(&enter_open_map);
	return 0;
}