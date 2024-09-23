// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "../bpf.h"

struct bpf_map_def map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = 0,
        .max_entries = 1
};

struct ctx;

int func(struct ctx* ctx)
/*@ Require ctx != 0 && Ebpf_map(map, 1, 2, 0)
    Ensure exists v, __return == v && TT
*/
{
    // And we can furthermore pass some bad parameters in here.  These
    // would be illegal to pass to bpf_map_update_elem if it were resolved.
    return bpf_map_update_elem(&map, (const void*)0, (const void*)0, 0);
}
