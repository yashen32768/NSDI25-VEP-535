// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"

struct bpf_map_def map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(unsigned int),
        .max_entries = 1
};

int func(void* ctx)
/*@ Require ctx != 0 && Ebpf_map(map, 1, 2, 4)
    Ensure exists v, __return == v && TT
*/
{
    unsigned int key = 1;

    // The following should fail because the ctx doesn't match, and in particular
    // the memory pointed to by ctx might be smaller than the memory read by the helper.
    int result = (int)bpf_sock_map_update(ctx, &map, &key, 0);
    return result;
}
