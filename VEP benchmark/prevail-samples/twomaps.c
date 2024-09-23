// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"

// Declare maps using new format.

struct bpf_map_def map1 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(int),
        .value_size = sizeof(unsigned long long),
        .max_entries = 1
};

struct bpf_map_def map2 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(int),
        .value_size = sizeof(unsigned long long),
        .max_entries = 1
};

int func(void * ctx)
/*@ Require ctx != 0 && Ebpf_map(map1, 1, 1, 8) * Ebpf_map(map2, 1, 1, 8)
    Ensure exists v, __return == v && TT
*/
{
    unsigned int rand32 = bpf_get_prandom_u32();
    struct bpf_map_def* map = (rand32 & 1) ? &map1 : &map2;

    int key = 10;
    unsigned long long* value = (unsigned long long*)bpf_map_lookup_elem(map, &key);
    if (value == (unsigned long long *)0)
        return 0;

    // The following is safe since both maps have the same value size.
    int ret;
    ret = (int)*value;
    return ret;
}
