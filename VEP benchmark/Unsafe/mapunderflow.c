// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "bpf.h"

struct bpf_map_def map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(unsigned long long),
        .max_entries = 1
};

struct ctx;

int func(struct ctx* ctx)
/*@ Require ctx != 0 && Ebpf_map(map, 1, 2, 8)
    Ensure exists v, __return == v && TT
*/
{
    int key = -1;
    unsigned long long value = 0;

    // The following should fail verification since it tries to
    // write before the start of the array, or past the end if -1
    // is interpreted as unsigned.
    return bpf_map_update_elem(&map, &key, &value, 0);
}
