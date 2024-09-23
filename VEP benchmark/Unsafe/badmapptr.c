// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "../bpf.h"

struct bpf_map_def test_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(unsigned int),
        .max_entries = 1
};

int test_repro(void* ctx)
/*@ Require ctx != 0 && Ebpf_map(test_map, 1, 1, 4)
    Ensure exists v, __return == v && TT
*/
{
    unsigned int key = 1;

    struct bpf_map_def * map = &test_map;

    // Instead of passing in the correct map pointer, pass in a value past it.
    // This should fail verification.
    unsigned int * value = bpf_map_lookup_elem(map + 1, &key);

    return (value != 0);
}
