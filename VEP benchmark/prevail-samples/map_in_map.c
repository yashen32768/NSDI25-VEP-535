// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "../bpf.h"

struct bpf_map_def inner_map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(unsigned int),
        .max_entries = 1
};

struct bpf_map_def array_of_maps = {
        .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
        .key_size = sizeof(unsigned int),
        .value_size = 20,
        .max_entries = 1
};


int func(void* ctx) 
/*@ Require ctx != 0 && Ebpf_map(array_of_maps, 1, 12, 20) * Ebpf_map(inner_map, 1, 2, 8)
    Ensure exists v, __return == v && TT
*/
{
    unsigned int outer_key = 0;
    void* nolocal_lru_map = bpf_map_lookup_elem(&array_of_maps, &outer_key);
    if (nolocal_lru_map) {
        unsigned int inner_key = 0;
        void* ret = bpf_map_lookup_elem(nolocal_lru_map, &inner_key);
        if (ret) {
            return 0;
        } else {
            ret = bpf_map_lookup_elem(&inner_map, &inner_key);
            return 0;
        }
    }
    return 0;
}
