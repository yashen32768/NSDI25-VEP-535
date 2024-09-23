// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"

struct bpf_map_def map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = 1025 * sizeof(unsigned int),
        .max_entries = 1
};

struct ctx;
static unsigned char stack_buffer[256];

int func(struct ctx* ctx)
/*@ With l
    Require Ebpf_map(map, 1, 2, 4100) * store_uchar_array(stack_buffer, 256, l)
    Ensure exists v, __return == v && TT
*/
{
    unsigned int rand32 = bpf_get_prandom_u32();
    *(unsigned int*)stack_buffer = rand32;

    int map_key = 0;
    unsigned char* map_value = (unsigned char*)bpf_map_lookup_elem(&map, &map_key);
    if (map_value == (unsigned char *)0)
        return 0;

    unsigned char* ptr;
    if (rand32 & 1) {
        ptr = map_value;
    } else {
        ptr = &stack_buffer[128];
    }

    unsigned char v = stack_buffer[0];
    unsigned char v2 = *ptr;
    return (v2 == v) ? 1 : 0;
}
