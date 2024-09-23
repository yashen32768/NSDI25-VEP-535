// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "bpf.h"

struct bpf_map_def map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = 4,
        .max_entries = 1
};

int func(struct bpf_sock_ops * ctx)
/*@ Require Sock_ops(ctx) * Ebpf_map(map, 1, 2, 4)
    Ensure exists v, __return == v && TT
*/
{
    unsigned int key = 1;

    // The following should fail because the sock_ops ctx isn't the same pointer passed in
    // but is offset 8 bytes into it.
    ctx = ((char*)ctx) + 8;
    int result = bpf_sock_map_update(ctx, &map, &key, 0);
    return result;
}
