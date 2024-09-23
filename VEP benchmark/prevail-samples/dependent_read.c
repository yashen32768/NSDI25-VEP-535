// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "../bpf.h"

unsigned int dependent_read(struct xdp_md* ctx)
/*@ Require XDP_SEP(ctx)
    Ensure exists v, __return == v && TT
*/
{
    void *data = (void *)(int)ctx->data;
    void *data_end = (void *)(int)ctx->data_end;
    if (data + 4 > data_end)
        return 0;
    unsigned int value = *(unsigned int *)data;
    return value;
}
