// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"

static unsigned char array[40];

int foo(struct xdp_md* ctx)
/*@ With l
    Require XDP_SEP(ctx) * store_uchar_array(array, 40, l)
    Ensure exists v, __return == v && TT
*/
{
    int index;
    int cumul = 0;
        int data = (int)ctx->data;
    int data_end = (int)ctx->data_end;
    /*@ Inv 
          0 <= index && index <= 40 */
    for (index = 0; index < 40; index++) {

        if ((data + index) >= data_end)
            break;

        array[index] = (unsigned char)1;
    }
    /*@ Inv 
          0 <= index && index <= 40 || 0 <= index && index <= 40 */
    for (index = 0; index < 40; index++) {
        cumul += (int)array[index];
    }
    return cumul;
}
