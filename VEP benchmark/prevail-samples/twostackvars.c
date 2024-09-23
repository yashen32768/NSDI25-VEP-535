// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"

struct ctx;
static int stack_buffer[16];

int func(struct ctx* ctx)
/*@ With l
    Require ctx != 0 && store_int_array(stack_buffer, 16, l) 
    Ensure exists v, __return == v && TT
*/
{
    
    int *ptr = (int*)0;

    unsigned int rand32 = bpf_get_prandom_u32();
    /*@ 0 <= (rand32 % 8) && (rand32 % 8) < 8 */
    if (rand32 & 1) {
        // In this path we want ptr to point to one section
        // of stack space that is known to be a number, and have
        // the rest of the stack be unknown.
        int i;
        /*@ Inv 
              0 <= i && i <= 8
        */
        for (i = 0; i < 8; i++)
        {
          int v = (int)bpf_get_prandom_u32();
          stack_buffer[i] = v;
        }
        int index = (int) rand32 % 8;
        ptr = &stack_buffer[index];
        /*@ 0 <= (index ^ 1) && (index ^ 1) < 8 */
        // Do something with the pointer to force it to be saved in a
        // register before joining the two paths.
        ptr[index ^ 1] = 0;
    } else {
        // In this path we want ptr to point to a different section
        // of stack space that is known to be a number, and have
        // the rest of the stack be unknown.
        int* stack_buffer2 = &stack_buffer[8];
        int i;
        /*@ Inv 
              0 <= i && i <= 8
        */
        for (i = 0; i < 8; i++)
        {
          int v = (int)bpf_get_prandom_u32();
          stack_buffer2[i] = v;
        }
        ptr = &stack_buffer2[rand32 % 8];
    }

    // Here we want to dereference the pointer to get a number.
    // In both paths above, ptr safely points to a number, even
    // though each part of stack_buffer is not necessarily a number
    // at this point.
    int v = *ptr;
    return v;
}
