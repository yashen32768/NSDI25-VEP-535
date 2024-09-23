// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"

char array[256];

int func(void* ctx)
/*@ With l
    Require ctx != 0 && store_char_array(array, 256, l)
    Ensure exists v, __return == v && TT
*/
{
   unsigned int rand32 = bpf_get_prandom_u32();
   unsigned int index = rand32 % 256;

   int val = (int)array[index];
   return val;
}
