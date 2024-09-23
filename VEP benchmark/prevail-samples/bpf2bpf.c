// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"

inline int plus1(int x)
/*@ With v 
    Require x == v
    Ensure __return == v + 1
*/
{
    return x + 1;
}

int func(void* ctx) 
/*@ Require emp
    Ensure __return == 4
*/
{
    return plus1(3);
}
