// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"


static char buffer[1];

int func()
/*@ With l
    Require store_char_array(buffer,1,l)
    Ensure exists v, __return == v && TT
*/
{
    

    // The following should fail verification since it asks the helper
    // to write past the end of the stack.
    return (int)bpf_get_current_comm(buffer, 20);
}
