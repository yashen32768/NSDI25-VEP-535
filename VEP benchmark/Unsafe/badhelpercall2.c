// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "../bpf.h"

static char buffer2[30];
static char buffer[1];
    
int func()
/*@ With l l1
    Require store_char_array(buffer,1,l) * store_char_array(buffer2,30,l1)
    Ensure exists v, __return == v && TT
*/
{
  int i;
  for (i = 0; i < 20; i++)
  {
    buffer2[i] = i + 0;
  }
  int v = bpf_get_prandom_u32();
  if (v >= 20)
        return 0;
  buffer[0] = buffer2[v];
    // The following should fail verification since it asks the helper
    // to write past the end of the stack.
  return bpf_get_current_comm(buffer, 20);
}
