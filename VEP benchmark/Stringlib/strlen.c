#include "../bpf.h"

static inline unsigned int strlen(char *p1) 
/*@ With n m l
    Require 0 <= n && l[n] == 0 && n < m && store_char_array(p1, m, l)
    Ensure __return <= n && l[__return] == 0 && store_char_array(p1, m, l)
*/
{ 
    unsigned int i;
    /*@ Inv 
        0 <= i && i <= n */ 
    for (i = 0; ; i++) {
      char c = p1[i];
        if (c == (char)0) break;
    }
    return i;
}

int bpf_prog1(struct xdp_md* ctx)
/*@ Require XDP_SEP(ctx)
    Ensure exists v, __return == v && TT 
*/
{
    void *data_end = (void *)(int)ctx->data_end;
    void *data = (void *)(int)ctx->data;
    if (data + 1 > data_end)
        return 1;
    unsigned int len = strlen((char*)data);
    return len == (unsigned int)((char*)data_end - (char*)data);
}
