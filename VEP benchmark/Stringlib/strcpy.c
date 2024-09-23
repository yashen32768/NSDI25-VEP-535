#include "../bpf.h"

struct bpf_map_def proxy_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(char) * 1000,
        .max_entries = 2
};

static inline char * strcpy (char *p1, const char *p2)
/*@ With n0 m0 l0 n1 m1 l1 
    Require 0 <= n0 && l0[n0] == 0 && n0 < m0 && 0 <= n1 && l1[n1] == 0 && n1 < m1 && store_char_array(p1, m0, l0) * store_char_array(p2, m1, l1)
    Ensure exists l2, __return == p1 && store_char_array(p2, m1, l1) * store_char_array(p1, m0, l2)
*/ 
{
    //#pragma unroll
    unsigned int i;
    /*@ Inv 
        0 <= i && i <= n0 && i <= n1 */
    for (i = 0;  ; i++) {
        char c = p2[i];
        p1[i] = c;
        if (c == (char)0)
            break;
    }
    return p1;
}

int bpf_prog1(struct xdp_md *ctx) 
/*@ Require XDP_SEP(ctx) * Ebpf_map(proxy_map, 2, 1, 1000)
    Ensure exists v, __return == v && TT
*/
{
    char *p1, *p2;
    unsigned int key0 = 0, key1 = 1;
    p1 = bpf_map_lookup_elem(&proxy_map, &key0);
    if (p1 == (char*)0) return 0;

    p2 = bpf_map_lookup_elem(&proxy_map, &key1);
    if (p2 == (char*)0) return 0;
    
    strcpy(p1, p2);
    return bpf_map_update_elem(&proxy_map, &key0, p1, 0);
}