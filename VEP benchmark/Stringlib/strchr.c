#include "../bpf.h"

struct bpf_map_def proxy_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(char) * 1000,
        .max_entries = 2
};

static inline char * strchr (char *p1, char v) 
/*@ With n m l
    Require v != 0 && 0 <= n && l[n] == 0 && n < m && store_char_array(p1, m, l)
    Ensure exists v1, __return == v1 && store_char_array(p1, m, l)
*/
{
    //#pragma unroll
    unsigned int i;
    /*@ Inv 
        0 <= i && i <= n */
    for (i = 0; ; i++) {
        char c = p1[i];
        if (c == (char)0) break;
        if (c == v) return p1 + i;
    }
    return (char*)0;
}

int bpf_prog1(struct xdp_md *ctx) 
/*@ Require XDP_SEP(ctx) * Ebpf_map(proxy_map, 2, 1, 1000)
    Ensure exists v, __return == v && TT
*/
{
    char *p1;
    unsigned int key0 = 0, key1 = 1;
    p1 = bpf_map_lookup_elem(&proxy_map, &key0);
    if (p1 == (char*)0) return 0;
    char *result = strchr(p1, (char)97);
    if (result == (char*)0) return 0;
    return 1;
}