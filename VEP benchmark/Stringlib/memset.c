#include "../bpf.h"

struct bpf_map_def proxy_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(char) * 1000,
        .max_entries = 2
};

static inline void memset (char *p1, char v, unsigned int n) 
/*@ With m l1
    Require n <= m && v == v && store_char_array(p1, m, l1)  
    Ensure exists l2, store_char_array(p1, m, l2)
*/
{
    //#pragma unroll
    unsigned int i;
    /*@ Inv exists l2,  
          0 <= i && i <= n@pre &&  
          store_char_array(p1@pre, m, l2)
    */
    for (i = 0; i < n; i++) {
        p1[i] = v;
    }
    return ;
}

int bpf_prog1(struct xdp_md *ctx) 
/*@ Require XDP_SEP(ctx) * Ebpf_map(proxy_map, 2, 1, 1000)
    Ensure exists v, __return == v && TT
*/
{
    char *p1;
    unsigned int key0 = 0;
    p1 = bpf_map_lookup_elem(&proxy_map, &key0);
    if (p1 == (char *)0) return 0;
    char v = (char) 89;
    memset(p1, v, 1000);
    return bpf_map_update_elem(&proxy_map, &key0, p1, 0);
}