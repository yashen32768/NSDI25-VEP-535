#include "../bpf.h"

struct bpf_map_def proxy_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(char) * 1000,
        .max_entries = 2
};

static inline char * memchr (char *p1, char v, unsigned int n) 
/*@ With n0 m l
    Require v != 0 && 0 <= n0 && l[n0] == 0 && n < m && store_char_array(p1, m, l)
    Ensure exists v1, __return == v1 && store_char_array(p1, m, l)
*/
{
    //#pragma unroll
    unsigned int i;
    /*@ Inv 
        0 <= i && i <= n@pre */
    for (i = 0; i < n; i++) {
      char c = p1[i];
        if (c == v) return p1 + i;
    }
    return (char*)0;
}

int bpf_prog1(struct xdp_md *ctx) 
/*@ Require XDP_SEP(ctx) * Ebpf_map(proxy_map, 2, 1, 1000)
    Ensure exists v, __return == v && TT
*/
{
    void *data_end = (void *)(long long)ctx->data_end;
    void *data = (void *)(long long)ctx->data;
    if (data + 1 > data_end)
        return 1;
    char *pos = (char *)data;
    char value = (char) 97;
    unsigned int key = (unsigned int)((char *)data_end - (char *)data);
    char * result = memchr(pos, value, key);
    if (result == (char *)0)
      return 0;
    return 1;
}