#include "../bpf.h"

struct bpf_map_def my_map  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(long long),
  .max_entries = 256
};

int bpf_prog1(struct __sk_buff *skb)
/*@ Require skb_buff(skb) * Ebpf_map(my_map, 256, 2, 8) 
    Ensure exists v, __return == v && TT
*/
{
    int index;
    unsigned char * tmp;
    tmp = (unsigned char *)skb;
    tmp = ((unsigned char *)  ((int)tmp + 14));
    int *tmp2;
    tmp2 = (int *)tmp;
    index = *tmp2;
    long long *value;

    if (skb->pkt_type != (unsigned int)4)
        return 0;

    value = bpf_map_lookup_elem(&my_map, &index);
    if (value)
        *value = *value + (long long)skb->len;

    return 0;
}