
// 1
void *bpf_map_lookup_elem(void *map, void *key)
/*@ With size value_size type
    Require Ebpf_map(*map, size, type, value_size)
    Ensure __return == 0 && Ebpf_map(*map, size, type, value_size)  || 
           __return != 0 && Ebpf_map(*map, size, type, value_size) * 
           map_element(__return, type, value_size)
*/;
// 2
int bpf_map_update_elem(void *map, void *key, void *value, unsigned long long flags)
/*@ With size value_size type
    Require Ebpf_map(*map, size, type, value_size) * map_element(value, type, value_size)
    Ensure exists v, __return == v && Ebpf_map(*map, size, type, value_size) * map_element(value, type, value_size)
*/;
// 3
int bpf_map_delete_elem(void *map, void *key);
// 4
int bpf_probe_read(void *dst, unsigned int size, void *unsafe_ptr);
// 5
unsigned long long bpf_ktime_get_ns()
/*@ Require emp
    Ensure exists v, __return == v
*/;
// 7
unsigned int bpf_get_prandom_u32()
/*@ Require emp
    Ensure exists v, __return == v && v >= 0
*/;
// 8
unsigned int bpf_get_smp_processor_id()
/*@ Require emp
    Ensure exists v, __return == v
*/;
// 9
long long bpf_skb_store_bytes(struct __sk_buff *skb, unsigned int offset, void *from, unsigned int len, unsigned long long flags);
// 10
long long bpf_l3_csum_replace(struct __sk_buff *skb, unsigned int offset, unsigned long long from, unsigned long long to, unsigned long long size);
// 11
long long bpf_l4_csum_replace(struct __sk_buff *skb, unsigned int offset, unsigned long long from, unsigned long long to, unsigned long long flags);
// 13
long long bpf_clone_redirect(struct __sk_buff *skb, unsigned int ifindex, unsigned long long flags);
// 14
unsigned long long bpf_get_current_pid_tgid();
// 15
unsigned long long bpf_get_current_uid_gid();
// 16
long long bpf_get_current_comm(void *buf, unsigned int size_of_buf)
/*@ With n l
    Require size_of_buf <= n && store_char_array(buf, n, l)
    Ensure exists v, __return == v && store_char_array(buf, n, l)
*/;
// 18
long long bpf_skb_vlan_push(struct __sk_buff *skb, unsigned int vlan_proto, unsigned int vlan_tci);
// 20
long long bpf_skb_get_tunnel_key(struct __sk_buff *skb, struct bpf_tunnel_key *key, unsigned int size, unsigned long long flags);
// 21
long long bpf_skb_set_tunnel_key(struct __sk_buff *skb, struct bpf_tunnel_key *key, unsigned int size, unsigned long long flags);
// 22
unsigned long long *bpf_perf_event_read(void *map, unsigned long long flags);
// 23
long long *bpf_redirect(unsigned int ifindex, unsigned long long flags);
// 25
long long *bpf_perf_event_output(void *ctx, void *map, unsigned long long flags, void *data, unsigned long long size);
// 26
long long *bpf_skb_load_bytes(void *skb, unsigned int offset, void *tp, unsigned int len);
// 27
long long *bpf_get_stackid(void *ctx, void *map, unsigned long long flags)
/*@ Require emp
    Ensure exists v, __return == v
*/;
// 28
long long *bpf_csum_diff(unsigned int *from, unsigned int from_size, unsigned int *to, unsigned int to_size, unsigned int seed);
// 31
long long *bpf_skb_change_proto(struct __sk_buff *skb, unsigned int proto, unsigned long long flags);
// 33
long long *bpf_skb_under_cgroup(struct __sk_buff *skb, void *map, unsigned int index);
// 34
unsigned int *bpf_get_hash_realc(struct __sk_buff *skb);
// 35
unsigned long long *bpf_get_current_task();
// 36
long long *bpf_probe_write_user(void *dst, void *src, unsigned int len);
// 37
long long *bpf_current_task_under_cgroup(void *map, unsigned int index);
// 38
long long *bpf_skb_change_tail(struct __sk_buff *skb, unsigned int len, unsigned long long flags);
// 43
long long *bpf_skb_change_head(struct __sk_buff *skb, unsigned int len, unsigned long long flags)
/*@ Require skb_buff(skb)
    Ensure exists v, __return == v && skb_buff(skb) 
*/;
// 44
long long *bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta);
// 45
long long *bpf_probe_read_str(void *dst, unsigned int size, void *unsafe_ptr);
// 49
long long *bpf_setsockopt(void *bpf_socket, int lovel, int optname, void *optval, int optlen)
/*@ Require emp 
    Ensure exists v, __return == v */;
// 51
long long *bpf_redirect_map(void *map, unsigned long long key, unsigned long long flags);
// 53
long long *bpf_sock_map_update(struct bpf_sock_ops *skops, void *map, void *key, unsigned long long flags) 
/*@ With size value_size type
    Require Sock_ops(skops) * Ebpf_map(*map, size, type, value_size) 
    Ensure exists v, __return == v */;
// 54
long long *bpf_xdp_adjust_meta(struct xdp_md *xdp_md, int delta);
// 55
long long *bpf_perf_event_read_value(void *map, unsigned long long flags, struct bpf_perf_event_value *buf, unsigned int buf_size);
// 56
long long bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, unsigned int buf_size)
/*@ Require emp
    Ensure exists v, __return == v */;
// 57
long long *bpf_getsockopt(void *bpf_socket, int level, int optname, void *optval, int optlen);
// 58
long long *bpf_override_return(struct pt_regs *regs, unsigned long long rc);
// 65
long long *bpf_xdp_adjust_tail(struct xdp_md *xdp_md, int delta);
// 69
long long *bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, unsigned int flags);
// 87
long long *bpf_map_push_elem(void *map, void *value, unsigned long long flags);
// 88
long long *bpf_map_pop_elem(void *map, void *value);
// 89
long long *bpf_map_peek_elem(void *map, void *value);
// 113
long long *bpf_probe_read_kernel(void *dst, unsigned int size, void *unsafe_ptr);
// 118
unsigned long long *bpf_jiffies64();
// 130
long long *bpf_ringbuf_output(void *ringbuf, void *data, unsigned long long size, unsigned long long flags);