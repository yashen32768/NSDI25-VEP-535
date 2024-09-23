enum __unamed_enum0 {
  BPF_ANY,
  BPF_NOEXIST,
  BPF_EXIST,
  __BPF_DUMMY,
  BPF_F_LOCK
};

enum xdp_action {
  XDP_ABORTED,
  XDP_DROP,
  XDP_PASS,
  XDP_TX,
  XDP_REDIRECT
};

enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC,
  BPF_MAP_TYPE_HASH,
  BPF_MAP_TYPE_ARRAY,
  BPF_MAP_TYPE_PROG_ARRAY,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  BPF_MAP_TYPE_PERCPU_HASH,
  BPF_MAP_TYPE_PERCPU_ARRAY,
  BPF_MAP_TYPE_STACK_TRACE,
  BPF_MAP_TYPE_CGROUP_ARRAY,
  BPF_MAP_TYPE_LRU_HASH,
  BPF_MAP_TYPE_LRU_PERCPU_HASH,
  BPF_MAP_TYPE_LPM_TRIE,
  BPF_MAP_TYPE_ARRAY_OF_MAPS,
  BPF_MAP_TYPE_HASH_OF_MAPS,
  BPF_MAP_TYPE_DEVMAP,
  BPF_MAP_TYPE_SOCKMAP,
  BPF_MAP_TYPE_CPUMAP,
  BPF_MAP_TYPE_XSKMAP,
  BPF_MAP_TYPE_SOCKHASH,
  BPF_MAP_TYPE_CGROUP_STORAGE,
  BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
  BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
  BPF_MAP_TYPE_QUEUE,
  BPF_MAP_TYPE_STACK,
  BPF_MAP_TYPE_SK_STORAGE,
  BPF_MAP_TYPE_DEVMAP_HASH,
  BPF_MAP_TYPE_STRUCT_OPS,
  BPF_MAP_TYPE_RINGBUF,
  BPF_MAP_TYPE_INODE_STORAGE,
  BPF_MAP_TYPE_TASK_STORAGE,
  BPF_MAP_TYPE_BLOOM_FILTER
};

enum __unamed_enum1 {
  BPF_SOCK_OPS_VOID,
  BPF_SOCK_OPS_TIMEOUT_INIT,	/* Should return SYN-RTO value to use or
                                 * -1 if default value should be used
                                 */
  BPF_SOCK_OPS_RWND_INIT,		/* Should return initial advertized
					 * window (in packets) or -1 if default
					 * value should be used
					 */
  BPF_SOCK_OPS_TCP_CONNECT_CB,	/* Calls BPF program right before an
                                 * active connection is initialized
                                 */
  BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,	/* Calls BPF program when an
                                         * active connection is
                                         * established
                                         */
  BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,	/* Calls BPF program when a
                                         * passive connection is
                                         * established
                                         */
  BPF_SOCK_OPS_NEEDS_ECN,		/* If connection's congestion control
					 * needs ECN
					 */
  BPF_SOCK_OPS_BASE_RTT,		/* Get base RTT. The correct value is
					 * based on the path and may be
					 * dependent on the congestion control
					 * algorithm. In general it indicates
					 * a congestion threshold. RTTs above
					 * this indicate congestion
					 */
  BPF_SOCK_OPS_RTO_CB,		/* Called when an RTO has triggered.
                                 * Arg1: value of icsk_retransmits
                                 * Arg2: value of icsk_rto
                                 * Arg3: whether RTO has expired
                                 */
  BPF_SOCK_OPS_RETRANS_CB,	/* Called when skb is retransmitted.
                                 * Arg1: sequence number of 1st byte
                                 * Arg2: # segments
                                 * Arg3: return value of
                                 *       tcp_transmit_skb (0 => success)
                                 */
  BPF_SOCK_OPS_STATE_CB,		/* Called when TCP changes state.
					 * Arg1: old_state
					 * Arg2: new_state
					 */
  BPF_SOCK_OPS_TCP_LISTEN_CB,	/* Called on listen(2), right after
                                 * socket transition to LISTEN state.
                                 */
  BPF_SOCK_OPS_RTT_CB		/* Called on every RTT.
                                 */
};

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

struct bpf_perf_event_value {
  unsigned long long counter;
  unsigned long long enabled;
  unsigned long long running;
};

struct xdp_md {
  unsigned int data;
  unsigned int data_end;
  unsigned int data_meta;
  unsigned int ingress_ifindex;
  unsigned int rx_queue_index;
  unsigned int egress_ifindex;
};

struct bpf_raw_tracepoint_args {
  unsigned long long args[0];
};

struct icmphdr;
struct iphdr
{
  unsigned char	ihl;
    /* version:4; */
  unsigned char	tos;
  unsigned short	tot_len;
  unsigned short	id;
  unsigned short	frag_off;
  unsigned char	ttl;
  unsigned char	protocol;
  unsigned short	check;
  unsigned int	saddr;
  unsigned int	daddr;
  /*The options start here. */
};

struct udphdr {
  unsigned short source;
  unsigned short dest;
  unsigned short len;
  unsigned short check;
};

struct eth_hdr {
  unsigned char   h_dest[6];
  unsigned char   h_source[6];
  unsigned int  h_proto;
};

// has unnamed unnamed union member

struct bpf_fib_lookup {
  unsigned char family;

  unsigned char l4_protocol;
  unsigned short sport;
  unsigned short dport;

  union {
    unsigned short tot_len;
    unsigned short mtu_result;
  } u1;
  unsigned int ifindex;

  union {
    unsigned char tos;
    unsigned int flowinfo;

    unsigned int rt_metric;
  } u2;

  union {
    unsigned int ipv4_src;
    unsigned int ipv6_src[4];
  } u3;

  union {
    unsigned int ipv4_dst;
    unsigned int ipv6_dst[4];
  } u4;

  unsigned short h_vlan_proto;
  unsigned short h_vlan_TCI;
  unsigned char smac[6];
  unsigned char dmac[6];
};

struct bpf_tunnel_key {
  unsigned int tunnel_id;
  union {
    unsigned int remote_ipv4;
    unsigned int remote_ipv6[4];
  } u1;
  unsigned char tunnel_tos;
  unsigned char tunnel_ttl;
  unsigned short tunnel_ext;
  unsigned int tunnel_label;
  union {
    unsigned int local_ipv4;
    unsigned int local_ipv6[4];
  } u2;
};

// arch specific
// x86
struct pt_regs {
  unsigned long long r15;
  unsigned long long r14;
  unsigned long long r13;
  unsigned long long r12;
  unsigned long long bp;
  unsigned long long bx;
  unsigned long long r11;
  unsigned long long r10;
  unsigned long long r9;
  unsigned long long r8;
  unsigned long long ax;
  unsigned long long cx;
  unsigned long long dx;
  unsigned long long si;
  unsigned long long di;
  unsigned long long orig_ax;
  unsigned long long ip;
  unsigned long long cs;
  unsigned long long flags;
  unsigned long long sp;
  unsigned long long ss;
};

// arm64
struct user_pt_regs {
  unsigned long long regs[31];
  unsigned long long sp;
  unsigned long long pc;
  unsigned long long pstate;
};

struct bpf_user_pt_regs_t {
  unsigned long long regs[31];
  unsigned long long sp;
  unsigned long long pc;
  unsigned long long pstate;
};

struct bpf_perf_event_data {
  struct bpf_user_pt_regs_t regs;
  unsigned long long sample_period;
  unsigned long long addr;
};

// has function pointers
struct bpf_sock_ops {
  unsigned int op;
  unsigned int reply;
  unsigned int family;
  unsigned int remote_ip4;	/* Stored in network byte order */
  unsigned int local_ip4;	/* Stored in network byte order */
  unsigned int remote_ip6[4];	/* Stored in network byte order */
  unsigned int local_ip6[4];	/* Stored in network byte order */
  unsigned int remote_port;	/* Stored in network byte order */
  unsigned int local_port;	/* stored in host byte order */
  unsigned int is_fullsock;	/* Some TCP fields are only valid if
                         * there is a full socket. If not, the
                         * fields read as zero.
                         */
  unsigned int snd_cwnd;
  unsigned int srtt_us;		/* Averaged RTT << 3 in usecs */
  unsigned int bpf_sock_ops_cb_flags; /* flags defined in uapi/linux/tcp.h */
  unsigned int state;
  unsigned int rtt_min;
  unsigned int snd_ssthresh;
  unsigned int rcv_nxt;
  unsigned int snd_nxt;
  unsigned int snd_una;
  unsigned int mss_cache;
  unsigned int ecn_flags;
  unsigned int rate_delivered;
  unsigned int rate_interval_us;
  unsigned int packets_out;
  unsigned int retrans_out;
  unsigned int total_retrans;
  unsigned int segs_in;
  unsigned int data_segs_in;
  unsigned int segs_out;
  unsigned int data_segs_out;
  unsigned int lost_out;
  unsigned int sacked_out;
  unsigned int sk_txhash;
  unsigned long long bytes_received;
  unsigned long long bytes_acked;
  void *__bpf_md_ptr;
  /* [skb_data, skb_data_end) covers the whole TCP header.
   *
   * BPF_SOCK_OPS_PARSE_HDR_OPT_CB: The packet received
   * BPF_SOCK_OPS_HDR_OPT_LEN_CB:   Not useful because the
   *                                header has not been written.
   * BPF_SOCK_OPS_WRITE_HDR_OPT_CB: The header and options have
   *				  been written so far.
   * BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:  The SYNACK that concludes
   *					the 3WHS.
   * BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: The ACK that concludes
   *					the 3WHS.
   *
   * bpf_load_hdr_opt() can also be used to read a particular option.
   */
  /* __bpf_md_ptr(void *, skb_data); */
  /* __bpf_md_ptr(void *, skb_data_end); */
  void *__bpf_md_ptr_2;
  void *__bpf_md_ptr_3;
  unsigned int skb_len;		/* The total length of a packet.
				 * It includes the header, options,
				 * and payload.
				 */
  unsigned int skb_tcp_flags;	/* tcp_flags of the header.  It provides
                         * an easy way to check for tcp_flags
                         * without parsing skb_data.
                         *
                         * In particular, the skb_tcp_flags
                         * will still be available in
                         * BPF_SOCK_OPS_HDR_OPT_LEN even though
                         * the outgoing header has not
                         * been written yet.
                         */
};

struct __sk_buff {
  unsigned int len;
  unsigned int pkt_type;
  unsigned int mark;
  unsigned int queue_mapping;
  unsigned int protocol;
  unsigned int vlan_present;
  unsigned int vlan_tci;
  unsigned int vlan_proto;
  unsigned int priority;
  unsigned int ingress_ifindex;
  unsigned int ifindex;
  unsigned int tc_index;
  unsigned int cb[5];
  unsigned int hash;
  unsigned int tc_classid;
  unsigned int data;
  unsigned int data_end;
  unsigned int napi_id;

  /* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
  unsigned int family;
  unsigned int remote_ip4;	/* Stored in network byte order */
  unsigned int local_ip4;	/* Stored in network byte order */
  unsigned int remote_ip6[4];	/* Stored in network byte order */
  unsigned int local_ip6[4];	/* Stored in network byte order */
  unsigned int remote_port;	/* Stored in network byte order */
  unsigned int local_port;	/* stored in host byte order */
  /* ... here. */

  unsigned int data_meta;
  void *__bpf_md_ptr;
  /* __bpf_md_ptr(struct bpf_flow_keys *, flow_keys); */
  unsigned long long tstamp;
  unsigned int wire_len;
  unsigned int gso_segs;
  void *__bpf_md_ptr_2;
  /* __bpf_md_ptr(struct bpf_sock *, sk); */
  unsigned int gso_size;
  unsigned char  tstamp_type;
  unsigned char padding1;
  unsigned char padding2;
  unsigned char padding3; 	/* Padding, future use. */
  /* unsigned int :24;	 */
  unsigned long long hwtstamp;
};

struct key_t {
	char comm[16];
	unsigned int kernstack;
	unsigned int userstack;
};


//@ Extern Coq (XDP_SEP : Z -> Assertion)
//@ Extern Coq (skb_buff : Z -> Assertion)
//@ Extern Coq (Sock_ops : Z -> Assertion)
//@ Extern Coq (Perf_event_data : Z -> Assertion)
//@ Extern Coq (Perf_event_value : Z -> Assertion)
//@ Extern Coq (Key_sep : Z -> Assertion)
//@ Extern Coq (Ebpf_map : Z -> Z -> Z -> Z -> Assertion)
//@ Extern Coq (map_element : Z -> Z -> Z -> Assertion)
//@ Extern Coq (TT : Assertion)
//@ Extern Coq (TT_tag : Prop)
#include "verification_stdlib.h"
#include "char_array_def.h"
#include "bpf_helpers.h"
/*@ include strategies "xdp.strategies" */
/*@ include strategies "TT.strategies" */
/*@ include strategies "EBPF_MAP.strategies" */
/*@ include strategies "skb_buff.strategies" */
/*@ include strategies "sockops.strategies"*/
/*@ include strategies "perf_event.strategies" */
