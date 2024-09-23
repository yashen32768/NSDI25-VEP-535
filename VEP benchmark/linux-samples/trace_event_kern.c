/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "../bpf.h"

struct bpf_map_def counts  = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(struct key_t),
  .value_size = sizeof(unsigned long long),
  .max_entries = 10000
};

struct bpf_map_def stackmap  = {
  .type = BPF_MAP_TYPE_STACK_TRACE,
  .key_size = sizeof(unsigned int),
  .value_size = 127 * sizeof(unsigned long long),
  .max_entries = 10000
};

static char time_fmt1[39] = "Time Enabled: %llu, Time Running: %llu";
static char time_fmt2[29] = "Get Time Failed, ErrCode: %d";
static char addr_fmt[32] = "Address recorded on event: %llx";
static char fmt[27] = "CPU-%d period %lld ip %llx";
static struct bpf_perf_event_value value_buf;
static struct key_t key;


int bpf_prog1(struct bpf_perf_event_data *ctx)
/*@ With l1 l2 l3 l4
    Require Perf_event_data(ctx) * Perf_event_value(&value_buf) * Key_sep(&key) * Ebpf_map(counts, 10000, 2, 8) * Ebpf_map(stackmap, 10000, 7, 1016) *
            store_char_array(&time_fmt1, 39, l1) * store_char_array(&time_fmt2, 29, l2) *
            store_char_array(&addr_fmt, 32, l3) * store_char_array(&fmt, 27, l4)
    Ensure exists v, __return == v && TT
*/
{

	unsigned int cpu = bpf_get_smp_processor_id();
	unsigned long long *val, one = 1;
	int ret;

	if (ctx->sample_period < 10000)
		/* ignore warmup */
		return 0;
	bpf_get_current_comm(&key.comm, 16);
	key.kernstack = (unsigned int)bpf_get_stackid(ctx, &stackmap, (unsigned long long)(0 | 512));
	key.userstack = (unsigned int)bpf_get_stackid(ctx, &stackmap, (unsigned long long)(0 | 512 | 256));
	if ((int)key.kernstack < 0 && (int)key.userstack < 0) {
		//bpf_trace_printk(fmt, sizeof(fmt), cpu, ctx->sample_period,
		//		 PT_REGS_IP(&ctx->regs));
		return 0;
	}

	ret = (int)bpf_perf_prog_read_value(ctx, (void *)&value_buf, sizeof(struct bpf_perf_event_value));
/*	if (!ret)
	  bpf_trace_printk(time_fmt1, sizeof(time_fmt1), value_buf.enabled, value_buf.running);
	else
	  bpf_trace_printk(time_fmt2, sizeof(time_fmt2), ret);

	if (ctx->addr != 0)
	  bpf_trace_printk(addr_fmt, sizeof(addr_fmt), ctx->addr); */

	val = bpf_map_lookup_elem(&counts, &key);
	if (val)
		(*val)++;
	else
		bpf_map_update_elem(&counts, &key, &one, 1);
  /*@ one == 1*/
	return 0;
}
