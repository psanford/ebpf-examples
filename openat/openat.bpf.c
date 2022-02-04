// +build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "common.h"
#include "bpf_helpers.h"

#define __NR_openat        257


char __license[] SEC("license") = "Dual MIT/GPL";

#define PATH_MAX 4096
struct event_t {
  u32 pid;
  char str[PATH_MAX];
};

struct event_tt {
  u32 pid;
};

struct bpf_map_def SEC("maps") tmp_storage_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct event_t),
    .max_entries = 1,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
  unsigned long syscall_id = ctx->args[1];
  struct pt_regs *regs;
  const char *pathname;
  u32 map_id;
  int res;
  struct event_t *event;

  if (syscall_id != __NR_openat)
    return 0;

  regs = (struct pt_regs *)ctx->args[0];

  res = bpf_probe_read(&pathname, sizeof(pathname), &regs->si);

  map_id = 0;
  event = bpf_map_lookup_elem(&tmp_storage_map, &map_id);
  if (!event) {
    bpf_printk("is_open_at no map_val\n");
    return 0;
  }

  res = bpf_probe_read_str(&event->str, PATH_MAX, pathname);
  if (res > 0) {
    event->str[(res - 1) & (PATH_MAX - 1)] = 0;
  } else {
    return 0;
  }

  event->pid = bpf_get_current_pid_tgid();
  bpf_printk("open_at: %d %s\n", sizeof(*event), event->str);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

  return 0;
}
