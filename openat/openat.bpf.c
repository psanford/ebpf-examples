// +build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "common.h"
#include "bpf_helpers.h"

#define PATH_MAX 4096
#define __NR_openat				257


char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") tmp_storage_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = PATH_MAX,
    .max_entries = 2,
};

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
  unsigned long syscall_id = ctx->args[1];
  struct pt_regs *regs;
  const char *pathname;
  char *map_value;
  u32 map_id;
  int res;

  if (syscall_id != __NR_openat)
    return 0;

  regs = (struct pt_regs *)ctx->args[0];

  res = bpf_probe_read(&pathname, sizeof(pathname), &regs->si);

  map_id = 1;
  map_value = bpf_map_lookup_elem(&tmp_storage_map, &map_id);
  if (!map_value) {
    bpf_printk("is_open_at no map_val\n");
    return 0;
  }

  res = bpf_probe_read_str(map_value, PATH_MAX, pathname);
  if (res > 0) {
    map_value[(res - 1) & (PATH_MAX - 1)] = 0;
  }

  bpf_printk("open_at: %s\n", map_value);

  /* bpf_map_update_elem(&tmp_storage_map, &map_id, &map_value, BPF_ANY); */


  return 0;
}
