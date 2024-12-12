#include <stdint.h>
#include <asm/types.h>

#include <linux/bpf.h>
#include <linux/pkt_sched.h>
#include <bpf/bpf_helpers.h>

#define __section(x) __attribute__((section(x), used))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

//struct bpf_elf_map {
//__u32 type;
//__u32 size_key;
//__u32 size_value;
//__u32 max_elem;
//__u32 flags;
//__u32 id;
//__u32 pinning;
//__u32 inner_id;
//__u32 inner_idx;
//};

struct tuple {
   long packets;
   long bytes;
};

#define BPF_MAP_ID_STATS        1 /* agent's map identifier */
#define BPF_MAX_MARK            256
#define BPF_PIN_GLOBAL		2

//struct bpf_elf_map __section("maps") map_stats = {
//   .type           =       BPF_MAP_TYPE_ARRAY,
//   .id             =       BPF_MAP_ID_STATS,
//   .size_key       =       sizeof(uint32_t),
//   .size_value     =       sizeof(struct tuple),
//   .max_elem       =       BPF_MAX_MARK,
//   .pinning        =	   BPF_PIN_GLOBAL,
//};

struct {
  __u32 type;
  __u32 max_entries;
  __u32 id;
  __u32 *key;
  struct tuple *value;
  __u32 pinning;
} map_stats __section(".maps") = {
  .type = BPF_MAP_TYPE_ARRAY,
  .id = BPF_MAP_ID_STATS,
  .max_entries = BPF_MAX_MARK,
  .pinning = BPF_PIN_GLOBAL,
};

static inline void cls_update_stats(const struct __sk_buff *skb,
			       uint32_t mark)
{
   struct tuple *tu;

   tu = bpf_map_lookup_elem(&map_stats, &mark);
   if (likely(tu)) {
	   __sync_fetch_and_add(&tu->packets, 1);
	   __sync_fetch_and_add(&tu->bytes, skb->len);
   }
   //bpf_printk("tc: Update stats\n");
}

__section("classifier") int cls_main(struct __sk_buff *skb)
{
   //bpf_printk("tc: Exec cls_main\n");
   uint32_t mark = skb->mark;

   if (unlikely(mark >= BPF_MAX_MARK))
	   return 0;

   cls_update_stats(skb, mark);

   return TC_H_MAKE(TC_H_ROOT, mark);
}

char __license[] __section("license") = "GPL";
