/* libmesh.a mesh_quick.o --- reconstructed C (offline).
 * Role: vendor-IE (beacon/probe) handling: roots announce/gone/yield/fixed, PS duty, conflict roots.
 * Object file: 172616 bytes on disk; 126/118 functions reconstructed, ~29125 code bytes.
 * Method: xtensa-esp32-elf-objdump -d/-s + readelf -rW/-sW + funcdb_libmesh.json v3
 * (calls/refs edges). Control flow preserved 1:1 via labels+gotos; regs a0-a15
 * are u32 locals; window rotation flattened. Direct calls come from
 * R_XTENSA_ASM_EXPAND relocs (ground truth); leftover indirect sites are
 * attributed in order from funcdb-v3 calls and marked funcdb-attributed;
 * literal-pool-only inferences contradicting funcdb-v3 were demoted (see
 * corrections). No logic invented; see Fidelity tags. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
typedef int8_t i8; typedef int16_t i16; typedef int32_t i32;
#define LD32(p) (*(volatile u32*)(uintptr_t)(p))
#define LD16U(p) (*(volatile u16*)(uintptr_t)(p))
#define LD16S(p) (*(volatile i16*)(uintptr_t)(p))
#define LD8U(p) (*(volatile u8*)(uintptr_t)(p))
#define ST32(p,v) (*(volatile u32*)(uintptr_t)(p) = (u32)(v))
#define ST16(p,v) (*(volatile u16*)(uintptr_t)(p) = (u16)(v))
#define ST8(p,v) (*(volatile u8*)(uintptr_t)(p) = (u8)(v))
#define LD32F(p) u2f(LD32(p))
#define ST32F(p,v) ST32((p), f2u(v))
#define SRC_FUNNEL(x,y) (0u) /* SAR-dependent funnel shift; value untracked */
static float u2f(u32 v){ float f; __builtin_memcpy(&f,&v,4); return f; }
static u32 f2u(float f){ u32 v; __builtin_memcpy(&v,&f,4); return v; }
extern u32 esp_mesh_appie; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_get_ap_assoc_expire; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_ps_duty; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_quick_funcs; /* undefined data (reloc-referenced) */
extern u32 g_is_root_fixed; /* undefined data (reloc-referenced) */
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_mesh_cfg_switch_parent; /* undefined data (reloc-referenced) */
extern u32 g_mesh_init_ps_type; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_max_layer; /* undefined data (reloc-referenced) */
extern u32 g_mesh_monitor_parent_beacon_count; /* undefined data (reloc-referenced) */
extern u32 g_mesh_topology; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 g_wifi_global_lock; /* undefined data (reloc-referenced) */
extern u32 is_esp_mesh_assoc; /* undefined data (reloc-referenced) */
extern u32 __divdi3(); /* undefined func (args unknown, returns u32) */
extern u32 __moddi3(); /* undefined func (args unknown, returns u32) */
extern u32 clone__mesh_roots_process_fixed_part_0(); /* undefined func (args unknown, returns u32) */
extern u32 clone__wifi_vnd_ext_mesh_roots_free_part_0(); /* undefined func (args unknown, returns u32) */
extern u32 clone_is_zero_addr(); /* undefined func (args unknown, returns u32) */
extern u32 cnx_node_search(); /* undefined func (args unknown, returns u32) */
extern u32 crc32_le(); /* undefined func (args unknown, returns u32) */
extern u32 dutytype2str(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_router_bssid(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_get_running_active_duty_cycle(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_is_root_conflicts_allowed(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_is_roots_found(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_set_router_bssid(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_beacon_interval(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_config(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_beacon_interval(); /* undefined func (args unknown, returns u32) */
extern u32 hal_get_tsf_time(); /* undefined func (args unknown, returns u32) */
extern u32 ic_get_random(); /* undefined func (args unknown, returns u32) */
extern u32 ieee80211_hostapd_beacon_txcb(); /* undefined func (args unknown, returns u32) */
extern u32 ieee80211_public_action_send_mesh_awake(); /* undefined func (args unknown, returns u32) */
extern u32 ieee80211_sta_is_connected(); /* undefined func (args unknown, returns u32) */
extern u32 ieee80211_vnd_mesh_fully_associated(); /* undefined func (args unknown, returns u32) */
extern u32 ieee80211_vnd_mesh_update_beacon(); /* undefined func (args unknown, returns u32) */
extern u32 mesh_free(); /* defined in another libmesh.a object */
extern u32 mesh_malloc(); /* defined in another libmesh.a object */
extern u32 pm_is_open(); /* undefined func (args unknown, returns u32) */
extern u32 pm_stop(); /* undefined func (args unknown, returns u32) */
extern u32 sprintf(); /* undefined func (args unknown, returns u32) */
extern u32 wDev_Mesh_Set_TBTT(); /* undefined func (args unknown, returns u32) */
extern u32 wifi_disconnect_process(); /* undefined func (args unknown, returns u32) */
extern u32 wifi_get_macaddr(); /* undefined func (args unknown, returns u32) */
extern u32 wifi_log(); /* undefined func (args unknown, returns u32) */
extern u32 wifi_mesh_event_post(); /* undefined func (args unknown, returns u32) */
static const u8 RODATA__rodata[] = { 0x00, 0x00, 0x00, 0x00 }; /* .rodata (4 bytes) */
static const u8 RODATA__rodata_CSWTCH_683[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00 }; /* .rodata.CSWTCH$683 (28 bytes) */
static const u8 RODATA__rodata___func___15[] = { 0x5f, 0x77, 0x69, 0x66, 0x69, 0x5f, 0x76, 0x6e, 0x64, 0x5f, 0x65, 0x78, 0x74, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x5f, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00 }; /* .rodata.__func__$15 (32 bytes) strings: [0x0]="_wifi_vnd_ext_mesh_roots_malloc" */
static const u8 RODATA__rodata___func___16[] = { 0x5f, 0x77, 0x69, 0x66, 0x69, 0x5f, 0x76, 0x6e, 0x64, 0x5f, 0x65, 0x78, 0x74, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x5f, 0x66, 0x72, 0x65 }; /* .rodata.__func__$16 (28 bytes) */
static const u8 RODATA__rodata___func___17[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x64, 0x65, 0x69, 0x6e, 0x69, 0x74, 0x5f }; /* .rodata.__func__$17 (12 bytes) */
static const u8 RODATA__rodata___func___6[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x5f, 0x72, 0x6f }; /* .rodata.__func__$6 (24 bytes) */
static const u8 RODATA__rodata___func___9[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x67, 0x65, 0x74, 0x5f, 0x76, 0x6e, 0x64, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x5f, 0x6c }; /* .rodata.__func__$9 (24 bytes) */
static const u8 RODATA__rodata__mesh_check_roots_gone_str1_1[] = { 0x72, 0x65, 0x63, 0x76, 0x20, 0x25, 0x73, 0x00 }; /* .rodata._mesh_check_roots_gone.str1.1 (8 bytes) strings: [0x0]="recv %s" */
static const u8 RODATA__rodata__mesh_check_window_close_expire_str1_1[] = { 0x66, 0x69, 0x78, 0x65, 0x64, 0x00, 0x67, 0x6f }; /* .rodata._mesh_check_window_close_expire.str1.1 (8 bytes) strings: [0x0]="fixed" */
static const u8 RODATA__rodata__mesh_roots_process_stop_str1_1[] = { 0x73, 0x74, 0x6f, 0x70 }; /* .rodata._mesh_roots_process_stop.str1.1 (4 bytes) */
static const u8 RODATA__rodata__mesh_roots_process_yield_str1_1[] = { 0x72, 0x65, 0x63, 0x76, 0x20, 0x66, 0x69, 0x78, 0x65, 0x64, 0x00, 0x72, 0x65, 0x63, 0x76, 0x20, 0x67, 0x6f, 0x6e, 0x65 }; /* .rodata._mesh_roots_process_yield.str1.1 (20 bytes) strings: [0x0]="recv fixed" */
static const u8 RODATA__rodata__mesh_timer_process_conflict_root_str1_1[] = { 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x70, 0x61, 0x6e, 0x64, 0x6f, 0x72, 0x61, 0x0a, 0x0a }; /* .rodata._mesh_timer_process_conflict_root.str1.1 (28 bytes) */
static const u8 RODATA__rodata__mesh_timer_process_yield_str1_1[] = { 0x74, 0x69, 0x6d, 0x65, 0x72, 0x20, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x00, 0x3c, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x2d, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x3e, 0x6e, 0x6f, 0x6e, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x2c, 0x20, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x20, 0x73, 0x65 }; /* .rodata._mesh_timer_process_yield.str1.1 (44 bytes) strings: [0x0]="timer yield" */
static const u8 RODATA__rodata_esp_mesh_add_conflict_root_str1_1[] = { 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x20, 0x73, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x0a }; /* .rodata.esp_mesh_add_conflict_root.str1.1 (72 bytes) */
static const u8 RODATA__rodata_esp_mesh_parse_conflict_assoc_ie_str1_1[] = { 0x72, 0x65, 0x63, 0x76, 0x20, 0x61, 0x73, 0x73, 0x6f, 0x63, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x00, 0x6e, 0x6f, 0x6e, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x2c, 0x20, 0x72, 0x65, 0x63, 0x76, 0x20, 0x61, 0x73, 0x73, 0x6f, 0x63, 0x00, 0x72, 0x65, 0x63, 0x76, 0x20, 0x61, 0x73, 0x73, 0x6f }; /* .rodata.esp_mesh_parse_conflict_assoc_ie.str1.1 (76 bytes) strings: [0x0]="recv assoc from %02x:%02x:%02x:%02x:%02x:%02x"; [0x2e]="non-root, recv assoc" */
static const u8 RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x2e, 0x63, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73, 0x0a }; /* .rodata.esp_mesh_ps_duty_cycle_get_process.str1.1 (40 bytes) strings: [0x0]="mesh_quick.c" */
static const u8 RODATA__rodata_ieee80211_add_ie_esp_mesh_head_str1_1[] = { 0x18, 0xfe, 0x34, 0x00 }; /* .rodata.ieee80211_add_ie_esp_mesh_head.str1.1 (4 bytes) */
static const u8 RODATA__rodata_ieee80211_add_mesh_duty_signaling_str1_1[] = { 0xff, 0xff, 0xff, 0xff }; /* .rodata.ieee80211_add_mesh_duty_signaling.str1.1 (4 bytes) */
static const u8 RODATA__rodata_ieee80211_mesh_quick_get[] = { 0x4d, 0x00, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0xa6, 0x00, 0x00, 0x00, 0xac, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0xc1, 0x00, 0x00, 0x00, 0xca, 0x00, 0x00, 0x00, 0xd3, 0x00, 0x00, 0x00, 0xdc, 0x00, 0x00, 0x00, 0xe2, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0xee, 0x00, 0x00, 0x00, 0xf6, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x1a, 0x01, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x29, 0x01, 0x00, 0x00, 0x3e, 0x01, 0x00, 0x00 }; /* .rodata.ieee80211_mesh_quick_get (100 bytes) */
static const u8 RODATA__rodata_ieee80211_mesh_quick_set[] = { 0x51, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x96, 0x00, 0x00, 0x00, 0xc4, 0x00, 0x00, 0x00, 0xd3, 0x00, 0x00, 0x00, 0xe2, 0x00, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x15, 0x01, 0x00, 0x00, 0x2a, 0x01, 0x00, 0x00, 0x3f, 0x01, 0x00, 0x00, 0x54, 0x01, 0x00, 0x00, 0x63, 0x01, 0x00, 0x00, 0xb1, 0x01, 0x00, 0x00, 0xc0, 0x01, 0x00, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xd9, 0x01, 0x00, 0x00, 0xe9, 0x01, 0x00, 0x00, 0xf8, 0x01, 0x00, 0x00, 0x07, 0x02, 0x00, 0x00, 0x0f, 0x02, 0x00, 0x00, 0x1e, 0x02, 0x00, 0x00, 0x33, 0x02, 0x00, 0x00, 0x48, 0x02, 0x00, 0x00 }; /* .rodata.ieee80211_mesh_quick_set (100 bytes) */
static const u8 RODATA__rodata_ieee80211_vnd_mesh_roots_set_str1_1[] = { 0x79, 0x69, 0x65, 0x6c, 0x64, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x20, 0x6e, 0x65, 0x77, 0x5f, 0x6d, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x72, 0x65, 0x63, 0x76, 0x20, 0x79, 0x69, 0x65 }; /* .rodata.ieee80211_vnd_mesh_roots_set.str1.1 (92 bytes) strings: [0x0]="yield" */
static const u8 RODATA__rodata_mesh_nwk_duty_process_remaining_str1_1[] = { 0x28, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x61, 0x73, 0x73, 0x6f, 0x63, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x29, 0x00, 0x00, 0x69, 0x6e, 0x63, 0x6f, 0x6d, 0x65, 0x20, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x00, 0x61, 0x75, 0x74, 0x6f, 0x2d, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x00 }; /* .rodata.mesh_nwk_duty_process_remaining.str1.1 (48 bytes) strings: [0x0]="(from assoc response)"; [0x17]="income check"; [0x24]="auto-expire" */
static const u8 RODATA__rodata_mesh_parse_ps_entire_rule_str1_1[] = { 0x63, 0x68, 0x69, 0x6c, 0x64, 0x28, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x00, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x28, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x28, 0x65, 0x6e, 0x74, 0x69, 0x72, 0x65, 0x29, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x2c, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x73, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x64, 0x69, 0x66, 0x66, 0x20, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x28, 0x69, 0x6e, 0x63, 0x6f, 0x6d, 0x65, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x64, 0x65, 0x76, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x29, 0x2c, 0x20, 0x73, 0x79, 0x6e, 0x63, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x28, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x72, 0x75, 0x6c, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6d, 0x65, 0x28, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x72, 0x75, 0x6c, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x0a, 0x0a }; /* .rodata.mesh_parse_ps_entire_rule.str1.1 (224 bytes) strings: [0x0]="child(cidx:"; [0xc]="parent("; [0x14]="mesh" */
static const u8 RODATA__rodata_mesh_parse_ps_uplink_rule_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x28, 0x75, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x29, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x75, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x2c, 0x20, 0x73, 0x79, 0x6e, 0x63, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x28, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x72, 0x75, 0x6c, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x28, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x72, 0x75, 0x6c, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x0a, 0x0a, 0x0a, 0x00 }; /* .rodata.mesh_parse_ps_uplink_rule.str1.1 (116 bytes) */
static const u8 RODATA__rodata_mesh_post_parent_switch_candidate_str1_1[] = { 0x3c, 0x70, 0x6f, 0x73 }; /* .rodata.mesh_post_parent_switch_candidate.str1.1 (4 bytes) */
static const u8 RODATA__rodata_mesh_root_process_roots_ie_str1_1[] = { 0x72, 0x65, 0x63, 0x76, 0x20, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63 }; /* .rodata.mesh_root_process_roots_ie.str1.1 (12 bytes) */
static const u8 RODATA__rodata_roots_type2str_str1_1[] = { 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x00 }; /* .rodata.roots_type2str.str1.1 (8 bytes) strings: [0x0]="unknown" */
static const u8 RODATA__rodata_wlog_error_2[] = { 0x25, 0x64, 0x3c, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x25, 0x73, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x00 }; /* .rodata_wlog_error.2 (36 bytes) strings: [0x0]="%d<malloc>%s fail, size:%d, heap:%d" */
static const u8 RODATA__rodata_wlog_error_5[] = { 0x25, 0x64, 0x3c, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x3e, 0x25, 0x73, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x20, 0x49, 0x45, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x0a, 0x00 }; /* .rodata_wlog_error.5 (52 bytes) */
static const u8 RODATA__rodata_wlog_info_20[] = { 0x28, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x29, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x28, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x29, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x2c, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x25, 0x73, 0x2c, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6e, 0x77, 0x6b, 0x5b, 0x64, 0x75, 0x74, 0x79, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x69, 0x6e, 0x73, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x75, 0x6c, 0x65, 0x3a, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x6e, 0x77, 0x6b, 0x5f, 0x64, 0x75, 0x74, 0x79, 0x3a, 0x25, 0x64 }; /* .rodata_wlog_info.20 (132 bytes) */
static const u8 RODATA__rodata_wlog_info_26[] = { 0x25, 0x64, 0x3c, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2d, 0x69, 0x65, 0x3e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x3d, 0x6d, 0x61, 0x78, 0x3a, 0x25 }; /* .rodata_wlog_info.26 (40 bytes) */
static const u8 RODATA__rodata_wlog_info_27[] = { 0x25, 0x64, 0x3c, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2d, 0x69, 0x65, 0x3e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64 }; /* .rodata_wlog_info.27 (36 bytes) */
static const u8 RODATA__rodata_wlog_info_32[] = { 0x25, 0x64, 0x3c, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x3e, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x28, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x25, 0x64, 0x2f, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x61, 0x73, 0x73, 0x6f, 0x63, 0x3a, 0x28, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x2f, 0x25, 0x64, 0x2f, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x73, 0x73, 0x69, 0x3a, 0x25, 0x64, 0x28, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x73, 0x65, 0x63, 0x73, 0x28, 0x25, 0x6c, 0x6c, 0x75, 0x73, 0x65, 0x63, 0x73, 0x29 }; /* .rodata_wlog_info.32 (152 bytes) */
static const u8 RODATA__rodata_wlog_info_34[] = { 0x25, 0x64, 0x3c, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3e, 0x25, 0x64, 0x73, 0x65, 0x63, 0x73, 0x28, 0x25, 0x64, 0x73, 0x65, 0x63, 0x73, 0x29, 0x20, 0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x77, 0x6f, 0x72, 0x73, 0x65, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x20, 0x72, 0x73, 0x73, 0x69, 0x3a, 0x25, 0x64, 0x28, 0x6c, 0x6f, 0x77, 0x20, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x3a, 0x25, 0x64, 0x29, 0x0a, 0x00 }; /* .rodata_wlog_info.34 (80 bytes) */
static const u8 RODATA__rodata_wlog_warning_10[] = { 0x25, 0x64, 0x3c, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x2d, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x3e, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x65, 0x72, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x20, 0x69, 0x73, 0x20, 0x67, 0x6f, 0x6e, 0x65 }; /* .rodata_wlog_warning.10 (60 bytes) */
static const u8 RODATA__rodata_wlog_warning_11[] = { 0x25, 0x64, 0x3c, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x2d, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x3e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x20, 0x69, 0x73, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x00 }; /* .rodata_wlog_warning.11 (60 bytes) strings: [0x0]="%d<timer-yield>forcer %02x:%02x:%02x:%02x:%02x:%02x is gone" */
static const u8 RODATA__rodata_wlog_warning_12[] = { 0x3c, 0x64, 0x65, 0x62, 0x75, 0x67, 0x3e, 0x6d, 0x79, 0x5f, 0x69, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x5b, 0x75, 0x73, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x69, 0x78, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x3a, 0x25, 0x64, 0x3e, 0x2c, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x3c, 0x66, 0x69, 0x78, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x3a, 0x25, 0x64 }; /* .rodata_wlog_warning.12 (108 bytes) */
static const u8 RODATA__rodata_wlog_warning_13[] = { 0x3c, 0x64, 0x65, 0x62, 0x75, 0x67, 0x3e, 0x25, 0x73, 0x2c, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x75, 0x73, 0x65, 0x64, 0x3a, 0x25, 0x64 }; /* .rodata_wlog_warning.13 (28 bytes) */
static const u8 RODATA__rodata_wlog_warning_14[] = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5b, 0x25, 0x64, 0x5d, 0x74, 0x74, 0x6c, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x72, 0x73, 0x73, 0x69, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x61, 0x70, 0x3a }; /* .rodata_wlog_warning.14 (64 bytes) */
static const u8 RODATA__rodata_wlog_warning_15[] = { 0x25, 0x64, 0x3c, 0x64, 0x65, 0x62, 0x75, 0x67, 0x3e, 0x73, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2d, 0x3e, 0x6e, 0x75, 0x6d, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x20, 0x42, 0x53, 0x53, 0x49, 0x44, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30 }; /* .rodata_wlog_warning.15 (80 bytes) */
static const u8 RODATA__rodata_wlog_warning_16[] = { 0x5b, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x63, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x73, 0x73, 0x69, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x74, 0x6c, 0x3a, 0x25, 0x64, 0x5d, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x3a, 0x25, 0x6c, 0x6c, 0x64, 0x2c, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x3a }; /* .rodata_wlog_warning.16 (92 bytes) */
static const u8 RODATA__rodata_wlog_warning_17[] = { 0x25, 0x64, 0x3c, 0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x3e, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x5f, 0x69, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x3e, 0x6e, 0x75, 0x6d, 0x3a }; /* .rodata_wlog_warning.17 (52 bytes) */
static const u8 RODATA__rodata_wlog_warning_18[] = { 0x25, 0x64, 0x3c, 0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x3e, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x5f, 0x69, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6e, 0x6f, 0x77, 0x3a, 0x25, 0x6c, 0x6c }; /* .rodata_wlog_warning.18 (40 bytes) */
static const u8 RODATA__rodata_wlog_warning_19[] = { 0x25, 0x64, 0x5b, 0x75, 0x73, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3c, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x69, 0x78, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x3a, 0x25, 0x64, 0x3e, 0x2c, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x5b, 0x66, 0x69, 0x78, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x3a, 0x25, 0x64, 0x5d }; /* .rodata_wlog_warning.19 (96 bytes) */
static const u8 RODATA__rodata_wlog_warning_21[] = { 0x28, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x29, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x2c, 0x20, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x69, 0x6e, 0x73, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6e, 0x77, 0x6b, 0x5f, 0x64, 0x75, 0x74, 0x79, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x69, 0x6e, 0x73, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x3a, 0x25, 0x6c, 0x6c, 0x64, 0x20, 0x6d, 0x73, 0x2c, 0x20, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x75, 0x73, 0x3a, 0x25, 0x6c, 0x6c, 0x64, 0x20, 0x6d }; /* .rodata_wlog_warning.21 (108 bytes) */
static const u8 RODATA__rodata_wlog_warning_22[] = { 0x28, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x29, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x2c, 0x20, 0x6e, 0x77, 0x6b, 0x5f, 0x64, 0x75, 0x74, 0x79, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x25, 0x73, 0x2c, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x69, 0x6e, 0x73, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x75, 0x6c, 0x65, 0x3a, 0x25, 0x64, 0x25, 0x73 }; /* .rodata_wlog_warning.22 (80 bytes) */
static const u8 RODATA__rodata_wlog_warning_23[] = { 0x28, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x29, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x6e, 0x77, 0x6b, 0x5f, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x5f, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x3a }; /* .rodata_wlog_warning.23 (36 bytes) */
static const u8 RODATA__rodata_wlog_warning_24[] = { 0x25, 0x64, 0x3c, 0x77, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x3e, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x20, 0x49, 0x45, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3a }; /* .rodata_wlog_warning.24 (32 bytes) */
static const u8 RODATA__rodata_wlog_warning_25[] = { 0x25, 0x64, 0x3c, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x3e, 0x25, 0x73, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x20, 0x21, 0x3d, 0x20, 0x32, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78 }; /* .rodata_wlog_warning.25 (60 bytes) */
static const u8 RODATA__rodata_wlog_warning_28[] = { 0x25, 0x64, 0x3c, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2d, 0x69, 0x65, 0x3e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x25, 0x73, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2c, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x69, 0x64, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2f, 0x74, 0x74, 0x6c, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64 }; /* .rodata_wlog_warning.28 (136 bytes) */
static const u8 RODATA__rodata_wlog_warning_29[] = { 0x25, 0x64, 0x3c, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2d, 0x69, 0x65, 0x3e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x25, 0x73, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x3c, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3e, 0x2c, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x69, 0x64, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x74, 0x6c, 0x3a, 0x25, 0x64, 0x3e, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x28, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x2c, 0x63, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25 }; /* .rodata_wlog_warning.29 (160 bytes) */
static const u8 RODATA__rodata_wlog_warning_3[] = { 0x25, 0x64, 0x3c, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x3e, 0x25, 0x73, 0x20, 0x6d, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x20, 0x21, 0x3d, 0x20, 0x32, 0x2c, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a }; /* .rodata_wlog_warning.3 (40 bytes) */
static const u8 RODATA__rodata_wlog_warning_30[] = { 0x25, 0x64, 0x3c, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2d, 0x69, 0x65, 0x3e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x25, 0x73, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x3c, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3e, 0x2c, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x69, 0x64, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x74, 0x6c, 0x3a, 0x25, 0x64, 0x28, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x28, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x2c, 0x63, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x6c, 0x65, 0x6e, 0x3a }; /* .rodata_wlog_warning.30 (160 bytes) */
static const u8 RODATA__rodata_wlog_warning_31[] = { 0x25, 0x64, 0x3c, 0x75, 0x6e, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x3e, 0x62, 0x73, 0x73, 0x69, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x72, 0x63, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x28, 0x63, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x61, 0x73, 0x73, 0x6f, 0x63, 0x3a, 0x25, 0x64, 0x28, 0x63, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x63, 0x61, 0x70, 0x28, 0x72, 0x6f, 0x6f, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x72, 0x63, 0x5f, 0x72, 0x73, 0x73, 0x69, 0x3a, 0x25, 0x64, 0x00 }; /* .rodata_wlog_warning.31 (160 bytes) strings: [0x0]="%d<unexpected>bssid:%02x:%02x:%02x:%02x:%02x:%02x, rc_addr:%02x:%02x:%02x:%02x:%02x:%02x, " */
static const u8 RODATA__rodata_wlog_warning_33[] = { 0x25, 0x64, 0x3c, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x3e, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x73, 0x65, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x72, 0x73, 0x73, 0x69, 0x3a, 0x25, 0x64, 0x28, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x6c, 0x6c, 0x75, 0x73, 0x65, 0x63 }; /* .rodata_wlog_warning.33 (116 bytes) */
static const u8 RODATA__rodata_wlog_warning_35[] = { 0x25, 0x64, 0x3c, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x3e, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x20, 0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x20, 0x77, 0x69, 0x74, 0x68, 0x69, 0x6e, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x73, 0x65, 0x63, 0x73, 0x28, 0x25, 0x6c, 0x6c, 0x75, 0x73, 0x65, 0x63 }; /* .rodata_wlog_warning.35 (116 bytes) */
static const u8 RODATA__rodata_wlog_warning_36[] = { 0x25, 0x64, 0x3c, 0x66, 0x72, 0x65, 0x65, 0x3e, 0x72, 0x6f, 0x6f, 0x74, 0x6c, 0x65, 0x73, 0x73 }; /* .rodata_wlog_warning.36 (16 bytes) */
static const u8 RODATA__rodata_wlog_warning_4[] = { 0x25, 0x64, 0x3c, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x3e, 0x25, 0x73, 0x20, 0x6d, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25 }; /* .rodata_wlog_warning.4 (36 bytes) */
static const u8 RODATA__rodata_wlog_warning_6[] = { 0x25, 0x64, 0x3c, 0x25, 0x73, 0x2d, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x3e, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x2c, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x2c, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x3c, 0x66, 0x69, 0x78, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x3a, 0x25, 0x64, 0x3e, 0x2c, 0x20, 0x6d, 0x79, 0x5f, 0x69, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2d, 0x3e, 0x6e, 0x75, 0x6d, 0x3a, 0x25 }; /* .rodata_wlog_warning.6 (116 bytes) */
static const u8 RODATA__rodata_wlog_warning_7[] = { 0x25, 0x64, 0x5b, 0x75, 0x73, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3c, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x69, 0x78, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x3a, 0x25, 0x64 }; /* .rodata_wlog_warning.7 (68 bytes) */
static const u8 RODATA__rodata_wlog_warning_8[] = { 0x25, 0x64, 0x3c, 0x25, 0x73, 0x2d, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x3e, 0x6f, 0x70, 0x65, 0x6e, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x2c, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x2c, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x3c, 0x66, 0x69, 0x78, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x3a, 0x25, 0x64, 0x3e, 0x2c, 0x20, 0x6d, 0x79, 0x5f, 0x69, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x2d, 0x3e, 0x6e, 0x75, 0x6d, 0x3a, 0x25, 0x64 }; /* .rodata_wlog_warning.8 (116 bytes) */
static const u8 RODATA__rodata_wlog_warning_9[] = { 0x25, 0x64, 0x5b, 0x75, 0x73, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3c, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x79, 0x69, 0x65, 0x6c, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x69, 0x78, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x67, 0x6f, 0x6e, 0x65, 0x3a, 0x25, 0x64 }; /* .rodata_wlog_warning.9 (68 bytes) */
static u8 LOCAL__bss_MESH_ZERO_ADDR[0x4]; /* stand-in for .bss.MESH_ZERO_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_esp_mesh_remain_nwk_duty[0x4]; /* stand-in for .bss.esp_mesh_remain_nwk_duty (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_is_roots_found_13[0x4]; /* stand-in for .bss.is_roots_found$13 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_iv[0x4]; /* stand-in for .bss.iv (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_last_parent_layer_2[0x4]; /* stand-in for .bss.last_parent_layer$2 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_max_ie_len_11[0x4]; /* stand-in for .bss.max_ie_len$11 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_sub_ie_3[0x4]; /* stand-in for .bss.mesh_sub_ie$3 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_monitor_count_1[0x4]; /* stand-in for .bss.monitor_count$1 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_monitor_time_start_5[0x4]; /* stand-in for .bss.monitor_time_start$5 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_post_event_time_14[0x4]; /* stand-in for .bss.post_event_time$14 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_post_event_time_7[0x4]; /* stand-in for .bss.post_event_time$7 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_roots_found_time_12[0x4]; /* stand-in for .bss.roots_found_time$12 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_rx_bcn_count_0[0x4]; /* stand-in for .bss.rx_bcn_count$0 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_is_probe_requested[0x4]; /* stand-in for .bss.s_is_probe_requested (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_conflict_roots[0x4]; /* stand-in for .bss.s_mesh_conflict_roots (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_ie_crypto_funcs[0x4]; /* stand-in for .bss.s_mesh_ie_crypto_funcs (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_ie_crypto_key[0x4]; /* stand-in for .bss.s_mesh_ie_crypto_key (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_monitor_parent_cfg[0x4]; /* stand-in for .bss.s_mesh_monitor_parent_cfg (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_parent_candidate[0x4]; /* stand-in for .bss.s_mesh_parent_candidate (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_roots_ie_life[0x4]; /* stand-in for .bss.s_mesh_roots_ie_life (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_rssi_threshold[0x4]; /* stand-in for .bss.s_mesh_rssi_threshold (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_parent_monitor_assoc_time[0x4]; /* stand-in for .bss.s_parent_monitor_assoc_time (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_parent_monitor_weak_time[0x4]; /* stand-in for .bss.s_parent_monitor_weak_time (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_parent_worse_rssi_time[0x4]; /* stand-in for .bss.s_parent_worse_rssi_time (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_ps_device_duty[0x4]; /* stand-in for .bss.s_ps_device_duty (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_ps_device_duty_type[0x4]; /* stand-in for .bss.s_ps_device_duty_type (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_ps_parent_duty[0x4]; /* stand-in for .bss.s_ps_parent_duty (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_ps_parent_duty_type[0x4]; /* stand-in for .bss.s_ps_parent_duty_type (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_recv_bcn_count[0x4]; /* stand-in for .bss.s_recv_bcn_count (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_signaling_token_8[0x4]; /* stand-in for .bss.signaling_token$8 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_wifi_vnd_ext_mesh_roots[0x4]; /* stand-in for .bss.wifi_vnd_ext_mesh_roots (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_MESH_BCAST_ADDR[0x4]; /* stand-in for .data.MESH_BCAST_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_candidate_rssi_4[0x4]; /* stand-in for .data.candidate_rssi$4 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* _mesh_check_roots_gone @ mesh_quick.o 0000002c size 206B bind GLOBAL
 * Calls: memset, roots_type2str, sprintf, esp_mesh_get_conflict_root_state, memcpy, wifi_mesh_event_post, mesh_get_vnd_roots_len | Data refs: .bss.s_mesh_conflict_roots, .bss.wifi_vnd_ext_mesh_roots, .rodata._mesh_check_roots_gone.str1.1, g_mesh_max_layer
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=7, refs=11); reloc-direct=7, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_check_roots_gone(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8, a9;
  float F6, F8;
  /* 002c: entry a1, 80 (frame 80 bytes) */
  a8 = 1;  /* 002f */
  a10 = 0;  /* 0031 */
  if (a2 == 0) a10 = a8;  /* 0033 */
  a5 = a2;  /* 0036 */
  a4 = (a4 >> 8) & 0x1;  /* 0038: extui width 1 */
  a9 = (a10 >> 8) & 0x1;  /* 003b: extui width 1 */
  if (a10 != 0) goto L_00f6;  /* 003e: bnez a10, f6 <_mesh_check_roots_gone+0xca> */
  L_0041: if (a3 == 0) a9 = a8;  /* 0041 */
  if (a9 != 0) goto L_00f6;  /* 0044: bnez a9, f6 <_mesh_check_roots_gone+0xca> */
  L_0047: a2 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0047: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a10 = LD32(a2 + 0x0);  /* 004a */
  a2 = 2;  /* 004c */
  if (a10 == 0) goto L_00f8;  /* 004e: beqz a10, f8 <_mesh_check_roots_gone+0xcc> */
  L_0051: a2 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0051: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a10 = LD8U(a2 + 0x11);  /* 0054 */
  a2 = 2;  /* 0057 */
  if (a10 < 5u) goto L_0060;  /* 005a: bltui a10, 5, 60 <_mesh_check_roots_gone+0x34> */
  L_005d: goto L_00f8;  /* 005d: j */
  L_0060: if (a4 < a2) goto L_006c;  /* 0060: bltu a4, a2, 6c <_mesh_check_roots_gone+0x40> */
  L_0063: a10 = a4 + (-5);  /* 0063 */
  if (a10 == 0) a8 = a9;  /* 0066 */
  if (a8 != 0) goto L_00f8;  /* 0069: bnez a8, f8 <_mesh_check_roots_gone+0xcc> */
  L_006c: a11 = 0;  /* 006c */
  a12 = 12;  /* 006e */
  a2 = -1;  /* 0070 */
  a10 = a1 + (4);  /* 0072 */
  ST32(a1 + 0x0, a11);  /* 0074 */
  ST32(a1 + 0x28, a2);  /* 0076 */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  a8 = (u32)&memset + 0x0;  /* 007b: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 007e: callx a8 (libc, via reloc-expand) */
  a10 = a4;  /* 0081 */
  a8 = (u32)&roots_type2str;  /* 0083: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4, a5, a6, a7);  /* 0086: callx a8 via reloc-expand */
  a12 = a10;  /* 0089: mov */
  a11 = (u32)(RODATA__rodata__mesh_check_roots_gone_str1_1 + 0x0);  /* 008c: -> "recv %s" */
  a10 = a1;  /* 008f: mov */
  a8 = (u32)&sprintf + 0x0;  /* 0092: l32r -> global */
  a2 = sprintf(a2, a3, a4, a5, a6, a7);  /* 0095: callx a8 via reloc-expand */
  a12 = 0x405;  /* 0098 */
  a13 = a1;  /* 009b */
  a12 = a12 + a12;  /* 009d */
  a11 = a1 + (40);  /* 009f */
  a10 = a5;  /* 00a2 */
  a8 = (u32)&esp_mesh_get_conflict_root_state;  /* 00a4: l32r -> func addr */
  a2 = esp_mesh_get_conflict_root_state(a2, a3, a4, a5, a6, a7);  /* 00a7: callx a8 via reloc-expand */
  a2 = a10;  /* 00aa */
  if (a10 != 1) goto L_00f8;  /* 00ac: bnei a10, 1, f8 <_mesh_check_roots_gone+0xcc> */
  L_00af: a11 = a5;  /* 00af */
  a12 = 12;  /* 00b1 */
  a10 = a1 + (16);  /* 00b3 */
  a8 = (u32)&memcpy + 0x0;  /* 00b6: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00b9: callx a8 (libc, via reloc-expand) */
  a4 = (u32)&g_mesh_max_layer + 0x0;  /* 00bc: l32r -> global */
  a12 = 12;  /* 00bf */
  a11 = a1 + (28);  /* 00c1 */
  a10 = 59;  /* 00c4 */
  a5 = LD16U(a4 + 0x0);  /* 00c6 */
  a5 = a5 + (-1);  /* 00c9 */
  ST16(a1 + 0x10, a5);  /* 00cb */
  __asm__ volatile("" ::: "memory");  /* 00ce: memw */
  a4 = LD32(a1 + 0x10);  /* 00d1 */
  a5 = LD32(a1 + 0x14);  /* 00d3 */
  ST32(a1 + 0x1c, a4);  /* 00d5 */
  a4 = LD32(a1 + 0x18);  /* 00d7 */
  ST32(a1 + 0x20, a5);  /* 00d9 */
  ST32(a1 + 0x24, a4);  /* 00dc */
  __asm__ volatile("" ::: "memory");  /* 00df: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 00e2: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 00e5: callx a8 via reloc-expand */
  a8 = (u32)&mesh_get_vnd_roots_len;  /* 00e8: l32r -> func addr */
  a2 = mesh_get_vnd_roots_len(a2, a3, a4, a5, a6, a7);  /* 00eb: callx a8 via reloc-expand */
  ST32(a3 + 0x0, a10);  /* 00ee */
  __asm__ volatile("" ::: "memory");  /* 00f0: memw */
  goto L_00f8;  /* 00f3: j */
  L_00f6: a2 = 2;  /* 00f6 */
  L_00f8: return a2;  /* 00f8: retw.n */
}


/* _mesh_check_window_close_expire @ mesh_quick.o 0000002c size 354B bind GLOBAL
 * Calls: wifi_log | indirect[4]: mem[a2+0x110] | Data refs: .bss.s_mesh_roots_ie_life, g_osi_funcs_p, .rodata._mesh_check_window_close_expire.str1.1, .bss.s_mesh_conflict_roots, .rodata_wlog_warning.6, .bss.wifi_vnd_ext_mesh_roots, .rodata_wlog_warning.7
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=8); reloc-direct=1, funcdb-attributed=0, unknown-indirect=4 */
u32 _mesh_check_window_close_expire(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a4, a5, a6, a7, a8, a9;
  /* 002c: entry a1, 80 (frame 80 bytes) */
  a6 = (a2 >> 8) & 0x1;  /* 002f: extui width 1 */
  a2 = -1;  /* 0032 */
  if (a6 < 2u) goto L_003a;  /* 0034: bltui a6, 2, 3a <_mesh_check_window_close_expire+0xe> */
  L_0037: goto L_018c;  /* 0037: j */
  L_003a: a5 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 003a: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a4 = a6 << 4;  /* 003d */
  a7 = a5 + a4;  /* 0040 */
  a2 = LD8U(a7 + 0x0);  /* 0042 */
  if (a2 != 0) goto L_004c;  /* 0045: bnez.n a2, 4c <_mesh_check_window_close_expire+0x20> */
  L_0047: goto L_018a;  /* 0047: j */
  L_004c: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 004c: l32r -> global */
  a9 = a7 + (8);  /* 004f */
  a2 = LD32(a8 + 0x0);  /* 0051 */
  a11 = LD32(a9 + 0x4);  /* 0053 */
  a10 = LD32(a2 + 0x110);  /* 0055 */
  a2 = LD32(a7 + 0x8);  /* 0058 */
  a2 = a2 | a11;  /* 005a */
  if (a2 != 0) goto L_006c;  /* 005d: bnez.n a2, 6c <_mesh_check_window_close_expire+0x40> */
  L_005f: /* 005f: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  ST32(a7 + 0x8, a10);  /* 0062 */
  ST32(a7 + 0xc, a11);  /* 0064 */
  __asm__ volatile("" ::: "memory");  /* 0066: memw */
  goto L_018c;  /* 0069: j */
  L_006c: ST32(a1 + 0x20, a8);  /* 006c */
  ST32(a1 + 0x24, a9);  /* 006e */
  __asm__ volatile("" ::: "memory");  /* 0070: memw */
  /* 0073: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x24);  /* 0076 */
  a2 = LD32(a9 + 0x4);  /* 0078 */
  a8 = LD32(a1 + 0x20);  /* 007a */
  if ((i32)a11 < (i32)a2) goto L_00aa;  /* 007d: blt a11, a2, aa <_mesh_check_window_close_expire+0x7e> */
  L_0080: if (a2 != a11) goto L_0088;  /* 0080: bne a2, a11, 88 <_mesh_check_window_close_expire+0x5c> */
  L_0083: a2 = LD32(a7 + 0x8);  /* 0083 */
  if (a10 < a2) goto L_00aa;  /* 0085: bltu a10, a2, aa <_mesh_check_window_close_expire+0x7e> */
  L_0088: a7 = a5 + a4;  /* 0088 */
  a2 = LD32(a8 + 0x0);  /* 008a */
  a10 = LD32(a2 + 0x110);  /* 008c */
  /* 008f: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a2 = LD32(a7 + 0x8);  /* 0092 */
  a2 = a10 - a2;  /* 0094: sub */
  a8 = LD32(a7 + 0xc);  /* 0097 */
  a7 = 1;  /* 0099 */
  if (a10 < a2) goto L_00a0;  /* 009b: bltu a10, a2, a0 <_mesh_check_window_close_expire+0x74> */
  L_009e: a7 = 0;  /* 009e */
  L_00a0: a8 = a11 - a8;  /* 00a0: sub */
  a8 = a8 - a7;  /* 00a3: sub */
  goto L_00d7;  /* 00a6: j */
  L_00aa: a2 = LD32(a8 + 0x0);  /* 00aa */
  a10 = LD32(a2 + 0x110);  /* 00ac */
  a2 = a5 + a4;  /* 00af */
  /* 00b1: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a8 = -1;  /* 00b4 */
  a7 = LD32(a2 + 0x8);  /* 00b6 */
  a7 = a7 ^ a8;  /* 00b8 */
  a10 = a7 + a10;  /* 00bb */
  a8 = 1;  /* 00bd */
  a2 = LD32(a2 + 0xc);  /* 00bf */
  if (a10 < a7) goto L_00c6;  /* 00c1: bltu a10, a7, c6 <_mesh_check_window_close_expire+0x9a> */
  L_00c4: a8 = 0;  /* 00c4 */
  L_00c6: a11 = a2 + a11;  /* 00c6 */
  a2 = a10 + (1);  /* 00c8 */
  a11 = a8 + a11;  /* 00ca */
  a8 = 1;  /* 00cd */
  if (a2 < a10) goto L_00d5;  /* 00d0: bltu a2, a10, d5 <_mesh_check_window_close_expire+0xa9> */
  L_00d3: a8 = 0;  /* 00d3 */
  L_00d5: a8 = a8 + a11;  /* 00d5 */
  L_00d7: a2 = a2 >> 10;  /* 00d7 */
  a8 = a8 << 22;  /* 00da */
  a8 = a8 | a2;  /* 00dd */
  a2 = 0x0001d4bfu;  /* 00e0: l32r = 119999 */
  if (a2 < a8) goto L_00e9;  /* 00e3: bltu a2, a8, e9 <_mesh_check_window_close_expire+0xbd> */
  L_00e6: goto L_018a;  /* 00e6: j */
  L_00e9: a4 = a5 + a4;  /* 00e9 */
  a10 = 0;  /* 00eb */
  a2 = 0;  /* 00ed */
  ST8(a4 + 0x0, a2);  /* 00f0 */
  __asm__ volatile("" ::: "memory");  /* 00f3: memw */
  ST32(a4 + 0x8, a10);  /* 00f6 */
  ST32(a4 + 0xc, a10);  /* 00f9 */
  a15 = (u32)(RODATA__rodata__mesh_check_window_close_expire_str1_1 + 0x0);  /* 00fb: -> "fixed" */
  if (a6 == a10) goto L_0104;  /* 00fe: beq a6, a10, 104 <_mesh_check_window_close_expire+0xd8> */
  L_0101: a15 = (u32)(RODATA__rodata__mesh_check_window_close_expire_str1_1 + 0x0);  /* 0101: -> "fixed" */
  L_0104: a8 = a8 >> 10;  /* 0104 */
  a2 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0107: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a4 = LD32(a2 + 0x0);  /* 010a */
  a2 = 0;  /* 010c */
  a6 = LD8U(a5 + 0x0);  /* 010e */
  a5 = LD8U(a5 + 0x10);  /* 0111 */
  if (a4 == a2) goto L_011a;  /* 0114: beq a4, a2, 11a <_mesh_check_window_close_expire+0xee> */
  L_0117: a2 = LD8U(a4 + 0x0);  /* 0117 */
  L_011a: a4 = 1;  /* 011a */
  a4 = a4 << 21;  /* 011c */
  a14 = 0x7cc;  /* 011f */
  a12 = 2;  /* 0122 */
  a13 = (u32)(RODATA__rodata_wlog_warning_6 + 0x0);  /* 0124: l32r -> .rodata_wlog_warning.6 */
  a11 = a4;  /* 0127 */
  a10 = 1;  /* 0129 */
  ST32(a1 + 0x10, a2);  /* 012b */
  ST32(a1 + 0xc, a3);  /* 012d */
  ST32(a1 + 0x8, a5);  /* 012f */
  ST32(a1 + 0x4, a6);  /* 0132 */
  ST32(a1 + 0x0, a8);  /* 0134 */
  __asm__ volatile("" ::: "memory");  /* 0137: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 013a: l32r -> global */
  a2 = wifi_log(a2, a3, a4);  /* 013d: callx a8 via reloc-expand */
  if (a3 == 0) goto L_018a;  /* 0140: beqz a3, 18a <_mesh_check_window_close_expire+0x15e> */
  L_0143: a14 = 0x7d7;  /* 0143 */
  a12 = 2;  /* 0146 */
  a2 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0148: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a11 = a4;  /* 014b */
  a10 = 1;  /* 014d */
  a3 = LD8U(a2 + 0x19);  /* 014f */
  a15 = LD32(a2 + 0x0);  /* 0152 */
  a15 = (a15 >> 1) & 0x1;  /* 0154: extui width 1 */
  ST32(a1 + 0x18, a3);  /* 0157 */
  a3 = LD8U(a2 + 0x11);  /* 0159 */
  ST32(a1 + 0x14, a3);  /* 015c */
  a3 = LD8U(a2 + 0x9);  /* 015e */
  ST32(a1 + 0x10, a3);  /* 0161 */
  a3 = LD8U(a2 + 0x1);  /* 0163 */
  ST32(a1 + 0xc, a3);  /* 0166 */
  a3 = LD32(a2 + 0x18);  /* 0168 */
  a3 = (a3 >> 1) & 0x1;  /* 016a: extui width 1 */
  ST32(a1 + 0x8, a3);  /* 016d */
  a3 = LD32(a2 + 0x10);  /* 016f */
  a3 = (a3 >> 1) & 0x1;  /* 0171: extui width 1 */
  ST32(a1 + 0x4, a3);  /* 0174 */
  a2 = LD32(a2 + 0x8);  /* 0176 */
  a2 = (a2 >> 1) & 0x1;  /* 0178: extui width 1 */
  a13 = (u32)(RODATA__rodata_wlog_warning_7 + 0x0);  /* 017b: l32r -> .rodata_wlog_warning.7 */
  ST32(a1 + 0x0, a2);  /* 017e */
  __asm__ volatile("" ::: "memory");  /* 0181: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0184: l32r -> global */
  a2 = wifi_log(a2, a3);  /* 0187: callx a8 via reloc-expand */
  L_018a: a2 = 0;  /* 018a */
  L_018c: return a2;  /* 018c: retw.n */
}


/* _mesh_check_window_open_expire @ mesh_quick.o 00000034 size 376B bind GLOBAL
 * Calls: _wifi_vnd_ext_mesh_roots_free, mesh_get_vnd_roots_len, roots_type2str, wifi_log | indirect[4]: mem[a2+0x110] | Data refs: g_osi_funcs_p, .bss.s_mesh_roots_ie_life, .bss.s_mesh_conflict_roots, .rodata_wlog_warning.8, .bss.wifi_vnd_ext_mesh_roots, .rodata_wlog_warning.9
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=10); reloc-direct=4, funcdb-attributed=0, unknown-indirect=4 */
u32 _mesh_check_window_open_expire(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a4, a5, a6, a7, a8, a9;
  /* 0034: entry a1, 80 (frame 80 bytes) */
  a7 = (a2 >> 8) & 0x1;  /* 0037: extui width 1 */
  a2 = 0x102;  /* 003a */
  if (a3 == 0) goto L_01aa;  /* 003d: beqz a3, 1aa <_mesh_check_window_open_expire+0x176> */
  L_0040: a5 = a7 + (-2);  /* 0040 */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0043: l32r -> global */
  a5 = (a5 >> 8) & 0x1;  /* 0046: extui width 1 */
  a5 = a5 << 4;  /* 0049 */
  a6 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 004c: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a4 = a6 + a5;  /* 004f */
  a9 = a4 + (8);  /* 0051 */
  a2 = LD32(a8 + 0x0);  /* 0053 */
  a11 = LD32(a9 + 0x4);  /* 0055 */
  a10 = LD32(a2 + 0x110);  /* 0057 */
  a2 = LD32(a4 + 0x8);  /* 005a */
  a2 = a2 | a11;  /* 005c */
  if (a2 != 0) goto L_006e;  /* 005f: bnez.n a2, 6e <_mesh_check_window_open_expire+0x3a> */
  L_0061: /* 0061: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  ST32(a4 + 0x8, a10);  /* 0064 */
  ST32(a4 + 0xc, a11);  /* 0066 */
  __asm__ volatile("" ::: "memory");  /* 0068: memw */
  goto L_01aa;  /* 006b: j */
  L_006e: ST32(a1 + 0x20, a8);  /* 006e */
  ST32(a1 + 0x24, a9);  /* 0070 */
  __asm__ volatile("" ::: "memory");  /* 0072: memw */
  /* 0075: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x24);  /* 0078 */
  a2 = LD32(a9 + 0x4);  /* 007a */
  a8 = LD32(a1 + 0x20);  /* 007c */
  if ((i32)a11 < (i32)a2) goto L_00ae;  /* 007e: blt a11, a2, ae <_mesh_check_window_open_expire+0x7a> */
  L_0081: if (a2 != a11) goto L_008a;  /* 0081: bne a2, a11, 8a <_mesh_check_window_open_expire+0x56> */
  L_0084: a2 = LD32(a4 + 0x8);  /* 0084 */
  if (a10 < a2) goto L_00ae;  /* 0087: bltu a10, a2, ae <_mesh_check_window_open_expire+0x7a> */
  L_008a: a4 = a6 + a5;  /* 008a */
  a2 = LD32(a8 + 0x0);  /* 008c */
  a10 = LD32(a2 + 0x110);  /* 008e */
  /* 0091: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a8 = 1;  /* 0094 */
  a2 = LD32(a4 + 0x8);  /* 0096 */
  a2 = a10 - a2;  /* 0098: sub */
  a4 = LD32(a4 + 0xc);  /* 009b */
  if (a10 < a2) goto L_00a4;  /* 009e: bltu a10, a2, a4 <_mesh_check_window_open_expire+0x70> */
  L_00a1: a8 = 0;  /* 00a1 */
  L_00a4: a4 = a11 - a4;  /* 00a4: sub */
  a4 = a4 - a8;  /* 00a7: sub */
  goto L_00da;  /* 00aa: j */
  L_00ae: a2 = LD32(a8 + 0x0);  /* 00ae */
  a10 = LD32(a2 + 0x110);  /* 00b0 */
  a2 = a6 + a5;  /* 00b3 */
  /* 00b5: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a8 = -1;  /* 00b8 */
  a4 = LD32(a2 + 0x8);  /* 00ba */
  a4 = a4 ^ a8;  /* 00bc */
  a10 = a4 + a10;  /* 00bf */
  a8 = 1;  /* 00c1 */
  a2 = LD32(a2 + 0xc);  /* 00c3 */
  if (a10 < a4) goto L_00ca;  /* 00c5: bltu a10, a4, ca <_mesh_check_window_open_expire+0x96> */
  L_00c8: a8 = 0;  /* 00c8 */
  L_00ca: a11 = a2 + a11;  /* 00ca */
  a2 = a10 + (1);  /* 00cc */
  a11 = a8 + a11;  /* 00ce */
  a4 = 1;  /* 00d0 */
  if (a2 < a10) goto L_00d8;  /* 00d2: bltu a2, a10, d8 <_mesh_check_window_open_expire+0xa4> */
  L_00d5: a4 = 0;  /* 00d5 */
  L_00d8: a4 = a4 + a11;  /* 00d8 */
  L_00da: a2 = a2 >> 10;  /* 00da */
  a4 = a4 << 22;  /* 00dd */
  a4 = a4 | a2;  /* 00e0 */
  a2 = 0x00003a97u;  /* 00e3: l32r = 14999 */
  if (a2 < a4) goto L_00ec;  /* 00e6: bltu a2, a4, ec <_mesh_check_window_open_expire+0xb8> */
  L_00e9: goto L_01a8;  /* 00e9: j */
  L_00ec: a10 = a7;  /* 00ec */
  a8 = (u32)&_wifi_vnd_ext_mesh_roots_free;  /* 00ee: l32r -> func addr */
  a2 = _wifi_vnd_ext_mesh_roots_free(a2, a3);  /* 00f1: callx a8 via reloc-expand */
  a5 = a6 + a5;  /* 00f4 */
  a8 = 0;  /* 00f6 */
  a2 = 1;  /* 00f8 */
  ST32(a5 + 0x8, a8);  /* 00fa */
  a4 = a4 >> 10;  /* 00fd */
  ST32(a5 + 0xc, a8);  /* 0100 */
  ST8(a5 + 0x0, a2);  /* 0103 */
  __asm__ volatile("" ::: "memory");  /* 0106: memw */
  __asm__ volatile("" ::: "memory");  /* 0109: memw */
  a8 = (u32)&mesh_get_vnd_roots_len;  /* 010c: l32r -> func addr */
  a2 = mesh_get_vnd_roots_len(a2, a3, a4, a5);  /* 010f: callx a8 via reloc-expand */
  a2 = a10;  /* 0112 */
  ST32(a3 + 0x0, a10);  /* 0114 */
  a10 = a7;  /* 0116 */
  __asm__ volatile("" ::: "memory");  /* 0118: memw */
  a8 = (u32)&roots_type2str;  /* 011b: l32r -> func addr */
  a2 = roots_type2str(a2, a3);  /* 011e: callx a8 via reloc-expand */
  a5 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0121: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a5 = LD32(a5 + 0x0);  /* 0124 */
  a7 = LD8U(a6 + 0x0);  /* 0126 */
  a8 = LD8U(a6 + 0x10);  /* 0129 */
  a6 = 0;  /* 012c */
  if (a5 == a6) goto L_0134;  /* 012e: beq a5, a6, 134 <_mesh_check_window_open_expire+0x100> */
  L_0131: a6 = LD8U(a5 + 0x0);  /* 0131 */
  L_0134: a5 = 1;  /* 0134 */
  a5 = a5 << 21;  /* 0136 */
  a14 = 0x223;  /* 0139 */
  a15 = a10;  /* 013c */
  a13 = (u32)(RODATA__rodata_wlog_warning_8 + 0x0);  /* 013e: l32r -> .rodata_wlog_warning.8 */
  a14 = a14 << 2;  /* 0141 */
  a12 = 2;  /* 0144 */
  a11 = a5;  /* 0146 */
  a10 = 1;  /* 0148 */
  ST32(a1 + 0xc, a2);  /* 014a */
  ST32(a1 + 0x10, a6);  /* 014c */
  ST32(a1 + 0x8, a8);  /* 014e */
  ST32(a1 + 0x4, a7);  /* 0150 */
  ST32(a1 + 0x0, a4);  /* 0152 */
  __asm__ volatile("" ::: "memory");  /* 0154: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0157: l32r -> global */
  a2 = wifi_log(a2, a3);  /* 015a: callx a8 via reloc-expand */
  a2 = LD32(a3 + 0x0);  /* 015d */
  if (a2 == 0) goto L_01a8;  /* 015f: beqz a2, 1a8 <_mesh_check_window_open_expire+0x174> */
  L_0162: a12 = 2;  /* 0162 */
  a11 = a5;  /* 0164 */
  a2 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0166: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a10 = 1;  /* 0169 */
  a3 = LD8U(a2 + 0x19);  /* 016b */
  a15 = LD32(a2 + 0x0);  /* 016e */
  a15 = (a15 >> 1) & 0x1;  /* 0170: extui width 1 */
  ST32(a1 + 0x18, a3);  /* 0173 */
  a3 = LD8U(a2 + 0x11);  /* 0175 */
  ST32(a1 + 0x14, a3);  /* 0178 */
  a3 = LD8U(a2 + 0x9);  /* 017a */
  ST32(a1 + 0x10, a3);  /* 017d */
  a3 = LD8U(a2 + 0x1);  /* 017f */
  ST32(a1 + 0xc, a3);  /* 0182 */
  a3 = LD32(a2 + 0x18);  /* 0184 */
  a3 = (a3 >> 1) & 0x1;  /* 0186: extui width 1 */
  ST32(a1 + 0x8, a3);  /* 0189 */
  a3 = LD32(a2 + 0x10);  /* 018b */
  a3 = (a3 >> 1) & 0x1;  /* 018d: extui width 1 */
  ST32(a1 + 0x4, a3);  /* 0190 */
  a2 = LD32(a2 + 0x8);  /* 0192 */
  a2 = (a2 >> 1) & 0x1;  /* 0194: extui width 1 */
  a14 = 0x00000893u;  /* 0197: l32r = 2195 */
  a13 = (u32)(RODATA__rodata_wlog_warning_9 + 0x0);  /* 019a: l32r -> .rodata_wlog_warning.9 */
  ST32(a1 + 0x0, a2);  /* 019d */
  __asm__ volatile("" ::: "memory");  /* 019f: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 01a2: l32r -> global */
  a2 = wifi_log(a2, a3);  /* 01a5: callx a8 via reloc-expand */
  L_01a8: a2 = 0;  /* 01a8 */
  L_01aa: return a2;  /* 01aa: retw.n */
}


/* _mesh_remove_gone @ mesh_quick.o 00000008 size 88B bind GLOBAL
 * Calls: ieee80211_vnd_mesh_roots_set | Data refs: g_mesh_max_layer
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_remove_gone(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 000b: extui width 1 */
  a11 = a3;  /* 000e */
  a12 = a4;  /* 0010 */
  if (a2 != 6) goto L_005c;  /* 0012: bnei a2, 6, 5c <_mesh_remove_gone+0x54> */
  L_0015: if (a3 == 0) goto L_005c;  /* 0015: beqz a3, 5c <_mesh_remove_gone+0x54> */
  L_0018: if (a4 != 1) goto L_0039;  /* 0018: bnei a4, 1, 39 <_mesh_remove_gone+0x31> */
  L_001b: a8 = (u32)&g_mesh_max_layer + 0x0;  /* 001b: l32r -> global */
  a10 = 0;  /* 001e */
  a8 = LD16U(a8 + 0x0);  /* 0020 */
  a8 = a8 + (-1);  /* 0023 */
  ST8(a3 + 0x0, a8);  /* 0025 */
  a8 = (a8 >> 8) & 0x1ff;  /* 0028: extui width 9 */
  ST8(a3 + 0x1, a8);  /* 002b */
  __asm__ volatile("" ::: "memory");  /* 002e: memw */
  __asm__ volatile("" ::: "memory");  /* 0031: memw */
  goto L_0053;  /* 0034: j */
  L_0039: if (a4 == 0) goto L_005c;  /* 0039: beqz.n a4, 5c <_mesh_remove_gone+0x54> */
  L_003b: a8 = (u32)&g_mesh_max_layer + 0x0;  /* 003b: l32r -> global */
  a12 = 1;  /* 003e */
  a10 = 2;  /* 0040 */
  a8 = LD16U(a8 + 0x0);  /* 0042 */
  a8 = a8 + (-1);  /* 0045 */
  ST8(a3 + 0x0, a8);  /* 0047 */
  a8 = (a8 >> 8) & 0x1ff;  /* 004a: extui width 9 */
  ST8(a3 + 0x1, a8);  /* 004d */
  __asm__ volatile("" ::: "memory");  /* 0050: memw */
  L_0053: __asm__ volatile("" ::: "memory");  /* 0053: memw */
  a8 = (u32)&ieee80211_vnd_mesh_roots_set;  /* 0056: l32r -> func addr */
  a2 = ieee80211_vnd_mesh_roots_set(a2, a3, a4, a5, a6, a7);  /* 0059: callx a8 via reloc-expand */
  L_005c: a2 = 0;  /* 005c */
  return a2;  /* 005e: retw.n */
}


/* _mesh_reset_window_open_time @ mesh_quick.o 0000000c size 121B bind GLOBAL
 * Calls: none | indirect[2]: mem[a3+0x110]; mem[a2+0x110] | Data refs: .bss.wifi_vnd_ext_mesh_roots, .bss.s_mesh_roots_ie_life, g_osi_funcs_p
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=2 */
u32 _mesh_reset_window_open_time(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 000f: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a4 = (a2 >> 8) & 0x1;  /* 0012: extui width 1 */
  a5 = a4 + (a8 << 3);  /* 0015 */
  a3 = (a3 >> 8) & 0x1;  /* 0018: extui width 1 */
  a2 = -1;  /* 001b */
  a6 = LD32(a5 + 0x0);  /* 001d */
  if (((a6 >> 0) & 1) == 0) goto L_0080;  /* 001f: bbci a6, 0, 80 <_mesh_reset_window_open_time+0x74> */
  L_0022: a4 = a4 + (-2);  /* 0022 */
  a4 = (a4 >> 8) & 0x1;  /* 0025: extui width 1 */
  a5 = LD8U(a5 + 0x1);  /* 0028 */
  if (a5 >= 5u) goto L_0080;  /* 002b: bgeui a5, 5, 80 <_mesh_reset_window_open_time+0x74> */
  L_002e: a4 = a4 << 4;  /* 002e */
  a5 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 0031: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a6 = a5 + a4;  /* 0034 */
  a2 = LD32(a6 + 0x8);  /* 0036 */
  a9 = LD32(a6 + 0xc);  /* 0038 */
  a2 = a2 | a9;  /* 003a */
  if (a2 != 0) goto L_005a;  /* 003d: bnez.n a2, 5a <_mesh_reset_window_open_time+0x4e> */
  L_003f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 003f: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0042 */
  a10 = LD32(a3 + 0x110);  /* 0044 */
  /* 0047: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  ST32(a6 + 0x8, a10);  /* 004a */
  ST32(a6 + 0xc, a11);  /* 004c */
  ST8(a6 + 0x0, a2);  /* 004e */
  __asm__ volatile("" ::: "memory");  /* 0051: memw */
  __asm__ volatile("" ::: "memory");  /* 0054: memw */
  goto L_0080;  /* 0057: j */
  L_005a: if (a3 != 0) goto L_0065;  /* 005a: bnez.n a3, 65 <_mesh_reset_window_open_time+0x59> */
  L_005c: a6 = LD8U(a8 + 0x0);  /* 005c */
  a2 = a3;  /* 005f: mov */
  if (((a6 >> 0) & 1) == 0) goto L_0080;  /* 0062: bbci a6, 0, 80 <_mesh_reset_window_open_time+0x74> */
  L_0065: a5 = a5 + a4;  /* 0065 */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0067: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 006a */
  a10 = LD32(a2 + 0x110);  /* 006c */
  a2 = 0;  /* 006f */
  /* 0071: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  ST32(a5 + 0x8, a10);  /* 0074 */
  ST8(a5 + 0x0, a2);  /* 0076 */
  __asm__ volatile("" ::: "memory");  /* 0079: memw */
  a2 = 0;  /* 007c */
  ST32(a5 + 0xc, a11);  /* 007e */
  L_0080: __asm__ volatile("" ::: "memory");  /* 0080: memw */
  return a2;  /* 0083: retw.n */
}


/* _mesh_roots_num_reach_max @ mesh_quick.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_roots_num_reach_max(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0007: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = (a2 >> 8) & 0x1;  /* 000a: extui width 1 */
  a8 = a2 + (a8 << 3);  /* 000d */
  a2 = 1;  /* 0010 */
  a8 = LD8U(a8 + 0x1);  /* 0013 */
  if (a8 >= 5u) goto L_001c;  /* 0016: bgeui a8, 5, 1c <_mesh_roots_num_reach_max+0x18> */
  L_0019: a2 = 0;  /* 0019 */
  L_001c: a2 = (a2 >> 1) & 0x1;  /* 001c: extui width 1 */
  return a2;  /* 001f: retw.n */
}


/* _mesh_roots_process_announce @ mesh_quick.o 00000044 size 600B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, wifi_get_macaddr, memcmp, memset, _wifi_vnd_ext_mesh_roots_malloc, clone_is_zero_addr, memcpy, clone__wifi_vnd_ext_mesh_roots_free_part_0 | Data refs: .rodata, .bss.wifi_vnd_ext_mesh_roots, esp_mesh_appie, .text.is_zero_addr, .text._wifi_vnd_ext_mesh_roots_free$part$0
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=6, refs=9); reloc-direct=8, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_roots_process_announce(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a3, a4, a5, a6, a7, a8, a9;
  /* 0044: entry a1, 96 (frame 96 bytes) */
  a3 = -91;  /* 0047 */
  ST8(a1 + 0xc, a3);  /* 004a */
  __asm__ volatile("" ::: "memory");  /* 004d: memw */
  a2 = (a2 >> 8) & 0x1;  /* 0050: extui width 1 */
  a3 = (u32)(RODATA__rodata + 0x0);  /* 0053: l32r -> .rodata */
  a4 = LD8U(a3 + 0x0);  /* 0056 */
  a3 = LD8U(a3 + 0x1);  /* 0059 */
  ST8(a1 + 0x7, a3);  /* 005c */
  a3 = 0;  /* 005f */
  ST16(a1 + 0x8, a3);  /* 0061 */
  ST16(a1 + 0xa, a3);  /* 0064 */
  __asm__ volatile("" ::: "memory");  /* 0067: memw */
  a3 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 006a: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  ST8(a1 + 0x6, a4);  /* 006d */
  __asm__ volatile("" ::: "memory");  /* 0070: memw */
  a4 = LD8U(a3 + 0x1);  /* 0073 */
  a5 = LD32(a3 + 0xc);  /* 0076 */
  ST32(a1 + 0x10, a4);  /* 0078 */
  a4 = LD32(a3 + 0x1c);  /* 007a */
  a8 = LD32(a3 + 0x14);  /* 007c */
  ST32(a1 + 0x18, a5);  /* 007e */
  ST32(a1 + 0x20, a4);  /* 0080 */
  a4 = 0;  /* 0082 */
  a5 = LD32(a1 + 0x10);  /* 0084 */
  ST32(a1 + 0x1c, a8);  /* 0086 */
  ST32(a1 + 0x0, a4);  /* 0088 */
  ST16(a1 + 0x4, a4);  /* 008a */
  __asm__ volatile("" ::: "memory");  /* 008d: memw */
  a7 = LD32(a3 + 0x4);  /* 0090 */
  if (a5 != a4) goto L_0098;  /* 0092: bne a5, a4, 98 <_mesh_roots_process_announce+0x54> */
  L_0095: goto L_0295;  /* 0095: j */
  L_0098: if (a2 != 1) goto L_00ac;  /* 0098: bnei a2, 1, ac <_mesh_roots_process_announce+0x68> */
  L_009b: a6 = a4;  /* 009b */
  a2 = LD32(a3 + 0x8);  /* 009d */
  a3 = a4;  /* 009f */
  a2 = (a2 >> 1) & 0x1;  /* 00a1: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 00a4: memw */
  goto L_00db;  /* 00a7: j */
  L_00ac: if (a2 != 2) goto L_00b9;  /* 00ac: bnei a2, 2, b9 <_mesh_roots_process_announce+0x75> */
  L_00af: a6 = LD8U(a3 + 0x11);  /* 00af */
  a2 = a4;  /* 00b2 */
  a3 = a4;  /* 00b4 */
  goto L_00db;  /* 00b6: j */
  L_00b9: if (a2 != 3) goto L_00c4;  /* 00b9: bnei a2, 3, c4 <_mesh_roots_process_announce+0x80> */
  L_00bc: a3 = LD8U(a3 + 0x19);  /* 00bc */
  a2 = a4;  /* 00bf */
  goto L_00d9;  /* 00c1: j */
  L_00c4: if (a2 != 4) goto L_00d5;  /* 00c4: bnei a2, 4, d5 <_mesh_roots_process_announce+0x91> */
  L_00c7: a2 = LD32(a3 + 0x8);  /* 00c7 */
  a2 = (a2 >> 1) & 0x1;  /* 00c9: extui width 1 */
  a6 = LD8U(a3 + 0x11);  /* 00cc */
  a3 = LD8U(a3 + 0x19);  /* 00cf */
  goto L_00db;  /* 00d2: j */
  L_00d5: a2 = a4;  /* 00d5 */
  a3 = a4;  /* 00d7 */
  L_00d9: a6 = a2;  /* 00d9 */
  L_00db: a4 = (u32)&esp_mesh_appie + 0x0;  /* 00db: l32r -> global */
  a12 = a1 + (6);  /* 00de */
  a11 = 15;  /* 00e0 */
  a10 = LD32(a4 + 0x0);  /* 00e2 */
  a10 = a10 + (2);  /* 00e4 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00e6: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2);  /* 00e9: callx a8 via reloc-expand */
  a11 = a1;  /* 00ec */
  a10 = 1;  /* 00ee */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 00f0: l32r -> global */
  a2 = wifi_get_macaddr(a2);  /* 00f3: callx a8 via reloc-expand */
  a10 = LD32(a4 + 0x0);  /* 00f6 */
  a12 = a1 + (12);  /* 00f8 */
  a11 = 0;  /* 00fa */
  a10 = a10 + (2);  /* 00fd */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0100: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2);  /* 0103: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x10);  /* 0106 */
  a4 = a7 + (4);  /* 0108 */
  a5 = a8 + (-1);  /* 010a */
  a5 = (a5 >> 8) & 0x1;  /* 010c: extui width 1 */
  a5 = a5 + (a5 << 1);  /* 010f */
  a8 = a7 + (16);  /* 0112 */
  a8 = a5 + (a8 << 2);  /* 0115 */
  a5 = 0;  /* 0118 */
  ST32(a1 + 0x24, a8);  /* 011a */
  a7 = a4;  /* 011c */
  ST32(a1 + 0x14, a5);  /* 011e */
  L_0120: a9 = LD8U(a1 + 0xc);  /* 0120 */
  if (a9 == 1) goto L_0138;  /* 0123: beqi a9, 1, 138 <_mesh_roots_process_announce+0xf4> */
  L_0126: a12 = 6;  /* 0126 */
  a11 = a1;  /* 0128 */
  a10 = a7;  /* 012a */
  __asm__ volatile("" ::: "memory");  /* 012c: memw */
  a8 = (u32)&memcmp + 0x0;  /* 012f: l32r -> global */
  a2 = memcmp(a2);  /* 0132: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01c9;  /* 0135: beqz a10, 1c9 <_mesh_roots_process_announce+0x185> */
  L_0138: a12 = 6;  /* 0138 */
  a11 = a1 + a12;  /* 013a */
  a10 = a7;  /* 013c: mov */
  a8 = (u32)&memcmp + 0x0;  /* 013f: l32r -> global */
  a2 = memcmp(a2);  /* 0142: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01c9;  /* 0145: beqz a10, 1c9 <_mesh_roots_process_announce+0x185> */
  L_0148: if (a2 == 0) goto L_015c;  /* 0148: beqz.n a2, 15c <_mesh_roots_process_announce+0x118> */
  L_014a: a8 = LD32(a1 + 0x18);  /* 014a */
  a12 = 6;  /* 014c */
  a11 = a8 + (4);  /* 014e */
  a10 = a7;  /* 0150: mov */
  a8 = (u32)&memcmp + 0x0;  /* 0153: l32r -> global */
  a2 = memcmp(a2);  /* 0156: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01c9;  /* 0159: beqz a10, 1c9 <_mesh_roots_process_announce+0x185> */
  L_015c: a8 = LD32(a1 + 0x1c);  /* 015c */
  a9 = 0;  /* 015e */
  a13 = a8 + (4);  /* 0160 */
  a14 = 6;  /* 0162 */
  goto L_018c;  /* 0164: j */
  L_0168: a12 = a14;  /* 0168 */
  a11 = a13;  /* 016a */
  a10 = a7;  /* 016c */
  ST32(a1 + 0x30, a9);  /* 016e */
  ST32(a1 + 0x28, a13);  /* 0170 */
  ST32(a1 + 0x2c, a14);  /* 0172 */
  __asm__ volatile("" ::: "memory");  /* 0174: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0177: l32r -> global */
  a2 = memcmp(a2);  /* 017a: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x28);  /* 017d */
  a13 = a13 + (12);  /* 017f */
  a9 = LD32(a1 + 0x30);  /* 0181 */
  a14 = LD32(a1 + 0x2c);  /* 0183 */
  if (a10 == 0) goto L_0192;  /* 0185: beqz.n a10, 192 <_mesh_roots_process_announce+0x14e> */
  L_0187: a9 = a9 + (1);  /* 0187 */
  a9 = (a9 >> 8) & 0x1;  /* 0189: extui width 1 */
  L_018c: if (a9 != a6) goto L_0168;  /* 018c: bne a9, a6, 168 <_mesh_roots_process_announce+0x124> */
  L_018f: goto L_0194;  /* 018f: j */
  L_0192: a5 = 1;  /* 0192 */
  L_0194: a8 = LD32(a1 + 0x20);  /* 0194 */
  a9 = 0;  /* 0196 */
  a13 = a8 + (4);  /* 0198 */
  a14 = 6;  /* 019a */
  goto L_01c4;  /* 019c: j */
  L_01a0: a12 = a14;  /* 01a0 */
  a11 = a13;  /* 01a2 */
  a10 = a7;  /* 01a4 */
  ST32(a1 + 0x30, a9);  /* 01a6 */
  ST32(a1 + 0x28, a13);  /* 01a8 */
  ST32(a1 + 0x2c, a14);  /* 01aa */
  __asm__ volatile("" ::: "memory");  /* 01ac: memw */
  a8 = (u32)&memcmp + 0x0;  /* 01af: l32r -> global */
  a2 = memcmp(a2);  /* 01b2: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x28);  /* 01b5 */
  a13 = a13 + (12);  /* 01b7 */
  a9 = LD32(a1 + 0x30);  /* 01b9 */
  a14 = LD32(a1 + 0x2c);  /* 01bb */
  if (a10 == 0) goto L_01c9;  /* 01bd: beqz.n a10, 1c9 <_mesh_roots_process_announce+0x185> */
  L_01bf: a9 = a9 + (1);  /* 01bf */
  a9 = (a9 >> 8) & 0x1;  /* 01c1: extui width 1 */
  L_01c4: if (a9 != a3) goto L_01a0;  /* 01c4: bne a9, a3, 1a0 <_mesh_roots_process_announce+0x15c> */
  L_01c7: if (a5 == 0) goto L_01e4;  /* 01c7: beqz.n a5, 1e4 <_mesh_roots_process_announce+0x1a0> */
  L_01c9: a8 = LD32(a1 + 0x14);  /* 01c9 */
  a12 = 6;  /* 01cb */
  a5 = a8 + (1);  /* 01cd */
  a5 = (a5 >> 8) & 0x1;  /* 01cf: extui width 1 */
  a11 = 0;  /* 01d2 */
  a10 = a7;  /* 01d4 */
  ST32(a1 + 0x14, a5);  /* 01d6 */
  __asm__ volatile("" ::: "memory");  /* 01d9: memw */
  a8 = (u32)&memset + 0x0;  /* 01dc: l32r -> global */
  a2 = memset(a2);  /* 01df: callx a8 (libc, via reloc-expand) */
  a5 = 1;  /* 01e2 */
  L_01e4: a7 = a7 + (12);  /* 01e4 */
  a8 = LD32(a1 + 0x24);  /* 01e6 */
  if (a7 == a8) goto L_01ee;  /* 01e8: beq a7, a8, 1ee <_mesh_roots_process_announce+0x1aa> */
  L_01eb: goto L_0120;  /* 01eb: j */
  L_01ee: if (a5 == 0) goto L_0295;  /* 01ee: beqz a5, 295 <_mesh_roots_process_announce+0x251> */
  L_01f1: a3 = LD32(a1 + 0x10);  /* 01f1 */
  a5 = LD32(a1 + 0x14);  /* 01f3 */
  a2 = a3 - a5;  /* 01f5: sub */
  a2 = (a2 >> 8) & 0x1;  /* 01f8: extui width 1 */
  a10 = a2 + (a2 << 1);  /* 01fb */
  a10 = a10 << 2;  /* 01fe */
  a10 = (a10 >> 8) & 0x1;  /* 0201: extui width 1 */
  if (a10 == 0) goto L_0271;  /* 0204: beqz a10, 271 <_mesh_roots_process_announce+0x22d> */
  L_0207: a11 = a10;  /* 0207 */
  a10 = 0;  /* 0209 */
  a8 = (u32)&_wifi_vnd_ext_mesh_roots_malloc;  /* 020b: l32r -> func addr */
  a2 = _wifi_vnd_ext_mesh_roots_malloc(a2);  /* 020e: callx a8 via reloc-expand */
  a5 = a10;  /* 0211 */
  if (a10 == 0) goto L_0277;  /* 0213: beqz a10, 277 <_mesh_roots_process_announce+0x233> */
  L_0216: a3 = 0;  /* 0216 */
  a6 = a3;  /* 0218 */
  a7 = 12;  /* 021a */
  L_021c: a11 = a4 + (-4);  /* 021c */
  a10 = a4;  /* 021f */
  ST32(a1 + 0x28, a11);  /* 0221 */
  __asm__ volatile("" ::: "memory");  /* 0223: memw */
  a8 = 0;  /* 0226: l32r -> .text.is_zero_addr+0x0 (link-time addr, kind unclear) */
  a2 = clone_is_zero_addr(a2);  /* 0229: callx a8 -> clone .text.is_zero_addr */
  a11 = LD32(a1 + 0x28);  /* 022c */
  if (a10 != 0) goto L_024c;  /* 022e: bnez.n a10, 24c <_mesh_roots_process_announce+0x208> */
  L_0230: a9 = a3 + (1);  /* 0230 */
  a3 = a3 + (a3 << 1);  /* 0232 */
  a9 = (a9 >> 8) & 0x1;  /* 0235: extui width 1 */
  a10 = a3 + (a5 << 2);  /* 0238 */
  a12 = a7;  /* 023b */
  ST32(a1 + 0x30, a9);  /* 023d */
  __asm__ volatile("" ::: "memory");  /* 023f: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0242: l32r -> global */
  a2 = memcpy(a2, a3);  /* 0245: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x30);  /* 0248 */
  a3 = a9;  /* 024a */
  L_024c: a8 = a6 + (1);  /* 024c */
  a6 = (a8 >> 8) & 0x1;  /* 024e: extui width 1 */
  a8 = LD32(a1 + 0x10);  /* 0251 */
  a4 = a4 + (12);  /* 0253 */
  if (a8 != a6) goto L_021c;  /* 0255: bne a8, a6, 21c <_mesh_roots_process_announce+0x1d8> */
  L_0258: a10 = 0;  /* 0258 */
  a8 = 0;  /* 025a: l32r -> .text._wifi_vnd_ext_mesh_roots_free$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__wifi_vnd_ext_mesh_roots_free_part_0(a2);  /* 025d: callx a8 -> clone .text._wifi_vnd_ext_mesh_roots_free$part$0 (entry +c) */
  a3 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0260: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  ST32(a3 + 0x4, a5);  /* 0263 */
  ST8(a3 + 0x1, a2);  /* 0265 */
  __asm__ volatile("" ::: "memory");  /* 0268: memw */
  __asm__ volatile("" ::: "memory");  /* 026b: memw */
  goto L_0277;  /* 026e: j */
  L_0271: a8 = 0;  /* 0271: l32r -> .text._wifi_vnd_ext_mesh_roots_free$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__wifi_vnd_ext_mesh_roots_free_part_0(a2);  /* 0274: callx a8 -> clone .text._wifi_vnd_ext_mesh_roots_free$part$0 (entry +c) */
  L_0277: a3 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0277: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = 0;  /* 027a */
  a4 = 1;  /* 027c */
  a5 = LD8U(a3 + 0x1);  /* 027e */
  if (a5 == 0) a4 = a2;  /* 0281 */
  a5 = -2;  /* 0284 */
  a2 = LD8U(a3 + 0x0);  /* 0286 */
  a2 = a2 & a5;  /* 0289 */
  a2 = a2 | a4;  /* 028c */
  ST8(a3 + 0x0, a2);  /* 028f */
  __asm__ volatile("" ::: "memory");  /* 0292: memw */
  L_0295: a2 = 0;  /* 0295 */
  __asm__ volatile("" ::: "memory");  /* 0297: memw */
  return a2;  /* 029a: retw.n */
}


/* _mesh_roots_process_conflict_table @ mesh_quick.o 00000020 size 217B bind GLOBAL
 * Calls: memcmp, esp_mesh_remove_conflict_root | Data refs: .bss.s_mesh_conflict_roots, .bss.wifi_vnd_ext_mesh_roots, .rodata._mesh_roots_process_yield.str1.1
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=2, refs=5); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_roots_process_conflict_table(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a7, a8, a9;
  float F5;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  a3 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0023: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a2 = (a2 >> 8) & 0x1;  /* 0026: extui width 1 */
  a3 = LD32(a3 + 0x0);  /* 0029 */
  if (a3 == 0) goto L_00f5;  /* 002b: beqz a3, f5 <_mesh_roots_process_conflict_table+0xd5> */
  L_002e: a5 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 002e: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a4 = LD32(a5 + 0x14);  /* 0031 */
  a9 = LD32(a5 + 0x1c);  /* 0033 */
  ST32(a1 + 0x4, a4);  /* 0035 */
  ST32(a1 + 0x8, a9);  /* 0037 */
  if (a2 != 2) goto L_004a;  /* 0039: bnei a2, 2, 4a <_mesh_roots_process_conflict_table+0x2a> */
  L_003c: a4 = 0;  /* 003c */
  a5 = LD8U(a5 + 0x11);  /* 003e */
  ST32(a1 + 0x0, a5);  /* 0041 */
  __asm__ volatile("" ::: "memory");  /* 0043: memw */
  goto L_0054;  /* 0046: j */
  L_004a: a4 = 0;  /* 004a */
  ST32(a1 + 0x0, a4);  /* 004c */
  if (a2 != 3) goto L_0054;  /* 004e: bnei a2, 3, 54 <_mesh_roots_process_conflict_table+0x34> */
  L_0051: a4 = LD8U(a5 + 0x19);  /* 0051 */
  L_0054: a5 = a3 + (17);  /* 0054 */
  a7 = 0;  /* 0057 */
  __asm__ volatile("" ::: "memory");  /* 0059: memw */
  goto L_00e6;  /* 005c: j */
  L_0061: a10 = LD8U(a2 + 0x9);  /* 0061 */
  if (((a10 >> 0) & 1) == 0) goto L_008c;  /* 0064: bbci a10, 0, 8c <_mesh_roots_process_conflict_table+0x6c> */
  L_0067: a12 = 6;  /* 0067 */
  a11 = a6;  /* 0069 */
  a10 = a5;  /* 006b */
  ST32(a1 + 0xc, a8);  /* 006d */
  __asm__ volatile("" ::: "memory");  /* 006f: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0072: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 0075: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0xc);  /* 0078 */
  if (a10 != 0) goto L_008c;  /* 007a: bnez.n a10, 8c <_mesh_roots_process_conflict_table+0x6c> */
  L_007c: a11 = 0x5d4;  /* 007c */
  a10 = a5;  /* 007f */
  a12 = (u32)(RODATA__rodata__mesh_roots_process_yield_str1_1 + 0x0);  /* 0081: -> "recv fixed" */
  a8 = (u32)&esp_mesh_remove_conflict_root;  /* 0084: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2, a3, a4, a5, a6);  /* 0087: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0xc);  /* 008a */
  L_008c: a13 = a8 + (1);  /* 008c */
  a8 = (a13 >> 8) & 0x1;  /* 008e: extui width 1 */
  a6 = a6 + (12);  /* 0091 */
  L_0093: a9 = LD32(a1 + 0x0);  /* 0093 */
  if (a8 != a9) goto L_0061;  /* 0095: bne a8, a9, 61 <_mesh_roots_process_conflict_table+0x41> */
  L_0098: a6 = 0;  /* 0098 */
  a2 = LD32(a1 + 0x8);  /* 009a */
  a14 = a2 + (4);  /* 009c */
  a2 = a7 + (a7 << 1);  /* 009e */
  a2 = a2 + (a3 << 3);  /* 00a1 */
  goto L_00db;  /* 00a4: j */
  L_00a9: a10 = LD8U(a2 + 0x9);  /* 00a9 */
  if (((a10 >> 0) & 1) == 0) goto L_00d4;  /* 00ac: bbci a10, 0, d4 <_mesh_roots_process_conflict_table+0xb4> */
  L_00af: a11 = a14;  /* 00af */
  a12 = 6;  /* 00b1 */
  a10 = a5;  /* 00b3 */
  ST32(a1 + 0xc, a14);  /* 00b5 */
  __asm__ volatile("" ::: "memory");  /* 00b7: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00ba: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 00bd: callx a8 (libc, via reloc-expand) */
  a14 = LD32(a1 + 0xc);  /* 00c0 */
  if (a10 != 0) goto L_00d4;  /* 00c2: bnez.n a10, d4 <_mesh_roots_process_conflict_table+0xb4> */
  L_00c4: a11 = 0x5dc;  /* 00c4 */
  a10 = a5;  /* 00c7 */
  a12 = (u32)(RODATA__rodata__mesh_roots_process_yield_str1_1 + 0x0);  /* 00c9: -> "recv fixed" */
  a8 = (u32)&esp_mesh_remove_conflict_root;  /* 00cc: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2, a3, a4, a5, a6);  /* 00cf: callx a8 via reloc-expand */
  a14 = LD32(a1 + 0xc);  /* 00d2 */
  L_00d4: a13 = a6 + (1);  /* 00d4 */
  a6 = (a13 >> 8) & 0x1;  /* 00d6: extui width 1 */
  a14 = a14 + (12);  /* 00d9 */
  L_00db: if (a6 != a4) goto L_00a9;  /* 00db: bne a6, a4, a9 <_mesh_roots_process_conflict_table+0x89> */
  L_00de: a7 = a7 + (1);  /* 00de */
  a5 = a5 + (24);  /* 00e0 */
  if (a7 == 10) goto L_00f5;  /* 00e3: beqi a7, 10, f5 <_mesh_roots_process_conflict_table+0xd5> */
  L_00e6: a9 = LD32(a1 + 0x4);  /* 00e6 */
  a2 = a7 + (a7 << 1);  /* 00e8 */
  a6 = a9 + (4);  /* 00eb */
  a8 = 0;  /* 00ed */
  a2 = a2 + (a3 << 3);  /* 00ef */
  goto L_0093;  /* 00f2: j */
  L_00f5: a2 = 0;  /* 00f5 */
  return a2;  /* 00f7: retw.n */
}


/* _mesh_roots_process_fixed @ mesh_quick.o 00000004 size 21B bind GLOBAL
 * Calls: clone__mesh_roots_process_fixed_part_0 | Data refs: .text._mesh_roots_process_fixed$part$0
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_roots_process_fixed(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 0007: extui width 1 */
  a10 = a3;  /* 000a */
  if (a2 != 4) goto L_0015;  /* 000c: bnei a2, 4, 15 <_mesh_roots_process_fixed+0x11> */
  L_000f: a8 = 0;  /* 000f: l32r -> .text._mesh_roots_process_fixed$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__mesh_roots_process_fixed_part_0(a2, a3, a4, a5, a6, a7);  /* 0012: callx a8 -> clone .text._mesh_roots_process_fixed$part$0 (entry +c) */
  L_0015: a2 = 0;  /* 0015 */
  return a2;  /* 0017: retw.n */
}


/* _mesh_roots_process_gone @ mesh_quick.o 0000002c size 360B bind GLOBAL
 * Calls: memcmp, memset, _mesh_remove_gone, _wifi_vnd_ext_mesh_roots_malloc, clone_is_zero_addr, memcpy, clone__wifi_vnd_ext_mesh_roots_free_part_0 | Data refs: .bss.wifi_vnd_ext_mesh_roots, .text.is_zero_addr, .text._wifi_vnd_ext_mesh_roots_free$part$0
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=5, refs=6); reloc-direct=7, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_roots_process_gone(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a5, a6, a7, a8, a9;
  /* 002c: entry a1, 80 (frame 80 bytes) */
  a5 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 002f: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = (a2 >> 8) & 0x1;  /* 0032: extui width 1 */
  ST32(a1 + 0xc, a2);  /* 0035 */
  a2 = LD8U(a5 + 0x11);  /* 0037 */
  ST32(a1 + 0x0, a2);  /* 003a */
  a2 = LD32(a5 + 0x14);  /* 003c */
  a7 = LD8U(a5 + 0x19);  /* 003e */
  ST32(a1 + 0x10, a4);  /* 0041 */
  ST32(a1 + 0x4, a2);  /* 0043 */
  a8 = LD32(a5 + 0x1c);  /* 0045 */
  if (a7 == 0) goto L_018d;  /* 0047: beqz a7, 18d <_mesh_roots_process_gone+0x161> */
  L_004a: a2 = a7 + (-1);  /* 004a */
  a2 = (a2 >> 8) & 0x1;  /* 004c: extui width 1 */
  a6 = a8 + (4);  /* 004f */
  a2 = a2 + (a2 << 1);  /* 0051 */
  a8 = a8 + (16);  /* 0054 */
  a8 = a2 + (a8 << 2);  /* 0057 */
  ST32(a1 + 0x8, a8);  /* 005a */
  a8 = a3 + (4);  /* 005c */
  a4 = a6;  /* 005e */
  a2 = 0;  /* 0060 */
  ST32(a1 + 0x14, a8);  /* 0062 */
  L_0064: if (a3 != 0) goto L_0075;  /* 0064: bnez.n a3, 75 <_mesh_roots_process_gone+0x49> */
  L_0066: a9 = a3;  /* 0066 */
  a14 = 6;  /* 0068 */
  a8 = LD32(a1 + 0x4);  /* 006a */
  a13 = a8 + (4);  /* 006c */
  __asm__ volatile("" ::: "memory");  /* 006e: memw */
  goto L_00e0;  /* 0071: j */
  L_0075: a11 = LD32(a1 + 0x14);  /* 0075 */
  a12 = 6;  /* 0077 */
  a10 = a4;  /* 0079 */
  a8 = (u32)&memcmp + 0x0;  /* 007b: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 007e: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00e5;  /* 0081: bnez a10, e5 <_mesh_roots_process_gone+0xb9> */
  L_0084: a11 = a10;  /* 0084 */
  a12 = 6;  /* 0086 */
  a10 = a4;  /* 0088 */
  a8 = (u32)&memset + 0x0;  /* 008a: l32r -> global */
  a2 = memset(a2, a3, a4);  /* 008d: callx a8 (libc, via reloc-expand) */
  a12 = LD32(a1 + 0x10);  /* 0090 */
  a2 = a2 + (1);  /* 0092 */
  a11 = a3;  /* 0094 */
  a2 = (a2 >> 8) & 0x1;  /* 0096: extui width 1 */
  a10 = LD32(a1 + 0xc);  /* 0099 */
  a8 = (u32)&_mesh_remove_gone;  /* 009b: l32r -> func addr */
  a2 = _mesh_remove_gone(a2, a3, a4);  /* 009e: callx a8 via reloc-expand */
  goto L_00e5;  /* 00a1: j */
  L_00a4: a12 = a14;  /* 00a4 */
  a11 = a13;  /* 00a6 */
  a10 = a4;  /* 00a8 */
  ST32(a1 + 0x18, a9);  /* 00aa */
  ST32(a1 + 0x20, a13);  /* 00ac */
  ST32(a1 + 0x1c, a14);  /* 00ae */
  __asm__ volatile("" ::: "memory");  /* 00b0: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00b3: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 00b6: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x18);  /* 00b9 */
  a13 = LD32(a1 + 0x20);  /* 00bb */
  a14 = LD32(a1 + 0x1c);  /* 00bd */
  if (a10 != 0) goto L_00d9;  /* 00bf: bnez.n a10, d9 <_mesh_roots_process_gone+0xad> */
  L_00c1: a12 = a14;  /* 00c1 */
  a11 = a10;  /* 00c3 */
  a10 = a4;  /* 00c5 */
  a8 = (u32)&memset + 0x0;  /* 00c7: l32r -> global */
  a2 = memset(a2, a3, a4);  /* 00ca: callx a8 (libc, via reloc-expand) */
  a2 = a2 + (1);  /* 00cd */
  a14 = LD32(a1 + 0x1c);  /* 00cf */
  a2 = (a2 >> 8) & 0x1;  /* 00d1: extui width 1 */
  a13 = LD32(a1 + 0x20);  /* 00d4 */
  a9 = LD32(a1 + 0x18);  /* 00d6 */
  L_00d9: a9 = a9 + (1);  /* 00d9 */
  a9 = (a9 >> 8) & 0x1;  /* 00db: extui width 1 */
  a13 = a13 + (12);  /* 00de */
  L_00e0: a8 = LD32(a1 + 0x0);  /* 00e0 */
  if (a9 != a8) goto L_00a4;  /* 00e2: bne a9, a8, a4 <_mesh_roots_process_gone+0x78> */
  L_00e5: a4 = a4 + (12);  /* 00e5 */
  a8 = LD32(a1 + 0x8);  /* 00e7 */
  if (a4 == a8) goto L_00ef;  /* 00e9: beq a4, a8, ef <_mesh_roots_process_gone+0xc3> */
  L_00ec: goto L_0064;  /* 00ec: j */
  L_00ef: if (a2 == 0) goto L_018d;  /* 00ef: beqz a2, 18d <_mesh_roots_process_gone+0x161> */
  L_00f2: a2 = a7 - a2;  /* 00f2: sub */
  a2 = (a2 >> 8) & 0x1;  /* 00f5: extui width 1 */
  a11 = a2 + (a2 << 1);  /* 00f8 */
  a11 = a11 << 2;  /* 00fb */
  a11 = (a11 >> 8) & 0x1;  /* 00fe: extui width 1 */
  a10 = 3;  /* 0101 */
  if (a11 == 0) goto L_016c;  /* 0103: beqz a11, 16c <_mesh_roots_process_gone+0x140> */
  L_0106: a8 = (u32)&_wifi_vnd_ext_mesh_roots_malloc;  /* 0106: l32r -> func addr */
  a2 = _wifi_vnd_ext_mesh_roots_malloc(a2, a3, a4);  /* 0109: callx a8 via reloc-expand */
  a3 = a10;  /* 010c */
  if (a10 == 0) goto L_0172;  /* 010e: beqz a10, 172 <_mesh_roots_process_gone+0x146> */
  L_0111: a8 = 0;  /* 0111 */
  a4 = a8;  /* 0113 */
  L_0115: a11 = a6 + (-4);  /* 0115 */
  a10 = a6;  /* 0118 */
  ST32(a1 + 0x18, a8);  /* 011a */
  ST32(a1 + 0x1c, a11);  /* 011d */
  __asm__ volatile("" ::: "memory");  /* 011f: memw */
  a8 = 0;  /* 0122: l32r -> .text.is_zero_addr+0x0 (link-time addr, kind unclear) */
  a2 = clone_is_zero_addr(a2, a3, a4);  /* 0125: callx a8 -> clone .text.is_zero_addr */
  a8 = LD32(a1 + 0x18);  /* 0128 */
  a11 = LD32(a1 + 0x1c);  /* 012a */
  if (a10 != 0) goto L_014a;  /* 012c: bnez.n a10, 14a <_mesh_roots_process_gone+0x11e> */
  L_012e: a13 = a8 + (1);  /* 012e */
  a8 = a8 + (a8 << 1);  /* 0130 */
  a13 = (a13 >> 8) & 0x1;  /* 0133: extui width 1 */
  a10 = a8 + (a3 << 2);  /* 0136 */
  a12 = 12;  /* 0139 */
  ST32(a1 + 0x20, a13);  /* 013b */
  __asm__ volatile("" ::: "memory");  /* 013d: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0140: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 0143: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x20);  /* 0146 */
  a8 = a13;  /* 0148 */
  L_014a: a9 = a4 + (1);  /* 014a */
  a4 = (a9 >> 8) & 0x1;  /* 014c: extui width 1 */
  a6 = a6 + (12);  /* 014f */
  if (a7 != a4) goto L_0115;  /* 0151: bne a7, a4, 115 <_mesh_roots_process_gone+0xe9> */
  L_0154: a10 = 3;  /* 0154 */
  a8 = 0;  /* 0156: l32r -> .text._wifi_vnd_ext_mesh_roots_free$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__wifi_vnd_ext_mesh_roots_free_part_0(a2, a3, a4);  /* 0159: callx a8 -> clone .text._wifi_vnd_ext_mesh_roots_free$part$0 (entry +c) */
  ST32(a5 + 0x1c, a3);  /* 015c */
  ST8(a5 + 0x19, a2);  /* 015e */
  __asm__ volatile("" ::: "memory");  /* 0161: memw */
  __asm__ volatile("" ::: "memory");  /* 0164: memw */
  goto L_0172;  /* 0167: j */
  L_016c: a8 = 0;  /* 016c: l32r -> .text._wifi_vnd_ext_mesh_roots_free$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__wifi_vnd_ext_mesh_roots_free_part_0(a2, a3, a4);  /* 016f: callx a8 -> clone .text._wifi_vnd_ext_mesh_roots_free$part$0 (entry +c) */
  L_0172: a4 = LD8U(a5 + 0x19);  /* 0172 */
  a2 = 0;  /* 0175 */
  a3 = 1;  /* 0177 */
  if (a4 == 0) a3 = a2;  /* 0179 */
  a4 = -2;  /* 017c */
  a2 = LD8U(a5 + 0x18);  /* 017e */
  a2 = a2 & a4;  /* 0181 */
  a2 = a2 | a3;  /* 0184 */
  ST8(a5 + 0x18, a2);  /* 0187 */
  __asm__ volatile("" ::: "memory");  /* 018a: memw */
  L_018d: a2 = 0;  /* 018d */
  __asm__ volatile("" ::: "memory");  /* 018f: memw */
  return a2;  /* 0192: retw.n */
}


/* _mesh_roots_process_stop @ mesh_quick.o 00000038 size 280B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp, _mesh_reset_window_open_time, esp_mesh_remove_conflict_root, _mesh_roots_process_announce, _mesh_roots_process_gone, clone__mesh_roots_process_fixed_part_0, clone__wifi_vnd_ext_mesh_roots_free_part_0 | Data refs: .bss.wifi_vnd_ext_mesh_roots, esp_mesh_appie, .rodata._mesh_roots_process_stop.str1.1, .text._mesh_roots_process_fixed$part$0, .text._wifi_vnd_ext_mesh_roots_free$part$0
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=6, refs=9); reloc-direct=8, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_roots_process_stop(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a3, a4, a5, a6, a7, a8, a9;
  float F8;
  /* 0038: entry a1, 64 (frame 64 bytes) */
  a3 = 0x102;  /* 003b */
  if (a2 == 0) goto L_014c;  /* 003e: beqz a2, 14c <_mesh_roots_process_stop+0x114> */
  L_0041: a6 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0041: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a12 = a1;  /* 0044 */
  a11 = 0;  /* 0046 */
  a3 = LD8U(a6 + 0x1);  /* 0048 */
  ST32(a1 + 0x18, a3);  /* 004b */
  a3 = -91;  /* 004d */
  ST8(a1 + 0x0, a3);  /* 0050 */
  __asm__ volatile("" ::: "memory");  /* 0053: memw */
  a3 = (u32)&esp_mesh_appie + 0x0;  /* 0056: l32r -> global */
  a10 = LD32(a3 + 0x0);  /* 0059 */
  a10 = a10 + (2);  /* 005b */
  a5 = LD8U(a6 + 0x11);  /* 005d */
  a4 = LD8U(a6 + 0x19);  /* 0060 */
  ST32(a1 + 0x14, a5);  /* 0063 */
  a5 = 0;  /* 0065 */
  a7 = LD32(a6 + 0xc);  /* 0068 */
  __asm__ volatile("" ::: "memory");  /* 006b: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 006e: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 via reloc-expand */
  a3 = LD8U(a1 + 0x0);  /* 0074 */
  ST32(a1 + 0x10, a5);  /* 0077 */
  if (a3 != 1) goto L_00e9;  /* 0079: bnei a3, 1, e9 <_mesh_roots_process_stop+0xb1> */
  L_007c: a5 = LD8U(a6 + 0x8);  /* 007c */
  if (((a5 >> 0) & 1) == 0) goto L_00e9;  /* 007f: bbci a5, 0, e9 <_mesh_roots_process_stop+0xb1> */
  L_0082: a5 = a2 + (4);  /* 0082 */
  a12 = 6;  /* 0084 */
  a11 = a7 + (4);  /* 0086 */
  a10 = a5;  /* 0089: mov */
  __asm__ volatile("" ::: "memory");  /* 008c: memw */
  a8 = (u32)&memcmp + 0x0;  /* 008f: l32r -> global */
  a2 = memcmp(a2);  /* 0092: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_00a8;  /* 0095: beqz.n a10, a8 <_mesh_roots_process_stop+0x70> */
  L_0097: a12 = 6;  /* 0097 */
  a11 = a7 + (16);  /* 009a */
  a10 = a5;  /* 009d: mov */
  a8 = (u32)&memcmp + 0x0;  /* 00a0: l32r -> global */
  a2 = memcmp(a2);  /* 00a3: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00e9;  /* 00a6: bnez.n a10, e9 <_mesh_roots_process_stop+0xb1> */
  L_00a8: a7 = LD8U(a6 + 0x8);  /* 00a8 */
  a9 = -2;  /* 00ab */
  a7 = a7 & a9;  /* 00ae */
  a12 = 0x524;  /* 00b1 */
  a11 = 0;  /* 00b4 */
  ST8(a6 + 0x8, a7);  /* 00b6 */
  __asm__ volatile("" ::: "memory");  /* 00b9: memw */
  a10 = 2;  /* 00bc */
  __asm__ volatile("" ::: "memory");  /* 00bf: memw */
  a8 = (u32)&_mesh_reset_window_open_time;  /* 00c2: l32r -> func addr */
  a2 = _mesh_reset_window_open_time(a2);  /* 00c5: callx a8 via reloc-expand */
  a12 = 0x525;  /* 00c8 */
  a11 = 0;  /* 00cb */
  a10 = 3;  /* 00cd */
  a8 = (u32)&_mesh_reset_window_open_time;  /* 00cf: l32r -> func addr */
  a2 = _mesh_reset_window_open_time(a2);  /* 00d2: callx a8 via reloc-expand */
  a12 = (u32)(RODATA__rodata__mesh_roots_process_stop_str1_1 + 0x0);  /* 00d5: l32r -> .rodata._mesh_roots_process_stop.str1.1 */
  a11 = 0x527;  /* 00d8 */
  a10 = a5;  /* 00db */
  a6 = 1;  /* 00dd */
  a8 = (u32)&esp_mesh_remove_conflict_root;  /* 00e0: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2);  /* 00e3: callx a8 via reloc-expand */
  ST32(a1 + 0x10, a6);  /* 00e6 */
  L_00e9: a5 = LD32(a1 + 0x18);  /* 00e9 */
  if (a5 == 0) goto L_00f8;  /* 00eb: beqz.n a5, f8 <_mesh_roots_process_stop+0xc0> */
  L_00ed: a10 = 4;  /* 00ed */
  __asm__ volatile("" ::: "memory");  /* 00ef: memw */
  a8 = (u32)&_mesh_roots_process_announce;  /* 00f2: l32r -> func addr */
  a2 = _mesh_roots_process_announce(a2);  /* 00f5: callx a8 via reloc-expand */
  L_00f8: if (a4 == 0) goto L_0128;  /* 00f8: beqz.n a4, 128 <_mesh_roots_process_stop+0xf0> */
  L_00fa: if (a3 != 1) goto L_010c;  /* 00fa: bnei a3, 1, 10c <_mesh_roots_process_stop+0xd4> */
  L_00fd: a12 = 0;  /* 00fd */
  a11 = a12;  /* 00ff */
  a10 = 4;  /* 0101 */
  a8 = (u32)&_mesh_roots_process_gone;  /* 0103: l32r -> func addr */
  a2 = _mesh_roots_process_gone(a2);  /* 0106: callx a8 via reloc-expand */
  goto L_013d;  /* 0109: j */
  L_010c: a12 = 1;  /* 010c */
  a11 = a2;  /* 010e */
  a10 = 4;  /* 0110 */
  a8 = (u32)&_mesh_roots_process_gone;  /* 0112: l32r -> func addr */
  a2 = _mesh_roots_process_gone(a2);  /* 0115: callx a8 via reloc-expand */
  a6 = LD32(a1 + 0x14);  /* 0118 */
  if (a6 == 0) goto L_013d;  /* 011a: beqz.n a6, 13d <_mesh_roots_process_stop+0x105> */
  L_011c: a10 = a2 + (4);  /* 011c */
  a8 = 0;  /* 011e: l32r -> .text._mesh_roots_process_fixed$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__mesh_roots_process_fixed_part_0(a2);  /* 0121: callx a8 -> clone .text._mesh_roots_process_fixed$part$0 (entry +c) */
  goto L_013d;  /* 0124: j */
  L_0128: a3 = a3 + (-1);  /* 0128 */
  a5 = 1;  /* 012a */
  a6 = a4;  /* 012c */
  if (a3 != 0) a6 = a5;  /* 012e */
  a7 = a6;  /* 0131 */
  if (a6 == 0) goto L_013d;  /* 0133: beqz.n a6, 13d <_mesh_roots_process_stop+0x105> */
  L_0135: a3 = LD32(a1 + 0x14);  /* 0135 */
  if (a3 == 0) a5 = a4;  /* 0137 */
  if (a5 != 0) goto L_011c;  /* 013a: bnez a5, 11c <_mesh_roots_process_stop+0xe4> */
  L_013d: a3 = 0;  /* 013d */
  a5 = LD32(a1 + 0x10);  /* 013f */
  if (a5 == a3) goto L_014c;  /* 0141: beq a5, a3, 14c <_mesh_roots_process_stop+0x114> */
  L_0144: a10 = 1;  /* 0144 */
  a8 = 0;  /* 0146: l32r -> .text._wifi_vnd_ext_mesh_roots_free$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__wifi_vnd_ext_mesh_roots_free_part_0(a2);  /* 0149: callx a8 -> clone .text._wifi_vnd_ext_mesh_roots_free$part$0 (entry +c) */
  L_014c: a2 = a3;  /* 014c */
  return a2;  /* 014e: retw.n */
}


/* _mesh_roots_process_yield @ mesh_quick.o 00000034 size 300B bind GLOBAL
 * Calls: memcmp, _mesh_reset_window_open_time, esp_mesh_remove_conflict_root | Data refs: .bss.wifi_vnd_ext_mesh_roots, .rodata._mesh_roots_process_yield.str1.1
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=3, refs=5); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_roots_process_yield(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a3, a4, a5, a6, a7, a8, a9;
  float F0;
  /* 0034: entry a1, 48 (frame 48 bytes) */
  a3 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0037: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a4 = (a2 >> 8) & 0x1;  /* 003a: extui width 1 */
  a2 = LD8U(a3 + 0x8);  /* 003d */
  if (((a2 >> 0) & 1) != 0) goto L_0046;  /* 0040: bbsi a2, 0, 46 <_mesh_roots_process_yield+0x12> */
  L_0043: goto L_015c;  /* 0043: j */
  L_0046: a5 = LD32(a3 + 0xc);  /* 0046 */
  a7 = LD32(a3 + 0x14);  /* 0048 */
  a2 = LD32(a3 + 0x1c);  /* 004a */
  if (a4 != 2) goto L_005c;  /* 004c: bnei a4, 2, 5c <_mesh_roots_process_yield+0x28> */
  L_004f: a2 = a7 + (4);  /* 004f */
  a4 = 0;  /* 0051 */
  a7 = a5 + (4);  /* 0053 */
  a6 = LD8U(a3 + 0x11);  /* 0055 */
  goto L_00c9;  /* 0058: j */
  L_005c: if (a4 == 3) goto L_0062;  /* 005c: beqi a4, 3, 62 <_mesh_roots_process_yield+0x2e> */
  L_005f: goto L_015c;  /* 005f: j */
  L_0062: a4 = LD8U(a3 + 0x19);  /* 0062 */
  a2 = a2 + (4);  /* 0065 */
  a6 = a5 + (4);  /* 0067 */
  ST32(a1 + 0x0, a4);  /* 0069 */
  a4 = 0;  /* 006b */
  __asm__ volatile("" ::: "memory");  /* 006d: memw */
  goto L_0154;  /* 0070: j */
  L_0075: a12 = 6;  /* 0075 */
  a11 = a7;  /* 0077 */
  a10 = a2;  /* 0079 */
  a8 = (u32)&memcmp + 0x0;  /* 007b: l32r -> global */
  a2 = memcmp(a2);  /* 007e: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0094;  /* 0081: beqz.n a10, 94 <_mesh_roots_process_yield+0x60> */
  L_0083: a12 = 6;  /* 0083 */
  a11 = a5 + (16);  /* 0086 */
  a10 = a2;  /* 0089: mov */
  a8 = (u32)&memcmp + 0x0;  /* 008c: l32r -> global */
  a2 = memcmp(a2);  /* 008f: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00c2;  /* 0092: bnez.n a10, c2 <_mesh_roots_process_yield+0x8e> */
  L_0094: a8 = LD8U(a3 + 0x8);  /* 0094 */
  a9 = -2;  /* 0097 */
  a8 = a8 & a9;  /* 0099 */
  a12 = 0x58e;  /* 009c */
  a11 = 0;  /* 009f */
  ST8(a3 + 0x8, a8);  /* 00a2 */
  __asm__ volatile("" ::: "memory");  /* 00a5: memw */
  a10 = 2;  /* 00a8 */
  __asm__ volatile("" ::: "memory");  /* 00ab: memw */
  a8 = (u32)&_mesh_reset_window_open_time;  /* 00ae: l32r -> func addr */
  a2 = _mesh_reset_window_open_time(a2);  /* 00b1: callx a8 via reloc-expand */
  a11 = 0x58f;  /* 00b4 */
  a10 = a2;  /* 00b7 */
  a12 = (u32)(RODATA__rodata__mesh_roots_process_yield_str1_1 + 0x0);  /* 00b9: -> "recv fixed" */
  a8 = (u32)&esp_mesh_remove_conflict_root;  /* 00bc: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2);  /* 00bf: callx a8 via reloc-expand */
  L_00c2: a4 = a4 + (1);  /* 00c2 */
  a4 = (a4 >> 8) & 0x1;  /* 00c4: extui width 1 */
  a2 = a2 + (12);  /* 00c7 */
  L_00c9: if (a6 != a4) goto L_0075;  /* 00c9: bne a6, a4, 75 <_mesh_roots_process_yield+0x41> */
  L_00cc: goto L_015c;  /* 00cc: j */
  L_00cf: a12 = 6;  /* 00cf */
  a11 = a6;  /* 00d1 */
  a10 = a2;  /* 00d3: mov */
  a8 = (u32)&memcmp + 0x0;  /* 00d6: l32r -> global */
  a2 = memcmp(a2);  /* 00d9: callx a8 (libc, via reloc-expand) */
  a7 = a5 + (16);  /* 00dc */
  if (a10 == 0) goto L_00f0;  /* 00df: beqz.n a10, f0 <_mesh_roots_process_yield+0xbc> */
  L_00e1: a12 = 6;  /* 00e1 */
  a11 = a7;  /* 00e3 */
  a10 = a2;  /* 00e5 */
  a8 = (u32)&memcmp + 0x0;  /* 00e7: l32r -> global */
  a2 = memcmp(a2);  /* 00ea: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_014d;  /* 00ed: bnez a10, 14d <_mesh_roots_process_yield+0x119> */
  L_00f0: a8 = LD8U(a3 + 0x8);  /* 00f0 */
  a9 = -2;  /* 00f3 */
  a8 = a8 & a9;  /* 00f5 */
  a12 = 0x5ad;  /* 00f8 */
  a11 = 0;  /* 00fb */
  ST8(a3 + 0x8, a8);  /* 00fd */
  __asm__ volatile("" ::: "memory");  /* 0100: memw */
  a10 = 3;  /* 0103 */
  __asm__ volatile("" ::: "memory");  /* 0105: memw */
  a8 = (u32)&_mesh_reset_window_open_time;  /* 0108: l32r -> func addr */
  a2 = _mesh_reset_window_open_time(a2);  /* 010b: callx a8 via reloc-expand */
  a12 = 6;  /* 010e */
  a11 = a7;  /* 0110: mov */
  a10 = a2;  /* 0113: mov */
  a8 = (u32)&memcmp + 0x0;  /* 0116: l32r -> global */
  a2 = memcmp(a2);  /* 0119: callx a8 (libc, via reloc-expand) */
  a8 = (u32)(RODATA__rodata__mesh_roots_process_yield_str1_1 + 0x0);  /* 011c: -> "recv fixed" */
  a12 = a8;  /* 011f */
  if (a10 != 0) goto L_0141;  /* 0121: bnez.n a10, 141 <_mesh_roots_process_yield+0x10d> */
  L_0123: a11 = 0x5b3;  /* 0123 */
  a10 = a6;  /* 0126 */
  ST32(a1 + 0x4, a8);  /* 0128 */
  __asm__ volatile("" ::: "memory");  /* 012b: memw */
  a8 = (u32)&esp_mesh_remove_conflict_root;  /* 012e: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2);  /* 0131: callx a8 via reloc-expand */
  a11 = 0x5b4;  /* 0134 */
  a10 = a7;  /* 0137 */
  a8 = LD32(a1 + 0x4);  /* 0139 */
  a12 = a8;  /* 013b */
  goto L_0147;  /* 013d: j */
  L_0141: a11 = 0x5b6;  /* 0141 */
  a10 = a6;  /* 0144: mov */
  L_0147: a8 = (u32)&esp_mesh_remove_conflict_root;  /* 0147: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2);  /* 014a: callx a8 via reloc-expand */
  L_014d: a4 = a4 + (1);  /* 014d */
  a4 = (a4 >> 8) & 0x1;  /* 014f: extui width 1 */
  a2 = a2 + (12);  /* 0152 */
  L_0154: a8 = LD32(a1 + 0x0);  /* 0154 */
  if (a8 == a4) goto L_015c;  /* 0156: beq a8, a4, 15c <_mesh_roots_process_yield+0x128> */
  L_0159: goto L_00cf;  /* 0159: j */
  L_015c: a2 = 0;  /* 015c */
  return a2;  /* 015e: retw.n */
}


/* _mesh_set_flag_roots_found @ mesh_quick.o 00000020 size 190B bind GLOBAL
 * Calls: memset, ieee80211_mesh_quick_get, mesh_get_sub_ie, memcpy, wifi_mesh_event_post, ieee80211_mesh_quick_set | Data refs: esp_mesh_appie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=6, refs=7); reloc-direct=6, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_set_flag_roots_found(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0020: entry a1, 64 (frame 64 bytes) */
  a3 = 0;  /* 0023 */
  a12 = 20;  /* 0025 */
  a11 = 0;  /* 0028 */
  a10 = a1;  /* 002a: mov */
  ST8(a1 + 0x15, a3);  /* 002d */
  __asm__ volatile("" ::: "memory");  /* 0030: memw */
  __asm__ volatile("" ::: "memory");  /* 0033: memw */
  a8 = (u32)&memset + 0x0;  /* 0036: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0039: callx a8 (libc, via reloc-expand) */
  a12 = a1 + (21);  /* 003c */
  a11 = 14;  /* 003f */
  a2 = (a2 >> 8) & 0x1;  /* 0041: extui width 1 */
  a4 = (u32)&esp_mesh_appie + 0x0;  /* 0044: l32r -> global */
  a10 = LD32(a4 + 0x0);  /* 0047 */
  a10 = a10 + (2);  /* 0049 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 004b: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 004e: callx a8 via reloc-expand */
  a8 = (u32)&mesh_get_sub_ie;  /* 0051: l32r -> func addr */
  a2 = mesh_get_sub_ie(a2, a3, a4, a5, a6, a7);  /* 0054: callx a8 via reloc-expand */
  a8 = LD8U(a1 + 0x15);  /* 0057 */
  a3 = a10;  /* 005a */
  if (a2 == 0) goto L_006c;  /* 005c: beqz.n a2, 6c <_mesh_set_flag_roots_found+0x4c> */
  L_005e: if (((a8 >> 5) & 1) != 0) goto L_007e;  /* 005e: bbsi a8, 5, 7e <_mesh_set_flag_roots_found+0x5e> */
  L_0061: a2 = 32;  /* 0061 */
  a8 = LD8U(a10 + 0x5);  /* 0063 */
  a8 = a8 | a2;  /* 0066 */
  goto L_0078;  /* 0069: j */
  L_006c: if (((a8 >> 5) & 1) == 0) goto L_007e;  /* 006c: bbci a8, 5, 7e <_mesh_set_flag_roots_found+0x5e> */
  L_006f: a8 = LD8U(a10 + 0x5);  /* 006f */
  a2 = -33;  /* 0072 */
  a8 = a8 & a2;  /* 0075 */
  L_0078: ST8(a3 + 0x5, a8);  /* 0078 */
  __asm__ volatile("" ::: "memory");  /* 007b: memw */
  L_007e: a8 = LD8U(a3 + 0x5);  /* 007e */
  a2 = LD8U(a1 + 0x15);  /* 0081 */
  if (a8 == a2) goto L_00dc;  /* 0084: beq a8, a2, dc <_mesh_set_flag_roots_found+0xbc> */
  L_0087: a2 = 0;  /* 0087 */
  a12 = a1 + (20);  /* 0089 */
  a10 = LD32(a4 + 0x0);  /* 008c */
  a11 = 0;  /* 008e */
  a10 = a10 + (2);  /* 0090 */
  ST8(a1 + 0x14, a2);  /* 0092 */
  __asm__ volatile("" ::: "memory");  /* 0095: memw */
  __asm__ volatile("" ::: "memory");  /* 0098: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 009b: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 009e: callx a8 via reloc-expand */
  a8 = LD8U(a1 + 0x14);  /* 00a1 */
  if (a8 == 0) goto L_00ce;  /* 00a4: beqz.n a8, ce <_mesh_set_flag_roots_found+0xae> */
  L_00a6: a8 = 64;  /* 00a6 */
  a12 = 16;  /* 00a8 */
  a11 = a3;  /* 00aa */
  a10 = a1 + (4);  /* 00ac */
  ST32(a1 + 0x0, a8);  /* 00ae */
  __asm__ volatile("" ::: "memory");  /* 00b0: memw */
  a8 = (u32)&memcpy + 0x0;  /* 00b3: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00b6: callx a8 (libc, via reloc-expand) */
  a12 = 20;  /* 00b9 */
  a11 = a1;  /* 00bb */
  a10 = 54;  /* 00bd */
  ST8(a1 + 0x13, a2);  /* 00bf */
  __asm__ volatile("" ::: "memory");  /* 00c2: memw */
  __asm__ volatile("" ::: "memory");  /* 00c5: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 00c8: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 00cb: callx a8 via reloc-expand */
  L_00ce: a12 = a3 + (5);  /* 00ce */
  a11 = 14;  /* 00d0 */
  a10 = LD32(a4 + 0x0);  /* 00d2 */
  a10 = a10 + (2);  /* 00d4 */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 00d6: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5, a6, a7);  /* 00d9: callx a8 via reloc-expand */
  L_00dc: return a2;  /* 00dc: retw.n */
}


/* _mesh_timer_process_announce @ mesh_quick.o 00000038 size 261B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, wifi_get_macaddr, _mesh_check_roots_gone, memset, memcpy, wifi_mesh_event_post, memcmp, _mesh_roots_process_announce | Data refs: .bss.wifi_vnd_ext_mesh_roots, esp_mesh_appie, .rodata
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=8, refs=11); reloc-direct=8, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_timer_process_announce(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0038: entry a1, 80 (frame 80 bytes) */
  a5 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 003b: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a4 = -1;  /* 003e */
  a3 = LD8U(a5 + 0x0);  /* 0040 */
  if (((a3 >> 0) & 1) != 0) goto L_0049;  /* 0043: bbsi a3, 0, 49 <_mesh_timer_process_announce+0x11> */
  L_0046: goto L_0139;  /* 0046: j */
  L_0049: a3 = LD8U(a5 + 0x8);  /* 0049 */
  a3 = (a3 >> 1) & 0x1;  /* 004c: extui width 1 */
  if (a3 != 0) goto L_0139;  /* 004f: bnez a3, 139 <_mesh_timer_process_announce+0x101> */
  L_0052: a4 = -91;  /* 0052 */
  ST8(a1 + 0x18, a4);  /* 0055 */
  __asm__ volatile("" ::: "memory");  /* 0058: memw */
  a12 = a1 + (24);  /* 005b */
  a11 = a3;  /* 005e */
  a4 = (u32)&esp_mesh_appie + 0x0;  /* 0060: l32r -> global */
  a10 = LD32(a4 + 0x0);  /* 0063 */
  a10 = a10 + (2);  /* 0065 */
  __asm__ volatile("" ::: "memory");  /* 0067: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 006a: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 006d: callx a8 via reloc-expand */
  a11 = a1 + (18);  /* 0070 */
  a6 = (u32)(RODATA__rodata + 0x0);  /* 0073: l32r -> .rodata */
  a10 = 1;  /* 0076 */
  a7 = LD8U(a6 + 0x0);  /* 0078 */
  a6 = LD8U(a6 + 0x1);  /* 007b */
  ST8(a1 + 0x12, a7);  /* 007e */
  a7 = a3;  /* 0081 */
  ST8(a1 + 0x13, a6);  /* 0083 */
  ST16(a1 + 0x14, a3);  /* 0086 */
  ST16(a1 + 0x16, a3);  /* 0089 */
  __asm__ volatile("" ::: "memory");  /* 008c: memw */
  __asm__ volatile("" ::: "memory");  /* 008f: memw */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 0092: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6, a7);  /* 0095: callx a8 via reloc-expand */
  a12 = a1 + (12);  /* 0098 */
  a11 = 15;  /* 009a */
  a10 = LD32(a4 + 0x0);  /* 009c */
  a10 = a10 + (2);  /* 009e */
  ST32(a1 + 0xc, a3);  /* 00a0 */
  ST16(a1 + 0x10, a3);  /* 00a2 */
  __asm__ volatile("" ::: "memory");  /* 00a5: memw */
  __asm__ volatile("" ::: "memory");  /* 00a8: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00ab: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 00ae: callx a8 via reloc-expand */
  a6 = LD8U(a5 + 0x1);  /* 00b1 */
  a4 = LD32(a5 + 0x4);  /* 00b4 */
  goto L_0134;  /* 00b6: j */
  L_00b9: a8 = LD8U(a1 + 0x18);  /* 00b9 */
  a12 = a7;  /* 00bc */
  a11 = a2;  /* 00be */
  a10 = a4;  /* 00c0: mov */
  if (a8 != 1) goto L_00fc;  /* 00c3: bnei a8, 1, fc <_mesh_timer_process_announce+0xc4> */
  L_00c6: a8 = (u32)&_mesh_check_roots_gone;  /* 00c6: l32r -> func addr */
  a2 = _mesh_check_roots_gone(a2, a3, a4, a5, a6, a7);  /* 00c9: callx a8 via reloc-expand */
  if (a10 != 3) goto L_0130;  /* 00cc: bnei a10, 3, 130 <_mesh_timer_process_announce+0xf8> */
  L_00cf: a8 = LD8U(a5 + 0x11);  /* 00cf */
  if (a8 >= 5u) goto L_0130;  /* 00d2: bgeui a8, 5, 130 <_mesh_timer_process_announce+0xf8> */
  L_00d5: a11 = a7;  /* 00d5 */
  a12 = 12;  /* 00d7 */
  a10 = a1;  /* 00d9 */
  a8 = (u32)&memset + 0x0;  /* 00db: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00de: callx a8 (libc, via reloc-expand) */
  a11 = a4;  /* 00e1 */
  a12 = 12;  /* 00e3 */
  a10 = a1;  /* 00e5 */
  a8 = (u32)&memcpy + 0x0;  /* 00e7: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00ea: callx a8 (libc, via reloc-expand) */
  a12 = 12;  /* 00ed */
  a11 = a1;  /* 00ef */
  a10 = 57;  /* 00f1 */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 00f3: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 00f6: callx a8 via reloc-expand */
  goto L_0130;  /* 00f9: j */
  L_00fc: a8 = (u32)&_mesh_check_roots_gone;  /* 00fc: l32r -> func addr */
  a2 = _mesh_check_roots_gone(a2, a3, a4, a5, a6, a7);  /* 00ff: callx a8 via reloc-expand */
  a8 = a4 + (4);  /* 0102 */
  a11 = a8;  /* 0104 */
  a12 = 6;  /* 0106 */
  a10 = a1 + (12);  /* 0108 */
  ST32(a1 + 0x20, a8);  /* 010a */
  __asm__ volatile("" ::: "memory");  /* 010c: memw */
  a8 = (u32)&memcmp + 0x0;  /* 010f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0112: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x20);  /* 0115 */
  if (a10 == 0) goto L_0128;  /* 0117: beqz.n a10, 128 <_mesh_timer_process_announce+0xf0> */
  L_0119: a12 = 6;  /* 0119 */
  a11 = a8;  /* 011b */
  a10 = a1 + (18);  /* 011d */
  a8 = (u32)&memcmp + 0x0;  /* 0120: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0123: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0130;  /* 0126: bnez.n a10, 130 <_mesh_timer_process_announce+0xf8> */
  L_0128: a10 = a7;  /* 0128 */
  a8 = (u32)&_mesh_roots_process_announce;  /* 012a: l32r -> func addr */
  a2 = _mesh_roots_process_announce(a2, a3, a4, a5, a6, a7);  /* 012d: callx a8 via reloc-expand */
  L_0130: a3 = a3 + (1);  /* 0130 */
  a4 = a4 + (12);  /* 0132 */
  L_0134: if ((i32)a3 < (i32)a6) goto L_00b9;  /* 0134: blt a3, a6, b9 <_mesh_timer_process_announce+0x81> */
  L_0137: a4 = 0;  /* 0137 */
  L_0139: a2 = a4;  /* 0139 */
  return a2;  /* 013b: retw.n */
}


/* _mesh_timer_process_conflict_root @ mesh_quick.o 00000028 size 275B bind GLOBAL
 * Calls: _mesh_check_roots_gone | indirect[6]: mem[a3+0x110]; mem[a6+0x110]; mem[a8+0x158]; mem[a1+0x10] | Data refs: .bss.wifi_vnd_ext_mesh_roots, .bss.s_mesh_conflict_roots, g_osi_funcs_p, .bss.post_event_time$14, .rodata.mesh_parse_ps_entire_rule.str1.1, .rodata.esp_mesh_ps_duty_cycle_get_process.str1.1, .rodata._mesh_timer_process_conflict_root.str1.1
 * Fidelity: medium - 6 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=8); reloc-direct=1, funcdb-attributed=0, unknown-indirect=6 */
u32 _mesh_timer_process_conflict_root(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0028: entry a1, 64 (frame 64 bytes) */
  a4 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 002b: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a3 = LD8U(a4 + 0x0);  /* 002e */
  a4 = LD8U(a4 + 0x8);  /* 0031 */
  a3 = a3 | a4;  /* 0034 */
  if (((a3 >> 0) & 1) != 0) goto L_003d;  /* 0037: bbsi a3, 0, 3d <_mesh_timer_process_conflict_root+0x15> */
  L_003a: goto L_0134;  /* 003a: j */
  L_003d: a5 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 003d: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a3 = LD32(a5 + 0x0);  /* 0040 */
  if (a3 == 0) goto L_0134;  /* 0042: beqz a3, 134 <_mesh_timer_process_conflict_root+0x10c> */
  L_0045: a4 = 9;  /* 0045 */
  a3 = LD8U(a3 + 0x0);  /* 0048 */
  if (a4 < a3) goto L_0051;  /* 004b: bltu a4, a3, 51 <_mesh_timer_process_conflict_root+0x29> */
  L_004e: goto L_0134;  /* 004e: j */
  L_0051: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0051: l32r -> global */
  a3 = LD32(a4 + 0x0);  /* 0054 */
  a10 = LD32(a3 + 0x110);  /* 0056 */
  /* 0059: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  a3 = (u32)&LOCAL__bss_post_event_time_14 + 0x0;  /* 005c: l32r -> .bss.post_event_time$14 (same-object static) */
  a6 = LD32(a3 + 0x4);  /* 005f */
  if ((i32)a11 < (i32)a6) goto L_008e;  /* 0061: blt a11, a6, 8e <_mesh_timer_process_conflict_root+0x66> */
  L_0064: if (a6 != a11) goto L_006c;  /* 0064: bne a6, a11, 6c <_mesh_timer_process_conflict_root+0x44> */
  L_0067: a6 = LD32(a3 + 0x0);  /* 0067 */
  if (a10 < a6) goto L_008e;  /* 0069: bltu a10, a6, 8e <_mesh_timer_process_conflict_root+0x66> */
  L_006c: a6 = LD32(a4 + 0x0);  /* 006c */
  a10 = LD32(a6 + 0x110);  /* 006e */
  a6 = 1;  /* 0071 */
  /* 0073: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a3 + 0x0);  /* 0076 */
  a9 = a10 - a9;  /* 0078: sub */
  a7 = LD32(a3 + 0x4);  /* 007b */
  if (a10 < a9) goto L_0084;  /* 007e: bltu a10, a9, 84 <_mesh_timer_process_conflict_root+0x5c> */
  L_0081: a6 = 0;  /* 0081 */
  L_0084: a8 = a11 - a7;  /* 0084: sub */
  a8 = a8 - a6;  /* 0087: sub */
  goto L_00b7;  /* 008a: j */
  L_008e: a6 = LD32(a4 + 0x0);  /* 008e */
  a10 = LD32(a6 + 0x110);  /* 0090 */
  a6 = -1;  /* 0093 */
  /* 0095: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a3 + 0x0);  /* 0098 */
  a9 = a9 ^ a6;  /* 009a */
  a10 = a9 + a10;  /* 009d */
  a6 = 1;  /* 009f */
  a8 = LD32(a3 + 0x4);  /* 00a1 */
  if (a10 < a9) goto L_00a8;  /* 00a3: bltu a10, a9, a8 <_mesh_timer_process_conflict_root+0x80> */
  L_00a6: a6 = 0;  /* 00a6 */
  L_00a8: a11 = a8 + a11;  /* 00a8 */
  a9 = a10 + (1);  /* 00aa */
  a11 = a6 + a11;  /* 00ac */
  a8 = 1;  /* 00ae */
  if (a9 < a10) goto L_00b5;  /* 00b0: bltu a9, a10, b5 <_mesh_timer_process_conflict_root+0x8d> */
  L_00b3: a8 = 0;  /* 00b3 */
  L_00b5: a8 = a8 + a11;  /* 00b5 */
  L_00b7: a8 = a8 << 22;  /* 00b7 */
  a9 = a9 >> 10;  /* 00ba */
  a6 = 0x00001387u;  /* 00bd: l32r = 4999 */
  a8 = a8 | a9;  /* 00c0 */
  if (a6 >= a8) goto L_0134;  /* 00c3: bgeu a6, a8, 134 <_mesh_timer_process_conflict_root+0x10c> */
  L_00c6: a7 = LD32(a5 + 0x0);  /* 00c6 */
  a5 = 0;  /* 00c8 */
  a6 = a7 + (13);  /* 00ca */
  L_00cc: a8 = a5 + (a5 << 1);  /* 00cc */
  a8 = a8 + (a7 << 3);  /* 00cf */
  a8 = LD8U(a8 + 0x9);  /* 00d2 */
  if (((a8 >> 0) & 1) != 0) goto L_0111;  /* 00d5: bbsi a8, 0, 111 <_mesh_timer_process_conflict_root+0xe9> */
  L_00d8: a8 = LD32(a4 + 0x0);  /* 00d8 */
  if (a8 == 0) goto L_012c;  /* 00da: beqz a8, 12c <_mesh_timer_process_conflict_root+0x104> */
  L_00dd: a9 = LD32(a8 + 0x150);  /* 00dd */
  if (a9 == 0) goto L_012c;  /* 00e0: beqz a9, 12c <_mesh_timer_process_conflict_root+0x104> */
  L_00e3: a10 = LD32(a8 + 0x158);  /* 00e3 */
  ST32(a1 + 0x10, a9);  /* 00e6 */
  __asm__ volatile("" ::: "memory");  /* 00e8: memw */
  /* 00eb: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ee */
  a10 = 1;  /* 00f0 */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 00f2: -> "child(cidx:" */
  a14 = a11;  /* 00f5 */
  a8 = 0x0000094du;  /* 00f7: l32r = 2381 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 00fa: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata__mesh_timer_process_conflict_root_str1_1 + 0x0);  /* 00fd: l32r -> .rodata._mesh_timer_process_conflict_root.str1.1 */
  a9 = LD32(a1 + 0x10);  /* 0100 */
  ST32(a1 + 0x0, a8);  /* 0103 */
  __asm__ volatile("" ::: "memory");  /* 0106: memw */
  /* 0109: INDIRECT callx a9 <- mem[a1+0x10]; result unknown */ a2 = 0;
  goto L_012c;  /* 010c: j */
  L_0111: a12 = 5;  /* 0111 */
  a11 = a2;  /* 0113 */
  a10 = a6;  /* 0115 */
  a8 = (u32)&_mesh_check_roots_gone;  /* 0117: l32r -> func addr */
  a2 = _mesh_check_roots_gone(a2, a3, a4, a5, a6, a7);  /* 011a: callx a8 via reloc-expand */
  if (a10 != 1) goto L_012c;  /* 011d: bnei a10, 1, 12c <_mesh_timer_process_conflict_root+0x104> */
  L_0120: a8 = LD32(a4 + 0x0);  /* 0120 */
  a10 = LD32(a8 + 0x110);  /* 0122 */
  /* 0125: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  ST32(a3 + 0x0, a10);  /* 0128 */
  ST32(a3 + 0x4, a11);  /* 012a */
  L_012c: a5 = a5 + (1);  /* 012c */
  a6 = a6 + (24);  /* 012e */
  if (a5 != 10) goto L_00cc;  /* 0131: bnei a5, 10, cc <_mesh_timer_process_conflict_root+0xa4> */
  L_0134: a2 = 0;  /* 0134 */
  __asm__ volatile("" ::: "memory");  /* 0136: memw */
  return a2;  /* 0139: retw.n */
}


/* _mesh_timer_process_fixed @ mesh_quick.o 00000010 size 68B bind GLOBAL
 * Calls: _mesh_reset_window_open_time, _mesh_check_window_open_expire | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_timer_process_fixed(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a11 = a2;  /* 0013 */
  a2 = 0x102;  /* 0015 */
  if (a11 == 0) goto L_0052;  /* 0018: beqz.n a11, 52 <_mesh_timer_process_fixed+0x42> */
  L_001a: a9 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 001a: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = -1;  /* 001d */
  a10 = LD8U(a9 + 0x10);  /* 001f */
  if (((a10 >> 0) & 1) == 0) goto L_0052;  /* 0022: bbci a10, 0, 52 <_mesh_timer_process_fixed+0x42> */
  L_0025: a8 = LD8U(a9 + 0x11);  /* 0025 */
  if (a8 >= 5u) goto L_0048;  /* 0028: bgeui a8, 5, 48 <_mesh_timer_process_fixed+0x38> */
  L_002b: a8 = LD8U(a9 + 0x0);  /* 002b */
  a9 = LD8U(a9 + 0x8);  /* 002e */
  a8 = a8 | a9;  /* 0031 */
  if (((a8 >> 0) & 1) == 0) goto L_0048;  /* 0034: bbci a8, 0, 48 <_mesh_timer_process_fixed+0x38> */
  L_0037: a12 = 0x000008c9u;  /* 0037: l32r = 2249 */
  a11 = 1;  /* 003a */
  a10 = 2;  /* 003c */
  a8 = (u32)&_mesh_reset_window_open_time;  /* 003e: l32r -> func addr */
  a2 = _mesh_reset_window_open_time(a2, a3, a4, a5, a6, a7);  /* 0041: callx a8 via reloc-expand */
  goto L_0052;  /* 0044: j */
  L_0048: a10 = 2;  /* 0048 */
  a8 = (u32)&_mesh_check_window_open_expire;  /* 004a: l32r -> func addr */
  a2 = _mesh_check_window_open_expire(a2, a3, a4, a5, a6, a7);  /* 004d: callx a8 via reloc-expand */
  a2 = 0;  /* 0050 */
  L_0052: return a2;  /* 0052: retw.n */
}


/* _mesh_timer_process_gone @ mesh_quick.o 00000010 size 64B bind GLOBAL
 * Calls: _mesh_reset_window_open_time, _mesh_check_window_open_expire | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_timer_process_gone(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a11 = a2;  /* 0013 */
  a2 = 0x102;  /* 0015 */
  if (a11 == 0) goto L_004e;  /* 0018: beqz.n a11, 4e <_mesh_timer_process_gone+0x3e> */
  L_001a: a9 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 001a: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = -1;  /* 001d */
  a10 = LD8U(a9 + 0x18);  /* 001f */
  if (((a10 >> 0) & 1) == 0) goto L_004e;  /* 0022: bbci a10, 0, 4e <_mesh_timer_process_gone+0x3e> */
  L_0025: a8 = LD8U(a9 + 0x19);  /* 0025 */
  if (a8 >= 5u) goto L_0044;  /* 0028: bgeui a8, 5, 44 <_mesh_timer_process_gone+0x34> */
  L_002b: a8 = LD8U(a9 + 0x8);  /* 002b */
  if (((a8 >> 0) & 1) == 0) goto L_0044;  /* 002e: bbci a8, 0, 44 <_mesh_timer_process_gone+0x34> */
  L_0031: a12 = 0x000008d9u;  /* 0031: l32r = 2265 */
  a11 = 1;  /* 0034 */
  a10 = 3;  /* 0037 */
  a8 = (u32)&_mesh_reset_window_open_time;  /* 003a: l32r -> func addr */
  a2 = _mesh_reset_window_open_time(a2, a3, a4, a5, a6, a7);  /* 003d: callx a8 via reloc-expand */
  goto L_004e;  /* 0040: j */
  L_0044: a10 = 3;  /* 0044 */
  a8 = (u32)&_mesh_check_window_open_expire;  /* 0046: l32r -> func addr */
  a2 = _mesh_check_window_open_expire(a2, a3, a4, a5, a6, a7);  /* 0049: callx a8 via reloc-expand */
  a2 = 0;  /* 004c */
  L_004e: return a2;  /* 004e: retw.n */
}


/* _mesh_timer_process_yield @ mesh_quick.o 00000060 size 468B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp, _mesh_check_roots_gone, wifi_log, wifi_get_macaddr, mesh_is_new_found_conflict_root, esp_mesh_update_conflict_root, esp_mesh_remove_conflict_root | Data refs: .bss.wifi_vnd_ext_mesh_roots, esp_mesh_appie, .rodata, .rodata_wlog_warning.10, .rodata_wlog_warning.11, .rodata._mesh_timer_process_yield.str1.1
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=8, refs=14); reloc-direct=8, funcdb-attributed=0, unknown-indirect=0 */
u32 _mesh_timer_process_yield(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a3, a4, a5, a6, a7, a8, a9;
  /* 0060: entry a1, 96 (frame 96 bytes) */
  a7 = a2;  /* 0063 */
  a2 = 0x102;  /* 0065 */
  if (a7 == 0) goto L_0232;  /* 0068: beqz a7, 232 <_mesh_timer_process_yield+0x1d2> */
  L_006b: a3 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 006b: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = 0;  /* 006e */
  a4 = LD8U(a3 + 0x8);  /* 0070 */
  if (((a4 >> a2) & 1) != 0) goto L_0079;  /* 0073: bbs a4, a2, 79 <_mesh_timer_process_yield+0x19> */
  L_0076: goto L_0232;  /* 0076: j */
  L_0079: a5 = -91;  /* 0079 */
  a12 = a1 + (51);  /* 007c */
  ST8(a1 + 0x33, a5);  /* 007f */
  __asm__ volatile("" ::: "memory");  /* 0082: memw */
  a11 = a2;  /* 0085 */
  a5 = (u32)&esp_mesh_appie + 0x0;  /* 0087: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 008a */
  a6 = a6 + (2);  /* 008c */
  a10 = a6;  /* 008e: mov */
  a4 = LD8U(a3 + 0x9);  /* 0091 */
  a3 = LD32(a3 + 0xc);  /* 0094 */
  __asm__ volatile("" ::: "memory");  /* 0097: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 009a: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6);  /* 009d: callx a8 via reloc-expand */
  a12 = a1 + (38);  /* 00a0 */
  a11 = 15;  /* 00a3 */
  a10 = a6;  /* 00a5 */
  a8 = (u32)(RODATA__rodata + 0x0);  /* 00a7: l32r -> .rodata */
  a9 = LD8U(a8 + 0x0);  /* 00aa */
  a8 = LD8U(a8 + 0x1);  /* 00ad */
  ST8(a1 + 0x26, a9);  /* 00b0 */
  ST8(a1 + 0x27, a8);  /* 00b3 */
  ST16(a1 + 0x28, a2);  /* 00b6 */
  ST16(a1 + 0x2a, a2);  /* 00b9 */
  __asm__ volatile("" ::: "memory");  /* 00bc: memw */
  __asm__ volatile("" ::: "memory");  /* 00bf: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00c2: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2);  /* 00c5: callx a8 via reloc-expand */
  a12 = 6;  /* 00c8 */
  a11 = a3 + (4);  /* 00ca */
  a10 = a1 + (38);  /* 00cc */
  a8 = (u32)&memcmp + 0x0;  /* 00cf: l32r -> global */
  a2 = memcmp(a2);  /* 00d2: callx a8 (libc, via reloc-expand) */
  if (a10 == a2) goto L_0112;  /* 00d5: beq a10, a2, 112 <_mesh_timer_process_yield+0xb2> */
  L_00d8: a12 = 1;  /* 00d8 */
  a11 = a7;  /* 00da */
  a10 = a3;  /* 00dc */
  a8 = (u32)&_mesh_check_roots_gone;  /* 00de: l32r -> func addr */
  a2 = _mesh_check_roots_gone(a2);  /* 00e1: callx a8 via reloc-expand */
  if (a10 != 1) goto L_0112;  /* 00e4: bnei a10, 1, 112 <_mesh_timer_process_yield+0xb2> */
  L_00e7: a2 = LD8U(a3 + 0x9);  /* 00e7 */
  a14 = 0x47b;  /* 00ea */
  a14 = a14 + a14;  /* 00ed */
  a15 = LD8U(a3 + 0x4);  /* 00ef */
  ST32(a1 + 0x10, a2);  /* 00f2 */
  a2 = LD8U(a3 + 0x8);  /* 00f4 */
  ST32(a1 + 0xc, a2);  /* 00f7 */
  a2 = LD8U(a3 + 0x7);  /* 00f9 */
  ST32(a1 + 0x8, a2);  /* 00fc */
  a2 = LD8U(a3 + 0x6);  /* 00fe */
  ST32(a1 + 0x4, a2);  /* 0101 */
  a2 = LD8U(a3 + 0x5);  /* 0103 */
  a13 = (u32)(RODATA__rodata_wlog_warning_10 + 0x0);  /* 0106: l32r -> .rodata_wlog_warning.10 */
  ST32(a1 + 0x0, a2);  /* 0109 */
  __asm__ volatile("" ::: "memory");  /* 010b: memw */
  goto L_0159;  /* 010e: j */
  L_0112: a12 = 6;  /* 0112 */
  a11 = a3 + (16);  /* 0114 */
  a10 = a1 + (38);  /* 0117 */
  a2 = a3 + (12);  /* 011a */
  a8 = (u32)&memcmp + 0x0;  /* 011c: l32r -> global */
  a2 = memcmp(a2);  /* 011f: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_016b;  /* 0122: beqz a10, 16b <_mesh_timer_process_yield+0x10b> */
  L_0125: a12 = 1;  /* 0125 */
  a11 = a7;  /* 0127 */
  a10 = a2;  /* 0129 */
  a8 = (u32)&_mesh_check_roots_gone;  /* 012b: l32r -> func addr */
  a2 = _mesh_check_roots_gone(a2);  /* 012e: callx a8 via reloc-expand */
  if (a10 != 1) goto L_016b;  /* 0131: bnei a10, 1, 16b <_mesh_timer_process_yield+0x10b> */
  L_0134: a2 = LD8U(a3 + 0x15);  /* 0134 */
  a14 = 9;  /* 0137 */
  a14 = a14 << 8;  /* 0139 */
  a15 = LD8U(a3 + 0x10);  /* 013c */
  ST32(a1 + 0x10, a2);  /* 013f */
  a2 = LD8U(a3 + 0x14);  /* 0141 */
  ST32(a1 + 0xc, a2);  /* 0144 */
  a2 = LD8U(a3 + 0x13);  /* 0146 */
  ST32(a1 + 0x8, a2);  /* 0149 */
  a2 = LD8U(a3 + 0x12);  /* 014b */
  ST32(a1 + 0x4, a2);  /* 014e */
  a2 = LD8U(a3 + 0x11);  /* 0150 */
  a13 = (u32)(RODATA__rodata_wlog_warning_11 + 0x0);  /* 0153: -> "%d<timer-yield>forcer %02x:%02x:%02x:%02x:%02x:%02x is gone" */
  ST32(a1 + 0x0, a2);  /* 0156 */
  L_0159: a12 = 2;  /* 0159 */
  a11 = a10 << 21;  /* 015c */
  __asm__ volatile("" ::: "memory");  /* 015f: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0162: l32r -> global */
  a2 = wifi_log(a2);  /* 0165: callx a8 via reloc-expand */
  goto L_0230;  /* 0168: j */
  L_016b: a2 = -1;  /* 016b */
  ST32(a1 + 0x2c, a2);  /* 016d */
  a2 = 0;  /* 016f */
  a11 = a1 + (32);  /* 0171 */
  a10 = 1;  /* 0174 */
  a4 = a4 + (a4 << 1);  /* 0176 */
  ST8(a1 + 0x32, a2);  /* 0179 */
  a2 = 0;  /* 017c */
  a4 = a4 + (a3 << 2);  /* 017e */
  ST16(a1 + 0x30, a2);  /* 0181 */
  a2 = 0;  /* 0184 */
  ST32(a1 + 0x20, a2);  /* 0186 */
  ST16(a1 + 0x24, a2);  /* 0189 */
  __asm__ volatile("" ::: "memory");  /* 018c: memw */
  __asm__ volatile("" ::: "memory");  /* 018f: memw */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 0192: l32r -> global */
  a2 = wifi_get_macaddr(a2);  /* 0195: callx a8 via reloc-expand */
  goto L_022a;  /* 0198: j */
  L_019c: a12 = 6;  /* 019c */
  a11 = a3 + (4);  /* 019e */
  a10 = a1 + (32);  /* 01a0 */
  a8 = (u32)&memcmp + 0x0;  /* 01a3: l32r -> global */
  a2 = memcmp(a2);  /* 01a6: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0228;  /* 01a9: bnez a10, 228 <_mesh_timer_process_yield+0x1c8> */
  L_01ac: a2 = LD8U(a1 + 0x33);  /* 01ac */
  if (a2 != 1) goto L_0219;  /* 01af: bnei a2, 1, 219 <_mesh_timer_process_yield+0x1b9> */
  L_01b2: a11 = a1 + (44);  /* 01b2 */
  a10 = a3;  /* 01b5 */
  a6 = (u32)(RODATA__rodata__mesh_timer_process_yield_str1_1 + 0x0);  /* 01b7: -> "timer yield" */
  a13 = a6;  /* 01ba */
  a12 = 0x00000917u;  /* 01bc: l32r = 2327 */
  a8 = (u32)&mesh_is_new_found_conflict_root;  /* 01bf: l32r -> func addr */
  a2 = mesh_is_new_found_conflict_root(a2);  /* 01c2: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0228;  /* 01c5: bnez a10, 228 <_mesh_timer_process_yield+0x1c8> */
  L_01c8: a12 = a1 + (50);  /* 01c8 */
  a2 = LD32(a5 + 0x0);  /* 01cb */
  a11 = 12;  /* 01cd */
  a2 = a2 + (2);  /* 01cf */
  a10 = a2;  /* 01d1 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 01d3: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2);  /* 01d6: callx a8 via reloc-expand */
  a12 = a1 + (48);  /* 01d9 */
  a11 = 8;  /* 01dc */
  a10 = a2;  /* 01df: mov */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 01e2: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2);  /* 01e5: callx a8 via reloc-expand */
  a2 = LD8U(a1 + 0x32);  /* 01e8 */
  a13 = a6;  /* 01eb */
  a10 = a3;  /* 01ed */
  ST8(a3 + 0xa, a2);  /* 01ef */
  __asm__ volatile("" ::: "memory");  /* 01f2: memw */
  a2 = LD8U(a1 + 0x30);  /* 01f5 */
  ST8(a3 + 0x2, a2);  /* 01f8 */
  __asm__ volatile("" ::: "memory");  /* 01fb: memw */
  a2 = LD8U(a1 + 0x31);  /* 01fe */
  a12 = 0x0000091fu;  /* 0201: l32r = 2335 */
  a11 = LD32(a1 + 0x2c);  /* 0204 */
  ST8(a3 + 0x3, a2);  /* 0206 */
  __asm__ volatile("" ::: "memory");  /* 0209: memw */
  __asm__ volatile("" ::: "memory");  /* 020c: memw */
  a8 = (u32)&esp_mesh_update_conflict_root;  /* 020f: l32r -> func addr */
  a2 = esp_mesh_update_conflict_root(a2);  /* 0212: callx a8 via reloc-expand */
  goto L_0228;  /* 0215: j */
  L_0219: a12 = (u32)(RODATA__rodata__mesh_timer_process_yield_str1_1 + 0x0);  /* 0219: -> "timer yield" */
  a10 = a1 + (32);  /* 021c */
  a11 = 0x00000923u;  /* 021f: l32r = 2339 */
  a8 = (u32)&esp_mesh_remove_conflict_root;  /* 0222: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2);  /* 0225: callx a8 via reloc-expand */
  L_0228: a3 = a3 + (12);  /* 0228 */
  L_022a: if (a3 == a4) goto L_0230;  /* 022a: beq a3, a4, 230 <_mesh_timer_process_yield+0x1d0> */
  L_022d: goto L_019c;  /* 022d: j */
  L_0230: a2 = 0;  /* 0230 */
  L_0232: return a2;  /* 0232: retw.n */
}


/* _print_roots_count @ mesh_quick.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
void _print_roots_count(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  /* 0000: entry a1, 32 (frame 32 bytes) */
  return;  /* 0003: retw.n */
}


/* _wifi_vnd_ext_mesh_roots_free @ mesh_quick.o 00000004 size 17B bind GLOBAL
 * Calls: clone__wifi_vnd_ext_mesh_roots_free_part_0 | Data refs: .text._wifi_vnd_ext_mesh_roots_free$part$0
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 _wifi_vnd_ext_mesh_roots_free(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a10 = (a2 >> 8) & 0x1;  /* 0007: extui width 1 */
  if (a10 >= 4u) goto L_0013;  /* 000a: bgeui a10, 4, 13 <_wifi_vnd_ext_mesh_roots_free+0xf> */
  L_000d: a8 = 0;  /* 000d: l32r -> .text._wifi_vnd_ext_mesh_roots_free$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__wifi_vnd_ext_mesh_roots_free_part_0(a2, a3, a4, a5, a6, a7);  /* 0010: callx a8 -> clone .text._wifi_vnd_ext_mesh_roots_free$part$0 (entry +c) */
  L_0013: return a2;  /* 0013: retw.n */
}


/* _wifi_vnd_ext_mesh_roots_malloc @ mesh_quick.o 00000018 size 88B bind GLOBAL
 * Calls: mesh_malloc, roots_type2str, wifi_log | indirect[1]: mem[a8+0xb8] | Data refs: .rodata.__func__$15, g_osi_funcs_p, .rodata_wlog_error.2
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=6); reloc-direct=3, funcdb-attributed=0, unknown-indirect=1 */
u32 _wifi_vnd_ext_mesh_roots_malloc(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  a5 = (a2 >> 8) & 0x1;  /* 001b: extui width 1 */
  a4 = 1;  /* 001e */
  if (a3 == 0) goto L_006c;  /* 0020: beqz a3, 6c <_wifi_vnd_ext_mesh_roots_malloc+0x54> */
  L_0023: if (a5 >= 4u) goto L_006c;  /* 0023: bgeui a5, 4, 6c <_wifi_vnd_ext_mesh_roots_malloc+0x54> */
  L_0026: a11 = (u32)(RODATA__rodata___func___15 + 0x0);  /* 0026: -> "_wifi_vnd_ext_mesh_roots_malloc" */
  a12 = 0x3ad;  /* 0029 */
  a10 = a3;  /* 002c */
  a8 = (u32)&mesh_malloc + 0x0;  /* 002e: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0031: callx a8 via reloc-expand */
  a2 = a10;  /* 0034 */
  if (a10 != 0) goto L_006e;  /* 0036: bnez.n a10, 6e <_wifi_vnd_ext_mesh_roots_malloc+0x56> */
  L_0038: a10 = a5;  /* 0038 */
  a8 = (u32)&roots_type2str;  /* 003a: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4, a5, a6, a7);  /* 003d: callx a8 via reloc-expand */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0040: l32r -> global */
  a5 = a10;  /* 0043 */
  a8 = LD32(a8 + 0x0);  /* 0045 */
  a10 = LD32(a8 + 0xb8);  /* 0047 */
  /* 004a: INDIRECT callx a10 <- mem[a8+0xb8]; result unknown */ a2 = 0;
  a15 = a5;  /* 004d */
  a14 = 0x3b6;  /* 004f */
  a13 = (u32)(RODATA__rodata_wlog_error_2 + 0x0);  /* 0052: -> "%d<malloc>%s fail, size:%d, heap:%d" */
  a12 = a4;  /* 0055 */
  a11 = a4 << 13;  /* 0057 */
  ST32(a1 + 0x4, a10);  /* 005a */
  a10 = 3;  /* 005c */
  ST32(a1 + 0x0, a3);  /* 005e */
  __asm__ volatile("" ::: "memory");  /* 0060: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0063: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 0066: callx a8 via reloc-expand */
  goto L_006e;  /* 0069: j */
  L_006c: a2 = 0;  /* 006c */
  L_006e: return a2;  /* 006e: retw.n */
}


/* esp_mesh_add_conflict_root @ mesh_quick.o 00000030 size 418B bind GLOBAL
 * Calls: mesh_malloc, memset, memcpy | indirect[3]: mem[a2+0x158]; mem[a2+0x150]; mem[a7+0x110] | Data refs: .bss.s_mesh_conflict_roots, .rodata.__func__$6, g_osi_funcs_p, .rodata.mesh_parse_ps_entire_rule.str1.1, .rodata.esp_mesh_ps_duty_cycle_get_process.str1.1, .rodata.esp_mesh_add_conflict_root.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=9); reloc-direct=3, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_add_conflict_root(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0030: entry a1, 64 (frame 64 bytes) */
  a5 = 1;  /* 0033 */
  a4 = 0;  /* 0035 */
  if (a2 == 0) a4 = a5;  /* 0037 */
  a6 = (a4 >> 8) & 0x1;  /* 003a: extui width 1 */
  if (a4 != 0) goto L_009c;  /* 003d: bnez a4, 9c <esp_mesh_add_conflict_root+0x6c> */
  L_0040: a4 = a6;  /* 0040 */
  if (a3 == 0) a4 = a5;  /* 0042 */
  if (a4 == 0) goto L_004d;  /* 0045: beqz.n a4, 4d <esp_mesh_add_conflict_root+0x1d> */
  L_0047: goto L_009c;  /* 0047: j */
  L_004d: a4 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 004d: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a6 = LD32(a4 + 0x0);  /* 0050 */
  if (a6 != 0) goto L_01c0;  /* 0052: bnez a6, 1c0 <esp_mesh_add_conflict_root+0x190> */
  L_0055: a10 = 241;  /* 0055 */
  a12 = 0x000012cbu;  /* 0058: l32r = 4811 */
  a11 = (u32)(RODATA__rodata___func___6 + 0x0);  /* 005b: l32r -> .rodata.__func__$6 */
  a8 = (u32)&mesh_malloc + 0x0;  /* 005e: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0061: callx a8 via reloc-expand */
  ST32(a4 + 0x0, a10);  /* 0064 */
  if (a10 != 0) goto L_00a1;  /* 0066: bnez.n a10, a1 <esp_mesh_add_conflict_root+0x71> */
  L_0068: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0068: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 006b */
  if (a2 == 0) goto L_009c;  /* 006d: beqz.n a2, 9c <esp_mesh_add_conflict_root+0x6c> */
  L_006f: a3 = LD32(a2 + 0x150);  /* 006f */
  if (a3 == 0) goto L_009c;  /* 0072: beqz.n a3, 9c <esp_mesh_add_conflict_root+0x6c> */
  L_0074: a10 = LD32(a2 + 0x158);  /* 0074 */
  a2 = 241;  /* 0077 */
  __asm__ volatile("" ::: "memory");  /* 007a: memw */
  /* 007d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0080 */
  a10 = a5;  /* 0082 */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 0084: -> "child(cidx:" */
  a14 = a11;  /* 0087 */
  ST32(a1 + 0x4, a2);  /* 0089 */
  a2 = 0x000012cdu;  /* 008b: l32r = 4813 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 008e: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_add_conflict_root_str1_1 + 0x0);  /* 0091: l32r -> .rodata.esp_mesh_add_conflict_root.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0094 */
  __asm__ volatile("" ::: "memory");  /* 0096: memw */
  /* 0099: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_009c: a2 = -1;  /* 009c */
  goto L_01d0;  /* 009e: j */
  L_00a1: a12 = 241;  /* 00a1 */
  a11 = a6;  /* 00a4 */
  a8 = (u32)&memset + 0x0;  /* 00a6: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00a9: callx a8 (libc, via reloc-expand) */
  goto L_01c0;  /* 00ac: j */
  L_00b0: a4 = a5 + (a5 << 1);  /* 00b0 */
  a8 = a4 << 3;  /* 00b3 */
  a4 = a4 + (a6 << 3);  /* 00b6 */
  a7 = LD8U(a4 + 0x9);  /* 00b9 */
  a7 = (a7 >> 1) & 0x1;  /* 00bc: extui width 1 */
  if (a7 == 0) goto L_00ce;  /* 00bf: beqz.n a7, ce <esp_mesh_add_conflict_root+0x9e> */
  L_00c1: a5 = a5 + (1);  /* 00c1 */
  a9 = a9 + (-1);  /* 00c3 */
  if (a9 != 0) goto L_00b0;  /* 00c5: bnez a9, b0 <esp_mesh_add_conflict_root+0x80> */
  L_00c8: goto L_009c;  /* 00c8: j */
  L_00ce: a10 = a8 + (13);  /* 00ce */
  a11 = a7;  /* 00d0 */
  a12 = 12;  /* 00d2 */
  a10 = a6 + a10;  /* 00d4 */
  ST32(a1 + 0x10, a8);  /* 00d6 */
  __asm__ volatile("" ::: "memory");  /* 00d9: memw */
  a8 = (u32)&memset + 0x0;  /* 00dc: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00df: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 00e2 */
  a11 = a2 + (4);  /* 00e4 */
  a8 = LD32(a1 + 0x10);  /* 00e6 */
  a10 = a8 + (17);  /* 00e8 */
  a10 = a6 + a10;  /* 00eb */
  a8 = (u32)&memcpy + 0x0;  /* 00ee: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00f1: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a4 + 0x9);  /* 00f4 */
  a9 = 64;  /* 00f7 */
  a8 = (a8 >> 1) & 0x1;  /* 00f9: extui width 1 */
  a8 = a8 | a9;  /* 00fc */
  ST8(a4 + 0xb, a7);  /* 00ff */
  ST8(a4 + 0xc, a7);  /* 0102 */
  __asm__ volatile("" ::: "memory");  /* 0105: memw */
  a7 = (u32)&g_osi_funcs_p + 0x0;  /* 0108: l32r -> global */
  a7 = LD32(a7 + 0x0);  /* 010b */
  ST8(a4 + 0x9, a8);  /* 010d */
  __asm__ volatile("" ::: "memory");  /* 0110: memw */
  a8 = -100;  /* 0113 */
  a10 = LD32(a7 + 0x110);  /* 0116 */
  ST8(a4 + 0xa, a8);  /* 0119 */
  __asm__ volatile("" ::: "memory");  /* 011c: memw */
  __asm__ volatile("" ::: "memory");  /* 011f: memw */
  /* 0122: INDIRECT callx a10 <- mem[a7+0x110]; result unknown */ a2 = 0;
  a7 = (a10 >> 8) & 0x1ff;  /* 0125: extui width 9 */
  a8 = 1;  /* 0128 */
  ST8(a4 + 0x2, a7);  /* 012a */
  a7 = (a10 >> 8) & 0x1ffff;  /* 012d: extui width 17 */
  ST8(a4 + 0x3, a7);  /* 0130 */
  a7 = (a11 >> 8) & 0x1ff;  /* 0133: extui width 9 */
  ST8(a4 + 0x6, a7);  /* 0136 */
  a7 = (a11 >> 8) & 0x1ffff;  /* 0139: extui width 17 */
  ST8(a4 + 0x7, a7);  /* 013c */
  __asm__ volatile("" ::: "memory");  /* 013f: memw */
  a7 = LD8U(a4 + 0x9);  /* 0142 */
  a7 = a7 | a8;  /* 0145 */
  ST8(a4 + 0x1, a10);  /* 0148 */
  a10 = (a10 >> 8) & 0x1ffffff;  /* 014b: extui width 25 */
  ST8(a4 + 0x5, a11);  /* 014e */
  a11 = (a11 >> 8) & 0x1ffffff;  /* 0151: extui width 25 */
  ST8(a4 + 0x4, a10);  /* 0154 */
  ST8(a4 + 0x8, a11);  /* 0157 */
  ST8(a4 + 0x9, a7);  /* 015a */
  __asm__ volatile("" ::: "memory");  /* 015d: memw */
  a7 = LD8U(a6 + 0x0);  /* 0160 */
  a7 = a7 + (1);  /* 0163 */
  ST8(a6 + 0x0, a7);  /* 0165 */
  __asm__ volatile("" ::: "memory");  /* 0168: memw */
  a7 = LD8U(a2 + 0x0);  /* 016b */
  a6 = LD8U(a2 + 0x1);  /* 016e */
  a9 = LD8U(a4 + 0x17);  /* 0171 */
  ST8(a4 + 0xd, a7);  /* 0174 */
  ST8(a4 + 0xe, a6);  /* 0177 */
  __asm__ volatile("" ::: "memory");  /* 017a: memw */
  a8 = LD8U(a2 + 0xa);  /* 017d */
  if (a9 != 0) goto L_0188;  /* 0180: bnez.n a9, 188 <esp_mesh_add_conflict_root+0x158> */
  L_0182: __asm__ volatile("" ::: "memory");  /* 0182: memw */
  goto L_01a1;  /* 0185: j */
  L_0188: a9 = (i32)(a9 << (32 - 7)) >> (32 - 7);  /* 0188: sext */
  a6 = a9 + (a9 << 1);  /* 018b */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 018e: sext */
  a6 = a6 + (a9 << 2);  /* 0191 */
  a8 = a8 + (a8 << 1);  /* 0194 */
  a8 = a8 + a6;  /* 0197 */
  a9 = a8 + (15);  /* 0199 */
  if ((i32)a8 >= 0) a9 = a8;  /* 019b */
  a8 = (a9 >> 8) & 0x1f;  /* 019e: extui width 5 */
  L_01a1: ST8(a4 + 0x17, a8);  /* 01a1 */
  __asm__ volatile("" ::: "memory");  /* 01a4: memw */
  a6 = LD8U(a2 + 0x2);  /* 01a7 */
  a2 = LD8U(a2 + 0x3);  /* 01aa */
  ST8(a4 + 0xf, a6);  /* 01ad */
  ST8(a4 + 0x10, a2);  /* 01b0 */
  __asm__ volatile("" ::: "memory");  /* 01b3: memw */
  a2 = 0;  /* 01b6 */
  ST32(a3 + 0x0, a5);  /* 01b8 */
  __asm__ volatile("" ::: "memory");  /* 01ba: memw */
  goto L_01d0;  /* 01bd: j */
  L_01c0: a5 = -1;  /* 01c0 */
  ST32(a3 + 0x0, a5);  /* 01c2 */
  a9 = 10;  /* 01c4 */
  a5 = 0;  /* 01c6 */
  a6 = LD32(a4 + 0x0);  /* 01c8 */
  __asm__ volatile("" ::: "memory");  /* 01ca: memw */
  goto L_00b0;  /* 01cd: j */
  L_01d0: return a2;  /* 01d0: retw.n */
}


/* esp_mesh_check_vnd_ie @ mesh_quick.o 0000000c size 121B bind GLOBAL
 * Calls: is_my_ie_encrypted, crc32_le, esp_mesh_decrypt_vnd_ie | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=3); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_check_vnd_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a4 = 1;  /* 000f */
  a5 = 0;  /* 0011 */
  if (a2 == 0) a5 = a4;  /* 0013 */
  a8 = (a5 >> 8) & 0x1;  /* 0016: extui width 1 */
  if (a5 != 0) goto L_0080;  /* 0019: bnez a5, 80 <esp_mesh_check_vnd_ie+0x74> */
  L_001c: if (a3 != 0) a4 = a8;  /* 001c */
  if (a4 != 0) goto L_0080;  /* 001f: bnez a4, 80 <esp_mesh_check_vnd_ie+0x74> */
  L_0022: a4 = LD8U(a2 + 0x1);  /* 0022 */
  if (a4 >= 5u) goto L_002d;  /* 0025: bgeui a4, 5, 2d <esp_mesh_check_vnd_ie+0x21> */
  L_0028: a2 = -1;  /* 0028 */
  goto L_0083;  /* 002a: j */
  L_002d: a8 = (u32)&is_my_ie_encrypted;  /* 002d: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6, a7);  /* 0030: callx a8 via reloc-expand */
  a8 = LD8U(a2 + 0x6);  /* 0033 */
  a5 = (a8 >> 1) & 0x1;  /* 0036: extui width 1 */
  if (a5 != a10) goto L_0028;  /* 0039: bne a5, a10, 28 <esp_mesh_check_vnd_ie+0x1c> */
  L_003c: a11 = a4 + (-5);  /* 003c */
  if (a11 < 5u) goto L_0028;  /* 003f: bltui a11, 5, 28 <esp_mesh_check_vnd_ie+0x1c> */
  L_0042: a5 = a2 + (7);  /* 0042 */
  if (((a8 >> 0) & 1) != 0) goto L_006c;  /* 0045: bbsi a8, 0, 6c <esp_mesh_check_vnd_ie+0x60> */
  L_0048: a4 = a4 + (-9);  /* 0048 */
  a11 = a5;  /* 004b */
  a12 = a4;  /* 004d */
  a10 = -1;  /* 004f */
  a5 = a5 + a4;  /* 0051 */
  a8 = (u32)&crc32_le + 0x0;  /* 0053: l32r -> global */
  a2 = crc32_le(a2, a3, a4, a5, a6, a7);  /* 0056: callx a8 via reloc-expand */
  a2 = LD32(a5 + 0x0);  /* 0059 */
  a3 = 0;  /* 005b */
  a10 = a2 - a10;  /* 005d: sub */
  a2 = 1;  /* 0060 */
  if (a10 == 0) a2 = a3;  /* 0062 */
  a2 = -a2;  /* 0065 */
  goto L_0083;  /* 0068: j */
  L_006c: a10 = LD8U(a2 + 0x5);  /* 006c */
  a13 = a3;  /* 006f */
  a12 = a5;  /* 0071 */
  a8 = (u32)&esp_mesh_decrypt_vnd_ie;  /* 0073: l32r -> func addr */
  a2 = esp_mesh_decrypt_vnd_ie(a2, a3, a4, a5, a6, a7);  /* 0076: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0048;  /* 0079: beqz a10, 48 <esp_mesh_check_vnd_ie+0x3c> */
  L_007c: goto L_0028;  /* 007c: j */
  L_0080: a2 = 0x102;  /* 0080 */
  L_0083: return a2;  /* 0083: retw.n */
}


/* esp_mesh_decrypt_vnd_ie @ mesh_quick.o 00000014 size 118B bind GLOBAL
 * Calls: memset, mesh_coding_ie_key | indirect[1]: mem[a9+0x4] | Data refs: .bss.s_mesh_ie_crypto_funcs, .bss.iv, .bss.s_mesh_ie_crypto_key
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=5); reloc-direct=2, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_decrypt_vnd_ie(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a6, a7, a8, a9;
  /* 0014: entry a1, 48 (frame 48 bytes) */
  a6 = 1;  /* 0017 */
  a2 = 0;  /* 0019 */
  if (a4 == 0) a2 = a6;  /* 001b */
  a7 = (a2 >> 8) & 0x1;  /* 001e: extui width 1 */
  if (a2 != 0) goto L_0085;  /* 0021: bnez a2, 85 <esp_mesh_decrypt_vnd_ie+0x71> */
  L_0024: a2 = a7;  /* 0024 */
  if (a5 == 0) a2 = a6;  /* 0026 */
  if (a2 != 0) goto L_0085;  /* 0029: bnez a2, 85 <esp_mesh_decrypt_vnd_ie+0x71> */
  L_002c: a9 = (u32)&LOCAL__bss_s_mesh_ie_crypto_funcs + 0x0;  /* 002c: l32r -> .bss.s_mesh_ie_crypto_funcs (same-object static) */
  a2 = 0x102;  /* 002f */
  a7 = LD32(a9 + 0x4);  /* 0032 */
  if (a7 == 0) goto L_0088;  /* 0034: beqz a7, 88 <esp_mesh_decrypt_vnd_ie+0x74> */
  L_0037: a2 = -1;  /* 0037 */
  if ((i32)a3 < (i32)a6) goto L_0088;  /* 0039: blt a3, a6, 88 <esp_mesh_decrypt_vnd_ie+0x74> */
  L_003c: a7 = (a3 >> 4) & 0x1;  /* 003c: extui width 1 */
  if (a7 != 0) goto L_0088;  /* 003f: bnez a7, 88 <esp_mesh_decrypt_vnd_ie+0x74> */
  L_0042: a8 = (u32)&LOCAL__bss_iv + 0x0;  /* 0042: l32r -> .bss.iv (same-object static) */
  a12 = 16;  /* 0045 */
  a11 = a7;  /* 0047 */
  a10 = a8;  /* 0049 */
  ST32(a1 + 0x4, a9);  /* 004b */
  __asm__ volatile("" ::: "memory");  /* 004d: memw */
  a8 = (u32)&memset + 0x0;  /* 0050: l32r -> global */
  a2 = memset(a2, a3, a4, a5);  /* 0053: callx a8 (libc, via reloc-expand) */
  a8 = a10;  /* 0056 */
  a10 = a5;  /* 0058 */
  a2 = (u32)&LOCAL__bss_s_mesh_ie_crypto_key + 0x0;  /* 005a: l32r -> .bss.s_mesh_ie_crypto_key (same-object static) */
  a11 = a2;  /* 005d */
  ST32(a1 + 0x0, a8);  /* 005f */
  __asm__ volatile("" ::: "memory");  /* 0061: memw */
  a8 = (u32)&mesh_coding_ie_key;  /* 0064: l32r -> func addr */
  a2 = mesh_coding_ie_key(a2, a3, a4, a5);  /* 0067: callx a8 via reloc-expand */
  a10 = a2;  /* 006a */
  a13 = a3;  /* 006c */
  a12 = a4;  /* 006e */
  a9 = LD32(a1 + 0x4);  /* 0070 */
  a8 = LD32(a1 + 0x0);  /* 0072 */
  a11 = a8;  /* 0074 */
  a5 = LD32(a9 + 0x4);  /* 0076 */
  /* 0079: INDIRECT callx a5 <- mem[a9+0x4]; result unknown */ a2 = 0;
  if (a10 == 0) a6 = a7;  /* 007c */
  a2 = -a6;  /* 007f */
  goto L_0088;  /* 0082: j */
  L_0085: a2 = 0x102;  /* 0085 */
  L_0088: return a2;  /* 0088: retw.n */
}


/* esp_mesh_encrypt_vnd_ie @ mesh_quick.o 00000014 size 118B bind GLOBAL
 * Calls: memset, mesh_coding_ie_key | indirect[1]: mem[a9+0x0] | Data refs: .bss.s_mesh_ie_crypto_funcs, .bss.iv, .bss.s_mesh_ie_crypto_key
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=5); reloc-direct=2, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_encrypt_vnd_ie(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a6, a7, a8, a9;
  /* 0014: entry a1, 48 (frame 48 bytes) */
  a6 = 1;  /* 0017 */
  a2 = 0;  /* 0019 */
  if (a4 == 0) a2 = a6;  /* 001b */
  a7 = (a2 >> 8) & 0x1;  /* 001e: extui width 1 */
  if (a2 != 0) goto L_0085;  /* 0021: bnez a2, 85 <esp_mesh_encrypt_vnd_ie+0x71> */
  L_0024: a2 = a7;  /* 0024 */
  if (a5 == 0) a2 = a6;  /* 0026 */
  if (a2 != 0) goto L_0085;  /* 0029: bnez a2, 85 <esp_mesh_encrypt_vnd_ie+0x71> */
  L_002c: a9 = (u32)&LOCAL__bss_s_mesh_ie_crypto_funcs + 0x0;  /* 002c: l32r -> .bss.s_mesh_ie_crypto_funcs (same-object static) */
  a2 = 0x102;  /* 002f */
  a7 = LD32(a9 + 0x0);  /* 0032 */
  if (a7 == 0) goto L_0088;  /* 0034: beqz a7, 88 <esp_mesh_encrypt_vnd_ie+0x74> */
  L_0037: a2 = -1;  /* 0037 */
  if ((i32)a3 < (i32)a6) goto L_0088;  /* 0039: blt a3, a6, 88 <esp_mesh_encrypt_vnd_ie+0x74> */
  L_003c: a7 = (a3 >> 4) & 0x1;  /* 003c: extui width 1 */
  if (a7 != 0) goto L_0088;  /* 003f: bnez a7, 88 <esp_mesh_encrypt_vnd_ie+0x74> */
  L_0042: a8 = (u32)&LOCAL__bss_iv + 0x0;  /* 0042: l32r -> .bss.iv (same-object static) */
  a12 = 16;  /* 0045 */
  a11 = a7;  /* 0047 */
  a10 = a8;  /* 0049 */
  ST32(a1 + 0x4, a9);  /* 004b */
  __asm__ volatile("" ::: "memory");  /* 004d: memw */
  a8 = (u32)&memset + 0x0;  /* 0050: l32r -> global */
  a2 = memset(a2, a3, a4, a5);  /* 0053: callx a8 (libc, via reloc-expand) */
  a8 = a10;  /* 0056 */
  a10 = a5;  /* 0058 */
  a2 = (u32)&LOCAL__bss_s_mesh_ie_crypto_key + 0x0;  /* 005a: l32r -> .bss.s_mesh_ie_crypto_key (same-object static) */
  a11 = a2;  /* 005d */
  ST32(a1 + 0x0, a8);  /* 005f */
  __asm__ volatile("" ::: "memory");  /* 0061: memw */
  a8 = (u32)&mesh_coding_ie_key;  /* 0064: l32r -> func addr */
  a2 = mesh_coding_ie_key(a2, a3, a4, a5);  /* 0067: callx a8 via reloc-expand */
  a10 = a2;  /* 006a */
  a13 = a3;  /* 006c */
  a12 = a4;  /* 006e */
  a9 = LD32(a1 + 0x4);  /* 0070 */
  a8 = LD32(a1 + 0x0);  /* 0072 */
  a11 = a8;  /* 0074 */
  a5 = LD32(a9 + 0x0);  /* 0076 */
  /* 0079: INDIRECT callx a5 <- mem[a9+0x0]; result unknown */ a2 = 0;
  if (a10 == 0) a6 = a7;  /* 007c */
  a2 = -a6;  /* 007f */
  goto L_0088;  /* 0082: j */
  L_0085: a2 = 0x102;  /* 0085 */
  L_0088: return a2;  /* 0088: retw.n */
}


/* esp_mesh_find_conflict_root @ mesh_quick.o 00000008 size 64B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.s_mesh_conflict_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_find_conflict_root(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a5 = a2;  /* 000b */
  a2 = -1;  /* 000d */
  if (a5 == 0) goto L_0046;  /* 000f: beqz.n a5, 46 <esp_mesh_find_conflict_root+0x3e> */
  L_0011: a2 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0011: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a4 = LD32(a2 + 0x0);  /* 0014 */
  a2 = -1;  /* 0016 */
  if (a4 == 0) goto L_0046;  /* 0018: beqz.n a4, 46 <esp_mesh_find_conflict_root+0x3e> */
  L_001a: a3 = a4 + (17);  /* 001a */
  a2 = 0;  /* 001d */
  a6 = 6;  /* 001f */
  L_0021: a8 = a2 + (a2 << 1);  /* 0021 */
  a8 = a8 + (a4 << 3);  /* 0024 */
  a8 = LD8U(a8 + 0x9);  /* 0027 */
  if (((a8 >> 0) & 1) == 0) goto L_003c;  /* 002a: bbci a8, 0, 3c <esp_mesh_find_conflict_root+0x34> */
  L_002d: a12 = a6;  /* 002d */
  a11 = a5;  /* 002f */
  a10 = a3;  /* 0031: mov */
  a8 = (u32)&memcmp + 0x0;  /* 0034: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0037: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0046;  /* 003a: beqz.n a10, 46 <esp_mesh_find_conflict_root+0x3e> */
  L_003c: a2 = a2 + (1);  /* 003c */
  a3 = a3 + (24);  /* 003e */
  if (a2 != 10) goto L_0021;  /* 0041: bnei a2, 10, 21 <esp_mesh_find_conflict_root+0x19> */
  L_0044: a2 = -1;  /* 0044 */
  L_0046: return a2;  /* 0046: retw.n */
}


/* esp_mesh_get_conflict_root_state @ mesh_quick.o 0000000c size 624B bind GLOBAL
 * Calls: memcmp | indirect[3]: mem[a7+0x110]; mem[a8+0x110] | Data refs: .bss.s_mesh_conflict_roots, g_osi_funcs_p
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=3); reloc-direct=1, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_get_conflict_root_state(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a6, a7, a8, a9;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a4 = 1;  /* 000f */
  a6 = 0;  /* 0011 */
  if (a2 == 0) a6 = a4;  /* 0013 */
  ST32(a1 + 0x0, a3);  /* 0016 */
  a7 = (a6 >> 8) & 0x1;  /* 0018: extui width 1 */
  if (a6 != 0) goto L_0276;  /* 001b: bnez a6, 276 <esp_mesh_get_conflict_root_state+0x26a> */
  L_001e: if (a5 != 0) a4 = a7;  /* 001e */
  if (a4 != 0) goto L_0276;  /* 0021: bnez a4, 276 <esp_mesh_get_conflict_root_state+0x26a> */
  L_0024: a5 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0024: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a7 = 2;  /* 0027 */
  a3 = LD32(a5 + 0x0);  /* 0029 */
  if (a3 == 0) goto L_0278;  /* 002b: beqz a3, 278 <esp_mesh_get_conflict_root_state+0x26c> */
  L_002e: a7 = a3 + (17);  /* 002e */
  a5 = a4;  /* 0031 */
  a8 = a2 + (4);  /* 0033 */
  a13 = 6;  /* 0035 */
  L_0038: a4 = a5 + (a5 << 1);  /* 0038 */
  a4 = a4 + (a3 << 3);  /* 003b */
  a10 = LD8U(a4 + 0x9);  /* 003e */
  a6 = a5 + a5;  /* 0041 */
  if (((a10 >> 0) & 1) != 0) goto L_0049;  /* 0043: bbsi a10, 0, 49 <esp_mesh_get_conflict_root_state+0x3d> */
  L_0046: goto L_0250;  /* 0046: j */
  L_0049: a12 = a13;  /* 0049 */
  a11 = a8;  /* 004b */
  a10 = a7;  /* 004d */
  ST32(a1 + 0x4, a8);  /* 004f */
  ST32(a1 + 0x8, a13);  /* 0051 */
  __asm__ volatile("" ::: "memory");  /* 0053: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0056: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 0059: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x4);  /* 005c */
  a13 = LD32(a1 + 0x8);  /* 005e */
  if (a10 != 0) goto L_0250;  /* 0060: bnez a10, 250 <esp_mesh_get_conflict_root_state+0x244> */
  L_0063: a13 = (u32)&g_osi_funcs_p + 0x0;  /* 0063: l32r -> global */
  a7 = LD32(a13 + 0x0);  /* 0066 */
  a10 = LD32(a7 + 0x110);  /* 0068 */
  a7 = a4 + (1);  /* 006b */
  ST32(a1 + 0x8, a13);  /* 006d */
  __asm__ volatile("" ::: "memory");  /* 006f: memw */
  /* 0072: INDIRECT callx a10 <- mem[a7+0x110]; result unknown */ a2 = 0;
  a12 = LD8U(a4 + 0x2);  /* 0075 */
  a12 = a12 << 8;  /* 0078 */
  a8 = LD8U(a4 + 0x1);  /* 007b */
  a12 = a12 | a8;  /* 007e */
  a8 = LD8U(a4 + 0x3);  /* 0081 */
  a8 = a8 << 16;  /* 0084 */
  a8 = a8 | a12;  /* 0087 */
  a12 = LD8U(a4 + 0x4);  /* 008a */
  a12 = a12 << 24;  /* 008d */
  a12 = a12 | a8;  /* 0090 */
  a8 = LD8U(a4 + 0x6);  /* 0093 */
  a8 = a8 << 8;  /* 0096 */
  a14 = LD8U(a4 + 0x5);  /* 0099 */
  a8 = a8 | a14;  /* 009c */
  a14 = LD8U(a4 + 0x7);  /* 009f */
  a14 = a14 << 16;  /* 00a2 */
  a14 = a14 | a8;  /* 00a5 */
  a8 = LD8U(a4 + 0x8);  /* 00a8 */
  a8 = a8 << 24;  /* 00ab */
  a8 = a8 | a14;  /* 00ae */
  a13 = LD32(a1 + 0x8);  /* 00b1 */
  if ((i32)a11 < (i32)a8) goto L_0115;  /* 00b3: blt a11, a8, 115 <esp_mesh_get_conflict_root_state+0x109> */
  L_00b6: if (a8 != a11) goto L_00bc;  /* 00b6: bne a8, a11, bc <esp_mesh_get_conflict_root_state+0xb0> */
  L_00b9: if (a10 < a12) goto L_0115;  /* 00b9: bltu a10, a12, 115 <esp_mesh_get_conflict_root_state+0x109> */
  L_00bc: a8 = LD32(a13 + 0x0);  /* 00bc */
  a10 = LD32(a8 + 0x110);  /* 00be */
  /* 00c1: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = LD8U(a7 + 0x1);  /* 00c4 */
  a8 = a8 << 8;  /* 00c7 */
  a12 = LD8U(a4 + 0x1);  /* 00ca */
  a8 = a8 | a12;  /* 00cd */
  a12 = LD8U(a7 + 0x2);  /* 00d0 */
  a12 = a12 << 16;  /* 00d3 */
  a12 = a12 | a8;  /* 00d6 */
  a8 = LD8U(a7 + 0x3);  /* 00d9 */
  a8 = a8 << 24;  /* 00dc */
  a8 = a8 | a12;  /* 00df */
  a8 = a10 - a8;  /* 00e2: sub */
  a13 = LD8U(a7 + 0x5);  /* 00e5 */
  a13 = a13 << 8;  /* 00e8 */
  a12 = LD8U(a7 + 0x4);  /* 00eb */
  a13 = a13 | a12;  /* 00ee */
  a12 = LD8U(a7 + 0x6);  /* 00f1 */
  a12 = a12 << 16;  /* 00f4 */
  a12 = a12 | a13;  /* 00f7 */
  a7 = LD8U(a7 + 0x7);  /* 00fa */
  a7 = a7 << 24;  /* 00fd */
  a7 = a7 | a12;  /* 0100 */
  a12 = 1;  /* 0103 */
  if (a10 < a8) goto L_010c;  /* 0106: bltu a10, a8, 10c <esp_mesh_get_conflict_root_state+0x100> */
  L_0109: a12 = 0;  /* 0109 */
  L_010c: a11 = a11 - a7;  /* 010c: sub */
  a11 = a11 - a12;  /* 010f: sub */
  goto L_0177;  /* 0112: j */
  L_0115: a8 = LD32(a13 + 0x0);  /* 0115 */
  a10 = LD32(a8 + 0x110);  /* 0117 */
  /* 011a: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = LD8U(a7 + 0x1);  /* 011d */
  a8 = a8 << 8;  /* 0120 */
  a12 = LD8U(a4 + 0x1);  /* 0123 */
  a8 = a8 | a12;  /* 0126 */
  a12 = LD8U(a7 + 0x2);  /* 0129 */
  a12 = a12 << 16;  /* 012c */
  a12 = a12 | a8;  /* 012f */
  a8 = LD8U(a7 + 0x3);  /* 0132 */
  a8 = a8 << 24;  /* 0135 */
  a8 = a8 | a12;  /* 0138 */
  a13 = LD8U(a7 + 0x5);  /* 013b */
  a13 = a13 << 8;  /* 013e */
  a12 = LD8U(a7 + 0x4);  /* 0141 */
  a13 = a13 | a12;  /* 0144 */
  a12 = LD8U(a7 + 0x6);  /* 0147 */
  a12 = a12 << 16;  /* 014a */
  a12 = a12 | a13;  /* 014d */
  a7 = LD8U(a7 + 0x7);  /* 0150 */
  a7 = a7 << 24;  /* 0153 */
  a7 = a7 | a12;  /* 0156 */
  a12 = -1;  /* 0159 */
  a8 = a12 ^ a8;  /* 015b */
  a10 = a8 + a10;  /* 015e */
  a12 = 1;  /* 0160 */
  if (a10 < a8) goto L_0168;  /* 0162: bltu a10, a8, 168 <esp_mesh_get_conflict_root_state+0x15c> */
  L_0165: a12 = 0;  /* 0165 */
  L_0168: a7 = a7 + a11;  /* 0168 */
  a8 = a10 + (1);  /* 016a */
  a7 = a12 + a7;  /* 016c */
  a11 = 1;  /* 016e */
  if (a8 < a10) goto L_0175;  /* 0170: bltu a8, a10, 175 <esp_mesh_get_conflict_root_state+0x169> */
  L_0173: a11 = 0;  /* 0173 */
  L_0175: a11 = a11 + a7;  /* 0175 */
  L_0177: a7 = a11 << 22;  /* 0177 */
  a8 = a8 >> 10;  /* 017a */
  a8 = a7 | a8;  /* 017d */
  a7 = a6 + a5;  /* 0180 */
  a7 = a7 + (a3 << 3);  /* 0182 */
  a10 = LD8U(a7 + 0x9);  /* 0185 */
  a11 = (i32)a11 >> 10;  /* 0188 */
  a10 = a10 >> 1;  /* 018b */
  a12 = LD8U(a7 + 0xa);  /* 018e */
  a12 = a12 << 7;  /* 0191 */
  a12 = a12 | a10;  /* 0194 */
  a10 = LD8U(a7 + 0xb);  /* 0197 */
  a10 = a10 << 15;  /* 019a */
  a10 = a10 | a12;  /* 019d */
  a7 = LD8U(a7 + 0xc);  /* 01a0 */
  a7 = a7 << 23;  /* 01a3 */
  a7 = a7 | a10;  /* 01a6 */
  a10 = 0;  /* 01a9 */
  if ((i32)a11 < (i32)a10) goto L_01da;  /* 01ab: blt a11, a10, 1da <esp_mesh_get_conflict_root_state+0x1ce> */
  L_01ae: if (a10 != a11) goto L_01b4;  /* 01ae: bne a10, a11, 1b4 <esp_mesh_get_conflict_root_state+0x1a8> */
  L_01b1: if (a8 < a7) goto L_01da;  /* 01b1: bltu a8, a7, 1da <esp_mesh_get_conflict_root_state+0x1ce> */
  L_01b4: a6 = a6 + a5;  /* 01b4 */
  a6 = a6 + (a3 << 3);  /* 01b6 */
  a7 = LD8U(a6 + 0x9);  /* 01b9 */
  a8 = -2;  /* 01bc */
  a7 = a7 & a8;  /* 01be */
  ST8(a6 + 0x9, a7);  /* 01c1 */
  __asm__ volatile("" ::: "memory");  /* 01c4: memw */
  a7 = 1;  /* 01c7 */
  a6 = LD8U(a3 + 0x0);  /* 01c9 */
  a6 = a6 + (-1);  /* 01cc */
  ST8(a3 + 0x0, a6);  /* 01ce */
  __asm__ volatile("" ::: "memory");  /* 01d1: memw */
  __asm__ volatile("" ::: "memory");  /* 01d4: memw */
  goto L_01dc;  /* 01d7: j */
  L_01da: a7 = 0;  /* 01da */
  L_01dc: a8 = LD8U(a2 + 0xa);  /* 01dc */
  a6 = -127;  /* 01df */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 01e2: sext */
  if (a8 == a6) goto L_0262;  /* 01e5: beq a8, a6, 262 <esp_mesh_get_conflict_root_state+0x256> */
  L_01e8: a9 = LD8U(a2 + 0x1);  /* 01e8 */
  a9 = a9 << 8;  /* 01eb */
  a6 = LD8U(a4 + 0xe);  /* 01ee */
  a6 = a6 << 8;  /* 01f1 */
  a11 = LD8U(a2 + 0x0);  /* 01f4 */
  a9 = a9 | a11;  /* 01f7 */
  a10 = LD8U(a4 + 0xd);  /* 01fa */
  a6 = a6 | a10;  /* 01fd */
  if (a9 < a6) goto L_0262;  /* 0200: bltu a9, a6, 262 <esp_mesh_get_conflict_root_state+0x256> */
  L_0203: a9 = LD8U(a4 + 0x17);  /* 0203 */
  if (a9 == 0) goto L_0220;  /* 0206: beqz.n a9, 220 <esp_mesh_get_conflict_root_state+0x214> */
  L_0208: a10 = (i32)(a9 << (32 - 7)) >> (32 - 7);  /* 0208: sext */
  a6 = a10 + (a10 << 1);  /* 020b */
  a8 = a8 + (a8 << 1);  /* 020e */
  a6 = a6 + (a10 << 2);  /* 0211 */
  a6 = a6 + a8;  /* 0214 */
  a8 = a6 + (15);  /* 0217 */
  if ((i32)a6 >= 0) a8 = a6;  /* 021a */
  a8 = (i32)a8 >> 4;  /* 021d */
  L_0220: a6 = LD8U(a2 + 0x3);  /* 0220 */
  a6 = a6 << 8;  /* 0223 */
  a10 = LD8U(a2 + 0x2);  /* 0226 */
  a6 = a6 | a10;  /* 0229 */
  a2 = LD8U(a4 + 0x10);  /* 022c */
  a2 = a2 << 8;  /* 022f */
  a10 = LD8U(a4 + 0xf);  /* 0232 */
  a2 = a2 | a10;  /* 0235 */
  a4 = a6 - a2;  /* 0238: sub */
  a4 = ((i32)a4 < 0) ? -(i32)a4 : a4;  /* 023b */
  if ((i32)a4 >= 2) goto L_0260;  /* 023e: bgei a4, 2, 260 <esp_mesh_get_conflict_root_state+0x254> */
  L_0241: a9 = (i32)(a9 << (32 - 7)) >> (32 - 7);  /* 0241: sext */
  a8 = a8 - a9;  /* 0244: sub */
  a8 = ((i32)a8 < 0) ? -(i32)a8 : a8;  /* 0247 */
  if ((i32)a8 < 2) goto L_0262;  /* 024a: blti a8, 2, 262 <esp_mesh_get_conflict_root_state+0x256> */
  L_024d: goto L_0260;  /* 024d: j */
  L_0250: a5 = a5 + (1);  /* 0250 */
  a7 = a7 + (24);  /* 0252 */
  if (a5 == 10) goto L_025b;  /* 0255: beqi a5, 10, 25b <esp_mesh_get_conflict_root_state+0x24f> */
  L_0258: goto L_0038;  /* 0258: j */
  L_025b: a7 = 2;  /* 025b */
  goto L_0262;  /* 025d: j */
  L_0260: a7 = 3;  /* 0260 */
  L_0262: a2 = LD32(a1 + 0x0);  /* 0262 */
  if (a2 == 0) goto L_0278;  /* 0264: beqz.n a2, 278 <esp_mesh_get_conflict_root_state+0x26c> */
  L_0266: a2 = 9;  /* 0266 */
  if ((i32)a2 < (i32)a5) goto L_0278;  /* 0268: blt a2, a5, 278 <esp_mesh_get_conflict_root_state+0x26c> */
  L_026b: a2 = LD32(a1 + 0x0);  /* 026b */
  ST32(a2 + 0x0, a5);  /* 026d */
  __asm__ volatile("" ::: "memory");  /* 026f: memw */
  goto L_0278;  /* 0272: j */
  L_0276: a7 = 2;  /* 0276 */
  L_0278: a2 = a7;  /* 0278 */
  return a2;  /* 027a: retw.n */
}


/* esp_mesh_get_vnd_ext_assoc_len @ mesh_quick.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_vnd_ext_assoc_len(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2;
  /* 0000: entry a1, 32 (frame 32 bytes) */
  a2 = 23;  /* 0003 */
  return a2;  /* 0005: retw.n */
}


/* esp_mesh_get_vnd_roots_len @ mesh_quick.o 00000084 size 576B bind GLOBAL
 * Calls: esp_mesh_is_root_conflicts_allowed, memset, mesh_get_vnd_roots_len, _mesh_check_window_close_expire, wifi_log, wifi_mesh_event_post, _mesh_set_flag_roots_found, mesh_free, clone__wifi_vnd_ext_mesh_roots_free_part_0, esp_mesh_map_change_beacon_interval, _mesh_timer_process_announce, _mesh_timer_process_yield, _mesh_timer_process_fixed, _mesh_timer_process_gone, _mesh_timer_process_conflict_root | indirect[5]: mem[a6+0x110]; mem[a8+0x110]; mem[a3+0x110] | Data refs: .bss.is_roots_found$13, .bss.s_mesh_conflict_roots, g_osi_funcs_p, .bss.roots_found_time$12, .bss.max_ie_len$11, .rodata_wlog_warning.17, .rodata.__func__$9, .text._wifi_vnd_ext_mesh_roots_free$part$0, .rodata_wlog_warning.18, .bss.s_mesh_roots_ie_life, .bss.wifi_vnd_ext_mesh_roots, .rodata_wlog_warning.19
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=14, refs=25); reloc-direct=15, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_get_vnd_roots_len(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F6;
  /* 0084: entry a1, 96 (frame 96 bytes) */
  a4 = (a2 >> 8) & 0x1;  /* 0087: extui width 1 */
  a8 = (u32)&esp_mesh_is_root_conflicts_allowed + 0x0;  /* 008a: l32r -> global */
  a2 = esp_mesh_is_root_conflicts_allowed(a2, a3, a4, a5, a6, a7);  /* 008d: callx a8 via reloc-expand */
  a2 = 0;  /* 0090 */
  a3 = a10;  /* 0092 */
  if (a10 == a2) goto L_009a;  /* 0094: beq a10, a2, 9a <esp_mesh_get_vnd_roots_len+0x16> */
  L_0097: goto L_02c2;  /* 0097: j */
  L_009a: a11 = a2;  /* 009a: mov */
  a12 = 12;  /* 009d */
  a10 = a1 + (48);  /* 009f */
  a8 = (u32)&memset + 0x0;  /* 00a2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00a5: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&mesh_get_vnd_roots_len;  /* 00a8: l32r -> func addr */
  a2 = mesh_get_vnd_roots_len(a2, a3, a4, a5, a6, a7);  /* 00ab: callx a8 via reloc-expand */
  a2 = a10;  /* 00ae */
  a11 = a10;  /* 00b0: mov */
  ST32(a1 + 0x3c, a10);  /* 00b3 */
  a10 = a3;  /* 00b6: mov */
  __asm__ volatile("" ::: "memory");  /* 00b9: memw */
  a8 = (u32)&_mesh_check_window_close_expire;  /* 00bc: l32r -> func addr */
  a2 = _mesh_check_window_close_expire(a2, a3, a4, a5, a6, a7);  /* 00bf: callx a8 via reloc-expand */
  a11 = a2;  /* 00c2 */
  a10 = 1;  /* 00c4 */
  a8 = (u32)&_mesh_check_window_close_expire;  /* 00c6: l32r -> func addr */
  a2 = _mesh_check_window_close_expire(a2, a3, a4, a5, a6, a7);  /* 00c9: callx a8 via reloc-expand */
  if (a2 != 0) goto L_01c9;  /* 00cc: bnez a2, 1c9 <esp_mesh_get_vnd_roots_len+0x145> */
  L_00cf: a5 = (u32)&LOCAL__bss_is_roots_found_13 + 0x0;  /* 00cf: l32r -> .bss.is_roots_found$13 (same-object static) */
  a3 = LD8U(a5 + 0x0);  /* 00d2 */
  a4 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 00d5: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  if (a3 == 0) goto L_01a4;  /* 00d8: beqz a3, 1a4 <esp_mesh_get_vnd_roots_len+0x120> */
  L_00db: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00db: l32r -> global */
  a6 = LD32(a3 + 0x0);  /* 00de */
  a10 = LD32(a6 + 0x110);  /* 00e0 */
  /* 00e3: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a6 = (u32)&LOCAL__bss_roots_found_time_12 + 0x0;  /* 00e6: l32r -> .bss.roots_found_time$12 (same-object static) */
  a8 = LD32(a6 + 0x4);  /* 00e9 */
  if ((i32)a11 < (i32)a8) goto L_0116;  /* 00eb: blt a11, a8, 116 <esp_mesh_get_vnd_roots_len+0x92> */
  L_00ee: if (a8 != a11) goto L_00f6;  /* 00ee: bne a8, a11, f6 <esp_mesh_get_vnd_roots_len+0x72> */
  L_00f1: a8 = LD32(a6 + 0x0);  /* 00f1 */
  if (a10 < a8) goto L_0116;  /* 00f3: bltu a10, a8, 116 <esp_mesh_get_vnd_roots_len+0x92> */
  L_00f6: a8 = LD32(a3 + 0x0);  /* 00f6 */
  a10 = LD32(a8 + 0x110);  /* 00f8 */
  /* 00fb: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a9 = 1;  /* 00fe */
  a8 = LD32(a6 + 0x0);  /* 0100 */
  a12 = LD32(a6 + 0x4);  /* 0102 */
  a6 = a10 - a8;  /* 0104: sub */
  if (a10 < a6) goto L_010c;  /* 0107: bltu a10, a6, 10c <esp_mesh_get_vnd_roots_len+0x88> */
  L_010a: a9 = 0;  /* 010a */
  L_010c: a8 = a11 - a12;  /* 010c: sub */
  a8 = a8 - a9;  /* 010f: sub */
  goto L_013f;  /* 0112: j */
  L_0116: a8 = LD32(a3 + 0x0);  /* 0116 */
  a10 = LD32(a8 + 0x110);  /* 0118 */
  /* 011b: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a9 = -1;  /* 011e */
  a8 = LD32(a6 + 0x0);  /* 0120 */
  a8 = a8 ^ a9;  /* 0122 */
  a10 = a8 + a10;  /* 0125 */
  a9 = 1;  /* 0127 */
  a6 = LD32(a6 + 0x4);  /* 0129 */
  if (a10 < a8) goto L_0130;  /* 012b: bltu a10, a8, 130 <esp_mesh_get_vnd_roots_len+0xac> */
  L_012e: a9 = 0;  /* 012e */
  L_0130: a11 = a6 + a11;  /* 0130 */
  a6 = a10 + (1);  /* 0132 */
  a11 = a9 + a11;  /* 0134 */
  a8 = 1;  /* 0136 */
  if (a6 < a10) goto L_013d;  /* 0138: bltu a6, a10, 13d <esp_mesh_get_vnd_roots_len+0xb9> */
  L_013b: a8 = 0;  /* 013b */
  L_013d: a8 = a8 + a11;  /* 013d */
  L_013f: a6 = (a6 >> 12) & 0x1fffff;  /* 013f: extui width 21 */
  a8 = a8 << 12;  /* 0142 */
  a8 = a8 | a6;  /* 0145 */
  a9 = LD32(a4 + 0x0);  /* 0148 */
  a6 = (u32)&LOCAL__bss_max_ie_len_11 + 0x0;  /* 014a: l32r -> .bss.max_ie_len$11 (same-object static) */
  ST32(a1 + 0x30, a8);  /* 014d */
  a8 = a2;  /* 014f */
  a10 = LD32(a6 + 0x0);  /* 0151 */
  if (a9 == 0) goto L_0158;  /* 0153: beqz.n a9, 158 <esp_mesh_get_vnd_roots_len+0xd4> */
  L_0155: a8 = LD8U(a9 + 0x0);  /* 0155 */
  L_0158: a14 = 0x137;  /* 0158 */
  a11 = 1;  /* 015b */
  a15 = 0;  /* 015d */
  a14 = a14 << 3;  /* 015f */
  a13 = (u32)(RODATA__rodata_wlog_warning_17 + 0x0);  /* 0162: l32r -> .rodata_wlog_warning.17 */
  a12 = 2;  /* 0165 */
  a11 = a11 << 21;  /* 0167 */
  ST32(a1 + 0x4, a8);  /* 016a */
  ST32(a1 + 0x0, a10);  /* 016c */
  a10 = 1;  /* 016e */
  __asm__ volatile("" ::: "memory");  /* 0170: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0173: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 0176: callx a8 via reloc-expand */
  a12 = 12;  /* 0179 */
  a11 = a1 + (48);  /* 017b */
  a10 = 60;  /* 017e */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 0180: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 0183: callx a8 via reloc-expand */
  a10 = 0;  /* 0186 */
  a8 = 0;  /* 0188 */
  ST32(a6 + 0x0, a10);  /* 018b */
  ST8(a5 + 0x0, a8);  /* 018d */
  __asm__ volatile("" ::: "memory");  /* 0190: memw */
  __asm__ volatile("" ::: "memory");  /* 0193: memw */
  a8 = (u32)&_mesh_set_flag_roots_found;  /* 0196: l32r -> func addr */
  a2 = _mesh_set_flag_roots_found(a2, a3, a4, a5, a6, a7);  /* 0199: callx a8 via reloc-expand */
  a3 = LD32(a3 + 0x0);  /* 019c */
  a10 = LD32(a3 + 0x110);  /* 019e */
  /* 01a1: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  L_01a4: a10 = LD32(a4 + 0x0);  /* 01a4 */
  if (a10 == 0) goto L_01ba;  /* 01a6: beqz a10, 1ba <esp_mesh_get_vnd_roots_len+0x136> */
  L_01a9: a3 = 0;  /* 01a9 */
  a12 = 0x000009c5u;  /* 01ac: l32r = 2501 */
  a11 = (u32)(RODATA__rodata___func___9 + 0x0);  /* 01af: l32r -> .rodata.__func__$9 */
  a8 = (u32)&mesh_free + 0x0;  /* 01b2: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 01b5: callx a8 via reloc-expand */
  ST32(a4 + 0x0, a3);  /* 01b8 */
  L_01ba: a10 = 1;  /* 01ba */
  __asm__ volatile("" ::: "memory");  /* 01bc: memw */
  a8 = 0;  /* 01bf: l32r -> .text._wifi_vnd_ext_mesh_roots_free$part$0+0x0 (link-time addr, kind unclear) */
  a2 = clone__wifi_vnd_ext_mesh_roots_free_part_0(a2, a3, a4, a5, a6, a7);  /* 01c2: callx a8 -> clone .text._wifi_vnd_ext_mesh_roots_free$part$0 (entry +c) */
  goto L_02c2;  /* 01c5: j */
  L_01c9: if (a4 == 0) goto L_02c2;  /* 01c9: beqz a4, 2c2 <esp_mesh_get_vnd_roots_len+0x23e> */
  L_01cc: a3 = (u32)&LOCAL__bss_is_roots_found_13 + 0x0;  /* 01cc: l32r -> .bss.is_roots_found$13 (same-object static) */
  a4 = LD8U(a3 + 0x0);  /* 01cf */
  if (a4 != 0) goto L_0281;  /* 01d2: bnez a4, 281 <esp_mesh_get_vnd_roots_len+0x1fd> */
  L_01d5: a4 = 1;  /* 01d5 */
  ST8(a3 + 0x0, a4);  /* 01d8 */
  __asm__ volatile("" ::: "memory");  /* 01db: memw */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 01de: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 01e1 */
  a10 = LD32(a3 + 0x110);  /* 01e4 */
  __asm__ volatile("" ::: "memory");  /* 01e7: memw */
  /* 01ea: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  a5 = a11 << 22;  /* 01ed */
  a15 = a2;  /* 01f0 */
  a3 = (u32)&LOCAL__bss_roots_found_time_12 + 0x0;  /* 01f2: l32r -> .bss.roots_found_time$12 (same-object static) */
  a12 = 2;  /* 01f5 */
  ST32(a3 + 0x0, a10);  /* 01f7 */
  a10 = a10 >> 10;  /* 01f9 */
  a10 = a5 | a10;  /* 01fc */
  ST32(a3 + 0x4, a11);  /* 01ff */
  a11 = (i32)a11 >> 10;  /* 0201 */
  a3 = (u32)&LOCAL__bss_max_ie_len_11 + 0x0;  /* 0204: l32r -> .bss.max_ie_len$11 (same-object static) */
  a4 = LD32(a3 + 0x0);  /* 0207 */
  a4 = ((i32)a2 > (i32)a4) ? a2 : a4;  /* 0209: max */
  ST32(a3 + 0x0, a4);  /* 020c */
  a3 = 1;  /* 020e */
  a3 = a3 << 21;  /* 0210 */
  a14 = 0x000009d5u;  /* 0213: l32r = 2517 */
  a13 = (u32)(RODATA__rodata_wlog_warning_18 + 0x0);  /* 0216: l32r -> .rodata_wlog_warning.18 */
  ST32(a1 + 0x8, a10);  /* 0219 */
  a10 = 1;  /* 021b */
  ST32(a1 + 0xc, a11);  /* 021d */
  a11 = a3;  /* 021f: mov */
  ST32(a1 + 0x0, a4);  /* 0222 */
  __asm__ volatile("" ::: "memory");  /* 0225: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0228: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 022b: callx a8 via reloc-expand */
  a12 = 2;  /* 022e */
  a11 = a3;  /* 0230 */
  a10 = 1;  /* 0232 */
  a4 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 0234: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a2 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0237: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a5 = LD8U(a4 + 0x10);  /* 023a */
  a15 = LD32(a2 + 0x0);  /* 023d */
  a15 = (a15 >> 1) & 0x1;  /* 023f: extui width 1 */
  ST32(a1 + 0x20, a5);  /* 0242 */
  a4 = LD8U(a4 + 0x0);  /* 0244 */
  ST32(a1 + 0x1c, a4);  /* 0247 */
  a4 = LD8U(a2 + 0x19);  /* 0249 */
  ST32(a1 + 0x18, a4);  /* 024c */
  a4 = LD8U(a2 + 0x11);  /* 024e */
  ST32(a1 + 0x14, a4);  /* 0251 */
  a4 = LD8U(a2 + 0x9);  /* 0253 */
  ST32(a1 + 0x10, a4);  /* 0256 */
  a4 = LD8U(a2 + 0x1);  /* 0258 */
  ST32(a1 + 0xc, a4);  /* 025b */
  a4 = LD32(a2 + 0x18);  /* 025d */
  a4 = (a4 >> 1) & 0x1;  /* 025f: extui width 1 */
  ST32(a1 + 0x8, a4);  /* 0262 */
  a4 = LD32(a2 + 0x10);  /* 0264 */
  a4 = (a4 >> 1) & 0x1;  /* 0266: extui width 1 */
  ST32(a1 + 0x4, a4);  /* 0269 */
  a2 = LD32(a2 + 0x8);  /* 026b */
  a2 = (a2 >> 1) & 0x1;  /* 026d: extui width 1 */
  a14 = 0x000009d7u;  /* 0270: l32r = 2519 */
  a13 = (u32)(RODATA__rodata_wlog_warning_19 + 0x0);  /* 0273: l32r -> .rodata_wlog_warning.19 */
  ST32(a1 + 0x0, a2);  /* 0276 */
  __asm__ volatile("" ::: "memory");  /* 0278: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 027b: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 027e: callx a8 via reloc-expand */
  L_0281: a10 = 0x12c;  /* 0281 */
  a8 = (u32)&esp_mesh_map_change_beacon_interval;  /* 0284: l32r -> func addr */
  a2 = esp_mesh_map_change_beacon_interval(a2, a3, a4, a5, a6, a7);  /* 0287: callx a8 via reloc-expand */
  a10 = a1 + (60);  /* 028a */
  a8 = (u32)&_mesh_timer_process_announce;  /* 028d: l32r -> func addr */
  a2 = _mesh_timer_process_announce(a2, a3, a4, a5, a6, a7);  /* 0290: callx a8 via reloc-expand */
  a10 = a1 + (60);  /* 0293 */
  a8 = (u32)&_mesh_timer_process_yield;  /* 0296: l32r -> func addr */
  a2 = _mesh_timer_process_yield(a2, a3, a4, a5, a6, a7);  /* 0299: callx a8 via reloc-expand */
  a10 = a1 + (60);  /* 029c */
  a8 = (u32)&_mesh_timer_process_fixed;  /* 029f: l32r -> func addr */
  a2 = _mesh_timer_process_fixed(a2, a3, a4, a5, a6, a7);  /* 02a2: callx a8 via reloc-expand */
  a10 = a1 + (60);  /* 02a5 */
  a8 = (u32)&_mesh_timer_process_gone;  /* 02a8: l32r -> func addr */
  a2 = _mesh_timer_process_gone(a2, a3, a4, a5, a6, a7);  /* 02ab: callx a8 via reloc-expand */
  a10 = a1 + (60);  /* 02ae */
  a8 = (u32)&_mesh_timer_process_conflict_root;  /* 02b1: l32r -> func addr */
  a2 = _mesh_timer_process_conflict_root(a2, a3, a4, a5, a6, a7);  /* 02b4: callx a8 via reloc-expand */
  a10 = 1;  /* 02b7 */
  a8 = (u32)&_mesh_set_flag_roots_found;  /* 02ba: l32r -> func addr */
  a2 = _mesh_set_flag_roots_found(a2, a3, a4, a5, a6, a7);  /* 02bd: callx a8 via reloc-expand */
  a2 = LD32(a1 + 0x3c);  /* 02c0 */
  L_02c2: return a2;  /* 02c2: retw.n */
}


/* esp_mesh_get_vnd_ssid_len @ mesh_quick.o 00000014 size 90B bind GLOBAL
 * Calls: memset, esp_wifi_get_config, strnlen, is_my_ie_encrypted | Data refs: esp_mesh_appie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=4, refs=5); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_vnd_ssid_len(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0014: entry a1, 224 (frame 224 bytes) */
  a2 = (u32)&esp_mesh_appie + 0x0;  /* 0017: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 001a */
  a2 = 0;  /* 001c */
  if (a3 == a2) goto L_006c;  /* 001e: beq a3, a2, 6c <esp_mesh_get_vnd_ssid_len+0x58> */
  L_0021: a11 = a2;  /* 0021 */
  a12 = 184;  /* 0023 */
  a10 = a1;  /* 0026 */
  a8 = (u32)&memset + 0x0;  /* 0028: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 002b: callx a8 (libc, via reloc-expand) */
  a11 = a1;  /* 002e */
  a10 = 1;  /* 0030 */
  a8 = (u32)&esp_wifi_get_config + 0x0;  /* 0032: l32r -> global */
  a2 = esp_wifi_get_config(a2, a3, a4, a5, a6, a7);  /* 0035: callx a8 via reloc-expand */
  a2 = a10;  /* 0038 */
  if (a10 != 0) goto L_006a;  /* 003a: bnez.n a10, 6a <esp_mesh_get_vnd_ssid_len+0x56> */
  L_003c: a11 = 32;  /* 003c */
  a10 = a1;  /* 003e */
  a8 = (u32)&strnlen + 0x0;  /* 0040: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0043: callx a8 (libc, via reloc-expand) */
  a3 = a10;  /* 0046 */
  if (a10 == 0) goto L_006c;  /* 0048: beqz.n a10, 6c <esp_mesh_get_vnd_ssid_len+0x58> */
  L_004a: a8 = (u32)&is_my_ie_encrypted;  /* 004a: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6, a7);  /* 004d: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0058;  /* 0050: bnez.n a10, 58 <esp_mesh_get_vnd_ssid_len+0x44> */
  L_0052: a3 = a3 + (6);  /* 0052 */
  goto L_0060;  /* 0054: j */
  L_0058: a3 = a3 + (21);  /* 0058 */
  a8 = -16;  /* 005b */
  a3 = a3 & a8;  /* 005d */
  L_0060: a3 = a3 + (7);  /* 0060 */
  if (a3 < 8u) goto L_006c;  /* 0062: bltui a3, 8, 6c <esp_mesh_get_vnd_ssid_len+0x58> */
  L_0065: a2 = a3;  /* 0065 */
  goto L_006c;  /* 0067: j */
  L_006a: a2 = 0;  /* 006a */
  L_006c: return a2;  /* 006c: retw.n */
}


/* esp_mesh_is_same_router @ mesh_quick.o 0000000c size 64B bind GLOBAL
 * Calls: esp_mesh_get_router_bssid, clone_is_zero_addr, memcmp | Data refs: .text.is_zero_addr
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=2); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_is_same_router(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a4 = a2;  /* 000f */
  a10 = a1;  /* 0011 */
  a2 = 0;  /* 0013 */
  ST32(a1 + 0x0, a2);  /* 0015 */
  ST16(a1 + 0x4, a2);  /* 0017 */
  __asm__ volatile("" ::: "memory");  /* 001a: memw */
  __asm__ volatile("" ::: "memory");  /* 001d: memw */
  a8 = (u32)&esp_mesh_get_router_bssid + 0x0;  /* 0020: l32r -> global */
  a2 = esp_mesh_get_router_bssid(a2, a3, a4, a5, a6, a7);  /* 0023: callx a8 via reloc-expand */
  a10 = a1;  /* 0026 */
  a8 = 0;  /* 0028: l32r -> .text.is_zero_addr+0x0 (link-time addr, kind unclear) */
  a2 = clone_is_zero_addr(a2, a3, a4, a5, a6, a7);  /* 002b: callx a8 -> clone .text.is_zero_addr */
  if (a10 != a2) goto L_004a;  /* 002e: bne a10, a2, 4a <esp_mesh_is_same_router+0x3e> */
  L_0031: if (a4 == a2) goto L_0048;  /* 0031: beq a4, a2, 48 <esp_mesh_is_same_router+0x3c> */
  L_0034: a12 = 6;  /* 0034 */
  a11 = a4 + (7);  /* 0036 */
  a10 = a1;  /* 0038 */
  a8 = (u32)&memcmp + 0x0;  /* 003a: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 003d: callx a8 (libc, via reloc-expand) */
  a3 = 1;  /* 0040 */
  if (a10 == 0) a2 = a3;  /* 0042 */
  goto L_004a;  /* 0045: j */
  L_0048: a2 = -1;  /* 0048 */
  L_004a: return a2;  /* 004a: retw.n */
}


/* esp_mesh_map_change_beacon_interval @ mesh_quick.o 0000001c size 128B bind GLOBAL
 * Calls: esp_wifi_get_beacon_interval, esp_wifi_set_beacon_interval, wifi_mesh_event_post, ieee80211_mesh_quick_get, esp_mesh_is_roots_found | Data refs: g_mesh_init_ps_type, esp_mesh_appie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=5, refs=7); reloc-direct=5, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_map_change_beacon_interval(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 001c: entry a1, 48 (frame 48 bytes) */
  a8 = 0;  /* 001f */
  a10 = a1 + (8);  /* 0021 */
  ST32(a1 + 0x8, a8);  /* 0023 */
  __asm__ volatile("" ::: "memory");  /* 0025: memw */
  a8 = (u32)&esp_wifi_get_beacon_interval + 0x0;  /* 0028: l32r -> global */
  a2 = esp_wifi_get_beacon_interval(a2, a3, a4, a5, a6, a7);  /* 002b: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0035;  /* 002e: bnez.n a10, 35 <esp_mesh_map_change_beacon_interval+0x19> */
  L_0030: a8 = LD32(a1 + 0x8);  /* 0030 */
  if (a8 == a2) goto L_0098;  /* 0032: beq a8, a2, 98 <esp_mesh_map_change_beacon_interval+0x7c> */
  L_0035: a8 = 0;  /* 0035 */
  a9 = 0x12c;  /* 0037 */
  ST8(a1 + 0xc, a8);  /* 003a */
  __asm__ volatile("" ::: "memory");  /* 003d: memw */
  a8 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0040: l32r -> global */
  a10 = LD32(a8 + 0x0);  /* 0043 */
  a8 = 0x3e8;  /* 0045 */
  if (a10 != 0) a8 = a9;  /* 0048 */
  if ((i32)a2 >= (i32)a8) goto L_0078;  /* 004b: bge a2, a8, 78 <esp_mesh_map_change_beacon_interval+0x5c> */
  L_004e: a10 = a2;  /* 004e */
  __asm__ volatile("" ::: "memory");  /* 0050: memw */
  a8 = (u32)&esp_wifi_set_beacon_interval + 0x0;  /* 0053: l32r -> global */
  a2 = esp_wifi_set_beacon_interval(a2, a3, a4, a5, a6, a7);  /* 0056: callx a8 via reloc-expand */
  a8 = 0;  /* 0059 */
  a12 = 6;  /* 005b */
  a11 = a1;  /* 005d */
  a10 = 65;  /* 005f */
  ST32(a1 + 0x0, a8);  /* 0062 */
  ST16(a1 + 0x4, a2);  /* 0065 */
  __asm__ volatile("" ::: "memory");  /* 0068: memw */
  __asm__ volatile("" ::: "memory");  /* 006b: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 006e: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 via reloc-expand */
  goto L_0098;  /* 0074: j */
  L_0078: a8 = (u32)&esp_mesh_appie + 0x0;  /* 0078: l32r -> global */
  a12 = a1 + (12);  /* 007b */
  a11 = 14;  /* 007d */
  a10 = LD32(a8 + 0x0);  /* 007f */
  a10 = a10 + (2);  /* 0081 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0083: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0086: callx a8 via reloc-expand */
  a8 = LD8U(a1 + 0xc);  /* 0089 */
  if (((a8 >> 5) & 1) != 0) goto L_0098;  /* 008c: bbsi a8, 5, 98 <esp_mesh_map_change_beacon_interval+0x7c> */
  L_008f: a8 = (u32)&esp_mesh_is_roots_found + 0x0;  /* 008f: l32r -> global */
  a2 = esp_mesh_is_roots_found(a2, a3, a4, a5, a6, a7);  /* 0092: callx a8 via reloc-expand */
  if (a10 == 0) goto L_004e;  /* 0095: beqz a10, 4e <esp_mesh_map_change_beacon_interval+0x32> */
  L_0098: a2 = 0;  /* 0098 */
  return a2;  /* 009a: retw.n */
}


/* esp_mesh_map_probe_response @ mesh_quick.o 00000030 size 238B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp, cnx_node_search, mesh_get_sub_ie, ieee80211_mesh_quick_set | Data refs: esp_mesh_appie, .bss.s_is_probe_requested, .bss.s_recv_bcn_count
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=5, refs=8); reloc-direct=5, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_map_probe_response(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a4, a5, a6, a7, a8;
  float F1;
  /* 0030: entry a1, 48 (frame 48 bytes) */
  a5 = 1;  /* 0033 */
  a6 = 0;  /* 0035 */
  if (a2 == 0) a6 = a5;  /* 0037 */
  a4 = (a6 >> 8) & 0x1;  /* 003a: extui width 1 */
  if (a6 != 0) goto L_0044;  /* 003d: bnez.n a6, 44 <esp_mesh_map_probe_response+0x14> */
  L_003f: if (a3 == 0) a4 = a5;  /* 003f */
  if (a4 == 0) goto L_0049;  /* 0042: beqz.n a4, 49 <esp_mesh_map_probe_response+0x19> */
  L_0044: a2 = -1;  /* 0044 */
  goto L_011c;  /* 0046: j */
  L_0049: a7 = (u32)&esp_mesh_appie + 0x0;  /* 0049: l32r -> global */
  a6 = -91;  /* 004c */
  a12 = a1;  /* 004f */
  a11 = a5;  /* 0051 */
  ST8(a1 + 0x8, a6);  /* 0053 */
  __asm__ volatile("" ::: "memory");  /* 0056: memw */
  a6 = LD32(a7 + 0x0);  /* 0059 */
  a6 = a6 + (2);  /* 005b */
  a10 = a6;  /* 005d */
  ST8(a1 + 0x7, a4);  /* 005f */
  ST8(a1 + 0x6, a4);  /* 0062 */
  ST32(a1 + 0x0, a4);  /* 0065 */
  ST16(a1 + 0x4, a4);  /* 0067 */
  __asm__ volatile("" ::: "memory");  /* 006a: memw */
  __asm__ volatile("" ::: "memory");  /* 006d: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0070: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3);  /* 0073: callx a8 via reloc-expand */
  a12 = a1 + (8);  /* 0076 */
  a11 = a4;  /* 0078 */
  a10 = a6;  /* 007a */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 007c: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3);  /* 007f: callx a8 via reloc-expand */
  a12 = a1 + (7);  /* 0082 */
  a11 = 5;  /* 0084 */
  a10 = a6;  /* 0086 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0088: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3);  /* 008b: callx a8 via reloc-expand */
  a12 = a1 + (6);  /* 008e */
  a11 = 4;  /* 0090 */
  a10 = a6;  /* 0092 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0094: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3);  /* 0097: callx a8 via reloc-expand */
  a11 = a2 + (8);  /* 009a */
  a12 = 6;  /* 009c */
  a10 = a1;  /* 009e */
  a8 = (u32)&memcmp + 0x0;  /* 00a0: l32r -> global */
  a2 = memcmp(a2, a3);  /* 00a3: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 00a6 */
  if (a10 != 0) goto L_0114;  /* 00a8: bnez a10, 114 <esp_mesh_map_probe_response+0xe4> */
  L_00ab: a4 = LD8U(a1 + 0x8);  /* 00ab */
  if (a4 == 3) goto L_0044;  /* 00ae: beqi a4, 3, 44 <esp_mesh_map_probe_response+0x14> */
  L_00b1: a10 = a3;  /* 00b1 */
  a8 = (u32)&cnx_node_search + 0x0;  /* 00b3: l32r -> global */
  a2 = cnx_node_search(a2, a3);  /* 00b6: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00f1;  /* 00b9: beqz.n a10, f1 <esp_mesh_map_probe_response+0xc1> */
  L_00bb: a8 = (u32)&mesh_get_sub_ie;  /* 00bb: l32r -> func addr */
  a2 = mesh_get_sub_ie(a2, a3);  /* 00be: callx a8 via reloc-expand */
  a4 = LD8U(a10 + 0x5);  /* 00c1 */
  a12 = a10 + (5);  /* 00c4 */
  a5 = a5 | a4;  /* 00c6 */
  a11 = 14;  /* 00c9 */
  a4 = LD32(a7 + 0x0);  /* 00cb */
  ST8(a10 + 0x5, a5);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00d0: memw */
  a10 = a4 + (2);  /* 00d3 */
  __asm__ volatile("" ::: "memory");  /* 00d5: memw */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 00d8: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5);  /* 00db: callx a8 via reloc-expand */
  a12 = a3;  /* 00de */
  a11 = 20;  /* 00e0 */
  a10 = LD32(a7 + 0x0);  /* 00e2 */
  a10 = a10 + (2);  /* 00e4 */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 00e6: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3);  /* 00e9: callx a8 via reloc-expand */
  goto L_00fc;  /* 00ec: j */
  L_00f1: a3 = LD8U(a1 + 0x7);  /* 00f1 */
  if (a3 == 0) goto L_00fc;  /* 00f4: beqz.n a3, fc <esp_mesh_map_probe_response+0xcc> */
  L_00f6: a4 = LD8U(a1 + 0x6);  /* 00f6 */
  if (a4 == a3) goto L_011a;  /* 00f9: beq a4, a3, 11a <esp_mesh_map_probe_response+0xea> */
  L_00fc: a4 = 1;  /* 00fc */
  a3 = (u32)&LOCAL__bss_s_is_probe_requested + 0x0;  /* 00fe: l32r -> .bss.s_is_probe_requested (same-object static) */
  ST8(a3 + 0x0, a4);  /* 0101 */
  __asm__ volatile("" ::: "memory");  /* 0104: memw */
  a4 = 0;  /* 0107 */
  a3 = (u32)&LOCAL__bss_s_recv_bcn_count + 0x0;  /* 0109: l32r -> .bss.s_recv_bcn_count (same-object static) */
  ST32(a3 + 0x0, a4);  /* 010c */
  __asm__ volatile("" ::: "memory");  /* 010e: memw */
  goto L_011c;  /* 0111: j */
  L_0114: a2 = 103;  /* 0114 */
  goto L_011c;  /* 0117: j */
  L_011a: a2 = 5;  /* 011a */
  L_011c: return a2;  /* 011c: retw.n */
}


/* esp_mesh_map_reject_connection @ mesh_quick.o 0000001c size 177B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp, cnx_node_search, ieee80211_vnd_mesh_fully_associated | Data refs: esp_mesh_appie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=4, refs=5); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_map_reject_connection(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 001c: entry a1, 48 (frame 48 bytes) */
  a11 = 1;  /* 001f */
  a9 = 0;  /* 0021 */
  if (a2 == 0) a9 = a11;  /* 0023 */
  a8 = (a9 >> 8) & 0x1;  /* 0026: extui width 1 */
  if (a9 != 0) goto L_00c9;  /* 0029: bnez a9, c9 <esp_mesh_map_reject_connection+0xad> */
  L_002c: if (a3 == 0) a8 = a11;  /* 002c */
  if (a8 != 0) goto L_00c9;  /* 002f: bnez a8, c9 <esp_mesh_map_reject_connection+0xad> */
  L_0032: a4 = -91;  /* 0032 */
  ST8(a1 + 0x7, a4);  /* 0035 */
  __asm__ volatile("" ::: "memory");  /* 0038: memw */
  a12 = a1;  /* 003b */
  a4 = (u32)&esp_mesh_appie + 0x0;  /* 003d: l32r -> global */
  a10 = LD32(a4 + 0x0);  /* 0040 */
  a10 = a10 + (2);  /* 0042 */
  ST32(a1 + 0x0, a8);  /* 0044 */
  ST16(a1 + 0x4, a8);  /* 0046 */
  ST8(a1 + 0x6, a8);  /* 0049 */
  __asm__ volatile("" ::: "memory");  /* 004c: memw */
  __asm__ volatile("" ::: "memory");  /* 004f: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0052: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0055: callx a8 via reloc-expand */
  a11 = a2 + (8);  /* 0058 */
  a12 = 6;  /* 005a */
  a10 = a1;  /* 005c */
  a8 = (u32)&memcmp + 0x0;  /* 005e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0061: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 0064 */
  if (a10 != 0) goto L_00b8;  /* 0066: bnez a10, b8 <esp_mesh_map_reject_connection+0x9c> */
  L_0069: a10 = a3;  /* 0069: mov */
  a8 = (u32)&cnx_node_search + 0x0;  /* 006c: l32r -> global */
  a2 = cnx_node_search(a2, a3, a4, a5, a6, a7);  /* 006f: callx a8 via reloc-expand */
  if (a10 == 0) goto L_008e;  /* 0072: beqz.n a10, 8e <esp_mesh_map_reject_connection+0x72> */
  L_0074: a10 = LD32(a4 + 0x0);  /* 0074 */
  a12 = a1 + (7);  /* 0076 */
  a11 = 0;  /* 0078 */
  a10 = a10 + (2);  /* 007b */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 007e: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0081: callx a8 via reloc-expand */
  a8 = LD8U(a1 + 0x7);  /* 0084 */
  if (a8 != 0) goto L_00ab;  /* 0087: bnez.n a8, ab <esp_mesh_map_reject_connection+0x8f> */
  L_0089: goto L_00be;  /* 0089: j */
  L_008e: a10 = LD32(a4 + 0x0);  /* 008e */
  a12 = a1 + (6);  /* 0090 */
  a11 = 4;  /* 0092 */
  a10 = a10 + (2);  /* 0094 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0096: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0099: callx a8 via reloc-expand */
  a10 = LD8U(a1 + 0x6);  /* 009c */
  a8 = (u32)&ieee80211_vnd_mesh_fully_associated + 0x0;  /* 009f: l32r -> global */
  a2 = ieee80211_vnd_mesh_fully_associated(a2, a3, a4, a5, a6, a7);  /* 00a2: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0074;  /* 00a5: beqz a10, 74 <esp_mesh_map_reject_connection+0x58> */
  L_00a8: goto L_00c4;  /* 00a8: j */
  L_00ab: a8 = a8 + (-3);  /* 00ab */
  a3 = 102;  /* 00ae */
  if (a8 == 0) a2 = a3;  /* 00b1 */
  goto L_00cb;  /* 00b4: j */
  L_00b8: a2 = 103;  /* 00b8 */
  goto L_00cb;  /* 00bb: j */
  L_00be: a2 = 101;  /* 00be */
  goto L_00cb;  /* 00c1: j */
  L_00c4: a2 = 5;  /* 00c4 */
  goto L_00cb;  /* 00c6: j */
  L_00c9: a2 = 0;  /* 00c9 */
  L_00cb: return a2;  /* 00cb: retw.n */
}


/* esp_mesh_map_stop_beacon @ mesh_quick.o 00000024 size 199B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, esp_mesh_is_root_conflicts_allowed, mesh_get_vnd_roots_len, ieee80211_hostapd_beacon_txcb | Data refs: esp_mesh_appie, .bss.s_recv_bcn_count, .bss.s_is_probe_requested
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=4, refs=7); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_map_stop_beacon(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a2 = -91;  /* 0027 */
  ST8(a1 + 0x2, a2);  /* 002a */
  __asm__ volatile("" ::: "memory");  /* 002d: memw */
  a4 = 0;  /* 0030 */
  a12 = a1 + (1);  /* 0032 */
  a11 = 14;  /* 0034 */
  a3 = 1;  /* 0036 */
  a2 = (u32)&esp_mesh_appie + 0x0;  /* 0038: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 003b */
  a2 = a2 + (2);  /* 003d */
  a10 = a2;  /* 003f: mov */
  ST8(a1 + 0x1, a4);  /* 0042 */
  ST8(a1 + 0x0, a4);  /* 0045 */
  __asm__ volatile("" ::: "memory");  /* 0048: memw */
  __asm__ volatile("" ::: "memory");  /* 004b: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 004e: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0051: callx a8 via reloc-expand */
  a12 = a1 + (2);  /* 0054 */
  a11 = 0;  /* 0056 */
  a10 = a2;  /* 0058 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 005a: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 005d: callx a8 via reloc-expand */
  a10 = a2;  /* 0060 */
  a12 = a1;  /* 0062 */
  a11 = 5;  /* 0064 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0066: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0069: callx a8 via reloc-expand */
  a2 = LD8U(a1 + 0x2);  /* 006c */
  if (a2 == 3) goto L_00b2;  /* 006f: beqi a2, 3, b2 <esp_mesh_map_stop_beacon+0x8e> */
  L_0072: if (a2 != 2) goto L_00a9;  /* 0072: bnei a2, 2, a9 <esp_mesh_map_stop_beacon+0x85> */
  L_0075: a3 = LD8U(a1 + 0x0);  /* 0075 */
  if (a3 != 0) goto L_00e4;  /* 0078: bnez a3, e4 <esp_mesh_map_stop_beacon+0xc0> */
  L_007b: a8 = (u32)&esp_mesh_is_root_conflicts_allowed + 0x0;  /* 007b: l32r -> global */
  a2 = esp_mesh_is_root_conflicts_allowed(a2, a3, a4, a5, a6, a7);  /* 007e: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00e4;  /* 0081: beqz a10, e4 <esp_mesh_map_stop_beacon+0xc0> */
  L_0084: a8 = (u32)&LOCAL__bss_s_recv_bcn_count + 0x0;  /* 0084: l32r -> .bss.s_recv_bcn_count (same-object static) */
  a2 = LD32(a8 + 0x0);  /* 0087 */
  a2 = a2 + (1);  /* 0089 */
  ST32(a8 + 0x0, a2);  /* 008b */
  a8 = (u32)&LOCAL__bss_s_is_probe_requested + 0x0;  /* 008d: l32r -> .bss.s_is_probe_requested (same-object static) */
  a9 = LD8U(a8 + 0x0);  /* 0090 */
  if (a9 == 0) goto L_00e4;  /* 0093: beqz a9, e4 <esp_mesh_map_stop_beacon+0xc0> */
  L_0096: a9 = 100;  /* 0096 */
  if ((i32)a9 >= (i32)a2) goto L_00e4;  /* 0099: bge a9, a2, e4 <esp_mesh_map_stop_beacon+0xc0> */
  L_009c: ST8(a8 + 0x0, a4);  /* 009c */
  __asm__ volatile("" ::: "memory");  /* 009f: memw */
  __asm__ volatile("" ::: "memory");  /* 00a2: memw */
  goto L_00b2;  /* 00a5: j */
  L_00a9: if (a2 != 0) goto L_00e4;  /* 00a9: bnez.n a2, e4 <esp_mesh_map_stop_beacon+0xc0> */
  L_00ab: a3 = (u32)&LOCAL__bss_s_recv_bcn_count + 0x0;  /* 00ab: l32r -> .bss.s_recv_bcn_count (same-object static) */
  ST32(a3 + 0x0, a2);  /* 00ae */
  a3 = a2;  /* 00b0 */
  L_00b2: a2 = 2;  /* 00b2 */
  a4 = LD8U(a1 + 0x1);  /* 00b4 */
  a4 = a4 & a2;  /* 00b7 */
  if (a4 == 0) goto L_00c4;  /* 00ba: beqz.n a4, c4 <esp_mesh_map_stop_beacon+0xa0> */
  L_00bc: a2 = 0;  /* 00bc */
  __asm__ volatile("" ::: "memory");  /* 00be: memw */
  goto L_00e9;  /* 00c1: j */
  L_00c4: a8 = (u32)&mesh_get_vnd_roots_len;  /* 00c4: l32r -> func addr */
  a2 = mesh_get_vnd_roots_len(a2, a3, a4, a5, a6, a7);  /* 00c7: callx a8 via reloc-expand */
  a2 = 1;  /* 00ca */
  a5 = a4;  /* 00cc */
  if (a10 == 0) a5 = a2;  /* 00ce */
  if (a5 == 0) goto L_00bc;  /* 00d1: beqz a5, bc <esp_mesh_map_stop_beacon+0x98> */
  L_00d4: if (a3 == 0) goto L_00bc;  /* 00d4: beqz a3, bc <esp_mesh_map_stop_beacon+0x98> */
  L_00d7: a10 = a4;  /* 00d7: mov */
  a8 = (u32)&ieee80211_hostapd_beacon_txcb + 0x0;  /* 00da: l32r -> global */
  a2 = ieee80211_hostapd_beacon_txcb(a2, a3, a4, a5, a6, a7);  /* 00dd: callx a8 via reloc-expand */
  goto L_00e9;  /* 00e0: j */
  L_00e4: a3 = 0;  /* 00e4 */
  goto L_00b2;  /* 00e6: j */
  L_00e9: return a2;  /* 00e9: retw.n */
}


/* esp_mesh_monitor_parent_candidate_ie @ mesh_quick.o 00000038 size 534B bind GLOBAL
 * Calls: memset, wifi_mesh_event_post, wifi_log, memcmp, ieee80211_mesh_quick_get, mesh_post_parent_switch_candidate | indirect[7]: mem[a8+0x110]; mem[a2+0x110]; mem[a6+0x110] | Data refs: .bss.s_mesh_parent_candidate, g_osi_funcs_p, .rodata_wlog_warning.35, .data.candidate_rssi$4, esp_mesh_appie
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=11); reloc-direct=6, funcdb-attributed=0, unknown-indirect=7 */
u32 esp_mesh_monitor_parent_candidate_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0038: entry a1, 112 (frame 112 bytes) */
  a5 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 003b: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a6 = LD8U(a5 + 0x0);  /* 003e */
  if (a6 != 0) goto L_0046;  /* 0041: bnez.n a6, 46 <esp_mesh_monitor_parent_candidate_ie+0xe> */
  L_0043: goto L_01c5;  /* 0043: j */
  L_0046: a6 = 1;  /* 0046 */
  a8 = 0;  /* 0048 */
  if (a3 == 0) a8 = a6;  /* 004a */
  a9 = (a8 >> 8) & 0x1;  /* 004d: extui width 1 */
  if (a8 != 0) goto L_01c5;  /* 0050: bnez a8, 1c5 <esp_mesh_monitor_parent_candidate_ie+0x18d> */
  L_0053: if (a2 != 0) a6 = a9;  /* 0053 */
  if (a6 != 0) goto L_01c5;  /* 0056: bnez a6, 1c5 <esp_mesh_monitor_parent_candidate_ie+0x18d> */
  L_0059: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0059: l32r -> global */
  a8 = LD32(a6 + 0x0);  /* 005c */
  a10 = LD32(a8 + 0x110);  /* 005f */
  /* 0062: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = LD32(a5 + 0xb4);  /* 0065 */
  if ((i32)a11 < (i32)a8) goto L_0098;  /* 0068: blt a11, a8, 98 <esp_mesh_monitor_parent_candidate_ie+0x60> */
  L_006b: if (a8 != a11) goto L_0074;  /* 006b: bne a8, a11, 74 <esp_mesh_monitor_parent_candidate_ie+0x3c> */
  L_006e: a8 = LD32(a5 + 0xb0);  /* 006e */
  if (a10 < a8) goto L_0098;  /* 0071: bltu a10, a8, 98 <esp_mesh_monitor_parent_candidate_ie+0x60> */
  L_0074: a8 = LD32(a6 + 0x0);  /* 0074 */
  a10 = LD32(a8 + 0x110);  /* 0076 */
  /* 0079: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a9 = 1;  /* 007c */
  a8 = LD32(a5 + 0xb0);  /* 007e */
  a8 = a10 - a8;  /* 0081: sub */
  a12 = LD32(a5 + 0xb4);  /* 0084 */
  if (a10 < a8) goto L_008c;  /* 0087: bltu a10, a8, 8c <esp_mesh_monitor_parent_candidate_ie+0x54> */
  L_008a: a9 = 0;  /* 008a */
  L_008c: a11 = a11 - a12;  /* 008c: sub */
  a10 = a8;  /* 008f */
  a11 = a11 - a9;  /* 0091: sub */
  goto L_00c5;  /* 0094: j */
  L_0098: a8 = LD32(a6 + 0x0);  /* 0098 */
  a10 = LD32(a8 + 0x110);  /* 009a */
  /* 009d: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = -1;  /* 00a0 */
  a12 = 1;  /* 00a2 */
  a9 = LD32(a5 + 0xb0);  /* 00a4 */
  a9 = a9 ^ a8;  /* 00a7 */
  a10 = a9 + a10;  /* 00aa */
  a8 = LD32(a5 + 0xb4);  /* 00ac */
  if (a10 < a9) goto L_00b4;  /* 00af: bltu a10, a9, b4 <esp_mesh_monitor_parent_candidate_ie+0x7c> */
  L_00b2: a12 = 0;  /* 00b2 */
  L_00b4: a8 = a8 + a11;  /* 00b4 */
  a9 = a10 + (1);  /* 00b6 */
  a8 = a12 + a8;  /* 00b8 */
  a11 = 1;  /* 00ba */
  if (a9 < a10) goto L_00c1;  /* 00bc: bltu a9, a10, c1 <esp_mesh_monitor_parent_candidate_ie+0x89> */
  L_00bf: a11 = 0;  /* 00bf */
  L_00c1: a10 = a9;  /* 00c1 */
  a11 = a11 + a8;  /* 00c3 */
  L_00c5: a9 = LD32(a5 + 0xac);  /* 00c5 */
  a12 = a9 << 31;  /* 00c8 */
  a9 = (i32)a9 >> 1;  /* 00cb */
  a8 = LD32(a5 + 0xa8);  /* 00ce */
  a8 = a8 >> 1;  /* 00d1 */
  a8 = a12 | a8;  /* 00d4 */
  if ((i32)a11 >= (i32)a9) goto L_00dd;  /* 00d7: bge a11, a9, dd <esp_mesh_monitor_parent_candidate_ie+0xa5> */
  L_00da: goto L_01ca;  /* 00da: j */
  L_00dd: if (a9 != a11) goto L_00e6;  /* 00dd: bne a9, a11, e6 <esp_mesh_monitor_parent_candidate_ie+0xae> */
  L_00e0: if (a10 >= a8) goto L_00e6;  /* 00e0: bgeu a10, a8, e6 <esp_mesh_monitor_parent_candidate_ie+0xae> */
  L_00e3: goto L_01ca;  /* 00e3: j */
  L_00e6: a12 = 47;  /* 00e6 */
  a11 = 0;  /* 00e8 */
  a10 = a1 + (32);  /* 00eb */
  a8 = (u32)&memset + 0x0;  /* 00ee: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00f1: callx a8 (libc, via reloc-expand) */
  a12 = 47;  /* 00f4 */
  a11 = a1 + (32);  /* 00f6 */
  a10 = 64;  /* 00f9 */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 00fb: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 00fe: callx a8 via reloc-expand */
  a2 = LD32(a6 + 0x0);  /* 0101 */
  a10 = LD32(a2 + 0x110);  /* 0103 */
  /* 0106: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a2 = LD32(a5 + 0xb4);  /* 0109 */
  if ((i32)a11 < (i32)a2) goto L_0139;  /* 010c: blt a11, a2, 139 <esp_mesh_monitor_parent_candidate_ie+0x101> */
  L_010f: if (a2 != a11) goto L_0118;  /* 010f: bne a2, a11, 118 <esp_mesh_monitor_parent_candidate_ie+0xe0> */
  L_0112: a2 = LD32(a5 + 0xb0);  /* 0112 */
  if (a10 < a2) goto L_0139;  /* 0115: bltu a10, a2, 139 <esp_mesh_monitor_parent_candidate_ie+0x101> */
  L_0118: a3 = 1;  /* 0118 */
  a2 = LD32(a6 + 0x0);  /* 011a */
  a10 = LD32(a2 + 0x110);  /* 011c */
  /* 011f: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a2 = LD32(a5 + 0xb0);  /* 0122 */
  a2 = a10 - a2;  /* 0125: sub */
  a4 = LD32(a5 + 0xb4);  /* 0128 */
  if (a10 < a2) goto L_0130;  /* 012b: bltu a10, a2, 130 <esp_mesh_monitor_parent_candidate_ie+0xf8> */
  L_012e: a3 = 0;  /* 012e */
  L_0130: a8 = a11 - a4;  /* 0130: sub */
  a8 = a8 - a3;  /* 0133: sub */
  goto L_0164;  /* 0136: j */
  L_0139: a2 = LD32(a6 + 0x0);  /* 0139 */
  a4 = 1;  /* 013b */
  a10 = LD32(a2 + 0x110);  /* 013d */
  a2 = -1;  /* 0140 */
  /* 0142: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a3 = LD32(a5 + 0xb0);  /* 0145 */
  a3 = a3 ^ a2;  /* 0148 */
  a10 = a3 + a10;  /* 014b */
  a2 = LD32(a5 + 0xb4);  /* 014d */
  if (a10 < a3) goto L_0155;  /* 0150: bltu a10, a3, 155 <esp_mesh_monitor_parent_candidate_ie+0x11d> */
  L_0153: a4 = 0;  /* 0153 */
  L_0155: a11 = a2 + a11;  /* 0155 */
  a2 = a10 + (1);  /* 0157 */
  a11 = a4 + a11;  /* 0159 */
  a8 = 1;  /* 015b */
  if (a2 < a10) goto L_0162;  /* 015d: bltu a2, a10, 162 <esp_mesh_monitor_parent_candidate_ie+0x12a> */
  L_0160: a8 = 0;  /* 0160 */
  L_0162: a8 = a8 + a11;  /* 0162 */
  L_0164: a2 = (a2 >> 12) & 0x1fffff;  /* 0164: extui width 21 */
  a8 = a8 << 12;  /* 0167 */
  a3 = LD32(a5 + 0xac);  /* 016a */
  a8 = a8 | a2;  /* 016d */
  a4 = a3 << 11;  /* 0170 */
  a3 = (i32)a3 >> 21;  /* 0173 */
  a12 = 2;  /* 0176 */
  a2 = LD32(a5 + 0xa8);  /* 0178 */
  a11 = 32;  /* 017b */
  a2 = (a2 >> 11) & 0x3fffff;  /* 017d: extui width 22 */
  a2 = a4 | a2;  /* 0180 */
  a10 = 1;  /* 0183 */
  a15 = LD8U(a5 + 0x4);  /* 0185 */
  ST32(a1 + 0x18, a2);  /* 0188 */
  ST32(a1 + 0x1c, a3);  /* 018a */
  ST32(a1 + 0x14, a8);  /* 018c */
  a2 = LD8U(a5 + 0x9);  /* 018e */
  ST32(a1 + 0x10, a2);  /* 0191 */
  a2 = LD8U(a5 + 0x8);  /* 0193 */
  ST32(a1 + 0xc, a2);  /* 0196 */
  a2 = LD8U(a5 + 0x7);  /* 0198 */
  ST32(a1 + 0x8, a2);  /* 019b */
  a2 = LD8U(a5 + 0x6);  /* 019e */
  ST32(a1 + 0x4, a2);  /* 01a1 */
  a2 = LD8U(a5 + 0x5);  /* 01a3 */
  a14 = 0x000014ffu;  /* 01a6: l32r = 5375 */
  a13 = (u32)(RODATA__rodata_wlog_warning_35 + 0x0);  /* 01a9: l32r -> .rodata_wlog_warning.35 */
  ST32(a1 + 0x0, a2);  /* 01ac */
  __asm__ volatile("" ::: "memory");  /* 01af: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 01b2: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 01b5: callx a8 via reloc-expand */
  a12 = 184;  /* 01b8 */
  a11 = 0;  /* 01bb */
  a10 = a5;  /* 01bd */
  a8 = (u32)&memset + 0x0;  /* 01bf: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01c2: callx a8 (libc, via reloc-expand) */
  L_01c5: a2 = -1;  /* 01c5 */
  goto L_024c;  /* 01c7: j */
  L_01ca: a6 = LD32(a6 + 0x0);  /* 01ca */
  a10 = LD32(a6 + 0x110);  /* 01cc */
  /* 01cf: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a12 = 6;  /* 01d2 */
  ST32(a5 + 0xb4, a11);  /* 01d4 */
  a11 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 01d7: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  ST32(a5 + 0xb0, a10);  /* 01da */
  a10 = a2;  /* 01dd */
  __asm__ volatile("" ::: "memory");  /* 01df: memw */
  a8 = (u32)&memcmp + 0x0;  /* 01e2: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 01e5: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 01e8 */
  if (a10 != 0) goto L_01c5;  /* 01ea: bnez a10, 1c5 <esp_mesh_monitor_parent_candidate_ie+0x18d> */
  L_01ed: a8 = (u32)&LOCAL__data_candidate_rssi_4 + 0x0;  /* 01ed: l32r -> .data.candidate_rssi$4 (same-object static) */
  a5 = -120;  /* 01f0 */
  a9 = LD8U(a8 + 0x0);  /* 01f3 */
  a6 = (i32)(a9 << (32 - 7)) >> (32 - 7);  /* 01f6: sext */
  if (a6 != a5) goto L_0202;  /* 01f9: bne a6, a5, 202 <esp_mesh_monitor_parent_candidate_ie+0x1ca> */
  L_01fc: a5 = (a4 >> 8) & 0x1;  /* 01fc: extui width 1 */
  goto L_021a;  /* 01ff: j */
  L_0202: a5 = (a4 >> 8) & 0x1;  /* 0202: extui width 1 */
  if (a9 == 0) goto L_021a;  /* 0205: beqz.n a9, 21a <esp_mesh_monitor_parent_candidate_ie+0x1e2> */
  L_0207: a5 = a6 + (a6 << 1);  /* 0207 */
  a5 = a5 + (a6 << 2);  /* 020a */
  a4 = a4 + (a4 << 1);  /* 020d */
  a4 = a5 + a4;  /* 0210 */
  a5 = a4 + (15);  /* 0212 */
  if ((i32)a4 >= 0) a5 = a4;  /* 0214 */
  a5 = (a5 >> 8) & 0x1f;  /* 0217: extui width 5 */
  L_021a: a4 = 0;  /* 021a */
  ST8(a1 + 0x20, a4);  /* 021c */
  __asm__ volatile("" ::: "memory");  /* 021f: memw */
  a12 = a1 + (32);  /* 0222 */
  a11 = 14;  /* 0225 */
  a4 = (u32)&esp_mesh_appie + 0x0;  /* 0227: l32r -> global */
  a10 = LD32(a4 + 0x0);  /* 022a */
  a10 = a10 + (2);  /* 022c */
  ST8(a8 + 0x0, a5);  /* 022e */
  __asm__ volatile("" ::: "memory");  /* 0231: memw */
  __asm__ volatile("" ::: "memory");  /* 0234: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0237: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 023a: callx a8 via reloc-expand */
  a11 = (i32)(a5 << (32 - 7)) >> (32 - 7);  /* 023d: sext */
  a10 = a3;  /* 0240: mov */
  a12 = LD8U(a1 + 0x20);  /* 0243 */
  a8 = (u32)&mesh_post_parent_switch_candidate;  /* 0246: l32r -> func addr */
  a2 = mesh_post_parent_switch_candidate(a2, a3, a4, a5, a6, a7);  /* 0249: callx a8 via reloc-expand */
  L_024c: return a2;  /* 024c: retw.n */
}


/* esp_mesh_monitor_parent_ie @ mesh_quick.o 00000088 size 1018B bind GLOBAL
 * Calls: memset, mesh_get_sub_ie, ieee80211_mesh_quick_get, ieee80211_mesh_quick_set, esp_mesh_map_change_beacon_interval, wifi_mesh_event_post, wifi_log, memcpy, mesh_post_parent_weak_rssi, mesh_post_parent_assoc_ie, clone_is_zero_addr, memcmp | Data refs: esp_mesh_appie, .rodata_wlog_warning.36, g_mesh_topology, .bss.last_parent_layer$2, .bss.monitor_count$1, g_mesh_monitor_parent_beacon_count, .bss.s_mesh_monitor_parent_cfg, .text.is_zero_addr
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=11, refs=18); reloc-direct=12, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_monitor_parent_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8, a9;
  /* 0088: entry a1, 96 (frame 96 bytes) */
  ST32(a1 + 0x38, a2);  /* 008b */
  a11 = 1;  /* 008d */
  a2 = 0;  /* 008f */
  if (a4 == 0) a2 = a11;  /* 0091 */
  ST32(a1 + 0x34, a3);  /* 0094 */
  a3 = (a2 >> 8) & 0x1;  /* 0096: extui width 1 */
  ST32(a1 + 0x30, a5);  /* 0099 */
  if (a2 != 0) goto L_047c;  /* 009b: bnez a2, 47c <esp_mesh_monitor_parent_ie+0x3f4> */
  L_009e: a2 = LD32(a1 + 0x34);  /* 009e */
  if (a2 != 0) a11 = a3;  /* 00a0 */
  if (a11 != 0) goto L_047c;  /* 00a3: bnez a11, 47c <esp_mesh_monitor_parent_ie+0x3f4> */
  L_00a6: a12 = 20;  /* 00a6 */
  a10 = a1;  /* 00a8 */
  ST8(a1 + 0x23, a11);  /* 00aa */
  a2 = -120;  /* 00ad */
  ST32(a1 + 0x14, a11);  /* 00b0 */
  ST16(a1 + 0x18, a11);  /* 00b2 */
  ST16(a1 + 0x1e, a11);  /* 00b5 */
  ST16(a1 + 0x1c, a11);  /* 00b8 */
  ST8(a1 + 0x22, a11);  /* 00bb */
  ST8(a1 + 0x21, a11);  /* 00be */
  __asm__ volatile("" ::: "memory");  /* 00c1: memw */
  __asm__ volatile("" ::: "memory");  /* 00c4: memw */
  a8 = (u32)&memset + 0x0;  /* 00c7: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00ca: callx a8 (libc, via reloc-expand) */
  ST8(a1 + 0x20, a2);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00d0: memw */
  __asm__ volatile("" ::: "memory");  /* 00d3: memw */
  a8 = (u32)&mesh_get_sub_ie;  /* 00d6: l32r -> func addr */
  a2 = mesh_get_sub_ie(a2, a3, a4, a5, a6, a7);  /* 00d9: callx a8 via reloc-expand */
  a3 = a10;  /* 00dc */
  a12 = a1 + (32);  /* 00de */
  a11 = 12;  /* 00e1 */
  a5 = (u32)&esp_mesh_appie + 0x0;  /* 00e3: l32r -> global */
  a7 = LD32(a5 + 0x0);  /* 00e6 */
  a7 = a7 + (2);  /* 00e9 */
  a10 = a7;  /* 00ec: mov */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00ef: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 00f2: callx a8 via reloc-expand */
  a2 = LD8U(a1 + 0x20);  /* 00f5 */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 00f8: sext */
  a8 = LD32(a1 + 0x30);  /* 00fb */
  a2 = a2 - a8;  /* 00fd: sub */
  a2 = ((i32)a2 < 0) ? -(i32)a2 : a2;  /* 0100 */
  if ((i32)a2 < 6) goto L_011d;  /* 0103: blti a2, 6, 11d <esp_mesh_monitor_parent_ie+0x95> */
  L_0106: ST8(a3 + 0x4, a8);  /* 0106 */
  __asm__ volatile("" ::: "memory");  /* 0109: memw */
  a12 = a1 + (48);  /* 010c */
  a11 = 12;  /* 010f */
  a10 = a7;  /* 0111: mov */
  __asm__ volatile("" ::: "memory");  /* 0114: memw */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 0117: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5, a6, a7);  /* 011a: callx a8 via reloc-expand */
  L_011d: a10 = LD32(a5 + 0x0);  /* 011d */
  a12 = a1 + (35);  /* 011f */
  a11 = 14;  /* 0122 */
  a10 = a10 + (2);  /* 0124 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0126: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0129: callx a8 via reloc-expand */
  a9 = LD8U(a4 + 0x1e);  /* 012c */
  a2 = LD8U(a1 + 0x23);  /* 012f */
  a7 = a2 ^ a9;  /* 0132 */
  a7 = (a7 >> 1) & 0xf;  /* 0135: extui width 4 */
  if (a7 == 0) goto L_016c;  /* 0138: beqz.n a7, 16c <esp_mesh_monitor_parent_ie+0xe4> */
  L_013a: a8 = 8;  /* 013a */
  a7 = LD8U(a3 + 0x5);  /* 013c */
  if ((a9 & a8) == 0) goto L_015f;  /* 013f: bnone a9, a8, 15f <esp_mesh_monitor_parent_ie+0xd7> */
  L_0142: a7 = a7 | a8;  /* 0142 */
  a10 = 0x12c;  /* 0145 */
  ST8(a3 + 0x5, a7);  /* 0148 */
  a7 = 0;  /* 014b */
  ST8(a3 + 0xe, a7);  /* 014d */
  __asm__ volatile("" ::: "memory");  /* 0150: memw */
  __asm__ volatile("" ::: "memory");  /* 0153: memw */
  a8 = (u32)&esp_mesh_map_change_beacon_interval;  /* 0156: l32r -> func addr */
  a2 = esp_mesh_map_change_beacon_interval(a2, a3, a4, a5, a6, a7);  /* 0159: callx a8 via reloc-expand */
  goto L_016a;  /* 015c: j */
  L_015f: a8 = -9;  /* 015f */
  a7 = a7 & a8;  /* 0161 */
  ST8(a3 + 0x5, a7);  /* 0164 */
  __asm__ volatile("" ::: "memory");  /* 0167: memw */
  L_016a: a7 = 16;  /* 016a */
  L_016c: a9 = LD8U(a4 + 0x1e);  /* 016c */
  a8 = a2 ^ a9;  /* 016f */
  if (((a8 >> 6) & 1) == 0) goto L_0199;  /* 0172: bbci a8, 6, 199 <esp_mesh_monitor_parent_ie+0x111> */
  L_0175: a8 = 32;  /* 0175 */
  a10 = 64;  /* 0177 */
  a7 = a7 | a8;  /* 0179 */
  a8 = LD8U(a3 + 0x5);  /* 017c */
  if ((a9 & a10) == 0) goto L_018d;  /* 017f: bnone a9, a10, 18d <esp_mesh_monitor_parent_ie+0x105> */
  L_0182: a8 = a8 | a10;  /* 0182 */
  __asm__ volatile("" ::: "memory");  /* 0185: memw */
  goto L_0193;  /* 0188: j */
  L_018d: a10 = -65;  /* 018d */
  a8 = a8 & a10;  /* 0190 */
  L_0193: ST8(a3 + 0x5, a8);  /* 0193 */
  __asm__ volatile("" ::: "memory");  /* 0196: memw */
  L_0199: a6 = 2;  /* 0199 */
  if ((a9 & a6) == 0) goto L_01d1;  /* 019b: bnone a9, a6, 1d1 <esp_mesh_monitor_parent_ie+0x149> */
  L_019e: a12 = a1 + (33);  /* 019e */
  a11 = 24;  /* 01a1 */
  a10 = LD32(a5 + 0x0);  /* 01a3 */
  a10 = a10 + (2);  /* 01a5 */
  __asm__ volatile("" ::: "memory");  /* 01a7: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 01aa: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 01ad: callx a8 via reloc-expand */
  a9 = LD8U(a4 + 0x32);  /* 01b0 */
  a10 = LD8U(a1 + 0x21);  /* 01b3 */
  if (a10 == a9) goto L_01e5;  /* 01b6: beq a10, a9, 1e5 <esp_mesh_monitor_parent_ie+0x15d> */
  L_01b9: if ((a2 & a6) == 0) goto L_01c0;  /* 01b9: bnone a2, a6, 1c0 <esp_mesh_monitor_parent_ie+0x138> */
  L_01bc: goto L_01d9;  /* 01bc: j */
  L_01c0: a8 = 4;  /* 01c0 */
  a7 = a7 | a8;  /* 01c2 */
  ST8(a3 + 0xd, a9);  /* 01c5 */
  __asm__ volatile("" ::: "memory");  /* 01c8: memw */
  __asm__ volatile("" ::: "memory");  /* 01cb: memw */
  goto L_01e5;  /* 01ce: j */
  L_01d1: if ((a2 & a6) == 0) goto L_01e5;  /* 01d1: bnone a2, a6, 1e5 <esp_mesh_monitor_parent_ie+0x15d> */
  L_01d4: a8 = LD8U(a4 + 0x7);  /* 01d4 */
  if (a8 == 0) goto L_01e5;  /* 01d7: beqz.n a8, 1e5 <esp_mesh_monitor_parent_ie+0x15d> */
  L_01d9: a12 = 20;  /* 01d9 */
  a11 = a1;  /* 01db */
  a10 = 55;  /* 01dd */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 01df: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 01e2: callx a8 via reloc-expand */
  L_01e5: if (((a7 >> 4) & 1) == 0) goto L_0204;  /* 01e5: bbci a7, 4, 204 <esp_mesh_monitor_parent_ie+0x17c> */
  L_01e8: a8 = LD8U(a3 + 0x5);  /* 01e8 */
  if (((a8 >> 3) & 1) == 0) goto L_0206;  /* 01eb: bbci a8, 3, 206 <esp_mesh_monitor_parent_ie+0x17e> */
  L_01ee: a12 = 2;  /* 01ee */
  a11 = 32;  /* 01f0 */
  a14 = 0x0000159bu;  /* 01f2: l32r = 5531 */
  a10 = 1;  /* 01f5 */
  a13 = (u32)(RODATA__rodata_wlog_warning_36 + 0x0);  /* 01f7: l32r -> .rodata_wlog_warning.36 */
  a8 = (u32)&wifi_log + 0x0;  /* 01fa: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 01fd: callx a8 via reloc-expand */
  goto L_0206;  /* 0200: j */
  L_0204: if (a7 == 0) goto L_0240;  /* 0204: beqz.n a7, 240 <esp_mesh_monitor_parent_ie+0x1b8> */
  L_0206: a12 = 16;  /* 0206 */
  a11 = a3;  /* 0208 */
  a10 = a1 + (4);  /* 020a */
  ST32(a1 + 0x0, a7);  /* 020c */
  __asm__ volatile("" ::: "memory");  /* 020f: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0212: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0215: callx a8 (libc, via reloc-expand) */
  a7 = -33;  /* 0218 */
  a8 = 1;  /* 021b */
  a9 = 0;  /* 021d */
  a6 = LD32(a1 + 0x38);  /* 021f */
  a12 = 20;  /* 0221 */
  a7 = a6 & a7;  /* 0223 */
  a7 = a7 + (-16);  /* 0226 */
  if (a7 != 0) a8 = a9;  /* 0229 */
  a11 = a1;  /* 022c */
  a10 = 54;  /* 022e */
  ST8(a1 + 0x13, a8);  /* 0231 */
  __asm__ volatile("" ::: "memory");  /* 0234: memw */
  __asm__ volatile("" ::: "memory");  /* 0237: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 023a: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 023d: callx a8 via reloc-expand */
  L_0240: a7 = (u32)&g_mesh_topology + 0x0;  /* 0240: l32r -> global */
  a7 = LD32(a7 + 0x0);  /* 0243 */
  if (a7 != 0) goto L_024d;  /* 0245: bnez.n a7, 24d <esp_mesh_monitor_parent_ie+0x1c5> */
  L_0247: a9 = LD8U(a4 + 0xf);  /* 0247 */
  goto L_0259;  /* 024a: j */
  L_024d: a9 = LD8U(a4 + 0x3d);  /* 024d */
  a9 = a9 << 8;  /* 0250 */
  a7 = LD8U(a4 + 0x3c);  /* 0253 */
  a9 = a9 | a7;  /* 0256 */
  L_0259: a8 = LD32(a1 + 0x38);  /* 0259 */
  if (a8 != 128) goto L_02da;  /* 025b: bnei a8, 128, 2da <esp_mesh_monitor_parent_ie+0x252> */
  L_025e: a10 = LD8U(a4 + 0x7);  /* 025e */
  a7 = (u32)&LOCAL__bss_last_parent_layer_2 + 0x0;  /* 0261: l32r -> .bss.last_parent_layer$2 (same-object static) */
  a8 = (u32)&LOCAL__bss_monitor_count_1 + 0x0;  /* 0264: l32r -> .bss.monitor_count$1 (same-object static) */
  if (a10 == 0) goto L_0295;  /* 0267: beqz.n a10, 295 <esp_mesh_monitor_parent_ie+0x20d> */
  L_0269: a10 = LD16U(a7 + 0x0);  /* 0269 */
  if (a10 != a9) goto L_0295;  /* 026c: bne a10, a9, 295 <esp_mesh_monitor_parent_ie+0x20d> */
  L_026f: a10 = (u32)&g_mesh_monitor_parent_beacon_count + 0x0;  /* 026f: l32r -> global */
  a7 = LD8U(a8 + 0x0);  /* 0272 */
  a10 = LD32(a10 + 0x0);  /* 0275 */
  if ((i32)a7 < (i32)a10) goto L_0285;  /* 0277: blt a7, a10, 285 <esp_mesh_monitor_parent_ie+0x1fd> */
  L_027a: a7 = (u32)&LOCAL__bss_s_mesh_monitor_parent_cfg + 0x0;  /* 027a: l32r -> .bss.s_mesh_monitor_parent_cfg (same-object static) */
  a8 = LD8U(a7 + 0x0);  /* 027d */
  if (a8 == 0) goto L_02c1;  /* 0280: beqz.n a8, 2c1 <esp_mesh_monitor_parent_ie+0x239> */
  L_0282: goto L_02a8;  /* 0282: j */
  L_0285: a7 = a7 + (1);  /* 0285 */
  ST8(a8 + 0x0, a7);  /* 0287 */
  __asm__ volatile("" ::: "memory");  /* 028a: memw */
  __asm__ volatile("" ::: "memory");  /* 028d: memw */
  goto L_02a0;  /* 0290: j */
  L_0295: a2 = 0;  /* 0295 */
  ST8(a8 + 0x0, a2);  /* 0297 */
  ST16(a7 + 0x0, a9);  /* 029a */
  __asm__ volatile("" ::: "memory");  /* 029d: memw */
  L_02a0: a6 = 0;  /* 02a0 */
  __asm__ volatile("" ::: "memory");  /* 02a2: memw */
  goto L_047e;  /* 02a5: j */
  L_02a8: a11 = LD8U(a4 + 0x11);  /* 02a8 */
  a13 = a2;  /* 02ab */
  a10 = a9;  /* 02ad */
  a12 = LD32(a1 + 0x30);  /* 02af */
  ST32(a1 + 0x3c, a9);  /* 02b1 */
  __asm__ volatile("" ::: "memory");  /* 02b3: memw */
  a8 = (u32)&mesh_post_parent_weak_rssi;  /* 02b6: l32r -> func addr */
  a2 = mesh_post_parent_weak_rssi(a2, a3, a4, a5, a6, a7);  /* 02b9: callx a8 via reloc-expand */
  goto L_02d8;  /* 02bc: j */
  L_02c1: a7 = LD8U(a7 + 0x1);  /* 02c1 */
  if (a7 == 0) goto L_02da;  /* 02c4: beqz.n a7, 2da <esp_mesh_monitor_parent_ie+0x252> */
  L_02c6: a10 = a9;  /* 02c6 */
  a11 = LD8U(a4 + 0x11);  /* 02c8 */
  a12 = LD32(a1 + 0x30);  /* 02cb */
  ST32(a1 + 0x3c, a9);  /* 02cd */
  __asm__ volatile("" ::: "memory");  /* 02cf: memw */
  a8 = (u32)&mesh_post_parent_assoc_ie;  /* 02d2: l32r -> func addr */
  a2 = mesh_post_parent_assoc_ie(a2, a3, a4, a5, a6, a7);  /* 02d5: callx a8 via reloc-expand */
  L_02d8: a9 = LD32(a1 + 0x3c);  /* 02d8 */
  L_02da: a10 = 10;  /* 02da */
  a7 = a9 + (1);  /* 02dc */
  a6 = 0;  /* 02de */
  if ((a2 & a10) == 0) goto L_02e6;  /* 02e0: bnone a2, a10, 2e6 <esp_mesh_monitor_parent_ie+0x25e> */
  L_02e3: goto L_03a5;  /* 02e3: j */
  L_02e6: a2 = a4 + (31);  /* 02e6 */
  a10 = a2;  /* 02e9: mov */
  ST32(a1 + 0x3c, a9);  /* 02ec */
  __asm__ volatile("" ::: "memory");  /* 02ef: memw */
  a8 = 0;  /* 02f2: l32r -> .text.is_zero_addr+0x0 (link-time addr, kind unclear) */
  a2 = clone_is_zero_addr(a2, a3, a4, a5, a6, a7);  /* 02f5: callx a8 -> clone .text.is_zero_addr */
  a9 = LD32(a1 + 0x3c);  /* 02f8 */
  if (a10 == a6) goto L_0305;  /* 02fa: beq a10, a6, 305 <esp_mesh_monitor_parent_ie+0x27d> */
  L_02fd: a6 = 0;  /* 02fd */
  goto L_036e;  /* 02ff: j */
  L_0305: if (a9 != 1) goto L_0318;  /* 0305: bnei a9, 1, 318 <esp_mesh_monitor_parent_ie+0x290> */
  L_0308: a10 = LD32(a1 + 0x34);  /* 0308 */
  a12 = 6;  /* 030a */
  a11 = a2;  /* 030c: mov */
  a8 = (u32)&memcmp + 0x0;  /* 030f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0312: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_02fd;  /* 0315: bnez a10, 2fd <esp_mesh_monitor_parent_ie+0x275> */
  L_0318: a10 = LD32(a5 + 0x0);  /* 0318 */
  a12 = a1 + (20);  /* 031b */
  a11 = 15;  /* 031e */
  a10 = a10 + (2);  /* 0321 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0323: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0326: callx a8 via reloc-expand */
  a12 = 6;  /* 0329 */
  a11 = a2;  /* 032c: mov */
  a10 = a1 + (20);  /* 032f */
  a8 = (u32)&memcmp + 0x0;  /* 0332: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0335: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_02fd;  /* 0338: beqz a10, 2fd <esp_mesh_monitor_parent_ie+0x275> */
  L_033b: a9 = LD8U(a4 + 0x14);  /* 033b */
  a12 = 6;  /* 033e */
  a11 = a2;  /* 0340 */
  a10 = a3 + a12;  /* 0342 */
  a6 = 8;  /* 0344 */
  a8 = LD8U(a4 + 0x15);  /* 0347 */
  ST8(a3 + 0x2, a9);  /* 034a */
  ST8(a3 + 0x3, a8);  /* 034d */
  __asm__ volatile("" ::: "memory");  /* 0350: memw */
  __asm__ volatile("" ::: "memory");  /* 0353: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0356: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0359: callx a8 (libc, via reloc-expand) */
  a2 = LD8U(a4 + 0x25);  /* 035c */
  ST8(a3 + 0xc, a2);  /* 035f */
  a2 = (a7 >> 8) & 0x1ff;  /* 0362: extui width 9 */
  ST8(a3 + 0x0, a7);  /* 0365 */
  ST8(a3 + 0x1, a2);  /* 0368 */
  __asm__ volatile("" ::: "memory");  /* 036b: memw */
  L_036e: a11 = 8;  /* 036e */
  a12 = a1 + (30);  /* 0370 */
  a9 = LD32(a5 + 0x0);  /* 0373 */
  a9 = a9 + (2);  /* 0375 */
  a10 = a9;  /* 0377 */
  ST32(a1 + 0x3c, a9);  /* 0379 */
  __asm__ volatile("" ::: "memory");  /* 037b: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 037e: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0381: callx a8 via reloc-expand */
  a2 = LD8U(a4 + 0x15);  /* 0384 */
  a2 = a2 << 8;  /* 0387 */
  a11 = LD8U(a4 + 0x14);  /* 038a */
  a2 = a2 | a11;  /* 038d */
  a10 = LD16U(a1 + 0x1e);  /* 0390 */
  a9 = LD32(a1 + 0x3c);  /* 0393 */
  if (a10 == a2) goto L_03a5;  /* 0395: beq a10, a2, 3a5 <esp_mesh_monitor_parent_ie+0x31d> */
  L_0398: a12 = a4 + (20);  /* 0398 */
  a11 = 8;  /* 039b */
  a10 = a9;  /* 039d */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 039f: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5, a6, a7);  /* 03a2: callx a8 via reloc-expand */
  L_03a5: a9 = LD32(a5 + 0x0);  /* 03a5 */
  a12 = a1 + (28);  /* 03a7 */
  a2 = a9 + (2);  /* 03aa */
  a11 = 3;  /* 03ac */
  a10 = a2;  /* 03af: mov */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 03b2: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 03b5: callx a8 via reloc-expand */
  a8 = LD16U(a1 + 0x1c);  /* 03b8 */
  ST32(a1 + 0x34, a8);  /* 03bb */
  if (a8 < 3u) goto L_03f8;  /* 03bd: bltui a8, 3, 3f8 <esp_mesh_monitor_parent_ie+0x370> */
  L_03c0: a10 = 0;  /* 03c0 */
  a12 = a1 + (26);  /* 03c2 */
  a11 = 10;  /* 03c5 */
  ST16(a1 + 0x1a, a10);  /* 03c7 */
  __asm__ volatile("" ::: "memory");  /* 03ca: memw */
  a10 = a2;  /* 03cd: mov */
  __asm__ volatile("" ::: "memory");  /* 03d0: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 03d3: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 03d6: callx a8 via reloc-expand */
  a10 = LD8U(a4 + 0x19);  /* 03d9 */
  a10 = a10 << 8;  /* 03dc */
  a12 = LD8U(a4 + 0x18);  /* 03df */
  a10 = a10 | a12;  /* 03e2 */
  a11 = LD16U(a1 + 0x1a);  /* 03e5 */
  if (a11 == a10) goto L_03f8;  /* 03e8: beq a11, a10, 3f8 <esp_mesh_monitor_parent_ie+0x370> */
  L_03eb: a12 = a4 + (24);  /* 03eb */
  a11 = 10;  /* 03ee */
  a10 = a2;  /* 03f0 */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 03f2: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5, a6, a7);  /* 03f5: callx a8 via reloc-expand */
  L_03f8: a2 = LD32(a1 + 0x34);  /* 03f8 */
  if (a2 == a7) goto L_0410;  /* 03fb: beq a2, a7, 410 <esp_mesh_monitor_parent_ie+0x388> */
  L_03fe: a2 = 1;  /* 03fe */
  a6 = a6 | a2;  /* 0401 */
  ST8(a3 + 0x0, a7);  /* 0404 */
  a7 = (a7 >> 8) & 0x1ff;  /* 0407: extui width 9 */
  ST8(a3 + 0x1, a7);  /* 040a */
  __asm__ volatile("" ::: "memory");  /* 040d: memw */
  L_0410: a12 = a1 + (34);  /* 0410 */
  a11 = 21;  /* 0413 */
  a10 = LD32(a5 + 0x0);  /* 0415 */
  a10 = a10 + (2);  /* 0418 */
  __asm__ volatile("" ::: "memory");  /* 041b: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 041e: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0421: callx a8 via reloc-expand */
  a2 = LD8U(a4 + 0x39);  /* 0424 */
  a4 = LD8U(a1 + 0x22);  /* 0427 */
  if (a4 == a2) goto L_043e;  /* 042a: beq a4, a2, 43e <esp_mesh_monitor_parent_ie+0x3b6> */
  L_042d: a4 = 2;  /* 042d */
  a6 = a6 | a4;  /* 042f */
  ST8(a3 + 0xe, a2);  /* 0432 */
  __asm__ volatile("" ::: "memory");  /* 0435: memw */
  __asm__ volatile("" ::: "memory");  /* 0438: memw */
  goto L_0440;  /* 043b: j */
  L_043e: if (a6 == 0) goto L_047e;  /* 043e: beqz.n a6, 47e <esp_mesh_monitor_parent_ie+0x3f6> */
  L_0440: a11 = a3;  /* 0440 */
  a12 = 16;  /* 0442 */
  a10 = a1 + (4);  /* 0444 */
  ST32(a1 + 0x0, a6);  /* 0446 */
  __asm__ volatile("" ::: "memory");  /* 0448: memw */
  a8 = (u32)&memcpy + 0x0;  /* 044b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 044e: callx a8 (libc, via reloc-expand) */
  a2 = -33;  /* 0451 */
  a3 = 0;  /* 0454 */
  a12 = 20;  /* 0456 */
  a8 = LD32(a1 + 0x38);  /* 0458 */
  a11 = a1;  /* 045a */
  a6 = a8 & a2;  /* 045c */
  a6 = a6 + (-16);  /* 045f */
  a2 = 1;  /* 0462 */
  if (a6 != 0) a2 = a3;  /* 0464 */
  a10 = 54;  /* 0467 */
  ST8(a1 + 0x13, a2);  /* 0469 */
  __asm__ volatile("" ::: "memory");  /* 046c: memw */
  __asm__ volatile("" ::: "memory");  /* 046f: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 0472: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 0475: callx a8 via reloc-expand */
  goto L_02a0;  /* 0478: j */
  L_047c: a6 = -1;  /* 047c */
  L_047e: a2 = a6;  /* 047e */
  return a2;  /* 0480: retw.n */
}


/* esp_mesh_monitor_vote_candidate_rssi @ mesh_quick.o 00000028 size 226B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp, ieee80211_mesh_quick_set | Data refs: esp_mesh_appie
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=3, refs=4); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_monitor_vote_candidate_rssi(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a8, a9;
  /* 0028: entry a1, 48 (frame 48 bytes) */
  a8 = 1;  /* 002b */
  a4 = 0;  /* 002d */
  if (a3 == 0) a4 = a8;  /* 002f */
  a5 = (a4 >> 8) & 0x1;  /* 0032: extui width 1 */
  if (a4 != 0) goto L_003c;  /* 0035: bnez.n a4, 3c <esp_mesh_monitor_vote_candidate_rssi+0x14> */
  L_0037: if (a2 != 0) a8 = a5;  /* 0037 */
  if (a8 == 0) goto L_0041;  /* 003a: beqz.n a8, 41 <esp_mesh_monitor_vote_candidate_rssi+0x19> */
  L_003c: a2 = -1;  /* 003c */
  goto L_0108;  /* 003e: j */
  L_0041: a5 = (u32)&esp_mesh_appie + 0x0;  /* 0041: l32r -> global */
  a12 = a1;  /* 0044 */
  a11 = 15;  /* 0046 */
  a4 = LD32(a5 + 0x0);  /* 0048 */
  a4 = a4 + (2);  /* 004a */
  a10 = a4;  /* 004c */
  ST8(a1 + 0x7, a8);  /* 004e */
  ST32(a1 + 0x0, a8);  /* 0051 */
  ST16(a1 + 0x4, a8);  /* 0053 */
  __asm__ volatile("" ::: "memory");  /* 0056: memw */
  __asm__ volatile("" ::: "memory");  /* 0059: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 005c: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 005f: callx a8 via reloc-expand */
  a12 = 6;  /* 0062 */
  a11 = a1;  /* 0064 */
  a10 = a2;  /* 0066 */
  a8 = (u32)&memcmp + 0x0;  /* 0068: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 006b: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00a0;  /* 006e: bnez.n a10, a0 <esp_mesh_monitor_vote_candidate_rssi+0x78> */
  L_0070: a12 = a1 + (6);  /* 0070 */
  a11 = 16;  /* 0072 */
  a10 = a4;  /* 0074 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0076: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0079: callx a8 via reloc-expand */
  a9 = LD8U(a3 + 0x1d);  /* 007c */
  a10 = (i32)(a9 << (32 - 7)) >> (32 - 7);  /* 007f: sext */
  a8 = LD8U(a1 + 0x6);  /* 0082 */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 0085: sext */
  if (a8 == a10) goto L_00a0;  /* 0088: beq a8, a10, a0 <esp_mesh_monitor_vote_candidate_rssi+0x78> */
  L_008b: a12 = a1 + (6);  /* 008b */
  a11 = 16;  /* 008d */
  a10 = a4;  /* 008f */
  ST8(a1 + 0x6, a9);  /* 0091 */
  __asm__ volatile("" ::: "memory");  /* 0094: memw */
  __asm__ volatile("" ::: "memory");  /* 0097: memw */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 009a: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5, a6, a7);  /* 009d: callx a8 via reloc-expand */
  L_00a0: a12 = a1 + (7);  /* 00a0 */
  a11 = 14;  /* 00a2 */
  a4 = LD32(a5 + 0x0);  /* 00a4 */
  a4 = a4 + (2);  /* 00a6 */
  a10 = a4;  /* 00a8 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00aa: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 00ad: callx a8 via reloc-expand */
  a5 = LD8U(a1 + 0x7);  /* 00b0 */
  if (((a5 >> 2) & 1) == 0) goto L_003c;  /* 00b3: bbci a5, 2, 3c <esp_mesh_monitor_vote_candidate_rssi+0x14> */
  L_00b6: a12 = a1;  /* 00b6 */
  a11 = 17;  /* 00b8 */
  a10 = a4;  /* 00ba */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00bc: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 00bf: callx a8 via reloc-expand */
  a10 = a2;  /* 00c2 */
  a12 = 6;  /* 00c4 */
  a11 = a1;  /* 00c6 */
  a8 = (u32)&memcmp + 0x0;  /* 00c8: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00cb: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 00ce */
  if (a10 == 0) goto L_00d8;  /* 00d0: beqz.n a10, d8 <esp_mesh_monitor_vote_candidate_rssi+0xb0> */
  L_00d2: a2 = 0;  /* 00d2 */
  goto L_0108;  /* 00d4: j */
  L_00d8: a12 = a1 + (6);  /* 00d8 */
  a11 = 18;  /* 00da */
  a10 = a4;  /* 00dc */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00de: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 00e1: callx a8 via reloc-expand */
  a5 = LD8U(a3 + 0x1d);  /* 00e4 */
  a8 = (i32)(a5 << (32 - 7)) >> (32 - 7);  /* 00e7: sext */
  a3 = LD8U(a1 + 0x6);  /* 00ea */
  a3 = (i32)(a3 << (32 - 7)) >> (32 - 7);  /* 00ed: sext */
  if (a3 == a8) goto L_00d2;  /* 00f0: beq a3, a8, d2 <esp_mesh_monitor_vote_candidate_rssi+0xaa> */
  L_00f3: a12 = a1 + (6);  /* 00f3 */
  a11 = 18;  /* 00f5 */
  a10 = a4;  /* 00f7 */
  ST8(a1 + 0x6, a5);  /* 00f9 */
  __asm__ volatile("" ::: "memory");  /* 00fc: memw */
  __asm__ volatile("" ::: "memory");  /* 00ff: memw */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 0102: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5, a6, a7);  /* 0105: callx a8 via reloc-expand */
  L_0108: return a2;  /* 0108: retw.n */
}


/* esp_mesh_parse_beacon @ mesh_quick.o 00000044 size 266B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp, wifi_disconnect_process, esp_mesh_monitor_parent_ie, esp_mesh_monitor_parent_candidate_ie, esp_mesh_is_same_router, esp_mesh_is_root_conflicts_allowed, mesh_check_conflict_beacon, esp_mesh_parse_conflict_assoc_ie, esp_mesh_parse_conflict_roots_ie, esp_mesh_monitor_vote_candidate_rssi | Data refs: esp_mesh_appie, g_mesh_is_root, .bss.s_mesh_parent_candidate
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=11, refs=14); reloc-direct=11, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_parse_beacon(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8;
  float F6;
  /* 0044: entry a1, 64 (frame 64 bytes) */
  ST32(a1 + 0x10, a7);  /* 0047 */
  a2 = (a2 >> 8) & 0x1;  /* 0049: extui width 1 */
  a7 = -1;  /* 004c */
  if (a3 == 0) goto L_014a;  /* 004e: beqz a3, 14a <esp_mesh_parse_beacon+0x106> */
  L_0051: a8 = 0;  /* 0051 */
  a7 = LD32(a6 + 0x0);  /* 0053 */
  ST32(a1 + 0x0, a8);  /* 0055 */
  ST16(a1 + 0x4, a8);  /* 0057 */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  if (a7 == a8) goto L_00a4;  /* 005d: beq a7, a8, a4 <esp_mesh_parse_beacon+0x60> */
  L_0060: a12 = a1;  /* 0060 */
  a11 = 1;  /* 0062 */
  a8 = (u32)&esp_mesh_appie + 0x0;  /* 0064: l32r -> global */
  a10 = LD32(a8 + 0x0);  /* 0067 */
  a10 = a10 + (2);  /* 0069 */
  __asm__ volatile("" ::: "memory");  /* 006b: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 006e: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 via reloc-expand */
  a12 = 6;  /* 0074 */
  a11 = a7 + (8);  /* 0076 */
  a10 = a1;  /* 0078 */
  a8 = (u32)&memcmp + 0x0;  /* 007a: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 007d: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_00a4;  /* 0080: beqz.n a10, a4 <esp_mesh_parse_beacon+0x60> */
  L_0082: if (a2 != 0) goto L_0087;  /* 0082: bnez.n a2, 87 <esp_mesh_parse_beacon+0x43> */
  L_0084: goto L_0148;  /* 0084: j */
  L_0087: a12 = 6;  /* 0087 */
  a11 = a4;  /* 0089: mov */
  a10 = a3;  /* 008c: mov */
  a8 = (u32)&memcmp + 0x0;  /* 008f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0092: callx a8 (libc, via reloc-expand) */
  a7 = a10;  /* 0095 */
  if (a10 != 0) goto L_0148;  /* 0097: bnez a10, 148 <esp_mesh_parse_beacon+0x104> */
  L_009a: a8 = (u32)&wifi_disconnect_process + 0x0;  /* 009a: l32r -> global */
  a2 = wifi_disconnect_process(a2, a3, a4, a5, a6, a7);  /* 009d: callx a8 via reloc-expand */
  goto L_014a;  /* 00a0: j */
  L_00a4: if (a2 == 0) goto L_00f6;  /* 00a4: beqz a2, f6 <esp_mesh_parse_beacon+0xb2> */
  L_00a7: a8 = (u32)&g_mesh_is_root + 0x0;  /* 00a7: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 00aa: memw */
  a8 = LD8U(a8 + 0x0);  /* 00ad */
  a8 = (a8 >> 8) & 0x1;  /* 00b0: extui width 1 */
  if (a8 != 0) goto L_00f6;  /* 00b3: bnez.n a8, f6 <esp_mesh_parse_beacon+0xb2> */
  L_00b5: a12 = 6;  /* 00b5 */
  a11 = a4;  /* 00b7 */
  a10 = a3;  /* 00b9 */
  a8 = (u32)&memcmp + 0x0;  /* 00bb: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00be: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00d9;  /* 00c1: bnez.n a10, d9 <esp_mesh_parse_beacon+0x95> */
  L_00c3: a13 = a5;  /* 00c3 */
  a12 = a7;  /* 00c5: mov */
  a11 = a3;  /* 00c8: mov */
  a10 = 128;  /* 00cb */
  a8 = (u32)&esp_mesh_monitor_parent_ie;  /* 00ce: l32r -> func addr */
  a2 = esp_mesh_monitor_parent_ie(a2, a3, a4, a5, a6, a7);  /* 00d1: callx a8 via reloc-expand */
  goto L_00f6;  /* 00d4: j */
  L_00d9: a11 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 00d9: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a12 = 6;  /* 00dc */
  a10 = a3;  /* 00de */
  a8 = (u32)&memcmp + 0x0;  /* 00e0: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00e3: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00f6;  /* 00e6: bnez.n a10, f6 <esp_mesh_parse_beacon+0xb2> */
  L_00e8: a12 = a5;  /* 00e8 */
  a11 = a7;  /* 00ea: mov */
  a10 = a3;  /* 00ed: mov */
  a8 = (u32)&esp_mesh_monitor_parent_candidate_ie;  /* 00f0: l32r -> func addr */
  a2 = esp_mesh_monitor_parent_candidate_ie(a2, a3, a4, a5, a6, a7);  /* 00f3: callx a8 via reloc-expand */
  L_00f6: a10 = LD32(a6 + 0x4);  /* 00f6 */
  a8 = (u32)&esp_mesh_is_same_router;  /* 00f8: l32r -> func addr */
  a2 = esp_mesh_is_same_router(a2, a3, a4, a5, a6, a7);  /* 00fb: callx a8 via reloc-expand */
  a4 = a10;  /* 00fe */
  a8 = (u32)&esp_mesh_is_root_conflicts_allowed + 0x0;  /* 0100: l32r -> global */
  a2 = esp_mesh_is_root_conflicts_allowed(a2, a3, a4, a5, a6, a7);  /* 0103: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0138;  /* 0106: bnez.n a10, 138 <esp_mesh_parse_beacon+0xf4> */
  L_0108: a8 = a4 + (-1);  /* 0108 */
  a12 = 1;  /* 010a */
  if (a8 != 0) a12 = a10;  /* 010c */
  a11 = a6;  /* 010f */
  a10 = a3;  /* 0111: mov */
  a8 = (u32)&mesh_check_conflict_beacon;  /* 0114: l32r -> func addr */
  a2 = mesh_check_conflict_beacon(a2, a3, a4, a5, a6, a7);  /* 0117: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0138;  /* 011a: bnez.n a10, 138 <esp_mesh_parse_beacon+0xf4> */
  L_011c: if (a2 == 0) goto L_012a;  /* 011c: beqz.n a2, 12a <esp_mesh_parse_beacon+0xe6> */
  L_011e: a12 = a5;  /* 011e */
  a11 = a6;  /* 0120 */
  a10 = a3;  /* 0122 */
  a8 = (u32)&esp_mesh_parse_conflict_assoc_ie;  /* 0124: l32r -> func addr */
  a2 = esp_mesh_parse_conflict_assoc_ie(a2, a3, a4, a5, a6, a7);  /* 0127: callx a8 via reloc-expand */
  L_012a: a12 = LD32(a1 + 0x10);  /* 012a */
  a10 = a3;  /* 012c: mov */
  a11 = LD32(a6 + 0x0);  /* 012f */
  a8 = (u32)&esp_mesh_parse_conflict_roots_ie;  /* 0132: l32r -> func addr */
  a2 = esp_mesh_parse_conflict_roots_ie(a2, a3, a4, a5, a6, a7);  /* 0135: callx a8 via reloc-expand */
  L_0138: if (a4 != 1) goto L_0148;  /* 0138: bnei a4, 1, 148 <esp_mesh_parse_beacon+0x104> */
  L_013b: a12 = a5;  /* 013b */
  a11 = a7;  /* 013d: mov */
  a10 = a3;  /* 0140 */
  a8 = (u32)&esp_mesh_monitor_vote_candidate_rssi;  /* 0142: l32r -> func addr */
  a2 = esp_mesh_monitor_vote_candidate_rssi(a2, a3, a4, a5, a6, a7);  /* 0145: callx a8 via reloc-expand */
  L_0148: a7 = 0;  /* 0148 */
  L_014a: a2 = a7;  /* 014a */
  return a2;  /* 014c: retw.n */
}


/* esp_mesh_parse_conflict_assoc_ie @ mesh_quick.o 000000a4 size 1072B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, clone_is_zero_addr, memcmp, wifi_log, memcpy, ieee80211_is_mesh_roots_announce, ieee80211_is_mesh_roots_yield, ieee80211_is_mesh_roots_fixed, ieee80211_is_mesh_roots_gone, memset, sprintf, mesh_is_new_found_conflict_root, ieee80211_vnd_mesh_roots_set, wifi_get_macaddr, esp_mesh_remove_conflict_root, esp_mesh_get_conflict_root_state, wifi_mesh_event_post, esp_mesh_update_conflict_root | indirect[6]: mem[a6+0x110]; mem[a5+0x110]; mem[a6+0x158]; mem[a6+0x150] | Data refs: .bss.monitor_time_start$5, g_osi_funcs_p, esp_mesh_appie, .text.is_zero_addr, g_mesh_topology, .rodata_wlog_warning.31, .rodata.mesh_parse_ps_entire_rule.str1.1, .rodata.esp_mesh_ps_duty_cycle_get_process.str1.1, .rodata._mesh_timer_process_conflict_root.str1.1, g_mesh_max_layer, .rodata.esp_mesh_parse_conflict_assoc_ie.str1.1, .bss.s_mesh_conflict_roots
 * Fidelity: medium - 6 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=17, refs=28); reloc-direct=18, funcdb-attributed=0, unknown-indirect=6 */
u32 esp_mesh_parse_conflict_assoc_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F2;
  /* 00a4: entry a1, 224 (frame 224 bytes) */
  a3 = LD32(a3 + 0x0);  /* 00a7 */
  a4 = 1;  /* 00a9 */
  a5 = 0;  /* 00ab */
  if (a3 == 0) a5 = a4;  /* 00ad */
  a6 = (a5 >> 8) & 0x1;  /* 00b0: extui width 1 */
  if (a5 != 0) goto L_00ba;  /* 00b3: bnez.n a5, ba <esp_mesh_parse_conflict_assoc_ie+0x16> */
  L_00b5: if (a2 != 0) a4 = a6;  /* 00b5 */
  if (a4 == 0) goto L_00bf;  /* 00b8: beqz.n a4, bf <esp_mesh_parse_conflict_assoc_ie+0x1b> */
  L_00ba: a5 = -1;  /* 00ba */
  goto L_04d0;  /* 00bc: j */
  L_00bf: a4 = (u32)&LOCAL__bss_monitor_time_start_5 + 0x0;  /* 00bf: l32r -> .bss.monitor_time_start$5 (same-object static) */
  a5 = LD32(a4 + 0x4);  /* 00c2 */
  a6 = LD32(a4 + 0x0);  /* 00c4 */
  a6 = a6 | a5;  /* 00c6 */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 00c9: l32r -> global */
  if (a6 != 0) goto L_00da;  /* 00cc: bnez.n a6, da <esp_mesh_parse_conflict_assoc_ie+0x36> */
  L_00ce: a6 = LD32(a5 + 0x0);  /* 00ce */
  a10 = LD32(a6 + 0x110);  /* 00d0 */
  /* 00d3: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  ST32(a4 + 0x0, a10);  /* 00d6 */
  ST32(a4 + 0x4, a11);  /* 00d8 */
  L_00da: a6 = LD32(a5 + 0x0);  /* 00da */
  a10 = LD32(a6 + 0x110);  /* 00dc */
  __asm__ volatile("" ::: "memory");  /* 00df: memw */
  /* 00e2: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a6 = LD32(a4 + 0x4);  /* 00e5 */
  if ((i32)a11 < (i32)a6) goto L_015a;  /* 00e7: blt a11, a6, 15a <esp_mesh_parse_conflict_assoc_ie+0xb6> */
  L_00ea: if (a6 != a11) goto L_00f2;  /* 00ea: bne a6, a11, f2 <esp_mesh_parse_conflict_assoc_ie+0x4e> */
  L_00ed: a6 = LD32(a4 + 0x0);  /* 00ed */
  if (a10 < a6) goto L_015a;  /* 00ef: bltu a10, a6, 15a <esp_mesh_parse_conflict_assoc_ie+0xb6> */
  L_00f2: a5 = LD32(a5 + 0x0);  /* 00f2 */
  a10 = LD32(a5 + 0x110);  /* 00f4 */
  /* 00f7: INDIRECT callx a10 <- mem[a5+0x110]; result unknown */ a2 = 0;
  a5 = LD32(a4 + 0x0);  /* 00fa */
  a6 = LD32(a4 + 0x4);  /* 00fc */
  a4 = a10 - a5;  /* 00fe: sub */
  a5 = 1;  /* 0101 */
  if (a10 < a4) goto L_0108;  /* 0103: bltu a10, a4, 108 <esp_mesh_parse_conflict_assoc_ie+0x64> */
  L_0106: a5 = 0;  /* 0106 */
  L_0108: a11 = a11 - a6;  /* 0108: sub */
  a11 = a11 - a5;  /* 010b: sub */
  a5 = a11 << 22;  /* 010e */
  a4 = a4 >> 10;  /* 0111 */
  a11 = (i32)a11 >> 10;  /* 0114 */
  a4 = a5 | a4;  /* 0117 */
  if ((i32)a11 >= 1) goto L_0126;  /* 011a: bgei a11, 1, 126 <esp_mesh_parse_conflict_assoc_ie+0x82> */
  L_011d: if (a11 != 0) goto L_00ba;  /* 011d: bnez a11, ba <esp_mesh_parse_conflict_assoc_ie+0x16> */
  L_0120: a5 = 0x0000270fu;  /* 0120: l32r = 9999 */
  if (a5 >= a4) goto L_00ba;  /* 0123: bgeu a5, a4, ba <esp_mesh_parse_conflict_assoc_ie+0x16> */
  L_0126: a4 = 0;  /* 0126 */
  a11 = 15;  /* 0128 */
  ST32(a1 + 0x8c, a4);  /* 012a */
  ST16(a1 + 0x90, a4);  /* 012d */
  __asm__ volatile("" ::: "memory");  /* 0130: memw */
  a4 = a1 + (80);  /* 0133 */
  a6 = a4 + (60);  /* 0136 */
  a12 = a6;  /* 0139 */
  a4 = (u32)&esp_mesh_appie + 0x0;  /* 013b: l32r -> global */
  a10 = LD32(a4 + 0x0);  /* 013e */
  a10 = a10 + (2);  /* 0140 */
  __asm__ volatile("" ::: "memory");  /* 0143: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0146: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0149: callx a8 via reloc-expand */
  a10 = a6;  /* 014c */
  a8 = 0;  /* 014e: l32r -> .text.is_zero_addr+0x0 (link-time addr, kind unclear) */
  a2 = clone_is_zero_addr(a2, a3, a4, a5, a6, a7);  /* 0151: callx a8 -> clone .text.is_zero_addr */
  if (a10 == 0) goto L_01a0;  /* 0154: beqz a10, 1a0 <esp_mesh_parse_conflict_assoc_ie+0xfc> */
  L_0157: goto L_00ba;  /* 0157: j */
  L_015a: a5 = LD32(a5 + 0x0);  /* 015a */
  a6 = -1;  /* 015c */
  a10 = LD32(a5 + 0x110);  /* 015e */
  /* 0161: INDIRECT callx a10 <- mem[a5+0x110]; result unknown */ a2 = 0;
  a5 = LD32(a4 + 0x0);  /* 0164 */
  a5 = a5 ^ a6;  /* 0166 */
  a10 = a5 + a10;  /* 0169 */
  a6 = 1;  /* 016b */
  a4 = LD32(a4 + 0x4);  /* 016d */
  if (a10 < a5) goto L_0174;  /* 016f: bltu a10, a5, 174 <esp_mesh_parse_conflict_assoc_ie+0xd0> */
  L_0172: a6 = 0;  /* 0172 */
  L_0174: a11 = a4 + a11;  /* 0174 */
  a5 = a10 + (1);  /* 0176 */
  a11 = a6 + a11;  /* 0178 */
  a4 = 1;  /* 017a */
  if (a5 < a10) goto L_0181;  /* 017c: bltu a5, a10, 181 <esp_mesh_parse_conflict_assoc_ie+0xdd> */
  L_017f: a4 = 0;  /* 017f */
  L_0181: a4 = a4 + a11;  /* 0181 */
  a6 = a4 << 22;  /* 0183 */
  a5 = a5 >> 10;  /* 0186 */
  a4 = (i32)a4 >> 10;  /* 0189 */
  a5 = a6 | a5;  /* 018c */
  if ((i32)a4 >= 1) goto L_0126;  /* 018f: bgei a4, 1, 126 <esp_mesh_parse_conflict_assoc_ie+0x82> */
  L_0192: if (a4 != 0) goto L_00ba;  /* 0192: bnez a4, ba <esp_mesh_parse_conflict_assoc_ie+0x16> */
  L_0195: a4 = 0x0000270fu;  /* 0195: l32r = 9999 */
  if (a4 < a5) goto L_0126;  /* 0198: bltu a4, a5, 126 <esp_mesh_parse_conflict_assoc_ie+0x82> */
  L_019b: goto L_00ba;  /* 019b: j */
  L_01a0: a7 = LD8U(a3 + 0x7);  /* 01a0 */
  if (a7 == 0) goto L_00ba;  /* 01a3: beqz a7, ba <esp_mesh_parse_conflict_assoc_ie+0x16> */
  L_01a6: a4 = a3 + (31);  /* 01a6 */
  a10 = a4;  /* 01a9 */
  a8 = 0;  /* 01ab: l32r -> .text.is_zero_addr+0x0 (link-time addr, kind unclear) */
  a2 = clone_is_zero_addr(a2, a3, a4, a5, a6, a7);  /* 01ae: callx a8 -> clone .text.is_zero_addr */
  a5 = a10;  /* 01b1 */
  if (a10 != 0) goto L_00ba;  /* 01b3: bnez a10, ba <esp_mesh_parse_conflict_assoc_ie+0x16> */
  L_01b6: a12 = 6;  /* 01b6 */
  a11 = a6;  /* 01b8: mov */
  a10 = a4;  /* 01bb: mov */
  a8 = (u32)&memcmp + 0x0;  /* 01be: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 01c1: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_00ba;  /* 01c4: beqz a10, ba <esp_mesh_parse_conflict_assoc_ie+0x16> */
  L_01c7: a6 = LD8U(a3 + 0x25);  /* 01c7 */
  a8 = -120;  /* 01ca */
  a6 = (i32)(a6 << (32 - 7)) >> (32 - 7);  /* 01cd: sext */
  if (a6 != a8) goto L_01d6;  /* 01d0: bne a6, a8, 1d6 <esp_mesh_parse_conflict_assoc_ie+0x132> */
  L_01d3: goto L_00ba;  /* 01d3: j */
  L_01d6: if (a7 == 1) goto L_01dc;  /* 01d6: beqi a7, 1, 1dc <esp_mesh_parse_conflict_assoc_ie+0x138> */
  L_01d9: goto L_02ea;  /* 01d9: j */
  L_01dc: a12 = 6;  /* 01dc */
  a11 = a4;  /* 01de */
  a10 = a2;  /* 01e0 */
  a8 = (u32)&memcmp + 0x0;  /* 01e2: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 01e5: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_02ea;  /* 01e8: beqz a10, 2ea <esp_mesh_parse_conflict_assoc_ie+0x246> */
  L_01eb: a8 = LD8U(a2 + 0x1);  /* 01eb */
  ST32(a1 + 0xa0, a8);  /* 01ee */
  a8 = LD8U(a2 + 0x2);  /* 01f1 */
  ST32(a1 + 0xa4, a8);  /* 01f4 */
  a8 = LD8U(a2 + 0x3);  /* 01f7 */
  ST32(a1 + 0xa8, a8);  /* 01fa */
  a8 = LD8U(a2 + 0x4);  /* 01fd */
  ST32(a1 + 0xac, a8);  /* 0200 */
  a8 = LD8U(a2 + 0x5);  /* 0203 */
  ST32(a1 + 0xb0, a8);  /* 0206 */
  a8 = LD8U(a3 + 0x1f);  /* 0209 */
  ST32(a1 + 0xb4, a8);  /* 020c */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 020f: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0212 */
  a15 = LD8U(a2 + 0x0);  /* 0214 */
  a11 = LD8U(a3 + 0x20);  /* 0217 */
  a12 = LD8U(a3 + 0x21);  /* 021a */
  a13 = LD8U(a3 + 0x22);  /* 021d */
  a14 = LD8U(a3 + 0x23);  /* 0220 */
  a7 = LD8U(a3 + 0x24);  /* 0223 */
  if (a8 != 0) goto L_0234;  /* 0226: bnez.n a8, 234 <esp_mesh_parse_conflict_assoc_ie+0x190> */
  L_0228: a9 = LD8U(a3 + 0xf);  /* 0228 */
  a8 = LD8U(a3 + 0xe);  /* 022b */
  __asm__ volatile("" ::: "memory");  /* 022e: memw */
  goto L_024c;  /* 0231: j */
  L_0234: a9 = LD8U(a3 + 0x3d);  /* 0234 */
  a9 = a9 << 8;  /* 0237 */
  a8 = LD8U(a3 + 0x3c);  /* 023a */
  a9 = a9 | a8;  /* 023d */
  a8 = LD8U(a3 + 0x3b);  /* 0240 */
  a8 = a8 << 8;  /* 0243 */
  a10 = LD8U(a3 + 0x3a);  /* 0246 */
  a8 = a8 | a10;  /* 0249 */
  L_024c: a8 = a8 + a9;  /* 024c */
  ST32(a1 + 0x44, a6);  /* 024e */
  a6 = LD8U(a3 + 0x17);  /* 0251 */
  a6 = a6 << 8;  /* 0254 */
  a10 = LD8U(a3 + 0x16);  /* 0257 */
  a6 = a6 | a10;  /* 025a */
  ST32(a1 + 0x40, a6);  /* 025d */
  a10 = LD8U(a3 + 0x15);  /* 0260 */
  a10 = a10 << 8;  /* 0263 */
  a6 = LD8U(a3 + 0x14);  /* 0266 */
  a10 = a10 | a6;  /* 0269 */
  ST32(a1 + 0x3c, a10);  /* 026c */
  a10 = 1;  /* 026e */
  a6 = LD8U(a3 + 0x10);  /* 0270 */
  ST32(a1 + 0x38, a6);  /* 0273 */
  a6 = LD8U(a3 + 0x11);  /* 0275 */
  ST32(a1 + 0x30, a8);  /* 0278 */
  ST32(a1 + 0x34, a6);  /* 027a */
  a8 = LD32(a1 + 0xb0);  /* 027c */
  a6 = LD32(a1 + 0xb4);  /* 027f */
  ST32(a1 + 0x10, a8);  /* 0282 */
  ST32(a1 + 0x14, a6);  /* 0284 */
  a8 = LD32(a1 + 0xa8);  /* 0286 */
  a6 = LD32(a1 + 0xac);  /* 0289 */
  ST32(a1 + 0x24, a14);  /* 028c */
  ST32(a1 + 0x20, a13);  /* 028e */
  ST32(a1 + 0x18, a11);  /* 0290 */
  a11 = 1;  /* 0292 */
  a11 = a11 << 21;  /* 0294 */
  ST32(a1 + 0xc, a6);  /* 0297 */
  ST32(a1 + 0x8, a8);  /* 0299 */
  a6 = LD32(a1 + 0xa4);  /* 029b */
  a8 = LD32(a1 + 0xa0);  /* 029e */
  a14 = 0x00001396u;  /* 02a1: l32r = 5014 */
  a13 = (u32)(RODATA__rodata_wlog_warning_31 + 0x0);  /* 02a4: l32r -> .rodata_wlog_warning.31 */
  ST32(a1 + 0x1c, a12);  /* 02a7 */
  a12 = 2;  /* 02a9 */
  ST32(a1 + 0x4, a6);  /* 02ab */
  ST32(a1 + 0x2c, a9);  /* 02ad */
  ST32(a1 + 0x28, a7);  /* 02af */
  ST32(a1 + 0x0, a8);  /* 02b1 */
  __asm__ volatile("" ::: "memory");  /* 02b3: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 02b6: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 02b9: callx a8 via reloc-expand */
  a6 = (u32)&g_osi_funcs_p + 0x0;  /* 02bc: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 02bf */
  if (a6 == 0) goto L_02ea;  /* 02c1: beqz.n a6, 2ea <esp_mesh_parse_conflict_assoc_ie+0x246> */
  L_02c3: a7 = LD32(a6 + 0x150);  /* 02c3 */
  if (a7 == 0) goto L_02ea;  /* 02c6: beqz.n a7, 2ea <esp_mesh_parse_conflict_assoc_ie+0x246> */
  L_02c8: a10 = LD32(a6 + 0x158);  /* 02c8 */
  /* 02cb: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02ce */
  a10 = 1;  /* 02d0 */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 02d2: -> "child(cidx:" */
  a14 = a11;  /* 02d5: mov */
  a6 = 0x000013a2u;  /* 02d8: l32r = 5026 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 02db: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata__mesh_timer_process_conflict_root_str1_1 + 0x0);  /* 02de: l32r -> .rodata._mesh_timer_process_conflict_root.str1.1 */
  ST32(a1 + 0x0, a6);  /* 02e1 */
  __asm__ volatile("" ::: "memory");  /* 02e4: memw */
  /* 02e7: INDIRECT callx a7 <- mem[a6+0x150]; result unknown */ a2 = 0;
  L_02ea: a6 = 0;  /* 02ea */
  a11 = a3 + (31);  /* 02ec */
  a12 = 6;  /* 02ef */
  ST8(a1 + 0x7f, a6);  /* 02f1 */
  __asm__ volatile("" ::: "memory");  /* 02f4: memw */
  a10 = a1 + (120);  /* 02f7 */
  a6 = (u32)&g_mesh_max_layer + 0x0;  /* 02fa: l32r -> global */
  a7 = LD16U(a6 + 0x0);  /* 02fd */
  a7 = a7 + (-1);  /* 0300 */
  ST16(a1 + 0x74, a7);  /* 0302 */
  __asm__ volatile("" ::: "memory");  /* 0305: memw */
  a7 = LD8U(a3 + 0x15);  /* 0308 */
  a7 = a7 << 8;  /* 030b */
  a8 = LD8U(a3 + 0x14);  /* 030e */
  a7 = a7 | a8;  /* 0311 */
  ST16(a1 + 0x76, a7);  /* 0314 */
  __asm__ volatile("" ::: "memory");  /* 0317: memw */
  a7 = LD8U(a3 + 0x25);  /* 031a */
  ST8(a1 + 0x7e, a7);  /* 031d */
  __asm__ volatile("" ::: "memory");  /* 0320: memw */
  __asm__ volatile("" ::: "memory");  /* 0323: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0326: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0329: callx a8 (libc, via reloc-expand) */
  a3 = LD8U(a3 + 0x7);  /* 032c */
  if (a3 == 1) goto L_0364;  /* 032f: beqi a3, 1, 364 <esp_mesh_parse_conflict_assoc_ie+0x2c0> */
  L_0332: a11 = 0;  /* 0332 */
  a10 = a1 + (116);  /* 0334 */
  a8 = (u32)&ieee80211_is_mesh_roots_announce;  /* 0337: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_announce(a2, a3, a4, a5, a6, a7);  /* 033a: callx a8 via reloc-expand */
  if (a10 != 0) goto L_04d0;  /* 033d: bnez a10, 4d0 <esp_mesh_parse_conflict_assoc_ie+0x42c> */
  L_0340: a10 = a4;  /* 0340: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_yield;  /* 0343: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_yield(a2, a3, a4, a5, a6, a7);  /* 0346: callx a8 via reloc-expand */
  if (a10 != 0) goto L_04d0;  /* 0349: bnez a10, 4d0 <esp_mesh_parse_conflict_assoc_ie+0x42c> */
  L_034c: a10 = a4;  /* 034c: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_fixed;  /* 034f: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_fixed(a2, a3, a4, a5, a6, a7);  /* 0352: callx a8 via reloc-expand */
  if (a10 != 0) goto L_04d0;  /* 0355: bnez a10, 4d0 <esp_mesh_parse_conflict_assoc_ie+0x42c> */
  L_0358: a10 = a4;  /* 0358: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_gone;  /* 035b: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_gone(a2, a3, a4, a5, a6, a7);  /* 035e: callx a8 via reloc-expand */
  if (a10 != 0) goto L_04d0;  /* 0361: bnez a10, 4d0 <esp_mesh_parse_conflict_assoc_ie+0x42c> */
  L_0364: a3 = -1;  /* 0364 */
  ST32(a1 + 0x94, a3);  /* 0366 */
  a3 = 0;  /* 0369 */
  a12 = 32;  /* 036c */
  a11 = a3;  /* 036f: mov */
  a10 = a1 + (84);  /* 0372 */
  ST32(a1 + 0x50, a3);  /* 0375 */
  __asm__ volatile("" ::: "memory");  /* 0378: memw */
  a8 = (u32)&memset + 0x0;  /* 037b: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 037e: callx a8 (libc, via reloc-expand) */
  a10 = a1 + (80);  /* 0381 */
  a4 = LD8U(a2 + 0x5);  /* 0384 */
  ST32(a1 + 0x4, a4);  /* 0387 */
  a4 = LD8U(a2 + 0x4);  /* 0389 */
  ST32(a1 + 0x0, a4);  /* 038c */
  a15 = LD8U(a2 + 0x3);  /* 038f */
  a14 = LD8U(a2 + 0x2);  /* 0392 */
  a13 = LD8U(a2 + 0x1);  /* 0395 */
  a12 = LD8U(a2 + 0x0);  /* 0398 */
  a2 = a1 + (80);  /* 039b */
  a4 = a2 + (68);  /* 039e */
  a11 = (u32)(RODATA__rodata_esp_mesh_parse_conflict_assoc_ie_str1_1 + 0x0);  /* 03a1: -> "recv assoc from %02x:%02x:%02x:%02x:%02x:%02x" */
  __asm__ volatile("" ::: "memory");  /* 03a4: memw */
  a8 = (u32)&sprintf + 0x0;  /* 03a7: l32r -> global */
  a2 = sprintf(a2, a3, a4, a5, a6, a7);  /* 03aa: callx a8 via reloc-expand */
  a12 = 0x27b;  /* 03ad */
  a13 = a2;  /* 03b0 */
  a12 = a12 << 3;  /* 03b2 */
  a11 = a4;  /* 03b5 */
  a10 = a1 + (116);  /* 03b7 */
  a8 = (u32)&mesh_is_new_found_conflict_root;  /* 03ba: l32r -> func addr */
  a2 = mesh_is_new_found_conflict_root(a2, a3, a4, a5, a6, a7);  /* 03bd: callx a8 via reloc-expand */
  a2 = LD16U(a6 + 0x0);  /* 03c0 */
  a12 = 1;  /* 03c3 */
  a2 = a2 + (-1);  /* 03c5 */
  a11 = a1 + (116);  /* 03c7 */
  a7 = a10;  /* 03ca */
  ST16(a1 + 0x74, a2);  /* 03cc */
  __asm__ volatile("" ::: "memory");  /* 03cf: memw */
  a10 = a3;  /* 03d2 */
  a2 = -91;  /* 03d4 */
  __asm__ volatile("" ::: "memory");  /* 03d7: memw */
  a8 = (u32)&ieee80211_vnd_mesh_roots_set;  /* 03da: l32r -> func addr */
  a2 = ieee80211_vnd_mesh_roots_set(a2, a3, a4, a5, a6, a7);  /* 03dd: callx a8 via reloc-expand */
  a6 = a1 + (80);  /* 03e0 */
  ST8(a1 + 0x98, a2);  /* 03e3 */
  __asm__ volatile("" ::: "memory");  /* 03e6: memw */
  a12 = a6 + (72);  /* 03e9 */
  a11 = a3;  /* 03ec: mov */
  a2 = (u32)&esp_mesh_appie + 0x0;  /* 03ef: l32r -> global */
  a10 = LD32(a2 + 0x0);  /* 03f2 */
  a10 = a10 + (2);  /* 03f5 */
  __asm__ volatile("" ::: "memory");  /* 03f8: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 03fb: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 03fe: callx a8 via reloc-expand */
  a2 = LD8U(a1 + 0x98);  /* 0401 */
  if (a2 == 1) goto L_0445;  /* 0404: beqi a2, 1, 445 <esp_mesh_parse_conflict_assoc_ie+0x3a1> */
  L_0407: a2 = a6 + (48);  /* 0407 */
  a11 = a2;  /* 040a */
  a10 = 1;  /* 040c */
  ST32(a1 + 0x80, a3);  /* 040e */
  ST16(a1 + 0x84, a3);  /* 0411 */
  __asm__ volatile("" ::: "memory");  /* 0414: memw */
  __asm__ volatile("" ::: "memory");  /* 0417: memw */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 041a: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6, a7);  /* 041d: callx a8 via reloc-expand */
  a12 = 6;  /* 0420 */
  a11 = a2;  /* 0422 */
  a10 = a1 + (120);  /* 0424 */
  a8 = (u32)&memcmp + 0x0;  /* 0427: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 042a: callx a8 (libc, via reloc-expand) */
  if (a10 != a3) goto L_04a0;  /* 042d: bne a10, a3, 4a0 <esp_mesh_parse_conflict_assoc_ie+0x3fc> */
  L_0430: a12 = (u32)(RODATA__rodata_esp_mesh_parse_conflict_assoc_ie_str1_1 + 0x0);  /* 0430: -> "recv assoc from %02x:%02x:%02x:%02x:%02x:%02x" */
  a11 = 0x4fb;  /* 0433 */
  a11 = a11 << 2;  /* 0436 */
  a10 = a2;  /* 0439 */
  a8 = (u32)&esp_mesh_remove_conflict_root;  /* 043b: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2, a3, a4, a5, a6, a7);  /* 043e: callx a8 via reloc-expand */
  goto L_04a0;  /* 0441: j */
  L_0445: if (a7 != 0) goto L_0460;  /* 0445: bnez.n a7, 460 <esp_mesh_parse_conflict_assoc_ie+0x3bc> */
  L_0447: a13 = (u32)(RODATA__rodata_esp_mesh_parse_conflict_assoc_ie_str1_1 + 0x0);  /* 0447: -> "recv assoc from %02x:%02x:%02x:%02x:%02x:%02x" */
  a11 = a4;  /* 044a */
  a10 = a1 + (116);  /* 044c */
  a12 = 0x000013f3u;  /* 044f: l32r = 5107 */
  a8 = (u32)&esp_mesh_get_conflict_root_state;  /* 0452: l32r -> func addr */
  a2 = esp_mesh_get_conflict_root_state(a2, a3, a4, a5, a6, a7);  /* 0455: callx a8 via reloc-expand */
  if (a10 != 3) goto L_04a0;  /* 0458: bnei a10, 3, 4a0 <esp_mesh_parse_conflict_assoc_ie+0x3fc> */
  L_045b: goto L_04ba;  /* 045b: j */
  L_0460: a2 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0460: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a12 = 12;  /* 0463 */
  a10 = 56;  /* 0465 */
  a3 = LD32(a2 + 0x0);  /* 0467 */
  a2 = LD32(a1 + 0x94);  /* 0469 */
  a2 = a2 + (a2 << 1);  /* 046c */
  a2 = a2 + (a3 << 3);  /* 046f */
  a2 = LD8U(a2 + 0x17);  /* 0472 */
  ST8(a1 + 0x7e, a2);  /* 0475 */
  __asm__ volatile("" ::: "memory");  /* 0478: memw */
  a2 = a1 + (80);  /* 047b */
  a11 = a2 + (48);  /* 047e */
  a2 = LD32(a1 + 0x74);  /* 0481 */
  a3 = LD32(a1 + 0x78);  /* 0484 */
  ST32(a1 + 0x80, a2);  /* 0487 */
  a2 = LD32(a1 + 0x7c);  /* 048a */
  ST32(a11 + 0x4, a3);  /* 048d */
  ST32(a11 + 0x8, a2);  /* 0490 */
  __asm__ volatile("" ::: "memory");  /* 0493: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 0496: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 0499: callx a8 via reloc-expand */
  goto L_04d0;  /* 049c: j */
  L_04a0: a11 = LD32(a1 + 0x94);  /* 04a0 */
  a12 = 0x503;  /* 04a3 */
  a13 = a1 + (80);  /* 04a6 */
  a12 = a12 << 2;  /* 04a9 */
  a10 = a1 + (116);  /* 04ac */
  a8 = (u32)&esp_mesh_update_conflict_root;  /* 04af: l32r -> func addr */
  a2 = esp_mesh_update_conflict_root(a2, a3, a4, a5, a6, a7);  /* 04b2: callx a8 via reloc-expand */
  goto L_04d0;  /* 04b5: j */
  L_04ba: a12 = 0x000013f7u;  /* 04ba: l32r = 5111 */
  a13 = a1 + (80);  /* 04bd */
  a10 = a1 + (116);  /* 04c0 */
  a11 = LD32(a1 + 0x94);  /* 04c3 */
  a8 = (u32)&esp_mesh_update_conflict_root;  /* 04c6: l32r -> func addr */
  a2 = esp_mesh_update_conflict_root(a2, a3, a4, a5, a6, a7);  /* 04c9: callx a8 via reloc-expand */
  goto L_0460;  /* 04cc: j */
  L_04d0: a2 = a5;  /* 04d0 */
  return a2;  /* 04d2: retw.n */
}


/* esp_mesh_parse_conflict_roots_ie @ mesh_quick.o 00000010 size 84B bind GLOBAL
 * Calls: mesh_parse_conflict_roots_ie | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_parse_conflict_roots_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a9 = 0;  /* 0013 */
  a8 = 1;  /* 0015 */
  a5 = a9;  /* 0017 */
  if (a3 == 0) a5 = a8;  /* 0019 */
  if (a4 == 0) a9 = a8;  /* 001c */
  a5 = a5 | a9;  /* 001f */
  if (a5 != 0) goto L_0060;  /* 0022: bnez.n a5, 60 <esp_mesh_parse_conflict_roots_ie+0x50> */
  L_0024: if (a2 == 0) a5 = a8;  /* 0024 */
  if (a5 != 0) goto L_0060;  /* 0027: bnez.n a5, 60 <esp_mesh_parse_conflict_roots_ie+0x50> */
  L_0029: a11 = LD32(a4 + 0x0);  /* 0029 */
  a12 = a3;  /* 002b */
  a10 = a2;  /* 002d: mov */
  a8 = (u32)&mesh_parse_conflict_roots_ie;  /* 0030: l32r -> func addr */
  a2 = mesh_parse_conflict_roots_ie(a2, a3, a4, a5, a6, a7);  /* 0033: callx a8 via reloc-expand */
  a12 = a3;  /* 0036 */
  a11 = LD32(a4 + 0x4);  /* 0038 */
  a10 = a2;  /* 003a */
  a8 = (u32)&mesh_parse_conflict_roots_ie;  /* 003c: l32r -> func addr */
  a2 = mesh_parse_conflict_roots_ie(a2, a3, a4, a5, a6, a7);  /* 003f: callx a8 via reloc-expand */
  a12 = a3;  /* 0042 */
  a10 = a2;  /* 0044 */
  a11 = LD32(a4 + 0x8);  /* 0046 */
  a8 = (u32)&mesh_parse_conflict_roots_ie;  /* 0048: l32r -> func addr */
  a2 = mesh_parse_conflict_roots_ie(a2, a3, a4, a5, a6, a7);  /* 004b: callx a8 via reloc-expand */
  a10 = a2;  /* 004e */
  a12 = a3;  /* 0050 */
  a11 = LD32(a4 + 0xc);  /* 0052 */
  a2 = a5;  /* 0054 */
  a8 = (u32)&mesh_parse_conflict_roots_ie;  /* 0056: l32r -> func addr */
  a2 = mesh_parse_conflict_roots_ie(a2, a3, a4, a5, a6, a7);  /* 0059: callx a8 via reloc-expand */
  goto L_0062;  /* 005c: j */
  L_0060: a2 = -1;  /* 0060 */
  L_0062: return a2;  /* 0062: retw.n */
}


/* esp_mesh_parse_ext_assoc_ie @ mesh_quick.o 00000018 size 118B bind GLOBAL
 * Calls: esp_mesh_get_router_bssid, memcmp, esp_mesh_set_router_bssid, memcpy, wifi_mesh_event_post | Data refs: .rodata
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=5, refs=6); reloc-direct=5, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_parse_ext_assoc_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  a4 = 1;  /* 001b */
  a8 = 0;  /* 001d */
  if (a2 == 0) a8 = a4;  /* 001f */
  a9 = (a8 >> 8) & 0x1;  /* 0022: extui width 1 */
  if (a8 != 0) goto L_0088;  /* 0025: bnez a8, 88 <esp_mesh_parse_ext_assoc_ie+0x70> */
  L_0028: if (a3 != 0) a4 = a9;  /* 0028 */
  if (a4 != 0) goto L_0088;  /* 002b: bnez a4, 88 <esp_mesh_parse_ext_assoc_ie+0x70> */
  L_002e: a8 = (u32)(RODATA__rodata + 0x0);  /* 002e: l32r -> .rodata */
  a10 = a1 + (6);  /* 0031 */
  a3 = a3 + (7);  /* 0034 */
  a9 = LD8U(a8 + 0x0);  /* 0036 */
  a8 = LD8U(a8 + 0x1);  /* 0039 */
  ST8(a1 + 0x6, a9);  /* 003c */
  ST8(a1 + 0x7, a8);  /* 003f */
  ST16(a1 + 0x8, a4);  /* 0042 */
  ST16(a1 + 0xa, a4);  /* 0045 */
  __asm__ volatile("" ::: "memory");  /* 0048: memw */
  __asm__ volatile("" ::: "memory");  /* 004b: memw */
  a8 = (u32)&esp_mesh_get_router_bssid + 0x0;  /* 004e: l32r -> global */
  a2 = esp_mesh_get_router_bssid(a2, a3, a4, a5, a6, a7);  /* 0051: callx a8 via reloc-expand */
  a12 = 6;  /* 0054 */
  a11 = a3;  /* 0056 */
  a10 = a1 + a12;  /* 0058 */
  a8 = (u32)&memcmp + 0x0;  /* 005a: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 005d: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_008a;  /* 0060: beqz.n a10, 8a <esp_mesh_parse_ext_assoc_ie+0x72> */
  L_0062: a10 = a3;  /* 0062 */
  a8 = (u32)&esp_mesh_set_router_bssid + 0x0;  /* 0064: l32r -> global */
  a2 = esp_mesh_set_router_bssid(a2, a3, a4, a5, a6, a7);  /* 0067: callx a8 via reloc-expand */
  a12 = 6;  /* 006a */
  a11 = a3;  /* 006c */
  a10 = a1;  /* 006e */
  a8 = (u32)&memcpy + 0x0;  /* 0070: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0073: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0076 */
  a11 = a1;  /* 0078 */
  a10 = 67;  /* 007a */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 007c: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 007f: callx a8 via reloc-expand */
  a10 = a4;  /* 0082 */
  goto L_008a;  /* 0084: j */
  L_0088: a10 = -1;  /* 0088 */
  L_008a: a2 = a10;  /* 008a */
  return a2;  /* 008c: retw.n */
}


/* esp_mesh_parse_ps_ie @ mesh_quick.o 00000030 size 614B bind GLOBAL
 * Calls: memcmp, mesh_parse_ps_uplink_rule, mesh_nwk_duty_post_event, mesh_parse_ps_entire_rule, esp_mesh_ps_duty_cycle_set_process | Data refs: g_mesh_init_ps_type, esp_mesh_ps_duty, .bss.MESH_ZERO_ADDR
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=5, refs=8); reloc-direct=5, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_parse_ps_ie(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a6, a7, a8, a9;
  /* 0030: entry a1, 48 (frame 48 bytes) */
  a8 = a5;  /* 0033 */
  a5 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0035: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 0038 */
  a5 = 0;  /* 003a */
  if (a6 != a5) goto L_0042;  /* 003c: bne a6, a5, 42 <esp_mesh_parse_ps_ie+0x12> */
  L_003f: goto L_028d;  /* 003f: j */
  L_0042: a6 = 208;  /* 0042 */
  if (a2 == a6) goto L_005c;  /* 0045: beq a2, a6, 5c <esp_mesh_parse_ps_ie+0x2c> */
  L_0048: a6 = 1;  /* 0048 */
  if (a3 == 0) a5 = a6;  /* 004a */
  a7 = (a5 >> 8) & 0x1;  /* 004d: extui width 1 */
  if (a5 != 0) goto L_0288;  /* 0050: bnez a5, 288 <esp_mesh_parse_ps_ie+0x258> */
  L_0053: if (a4 != 0) a6 = a7;  /* 0053 */
  if (a6 != 0) goto L_0288;  /* 0056: bnez a6, 288 <esp_mesh_parse_ps_ie+0x258> */
  L_0059: a5 = 7;  /* 0059 */
  L_005c: a4 = a4 + a5;  /* 005c */
  a5 = (u32)&esp_mesh_ps_duty + 0x0;  /* 005e: l32r -> global */
  a6 = 48;  /* 0061 */
  a15 = LD8U(a4 + 0xd);  /* 0063 */
  a14 = LD8U(a5 + 0xd);  /* 0066 */
  if (a2 == a6) goto L_00d5;  /* 0069: beq a2, a6, d5 <esp_mesh_parse_ps_ie+0xa5> */
  L_006c: if ((i32)a6 < (i32)a2) goto L_0079;  /* 006c: blt a6, a2, 79 <esp_mesh_parse_ps_ie+0x49> */
  L_006f: if (a2 == 0) goto L_008d;  /* 006f: beqz.n a2, 8d <esp_mesh_parse_ps_ie+0x5d> */
  L_0071: a7 = 1;  /* 0071 */
  if (a2 == 16) goto L_00dc;  /* 0073: beqi a2, 16, dc <esp_mesh_parse_ps_ie+0xac> */
  L_0076: goto L_028d;  /* 0076: j */
  L_0079: a6 = 208;  /* 0079 */
  if (a2 == a6) goto L_00da;  /* 007c: beq a2, a6, da <esp_mesh_parse_ps_ie+0xaa> */
  L_007f: a6 = 255;  /* 007f */
  a7 = 0;  /* 0082 */
  if (a2 == a6) goto L_00dc;  /* 0084: beq a2, a6, dc <esp_mesh_parse_ps_ie+0xac> */
  L_0087: if (a2 == 128) goto L_00dc;  /* 0087: beqi a2, 128, dc <esp_mesh_parse_ps_ie+0xac> */
  L_008a: goto L_028d;  /* 008a: j */
  L_008d: if (a8 == 0) goto L_0294;  /* 008d: beqz a8, 294 <esp_mesh_parse_ps_ie+0x264> */
  L_0090: a6 = LD32(a8 + 0x4);  /* 0090 */
  if (a6 == 0) goto L_0294;  /* 0092: beqz a6, 294 <esp_mesh_parse_ps_ie+0x264> */
  L_0095: a3 = LD32(a8 + 0x8);  /* 0095 */
  if (a3 == 0) goto L_0294;  /* 0097: beqz a3, 294 <esp_mesh_parse_ps_ie+0x264> */
  L_009a: a3 = LD8U(a4 + 0x0);  /* 009a */
  if (((a3 >> 2) & 1) == 0) goto L_00a8;  /* 009d: bbci a3, 2, a8 <esp_mesh_parse_ps_ie+0x78> */
  L_00a0: a3 = LD8U(a4 + 0x1);  /* 00a0 */
  goto L_00b0;  /* 00a3: j */
  L_00a8: a3 = (a3 >> 1) & 0x1;  /* 00a8: extui width 1 */
  if (a3 == 0) goto L_00b0;  /* 00ab: beqz.n a3, b0 <esp_mesh_parse_ps_ie+0x80> */
  L_00ad: a3 = LD8U(a5 + 0x2);  /* 00ad */
  L_00b0: a5 = a3 + (-1);  /* 00b0 */
  a5 = (a5 >> 8) & 0x1;  /* 00b2: extui width 1 */
  a7 = 99;  /* 00b5 */
  if (a7 >= a5) goto L_00be;  /* 00b8: bgeu a7, a5, be <esp_mesh_parse_ps_ie+0x8e> */
  L_00bb: goto L_0294;  /* 00bb: j */
  L_00be: ST8(a6 + 0x0, a3);  /* 00be */
  __asm__ volatile("" ::: "memory");  /* 00c1: memw */
  a3 = LD32(a8 + 0x8);  /* 00c4 */
  a4 = LD8U(a4 + 0x0);  /* 00c6 */
  ST8(a3 + 0x0, a4);  /* 00c9 */
  __asm__ volatile("" ::: "memory");  /* 00cc: memw */
  __asm__ volatile("" ::: "memory");  /* 00cf: memw */
  goto L_0294;  /* 00d2: j */
  L_00d5: a7 = 1;  /* 00d5 */
  goto L_00dc;  /* 00d7: j */
  L_00da: a7 = 0;  /* 00da */
  L_00dc: a6 = LD8U(a4 + 0x0);  /* 00dc */
  if (((a6 >> 7) & 1) != 0) goto L_0101;  /* 00df: bbsi a6, 7, 101 <esp_mesh_parse_ps_ie+0xd1> */
  L_00e2: a12 = 6;  /* 00e2 */
  a10 = a4 + (7);  /* 00e4 */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 00e6: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  ST32(a1 + 0x8, a8);  /* 00e9 */
  ST32(a1 + 0x4, a14);  /* 00eb */
  ST32(a1 + 0x0, a15);  /* 00ed */
  __asm__ volatile("" ::: "memory");  /* 00ef: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00f2: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 00f5: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x8);  /* 00f8 */
  a14 = LD32(a1 + 0x4);  /* 00fa */
  a15 = LD32(a1 + 0x0);  /* 00fc */
  if (a10 == 0) goto L_028d;  /* 00fe: beqz a10, 28d <esp_mesh_parse_ps_ie+0x25d> */
  L_0101: a9 = 99;  /* 0101 */
  a6 = LD8U(a4 + 0x2);  /* 0104 */
  a6 = a6 + (-1);  /* 0107 */
  a6 = (a6 >> 8) & 0x1;  /* 0109: extui width 1 */
  if (a9 >= a6) goto L_0112;  /* 010c: bgeu a9, a6, 112 <esp_mesh_parse_ps_ie+0xe2> */
  L_010f: goto L_028d;  /* 010f: j */
  L_0112: a9 = LD8U(a4 + 0x4);  /* 0112 */
  a13 = 0;  /* 0115 */
  a9 = a9 << 8;  /* 0117 */
  a6 = LD8U(a4 + 0x3);  /* 011a */
  a9 = a9 | a6;  /* 011d */
  a6 = LD8U(a4 + 0x5);  /* 0120 */
  a6 = a6 << 16;  /* 0123 */
  a6 = a6 | a9;  /* 0126 */
  a9 = LD8U(a4 + 0x6);  /* 0129 */
  a9 = a9 << 24;  /* 012c */
  a9 = a9 | a6;  /* 012f */
  if (a9 != a13) goto L_0138;  /* 0132: bne a9, a13, 138 <esp_mesh_parse_ps_ie+0x108> */
  L_0135: goto L_028d;  /* 0135: j */
  L_0138: a10 = LD8U(a4 + 0xf);  /* 0138 */
  if (a10 < 2u) goto L_0141;  /* 013b: bltui a10, 2, 141 <esp_mesh_parse_ps_ie+0x111> */
  L_013e: goto L_0292;  /* 013e: j */
  L_0141: a6 = 1;  /* 0141 */
  if (a8 != 0) a6 = a13;  /* 0143 */
  a6 = (a6 >> 8) & 0x1;  /* 0146: extui width 1 */
  if (((a10 >> a13) & 1) == 0) goto L_0174;  /* 0149: bbc a10, a13, 174 <esp_mesh_parse_ps_ie+0x144> */
  L_014c: if (a6 == a13) goto L_0174;  /* 014c: beq a6, a13, 174 <esp_mesh_parse_ps_ie+0x144> */
  L_014f: a12 = a13;  /* 014f */
  a11 = a4;  /* 0151 */
  a10 = a3;  /* 0153 */
  ST32(a1 + 0x0, a13);  /* 0155 */
  __asm__ volatile("" ::: "memory");  /* 0157: memw */
  a8 = (u32)&mesh_parse_ps_uplink_rule;  /* 015a: l32r -> func addr */
  a2 = mesh_parse_ps_uplink_rule(a2, a3, a4, a5);  /* 015d: callx a8 via reloc-expand */
  a12 = a4;  /* 0160 */
  a11 = a3;  /* 0162 */
  a13 = LD32(a1 + 0x0);  /* 0164 */
  a10 = a13;  /* 0166 */
  a8 = (u32)&mesh_nwk_duty_post_event;  /* 0168: l32r -> func addr */
  a2 = mesh_nwk_duty_post_event(a2, a3, a4, a5);  /* 016b: callx a8 via reloc-expand */
  a13 = LD32(a1 + 0x0);  /* 016e */
  goto L_0292;  /* 0170: j */
  L_0174: a11 = -208;  /* 0174 */
  a11 = a2 + a11;  /* 0177 */
  if (a11 == 0) goto L_0186;  /* 0179: beqz.n a11, 186 <esp_mesh_parse_ps_ie+0x156> */
  L_017b: if (a7 != 0) goto L_0186;  /* 017b: bnez.n a7, 186 <esp_mesh_parse_ps_ie+0x156> */
  L_017d: a11 = a15 - a14;  /* 017d: sub */
  if (((a11 >> 7) & 1) == 0) goto L_0186;  /* 0180: bbci a11, 7, 186 <esp_mesh_parse_ps_ie+0x156> */
  L_0183: goto L_0277;  /* 0183: j */
  L_0186: if (a8 == 0) goto L_01a5;  /* 0186: beqz.n a8, 1a5 <esp_mesh_parse_ps_ie+0x175> */
  L_0188: if (a9 != -1) goto L_01a5;  /* 0188: bnei a9, -1, 1a5 <esp_mesh_parse_ps_ie+0x175> */
  L_018b: a14 = a15 - a14;  /* 018b: sub */
  a14 = (i32)(a14 << (32 - 7)) >> (32 - 7);  /* 018e: sext */
  if ((i32)a14 >= 1) goto L_0197;  /* 0191: bgei a14, 1, 197 <esp_mesh_parse_ps_ie+0x167> */
  L_0194: goto L_0277;  /* 0194: j */
  L_0197: ST8(a5 + 0xd, a15);  /* 0197 */
  __asm__ volatile("" ::: "memory");  /* 019a: memw */
  __asm__ volatile("" ::: "memory");  /* 019d: memw */
  goto L_0277;  /* 01a0: j */
  L_01a5: a12 = a8;  /* 01a5 */
  a11 = a4;  /* 01a7 */
  if (a10 == 0) goto L_01bc;  /* 01a9: beqz.n a10, 1bc <esp_mesh_parse_ps_ie+0x18c> */
  L_01ab: a10 = a3;  /* 01ab */
  ST32(a1 + 0x8, a8);  /* 01ad */
  __asm__ volatile("" ::: "memory");  /* 01af: memw */
  a8 = (u32)&mesh_parse_ps_uplink_rule;  /* 01b2: l32r -> func addr */
  a2 = mesh_parse_ps_uplink_rule(a2, a3, a4, a5);  /* 01b5: callx a8 via reloc-expand */
  goto L_01c9;  /* 01b8: j */
  L_01bc: a10 = a3;  /* 01bc */
  ST32(a1 + 0x8, a8);  /* 01be */
  __asm__ volatile("" ::: "memory");  /* 01c0: memw */
  a8 = (u32)&mesh_parse_ps_entire_rule;  /* 01c3: l32r -> func addr */
  a2 = mesh_parse_ps_entire_rule(a2, a3, a4, a5);  /* 01c6: callx a8 via reloc-expand */
  L_01c9: a8 = LD32(a1 + 0x8);  /* 01c9 */
  if (a10 == 0) goto L_0268;  /* 01cb: beqz a10, 268 <esp_mesh_parse_ps_ie+0x238> */
  L_01ce: a10 = LD8U(a4 + 0x4);  /* 01ce */
  a10 = a10 << 8;  /* 01d1 */
  a9 = LD8U(a4 + 0x3);  /* 01d4 */
  a10 = a10 | a9;  /* 01d7 */
  a9 = LD8U(a4 + 0x5);  /* 01da */
  a9 = a9 << 16;  /* 01dd */
  a9 = a9 | a10;  /* 01e0 */
  a10 = LD8U(a4 + 0x6);  /* 01e3 */
  a10 = a10 << 24;  /* 01e6 */
  a10 = a10 | a9;  /* 01e9 */
  if (a10 != -1) goto L_0206;  /* 01ec: bnei a10, -1, 206 <esp_mesh_parse_ps_ie+0x1d6> */
  L_01ef: a9 = LD8U(a4 + 0xe);  /* 01ef */
  a10 = LD8U(a5 + 0xe);  /* 01f2 */
  if (a10 == a9) goto L_0212;  /* 01f5: beq a10, a9, 212 <esp_mesh_parse_ps_ie+0x1e2> */
  L_01f8: a10 = a9 + (-1);  /* 01f8 */
  a10 = (a10 >> 8) & 0x1;  /* 01fa: extui width 1 */
  a11 = 99;  /* 01fd */
  if (a11 >= a10) goto L_0214;  /* 0200: bgeu a11, a10, 214 <esp_mesh_parse_ps_ie+0x1e4> */
  L_0203: goto L_0212;  /* 0203: j */
  L_0206: a11 = -2;  /* 0206 */
  a9 = 0;  /* 0208 */
  if (a10 == a11) goto L_0245;  /* 020a: beq a10, a11, 245 <esp_mesh_parse_ps_ie+0x215> */
  L_020d: goto L_0214;  /* 020d: j */
  L_0212: a9 = 0;  /* 0212 */
  L_0214: a11 = (u32)&esp_mesh_ps_duty + 0x7;  /* 0214: l32r -> global */
  a12 = 6;  /* 0217 */
  a10 = a4 + (7);  /* 0219 */
  ST32(a1 + 0x8, a8);  /* 021b */
  ST32(a1 + 0x0, a9);  /* 021d */
  __asm__ volatile("" ::: "memory");  /* 021f: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0222: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 0225: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x8);  /* 0228 */
  a9 = LD32(a1 + 0x0);  /* 022a */
  if (a10 == 0) goto L_0245;  /* 022c: beqz.n a10, 245 <esp_mesh_parse_ps_ie+0x215> */
  L_022e: a11 = -4;  /* 022e */
  a10 = LD8U(a5 + 0x10);  /* 0230 */
  a10 = a10 & a11;  /* 0233 */
  a11 = 2;  /* 0236 */
  if (a8 != 0) goto L_023c;  /* 0238: bnez.n a8, 23c <esp_mesh_parse_ps_ie+0x20c> */
  L_023a: a11 = 1;  /* 023a */
  L_023c: a10 = a10 | a11;  /* 023c */
  ST8(a5 + 0x10, a10);  /* 023f */
  __asm__ volatile("" ::: "memory");  /* 0242: memw */
  L_0245: a13 = a6 << 24;  /* 0245 */
  a7 = a7 << 16;  /* 0248 */
  a12 = 0;  /* 024b */
  a13 = a13 | a7;  /* 024d */
  a14 = a4;  /* 0250 */
  a13 = a13 | a9;  /* 0252 */
  a11 = 1;  /* 0255 */
  a10 = a12;  /* 0257: mov */
  ST32(a1 + 0x8, a8);  /* 025a */
  __asm__ volatile("" ::: "memory");  /* 025d: memw */
  a8 = (u32)&esp_mesh_ps_duty_cycle_set_process;  /* 0260: l32r -> func addr */
  a2 = esp_mesh_ps_duty_cycle_set_process(a2, a3, a4, a5);  /* 0263: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x8);  /* 0266 */
  L_0268: a5 = 208;  /* 0268 */
  if (a2 != a5) goto L_0277;  /* 026b: bne a2, a5, 277 <esp_mesh_parse_ps_ie+0x247> */
  L_026e: a11 = 0;  /* 026e */
  a12 = a4;  /* 0270 */
  a10 = a11;  /* 0272 */
  goto L_027e;  /* 0274: j */
  L_0277: a12 = a4;  /* 0277 */
  a11 = a3;  /* 0279 */
  a10 = a8;  /* 027b: mov */
  L_027e: a8 = (u32)&mesh_nwk_duty_post_event;  /* 027e: l32r -> func addr */
  a2 = mesh_nwk_duty_post_event(a2, a3, a4, a5);  /* 0281: callx a8 via reloc-expand */
  goto L_028d;  /* 0284: j */
  L_0288: a2 = -1;  /* 0288 */
  goto L_0294;  /* 028a: j */
  L_028d: a2 = 0;  /* 028d */
  goto L_0294;  /* 028f: j */
  L_0292: a2 = a13;  /* 0292 */
  L_0294: return a2;  /* 0294: retw.n */
}


/* esp_mesh_ps_duty_cycle_get_process @ mesh_quick.o 00000038 size 325B bind GLOBAL
 * Calls: memcpy, mesh_nwk_duty_check_duration_expire, mesh_nwk_duty_process_remaining, mesh_nwk_duty_clr_master_identity | indirect[2]: mem[a3+0x158]; mem[a3+0x150] | Data refs: esp_mesh_ps_duty, g_log_level, g_osi_funcs_p, .rodata.mesh_parse_ps_entire_rule.str1.1, .rodata.esp_mesh_ps_duty_cycle_get_process.str1.1, g_mesh_is_root, .bss.esp_mesh_remain_nwk_duty
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=11); reloc-direct=4, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_ps_duty_cycle_get_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  float F83;
  /* 0038: entry a1, 48 (frame 48 bytes) */
  a10 = a3;  /* 003b */
  if (a3 == 0) goto L_0052;  /* 003d: beqz a3, 52 <esp_mesh_ps_duty_cycle_get_process+0x1a> */
  L_0040: a11 = (u32)&esp_mesh_ps_duty + 0x0;  /* 0040: l32r -> global */
  a12 = 16;  /* 0043 */
  a8 = (u32)&memcpy + 0x0;  /* 0046: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0049: callx a8 (libc, via reloc-expand) */
  goto L_0176;  /* 004c: j */
  L_0052: if (a2 != 0) goto L_0098;  /* 0052: bnez a2, 98 <esp_mesh_ps_duty_cycle_get_process+0x60> */
  L_0055: a2 = (u32)&g_log_level + 0x0;  /* 0055: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0058 */
  a2 = 0x00004008u;  /* 005b: l32r = 16392 */
  if (a3 >= 3u) goto L_0064;  /* 005e: bgeui a3, 3, 64 <esp_mesh_ps_duty_cycle_get_process+0x2c> */
  L_0061: goto L_0178;  /* 0061: j */
  L_0064: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0064: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0067 */
  if (a3 == 0) goto L_0178;  /* 0069: beqz a3, 178 <esp_mesh_ps_duty_cycle_get_process+0x140> */
  L_006c: a4 = LD32(a3 + 0x150);  /* 006c */
  if (a4 == 0) goto L_0178;  /* 006f: beqz a4, 178 <esp_mesh_ps_duty_cycle_get_process+0x140> */
  L_0072: a10 = LD32(a3 + 0x158);  /* 0072 */
  /* 0075: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0078 */
  a10 = 3;  /* 007a */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 007c: -> "child(cidx:" */
  a14 = a11;  /* 007f: mov */
  a3 = 0x00000f83u;  /* 0082: l32r = 3971 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 0085: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 0088: -> "mesh_quick.c" */
  ST32(a1 + 0x0, a3);  /* 008b */
  __asm__ volatile("" ::: "memory");  /* 008e: memw */
  /* 0091: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0178;  /* 0094: j */
  L_0098: a3 = (u32)&g_mesh_is_root + 0x0;  /* 0098: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 009b: memw */
  a3 = LD8U(a3 + 0x0);  /* 009e */
  a3 = (a3 >> 8) & 0x1;  /* 00a1: extui width 1 */
  if (a3 == 0) goto L_00ac;  /* 00a4: beqz.n a3, ac <esp_mesh_ps_duty_cycle_get_process+0x74> */
  L_00a6: a3 = 100;  /* 00a6 */
  goto L_0170;  /* 00a9: j */
  L_00ac: a4 = (u32)&esp_mesh_ps_duty + 0x0;  /* 00ac: l32r -> global */
  a8 = LD8U(a4 + 0x4);  /* 00af */
  a8 = a8 << 8;  /* 00b2 */
  a3 = LD8U(a4 + 0x3);  /* 00b5 */
  a8 = a8 | a3;  /* 00b8 */
  a3 = LD8U(a4 + 0x5);  /* 00bb */
  a3 = a3 << 16;  /* 00be */
  a3 = a3 | a8;  /* 00c1 */
  a10 = LD8U(a4 + 0x6);  /* 00c4 */
  a10 = a10 << 24;  /* 00c7 */
  a10 = a10 | a3;  /* 00ca */
  a8 = LD8U(a4 + 0x12);  /* 00cd */
  a8 = a8 << 8;  /* 00d0 */
  a3 = LD8U(a4 + 0x11);  /* 00d3 */
  a8 = a8 | a3;  /* 00d6 */
  a3 = LD8U(a4 + 0x13);  /* 00d9 */
  a3 = a3 << 16;  /* 00dc */
  a3 = a3 | a8;  /* 00df */
  a12 = LD8U(a4 + 0x14);  /* 00e2 */
  a12 = a12 << 24;  /* 00e5 */
  a12 = a12 | a3;  /* 00e8 */
  a8 = LD8U(a4 + 0x16);  /* 00eb */
  a8 = a8 << 8;  /* 00ee */
  a3 = LD8U(a4 + 0x15);  /* 00f1 */
  a8 = a8 | a3;  /* 00f4 */
  a3 = LD8U(a4 + 0x17);  /* 00f7 */
  a3 = a3 << 16;  /* 00fa */
  a3 = a3 | a8;  /* 00fd */
  a13 = LD8U(a4 + 0x18);  /* 0100 */
  a13 = a13 << 24;  /* 0103 */
  a13 = a13 | a3;  /* 0106 */
  a3 = LD8U(a4 + 0x0);  /* 0109 */
  if (((a3 >> 2) & 1) == 0) goto L_0115;  /* 010c: bbci a3, 2, 115 <esp_mesh_ps_duty_cycle_get_process+0xdd> */
  L_010f: a3 = LD8U(a4 + 0x1);  /* 010f */
  goto L_011b;  /* 0112: j */
  L_0115: if ((i32)a10 >= 0) goto L_0121;  /* 0115: bgez a10, 121 <esp_mesh_ps_duty_cycle_get_process+0xe9> */
  L_0118: a3 = LD8U(a4 + 0x2);  /* 0118 */
  L_011b: ST8(a2 + 0x0, a3);  /* 011b */
  __asm__ volatile("" ::: "memory");  /* 011e: memw */
  L_0121: __asm__ volatile("" ::: "memory");  /* 0121: memw */
  a8 = (u32)&mesh_nwk_duty_check_duration_expire;  /* 0124: l32r -> func addr */
  a2 = mesh_nwk_duty_check_duration_expire(a2, a3, a4, a5, a6, a7);  /* 0127: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0145;  /* 012a: bnez.n a10, 145 <esp_mesh_ps_duty_cycle_get_process+0x10d> */
  L_012c: a3 = LD8U(a2 + 0x0);  /* 012c */
  if (a3 == 0) goto L_0134;  /* 012f: beqz.n a3, 134 <esp_mesh_ps_duty_cycle_get_process+0xfc> */
  L_0131: goto L_0176;  /* 0131: j */
  L_0134: a4 = LD8U(a4 + 0x2);  /* 0134 */
  ST8(a2 + 0x0, a4);  /* 0137 */
  __asm__ volatile("" ::: "memory");  /* 013a: memw */
  __asm__ volatile("" ::: "memory");  /* 013d: memw */
  goto L_0176;  /* 0140: j */
  L_0145: a3 = (u32)&LOCAL__bss_esp_mesh_remain_nwk_duty + 0x0;  /* 0145: l32r -> .bss.esp_mesh_remain_nwk_duty (same-object static) */
  a12 = 0;  /* 0148 */
  a11 = a12;  /* 014a */
  a10 = a3;  /* 014c */
  a8 = (u32)&mesh_nwk_duty_process_remaining;  /* 014e: l32r -> func addr */
  a2 = mesh_nwk_duty_process_remaining(a2, a3, a4, a5, a6, a7);  /* 0151: callx a8 via reloc-expand */
  a5 = a10;  /* 0154 */
  if (a10 == 0) goto L_0160;  /* 0156: beqz.n a10, 160 <esp_mesh_ps_duty_cycle_get_process+0x128> */
  L_0158: a10 = a4;  /* 0158 */
  a8 = (u32)&mesh_nwk_duty_clr_master_identity;  /* 015a: l32r -> func addr */
  a2 = mesh_nwk_duty_clr_master_identity(a2, a3, a4, a5, a6, a7);  /* 015d: callx a8 via reloc-expand */
  L_0160: a8 = LD8U(a2 + 0x0);  /* 0160 */
  if (a8 != 0) goto L_0176;  /* 0163: bnez.n a8, 176 <esp_mesh_ps_duty_cycle_get_process+0x13e> */
  L_0165: if (a5 == 0) goto L_016d;  /* 0165: beqz.n a5, 16d <esp_mesh_ps_duty_cycle_get_process+0x135> */
  L_0167: a3 = LD8U(a4 + 0xe);  /* 0167 */
  goto L_0170;  /* 016a: j */
  L_016d: a3 = LD8U(a3 + 0x1);  /* 016d */
  L_0170: ST8(a2 + 0x0, a3);  /* 0170 */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  L_0176: a2 = 0;  /* 0176 */
  L_0178: __asm__ volatile("" ::: "memory");  /* 0178: memw */
  return a2;  /* 017b: retw.n */
}


/* esp_mesh_ps_duty_cycle_set_process @ mesh_quick.o 00000050 size 628B bind GLOBAL
 * Calls: esp_mesh_get_running_active_duty_cycle, mesh_nwk_duty_set_remaining, mesh_nwk_duty_check_allowed, mesh_nwk_duty_clr_remaining, mesh_nwk_duty_master_is_root, mesh_nwk_duty_process_remaining, ieee80211_sta_is_connected, mesh_nwk_duty_set_master_identity, memcpy, pm_is_open, pm_stop, ieee80211_vnd_mesh_update_beacon | indirect[1]: mem[a3+0x110] | Data refs: esp_mesh_ps_duty, .bss.esp_mesh_remain_nwk_duty, g_mesh_is_root, g_is_root_fixed, g_osi_funcs_p, g_mesh_init_ps_type
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=12, refs=18); reloc-direct=12, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_ps_duty_cycle_set_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a7, a8, a9;
  /* 0050: entry a1, 32 (frame 32 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 0053: extui width 1 */
  a3 = (a3 >> 8) & 0x1;  /* 0056: extui width 1 */
  a4 = (a4 >> 8) & 0x1;  /* 0059: extui width 1 */
  a10 = 0x102;  /* 005c */
  if (a6 == 0) goto L_02c0;  /* 005f: beqz a6, 2c0 <esp_mesh_ps_duty_cycle_set_process+0x270> */
  L_0062: a10 = 0;  /* 0062 */
  if (a2 == a10) goto L_009c;  /* 0064: beq a2, a10, 9c <esp_mesh_ps_duty_cycle_set_process+0x4c> */
  L_0067: a2 = (u32)&esp_mesh_ps_duty + 0x0;  /* 0067: l32r -> global */
  a7 = LD8U(a6 + 0x1);  /* 006a */
  a8 = LD8U(a2 + 0x0);  /* 006d */
  ST8(a2 + 0x1, a7);  /* 0070 */
  __asm__ volatile("" ::: "memory");  /* 0073: memw */
  a7 = LD8U(a6 + 0x0);  /* 0076 */
  if (((a8 >> 7) & 1) == 0) goto L_0082;  /* 0079: bbci a8, 7, 82 <esp_mesh_ps_duty_cycle_set_process+0x32> */
  L_007c: a8 = 128;  /* 007c */
  a7 = a7 | a8;  /* 007f */
  L_0082: ST8(a2 + 0x0, a7);  /* 0082 */
  __asm__ volatile("" ::: "memory");  /* 0085: memw */
  __asm__ volatile("" ::: "memory");  /* 0088: memw */
  a8 = (u32)&esp_mesh_get_running_active_duty_cycle + 0x0;  /* 008b: l32r -> global */
  a2 = esp_mesh_get_running_active_duty_cycle(a2, a3, a4, a5, a6);  /* 008e: callx a8 via reloc-expand */
  a7 = -1;  /* 0091 */
  a10 = (a10 >> 8) & 0x1;  /* 0093: extui width 1 */
  ST8(a2 + 0x1a, a7);  /* 0096 */
  __asm__ volatile("" ::: "memory");  /* 0099: memw */
  L_009c: if (a3 == 0) goto L_028a;  /* 009c: beqz a3, 28a <esp_mesh_ps_duty_cycle_set_process+0x23a> */
  L_009f: a2 = (a5 >> 8) & 0x1ffff;  /* 009f: extui width 17 */
  a8 = 1;  /* 00a2 */
  a3 = 0;  /* 00a4 */
  if (a2 != 0) a3 = a8;  /* 00a6 */
  a3 = (a3 >> 8) & 0x1;  /* 00a9: extui width 1 */
  a7 = (a5 >> 8) & 0x1ff;  /* 00ac: extui width 9 */
  if (a4 == 0) goto L_00d5;  /* 00af: beqz.n a4, d5 <esp_mesh_ps_duty_cycle_set_process+0x85> */
  L_00b1: a10 = a6;  /* 00b1 */
  __asm__ volatile("" ::: "memory");  /* 00b3: memw */
  a8 = (u32)&mesh_nwk_duty_set_remaining;  /* 00b6: l32r -> func addr */
  a2 = mesh_nwk_duty_set_remaining(a2, a3, a4, a5, a6);  /* 00b9: callx a8 via reloc-expand */
  a10 = a6;  /* 00bc */
  a8 = (u32)&mesh_nwk_duty_check_allowed;  /* 00be: l32r -> func addr */
  a2 = mesh_nwk_duty_check_allowed(a2, a3, a4, a5, a6);  /* 00c1: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0149;  /* 00c4: beqz a10, 149 <esp_mesh_ps_duty_cycle_set_process+0xf9> */
  L_00c7: a2 = 0xffffbfcau;  /* 00c7: l32r = -16438 */
  a2 = a10 + a2;  /* 00ca */
  if (a2 < 2u) goto L_00d2;  /* 00cc: bltui a2, 2, d2 <esp_mesh_ps_duty_cycle_set_process+0x82> */
  L_00cf: goto L_02c0;  /* 00cf: j */
  L_00d2: goto L_02be;  /* 00d2: j */
  L_00d5: a2 = LD8U(a6 + 0x4);  /* 00d5 */
  a2 = a2 << 8;  /* 00d8 */
  a9 = LD8U(a6 + 0x3);  /* 00db */
  a2 = a2 | a9;  /* 00de */
  a9 = LD8U(a6 + 0x5);  /* 00e1 */
  a9 = a9 << 16;  /* 00e4 */
  a9 = a9 | a2;  /* 00e7 */
  a2 = LD8U(a6 + 0x6);  /* 00ea */
  a2 = a2 << 24;  /* 00ed */
  a2 = a2 | a9;  /* 00f0 */
  if (a7 != 0) goto L_0149;  /* 00f3: bnez a7, 149 <esp_mesh_ps_duty_cycle_set_process+0xf9> */
  L_00f6: if (a2 != -1) goto L_0104;  /* 00f6: bnei a2, -1, 104 <esp_mesh_ps_duty_cycle_set_process+0xb4> */
  L_00f9: a8 = (u32)&mesh_nwk_duty_clr_remaining;  /* 00f9: l32r -> func addr */
  a2 = mesh_nwk_duty_clr_remaining(a2, a3, a4, a5, a6);  /* 00fc: callx a8 via reloc-expand */
  goto L_0149;  /* 00ff: j */
  L_0104: a10 = (a5 >> 8) & 0x1ffffff;  /* 0104: extui width 25 */
  a9 = a4;  /* 0107 */
  if (a10 != 0) a9 = a8;  /* 0109 */
  if (a9 == 0) goto L_0115;  /* 010c: beqz.n a9, 115 <esp_mesh_ps_duty_cycle_set_process+0xc5> */
  L_010e: a9 = a2 + (2);  /* 010e */
  if (a9 == 0) a8 = a4;  /* 0110 */
  if (a8 != 0) goto L_0120;  /* 0113: bnez.n a8, 120 <esp_mesh_ps_duty_cycle_set_process+0xd0> */
  L_0115: a10 = (u32)&LOCAL__bss_esp_mesh_remain_nwk_duty + 0x0;  /* 0115: l32r -> .bss.esp_mesh_remain_nwk_duty (same-object static) */
  a8 = LD8U(a10 + 0x0);  /* 0118 */
  if (a8 != 0) goto L_012e;  /* 011b: bnez.n a8, 12e <esp_mesh_ps_duty_cycle_set_process+0xde> */
  L_011d: goto L_0149;  /* 011d: j */
  L_0120: a10 = a6 + (7);  /* 0120 */
  a8 = (u32)&mesh_nwk_duty_master_is_root;  /* 0122: l32r -> func addr */
  a2 = mesh_nwk_duty_master_is_root(a2, a3, a4, a5, a6);  /* 0125: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0149;  /* 0128: bnez.n a10, 149 <esp_mesh_ps_duty_cycle_set_process+0xf9> */
  L_012a: goto L_0115;  /* 012a: j */
  L_012e: a8 = -2;  /* 012e */
  if (a2 == a8) goto L_013c;  /* 0130: beq a2, a8, 13c <esp_mesh_ps_duty_cycle_set_process+0xec> */
  L_0133: a8 = LD8U(a6 + 0x2);  /* 0133 */
  a2 = LD8U(a10 + 0x1);  /* 0136 */
  if (a8 >= a2) goto L_0149;  /* 0139: bgeu a8, a2, 149 <esp_mesh_ps_duty_cycle_set_process+0xf9> */
  L_013c: a12 = a3;  /* 013c */
  a11 = a6;  /* 013e */
  a8 = (u32)&mesh_nwk_duty_process_remaining;  /* 0140: l32r -> func addr */
  a2 = mesh_nwk_duty_process_remaining(a2, a3, a4, a5, a6);  /* 0143: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02be;  /* 0146: beqz a10, 2be <esp_mesh_ps_duty_cycle_set_process+0x26e> */
  L_0149: a8 = LD8U(a6 + 0x2);  /* 0149 */
  a2 = (u32)&esp_mesh_ps_duty + 0x0;  /* 014c: l32r -> global */
  ST8(a2 + 0x2, a8);  /* 014f */
  __asm__ volatile("" ::: "memory");  /* 0152: memw */
  a9 = LD8U(a6 + 0x4);  /* 0155 */
  a9 = a9 << 8;  /* 0158 */
  a8 = LD8U(a6 + 0x3);  /* 015b */
  a9 = a9 | a8;  /* 015e */
  a8 = LD8U(a6 + 0x5);  /* 0161 */
  a8 = a8 << 16;  /* 0164 */
  a8 = a8 | a9;  /* 0167 */
  a11 = (a8 >> 8) & 0x1ff;  /* 016a: extui width 9 */
  a10 = LD8U(a6 + 0x6);  /* 016d */
  ST8(a2 + 0x3, a8);  /* 0170 */
  a8 = (a8 >> 16) & 0x1ffff;  /* 0173: extui width 17 */
  ST8(a2 + 0x5, a8);  /* 0176 */
  __asm__ volatile("" ::: "memory");  /* 0179: memw */
  a8 = LD8U(a6 + 0xf);  /* 017c */
  ST8(a2 + 0xf, a8);  /* 017f */
  __asm__ volatile("" ::: "memory");  /* 0182: memw */
  a8 = (u32)&g_mesh_is_root + 0x0;  /* 0185: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0188: memw */
  a8 = LD8U(a8 + 0x0);  /* 018b */
  a8 = (a8 >> 8) & 0x1;  /* 018e: extui width 1 */
  ST8(a2 + 0x4, a11);  /* 0191 */
  ST8(a2 + 0x6, a10);  /* 0194 */
  __asm__ volatile("" ::: "memory");  /* 0197: memw */
  if (a8 == 0) goto L_01d8;  /* 019a: beqz.n a8, 1d8 <esp_mesh_ps_duty_cycle_set_process+0x188> */
  L_019c: a8 = (u32)&g_is_root_fixed + 0x0;  /* 019c: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 019f */
  if (a8 == 0) goto L_01d8;  /* 01a2: beqz.n a8, 1d8 <esp_mesh_ps_duty_cycle_set_process+0x188> */
  L_01a4: a3 = 0;  /* 01a4 */
  a8 = 1;  /* 01a6 */
  if (a7 == 0) a8 = a3;  /* 01a8 */
  a7 = LD8U(a6 + 0x4);  /* 01ab */
  a14 = (a8 >> 8) & 0x1;  /* 01ae: extui width 1 */
  a7 = a7 << 8;  /* 01b1 */
  a3 = LD8U(a6 + 0x3);  /* 01b4 */
  a7 = a7 | a3;  /* 01b7 */
  a3 = LD8U(a6 + 0x5);  /* 01ba */
  a3 = a3 << 16;  /* 01bd */
  a3 = a3 | a7;  /* 01c0 */
  a11 = LD8U(a6 + 0x6);  /* 01c3 */
  a11 = a11 << 24;  /* 01c6 */
  a11 = a11 | a3;  /* 01c9 */
  if (a8 != 0) goto L_01e8;  /* 01cc: bnez.n a8, 1e8 <esp_mesh_ps_duty_cycle_set_process+0x198> */
  L_01ce: if (a4 == 0) goto L_01f9;  /* 01ce: beqz.n a4, 1f9 <esp_mesh_ps_duty_cycle_set_process+0x1a9> */
  L_01d0: __asm__ volatile("" ::: "memory");  /* 01d0: memw */
  goto L_01e8;  /* 01d3: j */
  L_01d8: a8 = (u32)&ieee80211_sta_is_connected + 0x0;  /* 01d8: l32r -> global */
  a2 = ieee80211_sta_is_connected(a2, a3, a4, a5, a6);  /* 01db: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a4;  /* 01de: bnez a10, 1a4 <esp_mesh_ps_duty_cycle_set_process+0x154> */
  L_01e1: if (a3 != 0) goto L_01a4;  /* 01e1: bnez a3, 1a4 <esp_mesh_ps_duty_cycle_set_process+0x154> */
  L_01e4: goto L_027e;  /* 01e4: j */
  L_01e8: a12 = LD8U(a6 + 0xf);  /* 01e8 */
  a13 = 1;  /* 01eb */
  a10 = LD8U(a6 + 0x2);  /* 01ed */
  a8 = (u32)&mesh_nwk_duty_set_master_identity;  /* 01f0: l32r -> func addr */
  a2 = mesh_nwk_duty_set_master_identity(a2, a3, a4, a5, a6);  /* 01f3: callx a8 via reloc-expand */
  goto L_027e;  /* 01f6: j */
  L_01f9: a5 = (a5 >> 8) & 0x1;  /* 01f9: extui width 1 */
  if (a5 == 0) goto L_0204;  /* 01fc: beqz.n a5, 204 <esp_mesh_ps_duty_cycle_set_process+0x1b4> */
  L_01fe: ST8(a2 + 0xe, a5);  /* 01fe */
  __asm__ volatile("" ::: "memory");  /* 0201: memw */
  L_0204: a3 = -2;  /* 0204 */
  if (a11 == a3) goto L_0218;  /* 0206: beq a11, a3, 218 <esp_mesh_ps_duty_cycle_set_process+0x1c8> */
  L_0209: a12 = 6;  /* 0209 */
  a11 = a6 + (7);  /* 020b */
  a10 = a2 + (7);  /* 020d */
  __asm__ volatile("" ::: "memory");  /* 020f: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0212: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 0215: callx a8 (libc, via reloc-expand) */
  L_0218: a4 = LD8U(a6 + 0xd);  /* 0218 */
  a3 = LD8U(a2 + 0xd);  /* 021b */
  a3 = a4 - a3;  /* 021e: sub */
  a3 = (i32)(a3 << (32 - 7)) >> (32 - 7);  /* 0221: sext */
  if ((i32)a3 < 1) goto L_022d;  /* 0224: blti a3, 1, 22d <esp_mesh_ps_duty_cycle_set_process+0x1dd> */
  L_0227: ST8(a2 + 0xd, a4);  /* 0227 */
  __asm__ volatile("" ::: "memory");  /* 022a: memw */
  L_022d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 022d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0230 */
  a10 = LD32(a3 + 0x110);  /* 0233 */
  __asm__ volatile("" ::: "memory");  /* 0236: memw */
  /* 0239: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  a4 = (a10 >> 8) & 0x1ff;  /* 023c: extui width 9 */
  ST8(a2 + 0x12, a4);  /* 023f */
  __asm__ volatile("" ::: "memory");  /* 0242: memw */
  a4 = (a10 >> 8) & 0x1ffff;  /* 0245: extui width 17 */
  a3 = LD8U(a2 + 0x0);  /* 0248 */
  ST8(a2 + 0x13, a4);  /* 024b */
  a4 = (a11 >> 8) & 0x1ff;  /* 024e: extui width 9 */
  ST8(a2 + 0x11, a10);  /* 0251 */
  a10 = (a10 >> 8) & 0x1ffffff;  /* 0254: extui width 25 */
  ST8(a2 + 0x15, a11);  /* 0257 */
  ST8(a2 + 0x16, a4);  /* 025a */
  a4 = (a11 >> 8) & 0x1ffff;  /* 025d: extui width 17 */
  a11 = (a11 >> 8) & 0x1ffffff;  /* 0260: extui width 25 */
  ST8(a2 + 0x17, a4);  /* 0263 */
  a4 = (i32)(a3 << (32 - 7)) >> (32 - 7);  /* 0266: sext */
  ST8(a2 + 0x14, a10);  /* 0269 */
  ST8(a2 + 0x18, a11);  /* 026c */
  __asm__ volatile("" ::: "memory");  /* 026f: memw */
  if ((i32)a4 >= 0) goto L_027e;  /* 0272: bgez a4, 27e <esp_mesh_ps_duty_cycle_set_process+0x22e> */
  L_0275: a3 = (a3 >> 7) & 0x1;  /* 0275: extui width 1 */
  ST8(a2 + 0x0, a3);  /* 0278 */
  __asm__ volatile("" ::: "memory");  /* 027b: memw */
  L_027e: __asm__ volatile("" ::: "memory");  /* 027e: memw */
  a8 = (u32)&esp_mesh_get_running_active_duty_cycle + 0x0;  /* 0281: l32r -> global */
  a2 = esp_mesh_get_running_active_duty_cycle(a2, a3, a4, a5, a6);  /* 0284: callx a8 via reloc-expand */
  a10 = (a10 >> 8) & 0x1;  /* 0287: extui width 1 */
  L_028a: a2 = (u32)&g_mesh_init_ps_type + 0x0;  /* 028a: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 028d */
  if (a2 == 0) goto L_02be;  /* 0290: beqz.n a2, 2be <esp_mesh_ps_duty_cycle_set_process+0x26e> */
  L_0292: a2 = 100;  /* 0292 */
  if (a10 != a2) goto L_02b6;  /* 0295: bne a10, a2, 2b6 <esp_mesh_ps_duty_cycle_set_process+0x266> */
  L_0298: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0298: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 029b: memw */
  a2 = LD8U(a2 + 0x0);  /* 029e */
  a2 = (a2 >> 8) & 0x1;  /* 02a1: extui width 1 */
  if (a2 != 0) goto L_02b6;  /* 02a4: bnez.n a2, 2b6 <esp_mesh_ps_duty_cycle_set_process+0x266> */
  L_02a6: a8 = (u32)&pm_is_open + 0x0;  /* 02a6: l32r -> global */
  a2 = pm_is_open(a2, a3, a4, a5, a6);  /* 02a9: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02b6;  /* 02ac: beqz.n a10, 2b6 <esp_mesh_ps_duty_cycle_set_process+0x266> */
  L_02ae: a10 = a2;  /* 02ae */
  a8 = (u32)&pm_stop + 0x0;  /* 02b0: l32r -> global */
  a2 = pm_stop(a2, a3, a4, a5, a6);  /* 02b3: callx a8 via reloc-expand */
  L_02b6: a10 = 1;  /* 02b6 */
  a8 = (u32)&ieee80211_vnd_mesh_update_beacon + 0x0;  /* 02b8: l32r -> global */
  a2 = ieee80211_vnd_mesh_update_beacon(a2, a3, a4, a5, a6);  /* 02bb: callx a8 via reloc-expand */
  L_02be: a10 = 0;  /* 02be */
  L_02c0: a2 = a10;  /* 02c0 */
  return a2;  /* 02c2: retw.n */
}


/* esp_mesh_ps_duty_ext_get_process @ mesh_quick.o 00000008 size 20B bind GLOBAL
 * Calls: memcpy | Data refs: esp_mesh_ps_duty
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_ps_duty_ext_get_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a11 = (u32)&esp_mesh_ps_duty + 0x0;  /* 000b: l32r -> global */
  a12 = 27;  /* 000e */
  a10 = a2;  /* 0010 */
  a8 = (u32)&memcpy + 0x0;  /* 0012: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0015: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0018 */
  return a2;  /* 001a: retw.n */
}


/* esp_mesh_quick_funcs_deinit @ mesh_quick.o 00000008 size 19B bind GLOBAL
 * Calls: memset | Data refs: esp_mesh_quick_funcs
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_quick_funcs_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a10 = (u32)&esp_mesh_quick_funcs + 0x0;  /* 000b: l32r -> global */
  a12 = 176;  /* 000e */
  a11 = 0;  /* 0011 */
  a8 = (u32)&memset + 0x0;  /* 0013: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0016: callx a8 (libc, via reloc-expand) */
  return a2;  /* 0019: retw.n */
}


/* esp_mesh_quick_funcs_init @ mesh_quick.o 000000b0 size 253B bind GLOBAL
 * Calls: none | Data refs: esp_mesh_quick_funcs, esp_mesh_parse_beacon, esp_mesh_monitor_parent_ie, esp_mesh_check_vnd_ie, esp_mesh_map_change_beacon_interval, esp_mesh_map_stop_beacon, esp_mesh_parse_ext_assoc_ie, esp_mesh_parse_ps_ie, esp_mesh_map_probe_response, esp_mesh_sta_monitor_rssi, esp_mesh_map_reject_connection, esp_mesh_get_ap_assoc_expire +32 more
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=0, refs=39); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
void esp_mesh_quick_funcs_init(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a4, a8, a9;
  /* 00b0: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&esp_mesh_quick_funcs + 0x0;  /* 00b3: l32r -> global */
  a9 = (u32)&esp_mesh_parse_beacon;  /* 00b6: l32r -> func addr */
  ST32(a8 + 0x0, a9);  /* 00b9 */
  a9 = (u32)&esp_mesh_monitor_parent_ie;  /* 00bb: l32r -> func addr */
  ST32(a8 + 0x4, a9);  /* 00be */
  a9 = (u32)&esp_mesh_check_vnd_ie;  /* 00c0: l32r -> func addr */
  ST32(a8 + 0x8, a9);  /* 00c3 */
  a9 = (u32)&esp_mesh_map_change_beacon_interval;  /* 00c5: l32r -> func addr */
  ST32(a8 + 0xc, a9);  /* 00c8 */
  a9 = (u32)&esp_mesh_map_stop_beacon;  /* 00ca: l32r -> func addr */
  ST32(a8 + 0x10, a9);  /* 00cd */
  a9 = (u32)&esp_mesh_parse_ext_assoc_ie;  /* 00cf: l32r -> func addr */
  ST32(a8 + 0x14, a9);  /* 00d2 */
  a9 = (u32)&esp_mesh_parse_ps_ie;  /* 00d4: l32r -> func addr */
  ST32(a8 + 0x18, a9);  /* 00d7 */
  a9 = (u32)&esp_mesh_map_probe_response;  /* 00d9: l32r -> func addr */
  ST32(a8 + 0x24, a9);  /* 00dc */
  a9 = (u32)&esp_mesh_sta_monitor_rssi;  /* 00de: l32r -> func addr */
  ST32(a8 + 0x1c, a9);  /* 00e1 */
  a9 = (u32)&esp_mesh_map_reject_connection;  /* 00e3: l32r -> func addr */
  ST32(a8 + 0x20, a9);  /* 00e6 */
  a9 = (u32)&esp_mesh_get_ap_assoc_expire + 0x0;  /* 00e8: l32r -> global */
  ST32(a8 + 0x28, a9);  /* 00eb */
  a9 = (u32)&esp_mesh_get_vnd_ssid_len;  /* 00ed: l32r -> func addr */
  ST32(a8 + 0x2c, a9);  /* 00f0 */
  a9 = (u32)&esp_mesh_get_vnd_roots_len;  /* 00f2: l32r -> func addr */
  ST32(a8 + 0x30, a9);  /* 00f5 */
  a9 = (u32)&esp_mesh_get_vnd_ext_assoc_len;  /* 00f7: l32r -> func addr */
  ST32(a8 + 0x34, a9);  /* 00fa */
  a9 = (u32)&ieee80211_add_mesh_roots_ie;  /* 00fc: l32r -> func addr */
  ST32(a8 + 0x38, a9);  /* 00ff */
  a9 = (u32)&ieee80211_add_mesh_assoc_ie;  /* 0101: l32r -> func addr */
  ST32(a8 + 0x3c, a9);  /* 0104 */
  a9 = (u32)&ieee80211_add_mesh_ext_assoc_ie;  /* 0106: l32r -> func addr */
  ST32(a8 + 0x40, a9);  /* 0109 */
  a9 = (u32)&ieee80211_add_mesh_ssid_ie;  /* 010c: l32r -> func addr */
  ST32(a8 + 0x44, a9);  /* 010f */
  a9 = (u32)&ieee80211_add_mesh_ps_ie;  /* 0112: l32r -> func addr */
  ST32(a8 + 0x48, a9);  /* 0115 */
  a9 = (u32)&ieee80211_add_mesh_duty_signaling;  /* 0118: l32r -> func addr */
  ST32(a8 + 0xa8, a9);  /* 011b */
  a9 = (u32)&ieee80211_recv_mesh_duty_signaling;  /* 011e: l32r -> func addr */
  ST32(a8 + 0xac, a9);  /* 0121 */
  a9 = (u32)&is_esp_mesh_assoc + 0x0;  /* 0124: l32r -> global */
  ST32(a8 + 0x4c, a9);  /* 0127 */
  a9 = (u32)&is_esp_mesh_ext_assoc;  /* 012a: l32r -> func addr */
  ST32(a8 + 0x50, a9);  /* 012d */
  a9 = 0;  /* 0130: l32r -> .text.is_esp_mesh_ssid+0x0 (link-time addr, kind unclear) */
  ST32(a8 + 0x54, a9);  /* 0133 */
  a9 = 0;  /* 0136: l32r -> .text.is_esp_mesh_roots_announce+0x0 (link-time addr, kind unclear) */
  ST32(a8 + 0x58, a9);  /* 0139 */
  a9 = 0;  /* 013c: l32r -> .text.is_esp_mesh_roots_yield+0x0 (link-time addr, kind unclear) */
  ST32(a8 + 0x5c, a9);  /* 013f */
  a9 = 0;  /* 0142: l32r -> .text.is_esp_mesh_roots_fixed+0x0 (link-time addr, kind unclear) */
  ST32(a8 + 0x60, a9);  /* 0145 */
  a9 = 0;  /* 0148: l32r -> .text.is_esp_mesh_roots_gone+0x0 (link-time addr, kind unclear) */
  ST32(a8 + 0x64, a9);  /* 014b */
  a9 = (u32)&is_esp_mesh_ps;  /* 014e: l32r -> func addr */
  ST32(a8 + 0x68, a9);  /* 0151 */
  a9 = (u32)&esp_mesh_channel_enable_jp + 0x0;  /* 0154: l32r -> global */
  ST32(a8 + 0x6c, a9);  /* 0157 */
  a9 = (u32)&esp_mesh_is_scan_allowed + 0x0;  /* 015a: l32r -> global */
  ST32(a8 + 0x70, a9);  /* 015d */
  a9 = (u32)&esp_mesh_sync_interface_tsf;  /* 0160: l32r -> func addr */
  ST32(a8 + 0x74, a9);  /* 0163 */
  a9 = (u32)&esp_mesh_pm_tbtt_timeout_process + 0x0;  /* 0166: l32r -> global */
  ST32(a8 + 0x78, a9);  /* 0169 */
  a9 = (u32)&esp_mesh_pm_rx_beacon_process + 0x0;  /* 016c: l32r -> global */
  ST32(a8 + 0x7c, a9);  /* 016f */
  a9 = (u32)&esp_mesh_pm_tx_data_process + 0x0;  /* 0172: l32r -> global */
  ST32(a8 + 0x80, a9);  /* 0175 */
  a9 = (u32)&esp_mesh_pm_tx_null_process + 0x0;  /* 0178: l32r -> global */
  ST32(a8 + 0x84, a9);  /* 017b */
  a9 = (u32)&esp_mesh_pm_go_to_sleep + 0x0;  /* 017e: l32r -> global */
  ST32(a8 + 0x88, a9);  /* 0181 */
  a9 = (u32)&esp_mesh_pm_go_to_wake + 0x0;  /* 0184: l32r -> global */
  ST32(a8 + 0x8c, a9);  /* 0187 */
  a9 = (u32)&esp_mesh_is_start_pm_now + 0x0;  /* 018a: l32r -> global */
  ST32(a8 + 0x90, a9);  /* 018d */
  a9 = (u32)&esp_mesh_root_process_duty_duration_expire;  /* 0190: l32r -> func addr */
  ST32(a8 + 0x94, a9);  /* 0193 */
  a9 = (u32)&esp_mesh_ps_duty_cycle_get_process;  /* 0196: l32r -> func addr */
  ST32(a8 + 0x98, a9);  /* 0199 */
  a9 = (u32)&esp_mesh_ps_duty_cycle_set_process;  /* 019c: l32r -> func addr */
  ST32(a8 + 0x9c, a9);  /* 019f */
  a9 = (u32)&esp_mesh_ps_duty_ext_get_process;  /* 01a2: l32r -> func addr */
  ST32(a8 + 0xa4, a9);  /* 01a5 */
  __asm__ volatile("" ::: "memory");  /* 01a8: memw */
  return;  /* 01ab: retw.n */
}


/* esp_mesh_remove_conflict_root @ mesh_quick.o 00000008 size 118B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.s_mesh_conflict_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_remove_conflict_root(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a3, a4, a5, a6, a7, a8;
  /* 0008: entry a1, 48 (frame 48 bytes) */
  if (a2 == 0) goto L_007a;  /* 000b: beqz a2, 7a <esp_mesh_remove_conflict_root+0x72> */
  L_000e: a3 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 000e: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a5 = LD32(a3 + 0x0);  /* 0011 */
  if (a5 == 0) goto L_007a;  /* 0013: beqz a5, 7a <esp_mesh_remove_conflict_root+0x72> */
  L_0016: a7 = a5 + (17);  /* 0016 */
  a4 = 0;  /* 0019 */
  a8 = 6;  /* 001b */
  L_001d: a3 = a4 + (a4 << 1);  /* 001d */
  a3 = a3 + (a5 << 3);  /* 0020 */
  a6 = LD8U(a3 + 0x9);  /* 0023 */
  if (((a6 >> 0) & 1) == 0) goto L_0072;  /* 0026: bbci a6, 0, 72 <esp_mesh_remove_conflict_root+0x6a> */
  L_0029: a12 = a8;  /* 0029 */
  a11 = a2;  /* 002b */
  a10 = a7;  /* 002d */
  ST32(a1 + 0x0, a8);  /* 002f */
  __asm__ volatile("" ::: "memory");  /* 0031: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0034: l32r -> global */
  a2 = memcmp(a2);  /* 0037: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x0);  /* 003a */
  if (a10 != 0) goto L_0072;  /* 003c: bnez.n a10, 72 <esp_mesh_remove_conflict_root+0x6a> */
  L_003e: a2 = -2;  /* 003e */
  a6 = a6 & a2;  /* 0040 */
  ST8(a3 + 0x9, a6);  /* 0043 */
  __asm__ volatile("" ::: "memory");  /* 0046: memw */
  a4 = LD8U(a5 + 0x0);  /* 0049 */
  a4 = a4 + (-1);  /* 004c */
  ST8(a5 + 0x0, a4);  /* 004e */
  ST8(a3 + 0x1, a10);  /* 0051 */
  ST8(a3 + 0x2, a10);  /* 0054 */
  ST8(a3 + 0x3, a10);  /* 0057 */
  ST8(a3 + 0x4, a10);  /* 005a */
  ST8(a3 + 0x5, a10);  /* 005d */
  ST8(a3 + 0x6, a10);  /* 0060 */
  ST8(a3 + 0x7, a10);  /* 0063 */
  ST8(a3 + 0x8, a10);  /* 0066 */
  __asm__ volatile("" ::: "memory");  /* 0069: memw */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  goto L_007a;  /* 006f: j */
  L_0072: a4 = a4 + (1);  /* 0072 */
  a7 = a7 + (24);  /* 0074 */
  if (a4 != 10) goto L_001d;  /* 0077: bnei a4, 10, 1d <esp_mesh_remove_conflict_root+0x15> */
  L_007a: a2 = 0;  /* 007a */
  return a2;  /* 007c: retw.n */
}


/* esp_mesh_root_process_duty_duration_expire @ mesh_quick.o 00000018 size 146B bind GLOBAL
 * Calls: mesh_nwk_duty_check_duration_expire, mesh_nwk_duty_process_remaining, mesh_nwk_duty_clr_master_identity | Data refs: g_mesh_is_root, esp_mesh_ps_duty, .bss.esp_mesh_remain_nwk_duty
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=6); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_root_process_duty_duration_expire(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8, a9;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_mesh_is_root + 0x0;  /* 001b: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 001e: memw */
  a2 = LD8U(a2 + 0x0);  /* 0021 */
  a2 = (a2 >> 8) & 0x1;  /* 0024: extui width 1 */
  if (a2 == 0) goto L_00a6;  /* 0027: beqz a2, a6 <esp_mesh_root_process_duty_duration_expire+0x8e> */
  L_002a: a2 = (u32)&esp_mesh_ps_duty + 0x0;  /* 002a: l32r -> global */
  a8 = LD8U(a2 + 0x12);  /* 002d */
  a8 = a8 << 8;  /* 0030 */
  a9 = LD8U(a2 + 0x11);  /* 0033 */
  a8 = a8 | a9;  /* 0036 */
  a11 = LD8U(a2 + 0x13);  /* 0039 */
  a11 = a11 << 16;  /* 003c */
  a11 = a11 | a8;  /* 003f */
  a8 = LD8U(a2 + 0x16);  /* 0042 */
  a8 = a8 << 8;  /* 0045 */
  a9 = LD8U(a2 + 0x15);  /* 0048 */
  a8 = a8 | a9;  /* 004b */
  a9 = LD8U(a2 + 0x17);  /* 004e */
  a9 = a9 << 16;  /* 0051 */
  a9 = a9 | a8;  /* 0054 */
  a10 = LD8U(a2 + 0x4);  /* 0057 */
  a10 = a10 << 8;  /* 005a */
  a8 = LD8U(a2 + 0x3);  /* 005d */
  a10 = a10 | a8;  /* 0060 */
  a8 = LD8U(a2 + 0x5);  /* 0063 */
  a8 = a8 << 16;  /* 0066 */
  a8 = a8 | a10;  /* 0069 */
  a12 = LD8U(a2 + 0x14);  /* 006c */
  a12 = a12 << 24;  /* 006f */
  a12 = a12 | a11;  /* 0072 */
  a13 = LD8U(a2 + 0x18);  /* 0075 */
  a13 = a13 << 24;  /* 0078 */
  a13 = a13 | a9;  /* 007b */
  a10 = LD8U(a2 + 0x6);  /* 007e */
  a10 = a10 << 24;  /* 0081 */
  a10 = a10 | a8;  /* 0084 */
  a8 = (u32)&mesh_nwk_duty_check_duration_expire;  /* 0087: l32r -> func addr */
  a2 = mesh_nwk_duty_check_duration_expire(a2, a3, a4, a5, a6, a7);  /* 008a: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00a6;  /* 008d: beqz.n a10, a6 <esp_mesh_root_process_duty_duration_expire+0x8e> */
  L_008f: a12 = 0;  /* 008f */
  a10 = (u32)&LOCAL__bss_esp_mesh_remain_nwk_duty + 0x0;  /* 0091: l32r -> .bss.esp_mesh_remain_nwk_duty (same-object static) */
  a11 = a12;  /* 0094 */
  a8 = (u32)&mesh_nwk_duty_process_remaining;  /* 0096: l32r -> func addr */
  a2 = mesh_nwk_duty_process_remaining(a2, a3, a4, a5, a6, a7);  /* 0099: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00a6;  /* 009c: beqz.n a10, a6 <esp_mesh_root_process_duty_duration_expire+0x8e> */
  L_009e: a10 = a2;  /* 009e */
  a8 = (u32)&mesh_nwk_duty_clr_master_identity;  /* 00a0: l32r -> func addr */
  a2 = mesh_nwk_duty_clr_master_identity(a2, a3, a4, a5, a6, a7);  /* 00a3: callx a8 via reloc-expand */
  L_00a6: a2 = 0;  /* 00a6 */
  return a2;  /* 00a8: retw.n */
}


/* esp_mesh_sta_monitor_rssi @ mesh_quick.o 0000003c size 274B bind GLOBAL
 * Calls: esp_mesh_get_router_bssid, memcmp, ieee80211_mesh_quick_get, ieee80211_mesh_quick_set | Data refs: .rodata, esp_mesh_appie, .bss.s_mesh_parent_candidate
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=4, refs=7); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_sta_monitor_rssi(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 003c: entry a1, 64 (frame 64 bytes) */
  a8 = -1;  /* 003f */
  if (a2 == 0) goto L_014a;  /* 0041: beqz a2, 14a <esp_mesh_sta_monitor_rssi+0x10e> */
  L_0044: a3 = (u32)(RODATA__rodata + 0x0);  /* 0044: l32r -> .rodata */
  a8 = 0;  /* 0047 */
  a10 = a1;  /* 0049 */
  a5 = LD8U(a3 + 0x0);  /* 004b */
  a3 = LD8U(a3 + 0x1);  /* 004e */
  ST8(a1 + 0x7, a3);  /* 0051 */
  a3 = -1;  /* 0054 */
  ST32(a1 + 0xc, a8);  /* 0056 */
  ST16(a1 + 0x10, a8);  /* 0058 */
  ST16(a1 + 0x8, a8);  /* 005b */
  ST16(a1 + 0xa, a8);  /* 005e */
  ST32(a1 + 0x0, a8);  /* 0061 */
  ST16(a1 + 0x4, a8);  /* 0063 */
  ST8(a1 + 0x6, a5);  /* 0066 */
  ST8(a1 + 0x12, a3);  /* 0069 */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  __asm__ volatile("" ::: "memory");  /* 006f: memw */
  a8 = (u32)&esp_mesh_get_router_bssid + 0x0;  /* 0072: l32r -> global */
  a2 = esp_mesh_get_router_bssid(a2, a3, a4, a5, a6, a7);  /* 0075: callx a8 via reloc-expand */
  a12 = 6;  /* 0078 */
  a11 = a1;  /* 007a */
  a10 = a2;  /* 007c */
  a8 = (u32)&memcmp + 0x0;  /* 007e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0081: callx a8 (libc, via reloc-expand) */
  a6 = a10;  /* 0084 */
  if (a10 != 0) goto L_00e9;  /* 0086: bnez a10, e9 <esp_mesh_sta_monitor_rssi+0xad> */
  L_0089: a5 = (u32)&esp_mesh_appie + 0x0;  /* 0089: l32r -> global */
  a12 = a1 + (19);  /* 008c */
  a11 = 13;  /* 008f */
  a2 = LD32(a5 + 0x0);  /* 0091 */
  a2 = a2 + (2);  /* 0093 */
  a10 = a2;  /* 0095 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0097: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 009a: callx a8 via reloc-expand */
  a3 = LD8U(a1 + 0x13);  /* 009d */
  a3 = (i32)(a3 << (32 - 7)) >> (32 - 7);  /* 00a0: sext */
  if (a3 != a4) goto L_00a9;  /* 00a3: bne a3, a4, a9 <esp_mesh_sta_monitor_rssi+0x6d> */
  L_00a6: goto L_00e4;  /* 00a6: j */
  L_00a9: a12 = a1 + (19);  /* 00a9 */
  a11 = 13;  /* 00ac */
  a10 = a2;  /* 00ae: mov */
  ST8(a1 + 0x13, a4);  /* 00b1 */
  __asm__ volatile("" ::: "memory");  /* 00b4: memw */
  __asm__ volatile("" ::: "memory");  /* 00b7: memw */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 00ba: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5, a6, a7);  /* 00bd: callx a8 via reloc-expand */
  a12 = a1 + (18);  /* 00c0 */
  a11 = a6;  /* 00c3 */
  a2 = LD32(a5 + 0x0);  /* 00c5 */
  a2 = a2 + (2);  /* 00c7 */
  a10 = a2;  /* 00c9 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00cb: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 00ce: callx a8 via reloc-expand */
  a3 = LD8U(a1 + 0x12);  /* 00d1 */
  if (a3 != 1) goto L_00e4;  /* 00d4: bnei a3, 1, e4 <esp_mesh_sta_monitor_rssi+0xa8> */
  L_00d7: a12 = a1 + (19);  /* 00d7 */
  a11 = 16;  /* 00da */
  a10 = a2;  /* 00dc */
  a8 = (u32)&ieee80211_mesh_quick_set;  /* 00de: l32r -> func addr */
  a2 = ieee80211_mesh_quick_set(a2, a3, a4, a5, a6, a7);  /* 00e1: callx a8 via reloc-expand */
  L_00e4: a8 = 3;  /* 00e4 */
  goto L_014a;  /* 00e6: j */
  L_00e9: a3 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 00e9: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a3 = LD8U(a3 + 0x0);  /* 00ec */
  if (a3 == 0) goto L_0105;  /* 00ef: beqz.n a3, 105 <esp_mesh_sta_monitor_rssi+0xc9> */
  L_00f1: a12 = 6;  /* 00f1 */
  a10 = a2;  /* 00f4: mov */
  a11 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 00f7: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a8 = (u32)&memcmp + 0x0;  /* 00fa: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00fd: callx a8 (libc, via reloc-expand) */
  a8 = 2;  /* 0100 */
  if (a10 == 0) goto L_014a;  /* 0102: beqz a10, 14a <esp_mesh_sta_monitor_rssi+0x10e> */
  L_0105: a3 = (u32)&esp_mesh_appie + 0x0;  /* 0105: l32r -> global */
  a12 = a1 + (12);  /* 0108 */
  a11 = 15;  /* 010a */
  a3 = LD32(a3 + 0x0);  /* 010c */
  a3 = a3 + (2);  /* 010e */
  a10 = a3;  /* 0110 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0112: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0115: callx a8 via reloc-expand */
  a12 = a1 + (6);  /* 0118 */
  a11 = 17;  /* 011a */
  a10 = a3;  /* 011c */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 011e: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0121: callx a8 via reloc-expand */
  a12 = 6;  /* 0124 */
  a11 = a1 + (12);  /* 0126 */
  a10 = a2;  /* 0128 */
  a8 = (u32)&memcmp + 0x0;  /* 012a: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 012d: callx a8 (libc, via reloc-expand) */
  a8 = 4;  /* 0130 */
  if (a10 == 0) goto L_014a;  /* 0132: beqz.n a10, 14a <esp_mesh_sta_monitor_rssi+0x10e> */
  L_0134: a12 = 6;  /* 0134 */
  a10 = a2;  /* 0136 */
  a11 = a1 + a12;  /* 0138 */
  a8 = (u32)&memcmp + 0x0;  /* 013a: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 013d: callx a8 (libc, via reloc-expand) */
  a8 = 1;  /* 0140 */
  a2 = 0;  /* 0142 */
  if (a10 != 0) a8 = a2;  /* 0144 */
  a8 = a8 << 2;  /* 0147 */
  L_014a: a2 = a8;  /* 014a */
  return a2;  /* 014c: retw.n */
}


/* esp_mesh_sync_interface_tsf @ mesh_quick.o 00000014 size 134B bind GLOBAL
 * Calls: hal_get_tsf_time, wDev_Mesh_Set_TBTT | Data refs: .bss.rx_bcn_count$0
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_sync_interface_tsf(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a9 = (u32)&LOCAL__bss_rx_bcn_count_0 + 0x0;  /* 0017: l32r -> .bss.rx_bcn_count$0 (same-object static) */
  a3 = (a3 >> 8) & 0x1;  /* 001a: extui width 1 */
  a4 = (a4 >> 8) & 0x1;  /* 001d: extui width 1 */
  a5 = (a5 >> 8) & 0x1;  /* 0020: extui width 1 */
  a8 = LD32(a9 + 0x0);  /* 0023 */
  a8 = a8 + (1);  /* 0025 */
  a2 = (a8 >> 10) & 0x1;  /* 0027: extui width 1 */
  if (a2 == 0) goto L_0036;  /* 002a: beqz.n a2, 36 <esp_mesh_sync_interface_tsf+0x22> */
  L_002c: if (a5 != 0) goto L_0036;  /* 002c: bnez.n a5, 36 <esp_mesh_sync_interface_tsf+0x22> */
  L_002e: ST32(a9 + 0x0, a8);  /* 002e */
  __asm__ volatile("" ::: "memory");  /* 0030: memw */
  goto L_0063;  /* 0033: j */
  L_0036: a2 = 0;  /* 0036 */
  a10 = a2;  /* 0038 */
  ST32(a9 + 0x0, a2);  /* 003a */
  __asm__ volatile("" ::: "memory");  /* 003c: memw */
  a8 = (u32)&hal_get_tsf_time + 0x0;  /* 003f: l32r -> global */
  a2 = hal_get_tsf_time(a2, a3, a4, a5, a6, a7);  /* 0042: callx a8 via reloc-expand */
  a5 = a10;  /* 0045 */
  a10 = 1;  /* 0047 */
  a2 = a11;  /* 0049 */
  a8 = (u32)&hal_get_tsf_time + 0x0;  /* 004b: l32r -> global */
  a2 = hal_get_tsf_time(a2, a3, a4, a5, a6, a7);  /* 004e: callx a8 via reloc-expand */
  if ((i32)a11 < (i32)a2) goto L_0060;  /* 0051: blt a11, a2, 60 <esp_mesh_sync_interface_tsf+0x4c> */
  L_0054: if (a2 != a11) goto L_005a;  /* 0054: bne a2, a11, 5a <esp_mesh_sync_interface_tsf+0x46> */
  L_0057: if (a10 < a5) goto L_0060;  /* 0057: bltu a10, a5, 60 <esp_mesh_sync_interface_tsf+0x4c> */
  L_005a: a5 = a10 - a5;  /* 005a: sub */
  goto L_0063;  /* 005d: j */
  L_0060: a5 = a5 - a10;  /* 0060: sub */
  L_0063: a2 = 1;  /* 0063 */
  a3 = a3 ^ a2;  /* 0065 */
  a4 = a4 | a3;  /* 0068 */
  a4 = (a4 >> 8) & 0x1;  /* 006b: extui width 1 */
  if (a4 != 0) goto L_0078;  /* 006e: bnez.n a4, 78 <esp_mesh_sync_interface_tsf+0x64> */
  L_0070: a4 = 3;  /* 0070 */
  a4 = a4 << 11;  /* 0072 */
  if ((i32)a4 >= (i32)a5) goto L_0096;  /* 0075: bge a4, a5, 96 <esp_mesh_sync_interface_tsf+0x82> */
  L_0078: a10 = 0;  /* 0078 */
  a8 = (u32)&hal_get_tsf_time + 0x0;  /* 007a: l32r -> global */
  a2 = hal_get_tsf_time(a2, a3, a4, a5, a6, a7);  /* 007d: callx a8 via reloc-expand */
  a4 = a10 + 0xfff40000;  /* 0080: addmi a4, a10, 0xfffff400 */
  a3 = 1;  /* 0083 */
  if (a4 < a10) goto L_008a;  /* 0085: bltu a4, a10, 8a <esp_mesh_sync_interface_tsf+0x76> */
  L_0088: a3 = 0;  /* 0088 */
  L_008a: a11 = a11 + (-1);  /* 008a */
  a10 = a4;  /* 008c */
  a11 = a3 + a11;  /* 008e */
  a8 = (u32)&wDev_Mesh_Set_TBTT + 0x0;  /* 0090: l32r -> global */
  a2 = wDev_Mesh_Set_TBTT(a2, a3, a4, a5, a6, a7);  /* 0093: callx a8 via reloc-expand */
  L_0096: a2 = 0;  /* 0096 */
  return a2;  /* 0098: retw.n */
}


/* esp_mesh_update_conflict_root @ mesh_quick.o 00000008 size 234B bind GLOBAL
 * Calls: none | indirect[1]: mem[a2+0x110] | Data refs: .bss.s_mesh_conflict_roots, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_update_conflict_root(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  float F0;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a9 = a2;  /* 000b */
  a2 = 0;  /* 000d */
  a11 = a3 + (1);  /* 000f */
  a10 = 1;  /* 0011 */
  a8 = a2;  /* 0013 */
  if (a11 == 0) a8 = a10;  /* 0015 */
  a11 = 9;  /* 0018 */
  if ((i32)a11 < (i32)a3) goto L_0020;  /* 001a: blt a11, a3, 20 <esp_mesh_update_conflict_root+0x18> */
  L_001d: a10 = a2;  /* 001d: mov */
  L_0020: a8 = a8 | a10;  /* 0020 */
  a8 = (a8 >> 8) & 0x1;  /* 0023: extui width 1 */
  if (a8 != 0) goto L_00ee;  /* 0026: bnez a8, ee <esp_mesh_update_conflict_root+0xe6> */
  L_0029: a2 = 1;  /* 0029 */
  if (a9 != 0) a2 = a8;  /* 002b */
  if (a2 != 0) goto L_00ee;  /* 002e: bnez a2, ee <esp_mesh_update_conflict_root+0xe6> */
  L_0031: a8 = LD8U(a9 + 0x1);  /* 0031 */
  a3 = a3 + (a3 << 1);  /* 0034 */
  a8 = a8 << 8;  /* 0037 */
  a2 = LD8U(a9 + 0x0);  /* 003a */
  a8 = a8 | a2;  /* 003d */
  a2 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0040: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a2 = LD32(a2 + 0x0);  /* 0043 */
  a3 = a3 + (a2 << 3);  /* 0045 */
  a10 = LD8U(a3 + 0xe);  /* 0048 */
  a10 = a10 << 8;  /* 004b */
  a2 = LD8U(a3 + 0xd);  /* 004e */
  a10 = a10 | a2;  /* 0051 */
  a2 = -1;  /* 0054 */
  if (a8 >= a10) goto L_005c;  /* 0056: bgeu a8, a10, 5c <esp_mesh_update_conflict_root+0x54> */
  L_0059: goto L_00f0;  /* 0059: j */
  L_005c: ST8(a3 + 0xd, a8);  /* 005c */
  __asm__ volatile("" ::: "memory");  /* 005f: memw */
  a8 = a8 >> 8;  /* 0062 */
  a10 = LD8U(a3 + 0x17);  /* 0065 */
  ST8(a3 + 0xe, a8);  /* 0068 */
  __asm__ volatile("" ::: "memory");  /* 006b: memw */
  a8 = LD8U(a9 + 0xa);  /* 006e */
  if (a10 != 0) goto L_0079;  /* 0071: bnez.n a10, 79 <esp_mesh_update_conflict_root+0x71> */
  L_0073: __asm__ volatile("" ::: "memory");  /* 0073: memw */
  goto L_0092;  /* 0076: j */
  L_0079: a10 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 0079: sext */
  a2 = a10 + (a10 << 1);  /* 007c */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 007f: sext */
  a2 = a2 + (a10 << 2);  /* 0082 */
  a8 = a8 + (a8 << 1);  /* 0085 */
  a8 = a8 + a2;  /* 0088 */
  a10 = a8 + (15);  /* 008a */
  if ((i32)a8 >= 0) a10 = a8;  /* 008c */
  a8 = (a10 >> 8) & 0x1f;  /* 008f: extui width 5 */
  L_0092: ST8(a3 + 0x17, a8);  /* 0092 */
  __asm__ volatile("" ::: "memory");  /* 0095: memw */
  a2 = LD8U(a9 + 0x3);  /* 0098 */
  a8 = LD8U(a9 + 0x2);  /* 009b */
  ST8(a3 + 0x10, a2);  /* 009e */
  __asm__ volatile("" ::: "memory");  /* 00a1: memw */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00a4: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00a7 */
  a10 = LD32(a2 + 0x110);  /* 00a9 */
  ST8(a3 + 0xf, a8);  /* 00ac */
  __asm__ volatile("" ::: "memory");  /* 00af: memw */
  __asm__ volatile("" ::: "memory");  /* 00b2: memw */
  /* 00b5: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a2 = (a10 >> 8) & 0x1ff;  /* 00b8: extui width 9 */
  ST8(a3 + 0x2, a2);  /* 00bb */
  a2 = (a10 >> 8) & 0x1ffff;  /* 00be: extui width 17 */
  ST8(a3 + 0x3, a2);  /* 00c1 */
  a2 = (a11 >> 8) & 0x1ff;  /* 00c4: extui width 9 */
  ST8(a3 + 0x1, a10);  /* 00c7 */
  a10 = (a10 >> 8) & 0x1ffffff;  /* 00ca: extui width 25 */
  ST8(a3 + 0x5, a11);  /* 00cd */
  ST8(a3 + 0x6, a2);  /* 00d0 */
  a2 = (a11 >> 8) & 0x1ffff;  /* 00d3: extui width 17 */
  a11 = (a11 >> 8) & 0x1ffffff;  /* 00d6: extui width 25 */
  ST8(a3 + 0x7, a2);  /* 00d9 */
  a2 = 0;  /* 00dc */
  ST8(a3 + 0x4, a10);  /* 00de */
  ST8(a3 + 0x8, a11);  /* 00e1 */
  __asm__ volatile("" ::: "memory");  /* 00e4: memw */
  __asm__ volatile("" ::: "memory");  /* 00e7: memw */
  goto L_00f0;  /* 00ea: j */
  L_00ee: a2 = -1;  /* 00ee */
  L_00f0: return a2;  /* 00f0: retw.n */
}


/* ieee80211_add_ie_esp_mesh_head @ mesh_quick.o 00000004 size 60B bind GLOBAL
 * Calls: none | Data refs: .rodata.ieee80211_add_ie_esp_mesh_head.str1.1
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_add_ie_esp_mesh_head(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = -35;  /* 0007 */
  ST8(a2 + 0x0, a8);  /* 000a */
  __asm__ volatile("" ::: "memory");  /* 000d: memw */
  a4 = (a4 >> 8) & 0x1;  /* 0010: extui width 1 */
  a4 = a4 + a4;  /* 0013 */
  a4 = a6 | a4;  /* 0015 */
  a8 = (u32)(RODATA__rodata_ieee80211_add_ie_esp_mesh_head_str1_1 + 0x0);  /* 0018: l32r -> .rodata.ieee80211_add_ie_esp_mesh_head.str1.1 */
  a11 = LD8U(a8 + 0x0);  /* 001b */
  a10 = LD8U(a8 + 0x1);  /* 001e */
  a8 = LD8U(a8 + 0x2);  /* 0021 */
  ST8(a2 + 0x1, a5);  /* 0024 */
  ST8(a2 + 0x2, a11);  /* 0027 */
  ST8(a2 + 0x3, a10);  /* 002a */
  ST8(a2 + 0x4, a8);  /* 002d */
  ST8(a2 + 0x5, a3);  /* 0030 */
  ST8(a2 + 0x6, a4);  /* 0033 */
  __asm__ volatile("" ::: "memory");  /* 0036: memw */
  a2 = a2 + (7);  /* 0039 */
  __asm__ volatile("" ::: "memory");  /* 003b: memw */
  return a2;  /* 003e: retw.n */
}


/* ieee80211_add_mesh_assoc_ie @ mesh_quick.o 00000018 size 134B bind GLOBAL
 * Calls: is_my_ie_encrypted, memcpy, crc32_le, esp_mesh_encrypt_vnd_ie | Data refs: esp_mesh_appie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=4, refs=5); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_add_mesh_assoc_ie(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a4, a5, a6, a7, a8, a9;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a6 = 1;  /* 001b */
  a8 = 0;  /* 001d */
  if (a2 == 0) a8 = a6;  /* 0020 */
  a4 = (a8 >> 8) & 0x1;  /* 0023: extui width 1 */
  if (a8 != 0) goto L_009c;  /* 0026: bnez a8, 9c <ieee80211_add_mesh_assoc_ie+0x84> */
  L_0029: if (a3 == 0) a4 = a6;  /* 0029 */
  if (a4 != 0) goto L_009c;  /* 002c: bnez a4, 9c <ieee80211_add_mesh_assoc_ie+0x84> */
  L_002f: a5 = (u32)&esp_mesh_appie + 0x0;  /* 002f: l32r -> global */
  a7 = LD32(a5 + 0x0);  /* 0032 */
  if (a7 == 0) goto L_009c;  /* 0035: beqz a7, 9c <ieee80211_add_mesh_assoc_ie+0x84> */
  L_0038: a8 = (u32)&is_my_ie_encrypted;  /* 0038: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3);  /* 003b: callx a8 via reloc-expand */
  a11 = a7 + (2);  /* 003e */
  a4 = a10;  /* 0040 */
  a12 = 7;  /* 0042 */
  a10 = a2;  /* 0044: mov */
  a8 = (u32)&memcpy + 0x0;  /* 0047: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 004a: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a2 + 0x6);  /* 004d */
  a9 = -2;  /* 0050 */
  a8 = a8 & a9;  /* 0052 */
  a7 = a4 & a6;  /* 0055 */
  a8 = a8 | a7;  /* 0058 */
  a11 = LD32(a5 + 0x0);  /* 005b */
  a7 = a2 + (7);  /* 005d */
  a12 = 64;  /* 005f */
  a11 = a11 + (9);  /* 0061 */
  a10 = a7;  /* 0063 */
  ST8(a2 + 0x6, a8);  /* 0065 */
  __asm__ volatile("" ::: "memory");  /* 0068: memw */
  __asm__ volatile("" ::: "memory");  /* 006b: memw */
  a8 = (u32)&memcpy + 0x0;  /* 006e: l32r -> global */
  a2 = memcpy(a2, a3);  /* 0071: callx a8 (libc, via reloc-expand) */
  a12 = 60;  /* 0074 */
  a11 = a7;  /* 0076 */
  a10 = -1;  /* 0078 */
  a8 = (u32)&crc32_le + 0x0;  /* 007a: l32r -> global */
  a2 = crc32_le(a2, a3);  /* 007d: callx a8 via reloc-expand */
  a5 = a2 + (67);  /* 0080 */
  ST32(a5 + 0x0, a10);  /* 0083 */
  if (a4 == 0) goto L_0099;  /* 0085: beqz.n a4, 99 <ieee80211_add_mesh_assoc_ie+0x81> */
  L_0087: a13 = a3;  /* 0087 */
  a12 = a7;  /* 0089 */
  a11 = 64;  /* 008b */
  a10 = a6;  /* 008d: mov */
  __asm__ volatile("" ::: "memory");  /* 0090: memw */
  a8 = (u32)&esp_mesh_encrypt_vnd_ie;  /* 0093: l32r -> func addr */
  a2 = esp_mesh_encrypt_vnd_ie(a2, a3);  /* 0096: callx a8 via reloc-expand */
  L_0099: a2 = a2 + (71);  /* 0099 */
  L_009c: return a2;  /* 009c: retw.n */
}


/* ieee80211_add_mesh_duty_signaling @ mesh_quick.o 00000028 size 194B bind GLOBAL
 * Calls: memcpy, is_my_ie_encrypted, ieee80211_add_ie_esp_mesh_head, ieee80211_mesh_quick_get, crc32_le, esp_mesh_encrypt_vnd_ie | Data refs: esp_mesh_appie, .rodata.ieee80211_add_mesh_duty_signaling.str1.1, esp_mesh_ps_duty
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=6, refs=9); reloc-direct=6, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_add_mesh_duty_signaling(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a7, a8, a9;
  /* 0028: entry a1, 64 (frame 64 bytes) */
  a9 = (u32)&esp_mesh_appie + 0x0;  /* 002b: l32r -> global */
  a10 = a3;  /* 002e */
  a5 = (a5 >> 8) & 0x1;  /* 0030: extui width 1 */
  a3 = LD32(a9 + 0x0);  /* 0033 */
  if (a3 == 0) goto L_00e8;  /* 0035: beqz a3, e8 <ieee80211_add_mesh_duty_signaling+0xc0> */
  L_0038: a7 = 0;  /* 0038 */
  a3 = 1;  /* 003a */
  a8 = a7;  /* 003c */
  if (a2 == 0) a8 = a3;  /* 003e */
  if (a10 == 0) a7 = a3;  /* 0041 */
  a8 = a8 | a7;  /* 0044 */
  if (a8 != 0) goto L_00e8;  /* 0047: bnez a8, e8 <ieee80211_add_mesh_duty_signaling+0xc0> */
  L_004a: if (a5 == 0) a8 = a3;  /* 004a */
  if (a8 != 0) goto L_00e8;  /* 004d: bnez a8, e8 <ieee80211_add_mesh_duty_signaling+0xc0> */
  L_0050: a11 = (u32)(RODATA__rodata_ieee80211_add_mesh_duty_signaling_str1_1 + 0x0);  /* 0050: l32r -> .rodata.ieee80211_add_mesh_duty_signaling.str1.1 */
  a12 = 6;  /* 0053 */
  a10 = a1;  /* 0055: mov */
  ST32(a1 + 0x10, a9);  /* 0058 */
  __asm__ volatile("" ::: "memory");  /* 005b: memw */
  a8 = (u32)&memcpy + 0x0;  /* 005e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 0061: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&is_my_ie_encrypted;  /* 0064: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6);  /* 0067: callx a8 via reloc-expand */
  a14 = a10;  /* 006a */
  a12 = a3;  /* 006c */
  a13 = 53;  /* 006e */
  a11 = 15;  /* 0070 */
  a7 = a10;  /* 0072 */
  a10 = a2;  /* 0074: mov */
  a8 = (u32)&ieee80211_add_ie_esp_mesh_head;  /* 0077: l32r -> func addr */
  a2 = ieee80211_add_ie_esp_mesh_head(a2, a3, a4, a5, a6, a7);  /* 007a: callx a8 via reloc-expand */
  ST8(a2 + 0x7, a5);  /* 007d */
  __asm__ volatile("" ::: "memory");  /* 0080: memw */
  a8 = (a4 >> 8) & 0x1ff;  /* 0083: extui width 9 */
  a3 = a10;  /* 0086 */
  a12 = a2 + (12);  /* 0088 */
  a11 = 15;  /* 008a */
  a9 = LD32(a1 + 0x10);  /* 008c */
  a10 = LD32(a9 + 0x0);  /* 008e */
  a10 = a10 + (2);  /* 0090 */
  ST8(a2 + 0x8, a4);  /* 0092 */
  ST8(a2 + 0x9, a8);  /* 0095 */
  a8 = (a4 >> 8) & 0x1ffff;  /* 0098: extui width 17 */
  a4 = (a4 >> 8) & 0x1ffffff;  /* 009b: extui width 25 */
  ST8(a2 + 0xa, a8);  /* 009e */
  ST8(a2 + 0xb, a4);  /* 00a1 */
  __asm__ volatile("" ::: "memory");  /* 00a4: memw */
  __asm__ volatile("" ::: "memory");  /* 00a7: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00aa: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6);  /* 00ad: callx a8 via reloc-expand */
  a10 = a2 + (18);  /* 00b0 */
  a12 = 16;  /* 00b3 */
  a11 = a6;  /* 00b5 */
  if (a6 != 0) goto L_00bc;  /* 00b7: bnez.n a6, bc <ieee80211_add_mesh_duty_signaling+0x94> */
  L_00b9: a11 = (u32)&esp_mesh_ps_duty + 0x0;  /* 00b9: l32r -> global */
  L_00bc: a8 = (u32)&memcpy + 0x0;  /* 00bc: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 00bf: callx a8 (libc, via reloc-expand) */
  a12 = 44;  /* 00c2 */
  a11 = a3;  /* 00c4 */
  a10 = -1;  /* 00c6 */
  a8 = (u32)&crc32_le + 0x0;  /* 00c8: l32r -> global */
  a2 = crc32_le(a2, a3, a4, a5, a6);  /* 00cb: callx a8 via reloc-expand */
  ST32(a3 + 0x2c, a10);  /* 00ce */
  if (a7 == 0) goto L_00e5;  /* 00d0: beqz.n a7, e5 <ieee80211_add_mesh_duty_signaling+0xbd> */
  L_00d2: a13 = a1;  /* 00d2 */
  a12 = a3;  /* 00d4 */
  a11 = 48;  /* 00d6 */
  a10 = 64;  /* 00d9 */
  __asm__ volatile("" ::: "memory");  /* 00dc: memw */
  a8 = (u32)&esp_mesh_encrypt_vnd_ie;  /* 00df: l32r -> func addr */
  a2 = esp_mesh_encrypt_vnd_ie(a2, a3, a4, a5, a6);  /* 00e2: callx a8 via reloc-expand */
  L_00e5: a2 = a3 + (48);  /* 00e5 */
  L_00e8: return a2;  /* 00e8: retw.n */
}


/* ieee80211_add_mesh_ext_assoc_ie @ mesh_quick.o 0000001c size 118B bind GLOBAL
 * Calls: is_my_ie_encrypted, ieee80211_add_ie_esp_mesh_head, esp_mesh_get_router_bssid, crc32_le, esp_mesh_encrypt_vnd_ie | Data refs: esp_mesh_appie, g_mesh_init_ps_type
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=5, refs=7); reloc-direct=5, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_add_mesh_ext_assoc_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  /* 001c: entry a1, 32 (frame 32 bytes) */
  a4 = (u32)&esp_mesh_appie + 0x0;  /* 001f: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0022 */
  if (a4 == 0) goto L_0090;  /* 0024: beqz a4, 90 <ieee80211_add_mesh_ext_assoc_ie+0x74> */
  L_0027: a5 = 1;  /* 0027 */
  a4 = 0;  /* 0029 */
  if (a2 == 0) a4 = a5;  /* 002c */
  a8 = (a4 >> 8) & 0x1;  /* 002f: extui width 1 */
  if (a4 != 0) goto L_0090;  /* 0032: bnez a4, 90 <ieee80211_add_mesh_ext_assoc_ie+0x74> */
  L_0035: a4 = a8;  /* 0035: mov */
  if (a3 == 0) a4 = a5;  /* 0038 */
  if (a4 != 0) goto L_0090;  /* 003b: bnez a4, 90 <ieee80211_add_mesh_ext_assoc_ie+0x74> */
  L_003e: a8 = (u32)&is_my_ie_encrypted;  /* 003e: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6, a7);  /* 0041: callx a8 via reloc-expand */
  a4 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0044: l32r -> global */
  a14 = a10;  /* 0047 */
  a13 = 21;  /* 0049 */
  a11 = 12;  /* 004b */
  a6 = a10;  /* 004d */
  a12 = LD32(a4 + 0x0);  /* 004f */
  a4 = 2;  /* 0051 */
  if (a12 != 0) a5 = a4;  /* 0053 */
  a12 = a5;  /* 0056 */
  a10 = a2;  /* 0058 */
  a8 = (u32)&ieee80211_add_ie_esp_mesh_head;  /* 005a: l32r -> func addr */
  a2 = ieee80211_add_ie_esp_mesh_head(a2, a3, a4, a5, a6, a7);  /* 005d: callx a8 via reloc-expand */
  a4 = a10;  /* 0060 */
  a10 = a2 + (7);  /* 0062 */
  a8 = (u32)&esp_mesh_get_router_bssid + 0x0;  /* 0064: l32r -> global */
  a2 = esp_mesh_get_router_bssid(a2, a3, a4, a5, a6, a7);  /* 0067: callx a8 via reloc-expand */
  a12 = 12;  /* 006a */
  a11 = a4;  /* 006c */
  a10 = -1;  /* 006e */
  a8 = (u32)&crc32_le + 0x0;  /* 0070: l32r -> global */
  a2 = crc32_le(a2, a3, a4, a5, a6, a7);  /* 0073: callx a8 via reloc-expand */
  ST32(a4 + 0xc, a10);  /* 0076 */
  if (a6 == 0) goto L_008d;  /* 0078: beqz.n a6, 8d <ieee80211_add_mesh_ext_assoc_ie+0x71> */
  L_007a: a13 = a3;  /* 007a */
  a12 = a4;  /* 007c */
  a11 = 16;  /* 007e */
  a10 = 8;  /* 0081 */
  __asm__ volatile("" ::: "memory");  /* 0084: memw */
  a8 = (u32)&esp_mesh_encrypt_vnd_ie;  /* 0087: l32r -> func addr */
  a2 = esp_mesh_encrypt_vnd_ie(a2, a3, a4, a5, a6, a7);  /* 008a: callx a8 via reloc-expand */
  L_008d: a2 = a4 + (16);  /* 008d */
  L_0090: return a2;  /* 0090: retw.n */
}


/* ieee80211_add_mesh_ps_ie @ mesh_quick.o 0000001c size 114B bind GLOBAL
 * Calls: is_my_ie_encrypted, ieee80211_add_ie_esp_mesh_head, memcpy, crc32_le, esp_mesh_encrypt_vnd_ie | Data refs: esp_mesh_appie, esp_mesh_ps_duty
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=5, refs=7); reloc-direct=5, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_add_mesh_ps_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  /* 001c: entry a1, 32 (frame 32 bytes) */
  a2 = a3;  /* 001f */
  a3 = (u32)&esp_mesh_appie + 0x0;  /* 0021: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0024 */
  if (a3 == 0) goto L_008c;  /* 0026: beqz a3, 8c <ieee80211_add_mesh_ps_ie+0x70> */
  L_0029: a5 = 1;  /* 0029 */
  a3 = 0;  /* 002b */
  if (a2 == 0) a3 = a5;  /* 002d */
  a8 = (a3 >> 8) & 0x1;  /* 0030: extui width 1 */
  if (a3 != 0) goto L_008c;  /* 0033: bnez a3, 8c <ieee80211_add_mesh_ps_ie+0x70> */
  L_0036: a3 = a8;  /* 0036: mov */
  if (a4 == 0) a3 = a5;  /* 0039 */
  if (a3 != 0) goto L_008c;  /* 003c: bnez a3, 8c <ieee80211_add_mesh_ps_ie+0x70> */
  L_003f: a8 = (u32)&is_my_ie_encrypted;  /* 003f: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6, a7);  /* 0042: callx a8 via reloc-expand */
  a14 = a10;  /* 0045 */
  a13 = 37;  /* 0047 */
  a12 = a5;  /* 0049 */
  a11 = 14;  /* 004b */
  a6 = a10;  /* 004d: mov */
  a10 = a2;  /* 0050: mov */
  a8 = (u32)&ieee80211_add_ie_esp_mesh_head;  /* 0053: l32r -> func addr */
  a2 = ieee80211_add_ie_esp_mesh_head(a2, a3, a4, a5, a6, a7);  /* 0056: callx a8 via reloc-expand */
  a11 = (u32)&esp_mesh_ps_duty + 0x0;  /* 0059: l32r -> global */
  a3 = a10;  /* 005c */
  a12 = 16;  /* 005e */
  a10 = a2 + (7);  /* 0060 */
  a8 = (u32)&memcpy + 0x0;  /* 0062: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0065: callx a8 (libc, via reloc-expand) */
  a12 = 28;  /* 0068 */
  a11 = a3;  /* 006a */
  a10 = -1;  /* 006c */
  a8 = (u32)&crc32_le + 0x0;  /* 006e: l32r -> global */
  a2 = crc32_le(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 via reloc-expand */
  ST32(a3 + 0x1c, a10);  /* 0074 */
  if (a6 == 0) goto L_0089;  /* 0076: beqz.n a6, 89 <ieee80211_add_mesh_ps_ie+0x6d> */
  L_0078: a11 = 32;  /* 0078 */
  a13 = a4;  /* 007a */
  a12 = a3;  /* 007c */
  a10 = a11;  /* 007e */
  __asm__ volatile("" ::: "memory");  /* 0080: memw */
  a8 = (u32)&esp_mesh_encrypt_vnd_ie;  /* 0083: l32r -> func addr */
  a2 = esp_mesh_encrypt_vnd_ie(a2, a3, a4, a5, a6, a7);  /* 0086: callx a8 via reloc-expand */
  L_0089: a2 = a3 + (32);  /* 0089 */
  L_008c: return a2;  /* 008c: retw.n */
}


/* ieee80211_add_mesh_roots_ie @ mesh_quick.o 00000024 size 266B bind GLOBAL
 * Calls: mesh_get_vnd_roots_len, is_my_ie_encrypted, ieee80211_add_ie_esp_mesh_head, memcpy, memset, crc32_le, esp_mesh_encrypt_vnd_ie | Data refs: .bss.wifi_vnd_ext_mesh_roots, g_mesh_init_ps_type
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=7, refs=9); reloc-direct=7, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_add_mesh_roots_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a4 = 1;  /* 0027 */
  a5 = 0;  /* 0029 */
  if (a2 == 0) a5 = a4;  /* 002b */
  a6 = (a5 >> 8) & 0x1;  /* 002e: extui width 1 */
  if (a5 != 0) goto L_012c;  /* 0031: bnez a5, 12c <ieee80211_add_mesh_roots_ie+0x108> */
  L_0034: if (a3 != 0) a4 = a6;  /* 0034 */
  if (a4 != 0) goto L_012c;  /* 0037: bnez a4, 12c <ieee80211_add_mesh_roots_ie+0x108> */
  L_003a: a8 = (u32)&mesh_get_vnd_roots_len;  /* 003a: l32r -> func addr */
  a2 = mesh_get_vnd_roots_len(a2, a3, a4, a5, a6, a7);  /* 003d: callx a8 via reloc-expand */
  if (a10 == 0) goto L_012c;  /* 0040: beqz a10, 12c <ieee80211_add_mesh_roots_ie+0x108> */
  L_0043: a8 = (u32)&is_my_ie_encrypted;  /* 0043: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6, a7);  /* 0046: callx a8 via reloc-expand */
  a7 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0049: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a9 = a10;  /* 004c */
  L_004e: a15 = a4 << 3;  /* 004e */
  a6 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0051: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a5 = a4 + (a6 << 3);  /* 0054 */
  a5 = LD32(a5 + 0x0);  /* 0057 */
  if (((a5 >> 0) & 1) != 0) goto L_005f;  /* 0059: bbsi a5, 0, 5f <ieee80211_add_mesh_roots_ie+0x3b> */
  L_005c: goto L_0122;  /* 005c: j */
  L_005f: a5 = LD8U(a7 + 0x1);  /* 005f */
  a5 = a5 + (a5 << 1);  /* 0062 */
  a5 = a5 << 2;  /* 0065 */
  a6 = a5 + (13);  /* 0068 */
  if (a9 == 0) goto L_0078;  /* 006a: beqz.n a9, 78 <ieee80211_add_mesh_roots_ie+0x54> */
  L_006c: a6 = a5 + (21);  /* 006c */
  a10 = -16;  /* 006f */
  a6 = a6 & a10;  /* 0072 */
  a6 = a6 + (7);  /* 0075 */
  L_0078: a8 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0078: l32r -> global */
  a11 = 1;  /* 007b */
  a13 = a6 + (-2);  /* 007d */
  a12 = 2;  /* 0080 */
  a14 = a9;  /* 0082 */
  a10 = LD32(a8 + 0x0);  /* 0084 */
  a13 = (a13 >> 8) & 0x1;  /* 0086: extui width 1 */
  if (a10 == 0) a12 = a11;  /* 0089 */
  a11 = a4 + (8);  /* 008c */
  a10 = a2;  /* 008e */
  ST32(a1 + 0x4, a9);  /* 0090 */
  a5 = a6 - a5;  /* 0092: sub */
  a5 = a5 + (-13);  /* 0095 */
  ST32(a1 + 0x0, a15);  /* 0098 */
  __asm__ volatile("" ::: "memory");  /* 009b: memw */
  a8 = (u32)&ieee80211_add_ie_esp_mesh_head;  /* 009e: l32r -> func addr */
  a2 = ieee80211_add_ie_esp_mesh_head(a2, a3, a4, a5, a6, a7);  /* 00a1: callx a8 via reloc-expand */
  a14 = a10 + (2);  /* 00a4 */
  a15 = LD32(a1 + 0x0);  /* 00a6 */
  a8 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 00a8: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a15 = a8 + a15;  /* 00ab */
  a11 = LD32(a15 + 0x0);  /* 00ad */
  a11 = (a11 >> 7) & 0x3;  /* 00af: extui width 2 */
  ST8(a10 + 0x0, a11);  /* 00b2 */
  __asm__ volatile("" ::: "memory");  /* 00b5: memw */
  a13 = LD8U(a7 + 0x1);  /* 00b8 */
  ST8(a10 + 0x1, a13);  /* 00bb */
  __asm__ volatile("" ::: "memory");  /* 00be: memw */
  a13 = a13 + (a13 << 1);  /* 00c1 */
  a13 = a13 << 2;  /* 00c4 */
  a12 = a13;  /* 00c7 */
  a10 = a14;  /* 00c9 */
  a11 = LD32(a7 + 0x4);  /* 00cb */
  ST32(a1 + 0x0, a13);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00cf: memw */
  a8 = (u32)&memcpy + 0x0;  /* 00d2: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00d5: callx a8 (libc, via reloc-expand) */
  a12 = 0;  /* 00d8 */
  a12 = ((i32)a5 > (i32)a12) ? a5 : a12;  /* 00da: max */
  a11 = 255;  /* 00dd */
  a13 = LD32(a1 + 0x0);  /* 00e0 */
  a5 = a6 + (-4);  /* 00e2 */
  a10 = a10 + a13;  /* 00e5 */
  a8 = (u32)&memset + 0x0;  /* 00e7: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00ea: callx a8 (libc, via reloc-expand) */
  a14 = a2 + (7);  /* 00ed */
  a11 = a14;  /* 00ef */
  a12 = a6 + (-11);  /* 00f1 */
  a10 = -1;  /* 00f4 */
  ST32(a1 + 0x0, a14);  /* 00f6 */
  __asm__ volatile("" ::: "memory");  /* 00f8: memw */
  a8 = (u32)&crc32_le + 0x0;  /* 00fb: l32r -> global */
  a2 = crc32_le(a2, a3, a4, a5, a6, a7);  /* 00fe: callx a8 via reloc-expand */
  a5 = a2 + a5;  /* 0101 */
  a9 = LD32(a1 + 0x4);  /* 0103 */
  ST32(a5 + 0x0, a10);  /* 0105 */
  a14 = LD32(a1 + 0x0);  /* 0107 */
  if (a9 == 0) goto L_0120;  /* 0109: beqz.n a9, 120 <ieee80211_add_mesh_roots_ie+0xfc> */
  L_010b: a13 = a3;  /* 010b */
  a12 = a14;  /* 010d */
  a11 = a6 + (-7);  /* 010f */
  a10 = 4;  /* 0112 */
  __asm__ volatile("" ::: "memory");  /* 0115: memw */
  a8 = (u32)&esp_mesh_encrypt_vnd_ie;  /* 0118: l32r -> func addr */
  a2 = esp_mesh_encrypt_vnd_ie(a2, a3, a4, a5, a6, a7);  /* 011b: callx a8 via reloc-expand */
  a9 = LD32(a1 + 0x4);  /* 011e */
  L_0120: a2 = a2 + a6;  /* 0120 */
  L_0122: a4 = a4 + (1);  /* 0122 */
  a7 = a7 + (8);  /* 0124 */
  if (a4 == 4) goto L_012c;  /* 0126: beqi a4, 4, 12c <ieee80211_add_mesh_roots_ie+0x108> */
  L_0129: goto L_004e;  /* 0129: j */
  L_012c: return a2;  /* 012c: retw.n */
}


/* ieee80211_add_mesh_ssid_ie @ mesh_quick.o 00000020 size 224B bind GLOBAL
 * Calls: esp_mesh_get_vnd_ssid_len, is_my_ie_encrypted, ieee80211_add_ie_esp_mesh_head, memcpy, crc32_le, esp_mesh_encrypt_vnd_ie | Data refs: esp_mesh_appie, g_mesh_init_ps_type
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=6, refs=8); reloc-direct=6, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_add_mesh_ssid_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  a8 = a3;  /* 0023 */
  a3 = (u32)&esp_mesh_appie + 0x0;  /* 0025: l32r -> global */
  a5 = (a5 >> 8) & 0x1;  /* 0028: extui width 1 */
  a3 = LD32(a3 + 0x0);  /* 002b */
  if (a3 == 0) goto L_00fe;  /* 002d: beqz a3, fe <ieee80211_add_mesh_ssid_ie+0xde> */
  L_0030: a11 = 1;  /* 0030 */
  a3 = 0;  /* 0032 */
  if (a2 == 0) a3 = a11;  /* 0034 */
  a6 = (a3 >> 8) & 0x1;  /* 0037: extui width 1 */
  if (a3 != 0) goto L_00fe;  /* 003a: bnez a3, fe <ieee80211_add_mesh_ssid_ie+0xde> */
  L_003d: if (a8 == 0) a6 = a11;  /* 003d */
  if (a6 != 0) goto L_00fe;  /* 0040: bnez a6, fe <ieee80211_add_mesh_ssid_ie+0xde> */
  L_0043: if (a4 == 0) a6 = a11;  /* 0043 */
  if (a6 != 0) goto L_00fe;  /* 0046: bnez a6, fe <ieee80211_add_mesh_ssid_ie+0xde> */
  L_0049: if (a5 == 0) a6 = a11;  /* 0049 */
  if (a6 != 0) goto L_00fe;  /* 004c: bnez a6, fe <ieee80211_add_mesh_ssid_ie+0xde> */
  L_004f: ST32(a1 + 0x0, a11);  /* 004f */
  ST32(a1 + 0x8, a8);  /* 0051 */
  __asm__ volatile("" ::: "memory");  /* 0053: memw */
  a8 = (u32)&esp_mesh_get_vnd_ssid_len;  /* 0056: l32r -> func addr */
  a2 = esp_mesh_get_vnd_ssid_len(a2, a3, a4, a5, a6, a7);  /* 0059: callx a8 via reloc-expand */
  a7 = a10;  /* 005c */
  a9 = a10 + (-7);  /* 005e */
  a11 = LD32(a1 + 0x0);  /* 0061 */
  if (a10 == 0) a6 = a11;  /* 0063 */
  if (a6 != 0) goto L_00fe;  /* 0066: bnez a6, fe <ieee80211_add_mesh_ssid_ie+0xde> */
  L_0069: a3 = a10 + (-9);  /* 0069 */
  if (a3 == 0) a6 = a11;  /* 006c */
  if (a6 != 0) goto L_00fe;  /* 006f: bnez a6, fe <ieee80211_add_mesh_ssid_ie+0xde> */
  L_0072: ST32(a1 + 0x4, a9);  /* 0072 */
  __asm__ volatile("" ::: "memory");  /* 0074: memw */
  a8 = (u32)&is_my_ie_encrypted;  /* 0077: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6, a7);  /* 007a: callx a8 via reloc-expand */
  a13 = a7 + (-2);  /* 007d */
  a15 = a10;  /* 0080 */
  a14 = a10;  /* 0082 */
  a3 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0084: l32r -> global */
  a13 = (a13 >> 8) & 0x1;  /* 0087: extui width 1 */
  a10 = a2;  /* 008a */
  a12 = LD32(a3 + 0x0);  /* 008c */
  a3 = 2;  /* 008e */
  a11 = LD32(a1 + 0x0);  /* 0090 */
  if (a12 != 0) a11 = a3;  /* 0092 */
  a12 = a11;  /* 0095 */
  a11 = 6;  /* 0097 */
  ST32(a1 + 0x0, a15);  /* 009a */
  __asm__ volatile("" ::: "memory");  /* 009d: memw */
  a8 = (u32)&ieee80211_add_ie_esp_mesh_head;  /* 00a0: l32r -> func addr */
  a2 = ieee80211_add_ie_esp_mesh_head(a2, a3, a4, a5, a6, a7);  /* 00a3: callx a8 via reloc-expand */
  a10 = a2 + (9);  /* 00a6 */
  a12 = a5;  /* 00a8 */
  a11 = a4;  /* 00aa */
  ST8(a2 + 0x8, a5);  /* 00ac */
  a4 = a10;  /* 00af */
  a4 = a4 + a5;  /* 00b1 */
  a5 = a2 + (7);  /* 00b3 */
  ST8(a2 + 0x7, a6);  /* 00b5 */
  __asm__ volatile("" ::: "memory");  /* 00b8: memw */
  __asm__ volatile("" ::: "memory");  /* 00bb: memw */
  a8 = (u32)&memcpy + 0x0;  /* 00be: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00c1: callx a8 (libc, via reloc-expand) */
  a12 = a7 + (-11);  /* 00c4 */
  a11 = a5;  /* 00c7: mov */
  a10 = -1;  /* 00ca */
  ST8(a4 + 0x0, a6);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00d0: memw */
  __asm__ volatile("" ::: "memory");  /* 00d3: memw */
  a8 = (u32)&crc32_le + 0x0;  /* 00d6: l32r -> global */
  a2 = crc32_le(a2, a3, a4, a5, a6, a7);  /* 00d9: callx a8 via reloc-expand */
  a4 = a7 + (-4);  /* 00dc */
  a4 = a2 + a4;  /* 00df */
  a15 = LD32(a1 + 0x0);  /* 00e1 */
  ST32(a4 + 0x0, a10);  /* 00e3 */
  a8 = LD32(a1 + 0x8);  /* 00e5 */
  a9 = LD32(a1 + 0x4);  /* 00e7 */
  if (a15 == 0) goto L_00fc;  /* 00e9: beqz.n a15, fc <ieee80211_add_mesh_ssid_ie+0xdc> */
  L_00eb: a13 = a8;  /* 00eb */
  a12 = a5;  /* 00ed */
  a11 = a9;  /* 00ef */
  a10 = a3;  /* 00f1 */
  __asm__ volatile("" ::: "memory");  /* 00f3: memw */
  a8 = (u32)&esp_mesh_encrypt_vnd_ie;  /* 00f6: l32r -> func addr */
  a2 = esp_mesh_encrypt_vnd_ie(a2, a3, a4, a5, a6, a7);  /* 00f9: callx a8 via reloc-expand */
  L_00fc: a2 = a2 + a7;  /* 00fc */
  L_00fe: return a2;  /* 00fe: retw.n */
}


/* ieee80211_init_mesh_assoc_ie @ mesh_quick.o 00000010 size 70B bind GLOBAL
 * Calls: memcpy, ieee80211_add_ie_esp_mesh_head | Data refs: g_mesh_topology, g_mesh_init_ps_type
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_init_mesh_assoc_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a11 = a3;  /* 0013 */
  a4 = (a4 >> 8) & 0x1;  /* 0015: extui width 1 */
  a5 = 1;  /* 0018 */
  if (a2 == 0) goto L_0054;  /* 001a: beqz.n a2, 54 <ieee80211_init_mesh_assoc_ie+0x44> */
  L_001c: if (a3 == 0) goto L_0054;  /* 001c: beqz.n a3, 54 <ieee80211_init_mesh_assoc_ie+0x44> */
  L_001e: a12 = 58;  /* 001e */
  a10 = a2;  /* 0020 */
  a8 = (u32)&memcpy + 0x0;  /* 0022: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0025: callx a8 (libc, via reloc-expand) */
  a9 = (u32)&g_mesh_topology + 0x0;  /* 0028: l32r -> global */
  a12 = 2;  /* 002b */
  a8 = (u32)&g_mesh_init_ps_type + 0x0;  /* 002d: l32r -> global */
  a9 = LD32(a9 + 0x0);  /* 0030 */
  a8 = LD32(a8 + 0x0);  /* 0032 */
  if (a9 != 0) goto L_0040;  /* 0034: bnez.n a9, 40 <ieee80211_init_mesh_assoc_ie+0x30> */
  L_0036: a11 = a5;  /* 0036 */
  if (a8 != 0) goto L_0045;  /* 0038: bnez.n a8, 45 <ieee80211_init_mesh_assoc_ie+0x35> */
  L_003a: a12 = a5;  /* 003a */
  goto L_0045;  /* 003c: j */
  L_0040: if (a8 == 0) a12 = a5;  /* 0040 */
  a11 = 13;  /* 0043 */
  L_0045: a10 = a2;  /* 0045 */
  a14 = a4;  /* 0047 */
  a13 = 69;  /* 0049 */
  a8 = (u32)&ieee80211_add_ie_esp_mesh_head;  /* 004b: l32r -> func addr */
  a2 = ieee80211_add_ie_esp_mesh_head(a2, a3, a4, a5, a6, a7);  /* 004e: callx a8 via reloc-expand */
  a2 = a10 + (64);  /* 0051 */
  L_0054: return a2;  /* 0054: retw.n */
}


/* ieee80211_is_mesh_roots_announce @ mesh_quick.o 0000000c size 157B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.wifi_vnd_ext_mesh_roots, g_mesh_max_layer
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=3); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_is_mesh_roots_announce(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a7, a8, a9;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a3 = (a3 >> 8) & 0x1;  /* 000f: extui width 1 */
  if (a2 == 0) goto L_009e;  /* 0012: beqz a2, 9e <ieee80211_is_mesh_roots_announce+0x92> */
  L_0015: a5 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0015: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a4 = LD8U(a5 + 0x0);  /* 0018 */
  a4 = (a4 >> 1) & 0x1;  /* 001b: extui width 1 */
  if (a4 == 0) goto L_009e;  /* 001e: beqz a4, 9e <ieee80211_is_mesh_roots_announce+0x92> */
  L_0021: a9 = a2 + (4);  /* 0021 */
  a4 = (u32)&g_mesh_max_layer + 0x0;  /* 0023: l32r -> global */
  a13 = 6;  /* 0026 */
  a6 = LD16U(a4 + 0x0);  /* 0028 */
  a6 = a6 + (-1);  /* 002b */
  a7 = LD8U(a5 + 0x1);  /* 002d */
  a4 = LD32(a5 + 0x4);  /* 0030 */
  a5 = 0;  /* 0032 */
  goto L_009b;  /* 0034: j */
  L_003a: a12 = a13;  /* 003a */
  a10 = a9;  /* 003c */
  a11 = a4 + (4);  /* 003e */
  ST32(a1 + 0x0, a9);  /* 0040 */
  ST32(a1 + 0x4, a13);  /* 0042 */
  __asm__ volatile("" ::: "memory");  /* 0044: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0047: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 004a: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x0);  /* 004d */
  a13 = LD32(a1 + 0x4);  /* 004f */
  if (a10 != 0) goto L_0094;  /* 0051: bnez.n a10, 94 <ieee80211_is_mesh_roots_announce+0x88> */
  L_0053: if (a3 != 0) goto L_00a5;  /* 0053: bnez a3, a5 <ieee80211_is_mesh_roots_announce+0x99> */
  L_0056: a8 = LD8U(a2 + 0x1);  /* 0056 */
  a8 = a8 << 8;  /* 0059 */
  a10 = LD8U(a2 + 0x0);  /* 005c */
  a8 = a8 | a10;  /* 005f */
  a10 = LD8U(a4 + 0x1);  /* 0062 */
  a10 = a10 << 8;  /* 0065 */
  a11 = LD8U(a4 + 0x0);  /* 0068 */
  a10 = a10 | a11;  /* 006b */
  if (a10 < a8) goto L_0074;  /* 006e: bltu a10, a8, 74 <ieee80211_is_mesh_roots_announce+0x68> */
  L_0071: if (a10 == a6) goto L_00a3;  /* 0071: beq a10, a6, a3 <ieee80211_is_mesh_roots_announce+0x97> */
  L_0074: a8 = a8 + (-1);  /* 0074 */
  if (a10 != a8) goto L_0094;  /* 0076: bne a10, a8, 94 <ieee80211_is_mesh_roots_announce+0x88> */
  L_0079: a10 = LD8U(a2 + 0x3);  /* 0079 */
  a10 = a10 << 8;  /* 007c */
  a8 = LD8U(a4 + 0x3);  /* 007f */
  a8 = a8 << 8;  /* 0082 */
  a12 = LD8U(a2 + 0x2);  /* 0085 */
  a10 = a10 | a12;  /* 0088 */
  a11 = LD8U(a4 + 0x2);  /* 008b */
  a8 = a8 | a11;  /* 008e */
  if (a10 == a8) goto L_00a3;  /* 0091: beq a10, a8, a3 <ieee80211_is_mesh_roots_announce+0x97> */
  L_0094: a5 = a5 + (1);  /* 0094 */
  a5 = (a5 >> 8) & 0x1;  /* 0096: extui width 1 */
  a4 = a4 + (12);  /* 0099 */
  L_009b: if (a7 != a5) goto L_003a;  /* 009b: bne a7, a5, 3a <ieee80211_is_mesh_roots_announce+0x2e> */
  L_009e: a3 = 0;  /* 009e */
  goto L_00a5;  /* 00a0: j */
  L_00a3: a3 = 1;  /* 00a3 */
  L_00a5: a2 = a3;  /* 00a5 */
  return a2;  /* 00a7: retw.n */
}


/* ieee80211_is_mesh_roots_announce_used @ mesh_quick.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_is_mesh_roots_announce_used(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0007: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = LD32(a2 + 0x0);  /* 000a */
  a2 = (a2 >> 1) & 0x1;  /* 000c: extui width 1 */
  return a2;  /* 000f: retw.n */
}


/* ieee80211_is_mesh_roots_fixed @ mesh_quick.o 00000008 size 66B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_is_mesh_roots_fixed(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a5 = a2;  /* 000b */
  if (a2 == 0) goto L_0048;  /* 000d: beqz.n a2, 48 <ieee80211_is_mesh_roots_fixed+0x40> */
  L_000f: a3 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 000f: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = 0;  /* 0012 */
  a4 = LD8U(a3 + 0x10);  /* 0014 */
  if (((a4 >> a2) & 1) == 0) goto L_0048;  /* 0017: bbc a4, a2, 48 <ieee80211_is_mesh_roots_fixed+0x40> */
  L_001a: a4 = LD32(a3 + 0x14);  /* 001a */
  a4 = a4 + (4);  /* 001c */
  a6 = LD8U(a3 + 0x11);  /* 001e */
  a3 = a2;  /* 0021 */
  a2 = 6;  /* 0023 */
  goto L_003d;  /* 0025: j */
  L_0028: a11 = a4;  /* 0028 */
  a12 = a2;  /* 002a */
  a10 = a5;  /* 002c */
  a8 = (u32)&memcmp + 0x0;  /* 002e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0031: callx a8 (libc, via reloc-expand) */
  a4 = a4 + (12);  /* 0034 */
  if (a10 == 0) goto L_0046;  /* 0036: beqz.n a10, 46 <ieee80211_is_mesh_roots_fixed+0x3e> */
  L_0038: a3 = a3 + (1);  /* 0038 */
  a3 = (a3 >> 8) & 0x1;  /* 003a: extui width 1 */
  L_003d: if (a6 != a3) goto L_0028;  /* 003d: bne a6, a3, 28 <ieee80211_is_mesh_roots_fixed+0x20> */
  L_0040: a2 = 0;  /* 0040 */
  goto L_0048;  /* 0042: j */
  L_0046: a2 = 1;  /* 0046 */
  L_0048: return a2;  /* 0048: retw.n */
}


/* ieee80211_is_mesh_roots_gone @ mesh_quick.o 00000008 size 66B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_is_mesh_roots_gone(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a5 = a2;  /* 000b */
  if (a2 == 0) goto L_0048;  /* 000d: beqz.n a2, 48 <ieee80211_is_mesh_roots_gone+0x40> */
  L_000f: a3 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 000f: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = 0;  /* 0012 */
  a4 = LD8U(a3 + 0x18);  /* 0014 */
  if (((a4 >> a2) & 1) == 0) goto L_0048;  /* 0017: bbc a4, a2, 48 <ieee80211_is_mesh_roots_gone+0x40> */
  L_001a: a4 = LD32(a3 + 0x1c);  /* 001a */
  a4 = a4 + (4);  /* 001c */
  a6 = LD8U(a3 + 0x19);  /* 001e */
  a3 = a2;  /* 0021 */
  a2 = 6;  /* 0023 */
  goto L_003d;  /* 0025: j */
  L_0028: a11 = a4;  /* 0028 */
  a12 = a2;  /* 002a */
  a10 = a5;  /* 002c */
  a8 = (u32)&memcmp + 0x0;  /* 002e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0031: callx a8 (libc, via reloc-expand) */
  a4 = a4 + (12);  /* 0034 */
  if (a10 == 0) goto L_0046;  /* 0036: beqz.n a10, 46 <ieee80211_is_mesh_roots_gone+0x3e> */
  L_0038: a3 = a3 + (1);  /* 0038 */
  a3 = (a3 >> 8) & 0x1;  /* 003a: extui width 1 */
  L_003d: if (a6 != a3) goto L_0028;  /* 003d: bne a6, a3, 28 <ieee80211_is_mesh_roots_gone+0x20> */
  L_0040: a2 = 0;  /* 0040 */
  goto L_0048;  /* 0042: j */
  L_0046: a2 = 1;  /* 0046 */
  L_0048: return a2;  /* 0048: retw.n */
}


/* ieee80211_is_mesh_roots_valid @ mesh_quick.o 00000014 size 164B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp | Data refs: .bss.wifi_vnd_ext_mesh_roots, esp_mesh_appie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_is_mesh_roots_valid(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a5, a6, a7, a8, a9;
  /* 0014: entry a1, 48 (frame 48 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 0017: extui width 1 */
  if (a3 != 0) goto L_0021;  /* 001a: bnez.n a3, 21 <ieee80211_is_mesh_roots_valid+0xd> */
  L_001c: a2 = 0;  /* 001c */
  goto L_00b6;  /* 001e: j */
  L_0021: a8 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0021: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a5 = 0;  /* 0024 */
  a6 = a2 + (a8 << 3);  /* 0026 */
  ST32(a1 + 0x0, a5);  /* 0029 */
  ST16(a1 + 0x4, a5);  /* 002b */
  __asm__ volatile("" ::: "memory");  /* 002e: memw */
  a5 = LD8U(a6 + 0x1);  /* 0031 */
  a6 = LD32(a6 + 0x4);  /* 0034 */
  if (a2 != 0) goto L_0075;  /* 0036: bnez.n a2, 75 <ieee80211_is_mesh_roots_valid+0x61> */
  L_0038: a12 = a1;  /* 0038 */
  a11 = 15;  /* 003a */
  a7 = (u32)&esp_mesh_appie + 0x0;  /* 003c: l32r -> global */
  a10 = LD32(a7 + 0x0);  /* 003f */
  a7 = 6;  /* 0041 */
  a10 = a10 + (2);  /* 0044 */
  __asm__ volatile("" ::: "memory");  /* 0047: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 004a: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4);  /* 004d: callx a8 via reloc-expand */
  goto L_006d;  /* 0050: j */
  L_0054: a12 = a7;  /* 0054 */
  a11 = a1;  /* 0056 */
  a10 = a3;  /* 0058 */
  a8 = (u32)&memcmp + 0x0;  /* 005a: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 005d: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0068;  /* 0060: bnez.n a10, 68 <ieee80211_is_mesh_roots_valid+0x54> */
  L_0062: a2 = 1;  /* 0062 */
  goto L_00b6;  /* 0064: j */
  L_0068: a2 = a2 + (1);  /* 0068 */
  a2 = (a2 >> 8) & 0x1;  /* 006a: extui width 1 */
  L_006d: if (a2 != a5) goto L_0054;  /* 006d: bne a2, a5, 54 <ieee80211_is_mesh_roots_valid+0x40> */
  L_0070: goto L_0080;  /* 0070: j */
  L_0075: if (a2 != 1) goto L_0080;  /* 0075: bnei a2, 1, 80 <ieee80211_is_mesh_roots_valid+0x6c> */
  L_0078: if (a5 == 0) goto L_0080;  /* 0078: beqz.n a5, 80 <ieee80211_is_mesh_roots_valid+0x6c> */
  L_007a: a5 = LD8U(a8 + 0x8);  /* 007a */
  a5 = (a5 >> 1) & 0x1;  /* 007d: extui width 1 */
  L_0080: a2 = a6;  /* 0080 */
  a7 = 6;  /* 0082 */
  a6 = 0;  /* 0084 */
  goto L_00b0;  /* 0086: j */
  L_0089: a12 = a7;  /* 0089 */
  a11 = a2 + (4);  /* 008b */
  a10 = a3;  /* 008d */
  a8 = (u32)&memcmp + 0x0;  /* 008f: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 0092: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00a9;  /* 0095: bnez.n a10, a9 <ieee80211_is_mesh_roots_valid+0x95> */
  L_0097: a8 = LD8U(a2 + 0x1);  /* 0097 */
  a8 = a8 << 8;  /* 009a */
  a9 = LD8U(a2 + 0x0);  /* 009d */
  a8 = a8 | a9;  /* 00a0 */
  if ((i32)a8 < (i32)a4) goto L_00a9;  /* 00a3: blt a8, a4, a9 <ieee80211_is_mesh_roots_valid+0x95> */
  L_00a6: goto L_001c;  /* 00a6: j */
  L_00a9: a6 = a6 + (1);  /* 00a9 */
  a6 = (a6 >> 8) & 0x1;  /* 00ab: extui width 1 */
  a2 = a2 + (12);  /* 00ae */
  L_00b0: if (a6 != a5) goto L_0089;  /* 00b0: bne a6, a5, 89 <ieee80211_is_mesh_roots_valid+0x75> */
  L_00b3: goto L_0062;  /* 00b3: j */
  L_00b6: return a2;  /* 00b6: retw.n */
}


/* ieee80211_is_mesh_roots_yield @ mesh_quick.o 00000008 size 46B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_is_mesh_roots_yield(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 000b */
  if (a2 == 0) goto L_0034;  /* 000d: beqz.n a2, 34 <ieee80211_is_mesh_roots_yield+0x2c> */
  L_000f: a8 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 000f: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = 0;  /* 0012 */
  a9 = LD8U(a8 + 0x8);  /* 0014 */
  if (((a9 >> a2) & 1) == 0) goto L_0034;  /* 0017: bbc a9, a2, 34 <ieee80211_is_mesh_roots_yield+0x2c> */
  L_001a: a9 = LD8U(a8 + 0x9);  /* 001a */
  if (a9 != 2) goto L_0034;  /* 001d: bnei a9, 2, 34 <ieee80211_is_mesh_roots_yield+0x2c> */
  L_0020: a12 = 6;  /* 0020 */
  a11 = LD32(a8 + 0xc);  /* 0022 */
  a11 = a11 + (4);  /* 0024 */
  a8 = (u32)&memcmp + 0x0;  /* 0026: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0029: callx a8 (libc, via reloc-expand) */
  a8 = 1;  /* 002c */
  if (a10 == 0) a2 = a8;  /* 002e */
  a2 = (a2 >> 8) & 0x1;  /* 0031: extui width 1 */
  L_0034: return a2;  /* 0034: retw.n */
}


/* ieee80211_is_mesh_roots_yield_used @ mesh_quick.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_is_mesh_roots_yield_used(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0007: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = LD32(a2 + 0x8);  /* 000a */
  a2 = (a2 >> 1) & 0x1;  /* 000c: extui width 1 */
  return a2;  /* 000f: retw.n */
}


/* ieee80211_mesh_quick_get @ mesh_quick.o 00000010 size 322B bind GLOBAL
 * Calls: memcpy | Data refs: esp_mesh_appie, .rodata.ieee80211_mesh_quick_get, g_mesh_topology
 * Fidelity: low - jx dispatch (bgeu bound 24 at +0x3c, table .rodata.ieee80211_mesh_quick_get via l32r at +0x42 + (idx<<2) load at +0x45, jx a2 at +0x4a); per-case targets structural - need rodata table dump + per-case target walk to raise
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_mesh_quick_get(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a11 = a2;  /* 0013 */
  a8 = 0;  /* 0015 */
  a2 = 1;  /* 0017 */
  if (a11 == 0) a8 = a2;  /* 0019 */
  a10 = a4;  /* 001c */
  a3 = (a3 >> 8) & 0x1;  /* 001e: extui width 1 */
  a9 = (a8 >> 8) & 0x1;  /* 0021: extui width 1 */
  if (a8 != 0) goto L_014d;  /* 0024: bnez a8, 14d <ieee80211_mesh_quick_get+0x13d> */
  L_0027: if (a4 != 0) a2 = a9;  /* 0027 */
  if (a2 != 0) goto L_014d;  /* 002a: bnez a2, 14d <ieee80211_mesh_quick_get+0x13d> */
  L_002d: a2 = (u32)&esp_mesh_appie + 0x0;  /* 002d: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 0030 */
  a2 = 0x102;  /* 0032 */
  if (a8 == 0) goto L_0150;  /* 0035: beqz a8, 150 <ieee80211_mesh_quick_get+0x140> */
  L_0038: a8 = 24;  /* 0038 */
  a2 = -1;  /* 003a */
  if (a8 >= a3) goto L_0042;  /* 003c: bgeu a8, a3, 42 <ieee80211_mesh_quick_get+0x32> */
  L_003f: goto L_0150;  /* 003f: j */
  L_0042: a2 = (u32)(RODATA__rodata_ieee80211_mesh_quick_get + 0x0);  /* 0042: l32r -> .rodata.ieee80211_mesh_quick_get */
  a3 = a3 + (a2 << 2);  /* 0045 */
  a2 = LD32(a3 + 0x0);  /* 0048 */
  /* 004a: jx a2 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a2 = LD8U(a11 + 0x7);  /* 004d */
  goto L_0141;  /* 0050: j */
  a12 = 6;  /* 0053 */
  a11 = a11 + (8);  /* 0055 */
  L_0057: a8 = (u32)&memcpy + 0x0;  /* 0057: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 005a: callx a8 (libc, via reloc-expand) */
  L_005d: a2 = 0;  /* 005d */
  goto L_0150;  /* 005f: j */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 0063: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 0066 */
  if (a8 != 0) goto L_0070;  /* 0068: bnez.n a8, 70 <ieee80211_mesh_quick_get+0x60> */
  L_006a: a2 = LD8U(a11 + 0xe);  /* 006a */
  goto L_0141;  /* 006d: j */
  L_0070: a3 = LD8U(a11 + 0x3a);  /* 0070 */
  a2 = LD8U(a11 + 0x3b);  /* 0073 */
  goto L_008e;  /* 0076: j */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 007b: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 007e */
  if (a8 != 0) goto L_0088;  /* 0080: bnez.n a8, 88 <ieee80211_mesh_quick_get+0x78> */
  L_0082: a2 = LD8U(a11 + 0xf);  /* 0082 */
  goto L_0141;  /* 0085: j */
  L_0088: a3 = LD8U(a11 + 0x3c);  /* 0088 */
  a2 = LD8U(a11 + 0x3d);  /* 008b */
  L_008e: a2 = a2 << 8;  /* 008e */
  a2 = a2 | a3;  /* 0091 */
  ST16(a10 + 0x0, a2);  /* 0094 */
  __asm__ volatile("" ::: "memory");  /* 0097: memw */
  __asm__ volatile("" ::: "memory");  /* 009a: memw */
  goto L_005d;  /* 009d: j */
  a2 = LD8U(a11 + 0x10);  /* 00a0 */
  goto L_0141;  /* 00a3: j */
  a2 = LD8U(a11 + 0x11);  /* 00a6 */
  goto L_0141;  /* 00a9: j */
  a2 = LD8U(a11 + 0x12);  /* 00ac */
  goto L_0141;  /* 00af: j */
  a2 = LD8U(a11 + 0x13);  /* 00b2 */
  goto L_0141;  /* 00b5: j */
  a3 = LD8U(a11 + 0x14);  /* 00b8 */
  a2 = LD8U(a11 + 0x15);  /* 00bb */
  goto L_012f;  /* 00be: j */
  a3 = LD8U(a11 + 0x16);  /* 00c1 */
  a2 = LD8U(a11 + 0x17);  /* 00c4 */
  goto L_012f;  /* 00c7: j */
  a3 = LD8U(a11 + 0x18);  /* 00ca */
  a2 = LD8U(a11 + 0x19);  /* 00cd */
  goto L_012f;  /* 00d0: j */
  a3 = LD8U(a11 + 0x1a);  /* 00d3 */
  a2 = LD8U(a11 + 0x1b);  /* 00d6 */
  goto L_012f;  /* 00d9: j */
  a2 = LD8U(a11 + 0x1c);  /* 00dc */
  goto L_0141;  /* 00df: j */
  a2 = LD8U(a11 + 0x1d);  /* 00e2 */
  goto L_0141;  /* 00e5: j */
  a2 = LD8U(a11 + 0x1e);  /* 00e8 */
  goto L_0141;  /* 00eb: j */
  a12 = 6;  /* 00ee */
  a11 = a11 + (31);  /* 00f0 */
  goto L_0057;  /* 00f3: j */
  a2 = LD8U(a11 + 0x25);  /* 00f6 */
  goto L_0141;  /* 00f9: j */
  a12 = 6;  /* 00fc */
  a11 = a11 + (38);  /* 00fe */
  goto L_0057;  /* 0101: j */
  a2 = LD8U(a11 + 0x2c);  /* 0104 */
  goto L_0141;  /* 0107: j */
  a2 = LD8U(a11 + 0x2d);  /* 010a */
  goto L_0141;  /* 010d: j */
  a12 = 6;  /* 0110 */
  a11 = a11 + (51);  /* 0112 */
  goto L_0057;  /* 0115: j */
  a2 = LD8U(a11 + 0x39);  /* 011a */
  goto L_0141;  /* 011d: j */
  a3 = LD8U(a11 + 0x2e);  /* 0120 */
  a2 = LD8U(a11 + 0x2f);  /* 0123 */
  goto L_012f;  /* 0126: j */
  a3 = LD8U(a11 + 0x30);  /* 0129 */
  a2 = LD8U(a11 + 0x31);  /* 012c */
  L_012f: ST8(a10 + 0x0, a3);  /* 012f */
  ST8(a10 + 0x1, a2);  /* 0132 */
  __asm__ volatile("" ::: "memory");  /* 0135: memw */
  __asm__ volatile("" ::: "memory");  /* 0138: memw */
  goto L_005d;  /* 013b: j */
  a2 = LD8U(a11 + 0x32);  /* 013e */
  L_0141: ST8(a10 + 0x0, a2);  /* 0141 */
  __asm__ volatile("" ::: "memory");  /* 0144: memw */
  __asm__ volatile("" ::: "memory");  /* 0147: memw */
  goto L_005d;  /* 014a: j */
  L_014d: a2 = 0x102;  /* 014d */
  L_0150: return a2;  /* 0150: retw.n */
}


/* ieee80211_mesh_quick_set @ mesh_quick.o 00000014 size 594B bind GLOBAL
 * Calls: memcpy, ieee80211_vnd_mesh_update_beacon | Data refs: esp_mesh_appie, .rodata.ieee80211_mesh_quick_set, g_mesh_topology
 * Fidelity: low - jx dispatch (bgeu bound 24 at +0x40, table .rodata.ieee80211_mesh_quick_set via l32r at +0x46 + (idx<<2) load at +0x49, jx a3 at +0x4e); per-case targets structural - need rodata table dump + per-case target walk to raise
 * Edges: funcdb-v3 (calls=2, refs=5); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_mesh_quick_set(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8, a9;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 0017 */
  a8 = 0;  /* 0019 */
  a2 = 1;  /* 001b */
  if (a4 == 0) a8 = a2;  /* 001d */
  a11 = a4;  /* 0020 */
  a3 = (a3 >> 8) & 0x1;  /* 0022: extui width 1 */
  a9 = (a8 >> 8) & 0x1;  /* 0025: extui width 1 */
  if (a8 != 0) goto L_0261;  /* 0028: bnez a8, 261 <ieee80211_mesh_quick_set+0x24d> */
  L_002b: if (a10 != 0) a2 = a9;  /* 002b */
  if (a2 != 0) goto L_0261;  /* 002e: bnez a2, 261 <ieee80211_mesh_quick_set+0x24d> */
  L_0031: a2 = (u32)&esp_mesh_appie + 0x0;  /* 0031: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 0034 */
  a2 = 0x102;  /* 0036 */
  if (a8 == 0) goto L_0264;  /* 0039: beqz a8, 264 <ieee80211_mesh_quick_set+0x250> */
  L_003c: a8 = 24;  /* 003c */
  a2 = -1;  /* 003e */
  if (a8 >= a3) goto L_0046;  /* 0040: bgeu a8, a3, 46 <ieee80211_mesh_quick_set+0x32> */
  L_0043: goto L_0264;  /* 0043: j */
  L_0046: a2 = (u32)(RODATA__rodata_ieee80211_mesh_quick_set + 0x0);  /* 0046: l32r -> .rodata.ieee80211_mesh_quick_set */
  a3 = a3 + (a2 << 2);  /* 0049 */
  a2 = LD32(a3 + 0x0);  /* 004c */
  /* 004e: jx a2 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a2 = LD8U(a4 + 0x0);  /* 0051 */
  ST8(a10 + 0x7, a2);  /* 0054 */
  __asm__ volatile("" ::: "memory");  /* 0057: memw */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  goto L_0251;  /* 005d: j */
  a12 = 6;  /* 0060 */
  a10 = a10 + (8);  /* 0062 */
  goto L_01de;  /* 0064: j */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 0067: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 006a */
  if (a2 != 0) goto L_007d;  /* 006c: bnez.n a2, 7d <ieee80211_mesh_quick_set+0x69> */
  L_006e: a2 = LD8U(a4 + 0x0);  /* 006e */
  ST8(a10 + 0xe, a2);  /* 0071 */
  __asm__ volatile("" ::: "memory");  /* 0074: memw */
  __asm__ volatile("" ::: "memory");  /* 0077: memw */
  goto L_0251;  /* 007a: j */
  L_007d: a2 = LD16U(a4 + 0x0);  /* 007d */
  a2 = a2 >> 8;  /* 0080 */
  a3 = LD8U(a4 + 0x0);  /* 0083 */
  ST8(a10 + 0x3b, a2);  /* 0086 */
  ST8(a10 + 0x3a, a3);  /* 0089 */
  __asm__ volatile("" ::: "memory");  /* 008c: memw */
  __asm__ volatile("" ::: "memory");  /* 008f: memw */
  goto L_0251;  /* 0092: j */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 0096: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0099 */
  if (a2 != 0) goto L_00ac;  /* 009b: bnez.n a2, ac <ieee80211_mesh_quick_set+0x98> */
  L_009d: a2 = LD8U(a4 + 0x0);  /* 009d */
  ST8(a10 + 0xf, a2);  /* 00a0 */
  __asm__ volatile("" ::: "memory");  /* 00a3: memw */
  __asm__ volatile("" ::: "memory");  /* 00a6: memw */
  goto L_0251;  /* 00a9: j */
  L_00ac: a2 = LD16U(a4 + 0x0);  /* 00ac */
  a2 = a2 >> 8;  /* 00af */
  a3 = LD8U(a4 + 0x0);  /* 00b2 */
  ST8(a10 + 0x3d, a2);  /* 00b5 */
  ST8(a10 + 0x3c, a3);  /* 00b8 */
  __asm__ volatile("" ::: "memory");  /* 00bb: memw */
  __asm__ volatile("" ::: "memory");  /* 00be: memw */
  goto L_0251;  /* 00c1: j */
  a2 = LD8U(a4 + 0x0);  /* 00c4 */
  ST8(a10 + 0x10, a2);  /* 00c7 */
  __asm__ volatile("" ::: "memory");  /* 00ca: memw */
  __asm__ volatile("" ::: "memory");  /* 00cd: memw */
  goto L_0251;  /* 00d0: j */
  a2 = LD8U(a4 + 0x0);  /* 00d3 */
  ST8(a10 + 0x11, a2);  /* 00d6 */
  __asm__ volatile("" ::: "memory");  /* 00d9: memw */
  __asm__ volatile("" ::: "memory");  /* 00dc: memw */
  goto L_0251;  /* 00df: j */
  a2 = LD8U(a4 + 0x0);  /* 00e2 */
  ST8(a10 + 0x12, a2);  /* 00e5 */
  __asm__ volatile("" ::: "memory");  /* 00e8: memw */
  __asm__ volatile("" ::: "memory");  /* 00eb: memw */
  goto L_0251;  /* 00ee: j */
  a2 = LD8U(a4 + 0x0);  /* 00f1 */
  ST8(a10 + 0x13, a2);  /* 00f4 */
  __asm__ volatile("" ::: "memory");  /* 00f7: memw */
  __asm__ volatile("" ::: "memory");  /* 00fa: memw */
  goto L_0251;  /* 00fd: j */
  a3 = LD8U(a4 + 0x0);  /* 0100 */
  a2 = LD8U(a4 + 0x1);  /* 0103 */
  ST8(a10 + 0x14, a3);  /* 0106 */
  ST8(a10 + 0x15, a2);  /* 0109 */
  __asm__ volatile("" ::: "memory");  /* 010c: memw */
  __asm__ volatile("" ::: "memory");  /* 010f: memw */
  goto L_0251;  /* 0112: j */
  a3 = LD8U(a4 + 0x0);  /* 0115 */
  a2 = LD8U(a4 + 0x1);  /* 0118 */
  ST8(a10 + 0x16, a3);  /* 011b */
  ST8(a10 + 0x17, a2);  /* 011e */
  __asm__ volatile("" ::: "memory");  /* 0121: memw */
  __asm__ volatile("" ::: "memory");  /* 0124: memw */
  goto L_0251;  /* 0127: j */
  a3 = LD8U(a4 + 0x0);  /* 012a */
  a2 = LD8U(a4 + 0x1);  /* 012d */
  ST8(a10 + 0x18, a3);  /* 0130 */
  ST8(a10 + 0x19, a2);  /* 0133 */
  __asm__ volatile("" ::: "memory");  /* 0136: memw */
  __asm__ volatile("" ::: "memory");  /* 0139: memw */
  goto L_0251;  /* 013c: j */
  a3 = LD8U(a4 + 0x0);  /* 013f */
  a2 = LD8U(a4 + 0x1);  /* 0142 */
  ST8(a10 + 0x1a, a3);  /* 0145 */
  ST8(a10 + 0x1b, a2);  /* 0148 */
  __asm__ volatile("" ::: "memory");  /* 014b: memw */
  __asm__ volatile("" ::: "memory");  /* 014e: memw */
  goto L_0251;  /* 0151: j */
  a2 = LD8U(a4 + 0x0);  /* 0154 */
  ST8(a10 + 0x1c, a2);  /* 0157 */
  __asm__ volatile("" ::: "memory");  /* 015a: memw */
  __asm__ volatile("" ::: "memory");  /* 015d: memw */
  goto L_0251;  /* 0160: j */
  a3 = LD8U(a10 + 0x1d);  /* 0163 */
  a12 = (i32)(a3 << (32 - 7)) >> (32 - 7);  /* 0166: sext */
  a8 = LD8U(a4 + 0x0);  /* 0169 */
  a11 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 016c: sext */
  if (a12 != a11) goto L_0175;  /* 016f: bne a12, a11, 175 <ieee80211_mesh_quick_set+0x161> */
  L_0172: goto L_0251;  /* 0172: j */
  L_0175: a13 = a11 + (120);  /* 0175 */
  a2 = 1;  /* 0178 */
  a9 = 0;  /* 017a */
  if (a13 == 0) a9 = a2;  /* 017c */
  a13 = (a9 >> 8) & 0x1;  /* 017f: extui width 1 */
  if (a9 != 0) goto L_01a5;  /* 0182: bnez.n a9, 1a5 <ieee80211_mesh_quick_set+0x191> */
  L_0184: a9 = a12 + (120);  /* 0184 */
  if (a9 != 0) a2 = a13;  /* 0187 */
  if (a2 == 0) goto L_0190;  /* 018a: beqz.n a2, 190 <ieee80211_mesh_quick_set+0x17c> */
  L_018c: goto L_01a5;  /* 018c: j */
  L_0190: if (a3 == 0) goto L_01a5;  /* 0190: beqz.n a3, 1a5 <ieee80211_mesh_quick_set+0x191> */
  L_0192: a9 = a12 + (a12 << 1);  /* 0192 */
  a9 = a9 + (a12 << 2);  /* 0195 */
  a11 = a11 + (a11 << 1);  /* 0198 */
  a9 = a9 + a11;  /* 019b */
  a8 = a9 + (15);  /* 019d */
  if ((i32)a9 >= 0) a8 = a9;  /* 019f */
  a8 = (a8 >> 8) & 0x1f;  /* 01a2: extui width 5 */
  L_01a5: ST8(a10 + 0x1d, a8);  /* 01a5 */
  __asm__ volatile("" ::: "memory");  /* 01a8: memw */
  __asm__ volatile("" ::: "memory");  /* 01ab: memw */
  goto L_0251;  /* 01ae: j */
  a2 = LD8U(a4 + 0x0);  /* 01b1 */
  ST8(a10 + 0x1e, a2);  /* 01b4 */
  __asm__ volatile("" ::: "memory");  /* 01b7: memw */
  __asm__ volatile("" ::: "memory");  /* 01ba: memw */
  goto L_0251;  /* 01bd: j */
  a12 = 6;  /* 01c0 */
  a10 = a10 + (31);  /* 01c2 */
  goto L_01de;  /* 01c5: j */
  a2 = LD8U(a4 + 0x0);  /* 01c8 */
  ST8(a10 + 0x25, a2);  /* 01cb */
  __asm__ volatile("" ::: "memory");  /* 01ce: memw */
  __asm__ volatile("" ::: "memory");  /* 01d1: memw */
  goto L_0251;  /* 01d4: j */
  a12 = 6;  /* 01d9 */
  a10 = a10 + (38);  /* 01db */
  L_01de: a8 = (u32)&memcpy + 0x0;  /* 01de: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 01e1: callx a8 (libc, via reloc-expand) */
  goto L_0251;  /* 01e4: j */
  a2 = LD8U(a4 + 0x0);  /* 01e9 */
  ST8(a10 + 0x2c, a2);  /* 01ec */
  __asm__ volatile("" ::: "memory");  /* 01ef: memw */
  __asm__ volatile("" ::: "memory");  /* 01f2: memw */
  goto L_0251;  /* 01f5: j */
  a2 = LD8U(a4 + 0x0);  /* 01f8 */
  ST8(a10 + 0x2d, a2);  /* 01fb */
  __asm__ volatile("" ::: "memory");  /* 01fe: memw */
  __asm__ volatile("" ::: "memory");  /* 0201: memw */
  goto L_0251;  /* 0204: j */
  a12 = 6;  /* 0207 */
  a10 = a10 + (51);  /* 0209 */
  goto L_01de;  /* 020c: j */
  a2 = LD8U(a4 + 0x0);  /* 020f */
  ST8(a10 + 0x39, a2);  /* 0212 */
  __asm__ volatile("" ::: "memory");  /* 0215: memw */
  __asm__ volatile("" ::: "memory");  /* 0218: memw */
  goto L_0251;  /* 021b: j */
  a3 = LD8U(a4 + 0x0);  /* 021e */
  a2 = LD8U(a4 + 0x1);  /* 0221 */
  ST8(a10 + 0x2e, a3);  /* 0224 */
  ST8(a10 + 0x2f, a2);  /* 0227 */
  __asm__ volatile("" ::: "memory");  /* 022a: memw */
  __asm__ volatile("" ::: "memory");  /* 022d: memw */
  goto L_0251;  /* 0230: j */
  a3 = LD8U(a4 + 0x0);  /* 0233 */
  a2 = LD8U(a4 + 0x1);  /* 0236 */
  ST8(a10 + 0x30, a3);  /* 0239 */
  ST8(a10 + 0x31, a2);  /* 023c */
  __asm__ volatile("" ::: "memory");  /* 023f: memw */
  __asm__ volatile("" ::: "memory");  /* 0242: memw */
  goto L_0251;  /* 0245: j */
  a2 = LD8U(a4 + 0x0);  /* 0248 */
  ST8(a10 + 0x32, a2);  /* 024b */
  __asm__ volatile("" ::: "memory");  /* 024e: memw */
  L_0251: a10 = 1;  /* 0251 */
  __asm__ volatile("" ::: "memory");  /* 0253: memw */
  a8 = (u32)&ieee80211_vnd_mesh_update_beacon + 0x0;  /* 0256: l32r -> global */
  a2 = ieee80211_vnd_mesh_update_beacon(a2, a3, a4, a5, a6, a7);  /* 0259: callx a8 via reloc-expand */
  a2 = 0;  /* 025c */
  goto L_0264;  /* 025e: j */
  L_0261: a2 = 0x102;  /* 0261 */
  L_0264: return a2;  /* 0264: retw.n */
}


/* ieee80211_recv_mesh_duty_signaling @ mesh_quick.o 0000002c size 236B bind GLOBAL
 * Calls: memcpy, esp_mesh_check_vnd_ie, is_esp_mesh_duty_signaling, ieee80211_mesh_quick_get, memcmp, ieee80211_public_action_send_mesh_awake, esp_mesh_parse_ps_ie | Data refs: .rodata, .rodata.ieee80211_add_mesh_duty_signaling.str1.1, esp_mesh_appie, .bss.signaling_token$8
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=7, refs=11); reloc-direct=7, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_recv_mesh_duty_signaling(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8, a9;
  /* 002c: entry a1, 48 (frame 48 bytes) */
  a3 = (u32)(RODATA__rodata + 0x0);  /* 002f: l32r -> .rodata */
  a12 = 6;  /* 0032 */
  a10 = a1;  /* 0034 */
  a4 = LD8U(a3 + 0x0);  /* 0036 */
  a3 = LD8U(a3 + 0x1);  /* 0039 */
  a11 = (u32)(RODATA__rodata_ieee80211_add_mesh_duty_signaling_str1_1 + 0x0);  /* 003c: l32r -> .rodata.ieee80211_add_mesh_duty_signaling.str1.1 */
  ST8(a1 + 0x7, a3);  /* 003f */
  a3 = 0;  /* 0042 */
  ST8(a1 + 0x6, a4);  /* 0045 */
  a4 = -1;  /* 0048 */
  ST16(a1 + 0x8, a3);  /* 004a */
  ST16(a1 + 0xa, a3);  /* 004d */
  __asm__ volatile("" ::: "memory");  /* 0050: memw */
  __asm__ volatile("" ::: "memory");  /* 0053: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0056: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0059: callx a8 (libc, via reloc-expand) */
  a11 = a1;  /* 005c */
  a10 = a2;  /* 005e */
  a8 = (u32)&esp_mesh_check_vnd_ie;  /* 0060: l32r -> func addr */
  a2 = esp_mesh_check_vnd_ie(a2, a3, a4, a5, a6, a7);  /* 0063: callx a8 via reloc-expand */
  a3 = a10;  /* 0066 */
  if (a10 != 0) goto L_0114;  /* 0068: bnez a10, 114 <ieee80211_recv_mesh_duty_signaling+0xe8> */
  L_006b: a10 = a2;  /* 006b: mov */
  a8 = (u32)&is_esp_mesh_duty_signaling;  /* 006e: l32r -> func addr */
  a2 = is_esp_mesh_duty_signaling(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0114;  /* 0074: beqz a10, 114 <ieee80211_recv_mesh_duty_signaling+0xe8> */
  L_0077: a4 = (u32)&esp_mesh_appie + 0x0;  /* 0077: l32r -> global */
  a12 = a1 + (6);  /* 007a */
  a11 = 15;  /* 007c */
  a10 = LD32(a4 + 0x0);  /* 007e */
  a10 = a10 + (2);  /* 0080 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0082: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0085: callx a8 via reloc-expand */
  a12 = 6;  /* 0088 */
  a11 = a1 + a12;  /* 008a */
  a10 = a2 + (12);  /* 008c */
  a8 = (u32)&memcmp + 0x0;  /* 008e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0091: callx a8 (libc, via reloc-expand) */
  a4 = a10;  /* 0094 */
  if (a10 == 0) goto L_009d;  /* 0096: beqz.n a10, 9d <ieee80211_recv_mesh_duty_signaling+0x71> */
  L_0098: a4 = a3;  /* 0098 */
  goto L_0114;  /* 009a: j */
  L_009d: a8 = LD8U(a2 + 0x9);  /* 009d */
  a8 = a8 << 8;  /* 00a0 */
  a5 = LD8U(a2 + 0x8);  /* 00a3 */
  a8 = a8 | a5;  /* 00a6 */
  a5 = LD8U(a2 + 0xa);  /* 00a9 */
  a5 = a5 << 16;  /* 00ac */
  a5 = a5 | a8;  /* 00af */
  a10 = LD8U(a2 + 0xb);  /* 00b2 */
  a10 = a10 << 24;  /* 00b5 */
  a10 = a10 | a5;  /* 00b8 */
  a5 = (u32)&LOCAL__bss_signaling_token_8 + 0x0;  /* 00bb: l32r -> .bss.signaling_token$8 (same-object static) */
  a8 = LD32(a5 + 0x0);  /* 00be */
  if (a10 < a8) goto L_00d8;  /* 00c0: bltu a10, a8, d8 <ieee80211_recv_mesh_duty_signaling+0xac> */
  L_00c3: a11 = LD8U(a2 + 0x7);  /* 00c3 */
  if (a11 == 0) goto L_00d8;  /* 00c6: beqz a11, d8 <ieee80211_recv_mesh_duty_signaling+0xac> */
  L_00c9: a11 = a11 + (-1);  /* 00c9 */
  a12 = a2 + (18);  /* 00cc */
  a11 = (a11 >> 8) & 0x1;  /* 00cf: extui width 1 */
  a8 = (u32)&ieee80211_public_action_send_mesh_awake + 0x0;  /* 00d2: l32r -> global */
  a2 = ieee80211_public_action_send_mesh_awake(a2, a3, a4, a5, a6, a7);  /* 00d5: callx a8 via reloc-expand */
  L_00d8: a8 = LD8U(a2 + 0x9);  /* 00d8 */
  a8 = a8 << 8;  /* 00db */
  a9 = LD8U(a2 + 0x8);  /* 00de */
  a8 = a8 | a9;  /* 00e1 */
  a9 = LD8U(a2 + 0xa);  /* 00e4 */
  a9 = a9 << 16;  /* 00e7 */
  a9 = a9 | a8;  /* 00ea */
  a8 = LD8U(a2 + 0xb);  /* 00ed */
  a8 = a8 << 24;  /* 00f0 */
  a8 = a8 | a9;  /* 00f3 */
  a9 = LD32(a5 + 0x0);  /* 00f6 */
  a9 = a8 - a9;  /* 00f8: sub */
  if ((i32)a9 < 1) goto L_0098;  /* 00fb: blti a9, 1, 98 <ieee80211_recv_mesh_duty_signaling+0x6c> */
  L_00fe: a13 = 0;  /* 00fe */
  a12 = a2 + (18);  /* 0100 */
  a11 = a1;  /* 0103 */
  a10 = 208;  /* 0105 */
  ST32(a5 + 0x0, a8);  /* 0108 */
  __asm__ volatile("" ::: "memory");  /* 010b: memw */
  a8 = (u32)&esp_mesh_parse_ps_ie;  /* 010e: l32r -> func addr */
  a2 = esp_mesh_parse_ps_ie(a2, a3, a4, a5, a6, a7);  /* 0111: callx a8 via reloc-expand */
  L_0114: a2 = a4;  /* 0114 */
  return a2;  /* 0116: retw.n */
}


/* ieee80211_vnd_mesh_quick_get @ mesh_quick.o 0000000c size 85B bind GLOBAL
 * Calls: memcpy | Data refs: esp_mesh_appie, g_mesh_topology
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=3); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_vnd_mesh_quick_get(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 000f */
  a2 = 0x102;  /* 0011 */
  if (a10 == 0) goto L_005c;  /* 0014: beqz a10, 5c <ieee80211_vnd_mesh_quick_get+0x50> */
  L_0017: a4 = (u32)&esp_mesh_appie + 0x0;  /* 0017: l32r -> global */
  a11 = LD32(a4 + 0x0);  /* 001a */
  if (a11 == 0) goto L_005c;  /* 001c: beqz.n a11, 5c <ieee80211_vnd_mesh_quick_get+0x50> */
  L_001e: a12 = 58;  /* 001e */
  a11 = a11 + (2);  /* 0020 */
  a8 = (u32)&memcpy + 0x0;  /* 0023: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0026: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 0029: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 002c */
  if (a8 == 0) goto L_005a;  /* 002e: beqz.n a8, 5a <ieee80211_vnd_mesh_quick_get+0x4e> */
  L_0030: if (a3 == 0) goto L_005a;  /* 0030: beqz a3, 5a <ieee80211_vnd_mesh_quick_get+0x4e> */
  L_0033: a9 = LD32(a4 + 0x0);  /* 0033 */
  a8 = a9 + (60);  /* 0036 */
  a9 = LD8U(a9 + 0x3c);  /* 0039 */
  a4 = LD8U(a8 + 0x1);  /* 003c */
  ST8(a3 + 0x0, a9);  /* 003f */
  __asm__ volatile("" ::: "memory");  /* 0042: memw */
  a9 = LD8U(a8 + 0x2);  /* 0045 */
  ST8(a3 + 0x1, a4);  /* 0048 */
  __asm__ volatile("" ::: "memory");  /* 004b: memw */
  a4 = LD8U(a8 + 0x3);  /* 004e */
  ST8(a3 + 0x2, a9);  /* 0051 */
  ST8(a3 + 0x3, a4);  /* 0054 */
  __asm__ volatile("" ::: "memory");  /* 0057: memw */
  L_005a: a2 = 0;  /* 005a */
  L_005c: __asm__ volatile("" ::: "memory");  /* 005c: memw */
  return a2;  /* 005f: retw.n */
}


/* ieee80211_vnd_mesh_quick_set @ mesh_quick.o 00000030 size 416B bind GLOBAL
 * Calls: memcmp, wifi_disconnect_process, wifi_get_macaddr, memcpy, ieee80211_vnd_mesh_update_beacon | indirect[2]: mem[a8+0x54]; mem[a2+0x58] | Data refs: esp_mesh_appie, g_osi_funcs_p, g_wifi_global_lock, g_mesh_topology
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=9); reloc-direct=5, funcdb-attributed=0, unknown-indirect=2 */
u32 ieee80211_vnd_mesh_quick_set(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8, a9;
  float F4;
  /* 0030: entry a1, 48 (frame 48 bytes) */
  a8 = 0x102;  /* 0033 */
  if (a2 == 0) goto L_01cc;  /* 0036: beqz a2, 1cc <ieee80211_vnd_mesh_quick_set+0x19c> */
  L_0039: a5 = (u32)&esp_mesh_appie + 0x0;  /* 0039: l32r -> global */
  a4 = LD32(a5 + 0x0);  /* 003c */
  if (a4 == 0) goto L_01cc;  /* 003e: beqz a4, 1cc <ieee80211_vnd_mesh_quick_set+0x19c> */
  L_0041: a6 = 0;  /* 0041 */
  a12 = 6;  /* 0043 */
  a11 = a2 + (8);  /* 0045 */
  a10 = a4 + (10);  /* 0048 */
  ST32(a1 + 0x0, a6);  /* 004a */
  ST16(a1 + 0x4, a6);  /* 004d */
  __asm__ volatile("" ::: "memory");  /* 0050: memw */
  __asm__ volatile("" ::: "memory");  /* 0053: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0056: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0059: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a2 + 0x7);  /* 005c */
  if (a10 == a6) goto L_006d;  /* 005f: beq a10, a6, 6d <ieee80211_vnd_mesh_quick_set+0x3d> */
  L_0062: if (a8 == 1) goto L_009c;  /* 0062: beqi a8, 1, 9c <ieee80211_vnd_mesh_quick_set+0x6c> */
  L_0065: a10 = a6;  /* 0065 */
  a8 = (u32)&wifi_disconnect_process + 0x0;  /* 0067: l32r -> global */
  a2 = wifi_disconnect_process(a2, a3, a4, a5, a6, a7);  /* 006a: callx a8 via reloc-expand */
  L_006d: a6 = LD8U(a2 + 0x7);  /* 006d */
  if (a6 == 1) goto L_009c;  /* 0070: beqi a6, 1, 9c <ieee80211_vnd_mesh_quick_set+0x6c> */
  L_0073: a8 = LD8U(a4 + 0x17);  /* 0073 */
  a8 = a8 << 8;  /* 0076 */
  a6 = LD8U(a4 + 0x16);  /* 0079 */
  a8 = a8 | a6;  /* 007c */
  a9 = LD8U(a2 + 0x15);  /* 007f */
  a9 = a9 << 8;  /* 0082 */
  a6 = LD8U(a2 + 0x14);  /* 0085 */
  a9 = a9 | a6;  /* 0088 */
  if (a9 == a8) goto L_009c;  /* 008b: beq a9, a8, 9c <ieee80211_vnd_mesh_quick_set+0x6c> */
  L_008e: if (a8 == 0) goto L_009c;  /* 008e: beqz.n a8, 9c <ieee80211_vnd_mesh_quick_set+0x6c> */
  L_0090: ST8(a2 + 0x14, a8);  /* 0090 */
  a8 = a8 >> 8;  /* 0093 */
  ST8(a2 + 0x15, a8);  /* 0096 */
  __asm__ volatile("" ::: "memory");  /* 0099: memw */
  L_009c: a11 = a1;  /* 009c */
  a10 = 1;  /* 009e */
  __asm__ volatile("" ::: "memory");  /* 00a0: memw */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 00a3: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6, a7);  /* 00a6: callx a8 via reloc-expand */
  a12 = 6;  /* 00a9 */
  a11 = a1;  /* 00ab */
  a10 = a2 + (31);  /* 00ad */
  a8 = (u32)&memcmp + 0x0;  /* 00b0: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00b3: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00bd;  /* 00b6: bnez.n a10, bd <ieee80211_vnd_mesh_quick_set+0x8d> */
  L_00b8: a6 = LD8U(a2 + 0x7);  /* 00b8 */
  if (a6 == 0) goto L_00cf;  /* 00bb: beqz.n a6, cf <ieee80211_vnd_mesh_quick_set+0x9f> */
  L_00bd: a8 = -120;  /* 00bd */
  a6 = LD8U(a4 + 0x27);  /* 00c0 */
  a9 = (i32)(a6 << (32 - 7)) >> (32 - 7);  /* 00c3: sext */
  if (a9 == a8) goto L_00cf;  /* 00c6: beq a9, a8, cf <ieee80211_vnd_mesh_quick_set+0x9f> */
  L_00c9: ST8(a2 + 0x25, a6);  /* 00c9 */
  __asm__ volatile("" ::: "memory");  /* 00cc: memw */
  L_00cf: a12 = 6;  /* 00cf */
  a11 = a1;  /* 00d1: mov */
  a10 = a2 + (38);  /* 00d4 */
  __asm__ volatile("" ::: "memory");  /* 00d7: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00da: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00dd: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_00f4;  /* 00e0: beqz.n a10, f4 <ieee80211_vnd_mesh_quick_set+0xc4> */
  L_00e2: a6 = LD8U(a4 + 0x2e);  /* 00e2 */
  a8 = -120;  /* 00e5 */
  a9 = (i32)(a6 << (32 - 7)) >> (32 - 7);  /* 00e8: sext */
  if (a9 == a8) goto L_00f4;  /* 00eb: beq a9, a8, f4 <ieee80211_vnd_mesh_quick_set+0xc4> */
  L_00ee: ST8(a2 + 0x2c, a6);  /* 00ee */
  __asm__ volatile("" ::: "memory");  /* 00f1: memw */
  L_00f4: a8 = -2;  /* 00f4 */
  a6 = LD8U(a2 + 0x1e);  /* 00f6 */
  a8 = a6 & a8;  /* 00f9 */
  a9 = LD8U(a4 + 0x20);  /* 00fc */
  if (((a9 >> 0) & 1) == 0) goto L_0108;  /* 00ff: bbci a9, 0, 108 <ieee80211_vnd_mesh_quick_set+0xd8> */
  L_0102: a8 = 1;  /* 0102 */
  a8 = a6 | a8;  /* 0105 */
  L_0108: ST8(a2 + 0x1e, a8);  /* 0108 */
  __asm__ volatile("" ::: "memory");  /* 010b: memw */
  a12 = 6;  /* 010e */
  a11 = a4 + (53);  /* 0111 */
  a10 = a2 + (51);  /* 0114 */
  __asm__ volatile("" ::: "memory");  /* 0117: memw */
  a8 = (u32)&memcpy + 0x0;  /* 011a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 011d: callx a8 (libc, via reloc-expand) */
  a11 = LD8U(a4 + 0x1f);  /* 0120 */
  a12 = 0;  /* 0123 */
  a10 = (i32)(a11 << (32 - 7)) >> (32 - 7);  /* 0125: sext */
  a9 = 1;  /* 0128 */
  a13 = a12;  /* 012a */
  a8 = LD8U(a2 + 0x1d);  /* 012c */
  a6 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 012f: sext */
  a14 = a10 - a6;  /* 0132: sub */
  if (a14 != 0) a13 = a9;  /* 0135 */
  a14 = a6 + (120);  /* 0138 */
  if (a14 == 0) a9 = a12;  /* 013b */
  if ((a13 & a9) == 0) goto L_0166;  /* 013e: bnone a13, a9, 166 <ieee80211_vnd_mesh_quick_set+0x136> */
  L_0141: a9 = a10 + (120);  /* 0141 */
  if (a9 == a12) goto L_0166;  /* 0144: beq a9, a12, 166 <ieee80211_vnd_mesh_quick_set+0x136> */
  L_0147: if (a11 == a12) goto L_015d;  /* 0147: beq a11, a12, 15d <ieee80211_vnd_mesh_quick_set+0x12d> */
  L_014a: a9 = a10 + (a10 << 1);  /* 014a */
  a8 = a6 + (a6 << 1);  /* 014d */
  a9 = a9 + (a10 << 2);  /* 0150 */
  a9 = a9 + a8;  /* 0153 */
  a8 = a9 + (15);  /* 0155 */
  if ((i32)a9 >= 0) a8 = a9;  /* 0157 */
  a8 = (a8 >> 8) & 0x1f;  /* 015a: extui width 5 */
  L_015d: ST8(a4 + 0x1f, a8);  /* 015d */
  ST8(a2 + 0x1d, a8);  /* 0160 */
  __asm__ volatile("" ::: "memory");  /* 0163: memw */
  L_0166: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0166: l32r -> global */
  a4 = (u32)&g_wifi_global_lock + 0x0;  /* 0169: l32r -> global */
  a8 = LD32(a6 + 0x0);  /* 016c */
  a10 = LD32(a4 + 0x0);  /* 016e */
  a8 = LD32(a8 + 0x54);  /* 0171 */
  __asm__ volatile("" ::: "memory");  /* 0174: memw */
  /* 0177: INDIRECT callx a8 <- mem[a8+0x54]; result unknown */ a2 = 0;
  a11 = a2 + (7);  /* 017a */
  a12 = 51;  /* 017c */
  a5 = LD32(a5 + 0x0);  /* 017e */
  a10 = a5 + (9);  /* 0180 */
  a8 = (u32)&memcpy + 0x0;  /* 0182: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0185: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 0188: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 018b */
  if (a2 == 0) goto L_01b5;  /* 018d: beqz.n a2, 1b5 <ieee80211_vnd_mesh_quick_set+0x185> */
  L_018f: if (a3 == 0) goto L_01b5;  /* 018f: beqz.n a3, 1b5 <ieee80211_vnd_mesh_quick_set+0x185> */
  L_0191: a2 = a5 + (60);  /* 0191 */
  a9 = LD8U(a3 + 0x0);  /* 0194 */
  a8 = LD8U(a3 + 0x1);  /* 0197 */
  ST8(a5 + 0x3c, a9);  /* 019a */
  __asm__ volatile("" ::: "memory");  /* 019d: memw */
  a5 = LD8U(a3 + 0x2);  /* 01a0 */
  ST8(a2 + 0x1, a8);  /* 01a3 */
  __asm__ volatile("" ::: "memory");  /* 01a6: memw */
  a3 = LD8U(a3 + 0x3);  /* 01a9 */
  ST8(a2 + 0x2, a5);  /* 01ac */
  ST8(a2 + 0x3, a3);  /* 01af */
  __asm__ volatile("" ::: "memory");  /* 01b2: memw */
  L_01b5: a10 = 0;  /* 01b5 */
  __asm__ volatile("" ::: "memory");  /* 01b7: memw */
  a8 = (u32)&ieee80211_vnd_mesh_update_beacon + 0x0;  /* 01ba: l32r -> global */
  a2 = ieee80211_vnd_mesh_update_beacon(a2, a3, a4, a5, a6, a7);  /* 01bd: callx a8 via reloc-expand */
  a2 = LD32(a6 + 0x0);  /* 01c0 */
  a10 = LD32(a4 + 0x0);  /* 01c2 */
  a2 = LD32(a2 + 0x58);  /* 01c4 */
  /* 01c7: INDIRECT callx a2 <- mem[a2+0x58]; result unknown */ a2 = 0;
  a8 = 0;  /* 01ca */
  L_01cc: a2 = a8;  /* 01cc */
  return a2;  /* 01ce: retw.n */
}


/* ieee80211_vnd_mesh_roots_get @ mesh_quick.o 00000008 size 46B bind GLOBAL
 * Calls: memcpy | Data refs: .bss.wifi_vnd_ext_mesh_roots
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 ieee80211_vnd_mesh_roots_get(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (a2 >> 8) & 0x1;  /* 000b: extui width 1 */
  a10 = a3;  /* 000e */
  a2 = -1;  /* 0010 */
  if (a8 >= 4u) goto L_0034;  /* 0012: bgeui a8, 4, 34 <ieee80211_vnd_mesh_roots_get+0x2c> */
  L_0015: a2 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 0015: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a8 = a8 + (a2 << 3);  /* 0018 */
  a2 = -1;  /* 001b */
  a12 = LD8U(a8 + 0x1);  /* 001d */
  if ((i32)a4 < (i32)a12) goto L_0034;  /* 0020: blt a4, a12, 34 <ieee80211_vnd_mesh_roots_get+0x2c> */
  L_0023: a12 = a12 + (a12 << 1);  /* 0023 */
  a12 = a12 << 2;  /* 0026 */
  a11 = LD32(a8 + 0x4);  /* 0029 */
  a2 = 0;  /* 002b */
  a8 = (u32)&memcpy + 0x0;  /* 002e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0031: callx a8 (libc, via reloc-expand) */
  L_0034: return a2;  /* 0034: retw.n */
}


/* ieee80211_vnd_mesh_roots_set @ mesh_quick.o 000000b0 size 1187B bind GLOBAL
 * Calls: _mesh_roots_process_stop, ieee80211_mesh_quick_get, memcmp, _wifi_vnd_ext_mesh_roots_malloc, memcpy, wifi_log, roots_type2str, _wifi_vnd_ext_mesh_roots_free, _mesh_reset_window_open_time, _mesh_roots_process_yield, _mesh_roots_process_gone, _mesh_roots_process_conflict_table, _mesh_roots_process_announce, ieee80211_vnd_mesh_update_beacon, mesh_is_new_found_conflict_root, esp_mesh_update_conflict_root | indirect[7]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x158]; mem[a5+0xb8] | Data refs: .bss.wifi_vnd_ext_mesh_roots, esp_mesh_appie, .rodata.ieee80211_vnd_mesh_roots_set.str1.1, .rodata_wlog_warning.3, g_osi_funcs_p, .rodata.mesh_parse_ps_entire_rule.str1.1, .rodata.esp_mesh_ps_duty_cycle_get_process.str1.1, .rodata._mesh_timer_process_conflict_root.str1.1, .rodata_wlog_warning.4, g_mesh_max_layer
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=16, refs=26); reloc-direct=16, funcdb-attributed=0, unknown-indirect=7 */
u32 ieee80211_vnd_mesh_roots_set(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a5, a6, a7, a8, a9;
  /* 00b0: entry a1, 96 (frame 96 bytes) */
  ST32(a1 + 0x20, a4);  /* 00b3 */
  a2 = (a2 >> 8) & 0x1;  /* 00b5: extui width 1 */
  if (a2 < 5u) goto L_00be;  /* 00b8: bltui a2, 5, be <ieee80211_vnd_mesh_roots_set+0xe> */
  L_00bb: goto L_041c;  /* 00bb: j */
  L_00be: a7 = 1;  /* 00be */
  a5 = 0;  /* 00c0 */
  if (a4 == 0) a5 = a7;  /* 00c2 */
  a9 = (a5 >> 8) & 0x1;  /* 00c5: extui width 1 */
  if (a5 == 0) goto L_00d0;  /* 00c8: beqz.n a5, d0 <ieee80211_vnd_mesh_roots_set+0x20> */
  L_00ca: __asm__ volatile("" ::: "memory");  /* 00ca: memw */
  goto L_041c;  /* 00cd: j */
  L_00d0: a5 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 00d0: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a4 = a2 << 3;  /* 00d3 */
  a11 = a2 + (a5 << 3);  /* 00d6 */
  ST32(a1 + 0x28, a4);  /* 00d9 */
  ST32(a1 + 0x10, a9);  /* 00db */
  ST16(a1 + 0x14, a9);  /* 00dd */
  __asm__ volatile("" ::: "memory");  /* 00e0: memw */
  a4 = LD8U(a11 + 0x1);  /* 00e3 */
  a6 = LD32(a11 + 0x4);  /* 00e6 */
  if (a2 != 4) goto L_00fd;  /* 00e8: bnei a2, 4, fd <ieee80211_vnd_mesh_roots_set+0x4d> */
  L_00eb: a10 = a3;  /* 00eb */
  __asm__ volatile("" ::: "memory");  /* 00ed: memw */
  a8 = (u32)&_mesh_roots_process_stop;  /* 00f0: l32r -> func addr */
  a2 = _mesh_roots_process_stop(a2, a3, a4);  /* 00f3: callx a8 via reloc-expand */
  a2 = a10;  /* 00f6 */
  goto L_0551;  /* 00f8: j */
  L_00fd: if (a4 < 5u) goto L_0103;  /* 00fd: bltui a4, 5, 103 <ieee80211_vnd_mesh_roots_set+0x53> */
  L_0100: goto L_041c;  /* 0100: j */
  L_0103: a8 = LD32(a1 + 0x20);  /* 0103 */
  a10 = 5;  /* 0105 */
  a10 = ((i32)a8 < (i32)a10) ? a8 : a10;  /* 0107: min */
  a12 = a2 + a2;  /* 010a */
  ST32(a1 + 0x24, a10);  /* 010c */
  a10 = LD8U(a11 + 0x0);  /* 010e */
  a10 = (a10 >> 1) & 0x1;  /* 0111: extui width 1 */
  a10 = a10 | a12;  /* 0114 */
  a12 = a1 + (16);  /* 0117 */
  ST8(a11 + 0x0, a10);  /* 011a */
  __asm__ volatile("" ::: "memory");  /* 011d: memw */
  a11 = 15;  /* 0120 */
  a10 = (u32)&esp_mesh_appie + 0x0;  /* 0122: l32r -> global */
  a10 = LD32(a10 + 0x0);  /* 0125 */
  a10 = a10 + (2);  /* 0127 */
  ST32(a1 + 0x34, a9);  /* 0129 */
  __asm__ volatile("" ::: "memory");  /* 012b: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 012e: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4);  /* 0131: callx a8 via reloc-expand */
  a9 = LD32(a1 + 0x34);  /* 0134 */
  if (a4 != 0) goto L_0198;  /* 0136: bnez a4, 198 <ieee80211_vnd_mesh_roots_set+0xe8> */
  L_0139: a6 = a4;  /* 0139 */
  if (a2 == 0) a6 = a7;  /* 013b */
  if (a6 == 0) goto L_015e;  /* 013e: beqz.n a6, 15e <ieee80211_vnd_mesh_roots_set+0xae> */
  L_0140: a8 = LD32(a1 + 0x20);  /* 0140 */
  a6 = a8 + (-1);  /* 0142 */
  a8 = a4;  /* 0144 */
  if (a6 == 0) a8 = a7;  /* 0146 */
  if (a8 == 0) goto L_015e;  /* 0149: beqz.n a8, 15e <ieee80211_vnd_mesh_roots_set+0xae> */
  L_014b: a12 = 6;  /* 014b */
  a11 = a1 + (16);  /* 014d */
  a10 = a3 + (4);  /* 0150 */
  a8 = (u32)&memcmp + 0x0;  /* 0152: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 0155: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_015e;  /* 0158: bnez.n a10, 15e <ieee80211_vnd_mesh_roots_set+0xae> */
  L_015a: goto L_0200;  /* 015a: j */
  L_015e: a4 = LD32(a1 + 0x24);  /* 015e */
  a10 = a2;  /* 0160 */
  a7 = (a4 >> 8) & 0x1;  /* 0162: extui width 1 */
  a6 = a7 + (a7 << 1);  /* 0165 */
  a6 = a6 << 2;  /* 0168 */
  a6 = (a6 >> 8) & 0x1;  /* 016b: extui width 1 */
  a11 = a6;  /* 016e */
  a8 = (u32)&_wifi_vnd_ext_mesh_roots_malloc;  /* 0170: l32r -> func addr */
  a2 = _wifi_vnd_ext_mesh_roots_malloc(a2, a3, a4);  /* 0173: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x28);  /* 0176 */
  a4 = a5 + a8;  /* 0178 */
  ST32(a4 + 0x4, a10);  /* 017a */
  if (a10 == 0) goto L_0421;  /* 017c: beqz a10, 421 <ieee80211_vnd_mesh_roots_set+0x371> */
  L_017f: a12 = a6;  /* 017f */
  a11 = a3;  /* 0181 */
  __asm__ volatile("" ::: "memory");  /* 0183: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0186: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 0189: callx a8 (libc, via reloc-expand) */
  ST8(a4 + 0x1, a7);  /* 018c */
  __asm__ volatile("" ::: "memory");  /* 018f: memw */
  __asm__ volatile("" ::: "memory");  /* 0192: memw */
  goto L_0421;  /* 0195: j */
  L_0198: if (a2 == 1) goto L_019e;  /* 0198: beqi a2, 1, 19e <ieee80211_vnd_mesh_roots_set+0xee> */
  L_019b: goto L_0275;  /* 019b: j */
  L_019e: a7 = a4 + (-2);  /* 019e */
  if (a7 != 0) a9 = a2;  /* 01a1 */
  if (a9 != 0) goto L_01b1;  /* 01a4: bnez.n a9, 1b1 <ieee80211_vnd_mesh_roots_set+0x101> */
  L_01a6: a8 = LD32(a1 + 0x20);  /* 01a6 */
  a7 = a8 + (-2);  /* 01a8 */
  if (a7 != 0) a9 = a2;  /* 01ab */
  if (a9 == 0) goto L_0205;  /* 01ae: beqz a9, 205 <ieee80211_vnd_mesh_roots_set+0x155> */
  L_01b1: a2 = LD32(a1 + 0x24);  /* 01b1 */
  a11 = 1;  /* 01b3 */
  a14 = 0x617;  /* 01b5 */
  a12 = 2;  /* 01b8 */
  a11 = a11 << 21;  /* 01ba */
  a15 = (u32)(RODATA__rodata_ieee80211_vnd_mesh_roots_set_str1_1 + 0x0);  /* 01bd: -> "yield" */
  a10 = 1;  /* 01c0 */
  a13 = (u32)(RODATA__rodata_wlog_warning_3 + 0x0);  /* 01c3: l32r -> .rodata_wlog_warning.3 */
  ST32(a1 + 0x4, a2);  /* 01c6 */
  ST32(a1 + 0x0, a4);  /* 01c8 */
  __asm__ volatile("" ::: "memory");  /* 01cb: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 01ce: l32r -> global */
  a2 = wifi_log(a2, a3, a4);  /* 01d1: callx a8 via reloc-expand */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01d4: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01d7 */
  if (a2 == 0) goto L_0200;  /* 01d9: beqz.n a2, 200 <ieee80211_vnd_mesh_roots_set+0x150> */
  L_01db: a3 = LD32(a2 + 0x150);  /* 01db */
  if (a3 == 0) goto L_0200;  /* 01de: beqz.n a3, 200 <ieee80211_vnd_mesh_roots_set+0x150> */
  L_01e0: a10 = LD32(a2 + 0x158);  /* 01e0 */
  a2 = 0x61b;  /* 01e3 */
  /* 01e6: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01e9 */
  a10 = 1;  /* 01eb */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 01ed: -> "child(cidx:" */
  a14 = a11;  /* 01f0 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 01f2: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata__mesh_timer_process_conflict_root_str1_1 + 0x0);  /* 01f5: l32r -> .rodata._mesh_timer_process_conflict_root.str1.1 */
  ST32(a1 + 0x0, a2);  /* 01f8 */
  __asm__ volatile("" ::: "memory");  /* 01fa: memw */
  /* 01fd: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0200: a2 = 0;  /* 0200 */
  goto L_0551;  /* 0202: j */
  L_0205: a12 = 24;  /* 0205 */
  a11 = a3;  /* 0207 */
  a10 = a6;  /* 0209 */
  a8 = (u32)&memcpy + 0x0;  /* 020b: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 020e: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0211 */
  a11 = a6 + (4);  /* 0213 */
  a10 = a3 + (4);  /* 0215 */
  a8 = (u32)&memcmp + 0x0;  /* 0217: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 021a: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0264;  /* 021d: bnez a10, 264 <ieee80211_vnd_mesh_roots_set+0x1b4> */
  L_0220: a12 = 6;  /* 0220 */
  a11 = a6 + (16);  /* 0222 */
  a10 = a3 + (16);  /* 0225 */
  a8 = (u32)&memcmp + 0x0;  /* 0228: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 022b: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0264;  /* 022e: bnez.n a10, 264 <ieee80211_vnd_mesh_roots_set+0x1b4> */
  L_0230: a8 = LD8U(a3 + 0x1);  /* 0230 */
  a8 = a8 << 8;  /* 0233 */
  a7 = LD8U(a6 + 0x1);  /* 0236 */
  a7 = a7 << 8;  /* 0239 */
  a10 = LD8U(a3 + 0x0);  /* 023c */
  a8 = a8 | a10;  /* 023f */
  a9 = LD8U(a6 + 0x0);  /* 0242 */
  a7 = a7 | a9;  /* 0245 */
  if (a8 >= a7) goto L_024e;  /* 0248: bgeu a8, a7, 24e <ieee80211_vnd_mesh_roots_set+0x19e> */
  L_024b: goto L_0421;  /* 024b: j */
  L_024e: a12 = 12;  /* 024e */
  a11 = a3;  /* 0250 */
  a10 = a6;  /* 0252 */
  a8 = (u32)&memcpy + 0x0;  /* 0254: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 0257: callx a8 (libc, via reloc-expand) */
  a12 = 12;  /* 025a */
  a11 = a3 + a12;  /* 025c */
  a10 = a6 + a12;  /* 025e */
  goto L_026a;  /* 0260: j */
  L_0264: a10 = LD32(a5 + 0xc);  /* 0264 */
  a12 = 24;  /* 0266 */
  a11 = a3;  /* 0268 */
  L_026a: a8 = (u32)&memcpy + 0x0;  /* 026a: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 026d: callx a8 (libc, via reloc-expand) */
  goto L_0421;  /* 0270: j */
  L_0275: a8 = LD32(a1 + 0x20);  /* 0275 */
  if (a8 == 1) goto L_02d4;  /* 0277: beqi a8, 1, 2d4 <ieee80211_vnd_mesh_roots_set+0x224> */
  L_027a: a10 = a2;  /* 027a */
  a8 = (u32)&roots_type2str;  /* 027c: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4);  /* 027f: callx a8 via reloc-expand */
  a2 = LD32(a1 + 0x24);  /* 0282 */
  a15 = a10;  /* 0284 */
  a14 = 0x631;  /* 0286 */
  a12 = 2;  /* 0289 */
  a11 = a7 << 21;  /* 028b */
  a13 = (u32)(RODATA__rodata_wlog_warning_4 + 0x0);  /* 028e: l32r -> .rodata_wlog_warning.4 */
  a10 = a7;  /* 0291 */
  ST32(a1 + 0x4, a2);  /* 0293 */
  ST32(a1 + 0x0, a4);  /* 0295 */
  __asm__ volatile("" ::: "memory");  /* 0298: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 029b: l32r -> global */
  a2 = wifi_log(a2, a3, a4);  /* 029e: callx a8 via reloc-expand */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 02a1: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 02a4 */
  if (a2 == 0) goto L_041c;  /* 02a7: beqz a2, 41c <ieee80211_vnd_mesh_roots_set+0x36c> */
  L_02aa: a3 = LD32(a2 + 0x150);  /* 02aa */
  if (a3 == 0) goto L_041c;  /* 02ad: beqz a3, 41c <ieee80211_vnd_mesh_roots_set+0x36c> */
  L_02b0: a10 = LD32(a2 + 0x158);  /* 02b0 */
  a2 = 0x635;  /* 02b3 */
  /* 02b6: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02b9 */
  a10 = a7;  /* 02bb */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 02bd: -> "child(cidx:" */
  a14 = a11;  /* 02c0 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 02c2: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata__mesh_timer_process_conflict_root_str1_1 + 0x0);  /* 02c5: l32r -> .rodata._mesh_timer_process_conflict_root.str1.1 */
  ST32(a1 + 0x0, a2);  /* 02c8 */
  __asm__ volatile("" ::: "memory");  /* 02ca: memw */
  /* 02cd: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_041c;  /* 02d0: j */
  L_02d4: a13 = a3 + (4);  /* 02d4 */
  a10 = a13;  /* 02d6 */
  a12 = 6;  /* 02d8 */
  a11 = a1 + (16);  /* 02da */
  ST32(a1 + 0x30, a13);  /* 02dd */
  __asm__ volatile("" ::: "memory");  /* 02df: memw */
  a8 = (u32)&memcmp + 0x0;  /* 02e2: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 02e5: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x30);  /* 02e8 */
  if (a10 != 0) goto L_030a;  /* 02ea: bnez.n a10, 30a <ieee80211_vnd_mesh_roots_set+0x25a> */
  L_02ec: if (a2 == 2) goto L_02f2;  /* 02ec: beqi a2, 2, 2f2 <ieee80211_vnd_mesh_roots_set+0x242> */
  L_02ef: goto L_0421;  /* 02ef: j */
  L_02f2: a7 = LD8U(a3 + 0x3);  /* 02f2 */
  a7 = a7 << 8;  /* 02f5 */
  a10 = LD8U(a3 + 0x2);  /* 02f8 */
  a7 = a7 | a10;  /* 02fb */
  a9 = 0x00007fffu;  /* 02fe: l32r = 32767 */
  a9 = (a9 >> 16) & 0x1;  /* 0301: extui width 1 */
  if (a7 == a9) goto L_030a;  /* 0304: beq a7, a9, 30a <ieee80211_vnd_mesh_roots_set+0x25a> */
  L_0307: goto L_0421;  /* 0307: j */
  L_030a: a9 = a6;  /* 030a */
  a7 = 0;  /* 030c */
  a14 = 6;  /* 030e */
  L_0311: a12 = a14;  /* 0311 */
  a11 = a9 + (4);  /* 0313 */
  a10 = a13;  /* 0315 */
  ST32(a1 + 0x34, a9);  /* 0317 */
  ST32(a1 + 0x30, a13);  /* 0319 */
  ST32(a1 + 0x2c, a14);  /* 031b */
  __asm__ volatile("" ::: "memory");  /* 031d: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0320: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 0323: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x34);  /* 0326 */
  a13 = LD32(a1 + 0x30);  /* 0328 */
  a14 = LD32(a1 + 0x2c);  /* 032a */
  if (a10 == 0) goto L_035c;  /* 032c: beqz.n a10, 35c <ieee80211_vnd_mesh_roots_set+0x2ac> */
  L_032e: a7 = a7 + (1);  /* 032e */
  a7 = (a7 >> 8) & 0x1;  /* 0330: extui width 1 */
  a9 = a9 + (12);  /* 0333 */
  if (a4 != a7) goto L_0311;  /* 0335: bne a4, a7, 311 <ieee80211_vnd_mesh_roots_set+0x261> */
  L_0338: a9 = a4 + (1);  /* 0338 */
  a9 = (a9 >> 8) & 0x1;  /* 033a: extui width 1 */
  a7 = a9 + (a9 << 1);  /* 033d */
  a7 = a7 << 2;  /* 0340 */
  a7 = (a7 >> 8) & 0x1;  /* 0343: extui width 1 */
  a11 = a7;  /* 0346 */
  a10 = a2;  /* 0348 */
  ST32(a1 + 0x34, a9);  /* 034a */
  __asm__ volatile("" ::: "memory");  /* 034c: memw */
  a8 = (u32)&_wifi_vnd_ext_mesh_roots_malloc;  /* 034f: l32r -> func addr */
  a2 = _wifi_vnd_ext_mesh_roots_malloc(a2, a3, a4);  /* 0352: callx a8 via reloc-expand */
  a9 = LD32(a1 + 0x34);  /* 0355 */
  if (a10 != 0) goto L_0390;  /* 0357: bnez.n a10, 390 <ieee80211_vnd_mesh_roots_set+0x2e0> */
  L_0359: goto L_03d6;  /* 0359: j */
  L_035c: if (a2 == 2) goto L_0388;  /* 035c: beqi a2, 2, 388 <ieee80211_vnd_mesh_roots_set+0x2d8> */
  L_035f: a11 = LD8U(a3 + 0x1);  /* 035f */
  a11 = a11 << 8;  /* 0362 */
  a10 = LD8U(a9 + 0x1);  /* 0365 */
  a10 = a10 << 8;  /* 0368 */
  a13 = LD8U(a3 + 0x0);  /* 036b */
  a11 = a11 | a13;  /* 036e */
  a12 = LD8U(a9 + 0x0);  /* 0371 */
  a10 = a10 | a12;  /* 0374 */
  if (a11 < a10) goto L_0388;  /* 0377: bltu a11, a10, 388 <ieee80211_vnd_mesh_roots_set+0x2d8> */
  L_037a: a12 = 12;  /* 037a */
  a11 = a3;  /* 037c: mov */
  a10 = a9;  /* 037f: mov */
  a8 = (u32)&memcpy + 0x0;  /* 0382: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 0385: callx a8 (libc, via reloc-expand) */
  L_0388: if (a7 >= a4) goto L_0338;  /* 0388: bgeu a7, a4, 338 <ieee80211_vnd_mesh_roots_set+0x288> */
  L_038b: goto L_0421;  /* 038b: j */
  L_0390: a8 = a4 + (a4 << 1);  /* 0390 */
  a7 = a8 << 2;  /* 0393 */
  a11 = a6;  /* 0396 */
  a12 = a7;  /* 0398 */
  ST32(a1 + 0x34, a9);  /* 039a */
  __asm__ volatile("" ::: "memory");  /* 039c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 039f: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 03a2: callx a8 (libc, via reloc-expand) */
  a13 = a10;  /* 03a5 */
  a12 = 12;  /* 03a7 */
  a11 = a3;  /* 03a9 */
  a10 = a10 + a7;  /* 03ab */
  ST32(a1 + 0x30, a13);  /* 03ad */
  __asm__ volatile("" ::: "memory");  /* 03af: memw */
  a8 = (u32)&memcpy + 0x0;  /* 03b2: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 03b5: callx a8 (libc, via reloc-expand) */
  a10 = a2;  /* 03b8 */
  a8 = (u32)&_wifi_vnd_ext_mesh_roots_free;  /* 03ba: l32r -> func addr */
  a2 = _wifi_vnd_ext_mesh_roots_free(a2, a3, a4);  /* 03bd: callx a8 via reloc-expand */
  a4 = LD32(a1 + 0x28);  /* 03c0 */
  a6 = a5 + a4;  /* 03c2 */
  a13 = LD32(a1 + 0x30);  /* 03c4 */
  a9 = LD32(a1 + 0x34);  /* 03c6 */
  ST32(a6 + 0x4, a13);  /* 03c8 */
  ST8(a6 + 0x1, a9);  /* 03ca */
  __asm__ volatile("" ::: "memory");  /* 03cd: memw */
  __asm__ volatile("" ::: "memory");  /* 03d0: memw */
  goto L_0421;  /* 03d3: j */
  L_03d6: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 03d6: l32r -> global */
  a3 = LD32(a5 + 0x0);  /* 03d9 */
  if (a3 == 0) goto L_041c;  /* 03db: beqz.n a3, 41c <ieee80211_vnd_mesh_roots_set+0x36c> */
  L_03dd: a4 = LD32(a3 + 0x150);  /* 03dd */
  if (a4 == 0) goto L_041c;  /* 03e0: beqz.n a4, 41c <ieee80211_vnd_mesh_roots_set+0x36c> */
  L_03e2: a10 = LD32(a3 + 0x158);  /* 03e2 */
  /* 03e5: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 03e8 */
  a10 = a2;  /* 03ea */
  a8 = (u32)&roots_type2str;  /* 03ec: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4);  /* 03ef: callx a8 via reloc-expand */
  a5 = LD32(a5 + 0x0);  /* 03f2 */
  a2 = a10;  /* 03f4 */
  a10 = LD32(a5 + 0xb8);  /* 03f6 */
  /* 03f9: INDIRECT callx a10 <- mem[a5+0xb8]; result unknown */ a2 = 0;
  a13 = a3;  /* 03fc */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 03fe: -> "child(cidx:" */
  a14 = a11;  /* 0401 */
  ST32(a1 + 0x4, a2);  /* 0403 */
  a2 = 0x66d;  /* 0405 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 0408: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata_ieee80211_vnd_mesh_roots_set_str1_1 + 0x0);  /* 040b: -> "yield" */
  ST32(a1 + 0xc, a10);  /* 040e */
  a10 = 1;  /* 0410 */
  ST32(a1 + 0x8, a7);  /* 0412 */
  ST32(a1 + 0x0, a2);  /* 0414 */
  __asm__ volatile("" ::: "memory");  /* 0416: memw */
  /* 0419: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_041c: a2 = -1;  /* 041c */
  goto L_0551;  /* 041e: j */
  L_0421: a8 = LD32(a1 + 0x28);  /* 0421 */
  a6 = a5 + a8;  /* 0423 */
  a6 = LD8U(a6 + 0x1);  /* 0425 */
  if (a6 == 0) goto L_04dc;  /* 0428: beqz a6, 4dc <ieee80211_vnd_mesh_roots_set+0x42c> */
  L_042b: if (a2 == 2) goto L_0449;  /* 042b: beqi a2, 2, 449 <ieee80211_vnd_mesh_roots_set+0x399> */
  L_042e: if (a2 == 3) goto L_04a1;  /* 042e: beqi a2, 3, 4a1 <ieee80211_vnd_mesh_roots_set+0x3f1> */
  L_0431: if (a2 == 1) goto L_0437;  /* 0431: beqi a2, 1, 437 <ieee80211_vnd_mesh_roots_set+0x387> */
  L_0434: goto L_04d4;  /* 0434: j */
  L_0437: a4 = LD8U(a5 + 0x8);  /* 0437 */
  a4 = a2 | a4;  /* 043a */
  ST8(a5 + 0x8, a4);  /* 043d */
  __asm__ volatile("" ::: "memory");  /* 0440: memw */
  __asm__ volatile("" ::: "memory");  /* 0443: memw */
  goto L_04d4;  /* 0446: j */
  L_0449: a6 = LD8U(a5 + 0x10);  /* 0449 */
  a7 = 1;  /* 044c */
  a6 = a6 | a7;  /* 044e */
  a4 = LD32(a1 + 0x20);  /* 0451 */
  ST8(a5 + 0x10, a6);  /* 0453 */
  __asm__ volatile("" ::: "memory");  /* 0456: memw */
  if (a4 != 1) goto L_0485;  /* 0459: bnei a4, 1, 485 <ieee80211_vnd_mesh_roots_set+0x3d5> */
  L_045c: a6 = LD8U(a3 + 0x1);  /* 045c */
  a6 = a6 << 8;  /* 045f */
  a7 = LD8U(a3 + 0x0);  /* 0462 */
  a6 = a6 | a7;  /* 0465 */
  a7 = (u32)&g_mesh_max_layer + 0x0;  /* 0468: l32r -> global */
  a7 = LD16U(a7 + 0x0);  /* 046b */
  a7 = a7 + (-1);  /* 046e */
  if (a6 != a7) goto L_0485;  /* 0470: bne a6, a7, 485 <ieee80211_vnd_mesh_roots_set+0x3d5> */
  L_0473: a12 = 0x681;  /* 0473 */
  a11 = a4;  /* 0476: mov */
  a10 = a2;  /* 0479: mov */
  __asm__ volatile("" ::: "memory");  /* 047c: memw */
  a8 = (u32)&_mesh_reset_window_open_time;  /* 047f: l32r -> func addr */
  a2 = _mesh_reset_window_open_time(a2, a3, a4);  /* 0482: callx a8 via reloc-expand */
  L_0485: a11 = 0x684;  /* 0485 */
  a10 = 2;  /* 0488 */
  a8 = (u32)&_mesh_roots_process_yield;  /* 048a: l32r -> func addr */
  a2 = _mesh_roots_process_yield(a2, a3, a4);  /* 048d: callx a8 via reloc-expand */
  a12 = 0;  /* 0490 */
  a11 = a12;  /* 0492 */
  a10 = 2;  /* 0494 */
  a8 = (u32)&_mesh_roots_process_gone;  /* 0496: l32r -> func addr */
  a2 = _mesh_roots_process_gone(a2, a3, a4);  /* 0499: callx a8 via reloc-expand */
  a10 = 2;  /* 049c */
  goto L_04ce;  /* 049e: j */
  L_04a1: a4 = LD8U(a5 + 0x18);  /* 04a1 */
  a6 = 1;  /* 04a4 */
  a4 = a4 | a6;  /* 04a6 */
  a12 = 0x692;  /* 04a9 */
  a11 = 1;  /* 04ac */
  ST8(a5 + 0x18, a4);  /* 04af */
  __asm__ volatile("" ::: "memory");  /* 04b2: memw */
  a10 = a2;  /* 04b5: mov */
  __asm__ volatile("" ::: "memory");  /* 04b8: memw */
  a8 = (u32)&_mesh_reset_window_open_time;  /* 04bb: l32r -> func addr */
  a2 = _mesh_reset_window_open_time(a2, a3, a4);  /* 04be: callx a8 via reloc-expand */
  a11 = 0x695;  /* 04c1 */
  a10 = a2;  /* 04c4 */
  a8 = (u32)&_mesh_roots_process_yield;  /* 04c6: l32r -> func addr */
  a2 = _mesh_roots_process_yield(a2, a3, a4);  /* 04c9: callx a8 via reloc-expand */
  a10 = a2;  /* 04cc */
  L_04ce: a8 = (u32)&_mesh_roots_process_conflict_table;  /* 04ce: l32r -> func addr */
  a2 = _mesh_roots_process_conflict_table(a2, a3, a4);  /* 04d1: callx a8 via reloc-expand */
  L_04d4: a10 = a2;  /* 04d4 */
  a8 = (u32)&_mesh_roots_process_announce;  /* 04d6: l32r -> func addr */
  a2 = _mesh_roots_process_announce(a2, a3, a4);  /* 04d9: callx a8 via reloc-expand */
  L_04dc: a6 = LD8U(a5 + 0x1);  /* 04dc */
  a4 = 0;  /* 04df */
  a10 = 1;  /* 04e1 */
  a8 = a4;  /* 04e3 */
  if (a6 != 0) a8 = a10;  /* 04e5 */
  a6 = LD8U(a5 + 0x0);  /* 04e8 */
  a7 = a8;  /* 04eb */
  a8 = -2;  /* 04ed */
  a6 = a6 & a8;  /* 04ef */
  a6 = a6 | a7;  /* 04f2 */
  ST8(a5 + 0x0, a6);  /* 04f5 */
  __asm__ volatile("" ::: "memory");  /* 04f8: memw */
  __asm__ volatile("" ::: "memory");  /* 04fb: memw */
  a8 = (u32)&ieee80211_vnd_mesh_update_beacon + 0x0;  /* 04fe: l32r -> global */
  a2 = ieee80211_vnd_mesh_update_beacon(a2, a3, a4);  /* 0501: callx a8 via reloc-expand */
  if (a2 == 1) goto L_050a;  /* 0504: beqi a2, 1, 50a <ieee80211_vnd_mesh_roots_set+0x45a> */
  L_0507: goto L_0200;  /* 0507: j */
  L_050a: goto L_0545;  /* 050a: j */
  L_050d: a6 = (u32)(RODATA__rodata_ieee80211_vnd_mesh_roots_set_str1_1 + 0x0);  /* 050d: -> "yield" */
  a4 = a2 + (a2 << 1);  /* 0510 */
  a4 = a4 + (a3 << 2);  /* 0513 */
  a13 = a6;  /* 0516 */
  a12 = 0x6b4;  /* 0518 */
  a11 = a1 + (24);  /* 051b */
  a10 = a4;  /* 051e */
  ST32(a1 + 0x18, a5);  /* 0520 */
  __asm__ volatile("" ::: "memory");  /* 0523: memw */
  a8 = (u32)&mesh_is_new_found_conflict_root;  /* 0526: l32r -> func addr */
  a2 = mesh_is_new_found_conflict_root(a2, a3, a4);  /* 0529: callx a8 via reloc-expand */
  if (a10 != 0) goto L_053d;  /* 052c: bnez.n a10, 53d <ieee80211_vnd_mesh_roots_set+0x48d> */
  L_052e: a13 = a6;  /* 052e */
  a12 = 0x6b8;  /* 0530 */
  a11 = LD32(a1 + 0x18);  /* 0533 */
  a10 = a4;  /* 0535 */
  a8 = (u32)&esp_mesh_update_conflict_root;  /* 0537: l32r -> func addr */
  a2 = esp_mesh_update_conflict_root(a2, a3, a4);  /* 053a: callx a8 via reloc-expand */
  L_053d: a2 = a2 + (1);  /* 053d */
  a2 = (a2 >> 8) & 0x1;  /* 053f: extui width 1 */
  goto L_0549;  /* 0542: j */
  L_0545: a2 = a4;  /* 0545 */
  a5 = -1;  /* 0547 */
  L_0549: a4 = LD32(a1 + 0x24);  /* 0549 */
  if ((i32)a2 < (i32)a4) goto L_050d;  /* 054b: blt a2, a4, 50d <ieee80211_vnd_mesh_roots_set+0x45d> */
  L_054e: goto L_0200;  /* 054e: j */
  L_0551: return a2;  /* 0551: retw.n */
}


/* is_esp_mesh_duty_signaling @ mesh_quick.o 00000004 size 55B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 is_esp_mesh_duty_signaling(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = LD8U(a2 + 0x1);  /* 0007 */
  a8 = a2;  /* 000a */
  a2 = 0;  /* 000c */
  if (a9 < 4u) goto L_0039;  /* 000e: bltui a9, 4, 39 <is_esp_mesh_duty_signaling+0x35> */
  L_0011: a10 = LD8U(a8 + 0x3);  /* 0011 */
  a10 = a10 << 8;  /* 0014 */
  a9 = LD8U(a8 + 0x2);  /* 0017 */
  a10 = a10 | a9;  /* 001a */
  a9 = LD8U(a8 + 0x4);  /* 001d */
  a9 = a9 << 16;  /* 0020 */
  a9 = a9 | a10;  /* 0023 */
  a8 = LD8U(a8 + 0x5);  /* 0026 */
  a8 = a8 << 24;  /* 0029 */
  a8 = a8 | a9;  /* 002c */
  a9 = 0xf0cb01e8u;  /* 002f: l32r = -255131160 */
  a8 = a8 + a9;  /* 0032 */
  a9 = 1;  /* 0034 */
  if (a8 == 0) a2 = a9;  /* 0036 */
  L_0039: return a2;  /* 0039: retw.n */
}


/* is_esp_mesh_ext_assoc @ mesh_quick.o 00000008 size 100B bind GLOBAL
 * Calls: none | Data refs: g_mesh_init_ps_type
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 is_esp_mesh_ext_assoc(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a11 = LD8U(a2 + 0x1);  /* 000b */
  a9 = a2;  /* 000e */
  a2 = 0;  /* 0010 */
  if (a11 < 4u) goto L_006a;  /* 0012: bltui a11, 4, 6a <is_esp_mesh_ext_assoc+0x62> */
  L_0015: a8 = LD8U(a9 + 0x3);  /* 0015 */
  a8 = a8 << 8;  /* 0018 */
  a10 = LD8U(a9 + 0x2);  /* 001b */
  a8 = a8 | a10;  /* 001e */
  a10 = LD8U(a9 + 0x4);  /* 0021 */
  a10 = a10 << 16;  /* 0024 */
  a10 = a10 | a8;  /* 0027 */
  a8 = LD8U(a9 + 0x5);  /* 002a */
  a8 = a8 << 24;  /* 002d */
  a8 = a8 | a10;  /* 0030 */
  a10 = 0xf3cb01e8u;  /* 0033: l32r = -204799512 */
  a8 = a8 + a10;  /* 0036 */
  a10 = 1;  /* 0038 */
  if (a8 != a2) goto L_0068;  /* 003a: bne a8, a2, 68 <is_esp_mesh_ext_assoc+0x60> */
  L_003d: if (a11 < 7u) goto L_0068;  /* 003d: bltui a11, 7, 68 <is_esp_mesh_ext_assoc+0x60> */
  L_0040: a8 = LD8U(a9 + 0x6);  /* 0040 */
  a11 = a11 + (-21);  /* 0043 */
  /* 0046: ssr a10 (SAR/shift-amount, summarized) */
  a8 = a8 >> 0;  /* 0049: srl a8, a8 (shift amount in SAR, untracked) */
  a9 = (u32)&g_mesh_init_ps_type + 0x0;  /* 004c: l32r -> global */
  a12 = LD32(a9 + 0x0);  /* 004f */
  a9 = 2;  /* 0051 */
  if (a12 == 0) a9 = a10;  /* 0053 */
  a8 = a8 - a9;  /* 0056: sub */
  a9 = a2;  /* 0059 */
  if (a8 == 0) a9 = a10;  /* 005b */
  if (a11 != 0) a10 = a2;  /* 005e */
  a2 = a9 & a10;  /* 0061 */
  goto L_006a;  /* 0064: j */
  L_0068: a2 = 0;  /* 0068 */
  L_006a: return a2;  /* 006a: retw.n */
}


/* is_esp_mesh_ps @ mesh_quick.o 00000004 size 55B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 is_esp_mesh_ps(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = LD8U(a2 + 0x1);  /* 0007 */
  a8 = a2;  /* 000a */
  a2 = 0;  /* 000c */
  if (a9 < 4u) goto L_0039;  /* 000e: bltui a9, 4, 39 <is_esp_mesh_ps+0x35> */
  L_0011: a10 = LD8U(a8 + 0x3);  /* 0011 */
  a10 = a10 << 8;  /* 0014 */
  a9 = LD8U(a8 + 0x2);  /* 0017 */
  a10 = a10 | a9;  /* 001a */
  a9 = LD8U(a8 + 0x4);  /* 001d */
  a9 = a9 << 16;  /* 0020 */
  a9 = a9 | a10;  /* 0023 */
  a8 = LD8U(a8 + 0x5);  /* 0026 */
  a8 = a8 << 24;  /* 0029 */
  a8 = a8 | a9;  /* 002c */
  a9 = 0xf1cb01e8u;  /* 002f: l32r = -238353944 */
  a8 = a8 + a9;  /* 0032 */
  a9 = 1;  /* 0034 */
  if (a8 == 0) a2 = a9;  /* 0036 */
  L_0039: return a2;  /* 0039: retw.n */
}


/* is_my_ie_encrypted @ mesh_quick.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: .bss.s_mesh_ie_crypto_funcs
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 is_my_ie_encrypted(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&LOCAL__bss_s_mesh_ie_crypto_funcs + 0x0;  /* 0007: l32r -> .bss.s_mesh_ie_crypto_funcs (same-object static) */
  a2 = 0;  /* 000a */
  a9 = LD32(a8 + 0x0);  /* 000c */
  if (a9 == a2) goto L_0018;  /* 000e: beq a9, a2, 18 <is_my_ie_encrypted+0x14> */
  L_0011: a9 = LD32(a8 + 0x4);  /* 0011 */
  a8 = 1;  /* 0013 */
  if (a9 != 0) a2 = a8;  /* 0015 */
  L_0018: return a2;  /* 0018: retw.n */
}


/* mesh_check_conflict_beacon @ mesh_quick.o 00000024 size 205B bind GLOBAL
 * Calls: memset, memcpy, ieee80211_is_mesh_roots_announce, _mesh_roots_process_gone, ieee80211_is_mesh_roots_yield, ieee80211_vnd_mesh_roots_set, mesh_is_ie_ignored | Data refs: g_mesh_max_layer, .bss.s_mesh_roots_ie_life
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=7, refs=9); reloc-direct=7, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_check_conflict_beacon(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a5, a6, a7, a8;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a5 = LD32(a3 + 0x0);  /* 0027 */
  a6 = 0;  /* 0029 */
  a3 = 1;  /* 002b */
  if (a5 == 0) a6 = a3;  /* 002d */
  a4 = (a4 >> 8) & 0x1;  /* 0030: extui width 1 */
  a7 = (a6 >> 8) & 0x1;  /* 0033: extui width 1 */
  if (a6 != 0) goto L_003d;  /* 0036: bnez.n a6, 3d <mesh_check_conflict_beacon+0x19> */
  L_0038: if (a2 == 0) a7 = a3;  /* 0038 */
  if (a7 == 0) goto L_0042;  /* 003b: beqz.n a7, 42 <mesh_check_conflict_beacon+0x1e> */
  L_003d: a2 = -1;  /* 003d */
  goto L_00ef;  /* 003f: j */
  L_0042: a12 = 12;  /* 0042 */
  a11 = a7;  /* 0044: mov */
  a10 = a1;  /* 0047: mov */
  a8 = (u32)&memset + 0x0;  /* 004a: l32r -> global */
  a2 = memset(a2, a3, a4);  /* 004d: callx a8 (libc, via reloc-expand) */
  a6 = (u32)&g_mesh_max_layer + 0x0;  /* 0050: l32r -> global */
  a12 = 6;  /* 0053 */
  a11 = a2;  /* 0055 */
  a10 = a1 + (4);  /* 0057 */
  a8 = LD16U(a6 + 0x0);  /* 005a */
  a8 = a8 + (-1);  /* 005d */
  ST16(a1 + 0x0, a8);  /* 0060 */
  a8 = -120;  /* 0063 */
  ST8(a1 + 0xa, a8);  /* 0066 */
  __asm__ volatile("" ::: "memory");  /* 0069: memw */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 006f: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 0072: callx a8 (libc, via reloc-expand) */
  a12 = LD8U(a5 + 0x7);  /* 0075 */
  if (a12 != 0) goto L_008a;  /* 0078: bnez.n a12, 8a <mesh_check_conflict_beacon+0x66> */
  L_007a: a11 = 1;  /* 007a */
  a10 = a1;  /* 007c */
  a8 = (u32)&ieee80211_is_mesh_roots_announce;  /* 007e: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_announce(a2, a3, a4);  /* 0081: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00b6;  /* 0084: beqz.n a10, b6 <mesh_check_conflict_beacon+0x92> */
  L_0086: goto L_00c0;  /* 0086: j */
  L_008a: a11 = a1;  /* 008a */
  a10 = 6;  /* 008c */
  a8 = (u32)&_mesh_roots_process_gone;  /* 008e: l32r -> func addr */
  a2 = _mesh_roots_process_gone(a2, a3, a4);  /* 0091: callx a8 via reloc-expand */
  a8 = LD8U(a5 + 0x7);  /* 0094 */
  a8 = a8 + (-1);  /* 0097 */
  if (a8 != 0) a3 = a7;  /* 0099 */
  if (a3 == 0) goto L_007a;  /* 009c: beqz a3, 7a <mesh_check_conflict_beacon+0x56> */
  L_009f: if (a4 == 0) goto L_007a;  /* 009f: beqz a4, 7a <mesh_check_conflict_beacon+0x56> */
  L_00a2: a3 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 00a2: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a8 = LD8U(a3 + 0x0);  /* 00a5 */
  a3 = LD8U(a3 + 0x10);  /* 00a8 */
  a8 = a8 | a3;  /* 00ab */
  a8 = (a8 >> 8) & 0x1;  /* 00ae: extui width 1 */
  if (a8 == 0) goto L_00e2;  /* 00b1: beqz.n a8, e2 <mesh_check_conflict_beacon+0xbe> */
  L_00b3: goto L_003d;  /* 00b3: j */
  L_00b6: a10 = a2;  /* 00b6 */
  a8 = (u32)&ieee80211_is_mesh_roots_yield;  /* 00b8: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_yield(a2, a3, a4);  /* 00bb: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00dc;  /* 00be: beqz.n a10, dc <mesh_check_conflict_beacon+0xb8> */
  L_00c0: a3 = LD16U(a6 + 0x0);  /* 00c0 */
  a12 = 1;  /* 00c3 */
  a3 = a3 + (-1);  /* 00c5 */
  a11 = a1;  /* 00c7: mov */
  a10 = 2;  /* 00ca */
  ST16(a1 + 0x0, a3);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00d0: memw */
  __asm__ volatile("" ::: "memory");  /* 00d3: memw */
  a8 = (u32)&ieee80211_vnd_mesh_roots_set;  /* 00d6: l32r -> func addr */
  a2 = ieee80211_vnd_mesh_roots_set(a2, a3, a4);  /* 00d9: callx a8 via reloc-expand */
  L_00dc: if (a4 != 0) goto L_00a2;  /* 00dc: bnez a4, a2 <mesh_check_conflict_beacon+0x7e> */
  L_00df: goto L_003d;  /* 00df: j */
  L_00e2: a10 = a2;  /* 00e2 */
  a11 = a5;  /* 00e4 */
  a8 = (u32)&mesh_is_ie_ignored;  /* 00e6: l32r -> func addr */
  a2 = mesh_is_ie_ignored(a2, a3, a4);  /* 00e9: callx a8 via reloc-expand */
  a2 = -a10;  /* 00ec */
  L_00ef: return a2;  /* 00ef: retw.n */
}


/* mesh_clear_parent_candidate @ mesh_quick.o 00000008 size 21B bind GLOBAL
 * Calls: memset | Data refs: .bss.s_mesh_parent_candidate
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_clear_parent_candidate(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a10 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 000b: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a12 = 184;  /* 000e */
  a11 = 0;  /* 0011 */
  a8 = (u32)&memset + 0x0;  /* 0013: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0016: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0019 */
  return a2;  /* 001b: retw.n */
}


/* mesh_coding_ie_key @ mesh_quick.o 00000000 size 62B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_coding_ie_key(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 0000: entry a1, 32 (frame 32 bytes) */
  a8 = 1;  /* 0003 */
  a9 = 0;  /* 0005 */
  if (a3 == 0) a9 = a8;  /* 0007 */
  a10 = (a9 >> 8) & 0x1;  /* 000a: extui width 1 */
  if (a9 != 0) goto L_0039;  /* 000d: bnez.n a9, 39 <mesh_coding_ie_key+0x39> */
  L_000f: if (a2 != 0) a8 = a10;  /* 000f */
  if (a8 != 0) goto L_0039;  /* 0012: bnez.n a8, 39 <mesh_coding_ie_key+0x39> */
  L_0014: a3 = a3 + (26);  /* 0014 */
  a9 = 6;  /* 0017 */
  /* 0019: loop (hardware loop over a9, 31 <mesh_coding_ie_key+0x31>..0031) */ goto L_0031;
  a10 = a2 + a8;  /* 001c */
  a11 = LD8U(a3 + 0x0);  /* 001e */
  a8 = a8 + (1);  /* 0021 */
  a10 = LD8U(a10 + 0x0);  /* 0023 */
  a10 = a10 ^ a11;  /* 0026 */
  ST8(a3 + 0x0, a10);  /* 0029 */
  __asm__ volatile("" ::: "memory");  /* 002c: memw */
  a3 = a3 + (1);  /* 002f */
  a2 = 0;  /* 0031 */
  __asm__ volatile("" ::: "memory");  /* 0033: memw */
  goto L_003c;  /* 0036: j */
  L_0039: a2 = 0x102;  /* 0039 */
  L_003c: return a2;  /* 003c: retw.n */
}


/* mesh_deinit_cb @ mesh_quick.o 00000010 size 39B bind GLOBAL
 * Calls: mesh_free, esp_mesh_quick_funcs_deinit | Data refs: .bss.s_mesh_conflict_roots, .rodata.__func__$17
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_deinit_cb(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0013: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a10 = LD32(a2 + 0x0);  /* 0016 */
  if (a10 == 0) goto L_002c;  /* 0019: beqz a10, 2c <mesh_deinit_cb+0x1c> */
  L_001c: a12 = 0x117;  /* 001c */
  a11 = (u32)(RODATA__rodata___func___17 + 0x0);  /* 001f: l32r -> .rodata.__func__$17 */
  a8 = (u32)&mesh_free + 0x0;  /* 0022: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0025: callx a8 via reloc-expand */
  a8 = 0;  /* 0028 */
  ST32(a2 + 0x0, a8);  /* 002a */
  L_002c: __asm__ volatile("" ::: "memory");  /* 002c: memw */
  a8 = (u32)&esp_mesh_quick_funcs_deinit;  /* 002f: l32r -> func addr */
  a2 = esp_mesh_quick_funcs_deinit(a2, a3, a4, a5, a6, a7);  /* 0032: callx a8 via reloc-expand */
  return a2;  /* 0035: retw.n */
}


/* mesh_get_parent_candidate @ mesh_quick.o 00000008 size 26B bind GLOBAL
 * Calls: memcpy | Data refs: .bss.s_mesh_parent_candidate
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_get_parent_candidate(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 000b */
  a2 = 0x102;  /* 000d */
  if (a10 == 0) goto L_0020;  /* 0010: beqz.n a10, 20 <mesh_get_parent_candidate+0x18> */
  L_0012: a11 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 0012: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a12 = 92;  /* 0015 */
  a8 = (u32)&memcpy + 0x0;  /* 0018: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 001b: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 001e */
  L_0020: return a2;  /* 0020: retw.n */
}


/* mesh_get_parent_monitor_config @ mesh_quick.o 00000004 size 37B bind GLOBAL
 * Calls: none | Data refs: .bss.s_mesh_monitor_parent_cfg
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_get_parent_monitor_config(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 0007 */
  a2 = 0x102;  /* 0009 */
  if (a8 == 0) goto L_0024;  /* 000c: beqz a8, 24 <mesh_get_parent_monitor_config+0x20> */
  L_000f: a2 = (u32)&LOCAL__bss_s_mesh_monitor_parent_cfg + 0x0;  /* 000f: l32r -> .bss.s_mesh_monitor_parent_cfg (same-object static) */
  a9 = LD8U(a2 + 0x0);  /* 0012 */
  a2 = LD8U(a2 + 0x1);  /* 0015 */
  ST8(a8 + 0x0, a9);  /* 0018 */
  ST8(a8 + 0x1, a2);  /* 001b */
  __asm__ volatile("" ::: "memory");  /* 001e: memw */
  a2 = 0;  /* 0021 */
  L_0024: __asm__ volatile("" ::: "memory");  /* 0024: memw */
  return a2;  /* 0027: retw.n */
}


/* mesh_get_rssi_threshold @ mesh_quick.o 00000008 size 26B bind GLOBAL
 * Calls: memcpy | Data refs: .bss.s_mesh_rssi_threshold
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_get_rssi_threshold(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 000b */
  a2 = 0x102;  /* 000d */
  if (a10 == 0) goto L_0020;  /* 0010: beqz.n a10, 20 <mesh_get_rssi_threshold+0x18> */
  L_0012: a11 = (u32)&LOCAL__bss_s_mesh_rssi_threshold + 0x0;  /* 0012: l32r -> .bss.s_mesh_rssi_threshold (same-object static) */
  a12 = 12;  /* 0015 */
  a8 = (u32)&memcpy + 0x0;  /* 0018: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 001b: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 001e */
  L_0020: return a2;  /* 0020: retw.n */
}


/* mesh_get_sub_ie @ mesh_quick.o 00000010 size 126B bind GLOBAL
 * Calls: memcpy | Data refs: esp_mesh_appie, g_mesh_topology, .bss.mesh_sub_ie$3
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_get_sub_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&esp_mesh_appie + 0x0;  /* 0013: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0016 */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 0018: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 001b */
  if (a2 != 0) goto L_0025;  /* 001d: bnez.n a2, 25 <mesh_get_sub_ie+0x15> */
  L_001f: a8 = LD8U(a3 + 0x11);  /* 001f */
  goto L_0031;  /* 0022: j */
  L_0025: a8 = LD8U(a3 + 0x3f);  /* 0025 */
  a8 = a8 << 8;  /* 0028 */
  a2 = LD8U(a3 + 0x3e);  /* 002b */
  a8 = a8 | a2;  /* 002e */
  L_0031: a12 = 6;  /* 0031 */
  a11 = a3 + (33);  /* 0033 */
  a2 = (u32)&LOCAL__bss_mesh_sub_ie_3 + 0x0;  /* 0036: l32r -> .bss.mesh_sub_ie$3 (same-object static) */
  a10 = a2 + a12;  /* 0039 */
  ST8(a2 + 0x0, a8);  /* 003b */
  a8 = a8 >> 8;  /* 003e */
  ST8(a2 + 0x1, a8);  /* 0041 */
  __asm__ volatile("" ::: "memory");  /* 0044: memw */
  a8 = LD8U(a3 + 0x17);  /* 0047 */
  a9 = LD8U(a3 + 0x16);  /* 004a */
  ST8(a2 + 0x3, a8);  /* 004d */
  __asm__ volatile("" ::: "memory");  /* 0050: memw */
  a8 = LD8U(a3 + 0x1e);  /* 0053 */
  ST8(a2 + 0x4, a8);  /* 0056 */
  __asm__ volatile("" ::: "memory");  /* 0059: memw */
  a8 = LD8U(a3 + 0x20);  /* 005c */
  ST8(a2 + 0x2, a9);  /* 005f */
  ST8(a2 + 0x5, a8);  /* 0062 */
  __asm__ volatile("" ::: "memory");  /* 0065: memw */
  __asm__ volatile("" ::: "memory");  /* 0068: memw */
  a8 = (u32)&memcpy + 0x0;  /* 006b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 006e: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a3 + 0x27);  /* 0071 */
  ST8(a2 + 0xc, a8);  /* 0074 */
  __asm__ volatile("" ::: "memory");  /* 0077: memw */
  a8 = LD8U(a3 + 0x34);  /* 007a */
  a3 = LD8U(a3 + 0x3b);  /* 007d */
  ST8(a2 + 0xd, a8);  /* 0080 */
  ST8(a2 + 0xe, a3);  /* 0083 */
  __asm__ volatile("" ::: "memory");  /* 0086: memw */
  __asm__ volatile("" ::: "memory");  /* 0089: memw */
  return a2;  /* 008c: retw.n */
}


/* mesh_get_vnd_roots_len @ mesh_quick.o 00000014 size 125B bind GLOBAL
 * Calls: is_my_ie_encrypted, roots_type2str, wifi_log | Data refs: .bss.wifi_vnd_ext_mesh_roots, .rodata_wlog_error.5
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=5); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_get_vnd_roots_len(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0014: entry a1, 64 (frame 64 bytes) */
  a8 = (u32)&is_my_ie_encrypted;  /* 0017: l32r -> func addr */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6, a7);  /* 001a: callx a8 via reloc-expand */
  a4 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 001d: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a2 = 0;  /* 0020 */
  a6 = a10;  /* 0022 */
  a3 = a2;  /* 0024 */
  a7 = a4;  /* 0026: mov */
  a5 = 247;  /* 0029 */
  L_002c: a8 = a3 + (a7 << 3);  /* 002c */
  a8 = LD32(a8 + 0x0);  /* 002f */
  if (((a8 >> 0) & 1) == 0) goto L_0088;  /* 0031: bbci a8, 0, 88 <mesh_get_vnd_roots_len+0x74> */
  L_0034: a11 = LD8U(a4 + 0x1);  /* 0034 */
  a8 = a11 + (a11 << 1);  /* 0037 */
  a8 = a8 << 2;  /* 003a */
  a12 = a8 + (13);  /* 003d */
  a9 = a12;  /* 003f */
  if (a6 == 0) goto L_004d;  /* 0041: beqz.n a6, 4d <mesh_get_vnd_roots_len+0x39> */
  L_0043: a9 = -16;  /* 0043 */
  a8 = a8 + (21);  /* 0045 */
  a8 = a8 & a9;  /* 0048 */
  a9 = a8 + (7);  /* 004b */
  L_004d: if (a5 >= a12) goto L_0086;  /* 004d: bgeu a5, a12, 86 <mesh_get_vnd_roots_len+0x72> */
  L_0050: a10 = a3;  /* 0050 */
  ST32(a1 + 0x18, a9);  /* 0052 */
  ST32(a1 + 0x10, a11);  /* 0054 */
  ST32(a1 + 0x14, a12);  /* 0056 */
  __asm__ volatile("" ::: "memory");  /* 0059: memw */
  a8 = (u32)&roots_type2str;  /* 005c: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4, a5, a6, a7);  /* 005f: callx a8 via reloc-expand */
  a15 = a10;  /* 0062 */
  a14 = 0x7ac;  /* 0064 */
  a12 = LD32(a1 + 0x14);  /* 0067 */
  a11 = LD32(a1 + 0x10);  /* 0069 */
  ST32(a1 + 0x4, a12);  /* 006b */
  a12 = 1;  /* 006d */
  a10 = a12;  /* 006f */
  a13 = (u32)(RODATA__rodata_wlog_error_5 + 0x0);  /* 0071: l32r -> .rodata_wlog_error.5 */
  ST32(a1 + 0x0, a11);  /* 0074 */
  a11 = a12 << 21;  /* 0076 */
  ST32(a1 + 0x8, a5);  /* 0079 */
  __asm__ volatile("" ::: "memory");  /* 007b: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 007e: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 0081: callx a8 via reloc-expand */
  a9 = LD32(a1 + 0x18);  /* 0084 */
  L_0086: a2 = a2 + a9;  /* 0086 */
  L_0088: a3 = a3 + (1);  /* 0088 */
  a4 = a4 + (8);  /* 008a */
  if (a3 != 4) goto L_002c;  /* 008c: bnei a3, 4, 2c <mesh_get_vnd_roots_len+0x18> */
  L_008f: return a2;  /* 008f: retw.n */
}


/* mesh_init_cb @ mesh_quick.o 00000038 size 115B bind GLOBAL
 * Calls: memset, esp_mesh_quick_funcs_init | Data refs: .bss.s_mesh_parent_candidate, .bss.s_mesh_roots_ie_life, .bss.wifi_vnd_ext_mesh_roots, .bss.s_mesh_conflict_roots, .bss.s_ps_parent_duty, .bss.s_ps_device_duty, .bss.s_ps_parent_duty_type, .bss.esp_mesh_remain_nwk_duty, .bss.s_ps_device_duty_type
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=11); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_init_cb(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0038: entry a1, 32 (frame 32 bytes) */
  a10 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 003b: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a12 = 184;  /* 003e */
  a11 = 0;  /* 0041 */
  a8 = (u32)&memset + 0x0;  /* 0043: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0046: callx a8 (libc, via reloc-expand) */
  a2 = 32;  /* 0049 */
  a10 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 004b: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a12 = a2;  /* 004e */
  a11 = 0;  /* 0050 */
  a8 = (u32)&memset + 0x0;  /* 0052: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0055: callx a8 (libc, via reloc-expand) */
  a12 = a2;  /* 0058 */
  a10 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 005a: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a11 = 0;  /* 005d */
  a8 = (u32)&memset + 0x0;  /* 005f: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0062: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0065 */
  a8 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0067: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  ST32(a8 + 0x0, a2);  /* 006a */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  a8 = (u32)&esp_mesh_quick_funcs_init;  /* 006f: l32r -> func addr */
  a2 = esp_mesh_quick_funcs_init(a2, a3, a4, a5, a6, a7);  /* 0072: callx a8 via reloc-expand */
  a12 = 15;  /* 0075 */
  a11 = a2;  /* 0077 */
  a8 = (u32)&LOCAL__bss_s_ps_parent_duty + 0x0;  /* 0079: l32r -> .bss.s_ps_parent_duty (same-object static) */
  ST8(a8 + 0x0, a2);  /* 007c */
  __asm__ volatile("" ::: "memory");  /* 007f: memw */
  a8 = (u32)&LOCAL__bss_s_ps_device_duty + 0x0;  /* 0082: l32r -> .bss.s_ps_device_duty (same-object static) */
  ST8(a8 + 0x0, a2);  /* 0085 */
  __asm__ volatile("" ::: "memory");  /* 0088: memw */
  a8 = (u32)&LOCAL__bss_s_ps_parent_duty_type + 0x0;  /* 008b: l32r -> .bss.s_ps_parent_duty_type (same-object static) */
  a10 = (u32)&LOCAL__bss_esp_mesh_remain_nwk_duty + 0x0;  /* 008e: l32r -> .bss.esp_mesh_remain_nwk_duty (same-object static) */
  ST8(a8 + 0x0, a2);  /* 0091 */
  __asm__ volatile("" ::: "memory");  /* 0094: memw */
  a8 = (u32)&LOCAL__bss_s_ps_device_duty_type + 0x0;  /* 0097: l32r -> .bss.s_ps_device_duty_type (same-object static) */
  ST8(a8 + 0x0, a2);  /* 009a */
  __asm__ volatile("" ::: "memory");  /* 009d: memw */
  __asm__ volatile("" ::: "memory");  /* 00a0: memw */
  a8 = (u32)&memset + 0x0;  /* 00a3: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00a6: callx a8 (libc, via reloc-expand) */
  return a2;  /* 00a9: retw.n */
}


/* mesh_is_ie_ignored @ mesh_quick.o 00000014 size 115B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp | Data refs: esp_mesh_appie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_is_ie_ignored(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0014: entry a1, 48 (frame 48 bytes) */
  a2 = 0;  /* 0017 */
  ST8(a1 + 0x7, a2);  /* 0019 */
  a2 = -91;  /* 001c */
  a4 = 0;  /* 001f */
  a12 = a1 + (7);  /* 0021 */
  a11 = 14;  /* 0023 */
  ST8(a1 + 0x6, a2);  /* 0025 */
  __asm__ volatile("" ::: "memory");  /* 0028: memw */
  a2 = (u32)&esp_mesh_appie + 0x0;  /* 002b: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 002e */
  a2 = a2 + (2);  /* 0030 */
  a10 = a2;  /* 0032 */
  ST32(a1 + 0x0, a4);  /* 0034 */
  ST16(a1 + 0x4, a4);  /* 0036 */
  __asm__ volatile("" ::: "memory");  /* 0039: memw */
  __asm__ volatile("" ::: "memory");  /* 003c: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 003f: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 0042: callx a8 via reloc-expand */
  a11 = a4;  /* 0045 */
  a12 = a1 + (6);  /* 0047 */
  a10 = a2;  /* 0049 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 004b: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 004e: callx a8 via reloc-expand */
  a4 = LD8U(a1 + 0x6);  /* 0051 */
  if (a4 != 1) goto L_0062;  /* 0054: bnei a4, 1, 62 <mesh_is_ie_ignored+0x4e> */
  L_0057: a4 = LD8U(a1 + 0x7);  /* 0057 */
  if (((a4 >> 6) & 1) == 0) goto L_0062;  /* 005a: bbci a4, 6, 62 <mesh_is_ie_ignored+0x4e> */
  L_005d: a2 = 1;  /* 005d */
  goto L_0085;  /* 005f: j */
  L_0062: a12 = a1;  /* 0062 */
  a11 = 1;  /* 0064 */
  a10 = a2;  /* 0066 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0068: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 006b: callx a8 via reloc-expand */
  a12 = 6;  /* 006e */
  a11 = a1;  /* 0070: mov */
  a10 = a3 + (8);  /* 0073 */
  a8 = (u32)&memcmp + 0x0;  /* 0076: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0079: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_005d;  /* 007c: bnez a10, 5d <mesh_is_ie_ignored+0x49> */
  L_007f: a2 = LD8U(a3 + 0x1e);  /* 007f */
  a2 = (a2 >> 1) & 0x7f;  /* 0082: extui width 7 */
  L_0085: return a2;  /* 0085: retw.n */
}


/* mesh_is_new_found_conflict_root @ mesh_quick.o 00000008 size 74B bind GLOBAL
 * Calls: esp_mesh_find_conflict_root, esp_mesh_add_conflict_root | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=2); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_is_new_found_conflict_root(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a6, a7, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a9 = 0;  /* 000b */
  a6 = 1;  /* 000d */
  a8 = a9;  /* 000f */
  if (a2 == 0) a8 = a6;  /* 0011 */
  a7 = a2;  /* 0014 */
  a2 = a9;  /* 0016 */
  if (a3 == 0) a2 = a6;  /* 0018 */
  a2 = a8 | a2;  /* 001b */
  if (a2 != a9) goto L_004e;  /* 001e: bne a2, a9, 4e <mesh_is_new_found_conflict_root+0x46> */
  L_0021: a12 = a5;  /* 0021 */
  a11 = a4;  /* 0023 */
  a10 = a7 + (4);  /* 0025 */
  a8 = (u32)&esp_mesh_find_conflict_root;  /* 0027: l32r -> func addr */
  a2 = esp_mesh_find_conflict_root(a2, a3, a4, a5);  /* 002a: callx a8 via reloc-expand */
  if (a10 != -1) goto L_0046;  /* 002d: bnei a10, -1, 46 <mesh_is_new_found_conflict_root+0x3e> */
  L_0030: a13 = a5;  /* 0030 */
  a12 = a4;  /* 0032 */
  a11 = a3;  /* 0034: mov */
  a10 = a7;  /* 0037: mov */
  a8 = (u32)&esp_mesh_add_conflict_root;  /* 003a: l32r -> func addr */
  a2 = esp_mesh_add_conflict_root(a2, a3, a4, a5);  /* 003d: callx a8 via reloc-expand */
  if (a10 == 0) a2 = a6;  /* 0040 */
  goto L_0050;  /* 0043: j */
  L_0046: ST32(a3 + 0x0, a10);  /* 0046 */
  __asm__ volatile("" ::: "memory");  /* 0048: memw */
  goto L_0050;  /* 004b: j */
  L_004e: a2 = a9;  /* 004e */
  L_0050: return a2;  /* 0050: retw.n */
}


/* mesh_is_new_root_found @ mesh_quick.o 00000050 size 344B bind GLOBAL
 * Calls: wifi_get_macaddr, ieee80211_mesh_quick_get, memcmp, ieee80211_is_mesh_roots_announce, ieee80211_is_mesh_roots_yield, ieee80211_is_mesh_roots_fixed, ieee80211_is_mesh_roots_gone | Data refs: .rodata, esp_mesh_appie
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=7, refs=9); reloc-direct=7, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_is_new_root_found(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0050: entry a1, 48 (frame 48 bytes) */
  a6 = 0;  /* 0053 */
  a8 = 1;  /* 0055 */
  a5 = (a2 >> 8) & 0x1;  /* 0057: extui width 1 */
  a9 = a6;  /* 005a */
  a2 = a6;  /* 005c */
  if (a3 == 0) a2 = a8;  /* 005e */
  if (a4 == 0) a9 = a8;  /* 0061 */
  a2 = a2 | a9;  /* 0064 */
  if (a5 >= 4u) goto L_006d;  /* 0067: bgeui a5, 4, 6d <mesh_is_new_root_found+0x1d> */
  L_006a: a8 = a6;  /* 006a: mov */
  L_006d: a2 = a2 | a8;  /* 006d */
  a2 = (a2 >> 8) & 0x1;  /* 0070: extui width 1 */
  if (a2 != 0) goto L_01a4;  /* 0073: bnez a2, 1a4 <mesh_is_new_root_found+0x154> */
  L_0076: a6 = (u32)(RODATA__rodata + 0x0);  /* 0076: l32r -> .rodata */
  a11 = a1;  /* 0079 */
  a10 = 1;  /* 007b */
  a8 = LD8U(a6 + 0x0);  /* 007d */
  a6 = LD8U(a6 + 0x1);  /* 0080 */
  ST8(a1 + 0x6, a8);  /* 0083 */
  ST8(a1 + 0x7, a6);  /* 0086 */
  ST16(a1 + 0x8, a2);  /* 0089 */
  ST16(a1 + 0xa, a2);  /* 008c */
  ST32(a1 + 0x0, a2);  /* 008f */
  ST16(a1 + 0x4, a2);  /* 0092 */
  __asm__ volatile("" ::: "memory");  /* 0095: memw */
  __asm__ volatile("" ::: "memory");  /* 0098: memw */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 009b: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6, a7);  /* 009e: callx a8 via reloc-expand */
  if (a5 == 1) goto L_0111;  /* 00a1: beqi a5, 1, 111 <mesh_is_new_root_found+0xc1> */
  L_00a4: if (a5 != 3) goto L_00aa;  /* 00a4: bnei a5, 3, aa <mesh_is_new_root_found+0x5a> */
  L_00a7: goto L_0175;  /* 00a7: j */
  L_00aa: if (a5 != 0) goto L_01a6;  /* 00aa: bnez a5, 1a6 <mesh_is_new_root_found+0x156> */
  L_00ad: a4 = (u32)&esp_mesh_appie + 0x0;  /* 00ad: l32r -> global */
  a12 = a1 + (6);  /* 00b0 */
  a11 = 15;  /* 00b2 */
  a10 = LD32(a4 + 0x0);  /* 00b4 */
  a4 = a3 + (4);  /* 00b6 */
  a10 = a10 + (2);  /* 00b8 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00bb: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 00be: callx a8 via reloc-expand */
  a12 = 6;  /* 00c1 */
  a11 = a1 + a12;  /* 00c3 */
  a10 = a4;  /* 00c5 */
  a8 = (u32)&memcmp + 0x0;  /* 00c7: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00ca: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01a6;  /* 00cd: beqz a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_00d0: a12 = 6;  /* 00d0 */
  a11 = a1;  /* 00d2 */
  a10 = a4;  /* 00d4 */
  a8 = (u32)&memcmp + 0x0;  /* 00d6: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00d9: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01a6;  /* 00dc: beqz a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_00df: a11 = a2;  /* 00df */
  a10 = a3;  /* 00e1 */
  a8 = (u32)&ieee80211_is_mesh_roots_announce;  /* 00e3: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_announce(a2, a3, a4, a5, a6, a7);  /* 00e6: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a6;  /* 00e9: bnez a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_00ec: a10 = a4;  /* 00ec: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_yield;  /* 00ef: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_yield(a2, a3, a4, a5, a6, a7);  /* 00f2: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a6;  /* 00f5: bnez a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_00f8: a10 = a4;  /* 00f8: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_fixed;  /* 00fb: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_fixed(a2, a3, a4, a5, a6, a7);  /* 00fe: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a6;  /* 0101: bnez a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_0104: a10 = a4;  /* 0104 */
  a8 = (u32)&ieee80211_is_mesh_roots_gone;  /* 0106: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_gone(a2, a3, a4, a5, a6, a7);  /* 0109: callx a8 via reloc-expand */
  goto L_0198;  /* 010c: j */
  L_0111: a6 = a3 + (16);  /* 0111 */
  a12 = 6;  /* 0114 */
  a11 = a6;  /* 0116 */
  a10 = a1;  /* 0118 */
  a8 = (u32)&memcmp + 0x0;  /* 011a: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 011d: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01a6;  /* 0120: beqz a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_0123: a3 = a3 + (4);  /* 0123 */
  a12 = 6;  /* 0125 */
  a11 = a3;  /* 0127 */
  a10 = a4;  /* 0129 */
  a8 = (u32)&memcmp + 0x0;  /* 012b: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 012e: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01a6;  /* 0131: beqz a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_0134: a10 = a3;  /* 0134: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_yield;  /* 0137: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_yield(a2, a3, a4, a5, a6, a7);  /* 013a: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a6;  /* 013d: bnez a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_0140: a10 = a3;  /* 0140: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_fixed;  /* 0143: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_fixed(a2, a3, a4, a5, a6, a7);  /* 0146: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a6;  /* 0149: bnez a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_014c: a10 = a6;  /* 014c: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_fixed;  /* 014f: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_fixed(a2, a3, a4, a5, a6, a7);  /* 0152: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a6;  /* 0155: bnez a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_0158: a10 = a3;  /* 0158: mov */
  a8 = (u32)&ieee80211_is_mesh_roots_gone;  /* 015b: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_gone(a2, a3, a4, a5, a6, a7);  /* 015e: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a6;  /* 0161: bnez a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_0164: a10 = a6;  /* 0164 */
  a8 = (u32)&ieee80211_is_mesh_roots_gone;  /* 0166: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_gone(a2, a3, a4, a5, a6, a7);  /* 0169: callx a8 via reloc-expand */
  a10 = a10 ^ a5;  /* 016c */
  a2 = (a10 >> 8) & 0x1;  /* 016f: extui width 1 */
  goto L_01a6;  /* 0172: j */
  L_0175: a3 = a3 + (4);  /* 0175 */
  a12 = 6;  /* 0177 */
  a11 = a1;  /* 0179: mov */
  a10 = a3;  /* 017c */
  a8 = (u32)&memcmp + 0x0;  /* 017e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0181: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01a6;  /* 0184: beqz.n a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_0186: a10 = a3;  /* 0186 */
  a8 = (u32)&ieee80211_is_mesh_roots_gone;  /* 0188: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_gone(a2, a3, a4, a5, a6, a7);  /* 018b: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a6;  /* 018e: bnez.n a10, 1a6 <mesh_is_new_root_found+0x156> */
  L_0190: a10 = a3;  /* 0190 */
  a8 = (u32)&ieee80211_is_mesh_roots_fixed;  /* 0192: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_fixed(a2, a3, a4, a5, a6, a7);  /* 0195: callx a8 via reloc-expand */
  L_0198: a2 = 1;  /* 0198 */
  a2 = a10 ^ a2;  /* 019a */
  a2 = (a2 >> 8) & 0x1;  /* 019d: extui width 1 */
  goto L_01a6;  /* 01a0: j */
  L_01a4: a2 = 0;  /* 01a4 */
  L_01a6: return a2;  /* 01a6: retw.n */
}


/* mesh_is_new_root_invalid @ mesh_quick.o 0000000c size 132B bind GLOBAL
 * Calls: ieee80211_is_mesh_roots_valid | Data refs: .bss.s_mesh_roots_ie_life
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_is_new_root_invalid(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 000f: extui width 1 */
  a3 = (a3 >> 8) & 0x1;  /* 0012: extui width 1 */
  if (a2 == 2) goto L_0049;  /* 0015: beqi a2, 2, 49 <mesh_is_new_root_invalid+0x3d> */
  L_0018: if (a2 >= 3u) goto L_0020;  /* 0018: bgeui a2, 3, 20 <mesh_is_new_root_invalid+0x14> */
  L_001b: if (a2 != 0) goto L_0028;  /* 001b: bnez.n a2, 28 <mesh_is_new_root_invalid+0x1c> */
  L_001d: goto L_0084;  /* 001d: j */
  L_0020: if (a2 == 3) goto L_0058;  /* 0020: beqi a2, 3, 58 <mesh_is_new_root_invalid+0x4c> */
  L_0023: goto L_008c;  /* 0023: j */
  L_0028: a2 = LD8U(a4 + 0x1);  /* 0028 */
  a11 = a4 + (4);  /* 002b */
  a2 = a2 << 8;  /* 002d */
  a10 = 1;  /* 0030 */
  a12 = LD8U(a4 + 0x0);  /* 0032 */
  a12 = a2 | a12;  /* 0035 */
  a8 = (u32)&ieee80211_is_mesh_roots_valid;  /* 0038: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_valid(a2, a3, a4, a5, a6, a7);  /* 003b: callx a8 via reloc-expand */
  a2 = 1;  /* 003e */
  a2 = a10 ^ a2;  /* 0040 */
  a2 = (a2 >> 8) & 0x1;  /* 0043: extui width 1 */
  goto L_008e;  /* 0046: j */
  L_0049: a5 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 0049: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a5 = LD8U(a5 + 0x0);  /* 004c */
  if (a5 == 0) goto L_0058;  /* 004f: beqz.n a5, 58 <mesh_is_new_root_invalid+0x4c> */
  L_0051: a2 = 1;  /* 0051 */
  goto L_008e;  /* 0053: j */
  L_0058: a5 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 0058: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a5 = LD8U(a5 + 0x10);  /* 005b */
  if (a5 != 0) goto L_0051;  /* 005e: bnez a5, 51 <mesh_is_new_root_invalid+0x45> */
  L_0061: goto L_0084;  /* 0061: j */
  L_0064: a8 = LD8U(a4 + 0x1);  /* 0064 */
  a11 = a4 + (4);  /* 0067 */
  a8 = a8 << 8;  /* 0069 */
  a10 = a2;  /* 006c */
  a12 = LD8U(a4 + 0x0);  /* 006e */
  a4 = a4 + (12);  /* 0071 */
  a12 = a8 | a12;  /* 0073 */
  a8 = (u32)&ieee80211_is_mesh_roots_valid;  /* 0076: l32r -> func addr */
  a2 = ieee80211_is_mesh_roots_valid(a2, a3, a4, a5, a6, a7);  /* 0079: callx a8 via reloc-expand */
  if (a10 != 0) goto L_008c;  /* 007c: bnez.n a10, 8c <mesh_is_new_root_invalid+0x80> */
  L_007e: a5 = a5 + (1);  /* 007e */
  goto L_0086;  /* 0080: j */
  L_0084: a5 = 0;  /* 0084 */
  L_0086: if ((i32)a5 < (i32)a3) goto L_0064;  /* 0086: blt a5, a3, 64 <mesh_is_new_root_invalid+0x58> */
  L_0089: goto L_0051;  /* 0089: j */
  L_008c: a2 = 0;  /* 008c */
  L_008e: return a2;  /* 008e: retw.n */
}


/* mesh_nwk_duty_check_allowed @ mesh_quick.o 00000028 size 445B bind GLOBAL
 * Calls: ieee80211_sta_is_connected, __moddi3, __divdi3 | indirect[1]: mem[a8+0x110] | Data refs: esp_mesh_ps_duty, g_mesh_is_root, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=6); reloc-direct=3, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_nwk_duty_check_allowed(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8, a9;
  /* 0028: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&esp_mesh_ps_duty + 0x0;  /* 002b: l32r -> global */
  a4 = a2;  /* 002e */
  a2 = 1;  /* 0030 */
  ST8(a3 + 0x1a, a2);  /* 0032 */
  __asm__ volatile("" ::: "memory");  /* 0035: memw */
  __asm__ volatile("" ::: "memory");  /* 0038: memw */
  a8 = (u32)&ieee80211_sta_is_connected + 0x0;  /* 003b: l32r -> global */
  a2 = ieee80211_sta_is_connected(a2, a3, a4, a5, a6, a7);  /* 003e: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0046;  /* 0041: bnez.n a10, 46 <mesh_nwk_duty_check_allowed+0x1e> */
  L_0043: goto L_0081;  /* 0043: j */
  L_0046: a5 = LD8U(a4 + 0x4);  /* 0046 */
  a5 = a5 << 8;  /* 0049 */
  a2 = LD8U(a4 + 0x3);  /* 004c */
  a5 = a5 | a2;  /* 004f */
  a2 = LD8U(a4 + 0x5);  /* 0052 */
  a2 = a2 << 16;  /* 0055 */
  a2 = a2 | a5;  /* 0058 */
  a5 = LD8U(a4 + 0x6);  /* 005b */
  a5 = a5 << 24;  /* 005e */
  a5 = a5 | a2;  /* 0061 */
  a8 = (u32)&g_mesh_is_root + 0x0;  /* 0064: l32r -> global */
  if (a5 != -1) goto L_008d;  /* 0067: bnei a5, -1, 8d <mesh_nwk_duty_check_allowed+0x65> */
  L_006a: a2 = 0x102;  /* 006a */
  __asm__ volatile("" ::: "memory");  /* 006d: memw */
  a6 = LD8U(a8 + 0x0);  /* 0070 */
  a6 = (a6 >> 8) & 0x1;  /* 0073: extui width 1 */
  if (a6 == 0) goto L_01e3;  /* 0076: beqz a6, 1e3 <mesh_nwk_duty_check_allowed+0x1bb> */
  L_0079: a2 = LD8U(a3 + 0x0);  /* 0079 */
  if (((a2 >> 7) & 1) != 0) goto L_008d;  /* 007c: bbsi a2, 7, 8d <mesh_nwk_duty_check_allowed+0x65> */
  L_007f: a2 = 2;  /* 007f */
  L_0081: ST8(a3 + 0x19, a2);  /* 0081 */
  __asm__ volatile("" ::: "memory");  /* 0084: memw */
  __asm__ volatile("" ::: "memory");  /* 0087: memw */
  goto L_01e1;  /* 008a: j */
  L_008d: __asm__ volatile("" ::: "memory");  /* 008d: memw */
  a2 = LD8U(a8 + 0x0);  /* 0090 */
  a2 = (a2 >> 8) & 0x1;  /* 0093: extui width 1 */
  if (a2 != 0) goto L_01e1;  /* 0096: bnez a2, 1e1 <mesh_nwk_duty_check_allowed+0x1b9> */
  L_0099: a2 = LD8U(a3 + 0x0);  /* 0099 */
  a2 = a2 >> 7;  /* 009c */
  if (a2 == 0) goto L_00aa;  /* 009f: beqz.n a2, aa <mesh_nwk_duty_check_allowed+0x82> */
  L_00a1: a2 = (i32)a5 >> 31;  /* 00a1 */
  a2 = a2 - a5;  /* 00a4: sub */
  if ((i32)a2 < 0) goto L_01e1;  /* 00a7: bltz a2, 1e1 <mesh_nwk_duty_check_allowed+0x1b9> */
  L_00aa: a2 = LD8U(a3 + 0x4);  /* 00aa */
  a10 = -1;  /* 00ad */
  a2 = a2 << 8;  /* 00b0 */
  a5 = LD8U(a3 + 0x3);  /* 00b3 */
  a2 = a2 | a5;  /* 00b6 */
  a5 = LD8U(a3 + 0x5);  /* 00b9 */
  a5 = a5 << 16;  /* 00bc */
  a5 = a5 | a2;  /* 00bf */
  a2 = LD8U(a3 + 0x6);  /* 00c2 */
  a2 = a2 << 24;  /* 00c5 */
  a2 = a2 | a5;  /* 00c8 */
  if ((i32)a2 >= 1) goto L_00d1;  /* 00cb: bgei a2, 1, d1 <mesh_nwk_duty_check_allowed+0xa9> */
  L_00ce: goto L_0172;  /* 00ce: j */
  L_00d1: a5 = LD8U(a3 + 0x12);  /* 00d1 */
  a5 = a5 << 8;  /* 00d4 */
  a6 = LD8U(a3 + 0x11);  /* 00d7 */
  a5 = a5 | a6;  /* 00da */
  a6 = LD8U(a3 + 0x13);  /* 00dd */
  a6 = a6 << 16;  /* 00e0 */
  a6 = a6 | a5;  /* 00e3 */
  a5 = LD8U(a3 + 0x14);  /* 00e6 */
  a5 = a5 << 24;  /* 00e9 */
  a5 = a5 | a6;  /* 00ec */
  a6 = LD8U(a3 + 0x16);  /* 00ef */
  a6 = a6 << 8;  /* 00f2 */
  a8 = LD8U(a3 + 0x15);  /* 00f5 */
  a6 = a6 | a8;  /* 00f8 */
  a8 = LD8U(a3 + 0x17);  /* 00fb */
  a8 = a8 << 16;  /* 00fe */
  a8 = a8 | a6;  /* 0101 */
  a6 = LD8U(a3 + 0x18);  /* 0104 */
  a6 = a6 << 24;  /* 0107 */
  a6 = a6 | a8;  /* 010a */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 010d: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0110 */
  a10 = LD32(a8 + 0x110);  /* 0113 */
  /* 0116: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a5 = a10 - a5;  /* 0119: sub */
  a9 = 0x03938700u;  /* 011c: l32r = 60000000 */
  a8 = a2 * a9;  /* 011f */
  a2 = (u32)(((u64)a2 * a9) >> 32);  /* 0122: mulsh */
  a9 = 1;  /* 0125 */
  if (a10 < a5) goto L_012c;  /* 0127: bltu a10, a5, 12c <mesh_nwk_duty_check_allowed+0x104> */
  L_012a: a9 = 0;  /* 012a */
  L_012c: a11 = a11 - a6;  /* 012c: sub */
  a5 = a8 - a5;  /* 012f: sub */
  a11 = a11 - a9;  /* 0132: sub */
  a6 = 1;  /* 0135 */
  if (a8 < a5) goto L_013c;  /* 0137: bltu a8, a5, 13c <mesh_nwk_duty_check_allowed+0x114> */
  L_013a: a6 = 0;  /* 013a */
  L_013c: a2 = a2 - a11;  /* 013c: sub */
  a2 = a2 - a6;  /* 013f: sub */
  a12 = 0x03938700u;  /* 0142: l32r = 60000000 */
  a13 = 0;  /* 0145 */
  a10 = a5;  /* 0147 */
  a11 = a2;  /* 0149 */
  a8 = (u32)&__moddi3 + 0x0;  /* 014b: l32r -> global */
  a2 = __moddi3(a2, a3, a4, a5, a6, a7);  /* 014e: callx a8 via reloc-expand */
  a6 = 1;  /* 0151 */
  if ((i32)a11 >= (i32)a6) goto L_0160;  /* 0153: bge a11, a6, 160 <mesh_nwk_duty_check_allowed+0x138> */
  L_0156: if (a11 != 0) goto L_015e;  /* 0156: bnez.n a11, 15e <mesh_nwk_duty_check_allowed+0x136> */
  L_0158: a8 = 0x01c9c380u;  /* 0158: l32r = 30000000 */
  if (a8 < a10) goto L_0160;  /* 015b: bltu a8, a10, 160 <mesh_nwk_duty_check_allowed+0x138> */
  L_015e: a6 = 0;  /* 015e */
  L_0160: a13 = 0;  /* 0160 */
  a12 = 0x03938700u;  /* 0162: l32r = 60000000 */
  a10 = a5;  /* 0165: mov */
  a11 = a2;  /* 0168 */
  a8 = (u32)&__divdi3 + 0x0;  /* 016a: l32r -> global */
  a2 = __divdi3(a2, a3, a4, a5, a6, a7);  /* 016d: callx a8 via reloc-expand */
  a10 = a6 + a10;  /* 0170 */
  L_0172: a5 = LD8U(a4 + 0x2);  /* 0172 */
  a6 = LD8U(a3 + 0x2);  /* 0175 */
  if (a5 == a6) goto L_01b1;  /* 0178: beq a5, a6, 1b1 <mesh_nwk_duty_check_allowed+0x189> */
  L_017b: a2 = LD8U(a3 + 0x6);  /* 017b */
  a2 = a2 >> 7;  /* 017e */
  if (a2 != 0) goto L_01e1;  /* 0181: bnez a2, 1e1 <mesh_nwk_duty_check_allowed+0x1b9> */
  L_0184: if (a6 < a5) goto L_01e1;  /* 0184: bltu a6, a5, 1e1 <mesh_nwk_duty_check_allowed+0x1b9> */
  L_0187: a3 = LD8U(a4 + 0x4);  /* 0187 */
  a3 = a3 << 8;  /* 018a */
  a2 = LD8U(a4 + 0x3);  /* 018d */
  a3 = a3 | a2;  /* 0190 */
  a2 = LD8U(a4 + 0x5);  /* 0193 */
  a2 = a2 << 16;  /* 0196 */
  a2 = a2 | a3;  /* 0199 */
  a3 = LD8U(a4 + 0x6);  /* 019c */
  a3 = a3 << 24;  /* 019f */
  a3 = a3 | a2;  /* 01a2 */
  a2 = 0x00004036u;  /* 01a5: l32r = 16438 */
  if ((i32)a10 >= (i32)a3) goto L_01e3;  /* 01a8: bge a10, a3, 1e3 <mesh_nwk_duty_check_allowed+0x1bb> */
  L_01ab: a2 = 0x00004037u;  /* 01ab: l32r = 16439 */
  goto L_01e3;  /* 01ae: j */
  L_01b1: a5 = LD8U(a4 + 0x4);  /* 01b1 */
  a5 = a5 << 8;  /* 01b4 */
  a2 = LD8U(a4 + 0x3);  /* 01b7 */
  a5 = a5 | a2;  /* 01ba */
  a2 = LD8U(a4 + 0x5);  /* 01bd */
  a2 = a2 << 16;  /* 01c0 */
  a2 = a2 | a5;  /* 01c3 */
  a5 = LD8U(a4 + 0x6);  /* 01c6 */
  a5 = a5 << 24;  /* 01c9 */
  a5 = a5 | a2;  /* 01cc */
  if ((i32)a10 < (i32)a5) goto L_01e1;  /* 01cf: blt a10, a5, 1e1 <mesh_nwk_duty_check_allowed+0x1b9> */
  L_01d2: a2 = 0x00004036u;  /* 01d2: l32r = 16438 */
  if (a10 != a5) goto L_01e3;  /* 01d5: bne a10, a5, 1e3 <mesh_nwk_duty_check_allowed+0x1bb> */
  L_01d8: a4 = LD8U(a4 + 0xf);  /* 01d8 */
  a3 = LD8U(a3 + 0xf);  /* 01db */
  if (a4 == a3) goto L_01e3;  /* 01de: beq a4, a3, 1e3 <mesh_nwk_duty_check_allowed+0x1bb> */
  L_01e1: a2 = 0;  /* 01e1 */
  L_01e3: return a2;  /* 01e3: retw.n */
}


/* mesh_nwk_duty_check_duration_expire @ mesh_quick.o 00000008 size 67B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x110] | Data refs: g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_nwk_duty_check_duration_expire(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a3 = 0;  /* 000b */
  if ((i32)a2 < (i32)a3) goto L_0047;  /* 000e: blt a2, a3, 47 <mesh_nwk_duty_check_duration_expire+0x3f> */
  L_0011: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0011: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0014 */
  a10 = LD32(a8 + 0x110);  /* 0016 */
  /* 0019: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a4 = a10 - a4;  /* 001c: sub */
  a8 = 1;  /* 001f */
  if (a10 < a4) goto L_0028;  /* 0022: bltu a10, a4, 28 <mesh_nwk_duty_check_duration_expire+0x20> */
  L_0025: a8 = a3;  /* 0025: mov */
  L_0028: a3 = 0x03938700u;  /* 0028: l32r = 60000000 */
  a11 = a11 - a5;  /* 002b: sub */
  a11 = a11 - a8;  /* 002e: sub */
  a8 = a2 * a3;  /* 0031 */
  a2 = (u32)(((u64)a2 * a3) >> 32);  /* 0034: mulsh */
  a3 = 1;  /* 0037 */
  if ((i32)a11 < (i32)a2) goto L_0042;  /* 0039: blt a11, a2, 42 <mesh_nwk_duty_check_duration_expire+0x3a> */
  L_003c: if (a2 != a11) goto L_0044;  /* 003c: bne a2, a11, 44 <mesh_nwk_duty_check_duration_expire+0x3c> */
  L_003f: if (a4 >= a8) goto L_0044;  /* 003f: bgeu a4, a8, 44 <mesh_nwk_duty_check_duration_expire+0x3c> */
  L_0042: a3 = 0;  /* 0042 */
  L_0044: a3 = (a3 >> 8) & 0x1;  /* 0044: extui width 1 */
  L_0047: a2 = a3;  /* 0047 */
  return a2;  /* 0049: retw.n */
}


/* mesh_nwk_duty_clr_master_identity @ mesh_quick.o 00000018 size 284B bind GLOBAL
 * Calls: dutytype2str, wifi_log, mesh_nwk_duty_post_event | indirect[1]: mem[a3+0x110] | Data refs: g_osi_funcs_p, esp_mesh_ps_duty, .rodata_wlog_info.20
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=6); reloc-direct=3, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_nwk_duty_clr_master_identity(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0018: entry a1, 96 (frame 96 bytes) */
  a3 = LD8U(a2 + 0x0);  /* 001b */
  a4 = -2;  /* 001e */
  a3 = (a3 >> 7) & 0x1;  /* 0020: extui width 1 */
  a5 = -4;  /* 0023 */
  ST8(a2 + 0x0, a3);  /* 0025 */
  __asm__ volatile("" ::: "memory");  /* 0028: memw */
  a3 = LD8U(a2 + 0xe);  /* 002b */
  ST8(a2 + 0x2, a3);  /* 002e */
  __asm__ volatile("" ::: "memory");  /* 0031: memw */
  a3 = LD8U(a2 + 0xd);  /* 0034 */
  a3 = a3 + (1);  /* 0037 */
  ST8(a2 + 0xd, a3);  /* 0039 */
  a3 = 0;  /* 003c */
  ST8(a2 + 0xf, a3);  /* 003f */
  __asm__ volatile("" ::: "memory");  /* 0042: memw */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0045: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0048 */
  ST8(a2 + 0x3, a4);  /* 004a */
  __asm__ volatile("" ::: "memory");  /* 004d: memw */
  a4 = -1;  /* 0050 */
  a10 = LD32(a3 + 0x110);  /* 0053 */
  ST8(a2 + 0x4, a4);  /* 0056 */
  ST8(a2 + 0x5, a4);  /* 0059 */
  ST8(a2 + 0x6, a4);  /* 005c */
  __asm__ volatile("" ::: "memory");  /* 005f: memw */
  __asm__ volatile("" ::: "memory");  /* 0062: memw */
  /* 0065: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  a3 = (a10 >> 8) & 0x1ff;  /* 0068: extui width 9 */
  ST8(a2 + 0x12, a3);  /* 006b */
  a3 = (a10 >> 8) & 0x1ffff;  /* 006e: extui width 17 */
  ST8(a2 + 0x13, a3);  /* 0071 */
  a3 = (a11 >> 8) & 0x1ff;  /* 0074: extui width 9 */
  ST8(a2 + 0x16, a3);  /* 0077 */
  a3 = (a11 >> 8) & 0x1ffff;  /* 007a: extui width 17 */
  ST8(a2 + 0x17, a3);  /* 007d */
  __asm__ volatile("" ::: "memory");  /* 0080: memw */
  a3 = (u32)&esp_mesh_ps_duty + 0x0;  /* 0083: l32r -> global */
  a4 = LD8U(a3 + 0x10);  /* 0086 */
  a4 = a4 & a5;  /* 0089 */
  ST8(a3 + 0x10, a4);  /* 008c */
  ST8(a2 + 0x11, a10);  /* 008f */
  a10 = (a10 >> 8) & 0x1ffffff;  /* 0092: extui width 25 */
  ST8(a2 + 0x15, a11);  /* 0095 */
  __asm__ volatile("" ::: "memory");  /* 0098: memw */
  a11 = (a11 >> 8) & 0x1ffffff;  /* 009b: extui width 25 */
  a12 = LD8U(a2 + 0xc);  /* 009e */
  ST8(a2 + 0x14, a10);  /* 00a1 */
  ST8(a2 + 0x18, a11);  /* 00a4 */
  __asm__ volatile("" ::: "memory");  /* 00a7: memw */
  a10 = LD8U(a2 + 0x0);  /* 00aa */
  a11 = LD8U(a2 + 0xb);  /* 00ad */
  a4 = LD8U(a2 + 0x7);  /* 00b0 */
  a5 = LD8U(a2 + 0x8);  /* 00b3 */
  a6 = LD8U(a2 + 0x9);  /* 00b6 */
  a7 = LD8U(a2 + 0xa);  /* 00b9 */
  ST32(a1 + 0x30, a11);  /* 00bc */
  ST32(a1 + 0x34, a12);  /* 00be */
  __asm__ volatile("" ::: "memory");  /* 00c0: memw */
  a8 = (u32)&dutytype2str + 0x0;  /* 00c3: l32r -> global */
  a2 = dutytype2str(a2, a3, a4, a5, a6, a7);  /* 00c6: callx a8 via reloc-expand */
  a15 = a5;  /* 00c9 */
  a14 = a4;  /* 00cb */
  a8 = LD8U(a2 + 0xe);  /* 00cd */
  ST32(a1 + 0x24, a8);  /* 00d0 */
  a8 = LD8U(a2 + 0xf);  /* 00d2 */
  ST32(a1 + 0x20, a8);  /* 00d5 */
  a8 = LD8U(a2 + 0x4);  /* 00d7 */
  a8 = a8 << 8;  /* 00da */
  a9 = LD8U(a2 + 0x3);  /* 00dd */
  a8 = a8 | a9;  /* 00e0 */
  a9 = LD8U(a2 + 0x5);  /* 00e3 */
  a9 = a9 << 16;  /* 00e6 */
  a9 = a9 | a8;  /* 00e9 */
  a8 = LD8U(a2 + 0x6);  /* 00ec */
  a8 = a8 << 24;  /* 00ef */
  a8 = a8 | a9;  /* 00f2 */
  ST32(a1 + 0x1c, a8);  /* 00f5 */
  a8 = LD8U(a2 + 0x2);  /* 00f7 */
  a11 = LD32(a1 + 0x30);  /* 00fa */
  ST32(a1 + 0x18, a8);  /* 00fc */
  a2 = LD8U(a2 + 0xd);  /* 00fe */
  a12 = LD32(a1 + 0x34);  /* 0101 */
  a13 = (u32)(RODATA__rodata_wlog_info_20 + 0x0);  /* 0103: l32r -> .rodata_wlog_info.20 */
  ST32(a1 + 0x8, a11);  /* 0106 */
  a11 = 1;  /* 0108 */
  a11 = a11 << 16;  /* 010a */
  ST32(a1 + 0x14, a2);  /* 010d */
  a2 = 0;  /* 010f */
  ST32(a1 + 0x10, a10);  /* 0111 */
  a10 = 1;  /* 0113 */
  ST32(a1 + 0xc, a12);  /* 0115 */
  a12 = 3;  /* 0117 */
  ST32(a1 + 0x4, a7);  /* 0119 */
  ST32(a1 + 0x0, a6);  /* 011b */
  __asm__ volatile("" ::: "memory");  /* 011d: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0120: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 0123: callx a8 via reloc-expand */
  a11 = 0;  /* 0126 */
  a12 = a3;  /* 0128 */
  a10 = a11;  /* 012a */
  a8 = (u32)&mesh_nwk_duty_post_event;  /* 012c: l32r -> func addr */
  a2 = mesh_nwk_duty_post_event(a2, a3, a4, a5, a6, a7);  /* 012f: callx a8 via reloc-expand */
  return a2;  /* 0132: retw.n */
}


/* mesh_nwk_duty_clr_remaining @ mesh_quick.o 00000008 size 20B bind GLOBAL
 * Calls: memset | Data refs: .bss.esp_mesh_remain_nwk_duty
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_nwk_duty_clr_remaining(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a10 = (u32)&LOCAL__bss_esp_mesh_remain_nwk_duty + 0x0;  /* 000b: l32r -> .bss.esp_mesh_remain_nwk_duty (same-object static) */
  a12 = 15;  /* 000e */
  a11 = 0;  /* 0010 */
  a8 = (u32)&memset + 0x0;  /* 0012: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0015: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0018 */
  return a2;  /* 001a: retw.n */
}


/* mesh_nwk_duty_master_is_root @ mesh_quick.o 0000000c size 52B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memcmp | Data refs: esp_mesh_appie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_nwk_duty_master_is_root(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a8 = (u32)&esp_mesh_appie + 0x0;  /* 000f: l32r -> global */
  a3 = 0;  /* 0012 */
  a12 = a1;  /* 0014 */
  a11 = 15;  /* 0016 */
  a10 = LD32(a8 + 0x0);  /* 0018 */
  a10 = a10 + (2);  /* 001a */
  ST32(a1 + 0x0, a3);  /* 001c */
  ST16(a1 + 0x4, a3);  /* 001e */
  __asm__ volatile("" ::: "memory");  /* 0021: memw */
  __asm__ volatile("" ::: "memory");  /* 0024: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 0027: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 002a: callx a8 via reloc-expand */
  a12 = 6;  /* 002d */
  a11 = a1;  /* 002f */
  a10 = a2;  /* 0031 */
  a8 = (u32)&memcmp + 0x0;  /* 0033: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0036: callx a8 (libc, via reloc-expand) */
  a2 = 1;  /* 0039 */
  if (a10 != 0) a2 = a3;  /* 003b */
  return a2;  /* 003e: retw.n */
}


/* mesh_nwk_duty_post_event @ mesh_quick.o 00000028 size 184B bind GLOBAL
 * Calls: memset, mesh_ps_set_new_duty, memcpy, wifi_mesh_event_post | Data refs: .bss.s_ps_parent_duty_type, .bss.s_ps_parent_duty, .bss.s_ps_device_duty_type, .bss.s_ps_device_duty
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=4, refs=8); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_nwk_duty_post_event(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8;
  /* 0028: entry a1, 96 (frame 96 bytes) */
  a12 = 11;  /* 002b */
  a11 = 0;  /* 002d */
  a10 = a1 + (47);  /* 002f */
  a8 = (u32)&memset + 0x0;  /* 0032: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0035: callx a8 (libc, via reloc-expand) */
  a12 = 47;  /* 0038 */
  a11 = 0;  /* 003a */
  a10 = a1;  /* 003c */
  a8 = (u32)&memset + 0x0;  /* 003e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0041: callx a8 (libc, via reloc-expand) */
  if (a2 == 0) goto L_0098;  /* 0044: beqz a2, 98 <mesh_nwk_duty_post_event+0x70> */
  L_0047: a13 = 0;  /* 0047 */
  a12 = a13;  /* 0049 */
  a11 = a2;  /* 004b */
  a10 = a4;  /* 004d */
  a8 = (u32)&mesh_ps_set_new_duty;  /* 004f: l32r -> func addr */
  a2 = mesh_ps_set_new_duty(a2, a3, a4, a5, a6, a7);  /* 0052: callx a8 via reloc-expand */
  if (a10 != 0) goto L_00dc;  /* 0055: bnez a10, dc <mesh_nwk_duty_post_event+0xb4> */
  L_0058: a11 = a3;  /* 0058 */
  a12 = 6;  /* 005a */
  a10 = a1 + (47);  /* 005c */
  a8 = (u32)&memcpy + 0x0;  /* 005f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0062: callx a8 (libc, via reloc-expand) */
  a3 = LD8U(a2 + 0x0);  /* 0065 */
  a12 = 11;  /* 0068 */
  a11 = a1 + (47);  /* 006a */
  a10 = 68;  /* 006d */
  ST8(a1 + 0x35, a3);  /* 006f */
  __asm__ volatile("" ::: "memory");  /* 0072: memw */
  a3 = LD32(a2 + 0x4);  /* 0075 */
  a3 = LD8U(a3 + 0x0);  /* 0077 */
  a2 = LD32(a2 + 0x8);  /* 007a */
  ST8(a1 + 0x38, a3);  /* 007c */
  __asm__ volatile("" ::: "memory");  /* 007f: memw */
  a2 = LD8U(a2 + 0x0);  /* 0082 */
  ST8(a1 + 0x39, a2);  /* 0085 */
  a2 = 1;  /* 0088 */
  ST8(a1 + 0x37, a2);  /* 008a */
  __asm__ volatile("" ::: "memory");  /* 008d: memw */
  __asm__ volatile("" ::: "memory");  /* 0090: memw */
  goto L_00d3;  /* 0093: j */
  L_0098: a2 = (u32)&LOCAL__bss_s_ps_parent_duty_type + 0x0;  /* 0098: l32r -> .bss.s_ps_parent_duty_type (same-object static) */
  a5 = (u32)&LOCAL__bss_s_ps_parent_duty + 0x0;  /* 009b: l32r -> .bss.s_ps_parent_duty (same-object static) */
  if (a3 != 0) goto L_00a6;  /* 009e: bnez.n a3, a6 <mesh_nwk_duty_post_event+0x7e> */
  L_00a0: a2 = (u32)&LOCAL__bss_s_ps_device_duty_type + 0x0;  /* 00a0: l32r -> .bss.s_ps_device_duty_type (same-object static) */
  a5 = (u32)&LOCAL__bss_s_ps_device_duty + 0x0;  /* 00a3: l32r -> .bss.s_ps_device_duty (same-object static) */
  L_00a6: a13 = a2;  /* 00a6 */
  a12 = a5;  /* 00a8 */
  a11 = 0;  /* 00aa */
  a10 = a4;  /* 00ac */
  a8 = (u32)&mesh_ps_set_new_duty;  /* 00ae: l32r -> func addr */
  a2 = mesh_ps_set_new_duty(a2, a3, a4, a5, a6, a7);  /* 00b1: callx a8 via reloc-expand */
  if (a10 != 0) goto L_00dc;  /* 00b4: bnez.n a10, dc <mesh_nwk_duty_post_event+0xb4> */
  L_00b6: a8 = 1;  /* 00b6 */
  if (a3 != 0) a8 = a10;  /* 00b8 */
  a2 = LD8U(a2 + 0x0);  /* 00bb */
  a12 = 47;  /* 00be */
  a11 = a1;  /* 00c0 */
  a10 = 63;  /* 00c2 */
  a3 = LD8U(a5 + 0x0);  /* 00c4 */
  ST8(a1 + 0x6, a8);  /* 00c7 */
  ST8(a1 + 0x7, a3);  /* 00ca */
  ST8(a1 + 0x8, a2);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00d0: memw */
  L_00d3: __asm__ volatile("" ::: "memory");  /* 00d3: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 00d6: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 00d9: callx a8 via reloc-expand */
  L_00dc: a2 = 0;  /* 00dc */
  return a2;  /* 00de: retw.n */
}


/* mesh_nwk_duty_process_remaining @ mesh_quick.o 0000005c size 707B bind GLOBAL
 * Calls: memset, mesh_nwk_duty_check_duration_expire, __moddi3, __divdi3, wifi_log, dutytype2str, esp_mesh_ps_duty_cycle_set_process, mesh_nwk_duty_clr_remaining | indirect[1]: mem[a4+0x110] | Data refs: esp_mesh_ps_duty, g_osi_funcs_p, .rodata_wlog_warning.21, .rodata.mesh_nwk_duty_process_remaining.str1.1, .rodata_wlog_warning.22, .rodata_wlog_warning.23
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=8, refs=14); reloc-direct=8, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_nwk_duty_process_remaining(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a5, a6, a7, a8, a9;
  /* 005c: entry a1, 96 (frame 96 bytes) */
  a4 = (a4 >> 8) & 0x1;  /* 005f: extui width 1 */
  a5 = LD8U(a2 + 0x3);  /* 0062 */
  a12 = 16;  /* 0065 */
  a5 = a5 << 8;  /* 0067 */
  a11 = 0;  /* 006a */
  a10 = a1 + (32);  /* 006c */
  ST32(a1 + 0x30, a4);  /* 006f */
  a4 = LD8U(a2 + 0x2);  /* 0071 */
  a5 = a5 | a4;  /* 0074 */
  a4 = LD8U(a2 + 0x4);  /* 0077 */
  a4 = a4 << 16;  /* 007a */
  a4 = a4 | a5;  /* 007d */
  a5 = LD8U(a2 + 0x5);  /* 0080 */
  a5 = a5 << 24;  /* 0083 */
  a5 = a5 | a4;  /* 0086 */
  a6 = LD8U(a2 + 0x8);  /* 0089 */
  a6 = a6 << 8;  /* 008c */
  a4 = LD8U(a2 + 0x7);  /* 008f */
  a6 = a6 | a4;  /* 0092 */
  a4 = LD8U(a2 + 0x9);  /* 0095 */
  a4 = a4 << 16;  /* 0098 */
  a4 = a4 | a6;  /* 009b */
  a7 = LD8U(a2 + 0xa);  /* 009e */
  a7 = a7 << 24;  /* 00a1 */
  a7 = a7 | a4;  /* 00a4 */
  a6 = LD8U(a2 + 0xc);  /* 00a7 */
  a6 = a6 << 8;  /* 00aa */
  a4 = LD8U(a2 + 0xb);  /* 00ad */
  a6 = a6 | a4;  /* 00b0 */
  a4 = LD8U(a2 + 0xd);  /* 00b3 */
  a4 = a4 << 16;  /* 00b6 */
  a4 = a4 | a6;  /* 00b9 */
  a6 = LD8U(a2 + 0xe);  /* 00bc */
  a6 = a6 << 24;  /* 00bf */
  a6 = a6 | a4;  /* 00c2 */
  __asm__ volatile("" ::: "memory");  /* 00c5: memw */
  a8 = (u32)&memset + 0x0;  /* 00c8: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00cb: callx a8 (libc, via reloc-expand) */
  if (a3 != 0) goto L_00dc;  /* 00ce: bnez.n a3, dc <mesh_nwk_duty_process_remaining+0x80> */
  L_00d0: a4 = (u32)&esp_mesh_ps_duty + 0x0;  /* 00d0: l32r -> global */
  a4 = LD8U(a4 + 0x0);  /* 00d3 */
  if (((a4 >> 7) & 1) == 0) goto L_00dc;  /* 00d6: bbci a4, 7, dc <mesh_nwk_duty_process_remaining+0x80> */
  L_00d9: goto L_02d0;  /* 00d9: j */
  L_00dc: a4 = 2;  /* 00dc */
  a8 = LD8U(a2 + 0x0);  /* 00de */
  if (a8 == 0) goto L_02dc;  /* 00e1: beqz a8, 2dc <mesh_nwk_duty_process_remaining+0x280> */
  L_00e4: a13 = a6;  /* 00e4 */
  a12 = a7;  /* 00e6 */
  a10 = a5;  /* 00e8 */
  a8 = (u32)&mesh_nwk_duty_check_duration_expire;  /* 00ea: l32r -> func addr */
  a2 = mesh_nwk_duty_check_duration_expire(a2, a3, a4);  /* 00ed: callx a8 via reloc-expand */
  a13 = a10;  /* 00f0 */
  if (a10 != 0) goto L_02d5;  /* 00f2: bnez a10, 2d5 <mesh_nwk_duty_process_remaining+0x279> */
  L_00f5: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00f5: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 00f8 */
  a10 = LD32(a4 + 0x110);  /* 00fa */
  ST32(a1 + 0x34, a13);  /* 00fd */
  __asm__ volatile("" ::: "memory");  /* 00ff: memw */
  /* 0102: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a9 = a10 - a7;  /* 0105: sub */
  a8 = 1;  /* 0108 */
  a4 = 0x03938700u;  /* 010b: l32r = 60000000 */
  a12 = a5 * a4;  /* 010e */
  a4 = (u32)(((u64)a5 * a4) >> 32);  /* 0111: mulsh */
  a13 = LD32(a1 + 0x34);  /* 0114 */
  if (a10 < a9) goto L_011c;  /* 0116: bltu a10, a9, 11c <mesh_nwk_duty_process_remaining+0xc0> */
  L_0119: a8 = a13;  /* 0119: mov */
  L_011c: a11 = a11 - a6;  /* 011c: sub */
  a9 = a12 - a9;  /* 011f: sub */
  a11 = a11 - a8;  /* 0122: sub */
  a8 = 1;  /* 0125 */
  if (a12 < a9) goto L_012c;  /* 0127: bltu a12, a9, 12c <mesh_nwk_duty_process_remaining+0xd0> */
  L_012a: a8 = 0;  /* 012a */
  L_012c: a4 = a4 - a11;  /* 012c: sub */
  a4 = a4 - a8;  /* 012f: sub */
  a12 = 0x03938700u;  /* 0132: l32r = 60000000 */
  a10 = a9;  /* 0135 */
  a13 = 0;  /* 0137 */
  a11 = a4;  /* 0139 */
  ST32(a1 + 0x34, a9);  /* 013b */
  __asm__ volatile("" ::: "memory");  /* 013d: memw */
  a8 = (u32)&__moddi3 + 0x0;  /* 0140: l32r -> global */
  a2 = __moddi3(a2, a3, a4);  /* 0143: callx a8 via reloc-expand */
  a14 = 1;  /* 0146 */
  a9 = LD32(a1 + 0x34);  /* 0148 */
  if ((i32)a11 >= (i32)a14) goto L_0158;  /* 014a: bge a11, a14, 158 <mesh_nwk_duty_process_remaining+0xfc> */
  L_014d: if (a11 != 0) goto L_0156;  /* 014d: bnez a11, 156 <mesh_nwk_duty_process_remaining+0xfa> */
  L_0150: a8 = 0x01c9c380u;  /* 0150: l32r = 30000000 */
  if (a8 < a10) goto L_0158;  /* 0153: bltu a8, a10, 158 <mesh_nwk_duty_process_remaining+0xfc> */
  L_0156: a14 = 0;  /* 0156 */
  L_0158: a13 = 0;  /* 0158 */
  a12 = 0x03938700u;  /* 015a: l32r = 60000000 */
  a10 = a9;  /* 015d */
  a11 = a4;  /* 015f */
  ST32(a1 + 0x34, a9);  /* 0161 */
  ST32(a1 + 0x3c, a14);  /* 0163 */
  __asm__ volatile("" ::: "memory");  /* 0165: memw */
  a8 = (u32)&__divdi3 + 0x0;  /* 0168: l32r -> global */
  a2 = __divdi3(a2, a3, a4);  /* 016b: callx a8 via reloc-expand */
  a8 = 1;  /* 016e */
  a8 = a8 << 16;  /* 0170 */
  a12 = 0x3e8;  /* 0173 */
  a14 = LD32(a1 + 0x3c);  /* 0176 */
  a13 = 0;  /* 0178 */
  a14 = a14 + a10;  /* 017a */
  a10 = (a14 >> 8) & 0x1ff;  /* 017c: extui width 9 */
  a11 = a4;  /* 017f */
  a9 = LD32(a1 + 0x34);  /* 0181 */
  ST8(a2 + 0x3, a10);  /* 0183 */
  __asm__ volatile("" ::: "memory");  /* 0186: memw */
  a10 = (a14 >> 8) & 0x1ffff;  /* 0189: extui width 17 */
  a15 = LD8U(a2 + 0x1);  /* 018c */
  ST8(a2 + 0x4, a10);  /* 018f */
  a10 = (a14 >> 8) & 0x1ffffff;  /* 0192: extui width 25 */
  ST8(a2 + 0x2, a14);  /* 0195 */
  ST8(a2 + 0x5, a10);  /* 0198 */
  __asm__ volatile("" ::: "memory");  /* 019b: memw */
  a10 = a9;  /* 019e */
  ST32(a1 + 0x38, a8);  /* 01a0 */
  ST32(a1 + 0x3c, a14);  /* 01a2 */
  ST32(a1 + 0x34, a15);  /* 01a5 */
  __asm__ volatile("" ::: "memory");  /* 01a7: memw */
  a8 = (u32)&__divdi3 + 0x0;  /* 01aa: l32r -> global */
  a2 = __divdi3(a2, a3, a4);  /* 01ad: callx a8 via reloc-expand */
  a12 = 0x3e8;  /* 01b0 */
  a13 = 0;  /* 01b3 */
  ST32(a1 + 0x10, a10);  /* 01b5 */
  a10 = a7;  /* 01b7 */
  ST32(a1 + 0x14, a11);  /* 01b9 */
  a11 = a6;  /* 01bb */
  __asm__ volatile("" ::: "memory");  /* 01bd: memw */
  a8 = (u32)&__divdi3 + 0x0;  /* 01c0: l32r -> global */
  a2 = __divdi3(a2, a3, a4);  /* 01c3: callx a8 via reloc-expand */
  a12 = 2;  /* 01c6 */
  a8 = LD32(a1 + 0x38);  /* 01c8 */
  a15 = LD32(a1 + 0x34);  /* 01ca */
  a14 = LD32(a1 + 0x3c);  /* 01cc */
  a13 = (u32)(RODATA__rodata_wlog_warning_21 + 0x0);  /* 01ce: l32r -> .rodata_wlog_warning.21 */
  ST32(a1 + 0x8, a10);  /* 01d1 */
  a10 = 1;  /* 01d3 */
  ST32(a1 + 0xc, a11);  /* 01d5 */
  a11 = a8;  /* 01d7 */
  ST32(a1 + 0x0, a5);  /* 01d9 */
  __asm__ volatile("" ::: "memory");  /* 01db: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 01de: l32r -> global */
  a2 = wifi_log(a2, a3, a4);  /* 01e1: callx a8 via reloc-expand */
  a4 = LD8U(a2 + 0x3);  /* 01e4 */
  a4 = a4 << 8;  /* 01e7 */
  a5 = LD8U(a2 + 0x2);  /* 01ea */
  a4 = a4 | a5;  /* 01ed */
  a5 = LD8U(a2 + 0x4);  /* 01f0 */
  a5 = a5 << 16;  /* 01f3 */
  a5 = a5 | a4;  /* 01f6 */
  a4 = LD8U(a2 + 0x5);  /* 01f9 */
  a4 = a4 << 24;  /* 01fc */
  a4 = a4 | a5;  /* 01ff */
  if (a4 == 0) goto L_02da;  /* 0202: beqz a4, 2da <mesh_nwk_duty_process_remaining+0x27e> */
  L_0205: a5 = (a4 >> 8) & 0x1ff;  /* 0205: extui width 9 */
  ST8(a1 + 0x23, a4);  /* 0208 */
  ST8(a1 + 0x24, a5);  /* 020b */
  __asm__ volatile("" ::: "memory");  /* 020e: memw */
  a5 = (a4 >> 8) & 0x1ffff;  /* 0211: extui width 17 */
  a4 = (a4 >> 8) & 0x1ffffff;  /* 0214: extui width 25 */
  a7 = LD8U(a2 + 0x1);  /* 0217 */
  ST8(a1 + 0x26, a4);  /* 021a */
  __asm__ volatile("" ::: "memory");  /* 021d: memw */
  a4 = LD8U(a2 + 0x6);  /* 0220 */
  ST8(a1 + 0x25, a5);  /* 0223 */
  ST8(a1 + 0x22, a7);  /* 0226 */
  ST8(a1 + 0x2f, a4);  /* 0229 */
  __asm__ volatile("" ::: "memory");  /* 022c: memw */
  a5 = (u32)&esp_mesh_ps_duty + 0x0;  /* 022f: l32r -> global */
  if (a3 == 0) goto L_023d;  /* 0232: beqz.n a3, 23d <mesh_nwk_duty_process_remaining+0x1e1> */
  L_0234: a4 = LD8U(a3 + 0xd);  /* 0234 */
  __asm__ volatile("" ::: "memory");  /* 0237: memw */
  goto L_0240;  /* 023a: j */
  L_023d: a4 = LD8U(a5 + 0xd);  /* 023d */
  L_0240: a10 = LD8U(a5 + 0x0);  /* 0240 */
  ST8(a1 + 0x2d, a4);  /* 0243 */
  __asm__ volatile("" ::: "memory");  /* 0246: memw */
  __asm__ volatile("" ::: "memory");  /* 0249: memw */
  a8 = (u32)&dutytype2str + 0x0;  /* 024c: l32r -> global */
  a2 = dutytype2str(a2, a3, a4);  /* 024f: callx a8 via reloc-expand */
  a4 = LD8U(a2 + 0x3);  /* 0252 */
  a4 = a4 << 8;  /* 0255 */
  a6 = LD8U(a2 + 0x2);  /* 0258 */
  a4 = a4 | a6;  /* 025b */
  a6 = LD8U(a2 + 0x4);  /* 025e */
  a6 = a6 << 16;  /* 0261 */
  a6 = a6 | a4;  /* 0264 */
  a4 = LD8U(a2 + 0x5);  /* 0267 */
  a4 = a4 << 24;  /* 026a */
  a4 = a4 | a6;  /* 026d */
  a9 = LD32(a1 + 0x30);  /* 0270 */
  a6 = LD8U(a2 + 0x6);  /* 0272 */
  a8 = LD8U(a1 + 0x2d);  /* 0275 */
  a2 = (u32)(RODATA__rodata_mesh_nwk_duty_process_remaining_str1_1 + 0x0);  /* 0278: -> "(from assoc response)" */
  if (a9 != 0) goto L_0281;  /* 027b: bnez a9, 281 <mesh_nwk_duty_process_remaining+0x225> */
  L_027e: a2 = (u32)(RODATA__rodata_mesh_nwk_duty_process_remaining_str1_1 + 0x0);  /* 027e: -> "(from assoc response)" */
  L_0281: a11 = 1;  /* 0281 */
  a15 = a10;  /* 0283 */
  a14 = a7;  /* 0285 */
  a12 = 2;  /* 0287 */
  a13 = (u32)(RODATA__rodata_wlog_warning_22 + 0x0);  /* 0289: l32r -> .rodata_wlog_warning.22 */
  a11 = a11 << 16;  /* 028c */
  a10 = 1;  /* 028f */
  ST32(a1 + 0xc, a2);  /* 0291 */
  ST32(a1 + 0x8, a6);  /* 0293 */
  ST32(a1 + 0x4, a4);  /* 0295 */
  ST32(a1 + 0x0, a8);  /* 0297 */
  __asm__ volatile("" ::: "memory");  /* 0299: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 029c: l32r -> global */
  a2 = wifi_log(a2, a3, a4);  /* 029f: callx a8 via reloc-expand */
  if (a3 == 0) goto L_02ad;  /* 02a2: beqz.n a3, 2ad <mesh_nwk_duty_process_remaining+0x251> */
  L_02a4: a2 = LD8U(a1 + 0x2d);  /* 02a4 */
  ST8(a5 + 0xd, a2);  /* 02a7 */
  __asm__ volatile("" ::: "memory");  /* 02aa: memw */
  L_02ad: a12 = 0;  /* 02ad */
  a14 = a1 + (32);  /* 02af */
  a11 = 1;  /* 02b2 */
  a10 = a12;  /* 02b4 */
  a2 = LD32(a1 + 0x30);  /* 02b6 */
  a4 = 0;  /* 02b8 */
  a13 = a2 << 16;  /* 02ba */
  a2 = 0x100;  /* 02bd */
  a13 = a13 | a2;  /* 02c0 */
  __asm__ volatile("" ::: "memory");  /* 02c3: memw */
  a8 = (u32)&esp_mesh_ps_duty_cycle_set_process;  /* 02c6: l32r -> func addr */
  a2 = esp_mesh_ps_duty_cycle_set_process(a2, a3, a4);  /* 02c9: callx a8 via reloc-expand */
  goto L_0313;  /* 02cc: j */
  L_02d0: a4 = 1;  /* 02d0 */
  goto L_02dc;  /* 02d2: j */
  L_02d5: a4 = 3;  /* 02d5 */
  goto L_02dc;  /* 02d7: j */
  L_02da: a4 = 4;  /* 02da */
  L_02dc: a8 = (u32)&mesh_nwk_duty_clr_remaining;  /* 02dc: l32r -> func addr */
  a2 = mesh_nwk_duty_clr_remaining(a2, a3, a4);  /* 02df: callx a8 via reloc-expand */
  a14 = (u32)(RODATA__rodata_mesh_nwk_duty_process_remaining_str1_1 + 0x0);  /* 02e2: -> "(from assoc response)" */
  if (a3 != 0) goto L_02ea;  /* 02e5: bnez.n a3, 2ea <mesh_nwk_duty_process_remaining+0x28e> */
  L_02e7: a14 = (u32)(RODATA__rodata_mesh_nwk_duty_process_remaining_str1_1 + 0x0);  /* 02e7: -> "(from assoc response)" */
  L_02ea: a11 = 1;  /* 02ea */
  a15 = a4;  /* 02ec */
  a12 = 2;  /* 02ee */
  a11 = a11 << 16;  /* 02f0 */
  a13 = (u32)(RODATA__rodata_wlog_warning_23 + 0x0);  /* 02f3: l32r -> .rodata_wlog_warning.23 */
  a10 = 1;  /* 02f6 */
  a2 = 2;  /* 02f8 */
  a5 = 3;  /* 02fb */
  a8 = (u32)&wifi_log + 0x0;  /* 02fe: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5);  /* 0301: callx a8 via reloc-expand */
  if (a3 == 0) a2 = a5;  /* 0304 */
  a3 = (u32)&esp_mesh_ps_duty + 0x0;  /* 0307: l32r -> global */
  ST8(a3 + 0x1a, a2);  /* 030a */
  ST8(a3 + 0x19, a4);  /* 030d */
  __asm__ volatile("" ::: "memory");  /* 0310: memw */
  L_0313: a3 = 0;  /* 0313 */
  a2 = 1;  /* 0315 */
  if (a4 == 0) a2 = a3;  /* 0317 */
  __asm__ volatile("" ::: "memory");  /* 031a: memw */
  return a2;  /* 031d: retw.n */
}


/* mesh_nwk_duty_set_master_identity @ mesh_quick.o 00000014 size 196B bind GLOBAL
 * Calls: wifi_get_macaddr | indirect[1]: mem[a2+0x110] | Data refs: esp_mesh_ps_duty, g_mesh_is_root, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_nwk_duty_set_master_identity(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a5 = (u32)&esp_mesh_ps_duty + 0x0;  /* 0017: l32r -> global */
  a9 = -128;  /* 001a */
  a2 = (a2 >> 8) & 0x1;  /* 001d: extui width 1 */
  a10 = 1;  /* 0020 */
  a6 = (a6 >> 8) & 0x1;  /* 0023: extui width 1 */
  a8 = LD8U(a5 + 0x0);  /* 0026 */
  a8 = a8 | a9;  /* 0029 */
  a9 = (a3 >> 8) & 0x1ff;  /* 002c: extui width 9 */
  ST8(a5 + 0x4, a9);  /* 002f */
  a9 = (a3 >> 8) & 0x1ffff;  /* 0032: extui width 17 */
  ST8(a5 + 0x5, a9);  /* 0035 */
  __asm__ volatile("" ::: "memory");  /* 0038: memw */
  a9 = (a3 >> 8) & 0x1ffffff;  /* 003b: extui width 25 */
  a11 = (u32)&esp_mesh_ps_duty + 0x7;  /* 003e: l32r -> global */
  ST8(a5 + 0x0, a8);  /* 0041 */
  ST8(a5 + 0x2, a2);  /* 0044 */
  ST8(a5 + 0x3, a3);  /* 0047 */
  ST8(a5 + 0x6, a9);  /* 004a */
  __asm__ volatile("" ::: "memory");  /* 004d: memw */
  __asm__ volatile("" ::: "memory");  /* 0050: memw */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 0053: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6, a7);  /* 0056: callx a8 via reloc-expand */
  a8 = LD8U(a5 + 0xd);  /* 0059 */
  a8 = a8 + (1);  /* 005c */
  a6 = a6 + a8;  /* 005e */
  ST8(a5 + 0xd, a6);  /* 0060 */
  __asm__ volatile("" ::: "memory");  /* 0063: memw */
  a6 = (u32)&g_mesh_is_root + 0x0;  /* 0066: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0069: memw */
  a8 = LD8U(a6 + 0x0);  /* 006c */
  a8 = (a8 >> 8) & 0x1;  /* 006f: extui width 1 */
  ST8(a5 + 0xf, a4);  /* 0072 */
  __asm__ volatile("" ::: "memory");  /* 0075: memw */
  if ((i32)a3 >= 0) goto L_0088;  /* 0078: bgez a3, 88 <mesh_nwk_duty_set_master_identity+0x74> */
  L_007b: if (a8 == 0) goto L_0088;  /* 007b: beqz.n a8, 88 <mesh_nwk_duty_set_master_identity+0x74> */
  L_007d: ST8(a5 + 0xe, a2);  /* 007d */
  a2 = 0;  /* 0080 */
  ST8(a5 + 0xf, a2);  /* 0082 */
  __asm__ volatile("" ::: "memory");  /* 0085: memw */
  L_0088: a2 = -4;  /* 0088 */
  a3 = LD8U(a5 + 0x10);  /* 008a */
  a3 = a3 & a2;  /* 008d */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0090: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0093 */
  a10 = LD32(a2 + 0x110);  /* 0095 */
  ST8(a5 + 0x10, a3);  /* 0098 */
  __asm__ volatile("" ::: "memory");  /* 009b: memw */
  __asm__ volatile("" ::: "memory");  /* 009e: memw */
  /* 00a1: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a2 = (a10 >> 8) & 0x1ff;  /* 00a4: extui width 9 */
  ST8(a5 + 0x12, a2);  /* 00a7 */
  a2 = (a10 >> 8) & 0x1ffff;  /* 00aa: extui width 17 */
  ST8(a5 + 0x13, a2);  /* 00ad */
  a2 = (a11 >> 8) & 0x1ff;  /* 00b0: extui width 9 */
  ST8(a5 + 0x11, a10);  /* 00b3 */
  a10 = (a10 >> 8) & 0x1ffffff;  /* 00b6: extui width 25 */
  ST8(a5 + 0x15, a11);  /* 00b9 */
  ST8(a5 + 0x16, a2);  /* 00bc */
  a2 = (a11 >> 8) & 0x1ffff;  /* 00bf: extui width 17 */
  a11 = (a11 >> 8) & 0x1ffffff;  /* 00c2: extui width 25 */
  ST8(a5 + 0x17, a2);  /* 00c5 */
  a2 = 0;  /* 00c8 */
  ST8(a5 + 0x14, a10);  /* 00ca */
  ST8(a5 + 0x18, a11);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00d0: memw */
  __asm__ volatile("" ::: "memory");  /* 00d3: memw */
  return a2;  /* 00d6: retw.n */
}


/* mesh_nwk_duty_set_remaining @ mesh_quick.o 0000000c size 164B bind GLOBAL
 * Calls: mesh_nwk_duty_clr_remaining | indirect[1]: mem[a2+0x110] | Data refs: .bss.esp_mesh_remain_nwk_duty, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=3); reloc-direct=1, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_nwk_duty_set_remaining(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a8 = LD8U(a2 + 0x4);  /* 000f */
  a8 = a8 << 8;  /* 0012 */
  a3 = LD8U(a2 + 0x3);  /* 0015 */
  a8 = a8 | a3;  /* 0018 */
  a3 = LD8U(a2 + 0x5);  /* 001b */
  a3 = a3 << 16;  /* 001e */
  a3 = a3 | a8;  /* 0021 */
  a8 = LD8U(a2 + 0x6);  /* 0024 */
  a8 = a8 << 24;  /* 0027 */
  a8 = a8 | a3;  /* 002a */
  if (a8 != -1) goto L_0039;  /* 002d: bnei a8, -1, 39 <mesh_nwk_duty_set_remaining+0x2d> */
  L_0030: a8 = (u32)&mesh_nwk_duty_clr_remaining;  /* 0030: l32r -> func addr */
  a2 = mesh_nwk_duty_clr_remaining(a2, a3, a4, a5, a6, a7);  /* 0033: callx a8 via reloc-expand */
  goto L_00a9;  /* 0036: j */
  L_0039: a3 = (u32)&LOCAL__bss_esp_mesh_remain_nwk_duty + 0x0;  /* 0039: l32r -> .bss.esp_mesh_remain_nwk_duty (same-object static) */
  a9 = 1;  /* 003c */
  a10 = (a8 >> 8) & 0x1ff;  /* 003e: extui width 9 */
  ST8(a3 + 0x0, a9);  /* 0041 */
  __asm__ volatile("" ::: "memory");  /* 0044: memw */
  a9 = LD8U(a2 + 0x2);  /* 0047 */
  a2 = LD8U(a2 + 0xf);  /* 004a */
  ST8(a3 + 0x6, a2);  /* 004d */
  __asm__ volatile("" ::: "memory");  /* 0050: memw */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0053: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0056 */
  ST8(a3 + 0x3, a10);  /* 0058 */
  a10 = (a8 >> 8) & 0x1ffff;  /* 005b: extui width 17 */
  ST8(a3 + 0x2, a8);  /* 005e */
  a8 = (a8 >> 8) & 0x1ffffff;  /* 0061: extui width 25 */
  ST8(a3 + 0x4, a10);  /* 0064 */
  __asm__ volatile("" ::: "memory");  /* 0067: memw */
  a10 = LD32(a2 + 0x110);  /* 006a */
  ST8(a3 + 0x1, a9);  /* 006d */
  ST8(a3 + 0x5, a8);  /* 0070 */
  __asm__ volatile("" ::: "memory");  /* 0073: memw */
  __asm__ volatile("" ::: "memory");  /* 0076: memw */
  /* 0079: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a2 = (a10 >> 8) & 0x1ff;  /* 007c: extui width 9 */
  ST8(a3 + 0x8, a2);  /* 007f */
  a2 = (a10 >> 8) & 0x1ffff;  /* 0082: extui width 17 */
  ST8(a3 + 0x9, a2);  /* 0085 */
  a2 = (a11 >> 8) & 0x1ff;  /* 0088: extui width 9 */
  ST8(a3 + 0x7, a10);  /* 008b */
  a10 = (a10 >> 8) & 0x1ffffff;  /* 008e: extui width 25 */
  ST8(a3 + 0xb, a11);  /* 0091 */
  ST8(a3 + 0xc, a2);  /* 0094 */
  a2 = (a11 >> 8) & 0x1ffff;  /* 0097: extui width 17 */
  a11 = (a11 >> 8) & 0x1ffffff;  /* 009a: extui width 25 */
  ST8(a3 + 0xa, a10);  /* 009d */
  ST8(a3 + 0xd, a2);  /* 00a0 */
  ST8(a3 + 0xe, a11);  /* 00a3 */
  __asm__ volatile("" ::: "memory");  /* 00a6: memw */
  L_00a9: a2 = 0;  /* 00a9 */
  __asm__ volatile("" ::: "memory");  /* 00ab: memw */
  return a2;  /* 00ae: retw.n */
}


/* mesh_parse_conflict_roots_ie @ mesh_quick.o 00000080 size 1044B bind GLOBAL
 * Calls: wifi_log, clone_is_zero_addr, roots_type2str, mesh_is_new_root_invalid, mesh_process_roots_ie | indirect[8]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x158]; mem[a3+0x150] | Data refs: .rodata_wlog_info.26, g_osi_funcs_p, .rodata.mesh_parse_ps_entire_rule.str1.1, .rodata.esp_mesh_ps_duty_cycle_get_process.str1.1, .rodata._mesh_timer_process_conflict_root.str1.1, .bss.s_mesh_roots_ie_life, .rodata_wlog_info.27, g_mesh_max_layer, .text.is_zero_addr, .rodata_wlog_warning.28, g_mesh_topology, .rodata_wlog_warning.29 +1 more
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=16); reloc-direct=5, funcdb-attributed=0, unknown-indirect=8 */
u32 mesh_parse_conflict_roots_ie(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a5, a6, a7, a8, a9;
  /* 0080: entry a1, 160 (frame 160 bytes) */
  a5 = a2;  /* 0083 */
  a2 = 0;  /* 0085 */
  a14 = a3;  /* 0087 */
  a6 = a2;  /* 0089 */
  a3 = 1;  /* 008b */
  if (a14 == 0) a6 = a3;  /* 008d */
  if (a4 == 0) a2 = a3;  /* 0090 */
  a6 = a6 | a2;  /* 0093 */
  if (a6 != 0) goto L_0490;  /* 0096: bnez a6, 490 <mesh_parse_conflict_roots_ie+0x410> */
  L_0099: if (a5 == 0) a6 = a3;  /* 0099 */
  if (a6 != 0) goto L_0490;  /* 009c: bnez a6, 490 <mesh_parse_conflict_roots_ie+0x410> */
  L_009f: a7 = LD8U(a14 + 0x1);  /* 009f */
  a8 = 13;  /* 00a2 */
  a2 = a7 + (-9);  /* 00a4 */
  ST32(a1 + 0x54, a2);  /* 00a7 */
  a2 = -1;  /* 00aa */
  a9 = LD32(a1 + 0x54);  /* 00ac */
  if (a8 < a9) goto L_00b5;  /* 00af: bltu a8, a9, b5 <mesh_parse_conflict_roots_ie+0x35> */
  L_00b2: goto L_0492;  /* 00b2: j */
  L_00b5: a15 = LD8U(a14 + 0x7);  /* 00b5 */
  if (a15 < 4u) goto L_0110;  /* 00b8: bltui a15, 4, 110 <mesh_parse_conflict_roots_ie+0x90> */
  L_00bb: a2 = 4;  /* 00bb */
  a14 = 0x235;  /* 00bd */
  a13 = (u32)(RODATA__rodata_wlog_info_26 + 0x0);  /* 00c0: l32r -> .rodata_wlog_info.26 */
  a14 = a14 << 3;  /* 00c3 */
  a12 = 3;  /* 00c6 */
  a11 = a3 << 21;  /* 00c8 */
  a10 = a3;  /* 00cb */
  ST32(a1 + 0x0, a2);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00cf: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 00d2: l32r -> global */
  a2 = wifi_log(a2, a3, a4);  /* 00d5: callx a8 via reloc-expand */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00d8: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00db */
  if (a2 != 0) goto L_00e4;  /* 00dd: bnez.n a2, e4 <mesh_parse_conflict_roots_ie+0x64> */
  L_00df: goto L_017a;  /* 00df: j */
  L_00e4: a4 = LD32(a2 + 0x150);  /* 00e4 */
  if (a4 == 0) goto L_017a;  /* 00e7: beqz a4, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_00ea: a10 = LD32(a2 + 0x158);  /* 00ea */
  /* 00ed: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00f0 */
  a10 = a3;  /* 00f2 */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 00f4: -> "child(cidx:" */
  a14 = a11;  /* 00f7: mov */
  a2 = 0x000011aau;  /* 00fa: l32r = 4522 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 00fd: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata__mesh_timer_process_conflict_root_str1_1 + 0x0);  /* 0100: l32r -> .rodata._mesh_timer_process_conflict_root.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0103 */
  __asm__ volatile("" ::: "memory");  /* 0106: memw */
  /* 0109: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_017a;  /* 010c: j */
  L_0110: a3 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 0110: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a2 = -1;  /* 0113 */
  a6 = LD8U(a3 + 0x0);  /* 0115 */
  if (a6 != 0) goto L_0492;  /* 0118: bnez a6, 492 <mesh_parse_conflict_roots_ie+0x412> */
  L_011b: if (a15 != 3) goto L_0124;  /* 011b: bnei a15, 3, 124 <mesh_parse_conflict_roots_ie+0xa4> */
  L_011e: a3 = LD8U(a3 + 0x10);  /* 011e */
  if (a3 != 0) goto L_0492;  /* 0121: bnez a3, 492 <mesh_parse_conflict_roots_ie+0x412> */
  L_0124: a7 = LD8U(a14 + 0x8);  /* 0124 */
  a2 = a7 + (-1);  /* 0127 */
  a2 = (a2 >> 8) & 0x1;  /* 0129: extui width 1 */
  if (a2 < 5u) goto L_0180;  /* 012c: bltui a2, 5, 180 <mesh_parse_conflict_roots_ie+0x100> */
  L_012f: a2 = 5;  /* 012f */
  a14 = 0x000011c1u;  /* 0131: l32r = 4545 */
  a11 = 1;  /* 0134 */
  a15 = a7;  /* 0136 */
  a12 = 3;  /* 0138 */
  a11 = a11 << 21;  /* 013a */
  a13 = (u32)(RODATA__rodata_wlog_info_27 + 0x0);  /* 013d: l32r -> .rodata_wlog_info.27 */
  a10 = 1;  /* 0140 */
  ST32(a1 + 0x0, a2);  /* 0142 */
  __asm__ volatile("" ::: "memory");  /* 0144: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0147: l32r -> global */
  a2 = wifi_log(a2, a3, a4);  /* 014a: callx a8 via reloc-expand */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 014d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0150 */
  if (a2 == 0) goto L_017a;  /* 0152: beqz a2, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_0155: a3 = LD32(a2 + 0x150);  /* 0155 */
  if (a3 == 0) goto L_017a;  /* 0158: beqz.n a3, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_015a: a10 = LD32(a2 + 0x158);  /* 015a */
  /* 015d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 0160: -> "child(cidx:" */
  a2 = 0x000011c3u;  /* 0163: l32r = 4547 */
  L_0166: a13 = a10;  /* 0166 */
  a14 = a11;  /* 0168 */
  a10 = 1;  /* 016a */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 016c: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata__mesh_timer_process_conflict_root_str1_1 + 0x0);  /* 016f: l32r -> .rodata._mesh_timer_process_conflict_root.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0172 */
  __asm__ volatile("" ::: "memory");  /* 0174: memw */
  /* 0177: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_017a: a2 = 0;  /* 017a */
  goto L_0492;  /* 017c: j */
  L_0180: a2 = (u32)&g_mesh_max_layer + 0x0;  /* 0180: l32r -> global */
  a14 = a14 + (9);  /* 0183 */
  a3 = a14;  /* 0185 */
  a6 = 0;  /* 0187 */
  a2 = LD16U(a2 + 0x0);  /* 0189 */
  ST32(a1 + 0x58, a2);  /* 018c */
  __asm__ volatile("" ::: "memory");  /* 018f: memw */
  goto L_0453;  /* 0192: j */
  L_0195: a10 = a3 + (4);  /* 0195 */
  ST32(a1 + 0x7c, a14);  /* 0197 */
  ST32(a1 + 0x78, a15);  /* 019a */
  ST32(a1 + 0x74, a3);  /* 019d */
  __asm__ volatile("" ::: "memory");  /* 01a0: memw */
  a8 = 0;  /* 01a3: l32r -> .text.is_zero_addr+0x0 (link-time addr, kind unclear) */
  a2 = clone_is_zero_addr(a2, a3, a4);  /* 01a6: callx a8 -> clone .text.is_zero_addr */
  a2 = a10;  /* 01a9 */
  a11 = a3;  /* 01ab */
  a9 = LD8U(a3 + 0x1);  /* 01ad */
  a9 = a9 << 8;  /* 01b0 */
  a10 = LD8U(a3 + 0x0);  /* 01b3 */
  a9 = a9 | a10;  /* 01b6 */
  ST32(a1 + 0x50, a9);  /* 01b9 */
  a14 = LD32(a1 + 0x7c);  /* 01bc */
  a15 = LD32(a1 + 0x78);  /* 01bf */
  if (a2 == 0) goto L_0251;  /* 01c2: beqz a2, 251 <mesh_parse_conflict_roots_ie+0x1d1> */
  L_01c5: a10 = a15;  /* 01c5 */
  __asm__ volatile("" ::: "memory");  /* 01c7: memw */
  a8 = (u32)&roots_type2str;  /* 01ca: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4);  /* 01cd: callx a8 via reloc-expand */
  a11 = LD32(a1 + 0x54);  /* 01d0 */
  a12 = 2;  /* 01d3 */
  a15 = LD32(a1 + 0x50);  /* 01d5 */
  ST32(a1 + 0x3c, a11);  /* 01d8 */
  a11 = 1;  /* 01da */
  a11 = a11 << 21;  /* 01dc */
  ST32(a1 + 0x38, a15);  /* 01df */
  a15 = a10;  /* 01e1 */
  a10 = 1;  /* 01e3 */
  a2 = LD8U(a3 + 0x9);  /* 01e5 */
  ST32(a1 + 0x34, a2);  /* 01e8 */
  a2 = LD8U(a3 + 0x8);  /* 01ea */
  ST32(a1 + 0x30, a2);  /* 01ed */
  a2 = LD8U(a3 + 0x7);  /* 01ef */
  ST32(a1 + 0x2c, a2);  /* 01f2 */
  a2 = LD8U(a3 + 0x6);  /* 01f4 */
  ST32(a1 + 0x28, a2);  /* 01f7 */
  a2 = LD8U(a3 + 0x5);  /* 01f9 */
  ST32(a1 + 0x24, a2);  /* 01fc */
  a2 = LD8U(a3 + 0x4);  /* 01fe */
  ST32(a1 + 0x1c, a7);  /* 0201 */
  ST32(a1 + 0x20, a2);  /* 0203 */
  ST32(a1 + 0x18, a6);  /* 0205 */
  a2 = LD8U(a5 + 0x5);  /* 0207 */
  ST32(a1 + 0x14, a2);  /* 020a */
  a2 = LD8U(a5 + 0x4);  /* 020c */
  ST32(a1 + 0x10, a2);  /* 020f */
  a2 = LD8U(a5 + 0x3);  /* 0211 */
  ST32(a1 + 0xc, a2);  /* 0214 */
  a2 = LD8U(a5 + 0x2);  /* 0216 */
  ST32(a1 + 0x8, a2);  /* 0219 */
  a2 = LD8U(a5 + 0x1);  /* 021b */
  ST32(a1 + 0x4, a2);  /* 021e */
  a2 = LD8U(a5 + 0x0);  /* 0220 */
  a14 = 0x000011cau;  /* 0223: l32r = 4554 */
  ST32(a1 + 0x0, a2);  /* 0226 */
  a13 = (u32)(RODATA__rodata_wlog_warning_28 + 0x0);  /* 0228: l32r -> .rodata_wlog_warning.28 */
  __asm__ volatile("" ::: "memory");  /* 022b: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 022e: l32r -> global */
  a2 = wifi_log(a2, a3, a4);  /* 0231: callx a8 via reloc-expand */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0234: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0237 */
  if (a2 == 0) goto L_017a;  /* 0239: beqz a2, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_023c: a3 = LD32(a2 + 0x150);  /* 023c */
  if (a3 == 0) goto L_017a;  /* 023f: beqz a3, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_0242: a10 = LD32(a2 + 0x158);  /* 0242 */
  /* 0245: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 0248: -> "child(cidx:" */
  a2 = 0x000011cfu;  /* 024b: l32r = 4559 */
  goto L_0166;  /* 024e: j */
  L_0251: a8 = LD32(a1 + 0x50);  /* 0251 */
  a9 = LD32(a1 + 0x58);  /* 0254 */
  if (a8 >= a9) goto L_025d;  /* 0257: bgeu a8, a9, 25d <mesh_parse_conflict_roots_ie+0x1dd> */
  L_025a: goto L_0345;  /* 025a: j */
  L_025d: a10 = a15;  /* 025d */
  a8 = (u32)&roots_type2str;  /* 025f: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4);  /* 0262: callx a8 via reloc-expand */
  a11 = LD8U(a3 + 0x6);  /* 0265 */
  a15 = LD8U(a3 + 0x7);  /* 0268 */
  a8 = LD8U(a3 + 0x4);  /* 026b */
  a9 = LD8U(a3 + 0x5);  /* 026e */
  ST32(a1 + 0x5c, a11);  /* 0271 */
  a11 = LD8U(a3 + 0x8);  /* 0274 */
  a3 = LD8U(a3 + 0x9);  /* 0277 */
  a12 = LD8U(a5 + 0x3);  /* 027a */
  a13 = LD8U(a5 + 0x4);  /* 027d */
  a14 = LD8U(a5 + 0x5);  /* 0280 */
  ST32(a1 + 0x60, a15);  /* 0283 */
  ST32(a1 + 0x64, a11);  /* 0286 */
  a15 = LD8U(a5 + 0x0);  /* 0289 */
  a11 = LD8U(a5 + 0x2);  /* 028c */
  ST32(a1 + 0x68, a3);  /* 028f */
  a3 = LD8U(a5 + 0x1);  /* 0292 */
  a5 = LD32(a1 + 0x58);  /* 0295 */
  ST32(a1 + 0x70, a3);  /* 0298 */
  a3 = a5 + (-1);  /* 029b */
  a5 = (u32)&g_mesh_topology + 0x0;  /* 029d: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 02a0 */
  ST32(a1 + 0x6c, a15);  /* 02a2 */
  if (a5 != 0) goto L_02b5;  /* 02a5: bnez.n a5, 2b5 <mesh_parse_conflict_roots_ie+0x235> */
  L_02a7: a5 = LD8U(a4 + 0xf);  /* 02a7 */
  a4 = LD8U(a4 + 0xe);  /* 02aa */
  __asm__ volatile("" ::: "memory");  /* 02ad: memw */
  goto L_02cd;  /* 02b0: j */
  L_02b5: a5 = LD8U(a4 + 0x3d);  /* 02b5 */
  a5 = a5 << 8;  /* 02b8 */
  a15 = LD8U(a4 + 0x3c);  /* 02bb */
  a5 = a5 | a15;  /* 02be */
  a15 = LD8U(a4 + 0x3a);  /* 02c1 */
  a4 = LD8U(a4 + 0x3b);  /* 02c4 */
  a4 = a4 << 8;  /* 02c7 */
  a4 = a4 | a15;  /* 02ca */
  L_02cd: ST32(a1 + 0x20, a11);  /* 02cd */
  a11 = LD32(a1 + 0x6c);  /* 02cf */
  a15 = LD32(a1 + 0x54);  /* 02d2 */
  ST32(a1 + 0x40, a5);  /* 02d5 */
  ST32(a1 + 0x3c, a3);  /* 02d8 */
  a5 = LD32(a1 + 0x70);  /* 02da */
  a3 = LD32(a1 + 0x50);  /* 02dd */
  ST32(a1 + 0x18, a11);  /* 02e0 */
  a11 = LD32(a1 + 0x5c);  /* 02e2 */
  ST32(a1 + 0x48, a15);  /* 02e5 */
  a15 = LD32(a1 + 0x68);  /* 02e8 */
  ST32(a1 + 0x38, a3);  /* 02eb */
  ST32(a1 + 0x2c, a14);  /* 02ed */
  a3 = LD32(a1 + 0x64);  /* 02ef */
  ST32(a1 + 0x28, a13);  /* 02f2 */
  ST32(a1 + 0x1c, a5);  /* 02f4 */
  ST32(a1 + 0x8, a11);  /* 02f6 */
  a11 = 1;  /* 02f8 */
  a11 = a11 << 21;  /* 02fa */
  a5 = LD32(a1 + 0x60);  /* 02fd */
  a14 = 0x000011ddu;  /* 0300: l32r = 4573 */
  a13 = (u32)(RODATA__rodata_wlog_warning_29 + 0x0);  /* 0303: l32r -> .rodata_wlog_warning.29 */
  ST32(a1 + 0x24, a12);  /* 0306 */
  a12 = 2;  /* 0308 */
  ST32(a1 + 0x14, a15);  /* 030a */
  a15 = a10;  /* 030c */
  a10 = 1;  /* 030e */
  ST32(a1 + 0x4, a9);  /* 0310 */
  ST32(a1 + 0x0, a8);  /* 0312 */
  ST32(a1 + 0x10, a3);  /* 0314 */
  ST32(a1 + 0x44, a4);  /* 0316 */
  ST32(a1 + 0x34, a7);  /* 0319 */
  ST32(a1 + 0x30, a6);  /* 031b */
  ST32(a1 + 0xc, a5);  /* 031d */
  __asm__ volatile("" ::: "memory");  /* 031f: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0322: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5);  /* 0325: callx a8 via reloc-expand */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0328: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 032b */
  if (a3 == 0) goto L_017a;  /* 032d: beqz a3, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_0330: a4 = LD32(a3 + 0x150);  /* 0330 */
  if (a4 == 0) goto L_017a;  /* 0333: beqz a4, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_0336: a10 = LD32(a3 + 0x158);  /* 0336 */
  /* 0339: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 033c: -> "child(cidx:" */
  a3 = 0x000011e8u;  /* 033f: l32r = 4584 */
  goto L_0437;  /* 0342: j */
  L_0345: a8 = LD32(a1 + 0x50);  /* 0345 */
  a3 = a3 + (12);  /* 0348 */
  if (a8 != 0) goto L_0451;  /* 034a: bnez a8, 451 <mesh_parse_conflict_roots_ie+0x3d1> */
  L_034d: a10 = a15;  /* 034d: mov */
  ST32(a1 + 0x74, a11);  /* 0350 */
  __asm__ volatile("" ::: "memory");  /* 0353: memw */
  a8 = (u32)&roots_type2str;  /* 0356: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4);  /* 0359: callx a8 via reloc-expand */
  a11 = LD32(a1 + 0x74);  /* 035c */
  a9 = LD8U(a11 + 0x5);  /* 035f */
  a15 = LD8U(a11 + 0x6);  /* 0362 */
  a3 = LD8U(a11 + 0x7);  /* 0365 */
  a8 = LD8U(a11 + 0x4);  /* 0368 */
  ST32(a1 + 0x50, a9);  /* 036b */
  a9 = LD8U(a11 + 0x8);  /* 036e */
  a11 = LD8U(a11 + 0x9);  /* 0371 */
  ST32(a1 + 0x68, a11);  /* 0374 */
  a11 = LD8U(a5 + 0x0);  /* 0377 */
  a12 = LD8U(a5 + 0x3);  /* 037a */
  a13 = LD8U(a5 + 0x4);  /* 037d */
  a14 = LD8U(a5 + 0x5);  /* 0380 */
  ST32(a1 + 0x64, a9);  /* 0383 */
  ST32(a1 + 0x6c, a11);  /* 0386 */
  a9 = LD8U(a5 + 0x1);  /* 0389 */
  a11 = LD8U(a5 + 0x2);  /* 038c */
  a5 = (u32)&g_mesh_topology + 0x0;  /* 038f: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 0392 */
  ST32(a1 + 0x5c, a15);  /* 0394 */
  ST32(a1 + 0x60, a3);  /* 0397 */
  if (a5 != 0) goto L_03a8;  /* 039a: bnez.n a5, 3a8 <mesh_parse_conflict_roots_ie+0x328> */
  L_039c: a5 = LD8U(a4 + 0xf);  /* 039c */
  a4 = LD8U(a4 + 0xe);  /* 039f */
  __asm__ volatile("" ::: "memory");  /* 03a2: memw */
  goto L_03c0;  /* 03a5: j */
  L_03a8: a5 = LD8U(a4 + 0x3d);  /* 03a8 */
  a5 = a5 << 8;  /* 03ab */
  a15 = LD8U(a4 + 0x3c);  /* 03ae */
  a5 = a5 | a15;  /* 03b1 */
  a15 = LD8U(a4 + 0x3a);  /* 03b4 */
  a4 = LD8U(a4 + 0x3b);  /* 03b7 */
  a4 = a4 << 8;  /* 03ba */
  a4 = a4 | a15;  /* 03bd */
  L_03c0: a3 = LD32(a1 + 0x58);  /* 03c0 */
  a15 = LD32(a1 + 0x54);  /* 03c3 */
  ST32(a1 + 0x40, a5);  /* 03c6 */
  a5 = LD32(a1 + 0x6c);  /* 03c9 */
  ST32(a1 + 0x3c, a3);  /* 03cc */
  a3 = 0;  /* 03ce */
  ST32(a1 + 0x20, a11);  /* 03d0 */
  a11 = LD32(a1 + 0x64);  /* 03d2 */
  ST32(a1 + 0x48, a15);  /* 03d5 */
  ST32(a1 + 0x38, a3);  /* 03d8 */
  a15 = LD32(a1 + 0x60);  /* 03da */
  a3 = LD32(a1 + 0x5c);  /* 03dd */
  ST32(a1 + 0x18, a5);  /* 03e0 */
  a5 = LD32(a1 + 0x50);  /* 03e2 */
  ST32(a1 + 0x2c, a14);  /* 03e5 */
  ST32(a1 + 0x28, a13);  /* 03e7 */
  ST32(a1 + 0x1c, a9);  /* 03e9 */
  ST32(a1 + 0x10, a11);  /* 03eb */
  a11 = 1;  /* 03ed */
  a11 = a11 << 21;  /* 03ef */
  a9 = LD32(a1 + 0x68);  /* 03f2 */
  a14 = 0x000011edu;  /* 03f5: l32r = 4589 */
  a13 = (u32)(RODATA__rodata_wlog_warning_30 + 0x0);  /* 03f8: l32r -> .rodata_wlog_warning.30 */
  ST32(a1 + 0x24, a12);  /* 03fb */
  a12 = 2;  /* 03fd */
  ST32(a1 + 0xc, a15);  /* 03ff */
  a15 = a10;  /* 0401 */
  a10 = 1;  /* 0403 */
  ST32(a1 + 0x8, a3);  /* 0405 */
  ST32(a1 + 0x4, a5);  /* 0407 */
  ST32(a1 + 0x0, a8);  /* 0409 */
  ST32(a1 + 0x44, a4);  /* 040b */
  ST32(a1 + 0x34, a7);  /* 040e */
  ST32(a1 + 0x30, a6);  /* 0410 */
  ST32(a1 + 0x14, a9);  /* 0412 */
  __asm__ volatile("" ::: "memory");  /* 0414: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0417: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5);  /* 041a: callx a8 via reloc-expand */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 041d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0420 */
  if (a3 == 0) goto L_017a;  /* 0422: beqz a3, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_0425: a4 = LD32(a3 + 0x150);  /* 0425 */
  if (a4 == 0) goto L_017a;  /* 0428: beqz a4, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_042b: a10 = LD32(a3 + 0x158);  /* 042b */
  /* 042e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 0431: -> "child(cidx:" */
  a3 = 0x000011f8u;  /* 0434: l32r = 4600 */
  L_0437: a13 = a10;  /* 0437 */
  a14 = a11;  /* 0439 */
  a10 = 1;  /* 043b */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 043d: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata__mesh_timer_process_conflict_root_str1_1 + 0x0);  /* 0440: l32r -> .rodata._mesh_timer_process_conflict_root.str1.1 */
  ST32(a1 + 0x0, a3);  /* 0443 */
  __asm__ volatile("" ::: "memory");  /* 0446: memw */
  /* 0449: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0492;  /* 044c: j */
  L_0451: a6 = a6 + (1);  /* 0451 */
  L_0453: if ((i32)a6 >= (i32)a7) goto L_0459;  /* 0453: bge a6, a7, 459 <mesh_parse_conflict_roots_ie+0x3d9> */
  L_0456: goto L_0195;  /* 0456: j */
  L_0459: a12 = a14;  /* 0459 */
  a10 = a15;  /* 045b */
  a13 = a4;  /* 045d: mov */
  a11 = a7;  /* 0460 */
  ST32(a1 + 0x7c, a14);  /* 0462 */
  ST32(a1 + 0x78, a15);  /* 0465 */
  __asm__ volatile("" ::: "memory");  /* 0468: memw */
  a8 = (u32)&mesh_is_new_root_invalid;  /* 046b: l32r -> func addr */
  a2 = mesh_is_new_root_invalid(a2, a3, a4);  /* 046e: callx a8 via reloc-expand */
  a2 = a10;  /* 0471 */
  a14 = LD32(a1 + 0x7c);  /* 0473 */
  a15 = LD32(a1 + 0x78);  /* 0476 */
  if (a10 != 0) goto L_017a;  /* 0479: bnez a10, 17a <mesh_parse_conflict_roots_ie+0xfa> */
  L_047c: a13 = a5;  /* 047c */
  a12 = a14;  /* 047e */
  a11 = a7;  /* 0480: mov */
  a10 = a15;  /* 0483: mov */
  a8 = (u32)&mesh_process_roots_ie;  /* 0486: l32r -> func addr */
  a2 = mesh_process_roots_ie(a2, a3, a4);  /* 0489: callx a8 via reloc-expand */
  goto L_0492;  /* 048c: j */
  L_0490: a2 = -1;  /* 0490 */
  L_0492: return a2;  /* 0492: retw.n */
}


/* mesh_parse_ps_entire_rule @ mesh_quick.o 0000004c size 1086B bind GLOBAL
 * Calls: memcmp, dutytype2str, ieee80211_mesh_quick_get, mesh_nwk_duty_master_is_root | indirect[2]: mem[a2+0x158]; unknown | Data refs: esp_mesh_ps_duty, g_log_level, g_osi_funcs_p, .rodata.mesh_parse_ps_entire_rule.str1.1, esp_mesh_appie, .data.MESH_BCAST_ADDR
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=10); reloc-direct=4, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_parse_ps_entire_rule(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a4, a5, a6, a7, a8, a9;
  float F4;
  /* 004c: entry a1, 176 (frame 176 bytes) */
  a5 = (u32)&esp_mesh_ps_duty + 0x0;  /* 004f: l32r -> global */
  a6 = 0;  /* 0052 */
  ST8(a5 + 0x1a, a6);  /* 0054 */
  __asm__ volatile("" ::: "memory");  /* 0057: memw */
  a6 = LD8U(a3 + 0x4);  /* 005a */
  a6 = a6 << 8;  /* 005d */
  a7 = LD8U(a3 + 0x3);  /* 0060 */
  a6 = a6 | a7;  /* 0063 */
  a7 = LD8U(a3 + 0x5);  /* 0066 */
  a7 = a7 << 16;  /* 0069 */
  a7 = a7 | a6;  /* 006c */
  a6 = LD8U(a3 + 0x6);  /* 006f */
  a6 = a6 << 24;  /* 0072 */
  a6 = a6 | a7;  /* 0075 */
  if (a6 != -1) goto L_00ea;  /* 0078: bnei a6, -1, ea <mesh_parse_ps_entire_rule+0x9e> */
  L_007b: a6 = LD8U(a3 + 0x2);  /* 007b */
  a2 = 1;  /* 007e */
  a4 = LD8U(a5 + 0x2);  /* 0080 */
  if (a6 == a4) goto L_0089;  /* 0083: beq a6, a4, 89 <mesh_parse_ps_entire_rule+0x3d> */
  L_0086: goto L_047c;  /* 0086: j */
  L_0089: a4 = LD8U(a5 + 0x4);  /* 0089 */
  a4 = a4 << 8;  /* 008c */
  a6 = LD8U(a5 + 0x3);  /* 008f */
  a4 = a4 | a6;  /* 0092 */
  a6 = LD8U(a5 + 0x5);  /* 0095 */
  a6 = a6 << 16;  /* 0098 */
  a6 = a6 | a4;  /* 009b */
  a4 = LD8U(a5 + 0x6);  /* 009e */
  a4 = a4 << 24;  /* 00a1 */
  a4 = a4 | a6;  /* 00a4 */
  if (a4 == -1) goto L_00ad;  /* 00a7: beqi a4, -1, ad <mesh_parse_ps_entire_rule+0x61> */
  L_00aa: goto L_047c;  /* 00aa: j */
  L_00ad: a6 = LD8U(a3 + 0xd);  /* 00ad */
  a4 = LD8U(a5 + 0xd);  /* 00b0 */
  if (a6 == a4) goto L_00b9;  /* 00b3: beq a6, a4, b9 <mesh_parse_ps_entire_rule+0x6d> */
  L_00b6: goto L_047c;  /* 00b6: j */
  L_00b9: a6 = LD8U(a3 + 0xf);  /* 00b9 */
  a4 = LD8U(a5 + 0xf);  /* 00bc */
  if (a6 == a4) goto L_00c5;  /* 00bf: beq a6, a4, c5 <mesh_parse_ps_entire_rule+0x79> */
  L_00c2: goto L_047c;  /* 00c2: j */
  L_00c5: a12 = 6;  /* 00c5 */
  a10 = a3 + (7);  /* 00c7 */
  a11 = (u32)&esp_mesh_ps_duty + 0x7;  /* 00c9: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 00cc: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00cf: l32r -> global */
  a2 = memcmp(a2, a3);  /* 00d2: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_047c;  /* 00d5: bnez a10, 47c <mesh_parse_ps_entire_rule+0x430> */
  L_00d8: a4 = LD8U(a3 + 0xe);  /* 00d8 */
  a3 = LD8U(a5 + 0xe);  /* 00db */
  if (a4 == a3) goto L_00e4;  /* 00de: beq a4, a3, e4 <mesh_parse_ps_entire_rule+0x98> */
  L_00e1: goto L_047c;  /* 00e1: j */
  L_00e4: a2 = 0;  /* 00e4 */
  goto L_047c;  /* 00e6: j */
  L_00ea: a7 = -2;  /* 00ea */
  a9 = a3 + (7);  /* 00ec */
  if (a6 == a7) goto L_00f4;  /* 00ee: beq a6, a7, f4 <mesh_parse_ps_entire_rule+0xa8> */
  L_00f1: goto L_02f2;  /* 00f1: j */
  L_00f4: a11 = (u32)&esp_mesh_ps_duty + 0x7;  /* 00f4: l32r -> global */
  a12 = 6;  /* 00f7 */
  a10 = a9;  /* 00f9 */
  a8 = (u32)&memcmp + 0x0;  /* 00fb: l32r -> global */
  a2 = memcmp(a2, a3);  /* 00fe: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0169;  /* 0101: bnez a10, 169 <mesh_parse_ps_entire_rule+0x11d> */
  L_0104: a2 = 1;  /* 0104 */
  if (a4 == 0) a2 = a10;  /* 0106 */
  a2 = (a2 >> 8) & 0x1;  /* 0109: extui width 1 */
  a6 = LD8U(a5 + 0x10);  /* 010c */
  if (a2 == 0) goto L_0114;  /* 010f: beqz.n a2, 114 <mesh_parse_ps_entire_rule+0xc8> */
  L_0111: if (((a6 >> 0) & 1) != 0) goto L_00e4;  /* 0111: bbsi a6, 0, e4 <mesh_parse_ps_entire_rule+0x98> */
  L_0114: if (((a6 >> 1) & 1) == 0) goto L_011a;  /* 0114: bbci a6, 1, 11a <mesh_parse_ps_entire_rule+0xce> */
  L_0117: if (a4 == 0) goto L_00e4;  /* 0117: beqz a4, e4 <mesh_parse_ps_entire_rule+0x98> */
  L_011a: a6 = LD8U(a3 + 0x2);  /* 011a */
  a2 = 2;  /* 011d */
  a4 = LD8U(a5 + 0x2);  /* 011f */
  if (a6 == a4) goto L_0128;  /* 0122: beq a6, a4, 128 <mesh_parse_ps_entire_rule+0xdc> */
  L_0125: goto L_02de;  /* 0125: j */
  L_0128: a4 = LD8U(a5 + 0x4);  /* 0128 */
  a4 = a4 << 8;  /* 012b */
  a6 = LD8U(a5 + 0x3);  /* 012e */
  a4 = a4 | a6;  /* 0131 */
  a6 = LD8U(a5 + 0x5);  /* 0134 */
  a6 = a6 << 16;  /* 0137 */
  a6 = a6 | a4;  /* 013a */
  a4 = LD8U(a5 + 0x6);  /* 013d */
  a4 = a4 << 24;  /* 0140 */
  a4 = a4 | a6;  /* 0143 */
  a6 = -2;  /* 0146 */
  if (a4 == a6) goto L_014e;  /* 0148: beq a4, a6, 14e <mesh_parse_ps_entire_rule+0x102> */
  L_014b: goto L_02de;  /* 014b: j */
  L_014e: a6 = LD8U(a3 + 0xd);  /* 014e */
  a4 = LD8U(a5 + 0xd);  /* 0151 */
  if (a6 == a4) goto L_015a;  /* 0154: beq a6, a4, 15a <mesh_parse_ps_entire_rule+0x10e> */
  L_0157: goto L_02de;  /* 0157: j */
  L_015a: a4 = LD8U(a3 + 0xf);  /* 015a */
  a3 = LD8U(a5 + 0xf);  /* 015d */
  if (a4 == a3) goto L_0166;  /* 0160: beq a4, a3, 166 <mesh_parse_ps_entire_rule+0x11a> */
  L_0163: goto L_02de;  /* 0163: j */
  L_0166: goto L_02dc;  /* 0166: j */
  L_0169: a2 = LD8U(a3 + 0xd);  /* 0169 */
  a5 = LD8U(a5 + 0xd);  /* 016c */
  a2 = a2 - a5;  /* 016f: sub */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 0172: sext */
  if ((i32)a2 >= 1) goto L_017b;  /* 0175: bgei a2, 1, 17b <mesh_parse_ps_entire_rule+0x12f> */
  L_0178: goto L_02dc;  /* 0178: j */
  L_017b: a2 = (u32)&g_log_level + 0x0;  /* 017b: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 017e */
  if (a2 >= 3u) goto L_0186;  /* 0180: bgeui a2, 3, 186 <mesh_parse_ps_entire_rule+0x13a> */
  L_0183: goto L_0298;  /* 0183: j */
  L_0186: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0186: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0189 */
  if (a2 == 0) goto L_0298;  /* 018b: beqz a2, 298 <mesh_parse_ps_entire_rule+0x24c> */
  L_018e: a5 = LD32(a2 + 0x150);  /* 018e */
  if (a5 == 0) goto L_0298;  /* 0191: beqz a5, 298 <mesh_parse_ps_entire_rule+0x24c> */
  L_0194: a10 = LD32(a2 + 0x158);  /* 0194 */
  /* 0197: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a6 = a10;  /* 019a */
  if (a4 != 0) goto L_0470;  /* 019c: bnez a4, 470 <mesh_parse_ps_entire_rule+0x424> */
  L_019f: a2 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 019f: -> "child(cidx:" */
  L_01a2: a8 = LD8U(a3 + 0x7);  /* 01a2 */
  ST32(a1 + 0x50, a8);  /* 01a5 */
  a8 = LD8U(a3 + 0x8);  /* 01a8 */
  ST32(a1 + 0x54, a8);  /* 01ab */
  a8 = LD8U(a3 + 0x9);  /* 01ae */
  ST32(a1 + 0x58, a8);  /* 01b1 */
  a8 = LD8U(a3 + 0xa);  /* 01b4 */
  ST32(a1 + 0x5c, a8);  /* 01b7 */
  a8 = LD8U(a3 + 0xb);  /* 01ba */
  a11 = (u32)&esp_mesh_ps_duty + 0x0;  /* 01bd: l32r -> global */
  ST32(a1 + 0x60, a8);  /* 01c0 */
  a8 = LD8U(a3 + 0xc);  /* 01c3 */
  ST32(a1 + 0x64, a8);  /* 01c6 */
  a8 = LD8U(a11 + 0x7);  /* 01c9 */
  ST32(a1 + 0x68, a8);  /* 01cc */
  a8 = LD8U(a11 + 0x8);  /* 01cf */
  ST32(a1 + 0x6c, a8);  /* 01d2 */
  a8 = LD8U(a11 + 0x9);  /* 01d5 */
  ST32(a1 + 0x70, a8);  /* 01d8 */
  a8 = LD8U(a11 + 0xa);  /* 01db */
  ST32(a1 + 0x74, a8);  /* 01de */
  a8 = LD8U(a11 + 0xb);  /* 01e1 */
  a9 = LD8U(a11 + 0x2);  /* 01e4 */
  a10 = LD8U(a11 + 0x0);  /* 01e7 */
  ST32(a1 + 0x78, a8);  /* 01ea */
  a8 = LD8U(a3 + 0xd);  /* 01ed */
  a7 = LD8U(a11 + 0xc);  /* 01f0 */
  ST32(a1 + 0x88, a8);  /* 01f3 */
  ST32(a1 + 0x8c, a9);  /* 01f6 */
  ST32(a1 + 0x7c, a11);  /* 01f9 */
  __asm__ volatile("" ::: "memory");  /* 01fc: memw */
  a8 = (u32)&dutytype2str + 0x0;  /* 01ff: l32r -> global */
  a2 = dutytype2str(a2, a3);  /* 0202: callx a8 via reloc-expand */
  a12 = a10;  /* 0205 */
  a11 = LD32(a1 + 0x7c);  /* 0207 */
  a14 = LD8U(a3 + 0x2);  /* 020a */
  a13 = LD8U(a11 + 0xf);  /* 020d */
  a10 = LD8U(a3 + 0x0);  /* 0210 */
  ST32(a1 + 0x7c, a12);  /* 0213 */
  ST32(a1 + 0x80, a13);  /* 0216 */
  ST32(a1 + 0x84, a14);  /* 0219 */
  __asm__ volatile("" ::: "memory");  /* 021c: memw */
  a8 = (u32)&dutytype2str + 0x0;  /* 021f: l32r -> global */
  a2 = dutytype2str(a2, a3);  /* 0222: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x88);  /* 0225 */
  a15 = LD8U(a3 + 0xf);  /* 0228 */
  ST32(a1 + 0x34, a8);  /* 022b */
  a8 = LD32(a1 + 0x78);  /* 022d */
  ST32(a1 + 0x2c, a8);  /* 0230 */
  a8 = LD32(a1 + 0x74);  /* 0232 */
  ST32(a1 + 0x28, a8);  /* 0235 */
  a8 = LD32(a1 + 0x70);  /* 0237 */
  ST32(a1 + 0x24, a8);  /* 023a */
  a8 = LD32(a1 + 0x6c);  /* 023c */
  ST32(a1 + 0x20, a8);  /* 023f */
  a8 = LD32(a1 + 0x68);  /* 0241 */
  ST32(a1 + 0x1c, a8);  /* 0244 */
  a8 = LD32(a1 + 0x64);  /* 0246 */
  ST32(a1 + 0x18, a8);  /* 0249 */
  a8 = LD32(a1 + 0x60);  /* 024b */
  ST32(a1 + 0x14, a8);  /* 024e */
  a8 = LD32(a1 + 0x5c);  /* 0250 */
  a14 = LD32(a1 + 0x84);  /* 0253 */
  a13 = LD32(a1 + 0x80);  /* 0256 */
  a12 = LD32(a1 + 0x7c);  /* 0259 */
  a9 = LD32(a1 + 0x8c);  /* 025c */
  ST32(a1 + 0x10, a8);  /* 025f */
  a8 = LD32(a1 + 0x58);  /* 0261 */
  ST32(a1 + 0x4c, a15);  /* 0264 */
  a15 = a2;  /* 0267 */
  ST32(a1 + 0x48, a10);  /* 0269 */
  a10 = 3;  /* 026c */
  ST32(a1 + 0x44, a14);  /* 026e */
  ST32(a1 + 0x40, a13);  /* 0271 */
  a13 = a6;  /* 0274 */
  ST32(a1 + 0x3c, a12);  /* 0276 */
  ST32(a1 + 0x38, a9);  /* 0278 */
  ST32(a1 + 0x30, a7);  /* 027a */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 027c: -> "child(cidx:" */
  a14 = a11;  /* 027f */
  ST32(a1 + 0xc, a8);  /* 0281 */
  a8 = LD32(a1 + 0x54);  /* 0283 */
  ST32(a1 + 0x8, a8);  /* 0286 */
  a8 = LD32(a1 + 0x50);  /* 0288 */
  a12 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 028b: -> "child(cidx:" */
  ST32(a1 + 0x4, a8);  /* 028e */
  ST32(a1 + 0x0, a4);  /* 0290 */
  __asm__ volatile("" ::: "memory");  /* 0292: memw */
  /* 0295: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_0298: a2 = (u32)&esp_mesh_ps_duty + 0x0;  /* 0298: l32r -> global */
  a3 = LD8U(a3 + 0xd);  /* 029b */
  a4 = LD8U(a2 + 0x4);  /* 029e */
  a4 = a4 << 8;  /* 02a1 */
  ST8(a2 + 0xd, a3);  /* 02a4 */
  __asm__ volatile("" ::: "memory");  /* 02a7: memw */
  a3 = LD8U(a2 + 0x3);  /* 02aa */
  a4 = a4 | a3;  /* 02ad */
  a3 = LD8U(a2 + 0x5);  /* 02b0 */
  a3 = a3 << 16;  /* 02b3 */
  a3 = a3 | a4;  /* 02b6 */
  a2 = LD8U(a2 + 0x6);  /* 02b9 */
  a2 = a2 << 24;  /* 02bc */
  a2 = a2 | a3;  /* 02bf */
  a3 = -2;  /* 02c2 */
  if (a2 != a3) goto L_02dc;  /* 02c4: bne a2, a3, 2dc <mesh_parse_ps_entire_rule+0x290> */
  L_02c7: a2 = (u32)&esp_mesh_appie + 0x0;  /* 02c7: l32r -> global */
  a11 = 15;  /* 02ca */
  a10 = LD32(a2 + 0x0);  /* 02cc */
  a10 = a10 + (2);  /* 02ce */
  a12 = (u32)&esp_mesh_ps_duty + 0x7;  /* 02d0: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 02d3: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 02d6: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3);  /* 02d9: callx a8 via reloc-expand */
  L_02dc: a2 = 0;  /* 02dc */
  L_02de: a4 = 2;  /* 02de */
  a3 = (u32)&esp_mesh_ps_duty + 0x0;  /* 02e0: l32r -> global */
  ST8(a3 + 0x1a, a4);  /* 02e3 */
  __asm__ volatile("" ::: "memory");  /* 02e6: memw */
  __asm__ volatile("" ::: "memory");  /* 02e9: memw */
  goto L_047c;  /* 02ec: j */
  L_02f2: a10 = a9;  /* 02f2 */
  ST32(a1 + 0x8c, a9);  /* 02f4 */
  __asm__ volatile("" ::: "memory");  /* 02f7: memw */
  a8 = (u32)&mesh_nwk_duty_master_is_root;  /* 02fa: l32r -> func addr */
  a2 = mesh_nwk_duty_master_is_root(a2, a3);  /* 02fd: callx a8 via reloc-expand */
  a8 = LD8U(a5 + 0x2);  /* 0300 */
  a7 = LD8U(a3 + 0x2);  /* 0303 */
  a9 = LD32(a1 + 0x8c);  /* 0306 */
  if (a10 == 0) goto L_0379;  /* 0309: beqz a10, 379 <mesh_parse_ps_entire_rule+0x32d> */
  L_030c: a10 = a2;  /* 030c */
  a12 = 6;  /* 030e */
  a2 = 1;  /* 0310 */
  a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 0313: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  ST32(a1 + 0x88, a8);  /* 0316 */
  __asm__ volatile("" ::: "memory");  /* 0319: memw */
  a8 = (u32)&memcmp + 0x0;  /* 031c: l32r -> global */
  a2 = memcmp(a2, a3);  /* 031f: callx a8 (libc, via reloc-expand) */
  a11 = 0;  /* 0322 */
  if (a10 == 0) a11 = a2;  /* 0324 */
  a10 = (a11 >> 8) & 0x1;  /* 0327: extui width 1 */
  a8 = LD32(a1 + 0x88);  /* 032a */
  a9 = LD32(a1 + 0x8c);  /* 032d */
  if (a11 != 0) goto L_0338;  /* 0330: bnez.n a11, 338 <mesh_parse_ps_entire_rule+0x2ec> */
  L_0332: if (a4 != 0) a2 = a10;  /* 0332 */
  if (a2 == 0) goto L_0379;  /* 0335: beqz a2, 379 <mesh_parse_ps_entire_rule+0x32d> */
  L_0338: a2 = 3;  /* 0338 */
  if (a7 == a8) goto L_0340;  /* 033a: beq a7, a8, 340 <mesh_parse_ps_entire_rule+0x2f4> */
  L_033d: goto L_047c;  /* 033d: j */
  L_0340: a4 = LD8U(a5 + 0x4);  /* 0340 */
  a4 = a4 << 8;  /* 0343 */
  a7 = LD8U(a5 + 0x3);  /* 0346 */
  a4 = a4 | a7;  /* 0349 */
  a7 = LD8U(a5 + 0x5);  /* 034c */
  a7 = a7 << 16;  /* 034f */
  a7 = a7 | a4;  /* 0352 */
  a4 = LD8U(a5 + 0x6);  /* 0355 */
  a4 = a4 << 24;  /* 0358 */
  a4 = a4 | a7;  /* 035b */
  if (a6 == a4) goto L_0364;  /* 035e: beq a6, a4, 364 <mesh_parse_ps_entire_rule+0x318> */
  L_0361: goto L_047c;  /* 0361: j */
  L_0364: a6 = LD8U(a3 + 0xd);  /* 0364 */
  a4 = LD8U(a5 + 0xd);  /* 0367 */
  if (a6 == a4) goto L_0370;  /* 036a: beq a6, a4, 370 <mesh_parse_ps_entire_rule+0x324> */
  L_036d: goto L_047c;  /* 036d: j */
  L_0370: a4 = LD8U(a3 + 0xf);  /* 0370 */
  a3 = LD8U(a5 + 0xf);  /* 0373 */
  goto L_03ed;  /* 0376: j */
  L_0379: a2 = LD8U(a3 + 0x0);  /* 0379 */
  if (((a2 >> 7) & 1) != 0) goto L_039e;  /* 037c: bbsi a2, 7, 39e <mesh_parse_ps_entire_rule+0x352> */
  L_037f: a10 = a9;  /* 037f */
  a12 = 6;  /* 0381 */
  a11 = (u32)&esp_mesh_ps_duty + 0x7;  /* 0383: l32r -> global */
  ST32(a1 + 0x88, a8);  /* 0386 */
  ST32(a1 + 0x8c, a9);  /* 0389 */
  __asm__ volatile("" ::: "memory");  /* 038c: memw */
  a8 = (u32)&memcmp + 0x0;  /* 038f: l32r -> global */
  a2 = memcmp(a2, a3);  /* 0392: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x88);  /* 0395 */
  a9 = LD32(a1 + 0x8c);  /* 0398 */
  if (a10 != 0) goto L_0408;  /* 039b: bnez a10, 408 <mesh_parse_ps_entire_rule+0x3bc> */
  L_039e: a4 = LD8U(a5 + 0xf);  /* 039e */
  if (a4 != 1) goto L_03b2;  /* 03a1: bnei a4, 1, 3b2 <mesh_parse_ps_entire_rule+0x366> */
  L_03a4: if (a8 < a7) goto L_03a9;  /* 03a4: bltu a8, a7, 3a9 <mesh_parse_ps_entire_rule+0x35d> */
  L_03a7: a4 = 0;  /* 03a7 */
  L_03a9: a4 = a4 << 2;  /* 03a9 */
  goto L_0453;  /* 03ac: j */
  L_03b2: a2 = 5;  /* 03b2 */
  if (a7 == a8) goto L_03ba;  /* 03b4: beq a7, a8, 3ba <mesh_parse_ps_entire_rule+0x36e> */
  L_03b7: goto L_047c;  /* 03b7: j */
  L_03ba: a7 = LD8U(a5 + 0x4);  /* 03ba */
  a7 = a7 << 8;  /* 03bd */
  a8 = LD8U(a5 + 0x3);  /* 03c0 */
  a7 = a7 | a8;  /* 03c3 */
  a8 = LD8U(a5 + 0x5);  /* 03c6 */
  a8 = a8 << 16;  /* 03c9 */
  a8 = a8 | a7;  /* 03cc */
  a7 = LD8U(a5 + 0x6);  /* 03cf */
  a7 = a7 << 24;  /* 03d2 */
  a7 = a7 | a8;  /* 03d5 */
  if (a6 == a7) goto L_03de;  /* 03d8: beq a6, a7, 3de <mesh_parse_ps_entire_rule+0x392> */
  L_03db: goto L_047c;  /* 03db: j */
  L_03de: a6 = LD8U(a3 + 0xd);  /* 03de */
  a5 = LD8U(a5 + 0xd);  /* 03e1 */
  if (a6 == a5) goto L_03ea;  /* 03e4: beq a6, a5, 3ea <mesh_parse_ps_entire_rule+0x39e> */
  L_03e7: goto L_047c;  /* 03e7: j */
  L_03ea: a3 = LD8U(a3 + 0xf);  /* 03ea */
  L_03ed: if (a3 == a4) goto L_03f3;  /* 03ed: beq a3, a4, 3f3 <mesh_parse_ps_entire_rule+0x3a7> */
  L_03f0: goto L_047c;  /* 03f0: j */
  L_03f3: a12 = 6;  /* 03f3 */
  a10 = a9;  /* 03f5 */
  a11 = (u32)&esp_mesh_ps_duty + 0x7;  /* 03f7: l32r -> global */
  a8 = (u32)&memcmp + 0x0;  /* 03fa: l32r -> global */
  a2 = memcmp(a2, a3);  /* 03fd: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_00e4;  /* 0400: beqz a10, e4 <mesh_parse_ps_entire_rule+0x98> */
  L_0403: goto L_047c;  /* 0403: j */
  L_0408: a4 = LD8U(a5 + 0x4);  /* 0408 */
  a4 = a4 << 8;  /* 040b */
  a2 = LD8U(a5 + 0x3);  /* 040e */
  a4 = a4 | a2;  /* 0411 */
  a2 = LD8U(a5 + 0x5);  /* 0414 */
  a2 = a2 << 16;  /* 0417 */
  a2 = a2 | a4;  /* 041a */
  a4 = LD8U(a5 + 0x6);  /* 041d */
  a4 = a4 << 24;  /* 0420 */
  a4 = a4 | a2;  /* 0423 */
  if (a7 == a8) goto L_0459;  /* 0426: beq a7, a8, 459 <mesh_parse_ps_entire_rule+0x40d> */
  L_0429: a2 = 6;  /* 0429 */
  if ((i32)a4 < 0) goto L_047c;  /* 042b: bltz a4, 47c <mesh_parse_ps_entire_rule+0x430> */
  L_042e: a2 = 7;  /* 042e */
  if (a8 < a7) goto L_047c;  /* 0430: bltu a8, a7, 47c <mesh_parse_ps_entire_rule+0x430> */
  L_0433: a4 = LD8U(a5 + 0xf);  /* 0433 */
  a2 = 0;  /* 0436 */
  if (a4 == 1) goto L_047c;  /* 0438: beqi a4, 1, 47c <mesh_parse_ps_entire_rule+0x430> */
  L_043b: a4 = LD8U(a5 + 0xd);  /* 043b */
  a3 = LD8U(a3 + 0xd);  /* 043e */
  a3 = a3 - a4;  /* 0441: sub */
  a3 = (i32)(a3 << (32 - 7)) >> (32 - 7);  /* 0444: sext */
  a4 = 1;  /* 0447 */
  if ((i32)a3 >= 5) goto L_0450;  /* 044a: bgei a3, 5, 450 <mesh_parse_ps_entire_rule+0x404> */
  L_044d: a4 = a2;  /* 044d: mov */
  L_0450: a4 = a4 << 3;  /* 0450 */
  L_0453: a2 = (a4 >> 8) & 0x1;  /* 0453: extui width 1 */
  goto L_047c;  /* 0456: j */
  L_0459: a2 = 9;  /* 0459 */
  if ((i32)a4 < (i32)a6) goto L_047c;  /* 045b: blt a4, a6, 47c <mesh_parse_ps_entire_rule+0x430> */
  L_045e: a3 = LD8U(a3 + 0xd);  /* 045e */
  a2 = LD8U(a5 + 0xd);  /* 0461 */
  if (a3 != a2) goto L_046a;  /* 0464: bne a3, a2, 46a <mesh_parse_ps_entire_rule+0x41e> */
  L_0467: goto L_00e4;  /* 0467: j */
  L_046a: a2 = 10;  /* 046a */
  goto L_047c;  /* 046c: j */
  L_0470: a4 = LD8U(a4 + 0x0);  /* 0470 */
  a4 = a4 + (-1);  /* 0473 */
  a2 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 0475: -> "child(cidx:" */
  goto L_01a2;  /* 0478: j */
  L_047c: a3 = (u32)&esp_mesh_ps_duty + 0x0;  /* 047c: l32r -> global */
  ST8(a3 + 0x19, a2);  /* 047f */
  __asm__ volatile("" ::: "memory");  /* 0482: memw */
  __asm__ volatile("" ::: "memory");  /* 0485: memw */
  return a2;  /* 0488: retw.n */
}


/* mesh_parse_ps_uplink_rule @ mesh_quick.o 00000030 size 471B bind GLOBAL
 * Calls: memcmp, dutytype2str, ieee80211_mesh_quick_get, mesh_nwk_duty_post_event | indirect[2]: mem[a2+0x158]; unknown | Data refs: esp_mesh_ps_duty, g_log_level, g_osi_funcs_p, .rodata.mesh_parse_ps_entire_rule.str1.1, .rodata.mesh_parse_ps_uplink_rule.str1.1, esp_mesh_appie
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=10); reloc-direct=4, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_parse_ps_uplink_rule(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0030: entry a1, 80 (frame 80 bytes) */
  a5 = (u32)&esp_mesh_ps_duty + 0x0;  /* 0033: l32r -> global */
  a6 = 0;  /* 0036 */
  ST8(a5 + 0x1a, a6);  /* 0038 */
  __asm__ volatile("" ::: "memory");  /* 003b: memw */
  if (a4 == 0) goto L_0119;  /* 003e: beqz a4, 119 <mesh_parse_ps_uplink_rule+0xe9> */
  L_0041: a12 = 6;  /* 0041 */
  a11 = a3 + (7);  /* 0043 */
  a10 = (u32)&esp_mesh_ps_duty + 0x7;  /* 0045: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0048: memw */
  a8 = (u32)&memcmp + 0x0;  /* 004b: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 004e: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a5 + 0x2);  /* 0051 */
  a4 = LD8U(a3 + 0x2);  /* 0054 */
  if (a10 != 0) goto L_00bf;  /* 0057: bnez a10, bf <mesh_parse_ps_uplink_rule+0x8f> */
  L_005a: a2 = 1;  /* 005a */
  if (a4 == a8) goto L_0062;  /* 005c: beq a4, a8, 62 <mesh_parse_ps_uplink_rule+0x32> */
  L_005f: goto L_01fc;  /* 005f: j */
  L_0062: a9 = LD8U(a3 + 0x4);  /* 0062 */
  a9 = a9 << 8;  /* 0065 */
  a4 = LD8U(a3 + 0x3);  /* 0068 */
  a9 = a9 | a4;  /* 006b */
  a8 = LD8U(a3 + 0x5);  /* 006e */
  a8 = a8 << 16;  /* 0071 */
  a8 = a8 | a9;  /* 0074 */
  a9 = LD8U(a3 + 0x6);  /* 0077 */
  a9 = a9 << 24;  /* 007a */
  a9 = a9 | a8;  /* 007d */
  a8 = LD8U(a5 + 0x4);  /* 0080 */
  a8 = a8 << 8;  /* 0083 */
  a4 = LD8U(a5 + 0x3);  /* 0086 */
  a8 = a8 | a4;  /* 0089 */
  a10 = LD8U(a5 + 0x5);  /* 008c */
  a10 = a10 << 16;  /* 008f */
  a10 = a10 | a8;  /* 0092 */
  a8 = LD8U(a5 + 0x6);  /* 0095 */
  a8 = a8 << 24;  /* 0098 */
  a8 = a8 | a10;  /* 009b */
  if (a9 == a8) goto L_00a4;  /* 009e: beq a9, a8, a4 <mesh_parse_ps_uplink_rule+0x74> */
  L_00a1: goto L_01fc;  /* 00a1: j */
  L_00a4: a6 = LD8U(a3 + 0xd);  /* 00a4 */
  a4 = LD8U(a5 + 0xd);  /* 00a7 */
  if (a6 == a4) goto L_00b0;  /* 00aa: beq a6, a4, b0 <mesh_parse_ps_uplink_rule+0x80> */
  L_00ad: goto L_01fc;  /* 00ad: j */
  L_00b0: a4 = LD8U(a3 + 0xf);  /* 00b0 */
  a3 = LD8U(a5 + 0xf);  /* 00b3 */
  if (a4 == a3) goto L_00bc;  /* 00b6: beq a4, a3, bc <mesh_parse_ps_uplink_rule+0x8c> */
  L_00b9: goto L_01fc;  /* 00b9: j */
  L_00bc: goto L_01de;  /* 00bc: j */
  L_00bf: if (a4 == a8) goto L_00d1;  /* 00bf: beq a4, a8, d1 <mesh_parse_ps_uplink_rule+0xa1> */
  L_00c2: a2 = 1;  /* 00c2 */
  if (a8 < a4) goto L_00c9;  /* 00c4: bltu a8, a4, c9 <mesh_parse_ps_uplink_rule+0x99> */
  L_00c7: a2 = a6;  /* 00c7 */
  L_00c9: a2 = a2 + a2;  /* 00c9 */
  a2 = (a2 >> 8) & 0x1;  /* 00cb: extui width 1 */
  goto L_01fc;  /* 00ce: j */
  L_00d1: a8 = LD8U(a3 + 0x4);  /* 00d1 */
  a8 = a8 << 8;  /* 00d4 */
  a2 = LD8U(a3 + 0x3);  /* 00d7 */
  a8 = a8 | a2;  /* 00da */
  a2 = LD8U(a3 + 0x5);  /* 00dd */
  a2 = a2 << 16;  /* 00e0 */
  a2 = a2 | a8;  /* 00e3 */
  a3 = LD8U(a3 + 0x6);  /* 00e6 */
  a3 = a3 << 24;  /* 00e9 */
  a3 = a3 | a2;  /* 00ec */
  a8 = LD8U(a5 + 0x4);  /* 00ef */
  a8 = a8 << 8;  /* 00f2 */
  a2 = LD8U(a5 + 0x3);  /* 00f5 */
  a8 = a8 | a2;  /* 00f8 */
  a2 = LD8U(a5 + 0x5);  /* 00fb */
  a2 = a2 << 16;  /* 00fe */
  a2 = a2 | a8;  /* 0101 */
  a8 = LD8U(a5 + 0x6);  /* 0104 */
  a8 = a8 << 24;  /* 0107 */
  a8 = a8 | a2;  /* 010a */
  a2 = 3;  /* 010d */
  if ((i32)a8 < (i32)a3) goto L_0115;  /* 010f: blt a8, a3, 115 <mesh_parse_ps_uplink_rule+0xe5> */
  L_0112: goto L_01de;  /* 0112: j */
  L_0115: goto L_01fc;  /* 0115: j */
  L_0119: a10 = LD8U(a3 + 0xd);  /* 0119 */
  a9 = LD8U(a5 + 0xd);  /* 011c */
  a8 = a10 - a9;  /* 011f: sub */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 0122: sext */
  if ((i32)a8 >= 1) goto L_012b;  /* 0125: bgei a8, 1, 12b <mesh_parse_ps_uplink_rule+0xfb> */
  L_0128: goto L_01e5;  /* 0128: j */
  L_012b: a2 = (u32)&g_log_level + 0x0;  /* 012b: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 012e */
  if (a2 < 3u) goto L_019d;  /* 0130: bltui a2, 3, 19d <mesh_parse_ps_uplink_rule+0x16d> */
  L_0133: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0133: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0136 */
  if (a2 == 0) goto L_019d;  /* 0139: beqz a2, 19d <mesh_parse_ps_uplink_rule+0x16d> */
  L_013c: a4 = LD32(a2 + 0x150);  /* 013c */
  if (a4 == 0) goto L_019d;  /* 013f: beqz a4, 19d <mesh_parse_ps_uplink_rule+0x16d> */
  L_0142: a10 = LD32(a2 + 0x158);  /* 0142 */
  /* 0145: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 0148: mov */
  a10 = LD8U(a5 + 0x0);  /* 014b */
  a6 = LD8U(a3 + 0xd);  /* 014e */
  a7 = LD8U(a5 + 0x2);  /* 0151 */
  a8 = (u32)&dutytype2str + 0x0;  /* 0154: l32r -> global */
  a2 = dutytype2str(a2, a3, a4, a5, a6, a7);  /* 0157: callx a8 via reloc-expand */
  a8 = a10;  /* 015a */
  a9 = LD8U(a5 + 0xf);  /* 015c */
  a12 = LD8U(a3 + 0x2);  /* 015f */
  a10 = LD8U(a3 + 0x0);  /* 0162 */
  ST32(a1 + 0x20, a8);  /* 0165 */
  ST32(a1 + 0x24, a9);  /* 0167 */
  ST32(a1 + 0x28, a12);  /* 0169 */
  __asm__ volatile("" ::: "memory");  /* 016b: memw */
  a8 = (u32)&dutytype2str + 0x0;  /* 016e: l32r -> global */
  a2 = dutytype2str(a2, a3, a4, a5, a6, a7);  /* 0171: callx a8 via reloc-expand */
  a15 = a6;  /* 0174 */
  a12 = LD32(a1 + 0x28);  /* 0176 */
  a13 = LD8U(a3 + 0xf);  /* 0178 */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 017b: -> "child(cidx:" */
  a14 = a11;  /* 017e */
  a9 = LD32(a1 + 0x24);  /* 0180 */
  a8 = LD32(a1 + 0x20);  /* 0182 */
  ST32(a1 + 0xc, a12);  /* 0184 */
  a12 = (u32)(RODATA__rodata_mesh_parse_ps_uplink_rule_str1_1 + 0x0);  /* 0186: l32r -> .rodata.mesh_parse_ps_uplink_rule.str1.1 */
  ST32(a1 + 0x14, a13);  /* 0189 */
  a13 = a2;  /* 018b */
  ST32(a1 + 0x10, a10);  /* 018d */
  a10 = 3;  /* 018f */
  ST32(a1 + 0x8, a9);  /* 0191 */
  ST32(a1 + 0x4, a8);  /* 0193 */
  ST32(a1 + 0x0, a7);  /* 0195 */
  __asm__ volatile("" ::: "memory");  /* 0197: memw */
  /* 019a: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_019d: a2 = LD8U(a3 + 0xd);  /* 019d */
  ST8(a5 + 0xd, a2);  /* 01a0 */
  __asm__ volatile("" ::: "memory");  /* 01a3: memw */
  a2 = LD8U(a5 + 0x4);  /* 01a6 */
  a2 = a2 << 8;  /* 01a9 */
  a3 = LD8U(a5 + 0x3);  /* 01ac */
  a2 = a2 | a3;  /* 01af */
  a3 = LD8U(a5 + 0x5);  /* 01b2 */
  a3 = a3 << 16;  /* 01b5 */
  a3 = a3 | a2;  /* 01b8 */
  a2 = LD8U(a5 + 0x6);  /* 01bb */
  a2 = a2 << 24;  /* 01be */
  a2 = a2 | a3;  /* 01c1 */
  a3 = -2;  /* 01c4 */
  if (a2 != a3) goto L_01de;  /* 01c6: bne a2, a3, 1de <mesh_parse_ps_uplink_rule+0x1ae> */
  L_01c9: a2 = (u32)&esp_mesh_appie + 0x0;  /* 01c9: l32r -> global */
  a11 = 15;  /* 01cc */
  a10 = LD32(a2 + 0x0);  /* 01ce */
  a10 = a10 + (2);  /* 01d0 */
  a12 = (u32)&esp_mesh_ps_duty + 0x7;  /* 01d2: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 01d5: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 01d8: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 01db: callx a8 via reloc-expand */
  L_01de: a2 = 0;  /* 01de */
  goto L_01fc;  /* 01e0: j */
  L_01e5: if (a10 != a9) goto L_01de;  /* 01e5: bne a10, a9, 1de <mesh_parse_ps_uplink_rule+0x1ae> */
  L_01e8: a6 = LD8U(a5 + 0x0);  /* 01e8 */
  if (((a6 >> 7) & 1) == 0) goto L_01de;  /* 01eb: bbci a6, 7, 1de <mesh_parse_ps_uplink_rule+0x1ae> */
  L_01ee: a11 = a2;  /* 01ee */
  a12 = a3;  /* 01f0 */
  a10 = a4;  /* 01f2 */
  a8 = (u32)&mesh_nwk_duty_post_event;  /* 01f4: l32r -> func addr */
  a2 = mesh_nwk_duty_post_event(a2, a3, a4, a5, a6, a7);  /* 01f7: callx a8 via reloc-expand */
  a2 = a4;  /* 01fa */
  L_01fc: ST8(a5 + 0x19, a2);  /* 01fc */
  __asm__ volatile("" ::: "memory");  /* 01ff: memw */
  __asm__ volatile("" ::: "memory");  /* 0202: memw */
  return a2;  /* 0205: retw.n */
}


/* mesh_post_parent_assoc_ie @ mesh_quick.o 00000014 size 202B bind GLOBAL
 * Calls: memset, wifi_mesh_event_post | indirect[4]: mem[a8+0x110]; mem[a6+0x110] | Data refs: .bss.s_parent_monitor_assoc_time, g_osi_funcs_p
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_post_parent_assoc_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0014: entry a1, 80 (frame 80 bytes) */
  a5 = (u32)&LOCAL__bss_s_parent_monitor_assoc_time + 0x0;  /* 0017: l32r -> .bss.s_parent_monitor_assoc_time (same-object static) */
  a2 = (a2 >> 16) & 0x1;  /* 001a: extui width 1 */
  a3 = (a3 >> 8) & 0x1;  /* 001d: extui width 1 */
  a6 = LD32(a5 + 0x4);  /* 0020 */
  a8 = LD32(a5 + 0x0);  /* 0022 */
  a8 = a8 | a6;  /* 0024 */
  a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0027: l32r -> global */
  if (a8 != 0) goto L_003a;  /* 002a: bnez a8, 3a <mesh_post_parent_assoc_ie+0x26> */
  L_002d: a8 = LD32(a6 + 0x0);  /* 002d */
  a10 = LD32(a8 + 0x110);  /* 0030 */
  /* 0033: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  ST32(a5 + 0x0, a10);  /* 0036 */
  ST32(a5 + 0x4, a11);  /* 0038 */
  L_003a: a8 = LD32(a6 + 0x0);  /* 003a */
  a10 = LD32(a8 + 0x110);  /* 003c */
  __asm__ volatile("" ::: "memory");  /* 003f: memw */
  /* 0042: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = LD32(a5 + 0x4);  /* 0045 */
  if ((i32)a11 < (i32)a8) goto L_0072;  /* 0047: blt a11, a8, 72 <mesh_post_parent_assoc_ie+0x5e> */
  L_004a: if (a8 != a11) goto L_0052;  /* 004a: bne a8, a11, 52 <mesh_post_parent_assoc_ie+0x3e> */
  L_004d: a8 = LD32(a5 + 0x0);  /* 004d */
  if (a10 < a8) goto L_0072;  /* 004f: bltu a10, a8, 72 <mesh_post_parent_assoc_ie+0x5e> */
  L_0052: a6 = LD32(a6 + 0x0);  /* 0052 */
  a10 = LD32(a6 + 0x110);  /* 0054 */
  a6 = 1;  /* 0057 */
  /* 0059: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a5 + 0x0);  /* 005c */
  a9 = a10 - a9;  /* 005e: sub */
  a8 = LD32(a5 + 0x4);  /* 0061 */
  if (a10 < a9) goto L_0068;  /* 0063: bltu a10, a9, 68 <mesh_post_parent_assoc_ie+0x54> */
  L_0066: a6 = 0;  /* 0066 */
  L_0068: a8 = a11 - a8;  /* 0068: sub */
  a8 = a8 - a6;  /* 006b: sub */
  goto L_009c;  /* 006e: j */
  L_0072: a6 = LD32(a6 + 0x0);  /* 0072 */
  a10 = LD32(a6 + 0x110);  /* 0074 */
  a6 = -1;  /* 0077 */
  /* 007a: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a5 + 0x0);  /* 007d */
  a9 = a9 ^ a6;  /* 007f */
  a10 = a9 + a10;  /* 0082 */
  a6 = 1;  /* 0084 */
  a8 = LD32(a5 + 0x4);  /* 0086 */
  if (a10 < a9) goto L_008d;  /* 0088: bltu a10, a9, 8d <mesh_post_parent_assoc_ie+0x79> */
  L_008b: a6 = 0;  /* 008b */
  L_008d: a11 = a8 + a11;  /* 008d */
  a9 = a10 + (1);  /* 008f */
  a11 = a6 + a11;  /* 0091 */
  a8 = 1;  /* 0093 */
  if (a9 < a10) goto L_009a;  /* 0095: bltu a9, a10, 9a <mesh_post_parent_assoc_ie+0x86> */
  L_0098: a8 = 0;  /* 0098 */
  L_009a: a8 = a8 + a11;  /* 009a */
  L_009c: a8 = a8 << 22;  /* 009c */
  a9 = a9 >> 10;  /* 009f */
  a6 = 0x0001d4bfu;  /* 00a2: l32r = 119999 */
  a8 = a8 | a9;  /* 00a5 */
  if (a6 >= a8) goto L_00dc;  /* 00a8: bgeu a6, a8, dc <mesh_post_parent_assoc_ie+0xc8> */
  L_00ab: a8 = 0;  /* 00ab */
  a12 = 43;  /* 00ad */
  a11 = a8;  /* 00af */
  a10 = a1 + (4);  /* 00b1 */
  ST32(a5 + 0x0, a8);  /* 00b3 */
  ST32(a5 + 0x4, a8);  /* 00b5 */
  __asm__ volatile("" ::: "memory");  /* 00b8: memw */
  a8 = (u32)&memset + 0x0;  /* 00bb: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00be: callx a8 (libc, via reloc-expand) */
  a12 = 47;  /* 00c1 */
  a11 = a1;  /* 00c3 */
  a10 = 63;  /* 00c5 */
  ST16(a1 + 0x0, a2);  /* 00c7 */
  ST8(a1 + 0x2, a4);  /* 00ca */
  ST8(a1 + 0x3, a3);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00d0: memw */
  __asm__ volatile("" ::: "memory");  /* 00d3: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 00d6: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 00d9: callx a8 via reloc-expand */
  L_00dc: return a2;  /* 00dc: retw.n */
}


/* mesh_post_parent_switch_candidate @ mesh_quick.o 0000004c size 783B bind GLOBAL
 * Calls: memset, wifi_mesh_event_post, wifi_log, memcpy | indirect[9]: mem[a6+0x110]; mem[a4+0x110] | Data refs: .bss.s_mesh_parent_candidate, g_osi_funcs_p, .bss.s_parent_monitor_weak_time, .bss.s_parent_monitor_assoc_time, g_mesh_topology, g_mesh_cfg_switch_parent, .rodata_wlog_info.32, .rodata.mesh_post_parent_switch_candidate.str1.1, .rodata_wlog_warning.33
 * Fidelity: medium - 9 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=13); reloc-direct=4, funcdb-attributed=0, unknown-indirect=9 */
u32 mesh_post_parent_switch_candidate(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F5, F8;
  /* 004c: entry a1, 160 (frame 160 bytes) */
  a12 = 47;  /* 004f */
  a11 = 0;  /* 0051 */
  a10 = a1 + (64);  /* 0053 */
  ST32(a1 + 0x70, a3);  /* 0056 */
  a4 = (a4 >> 8) & 0x1;  /* 0059: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 005c: memw */
  a8 = (u32)&memset + 0x0;  /* 005f: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0062: callx a8 (libc, via reloc-expand) */
  if (a2 == 0) goto L_0359;  /* 0065: beqz a2, 359 <mesh_post_parent_switch_candidate+0x30d> */
  L_0068: a5 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 0068: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a6 = LD32(a5 + 0xa0);  /* 006b */
  a7 = LD32(a5 + 0xa4);  /* 006e */
  a6 = a6 | a7;  /* 0071 */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0074: l32r -> global */
  if (a6 != 0) goto L_0087;  /* 0077: bnez.n a6, 87 <mesh_post_parent_switch_candidate+0x3b> */
  L_0079: a6 = LD32(a3 + 0x0);  /* 0079 */
  a10 = LD32(a6 + 0x110);  /* 007b */
  /* 007e: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  ST32(a5 + 0xa0, a10);  /* 0081 */
  ST32(a5 + 0xa4, a11);  /* 0084 */
  L_0087: a6 = LD32(a3 + 0x0);  /* 0087 */
  a10 = LD32(a6 + 0x110);  /* 0089 */
  __asm__ volatile("" ::: "memory");  /* 008c: memw */
  /* 008f: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a6 = (u32)&LOCAL__bss_s_parent_monitor_weak_time + 0x0;  /* 0092: l32r -> .bss.s_parent_monitor_weak_time (same-object static) */
  ST32(a6 + 0x0, a10);  /* 0095 */
  ST32(a6 + 0x4, a11);  /* 0097 */
  a6 = LD32(a3 + 0x0);  /* 0099 */
  a10 = LD32(a6 + 0x110);  /* 009b */
  __asm__ volatile("" ::: "memory");  /* 009e: memw */
  /* 00a1: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a6 = (u32)&LOCAL__bss_s_parent_monitor_assoc_time + 0x0;  /* 00a4: l32r -> .bss.s_parent_monitor_assoc_time (same-object static) */
  ST32(a6 + 0x0, a10);  /* 00a7 */
  ST32(a6 + 0x4, a11);  /* 00a9 */
  a6 = (u32)&g_mesh_topology + 0x0;  /* 00ab: l32r -> global */
  a10 = LD32(a6 + 0x0);  /* 00ae */
  if (a10 != 0) goto L_00c0;  /* 00b0: bnez.n a10, c0 <mesh_post_parent_switch_candidate+0x74> */
  L_00b2: a6 = LD8U(a2 + 0xf);  /* 00b2 */
  a7 = LD8U(a2 + 0xe);  /* 00b5 */
  __asm__ volatile("" ::: "memory");  /* 00b8: memw */
  goto L_00d8;  /* 00bb: j */
  L_00c0: a6 = LD8U(a2 + 0x3d);  /* 00c0 */
  a6 = a6 << 8;  /* 00c3 */
  a7 = LD8U(a2 + 0x3c);  /* 00c6 */
  a6 = a6 | a7;  /* 00c9 */
  a7 = LD8U(a2 + 0x3b);  /* 00cc */
  a7 = a7 << 8;  /* 00cf */
  a9 = LD8U(a2 + 0x3a);  /* 00d2 */
  a7 = a7 | a9;  /* 00d5 */
  L_00d8: a4 = (a4 >> 1) & 0x3;  /* 00d8: extui width 2 */
  if (a4 != 0) goto L_0106;  /* 00db: bnez.n a4, 106 <mesh_post_parent_switch_candidate+0xba> */
  L_00dd: a9 = 1;  /* 00dd */
  if (a7 == 0) a4 = a9;  /* 00df */
  if (a4 != 0) goto L_0106;  /* 00e2: bnez.n a4, 106 <mesh_post_parent_switch_candidate+0xba> */
  L_00e4: a9 = LD8U(a2 + 0x11);  /* 00e4 */
  a4 = LD8U(a2 + 0x10);  /* 00e7 */
  if (a4 == a9) goto L_0106;  /* 00ea: beq a4, a9, 106 <mesh_post_parent_switch_candidate+0xba> */
  L_00ed: if (a10 != 0) goto L_00f5;  /* 00ed: bnez.n a10, f5 <mesh_post_parent_switch_candidate+0xa9> */
  L_00ef: a4 = LD8U(a5 + 0x6f);  /* 00ef */
  goto L_00f8;  /* 00f2: j */
  L_00f5: a4 = LD16U(a5 + 0x9c);  /* 00f5 */
  L_00f8: if ((i32)a4 < (i32)a6) goto L_0106;  /* 00f8: blt a4, a6, 106 <mesh_post_parent_switch_candidate+0xba> */
  L_00fb: a4 = LD8U(a5 + 0x71);  /* 00fb */
  a4 = a4 + (1);  /* 00fe */
  if ((i32)a4 < (i32)a9) goto L_0106;  /* 0100: blt a4, a9, 106 <mesh_post_parent_switch_candidate+0xba> */
  L_0103: goto L_0219;  /* 0103: j */
  L_0106: a4 = 0;  /* 0106 */
  a12 = 47;  /* 0108 */
  a11 = a1 + (64);  /* 010a */
  a10 = 64;  /* 010d */
  ST8(a1 + 0x45, a4);  /* 010f */
  __asm__ volatile("" ::: "memory");  /* 0112: memw */
  __asm__ volatile("" ::: "memory");  /* 0115: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 0118: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 011b: callx a8 via reloc-expand */
  a4 = LD32(a3 + 0x0);  /* 011e */
  a10 = LD32(a4 + 0x110);  /* 0120 */
  /* 0123: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a4 = LD32(a5 + 0xa4);  /* 0126 */
  if ((i32)a11 < (i32)a4) goto L_0156;  /* 0129: blt a11, a4, 156 <mesh_post_parent_switch_candidate+0x10a> */
  L_012c: if (a4 != a11) goto L_0135;  /* 012c: bne a4, a11, 135 <mesh_post_parent_switch_candidate+0xe9> */
  L_012f: a4 = LD32(a5 + 0xa0);  /* 012f */
  if (a10 < a4) goto L_0156;  /* 0132: bltu a10, a4, 156 <mesh_post_parent_switch_candidate+0x10a> */
  L_0135: a4 = LD32(a3 + 0x0);  /* 0135 */
  a10 = LD32(a4 + 0x110);  /* 0137 */
  /* 013a: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a9 = 1;  /* 013d */
  a4 = LD32(a5 + 0xa0);  /* 013f */
  a4 = a10 - a4;  /* 0142: sub */
  a8 = LD32(a5 + 0xa4);  /* 0145 */
  if (a10 < a4) goto L_014d;  /* 0148: bltu a10, a4, 14d <mesh_post_parent_switch_candidate+0x101> */
  L_014b: a9 = 0;  /* 014b */
  L_014d: a8 = a11 - a8;  /* 014d: sub */
  a8 = a8 - a9;  /* 0150: sub */
  goto L_0182;  /* 0153: j */
  L_0156: a4 = LD32(a3 + 0x0);  /* 0156 */
  a10 = LD32(a4 + 0x110);  /* 0158 */
  a4 = -1;  /* 015b */
  /* 015d: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a9 = 1;  /* 0160 */
  a8 = LD32(a5 + 0xa0);  /* 0162 */
  a8 = a8 ^ a4;  /* 0165 */
  a10 = a8 + a10;  /* 0168 */
  a4 = LD32(a5 + 0xa4);  /* 016a */
  if (a10 < a8) goto L_0172;  /* 016d: bltu a10, a8, 172 <mesh_post_parent_switch_candidate+0x126> */
  L_0170: a9 = 0;  /* 0170 */
  L_0172: a11 = a4 + a11;  /* 0172 */
  a4 = a10 + (1);  /* 0174 */
  a11 = a9 + a11;  /* 0176 */
  a8 = 1;  /* 0178 */
  if (a4 < a10) goto L_0180;  /* 017a: bltu a4, a10, 180 <mesh_post_parent_switch_candidate+0x134> */
  L_017d: a8 = 0;  /* 017d */
  L_0180: a8 = a8 + a11;  /* 0180 */
  L_0182: a9 = (u32)&g_mesh_topology + 0x0;  /* 0182: l32r -> global */
  a4 = (a4 >> 12) & 0x1fffff;  /* 0185: extui width 21 */
  a8 = a8 << 12;  /* 0188 */
  a8 = a8 | a4;  /* 018b */
  a7 = a7 + a6;  /* 018e */
  a3 = LD8U(a5 + 0x5);  /* 0190 */
  a9 = LD32(a9 + 0x0);  /* 0193 */
  ST32(a1 + 0x74, a3);  /* 0195 */
  a15 = LD8U(a5 + 0x4);  /* 0198 */
  a12 = LD8U(a5 + 0x6);  /* 019b */
  a13 = LD8U(a5 + 0x7);  /* 019e */
  a14 = LD8U(a5 + 0x8);  /* 01a1 */
  a4 = LD8U(a5 + 0x9);  /* 01a4 */
  if (a9 != 0) goto L_01b4;  /* 01a7: bnez.n a9, 1b4 <mesh_post_parent_switch_candidate+0x168> */
  L_01a9: a11 = LD8U(a5 + 0x6f);  /* 01a9 */
  __asm__ volatile("" ::: "memory");  /* 01ac: memw */
  goto L_01b7;  /* 01af: j */
  L_01b4: a11 = LD16U(a5 + 0x9c);  /* 01b4 */
  L_01b7: a3 = LD32(a5 + 0xac);  /* 01b7 */
  a10 = a3 << 12;  /* 01ba */
  a9 = LD32(a5 + 0xa8);  /* 01bd */
  a9 = (a9 >> 12) & 0x1fffff;  /* 01c0: extui width 21 */
  a9 = a10 | a9;  /* 01c3 */
  a10 = (i32)a3 >> 20;  /* 01c6 */
  ST32(a1 + 0x34, a8);  /* 01c9 */
  a8 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 01cb: l32r -> global */
  ST32(a1 + 0x3c, a10);  /* 01ce */
  a10 = 1;  /* 01d0 */
  ST32(a1 + 0x38, a9);  /* 01d2 */
  a8 = LD32(a8 + 0xc);  /* 01d4 */
  a3 = LD32(a1 + 0x70);  /* 01d6 */
  ST32(a1 + 0x30, a8);  /* 01d9 */
  ST32(a1 + 0x2c, a3);  /* 01db */
  a3 = LD8U(a5 + 0x71);  /* 01dd */
  ST32(a1 + 0x28, a3);  /* 01e0 */
  a3 = LD8U(a2 + 0x11);  /* 01e2 */
  ST32(a1 + 0x24, a3);  /* 01e5 */
  a2 = LD8U(a2 + 0x10);  /* 01e7 */
  ST32(a1 + 0x20, a2);  /* 01ea */
  a2 = LD32(a1 + 0x74);  /* 01ec */
  ST32(a1 + 0xc, a14);  /* 01ef */
  ST32(a1 + 0x8, a13);  /* 01f1 */
  a14 = 0x00001461u;  /* 01f3: l32r = 5217 */
  a13 = (u32)(RODATA__rodata_wlog_info_32 + 0x0);  /* 01f6: l32r -> .rodata_wlog_info.32 */
  ST32(a1 + 0x1c, a11);  /* 01f9 */
  a11 = 32;  /* 01fb */
  ST32(a1 + 0x4, a12);  /* 01fd */
  a12 = 3;  /* 01ff */
  ST32(a1 + 0x10, a4);  /* 0201 */
  ST32(a1 + 0x0, a2);  /* 0203 */
  ST32(a1 + 0x18, a6);  /* 0205 */
  ST32(a1 + 0x14, a7);  /* 0208 */
  __asm__ volatile("" ::: "memory");  /* 020b: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 020e: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 0211: callx a8 via reloc-expand */
  goto L_034c;  /* 0214: j */
  L_0219: a4 = LD32(a3 + 0x0);  /* 0219 */
  a10 = LD32(a4 + 0x110);  /* 021b */
  /* 021e: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a4 = LD32(a5 + 0xa4);  /* 0221 */
  if ((i32)a11 < (i32)a4) goto L_0252;  /* 0224: blt a11, a4, 252 <mesh_post_parent_switch_candidate+0x206> */
  L_0227: if (a4 != a11) goto L_0230;  /* 0227: bne a4, a11, 230 <mesh_post_parent_switch_candidate+0x1e4> */
  L_022a: a4 = LD32(a5 + 0xa0);  /* 022a */
  if (a10 < a4) goto L_0252;  /* 022d: bltu a10, a4, 252 <mesh_post_parent_switch_candidate+0x206> */
  L_0230: a7 = 1;  /* 0230 */
  a4 = LD32(a3 + 0x0);  /* 0232 */
  a10 = LD32(a4 + 0x110);  /* 0234 */
  /* 0237: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a4 = LD32(a5 + 0xa0);  /* 023a */
  a4 = a10 - a4;  /* 023d: sub */
  a8 = LD32(a5 + 0xa4);  /* 0240 */
  if (a10 < a4) goto L_0248;  /* 0243: bltu a10, a4, 248 <mesh_post_parent_switch_candidate+0x1fc> */
  L_0246: a7 = 0;  /* 0246 */
  L_0248: a11 = a11 - a8;  /* 0248: sub */
  a11 = a11 - a7;  /* 024b: sub */
  goto L_027f;  /* 024e: j */
  L_0252: a4 = LD32(a3 + 0x0);  /* 0252 */
  a7 = -1;  /* 0254 */
  a10 = LD32(a4 + 0x110);  /* 0256 */
  /* 0259: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a8 = 1;  /* 025c */
  a4 = LD32(a5 + 0xa0);  /* 025e */
  a4 = a4 ^ a7;  /* 0261 */
  a10 = a4 + a10;  /* 0264 */
  a7 = LD32(a5 + 0xa4);  /* 0266 */
  if (a10 < a4) goto L_026e;  /* 0269: bltu a10, a4, 26e <mesh_post_parent_switch_candidate+0x222> */
  L_026c: a8 = 0;  /* 026c */
  L_026e: a7 = a7 + a11;  /* 026e */
  a4 = a10 + (1);  /* 0270 */
  a7 = a8 + a7;  /* 0272 */
  a11 = 1;  /* 0274 */
  if (a4 < a10) goto L_027d;  /* 0277: bltu a4, a10, 27d <mesh_post_parent_switch_candidate+0x231> */
  L_027a: a11 = 0;  /* 027a */
  L_027d: a11 = a11 + a7;  /* 027d */
  L_027f: a7 = LD32(a5 + 0xac);  /* 027f */
  if ((i32)a11 >= (i32)a7) goto L_0288;  /* 0282: bge a11, a7, 288 <mesh_post_parent_switch_candidate+0x23c> */
  L_0285: goto L_0359;  /* 0285: j */
  L_0288: if (a7 != a11) goto L_0294;  /* 0288: bne a7, a11, 294 <mesh_post_parent_switch_candidate+0x248> */
  L_028b: a7 = LD32(a5 + 0xa8);  /* 028b */
  if (a4 >= a7) goto L_0294;  /* 028e: bgeu a4, a7, 294 <mesh_post_parent_switch_candidate+0x248> */
  L_0291: goto L_0359;  /* 0291: j */
  L_0294: a4 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 0294: l32r -> global */
  a3 = LD32(a1 + 0x70);  /* 0297 */
  a7 = LD32(a4 + 0xc);  /* 029a */
  if ((i32)a3 < (i32)a7) goto L_02d8;  /* 029c: blt a3, a7, 2d8 <mesh_post_parent_switch_candidate+0x28c> */
  L_029f: a11 = a5 + (4);  /* 029f */
  a12 = 6;  /* 02a2 */
  a2 = LD8U(a2 + 0x11);  /* 02a5 */
  a10 = a1 + (73);  /* 02a8 */
  ST8(a1 + 0x43, a2);  /* 02ab */
  a2 = 1;  /* 02ae */
  ST16(a1 + 0x40, a6);  /* 02b0 */
  ST8(a1 + 0x42, a3);  /* 02b3 */
  ST8(a1 + 0x45, a2);  /* 02b6 */
  __asm__ volatile("" ::: "memory");  /* 02b9: memw */
  __asm__ volatile("" ::: "memory");  /* 02bc: memw */
  a8 = (u32)&memcpy + 0x0;  /* 02bf: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 02c2: callx a8 (libc, via reloc-expand) */
  a12 = 32;  /* 02c5 */
  a11 = a5 + (10);  /* 02c8 */
  a10 = a1 + (79);  /* 02cb */
  a8 = (u32)&memcpy + 0x0;  /* 02ce: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 02d1: callx a8 (libc, via reloc-expand) */
  goto L_02e0;  /* 02d4: j */
  L_02d8: a2 = 0;  /* 02d8 */
  ST8(a1 + 0x45, a2);  /* 02da */
  __asm__ volatile("" ::: "memory");  /* 02dd: memw */
  L_02e0: a12 = 47;  /* 02e0 */
  a11 = a1 + (64);  /* 02e2 */
  a10 = 64;  /* 02e5 */
  __asm__ volatile("" ::: "memory");  /* 02e7: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 02ea: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6, a7);  /* 02ed: callx a8 via reloc-expand */
  a6 = LD32(a5 + 0xac);  /* 02f0 */
  a12 = 2;  /* 02f3 */
  a7 = a6 << 12;  /* 02f5 */
  a6 = (i32)a6 >> 20;  /* 02f8 */
  a11 = 32;  /* 02fb */
  a2 = LD32(a5 + 0xa8);  /* 02fd */
  a10 = 1;  /* 0300 */
  a2 = (a2 >> 12) & 0x1fffff;  /* 0302: extui width 21 */
  a2 = a7 | a2;  /* 0305 */
  a15 = LD8U(a5 + 0x4);  /* 0308 */
  ST32(a1 + 0x28, a2);  /* 030b */
  ST32(a1 + 0x2c, a6);  /* 030d */
  a2 = LD32(a4 + 0xc);  /* 030f */
  ST32(a1 + 0x20, a2);  /* 0311 */
  a2 = LD32(a1 + 0x70);  /* 0313 */
  ST32(a1 + 0x1c, a2);  /* 0316 */
  a2 = (u32)(RODATA__rodata_mesh_post_parent_switch_candidate_str1_1 + 0x0);  /* 0318: l32r -> .rodata.mesh_post_parent_switch_candidate.str1.1 */
  ST32(a1 + 0x18, a2);  /* 031b */
  a2 = LD8U(a1 + 0x45);  /* 031d */
  ST32(a1 + 0x14, a2);  /* 0320 */
  a2 = LD8U(a5 + 0x9);  /* 0322 */
  ST32(a1 + 0x10, a2);  /* 0325 */
  a2 = LD8U(a5 + 0x8);  /* 0327 */
  ST32(a1 + 0xc, a2);  /* 032a */
  a2 = LD8U(a5 + 0x7);  /* 032c */
  ST32(a1 + 0x8, a2);  /* 032f */
  a2 = LD8U(a5 + 0x6);  /* 0332 */
  ST32(a1 + 0x4, a2);  /* 0335 */
  a2 = LD8U(a5 + 0x5);  /* 0337 */
  a14 = 0x00001481u;  /* 033a: l32r = 5249 */
  a13 = (u32)(RODATA__rodata_wlog_warning_33 + 0x0);  /* 033d: l32r -> .rodata_wlog_warning.33 */
  ST32(a1 + 0x0, a2);  /* 0340 */
  __asm__ volatile("" ::: "memory");  /* 0343: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0346: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 0349: callx a8 via reloc-expand */
  L_034c: a12 = 184;  /* 034c */
  a11 = 0;  /* 034f */
  a10 = a5;  /* 0351 */
  a8 = (u32)&memset + 0x0;  /* 0353: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0356: callx a8 (libc, via reloc-expand) */
  L_0359: return a2;  /* 0359: retw.n */
}


/* mesh_post_parent_weak_rssi @ mesh_quick.o 00000028 size 379B bind GLOBAL
 * Calls: wifi_log, memset, wifi_mesh_event_post | indirect[8]: mem[a2+0x110]; mem[a8+0x110]; mem[a6+0x110] | Data refs: g_osi_funcs_p, g_mesh_cfg_switch_parent, .bss.s_parent_worse_rssi_time, .bss.s_parent_monitor_weak_time, .bss.s_mesh_rssi_threshold, .rodata_wlog_info.34
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=9); reloc-direct=3, funcdb-attributed=0, unknown-indirect=8 */
u32 mesh_post_parent_weak_rssi(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a6, a7, a8, a9;
  float F9;
  /* 0028: entry a1, 112 (frame 112 bytes) */
  a6 = (u32)&g_osi_funcs_p + 0x0;  /* 002b: l32r -> global */
  a2 = (a2 >> 16) & 0x1;  /* 002e: extui width 1 */
  a3 = (a3 >> 8) & 0x1;  /* 0031: extui width 1 */
  a5 = (a5 >> 8) & 0x1;  /* 0034: extui width 1 */
  a7 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 0037: l32r -> global */
  ST32(a1 + 0x44, a2);  /* 003a */
  a8 = LD32(a7 + 0x4);  /* 003d */
  a2 = LD32(a6 + 0x0);  /* 003f */
  ST32(a1 + 0x48, a3);  /* 0041 */
  ST32(a1 + 0x40, a5);  /* 0044 */
  a10 = LD32(a2 + 0x110);  /* 0047 */
  a3 = (u32)&LOCAL__bss_s_parent_worse_rssi_time + 0x0;  /* 004a: l32r -> .bss.s_parent_worse_rssi_time (same-object static) */
  a2 = (u32)&LOCAL__bss_s_parent_monitor_weak_time + 0x0;  /* 004d: l32r -> .bss.s_parent_monitor_weak_time (same-object static) */
  if ((i32)a4 < (i32)a8) goto L_0072;  /* 0050: blt a4, a8, 72 <mesh_post_parent_weak_rssi+0x4a> */
  L_0053: __asm__ volatile("" ::: "memory");  /* 0053: memw */
  /* 0056: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  ST32(a2 + 0x0, a10);  /* 0059 */
  ST32(a2 + 0x4, a11);  /* 005b */
  a2 = LD32(a6 + 0x0);  /* 005d */
  a10 = LD32(a2 + 0x110);  /* 005f */
  __asm__ volatile("" ::: "memory");  /* 0062: memw */
  /* 0065: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  ST32(a3 + 0x0, a10);  /* 0068 */
  ST32(a3 + 0x4, a11);  /* 006a */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  goto L_01a1;  /* 006f: j */
  L_0072: a8 = LD32(a2 + 0x0);  /* 0072 */
  a9 = LD32(a2 + 0x4);  /* 0074 */
  a8 = a8 | a9;  /* 0076 */
  if (a8 != 0) goto L_0082;  /* 0079: bnez.n a8, 82 <mesh_post_parent_weak_rssi+0x5a> */
  L_007b: /* 007b: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  ST32(a2 + 0x0, a10);  /* 007e */
  ST32(a2 + 0x4, a11);  /* 0080 */
  L_0082: a8 = LD32(a3 + 0x0);  /* 0082 */
  a9 = LD32(a3 + 0x4);  /* 0084 */
  a8 = a8 | a9;  /* 0086 */
  if (a8 != 0) goto L_009a;  /* 0089: bnez.n a8, 9a <mesh_post_parent_weak_rssi+0x72> */
  L_008b: a8 = LD32(a6 + 0x0);  /* 008b */
  a10 = LD32(a8 + 0x110);  /* 008d */
  __asm__ volatile("" ::: "memory");  /* 0090: memw */
  /* 0093: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  ST32(a3 + 0x0, a10);  /* 0096 */
  ST32(a3 + 0x4, a11);  /* 0098 */
  L_009a: a8 = LD32(a6 + 0x0);  /* 009a */
  a10 = LD32(a8 + 0x110);  /* 009c */
  __asm__ volatile("" ::: "memory");  /* 009f: memw */
  /* 00a2: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = LD32(a2 + 0x4);  /* 00a5 */
  if ((i32)a11 < (i32)a8) goto L_00d2;  /* 00a7: blt a11, a8, d2 <mesh_post_parent_weak_rssi+0xaa> */
  L_00aa: if (a8 != a11) goto L_00b2;  /* 00aa: bne a8, a11, b2 <mesh_post_parent_weak_rssi+0x8a> */
  L_00ad: a8 = LD32(a2 + 0x0);  /* 00ad */
  if (a10 < a8) goto L_00d2;  /* 00af: bltu a10, a8, d2 <mesh_post_parent_weak_rssi+0xaa> */
  L_00b2: a8 = LD32(a6 + 0x0);  /* 00b2 */
  a10 = LD32(a8 + 0x110);  /* 00b4 */
  /* 00b7: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a12 = 1;  /* 00ba */
  a9 = LD32(a2 + 0x0);  /* 00bc */
  a9 = a10 - a9;  /* 00be: sub */
  a8 = LD32(a2 + 0x4);  /* 00c1 */
  if (a10 < a9) goto L_00c8;  /* 00c3: bltu a10, a9, c8 <mesh_post_parent_weak_rssi+0xa0> */
  L_00c6: a12 = 0;  /* 00c6 */
  L_00c8: a8 = a11 - a8;  /* 00c8: sub */
  a8 = a8 - a12;  /* 00cb: sub */
  goto L_00fb;  /* 00ce: j */
  L_00d2: a8 = LD32(a6 + 0x0);  /* 00d2 */
  a10 = LD32(a8 + 0x110);  /* 00d4 */
  /* 00d7: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = -1;  /* 00da */
  a12 = 1;  /* 00dc */
  a9 = LD32(a2 + 0x0);  /* 00de */
  a9 = a9 ^ a8;  /* 00e0 */
  a10 = a9 + a10;  /* 00e3 */
  a8 = LD32(a2 + 0x4);  /* 00e5 */
  if (a10 < a9) goto L_00ec;  /* 00e7: bltu a10, a9, ec <mesh_post_parent_weak_rssi+0xc4> */
  L_00ea: a12 = 0;  /* 00ea */
  L_00ec: a11 = a8 + a11;  /* 00ec */
  a9 = a10 + (1);  /* 00ee */
  a11 = a12 + a11;  /* 00f0 */
  a8 = 1;  /* 00f2 */
  if (a9 < a10) goto L_00f9;  /* 00f4: bltu a9, a10, f9 <mesh_post_parent_weak_rssi+0xd1> */
  L_00f7: a8 = 0;  /* 00f7 */
  L_00f9: a8 = a8 + a11;  /* 00f9 */
  L_00fb: a9 = a9 >> 10;  /* 00fb */
  a8 = a8 << 22;  /* 00fe */
  a5 = a8 | a9;  /* 0101 */
  a9 = (u32)&LOCAL__bss_s_mesh_rssi_threshold + 0x0;  /* 0104: l32r -> .bss.s_mesh_rssi_threshold (same-object static) */
  a10 = LD32(a9 + 0x8);  /* 0107 */
  if ((i32)a10 < (i32)a4) goto L_0146;  /* 0109: blt a10, a4, 146 <mesh_post_parent_weak_rssi+0x11e> */
  L_010c: a6 = 0;  /* 010c */
  a9 = LD32(a7 + 0x0);  /* 010e */
  if (a5 < a9) goto L_0155;  /* 0110: bltu a5, a9, 155 <mesh_post_parent_weak_rssi+0x12d> */
  L_0113: a8 = LD32(a1 + 0x40);  /* 0113 */
  if (((a8 >> 1) & 1) != 0) goto L_0155;  /* 0116: bbsi a8, 1, 155 <mesh_post_parent_weak_rssi+0x12d> */
  L_0119: a9 = (i32)a9 >> 10;  /* 0119 */
  a15 = a5 >> 10;  /* 011c */
  a14 = 0x000014abu;  /* 011f: l32r = 5291 */
  a12 = 3;  /* 0122 */
  a11 = 32;  /* 0124 */
  a13 = (u32)(RODATA__rodata_wlog_info_34 + 0x0);  /* 0126: l32r -> .rodata_wlog_info.34 */
  ST32(a1 + 0x8, a10);  /* 0129 */
  a10 = 1;  /* 012b */
  ST32(a1 + 0x4, a4);  /* 012d */
  ST32(a1 + 0x0, a9);  /* 012f */
  __asm__ volatile("" ::: "memory");  /* 0131: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0134: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5);  /* 0137: callx a8 via reloc-expand */
  ST32(a3 + 0x0, a6);  /* 013a */
  ST32(a3 + 0x4, a6);  /* 013c */
  a6 = 1;  /* 013e */
  __asm__ volatile("" ::: "memory");  /* 0140: memw */
  goto L_0155;  /* 0143: j */
  L_0146: a6 = LD32(a6 + 0x0);  /* 0146 */
  a10 = LD32(a6 + 0x110);  /* 0148 */
  a6 = 0;  /* 014b */
  /* 014e: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  ST32(a3 + 0x0, a10);  /* 0151 */
  ST32(a3 + 0x4, a11);  /* 0153 */
  L_0155: a7 = LD32(a7 + 0x0);  /* 0155 */
  if (a5 < a7) goto L_0160;  /* 0157: bltu a5, a7, 160 <mesh_post_parent_weak_rssi+0x138> */
  L_015a: a5 = LD32(a1 + 0x40);  /* 015a */
  if (((a5 >> 1) & 1) == 0) goto L_0162;  /* 015d: bbci a5, 1, 162 <mesh_post_parent_weak_rssi+0x13a> */
  L_0160: if (a6 == 0) goto L_01a1;  /* 0160: beqz.n a6, 1a1 <mesh_post_parent_weak_rssi+0x179> */
  L_0162: a8 = 0;  /* 0162 */
  a11 = a8;  /* 0164 */
  a12 = 43;  /* 0166 */
  a10 = a1 + (20);  /* 0168 */
  ST32(a2 + 0x0, a8);  /* 016b */
  ST32(a2 + 0x4, a8);  /* 016d */
  ST32(a3 + 0x0, a8);  /* 016f */
  ST32(a3 + 0x4, a8);  /* 0171 */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  a8 = (u32)&memset + 0x0;  /* 0176: l32r -> global */
  a2 = memset(a2, a3, a4, a5);  /* 0179: callx a8 (libc, via reloc-expand) */
  a12 = 47;  /* 017c */
  a11 = a1 + (16);  /* 017e */
  a10 = 61;  /* 0181 */
  a8 = LD32(a1 + 0x44);  /* 0183 */
  a2 = LD32(a1 + 0x48);  /* 0186 */
  ST16(a1 + 0x10, a8);  /* 0189 */
  ST8(a1 + 0x12, a4);  /* 018c */
  ST8(a1 + 0x13, a2);  /* 018f */
  ST8(a1 + 0x14, a6);  /* 0192 */
  __asm__ volatile("" ::: "memory");  /* 0195: memw */
  __asm__ volatile("" ::: "memory");  /* 0198: memw */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 019b: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5);  /* 019e: callx a8 via reloc-expand */
  L_01a1: return a2;  /* 01a1: retw.n */
}


/* mesh_process_roots_ie @ mesh_quick.o 00000070 size 788B bind GLOBAL
 * Calls: wifi_get_macaddr, mesh_is_new_root_found, memcmp, memcpy, mesh_process_roots_ie_ttl, ieee80211_vnd_mesh_roots_set, mesh_root_process_roots_ie, roots_type2str, wifi_log | indirect[2]: mem[a2+0x158]; mem[a2+0x150] | Data refs: .bss.wifi_vnd_ext_mesh_roots, g_mesh_max_layer, .rodata_wlog_warning.25, g_osi_funcs_p, .rodata.mesh_parse_ps_entire_rule.str1.1, .rodata.esp_mesh_ps_duty_cycle_get_process.str1.1, .rodata._mesh_timer_process_conflict_root.str1.1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=9, refs=16); reloc-direct=9, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_process_roots_ie(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a6, a7, a8, a9;
  float F1;
  /* 0070: entry a1, 96 (frame 96 bytes) */
  a3 = (a3 >> 8) & 0x1;  /* 0073: extui width 1 */
  a7 = (a2 >> 8) & 0x1;  /* 0076: extui width 1 */
  ST32(a1 + 0x30, a3);  /* 0079 */
  if (a7 < 4u) goto L_0081;  /* 007b: bltui a7, 4, 81 <mesh_process_roots_ie+0x11> */
  L_007e: goto L_0380;  /* 007e: j */
  L_0081: a10 = 1;  /* 0081 */
  a3 = 0;  /* 0083 */
  a2 = LD32(a1 + 0x30);  /* 0085 */
  if (a2 == 0) a3 = a10;  /* 0087 */
  a6 = (a3 >> 8) & 0x1;  /* 008a: extui width 1 */
  if (a3 != 0) goto L_0380;  /* 008d: bnez a3, 380 <mesh_process_roots_ie+0x310> */
  L_0090: if (a4 == 0) a6 = a10;  /* 0090 */
  if (a6 != 0) goto L_0380;  /* 0093: bnez a6, 380 <mesh_process_roots_ie+0x310> */
  L_0096: if (a5 == 0) a6 = a10;  /* 0096 */
  if (a6 != 0) goto L_0380;  /* 0099: bnez a6, 380 <mesh_process_roots_ie+0x310> */
  L_009c: a11 = a1 + (32);  /* 009c */
  ST32(a1 + 0x20, a6);  /* 009f */
  ST16(a1 + 0x24, a6);  /* 00a1 */
  __asm__ volatile("" ::: "memory");  /* 00a4: memw */
  __asm__ volatile("" ::: "memory");  /* 00a7: memw */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 00aa: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5);  /* 00ad: callx a8 via reloc-expand */
  a2 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 00b0: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a3 = a7 + (a2 << 3);  /* 00b3 */
  a8 = LD8U(a3 + 0x1);  /* 00b6 */
  ST32(a1 + 0x34, a8);  /* 00b9 */
  a3 = LD32(a3 + 0x4);  /* 00bb */
  if (a7 != 1) goto L_00c3;  /* 00bd: bnei a7, 1, c3 <mesh_process_roots_ie+0x53> */
  L_00c0: goto L_0190;  /* 00c0: j */
  L_00c3: a2 = a4;  /* 00c3 */
  if (a7 == 2) goto L_00cb;  /* 00c5: beqi a7, 2, cb <mesh_process_roots_ie+0x5b> */
  L_00c8: goto L_0184;  /* 00c8: j */
  L_00cb: a7 = (u32)&g_mesh_max_layer + 0x0;  /* 00cb: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 00ce: memw */
  goto L_0378;  /* 00d1: j */
  L_00d4: a12 = a5;  /* 00d4 */
  a11 = a2;  /* 00d6 */
  a10 = a7;  /* 00d8 */
  a8 = (u32)&mesh_is_new_root_found;  /* 00da: l32r -> func addr */
  a2 = mesh_is_new_root_found(a2, a3, a4, a5);  /* 00dd: callx a8 via reloc-expand */
  if (a10 != 0) goto L_013e;  /* 00e0: bnez a10, 13e <mesh_process_roots_ie+0xce> */
  L_00e3: a9 = a2 + (4);  /* 00e3 */
  a13 = a3;  /* 00e5 */
  a4 = a10;  /* 00e7 */
  ST32(a1 + 0x38, a9);  /* 00e9 */
  __asm__ volatile("" ::: "memory");  /* 00eb: memw */
  goto L_0134;  /* 00ee: j */
  L_00f1: a10 = LD32(a1 + 0x38);  /* 00f1 */
  a11 = a13 + (4);  /* 00f3 */
  a12 = 6;  /* 00f5 */
  ST32(a1 + 0x3c, a13);  /* 00f7 */
  __asm__ volatile("" ::: "memory");  /* 00f9: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00fc: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 00ff: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x3c);  /* 0102 */
  if (a10 != 0) goto L_0130;  /* 0104: bnez.n a10, 130 <mesh_process_roots_ie+0xc0> */
  L_0106: a11 = LD8U(a2 + 0x1);  /* 0106 */
  a11 = a11 << 8;  /* 0109 */
  a10 = LD8U(a13 + 0x1);  /* 010c */
  a10 = a10 << 8;  /* 010f */
  a14 = LD8U(a2 + 0x0);  /* 0112 */
  a11 = a11 | a14;  /* 0115 */
  a12 = LD8U(a13 + 0x0);  /* 0118 */
  a10 = a10 | a12;  /* 011b */
  if (a11 < a10) goto L_0130;  /* 011e: bltu a11, a10, 130 <mesh_process_roots_ie+0xc0> */
  L_0121: a10 = a13;  /* 0121 */
  a12 = 12;  /* 0123 */
  a11 = a2;  /* 0125: mov */
  a8 = (u32)&memcpy + 0x0;  /* 0128: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 012b: callx a8 (libc, via reloc-expand) */
  a13 = a10;  /* 012e */
  L_0130: a4 = a4 + (1);  /* 0130 */
  a13 = a13 + (12);  /* 0132 */
  L_0134: a8 = LD32(a1 + 0x34);  /* 0134 */
  if ((i32)a4 < (i32)a8) goto L_00f1;  /* 0136: blt a4, a8, f1 <mesh_process_roots_ie+0x81> */
  L_0139: goto L_0180;  /* 0139: j */
  L_013e: a13 = a6;  /* 013e */
  a12 = a5;  /* 0140 */
  a11 = a2;  /* 0142 */
  a10 = a7;  /* 0144 */
  a8 = (u32)&mesh_process_roots_ie_ttl;  /* 0146: l32r -> func addr */
  a2 = mesh_process_roots_ie_ttl(a2, a3, a4, a5);  /* 0149: callx a8 via reloc-expand */
  a4 = LD8U(a2 + 0x1);  /* 014c */
  a4 = a4 << 8;  /* 014f */
  a8 = LD8U(a2 + 0x0);  /* 0152 */
  a4 = a4 | a8;  /* 0155 */
  if (a4 == 0) goto L_0173;  /* 0158: beqz.n a4, 173 <mesh_process_roots_ie+0x103> */
  L_015a: a9 = (u32)&g_mesh_max_layer + 0x0;  /* 015a: l32r -> global */
  a8 = LD16U(a9 + 0x0);  /* 015d */
  if (a4 >= a8) goto L_0173;  /* 0160: bgeu a4, a8, 173 <mesh_process_roots_ie+0x103> */
  L_0163: a12 = 1;  /* 0163 */
  a11 = a2;  /* 0165 */
  a10 = a7;  /* 0167 */
  if (a7 == 0) goto L_016d;  /* 0169: beqz.n a7, 16d <mesh_process_roots_ie+0xfd> */
  L_016b: a10 = 3;  /* 016b */
  L_016d: a8 = (u32)&ieee80211_vnd_mesh_roots_set;  /* 016d: l32r -> func addr */
  a2 = ieee80211_vnd_mesh_roots_set(a2, a3, a4, a5);  /* 0170: callx a8 via reloc-expand */
  L_0173: a12 = a5;  /* 0173 */
  a11 = a2;  /* 0175 */
  a10 = a7;  /* 0177: mov */
  a8 = (u32)&mesh_root_process_roots_ie;  /* 017a: l32r -> func addr */
  a2 = mesh_root_process_roots_ie(a2, a3, a4, a5);  /* 017d: callx a8 via reloc-expand */
  L_0180: a6 = a6 + (1);  /* 0180 */
  a2 = a2 + (12);  /* 0182 */
  L_0184: a4 = LD32(a1 + 0x30);  /* 0184 */
  if ((i32)a6 >= (i32)a4) goto L_018c;  /* 0186: bge a6, a4, 18c <mesh_process_roots_ie+0x11c> */
  L_0189: goto L_00d4;  /* 0189: j */
  L_018c: goto L_0340;  /* 018c: j */
  L_0190: a8 = LD32(a1 + 0x30);  /* 0190 */
  if (a8 == 2) goto L_020d;  /* 0192: beqi a8, 2, 20d <mesh_process_roots_ie+0x19d> */
  L_0195: a10 = a7;  /* 0195 */
  a8 = (u32)&roots_type2str;  /* 0197: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4, a5);  /* 019a: callx a8 via reloc-expand */
  a3 = LD8U(a5 + 0x5);  /* 019d */
  a15 = a10;  /* 01a0 */
  a12 = 2;  /* 01a2 */
  a11 = a7 << 21;  /* 01a4 */
  a10 = a7;  /* 01a7 */
  ST32(a1 + 0x18, a3);  /* 01a9 */
  a3 = LD8U(a5 + 0x4);  /* 01ab */
  ST32(a1 + 0x14, a3);  /* 01ae */
  a3 = LD8U(a5 + 0x3);  /* 01b0 */
  ST32(a1 + 0x10, a3);  /* 01b3 */
  a3 = LD8U(a5 + 0x2);  /* 01b5 */
  ST32(a1 + 0xc, a3);  /* 01b8 */
  a3 = LD8U(a5 + 0x1);  /* 01ba */
  ST32(a1 + 0x8, a3);  /* 01bd */
  a3 = LD8U(a5 + 0x0);  /* 01bf */
  a9 = LD32(a1 + 0x30);  /* 01c2 */
  a14 = 0x000010eau;  /* 01c4: l32r = 4330 */
  a13 = (u32)(RODATA__rodata_wlog_warning_25 + 0x0);  /* 01c7: l32r -> .rodata_wlog_warning.25 */
  ST32(a1 + 0x4, a3);  /* 01ca */
  ST32(a1 + 0x0, a9);  /* 01cd */
  __asm__ volatile("" ::: "memory");  /* 01cf: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 01d2: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5);  /* 01d5: callx a8 via reloc-expand */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01d8: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01db */
  if (a2 == 0) goto L_0340;  /* 01dd: beqz a2, 340 <mesh_process_roots_ie+0x2d0> */
  L_01e0: a3 = LD32(a2 + 0x150);  /* 01e0 */
  if (a3 == 0) goto L_0340;  /* 01e3: beqz a3, 340 <mesh_process_roots_ie+0x2d0> */
  L_01e6: a10 = LD32(a2 + 0x158);  /* 01e6 */
  /* 01e9: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01ec */
  a10 = a7;  /* 01ee */
  a11 = (u32)(RODATA__rodata_mesh_parse_ps_entire_rule_str1_1 + 0x0);  /* 01f0: -> "child(cidx:" */
  a14 = a11;  /* 01f3: mov */
  a2 = 0x000010ecu;  /* 01f6: l32r = 4332 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ps_duty_cycle_get_process_str1_1 + 0x0);  /* 01f9: -> "mesh_quick.c" */
  a12 = (u32)(RODATA__rodata__mesh_timer_process_conflict_root_str1_1 + 0x0);  /* 01fc: l32r -> .rodata._mesh_timer_process_conflict_root.str1.1 */
  ST32(a1 + 0x0, a2);  /* 01ff */
  __asm__ volatile("" ::: "memory");  /* 0202: memw */
  /* 0205: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0340;  /* 0208: j */
  L_020d: a12 = a5;  /* 020d */
  a11 = a4;  /* 020f */
  a10 = a7;  /* 0211 */
  a8 = (u32)&mesh_is_new_root_found;  /* 0213: l32r -> func addr */
  a2 = mesh_is_new_root_found(a2, a3, a4, a5);  /* 0216: callx a8 via reloc-expand */
  if (a10 != 0) goto L_02c3;  /* 0219: bnez a10, 2c3 <mesh_process_roots_ie+0x253> */
  L_021c: a2 = LD32(a2 + 0x8);  /* 021c */
  if (((a2 >> 0) & 1) != 0) goto L_0224;  /* 021e: bbsi a2, 0, 224 <mesh_process_roots_ie+0x1b4> */
  L_0221: goto L_0340;  /* 0221: j */
  L_0224: a2 = LD8U(a4 + 0x1);  /* 0224 */
  a2 = a2 << 8;  /* 0227 */
  a5 = LD8U(a4 + 0x0);  /* 022a */
  a2 = a2 | a5;  /* 022d */
  a2 = a2 + (-1);  /* 0230 */
  a5 = (a2 >> 16) & 0x1;  /* 0232: extui width 1 */
  ST8(a4 + 0x0, a2);  /* 0235 */
  a2 = (a2 >> 8) & 0x1ff;  /* 0238: extui width 9 */
  if (a5 == 0) a10 = a7;  /* 023b */
  a10 = (a10 >> 8) & 0x1;  /* 023e: extui width 1 */
  ST8(a4 + 0x1, a2);  /* 0241 */
  __asm__ volatile("" ::: "memory");  /* 0244: memw */
  a2 = LD8U(a4 + 0xd);  /* 0247 */
  a2 = a2 << 8;  /* 024a */
  a6 = LD8U(a4 + 0xc);  /* 024d */
  a2 = a2 | a6;  /* 0250 */
  a2 = a2 + (-1);  /* 0253 */
  a6 = (a2 >> 16) & 0x1;  /* 0255: extui width 1 */
  ST8(a4 + 0xc, a2);  /* 0258 */
  a2 = (a2 >> 8) & 0x1ff;  /* 025b: extui width 9 */
  ST8(a4 + 0xd, a2);  /* 025e */
  __asm__ volatile("" ::: "memory");  /* 0261: memw */
  if (a10 != 0) goto L_0340;  /* 0264: bnez a10, 340 <mesh_process_roots_ie+0x2d0> */
  L_0267: if (a6 == 0) a10 = a7;  /* 0267 */
  if (a10 != 0) goto L_0340;  /* 026a: bnez a10, 340 <mesh_process_roots_ie+0x2d0> */
  L_026d: a12 = 6;  /* 026d */
  a11 = a3 + (4);  /* 026f */
  a10 = a4 + (4);  /* 0271 */
  __asm__ volatile("" ::: "memory");  /* 0273: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0276: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 0279: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0340;  /* 027c: bnez a10, 340 <mesh_process_roots_ie+0x2d0> */
  L_027f: a12 = 6;  /* 027f */
  a11 = a3 + (16);  /* 0281 */
  a10 = a4 + (16);  /* 0284 */
  a8 = (u32)&memcmp + 0x0;  /* 0287: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 028a: callx a8 (libc, via reloc-expand) */
  a6 = a3 + (12);  /* 028d */
  a7 = a4 + (12);  /* 028f */
  a2 = a10;  /* 0291 */
  if (a10 != 0) goto L_0340;  /* 0293: bnez a10, 340 <mesh_process_roots_ie+0x2d0> */
  L_0296: a8 = LD8U(a3 + 0x1);  /* 0296 */
  a8 = a8 << 8;  /* 0299 */
  a9 = LD8U(a3 + 0x0);  /* 029c */
  a8 = a8 | a9;  /* 029f */
  if (a5 >= a8) goto L_02a8;  /* 02a2: bgeu a5, a8, 2a8 <mesh_process_roots_ie+0x238> */
  L_02a5: goto L_0340;  /* 02a5: j */
  L_02a8: a11 = a4;  /* 02a8 */
  a12 = 12;  /* 02aa */
  a10 = a3;  /* 02ac */
  a8 = (u32)&memcpy + 0x0;  /* 02ae: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 02b1: callx a8 (libc, via reloc-expand) */
  a12 = 12;  /* 02b4 */
  a11 = a7;  /* 02b6 */
  a10 = a6;  /* 02b8 */
  a8 = (u32)&memcpy + 0x0;  /* 02ba: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 02bd: callx a8 (libc, via reloc-expand) */
  goto L_0382;  /* 02c0: j */
  L_02c3: a12 = 6;  /* 02c3 */
  a11 = a4 + (4);  /* 02c5 */
  a10 = a1 + (32);  /* 02c7 */
  a8 = (u32)&memcmp + 0x0;  /* 02ca: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 02cd: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0334;  /* 02d0: beqz a10, 334 <mesh_process_roots_ie+0x2c4> */
  L_02d3: a2 = LD8U(a4 + 0x1);  /* 02d3 */
  a2 = a2 << 8;  /* 02d6 */
  a3 = LD8U(a4 + 0x0);  /* 02d9 */
  a2 = a2 | a3;  /* 02dc */
  a2 = a2 + (-1);  /* 02df */
  a8 = (a2 >> 16) & 0x1;  /* 02e1: extui width 1 */
  ST8(a4 + 0x0, a2);  /* 02e4 */
  a2 = (a2 >> 8) & 0x1ff;  /* 02e7: extui width 9 */
  ST8(a4 + 0x1, a2);  /* 02ea */
  __asm__ volatile("" ::: "memory");  /* 02ed: memw */
  a2 = LD8U(a4 + 0xd);  /* 02f0 */
  a2 = a2 << 8;  /* 02f3 */
  a3 = LD8U(a4 + 0xc);  /* 02f6 */
  a2 = a2 | a3;  /* 02f9 */
  a2 = a2 + (-1);  /* 02fc */
  a6 = (a2 >> 16) & 0x1;  /* 02fe: extui width 1 */
  ST8(a4 + 0xc, a2);  /* 0301 */
  a2 = (a2 >> 8) & 0x1ff;  /* 0304: extui width 9 */
  ST8(a4 + 0xd, a2);  /* 0307 */
  __asm__ volatile("" ::: "memory");  /* 030a: memw */
  if (a8 == 0) goto L_0334;  /* 030d: beqz.n a8, 334 <mesh_process_roots_ie+0x2c4> */
  L_030f: a2 = (u32)&g_mesh_max_layer + 0x0;  /* 030f: l32r -> global */
  a3 = LD16U(a2 + 0x0);  /* 0312 */
  if (a8 < a3) goto L_031a;  /* 0315: bltu a8, a3, 31a <mesh_process_roots_ie+0x2aa> */
  L_0318: a7 = 0;  /* 0318 */
  L_031a: a10 = 1;  /* 031a */
  a2 = 0;  /* 031c */
  if (a6 != 0) a2 = a10;  /* 031e */
  if ((a2 & a7) == 0) goto L_0334;  /* 0321: bnone a2, a7, 334 <mesh_process_roots_ie+0x2c4> */
  L_0324: if (a6 >= a3) goto L_0334;  /* 0324: bgeu a6, a3, 334 <mesh_process_roots_ie+0x2c4> */
  L_0327: a12 = 2;  /* 0327 */
  a11 = a4;  /* 0329 */
  __asm__ volatile("" ::: "memory");  /* 032b: memw */
  a8 = (u32)&ieee80211_vnd_mesh_roots_set;  /* 032e: l32r -> func addr */
  a2 = ieee80211_vnd_mesh_roots_set(a2, a3, a4, a5);  /* 0331: callx a8 via reloc-expand */
  L_0334: a12 = a5;  /* 0334 */
  a11 = a4;  /* 0336 */
  a10 = 1;  /* 0338 */
  a8 = (u32)&mesh_root_process_roots_ie;  /* 033a: l32r -> func addr */
  a2 = mesh_root_process_roots_ie(a2, a3, a4, a5);  /* 033d: callx a8 via reloc-expand */
  L_0340: a2 = 0;  /* 0340 */
  goto L_0382;  /* 0342: j */
  L_0346: a13 = a6;  /* 0346 */
  a12 = a5;  /* 0348 */
  a11 = a4;  /* 034a */
  a10 = 2;  /* 034c */
  a8 = (u32)&mesh_process_roots_ie_ttl;  /* 034e: l32r -> func addr */
  a2 = mesh_process_roots_ie_ttl(a2, a3, a4, a5);  /* 0351: callx a8 via reloc-expand */
  a3 = LD8U(a4 + 0x1);  /* 0354 */
  a3 = a3 << 8;  /* 0357 */
  a8 = LD8U(a4 + 0x0);  /* 035a */
  a3 = a3 | a8;  /* 035d */
  if (a3 == 0) goto L_0374;  /* 0360: beqz.n a3, 374 <mesh_process_roots_ie+0x304> */
  L_0362: a8 = LD16U(a7 + 0x0);  /* 0362 */
  if (a3 >= a8) goto L_0374;  /* 0365: bgeu a3, a8, 374 <mesh_process_roots_ie+0x304> */
  L_0368: a12 = 1;  /* 0368 */
  a11 = a4;  /* 036a */
  a10 = 2;  /* 036c */
  a8 = (u32)&ieee80211_vnd_mesh_roots_set;  /* 036e: l32r -> func addr */
  a2 = ieee80211_vnd_mesh_roots_set(a2, a3, a4, a5);  /* 0371: callx a8 via reloc-expand */
  L_0374: a6 = a6 + (1);  /* 0374 */
  a4 = a4 + (12);  /* 0376 */
  L_0378: a2 = LD32(a1 + 0x30);  /* 0378 */
  if ((i32)a6 < (i32)a2) goto L_0346;  /* 037a: blt a6, a2, 346 <mesh_process_roots_ie+0x2d6> */
  L_037d: goto L_0340;  /* 037d: j */
  L_0380: a2 = -1;  /* 0380 */
  L_0382: return a2;  /* 0382: retw.n */
}


/* mesh_process_roots_ie_ttl @ mesh_quick.o 00000018 size 156B bind GLOBAL
 * Calls: _mesh_roots_process_yield, _mesh_roots_process_gone, _mesh_roots_process_conflict_table | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=3); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_process_roots_ie_ttl(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a9 = 0;  /* 001b */
  a8 = 1;  /* 001d */
  a5 = (a2 >> 8) & 0x1;  /* 001f: extui width 1 */
  a2 = a9;  /* 0022 */
  if (a3 == 0) a2 = a8;  /* 0024 */
  if (a4 != 0) a8 = a9;  /* 0027 */
  a2 = a2 | a8;  /* 002a */
  if (a2 != a9) goto L_00b0;  /* 002d: bne a2, a9, b0 <mesh_process_roots_ie_ttl+0x98> */
  L_0030: if (a5 >= 4u) goto L_00b0;  /* 0030: bgeui a5, 4, b0 <mesh_process_roots_ie_ttl+0x98> */
  L_0033: if (a5 == 2) goto L_0040;  /* 0033: beqi a5, 2, 40 <mesh_process_roots_ie_ttl+0x28> */
  L_0036: if (a5 == 3) goto L_006c;  /* 0036: beqi a5, 3, 6c <mesh_process_roots_ie_ttl+0x54> */
  L_0039: if (a5 != 1) goto L_008e;  /* 0039: bnei a5, 1, 8e <mesh_process_roots_ie_ttl+0x76> */
  L_003c: goto L_00b2;  /* 003c: j */
  L_0040: a8 = LD8U(a3 + 0x1);  /* 0040 */
  a8 = a8 << 8;  /* 0043 */
  a9 = LD8U(a3 + 0x0);  /* 0046 */
  a8 = a8 | a9;  /* 0049 */
  if (a8 != 1) goto L_008e;  /* 004c: bnei a8, 1, 8e <mesh_process_roots_ie_ttl+0x76> */
  L_004f: a10 = a5;  /* 004f */
  a11 = 0x000010a5u;  /* 0051: l32r = 4261 */
  a8 = (u32)&_mesh_roots_process_yield;  /* 0054: l32r -> func addr */
  a2 = _mesh_roots_process_yield(a2, a3, a4, a5, a6, a7);  /* 0057: callx a8 via reloc-expand */
  a12 = a2;  /* 005a */
  a11 = a2;  /* 005c: mov */
  a10 = a5;  /* 005f: mov */
  a8 = (u32)&_mesh_roots_process_gone;  /* 0062: l32r -> func addr */
  a2 = _mesh_roots_process_gone(a2, a3, a4, a5, a6, a7);  /* 0065: callx a8 via reloc-expand */
  goto L_0086;  /* 0068: j */
  L_006c: a2 = LD8U(a3 + 0x1);  /* 006c */
  a2 = a2 << 8;  /* 006f */
  a8 = LD8U(a3 + 0x0);  /* 0072 */
  a2 = a2 | a8;  /* 0075 */
  if (a2 != 1) goto L_008e;  /* 0078: bnei a2, 1, 8e <mesh_process_roots_ie_ttl+0x76> */
  L_007b: a10 = a5;  /* 007b */
  a11 = 0x000010afu;  /* 007d: l32r = 4271 */
  a8 = (u32)&_mesh_roots_process_yield;  /* 0080: l32r -> func addr */
  a2 = _mesh_roots_process_yield(a2, a3, a4, a5, a6, a7);  /* 0083: callx a8 via reloc-expand */
  L_0086: a10 = a5;  /* 0086 */
  a8 = (u32)&_mesh_roots_process_conflict_table;  /* 0088: l32r -> func addr */
  a2 = _mesh_roots_process_conflict_table(a2, a3, a4, a5, a6, a7);  /* 008b: callx a8 via reloc-expand */
  L_008e: a2 = LD8U(a3 + 0x1);  /* 008e */
  a2 = a2 << 8;  /* 0091 */
  a5 = LD8U(a3 + 0x0);  /* 0094 */
  a2 = a2 | a5;  /* 0097 */
  a2 = a2 + (-1);  /* 009a */
  ST8(a3 + 0x0, a2);  /* 009c */
  a2 = (a2 >> 8) & 0x1ff;  /* 009f: extui width 9 */
  ST8(a3 + 0x1, a2);  /* 00a2 */
  __asm__ volatile("" ::: "memory");  /* 00a5: memw */
  a2 = 0;  /* 00a8 */
  __asm__ volatile("" ::: "memory");  /* 00aa: memw */
  goto L_00b2;  /* 00ad: j */
  L_00b0: a2 = -1;  /* 00b0 */
  L_00b2: return a2;  /* 00b2: retw.n */
}


/* mesh_ps_set_new_duty @ mesh_quick.o 00000004 size 166B bind GLOBAL
 * Calls: none | Data refs: esp_mesh_ps_duty
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_ps_set_new_duty(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 0007 */
  if (a3 == 0) goto L_0014;  /* 0009: beqz.n a3, 14 <mesh_ps_set_new_duty+0x10> */
  L_000b: a2 = LD8U(a3 + 0x1);  /* 000b */
  a9 = LD8U(a3 + 0x2);  /* 000e */
  goto L_001a;  /* 0011: j */
  L_0014: a2 = LD8U(a4 + 0x0);  /* 0014 */
  a9 = LD8U(a5 + 0x0);  /* 0017 */
  L_001a: a11 = 4;  /* 001a */
  a10 = LD8U(a8 + 0x0);  /* 001c */
  if (a10 != a9) goto L_003d;  /* 001f: bne a10, a9, 3d <mesh_ps_set_new_duty+0x39> */
  L_0022: if ((a9 & a11) == 0) goto L_0030;  /* 0022: bnone a9, a11, 30 <mesh_ps_set_new_duty+0x2c> */
  L_0025: a9 = LD8U(a8 + 0x1);  /* 0025 */
  if (a9 != a2) goto L_0040;  /* 0028: bne a9, a2, 40 <mesh_ps_set_new_duty+0x3c> */
  L_002b: goto L_0036;  /* 002b: j */
  L_0030: a9 = LD8U(a8 + 0x2);  /* 0030 */
  if (a9 != a2) goto L_0046;  /* 0033: bne a9, a2, 46 <mesh_ps_set_new_duty+0x42> */
  L_0036: a2 = -1;  /* 0036 */
  goto L_00a5;  /* 0038: j */
  L_003d: if ((a10 & a11) == 0) goto L_0046;  /* 003d: bnone a10, a11, 46 <mesh_ps_set_new_duty+0x42> */
  L_0040: a9 = LD8U(a8 + 0x1);  /* 0040 */
  goto L_0069;  /* 0043: j */
  L_0046: if (a3 == 0) goto L_0066;  /* 0046: beqz.n a3, 66 <mesh_ps_set_new_duty+0x62> */
  L_0048: a9 = (a10 >> 1) & 0x1;  /* 0048: extui width 1 */
  if (a9 == 0) goto L_0060;  /* 004b: beqz.n a9, 60 <mesh_ps_set_new_duty+0x5c> */
  L_004d: a2 = (u32)&esp_mesh_ps_duty + 0x0;  /* 004d: l32r -> global */
  a9 = LD8U(a2 + 0xf);  /* 0050 */
  if (a9 != 1) goto L_005d;  /* 0053: bnei a9, 1, 5d <mesh_ps_set_new_duty+0x59> */
  L_0056: a9 = LD8U(a8 + 0x2);  /* 0056 */
  goto L_0060;  /* 0059: j */
  L_005d: a9 = LD8U(a2 + 0x2);  /* 005d */
  L_0060: a10 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 0060: sext */
  if ((i32)a10 >= 0) goto L_0069;  /* 0063: bgez a10, 69 <mesh_ps_set_new_duty+0x65> */
  L_0066: a9 = LD8U(a8 + 0x2);  /* 0066 */
  L_0069: a10 = a9 + (-1);  /* 0069 */
  a10 = (a10 >> 8) & 0x1;  /* 006b: extui width 1 */
  a11 = 99;  /* 006e */
  a2 = -1;  /* 0071 */
  if (a11 < a10) goto L_00a5;  /* 0073: bltu a11, a10, a5 <mesh_ps_set_new_duty+0xa1> */
  L_0076: if (a3 == 0) goto L_0094;  /* 0076: beqz.n a3, 94 <mesh_ps_set_new_duty+0x90> */
  L_0078: a2 = LD32(a3 + 0x4);  /* 0078 */
  ST8(a2 + 0x0, a9);  /* 007a */
  __asm__ volatile("" ::: "memory");  /* 007d: memw */
  a2 = LD32(a3 + 0x8);  /* 0080 */
  a3 = LD8U(a8 + 0x0);  /* 0082 */
  ST8(a2 + 0x0, a3);  /* 0085 */
  __asm__ volatile("" ::: "memory");  /* 0088: memw */
  a2 = 0;  /* 008b */
  __asm__ volatile("" ::: "memory");  /* 008d: memw */
  goto L_00a5;  /* 0090: j */
  L_0094: ST8(a4 + 0x0, a9);  /* 0094 */
  __asm__ volatile("" ::: "memory");  /* 0097: memw */
  a2 = LD8U(a8 + 0x0);  /* 009a */
  ST8(a5 + 0x0, a2);  /* 009d */
  __asm__ volatile("" ::: "memory");  /* 00a0: memw */
  a2 = a3;  /* 00a3 */
  L_00a5: __asm__ volatile("" ::: "memory");  /* 00a5: memw */
  return a2;  /* 00a8: retw.n */
}


/* mesh_root_process_roots_ie @ mesh_quick.o 0000008c size 674B bind GLOBAL
 * Calls: ieee80211_mesh_quick_get, memset, wifi_get_macaddr, memcmp, mesh_is_new_found_conflict_root, esp_mesh_get_conflict_root_state, memcpy, wifi_mesh_event_post, esp_mesh_update_conflict_root, esp_mesh_find_conflict_root, esp_mesh_remove_conflict_root, wifi_log | indirect[4]: mem[a5+0x110]; mem[a6+0x110]; mem[a3+0x110] | Data refs: esp_mesh_appie, .rodata.mesh_root_process_roots_ie.str1.1, .bss.s_mesh_conflict_roots, g_osi_funcs_p, .bss.post_event_time$7, .rodata.ieee80211_vnd_mesh_roots_set.str1.1, .rodata._mesh_roots_process_yield.str1.1, .rodata_wlog_warning.24
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=12, refs=20); reloc-direct=12, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_root_process_roots_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a7, a8;
  /* 008c: entry a1, 64 (frame 64 bytes) */
  a7 = (a2 >> 8) & 0x1;  /* 008f: extui width 1 */
  a2 = -91;  /* 0092 */
  ST8(a1 + 0x1a, a2);  /* 0095 */
  __asm__ volatile("" ::: "memory");  /* 0098: memw */
  a12 = a1 + (26);  /* 009b */
  a11 = 0;  /* 009e */
  a2 = (u32)&esp_mesh_appie + 0x0;  /* 00a0: l32r -> global */
  a10 = LD32(a2 + 0x0);  /* 00a3 */
  a2 = -1;  /* 00a6 */
  a10 = a10 + (2);  /* 00a9 */
  __asm__ volatile("" ::: "memory");  /* 00ac: memw */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 00af: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6, a7);  /* 00b2: callx a8 via reloc-expand */
  a6 = LD8U(a1 + 0x1a);  /* 00b5 */
  if (a6 == 1) goto L_00be;  /* 00b8: beqi a6, 1, be <mesh_root_process_roots_ie+0x32> */
  L_00bb: goto L_032c;  /* 00bb: j */
  L_00be: a2 = 0;  /* 00be */
  if (a3 == 0) a2 = a6;  /* 00c0 */
  a5 = (a2 >> 8) & 0x1;  /* 00c3: extui width 1 */
  if (a2 != 0) goto L_0314;  /* 00c6: bnez a2, 314 <mesh_root_process_roots_ie+0x288> */
  L_00c9: if (a4 == 0) a5 = a6;  /* 00c9 */
  if (a5 != 0) goto L_0314;  /* 00cc: bnez a5, 314 <mesh_root_process_roots_ie+0x288> */
  L_00cf: a11 = a5;  /* 00cf */
  a2 = -1;  /* 00d1 */
  a12 = 12;  /* 00d3 */
  a10 = a1;  /* 00d5: mov */
  ST32(a1 + 0x14, a2);  /* 00d8 */
  ST16(a1 + 0x18, a5);  /* 00da */
  __asm__ volatile("" ::: "memory");  /* 00dd: memw */
  __asm__ volatile("" ::: "memory");  /* 00e0: memw */
  a8 = (u32)&memset + 0x0;  /* 00e3: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 00e6: callx a8 (libc, via reloc-expand) */
  a11 = a1 + (12);  /* 00e9 */
  a10 = a6;  /* 00ec: mov */
  ST32(a1 + 0xc, a5);  /* 00ef */
  ST16(a1 + 0x10, a5);  /* 00f2 */
  __asm__ volatile("" ::: "memory");  /* 00f5: memw */
  __asm__ volatile("" ::: "memory");  /* 00f8: memw */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 00fb: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6);  /* 00fe: callx a8 via reloc-expand */
  if (a7 != 1) goto L_0107;  /* 0101: bnei a7, 1, 107 <mesh_root_process_roots_ie+0x7b> */
  L_0104: goto L_0195;  /* 0104: j */
  L_0107: if (a7 != 3) goto L_010d;  /* 0107: bnei a7, 3, 10d <mesh_root_process_roots_ie+0x81> */
  L_010a: goto L_02a6;  /* 010a: j */
  L_010d: if (a7 != 0) goto L_02f8;  /* 010d: bnez a7, 2f8 <mesh_root_process_roots_ie+0x26c> */
  L_0110: a12 = 6;  /* 0110 */
  a11 = a3 + (4);  /* 0112 */
  a10 = a1 + (12);  /* 0114 */
  a8 = (u32)&memcmp + 0x0;  /* 0116: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 0119: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0121;  /* 011c: bnez.n a10, 121 <mesh_root_process_roots_ie+0x95> */
  L_011e: goto L_017a;  /* 011e: j */
  L_0121: a4 = (u32)(RODATA__rodata_mesh_root_process_roots_ie_str1_1 + 0x0);  /* 0121: l32r -> .rodata.mesh_root_process_roots_ie.str1.1 */
  a12 = 0x7f1;  /* 0124 */
  a13 = a4;  /* 0127 */
  a12 = a12 + a12;  /* 0129 */
  a11 = a1 + (20);  /* 012b */
  a10 = a3;  /* 012e */
  a8 = (u32)&mesh_is_new_found_conflict_root;  /* 0130: l32r -> func addr */
  a2 = mesh_is_new_found_conflict_root(a2, a3, a4, a5, a6);  /* 0133: callx a8 via reloc-expand */
  a2 = a10;  /* 0136 */
  if (a10 != 0) goto L_0155;  /* 0138: bnez.n a10, 155 <mesh_root_process_roots_ie+0xc9> */
  L_013a: a12 = 0x00000fe5u;  /* 013a: l32r = 4069 */
  a13 = a4;  /* 013d: mov */
  a11 = a1 + (20);  /* 0140 */
  a10 = a3;  /* 0143: mov */
  a8 = (u32)&esp_mesh_get_conflict_root_state;  /* 0146: l32r -> func addr */
  a2 = esp_mesh_get_conflict_root_state(a2, a3, a4, a5, a6);  /* 0149: callx a8 via reloc-expand */
  if (a10 != 3) goto L_0152;  /* 014c: bnei a10, 3, 152 <mesh_root_process_roots_ie+0xc6> */
  L_014f: goto L_0319;  /* 014f: j */
  L_0152: goto L_0181;  /* 0152: j */
  L_0155: a2 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0155: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a11 = LD32(a1 + 0x14);  /* 0158 */
  a11 = a11 + (a11 << 1);  /* 015a */
  a2 = LD32(a2 + 0x0);  /* 015d */
  a11 = a11 + (a2 << 3);  /* 015f */
  L_0162: a12 = 12;  /* 0162 */
  a11 = a11 + (13);  /* 0164 */
  a10 = a1;  /* 0166 */
  a8 = (u32)&memcpy + 0x0;  /* 0168: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 016b: callx a8 (libc, via reloc-expand) */
  a12 = 12;  /* 016e */
  a11 = a1;  /* 0170 */
  a10 = 57;  /* 0172 */
  L_0174: a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 0174: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6);  /* 0177: callx a8 via reloc-expand */
  L_017a: a2 = 0;  /* 017a */
  goto L_032c;  /* 017c: j */
  L_0181: a11 = LD32(a1 + 0x14);  /* 0181 */
  a13 = a4;  /* 0183 */
  a12 = a6 << 12;  /* 0185 */
  a10 = a3;  /* 0188 */
  a8 = (u32)&esp_mesh_update_conflict_root;  /* 018a: l32r -> func addr */
  a2 = esp_mesh_update_conflict_root(a2, a3, a4, a5, a6);  /* 018d: callx a8 via reloc-expand */
  goto L_032c;  /* 0190: j */
  L_0195: a12 = 6;  /* 0195 */
  a11 = a3 + (4);  /* 0197 */
  a10 = a1 + (12);  /* 0199 */
  a8 = (u32)&memcmp + 0x0;  /* 019b: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 019e: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 01a1 */
  if (a10 != 0) goto L_0264;  /* 01a3: bnez a10, 264 <mesh_root_process_roots_ie+0x1d8> */
  L_01a6: a4 = (u32)&esp_mesh_appie + 0x0;  /* 01a6: l32r -> global */
  a12 = a1 + (24);  /* 01a9 */
  a11 = 8;  /* 01ac */
  a10 = LD32(a4 + 0x0);  /* 01ae */
  a10 = a10 + (2);  /* 01b0 */
  a8 = (u32)&ieee80211_mesh_quick_get;  /* 01b3: l32r -> func addr */
  a2 = ieee80211_mesh_quick_get(a2, a3, a4, a5, a6);  /* 01b6: callx a8 via reloc-expand */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 01b9: l32r -> global */
  a5 = LD32(a4 + 0x0);  /* 01bc */
  a10 = LD32(a5 + 0x110);  /* 01be */
  /* 01c1: INDIRECT callx a10 <- mem[a5+0x110]; result unknown */ a2 = 0;
  a5 = (u32)&LOCAL__bss_post_event_time_7 + 0x0;  /* 01c4: l32r -> .bss.post_event_time$7 (same-object static) */
  a6 = LD32(a5 + 0x4);  /* 01c7 */
  if ((i32)a11 < (i32)a6) goto L_01f6;  /* 01c9: blt a11, a6, 1f6 <mesh_root_process_roots_ie+0x16a> */
  L_01cc: if (a6 != a11) goto L_01d4;  /* 01cc: bne a6, a11, 1d4 <mesh_root_process_roots_ie+0x148> */
  L_01cf: a6 = LD32(a5 + 0x0);  /* 01cf */
  if (a10 < a6) goto L_01f6;  /* 01d1: bltu a10, a6, 1f6 <mesh_root_process_roots_ie+0x16a> */
  L_01d4: a7 = 1;  /* 01d4 */
  a6 = LD32(a4 + 0x0);  /* 01d6 */
  a10 = LD32(a6 + 0x110);  /* 01d8 */
  /* 01db: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a6 = LD32(a5 + 0x0);  /* 01de */
  a6 = a10 - a6;  /* 01e0: sub */
  a8 = LD32(a5 + 0x4);  /* 01e3 */
  if (a10 < a6) goto L_01ec;  /* 01e6: bltu a10, a6, 1ec <mesh_root_process_roots_ie+0x160> */
  L_01e9: a7 = 0;  /* 01e9 */
  L_01ec: a8 = a11 - a8;  /* 01ec: sub */
  a8 = a8 - a7;  /* 01ef: sub */
  goto L_021f;  /* 01f2: j */
  L_01f6: a6 = LD32(a4 + 0x0);  /* 01f6 */
  a10 = LD32(a6 + 0x110);  /* 01f8 */
  a6 = -1;  /* 01fb */
  /* 01fd: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a8 = 1;  /* 0200 */
  a7 = LD32(a5 + 0x0);  /* 0202 */
  a7 = a7 ^ a6;  /* 0204 */
  a10 = a7 + a10;  /* 0207 */
  a6 = LD32(a5 + 0x4);  /* 0209 */
  if (a10 < a7) goto L_0210;  /* 020b: bltu a10, a7, 210 <mesh_root_process_roots_ie+0x184> */
  L_020e: a8 = 0;  /* 020e */
  L_0210: a11 = a6 + a11;  /* 0210 */
  a6 = a10 + (1);  /* 0212 */
  a11 = a8 + a11;  /* 0214 */
  a8 = 1;  /* 0216 */
  if (a6 < a10) goto L_021d;  /* 0218: bltu a6, a10, 21d <mesh_root_process_roots_ie+0x191> */
  L_021b: a8 = 0;  /* 021b */
  L_021d: a8 = a8 + a11;  /* 021d */
  L_021f: a6 = a6 >> 10;  /* 021f */
  a8 = a8 << 22;  /* 0222 */
  a7 = LD32(a5 + 0x4);  /* 0225 */
  a8 = a8 | a6;  /* 0227 */
  a6 = LD32(a5 + 0x0);  /* 022a */
  a6 = a6 | a7;  /* 022c */
  if (a6 == 0) goto L_023a;  /* 022f: beqz.n a6, 23a <mesh_root_process_roots_ie+0x1ae> */
  L_0231: a6 = 0x00001387u;  /* 0231: l32r = 4999 */
  if (a6 < a8) goto L_023a;  /* 0234: bltu a6, a8, 23a <mesh_root_process_roots_ie+0x1ae> */
  L_0237: goto L_017a;  /* 0237: j */
  L_023a: a12 = 12;  /* 023a */
  a11 = a3 + a12;  /* 023c */
  a10 = a1;  /* 023e */
  a8 = (u32)&memcpy + 0x0;  /* 0240: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 0243: callx a8 (libc, via reloc-expand) */
  a12 = 12;  /* 0246 */
  a11 = a1;  /* 0248 */
  a10 = 58;  /* 024a */
  a8 = (u32)&wifi_mesh_event_post + 0x0;  /* 024c: l32r -> global */
  a2 = wifi_mesh_event_post(a2, a3, a4, a5, a6);  /* 024f: callx a8 via reloc-expand */
  a3 = LD32(a4 + 0x0);  /* 0252 */
  a10 = LD32(a3 + 0x110);  /* 0254 */
  /* 0257: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  ST32(a5 + 0x0, a10);  /* 025a */
  ST32(a5 + 0x4, a11);  /* 025c */
  __asm__ volatile("" ::: "memory");  /* 025e: memw */
  goto L_032c;  /* 0261: j */
  L_0264: a4 = (u32)(RODATA__rodata_ieee80211_vnd_mesh_roots_set_str1_1 + 0x0);  /* 0264: -> "yield" */
  a12 = 129;  /* 0267 */
  a13 = a4;  /* 026a: mov */
  a12 = a12 << 5;  /* 026d */
  a11 = a1 + (20);  /* 0270 */
  a10 = a3;  /* 0273: mov */
  a8 = (u32)&esp_mesh_get_conflict_root_state;  /* 0276: l32r -> func addr */
  a2 = esp_mesh_get_conflict_root_state(a2, a3, a4, a5, a6);  /* 0279: callx a8 via reloc-expand */
  if (a10 == 3) goto L_0282;  /* 027c: beqi a10, 3, 282 <mesh_root_process_roots_ie+0x1f6> */
  L_027f: goto L_017a;  /* 027f: j */
  L_0282: a2 = LD32(a1 + 0x14);  /* 0282 */
  a10 = a3;  /* 0284 */
  a11 = a2;  /* 0286: mov */
  a13 = a4;  /* 0289: mov */
  a2 = a2 + (a2 << 1);  /* 028c */
  a12 = 0x00001023u;  /* 028f: l32r = 4131 */
  a8 = (u32)&esp_mesh_update_conflict_root;  /* 0292: l32r -> func addr */
  a2 = esp_mesh_update_conflict_root(a2, a3, a4, a5, a6);  /* 0295: callx a8 via reloc-expand */
  a3 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0298: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a3 = LD32(a3 + 0x0);  /* 029b */
  a11 = a2 + (a3 << 3);  /* 029d */
  goto L_0162;  /* 02a0: j */
  L_02a6: a2 = a3 + (4);  /* 02a6 */
  a12 = 6;  /* 02a8 */
  a11 = a2;  /* 02aa */
  a10 = a1 + (12);  /* 02ac */
  a8 = (u32)&memcmp + 0x0;  /* 02af: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 02b2: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_017a;  /* 02b5: beqz a10, 17a <mesh_root_process_roots_ie+0xee> */
  L_02b8: a4 = (u32)(RODATA__rodata__mesh_roots_process_yield_str1_1 + 0x0);  /* 02b8: -> "recv fixed" */
  a10 = a2;  /* 02bb */
  a12 = a4;  /* 02bd */
  a11 = 0x00001032u;  /* 02bf: l32r = 4146 */
  a8 = (u32)&esp_mesh_find_conflict_root;  /* 02c2: l32r -> func addr */
  a2 = esp_mesh_find_conflict_root(a2, a3, a4, a5, a6);  /* 02c5: callx a8 via reloc-expand */
  ST32(a1 + 0x14, a10);  /* 02c8 */
  if (a10 != -1) goto L_02e5;  /* 02ca: bnei a10, -1, 2e5 <mesh_root_process_roots_ie+0x259> */
  L_02cd: a12 = 12;  /* 02cd */
  a11 = a3;  /* 02cf */
  a10 = a1;  /* 02d1 */
  __asm__ volatile("" ::: "memory");  /* 02d3: memw */
  a8 = (u32)&memcpy + 0x0;  /* 02d6: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 02d9: callx a8 (libc, via reloc-expand) */
  a12 = 12;  /* 02dc */
  a11 = a1;  /* 02de */
  a10 = 59;  /* 02e0 */
  goto L_0174;  /* 02e2: j */
  L_02e5: a11 = 0x0000104bu;  /* 02e5: l32r = 4171 */
  a12 = a4;  /* 02e8: mov */
  a10 = a2;  /* 02eb: mov */
  a8 = (u32)&esp_mesh_remove_conflict_root;  /* 02ee: l32r -> func addr */
  a2 = esp_mesh_remove_conflict_root(a2, a3, a4, a5, a6);  /* 02f1: callx a8 via reloc-expand */
  goto L_017a;  /* 02f4: j */
  L_02f8: a13 = (u32)(RODATA__rodata_wlog_warning_24 + 0x0);  /* 02f8: l32r -> .rodata_wlog_warning.24 */
  a14 = 0x105;  /* 02fb */
  a15 = a7;  /* 02fe */
  a14 = a14 << 4;  /* 0300 */
  a12 = 2;  /* 0303 */
  a11 = a6 << 21;  /* 0305 */
  a10 = a6;  /* 0308 */
  a8 = (u32)&wifi_log + 0x0;  /* 030a: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6);  /* 030d: callx a8 via reloc-expand */
  goto L_017a;  /* 0310: j */
  L_0314: a2 = -1;  /* 0314 */
  goto L_032c;  /* 0316: j */
  L_0319: a12 = 0x00000fe9u;  /* 0319: l32r = 4073 */
  a13 = a4;  /* 031c */
  a10 = a3;  /* 031e */
  a11 = LD32(a1 + 0x14);  /* 0320 */
  a8 = (u32)&esp_mesh_update_conflict_root;  /* 0322: l32r -> func addr */
  a2 = esp_mesh_update_conflict_root(a2, a3, a4, a5, a6);  /* 0325: callx a8 via reloc-expand */
  goto L_0155;  /* 0328: j */
  L_032c: return a2;  /* 032c: retw.n */
}


/* mesh_set_ie_crypto_config @ mesh_quick.o 00000014 size 82B bind GLOBAL
 * Calls: strnlen, memcpy, ieee80211_vnd_mesh_update_beacon | Data refs: .bss.s_mesh_ie_crypto_funcs, .bss.s_mesh_ie_crypto_key
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=5); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_set_ie_crypto_config(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a3 = 0x102;  /* 0017 */
  if (a2 == 0) goto L_0062;  /* 001a: beqz a2, 62 <mesh_set_ie_crypto_config+0x4e> */
  L_001d: a3 = LD32(a2 + 0x20);  /* 001d */
  if (a3 == 0) goto L_002c;  /* 001f: beqz.n a3, 2c <mesh_set_ie_crypto_config+0x18> */
  L_0021: a8 = (u32)&LOCAL__bss_s_mesh_ie_crypto_funcs + 0x0;  /* 0021: l32r -> .bss.s_mesh_ie_crypto_funcs (same-object static) */
  a10 = LD32(a3 + 0x0);  /* 0024 */
  a9 = LD32(a3 + 0x4);  /* 0026 */
  ST32(a8 + 0x0, a10);  /* 0028 */
  ST32(a8 + 0x4, a9);  /* 002a */
  L_002c: a11 = 32;  /* 002c */
  a10 = a2;  /* 002e */
  __asm__ volatile("" ::: "memory");  /* 0030: memw */
  a8 = (u32)&strnlen + 0x0;  /* 0033: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0036: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_004c;  /* 0039: beqz.n a10, 4c <mesh_set_ie_crypto_config+0x38> */
  L_003b: a10 = (u32)&LOCAL__bss_s_mesh_ie_crypto_key + 0x0;  /* 003b: l32r -> .bss.s_mesh_ie_crypto_key (same-object static) */
  a12 = 32;  /* 003e */
  a11 = a2;  /* 0040 */
  a8 = (u32)&memcpy + 0x0;  /* 0042: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0045: callx a8 (libc, via reloc-expand) */
  goto L_0055;  /* 0048: j */
  L_004c: if (a3 != 0) goto L_0055;  /* 004c: bnez.n a3, 55 <mesh_set_ie_crypto_config+0x41> */
  L_004e: a2 = (u32)&LOCAL__bss_s_mesh_ie_crypto_funcs + 0x0;  /* 004e: l32r -> .bss.s_mesh_ie_crypto_funcs (same-object static) */
  ST32(a2 + 0x0, a3);  /* 0051 */
  ST32(a2 + 0x4, a3);  /* 0053 */
  L_0055: a10 = 1;  /* 0055 */
  __asm__ volatile("" ::: "memory");  /* 0057: memw */
  a8 = (u32)&ieee80211_vnd_mesh_update_beacon + 0x0;  /* 005a: l32r -> global */
  a2 = ieee80211_vnd_mesh_update_beacon(a2, a3, a4, a5, a6, a7);  /* 005d: callx a8 via reloc-expand */
  a3 = 0;  /* 0060 */
  L_0062: a2 = a3;  /* 0062 */
  return a2;  /* 0064: retw.n */
}


/* mesh_set_parent_candidate @ mesh_quick.o 00000024 size 221B bind GLOBAL
 * Calls: memcmp, ic_get_random, memcpy | indirect[2]: mem[a9+0x110]; mem[a8+0x110] | Data refs: g_mesh_topology, .bss.s_mesh_parent_candidate, g_osi_funcs_p
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=6); reloc-direct=3, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_set_parent_candidate(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a5, a6, a7, a8, a9;
  float F42400;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a5 = 1;  /* 0027 */
  a6 = 0;  /* 0029 */
  if (a2 == 0) a6 = a5;  /* 002b */
  a7 = (a6 >> 8) & 0x1;  /* 002e: extui width 1 */
  if (a6 != 0) goto L_00fa;  /* 0031: bnez a6, fa <mesh_set_parent_candidate+0xd6> */
  L_0034: if (a3 == 0) a7 = a5;  /* 0034 */
  if (a7 != 0) goto L_00fa;  /* 0037: bnez a7, fa <mesh_set_parent_candidate+0xd6> */
  L_003a: a6 = (u32)&g_mesh_topology + 0x0;  /* 003a: l32r -> global */
  a8 = a7;  /* 003d */
  a9 = LD32(a6 + 0x0);  /* 003f */
  if (a9 != 0) a8 = a5;  /* 0041 */
  if (a8 == 0) goto L_0050;  /* 0044: beqz a8, 50 <mesh_set_parent_candidate+0x2c> */
  L_0047: if (a4 != 0) a5 = a7;  /* 0047 */
  a7 = 0x102;  /* 004a */
  if (a5 != 0) goto L_00fd;  /* 004d: bnez a5, fd <mesh_set_parent_candidate+0xd9> */
  L_0050: a5 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 0050: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  a8 = LD8U(a5 + 0x0);  /* 0053 */
  a7 = (u32)&LOCAL__bss_s_mesh_parent_candidate + 0x0;  /* 0056: l32r -> .bss.s_mesh_parent_candidate (same-object static) */
  if (a8 == 0) goto L_006c;  /* 0059: beqz.n a8, 6c <mesh_set_parent_candidate+0x48> */
  L_005b: a12 = 92;  /* 005b */
  a11 = a7;  /* 005d: mov */
  a10 = a2;  /* 0060: mov */
  a8 = (u32)&memcmp + 0x0;  /* 0063: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 0066: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00b5;  /* 0069: bnez a10, b5 <mesh_set_parent_candidate+0x91> */
  L_006c: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 006c: l32r -> global */
  a9 = LD32(a8 + 0x0);  /* 006f */
  a10 = LD32(a9 + 0x110);  /* 0072 */
  ST32(a1 + 0x0, a8);  /* 0075 */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  /* 007b: INDIRECT callx a10 <- mem[a9+0x110]; result unknown */ a2 = 0;
  a8 = LD32(a1 + 0x0);  /* 007e */
  a8 = LD32(a8 + 0x0);  /* 0080 */
  ST32(a5 + 0xa0, a10);  /* 0082 */
  a10 = LD32(a8 + 0x110);  /* 0085 */
  ST32(a5 + 0xa4, a11);  /* 0088 */
  __asm__ volatile("" ::: "memory");  /* 008b: memw */
  /* 008e: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  ST32(a5 + 0xb0, a10);  /* 0091 */
  ST32(a5 + 0xb4, a11);  /* 0094 */
  __asm__ volatile("" ::: "memory");  /* 0097: memw */
  a8 = (u32)&ic_get_random + 0x0;  /* 009a: l32r -> global */
  a2 = ic_get_random(a2, a3, a4);  /* 009d: callx a8 via reloc-expand */
  a8 = 0x007fffffu;  /* 00a0: l32r = 8388607 */
  a10 = a10 & a8;  /* 00a3 */
  a8 = 0x00f42400u;  /* 00a6: l32r = 16000000 */
  a10 = a10 + a8;  /* 00a9 */
  a8 = 0;  /* 00ac */
  ST32(a5 + 0xa8, a10);  /* 00af */
  ST32(a5 + 0xac, a8);  /* 00b2 */
  L_00b5: a8 = 1;  /* 00b5 */
  a11 = a2;  /* 00b7 */
  a12 = 92;  /* 00b9 */
  a10 = a7;  /* 00bb */
  ST8(a5 + 0x0, a8);  /* 00bd */
  __asm__ volatile("" ::: "memory");  /* 00c0: memw */
  __asm__ volatile("" ::: "memory");  /* 00c3: memw */
  a8 = (u32)&memcpy + 0x0;  /* 00c6: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 00c9: callx a8 (libc, via reloc-expand) */
  a2 = LD32(a6 + 0x0);  /* 00cc */
  if (a2 != 0) goto L_00e0;  /* 00ce: bnez.n a2, e0 <mesh_set_parent_candidate+0xbc> */
  L_00d0: a2 = LD8U(a3 + 0xf);  /* 00d0 */
  ST8(a5 + 0x6f, a2);  /* 00d3 */
  __asm__ volatile("" ::: "memory");  /* 00d6: memw */
  __asm__ volatile("" ::: "memory");  /* 00d9: memw */
  goto L_00e9;  /* 00dc: j */
  L_00e0: a2 = LD16U(a4 + 0x2);  /* 00e0 */
  ST16(a5 + 0x9c, a2);  /* 00e3 */
  __asm__ volatile("" ::: "memory");  /* 00e6: memw */
  L_00e9: a7 = 0;  /* 00e9 */
  a2 = LD8U(a3 + 0x11);  /* 00eb */
  ST8(a5 + 0x71, a2);  /* 00ee */
  __asm__ volatile("" ::: "memory");  /* 00f1: memw */
  __asm__ volatile("" ::: "memory");  /* 00f4: memw */
  goto L_00fd;  /* 00f7: j */
  L_00fa: a7 = 0x102;  /* 00fa */
  L_00fd: a2 = a7;  /* 00fd */
  return a2;  /* 00ff: retw.n */
}


/* mesh_set_parent_monitor_config @ mesh_quick.o 00000014 size 113B bind GLOBAL
 * Calls: none | indirect[3]: mem[a8+0x110]; mem[a2+0x110]; mem[a3+0x110] | Data refs: .bss.s_mesh_monitor_parent_cfg, g_osi_funcs_p, .bss.s_parent_monitor_weak_time, .bss.s_parent_worse_rssi_time, .bss.s_parent_monitor_assoc_time
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=5); reloc-direct=0, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_set_parent_monitor_config(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 0017 */
  a2 = 0x102;  /* 0019 */
  if (a8 == 0) goto L_0080;  /* 001c: beqz a8, 80 <mesh_set_parent_monitor_config+0x6c> */
  L_001f: a3 = (u32)&LOCAL__bss_s_mesh_monitor_parent_cfg + 0x0;  /* 001f: l32r -> .bss.s_mesh_monitor_parent_cfg (same-object static) */
  a2 = LD8U(a8 + 0x0);  /* 0022 */
  a8 = LD8U(a8 + 0x1);  /* 0025 */
  ST8(a3 + 0x0, a2);  /* 0028 */
  ST8(a3 + 0x1, a8);  /* 002b */
  __asm__ volatile("" ::: "memory");  /* 002e: memw */
  a8 = (a8 >> 8) & 0x1;  /* 0031: extui width 1 */
  if (a8 == 0) goto L_0062;  /* 0034: beqz.n a8, 62 <mesh_set_parent_monitor_config+0x4e> */
  L_0036: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0036: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 0039 */
  a10 = LD32(a8 + 0x110);  /* 003c */
  __asm__ volatile("" ::: "memory");  /* 003f: memw */
  /* 0042: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = (u32)&LOCAL__bss_s_parent_monitor_weak_time + 0x0;  /* 0045: l32r -> .bss.s_parent_monitor_weak_time (same-object static) */
  a2 = LD32(a2 + 0x0);  /* 0048 */
  ST32(a8 + 0x0, a10);  /* 004a */
  a10 = LD32(a2 + 0x110);  /* 004d */
  ST32(a8 + 0x4, a11);  /* 0050 */
  __asm__ volatile("" ::: "memory");  /* 0053: memw */
  /* 0056: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a2 = (u32)&LOCAL__bss_s_parent_worse_rssi_time + 0x0;  /* 0059: l32r -> .bss.s_parent_worse_rssi_time (same-object static) */
  ST32(a2 + 0x0, a10);  /* 005c */
  ST32(a2 + 0x4, a11);  /* 005f */
  L_0062: a2 = 0;  /* 0062 */
  a3 = LD8U(a3 + 0x0);  /* 0064 */
  if (a3 == a2) goto L_0080;  /* 0067: beq a3, a2, 80 <mesh_set_parent_monitor_config+0x6c> */
  L_006a: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 006a: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006d */
  a10 = LD32(a3 + 0x110);  /* 0070 */
  __asm__ volatile("" ::: "memory");  /* 0073: memw */
  /* 0076: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  a3 = (u32)&LOCAL__bss_s_parent_monitor_assoc_time + 0x0;  /* 0079: l32r -> .bss.s_parent_monitor_assoc_time (same-object static) */
  ST32(a3 + 0x0, a10);  /* 007c */
  ST32(a3 + 0x4, a11);  /* 007e */
  L_0080: __asm__ volatile("" ::: "memory");  /* 0080: memw */
  return a2;  /* 0083: retw.n */
}


/* mesh_set_rssi_threshold @ mesh_quick.o 00000008 size 26B bind GLOBAL
 * Calls: memcpy | Data refs: .bss.s_mesh_rssi_threshold
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_set_rssi_threshold(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a11 = a2;  /* 000b */
  a2 = 0x102;  /* 000d */
  if (a11 == 0) goto L_0020;  /* 0010: beqz.n a11, 20 <mesh_set_rssi_threshold+0x18> */
  L_0012: a10 = (u32)&LOCAL__bss_s_mesh_rssi_threshold + 0x0;  /* 0012: l32r -> .bss.s_mesh_rssi_threshold (same-object static) */
  a12 = 12;  /* 0015 */
  a8 = (u32)&memcpy + 0x0;  /* 0018: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 001b: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 001e */
  L_0020: return a2;  /* 0020: retw.n */
}


/* print_roots_ie @ mesh_quick.o 00000040 size 594B bind GLOBAL
 * Calls: mesh_get_vnd_roots_len, wifi_log, roots_type2str, esp_mesh_get_router_bssid | Data refs: .bss.s_mesh_roots_ie_life, .bss.wifi_vnd_ext_mesh_roots, .rodata_wlog_warning.12, .rodata_wlog_warning.13, .rodata_wlog_warning.14, .bss.s_mesh_conflict_roots, .rodata_wlog_warning.15, .rodata_wlog_warning.16
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=4, refs=12); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 print_roots_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0040: entry a1, 96 (frame 96 bytes) */
  a8 = (u32)&mesh_get_vnd_roots_len;  /* 0043: l32r -> func addr */
  a2 = mesh_get_vnd_roots_len(a2, a3, a4, a5, a6, a7);  /* 0046: callx a8 via reloc-expand */
  a2 = (u32)&LOCAL__bss_s_mesh_roots_ie_life + 0x0;  /* 0049: l32r -> .bss.s_mesh_roots_ie_life (same-object static) */
  a11 = 1;  /* 004c */
  a14 = a10;  /* 004e */
  a12 = 2;  /* 0050 */
  a11 = a11 << 21;  /* 0052 */
  a4 = LD8U(a2 + 0x10);  /* 0055 */
  a10 = 1;  /* 0058 */
  a5 = 0;  /* 005a */
  a3 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 005c: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a15 = LD32(a3 + 0x0);  /* 005f */
  a15 = (a15 >> 1) & 0x1;  /* 0061: extui width 1 */
  ST32(a1 + 0x20, a4);  /* 0064 */
  a4 = a3;  /* 0066 */
  a2 = LD8U(a2 + 0x0);  /* 0068 */
  ST32(a1 + 0x1c, a2);  /* 006b */
  a2 = LD8U(a3 + 0x19);  /* 006d */
  ST32(a1 + 0x18, a2);  /* 0070 */
  a2 = LD8U(a3 + 0x11);  /* 0072 */
  ST32(a1 + 0x14, a2);  /* 0075 */
  a2 = LD8U(a3 + 0x9);  /* 0077 */
  ST32(a1 + 0x10, a2);  /* 007a */
  a2 = LD8U(a3 + 0x1);  /* 007c */
  ST32(a1 + 0xc, a2);  /* 007f */
  a2 = LD32(a3 + 0x18);  /* 0081 */
  a2 = (a2 >> 1) & 0x1;  /* 0083: extui width 1 */
  ST32(a1 + 0x8, a2);  /* 0086 */
  a2 = LD32(a3 + 0x10);  /* 0088 */
  a2 = (a2 >> 1) & 0x1;  /* 008a: extui width 1 */
  ST32(a1 + 0x4, a2);  /* 008d */
  a2 = LD32(a3 + 0x8);  /* 008f */
  a2 = (a2 >> 1) & 0x1;  /* 0092: extui width 1 */
  a13 = (u32)(RODATA__rodata_wlog_warning_12 + 0x0);  /* 0095: l32r -> .rodata_wlog_warning.12 */
  ST32(a1 + 0x0, a2);  /* 0098 */
  __asm__ volatile("" ::: "memory");  /* 009b: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 009e: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 00a1: callx a8 via reloc-expand */
  L_00a4: a2 = a5 + (a3 << 3);  /* 00a4 */
  a10 = LD32(a2 + 0x0);  /* 00a7 */
  if (((a10 >> 0) & 1) != 0) goto L_00b9;  /* 00a9: bbsi a10, 0, b9 <print_roots_ie+0x79> */
  L_00ac: a5 = a5 + (1);  /* 00ac */
  a4 = a4 + (8);  /* 00ae */
  if (a5 != 4) goto L_00a4;  /* 00b0: bnei a5, 4, a4 <print_roots_ie+0x64> */
  L_00b3: goto L_014a;  /* 00b3: j */
  L_00b9: a10 = (a10 >> 7) & 0x3;  /* 00b9: extui width 2 */
  a8 = (u32)&roots_type2str;  /* 00bc: l32r -> func addr */
  a2 = roots_type2str(a2, a3, a4, a5, a6, a7);  /* 00bf: callx a8 via reloc-expand */
  a2 = 1;  /* 00c2 */
  a15 = LD8U(a4 + 0x1);  /* 00c4 */
  a14 = a10;  /* 00c7 */
  a11 = a2 << 21;  /* 00c9 */
  a10 = a2;  /* 00cc */
  a12 = 2;  /* 00ce */
  a13 = (u32)(RODATA__rodata_wlog_warning_13 + 0x0);  /* 00d0: l32r -> .rodata_wlog_warning.13 */
  a6 = 0;  /* 00d3 */
  ST32(a1 + 0x0, a2);  /* 00d5 */
  __asm__ volatile("" ::: "memory");  /* 00d7: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 00da: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 00dd: callx a8 via reloc-expand */
  a2 = LD32(a4 + 0x4);  /* 00e0 */
  goto L_0140;  /* 00e2: j */
  L_00e5: a8 = LD8U(a2 + 0x3);  /* 00e5 */
  a11 = 1;  /* 00e8 */
  a8 = a8 << 8;  /* 00ea */
  a14 = a6;  /* 00ed */
  a12 = 2;  /* 00ef */
  a10 = LD8U(a2 + 0x2);  /* 00f1 */
  a11 = a11 << 21;  /* 00f4 */
  a8 = a8 | a10;  /* 00f7 */
  a10 = 1;  /* 00fa */
  a6 = a6 + (1);  /* 00fc */
  a15 = LD8U(a2 + 0x0);  /* 00fe */
  a9 = LD8U(a2 + 0x1);  /* 0101 */
  a9 = a9 << 8;  /* 0104 */
  a15 = a9 | a15;  /* 0107 */
  ST32(a1 + 0x1c, a8);  /* 010a */
  a8 = LD8U(a2 + 0xa);  /* 010c */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 010f: sext */
  ST32(a1 + 0x18, a8);  /* 0112 */
  a8 = LD8U(a2 + 0x9);  /* 0114 */
  ST32(a1 + 0x14, a8);  /* 0117 */
  a8 = LD8U(a2 + 0x8);  /* 0119 */
  ST32(a1 + 0x10, a8);  /* 011c */
  a8 = LD8U(a2 + 0x7);  /* 011e */
  ST32(a1 + 0xc, a8);  /* 0121 */
  a8 = LD8U(a2 + 0x6);  /* 0123 */
  ST32(a1 + 0x8, a8);  /* 0126 */
  a8 = LD8U(a2 + 0x5);  /* 0128 */
  ST32(a1 + 0x4, a8);  /* 012b */
  a8 = LD8U(a2 + 0x4);  /* 012d */
  a2 = a2 + (12);  /* 0130 */
  a13 = (u32)(RODATA__rodata_wlog_warning_14 + 0x0);  /* 0132: l32r -> .rodata_wlog_warning.14 */
  ST32(a1 + 0x0, a8);  /* 0135 */
  __asm__ volatile("" ::: "memory");  /* 0137: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 013a: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 013d: callx a8 via reloc-expand */
  L_0140: a8 = LD8U(a4 + 0x1);  /* 0140 */
  if ((i32)a6 < (i32)a8) goto L_00e5;  /* 0143: blt a6, a8, e5 <print_roots_ie+0xa5> */
  L_0146: goto L_00ac;  /* 0146: j */
  L_014a: a2 = 0;  /* 014a */
  a10 = a1 + (48);  /* 014c */
  ST32(a1 + 0x30, a2);  /* 014f */
  ST16(a1 + 0x34, a2);  /* 0151 */
  __asm__ volatile("" ::: "memory");  /* 0154: memw */
  __asm__ volatile("" ::: "memory");  /* 0157: memw */
  a8 = (u32)&esp_mesh_get_router_bssid + 0x0;  /* 015a: l32r -> global */
  a2 = esp_mesh_get_router_bssid(a2, a3, a4, a5, a6, a7);  /* 015d: callx a8 via reloc-expand */
  a15 = a2;  /* 0160 */
  a3 = (u32)&LOCAL__bss_s_mesh_conflict_roots + 0x0;  /* 0162: l32r -> .bss.s_mesh_conflict_roots (same-object static) */
  a4 = LD32(a3 + 0x0);  /* 0165 */
  if (a4 == a2) goto L_016d;  /* 0167: beq a4, a2, 16d <print_roots_ie+0x12d> */
  L_016a: a15 = LD8U(a4 + 0x0);  /* 016a */
  L_016d: a14 = 0x4c7;  /* 016d */
  a11 = 1;  /* 0170 */
  a14 = a14 + a14;  /* 0172 */
  a12 = 2;  /* 0174 */
  a2 = LD8U(a1 + 0x35);  /* 0176 */
  a11 = a11 << 21;  /* 0179 */
  a10 = 1;  /* 017c */
  ST32(a1 + 0x14, a2);  /* 017e */
  a2 = LD8U(a1 + 0x34);  /* 0180 */
  ST32(a1 + 0x10, a2);  /* 0183 */
  a2 = LD8U(a1 + 0x33);  /* 0185 */
  ST32(a1 + 0xc, a2);  /* 0188 */
  a2 = LD8U(a1 + 0x32);  /* 018a */
  ST32(a1 + 0x8, a2);  /* 018d */
  a2 = LD8U(a1 + 0x31);  /* 018f */
  ST32(a1 + 0x4, a2);  /* 0192 */
  a2 = LD8U(a1 + 0x30);  /* 0194 */
  a13 = (u32)(RODATA__rodata_wlog_warning_15 + 0x0);  /* 0197: l32r -> .rodata_wlog_warning.15 */
  ST32(a1 + 0x0, a2);  /* 019a */
  __asm__ volatile("" ::: "memory");  /* 019c: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 019f: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 01a2: callx a8 via reloc-expand */
  a2 = LD32(a3 + 0x0);  /* 01a5 */
  if (a2 == 0) goto L_0290;  /* 01a8: beqz a2, 290 <print_roots_ie+0x250> */
  L_01ab: a2 = LD8U(a2 + 0x0);  /* 01ab */
  if (a2 == 0) goto L_0290;  /* 01ae: beqz a2, 290 <print_roots_ie+0x250> */
  L_01b1: a4 = 0;  /* 01b1 */
  L_01b4: a8 = a4 + (a4 << 1);  /* 01b4 */
  a2 = LD32(a3 + 0x0);  /* 01b7 */
  a8 = a8 + (a2 << 3);  /* 01b9 */
  a2 = LD8U(a8 + 0x9);  /* 01bc */
  if (((a2 >> 0) & 1) != 0) goto L_01c5;  /* 01bf: bbsi a2, 0, 1c5 <print_roots_ie+0x185> */
  L_01c2: goto L_0288;  /* 01c2: j */
  L_01c5: a5 = a2 >> 1;  /* 01c5 */
  a11 = 1;  /* 01c8 */
  a2 = LD8U(a8 + 0xa);  /* 01ca */
  a14 = a4;  /* 01cd */
  a2 = a2 << 7;  /* 01cf */
  a2 = a2 | a5;  /* 01d2 */
  a12 = 2;  /* 01d5 */
  a9 = LD8U(a8 + 0xb);  /* 01d7 */
  a11 = a11 << 21;  /* 01da */
  a9 = a9 << 15;  /* 01dd */
  a9 = a9 | a2;  /* 01e0 */
  a2 = LD8U(a8 + 0xc);  /* 01e3 */
  a2 = a2 << 23;  /* 01e6 */
  a2 = a2 | a9;  /* 01e9 */
  a15 = LD8U(a8 + 0x11);  /* 01ec */
  ST32(a1 + 0x28, a2);  /* 01ef */
  a9 = LD8U(a8 + 0x2);  /* 01f1 */
  a9 = a9 << 8;  /* 01f4 */
  a2 = LD8U(a8 + 0x1);  /* 01f7 */
  a9 = a9 | a2;  /* 01fa */
  a2 = LD8U(a8 + 0x3);  /* 01fd */
  a2 = a2 << 16;  /* 0200 */
  a2 = a2 | a9;  /* 0203 */
  a10 = LD8U(a8 + 0x4);  /* 0206 */
  a10 = a10 << 24;  /* 0209 */
  a10 = a10 | a2;  /* 020c */
  a10 = a10 >> 10;  /* 020f */
  a9 = LD8U(a8 + 0x6);  /* 0212 */
  a9 = a9 << 8;  /* 0215 */
  a2 = LD8U(a8 + 0x5);  /* 0218 */
  a9 = a9 | a2;  /* 021b */
  a2 = LD8U(a8 + 0x7);  /* 021e */
  a2 = a2 << 16;  /* 0221 */
  a2 = a2 | a9;  /* 0224 */
  a9 = LD8U(a8 + 0x8);  /* 0227 */
  a9 = a9 << 24;  /* 022a */
  a9 = a9 | a2;  /* 022d */
  a2 = a2 << 22;  /* 0230 */
  a10 = a2 | a10;  /* 0233 */
  a2 = (i32)a9 >> 10;  /* 0236 */
  ST32(a1 + 0x20, a10);  /* 0239 */
  a10 = 1;  /* 023b */
  ST32(a1 + 0x24, a2);  /* 023d */
  a2 = LD8U(a8 + 0xe);  /* 023f */
  a2 = a2 << 8;  /* 0242 */
  a5 = LD8U(a8 + 0xd);  /* 0245 */
  a2 = a2 | a5;  /* 0248 */
  ST32(a1 + 0x1c, a2);  /* 024b */
  a2 = LD8U(a8 + 0x17);  /* 024d */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 0250: sext */
  ST32(a1 + 0x18, a2);  /* 0253 */
  a2 = LD8U(a8 + 0x10);  /* 0255 */
  a2 = a2 << 8;  /* 0258 */
  a5 = LD8U(a8 + 0xf);  /* 025b */
  a2 = a2 | a5;  /* 025e */
  ST32(a1 + 0x14, a2);  /* 0261 */
  a2 = LD8U(a8 + 0x16);  /* 0263 */
  ST32(a1 + 0x10, a2);  /* 0266 */
  a2 = LD8U(a8 + 0x15);  /* 0268 */
  ST32(a1 + 0xc, a2);  /* 026b */
  a2 = LD8U(a8 + 0x14);  /* 026d */
  ST32(a1 + 0x8, a2);  /* 0270 */
  a2 = LD8U(a8 + 0x13);  /* 0272 */
  ST32(a1 + 0x4, a2);  /* 0275 */
  a2 = LD8U(a8 + 0x12);  /* 0277 */
  ST32(a1 + 0x0, a2);  /* 027a */
  a13 = (u32)(RODATA__rodata_wlog_warning_16 + 0x0);  /* 027c: l32r -> .rodata_wlog_warning.16 */
  __asm__ volatile("" ::: "memory");  /* 027f: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 0282: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 0285: callx a8 via reloc-expand */
  L_0288: a4 = a4 + (1);  /* 0288 */
  if (a4 == 10) goto L_0290;  /* 028a: beqi a4, 10, 290 <print_roots_ie+0x250> */
  L_028d: goto L_01b4;  /* 028d: j */
  L_0290: return a2;  /* 0290: retw.n */
}


/* roots_type2str @ mesh_quick.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.roots_type2str.str1.1, .rodata.CSWTCH$683
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 roots_type2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (a2 >> 8) & 0x1;  /* 000b: extui width 1 */
  a2 = (u32)(RODATA__rodata_roots_type2str_str1_1 + 0x0);  /* 000e: -> "unknown" */
  if (a8 >= 7u) goto L_001c;  /* 0011: bgeui a8, 7, 1c <roots_type2str+0x14> */
  L_0014: a2 = (u32)(RODATA__rodata_CSWTCH_683 + 0x0);  /* 0014: l32r -> .rodata.CSWTCH$683 */
  a8 = a8 + (a2 << 2);  /* 0017 */
  a2 = LD32(a8 + 0x0);  /* 001a */
  L_001c: return a2;  /* 001c: retw.n */
}


/* --- clone of .text._mesh_roots_process_fixed$part$0 (not in funcdb; reconstructed with same pipeline) ---
/* clone__mesh_roots_process_fixed_part_0 @ mesh_quick.o 00000000 size 113B bind LOCAL
 * Calls: memcmp | Data refs: .bss.wifi_vnd_ext_mesh_roots, g_mesh_max_layer
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 clone__mesh_roots_process_fixed_part_0(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a3, a4, a5, a6, a7, a8, a9;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a5 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 000f: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a3 = 1;  /* 0012 */
  a4 = 0;  /* 0014 */
  a6 = LD8U(a5 + 0x11);  /* 0016 */
  if (a6 == 0) a4 = a3;  /* 0019 */
  a7 = (a4 >> 8) & 0x1;  /* 001c: extui width 1 */
  if (a4 != 0) goto L_006c;  /* 001f: bnez a4, 6c <.text._mesh_roots_process_fixed$part$0+0x6c> */
  L_0022: if (a2 != 0) a3 = a7;  /* 0022 */
  if (a3 != 0) goto L_006c;  /* 0025: bnez a3, 6c <.text._mesh_roots_process_fixed$part$0+0x6c> */
  L_0028: a4 = (u32)&g_mesh_max_layer + 0x0;  /* 0028: l32r -> global */
  a9 = 6;  /* 002b */
  a8 = LD16U(a4 + 0x0);  /* 002d */
  a8 = a8 + (-1);  /* 0030 */
  a13 = (a8 >> 8) & 0x1;  /* 0032: extui width 1 */
  a4 = LD32(a5 + 0x14);  /* 0035 */
  a5 = (a8 >> 8) & 0x1ff;  /* 0037: extui width 9 */
  a4 = a4 + (4);  /* 003a */
  L_003c: a12 = a9;  /* 003c */
  a11 = a2;  /* 003e */
  a10 = a4;  /* 0040 */
  ST32(a1 + 0x0, a9);  /* 0042 */
  a7 = a4 + (-4);  /* 0044 */
  ST32(a1 + 0x4, a13);  /* 0047 */
  __asm__ volatile("" ::: "memory");  /* 0049: memw */
  a8 = (u32)&memcmp + 0x0;  /* 004c: l32r -> global */
  a2 = memcmp(a2);  /* 004f: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x0);  /* 0052 */
  a13 = LD32(a1 + 0x4);  /* 0054 */
  if (a10 != 0) goto L_0062;  /* 0056: bnez a10, 62 <.text._mesh_roots_process_fixed$part$0+0x62> */
  L_0059: ST8(a7 + 0x0, a13);  /* 0059 */
  ST8(a7 + 0x1, a5);  /* 005c */
  __asm__ volatile("" ::: "memory");  /* 005f: memw */
  L_0062: a3 = a3 + (1);  /* 0062 */
  a3 = (a3 >> 8) & 0x1;  /* 0064: extui width 1 */
  a4 = a4 + (12);  /* 0067 */
  if (a3 < a6) goto L_003c;  /* 0069: bltu a3, a6, 3c <.text._mesh_roots_process_fixed$part$0+0x3c> */
  L_006c: __asm__ volatile("" ::: "memory");  /* 006c: memw */
  return a2;  /* 006f: retw.n */
}


/* --- clone of .text._wifi_vnd_ext_mesh_roots_free$part$0 (not in funcdb; reconstructed with same pipeline) ---
/* clone__wifi_vnd_ext_mesh_roots_free_part_0 @ mesh_quick.o 00000000 size 60B bind LOCAL
 * Calls: mesh_free | Data refs: .bss.wifi_vnd_ext_mesh_roots, .rodata.__func__$16
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 clone__wifi_vnd_ext_mesh_roots_free_part_0(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&LOCAL__bss_wifi_vnd_ext_mesh_roots + 0x0;  /* 000f: l32r -> .bss.wifi_vnd_ext_mesh_roots (same-object static) */
  a12 = 0x39f;  /* 0012 */
  a2 = a2 + (a8 << 3);  /* 0015 */
  a11 = (u32)(RODATA__rodata___func___16 + 0x0);  /* 0018: l32r -> .rodata.__func__$16 */
  a10 = LD32(a2 + 0x4);  /* 001b */
  a8 = (u32)&mesh_free + 0x0;  /* 001e: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0021: callx a8 via reloc-expand */
  a8 = 0;  /* 0024 */
  a9 = 254;  /* 0026 */
  ST32(a2 + 0x4, a8);  /* 0029 */
  a8 = LD16U(a2 + 0x0);  /* 002b */
  a8 = a8 & a9;  /* 002e */
  ST16(a2 + 0x0, a8);  /* 0031 */
  __asm__ volatile("" ::: "memory");  /* 0034: memw */
  __asm__ volatile("" ::: "memory");  /* 0037: memw */
  return a2;  /* 003a: retw.n */
}


/* --- clone of .text.is_esp_mesh_roots_announce (not in funcdb; reconstructed with same pipeline) ---
/* clone_is_esp_mesh_roots_announce @ mesh_quick.o 00000000 size 59B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 clone_is_esp_mesh_roots_announce(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = LD8U(a2 + 0x1);  /* 0007 */
  a8 = a2;  /* 000a */
  a2 = 0;  /* 000c */
  if (a9 < 4u) goto L_0039;  /* 000e: bltui a9, 4, 39 <.text.is_esp_mesh_roots_announce+0x39> */
  L_0011: a10 = LD8U(a8 + 0x3);  /* 0011 */
  a10 = a10 << 8;  /* 0014 */
  a9 = LD8U(a8 + 0x2);  /* 0017 */
  a10 = a10 | a9;  /* 001a */
  a9 = LD8U(a8 + 0x4);  /* 001d */
  a9 = a9 << 16;  /* 0020 */
  a9 = a9 | a10;  /* 0023 */
  a8 = LD8U(a8 + 0x5);  /* 0026 */
  a8 = a8 << 24;  /* 0029 */
  a8 = a8 | a9;  /* 002c */
  a9 = 0xf7cb01e8u;  /* 002f: l32r = -137690648 */
  a8 = a8 + a9;  /* 0032 */
  a9 = 1;  /* 0034 */
  if (a8 == 0) a2 = a9;  /* 0036 */
  L_0039: return a2;  /* 0039: retw.n */
}


/* --- clone of .text.is_esp_mesh_roots_fixed (not in funcdb; reconstructed with same pipeline) ---
/* clone_is_esp_mesh_roots_fixed @ mesh_quick.o 00000000 size 59B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 clone_is_esp_mesh_roots_fixed(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = LD8U(a2 + 0x1);  /* 0007 */
  a8 = a2;  /* 000a */
  a2 = 0;  /* 000c */
  if (a9 < 4u) goto L_0039;  /* 000e: bltui a9, 4, 39 <.text.is_esp_mesh_roots_fixed+0x39> */
  L_0011: a10 = LD8U(a8 + 0x3);  /* 0011 */
  a10 = a10 << 8;  /* 0014 */
  a9 = LD8U(a8 + 0x2);  /* 0017 */
  a10 = a10 | a9;  /* 001a */
  a9 = LD8U(a8 + 0x4);  /* 001d */
  a9 = a9 << 16;  /* 0020 */
  a9 = a9 | a10;  /* 0023 */
  a8 = LD8U(a8 + 0x5);  /* 0026 */
  a8 = a8 << 24;  /* 0029 */
  a8 = a8 | a9;  /* 002c */
  a9 = 0xf5cb01e8u;  /* 002f: l32r = -171245080 */
  a8 = a8 + a9;  /* 0032 */
  a9 = 1;  /* 0034 */
  if (a8 == 0) a2 = a9;  /* 0036 */
  L_0039: return a2;  /* 0039: retw.n */
}


/* --- clone of .text.is_esp_mesh_roots_gone (not in funcdb; reconstructed with same pipeline) ---
/* clone_is_esp_mesh_roots_gone @ mesh_quick.o 00000000 size 59B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 clone_is_esp_mesh_roots_gone(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = LD8U(a2 + 0x1);  /* 0007 */
  a8 = a2;  /* 000a */
  a2 = 0;  /* 000c */
  if (a9 < 4u) goto L_0039;  /* 000e: bltui a9, 4, 39 <.text.is_esp_mesh_roots_gone+0x39> */
  L_0011: a10 = LD8U(a8 + 0x3);  /* 0011 */
  a10 = a10 << 8;  /* 0014 */
  a9 = LD8U(a8 + 0x2);  /* 0017 */
  a10 = a10 | a9;  /* 001a */
  a9 = LD8U(a8 + 0x4);  /* 001d */
  a9 = a9 << 16;  /* 0020 */
  a9 = a9 | a10;  /* 0023 */
  a8 = LD8U(a8 + 0x5);  /* 0026 */
  a8 = a8 << 24;  /* 0029 */
  a8 = a8 | a9;  /* 002c */
  a9 = 0xf4cb01e8u;  /* 002f: l32r = -188022296 */
  a8 = a8 + a9;  /* 0032 */
  a9 = 1;  /* 0034 */
  if (a8 == 0) a2 = a9;  /* 0036 */
  L_0039: return a2;  /* 0039: retw.n */
}


/* --- clone of .text.is_esp_mesh_roots_yield (not in funcdb; reconstructed with same pipeline) ---
/* clone_is_esp_mesh_roots_yield @ mesh_quick.o 00000000 size 59B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 clone_is_esp_mesh_roots_yield(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = LD8U(a2 + 0x1);  /* 0007 */
  a8 = a2;  /* 000a */
  a2 = 0;  /* 000c */
  if (a9 < 4u) goto L_0039;  /* 000e: bltui a9, 4, 39 <.text.is_esp_mesh_roots_yield+0x39> */
  L_0011: a10 = LD8U(a8 + 0x3);  /* 0011 */
  a10 = a10 << 8;  /* 0014 */
  a9 = LD8U(a8 + 0x2);  /* 0017 */
  a10 = a10 | a9;  /* 001a */
  a9 = LD8U(a8 + 0x4);  /* 001d */
  a9 = a9 << 16;  /* 0020 */
  a9 = a9 | a10;  /* 0023 */
  a8 = LD8U(a8 + 0x5);  /* 0026 */
  a8 = a8 << 24;  /* 0029 */
  a8 = a8 | a9;  /* 002c */
  a9 = 0xf6cb01e8u;  /* 002f: l32r = -154467864 */
  a8 = a8 + a9;  /* 0032 */
  a9 = 1;  /* 0034 */
  if (a8 == 0) a2 = a9;  /* 0036 */
  L_0039: return a2;  /* 0039: retw.n */
}


/* --- clone of .text.is_esp_mesh_ssid (not in funcdb; reconstructed with same pipeline) ---
/* clone_is_esp_mesh_ssid @ mesh_quick.o 00000000 size 59B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 clone_is_esp_mesh_ssid(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = LD8U(a2 + 0x1);  /* 0007 */
  a8 = a2;  /* 000a */
  a2 = 0;  /* 000c */
  if (a9 < 4u) goto L_0039;  /* 000e: bltui a9, 4, 39 <.text.is_esp_mesh_ssid+0x39> */
  L_0011: a10 = LD8U(a8 + 0x3);  /* 0011 */
  a10 = a10 << 8;  /* 0014 */
  a9 = LD8U(a8 + 0x2);  /* 0017 */
  a10 = a10 | a9;  /* 001a */
  a9 = LD8U(a8 + 0x4);  /* 001d */
  a9 = a9 << 16;  /* 0020 */
  a9 = a9 | a10;  /* 0023 */
  a8 = LD8U(a8 + 0x5);  /* 0026 */
  a8 = a8 << 24;  /* 0029 */
  a8 = a8 | a9;  /* 002c */
  a9 = 0xf9cb01e8u;  /* 002f: l32r = -104136216 */
  a8 = a8 + a9;  /* 0032 */
  a9 = 1;  /* 0034 */
  if (a8 == 0) a2 = a9;  /* 0036 */
  L_0039: return a2;  /* 0039: retw.n */
}


/* --- clone of .text.is_zero_addr (not in funcdb; reconstructed with same pipeline) ---
/* clone_is_zero_addr @ mesh_quick.o 00000000 size 48B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 clone_is_zero_addr(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0000: entry a1, 32 (frame 32 bytes) */
  a9 = LD8U(a2 + 0x1);  /* 0003 */
  a8 = LD8U(a2 + 0x0);  /* 0006 */
  a8 = a8 | a9;  /* 0009 */
  a9 = LD8U(a2 + 0x2);  /* 000c */
  a8 = a8 | a9;  /* 000f */
  a9 = LD8U(a2 + 0x3);  /* 0012 */
  a8 = a8 | a9;  /* 0015 */
  a9 = LD8U(a2 + 0x4);  /* 0018 */
  a8 = a8 | a9;  /* 001b */
  a9 = 0;  /* 001e */
  a2 = LD8U(a2 + 0x5);  /* 0020 */
  a8 = a8 | a2;  /* 0023 */
  a8 = (a8 >> 8) & 0x1;  /* 0026: extui width 1 */
  a2 = 1;  /* 0029 */
  if (a8 != 0) a2 = a9;  /* 002b */
  return a2;  /* 002e: retw.n */
}

