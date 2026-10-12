/* libmesh.a mesh_network.o --- reconstructed C (offline).
 * Role: network lookup: channel scan results, allow-switch, reselect, look-for-network.
 * Object file: 19592 bytes on disk; 5/5 functions reconstructed, ~3404 code bytes.
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
extern u32 g_is_standalone_sta; /* undefined data (reloc-referenced) */
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ext_cfg; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ie; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_rt_capacity; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_organized; /* undefined data (reloc-referenced) */
extern u32 g_mesh_topology; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_clear_parent(); /* defined in another libmesh.a object */
extern u32 esp_mesh_flush_scan_result(); /* defined in another libmesh.a object */
extern u32 esp_mesh_is_root_conflicts_allowed(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_is_same_router(); /* defined in another libmesh.a object */
extern u32 esp_mesh_send_event_internal(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_config(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_scan_get_cur_ap_info(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_scan_get_cur_ap_record(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_config(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_country(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_mode(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_non_mesh_connections(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_vnd_mesh_set(); /* undefined func (args unknown, returns u32) */
extern u32 mesh_free(); /* defined in another libmesh.a object */
extern u32 mesh_malloc(); /* defined in another libmesh.a object */
extern u32 mesh_nwk_check_no_parent_found(); /* defined in another libmesh.a object */
extern u32 mesh_process_parent_organized(); /* defined in another libmesh.a object */
extern u32 nwk_event_id2str(); /* defined in another libmesh.a object */
static const u8 RODATA__rodata[] = { 0x4a, 0x50, 0x00, 0x01, 0x0e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 }; /* .rodata (12 bytes) */
static const u8 RODATA__rodata___func___0[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6e, 0x77, 0x6b, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x6c, 0x65, 0x63 }; /* .rodata.__func__$0 (24 bytes) */
static const u8 RODATA__rodata___func___1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6e, 0x77, 0x6b, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6c, 0x6f, 0x6f, 0x6b, 0x5f, 0x66, 0x6f, 0x72, 0x5f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72 }; /* .rodata.__func__$1 (32 bytes) */
static const u8 RODATA__rodata___func___4[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x64, 0x6f, 0x6e, 0x65, 0x5f, 0x67, 0x65, 0x74, 0x5f, 0x63, 0x68, 0x61, 0x6e, 0x6e }; /* .rodata.__func__$4 (28 bytes) */
static const u8 RODATA__rodata_esp_mesh_channel_enable_jp_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x31, 0x34, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78 }; /* .rodata.esp_mesh_channel_enable_jp.str1.1 (68 bytes) strings: [0x0]="mesh" */
static const u8 RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1[] = { 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x00, 0x6f, 0x70, 0x65, 0x6e, 0x00, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x00, 0x00, 0x5b, 0x56, 0x4f, 0x54, 0x49, 0x4e, 0x47, 0x5d, 0x00, 0x5b, 0x46, 0x49, 0x58, 0x45, 0x44, 0x2d, 0x52, 0x4f, 0x4f, 0x54, 0x5d, 0x00, 0x3c, 0x73, 0x63, 0x61, 0x6e, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x3e, 0x00, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x63, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x20, 0x69, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x28, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x70, 0x61, 0x6e, 0x64, 0x6f, 0x72, 0x61, 0x0a, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x66, 0x69, 0x6e, 0x64, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x3a, 0x25, 0x73, 0x2c, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x63, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x28, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6f, 0x6c, 0x64, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x53, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x25, 0x64, 0x5d, 0x25, 0x73, 0x2c, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x73, 0x73, 0x69, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x66, 0x69, 0x6e, 0x64, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x3a, 0x5b, 0x73, 0x73, 0x69, 0x64, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x5d, 0x25, 0x73, 0x2c, 0x20, 0x72, 0x73, 0x73, 0x69, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x28, 0x25, 0x73, 0x29, 0x2c, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6f, 0x6c, 0x64, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x25, 0x64, 0x5d, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3a, 0x25, 0x64, 0x20, 0x64, 0x75, /* ... +276 bytes */ }; /* .rodata.esp_mesh_scan_done_get_channel.str1.1 (788 bytes) strings: [0x0]="encrypted"; [0xa]="open"; [0xf]="router found"; [0x1d]="[VOTING]"; [0x26]="[FIXED-ROOT]"; [0x33]="<scan router>" */
static const u8 RODATA__rodata_mesh_nwk_process_allow_switch_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x4e, 0x57, 0x4b, 0x5f, 0x50, 0x41, 0x52, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x49, 0x4f, 0x4e, 0x3e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x3c, 0x63, 0x66, 0x67, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3e, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x2c, 0x20, 0x66, 0x69, 0x6e, 0x64, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x73, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x53, 0x53, 0x49, 0x44, 0x3a, 0x25, 0x73, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x4e, 0x57, 0x4b, 0x5f, 0x50, 0x41, 0x52, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x49, 0x4f, 0x4e, 0x3e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3c, 0x63, 0x66, 0x67, 0x3a, 0x25, 0x64, 0x3e, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x2c, 0x20, 0x64, 0x6f, 0x20, 0x61, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73, 0x63, 0x61, 0x6e, 0x0a }; /* .rodata.mesh_nwk_process_allow_switch.str1.1 (228 bytes) */
static const u8 RODATA__rodata_mesh_nwk_process_look_for_network_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x25, 0x73, 0x3e, 0x6e, 0x65, 0x65, 0x64, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x2c, 0x20, 0x6e, 0x65, 0x65, 0x64, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x2c, 0x20, 0x6c, 0x6f, 0x6f, 0x6b, 0x5f, 0x66, 0x6f, 0x72, 0x5f, 0x6e, 0x77, 0x6b, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x25, 0x73, 0x3e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x3c, 0x63, 0x66, 0x67, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3e, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x2c, 0x20, 0x66, 0x69, 0x6e, 0x64, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x73, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x53, 0x53, 0x49, 0x44, 0x3a, 0x25, 0x73, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x25, 0x73, 0x3e, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3c, 0x63, 0x66, 0x67, 0x3a, 0x25, 0x64, 0x3e, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x2c, 0x20, 0x64, 0x6f, 0x20, 0x61, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73, 0x63, 0x61, 0x6e, 0x0a, 0x00 }; /* .rodata.mesh_nwk_process_look_for_network.str1.1 (260 bytes) */
static const u8 RODATA__rodata_mesh_nwk_process_reselect_str1_1[] = { 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x6e, 0x6f, 0x6e, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x2c, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x73, 0x20, 0x64, 0x65, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x65, 0x64, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x20, 0x77, 0x69, 0x66, 0x69, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x28, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x4e, 0x57, 0x4b, 0x5f, 0x50, 0x41, 0x52, 0x45, 0x4e, 0x54, 0x5f, 0x44, 0x49, 0x53, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x45, 0x44, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x67, 0x65, 0x74, 0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x25, 0x73, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x4e, 0x57, 0x4b, 0x5f, 0x50, 0x41, 0x52, 0x45, 0x4e, 0x54, 0x5f, 0x44, 0x49, 0x53, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x45, 0x44, 0x3e, 0x25, 0x73, 0x2c, 0x20, 0x6e, 0x65, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x4e, 0x57, 0x4b, 0x5f, 0x50, 0x41, 0x52, 0x45, 0x4e, 0x54, 0x5f, 0x44, 0x49, 0x53, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x45, 0x44, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x25, 0x73, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a }; /* .rodata.mesh_nwk_process_reselect.str1.1 (344 bytes) strings: [0x0]="root"; [0x5]="non-root"; [0xe]=", parent is designated" */
static u8 LOCAL__bss_MESH_ZERO_ADDR[0x4]; /* stand-in for .bss.MESH_ZERO_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_look_for_nwk_count_2[0x4]; /* stand-in for .bss.look_for_nwk_count$2 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_scan_times_3[0x4]; /* stand-in for .bss.scan_times$3 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_channel_enable_jp @ mesh_network.o 00000018 size 79B bind GLOBAL
 * Calls: esp_wifi_set_country | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: .rodata, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_channel_enable_jp.str1.1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=5); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_channel_enable_jp(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  a2 = (u32)(RODATA__rodata + 0x0);  /* 001b: -> "JP" */
  a10 = a1;  /* 001e */
  a8 = LD32(a2 + 0x0);  /* 0020 */
  a3 = LD32(a2 + 0x4);  /* 0022 */
  a2 = LD32(a2 + 0x8);  /* 0024 */
  ST32(a1 + 0x0, a8);  /* 0026 */
  ST32(a1 + 0x8, a2);  /* 0028 */
  ST32(a1 + 0x4, a3);  /* 002a */
  __asm__ volatile("" ::: "memory");  /* 002d: memw */
  a8 = (u32)&esp_wifi_set_country + 0x0;  /* 0030: l32r -> global */
  a2 = esp_wifi_set_country(a2, a3, a4, a5, a6, a7);  /* 0033: callx a8 via reloc-expand */
  a2 = a10;  /* 0036 */
  if (a10 == 0) goto L_0065;  /* 0038: beqz.n a10, 65 <esp_mesh_channel_enable_jp+0x4d> */
  L_003a: a3 = (u32)&g_log_level + 0x0;  /* 003a: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 003d */
  if (a3 < 3u) goto L_0065;  /* 003f: bltui a3, 3, 65 <esp_mesh_channel_enable_jp+0x4d> */
  L_0042: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0042: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0045 */
  if (a8 == 0) goto L_0065;  /* 0047: beqz.n a8, 65 <esp_mesh_channel_enable_jp+0x4d> */
  L_0049: a3 = LD32(a8 + 0x150);  /* 0049 */
  if (a3 == 0) goto L_0065;  /* 004c: beqz.n a3, 65 <esp_mesh_channel_enable_jp+0x4d> */
  L_004e: a10 = LD32(a8 + 0x158);  /* 004e */
  /* 0051: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0054 */
  a15 = a2;  /* 0056 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0058: -> "mesh" */
  a10 = 3;  /* 005b */
  a14 = a11;  /* 005d */
  a12 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 005f: -> "mesh" */
  /* 0062: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0065: return a2;  /* 0065: retw.n */
}


/* esp_mesh_scan_done_get_channel @ mesh_network.o 000000bc size 1746B bind GLOBAL
 * Calls: strnlen, mesh_malloc, esp_mesh_flush_scan_result, esp_wifi_scan_get_cur_ap_info, memset, esp_wifi_scan_get_cur_ap_record, memcmp, esp_mesh_is_same_router, esp_mesh_is_root_conflicts_allowed, esp_wifi_vnd_mesh_set, mesh_free | indirect[20]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x158]; mem[a5+0xb8] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_channel_enable_jp.str1.1, .rodata.esp_mesh_scan_done_get_channel.str1.1, g_mesh_topology, g_mesh_ext_cfg, .rodata.__func__$4, .bss.scan_times$3, g_mesh_ie, g_mesh_rt_capacity
 * Fidelity: medium - 20 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=11, refs=21); reloc-direct=11, funcdb-attributed=0, unknown-indirect=20 */
u32 esp_mesh_scan_done_get_channel(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 00bc: entry a1, 0x140 (frame 0x140 bytes) */
  a5 = (a5 >> 8) & 0x1;  /* 00bf: extui width 1 */
  ST32(a1 + 0x108, a2);  /* 00c2 */
  ST32(a1 + 0xd8, a3);  /* 00c5 */
  ST32(a1 + 0xf8, a4);  /* 00c8 */
  ST32(a1 + 0x10c, a5);  /* 00cb */
  if (a3 != 0) goto L_0100;  /* 00ce: bnez.n a3, 100 <esp_mesh_scan_done_get_channel+0x44> */
  L_00d0: a2 = (u32)&g_log_level + 0x0;  /* 00d0: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00d3 */
  a2 = 0x00004008u;  /* 00d5: l32r = 16392 */
  if (a3 >= 3u) goto L_00de;  /* 00d8: bgeui a3, 3, de <esp_mesh_scan_done_get_channel+0x22> */
  L_00db: goto L_0789;  /* 00db: j */
  L_00de: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00de: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00e1 */
  if (a3 == 0) goto L_0789;  /* 00e3: beqz a3, 789 <esp_mesh_scan_done_get_channel+0x6cd> */
  L_00e6: a4 = LD32(a3 + 0x150);  /* 00e6 */
  if (a4 == 0) goto L_0789;  /* 00e9: beqz a4, 789 <esp_mesh_scan_done_get_channel+0x6cd> */
  L_00ec: a10 = LD32(a3 + 0x158);  /* 00ec */
  a3 = 64;  /* 00ef */
  __asm__ volatile("" ::: "memory");  /* 00f2: memw */
  /* 00f5: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 00f8: -> "mesh" */
  goto L_012c;  /* 00fb: j */
  L_0100: a2 = LD32(a1 + 0xf8);  /* 0100 */
  if (a2 != 0) goto L_0144;  /* 0103: bnez.n a2, 144 <esp_mesh_scan_done_get_channel+0x88> */
  L_0105: a2 = (u32)&g_log_level + 0x0;  /* 0105: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0108 */
  a2 = 0x00004008u;  /* 010a: l32r = 16392 */
  if (a3 >= 3u) goto L_0113;  /* 010d: bgeui a3, 3, 113 <esp_mesh_scan_done_get_channel+0x57> */
  L_0110: goto L_0789;  /* 0110: j */
  L_0113: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0113: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0116 */
  if (a3 == 0) goto L_0789;  /* 0118: beqz a3, 789 <esp_mesh_scan_done_get_channel+0x6cd> */
  L_011b: a4 = LD32(a3 + 0x150);  /* 011b */
  if (a4 == 0) goto L_0789;  /* 011e: beqz a4, 789 <esp_mesh_scan_done_get_channel+0x6cd> */
  L_0121: a10 = LD32(a3 + 0x158);  /* 0121 */
  a3 = 65;  /* 0124 */
  /* 0126: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0129: -> "mesh" */
  L_012c: a13 = a10;  /* 012c */
  a14 = a11;  /* 012e */
  a10 = 3;  /* 0130 */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0132: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0135: -> "encrypted" */
  ST32(a1 + 0x0, a3);  /* 0138 */
  __asm__ volatile("" ::: "memory");  /* 013a: memw */
  /* 013d: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0789;  /* 0140: j */
  L_0144: a2 = (u32)&g_mesh_topology + 0x0;  /* 0144: l32r -> global */
  a3 = 1;  /* 0147 */
  a4 = 8;  /* 0149 */
  a5 = 0;  /* 014b */
  a11 = 64;  /* 014d */
  a7 = LD32(a2 + 0x0);  /* 014f */
  a2 = 16;  /* 0151 */
  if (a7 == 0) a2 = a3;  /* 0153 */
  a4 = a2 | a4;  /* 0156 */
  a2 = a5;  /* 0159 */
  a10 = (u32)&g_mesh_ext_cfg + 0x33;  /* 015b: l32r -> global */
  ST32(a1 + 0xf4, a4);  /* 015e */
  a4 = 58;  /* 0161 */
  ST32(a1 + 0xac, a5);  /* 0163 */
  ST16(a1 + 0xb0, a5);  /* 0166 */
  __asm__ volatile("" ::: "memory");  /* 0169: memw */
  __asm__ volatile("" ::: "memory");  /* 016c: memw */
  a8 = (u32)&strnlen + 0x0;  /* 016f: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0172: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) a2 = a3;  /* 0175 */
  a2 = (a2 >> 8) & 0x1;  /* 0178: extui width 1 */
  a6 = a10;  /* 017b */
  ST32(a1 + 0x104, a2);  /* 017d */
  a2 = 62;  /* 0180 */
  if (a7 != 0) a4 = a2;  /* 0182 */
  a8 = a4 + (13);  /* 0185 */
  a12 = 85;  /* 0187 */
  a11 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 0189: l32r -> .rodata.__func__$4 */
  a10 = a8;  /* 018c */
  ST32(a1 + 0xd0, a8);  /* 018e */
  __asm__ volatile("" ::: "memory");  /* 0191: memw */
  a8 = (u32)&mesh_malloc + 0x0;  /* 0194: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0197: callx a8 via reloc-expand */
  a2 = a10;  /* 019a */
  if (a10 != a5) goto L_01e8;  /* 019c: bne a10, a5, 1e8 <esp_mesh_scan_done_get_channel+0x12c> */
  L_019f: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 019f: l32r -> global */
  a2 = LD32(a5 + 0x0);  /* 01a2 */
  if (a2 == 0) goto L_01dc;  /* 01a4: beqz.n a2, 1dc <esp_mesh_scan_done_get_channel+0x120> */
  L_01a6: a4 = LD32(a2 + 0x150);  /* 01a6 */
  if (a4 == 0) goto L_01dc;  /* 01a9: beqz a4, 1dc <esp_mesh_scan_done_get_channel+0x120> */
  L_01ac: a10 = LD32(a2 + 0x158);  /* 01ac */
  /* 01af: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 01b2 */
  a5 = LD32(a5 + 0x0);  /* 01b4 */
  a10 = LD32(a5 + 0xb8);  /* 01b6 */
  a5 = 87;  /* 01b9 */
  /* 01bb: INDIRECT callx a10 <- mem[a5+0xb8]; result unknown */ a2 = 0;
  a13 = a2;  /* 01be */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 01c0: -> "mesh" */
  a14 = a11;  /* 01c3 */
  a9 = LD32(a1 + 0xd0);  /* 01c5 */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 01c8: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 01cb: -> "encrypted" */
  ST32(a1 + 0x8, a10);  /* 01ce */
  a10 = a3;  /* 01d0 */
  ST32(a1 + 0x4, a9);  /* 01d2 */
  ST32(a1 + 0x0, a5);  /* 01d4 */
  __asm__ volatile("" ::: "memory");  /* 01d6: memw */
  /* 01d9: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_01dc: a8 = (u32)&esp_mesh_flush_scan_result + 0x0;  /* 01dc: l32r -> global */
  a2 = esp_mesh_flush_scan_result(a2, a3, a4, a5, a6, a7);  /* 01df: callx a8 via reloc-expand */
  a2 = 0;  /* 01e2 */
  goto L_0789;  /* 01e4: j */
  L_01e8: a7 = (u32)&LOCAL__bss_scan_times_3 + 0x0;  /* 01e8: l32r -> .bss.scan_times$3 (same-object static) */
  a4 = a10 + a4;  /* 01eb */
  a3 = LD32(a7 + 0x0);  /* 01ed */
  a3 = a3 + (1);  /* 01ef */
  ST32(a7 + 0x0, a3);  /* 01f1 */
  a7 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 01f3: -> "encrypted" */
  a3 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 01f6: -> "encrypted" */
  if (a6 != 0) a3 = a7;  /* 01f9 */
  a7 = a5;  /* 01fc */
  ST32(a1 + 0xe4, a5);  /* 01fe */
  ST32(a1 + 0xd4, a5);  /* 0201 */
  ST32(a1 + 0xec, a5);  /* 0204 */
  ST32(a1 + 0xc8, a5);  /* 0207 */
  ST32(a1 + 0xe8, a5);  /* 020a */
  ST32(a1 + 0xcc, a5);  /* 020d */
  ST32(a1 + 0xdc, a5);  /* 0210 */
  ST32(a1 + 0xe0, a5);  /* 0213 */
  ST32(a1 + 0xc0, a5);  /* 0216 */
  ST32(a1 + 0xc4, a5);  /* 0219 */
  a5 = a1 + (64);  /* 021c */
  a5 = a5 + (116);  /* 021f */
  ST32(a1 + 0x100, a3);  /* 0222 */
  a3 = 136;  /* 0225 */
  ST32(a1 + 0xf0, a3);  /* 0228 */
  ST32(a1 + 0x110, a5);  /* 022b */
  ST32(a1 + 0x114, a4);  /* 022e */
  L_0231: a6 = 0;  /* 0231 */
  a11 = LD32(a1 + 0x110);  /* 0233 */
  a10 = LD32(a1 + 0xf4);  /* 0236 */
  ST32(a1 + 0xb4, a6);  /* 0239 */
  __asm__ volatile("" ::: "memory");  /* 023c: memw */
  a8 = (u32)&esp_wifi_scan_get_cur_ap_info + 0x0;  /* 023f: l32r -> global */
  a2 = esp_wifi_scan_get_cur_ap_info(a2, a3, a4, a5, a6, a7);  /* 0242: callx a8 via reloc-expand */
  if (a10 == a6) goto L_024b;  /* 0245: beq a10, a6, 24b <esp_mesh_scan_done_get_channel+0x18f> */
  L_0248: goto L_05dc;  /* 0248: j */
  L_024b: a12 = 108;  /* 024b */
  a11 = a6;  /* 024e */
  a10 = a1 + (64);  /* 0250 */
  a8 = (u32)&memset + 0x0;  /* 0253: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0256: callx a8 (libc, via reloc-expand) */
  a3 = LD32(a1 + 0xb4);  /* 0259 */
  if ((i32)a3 < 1) goto L_027c;  /* 025c: blti a3, 1, 27c <esp_mesh_scan_done_get_channel+0x1c0> */
  L_025f: a11 = a6;  /* 025f */
  a10 = a2;  /* 0261: mov */
  a12 = LD32(a1 + 0xd0);  /* 0264 */
  a8 = (u32)&memset + 0x0;  /* 0267: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 026a: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0xd0);  /* 026d */
  a3 = LD32(a1 + 0xb4);  /* 0270 */
  if (a3 != a8) goto L_027c;  /* 0273: bne a3, a8, 27c <esp_mesh_scan_done_get_channel+0x1c0> */
  L_0276: a9 = LD32(a1 + 0x114);  /* 0276 */
  ST32(a1 + 0xa0, a9);  /* 0279 */
  L_027c: a12 = a2;  /* 027c */
  a11 = a1 + (64);  /* 027e */
  a10 = LD32(a1 + 0xf4);  /* 0281 */
  __asm__ volatile("" ::: "memory");  /* 0284: memw */
  a8 = (u32)&esp_wifi_scan_get_cur_ap_record + 0x0;  /* 0287: l32r -> global */
  a2 = esp_wifi_scan_get_cur_ap_record(a2, a3, a4, a5, a6, a7);  /* 028a: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02bc;  /* 028d: beqz.n a10, 2bc <esp_mesh_scan_done_get_channel+0x200> */
  L_028f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 028f: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0292 */
  if (a3 == 0) goto L_02bc;  /* 0294: beqz.n a3, 2bc <esp_mesh_scan_done_get_channel+0x200> */
  L_0296: a4 = LD32(a3 + 0x150);  /* 0296 */
  if (a4 == 0) goto L_02bc;  /* 0299: beqz a4, 2bc <esp_mesh_scan_done_get_channel+0x200> */
  L_029c: a10 = LD32(a3 + 0x158);  /* 029c */
  a3 = 115;  /* 029f */
  /* 02a2: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02a5 */
  a10 = 1;  /* 02a7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 02a9: -> "mesh" */
  a14 = a11;  /* 02ac */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 02ae: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 02b1: -> "encrypted" */
  ST32(a1 + 0x0, a3);  /* 02b4 */
  __asm__ volatile("" ::: "memory");  /* 02b6: memw */
  /* 02b9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_02bc: a3 = LD32(a1 + 0xc8);  /* 02bc */
  a3 = a3 + (1);  /* 02bf */
  ST32(a1 + 0xc8, a3);  /* 02c1 */
  a3 = LD32(a1 + 0xb4);  /* 02c4 */
  if (a3 == 0) goto L_0421;  /* 02c7: beqz a3, 421 <esp_mesh_scan_done_get_channel+0x365> */
  L_02ca: a12 = 6;  /* 02ca */
  a10 = a2 + (8);  /* 02cc */
  a11 = (u32)&g_mesh_ie + 0x8;  /* 02ce: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 02d1: memw */
  a8 = (u32)&memcmp + 0x0;  /* 02d4: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 02d7: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_02ec;  /* 02da: beqz.n a10, 2ec <esp_mesh_scan_done_get_channel+0x230> */
  L_02dc: a4 = LD32(a1 + 0xec);  /* 02dc */
  a4 = a4 + (1);  /* 02df */
  ST32(a1 + 0xec, a4);  /* 02e1 */
  __asm__ volatile("" ::: "memory");  /* 02e4: memw */
  goto L_0231;  /* 02e7: j */
  L_02ec: a5 = LD32(a1 + 0xe8);  /* 02ec */
  a3 = a5 + (1);  /* 02ef */
  a3 = (a3 >> 16) & 0x1;  /* 02f1: extui width 1 */
  ST32(a1 + 0xe8, a3);  /* 02f4 */
  a3 = (u32)&g_mesh_rt_capacity + 0x0;  /* 02f7: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 02fa */
  a3 = LD8U(a2 + 0x15);  /* 02fc */
  a3 = a3 << 8;  /* 02ff */
  a5 = LD8U(a2 + 0x14);  /* 0302 */
  a3 = a3 | a5;  /* 0305 */
  a5 = LD8U(a2 + 0x7);  /* 0308 */
  if (a5 == 1) goto L_0311;  /* 030b: beqi a5, 1, 311 <esp_mesh_scan_done_get_channel+0x255> */
  L_030e: goto L_03d4;  /* 030e: j */
  L_0311: a6 = LD32(a1 + 0xd4);  /* 0311 */
  a6 = a6 + (1);  /* 0314 */
  a5 = (u32)&g_log_level + 0x0;  /* 0316: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 0319 */
  ST32(a1 + 0xd4, a6);  /* 031b */
  if (a5 < 3u) goto L_0365;  /* 031e: bltui a5, 3, 365 <esp_mesh_scan_done_get_channel+0x2a9> */
  L_0321: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0321: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 0324 */
  if (a6 == 0) goto L_0365;  /* 0326: beqz.n a6, 365 <esp_mesh_scan_done_get_channel+0x2a9> */
  L_0328: a5 = LD32(a6 + 0x150);  /* 0328 */
  if (a5 == 0) goto L_0365;  /* 032b: beqz.n a5, 365 <esp_mesh_scan_done_get_channel+0x2a9> */
  L_032d: a10 = LD32(a6 + 0x158);  /* 032d */
  __asm__ volatile("" ::: "memory");  /* 0330: memw */
  /* 0333: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0336 */
  a15 = a1 + (70);  /* 0338 */
  a8 = LD32(a1 + 0xc0);  /* 033b */
  a10 = 3;  /* 033e */
  a6 = LD8U(a1 + 0x67);  /* 0340 */
  ST32(a1 + 0xc, a8);  /* 0343 */
  ST32(a1 + 0x8, a6);  /* 0345 */
  ST32(a1 + 0x4, a4);  /* 0347 */
  a6 = LD8U(a2 + 0x15);  /* 0349 */
  a6 = a6 << 8;  /* 034c */
  a8 = LD8U(a2 + 0x14);  /* 034f */
  a6 = a6 | a8;  /* 0352 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0355: -> "mesh" */
  a14 = a11;  /* 0358 */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 035a: -> "encrypted" */
  ST32(a1 + 0x0, a6);  /* 035d */
  __asm__ volatile("" ::: "memory");  /* 035f: memw */
  /* 0362: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_0365: a5 = LD8U(a2 + 0x15);  /* 0365 */
  a5 = a5 << 8;  /* 0368 */
  a6 = LD8U(a2 + 0x14);  /* 036b */
  a5 = a5 | a6;  /* 036e */
  a9 = LD32(a1 + 0xdc);  /* 0371 */
  if (a9 == 0) goto L_0379;  /* 0374: beqz.n a9, 379 <esp_mesh_scan_done_get_channel+0x2bd> */
  L_0376: if ((i32)a5 >= (i32)a9) goto L_0382;  /* 0376: bge a5, a9, 382 <esp_mesh_scan_done_get_channel+0x2c6> */
  L_0379: if ((i32)a3 >= (i32)a4) goto L_0382;  /* 0379: bge a3, a4, 382 <esp_mesh_scan_done_get_channel+0x2c6> */
  L_037c: a3 = LD8U(a1 + 0x67);  /* 037c */
  ST32(a1 + 0xc0, a3);  /* 037f */
  L_0382: a3 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0382: l32r -> global */
  a3 = LD8U(a3 + 0xc4);  /* 0385 */
  ST32(a1 + 0xdc, a5);  /* 0388 */
  if (((a3 >> 1) & 1) == 0) goto L_0391;  /* 038b: bbci a3, 1, 391 <esp_mesh_scan_done_get_channel+0x2d5> */
  L_038e: goto L_0231;  /* 038e: j */
  L_0391: a10 = LD32(a1 + 0xa0);  /* 0391 */
  __asm__ volatile("" ::: "memory");  /* 0394: memw */
  a8 = (u32)&esp_mesh_is_same_router + 0x0;  /* 0397: l32r -> global */
  a2 = esp_mesh_is_same_router(a2, a3, a4, a5, a6, a7);  /* 039a: callx a8 via reloc-expand */
  if (a10 == 1) goto L_03a3;  /* 039d: beqi a10, 1, 3a3 <esp_mesh_scan_done_get_channel+0x2e7> */
  L_03a0: goto L_0231;  /* 03a0: j */
  L_03a3: a8 = (u32)&esp_mesh_is_root_conflicts_allowed + 0x0;  /* 03a3: l32r -> global */
  a2 = esp_mesh_is_root_conflicts_allowed(a2, a3, a4, a5, a6, a7);  /* 03a6: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0231;  /* 03a9: bnez a10, 231 <esp_mesh_scan_done_get_channel+0x175> */
  L_03ac: a4 = LD32(a1 + 0xd4);  /* 03ac */
  if (a4 != 1) goto L_03b5;  /* 03af: bnei a4, 1, 3b5 <esp_mesh_scan_done_get_channel+0x2f9> */
  L_03b2: goto L_0231;  /* 03b2: j */
  L_03b5: a4 = 32;  /* 03b5 */
  a11 = 0;  /* 03b7 */
  a10 = (u32)&g_mesh_ie + 0x0;  /* 03b9: l32r -> global */
  a3 = LD8U(a10 + 0x1e);  /* 03bc */
  a3 = a3 | a4;  /* 03bf */
  ST8(a10 + 0x1e, a3);  /* 03c2 */
  __asm__ volatile("" ::: "memory");  /* 03c5: memw */
  __asm__ volatile("" ::: "memory");  /* 03c8: memw */
  a8 = (u32)&esp_wifi_vnd_mesh_set + 0x0;  /* 03cb: l32r -> global */
  a2 = esp_wifi_vnd_mesh_set(a2, a3, a4, a5, a6, a7);  /* 03ce: callx a8 via reloc-expand */
  goto L_0231;  /* 03d1: j */
  L_03d4: if (a5 != 0) goto L_03e4;  /* 03d4: bnez.n a5, 3e4 <esp_mesh_scan_done_get_channel+0x328> */
  L_03d6: a5 = LD32(a1 + 0xe4);  /* 03d6 */
  a5 = a5 + (1);  /* 03d9 */
  ST32(a1 + 0xe4, a5);  /* 03db */
  __asm__ volatile("" ::: "memory");  /* 03de: memw */
  goto L_0231;  /* 03e1: j */
  L_03e4: if (a5 != 3) goto L_03ea;  /* 03e4: bnei a5, 3, 3ea <esp_mesh_scan_done_get_channel+0x32e> */
  L_03e7: goto L_0231;  /* 03e7: j */
  L_03ea: a5 = LD8U(a2 + 0x1e);  /* 03ea */
  a6 = 8;  /* 03ed */
  a5 = a5 & a6;  /* 03ef */
  if (a5 != 0) goto L_0231;  /* 03f2: bnez a5, 231 <esp_mesh_scan_done_get_channel+0x175> */
  L_03f5: a6 = 1;  /* 03f5 */
  a8 = LD32(a1 + 0xcc);  /* 03f7 */
  a7 = a7 + (1);  /* 03fa */
  if (a8 == 0) a5 = a6;  /* 03fc */
  ST32(a1 + 0xcc, a3);  /* 03ff */
  if (a5 != 0) goto L_040d;  /* 0402: bnez.n a5, 40d <esp_mesh_scan_done_get_channel+0x351> */
  L_0404: if ((i32)a3 < (i32)a8) goto L_040d;  /* 0404: blt a3, a8, 40d <esp_mesh_scan_done_get_channel+0x351> */
  L_0407: __asm__ volatile("" ::: "memory");  /* 0407: memw */
  goto L_0231;  /* 040a: j */
  L_040d: if ((i32)a3 < (i32)a4) goto L_0413;  /* 040d: blt a3, a4, 413 <esp_mesh_scan_done_get_channel+0x357> */
  L_0410: goto L_0231;  /* 0410: j */
  L_0413: a9 = LD8U(a1 + 0x67);  /* 0413 */
  ST32(a1 + 0xe0, a9);  /* 0416 */
  __asm__ volatile("" ::: "memory");  /* 0419: memw */
  goto L_0231;  /* 041c: j */
  L_0421: a3 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0421: l32r -> global */
  a3 = LD8U(a3 + 0xc4);  /* 0424 */
  if (((a3 >> 1) & 1) == 0) goto L_042d;  /* 0427: bbci a3, 1, 42d <esp_mesh_scan_done_get_channel+0x371> */
  L_042a: goto L_0231;  /* 042a: j */
  L_042d: a3 = a1 + (70);  /* 042d */
  a12 = 32;  /* 0430 */
  a10 = (u32)&g_mesh_ext_cfg + 0xc;  /* 0432: l32r -> global */
  a11 = a3;  /* 0435 */
  a8 = (u32)&memcmp + 0x0;  /* 0437: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 043a: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0231;  /* 043d: bnez a10, 231 <esp_mesh_scan_done_get_channel+0x175> */
  L_0440: a4 = (u32)&g_log_level + 0x0;  /* 0440: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0443 */
  if (a4 < 3u) goto L_04a4;  /* 0445: bltui a4, 3, 4a4 <esp_mesh_scan_done_get_channel+0x3e8> */
  L_0448: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0448: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 044b */
  if (a4 == 0) goto L_04a4;  /* 044e: beqz a4, 4a4 <esp_mesh_scan_done_get_channel+0x3e8> */
  L_0451: a5 = LD32(a4 + 0x150);  /* 0451 */
  if (a5 == 0) goto L_04a4;  /* 0454: beqz a5, 4a4 <esp_mesh_scan_done_get_channel+0x3e8> */
  L_0457: a10 = LD32(a4 + 0x158);  /* 0457 */
  /* 045a: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 045d */
  a10 = 3;  /* 045f */
  a4 = LD8U(a1 + 0x6c);  /* 0461 */
  a4 = (i32)(a4 << (32 - 7)) >> (32 - 7);  /* 0464: sext */
  ST32(a1 + 0x24, a4);  /* 0467 */
  a4 = LD8U(a1 + 0x67);  /* 0469 */
  ST32(a1 + 0x20, a4);  /* 046c */
  a4 = LD8U(a1 + 0x45);  /* 046e */
  ST32(a1 + 0x1c, a4);  /* 0471 */
  a4 = LD8U(a1 + 0x44);  /* 0473 */
  ST32(a1 + 0x18, a4);  /* 0476 */
  a4 = LD8U(a1 + 0x43);  /* 0478 */
  ST32(a1 + 0x14, a4);  /* 047b */
  a4 = LD8U(a1 + 0x42);  /* 047d */
  ST32(a1 + 0x10, a4);  /* 0480 */
  a4 = LD8U(a1 + 0x41);  /* 0482 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0485: -> "mesh" */
  a14 = a11;  /* 0488 */
  ST32(a1 + 0xc, a4);  /* 048a */
  ST32(a1 + 0x4, a3);  /* 048c */
  a4 = LD8U(a1 + 0x40);  /* 048e */
  a3 = LD32(a1 + 0xc8);  /* 0491 */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0494: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0497: -> "encrypted" */
  ST32(a1 + 0x8, a4);  /* 049a */
  ST32(a1 + 0x0, a3);  /* 049c */
  __asm__ volatile("" ::: "memory");  /* 049e: memw */
  /* 04a1: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_04a4: a3 = (u32)&g_mesh_ext_cfg + 0x0;  /* 04a4: l32r -> global */
  a3 = LD8U(a3 + 0xc4);  /* 04a7 */
  if (((a3 >> 0) & 1) == 0) goto L_04b8;  /* 04aa: bbci a3, 0, 4b8 <esp_mesh_scan_done_get_channel+0x3fc> */
  L_04ad: a12 = 6;  /* 04ad */
  a10 = a1 + (64);  /* 04af */
  a11 = (u32)&g_mesh_ext_cfg + 0xbe;  /* 04b2: l32r -> global */
  goto L_04c0;  /* 04b5: j */
  L_04b8: a10 = (u32)&g_mesh_ext_cfg + 0xc;  /* 04b8: l32r -> global */
  a12 = 32;  /* 04bb */
  a11 = a1 + (70);  /* 04bd */
  L_04c0: a8 = (u32)&memcmp + 0x0;  /* 04c0: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 04c3: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0231;  /* 04c6: bnez a10, 231 <esp_mesh_scan_done_get_channel+0x175> */
  L_04c9: a3 = (u32)&g_log_level + 0x0;  /* 04c9: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 04cc */
  if (a3 < 3u) goto L_0545;  /* 04ce: bltui a3, 3, 545 <esp_mesh_scan_done_get_channel+0x489> */
  L_04d1: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 04d1: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 04d4 */
  if (a4 == 0) goto L_0545;  /* 04d6: beqz a4, 545 <esp_mesh_scan_done_get_channel+0x489> */
  L_04d9: a3 = LD32(a4 + 0x150);  /* 04d9 */
  if (a3 == 0) goto L_0545;  /* 04dc: beqz a3, 545 <esp_mesh_scan_done_get_channel+0x489> */
  L_04df: a10 = LD32(a4 + 0x158);  /* 04df */
  /* 04e2: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a9 = LD8U(a1 + 0x43);  /* 04e5 */
  a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 04e8: l32r -> global */
  a8 = LD8U(a1 + 0x6c);  /* 04eb */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 04ee: sext */
  a11 = LD32(a1 + 0x70);  /* 04f1 */
  ST32(a1 + 0xfc, a9);  /* 04f4 */
  a15 = LD8U(a4 + 0x2c);  /* 04f7 */
  a5 = LD8U(a1 + 0x41);  /* 04fa */
  a4 = LD8U(a1 + 0x40);  /* 04fd */
  a6 = LD8U(a1 + 0x42);  /* 0500 */
  a12 = LD8U(a1 + 0x44);  /* 0503 */
  a13 = LD8U(a1 + 0x45);  /* 0506 */
  a9 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0509: -> "encrypted" */
  if (a11 != 0) goto L_0511;  /* 050c: bnez.n a11, 511 <esp_mesh_scan_done_get_channel+0x455> */
  L_050e: a9 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 050e: -> "encrypted" */
  L_0511: a14 = LD32(a1 + 0xc4);  /* 0511 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0514: -> "mesh" */
  ST32(a1 + 0x28, a14);  /* 0517 */
  ST32(a1 + 0x20, a9);  /* 0519 */
  a14 = LD8U(a1 + 0x67);  /* 051b */
  a9 = LD32(a1 + 0xfc);  /* 051e */
  ST32(a1 + 0x8, a4);  /* 0521 */
  a4 = (u32)&g_mesh_ext_cfg + 0xc;  /* 0523: l32r -> global */
  ST32(a1 + 0x18, a12);  /* 0526 */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0528: -> "encrypted" */
  ST32(a1 + 0x24, a14);  /* 052b */
  a14 = a11;  /* 052d */
  ST32(a1 + 0x1c, a13);  /* 052f */
  a13 = a10;  /* 0531 */
  a10 = 3;  /* 0533 */
  ST32(a1 + 0x14, a9);  /* 0535 */
  ST32(a1 + 0x10, a6);  /* 0537 */
  ST32(a1 + 0xc, a5);  /* 0539 */
  ST32(a1 + 0x4, a8);  /* 053b */
  ST32(a1 + 0x0, a4);  /* 053d */
  __asm__ volatile("" ::: "memory");  /* 053f: memw */
  /* 0542: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  L_0545: a3 = 1;  /* 0545 */
  a11 = 0;  /* 0547 */
  a4 = LD32(a1 + 0x70);  /* 0549 */
  if (a4 == 0) a3 = a11;  /* 054c */
  a4 = LD32(a1 + 0x104);  /* 054f */
  if (a3 == a4) goto L_05ab;  /* 0552: beq a3, a4, 5ab <esp_mesh_scan_done_get_channel+0x4ef> */
  L_0555: a3 = (u32)&g_log_level + 0x0;  /* 0555: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0558 */
  if (a3 >= 3u) goto L_0560;  /* 055a: bgeui a3, 3, 560 <esp_mesh_scan_done_get_channel+0x4a4> */
  L_055d: goto L_0231;  /* 055d: j */
  L_0560: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0560: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0563 */
  if (a3 != a11) goto L_056b;  /* 0565: bne a3, a11, 56b <esp_mesh_scan_done_get_channel+0x4af> */
  L_0568: goto L_0231;  /* 0568: j */
  L_056b: a4 = LD32(a3 + 0x150);  /* 056b */
  if (a4 != a11) goto L_0574;  /* 056e: bne a4, a11, 574 <esp_mesh_scan_done_get_channel+0x4b8> */
  L_0571: goto L_0231;  /* 0571: j */
  L_0574: a10 = LD32(a3 + 0x158);  /* 0574 */
  /* 0577: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 057a */
  a10 = 3;  /* 057c */
  a3 = LD32(a1 + 0x70);  /* 057e */
  ST32(a1 + 0xc, a3);  /* 0581 */
  a3 = LD8U(a1 + 0x67);  /* 0583 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0586: -> "mesh" */
  a14 = a11;  /* 0589 */
  a5 = LD32(a1 + 0x100);  /* 058b */
  a6 = LD32(a1 + 0xc8);  /* 058e */
  ST32(a1 + 0x8, a3);  /* 0591 */
  a3 = a1 + (70);  /* 0593 */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0596: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0599: -> "encrypted" */
  ST32(a1 + 0x10, a5);  /* 059c */
  ST32(a1 + 0x4, a3);  /* 059e */
  ST32(a1 + 0x0, a6);  /* 05a0 */
  __asm__ volatile("" ::: "memory");  /* 05a2: memw */
  /* 05a5: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  goto L_0231;  /* 05a8: j */
  L_05ab: a3 = LD8U(a1 + 0x6c);  /* 05ab */
  a4 = (i32)(a3 << (32 - 7)) >> (32 - 7);  /* 05ae: sext */
  a8 = LD32(a1 + 0xf0);  /* 05b1 */
  a5 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 05b4: sext */
  if ((i32)a5 < (i32)a4) goto L_05bd;  /* 05b7: blt a5, a4, 5bd <esp_mesh_scan_done_get_channel+0x501> */
  L_05ba: goto L_0231;  /* 05ba: j */
  L_05bd: a4 = LD32(a1 + 0x40);  /* 05bd */
  a9 = LD8U(a1 + 0x67);  /* 05c0 */
  ST32(a1 + 0xac, a4);  /* 05c3 */
  a4 = LD16U(a1 + 0x44);  /* 05c6 */
  ST32(a1 + 0xc4, a9);  /* 05c9 */
  ST16(a1 + 0xb0, a4);  /* 05cc */
  __asm__ volatile("" ::: "memory");  /* 05cf: memw */
  ST32(a1 + 0xf0, a3);  /* 05d2 */
  __asm__ volatile("" ::: "memory");  /* 05d5: memw */
  goto L_0231;  /* 05d8: j */
  L_05dc: a11 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 05dc: l32r -> .rodata.__func__$4 */
  a10 = a2;  /* 05df */
  a12 = 231;  /* 05e1 */
  a8 = (u32)&mesh_free + 0x0;  /* 05e4: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 05e7: callx a8 via reloc-expand */
  a2 = LD32(a1 + 0xc4);  /* 05ea */
  if (a2 == 0) goto L_062c;  /* 05ed: beqz.n a2, 62c <esp_mesh_scan_done_get_channel+0x570> */
  L_05ef: a4 = 1;  /* 05ef */
  a3 = LD32(a1 + 0xf8);  /* 05f1 */
  a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 05f4: l32r -> global */
  ST8(a3 + 0x0, a4);  /* 05f7 */
  __asm__ volatile("" ::: "memory");  /* 05fa: memw */
  a3 = LD8U(a2 + 0xc4);  /* 05fd */
  if (((a3 >> 0) & 1) != 0) goto L_062c;  /* 0600: bbsi a3, 0, 62c <esp_mesh_scan_done_get_channel+0x570> */
  L_0603: a3 = a3 | a4;  /* 0603 */
  a4 = a1 + (64);  /* 0606 */
  ST8(a2 + 0xc4, a3);  /* 0609 */
  __asm__ volatile("" ::: "memory");  /* 060c: memw */
  a3 = 190;  /* 060f */
  a2 = a2 + a3;  /* 0612 */
  a3 = a4 + (108);  /* 0614 */
  a5 = LD16U(a1 + 0xac);  /* 0617 */
  a4 = LD16U(a1 + 0xae);  /* 061a */
  a3 = LD16U(a3 + 0x4);  /* 061d */
  ST16(a2 + 0x0, a5);  /* 0620 */
  ST16(a2 + 0x2, a4);  /* 0623 */
  ST16(a2 + 0x4, a3);  /* 0626 */
  __asm__ volatile("" ::: "memory");  /* 0629: memw */
  L_062c: a5 = LD32(a1 + 0xc0);  /* 062c */
  if (a5 != 0) goto L_063d;  /* 062f: bnez.n a5, 63d <esp_mesh_scan_done_get_channel+0x581> */
  L_0631: a6 = LD32(a1 + 0xc4);  /* 0631 */
  a8 = LD32(a1 + 0xe0);  /* 0634 */
  if (a8 != 0) a6 = a8;  /* 0637 */
  ST32(a1 + 0xc0, a6);  /* 063a */
  L_063d: a2 = LD32(a1 + 0xc0);  /* 063d */
  a9 = LD32(a1 + 0xd8);  /* 0640 */
  ST8(a9 + 0x0, a2);  /* 0643 */
  __asm__ volatile("" ::: "memory");  /* 0646: memw */
  a2 = (u32)&g_log_level + 0x0;  /* 0649: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 064c */
  if (a2 >= 3u) goto L_0654;  /* 064e: bgeui a2, 3, 654 <esp_mesh_scan_done_get_channel+0x598> */
  L_0651: goto L_0779;  /* 0651: j */
  L_0654: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0654: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0657 */
  if (a3 != 0) goto L_066c;  /* 0659: bnez a3, 66c <esp_mesh_scan_done_get_channel+0x5b0> */
  L_065c: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 065c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 065f */
  if (a2 != 0) goto L_0719;  /* 0661: bnez a2, 719 <esp_mesh_scan_done_get_channel+0x65d> */
  L_0664: __asm__ volatile("" ::: "memory");  /* 0664: memw */
  goto L_0779;  /* 0667: j */
  L_066c: a2 = LD32(a3 + 0x150);  /* 066c */
  if (a2 == 0) goto L_065c;  /* 066f: beqz a2, 65c <esp_mesh_scan_done_get_channel+0x5a0> */
  L_0672: a10 = LD32(a3 + 0x158);  /* 0672 */
  /* 0675: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0678: l32r -> global */
  a6 = LD32(a1 + 0x108);  /* 067b */
  a3 = LD8U(a8 + 0xbe);  /* 067e */
  a15 = LD8U(a6 + 0x1);  /* 0681 */
  a13 = LD8U(a8 + 0xbf);  /* 0684 */
  a4 = LD8U(a8 + 0xc0);  /* 0687 */
  a5 = LD8U(a8 + 0xc1);  /* 068a */
  a6 = LD8U(a8 + 0xc2);  /* 068d */
  a8 = LD8U(a8 + 0xc3);  /* 0690 */
  a9 = LD32(a1 + 0xc4);  /* 0693 */
  ST32(a1 + 0xc0, a8);  /* 0696 */
  a8 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0699: -> "encrypted" */
  if (a9 != 0) goto L_06a1;  /* 069c: bnez.n a9, 6a1 <esp_mesh_scan_done_get_channel+0x5e5> */
  L_069e: a8 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 069e: -> "encrypted" */
  L_06a1: a9 = (u32)&g_mesh_ie + 0x0;  /* 06a1: l32r -> global */
  a11 = LD8U(a9 + 0x1e);  /* 06a4 */
  a9 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 06a7: -> "encrypted" */
  if (((a11 >> 1) & 1) != 0) goto L_06b0;  /* 06aa: bbsi a11, 1, 6b0 <esp_mesh_scan_done_get_channel+0x5f4> */
  L_06ad: a9 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 06ad: -> "encrypted" */
  L_06b0: a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 06b0: -> "encrypted" */
  if (((a11 >> 6) & 1) != 0) goto L_06b9;  /* 06b3: bbsi a11, 6, 6b9 <esp_mesh_scan_done_get_channel+0x5fd> */
  L_06b6: a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 06b6: -> "encrypted" */
  L_06b9: a11 = LD32(a1 + 0x10c);  /* 06b9 */
  a14 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 06bc: -> "encrypted" */
  if (a11 != 0) goto L_06c4;  /* 06bf: bnez.n a11, 6c4 <esp_mesh_scan_done_get_channel+0x608> */
  L_06c1: a14 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 06c1: -> "encrypted" */
  L_06c4: a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 06c4: -> "mesh" */
  ST32(a1 + 0x3c, a14);  /* 06c7 */
  ST32(a1 + 0x30, a8);  /* 06c9 */
  a14 = LD32(a1 + 0xc0);  /* 06cb */
  a8 = LD32(a1 + 0xc8);  /* 06ce */
  ST32(a1 + 0x28, a6);  /* 06d1 */
  ST32(a1 + 0x24, a5);  /* 06d3 */
  a6 = LD32(a1 + 0xec);  /* 06d5 */
  a5 = LD32(a1 + 0xe8);  /* 06d8 */
  ST32(a1 + 0x20, a4);  /* 06db */
  ST32(a1 + 0x18, a3);  /* 06dd */
  a4 = LD32(a1 + 0xe4);  /* 06df */
  a3 = LD32(a1 + 0xd4);  /* 06e2 */
  ST32(a1 + 0x38, a12);  /* 06e5 */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 06e7: -> "encrypted" */
  ST32(a1 + 0x2c, a14);  /* 06ea */
  a14 = a11;  /* 06ec */
  ST32(a1 + 0x1c, a13);  /* 06ee */
  a13 = a10;  /* 06f0 */
  a10 = 3;  /* 06f2 */
  ST32(a1 + 0x34, a9);  /* 06f4 */
  ST32(a1 + 0x14, a3);  /* 06f6 */
  ST32(a1 + 0x10, a7);  /* 06f8 */
  ST32(a1 + 0xc, a4);  /* 06fa */
  ST32(a1 + 0x8, a5);  /* 06fc */
  ST32(a1 + 0x4, a6);  /* 06fe */
  ST32(a1 + 0x0, a8);  /* 0700 */
  __asm__ volatile("" ::: "memory");  /* 0702: memw */
  /* 0705: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  a2 = (u32)&g_log_level + 0x0;  /* 0708: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 070b */
  if (a2 < 3u) goto L_0713;  /* 070d: bltui a2, 3, 713 <esp_mesh_scan_done_get_channel+0x657> */
  L_0710: goto L_065c;  /* 0710: j */
  L_0713: goto L_0779;  /* 0713: j */
  L_0719: a3 = LD32(a2 + 0x150);  /* 0719 */
  if (a3 == 0) goto L_0779;  /* 071c: beqz a3, 779 <esp_mesh_scan_done_get_channel+0x6bd> */
  L_071f: a10 = LD32(a2 + 0x158);  /* 071f */
  /* 0722: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0xd8);  /* 0725 */
  a2 = (u32)&LOCAL__bss_scan_times_3 + 0x0;  /* 0728: l32r -> .bss.scan_times$3 (same-object static) */
  a5 = LD8U(a9 + 0x0);  /* 072b */
  a15 = LD32(a2 + 0x0);  /* 072e */
  a4 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0730: -> "encrypted" */
  if (a5 != 0) goto L_0738;  /* 0733: bnez.n a5, 738 <esp_mesh_scan_done_get_channel+0x67c> */
  L_0735: a4 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0735: -> "encrypted" */
  L_0738: a13 = a10;  /* 0738 */
  a10 = 3;  /* 073a */
  a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 073c: l32r -> global */
  a6 = LD8U(a2 + 0x32);  /* 073f */
  ST32(a1 + 0x24, a6);  /* 0742 */
  a6 = LD8U(a2 + 0x31);  /* 0744 */
  ST32(a1 + 0x20, a6);  /* 0747 */
  a6 = LD8U(a2 + 0x30);  /* 0749 */
  ST32(a1 + 0x1c, a6);  /* 074c */
  a6 = LD8U(a2 + 0x2f);  /* 074e */
  ST32(a1 + 0x18, a6);  /* 0751 */
  a6 = LD8U(a2 + 0x2e);  /* 0753 */
  ST32(a1 + 0x14, a6);  /* 0756 */
  a6 = LD8U(a2 + 0x2d);  /* 0758 */
  ST32(a1 + 0x10, a6);  /* 075b */
  a6 = (u32)&g_mesh_ext_cfg + 0xc;  /* 075d: l32r -> global */
  ST32(a1 + 0xc, a6);  /* 0760 */
  a2 = LD8U(a2 + 0x4);  /* 0762 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0765: -> "mesh" */
  a14 = a11;  /* 0768 */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 076a: -> "encrypted" */
  ST32(a1 + 0x8, a2);  /* 076d */
  ST32(a1 + 0x4, a5);  /* 076f */
  ST32(a1 + 0x0, a4);  /* 0771 */
  __asm__ volatile("" ::: "memory");  /* 0773: memw */
  /* 0776: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  L_0779: a2 = LD32(a1 + 0xd8);  /* 0779 */
  a3 = LD8U(a2 + 0x0);  /* 077c */
  a2 = 0;  /* 077f */
  if (a3 == a2) goto L_0789;  /* 0781: beq a3, a2, 789 <esp_mesh_scan_done_get_channel+0x6cd> */
  L_0784: a3 = (u32)&LOCAL__bss_scan_times_3 + 0x0;  /* 0784: l32r -> .bss.scan_times$3 (same-object static) */
  ST32(a3 + 0x0, a2);  /* 0787 */
  L_0789: __asm__ volatile("" ::: "memory");  /* 0789: memw */
  return a2;  /* 078c: retw.n */
}


/* mesh_nwk_process_allow_switch @ mesh_network.o 00000038 size 248B bind GLOBAL
 * Calls: memcmp, mesh_nwk_process_reselect, esp_wifi_set_mode | indirect[4]: mem[a8+0x158]; unknown; mem[a8+0x150] | Data refs: g_mesh_is_root, g_mesh_ext_cfg, .bss.MESH_ZERO_ADDR, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_channel_enable_jp.str1.1, .rodata.mesh_nwk_process_allow_switch.str1.1, g_is_standalone_sta
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=11); reloc-direct=3, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_nwk_process_allow_switch(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0038: entry a1, 64 (frame 64 bytes) */
  a3 = (u32)&g_mesh_is_root + 0x0;  /* 003b: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 003e: memw */
  a8 = LD8U(a3 + 0x0);  /* 0041 */
  a8 = (a8 >> 8) & 0x1;  /* 0044: extui width 1 */
  a3 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0047: l32r -> global */
  if (a8 == 0) goto L_00c4;  /* 004a: beqz a8, c4 <mesh_nwk_process_allow_switch+0x8c> */
  L_004d: a4 = LD8U(a3 + 0xc4);  /* 004d */
  if (((a4 >> 1) & 1) != 0) goto L_00c4;  /* 0050: bbsi a4, 1, c4 <mesh_nwk_process_allow_switch+0x8c> */
  L_0053: a4 = LD8U(a3 + 0x73);  /* 0053 */
  if (a4 != 0) goto L_006b;  /* 0056: bnez a4, 6b <mesh_nwk_process_allow_switch+0x33> */
  L_0059: a12 = 6;  /* 0059 */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 005c: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a10 = (u32)&g_mesh_ext_cfg + 0x2d;  /* 005f: l32r -> global */
  a8 = (u32)&memcmp + 0x0;  /* 0062: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0065: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00c4;  /* 0068: bnez a10, c4 <mesh_nwk_process_allow_switch+0x8c> */
  L_006b: a4 = (u32)&g_log_level + 0x0;  /* 006b: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 006e */
  if (a4 < 3u) goto L_00b8;  /* 0070: bltui a4, 3, b8 <mesh_nwk_process_allow_switch+0x80> */
  L_0073: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0073: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 0076 */
  if (a8 == 0) goto L_00b8;  /* 0078: beqz.n a8, b8 <mesh_nwk_process_allow_switch+0x80> */
  L_007a: a4 = LD32(a8 + 0x150);  /* 007a */
  if (a4 == 0) goto L_00b8;  /* 007d: beqz.n a4, b8 <mesh_nwk_process_allow_switch+0x80> */
  L_007f: a10 = LD32(a8 + 0x158);  /* 007f */
  /* 0082: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0085 */
  a10 = 3;  /* 0087 */
  a8 = (u32)&g_mesh_ext_cfg + 0xc;  /* 0089: l32r -> global */
  a15 = LD8U(a3 + 0x2d);  /* 008c */
  ST32(a1 + 0x14, a8);  /* 008f */
  a8 = LD8U(a3 + 0x32);  /* 0091 */
  ST32(a1 + 0x10, a8);  /* 0094 */
  a8 = LD8U(a3 + 0x31);  /* 0096 */
  ST32(a1 + 0xc, a8);  /* 0099 */
  a8 = LD8U(a3 + 0x30);  /* 009b */
  ST32(a1 + 0x8, a8);  /* 009e */
  a8 = LD8U(a3 + 0x2f);  /* 00a0 */
  ST32(a1 + 0x4, a8);  /* 00a3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 00a5: -> "mesh" */
  a14 = a11;  /* 00a8 */
  a8 = LD8U(a3 + 0x2e);  /* 00aa */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_allow_switch_str1_1 + 0x0);  /* 00ad: l32r -> .rodata.mesh_nwk_process_allow_switch.str1.1 */
  ST32(a1 + 0x0, a8);  /* 00b0 */
  __asm__ volatile("" ::: "memory");  /* 00b2: memw */
  /* 00b5: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_00b8: a12 = 0;  /* 00b8 */
  a11 = a12;  /* 00ba */
  a10 = 1;  /* 00bc */
  a8 = (u32)&mesh_nwk_process_reselect;  /* 00be: l32r -> func addr */
  a2 = mesh_nwk_process_reselect(a2, a3, a4, a5, a6, a7);  /* 00c1: callx a8 via reloc-expand */
  L_00c4: a4 = LD8U(a3 + 0x5);  /* 00c4 */
  if (a4 != 0) goto L_00ce;  /* 00c7: bnez.n a4, ce <mesh_nwk_process_allow_switch+0x96> */
  L_00c9: a8 = LD8U(a3 + 0x4);  /* 00c9 */
  if (a8 != 0) goto L_00fc;  /* 00cc: bnez.n a8, fc <mesh_nwk_process_allow_switch+0xc4> */
  L_00ce: a4 = (u32)&g_log_level + 0x0;  /* 00ce: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 00d1 */
  if (a4 < 3u) goto L_00fa;  /* 00d3: bltui a4, 3, fa <mesh_nwk_process_allow_switch+0xc2> */
  L_00d6: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00d6: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 00d9 */
  if (a8 == 0) goto L_00fa;  /* 00db: beqz.n a8, fa <mesh_nwk_process_allow_switch+0xc2> */
  L_00dd: a4 = LD32(a8 + 0x150);  /* 00dd */
  if (a4 == 0) goto L_00fa;  /* 00e0: beqz.n a4, fa <mesh_nwk_process_allow_switch+0xc2> */
  L_00e2: a10 = LD32(a8 + 0x158);  /* 00e2 */
  /* 00e5: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00e8 */
  a10 = 3;  /* 00ea */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 00ec: -> "mesh" */
  a14 = a11;  /* 00ef */
  a15 = LD8U(a3 + 0x4);  /* 00f1 */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_allow_switch_str1_1 + 0x0);  /* 00f4: l32r -> .rodata.mesh_nwk_process_allow_switch.str1.1 */
  /* 00f7: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_00fa: a8 = 0;  /* 00fa */
  L_00fc: a4 = 2;  /* 00fc */
  ST8(a2 + 0x5, a8);  /* 00fe */
  __asm__ volatile("" ::: "memory");  /* 0101: memw */
  a8 = LD8U(a3 + 0xc4);  /* 0104 */
  a3 = 3;  /* 0107 */
  a8 = (a8 >> 1) & 0x3;  /* 0109: extui width 2 */
  if (a8 != 0) a3 = a4;  /* 010c */
  ST8(a2 + 0x4, a3);  /* 010f */
  __asm__ volatile("" ::: "memory");  /* 0112: memw */
  a3 = 43;  /* 0115 */
  ST32(a2 + 0x0, a3);  /* 0117 */
  a2 = (u32)&g_is_standalone_sta + 0x0;  /* 0119: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 011c */
  if (a2 != 0) goto L_012c;  /* 011f: bnez.n a2, 12c <mesh_nwk_process_allow_switch+0xf4> */
  L_0121: a10 = 1;  /* 0121 */
  __asm__ volatile("" ::: "memory");  /* 0123: memw */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 0126: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 0129: callx a8 via reloc-expand */
  L_012c: a2 = 0;  /* 012c */
  return a2;  /* 012e: retw.n */
}


/* mesh_nwk_process_look_for_network @ mesh_network.o 00000084 size 732B bind GLOBAL
 * Calls: nwk_event_id2str, mesh_nwk_check_no_parent_found, memcmp, mesh_nwk_process_reselect, memset, memcpy, esp_mesh_send_event_internal, esp_wifi_set_mode, esp_wifi_set_non_mesh_connections, mesh_malloc, esp_wifi_get_config, esp_wifi_set_config, mesh_free, mesh_process_parent_organized | indirect[11]: mem[a8+0x158]; unknown; mem[a5+0x158]; mem[a5+0x150] | Data refs: .bss.look_for_nwk_count$2, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_channel_enable_jp.str1.1, .rodata.mesh_nwk_process_look_for_network.str1.1, g_mesh_ext_cfg, .bss.MESH_ZERO_ADDR, .rodata.esp_mesh_scan_done_get_channel.str1.1, g_mesh_is_root, g_is_standalone_sta, .rodata.__func__$1, .rodata.mesh_nwk_process_reselect.str1.1
 * Fidelity: medium - 11 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=14, refs=26); reloc-direct=14, funcdb-attributed=0, unknown-indirect=11 */
u32 mesh_nwk_process_look_for_network(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a6, a7, a8;
  /* 0084: entry a1, 96 (frame 96 bytes) */
  a11 = LD8U(a2 + 0x4);  /* 0087 */
  a6 = LD8U(a2 + 0x5);  /* 008a */
  if (a11 == 0) goto L_0216;  /* 008d: beqz a11, 216 <mesh_nwk_process_look_for_network+0x192> */
  L_0090: a7 = 0x12c;  /* 0090 */
  ST32(a3 + 0x8, a7);  /* 0093 */
  if (((a11 >> 0) & 1) == 0) goto L_00b0;  /* 0095: bbci a11, 0, b0 <mesh_nwk_process_look_for_network+0x2c> */
  L_0098: a7 = (u32)&LOCAL__bss_look_for_nwk_count_2 + 0x0;  /* 0098: l32r -> .bss.look_for_nwk_count$2 (same-object static) */
  a8 = LD32(a7 + 0x0);  /* 009b */
  a8 = a8 + (1);  /* 009d */
  ST32(a7 + 0x0, a8);  /* 009f */
  if (((a8 >> 0) & 1) != 0) goto L_00b0;  /* 00a1: bbsi a8, 0, b0 <mesh_nwk_process_look_for_network+0x2c> */
  L_00a4: a7 = 1;  /* 00a4 */
  ST8(a3 + 0x6, a7);  /* 00a7 */
  a7 = 120;  /* 00aa */
  ST32(a3 + 0x8, a7);  /* 00ad */
  L_00b0: ST8(a3 + 0x5, a6);  /* 00b0 */
  __asm__ volatile("" ::: "memory");  /* 00b3: memw */
  a6 = 43;  /* 00b6 */
  ST32(a3 + 0xc, a6);  /* 00b8 */
  a6 = 6;  /* 00ba */
  ST32(a3 + 0x0, a6);  /* 00bc */
  a6 = (u32)&g_log_level + 0x0;  /* 00be: l32r -> global */
  a7 = LD32(a6 + 0x0);  /* 00c1 */
  if (a7 < 3u) goto L_0112;  /* 00c4: bltui a7, 3, 112 <mesh_nwk_process_look_for_network+0x8e> */
  L_00c7: a7 = (u32)&g_osi_funcs_p + 0x0;  /* 00c7: l32r -> global */
  a8 = LD32(a7 + 0x0);  /* 00ca */
  if (a8 == 0) goto L_0112;  /* 00cd: beqz a8, 112 <mesh_nwk_process_look_for_network+0x8e> */
  L_00d0: a7 = LD32(a8 + 0x150);  /* 00d0 */
  if (a7 == 0) goto L_0112;  /* 00d3: beqz.n a7, 112 <mesh_nwk_process_look_for_network+0x8e> */
  L_00d5: a10 = LD32(a8 + 0x158);  /* 00d5 */
  __asm__ volatile("" ::: "memory");  /* 00d8: memw */
  /* 00db: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00de */
  a10 = LD32(a2 + 0x0);  /* 00e0 */
  ST32(a1 + 0x30, a13);  /* 00e2 */
  __asm__ volatile("" ::: "memory");  /* 00e4: memw */
  a8 = (u32)&nwk_event_id2str + 0x0;  /* 00e7: l32r -> global */
  a2 = nwk_event_id2str(a2, a3, a4, a5);  /* 00ea: callx a8 via reloc-expand */
  a15 = a10;  /* 00ed */
  a10 = 3;  /* 00ef */
  a8 = (u32)&LOCAL__bss_look_for_nwk_count_2 + 0x0;  /* 00f1: l32r -> .bss.look_for_nwk_count$2 (same-object static) */
  a8 = LD32(a8 + 0x0);  /* 00f4 */
  ST32(a1 + 0x8, a8);  /* 00f6 */
  a8 = LD8U(a3 + 0x6);  /* 00f8 */
  ST32(a1 + 0x4, a8);  /* 00fb */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 00fd: -> "mesh" */
  a14 = a11;  /* 0100 */
  a8 = LD8U(a2 + 0x4);  /* 0102 */
  a13 = LD32(a1 + 0x30);  /* 0105 */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_look_for_network_str1_1 + 0x0);  /* 0107: l32r -> .rodata.mesh_nwk_process_look_for_network.str1.1 */
  ST32(a1 + 0x0, a8);  /* 010a */
  __asm__ volatile("" ::: "memory");  /* 010c: memw */
  /* 010f: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_0112: a12 = a4;  /* 0112 */
  a11 = LD32(a5 + 0x0);  /* 0114 */
  a10 = LD32(a2 + 0x0);  /* 0117 */
  a8 = (u32)&mesh_nwk_check_no_parent_found + 0x0;  /* 011a: l32r -> global */
  a2 = mesh_nwk_check_no_parent_found(a2, a3, a4, a5);  /* 011d: callx a8 via reloc-expand */
  if (a10 != 0) goto L_020a;  /* 0120: bnez a10, 20a <mesh_nwk_process_look_for_network+0x186> */
  L_0123: a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0123: l32r -> global */
  ST32(a5 + 0x0, a10);  /* 0126 */
  a5 = LD8U(a4 + 0xc4);  /* 0128 */
  if (((a5 >> 1) & 1) == 0) goto L_0131;  /* 012b: bbci a5, 1, 131 <mesh_nwk_process_look_for_network+0xad> */
  L_012e: goto L_01b5;  /* 012e: j */
  L_0131: a5 = LD8U(a4 + 0x73);  /* 0131 */
  if (a5 != 0) goto L_014c;  /* 0134: bnez a5, 14c <mesh_nwk_process_look_for_network+0xc8> */
  L_0137: a12 = 6;  /* 0137 */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 013a: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a10 = (u32)&g_mesh_ext_cfg + 0x2d;  /* 013d: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0140: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0143: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 0146: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_01b5;  /* 0149: bnez a10, 1b5 <mesh_nwk_process_look_for_network+0x131> */
  L_014c: a5 = LD32(a6 + 0x0);  /* 014c */
  if (a5 < 3u) goto L_01a9;  /* 014e: bltui a5, 3, 1a9 <mesh_nwk_process_look_for_network+0x125> */
  L_0151: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0151: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 0154 */
  if (a5 == 0) goto L_01a9;  /* 0157: beqz a5, 1a9 <mesh_nwk_process_look_for_network+0x125> */
  L_015a: a7 = LD32(a5 + 0x150);  /* 015a */
  if (a7 == 0) goto L_01a9;  /* 015d: beqz a7, 1a9 <mesh_nwk_process_look_for_network+0x125> */
  L_0160: a10 = LD32(a5 + 0x158);  /* 0160 */
  /* 0163: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 0166 */
  a10 = LD32(a2 + 0x0);  /* 0168 */
  a8 = (u32)&nwk_event_id2str + 0x0;  /* 016b: l32r -> global */
  a2 = nwk_event_id2str(a2, a3, a4, a5);  /* 016e: callx a8 via reloc-expand */
  a15 = a10;  /* 0171 */
  a13 = a5;  /* 0173 */
  a8 = (u32)&g_mesh_ext_cfg + 0xc;  /* 0175: l32r -> global */
  a10 = 3;  /* 0178 */
  ST32(a1 + 0x18, a8);  /* 017a */
  a8 = LD8U(a4 + 0x32);  /* 017c */
  ST32(a1 + 0x14, a8);  /* 017f */
  a8 = LD8U(a4 + 0x31);  /* 0181 */
  ST32(a1 + 0x10, a8);  /* 0184 */
  a8 = LD8U(a4 + 0x30);  /* 0186 */
  ST32(a1 + 0xc, a8);  /* 0189 */
  a8 = LD8U(a4 + 0x2f);  /* 018b */
  ST32(a1 + 0x8, a8);  /* 018e */
  a8 = LD8U(a4 + 0x2e);  /* 0190 */
  ST32(a1 + 0x4, a8);  /* 0193 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0195: -> "mesh" */
  a14 = a11;  /* 0198 */
  a8 = LD8U(a4 + 0x2d);  /* 019a */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_look_for_network_str1_1 + 0x0);  /* 019d: l32r -> .rodata.mesh_nwk_process_look_for_network.str1.1 */
  ST32(a1 + 0x0, a8);  /* 01a0 */
  __asm__ volatile("" ::: "memory");  /* 01a3: memw */
  /* 01a6: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_01a9: a12 = 0;  /* 01a9 */
  a11 = a12;  /* 01ab */
  a10 = 1;  /* 01ad */
  a8 = (u32)&mesh_nwk_process_reselect;  /* 01af: l32r -> func addr */
  a2 = mesh_nwk_process_reselect(a2, a3, a4, a5);  /* 01b2: callx a8 via reloc-expand */
  L_01b5: a5 = LD8U(a4 + 0x5);  /* 01b5 */
  if (a5 != 0) goto L_01c1;  /* 01b8: bnez a5, 1c1 <mesh_nwk_process_look_for_network+0x13d> */
  L_01bb: a5 = LD8U(a4 + 0x4);  /* 01bb */
  if (a5 != 0) goto L_035c;  /* 01be: bnez a5, 35c <mesh_nwk_process_look_for_network+0x2d8> */
  L_01c1: a5 = LD32(a6 + 0x0);  /* 01c1 */
  if (a5 < 3u) goto L_01fc;  /* 01c3: bltui a5, 3, 1fc <mesh_nwk_process_look_for_network+0x178> */
  L_01c6: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 01c6: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 01c9 */
  if (a5 == 0) goto L_01fc;  /* 01cb: beqz.n a5, 1fc <mesh_nwk_process_look_for_network+0x178> */
  L_01cd: a6 = LD32(a5 + 0x150);  /* 01cd */
  if (a6 == 0) goto L_01fc;  /* 01d0: beqz.n a6, 1fc <mesh_nwk_process_look_for_network+0x178> */
  L_01d2: a10 = LD32(a5 + 0x158);  /* 01d2 */
  /* 01d5: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 01d8 */
  a10 = LD32(a2 + 0x0);  /* 01da */
  a8 = (u32)&nwk_event_id2str + 0x0;  /* 01dc: l32r -> global */
  a2 = nwk_event_id2str(a2, a3, a4, a5);  /* 01df: callx a8 via reloc-expand */
  a15 = a10;  /* 01e2 */
  a13 = a5;  /* 01e4 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 01e6: -> "mesh" */
  a10 = 3;  /* 01e9 */
  a14 = a11;  /* 01eb */
  a2 = LD8U(a4 + 0x4);  /* 01ed */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_look_for_network_str1_1 + 0x0);  /* 01f0: l32r -> .rodata.mesh_nwk_process_look_for_network.str1.1 */
  ST32(a1 + 0x0, a2);  /* 01f3 */
  __asm__ volatile("" ::: "memory");  /* 01f6: memw */
  /* 01f9: INDIRECT callx a6 <- mem[a5+0x150]; result unknown */ a2 = 0;
  L_01fc: a2 = 0;  /* 01fc */
  ST8(a3 + 0x5, a2);  /* 01fe */
  __asm__ volatile("" ::: "memory");  /* 0201: memw */
  __asm__ volatile("" ::: "memory");  /* 0204: memw */
  goto L_035c;  /* 0207: j */
  L_020a: a2 = LD32(a5 + 0x0);  /* 020a */
  a2 = a2 + (1);  /* 020c */
  ST32(a5 + 0x0, a2);  /* 020e */
  __asm__ volatile("" ::: "memory");  /* 0210: memw */
  goto L_035c;  /* 0213: j */
  L_0216: if (a6 != 0) goto L_024b;  /* 0216: bnez.n a6, 24b <mesh_nwk_process_look_for_network+0x1c7> */
  L_0218: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0218: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 021b */
  if (a2 == 0) goto L_035c;  /* 021e: beqz a2, 35c <mesh_nwk_process_look_for_network+0x2d8> */
  L_0221: a3 = LD32(a2 + 0x150);  /* 0221 */
  if (a3 == 0) goto L_035c;  /* 0224: beqz a3, 35c <mesh_nwk_process_look_for_network+0x2d8> */
  L_0227: a10 = LD32(a2 + 0x158);  /* 0227 */
  a2 = 0x145;  /* 022a */
  /* 022d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0230 */
  a10 = 1;  /* 0232 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0234: -> "mesh" */
  a14 = a11;  /* 0237 */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0239: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 023c: -> "encrypted" */
  ST32(a1 + 0x0, a2);  /* 023f */
  __asm__ volatile("" ::: "memory");  /* 0242: memw */
  /* 0245: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_035c;  /* 0248: j */
  L_024b: a4 = (u32)&LOCAL__bss_look_for_nwk_count_2 + 0x0;  /* 024b: l32r -> .bss.look_for_nwk_count$2 (same-object static) */
  a12 = 7;  /* 024e */
  a10 = a1 + (32);  /* 0250 */
  ST32(a5 + 0x0, a11);  /* 0253 */
  ST32(a4 + 0x0, a11);  /* 0255 */
  __asm__ volatile("" ::: "memory");  /* 0258: memw */
  a8 = (u32)&memset + 0x0;  /* 025b: l32r -> global */
  a2 = memset(a2, a3, a4, a5);  /* 025e: callx a8 (libc, via reloc-expand) */
  a4 = LD8U(a2 + 0x5);  /* 0261 */
  ST8(a1 + 0x20, a4);  /* 0264 */
  __asm__ volatile("" ::: "memory");  /* 0267: memw */
  a4 = (u32)&g_mesh_is_root + 0x0;  /* 026a: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 026d: memw */
  a4 = LD8U(a4 + 0x0);  /* 0270 */
  a4 = (a4 >> 8) & 0x1;  /* 0273: extui width 1 */
  if (a4 == 0) goto L_0294;  /* 0276: beqz.n a4, 294 <mesh_nwk_process_look_for_network+0x210> */
  L_0278: a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0278: l32r -> global */
  a5 = LD8U(a4 + 0xc4);  /* 027b */
  if (((a5 >> 0) & 1) == 0) goto L_0294;  /* 027e: bbci a5, 0, 294 <mesh_nwk_process_look_for_network+0x210> */
  L_0281: a11 = 190;  /* 0281 */
  a12 = 6;  /* 0284 */
  a11 = a4 + a11;  /* 0286 */
  a10 = a1 + (33);  /* 0288 */
  __asm__ volatile("" ::: "memory");  /* 028b: memw */
  a8 = (u32)&memcpy + 0x0;  /* 028e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 0291: callx a8 (libc, via reloc-expand) */
  L_0294: a12 = 7;  /* 0294 */
  a11 = a1 + (32);  /* 0296 */
  a10 = 22;  /* 0299 */
  a8 = (u32)&esp_mesh_send_event_internal + 0x0;  /* 029b: l32r -> global */
  a2 = esp_mesh_send_event_internal(a2, a3, a4, a5);  /* 029e: callx a8 via reloc-expand */
  a4 = (u32)&g_is_standalone_sta + 0x0;  /* 02a1: l32r -> global */
  a4 = LD8U(a4 + 0x0);  /* 02a4 */
  if (a4 != 0) goto L_0348;  /* 02a7: bnez a4, 348 <mesh_nwk_process_look_for_network+0x2c4> */
  L_02aa: a10 = 3;  /* 02aa */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 02ac: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5);  /* 02af: callx a8 via reloc-expand */
  a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 02b2: l32r -> global */
  a10 = LD8U(a4 + 0xbc);  /* 02b5 */
  a8 = (u32)&esp_wifi_set_non_mesh_connections + 0x0;  /* 02b8: l32r -> global */
  a2 = esp_wifi_set_non_mesh_connections(a2, a3, a4, a5);  /* 02bb: callx a8 via reloc-expand */
  a12 = 0x15a;  /* 02be */
  a10 = 184;  /* 02c1 */
  a5 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 02c4: l32r -> .rodata.__func__$1 */
  a11 = a5;  /* 02c7: mov */
  a8 = (u32)&mesh_malloc + 0x0;  /* 02ca: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5);  /* 02cd: callx a8 via reloc-expand */
  a4 = a10;  /* 02d0: mov */
  if (a10 == 0) goto L_0309;  /* 02d3: beqz.n a10, 309 <mesh_nwk_process_look_for_network+0x285> */
  L_02d5: a11 = a10;  /* 02d5: mov */
  a10 = 1;  /* 02d8 */
  a8 = (u32)&esp_wifi_get_config + 0x0;  /* 02da: l32r -> global */
  a2 = esp_wifi_get_config(a2, a3, a4, a5);  /* 02dd: callx a8 via reloc-expand */
  a6 = LD8U(a2 + 0x5);  /* 02e0 */
  a11 = a4;  /* 02e3: mov */
  a10 = 1;  /* 02e6 */
  ST8(a4 + 0x61, a6);  /* 02e9 */
  __asm__ volatile("" ::: "memory");  /* 02ec: memw */
  __asm__ volatile("" ::: "memory");  /* 02ef: memw */
  a8 = (u32)&esp_wifi_set_config + 0x0;  /* 02f2: l32r -> global */
  a2 = esp_wifi_set_config(a2, a3, a4, a5, a6);  /* 02f5: callx a8 via reloc-expand */
  a12 = 0x15f;  /* 02f8 */
  a11 = a5;  /* 02fb */
  a10 = a4;  /* 02fd */
  a8 = (u32)&mesh_free + 0x0;  /* 02ff: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5);  /* 0302: callx a8 via reloc-expand */
  goto L_0348;  /* 0305: j */
  L_0309: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0309: l32r -> global */
  a4 = LD32(a6 + 0x0);  /* 030c */
  if (a4 == 0) goto L_0348;  /* 030e: beqz.n a4, 348 <mesh_nwk_process_look_for_network+0x2c4> */
  L_0310: a5 = LD32(a4 + 0x150);  /* 0310 */
  if (a5 == 0) goto L_0348;  /* 0313: beqz a5, 348 <mesh_nwk_process_look_for_network+0x2c4> */
  L_0316: a10 = LD32(a4 + 0x158);  /* 0316 */
  /* 0319: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 031c */
  a6 = LD32(a6 + 0x0);  /* 031e */
  a10 = LD32(a6 + 0xb8);  /* 0321 */
  a6 = 184;  /* 0324 */
  /* 0327: INDIRECT callx a10 <- mem[a6+0xb8]; result unknown */ a2 = 0;
  a13 = a4;  /* 032a */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 032c: -> "mesh" */
  a14 = a11;  /* 032f */
  ST32(a1 + 0x4, a6);  /* 0331 */
  a6 = 0x161;  /* 0333 */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0336: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 0339: -> "root" */
  ST32(a1 + 0x8, a10);  /* 033c */
  a10 = 1;  /* 033e */
  ST32(a1 + 0x0, a6);  /* 0340 */
  __asm__ volatile("" ::: "memory");  /* 0342: memw */
  /* 0345: INDIRECT callx a5 <- mem[a4+0x150]; result unknown */ a2 = 0;
  L_0348: a10 = a3;  /* 0348 */
  a2 = LD8U(a2 + 0x5);  /* 034a */
  ST8(a3 + 0x5, a2);  /* 034d */
  __asm__ volatile("" ::: "memory");  /* 0350: memw */
  __asm__ volatile("" ::: "memory");  /* 0353: memw */
  a8 = (u32)&mesh_process_parent_organized + 0x0;  /* 0356: l32r -> global */
  a2 = mesh_process_parent_organized(a2, a3, a4, a5);  /* 0359: callx a8 via reloc-expand */
  L_035c: a2 = 0;  /* 035c */
  return a2;  /* 035e: retw.n */
}


/* mesh_nwk_process_reselect @ mesh_network.o 0000006c size 599B bind GLOBAL
 * Calls: mesh_malloc, memset, esp_wifi_get_config, mesh_free, esp_mesh_clear_parent, esp_wifi_set_config | indirect[11]: mem[a3+0x158]; mem[a5+0xb8]; mem[a3+0x150]; unknown | Data refs: .rodata.__func__$0, g_osi_funcs_p, .rodata.esp_mesh_channel_enable_jp.str1.1, .rodata.esp_mesh_scan_done_get_channel.str1.1, .rodata.mesh_nwk_process_reselect.str1.1, g_log_level, g_mesh_is_root, g_mesh_self_organized, g_mesh_ext_cfg
 * Fidelity: medium - 11 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=15); reloc-direct=6, funcdb-attributed=0, unknown-indirect=11 */
u32 mesh_nwk_process_reselect(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 006c: entry a1, 64 (frame 64 bytes) */
  a6 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 006f: l32r -> .rodata.__func__$0 */
  a12 = 0x191;  /* 0072 */
  a11 = a6;  /* 0075: mov */
  a10 = 184;  /* 0078 */
  a8 = (u32)&mesh_malloc + 0x0;  /* 007b: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 007e: callx a8 via reloc-expand */
  a7 = (a2 >> 8) & 0x1;  /* 0081: extui width 1 */
  a5 = a10;  /* 0084 */
  if (a10 != 0) goto L_00d1;  /* 0086: bnez a10, d1 <mesh_nwk_process_reselect+0x65> */
  L_0089: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0089: l32r -> global */
  a2 = -1;  /* 008c */
  a3 = LD32(a5 + 0x0);  /* 008e */
  if (a3 == 0) goto L_02c1;  /* 0091: beqz a3, 2c1 <mesh_nwk_process_reselect+0x255> */
  L_0094: a4 = LD32(a3 + 0x150);  /* 0094 */
  if (a4 == 0) goto L_02c1;  /* 0097: beqz a4, 2c1 <mesh_nwk_process_reselect+0x255> */
  L_009a: a10 = LD32(a3 + 0x158);  /* 009a */
  /* 009d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 00a0 */
  a5 = LD32(a5 + 0x0);  /* 00a2 */
  a10 = LD32(a5 + 0xb8);  /* 00a5 */
  a5 = 184;  /* 00a8 */
  /* 00ab: INDIRECT callx a10 <- mem[a5+0xb8]; result unknown */ a2 = 0;
  a13 = a3;  /* 00ae */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 00b0: -> "mesh" */
  a14 = a11;  /* 00b3 */
  ST32(a1 + 0x4, a5);  /* 00b5 */
  a5 = 0x193;  /* 00b7 */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 00ba: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 00bd: -> "root" */
  ST32(a1 + 0x8, a10);  /* 00c0 */
  a10 = 1;  /* 00c2 */
  ST32(a1 + 0x0, a5);  /* 00c4 */
  __asm__ volatile("" ::: "memory");  /* 00c6: memw */
  /* 00c9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_02c1;  /* 00cc: j */
  L_00d1: a12 = 184;  /* 00d1 */
  a11 = 0;  /* 00d4 */
  a8 = (u32)&memset + 0x0;  /* 00d6: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00d9: callx a8 (libc, via reloc-expand) */
  a11 = a5;  /* 00dc */
  a10 = 0;  /* 00de */
  a8 = (u32)&esp_wifi_get_config + 0x0;  /* 00e0: l32r -> global */
  a2 = esp_wifi_get_config(a2, a3, a4, a5, a6, a7);  /* 00e3: callx a8 via reloc-expand */
  a2 = a10;  /* 00e6 */
  if (a10 == 0) goto L_0184;  /* 00e8: beqz a10, 184 <mesh_nwk_process_reselect+0x118> */
  L_00eb: a3 = (u32)&g_log_level + 0x0;  /* 00eb: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00ee */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00f0: l32r -> global */
  if (a3 < 3u) goto L_0146;  /* 00f3: bltui a3, 3, 146 <mesh_nwk_process_reselect+0xda> */
  L_00f6: a3 = LD32(a4 + 0x0);  /* 00f6 */
  if (a3 == 0) goto L_0146;  /* 00f9: beqz a3, 146 <mesh_nwk_process_reselect+0xda> */
  L_00fc: a7 = LD32(a3 + 0x150);  /* 00fc */
  if (a7 == 0) goto L_0146;  /* 00ff: beqz a7, 146 <mesh_nwk_process_reselect+0xda> */
  L_0102: a10 = LD32(a3 + 0x158);  /* 0102 */
  /* 0105: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = (u32)&g_mesh_is_root + 0x0;  /* 0108: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 010b: memw */
  a3 = LD8U(a3 + 0x0);  /* 010e */
  a3 = (a3 >> 8) & 0x1;  /* 0111: extui width 1 */
  a15 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 0114: -> "root" */
  if (a3 != 0) goto L_011c;  /* 0117: bnez.n a3, 11c <mesh_nwk_process_reselect+0xb0> */
  L_0119: a15 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 0119: -> "root" */
  L_011c: a3 = (u32)&g_mesh_self_organized + 0x0;  /* 011c: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 011f: memw */
  a3 = LD8U(a3 + 0x0);  /* 0122 */
  a3 = (a3 >> 8) & 0x1;  /* 0125: extui width 1 */
  a8 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 0128: -> "root" */
  if (a3 == 0) goto L_0130;  /* 012b: beqz.n a3, 130 <mesh_nwk_process_reselect+0xc4> */
  L_012d: a8 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 012d: -> "encrypted" */
  L_0130: a13 = a10;  /* 0130 */
  a10 = 3;  /* 0132 */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 0134: -> "mesh" */
  a14 = a11;  /* 0137 */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 0139: -> "root" */
  ST32(a1 + 0x4, a2);  /* 013c */
  ST32(a1 + 0x0, a8);  /* 013e */
  __asm__ volatile("" ::: "memory");  /* 0140: memw */
  /* 0143: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_0146: a2 = LD32(a4 + 0x0);  /* 0146 */
  if (a2 == 0) goto L_0170;  /* 0148: beqz.n a2, 170 <mesh_nwk_process_reselect+0x104> */
  L_014a: a3 = LD32(a2 + 0x150);  /* 014a */
  if (a3 == 0) goto L_0170;  /* 014d: beqz a3, 170 <mesh_nwk_process_reselect+0x104> */
  L_0150: a10 = LD32(a2 + 0x158);  /* 0150 */
  a2 = 0x1a0;  /* 0153 */
  /* 0156: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0159 */
  a10 = 1;  /* 015b */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 015d: -> "mesh" */
  a14 = a11;  /* 0160 */
  a15 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0162: -> "encrypted" */
  a12 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0165: -> "encrypted" */
  ST32(a1 + 0x0, a2);  /* 0168 */
  __asm__ volatile("" ::: "memory");  /* 016a: memw */
  /* 016d: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0170: a12 = 0x1a1;  /* 0170 */
  a11 = a6;  /* 0173 */
  a10 = a5;  /* 0175 */
  a8 = (u32)&mesh_free + 0x0;  /* 0177: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 017a: callx a8 via reloc-expand */
  a2 = -1;  /* 017d */
  goto L_02c1;  /* 017f: j */
  L_0184: if (a7 != 2) goto L_0195;  /* 0184: bnei a7, 2, 195 <mesh_nwk_process_reselect+0x129> */
  L_0187: ST8(a5 + 0x6b, a10);  /* 0187 */
  __asm__ volatile("" ::: "memory");  /* 018a: memw */
  __asm__ volatile("" ::: "memory");  /* 018d: memw */
  goto L_0248;  /* 0190: j */
  L_0195: a8 = (u32)&g_log_level + 0x0;  /* 0195: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0198 */
  if (a8 < 3u) goto L_01de;  /* 019a: bltui a8, 3, 1de <mesh_nwk_process_reselect+0x172> */
  L_019d: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 019d: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 01a0 */
  if (a8 == 0) goto L_01de;  /* 01a2: beqz.n a8, 1de <mesh_nwk_process_reselect+0x172> */
  L_01a4: a9 = LD32(a8 + 0x150);  /* 01a4 */
  if (a9 == 0) goto L_01de;  /* 01a7: beqz.n a9, 1de <mesh_nwk_process_reselect+0x172> */
  L_01a9: a10 = LD32(a8 + 0x158);  /* 01a9 */
  ST32(a1 + 0x10, a9);  /* 01ac */
  __asm__ volatile("" ::: "memory");  /* 01ae: memw */
  /* 01b1: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = (u32)&g_mesh_is_root + 0x0;  /* 01b4: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 01b7: memw */
  a8 = LD8U(a8 + 0x0);  /* 01ba */
  a8 = (a8 >> 8) & 0x1;  /* 01bd: extui width 1 */
  a15 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 01c0: -> "root" */
  a9 = LD32(a1 + 0x10);  /* 01c3 */
  if (a8 != 0) goto L_01ca;  /* 01c5: bnez.n a8, 1ca <mesh_nwk_process_reselect+0x15e> */
  L_01c7: a15 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 01c7: -> "root" */
  L_01ca: a13 = a10;  /* 01ca */
  a10 = 3;  /* 01cc */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 01ce: -> "mesh" */
  a14 = a11;  /* 01d1 */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 01d3: -> "root" */
  ST32(a1 + 0x0, a7);  /* 01d6 */
  __asm__ volatile("" ::: "memory");  /* 01d8: memw */
  /* 01db: INDIRECT callx a9 <- mem[a1+0x10]; result unknown */ a2 = 0;
  L_01de: a9 = 0;  /* 01de */
  a12 = 6;  /* 01e0 */
  a11 = 0;  /* 01e2 */
  ST8(a5 + 0x64, a9);  /* 01e4 */
  __asm__ volatile("" ::: "memory");  /* 01e7: memw */
  a10 = a5 + (101);  /* 01ea */
  ST32(a1 + 0x10, a9);  /* 01ed */
  __asm__ volatile("" ::: "memory");  /* 01ef: memw */
  a8 = (u32)&memset + 0x0;  /* 01f2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01f5: callx a8 (libc, via reloc-expand) */
  a10 = -2;  /* 01f8 */
  a12 = 6;  /* 01fa */
  a11 = 0;  /* 01fc */
  a7 = (u32)&g_mesh_ext_cfg + 0x0;  /* 01fe: l32r -> global */
  a8 = LD8U(a7 + 0xc4);  /* 0201 */
  a8 = a8 & a10;  /* 0204 */
  a10 = (u32)&g_mesh_ext_cfg + 0xbe;  /* 0207: l32r -> global */
  ST8(a7 + 0xc4, a8);  /* 020a */
  __asm__ volatile("" ::: "memory");  /* 020d: memw */
  __asm__ volatile("" ::: "memory");  /* 0210: memw */
  a8 = (u32)&memset + 0x0;  /* 0213: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0216: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x10);  /* 0219 */
  if (a3 != 5) goto L_0248;  /* 021b: bnei a3, 5, 248 <mesh_nwk_process_reselect+0x1dc> */
  L_021e: if (a4 == 0) goto L_0248;  /* 021e: beqz.n a4, 248 <mesh_nwk_process_reselect+0x1dc> */
  L_0220: a3 = 3;  /* 0220 */
  a11 = 0x1c3;  /* 0222 */
  a8 = LD8U(a7 + 0xc4);  /* 0225 */
  a7 = 2;  /* 0228 */
  a8 = (a8 >> 1) & 0x3;  /* 022a: extui width 2 */
  if (a8 != 0) a3 = a7;  /* 022d */
  a10 = a6;  /* 0230 */
  ST8(a4 + 0x4, a3);  /* 0232 */
  a3 = 43;  /* 0235 */
  ST8(a4 + 0x5, a9);  /* 0237 */
  __asm__ volatile("" ::: "memory");  /* 023a: memw */
  ST32(a4 + 0x0, a3);  /* 023d */
  __asm__ volatile("" ::: "memory");  /* 023f: memw */
  a8 = (u32)&esp_mesh_clear_parent + 0x0;  /* 0242: l32r -> global */
  a2 = esp_mesh_clear_parent(a2, a3, a4, a5, a6, a7);  /* 0245: callx a8 via reloc-expand */
  L_0248: a11 = a5;  /* 0248 */
  a10 = 0;  /* 024a */
  a8 = (u32)&esp_wifi_set_config + 0x0;  /* 024c: l32r -> global */
  a2 = esp_wifi_set_config(a2, a3, a4, a5, a6, a7);  /* 024f: callx a8 via reloc-expand */
  a7 = a10;  /* 0252 */
  if (a10 == 0) goto L_02b4;  /* 0254: beqz a10, 2b4 <mesh_nwk_process_reselect+0x248> */
  L_0257: a3 = (u32)&g_log_level + 0x0;  /* 0257: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 025a */
  if (a3 < 3u) goto L_02b4;  /* 025c: bltui a3, 3, 2b4 <mesh_nwk_process_reselect+0x248> */
  L_025f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 025f: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0262 */
  if (a3 == 0) goto L_02b4;  /* 0265: beqz a3, 2b4 <mesh_nwk_process_reselect+0x248> */
  L_0268: a4 = LD32(a3 + 0x150);  /* 0268 */
  if (a4 == 0) goto L_02b4;  /* 026b: beqz a4, 2b4 <mesh_nwk_process_reselect+0x248> */
  L_026e: a10 = LD32(a3 + 0x158);  /* 026e */
  /* 0271: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = (u32)&g_mesh_is_root + 0x0;  /* 0274: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0277: memw */
  a3 = LD8U(a3 + 0x0);  /* 027a */
  a3 = (a3 >> 8) & 0x1;  /* 027d: extui width 1 */
  a15 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 0280: -> "root" */
  if (a3 != 0) goto L_0288;  /* 0283: bnez.n a3, 288 <mesh_nwk_process_reselect+0x21c> */
  L_0285: a15 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 0285: -> "root" */
  L_0288: a3 = (u32)&g_mesh_self_organized + 0x0;  /* 0288: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 028b: memw */
  a3 = LD8U(a3 + 0x0);  /* 028e */
  a3 = (a3 >> 8) & 0x1;  /* 0291: extui width 1 */
  a8 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 0294: -> "root" */
  if (a3 == 0) goto L_029c;  /* 0297: beqz.n a3, 29c <mesh_nwk_process_reselect+0x230> */
  L_0299: a8 = (u32)(RODATA__rodata_esp_mesh_scan_done_get_channel_str1_1 + 0x0);  /* 0299: -> "encrypted" */
  L_029c: a13 = a10;  /* 029c */
  a10 = 3;  /* 029e */
  a11 = (u32)(RODATA__rodata_esp_mesh_channel_enable_jp_str1_1 + 0x0);  /* 02a0: -> "mesh" */
  a14 = a11;  /* 02a3: mov */
  a12 = (u32)(RODATA__rodata_mesh_nwk_process_reselect_str1_1 + 0x0);  /* 02a6: -> "root" */
  ST32(a1 + 0x4, a7);  /* 02a9 */
  ST32(a1 + 0x0, a8);  /* 02ab */
  __asm__ volatile("" ::: "memory");  /* 02ae: memw */
  /* 02b1: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_02b4: a12 = 0x1d5;  /* 02b4 */
  a11 = a6;  /* 02b7 */
  a10 = a5;  /* 02b9 */
  a8 = (u32)&mesh_free + 0x0;  /* 02bb: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 02be: callx a8 via reloc-expand */
  L_02c1: return a2;  /* 02c1: retw.n */
}

