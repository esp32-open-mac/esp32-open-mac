/* libmesh.a mesh_route.o --- reconstructed C (offline).
 * Role: routing tables: lookup, refresh, pack/announce, add/remove announcements, acks.
 * Object file: 67284 bytes on disk; 37/37 functions reconstructed, ~12894 code bytes.
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
extern u32 g_is_mesh_started; /* undefined data (reloc-referenced) */
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_mesh_chain; /* undefined data (reloc-referenced) */
extern u32 g_mesh_conn; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ext_cfg; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ie; /* undefined data (reloc-referenced) */
extern u32 g_mesh_init_ps_type; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_max_layer; /* undefined data (reloc-referenced) */
extern u32 g_mesh_rmv_opt; /* undefined data (reloc-referenced) */
extern u32 g_mesh_rt_capacity; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_map_addr; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_sta_addr; /* undefined data (reloc-referenced) */
extern u32 g_mesh_topology; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 mesh_conn_mutex; /* undefined data (reloc-referenced) */
extern u32 mesh_multi_recv_ack; /* undefined data (reloc-referenced) */
extern u32 mesh_multi_send_ack; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_get_ap_assoc_expire(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_get_child_idx(); /* defined in another libmesh.a object */
extern u32 esp_mesh_is_roots_found(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_is_rt_change_debug(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_nwk_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_send_event_internal(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_send_mgmt(); /* defined in another libmesh.a object */
extern u32 esp_mesh_set_beacon_interval(); /* defined in another libmesh.a object */
extern u32 esp_mesh_tx_tid_flush(); /* defined in another libmesh.a object */
extern u32 esp_wifi_deauth_sta(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_vnd_mesh_get(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_vnd_mesh_set(); /* undefined func (args unknown, returns u32) */
extern u32 mesh_free(); /* defined in another libmesh.a object */
extern u32 mesh_malloc(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_lock(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_unlock(); /* defined in another libmesh.a object */
extern u32 nwk_event_id2str(); /* defined in another libmesh.a object */
static const u8 RODATA__rodata_CSWTCH_438[] = { 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00 }; /* .rodata.CSWTCH$438 (12 bytes) */
static const u8 RODATA__rodata___func___0[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x67, 0x65, 0x74, 0x5f, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x61, 0x62 }; /* .rodata.__func__$0 (24 bytes) */
static const u8 RODATA__rodata___func___1[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x61, 0x62 }; /* .rodata.__func__$1 (28 bytes) */
static const u8 RODATA__rodata___func___10[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x74, 0x5f, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f }; /* .rodata.__func__$10 (20 bytes) */
static const u8 RODATA__rodata___func___11[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x64, 0x65, 0x69, 0x6e, 0x69 }; /* .rodata.__func__$11 (20 bytes) */
static const u8 RODATA__rodata___func___2[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x5f, 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x5f, 0x61 }; /* .rodata.__func__$2 (32 bytes) */
static const u8 RODATA__rodata___func___3[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x6f, 0x6d, 0x62, 0x69, 0x6e, 0x65, 0x5f, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x5f, 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x5f, 0x61, 0x63, 0x6b }; /* .rodata.__func__$3 (36 bytes) */
static const u8 RODATA__rodata___func___4[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72 }; /* .rodata.__func__$4 (36 bytes) */
static const u8 RODATA__rodata___func___5[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x6f, 0x70, 0x79, 0x5f, 0x6d, 0x67, 0x6d, 0x74, 0x5f, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x00 }; /* .rodata.__func__$5 (28 bytes) strings: [0x0]="esp_mesh_copy_mgmt_announce" */
static const u8 RODATA__rodata___func___6[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x5f, 0x72, 0x6d, 0x76, 0x5f, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65 }; /* .rodata.__func__$6 (24 bytes) */
static const u8 RODATA__rodata___func___7[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x5f, 0x72, 0x6d, 0x76, 0x5f, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74 }; /* .rodata.__func__$7 (28 bytes) */
static const u8 RODATA__rodata___func___8[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x00 }; /* .rodata.__func__$8 (24 bytes) strings: [0x0]="mesh_update_route_table" */
static const u8 RODATA__rodata___func___9[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x67, 0x65, 0x74, 0x5f, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x5f, 0x6e, 0x75, 0x6d, 0x00 }; /* .rodata.__func__$9 (32 bytes) strings: [0x0]="esp_mesh_get_total_children_num" */
static const u8 RODATA__rodata_esp_mesh_check_multi_redundant_ack_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x3e, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x20, 0x69, 0x73, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x62, 0x79, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x64, 0x69, 0x73, 0x63, 0x61, 0x72, 0x64, 0x20, 0x6f, 0x75, 0x74, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x61, 0x63, 0x6b, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x28, 0x70, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x29, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x3e, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x28, 0x25, 0x6c, 0x6c, 0x75, 0x6d, 0x73, 0x29, 0x2c, 0x20, 0x77, 0x61, 0x69, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6d, 0x6f, 0x72, 0x65, 0x20, 0x61, 0x63, 0x6b, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x28, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x64, 0x69, 0x73, 0x63, 0x61, 0x72, 0x64, 0x28, 0x70, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64 }; /* .rodata.esp_mesh_check_multi_redundant_ack.str1.1 (308 bytes) */
static const u8 RODATA__rodata_esp_mesh_combine_multi_redundant_ack_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x74, 0x5f, 0x63, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x3e, 0x70, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x28, 0x6c, 0x6f, 0x73, 0x73, 0x29, 0x2c, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x20, 0x70, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x28, 0x6d, 0x6f, 0x72, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x2d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x28, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x3e, 0x70, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x28, 0x6d, 0x6f, 0x72, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x2d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x28, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x0a }; /* .rodata.esp_mesh_combine_multi_redundant_ack.str1.1 (344 bytes) */
static const u8 RODATA__rodata_esp_mesh_copy_mgmt_announce_str1_1[] = { 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x5b, 0x41, 0x4e, 0x4e, 0x4f, 0x55, 0x4e, 0x43, 0x45, 0x5d, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x2c, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3a, 0x25, 0x64, 0x28, 0x6d, 0x61, 0x78, 0x20, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x29, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x20, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3a, 0x25, 0x64, 0x28, 0x6d, 0x61, 0x78, 0x20, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64 }; /* .rodata.esp_mesh_copy_mgmt_announce.str1.1 (272 bytes) */
static const u8 RODATA__rodata_esp_mesh_get_routing_table_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x0a, 0x00 }; /* .rodata.esp_mesh_get_routing_table.str1.1 (32 bytes) */
static const u8 RODATA__rodata_esp_mesh_lookup_route_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x2e, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73 }; /* .rodata.esp_mesh_lookup_route.str1.1 (44 bytes) strings: [0x0]="mesh_route.c"; [0xd]="mesh" */
static const u8 RODATA__rodata_esp_mesh_monitor_nonassociated_children_str1_1[] = { 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x21, 0x21, 0x21, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x52, 0x4f, 0x55, 0x54, 0x45, 0x5f, 0x54, 0x41, 0x42, 0x4c, 0x45, 0x5f, 0x4e, 0x45, 0x57, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x5b, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x5d, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x3e, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x63, 0x69, 0x64, 0x78, 0x5b, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x70, 0x61, 0x6e, 0x64, 0x6f, 0x72, 0x61, 0x0a }; /* .rodata.esp_mesh_monitor_nonassociated_children.str1.1 (180 bytes) */
static const u8 RODATA__rodata_esp_mesh_nwk_redundant_route_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x25, 0x73, 0x3e, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x25, 0x73, 0x3e, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x61, 0x63, 0x6b, 0x28, 0x70, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x20, 0x74, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78 }; /* .rodata.esp_mesh_nwk_redundant_route.str1.1 (160 bytes) */
static const u8 RODATA__rodata_esp_mesh_pack_multi_routing_table_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x41, 0x43, 0x4b, 0x5d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x6d, 0x76, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x5f, 0x73, 0x65, 0x6e, 0x64, 0x5f, 0x61, 0x63, 0x6b, 0x5b, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3a, 0x25, 0x64, 0x5d, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x41, 0x43, 0x4b, 0x5d, 0x73, 0x75, 0x62, 0x2d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x5b, 0x25, 0x64, 0x5d, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00 }; /* .rodata.esp_mesh_pack_multi_routing_table.str1.1 (212 bytes) */
static const u8 RODATA__rodata_esp_mesh_process_redundant_subchildren_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x64, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x6c, 0x69, 0x73, 0x74, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x28, 0x73, 0x65, 0x6c, 0x66, 0x29, 0x20, 0x75, 0x6e, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x3c, 0x73, 0x65, 0x6c, 0x66, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x3e, 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x64, 0x2c, 0x20, 0x3c, 0x73, 0x65, 0x6c, 0x66, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x3e, 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x54, 0x58, 0x2d, 0x52, 0x4d, 0x56, 0x5d, 0x73, 0x75, 0x62, 0x2d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x20, 0x6f, 0x66, 0x20, 0x63, 0x69, 0x64, 0x78, 0x5b, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78 }; /* .rodata.esp_mesh_process_redundant_subchildren.str1.1 (448 bytes) */
static const u8 RODATA__rodata_esp_mesh_refresh_routing_table_str1_1[] = { 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x00, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x3c, 0x6e, 0x65, 0x77, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6f, 0x6c, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6c, 0x61, 0x73, 0x74, 0x3a, 0x25, 0x64, 0x3e, 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x5f, 0x6d, 0x73, 0x3a, 0x25, 0x64, 0x28, 0x25, 0x64, 0x29, 0x3c, 0x25, 0x73, 0x3e, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x3e, 0x72, 0x65, 0x64, 0x75, 0x6e, 0x64, 0x61, 0x6e, 0x74, 0x20, 0x72, 0x65, 0x71, 0x2f, 0x61, 0x63, 0x6b, 0x20, 0x6f, 0x63, 0x63, 0x75, 0x72, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x2d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x2c, 0x20, 0x75, 0x6e, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x20, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3a, 0x25 }; /* .rodata.esp_mesh_refresh_routing_table.str1.1 (232 bytes) strings: [0x0]="redundant" */
static const u8 RODATA__rodata_esp_mesh_remove_nonassociated_children_str1_1[] = { 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x5b, 0x41, 0x4e, 0x4e, 0x4f, 0x55, 0x4e, 0x43, 0x45, 0x5d, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x2c, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x5b, 0x41, 0x4e, 0x4e, 0x4f, 0x55, 0x4e, 0x43, 0x45, 0x5d, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x2c, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x69, 0x64, 0x78, 0x3a, 0x25, 0x64, 0x0a, 0x00 }; /* .rodata.esp_mesh_remove_nonassociated_children.str1.1 (172 bytes) */
static const u8 RODATA__rodata_esp_mesh_send_rtable_ack_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x3e, 0x73, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x63, 0x6b, 0x2c, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x20, 0x74, 0x6f, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32 }; /* .rodata.esp_mesh_send_rtable_ack.str1.1 (120 bytes) */
static const u8 RODATA__rodata_mesh_fill_rmv_sub_child_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x54, 0x58, 0x2d, 0x52, 0x4d, 0x56, 0x5d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x6d, 0x76, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x54, 0x58, 0x2d, 0x52, 0x4d, 0x56, 0x5d, 0x73, 0x75, 0x62, 0x2d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6f, 0x63, 0x63, 0x75, 0x70, 0x69, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x6d, 0x76, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x54, 0x58, 0x2d, 0x52, 0x4d, 0x56, 0x5d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5b, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6f, 0x63, 0x63, 0x75, 0x70, 0x69, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x6d, 0x76, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x5f, 0x63, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x5b, 0x25, 0x64, 0x5d, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x54, 0x58, 0x2d, 0x52, 0x4d, 0x56, 0x5d, 0x73, 0x75, 0x62, 0x2d, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6f, 0x63, 0x63, 0x75, 0x70, 0x69, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x5b, 0x25, 0x64, 0x5d, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64 }; /* .rodata.mesh_fill_rmv_sub_child.str1.1 (388 bytes) */
static const u8 RODATA__rodata_mesh_malloc_rmv_announcement_str1_1[] = { 0x74, 0x72, 0x65, 0x65, 0x00, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x25, 0x64, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x20, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00 }; /* .rodata.mesh_malloc_rmv_announcement.str1.1 (84 bytes) strings: [0x0]="tree"; [0x5]="chain" */
static const u8 RODATA__rodata_mesh_update_route_table_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x3e, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x3a, 0x20, 0x63, 0x69, 0x64, 0x78, 0x5b, 0x25, 0x64, 0x5d, 0x20, 0x3e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6d, 0x61, 0x78, 0x5b, 0x25, 0x64, 0x5d, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x2c, 0x20, 0x63, 0x69, 0x64, 0x78, 0x5b, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x20, 0x61, 0x69, 0x64, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x2c, 0x20, 0x63, 0x69, 0x64, 0x78, 0x5b, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a }; /* .rodata.mesh_update_route_table.str1.1 (240 bytes) */
static const u8 RODATA__rodata_routetype2str_str1_1[] = { 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x00 }; /* .rodata.routetype2str.str1.1 (8 bytes) strings: [0x0]="Unknown" */
static u8 LOCAL__bss_MESH_ZERO_ADDR[0x4]; /* stand-in for .bss.MESH_ZERO_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_is_route_inited[0x4]; /* stand-in for .bss.is_route_inited (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_route_table[0x4]; /* stand-in for .bss.mesh_route_table (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_rt_change_timer[0x4]; /* stand-in for .bss.rt_change_timer (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_check_multi_redundant_ack @ mesh_route.o 00000028 size 626B bind GLOBAL
 * Calls: memcmp, mesh_free, memset | indirect[10]: mem[a8+0x158]; unknown; mem[a9+0x110]; mem[a7+0x110] | Data refs: mesh_multi_recv_ack, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, .rodata.esp_mesh_check_multi_redundant_ack.str1.1, .rodata.__func__$2
 * Fidelity: medium - 10 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=9); reloc-direct=3, funcdb-attributed=0, unknown-indirect=10 */
u32 esp_mesh_check_multi_redundant_ack(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a4, a5, a6, a7, a8, a9;
  /* 0028: entry a1, 112 (frame 112 bytes) */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 002b: sext */
  a5 = (u32)&mesh_multi_recv_ack + 0x0;  /* 002e: l32r -> global */
  a7 = a2 + (a2 << 1);  /* 0031 */
  a7 = a7 + (a5 << 3);  /* 0034 */
  a4 = a2 + a2;  /* 0037 */
  a6 = LD32(a7 + 0x4);  /* 0039 */
  a8 = (a6 >> 7) & 0x1ffff;  /* 003b: extui width 17 */
  if (a8 == 0) goto L_0296;  /* 003e: beqz a8, 296 <esp_mesh_check_multi_redundant_ack+0x26e> */
  L_0041: if (((a6 >> 23) & 1) != 0) goto L_0047;  /* 0041: bbsi a6, 23, 47 <esp_mesh_check_multi_redundant_ack+0x1f> */
  L_0044: goto L_0296;  /* 0044: j */
  L_0047: a12 = 6;  /* 0047 */
  a11 = a3;  /* 0049 */
  a10 = a7;  /* 004b: mov */
  a6 = a7;  /* 004e: mov */
  ST32(a1 + 0x40, a7);  /* 0051 */
  __asm__ volatile("" ::: "memory");  /* 0054: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0057: l32r -> global */
  a2 = memcmp(a2, a3);  /* 005a: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_00e9;  /* 005d: beqz a10, e9 <esp_mesh_check_multi_redundant_ack+0xc1> */
  L_0060: a8 = (u32)&g_log_level + 0x0;  /* 0060: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0063 */
  if (a8 < 3u) goto L_00d8;  /* 0065: bltui a8, 3, d8 <esp_mesh_check_multi_redundant_ack+0xb0> */
  L_0068: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0068: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 006b */
  if (a8 == 0) goto L_00d8;  /* 006d: beqz a8, d8 <esp_mesh_check_multi_redundant_ack+0xb0> */
  L_0070: a6 = LD32(a8 + 0x150);  /* 0070 */
  if (a6 == 0) goto L_00d8;  /* 0073: beqz a6, d8 <esp_mesh_check_multi_redundant_ack+0xb0> */
  L_0076: a10 = LD32(a8 + 0x158);  /* 0076 */
  /* 0079: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 007c */
  a15 = a2;  /* 007e */
  a8 = LD16U(a7 + 0xc);  /* 0080 */
  a10 = 3;  /* 0083 */
  ST32(a1 + 0x34, a8);  /* 0085 */
  a8 = LD32(a7 + 0x4);  /* 0087 */
  a8 = (a8 >> 7) & 0x1ffff;  /* 0089: extui width 17 */
  ST32(a1 + 0x30, a8);  /* 008c */
  a8 = LD8U(a7 + 0x5);  /* 008e */
  ST32(a1 + 0x2c, a8);  /* 0091 */
  a8 = LD8U(a7 + 0x4);  /* 0093 */
  ST32(a1 + 0x28, a8);  /* 0096 */
  a8 = LD8U(a7 + 0x3);  /* 0098 */
  ST32(a1 + 0x24, a8);  /* 009b */
  a8 = LD8U(a7 + 0x2);  /* 009d */
  ST32(a1 + 0x20, a8);  /* 00a0 */
  a8 = LD8U(a7 + 0x1);  /* 00a2 */
  ST32(a1 + 0x1c, a8);  /* 00a5 */
  a7 = LD8U(a7 + 0x0);  /* 00a7 */
  ST32(a1 + 0x18, a7);  /* 00aa */
  a7 = LD8U(a3 + 0x5);  /* 00ac */
  ST32(a1 + 0x14, a7);  /* 00af */
  a7 = LD8U(a3 + 0x4);  /* 00b1 */
  ST32(a1 + 0x10, a7);  /* 00b4 */
  a7 = LD8U(a3 + 0x3);  /* 00b6 */
  ST32(a1 + 0xc, a7);  /* 00b9 */
  a7 = LD8U(a3 + 0x2);  /* 00bb */
  ST32(a1 + 0x8, a7);  /* 00be */
  a7 = LD8U(a3 + 0x1);  /* 00c0 */
  ST32(a1 + 0x4, a7);  /* 00c3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00c5: -> "mesh_route.c" */
  a14 = a11;  /* 00c8 */
  a3 = LD8U(a3 + 0x0);  /* 00ca */
  a12 = (u32)(RODATA__rodata_esp_mesh_check_multi_redundant_ack_str1_1 + 0x0);  /* 00cd: l32r -> .rodata.esp_mesh_check_multi_redundant_ack.str1.1 */
  ST32(a1 + 0x0, a3);  /* 00d0 */
  __asm__ volatile("" ::: "memory");  /* 00d2: memw */
  /* 00d5: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_00d8: a2 = a4 + a2;  /* 00d8 */
  a2 = a2 + (a5 << 3);  /* 00da */
  a12 = 0x5d1;  /* 00dd */
  a11 = (u32)(RODATA__rodata___func___2 + 0x0);  /* 00e0: l32r -> .rodata.__func__$2 */
  a10 = LD32(a2 + 0x8);  /* 00e3 */
  goto L_0283;  /* 00e5: j */
  L_00e9: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 00e9: l32r -> global */
  a9 = LD32(a6 + 0x0);  /* 00ec */
  a10 = LD32(a9 + 0x110);  /* 00ee */
  /* 00f1: INDIRECT callx a10 <- mem[a9+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a7 + 0x14);  /* 00f4 */
  if ((i32)a11 < (i32)a9) goto L_014e;  /* 00f6: blt a11, a9, 14e <esp_mesh_check_multi_redundant_ack+0x126> */
  L_00f9: if (a9 != a11) goto L_0101;  /* 00f9: bne a9, a11, 101 <esp_mesh_check_multi_redundant_ack+0xd9> */
  L_00fc: a7 = LD32(a7 + 0x10);  /* 00fc */
  if (a10 < a7) goto L_014e;  /* 00fe: bltu a10, a7, 14e <esp_mesh_check_multi_redundant_ack+0x126> */
  L_0101: a7 = LD32(a6 + 0x0);  /* 0101 */
  a10 = LD32(a7 + 0x110);  /* 0103 */
  /* 0106: INDIRECT callx a10 <- mem[a7+0x110]; result unknown */ a2 = 0;
  a9 = a4 + a2;  /* 0109 */
  a9 = a9 + (a5 << 3);  /* 010b */
  a7 = LD32(a9 + 0x10);  /* 010e */
  a7 = a10 - a7;  /* 0110: sub */
  a12 = LD32(a9 + 0x14);  /* 0113 */
  a9 = 1;  /* 0115 */
  if (a10 < a7) goto L_011c;  /* 0117: bltu a10, a7, 11c <esp_mesh_check_multi_redundant_ack+0xf4> */
  L_011a: a9 = 0;  /* 011a */
  L_011c: a11 = a11 - a12;  /* 011c: sub */
  a11 = a11 - a9;  /* 011f: sub */
  a9 = a11 << 22;  /* 0122 */
  a7 = a7 >> 10;  /* 0125 */
  a11 = (i32)a11 >> 10;  /* 0128 */
  a7 = a9 | a7;  /* 012b */
  if ((i32)a11 >= 1) goto L_0140;  /* 012e: bgei a11, 1, 140 <esp_mesh_check_multi_redundant_ack+0x118> */
  L_0131: if (a11 != 0) goto L_0296;  /* 0131: bnez a11, 296 <esp_mesh_check_multi_redundant_ack+0x26e> */
  L_0134: a9 = 0x271;  /* 0134 */
  a9 = a9 << 3;  /* 0137 */
  if (a9 < a7) goto L_0140;  /* 013a: bltu a9, a7, 140 <esp_mesh_check_multi_redundant_ack+0x118> */
  L_013d: goto L_0296;  /* 013d: j */
  L_0140: a7 = (u32)&g_log_level + 0x0;  /* 0140: l32r -> global */
  a7 = LD32(a7 + 0x0);  /* 0143 */
  if (a7 >= 3u) goto L_019a;  /* 0145: bgeui a7, 3, 19a <esp_mesh_check_multi_redundant_ack+0x172> */
  L_0148: goto L_0276;  /* 0148: j */
  L_014e: a7 = LD32(a6 + 0x0);  /* 014e */
  a10 = LD32(a7 + 0x110);  /* 0150 */
  a7 = a4 + a2;  /* 0153 */
  /* 0155: INDIRECT callx a10 <- mem[a7+0x110]; result unknown */ a2 = 0;
  a7 = a7 + (a5 << 3);  /* 0158 */
  a12 = -1;  /* 015b */
  a9 = LD32(a7 + 0x10);  /* 015d */
  a9 = a9 ^ a12;  /* 015f */
  a10 = a9 + a10;  /* 0162 */
  a12 = 1;  /* 0164 */
  a7 = LD32(a7 + 0x14);  /* 0166 */
  if (a10 < a9) goto L_016d;  /* 0168: bltu a10, a9, 16d <esp_mesh_check_multi_redundant_ack+0x145> */
  L_016b: a12 = 0;  /* 016b */
  L_016d: a11 = a7 + a11;  /* 016d */
  a9 = a10 + (1);  /* 016f */
  a11 = a12 + a11;  /* 0171 */
  a7 = 1;  /* 0173 */
  if (a9 < a10) goto L_017a;  /* 0175: bltu a9, a10, 17a <esp_mesh_check_multi_redundant_ack+0x152> */
  L_0178: a7 = 0;  /* 0178 */
  L_017a: a7 = a7 + a11;  /* 017a */
  a10 = a7 << 22;  /* 017c */
  a9 = a9 >> 10;  /* 017f */
  a7 = (i32)a7 >> 10;  /* 0182 */
  a9 = a10 | a9;  /* 0185 */
  if ((i32)a7 >= 1) goto L_0140;  /* 0188: bgei a7, 1, 140 <esp_mesh_check_multi_redundant_ack+0x118> */
  L_018b: if (a7 != 0) goto L_0296;  /* 018b: bnez a7, 296 <esp_mesh_check_multi_redundant_ack+0x26e> */
  L_018e: a7 = 0x271;  /* 018e */
  a7 = a7 << 3;  /* 0191 */
  if (a7 < a9) goto L_0140;  /* 0194: bltu a7, a9, 140 <esp_mesh_check_multi_redundant_ack+0x118> */
  L_0197: goto L_0296;  /* 0197: j */
  L_019a: a7 = LD32(a6 + 0x0);  /* 019a */
  if (a7 == 0) goto L_0276;  /* 019c: beqz a7, 276 <esp_mesh_check_multi_redundant_ack+0x24e> */
  L_019f: a8 = LD32(a7 + 0x150);  /* 019f */
  ST32(a1 + 0x44, a8);  /* 01a2 */
  if (a8 == 0) goto L_0276;  /* 01a5: beqz a8, 276 <esp_mesh_check_multi_redundant_ack+0x24e> */
  L_01a8: a10 = LD32(a7 + 0x158);  /* 01a8 */
  __asm__ volatile("" ::: "memory");  /* 01ab: memw */
  /* 01ae: INDIRECT callx a10 <- mem[a7+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 01b1 */
  a9 = LD32(a6 + 0x0);  /* 01b3 */
  a10 = LD32(a9 + 0x110);  /* 01b6 */
  /* 01b9: INDIRECT callx a10 <- mem[a9+0x110]; result unknown */ a2 = 0;
  a9 = a4 + a2;  /* 01bc */
  a9 = a9 + (a5 << 3);  /* 01be */
  a12 = LD32(a9 + 0x14);  /* 01c1 */
  if ((i32)a11 < (i32)a12) goto L_01f2;  /* 01c3: blt a11, a12, 1f2 <esp_mesh_check_multi_redundant_ack+0x1ca> */
  L_01c6: if (a12 != a11) goto L_01ce;  /* 01c6: bne a12, a11, 1ce <esp_mesh_check_multi_redundant_ack+0x1a6> */
  L_01c9: a9 = LD32(a9 + 0x10);  /* 01c9 */
  if (a10 < a9) goto L_01f2;  /* 01cb: bltu a10, a9, 1f2 <esp_mesh_check_multi_redundant_ack+0x1ca> */
  L_01ce: a8 = LD32(a6 + 0x0);  /* 01ce */
  a10 = LD32(a8 + 0x110);  /* 01d0 */
  /* 01d3: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = a4 + a2;  /* 01d6 */
  a8 = a8 + (a5 << 3);  /* 01d8 */
  a9 = LD32(a8 + 0x10);  /* 01db */
  a12 = 1;  /* 01dd */
  a9 = a10 - a9;  /* 01df: sub */
  a8 = LD32(a8 + 0x14);  /* 01e2 */
  if (a10 < a9) goto L_01e9;  /* 01e4: bltu a10, a9, 1e9 <esp_mesh_check_multi_redundant_ack+0x1c1> */
  L_01e7: a12 = 0;  /* 01e7 */
  L_01e9: a8 = a11 - a8;  /* 01e9: sub */
  a8 = a8 - a12;  /* 01ec: sub */
  goto L_0220;  /* 01ef: j */
  L_01f2: a8 = LD32(a6 + 0x0);  /* 01f2 */
  a10 = LD32(a8 + 0x110);  /* 01f4 */
  /* 01f7: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = a4 + a2;  /* 01fa */
  a8 = a8 + (a5 << 3);  /* 01fc */
  a9 = LD32(a8 + 0x10);  /* 01ff */
  a12 = -1;  /* 0201 */
  a9 = a9 ^ a12;  /* 0203 */
  a10 = a9 + a10;  /* 0206 */
  a12 = 1;  /* 0208 */
  a8 = LD32(a8 + 0x14);  /* 020a */
  if (a10 < a9) goto L_0211;  /* 020c: bltu a10, a9, 211 <esp_mesh_check_multi_redundant_ack+0x1e9> */
  L_020f: a12 = 0;  /* 020f */
  L_0211: a11 = a8 + a11;  /* 0211 */
  a9 = a10 + (1);  /* 0213 */
  a11 = a12 + a11;  /* 0215 */
  a8 = 1;  /* 0217 */
  if (a9 < a10) goto L_021e;  /* 0219: bltu a9, a10, 21e <esp_mesh_check_multi_redundant_ack+0x1f6> */
  L_021c: a8 = 0;  /* 021c */
  L_021e: a8 = a8 + a11;  /* 021e */
  L_0220: a10 = a8 << 22;  /* 0220 */
  a9 = a9 >> 10;  /* 0223 */
  a9 = a10 | a9;  /* 0226 */
  a10 = a4 + a2;  /* 0229 */
  a10 = a10 + (a5 << 3);  /* 022b */
  a12 = LD16U(a10 + 0xc);  /* 022e */
  a8 = (i32)a8 >> 10;  /* 0231 */
  a13 = a7;  /* 0234 */
  ST32(a1 + 0x28, a12);  /* 0236 */
  a10 = LD32(a10 + 0x4);  /* 0238 */
  a10 = (a10 >> 7) & 0x1ffff;  /* 023a: extui width 17 */
  ST32(a1 + 0x24, a10);  /* 023d */
  ST32(a1 + 0x20, a2);  /* 023f */
  a10 = LD8U(a3 + 0x5);  /* 0241 */
  ST32(a1 + 0x1c, a10);  /* 0244 */
  a10 = LD8U(a3 + 0x4);  /* 0246 */
  ST32(a1 + 0x18, a10);  /* 0249 */
  a10 = LD8U(a3 + 0x3);  /* 024b */
  ST32(a1 + 0x14, a10);  /* 024e */
  a10 = LD8U(a3 + 0x2);  /* 0250 */
  ST32(a1 + 0x10, a10);  /* 0253 */
  a10 = LD8U(a3 + 0x1);  /* 0255 */
  ST32(a1 + 0xc, a10);  /* 0258 */
  a10 = 3;  /* 025a */
  a3 = LD8U(a3 + 0x0);  /* 025c */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 025f: -> "mesh_route.c" */
  a14 = a11;  /* 0262 */
  ST32(a1 + 0x8, a3);  /* 0264 */
  a12 = (u32)(RODATA__rodata_esp_mesh_check_multi_redundant_ack_str1_1 + 0x0);  /* 0266: l32r -> .rodata.esp_mesh_check_multi_redundant_ack.str1.1 */
  a3 = LD32(a1 + 0x44);  /* 0269 */
  ST32(a1 + 0x0, a9);  /* 026c */
  ST32(a1 + 0x4, a8);  /* 026e */
  __asm__ volatile("" ::: "memory");  /* 0270: memw */
  /* 0273: INDIRECT callx a3 <- mem[a1+0x44]; result unknown */ a2 = 0;
  L_0276: a4 = a4 + a2;  /* 0276 */
  a4 = a4 + (a5 << 3);  /* 0278 */
  a12 = 0x5de;  /* 027b */
  a11 = (u32)(RODATA__rodata___func___2 + 0x0);  /* 027e: l32r -> .rodata.__func__$2 */
  a10 = LD32(a4 + 0x8);  /* 0281 */
  L_0283: a8 = (u32)&mesh_free + 0x0;  /* 0283: l32r -> global */
  a2 = mesh_free(a2, a3);  /* 0286: callx a8 via reloc-expand */
  a12 = 24;  /* 0289 */
  a11 = 0;  /* 028b */
  a10 = LD32(a1 + 0x40);  /* 028d */
  a8 = (u32)&memset + 0x0;  /* 0290: l32r -> global */
  a2 = memset(a2, a3);  /* 0293: callx a8 (libc, via reloc-expand) */
  L_0296: a2 = 0;  /* 0296 */
  return a2;  /* 0298: retw.n */
}


/* esp_mesh_check_nonassociated_children @ mesh_route.o 00000010 size 110B bind GLOBAL
 * Calls: esp_mesh_lookup_route, memset, mesh_update_route_table | Data refs: .bss.mesh_route_table
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=4); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_check_nonassociated_children(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 48 (frame 48 bytes) */
  a8 = -1;  /* 0013 */
  a12 = a1;  /* 0015 */
  a11 = a1 + (4);  /* 0017 */
  a10 = a2;  /* 001a: mov */
  ST8(a1 + 0x4, a8);  /* 001d */
  __asm__ volatile("" ::: "memory");  /* 0020: memw */
  __asm__ volatile("" ::: "memory");  /* 0023: memw */
  a8 = (u32)&esp_mesh_lookup_route;  /* 0026: l32r -> func addr */
  a2 = esp_mesh_lookup_route(a2, a3, a4, a5, a6, a7);  /* 0029: callx a8 via reloc-expand */
  a10 = LD16S(a1 + 0x2);  /* 002c */
  if (a10 == -1) goto L_007a;  /* 002f: beqi a10, -1, 7a <esp_mesh_check_nonassociated_children+0x6a> */
  L_0032: a10 = a10 + (a10 << 1);  /* 0032 */
  a12 = 6;  /* 0035 */
  a2 = LD8U(a1 + 0x0);  /* 0037 */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 003a: sext */
  a8 = a2 + (8);  /* 003d */
  a9 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 003f: l32r -> .bss.mesh_route_table (same-object static) */
  a8 = a8 + (a9 << 2);  /* 0042 */
  a11 = LD8U(a8 + 0x9);  /* 0045 */
  a11 = a11 << 8;  /* 0048 */
  a9 = LD8U(a8 + 0x8);  /* 004b */
  a11 = a11 | a9;  /* 004e */
  a9 = LD8U(a8 + 0xa);  /* 0051 */
  a9 = a9 << 16;  /* 0054 */
  a9 = a9 | a11;  /* 0057 */
  a11 = 0;  /* 005a */
  a8 = LD8U(a8 + 0xb);  /* 005c */
  a8 = a8 << 24;  /* 005f */
  a8 = a8 | a9;  /* 0062 */
  a10 = a10 + (a8 << 1);  /* 0065 */
  a8 = (u32)&memset + 0x0;  /* 0068: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 006b: callx a8 (libc, via reloc-expand) */
  a12 = 1;  /* 006e */
  a11 = 2;  /* 0070 */
  a10 = a2;  /* 0072 */
  a8 = (u32)&mesh_update_route_table;  /* 0074: l32r -> func addr */
  a2 = mesh_update_route_table(a2, a3, a4, a5, a6, a7);  /* 0077: callx a8 via reloc-expand */
  L_007a: a2 = 0;  /* 007a */
  return a2;  /* 007c: retw.n */
}


/* esp_mesh_combine_multi_redundant_ack @ mesh_route.o 00000048 size 608B bind GLOBAL
 * Calls: memcmp, mesh_free, memset, memcpy, mesh_malloc | indirect[8]: mem[a10+0x158]; mem[a6+0xb8]; mem[a1+0x54]; mem[a6+0x158] | Data refs: mesh_multi_recv_ack, .rodata.__func__$3, g_mesh_rt_capacity, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, .rodata.esp_mesh_combine_multi_redundant_ack.str1.1
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=12); reloc-direct=5, funcdb-attributed=0, unknown-indirect=8 */
u32 esp_mesh_combine_multi_redundant_ack(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0048: entry a1, 128 (frame 128 bytes) */
  a3 = (a3 >> 8) & 0x1;  /* 004b: extui width 1 */
  a8 = a7;  /* 004e */
  ST32(a1 + 0x44, a3);  /* 0050 */
  a7 = a5;  /* 0053 */
  a3 = (i32)(a4 << (32 - 7)) >> (32 - 7);  /* 0055: sext */
  a4 = a3 + (a3 << 1);  /* 0058 */
  a8 = (a8 >> 16) & 0x1;  /* 005b: extui width 1 */
  a5 = (u32)&mesh_multi_recv_ack + 0x0;  /* 005e: l32r -> global */
  a12 = 6;  /* 0061 */
  a4 = a4 + (a5 << 3);  /* 0063 */
  a11 = a7;  /* 0066: mov */
  a10 = a4;  /* 0069: mov */
  ST32(a1 + 0x4c, a6);  /* 006c */
  a6 = a3 + a3;  /* 006f */
  a2 = (a2 >> 8) & 0x1;  /* 0072: extui width 1 */
  ST32(a1 + 0x40, a8);  /* 0075 */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  a8 = (u32)&memcmp + 0x0;  /* 007b: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 007e: callx a8 (libc, via reloc-expand) */
  ST32(a1 + 0x48, a6);  /* 0081 */
  if (a10 == 0) goto L_012c;  /* 0084: beqz a10, 12c <esp_mesh_combine_multi_redundant_ack+0xe4> */
  L_0087: a12 = 0x593;  /* 0087 */
  a9 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 008a: l32r -> .rodata.__func__$3 */
  a11 = a9;  /* 008d */
  a10 = LD32(a4 + 0x8);  /* 008f */
  ST32(a1 + 0x54, a9);  /* 0091 */
  __asm__ volatile("" ::: "memory");  /* 0094: memw */
  a8 = (u32)&mesh_free + 0x0;  /* 0097: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 009a: callx a8 via reloc-expand */
  a12 = 24;  /* 009d */
  a11 = 0;  /* 009f */
  a10 = a4;  /* 00a1 */
  a8 = (u32)&memset + 0x0;  /* 00a3: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00a6: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 00a9 */
  a11 = a7;  /* 00ab */
  a10 = a4;  /* 00ad */
  a8 = (u32)&memcpy + 0x0;  /* 00af: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00b2: callx a8 (libc, via reloc-expand) */
  a5 = (u32)&g_mesh_rt_capacity + 0x0;  /* 00b5: l32r -> global */
  a12 = 0x599;  /* 00b8 */
  a10 = LD32(a5 + 0x0);  /* 00bb */
  a10 = a10 + (a10 << 1);  /* 00bd */
  a10 = a10 + a10;  /* 00c0 */
  a9 = LD32(a1 + 0x54);  /* 00c2 */
  a11 = a9;  /* 00c5: mov */
  a8 = (u32)&mesh_malloc + 0x0;  /* 00c8: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 00cb: callx a8 via reloc-expand */
  ST32(a4 + 0x8, a10);  /* 00ce */
  if (a10 != 0) goto L_012c;  /* 00d0: bnez a10, 12c <esp_mesh_combine_multi_redundant_ack+0xe4> */
  L_00d3: a6 = (u32)&g_log_level + 0x0;  /* 00d3: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 00d6 */
  if (a6 < 3u) goto L_012c;  /* 00d8: bltui a6, 3, 12c <esp_mesh_combine_multi_redundant_ack+0xe4> */
  L_00db: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 00db: l32r -> global */
  a10 = LD32(a6 + 0x0);  /* 00de */
  if (a10 == 0) goto L_012c;  /* 00e0: beqz a10, 12c <esp_mesh_combine_multi_redundant_ack+0xe4> */
  L_00e3: a9 = LD32(a10 + 0x150);  /* 00e3 */
  if (a9 == 0) goto L_012c;  /* 00e6: beqz a9, 12c <esp_mesh_combine_multi_redundant_ack+0xe4> */
  L_00e9: a10 = LD32(a10 + 0x158);  /* 00e9 */
  ST32(a1 + 0x54, a9);  /* 00ec */
  __asm__ volatile("" ::: "memory");  /* 00ef: memw */
  /* 00f2: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00f5 */
  a6 = LD32(a6 + 0x0);  /* 00f7 */
  a10 = LD32(a6 + 0xb8);  /* 00f9 */
  a5 = LD32(a5 + 0x0);  /* 00fc */
  a6 = a5 + (a5 << 1);  /* 00fe */
  a6 = a6 + a6;  /* 0101 */
  ST32(a1 + 0x50, a13);  /* 0104 */
  __asm__ volatile("" ::: "memory");  /* 0107: memw */
  /* 010a: INDIRECT callx a10 <- mem[a6+0xb8]; result unknown */ a2 = 0;
  a15 = 0x59b;  /* 010d */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0110: -> "mesh_route.c" */
  a14 = a11;  /* 0113 */
  a13 = LD32(a1 + 0x50);  /* 0115 */
  a12 = (u32)(RODATA__rodata_esp_mesh_combine_multi_redundant_ack_str1_1 + 0x0);  /* 0118: l32r -> .rodata.esp_mesh_combine_multi_redundant_ack.str1.1 */
  a9 = LD32(a1 + 0x54);  /* 011b */
  ST32(a1 + 0x8, a10);  /* 011e */
  a10 = 3;  /* 0120 */
  ST32(a1 + 0x4, a6);  /* 0122 */
  ST32(a1 + 0x0, a5);  /* 0124 */
  __asm__ volatile("" ::: "memory");  /* 0126: memw */
  /* 0129: INDIRECT callx a9 <- mem[a1+0x54]; result unknown */ a2 = 0;
  L_012c: a5 = 127;  /* 012c */
  a6 = (u32)&g_osi_funcs_p + 0x0;  /* 012f: l32r -> global */
  if (a2 != a5) goto L_0138;  /* 0132: bne a2, a5, 138 <esp_mesh_combine_multi_redundant_ack+0xf0> */
  L_0135: goto L_01ec;  /* 0135: j */
  L_0138: a9 = a3 + (a3 << 1);  /* 0138 */
  a8 = (u32)&mesh_multi_recv_ack + 0x0;  /* 013b: l32r -> global */
  a9 = a9 + (a8 << 3);  /* 013e */
  a5 = LD32(a9 + 0x4);  /* 0141 */
  a5 = (a5 >> 7) & 0x1ffff;  /* 0143: extui width 17 */
  a5 = a2 - a5;  /* 0146: sub */
  if ((i32)a5 >= 2) goto L_014f;  /* 0149: bgei a5, 2, 14f <esp_mesh_combine_multi_redundant_ack+0x107> */
  L_014c: goto L_01ec;  /* 014c: j */
  L_014f: a6 = LD32(a6 + 0x0);  /* 014f */
  if (a6 == 0) goto L_01bd;  /* 0151: beqz a6, 1bd <esp_mesh_combine_multi_redundant_ack+0x175> */
  L_0154: a5 = LD32(a6 + 0x150);  /* 0154 */
  if (a5 == 0) goto L_01bd;  /* 0157: beqz a5, 1bd <esp_mesh_combine_multi_redundant_ack+0x175> */
  L_015a: a10 = LD32(a6 + 0x158);  /* 015a */
  ST32(a1 + 0x54, a9);  /* 015d */
  __asm__ volatile("" ::: "memory");  /* 0160: memw */
  /* 0163: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0166 */
  a10 = 2;  /* 0168 */
  a9 = LD32(a1 + 0x54);  /* 016a */
  a6 = LD16U(a9 + 0xc);  /* 016d */
  ST32(a1 + 0x30, a6);  /* 0170 */
  a6 = LD32(a1 + 0x40);  /* 0172 */
  ST32(a1 + 0x2c, a6);  /* 0175 */
  a6 = LD8U(a7 + 0x5);  /* 0177 */
  ST32(a1 + 0x24, a6);  /* 017a */
  a6 = LD8U(a7 + 0x4);  /* 017c */
  ST32(a1 + 0x20, a6);  /* 017f */
  a6 = LD8U(a7 + 0x3);  /* 0181 */
  ST32(a1 + 0x1c, a6);  /* 0184 */
  a6 = LD8U(a7 + 0x2);  /* 0186 */
  ST32(a1 + 0x18, a6);  /* 0189 */
  a6 = LD8U(a7 + 0x1);  /* 018b */
  a8 = LD32(a1 + 0x44);  /* 018e */
  ST32(a1 + 0x14, a6);  /* 0191 */
  a6 = LD8U(a7 + 0x0);  /* 0193 */
  ST32(a1 + 0x28, a3);  /* 0196 */
  ST32(a1 + 0x10, a6);  /* 0198 */
  ST32(a1 + 0xc, a8);  /* 019a */
  ST32(a1 + 0x8, a2);  /* 019c */
  a2 = LD32(a9 + 0x4);  /* 019e */
  a2 = (a2 >> 7) & 0x1ffff;  /* 01a0: extui width 17 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01a3: -> "mesh_route.c" */
  a14 = a11;  /* 01a6 */
  ST32(a1 + 0x4, a2);  /* 01a8 */
  a2 = 0x5a2;  /* 01ab */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01ae: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_combine_multi_redundant_ack_str1_1 + 0x0);  /* 01b1: l32r -> .rodata.esp_mesh_combine_multi_redundant_ack.str1.1 */
  ST32(a1 + 0x0, a2);  /* 01b4 */
  __asm__ volatile("" ::: "memory");  /* 01b7: memw */
  /* 01ba: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_01bd: a3 = a3 + (a3 << 1);  /* 01bd */
  a2 = (u32)&mesh_multi_recv_ack + 0x0;  /* 01c0: l32r -> global */
  a3 = a3 + (a2 << 3);  /* 01c3 */
  a2 = LD32(a3 + 0x4);  /* 01c6 */
  a2 = (a2 >> 7) & 0x1ffff;  /* 01c8: extui width 17 */
  if (a2 == 0) goto L_02a4;  /* 01cb: beqz a2, 2a4 <esp_mesh_combine_multi_redundant_ack+0x25c> */
  L_01ce: a12 = 0x5ae;  /* 01ce */
  a10 = LD32(a3 + 0x8);  /* 01d1 */
  a11 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 01d3: l32r -> .rodata.__func__$3 */
  a8 = (u32)&mesh_free + 0x0;  /* 01d6: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 01d9: callx a8 via reloc-expand */
  a12 = 24;  /* 01dc */
  a11 = 0;  /* 01de */
  a10 = a4;  /* 01e0 */
  a8 = (u32)&memset + 0x0;  /* 01e2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01e5: callx a8 (libc, via reloc-expand) */
  goto L_02a4;  /* 01e8: j */
  L_01ec: a5 = LD32(a1 + 0x48);  /* 01ec */
  a4 = a5 + a3;  /* 01ef */
  a8 = (u32)&mesh_multi_recv_ack + 0x0;  /* 01f1: l32r -> global */
  a4 = a4 + (a8 << 3);  /* 01f4 */
  a5 = LD32(a1 + 0x44);  /* 01f7 */
  a9 = a5 << 7;  /* 01fa */
  a5 = (a2 >> 7) & 0x1;  /* 01fd: extui width 1 */
  a5 = a5 | a9;  /* 0200 */
  a8 = LD32(a1 + 0x40);  /* 0203 */
  a12 = a8 + (a8 << 1);  /* 0206 */
  a12 = a12 + a12;  /* 0209 */
  a10 = LD16U(a4 + 0xc);  /* 020b */
  a10 = a10 + (a10 << 1);  /* 020e */
  ST8(a4 + 0x6, a5);  /* 0211 */
  __asm__ volatile("" ::: "memory");  /* 0214: memw */
  a5 = LD32(a4 + 0x8);  /* 0217 */
  a10 = a10 + (a5 << 1);  /* 0219 */
  a11 = LD32(a1 + 0x4c);  /* 021c */
  __asm__ volatile("" ::: "memory");  /* 021f: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0222: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0225: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x40);  /* 0228 */
  a5 = LD16U(a4 + 0xc);  /* 022b */
  a5 = a8 + a5;  /* 022e */
  ST16(a4 + 0xc, a5);  /* 0230 */
  __asm__ volatile("" ::: "memory");  /* 0233: memw */
  a5 = LD32(a6 + 0x0);  /* 0236 */
  a10 = LD32(a5 + 0x110);  /* 0238 */
  __asm__ volatile("" ::: "memory");  /* 023b: memw */
  /* 023e: INDIRECT callx a10 <- mem[a5+0x110]; result unknown */ a2 = 0;
  a5 = (u32)&g_log_level + 0x0;  /* 0241: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 0244 */
  ST32(a4 + 0x10, a10);  /* 0246 */
  ST32(a4 + 0x14, a11);  /* 0248 */
  if (a5 < 3u) goto L_02a4;  /* 024a: bltui a5, 3, 2a4 <esp_mesh_combine_multi_redundant_ack+0x25c> */
  L_024d: a5 = LD32(a6 + 0x0);  /* 024d */
  if (a5 == 0) goto L_02a4;  /* 024f: beqz a5, 2a4 <esp_mesh_combine_multi_redundant_ack+0x25c> */
  L_0252: a6 = LD32(a5 + 0x150);  /* 0252 */
  if (a6 == 0) goto L_02a4;  /* 0255: beqz a6, 2a4 <esp_mesh_combine_multi_redundant_ack+0x25c> */
  L_0258: a10 = LD32(a5 + 0x158);  /* 0258 */
  __asm__ volatile("" ::: "memory");  /* 025b: memw */
  /* 025e: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0261 */
  a15 = a2;  /* 0263 */
  a4 = LD16U(a4 + 0xc);  /* 0265 */
  a10 = 3;  /* 0268 */
  ST32(a1 + 0x1c, a3);  /* 026a */
  a3 = LD8U(a7 + 0x5);  /* 026c */
  ST32(a1 + 0x18, a3);  /* 026f */
  a3 = LD8U(a7 + 0x4);  /* 0271 */
  ST32(a1 + 0x14, a3);  /* 0274 */
  a3 = LD8U(a7 + 0x3);  /* 0276 */
  ST32(a1 + 0x10, a3);  /* 0279 */
  a3 = LD8U(a7 + 0x2);  /* 027b */
  ST32(a1 + 0xc, a3);  /* 027e */
  a3 = LD8U(a7 + 0x1);  /* 0280 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0283: -> "mesh_route.c" */
  a14 = a11;  /* 0286 */
  a5 = LD32(a1 + 0x40);  /* 0288 */
  a8 = LD32(a1 + 0x44);  /* 028b */
  ST32(a1 + 0x8, a3);  /* 028e */
  a3 = LD8U(a7 + 0x0);  /* 0290 */
  a12 = (u32)(RODATA__rodata_esp_mesh_combine_multi_redundant_ack_str1_1 + 0x0);  /* 0293: l32r -> .rodata.esp_mesh_combine_multi_redundant_ack.str1.1 */
  ST32(a1 + 0x24, a4);  /* 0296 */
  ST32(a1 + 0x20, a5);  /* 0298 */
  ST32(a1 + 0x4, a3);  /* 029a */
  ST32(a1 + 0x0, a8);  /* 029c */
  __asm__ volatile("" ::: "memory");  /* 029e: memw */
  /* 02a1: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_02a4: a2 = 0;  /* 02a4 */
  return a2;  /* 02a6: retw.n */
}


/* esp_mesh_copy_mgmt_announce @ mesh_route.o 0000004c size 669B bind GLOBAL
 * Calls: memcpy, mesh_malloc, esp_mesh_tx_tid_flush | indirect[9]: mem[a3+0x158]; mem[a3+0x150]; unknown; mem[a7+0xb8] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, g_mesh_topology, g_mesh_rt_capacity, g_mesh_max_layer, .rodata.esp_mesh_copy_mgmt_announce.str1.1, .rodata.__func__$5
 * Fidelity: medium - 9 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=11); reloc-direct=3, funcdb-attributed=0, unknown-indirect=9 */
u32 esp_mesh_copy_mgmt_announce(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0;
  /* 004c: entry a1, 112 (frame 112 bytes) */
  if (a2 != 0) goto L_007e;  /* 004f: bnez.n a2, 7e <esp_mesh_copy_mgmt_announce+0x32> */
  L_0051: a2 = (u32)&g_log_level + 0x0;  /* 0051: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0054 */
  a2 = 0x00004008u;  /* 0057: l32r = 16392 */
  if (a3 >= 3u) goto L_0060;  /* 005a: bgeui a3, 3, 60 <esp_mesh_copy_mgmt_announce+0x14> */
  L_005d: goto L_02e4;  /* 005d: j */
  L_0060: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0060: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0063 */
  if (a3 == 0) goto L_02e4;  /* 0066: beqz a3, 2e4 <esp_mesh_copy_mgmt_announce+0x298> */
  L_0069: a4 = LD32(a3 + 0x150);  /* 0069 */
  if (a4 == 0) goto L_02e4;  /* 006c: beqz a4, 2e4 <esp_mesh_copy_mgmt_announce+0x298> */
  L_006f: a10 = LD32(a3 + 0x158);  /* 006f */
  a3 = 0x4b5;  /* 0072 */
  /* 0075: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0078: -> "mesh_route.c" */
  goto L_00a8;  /* 007b: j */
  L_007e: if (a3 != 0) goto L_00c1;  /* 007e: bnez.n a3, c1 <esp_mesh_copy_mgmt_announce+0x75> */
  L_0080: a2 = (u32)&g_log_level + 0x0;  /* 0080: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0083 */
  a2 = 0x00004008u;  /* 0085: l32r = 16392 */
  if (a3 >= 3u) goto L_008e;  /* 0088: bgeui a3, 3, 8e <esp_mesh_copy_mgmt_announce+0x42> */
  L_008b: goto L_02e4;  /* 008b: j */
  L_008e: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 008e: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0091 */
  if (a3 == 0) goto L_02e4;  /* 0093: beqz a3, 2e4 <esp_mesh_copy_mgmt_announce+0x298> */
  L_0096: a4 = LD32(a3 + 0x150);  /* 0096 */
  if (a4 == 0) goto L_02e4;  /* 0099: beqz a4, 2e4 <esp_mesh_copy_mgmt_announce+0x298> */
  L_009c: a10 = LD32(a3 + 0x158);  /* 009c */
  a3 = 0x4b6;  /* 009f */
  /* 00a2: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00a5: -> "mesh_route.c" */
  L_00a8: a13 = a10;  /* 00a8 */
  a14 = a11;  /* 00aa */
  a10 = 3;  /* 00ac */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00ae: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00b1: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 00b4 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  /* 00b9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_02e4;  /* 00bc: j */
  L_00c1: if (a4 != 0) goto L_00f0;  /* 00c1: bnez.n a4, f0 <esp_mesh_copy_mgmt_announce+0xa4> */
  L_00c3: a2 = (u32)&g_log_level + 0x0;  /* 00c3: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c6 */
  a2 = 0x00004008u;  /* 00c8: l32r = 16392 */
  if (a3 >= 3u) goto L_00d1;  /* 00cb: bgeui a3, 3, d1 <esp_mesh_copy_mgmt_announce+0x85> */
  L_00ce: goto L_02e4;  /* 00ce: j */
  L_00d1: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00d1: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d4 */
  if (a3 == 0) goto L_02e4;  /* 00d6: beqz a3, 2e4 <esp_mesh_copy_mgmt_announce+0x298> */
  L_00d9: a4 = LD32(a3 + 0x150);  /* 00d9 */
  if (a4 == 0) goto L_02e4;  /* 00dc: beqz a4, 2e4 <esp_mesh_copy_mgmt_announce+0x298> */
  L_00df: a10 = LD32(a3 + 0x158);  /* 00df */
  a3 = 0x4b7;  /* 00e2 */
  /* 00e5: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00e8: -> "mesh_route.c" */
  goto L_00a8;  /* 00eb: j */
  L_00f0: a5 = LD8U(a2 + 0x0);  /* 00f0 */
  a6 = a5 + (-3);  /* 00f3 */
  a6 = (a6 >> 8) & 0x1;  /* 00f6: extui width 1 */
  a2 = 0x00004008u;  /* 00f9: l32r = 16392 */
  if (a6 < 3u) goto L_0102;  /* 00fc: bltui a6, 3, 102 <esp_mesh_copy_mgmt_announce+0xb6> */
  L_00ff: goto L_02e4;  /* 00ff: j */
  L_0102: a2 = 0;  /* 0102 */
  a10 = a4 + (20);  /* 0104 */
  a7 = (u32)&g_mesh_topology + 0x0;  /* 0107: l32r -> global */
  ST8(a4 + 0x1, a2);  /* 010a */
  ST8(a4 + 0x2, a2);  /* 010d */
  a2 = (a5 >> 8) & 0x1ffffff;  /* 0110: extui width 25 */
  ST8(a4 + 0x3, a2);  /* 0113 */
  ST8(a4 + 0x0, a5);  /* 0116 */
  __asm__ volatile("" ::: "memory");  /* 0119: memw */
  a2 = LD32(a7 + 0x0);  /* 011c */
  if (a5 != 3) goto L_0144;  /* 011e: bnei a5, 3, 144 <esp_mesh_copy_mgmt_announce+0xf8> */
  L_0121: if (a2 != 0) goto L_0136;  /* 0121: bnez.n a2, 136 <esp_mesh_copy_mgmt_announce+0xea> */
  L_0123: a12 = 154;  /* 0123 */
  a11 = a3;  /* 0126 */
  __asm__ volatile("" ::: "memory");  /* 0128: memw */
  a8 = (u32)&memcpy + 0x0;  /* 012b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 012e: callx a8 (libc, via reloc-expand) */
  goto L_02e4;  /* 0131: j */
  L_0136: a12 = 12;  /* 0136 */
  a11 = a3;  /* 0138 */
  a8 = (u32)&memcpy + 0x0;  /* 013a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 013d: callx a8 (libc, via reloc-expand) */
  goto L_02e2;  /* 0140: j */
  L_0144: if (a2 != 0) goto L_0166;  /* 0144: bnez.n a2, 166 <esp_mesh_copy_mgmt_announce+0x11a> */
  L_0146: a12 = 153;  /* 0146 */
  a11 = a3;  /* 0149 */
  a8 = (u32)&memcpy + 0x0;  /* 014b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 014e: callx a8 (libc, via reloc-expand) */
  a5 = LD8U(a4 + 0xac);  /* 0151 */
  a5 = a5 << 8;  /* 0154 */
  a2 = LD8U(a4 + 0xab);  /* 0157 */
  a5 = a5 | a2;  /* 015a */
  a2 = 153;  /* 015d */
  a6 = LD8U(a4 + 0x14);  /* 0160 */
  goto L_018a;  /* 0163: j */
  L_0166: a12 = 10;  /* 0166 */
  a11 = a3;  /* 0168 */
  a8 = (u32)&memcpy + 0x0;  /* 016a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 016d: callx a8 (libc, via reloc-expand) */
  a5 = LD8U(a4 + 0x1d);  /* 0170 */
  a5 = a5 << 8;  /* 0173 */
  a2 = LD8U(a4 + 0x1c);  /* 0176 */
  a5 = a5 | a2;  /* 0179 */
  a6 = LD8U(a4 + 0x15);  /* 017c */
  a6 = a6 << 8;  /* 017f */
  a2 = LD8U(a4 + 0x14);  /* 0182 */
  a6 = a6 | a2;  /* 0185 */
  a2 = 10;  /* 0188 */
  L_018a: if (a5 == 0) goto L_0194;  /* 018a: beqz.n a5, 194 <esp_mesh_copy_mgmt_announce+0x148> */
  L_018c: a8 = (u32)&g_mesh_rt_capacity + 0x0;  /* 018c: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 018f */
  if ((i32)a8 >= (i32)a5) goto L_01f5;  /* 0191: bge a8, a5, 1f5 <esp_mesh_copy_mgmt_announce+0x1a9> */
  L_0194: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0194: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0197 */
  a2 = -1;  /* 0199 */
  if (a3 == 0) goto L_02e4;  /* 019b: beqz a3, 2e4 <esp_mesh_copy_mgmt_announce+0x298> */
  L_019e: a7 = LD32(a3 + 0x150);  /* 019e */
  if (a7 == 0) goto L_02e4;  /* 01a1: beqz a7, 2e4 <esp_mesh_copy_mgmt_announce+0x298> */
  L_01a4: a10 = LD32(a3 + 0x158);  /* 01a4 */
  /* 01a7: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01aa */
  a10 = 2;  /* 01ac */
  a3 = (u32)&g_mesh_max_layer + 0x0;  /* 01ae: l32r -> global */
  a3 = LD16U(a3 + 0x0);  /* 01b1 */
  ST32(a1 + 0x20, a6);  /* 01b4 */
  ST32(a1 + 0x24, a3);  /* 01b6 */
  a3 = LD8U(a4 + 0x13);  /* 01b8 */
  ST32(a1 + 0x1c, a3);  /* 01bb */
  a3 = LD8U(a4 + 0x12);  /* 01bd */
  ST32(a1 + 0x18, a3);  /* 01c0 */
  a3 = LD8U(a4 + 0x11);  /* 01c2 */
  ST32(a1 + 0x14, a3);  /* 01c5 */
  a3 = LD8U(a4 + 0x10);  /* 01c7 */
  ST32(a1 + 0x10, a3);  /* 01ca */
  a3 = LD8U(a4 + 0xf);  /* 01cc */
  ST32(a1 + 0xc, a3);  /* 01cf */
  a3 = LD8U(a4 + 0xe);  /* 01d1 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01d4: -> "mesh_route.c" */
  a14 = a11;  /* 01d7 */
  ST32(a1 + 0x8, a3);  /* 01d9 */
  a3 = 0x4dc;  /* 01db */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01de: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_copy_mgmt_announce_str1_1 + 0x0);  /* 01e1: l32r -> .rodata.esp_mesh_copy_mgmt_announce.str1.1 */
  ST32(a1 + 0x4, a5);  /* 01e4 */
  ST32(a1 + 0x0, a3);  /* 01e7 */
  __asm__ volatile("" ::: "memory");  /* 01ea: memw */
  /* 01ed: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  goto L_02e4;  /* 01f0: j */
  L_01f5: a5 = a5 + (a5 << 1);  /* 01f5 */
  a5 = a5 + a5;  /* 01f8 */
  a11 = (u32)(RODATA__rodata___func___5 + 0x0);  /* 01fa: -> "esp_mesh_copy_mgmt_announce" */
  a12 = 0x4e4;  /* 01fd */
  a10 = a5;  /* 0200: mov */
  a8 = (u32)&mesh_malloc + 0x0;  /* 0203: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0206: callx a8 via reloc-expand */
  if (a10 != 0) goto L_029c;  /* 0209: bnez a10, 29c <esp_mesh_copy_mgmt_announce+0x250> */
  L_020c: a7 = (u32)&g_osi_funcs_p + 0x0;  /* 020c: l32r -> global */
  a3 = LD32(a7 + 0x0);  /* 020f */
  if (a3 == 0) goto L_0290;  /* 0212: beqz a3, 290 <esp_mesh_copy_mgmt_announce+0x244> */
  L_0215: a2 = LD32(a3 + 0x150);  /* 0215 */
  if (a2 == 0) goto L_0290;  /* 0218: beqz a2, 290 <esp_mesh_copy_mgmt_announce+0x244> */
  L_021b: a10 = LD32(a3 + 0x158);  /* 021b */
  /* 021e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 0221 */
  a10 = (u32)&g_mesh_max_layer + 0x0;  /* 0223: l32r -> global */
  a7 = LD32(a7 + 0x0);  /* 0226 */
  a8 = LD8U(a4 + 0xe);  /* 0228 */
  a9 = LD8U(a4 + 0xf);  /* 022b */
  a12 = LD8U(a4 + 0x10);  /* 022e */
  a13 = LD8U(a4 + 0x11);  /* 0231 */
  a14 = LD8U(a4 + 0x12);  /* 0234 */
  a15 = LD16U(a10 + 0x0);  /* 0237 */
  a10 = LD32(a7 + 0xb8);  /* 023a */
  a4 = LD8U(a4 + 0x13);  /* 023d */
  ST32(a1 + 0x30, a8);  /* 0240 */
  ST32(a1 + 0x34, a9);  /* 0242 */
  ST32(a1 + 0x38, a12);  /* 0244 */
  ST32(a1 + 0x3c, a13);  /* 0246 */
  ST32(a1 + 0x40, a14);  /* 0248 */
  ST32(a1 + 0x44, a15);  /* 024b */
  __asm__ volatile("" ::: "memory");  /* 024e: memw */
  /* 0251: INDIRECT callx a10 <- mem[a7+0xb8]; result unknown */ a2 = 0;
  a15 = LD32(a1 + 0x44);  /* 0254 */
  a12 = LD32(a1 + 0x38);  /* 0257 */
  a14 = LD32(a1 + 0x40);  /* 0259 */
  a13 = LD32(a1 + 0x3c);  /* 025c */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 025e: -> "mesh_route.c" */
  a9 = LD32(a1 + 0x34);  /* 0261 */
  a8 = LD32(a1 + 0x30);  /* 0263 */
  ST32(a1 + 0x20, a15);  /* 0265 */
  ST32(a1 + 0x18, a4);  /* 0267 */
  a4 = 0x4e6;  /* 0269 */
  ST32(a1 + 0xc, a12);  /* 026c */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 026e: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_copy_mgmt_announce_str1_1 + 0x0);  /* 0271: l32r -> .rodata.esp_mesh_copy_mgmt_announce.str1.1 */
  ST32(a1 + 0x28, a10);  /* 0274 */
  a10 = 2;  /* 0276 */
  ST32(a1 + 0x14, a14);  /* 0278 */
  a14 = a11;  /* 027a */
  ST32(a1 + 0x10, a13);  /* 027c */
  a13 = a3;  /* 027e */
  ST32(a1 + 0x24, a5);  /* 0280 */
  ST32(a1 + 0x1c, a6);  /* 0282 */
  ST32(a1 + 0x8, a9);  /* 0284 */
  ST32(a1 + 0x4, a8);  /* 0286 */
  ST32(a1 + 0x0, a4);  /* 0288 */
  __asm__ volatile("" ::: "memory");  /* 028a: memw */
  /* 028d: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  L_0290: a8 = (u32)&esp_mesh_tx_tid_flush + 0x0;  /* 0290: l32r -> global */
  a2 = esp_mesh_tx_tid_flush(a2, a3, a4, a5, a6, a7);  /* 0293: callx a8 via reloc-expand */
  a2 = -1;  /* 0296 */
  goto L_02e4;  /* 0298: j */
  L_029c: a11 = a3 + a2;  /* 029c */
  a12 = a5;  /* 029e */
  a8 = (u32)&memcpy + 0x0;  /* 02a0: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 02a3: callx a8 (libc, via reloc-expand) */
  a2 = LD32(a7 + 0x0);  /* 02a6 */
  a9 = (a10 >> 8) & 0x1;  /* 02a8: extui width 1 */
  a7 = a10 >> 8;  /* 02ab */
  a6 = (a10 >> 16) & 0x1ffff;  /* 02ae: extui width 17 */
  a8 = (a10 >> 8) & 0x1ffffff;  /* 02b1: extui width 25 */
  if (a2 != 0) goto L_02d0;  /* 02b4: bnez.n a2, 2d0 <esp_mesh_copy_mgmt_announce+0x284> */
  L_02b6: a5 = 173;  /* 02b6 */
  a4 = a4 + a5;  /* 02b9 */
  ST8(a4 + 0x0, a9);  /* 02bb */
  ST8(a4 + 0x1, a7);  /* 02be */
  ST8(a4 + 0x2, a6);  /* 02c1 */
  ST8(a4 + 0x3, a8);  /* 02c4 */
  __asm__ volatile("" ::: "memory");  /* 02c7: memw */
  __asm__ volatile("" ::: "memory");  /* 02ca: memw */
  goto L_02e4;  /* 02cd: j */
  L_02d0: a3 = a4 + (30);  /* 02d0 */
  ST8(a4 + 0x1e, a9);  /* 02d3 */
  ST8(a4 + 0x1f, a7);  /* 02d6 */
  ST8(a4 + 0x20, a6);  /* 02d9 */
  ST8(a4 + 0x21, a8);  /* 02dc */
  __asm__ volatile("" ::: "memory");  /* 02df: memw */
  L_02e2: a2 = 0;  /* 02e2 */
  L_02e4: __asm__ volatile("" ::: "memory");  /* 02e4: memw */
  return a2;  /* 02e7: retw.n */
}


/* esp_mesh_delete_sub_children @ mesh_route.o 0000000c size 92B bind GLOBAL
 * Calls: memset, mesh_update_route_table | Data refs: .bss.mesh_route_table
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_delete_sub_children(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 000f: sext */
  a8 = (a3 >> 8) & 0x1;  /* 0012: extui width 1 */
  if (a2 == -1) goto L_0064;  /* 0015: beqi a2, -1, 64 <esp_mesh_delete_sub_children+0x58> */
  L_0018: a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 0018: sext */
  a12 = 0;  /* 001b */
  a11 = 1;  /* 001d */
  if (a8 == -1) goto L_005c;  /* 001f: beqi a8, -1, 5c <esp_mesh_delete_sub_children+0x50> */
  L_0022: a10 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0022: l32r -> .bss.mesh_route_table (same-object static) */
  a9 = a2 + (8);  /* 0025 */
  a9 = a9 + (a10 << 2);  /* 0027 */
  a8 = a8 + (a8 << 1);  /* 002a */
  a12 = 6;  /* 002d */
  a11 = LD8U(a9 + 0x9);  /* 002f */
  a11 = a11 << 8;  /* 0032 */
  a10 = LD8U(a9 + 0x8);  /* 0035 */
  a11 = a11 | a10;  /* 0038 */
  a10 = LD8U(a9 + 0xa);  /* 003b */
  a10 = a10 << 16;  /* 003e */
  a10 = a10 | a11;  /* 0041 */
  a11 = 0;  /* 0044 */
  a9 = LD8U(a9 + 0xb);  /* 0046 */
  a9 = a9 << 24;  /* 0049 */
  a10 = a9 | a10;  /* 004c */
  a10 = a8 + (a10 << 1);  /* 004f */
  a8 = (u32)&memset + 0x0;  /* 0052: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0055: callx a8 (libc, via reloc-expand) */
  a12 = 1;  /* 0058 */
  a11 = 2;  /* 005a */
  L_005c: a10 = a2;  /* 005c */
  a8 = (u32)&mesh_update_route_table;  /* 005e: l32r -> func addr */
  a2 = mesh_update_route_table(a2, a3, a4, a5, a6, a7);  /* 0061: callx a8 via reloc-expand */
  L_0064: a2 = 0;  /* 0064 */
  return a2;  /* 0066: retw.n */
}


/* esp_mesh_get_routing_table @ mesh_route.o 00000050 size 346B bind GLOBAL
 * Calls: esp_mesh_get_routing_table_size, memcpy, mesh_mutex_lock, mesh_mutex_unlock | indirect[4]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x158]; mem[a2+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, .rodata.esp_mesh_get_routing_table.str1.1, g_mesh_self_sta_addr, mesh_conn_mutex, .rodata.__func__$0, g_mesh_conn, .bss.mesh_route_table
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=14); reloc-direct=4, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_get_routing_table(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0050: entry a1, 48 (frame 48 bytes) */
  a5 = (u32)&g_is_mesh_started + 0x0;  /* 0053: l32r -> global */
  a5 = LD8U(a5 + 0x0);  /* 0056 */
  if (a5 != 0) goto L_008f;  /* 0059: bnez.n a5, 8f <esp_mesh_get_routing_table+0x3f> */
  L_005b: a2 = (u32)&g_log_level + 0x0;  /* 005b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005e */
  a2 = 0x00004004u;  /* 0060: l32r = 16388 */
  if (a3 >= 3u) goto L_0069;  /* 0063: bgeui a3, 3, 69 <esp_mesh_get_routing_table+0x19> */
  L_0066: goto L_01a5;  /* 0066: j */
  L_0069: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0069: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006c */
  if (a3 == 0) goto L_01a5;  /* 006e: beqz a3, 1a5 <esp_mesh_get_routing_table+0x155> */
  L_0071: a4 = LD32(a3 + 0x150);  /* 0071 */
  if (a4 == 0) goto L_01a5;  /* 0074: beqz a4, 1a5 <esp_mesh_get_routing_table+0x155> */
  L_0077: a10 = LD32(a3 + 0x158);  /* 0077 */
  /* 007a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 007d */
  a10 = 3;  /* 007f */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0081: -> "mesh_route.c" */
  a14 = a11;  /* 0084 */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_routing_table_str1_1 + 0x0);  /* 0086: l32r -> .rodata.esp_mesh_get_routing_table.str1.1 */
  /* 0089: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01a5;  /* 008c: j */
  L_008f: if (a2 != 0) goto L_00d1;  /* 008f: bnez.n a2, d1 <esp_mesh_get_routing_table+0x81> */
  L_0091: a2 = (u32)&g_log_level + 0x0;  /* 0091: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0094 */
  if (a2 >= 3u) goto L_009c;  /* 0096: bgeui a2, 3, 9c <esp_mesh_get_routing_table+0x4c> */
  L_0099: goto L_00c8;  /* 0099: j */
  L_009c: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 009c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 009f */
  if (a2 == 0) goto L_00c8;  /* 00a1: beqz.n a2, c8 <esp_mesh_get_routing_table+0x78> */
  L_00a3: a3 = LD32(a2 + 0x150);  /* 00a3 */
  if (a3 == 0) goto L_00c8;  /* 00a6: beqz.n a3, c8 <esp_mesh_get_routing_table+0x78> */
  L_00a8: a10 = LD32(a2 + 0x158);  /* 00a8 */
  a2 = 0x6dc;  /* 00ab */
  /* 00ae: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00b1 */
  a10 = 3;  /* 00b3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00b5: -> "mesh_route.c" */
  a14 = a11;  /* 00b8 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00ba: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00bd: -> "mesh_route.c" */
  ST32(a1 + 0x0, a2);  /* 00c0 */
  __asm__ volatile("" ::: "memory");  /* 00c2: memw */
  /* 00c5: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_00c8: a2 = 0x00004008u;  /* 00c8: l32r = 16392 */
  goto L_01a5;  /* 00cb: j */
  L_00d1: a8 = (u32)&esp_mesh_get_routing_table_size;  /* 00d1: l32r -> func addr */
  a2 = esp_mesh_get_routing_table_size(a2, a3, a4, a5, a6, a7);  /* 00d4: callx a8 via reloc-expand */
  a10 = a10 + (a10 << 1);  /* 00d7 */
  a10 = a10 + a10;  /* 00da */
  if (a3 < a10) goto L_00c8;  /* 00dc: bltu a3, a10, c8 <esp_mesh_get_routing_table+0x78> */
  L_00df: a11 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 00df: l32r -> global */
  a12 = 6;  /* 00e2 */
  a10 = a2;  /* 00e5: mov */
  a8 = (u32)&memcpy + 0x0;  /* 00e8: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00eb: callx a8 (libc, via reloc-expand) */
  a6 = 0;  /* 00ee */
  a3 = (u32)&mesh_conn_mutex + 0x0;  /* 00f0: l32r -> global */
  a12 = 0x6e9;  /* 00f3 */
  a2 = a2 + (6);  /* 00f6 */
  a5 = a6;  /* 00f8 */
  a7 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 00fa: l32r -> .rodata.__func__$0 */
  a11 = a7;  /* 00fd */
  a10 = LD32(a3 + 0x0);  /* 00ff */
  a3 = a6;  /* 0101 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 0103: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 0106: callx a8 via reloc-expand */
  L_0109: a11 = a6 << 6;  /* 0109 */
  a8 = (u32)&g_mesh_conn + 0x0;  /* 010c: l32r -> global */
  a11 = a8 + a11;  /* 010f */
  a8 = LD32(a11 + 0x4);  /* 0111 */
  if (((a8 >> 16) & 1) == 0) goto L_0182;  /* 0113: bbci a8, 16, 182 <esp_mesh_get_routing_table+0x132> */
  L_0116: a12 = 6;  /* 0116 */
  a10 = a2;  /* 0118 */
  a8 = (u32)&memcpy + 0x0;  /* 011a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 011d: callx a8 (libc, via reloc-expand) */
  a10 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0120: l32r -> .bss.mesh_route_table (same-object static) */
  a13 = a2 + (6);  /* 0123 */
  a2 = a6 + (a10 << 1);  /* 0125 */
  a5 = a5 + (1);  /* 0128 */
  a5 = (a5 >> 8) & 0x1;  /* 012a: extui width 1 */
  a12 = LD8U(a2 + 0x1);  /* 012d */
  a12 = a12 << 8;  /* 0130 */
  a8 = LD8U(a2 + 0x0);  /* 0133 */
  a12 = a12 | a8;  /* 0136 */
  a8 = a6 + (8);  /* 0139 */
  a8 = a8 + (a10 << 2);  /* 013b */
  a11 = LD8U(a8 + 0x9);  /* 013e */
  a12 = a12 + (a12 << 1);  /* 0141 */
  a11 = a11 << 8;  /* 0144 */
  a12 = a12 + a12;  /* 0147 */
  a10 = LD8U(a8 + 0x8);  /* 0149 */
  a11 = a11 | a10;  /* 014c */
  a10 = LD8U(a8 + 0xa);  /* 014f */
  a10 = a10 << 16;  /* 0152 */
  a10 = a10 | a11;  /* 0155 */
  a11 = LD8U(a8 + 0xb);  /* 0158 */
  a11 = a11 << 24;  /* 015b */
  a11 = a11 | a10;  /* 015e */
  a10 = a13;  /* 0161 */
  a8 = (u32)&memcpy + 0x0;  /* 0163: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0166: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a2 + 0x1);  /* 0169 */
  a13 = a10;  /* 016c */
  a8 = a8 << 8;  /* 016e */
  a10 = LD8U(a2 + 0x0);  /* 0171 */
  a8 = a8 | a10;  /* 0174 */
  a2 = a8 + (a8 << 1);  /* 0177 */
  a8 = a8 + a3;  /* 017a */
  a2 = a2 + (a13 << 1);  /* 017c */
  a3 = (a8 >> 16) & 0x1;  /* 017f: extui width 1 */
  L_0182: a6 = a6 + (1);  /* 0182 */
  if (a6 != 10) goto L_0109;  /* 0184: bnei a6, 10, 109 <esp_mesh_get_routing_table+0xb9> */
  L_0187: a2 = (u32)&mesh_conn_mutex + 0x0;  /* 0187: l32r -> global */
  a12 = 0x6f7;  /* 018a */
  a11 = a7;  /* 018d */
  a10 = LD32(a2 + 0x0);  /* 018f */
  a2 = 0;  /* 0191 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0193: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 0196: callx a8 via reloc-expand */
  if (a4 == a2) goto L_01a5;  /* 0199: beq a4, a2, 1a5 <esp_mesh_get_routing_table+0x155> */
  L_019c: a3 = a3 + a5;  /* 019c */
  a3 = (a3 >> 16) & 0x1;  /* 019e: extui width 1 */
  a3 = a3 + (1);  /* 01a1 */
  ST32(a4 + 0x0, a3);  /* 01a3 */
  L_01a5: __asm__ volatile("" ::: "memory");  /* 01a5: memw */
  return a2;  /* 01a8: retw.n */
}


/* esp_mesh_get_routing_table_size @ mesh_route.o 00000008 size 24B bind GLOBAL
 * Calls: esp_mesh_get_total_children_num | Data refs: g_is_mesh_started
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_routing_table_size(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 000b: l32r -> global */
  a8 = LD8U(a2 + 0x0);  /* 000e */
  a2 = 0;  /* 0011 */
  if (a8 == a2) goto L_001e;  /* 0013: beq a8, a2, 1e <esp_mesh_get_routing_table_size+0x16> */
  L_0016: a8 = (u32)&esp_mesh_get_total_children_num;  /* 0016: l32r -> func addr */
  a2 = esp_mesh_get_total_children_num(a2, a3, a4, a5, a6, a7);  /* 0019: callx a8 via reloc-expand */
  a2 = a10 + (1);  /* 001c */
  L_001e: return a2;  /* 001e: retw.n */
}


/* esp_mesh_get_sub_capacity @ mesh_route.o 00000000 size 82B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_sub_capacity(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0000: entry a1, 32 (frame 32 bytes) */
  a8 = (a2 >> 16) & 0x1;  /* 0003: extui width 1 */
  a11 = 0;  /* 0006 */
  a3 = (a3 >> 16) & 0x1;  /* 0008: extui width 1 */
  a10 = 1;  /* 000b */
  a9 = a11;  /* 000d */
  a12 = a8 - a3;  /* 000f: sub */
  if (a8 == 0) a9 = a10;  /* 0012 */
  if (a12 == 0) a11 = a10;  /* 0015 */
  a9 = a9 | a11;  /* 0018 */
  a2 = (a4 >> 8) & 0x1;  /* 001b: extui width 1 */
  if (a9 != 0) goto L_004e;  /* 001e: bnez.n a9, 4e <esp_mesh_get_sub_capacity+0x4e> */
  L_0020: if (a2 == 0) a9 = a10;  /* 0020 */
  if (a9 != 0) goto L_004e;  /* 0023: bnez.n a9, 4e <esp_mesh_get_sub_capacity+0x4e> */
  L_0025: a11 = 6;  /* 0025 */
  a8 = (a8 < a11) ? a8 : a11;  /* 0027: minu */
  a8 = a8 - a3;  /* 002a: sub */
  a8 = a8 + (-1);  /* 002d */
  a8 = (i32)(a8 << (32 - 15)) >> (32 - 15);  /* 002f: sext */
  if ((i32)a8 < (i32)a10) goto L_0050;  /* 0032: blt a8, a10, 50 <esp_mesh_get_sub_capacity+0x50> */
  L_0035: a8 = a8 + (-1);  /* 0035 */
  a8 = (a8 >> 16) & 0x1;  /* 0037: extui width 1 */
  a8 = a8 + a10;  /* 003a */
  /* 003d: loop (hardware loop over a8, 45 <esp_mesh_get_sub_capacity+0x45>..0045) */ goto L_0045;
  a10 = a10 * a2;  /* 0040 */
  a9 = a9 + a10;  /* 0043 */
  a2 = 0x3e8;  /* 0045 */
  a2 = (a9 < a2) ? a9 : a2;  /* 0048: minu */
  goto L_0050;  /* 004b: j */
  L_004e: a2 = 0;  /* 004e */
  L_0050: return a2;  /* 0050: retw.n */
}


/* esp_mesh_get_total_children_num @ mesh_route.o 00000018 size 98B bind GLOBAL
 * Calls: mesh_mutex_lock, mesh_mutex_unlock | Data refs: mesh_conn_mutex, .rodata.__func__$9, g_mesh_conn, .bss.mesh_route_table
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=6); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_total_children_num(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8, a9;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&mesh_conn_mutex + 0x0;  /* 001b: l32r -> global */
  a12 = 134;  /* 001e */
  a5 = (u32)(RODATA__rodata___func___9 + 0x0);  /* 0021: -> "esp_mesh_get_total_children_num" */
  a11 = a5;  /* 0024 */
  a10 = LD32(a3 + 0x0);  /* 0026 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 0028: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 002b: callx a8 via reloc-expand */
  a9 = 0;  /* 002e */
  a4 = a9;  /* 0030 */
  a11 = (u32)&g_mesh_conn + 0x0;  /* 0032: l32r -> global */
  a2 = a9;  /* 0035: mov */
  a10 = 10;  /* 0038 */
  a12 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 003b: l32r -> .bss.mesh_route_table (same-object static) */
  /* 003e: loop (hardware loop over a10, 66 <esp_mesh_get_total_children_num+0x4e>..0066) */ goto L_0066;
  a8 = a9 << 6;  /* 0041 */
  a8 = a11 + a8;  /* 0044 */
  a8 = LD32(a8 + 0x4);  /* 0046 */
  if (((a8 >> 16) & 1) == 0) goto L_0064;  /* 0048: bbci a8, 16, 64 <esp_mesh_get_total_children_num+0x4c> */
  L_004b: a8 = a9 + (a12 << 1);  /* 004b */
  a4 = a4 + (1);  /* 004e */
  a13 = LD8U(a8 + 0x0);  /* 0050 */
  a4 = (a4 >> 8) & 0x1;  /* 0053: extui width 1 */
  a8 = LD8U(a8 + 0x1);  /* 0056 */
  a8 = a8 << 8;  /* 0059 */
  a8 = a8 | a13;  /* 005c */
  a8 = a2 + a8;  /* 005f */
  a2 = (a8 >> 16) & 0x1;  /* 0061: extui width 1 */
  L_0064: a9 = a9 + (1);  /* 0064 */
  a10 = LD32(a3 + 0x0);  /* 0066 */
  a12 = 142;  /* 0068 */
  a11 = a5;  /* 006b */
  a2 = a2 + a4;  /* 006d */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 006f: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 0072: callx a8 via reloc-expand */
  a2 = (a2 >> 16) & 0x1;  /* 0075: extui width 1 */
  return a2;  /* 0078: retw.n */
}


/* esp_mesh_ie_update_capacity @ mesh_route.o 00000028 size 342B bind GLOBAL
 * Calls: memset, esp_mesh_get_total_children_num, esp_mesh_send_event_internal, mesh_rt_change_timer_start, esp_mesh_is_roots_found, esp_wifi_vnd_mesh_set | Data refs: g_mesh_is_root, g_mesh_topology, g_mesh_ie
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=6, refs=9); reloc-direct=6, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_ie_update_capacity(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0028: entry a1, 96 (frame 96 bytes) */
  a12 = 56;  /* 002b */
  a11 = 0;  /* 002d */
  a10 = a1;  /* 0030 */
  a8 = (u32)&memset + 0x0;  /* 0032: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0035: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_get_total_children_num;  /* 0038: l32r -> func addr */
  a2 = esp_mesh_get_total_children_num(a2, a3, a4, a5, a6, a7);  /* 003b: callx a8 via reloc-expand */
  a9 = LD8U(a2 + 0x17);  /* 003e */
  a5 = 0;  /* 0041 */
  a9 = a9 << 8;  /* 0043 */
  a4 = LD8U(a2 + 0x16);  /* 0046 */
  a9 = a9 | a4;  /* 0049 */
  a8 = a9 + (-1);  /* 004c */
  a4 = a10 + (1);  /* 004e */
  a6 = (u32)&g_mesh_is_root + 0x0;  /* 0050: l32r -> global */
  if (a10 == a8) goto L_00a8;  /* 0053: beq a10, a8, a8 <esp_mesh_ie_update_capacity+0x80> */
  L_0056: a5 = (a10 >> 16) & 0x1;  /* 0056: extui width 1 */
  if ((i32)a8 >= (i32)a10) goto L_0069;  /* 0059: bge a8, a10, 69 <esp_mesh_ie_update_capacity+0x41> */
  L_005c: a5 = a5 - a9;  /* 005c: sub */
  a5 = a5 + (1);  /* 005f */
  a8 = (a5 >> 16) & 0x1;  /* 0061: extui width 1 */
  a10 = 5;  /* 0064 */
  goto L_0071;  /* 0066: j */
  L_0069: a8 = a8 - a5;  /* 0069: sub */
  a8 = (a8 >> 16) & 0x1;  /* 006c: extui width 1 */
  a10 = 6;  /* 006f */
  L_0071: a12 = 4;  /* 0071 */
  a11 = a1 + a12;  /* 0073 */
  ST32(a1 + 0x0, a10);  /* 0075 */
  ST16(a1 + 0x6, a8);  /* 0077 */
  ST16(a1 + 0x4, a4);  /* 007a */
  __asm__ volatile("" ::: "memory");  /* 007d: memw */
  __asm__ volatile("" ::: "memory");  /* 0080: memw */
  a8 = (u32)&esp_mesh_send_event_internal + 0x0;  /* 0083: l32r -> global */
  a2 = esp_mesh_send_event_internal(a2, a3, a4, a5, a6, a7);  /* 0086: callx a8 via reloc-expand */
  __asm__ volatile("" ::: "memory");  /* 0089: memw */
  a5 = LD8U(a6 + 0x0);  /* 008c */
  a5 = (a5 >> 8) & 0x1;  /* 008f: extui width 1 */
  if (a5 == 0) goto L_009d;  /* 0092: beqz.n a5, 9d <esp_mesh_ie_update_capacity+0x75> */
  L_0094: a8 = (u32)&mesh_rt_change_timer_start;  /* 0094: l32r -> func addr */
  a2 = mesh_rt_change_timer_start(a2, a3, a4, a5, a6, a7);  /* 0097: callx a8 via reloc-expand */
  goto L_00a6;  /* 009a: j */
  L_009d: a8 = (u32)&esp_mesh_is_roots_found + 0x0;  /* 009d: l32r -> global */
  a2 = esp_mesh_is_roots_found(a2, a3, a4, a5, a6, a7);  /* 00a0: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0094;  /* 00a3: bnez a10, 94 <esp_mesh_ie_update_capacity+0x6c> */
  L_00a6: a5 = 1;  /* 00a6 */
  L_00a8: a8 = (u32)&g_mesh_topology + 0x0;  /* 00a8: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 00ab */
  if (a8 != 0) goto L_00b5;  /* 00ad: bnez.n a8, b5 <esp_mesh_ie_update_capacity+0x8d> */
  L_00af: a3 = LD8U(a2 + 0xf);  /* 00af */
  goto L_00b8;  /* 00b2: j */
  L_00b5: a3 = LD16U(a3 + 0x2);  /* 00b5 */
  L_00b8: __asm__ volatile("" ::: "memory");  /* 00b8: memw */
  a11 = LD8U(a6 + 0x0);  /* 00bb */
  a11 = (a11 >> 8) & 0x1;  /* 00be: extui width 1 */
  if (a11 == 0) goto L_010c;  /* 00c1: beqz a11, 10c <esp_mesh_ie_update_capacity+0xe4> */
  L_00c4: a3 = LD8U(a2 + 0x15);  /* 00c4 */
  a3 = a3 << 8;  /* 00c7 */
  a6 = LD8U(a2 + 0x14);  /* 00ca */
  a3 = a3 | a6;  /* 00cd */
  if (a3 != a4) goto L_00e5;  /* 00d0: bne a3, a4, e5 <esp_mesh_ie_update_capacity+0xbd> */
  L_00d3: a3 = LD8U(a2 + 0x16);  /* 00d3 */
  a2 = LD8U(a2 + 0x17);  /* 00d6 */
  a2 = a2 << 8;  /* 00d9 */
  a2 = a2 | a3;  /* 00dc */
  if (a2 != a4) goto L_00e5;  /* 00df: bne a2, a4, e5 <esp_mesh_ie_update_capacity+0xbd> */
  L_00e2: goto L_0174;  /* 00e2: j */
  L_00e5: a10 = (u32)&g_mesh_ie + 0x0;  /* 00e5: l32r -> global */
  a2 = (a4 >> 8) & 0x1;  /* 00e8: extui width 1 */
  a11 = 0;  /* 00eb */
  a4 = (a4 >> 8) & 0x1ff;  /* 00ed: extui width 9 */
  ST8(a10 + 0x14, a2);  /* 00f0 */
  ST8(a10 + 0x15, a4);  /* 00f3 */
  ST8(a10 + 0x16, a2);  /* 00f6 */
  ST8(a10 + 0x17, a4);  /* 00f9 */
  ST8(a10 + 0x18, a11);  /* 00fc */
  ST8(a10 + 0x19, a11);  /* 00ff */
  __asm__ volatile("" ::: "memory");  /* 0102: memw */
  __asm__ volatile("" ::: "memory");  /* 0105: memw */
  goto L_016b;  /* 0108: j */
  L_010c: if (a3 != 2) goto L_014d;  /* 010c: bnei a3, 2, 14d <esp_mesh_ie_update_capacity+0x125> */
  L_010f: a3 = LD8U(a2 + 0x19);  /* 010f */
  a3 = a3 << 8;  /* 0112 */
  a6 = LD8U(a2 + 0x18);  /* 0115 */
  a3 = a3 | a6;  /* 0118 */
  if (a3 != a4) goto L_012d;  /* 011b: bne a3, a4, 12d <esp_mesh_ie_update_capacity+0x105> */
  L_011e: a3 = LD8U(a2 + 0x16);  /* 011e */
  a2 = LD8U(a2 + 0x17);  /* 0121 */
  a2 = a2 << 8;  /* 0124 */
  a2 = a2 | a3;  /* 0127 */
  if (a2 == a4) goto L_0174;  /* 012a: beq a2, a4, 174 <esp_mesh_ie_update_capacity+0x14c> */
  L_012d: a10 = (u32)&g_mesh_ie + 0x0;  /* 012d: l32r -> global */
  a2 = (a4 >> 8) & 0x1;  /* 0130: extui width 1 */
  a4 = (a4 >> 8) & 0x1ff;  /* 0133: extui width 9 */
  a11 = 0;  /* 0136 */
  ST8(a10 + 0x18, a2);  /* 0138 */
  ST8(a10 + 0x19, a4);  /* 013b */
  ST8(a10 + 0x16, a2);  /* 013e */
  ST8(a10 + 0x17, a4);  /* 0141 */
  __asm__ volatile("" ::: "memory");  /* 0144: memw */
  __asm__ volatile("" ::: "memory");  /* 0147: memw */
  goto L_016b;  /* 014a: j */
  L_014d: a3 = LD8U(a2 + 0x16);  /* 014d */
  a2 = LD8U(a2 + 0x17);  /* 0150 */
  a2 = a2 << 8;  /* 0153 */
  a2 = a2 | a3;  /* 0156 */
  if (a2 == a4) goto L_0174;  /* 0159: beq a2, a4, 174 <esp_mesh_ie_update_capacity+0x14c> */
  L_015c: a10 = (u32)&g_mesh_ie + 0x0;  /* 015c: l32r -> global */
  ST8(a10 + 0x16, a4);  /* 015f */
  a4 = (a4 >> 8) & 0x1ff;  /* 0162: extui width 9 */
  ST8(a10 + 0x17, a4);  /* 0165 */
  __asm__ volatile("" ::: "memory");  /* 0168: memw */
  L_016b: __asm__ volatile("" ::: "memory");  /* 016b: memw */
  a8 = (u32)&esp_wifi_vnd_mesh_set + 0x0;  /* 016e: l32r -> global */
  a2 = esp_wifi_vnd_mesh_set(a2, a3, a4, a5, a6, a7);  /* 0171: callx a8 via reloc-expand */
  L_0174: a3 = 0;  /* 0174 */
  a2 = 0x00004032u;  /* 0176: l32r = 16434 */
  if (a5 == 0) a2 = a3;  /* 0179 */
  return a2;  /* 017c: retw.n */
}


/* esp_mesh_lookup_route @ mesh_route.o 00000030 size 298B bind GLOBAL
 * Calls: memcmp, esp_mesh_lookup_sub_route | indirect[2]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, .bss.MESH_ZERO_ADDR, g_mesh_conn
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_lookup_route(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0030: entry a1, 80 (frame 80 bytes) */
  if (a2 != 0) goto L_0074;  /* 0033: bnez.n a2, 74 <esp_mesh_lookup_route+0x44> */
  L_0035: a2 = (u32)&g_log_level + 0x0;  /* 0035: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0038 */
  a2 = 0x00004008u;  /* 003a: l32r = 16392 */
  if (a3 >= 3u) goto L_0043;  /* 003d: bgeui a3, 3, 43 <esp_mesh_lookup_route+0x13> */
  L_0040: goto L_0158;  /* 0040: j */
  L_0043: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0043: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0046 */
  if (a3 == 0) goto L_0158;  /* 0048: beqz a3, 158 <esp_mesh_lookup_route+0x128> */
  L_004b: a4 = LD32(a3 + 0x150);  /* 004b */
  if (a4 == 0) goto L_0158;  /* 004e: beqz a4, 158 <esp_mesh_lookup_route+0x128> */
  L_0051: a10 = LD32(a3 + 0x158);  /* 0051 */
  a3 = 193;  /* 0054 */
  /* 0057: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 005a */
  a10 = 3;  /* 005c */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 005e: -> "mesh_route.c" */
  a14 = a11;  /* 0061 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0063: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0066: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 0069 */
  __asm__ volatile("" ::: "memory");  /* 006b: memw */
  /* 006e: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0158;  /* 0071: j */
  L_0074: a5 = a3 | a4;  /* 0074 */
  if (a5 != 0) goto L_007e;  /* 0077: bnez.n a5, 7e <esp_mesh_lookup_route+0x4e> */
  L_0079: a2 = -1;  /* 0079 */
  goto L_0158;  /* 007b: j */
  L_007e: if (a3 == 0) goto L_0089;  /* 007e: beqz.n a3, 89 <esp_mesh_lookup_route+0x59> */
  L_0080: a5 = -1;  /* 0080 */
  ST8(a3 + 0x0, a5);  /* 0083 */
  __asm__ volatile("" ::: "memory");  /* 0086: memw */
  L_0089: if (a4 == 0) goto L_0098;  /* 0089: beqz.n a4, 98 <esp_mesh_lookup_route+0x68> */
  L_008b: a5 = -1;  /* 008b */
  ST8(a4 + 0x0, a5);  /* 008d */
  a5 = -1;  /* 0090 */
  ST16(a4 + 0x2, a5);  /* 0092 */
  __asm__ volatile("" ::: "memory");  /* 0095: memw */
  L_0098: a12 = 6;  /* 0098 */
  a10 = a2;  /* 009a */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 009c: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  __asm__ volatile("" ::: "memory");  /* 009f: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00a2: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00a5: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0079;  /* 00a8: beqz a10, 79 <esp_mesh_lookup_route+0x49> */
  L_00ab: a6 = 0;  /* 00ab */
  a5 = (u32)&g_mesh_conn + 0x0;  /* 00ae: l32r -> global */
  a13 = 6;  /* 00b1 */
  L_00b4: a9 = a6 << 6;  /* 00b4 */
  a7 = (a6 >> 8) & 0x1;  /* 00b7: extui width 1 */
  a8 = (u32)&g_mesh_conn + 0x0;  /* 00ba: l32r -> global */
  a9 = a8 + a9;  /* 00bd */
  a9 = LD32(a9 + 0x4);  /* 00bf */
  if (((a9 >> 16) & 1) != 0) goto L_00d2;  /* 00c1: bbsi a9, 16, d2 <esp_mesh_lookup_route+0xa2> */
  L_00c4: a6 = a6 + (1);  /* 00c4 */
  a5 = a5 + (64);  /* 00c6 */
  if (a6 != 10) goto L_00b4;  /* 00c9: bnei a6, 10, b4 <esp_mesh_lookup_route+0x84> */
  L_00cc: a7 = 255;  /* 00cc */
  goto L_0112;  /* 00cf: j */
  L_00d2: a12 = a13;  /* 00d2 */
  a11 = a5;  /* 00d4 */
  a10 = a2;  /* 00d6 */
  ST32(a1 + 0x20, a13);  /* 00d8 */
  __asm__ volatile("" ::: "memory");  /* 00db: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00de: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00e1: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x20);  /* 00e4 */
  if (a10 == 0) goto L_0112;  /* 00e6: beqz.n a10, 112 <esp_mesh_lookup_route+0xe2> */
  L_00e8: a12 = a13;  /* 00e8 */
  a11 = a1 + (16);  /* 00ea */
  a10 = LD16U(a5 + 0x4);  /* 00ed */
  a9 = LD32(a5 + 0x0);  /* 00f0 */
  ST32(a1 + 0x10, a9);  /* 00f2 */
  a9 = (a10 >> 8) & 0x1ff;  /* 00f4: extui width 9 */
  a9 = a9 + (1);  /* 00f7 */
  ST16(a1 + 0x14, a10);  /* 00f9 */
  a10 = a2;  /* 00fc */
  ST8(a1 + 0x15, a9);  /* 00fe */
  __asm__ volatile("" ::: "memory");  /* 0101: memw */
  __asm__ volatile("" ::: "memory");  /* 0104: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0107: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 010a: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x20);  /* 010d */
  if (a10 != 0) goto L_00c4;  /* 010f: bnez a10, c4 <esp_mesh_lookup_route+0x94> */
  L_0112: if (a3 == 0) goto L_011a;  /* 0112: beqz.n a3, 11a <esp_mesh_lookup_route+0xea> */
  L_0114: ST8(a3 + 0x0, a7);  /* 0114 */
  __asm__ volatile("" ::: "memory");  /* 0117: memw */
  L_011a: if (a4 != 0) goto L_0124;  /* 011a: bnez.n a4, 124 <esp_mesh_lookup_route+0xf4> */
  L_011c: __asm__ volatile("" ::: "memory");  /* 011c: memw */
  goto L_0148;  /* 011f: j */
  L_0124: ST8(a4 + 0x0, a7);  /* 0124 */
  __asm__ volatile("" ::: "memory");  /* 0127: memw */
  a5 = 0;  /* 012a */
  L_012c: a11 = a5;  /* 012c */
  a10 = a2;  /* 012e */
  a3 = (a5 >> 8) & 0x1;  /* 0130: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 0133: memw */
  a8 = (u32)&esp_mesh_lookup_sub_route;  /* 0136: l32r -> func addr */
  a2 = esp_mesh_lookup_sub_route(a2, a3, a4, a5, a6, a7);  /* 0139: callx a8 via reloc-expand */
  if (a10 == -1) goto L_0150;  /* 013c: beqi a10, -1, 150 <esp_mesh_lookup_route+0x120> */
  L_013f: ST8(a4 + 0x0, a3);  /* 013f */
  ST16(a4 + 0x2, a10);  /* 0142 */
  __asm__ volatile("" ::: "memory");  /* 0145: memw */
  L_0148: a2 = 0;  /* 0148 */
  __asm__ volatile("" ::: "memory");  /* 014a: memw */
  goto L_0158;  /* 014d: j */
  L_0150: a5 = a5 + (1);  /* 0150 */
  if (a5 != 10) goto L_012c;  /* 0152: bnei a5, 10, 12c <esp_mesh_lookup_route+0xfc> */
  L_0155: goto L_0148;  /* 0155: j */
  L_0158: return a2;  /* 0158: retw.n */
}


/* esp_mesh_lookup_sub_route @ mesh_route.o 00000014 size 182B bind GLOBAL
 * Calls: memcmp, memcpy | Data refs: g_mesh_ext_cfg, .bss.mesh_route_table
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_lookup_sub_route(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0014: entry a1, 48 (frame 48 bytes) */
  a3 = (a3 >> 8) & 0x1;  /* 0017: extui width 1 */
  a8 = 1;  /* 001a */
  if (a2 == 0) goto L_00c6;  /* 001c: beqz a2, c6 <esp_mesh_lookup_sub_route+0xb2> */
  L_001f: a9 = a3 >> 7;  /* 001f */
  if (a9 != 0) goto L_00c6;  /* 0022: bnez a9, c6 <esp_mesh_lookup_sub_route+0xb2> */
  L_0025: a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0025: l32r -> global */
  a3 = (i32)(a3 << (32 - 7)) >> (32 - 7);  /* 0028: sext */
  a4 = LD8U(a4 + 0xbd);  /* 002b */
  if ((i32)a3 < (i32)a4) goto L_0034;  /* 002e: blt a3, a4, 34 <esp_mesh_lookup_sub_route+0x20> */
  L_0031: goto L_00c6;  /* 0031: j */
  L_0034: a5 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0034: l32r -> .bss.mesh_route_table (same-object static) */
  a4 = a3 + (a5 << 1);  /* 0037 */
  a3 = a3 + (8);  /* 003a */
  a3 = a3 + (a5 << 2);  /* 003c */
  a6 = LD8U(a4 + 0x0);  /* 003f */
  a4 = LD8U(a4 + 0x1);  /* 0042 */
  a4 = a4 << 8;  /* 0045 */
  a4 = a4 | a6;  /* 0048 */
  if (a4 == 0) a9 = a8;  /* 004b */
  a5 = LD8U(a3 + 0x9);  /* 004e */
  a5 = a5 << 8;  /* 0051 */
  a6 = LD8U(a3 + 0x8);  /* 0054 */
  a5 = a5 | a6;  /* 0057 */
  a10 = LD8U(a3 + 0xa);  /* 005a */
  a10 = a10 << 16;  /* 005d */
  a10 = a10 | a5;  /* 0060 */
  a5 = LD8U(a3 + 0xb);  /* 0063 */
  a5 = a5 << 24;  /* 0066 */
  a5 = a5 | a10;  /* 0069 */
  if (a9 != 0) goto L_00c6;  /* 006c: bnez a9, c6 <esp_mesh_lookup_sub_route+0xb2> */
  L_006f: a3 = a9;  /* 006f */
  if (a5 == 0) a3 = a8;  /* 0071 */
  a3 = (a3 >> 8) & 0x1;  /* 0074: extui width 1 */
  if (a3 != 0) goto L_00c6;  /* 0077: bnez a3, c6 <esp_mesh_lookup_sub_route+0xb2> */
  L_007a: a6 = 6;  /* 007a */
  L_007c: a12 = a6;  /* 007c */
  a11 = a5;  /* 007e */
  a10 = a2;  /* 0080 */
  a8 = (u32)&memcmp + 0x0;  /* 0082: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0085: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_008d;  /* 0088: bnez.n a10, 8d <esp_mesh_lookup_sub_route+0x79> */
  L_008a: goto L_00b6;  /* 008a: j */
  L_008d: a12 = a6;  /* 008d */
  a11 = a5;  /* 008f */
  a10 = a1;  /* 0091 */
  a8 = (u32)&memcpy + 0x0;  /* 0093: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0096: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a1 + 0x5);  /* 0099 */
  a12 = a6;  /* 009c */
  a8 = a8 + (1);  /* 009e */
  a11 = a1;  /* 00a0 */
  a10 = a2;  /* 00a2: mov */
  ST8(a1 + 0x5, a8);  /* 00a5 */
  __asm__ volatile("" ::: "memory");  /* 00a8: memw */
  __asm__ volatile("" ::: "memory");  /* 00ab: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00ae: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00b1: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00bc;  /* 00b4: bnez.n a10, bc <esp_mesh_lookup_sub_route+0xa8> */
  L_00b6: a2 = (i32)(a3 << (32 - 15)) >> (32 - 15);  /* 00b6: sext */
  goto L_00c8;  /* 00b9: j */
  L_00bc: a3 = a3 + (1);  /* 00bc */
  a3 = (a3 >> 16) & 0x1;  /* 00be: extui width 1 */
  a5 = a5 + (6);  /* 00c1 */
  if (a3 < a4) goto L_007c;  /* 00c3: bltu a3, a4, 7c <esp_mesh_lookup_sub_route+0x68> */
  L_00c6: a2 = -1;  /* 00c6 */
  L_00c8: return a2;  /* 00c8: retw.n */
}


/* esp_mesh_match_self @ mesh_route.o 00000018 size 66B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.MESH_ZERO_ADDR, g_mesh_self_sta_addr, g_mesh_self_map_addr
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_match_self(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a3 = a2;  /* 001b */
  if (a2 == 0) goto L_0058;  /* 001d: beqz.n a2, 58 <esp_mesh_match_self+0x40> */
  L_001f: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 001f: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a10 = a2;  /* 0022 */
  a12 = 6;  /* 0024 */
  a8 = (u32)&memcmp + 0x0;  /* 0026: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0029: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 002c */
  if (a10 == a2) goto L_0058;  /* 002e: beq a10, a2, 58 <esp_mesh_match_self+0x40> */
  L_0031: a11 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 0031: l32r -> global */
  a12 = 6;  /* 0034 */
  a10 = a3;  /* 0036 */
  a8 = (u32)&memcmp + 0x0;  /* 0038: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 003b: callx a8 (libc, via reloc-expand) */
  a2 = 1;  /* 003e */
  if (a10 == 0) goto L_0058;  /* 0040: beqz.n a10, 58 <esp_mesh_match_self+0x40> */
  L_0042: a11 = (u32)&g_mesh_self_map_addr + 0x0;  /* 0042: l32r -> global */
  a10 = a3;  /* 0045 */
  a12 = 6;  /* 0047 */
  a8 = (u32)&memcmp + 0x0;  /* 004a: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 004d: callx a8 (libc, via reloc-expand) */
  a3 = 0;  /* 0050 */
  if (a10 != 0) a2 = a3;  /* 0052 */
  a2 = (a2 >> 8) & 0x1;  /* 0055: extui width 1 */
  L_0058: return a2;  /* 0058: retw.n */
}


/* esp_mesh_monitor_nonassociated_children @ mesh_route.o 0000004c size 673B bind GLOBAL
 * Calls: esp_mesh_get_child_idx, esp_mesh_lookup_route, memset, mesh_update_route_table, memcpy | indirect[10]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x158]; mem[a4+0xb8] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, .bss.mesh_route_table, .rodata.esp_mesh_monitor_nonassociated_children.str1.1
 * Fidelity: medium - 10 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=10); reloc-direct=5, funcdb-attributed=0, unknown-indirect=10 */
u32 esp_mesh_monitor_nonassociated_children(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 004c: entry a1, 64 (frame 64 bytes) */
  if (a2 != 0) goto L_007e;  /* 004f: bnez.n a2, 7e <esp_mesh_monitor_nonassociated_children+0x32> */
  L_0051: a2 = (u32)&g_log_level + 0x0;  /* 0051: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0054 */
  a2 = 0x00004008u;  /* 0057: l32r = 16392 */
  if (a3 >= 3u) goto L_0060;  /* 005a: bgeui a3, 3, 60 <esp_mesh_monitor_nonassociated_children+0x14> */
  L_005d: goto L_02e8;  /* 005d: j */
  L_0060: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0060: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0063 */
  if (a3 == 0) goto L_02e8;  /* 0066: beqz a3, 2e8 <esp_mesh_monitor_nonassociated_children+0x29c> */
  L_0069: a4 = LD32(a3 + 0x150);  /* 0069 */
  if (a4 == 0) goto L_02e8;  /* 006c: beqz a4, 2e8 <esp_mesh_monitor_nonassociated_children+0x29c> */
  L_006f: a10 = LD32(a3 + 0x158);  /* 006f */
  a3 = 0x41b;  /* 0072 */
  /* 0075: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0078: -> "mesh_route.c" */
  goto L_00a8;  /* 007b: j */
  L_007e: if (a3 != 0) goto L_00c0;  /* 007e: bnez.n a3, c0 <esp_mesh_monitor_nonassociated_children+0x74> */
  L_0080: a2 = (u32)&g_log_level + 0x0;  /* 0080: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0083 */
  a2 = 0x00004008u;  /* 0085: l32r = 16392 */
  if (a3 >= 3u) goto L_008e;  /* 0088: bgeui a3, 3, 8e <esp_mesh_monitor_nonassociated_children+0x42> */
  L_008b: goto L_02e8;  /* 008b: j */
  L_008e: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 008e: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0091 */
  if (a3 == 0) goto L_02e8;  /* 0093: beqz a3, 2e8 <esp_mesh_monitor_nonassociated_children+0x29c> */
  L_0096: a4 = LD32(a3 + 0x150);  /* 0096 */
  if (a4 == 0) goto L_02e8;  /* 0099: beqz a4, 2e8 <esp_mesh_monitor_nonassociated_children+0x29c> */
  L_009c: a10 = LD32(a3 + 0x158);  /* 009c */
  a3 = 0x41c;  /* 009f */
  /* 00a2: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00a5: -> "mesh_route.c" */
  L_00a8: a13 = a10;  /* 00a8 */
  a14 = a11;  /* 00aa */
  a10 = 3;  /* 00ac */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00ae: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00b1: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 00b4 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  /* 00b9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_02e8;  /* 00bc: j */
  L_00c0: a10 = a2;  /* 00c0 */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 00c2: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6, a7);  /* 00c5: callx a8 via reloc-expand */
  a5 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 00c8: sext */
  if (a5 != -1) goto L_00d1;  /* 00cb: bnei a5, -1, d1 <esp_mesh_monitor_nonassociated_children+0x85> */
  L_00ce: goto L_0234;  /* 00ce: j */
  L_00d1: a12 = a1 + (16);  /* 00d1 */
  a11 = 0;  /* 00d4 */
  a10 = a3;  /* 00d7: mov */
  a8 = (u32)&esp_mesh_lookup_route;  /* 00da: l32r -> func addr */
  a2 = esp_mesh_lookup_route(a2, a3, a4, a5, a6, a7);  /* 00dd: callx a8 via reloc-expand */
  a4 = LD8U(a1 + 0x10);  /* 00e0 */
  a2 = 0;  /* 00e3 */
  a4 = (i32)(a4 << (32 - 7)) >> (32 - 7);  /* 00e5: sext */
  if (a4 != a5) goto L_00ee;  /* 00e8: bne a4, a5, ee <esp_mesh_monitor_nonassociated_children+0xa2> */
  L_00eb: goto L_02e8;  /* 00eb: j */
  L_00ee: a10 = LD16S(a1 + 0x12);  /* 00ee */
  if (a10 == -1) goto L_013d;  /* 00f1: beqi a10, -1, 13d <esp_mesh_monitor_nonassociated_children+0xf1> */
  L_00f4: a6 = a4 + (8);  /* 00f4 */
  a10 = a10 + (a10 << 1);  /* 00f6 */
  a7 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 00f9: l32r -> .bss.mesh_route_table (same-object static) */
  a11 = a2;  /* 00fc */
  a6 = a6 + (a7 << 2);  /* 00fe */
  a12 = 6;  /* 0101 */
  a9 = LD8U(a6 + 0x9);  /* 0103 */
  a9 = a9 << 8;  /* 0106 */
  a7 = LD8U(a6 + 0x8);  /* 0109 */
  a9 = a9 | a7;  /* 010c */
  a8 = LD8U(a6 + 0xa);  /* 010f */
  a8 = a8 << 16;  /* 0112 */
  a8 = a8 | a9;  /* 0115 */
  a6 = LD8U(a6 + 0xb);  /* 0118 */
  a6 = a6 << 24;  /* 011b */
  a6 = a6 | a8;  /* 011e */
  a10 = a10 + (a6 << 1);  /* 0121 */
  a8 = (u32)&memset + 0x0;  /* 0124: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0127: callx a8 (libc, via reloc-expand) */
  a12 = 1;  /* 012a */
  a11 = 2;  /* 012c */
  a10 = a4;  /* 012f: mov */
  a8 = (u32)&mesh_update_route_table;  /* 0132: l32r -> func addr */
  a2 = mesh_update_route_table(a2, a3, a4, a5, a6, a7);  /* 0135: callx a8 via reloc-expand */
  goto L_0143;  /* 0138: j */
  L_013d: if (a4 == -1) goto L_0143;  /* 013d: beqi a4, -1, 143 <esp_mesh_monitor_nonassociated_children+0xf7> */
  L_0140: goto L_02e8;  /* 0140: j */
  L_0143: a6 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0143: l32r -> .bss.mesh_route_table (same-object static) */
  a2 = a5 + (8);  /* 0146 */
  a9 = a2 + (a6 << 2);  /* 0148 */
  a8 = LD8U(a9 + 0x9);  /* 014b */
  a8 = a8 << 8;  /* 014e */
  a4 = LD8U(a9 + 0x8);  /* 0151 */
  a8 = a8 | a4;  /* 0154 */
  a4 = LD8U(a9 + 0xa);  /* 0157 */
  a4 = a4 << 16;  /* 015a */
  a4 = a4 | a8;  /* 015d */
  a11 = LD8U(a9 + 0xb);  /* 0160 */
  a11 = a11 << 24;  /* 0163 */
  a11 = a11 | a4;  /* 0166 */
  if (a11 != 0) goto L_01b4;  /* 0169: bnez a11, 1b4 <esp_mesh_monitor_nonassociated_children+0x168> */
  L_016c: a12 = a11;  /* 016c */
  a10 = a5;  /* 016e */
  a8 = (u32)&mesh_update_route_table;  /* 0170: l32r -> func addr */
  a2 = mesh_update_route_table(a2, a3, a4, a5, a6, a7);  /* 0173: callx a8 via reloc-expand */
  if (a10 == 0) goto L_01b4;  /* 0176: beqz.n a10, 1b4 <esp_mesh_monitor_nonassociated_children+0x168> */
  L_0178: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0178: l32r -> global */
  a2 = LD32(a4 + 0x0);  /* 017b */
  if (a2 == 0) goto L_0234;  /* 017d: beqz a2, 234 <esp_mesh_monitor_nonassociated_children+0x1e8> */
  L_0180: a3 = LD32(a2 + 0x150);  /* 0180 */
  if (a3 == 0) goto L_0234;  /* 0183: beqz a3, 234 <esp_mesh_monitor_nonassociated_children+0x1e8> */
  L_0186: a10 = LD32(a2 + 0x158);  /* 0186 */
  /* 0189: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 018c */
  a4 = LD32(a4 + 0x0);  /* 018e */
  a10 = LD32(a4 + 0xb8);  /* 0190 */
  a4 = 0x444;  /* 0193 */
  /* 0196: INDIRECT callx a10 <- mem[a4+0xb8]; result unknown */ a2 = 0;
  a13 = a2;  /* 0199 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 019b: -> "mesh_route.c" */
  a14 = a11;  /* 019e */
  ST32(a1 + 0x8, a10);  /* 01a0 */
  a10 = 1;  /* 01a2 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01a4: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_monitor_nonassociated_children_str1_1 + 0x0);  /* 01a7: l32r -> .rodata.esp_mesh_monitor_nonassociated_children.str1.1 */
  ST32(a1 + 0x4, a5);  /* 01aa */
  ST32(a1 + 0x0, a4);  /* 01ac */
  __asm__ volatile("" ::: "memory");  /* 01ae: memw */
  goto L_022e;  /* 01b1: j */
  L_01b4: a7 = a5 + (a6 << 1);  /* 01b4 */
  a8 = LD8U(a7 + 0x1);  /* 01b7 */
  a4 = a5 + a5;  /* 01ba */
  a8 = a8 << 8;  /* 01bc */
  a9 = LD8U(a7 + 0x0);  /* 01bf */
  a8 = a8 | a9;  /* 01c2 */
  if (a8 == 0) goto L_023a;  /* 01c5: beqz a8, 23a <esp_mesh_monitor_nonassociated_children+0x1ee> */
  L_01c8: a7 = a2 + (a6 << 1);  /* 01c8 */
  a9 = LD8U(a7 + 0x5);  /* 01cb */
  a9 = a9 << 8;  /* 01ce */
  a10 = LD8U(a7 + 0x4);  /* 01d1 */
  a9 = a9 | a10;  /* 01d4 */
  if (a8 < a9) goto L_023a;  /* 01d7: bltu a8, a9, 23a <esp_mesh_monitor_nonassociated_children+0x1ee> */
  L_01da: a12 = 0;  /* 01da */
  a11 = 2;  /* 01dc */
  a10 = a5;  /* 01de */
  a8 = (u32)&mesh_update_route_table;  /* 01e0: l32r -> func addr */
  a2 = mesh_update_route_table(a2, a3, a4, a5, a6, a7);  /* 01e3: callx a8 via reloc-expand */
  a7 = a10;  /* 01e6 */
  if (a10 == 0) goto L_023a;  /* 01e8: beqz a10, 23a <esp_mesh_monitor_nonassociated_children+0x1ee> */
  L_01eb: a2 = 0x00004007u;  /* 01eb: l32r = 16391 */
  if (a10 == a2) goto L_0234;  /* 01ee: beq a10, a2, 234 <esp_mesh_monitor_nonassociated_children+0x1e8> */
  L_01f1: a2 = (u32)&g_log_level + 0x0;  /* 01f1: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01f4 */
  if (a2 < 3u) goto L_0234;  /* 01f7: bltui a2, 3, 234 <esp_mesh_monitor_nonassociated_children+0x1e8> */
  L_01fa: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 01fa: l32r -> global */
  a2 = LD32(a4 + 0x0);  /* 01fd */
  if (a2 == 0) goto L_0234;  /* 0200: beqz.n a2, 234 <esp_mesh_monitor_nonassociated_children+0x1e8> */
  L_0202: a3 = LD32(a2 + 0x150);  /* 0202 */
  if (a3 == 0) goto L_0234;  /* 0205: beqz a3, 234 <esp_mesh_monitor_nonassociated_children+0x1e8> */
  L_0208: a10 = LD32(a2 + 0x158);  /* 0208 */
  /* 020b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 020e */
  a4 = LD32(a4 + 0x0);  /* 0210 */
  a10 = LD32(a4 + 0xb8);  /* 0213 */
  /* 0216: INDIRECT callx a10 <- mem[a4+0xb8]; result unknown */ a2 = 0;
  a15 = 0x450;  /* 0219 */
  a13 = a2;  /* 021c */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 021e: -> "mesh_route.c" */
  a14 = a11;  /* 0221 */
  a12 = (u32)(RODATA__rodata_esp_mesh_monitor_nonassociated_children_str1_1 + 0x0);  /* 0223: l32r -> .rodata.esp_mesh_monitor_nonassociated_children.str1.1 */
  ST32(a1 + 0x8, a10);  /* 0226 */
  a10 = 3;  /* 0228 */
  ST32(a1 + 0x4, a7);  /* 022a */
  ST32(a1 + 0x0, a5);  /* 022c */
  L_022e: __asm__ volatile("" ::: "memory");  /* 022e: memw */
  /* 0231: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0234: a2 = -1;  /* 0234 */
  goto L_02e8;  /* 0236: j */
  L_023a: a5 = a6 + a4;  /* 023a */
  a7 = LD8U(a5 + 0x0);  /* 023c */
  a5 = LD8U(a5 + 0x1);  /* 023f */
  a5 = a5 << 8;  /* 0242 */
  a5 = a5 | a7;  /* 0245 */
  if (a5 == 0) goto L_0289;  /* 0248: beqz.n a5, 289 <esp_mesh_monitor_nonassociated_children+0x23d> */
  L_024a: a7 = a2 + (a6 << 1);  /* 024a */
  a8 = LD8U(a7 + 0x5);  /* 024d */
  a8 = a8 << 8;  /* 0250 */
  a9 = LD8U(a7 + 0x4);  /* 0253 */
  a8 = a8 | a9;  /* 0256 */
  if (a5 < a8) goto L_0289;  /* 0259: bltu a5, a8, 289 <esp_mesh_monitor_nonassociated_children+0x23d> */
  L_025c: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 025c: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 025f */
  if (a5 == 0) goto L_0289;  /* 0261: beqz.n a5, 289 <esp_mesh_monitor_nonassociated_children+0x23d> */
  L_0263: a7 = LD32(a5 + 0x150);  /* 0263 */
  if (a7 == 0) goto L_0289;  /* 0266: beqz.n a7, 289 <esp_mesh_monitor_nonassociated_children+0x23d> */
  L_0268: a10 = LD32(a5 + 0x158);  /* 0268 */
  a5 = 0x459;  /* 026b */
  /* 026e: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0271 */
  a10 = 1;  /* 0273 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0275: -> "mesh_route.c" */
  a14 = a11;  /* 0278 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 027a: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_monitor_nonassociated_children_str1_1 + 0x0);  /* 027d: l32r -> .rodata.esp_mesh_monitor_nonassociated_children.str1.1 */
  ST32(a1 + 0x0, a5);  /* 0280 */
  __asm__ volatile("" ::: "memory");  /* 0283: memw */
  /* 0286: INDIRECT callx a7 <- mem[a5+0x150]; result unknown */ a2 = 0;
  L_0289: a8 = a2 + (a6 << 2);  /* 0289 */
  a4 = a6 + a4;  /* 028c */
  a12 = 6;  /* 028e */
  a5 = LD8U(a8 + 0x9);  /* 0290 */
  a11 = a3;  /* 0293 */
  a5 = a5 << 8;  /* 0295 */
  a2 = LD8U(a8 + 0x8);  /* 0298 */
  a5 = a5 | a2;  /* 029b */
  a2 = LD8U(a8 + 0xa);  /* 029e */
  a2 = a2 << 16;  /* 02a1 */
  a2 = a2 | a5;  /* 02a4 */
  a10 = LD8U(a8 + 0xb);  /* 02a7 */
  a10 = a10 << 24;  /* 02aa */
  a10 = a10 | a2;  /* 02ad */
  a2 = LD8U(a4 + 0x1);  /* 02b0 */
  a2 = a2 << 8;  /* 02b3 */
  a5 = LD8U(a4 + 0x0);  /* 02b6 */
  a2 = a2 | a5;  /* 02b9 */
  a2 = a2 + (a2 << 1);  /* 02bc */
  a10 = a2 + (a10 << 1);  /* 02bf */
  a8 = (u32)&memcpy + 0x0;  /* 02c2: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 02c5: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a4 + 0x1);  /* 02c8 */
  a8 = a8 << 8;  /* 02cb */
  a2 = LD8U(a4 + 0x0);  /* 02ce */
  a8 = a8 | a2;  /* 02d1 */
  a8 = a8 + (1);  /* 02d4 */
  ST8(a4 + 0x0, a8);  /* 02d6 */
  __asm__ volatile("" ::: "memory");  /* 02d9: memw */
  a8 = (a8 >> 8) & 0x1ff;  /* 02dc: extui width 9 */
  a2 = 0x00004032u;  /* 02df: l32r = 16434 */
  ST8(a4 + 0x1, a8);  /* 02e2 */
  __asm__ volatile("" ::: "memory");  /* 02e5: memw */
  L_02e8: __asm__ volatile("" ::: "memory");  /* 02e8: memw */
  return a2;  /* 02eb: retw.n */
}


/* esp_mesh_nwk_redundant_route @ mesh_route.o 00000044 size 376B bind GLOBAL
 * Calls: esp_mesh_get_child_idx, esp_mesh_process_redundant_subchildren, esp_mesh_send_rtable_request, nwk_event_id2str, esp_mesh_send_rtable_ack | indirect[6]: mem[a2+0x158]; mem[a2+0x150]; mem[a5+0x158]; unknown | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, g_mesh_ext_cfg, .rodata.esp_mesh_nwk_redundant_route.str1.1, g_mesh_conn, mesh_multi_send_ack
 * Fidelity: medium - 6 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=12); reloc-direct=5, funcdb-attributed=0, unknown-indirect=6 */
u32 esp_mesh_nwk_redundant_route(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0044: entry a1, 64 (frame 64 bytes) */
  if (a2 != 0) goto L_0088;  /* 0047: bnez.n a2, 88 <esp_mesh_nwk_redundant_route+0x44> */
  L_0049: a2 = (u32)&g_log_level + 0x0;  /* 0049: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 004c */
  a3 = 0x00004008u;  /* 004e: l32r = 16392 */
  if (a2 >= 3u) goto L_0057;  /* 0051: bgeui a2, 3, 57 <esp_mesh_nwk_redundant_route+0x13> */
  L_0054: goto L_01b8;  /* 0054: j */
  L_0057: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0057: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 005a */
  if (a2 == 0) goto L_01b8;  /* 005c: beqz a2, 1b8 <esp_mesh_nwk_redundant_route+0x174> */
  L_005f: a4 = LD32(a2 + 0x150);  /* 005f */
  if (a4 == 0) goto L_01b8;  /* 0062: beqz a4, 1b8 <esp_mesh_nwk_redundant_route+0x174> */
  L_0065: a10 = LD32(a2 + 0x158);  /* 0065 */
  a2 = 0x75f;  /* 0068 */
  /* 006b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 006e */
  a10 = 3;  /* 0070 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0072: -> "mesh_route.c" */
  a14 = a11;  /* 0075 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0077: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 007a: -> "mesh_route.c" */
  ST32(a1 + 0x0, a2);  /* 007d */
  __asm__ volatile("" ::: "memory");  /* 007f: memw */
  /* 0082: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_01b8;  /* 0085: j */
  L_0088: a3 = LD8U(a2 + 0x6);  /* 0088 */
  a5 = a2 + (10);  /* 008b */
  if (a3 == 0) goto L_0145;  /* 008d: beqz a3, 145 <esp_mesh_nwk_redundant_route+0x101> */
  L_0090: a10 = a5;  /* 0090 */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 0092: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6, a7);  /* 0095: callx a8 via reloc-expand */
  a4 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 0098: sext */
  a3 = -1;  /* 009b */
  if ((i32)a4 < 0) goto L_01b8;  /* 009d: bltz a4, 1b8 <esp_mesh_nwk_redundant_route+0x174> */
  L_00a0: a3 = (u32)&g_mesh_ext_cfg + 0x0;  /* 00a0: l32r -> global */
  a6 = LD8U(a3 + 0xbd);  /* 00a3 */
  a3 = -1;  /* 00a6 */
  if ((i32)a4 < (i32)a6) goto L_00ae;  /* 00a8: blt a4, a6, ae <esp_mesh_nwk_redundant_route+0x6a> */
  L_00ab: goto L_01b8;  /* 00ab: j */
  L_00ae: a3 = LD16U(a2 + 0x8);  /* 00ae */
  if (a3 != 1) goto L_00c5;  /* 00b1: bnei a3, 1, c5 <esp_mesh_nwk_redundant_route+0x81> */
  L_00b4: a12 = 0;  /* 00b4 */
  a11 = a12;  /* 00b6 */
  a10 = a4;  /* 00b8 */
  a8 = (u32)&esp_mesh_process_redundant_subchildren;  /* 00ba: l32r -> func addr */
  a2 = esp_mesh_process_redundant_subchildren(a2, a3, a4, a5, a6, a7);  /* 00bd: callx a8 via reloc-expand */
  a3 = a10;  /* 00c0 */
  goto L_012c;  /* 00c2: j */
  L_00c5: a10 = a5;  /* 00c5 */
  a8 = (u32)&esp_mesh_send_rtable_request;  /* 00c7: l32r -> func addr */
  a2 = esp_mesh_send_rtable_request(a2, a3, a4, a5, a6, a7);  /* 00ca: callx a8 via reloc-expand */
  a5 = (u32)&g_log_level + 0x0;  /* 00cd: l32r -> global */
  a3 = a10;  /* 00d0 */
  a5 = LD32(a5 + 0x0);  /* 00d2 */
  if (a5 < 3u) goto L_012c;  /* 00d5: bltui a5, 3, 12c <esp_mesh_nwk_redundant_route+0xe8> */
  L_00d8: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 00d8: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 00db */
  if (a5 == 0) goto L_012c;  /* 00dd: beqz a5, 12c <esp_mesh_nwk_redundant_route+0xe8> */
  L_00e0: a6 = LD32(a5 + 0x150);  /* 00e0 */
  if (a6 == 0) goto L_012c;  /* 00e3: beqz a6, 12c <esp_mesh_nwk_redundant_route+0xe8> */
  L_00e6: a10 = LD32(a5 + 0x158);  /* 00e6 */
  /* 00e9: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 00ec */
  a10 = LD32(a2 + 0x0);  /* 00ee */
  a8 = (u32)&nwk_event_id2str + 0x0;  /* 00f0: l32r -> global */
  a2 = nwk_event_id2str(a2, a3, a4, a5, a6, a7);  /* 00f3: callx a8 via reloc-expand */
  a15 = a10;  /* 00f6 */
  a13 = a5;  /* 00f8 */
  ST32(a1 + 0x18, a3);  /* 00fa */
  a10 = 3;  /* 00fc */
  a8 = LD8U(a2 + 0xf);  /* 00fe */
  ST32(a1 + 0x14, a8);  /* 0101 */
  a8 = LD8U(a2 + 0xe);  /* 0103 */
  ST32(a1 + 0x10, a8);  /* 0106 */
  a8 = LD8U(a2 + 0xd);  /* 0108 */
  ST32(a1 + 0xc, a8);  /* 010b */
  a8 = LD8U(a2 + 0xc);  /* 010d */
  ST32(a1 + 0x8, a8);  /* 0110 */
  a8 = LD8U(a2 + 0xb);  /* 0112 */
  ST32(a1 + 0x4, a8);  /* 0115 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0117: -> "mesh_route.c" */
  a14 = a11;  /* 011a: mov */
  a2 = LD8U(a2 + 0xa);  /* 011d */
  a12 = (u32)(RODATA__rodata_esp_mesh_nwk_redundant_route_str1_1 + 0x0);  /* 0120: l32r -> .rodata.esp_mesh_nwk_redundant_route.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0123 */
  __asm__ volatile("" ::: "memory");  /* 0126: memw */
  /* 0129: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_012c: a4 = a4 << 6;  /* 012c */
  a2 = (u32)&g_mesh_conn + 0x0;  /* 012f: l32r -> global */
  a2 = a2 + a4;  /* 0132 */
  a4 = 1;  /* 0134 */
  ST8(a2 + 0x28, a4);  /* 0136 */
  __asm__ volatile("" ::: "memory");  /* 0139: memw */
  __asm__ volatile("" ::: "memory");  /* 013c: memw */
  goto L_01b8;  /* 013f: j */
  L_0145: a10 = LD8U(a2 + 0x10);  /* 0145 */
  a11 = a5;  /* 0148 */
  a8 = (u32)&esp_mesh_send_rtable_ack;  /* 014a: l32r -> func addr */
  a2 = esp_mesh_send_rtable_ack(a2, a3, a4, a5, a6, a7);  /* 014d: callx a8 via reloc-expand */
  a3 = a10;  /* 0150 */
  a4 = (u32)&g_log_level + 0x0;  /* 0152: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0155 */
  if (a4 < 3u) goto L_01b8;  /* 0157: bltui a4, 3, 1b8 <esp_mesh_nwk_redundant_route+0x174> */
  L_015a: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 015a: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 015d */
  if (a4 == 0) goto L_01b8;  /* 015f: beqz a4, 1b8 <esp_mesh_nwk_redundant_route+0x174> */
  L_0162: a5 = LD32(a4 + 0x150);  /* 0162 */
  if (a5 == 0) goto L_01b8;  /* 0165: beqz a5, 1b8 <esp_mesh_nwk_redundant_route+0x174> */
  L_0168: a10 = LD32(a4 + 0x158);  /* 0168 */
  /* 016b: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 016e */
  a10 = LD32(a2 + 0x0);  /* 0170 */
  a8 = (u32)&nwk_event_id2str + 0x0;  /* 0173: l32r -> global */
  a2 = nwk_event_id2str(a2, a3, a4, a5, a6, a7);  /* 0176: callx a8 via reloc-expand */
  a15 = a10;  /* 0179 */
  a13 = a4;  /* 017b */
  ST32(a1 + 0x1c, a3);  /* 017d */
  a10 = 3;  /* 017f */
  a6 = LD8U(a2 + 0xf);  /* 0181 */
  ST32(a1 + 0x18, a6);  /* 0184 */
  a6 = LD8U(a2 + 0xe);  /* 0186 */
  ST32(a1 + 0x14, a6);  /* 0189 */
  a6 = LD8U(a2 + 0xd);  /* 018b */
  ST32(a1 + 0x10, a6);  /* 018e */
  a6 = LD8U(a2 + 0xc);  /* 0190 */
  ST32(a1 + 0xc, a6);  /* 0193 */
  a6 = LD8U(a2 + 0xb);  /* 0195 */
  ST32(a1 + 0x8, a6);  /* 0198 */
  a2 = LD8U(a2 + 0xa);  /* 019a */
  ST32(a1 + 0x4, a2);  /* 019d */
  a2 = (u32)&mesh_multi_send_ack + 0x0;  /* 019f: l32r -> global */
  a2 = LD16U(a2 + 0x6);  /* 01a2 */
  a2 = (a2 >> 7) & 0x1;  /* 01a5: extui width 1 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01a8: -> "mesh_route.c" */
  a14 = a11;  /* 01ab */
  a12 = (u32)(RODATA__rodata_esp_mesh_nwk_redundant_route_str1_1 + 0x0);  /* 01ad: l32r -> .rodata.esp_mesh_nwk_redundant_route.str1.1 */
  ST32(a1 + 0x0, a2);  /* 01b0 */
  __asm__ volatile("" ::: "memory");  /* 01b2: memw */
  /* 01b5: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_01b8: a2 = a3;  /* 01b8 */
  return a2;  /* 01ba: retw.n */
}


/* esp_mesh_pack_multi_routing_table @ mesh_route.o 00000048 size 1193B bind GLOBAL
 * Calls: mesh_pack_rmv_announcement, memcpy | indirect[7]: mem[a3+0x158]; mem[a3+0x150]; mem[a6+0x158]; unknown | Data refs: g_mesh_is_root, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, g_mesh_conn, .bss.mesh_route_table, g_mesh_topology, .rodata.esp_mesh_pack_multi_routing_table.str1.1
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=10); reloc-direct=2, funcdb-attributed=0, unknown-indirect=7 */
u32 esp_mesh_pack_multi_routing_table(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0048: entry a1, 112 (frame 112 bytes) */
  a6 = (a2 >> 8) & 0x1;  /* 004b: extui width 1 */
  a2 = (u32)&g_mesh_is_root + 0x0;  /* 004e: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0051: memw */
  a5 = LD8U(a2 + 0x0);  /* 0054 */
  a2 = 0;  /* 0057 */
  a5 = (a5 >> 8) & 0x1;  /* 0059: extui width 1 */
  ST32(a1 + 0x30, a3);  /* 005c */
  if (a5 == a2) goto L_0064;  /* 005e: beq a5, a2, 64 <esp_mesh_pack_multi_routing_table+0x1c> */
  L_0061: goto L_04ec;  /* 0061: j */
  L_0064: a2 = (i32)(a6 << (32 - 7)) >> (32 - 7);  /* 0064: sext */
  if (a3 != 0) goto L_009a;  /* 0067: bnez.n a3, 9a <esp_mesh_pack_multi_routing_table+0x52> */
  L_0069: a2 = (u32)&g_log_level + 0x0;  /* 0069: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 006c */
  a2 = 0x00004008u;  /* 006e: l32r = 16392 */
  if (a3 >= 3u) goto L_0077;  /* 0071: bgeui a3, 3, 77 <esp_mesh_pack_multi_routing_table+0x2f> */
  L_0074: goto L_04ec;  /* 0074: j */
  L_0077: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0077: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 007a */
  if (a3 == 0) goto L_04ec;  /* 007c: beqz a3, 4ec <esp_mesh_pack_multi_routing_table+0x4a4> */
  L_007f: a4 = LD32(a3 + 0x150);  /* 007f */
  if (a4 == 0) goto L_04ec;  /* 0082: beqz a4, 4ec <esp_mesh_pack_multi_routing_table+0x4a4> */
  L_0085: a10 = LD32(a3 + 0x158);  /* 0085 */
  a3 = 0x2ef;  /* 0088 */
  __asm__ volatile("" ::: "memory");  /* 008b: memw */
  /* 008e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0091: -> "mesh_route.c" */
  goto L_00c7;  /* 0094: j */
  L_009a: if (a4 != 0) goto L_00e1;  /* 009a: bnez a4, e1 <esp_mesh_pack_multi_routing_table+0x99> */
  L_009d: a2 = (u32)&g_log_level + 0x0;  /* 009d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00a0 */
  a2 = 0x00004008u;  /* 00a3: l32r = 16392 */
  if (a3 >= 3u) goto L_00ac;  /* 00a6: bgeui a3, 3, ac <esp_mesh_pack_multi_routing_table+0x64> */
  L_00a9: goto L_04ec;  /* 00a9: j */
  L_00ac: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00ac: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00af */
  if (a3 == 0) goto L_04ec;  /* 00b2: beqz a3, 4ec <esp_mesh_pack_multi_routing_table+0x4a4> */
  L_00b5: a4 = LD32(a3 + 0x150);  /* 00b5 */
  if (a4 == 0) goto L_04ec;  /* 00b8: beqz a4, 4ec <esp_mesh_pack_multi_routing_table+0x4a4> */
  L_00bb: a10 = LD32(a3 + 0x158);  /* 00bb */
  a3 = 0x2f0;  /* 00be */
  /* 00c1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00c4: -> "mesh_route.c" */
  L_00c7: a13 = a10;  /* 00c7 */
  a14 = a11;  /* 00c9 */
  a10 = 3;  /* 00cb */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00cd: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00d0: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 00d3 */
  __asm__ volatile("" ::: "memory");  /* 00d6: memw */
  /* 00d9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_04ec;  /* 00dc: j */
  L_00e1: a9 = (u32)&g_mesh_conn + 0x0;  /* 00e1: l32r -> global */
  a7 = a5;  /* 00e4 */
  a8 = 10;  /* 00e6 */
  a10 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 00e8: l32r -> .bss.mesh_route_table (same-object static) */
  ST16(a1 + 0x20, a5);  /* 00eb */
  __asm__ volatile("" ::: "memory");  /* 00ee: memw */
  /* 00f1: loop (hardware loop over a8, 116 <esp_mesh_pack_multi_routing_table+0xce>..0116) */ goto L_0116;
  a6 = a7 << 6;  /* 00f4 */
  a6 = a9 + a6;  /* 00f7 */
  a6 = LD32(a6 + 0x4);  /* 00f9 */
  if (((a6 >> 16) & 1) == 0) goto L_0114;  /* 00fb: bbci a6, 16, 114 <esp_mesh_pack_multi_routing_table+0xcc> */
  L_00fe: a6 = a7 + (a10 << 1);  /* 00fe */
  a5 = a5 + (1);  /* 0101 */
  a11 = LD8U(a6 + 0x0);  /* 0103 */
  a6 = LD8U(a6 + 0x1);  /* 0106 */
  a6 = a6 << 8;  /* 0109 */
  a6 = a6 | a11;  /* 010c */
  a5 = a5 + a6;  /* 010f */
  a5 = (a5 >> 16) & 0x1;  /* 0111: extui width 1 */
  L_0114: a7 = a7 + (1);  /* 0114 */
  a3 = (u32)&g_mesh_topology + 0x0;  /* 0116: l32r -> global */
  a6 = 162;  /* 0119 */
  a10 = 139;  /* 011c */
  a15 = a5;  /* 011f */
  a7 = LD32(a3 + 0x0);  /* 0121 */
  if (a7 != 0) a10 = a6;  /* 0123 */
  a6 = LD8U(a4 + 0x6);  /* 0126 */
  if ((i32)a10 < (i32)a5) goto L_0140;  /* 0129: blt a10, a5, 140 <esp_mesh_pack_multi_routing_table+0xf8> */
  L_012c: a7 = -128;  /* 012c */
  a6 = a6 & a7;  /* 012f */
  ST8(a4 + 0x6, a6);  /* 0132 */
  __asm__ volatile("" ::: "memory");  /* 0135: memw */
  __asm__ volatile("" ::: "memory");  /* 0138: memw */
  goto L_01da;  /* 013b: j */
  L_0140: a9 = LD16U(a4 + 0x6);  /* 0140 */
  a11 = -128;  /* 0143 */
  a9 = a9 + (1);  /* 0146 */
  a7 = (a9 >> 7) & 0x1;  /* 0148: extui width 1 */
  a6 = a6 & a11;  /* 014b */
  a9 = LD16U(a4 + 0x8);  /* 014e */
  a6 = a6 | a7;  /* 0151 */
  a9 = a5 - a9;  /* 0154: sub */
  ST8(a4 + 0x6, a6);  /* 0157 */
  __asm__ volatile("" ::: "memory");  /* 015a: memw */
  if ((i32)a10 >= (i32)a9) goto L_0172;  /* 015d: bge a10, a9, 172 <esp_mesh_pack_multi_routing_table+0x12a> */
  L_0160: a7 = (a7 & 0xFFFFu) * (a10 & 0xFFFFu);  /* 0160: mul16u */
  a5 = a10;  /* 0163 */
  ST16(a4 + 0x8, a7);  /* 0165 */
  __asm__ volatile("" ::: "memory");  /* 0168: memw */
  __asm__ volatile("" ::: "memory");  /* 016b: memw */
  goto L_018c;  /* 016e: j */
  L_0172: a7 = a7 + (-1);  /* 0172 */
  a7 = (a7 & 0xFFFFu) * (a10 & 0xFFFFu);  /* 0174: mul16u */
  ST16(a4 + 0x8, a5);  /* 0177 */
  a5 = a5 - a7;  /* 017a: sub */
  a7 = 127;  /* 017d */
  a6 = a6 | a7;  /* 0180 */
  a5 = (a5 >> 16) & 0x1;  /* 0183: extui width 1 */
  ST8(a4 + 0x6, a6);  /* 0186 */
  __asm__ volatile("" ::: "memory");  /* 0189: memw */
  L_018c: a6 = (u32)&g_log_level + 0x0;  /* 018c: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 018f */
  if (a6 < 3u) goto L_01da;  /* 0191: bltui a6, 3, 1da <esp_mesh_pack_multi_routing_table+0x192> */
  L_0194: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0194: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 0197 */
  if (a6 == 0) goto L_01da;  /* 0199: beqz.n a6, 1da <esp_mesh_pack_multi_routing_table+0x192> */
  L_019b: a7 = LD32(a6 + 0x150);  /* 019b */
  if (a7 == 0) goto L_01da;  /* 019e: beqz.n a7, 1da <esp_mesh_pack_multi_routing_table+0x192> */
  L_01a0: a10 = LD32(a6 + 0x158);  /* 01a0 */
  ST32(a1 + 0x40, a15);  /* 01a3 */
  __asm__ volatile("" ::: "memory");  /* 01a6: memw */
  /* 01a9: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01ac */
  a10 = 3;  /* 01ae */
  a6 = LD16U(a4 + 0x8);  /* 01b0 */
  ST32(a1 + 0x10, a6);  /* 01b3 */
  a6 = LD16U(a4 + 0x6);  /* 01b5 */
  a6 = (a6 >> 7) & 0x1;  /* 01b8: extui width 1 */
  ST32(a1 + 0xc, a6);  /* 01bb */
  a6 = LD16U(a4 + 0xc);  /* 01bd */
  ST32(a1 + 0x8, a6);  /* 01c0 */
  a6 = LD8U(a4 + 0xa);  /* 01c2 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01c5: -> "mesh_route.c" */
  a14 = a11;  /* 01c8 */
  a15 = LD32(a1 + 0x40);  /* 01ca */
  a12 = (u32)(RODATA__rodata_esp_mesh_pack_multi_routing_table_str1_1 + 0x0);  /* 01cd: l32r -> .rodata.esp_mesh_pack_multi_routing_table.str1.1 */
  ST32(a1 + 0x4, a6);  /* 01d0 */
  ST32(a1 + 0x0, a5);  /* 01d2 */
  __asm__ volatile("" ::: "memory");  /* 01d4: memw */
  /* 01d7: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_01da: a7 = 0;  /* 01da */
  a10 = 1;  /* 01dc */
  a9 = a7;  /* 01de */
  a6 = LD8U(a4 + 0x6);  /* 01e0 */
  a12 = a5;  /* 01e3 */
  a11 = (a6 >> 7) & 0x1;  /* 01e5: extui width 1 */
  a6 = a11 + (-127);  /* 01e8 */
  if (a11 != 0) a9 = a10;  /* 01eb */
  if (a6 == 0) a10 = a7;  /* 01ee */
  a6 = a9 & a10;  /* 01f1 */
  a6 = a6 << 7;  /* 01f4 */
  a11 = a11 | a6;  /* 01f7 */
  ST8(a4 + 0x6, a11);  /* 01fa */
  __asm__ volatile("" ::: "memory");  /* 01fd: memw */
  a10 = a2;  /* 0200 */
  a11 = a1 + (32);  /* 0202 */
  a13 = LD16U(a4 + 0x6);  /* 0205 */
  a13 = (a13 >> 7) & 0x1;  /* 0208: extui width 1 */
  a13 = a13 | a6;  /* 020b */
  a6 = LD32(a3 + 0x0);  /* 020e */
  if (a6 != a7) goto L_0234;  /* 0210: bne a6, a7, 234 <esp_mesh_pack_multi_routing_table+0x1ec> */
  L_0213: __asm__ volatile("" ::: "memory");  /* 0213: memw */
  a8 = (u32)&mesh_pack_rmv_announcement;  /* 0216: l32r -> func addr */
  a2 = mesh_pack_rmv_announcement(a2, a3, a4, a5, a6, a7);  /* 0219: callx a8 via reloc-expand */
  a7 = 153;  /* 021c */
  a3 = a10 + a7;  /* 021f */
  ST32(a1 + 0x38, a3);  /* 0221 */
  a2 = a10;  /* 0223 */
  ST32(a1 + 0x34, a6);  /* 0225 */
  if (a10 != 0) goto L_0245;  /* 0227: bnez.n a10, 245 <esp_mesh_pack_multi_routing_table+0x1fd> */
  L_0229: a2 = 0x00004007u;  /* 0229: l32r = 16391 */
  __asm__ volatile("" ::: "memory");  /* 022c: memw */
  goto L_04ec;  /* 022f: j */
  L_0234: a8 = (u32)&mesh_pack_rmv_announcement;  /* 0234: l32r -> func addr */
  a2 = mesh_pack_rmv_announcement(a2, a3, a4, a5, a6, a7);  /* 0237: callx a8 via reloc-expand */
  ST32(a1 + 0x34, a10);  /* 023a */
  if (a10 == 0) goto L_0229;  /* 023c: beqz a10, 229 <esp_mesh_pack_multi_routing_table+0x1e1> */
  L_023f: a8 = a10 + (10);  /* 023f */
  a2 = a7;  /* 0241 */
  ST32(a1 + 0x38, a8);  /* 0243 */
  L_0245: a7 = 0;  /* 0245 */
  a3 = a7;  /* 0247 */
  a6 = LD8U(a4 + 0xa);  /* 0249 */
  __asm__ volatile("" ::: "memory");  /* 024c: memw */
  goto L_04ac;  /* 024f: j */
  L_0255: a11 = (u32)&g_mesh_conn + 0x0;  /* 0255: l32r -> global */
  a9 = a6 << 6;  /* 0258 */
  a10 = a11 + a9;  /* 025b */
  a10 = LD32(a10 + 0x4);  /* 025d */
  if (((a10 >> 16) & 1) != 0) goto L_0265;  /* 025f: bbsi a10, 16, 265 <esp_mesh_pack_multi_routing_table+0x21d> */
  L_0262: goto L_04aa;  /* 0262: j */
  L_0265: a10 = LD8U(a4 + 0xa);  /* 0265 */
  if (a10 != 0) goto L_0270;  /* 0268: bnez.n a10, 270 <esp_mesh_pack_multi_routing_table+0x228> */
  L_026a: a12 = LD16U(a4 + 0xc);  /* 026a */
  if (a12 == 0) goto L_03e6;  /* 026d: beqz a12, 3e6 <esp_mesh_pack_multi_routing_table+0x39e> */
  L_0270: if (a6 == a10) goto L_0276;  /* 0270: beq a6, a10, 276 <esp_mesh_pack_multi_routing_table+0x22e> */
  L_0273: goto L_03e6;  /* 0273: j */
  L_0276: a9 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0276: l32r -> .bss.mesh_route_table (same-object static) */
  a13 = a6 + (a9 << 1);  /* 0279 */
  a10 = LD8U(a13 + 0x1);  /* 027c */
  a10 = a10 << 8;  /* 027f */
  a11 = LD8U(a13 + 0x0);  /* 0282 */
  a10 = a10 | a11;  /* 0285 */
  a11 = LD16U(a4 + 0xc);  /* 0288 */
  a10 = a10 - a11;  /* 028b: sub */
  if ((i32)a10 >= 1) goto L_0294;  /* 028e: bgei a10, 1, 294 <esp_mesh_pack_multi_routing_table+0x24c> */
  L_0291: goto L_03d8;  /* 0291: j */
  L_0294: a11 = a6 + (8);  /* 0294 */
  a11 = a11 + (a9 << 2);  /* 0296 */
  a9 = LD8U(a11 + 0x9);  /* 0299 */
  a9 = a9 << 8;  /* 029c */
  a12 = LD8U(a11 + 0x8);  /* 029f */
  a9 = a9 | a12;  /* 02a2 */
  a12 = LD8U(a11 + 0xa);  /* 02a5 */
  a12 = a12 << 16;  /* 02a8 */
  a12 = a12 | a9;  /* 02ab */
  a9 = LD8U(a11 + 0xb);  /* 02ae */
  a9 = a9 << 24;  /* 02b1 */
  a9 = a9 | a12;  /* 02b4 */
  if (a9 == 0) goto L_03d8;  /* 02b7: beqz a9, 3d8 <esp_mesh_pack_multi_routing_table+0x390> */
  L_02ba: a9 = a5 - a7;  /* 02ba: sub */
  a9 = ((i32)a9 < (i32)a10) ? a9 : a10;  /* 02bd: min */
  a10 = (u32)&g_log_level + 0x0;  /* 02c0: l32r -> global */
  a10 = LD32(a10 + 0x0);  /* 02c3 */
  if (a10 >= 3u) goto L_02cb;  /* 02c5: bgeui a10, 3, 2cb <esp_mesh_pack_multi_routing_table+0x283> */
  L_02c8: goto L_0363;  /* 02c8: j */
  L_02cb: a10 = (u32)&g_osi_funcs_p + 0x0;  /* 02cb: l32r -> global */
  a10 = LD32(a10 + 0x0);  /* 02ce */
  if (a10 == 0) goto L_0363;  /* 02d0: beqz a10, 363 <esp_mesh_pack_multi_routing_table+0x31b> */
  L_02d3: a8 = LD32(a10 + 0x150);  /* 02d3 */
  if (a8 == 0) goto L_0363;  /* 02d6: beqz a8, 363 <esp_mesh_pack_multi_routing_table+0x31b> */
  L_02d9: a10 = LD32(a10 + 0x158);  /* 02d9 */
  ST32(a1 + 0x3c, a8);  /* 02dc */
  ST32(a1 + 0x48, a9);  /* 02de */
  ST32(a1 + 0x40, a11);  /* 02e1 */
  ST32(a1 + 0x44, a13);  /* 02e4 */
  __asm__ volatile("" ::: "memory");  /* 02e7: memw */
  /* 02ea: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a11 = LD32(a1 + 0x40);  /* 02ed */
  a14 = LD8U(a11 + 0x9);  /* 02f0 */
  a14 = a14 << 8;  /* 02f3 */
  a12 = LD8U(a11 + 0x8);  /* 02f6 */
  a14 = a14 | a12;  /* 02f9 */
  a12 = LD8U(a11 + 0xa);  /* 02fc */
  a12 = a12 << 16;  /* 02ff */
  a12 = a12 | a14;  /* 0302 */
  a11 = LD8U(a11 + 0xb);  /* 0305 */
  a11 = a11 << 24;  /* 0308 */
  a11 = a11 | a12;  /* 030b */
  a12 = LD16U(a4 + 0xc);  /* 030e */
  a12 = a12 + (a12 << 1);  /* 0311 */
  a12 = a12 + (a11 << 1);  /* 0314 */
  a9 = LD32(a1 + 0x48);  /* 0317 */
  a13 = LD32(a1 + 0x44);  /* 031a */
  a15 = LD8U(a12 + 0x0);  /* 031d */
  ST32(a1 + 0x1c, a9);  /* 0320 */
  ST32(a1 + 0x18, a7);  /* 0322 */
  a14 = LD8U(a13 + 0x0);  /* 0324 */
  a13 = LD8U(a13 + 0x1);  /* 0327 */
  a13 = a13 << 8;  /* 032a */
  a13 = a13 | a14;  /* 032d */
  ST32(a1 + 0x14, a13);  /* 0330 */
  a13 = LD8U(a12 + 0x5);  /* 0332 */
  ST32(a1 + 0x10, a13);  /* 0335 */
  a13 = LD8U(a12 + 0x4);  /* 0337 */
  ST32(a1 + 0xc, a13);  /* 033a */
  a13 = LD8U(a12 + 0x3);  /* 033c */
  ST32(a1 + 0x8, a13);  /* 033f */
  a13 = LD8U(a12 + 0x2);  /* 0341 */
  ST32(a1 + 0x4, a13);  /* 0344 */
  a13 = a10;  /* 0346 */
  a10 = 3;  /* 0348 */
  a12 = LD8U(a12 + 0x1);  /* 034a */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 034d: -> "mesh_route.c" */
  a14 = a11;  /* 0350 */
  ST32(a1 + 0x0, a12);  /* 0352 */
  a8 = LD32(a1 + 0x3c);  /* 0354 */
  a12 = (u32)(RODATA__rodata_esp_mesh_pack_multi_routing_table_str1_1 + 0x0);  /* 0357: l32r -> .rodata.esp_mesh_pack_multi_routing_table.str1.1 */
  __asm__ volatile("" ::: "memory");  /* 035a: memw */
  /* 035d: INDIRECT callx a8 <- mem[a1+0x3c]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x48);  /* 0360 */
  L_0363: a10 = a6 + (8);  /* 0363 */
  a13 = a9 + (a9 << 1);  /* 0365 */
  a13 = a13 + a13;  /* 0368 */
  a11 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 036a: l32r -> .bss.mesh_route_table (same-object static) */
  a10 = a10 + (a11 << 2);  /* 036d */
  a12 = LD8U(a10 + 0x9);  /* 0370 */
  a12 = a12 << 8;  /* 0373 */
  a11 = LD8U(a10 + 0x8);  /* 0376 */
  a12 = a12 | a11;  /* 0379 */
  a11 = LD8U(a10 + 0xa);  /* 037c */
  a11 = a11 << 16;  /* 037f */
  a11 = a11 | a12;  /* 0382 */
  a12 = a13;  /* 0385 */
  a10 = LD8U(a10 + 0xb);  /* 0387 */
  a10 = a10 << 24;  /* 038a */
  a10 = a10 | a11;  /* 038d */
  a11 = LD16U(a4 + 0xc);  /* 0390 */
  a11 = a11 + (a11 << 1);  /* 0393 */
  a11 = a11 + (a10 << 1);  /* 0396 */
  a8 = LD32(a1 + 0x38);  /* 0399 */
  a10 = a8 + a3;  /* 039b */
  ST32(a1 + 0x48, a9);  /* 039d */
  ST32(a1 + 0x44, a13);  /* 03a0 */
  __asm__ volatile("" ::: "memory");  /* 03a3: memw */
  a8 = (u32)&memcpy + 0x0;  /* 03a6: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 03a9: callx a8 (libc, via reloc-expand) */
  a11 = 162;  /* 03ac */
  a10 = (u32)&g_mesh_topology + 0x0;  /* 03af: l32r -> global */
  a9 = LD32(a1 + 0x48);  /* 03b2 */
  a7 = a7 + a9;  /* 03b5 */
  a12 = LD32(a10 + 0x0);  /* 03b7 */
  a10 = 139;  /* 03b9 */
  if (a12 != 0) a10 = a11;  /* 03bc */
  a13 = LD32(a1 + 0x44);  /* 03bf */
  if ((i32)a7 < (i32)a10) goto L_03d6;  /* 03c2: blt a7, a10, 3d6 <esp_mesh_pack_multi_routing_table+0x38e> */
  L_03c5: a5 = LD16U(a4 + 0xc);  /* 03c5 */
  a9 = a9 + a5;  /* 03c8 */
  ST8(a4 + 0xa, a6);  /* 03ca */
  __asm__ volatile("" ::: "memory");  /* 03cd: memw */
  __asm__ volatile("" ::: "memory");  /* 03d0: memw */
  goto L_049b;  /* 03d3: j */
  L_03d6: a3 = a3 + a13;  /* 03d6 */
  L_03d8: a9 = 0;  /* 03d8 */
  ST16(a4 + 0xc, a9);  /* 03da */
  __asm__ volatile("" ::: "memory");  /* 03dd: memw */
  __asm__ volatile("" ::: "memory");  /* 03e0: memw */
  goto L_04aa;  /* 03e3: j */
  L_03e6: a8 = LD32(a1 + 0x38);  /* 03e6 */
  a11 = a11 + a9;  /* 03e8 */
  a10 = a8 + a3;  /* 03ea */
  a12 = 6;  /* 03ec */
  a8 = (u32)&memcpy + 0x0;  /* 03ee: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 03f1: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 03f4: l32r -> global */
  a15 = 162;  /* 03f7 */
  a14 = 139;  /* 03fa */
  a9 = a15;  /* 03fd */
  a7 = a7 + (1);  /* 03ff */
  a10 = LD32(a8 + 0x0);  /* 0401 */
  if (a10 == 0) a9 = a14;  /* 0403 */
  if ((i32)a7 < (i32)a9) goto L_041c;  /* 0406: blt a7, a9, 41c <esp_mesh_pack_multi_routing_table+0x3d4> */
  L_0409: a5 = 0;  /* 0409 */
  ST8(a4 + 0xa, a6);  /* 040b */
  ST16(a4 + 0xc, a5);  /* 040e */
  __asm__ volatile("" ::: "memory");  /* 0411: memw */
  __asm__ volatile("" ::: "memory");  /* 0414: memw */
  goto L_04b4;  /* 0417: j */
  L_041c: a11 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 041c: l32r -> .bss.mesh_route_table (same-object static) */
  a3 = a3 + (6);  /* 041f */
  a10 = a6 + (a11 << 1);  /* 0421 */
  a9 = LD8U(a10 + 0x0);  /* 0424 */
  a10 = LD8U(a10 + 0x1);  /* 0427 */
  a10 = a10 << 8;  /* 042a */
  a10 = a10 | a9;  /* 042d */
  if (a10 == 0) goto L_04aa;  /* 0430: beqz a10, 4aa <esp_mesh_pack_multi_routing_table+0x462> */
  L_0433: a9 = a6 + (8);  /* 0433 */
  a9 = a9 + (a11 << 2);  /* 0435 */
  a12 = LD8U(a9 + 0x9);  /* 0438 */
  a12 = a12 << 8;  /* 043b */
  a11 = LD8U(a9 + 0x8);  /* 043e */
  a12 = a12 | a11;  /* 0441 */
  a11 = LD8U(a9 + 0xa);  /* 0444 */
  a11 = a11 << 16;  /* 0447 */
  a12 = a11 | a12;  /* 044a */
  a11 = LD8U(a9 + 0xb);  /* 044d */
  a11 = a11 << 24;  /* 0450 */
  a11 = a11 | a12;  /* 0453 */
  if (a11 == 0) goto L_04aa;  /* 0456: beqz a11, 4aa <esp_mesh_pack_multi_routing_table+0x462> */
  L_0459: a9 = a5 - a7;  /* 0459: sub */
  a9 = ((i32)a9 < (i32)a10) ? a9 : a10;  /* 045c: min */
  a8 = LD32(a1 + 0x38);  /* 045f */
  a13 = a9 + (a9 << 1);  /* 0461 */
  a13 = a13 + a13;  /* 0464 */
  a12 = a13;  /* 0466 */
  a10 = a8 + a3;  /* 0468 */
  ST32(a1 + 0x48, a9);  /* 046b */
  ST32(a1 + 0x44, a13);  /* 046e */
  ST32(a1 + 0x3c, a14);  /* 0471 */
  ST32(a1 + 0x40, a15);  /* 0474 */
  __asm__ volatile("" ::: "memory");  /* 0477: memw */
  a8 = (u32)&memcpy + 0x0;  /* 047a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 047d: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 0480: l32r -> global */
  a9 = LD32(a1 + 0x48);  /* 0483 */
  a7 = a7 + a9;  /* 0486 */
  a10 = LD32(a8 + 0x0);  /* 0488 */
  a14 = LD32(a1 + 0x3c);  /* 048a */
  a15 = LD32(a1 + 0x40);  /* 048c */
  if (a10 != 0) a14 = a15;  /* 048f */
  a13 = LD32(a1 + 0x44);  /* 0492 */
  if ((i32)a7 < (i32)a14) goto L_04a8;  /* 0495: blt a7, a14, 4a8 <esp_mesh_pack_multi_routing_table+0x460> */
  L_0498: ST8(a4 + 0xa, a6);  /* 0498 */
  L_049b: ST16(a4 + 0xc, a9);  /* 049b */
  __asm__ volatile("" ::: "memory");  /* 049e: memw */
  __asm__ volatile("" ::: "memory");  /* 04a1: memw */
  goto L_04b4;  /* 04a4: j */
  L_04a8: a3 = a3 + a13;  /* 04a8 */
  L_04aa: a6 = a6 + (1);  /* 04aa */
  L_04ac: a8 = 9;  /* 04ac */
  if (a8 < a6) goto L_04b4;  /* 04ae: bltu a8, a6, 4b4 <esp_mesh_pack_multi_routing_table+0x46c> */
  L_04b1: goto L_0255;  /* 04b1: j */
  L_04b4: a4 = (u32)&g_mesh_topology + 0x0;  /* 04b4: l32r -> global */
  a3 = LD32(a1 + 0x34);  /* 04b7 */
  a4 = LD32(a4 + 0x0);  /* 04b9 */
  if (a4 != 0) a2 = a3;  /* 04bb */
  a5 = (a2 >> 8) & 0x1ff;  /* 04be: extui width 9 */
  a8 = LD32(a1 + 0x30);  /* 04c1 */
  a4 = a8 + (3);  /* 04c3 */
  ST8(a8 + 0x3, a2);  /* 04c5 */
  ST8(a8 + 0x4, a5);  /* 04c8 */
  a5 = (a2 >> 8) & 0x1ffff;  /* 04cb: extui width 17 */
  a2 = (a2 >> 8) & 0x1ffffff;  /* 04ce: extui width 25 */
  ST8(a8 + 0x5, a5);  /* 04d1 */
  ST8(a8 + 0x6, a2);  /* 04d4 */
  __asm__ volatile("" ::: "memory");  /* 04d7: memw */
  a2 = LD32(a1 + 0x20);  /* 04da */
  ST8(a8 + 0x1, a2);  /* 04dd */
  a2 = (a2 >> 8) & 0x1ff;  /* 04e0: extui width 9 */
  ST8(a8 + 0x2, a2);  /* 04e3 */
  __asm__ volatile("" ::: "memory");  /* 04e6: memw */
  a2 = 0;  /* 04e9 */
  L_04ec: __asm__ volatile("" ::: "memory");  /* 04ec: memw */
  return a2;  /* 04ef: retw.n */
}


/* esp_mesh_pack_rmv_announcement @ mesh_route.o 00000024 size 281B bind GLOBAL
 * Calls: mesh_pack_rmv_announcement, mesh_fill_rmv_sub_child | Data refs: g_mesh_is_root, g_mesh_ext_cfg, .bss.mesh_route_table, g_mesh_conn, g_mesh_topology
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_pack_rmv_announcement(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a4, a5, a6, a7, a8, a9;
  float F9;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a6 = (a2 >> 8) & 0x1;  /* 0027: extui width 1 */
  a2 = 0;  /* 002a */
  ST16(a1 + 0x0, a2);  /* 002c */
  __asm__ volatile("" ::: "memory");  /* 002f: memw */
  a2 = (u32)&g_mesh_is_root + 0x0;  /* 0032: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0035: memw */
  a4 = LD8U(a2 + 0x0);  /* 0038 */
  a2 = 0;  /* 003b */
  a4 = (a4 >> 8) & 0x1;  /* 003d: extui width 1 */
  if (a4 == a2) goto L_0046;  /* 0040: beq a4, a2, 46 <esp_mesh_pack_rmv_announcement+0x22> */
  L_0043: goto L_0138;  /* 0043: j */
  L_0046: a5 = (i32)(a6 << (32 - 7)) >> (32 - 7);  /* 0046: sext */
  if ((i32)a5 < (i32)a2) goto L_0074;  /* 0049: blt a5, a2, 74 <esp_mesh_pack_rmv_announcement+0x50> */
  L_004c: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 004c: l32r -> global */
  a2 = LD8U(a2 + 0xbd);  /* 004f */
  if ((i32)a5 >= (i32)a2) goto L_0074;  /* 0052: bge a5, a2, 74 <esp_mesh_pack_rmv_announcement+0x50> */
  L_0055: a2 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0055: l32r -> .bss.mesh_route_table (same-object static) */
  a5 = a5 + (a2 << 1);  /* 0058 */
  a4 = LD8U(a5 + 0x1);  /* 005b */
  a4 = a4 << 8;  /* 005e */
  a2 = LD8U(a5 + 0x0);  /* 0061 */
  a4 = a4 | a2;  /* 0064 */
  a4 = a4 + (1);  /* 0067 */
  a4 = (a4 >> 16) & 0x1;  /* 0069: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  goto L_00a5;  /* 006f: j */
  L_0074: a7 = (u32)&g_mesh_conn + 0x0;  /* 0074: l32r -> global */
  a2 = a4;  /* 0077 */
  a6 = 10;  /* 0079 */
  a8 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 007b: l32r -> .bss.mesh_route_table (same-object static) */
  /* 007e: loop (hardware loop over a6, a3 <esp_mesh_pack_rmv_announcement+0x7f>..00a3) */ goto L_00a3;
  a5 = a2 << 6;  /* 0081 */
  a5 = a7 + a5;  /* 0084 */
  a5 = LD32(a5 + 0x4);  /* 0086 */
  if (((a5 >> 16) & 1) == 0) goto L_00a1;  /* 0088: bbci a5, 16, a1 <esp_mesh_pack_rmv_announcement+0x7d> */
  L_008b: a5 = a2 + (a8 << 1);  /* 008b */
  a4 = a4 + (1);  /* 008e */
  a9 = LD8U(a5 + 0x0);  /* 0090 */
  a5 = LD8U(a5 + 0x1);  /* 0093 */
  a5 = a5 << 8;  /* 0096 */
  a5 = a5 | a9;  /* 0099 */
  a4 = a4 + a5;  /* 009c */
  a4 = (a4 >> 16) & 0x1;  /* 009e: extui width 1 */
  L_00a1: a2 = a2 + (1);  /* 00a1 */
  a6 = 10;  /* 00a3 */
  L_00a5: a2 = 0;  /* 00a5 */
  if (a4 != a2) goto L_00ad;  /* 00a7: bne a4, a2, ad <esp_mesh_pack_rmv_announcement+0x89> */
  L_00aa: goto L_0138;  /* 00aa: j */
  L_00ad: a8 = (u32)&g_mesh_topology + 0x0;  /* 00ad: l32r -> global */
  a7 = 139;  /* 00b0 */
  a6 = (i32)(a6 << (32 - 7)) >> (32 - 7);  /* 00b3: sext */
  a5 = LD32(a8 + 0x0);  /* 00b6 */
  a8 = 162;  /* 00b8 */
  if (a5 != 0) a7 = a8;  /* 00bb */
  a7 = ((i32)a4 < (i32)a7) ? a4 : a7;  /* 00be: min */
  if (a5 != a2) goto L_00e4;  /* 00c1: bne a5, a2, e4 <esp_mesh_pack_rmv_announcement+0xc0> */
  L_00c4: a11 = a1;  /* 00c4 */
  a13 = a5;  /* 00c6: mov */
  a12 = a7;  /* 00c9 */
  a10 = a6;  /* 00cb: mov */
  a8 = (u32)&mesh_pack_rmv_announcement;  /* 00ce: l32r -> func addr */
  a2 = mesh_pack_rmv_announcement(a2, a3);  /* 00d1: callx a8 via reloc-expand */
  a11 = 153;  /* 00d4 */
  a2 = a10;  /* 00d7 */
  a11 = a10 + a11;  /* 00d9 */
  if (a10 != 0) goto L_00f9;  /* 00db: bnez.n a10, f9 <esp_mesh_pack_rmv_announcement+0xd5> */
  L_00dd: a2 = 0x00004007u;  /* 00dd: l32r = 16391 */
  goto L_0138;  /* 00e0: j */
  L_00e4: a13 = a2;  /* 00e4 */
  a12 = a7;  /* 00e6 */
  a11 = a1;  /* 00e8 */
  a10 = a6;  /* 00ea */
  a8 = (u32)&mesh_pack_rmv_announcement;  /* 00ec: l32r -> func addr */
  a2 = mesh_pack_rmv_announcement(a2, a3);  /* 00ef: callx a8 via reloc-expand */
  a5 = a10;  /* 00f2 */
  if (a10 == 0) goto L_00dd;  /* 00f4: beqz a10, dd <esp_mesh_pack_rmv_announcement+0xb9> */
  L_00f7: a11 = a10 + (10);  /* 00f7 */
  L_00f9: a13 = a4;  /* 00f9 */
  a10 = a6;  /* 00fb */
  a12 = a7;  /* 00fd */
  a8 = (u32)&mesh_fill_rmv_sub_child;  /* 00ff: l32r -> func addr */
  a2 = mesh_fill_rmv_sub_child(a2, a3);  /* 0102: callx a8 via reloc-expand */
  a6 = (u32)&g_mesh_topology + 0x0;  /* 0105: l32r -> global */
  a4 = LD32(a6 + 0x0);  /* 0108 */
  if (a4 != 0) a2 = a5;  /* 010a */
  a5 = (a2 >> 8) & 0x1ff;  /* 010d: extui width 9 */
  a4 = a3 + (3);  /* 0110 */
  ST8(a3 + 0x3, a2);  /* 0112 */
  ST8(a3 + 0x4, a5);  /* 0115 */
  a5 = (a2 >> 8) & 0x1ffff;  /* 0118: extui width 17 */
  a2 = (a2 >> 8) & 0x1ffffff;  /* 011b: extui width 25 */
  ST8(a3 + 0x6, a2);  /* 011e */
  __asm__ volatile("" ::: "memory");  /* 0121: memw */
  a2 = LD32(a1 + 0x0);  /* 0124 */
  ST8(a3 + 0x1, a2);  /* 0126 */
  a2 = (a2 >> 8) & 0x1ff;  /* 0129: extui width 9 */
  ST8(a3 + 0x2, a2);  /* 012c */
  a2 = 0;  /* 012f */
  ST8(a3 + 0x5, a5);  /* 0132 */
  __asm__ volatile("" ::: "memory");  /* 0135: memw */
  L_0138: __asm__ volatile("" ::: "memory");  /* 0138: memw */
  return a2;  /* 013b: retw.n */
}


/* esp_mesh_print_route_table @ mesh_route.o 0000001c size 131B bind GLOBAL
 * Calls: memset, esp_wifi_vnd_mesh_get, esp_wifi_vnd_mesh_set | Data refs: g_mesh_topology, g_mesh_max_layer, g_mesh_ie, g_mesh_chain
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=7); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_print_route_table(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 001c: entry a1, 96 (frame 96 bytes) */
  a11 = 0;  /* 001f */
  a12 = 58;  /* 0022 */
  a10 = a1;  /* 0025 */
  a8 = (u32)&memset + 0x0;  /* 0027: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 002a: callx a8 (libc, via reloc-expand) */
  a8 = 0;  /* 002d */
  a11 = a1 + (58);  /* 0030 */
  a10 = a1;  /* 0033: mov */
  ST16(a1 + 0x3a, a8);  /* 0036 */
  ST16(a1 + 0x3c, a8);  /* 0039 */
  __asm__ volatile("" ::: "memory");  /* 003c: memw */
  __asm__ volatile("" ::: "memory");  /* 003f: memw */
  a8 = (u32)&esp_wifi_vnd_mesh_get + 0x0;  /* 0042: l32r -> global */
  a2 = esp_wifi_vnd_mesh_get(a2, a3, a4, a5, a6, a7);  /* 0045: callx a8 via reloc-expand */
  if (a10 != 0) goto L_009d;  /* 0048: bnez a10, 9d <esp_mesh_print_route_table+0x81> */
  L_004b: a8 = (u32)&g_mesh_topology + 0x0;  /* 004b: l32r -> global */
  a12 = LD32(a8 + 0x0);  /* 004e */
  a10 = LD16U(a1 + 0x3a);  /* 0050 */
  a8 = LD16U(a1 + 0x3c);  /* 0053 */
  if (a12 != 0) goto L_005e;  /* 0056: bnez.n a12, 5e <esp_mesh_print_route_table+0x42> */
  L_0058: a8 = LD8U(a1 + 0xf);  /* 0058 */
  a10 = LD8U(a1 + 0xe);  /* 005b */
  L_005e: a10 = a8 + a10;  /* 005e */
  a9 = (u32)&g_mesh_max_layer + 0x0;  /* 0060: l32r -> global */
  a9 = LD16U(a9 + 0x0);  /* 0063 */
  if (a10 == a9) goto L_009d;  /* 0066: beq a10, a9, 9d <esp_mesh_print_route_table+0x81> */
  L_0069: a10 = (u32)&g_mesh_ie + 0x0;  /* 0069: l32r -> global */
  a11 = (u32)&g_mesh_chain + 0x0;  /* 006c: l32r -> global */
  if (a12 != 0) goto L_0088;  /* 006f: bnez.n a12, 88 <esp_mesh_print_route_table+0x6c> */
  L_0071: a8 = (a8 >> 8) & 0x1;  /* 0071: extui width 1 */
  a9 = a9 - a8;  /* 0074: sub */
  ST8(a10 + 0xe, a9);  /* 0077 */
  ST8(a10 + 0xf, a8);  /* 007a */
  __asm__ volatile("" ::: "memory");  /* 007d: memw */
  __asm__ volatile("" ::: "memory");  /* 0080: memw */
  goto L_0094;  /* 0083: j */
  L_0088: a9 = a9 - a8;  /* 0088: sub */
  ST16(a11 + 0x0, a9);  /* 008b */
  ST16(a11 + 0x2, a8);  /* 008e */
  __asm__ volatile("" ::: "memory");  /* 0091: memw */
  L_0094: __asm__ volatile("" ::: "memory");  /* 0094: memw */
  a8 = (u32)&esp_wifi_vnd_mesh_set + 0x0;  /* 0097: l32r -> global */
  a2 = esp_wifi_vnd_mesh_set(a2, a3, a4, a5, a6, a7);  /* 009a: callx a8 via reloc-expand */
  L_009d: return a2;  /* 009d: retw.n */
}


/* esp_mesh_process_redundant_subchildren @ mesh_route.o 00000068 size 858B bind GLOBAL
 * Calls: mesh_malloc, memcmp, esp_mesh_remove_nonassociated_children, mesh_pack_rmv_announcement, memcpy, memset, esp_mesh_push_to_nwk_queue, mesh_free, esp_mesh_match_self | indirect[10]: mem[a3+0x158]; mem[a6+0xb8]; mem[a3+0x150]; mem[a10+0x158] | Data refs: .bss.mesh_route_table, .rodata.__func__$4, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, .rodata.esp_mesh_process_redundant_subchildren.str1.1, g_mesh_is_root, g_mesh_topology, g_mesh_conn, .rodata.esp_mesh_monitor_nonassociated_children.str1.1
 * Fidelity: medium - 10 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=9, refs=19); reloc-direct=9, funcdb-attributed=0, unknown-indirect=10 */
u32 esp_mesh_process_redundant_subchildren(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a5, a6, a7, a8, a9;
  float F4;
  /* 0068: entry a1, 0x140 (frame 0x140 bytes) */
  ST32(a1 + 0x104, a3);  /* 006b */
  a3 = (a2 >> 8) & 0x1;  /* 006e: extui width 1 */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 0071: sext */
  a4 = (a4 >> 16) & 0x1;  /* 0074: extui width 1 */
  a5 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0077: l32r -> .bss.mesh_route_table (same-object static) */
  ST32(a1 + 0x108, a3);  /* 007a */
  a3 = a2 + (8);  /* 007d */
  a3 = a3 + (a5 << 2);  /* 007f */
  a5 = a2 + (a5 << 1);  /* 0082 */
  a7 = LD8U(a3 + 0x9);  /* 0085 */
  a7 = a7 << 8;  /* 0088 */
  a6 = LD8U(a3 + 0x8);  /* 008b */
  a7 = a7 | a6;  /* 008e */
  a6 = LD8U(a3 + 0xa);  /* 0091 */
  a6 = a6 << 16;  /* 0094 */
  a6 = a6 | a7;  /* 0097 */
  a3 = LD8U(a3 + 0xb);  /* 009a */
  a3 = a3 << 24;  /* 009d */
  a3 = a3 | a6;  /* 00a0 */
  a6 = LD8U(a5 + 0x0);  /* 00a3 */
  a5 = LD8U(a5 + 0x1);  /* 00a6 */
  a5 = a5 << 8;  /* 00a9 */
  a5 = a5 | a6;  /* 00ac */
  a6 = LD32(a1 + 0x104);  /* 00af */
  if (a6 != 0) goto L_00ba;  /* 00b2: bnez.n a6, ba <esp_mesh_process_redundant_subchildren+0x52> */
  L_00b4: if (a4 != a6) goto L_00ba;  /* 00b4: bne a4, a6, ba <esp_mesh_process_redundant_subchildren+0x52> */
  L_00b7: goto L_0226;  /* 00b7: j */
  L_00ba: a6 = a5;  /* 00ba */
  a5 = a5 + (a5 << 1);  /* 00bc */
  a11 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 00bf: l32r -> .rodata.__func__$4 */
  a5 = a5 + a5;  /* 00c2 */
  a12 = 0x512;  /* 00c5 */
  a10 = a5;  /* 00c8: mov */
  __asm__ volatile("" ::: "memory");  /* 00cb: memw */
  a8 = (u32)&mesh_malloc + 0x0;  /* 00ce: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6);  /* 00d1: callx a8 via reloc-expand */
  ST32(a1 + 0x100, a10);  /* 00d4 */
  if (a10 == 0) goto L_00e5;  /* 00d7: beqz.n a10, e5 <esp_mesh_process_redundant_subchildren+0x7d> */
  L_00d9: a5 = 0;  /* 00d9 */
  a7 = a3;  /* 00db */
  a3 = a5;  /* 00dd */
  __asm__ volatile("" ::: "memory");  /* 00df: memw */
  goto L_0216;  /* 00e2: j */
  L_00e5: a2 = (u32)&g_log_level + 0x0;  /* 00e5: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00e8 */
  a2 = 0x00004007u;  /* 00eb: l32r = 16391 */
  if (a3 >= 3u) goto L_00f4;  /* 00ee: bgeui a3, 3, f4 <esp_mesh_process_redundant_subchildren+0x8c> */
  L_00f1: goto L_03c0;  /* 00f1: j */
  L_00f4: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 00f4: l32r -> global */
  a3 = LD32(a6 + 0x0);  /* 00f7 */
  if (a3 == 0) goto L_03c0;  /* 00f9: beqz a3, 3c0 <esp_mesh_process_redundant_subchildren+0x358> */
  L_00fc: a4 = LD32(a3 + 0x150);  /* 00fc */
  if (a4 == 0) goto L_03c0;  /* 00ff: beqz a4, 3c0 <esp_mesh_process_redundant_subchildren+0x358> */
  L_0102: a10 = LD32(a3 + 0x158);  /* 0102 */
  /* 0105: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 0108: mov */
  a6 = LD32(a6 + 0x0);  /* 010b */
  a10 = LD32(a6 + 0xb8);  /* 010e */
  /* 0111: INDIRECT callx a10 <- mem[a6+0xb8]; result unknown */ a2 = 0;
  a15 = 0x514;  /* 0114 */
  a13 = a3;  /* 0117 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0119: -> "mesh_route.c" */
  a14 = a11;  /* 011c */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_redundant_subchildren_str1_1 + 0x0);  /* 011e: l32r -> .rodata.esp_mesh_process_redundant_subchildren.str1.1 */
  ST32(a1 + 0x4, a10);  /* 0121 */
  a10 = 3;  /* 0123 */
  ST32(a1 + 0x0, a5);  /* 0125 */
  __asm__ volatile("" ::: "memory");  /* 0127: memw */
  /* 012a: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03c0;  /* 012d: j */
  L_0130: a11 = a13;  /* 0130 */
  a12 = 6;  /* 0132 */
  a10 = a7;  /* 0134 */
  ST32(a1 + 0x110, a9);  /* 0136 */
  ST32(a1 + 0x10c, a13);  /* 0139 */
  __asm__ volatile("" ::: "memory");  /* 013c: memw */
  a8 = (u32)&memcmp + 0x0;  /* 013f: l32r -> global */
  a2 = memcmp(a2, a3, a4);  /* 0142: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x10c);  /* 0145 */
  a13 = a13 + (6);  /* 0148 */
  a9 = LD32(a1 + 0x110);  /* 014a */
  if (a10 == 0) goto L_0212;  /* 014d: beqz a10, 212 <esp_mesh_process_redundant_subchildren+0x1aa> */
  L_0150: a9 = a9 + (1);  /* 0150 */
  L_0152: if ((i32)a9 < (i32)a4) goto L_0130;  /* 0152: blt a9, a4, 130 <esp_mesh_process_redundant_subchildren+0xc8> */
  L_0155: goto L_0397;  /* 0155: j */
  L_015a: a9 = LD32(a9 + 0x0);  /* 015a */
  if (a9 >= 3u) goto L_0162;  /* 015c: bgeui a9, 3, 162 <esp_mesh_process_redundant_subchildren+0xfa> */
  L_015f: goto L_0212;  /* 015f: j */
  L_0162: a9 = (u32)&g_osi_funcs_p + 0x0;  /* 0162: l32r -> global */
  a10 = LD32(a9 + 0x0);  /* 0165 */
  if (a10 == 0) goto L_0212;  /* 0167: beqz a10, 212 <esp_mesh_process_redundant_subchildren+0x1aa> */
  L_016a: a9 = LD32(a10 + 0x150);  /* 016a */
  if (a9 == 0) goto L_0212;  /* 016d: beqz a9, 212 <esp_mesh_process_redundant_subchildren+0x1aa> */
  L_0170: a10 = LD32(a10 + 0x158);  /* 0170 */
  ST32(a1 + 0x110, a9);  /* 0173 */
  __asm__ volatile("" ::: "memory");  /* 0176: memw */
  /* 0179: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a15 = 0x527;  /* 017c */
  a13 = a10;  /* 017f */
  ST32(a1 + 0x24, a5);  /* 0181 */
  ST32(a1 + 0x20, a4);  /* 0183 */
  ST32(a1 + 0x1c, a6);  /* 0185 */
  a12 = LD8U(a7 + 0x5);  /* 0187 */
  ST32(a1 + 0x18, a12);  /* 018a */
  a12 = LD8U(a7 + 0x4);  /* 018c */
  ST32(a1 + 0x14, a12);  /* 018f */
  a12 = LD8U(a7 + 0x3);  /* 0191 */
  ST32(a1 + 0x10, a12);  /* 0194 */
  a12 = LD8U(a7 + 0x2);  /* 0196 */
  ST32(a1 + 0xc, a12);  /* 0199 */
  a12 = LD8U(a7 + 0x1);  /* 019b */
  ST32(a1 + 0x8, a12);  /* 019e */
  a12 = LD8U(a7 + 0x0);  /* 01a0 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01a3: -> "mesh_route.c" */
  a14 = a11;  /* 01a6 */
  ST32(a1 + 0x4, a12);  /* 01a8 */
  ST32(a1 + 0x0, a3);  /* 01aa */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_redundant_subchildren_str1_1 + 0x0);  /* 01ac: l32r -> .rodata.esp_mesh_process_redundant_subchildren.str1.1 */
  __asm__ volatile("" ::: "memory");  /* 01af: memw */
  goto L_0207;  /* 01b2: j */
  L_01b5: a9 = LD32(a9 + 0x0);  /* 01b5 */
  if (a9 < 3u) goto L_0212;  /* 01b7: bltui a9, 3, 212 <esp_mesh_process_redundant_subchildren+0x1aa> */
  L_01ba: a9 = (u32)&g_osi_funcs_p + 0x0;  /* 01ba: l32r -> global */
  a10 = LD32(a9 + 0x0);  /* 01bd */
  if (a10 == 0) goto L_0212;  /* 01bf: beqz a10, 212 <esp_mesh_process_redundant_subchildren+0x1aa> */
  L_01c2: a9 = LD32(a10 + 0x150);  /* 01c2 */
  if (a9 == 0) goto L_0212;  /* 01c5: beqz a9, 212 <esp_mesh_process_redundant_subchildren+0x1aa> */
  L_01c8: a10 = LD32(a10 + 0x158);  /* 01c8 */
  ST32(a1 + 0x110, a9);  /* 01cb */
  __asm__ volatile("" ::: "memory");  /* 01ce: memw */
  /* 01d1: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a15 = 0x52c;  /* 01d4 */
  a13 = a10;  /* 01d7 */
  ST32(a1 + 0x24, a5);  /* 01d9 */
  ST32(a1 + 0x20, a4);  /* 01db */
  ST32(a1 + 0x1c, a6);  /* 01dd */
  a12 = LD8U(a7 + 0x5);  /* 01df */
  ST32(a1 + 0x18, a12);  /* 01e2 */
  a12 = LD8U(a7 + 0x4);  /* 01e4 */
  ST32(a1 + 0x14, a12);  /* 01e7 */
  a12 = LD8U(a7 + 0x3);  /* 01e9 */
  ST32(a1 + 0x10, a12);  /* 01ec */
  a12 = LD8U(a7 + 0x2);  /* 01ee */
  ST32(a1 + 0xc, a12);  /* 01f1 */
  a12 = LD8U(a7 + 0x1);  /* 01f3 */
  ST32(a1 + 0x8, a12);  /* 01f6 */
  a12 = LD8U(a7 + 0x0);  /* 01f8 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01fb: -> "mesh_route.c" */
  a14 = a11;  /* 01fe */
  ST32(a1 + 0x4, a12);  /* 0200 */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_redundant_subchildren_str1_1 + 0x0);  /* 0202: l32r -> .rodata.esp_mesh_process_redundant_subchildren.str1.1 */
  ST32(a1 + 0x0, a3);  /* 0205 */
  L_0207: a10 = 3;  /* 0207 */
  a9 = LD32(a1 + 0x110);  /* 0209 */
  __asm__ volatile("" ::: "memory");  /* 020c: memw */
  /* 020f: INDIRECT callx a9 <- mem[a1+0x110]; result unknown */ a2 = 0;
  L_0212: a3 = a3 + (1);  /* 0212 */
  a7 = a7 + (6);  /* 0214 */
  L_0216: if ((i32)a3 >= (i32)a6) goto L_0221;  /* 0216: bge a3, a6, 221 <esp_mesh_process_redundant_subchildren+0x1b9> */
  L_0219: a13 = LD32(a1 + 0x104);  /* 0219 */
  a9 = 0;  /* 021c */
  goto L_0152;  /* 021e: j */
  L_0221: a3 = LD32(a1 + 0x100);  /* 0221 */
  a6 = 1;  /* 0224 */
  L_0226: a4 = 1;  /* 0226 */
  a7 = 0;  /* 0228 */
  if (a3 == 0) a7 = a4;  /* 022a */
  a8 = (a7 >> 8) & 0x1;  /* 022d: extui width 1 */
  if (a7 != 0) goto L_0378;  /* 0230: bnez a7, 378 <esp_mesh_process_redundant_subchildren+0x310> */
  L_0233: if (a5 != 0) a4 = a8;  /* 0233 */
  if (a4 != 0) goto L_0378;  /* 0236: bnez a4, 378 <esp_mesh_process_redundant_subchildren+0x310> */
  L_0239: a4 = (u32)&g_mesh_is_root + 0x0;  /* 0239: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 023c: memw */
  a7 = LD8U(a4 + 0x0);  /* 023f */
  a7 = (a7 >> 8) & 0x1;  /* 0242: extui width 1 */
  if (a7 == 0) goto L_0259;  /* 0245: beqz.n a7, 259 <esp_mesh_process_redundant_subchildren+0x1f1> */
  L_0247: a10 = a2;  /* 0247 */
  a12 = a5;  /* 0249 */
  a11 = a3;  /* 024b: mov */
  a8 = (u32)&esp_mesh_remove_nonassociated_children;  /* 024e: l32r -> func addr */
  a2 = esp_mesh_remove_nonassociated_children(a2, a3, a4);  /* 0251: callx a8 via reloc-expand */
  a2 = a10;  /* 0254 */
  goto L_0384;  /* 0256: j */
  L_0259: a4 = (u32)&g_mesh_topology + 0x0;  /* 0259: l32r -> global */
  a8 = 162;  /* 025c */
  a11 = LD32(a4 + 0x0);  /* 025f */
  a4 = 139;  /* 0261 */
  if (a11 != 0) a4 = a8;  /* 0264 */
  a4 = ((i32)a4 < (i32)a5) ? a4 : a5;  /* 0267: min */
  if (a11 != 0) goto L_0286;  /* 026a: bnez.n a11, 286 <esp_mesh_process_redundant_subchildren+0x21e> */
  L_026c: a13 = a11;  /* 026c */
  a12 = a4;  /* 026e */
  a10 = a2;  /* 0270 */
  a8 = (u32)&mesh_pack_rmv_announcement;  /* 0272: l32r -> func addr */
  a2 = mesh_pack_rmv_announcement(a2, a3, a4);  /* 0275: callx a8 via reloc-expand */
  if (a10 == 0) goto L_037d;  /* 0278: beqz a10, 37d <esp_mesh_process_redundant_subchildren+0x315> */
  L_027b: a5 = 153;  /* 027b */
  a10 = a10 + a5;  /* 027e */
  goto L_0299;  /* 0280: j */
  L_0286: a13 = a7;  /* 0286 */
  a12 = a4;  /* 0288 */
  a11 = a7;  /* 028a */
  a10 = a2;  /* 028c */
  a8 = (u32)&mesh_pack_rmv_announcement;  /* 028e: l32r -> func addr */
  a2 = mesh_pack_rmv_announcement(a2, a3, a4);  /* 0291: callx a8 via reloc-expand */
  if (a10 == 0) goto L_037d;  /* 0294: beqz a10, 37d <esp_mesh_process_redundant_subchildren+0x315> */
  L_0297: a10 = a10 + (10);  /* 0297 */
  L_0299: a12 = a4 + (a4 << 1);  /* 0299 */
  a12 = a12 + a12;  /* 029c */
  a11 = a3;  /* 029f: mov */
  a8 = (u32)&memcpy + 0x0;  /* 02a2: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 02a5: callx a8 (libc, via reloc-expand) */
  a5 = (u32)&g_log_level + 0x0;  /* 02a8: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 02ab */
  if (a5 < 3u) goto L_031e;  /* 02ad: bltui a5, 3, 31e <esp_mesh_process_redundant_subchildren+0x2b6> */
  L_02b0: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 02b0: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 02b3 */
  if (a5 == 0) goto L_031e;  /* 02b5: beqz a5, 31e <esp_mesh_process_redundant_subchildren+0x2b6> */
  L_02b8: a7 = LD32(a5 + 0x150);  /* 02b8 */
  if (a7 == 0) goto L_031e;  /* 02bb: beqz a7, 31e <esp_mesh_process_redundant_subchildren+0x2b6> */
  L_02be: a10 = LD32(a5 + 0x158);  /* 02be */
  /* 02c1: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a8 = a2 << 6;  /* 02c4 */
  a13 = a10;  /* 02c7 */
  a5 = (u32)&g_mesh_conn + 0x0;  /* 02c9: l32r -> global */
  a10 = 3;  /* 02cc */
  a5 = a5 + a8;  /* 02ce */
  a8 = LD8U(a5 + 0x5);  /* 02d0 */
  a15 = LD8U(a3 + 0x0);  /* 02d3 */
  ST32(a1 + 0x30, a8);  /* 02d6 */
  a8 = LD8U(a5 + 0x4);  /* 02d8 */
  ST32(a1 + 0x2c, a8);  /* 02db */
  a8 = LD8U(a5 + 0x3);  /* 02dd */
  ST32(a1 + 0x28, a8);  /* 02e0 */
  a8 = LD8U(a5 + 0x2);  /* 02e2 */
  ST32(a1 + 0x24, a8);  /* 02e5 */
  a8 = LD8U(a5 + 0x1);  /* 02e7 */
  ST32(a1 + 0x20, a8);  /* 02ea */
  a5 = LD8U(a5 + 0x0);  /* 02ec */
  ST32(a1 + 0x18, a2);  /* 02ef */
  ST32(a1 + 0x1c, a5);  /* 02f1 */
  ST32(a1 + 0x14, a4);  /* 02f3 */
  a2 = LD8U(a3 + 0x5);  /* 02f5 */
  ST32(a1 + 0x10, a2);  /* 02f8 */
  a2 = LD8U(a3 + 0x4);  /* 02fa */
  ST32(a1 + 0xc, a2);  /* 02fd */
  a2 = LD8U(a3 + 0x3);  /* 02ff */
  ST32(a1 + 0x8, a2);  /* 0302 */
  a2 = LD8U(a3 + 0x2);  /* 0304 */
  ST32(a1 + 0x4, a2);  /* 0307 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0309: -> "mesh_route.c" */
  a14 = a11;  /* 030c: mov */
  a2 = LD8U(a3 + 0x1);  /* 030f */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_redundant_subchildren_str1_1 + 0x0);  /* 0312: l32r -> .rodata.esp_mesh_process_redundant_subchildren.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0315 */
  __asm__ volatile("" ::: "memory");  /* 0318: memw */
  /* 031b: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_031e: a11 = 0;  /* 031e */
  a12 = 180;  /* 0320 */
  a10 = a1 + (68);  /* 0323 */
  a8 = (u32)&memset + 0x0;  /* 0326: l32r -> global */
  a2 = memset(a2, a3, a4);  /* 0329: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x108);  /* 032c */
  a2 = 37;  /* 032f */
  a11 = 0;  /* 0331 */
  a10 = a1 + (64);  /* 0334 */
  ST32(a1 + 0x40, a2);  /* 0337 */
  a2 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 033a: sext */
  ST32(a1 + 0x48, a2);  /* 033d */
  __asm__ volatile("" ::: "memory");  /* 0340: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 0343: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4);  /* 0346: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0378;  /* 0349: beqz.n a10, 378 <esp_mesh_process_redundant_subchildren+0x310> */
  L_034b: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 034b: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 034e */
  if (a2 == 0) goto L_0378;  /* 0350: beqz.n a2, 378 <esp_mesh_process_redundant_subchildren+0x310> */
  L_0352: a4 = LD32(a2 + 0x150);  /* 0352 */
  if (a4 == 0) goto L_0378;  /* 0355: beqz a4, 378 <esp_mesh_process_redundant_subchildren+0x310> */
  L_0358: a10 = LD32(a2 + 0x158);  /* 0358 */
  a2 = 0x579;  /* 035b */
  /* 035e: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0361 */
  a10 = 1;  /* 0363 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0365: -> "mesh_route.c" */
  a14 = a11;  /* 0368 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 036a: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_monitor_nonassociated_children_str1_1 + 0x0);  /* 036d: l32r -> .rodata.esp_mesh_monitor_nonassociated_children.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0370 */
  __asm__ volatile("" ::: "memory");  /* 0372: memw */
  /* 0375: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0378: a2 = 0;  /* 0378 */
  goto L_0384;  /* 037a: j */
  L_037d: a2 = 0x00004007u;  /* 037d: l32r = 16391 */
  goto L_03c0;  /* 0380: j */
  L_0384: if (a6 == 0) goto L_03c0;  /* 0384: beqz.n a6, 3c0 <esp_mesh_process_redundant_subchildren+0x358> */
  L_0386: a11 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 0386: l32r -> .rodata.__func__$4 */
  a12 = 0x57c;  /* 0389 */
  a10 = a3;  /* 038c */
  a8 = (u32)&mesh_free + 0x0;  /* 038e: l32r -> global */
  a2 = mesh_free(a2, a3, a4);  /* 0391: callx a8 via reloc-expand */
  goto L_03c0;  /* 0394: j */
  L_0397: a8 = LD32(a1 + 0x100);  /* 0397 */
  a10 = a5 + (a5 << 1);  /* 039a */
  a12 = 6;  /* 039d */
  a11 = a7;  /* 039f */
  a10 = a10 + (a8 << 1);  /* 03a1 */
  a8 = (u32)&memcpy + 0x0;  /* 03a4: l32r -> global */
  a2 = memcpy(a2, a3, a4);  /* 03a7: callx a8 (libc, via reloc-expand) */
  a10 = a7;  /* 03aa */
  a5 = a5 + (1);  /* 03ac */
  a8 = (u32)&esp_mesh_match_self;  /* 03ae: l32r -> func addr */
  a2 = esp_mesh_match_self(a2, a3, a4, a5);  /* 03b1: callx a8 via reloc-expand */
  a9 = (u32)&g_log_level + 0x0;  /* 03b4: l32r -> global */
  a5 = (a5 >> 16) & 0x1;  /* 03b7: extui width 1 */
  if (a10 != 0) goto L_015a;  /* 03ba: bnez a10, 15a <esp_mesh_process_redundant_subchildren+0xf2> */
  L_03bd: goto L_01b5;  /* 03bd: j */
  L_03c0: return a2;  /* 03c0: retw.n */
}


/* esp_mesh_refresh_routing_table @ mesh_route.o 00000098 size 1666B bind GLOBAL
 * Calls: esp_mesh_get_child_idx, esp_mesh_check_multi_redundant_ack, esp_mesh_monitor_nonassociated_children, esp_mesh_get_ap_assoc_expire, memset, memcpy, esp_mesh_push_to_nwk_queue, esp_mesh_is_rt_change_debug, esp_mesh_remove_nonassociated_children, esp_mesh_combine_multi_redundant_ack, esp_mesh_process_redundant_subchildren, mesh_free | indirect[14]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x110]; mem[a2+0x158] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, g_mesh_topology, g_mesh_ext_cfg, g_mesh_conn, .bss.mesh_route_table, .rodata.esp_mesh_refresh_routing_table.str1.1, .rodata.esp_mesh_monitor_nonassociated_children.str1.1, mesh_multi_recv_ack, .rodata.__func__$1
 * Fidelity: medium - 14 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=12, refs=23); reloc-direct=12, funcdb-attributed=0, unknown-indirect=14 */
u32 esp_mesh_refresh_routing_table(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a7, a8, a9;
  /* 0098: entry a1, 0x150 (frame 0x150 bytes) */
  a7 = a2;  /* 009b */
  if (a2 != 0) goto L_00e1;  /* 009d: bnez a2, e1 <esp_mesh_refresh_routing_table+0x49> */
  L_00a0: a2 = (u32)&g_log_level + 0x0;  /* 00a0: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00a3 */
  a2 = 0x00004008u;  /* 00a5: l32r = 16392 */
  if (a3 >= 3u) goto L_00ae;  /* 00a8: bgeui a3, 3, ae <esp_mesh_refresh_routing_table+0x16> */
  L_00ab: goto L_0718;  /* 00ab: j */
  L_00ae: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00ae: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00b1 */
  if (a3 == 0) goto L_0718;  /* 00b3: beqz a3, 718 <esp_mesh_refresh_routing_table+0x680> */
  L_00b6: a4 = LD32(a3 + 0x150);  /* 00b6 */
  if (a4 == 0) goto L_0718;  /* 00b9: beqz a4, 718 <esp_mesh_refresh_routing_table+0x680> */
  L_00bc: a10 = LD32(a3 + 0x158);  /* 00bc */
  a3 = 0x5e6;  /* 00bf */
  /* 00c2: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00c5 */
  a10 = 3;  /* 00c7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00c9: -> "mesh_route.c" */
  a14 = a11;  /* 00cc */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00ce: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00d1: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 00d4 */
  __asm__ volatile("" ::: "memory");  /* 00d6: memw */
  /* 00d9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0718;  /* 00dc: j */
  L_00e1: a3 = LD8U(a7 + 0x1);  /* 00e1 */
  a3 = a3 << 8;  /* 00e4 */
  a2 = LD8U(a2 + 0x0);  /* 00e7 */
  a3 = a3 | a2;  /* 00ea */
  a2 = LD8U(a7 + 0x2);  /* 00ed */
  a2 = a2 << 16;  /* 00f0 */
  a2 = a2 | a3;  /* 00f3 */
  a4 = LD8U(a7 + 0x3);  /* 00f6 */
  a4 = a4 << 24;  /* 00f9 */
  a9 = a4 | a2;  /* 00fc */
  a3 = a9 + (-3);  /* 00ff */
  a2 = 0x00004008u;  /* 0102: l32r = 16392 */
  if (a3 < 3u) goto L_010b;  /* 0105: bltui a3, 3, 10b <esp_mesh_refresh_routing_table+0x73> */
  L_0108: goto L_0718;  /* 0108: j */
  L_010b: a3 = a7 + (14);  /* 010b */
  a10 = a3;  /* 010d: mov */
  ST32(a1 + 0x128, a9);  /* 0110 */
  __asm__ volatile("" ::: "memory");  /* 0113: memw */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 0116: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6);  /* 0119: callx a8 via reloc-expand */
  a2 = (a10 >> 8) & 0x1;  /* 011c: extui width 1 */
  a4 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 011f: sext */
  a9 = LD32(a1 + 0x128);  /* 0122 */
  ST32(a1 + 0x100, a2);  /* 0125 */
  a12 = (u32)&g_mesh_topology + 0x0;  /* 0128: l32r -> global */
  if (a9 != 5) goto L_0131;  /* 012b: bnei a9, 5, 131 <esp_mesh_refresh_routing_table+0x99> */
  L_012e: goto L_052c;  /* 012e: j */
  L_0131: a11 = a3;  /* 0131 */
  a10 = a4;  /* 0133 */
  ST32(a1 + 0x124, a12);  /* 0135 */
  __asm__ volatile("" ::: "memory");  /* 0138: memw */
  a8 = (u32)&esp_mesh_check_multi_redundant_ack;  /* 013b: l32r -> func addr */
  a2 = esp_mesh_check_multi_redundant_ack(a2, a3, a4, a5, a6);  /* 013e: callx a8 via reloc-expand */
  a9 = LD32(a1 + 0x128);  /* 0141 */
  a12 = LD32(a1 + 0x124);  /* 0144 */
  if (a9 == 3) goto L_014d;  /* 0147: beqi a9, 3, 14d <esp_mesh_refresh_routing_table+0xb5> */
  L_014a: goto L_052c;  /* 014a: j */
  L_014d: a2 = LD32(a12 + 0x0);  /* 014d */
  a4 = LD8U(a7 + 0x14);  /* 014f */
  if (a2 != 0) goto L_0174;  /* 0152: bnez.n a2, 174 <esp_mesh_refresh_routing_table+0xdc> */
  L_0154: a2 = LD8U(a7 + 0xac);  /* 0154 */
  a2 = a2 << 8;  /* 0157 */
  ST32(a1 + 0x104, a4);  /* 015a */
  a4 = LD8U(a7 + 0xab);  /* 015d */
  a2 = a2 | a4;  /* 0160 */
  a4 = a9;  /* 0163 */
  ST32(a1 + 0x100, a2);  /* 0165 */
  a2 = 154;  /* 0168 */
  a6 = LD8U(a7 + 0xad);  /* 016b */
  __asm__ volatile("" ::: "memory");  /* 016e: memw */
  goto L_019f;  /* 0171: j */
  L_0174: a2 = LD8U(a7 + 0x15);  /* 0174 */
  a2 = a2 << 8;  /* 0177 */
  a2 = a2 | a4;  /* 017a */
  a6 = LD8U(a7 + 0x1f);  /* 017d */
  a6 = a6 << 8;  /* 0180 */
  ST32(a1 + 0x104, a2);  /* 0183 */
  a2 = LD8U(a7 + 0x1e);  /* 0186 */
  a6 = a6 | a2;  /* 0189 */
  a2 = LD8U(a7 + 0x1d);  /* 018c */
  a2 = a2 << 8;  /* 018f */
  a4 = LD8U(a7 + 0x1c);  /* 0192 */
  a2 = a2 | a4;  /* 0195 */
  a4 = 4;  /* 0198 */
  ST32(a1 + 0x100, a2);  /* 019a */
  a2 = 12;  /* 019d */
  L_019f: a8 = a7 + (21);  /* 019f */
  a5 = 0;  /* 01a2 */
  a9 = a7 + (22);  /* 01a4 */
  __asm__ volatile("" ::: "memory");  /* 01a7: memw */
  goto L_01db;  /* 01aa: j */
  L_01ae: a10 = LD32(a12 + 0x0);  /* 01ae */
  a11 = a8;  /* 01b0 */
  if (a10 == 0) goto L_01ba;  /* 01b2: beqz.n a10, 1ba <esp_mesh_refresh_routing_table+0x122> */
  L_01b4: if (a5 != 0) goto L_01e1;  /* 01b4: bnez a5, 1e1 <esp_mesh_refresh_routing_table+0x149> */
  L_01b7: a11 = a9;  /* 01b7: mov */
  L_01ba: a10 = a3;  /* 01ba */
  ST32(a1 + 0x120, a8);  /* 01bc */
  a5 = a5 + (1);  /* 01bf */
  ST32(a1 + 0x128, a9);  /* 01c1 */
  ST32(a1 + 0x124, a12);  /* 01c4 */
  __asm__ volatile("" ::: "memory");  /* 01c7: memw */
  a8 = (u32)&esp_mesh_monitor_nonassociated_children;  /* 01ca: l32r -> func addr */
  a2 = esp_mesh_monitor_nonassociated_children(a2, a3, a4, a5, a6);  /* 01cd: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x120);  /* 01d0 */
  a8 = a8 + (6);  /* 01d3 */
  a12 = LD32(a1 + 0x124);  /* 01d5 */
  a9 = LD32(a1 + 0x128);  /* 01d8 */
  L_01db: a10 = LD32(a1 + 0x104);  /* 01db */
  if ((i32)a5 < (i32)a10) goto L_01ae;  /* 01de: blt a5, a10, 1ae <esp_mesh_refresh_routing_table+0x116> */
  L_01e1: a10 = a3;  /* 01e1 */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 01e3: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6);  /* 01e6: callx a8 via reloc-expand */
  a3 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 01e9: sext */
  if ((i32)a3 < 0) goto L_0518;  /* 01ec: bltz a3, 518 <esp_mesh_refresh_routing_table+0x480> */
  L_01ef: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 01ef: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 01f2 */
  if ((i32)a3 < (i32)a5) goto L_01fb;  /* 01f5: blt a3, a5, 1fb <esp_mesh_refresh_routing_table+0x163> */
  L_01f8: goto L_0518;  /* 01f8: j */
  L_01fb: a5 = a3 << 6;  /* 01fb */
  a8 = (u32)&g_mesh_conn + 0x0;  /* 01fe: l32r -> global */
  a12 = a8 + a5;  /* 0201 */
  a9 = LD32(a12 + 0x4);  /* 0203 */
  if (((a9 >> 16) & 1) != 0) goto L_020b;  /* 0205: bbsi a9, 16, 20b <esp_mesh_refresh_routing_table+0x173> */
  L_0208: goto L_0518;  /* 0208: j */
  L_020b: a2 = a2 - a4;  /* 020b: sub */
  a4 = 1;  /* 020e */
  a9 = LD8U(a7 + 0x5);  /* 0210 */
  a9 = a9 << 8;  /* 0213 */
  a10 = LD8U(a7 + 0x4);  /* 0216 */
  a9 = a9 | a10;  /* 0219 */
  a10 = LD8U(a7 + 0x6);  /* 021c */
  a10 = a10 << 16;  /* 021f */
  a10 = a10 | a9;  /* 0222 */
  a9 = LD8U(a7 + 0x7);  /* 0225 */
  a9 = a9 << 24;  /* 0228 */
  a9 = a9 | a10;  /* 022b */
  a2 = a9 - a2;  /* 022e: sub */
  a9 = 0;  /* 0231 */
  if (a2 == 0) a9 = a4;  /* 0233 */
  a2 = (a9 >> 8) & 0x1;  /* 0236: extui width 1 */
  if (a9 != 0) goto L_0518;  /* 0239: bnez a9, 518 <esp_mesh_refresh_routing_table+0x480> */
  L_023c: a8 = LD32(a1 + 0x104);  /* 023c */
  a6 = a8 - a6;  /* 023f: sub */
  if (a6 == 0) a4 = a2;  /* 0242 */
  if (a4 != 0) goto L_0518;  /* 0245: bnez a4, 518 <esp_mesh_refresh_routing_table+0x480> */
  L_0248: a2 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0248: l32r -> .bss.mesh_route_table (same-object static) */
  a2 = a3 + (a2 << 1);  /* 024b */
  a4 = LD8U(a2 + 0x0);  /* 024e */
  a2 = LD8U(a2 + 0x1);  /* 0251 */
  a2 = a2 << 8;  /* 0254 */
  a2 = a2 | a4;  /* 0257 */
  a4 = LD32(a1 + 0x100);  /* 025a */
  if (a2 >= a4) goto L_0263;  /* 025d: bgeu a2, a4, 263 <esp_mesh_refresh_routing_table+0x1cb> */
  L_0260: goto L_0500;  /* 0260: j */
  L_0263: a4 = LD32(a12 + 0x34);  /* 0263 */
  a2 = LD32(a12 + 0x30);  /* 0265 */
  a2 = a2 | a4;  /* 0267 */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 026a: l32r -> global */
  if (a2 != 0) goto L_0285;  /* 026d: bnez.n a2, 285 <esp_mesh_refresh_routing_table+0x1ed> */
  L_026f: a2 = LD32(a4 + 0x0);  /* 026f */
  a10 = LD32(a2 + 0x110);  /* 0271 */
  ST32(a1 + 0x124, a12);  /* 0274 */
  __asm__ volatile("" ::: "memory");  /* 0277: memw */
  /* 027a: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a12 = LD32(a1 + 0x124);  /* 027d */
  ST32(a12 + 0x30, a10);  /* 0280 */
  ST32(a12 + 0x34, a11);  /* 0282 */
  L_0285: a2 = LD32(a4 + 0x0);  /* 0285 */
  a10 = LD32(a2 + 0x110);  /* 0287 */
  __asm__ volatile("" ::: "memory");  /* 028a: memw */
  /* 028d: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a6 = (u32)&g_mesh_conn + 0x0;  /* 0290: l32r -> global */
  a2 = a6 + a5;  /* 0293 */
  a6 = LD32(a2 + 0x34);  /* 0295 */
  if ((i32)a11 < (i32)a6) goto L_02c6;  /* 0297: blt a11, a6, 2c6 <esp_mesh_refresh_routing_table+0x22e> */
  L_029a: if (a6 != a11) goto L_02a2;  /* 029a: bne a6, a11, 2a2 <esp_mesh_refresh_routing_table+0x20a> */
  L_029d: a2 = LD32(a2 + 0x30);  /* 029d */
  if (a10 < a2) goto L_02c6;  /* 029f: bltu a10, a2, 2c6 <esp_mesh_refresh_routing_table+0x22e> */
  L_02a2: a2 = LD32(a4 + 0x0);  /* 02a2 */
  a10 = LD32(a2 + 0x110);  /* 02a4 */
  /* 02a7: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a9 = 1;  /* 02aa */
  a8 = (u32)&g_mesh_conn + 0x0;  /* 02ac: l32r -> global */
  a2 = a8 + a5;  /* 02af */
  a6 = LD32(a2 + 0x30);  /* 02b1 */
  a6 = a10 - a6;  /* 02b3: sub */
  a2 = LD32(a2 + 0x34);  /* 02b6 */
  if (a10 < a6) goto L_02bd;  /* 02b8: bltu a10, a6, 2bd <esp_mesh_refresh_routing_table+0x225> */
  L_02bb: a9 = 0;  /* 02bb */
  L_02bd: a2 = a11 - a2;  /* 02bd: sub */
  a2 = a2 - a9;  /* 02c0: sub */
  goto L_02f4;  /* 02c3: j */
  L_02c6: a2 = LD32(a4 + 0x0);  /* 02c6 */
  a10 = LD32(a2 + 0x110);  /* 02c8 */
  /* 02cb: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a9 = -1;  /* 02ce */
  a6 = (u32)&g_mesh_conn + 0x0;  /* 02d0: l32r -> global */
  a2 = a6 + a5;  /* 02d3 */
  a6 = LD32(a2 + 0x30);  /* 02d5 */
  a6 = a6 ^ a9;  /* 02d7 */
  a10 = a6 + a10;  /* 02da */
  a9 = 1;  /* 02dc */
  a2 = LD32(a2 + 0x34);  /* 02de */
  if (a10 < a6) goto L_02e5;  /* 02e0: bltu a10, a6, 2e5 <esp_mesh_refresh_routing_table+0x24d> */
  L_02e3: a9 = 0;  /* 02e3 */
  L_02e5: a11 = a2 + a11;  /* 02e5 */
  a6 = a10 + (1);  /* 02e7 */
  a11 = a9 + a11;  /* 02e9 */
  a2 = 1;  /* 02eb */
  if (a6 < a10) goto L_02f2;  /* 02ed: bltu a6, a10, 2f2 <esp_mesh_refresh_routing_table+0x25a> */
  L_02f0: a2 = 0;  /* 02f0 */
  L_02f2: a2 = a2 + a11;  /* 02f2 */
  L_02f4: a8 = (u32)&g_mesh_conn + 0x0;  /* 02f4: l32r -> global */
  a6 = a6 >> 10;  /* 02f7 */
  a2 = a2 << 22;  /* 02fa */
  a2 = a2 | a6;  /* 02fd */
  a5 = a8 + a5;  /* 0300 */
  ST32(a5 + 0x38, a2);  /* 0302 */
  __asm__ volatile("" ::: "memory");  /* 0304: memw */
  a8 = (u32)&esp_mesh_get_ap_assoc_expire + 0x0;  /* 0307: l32r -> global */
  a2 = esp_mesh_get_ap_assoc_expire(a2, a3, a4, a5, a6);  /* 030a: callx a8 via reloc-expand */
  a6 = a10 << 5;  /* 030d */
  a6 = a6 - a10;  /* 0310: sub */
  a6 = a6 + (a10 << 2);  /* 0313 */
  a6 = a6 << 4;  /* 0316 */
  if (a6 < a2) goto L_031f;  /* 0319: bltu a6, a2, 31f <esp_mesh_refresh_routing_table+0x287> */
  L_031c: goto L_0414;  /* 031c: j */
  L_031f: a2 = (u32)&g_log_level + 0x0;  /* 031f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0322 */
  if (a2 >= 3u) goto L_032b;  /* 0325: bgeui a2, 3, 32b <esp_mesh_refresh_routing_table+0x293> */
  L_0328: goto L_0414;  /* 0328: j */
  L_032b: a2 = LD32(a4 + 0x0);  /* 032b */
  if (a2 == 0) goto L_0414;  /* 032e: beqz a2, 414 <esp_mesh_refresh_routing_table+0x37c> */
  L_0331: a6 = LD32(a2 + 0x150);  /* 0331 */
  if (a6 == 0) goto L_0414;  /* 0334: beqz a6, 414 <esp_mesh_refresh_routing_table+0x37c> */
  L_0337: a10 = LD32(a2 + 0x158);  /* 0337 */
  /* 033a: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 033d */
  a4 = LD8U(a7 + 0xf);  /* 033f */
  a2 = LD8U(a7 + 0xe);  /* 0342 */
  ST32(a1 + 0x10c, a4);  /* 0345 */
  a4 = LD8U(a7 + 0x5);  /* 0348 */
  a4 = a4 << 8;  /* 034b */
  ST32(a1 + 0x108, a2);  /* 034e */
  a2 = LD8U(a7 + 0x4);  /* 0351 */
  a4 = a4 | a2;  /* 0354 */
  a2 = LD8U(a7 + 0x6);  /* 0357 */
  a2 = a2 << 16;  /* 035a */
  a2 = a2 | a4;  /* 035d */
  a4 = LD8U(a7 + 0x7);  /* 0360 */
  a4 = a4 << 24;  /* 0363 */
  a4 = a4 | a2;  /* 0366 */
  a8 = LD8U(a7 + 0x10);  /* 0369 */
  a2 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 036c: l32r -> .bss.mesh_route_table (same-object static) */
  a2 = a3 + (a2 << 1);  /* 036f */
  ST32(a1 + 0x110, a8);  /* 0372 */
  a10 = LD8U(a2 + 0x0);  /* 0375 */
  a2 = LD8U(a2 + 0x1);  /* 0378 */
  a2 = a2 << 8;  /* 037b */
  a2 = a2 | a10;  /* 037e */
  a2 = a2 + (1);  /* 0381 */
  a12 = LD16U(a5 + 0x2a);  /* 0383 */
  a8 = LD32(a5 + 0x38);  /* 0386 */
  a15 = LD8U(a7 + 0x11);  /* 0388 */
  a14 = LD8U(a7 + 0x12);  /* 038b */
  a9 = LD8U(a7 + 0x13);  /* 038e */
  ST32(a1 + 0x120, a8);  /* 0391 */
  ST32(a1 + 0x128, a9);  /* 0394 */
  ST32(a1 + 0x124, a12);  /* 0397 */
  ST32(a1 + 0x114, a13);  /* 039a */
  ST32(a1 + 0x11c, a14);  /* 039d */
  ST32(a1 + 0x118, a15);  /* 03a0 */
  __asm__ volatile("" ::: "memory");  /* 03a3: memw */
  a8 = (u32)&esp_mesh_get_ap_assoc_expire + 0x0;  /* 03a6: l32r -> global */
  a2 = esp_mesh_get_ap_assoc_expire(a2, a3, a4, a5, a6);  /* 03a9: callx a8 via reloc-expand */
  a11 = a10 << 5;  /* 03ac */
  a11 = a11 - a10;  /* 03af: sub */
  a10 = a11 + (a10 << 2);  /* 03b2 */
  a11 = LD8U(a5 + 0x28);  /* 03b5 */
  a10 = a10 << 4;  /* 03b8 */
  a5 = (u32)(RODATA__rodata_esp_mesh_refresh_routing_table_str1_1 + 0x0);  /* 03bb: -> "redundant" */
  a8 = LD32(a1 + 0x120);  /* 03be */
  a9 = LD32(a1 + 0x128);  /* 03c1 */
  a12 = LD32(a1 + 0x124);  /* 03c4 */
  a13 = LD32(a1 + 0x114);  /* 03c7 */
  a14 = LD32(a1 + 0x11c);  /* 03ca */
  a15 = LD32(a1 + 0x118);  /* 03cd */
  if (a11 != 0) goto L_03d5;  /* 03d0: bnez.n a11, 3d5 <esp_mesh_refresh_routing_table+0x33d> */
  L_03d2: a5 = (u32)(RODATA__rodata_esp_mesh_refresh_routing_table_str1_1 + 0x0);  /* 03d2: -> "redundant" */
  L_03d5: ST32(a1 + 0x24, a2);  /* 03d5 */
  a2 = LD32(a1 + 0x100);  /* 03d7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 03da: -> "mesh_route.c" */
  ST32(a1 + 0x34, a5);  /* 03dd */
  ST32(a1 + 0x2c, a8);  /* 03df */
  a5 = LD32(a1 + 0x110);  /* 03e1 */
  a8 = LD32(a1 + 0x10c);  /* 03e4 */
  ST32(a1 + 0x20, a2);  /* 03e7 */
  ST32(a1 + 0x1c, a4);  /* 03e9 */
  a2 = LD32(a1 + 0x108);  /* 03eb */
  a4 = LD32(a1 + 0x104);  /* 03ee */
  ST32(a1 + 0x28, a12);  /* 03f1 */
  a12 = (u32)(RODATA__rodata_esp_mesh_refresh_routing_table_str1_1 + 0x0);  /* 03f3: -> "redundant" */
  ST32(a1 + 0x30, a10);  /* 03f6 */
  a10 = 3;  /* 03f8 */
  ST32(a1 + 0x10, a14);  /* 03fa */
  a14 = a11;  /* 03fc */
  ST32(a1 + 0xc, a15);  /* 03fe */
  a15 = a3;  /* 0400 */
  ST32(a1 + 0x18, a4);  /* 0402 */
  ST32(a1 + 0x14, a9);  /* 0404 */
  ST32(a1 + 0x8, a5);  /* 0406 */
  ST32(a1 + 0x4, a8);  /* 0408 */
  ST32(a1 + 0x0, a2);  /* 040b */
  __asm__ volatile("" ::: "memory");  /* 040e: memw */
  /* 0411: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_0414: a3 = a3 << 6;  /* 0414 */
  a2 = (u32)&g_mesh_conn + 0x0;  /* 0417: l32r -> global */
  a4 = a2 + a3;  /* 041a */
  a5 = LD8U(a4 + 0x28);  /* 041d */
  if (a5 == 0) goto L_0454;  /* 0420: beqz.n a5, 454 <esp_mesh_refresh_routing_table+0x3bc> */
  L_0422: a5 = LD16U(a4 + 0x2a);  /* 0422 */
  a6 = LD32(a1 + 0x100);  /* 0425 */
  if (a5 != a6) goto L_0454;  /* 0428: bne a5, a6, 454 <esp_mesh_refresh_routing_table+0x3bc> */
  L_042b: a3 = LD32(a4 + 0x38);  /* 042b */
  a8 = (u32)&esp_mesh_get_ap_assoc_expire + 0x0;  /* 042e: l32r -> global */
  a2 = esp_mesh_get_ap_assoc_expire(a2, a3, a4, a5, a6);  /* 0431: callx a8 via reloc-expand */
  a2 = a10 << 5;  /* 0434 */
  a2 = a2 - a10;  /* 0437: sub */
  a2 = a2 + (a10 << 2);  /* 043a */
  a2 = a2 << 4;  /* 043d */
  if (a2 < a3) goto L_0446;  /* 0440: bltu a2, a3, 446 <esp_mesh_refresh_routing_table+0x3ae> */
  L_0443: goto L_0526;  /* 0443: j */
  L_0446: a2 = 0;  /* 0446 */
  ST8(a4 + 0x28, a2);  /* 0448 */
  __asm__ volatile("" ::: "memory");  /* 044b: memw */
  __asm__ volatile("" ::: "memory");  /* 044e: memw */
  goto L_0526;  /* 0451: j */
  L_0454: a8 = LD32(a1 + 0x100);  /* 0454 */
  a3 = a2 + a3;  /* 0457 */
  ST16(a3 + 0x2a, a8);  /* 045a */
  __asm__ volatile("" ::: "memory");  /* 045d: memw */
  a4 = LD32(a3 + 0x38);  /* 0460 */
  __asm__ volatile("" ::: "memory");  /* 0463: memw */
  a8 = (u32)&esp_mesh_get_ap_assoc_expire + 0x0;  /* 0466: l32r -> global */
  a2 = esp_mesh_get_ap_assoc_expire(a2, a3, a4, a5, a6);  /* 0469: callx a8 via reloc-expand */
  a2 = a10 << 5;  /* 046c */
  a2 = a2 - a10;  /* 046f: sub */
  a2 = a2 + (a10 << 2);  /* 0472 */
  a2 = a2 << 4;  /* 0475 */
  if (a2 < a4) goto L_047e;  /* 0478: bltu a2, a4, 47e <esp_mesh_refresh_routing_table+0x3e6> */
  L_047b: goto L_0518;  /* 047b: j */
  L_047e: a4 = 0;  /* 047e */
  a12 = 180;  /* 0480 */
  a11 = a4;  /* 0483 */
  a2 = 19;  /* 0485 */
  ST32(a3 + 0x30, a4);  /* 0487 */
  a10 = a1 + (68);  /* 0489 */
  a5 = a4;  /* 048c */
  ST32(a3 + 0x34, a4);  /* 048e */
  __asm__ volatile("" ::: "memory");  /* 0491: memw */
  a8 = (u32)&memset + 0x0;  /* 0494: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 0497: callx a8 (libc, via reloc-expand) */
  a11 = a7 + (14);  /* 049a */
  a12 = 6;  /* 049c */
  a10 = a1 + (74);  /* 049e */
  ST32(a1 + 0x40, a2);  /* 04a1 */
  a2 = 1;  /* 04a4 */
  ST8(a1 + 0x44, a2);  /* 04a6 */
  ST8(a1 + 0x46, a2);  /* 04a9 */
  __asm__ volatile("" ::: "memory");  /* 04ac: memw */
  a2 = LD32(a1 + 0x100);  /* 04af */
  ST16(a1 + 0x48, a2);  /* 04b2 */
  __asm__ volatile("" ::: "memory");  /* 04b5: memw */
  __asm__ volatile("" ::: "memory");  /* 04b8: memw */
  a8 = (u32)&memcpy + 0x0;  /* 04bb: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 04be: callx a8 (libc, via reloc-expand) */
  a11 = a4;  /* 04c1 */
  a10 = a1 + (64);  /* 04c3 */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 04c6: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6);  /* 04c9: callx a8 via reloc-expand */
  if (a10 == a4) goto L_0518;  /* 04cc: beq a10, a4, 518 <esp_mesh_refresh_routing_table+0x480> */
  L_04cf: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 04cf: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 04d2 */
  if (a2 == a4) goto L_0518;  /* 04d4: beq a2, a4, 518 <esp_mesh_refresh_routing_table+0x480> */
  L_04d7: a3 = LD32(a2 + 0x150);  /* 04d7 */
  if (a3 == a4) goto L_0518;  /* 04da: beq a3, a4, 518 <esp_mesh_refresh_routing_table+0x480> */
  L_04dd: a10 = LD32(a2 + 0x158);  /* 04dd */
  a2 = 0x669;  /* 04e0 */
  /* 04e3: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 04e6 */
  a10 = 1;  /* 04e8 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 04ea: -> "mesh_route.c" */
  a14 = a11;  /* 04ed */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 04ef: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_monitor_nonassociated_children_str1_1 + 0x0);  /* 04f2: l32r -> .rodata.esp_mesh_monitor_nonassociated_children.str1.1 */
  ST32(a1 + 0x0, a2);  /* 04f5 */
  __asm__ volatile("" ::: "memory");  /* 04f7: memw */
  /* 04fa: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0518;  /* 04fd: j */
  L_0500: a11 = LD8U(a12 + 0x28);  /* 0500 */
  if (a11 != 0) goto L_0518;  /* 0503: bnez.n a11, 518 <esp_mesh_refresh_routing_table+0x480> */
  L_0505: a10 = a3 << 6;  /* 0505 */
  a10 = a10 + (40);  /* 0508 */
  a4 = (u32)&g_mesh_conn + 0x0;  /* 050b: l32r -> global */
  a12 = 24;  /* 050e */
  a10 = a4 + a10;  /* 0510 */
  a8 = (u32)&memset + 0x0;  /* 0512: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 0515: callx a8 (libc, via reloc-expand) */
  L_0518: a8 = (u32)&esp_mesh_is_rt_change_debug + 0x0;  /* 0518: l32r -> global */
  a2 = esp_mesh_is_rt_change_debug(a2, a3, a4, a5, a6);  /* 051b: callx a8 via reloc-expand */
  a2 = 0;  /* 051e */
  if (a10 != a2) goto L_0526;  /* 0520: bne a10, a2, 526 <esp_mesh_refresh_routing_table+0x48e> */
  L_0523: goto L_0718;  /* 0523: j */
  L_0526: a2 = 0x00004032u;  /* 0526: l32r = 16434 */
  goto L_0718;  /* 0529: j */
  L_052c: a2 = 0;  /* 052c */
  if ((i32)a4 >= (i32)a2) goto L_0534;  /* 052e: bge a4, a2, 534 <esp_mesh_refresh_routing_table+0x49c> */
  L_0531: goto L_06c4;  /* 0531: j */
  L_0534: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0534: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 0537 */
  if ((i32)a4 < (i32)a5) goto L_0540;  /* 053a: blt a4, a5, 540 <esp_mesh_refresh_routing_table+0x4a8> */
  L_053d: goto L_06c4;  /* 053d: j */
  L_0540: a2 = LD32(a12 + 0x0);  /* 0540 */
  if (a2 != 0) goto L_0574;  /* 0542: bnez.n a2, 574 <esp_mesh_refresh_routing_table+0x4dc> */
  L_0544: a5 = LD8U(a7 + 0xae);  /* 0544 */
  a5 = a5 << 8;  /* 0547 */
  a2 = LD8U(a7 + 0xad);  /* 054a */
  a5 = a5 | a2;  /* 054d */
  a2 = LD8U(a7 + 0xaf);  /* 0550 */
  a2 = a2 << 16;  /* 0553 */
  a2 = a2 | a5;  /* 0556 */
  a5 = LD8U(a7 + 0xb0);  /* 0559 */
  a5 = a5 << 24;  /* 055c */
  a5 = a5 | a2;  /* 055f */
  a6 = LD8U(a7 + 0xac);  /* 0562 */
  a6 = a6 << 8;  /* 0565 */
  a2 = LD8U(a7 + 0xab);  /* 0568 */
  a6 = a6 | a2;  /* 056b */
  a2 = LD8U(a7 + 0x14);  /* 056e */
  goto L_05aa;  /* 0571: j */
  L_0574: a5 = LD8U(a7 + 0x1f);  /* 0574 */
  a5 = a5 << 8;  /* 0577 */
  a2 = LD8U(a7 + 0x1e);  /* 057a */
  a5 = a5 | a2;  /* 057d */
  a2 = LD8U(a7 + 0x20);  /* 0580 */
  a2 = a2 << 16;  /* 0583 */
  a2 = a2 | a5;  /* 0586 */
  a5 = LD8U(a7 + 0x21);  /* 0589 */
  a5 = a5 << 24;  /* 058c */
  a5 = a5 | a2;  /* 058f */
  a6 = LD8U(a7 + 0x1d);  /* 0592 */
  a6 = a6 << 8;  /* 0595 */
  a2 = LD8U(a7 + 0x1c);  /* 0598 */
  a6 = a6 | a2;  /* 059b */
  a2 = LD8U(a7 + 0x15);  /* 059e */
  a2 = a2 << 8;  /* 05a1 */
  a10 = LD8U(a7 + 0x14);  /* 05a4 */
  a2 = a2 | a10;  /* 05a7 */
  L_05aa: if (a9 != 4) goto L_05bc;  /* 05aa: bnei a9, 4, 5bc <esp_mesh_refresh_routing_table+0x524> */
  L_05ad: a12 = a6;  /* 05ad */
  a11 = a5;  /* 05af */
  a10 = a4;  /* 05b1 */
  a8 = (u32)&esp_mesh_remove_nonassociated_children;  /* 05b3: l32r -> func addr */
  a2 = esp_mesh_remove_nonassociated_children(a2, a3, a4, a5, a6);  /* 05b6: callx a8 via reloc-expand */
  goto L_06c2;  /* 05b9: j */
  L_05bc: a9 = 23;  /* 05bc */
  if (a9 >= a2) goto L_062d;  /* 05be: bgeu a9, a2, 62d <esp_mesh_refresh_routing_table+0x595> */
  L_05c1: a9 = (u32)&g_osi_funcs_p + 0x0;  /* 05c1: l32r -> global */
  a10 = LD32(a9 + 0x0);  /* 05c4 */
  if (a10 == 0) goto L_05f8;  /* 05c6: beqz.n a10, 5f8 <esp_mesh_refresh_routing_table+0x560> */
  L_05c8: a9 = LD32(a10 + 0x150);  /* 05c8 */
  if (a9 == 0) goto L_05f8;  /* 05cb: beqz.n a9, 5f8 <esp_mesh_refresh_routing_table+0x560> */
  L_05cd: a10 = LD32(a10 + 0x158);  /* 05cd */
  ST32(a1 + 0x128, a9);  /* 05d0 */
  __asm__ volatile("" ::: "memory");  /* 05d3: memw */
  /* 05d6: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a12 = 0x697;  /* 05d9 */
  a13 = a10;  /* 05dc */
  a10 = 2;  /* 05de */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 05e0: -> "mesh_route.c" */
  a14 = a11;  /* 05e3 */
  ST32(a1 + 0x0, a12);  /* 05e5 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 05e7: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_refresh_routing_table_str1_1 + 0x0);  /* 05ea: -> "redundant" */
  a9 = LD32(a1 + 0x128);  /* 05ed */
  ST32(a1 + 0x4, a2);  /* 05f0 */
  __asm__ volatile("" ::: "memory");  /* 05f2: memw */
  /* 05f5: INDIRECT callx a9 <- mem[a1+0x128]; result unknown */ a2 = 0;
  L_05f8: a9 = (u32)&g_osi_funcs_p + 0x0;  /* 05f8: l32r -> global */
  a10 = LD32(a9 + 0x0);  /* 05fb */
  if (a10 == 0) goto L_062d;  /* 05fd: beqz.n a10, 62d <esp_mesh_refresh_routing_table+0x595> */
  L_05ff: a9 = LD32(a10 + 0x150);  /* 05ff */
  if (a9 == 0) goto L_062d;  /* 0602: beqz.n a9, 62d <esp_mesh_refresh_routing_table+0x595> */
  L_0604: a10 = LD32(a10 + 0x158);  /* 0604 */
  ST32(a1 + 0x128, a9);  /* 0607 */
  __asm__ volatile("" ::: "memory");  /* 060a: memw */
  /* 060d: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a12 = 0x69a;  /* 0610 */
  a13 = a10;  /* 0613 */
  a10 = 1;  /* 0615 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0617: -> "mesh_route.c" */
  a14 = a11;  /* 061a */
  ST32(a1 + 0x0, a12);  /* 061c */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 061e: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_monitor_nonassociated_children_str1_1 + 0x0);  /* 0621: l32r -> .rodata.esp_mesh_monitor_nonassociated_children.str1.1 */
  a9 = LD32(a1 + 0x128);  /* 0624 */
  __asm__ volatile("" ::: "memory");  /* 0627: memw */
  /* 062a: INDIRECT callx a9 <- mem[a1+0x128]; result unknown */ a2 = 0;
  L_062d: a9 = (u32)&g_mesh_topology + 0x0;  /* 062d: l32r -> global */
  a9 = LD32(a9 + 0x0);  /* 0630 */
  if (a9 != 0) goto L_0644;  /* 0632: bnez.n a9, 644 <esp_mesh_refresh_routing_table+0x5ac> */
  L_0634: a2 = a2 + (1);  /* 0634 */
  a2 = a2 + (a2 << 1);  /* 0636 */
  a2 = a2 + (a7 << 1);  /* 0639 */
  a11 = LD8U(a2 + 0x15);  /* 063c */
  goto L_0647;  /* 063f: j */
  L_0644: a11 = LD8U(a7 + 0x16);  /* 0644 */
  L_0647: a9 = (a11 >> 7) & 0x1;  /* 0647: extui width 1 */
  a11 = a11 >> 7;  /* 064a */
  if (a9 == 0) goto L_06b6;  /* 064d: beqz a9, 6b6 <esp_mesh_refresh_routing_table+0x61e> */
  L_0650: a13 = a3;  /* 0650 */
  a10 = a9;  /* 0652 */
  a15 = a6;  /* 0654: mov */
  a14 = a5;  /* 0657: mov */
  a12 = a4;  /* 065a: mov */
  ST32(a1 + 0x128, a9);  /* 065d */
  __asm__ volatile("" ::: "memory");  /* 0660: memw */
  a8 = (u32)&esp_mesh_combine_multi_redundant_ack;  /* 0663: l32r -> func addr */
  a2 = esp_mesh_combine_multi_redundant_ack(a2, a3, a4, a5, a6);  /* 0666: callx a8 via reloc-expand */
  a3 = 127;  /* 0669 */
  a2 = a10;  /* 066c */
  a9 = LD32(a1 + 0x128);  /* 066e */
  if (a9 != a3) goto L_06c4;  /* 0671: bne a9, a3, 6c4 <esp_mesh_refresh_routing_table+0x62c> */
  L_0674: a5 = a4 + (a4 << 1);  /* 0674 */
  a10 = a4;  /* 0677 */
  a3 = (u32)&mesh_multi_recv_ack + 0x0;  /* 0679: l32r -> global */
  a5 = a5 + (a3 << 3);  /* 067c */
  a12 = LD16U(a5 + 0xc);  /* 067f */
  a11 = LD32(a5 + 0x8);  /* 0682 */
  a8 = (u32)&esp_mesh_process_redundant_subchildren;  /* 0684: l32r -> func addr */
  a2 = esp_mesh_process_redundant_subchildren(a2, a3, a4, a5, a6);  /* 0687: callx a8 via reloc-expand */
  a2 = a10;  /* 068a */
  a12 = 0x6b8;  /* 068c */
  a10 = LD32(a5 + 0x8);  /* 068f */
  a11 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 0691: l32r -> .rodata.__func__$1 */
  a8 = (u32)&mesh_free + 0x0;  /* 0694: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6);  /* 0697: callx a8 via reloc-expand */
  a12 = 24;  /* 069a */
  a11 = 0;  /* 069c */
  a5 = LD32(a1 + 0x100);  /* 069e */
  a4 = (i32)(a5 << (32 - 7)) >> (32 - 7);  /* 06a1: sext */
  a10 = a4 + (a4 << 1);  /* 06a4 */
  a10 = a10 + (a3 << 3);  /* 06a7 */
  a8 = (u32)&memset + 0x0;  /* 06aa: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 06ad: callx a8 (libc, via reloc-expand) */
  goto L_06c4;  /* 06b0: j */
  L_06b6: a12 = a6;  /* 06b6 */
  a11 = a5;  /* 06b8 */
  a10 = a4;  /* 06ba */
  a8 = (u32)&esp_mesh_process_redundant_subchildren;  /* 06bc: l32r -> func addr */
  a2 = esp_mesh_process_redundant_subchildren(a2, a3, a4, a5, a6);  /* 06bf: callx a8 via reloc-expand */
  L_06c2: a2 = a10;  /* 06c2 */
  L_06c4: a3 = (u32)&g_mesh_topology + 0x0;  /* 06c4: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 06c7 */
  a11 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 06c9: l32r -> .rodata.__func__$1 */
  if (a3 != 0) goto L_06f1;  /* 06cc: bnez.n a3, 6f1 <esp_mesh_refresh_routing_table+0x659> */
  L_06ce: a12 = 0x6c9;  /* 06ce */
  a4 = LD8U(a7 + 0xae);  /* 06d1 */
  a4 = a4 << 8;  /* 06d4 */
  a3 = LD8U(a7 + 0xad);  /* 06d7 */
  a4 = a4 | a3;  /* 06da */
  a3 = LD8U(a7 + 0xaf);  /* 06dd */
  a3 = a3 << 16;  /* 06e0 */
  a3 = a3 | a4;  /* 06e3 */
  a10 = LD8U(a7 + 0xb0);  /* 06e6 */
  a10 = a10 << 24;  /* 06e9 */
  goto L_070f;  /* 06ec: j */
  L_06f1: a4 = LD8U(a7 + 0x1f);  /* 06f1 */
  a12 = 0x6cb;  /* 06f4 */
  a4 = a4 << 8;  /* 06f7 */
  a3 = LD8U(a7 + 0x1e);  /* 06fa */
  a4 = a4 | a3;  /* 06fd */
  a3 = LD8U(a7 + 0x20);  /* 0700 */
  a3 = a3 << 16;  /* 0703 */
  a3 = a3 | a4;  /* 0706 */
  a10 = LD8U(a7 + 0x21);  /* 0709 */
  a10 = a10 << 24;  /* 070c */
  L_070f: a10 = a10 | a3;  /* 070f */
  a8 = (u32)&mesh_free + 0x0;  /* 0712: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6);  /* 0715: callx a8 via reloc-expand */
  L_0718: return a2;  /* 0718: retw.n */
}


/* esp_mesh_remove_nonassociated_children @ mesh_route.o 0000003c size 394B bind GLOBAL
 * Calls: esp_mesh_lookup_route, memset, mesh_update_route_table | indirect[5]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, g_mesh_ext_cfg, .rodata.esp_mesh_remove_nonassociated_children.str1.1, g_mesh_rt_capacity, .bss.mesh_route_table
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=10); reloc-direct=3, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_remove_nonassociated_children(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 003c: entry a1, 80 (frame 80 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 003f: extui width 1 */
  a4 = (a4 >> 16) & 0x1;  /* 0042: extui width 1 */
  if (a3 != 0) goto L_0089;  /* 0045: bnez a3, 89 <esp_mesh_remove_nonassociated_children+0x4d> */
  L_0048: a2 = (u32)&g_log_level + 0x0;  /* 0048: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 004b */
  a2 = 0x00004008u;  /* 004d: l32r = 16392 */
  if (a3 >= 3u) goto L_0056;  /* 0050: bgeui a3, 3, 56 <esp_mesh_remove_nonassociated_children+0x1a> */
  L_0053: goto L_01c4;  /* 0053: j */
  L_0056: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0056: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0059 */
  if (a3 == 0) goto L_01c4;  /* 005b: beqz a3, 1c4 <esp_mesh_remove_nonassociated_children+0x188> */
  L_005e: a4 = LD32(a3 + 0x150);  /* 005e */
  if (a4 == 0) goto L_01c4;  /* 0061: beqz a4, 1c4 <esp_mesh_remove_nonassociated_children+0x188> */
  L_0064: a10 = LD32(a3 + 0x158);  /* 0064 */
  a3 = 0x469;  /* 0067 */
  /* 006a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 006d */
  a10 = 3;  /* 006f */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0071: -> "mesh_route.c" */
  a14 = a11;  /* 0074 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0076: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0079: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 007c */
  __asm__ volatile("" ::: "memory");  /* 007e: memw */
  /* 0081: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01c4;  /* 0084: j */
  L_0089: a5 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 0089: sext */
  if ((i32)a5 < 0) goto L_0098;  /* 008c: bltz a5, 98 <esp_mesh_remove_nonassociated_children+0x5c> */
  L_008f: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 008f: l32r -> global */
  a2 = LD8U(a2 + 0xbd);  /* 0092 */
  if ((i32)a5 < (i32)a2) goto L_00ca;  /* 0095: blt a5, a2, ca <esp_mesh_remove_nonassociated_children+0x8e> */
  L_0098: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0098: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 009b */
  a2 = -1;  /* 009d */
  if (a3 == 0) goto L_01c4;  /* 009f: beqz a3, 1c4 <esp_mesh_remove_nonassociated_children+0x188> */
  L_00a2: a6 = LD32(a3 + 0x150);  /* 00a2 */
  if (a6 == 0) goto L_01c4;  /* 00a5: beqz a6, 1c4 <esp_mesh_remove_nonassociated_children+0x188> */
  L_00a8: a10 = LD32(a3 + 0x158);  /* 00a8 */
  a3 = 0x471;  /* 00ab */
  /* 00ae: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00b1 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00b3: -> "mesh_route.c" */
  a14 = a11;  /* 00b6 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00b8: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_remove_nonassociated_children_str1_1 + 0x0);  /* 00bb: l32r -> .rodata.esp_mesh_remove_nonassociated_children.str1.1 */
  ST32(a1 + 0x8, a4);  /* 00be */
  ST32(a1 + 0x4, a5);  /* 00c0 */
  ST32(a1 + 0x0, a3);  /* 00c2 */
  __asm__ volatile("" ::: "memory");  /* 00c4: memw */
  goto L_0100;  /* 00c7: j */
  L_00ca: if (a4 == 0) goto L_00d4;  /* 00ca: beqz.n a4, d4 <esp_mesh_remove_nonassociated_children+0x98> */
  L_00cc: a2 = (u32)&g_mesh_rt_capacity + 0x0;  /* 00cc: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00cf */
  if ((i32)a2 >= (i32)a4) goto L_010c;  /* 00d1: bge a2, a4, 10c <esp_mesh_remove_nonassociated_children+0xd0> */
  L_00d4: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00d4: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00d7 */
  a2 = -1;  /* 00d9 */
  if (a3 == 0) goto L_01c4;  /* 00db: beqz a3, 1c4 <esp_mesh_remove_nonassociated_children+0x188> */
  L_00de: a6 = LD32(a3 + 0x150);  /* 00de */
  if (a6 == 0) goto L_01c4;  /* 00e1: beqz a6, 1c4 <esp_mesh_remove_nonassociated_children+0x188> */
  L_00e4: a10 = LD32(a3 + 0x158);  /* 00e4 */
  a3 = 0x476;  /* 00e7 */
  /* 00ea: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ed */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00ef: -> "mesh_route.c" */
  a14 = a11;  /* 00f2 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00f4: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_remove_nonassociated_children_str1_1 + 0x0);  /* 00f7: l32r -> .rodata.esp_mesh_remove_nonassociated_children.str1.1 */
  ST32(a1 + 0x8, a5);  /* 00fa */
  ST32(a1 + 0x4, a4);  /* 00fc */
  ST32(a1 + 0x0, a3);  /* 00fe */
  L_0100: a10 = 2;  /* 0100 */
  __asm__ volatile("" ::: "memory");  /* 0102: memw */
  /* 0105: INDIRECT callx a6 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01c4;  /* 0108: j */
  L_010c: a6 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 010c: l32r -> .bss.mesh_route_table (same-object static) */
  a7 = a5 + a5;  /* 010f */
  a2 = a5 + (a6 << 1);  /* 0111 */
  a8 = LD8U(a2 + 0x0);  /* 0114 */
  a2 = LD8U(a2 + 0x1);  /* 0117 */
  a2 = a2 << 8;  /* 011a */
  a2 = a2 | a8;  /* 011d */
  if (a2 != 0) goto L_0128;  /* 0120: bnez.n a2, 128 <esp_mesh_remove_nonassociated_children+0xec> */
  L_0122: a2 = 0;  /* 0122 */
  goto L_01c4;  /* 0124: j */
  L_0128: a2 = -1;  /* 0128 */
  a8 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 012a: l32r -> .bss.mesh_route_table (same-object static) */
  a13 = 0;  /* 012d */
  a6 = a13;  /* 012f */
  ST8(a1 + 0x10, a2);  /* 0131 */
  a2 = -1;  /* 0134 */
  ST16(a1 + 0x12, a2);  /* 0136 */
  __asm__ volatile("" ::: "memory");  /* 0139: memw */
  a2 = a5 + (8);  /* 013c */
  a2 = a2 + (a8 << 2);  /* 013e */
  L_0141: a12 = a1 + (16);  /* 0141 */
  a11 = 0;  /* 0144 */
  a10 = a3;  /* 0146: mov */
  ST32(a1 + 0x20, a13);  /* 0149 */
  __asm__ volatile("" ::: "memory");  /* 014b: memw */
  a8 = (u32)&esp_mesh_lookup_route;  /* 014e: l32r -> func addr */
  a2 = esp_mesh_lookup_route(a2, a3, a4, a5, a6, a7);  /* 0151: callx a8 via reloc-expand */
  a9 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0154: l32r -> .bss.mesh_route_table (same-object static) */
  a8 = a9 + a7;  /* 0157 */
  a10 = LD8U(a8 + 0x0);  /* 0159 */
  a8 = LD8U(a8 + 0x1);  /* 015c */
  a8 = a8 << 8;  /* 015f */
  a8 = a8 | a10;  /* 0162 */
  a13 = LD32(a1 + 0x20);  /* 0165 */
  if (a8 == 0) goto L_01a8;  /* 0167: beqz.n a8, 1a8 <esp_mesh_remove_nonassociated_children+0x16c> */
  L_0169: a8 = LD8U(a1 + 0x10);  /* 0169 */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 016c: sext */
  if (a8 != a5) goto L_01a8;  /* 016f: bne a8, a5, 1a8 <esp_mesh_remove_nonassociated_children+0x16c> */
  L_0172: a10 = LD16S(a1 + 0x12);  /* 0172 */
  if (a10 == -1) goto L_01a8;  /* 0175: beqi a10, -1, 1a8 <esp_mesh_remove_nonassociated_children+0x16c> */
  L_0178: a10 = a10 + (a10 << 1);  /* 0178 */
  a12 = 6;  /* 017b */
  a8 = LD8U(a2 + 0x9);  /* 017d */
  a8 = a8 << 8;  /* 0180 */
  a11 = LD8U(a2 + 0x8);  /* 0183 */
  a8 = a8 | a11;  /* 0186 */
  a11 = LD8U(a2 + 0xa);  /* 0189 */
  a11 = a11 << 16;  /* 018c */
  a11 = a11 | a8;  /* 018f */
  a8 = LD8U(a2 + 0xb);  /* 0192 */
  a8 = a8 << 24;  /* 0195 */
  a8 = a8 | a11;  /* 0198 */
  a10 = a10 + (a8 << 1);  /* 019b */
  a11 = 0;  /* 019e */
  a8 = (u32)&memset + 0x0;  /* 01a0: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01a3: callx a8 (libc, via reloc-expand) */
  a13 = 1;  /* 01a6 */
  L_01a8: a6 = a6 + (1);  /* 01a8 */
  a3 = a3 + (6);  /* 01aa */
  if ((i32)a6 < (i32)a4) goto L_0141;  /* 01ac: blt a6, a4, 141 <esp_mesh_remove_nonassociated_children+0x105> */
  L_01af: if (a13 == 0) goto L_0122;  /* 01af: beqz a13, 122 <esp_mesh_remove_nonassociated_children+0xe6> */
  L_01b2: a12 = 1;  /* 01b2 */
  a11 = 2;  /* 01b5 */
  a10 = a5;  /* 01b8: mov */
  a8 = (u32)&mesh_update_route_table;  /* 01bb: l32r -> func addr */
  a2 = mesh_update_route_table(a2, a3, a4, a5, a6, a7);  /* 01be: callx a8 via reloc-expand */
  a2 = 0x00004032u;  /* 01c1: l32r = 16434 */
  L_01c4: return a2;  /* 01c4: retw.n */
}


/* esp_mesh_route_deinit @ mesh_route.o 0000001c size 143B bind GLOBAL
 * Calls: mesh_free, memset | indirect[2]: mem[a5+0xec]; mem[a4+0xf0] | Data refs: .bss.is_route_inited, .bss.mesh_route_table, .rodata.__func__$11, g_osi_funcs_p, .bss.rt_change_timer
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_route_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 001c: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&LOCAL__bss_is_route_inited + 0x0;  /* 001f: l32r -> .bss.is_route_inited (same-object static) */
  a2 = LD8U(a3 + 0x0);  /* 0022 */
  if (a2 == 0) goto L_00a6;  /* 0025: beqz a2, a6 <esp_mesh_route_deinit+0x8a> */
  L_0028: a5 = 0;  /* 0028 */
  a4 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 002a: l32r -> .bss.mesh_route_table (same-object static) */
  L_002d: a2 = a5 + (8);  /* 002d */
  a2 = a2 + (a4 << 2);  /* 002f */
  a9 = LD8U(a2 + 0x9);  /* 0032 */
  a9 = a9 << 8;  /* 0035 */
  a8 = LD8U(a2 + 0x8);  /* 0038 */
  a9 = a9 | a8;  /* 003b */
  a8 = LD8U(a2 + 0xa);  /* 003e */
  a8 = a8 << 16;  /* 0041 */
  a8 = a8 | a9;  /* 0044 */
  a10 = LD8U(a2 + 0xb);  /* 0047 */
  a10 = a10 << 24;  /* 004a */
  a10 = a10 | a8;  /* 004d */
  if (a10 == 0) goto L_006e;  /* 0050: beqz.n a10, 6e <esp_mesh_route_deinit+0x52> */
  L_0052: a11 = (u32)(RODATA__rodata___func___11 + 0x0);  /* 0052: l32r -> .rodata.__func__$11 */
  a12 = 79;  /* 0055 */
  a8 = (u32)&mesh_free + 0x0;  /* 0057: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 005a: callx a8 via reloc-expand */
  a8 = 0;  /* 005d */
  ST8(a2 + 0x8, a8);  /* 005f */
  ST8(a2 + 0x9, a8);  /* 0062 */
  ST8(a2 + 0xa, a8);  /* 0065 */
  ST8(a2 + 0xb, a8);  /* 0068 */
  __asm__ volatile("" ::: "memory");  /* 006b: memw */
  L_006e: a5 = a5 + (1);  /* 006e */
  if (a5 != 10) goto L_002d;  /* 0070: bnei a5, 10, 2d <esp_mesh_route_deinit+0x11> */
  L_0073: a12 = 80;  /* 0073 */
  a11 = 0;  /* 0075 */
  a10 = a4;  /* 0078: mov */
  __asm__ volatile("" ::: "memory");  /* 007b: memw */
  a8 = (u32)&memset + 0x0;  /* 007e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0081: callx a8 (libc, via reloc-expand) */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0084: l32r -> global */
  a5 = LD32(a4 + 0x0);  /* 0087 */
  a2 = (u32)&LOCAL__bss_rt_change_timer + 0x0;  /* 0089: l32r -> .bss.rt_change_timer (same-object static) */
  a10 = a2;  /* 008c */
  a5 = LD32(a5 + 0xec);  /* 008e */
  /* 0091: INDIRECT callx a5 <- mem[a5+0xec]; result unknown */ a2 = 0;
  a10 = a2;  /* 0094 */
  a2 = 0;  /* 0096 */
  a4 = LD32(a4 + 0x0);  /* 0098 */
  a4 = LD32(a4 + 0xf0);  /* 009a */
  /* 009d: INDIRECT callx a4 <- mem[a4+0xf0]; result unknown */ a2 = 0;
  ST8(a3 + 0x0, a2);  /* 00a0 */
  __asm__ volatile("" ::: "memory");  /* 00a3: memw */
  L_00a6: __asm__ volatile("" ::: "memory");  /* 00a6: memw */
  return a2;  /* 00a9: retw.n */
}


/* esp_mesh_route_init @ mesh_route.o 0000001c size 73B bind GLOBAL
 * Calls: memset | indirect[1]: mem[a9+0xf4] | Data refs: .bss.is_route_inited, .bss.mesh_route_table, .bss.rt_change_timer, g_osi_funcs_p, mesh_rt_change_timeout
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=6); reloc-direct=1, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_route_init(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 001c: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&LOCAL__bss_is_route_inited + 0x0;  /* 001f: l32r -> .bss.is_route_inited (same-object static) */
  a2 = LD8U(a3 + 0x0);  /* 0022 */
  if (a2 != 0) goto L_005e;  /* 0025: bnez.n a2, 5e <esp_mesh_route_init+0x42> */
  L_0027: a11 = a2;  /* 0027 */
  a12 = 80;  /* 0029 */
  a10 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 002c: l32r -> .bss.mesh_route_table (same-object static) */
  a8 = (u32)&memset + 0x0;  /* 002f: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0032: callx a8 (libc, via reloc-expand) */
  a11 = a2;  /* 0035 */
  a12 = 20;  /* 0037 */
  a8 = (u32)&LOCAL__bss_rt_change_timer + 0x0;  /* 003a: l32r -> .bss.rt_change_timer (same-object static) */
  a10 = a8;  /* 003d: mov */
  a8 = (u32)&memset + 0x0;  /* 0040: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0043: callx a8 (libc, via reloc-expand) */
  a12 = a2;  /* 0046 */
  a9 = (u32)&g_osi_funcs_p + 0x0;  /* 0048: l32r -> global */
  a2 = 1;  /* 004b */
  a9 = LD32(a9 + 0x0);  /* 004d */
  a11 = (u32)&mesh_rt_change_timeout;  /* 004f: l32r -> func addr */
  a9 = LD32(a9 + 0xf4);  /* 0052 */
  /* 0055: INDIRECT callx a9 <- mem[a9+0xf4]; result unknown */ a2 = 0;
  ST8(a3 + 0x0, a2);  /* 0058 */
  __asm__ volatile("" ::: "memory");  /* 005b: memw */
  L_005e: a2 = 0;  /* 005e */
  __asm__ volatile("" ::: "memory");  /* 0060: memw */
  return a2;  /* 0063: retw.n */
}


/* esp_mesh_send_add_announcement @ mesh_route.o 00000020 size 180B bind GLOBAL
 * Calls: memset, esp_mesh_get_total_children_num, memcpy, esp_mesh_send_mgmt | Data refs: g_mesh_topology, g_mesh_self_sta_addr
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=4, refs=6); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_send_add_announcement(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  /* 0020: entry a1, 224 (frame 224 bytes) */
  a2 = 3;  /* 0023 */
  a12 = 177;  /* 0026 */
  a11 = 0;  /* 0029 */
  a10 = a1;  /* 002c: mov */
  a8 = (u32)&memset + 0x0;  /* 002f: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0032: callx a8 (libc, via reloc-expand) */
  ST8(a1 + 0xb1, a2);  /* 0035 */
  __asm__ volatile("" ::: "memory");  /* 0038: memw */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 003b: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 003e */
  a2 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 0040: l32r -> global */
  if (a8 != 0) goto L_0074;  /* 0043: bnez.n a8, 74 <esp_mesh_send_add_announcement+0x54> */
  L_0045: __asm__ volatile("" ::: "memory");  /* 0045: memw */
  a8 = (u32)&esp_mesh_get_total_children_num;  /* 0048: l32r -> func addr */
  a2 = esp_mesh_get_total_children_num(a2, a3, a4, a5, a6, a7);  /* 004b: callx a8 via reloc-expand */
  a10 = a10 + (1);  /* 004e */
  a12 = 6;  /* 0050 */
  ST8(a1 + 0xab, a10);  /* 0052 */
  a10 = (a10 >> 8) & 0x1ff;  /* 0055: extui width 9 */
  a11 = a2;  /* 0058 */
  ST8(a1 + 0xac, a10);  /* 005a */
  __asm__ volatile("" ::: "memory");  /* 005d: memw */
  a10 = a1 + (21);  /* 0060 */
  __asm__ volatile("" ::: "memory");  /* 0063: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0066: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0069: callx a8 (libc, via reloc-expand) */
  a8 = 154;  /* 006c */
  goto L_0094;  /* 006f: j */
  L_0074: a8 = (u32)&esp_mesh_get_total_children_num;  /* 0074: l32r -> func addr */
  a2 = esp_mesh_get_total_children_num(a2, a3, a4, a5, a6, a7);  /* 0077: callx a8 via reloc-expand */
  a10 = a10 + (1);  /* 007a */
  ST16(a1 + 0x1c, a10);  /* 007c */
  __asm__ volatile("" ::: "memory");  /* 007f: memw */
  a12 = 6;  /* 0082 */
  a11 = a2;  /* 0084 */
  a10 = a1 + (22);  /* 0086 */
  __asm__ volatile("" ::: "memory");  /* 0089: memw */
  a8 = (u32)&memcpy + 0x0;  /* 008c: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 008f: callx a8 (libc, via reloc-expand) */
  a8 = 12;  /* 0092 */
  L_0094: a3 = 177;  /* 0094 */
  a3 = a3 + a1;  /* 0097 */
  ST8(a1 + 0xb2, a8);  /* 0099 */
  a8 = 0;  /* 009c */
  a14 = 0;  /* 009e */
  a13 = -1;  /* 00a0 */
  a12 = a3;  /* 00a2 */
  ST8(a3 + 0x2, a8);  /* 00a4 */
  a8 = a1 + (20);  /* 00a7 */
  a2 = (a8 >> 8) & 0x1ff;  /* 00aa: extui width 9 */
  a11 = 8;  /* 00ad */
  a10 = a14;  /* 00af: mov */
  ST8(a1 + 0xb4, a8);  /* 00b2 */
  ST8(a3 + 0x4, a2);  /* 00b5 */
  a2 = (a8 >> 8) & 0x1ffff;  /* 00b8: extui width 17 */
  a8 = (a8 >> 8) & 0x1ffffff;  /* 00bb: extui width 25 */
  ST8(a3 + 0x5, a2);  /* 00be */
  ST8(a3 + 0x6, a8);  /* 00c1 */
  __asm__ volatile("" ::: "memory");  /* 00c4: memw */
  __asm__ volatile("" ::: "memory");  /* 00c7: memw */
  a8 = (u32)&esp_mesh_send_mgmt + 0x0;  /* 00ca: l32r -> global */
  a2 = esp_mesh_send_mgmt(a2, a3, a4, a5, a6, a7);  /* 00cd: callx a8 via reloc-expand */
  a2 = a10;  /* 00d0 */
  return a2;  /* 00d2: retw.n */
}


/* esp_mesh_send_rtable_ack @ mesh_route.o 0000004c size 450B bind GLOBAL
 * Calls: memset, memcmp, memcpy, esp_mesh_pack_multi_routing_table, esp_mesh_send_mgmt, esp_mesh_push_to_nwk_queue | indirect[5]: mem[a3+0x158]; mem[a2+0x158]; unknown; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, mesh_multi_send_ack, .rodata.esp_mesh_send_rtable_ack.str1.1, .rodata.esp_mesh_monitor_nonassociated_children.str1.1
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=12); reloc-direct=6, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_send_rtable_ack(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 004c: entry a1, 0x110 (frame 0x110 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 004f: extui width 1 */
  if (a3 != 0) goto L_0090;  /* 0052: bnez.n a3, 90 <esp_mesh_send_rtable_ack+0x44> */
  L_0054: a2 = (u32)&g_log_level + 0x0;  /* 0054: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0057 */
  a2 = 0x00004008u;  /* 0059: l32r = 16392 */
  if (a3 >= 3u) goto L_0062;  /* 005c: bgeui a3, 3, 62 <esp_mesh_send_rtable_ack+0x16> */
  L_005f: goto L_020c;  /* 005f: j */
  L_0062: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0062: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0065 */
  if (a3 == 0) goto L_020c;  /* 0067: beqz a3, 20c <esp_mesh_send_rtable_ack+0x1c0> */
  L_006a: a4 = LD32(a3 + 0x150);  /* 006a */
  if (a4 == 0) goto L_020c;  /* 006d: beqz a4, 20c <esp_mesh_send_rtable_ack+0x1c0> */
  L_0070: a10 = LD32(a3 + 0x158);  /* 0070 */
  a3 = 0x732;  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0079 */
  a10 = 3;  /* 007b */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 007d: -> "mesh_route.c" */
  a14 = a11;  /* 0080 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0082: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0085: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 0088 */
  __asm__ volatile("" ::: "memory");  /* 008a: memw */
  goto L_0206;  /* 008d: j */
  L_0090: a4 = a1 + (48);  /* 0090 */
  a10 = 184;  /* 0093 */
  a10 = a4 + a10;  /* 0096 */
  a12 = 7;  /* 0098 */
  a4 = 5;  /* 009a */
  a11 = 0;  /* 009c */
  a8 = (u32)&memset + 0x0;  /* 009e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00a1: callx a8 (libc, via reloc-expand) */
  ST8(a1 + 0xe8, a4);  /* 00a4 */
  __asm__ volatile("" ::: "memory");  /* 00a7: memw */
  a4 = (u32)&mesh_multi_send_ack + 0x0;  /* 00aa: l32r -> global */
  if (a2 != 0) goto L_00c4;  /* 00ad: bnez.n a2, c4 <esp_mesh_send_rtable_ack+0x78> */
  L_00af: a12 = 6;  /* 00af */
  a11 = a3;  /* 00b2: mov */
  a10 = a4;  /* 00b5: mov */
  __asm__ volatile("" ::: "memory");  /* 00b8: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00bb: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00be: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0144;  /* 00c1: beqz a10, 144 <esp_mesh_send_rtable_ack+0xf8> */
  L_00c4: a2 = (u32)&g_log_level + 0x0;  /* 00c4: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00c7 */
  if (a2 < 3u) goto L_012c;  /* 00c9: bltui a2, 3, 12c <esp_mesh_send_rtable_ack+0xe0> */
  L_00cc: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00cc: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00cf */
  if (a2 == 0) goto L_012c;  /* 00d1: beqz a2, 12c <esp_mesh_send_rtable_ack+0xe0> */
  L_00d4: a5 = LD32(a2 + 0x150);  /* 00d4 */
  if (a5 == 0) goto L_012c;  /* 00d7: beqz a5, 12c <esp_mesh_send_rtable_ack+0xe0> */
  L_00da: a10 = LD32(a2 + 0x158);  /* 00da */
  /* 00dd: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00e0 */
  a10 = 3;  /* 00e2 */
  a2 = LD8U(a3 + 0x5);  /* 00e4 */
  a15 = LD8U(a4 + 0x0);  /* 00e7 */
  ST32(a1 + 0x28, a2);  /* 00ea */
  a2 = LD8U(a3 + 0x4);  /* 00ec */
  ST32(a1 + 0x24, a2);  /* 00ef */
  a2 = LD8U(a3 + 0x3);  /* 00f1 */
  ST32(a1 + 0x20, a2);  /* 00f4 */
  a2 = LD8U(a3 + 0x2);  /* 00f6 */
  ST32(a1 + 0x1c, a2);  /* 00f9 */
  a2 = LD8U(a3 + 0x1);  /* 00fb */
  ST32(a1 + 0x18, a2);  /* 00fe */
  a2 = LD8U(a3 + 0x0);  /* 0100 */
  ST32(a1 + 0x14, a2);  /* 0103 */
  a2 = LD8U(a4 + 0x5);  /* 0105 */
  ST32(a1 + 0x10, a2);  /* 0108 */
  a2 = LD8U(a4 + 0x4);  /* 010a */
  ST32(a1 + 0xc, a2);  /* 010d */
  a2 = LD8U(a4 + 0x3);  /* 010f */
  ST32(a1 + 0x8, a2);  /* 0112 */
  a2 = LD8U(a4 + 0x2);  /* 0114 */
  ST32(a1 + 0x4, a2);  /* 0117 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0119: -> "mesh_route.c" */
  a14 = a11;  /* 011c */
  a2 = LD8U(a4 + 0x1);  /* 011e */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_rtable_ack_str1_1 + 0x0);  /* 0121: l32r -> .rodata.esp_mesh_send_rtable_ack.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0124 */
  __asm__ volatile("" ::: "memory");  /* 0126: memw */
  /* 0129: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_012c: a12 = 14;  /* 012c */
  a11 = 0;  /* 012e */
  a10 = a4;  /* 0130 */
  a8 = (u32)&memset + 0x0;  /* 0132: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0135: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0138 */
  a11 = a3;  /* 013a */
  a10 = a4;  /* 013c */
  a8 = (u32)&memcpy + 0x0;  /* 013e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0141: callx a8 (libc, via reloc-expand) */
  L_0144: a2 = a1 + (48);  /* 0144 */
  a6 = 184;  /* 0147 */
  a6 = a2 + a6;  /* 014a */
  a12 = a4;  /* 014c */
  a11 = a6;  /* 014e */
  a10 = 10;  /* 0150 */
  a8 = (u32)&esp_mesh_pack_multi_routing_table;  /* 0152: l32r -> func addr */
  a2 = esp_mesh_pack_multi_routing_table(a2, a3, a4, a5, a6, a7);  /* 0155: callx a8 via reloc-expand */
  a5 = LD32(a1 + 0xec);  /* 0158 */
  a5 = a5 << 8;  /* 015b */
  a2 = LD8U(a1 + 0xeb);  /* 015e */
  a5 = a5 | a2;  /* 0161 */
  a2 = 0;  /* 0164 */
  if (a5 == a2) goto L_017c;  /* 0166: beq a5, a2, 17c <esp_mesh_send_rtable_ack+0x130> */
  L_0169: a14 = a2;  /* 0169 */
  a13 = -1;  /* 016b */
  a12 = a6;  /* 016d */
  a11 = 2;  /* 016f */
  a10 = a3;  /* 0171: mov */
  a8 = (u32)&esp_mesh_send_mgmt + 0x0;  /* 0174: l32r -> global */
  a2 = esp_mesh_send_mgmt(a2, a3, a4, a5, a6, a7);  /* 0177: callx a8 via reloc-expand */
  a2 = a10;  /* 017a */
  L_017c: a8 = LD8U(a4 + 0x6);  /* 017c */
  a5 = 1;  /* 017f */
  a8 = (a8 >> 7) & 0x1;  /* 0181: extui width 1 */
  a9 = 0;  /* 0184 */
  if (a8 == 0) a9 = a5;  /* 0186 */
  a6 = (a9 >> 8) & 0x1;  /* 0189: extui width 1 */
  if (a9 != 0) goto L_0196;  /* 018c: bnez.n a9, 196 <esp_mesh_send_rtable_ack+0x14a> */
  L_018e: a8 = a8 + (-127);  /* 018e */
  if (a8 == 0) a6 = a5;  /* 0191 */
  if (a6 == 0) goto L_01a8;  /* 0194: beqz.n a6, 1a8 <esp_mesh_send_rtable_ack+0x15c> */
  L_0196: a12 = 14;  /* 0196 */
  a11 = 0;  /* 0198 */
  a10 = a4;  /* 019b: mov */
  a8 = (u32)&memset + 0x0;  /* 019e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01a1: callx a8 (libc, via reloc-expand) */
  goto L_020c;  /* 01a4: j */
  L_01a8: a12 = 180;  /* 01a8 */
  a11 = a6;  /* 01ab */
  a10 = a1 + (52);  /* 01ad */
  a8 = (u32)&memset + 0x0;  /* 01b0: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01b3: callx a8 (libc, via reloc-expand) */
  a11 = a3;  /* 01b6 */
  a4 = 19;  /* 01b8 */
  a12 = 6;  /* 01ba */
  a10 = a1 + (58);  /* 01bd */
  ST32(a1 + 0x30, a4);  /* 01c0 */
  ST8(a1 + 0x34, a5);  /* 01c3 */
  __asm__ volatile("" ::: "memory");  /* 01c6: memw */
  __asm__ volatile("" ::: "memory");  /* 01c9: memw */
  a8 = (u32)&memcpy + 0x0;  /* 01cc: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 01cf: callx a8 (libc, via reloc-expand) */
  a11 = a6;  /* 01d2: mov */
  a10 = a1 + (48);  /* 01d5 */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 01d8: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 01db: callx a8 via reloc-expand */
  if (a10 == 0) goto L_020c;  /* 01de: beqz.n a10, 20c <esp_mesh_send_rtable_ack+0x1c0> */
  L_01e0: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 01e0: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 01e3 */
  if (a3 == 0) goto L_020c;  /* 01e5: beqz.n a3, 20c <esp_mesh_send_rtable_ack+0x1c0> */
  L_01e7: a4 = LD32(a3 + 0x150);  /* 01e7 */
  if (a4 == 0) goto L_020c;  /* 01ea: beqz.n a4, 20c <esp_mesh_send_rtable_ack+0x1c0> */
  L_01ec: a10 = LD32(a3 + 0x158);  /* 01ec */
  a3 = 0x758;  /* 01ef */
  /* 01f2: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01f5 */
  a10 = a5;  /* 01f7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01f9: -> "mesh_route.c" */
  a14 = a11;  /* 01fc */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 01fe: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_monitor_nonassociated_children_str1_1 + 0x0);  /* 0201: l32r -> .rodata.esp_mesh_monitor_nonassociated_children.str1.1 */
  ST32(a1 + 0x0, a3);  /* 0204 */
  L_0206: __asm__ volatile("" ::: "memory");  /* 0206: memw */
  /* 0209: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_020c: return a2;  /* 020c: retw.n */
}


/* esp_mesh_send_rtable_request @ mesh_route.o 00000020 size 114B bind GLOBAL
 * Calls: memset, esp_mesh_send_mgmt | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=5); reloc-direct=2, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_send_rtable_request(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0020: entry a1, 64 (frame 64 bytes) */
  if (a2 != 0) goto L_0064;  /* 0023: bnez.n a2, 64 <esp_mesh_send_rtable_request+0x44> */
  L_0025: a2 = (u32)&g_log_level + 0x0;  /* 0025: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0028 */
  a2 = 0x00004008u;  /* 002a: l32r = 16392 */
  if (a3 < 3u) goto L_0090;  /* 002d: bltui a3, 3, 90 <esp_mesh_send_rtable_request+0x70> */
  L_0030: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0030: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0033 */
  if (a8 == 0) goto L_0090;  /* 0035: beqz a8, 90 <esp_mesh_send_rtable_request+0x70> */
  L_0038: a3 = LD32(a8 + 0x150);  /* 0038 */
  if (a3 == 0) goto L_0090;  /* 003b: beqz a3, 90 <esp_mesh_send_rtable_request+0x70> */
  L_003e: a10 = LD32(a8 + 0x158);  /* 003e */
  /* 0041: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x728;  /* 0044 */
  a13 = a10;  /* 0047 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0049: -> "mesh_route.c" */
  a10 = 3;  /* 004c */
  a14 = a11;  /* 004e: mov */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0051: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0054: -> "mesh_route.c" */
  ST32(a1 + 0x0, a8);  /* 0057 */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  /* 005d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0090;  /* 0060: j */
  L_0064: a12 = 7;  /* 0064 */
  a11 = 0;  /* 0066 */
  a10 = a1 + (16);  /* 0068 */
  a8 = (u32)&memset + 0x0;  /* 006b: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 006e: callx a8 (libc, via reloc-expand) */
  a10 = a2;  /* 0071 */
  a3 = 5;  /* 0073 */
  a14 = 0;  /* 0075 */
  a13 = -1;  /* 0077 */
  a12 = a1 + (16);  /* 0079 */
  a11 = 2;  /* 007c */
  ST8(a1 + 0x10, a3);  /* 007f */
  __asm__ volatile("" ::: "memory");  /* 0082: memw */
  __asm__ volatile("" ::: "memory");  /* 0085: memw */
  a8 = (u32)&esp_mesh_send_mgmt + 0x0;  /* 0088: l32r -> global */
  a2 = esp_mesh_send_mgmt(a2, a3, a4, a5, a6, a7);  /* 008b: callx a8 via reloc-expand */
  a2 = a10;  /* 008e */
  L_0090: return a2;  /* 0090: retw.n */
}


/* mesh_construct_rmv_announcement @ mesh_route.o 00000020 size 160B bind GLOBAL
 * Calls: memset, memcpy | Data refs: g_mesh_topology, g_mesh_self_sta_addr
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_construct_rmv_announcement(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0020: entry a1, 208 (frame 208 bytes) */
  a5 = 151;  /* 0023 */
  a12 = a5;  /* 0026 */
  a11 = 0;  /* 0028 */
  a10 = a1;  /* 002a */
  a8 = (u32)&memset + 0x0;  /* 002c: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 002f: callx a8 (libc, via reloc-expand) */
  a12 = 14;  /* 0032 */
  a11 = 0;  /* 0034 */
  a10 = a1 + a5;  /* 0037 */
  a8 = (u32)&memset + 0x0;  /* 003a: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 003d: callx a8 (libc, via reloc-expand) */
  a6 = (u32)&g_mesh_topology + 0x0;  /* 0040: l32r -> global */
  a3 = (a3 >> 16) & 0x1;  /* 0043: extui width 1 */
  a4 = (a4 >> 8) & 0x1;  /* 0046: extui width 1 */
  a12 = 6;  /* 0049 */
  a8 = LD32(a6 + 0x0);  /* 004b */
  a6 = (a3 >> 8) & 0x1;  /* 004d: extui width 1 */
  a3 = a3 >> 8;  /* 0050 */
  a11 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 0053: l32r -> global */
  if (a8 != 0) goto L_0089;  /* 0056: bnez.n a8, 89 <mesh_construct_rmv_announcement+0x69> */
  L_0058: a10 = a1 + (1);  /* 0058 */
  a8 = (u32)&memcpy + 0x0;  /* 005b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 005e: callx a8 (libc, via reloc-expand) */
  a12 = a5;  /* 0061 */
  a11 = a1;  /* 0063 */
  a5 = a2 + a5;  /* 0065 */
  a10 = a2;  /* 0067 */
  ST8(a1 + 0x7, a4);  /* 0069 */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  __asm__ volatile("" ::: "memory");  /* 006f: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0072: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0075: callx a8 (libc, via reloc-expand) */
  ST8(a5 + 0x0, a6);  /* 0078 */
  ST8(a5 + 0x1, a3);  /* 007b */
  __asm__ volatile("" ::: "memory");  /* 007e: memw */
  __asm__ volatile("" ::: "memory");  /* 0081: memw */
  goto L_00b9;  /* 0084: j */
  L_0089: a10 = 153;  /* 0089 */
  a10 = a1 + a10;  /* 008c */
  a8 = (u32)&memcpy + 0x0;  /* 008e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0091: callx a8 (libc, via reloc-expand) */
  if (a4 == 0) goto L_009c;  /* 0094: beqz.n a4, 9c <mesh_construct_rmv_announcement+0x7c> */
  L_0096: ST8(a1 + 0x99, a4);  /* 0096 */
  __asm__ volatile("" ::: "memory");  /* 0099: memw */
  L_009c: a11 = 151;  /* 009c */
  a12 = 8;  /* 009f */
  a11 = a1 + a11;  /* 00a1 */
  a10 = a2;  /* 00a4: mov */
  __asm__ volatile("" ::: "memory");  /* 00a7: memw */
  a8 = (u32)&memcpy + 0x0;  /* 00aa: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00ad: callx a8 (libc, via reloc-expand) */
  ST8(a2 + 0x8, a6);  /* 00b0 */
  ST8(a2 + 0x9, a3);  /* 00b3 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  L_00b9: a2 = 0;  /* 00b9 */
  __asm__ volatile("" ::: "memory");  /* 00bb: memw */
  return a2;  /* 00be: retw.n */
}


/* mesh_fill_rmv_sub_child @ mesh_route.o 0000003c size 860B bind GLOBAL
 * Calls: memcpy | indirect[8]: mem[a6+0x158]; unknown; mem[a9+0x158]; mem[a10+0x158] | Data refs: g_mesh_conn, g_mesh_ext_cfg, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, .rodata.mesh_fill_rmv_sub_child.str1.1, .bss.mesh_route_table, g_mesh_topology
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=9); reloc-direct=1, funcdb-attributed=0, unknown-indirect=8 */
u32 mesh_fill_rmv_sub_child(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a6, a7, a8, a9;
  /* 003c: entry a1, 96 (frame 96 bytes) */
  a4 = (a4 >> 16) & 0x1;  /* 003f: extui width 1 */
  a7 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 0042: sext */
  ST32(a1 + 0x30, a4);  /* 0045 */
  a9 = (a5 >> 16) & 0x1;  /* 0047: extui width 1 */
  a2 = (u32)&g_mesh_conn + 0x0;  /* 004a: l32r -> global */
  if ((i32)a7 < 0) goto L_01cc;  /* 004d: bltz a7, 1cc <mesh_fill_rmv_sub_child+0x190> */
  L_0050: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0050: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 0053 */
  if ((i32)a7 < (i32)a5) goto L_005c;  /* 0056: blt a7, a5, 5c <mesh_fill_rmv_sub_child+0x20> */
  L_0059: goto L_01cc;  /* 0059: j */
  L_005c: a5 = (u32)&g_log_level + 0x0;  /* 005c: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 005f */
  if (a6 < 3u) goto L_00b9;  /* 0061: bltui a6, 3, b9 <mesh_fill_rmv_sub_child+0x7d> */
  L_0064: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0064: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 0067 */
  if (a6 == 0) goto L_00b9;  /* 0069: beqz a6, b9 <mesh_fill_rmv_sub_child+0x7d> */
  L_006c: a4 = LD32(a6 + 0x150);  /* 006c */
  if (a4 == 0) goto L_00b9;  /* 006f: beqz a4, b9 <mesh_fill_rmv_sub_child+0x7d> */
  L_0072: a10 = LD32(a6 + 0x158);  /* 0072 */
  a6 = a7 << 6;  /* 0075 */
  a6 = a2 + a6;  /* 0078 */
  ST32(a1 + 0x3c, a9);  /* 007a */
  __asm__ volatile("" ::: "memory");  /* 007c: memw */
  /* 007f: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0082 */
  a10 = 3;  /* 0084 */
  a9 = LD32(a1 + 0x3c);  /* 0086 */
  a8 = LD32(a1 + 0x30);  /* 0088 */
  a15 = LD8U(a6 + 0x0);  /* 008a */
  ST32(a1 + 0x18, a8);  /* 008d */
  ST32(a1 + 0x14, a9);  /* 008f */
  a9 = LD8U(a6 + 0x5);  /* 0091 */
  ST32(a1 + 0x10, a9);  /* 0094 */
  a9 = LD8U(a6 + 0x4);  /* 0096 */
  ST32(a1 + 0xc, a9);  /* 0099 */
  a9 = LD8U(a6 + 0x3);  /* 009b */
  ST32(a1 + 0x8, a9);  /* 009e */
  a9 = LD8U(a6 + 0x2);  /* 00a0 */
  ST32(a1 + 0x4, a9);  /* 00a3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 00a5: -> "mesh_route.c" */
  a14 = a11;  /* 00a8 */
  a6 = LD8U(a6 + 0x1);  /* 00aa */
  a12 = (u32)(RODATA__rodata_mesh_fill_rmv_sub_child_str1_1 + 0x0);  /* 00ad: l32r -> .rodata.mesh_fill_rmv_sub_child.str1.1 */
  ST32(a1 + 0x0, a6);  /* 00b0 */
  __asm__ volatile("" ::: "memory");  /* 00b3: memw */
  /* 00b6: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_00b9: a11 = a7 << 6;  /* 00b9 */
  a12 = 6;  /* 00bc */
  a11 = a2 + a11;  /* 00be */
  a10 = a3;  /* 00c0: mov */
  a8 = (u32)&memcpy + 0x0;  /* 00c3: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 00c6: callx a8 (libc, via reloc-expand) */
  a6 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 00c9: l32r -> .bss.mesh_route_table (same-object static) */
  a4 = a7 + a7;  /* 00cc */
  a12 = a7 + (a6 << 1);  /* 00ce */
  a2 = LD8U(a12 + 0x1);  /* 00d1 */
  a2 = a2 << 8;  /* 00d4 */
  a9 = LD8U(a12 + 0x0);  /* 00d7 */
  a2 = a2 | a9;  /* 00da */
  if (a2 == 0) goto L_0394;  /* 00dd: beqz a2, 394 <mesh_fill_rmv_sub_child+0x358> */
  L_00e0: a7 = a7 + (8);  /* 00e0 */
  a2 = a7 + (a6 << 2);  /* 00e2 */
  a9 = LD8U(a2 + 0x9);  /* 00e5 */
  a9 = a9 << 8;  /* 00e8 */
  a10 = LD8U(a2 + 0x8);  /* 00eb */
  a9 = a9 | a10;  /* 00ee */
  a10 = LD8U(a2 + 0xa);  /* 00f1 */
  a10 = a10 << 16;  /* 00f4 */
  a10 = a10 | a9;  /* 00f7 */
  a9 = LD8U(a2 + 0xb);  /* 00fa */
  a9 = a9 << 24;  /* 00fd */
  a9 = a9 | a10;  /* 0100 */
  if (a9 == 0) goto L_0394;  /* 0103: beqz a9, 394 <mesh_fill_rmv_sub_child+0x358> */
  L_0106: a5 = LD32(a5 + 0x0);  /* 0106 */
  if (a5 < 3u) goto L_0185;  /* 0108: bltui a5, 3, 185 <mesh_fill_rmv_sub_child+0x149> */
  L_010b: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 010b: l32r -> global */
  a9 = LD32(a5 + 0x0);  /* 010e */
  if (a9 == 0) goto L_0185;  /* 0110: beqz a9, 185 <mesh_fill_rmv_sub_child+0x149> */
  L_0113: a5 = LD32(a9 + 0x150);  /* 0113 */
  if (a5 == 0) goto L_0185;  /* 0116: beqz a5, 185 <mesh_fill_rmv_sub_child+0x149> */
  L_0119: a10 = LD32(a9 + 0x158);  /* 0119 */
  ST32(a1 + 0x34, a12);  /* 011c */
  __asm__ volatile("" ::: "memory");  /* 011f: memw */
  /* 0122: INDIRECT callx a10 <- mem[a9+0x158]; result unknown */ a2 = 0;
  a11 = LD8U(a2 + 0x9);  /* 0125 */
  a11 = a11 << 8;  /* 0128 */
  a9 = LD8U(a2 + 0x8);  /* 012b */
  a11 = a11 | a9;  /* 012e */
  a9 = LD8U(a2 + 0xa);  /* 0131 */
  a9 = a9 << 16;  /* 0134 */
  a9 = a9 | a11;  /* 0137 */
  a2 = LD8U(a2 + 0xb);  /* 013a */
  a2 = a2 << 24;  /* 013d */
  a2 = a2 | a9;  /* 0140 */
  a8 = LD32(a1 + 0x30);  /* 0143 */
  a12 = LD32(a1 + 0x34);  /* 0145 */
  a15 = LD8U(a2 + 0x0);  /* 0147 */
  ST32(a1 + 0x18, a8);  /* 014a */
  a9 = LD8U(a12 + 0x1);  /* 014c */
  a9 = a9 << 8;  /* 014f */
  a13 = LD8U(a12 + 0x0);  /* 0152 */
  a9 = a9 | a13;  /* 0155 */
  a13 = a10;  /* 0158 */
  a10 = 3;  /* 015a */
  ST32(a1 + 0x14, a9);  /* 015c */
  a9 = LD8U(a2 + 0x5);  /* 015e */
  ST32(a1 + 0x10, a9);  /* 0161 */
  a9 = LD8U(a2 + 0x4);  /* 0163 */
  ST32(a1 + 0xc, a9);  /* 0166 */
  a9 = LD8U(a2 + 0x3);  /* 0168 */
  ST32(a1 + 0x8, a9);  /* 016b */
  a9 = LD8U(a2 + 0x2);  /* 016d */
  ST32(a1 + 0x4, a9);  /* 0170 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0172: -> "mesh_route.c" */
  a14 = a11;  /* 0175 */
  a2 = LD8U(a2 + 0x1);  /* 0177 */
  a12 = (u32)(RODATA__rodata_mesh_fill_rmv_sub_child_str1_1 + 0x0);  /* 017a: l32r -> .rodata.mesh_fill_rmv_sub_child.str1.1 */
  ST32(a1 + 0x0, a2);  /* 017d */
  __asm__ volatile("" ::: "memory");  /* 017f: memw */
  /* 0182: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_0185: a10 = a3 + (6);  /* 0185 */
  a8 = LD32(a1 + 0x30);  /* 0187 */
  a12 = a8 + (-1);  /* 0189 */
  a8 = a6 + a4;  /* 018b */
  a2 = LD8U(a8 + 0x1);  /* 018d */
  a2 = a2 << 8;  /* 0190 */
  a4 = LD8U(a8 + 0x0);  /* 0193 */
  a2 = a2 | a4;  /* 0196 */
  a12 = ((i32)a12 < (i32)a2) ? a12 : a2;  /* 0199: min */
  a2 = a7 + (a6 << 2);  /* 019c */
  a5 = LD8U(a2 + 0x9);  /* 019f */
  a12 = a12 + (a12 << 1);  /* 01a2 */
  a5 = a5 << 8;  /* 01a5 */
  a12 = a12 + a12;  /* 01a8 */
  a4 = LD8U(a2 + 0x8);  /* 01aa */
  a5 = a5 | a4;  /* 01ad */
  a4 = LD8U(a2 + 0xa);  /* 01b0 */
  a4 = a4 << 16;  /* 01b3 */
  a4 = a4 | a5;  /* 01b6 */
  a11 = LD8U(a2 + 0xb);  /* 01b9 */
  a11 = a11 << 24;  /* 01bc */
  a11 = a11 | a4;  /* 01bf */
  a8 = (u32)&memcpy + 0x0;  /* 01c2: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 01c5: callx a8 (libc, via reloc-expand) */
  goto L_0394;  /* 01c8: j */
  L_01cc: a5 = 0;  /* 01cc */
  a6 = a5;  /* 01ce */
  a7 = a5;  /* 01d0 */
  a4 = a5;  /* 01d2 */
  L_01d4: a8 = (u32)&g_mesh_conn + 0x0;  /* 01d4: l32r -> global */
  a9 = a4 << 6;  /* 01d7 */
  a9 = a8 + a9;  /* 01da */
  a9 = LD32(a9 + 0x4);  /* 01dc */
  if (((a9 >> 16) & 1) != 0) goto L_01e4;  /* 01de: bbsi a9, 16, 1e4 <mesh_fill_rmv_sub_child+0x1a8> */
  L_01e1: goto L_0389;  /* 01e1: j */
  L_01e4: a9 = (u32)&g_log_level + 0x0;  /* 01e4: l32r -> global */
  a9 = LD32(a9 + 0x0);  /* 01e7 */
  if (a9 < 3u) goto L_0255;  /* 01e9: bltui a9, 3, 255 <mesh_fill_rmv_sub_child+0x219> */
  L_01ec: a9 = (u32)&g_osi_funcs_p + 0x0;  /* 01ec: l32r -> global */
  a10 = LD32(a9 + 0x0);  /* 01ef */
  if (a10 == 0) goto L_0255;  /* 01f1: beqz a10, 255 <mesh_fill_rmv_sub_child+0x219> */
  L_01f4: a9 = LD32(a10 + 0x150);  /* 01f4 */
  if (a9 == 0) goto L_0255;  /* 01f7: beqz a9, 255 <mesh_fill_rmv_sub_child+0x219> */
  L_01fa: a10 = LD32(a10 + 0x158);  /* 01fa */
  ST32(a1 + 0x3c, a9);  /* 01fd */
  __asm__ volatile("" ::: "memory");  /* 01ff: memw */
  /* 0202: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a15 = a4;  /* 0205 */
  a8 = LD32(a1 + 0x30);  /* 0207 */
  a12 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0209: l32r -> .bss.mesh_route_table (same-object static) */
  a12 = a4 + (a12 << 1);  /* 020c */
  ST32(a1 + 0x24, a5);  /* 020f */
  ST32(a1 + 0x20, a6);  /* 0211 */
  ST32(a1 + 0x1c, a8);  /* 0213 */
  a13 = LD8U(a12 + 0x0);  /* 0215 */
  a12 = LD8U(a12 + 0x1);  /* 0218 */
  a12 = a12 << 8;  /* 021b */
  a12 = a12 | a13;  /* 021e */
  a13 = a10;  /* 0221 */
  ST32(a1 + 0x18, a12);  /* 0223 */
  a10 = 3;  /* 0225 */
  a12 = LD8U(a2 + 0x5);  /* 0227 */
  ST32(a1 + 0x14, a12);  /* 022a */
  a12 = LD8U(a2 + 0x4);  /* 022c */
  ST32(a1 + 0x10, a12);  /* 022f */
  a12 = LD8U(a2 + 0x3);  /* 0231 */
  ST32(a1 + 0xc, a12);  /* 0234 */
  a12 = LD8U(a2 + 0x2);  /* 0236 */
  ST32(a1 + 0x8, a12);  /* 0239 */
  a12 = LD8U(a2 + 0x1);  /* 023b */
  ST32(a1 + 0x4, a12);  /* 023e */
  a12 = LD8U(a2 + 0x0);  /* 0240 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0243: -> "mesh_route.c" */
  a14 = a11;  /* 0246 */
  ST32(a1 + 0x0, a12);  /* 0248 */
  a9 = LD32(a1 + 0x3c);  /* 024a */
  a12 = (u32)(RODATA__rodata_mesh_fill_rmv_sub_child_str1_1 + 0x0);  /* 024c: l32r -> .rodata.mesh_fill_rmv_sub_child.str1.1 */
  __asm__ volatile("" ::: "memory");  /* 024f: memw */
  /* 0252: INDIRECT callx a9 <- mem[a1+0x3c]; result unknown */ a2 = 0;
  L_0255: a11 = a2;  /* 0255 */
  a12 = 6;  /* 0257 */
  a10 = a3 + a7;  /* 0259 */
  a8 = (u32)&memcpy + 0x0;  /* 025b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 025e: callx a8 (libc, via reloc-expand) */
  a9 = (u32)&g_mesh_topology + 0x0;  /* 0261: l32r -> global */
  a10 = 162;  /* 0264 */
  a6 = a6 + (1);  /* 0267 */
  a11 = LD32(a9 + 0x0);  /* 0269 */
  a9 = 139;  /* 026b */
  if (a11 != 0) a9 = a10;  /* 026e */
  if ((i32)a9 >= (i32)a6) goto L_0277;  /* 0271: bge a9, a6, 277 <mesh_fill_rmv_sub_child+0x23b> */
  L_0274: goto L_0394;  /* 0274: j */
  L_0277: a7 = a7 + (6);  /* 0277 */
  a10 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 0279: l32r -> .bss.mesh_route_table (same-object static) */
  a13 = a4 + (a10 << 1);  /* 027c */
  a9 = LD8U(a13 + 0x1);  /* 027f */
  a9 = a9 << 8;  /* 0282 */
  a11 = LD8U(a13 + 0x0);  /* 0285 */
  a9 = a9 | a11;  /* 0288 */
  if (a9 == 0) goto L_0389;  /* 028b: beqz a9, 389 <mesh_fill_rmv_sub_child+0x34d> */
  L_028e: a11 = a4 + (8);  /* 028e */
  a11 = a11 + (a10 << 2);  /* 0290 */
  a10 = LD8U(a11 + 0x9);  /* 0293 */
  a10 = a10 << 8;  /* 0296 */
  a12 = LD8U(a11 + 0x8);  /* 0299 */
  a10 = a10 | a12;  /* 029c */
  a12 = LD8U(a11 + 0xa);  /* 029f */
  a12 = a12 << 16;  /* 02a2 */
  a12 = a12 | a10;  /* 02a5 */
  a10 = LD8U(a11 + 0xb);  /* 02a8 */
  a10 = a10 << 24;  /* 02ab */
  a10 = a10 | a12;  /* 02ae */
  if (a10 == 0) goto L_0389;  /* 02b1: beqz a10, 389 <mesh_fill_rmv_sub_child+0x34d> */
  L_02b4: a8 = LD32(a1 + 0x30);  /* 02b4 */
  a5 = a8 - a6;  /* 02b6: sub */
  a5 = ((i32)a5 < (i32)a9) ? a5 : a9;  /* 02b9: min */
  a9 = (u32)&g_log_level + 0x0;  /* 02bc: l32r -> global */
  a9 = LD32(a9 + 0x0);  /* 02bf */
  if (a9 >= 3u) goto L_02c7;  /* 02c1: bgeui a9, 3, 2c7 <mesh_fill_rmv_sub_child+0x28b> */
  L_02c4: goto L_0348;  /* 02c4: j */
  L_02c7: a9 = (u32)&g_osi_funcs_p + 0x0;  /* 02c7: l32r -> global */
  a10 = LD32(a9 + 0x0);  /* 02ca */
  if (a10 == 0) goto L_0348;  /* 02cc: beqz a10, 348 <mesh_fill_rmv_sub_child+0x30c> */
  L_02cf: a9 = LD32(a10 + 0x150);  /* 02cf */
  if (a9 == 0) goto L_0348;  /* 02d2: beqz a9, 348 <mesh_fill_rmv_sub_child+0x30c> */
  L_02d5: a10 = LD32(a10 + 0x158);  /* 02d5 */
  ST32(a1 + 0x3c, a9);  /* 02d8 */
  ST32(a1 + 0x34, a11);  /* 02da */
  ST32(a1 + 0x38, a13);  /* 02dc */
  __asm__ volatile("" ::: "memory");  /* 02de: memw */
  /* 02e1: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a11 = LD32(a1 + 0x34);  /* 02e4 */
  a12 = LD8U(a11 + 0x9);  /* 02e6 */
  a12 = a12 << 8;  /* 02e9 */
  a14 = LD8U(a11 + 0x8);  /* 02ec */
  a12 = a12 | a14;  /* 02ef */
  a14 = LD8U(a11 + 0xa);  /* 02f2 */
  a14 = a14 << 16;  /* 02f5 */
  a14 = a14 | a12;  /* 02f8 */
  a12 = LD8U(a11 + 0xb);  /* 02fb */
  a12 = a12 << 24;  /* 02fe */
  a12 = a12 | a14;  /* 0301 */
  a13 = LD32(a1 + 0x38);  /* 0304 */
  a15 = LD8U(a12 + 0x0);  /* 0306 */
  ST32(a1 + 0x1c, a5);  /* 0309 */
  ST32(a1 + 0x18, a6);  /* 030b */
  a14 = LD8U(a13 + 0x0);  /* 030d */
  a13 = LD8U(a13 + 0x1);  /* 0310 */
  a13 = a13 << 8;  /* 0313 */
  a13 = a13 | a14;  /* 0316 */
  ST32(a1 + 0x14, a13);  /* 0319 */
  a13 = LD8U(a12 + 0x5);  /* 031b */
  ST32(a1 + 0x10, a13);  /* 031e */
  a13 = LD8U(a12 + 0x4);  /* 0320 */
  ST32(a1 + 0xc, a13);  /* 0323 */
  a13 = LD8U(a12 + 0x3);  /* 0325 */
  ST32(a1 + 0x8, a13);  /* 0328 */
  a13 = LD8U(a12 + 0x2);  /* 032a */
  ST32(a1 + 0x4, a13);  /* 032d */
  a13 = a10;  /* 032f */
  a10 = 3;  /* 0331 */
  a12 = LD8U(a12 + 0x1);  /* 0333 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0336: -> "mesh_route.c" */
  a14 = a11;  /* 0339 */
  ST32(a1 + 0x0, a12);  /* 033b */
  a9 = LD32(a1 + 0x3c);  /* 033d */
  a12 = (u32)(RODATA__rodata_mesh_fill_rmv_sub_child_str1_1 + 0x0);  /* 033f: l32r -> .rodata.mesh_fill_rmv_sub_child.str1.1 */
  __asm__ volatile("" ::: "memory");  /* 0342: memw */
  /* 0345: INDIRECT callx a9 <- mem[a1+0x3c]; result unknown */ a2 = 0;
  L_0348: a9 = a4 + (8);  /* 0348 */
  a13 = a5 + (a5 << 1);  /* 034a */
  a10 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 034d: l32r -> .bss.mesh_route_table (same-object static) */
  a13 = a13 + a13;  /* 0350 */
  a9 = a9 + (a10 << 2);  /* 0352 */
  a12 = a13;  /* 0355 */
  a6 = a6 + a5;  /* 0357 */
  a11 = LD8U(a9 + 0x9);  /* 0359 */
  a11 = a11 << 8;  /* 035c */
  a10 = LD8U(a9 + 0x8);  /* 035f */
  a11 = a11 | a10;  /* 0362 */
  a10 = LD8U(a9 + 0xa);  /* 0365 */
  a10 = a10 << 16;  /* 0368 */
  a10 = a10 | a11;  /* 036b */
  a11 = LD8U(a9 + 0xb);  /* 036e */
  a11 = a11 << 24;  /* 0371 */
  a11 = a11 | a10;  /* 0374 */
  a10 = a3 + a7;  /* 0377 */
  ST32(a1 + 0x38, a13);  /* 0379 */
  __asm__ volatile("" ::: "memory");  /* 037c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 037f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 0382: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x38);  /* 0385 */
  a7 = a7 + a13;  /* 0387 */
  L_0389: a4 = a4 + (1);  /* 0389 */
  a2 = a2 + (64);  /* 038b */
  if (a4 == 10) goto L_0394;  /* 038e: beqi a4, 10, 394 <mesh_fill_rmv_sub_child+0x358> */
  L_0391: goto L_01d4;  /* 0391: j */
  L_0394: a2 = 0;  /* 0394 */
  return a2;  /* 0396: retw.n */
}


/* mesh_get_subnet_nodes_list @ mesh_route.o 00000028 size 214B bind GLOBAL
 * Calls: esp_mesh_get_child_idx, memcpy | indirect[3]: mem[a2+0x158]; mem[a2+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, g_mesh_ext_cfg, .bss.mesh_route_table
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_get_subnet_nodes_list(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0028: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_006a;  /* 002b: bnez.n a2, 6a <mesh_get_subnet_nodes_list+0x42> */
  L_002d: a2 = (u32)&g_log_level + 0x0;  /* 002d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0030 */
  if (a2 >= 3u) goto L_0038;  /* 0032: bgeui a2, 3, 38 <mesh_get_subnet_nodes_list+0x10> */
  L_0035: goto L_0064;  /* 0035: j */
  L_0038: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0038: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 003b */
  if (a2 == 0) goto L_0064;  /* 003d: beqz.n a2, 64 <mesh_get_subnet_nodes_list+0x3c> */
  L_003f: a3 = LD32(a2 + 0x150);  /* 003f */
  if (a3 == 0) goto L_0064;  /* 0042: beqz.n a3, 64 <mesh_get_subnet_nodes_list+0x3c> */
  L_0044: a10 = LD32(a2 + 0x158);  /* 0044 */
  a2 = 0x713;  /* 0047 */
  /* 004a: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 004d: -> "mesh_route.c" */
  L_0050: a13 = a10;  /* 0050 */
  a14 = a11;  /* 0052 */
  a10 = 3;  /* 0054 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0056: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0059: -> "mesh_route.c" */
  ST32(a1 + 0x0, a2);  /* 005c */
  __asm__ volatile("" ::: "memory");  /* 005e: memw */
  /* 0061: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0064: a2 = 0x00004008u;  /* 0064: l32r = 16392 */
  goto L_00fc;  /* 0067: j */
  L_006a: if (a3 != 0) goto L_0095;  /* 006a: bnez.n a3, 95 <mesh_get_subnet_nodes_list+0x6d> */
  L_006c: a2 = (u32)&g_log_level + 0x0;  /* 006c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 006f */
  if (a2 < 3u) goto L_0064;  /* 0071: bltui a2, 3, 64 <mesh_get_subnet_nodes_list+0x3c> */
  L_0074: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0074: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0077 */
  if (a2 == 0) goto L_0064;  /* 007a: beqz a2, 64 <mesh_get_subnet_nodes_list+0x3c> */
  L_007d: a3 = LD32(a2 + 0x150);  /* 007d */
  if (a3 == 0) goto L_0064;  /* 0080: beqz a3, 64 <mesh_get_subnet_nodes_list+0x3c> */
  L_0083: a10 = LD32(a2 + 0x158);  /* 0083 */
  a2 = 0x714;  /* 0086 */
  /* 0089: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 008c: -> "mesh_route.c" */
  goto L_0050;  /* 008f: j */
  L_0095: if (a4 == 0) goto L_0064;  /* 0095: beqz a4, 64 <mesh_get_subnet_nodes_list+0x3c> */
  L_0098: a10 = a2;  /* 0098 */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 009a: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6, a7);  /* 009d: callx a8 via reloc-expand */
  a10 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 00a0: sext */
  if ((i32)a10 < 0) goto L_0064;  /* 00a3: bltz a10, 64 <mesh_get_subnet_nodes_list+0x3c> */
  L_00a6: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 00a6: l32r -> global */
  a2 = LD8U(a2 + 0xbd);  /* 00a9 */
  if ((i32)a10 >= (i32)a2) goto L_0064;  /* 00ac: bge a10, a2, 64 <mesh_get_subnet_nodes_list+0x3c> */
  L_00af: a8 = a10 + (8);  /* 00af */
  a12 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 00b1: l32r -> .bss.mesh_route_table (same-object static) */
  a8 = a8 + (a12 << 2);  /* 00b4 */
  a11 = LD8U(a8 + 0x9);  /* 00b7 */
  a11 = a11 << 8;  /* 00ba */
  a2 = LD8U(a8 + 0x8);  /* 00bd */
  a11 = a11 | a2;  /* 00c0 */
  a2 = 0;  /* 00c3 */
  a9 = LD8U(a8 + 0xa);  /* 00c5 */
  a9 = a9 << 16;  /* 00c8 */
  a9 = a9 | a11;  /* 00cb */
  a11 = LD8U(a8 + 0xb);  /* 00ce */
  a11 = a11 << 24;  /* 00d1 */
  a11 = a11 | a9;  /* 00d4 */
  if (a11 == a2) goto L_00fc;  /* 00d7: beq a11, a2, fc <mesh_get_subnet_nodes_list+0xd4> */
  L_00da: a10 = a10 + (a12 << 1);  /* 00da */
  a12 = LD8U(a10 + 0x1);  /* 00dd */
  a12 = a12 << 8;  /* 00e0 */
  a8 = LD8U(a10 + 0x0);  /* 00e3 */
  a12 = a12 | a8;  /* 00e6 */
  if (a12 == a2) goto L_00fc;  /* 00e9: beq a12, a2, fc <mesh_get_subnet_nodes_list+0xd4> */
  L_00ec: a12 = ((i32)a12 < (i32)a4) ? a12 : a4;  /* 00ec: min */
  a12 = a12 + (a12 << 1);  /* 00ef */
  a12 = a12 + a12;  /* 00f2 */
  a10 = a3;  /* 00f4 */
  a8 = (u32)&memcpy + 0x0;  /* 00f6: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00f9: callx a8 (libc, via reloc-expand) */
  L_00fc: return a2;  /* 00fc: retw.n */
}


/* mesh_get_subnet_nodes_num @ mesh_route.o 00000024 size 156B bind GLOBAL
 * Calls: esp_mesh_get_child_idx | indirect[3]: mem[a2+0x158]; mem[a2+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, g_mesh_ext_cfg, .bss.mesh_route_table
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=6); reloc-direct=1, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_get_subnet_nodes_num(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0052;  /* 0027: bnez.n a2, 52 <mesh_get_subnet_nodes_num+0x2e> */
  L_0029: a2 = (u32)&g_log_level + 0x0;  /* 0029: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 002c */
  if (a2 >= 3u) goto L_0035;  /* 002e: bgeui a2, 3, 35 <mesh_get_subnet_nodes_num+0x11> */
  L_0031: goto L_0088;  /* 0031: j */
  L_0035: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0035: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0038 */
  if (a2 == 0) goto L_0088;  /* 003a: beqz a2, 88 <mesh_get_subnet_nodes_num+0x64> */
  L_003d: a3 = LD32(a2 + 0x150);  /* 003d */
  if (a3 == 0) goto L_0088;  /* 0040: beqz a3, 88 <mesh_get_subnet_nodes_num+0x64> */
  L_0043: a10 = LD32(a2 + 0x158);  /* 0043 */
  a2 = 0x703;  /* 0046 */
  /* 0049: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 004c: -> "mesh_route.c" */
  goto L_0074;  /* 004f: j */
  L_0052: if (a3 != 0) goto L_008e;  /* 0052: bnez.n a3, 8e <mesh_get_subnet_nodes_num+0x6a> */
  L_0054: a2 = (u32)&g_log_level + 0x0;  /* 0054: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0057 */
  if (a2 < 3u) goto L_0088;  /* 0059: bltui a2, 3, 88 <mesh_get_subnet_nodes_num+0x64> */
  L_005c: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 005c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 005f */
  if (a2 == 0) goto L_0088;  /* 0061: beqz.n a2, 88 <mesh_get_subnet_nodes_num+0x64> */
  L_0063: a3 = LD32(a2 + 0x150);  /* 0063 */
  if (a3 == 0) goto L_0088;  /* 0066: beqz.n a3, 88 <mesh_get_subnet_nodes_num+0x64> */
  L_0068: a10 = LD32(a2 + 0x158);  /* 0068 */
  a2 = 0x704;  /* 006b */
  /* 006e: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0071: -> "mesh_route.c" */
  L_0074: a13 = a10;  /* 0074 */
  a14 = a11;  /* 0076 */
  a10 = 3;  /* 0078 */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 007a: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 007d: -> "mesh_route.c" */
  ST32(a1 + 0x0, a2);  /* 0080 */
  __asm__ volatile("" ::: "memory");  /* 0082: memw */
  /* 0085: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0088: a2 = 0x00004008u;  /* 0088: l32r = 16392 */
  goto L_00bb;  /* 008b: j */
  L_008e: a10 = a2;  /* 008e */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 0090: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6, a7);  /* 0093: callx a8 via reloc-expand */
  a10 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 0096: sext */
  if ((i32)a10 < 0) goto L_0088;  /* 0099: bltz a10, 88 <mesh_get_subnet_nodes_num+0x64> */
  L_009c: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 009c: l32r -> global */
  a2 = LD8U(a2 + 0xbd);  /* 009f */
  if ((i32)a10 >= (i32)a2) goto L_0088;  /* 00a2: bge a10, a2, 88 <mesh_get_subnet_nodes_num+0x64> */
  L_00a5: a2 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 00a5: l32r -> .bss.mesh_route_table (same-object static) */
  a10 = a10 + (a2 << 1);  /* 00a8 */
  a8 = LD8U(a10 + 0x1);  /* 00ab */
  a8 = a8 << 8;  /* 00ae */
  a2 = LD8U(a10 + 0x0);  /* 00b1 */
  a8 = a8 | a2;  /* 00b4 */
  a2 = 0;  /* 00b7 */
  ST32(a3 + 0x0, a8);  /* 00b9 */
  L_00bb: __asm__ volatile("" ::: "memory");  /* 00bb: memw */
  return a2;  /* 00be: retw.n */
}


/* mesh_malloc_rmv_announcement @ mesh_route.o 00000028 size 148B bind GLOBAL
 * Calls: mesh_malloc, esp_mesh_tx_tid_flush | indirect[3]: mem[a8+0x158]; mem[a6+0xb8]; unknown | Data refs: g_mesh_topology, .rodata.__func__$7, g_osi_funcs_p, .rodata.mesh_malloc_rmv_announcement.str1.1, .rodata.esp_mesh_lookup_route.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_malloc_rmv_announcement(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0028: entry a1, 64 (frame 64 bytes) */
  a3 = (a3 >> 16) & 0x1;  /* 002b: extui width 1 */
  a3 = a3 + (a3 << 1);  /* 002e */
  a4 = (u32)&g_mesh_topology + 0x0;  /* 0031: l32r -> global */
  a8 = a3 + a3;  /* 0034 */
  a8 = (a8 >> 16) & 0x1;  /* 0036: extui width 1 */
  a3 = a8 + (10);  /* 0039 */
  a3 = (a3 >> 16) & 0x1;  /* 003b: extui width 1 */
  a5 = LD32(a4 + 0x0);  /* 003e */
  if (a5 != 0) goto L_004a;  /* 0040: bnez.n a5, 4a <mesh_malloc_rmv_announcement+0x22> */
  L_0042: a3 = 153;  /* 0042 */
  a8 = a8 + a3;  /* 0045 */
  a3 = (a8 >> 16) & 0x1;  /* 0047: extui width 1 */
  L_004a: if (a2 == 0) goto L_0052;  /* 004a: beqz.n a2, 52 <mesh_malloc_rmv_announcement+0x2a> */
  L_004c: ST16(a2 + 0x0, a3);  /* 004c */
  __asm__ volatile("" ::: "memory");  /* 004f: memw */
  L_0052: a12 = 0x256;  /* 0052 */
  a10 = a3;  /* 0055: mov */
  a11 = (u32)(RODATA__rodata___func___7 + 0x0);  /* 0058: l32r -> .rodata.__func__$7 */
  __asm__ volatile("" ::: "memory");  /* 005b: memw */
  a8 = (u32)&mesh_malloc + 0x0;  /* 005e: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0061: callx a8 via reloc-expand */
  a2 = a10;  /* 0064: mov */
  if (a10 != 0) goto L_00ba;  /* 0067: bnez a10, ba <mesh_malloc_rmv_announcement+0x92> */
  L_006a: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 006a: l32r -> global */
  a8 = LD32(a6 + 0x0);  /* 006d */
  if (a8 == 0) goto L_00b4;  /* 006f: beqz a8, b4 <mesh_malloc_rmv_announcement+0x8c> */
  L_0072: a5 = LD32(a8 + 0x150);  /* 0072 */
  if (a5 == 0) goto L_00b4;  /* 0075: beqz.n a5, b4 <mesh_malloc_rmv_announcement+0x8c> */
  L_0077: a10 = LD32(a8 + 0x158);  /* 0077 */
  /* 007a: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 007d */
  a8 = LD32(a4 + 0x0);  /* 007f */
  a4 = (u32)(RODATA__rodata_mesh_malloc_rmv_announcement_str1_1 + 0x0);  /* 0081: -> "tree" */
  if (a8 == 0) goto L_008a;  /* 0084: beqz a8, 8a <mesh_malloc_rmv_announcement+0x62> */
  L_0087: a4 = (u32)(RODATA__rodata_mesh_malloc_rmv_announcement_str1_1 + 0x0);  /* 0087: -> "tree" */
  L_008a: a6 = LD32(a6 + 0x0);  /* 008a */
  a10 = LD32(a6 + 0xb8);  /* 008c */
  /* 008f: INDIRECT callx a10 <- mem[a6+0xb8]; result unknown */ a2 = 0;
  a13 = a7;  /* 0092 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0094: -> "mesh_route.c" */
  a14 = a11;  /* 0097 */
  ST32(a1 + 0xc, a3);  /* 0099 */
  a3 = 0x258;  /* 009b */
  a15 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 009e: -> "mesh_route.c" */
  a12 = (u32)(RODATA__rodata_mesh_malloc_rmv_announcement_str1_1 + 0x0);  /* 00a1: -> "tree" */
  ST32(a1 + 0x10, a10);  /* 00a4 */
  a10 = 2;  /* 00a6 */
  ST32(a1 + 0x8, a4);  /* 00a8 */
  ST32(a1 + 0x4, a3);  /* 00aa */
  ST32(a1 + 0x0, a3);  /* 00ac */
  __asm__ volatile("" ::: "memory");  /* 00ae: memw */
  /* 00b1: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_00b4: a8 = (u32)&esp_mesh_tx_tid_flush + 0x0;  /* 00b4: l32r -> global */
  a2 = esp_mesh_tx_tid_flush(a2, a3, a4, a5, a6, a7);  /* 00b7: callx a8 via reloc-expand */
  L_00ba: return a2;  /* 00ba: retw.n */
}


/* mesh_pack_rmv_announcement @ mesh_route.o 00000014 size 189B bind GLOBAL
 * Calls: mesh_malloc_rmv_announcement, mesh_construct_rmv_announcement, mesh_free | Data refs: g_mesh_rmv_opt, .rodata.__func__$6
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=5); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_pack_rmv_announcement(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0014: entry a1, 48 (frame 48 bytes) */
  a4 = (a4 >> 16) & 0x1;  /* 0017: extui width 1 */
  a10 = a1;  /* 001a */
  a6 = (a2 >> 8) & 0x1;  /* 001c: extui width 1 */
  a11 = a4;  /* 001f */
  a2 = 0;  /* 0021 */
  if (a3 != 0) a10 = a3;  /* 0023 */
  ST16(a1 + 0x0, a2);  /* 0026 */
  __asm__ volatile("" ::: "memory");  /* 0029: memw */
  __asm__ volatile("" ::: "memory");  /* 002c: memw */
  a8 = (u32)&mesh_malloc_rmv_announcement;  /* 002f: l32r -> func addr */
  a2 = mesh_malloc_rmv_announcement(a2, a3, a4, a5, a6, a7);  /* 0032: callx a8 via reloc-expand */
  a5 = (a5 >> 8) & 0x1;  /* 0035: extui width 1 */
  a2 = a10;  /* 0038 */
  if (a10 == 0) goto L_00cc;  /* 003a: beqz a10, cc <mesh_pack_rmv_announcement+0xb8> */
  L_003d: a12 = a5;  /* 003d: mov */
  a11 = a4;  /* 0040 */
  a8 = (u32)&mesh_construct_rmv_announcement;  /* 0042: l32r -> func addr */
  a2 = mesh_construct_rmv_announcement(a2, a3, a4, a5, a6, a7);  /* 0045: callx a8 via reloc-expand */
  a4 = (i32)(a6 << (32 - 7)) >> (32 - 7);  /* 0048: sext */
  a5 = (u32)&g_mesh_rmv_opt + 0x0;  /* 004b: l32r -> global */
  a8 = a4 - a4;  /* 004e: subx8 */
  a9 = 4;  /* 0051 */
  a8 = a5 + a8;  /* 0054 */
  a6 = a4 << 3;  /* 0057 */
  ST8(a8 + 0x0, a9);  /* 005a */
  __asm__ volatile("" ::: "memory");  /* 005d: memw */
  a9 = LD16U(a1 + 0x0);  /* 0060 */
  if (a3 == 0) goto L_0069;  /* 0063: beqz a3, 69 <mesh_pack_rmv_announcement+0x55> */
  L_0066: a9 = LD16U(a3 + 0x0);  /* 0066 */
  L_0069: a8 = a6 - a4;  /* 0069: sub */
  a8 = a5 + a8;  /* 006c */
  a10 = LD8U(a8 + 0x4);  /* 006e */
  a10 = a10 << 8;  /* 0071 */
  ST8(a8 + 0x1, a9);  /* 0074 */
  __asm__ volatile("" ::: "memory");  /* 0077: memw */
  a9 = a9 >> 8;  /* 007a */
  a3 = LD8U(a8 + 0x3);  /* 007d */
  a10 = a10 | a3;  /* 0080 */
  ST8(a8 + 0x2, a9);  /* 0083 */
  __asm__ volatile("" ::: "memory");  /* 0086: memw */
  a9 = LD8U(a8 + 0x5);  /* 0089 */
  a9 = a9 << 16;  /* 008c */
  a9 = a9 | a10;  /* 008f */
  a10 = LD8U(a8 + 0x6);  /* 0092 */
  a10 = a10 << 24;  /* 0095 */
  a10 = a10 | a9;  /* 0098 */
  if (a10 == 0) goto L_00ad;  /* 009b: beqz a10, ad <mesh_pack_rmv_announcement+0x99> */
  L_009e: a11 = (u32)(RODATA__rodata___func___6 + 0x0);  /* 009e: l32r -> .rodata.__func__$6 */
  a12 = 0x294;  /* 00a1 */
  __asm__ volatile("" ::: "memory");  /* 00a4: memw */
  a8 = (u32)&mesh_free + 0x0;  /* 00a7: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 00aa: callx a8 via reloc-expand */
  L_00ad: a6 = a6 - a4;  /* 00ad: sub */
  a5 = a5 + a6;  /* 00b0 */
  a4 = (a2 >> 8) & 0x1ff;  /* 00b2: extui width 9 */
  ST8(a5 + 0x4, a4);  /* 00b5 */
  a4 = (a2 >> 8) & 0x1ffff;  /* 00b8: extui width 17 */
  a3 = a5 + (3);  /* 00bb */
  ST8(a5 + 0x5, a4);  /* 00bd */
  a4 = (a2 >> 8) & 0x1ffffff;  /* 00c0: extui width 25 */
  ST8(a5 + 0x3, a2);  /* 00c3 */
  ST8(a5 + 0x6, a4);  /* 00c6 */
  __asm__ volatile("" ::: "memory");  /* 00c9: memw */
  L_00cc: __asm__ volatile("" ::: "memory");  /* 00cc: memw */
  return a2;  /* 00cf: retw.n */
}


/* mesh_rt_change_timeout @ mesh_route.o 00000010 size 70B bind GLOBAL
 * Calls: mesh_malloc, esp_mesh_push_to_nwk_queue, mesh_free | Data refs: .rodata.__func__$10
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=4); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_rt_change_timeout(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 224 (frame 224 bytes) */
  a3 = (u32)(RODATA__rodata___func___10 + 0x0);  /* 0013: l32r -> .rodata.__func__$10 */
  a12 = 92;  /* 0016 */
  a11 = a3;  /* 0018 */
  a10 = 8;  /* 001a */
  a8 = (u32)&mesh_malloc + 0x0;  /* 001c: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 001f: callx a8 via reloc-expand */
  a2 = a10;  /* 0022 */
  if (a10 == 0) goto L_0054;  /* 0024: beqz.n a10, 54 <mesh_rt_change_timeout+0x44> */
  L_0026: a8 = 7;  /* 0026 */
  a11 = 0;  /* 0028 */
  ST8(a10 + 0x0, a8);  /* 002a */
  a9 = 21;  /* 002d */
  ST32(a10 + 0x4, a11);  /* 002f */
  ST32(a1 + 0x4, a10);  /* 0031 */
  a10 = a1;  /* 0033 */
  ST32(a1 + 0x0, a9);  /* 0035 */
  ST8(a1 + 0x8, a8);  /* 0037 */
  __asm__ volatile("" ::: "memory");  /* 003a: memw */
  __asm__ volatile("" ::: "memory");  /* 003d: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 0040: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 0043: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0054;  /* 0046: beqz.n a10, 54 <mesh_rt_change_timeout+0x44> */
  L_0048: a12 = 92;  /* 0048 */
  a11 = a3;  /* 004a */
  a10 = a2;  /* 004c */
  a8 = (u32)&mesh_free + 0x0;  /* 004e: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0051: callx a8 via reloc-expand */
  L_0054: return a2;  /* 0054: retw.n */
}


/* mesh_rt_change_timeout_process @ mesh_route.o 00000018 size 63B bind GLOBAL
 * Calls: esp_mesh_set_beacon_interval | indirect[1]: mem[a8+0xec] | Data refs: g_osi_funcs_p, .bss.rt_change_timer, g_mesh_is_root, g_mesh_ie, g_mesh_init_ps_type
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=6); reloc-direct=1, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_rt_change_timeout_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 001b: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 001e */
  a10 = (u32)&LOCAL__bss_rt_change_timer + 0x0;  /* 0020: l32r -> .bss.rt_change_timer (same-object static) */
  a8 = LD32(a8 + 0xec);  /* 0023 */
  /* 0026: INDIRECT callx a8 <- mem[a8+0xec]; result unknown */ a2 = 0;
  a8 = (u32)&g_mesh_is_root + 0x0;  /* 0029: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 002c: memw */
  a8 = LD8U(a8 + 0x0);  /* 002f */
  a8 = (a8 >> 8) & 0x1;  /* 0032: extui width 1 */
  if (a8 == 0) goto L_0055;  /* 0035: beqz.n a8, 55 <mesh_rt_change_timeout_process+0x3d> */
  L_0037: a8 = (u32)&g_mesh_ie + 0x0;  /* 0037: l32r -> global */
  a8 = LD8U(a8 + 0x11);  /* 003a */
  if (a8 == 0) goto L_0055;  /* 003d: beqz.n a8, 55 <mesh_rt_change_timeout_process+0x3d> */
  L_003f: a9 = 0x3e8;  /* 003f */
  a8 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0042: l32r -> global */
  a10 = LD32(a8 + 0x0);  /* 0045 */
  a8 = 0x12c;  /* 0047 */
  if (a10 == 0) a8 = a9;  /* 004a */
  a10 = a8;  /* 004d */
  a8 = (u32)&esp_mesh_set_beacon_interval + 0x0;  /* 004f: l32r -> global */
  a2 = esp_mesh_set_beacon_interval(a2, a3, a4, a5, a6, a7);  /* 0052: callx a8 via reloc-expand */
  L_0055: return a2;  /* 0055: retw.n */
}


/* mesh_rt_change_timer_start @ mesh_route.o 0000000c size 24B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0xe8] | Data refs: g_osi_funcs_p, .bss.rt_change_timer
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_rt_change_timer_start(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 000f: l32r -> global */
  a12 = 0;  /* 0012 */
  a8 = LD32(a8 + 0x0);  /* 0014 */
  a11 = 0x000186a0u;  /* 0016: l32r = 100000 */
  a8 = LD32(a8 + 0xe8);  /* 0019 */
  a10 = (u32)&LOCAL__bss_rt_change_timer + 0x0;  /* 001c: l32r -> .bss.rt_change_timer (same-object static) */
  /* 001f: INDIRECT callx a8 <- mem[a8+0xe8]; result unknown */ a2 = 0;
  return a2;  /* 0022: retw.n */
}


/* mesh_update_route_table @ mesh_route.o 0000005c size 913B bind GLOBAL
 * Calls: mesh_malloc, esp_wifi_deauth_sta, esp_mesh_tx_tid_flush, memcmp, memcpy, mesh_free | indirect[11]: mem[a4+0x158]; mem[a4+0x150]; mem[a8+0xb8]; mem[a3+0x158] | Data refs: g_mesh_ext_cfg, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_lookup_route.str1.1, .rodata.mesh_update_route_table.str1.1, .bss.mesh_route_table, g_mesh_topology, g_mesh_max_layer, .rodata.__func__$8, .bss.MESH_ZERO_ADDR
 * Fidelity: medium - 11 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=16); reloc-direct=6, funcdb-attributed=0, unknown-indirect=11 */
u32 mesh_update_route_table(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 005c: entry a1, 64 (frame 64 bytes) */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 005f: sext */
  a9 = (a4 >> 8) & 0x1;  /* 0062: extui width 1 */
  if ((i32)a2 < 0) goto L_0071;  /* 0065: bltz a2, 71 <mesh_update_route_table+0x15> */
  L_0068: a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0068: l32r -> global */
  a4 = LD8U(a4 + 0xbd);  /* 006b */
  if ((i32)a2 < (i32)a4) goto L_00b4;  /* 006e: blt a2, a4, b4 <mesh_update_route_table+0x58> */
  L_0071: a3 = (u32)&g_log_level + 0x0;  /* 0071: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 0074 */
  a3 = -1;  /* 0076 */
  if (a4 >= 3u) goto L_007e;  /* 0078: bgeui a4, 3, 7e <mesh_update_route_table+0x22> */
  L_007b: goto L_03e6;  /* 007b: j */
  L_007e: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 007e: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0081 */
  if (a4 == 0) goto L_03e6;  /* 0083: beqz a4, 3e6 <mesh_update_route_table+0x38a> */
  L_0086: a5 = LD32(a4 + 0x150);  /* 0086 */
  if (a5 == 0) goto L_03e6;  /* 0089: beqz a5, 3e6 <mesh_update_route_table+0x38a> */
  L_008c: a10 = LD32(a4 + 0x158);  /* 008c */
  /* 008f: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0092 */
  a15 = 0x16c;  /* 0094 */
  a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0097: l32r -> global */
  a10 = 3;  /* 009a */
  a4 = LD8U(a4 + 0xbd);  /* 009c */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 009f: -> "mesh_route.c" */
  a14 = a11;  /* 00a2 */
  a12 = (u32)(RODATA__rodata_mesh_update_route_table_str1_1 + 0x0);  /* 00a4: l32r -> .rodata.mesh_update_route_table.str1.1 */
  ST32(a1 + 0x4, a4);  /* 00a7 */
  ST32(a1 + 0x0, a2);  /* 00a9 */
  __asm__ volatile("" ::: "memory");  /* 00ab: memw */
  /* 00ae: INDIRECT callx a5 <- mem[a4+0x150]; result unknown */ a2 = 0;
  goto L_03e6;  /* 00b1: j */
  L_00b4: if (a3 != 1) goto L_00ba;  /* 00b4: bnei a3, 1, ba <mesh_update_route_table+0x5e> */
  L_00b7: goto L_038c;  /* 00b7: j */
  L_00ba: if (a3 == 2) goto L_00c4;  /* 00ba: beqi a3, 2, c4 <mesh_update_route_table+0x68> */
  L_00bd: if (a3 == 0) goto L_02b9;  /* 00bd: beqz a3, 2b9 <mesh_update_route_table+0x25d> */
  L_00c0: goto L_02ae;  /* 00c0: j */
  L_00c4: a6 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 00c4: l32r -> .bss.mesh_route_table (same-object static) */
  a5 = a2 + (8);  /* 00c7 */
  a3 = a5 + (a6 << 1);  /* 00c9 */
  a4 = LD8U(a3 + 0x4);  /* 00cc */
  a3 = LD8U(a3 + 0x5);  /* 00cf */
  a3 = a3 << 8;  /* 00d2 */
  a3 = a3 | a4;  /* 00d5 */
  a4 = a2 + a2;  /* 00d8 */
  ST32(a1 + 0x10, a4);  /* 00da */
  a4 = a2 + (a6 << 1);  /* 00dc */
  a7 = LD8U(a4 + 0x0);  /* 00df */
  a4 = LD8U(a4 + 0x1);  /* 00e2 */
  a4 = a4 << 8;  /* 00e5 */
  a4 = a4 | a7;  /* 00e8 */
  if (a4 < a3) goto L_0103;  /* 00eb: bltu a4, a3, 103 <mesh_update_route_table+0xa7> */
  L_00ee: a4 = (u32)&g_mesh_topology + 0x0;  /* 00ee: l32r -> global */
  a7 = LD32(a4 + 0x0);  /* 00f1 */
  a4 = 100;  /* 00f3 */
  if (a7 != 0) goto L_00fe;  /* 00f6: bnez.n a7, fe <mesh_update_route_table+0xa2> */
  L_00f8: a4 = (u32)&g_mesh_max_layer + 0x0;  /* 00f8: l32r -> global */
  a4 = LD16U(a4 + 0x0);  /* 00fb */
  L_00fe: a4 = a3 + a4;  /* 00fe */
  a3 = (a4 >> 16) & 0x1;  /* 0100: extui width 1 */
  L_0103: a7 = a3 + (a3 << 1);  /* 0103 */
  a7 = a7 + a7;  /* 0106 */
  a11 = (u32)(RODATA__rodata___func___8 + 0x0);  /* 0108: -> "mesh_update_route_table" */
  a12 = 0x17d;  /* 010b */
  a10 = a7;  /* 010e: mov */
  ST32(a1 + 0x14, a9);  /* 0111 */
  __asm__ volatile("" ::: "memory");  /* 0113: memw */
  a8 = (u32)&mesh_malloc + 0x0;  /* 0116: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0119: callx a8 via reloc-expand */
  a4 = a10;  /* 011c */
  a9 = LD32(a1 + 0x14);  /* 011e */
  if (a10 != 0) goto L_01b0;  /* 0120: bnez a10, 1b0 <mesh_update_route_table+0x154> */
  L_0123: a5 = (u32)&g_log_level + 0x0;  /* 0123: l32r -> global */
  a3 = LD32(a5 + 0x0);  /* 0126 */
  if (a3 < 3u) goto L_0199;  /* 0128: bltui a3, 3, 199 <mesh_update_route_table+0x13d> */
  L_012b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 012b: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 012e */
  if (a4 != 0) goto L_0139;  /* 0130: bnez.n a4, 139 <mesh_update_route_table+0xdd> */
  L_0132: a3 = LD32(a3 + 0x0);  /* 0132 */
  if (a3 != 0) goto L_0174;  /* 0134: bnez.n a3, 174 <mesh_update_route_table+0x118> */
  L_0136: goto L_0199;  /* 0136: j */
  L_0139: a6 = LD32(a4 + 0x150);  /* 0139 */
  if (a6 == 0) goto L_0132;  /* 013c: beqz a6, 132 <mesh_update_route_table+0xd6> */
  L_013f: a10 = LD32(a4 + 0x158);  /* 013f */
  /* 0142: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 0145 */
  a8 = LD32(a3 + 0x0);  /* 0147 */
  a10 = LD32(a8 + 0xb8);  /* 014a */
  /* 014d: INDIRECT callx a10 <- mem[a8+0xb8]; result unknown */ a2 = 0;
  a13 = a4;  /* 0150 */
  a15 = 0x17f;  /* 0152 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0155: -> "mesh_route.c" */
  a14 = a11;  /* 0158 */
  a12 = (u32)(RODATA__rodata_mesh_update_route_table_str1_1 + 0x0);  /* 015a: l32r -> .rodata.mesh_update_route_table.str1.1 */
  ST32(a1 + 0x8, a10);  /* 015d */
  a10 = 3;  /* 015f */
  ST32(a1 + 0x4, a7);  /* 0161 */
  ST32(a1 + 0x0, a2);  /* 0163 */
  __asm__ volatile("" ::: "memory");  /* 0166: memw */
  /* 0169: INDIRECT callx a6 <- mem[a4+0x150]; result unknown */ a2 = 0;
  a4 = LD32(a5 + 0x0);  /* 016c */
  if (a4 >= 3u) goto L_0132;  /* 016e: bgeui a4, 3, 132 <mesh_update_route_table+0xd6> */
  L_0171: goto L_0199;  /* 0171: j */
  L_0174: a4 = LD32(a3 + 0x150);  /* 0174 */
  if (a4 == 0) goto L_0199;  /* 0177: beqz.n a4, 199 <mesh_update_route_table+0x13d> */
  L_0179: a10 = LD32(a3 + 0x158);  /* 0179 */
  a3 = a2 + (1);  /* 017c */
  /* 017e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a15 = 0x184;  /* 0181 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0184: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 0187 */
  L_0189: a13 = a10;  /* 0189 */
  a14 = a11;  /* 018b */
  a10 = 3;  /* 018d */
  a12 = (u32)(RODATA__rodata_mesh_update_route_table_str1_1 + 0x0);  /* 0190: l32r -> .rodata.mesh_update_route_table.str1.1 */
  __asm__ volatile("" ::: "memory");  /* 0193: memw */
  /* 0196: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_0199: a2 = a2 + (1);  /* 0199 */
  a10 = (a2 >> 16) & 0x1;  /* 019b: extui width 1 */
  a8 = (u32)&esp_wifi_deauth_sta + 0x0;  /* 019e: l32r -> global */
  a2 = esp_wifi_deauth_sta(a2, a3, a4, a5, a6, a7);  /* 01a1: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_tx_tid_flush + 0x0;  /* 01a4: l32r -> global */
  a2 = esp_mesh_tx_tid_flush(a2, a3, a4, a5, a6, a7);  /* 01a7: callx a8 via reloc-expand */
  a3 = 0x00004007u;  /* 01aa: l32r = 16391 */
  goto L_03e6;  /* 01ad: j */
  L_01b0: a10 = a5 + (a6 << 2);  /* 01b0 */
  a7 = LD8U(a10 + 0x9);  /* 01b3 */
  a7 = a7 << 8;  /* 01b6 */
  a2 = LD8U(a10 + 0x8);  /* 01b9 */
  a7 = a7 | a2;  /* 01bc */
  a2 = LD8U(a10 + 0xa);  /* 01bf */
  a2 = a2 << 16;  /* 01c2 */
  a2 = a2 | a7;  /* 01c5 */
  a7 = LD8U(a10 + 0xb);  /* 01c8 */
  a7 = a7 << 24;  /* 01cb */
  a11 = a7 | a2;  /* 01ce */
  a2 = 0;  /* 01d1 */
  if (a11 != a2) goto L_01d9;  /* 01d3: bne a11, a2, 1d9 <mesh_update_route_table+0x17d> */
  L_01d6: goto L_027a;  /* 01d6: j */
  L_01d9: a8 = LD32(a1 + 0x10);  /* 01d9 */
  a13 = a6 + a8;  /* 01db */
  a2 = LD8U(a13 + 0x1);  /* 01dd */
  a2 = a2 << 8;  /* 01e0 */
  a7 = LD8U(a13 + 0x0);  /* 01e3 */
  a2 = a2 | a7;  /* 01e6 */
  if (a9 == 0) goto L_0240;  /* 01e9: beqz a9, 240 <mesh_update_route_table+0x1e4> */
  L_01ec: a2 = 0;  /* 01ec */
  a7 = a11;  /* 01ee */
  a14 = a2;  /* 01f0 */
  goto L_022d;  /* 01f2: j */
  L_01f5: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 01f5: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 01f8 */
  a10 = a7;  /* 01fa */
  ST32(a1 + 0x18, a13);  /* 01fc */
  ST32(a1 + 0x14, a14);  /* 01fe */
  __asm__ volatile("" ::: "memory");  /* 0201: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0204: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0207: callx a8 (libc, via reloc-expand) */
  a13 = LD32(a1 + 0x18);  /* 020a */
  a14 = LD32(a1 + 0x14);  /* 020c */
  if (a10 == 0) goto L_0229;  /* 020e: beqz.n a10, 229 <mesh_update_route_table+0x1cd> */
  L_0210: a10 = a2 + (a2 << 1);  /* 0210 */
  a12 = 6;  /* 0213 */
  a11 = a7;  /* 0215 */
  a10 = a10 + (a4 << 1);  /* 0217 */
  a8 = (u32)&memcpy + 0x0;  /* 021a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 021d: callx a8 (libc, via reloc-expand) */
  a2 = a2 + (1);  /* 0220 */
  a14 = LD32(a1 + 0x14);  /* 0222 */
  a2 = (a2 >> 16) & 0x1;  /* 0224: extui width 1 */
  a13 = LD32(a1 + 0x18);  /* 0227 */
  L_0229: a14 = a14 + (1);  /* 0229 */
  a7 = a7 + (6);  /* 022b */
  L_022d: a9 = LD8U(a13 + 0x1);  /* 022d */
  a9 = a9 << 8;  /* 0230 */
  a10 = LD8U(a13 + 0x0);  /* 0233 */
  a9 = a9 | a10;  /* 0236 */
  if ((i32)a14 < (i32)a9) goto L_01f5;  /* 0239: blt a14, a9, 1f5 <mesh_update_route_table+0x199> */
  L_023c: goto L_024d;  /* 023c: j */
  L_0240: a12 = a2 + (a2 << 1);  /* 0240 */
  a12 = a12 + a12;  /* 0243 */
  a10 = a4;  /* 0245 */
  a8 = (u32)&memcpy + 0x0;  /* 0247: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 024a: callx a8 (libc, via reloc-expand) */
  L_024d: a10 = a5 + (a6 << 2);  /* 024d */
  a9 = LD8U(a10 + 0x9);  /* 0250 */
  a12 = 0x19b;  /* 0253 */
  a9 = a9 << 8;  /* 0256 */
  a7 = LD8U(a10 + 0x8);  /* 0259 */
  a9 = a9 | a7;  /* 025c */
  a7 = LD8U(a10 + 0xa);  /* 025f */
  a7 = a7 << 16;  /* 0262 */
  a7 = a7 | a9;  /* 0265 */
  a10 = LD8U(a10 + 0xb);  /* 0268 */
  a10 = a10 << 24;  /* 026b */
  a10 = a10 | a7;  /* 026e */
  a11 = (u32)(RODATA__rodata___func___8 + 0x0);  /* 0271: -> "mesh_update_route_table" */
  a8 = (u32)&mesh_free + 0x0;  /* 0274: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0277: callx a8 via reloc-expand */
  L_027a: a8 = LD32(a1 + 0x10);  /* 027a */
  a7 = a6 + a8;  /* 027c */
  a8 = (a4 >> 8) & 0x1ffffff;  /* 027e: extui width 25 */
  ST8(a7 + 0x0, a2);  /* 0281 */
  a2 = a2 >> 8;  /* 0284 */
  ST8(a7 + 0x1, a2);  /* 0287 */
  a2 = a5 + (a6 << 1);  /* 028a */
  a5 = a5 + (a6 << 2);  /* 028d */
  ST8(a2 + 0x4, a3);  /* 0290 */
  a3 = a3 >> 8;  /* 0293 */
  ST8(a2 + 0x5, a3);  /* 0296 */
  a2 = (a4 >> 8) & 0x1ff;  /* 0299: extui width 9 */
  ST8(a5 + 0x9, a2);  /* 029c */
  a2 = (a4 >> 8) & 0x1ffff;  /* 029f: extui width 17 */
  ST8(a5 + 0x8, a4);  /* 02a2 */
  ST8(a5 + 0xa, a2);  /* 02a5 */
  ST8(a5 + 0xb, a8);  /* 02a8 */
  __asm__ volatile("" ::: "memory");  /* 02ab: memw */
  L_02ae: a3 = 0;  /* 02ae */
  __asm__ volatile("" ::: "memory");  /* 02b0: memw */
  goto L_03e6;  /* 02b3: j */
  L_02b9: a4 = (u32)&g_mesh_topology + 0x0;  /* 02b9: l32r -> global */
  a5 = LD32(a4 + 0x0);  /* 02bc */
  a4 = 100;  /* 02be */
  if (a5 != 0) goto L_02c9;  /* 02c1: bnez.n a5, 2c9 <mesh_update_route_table+0x26d> */
  L_02c3: a4 = (u32)&g_mesh_max_layer + 0x0;  /* 02c3: l32r -> global */
  a4 = LD16U(a4 + 0x0);  /* 02c6 */
  L_02c9: a5 = a4 + (a4 << 1);  /* 02c9 */
  a5 = a5 + a5;  /* 02cc */
  a12 = 0x1a9;  /* 02ce */
  a10 = a5;  /* 02d1 */
  a11 = (u32)(RODATA__rodata___func___8 + 0x0);  /* 02d3: -> "mesh_update_route_table" */
  a8 = (u32)&mesh_malloc + 0x0;  /* 02d6: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 02d9: callx a8 via reloc-expand */
  if (a10 != 0) goto L_034e;  /* 02dc: bnez a10, 34e <mesh_update_route_table+0x2f2> */
  L_02df: a6 = (u32)&g_log_level + 0x0;  /* 02df: l32r -> global */
  a3 = LD32(a6 + 0x0);  /* 02e2 */
  if (a3 >= 3u) goto L_02ea;  /* 02e4: bgeui a3, 3, 2ea <mesh_update_route_table+0x28e> */
  L_02e7: goto L_0199;  /* 02e7: j */
  L_02ea: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 02ea: l32r -> global */
  a3 = LD32(a4 + 0x0);  /* 02ed */
  if (a3 != 0) goto L_02f8;  /* 02ef: bnez.n a3, 2f8 <mesh_update_route_table+0x29c> */
  L_02f1: a3 = LD32(a4 + 0x0);  /* 02f1 */
  if (a3 != 0) goto L_0331;  /* 02f3: bnez.n a3, 331 <mesh_update_route_table+0x2d5> */
  L_02f5: goto L_0199;  /* 02f5: j */
  L_02f8: a7 = LD32(a3 + 0x150);  /* 02f8 */
  if (a7 == 0) goto L_02f1;  /* 02fb: beqz a7, 2f1 <mesh_update_route_table+0x295> */
  L_02fe: a10 = LD32(a3 + 0x158);  /* 02fe */
  /* 0301: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 0304 */
  a8 = LD32(a4 + 0x0);  /* 0306 */
  a10 = LD32(a8 + 0xb8);  /* 0308 */
  /* 030b: INDIRECT callx a10 <- mem[a8+0xb8]; result unknown */ a2 = 0;
  a13 = a3;  /* 030e */
  a15 = 0x1ab;  /* 0310 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0313: -> "mesh_route.c" */
  a14 = a11;  /* 0316 */
  a12 = (u32)(RODATA__rodata_mesh_update_route_table_str1_1 + 0x0);  /* 0318: l32r -> .rodata.mesh_update_route_table.str1.1 */
  ST32(a1 + 0x8, a10);  /* 031b */
  a10 = 3;  /* 031d */
  ST32(a1 + 0x4, a5);  /* 031f */
  ST32(a1 + 0x0, a2);  /* 0321 */
  __asm__ volatile("" ::: "memory");  /* 0323: memw */
  /* 0326: INDIRECT callx a7 <- mem[a3+0x150]; result unknown */ a2 = 0;
  a3 = LD32(a6 + 0x0);  /* 0329 */
  if (a3 >= 3u) goto L_02f1;  /* 032b: bgeui a3, 3, 2f1 <mesh_update_route_table+0x295> */
  L_032e: goto L_0199;  /* 032e: j */
  L_0331: a4 = LD32(a3 + 0x150);  /* 0331 */
  if (a4 == 0) goto L_0199;  /* 0334: beqz a4, 199 <mesh_update_route_table+0x13d> */
  L_0337: a10 = LD32(a3 + 0x158);  /* 0337 */
  a3 = a2 + (1);  /* 033a */
  /* 033d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a15 = 0x1b0;  /* 0340 */
  a11 = (u32)(RODATA__rodata_esp_mesh_lookup_route_str1_1 + 0x0);  /* 0343: -> "mesh_route.c" */
  ST32(a1 + 0x0, a3);  /* 0346 */
  __asm__ volatile("" ::: "memory");  /* 0348: memw */
  goto L_0189;  /* 034b: j */
  L_034e: a5 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 034e: l32r -> .bss.mesh_route_table (same-object static) */
  a7 = 0;  /* 0351 */
  a6 = a2 + (a5 << 1);  /* 0353 */
  a2 = a2 + (8);  /* 0356 */
  ST8(a6 + 0x0, a7);  /* 0358 */
  ST8(a6 + 0x1, a7);  /* 035b */
  a6 = a2 + (a5 << 1);  /* 035e */
  a2 = a2 + (a5 << 2);  /* 0361 */
  ST8(a6 + 0x4, a4);  /* 0364 */
  a4 = a4 >> 8;  /* 0367 */
  ST8(a6 + 0x5, a4);  /* 036a */
  a4 = (a10 >> 8) & 0x1ff;  /* 036d: extui width 9 */
  ST8(a2 + 0x8, a10);  /* 0370 */
  ST8(a2 + 0x9, a4);  /* 0373 */
  a4 = (a10 >> 8) & 0x1ffff;  /* 0376: extui width 17 */
  a10 = (a10 >> 8) & 0x1ffffff;  /* 0379: extui width 25 */
  ST8(a2 + 0xa, a4);  /* 037c */
  ST8(a2 + 0xb, a10);  /* 037f */
  __asm__ volatile("" ::: "memory");  /* 0382: memw */
  __asm__ volatile("" ::: "memory");  /* 0385: memw */
  goto L_03e6;  /* 0388: j */
  L_038c: a5 = (u32)&LOCAL__bss_mesh_route_table + 0x0;  /* 038c: l32r -> .bss.mesh_route_table (same-object static) */
  a4 = a2 + (8);  /* 038f */
  a7 = a4 + (a5 << 2);  /* 0391 */
  a6 = LD8U(a7 + 0x9);  /* 0394 */
  a6 = a6 << 8;  /* 0397 */
  a3 = LD8U(a7 + 0x8);  /* 039a */
  a6 = a6 | a3;  /* 039d */
  a3 = LD8U(a7 + 0xa);  /* 03a0 */
  a3 = a3 << 16;  /* 03a3 */
  a3 = a3 | a6;  /* 03a6 */
  a10 = LD8U(a7 + 0xb);  /* 03a9 */
  a10 = a10 << 24;  /* 03ac */
  a10 = a10 | a3;  /* 03af */
  if (a10 == 0) goto L_03c0;  /* 03b2: beqz.n a10, 3c0 <mesh_update_route_table+0x364> */
  L_03b4: a11 = (u32)(RODATA__rodata___func___8 + 0x0);  /* 03b4: -> "mesh_update_route_table" */
  a12 = 0x1c2;  /* 03b7 */
  a8 = (u32)&mesh_free + 0x0;  /* 03ba: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 03bd: callx a8 via reloc-expand */
  L_03c0: a3 = 0;  /* 03c0 */
  a2 = a2 + (a5 << 1);  /* 03c2 */
  ST8(a2 + 0x0, a3);  /* 03c5 */
  ST8(a2 + 0x1, a3);  /* 03c8 */
  a2 = a4 + (a5 << 1);  /* 03cb */
  ST8(a2 + 0x4, a3);  /* 03ce */
  ST8(a2 + 0x5, a3);  /* 03d1 */
  a2 = a4 + (a5 << 2);  /* 03d4 */
  ST8(a2 + 0x8, a3);  /* 03d7 */
  ST8(a2 + 0x9, a3);  /* 03da */
  ST8(a2 + 0xa, a3);  /* 03dd */
  ST8(a2 + 0xb, a3);  /* 03e0 */
  __asm__ volatile("" ::: "memory");  /* 03e3: memw */
  L_03e6: a2 = a3;  /* 03e6 */
  __asm__ volatile("" ::: "memory");  /* 03e8: memw */
  return a2;  /* 03eb: retw.n */
}


/* routetype2str @ mesh_route.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.routetype2str.str1.1, .rodata.CSWTCH$438
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 routetype2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 000b */
  a2 = (u32)(RODATA__rodata_routetype2str_str1_1 + 0x0);  /* 000d: -> "Unknown" */
  if (a8 >= 3u) goto L_001c;  /* 0010: bgeui a8, 3, 1c <routetype2str+0x14> */
  L_0013: a2 = (u32)(RODATA__rodata_CSWTCH_438 + 0x0);  /* 0013: l32r -> .rodata.CSWTCH$438 */
  a8 = a8 + (a2 << 2);  /* 0016 */
  a2 = LD32(a8 + 0x0);  /* 0019 */
  L_001c: return a2;  /* 001c: retw.n */
}

