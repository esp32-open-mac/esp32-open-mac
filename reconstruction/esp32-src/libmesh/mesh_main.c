/* libmesh.a mesh_main.o --- reconstructed C (offline).
 * Role: packet delivery/forwarding: unicast, multicast, broadcast, mgmt announce handling.
 * Object file: 54248 bytes on disk; 16/16 functions reconstructed, ~10635 code bytes.
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
extern u32 g_is_root_fixed; /* undefined data (reloc-referenced) */
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_mesh_conn; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ext_cfg; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ext_vote_state; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ie; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_max_layer; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_sta_addr; /* undefined data (reloc-referenced) */
extern u32 g_mesh_topology; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 mesh_conn_mutex; /* undefined data (reloc-referenced) */
extern u32 mesh_myself_mbox; /* undefined data (reloc-referenced) */
extern u32 __extendsfdf2(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_available_txupQ_num(); /* defined in another libmesh.a object */
extern u32 esp_mesh_copy_mgmt_announce(); /* defined in another libmesh.a object */
extern u32 esp_mesh_create_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_force_txupQ_pending(); /* defined in another libmesh.a object */
extern u32 esp_mesh_free_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_child_num(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_parent_bssid(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_total_children_num(); /* defined in another libmesh.a object */
extern u32 esp_mesh_is_my_group(); /* defined in another libmesh.a object */
extern u32 esp_mesh_lookup_route(); /* defined in another libmesh.a object */
extern u32 esp_mesh_match_self(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_myself_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_nwk_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_tcpip_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_tx_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_send_block_start(); /* defined in another libmesh.a object */
extern u32 esp_mesh_send_root_switch(); /* defined in another libmesh.a object */
extern u32 is_mesh_child(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_lock(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_unlock(); /* defined in another libmesh.a object */
extern u32 mesh_topo_get_ttl(); /* defined in another libmesh.a object */
extern u32 opt_type2str(); /* defined in another libmesh.a object */
static const u8 RODATA__rodata_CSWTCH_647[] = { 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00 }; /* .rodata.CSWTCH$647 (20 bytes) */
static const u8 RODATA__rodata___func___0[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x75, 0x63, 0x61 }; /* .rodata.__func__$0 (20 bytes) */
static const u8 RODATA__rodata___func___1[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x62, 0x63, 0x61 }; /* .rodata.__func__$1 (20 bytes) */
static const u8 RODATA__rodata___func___2[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6d, 0x63, 0x61, 0x73, 0x74, 0x5f, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x5f, 0x6e, 0x6f, 0x64 }; /* .rodata.__func__$2 (28 bytes) */
static const u8 RODATA__rodata___func___3[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x63, 0x61, 0x73, 0x74, 0x5f, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x5f, 0x6e, 0x6f, 0x64 }; /* .rodata.__func__$3 (24 bytes) */
static const u8 RODATA__rodata___func___4[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x00 }; /* .rodata.__func__$4 (24 bytes) strings: [0x0]="esp_mesh_forward_packet" */
static const u8 RODATA__rodata_esp_mesh_delivery_toDS_str1_1[] = { 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x74, 0x69, 0x64, 0x3a, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x54, 0x58, 0x5f, 0x54, 0x4f, 0x5f, 0x44, 0x53, 0x2c, 0x20, 0x63, 0x74, 0x78, 0x3a, 0x25, 0x70, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x62, 0x75, 0x66, 0x3a, 0x25, 0x70, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x20, 0x66, 0x61, 0x69 }; /* .rodata.esp_mesh_delivery_toDS.str1.1 (96 bytes) */
static const u8 RODATA__rodata_esp_mesh_delivery_toSelf_str1_1[] = { 0x20, 0x41, 0x50, 0x2c, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x00, 0x53, 0x54, 0x41, 0x2c, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x3a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x73, 0x65, 0x6c, 0x66, 0x5d, 0x70, 0x75, 0x73, 0x68, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x20, 0x71, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x69, 0x66, 0x78, 0x3a, 0x25, 0x73, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x3c, 0x68, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x74, 0x6c, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6f, 0x70, 0x74, 0x3a, 0x25, 0x64, 0x3e, 0x2c, 0x20, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00 }; /* .rodata.esp_mesh_delivery_toSelf.str1.1 (168 bytes) strings: [0x0]=" AP, child:"; [0xc]="STA, parent:" */
static const u8 RODATA__rodata_esp_mesh_forward_packet_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x75, 0x63, 0x61, 0x73, 0x74, 0x5d, 0x25, 0x73, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x2f, 0x64, 0x65, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x28, 0x75, 0x70, 0x29, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x5b, 0x54, 0x41, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x44, 0x53, 0x54, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x77, 0x6e, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x6e, 0x6f, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64 }; /* .rodata.esp_mesh_forward_packet.str1.1 (176 bytes) */
static const u8 RODATA__rodata_esp_mesh_get_optlen_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73, 0x0a }; /* .rodata.esp_mesh_get_optlen.str1.1 (44 bytes) strings: [0x0]="mesh_main.c"; [0xc]="mesh" */
static const u8 RODATA__rodata_esp_mesh_mcast_cover_node_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x0a, 0x00 }; /* .rodata.esp_mesh_mcast_cover_node.str1.1 (32 bytes) */
static const u8 RODATA__rodata_esp_mesh_process_options_str1_1[] = { 0x78, 0x6d, 0x69, 0x74, 0x00, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5d, 0x75, 0x6e, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x5b, 0x53, 0x52, 0x43, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6f, 0x70, 0x74, 0x3a, 0x25, 0x64, 0x28, 0x25, 0x73, 0x29, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64 }; /* .rodata.esp_mesh_process_options.str1.1 (100 bytes) strings: [0x0]="xmit"; [0x5]="forward" */
static const u8 RODATA__rodata_esp_mesh_process_ucast_str1_1[] = { 0x78, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x72, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x45, 0x52, 0x52, 0x5f, 0x4e, 0x4f, 0x5f, 0x52, 0x4f, 0x55, 0x54, 0x45, 0x5f, 0x46, 0x4f, 0x55, 0x4e, 0x44, 0x3e, 0x74, 0x6f, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x2c, 0x20, 0x64, 0x69, 0x73, 0x63, 0x61, 0x72, 0x64, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2d, 0x2d, 0x3e, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x25, 0x73, 0x5b, 0x54, 0x41, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x73, 0x74, 0x61, 0x72, 0x74, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x6e, 0x6f, 0x20, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x78, 0x73, 0x65, 0x6e, 0x71, 0x6f, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x75, 0x63, 0x61, 0x73, 0x74, 0x5d, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x6e, 0x27, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x45, 0x52, 0x52, 0x5f, 0x4e, 0x4f, 0x5f, 0x52, 0x4f, 0x55, 0x54, 0x45, 0x5f, 0x46, 0x4f, 0x55, 0x4e, 0x44, 0x3e, 0x72, 0x6f, 0x6f, 0x74, 0x2c, 0x20, 0x6e, 0x6f, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x2c, 0x20, 0x64, 0x69, 0x73, 0x63, 0x61, 0x72, 0x64, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2d, 0x2d, 0x3e, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x25, 0x73, 0x5b, 0x54, 0x41, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x5b, 0x75, 0x63, 0x61, 0x73, 0x74, 0x5d, 0x69, 0x6e, /* ... +316 bytes */ }; /* .rodata.esp_mesh_process_ucast.str1.1 (828 bytes) strings: [0x0]="xmitter" */
static const u8 RODATA__rodata_mesh_process_mgmt_announce_str1_1[] = { 0x61, 0x64, 0x64, 0x00, 0x72, 0x6d, 0x76, 0x00, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x6c, 0x65, 0x61, 0x66, 0x2c, 0x20, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x72, 0x65, 0x6e, 0x2c, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x73, 0x6f, 0x63, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x3e, 0x64, 0x69, 0x73, 0x63, 0x61, 0x72, 0x64, 0x20, 0x25, 0x73, 0x20, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x64, 0x75, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3a, 0x25, 0x64, 0x3e, 0x3d, 0x5b, 0x6d, 0x61, 0x78, 0x20, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x5d, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x25, 0x73, 0x3e, 0x64, 0x69, 0x73, 0x63, 0x61, 0x72, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x73, 0x72, 0x63, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78 }; /* .rodata.mesh_process_mgmt_announce.str1.1 (312 bytes) strings: [0x0]="add"; [0x4]="rmv"; [0x8]="remove" */
static const u8 RODATA__rodata_mesh_process_mgmt_root_waive_str1_1[] = { 0x72, 0x63, 0x20, 0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2c, 0x20, 0x00, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x4e, 0x45, 0x57, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, 0x56, 0x4f, 0x54, 0x45, 0x5f, 0x53, 0x54, 0x41, 0x52, 0x54, 0x3e, 0x25, 0x73, 0x61, 0x74, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x73, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x65, 0x72, 0x63, 0x65, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x20, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x3a, 0x25, 0x66, 0x2c, 0x20, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x70, 0x61, 0x6e, 0x64, 0x6f, 0x72, 0x61, 0x0a, 0x0a }; /* .rodata.mesh_process_mgmt_root_waive.str1.1 (140 bytes) strings: [0x0]="rc specified, " */
static const u8 RODATA__rodata_mesh_process_mgmt_routing_table_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x25, 0x73, 0x3e, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x76, 0x61, 0x6c, 0x3a, 0x25, 0x70, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x25, 0x73, 0x3e, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x61, 0x63, 0x6b, 0x2c, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x64, 0x69, 0x73, 0x63, 0x61, 0x72, 0x64, 0x20, 0x25, 0x73, 0x20, 0x64, 0x75, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3a, 0x25, 0x64, 0x3e, 0x3d, 0x5b, 0x6d, 0x61, 0x78, 0x20, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x5d, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78 }; /* .rodata.mesh_process_mgmt_routing_table.str1.1 (256 bytes) */
static const u8 RODATA__rodata_optype2str_str1_1[] = { 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x00 }; /* .rodata.optype2str.str1.1 (8 bytes) strings: [0x0]="Unknown" */
static u8 LOCAL__bss_MESH_ZERO_ADDR[0x4]; /* stand-in for .bss.MESH_ZERO_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_xseqno[0x4]; /* stand-in for .bss.mesh_xseqno (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_MESH_BCAST_ADDR[0x4]; /* stand-in for .data.MESH_BCAST_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_delivery_toDS @ mesh_main.o 0000004c size 426B bind GLOBAL
 * Calls: esp_mesh_match_self, memcmp, esp_mesh_push_to_tcpip_queue, esp_mesh_send_block_start | indirect[10]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0xa0]; mem[a2+0x158] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, .bss.MESH_ZERO_ADDR, g_mesh_is_root, .rodata.esp_mesh_delivery_toDS.str1.1
 * Fidelity: medium - 10 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=12); reloc-direct=4, funcdb-attributed=0, unknown-indirect=10 */
u32 esp_mesh_delivery_toDS(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 004c: entry a1, 64 (frame 64 bytes) */
  ST32(a1 + 0x10, a2);  /* 004f */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 0051: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0054 */
  if (a2 != 0) goto L_0090;  /* 0057: bnez.n a2, 90 <esp_mesh_delivery_toDS+0x44> */
  L_0059: a2 = (u32)&g_log_level + 0x0;  /* 0059: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005c */
  a2 = 0x00004004u;  /* 005e: l32r = 16388 */
  if (a3 >= 3u) goto L_0067;  /* 0061: bgeui a3, 3, 67 <esp_mesh_delivery_toDS+0x1b> */
  L_0064: goto L_01f4;  /* 0064: j */
  L_0067: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0067: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006a */
  if (a3 == 0) goto L_01f4;  /* 006c: beqz a3, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_006f: a4 = LD32(a3 + 0x150);  /* 006f */
  if (a4 == 0) goto L_01f4;  /* 0072: beqz a4, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_0075: a10 = LD32(a3 + 0x158);  /* 0075 */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  /* 007b: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 007e */
  a10 = 3;  /* 0080 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0082: -> "mesh_main.c" */
  a14 = a11;  /* 0085 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 0087: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 008a: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01f4;  /* 008d: j */
  L_0090: a2 = LD32(a1 + 0x10);  /* 0090 */
  if (a2 != 0) goto L_00c0;  /* 0092: bnez.n a2, c0 <esp_mesh_delivery_toDS+0x74> */
  L_0094: a2 = (u32)&g_log_level + 0x0;  /* 0094: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0097 */
  a2 = 0x00004008u;  /* 0099: l32r = 16392 */
  if (a3 >= 3u) goto L_00a2;  /* 009c: bgeui a3, 3, a2 <esp_mesh_delivery_toDS+0x56> */
  L_009f: goto L_01f4;  /* 009f: j */
  L_00a2: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a2: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a5 */
  if (a3 == 0) goto L_01f4;  /* 00a7: beqz a3, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_00aa: a4 = LD32(a3 + 0x150);  /* 00aa */
  if (a4 == 0) goto L_01f4;  /* 00ad: beqz a4, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_00b0: a10 = LD32(a3 + 0x158);  /* 00b0 */
  a3 = 0x451;  /* 00b3 */
  /* 00b6: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00b9: -> "mesh_main.c" */
  goto L_00ec;  /* 00bc: j */
  L_00c0: a10 = LD32(a2 + 0x0);  /* 00c0 */
  if (a10 != 0) goto L_0104;  /* 00c2: bnez.n a10, 104 <esp_mesh_delivery_toDS+0xb8> */
  L_00c4: a2 = (u32)&g_log_level + 0x0;  /* 00c4: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c7 */
  a2 = 0x00004008u;  /* 00c9: l32r = 16392 */
  if (a3 >= 3u) goto L_00d2;  /* 00cc: bgeui a3, 3, d2 <esp_mesh_delivery_toDS+0x86> */
  L_00cf: goto L_01f4;  /* 00cf: j */
  L_00d2: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00d2: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d5 */
  if (a3 == 0) goto L_01f4;  /* 00d7: beqz a3, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_00da: a4 = LD32(a3 + 0x150);  /* 00da */
  if (a4 == 0) goto L_01f4;  /* 00dd: beqz a4, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_00e0: a10 = LD32(a3 + 0x158);  /* 00e0 */
  a3 = 0x452;  /* 00e3 */
  /* 00e6: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00e9: -> "mesh_main.c" */
  L_00ec: a13 = a10;  /* 00ec */
  a14 = a11;  /* 00ee */
  a10 = 3;  /* 00f0 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00f2: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00f5: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 00f8 */
  __asm__ volatile("" ::: "memory");  /* 00fa: memw */
  /* 00fd: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01f4;  /* 0100: j */
  L_0104: a2 = LD32(a2 + 0x28);  /* 0104 */
  if (((a2 >> 0) & 1) == 0) goto L_0145;  /* 0106: bbci a2, 0, 145 <esp_mesh_delivery_toDS+0xf9> */
  L_0109: a2 = a10 + (18);  /* 0109 */
  a3 = LD32(a2 + 0x0);  /* 010c */
  a2 = 0x403;  /* 010e */
  a2 = a2 << 14;  /* 0111 */
  a3 = a3 & a2;  /* 0114 */
  a2 = 1;  /* 0117 */
  a2 = a2 << 24;  /* 0119 */
  if (a3 != a2) goto L_0145;  /* 011c: bne a3, a2, 145 <esp_mesh_delivery_toDS+0xf9> */
  L_011f: a2 = a10 + (22);  /* 011f */
  a10 = a2;  /* 0122 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0124: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0127: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0145;  /* 012a: bnez.n a10, 145 <esp_mesh_delivery_toDS+0xf9> */
  L_012c: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 012c: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 012f */
  a10 = a2;  /* 0131: mov */
  a8 = (u32)&memcmp + 0x0;  /* 0134: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0137: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0145;  /* 013a: bnez.n a10, 145 <esp_mesh_delivery_toDS+0xf9> */
  L_013c: a2 = (u32)&g_mesh_is_root + 0x0;  /* 013c: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 013f: memw */
  a2 = LD8U(a2 + 0x0);  /* 0142 */
  L_0145: a4 = 0;  /* 0145 */
  a8 = LD32(a1 + 0x10);  /* 0147 */
  if (a8 == a4) goto L_0159;  /* 0149: beq a8, a4, 159 <esp_mesh_delivery_toDS+0x10d> */
  L_014c: a3 = 1;  /* 014c */
  a2 = LD32(a8 + 0x28);  /* 014e */
  a2 = (a2 >> 2) & 0x1;  /* 0150: extui width 1 */
  a2 = a2 + (-1);  /* 0153 */
  if (a2 == 0) a4 = a3;  /* 0156 */
  L_0159: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0159: l32r -> global */
  a2 = LD32(a3 + 0x0);  /* 015c */
  a10 = LD32(a8 + 0x24);  /* 015e */
  a2 = LD32(a2 + 0xa0);  /* 0160 */
  /* 0163: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 0166 */
  a10 = a1 + (16);  /* 0168 */
  a8 = (u32)&esp_mesh_push_to_tcpip_queue + 0x0;  /* 016b: l32r -> global */
  a2 = esp_mesh_push_to_tcpip_queue(a2, a3, a4, a5, a6, a7);  /* 016e: callx a8 via reloc-expand */
  a8 = 0xffffbff3u;  /* 0171: l32r = -16397 */
  a2 = a10;  /* 0174 */
  a8 = a10 + a8;  /* 0176 */
  if (a8 != 0) goto L_01f4;  /* 0178: bnez a8, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_017b: if (a4 == 0) goto L_01f4;  /* 017b: beqz a4, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_017e: a2 = LD32(a3 + 0x0);  /* 017e */
  if (a2 == 0) goto L_01b5;  /* 0180: beqz.n a2, 1b5 <esp_mesh_delivery_toDS+0x169> */
  L_0182: a4 = LD32(a2 + 0x150);  /* 0182 */
  if (a4 == 0) goto L_01b5;  /* 0185: beqz.n a4, 1b5 <esp_mesh_delivery_toDS+0x169> */
  L_0187: a10 = LD32(a2 + 0x158);  /* 0187 */
  /* 018a: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 018d */
  a10 = 2;  /* 018f */
  a2 = LD32(a1 + 0x10);  /* 0191 */
  a8 = LD32(a2 + 0x0);  /* 0193 */
  ST32(a1 + 0xc, a8);  /* 0195 */
  a8 = LD16U(a2 + 0x4);  /* 0197 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 019a: -> "mesh_main.c" */
  a14 = a11;  /* 019d */
  ST32(a1 + 0x4, a2);  /* 019f */
  a2 = 0x45e;  /* 01a1 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01a4: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_delivery_toDS_str1_1 + 0x0);  /* 01a7: l32r -> .rodata.esp_mesh_delivery_toDS.str1.1 */
  ST32(a1 + 0x8, a8);  /* 01aa */
  ST32(a1 + 0x0, a2);  /* 01ac */
  __asm__ volatile("" ::: "memory");  /* 01af: memw */
  /* 01b2: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_01b5: a11 = 0;  /* 01b5 */
  a10 = 4;  /* 01b7 */
  a2 = 0x0000400du;  /* 01b9: l32r = 16397 */
  a13 = a2;  /* 01bc */
  a12 = LD32(a1 + 0x10);  /* 01be */
  a8 = (u32)&esp_mesh_send_block_start + 0x0;  /* 01c0: l32r -> global */
  a2 = esp_mesh_send_block_start(a2, a3, a4, a5, a6, a7);  /* 01c3: callx a8 via reloc-expand */
  if (a10 == 0) goto L_01f4;  /* 01c6: beqz.n a10, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_01c8: a8 = LD32(a3 + 0x0);  /* 01c8 */
  a2 = -1;  /* 01ca */
  if (a8 == 0) goto L_01f4;  /* 01cc: beqz.n a8, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_01ce: a3 = LD32(a8 + 0x150);  /* 01ce */
  if (a3 == 0) goto L_01f4;  /* 01d1: beqz a3, 1f4 <esp_mesh_delivery_toDS+0x1a8> */
  L_01d4: a4 = 0x461;  /* 01d4 */
  a10 = LD32(a8 + 0x158);  /* 01d7 */
  /* 01da: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01dd */
  a10 = 1;  /* 01df */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01e1: -> "mesh_main.c" */
  a14 = a11;  /* 01e4 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01e6: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_delivery_toDS_str1_1 + 0x0);  /* 01e9: l32r -> .rodata.esp_mesh_delivery_toDS.str1.1 */
  ST32(a1 + 0x0, a4);  /* 01ec */
  __asm__ volatile("" ::: "memory");  /* 01ee: memw */
  /* 01f1: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_01f4: return a2;  /* 01f4: retw.n */
}


/* esp_mesh_delivery_toSelf @ mesh_main.o 00000064 size 834B bind GLOBAL
 * Calls: memset, esp_mesh_push_to_nwk_queue, esp_mesh_push_to_myself_queue, esp_mesh_send_block_start, mesh_topo_get_ttl | indirect[10]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0xa0]; mem[a6+0x158] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_topology, g_mesh_ext_vote_state, .rodata.esp_mesh_delivery_toDS.str1.1, .rodata.esp_mesh_delivery_toSelf.str1.1, mesh_myself_mbox
 * Fidelity: medium - 10 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=15); reloc-direct=5, funcdb-attributed=0, unknown-indirect=10 */
u32 esp_mesh_delivery_toSelf(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0000001;
  /* 0064: entry a1, 0x150 (frame 0x150 bytes) */
  ST32(a1 + 0x100, a2);  /* 0067 */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 006a: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 006d */
  if (a2 != 0) goto L_00ac;  /* 0070: bnez.n a2, ac <esp_mesh_delivery_toSelf+0x48> */
  L_0072: a2 = (u32)&g_log_level + 0x0;  /* 0072: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0075 */
  a2 = 0x00004004u;  /* 0078: l32r = 16388 */
  if (a3 >= 3u) goto L_0081;  /* 007b: bgeui a3, 3, 81 <esp_mesh_delivery_toSelf+0x1d> */
  L_007e: goto L_03a4;  /* 007e: j */
  L_0081: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0081: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0084 */
  if (a3 == 0) goto L_03a4;  /* 0087: beqz a3, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_008a: a4 = LD32(a3 + 0x150);  /* 008a */
  if (a4 == 0) goto L_03a4;  /* 008d: beqz a4, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_0090: a10 = LD32(a3 + 0x158);  /* 0090 */
  __asm__ volatile("" ::: "memory");  /* 0093: memw */
  /* 0096: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0099 */
  a10 = 3;  /* 009b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 009d: -> "mesh_main.c" */
  a14 = a11;  /* 00a0 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 00a2: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 00a5: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03a4;  /* 00a8: j */
  L_00ac: a12 = 184;  /* 00ac */
  a11 = 0;  /* 00af */
  a10 = a1 + (64);  /* 00b1 */
  a8 = (u32)&memset + 0x0;  /* 00b4: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00b7: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x100);  /* 00ba */
  if (a9 != 0) goto L_00ea;  /* 00bd: bnez.n a9, ea <esp_mesh_delivery_toSelf+0x86> */
  L_00bf: a2 = (u32)&g_log_level + 0x0;  /* 00bf: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c2 */
  a2 = 0x00004008u;  /* 00c4: l32r = 16392 */
  if (a3 >= 3u) goto L_00cd;  /* 00c7: bgeui a3, 3, cd <esp_mesh_delivery_toSelf+0x69> */
  L_00ca: goto L_03a4;  /* 00ca: j */
  L_00cd: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00cd: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d0 */
  if (a3 == 0) goto L_03a4;  /* 00d2: beqz a3, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_00d5: a4 = LD32(a3 + 0x150);  /* 00d5 */
  if (a4 == 0) goto L_03a4;  /* 00d8: beqz a4, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_00db: a10 = LD32(a3 + 0x158);  /* 00db */
  a3 = 0x472;  /* 00de */
  /* 00e1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00e4: -> "mesh_main.c" */
  goto L_0118;  /* 00e7: j */
  L_00ea: a8 = LD32(a9 + 0x0);  /* 00ea */
  if (a8 != 0) goto L_0130;  /* 00ec: bnez a8, 130 <esp_mesh_delivery_toSelf+0xcc> */
  L_00ef: a2 = (u32)&g_log_level + 0x0;  /* 00ef: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00f2 */
  a2 = 0x00004008u;  /* 00f4: l32r = 16392 */
  if (a3 >= 3u) goto L_00fd;  /* 00f7: bgeui a3, 3, fd <esp_mesh_delivery_toSelf+0x99> */
  L_00fa: goto L_03a4;  /* 00fa: j */
  L_00fd: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00fd: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0100 */
  if (a3 == 0) goto L_03a4;  /* 0103: beqz a3, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_0106: a4 = LD32(a3 + 0x150);  /* 0106 */
  if (a4 == 0) goto L_03a4;  /* 0109: beqz a4, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_010c: a10 = LD32(a3 + 0x158);  /* 010c */
  a3 = 0x473;  /* 010f */
  /* 0112: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0115: -> "mesh_main.c" */
  L_0118: a13 = a10;  /* 0118 */
  a14 = a11;  /* 011a */
  a10 = 3;  /* 011c */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 011e: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0121: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 0124 */
  L_0126: __asm__ volatile("" ::: "memory");  /* 0126: memw */
  /* 0129: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03a4;  /* 012c: j */
  L_0130: a2 = LD32(a9 + 0x28);  /* 0130 */
  a7 = 1;  /* 0132 */
  a2 = (a2 >> 2) & 0x1;  /* 0134: extui width 1 */
  a2 = a2 + (-1);  /* 0137 */
  a3 = 0;  /* 0139 */
  a6 = a8 + (18);  /* 013b */
  if (a2 != 0) a7 = a3;  /* 013e */
  a2 = LD32(a6 + 0x0);  /* 0141 */
  a4 = a8 + (14);  /* 0143 */
  a7 = (a7 >> 8) & 0x1;  /* 0145: extui width 1 */
  if (((a2 >> 24) & 1) == 0) goto L_0160;  /* 0148: bbci a2, 24, 160 <esp_mesh_delivery_toSelf+0xfc> */
  L_014b: a10 = 33;  /* 014b */
  a5 = (u32)&g_mesh_topology + 0x0;  /* 014d: l32r -> global */
  a11 = LD32(a5 + 0x0);  /* 0150 */
  a5 = 28;  /* 0152 */
  if (a11 != 0) a5 = a10;  /* 0154 */
  a3 = LD8U(a8 + 0xf);  /* 0157 */
  a3 = a3 - a5;  /* 015a: subx4 */
  if (a3 >= 4u) goto L_0178;  /* 015d: bgeui a3, 4, 178 <esp_mesh_delivery_toSelf+0x114> */
  L_0160: if (((a2 >> 23) & 1) == 0) goto L_0199;  /* 0160: bbci a2, 23, 199 <esp_mesh_delivery_toSelf+0x135> */
  L_0163: a5 = (u32)&g_mesh_topology + 0x0;  /* 0163: l32r -> global */
  a10 = 33;  /* 0166 */
  a11 = LD32(a5 + 0x0);  /* 0168 */
  a5 = 28;  /* 016a */
  if (a11 != 0) a5 = a10;  /* 016c */
  a3 = LD8U(a8 + 0xf);  /* 016f */
  a3 = a3 - a5;  /* 0172: subx4 */
  if (a3 < 3u) goto L_0199;  /* 0175: bltui a3, 3, 199 <esp_mesh_delivery_toSelf+0x135> */
  L_0178: a3 = 28;  /* 0178 */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 017a: l32r -> global */
  a5 = LD32(a2 + 0x0);  /* 017d */
  a2 = 33;  /* 017f */
  if (a5 != 0) a3 = a2;  /* 0181 */
  a3 = a4 + a3;  /* 0184 */
  a5 = LD8U(a3 + 0x0);  /* 0186 */
  a5 = a5 + (-7);  /* 0189 */
  a5 = (a5 >> 8) & 0x1;  /* 018c: extui width 1 */
  a2 = 0x00004015u;  /* 018f: l32r = 16405 */
  if (a5 < 2u) goto L_01cd;  /* 0192: bltui a5, 2, 1cd <esp_mesh_delivery_toSelf+0x169> */
  L_0195: goto L_03a4;  /* 0195: j */
  L_0199: a3 = 0;  /* 0199 */
  if (((a2 >> 25) & 1) == 0) goto L_01cd;  /* 019b: bbci a2, 25, 1cd <esp_mesh_delivery_toSelf+0x169> */
  L_019e: a2 = (u32)&g_mesh_ext_vote_state + 0x0;  /* 019e: l32r -> global */
  a11 = LD8U(a2 + 0x0);  /* 01a1 */
  a2 = 4;  /* 01a4 */
  a11 = a11 & a2;  /* 01a6 */
  a2 = 0x00004015u;  /* 01a9: l32r = 16405 */
  if (a11 == a3) goto L_01b2;  /* 01ac: beq a11, a3, 1b2 <esp_mesh_delivery_toSelf+0x14e> */
  L_01af: goto L_03a4;  /* 01af: j */
  L_01b2: a3 = 32;  /* 01b2 */
  a10 = a1 + (64);  /* 01b4 */
  ST32(a1 + 0x40, a3);  /* 01b7 */
  a3 = 2;  /* 01ba */
  ST32(a1 + 0x44, a3);  /* 01bc */
  __asm__ volatile("" ::: "memory");  /* 01bf: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 01c2: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 01c5: callx a8 via reloc-expand */
  goto L_03a4;  /* 01c8: j */
  L_01cd: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 01cd: l32r -> global */
  a2 = LD32(a5 + 0x0);  /* 01d0 */
  a10 = LD32(a9 + 0x24);  /* 01d2 */
  a2 = LD32(a2 + 0xa0);  /* 01d5 */
  ST32(a1 + 0x124, a8);  /* 01d8 */
  __asm__ volatile("" ::: "memory");  /* 01db: memw */
  /* 01de: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 01e1 */
  a10 = a1 + 0x10000;  /* 01e3: addmi a10, a1, 0x100 */
  a8 = (u32)&esp_mesh_push_to_myself_queue + 0x0;  /* 01e6: l32r -> global */
  a2 = esp_mesh_push_to_myself_queue(a2, a3, a4, a5, a6, a7);  /* 01e9: callx a8 via reloc-expand */
  a9 = 0xffffbff3u;  /* 01ec: l32r = -16397 */
  a2 = a10;  /* 01ef */
  a9 = a10 + a9;  /* 01f1 */
  a8 = LD32(a1 + 0x124);  /* 01f3 */
  if (a9 != 0) goto L_0258;  /* 01f6: bnez a9, 258 <esp_mesh_delivery_toSelf+0x1f4> */
  L_01f9: if (a7 == 0) goto L_0258;  /* 01f9: beqz a7, 258 <esp_mesh_delivery_toSelf+0x1f4> */
  L_01fc: a11 = 0;  /* 01fc */
  a10 = 3;  /* 01fe */
  a13 = 0x0000400du;  /* 0200: l32r = 16397 */
  a12 = LD32(a1 + 0x100);  /* 0203 */
  a8 = (u32)&esp_mesh_send_block_start + 0x0;  /* 0206: l32r -> global */
  a2 = esp_mesh_send_block_start(a2, a3, a4, a5, a6, a7);  /* 0209: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x124);  /* 020c */
  if (a10 != 0) goto L_022a;  /* 020f: bnez.n a10, 22a <esp_mesh_delivery_toSelf+0x1c6> */
  L_0211: a7 = LD32(a6 + 0x0);  /* 0211 */
  a6 = 0x403;  /* 0213 */
  a6 = a6 << 14;  /* 0216 */
  a7 = a7 & a6;  /* 0219 */
  a6 = 1;  /* 021c */
  a6 = a6 << 24;  /* 021e */
  if (a7 == a6) goto L_0227;  /* 0221: beq a7, a6, 227 <esp_mesh_delivery_toSelf+0x1c3> */
  L_0224: goto L_03a4;  /* 0224: j */
  L_0227: goto L_025e;  /* 0227: j */
  L_022a: a3 = LD32(a5 + 0x0);  /* 022a */
  a2 = -1;  /* 022c */
  if (a3 == 0) goto L_03a4;  /* 022e: beqz a3, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_0231: a4 = LD32(a3 + 0x150);  /* 0231 */
  if (a4 == 0) goto L_03a4;  /* 0234: beqz a4, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_0237: a10 = LD32(a3 + 0x158);  /* 0237 */
  a3 = 0x492;  /* 023a */
  /* 023d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0240 */
  a10 = 1;  /* 0242 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0244: -> "mesh_main.c" */
  a14 = a11;  /* 0247 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0249: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_delivery_toDS_str1_1 + 0x0);  /* 024c: l32r -> .rodata.esp_mesh_delivery_toDS.str1.1 */
  ST32(a1 + 0x0, a3);  /* 024f */
  __asm__ volatile("" ::: "memory");  /* 0251: memw */
  goto L_0126;  /* 0254: j */
  L_0258: if (a2 == 0) goto L_03a4;  /* 0258: beqz a2, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_025b: goto L_0211;  /* 025b: j */
  L_025e: a7 = LD32(a4 + 0x18);  /* 025e */
  a6 = 0xf0000001u;  /* 0260: l32r = -268435455 */
  a6 = a7 + a6;  /* 0263 */
  if (a6 == 0) goto L_03a4;  /* 0265: beqz a6, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_0268: if (a7 == 0) goto L_03a4;  /* 0268: beqz a7, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_026b: a6 = (u32)&g_log_level + 0x0;  /* 026b: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 026e */
  if (a6 >= 3u) goto L_0276;  /* 0270: bgeui a6, 3, 276 <esp_mesh_delivery_toSelf+0x212> */
  L_0273: goto L_03a4;  /* 0273: j */
  L_0276: a6 = LD32(a5 + 0x0);  /* 0276 */
  if (a6 == 0) goto L_03a4;  /* 0278: beqz a6, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_027b: a5 = LD32(a6 + 0x150);  /* 027b */
  if (a5 == 0) goto L_03a4;  /* 027e: beqz a5, 3a4 <esp_mesh_delivery_toSelf+0x340> */
  L_0281: a10 = LD32(a6 + 0x158);  /* 0281 */
  ST32(a1 + 0x124, a8);  /* 0284 */
  __asm__ volatile("" ::: "memory");  /* 0287: memw */
  /* 028a: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 028d */
  a7 = LD32(a1 + 0x100);  /* 028f */
  a9 = LD8U(a7 + 0x12);  /* 0292 */
  a6 = (u32)(RODATA__rodata_esp_mesh_delivery_toSelf_str1_1 + 0x0);  /* 0295: -> " AP, child:" */
  a8 = LD32(a1 + 0x124);  /* 0298 */
  if (a9 == 1) goto L_02a1;  /* 029b: beqi a9, 1, 2a1 <esp_mesh_delivery_toSelf+0x23d> */
  L_029e: a6 = (u32)(RODATA__rodata_esp_mesh_delivery_toSelf_str1_1 + 0x0);  /* 029e: -> " AP, child:" */
  L_02a1: a11 = a8 + (42);  /* 02a1 */
  a10 = a4;  /* 02a4 */
  a9 = LD8U(a7 + 0xc);  /* 02a6 */
  ST32(a1 + 0x104, a9);  /* 02a9 */
  a9 = LD8U(a7 + 0xd);  /* 02ac */
  ST32(a1 + 0x108, a9);  /* 02af */
  a9 = LD8U(a7 + 0xe);  /* 02b2 */
  ST32(a1 + 0x10c, a9);  /* 02b5 */
  a9 = LD8U(a7 + 0xf);  /* 02b8 */
  ST32(a1 + 0x110, a9);  /* 02bb */
  a9 = LD8U(a7 + 0x10);  /* 02be */
  ST32(a1 + 0x114, a9);  /* 02c1 */
  a9 = LD8U(a7 + 0x11);  /* 02c4 */
  ST32(a1 + 0x118, a9);  /* 02c7 */
  a9 = LD16U(a7 + 0x4);  /* 02ca */
  a7 = LD8U(a8 + 0xf);  /* 02cd */
  ST32(a1 + 0x11c, a9);  /* 02d0 */
  a9 = a7 << 2;  /* 02d3 */
  a7 = a8 + (14);  /* 02d6 */
  a7 = LD32(a7 + 0x18);  /* 02d8 */
  ST32(a1 + 0x120, a9);  /* 02db */
  ST32(a1 + 0x124, a8);  /* 02de */
  ST32(a1 + 0x12c, a13);  /* 02e1 */
  __asm__ volatile("" ::: "memory");  /* 02e4: memw */
  a8 = (u32)&mesh_topo_get_ttl + 0x0;  /* 02e7: l32r -> global */
  a2 = mesh_topo_get_ttl(a2, a3, a4, a5, a6, a7);  /* 02ea: callx a8 via reloc-expand */
  a12 = a10;  /* 02ed */
  a8 = LD32(a1 + 0x124);  /* 02ef */
  a4 = a8 + (18);  /* 02f2 */
  a10 = LD32(a4 + 0x0);  /* 02f5 */
  a13 = LD32(a1 + 0x12c);  /* 02f7 */
  if (((a10 >> 24) & 1) == 0) goto L_0312;  /* 02fa: bbci a10, 24, 312 <esp_mesh_delivery_toSelf+0x2ae> */
  L_02fd: a14 = 33;  /* 02fd */
  a9 = (u32)&g_mesh_topology + 0x0;  /* 02ff: l32r -> global */
  a11 = LD32(a9 + 0x0);  /* 0302 */
  a9 = 28;  /* 0304 */
  if (a11 != 0) a9 = a14;  /* 0306 */
  a4 = LD8U(a8 + 0xf);  /* 0309 */
  a4 = a4 - a9;  /* 030c: subx4 */
  if (a4 >= 4u) goto L_032d;  /* 030f: bgeui a4, 4, 32d <esp_mesh_delivery_toSelf+0x2c9> */
  L_0312: a9 = -1;  /* 0312 */
  if (((a10 >> 23) & 1) == 0) goto L_0330;  /* 0314: bbci a10, 23, 330 <esp_mesh_delivery_toSelf+0x2cc> */
  L_0317: a4 = LD8U(a8 + 0xf);  /* 0317 */
  a10 = 33;  /* 031a */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 031c: l32r -> global */
  a11 = LD32(a8 + 0x0);  /* 031f */
  a8 = 28;  /* 0321 */
  if (a11 != 0) a8 = a10;  /* 0324 */
  a4 = a4 - a8;  /* 0327: subx4 */
  if (a4 < 3u) goto L_0330;  /* 032a: bltui a4, 3, 330 <esp_mesh_delivery_toSelf+0x2cc> */
  L_032d: a9 = LD8U(a3 + 0x0);  /* 032d */
  L_0330: a3 = (u32)&mesh_myself_mbox + 0x0;  /* 0330: l32r -> global */
  a10 = LD32(a3 + 0x0);  /* 0333 */
  a3 = 0;  /* 0335 */
  if (a10 == a3) goto L_035d;  /* 0337: beq a10, a3, 35d <esp_mesh_delivery_toSelf+0x2f9> */
  L_033a: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 033a: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 033d */
  a3 = LD32(a3 + 0x78);  /* 0340 */
  ST32(a1 + 0x128, a9);  /* 0343 */
  ST32(a1 + 0x124, a12);  /* 0346 */
  ST32(a1 + 0x12c, a13);  /* 0349 */
  __asm__ volatile("" ::: "memory");  /* 034c: memw */
  /* 034f: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a3 = a10;  /* 0352 */
  a13 = LD32(a1 + 0x12c);  /* 0354 */
  a12 = LD32(a1 + 0x124);  /* 0357 */
  a9 = LD32(a1 + 0x128);  /* 035a */
  L_035d: a15 = 0x499;  /* 035d */
  a10 = 3;  /* 0360 */
  ST32(a1 + 0x30, a3);  /* 0362 */
  ST32(a1 + 0x2c, a9);  /* 0364 */
  a3 = LD32(a1 + 0x120);  /* 0366 */
  a9 = LD32(a1 + 0x11c);  /* 0369 */
  ST32(a1 + 0x20, a3);  /* 036c */
  ST32(a1 + 0x1c, a9);  /* 036e */
  a3 = LD32(a1 + 0x118);  /* 0370 */
  a9 = LD32(a1 + 0x114);  /* 0373 */
  ST32(a1 + 0x18, a3);  /* 0376 */
  ST32(a1 + 0x14, a9);  /* 0378 */
  a3 = LD32(a1 + 0x110);  /* 037a */
  a9 = LD32(a1 + 0x10c);  /* 037d */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0380: -> "mesh_main.c" */
  a14 = a11;  /* 0383 */
  ST32(a1 + 0x10, a3);  /* 0385 */
  ST32(a1 + 0xc, a9);  /* 0387 */
  a3 = LD32(a1 + 0x108);  /* 0389 */
  a9 = LD32(a1 + 0x104);  /* 038c */
  ST32(a1 + 0x28, a12);  /* 038f */
  a12 = (u32)(RODATA__rodata_esp_mesh_delivery_toSelf_str1_1 + 0x0);  /* 0391: -> " AP, child:" */
  ST32(a1 + 0x34, a2);  /* 0394 */
  ST32(a1 + 0x24, a7);  /* 0396 */
  ST32(a1 + 0x8, a3);  /* 0398 */
  ST32(a1 + 0x4, a9);  /* 039a */
  ST32(a1 + 0x0, a6);  /* 039c */
  __asm__ volatile("" ::: "memory");  /* 039e: memw */
  /* 03a1: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_03a4: return a2;  /* 03a4: retw.n */
}


/* esp_mesh_forward_packet @ mesh_main.o 00000084 size 828B bind GLOBAL
 * Calls: mesh_process_mgmt_root_waive, mesh_process_mgmt_announce, memcmp, esp_mesh_process_bcast, esp_mesh_process_mcast, esp_mesh_match_self, esp_mesh_process_options, esp_mesh_delivery_toSelf, esp_mesh_process_ucast, esp_mesh_force_txupQ_pending | indirect[8]: mem[a2+0x158]; mem[a2+0x150]; mem[a5+0x158]; mem[a10+0xb8] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_topology, .data.MESH_BCAST_ADDR, .bss.MESH_ZERO_ADDR, g_mesh_is_root, .rodata.esp_mesh_process_ucast.str1.1, .rodata.esp_mesh_process_options.str1.1, .rodata.esp_mesh_forward_packet.str1.1 +1 more
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=10, refs=23); reloc-direct=10, funcdb-attributed=0, unknown-indirect=8 */
u32 esp_mesh_forward_packet(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0000001, F2;
  /* 0084: entry a1, 176 (frame 176 bytes) */
  a3 = (u32)&g_is_mesh_started + 0x0;  /* 0087: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 008a */
  if (a3 != 0) goto L_00c5;  /* 008d: bnez.n a3, c5 <esp_mesh_forward_packet+0x41> */
  L_008f: a2 = (u32)&g_log_level + 0x0;  /* 008f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0092 */
  a4 = 0x00004004u;  /* 0094: l32r = 16388 */
  if (a2 >= 3u) goto L_009d;  /* 0097: bgeui a2, 3, 9d <esp_mesh_forward_packet+0x19> */
  L_009a: goto L_03bc;  /* 009a: j */
  L_009d: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 009d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00a0 */
  if (a2 == 0) goto L_03bc;  /* 00a2: beqz a2, 3bc <esp_mesh_forward_packet+0x338> */
  L_00a5: a3 = LD32(a2 + 0x150);  /* 00a5 */
  if (a3 == 0) goto L_03bc;  /* 00a8: beqz a3, 3bc <esp_mesh_forward_packet+0x338> */
  L_00ab: a10 = LD32(a2 + 0x158);  /* 00ab */
  /* 00ae: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00b1 */
  a10 = 3;  /* 00b3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00b5: -> "mesh_main.c" */
  a14 = a11;  /* 00b8 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 00ba: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 00bd: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_03bc;  /* 00c0: j */
  L_00c5: if (a2 != 0) goto L_00f2;  /* 00c5: bnez.n a2, f2 <esp_mesh_forward_packet+0x6e> */
  L_00c7: a2 = (u32)&g_log_level + 0x0;  /* 00c7: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00ca */
  a4 = 0x00004008u;  /* 00cc: l32r = 16392 */
  if (a2 >= 3u) goto L_00d5;  /* 00cf: bgeui a2, 3, d5 <esp_mesh_forward_packet+0x51> */
  L_00d2: goto L_03bc;  /* 00d2: j */
  L_00d5: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00d5: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00d8 */
  if (a2 == 0) goto L_03bc;  /* 00da: beqz a2, 3bc <esp_mesh_forward_packet+0x338> */
  L_00dd: a3 = LD32(a2 + 0x150);  /* 00dd */
  if (a3 == 0) goto L_03bc;  /* 00e0: beqz a3, 3bc <esp_mesh_forward_packet+0x338> */
  L_00e3: a10 = LD32(a2 + 0x158);  /* 00e3 */
  a2 = 127;  /* 00e6 */
  /* 00e9: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00ec: -> "mesh_main.c" */
  goto L_0120;  /* 00ef: j */
  L_00f2: a3 = LD32(a2 + 0x0);  /* 00f2 */
  if (a3 != 0) goto L_0138;  /* 00f4: bnez a3, 138 <esp_mesh_forward_packet+0xb4> */
  L_00f7: a2 = (u32)&g_log_level + 0x0;  /* 00f7: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00fa */
  a4 = 0x00004008u;  /* 00fc: l32r = 16392 */
  if (a2 >= 3u) goto L_0105;  /* 00ff: bgeui a2, 3, 105 <esp_mesh_forward_packet+0x81> */
  L_0102: goto L_03bc;  /* 0102: j */
  L_0105: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0105: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0108 */
  if (a2 == 0) goto L_03bc;  /* 010b: beqz a2, 3bc <esp_mesh_forward_packet+0x338> */
  L_010e: a3 = LD32(a2 + 0x150);  /* 010e */
  if (a3 == 0) goto L_03bc;  /* 0111: beqz a3, 3bc <esp_mesh_forward_packet+0x338> */
  L_0114: a10 = LD32(a2 + 0x158);  /* 0114 */
  a2 = 128;  /* 0117 */
  /* 011a: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 011d: -> "mesh_main.c" */
  L_0120: a13 = a10;  /* 0120 */
  a14 = a11;  /* 0122 */
  a10 = 3;  /* 0124 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0126: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0129: -> "mesh_main.c" */
  ST32(a1 + 0x0, a2);  /* 012c */
  __asm__ volatile("" ::: "memory");  /* 012e: memw */
  /* 0131: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_03bc;  /* 0134: j */
  L_0138: a6 = (u32)&g_mesh_topology + 0x0;  /* 0138: l32r -> global */
  a10 = 28;  /* 013b */
  a4 = 33;  /* 013d */
  a5 = LD32(a6 + 0x0);  /* 013f */
  if (a5 != 0) a10 = a4;  /* 0141 */
  a5 = a3 + (18);  /* 0144 */
  a7 = LD32(a5 + 0x0);  /* 0147 */
  if (((a7 >> 24) & 1) == 0) goto L_0155;  /* 0149: bbci a7, 24, 155 <esp_mesh_forward_packet+0xd1> */
  L_014c: a4 = LD8U(a3 + 0xf);  /* 014c */
  a4 = a4 - a10;  /* 014f: subx4 */
  if (a4 >= 4u) goto L_0161;  /* 0152: bgeui a4, 4, 161 <esp_mesh_forward_packet+0xdd> */
  L_0155: if (((a7 >> 23) & 1) == 0) goto L_01af;  /* 0155: bbci a7, 23, 1af <esp_mesh_forward_packet+0x12b> */
  L_0158: a4 = LD8U(a3 + 0xf);  /* 0158 */
  a4 = a4 - a10;  /* 015b: subx4 */
  if (a4 < 3u) goto L_01af;  /* 015e: bltui a4, 3, 1af <esp_mesh_forward_packet+0x12b> */
  L_0161: a10 = a10 + (14);  /* 0161 */
  a10 = a3 + a10;  /* 0163 */
  a4 = LD8U(a10 + 0x0);  /* 0165 */
  a8 = LD32(a2 + 0x28);  /* 0168 */
  if (a4 != 2) goto L_0190;  /* 016a: bnei a4, 2, 190 <esp_mesh_forward_packet+0x10c> */
  L_016d: a7 = LD8U(a10 + 0x2);  /* 016d */
  a7 = a7 << 8;  /* 0170 */
  a9 = LD8U(a10 + 0x1);  /* 0173 */
  a7 = a7 | a9;  /* 0176 */
  a9 = 24;  /* 0179 */
  if (a7 != a9) goto L_0190;  /* 017b: bne a7, a9, 190 <esp_mesh_forward_packet+0x10c> */
  L_017e: a7 = 0x180;  /* 017e */
  if ((a8 & a7) != 0) goto L_0190;  /* 0181: bany a8, a7, 190 <esp_mesh_forward_packet+0x10c> */
  L_0184: a11 = a10 + (3);  /* 0184 */
  a8 = (u32)&mesh_process_mgmt_root_waive;  /* 0186: l32r -> func addr */
  a2 = mesh_process_mgmt_root_waive(a2, a3, a4, a5, a6, a7);  /* 0189: callx a8 via reloc-expand */
  goto L_01af;  /* 018c: j */
  L_0190: if (((a8 >> 0) & 1) != 0) goto L_01af;  /* 0190: bbsi a8, 0, 1af <esp_mesh_forward_packet+0x12b> */
  L_0193: a4 = a4 + (-3);  /* 0193 */
  a4 = (a4 >> 8) & 0x1;  /* 0196: extui width 1 */
  if (a4 >= 2u) goto L_01af;  /* 0199: bgeui a4, 2, 1af <esp_mesh_forward_packet+0x12b> */
  L_019c: a13 = a2 + (12);  /* 019c */
  a12 = a3 + (28);  /* 019e */
  a11 = a10 + (3);  /* 01a1 */
  a8 = (u32)&mesh_process_mgmt_announce;  /* 01a3: l32r -> func addr */
  a2 = mesh_process_mgmt_announce(a2, a3, a4, a5, a6, a7);  /* 01a6: callx a8 via reloc-expand */
  a4 = 0x00004015u;  /* 01a9: l32r = 16405 */
  if (a10 != 0) goto L_03bc;  /* 01ac: bnez a10, 3bc <esp_mesh_forward_packet+0x338> */
  L_01af: a4 = LD32(a5 + 0x0);  /* 01af */
  if (((a4 >> 27) & 1) != 0) goto L_01c6;  /* 01b1: bbsi a4, 27, 1c6 <esp_mesh_forward_packet+0x142> */
  L_01b4: a4 = a3 + (22);  /* 01b4 */
  a12 = 6;  /* 01b7 */
  a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 01b9: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  a10 = a4;  /* 01bc */
  a8 = (u32)&memcmp + 0x0;  /* 01be: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 01c1: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_01d1;  /* 01c4: bnez.n a10, 1d1 <esp_mesh_forward_packet+0x14d> */
  L_01c6: a10 = a2;  /* 01c6 */
  a8 = (u32)&esp_mesh_process_bcast;  /* 01c8: l32r -> func addr */
  a2 = esp_mesh_process_bcast(a2, a3, a4, a5, a6, a7);  /* 01cb: callx a8 via reloc-expand */
  goto L_0234;  /* 01ce: j */
  L_01d1: a7 = LD8U(a3 + 0x16);  /* 01d1 */
  if (((a7 >> 0) & 1) == 0) goto L_01e8;  /* 01d4: bbci a7, 0, 1e8 <esp_mesh_forward_packet+0x164> */
  L_01d7: a7 = LD8U(a3 + 0xe);  /* 01d7 */
  if (((a7 >> 5) & 1) != 0) goto L_01e8;  /* 01da: bbsi a7, 5, 1e8 <esp_mesh_forward_packet+0x164> */
  L_01dd: a10 = a2;  /* 01dd */
  a8 = (u32)&esp_mesh_process_mcast;  /* 01df: l32r -> func addr */
  a2 = esp_mesh_process_mcast(a2, a3, a4, a5, a6, a7);  /* 01e2: callx a8 via reloc-expand */
  goto L_0234;  /* 01e5: j */
  L_01e8: a10 = a4;  /* 01e8 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 01ea: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 01ed: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0239;  /* 01f0: beqz a10, 239 <esp_mesh_forward_packet+0x1b5> */
  L_01f3: a7 = LD32(a5 + 0x0);  /* 01f3 */
  if (((a7 >> 24) & 1) == 0) goto L_020c;  /* 01f5: bbci a7, 24, 20c <esp_mesh_forward_packet+0x188> */
  L_01f8: a5 = 28;  /* 01f8 */
  a8 = 33;  /* 01fb */
  a9 = LD32(a6 + 0x0);  /* 01fd */
  if (a9 != 0) a5 = a8;  /* 0200 */
  a4 = LD8U(a3 + 0xf);  /* 0203 */
  a4 = a4 - a5;  /* 0206: subx4 */
  if (a4 >= 4u) goto L_0221;  /* 0209: bgeui a4, 4, 221 <esp_mesh_forward_packet+0x19d> */
  L_020c: if (((a7 >> 23) & 1) == 0) goto L_022c;  /* 020c: bbci a7, 23, 22c <esp_mesh_forward_packet+0x1a8> */
  L_020f: a6 = LD32(a6 + 0x0);  /* 020f */
  a4 = 28;  /* 0211 */
  a5 = 33;  /* 0213 */
  if (a6 != 0) a4 = a5;  /* 0215 */
  a3 = LD8U(a3 + 0xf);  /* 0218 */
  a3 = a3 - a4;  /* 021b: subx4 */
  if (a3 < 3u) goto L_022c;  /* 021e: bltui a3, 3, 22c <esp_mesh_forward_packet+0x1a8> */
  L_0221: a10 = a2;  /* 0221 */
  a8 = (u32)&esp_mesh_process_options;  /* 0223: l32r -> func addr */
  a2 = esp_mesh_process_options(a2, a3, a4, a5, a6, a7);  /* 0226: callx a8 via reloc-expand */
  goto L_0234;  /* 0229: j */
  L_022c: a10 = a2;  /* 022c */
  a8 = (u32)&esp_mesh_delivery_toSelf;  /* 022e: l32r -> func addr */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 0231: callx a8 via reloc-expand */
  L_0234: a4 = a10;  /* 0234 */
  goto L_03bc;  /* 0236: j */
  L_0239: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 0239: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 023c */
  a10 = a4;  /* 023e */
  a8 = (u32)&memcmp + 0x0;  /* 0240: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0243: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0259;  /* 0246: bnez.n a10, 259 <esp_mesh_forward_packet+0x1d5> */
  L_0248: a4 = (u32)&g_mesh_is_root + 0x0;  /* 0248: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 024b: memw */
  a4 = LD8U(a4 + 0x0);  /* 024e */
  a4 = (a4 >> 8) & 0x1;  /* 0251: extui width 1 */
  if (a4 == 0) goto L_0259;  /* 0254: beqz.n a4, 259 <esp_mesh_forward_packet+0x1d5> */
  L_0256: goto L_01f3;  /* 0256: j */
  L_0259: a10 = a2;  /* 0259 */
  a8 = (u32)&esp_mesh_process_ucast;  /* 025b: l32r -> func addr */
  a2 = esp_mesh_process_ucast(a2, a3, a4, a5, a6, a7);  /* 025e: callx a8 via reloc-expand */
  a6 = 0x0000400fu;  /* 0261: l32r = 16399 */
  a4 = a10;  /* 0264 */
  if (a10 == a6) goto L_026c;  /* 0266: beq a10, a6, 26c <esp_mesh_forward_packet+0x1e8> */
  L_0269: goto L_03bc;  /* 0269: j */
  L_026c: a6 = LD32(a5 + 0x0);  /* 026c */
  a5 = 0x403;  /* 026e */
  a5 = a5 << 14;  /* 0271 */
  a6 = a6 & a5;  /* 0274 */
  a5 = 1;  /* 0277 */
  a5 = a5 << 24;  /* 0279 */
  if (a6 == a5) goto L_0282;  /* 027c: beq a6, a5, 282 <esp_mesh_forward_packet+0x1fe> */
  L_027f: goto L_03bc;  /* 027f: j */
  L_0282: a8 = a3 + (14);  /* 0282 */
  a5 = LD32(a8 + 0x18);  /* 0284 */
  if (a5 == 0) goto L_03bc;  /* 0286: beqz a5, 3bc <esp_mesh_forward_packet+0x338> */
  L_0289: a6 = 0xf0000001u;  /* 0289: l32r = -268435455 */
  a5 = a5 + a6;  /* 028c */
  if (a5 == 0) goto L_03bc;  /* 028e: beqz a5, 3bc <esp_mesh_forward_packet+0x338> */
  L_0291: a5 = (u32)&g_log_level + 0x0;  /* 0291: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 0294 */
  if (a5 >= 3u) goto L_029c;  /* 0296: bgeui a5, 3, 29c <esp_mesh_forward_packet+0x218> */
  L_0299: goto L_03aa;  /* 0299: j */
  L_029c: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 029c: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 029f */
  if (a5 == 0) goto L_03aa;  /* 02a1: beqz a5, 3aa <esp_mesh_forward_packet+0x326> */
  L_02a4: a6 = LD32(a5 + 0x150);  /* 02a4 */
  if (a6 == 0) goto L_03aa;  /* 02a7: beqz a6, 3aa <esp_mesh_forward_packet+0x326> */
  L_02aa: a10 = LD32(a5 + 0x158);  /* 02aa */
  ST32(a1 + 0x88, a8);  /* 02ad */
  __asm__ volatile("" ::: "memory");  /* 02b0: memw */
  /* 02b3: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 02b6 */
  a10 = a2 + (12);  /* 02b8 */
  a8 = LD32(a1 + 0x88);  /* 02bb */
  a8 = LD32(a8 + 0x18);  /* 02be */
  ST32(a1 + 0x50, a8);  /* 02c1 */
  __asm__ volatile("" ::: "memory");  /* 02c4: memw */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 02c7: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 02ca: callx a8 via reloc-expand */
  a8 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 02cd: -> "xmitter" */
  if (a10 != 0) goto L_02d5;  /* 02d0: bnez.n a10, 2d5 <esp_mesh_forward_packet+0x251> */
  L_02d2: a8 = (u32)(RODATA__rodata_esp_mesh_process_options_str1_1 + 0x0);  /* 02d2: -> "xmit" */
  L_02d5: a5 = LD8U(a2 + 0xc);  /* 02d5 */
  ST32(a1 + 0x54, a5);  /* 02d8 */
  a5 = LD8U(a2 + 0xd);  /* 02db */
  ST32(a1 + 0x58, a5);  /* 02de */
  a5 = LD8U(a2 + 0xe);  /* 02e1 */
  ST32(a1 + 0x5c, a5);  /* 02e4 */
  a5 = LD8U(a2 + 0xf);  /* 02e7 */
  ST32(a1 + 0x60, a5);  /* 02ea */
  a5 = LD8U(a2 + 0x10);  /* 02ed */
  ST32(a1 + 0x64, a5);  /* 02f0 */
  a5 = LD8U(a2 + 0x11);  /* 02f3 */
  ST32(a1 + 0x68, a5);  /* 02f6 */
  a5 = LD8U(a3 + 0x16);  /* 02f9 */
  a10 = (u32)&g_osi_funcs_p + 0x0;  /* 02fc: l32r -> global */
  ST32(a1 + 0x6c, a5);  /* 02ff */
  a5 = LD8U(a3 + 0x17);  /* 0302 */
  a10 = LD32(a10 + 0x0);  /* 0305 */
  ST32(a1 + 0x70, a5);  /* 0308 */
  a5 = a3 + (18);  /* 030b */
  a9 = LD8U(a3 + 0x18);  /* 030e */
  a12 = LD8U(a3 + 0x19);  /* 0311 */
  a13 = LD8U(a3 + 0x1a);  /* 0314 */
  a14 = LD8U(a3 + 0x1b);  /* 0317 */
  a5 = LD32(a5 + 0x0);  /* 031a */
  a5 = (a5 >> 5) & 0x3ff;  /* 031d: extui width 10 */
  a15 = LD16U(a2 + 0x4);  /* 0320 */
  a10 = LD32(a10 + 0xb8);  /* 0323 */
  ST32(a1 + 0x88, a8);  /* 0326 */
  ST32(a1 + 0x74, a9);  /* 0329 */
  ST32(a1 + 0x78, a12);  /* 032c */
  ST32(a1 + 0x7c, a13);  /* 032f */
  ST32(a1 + 0x80, a14);  /* 0332 */
  ST32(a1 + 0x84, a15);  /* 0335 */
  __asm__ volatile("" ::: "memory");  /* 0338: memw */
  /* 033b: INDIRECT callx a10 <- mem[a10+0xb8]; result unknown */ a2 = 0;
  ST32(a1 + 0x3c, a5);  /* 033e */
  a5 = LD32(a1 + 0x70);  /* 0340 */
  ST32(a1 + 0x28, a5);  /* 0343 */
  a5 = LD32(a1 + 0x6c);  /* 0345 */
  ST32(a1 + 0x24, a5);  /* 0348 */
  a5 = LD32(a1 + 0x68);  /* 034a */
  ST32(a1 + 0x20, a5);  /* 034d */
  a5 = LD32(a1 + 0x64);  /* 034f */
  ST32(a1 + 0x1c, a5);  /* 0352 */
  a5 = LD32(a1 + 0x60);  /* 0354 */
  ST32(a1 + 0x18, a5);  /* 0357 */
  a5 = LD32(a1 + 0x5c);  /* 0359 */
  ST32(a1 + 0x14, a5);  /* 035c */
  a5 = LD32(a1 + 0x58);  /* 035e */
  ST32(a1 + 0x10, a5);  /* 0361 */
  a5 = LD32(a1 + 0x54);  /* 0363 */
  a15 = LD32(a1 + 0x84);  /* 0366 */
  a14 = LD32(a1 + 0x80);  /* 0369 */
  a13 = LD32(a1 + 0x7c);  /* 036c */
  a12 = LD32(a1 + 0x78);  /* 036f */
  a9 = LD32(a1 + 0x74);  /* 0372 */
  a8 = LD32(a1 + 0x88);  /* 0375 */
  ST32(a1 + 0xc, a5);  /* 0378 */
  a5 = LD32(a1 + 0x50);  /* 037a */
  ST32(a1 + 0x44, a10);  /* 037d */
  a10 = 3;  /* 0380 */
  ST32(a1 + 0x40, a15);  /* 0382 */
  a15 = 248;  /* 0385 */
  ST32(a1 + 0x38, a14);  /* 0388 */
  ST32(a1 + 0x34, a13);  /* 038a */
  a13 = a7;  /* 038c */
  ST32(a1 + 0x30, a12);  /* 038e */
  ST32(a1 + 0x2c, a9);  /* 0390 */
  ST32(a1 + 0x8, a8);  /* 0392 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0394: -> "mesh_main.c" */
  a14 = a11;  /* 0397 */
  ST32(a1 + 0x4, a5);  /* 0399 */
  a5 = (u32)(RODATA__rodata_esp_mesh_forward_packet_str1_1 + 0x0);  /* 039b: l32r -> .rodata.esp_mesh_forward_packet.str1.1 */
  a12 = (u32)(RODATA__rodata_esp_mesh_forward_packet_str1_1 + 0x0);  /* 039e: l32r -> .rodata.esp_mesh_forward_packet.str1.1 */
  ST32(a1 + 0x0, a5);  /* 03a1 */
  __asm__ volatile("" ::: "memory");  /* 03a4: memw */
  /* 03a7: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_03aa: a3 = a3 + (14);  /* 03aa */
  a13 = 0x100;  /* 03ac */
  a10 = a2;  /* 03af */
  a12 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 03b1: -> "esp_mesh_forward_packet" */
  a11 = LD32(a3 + 0x18);  /* 03b4 */
  a8 = (u32)&esp_mesh_force_txupQ_pending + 0x0;  /* 03b6: l32r -> global */
  a2 = esp_mesh_force_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 03b9: callx a8 via reloc-expand */
  L_03bc: a2 = a4;  /* 03bc */
  return a2;  /* 03be: retw.n */
}


/* esp_mesh_get_optlen @ mesh_main.o 0000001c size 96B bind GLOBAL
 * Calls: none | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, g_mesh_topology
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=4); reloc-direct=0, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_optlen(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 001c: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0060;  /* 001f: bnez.n a2, 60 <esp_mesh_get_optlen+0x44> */
  L_0021: a2 = (u32)&g_log_level + 0x0;  /* 0021: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0024 */
  a2 = 0x00004008u;  /* 0027: l32r = 16392 */
  if (a3 < 3u) goto L_007a;  /* 002a: bltui a3, 3, 7a <esp_mesh_get_optlen+0x5e> */
  L_002d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 002d: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0030 */
  if (a8 == 0) goto L_007a;  /* 0032: beqz a8, 7a <esp_mesh_get_optlen+0x5e> */
  L_0035: a3 = LD32(a8 + 0x150);  /* 0035 */
  if (a3 == 0) goto L_007a;  /* 0038: beqz.n a3, 7a <esp_mesh_get_optlen+0x5e> */
  L_003a: a10 = LD32(a8 + 0x158);  /* 003a */
  /* 003d: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x11d;  /* 0040 */
  a13 = a10;  /* 0043 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0045: -> "mesh_main.c" */
  a10 = 3;  /* 0048 */
  a14 = a11;  /* 004a: mov */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 004d: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0050: -> "mesh_main.c" */
  ST32(a1 + 0x0, a8);  /* 0053 */
  __asm__ volatile("" ::: "memory");  /* 0056: memw */
  /* 0059: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_007a;  /* 005c: j */
  L_0060: a3 = (u32)&g_mesh_topology + 0x0;  /* 0060: l32r -> global */
  a8 = 28;  /* 0063 */
  a9 = LD32(a3 + 0x0);  /* 0065 */
  a3 = 33;  /* 0067 */
  if (a9 != 0) a8 = a3;  /* 0069 */
  a2 = a2 + a8;  /* 006c */
  a3 = LD8U(a2 + 0x1);  /* 006e */
  a2 = LD8U(a2 + 0x2);  /* 0071 */
  a2 = a2 << 8;  /* 0074 */
  a2 = a2 | a3;  /* 0077 */
  L_007a: return a2;  /* 007a: retw.n */
}


/* esp_mesh_mcast_cover_node @ mesh_main.o 00000064 size 758B bind GLOBAL
 * Calls: memcmp, esp_mesh_match_self, mesh_mutex_lock, esp_mesh_lookup_route, mesh_mutex_unlock | indirect[5]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_topology, mesh_conn_mutex, g_mesh_ext_cfg, .rodata.__func__$3
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=14); reloc-direct=5, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_mcast_cover_node(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0064: entry a1, 80 (frame 80 bytes) */
  a6 = (u32)&g_is_mesh_started + 0x0;  /* 0067: l32r -> global */
  a6 = LD8U(a6 + 0x0);  /* 006a */
  if (a6 != 0) goto L_00a5;  /* 006d: bnez.n a6, a5 <esp_mesh_mcast_cover_node+0x41> */
  L_006f: a2 = (u32)&g_log_level + 0x0;  /* 006f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0072 */
  a2 = 0x00004004u;  /* 0074: l32r = 16388 */
  if (a3 >= 3u) goto L_007d;  /* 0077: bgeui a3, 3, 7d <esp_mesh_mcast_cover_node+0x19> */
  L_007a: goto L_0358;  /* 007a: j */
  L_007d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 007d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0080 */
  if (a3 == 0) goto L_0358;  /* 0082: beqz a3, 358 <esp_mesh_mcast_cover_node+0x2f4> */
  L_0085: a4 = LD32(a3 + 0x150);  /* 0085 */
  if (a4 == 0) goto L_0358;  /* 0088: beqz a4, 358 <esp_mesh_mcast_cover_node+0x2f4> */
  L_008b: a10 = LD32(a3 + 0x158);  /* 008b */
  /* 008e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0091 */
  a10 = 3;  /* 0093 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0095: -> "mesh_main.c" */
  a14 = a11;  /* 0098 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 009a: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 009d: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0358;  /* 00a0: j */
  L_00a5: if (a2 != 0) goto L_00d2;  /* 00a5: bnez.n a2, d2 <esp_mesh_mcast_cover_node+0x6e> */
  L_00a7: a2 = (u32)&g_log_level + 0x0;  /* 00a7: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00aa */
  a2 = 0x00004008u;  /* 00ac: l32r = 16392 */
  if (a3 >= 3u) goto L_00b5;  /* 00af: bgeui a3, 3, b5 <esp_mesh_mcast_cover_node+0x51> */
  L_00b2: goto L_0358;  /* 00b2: j */
  L_00b5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b5: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00b8 */
  if (a3 == 0) goto L_0358;  /* 00ba: beqz a3, 358 <esp_mesh_mcast_cover_node+0x2f4> */
  L_00bd: a4 = LD32(a3 + 0x150);  /* 00bd */
  if (a4 == 0) goto L_0358;  /* 00c0: beqz a4, 358 <esp_mesh_mcast_cover_node+0x2f4> */
  L_00c3: a10 = LD32(a3 + 0x158);  /* 00c3 */
  a3 = 0x12e;  /* 00c6 */
  /* 00c9: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00cc: -> "mesh_main.c" */
  goto L_0100;  /* 00cf: j */
  L_00d2: a8 = LD32(a2 + 0x0);  /* 00d2 */
  if (a8 != 0) goto L_0118;  /* 00d4: bnez a8, 118 <esp_mesh_mcast_cover_node+0xb4> */
  L_00d7: a2 = (u32)&g_log_level + 0x0;  /* 00d7: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00da */
  a2 = 0x00004008u;  /* 00dc: l32r = 16392 */
  if (a3 >= 3u) goto L_00e5;  /* 00df: bgeui a3, 3, e5 <esp_mesh_mcast_cover_node+0x81> */
  L_00e2: goto L_0358;  /* 00e2: j */
  L_00e5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00e5: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00e8 */
  if (a3 == 0) goto L_0358;  /* 00eb: beqz a3, 358 <esp_mesh_mcast_cover_node+0x2f4> */
  L_00ee: a4 = LD32(a3 + 0x150);  /* 00ee */
  if (a4 == 0) goto L_0358;  /* 00f1: beqz a4, 358 <esp_mesh_mcast_cover_node+0x2f4> */
  L_00f4: a10 = LD32(a3 + 0x158);  /* 00f4 */
  a3 = 0x12f;  /* 00f7 */
  /* 00fa: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00fd: -> "mesh_main.c" */
  L_0100: a13 = a10;  /* 0100 */
  a14 = a11;  /* 0102 */
  a10 = 3;  /* 0104 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0106: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0109: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 010c */
  __asm__ volatile("" ::: "memory");  /* 010e: memw */
  /* 0111: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0358;  /* 0114: j */
  L_0118: a2 = (u32)&g_mesh_topology + 0x0;  /* 0118: l32r -> global */
  a6 = 28;  /* 011b */
  a7 = LD32(a2 + 0x0);  /* 011d */
  a2 = 33;  /* 011f */
  if (a7 != 0) a6 = a2;  /* 0121 */
  a2 = a8 + (18);  /* 0124 */
  a7 = LD32(a2 + 0x0);  /* 0127 */
  if (((a7 >> 24) & 1) == 0) goto L_0135;  /* 0129: bbci a7, 24, 135 <esp_mesh_mcast_cover_node+0xd1> */
  L_012c: a2 = LD8U(a8 + 0xf);  /* 012c */
  a2 = a2 - a6;  /* 012f: subx4 */
  if (a2 >= 4u) goto L_0153;  /* 0132: bgeui a2, 4, 153 <esp_mesh_mcast_cover_node+0xef> */
  L_0135: a2 = 0x401;  /* 0135 */
  a2 = a2 << 4;  /* 0138 */
  if (((a7 >> 23) & 1) != 0) goto L_0141;  /* 013b: bbsi a7, 23, 141 <esp_mesh_mcast_cover_node+0xdd> */
  L_013e: goto L_0358;  /* 013e: j */
  L_0141: a7 = LD8U(a8 + 0xf);  /* 0141 */
  a2 = 0x401;  /* 0144 */
  a7 = a7 - a6;  /* 0147: subx4 */
  a2 = a2 << 4;  /* 014a */
  if (a7 >= 3u) goto L_0153;  /* 014d: bgeui a7, 3, 153 <esp_mesh_mcast_cover_node+0xef> */
  L_0150: goto L_0358;  /* 0150: j */
  L_0153: a3 = (a3 >> 1) & 0x1;  /* 0153: extui width 1 */
  if (a4 != 0) goto L_015d;  /* 0156: bnez.n a4, 15d <esp_mesh_mcast_cover_node+0xf9> */
  L_0158: a2 = -1;  /* 0158 */
  if (a3 != 0) goto L_0358;  /* 015a: bnez a3, 358 <esp_mesh_mcast_cover_node+0x2f4> */
  L_015d: a6 = a6 + (14);  /* 015d */
  a8 = a8 + a6;  /* 015f */
  a2 = LD8U(a8 + 0x0);  /* 0161 */
  a6 = LD8U(a8 + 0x2);  /* 0164 */
  a7 = LD8U(a8 + 0x1);  /* 0167 */
  ST8(a1 + 0x10, a2);  /* 016a */
  ST8(a1 + 0x12, a6);  /* 016d */
  a6 = (a2 >> 8) & 0x1;  /* 0170: extui width 1 */
  ST8(a1 + 0x11, a7);  /* 0173 */
  __asm__ volatile("" ::: "memory");  /* 0176: memw */
  a2 = 0x00004011u;  /* 0179: l32r = 16401 */
  if (a6 == 7) goto L_0182;  /* 017c: beqi a6, 7, 182 <esp_mesh_mcast_cover_node+0x11e> */
  L_017f: goto L_0358;  /* 017f: j */
  L_0182: a6 = LD32(a1 + 0x10);  /* 0182 */
  a6 = (a6 >> 16) & 0x1ff;  /* 0184: extui width 9 */
  a2 = 0xaaaaaaabu;  /* 0187: l32r = -1431655765 */
  a6 = (u32)(((u64)a6 * a2) >> 32);  /* 018a: muluh */
  a2 = a8 + (3);  /* 018d */
  a7 = (a2 >> 8) & 0x1ff;  /* 018f: extui width 9 */
  ST8(a1 + 0x14, a7);  /* 0192 */
  a7 = (a2 >> 8) & 0x1ffff;  /* 0195: extui width 17 */
  a6 = a6 >> 2;  /* 0198 */
  ST8(a1 + 0x15, a7);  /* 019b */
  a7 = (a2 >> 8) & 0x1ffffff;  /* 019e: extui width 25 */
  ST8(a1 + 0x16, a7);  /* 01a1 */
  a7 = 0;  /* 01a4 */
  ST8(a1 + 0x13, a2);  /* 01a6 */
  __asm__ volatile("" ::: "memory");  /* 01a9: memw */
  ST32(a5 + 0x0, a7);  /* 01ac */
  if (a3 != a7) goto L_01bc;  /* 01ae: bne a3, a7, 1bc <esp_mesh_mcast_cover_node+0x158> */
  L_01b1: a4 = a2;  /* 01b1 */
  a7 = a2;  /* 01b3 */
  __asm__ volatile("" ::: "memory");  /* 01b5: memw */
  goto L_01f3;  /* 01b8: j */
  L_01bc: a3 = a7;  /* 01bc */
  a7 = 6;  /* 01be */
  goto L_01d6;  /* 01c0: j */
  L_01c4: a11 = a2;  /* 01c4 */
  a12 = a7;  /* 01c6 */
  a10 = a4;  /* 01c8 */
  a8 = (u32)&memcmp + 0x0;  /* 01ca: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 01cd: callx a8 (libc, via reloc-expand) */
  a2 = a2 + (6);  /* 01d0 */
  if (a10 == 0) goto L_01de;  /* 01d2: beqz.n a10, 1de <esp_mesh_mcast_cover_node+0x17a> */
  L_01d4: a3 = a3 + (1);  /* 01d4 */
  L_01d6: if ((i32)a3 < (i32)a6) goto L_01c4;  /* 01d6: blt a3, a6, 1c4 <esp_mesh_mcast_cover_node+0x160> */
  L_01d9: a2 = 0;  /* 01d9 */
  goto L_0320;  /* 01db: j */
  L_01de: a2 = 1;  /* 01de */
  goto L_0320;  /* 01e0: j */
  L_01e4: a10 = a7;  /* 01e4 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 01e6: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 01e9: callx a8 via reloc-expand */
  a7 = a7 + (6);  /* 01ec */
  if (a10 != 0) goto L_0348;  /* 01ee: bnez a10, 348 <esp_mesh_mcast_cover_node+0x2e4> */
  L_01f1: a3 = a3 + (1);  /* 01f1 */
  L_01f3: if ((i32)a3 < (i32)a6) goto L_01e4;  /* 01f3: blt a3, a6, 1e4 <esp_mesh_mcast_cover_node+0x180> */
  L_01f6: goto L_0353;  /* 01f6: j */
  L_01f9: ST32(a5 + 0x0, a7);  /* 01f9 */
  a3 = a2;  /* 01fb */
  a8 = 0;  /* 01fd */
  if (a6 == 1) goto L_0205;  /* 01ff: beqi a6, 1, 205 <esp_mesh_mcast_cover_node+0x1a1> */
  L_0202: goto L_0294;  /* 0202: j */
  L_0205: a8 = 2;  /* 0205 */
  a8 = a7 & a8;  /* 0207 */
  a2 = 0;  /* 020a */
  if (a8 != a2) goto L_0212;  /* 020c: bne a8, a2, 212 <esp_mesh_mcast_cover_node+0x1ae> */
  L_020f: goto L_0294;  /* 020f: j */
  L_0212: __asm__ volatile("" ::: "memory");  /* 0212: memw */
  goto L_0358;  /* 0215: j */
  L_0218: a10 = a3;  /* 0218 */
  ST32(a1 + 0x20, a8);  /* 021a */
  __asm__ volatile("" ::: "memory");  /* 021c: memw */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 021f: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0222: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x20);  /* 0225 */
  if (a10 == 0) goto L_0230;  /* 0227: beqz.n a10, 230 <esp_mesh_mcast_cover_node+0x1cc> */
  L_0229: a8 = a8 + (1);  /* 0229 */
  a3 = a3 + (6);  /* 022b */
  goto L_0297;  /* 022d: j */
  L_0230: a7 = (u32)&mesh_conn_mutex + 0x0;  /* 0230: l32r -> global */
  a12 = 0x17b;  /* 0233 */
  a11 = a2;  /* 0236 */
  a10 = LD32(a7 + 0x0);  /* 0238 */
  ST32(a1 + 0x20, a8);  /* 023a */
  __asm__ volatile("" ::: "memory");  /* 023c: memw */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 023f: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 0242: callx a8 via reloc-expand */
  a12 = a1 + (24);  /* 0245 */
  a11 = a1 + (28);  /* 0248 */
  a10 = a3;  /* 024b: mov */
  a8 = (u32)&esp_mesh_lookup_route + 0x0;  /* 024e: l32r -> global */
  a2 = esp_mesh_lookup_route(a2, a3, a4, a5, a6, a7);  /* 0251: callx a8 via reloc-expand */
  a10 = LD32(a7 + 0x0);  /* 0254 */
  a12 = 0x17d;  /* 0256 */
  a11 = a2;  /* 0259 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 025b: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 025e: callx a8 via reloc-expand */
  a7 = LD8U(a1 + 0x1c);  /* 0261 */
  a7 = (i32)(a7 << (32 - 7)) >> (32 - 7);  /* 0264: sext */
  a8 = LD32(a1 + 0x20);  /* 0267 */
  if ((i32)a7 < 0) goto L_0278;  /* 0269: bltz a7, 278 <esp_mesh_mcast_cover_node+0x214> */
  L_026c: a9 = (u32)&g_mesh_ext_cfg + 0x0;  /* 026c: l32r -> global */
  a9 = LD8U(a9 + 0xbd);  /* 026f */
  if ((i32)a7 >= (i32)a9) goto L_0278;  /* 0272: bge a7, a9, 278 <esp_mesh_mcast_cover_node+0x214> */
  L_0275: goto L_0339;  /* 0275: j */
  L_0278: a7 = LD8U(a1 + 0x18);  /* 0278 */
  a7 = (i32)(a7 << (32 - 7)) >> (32 - 7);  /* 027b: sext */
  if ((i32)a7 < 0) goto L_0229;  /* 027e: bltz a7, 229 <esp_mesh_mcast_cover_node+0x1c5> */
  L_0281: a9 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0281: l32r -> global */
  a9 = LD8U(a9 + 0xbd);  /* 0284 */
  if ((i32)a7 >= (i32)a9) goto L_0229;  /* 0287: bge a7, a9, 229 <esp_mesh_mcast_cover_node+0x1c5> */
  L_028a: a7 = LD16S(a1 + 0x1a);  /* 028a */
  if (a7 == -1) goto L_0229;  /* 028d: beqi a7, -1, 229 <esp_mesh_mcast_cover_node+0x1c5> */
  L_0290: goto L_0339;  /* 0290: j */
  L_0294: a2 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 0294: l32r -> .rodata.__func__$3 */
  L_0297: if ((i32)a8 >= (i32)a6) goto L_029d;  /* 0297: bge a8, a6, 29d <esp_mesh_mcast_cover_node+0x239> */
  L_029a: goto L_0218;  /* 029a: j */
  L_029d: goto L_0343;  /* 029d: j */
  L_02a1: a3 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 02a1: l32r -> .rodata.__func__$3 */
  a7 = 0;  /* 02a4 */
  ST32(a5 + 0x0, a2);  /* 02a6 */
  __asm__ volatile("" ::: "memory");  /* 02a8: memw */
  goto L_031a;  /* 02ab: j */
  L_02ae: a10 = a4;  /* 02ae */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 02b0: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 02b3: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02c1;  /* 02b6: beqz.n a10, 2c1 <esp_mesh_mcast_cover_node+0x25d> */
  L_02b8: a7 = a7 + (1);  /* 02b8 */
  a4 = a4 + (6);  /* 02ba */
  goto L_031a;  /* 02bc: j */
  L_02c1: a2 = (u32)&mesh_conn_mutex + 0x0;  /* 02c1: l32r -> global */
  a12 = 0x18c;  /* 02c4 */
  a11 = a3;  /* 02c7 */
  a10 = LD32(a2 + 0x0);  /* 02c9 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 02cb: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 02ce: callx a8 via reloc-expand */
  a12 = a1 + (24);  /* 02d1 */
  a11 = a1 + (28);  /* 02d4 */
  a10 = a4;  /* 02d7: mov */
  a8 = (u32)&esp_mesh_lookup_route + 0x0;  /* 02da: l32r -> global */
  a2 = esp_mesh_lookup_route(a2, a3, a4, a5, a6, a7);  /* 02dd: callx a8 via reloc-expand */
  a10 = LD32(a2 + 0x0);  /* 02e0 */
  a12 = 0x18e;  /* 02e2 */
  a11 = a3;  /* 02e5 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 02e7: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 02ea: callx a8 via reloc-expand */
  a2 = LD8U(a1 + 0x1c);  /* 02ed */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 02f0: sext */
  if ((i32)a2 < 0) goto L_02ff;  /* 02f3: bltz a2, 2ff <esp_mesh_mcast_cover_node+0x29b> */
  L_02f6: a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 02f6: l32r -> global */
  a8 = LD8U(a8 + 0xbd);  /* 02f9 */
  if ((i32)a2 < (i32)a8) goto L_02b8;  /* 02fc: blt a2, a8, 2b8 <esp_mesh_mcast_cover_node+0x254> */
  L_02ff: a2 = LD8U(a1 + 0x18);  /* 02ff */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 0302: sext */
  if ((i32)a2 < 0) goto L_0311;  /* 0305: bltz a2, 311 <esp_mesh_mcast_cover_node+0x2ad> */
  L_0308: a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0308: l32r -> global */
  a8 = LD8U(a8 + 0xbd);  /* 030b */
  if ((i32)a2 < (i32)a8) goto L_02b8;  /* 030e: blt a2, a8, 2b8 <esp_mesh_mcast_cover_node+0x254> */
  L_0311: a2 = LD16S(a1 + 0x1a);  /* 0311 */
  if (a2 != -1) goto L_02b8;  /* 0314: bnei a2, -1, 2b8 <esp_mesh_mcast_cover_node+0x254> */
  L_0317: goto L_032a;  /* 0317: j */
  L_031a: if ((i32)a7 < (i32)a6) goto L_02ae;  /* 031a: blt a7, a6, 2ae <esp_mesh_mcast_cover_node+0x24a> */
  L_031d: goto L_0334;  /* 031d: j */
  L_0320: ST32(a5 + 0x0, a2);  /* 0320 */
  a2 = 0;  /* 0322 */
  __asm__ volatile("" ::: "memory");  /* 0324: memw */
  goto L_0358;  /* 0327: j */
  L_032a: a3 = LD32(a5 + 0x0);  /* 032a */
  a2 = 8;  /* 032c */
  a2 = a2 | a3;  /* 032e */
  goto L_0320;  /* 0331: j */
  L_0334: a2 = LD32(a5 + 0x0);  /* 0334 */
  goto L_0320;  /* 0336: j */
  L_0339: a3 = LD32(a5 + 0x0);  /* 0339 */
  a2 = 4;  /* 033b */
  a2 = a2 | a3;  /* 033d */
  goto L_02a1;  /* 0340: j */
  L_0343: a2 = LD32(a5 + 0x0);  /* 0343 */
  goto L_02a1;  /* 0345: j */
  L_0348: a3 = LD32(a5 + 0x0);  /* 0348 */
  a7 = 2;  /* 034a */
  a7 = a7 | a3;  /* 034c */
  goto L_01f9;  /* 034f: j */
  L_0353: a7 = LD32(a5 + 0x0);  /* 0353 */
  goto L_01f9;  /* 0355: j */
  L_0358: return a2;  /* 0358: retw.n */
}


/* esp_mesh_process_bcast @ mesh_main.o 0000009c size 768B bind GLOBAL
 * Calls: esp_mesh_create_context, memcpy, memset, esp_mesh_push_to_tx_queue, esp_mesh_free_context, esp_mesh_get_child_num, is_mesh_child, esp_mesh_match_self, esp_mesh_is_my_group, esp_mesh_delivery_toSelf | indirect[8]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0xa0] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_is_root, .rodata.__func__$1
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=10, refs=17); reloc-direct=10, funcdb-attributed=0, unknown-indirect=8 */
u32 esp_mesh_process_bcast(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  float F7;
  /* 009c: entry a1, 80 (frame 80 bytes) */
  ST32(a1 + 0x20, a2);  /* 009f */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 00a1: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 00a4 */
  if (a2 != 0) goto L_00e0;  /* 00a7: bnez.n a2, e0 <esp_mesh_process_bcast+0x44> */
  L_00a9: a2 = (u32)&g_log_level + 0x0;  /* 00a9: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ac */
  a2 = 0x00004004u;  /* 00ae: l32r = 16388 */
  if (a3 >= 3u) goto L_00b7;  /* 00b1: bgeui a3, 3, b7 <esp_mesh_process_bcast+0x1b> */
  L_00b4: goto L_039a;  /* 00b4: j */
  L_00b7: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b7: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00ba */
  if (a3 == 0) goto L_039a;  /* 00bc: beqz a3, 39a <esp_mesh_process_bcast+0x2fe> */
  L_00bf: a4 = LD32(a3 + 0x150);  /* 00bf */
  if (a4 == 0) goto L_039a;  /* 00c2: beqz a4, 39a <esp_mesh_process_bcast+0x2fe> */
  L_00c5: a10 = LD32(a3 + 0x158);  /* 00c5 */
  __asm__ volatile("" ::: "memory");  /* 00c8: memw */
  /* 00cb: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ce */
  a10 = 3;  /* 00d0 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00d2: -> "mesh_main.c" */
  a14 = a11;  /* 00d5 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 00d7: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 00da: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_039a;  /* 00dd: j */
  L_00e0: a2 = 0;  /* 00e0 */
  a8 = LD32(a1 + 0x20);  /* 00e2 */
  ST32(a1 + 0x10, a2);  /* 00e4 */
  if (a8 != a2) goto L_0118;  /* 00e6: bne a8, a2, 118 <esp_mesh_process_bcast+0x7c> */
  L_00e9: a2 = (u32)&g_log_level + 0x0;  /* 00e9: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ec */
  a2 = 0x00004008u;  /* 00ee: l32r = 16392 */
  if (a3 >= 3u) goto L_00f7;  /* 00f1: bgeui a3, 3, f7 <esp_mesh_process_bcast+0x5b> */
  L_00f4: goto L_039a;  /* 00f4: j */
  L_00f7: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00f7: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00fa */
  if (a3 == 0) goto L_039a;  /* 00fc: beqz a3, 39a <esp_mesh_process_bcast+0x2fe> */
  L_00ff: a4 = LD32(a3 + 0x150);  /* 00ff */
  if (a4 == 0) goto L_039a;  /* 0102: beqz a4, 39a <esp_mesh_process_bcast+0x2fe> */
  L_0105: a10 = LD32(a3 + 0x158);  /* 0105 */
  a3 = 0x2cf;  /* 0108 */
  __asm__ volatile("" ::: "memory");  /* 010b: memw */
  /* 010e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0111: -> "mesh_main.c" */
  goto L_0144;  /* 0114: j */
  L_0118: a3 = LD32(a8 + 0x0);  /* 0118 */
  if (a3 != 0) goto L_015d;  /* 011a: bnez.n a3, 15d <esp_mesh_process_bcast+0xc1> */
  L_011c: a2 = (u32)&g_log_level + 0x0;  /* 011c: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 011f */
  a2 = 0x00004008u;  /* 0121: l32r = 16392 */
  if (a3 >= 3u) goto L_012a;  /* 0124: bgeui a3, 3, 12a <esp_mesh_process_bcast+0x8e> */
  L_0127: goto L_039a;  /* 0127: j */
  L_012a: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 012a: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 012d */
  if (a3 == 0) goto L_039a;  /* 012f: beqz a3, 39a <esp_mesh_process_bcast+0x2fe> */
  L_0132: a4 = LD32(a3 + 0x150);  /* 0132 */
  if (a4 == 0) goto L_039a;  /* 0135: beqz a4, 39a <esp_mesh_process_bcast+0x2fe> */
  L_0138: a10 = LD32(a3 + 0x158);  /* 0138 */
  a3 = 0x2d0;  /* 013b */
  /* 013e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0141: -> "mesh_main.c" */
  L_0144: a13 = a10;  /* 0144 */
  a14 = a11;  /* 0146 */
  a10 = 3;  /* 0148 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 014a: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 014d: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 0150 */
  __asm__ volatile("" ::: "memory");  /* 0152: memw */
  /* 0155: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_039a;  /* 0158: j */
  L_015d: a4 = LD8U(a8 + 0x12);  /* 015d */
  a2 = 0x00004013u;  /* 0160: l32r = 16403 */
  if (a4 < 4u) goto L_0169;  /* 0163: bltui a4, 4, 169 <esp_mesh_process_bcast+0xcd> */
  L_0166: goto L_039a;  /* 0166: j */
  L_0169: if (a4 == 1) goto L_016f;  /* 0169: beqi a4, 1, 16f <esp_mesh_process_bcast+0xd3> */
  L_016c: goto L_0209;  /* 016c: j */
  L_016f: a2 = (u32)&g_mesh_is_root + 0x0;  /* 016f: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0172: memw */
  a2 = LD8U(a2 + 0x0);  /* 0175 */
  a2 = (a2 >> 8) & 0x1;  /* 0178: extui width 1 */
  if (a2 != 0) goto L_01f4;  /* 017b: bnez a2, 1f4 <esp_mesh_process_bcast+0x158> */
  L_017e: a12 = 0x2eb;  /* 017e */
  a5 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 0181: l32r -> .rodata.__func__$1 */
  a11 = a5;  /* 0184: mov */
  a10 = LD16U(a8 + 0x4);  /* 0187 */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 018a: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 018d: callx a8 via reloc-expand */
  a4 = a10;  /* 0190 */
  ST32(a1 + 0x10, a10);  /* 0192 */
  if (a10 == 0) goto L_01f4;  /* 0194: beqz a10, 1f4 <esp_mesh_process_bcast+0x158> */
  L_0197: a12 = 44;  /* 0197 */
  a10 = a10 + (4);  /* 0199 */
  a6 = LD32(a1 + 0x20);  /* 019b */
  a11 = a6 + (4);  /* 019d */
  __asm__ volatile("" ::: "memory");  /* 019f: memw */
  a8 = (u32)&memcpy + 0x0;  /* 01a2: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 01a5: callx a8 (libc, via reloc-expand) */
  a12 = LD16U(a6 + 0x4);  /* 01a8 */
  a11 = LD32(a6 + 0x0);  /* 01ab */
  a10 = LD32(a4 + 0x0);  /* 01ad */
  a8 = (u32)&memcpy + 0x0;  /* 01af: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 01b2: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 01b5 */
  a11 = 255;  /* 01b7 */
  a4 = LD32(a1 + 0x10);  /* 01ba */
  a10 = a4 + a12;  /* 01bc */
  ST8(a4 + 0x12, a2);  /* 01be */
  __asm__ volatile("" ::: "memory");  /* 01c1: memw */
  __asm__ volatile("" ::: "memory");  /* 01c4: memw */
  a8 = (u32)&memset + 0x0;  /* 01c7: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01ca: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01cd: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01d0 */
  a10 = LD32(a4 + 0x24);  /* 01d2 */
  a2 = LD32(a2 + 0xa0);  /* 01d4 */
  /* 01d7: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 01da */
  a10 = a1 + (16);  /* 01dc */
  a8 = (u32)&esp_mesh_push_to_tx_queue + 0x0;  /* 01df: l32r -> global */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 01e2: callx a8 via reloc-expand */
  if (a10 == 0) goto L_01f4;  /* 01e5: beqz.n a10, 1f4 <esp_mesh_process_bcast+0x158> */
  L_01e7: a10 = LD32(a1 + 0x10);  /* 01e7 */
  a12 = 0x2f5;  /* 01e9 */
  a11 = a5;  /* 01ec */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 01ee: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 01f1: callx a8 via reloc-expand */
  L_01f4: a8 = (u32)&esp_mesh_get_child_num + 0x0;  /* 01f4: l32r -> global */
  a2 = esp_mesh_get_child_num(a2, a3, a4, a5, a6, a7);  /* 01f7: callx a8 via reloc-expand */
  if (a10 >= 2u) goto L_0200;  /* 01fa: bgeui a10, 2, 200 <esp_mesh_process_bcast+0x164> */
  L_01fd: goto L_02f9;  /* 01fd: j */
  L_0200: goto L_02d8;  /* 0200: j */
  L_0203: a2 = 0x00004015u;  /* 0203: l32r = 16405 */
  goto L_039a;  /* 0206: j */
  L_0209: if (a4 != 0) goto L_0244;  /* 0209: bnez.n a4, 244 <esp_mesh_process_bcast+0x1a8> */
  L_020b: a2 = a3 + (28);  /* 020b */
  a10 = a2;  /* 020e */
  a8 = (u32)&is_mesh_child + 0x0;  /* 0210: l32r -> global */
  a2 = is_mesh_child(a2, a3, a4, a5, a6, a7);  /* 0213: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0203;  /* 0216: bnez a10, 203 <esp_mesh_process_bcast+0x167> */
  L_0219: a4 = LD32(a1 + 0x20);  /* 0219 */
  a4 = LD32(a4 + 0x28);  /* 021b */
  if (((a4 >> 0) & 1) == 0) goto L_0224;  /* 021d: bbci a4, 0, 224 <esp_mesh_process_bcast+0x188> */
  L_0220: goto L_02d0;  /* 0220: j */
  L_0224: a10 = a2;  /* 0224 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0226: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0229: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02d0;  /* 022c: beqz a10, 2d0 <esp_mesh_process_bcast+0x234> */
  L_022f: goto L_0203;  /* 022f: j */
  L_0234: a10 = a3 + (22);  /* 0234 */
  a8 = (u32)&esp_mesh_is_my_group + 0x0;  /* 0237: l32r -> global */
  a2 = esp_mesh_is_my_group(a2, a3, a4, a5, a6, a7);  /* 023a: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0304;  /* 023d: bnez a10, 304 <esp_mesh_process_bcast+0x268> */
  L_0240: goto L_0203;  /* 0240: j */
  L_0244: a4 = LD32(a8 + 0x28);  /* 0244 */
  if (((a4 >> 0) & 1) != 0) goto L_024c;  /* 0246: bbsi a4, 0, 24c <esp_mesh_process_bcast+0x1b0> */
  L_0249: goto L_039a;  /* 0249: j */
  L_024c: a2 = (u32)&g_mesh_is_root + 0x0;  /* 024c: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 024f: memw */
  a2 = LD8U(a2 + 0x0);  /* 0252 */
  a2 = (a2 >> 8) & 0x1;  /* 0255: extui width 1 */
  if (a2 != 0) goto L_02d0;  /* 0258: bnez a2, 2d0 <esp_mesh_process_bcast+0x234> */
  L_025b: a12 = 0x33e;  /* 025b */
  a5 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 025e: l32r -> .rodata.__func__$1 */
  a11 = a5;  /* 0261 */
  a10 = LD16U(a8 + 0x4);  /* 0263 */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 0266: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 0269: callx a8 via reloc-expand */
  a4 = a10;  /* 026c */
  ST32(a1 + 0x10, a10);  /* 026e */
  if (a10 == 0) goto L_02d0;  /* 0270: beqz a10, 2d0 <esp_mesh_process_bcast+0x234> */
  L_0273: a12 = 44;  /* 0273 */
  a10 = a10 + (4);  /* 0275 */
  a6 = LD32(a1 + 0x20);  /* 0277 */
  a11 = a6 + (4);  /* 0279 */
  __asm__ volatile("" ::: "memory");  /* 027b: memw */
  a8 = (u32)&memcpy + 0x0;  /* 027e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0281: callx a8 (libc, via reloc-expand) */
  a12 = LD16U(a6 + 0x4);  /* 0284 */
  a11 = LD32(a6 + 0x0);  /* 0287 */
  a10 = LD32(a4 + 0x0);  /* 0289 */
  a8 = (u32)&memcpy + 0x0;  /* 028b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 028e: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0291 */
  a11 = 255;  /* 0293 */
  a4 = LD32(a1 + 0x10);  /* 0296 */
  a10 = a4 + a12;  /* 0298 */
  ST8(a4 + 0x12, a2);  /* 029a */
  __asm__ volatile("" ::: "memory");  /* 029d: memw */
  __asm__ volatile("" ::: "memory");  /* 02a0: memw */
  a8 = (u32)&memset + 0x0;  /* 02a3: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 02a6: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 02a9: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 02ac */
  a10 = LD32(a4 + 0x24);  /* 02ae */
  a2 = LD32(a2 + 0xa0);  /* 02b0 */
  /* 02b3: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 02b6 */
  a10 = a1 + (16);  /* 02b8 */
  a8 = (u32)&esp_mesh_push_to_tx_queue + 0x0;  /* 02bb: l32r -> global */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 02be: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02d0;  /* 02c1: beqz.n a10, 2d0 <esp_mesh_process_bcast+0x234> */
  L_02c3: a10 = LD32(a1 + 0x10);  /* 02c3 */
  a12 = 0x348;  /* 02c5 */
  a11 = a5;  /* 02c8 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 02ca: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 02cd: callx a8 via reloc-expand */
  L_02d0: a8 = (u32)&esp_mesh_get_child_num + 0x0;  /* 02d0: l32r -> global */
  a2 = esp_mesh_get_child_num(a2, a3, a4, a5, a6, a7);  /* 02d3: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02f9;  /* 02d6: beqz.n a10, 2f9 <esp_mesh_process_bcast+0x25d> */
  L_02d8: a10 = LD32(a1 + 0x20);  /* 02d8 */
  a2 = 1;  /* 02da */
  a12 = 6;  /* 02dc */
  a11 = 255;  /* 02df */
  ST8(a10 + 0x12, a2);  /* 02e2 */
  __asm__ volatile("" ::: "memory");  /* 02e5: memw */
  a10 = a10 + a12;  /* 02e8 */
  __asm__ volatile("" ::: "memory");  /* 02eb: memw */
  a8 = (u32)&memset + 0x0;  /* 02ee: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 02f1: callx a8 (libc, via reloc-expand) */
  goto L_0311;  /* 02f4: j */
  L_02f9: a2 = a3 + (18);  /* 02f9 */
  a2 = LD32(a2 + 0x0);  /* 02fc */
  if (((a2 >> 27) & 1) == 0) goto L_0304;  /* 02fe: bbci a2, 27, 304 <esp_mesh_process_bcast+0x268> */
  L_0301: goto L_0234;  /* 0301: j */
  L_0304: a10 = LD32(a1 + 0x20);  /* 0304 */
  a8 = (u32)&esp_mesh_delivery_toSelf;  /* 0306: l32r -> func addr */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 0309: callx a8 via reloc-expand */
  goto L_0398;  /* 030c: j */
  L_0311: a2 = a3 + (18);  /* 0311 */
  a2 = LD32(a2 + 0x0);  /* 0314 */
  if (((a2 >> 27) & 1) != 0) goto L_0338;  /* 0316: bbsi a2, 27, 338 <esp_mesh_process_bcast+0x29c> */
  L_0319: a12 = 0x364;  /* 0319 */
  a2 = LD32(a1 + 0x20);  /* 031c */
  a3 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 031e: l32r -> .rodata.__func__$1 */
  a11 = a3;  /* 0321 */
  a10 = LD16U(a2 + 0x4);  /* 0323 */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 0326: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 0329: callx a8 via reloc-expand */
  a2 = a10;  /* 032c */
  ST32(a1 + 0x10, a10);  /* 032e */
  if (a10 != 0) goto L_034a;  /* 0330: bnez.n a10, 34a <esp_mesh_process_bcast+0x2ae> */
  L_0332: __asm__ volatile("" ::: "memory");  /* 0332: memw */
  goto L_037d;  /* 0335: j */
  L_0338: a10 = a3 + (22);  /* 0338 */
  a8 = (u32)&esp_mesh_is_my_group + 0x0;  /* 033b: l32r -> global */
  a2 = esp_mesh_is_my_group(a2, a3, a4, a5, a6, a7);  /* 033e: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0319;  /* 0341: bnez a10, 319 <esp_mesh_process_bcast+0x27d> */
  L_0344: goto L_037d;  /* 0344: j */
  L_034a: a4 = LD32(a1 + 0x20);  /* 034a */
  a12 = 44;  /* 034c */
  a11 = a4 + (4);  /* 034e */
  a10 = a10 + (4);  /* 0350 */
  a8 = (u32)&memcpy + 0x0;  /* 0353: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0356: callx a8 (libc, via reloc-expand) */
  a12 = LD16U(a2 + 0x4);  /* 0359 */
  a11 = LD32(a4 + 0x0);  /* 035c */
  a10 = LD32(a2 + 0x0);  /* 035e */
  a8 = (u32)&memcpy + 0x0;  /* 0360: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0363: callx a8 (libc, via reloc-expand) */
  a10 = LD32(a1 + 0x10);  /* 0366 */
  a8 = (u32)&esp_mesh_delivery_toSelf;  /* 0368: l32r -> func addr */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 036b: callx a8 via reloc-expand */
  if (a10 == 0) goto L_037d;  /* 036e: beqz.n a10, 37d <esp_mesh_process_bcast+0x2e1> */
  L_0370: a12 = 0x36b;  /* 0370 */
  a10 = LD32(a1 + 0x10);  /* 0373 */
  a11 = a3;  /* 0375 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0377: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 037a: callx a8 via reloc-expand */
  L_037d: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 037d: l32r -> global */
  a3 = LD32(a1 + 0x20);  /* 0380 */
  a2 = LD32(a2 + 0x0);  /* 0382 */
  a10 = LD32(a3 + 0x24);  /* 0384 */
  a2 = LD32(a2 + 0xa0);  /* 0387 */
  /* 038a: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 038d */
  a10 = a1 + (32);  /* 038f */
  a8 = (u32)&esp_mesh_push_to_tx_queue + 0x0;  /* 0392: l32r -> global */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 0395: callx a8 via reloc-expand */
  L_0398: a2 = a10;  /* 0398 */
  L_039a: return a2;  /* 039a: retw.n */
}


/* esp_mesh_process_mcast @ mesh_main.o 00000048 size 310B bind GLOBAL
 * Calls: is_mesh_child, esp_mesh_match_self, esp_mesh_mcast_cover_node, esp_mesh_delivery_toSelf, mesh_process_mcast_cover_node | indirect[5]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_is_root
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=11); reloc-direct=5, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_process_mcast(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0;
  /* 0048: entry a1, 64 (frame 64 bytes) */
  a3 = a2;  /* 004b */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 004d: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0050 */
  if (a2 != 0) goto L_008d;  /* 0053: bnez.n a2, 8d <esp_mesh_process_mcast+0x45> */
  L_0055: a2 = (u32)&g_log_level + 0x0;  /* 0055: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0058 */
  a2 = 0x00004004u;  /* 005b: l32r = 16388 */
  if (a3 >= 3u) goto L_0064;  /* 005e: bgeui a3, 3, 64 <esp_mesh_process_mcast+0x1c> */
  L_0061: goto L_017c;  /* 0061: j */
  L_0064: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0064: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0067 */
  if (a3 == 0) goto L_017c;  /* 006a: beqz a3, 17c <esp_mesh_process_mcast+0x134> */
  L_006d: a4 = LD32(a3 + 0x150);  /* 006d */
  if (a4 == 0) goto L_017c;  /* 0070: beqz a4, 17c <esp_mesh_process_mcast+0x134> */
  L_0073: a10 = LD32(a3 + 0x158);  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0079 */
  a10 = 3;  /* 007b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 007d: -> "mesh_main.c" */
  a14 = a11;  /* 0080 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 0082: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 0085: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_017c;  /* 0088: j */
  L_008d: a2 = 0;  /* 008d */
  ST32(a1 + 0x10, a2);  /* 008f */
  if (a3 != a2) goto L_00c2;  /* 0091: bne a3, a2, c2 <esp_mesh_process_mcast+0x7a> */
  L_0094: a2 = (u32)&g_log_level + 0x0;  /* 0094: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0097 */
  a2 = 0x00004008u;  /* 0099: l32r = 16392 */
  if (a3 >= 3u) goto L_00a2;  /* 009c: bgeui a3, 3, a2 <esp_mesh_process_mcast+0x5a> */
  L_009f: goto L_017c;  /* 009f: j */
  L_00a2: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a2: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a5 */
  if (a3 == 0) goto L_017c;  /* 00a7: beqz a3, 17c <esp_mesh_process_mcast+0x134> */
  L_00aa: a4 = LD32(a3 + 0x150);  /* 00aa */
  if (a4 == 0) goto L_017c;  /* 00ad: beqz a4, 17c <esp_mesh_process_mcast+0x134> */
  L_00b0: a10 = LD32(a3 + 0x158);  /* 00b0 */
  a3 = 0x287;  /* 00b3 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  /* 00b9: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00bc: -> "mesh_main.c" */
  goto L_00f0;  /* 00bf: j */
  L_00c2: a8 = LD32(a3 + 0x0);  /* 00c2 */
  if (a8 != 0) goto L_0108;  /* 00c4: bnez a8, 108 <esp_mesh_process_mcast+0xc0> */
  L_00c7: a2 = (u32)&g_log_level + 0x0;  /* 00c7: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ca */
  a2 = 0x00004008u;  /* 00cc: l32r = 16392 */
  if (a3 >= 3u) goto L_00d5;  /* 00cf: bgeui a3, 3, d5 <esp_mesh_process_mcast+0x8d> */
  L_00d2: goto L_017c;  /* 00d2: j */
  L_00d5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00d5: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d8 */
  if (a3 == 0) goto L_017c;  /* 00db: beqz a3, 17c <esp_mesh_process_mcast+0x134> */
  L_00de: a4 = LD32(a3 + 0x150);  /* 00de */
  if (a4 == 0) goto L_017c;  /* 00e1: beqz a4, 17c <esp_mesh_process_mcast+0x134> */
  L_00e4: a10 = LD32(a3 + 0x158);  /* 00e4 */
  a3 = 0x288;  /* 00e7 */
  /* 00ea: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00ed: -> "mesh_main.c" */
  L_00f0: a13 = a10;  /* 00f0 */
  a14 = a11;  /* 00f2 */
  a10 = 3;  /* 00f4 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00f6: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00f9: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 00fc */
  __asm__ volatile("" ::: "memory");  /* 00fe: memw */
  /* 0101: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_017c;  /* 0104: j */
  L_0108: a9 = LD8U(a3 + 0x12);  /* 0108 */
  a2 = 0x00004013u;  /* 010b: l32r = 16403 */
  if (a9 >= 4u) goto L_017c;  /* 010e: bgeui a9, 4, 17c <esp_mesh_process_mcast+0x134> */
  L_0111: if (a9 != 0) goto L_0141;  /* 0111: bnez.n a9, 141 <esp_mesh_process_mcast+0xf9> */
  L_0113: a2 = a8 + (28);  /* 0113 */
  a10 = a2;  /* 0116 */
  a8 = (u32)&is_mesh_child + 0x0;  /* 0118: l32r -> global */
  a2 = is_mesh_child(a2, a3, a4, a5, a6, a7);  /* 011b: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0126;  /* 011e: beqz.n a10, 126 <esp_mesh_process_mcast+0xde> */
  L_0120: a2 = 0x00004015u;  /* 0120: l32r = 16405 */
  goto L_017c;  /* 0123: j */
  L_0126: a4 = LD32(a3 + 0x28);  /* 0126 */
  if (((a4 >> 0) & 1) != 0) goto L_0137;  /* 0128: bbsi a4, 0, 137 <esp_mesh_process_mcast+0xef> */
  L_012b: a10 = a2;  /* 012b: mov */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 012e: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0131: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0120;  /* 0134: bnez a10, 120 <esp_mesh_process_mcast+0xd8> */
  L_0137: a13 = a1 + (16);  /* 0137 */
  a12 = 0;  /* 013a */
  a11 = 6;  /* 013c */
  goto L_0155;  /* 013e: j */
  L_0141: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0141: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0144: memw */
  a12 = LD8U(a2 + 0x0);  /* 0147 */
  a12 = (a12 >> 8) & 0x1;  /* 014a: extui width 1 */
  if (a12 != 0) goto L_0137;  /* 014d: bnez a12, 137 <esp_mesh_process_mcast+0xef> */
  L_0150: a13 = a1 + (16);  /* 0150 */
  a11 = 14;  /* 0153 */
  L_0155: a10 = a3;  /* 0155: mov */
  a8 = (u32)&esp_mesh_mcast_cover_node;  /* 0158: l32r -> func addr */
  a2 = esp_mesh_mcast_cover_node(a2, a3, a4, a5, a6, a7);  /* 015b: callx a8 via reloc-expand */
  a11 = LD32(a1 + 0x10);  /* 015e */
  a2 = 0x0000400fu;  /* 0160: l32r = 16399 */
  if (a11 == 0) goto L_017c;  /* 0163: beqz.n a11, 17c <esp_mesh_process_mcast+0x134> */
  L_0165: a10 = a3;  /* 0165 */
  if (a11 != 2) goto L_0174;  /* 0167: bnei a11, 2, 174 <esp_mesh_process_mcast+0x12c> */
  L_016a: a8 = (u32)&esp_mesh_delivery_toSelf;  /* 016a: l32r -> func addr */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 016d: callx a8 via reloc-expand */
  goto L_017a;  /* 0170: j */
  L_0174: a8 = (u32)&mesh_process_mcast_cover_node;  /* 0174: l32r -> func addr */
  a2 = mesh_process_mcast_cover_node(a2, a3, a4, a5, a6, a7);  /* 0177: callx a8 via reloc-expand */
  L_017a: a2 = a10;  /* 017a */
  L_017c: return a2;  /* 017c: retw.n */
}


/* esp_mesh_process_options @ mesh_main.o 00000048 size 470B bind GLOBAL
 * Calls: esp_mesh_delivery_toSelf, mesh_process_mgmt_root_switch, mesh_process_mgmt_routing_table, opt_type2str | indirect[7]: mem[a3+0x158]; mem[a3+0x150]; mem[a7+0x158]; unknown | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_topology, .rodata.esp_mesh_process_options.str1.1
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=11); reloc-direct=4, funcdb-attributed=0, unknown-indirect=7 */
u32 esp_mesh_process_options(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0048: entry a1, 112 (frame 112 bytes) */
  a6 = a2;  /* 004b */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 004d: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0050 */
  if (a2 != 0) goto L_008e;  /* 0053: bnez.n a2, 8e <esp_mesh_process_options+0x46> */
  L_0055: a2 = (u32)&g_log_level + 0x0;  /* 0055: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0058 */
  a2 = 0x00004004u;  /* 005b: l32r = 16388 */
  if (a3 >= 3u) goto L_0064;  /* 005e: bgeui a3, 3, 64 <esp_mesh_process_options+0x1c> */
  L_0061: goto L_021c;  /* 0061: j */
  L_0064: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0064: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0067 */
  if (a3 == 0) goto L_021c;  /* 006a: beqz a3, 21c <esp_mesh_process_options+0x1d4> */
  L_006d: a4 = LD32(a3 + 0x150);  /* 006d */
  if (a4 == 0) goto L_021c;  /* 0070: beqz a4, 21c <esp_mesh_process_options+0x1d4> */
  L_0073: a10 = LD32(a3 + 0x158);  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0079 */
  a10 = 3;  /* 007b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 007d: -> "mesh_main.c" */
  a14 = a11;  /* 0080 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 0082: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 0085: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_021c;  /* 0088: j */
  L_008e: if (a6 != 0) goto L_00ba;  /* 008e: bnez.n a6, ba <esp_mesh_process_options+0x72> */
  L_0090: a2 = (u32)&g_log_level + 0x0;  /* 0090: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0093 */
  a2 = 0x00004008u;  /* 0095: l32r = 16392 */
  if (a3 >= 3u) goto L_009e;  /* 0098: bgeui a3, 3, 9e <esp_mesh_process_options+0x56> */
  L_009b: goto L_021c;  /* 009b: j */
  L_009e: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 009e: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a1 */
  if (a3 == 0) goto L_021c;  /* 00a3: beqz a3, 21c <esp_mesh_process_options+0x1d4> */
  L_00a6: a4 = LD32(a3 + 0x150);  /* 00a6 */
  if (a4 == 0) goto L_021c;  /* 00a9: beqz a4, 21c <esp_mesh_process_options+0x1d4> */
  L_00ac: a10 = LD32(a3 + 0x158);  /* 00ac */
  a3 = 74;  /* 00af */
  /* 00b1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00b4: -> "mesh_main.c" */
  goto L_00e7;  /* 00b7: j */
  L_00ba: a4 = LD32(a6 + 0x0);  /* 00ba */
  if (a4 != 0) goto L_0100;  /* 00bc: bnez a4, 100 <esp_mesh_process_options+0xb8> */
  L_00bf: a2 = (u32)&g_log_level + 0x0;  /* 00bf: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c2 */
  a2 = 0x00004008u;  /* 00c4: l32r = 16392 */
  if (a3 >= 3u) goto L_00cd;  /* 00c7: bgeui a3, 3, cd <esp_mesh_process_options+0x85> */
  L_00ca: goto L_021c;  /* 00ca: j */
  L_00cd: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00cd: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d0 */
  if (a3 == 0) goto L_021c;  /* 00d2: beqz a3, 21c <esp_mesh_process_options+0x1d4> */
  L_00d5: a4 = LD32(a3 + 0x150);  /* 00d5 */
  if (a4 == 0) goto L_021c;  /* 00d8: beqz a4, 21c <esp_mesh_process_options+0x1d4> */
  L_00db: a10 = LD32(a3 + 0x158);  /* 00db */
  a3 = 75;  /* 00de */
  /* 00e1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00e4: -> "mesh_main.c" */
  L_00e7: a13 = a10;  /* 00e7 */
  a14 = a11;  /* 00e9 */
  a10 = 3;  /* 00eb */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00ed: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00f0: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 00f3 */
  __asm__ volatile("" ::: "memory");  /* 00f6: memw */
  /* 00f9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_021c;  /* 00fc: j */
  L_0100: a2 = (u32)&g_mesh_topology + 0x0;  /* 0100: l32r -> global */
  a3 = 33;  /* 0103 */
  a5 = LD32(a2 + 0x0);  /* 0105 */
  a2 = 28;  /* 0107 */
  if (a5 != 0) a2 = a3;  /* 0109 */
  a5 = a4 + (18);  /* 010c */
  a3 = a2 + (14);  /* 010f */
  a7 = LD32(a5 + 0x0);  /* 0111 */
  a3 = a4 + a3;  /* 0113 */
  if (((a7 >> 24) & 1) == 0) goto L_0121;  /* 0115: bbci a7, 24, 121 <esp_mesh_process_options+0xd9> */
  L_0118: a5 = LD8U(a4 + 0xf);  /* 0118 */
  a5 = a5 - a2;  /* 011b: subx4 */
  if (a5 >= 4u) goto L_012d;  /* 011e: bgeui a5, 4, 12d <esp_mesh_process_options+0xe5> */
  L_0121: if (((a7 >> 23) & 1) == 0) goto L_0177;  /* 0121: bbci a7, 23, 177 <esp_mesh_process_options+0x12f> */
  L_0124: a5 = LD8U(a4 + 0xf);  /* 0124 */
  a2 = a5 - a2;  /* 0127: subx4 */
  if (a2 < 3u) goto L_0177;  /* 012a: bltui a2, 3, 177 <esp_mesh_process_options+0x12f> */
  L_012d: a2 = LD8U(a3 + 0x0);  /* 012d */
  if (a2 != 8) goto L_0140;  /* 0130: bnei a2, 8, 140 <esp_mesh_process_options+0xf8> */
  L_0133: a10 = a6;  /* 0133: mov */
  a8 = (u32)&esp_mesh_delivery_toSelf;  /* 0136: l32r -> func addr */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 0139: callx a8 via reloc-expand */
  goto L_0172;  /* 013c: j */
  L_0140: if (a2 != 1) goto L_0160;  /* 0140: bnei a2, 1, 160 <esp_mesh_process_options+0x118> */
  L_0143: a2 = LD8U(a3 + 0x2);  /* 0143 */
  a2 = a2 << 8;  /* 0146 */
  a5 = LD8U(a3 + 0x1);  /* 0149 */
  a2 = a2 | a5;  /* 014c */
  if (a2 != 8) goto L_0177;  /* 014f: bnei a2, 8, 177 <esp_mesh_process_options+0x12f> */
  L_0152: a11 = a3 + (3);  /* 0152 */
  a10 = a3;  /* 0154 */
  a8 = (u32)&mesh_process_mgmt_root_switch;  /* 0156: l32r -> func addr */
  a2 = mesh_process_mgmt_root_switch(a2, a3, a4, a5, a6, a7);  /* 0159: callx a8 via reloc-expand */
  goto L_0172;  /* 015c: j */
  L_0160: if (a2 != 5) goto L_0177;  /* 0160: bnei a2, 5, 177 <esp_mesh_process_options+0x12f> */
  L_0163: a13 = a6 + (12);  /* 0163 */
  a12 = a4 + (28);  /* 0165 */
  a11 = a3 + (3);  /* 0168 */
  a10 = a3;  /* 016a */
  a8 = (u32)&mesh_process_mgmt_routing_table;  /* 016c: l32r -> func addr */
  a2 = mesh_process_mgmt_routing_table(a2, a3, a4, a5, a6, a7);  /* 016f: callx a8 via reloc-expand */
  L_0172: a2 = a10;  /* 0172 */
  goto L_021c;  /* 0174: j */
  L_0177: a2 = (u32)&g_log_level + 0x0;  /* 0177: l32r -> global */
  a5 = LD32(a2 + 0x0);  /* 017a */
  a2 = 0x00004015u;  /* 017c: l32r = 16405 */
  if (a5 >= 3u) goto L_0185;  /* 017f: bgeui a5, 3, 185 <esp_mesh_process_options+0x13d> */
  L_0182: goto L_021c;  /* 0182: j */
  L_0185: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0185: l32r -> global */
  a7 = LD32(a5 + 0x0);  /* 0188 */
  if (a7 == 0) goto L_021c;  /* 018a: beqz a7, 21c <esp_mesh_process_options+0x1d4> */
  L_018d: a5 = LD32(a7 + 0x150);  /* 018d */
  if (a5 == 0) goto L_021c;  /* 0190: beqz a5, 21c <esp_mesh_process_options+0x1d4> */
  L_0193: a10 = LD32(a7 + 0x158);  /* 0193 */
  /* 0196: INDIRECT callx a10 <- mem[a7+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 0199: mov */
  a2 = LD32(a6 + 0x28);  /* 019c */
  a6 = (u32)(RODATA__rodata_esp_mesh_process_options_str1_1 + 0x0);  /* 019f: -> "xmit" */
  if (((a2 >> 0) & 1) != 0) goto L_01a8;  /* 01a2: bbsi a2, 0, 1a8 <esp_mesh_process_options+0x160> */
  L_01a5: a6 = (u32)(RODATA__rodata_esp_mesh_process_options_str1_1 + 0x0);  /* 01a5: -> "xmit" */
  L_01a8: a8 = LD8U(a4 + 0x1c);  /* 01a8 */
  a9 = LD8U(a4 + 0x1d);  /* 01ab */
  a12 = LD8U(a4 + 0x1e);  /* 01ae */
  a13 = LD8U(a4 + 0x1f);  /* 01b1 */
  a14 = LD8U(a4 + 0x20);  /* 01b4 */
  a15 = LD8U(a4 + 0x21);  /* 01b7 */
  a4 = LD8U(a3 + 0x0);  /* 01ba */
  a10 = a4;  /* 01bd */
  ST32(a1 + 0x30, a8);  /* 01bf */
  ST32(a1 + 0x34, a9);  /* 01c1 */
  ST32(a1 + 0x38, a12);  /* 01c3 */
  ST32(a1 + 0x3c, a13);  /* 01c6 */
  ST32(a1 + 0x40, a14);  /* 01c9 */
  ST32(a1 + 0x44, a15);  /* 01cc */
  __asm__ volatile("" ::: "memory");  /* 01cf: memw */
  a8 = (u32)&opt_type2str + 0x0;  /* 01d2: l32r -> global */
  a2 = opt_type2str(a2, a3, a4, a5, a6, a7);  /* 01d5: callx a8 via reloc-expand */
  a2 = LD8U(a3 + 0x1);  /* 01d8 */
  a3 = LD8U(a3 + 0x2);  /* 01db */
  a3 = a3 << 8;  /* 01de */
  a2 = a3 | a2;  /* 01e1 */
  a12 = LD32(a1 + 0x38);  /* 01e4 */
  a15 = LD32(a1 + 0x44);  /* 01e6 */
  a14 = LD32(a1 + 0x40);  /* 01e9 */
  a13 = LD32(a1 + 0x3c);  /* 01ec */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01ee: -> "mesh_main.c" */
  a9 = LD32(a1 + 0x34);  /* 01f1 */
  a8 = LD32(a1 + 0x30);  /* 01f3 */
  ST32(a1 + 0x8, a12);  /* 01f5 */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_options_str1_1 + 0x0);  /* 01f7: -> "xmit" */
  ST32(a1 + 0x20, a2);  /* 01fa */
  ST32(a1 + 0x1c, a10);  /* 01fc */
  a10 = 3;  /* 01fe */
  ST32(a1 + 0x14, a15);  /* 0200 */
  a15 = a6;  /* 0202 */
  ST32(a1 + 0x10, a14);  /* 0204 */
  a14 = a11;  /* 0206 */
  ST32(a1 + 0xc, a13);  /* 0208 */
  a13 = a7;  /* 020a */
  ST32(a1 + 0x18, a4);  /* 020c */
  ST32(a1 + 0x4, a9);  /* 020e */
  ST32(a1 + 0x0, a8);  /* 0210 */
  __asm__ volatile("" ::: "memory");  /* 0213: memw */
  /* 0216: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  a2 = 0x00004015u;  /* 0219: l32r = 16405 */
  L_021c: return a2;  /* 021c: retw.n */
}


/* esp_mesh_process_ucast @ mesh_main.o 000000d8 size 2264B bind GLOBAL
 * Calls: esp_mesh_get_parent_bssid, mesh_mutex_lock, esp_mesh_lookup_route, memcpy, mesh_mutex_unlock, esp_mesh_match_self, esp_mesh_available_txupQ_num, esp_mesh_send_block_start, memcmp, esp_mesh_process_options, esp_mesh_delivery_toSelf, esp_mesh_delivery_toDS, esp_mesh_push_to_tx_queue | indirect[17]: mem[a3+0x158]; mem[a3+0x150]; unknown; mem[a2+0x158] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, mesh_conn_mutex, .rodata.__func__$0, g_mesh_ext_cfg, g_mesh_conn, g_mesh_is_root, .rodata.esp_mesh_process_ucast.str1.1, .rodata.esp_mesh_process_options.str1.1 +4 more
 * Fidelity: medium - disasm-verified jx-free; 13 calls and 30 refs match funcdb-v3; 17 indirect sites cite driving loads; route-lookup delivery forward branches mapped
 * Edges: funcdb-v3 (calls=13, refs=29); reloc-direct=13, funcdb-attributed=0, unknown-indirect=17 */
u32 esp_mesh_process_ucast(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0000001, F5, F7;
  /* 00d8: entry a1, 208 (frame 208 bytes) */
  ST32(a1 + 0x70, a2);  /* 00db */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 00de: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 00e1 */
  if (a2 != 0) goto L_0124;  /* 00e4: bnez.n a2, 124 <esp_mesh_process_ucast+0x4c> */
  L_00e6: a2 = (u32)&g_log_level + 0x0;  /* 00e6: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00e9 */
  a2 = 0x00004004u;  /* 00ec: l32r = 16388 */
  if (a3 >= 3u) goto L_00f5;  /* 00ef: bgeui a3, 3, f5 <esp_mesh_process_ucast+0x1d> */
  L_00f2: goto L_09ae;  /* 00f2: j */
  L_00f5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00f5: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00f8 */
  if (a3 != 0) goto L_0100;  /* 00fb: bnez.n a3, 100 <esp_mesh_process_ucast+0x28> */
  L_00fd: goto L_09ae;  /* 00fd: j */
  L_0100: a4 = LD32(a3 + 0x150);  /* 0100 */
  if (a4 != 0) goto L_0108;  /* 0103: bnez.n a4, 108 <esp_mesh_process_ucast+0x30> */
  L_0105: goto L_09ae;  /* 0105: j */
  L_0108: a10 = LD32(a3 + 0x158);  /* 0108 */
  __asm__ volatile("" ::: "memory");  /* 010b: memw */
  /* 010e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0111 */
  a10 = 3;  /* 0113 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0115: -> "mesh_main.c" */
  a14 = a11;  /* 0118 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 011a: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 011d: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_09ae;  /* 0120: j */
  L_0124: a10 = LD32(a1 + 0x70);  /* 0124 */
  if (a10 != 0) goto L_015a;  /* 0127: bnez.n a10, 15a <esp_mesh_process_ucast+0x82> */
  L_0129: a2 = (u32)&g_log_level + 0x0;  /* 0129: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 012c */
  a2 = 0x00004008u;  /* 012f: l32r = 16392 */
  if (a3 >= 3u) goto L_0138;  /* 0132: bgeui a3, 3, 138 <esp_mesh_process_ucast+0x60> */
  L_0135: goto L_09ae;  /* 0135: j */
  L_0138: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0138: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 013b */
  if (a3 != 0) goto L_0143;  /* 013e: bnez.n a3, 143 <esp_mesh_process_ucast+0x6b> */
  L_0140: goto L_09ae;  /* 0140: j */
  L_0143: a4 = LD32(a3 + 0x150);  /* 0143 */
  if (a4 != 0) goto L_014b;  /* 0146: bnez.n a4, 14b <esp_mesh_process_ucast+0x73> */
  L_0148: goto L_09ae;  /* 0148: j */
  L_014b: a10 = LD32(a3 + 0x158);  /* 014b */
  a3 = 0x386;  /* 014e */
  /* 0151: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0154: -> "mesh_main.c" */
  goto L_018c;  /* 0157: j */
  L_015a: a7 = LD32(a10 + 0x0);  /* 015a */
  if (a7 != 0) goto L_01a4;  /* 015c: bnez a7, 1a4 <esp_mesh_process_ucast+0xcc> */
  L_015f: a2 = (u32)&g_log_level + 0x0;  /* 015f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0162 */
  a2 = 0x00004008u;  /* 0164: l32r = 16392 */
  if (a3 >= 3u) goto L_016d;  /* 0167: bgeui a3, 3, 16d <esp_mesh_process_ucast+0x95> */
  L_016a: goto L_09ae;  /* 016a: j */
  L_016d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 016d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0170 */
  if (a3 != 0) goto L_0178;  /* 0173: bnez.n a3, 178 <esp_mesh_process_ucast+0xa0> */
  L_0175: goto L_09ae;  /* 0175: j */
  L_0178: a4 = LD32(a3 + 0x150);  /* 0178 */
  if (a4 != 0) goto L_0180;  /* 017b: bnez.n a4, 180 <esp_mesh_process_ucast+0xa8> */
  L_017d: goto L_09ae;  /* 017d: j */
  L_0180: a10 = LD32(a3 + 0x158);  /* 0180 */
  a3 = 0x387;  /* 0183 */
  /* 0186: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0189: -> "mesh_main.c" */
  L_018c: a14 = a11;  /* 018c */
  a13 = a10;  /* 018e */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0190: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0193: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 0196 */
  L_0198: a10 = 3;  /* 0198 */
  __asm__ volatile("" ::: "memory");  /* 019a: memw */
  /* 019d: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_09ae;  /* 01a0: j */
  L_01a4: a2 = LD8U(a7 + 0xe);  /* 01a4 */
  if (((a2 >> 5) & 1) == 0) goto L_01c0;  /* 01a7: bbci a2, 5, 1c0 <esp_mesh_process_ucast+0xe8> */
  L_01aa: a2 = 0;  /* 01aa */
  a10 = a10 + (6);  /* 01ac */
  ST8(a10 + 0xc, a2);  /* 01ae */
  __asm__ volatile("" ::: "memory");  /* 01b1: memw */
  __asm__ volatile("" ::: "memory");  /* 01b4: memw */
  a8 = (u32)&esp_mesh_get_parent_bssid + 0x0;  /* 01b7: l32r -> global */
  a2 = esp_mesh_get_parent_bssid(a2, a3, a4, a5, a6, a7);  /* 01ba: callx a8 via reloc-expand */
  goto L_0281;  /* 01bd: j */
  L_01c0: a2 = LD8U(a10 + 0x12);  /* 01c0 */
  if (a2 == 1) goto L_01ce;  /* 01c3: beqi a2, 1, 1ce <esp_mesh_process_ucast+0xf6> */
  L_01c6: a3 = LD32(a10 + 0x28);  /* 01c6 */
  a3 = (a3 >> 1) & 0x1;  /* 01c8: extui width 1 */
  if (a3 == 0) goto L_02d5;  /* 01cb: beqz a3, 2d5 <esp_mesh_process_ucast+0x1fd> */
  L_01ce: a12 = 0x399;  /* 01ce */
  a2 = (u32)&mesh_conn_mutex + 0x0;  /* 01d1: l32r -> global */
  a3 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 01d4: l32r -> .rodata.__func__$0 */
  a11 = a3;  /* 01d7 */
  a10 = LD32(a2 + 0x0);  /* 01d9 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 01db: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 01de: callx a8 via reloc-expand */
  a11 = a1 + (100);  /* 01e1 */
  a12 = a1 + (96);  /* 01e4 */
  a10 = a7 + (22);  /* 01e7 */
  a8 = (u32)&esp_mesh_lookup_route + 0x0;  /* 01ea: l32r -> global */
  a2 = esp_mesh_lookup_route(a2, a3, a4, a5, a6, a7);  /* 01ed: callx a8 via reloc-expand */
  a11 = LD8U(a1 + 0x64);  /* 01f0 */
  a11 = (i32)(a11 << (32 - 7)) >> (32 - 7);  /* 01f3: sext */
  if ((i32)a11 < 0) goto L_0202;  /* 01f6: bltz a11, 202 <esp_mesh_process_ucast+0x12a> */
  L_01f9: a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 01f9: l32r -> global */
  a4 = LD8U(a4 + 0xbd);  /* 01fc */
  if ((i32)a11 < (i32)a4) goto L_021a;  /* 01ff: blt a11, a4, 21a <esp_mesh_process_ucast+0x142> */
  L_0202: a4 = LD8U(a1 + 0x60);  /* 0202 */
  a4 = (i32)(a4 << (32 - 7)) >> (32 - 7);  /* 0205: sext */
  if ((i32)a4 < 0) goto L_0286;  /* 0208: bltz a4, 286 <esp_mesh_process_ucast+0x1ae> */
  L_020b: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 020b: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 020e */
  if ((i32)a4 >= (i32)a5) goto L_0286;  /* 0211: bge a4, a5, 286 <esp_mesh_process_ucast+0x1ae> */
  L_0214: a4 = LD16S(a1 + 0x62);  /* 0214 */
  if (a4 == -1) goto L_0286;  /* 0217: beqi a4, -1, 286 <esp_mesh_process_ucast+0x1ae> */
  L_021a: a5 = 1;  /* 021a */
  a4 = LD32(a1 + 0x70);  /* 021c */
  ST8(a4 + 0x12, a5);  /* 021f */
  __asm__ volatile("" ::: "memory");  /* 0222: memw */
  if ((i32)a11 < 0) goto L_0249;  /* 0225: bltz a11, 249 <esp_mesh_process_ucast+0x171> */
  L_0228: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0228: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 022b */
  if ((i32)a11 >= (i32)a5) goto L_0249;  /* 022e: bge a11, a5, 249 <esp_mesh_process_ucast+0x171> */
  L_0231: a11 = a11 << 6;  /* 0231 */
  a12 = 6;  /* 0234 */
  a5 = (u32)&g_mesh_conn + 0x0;  /* 0237: l32r -> global */
  a10 = a4 + a12;  /* 023a */
  a11 = a5 + a11;  /* 023d */
  __asm__ volatile("" ::: "memory");  /* 0240: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0243: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0246: callx a8 (libc, via reloc-expand) */
  L_0249: a11 = LD8U(a1 + 0x60);  /* 0249 */
  a11 = (i32)(a11 << (32 - 7)) >> (32 - 7);  /* 024c: sext */
  if ((i32)a11 < 0) goto L_0274;  /* 024f: bltz a11, 274 <esp_mesh_process_ucast+0x19c> */
  L_0252: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0252: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 0255 */
  if ((i32)a11 >= (i32)a5) goto L_0274;  /* 0258: bge a11, a5, 274 <esp_mesh_process_ucast+0x19c> */
  L_025b: a5 = LD16S(a1 + 0x62);  /* 025b */
  if (a5 == -1) goto L_0274;  /* 025e: beqi a5, -1, 274 <esp_mesh_process_ucast+0x19c> */
  L_0261: a11 = a11 << 6;  /* 0261 */
  a12 = 6;  /* 0264 */
  a5 = (u32)&g_mesh_conn + 0x0;  /* 0266: l32r -> global */
  a10 = a4 + a12;  /* 0269 */
  a11 = a5 + a11;  /* 026b */
  a8 = (u32)&memcpy + 0x0;  /* 026e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0271: callx a8 (libc, via reloc-expand) */
  L_0274: a12 = 0x3ad;  /* 0274 */
  L_0277: a10 = LD32(a2 + 0x0);  /* 0277 */
  a11 = a3;  /* 0279 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 027b: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 027e: callx a8 via reloc-expand */
  L_0281: a3 = 0;  /* 0281 */
  goto L_04b0;  /* 0283: j */
  L_0286: a10 = LD32(a2 + 0x0);  /* 0286 */
  a12 = 0x3af;  /* 0288 */
  a11 = a3;  /* 028b: mov */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 028e: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 0291: callx a8 via reloc-expand */
  a2 = LD8U(a7 + 0xe);  /* 0294 */
  if (((a2 >> 4) & 1) == 0) goto L_029d;  /* 0297: bbci a2, 4, 29d <esp_mesh_process_ucast+0x1c5> */
  L_029a: goto L_04a9;  /* 029a: j */
  L_029d: a2 = (u32)&g_mesh_is_root + 0x0;  /* 029d: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 02a0: memw */
  a2 = LD8U(a2 + 0x0);  /* 02a3 */
  a2 = (a2 >> 8) & 0x1;  /* 02a6: extui width 1 */
  if (a2 == 0) goto L_02b6;  /* 02a9: beqz.n a2, 2b6 <esp_mesh_process_ucast+0x1de> */
  L_02ab: a2 = a7 + (18);  /* 02ab */
  a2 = LD32(a2 + 0x0);  /* 02ae */
  if (((a2 >> 22) & 1) == 0) goto L_02b6;  /* 02b0: bbci a2, 22, 2b6 <esp_mesh_process_ucast+0x1de> */
  L_02b3: goto L_04a9;  /* 02b3: j */
  L_02b6: a2 = 0;  /* 02b6 */
  a3 = 1;  /* 02b8 */
  a10 = LD32(a1 + 0x70);  /* 02bb */
  a10 = a10 + (6);  /* 02be */
  ST8(a10 + 0xc, a2);  /* 02c1 */
  __asm__ volatile("" ::: "memory");  /* 02c4: memw */
  __asm__ volatile("" ::: "memory");  /* 02c7: memw */
  a8 = (u32)&esp_mesh_get_parent_bssid + 0x0;  /* 02ca: l32r -> global */
  a2 = esp_mesh_get_parent_bssid(a2, a3, a4, a5, a6, a7);  /* 02cd: callx a8 via reloc-expand */
  goto L_04b0;  /* 02d0: j */
  L_02d5: if (a2 != 0) goto L_04b0;  /* 02d5: bnez a2, 4b0 <esp_mesh_process_ucast+0x3d8> */
  L_02d8: a2 = (u32)&mesh_conn_mutex + 0x0;  /* 02d8: l32r -> global */
  a12 = 0x3cd;  /* 02db */
  a3 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 02de: l32r -> .rodata.__func__$0 */
  a11 = a3;  /* 02e1 */
  a10 = LD32(a2 + 0x0);  /* 02e3 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 02e6: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 02e9: callx a8 via reloc-expand */
  a11 = a1 + (100);  /* 02ec */
  a12 = a1 + (96);  /* 02ef */
  a10 = a7 + (22);  /* 02f2 */
  a8 = (u32)&esp_mesh_lookup_route + 0x0;  /* 02f5: l32r -> global */
  a2 = esp_mesh_lookup_route(a2, a3, a4, a5, a6, a7);  /* 02f8: callx a8 via reloc-expand */
  a11 = LD8U(a1 + 0x64);  /* 02fb */
  a11 = (i32)(a11 << (32 - 7)) >> (32 - 7);  /* 02fe: sext */
  if ((i32)a11 < 0) goto L_030d;  /* 0301: bltz a11, 30d <esp_mesh_process_ucast+0x235> */
  L_0304: a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0304: l32r -> global */
  a4 = LD8U(a4 + 0xbd);  /* 0307 */
  if ((i32)a11 < (i32)a4) goto L_0325;  /* 030a: blt a11, a4, 325 <esp_mesh_process_ucast+0x24d> */
  L_030d: a4 = LD8U(a1 + 0x60);  /* 030d */
  a4 = (i32)(a4 << (32 - 7)) >> (32 - 7);  /* 0310: sext */
  if ((i32)a4 < 0) goto L_0382;  /* 0313: bltz a4, 382 <esp_mesh_process_ucast+0x2aa> */
  L_0316: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0316: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 0319 */
  if ((i32)a4 >= (i32)a5) goto L_0382;  /* 031c: bge a4, a5, 382 <esp_mesh_process_ucast+0x2aa> */
  L_031f: a4 = LD16S(a1 + 0x62);  /* 031f */
  if (a4 == -1) goto L_0382;  /* 0322: beqi a4, -1, 382 <esp_mesh_process_ucast+0x2aa> */
  L_0325: a5 = 1;  /* 0325 */
  a4 = LD32(a1 + 0x70);  /* 0327 */
  ST8(a4 + 0x12, a5);  /* 032a */
  __asm__ volatile("" ::: "memory");  /* 032d: memw */
  if ((i32)a11 < 0) goto L_0351;  /* 0330: bltz a11, 351 <esp_mesh_process_ucast+0x279> */
  L_0333: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0333: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 0336 */
  if ((i32)a11 >= (i32)a5) goto L_0351;  /* 0339: bge a11, a5, 351 <esp_mesh_process_ucast+0x279> */
  L_033c: a11 = a11 << 6;  /* 033c */
  a12 = 6;  /* 033f */
  a5 = (u32)&g_mesh_conn + 0x0;  /* 0341: l32r -> global */
  a10 = a4 + a12;  /* 0344 */
  a11 = a5 + a11;  /* 0346 */
  __asm__ volatile("" ::: "memory");  /* 0348: memw */
  a8 = (u32)&memcpy + 0x0;  /* 034b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 034e: callx a8 (libc, via reloc-expand) */
  L_0351: a11 = LD8U(a1 + 0x60);  /* 0351 */
  a11 = (i32)(a11 << (32 - 7)) >> (32 - 7);  /* 0354: sext */
  if ((i32)a11 < 0) goto L_037c;  /* 0357: bltz a11, 37c <esp_mesh_process_ucast+0x2a4> */
  L_035a: a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 035a: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 035d */
  if ((i32)a11 >= (i32)a5) goto L_037c;  /* 0360: bge a11, a5, 37c <esp_mesh_process_ucast+0x2a4> */
  L_0363: a5 = LD16S(a1 + 0x62);  /* 0363 */
  if (a5 == -1) goto L_037c;  /* 0366: beqi a5, -1, 37c <esp_mesh_process_ucast+0x2a4> */
  L_0369: a11 = a11 << 6;  /* 0369 */
  a12 = 6;  /* 036c */
  a5 = (u32)&g_mesh_conn + 0x0;  /* 036e: l32r -> global */
  a10 = a4 + a12;  /* 0371 */
  a11 = a5 + a11;  /* 0373 */
  a8 = (u32)&memcpy + 0x0;  /* 0376: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0379: callx a8 (libc, via reloc-expand) */
  L_037c: a12 = 0x3e2;  /* 037c */
  goto L_0277;  /* 037f: j */
  L_0382: a10 = LD32(a2 + 0x0);  /* 0382 */
  a11 = a3;  /* 0384 */
  a2 = a7 + (18);  /* 0386 */
  a12 = 0x3e4;  /* 0389 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 038c: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 038f: callx a8 via reloc-expand */
  a3 = LD32(a2 + 0x0);  /* 0392 */
  a2 = 0x403;  /* 0394 */
  a2 = a2 << 14;  /* 0397 */
  a3 = a3 & a2;  /* 039a */
  a2 = 1;  /* 039d */
  a2 = a2 << 24;  /* 039f */
  if (a3 == a2) goto L_03a8;  /* 03a2: beq a3, a2, 3a8 <esp_mesh_process_ucast+0x2d0> */
  L_03a5: goto L_04a9;  /* 03a5: j */
  L_03a8: a4 = a7 + (14);  /* 03a8 */
  a3 = LD32(a4 + 0x18);  /* 03aa */
  a2 = 0xf0000001u;  /* 03ac: l32r = -268435455 */
  a2 = a3 + a2;  /* 03af */
  if (a2 == 0) goto L_04a9;  /* 03b2: beqz a2, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_03b5: if (a3 == 0) goto L_04a9;  /* 03b5: beqz a3, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_03b8: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 03b8: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 03bb */
  if (a3 == 0) goto L_04a9;  /* 03be: beqz a3, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_03c1: a2 = LD32(a3 + 0x150);  /* 03c1 */
  if (a2 == 0) goto L_04a9;  /* 03c4: beqz a2, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_03c7: a10 = LD32(a3 + 0x158);  /* 03c7 */
  /* 03ca: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 03cd */
  a4 = LD32(a4 + 0x18);  /* 03cf */
  a10 = LD32(a1 + 0x70);  /* 03d1 */
  ST32(a1 + 0x74, a4);  /* 03d4 */
  a4 = LD16U(a10 + 0x4);  /* 03d7 */
  a10 = a10 + (12);  /* 03da */
  ST32(a1 + 0x78, a4);  /* 03dc */
  a4 = LD8U(a7 + 0x1c);  /* 03df */
  ST32(a1 + 0x7c, a4);  /* 03e2 */
  a4 = LD8U(a7 + 0x1d);  /* 03e5 */
  ST32(a1 + 0x80, a4);  /* 03e8 */
  a4 = LD8U(a7 + 0x1e);  /* 03eb */
  a15 = LD8U(a7 + 0x17);  /* 03ee */
  a12 = LD8U(a7 + 0x18);  /* 03f1 */
  a13 = LD8U(a7 + 0x19);  /* 03f4 */
  a14 = LD8U(a7 + 0x1a);  /* 03f7 */
  ST32(a1 + 0x84, a4);  /* 03fa */
  a4 = LD8U(a7 + 0x1f);  /* 03fd */
  a5 = LD8U(a7 + 0x21);  /* 0400 */
  a6 = LD8U(a7 + 0x16);  /* 0403 */
  ST32(a1 + 0x88, a4);  /* 0406 */
  a4 = LD8U(a7 + 0x20);  /* 0409 */
  a7 = LD8U(a7 + 0x1b);  /* 040c */
  ST32(a1 + 0x9c, a12);  /* 040f */
  ST32(a1 + 0xa0, a13);  /* 0412 */
  ST32(a1 + 0xa4, a14);  /* 0415 */
  ST32(a1 + 0x98, a15);  /* 0418 */
  __asm__ volatile("" ::: "memory");  /* 041b: memw */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 041e: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0421: callx a8 via reloc-expand */
  a9 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 0424: -> "xmitter" */
  a12 = LD32(a1 + 0x9c);  /* 0427 */
  a13 = LD32(a1 + 0xa0);  /* 042a */
  a14 = LD32(a1 + 0xa4);  /* 042d */
  a15 = LD32(a1 + 0x98);  /* 0430 */
  if (a10 != 0) goto L_0438;  /* 0433: bnez.n a10, 438 <esp_mesh_process_ucast+0x360> */
  L_0435: a9 = (u32)(RODATA__rodata_esp_mesh_process_options_str1_1 + 0x0);  /* 0435: -> "xmit" */
  L_0438: a8 = LD32(a1 + 0x70);  /* 0438 */
  a10 = LD8U(a8 + 0x11);  /* 043b */
  ST32(a1 + 0x54, a10);  /* 043e */
  a10 = LD8U(a8 + 0x10);  /* 0441 */
  ST32(a1 + 0x50, a10);  /* 0444 */
  a10 = LD8U(a8 + 0xf);  /* 0447 */
  ST32(a1 + 0x4c, a10);  /* 044a */
  a10 = LD8U(a8 + 0xe);  /* 044d */
  ST32(a1 + 0x48, a10);  /* 0450 */
  a10 = LD8U(a8 + 0xd);  /* 0453 */
  ST32(a1 + 0x44, a10);  /* 0456 */
  a10 = 2;  /* 0459 */
  a8 = LD8U(a8 + 0xc);  /* 045b */
  ST32(a1 + 0x1c, a4);  /* 045e */
  a4 = LD32(a1 + 0x88);  /* 0460 */
  ST32(a1 + 0x18, a4);  /* 0463 */
  a4 = LD32(a1 + 0x84);  /* 0465 */
  ST32(a1 + 0x14, a4);  /* 0468 */
  a4 = LD32(a1 + 0x80);  /* 046a */
  ST32(a1 + 0x10, a4);  /* 046d */
  a4 = LD32(a1 + 0x7c);  /* 046f */
  ST32(a1 + 0xc, a4);  /* 0472 */
  a4 = LD32(a1 + 0x78);  /* 0474 */
  ST32(a1 + 0x34, a14);  /* 0477 */
  ST32(a1 + 0x30, a13);  /* 0479 */
  a13 = a3;  /* 047b */
  ST32(a1 + 0x2c, a12);  /* 047d */
  ST32(a1 + 0x28, a15);  /* 047f */
  ST32(a1 + 0x40, a8);  /* 0481 */
  ST32(a1 + 0x3c, a9);  /* 0484 */
  ST32(a1 + 0x38, a7);  /* 0486 */
  ST32(a1 + 0x24, a6);  /* 0488 */
  ST32(a1 + 0x20, a5);  /* 048a */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 048c: -> "mesh_main.c" */
  a14 = a11;  /* 048f */
  ST32(a1 + 0x8, a4);  /* 0491 */
  a4 = LD32(a1 + 0x74);  /* 0493 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0496: -> "mesh_main.c" */
  ST32(a1 + 0x4, a4);  /* 0499 */
  a4 = 0x3e9;  /* 049b */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 049e: -> "xmitter" */
  ST32(a1 + 0x0, a4);  /* 04a1 */
  __asm__ volatile("" ::: "memory");  /* 04a3: memw */
  /* 04a6: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  L_04a9: a2 = 0x0000400fu;  /* 04a9: l32r = 16399 */
  goto L_09ae;  /* 04ac: j */
  L_04b0: a2 = LD32(a1 + 0x70);  /* 04b0 */
  a4 = LD32(a2 + 0x28);  /* 04b3 */
  if (((a4 >> 0) & 1) != 0) goto L_04bb;  /* 04b5: bbsi a4, 0, 4bb <esp_mesh_process_ucast+0x3e3> */
  L_04b8: goto L_05a9;  /* 04b8: j */
  L_04bb: a4 = LD8U(a7 + 0x15);  /* 04bb */
  if (((a4 >> 0) & 1) != 0) goto L_04c4;  /* 04be: bbsi a4, 0, 4c4 <esp_mesh_process_ucast+0x3ec> */
  L_04c1: goto L_05a9;  /* 04c1: j */
  L_04c4: a2 = LD8U(a2 + 0x12);  /* 04c4 */
  if (a2 != 0) goto L_05a9;  /* 04c7: bnez a2, 5a9 <esp_mesh_process_ucast+0x4d1> */
  L_04ca: a4 = (u32)&LOCAL__bss_mesh_xseqno + 0x0;  /* 04ca: l32r -> .bss.mesh_xseqno (same-object static) */
  a2 = LD32(a4 + 0x0);  /* 04cd */
  a2 = a2 + (1);  /* 04cf */
  a5 = 0x0ffffffeu;  /* 04d1: l32r = 268435454 */
  if (a5 < a2) goto L_04da;  /* 04d4: bltu a5, a2, 4da <esp_mesh_process_ucast+0x402> */
  L_04d7: goto L_04dc;  /* 04d7: j */
  L_04da: a2 = 1;  /* 04da */
  L_04dc: ST32(a4 + 0x0, a2);  /* 04dc */
  a5 = a7 + (14);  /* 04de */
  a11 = 0;  /* 04e0 */
  a2 = LD32(a4 + 0x0);  /* 04e2 */
  a10 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 04e4: l32r -> global */
  ST32(a5 + 0x18, a2);  /* 04e7 */
  __asm__ volatile("" ::: "memory");  /* 04e9: memw */
  a8 = (u32)&esp_mesh_available_txupQ_num + 0x0;  /* 04ec: l32r -> global */
  a2 = esp_mesh_available_txupQ_num(a2, a3, a4, a5, a6, a7);  /* 04ef: callx a8 via reloc-expand */
  a2 = a10;  /* 04f2 */
  if (a10 != 0) goto L_055c;  /* 04f4: bnez a10, 55c <esp_mesh_process_ucast+0x484> */
  L_04f7: a12 = LD32(a1 + 0x70);  /* 04f7 */
  if (a12 != 0) goto L_0502;  /* 04fa: bnez.n a12, 502 <esp_mesh_process_ucast+0x42a> */
  L_04fc: a2 = 0x00004012u;  /* 04fc: l32r = 16402 */
  goto L_09ae;  /* 04ff: j */
  L_0502: a3 = LD32(a12 + 0x28);  /* 0502 */
  a3 = (a3 >> 2) & 0x1;  /* 0504: extui width 1 */
  if (a3 != 1) goto L_04fc;  /* 0507: bnei a3, 1, 4fc <esp_mesh_process_ucast+0x424> */
  L_050a: a11 = a10;  /* 050a */
  a13 = 0x00004012u;  /* 050c: l32r = 16402 */
  a8 = (u32)&esp_mesh_send_block_start + 0x0;  /* 050f: l32r -> global */
  a2 = esp_mesh_send_block_start(a2, a3, a4, a5, a6, a7);  /* 0512: callx a8 via reloc-expand */
  if (a10 == 0) goto L_04fc;  /* 0515: beqz a10, 4fc <esp_mesh_process_ucast+0x424> */
  L_0518: a2 = (u32)&g_log_level + 0x0;  /* 0518: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 051b */
  if (a2 < 3u) goto L_054c;  /* 051d: bltui a2, 3, 54c <esp_mesh_process_ucast+0x474> */
  L_0520: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0520: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0523 */
  if (a2 == 0) goto L_054c;  /* 0525: beqz.n a2, 54c <esp_mesh_process_ucast+0x474> */
  L_0527: a3 = LD32(a2 + 0x150);  /* 0527 */
  if (a3 == 0) goto L_054c;  /* 052a: beqz.n a3, 54c <esp_mesh_process_ucast+0x474> */
  L_052c: a10 = LD32(a2 + 0x158);  /* 052c */
  /* 052f: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0532 */
  a15 = 0x3ff;  /* 0534 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0537: -> "mesh_main.c" */
  a10 = 3;  /* 053a */
  a14 = a11;  /* 053c */
  a2 = LD32(a5 + 0x18);  /* 053e */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 0540: -> "xmitter" */
  ST32(a1 + 0x0, a2);  /* 0543 */
  __asm__ volatile("" ::: "memory");  /* 0546: memw */
  /* 0549: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_054c: a2 = LD32(a4 + 0x0);  /* 054c */
  a2 = a2 + (-1);  /* 054e */
  ST32(a4 + 0x0, a2);  /* 0550 */
  a2 = -1;  /* 0552 */
  __asm__ volatile("" ::: "memory");  /* 0554: memw */
  goto L_09ae;  /* 0557: j */
  L_055c: a5 = 0x00004004u;  /* 055c: l32r = 16388 */
  if (a10 != a5) goto L_05a9;  /* 055f: bne a10, a5, 5a9 <esp_mesh_process_ucast+0x4d1> */
  L_0562: a3 = LD32(a4 + 0x0);  /* 0562 */
  a3 = a3 + (-1);  /* 0564 */
  ST32(a4 + 0x0, a3);  /* 0566 */
  a3 = (u32)&g_log_level + 0x0;  /* 0568: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 056b */
  if (a3 >= 3u) goto L_0573;  /* 056d: bgeui a3, 3, 573 <esp_mesh_process_ucast+0x49b> */
  L_0570: goto L_09ae;  /* 0570: j */
  L_0573: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0573: l32r -> global */
  a3 = LD32(a5 + 0x0);  /* 0576 */
  if (a3 == 0) goto L_09ae;  /* 0578: beqz a3, 9ae <esp_mesh_process_ucast+0x8d6> */
  L_057b: a4 = LD32(a3 + 0x150);  /* 057b */
  if (a4 == 0) goto L_09ae;  /* 057e: beqz a4, 9ae <esp_mesh_process_ucast+0x8d6> */
  L_0581: a10 = LD32(a3 + 0x158);  /* 0581 */
  __asm__ volatile("" ::: "memory");  /* 0584: memw */
  /* 0587: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 058a */
  a5 = LD32(a5 + 0x0);  /* 058c */
  a10 = LD32(a5 + 0xb8);  /* 058e */
  /* 0591: INDIRECT callx a10 <- mem[a5+0xb8]; result unknown */ a2 = 0;
  a15 = 0x408;  /* 0594 */
  a13 = a3;  /* 0597 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0599: -> "mesh_main.c" */
  a14 = a11;  /* 059c */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 059e: -> "xmitter" */
  ST32(a1 + 0x0, a10);  /* 05a1 */
  __asm__ volatile("" ::: "memory");  /* 05a3: memw */
  goto L_0198;  /* 05a6: j */
  L_05a9: a6 = (u32)&g_mesh_is_root + 0x0;  /* 05a9: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 05ac: memw */
  a2 = LD8U(a6 + 0x0);  /* 05af */
  a2 = (a2 >> 8) & 0x1;  /* 05b2: extui width 1 */
  a4 = LD32(a1 + 0x70);  /* 05b5 */
  if (a2 == 0) goto L_0994;  /* 05b8: beqz a2, 994 <esp_mesh_process_ucast+0x8bc> */
  L_05bb: a5 = LD8U(a4 + 0x12);  /* 05bb */
  if (a5 != 0) goto L_0994;  /* 05be: bnez a5, 994 <esp_mesh_process_ucast+0x8bc> */
  L_05c1: a2 = a7 + (18);  /* 05c1 */
  a2 = LD32(a2 + 0x0);  /* 05c4 */
  if (((a2 >> 22) & 1) != 0) goto L_05cc;  /* 05c6: bbsi a2, 22, 5cc <esp_mesh_process_ucast+0x4f4> */
  L_05c9: goto L_0988;  /* 05c9: j */
  L_05cc: if (a3 == 0) goto L_06f8;  /* 05cc: beqz a3, 6f8 <esp_mesh_process_ucast+0x620> */
  L_05cf: a3 = 0x403;  /* 05cf */
  a3 = a3 << 14;  /* 05d2 */
  a4 = 1;  /* 05d5 */
  a3 = a2 & a3;  /* 05d7 */
  a4 = a4 << 24;  /* 05da */
  a2 = 1;  /* 05dd */
  if (a3 == a4) goto L_05e5;  /* 05df: beq a3, a4, 5e5 <esp_mesh_process_ucast+0x50d> */
  L_05e2: goto L_04a9;  /* 05e2: j */
  L_05e5: a4 = a7 + (14);  /* 05e5 */
  a3 = LD32(a4 + 0x18);  /* 05e7 */
  a6 = a5;  /* 05e9 */
  if (a3 != 0) a6 = a2;  /* 05eb */
  if (a6 == 0) goto L_04a9;  /* 05ee: beqz a6, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_05f1: a6 = 0xf0000001u;  /* 05f1: l32r = -268435455 */
  a3 = a3 + a6;  /* 05f4 */
  if (a3 == 0) a2 = a5;  /* 05f6 */
  if (a2 == 0) goto L_04a9;  /* 05f9: beqz a2, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_05fc: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 05fc: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 05ff */
  if (a2 == 0) goto L_04a9;  /* 0601: beqz a2, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_0604: a3 = LD32(a2 + 0x150);  /* 0604 */
  if (a3 == 0) goto L_04a9;  /* 0607: beqz a3, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_060a: a10 = LD32(a2 + 0x158);  /* 060a */
  /* 060d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 0610 */
  a10 = LD32(a1 + 0x70);  /* 0612 */
  a4 = LD32(a4 + 0x18);  /* 0615 */
  a2 = LD16U(a10 + 0x4);  /* 0617 */
  a10 = a10 + (12);  /* 061a */
  ST32(a1 + 0x74, a4);  /* 061c */
  ST32(a1 + 0x78, a2);  /* 061f */
  a4 = LD8U(a7 + 0x1c);  /* 0622 */
  a2 = LD8U(a7 + 0x1d);  /* 0625 */
  a8 = LD8U(a7 + 0x21);  /* 0628 */
  a9 = LD8U(a7 + 0x16);  /* 062b */
  a12 = LD8U(a7 + 0x17);  /* 062e */
  a13 = LD8U(a7 + 0x18);  /* 0631 */
  a14 = LD8U(a7 + 0x19);  /* 0634 */
  a15 = LD8U(a7 + 0x1a);  /* 0637 */
  ST32(a1 + 0x7c, a4);  /* 063a */
  ST32(a1 + 0x80, a2);  /* 063d */
  a4 = LD8U(a7 + 0x1e);  /* 0640 */
  a2 = LD8U(a7 + 0x1f);  /* 0643 */
  a6 = LD8U(a7 + 0x20);  /* 0646 */
  ST32(a1 + 0x84, a4);  /* 0649 */
  a7 = LD8U(a7 + 0x1b);  /* 064c */
  ST32(a1 + 0x88, a2);  /* 064f */
  ST32(a1 + 0x90, a8);  /* 0652 */
  ST32(a1 + 0x94, a9);  /* 0655 */
  ST32(a1 + 0x9c, a12);  /* 0658 */
  ST32(a1 + 0xa0, a13);  /* 065b */
  ST32(a1 + 0xa4, a14);  /* 065e */
  ST32(a1 + 0x98, a15);  /* 0661 */
  __asm__ volatile("" ::: "memory");  /* 0664: memw */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0667: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 066a: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x90);  /* 066d */
  a4 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 0670: -> "xmitter" */
  a9 = LD32(a1 + 0x94);  /* 0673 */
  a12 = LD32(a1 + 0x9c);  /* 0676 */
  a13 = LD32(a1 + 0xa0);  /* 0679 */
  a14 = LD32(a1 + 0xa4);  /* 067c */
  a15 = LD32(a1 + 0x98);  /* 067f */
  if (a10 != 0) goto L_0688;  /* 0682: bnez a10, 688 <esp_mesh_process_ucast+0x5b0> */
  L_0685: a4 = (u32)(RODATA__rodata_esp_mesh_process_options_str1_1 + 0x0);  /* 0685: -> "xmit" */
  L_0688: a2 = LD32(a1 + 0x70);  /* 0688 */
  a10 = LD8U(a2 + 0x11);  /* 068b */
  ST32(a1 + 0x54, a10);  /* 068e */
  a10 = LD8U(a2 + 0x10);  /* 0691 */
  ST32(a1 + 0x50, a10);  /* 0694 */
  a10 = LD8U(a2 + 0xf);  /* 0697 */
  ST32(a1 + 0x4c, a10);  /* 069a */
  a10 = LD8U(a2 + 0xe);  /* 069d */
  ST32(a1 + 0x48, a10);  /* 06a0 */
  a10 = LD8U(a2 + 0xd);  /* 06a3 */
  ST32(a1 + 0x44, a10);  /* 06a6 */
  a2 = LD8U(a2 + 0xc);  /* 06a9 */
  ST32(a1 + 0x3c, a4);  /* 06ac */
  a4 = LD32(a1 + 0x88);  /* 06ae */
  ST32(a1 + 0x40, a2);  /* 06b1 */
  a2 = LD32(a1 + 0x84);  /* 06b4 */
  ST32(a1 + 0x18, a4);  /* 06b7 */
  a4 = LD32(a1 + 0x80);  /* 06b9 */
  ST32(a1 + 0x14, a2);  /* 06bc */
  a2 = LD32(a1 + 0x7c);  /* 06be */
  ST32(a1 + 0x10, a4);  /* 06c1 */
  a4 = LD32(a1 + 0x78);  /* 06c3 */
  ST32(a1 + 0x34, a15);  /* 06c6 */
  ST32(a1 + 0x30, a14);  /* 06c8 */
  ST32(a1 + 0x2c, a13);  /* 06ca */
  a13 = a5;  /* 06cc */
  ST32(a1 + 0x28, a12);  /* 06ce */
  ST32(a1 + 0xc, a2);  /* 06d0 */
  ST32(a1 + 0x38, a7);  /* 06d2 */
  ST32(a1 + 0x24, a9);  /* 06d4 */
  ST32(a1 + 0x20, a8);  /* 06d6 */
  ST32(a1 + 0x1c, a6);  /* 06d8 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 06da: -> "mesh_main.c" */
  a14 = a11;  /* 06dd */
  ST32(a1 + 0x8, a4);  /* 06df */
  a2 = LD32(a1 + 0x74);  /* 06e1 */
  ST32(a1 + 0x4, a2);  /* 06e4 */
  a2 = 0x41a;  /* 06e6 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 06e9: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 06ec: -> "xmitter" */
  ST32(a1 + 0x0, a2);  /* 06ef */
  __asm__ volatile("" ::: "memory");  /* 06f1: memw */
  goto L_097b;  /* 06f4: j */
  L_06f8: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 06f8: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 06fb */
  a10 = a7 + (22);  /* 06fd */
  a8 = (u32)&memcmp + 0x0;  /* 0700: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0703: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_085d;  /* 0706: bnez a10, 85d <esp_mesh_process_ucast+0x785> */
  L_0709: __asm__ volatile("" ::: "memory");  /* 0709: memw */
  a3 = LD8U(a6 + 0x0);  /* 070c */
  a3 = (a3 >> 8) & 0x1;  /* 070f: extui width 1 */
  if (a3 == 0) goto L_085d;  /* 0712: beqz a3, 85d <esp_mesh_process_ucast+0x785> */
  L_0715: if (((a2 >> 24) & 1) == 0) goto L_072d;  /* 0715: bbci a2, 24, 72d <esp_mesh_process_ucast+0x655> */
  L_0718: a5 = (u32)&g_mesh_topology + 0x0;  /* 0718: l32r -> global */
  a6 = 33;  /* 071b */
  a8 = LD32(a5 + 0x0);  /* 071d */
  a5 = 28;  /* 071f */
  if (a8 != 0) a5 = a6;  /* 0721 */
  a3 = LD8U(a7 + 0xf);  /* 0724 */
  a3 = a3 - a5;  /* 0727: subx4 */
  if (a3 >= 4u) goto L_0745;  /* 072a: bgeui a3, 4, 745 <esp_mesh_process_ucast+0x66d> */
  L_072d: if (((a2 >> 23) & 1) == 0) goto L_0750;  /* 072d: bbci a2, 23, 750 <esp_mesh_process_ucast+0x678> */
  L_0730: a3 = (u32)&g_mesh_topology + 0x0;  /* 0730: l32r -> global */
  a5 = 33;  /* 0733 */
  a6 = LD32(a3 + 0x0);  /* 0735 */
  a3 = 28;  /* 0737 */
  if (a6 != 0) a3 = a5;  /* 0739 */
  a2 = LD8U(a7 + 0xf);  /* 073c */
  a2 = a2 - a3;  /* 073f: subx4 */
  if (a2 < 3u) goto L_0750;  /* 0742: bltui a2, 3, 750 <esp_mesh_process_ucast+0x678> */
  L_0745: a10 = a4;  /* 0745 */
  a8 = (u32)&esp_mesh_process_options;  /* 0747: l32r -> func addr */
  a2 = esp_mesh_process_options(a2, a3, a4, a5, a6, a7);  /* 074a: callx a8 via reloc-expand */
  goto L_09ac;  /* 074d: j */
  L_0750: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0750: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0753 */
  if (a2 == 0) goto L_0851;  /* 0755: beqz a2, 851 <esp_mesh_process_ucast+0x779> */
  L_0758: a3 = LD32(a2 + 0x150);  /* 0758 */
  if (a3 == 0) goto L_0851;  /* 075b: beqz a3, 851 <esp_mesh_process_ucast+0x779> */
  L_075e: a10 = LD32(a2 + 0x158);  /* 075e */
  a2 = a7 + (14);  /* 0761 */
  /* 0763: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 0766 */
  a10 = LD32(a1 + 0x70);  /* 0768 */
  a2 = LD32(a2 + 0x18);  /* 076b */
  a4 = LD16U(a10 + 0x4);  /* 076e */
  a10 = a10 + (12);  /* 0771 */
  ST32(a1 + 0x74, a2);  /* 0774 */
  ST32(a1 + 0x78, a4);  /* 0777 */
  a2 = LD8U(a7 + 0x1c);  /* 077a */
  a4 = LD8U(a7 + 0x1d);  /* 077d */
  a8 = LD8U(a7 + 0x21);  /* 0780 */
  a9 = LD8U(a7 + 0x16);  /* 0783 */
  a12 = LD8U(a7 + 0x17);  /* 0786 */
  a13 = LD8U(a7 + 0x18);  /* 0789 */
  a14 = LD8U(a7 + 0x19);  /* 078c */
  a15 = LD8U(a7 + 0x1a);  /* 078f */
  ST32(a1 + 0x7c, a2);  /* 0792 */
  ST32(a1 + 0x80, a4);  /* 0795 */
  a2 = LD8U(a7 + 0x1e);  /* 0798 */
  a4 = LD8U(a7 + 0x1f);  /* 079b */
  a6 = LD8U(a7 + 0x20);  /* 079e */
  ST32(a1 + 0x88, a4);  /* 07a1 */
  a7 = LD8U(a7 + 0x1b);  /* 07a4 */
  ST32(a1 + 0x84, a2);  /* 07a7 */
  ST32(a1 + 0x90, a8);  /* 07aa */
  ST32(a1 + 0x94, a9);  /* 07ad */
  ST32(a1 + 0x9c, a12);  /* 07b0 */
  ST32(a1 + 0xa0, a13);  /* 07b3 */
  ST32(a1 + 0xa4, a14);  /* 07b6 */
  ST32(a1 + 0x98, a15);  /* 07b9 */
  __asm__ volatile("" ::: "memory");  /* 07bc: memw */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 07bf: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 07c2: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x90);  /* 07c5 */
  a4 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 07c8: -> "xmitter" */
  a9 = LD32(a1 + 0x94);  /* 07cb */
  a12 = LD32(a1 + 0x9c);  /* 07ce */
  a13 = LD32(a1 + 0xa0);  /* 07d1 */
  a14 = LD32(a1 + 0xa4);  /* 07d4 */
  a15 = LD32(a1 + 0x98);  /* 07d7 */
  if (a10 != 0) goto L_07e0;  /* 07da: bnez a10, 7e0 <esp_mesh_process_ucast+0x708> */
  L_07dd: a4 = (u32)(RODATA__rodata_esp_mesh_process_options_str1_1 + 0x0);  /* 07dd: -> "xmit" */
  L_07e0: a2 = LD32(a1 + 0x70);  /* 07e0 */
  a10 = LD8U(a2 + 0x11);  /* 07e3 */
  ST32(a1 + 0x54, a10);  /* 07e6 */
  a10 = LD8U(a2 + 0x10);  /* 07e9 */
  ST32(a1 + 0x50, a10);  /* 07ec */
  a10 = LD8U(a2 + 0xf);  /* 07ef */
  ST32(a1 + 0x4c, a10);  /* 07f2 */
  a10 = LD8U(a2 + 0xe);  /* 07f5 */
  ST32(a1 + 0x48, a10);  /* 07f8 */
  a10 = LD8U(a2 + 0xd);  /* 07fb */
  ST32(a1 + 0x44, a10);  /* 07fe */
  a10 = 2;  /* 0801 */
  a2 = LD8U(a2 + 0xc);  /* 0803 */
  ST32(a1 + 0x40, a2);  /* 0806 */
  a2 = LD32(a1 + 0x88);  /* 0809 */
  ST32(a1 + 0x3c, a4);  /* 080c */
  a4 = LD32(a1 + 0x84);  /* 080e */
  ST32(a1 + 0x18, a2);  /* 0811 */
  a2 = LD32(a1 + 0x80);  /* 0813 */
  ST32(a1 + 0x14, a4);  /* 0816 */
  a4 = LD32(a1 + 0x7c);  /* 0818 */
  ST32(a1 + 0x10, a2);  /* 081b */
  a2 = LD32(a1 + 0x78);  /* 081d */
  ST32(a1 + 0x34, a15);  /* 0820 */
  ST32(a1 + 0x30, a14);  /* 0822 */
  ST32(a1 + 0x2c, a13);  /* 0824 */
  a13 = a5;  /* 0826 */
  ST32(a1 + 0x28, a12);  /* 0828 */
  ST32(a1 + 0xc, a4);  /* 082a */
  ST32(a1 + 0x38, a7);  /* 082c */
  ST32(a1 + 0x24, a9);  /* 082e */
  ST32(a1 + 0x20, a8);  /* 0830 */
  ST32(a1 + 0x1c, a6);  /* 0832 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0834: -> "mesh_main.c" */
  a14 = a11;  /* 0837 */
  ST32(a1 + 0x8, a2);  /* 0839 */
  a2 = 0x432;  /* 083b */
  a4 = LD32(a1 + 0x74);  /* 083e */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0841: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 0844: -> "xmitter" */
  ST32(a1 + 0x4, a4);  /* 0847 */
  ST32(a1 + 0x0, a2);  /* 0849 */
  __asm__ volatile("" ::: "memory");  /* 084b: memw */
  /* 084e: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  L_0851: a10 = LD32(a1 + 0x70);  /* 0851 */
  a8 = (u32)&esp_mesh_delivery_toSelf;  /* 0854: l32r -> func addr */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 0857: callx a8 via reloc-expand */
  goto L_09ac;  /* 085a: j */
  L_085d: a3 = 0x403;  /* 085d */
  a3 = a3 << 14;  /* 0860 */
  a2 = a2 & a3;  /* 0863 */
  a3 = 1;  /* 0866 */
  a3 = a3 << 24;  /* 0868 */
  if (a2 == a3) goto L_0871;  /* 086b: beq a2, a3, 871 <esp_mesh_process_ucast+0x799> */
  L_086e: goto L_04a9;  /* 086e: j */
  L_0871: a4 = a7 + (14);  /* 0871 */
  a2 = LD32(a4 + 0x18);  /* 0873 */
  if (a2 == 0) goto L_04a9;  /* 0875: beqz a2, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_0878: a3 = 0xf0000001u;  /* 0878: l32r = -268435455 */
  a2 = a2 + a3;  /* 087b */
  if (a2 == 0) goto L_04a9;  /* 087d: beqz a2, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_0880: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0880: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0883 */
  if (a2 == 0) goto L_04a9;  /* 0885: beqz a2, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_0888: a3 = LD32(a2 + 0x150);  /* 0888 */
  if (a3 == 0) goto L_04a9;  /* 088b: beqz a3, 4a9 <esp_mesh_process_ucast+0x3d1> */
  L_088e: a10 = LD32(a2 + 0x158);  /* 088e */
  /* 0891: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 0894 */
  a4 = LD32(a4 + 0x18);  /* 0896 */
  a10 = LD32(a1 + 0x70);  /* 0898 */
  ST32(a1 + 0x74, a4);  /* 089b */
  a2 = LD16U(a10 + 0x4);  /* 089e */
  a10 = a10 + (12);  /* 08a1 */
  a4 = LD8U(a7 + 0x1c);  /* 08a3 */
  ST32(a1 + 0x78, a2);  /* 08a6 */
  ST32(a1 + 0x7c, a4);  /* 08a9 */
  a2 = LD8U(a7 + 0x1d);  /* 08ac */
  a4 = LD8U(a7 + 0x1e);  /* 08af */
  a9 = LD8U(a7 + 0x16);  /* 08b2 */
  a12 = LD8U(a7 + 0x17);  /* 08b5 */
  a13 = LD8U(a7 + 0x18);  /* 08b8 */
  a14 = LD8U(a7 + 0x19);  /* 08bb */
  a15 = LD8U(a7 + 0x1a);  /* 08be */
  a8 = LD8U(a7 + 0x1b);  /* 08c1 */
  ST32(a1 + 0x80, a2);  /* 08c4 */
  ST32(a1 + 0x84, a4);  /* 08c7 */
  a2 = LD8U(a7 + 0x1f);  /* 08ca */
  a4 = LD8U(a7 + 0x21);  /* 08cd */
  a6 = LD8U(a7 + 0x20);  /* 08d0 */
  ST32(a1 + 0x8c, a4);  /* 08d3 */
  ST32(a1 + 0x90, a8);  /* 08d6 */
  ST32(a1 + 0x94, a9);  /* 08d9 */
  ST32(a1 + 0x9c, a12);  /* 08dc */
  ST32(a1 + 0xa0, a13);  /* 08df */
  ST32(a1 + 0xa4, a14);  /* 08e2 */
  ST32(a1 + 0x98, a15);  /* 08e5 */
  ST32(a1 + 0x88, a2);  /* 08e8 */
  __asm__ volatile("" ::: "memory");  /* 08eb: memw */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 08ee: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 08f1: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x90);  /* 08f4 */
  a4 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 08f7: -> "xmitter" */
  a9 = LD32(a1 + 0x94);  /* 08fa */
  a12 = LD32(a1 + 0x9c);  /* 08fd */
  a13 = LD32(a1 + 0xa0);  /* 0900 */
  a14 = LD32(a1 + 0xa4);  /* 0903 */
  a15 = LD32(a1 + 0x98);  /* 0906 */
  if (a10 != 0) goto L_090e;  /* 0909: bnez.n a10, 90e <esp_mesh_process_ucast+0x836> */
  L_090b: a4 = (u32)(RODATA__rodata_esp_mesh_process_options_str1_1 + 0x0);  /* 090b: -> "xmit" */
  L_090e: a2 = LD32(a1 + 0x70);  /* 090e */
  a10 = LD8U(a2 + 0x11);  /* 0911 */
  ST32(a1 + 0x54, a10);  /* 0914 */
  a10 = LD8U(a2 + 0x10);  /* 0917 */
  ST32(a1 + 0x50, a10);  /* 091a */
  a10 = LD8U(a2 + 0xf);  /* 091d */
  ST32(a1 + 0x4c, a10);  /* 0920 */
  a10 = LD8U(a2 + 0xe);  /* 0923 */
  ST32(a1 + 0x48, a10);  /* 0926 */
  a10 = LD8U(a2 + 0xd);  /* 0929 */
  ST32(a1 + 0x44, a10);  /* 092c */
  a2 = LD8U(a2 + 0xc);  /* 092f */
  ST32(a1 + 0x40, a2);  /* 0932 */
  a2 = LD32(a1 + 0x8c);  /* 0935 */
  ST32(a1 + 0x3c, a4);  /* 0938 */
  ST32(a1 + 0x20, a2);  /* 093a */
  a4 = LD32(a1 + 0x88);  /* 093c */
  a2 = LD32(a1 + 0x84);  /* 093f */
  ST32(a1 + 0x18, a4);  /* 0942 */
  ST32(a1 + 0x14, a2);  /* 0944 */
  a4 = LD32(a1 + 0x80);  /* 0946 */
  a2 = LD32(a1 + 0x7c);  /* 0949 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 094c: -> "mesh_main.c" */
  ST32(a1 + 0x34, a15);  /* 094f */
  ST32(a1 + 0x30, a14);  /* 0951 */
  a14 = a11;  /* 0953 */
  ST32(a1 + 0x2c, a13);  /* 0955 */
  a13 = a5;  /* 0957 */
  ST32(a1 + 0x28, a12);  /* 0959 */
  ST32(a1 + 0xc, a2);  /* 095b */
  ST32(a1 + 0x38, a8);  /* 095d */
  ST32(a1 + 0x24, a9);  /* 095f */
  ST32(a1 + 0x1c, a6);  /* 0961 */
  ST32(a1 + 0x10, a4);  /* 0963 */
  a4 = LD32(a1 + 0x78);  /* 0965 */
  a2 = LD32(a1 + 0x74);  /* 0968 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 096b: -> "mesh_main.c" */
  ST32(a1 + 0x4, a2);  /* 096e */
  a2 = 0x439;  /* 0970 */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_ucast_str1_1 + 0x0);  /* 0973: -> "xmitter" */
  ST32(a1 + 0x8, a4);  /* 0976 */
  ST32(a1 + 0x0, a2);  /* 0978 */
  L_097b: a10 = 2;  /* 097b */
  __asm__ volatile("" ::: "memory");  /* 097e: memw */
  /* 0981: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  goto L_04a9;  /* 0984: j */
  L_0988: a10 = a4;  /* 0988 */
  a8 = (u32)&esp_mesh_delivery_toDS;  /* 098a: l32r -> func addr */
  a2 = esp_mesh_delivery_toDS(a2, a3, a4, a5, a6, a7);  /* 098d: callx a8 via reloc-expand */
  goto L_09ac;  /* 0990: j */
  L_0994: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0994: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0997 */
  a10 = LD32(a4 + 0x24);  /* 0999 */
  a2 = LD32(a2 + 0xa0);  /* 099b */
  /* 099e: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 09a1 */
  a10 = a1 + (112);  /* 09a3 */
  a8 = (u32)&esp_mesh_push_to_tx_queue + 0x0;  /* 09a6: l32r -> global */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 09a9: callx a8 via reloc-expand */
  L_09ac: a2 = a10;  /* 09ac */
  L_09ae: return a2;  /* 09ae: retw.n */
}


/* mesh_process_mcast_cover_node @ mesh_main.o 00000098 size 1062B bind GLOBAL
 * Calls: esp_mesh_get_optlen, esp_mesh_create_context, memcpy, mesh_remove_myself_from_forwarding, esp_mesh_delivery_toSelf, esp_mesh_free_context, esp_mesh_push_to_tx_queue | indirect[8]: mem[a3+0x158]; mem[a3+0x150]; mem[a4+0xa0]; mem[a3+0xa0] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_is_root, g_mesh_topology, .rodata.__func__$2
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=7, refs=15); reloc-direct=7, funcdb-attributed=0, unknown-indirect=8 */
u32 mesh_process_mcast_cover_node(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F4;
  /* 0098: entry a1, 96 (frame 96 bytes) */
  ST32(a1 + 0x20, a2);  /* 009b */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 009d: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 00a0 */
  if (a2 != 0) goto L_00dd;  /* 00a3: bnez.n a2, dd <mesh_process_mcast_cover_node+0x45> */
  L_00a5: a2 = (u32)&g_log_level + 0x0;  /* 00a5: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00a8 */
  a2 = 0x00004004u;  /* 00aa: l32r = 16388 */
  if (a3 >= 3u) goto L_00b3;  /* 00ad: bgeui a3, 3, b3 <mesh_process_mcast_cover_node+0x1b> */
  L_00b0: goto L_04bc;  /* 00b0: j */
  L_00b3: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b3: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00b6 */
  if (a3 == 0) goto L_04bc;  /* 00b8: beqz a3, 4bc <mesh_process_mcast_cover_node+0x424> */
  L_00bb: a4 = LD32(a3 + 0x150);  /* 00bb */
  if (a4 == 0) goto L_04bc;  /* 00be: beqz a4, 4bc <mesh_process_mcast_cover_node+0x424> */
  L_00c1: a10 = LD32(a3 + 0x158);  /* 00c1 */
  __asm__ volatile("" ::: "memory");  /* 00c4: memw */
  /* 00c7: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ca */
  a10 = 3;  /* 00cc */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00ce: -> "mesh_main.c" */
  a14 = a11;  /* 00d1 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 00d3: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 00d6: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_04bc;  /* 00d9: j */
  L_00dd: a5 = 0;  /* 00dd */
  a10 = LD32(a1 + 0x20);  /* 00df */
  ST32(a1 + 0x10, a5);  /* 00e1 */
  if (a10 != a5) goto L_011a;  /* 00e3: bne a10, a5, 11a <mesh_process_mcast_cover_node+0x82> */
  L_00e6: a2 = (u32)&g_log_level + 0x0;  /* 00e6: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00e9 */
  a2 = 0x00004008u;  /* 00eb: l32r = 16392 */
  if (a3 >= 3u) goto L_00f4;  /* 00ee: bgeui a3, 3, f4 <mesh_process_mcast_cover_node+0x5c> */
  L_00f1: goto L_04bc;  /* 00f1: j */
  L_00f4: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00f4: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00f7 */
  if (a3 != a5) goto L_00ff;  /* 00f9: bne a3, a5, ff <mesh_process_mcast_cover_node+0x67> */
  L_00fc: goto L_04bc;  /* 00fc: j */
  L_00ff: a4 = LD32(a3 + 0x150);  /* 00ff */
  if (a4 != a5) goto L_0108;  /* 0102: bne a4, a5, 108 <mesh_process_mcast_cover_node+0x70> */
  L_0105: goto L_04bc;  /* 0105: j */
  L_0108: a10 = LD32(a3 + 0x158);  /* 0108 */
  a3 = 0x1c1;  /* 010b */
  __asm__ volatile("" ::: "memory");  /* 010e: memw */
  /* 0111: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0114: -> "mesh_main.c" */
  goto L_0148;  /* 0117: j */
  L_011a: a4 = LD32(a10 + 0x0);  /* 011a */
  if (a4 != 0) goto L_0161;  /* 011c: bnez a4, 161 <mesh_process_mcast_cover_node+0xc9> */
  L_011f: a2 = (u32)&g_log_level + 0x0;  /* 011f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0122 */
  a2 = 0x00004008u;  /* 0124: l32r = 16392 */
  if (a3 >= 3u) goto L_012d;  /* 0127: bgeui a3, 3, 12d <mesh_process_mcast_cover_node+0x95> */
  L_012a: goto L_04bc;  /* 012a: j */
  L_012d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 012d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0130 */
  if (a3 == 0) goto L_04bc;  /* 0133: beqz a3, 4bc <mesh_process_mcast_cover_node+0x424> */
  L_0136: a4 = LD32(a3 + 0x150);  /* 0136 */
  if (a4 == 0) goto L_04bc;  /* 0139: beqz a4, 4bc <mesh_process_mcast_cover_node+0x424> */
  L_013c: a10 = LD32(a3 + 0x158);  /* 013c */
  a3 = 0x1c2;  /* 013f */
  /* 0142: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0145: -> "mesh_main.c" */
  L_0148: a13 = a10;  /* 0148 */
  a14 = a11;  /* 014a */
  a10 = 3;  /* 014c */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 014e: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0151: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 0154 */
  __asm__ volatile("" ::: "memory");  /* 0156: memw */
  /* 0159: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_04bc;  /* 015c: j */
  L_0161: a2 = LD8U(a10 + 0x12);  /* 0161 */
  if (a2 == 0) goto L_0179;  /* 0164: beqz a2, 179 <mesh_process_mcast_cover_node+0xe1> */
  L_0167: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0167: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 016a: memw */
  a2 = LD8U(a2 + 0x0);  /* 016d */
  a2 = (a2 >> 8) & 0x1;  /* 0170: extui width 1 */
  if (a2 != 0) goto L_0179;  /* 0173: bnez a2, 179 <mesh_process_mcast_cover_node+0xe1> */
  L_0176: a5 = (a3 >> 1) & 0xf;  /* 0176: extui width 4 */
  L_0179: a7 = (u32)&g_mesh_topology + 0x0;  /* 0179: l32r -> global */
  a6 = 28;  /* 017c */
  a2 = 33;  /* 017e */
  a8 = LD32(a7 + 0x0);  /* 0180 */
  if (a8 == 0) a2 = a6;  /* 0182 */
  ST32(a1 + 0x24, a2);  /* 0185 */
  a2 = 2;  /* 0187 */
  a2 = a3 & a2;  /* 0189 */
  if (a5 != 0) goto L_0195;  /* 018c: bnez a5, 195 <mesh_process_mcast_cover_node+0xfd> */
  L_018f: if (((a3 >> 2) & 1) != 0) goto L_0195;  /* 018f: bbsi a3, 2, 195 <mesh_process_mcast_cover_node+0xfd> */
  L_0192: goto L_03ac;  /* 0192: j */
  L_0195: if (a2 == 0) goto L_03b9;  /* 0195: beqz a2, 3b9 <mesh_process_mcast_cover_node+0x321> */
  L_0198: a6 = (u32)(RODATA__rodata___func___2 + 0x0);  /* 0198: l32r -> .rodata.__func__$2 */
  a2 = a4 + (14);  /* 019b */
  a12 = 0x1e9;  /* 019d */
  a11 = a6;  /* 01a0 */
  a10 = a2;  /* 01a2 */
  ST32(a1 + 0x28, a2);  /* 01a4 */
  __asm__ volatile("" ::: "memory");  /* 01a7: memw */
  a8 = (u32)&esp_mesh_get_optlen;  /* 01aa: l32r -> func addr */
  a2 = esp_mesh_get_optlen(a2, a3, a4, a5, a6, a7);  /* 01ad: callx a8 via reloc-expand */
  a12 = 0x1ec;  /* 01b0 */
  a11 = a6;  /* 01b3 */
  a8 = LD32(a1 + 0x24);  /* 01b5 */
  a2 = a8 + (-3);  /* 01b7 */
  a10 = a2 + a10;  /* 01ba */
  a9 = (a10 >> 2) & 0x1;  /* 01bc: extui width 1 */
  a2 = 0;  /* 01bf */
  a8 = 1;  /* 01c1 */
  if (a9 == 0) a8 = a2;  /* 01c3 */
  a2 = LD32(a1 + 0x20);  /* 01c6 */
  a10 = a10 >> 2;  /* 01c8 */
  a8 = a8 + a10;  /* 01cb */
  a9 = a8 << 2;  /* 01cd */
  a10 = LD16U(a2 + 0x4);  /* 01d0 */
  a2 = LD8U(a4 + 0xf);  /* 01d3 */
  a2 = a2 << 2;  /* 01d6 */
  a10 = a10 - a2;  /* 01d9: sub */
  a10 = a8 + (a10 << 2);  /* 01dc */
  ST32(a1 + 0x2c, a9);  /* 01df */
  ST32(a1 + 0x34, a8);  /* 01e1 */
  __asm__ volatile("" ::: "memory");  /* 01e4: memw */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 01e7: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 01ea: callx a8 via reloc-expand */
  a2 = a10;  /* 01ed */
  if (a10 == 0) goto L_02ce;  /* 01ef: beqz a10, 2ce <mesh_process_mcast_cover_node+0x236> */
  L_01f2: a12 = 44;  /* 01f2 */
  a14 = LD32(a1 + 0x20);  /* 01f4 */
  a10 = a10 + (4);  /* 01f6 */
  a11 = a14 + (4);  /* 01f8 */
  ST32(a1 + 0x30, a14);  /* 01fa */
  __asm__ volatile("" ::: "memory");  /* 01fc: memw */
  a8 = (u32)&memcpy + 0x0;  /* 01ff: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0202: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x2c);  /* 0205 */
  a13 = (a9 >> 16) & 0x1;  /* 0207: extui width 1 */
  a10 = LD8U(a4 + 0xf);  /* 020a */
  a10 = a10 << 2;  /* 020d */
  a9 = LD16U(a2 + 0x4);  /* 0210 */
  a9 = a9 - a10;  /* 0213: sub */
  a9 = a13 + a9;  /* 0216 */
  a10 = 45;  /* 0218 */
  a12 = LD32(a7 + 0x0);  /* 021a */
  a14 = LD32(a1 + 0x30);  /* 021c */
  ST16(a2 + 0x4, a9);  /* 021e */
  __asm__ volatile("" ::: "memory");  /* 0221: memw */
  a9 = 50;  /* 0224 */
  if (a12 == 0) a9 = a10;  /* 0226 */
  a12 = a9;  /* 0229 */
  a11 = LD32(a14 + 0x0);  /* 022b */
  a10 = LD32(a2 + 0x0);  /* 022d */
  ST32(a1 + 0x30, a13);  /* 022f */
  __asm__ volatile("" ::: "memory");  /* 0231: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0234: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0237: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a2 + 0x0);  /* 023a */
  a8 = LD32(a1 + 0x34);  /* 023c */
  ST8(a9 + 0xf, a8);  /* 023e */
  __asm__ volatile("" ::: "memory");  /* 0241: memw */
  a10 = LD8U(a4 + 0xf);  /* 0244 */
  a10 = a10 << 2;  /* 0247 */
  a8 = LD16U(a9 + 0x10);  /* 024a */
  a8 = a8 - a10;  /* 024d: sub */
  a13 = LD32(a1 + 0x30);  /* 0250 */
  a13 = a13 + a8;  /* 0252 */
  a8 = 33;  /* 0254 */
  a10 = LD32(a7 + 0x0);  /* 0256 */
  a7 = 28;  /* 0258 */
  if (a10 != 0) a7 = a8;  /* 025a */
  a7 = a7 + (14);  /* 025d */
  a7 = a9 + a7;  /* 025f */
  ST16(a9 + 0x10, a13);  /* 0261 */
  __asm__ volatile("" ::: "memory");  /* 0264: memw */
  a12 = a7 + (3);  /* 0267 */
  a13 = LD32(a1 + 0x24);  /* 0269 */
  a11 = a13 + (3);  /* 026b */
  a8 = LD8U(a7 + 0x2);  /* 026d */
  a8 = a8 << 8;  /* 0270 */
  a10 = LD8U(a7 + 0x1);  /* 0273 */
  a10 = a8 | a10;  /* 0276 */
  a13 = LD32(a1 + 0x28);  /* 0279 */
  a11 = a13 + a11;  /* 027b */
  ST32(a1 + 0x30, a9);  /* 027d */
  __asm__ volatile("" ::: "memory");  /* 027f: memw */
  a8 = (u32)&mesh_remove_myself_from_forwarding;  /* 0282: l32r -> func addr */
  a2 = mesh_remove_myself_from_forwarding(a2, a3, a4, a5, a6, a7);  /* 0285: callx a8 via reloc-expand */
  a8 = LD8U(a7 + 0x2);  /* 0288 */
  a8 = a8 << 8;  /* 028b */
  a10 = LD8U(a7 + 0x1);  /* 028e */
  a8 = a8 | a10;  /* 0291 */
  a8 = a8 + (-6);  /* 0294 */
  a9 = LD32(a1 + 0x30);  /* 0297 */
  ST8(a7 + 0x1, a8);  /* 0299 */
  a8 = (a8 >> 8) & 0x1ff;  /* 029c: extui width 9 */
  ST8(a7 + 0x2, a8);  /* 029f */
  __asm__ volatile("" ::: "memory");  /* 02a2: memw */
  a8 = LD8U(a9 + 0xf);  /* 02a5 */
  a8 = a8 << 2;  /* 02a8 */
  a10 = a8 + (14);  /* 02ab */
  a12 = LD16U(a9 + 0x10);  /* 02ad */
  a12 = a12 - a8;  /* 02b0: sub */
  a7 = LD8U(a4 + 0xf);  /* 02b3 */
  a7 = a7 << 2;  /* 02b6 */
  a7 = a7 + (14);  /* 02b9 */
  a9 = LD32(a1 + 0x20);  /* 02bb */
  a13 = LD32(a2 + 0x0);  /* 02bd */
  a10 = a13 + a10;  /* 02bf */
  a11 = LD32(a9 + 0x0);  /* 02c1 */
  a11 = a11 + a7;  /* 02c3 */
  __asm__ volatile("" ::: "memory");  /* 02c5: memw */
  a8 = (u32)&memcpy + 0x0;  /* 02c8: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 02cb: callx a8 (libc, via reloc-expand) */
  L_02ce: a10 = LD32(a1 + 0x20);  /* 02ce */
  a8 = (u32)&esp_mesh_delivery_toSelf;  /* 02d0: l32r -> func addr */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 02d3: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02e5;  /* 02d6: beqz.n a10, 2e5 <mesh_process_mcast_cover_node+0x24d> */
  L_02d8: a12 = 0x211;  /* 02d8 */
  a10 = LD32(a1 + 0x20);  /* 02db */
  a11 = a6;  /* 02dd */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 02df: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 02e2: callx a8 via reloc-expand */
  L_02e5: a7 = 0;  /* 02e5 */
  a8 = 1;  /* 02e7 */
  ST32(a1 + 0x20, a7);  /* 02e9 */
  if (a2 != a7) goto L_02f1;  /* 02eb: bne a2, a7, 2f1 <mesh_process_mcast_cover_node+0x259> */
  L_02ee: goto L_047a;  /* 02ee: j */
  L_02f1: a9 = LD32(a2 + 0x0);  /* 02f1 */
  ST32(a1 + 0x24, a9);  /* 02f3 */
  a9 = 4;  /* 02f5 */
  a3 = a3 & a9;  /* 02f8 */
  if (a5 != a7) goto L_0301;  /* 02fb: bne a5, a7, 301 <mesh_process_mcast_cover_node+0x269> */
  L_02fe: goto L_0388;  /* 02fe: j */
  L_0301: if (a3 == a7) goto L_037c;  /* 0301: beq a3, a7, 37c <mesh_process_mcast_cover_node+0x2e4> */
  L_0304: a10 = LD16U(a2 + 0x4);  /* 0304 */
  a12 = 0x21e;  /* 0307 */
  a11 = a6;  /* 030a: mov */
  __asm__ volatile("" ::: "memory");  /* 030d: memw */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 0310: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 0313: callx a8 via reloc-expand */
  a3 = a10;  /* 0316 */
  ST32(a1 + 0x10, a10);  /* 0318 */
  if (a10 == a7) goto L_037a;  /* 031a: beq a10, a7, 37a <mesh_process_mcast_cover_node+0x2e2> */
  L_031d: a12 = 44;  /* 031d */
  a11 = a2 + (4);  /* 031f */
  a10 = a10 + (4);  /* 0321 */
  __asm__ volatile("" ::: "memory");  /* 0323: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0326: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0329: callx a8 (libc, via reloc-expand) */
  a12 = LD16U(a2 + 0x4);  /* 032c */
  a11 = LD32(a2 + 0x0);  /* 032f */
  a10 = LD32(a3 + 0x0);  /* 0331 */
  a8 = (u32)&memcpy + 0x0;  /* 0333: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0336: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0339 */
  a11 = a4 + (22);  /* 033b */
  a3 = LD32(a1 + 0x10);  /* 033e */
  a10 = a3 + a12;  /* 0340 */
  ST8(a3 + 0x12, a7);  /* 0342 */
  __asm__ volatile("" ::: "memory");  /* 0345: memw */
  __asm__ volatile("" ::: "memory");  /* 0348: memw */
  a8 = (u32)&memcpy + 0x0;  /* 034b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 034e: callx a8 (libc, via reloc-expand) */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0351: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0354 */
  a10 = LD32(a3 + 0x24);  /* 0356 */
  a4 = LD32(a4 + 0xa0);  /* 0358 */
  /* 035b: INDIRECT callx a4 <- mem[a4+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 035e */
  a10 = a1 + (16);  /* 0360 */
  a8 = (u32)&esp_mesh_push_to_tx_queue + 0x0;  /* 0363: l32r -> global */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 0366: callx a8 via reloc-expand */
  if (a10 == a7) goto L_037a;  /* 0369: beq a10, a7, 37a <mesh_process_mcast_cover_node+0x2e2> */
  L_036c: a10 = LD32(a1 + 0x10);  /* 036c */
  a12 = 0x22d;  /* 036e */
  a11 = a6;  /* 0371: mov */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0374: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 0377: callx a8 via reloc-expand */
  L_037a: a3 = 1;  /* 037a */
  L_037c: ST8(a2 + 0x12, a3);  /* 037c */
  __asm__ volatile("" ::: "memory");  /* 037f: memw */
  __asm__ volatile("" ::: "memory");  /* 0382: memw */
  goto L_0390;  /* 0385: j */
  L_0388: if (a3 == 0) goto L_0390;  /* 0388: beqz.n a3, 390 <mesh_process_mcast_cover_node+0x2f8> */
  L_038a: ST8(a2 + 0x12, a8);  /* 038a */
  __asm__ volatile("" ::: "memory");  /* 038d: memw */
  L_0390: a12 = 6;  /* 0390 */
  a10 = a2 + a12;  /* 0392 */
  a13 = LD32(a1 + 0x24);  /* 0394 */
  a11 = a13 + (22);  /* 0396 */
  __asm__ volatile("" ::: "memory");  /* 0399: memw */
  a8 = (u32)&memcpy + 0x0;  /* 039c: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 039f: callx a8 (libc, via reloc-expand) */
  a8 = 1;  /* 03a2 */
  ST32(a1 + 0x20, a2);  /* 03a4 */
  __asm__ volatile("" ::: "memory");  /* 03a6: memw */
  goto L_047a;  /* 03a9: j */
  L_03ac: if (a2 == 0) goto L_03b9;  /* 03ac: beqz.n a2, 3b9 <mesh_process_mcast_cover_node+0x321> */
  L_03ae: a8 = (u32)&esp_mesh_delivery_toSelf;  /* 03ae: l32r -> func addr */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 03b1: callx a8 via reloc-expand */
  a2 = a10;  /* 03b4 */
  goto L_04bc;  /* 03b6: j */
  L_03b9: a2 = 4;  /* 03b9 */
  a3 = a3 & a2;  /* 03bb */
  if (a5 == 0) goto L_044c;  /* 03be: beqz a5, 44c <mesh_process_mcast_cover_node+0x3b4> */
  L_03c1: if (a3 == 0) goto L_0460;  /* 03c1: beqz a3, 460 <mesh_process_mcast_cover_node+0x3c8> */
  L_03c4: a5 = (u32)(RODATA__rodata___func___2 + 0x0);  /* 03c4: l32r -> .rodata.__func__$2 */
  a12 = 0x24f;  /* 03c7 */
  a11 = a5;  /* 03ca */
  a10 = LD16U(a10 + 0x4);  /* 03cc */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 03cf: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 03d2: callx a8 via reloc-expand */
  a2 = a10;  /* 03d5 */
  ST32(a1 + 0x10, a10);  /* 03d7 */
  if (a10 == 0) goto L_043c;  /* 03d9: beqz a10, 43c <mesh_process_mcast_cover_node+0x3a4> */
  L_03dc: a12 = 44;  /* 03dc */
  a10 = a10 + (4);  /* 03de */
  a3 = LD32(a1 + 0x20);  /* 03e0 */
  a11 = a3 + (4);  /* 03e2 */
  __asm__ volatile("" ::: "memory");  /* 03e4: memw */
  a8 = (u32)&memcpy + 0x0;  /* 03e7: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 03ea: callx a8 (libc, via reloc-expand) */
  a12 = LD16U(a3 + 0x4);  /* 03ed */
  a11 = LD32(a3 + 0x0);  /* 03f0 */
  a3 = 0;  /* 03f2 */
  a10 = LD32(a2 + 0x0);  /* 03f4 */
  a8 = (u32)&memcpy + 0x0;  /* 03f7: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 03fa: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 03fd */
  a11 = a4 + (22);  /* 03ff */
  a2 = LD32(a1 + 0x10);  /* 0402 */
  a10 = a2 + a12;  /* 0404 */
  ST8(a2 + 0x12, a3);  /* 0406 */
  __asm__ volatile("" ::: "memory");  /* 0409: memw */
  __asm__ volatile("" ::: "memory");  /* 040c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 040f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0412: callx a8 (libc, via reloc-expand) */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0415: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0418 */
  a10 = LD32(a2 + 0x24);  /* 041a */
  a3 = LD32(a3 + 0xa0);  /* 041c */
  /* 041f: INDIRECT callx a3 <- mem[a3+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 0422 */
  a10 = a1 + (16);  /* 0424 */
  a8 = (u32)&esp_mesh_push_to_tx_queue + 0x0;  /* 0427: l32r -> global */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 042a: callx a8 via reloc-expand */
  if (a10 == 0) goto L_043c;  /* 042d: beqz.n a10, 43c <mesh_process_mcast_cover_node+0x3a4> */
  L_042f: a10 = LD32(a1 + 0x10);  /* 042f */
  a12 = 0x25d;  /* 0431 */
  a11 = a5;  /* 0434 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0436: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 0439: callx a8 via reloc-expand */
  L_043c: a3 = 1;  /* 043c */
  a2 = LD32(a1 + 0x20);  /* 043e */
  ST8(a2 + 0x12, a3);  /* 0440 */
  __asm__ volatile("" ::: "memory");  /* 0443: memw */
  __asm__ volatile("" ::: "memory");  /* 0446: memw */
  goto L_0466;  /* 0449: j */
  L_044c: a2 = 0x0000400fu;  /* 044c: l32r = 16399 */
  if (a3 == 0) goto L_04bc;  /* 044f: beqz a3, 4bc <mesh_process_mcast_cover_node+0x424> */
  L_0452: a2 = 1;  /* 0452 */
  ST8(a10 + 0x12, a2);  /* 0454 */
  __asm__ volatile("" ::: "memory");  /* 0457: memw */
  __asm__ volatile("" ::: "memory");  /* 045a: memw */
  goto L_0466;  /* 045d: j */
  L_0460: ST8(a10 + 0x12, a3);  /* 0460 */
  __asm__ volatile("" ::: "memory");  /* 0463: memw */
  L_0466: a12 = 6;  /* 0466 */
  a11 = a4 + (22);  /* 0468 */
  a10 = LD32(a1 + 0x20);  /* 046b */
  a10 = a10 + a12;  /* 046d */
  __asm__ volatile("" ::: "memory");  /* 046f: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0472: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0475: callx a8 (libc, via reloc-expand) */
  a8 = 0;  /* 0478 */
  L_047a: a2 = LD32(a1 + 0x20);  /* 047a */
  if (a2 != 0) goto L_0484;  /* 047c: bnez.n a2, 484 <mesh_process_mcast_cover_node+0x3ec> */
  L_047e: if (a8 == 0) goto L_0484;  /* 047e: beqz.n a8, 484 <mesh_process_mcast_cover_node+0x3ec> */
  L_0480: goto L_04ba;  /* 0480: j */
  L_0484: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0484: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0487 */
  a10 = LD32(a2 + 0x24);  /* 048a */
  a3 = LD32(a3 + 0xa0);  /* 048d */
  ST32(a1 + 0x34, a8);  /* 0490 */
  __asm__ volatile("" ::: "memory");  /* 0493: memw */
  /* 0496: INDIRECT callx a3 <- mem[a3+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 0499 */
  a10 = a1 + (32);  /* 049b */
  a8 = (u32)&esp_mesh_push_to_tx_queue + 0x0;  /* 049e: l32r -> global */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 04a1: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x34);  /* 04a4 */
  a2 = a10;  /* 04a6 */
  if (a10 == 0) goto L_04ba;  /* 04a8: beqz.n a10, 4ba <mesh_process_mcast_cover_node+0x422> */
  L_04aa: if (a8 == 0) goto L_04bc;  /* 04aa: beqz.n a8, 4bc <mesh_process_mcast_cover_node+0x424> */
  L_04ac: a12 = 0x27a;  /* 04ac */
  a11 = (u32)(RODATA__rodata___func___2 + 0x0);  /* 04af: l32r -> .rodata.__func__$2 */
  a10 = LD32(a1 + 0x20);  /* 04b2 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 04b4: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 04b7: callx a8 via reloc-expand */
  L_04ba: a2 = 0;  /* 04ba */
  L_04bc: return a2;  /* 04bc: retw.n */
}


/* mesh_process_mgmt_announce @ mesh_main.o 00000084 size 949B bind GLOBAL
 * Calls: memset, esp_mesh_push_to_nwk_queue, esp_mesh_copy_mgmt_announce, memcpy, opt_type2str, esp_mesh_get_total_children_num | indirect[11]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x158]; unknown | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_topology, g_mesh_ie, .rodata.mesh_process_mgmt_announce.str1.1, g_mesh_max_layer, g_mesh_is_root, g_mesh_self_sta_addr
 * Fidelity: medium - 11 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=17); reloc-direct=6, funcdb-attributed=0, unknown-indirect=11 */
u32 mesh_process_mgmt_announce(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a6, a7, a8;
  /* 0084: entry a1, 0x1e0 (frame 0x1e0 bytes) */
  a14 = a4;  /* 0087 */
  a4 = (u32)&g_is_mesh_started + 0x0;  /* 0089: l32r -> global */
  a6 = a5;  /* 008c */
  a4 = LD8U(a4 + 0x0);  /* 008e */
  if (a4 != 0) goto L_00c8;  /* 0091: bnez.n a4, c8 <mesh_process_mgmt_announce+0x44> */
  L_0093: a2 = (u32)&g_log_level + 0x0;  /* 0093: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0096 */
  a7 = 0x00004004u;  /* 0098: l32r = 16388 */
  if (a2 >= 3u) goto L_00a1;  /* 009b: bgeui a2, 3, a1 <mesh_process_mgmt_announce+0x1d> */
  L_009e: goto L_0435;  /* 009e: j */
  L_00a1: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00a1: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00a4 */
  if (a2 == 0) goto L_0435;  /* 00a6: beqz a2, 435 <mesh_process_mgmt_announce+0x3b1> */
  L_00a9: a3 = LD32(a2 + 0x150);  /* 00a9 */
  if (a3 == 0) goto L_0435;  /* 00ac: beqz a3, 435 <mesh_process_mgmt_announce+0x3b1> */
  L_00af: a10 = LD32(a2 + 0x158);  /* 00af */
  /* 00b2: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00b5 */
  a10 = 3;  /* 00b7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00b9: -> "mesh_main.c" */
  a14 = a11;  /* 00bc */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 00be: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 00c1: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0435;  /* 00c4: j */
  L_00c8: if (a2 != 0) goto L_010a;  /* 00c8: bnez.n a2, 10a <mesh_process_mgmt_announce+0x86> */
  L_00ca: a2 = (u32)&g_log_level + 0x0;  /* 00ca: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00cd */
  if (a2 >= 3u) goto L_00d5;  /* 00cf: bgeui a2, 3, d5 <mesh_process_mgmt_announce+0x51> */
  L_00d2: goto L_0104;  /* 00d2: j */
  L_00d5: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00d5: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00d8 */
  if (a2 == 0) goto L_0104;  /* 00da: beqz a2, 104 <mesh_process_mgmt_announce+0x80> */
  L_00dd: a3 = LD32(a2 + 0x150);  /* 00dd */
  if (a3 == 0) goto L_0104;  /* 00e0: beqz a3, 104 <mesh_process_mgmt_announce+0x80> */
  L_00e3: a10 = LD32(a2 + 0x158);  /* 00e3 */
  a2 = 0x4ea;  /* 00e6 */
  /* 00e9: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00ec: -> "mesh_main.c" */
  L_00ef: a13 = a10;  /* 00ef */
  a14 = a11;  /* 00f1 */
  a10 = 3;  /* 00f3 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00f5: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00f8: -> "mesh_main.c" */
  ST32(a1 + 0x0, a2);  /* 00fb */
  __asm__ volatile("" ::: "memory");  /* 00fe: memw */
  /* 0101: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0104: a7 = 0x00004008u;  /* 0104: l32r = 16392 */
  goto L_0435;  /* 0107: j */
  L_010a: if (a3 != 0) goto L_0134;  /* 010a: bnez.n a3, 134 <mesh_process_mgmt_announce+0xb0> */
  L_010c: a2 = (u32)&g_log_level + 0x0;  /* 010c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 010f */
  if (a2 < 3u) goto L_0104;  /* 0111: bltui a2, 3, 104 <mesh_process_mgmt_announce+0x80> */
  L_0114: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0114: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0117 */
  if (a2 == 0) goto L_0104;  /* 011a: beqz a2, 104 <mesh_process_mgmt_announce+0x80> */
  L_011d: a3 = LD32(a2 + 0x150);  /* 011d */
  if (a3 == 0) goto L_0104;  /* 0120: beqz a3, 104 <mesh_process_mgmt_announce+0x80> */
  L_0123: a10 = LD32(a2 + 0x158);  /* 0123 */
  a2 = 0x4eb;  /* 0126 */
  /* 0129: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 012c: -> "mesh_main.c" */
  goto L_00ef;  /* 012f: j */
  L_0134: a12 = 184;  /* 0134 */
  a11 = 0;  /* 0137 */
  a10 = a1 + (64);  /* 0139 */
  ST32(a1 + 0x1b4, a14);  /* 013c */
  __asm__ volatile("" ::: "memory");  /* 013f: memw */
  a8 = (u32)&memset + 0x0;  /* 0142: l32r -> global */
  a2 = memset(a2, a3, a4, a5);  /* 0145: callx a8 (libc, via reloc-expand) */
  a5 = (u32)&g_mesh_topology + 0x0;  /* 0148: l32r -> global */
  a4 = LD32(a5 + 0x0);  /* 014b */
  a14 = LD32(a1 + 0x1b4);  /* 014d */
  if (a4 != 0) goto L_0160;  /* 0150: bnez.n a4, 160 <mesh_process_mgmt_announce+0xdc> */
  L_0152: a8 = LD8U(a3 + 0x0);  /* 0152 */
  ST32(a1 + 0x1b0, a8);  /* 0155 */
  __asm__ volatile("" ::: "memory");  /* 0158: memw */
  goto L_016f;  /* 015b: j */
  L_0160: a5 = LD8U(a3 + 0x1);  /* 0160 */
  a5 = a5 << 8;  /* 0163 */
  a4 = LD8U(a3 + 0x0);  /* 0166 */
  a5 = a5 | a4;  /* 0169 */
  ST32(a1 + 0x1b0, a5);  /* 016c */
  L_016f: a4 = LD8U(a2 + 0x2);  /* 016f */
  a4 = a4 << 8;  /* 0172 */
  a5 = LD8U(a2 + 0x1);  /* 0175 */
  a4 = a4 | a5;  /* 0178 */
  if (a4 == 0) goto L_0104;  /* 017b: beqz a4, 104 <mesh_process_mgmt_announce+0x80> */
  L_017e: a4 = LD8U(a2 + 0x0);  /* 017e */
  a4 = a4 + (-3);  /* 0181 */
  a4 = (a4 >> 8) & 0x1;  /* 0184: extui width 1 */
  if (a4 < 2u) goto L_018d;  /* 0187: bltui a4, 2, 18d <mesh_process_mgmt_announce+0x109> */
  L_018a: goto L_0104;  /* 018a: j */
  L_018d: a4 = (u32)&g_mesh_ie + 0x0;  /* 018d: l32r -> global */
  a5 = LD8U(a4 + 0x7);  /* 0190 */
  if (a5 != 3) goto L_01f4;  /* 0193: bnei a5, 3, 1f4 <mesh_process_mgmt_announce+0x170> */
  L_0196: a5 = LD8U(a4 + 0x11);  /* 0196 */
  if (a5 == 0) goto L_01f4;  /* 0199: beqz a5, 1f4 <mesh_process_mgmt_announce+0x170> */
  L_019c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 019c: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 019f */
  if (a3 == 0) goto L_01de;  /* 01a1: beqz.n a3, 1de <mesh_process_mgmt_announce+0x15a> */
  L_01a3: a5 = LD32(a3 + 0x150);  /* 01a3 */
  if (a5 == 0) goto L_01de;  /* 01a6: beqz.n a5, 1de <mesh_process_mgmt_announce+0x15a> */
  L_01a8: a10 = LD32(a3 + 0x158);  /* 01a8 */
  __asm__ volatile("" ::: "memory");  /* 01ab: memw */
  /* 01ae: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = LD8U(a2 + 0x0);  /* 01b1 */
  a2 = (u32)(RODATA__rodata_mesh_process_mgmt_announce_str1_1 + 0x0);  /* 01b4: -> "add" */
  if (a3 == 3) goto L_01bd;  /* 01b7: beqi a3, 3, 1bd <mesh_process_mgmt_announce+0x139> */
  L_01ba: a2 = (u32)(RODATA__rodata_mesh_process_mgmt_announce_str1_1 + 0x0);  /* 01ba: -> "add" */
  L_01bd: a13 = a10;  /* 01bd */
  a10 = 2;  /* 01bf */
  a3 = LD8U(a4 + 0x11);  /* 01c1 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01c4: -> "mesh_main.c" */
  a14 = a11;  /* 01c7 */
  ST32(a1 + 0x4, a2);  /* 01c9 */
  a2 = 0x4fb;  /* 01cb */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01ce: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_announce_str1_1 + 0x0);  /* 01d1: -> "add" */
  ST32(a1 + 0x8, a3);  /* 01d4 */
  ST32(a1 + 0x0, a2);  /* 01d6 */
  __asm__ volatile("" ::: "memory");  /* 01d8: memw */
  /* 01db: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_01de: a2 = 25;  /* 01de */
  a11 = 0;  /* 01e0 */
  a10 = a1 + (64);  /* 01e2 */
  ST32(a1 + 0x40, a2);  /* 01e5 */
  __asm__ volatile("" ::: "memory");  /* 01e8: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 01eb: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5);  /* 01ee: callx a8 via reloc-expand */
  goto L_0390;  /* 01f1: j */
  L_01f4: a5 = (u32)&g_mesh_max_layer + 0x0;  /* 01f4: l32r -> global */
  a8 = LD32(a1 + 0x1b0);  /* 01f7 */
  a4 = LD16U(a5 + 0x0);  /* 01fa */
  if (a8 < a4) goto L_026d;  /* 01fd: bltu a8, a4, 26d <mesh_process_mgmt_announce+0x1e9> */
  L_0200: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0200: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0203 */
  if (a3 != 0) goto L_020c;  /* 0205: bnez.n a3, 20c <mesh_process_mgmt_announce+0x188> */
  L_0207: goto L_0390;  /* 0207: j */
  L_020c: a4 = LD32(a3 + 0x150);  /* 020c */
  if (a4 == 0) goto L_0390;  /* 020f: beqz a4, 390 <mesh_process_mgmt_announce+0x30c> */
  L_0212: a10 = LD32(a3 + 0x158);  /* 0212 */
  /* 0215: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = LD8U(a2 + 0x0);  /* 0218 */
  a2 = (u32)(RODATA__rodata_mesh_process_mgmt_announce_str1_1 + 0x0);  /* 021b: -> "add" */
  if (a3 == 3) goto L_0224;  /* 021e: beqi a3, 3, 224 <mesh_process_mgmt_announce+0x1a0> */
  L_0221: a2 = (u32)(RODATA__rodata_mesh_process_mgmt_announce_str1_1 + 0x0);  /* 0221: -> "add" */
  L_0224: a13 = a10;  /* 0224 */
  a10 = 2;  /* 0226 */
  a3 = LD8U(a6 + 0x5);  /* 0228 */
  ST32(a1 + 0x24, a3);  /* 022b */
  a3 = LD8U(a6 + 0x4);  /* 022d */
  ST32(a1 + 0x20, a3);  /* 0230 */
  a3 = LD8U(a6 + 0x3);  /* 0232 */
  ST32(a1 + 0x1c, a3);  /* 0235 */
  a3 = LD8U(a6 + 0x2);  /* 0237 */
  ST32(a1 + 0x18, a3);  /* 023a */
  a3 = LD8U(a6 + 0x1);  /* 023c */
  ST32(a1 + 0x14, a3);  /* 023f */
  a3 = LD8U(a6 + 0x0);  /* 0241 */
  ST32(a1 + 0x10, a3);  /* 0244 */
  a3 = LD16U(a5 + 0x0);  /* 0246 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0249: -> "mesh_main.c" */
  a14 = a11;  /* 024c */
  ST32(a1 + 0xc, a3);  /* 024e */
  a3 = LD32(a1 + 0x1b0);  /* 0250 */
  ST32(a1 + 0x4, a2);  /* 0253 */
  a2 = 0x507;  /* 0255 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0258: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_announce_str1_1 + 0x0);  /* 025b: -> "add" */
  ST32(a1 + 0x8, a3);  /* 025e */
  ST32(a1 + 0x0, a2);  /* 0260 */
  __asm__ volatile("" ::: "memory");  /* 0262: memw */
  /* 0265: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  goto L_0390;  /* 0268: j */
  L_026d: a8 = a1 + (64);  /* 026d */
  a4 = 184;  /* 0270 */
  a4 = a8 + a4;  /* 0273 */
  a12 = 177;  /* 0275 */
  a11 = 0;  /* 0278 */
  a10 = a4;  /* 027a */
  ST32(a1 + 0x1b4, a14);  /* 027c */
  __asm__ volatile("" ::: "memory");  /* 027f: memw */
  a8 = (u32)&memset + 0x0;  /* 0282: l32r -> global */
  a2 = memset(a2, a3, a4, a5);  /* 0285: callx a8 (libc, via reloc-expand) */
  a12 = a4;  /* 0288 */
  a11 = a3;  /* 028a */
  a10 = a2;  /* 028c */
  a8 = (u32)&esp_mesh_copy_mgmt_announce + 0x0;  /* 028e: l32r -> global */
  a2 = esp_mesh_copy_mgmt_announce(a2, a3, a4, a5);  /* 0291: callx a8 via reloc-expand */
  a14 = LD32(a1 + 0x1b4);  /* 0294 */
  a7 = a10;  /* 0297 */
  if (a10 != 0) goto L_0300;  /* 0299: bnez a10, 300 <mesh_process_mgmt_announce+0x27c> */
  L_029c: a10 = 19;  /* 029c */
  a12 = 6;  /* 029e */
  ST32(a1 + 0x40, a10);  /* 02a0 */
  a10 = LD8U(a2 + 0x2);  /* 02a3 */
  a10 = a10 << 8;  /* 02a6 */
  a11 = LD8U(a2 + 0x1);  /* 02a9 */
  a10 = a10 | a11;  /* 02ac */
  a11 = a14;  /* 02af */
  ST32(a1 + 0xfc, a10);  /* 02b1 */
  a10 = a1 + 0x10000;  /* 02b4: addmi a10, a1, 0x100 */
  __asm__ volatile("" ::: "memory");  /* 02b7: memw */
  a8 = (u32)&memcpy + 0x0;  /* 02ba: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 02bd: callx a8 (libc, via reloc-expand) */
  a11 = a6;  /* 02c0 */
  a10 = 198;  /* 02c2 */
  a6 = a1 + (64);  /* 02c5 */
  a12 = 6;  /* 02c8 */
  a10 = a6 + a10;  /* 02ca */
  a8 = (u32)&memcpy + 0x0;  /* 02cc: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 02cf: callx a8 (libc, via reloc-expand) */
  a11 = a4;  /* 02d2 */
  a12 = 177;  /* 02d4 */
  a10 = a1 + (70);  /* 02d7 */
  a8 = (u32)&memcpy + 0x0;  /* 02da: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 02dd: callx a8 (libc, via reloc-expand) */
  a11 = a7;  /* 02e0: mov */
  a10 = a6;  /* 02e3: mov */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 02e6: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5);  /* 02e9: callx a8 via reloc-expand */
  a4 = (u32)&g_mesh_is_root + 0x0;  /* 02ec: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 02ef: memw */
  a4 = LD8U(a4 + 0x0);  /* 02f2 */
  a4 = (a4 >> 8) & 0x1;  /* 02f5: extui width 1 */
  if (a4 == 0) goto L_0398;  /* 02f8: beqz a4, 398 <mesh_process_mgmt_announce+0x314> */
  L_02fb: goto L_0390;  /* 02fb: j */
  L_0300: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0300: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0303 */
  if (a3 == 0) goto L_0390;  /* 0305: beqz a3, 390 <mesh_process_mgmt_announce+0x30c> */
  L_0308: a4 = LD32(a3 + 0x150);  /* 0308 */
  if (a4 == 0) goto L_0390;  /* 030b: beqz a4, 390 <mesh_process_mgmt_announce+0x30c> */
  L_030e: a10 = LD32(a3 + 0x158);  /* 030e */
  ST32(a1 + 0x1b4, a14);  /* 0311 */
  __asm__ volatile("" ::: "memory");  /* 0314: memw */
  /* 0317: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 031a */
  a10 = LD8U(a2 + 0x0);  /* 031c */
  a8 = (u32)&opt_type2str + 0x0;  /* 031f: l32r -> global */
  a2 = opt_type2str(a2, a3, a4, a5);  /* 0322: callx a8 via reloc-expand */
  a13 = a3;  /* 0325 */
  a14 = LD32(a1 + 0x1b4);  /* 0327 */
  a5 = LD8U(a14 + 0x5);  /* 032a */
  ST32(a1 + 0x38, a5);  /* 032d */
  a5 = LD8U(a14 + 0x4);  /* 032f */
  ST32(a1 + 0x34, a5);  /* 0332 */
  a5 = LD8U(a14 + 0x3);  /* 0334 */
  ST32(a1 + 0x30, a5);  /* 0337 */
  a5 = LD8U(a14 + 0x2);  /* 0339 */
  ST32(a1 + 0x2c, a5);  /* 033c */
  a5 = LD8U(a14 + 0x1);  /* 033e */
  ST32(a1 + 0x28, a5);  /* 0341 */
  a5 = LD8U(a14 + 0x0);  /* 0343 */
  ST32(a1 + 0x24, a5);  /* 0346 */
  a5 = LD8U(a6 + 0x5);  /* 0348 */
  ST32(a1 + 0x20, a5);  /* 034b */
  a5 = LD8U(a6 + 0x4);  /* 034d */
  ST32(a1 + 0x1c, a5);  /* 0350 */
  a5 = LD8U(a6 + 0x3);  /* 0352 */
  ST32(a1 + 0x18, a5);  /* 0355 */
  a5 = LD8U(a6 + 0x2);  /* 0357 */
  ST32(a1 + 0x14, a5);  /* 035a */
  a5 = LD8U(a6 + 0x1);  /* 035c */
  ST32(a1 + 0x10, a5);  /* 035f */
  a5 = LD8U(a6 + 0x0);  /* 0361 */
  ST32(a1 + 0xc, a5);  /* 0364 */
  a5 = LD8U(a2 + 0x1);  /* 0366 */
  a2 = LD8U(a2 + 0x2);  /* 0369 */
  a2 = a2 << 8;  /* 036c */
  a2 = a2 | a5;  /* 036f */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0372: -> "mesh_main.c" */
  a14 = a11;  /* 0375 */
  ST32(a1 + 0x8, a2);  /* 0377 */
  a2 = 0x521;  /* 0379 */
  ST32(a1 + 0x4, a10);  /* 037c */
  a10 = 2;  /* 037e */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0381: -> "mesh_main.c" */
  ST32(a1 + 0x0, a2);  /* 0384 */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_announce_str1_1 + 0x0);  /* 0387: -> "add" */
  __asm__ volatile("" ::: "memory");  /* 038a: memw */
  /* 038d: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_0390: a7 = 0x00004015u;  /* 0390: l32r = 16405 */
  goto L_0435;  /* 0393: j */
  L_0398: a8 = LD32(a1 + 0x1b0);  /* 0398 */
  a4 = a8 + (1);  /* 039b */
  a4 = (a4 >> 16) & 0x1;  /* 039d: extui width 1 */
  a5 = LD16U(a5 + 0x0);  /* 03a0 */
  if (a4 >= a5) goto L_0390;  /* 03a3: bgeu a4, a5, 390 <mesh_process_mgmt_announce+0x30c> */
  L_03a6: a6 = (u32)&g_mesh_topology + 0x0;  /* 03a6: l32r -> global */
  a5 = LD32(a6 + 0x0);  /* 03a9 */
  ST8(a3 + 0x0, a4);  /* 03ab */
  __asm__ volatile("" ::: "memory");  /* 03ae: memw */
  if (a5 != 0) goto L_03b9;  /* 03b1: bnez.n a5, 3b9 <mesh_process_mgmt_announce+0x335> */
  L_03b3: __asm__ volatile("" ::: "memory");  /* 03b3: memw */
  goto L_03c2;  /* 03b6: j */
  L_03b9: a6 = a4 >> 8;  /* 03b9 */
  ST8(a3 + 0x1, a6);  /* 03bc */
  __asm__ volatile("" ::: "memory");  /* 03bf: memw */
  L_03c2: a2 = LD8U(a2 + 0x0);  /* 03c2 */
  if (a2 != 3) goto L_0418;  /* 03c5: bnei a2, 3, 418 <mesh_process_mgmt_announce+0x394> */
  L_03c8: if (a5 != 0) goto L_03f5;  /* 03c8: bnez.n a5, 3f5 <mesh_process_mgmt_announce+0x371> */
  L_03ca: a2 = 151;  /* 03ca */
  ST8(a3 + 0x99, a4);  /* 03cd */
  __asm__ volatile("" ::: "memory");  /* 03d0: memw */
  __asm__ volatile("" ::: "memory");  /* 03d3: memw */
  a8 = (u32)&esp_mesh_get_total_children_num + 0x0;  /* 03d6: l32r -> global */
  a2 = esp_mesh_get_total_children_num(a2, a3, a4, a5);  /* 03d9: callx a8 via reloc-expand */
  a10 = a10 + (1);  /* 03dc */
  a2 = a3 + a2;  /* 03de */
  ST8(a2 + 0x0, a10);  /* 03e0 */
  a10 = (a10 >> 8) & 0x1ff;  /* 03e3: extui width 9 */
  ST8(a2 + 0x1, a10);  /* 03e6 */
  __asm__ volatile("" ::: "memory");  /* 03e9: memw */
  __asm__ volatile("" ::: "memory");  /* 03ec: memw */
  goto L_0418;  /* 03ef: j */
  L_03f5: a2 = a4 >> 8;  /* 03f5 */
  ST8(a3 + 0xa, a4);  /* 03f8 */
  ST8(a3 + 0xb, a2);  /* 03fb */
  __asm__ volatile("" ::: "memory");  /* 03fe: memw */
  __asm__ volatile("" ::: "memory");  /* 0401: memw */
  a8 = (u32)&esp_mesh_get_total_children_num + 0x0;  /* 0404: l32r -> global */
  a2 = esp_mesh_get_total_children_num(a2, a3, a4, a5);  /* 0407: callx a8 via reloc-expand */
  a10 = a10 + (1);  /* 040a */
  ST8(a3 + 0x8, a10);  /* 040c */
  a10 = (a10 >> 8) & 0x1ff;  /* 040f: extui width 9 */
  ST8(a3 + 0x9, a10);  /* 0412 */
  __asm__ volatile("" ::: "memory");  /* 0415: memw */
  L_0418: a8 = (u32)&g_mesh_topology + 0x0;  /* 0418: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 041b */
  if (a2 != 0) goto L_0435;  /* 041d: bnez.n a2, 435 <mesh_process_mgmt_announce+0x3b1> */
  L_041f: a4 = a4 + (a4 << 1);  /* 041f */
  a10 = a4 + (a3 << 1);  /* 0422 */
  a11 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 0425: l32r -> global */
  a12 = 6;  /* 0428 */
  a10 = a10 + (1);  /* 042a */
  __asm__ volatile("" ::: "memory");  /* 042c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 042f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 0432: callx a8 (libc, via reloc-expand) */
  L_0435: a2 = a7;  /* 0435 */
  return a2;  /* 0437: retw.n */
}


/* mesh_process_mgmt_root_switch @ mesh_main.o 00000048 size 314B bind GLOBAL
 * Calls: memset, memcpy, esp_mesh_send_root_switch, esp_mesh_push_to_nwk_queue | indirect[5]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_is_root_fixed, g_mesh_ext_vote_state, g_mesh_ie, g_mesh_is_root
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=13); reloc-direct=4, funcdb-attributed=0, unknown-indirect=5 */
u32 mesh_process_mgmt_root_switch(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F8;
  /* 0048: entry a1, 240 (frame 240 bytes) */
  a8 = (u32)&g_is_mesh_started + 0x0;  /* 004b: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 004e */
  if (a8 != 0) goto L_0088;  /* 0051: bnez.n a8, 88 <mesh_process_mgmt_root_switch+0x40> */
  L_0053: a2 = (u32)&g_log_level + 0x0;  /* 0053: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0056 */
  a2 = 0x00004004u;  /* 0058: l32r = 16388 */
  if (a3 >= 3u) goto L_0061;  /* 005b: bgeui a3, 3, 61 <mesh_process_mgmt_root_switch+0x19> */
  L_005e: goto L_0180;  /* 005e: j */
  L_0061: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0061: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0064 */
  if (a8 == 0) goto L_0180;  /* 0066: beqz a8, 180 <mesh_process_mgmt_root_switch+0x138> */
  L_0069: a3 = LD32(a8 + 0x150);  /* 0069 */
  if (a3 == 0) goto L_0180;  /* 006c: beqz a3, 180 <mesh_process_mgmt_root_switch+0x138> */
  L_006f: a10 = LD32(a8 + 0x158);  /* 006f */
  /* 0072: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0075 */
  a10 = 3;  /* 0077 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0079: -> "mesh_main.c" */
  a14 = a11;  /* 007c */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 007e: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 0081: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0180;  /* 0084: j */
  L_0088: if (a2 != 0) goto L_00b5;  /* 0088: bnez.n a2, b5 <mesh_process_mgmt_root_switch+0x6d> */
  L_008a: a2 = (u32)&g_log_level + 0x0;  /* 008a: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 008d */
  a2 = 0x00004008u;  /* 008f: l32r = 16392 */
  if (a3 >= 3u) goto L_0098;  /* 0092: bgeui a3, 3, 98 <mesh_process_mgmt_root_switch+0x50> */
  L_0095: goto L_0180;  /* 0095: j */
  L_0098: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0098: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 009b */
  if (a8 == 0) goto L_0180;  /* 009d: beqz a8, 180 <mesh_process_mgmt_root_switch+0x138> */
  L_00a0: a3 = LD32(a8 + 0x150);  /* 00a0 */
  if (a3 == 0) goto L_0180;  /* 00a3: beqz a3, 180 <mesh_process_mgmt_root_switch+0x138> */
  L_00a6: a10 = LD32(a8 + 0x158);  /* 00a6 */
  /* 00a9: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x4a8;  /* 00ac */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00af: -> "mesh_main.c" */
  goto L_00df;  /* 00b2: j */
  L_00b5: if (a3 != 0) goto L_00f8;  /* 00b5: bnez.n a3, f8 <mesh_process_mgmt_root_switch+0xb0> */
  L_00b7: a2 = (u32)&g_log_level + 0x0;  /* 00b7: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ba */
  a2 = 0x00004008u;  /* 00bc: l32r = 16392 */
  if (a3 >= 3u) goto L_00c5;  /* 00bf: bgeui a3, 3, c5 <mesh_process_mgmt_root_switch+0x7d> */
  L_00c2: goto L_0180;  /* 00c2: j */
  L_00c5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00c5: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00c8 */
  if (a8 == 0) goto L_0180;  /* 00ca: beqz a8, 180 <mesh_process_mgmt_root_switch+0x138> */
  L_00cd: a3 = LD32(a8 + 0x150);  /* 00cd */
  if (a3 == 0) goto L_0180;  /* 00d0: beqz a3, 180 <mesh_process_mgmt_root_switch+0x138> */
  L_00d3: a10 = LD32(a8 + 0x158);  /* 00d3 */
  /* 00d6: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x4a9;  /* 00d9 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00dc: -> "mesh_main.c" */
  L_00df: a13 = a10;  /* 00df */
  a14 = a11;  /* 00e1 */
  a10 = 3;  /* 00e3 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00e5: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00e8: -> "mesh_main.c" */
  ST32(a1 + 0x0, a8);  /* 00eb */
  __asm__ volatile("" ::: "memory");  /* 00ee: memw */
  /* 00f1: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0180;  /* 00f4: j */
  L_00f8: a12 = 184;  /* 00f8 */
  a11 = 0;  /* 00fb */
  a10 = a1 + (16);  /* 00fd */
  a8 = (u32)&memset + 0x0;  /* 0100: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0103: callx a8 (libc, via reloc-expand) */
  a12 = 8;  /* 0106 */
  a11 = a3;  /* 0108: mov */
  a10 = a1 + (24);  /* 010b */
  a8 = (u32)&memcpy + 0x0;  /* 010e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0111: callx a8 (libc, via reloc-expand) */
  a2 = LD8U(a1 + 0x18);  /* 0114 */
  if (a2 != 1) goto L_0148;  /* 0117: bnei a2, 1, 148 <mesh_process_mgmt_root_switch+0x100> */
  L_011a: a2 = (u32)&g_is_root_fixed + 0x0;  /* 011a: l32r -> global */
  a8 = LD8U(a2 + 0x0);  /* 011d */
  if (a8 != 0) goto L_013c;  /* 0120: bnez.n a8, 13c <mesh_process_mgmt_root_switch+0xf4> */
  L_0122: a3 = 4;  /* 0122 */
  a9 = (u32)&g_mesh_ext_vote_state + 0x0;  /* 0124: l32r -> global */
  a2 = LD8U(a9 + 0x0);  /* 0127 */
  a2 = a2 | a3;  /* 012a */
  ST8(a9 + 0x0, a2);  /* 012d */
  __asm__ volatile("" ::: "memory");  /* 0130: memw */
  a2 = (u32)&g_mesh_ie + 0x0;  /* 0133: l32r -> global */
  ST8(a2 + 0x32, a8);  /* 0136 */
  __asm__ volatile("" ::: "memory");  /* 0139: memw */
  L_013c: a2 = 34;  /* 013c */
  ST32(a1 + 0x10, a2);  /* 013e */
  a2 = 2;  /* 0140 */
  __asm__ volatile("" ::: "memory");  /* 0142: memw */
  goto L_016c;  /* 0145: j */
  L_0148: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0148: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 014b: memw */
  a8 = LD8U(a2 + 0x0);  /* 014e */
  a8 = (a8 >> 8) & 0x1;  /* 0151: extui width 1 */
  a2 = 0x00004015u;  /* 0154: l32r = 16405 */
  if (a8 == 0) goto L_0180;  /* 0157: beqz.n a8, 180 <mesh_process_mgmt_root_switch+0x138> */
  L_0159: a12 = 1;  /* 0159 */
  a2 = 32;  /* 015b */
  a11 = a12;  /* 015d */
  a10 = a1 + (26);  /* 015f */
  a8 = (u32)&esp_mesh_send_root_switch + 0x0;  /* 0162: l32r -> global */
  a2 = esp_mesh_send_root_switch(a2, a3, a4, a5, a6, a7);  /* 0165: callx a8 via reloc-expand */
  ST32(a1 + 0x10, a2);  /* 0168 */
  a2 = 5;  /* 016a */
  L_016c: a11 = 0;  /* 016c */
  a10 = a1 + (16);  /* 016e */
  ST32(a1 + 0x14, a2);  /* 0171 */
  __asm__ volatile("" ::: "memory");  /* 0174: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 0177: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 017a: callx a8 via reloc-expand */
  a2 = 0x00004015u;  /* 017d: l32r = 16405 */
  L_0180: return a2;  /* 0180: retw.n */
}


/* mesh_process_mgmt_root_waive @ mesh_main.o 00000050 size 402B bind GLOBAL
 * Calls: memset, memcpy, esp_mesh_push_to_nwk_queue, __extendsfdf2 | indirect[9]: mem[a8+0x158]; mem[a8+0x150]; mem[a2+0x158]; unknown | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, g_mesh_ext_vote_state, .rodata.mesh_process_mgmt_root_waive.str1.1
 * Fidelity: medium - 9 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=11); reloc-direct=4, funcdb-attributed=0, unknown-indirect=9 */
u32 mesh_process_mgmt_root_waive(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  float F0, F1;
  u32 BOOL_b0; /* boolean special-regs (FP compare results) */
  /* 0050: entry a1, 0x100 (frame 0x100 bytes) */
  a4 = (u32)&g_is_mesh_started + 0x0;  /* 0053: l32r -> global */
  a4 = LD8U(a4 + 0x0);  /* 0056 */
  if (a4 != 0) goto L_0091;  /* 0059: bnez.n a4, 91 <mesh_process_mgmt_root_waive+0x41> */
  L_005b: a2 = (u32)&g_log_level + 0x0;  /* 005b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005e */
  a2 = 0x00004004u;  /* 0060: l32r = 16388 */
  if (a3 >= 3u) goto L_0069;  /* 0063: bgeui a3, 3, 69 <mesh_process_mgmt_root_waive+0x19> */
  L_0066: goto L_01e0;  /* 0066: j */
  L_0069: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0069: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 006c */
  if (a8 == 0) goto L_01e0;  /* 006e: beqz a8, 1e0 <mesh_process_mgmt_root_waive+0x190> */
  L_0071: a3 = LD32(a8 + 0x150);  /* 0071 */
  if (a3 == 0) goto L_01e0;  /* 0074: beqz a3, 1e0 <mesh_process_mgmt_root_waive+0x190> */
  L_0077: a10 = LD32(a8 + 0x158);  /* 0077 */
  /* 007a: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 007d */
  a10 = 3;  /* 007f */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0081: -> "mesh_main.c" */
  a14 = a11;  /* 0084 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 0086: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 0089: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_01e0;  /* 008c: j */
  L_0091: if (a2 != 0) goto L_00be;  /* 0091: bnez.n a2, be <mesh_process_mgmt_root_waive+0x6e> */
  L_0093: a2 = (u32)&g_log_level + 0x0;  /* 0093: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0096 */
  a2 = 0x00004008u;  /* 0098: l32r = 16392 */
  if (a3 >= 3u) goto L_00a1;  /* 009b: bgeui a3, 3, a1 <mesh_process_mgmt_root_waive+0x51> */
  L_009e: goto L_01e0;  /* 009e: j */
  L_00a1: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a1: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00a4 */
  if (a8 == 0) goto L_01e0;  /* 00a6: beqz a8, 1e0 <mesh_process_mgmt_root_waive+0x190> */
  L_00a9: a3 = LD32(a8 + 0x150);  /* 00a9 */
  if (a3 == 0) goto L_01e0;  /* 00ac: beqz a3, 1e0 <mesh_process_mgmt_root_waive+0x190> */
  L_00af: a4 = 0x4cf;  /* 00af */
  a10 = LD32(a8 + 0x158);  /* 00b2 */
  /* 00b5: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00b8: -> "mesh_main.c" */
  goto L_00e8;  /* 00bb: j */
  L_00be: if (a3 != 0) goto L_0101;  /* 00be: bnez.n a3, 101 <mesh_process_mgmt_root_waive+0xb1> */
  L_00c0: a2 = (u32)&g_log_level + 0x0;  /* 00c0: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c3 */
  a2 = 0x00004008u;  /* 00c5: l32r = 16392 */
  if (a3 >= 3u) goto L_00ce;  /* 00c8: bgeui a3, 3, ce <mesh_process_mgmt_root_waive+0x7e> */
  L_00cb: goto L_01e0;  /* 00cb: j */
  L_00ce: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00ce: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00d1 */
  if (a8 == 0) goto L_01e0;  /* 00d3: beqz a8, 1e0 <mesh_process_mgmt_root_waive+0x190> */
  L_00d6: a3 = LD32(a8 + 0x150);  /* 00d6 */
  if (a3 == 0) goto L_01e0;  /* 00d9: beqz a3, 1e0 <mesh_process_mgmt_root_waive+0x190> */
  L_00dc: a4 = 0x4d0;  /* 00dc */
  a10 = LD32(a8 + 0x158);  /* 00df */
  /* 00e2: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00e5: -> "mesh_main.c" */
  L_00e8: a13 = a10;  /* 00e8 */
  a14 = a11;  /* 00ea */
  a10 = 3;  /* 00ec */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00ee: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00f1: -> "mesh_main.c" */
  ST32(a1 + 0x0, a4);  /* 00f4 */
  __asm__ volatile("" ::: "memory");  /* 00f6: memw */
  /* 00f9: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_01e0;  /* 00fc: j */
  L_0101: a12 = 184;  /* 0101 */
  a11 = 0;  /* 0104 */
  a10 = a1 + (32);  /* 0107 */
  a8 = (u32)&memset + 0x0;  /* 010a: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 010d: callx a8 (libc, via reloc-expand) */
  a12 = 24;  /* 0110 */
  a11 = a3;  /* 0112 */
  a10 = a1 + (36);  /* 0114 */
  a8 = (u32)&memcpy + 0x0;  /* 0117: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 011a: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&g_mesh_ext_vote_state + 0x0;  /* 011d: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0120 */
  if (((a2 >> 0) & 1) == 0) goto L_0132;  /* 0123: bbci a2, 0, 132 <mesh_process_mgmt_root_waive+0xe2> */
  L_0126: a3 = LD32(a1 + 0x34);  /* 0126 */
  a2 = 0x00004016u;  /* 0129: l32r = 16406 */
  if (a3 == 2) goto L_0132;  /* 012c: beqi a3, 2, 132 <mesh_process_mgmt_root_waive+0xe2> */
  L_012f: goto L_01e0;  /* 012f: j */
  L_0132: a2 = 31;  /* 0132 */
  a11 = 0;  /* 0134 */
  a10 = a1 + (32);  /* 0136 */
  ST32(a1 + 0x20, a2);  /* 0139 */
  a2 = 1;  /* 013b */
  ST32(a1 + 0x38, a2);  /* 013d */
  __asm__ volatile("" ::: "memory");  /* 013f: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 0142: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 0145: callx a8 via reloc-expand */
  a2 = 0x00000000u;  /* 0148: l32r = 0 */
  F1 = u2f(a2);  /* 014b: wfr (bitcast u32->float) */
  F0 = LD32F(a1 + 0x24);  /* 014e: lsi */
  BOOL_b0 = (F0 == F1);  /* 0151: oeq.s (false if unordered/NaN) */
  if (BOOL_b0) goto L_015c;  /* 0154: bt b0, 15c <mesh_process_mgmt_root_waive+0x10c> (boolean reg) */
  goto L_01de;  /* 0157: j */
  L_015c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 015c: l32r -> global */
  a2 = LD32(a3 + 0x0);  /* 015f */
  if (a2 == 0) goto L_01b2;  /* 0161: beqz a2, 1b2 <mesh_process_mgmt_root_waive+0x162> */
  L_0164: a4 = LD32(a2 + 0x150);  /* 0164 */
  if (a4 == 0) goto L_01b2;  /* 0167: beqz a4, 1b2 <mesh_process_mgmt_root_waive+0x162> */
  L_016a: a10 = LD32(a2 + 0x158);  /* 016a */
  /* 016d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a6 = a10;  /* 0170 */
  a2 = LD8U(a1 + 0x28);  /* 0172 */
  a5 = (u32)(RODATA__rodata_mesh_process_mgmt_root_waive_str1_1 + 0x0);  /* 0175: -> "rc specified, " */
  if (a2 != 0) goto L_017d;  /* 0178: bnez.n a2, 17d <mesh_process_mgmt_root_waive+0x12d> */
  L_017a: a5 = (u32)(RODATA__rodata_mesh_process_mgmt_root_waive_str1_1 + 0x0);  /* 017a: -> "rc specified, " */
  L_017d: a8 = LD32(a1 + 0x34);  /* 017d */
  a10 = LD32(a1 + 0x24);  /* 017f */
  ST32(a1 + 0x18, a8);  /* 0181 */
  __asm__ volatile("" ::: "memory");  /* 0183: memw */
  a8 = (u32)&__extendsfdf2 + 0x0;  /* 0186: l32r -> global */
  a2 = __extendsfdf2(a2, a3, a4, a5, a6, a7);  /* 0189: callx a8 via reloc-expand */
  a13 = a6;  /* 018c */
  a2 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 018e: -> "mesh_main.c" */
  a14 = a2;  /* 0191 */
  a8 = LD32(a1 + 0x2c);  /* 0193 */
  ST32(a1 + 0x4, a5);  /* 0195 */
  a5 = 0x4dc;  /* 0197 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 019a: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_root_waive_str1_1 + 0x0);  /* 019d: -> "rc specified, " */
  ST32(a1 + 0x10, a10);  /* 01a0 */
  a10 = 2;  /* 01a2 */
  ST32(a1 + 0x14, a11);  /* 01a4 */
  a11 = a2;  /* 01a6 */
  ST32(a1 + 0x8, a8);  /* 01a8 */
  ST32(a1 + 0x0, a5);  /* 01aa */
  __asm__ volatile("" ::: "memory");  /* 01ac: memw */
  /* 01af: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_01b2: a2 = LD32(a3 + 0x0);  /* 01b2 */
  if (a2 == 0) goto L_01de;  /* 01b4: beqz a2, 1de <mesh_process_mgmt_root_waive+0x18e> */
  L_01b7: a3 = LD32(a2 + 0x150);  /* 01b7 */
  if (a3 == 0) goto L_01de;  /* 01ba: beqz a3, 1de <mesh_process_mgmt_root_waive+0x18e> */
  L_01bd: a10 = LD32(a2 + 0x158);  /* 01bd */
  a2 = 0x4e1;  /* 01c0 */
  /* 01c3: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01c6 */
  a10 = 1;  /* 01c8 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01ca: -> "mesh_main.c" */
  a14 = a11;  /* 01cd */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01cf: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_root_waive_str1_1 + 0x0);  /* 01d2: -> "rc specified, " */
  ST32(a1 + 0x0, a2);  /* 01d5 */
  __asm__ volatile("" ::: "memory");  /* 01d8: memw */
  /* 01db: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_01de: a2 = 0;  /* 01de */
  L_01e0: return a2;  /* 01e0: retw.n */
}


/* mesh_process_mgmt_routing_table @ mesh_main.o 00000074 size 898B bind GLOBAL
 * Calls: memset, opt_type2str, memcpy, esp_mesh_push_to_nwk_queue, esp_mesh_copy_mgmt_announce | indirect[15]: mem[a3+0x158]; mem[a3+0x150]; mem[a5+0x158]; unknown | Data refs: g_log_level, g_is_mesh_started, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1, .rodata.mesh_process_mgmt_routing_table.str1.1, .rodata.mesh_process_mgmt_root_waive.str1.1, g_mesh_max_layer, .rodata.mesh_process_mgmt_announce.str1.1
 * Fidelity: medium - 15 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=14); reloc-direct=5, funcdb-attributed=0, unknown-indirect=15 */
u32 mesh_process_mgmt_routing_table(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a6, a7, a8;
  /* 0074: entry a1, 0x1e0 (frame 0x1e0 bytes) */
  a6 = (u32)&g_log_level + 0x0;  /* 0077: l32r -> global */
  a7 = LD32(a6 + 0x0);  /* 007a */
  a6 = (u32)&g_is_mesh_started + 0x0;  /* 007c: l32r -> global */
  a6 = LD8U(a6 + 0x0);  /* 007f */
  if (a6 != 0) goto L_00b3;  /* 0082: bnez.n a6, b3 <mesh_process_mgmt_routing_table+0x3f> */
  L_0084: a2 = 0x00004004u;  /* 0084: l32r = 16388 */
  if (a7 >= 3u) goto L_008d;  /* 0087: bgeui a7, 3, 8d <mesh_process_mgmt_routing_table+0x19> */
  L_008a: goto L_03f4;  /* 008a: j */
  L_008d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 008d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0090 */
  if (a3 == 0) goto L_03f4;  /* 0092: beqz a3, 3f4 <mesh_process_mgmt_routing_table+0x380> */
  L_0095: a4 = LD32(a3 + 0x150);  /* 0095 */
  if (a4 == 0) goto L_03f4;  /* 0098: beqz a4, 3f4 <mesh_process_mgmt_routing_table+0x380> */
  L_009b: a10 = LD32(a3 + 0x158);  /* 009b */
  /* 009e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00a1 */
  a10 = 3;  /* 00a3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00a5: -> "mesh_main.c" */
  a14 = a11;  /* 00a8 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 00aa: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 00ad: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03f4;  /* 00b0: j */
  L_00b3: if (a2 != 0) goto L_00ed;  /* 00b3: bnez.n a2, ed <mesh_process_mgmt_routing_table+0x79> */
  L_00b5: a2 = 0x00004008u;  /* 00b5: l32r = 16392 */
  if (a7 >= 3u) goto L_00be;  /* 00b8: bgeui a7, 3, be <mesh_process_mgmt_routing_table+0x4a> */
  L_00bb: goto L_03f4;  /* 00bb: j */
  L_00be: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00be: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00c1 */
  if (a3 == 0) goto L_03f4;  /* 00c3: beqz a3, 3f4 <mesh_process_mgmt_routing_table+0x380> */
  L_00c6: a4 = LD32(a3 + 0x150);  /* 00c6 */
  if (a4 == 0) goto L_03f4;  /* 00c9: beqz a4, 3f4 <mesh_process_mgmt_routing_table+0x380> */
  L_00cc: a10 = LD32(a3 + 0x158);  /* 00cc */
  a3 = 0x558;  /* 00cf */
  /* 00d2: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00d5 */
  a10 = 3;  /* 00d7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00d9: -> "mesh_main.c" */
  a14 = a11;  /* 00dc */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00de: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00e1: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 00e4 */
  __asm__ volatile("" ::: "memory");  /* 00e6: memw */
  goto L_01ce;  /* 00e9: j */
  L_00ed: a12 = 184;  /* 00ed */
  a11 = 0;  /* 00f0 */
  a10 = a1 + (64);  /* 00f3 */
  a8 = (u32)&memset + 0x0;  /* 00f6: l32r -> global */
  a2 = memset(a2, a3, a4, a5);  /* 00f9: callx a8 (libc, via reloc-expand) */
  a6 = LD8U(a2 + 0x2);  /* 00fc */
  a6 = a6 << 8;  /* 00ff */
  a8 = LD8U(a2 + 0x1);  /* 0102 */
  a6 = a6 | a8;  /* 0105 */
  if (a6 != 0) goto L_01d9;  /* 0108: bnez a6, 1d9 <mesh_process_mgmt_routing_table+0x165> */
  L_010b: if (a7 < 3u) goto L_0170;  /* 010b: bltui a7, 3, 170 <mesh_process_mgmt_routing_table+0xfc> */
  L_010e: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 010e: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 0111 */
  if (a5 == 0) goto L_0170;  /* 0113: beqz a5, 170 <mesh_process_mgmt_routing_table+0xfc> */
  L_0116: a6 = LD32(a5 + 0x150);  /* 0116 */
  if (a6 == 0) goto L_0170;  /* 0119: beqz a6, 170 <mesh_process_mgmt_routing_table+0xfc> */
  L_011c: a10 = LD32(a5 + 0x158);  /* 011c */
  /* 011f: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 0122: mov */
  a10 = LD8U(a2 + 0x0);  /* 0125 */
  a8 = (u32)&opt_type2str + 0x0;  /* 0128: l32r -> global */
  a2 = opt_type2str(a2, a3, a4, a5);  /* 012b: callx a8 via reloc-expand */
  a15 = a10;  /* 012e */
  a13 = a5;  /* 0130 */
  a7 = LD8U(a4 + 0x5);  /* 0132 */
  a10 = 3;  /* 0135 */
  ST32(a1 + 0x1c, a7);  /* 0137 */
  a7 = LD8U(a4 + 0x4);  /* 0139 */
  ST32(a1 + 0x18, a7);  /* 013c */
  a7 = LD8U(a4 + 0x3);  /* 013e */
  ST32(a1 + 0x14, a7);  /* 0141 */
  a7 = LD8U(a4 + 0x2);  /* 0143 */
  ST32(a1 + 0x10, a7);  /* 0146 */
  a7 = LD8U(a4 + 0x1);  /* 0148 */
  ST32(a1 + 0xc, a7);  /* 014b */
  a7 = LD8U(a4 + 0x0);  /* 014d */
  ST32(a1 + 0x4, a3);  /* 0150 */
  ST32(a1 + 0x8, a7);  /* 0152 */
  a3 = LD8U(a2 + 0x1);  /* 0154 */
  a2 = LD8U(a2 + 0x2);  /* 0157 */
  a2 = a2 << 8;  /* 015a */
  a2 = a2 | a3;  /* 015d */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0160: -> "mesh_main.c" */
  a14 = a11;  /* 0163 */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_routing_table_str1_1 + 0x0);  /* 0165: l32r -> .rodata.mesh_process_mgmt_routing_table.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0168 */
  __asm__ volatile("" ::: "memory");  /* 016a: memw */
  /* 016d: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_0170: a2 = 19;  /* 0170 */
  a12 = 6;  /* 0172 */
  a11 = a4;  /* 0174 */
  ST32(a1 + 0x40, a2);  /* 0176 */
  a3 = 0;  /* 0179 */
  a2 = 1;  /* 017b */
  a10 = a1 + (74);  /* 017d */
  ST8(a1 + 0x44, a2);  /* 0180 */
  ST8(a1 + 0x50, a2);  /* 0183 */
  ST8(a1 + 0x46, a3);  /* 0186 */
  __asm__ volatile("" ::: "memory");  /* 0189: memw */
  __asm__ volatile("" ::: "memory");  /* 018c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 018f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 0192: callx a8 (libc, via reloc-expand) */
  a11 = 0;  /* 0195 */
  a10 = a1 + (64);  /* 0197 */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 019a: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5);  /* 019d: callx a8 via reloc-expand */
  a2 = 0x00004015u;  /* 01a0: l32r = 16405 */
  if (a10 == 0) goto L_03f4;  /* 01a3: beqz a10, 3f4 <mesh_process_mgmt_routing_table+0x380> */
  L_01a6: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 01a6: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 01a9 */
  if (a3 == 0) goto L_03f4;  /* 01ab: beqz a3, 3f4 <mesh_process_mgmt_routing_table+0x380> */
  L_01ae: a4 = LD32(a3 + 0x150);  /* 01ae */
  if (a4 == 0) goto L_03f4;  /* 01b1: beqz a4, 3f4 <mesh_process_mgmt_routing_table+0x380> */
  L_01b4: a10 = LD32(a3 + 0x158);  /* 01b4 */
  a3 = 0x565;  /* 01b7 */
  /* 01ba: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01bd */
  a10 = 1;  /* 01bf */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01c1: -> "mesh_main.c" */
  a14 = a11;  /* 01c4 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 01c6: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_root_waive_str1_1 + 0x0);  /* 01c9: -> "rc specified, " */
  ST32(a1 + 0x0, a3);  /* 01cc */
  L_01ce: __asm__ volatile("" ::: "memory");  /* 01ce: memw */
  /* 01d1: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03f4;  /* 01d4: j */
  L_01d9: if (a7 < 3u) goto L_0245;  /* 01d9: bltui a7, 3, 245 <mesh_process_mgmt_routing_table+0x1d1> */
  L_01dc: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 01dc: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 01df */
  if (a6 == 0) goto L_0245;  /* 01e1: beqz a6, 245 <mesh_process_mgmt_routing_table+0x1d1> */
  L_01e4: a7 = LD32(a6 + 0x150);  /* 01e4 */
  if (a7 == 0) goto L_0245;  /* 01e7: beqz a7, 245 <mesh_process_mgmt_routing_table+0x1d1> */
  L_01ea: a10 = LD32(a6 + 0x158);  /* 01ea */
  /* 01ed: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01f0 */
  a10 = LD8U(a2 + 0x0);  /* 01f2 */
  ST32(a1 + 0x1b0, a13);  /* 01f5 */
  __asm__ volatile("" ::: "memory");  /* 01f8: memw */
  a8 = (u32)&opt_type2str + 0x0;  /* 01fb: l32r -> global */
  a2 = opt_type2str(a2, a3, a4, a5);  /* 01fe: callx a8 via reloc-expand */
  a15 = a10;  /* 0201 */
  a10 = 3;  /* 0203 */
  a6 = LD8U(a2 + 0x2);  /* 0205 */
  a6 = a6 << 8;  /* 0208 */
  a8 = LD8U(a2 + 0x1);  /* 020b */
  a6 = a6 | a8;  /* 020e */
  ST32(a1 + 0x18, a6);  /* 0211 */
  a6 = LD8U(a4 + 0x5);  /* 0213 */
  ST32(a1 + 0x14, a6);  /* 0216 */
  a6 = LD8U(a4 + 0x4);  /* 0218 */
  ST32(a1 + 0x10, a6);  /* 021b */
  a6 = LD8U(a4 + 0x3);  /* 021d */
  ST32(a1 + 0xc, a6);  /* 0220 */
  a6 = LD8U(a4 + 0x2);  /* 0222 */
  ST32(a1 + 0x8, a6);  /* 0225 */
  a6 = LD8U(a4 + 0x1);  /* 0227 */
  ST32(a1 + 0x4, a6);  /* 022a */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 022d: -> "mesh_main.c" */
  a14 = a11;  /* 0230: mov */
  a6 = LD8U(a4 + 0x0);  /* 0233 */
  a13 = LD32(a1 + 0x1b0);  /* 0236 */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_routing_table_str1_1 + 0x0);  /* 0239: l32r -> .rodata.mesh_process_mgmt_routing_table.str1.1 */
  ST32(a1 + 0x0, a6);  /* 023c */
  __asm__ volatile("" ::: "memory");  /* 023f: memw */
  /* 0242: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_0245: if (a3 == 0) goto L_03f1;  /* 0245: beqz a3, 3f1 <mesh_process_mgmt_routing_table+0x37d> */
  L_0248: a6 = (u32)&g_mesh_max_layer + 0x0;  /* 0248: l32r -> global */
  a8 = LD8U(a3 + 0x0);  /* 024b */
  a7 = LD16U(a6 + 0x0);  /* 024e */
  if (a8 < a7) goto L_02bc;  /* 0251: bltu a8, a7, 2bc <mesh_process_mgmt_routing_table+0x248> */
  L_0254: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0254: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0257 */
  if (a4 == 0) goto L_03f1;  /* 025a: beqz a4, 3f1 <mesh_process_mgmt_routing_table+0x37d> */
  L_025d: a7 = LD32(a4 + 0x150);  /* 025d */
  if (a7 == 0) goto L_03f1;  /* 0260: beqz a7, 3f1 <mesh_process_mgmt_routing_table+0x37d> */
  L_0263: a10 = LD32(a4 + 0x158);  /* 0263 */
  /* 0266: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 0269 */
  a10 = LD8U(a2 + 0x0);  /* 026b */
  a8 = (u32)&opt_type2str + 0x0;  /* 026e: l32r -> global */
  a2 = opt_type2str(a2, a3, a4, a5);  /* 0271: callx a8 via reloc-expand */
  a13 = a4;  /* 0274 */
  a2 = LD8U(a5 + 0x5);  /* 0276 */
  ST32(a1 + 0x24, a2);  /* 0279 */
  a2 = LD8U(a5 + 0x4);  /* 027b */
  ST32(a1 + 0x20, a2);  /* 027e */
  a2 = LD8U(a5 + 0x3);  /* 0280 */
  ST32(a1 + 0x1c, a2);  /* 0283 */
  a2 = LD8U(a5 + 0x2);  /* 0285 */
  ST32(a1 + 0x18, a2);  /* 0288 */
  a2 = LD8U(a5 + 0x1);  /* 028a */
  ST32(a1 + 0x14, a2);  /* 028d */
  a2 = LD8U(a5 + 0x0);  /* 028f */
  ST32(a1 + 0x10, a2);  /* 0292 */
  a2 = LD16U(a6 + 0x0);  /* 0294 */
  ST32(a1 + 0xc, a2);  /* 0297 */
  a2 = LD8U(a3 + 0x0);  /* 0299 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 029c: -> "mesh_main.c" */
  a14 = a11;  /* 029f */
  ST32(a1 + 0x8, a2);  /* 02a1 */
  a2 = 0x570;  /* 02a3 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 02a6: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_routing_table_str1_1 + 0x0);  /* 02a9: l32r -> .rodata.mesh_process_mgmt_routing_table.str1.1 */
  ST32(a1 + 0x4, a10);  /* 02ac */
  a10 = 2;  /* 02ae */
  ST32(a1 + 0x0, a2);  /* 02b0 */
  __asm__ volatile("" ::: "memory");  /* 02b2: memw */
  /* 02b5: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  goto L_03f1;  /* 02b8: j */
  L_02bc: a8 = a1 + (64);  /* 02bc */
  a6 = 184;  /* 02bf */
  a6 = a8 + a6;  /* 02c2 */
  a12 = 177;  /* 02c4 */
  a11 = 0;  /* 02c7 */
  a10 = a6;  /* 02c9 */
  a8 = (u32)&memset + 0x0;  /* 02cb: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 02ce: callx a8 (libc, via reloc-expand) */
  a11 = a3;  /* 02d1 */
  a12 = a6;  /* 02d3 */
  a10 = a2;  /* 02d5 */
  a8 = (u32)&esp_mesh_copy_mgmt_announce + 0x0;  /* 02d7: l32r -> global */
  a2 = esp_mesh_copy_mgmt_announce(a2, a3, a4, a5);  /* 02da: callx a8 via reloc-expand */
  a3 = a10;  /* 02dd */
  if (a10 != 0) goto L_0369;  /* 02df: bnez a10, 369 <mesh_process_mgmt_routing_table+0x2f5> */
  L_02e2: a7 = 19;  /* 02e2 */
  ST32(a1 + 0x40, a7);  /* 02e5 */
  a12 = 6;  /* 02e8 */
  a11 = a4;  /* 02eb */
  a10 = a1 + 0x10000;  /* 02ed: addmi a10, a1, 0x100 */
  a7 = LD8U(a2 + 0x1);  /* 02f0 */
  a2 = LD8U(a2 + 0x2);  /* 02f3 */
  a2 = a2 << 8;  /* 02f6 */
  a2 = a2 | a7;  /* 02f9 */
  ST32(a1 + 0xfc, a2);  /* 02fc */
  __asm__ volatile("" ::: "memory");  /* 02ff: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0302: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 0305: callx a8 (libc, via reloc-expand) */
  a2 = a1 + (64);  /* 0308 */
  a10 = 198;  /* 030b */
  a12 = 6;  /* 030e */
  a11 = a5;  /* 0310 */
  a10 = a2 + a10;  /* 0312 */
  a8 = (u32)&memcpy + 0x0;  /* 0314: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 0317: callx a8 (libc, via reloc-expand) */
  a11 = a6;  /* 031a */
  a12 = 177;  /* 031c */
  a10 = a1 + (70);  /* 031f */
  a8 = (u32)&memcpy + 0x0;  /* 0322: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5);  /* 0325: callx a8 (libc, via reloc-expand) */
  a11 = a3;  /* 0328: mov */
  a10 = a2;  /* 032b: mov */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 032e: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5);  /* 0331: callx a8 via reloc-expand */
  if (a10 == 0) goto L_03f1;  /* 0334: beqz a10, 3f1 <mesh_process_mgmt_routing_table+0x37d> */
  L_0337: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0337: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 033a */
  if (a2 == 0) goto L_03f1;  /* 033c: beqz a2, 3f1 <mesh_process_mgmt_routing_table+0x37d> */
  L_033f: a3 = LD32(a2 + 0x150);  /* 033f */
  if (a3 == 0) goto L_03f1;  /* 0342: beqz a3, 3f1 <mesh_process_mgmt_routing_table+0x37d> */
  L_0345: a10 = LD32(a2 + 0x158);  /* 0345 */
  a2 = 0x57d;  /* 0348 */
  /* 034b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 034e */
  a10 = 1;  /* 0350 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0352: -> "mesh_main.c" */
  a14 = a11;  /* 0355 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0357: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_root_waive_str1_1 + 0x0);  /* 035a: -> "rc specified, " */
  ST32(a1 + 0x0, a2);  /* 035d */
  __asm__ volatile("" ::: "memory");  /* 035f: memw */
  /* 0362: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_03f1;  /* 0365: j */
  L_0369: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0369: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 036c */
  if (a3 == 0) goto L_03f1;  /* 036e: beqz a3, 3f1 <mesh_process_mgmt_routing_table+0x37d> */
  L_0371: a6 = LD32(a3 + 0x150);  /* 0371 */
  if (a6 == 0) goto L_03f1;  /* 0374: beqz a6, 3f1 <mesh_process_mgmt_routing_table+0x37d> */
  L_0377: a10 = LD32(a3 + 0x158);  /* 0377 */
  /* 037a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 037d */
  a10 = LD8U(a2 + 0x0);  /* 037f */
  a8 = (u32)&opt_type2str + 0x0;  /* 0382: l32r -> global */
  a2 = opt_type2str(a2, a3, a4, a5);  /* 0385: callx a8 via reloc-expand */
  a13 = a3;  /* 0388 */
  a7 = LD8U(a4 + 0x5);  /* 038a */
  ST32(a1 + 0x38, a7);  /* 038d */
  a7 = LD8U(a4 + 0x4);  /* 038f */
  ST32(a1 + 0x34, a7);  /* 0392 */
  a7 = LD8U(a4 + 0x3);  /* 0394 */
  ST32(a1 + 0x30, a7);  /* 0397 */
  a7 = LD8U(a4 + 0x2);  /* 0399 */
  ST32(a1 + 0x2c, a7);  /* 039c */
  a7 = LD8U(a4 + 0x1);  /* 039e */
  ST32(a1 + 0x28, a7);  /* 03a1 */
  a4 = LD8U(a4 + 0x0);  /* 03a3 */
  ST32(a1 + 0x24, a4);  /* 03a6 */
  a4 = LD8U(a5 + 0x5);  /* 03a8 */
  ST32(a1 + 0x20, a4);  /* 03ab */
  a4 = LD8U(a5 + 0x4);  /* 03ad */
  ST32(a1 + 0x1c, a4);  /* 03b0 */
  a4 = LD8U(a5 + 0x3);  /* 03b2 */
  ST32(a1 + 0x18, a4);  /* 03b5 */
  a4 = LD8U(a5 + 0x2);  /* 03b7 */
  ST32(a1 + 0x14, a4);  /* 03ba */
  a4 = LD8U(a5 + 0x1);  /* 03bc */
  ST32(a1 + 0x10, a4);  /* 03bf */
  a4 = LD8U(a5 + 0x0);  /* 03c1 */
  ST32(a1 + 0xc, a4);  /* 03c4 */
  a4 = LD8U(a2 + 0x1);  /* 03c6 */
  a2 = LD8U(a2 + 0x2);  /* 03c9 */
  a2 = a2 << 8;  /* 03cc */
  a2 = a2 | a4;  /* 03cf */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 03d2: -> "mesh_main.c" */
  a14 = a11;  /* 03d5 */
  ST32(a1 + 0x8, a2);  /* 03d7 */
  a2 = 0x57f;  /* 03d9 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 03dc: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_mesh_process_mgmt_announce_str1_1 + 0x0);  /* 03df: -> "add" */
  ST32(a1 + 0x4, a10);  /* 03e2 */
  a10 = 2;  /* 03e5 */
  ST32(a1 + 0x0, a2);  /* 03e8 */
  __asm__ volatile("" ::: "memory");  /* 03eb: memw */
  /* 03ee: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_03f1: a2 = 0x00004015u;  /* 03f1: l32r = 16405 */
  L_03f4: return a2;  /* 03f4: retw.n */
}


/* mesh_remove_myself_from_forwarding @ mesh_main.o 00000030 size 234B bind GLOBAL
 * Calls: esp_mesh_match_self, memcpy | indirect[5]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_optlen.str1.1, .rodata.esp_mesh_mcast_cover_node.str1.1
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=5 */
u32 mesh_remove_myself_from_forwarding(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  float F2;
  /* 0030: entry a1, 48 (frame 48 bytes) */
  a5 = (u32)&g_is_mesh_started + 0x0;  /* 0033: l32r -> global */
  a5 = LD8U(a5 + 0x0);  /* 0036 */
  if (a5 != 0) goto L_0071;  /* 0039: bnez.n a5, 71 <mesh_remove_myself_from_forwarding+0x41> */
  L_003b: a2 = (u32)&g_log_level + 0x0;  /* 003b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 003e */
  a2 = 0x00004004u;  /* 0040: l32r = 16388 */
  if (a3 >= 3u) goto L_0049;  /* 0043: bgeui a3, 3, 49 <mesh_remove_myself_from_forwarding+0x19> */
  L_0046: goto L_0118;  /* 0046: j */
  L_0049: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0049: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 004c */
  if (a3 == 0) goto L_0118;  /* 004e: beqz a3, 118 <mesh_remove_myself_from_forwarding+0xe8> */
  L_0051: a4 = LD32(a3 + 0x150);  /* 0051 */
  if (a4 == 0) goto L_0118;  /* 0054: beqz a4, 118 <mesh_remove_myself_from_forwarding+0xe8> */
  L_0057: a10 = LD32(a3 + 0x158);  /* 0057 */
  /* 005a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 005d */
  a10 = 3;  /* 005f */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0061: -> "mesh_main.c" */
  a14 = a11;  /* 0064 */
  a12 = (u32)(RODATA__rodata_esp_mesh_mcast_cover_node_str1_1 + 0x0);  /* 0066: l32r -> .rodata.esp_mesh_mcast_cover_node.str1.1 */
  /* 0069: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0118;  /* 006c: j */
  L_0071: if (a3 != 0) goto L_009e;  /* 0071: bnez.n a3, 9e <mesh_remove_myself_from_forwarding+0x6e> */
  L_0073: a2 = (u32)&g_log_level + 0x0;  /* 0073: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0076 */
  a2 = 0x00004008u;  /* 0078: l32r = 16392 */
  if (a3 >= 3u) goto L_0081;  /* 007b: bgeui a3, 3, 81 <mesh_remove_myself_from_forwarding+0x51> */
  L_007e: goto L_0118;  /* 007e: j */
  L_0081: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0081: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0084 */
  if (a3 == 0) goto L_0118;  /* 0086: beqz a3, 118 <mesh_remove_myself_from_forwarding+0xe8> */
  L_0089: a4 = LD32(a3 + 0x150);  /* 0089 */
  if (a4 == 0) goto L_0118;  /* 008c: beqz a4, 118 <mesh_remove_myself_from_forwarding+0xe8> */
  L_008f: a10 = LD32(a3 + 0x158);  /* 008f */
  a3 = 0x1a4;  /* 0092 */
  /* 0095: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 0098: -> "mesh_main.c" */
  goto L_00c7;  /* 009b: j */
  L_009e: if (a4 != 0) goto L_00e0;  /* 009e: bnez.n a4, e0 <mesh_remove_myself_from_forwarding+0xb0> */
  L_00a0: a2 = (u32)&g_log_level + 0x0;  /* 00a0: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00a3 */
  a2 = 0x00004008u;  /* 00a6: l32r = 16392 */
  if (a3 < 3u) goto L_0118;  /* 00a9: bltui a3, 3, 118 <mesh_remove_myself_from_forwarding+0xe8> */
  L_00ac: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00ac: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00af */
  if (a3 == 0) goto L_0118;  /* 00b2: beqz a3, 118 <mesh_remove_myself_from_forwarding+0xe8> */
  L_00b5: a4 = LD32(a3 + 0x150);  /* 00b5 */
  if (a4 == 0) goto L_0118;  /* 00b8: beqz a4, 118 <mesh_remove_myself_from_forwarding+0xe8> */
  L_00bb: a10 = LD32(a3 + 0x158);  /* 00bb */
  a3 = 0x1a5;  /* 00be */
  /* 00c1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00c4: -> "mesh_main.c" */
  L_00c7: a13 = a10;  /* 00c7 */
  a14 = a11;  /* 00c9 */
  a10 = 3;  /* 00cb */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00cd: -> "mesh_main.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_optlen_str1_1 + 0x0);  /* 00d0: -> "mesh_main.c" */
  ST32(a1 + 0x0, a3);  /* 00d3 */
  __asm__ volatile("" ::: "memory");  /* 00d6: memw */
  /* 00d9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0118;  /* 00dc: j */
  L_00e0: a5 = 0xaaaaaaabu;  /* 00e0: l32r = -1431655765 */
  a7 = 6;  /* 00e3 */
  a2 = (u32)(((u64)a2 * a5) >> 32);  /* 00e5: muluh */
  a5 = 0;  /* 00e8 */
  a2 = a2 >> 2;  /* 00ea */
  a6 = a5;  /* 00ed */
  goto L_0112;  /* 00ef: j */
  L_00f2: a10 = a3;  /* 00f2 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 00f4: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 00f7: callx a8 via reloc-expand */
  if (a10 != 0) goto L_010e;  /* 00fa: bnez.n a10, 10e <mesh_remove_myself_from_forwarding+0xde> */
  L_00fc: a10 = a5 + (a5 << 1);  /* 00fc */
  a12 = a7;  /* 00ff */
  a11 = a3;  /* 0101 */
  a10 = a10 + (a4 << 1);  /* 0103 */
  a8 = (u32)&memcpy + 0x0;  /* 0106: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0109: callx a8 (libc, via reloc-expand) */
  a5 = a5 + (1);  /* 010c */
  L_010e: a6 = a6 + (1);  /* 010e */
  a3 = a3 + (6);  /* 0110 */
  L_0112: if ((i32)a6 < (i32)a2) goto L_00f2;  /* 0112: blt a6, a2, f2 <mesh_remove_myself_from_forwarding+0xc2> */
  L_0115: a2 = 0;  /* 0115 */
  L_0118: return a2;  /* 0118: retw.n */
}


/* optype2str @ mesh_main.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.optype2str.str1.1, .rodata.CSWTCH$647
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 optype2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2 + (-3);  /* 000b */
  a2 = (u32)(RODATA__rodata_optype2str_str1_1 + 0x0);  /* 000e: -> "Unknown" */
  if (a8 >= 5u) goto L_001c;  /* 0011: bgeui a8, 5, 1c <optype2str+0x14> */
  L_0014: a2 = (u32)(RODATA__rodata_CSWTCH_647 + 0x0);  /* 0014: l32r -> .rodata.CSWTCH$647 */
  a8 = a8 + (a2 << 2);  /* 0017 */
  a2 = LD32(a8 + 0x0);  /* 001a */
  L_001c: return a2;  /* 001c: retw.n */
}

