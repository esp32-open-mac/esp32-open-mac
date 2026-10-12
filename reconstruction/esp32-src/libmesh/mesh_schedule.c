/* libmesh.a mesh_schedule.o --- reconstructed C (offline).
 * Role: TX scheduling, upstream pending windows (XON), send-block, tx/xon tasks.
 * Object file: 128568 bytes on disk; 50/50 functions reconstructed, ~23844 code bytes.
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
extern u32 g_is_wifi_connected; /* undefined data (reloc-referenced) */
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_mesh_conn; /* undefined data (reloc-referenced) */
extern u32 g_mesh_current_parent; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ext_cfg; /* undefined data (reloc-referenced) */
extern u32 g_mesh_init_ps_type; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_max_layer; /* undefined data (reloc-referenced) */
extern u32 g_mesh_packet_lifetime; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_sta_addr; /* undefined data (reloc-referenced) */
extern u32 g_mesh_stop_event_group; /* undefined data (reloc-referenced) */
extern u32 g_mesh_stop_reconnection; /* undefined data (reloc-referenced) */
extern u32 g_mesh_topology; /* undefined data (reloc-referenced) */
extern u32 g_mesh_xon_cfg_qsize; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 mesh_conn_leave; /* undefined data (reloc-referenced) */
extern u32 mesh_conn_mutex; /* undefined data (reloc-referenced) */
extern u32 mesh_myself_mbox; /* undefined data (reloc-referenced) */
extern u32 mesh_self_xonseq; /* undefined data (reloc-referenced) */
extern u32 mesh_tcpip_mbox; /* undefined data (reloc-referenced) */
extern u32 mesh_xon; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_create_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_create_mbox(); /* defined in another libmesh.a object */
extern u32 esp_mesh_delivery_toDS(); /* defined in another libmesh.a object */
extern u32 esp_mesh_delivery_toSelf(); /* defined in another libmesh.a object */
extern u32 esp_mesh_free_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_free_mbox(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_child_idx(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_child_idx_lock(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_layer(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_parent_bssid(); /* defined in another libmesh.a object */
extern u32 esp_mesh_match_self(); /* defined in another libmesh.a object */
extern u32 esp_mesh_print_rxQ_waiting(); /* defined in another libmesh.a object */
extern u32 esp_mesh_ps_control_check_awake(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_nwk_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_tcpip_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_xmit_state_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_send_sem_signal(); /* defined in another libmesh.a object */
extern u32 esp_wifi_mesh_tx(); /* undefined func (args unknown, returns u32) */
extern u32 mesh_mutex_lock(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_unlock(); /* defined in another libmesh.a object */
extern u32 mesh_send_process_topo(); /* defined in another libmesh.a object */
extern u32 mesh_topo_get_ttl(); /* defined in another libmesh.a object */
extern u32 print_txupQ_pending(); /* defined in another libmesh.a object */
extern u32 route_announce_timer_start(); /* defined in another libmesh.a object */
extern u32 tx_msg_id2str(); /* defined in another libmesh.a object */
extern u32 txq_opr2str(); /* defined in another libmesh.a object */
extern u32 wifi_get_macaddr(); /* undefined func (args unknown, returns u32) */
static const u8 RODATA__rodata___func___0[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x6e, 0x64, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x64, 0x65, 0x69, 0x6e }; /* .rodata.__func__$0 (20 bytes) */
static const u8 RODATA__rodata___func___1[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x6e, 0x64, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x64, 0x65, 0x69, 0x6e }; /* .rodata.__func__$1 (24 bytes) */
static const u8 RODATA__rodata___func___10[] = { 0x74, 0x78, 0x5f, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x6d, 0x61, 0x69, 0x6e }; /* .rodata.__func__$10 (12 bytes) */
static const u8 RODATA__rodata___func___11[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x5f, 0x74 }; /* .rodata.__func__$11 (12 bytes) */
static const u8 RODATA__rodata___func___12[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x74, 0x78, 0x75, 0x70, 0x51, 0x5f, 0x6e, 0x75, 0x6d }; /* .rodata.__func__$12 (28 bytes) */
static const u8 RODATA__rodata___func___13[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x78, 0x75, 0x70, 0x51, 0x5f, 0x70, 0x65, 0x6e, 0x64, 0x69 }; /* .rodata.__func__$13 (20 bytes) */
static const u8 RODATA__rodata___func___14[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x5f, 0x74, 0x78, 0x75, 0x70, 0x51, 0x5f, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67 }; /* .rodata.__func__$14 (28 bytes) */
static const u8 RODATA__rodata___func___15[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x78, 0x75, 0x70, 0x51, 0x5f, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x5f, 0x78, 0x6f, 0x6e, 0x73, 0x65, 0x71, 0x00 }; /* .rodata.__func__$15 (36 bytes) strings: [0x0]="esp_mesh_txupQ_pending_clear_xonseq" */
static const u8 RODATA__rodata___func___16[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x78, 0x73, 0x65, 0x71 }; /* .rodata.__func__$16 (24 bytes) */
static const u8 RODATA__rodata___func___17[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x6e, 0x64, 0x5f, 0x78, 0x6f }; /* .rodata.__func__$17 (16 bytes) */
static const u8 RODATA__rodata___func___18[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x78, 0x5f }; /* .rodata.__func__$18 (8 bytes) */
static const u8 RODATA__rodata___func___19[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x75, 0x73, 0x68, 0x5f, 0x74, 0x6f, 0x5f, 0x74, 0x78, 0x5f, 0x71, 0x75, 0x65, 0x75 }; /* .rodata.__func__$19 (24 bytes) */
static const u8 RODATA__rodata___func___2[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x78, 0x5f, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x64, 0x65, 0x69, 0x6e, 0x69, 0x74, 0x00 }; /* .rodata.__func__$2 (20 bytes) strings: [0x0]="mesh_tx_task_deinit" */
static const u8 RODATA__rodata___func___20[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x74, 0x69, 0x64, 0x5f, 0x6d, 0x62, 0x6f, 0x78, 0x5f, 0x66, 0x75, 0x6c, 0x6c }; /* .rodata.__func__$20 (24 bytes) */
static const u8 RODATA__rodata___func___21[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x6e, 0x64, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6d, 0x61, 0x69, 0x6e }; /* .rodata.__func__$21 (20 bytes) */
static const u8 RODATA__rodata___func___22[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x78, 0x75, 0x70, 0x51, 0x5f, 0x70, 0x65, 0x6e, 0x64, 0x69 }; /* .rodata.__func__$22 (28 bytes) */
static const u8 RODATA__rodata___func___3[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x78, 0x6f, 0x6e, 0x5f, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x6d, 0x61 }; /* .rodata.__func__$3 (16 bytes) */
static const u8 RODATA__rodata___func___4[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x78, 0x6f, 0x6e, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65 }; /* .rodata.__func__$4 (28 bytes) */
static const u8 RODATA__rodata___func___5[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x78, 0x6f, 0x6e, 0x5f, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x65 }; /* .rodata.__func__$5 (20 bytes) */
static const u8 RODATA__rodata___func___6[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x78, 0x6f, 0x6e, 0x5f, 0x64, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x00 }; /* .rodata.__func__$6 (24 bytes) strings: [0x0]="mesh_xon_deliver_packet" */
static const u8 RODATA__rodata___func___7[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x64, 0x69, 0x73, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74 }; /* .rodata.__func__$7 (24 bytes) */
static const u8 RODATA__rodata___func___9[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x78, 0x5f, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x6d, 0x61, 0x69 }; /* .rodata.__func__$9 (16 bytes) */
static const u8 RODATA__rodata_esp_mesh_available_txupQ_num_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x58, 0x4f, 0x4e, 0x5d, 0x61, 0x73, 0x79, 0x6e, 0x63, 0x2c, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32 }; /* .rodata.esp_mesh_available_txupQ_num.str1.1 (64 bytes) */
static const u8 RODATA__rodata_esp_mesh_flush_upstream_packets_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x28, 0x6d, 0x61, 0x78, 0x29, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x75, 0x70, 0x51, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x28, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x20, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x29, 0x2c, 0x20, 0x70, 0x75, 0x73, 0x68, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x62, 0x6f, 0x78, 0x28, 0x78, 0x6f, 0x6e, 0x20, 0x74, 0x61, 0x73, 0x6b, 0x29, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x2c, 0x20, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x0a }; /* .rodata.esp_mesh_flush_upstream_packets.str1.1 (156 bytes) */
static const u8 RODATA__rodata_esp_mesh_force_txupQ_pending_str1_1[] = { 0x6e, 0x6f, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x25, 0x73, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25 }; /* .rodata.esp_mesh_force_txupQ_pending.str1.1 (84 bytes) strings: [0x0]="no found"; [0x9]="mesh not start" */
static const u8 RODATA__rodata_esp_mesh_operation_rxseqno_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x72, 0x65, 0x63, 0x76, 0x5d, 0x63, 0x69, 0x64, 0x78, 0x5b, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x20, 0x64, 0x75, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x69, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6f, 0x75, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x72, 0x65, 0x63, 0x76, 0x5d, 0x63, 0x69, 0x64, 0x78, 0x5b, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x20, 0x6c, 0x6f, 0x73, 0x73, 0x2c, 0x20, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x2f, 0x6e, 0x65, 0x77, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x2c, 0x20, 0x69, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6f, 0x75, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x72, 0x65, 0x63, 0x76, 0x5d, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a, 0x00 }; /* .rodata.esp_mesh_operation_rxseqno.str1.1 (312 bytes) */
static const u8 RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x0a, 0x00 }; /* .rodata.esp_mesh_print_txQ_waiting.str1.1 (32 bytes) */
static const u8 RODATA__rodata_esp_mesh_process_txupQ_pending_str1_1[] = { 0x2c, 0x20, 0x74, 0x6f, 0x44, 0x53, 0x00, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x00, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x6c, 0x69, 0x6e, 0x67, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x74, 0x69, 0x64, 0x3a, 0x25, 0x64, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x25, 0x73, 0x25, 0x73, 0x25, 0x73, 0x2c, 0x20, 0x74, 0x6f, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a }; /* .rodata.esp_mesh_process_txupQ_pending.str1.1 (128 bytes) strings: [0x0]=", toDS"; [0x7]=", forward"; [0x11]=", healing" */
static const u8 RODATA__rodata_esp_mesh_push_to_tx_queue_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x58, 0x4f, 0x4e, 0x5d, 0x55, 0x70, 0x20, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x54, 0x4f, 0x53, 0x2c, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x73, 0x74, 0x61, 0x72, 0x74, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x71, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x69, 0x64, 0x3a, 0x25, 0x73, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x45, 0x52, 0x52, 0x5f, 0x44, 0x49, 0x53, 0x43, 0x41, 0x52, 0x44, 0x5f, 0x44, 0x55, 0x50, 0x4c, 0x49, 0x43, 0x41, 0x54, 0x45, 0x3e, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x2c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x73, 0x6b, 0x65, 0x64, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x5b, 0x53, 0x41, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x44, 0x41, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x74, 0x69, 0x64, 0x3a, 0x25, 0x73, 0x0a }; /* .rodata.esp_mesh_push_to_tx_queue.str1.1 (296 bytes) */
static const u8 RODATA__rodata_esp_mesh_push_to_wnd_queue_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x77, 0x6e, 0x64, 0x5d, 0x70, 0x75, 0x73, 0x68, 0x20, 0x74, 0x6f, 0x20, 0x77, 0x6e, 0x64, 0x20, 0x71, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64 }; /* .rodata.esp_mesh_push_to_wnd_queue.str1.1 (48 bytes) */
static const u8 RODATA__rodata_esp_mesh_send_block_event_str1_1[] = { 0x6e, 0x6f, 0x20, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x00, 0x71, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x00, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x00, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x70, 0x75, 0x73, 0x68, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x71, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x5b, 0x25, 0x73, 0x5d, 0x2c, 0x20, 0x74, 0x69, 0x64, 0x3a, 0x25, 0x64, 0x25, 0x73, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x70, 0x61, 0x6e, 0x64, 0x6f, 0x72, 0x61, 0x0a, 0x0a, 0x00 }; /* .rodata.esp_mesh_send_block_event.str1.1 (136 bytes) strings: [0x0]="no window"; [0xa]="q full"; [0x11]="[block]" */
static const u8 RODATA__rodata_esp_mesh_send_block_init_str1_1[] = { 0x4d, 0x54, 0x58, 0x42 }; /* .rodata.esp_mesh_send_block_init.str1.1 (4 bytes) */
static const u8 RODATA__rodata_esp_mesh_send_xon_str1_1[] = { 0x2c, 0x20, 0x72, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x3f, 0x3f, 0x00, 0x2c, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x20, 0x72, 0x65, 0x62, 0x6f, 0x6f, 0x74, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x78, 0x72, 0x73, 0x70, 0x5d, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x6e, 0x27, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x78, 0x72, 0x73, 0x70, 0x5d, 0x77, 0x6e, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x73, 0x6b, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x20, 0x3c, 0x3d, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x5f, 0x69, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x25, 0x73, 0x25, 0x73, 0x2c, 0x20, 0x78, 0x72, 0x73, 0x70, 0x5f, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x78, 0x72, 0x73, 0x70, 0x3a, 0x30, 0x5d, 0x6e, 0x6f, 0x20, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x2c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x73, 0x6b, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x20, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x2f, 0x64, 0x65, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x28, 0x75, 0x70, 0x29, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x78, 0x72, 0x73, 0x70, 0x5f, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x78, 0x72, 0x73, 0x70, 0x3a, 0x31, 0x5d, 0x74, 0x68, 0x65, 0x20, 0x61, 0x73, 0x6b, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x20, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x2f, 0x64, 0x65, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x28, 0x75, 0x70, 0x29, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x78, 0x72, 0x73, 0x70, 0x5f, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, /* ... +76 bytes */ }; /* .rodata.esp_mesh_send_xon.str1.1 (588 bytes) strings: [0x0]=", restart??"; [0xc]=", self just reboot" */
static const u8 RODATA__rodata_esp_mesh_tx_task_init[] = { 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x51, 0x01, 0x00, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x62, 0x01, 0x00, 0x00, 0x6f, 0x01, 0x00, 0x00, 0x71, 0x01, 0x00, 0x00, 0x34, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2f, 0x01, 0x00, 0x00 }; /* .rodata.esp_mesh_tx_task_init (56 bytes) */
static const u8 RODATA__rodata_esp_mesh_tx_task_init_str1_1[] = { 0x4d, 0x54, 0x58, 0x00, 0x4d, 0x54, 0x58, 0x4f }; /* .rodata.esp_mesh_tx_task_init.str1.1 (8 bytes) strings: [0x0]="MTX" */
static const u8 RODATA__rodata_esp_mesh_tx_tid_flush_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x62, 0x63, 0x61, 0x73, 0x74, 0x2c, 0x20, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x51, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x78, 0x6f, 0x6e, 0x2c, 0x20, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x51, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x78, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2c, 0x20, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x51, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x6d, 0x67, 0x6d, 0x74, 0x2c, 0x20, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x51, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25 }; /* .rodata.esp_mesh_tx_tid_flush.str1.1 (196 bytes) */
static const u8 RODATA__rodata_esp_mesh_txupQ_pending_str1_1[] = { 0x73, 0x65, 0x6c, 0x66, 0x00, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x00, 0x75, 0x70, 0x00, 0x2c, 0x64, 0x77, 0x00, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x58, 0x4f, 0x4e, 0x53, 0x45, 0x51, 0x5f, 0x4d, 0x41, 0x58, 0x00, 0x3e, 0x3d, 0x00, 0x3c, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x5b, 0x58, 0x53, 0x45, 0x51, 0x5d, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x20, 0x5b, 0x25, 0x73, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x25, 0x73, 0x5d, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x28, 0x25, 0x64, 0x2d, 0x25, 0x64, 0x29, 0x5b, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x3c, 0x25, 0x73, 0x25, 0x73, 0x3e, 0x25, 0x73, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x20, 0x5b, 0x25, 0x73, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x25, 0x73, 0x5d, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x28, 0x25, 0x64, 0x2d, 0x25, 0x64, 0x29, 0x5b, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x3c, 0x25, 0x73, 0x25, 0x73, 0x3e, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5b, 0x58, 0x4f, 0x4e, 0x5d, 0x6e, 0x6f, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20, 0x25, 0x73, 0x5b, 0x25, 0x73, 0x2c, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5d, 0x78, 0x6f, 0x6e, 0x73, 0x65, 0x71, 0x2e, 0x69, 0x6e, 0x5b, 0x25, 0x64, 0x5d, 0x20, 0x25, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x73, 0x6b, 0x65, 0x64, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x5b, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x5b, 0x58, 0x53, 0x45, 0x51, 0x5d, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x20, 0x5b, 0x25, 0x64, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x25, 0x73, 0x5d, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x28, 0x25, 0x64, 0x2d, 0x25, 0x64, 0x29, 0x5b, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x5b, 0x72, 0x78, 0x2d, 0x77, 0x6e, 0x64, 0x3a, 0x25, 0x64, 0x5d, /* ... +472 bytes */ }; /* .rodata.esp_mesh_txupQ_pending.str1.1 (984 bytes) strings: [0x0]="self"; [0x5]="parent"; [0xf]=",dw"; [0x13]="MESH_XONSEQ_MAX" */
static const u8 RODATA__rodata_mesh_check_tid_mbox_full[] = { 0x92, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00, 0xbc, 0x00, 0x00, 0x00, 0xaf, 0x01, 0x00, 0x00, 0x97, 0x01, 0x00, 0x00, 0xa6, 0x01, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0xaf, 0x01, 0x00, 0x00, 0xaf, 0x01, 0x00, 0x00 }; /* .rodata.mesh_check_tid_mbox_full (56 bytes) */
static const u8 RODATA__rodata_mesh_check_tid_mbox_full_str1_1[] = { 0x78, 0x6d, 0x69, 0x74, 0x00, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x54, 0x58, 0x51, 0x3e, 0x25, 0x73, 0x20, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x20, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x2c, 0x20, 0x6d, 0x67, 0x6d, 0x74, 0x20, 0x71, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x2c, 0x20, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x0a, 0x00 }; /* .rodata.mesh_check_tid_mbox_full.str1.1 (136 bytes) strings: [0x0]="xmit"; [0x5]="forward" */
static const u8 RODATA__rodata_mesh_flush_upstream_packets_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2c, 0x20, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x51, 0x3a, 0x25, 0x64, 0x0a }; /* .rodata.mesh_flush_upstream_packets.str1.1 (48 bytes) */
static const u8 RODATA__rodata_mesh_get_tx_pending_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x2e, 0x63, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73, 0x0a, 0x00 }; /* .rodata.mesh_get_tx_pending.str1.1 (44 bytes) strings: [0x0]="mesh_schedule.c" */
static const u8 RODATA__rodata_mesh_print_txQ_waiting_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x54, 0x58, 0x51, 0x5d, 0x3c, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x3e, 0x75, 0x70, 0x28, 0x25, 0x64, 0x2c, 0x20, 0x62, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x64, 0x6f, 0x77, 0x6e, 0x28, 0x25, 0x64, 0x2c, 0x20, 0x62, 0x65, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x6d, 0x67, 0x6d, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x78, 0x6f, 0x6e, 0x28, 0x72, 0x65, 0x71, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x73, 0x70, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x62, 0x63, 0x61, 0x73, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x77, 0x6e, 0x64, 0x28, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x29, 0x0a, 0x00 }; /* .rodata.mesh_print_txQ_waiting.str1.1 (148 bytes) strings: [0x0]="mesh" */
static const u8 RODATA__rodata_mesh_send_block_main_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x2c, 0x20, 0x63, 0x74, 0x78, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x6e, 0x27, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x64, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x20, 0x74, 0x6f, 0x44, 0x53, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x70, 0x75, 0x73, 0x68, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x78, 0x20, 0x71, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2c, 0x20, 0x74, 0x69, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x74, 0x78, 0x3a, 0x25, 0x70, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x62, 0x75, 0x66, 0x3a, 0x25, 0x70, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2c, 0x20, 0x74, 0x69, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x63, 0x74, 0x78, 0x3a, 0x25, 0x70, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x62, 0x75, 0x66, 0x3a, 0x25, 0x70, 0x2c, 0x20, 0x6d, 0x62, 0x6f, 0x78, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5d, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00 }; /* .rodata.mesh_send_block_main.str1.1 (344 bytes) */
static const u8 RODATA__rodata_mesh_tx_task_main_str1_1[] = { 0x73, 0x74, 0x6f, 0x70, 0x00, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x50, 0x4b, 0x54, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, 0x53, 0x57, 0x49, 0x54, 0x43, 0x48, 0x5f, 0x52, 0x45, 0x51, 0x00, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x50, 0x4b, 0x54, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, 0x53, 0x57, 0x49, 0x54, 0x43, 0x48, 0x5f, 0x41, 0x43, 0x4b, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x2c, 0x20, 0x74, 0x78, 0x20, 0x70, 0x73, 0x20, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x73, 0x5f, 0x74, 0x78, 0x5f, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x63, 0x74, 0x78, 0x20, 0x4e, 0x55, 0x4c, 0x4c, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x63, 0x74, 0x78, 0x3a, 0x25, 0x70, 0x3c, 0x25, 0x73, 0x3e, 0x2c, 0x20, 0x63, 0x74, 0x78, 0x2d, 0x3e, 0x62, 0x75, 0x66, 0x20, 0x4e, 0x55, 0x4c, 0x4c, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x63, 0x74, 0x78, 0x2d, 0x3e, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x3e, 0x25, 0x73, 0x20, 0x25, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x64, 0x6f, 0x6e, 0x65, 0x3e, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x42, 0x49, 0x54, 0x5f, 0x54, 0x58, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x74, 0x78 }; /* .rodata.mesh_tx_task_main.str1.1 (372 bytes) strings: [0x0]="stop"; [0x5]="MESH_PKT_ROOT_SWITCH_REQ"; [0x1e]="MESH_PKT_ROOT_SWITCH_ACK" */
static const u8 RODATA__rodata_mesh_tx_tid_stop_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x78, 0x6f, 0x6e, 0x28, 0x72, 0x65, 0x71, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x72, 0x73, 0x70, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x6d, 0x67, 0x6d, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x62, 0x63, 0x61, 0x73, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x64, 0x6f, 0x77, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x64, 0x6f, 0x6e, 0x77, 0x2d, 0x62, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x73, 0x28, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x75, 0x70, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x75, 0x70, 0x2d, 0x62, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x73, 0x28, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x78, 0x3a, 0x25, 0x64, 0x29 }; /* .rodata.mesh_tx_tid_stop.str1.1 (160 bytes) */
static const u8 RODATA__rodata_mesh_xon_deliver_packet_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x68, 0x65, 0x61, 0x6c, 0x69, 0x6e, 0x67, 0x3e, 0x74, 0x6f, 0x53, 0x65, 0x6c, 0x66, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x20, 0x6c, 0x6f, 0x73, 0x73, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x68, 0x65, 0x61, 0x6c, 0x69, 0x6e, 0x67, 0x3e, 0x74, 0x6f, 0x44, 0x53, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x20, 0x6c, 0x6f, 0x73, 0x73, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00 }; /* .rodata.mesh_xon_deliver_packet.str1.1 (104 bytes) */
static const u8 RODATA__rodata_mesh_xon_process_disconnected_str1_1[] = { 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x6e, 0x6f, 0x6e, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x64, 0x72, 0x6f, 0x70, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x25, 0x73, 0x2c, 0x20, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74 }; /* .rodata.mesh_xon_process_disconnected.str1.1 (84 bytes) strings: [0x0]="root"; [0x5]="non-root" */
static const u8 RODATA__rodata_mesh_xon_task_main_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x2c, 0x20, 0x78, 0x6f, 0x6e, 0x20, 0x70, 0x73, 0x20, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x73, 0x5f, 0x74, 0x78, 0x5f, 0x77, 0x61, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x5d, 0x25, 0x73, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x20, 0x72, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x73, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x64, 0x2c, 0x20, 0x77, 0x6e, 0x64, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x63, 0x74, 0x78, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x78, 0x72, 0x65, 0x71, 0x5d, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x6e, 0x27, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x54, 0x58, 0x2d, 0x58, 0x4f, 0x4e, 0x5d, 0x64, 0x72, 0x6f, 0x70, 0x20, 0x63, 0x74, 0x78, 0x2c, 0x20, 0x64, 0x65, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2d, 0x2d, 0x3e, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x77, 0x6e, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x78, 0x72, 0x65, 0x71, 0x5d, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x2c, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x78, 0x72, 0x65, 0x71, 0x20, 0x74, 0x6f, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x5b, 0x57, 0x4e, 0x44, 0x2d, 0x52, 0x58, 0x5d, 0x6d, 0x61, 0x78, 0x5f, 0x77, 0x6e, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x64, 0x20, 0x6d, 0x73, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x2c, 0x20, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6e, 0x6f, 0x5f, 0x77, 0x6e, 0x64, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x64, 0x6f, 0x6e, 0x65, 0x3e, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x45, 0x56, /* ... +40 bytes */ }; /* .rodata.mesh_xon_task_main.str1.1 (552 bytes) strings: [0x81]="ctx" */
static const u8 RODATA__rodata_tx_task_main_str1_1[] = { 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x62, 0x72, 0x65, 0x61, 0x6b, 0x3e, 0x74, 0x78 }; /* .rodata.tx_task_main.str1.1 (28 bytes) */
static const u8 RODATA__rodata_xon_task_main_str1_1[] = { 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x62, 0x72, 0x65, 0x61, 0x6b, 0x3e, 0x78, 0x6f, 0x6e, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x3e, 0x25, 0x73, 0x0a }; /* .rodata.xon_task_main.str1.1 (52 bytes) */
static u8 LOCAL__bss_MESH_ZERO_ADDR[0x4]; /* stand-in for .bss.MESH_ZERO_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_is_block_running[0x4]; /* stand-in for .bss.is_block_running (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_is_mesh_tx_started[0x4]; /* stand-in for .bss.is_mesh_tx_started (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_ack_state_mbox[0x4]; /* stand-in for .bss.mesh_ack_state_mbox (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_be_xmit_seqno[0x4]; /* stand-in for .bss.mesh_be_xmit_seqno (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_new_wnd_mbox[0x4]; /* stand-in for .bss.mesh_new_wnd_mbox (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_reassign_xseqno[0x4]; /* stand-in for .bss.mesh_reassign_xseqno (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_tx_fail_cnt_8[0x4]; /* stand-in for .bss.mesh_tx_fail_cnt$8 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_tx_mbox[0x4]; /* stand-in for .bss.mesh_tx_mbox (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_tx_task[0x4]; /* stand-in for .bss.mesh_tx_task (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_xreq_seqno[0x4]; /* stand-in for .bss.mesh_xreq_seqno (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_send_block_flush_mbox[0x4]; /* stand-in for .bss.send_block_flush_mbox (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_send_block_mbox[0x4]; /* stand-in for .bss.send_block_mbox (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_send_block_task[0x4]; /* stand-in for .bss.send_block_task (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_MESH_BCAST_ADDR[0x4]; /* stand-in for .data.MESH_BCAST_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_available_txupQ_num @ mesh_schedule.o 00000060 size 368B bind GLOBAL
 * Calls: esp_mesh_match_self, memcmp, mesh_mutex_lock, esp_mesh_get_child_idx, mesh_mutex_unlock, print_txupQ_pending | indirect[4]: mem[a2+0x158]; unknown; mem[a5+0x158]; mem[a5+0x150] | Data refs: g_is_mesh_started, g_mesh_ext_cfg, g_mesh_xon_cfg_qsize, .rodata.__func__$12, g_mesh_current_parent, .bss.mesh_tx_task, mesh_self_xonseq, mesh_conn_mutex, g_mesh_conn, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1 +3 more
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=21); reloc-direct=6, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_available_txupQ_num(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a4, a5, a6, a7, a8;
  /* 0060: entry a1, 80 (frame 80 bytes) */
  a5 = a2;  /* 0063 */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 0065: l32r -> global */
  a4 = 0;  /* 0068 */
  a6 = LD8U(a2 + 0x0);  /* 006a */
  a2 = 1;  /* 006d */
  if (a6 == 0) a4 = a2;  /* 006f */
  a6 = (a4 >> 8) & 0x1;  /* 0072: extui width 1 */
  if (a4 != 0) goto L_01c9;  /* 0075: bnez a4, 1c9 <esp_mesh_available_txupQ_num+0x169> */
  L_0078: if (a5 != 0) a2 = a6;  /* 0078 */
  if (a2 != 0) goto L_01c9;  /* 007b: bnez a2, 1c9 <esp_mesh_available_txupQ_num+0x169> */
  L_007e: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 007e: l32r -> global */
  a10 = a5;  /* 0081 */
  a2 = LD8U(a2 + 0xbd);  /* 0083 */
  a2 = a2 + a2;  /* 0086 */
  a2 = a2 + (1);  /* 0088 */
  a4 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 008a: l32r -> global */
  a7 = LD32(a4 + 0x0);  /* 008d */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 008f: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4);  /* 0092: callx a8 via reloc-expand */
  a7 = a7 / a2;  /* 0095: quos */
  a6 = (u32)(RODATA__rodata___func___12 + 0x0);  /* 0098: l32r -> .rodata.__func__$12 */
  if (a10 != 0) goto L_00ac;  /* 009b: bnez.n a10, ac <esp_mesh_available_txupQ_num+0x4c> */
  L_009d: a12 = 6;  /* 009d */
  a10 = a5;  /* 009f */
  a11 = (u32)&g_mesh_current_parent + 0x0;  /* 00a1: l32r -> global */
  a8 = (u32)&memcmp + 0x0;  /* 00a4: l32r -> global */
  a2 = memcmp(a2, a3);  /* 00a7: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_00d1;  /* 00aa: bnez.n a10, d1 <esp_mesh_available_txupQ_num+0x71> */
  L_00ac: a12 = 0x705;  /* 00ac */
  a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 00af: l32r -> .bss.mesh_tx_task (same-object static) */
  a11 = a6;  /* 00b2 */
  a10 = LD32(a2 + 0x1c);  /* 00b4 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 00b6: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3);  /* 00b9: callx a8 via reloc-expand */
  a12 = 0x709;  /* 00bc */
  a11 = a6;  /* 00bf */
  a4 = (u32)&mesh_self_xonseq + 0x0;  /* 00c1: l32r -> global */
  a8 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 00c4: l32r -> .bss.mesh_tx_task (same-object static) */
  a2 = LD32(a4 + 0x0);  /* 00c7 */
  a10 = LD32(a8 + 0x1c);  /* 00c9 */
  a4 = LD8U(a4 + 0x8);  /* 00cb */
  goto L_010a;  /* 00ce: j */
  L_00d1: a8 = (u32)&mesh_conn_mutex + 0x0;  /* 00d1: l32r -> global */
  a12 = 0x70b;  /* 00d4 */
  a11 = a6;  /* 00d7 */
  a10 = LD32(a8 + 0x0);  /* 00d9 */
  ST32(a1 + 0x20, a8);  /* 00db */
  __asm__ volatile("" ::: "memory");  /* 00dd: memw */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 00e0: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3);  /* 00e3: callx a8 via reloc-expand */
  a10 = a5;  /* 00e6 */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 00e8: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3);  /* 00eb: callx a8 via reloc-expand */
  a4 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 00ee: sext */
  a8 = LD32(a1 + 0x20);  /* 00f1 */
  if (a4 == -1) goto L_0114;  /* 00f3: beqi a4, -1, 114 <esp_mesh_available_txupQ_num+0xb4> */
  L_00f6: a4 = a4 << 6;  /* 00f6 */
  a12 = 0x710;  /* 00f9 */
  a11 = a6;  /* 00fc */
  a2 = (u32)&g_mesh_conn + 0x0;  /* 00fe: l32r -> global */
  a4 = a2 + a4;  /* 0101 */
  a2 = LD32(a4 + 0x8);  /* 0103 */
  a10 = LD32(a8 + 0x0);  /* 0105 */
  a4 = LD8U(a4 + 0x10);  /* 0107 */
  L_010a: a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 010a: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3);  /* 010d: callx a8 via reloc-expand */
  goto L_0179;  /* 0110: j */
  L_0114: a10 = LD32(a8 + 0x0);  /* 0114 */
  a12 = 0x712;  /* 0116 */
  a11 = a6;  /* 0119 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 011b: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3);  /* 011e: callx a8 via reloc-expand */
  a2 = (u32)&g_log_level + 0x0;  /* 0121: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0124 */
  if (a2 >= 3u) goto L_012c;  /* 0126: bgeui a2, 3, 12c <esp_mesh_available_txupQ_num+0xcc> */
  L_0129: goto L_01cc;  /* 0129: j */
  L_012c: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 012c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 012f */
  if (a2 == 0) goto L_01cc;  /* 0132: beqz a2, 1cc <esp_mesh_available_txupQ_num+0x16c> */
  L_0135: a3 = LD32(a2 + 0x150);  /* 0135 */
  if (a3 == 0) goto L_01cc;  /* 0138: beqz a3, 1cc <esp_mesh_available_txupQ_num+0x16c> */
  L_013b: a10 = LD32(a2 + 0x158);  /* 013b */
  /* 013e: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0141 */
  a15 = 0x714;  /* 0143 */
  a2 = LD8U(a5 + 0x5);  /* 0146 */
  a10 = 3;  /* 0149 */
  ST32(a1 + 0x14, a2);  /* 014b */
  a2 = LD8U(a5 + 0x4);  /* 014d */
  ST32(a1 + 0x10, a2);  /* 0150 */
  a2 = LD8U(a5 + 0x3);  /* 0152 */
  ST32(a1 + 0xc, a2);  /* 0155 */
  a2 = LD8U(a5 + 0x2);  /* 0157 */
  ST32(a1 + 0x8, a2);  /* 015a */
  a2 = LD8U(a5 + 0x1);  /* 015c */
  ST32(a1 + 0x4, a2);  /* 015f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0161: -> "mesh" */
  a14 = a11;  /* 0164 */
  a2 = LD8U(a5 + 0x0);  /* 0166 */
  a12 = (u32)(RODATA__rodata_esp_mesh_available_txupQ_num_str1_1 + 0x0);  /* 0169: l32r -> .rodata.esp_mesh_available_txupQ_num.str1.1 */
  ST32(a1 + 0x0, a2);  /* 016c */
  __asm__ volatile("" ::: "memory");  /* 016e: memw */
  /* 0171: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  goto L_01cc;  /* 0174: j */
  L_0179: a4 = a7 - a4;  /* 0179: sub */
  if ((i32)a4 >= 0) goto L_01bc;  /* 017c: bgez a4, 1bc <esp_mesh_available_txupQ_num+0x15c> */
  L_017f: a10 = a5;  /* 017f */
  a12 = 0x729;  /* 0181 */
  a11 = a6;  /* 0184 */
  a8 = (u32)&print_txupQ_pending + 0x0;  /* 0186: l32r -> global */
  a2 = print_txupQ_pending(a2, a3);  /* 0189: callx a8 via reloc-expand */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 018c: l32r -> global */
  a5 = LD32(a4 + 0x0);  /* 018f */
  a4 = 0;  /* 0191 */
  if (a5 == a4) goto L_01bc;  /* 0193: beq a5, a4, 1bc <esp_mesh_available_txupQ_num+0x15c> */
  L_0196: a6 = LD32(a5 + 0x150);  /* 0196 */
  if (a6 == a4) goto L_01bc;  /* 0199: beq a6, a4, 1bc <esp_mesh_available_txupQ_num+0x15c> */
  L_019c: a10 = LD32(a5 + 0x158);  /* 019c */
  a5 = 0x72b;  /* 019f */
  /* 01a2: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01a5 */
  a10 = 1;  /* 01a7 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 01a9: -> "mesh" */
  a14 = a11;  /* 01ac */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 01ae: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 01b1: -> "no window" */
  ST32(a1 + 0x0, a5);  /* 01b4 */
  __asm__ volatile("" ::: "memory");  /* 01b6: memw */
  /* 01b9: INDIRECT callx a6 <- mem[a5+0x150]; result unknown */ a2 = 0;
  L_01bc: if (a3 == 0) goto L_01cc;  /* 01bc: beqz.n a3, 1cc <esp_mesh_available_txupQ_num+0x16c> */
  L_01be: ST32(a3 + 0x0, a2);  /* 01be */
  __asm__ volatile("" ::: "memory");  /* 01c0: memw */
  goto L_01cc;  /* 01c3: j */
  L_01c9: a4 = 0x00004004u;  /* 01c9: l32r = 16388 */
  L_01cc: a2 = a4;  /* 01cc */
  return a2;  /* 01ce: retw.n */
}


/* esp_mesh_best_effort_tx @ mesh_schedule.o 00000054 size 721B bind GLOBAL
 * Calls: memcpy, wifi_get_macaddr, esp_wifi_mesh_tx, esp_mesh_get_child_idx_lock, memcmp | indirect[12]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x110]; mem[a9+0xa0] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .bss.mesh_be_xmit_seqno, .bss.mesh_ack_state_mbox, g_mesh_packet_lifetime, g_is_wifi_connected, g_mesh_current_parent
 * Fidelity: medium - 12 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=16); reloc-direct=5, funcdb-attributed=0, unknown-indirect=12 */
u32 esp_mesh_best_effort_tx(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0000001, F3;
  /* 0054: entry a1, 96 (frame 96 bytes) */
  ST32(a1 + 0x20, a3);  /* 0057 */
  a3 = (u32)&g_is_mesh_started + 0x0;  /* 0059: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 005c */
  if (a3 != 0) goto L_0099;  /* 005f: bnez.n a3, 99 <esp_mesh_best_effort_tx+0x45> */
  L_0061: a2 = (u32)&g_log_level + 0x0;  /* 0061: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0064 */
  a3 = 0x00004004u;  /* 0066: l32r = 16388 */
  if (a2 >= 3u) goto L_006f;  /* 0069: bgeui a2, 3, 6f <esp_mesh_best_effort_tx+0x1b> */
  L_006c: goto L_031e;  /* 006c: j */
  L_006f: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 006f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0072 */
  if (a2 == 0) goto L_031e;  /* 0074: beqz a2, 31e <esp_mesh_best_effort_tx+0x2ca> */
  L_0077: a4 = LD32(a2 + 0x150);  /* 0077 */
  if (a4 == 0) goto L_031e;  /* 007a: beqz a4, 31e <esp_mesh_best_effort_tx+0x2ca> */
  L_007d: a10 = LD32(a2 + 0x158);  /* 007d */
  __asm__ volatile("" ::: "memory");  /* 0080: memw */
  /* 0083: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0086 */
  a10 = 3;  /* 0088 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 008a: -> "mesh" */
  a14 = a11;  /* 008d */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 008f: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 0092: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_031e;  /* 0095: j */
  L_0099: if (a2 != 0) goto L_00c6;  /* 0099: bnez.n a2, c6 <esp_mesh_best_effort_tx+0x72> */
  L_009b: a2 = (u32)&g_log_level + 0x0;  /* 009b: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 009e */
  a3 = 0x00004008u;  /* 00a0: l32r = 16392 */
  if (a2 >= 3u) goto L_00a9;  /* 00a3: bgeui a2, 3, a9 <esp_mesh_best_effort_tx+0x55> */
  L_00a6: goto L_031e;  /* 00a6: j */
  L_00a9: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00a9: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00ac */
  if (a2 == 0) goto L_031e;  /* 00ae: beqz a2, 31e <esp_mesh_best_effort_tx+0x2ca> */
  L_00b1: a4 = LD32(a2 + 0x150);  /* 00b1 */
  if (a4 == 0) goto L_031e;  /* 00b4: beqz a4, 31e <esp_mesh_best_effort_tx+0x2ca> */
  L_00b7: a10 = LD32(a2 + 0x158);  /* 00b7 */
  a2 = 0x37a;  /* 00ba */
  /* 00bd: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00c0: -> "mesh" */
  goto L_00f3;  /* 00c3: j */
  L_00c6: a4 = LD32(a2 + 0x0);  /* 00c6 */
  if (a4 != 0) goto L_010b;  /* 00c8: bnez.n a4, 10b <esp_mesh_best_effort_tx+0xb7> */
  L_00ca: a2 = (u32)&g_log_level + 0x0;  /* 00ca: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00cd */
  a3 = 0x00004008u;  /* 00cf: l32r = 16392 */
  if (a2 >= 3u) goto L_00d8;  /* 00d2: bgeui a2, 3, d8 <esp_mesh_best_effort_tx+0x84> */
  L_00d5: goto L_031e;  /* 00d5: j */
  L_00d8: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00d8: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00db */
  if (a2 == 0) goto L_031e;  /* 00de: beqz a2, 31e <esp_mesh_best_effort_tx+0x2ca> */
  L_00e1: a4 = LD32(a2 + 0x150);  /* 00e1 */
  if (a4 == 0) goto L_031e;  /* 00e4: beqz a4, 31e <esp_mesh_best_effort_tx+0x2ca> */
  L_00e7: a10 = LD32(a2 + 0x158);  /* 00e7 */
  a2 = 0x37b;  /* 00ea */
  /* 00ed: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00f0: -> "mesh" */
  L_00f3: a13 = a10;  /* 00f3 */
  a14 = a11;  /* 00f5 */
  a10 = 3;  /* 00f7 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00f9: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00fc: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a2);  /* 00ff */
  __asm__ volatile("" ::: "memory");  /* 0102: memw */
  /* 0105: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_031e;  /* 0108: j */
  L_010b: a3 = LD32(a1 + 0x20);  /* 010b */
  if (a3 != 0) goto L_013c;  /* 010d: bnez.n a3, 13c <esp_mesh_best_effort_tx+0xe8> */
  L_010f: a2 = (u32)&g_log_level + 0x0;  /* 010f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0112 */
  a3 = 0x00004008u;  /* 0114: l32r = 16392 */
  if (a2 >= 3u) goto L_011d;  /* 0117: bgeui a2, 3, 11d <esp_mesh_best_effort_tx+0xc9> */
  L_011a: goto L_031e;  /* 011a: j */
  L_011d: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 011d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0120 */
  if (a2 == 0) goto L_031e;  /* 0122: beqz a2, 31e <esp_mesh_best_effort_tx+0x2ca> */
  L_0125: a4 = LD32(a2 + 0x150);  /* 0125 */
  if (a4 == 0) goto L_031e;  /* 0128: beqz a4, 31e <esp_mesh_best_effort_tx+0x2ca> */
  L_012b: a10 = LD32(a2 + 0x158);  /* 012b */
  a2 = 0x37c;  /* 012e */
  /* 0131: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0134: -> "mesh" */
  goto L_00f3;  /* 0137: j */
  L_013c: a8 = a4 + (18);  /* 013c */
  a5 = 3;  /* 013f */
  a6 = LD32(a8 + 0x0);  /* 0141 */
  a5 = a5 << 14;  /* 0143 */
  a3 = -1;  /* 0146 */
  ST32(a1 + 0x28, a8);  /* 0148 */
  if ((a6 & a5) == 0) goto L_0150;  /* 014a: bnone a6, a5, 150 <esp_mesh_best_effort_tx+0xfc> */
  L_014d: goto L_031e;  /* 014d: j */
  L_0150: a3 = (u32)&LOCAL__bss_mesh_be_xmit_seqno + 0x0;  /* 0150: l32r -> .bss.mesh_be_xmit_seqno (same-object static) */
  a5 = LD32(a3 + 0x0);  /* 0153 */
  a5 = a5 + (1);  /* 0155 */
  a6 = 0x0ffffffeu;  /* 0157: l32r = 268435454 */
  if (a6 < a5) goto L_0164;  /* 015a: bltu a6, a5, 164 <esp_mesh_best_effort_tx+0x110> */
  L_015d: __asm__ volatile("" ::: "memory");  /* 015d: memw */
  goto L_0166;  /* 0160: j */
  L_0164: a5 = 1;  /* 0164 */
  L_0166: ST32(a3 + 0x0, a5);  /* 0166 */
  a5 = a4 + (14);  /* 0168 */
  a6 = a2 + (6);  /* 016a */
  a3 = LD32(a3 + 0x0);  /* 016c */
  ST32(a5 + 0x14, a3);  /* 016e */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0170: l32r -> global */
  a3 = LD32(a5 + 0x0);  /* 0173 */
  a10 = LD32(a3 + 0x110);  /* 0175 */
  __asm__ volatile("" ::: "memory");  /* 0178: memw */
  /* 017b: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  a12 = 6;  /* 017e */
  a7 = a11;  /* 0180 */
  a3 = LD32(a2 + 0x0);  /* 0182 */
  a11 = a6;  /* 0184 */
  ST32(a1 + 0x24, a10);  /* 0186 */
  a10 = a3;  /* 0189: mov */
  __asm__ volatile("" ::: "memory");  /* 018c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 018f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0192: callx a8 (libc, via reloc-expand) */
  a11 = a3 + (6);  /* 0195 */
  a10 = LD8U(a2 + 0x12);  /* 0197 */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 019a: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6, a7);  /* 019d: callx a8 via reloc-expand */
  a8 = -18;  /* 01a0 */
  a9 = LD32(a1 + 0x24);  /* 01a2 */
  ST8(a3 + 0xc, a8);  /* 01a4 */
  ST8(a3 + 0xd, a8);  /* 01a7 */
  __asm__ volatile("" ::: "memory");  /* 01aa: memw */
  a3 = -1;  /* 01ad */
  a3 = a3 ^ a9;  /* 01af */
  ST32(a1 + 0x2c, a3);  /* 01b2 */
  L_01b5: a13 = a6;  /* 01b5 */
  a12 = LD16U(a2 + 0x4);  /* 01b7 */
  a11 = LD32(a2 + 0x0);  /* 01ba */
  a10 = LD8U(a2 + 0x12);  /* 01bc */
  __asm__ volatile("" ::: "memory");  /* 01bf: memw */
  a8 = (u32)&esp_wifi_mesh_tx + 0x0;  /* 01c2: l32r -> global */
  a2 = esp_wifi_mesh_tx(a2, a3, a4, a5, a6, a7);  /* 01c5: callx a8 via reloc-expand */
  a3 = a10;  /* 01c8 */
  if (a10 == 0) goto L_01d6;  /* 01ca: beqz.n a10, 1d6 <esp_mesh_best_effort_tx+0x182> */
  L_01cc: a2 = LD32(a1 + 0x20);  /* 01cc */
  ST32(a2 + 0x0, a10);  /* 01ce */
  __asm__ volatile("" ::: "memory");  /* 01d0: memw */
  goto L_031e;  /* 01d3: j */
  L_01d6: a8 = 8;  /* 01d6 */
  a9 = LD32(a5 + 0x0);  /* 01d8 */
  a10 = (u32)&LOCAL__bss_mesh_ack_state_mbox + 0x0;  /* 01da: l32r -> .bss.mesh_ack_state_mbox (same-object static) */
  ST32(a1 + 0x14, a8);  /* 01dd */
  a8 = (u32)&g_mesh_packet_lifetime + 0x0;  /* 01df: l32r -> global */
  a13 = LD32(a9 + 0x74);  /* 01e2 */
  a14 = LD32(a10 + 0x0);  /* 01e5 */
  a10 = LD32(a8 + 0x0);  /* 01e7 */
  a8 = 0x271;  /* 01e9 */
  a8 = a8 << 3;  /* 01ec */
  a10 = (a10 < a8) ? a10 : a8;  /* 01ef: minu */
  a9 = LD32(a9 + 0xa0);  /* 01f2 */
  ST32(a1 + 0x30, a13);  /* 01f5 */
  ST32(a1 + 0x34, a14);  /* 01f8 */
  __asm__ volatile("" ::: "memory");  /* 01fa: memw */
  /* 01fd: INDIRECT callx a9 <- mem[a9+0xa0]; result unknown */ a2 = 0;
  a12 = a10;  /* 0200 */
  a11 = a1 + (16);  /* 0202 */
  a14 = LD32(a1 + 0x34);  /* 0205 */
  a10 = a14;  /* 0207: mov */
  a13 = LD32(a1 + 0x30);  /* 020a */
  /* 020d: INDIRECT callx a13 <- mem[a1+0x30]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_024d;  /* 0210: bnei a10, 1, 24d <esp_mesh_best_effort_tx+0x1f9> */
  L_0213: a8 = a4 + (14);  /* 0213 */
  a9 = LD32(a1 + 0x10);  /* 0215 */
  a8 = LD32(a8 + 0x14);  /* 0217 */
  if (a9 != a8) goto L_0224;  /* 0219: bne a9, a8, 224 <esp_mesh_best_effort_tx+0x1d0> */
  L_021c: a8 = LD32(a1 + 0x14);  /* 021c */
  if (a8 != 1) goto L_0224;  /* 021e: bnei a8, 1, 224 <esp_mesh_best_effort_tx+0x1d0> */
  L_0221: goto L_0318;  /* 0221: j */
  L_0224: a8 = LD8U(a2 + 0x12);  /* 0224 */
  if (a8 != 0) goto L_0239;  /* 0227: bnez.n a8, 239 <esp_mesh_best_effort_tx+0x1e5> */
  L_0229: a8 = (u32)&g_is_wifi_connected + 0x0;  /* 0229: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 022c */
  if (a8 != 0) goto L_0259;  /* 022f: bnez.n a8, 259 <esp_mesh_best_effort_tx+0x205> */
  L_0231: a2 = 7;  /* 0231 */
  goto L_024f;  /* 0233: j */
  L_0239: if (a8 != 1) goto L_0259;  /* 0239: bnei a8, 1, 259 <esp_mesh_best_effort_tx+0x205> */
  L_023c: a10 = a6;  /* 023c */
  a8 = (u32)&esp_mesh_get_child_idx_lock + 0x0;  /* 023e: l32r -> global */
  a2 = esp_mesh_get_child_idx_lock(a2, a3, a4, a5, a6, a7);  /* 0241: callx a8 via reloc-expand */
  a10 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 0244: sext */
  if (a10 != -1) goto L_0259;  /* 0247: bnei a10, -1, 259 <esp_mesh_best_effort_tx+0x205> */
  L_024a: goto L_0231;  /* 024a: j */
  L_024d: a2 = 6;  /* 024d */
  L_024f: ST32(a1 + 0x14, a2);  /* 024f */
  __asm__ volatile("" ::: "memory");  /* 0251: memw */
  goto L_0318;  /* 0254: j */
  L_0259: a8 = LD32(a5 + 0x0);  /* 0259 */
  a10 = LD32(a8 + 0x110);  /* 025b */
  /* 025e: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  if ((i32)a11 < (i32)a7) goto L_0292;  /* 0261: blt a11, a7, 292 <esp_mesh_best_effort_tx+0x23e> */
  L_0264: if (a7 != a11) goto L_026c;  /* 0264: bne a7, a11, 26c <esp_mesh_best_effort_tx+0x218> */
  L_0267: a9 = LD32(a1 + 0x24);  /* 0267 */
  if (a10 < a9) goto L_0292;  /* 0269: bltu a10, a9, 292 <esp_mesh_best_effort_tx+0x23e> */
  L_026c: a8 = LD32(a5 + 0x0);  /* 026c */
  a10 = LD32(a8 + 0x110);  /* 026e */
  /* 0271: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x24);  /* 0274 */
  a8 = a10 - a9;  /* 0276: sub */
  a9 = 1;  /* 0279 */
  if (a10 < a8) goto L_0280;  /* 027b: bltu a10, a8, 280 <esp_mesh_best_effort_tx+0x22c> */
  L_027e: a9 = 0;  /* 027e */
  L_0280: a11 = a11 - a7;  /* 0280: sub */
  a11 = a11 - a9;  /* 0283: sub */
  a9 = a11 << 22;  /* 0286 */
  a8 = a8 >> 10;  /* 0289 */
  a8 = a9 | a8;  /* 028c */
  goto L_02c1;  /* 028f: j */
  L_0292: a8 = LD32(a5 + 0x0);  /* 0292 */
  a10 = LD32(a8 + 0x110);  /* 0294 */
  /* 0297: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = LD32(a1 + 0x2c);  /* 029a */
  a10 = a8 + a10;  /* 029c */
  a8 = 1;  /* 029e */
  a9 = LD32(a1 + 0x2c);  /* 02a0 */
  if (a10 < a9) goto L_02a8;  /* 02a2: bltu a10, a9, 2a8 <esp_mesh_best_effort_tx+0x254> */
  L_02a5: a8 = 0;  /* 02a5 */
  L_02a8: a11 = a7 + a11;  /* 02a8 */
  a9 = a10 + (1);  /* 02aa */
  a11 = a8 + a11;  /* 02ac */
  a8 = 1;  /* 02ae */
  if (a9 < a10) goto L_02b6;  /* 02b0: bltu a9, a10, 2b6 <esp_mesh_best_effort_tx+0x262> */
  L_02b3: a8 = 0;  /* 02b3 */
  L_02b6: a11 = a8 + a11;  /* 02b6 */
  a10 = a11 << 22;  /* 02b8 */
  a8 = a9 >> 10;  /* 02bb */
  a8 = a10 | a8;  /* 02be */
  L_02c1: a10 = (u32)&g_mesh_packet_lifetime + 0x0;  /* 02c1: l32r -> global */
  a11 = (i32)a11 >> 10;  /* 02c4 */
  a9 = LD32(a10 + 0x0);  /* 02c7 */
  a10 = 0;  /* 02c9 */
  if ((i32)a10 < (i32)a11) goto L_0318;  /* 02cb: blt a10, a11, 318 <esp_mesh_best_effort_tx+0x2c4> */
  L_02ce: if (a11 != a10) goto L_02d4;  /* 02ce: bne a11, a10, 2d4 <esp_mesh_best_effort_tx+0x280> */
  L_02d1: if (a9 < a8) goto L_0318;  /* 02d1: bltu a9, a8, 318 <esp_mesh_best_effort_tx+0x2c4> */
  L_02d4: a8 = LD32(a1 + 0x28);  /* 02d4 */
  a9 = LD32(a8 + 0x0);  /* 02d6 */
  a8 = 0x403;  /* 02d8 */
  a8 = a8 << 14;  /* 02db */
  a9 = a9 & a8;  /* 02de */
  a8 = 1;  /* 02e1 */
  a8 = a8 << 24;  /* 02e3 */
  if (a9 == a8) goto L_02ec;  /* 02e6: beq a9, a8, 2ec <esp_mesh_best_effort_tx+0x298> */
  L_02e9: goto L_01b5;  /* 02e9: j */
  L_02ec: a8 = a4 + (14);  /* 02ec */
  a11 = LD32(a8 + 0x18);  /* 02ee */
  a9 = 0;  /* 02f0 */
  a8 = 1;  /* 02f2 */
  a10 = 0xf0000001u;  /* 02f4: l32r = -268435455 */
  a10 = a11 + a10;  /* 02f7 */
  if (a10 == 0) a9 = a8;  /* 02f9 */
  a10 = (a9 >> 8) & 0x1;  /* 02fc: extui width 1 */
  if (a9 != 0) goto L_01b5;  /* 02ff: bnez a9, 1b5 <esp_mesh_best_effort_tx+0x161> */
  L_0302: if (a11 != 0) a8 = a10;  /* 0302 */
  if (a8 != 0) goto L_01b5;  /* 0305: bnez a8, 1b5 <esp_mesh_best_effort_tx+0x161> */
  L_0308: a11 = (u32)&g_mesh_current_parent + 0x0;  /* 0308: l32r -> global */
  a12 = 6;  /* 030b */
  a10 = a6;  /* 030d */
  a8 = (u32)&memcmp + 0x0;  /* 030f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0312: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01b5;  /* 0315: beqz a10, 1b5 <esp_mesh_best_effort_tx+0x161> */
  L_0318: a2 = LD32(a1 + 0x14);  /* 0318 */
  a9 = LD32(a1 + 0x20);  /* 031a */
  ST32(a9 + 0x0, a2);  /* 031c */
  L_031e: a2 = a3;  /* 031e */
  __asm__ volatile("" ::: "memory");  /* 0320: memw */
  return a2;  /* 0323: retw.n */
}


/* esp_mesh_discard_context @ mesh_schedule.o 00000044 size 300B bind GLOBAL
 * Calls: memcmp, esp_mesh_match_self, esp_mesh_push_to_xmit_state_queue, esp_mesh_free_context | indirect[3]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .bss.MESH_ZERO_ADDR, g_mesh_is_root, .rodata.__func__$7
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=11); reloc-direct=4, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_discard_context(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0044: entry a1, 64 (frame 64 bytes) */
  ST32(a1 + 0x10, a3);  /* 0047 */
  if (a2 != 0) goto L_007a;  /* 0049: bnez.n a2, 7a <esp_mesh_discard_context+0x36> */
  L_004b: a2 = (u32)&g_log_level + 0x0;  /* 004b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 004e */
  a2 = 0x00004008u;  /* 0050: l32r = 16392 */
  if (a3 >= 3u) goto L_0059;  /* 0053: bgeui a3, 3, 59 <esp_mesh_discard_context+0x15> */
  L_0056: goto L_016e;  /* 0056: j */
  L_0059: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0059: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 005c */
  if (a3 == 0) goto L_016e;  /* 005e: beqz a3, 16e <esp_mesh_discard_context+0x12a> */
  L_0061: a4 = LD32(a3 + 0x150);  /* 0061 */
  if (a4 == 0) goto L_016e;  /* 0064: beqz a4, 16e <esp_mesh_discard_context+0x12a> */
  L_0067: a10 = LD32(a3 + 0x158);  /* 0067 */
  __asm__ volatile("" ::: "memory");  /* 006a: memw */
  /* 006d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0070: -> "mesh" */
  a3 = 0x000009e4u;  /* 0073: l32r = 2532 */
  goto L_00a7;  /* 0076: j */
  L_007a: a3 = LD32(a2 + 0x0);  /* 007a */
  if (a3 != 0) goto L_00c0;  /* 007c: bnez a3, c0 <esp_mesh_discard_context+0x7c> */
  L_007f: a2 = (u32)&g_log_level + 0x0;  /* 007f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0082 */
  a2 = 0x00004008u;  /* 0084: l32r = 16392 */
  if (a3 >= 3u) goto L_008d;  /* 0087: bgeui a3, 3, 8d <esp_mesh_discard_context+0x49> */
  L_008a: goto L_016e;  /* 008a: j */
  L_008d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 008d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0090 */
  if (a3 == 0) goto L_016e;  /* 0092: beqz a3, 16e <esp_mesh_discard_context+0x12a> */
  L_0095: a4 = LD32(a3 + 0x150);  /* 0095 */
  if (a4 == 0) goto L_016e;  /* 0098: beqz a4, 16e <esp_mesh_discard_context+0x12a> */
  L_009b: a10 = LD32(a3 + 0x158);  /* 009b */
  /* 009e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00a1: -> "mesh" */
  a3 = 0x000009e5u;  /* 00a4: l32r = 2533 */
  L_00a7: a13 = a10;  /* 00a7 */
  a14 = a11;  /* 00a9 */
  a10 = 3;  /* 00ab */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00ad: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00b0: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 00b3 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  /* 00b9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_016e;  /* 00bc: j */
  L_00c0: a9 = LD32(a1 + 0x10);  /* 00c0 */
  a8 = 9;  /* 00c2 */
  a4 = a3 + (22);  /* 00c4 */
  a5 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 00c7: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  if (a9 != a8) goto L_00e2;  /* 00ca: bne a9, a8, e2 <esp_mesh_discard_context+0x9e> */
  L_00cd: a12 = 6;  /* 00cd */
  a11 = a5;  /* 00cf */
  a10 = a4;  /* 00d1 */
  a8 = (u32)&memcmp + 0x0;  /* 00d3: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00d6: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_015e;  /* 00d9: bnez a10, 15e <esp_mesh_discard_context+0x11a> */
  L_00dc: goto L_0129;  /* 00dc: j */
  L_00e2: a8 = LD32(a2 + 0x28);  /* 00e2 */
  if (((a8 >> 0) & 1) == 0) goto L_00cd;  /* 00e4: bbci a8, 0, cd <esp_mesh_discard_context+0x89> */
  L_00e7: a8 = a3 + (18);  /* 00e7 */
  a9 = LD32(a8 + 0x0);  /* 00ea */
  a8 = 0x403;  /* 00ec */
  a8 = a8 << 14;  /* 00ef */
  a9 = a9 & a8;  /* 00f2 */
  a8 = 1;  /* 00f5 */
  a8 = a8 << 24;  /* 00f7 */
  if (a9 != a8) goto L_00cd;  /* 00fa: bne a9, a8, cd <esp_mesh_discard_context+0x89> */
  L_00fd: a10 = a4;  /* 00fd */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 00ff: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0102: callx a8 via reloc-expand */
  if (a10 != 0) goto L_00cd;  /* 0105: bnez a10, cd <esp_mesh_discard_context+0x89> */
  L_0108: a12 = 6;  /* 0108 */
  a11 = a5;  /* 010a */
  a10 = a4;  /* 010c */
  a8 = (u32)&memcmp + 0x0;  /* 010e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0111: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a2 + 0x28);  /* 0114 */
  if (a10 != 0) goto L_013d;  /* 0116: bnez.n a10, 13d <esp_mesh_discard_context+0xf9> */
  L_0118: a8 = (u32)&g_mesh_is_root + 0x0;  /* 0118: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 011b: memw */
  a8 = LD8U(a8 + 0x0);  /* 011e */
  a8 = (a8 >> 8) & 0x1;  /* 0121: extui width 1 */
  if (a8 == 0) goto L_013d;  /* 0124: beqz.n a8, 13d <esp_mesh_discard_context+0xf9> */
  L_0126: if (((a9 >> 2) & 1) != 0) goto L_013d;  /* 0126: bbsi a9, 2, 13d <esp_mesh_discard_context+0xf9> */
  L_0129: a3 = (u32)&g_mesh_is_root + 0x0;  /* 0129: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 012c: memw */
  a3 = LD8U(a3 + 0x0);  /* 012f */
  a3 = (a3 >> 8) & 0x1;  /* 0132: extui width 1 */
  if (a3 != 0) goto L_0159;  /* 0135: bnez.n a3, 159 <esp_mesh_discard_context+0x115> */
  L_0137: goto L_015e;  /* 0137: j */
  L_013d: if (((a9 >> 3) & 1) != 0) goto L_0150;  /* 013d: bbsi a9, 3, 150 <esp_mesh_discard_context+0x10c> */
  L_0140: a11 = 0;  /* 0140 */
  a10 = a1 + (16);  /* 0142 */
  a8 = (u32)&esp_mesh_push_to_xmit_state_queue + 0x0;  /* 0145: l32r -> global */
  a2 = esp_mesh_push_to_xmit_state_queue(a2, a3, a4, a5, a6, a7);  /* 0148: callx a8 via reloc-expand */
  goto L_015e;  /* 014b: j */
  L_0150: a3 = LD8U(a3 + 0xe);  /* 0150 */
  if (((a3 >> 5) & 1) == 0) goto L_0140;  /* 0153: bbci a3, 5, 140 <esp_mesh_discard_context+0xfc> */
  L_0156: goto L_00cd;  /* 0156: j */
  L_0159: a3 = LD32(a2 + 0x28);  /* 0159 */
  if (((a3 >> 0) & 1) != 0) goto L_0140;  /* 015b: bbsi a3, 0, 140 <esp_mesh_discard_context+0xfc> */
  L_015e: a10 = a2;  /* 015e */
  a2 = 0;  /* 0160 */
  a12 = 0x000009f3u;  /* 0162: l32r = 2547 */
  a11 = (u32)(RODATA__rodata___func___7 + 0x0);  /* 0165: l32r -> .rodata.__func__$7 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0168: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 016b: callx a8 via reloc-expand */
  L_016e: return a2;  /* 016e: retw.n */
}


/* esp_mesh_flush_upstream_packets @ mesh_schedule.o 00000038 size 326B bind GLOBAL
 * Calls: none | indirect[12]: mem[a3+0x158]; mem[a3+0x150]; mem[a8+0x158]; mem[a8+0x78] | Data refs: g_log_level, .bss.mesh_tx_task, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .bss.mesh_tx_mbox, .rodata.mesh_get_tx_pending.str1.1, g_mesh_ext_cfg, .rodata.esp_mesh_flush_upstream_packets.str1.1
 * Fidelity: medium - 12 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=8); reloc-direct=0, funcdb-attributed=0, unknown-indirect=12 */
u32 esp_mesh_flush_upstream_packets(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0038: entry a1, 80 (frame 80 bytes) */
  a2 = (u32)&g_log_level + 0x0;  /* 003b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 003e */
  a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0040: l32r -> .bss.mesh_tx_task (same-object static) */
  a4 = LD32(a2 + 0x18);  /* 0043 */
  if (a4 != 0) goto L_006d;  /* 0045: bnez.n a4, 6d <esp_mesh_flush_upstream_packets+0x35> */
  L_0047: a2 = 0x00004008u;  /* 0047: l32r = 16392 */
  if (a3 >= 3u) goto L_0050;  /* 004a: bgeui a3, 3, 50 <esp_mesh_flush_upstream_packets+0x18> */
  L_004d: goto L_017c;  /* 004d: j */
  L_0050: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0050: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0053 */
  if (a3 == 0) goto L_017c;  /* 0055: beqz a3, 17c <esp_mesh_flush_upstream_packets+0x144> */
  L_0058: a4 = LD32(a3 + 0x150);  /* 0058 */
  if (a4 == 0) goto L_017c;  /* 005b: beqz a4, 17c <esp_mesh_flush_upstream_packets+0x144> */
  L_005e: a10 = LD32(a3 + 0x158);  /* 005e */
  /* 0061: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0064: -> "mesh" */
  a3 = 0x00000e02u;  /* 0067: l32r = 3586 */
  goto L_0097;  /* 006a: j */
  L_006d: a5 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 006d: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a4 = LD32(a5 + 0x0);  /* 0070 */
  if (a4 != 0) goto L_00b0;  /* 0072: bnez.n a4, b0 <esp_mesh_flush_upstream_packets+0x78> */
  L_0074: a2 = 0x00004008u;  /* 0074: l32r = 16392 */
  if (a3 >= 3u) goto L_007d;  /* 0077: bgeui a3, 3, 7d <esp_mesh_flush_upstream_packets+0x45> */
  L_007a: goto L_017c;  /* 007a: j */
  L_007d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 007d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0080 */
  if (a3 == 0) goto L_017c;  /* 0082: beqz a3, 17c <esp_mesh_flush_upstream_packets+0x144> */
  L_0085: a4 = LD32(a3 + 0x150);  /* 0085 */
  if (a4 == 0) goto L_017c;  /* 0088: beqz a4, 17c <esp_mesh_flush_upstream_packets+0x144> */
  L_008b: a10 = LD32(a3 + 0x158);  /* 008b */
  /* 008e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0091: -> "mesh" */
  a3 = 0x00000e03u;  /* 0094: l32r = 3587 */
  L_0097: a13 = a10;  /* 0097 */
  a14 = a11;  /* 0099 */
  a10 = 3;  /* 009b */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 009d: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00a0: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 00a3 */
  __asm__ volatile("" ::: "memory");  /* 00a6: memw */
  /* 00a9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_017c;  /* 00ac: j */
  L_00b0: a4 = 16;  /* 00b0 */
  ST32(a1 + 0x10, a4);  /* 00b2 */
  if (a3 < 3u) goto L_010c;  /* 00b4: bltui a3, 3, 10c <esp_mesh_flush_upstream_packets+0xd4> */
  L_00b7: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b7: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00ba */
  if (a8 == 0) goto L_010c;  /* 00bc: beqz a8, 10c <esp_mesh_flush_upstream_packets+0xd4> */
  L_00bf: a4 = LD32(a8 + 0x150);  /* 00bf */
  if (a4 == 0) goto L_010c;  /* 00c2: beqz a4, 10c <esp_mesh_flush_upstream_packets+0xd4> */
  L_00c5: a10 = LD32(a8 + 0x158);  /* 00c5 */
  __asm__ volatile("" ::: "memory");  /* 00c8: memw */
  /* 00cb: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a6 = a10;  /* 00ce */
  a8 = LD32(a3 + 0x0);  /* 00d0 */
  a7 = (u32)&g_mesh_ext_cfg + 0x0;  /* 00d2: l32r -> global */
  a8 = LD32(a8 + 0x78);  /* 00d5 */
  a10 = LD32(a2 + 0x18);  /* 00d8 */
  a7 = LD8U(a7 + 0xbd);  /* 00db */
  /* 00de: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = a10;  /* 00e1 */
  a3 = LD32(a3 + 0x0);  /* 00e3 */
  a10 = LD32(a5 + 0x0);  /* 00e5 */
  a3 = LD32(a3 + 0x78);  /* 00e7 */
  ST32(a1 + 0x20, a8);  /* 00ea */
  __asm__ volatile("" ::: "memory");  /* 00ec: memw */
  /* 00ef: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a15 = a7;  /* 00f2 */
  a13 = a6;  /* 00f4 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00f6: -> "mesh" */
  a14 = a11;  /* 00f9 */
  a8 = LD32(a1 + 0x20);  /* 00fb */
  a12 = (u32)(RODATA__rodata_esp_mesh_flush_upstream_packets_str1_1 + 0x0);  /* 00fd: l32r -> .rodata.esp_mesh_flush_upstream_packets.str1.1 */
  ST32(a1 + 0x4, a10);  /* 0100 */
  a10 = 3;  /* 0102 */
  ST32(a1 + 0x0, a8);  /* 0104 */
  __asm__ volatile("" ::: "memory");  /* 0106: memw */
  /* 0109: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_010c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 010c: l32r -> global */
  goto L_015c;  /* 010f: j */
  L_0112: a8 = LD32(a3 + 0x0);  /* 0112 */
  if (a8 == 0) goto L_0149;  /* 0114: beqz.n a8, 149 <esp_mesh_flush_upstream_packets+0x111> */
  L_0116: a4 = LD32(a8 + 0x150);  /* 0116 */
  if (a4 == 0) goto L_0149;  /* 0119: beqz.n a4, 149 <esp_mesh_flush_upstream_packets+0x111> */
  L_011b: a10 = LD32(a8 + 0x158);  /* 011b */
  /* 011e: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 0121 */
  a8 = LD32(a3 + 0x0);  /* 0123 */
  a10 = LD32(a2 + 0x18);  /* 0125 */
  a8 = LD32(a8 + 0x78);  /* 0127 */
  /* 012a: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a13 = a5;  /* 012d */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 012f: -> "mesh" */
  a14 = a11;  /* 0132 */
  a8 = 0x00000e0cu;  /* 0134: l32r = 3596 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0137: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_flush_upstream_packets_str1_1 + 0x0);  /* 013a: l32r -> .rodata.esp_mesh_flush_upstream_packets.str1.1 */
  ST32(a1 + 0x4, a10);  /* 013d */
  a10 = 2;  /* 013f */
  ST32(a1 + 0x0, a8);  /* 0141 */
  __asm__ volatile("" ::: "memory");  /* 0143: memw */
  /* 0146: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0149: a12 = 0;  /* 0149 */
  a11 = a1 + (16);  /* 014b */
  a4 = LD32(a3 + 0x0);  /* 014e */
  a10 = LD32(a2 + 0x18);  /* 0150 */
  a4 = LD32(a4 + 0x74);  /* 0152 */
  /* 0155: INDIRECT callx a4 <- mem[a4+0x74]; result unknown */ a2 = 0;
  a4 = 16;  /* 0158 */
  ST32(a1 + 0x10, a4);  /* 015a */
  L_015c: a10 = LD32(a2 + 0x18);  /* 015c */
  if (a10 != 0) goto L_0168;  /* 015e: bnez.n a10, 168 <esp_mesh_flush_upstream_packets+0x130> */
  L_0160: a2 = 0;  /* 0160 */
  __asm__ volatile("" ::: "memory");  /* 0162: memw */
  goto L_017c;  /* 0165: j */
  L_0168: a4 = LD32(a3 + 0x0);  /* 0168 */
  a12 = 0;  /* 016a */
  a11 = a1 + (16);  /* 016c */
  a4 = LD32(a4 + 0x70);  /* 016f */
  /* 0172: INDIRECT callx a4 <- mem[a4+0x70]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_0112;  /* 0175: bnei a10, 1, 112 <esp_mesh_flush_upstream_packets+0xda> */
  L_0178: goto L_0160;  /* 0178: j */
  L_017c: return a2;  /* 017c: retw.n */
}


/* esp_mesh_force_txupQ_pending @ mesh_schedule.o 00000038 size 272B bind GLOBAL
 * Calls: esp_mesh_txupQ_pending | indirect[5]: mem[a3+0x158]; mem[a3+0x150]; mem[a8+0x158]; unknown | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.__func__$14, .rodata.esp_mesh_force_txupQ_pending.str1.1, .rodata.esp_mesh_send_block_event.str1.1
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=8); reloc-direct=1, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_force_txupQ_pending(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F6;
  /* 0038: entry a1, 80 (frame 80 bytes) */
  if (a2 != 0) goto L_006a;  /* 003b: bnez.n a2, 6a <esp_mesh_force_txupQ_pending+0x32> */
  L_003d: a2 = (u32)&g_log_level + 0x0;  /* 003d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0040 */
  a2 = 0x00004008u;  /* 0043: l32r = 16392 */
  if (a3 >= 3u) goto L_004c;  /* 0046: bgeui a3, 3, 4c <esp_mesh_force_txupQ_pending+0x14> */
  L_0049: goto L_0146;  /* 0049: j */
  L_004c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 004c: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 004f */
  if (a3 == 0) goto L_0146;  /* 0052: beqz a3, 146 <esp_mesh_force_txupQ_pending+0x10e> */
  L_0055: a4 = LD32(a3 + 0x150);  /* 0055 */
  if (a4 == 0) goto L_0146;  /* 0058: beqz a4, 146 <esp_mesh_force_txupQ_pending+0x10e> */
  L_005b: a10 = LD32(a3 + 0x158);  /* 005b */
  a3 = 0x5df;  /* 005e */
  /* 0061: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0064: -> "mesh" */
  goto L_0098;  /* 0067: j */
  L_006a: a3 = LD32(a2 + 0x0);  /* 006a */
  if (a3 != 0) goto L_00b1;  /* 006c: bnez a3, b1 <esp_mesh_force_txupQ_pending+0x79> */
  L_006f: a2 = (u32)&g_log_level + 0x0;  /* 006f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0072 */
  a2 = 0x00004008u;  /* 0074: l32r = 16392 */
  if (a3 >= 3u) goto L_007d;  /* 0077: bgeui a3, 3, 7d <esp_mesh_force_txupQ_pending+0x45> */
  L_007a: goto L_0146;  /* 007a: j */
  L_007d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 007d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0080 */
  if (a3 == 0) goto L_0146;  /* 0083: beqz a3, 146 <esp_mesh_force_txupQ_pending+0x10e> */
  L_0086: a4 = LD32(a3 + 0x150);  /* 0086 */
  if (a4 == 0) goto L_0146;  /* 0089: beqz a4, 146 <esp_mesh_force_txupQ_pending+0x10e> */
  L_008c: a10 = LD32(a3 + 0x158);  /* 008c */
  a3 = 0x5e0;  /* 008f */
  /* 0092: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0095: -> "mesh" */
  L_0098: a13 = a10;  /* 0098 */
  a14 = a11;  /* 009a */
  a10 = 3;  /* 009c */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 009e: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00a1: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 00a4 */
  __asm__ volatile("" ::: "memory");  /* 00a6: memw */
  /* 00a9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0146;  /* 00ac: j */
  L_00b1: a5 = (u32)(RODATA__rodata___func___14 + 0x0);  /* 00b1: l32r -> .rodata.__func__$14 */
  a3 = a3 + (14);  /* 00b4 */
  a14 = 0x5ea;  /* 00b6 */
  a13 = a5;  /* 00b9 */
  a11 = 1;  /* 00bb */
  a12 = LD32(a3 + 0x18);  /* 00be */
  a10 = a2;  /* 00c1 */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 00c3: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 00c6: callx a8 via reloc-expand */
  a4 = a10;  /* 00c9: mov */
  if (a10 == 0) goto L_0132;  /* 00cc: beqz a10, 132 <esp_mesh_force_txupQ_pending+0xfa> */
  L_00cf: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 00cf: l32r -> global */
  a8 = LD32(a6 + 0x0);  /* 00d2 */
  if (a8 == 0) goto L_0132;  /* 00d5: beqz a8, 132 <esp_mesh_force_txupQ_pending+0xfa> */
  L_00d8: a6 = LD32(a8 + 0x150);  /* 00d8 */
  if (a6 == 0) goto L_0132;  /* 00db: beqz a6, 132 <esp_mesh_force_txupQ_pending+0xfa> */
  L_00de: a10 = LD32(a8 + 0x158);  /* 00de */
  /* 00e1: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = (u32)(RODATA__rodata_esp_mesh_force_txupQ_pending_str1_1 + 0x0);  /* 00e4: -> "no found" */
  if (a4 == -1) goto L_00f6;  /* 00e7: beqi a4, -1, f6 <esp_mesh_force_txupQ_pending+0xbe> */
  L_00ea: a9 = 0x00004004u;  /* 00ea: l32r = 16388 */
  a8 = (u32)(RODATA__rodata_esp_mesh_force_txupQ_pending_str1_1 + 0x0);  /* 00ed: -> "no found" */
  if (a4 == a9) goto L_00f6;  /* 00f0: beq a4, a9, f6 <esp_mesh_force_txupQ_pending+0xbe> */
  L_00f3: a8 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 00f3: -> "no window" */
  L_00f6: a13 = a10;  /* 00f6 */
  a10 = 2;  /* 00f8 */
  ST32(a1 + 0x20, a4);  /* 00fa */
  a4 = LD8U(a2 + 0x11);  /* 00fc */
  ST32(a1 + 0x1c, a4);  /* 00ff */
  a4 = LD8U(a2 + 0x10);  /* 0101 */
  ST32(a1 + 0x18, a4);  /* 0104 */
  a4 = LD8U(a2 + 0xf);  /* 0106 */
  ST32(a1 + 0x14, a4);  /* 0109 */
  a4 = LD8U(a2 + 0xe);  /* 010b */
  ST32(a1 + 0x10, a4);  /* 010e */
  a4 = LD8U(a2 + 0xd);  /* 0110 */
  ST32(a1 + 0xc, a4);  /* 0113 */
  a4 = LD8U(a2 + 0xc);  /* 0115 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0118: -> "mesh" */
  a14 = a11;  /* 011b */
  ST32(a1 + 0x8, a4);  /* 011d */
  a4 = 0x5ec;  /* 011f */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0122: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_force_txupQ_pending_str1_1 + 0x0);  /* 0125: -> "no found" */
  ST32(a1 + 0x4, a8);  /* 0128 */
  ST32(a1 + 0x0, a4);  /* 012a */
  __asm__ volatile("" ::: "memory");  /* 012c: memw */
  /* 012f: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_0132: a10 = a2;  /* 0132 */
  a14 = 0x5ef;  /* 0134 */
  a13 = a5;  /* 0137 */
  a12 = LD32(a3 + 0x18);  /* 0139 */
  a11 = 0;  /* 013c */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 013e: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0141: callx a8 via reloc-expand */
  a2 = 0;  /* 0144 */
  L_0146: return a2;  /* 0146: retw.n */
}


/* esp_mesh_forward_check_active @ mesh_schedule.o 00000008 size 51B bind GLOBAL
 * Calls: esp_mesh_get_layer, esp_mesh_ps_control_check_awake | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=2); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_forward_check_active(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&esp_mesh_get_layer + 0x0;  /* 000b: l32r -> global */
  a2 = esp_mesh_get_layer(a2, a3, a4, a5, a6, a7);  /* 000e: callx a8 via reloc-expand */
  a10 = 11;  /* 0011 */
  a8 = (u32)&esp_mesh_ps_control_check_awake + 0x0;  /* 0013: l32r -> global */
  a2 = esp_mesh_ps_control_check_awake(a2, a3, a4, a5, a6, a7);  /* 0016: callx a8 via reloc-expand */
  if (a10 != 0) goto L_002a;  /* 0019: bnez.n a10, 2a <esp_mesh_forward_check_active+0x22> */
  L_001b: ST8(a3 + 0x0, a10);  /* 001b */
  __asm__ volatile("" ::: "memory");  /* 001e: memw */
  a8 = 1;  /* 0021 */
  __asm__ volatile("" ::: "memory");  /* 0023: memw */
  goto L_002e;  /* 0026: j */
  L_002a: if (a4 == 0) goto L_0034;  /* 002a: beqz.n a4, 34 <esp_mesh_forward_check_active+0x2c> */
  L_002c: a8 = 0;  /* 002c */
  L_002e: ST8(a4 + 0x0, a8);  /* 002e */
  __asm__ volatile("" ::: "memory");  /* 0031: memw */
  L_0034: a2 = 0;  /* 0034 */
  __asm__ volatile("" ::: "memory");  /* 0036: memw */
  return a2;  /* 0039: retw.n */
}


/* esp_mesh_get_tx_pending @ mesh_schedule.o 0000001c size 71B bind GLOBAL
 * Calls: mesh_get_tx_pending | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=6); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_tx_pending(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  /* 001c: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&g_is_mesh_started + 0x0;  /* 001f: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 0022 */
  if (a3 != 0) goto L_0057;  /* 0025: bnez.n a3, 57 <esp_mesh_get_tx_pending+0x3b> */
  L_0027: a2 = (u32)&g_log_level + 0x0;  /* 0027: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002a */
  a2 = 0x00004004u;  /* 002c: l32r = 16388 */
  if (a3 < 3u) goto L_0061;  /* 002f: bltui a3, 3, 61 <esp_mesh_get_tx_pending+0x45> */
  L_0032: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0032: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0035 */
  if (a8 == 0) goto L_0061;  /* 0038: beqz.n a8, 61 <esp_mesh_get_tx_pending+0x45> */
  L_003a: a3 = LD32(a8 + 0x150);  /* 003a */
  if (a3 == 0) goto L_0061;  /* 003d: beqz.n a3, 61 <esp_mesh_get_tx_pending+0x45> */
  L_003f: a10 = LD32(a8 + 0x158);  /* 003f */
  /* 0042: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0045 */
  a10 = 3;  /* 0047 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0049: -> "mesh" */
  a14 = a11;  /* 004c */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 004e: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 0051: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0061;  /* 0054: j */
  L_0057: a10 = a2;  /* 0057 */
  a8 = (u32)&mesh_get_tx_pending;  /* 0059: l32r -> func addr */
  a2 = mesh_get_tx_pending(a2, a3, a4, a5, a6, a7);  /* 005c: callx a8 via reloc-expand */
  a2 = 0;  /* 005f */
  L_0061: return a2;  /* 0061: retw.n */
}


/* esp_mesh_operation_rxseqno @ mesh_schedule.o 00000050 size 910B bind GLOBAL
 * Calls: mesh_mutex_lock, esp_mesh_get_child_idx, mesh_mutex_unlock, memcpy, memcmp, memset, esp_mesh_push_to_nwk_queue | indirect[14]: mem[a3+0x158]; mem[a3+0x150]; mem[a6+0x110]; mem[a8+0x110] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, mesh_conn_mutex, .rodata.__func__$16, g_mesh_conn, .rodata.esp_mesh_operation_rxseqno.str1.1
 * Fidelity: medium - 14 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=7, refs=15); reloc-direct=7, funcdb-attributed=0, unknown-indirect=14 */
u32 esp_mesh_operation_rxseqno(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F8;
  /* 0050: entry a1, 0x120 (frame 0x120 bytes) */
  a13 = a2;  /* 0053 */
  a9 = a5;  /* 0055 */
  a2 = 0x00004008u;  /* 0057: l32r = 16392 */
  a5 = a6;  /* 005a */
  if (a13 < 2u) goto L_0062;  /* 005c: bltui a13, 2, 62 <esp_mesh_operation_rxseqno+0x12> */
  L_005f: goto L_03dc;  /* 005f: j */
  L_0062: if (a3 != 0) goto L_008e;  /* 0062: bnez.n a3, 8e <esp_mesh_operation_rxseqno+0x3e> */
  L_0064: a3 = (u32)&g_log_level + 0x0;  /* 0064: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0067 */
  if (a3 >= 3u) goto L_0070;  /* 006a: bgeui a3, 3, 70 <esp_mesh_operation_rxseqno+0x20> */
  L_006d: goto L_03dc;  /* 006d: j */
  L_0070: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0070: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0073 */
  if (a3 == 0) goto L_03dc;  /* 0076: beqz a3, 3dc <esp_mesh_operation_rxseqno+0x38c> */
  L_0079: a4 = LD32(a3 + 0x150);  /* 0079 */
  if (a4 == 0) goto L_03dc;  /* 007c: beqz a4, 3dc <esp_mesh_operation_rxseqno+0x38c> */
  L_007f: a10 = LD32(a3 + 0x158);  /* 007f */
  a3 = 0x4ea;  /* 0082 */
  /* 0085: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0088: -> "mesh" */
  goto L_00b7;  /* 008b: j */
  L_008e: if (a4 != 0) goto L_00d0;  /* 008e: bnez.n a4, d0 <esp_mesh_operation_rxseqno+0x80> */
  L_0090: a3 = (u32)&g_log_level + 0x0;  /* 0090: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0093 */
  if (a3 >= 3u) goto L_009c;  /* 0096: bgeui a3, 3, 9c <esp_mesh_operation_rxseqno+0x4c> */
  L_0099: goto L_03dc;  /* 0099: j */
  L_009c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 009c: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 009f */
  if (a3 == 0) goto L_03dc;  /* 00a2: beqz a3, 3dc <esp_mesh_operation_rxseqno+0x38c> */
  L_00a5: a4 = LD32(a3 + 0x150);  /* 00a5 */
  if (a4 == 0) goto L_03dc;  /* 00a8: beqz a4, 3dc <esp_mesh_operation_rxseqno+0x38c> */
  L_00ab: a10 = LD32(a3 + 0x158);  /* 00ab */
  a3 = 0x4eb;  /* 00ae */
  /* 00b1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00b4: -> "mesh" */
  L_00b7: a13 = a10;  /* 00b7 */
  a14 = a11;  /* 00b9 */
  a10 = 3;  /* 00bb */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00bd: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00c0: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 00c3 */
  __asm__ volatile("" ::: "memory");  /* 00c6: memw */
  /* 00c9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03dc;  /* 00cc: j */
  L_00d0: if (a9 != 0) goto L_00fc;  /* 00d0: bnez.n a9, fc <esp_mesh_operation_rxseqno+0xac> */
  L_00d2: a3 = (u32)&g_log_level + 0x0;  /* 00d2: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d5 */
  if (a3 >= 3u) goto L_00dd;  /* 00d7: bgeui a3, 3, dd <esp_mesh_operation_rxseqno+0x8d> */
  L_00da: goto L_03dc;  /* 00da: j */
  L_00dd: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00dd: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00e0 */
  if (a3 == 0) goto L_03dc;  /* 00e2: beqz a3, 3dc <esp_mesh_operation_rxseqno+0x38c> */
  L_00e5: a4 = LD32(a3 + 0x150);  /* 00e5 */
  if (a4 == 0) goto L_03dc;  /* 00e8: beqz a4, 3dc <esp_mesh_operation_rxseqno+0x38c> */
  L_00eb: a10 = LD32(a3 + 0x158);  /* 00eb */
  a3 = 0x4ec;  /* 00ee */
  /* 00f1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00f4: -> "mesh" */
  goto L_00b7;  /* 00f7: j */
  L_00fc: a2 = (u32)&mesh_conn_mutex + 0x0;  /* 00fc: l32r -> global */
  a12 = 0x4f2;  /* 00ff */
  a10 = LD32(a2 + 0x0);  /* 0102 */
  a11 = (u32)(RODATA__rodata___func___16 + 0x0);  /* 0104: l32r -> .rodata.__func__$16 */
  ST32(a1 + 0xf4, a9);  /* 0107 */
  ST32(a1 + 0xf0, a13);  /* 010a */
  __asm__ volatile("" ::: "memory");  /* 010d: memw */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 0110: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 0113: callx a8 via reloc-expand */
  a10 = a3;  /* 0116 */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 0118: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6, a7);  /* 011b: callx a8 via reloc-expand */
  a6 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 011e: sext */
  a9 = LD32(a1 + 0xf4);  /* 0121 */
  a13 = LD32(a1 + 0xf0);  /* 0124 */
  if (a6 != -1) goto L_012d;  /* 0127: bnei a6, -1, 12d <esp_mesh_operation_rxseqno+0xdd> */
  L_012a: goto L_031d;  /* 012a: j */
  L_012d: a2 = a6 << 6;  /* 012d */
  a7 = (u32)&g_mesh_conn + 0x0;  /* 0130: l32r -> global */
  if (a13 != 0) goto L_01fc;  /* 0133: bnez a13, 1fc <esp_mesh_operation_rxseqno+0x1ac> */
  L_0136: a6 = a7 + a2;  /* 0136 */
  a10 = LD16U(a6 + 0x14);  /* 0138 */
  ST16(a9 + 0x0, a10);  /* 013b */
  __asm__ volatile("" ::: "memory");  /* 013e: memw */
  if (a5 == 0) goto L_0149;  /* 0141: beqz.n a5, 149 <esp_mesh_operation_rxseqno+0xf9> */
  L_0143: a6 = LD32(a6 + 0x18);  /* 0143 */
  ST32(a5 + 0x0, a6);  /* 0146 */
  L_0149: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0149: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 014c */
  a10 = LD32(a6 + 0x110);  /* 014e */
  a6 = a7 + a2;  /* 0151 */
  __asm__ volatile("" ::: "memory");  /* 0153: memw */
  /* 0156: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a6 + 0x24);  /* 0159 */
  if ((i32)a11 < (i32)a9) goto L_0196;  /* 015b: blt a11, a9, 196 <esp_mesh_operation_rxseqno+0x146> */
  L_015e: if (a9 != a11) goto L_0166;  /* 015e: bne a9, a11, 166 <esp_mesh_operation_rxseqno+0x116> */
  L_0161: a6 = LD32(a6 + 0x20);  /* 0161 */
  if (a10 < a6) goto L_0196;  /* 0163: bltu a10, a6, 196 <esp_mesh_operation_rxseqno+0x146> */
  L_0166: a6 = LD32(a5 + 0x0);  /* 0166 */
  a10 = LD32(a6 + 0x110);  /* 0168 */
  a6 = a7 + a2;  /* 016b */
  /* 016d: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a6 + 0x20);  /* 0170 */
  a9 = a10 - a9;  /* 0172: sub */
  a12 = LD32(a6 + 0x24);  /* 0175 */
  a6 = 1;  /* 0177 */
  if (a10 < a9) goto L_0180;  /* 017a: bltu a10, a9, 180 <esp_mesh_operation_rxseqno+0x130> */
  L_017d: a6 = 0;  /* 017d */
  L_0180: a11 = a11 - a12;  /* 0180: sub */
  a11 = a11 - a6;  /* 0183: sub */
  a6 = a11 << 22;  /* 0186 */
  a9 = a9 >> 10;  /* 0189 */
  a9 = a6 | a9;  /* 018c */
  a11 = (i32)a11 >> 10;  /* 018f */
  goto L_01ce;  /* 0192: j */
  L_0196: a6 = LD32(a5 + 0x0);  /* 0196 */
  a10 = LD32(a6 + 0x110);  /* 0198 */
  a6 = a7 + a2;  /* 019b */
  /* 019d: INDIRECT callx a10 <- mem[a6+0x110]; result unknown */ a2 = 0;
  a12 = -1;  /* 01a0 */
  a9 = LD32(a6 + 0x20);  /* 01a2 */
  a9 = a9 ^ a12;  /* 01a4 */
  a10 = a9 + a10;  /* 01a7 */
  a12 = 1;  /* 01a9 */
  a6 = LD32(a6 + 0x24);  /* 01ab */
  if (a10 < a9) goto L_01b2;  /* 01ad: bltu a10, a9, 1b2 <esp_mesh_operation_rxseqno+0x162> */
  L_01b0: a12 = 0;  /* 01b0 */
  L_01b2: a11 = a6 + a11;  /* 01b2 */
  a9 = a10 + (1);  /* 01b4 */
  a11 = a12 + a11;  /* 01b6 */
  a6 = 1;  /* 01b8 */
  if (a9 < a10) goto L_01c0;  /* 01bb: bltu a9, a10, 1c0 <esp_mesh_operation_rxseqno+0x170> */
  L_01be: a6 = 0;  /* 01be */
  L_01c0: a6 = a6 + a11;  /* 01c0 */
  a10 = a6 << 22;  /* 01c2 */
  a9 = a9 >> 10;  /* 01c5 */
  a9 = a10 | a9;  /* 01c8 */
  a11 = (i32)a6 >> 10;  /* 01cb */
  L_01ce: a6 = 1;  /* 01ce */
  if ((i32)a11 >= 1) goto L_01e0;  /* 01d0: bgei a11, 1, 1e0 <esp_mesh_operation_rxseqno+0x190> */
  L_01d3: if (a11 != 0) goto L_01de;  /* 01d3: bnez.n a11, 1de <esp_mesh_operation_rxseqno+0x18e> */
  L_01d5: a10 = 0x177;  /* 01d5 */
  a10 = a10 << 3;  /* 01d8 */
  if (a10 < a9) goto L_01e0;  /* 01db: bltu a10, a9, 1e0 <esp_mesh_operation_rxseqno+0x190> */
  L_01de: a6 = 0;  /* 01de */
  L_01e0: a6 = (a6 >> 8) & 0x1;  /* 01e0: extui width 1 */
  goto L_03d6;  /* 01e3: j */
  L_01e6: a8 = LD32(a5 + 0x0);  /* 01e6 */
  a7 = a7 + a2;  /* 01e8 */
  a10 = LD32(a8 + 0x110);  /* 01ea */
  /* 01ed: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  ST32(a7 + 0x20, a10);  /* 01f0 */
  ST32(a7 + 0x24, a11);  /* 01f2 */
  __asm__ volatile("" ::: "memory");  /* 01f4: memw */
  goto L_036d;  /* 01f7: j */
  L_01fc: a9 = LD16U(a9 + 0x0);  /* 01fc */
  a2 = a7 + a2;  /* 01ff */
  ST16(a2 + 0x14, a9);  /* 0201 */
  __asm__ volatile("" ::: "memory");  /* 0204: memw */
  if (a5 != 0) goto L_0210;  /* 0207: bnez.n a5, 210 <esp_mesh_operation_rxseqno+0x1c0> */
  L_0209: __asm__ volatile("" ::: "memory");  /* 0209: memw */
  goto L_0315;  /* 020c: j */
  L_0210: a2 = LD32(a2 + 0x18);  /* 0210 */
  a9 = LD32(a5 + 0x0);  /* 0212 */
  if (a2 != 0) goto L_0294;  /* 0214: bnez a2, 294 <esp_mesh_operation_rxseqno+0x244> */
  L_0217: if (a9 >= 2u) goto L_021d;  /* 0217: bgeui a9, 2, 21d <esp_mesh_operation_rxseqno+0x1cd> */
  L_021a: goto L_030c;  /* 021a: j */
  L_021d: a2 = (u32)&g_log_level + 0x0;  /* 021d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0220 */
  if (a2 >= 3u) goto L_0235;  /* 0222: bgeui a2, 3, 235 <esp_mesh_operation_rxseqno+0x1e5> */
  L_0225: goto L_030c;  /* 0225: j */
  L_0228: a2 = (u32)&g_log_level + 0x0;  /* 0228: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 022b */
  if (a2 >= 3u) goto L_02a9;  /* 022d: bgeui a2, 3, 2a9 <esp_mesh_operation_rxseqno+0x259> */
  L_0230: goto L_030c;  /* 0230: j */
  L_0235: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0235: l32r -> global */
  a9 = LD32(a2 + 0x0);  /* 0238 */
  if (a9 == 0) goto L_02a9;  /* 023a: beqz a9, 2a9 <esp_mesh_operation_rxseqno+0x259> */
  L_023d: a2 = LD32(a9 + 0x150);  /* 023d */
  if (a2 == 0) goto L_02a9;  /* 0240: beqz a2, 2a9 <esp_mesh_operation_rxseqno+0x259> */
  L_0243: a10 = LD32(a9 + 0x158);  /* 0243 */
  /* 0246: INDIRECT callx a10 <- mem[a9+0x158]; result unknown */ a2 = 0;
  a9 = a6 << 6;  /* 0249 */
  a9 = a7 + a9;  /* 024c */
  a12 = LD8U(a9 + 0x10);  /* 024e */
  a13 = a10;  /* 0251 */
  a15 = 0x50d;  /* 0253 */
  a10 = 3;  /* 0256 */
  ST32(a1 + 0x28, a12);  /* 0258 */
  a12 = LD32(a9 + 0xc);  /* 025a */
  ST32(a1 + 0x24, a12);  /* 025c */
  a9 = LD32(a9 + 0x8);  /* 025e */
  ST32(a1 + 0x20, a9);  /* 0260 */
  a9 = LD32(a5 + 0x0);  /* 0262 */
  ST32(a1 + 0x1c, a9);  /* 0264 */
  a9 = LD8U(a3 + 0x5);  /* 0266 */
  ST32(a1 + 0x18, a9);  /* 0269 */
  a9 = LD8U(a3 + 0x4);  /* 026b */
  ST32(a1 + 0x14, a9);  /* 026e */
  a9 = LD8U(a3 + 0x3);  /* 0270 */
  ST32(a1 + 0x10, a9);  /* 0273 */
  a9 = LD8U(a3 + 0x2);  /* 0275 */
  ST32(a1 + 0xc, a9);  /* 0278 */
  a9 = LD8U(a3 + 0x1);  /* 027a */
  ST32(a1 + 0x8, a9);  /* 027d */
  a9 = LD8U(a3 + 0x0);  /* 027f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0282: -> "mesh" */
  a14 = a11;  /* 0285 */
  a12 = (u32)(RODATA__rodata_esp_mesh_operation_rxseqno_str1_1 + 0x0);  /* 0287: l32r -> .rodata.esp_mesh_operation_rxseqno.str1.1 */
  ST32(a1 + 0x4, a9);  /* 028a */
  ST32(a1 + 0x0, a6);  /* 028c */
  __asm__ volatile("" ::: "memory");  /* 028e: memw */
  /* 0291: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  L_0294: a9 = a6 << 6;  /* 0294 */
  a9 = a7 + a9;  /* 0297 */
  a2 = LD32(a5 + 0x0);  /* 0299 */
  a9 = LD32(a9 + 0x18);  /* 029b */
  a2 = a2 - a9;  /* 029d: sub */
  if (a2 >= 2u) goto L_0228;  /* 02a0: bgeui a2, 2, 228 <esp_mesh_operation_rxseqno+0x1d8> */
  L_02a3: goto L_030c;  /* 02a3: j */
  L_02a9: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 02a9: l32r -> global */
  a9 = LD32(a2 + 0x0);  /* 02ac */
  if (a9 == 0) goto L_030c;  /* 02ae: beqz a9, 30c <esp_mesh_operation_rxseqno+0x2bc> */
  L_02b1: a2 = LD32(a9 + 0x150);  /* 02b1 */
  if (a2 == 0) goto L_030c;  /* 02b4: beqz a2, 30c <esp_mesh_operation_rxseqno+0x2bc> */
  L_02b7: a10 = LD32(a9 + 0x158);  /* 02b7 */
  /* 02ba: INDIRECT callx a10 <- mem[a9+0x158]; result unknown */ a2 = 0;
  a9 = a6 << 6;  /* 02bd */
  a9 = a7 + a9;  /* 02c0 */
  a12 = LD8U(a9 + 0x10);  /* 02c2 */
  a13 = a10;  /* 02c5 */
  a15 = 0x516;  /* 02c7 */
  a10 = 3;  /* 02ca */
  ST32(a1 + 0x2c, a12);  /* 02cc */
  a12 = LD32(a9 + 0xc);  /* 02ce */
  ST32(a1 + 0x28, a12);  /* 02d0 */
  a12 = LD32(a9 + 0x8);  /* 02d2 */
  ST32(a1 + 0x24, a12);  /* 02d4 */
  a12 = LD32(a5 + 0x0);  /* 02d6 */
  ST32(a1 + 0x20, a12);  /* 02d8 */
  a9 = LD32(a9 + 0x18);  /* 02da */
  ST32(a1 + 0x1c, a9);  /* 02dc */
  a9 = LD8U(a3 + 0x5);  /* 02de */
  ST32(a1 + 0x18, a9);  /* 02e1 */
  a9 = LD8U(a3 + 0x4);  /* 02e3 */
  ST32(a1 + 0x14, a9);  /* 02e6 */
  a9 = LD8U(a3 + 0x3);  /* 02e8 */
  ST32(a1 + 0x10, a9);  /* 02eb */
  a9 = LD8U(a3 + 0x2);  /* 02ed */
  ST32(a1 + 0xc, a9);  /* 02f0 */
  a9 = LD8U(a3 + 0x1);  /* 02f2 */
  ST32(a1 + 0x8, a9);  /* 02f5 */
  a9 = LD8U(a3 + 0x0);  /* 02f7 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 02fa: -> "mesh" */
  a14 = a11;  /* 02fd */
  a12 = (u32)(RODATA__rodata_esp_mesh_operation_rxseqno_str1_1 + 0x0);  /* 02ff: l32r -> .rodata.esp_mesh_operation_rxseqno.str1.1 */
  ST32(a1 + 0x4, a9);  /* 0302 */
  ST32(a1 + 0x0, a6);  /* 0304 */
  __asm__ volatile("" ::: "memory");  /* 0306: memw */
  /* 0309: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  L_030c: a6 = a6 << 6;  /* 030c */
  a6 = a7 + a6;  /* 030f */
  a2 = LD32(a5 + 0x0);  /* 0311 */
  ST32(a6 + 0x18, a2);  /* 0313 */
  L_0315: a6 = 0;  /* 0315 */
  __asm__ volatile("" ::: "memory");  /* 0317: memw */
  goto L_036d;  /* 031a: j */
  L_031d: a2 = (u32)&g_log_level + 0x0;  /* 031d: l32r -> global */
  a6 = 1;  /* 0320 */
  a2 = LD32(a2 + 0x0);  /* 0322 */
  if (a2 < 3u) goto L_036d;  /* 0324: bltui a2, 3, 36d <esp_mesh_operation_rxseqno+0x31d> */
  L_0327: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0327: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 032a */
  if (a2 == 0) goto L_036d;  /* 032c: beqz.n a2, 36d <esp_mesh_operation_rxseqno+0x31d> */
  L_032e: a7 = LD32(a2 + 0x150);  /* 032e */
  if (a7 == 0) goto L_036d;  /* 0331: beqz.n a7, 36d <esp_mesh_operation_rxseqno+0x31d> */
  L_0333: a10 = LD32(a2 + 0x158);  /* 0333 */
  /* 0336: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0339 */
  a15 = 0x523;  /* 033b */
  a2 = LD8U(a3 + 0x5);  /* 033e */
  a10 = 3;  /* 0341 */
  ST32(a1 + 0x14, a2);  /* 0343 */
  a2 = LD8U(a3 + 0x4);  /* 0345 */
  ST32(a1 + 0x10, a2);  /* 0348 */
  a2 = LD8U(a3 + 0x3);  /* 034a */
  ST32(a1 + 0xc, a2);  /* 034d */
  a2 = LD8U(a3 + 0x2);  /* 034f */
  ST32(a1 + 0x8, a2);  /* 0352 */
  a2 = LD8U(a3 + 0x1);  /* 0354 */
  ST32(a1 + 0x4, a2);  /* 0357 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0359: -> "mesh" */
  a14 = a11;  /* 035c */
  a2 = LD8U(a3 + 0x0);  /* 035e */
  a12 = (u32)(RODATA__rodata_esp_mesh_operation_rxseqno_str1_1 + 0x0);  /* 0361: l32r -> .rodata.esp_mesh_operation_rxseqno.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0364 */
  __asm__ volatile("" ::: "memory");  /* 0367: memw */
  /* 036a: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_036d: a12 = 0x525;  /* 036d */
  a2 = (u32)&mesh_conn_mutex + 0x0;  /* 0370: l32r -> global */
  a11 = (u32)(RODATA__rodata___func___16 + 0x0);  /* 0373: l32r -> .rodata.__func__$16 */
  a10 = LD32(a2 + 0x0);  /* 0376 */
  a2 = 0;  /* 0378 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 037b: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 037e: callx a8 via reloc-expand */
  if (a6 == a2) goto L_03dc;  /* 0381: beq a6, a2, 3dc <esp_mesh_operation_rxseqno+0x38c> */
  L_0384: a12 = 6;  /* 0384 */
  a11 = a3;  /* 0386 */
  a2 = 18;  /* 0388 */
  a10 = a1 + (52);  /* 038a */
  ST32(a1 + 0x30, a2);  /* 038d */
  __asm__ volatile("" ::: "memory");  /* 0390: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0393: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0396: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0399 */
  a11 = a4;  /* 039b */
  a10 = a3;  /* 039d */
  a8 = (u32)&memcmp + 0x0;  /* 039f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 03a2: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 03a5 */
  if (a10 != 0) goto L_03ba;  /* 03a7: bnez.n a10, 3ba <esp_mesh_operation_rxseqno+0x36a> */
  L_03a9: a11 = a10;  /* 03a9 */
  a10 = a1 + (58);  /* 03ab */
  a8 = (u32)&memset + 0x0;  /* 03ae: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 03b1: callx a8 (libc, via reloc-expand) */
  goto L_03c5;  /* 03b4: j */
  L_03ba: a11 = a4;  /* 03ba */
  a10 = a1 + (58);  /* 03bc */
  a8 = (u32)&memcpy + 0x0;  /* 03bf: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 03c2: callx a8 (libc, via reloc-expand) */
  L_03c5: a11 = 0;  /* 03c5 */
  a10 = a1 + (48);  /* 03c7 */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 03ca: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 03cd: callx a8 via reloc-expand */
  a2 = 0;  /* 03d0 */
  goto L_03dc;  /* 03d2: j */
  L_03d6: if (a6 != 0) goto L_01e6;  /* 03d6: bnez a6, 1e6 <esp_mesh_operation_rxseqno+0x196> */
  L_03d9: goto L_0315;  /* 03d9: j */
  L_03dc: return a2;  /* 03dc: retw.n */
}


/* esp_mesh_print_txQ_waiting @ mesh_schedule.o 00000020 size 82B bind GLOBAL
 * Calls: mesh_print_txQ_waiting | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1, .bss.is_mesh_tx_started
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=7); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_print_txQ_waiting(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  /* 0020: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 0023: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0026 */
  if (a2 != 0) goto L_005d;  /* 0029: bnez.n a2, 5d <esp_mesh_print_txQ_waiting+0x3d> */
  L_002b: a2 = (u32)&g_log_level + 0x0;  /* 002b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002e */
  a2 = 0x00004004u;  /* 0030: l32r = 16388 */
  if (a3 < 3u) goto L_0070;  /* 0033: bltui a3, 3, 70 <esp_mesh_print_txQ_waiting+0x50> */
  L_0036: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0036: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0039 */
  if (a8 == 0) goto L_0070;  /* 003c: beqz.n a8, 70 <esp_mesh_print_txQ_waiting+0x50> */
  L_003e: a3 = LD32(a8 + 0x150);  /* 003e */
  if (a3 == 0) goto L_0070;  /* 0041: beqz.n a3, 70 <esp_mesh_print_txQ_waiting+0x50> */
  L_0043: a10 = LD32(a8 + 0x158);  /* 0043 */
  /* 0046: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0049 */
  a10 = 3;  /* 004b */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 004d: -> "mesh" */
  a14 = a11;  /* 0050 */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0052: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 0055: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0070;  /* 0058: j */
  L_005d: a2 = (u32)&LOCAL__bss_is_mesh_tx_started + 0x0;  /* 005d: l32r -> .bss.is_mesh_tx_started (same-object static) */
  a3 = LD8U(a2 + 0x0);  /* 0060 */
  a2 = 0x00004004u;  /* 0063: l32r = 16388 */
  if (a3 == 0) goto L_0070;  /* 0066: beqz.n a3, 70 <esp_mesh_print_txQ_waiting+0x50> */
  L_0068: a8 = (u32)&mesh_print_txQ_waiting;  /* 0068: l32r -> func addr */
  a2 = mesh_print_txQ_waiting(a2, a3, a4, a5, a6, a7);  /* 006b: callx a8 via reloc-expand */
  a2 = 0;  /* 006e */
  L_0070: return a2;  /* 0070: retw.n */
}


/* esp_mesh_process_txupQ_pending @ mesh_schedule.o 0000004c size 555B bind GLOBAL
 * Calls: esp_mesh_txupQ_pending | indirect[8]: mem[a3+0x158]; mem[a3+0x150]; mem[a6+0x158]; unknown | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.esp_mesh_process_txupQ_pending.str1.1, .rodata.esp_mesh_send_block_event.str1.1, .rodata.__func__$22
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=10); reloc-direct=1, funcdb-attributed=0, unknown-indirect=8 */
u32 esp_mesh_process_txupQ_pending(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0000001;
  /* 004c: entry a1, 128 (frame 128 bytes) */
  a4 = (u32)&g_is_mesh_started + 0x0;  /* 004f: l32r -> global */
  a2 = (a2 >> 8) & 0x1;  /* 0052: extui width 1 */
  a4 = LD8U(a4 + 0x0);  /* 0055 */
  if (a4 != 0) goto L_0091;  /* 0058: bnez.n a4, 91 <esp_mesh_process_txupQ_pending+0x45> */
  L_005a: a2 = (u32)&g_log_level + 0x0;  /* 005a: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005d */
  a2 = 0x00004004u;  /* 005f: l32r = 16388 */
  if (a3 >= 3u) goto L_0068;  /* 0062: bgeui a3, 3, 68 <esp_mesh_process_txupQ_pending+0x1c> */
  L_0065: goto L_0275;  /* 0065: j */
  L_0068: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0068: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006b */
  if (a3 == 0) goto L_0275;  /* 006e: beqz a3, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_0071: a4 = LD32(a3 + 0x150);  /* 0071 */
  if (a4 == 0) goto L_0275;  /* 0074: beqz a4, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_0077: a10 = LD32(a3 + 0x158);  /* 0077 */
  /* 007a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 007d */
  a10 = 3;  /* 007f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0081: -> "mesh" */
  a14 = a11;  /* 0084 */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0086: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 0089: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0275;  /* 008c: j */
  L_0091: if (a3 != 0) goto L_00be;  /* 0091: bnez.n a3, be <esp_mesh_process_txupQ_pending+0x72> */
  L_0093: a2 = (u32)&g_log_level + 0x0;  /* 0093: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0096 */
  a2 = 0x00004008u;  /* 0098: l32r = 16392 */
  if (a3 >= 3u) goto L_00a1;  /* 009b: bgeui a3, 3, a1 <esp_mesh_process_txupQ_pending+0x55> */
  L_009e: goto L_0275;  /* 009e: j */
  L_00a1: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a1: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a4 */
  if (a3 == 0) goto L_0275;  /* 00a6: beqz a3, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_00a9: a4 = LD32(a3 + 0x150);  /* 00a9 */
  if (a4 == 0) goto L_0275;  /* 00ac: beqz a4, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_00af: a10 = LD32(a3 + 0x158);  /* 00af */
  a3 = 186;  /* 00b2 */
  /* 00b5: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00b8: -> "mesh" */
  goto L_00ec;  /* 00bb: j */
  L_00be: a4 = LD32(a3 + 0x0);  /* 00be */
  if (a4 != 0) goto L_0104;  /* 00c0: bnez a4, 104 <esp_mesh_process_txupQ_pending+0xb8> */
  L_00c3: a2 = (u32)&g_log_level + 0x0;  /* 00c3: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c6 */
  a2 = 0x00004008u;  /* 00c8: l32r = 16392 */
  if (a3 >= 3u) goto L_00d1;  /* 00cb: bgeui a3, 3, d1 <esp_mesh_process_txupQ_pending+0x85> */
  L_00ce: goto L_0275;  /* 00ce: j */
  L_00d1: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00d1: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d4 */
  if (a3 == 0) goto L_0275;  /* 00d7: beqz a3, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_00da: a4 = LD32(a3 + 0x150);  /* 00da */
  if (a4 == 0) goto L_0275;  /* 00dd: beqz a4, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_00e0: a10 = LD32(a3 + 0x158);  /* 00e0 */
  a3 = 187;  /* 00e3 */
  /* 00e6: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00e9: -> "mesh" */
  L_00ec: a13 = a10;  /* 00ec */
  a14 = a11;  /* 00ee */
  a10 = 3;  /* 00f0 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00f2: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00f5: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 00f8 */
  L_00fa: __asm__ volatile("" ::: "memory");  /* 00fa: memw */
  /* 00fd: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0275;  /* 0100: j */
  L_0104: a5 = a4 + (18);  /* 0104 */
  a5 = LD32(a5 + 0x0);  /* 0107 */
  a11 = 1;  /* 0109 */
  a7 = (a5 >> 1) & 0x1ffffff;  /* 010b: extui width 25 */
  a6 = a7 ^ a11;  /* 010e */
  if (a7 != a11) goto L_011c;  /* 0111: bne a7, a11, 11c <esp_mesh_process_txupQ_pending+0xd0> */
  L_0114: a7 = a2 + (-8);  /* 0114 */
  if (a7 == 0) a6 = a11;  /* 0117 */
  if (a6 == 0) goto L_0121;  /* 011a: beqz.n a6, 121 <esp_mesh_process_txupQ_pending+0xd5> */
  L_011c: a2 = 0;  /* 011c */
  goto L_0275;  /* 011e: j */
  L_0121: a6 = 13;  /* 0121 */
  if (a6 < a2) goto L_0129;  /* 0123: bltu a6, a2, 129 <esp_mesh_process_txupQ_pending+0xdd> */
  L_0126: goto L_01f4;  /* 0126: j */
  L_0129: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0129: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 012c */
  if (a6 == 0) goto L_01c4;  /* 012e: beqz a6, 1c4 <esp_mesh_process_txupQ_pending+0x178> */
  L_0131: a5 = LD32(a6 + 0x150);  /* 0131 */
  if (a5 == 0) goto L_01c4;  /* 0134: beqz a5, 1c4 <esp_mesh_process_txupQ_pending+0x178> */
  L_0137: a10 = LD32(a6 + 0x158);  /* 0137 */
  /* 013a: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a6 = LD8U(a3 + 0xc);  /* 013d */
  a7 = LD8U(a4 + 0xe);  /* 0140 */
  ST32(a1 + 0x50, a6);  /* 0143 */
  a12 = LD8U(a3 + 0xd);  /* 0146 */
  a13 = LD8U(a3 + 0xe);  /* 0149 */
  a14 = LD8U(a3 + 0xf);  /* 014c */
  a15 = LD8U(a3 + 0x10);  /* 014f */
  a6 = LD8U(a3 + 0x11);  /* 0152 */
  a8 = (u32)(RODATA__rodata_esp_mesh_process_txupQ_pending_str1_1 + 0x0);  /* 0155: -> ", toDS" */
  if (((a7 >> 5) & 1) != 0) goto L_015e;  /* 0158: bbsi a7, 5, 15e <esp_mesh_process_txupQ_pending+0x112> */
  L_015b: a8 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 015b: -> "no window" */
  L_015e: a7 = LD32(a3 + 0x28);  /* 015e */
  a3 = (u32)(RODATA__rodata_esp_mesh_process_txupQ_pending_str1_1 + 0x0);  /* 0160: -> ", toDS" */
  if (((a7 >> 0) & 1) == 0) goto L_0169;  /* 0163: bbci a7, 0, 169 <esp_mesh_process_txupQ_pending+0x11d> */
  L_0166: a3 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0166: -> "no window" */
  L_0169: a9 = (u32)(RODATA__rodata_esp_mesh_process_txupQ_pending_str1_1 + 0x0);  /* 0169: -> ", toDS" */
  if (((a7 >> 2) & 1) != 0) goto L_0172;  /* 016c: bbsi a7, 2, 172 <esp_mesh_process_txupQ_pending+0x126> */
  L_016f: a9 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 016f: -> "no window" */
  L_0172: a7 = LD8U(a4 + 0x1b);  /* 0172 */
  ST32(a1 + 0x40, a7);  /* 0175 */
  a7 = LD8U(a4 + 0x1a);  /* 0178 */
  ST32(a1 + 0x3c, a7);  /* 017b */
  a7 = LD8U(a4 + 0x19);  /* 017d */
  ST32(a1 + 0x38, a7);  /* 0180 */
  a7 = LD8U(a4 + 0x18);  /* 0182 */
  ST32(a1 + 0x34, a7);  /* 0185 */
  a7 = LD8U(a4 + 0x17);  /* 0187 */
  ST32(a1 + 0x30, a7);  /* 018a */
  a4 = LD8U(a4 + 0x16);  /* 018c */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 018f: -> "mesh" */
  ST32(a1 + 0x24, a3);  /* 0192 */
  a3 = LD32(a1 + 0x50);  /* 0194 */
  ST32(a1 + 0x18, a15);  /* 0197 */
  ST32(a1 + 0xc, a12);  /* 0199 */
  ST32(a1 + 0x4, a2);  /* 019b */
  a2 = 195;  /* 019d */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 01a0: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_process_txupQ_pending_str1_1 + 0x0);  /* 01a3: -> ", toDS" */
  ST32(a1 + 0x14, a14);  /* 01a6 */
  a14 = a11;  /* 01a8 */
  ST32(a1 + 0x10, a13);  /* 01aa */
  a13 = a10;  /* 01ac */
  a10 = 2;  /* 01ae */
  ST32(a1 + 0x2c, a4);  /* 01b0 */
  ST32(a1 + 0x28, a9);  /* 01b2 */
  ST32(a1 + 0x20, a8);  /* 01b4 */
  ST32(a1 + 0x1c, a6);  /* 01b6 */
  ST32(a1 + 0x8, a3);  /* 01b9 */
  ST32(a1 + 0x0, a2);  /* 01bb */
  __asm__ volatile("" ::: "memory");  /* 01be: memw */
  /* 01c1: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_01c4: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01c4: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 01c7 */
  a2 = -1;  /* 01c9 */
  if (a3 == 0) goto L_0275;  /* 01cb: beqz a3, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_01ce: a4 = LD32(a3 + 0x150);  /* 01ce */
  if (a4 == 0) goto L_0275;  /* 01d1: beqz a4, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_01d4: a10 = LD32(a3 + 0x158);  /* 01d4 */
  a3 = 199;  /* 01d7 */
  /* 01da: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01dd */
  a10 = 1;  /* 01df */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 01e1: -> "mesh" */
  a14 = a11;  /* 01e4 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 01e6: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 01e9: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 01ec */
  __asm__ volatile("" ::: "memory");  /* 01ee: memw */
  goto L_00fa;  /* 01f1: j */
  L_01f4: if (a2 != 3) goto L_023d;  /* 01f4: bnei a2, 3, 23d <esp_mesh_process_txupQ_pending+0x1f1> */
  L_01f7: a6 = LD32(a3 + 0x28);  /* 01f7 */
  a2 = 4;  /* 01f9 */
  a2 = a2 & a6;  /* 01fb */
  if (a2 != 0) goto L_011c;  /* 01fe: bnez a2, 11c <esp_mesh_process_txupQ_pending+0xd0> */
  L_0201: a6 = 0x403;  /* 0201 */
  a6 = a6 << 14;  /* 0204 */
  a5 = a5 & a6;  /* 0207 */
  a6 = a11 << 24;  /* 020a */
  if (a5 == a6) goto L_0213;  /* 020d: beq a5, a6, 213 <esp_mesh_process_txupQ_pending+0x1c7> */
  L_0210: goto L_011c;  /* 0210: j */
  L_0213: a4 = a4 + (14);  /* 0213 */
  a12 = LD32(a4 + 0x18);  /* 0215 */
  if (a12 != 0) a2 = a11;  /* 0217 */
  if (a2 == 0) goto L_011c;  /* 021a: beqz a2, 11c <esp_mesh_process_txupQ_pending+0xd0> */
  L_021d: a2 = 0xf0000001u;  /* 021d: l32r = -268435455 */
  a2 = a12 + a2;  /* 0220 */
  if (a2 == 0) goto L_011c;  /* 0222: beqz a2, 11c <esp_mesh_process_txupQ_pending+0xd0> */
  L_0225: a14 = 224;  /* 0225 */
  a13 = (u32)(RODATA__rodata___func___22 + 0x0);  /* 0228: l32r -> .rodata.__func__$22 */
  a11 = 1;  /* 022b */
  L_022d: a10 = a3;  /* 022d */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 022f: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0232: callx a8 via reloc-expand */
  a2 = 0x00004014u;  /* 0235: l32r = 16404 */
  if (a10 != 0) goto L_0275;  /* 0238: bnez.n a10, 275 <esp_mesh_process_txupQ_pending+0x229> */
  L_023a: goto L_011c;  /* 023a: j */
  L_023d: if (a2 != 4) goto L_0250;  /* 023d: bnei a2, 4, 250 <esp_mesh_process_txupQ_pending+0x204> */
  L_0240: a5 = LD32(a3 + 0x28);  /* 0240 */
  if ((a2 & a5) == 0) goto L_0248;  /* 0242: bnone a2, a5, 248 <esp_mesh_process_txupQ_pending+0x1fc> */
  L_0245: goto L_011c;  /* 0245: j */
  L_0248: a4 = a4 + (14);  /* 0248 */
  a14 = 233;  /* 024a */
  goto L_0257;  /* 024d: j */
  L_0250: if (a2 != 0) goto L_0260;  /* 0250: bnez.n a2, 260 <esp_mesh_process_txupQ_pending+0x214> */
  L_0252: a4 = a4 + (14);  /* 0252 */
  a14 = 250;  /* 0254 */
  L_0257: a13 = (u32)(RODATA__rodata___func___22 + 0x0);  /* 0257: l32r -> .rodata.__func__$22 */
  a12 = LD32(a4 + 0x18);  /* 025a */
  goto L_022d;  /* 025c: j */
  L_0260: if (a2 == 2) goto L_0266;  /* 0260: beqi a2, 2, 266 <esp_mesh_process_txupQ_pending+0x21a> */
  L_0263: goto L_011c;  /* 0263: j */
  L_0266: a4 = a4 + (14);  /* 0266 */
  a13 = (u32)(RODATA__rodata___func___22 + 0x0);  /* 0268: l32r -> .rodata.__func__$22 */
  a14 = 255;  /* 026b */
  a11 = 3;  /* 026e */
  a12 = LD32(a4 + 0x18);  /* 0270 */
  goto L_022d;  /* 0272: j */
  L_0275: return a2;  /* 0275: retw.n */
}


/* esp_mesh_push_to_ack_state_queue @ mesh_schedule.o 00000020 size 144B bind GLOBAL
 * Calls: none | indirect[4]: mem[a8+0x158]; mem[a8+0x150]; mem[a3+0x6c] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .bss.mesh_ack_state_mbox, .rodata.mesh_get_tx_pending.str1.1
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=5); reloc-direct=0, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_push_to_ack_state_queue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_004d;  /* 0023: bnez.n a2, 4d <esp_mesh_push_to_ack_state_queue+0x2d> */
  L_0025: a2 = (u32)&g_log_level + 0x0;  /* 0025: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0028 */
  a2 = 0x00004008u;  /* 002a: l32r = 16392 */
  if (a3 < 3u) goto L_00ae;  /* 002d: bltui a3, 3, ae <esp_mesh_push_to_ack_state_queue+0x8e> */
  L_0030: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0030: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0033 */
  if (a8 == 0) goto L_00ae;  /* 0035: beqz a8, ae <esp_mesh_push_to_ack_state_queue+0x8e> */
  L_0038: a3 = LD32(a8 + 0x150);  /* 0038 */
  if (a3 == 0) goto L_00ae;  /* 003b: beqz a3, ae <esp_mesh_push_to_ack_state_queue+0x8e> */
  L_003e: a10 = LD32(a8 + 0x158);  /* 003e */
  /* 0041: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x2f9;  /* 0044 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0047: -> "mesh" */
  goto L_007a;  /* 004a: j */
  L_004d: a3 = (u32)&LOCAL__bss_mesh_ack_state_mbox + 0x0;  /* 004d: l32r -> .bss.mesh_ack_state_mbox (same-object static) */
  a10 = LD32(a3 + 0x0);  /* 0050 */
  if (a10 != 0) goto L_0095;  /* 0052: bnez.n a10, 95 <esp_mesh_push_to_ack_state_queue+0x75> */
  L_0054: a2 = (u32)&g_log_level + 0x0;  /* 0054: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0057 */
  a2 = 0x00004008u;  /* 005a: l32r = 16392 */
  if (a3 < 3u) goto L_00ae;  /* 005d: bltui a3, 3, ae <esp_mesh_push_to_ack_state_queue+0x8e> */
  L_0060: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0060: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0063 */
  if (a8 == 0) goto L_00ae;  /* 0066: beqz a8, ae <esp_mesh_push_to_ack_state_queue+0x8e> */
  L_0069: a3 = LD32(a8 + 0x150);  /* 0069 */
  if (a3 == 0) goto L_00ae;  /* 006c: beqz.n a3, ae <esp_mesh_push_to_ack_state_queue+0x8e> */
  L_006e: a10 = LD32(a8 + 0x158);  /* 006e */
  /* 0071: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x2fa;  /* 0074 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0077: -> "mesh" */
  L_007a: a13 = a10;  /* 007a */
  a14 = a11;  /* 007c */
  a10 = 3;  /* 007e */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0081: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0084: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a8);  /* 0087 */
  __asm__ volatile("" ::: "memory");  /* 008a: memw */
  /* 008d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00ae;  /* 0090: j */
  L_0095: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0095: l32r -> global */
  a11 = a2;  /* 0098 */
  a12 = 0;  /* 009a */
  a3 = LD32(a3 + 0x0);  /* 009c */
  a3 = LD32(a3 + 0x6c);  /* 009e */
  /* 00a1: INDIRECT callx a3 <- mem[a3+0x6c]; result unknown */ a2 = 0;
  a10 = a10 + (-1);  /* 00a4 */
  a3 = 0;  /* 00a6 */
  a2 = 0x0000400cu;  /* 00a8: l32r = 16396 */
  if (a10 == 0) a2 = a3;  /* 00ab */
  L_00ae: return a2;  /* 00ae: retw.n */
}


/* esp_mesh_push_to_ps_tx_queue @ mesh_schedule.o 0000000c size 109B bind GLOBAL
 * Calls: none | indirect[2]: mem[a8+0x6c] | Data refs: .bss.mesh_tx_mbox, .bss.mesh_tx_task, g_osi_funcs_p
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_push_to_ps_tx_queue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a11 = a2 + (-12);  /* 000f */
  a8 = 1;  /* 0012 */
  a10 = 0;  /* 0014 */
  if (a11 == 0) a10 = a8;  /* 0016 */
  ST32(a1 + 0x0, a2);  /* 0019 */
  a11 = (a10 >> 8) & 0x1;  /* 001b: extui width 1 */
  if (a10 != 0) goto L_0028;  /* 001e: bnez.n a10, 28 <esp_mesh_push_to_ps_tx_queue+0x1c> */
  L_0020: a9 = a2 + (-15);  /* 0020 */
  if (a9 != 0) a8 = a11;  /* 0023 */
  if (a8 == 0) goto L_004a;  /* 0026: beqz.n a8, 4a <esp_mesh_push_to_ps_tx_queue+0x3e> */
  L_0028: a8 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0028: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a10 = LD32(a8 + 0x90);  /* 002b */
  if (a10 == 0) goto L_004a;  /* 002e: beqz.n a10, 4a <esp_mesh_push_to_ps_tx_queue+0x3e> */
  L_0030: a8 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0030: l32r -> .bss.mesh_tx_task (same-object static) */
  a8 = LD8U(a8 + 0x14);  /* 0033 */
  if (a8 == 0) goto L_004a;  /* 0036: beqz.n a8, 4a <esp_mesh_push_to_ps_tx_queue+0x3e> */
  L_0038: a12 = -1;  /* 0038 */
  a11 = a1;  /* 003a */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 003c: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 003f */
  a8 = LD32(a8 + 0x6c);  /* 0041 */
  __asm__ volatile("" ::: "memory");  /* 0044: memw */
  /* 0047: INDIRECT callx a8 <- mem[a8+0x6c]; result unknown */ a2 = 0;
  L_004a: a8 = -3;  /* 004a */
  a9 = LD32(a1 + 0x0);  /* 004c */
  a8 = a8 & a9;  /* 004e */
  a9 = 13;  /* 0051 */
  if (a8 != a9) goto L_0075;  /* 0053: bne a8, a9, 75 <esp_mesh_push_to_ps_tx_queue+0x69> */
  L_0056: a8 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0056: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a10 = LD32(a8 + 0x9c);  /* 0059 */
  if (a10 == 0) goto L_0075;  /* 005c: beqz.n a10, 75 <esp_mesh_push_to_ps_tx_queue+0x69> */
  L_005e: a8 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 005e: l32r -> .bss.mesh_tx_task (same-object static) */
  a8 = LD8U(a8 + 0x2c);  /* 0061 */
  if (a8 == 0) goto L_0075;  /* 0064: beqz.n a8, 75 <esp_mesh_push_to_ps_tx_queue+0x69> */
  L_0066: a12 = -1;  /* 0066 */
  a11 = a1;  /* 0068 */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 006a: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 006d */
  a8 = LD32(a8 + 0x6c);  /* 006f */
  /* 0072: INDIRECT callx a8 <- mem[a8+0x6c]; result unknown */ a2 = 0;
  L_0075: a2 = 0;  /* 0075 */
  return a2;  /* 0077: retw.n */
}


/* esp_mesh_push_to_tx_queue @ mesh_schedule.o 0000007c size 1216B bind GLOBAL
 * Calls: memcmp, esp_mesh_send_block_start, tx_msg_id2str, esp_mesh_process_txupQ_pending, mesh_check_tid_mbox_full, esp_mesh_txupQ_pending | indirect[16]: mem[a2+0x158]; mem[a2+0x150]; unknown; mem[a10+0x78] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1, .bss.is_mesh_tx_started, .rodata.mesh_get_tx_pending.str1.1, g_mesh_topology, .data.MESH_BCAST_ADDR, .rodata.esp_mesh_push_to_tx_queue.str1.1, .rodata.esp_mesh_send_block_event.str1.1, .bss.mesh_tx_mbox +4 more
 * Fidelity: medium - 16 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=22); reloc-direct=6, funcdb-attributed=0, unknown-indirect=16 */
u32 esp_mesh_push_to_tx_queue(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a6, a7, a8, a9;
  float F3;
  /* 007c: entry a1, 176 (frame 176 bytes) */
  a7 = a2;  /* 007f */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 0081: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0084 */
  if (a2 != 0) goto L_00c0;  /* 0087: bnez.n a2, c0 <esp_mesh_push_to_tx_queue+0x44> */
  L_0089: a2 = (u32)&g_log_level + 0x0;  /* 0089: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 008c */
  a6 = 0x00004004u;  /* 008f: l32r = 16388 */
  if (a2 >= 3u) goto L_0098;  /* 0092: bgeui a2, 3, 98 <esp_mesh_push_to_tx_queue+0x1c> */
  L_0095: goto L_0538;  /* 0095: j */
  L_0098: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0098: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 009b */
  if (a2 == 0) goto L_0538;  /* 009e: beqz a2, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_00a1: a3 = LD32(a2 + 0x150);  /* 00a1 */
  if (a3 == 0) goto L_0538;  /* 00a4: beqz a3, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_00a7: a10 = LD32(a2 + 0x158);  /* 00a7 */
  /* 00aa: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ad */
  a10 = 3;  /* 00af */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00b1: -> "mesh" */
  a14 = a11;  /* 00b4 */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00b6: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 00b9: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0538;  /* 00bc: j */
  L_00c0: a2 = (u32)&LOCAL__bss_is_mesh_tx_started + 0x0;  /* 00c0: l32r -> .bss.is_mesh_tx_started (same-object static) */
  a2 = LD8U(a2 + 0x0);  /* 00c3 */
  a6 = 0x00004004u;  /* 00c6: l32r = 16388 */
  if (a2 == 0) goto L_0538;  /* 00c9: beqz a2, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_00cc: if (a7 != 0) goto L_010e;  /* 00cc: bnez.n a7, 10e <esp_mesh_push_to_tx_queue+0x92> */
  L_00ce: a2 = (u32)&g_log_level + 0x0;  /* 00ce: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00d1 */
  if (a2 >= 3u) goto L_00d9;  /* 00d3: bgeui a2, 3, d9 <esp_mesh_push_to_tx_queue+0x5d> */
  L_00d6: goto L_0108;  /* 00d6: j */
  L_00d9: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00d9: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00dc */
  if (a2 == 0) goto L_0108;  /* 00de: beqz a2, 108 <esp_mesh_push_to_tx_queue+0x8c> */
  L_00e1: a3 = LD32(a2 + 0x150);  /* 00e1 */
  if (a3 == 0) goto L_0108;  /* 00e4: beqz a3, 108 <esp_mesh_push_to_tx_queue+0x8c> */
  L_00e7: a10 = LD32(a2 + 0x158);  /* 00e7 */
  a2 = 0x277;  /* 00ea */
  /* 00ed: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00f0: -> "mesh" */
  L_00f3: a13 = a10;  /* 00f3 */
  a14 = a11;  /* 00f5 */
  a10 = 3;  /* 00f7 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00f9: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00fc: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a2);  /* 00ff */
  L_0102: __asm__ volatile("" ::: "memory");  /* 0102: memw */
  /* 0105: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0108: a6 = 0x00004008u;  /* 0108: l32r = 16392 */
  goto L_0538;  /* 010b: j */
  L_010e: a13 = LD32(a7 + 0x0);  /* 010e */
  a8 = LD32(a13 + 0x0);  /* 0110 */
  if (a8 != 0) goto L_013c;  /* 0112: bnez.n a8, 13c <esp_mesh_push_to_tx_queue+0xc0> */
  L_0114: a2 = (u32)&g_log_level + 0x0;  /* 0114: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0117 */
  if (a2 < 3u) goto L_0108;  /* 0119: bltui a2, 3, 108 <esp_mesh_push_to_tx_queue+0x8c> */
  L_011c: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 011c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 011f */
  if (a2 == 0) goto L_0108;  /* 0122: beqz a2, 108 <esp_mesh_push_to_tx_queue+0x8c> */
  L_0125: a3 = LD32(a2 + 0x150);  /* 0125 */
  if (a3 == 0) goto L_0108;  /* 0128: beqz a3, 108 <esp_mesh_push_to_tx_queue+0x8c> */
  L_012b: a10 = LD32(a2 + 0x158);  /* 012b */
  a2 = 0x279;  /* 012e */
  /* 0131: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0134: -> "mesh" */
  goto L_00f3;  /* 0137: j */
  L_013c: a2 = (u32)&g_mesh_topology + 0x0;  /* 013c: l32r -> global */
  a4 = 33;  /* 013f */
  a14 = 28;  /* 0141 */
  a5 = LD32(a2 + 0x0);  /* 0143 */
  if (a5 != 0) a14 = a4;  /* 0145 */
  a4 = a14 + (14);  /* 0148 */
  a4 = a8 + a4;  /* 014a */
  ST32(a1 + 0x64, a4);  /* 014c */
  a4 = a8 + (18);  /* 014f */
  a5 = 1;  /* 0152 */
  a5 = a5 << 23;  /* 0154 */
  a6 = LD32(a4 + 0x0);  /* 0157 */
  a5 = a6 & a5;  /* 0159 */
  ST32(a1 + 0x60, a4);  /* 015c */
  a4 = 5;  /* 015f */
  if (a5 != 0) goto L_018f;  /* 0161: bnez.n a5, 18f <esp_mesh_push_to_tx_queue+0x113> */
  L_0163: a10 = LD8U(a13 + 0x12);  /* 0163 */
  if (((a6 >> 8) & 1) == 0) goto L_0178;  /* 0166: bbci a6, 8, 178 <esp_mesh_push_to_tx_queue+0xfc> */
  L_0169: a10 = a10 + (-1);  /* 0169 */
  a4 = 6;  /* 016b */
  a11 = 7;  /* 016d */
  if (a10 == 0) a4 = a11;  /* 016f */
  __asm__ volatile("" ::: "memory");  /* 0172: memw */
  goto L_018f;  /* 0175: j */
  L_0178: a4 = 3;  /* 0178 */
  a4 = a4 << 14;  /* 017a */
  a11 = 1;  /* 017d */
  if ((a6 & a4) != 0) goto L_018a;  /* 017f: bany a6, a4, 18a <esp_mesh_push_to_tx_queue+0x10e> */
  L_0182: if (a10 == 0) a11 = a5;  /* 0182 */
  a4 = a11 + a11;  /* 0185 */
  goto L_018f;  /* 0187: j */
  L_018a: a4 = 17;  /* 018a */
  if (a10 != 0) a4 = a11;  /* 018c */
  L_018f: ST32(a1 + 0x50, a4);  /* 018f */
  if (((a6 >> 27) & 1) != 0) goto L_01c8;  /* 0192: bbsi a6, 27, 1c8 <esp_mesh_push_to_tx_queue+0x14c> */
  L_0195: a10 = a8 + (22);  /* 0195 */
  a12 = 6;  /* 0198 */
  a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 019b: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  ST32(a1 + 0x88, a8);  /* 019e */
  ST32(a1 + 0x80, a13);  /* 01a1 */
  ST32(a1 + 0x84, a14);  /* 01a4 */
  __asm__ volatile("" ::: "memory");  /* 01a7: memw */
  a8 = (u32)&memcmp + 0x0;  /* 01aa: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 01ad: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x88);  /* 01b0 */
  a13 = LD32(a1 + 0x80);  /* 01b3 */
  a14 = LD32(a1 + 0x84);  /* 01b6 */
  if (a10 == 0) goto L_01c8;  /* 01b9: beqz a10, 1c8 <esp_mesh_push_to_tx_queue+0x14c> */
  L_01bc: a4 = LD8U(a8 + 0x16);  /* 01bc */
  if (((a4 >> 0) & 1) == 0) goto L_01ee;  /* 01bf: bbci a4, 0, 1ee <esp_mesh_push_to_tx_queue+0x172> */
  L_01c2: a4 = LD8U(a8 + 0xe);  /* 01c2 */
  if (((a4 >> 5) & 1) != 0) goto L_01ee;  /* 01c5: bbsi a4, 5, 1ee <esp_mesh_push_to_tx_queue+0x172> */
  L_01c8: if (((a6 >> 24) & 1) == 0) goto L_01d4;  /* 01c8: bbci a6, 24, 1d4 <esp_mesh_push_to_tx_queue+0x158> */
  L_01cb: a4 = LD8U(a8 + 0xf);  /* 01cb */
  a4 = a4 - a14;  /* 01ce: subx4 */
  if (a4 >= 4u) goto L_01e0;  /* 01d1: bgeui a4, 4, 1e0 <esp_mesh_push_to_tx_queue+0x164> */
  L_01d4: if (a5 == 0) goto L_01e9;  /* 01d4: beqz a5, 1e9 <esp_mesh_push_to_tx_queue+0x16d> */
  L_01d7: a4 = LD8U(a8 + 0xf);  /* 01d7 */
  a4 = a4 - a14;  /* 01da: subx4 */
  if (a4 < 3u) goto L_01e9;  /* 01dd: bltui a4, 3, 1e9 <esp_mesh_push_to_tx_queue+0x16d> */
  L_01e0: a5 = LD32(a1 + 0x64);  /* 01e0 */
  a4 = LD8U(a5 + 0x0);  /* 01e3 */
  if (a4 == 2) goto L_01ee;  /* 01e6: beqi a4, 2, 1ee <esp_mesh_push_to_tx_queue+0x172> */
  L_01e9: a4 = 8;  /* 01e9 */
  ST32(a1 + 0x50, a4);  /* 01eb */
  L_01ee: a10 = 1;  /* 01ee */
  a11 = 0;  /* 01f0 */
  a5 = LD32(a1 + 0x50);  /* 01f2 */
  a4 = a5 + (-17);  /* 01f5 */
  if (a4 == 0) a11 = a10;  /* 01f8 */
  a4 = (a11 >> 8) & 0x1;  /* 01fb: extui width 1 */
  if (a11 != 0) goto L_0206;  /* 01fe: bnez.n a11, 206 <esp_mesh_push_to_tx_queue+0x18a> */
  L_0200: if (a5 != 0) a10 = a4;  /* 0200 */
  if (a10 == 0) goto L_02b8;  /* 0203: beqz a10, 2b8 <esp_mesh_push_to_tx_queue+0x23c> */
  L_0206: a10 = 3;  /* 0206 */
  a10 = a10 << 14;  /* 0208 */
  a4 = 1;  /* 020b */
  if ((a6 & a10) != 0) goto L_0213;  /* 020d: bany a6, a10, 213 <esp_mesh_push_to_tx_queue+0x197> */
  L_0210: goto L_02b8;  /* 0210: j */
  L_0213: if (((a6 >> 24) & 1) != 0) goto L_0219;  /* 0213: bbsi a6, 24, 219 <esp_mesh_push_to_tx_queue+0x19d> */
  L_0216: goto L_02b8;  /* 0216: j */
  L_0219: a2 = LD32(a13 + 0x28);  /* 0219 */
  if (((a2 >> 0) & 1) == 0) goto L_0221;  /* 021b: bbci a2, 0, 221 <esp_mesh_push_to_tx_queue+0x1a5> */
  L_021e: goto L_0108;  /* 021e: j */
  L_0221: a3 = (u32)&g_log_level + 0x0;  /* 0221: l32r -> global */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0224: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0227 */
  a2 = LD32(a4 + 0x0);  /* 0229 */
  if (a3 >= 3u) goto L_0239;  /* 022b: bgeui a3, 3, 239 <esp_mesh_push_to_tx_queue+0x1bd> */
  L_022e: a2 = LD32(a4 + 0x0);  /* 022e */
  if (a2 != 0) goto L_0291;  /* 0230: bnez a2, 291 <esp_mesh_push_to_tx_queue+0x215> */
  L_0233: __asm__ volatile("" ::: "memory");  /* 0233: memw */
  goto L_0108;  /* 0236: j */
  L_0239: if (a2 == 0) goto L_022e;  /* 0239: beqz a2, 22e <esp_mesh_push_to_tx_queue+0x1b2> */
  L_023c: a3 = LD32(a2 + 0x150);  /* 023c */
  if (a3 == 0) goto L_022e;  /* 023f: beqz a3, 22e <esp_mesh_push_to_tx_queue+0x1b2> */
  L_0242: a10 = LD32(a2 + 0x158);  /* 0242 */
  ST32(a1 + 0x88, a8);  /* 0245 */
  __asm__ volatile("" ::: "memory");  /* 0248: memw */
  /* 024b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 024e */
  a15 = 0x2a9;  /* 0250 */
  a10 = 3;  /* 0253 */
  a8 = LD32(a1 + 0x88);  /* 0255 */
  a2 = LD8U(a8 + 0x21);  /* 0258 */
  ST32(a1 + 0x14, a2);  /* 025b */
  a2 = LD8U(a8 + 0x20);  /* 025d */
  ST32(a1 + 0x10, a2);  /* 0260 */
  a2 = LD8U(a8 + 0x1f);  /* 0262 */
  ST32(a1 + 0xc, a2);  /* 0265 */
  a2 = LD8U(a8 + 0x1e);  /* 0267 */
  ST32(a1 + 0x8, a2);  /* 026a */
  a2 = LD8U(a8 + 0x1d);  /* 026c */
  ST32(a1 + 0x4, a2);  /* 026f */
  a2 = LD8U(a8 + 0x1c);  /* 0271 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0274: -> "mesh" */
  a14 = a11;  /* 0277 */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_tx_queue_str1_1 + 0x0);  /* 0279: l32r -> .rodata.esp_mesh_push_to_tx_queue.str1.1 */
  ST32(a1 + 0x0, a2);  /* 027c */
  __asm__ volatile("" ::: "memory");  /* 027e: memw */
  /* 0281: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  a2 = LD32(a7 + 0x0);  /* 0284 */
  a2 = LD32(a2 + 0x28);  /* 0286 */
  if (((a2 >> 0) & 1) == 0) goto L_022e;  /* 0288: bbci a2, 0, 22e <esp_mesh_push_to_tx_queue+0x1b2> */
  L_028b: goto L_0108;  /* 028b: j */
  L_0291: a3 = LD32(a2 + 0x150);  /* 0291 */
  if (a3 == 0) goto L_0108;  /* 0294: beqz a3, 108 <esp_mesh_push_to_tx_queue+0x8c> */
  L_0297: a10 = LD32(a2 + 0x158);  /* 0297 */
  a2 = 0x2ac;  /* 029a */
  /* 029d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02a0 */
  a10 = 1;  /* 02a2 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 02a4: -> "mesh" */
  a14 = a11;  /* 02a7 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 02a9: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 02ac: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 02af */
  __asm__ volatile("" ::: "memory");  /* 02b1: memw */
  goto L_0102;  /* 02b4: j */
  L_02b8: a6 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 02b8: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a5 = a5 + (a5 << 1);  /* 02bb */
  a5 = a5 + (a6 << 2);  /* 02be */
  a5 = LD32(a5 + 0x0);  /* 02c1 */
  if (a5 == 0) goto L_0350;  /* 02c3: beqz a5, 350 <esp_mesh_push_to_tx_queue+0x2d4> */
  L_02c6: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 02c6: l32r -> global */
  a10 = LD32(a6 + 0x0);  /* 02c9 */
  a11 = LD32(a10 + 0x78);  /* 02cb */
  a10 = a5;  /* 02ce */
  ST32(a1 + 0x88, a8);  /* 02d0 */
  __asm__ volatile("" ::: "memory");  /* 02d3: memw */
  /* 02d6: INDIRECT callx a11 <- mem[a10+0x78]; result unknown */ a2 = 0;
  a11 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 02d9: l32r -> global */
  a11 = LD32(a11 + 0x0);  /* 02dc */
  a8 = LD32(a1 + 0x88);  /* 02de */
  if (a10 < a11) goto L_0350;  /* 02e1: bltu a10, a11, 350 <esp_mesh_push_to_tx_queue+0x2d4> */
  L_02e4: a12 = LD32(a7 + 0x0);  /* 02e4 */
  a10 = LD32(a1 + 0x50);  /* 02e6 */
  if (a12 == 0) goto L_0350;  /* 02e9: beqz a12, 350 <esp_mesh_push_to_tx_queue+0x2d4> */
  L_02ec: a11 = LD32(a12 + 0x28);  /* 02ec */
  a11 = (a11 >> 2) & 0x1;  /* 02ee: extui width 1 */
  if (a11 != 1) goto L_0350;  /* 02f1: bnei a11, 1, 350 <esp_mesh_push_to_tx_queue+0x2d4> */
  L_02f4: a11 = a4;  /* 02f4 */
  a6 = 0x0000400du;  /* 02f6: l32r = 16397 */
  a10 = (a10 >> 8) & 0x1;  /* 02f9: extui width 1 */
  a13 = a6;  /* 02fc: mov */
  a8 = (u32)&esp_mesh_send_block_start;  /* 02ff: l32r -> func addr */
  a2 = esp_mesh_send_block_start(a2, a3, a4, a5, a6);  /* 0302: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0538;  /* 0305: beqz a10, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_0308: a2 = (u32)&g_log_level + 0x0;  /* 0308: l32r -> global */
  a6 = -1;  /* 030b */
  a2 = LD32(a2 + 0x0);  /* 030d */
  if (a2 >= 3u) goto L_0315;  /* 030f: bgeui a2, 3, 315 <esp_mesh_push_to_tx_queue+0x299> */
  L_0312: goto L_0538;  /* 0312: j */
  L_0315: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0315: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 0318 */
  if (a2 == 0) goto L_0538;  /* 031b: beqz a2, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_031e: a3 = LD32(a2 + 0x150);  /* 031e */
  if (a3 == 0) goto L_0538;  /* 0321: beqz a3, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_0324: a10 = LD32(a2 + 0x158);  /* 0324 */
  /* 0327: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 032a */
  a10 = LD8U(a1 + 0x50);  /* 032c */
  a8 = (u32)&tx_msg_id2str + 0x0;  /* 032f: l32r -> global */
  a2 = tx_msg_id2str(a2, a3, a4, a5);  /* 0332: callx a8 via reloc-expand */
  a15 = 0x2c3;  /* 0335 */
  a13 = a2;  /* 0338 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 033a: -> "mesh" */
  a14 = a11;  /* 033d */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_tx_queue_str1_1 + 0x0);  /* 033f: l32r -> .rodata.esp_mesh_push_to_tx_queue.str1.1 */
  ST32(a1 + 0x0, a10);  /* 0342 */
  a10 = 3;  /* 0344 */
  __asm__ volatile("" ::: "memory");  /* 0346: memw */
  /* 0349: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0538;  /* 034c: j */
  L_0350: a11 = LD32(a7 + 0x0);  /* 0350 */
  a10 = LD8U(a1 + 0x50);  /* 0352 */
  ST32(a1 + 0x88, a8);  /* 0355 */
  __asm__ volatile("" ::: "memory");  /* 0358: memw */
  a8 = (u32)&esp_mesh_process_txupQ_pending;  /* 035b: l32r -> func addr */
  a2 = esp_mesh_process_txupQ_pending(a2, a3, a4, a5);  /* 035e: callx a8 via reloc-expand */
  a6 = a10;  /* 0361 */
  a8 = LD32(a1 + 0x88);  /* 0363 */
  if (a10 == 0) goto L_0449;  /* 0366: beqz a10, 449 <esp_mesh_push_to_tx_queue+0x3cd> */
  L_0369: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0369: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 036c */
  if (a3 == 0) goto L_0538;  /* 036e: beqz a3, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_0371: a2 = LD32(a3 + 0x150);  /* 0371 */
  if (a2 == 0) goto L_0538;  /* 0374: beqz a2, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_0377: a10 = LD32(a3 + 0x158);  /* 0377 */
  /* 037a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 037d */
  a8 = LD32(a1 + 0x88);  /* 037f */
  a3 = a8 + (14);  /* 0382 */
  a3 = LD32(a3 + 0x18);  /* 0384 */
  ST32(a1 + 0x60, a3);  /* 0386 */
  a3 = LD32(a7 + 0x0);  /* 0389 */
  a5 = LD32(a3 + 0x28);  /* 038c */
  a3 = (u32)(RODATA__rodata_mesh_check_tid_mbox_full_str1_1 + 0x0);  /* 038f: -> "xmit" */
  if (((a5 >> 0) & 1) != 0) goto L_0398;  /* 0392: bbsi a5, 0, 398 <esp_mesh_push_to_tx_queue+0x31c> */
  L_0395: a3 = (u32)(RODATA__rodata_mesh_check_tid_mbox_full_str1_1 + 0x0);  /* 0395: -> "xmit" */
  L_0398: a9 = LD8U(a8 + 0x1c);  /* 0398 */
  ST32(a1 + 0x64, a9);  /* 039b */
  a9 = LD8U(a8 + 0x1e);  /* 039e */
  a5 = LD8U(a8 + 0x1d);  /* 03a1 */
  ST32(a1 + 0x6c, a9);  /* 03a4 */
  a9 = LD8U(a8 + 0x21);  /* 03a7 */
  a7 = LD8U(a8 + 0x16);  /* 03aa */
  a15 = LD8U(a8 + 0x1f);  /* 03ad */
  a12 = LD8U(a8 + 0x18);  /* 03b0 */
  a13 = LD8U(a8 + 0x19);  /* 03b3 */
  a14 = LD8U(a8 + 0x1a);  /* 03b6 */
  ST32(a1 + 0x68, a5);  /* 03b9 */
  ST32(a1 + 0x70, a9);  /* 03bc */
  a5 = LD8U(a8 + 0x20);  /* 03bf */
  a9 = LD8U(a8 + 0x17);  /* 03c2 */
  a10 = LD8U(a1 + 0x50);  /* 03c5 */
  a8 = LD8U(a8 + 0x1b);  /* 03c8 */
  ST32(a1 + 0x78, a9);  /* 03cb */
  ST32(a1 + 0x88, a8);  /* 03ce */
  ST32(a1 + 0x7c, a12);  /* 03d1 */
  ST32(a1 + 0x80, a13);  /* 03d4 */
  ST32(a1 + 0x84, a14);  /* 03d7 */
  ST32(a1 + 0x74, a15);  /* 03da */
  __asm__ volatile("" ::: "memory");  /* 03dd: memw */
  a8 = (u32)&tx_msg_id2str + 0x0;  /* 03e0: l32r -> global */
  a2 = tx_msg_id2str(a2, a3, a4, a5);  /* 03e3: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x88);  /* 03e6 */
  a9 = LD32(a1 + 0x78);  /* 03e9 */
  ST32(a1 + 0x3c, a8);  /* 03ec */
  ST32(a1 + 0x2c, a9);  /* 03ee */
  a8 = LD32(a1 + 0x70);  /* 03f0 */
  a9 = LD32(a1 + 0x6c);  /* 03f3 */
  a12 = LD32(a1 + 0x7c);  /* 03f6 */
  a15 = LD32(a1 + 0x74);  /* 03f9 */
  a14 = LD32(a1 + 0x84);  /* 03fc */
  a13 = LD32(a1 + 0x80);  /* 03ff */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0402: -> "mesh" */
  ST32(a1 + 0x24, a8);  /* 0405 */
  ST32(a1 + 0x20, a5);  /* 0407 */
  a8 = LD32(a1 + 0x64);  /* 0409 */
  a5 = LD32(a1 + 0x68);  /* 040c */
  ST32(a1 + 0x18, a9);  /* 040f */
  a9 = LD32(a1 + 0x60);  /* 0411 */
  ST32(a1 + 0x30, a12);  /* 0414 */
  ST32(a1 + 0x1c, a15);  /* 0416 */
  ST32(a1 + 0xc, a3);  /* 0418 */
  a3 = 0x2cc;  /* 041a */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 041d: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_tx_queue_str1_1 + 0x0);  /* 0420: l32r -> .rodata.esp_mesh_push_to_tx_queue.str1.1 */
  ST32(a1 + 0x40, a10);  /* 0423 */
  a10 = 2;  /* 0426 */
  ST32(a1 + 0x38, a14);  /* 0428 */
  a14 = a11;  /* 042a */
  ST32(a1 + 0x34, a13);  /* 042c */
  a13 = a4;  /* 042e */
  ST32(a1 + 0x28, a7);  /* 0430 */
  ST32(a1 + 0x14, a5);  /* 0432 */
  ST32(a1 + 0x10, a8);  /* 0434 */
  ST32(a1 + 0x8, a9);  /* 0436 */
  ST32(a1 + 0x4, a6);  /* 0438 */
  ST32(a1 + 0x0, a3);  /* 043b */
  __asm__ volatile("" ::: "memory");  /* 043e: memw */
  /* 0441: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  goto L_0538;  /* 0444: j */
  L_0449: a12 = LD32(a7 + 0x0);  /* 0449 */
  a11 = a4;  /* 044b */
  a10 = LD32(a1 + 0x50);  /* 044d */
  ST32(a1 + 0x88, a8);  /* 0450 */
  __asm__ volatile("" ::: "memory");  /* 0453: memw */
  a8 = (u32)&mesh_check_tid_mbox_full;  /* 0456: l32r -> func addr */
  a2 = mesh_check_tid_mbox_full(a2, a3, a4, a5);  /* 0459: callx a8 via reloc-expand */
  a6 = a10;  /* 045c */
  a8 = LD32(a1 + 0x88);  /* 045e */
  if (a10 != 0) goto L_0504;  /* 0461: bnez a10, 504 <esp_mesh_push_to_tx_queue+0x488> */
  L_0464: a9 = LD32(a7 + 0x0);  /* 0464 */
  a10 = LD32(a9 + 0x28);  /* 0466 */
  if (((a10 >> 0) & 1) == 0) goto L_04a6;  /* 0468: bbci a10, 0, 4a6 <esp_mesh_push_to_tx_queue+0x42a> */
  L_046b: a10 = LD32(a1 + 0x60);  /* 046b */
  a9 = LD32(a10 + 0x0);  /* 046e */
  if (((a9 >> 8) & 1) != 0) goto L_04a6;  /* 0470: bbsi a9, 8, 4a6 <esp_mesh_push_to_tx_queue+0x42a> */
  L_0473: if (((a9 >> 24) & 1) == 0) goto L_0488;  /* 0473: bbci a9, 24, 488 <esp_mesh_push_to_tx_queue+0x40c> */
  L_0476: a11 = 28;  /* 0476 */
  a13 = LD32(a2 + 0x0);  /* 0478 */
  a12 = 33;  /* 047a */
  if (a13 != 0) a11 = a12;  /* 047c */
  a10 = LD8U(a8 + 0xf);  /* 047f */
  a10 = a10 - a11;  /* 0482: subx4 */
  if (a10 >= 4u) goto L_049d;  /* 0485: bgeui a10, 4, 49d <esp_mesh_push_to_tx_queue+0x421> */
  L_0488: if (((a9 >> 23) & 1) == 0) goto L_04b1;  /* 0488: bbci a9, 23, 4b1 <esp_mesh_push_to_tx_queue+0x435> */
  L_048b: a10 = LD32(a2 + 0x0);  /* 048b */
  a2 = 28;  /* 048d */
  a9 = LD8U(a8 + 0xf);  /* 048f */
  a8 = 33;  /* 0492 */
  if (a10 != 0) a2 = a8;  /* 0494 */
  a2 = a9 - a2;  /* 0497: subx4 */
  if (a2 < 3u) goto L_04b1;  /* 049a: bltui a2, 3, 4b1 <esp_mesh_push_to_tx_queue+0x435> */
  L_049d: a8 = LD32(a1 + 0x64);  /* 049d */
  a2 = LD8U(a8 + 0x0);  /* 04a0 */
  if (a2 != 5) goto L_04b1;  /* 04a3: bnei a2, 5, 4b1 <esp_mesh_push_to_tx_queue+0x435> */
  L_04a6: a9 = (u32)&g_osi_funcs_p + 0x0;  /* 04a6: l32r -> global */
  a2 = LD32(a9 + 0x0);  /* 04a9 */
  a2 = LD32(a2 + 0x6c);  /* 04ab */
  goto L_04b9;  /* 04ae: j */
  L_04b1: a10 = (u32)&g_osi_funcs_p + 0x0;  /* 04b1: l32r -> global */
  a2 = LD32(a10 + 0x0);  /* 04b4 */
  a2 = LD32(a2 + 0x70);  /* 04b6 */
  L_04b9: a12 = a3;  /* 04b9: mov */
  a11 = a7;  /* 04bc: mov */
  a10 = a5;  /* 04bf: mov */
  /* 04c2: INDIRECT callx a2 <- mem[a2+0x70]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_0535;  /* 04c5: bnei a10, 1, 535 <esp_mesh_push_to_tx_queue+0x4b9> */
  L_04c8: a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 04c8: l32r -> .bss.mesh_tx_task (same-object static) */
  a4 = a4 + (a4 << 1);  /* 04cb */
  a4 = a4 + (a2 << 3);  /* 04ce */
  a3 = LD32(a4 + 0x0);  /* 04d1 */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 04d3: l32r -> global */
  a2 = LD32(a4 + 0x0);  /* 04d6 */
  a4 = LD32(a1 + 0x50);  /* 04d8 */
  if (a4 < 4u) goto L_04f4;  /* 04db: bltui a4, 4, 4f4 <esp_mesh_push_to_tx_queue+0x478> */
  L_04de: a12 = 0;  /* 04de */
  a11 = a1 + (80);  /* 04e0 */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 04e3: l32r -> global */
  a10 = a3;  /* 04e6 */
  a2 = LD32(a5 + 0x0);  /* 04e8 */
  a2 = LD32(a2 + 0x6c);  /* 04ea */
  /* 04ed: INDIRECT callx a2 <- mem[a2+0x6c]; result unknown */ a2 = 0;
  goto L_0538;  /* 04f0: j */
  L_04f4: a2 = LD32(a2 + 0x78);  /* 04f4 */
  a10 = a5;  /* 04f7 */
  /* 04f9: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a2 = 31;  /* 04fc */
  if (a2 >= a10) goto L_04de;  /* 04fe: bgeu a2, a10, 4de <esp_mesh_push_to_tx_queue+0x462> */
  L_0501: goto L_0538;  /* 0501: j */
  L_0504: a9 = LD32(a1 + 0x60);  /* 0504 */
  a2 = LD8U(a9 + 0x3);  /* 0507 */
  if (((a2 >> 0) & 1) == 0) goto L_0538;  /* 050a: bbci a2, 0, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_050d: a11 = LD32(a1 + 0x50);  /* 050d */
  if (a11 != 0) goto L_051c;  /* 0510: bnez.n a11, 51c <esp_mesh_push_to_tx_queue+0x4a0> */
  L_0512: a8 = a8 + (14);  /* 0512 */
  a14 = 0x2ef;  /* 0514 */
  goto L_0524;  /* 0517: j */
  L_051c: if (a11 != 2) goto L_0538;  /* 051c: bnei a11, 2, 538 <esp_mesh_push_to_tx_queue+0x4bc> */
  L_051f: a8 = a8 + (14);  /* 051f */
  a14 = 0x2f1;  /* 0521 */
  L_0524: a13 = (u32)(RODATA__rodata___func___19 + 0x0);  /* 0524: l32r -> .rodata.__func__$19 */
  a12 = LD32(a8 + 0x18);  /* 0527 */
  a10 = LD32(a7 + 0x0);  /* 0529 */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 052b: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5);  /* 052e: callx a8 via reloc-expand */
  goto L_0538;  /* 0531: j */
  L_0535: a6 = 0x0000400cu;  /* 0535: l32r = 16396 */
  L_0538: a2 = a6;  /* 0538 */
  return a2;  /* 053a: retw.n */
}


/* esp_mesh_push_to_wnd_queue @ mesh_schedule.o 00000024 size 222B bind GLOBAL
 * Calls: none | indirect[7]: mem[a3+0x158]; mem[a3+0x150]; mem[a4+0x6c]; mem[a8+0x158] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .bss.mesh_new_wnd_mbox, .rodata.mesh_get_tx_pending.str1.1, .rodata.esp_mesh_push_to_wnd_queue.str1.1
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=6); reloc-direct=0, funcdb-attributed=0, unknown-indirect=7 */
u32 esp_mesh_push_to_wnd_queue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0059;  /* 0027: bnez.n a2, 59 <esp_mesh_push_to_wnd_queue+0x35> */
  L_0029: a2 = (u32)&g_log_level + 0x0;  /* 0029: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002c */
  a2 = 0x00004008u;  /* 002f: l32r = 16392 */
  if (a3 >= 3u) goto L_0038;  /* 0032: bgeui a3, 3, 38 <esp_mesh_push_to_wnd_queue+0x14> */
  L_0035: goto L_0100;  /* 0035: j */
  L_0038: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0038: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 003b */
  if (a3 == 0) goto L_0100;  /* 003e: beqz a3, 100 <esp_mesh_push_to_wnd_queue+0xdc> */
  L_0041: a4 = LD32(a3 + 0x150);  /* 0041 */
  if (a4 == 0) goto L_0100;  /* 0044: beqz a4, 100 <esp_mesh_push_to_wnd_queue+0xdc> */
  L_0047: a10 = LD32(a3 + 0x158);  /* 0047 */
  a3 = 0x4d8;  /* 004a */
  /* 004d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0050: -> "mesh" */
  goto L_0088;  /* 0053: j */
  L_0059: a5 = (u32)&LOCAL__bss_mesh_new_wnd_mbox + 0x0;  /* 0059: l32r -> .bss.mesh_new_wnd_mbox (same-object static) */
  a10 = LD32(a5 + 0x0);  /* 005c */
  if (a10 != 0) goto L_00a0;  /* 005e: bnez.n a10, a0 <esp_mesh_push_to_wnd_queue+0x7c> */
  L_0060: a2 = (u32)&g_log_level + 0x0;  /* 0060: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0063 */
  a2 = 0x00004008u;  /* 0065: l32r = 16392 */
  if (a3 >= 3u) goto L_006e;  /* 0068: bgeui a3, 3, 6e <esp_mesh_push_to_wnd_queue+0x4a> */
  L_006b: goto L_0100;  /* 006b: j */
  L_006e: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 006e: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0071 */
  if (a3 == 0) goto L_0100;  /* 0073: beqz a3, 100 <esp_mesh_push_to_wnd_queue+0xdc> */
  L_0076: a4 = LD32(a3 + 0x150);  /* 0076 */
  if (a4 == 0) goto L_0100;  /* 0079: beqz a4, 100 <esp_mesh_push_to_wnd_queue+0xdc> */
  L_007c: a10 = LD32(a3 + 0x158);  /* 007c */
  a3 = 0x4d9;  /* 007f */
  /* 0082: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0085: -> "mesh" */
  L_0088: a13 = a10;  /* 0088 */
  a14 = a11;  /* 008a */
  a10 = 3;  /* 008c */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 008e: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0091: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 0094 */
  __asm__ volatile("" ::: "memory");  /* 0096: memw */
  /* 0099: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0100;  /* 009c: j */
  L_00a0: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a0: l32r -> global */
  a11 = a2;  /* 00a3 */
  a12 = 0;  /* 00a5 */
  a2 = 0;  /* 00a7 */
  a4 = LD32(a3 + 0x0);  /* 00a9 */
  a4 = LD32(a4 + 0x6c);  /* 00ab */
  /* 00ae: INDIRECT callx a4 <- mem[a4+0x6c]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_0100;  /* 00b1: beqi a10, 1, 100 <esp_mesh_push_to_wnd_queue+0xdc> */
  L_00b4: a2 = (u32)&g_log_level + 0x0;  /* 00b4: l32r -> global */
  a4 = LD32(a2 + 0x0);  /* 00b7 */
  a2 = 0x0000400cu;  /* 00b9: l32r = 16396 */
  if (a4 < 3u) goto L_0100;  /* 00bc: bltui a4, 3, 100 <esp_mesh_push_to_wnd_queue+0xdc> */
  L_00bf: a8 = LD32(a3 + 0x0);  /* 00bf */
  if (a8 == 0) goto L_0100;  /* 00c1: beqz.n a8, 100 <esp_mesh_push_to_wnd_queue+0xdc> */
  L_00c3: a4 = LD32(a8 + 0x150);  /* 00c3 */
  if (a4 == 0) goto L_0100;  /* 00c6: beqz.n a4, 100 <esp_mesh_push_to_wnd_queue+0xdc> */
  L_00c8: a2 = 0;  /* 00c8 */
  a10 = LD32(a8 + 0x158);  /* 00cb */
  /* 00ce: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a6 = a10;  /* 00d1 */
  a10 = LD32(a5 + 0x0);  /* 00d3 */
  if (a10 == a2) goto L_00e5;  /* 00d6: beq a10, a2, e5 <esp_mesh_push_to_wnd_queue+0xc1> */
  L_00d9: a2 = LD32(a3 + 0x0);  /* 00d9 */
  a2 = LD32(a2 + 0x78);  /* 00dc */
  /* 00df: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a2 = a10;  /* 00e2: mov */
  L_00e5: a15 = 0x4de;  /* 00e5 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00e8: -> "mesh" */
  a13 = a6;  /* 00eb */
  a14 = a11;  /* 00ed */
  a10 = 3;  /* 00ef */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_wnd_queue_str1_1 + 0x0);  /* 00f1: l32r -> .rodata.esp_mesh_push_to_wnd_queue.str1.1 */
  ST32(a1 + 0x0, a2);  /* 00f4 */
  __asm__ volatile("" ::: "memory");  /* 00f7: memw */
  /* 00fa: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  a2 = 0x0000400cu;  /* 00fd: l32r = 16396 */
  L_0100: return a2;  /* 0100: retw.n */
}


/* esp_mesh_recv_xon @ mesh_schedule.o 00000034 size 287B bind GLOBAL
 * Calls: esp_mesh_send_xon, memcpy, esp_mesh_push_to_wnd_queue | indirect[5]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .bss.mesh_xreq_seqno
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=10); reloc-direct=3, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_recv_xon(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0034: entry a1, 64 (frame 64 bytes) */
  a10 = a2;  /* 0037 */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 0039: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 003c */
  if (a2 != 0) goto L_0078;  /* 003f: bnez.n a2, 78 <esp_mesh_recv_xon+0x44> */
  L_0041: a2 = (u32)&g_log_level + 0x0;  /* 0041: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0044 */
  a2 = 0x00004004u;  /* 0047: l32r = 16388 */
  if (a3 >= 3u) goto L_0050;  /* 004a: bgeui a3, 3, 50 <esp_mesh_recv_xon+0x1c> */
  L_004d: goto L_0151;  /* 004d: j */
  L_0050: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0050: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0053 */
  if (a8 == 0) goto L_0151;  /* 0056: beqz a8, 151 <esp_mesh_recv_xon+0x11d> */
  L_0059: a3 = LD32(a8 + 0x150);  /* 0059 */
  if (a3 == 0) goto L_0151;  /* 005c: beqz a3, 151 <esp_mesh_recv_xon+0x11d> */
  L_005f: a10 = LD32(a8 + 0x158);  /* 005f */
  /* 0062: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0065 */
  a10 = 3;  /* 0067 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0069: -> "mesh" */
  a14 = a11;  /* 006c */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 006e: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 0071: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0151;  /* 0074: j */
  L_0078: if (a10 != 0) goto L_00a6;  /* 0078: bnez.n a10, a6 <esp_mesh_recv_xon+0x72> */
  L_007a: a2 = (u32)&g_log_level + 0x0;  /* 007a: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 007d */
  a2 = 0x00004008u;  /* 007f: l32r = 16392 */
  if (a3 >= 3u) goto L_0088;  /* 0082: bgeui a3, 3, 88 <esp_mesh_recv_xon+0x54> */
  L_0085: goto L_0151;  /* 0085: j */
  L_0088: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0088: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 008b */
  if (a8 == 0) goto L_0151;  /* 008d: beqz a8, 151 <esp_mesh_recv_xon+0x11d> */
  L_0090: a3 = LD32(a8 + 0x150);  /* 0090 */
  if (a3 == 0) goto L_0151;  /* 0093: beqz a3, 151 <esp_mesh_recv_xon+0x11d> */
  L_0096: a10 = LD32(a8 + 0x158);  /* 0096 */
  /* 0099: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x558;  /* 009c */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 009f: -> "mesh" */
  goto L_00d3;  /* 00a2: j */
  L_00a6: a8 = LD32(a10 + 0x0);  /* 00a6 */
  if (a8 != 0) goto L_00ec;  /* 00a8: bnez a8, ec <esp_mesh_recv_xon+0xb8> */
  L_00ab: a2 = (u32)&g_log_level + 0x0;  /* 00ab: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ae */
  a2 = 0x00004008u;  /* 00b0: l32r = 16392 */
  if (a3 >= 3u) goto L_00b9;  /* 00b3: bgeui a3, 3, b9 <esp_mesh_recv_xon+0x85> */
  L_00b6: goto L_0151;  /* 00b6: j */
  L_00b9: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b9: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00bc */
  if (a8 == 0) goto L_0151;  /* 00be: beqz a8, 151 <esp_mesh_recv_xon+0x11d> */
  L_00c1: a3 = LD32(a8 + 0x150);  /* 00c1 */
  if (a3 == 0) goto L_0151;  /* 00c4: beqz a3, 151 <esp_mesh_recv_xon+0x11d> */
  L_00c7: a10 = LD32(a8 + 0x158);  /* 00c7 */
  /* 00ca: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x559;  /* 00cd */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00d0: -> "mesh" */
  L_00d3: a13 = a10;  /* 00d3 */
  a14 = a11;  /* 00d5 */
  a10 = 3;  /* 00d7 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00d9: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00dc: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a8);  /* 00df */
  __asm__ volatile("" ::: "memory");  /* 00e2: memw */
  /* 00e5: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0151;  /* 00e8: j */
  L_00ec: a11 = LD8U(a10 + 0x12);  /* 00ec */
  if (a11 != 1) goto L_0114;  /* 00ef: bnei a11, 1, 114 <esp_mesh_recv_xon+0xe0> */
  L_00f2: a2 = a8 + (18);  /* 00f2 */
  a3 = LD32(a2 + 0x0);  /* 00f5 */
  a2 = 0;  /* 00f7 */
  if (((a3 >> 8) & 1) == 0) goto L_0151;  /* 00f9: bbci a3, 8, 151 <esp_mesh_recv_xon+0x11d> */
  L_00fc: a8 = a8 + (14);  /* 00fc */
  a15 = a2;  /* 00fe */
  a14 = LD32(a8 + 0x14);  /* 0100 */
  a12 = a11;  /* 0102 */
  a10 = a10 + (12);  /* 0104 */
  a13 = LD32(a8 + 0x18);  /* 0106 */
  a8 = (u32)&esp_mesh_send_xon;  /* 0108: l32r -> func addr */
  a2 = esp_mesh_send_xon(a2, a3, a4, a5, a6, a7);  /* 010b: callx a8 via reloc-expand */
  a2 = a10;  /* 010e */
  goto L_0151;  /* 0110: j */
  L_0114: a2 = 0;  /* 0114 */
  if (a11 != a2) goto L_0151;  /* 0116: bne a11, a2, 151 <esp_mesh_recv_xon+0x11d> */
  L_0119: a3 = a8 + (18);  /* 0119 */
  a9 = LD32(a3 + 0x0);  /* 011c */
  if (((a9 >> 8) & 1) == 0) goto L_0151;  /* 011e: bbci a9, 8, 151 <esp_mesh_recv_xon+0x11d> */
  L_0121: a8 = a8 + (14);  /* 0121 */
  a3 = (u32)&LOCAL__bss_mesh_xreq_seqno + 0x0;  /* 0123: l32r -> .bss.mesh_xreq_seqno (same-object static) */
  a11 = LD32(a8 + 0x14);  /* 0126 */
  a3 = LD32(a3 + 0x0);  /* 0128 */
  if (a11 != a3) goto L_0151;  /* 012a: bne a11, a3, 151 <esp_mesh_recv_xon+0x11d> */
  L_012d: a11 = a10 + (12);  /* 012d */
  a9 = (a9 >> 5) & 0x3ff;  /* 012f: extui width 10 */
  a3 = LD32(a8 + 0x18);  /* 0132 */
  a12 = 6;  /* 0134 */
  a10 = a1 + (24);  /* 0136 */
  ST32(a1 + 0x10, a9);  /* 0139 */
  ST32(a1 + 0x14, a3);  /* 013b */
  __asm__ volatile("" ::: "memory");  /* 013d: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0140: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0143: callx a8 (libc, via reloc-expand) */
  a11 = a2;  /* 0146 */
  a10 = a1 + (16);  /* 0148 */
  a8 = (u32)&esp_mesh_push_to_wnd_queue;  /* 014b: l32r -> func addr */
  a2 = esp_mesh_push_to_wnd_queue(a2, a3, a4, a5, a6, a7);  /* 014e: callx a8 via reloc-expand */
  L_0151: return a2;  /* 0151: retw.n */
}


/* esp_mesh_send_block_deinit @ mesh_schedule.o 00000020 size 156B bind GLOBAL
 * Calls: memset, esp_mesh_free_context | indirect[3]: mem[a5+0x6c]; mem[a2+0x8c]; mem[a4+0x74] | Data refs: .bss.is_block_running, .bss.send_block_mbox, g_osi_funcs_p, .bss.send_block_flush_mbox, .rodata.__func__$1, g_mesh_stop_event_group
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=8); reloc-direct=2, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_send_block_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8, a9;
  /* 0020: entry a1, 64 (frame 64 bytes) */
  a3 = (u32)&LOCAL__bss_is_block_running + 0x0;  /* 0023: l32r -> .bss.is_block_running (same-object static) */
  a2 = 0;  /* 0026 */
  a4 = LD8U(a3 + 0x0);  /* 0028 */
  ST32(a1 + 0x14, a2);  /* 002b */
  if (a4 != a2) goto L_0033;  /* 002d: bne a4, a2, 33 <esp_mesh_send_block_deinit+0x13> */
  L_0030: goto L_00ba;  /* 0030: j */
  L_0033: ST8(a3 + 0x0, a2);  /* 0033 */
  __asm__ volatile("" ::: "memory");  /* 0036: memw */
  a3 = (u32)&LOCAL__bss_send_block_mbox + 0x0;  /* 0039: l32r -> .bss.send_block_mbox (same-object static) */
  a4 = LD32(a3 + 0x0);  /* 003c */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 003e: l32r -> global */
  if (a4 == a2) goto L_0068;  /* 0041: beq a4, a2, 68 <esp_mesh_send_block_deinit+0x48> */
  L_0044: a12 = 16;  /* 0044 */
  a11 = a2;  /* 0046 */
  a10 = a1;  /* 0048 */
  a5 = LD32(a3 + 0x0);  /* 004a */
  __asm__ volatile("" ::: "memory");  /* 004c: memw */
  a8 = (u32)&memset + 0x0;  /* 004f: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0052: callx a8 (libc, via reloc-expand) */
  a8 = -1;  /* 0055 */
  a12 = a2;  /* 0057 */
  a11 = a1;  /* 0059 */
  ST32(a1 + 0x10, a8);  /* 005b */
  a10 = a4;  /* 005d */
  a8 = LD32(a5 + 0x6c);  /* 005f */
  __asm__ volatile("" ::: "memory");  /* 0062: memw */
  /* 0065: INDIRECT callx a8 <- mem[a5+0x6c]; result unknown */ a2 = 0;
  L_0068: a2 = (u32)&LOCAL__bss_send_block_flush_mbox + 0x0;  /* 0068: l32r -> .bss.send_block_flush_mbox (same-object static) */
  goto L_0084;  /* 006b: j */
  L_0070: a11 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 0070: l32r -> .rodata.__func__$1 */
  a12 = 0x6f3;  /* 0073 */
  a12 = a12 + a12;  /* 0076 */
  a4 = 0;  /* 0078 */
  a10 = LD32(a1 + 0x14);  /* 007a */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 007c: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 007f: callx a8 via reloc-expand */
  ST32(a1 + 0x14, a4);  /* 0082 */
  L_0084: a10 = LD32(a2 + 0x0);  /* 0084 */
  a4 = LD32(a3 + 0x0);  /* 0086 */
  if (a10 != 0) goto L_00a9;  /* 0088: bnez.n a10, a9 <esp_mesh_send_block_deinit+0x89> */
  L_008a: a12 = 0;  /* 008a */
  ST32(a2 + 0x0, a12);  /* 008c */
  a14 = -1;  /* 008e */
  a13 = 1;  /* 0090 */
  a11 = 64;  /* 0092 */
  a2 = LD32(a3 + 0x0);  /* 0094 */
  a3 = (u32)&g_mesh_stop_event_group + 0x0;  /* 0096: l32r -> global */
  a2 = LD32(a2 + 0x8c);  /* 0099 */
  a10 = LD32(a3 + 0x0);  /* 009c */
  __asm__ volatile("" ::: "memory");  /* 009e: memw */
  /* 00a1: INDIRECT callx a2 <- mem[a2+0x8c]; result unknown */ a2 = 0;
  goto L_00ba;  /* 00a4: j */
  L_00a9: a4 = LD32(a4 + 0x74);  /* 00a9 */
  a12 = 0;  /* 00ac */
  a11 = a1 + (20);  /* 00ae */
  /* 00b1: INDIRECT callx a4 <- mem[a4+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_0070;  /* 00b4: beqi a10, 1, 70 <esp_mesh_send_block_deinit+0x50> */
  L_00b7: goto L_008a;  /* 00b7: j */
  L_00ba: return a2;  /* 00ba: retw.n */
}


/* esp_mesh_send_block_event @ mesh_schedule.o 00000048 size 370B bind GLOBAL
 * Calls: none | indirect[10]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x6c]; mem[a8+0x158] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1, .bss.send_block_mbox, .rodata.mesh_get_tx_pending.str1.1, .rodata.esp_mesh_send_block_event.str1.1
 * Fidelity: medium - 10 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=8); reloc-direct=0, funcdb-attributed=0, unknown-indirect=10 */
u32 esp_mesh_send_block_event(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0048: entry a1, 64 (frame 64 bytes) */
  a3 = a2;  /* 004b */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 004d: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0050 */
  if (a2 != 0) goto L_008d;  /* 0053: bnez.n a2, 8d <esp_mesh_send_block_event+0x45> */
  L_0055: a2 = (u32)&g_log_level + 0x0;  /* 0055: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0058 */
  a2 = 0x00004004u;  /* 005b: l32r = 16388 */
  if (a3 >= 3u) goto L_0064;  /* 005e: bgeui a3, 3, 64 <esp_mesh_send_block_event+0x1c> */
  L_0061: goto L_01b8;  /* 0061: j */
  L_0064: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0064: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0067 */
  if (a3 == 0) goto L_01b8;  /* 006a: beqz a3, 1b8 <esp_mesh_send_block_event+0x170> */
  L_006d: a4 = LD32(a3 + 0x150);  /* 006d */
  if (a4 == 0) goto L_01b8;  /* 0070: beqz a4, 1b8 <esp_mesh_send_block_event+0x170> */
  L_0073: a10 = LD32(a3 + 0x158);  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0079 */
  a10 = 3;  /* 007b */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 007d: -> "mesh" */
  a14 = a11;  /* 0080 */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0082: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 0085: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01b8;  /* 0088: j */
  L_008d: if (a3 != 0) goto L_00bc;  /* 008d: bnez.n a3, bc <esp_mesh_send_block_event+0x74> */
  L_008f: a2 = (u32)&g_log_level + 0x0;  /* 008f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0092 */
  a2 = 0x00004008u;  /* 0094: l32r = 16392 */
  if (a3 >= 3u) goto L_009d;  /* 0097: bgeui a3, 3, 9d <esp_mesh_send_block_event+0x55> */
  L_009a: goto L_01b8;  /* 009a: j */
  L_009d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 009d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a0 */
  if (a3 == 0) goto L_01b8;  /* 00a2: beqz a3, 1b8 <esp_mesh_send_block_event+0x170> */
  L_00a5: a4 = LD32(a3 + 0x150);  /* 00a5 */
  if (a4 == 0) goto L_01b8;  /* 00a8: beqz a4, 1b8 <esp_mesh_send_block_event+0x170> */
  L_00ab: a10 = LD32(a3 + 0x158);  /* 00ab */
  a3 = 0x13e;  /* 00ae */
  /* 00b1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00b4: -> "mesh" */
  goto L_00eb;  /* 00b7: j */
  L_00bc: a5 = (u32)&LOCAL__bss_send_block_mbox + 0x0;  /* 00bc: l32r -> .bss.send_block_mbox (same-object static) */
  a10 = LD32(a5 + 0x0);  /* 00bf */
  if (a10 != 0) goto L_0101;  /* 00c1: bnez.n a10, 101 <esp_mesh_send_block_event+0xb9> */
  L_00c3: a2 = (u32)&g_log_level + 0x0;  /* 00c3: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c6 */
  a2 = 0x00004008u;  /* 00c8: l32r = 16392 */
  if (a3 >= 3u) goto L_00d1;  /* 00cb: bgeui a3, 3, d1 <esp_mesh_send_block_event+0x89> */
  L_00ce: goto L_01b8;  /* 00ce: j */
  L_00d1: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00d1: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d4 */
  if (a3 == 0) goto L_01b8;  /* 00d6: beqz a3, 1b8 <esp_mesh_send_block_event+0x170> */
  L_00d9: a4 = LD32(a3 + 0x150);  /* 00d9 */
  if (a4 == 0) goto L_01b8;  /* 00dc: beqz a4, 1b8 <esp_mesh_send_block_event+0x170> */
  L_00df: a10 = LD32(a3 + 0x158);  /* 00df */
  a3 = 0x13f;  /* 00e2 */
  /* 00e5: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00e8: -> "mesh" */
  L_00eb: a13 = a10;  /* 00eb */
  a14 = a11;  /* 00ed */
  a10 = 3;  /* 00ef */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00f1: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00f4: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 00f7 */
  __asm__ volatile("" ::: "memory");  /* 00f9: memw */
  goto L_01b2;  /* 00fc: j */
  L_0101: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0101: l32r -> global */
  a12 = 0;  /* 0104 */
  a11 = a3;  /* 0106 */
  a2 = LD32(a4 + 0x0);  /* 0108 */
  a2 = LD32(a2 + 0x6c);  /* 010a */
  /* 010d: INDIRECT callx a2 <- mem[a2+0x6c]; result unknown */ a2 = 0;
  a2 = 0;  /* 0110 */
  if (a10 != 1) goto L_0118;  /* 0112: bnei a10, 1, 118 <esp_mesh_send_block_event+0xd0> */
  L_0115: goto L_01b8;  /* 0115: j */
  L_0118: a6 = (u32)&g_log_level + 0x0;  /* 0118: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 011b */
  if (a6 < 3u) goto L_0185;  /* 011d: bltui a6, 3, 185 <esp_mesh_send_block_event+0x13d> */
  L_0120: a8 = LD32(a4 + 0x0);  /* 0120 */
  if (a8 == a2) goto L_0185;  /* 0122: beq a8, a2, 185 <esp_mesh_send_block_event+0x13d> */
  L_0125: a6 = LD32(a8 + 0x150);  /* 0125 */
  if (a6 == a2) goto L_0185;  /* 0128: beq a6, a2, 185 <esp_mesh_send_block_event+0x13d> */
  L_012b: a10 = LD32(a8 + 0x158);  /* 012b */
  /* 012e: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 0131 */
  a10 = LD32(a5 + 0x0);  /* 0133 */
  if (a10 == a2) goto L_0142;  /* 0135: beq a10, a2, 142 <esp_mesh_send_block_event+0xfa> */
  L_0138: a2 = LD32(a4 + 0x0);  /* 0138 */
  a2 = LD32(a2 + 0x78);  /* 013a */
  /* 013d: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a2 = a10;  /* 0140 */
  L_0142: a8 = LD32(a3 + 0x10);  /* 0142 */
  a10 = 0x00004012u;  /* 0144: l32r = 16402 */
  a9 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0147: -> "no window" */
  if (a8 == a10) goto L_0150;  /* 014a: beq a8, a10, 150 <esp_mesh_send_block_event+0x108> */
  L_014d: a9 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 014d: -> "no window" */
  L_0150: a12 = LD8U(a3 + 0x0);  /* 0150 */
  a3 = LD32(a3 + 0xc);  /* 0153 */
  a10 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0155: -> "no window" */
  if (a3 == 0) goto L_0165;  /* 0158: beqz.n a3, 165 <esp_mesh_send_block_event+0x11d> */
  L_015a: a3 = LD32(a3 + 0x28);  /* 015a */
  a3 = (a3 >> 2) & 0x1;  /* 015c: extui width 1 */
  if (a3 != 1) goto L_0165;  /* 015f: bnei a3, 1, 165 <esp_mesh_send_block_event+0x11d> */
  L_0162: a10 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0162: -> "no window" */
  L_0165: a15 = 0x144;  /* 0165 */
  a13 = a7;  /* 0168 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 016a: -> "mesh" */
  a14 = a11;  /* 016d */
  ST32(a1 + 0xc, a12);  /* 016f */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0171: -> "no window" */
  ST32(a1 + 0x10, a10);  /* 0174 */
  a10 = 3;  /* 0176 */
  ST32(a1 + 0x8, a9);  /* 0178 */
  ST32(a1 + 0x4, a8);  /* 017a */
  ST32(a1 + 0x0, a2);  /* 017c */
  __asm__ volatile("" ::: "memory");  /* 017f: memw */
  /* 0182: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_0185: a8 = 0x0000400cu;  /* 0185: l32r = 16396 */
  a2 = a8;  /* 0188 */
  a3 = LD32(a5 + 0x0);  /* 018a */
  if (a3 == 0) goto L_01b8;  /* 018c: beqz.n a3, 1b8 <esp_mesh_send_block_event+0x170> */
  L_018e: a3 = LD32(a4 + 0x0);  /* 018e */
  if (a3 == 0) goto L_01b8;  /* 0190: beqz.n a3, 1b8 <esp_mesh_send_block_event+0x170> */
  L_0192: a4 = LD32(a3 + 0x150);  /* 0192 */
  if (a4 == 0) goto L_01b8;  /* 0195: beqz a4, 1b8 <esp_mesh_send_block_event+0x170> */
  L_0198: a10 = LD32(a3 + 0x158);  /* 0198 */
  a3 = 0x14d;  /* 019b */
  /* 019e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01a1 */
  a10 = 1;  /* 01a3 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 01a5: -> "mesh" */
  a14 = a11;  /* 01a8 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 01aa: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 01ad: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 01b0 */
  L_01b2: __asm__ volatile("" ::: "memory");  /* 01b2: memw */
  /* 01b5: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_01b8: return a2;  /* 01b8: retw.n */
}


/* esp_mesh_send_block_init @ mesh_schedule.o 00000020 size 84B bind GLOBAL
 * Calls: esp_mesh_create_mbox, mesh_send_block_deinit | indirect[1]: mem[a8+0x94] | Data refs: .bss.send_block_mbox, .bss.send_block_task, g_osi_funcs_p, .rodata.esp_mesh_send_block_init.str1.1, mesh_send_block_main
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_send_block_init(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0020: entry a1, 32 (frame 32 bytes) */
  a10 = (u32)&LOCAL__bss_send_block_mbox + 0x0;  /* 0023: l32r -> .bss.send_block_mbox (same-object static) */
  a2 = LD32(a10 + 0x0);  /* 0026 */
  if (a2 == 0) goto L_0032;  /* 0028: beqz.n a2, 32 <esp_mesh_send_block_init+0x12> */
  L_002a: a2 = 0;  /* 002a */
  goto L_0072;  /* 002c: j */
  L_0032: a12 = 20;  /* 0032 */
  a11 = 1;  /* 0034 */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 0037: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 003a: callx a8 via reloc-expand */
  a2 = 0x00004007u;  /* 003d: l32r = 16391 */
  if (a10 != 0) goto L_0072;  /* 0040: bnez.n a10, 72 <esp_mesh_send_block_init+0x52> */
  L_0042: a2 = (u32)&LOCAL__bss_send_block_task + 0x0;  /* 0042: l32r -> .bss.send_block_task (same-object static) */
  a13 = LD32(a2 + 0x0);  /* 0045 */
  if (a13 != 0) goto L_002a;  /* 0047: bnez a13, 2a <esp_mesh_send_block_init+0xa> */
  L_004a: a12 = 1;  /* 004a */
  a15 = a2;  /* 004c */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 004e: l32r -> global */
  a14 = 7;  /* 0051 */
  a12 = a12 << 11;  /* 0053 */
  a8 = LD32(a8 + 0x0);  /* 0056 */
  a11 = (u32)(RODATA__rodata_esp_mesh_send_block_init_str1_1 + 0x0);  /* 0059: l32r -> .rodata.esp_mesh_send_block_init.str1.1 */
  a8 = LD32(a8 + 0x94);  /* 005c */
  a10 = (u32)&mesh_send_block_main;  /* 005f: l32r -> func addr */
  /* 0062: INDIRECT callx a8 <- mem[a8+0x94]; result unknown */ a2 = 0;
  a2 = LD32(a2 + 0x0);  /* 0065 */
  if (a2 != 0) goto L_002a;  /* 0067: bnez a2, 2a <esp_mesh_send_block_init+0xa> */
  L_006a: a8 = (u32)&mesh_send_block_deinit;  /* 006a: l32r -> func addr */
  a2 = mesh_send_block_deinit(a2, a3, a4, a5, a6, a7);  /* 006d: callx a8 via reloc-expand */
  a2 = -1;  /* 0070 */
  L_0072: return a2;  /* 0072: retw.n */
}


/* esp_mesh_send_block_start @ mesh_schedule.o 00000044 size 368B bind GLOBAL
 * Calls: esp_mesh_send_block_event | indirect[7]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x158]; mem[a2+0x150] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, mesh_myself_mbox, mesh_tcpip_mbox, .bss.mesh_tx_mbox, .bss.mesh_tx_task
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=11); reloc-direct=1, funcdb-attributed=0, unknown-indirect=7 */
u32 esp_mesh_send_block_start(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F8;
  /* 0044: entry a1, 80 (frame 80 bytes) */
  a8 = (a2 >> 8) & 0x1;  /* 0047: extui width 1 */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 004a: l32r -> global */
  a3 = (a3 >> 8) & 0x1;  /* 004d: extui width 1 */
  a2 = LD8U(a2 + 0x0);  /* 0050 */
  if (a2 != 0) goto L_008c;  /* 0053: bnez.n a2, 8c <esp_mesh_send_block_start+0x48> */
  L_0055: a2 = (u32)&g_log_level + 0x0;  /* 0055: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0058 */
  a2 = 0x00004004u;  /* 005b: l32r = 16388 */
  if (a3 >= 3u) goto L_0064;  /* 005e: bgeui a3, 3, 64 <esp_mesh_send_block_start+0x20> */
  L_0061: goto L_01b2;  /* 0061: j */
  L_0064: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0064: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0067 */
  if (a3 == 0) goto L_01b2;  /* 006a: beqz a3, 1b2 <esp_mesh_send_block_start+0x16e> */
  L_006d: a4 = LD32(a3 + 0x150);  /* 006d */
  if (a4 == 0) goto L_01b2;  /* 0070: beqz a4, 1b2 <esp_mesh_send_block_start+0x16e> */
  L_0073: a10 = LD32(a3 + 0x158);  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0079 */
  a10 = 3;  /* 007b */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 007d: -> "mesh" */
  a14 = a11;  /* 0080 */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0082: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 0085: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01b2;  /* 0088: j */
  L_008c: if (a4 != 0) goto L_00ce;  /* 008c: bnez.n a4, ce <esp_mesh_send_block_start+0x8a> */
  L_008e: a2 = (u32)&g_log_level + 0x0;  /* 008e: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0091 */
  if (a2 >= 3u) goto L_0099;  /* 0093: bgeui a2, 3, 99 <esp_mesh_send_block_start+0x55> */
  L_0096: goto L_00c8;  /* 0096: j */
  L_0099: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0099: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 009c */
  if (a2 == 0) goto L_00c8;  /* 009e: beqz a2, c8 <esp_mesh_send_block_start+0x84> */
  L_00a1: a3 = LD32(a2 + 0x150);  /* 00a1 */
  if (a3 == 0) goto L_00c8;  /* 00a4: beqz a3, c8 <esp_mesh_send_block_start+0x84> */
  L_00a7: a10 = LD32(a2 + 0x158);  /* 00a7 */
  a2 = 0x119;  /* 00aa */
  /* 00ad: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00b0: -> "mesh" */
  L_00b3: a13 = a10;  /* 00b3 */
  a14 = a11;  /* 00b5 */
  a10 = 3;  /* 00b7 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00b9: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00bc: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a2);  /* 00bf */
  __asm__ volatile("" ::: "memory");  /* 00c2: memw */
  /* 00c5: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_00c8: a2 = 0x00004008u;  /* 00c8: l32r = 16392 */
  goto L_01b2;  /* 00cb: j */
  L_00ce: a2 = LD32(a4 + 0x0);  /* 00ce */
  if (a2 != 0) goto L_00f8;  /* 00d0: bnez.n a2, f8 <esp_mesh_send_block_start+0xb4> */
  L_00d2: a2 = (u32)&g_log_level + 0x0;  /* 00d2: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00d5 */
  if (a2 < 3u) goto L_00c8;  /* 00d7: bltui a2, 3, c8 <esp_mesh_send_block_start+0x84> */
  L_00da: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00da: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00dd */
  if (a2 == 0) goto L_00c8;  /* 00df: beqz a2, c8 <esp_mesh_send_block_start+0x84> */
  L_00e2: a3 = LD32(a2 + 0x150);  /* 00e2 */
  if (a3 == 0) goto L_00c8;  /* 00e5: beqz a3, c8 <esp_mesh_send_block_start+0x84> */
  L_00e8: a10 = LD32(a2 + 0x158);  /* 00e8 */
  a2 = 0x11a;  /* 00eb */
  /* 00ee: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00f1: -> "mesh" */
  goto L_00b3;  /* 00f4: j */
  L_00f8: a2 = 0xffffbfeeu;  /* 00f8: l32r = -16402 */
  a2 = a5 + a2;  /* 00fb */
  if (a2 == 0) goto L_0109;  /* 00fd: beqz.n a2, 109 <esp_mesh_send_block_start+0xc5> */
  L_00ff: a2 = -1;  /* 00ff */
  a9 = 0xffffbff3u;  /* 0101: l32r = -16397 */
  a9 = a5 + a9;  /* 0104 */
  if (a9 != 0) goto L_01b2;  /* 0106: bnez a9, 1b2 <esp_mesh_send_block_start+0x16e> */
  L_0109: a2 = 0x0000400du;  /* 0109: l32r = 16397 */
  ST32(a1 + 0x20, a5);  /* 010c */
  ST32(a1 + 0x1c, a4);  /* 010e */
  if (a5 == a2) goto L_0116;  /* 0110: beq a5, a2, 116 <esp_mesh_send_block_start+0xd2> */
  L_0113: goto L_01a2;  /* 0113: j */
  L_0116: a2 = 0;  /* 0116 */
  ST32(a1 + 0x18, a2);  /* 0118 */
  a2 = (u32)&mesh_myself_mbox + 0x0;  /* 011a: l32r -> global */
  if (a8 == 3) goto L_0126;  /* 011d: beqi a8, 3, 126 <esp_mesh_send_block_start+0xe2> */
  L_0120: if (a8 != 4) goto L_0130;  /* 0120: bnei a8, 4, 130 <esp_mesh_send_block_start+0xec> */
  L_0123: a2 = (u32)&mesh_tcpip_mbox + 0x0;  /* 0123: l32r -> global */
  L_0126: a2 = LD32(a2 + 0x0);  /* 0126 */
  ST32(a1 + 0x14, a2);  /* 0128 */
  __asm__ volatile("" ::: "memory");  /* 012a: memw */
  goto L_019c;  /* 012d: j */
  L_0130: a4 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0130: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a2 = a8 + (a8 << 1);  /* 0133 */
  a2 = a2 + (a4 << 2);  /* 0136 */
  a4 = LD32(a2 + 0x0);  /* 0139 */
  if (a4 != 0) goto L_0162;  /* 013b: bnez.n a4, 162 <esp_mesh_send_block_start+0x11e> */
  L_013d: a2 = (u32)&g_log_level + 0x0;  /* 013d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0140 */
  if (a2 < 3u) goto L_00c8;  /* 0142: bltui a2, 3, c8 <esp_mesh_send_block_start+0x84> */
  L_0145: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0145: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0148 */
  if (a2 == 0) goto L_00c8;  /* 014a: beqz a2, c8 <esp_mesh_send_block_start+0x84> */
  L_014d: a3 = LD32(a2 + 0x150);  /* 014d */
  if (a3 == 0) goto L_00c8;  /* 0150: beqz a3, c8 <esp_mesh_send_block_start+0x84> */
  L_0153: a10 = LD32(a2 + 0x158);  /* 0153 */
  a2 = 0x130;  /* 0156 */
  /* 0159: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 015c: -> "mesh" */
  goto L_00b3;  /* 015f: j */
  L_0162: a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0162: l32r -> .bss.mesh_tx_task (same-object static) */
  a3 = a3 + (a3 << 1);  /* 0165 */
  a3 = a3 + (a2 << 3);  /* 0168 */
  a2 = LD32(a3 + 0x0);  /* 016b */
  if (a2 != 0) goto L_0198;  /* 016d: bnez.n a2, 198 <esp_mesh_send_block_start+0x154> */
  L_016f: a2 = (u32)&g_log_level + 0x0;  /* 016f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0172 */
  if (a2 >= 3u) goto L_017a;  /* 0174: bgeui a2, 3, 17a <esp_mesh_send_block_start+0x136> */
  L_0177: goto L_00c8;  /* 0177: j */
  L_017a: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 017a: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 017d */
  if (a2 == 0) goto L_00c8;  /* 017f: beqz a2, c8 <esp_mesh_send_block_start+0x84> */
  L_0182: a3 = LD32(a2 + 0x150);  /* 0182 */
  if (a3 == 0) goto L_00c8;  /* 0185: beqz a3, c8 <esp_mesh_send_block_start+0x84> */
  L_0188: a10 = LD32(a2 + 0x158);  /* 0188 */
  a2 = 0x131;  /* 018b */
  /* 018e: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0191: -> "mesh" */
  goto L_00b3;  /* 0194: j */
  L_0198: ST32(a1 + 0x14, a4);  /* 0198 */
  ST32(a1 + 0x18, a2);  /* 019a */
  L_019c: ST8(a1 + 0x10, a8);  /* 019c */
  __asm__ volatile("" ::: "memory");  /* 019f: memw */
  L_01a2: a11 = 0;  /* 01a2 */
  a10 = a1 + (16);  /* 01a4 */
  __asm__ volatile("" ::: "memory");  /* 01a7: memw */
  a8 = (u32)&esp_mesh_send_block_event;  /* 01aa: l32r -> func addr */
  a2 = esp_mesh_send_block_event(a2, a3, a4, a5, a6, a7);  /* 01ad: callx a8 via reloc-expand */
  a2 = 0;  /* 01b0 */
  L_01b2: return a2;  /* 01b2: retw.n */
}


/* esp_mesh_send_block_time @ mesh_schedule.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_mesh_packet_lifetime
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_send_block_time(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_packet_lifetime + 0x0;  /* 0007: l32r -> global */
  ST32(a8 + 0x0, a2);  /* 000a */
  a2 = 0;  /* 000c */
  __asm__ volatile("" ::: "memory");  /* 000e: memw */
  return a2;  /* 0011: retw.n */
}


/* esp_mesh_send_xon @ mesh_schedule.o 000000b4 size 1564B bind GLOBAL
 * Calls: esp_mesh_create_context, mesh_send_process_topo, esp_mesh_available_txupQ_num, esp_mesh_discard_context, esp_mesh_txupQ_pending_clear_xonseq, memcpy, esp_mesh_txupQ_pending, esp_mesh_free_context, esp_mesh_push_to_tx_queue, esp_mesh_print_txQ_waiting, esp_mesh_print_rxQ_waiting | indirect[22]: mem[a2+0x158]; mem[a2+0x150]; mem[a6+0xb8]; mem[a5+0x158] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, g_mesh_topology, .rodata.__func__$17, .bss.mesh_xreq_seqno, .rodata.esp_mesh_send_xon.str1.1, .rodata.esp_mesh_send_block_event.str1.1, g_mesh_ext_cfg +3 more
 * Fidelity: medium - 22 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=11, refs=26); reloc-direct=11, funcdb-attributed=0, unknown-indirect=22 */
u32 esp_mesh_send_xon(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 00b4: entry a1, 144 (frame 144 bytes) */
  ST32(a1 + 0x4c, a3);  /* 00b7 */
  a7 = (a7 >> 8) & 0x1;  /* 00ba: extui width 1 */
  a3 = (u32)&g_is_mesh_started + 0x0;  /* 00bd: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 00c0 */
  ST32(a1 + 0x44, a5);  /* 00c3 */
  ST32(a1 + 0x48, a6);  /* 00c6 */
  if (a3 != 0) goto L_0106;  /* 00c9: bnez.n a3, 106 <esp_mesh_send_xon+0x52> */
  L_00cb: a2 = (u32)&g_log_level + 0x0;  /* 00cb: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00ce */
  a3 = 0x00004004u;  /* 00d0: l32r = 16388 */
  if (a2 >= 3u) goto L_00d9;  /* 00d3: bgeui a2, 3, d9 <esp_mesh_send_xon+0x25> */
  L_00d6: goto L_06cc;  /* 00d6: j */
  L_00d9: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00d9: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00dc */
  if (a2 == 0) goto L_06cc;  /* 00df: beqz a2, 6cc <esp_mesh_send_xon+0x618> */
  L_00e2: a4 = LD32(a2 + 0x150);  /* 00e2 */
  if (a4 == 0) goto L_06cc;  /* 00e5: beqz a4, 6cc <esp_mesh_send_xon+0x618> */
  L_00e8: a10 = LD32(a2 + 0x158);  /* 00e8 */
  __asm__ volatile("" ::: "memory");  /* 00eb: memw */
  /* 00ee: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00f1 */
  a10 = 3;  /* 00f3 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00f5: -> "mesh" */
  a14 = a11;  /* 00f8 */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00fa: l32r -> .rodata.esp_mesh_print_txQ_waiting.str1.1 */
  /* 00fd: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_06cc;  /* 0100: j */
  L_0106: if (a2 != 0) goto L_0149;  /* 0106: bnez.n a2, 149 <esp_mesh_send_xon+0x95> */
  L_0108: a2 = (u32)&g_log_level + 0x0;  /* 0108: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 010b */
  a3 = 0x00004008u;  /* 010d: l32r = 16392 */
  if (a2 >= 3u) goto L_0116;  /* 0110: bgeui a2, 3, 116 <esp_mesh_send_xon+0x62> */
  L_0113: goto L_06cc;  /* 0113: j */
  L_0116: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0116: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0119 */
  if (a2 == 0) goto L_06cc;  /* 011b: beqz a2, 6cc <esp_mesh_send_xon+0x618> */
  L_011e: a4 = LD32(a2 + 0x150);  /* 011e */
  if (a4 == 0) goto L_06cc;  /* 0121: beqz a4, 6cc <esp_mesh_send_xon+0x618> */
  L_0124: a10 = LD32(a2 + 0x158);  /* 0124 */
  a2 = 0x3e4;  /* 0127 */
  /* 012a: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 012d */
  a10 = 3;  /* 012f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0131: -> "mesh" */
  a14 = a11;  /* 0134 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0136: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0139: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a2);  /* 013c */
  __asm__ volatile("" ::: "memory");  /* 013e: memw */
  /* 0141: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_06cc;  /* 0144: j */
  L_0149: a3 = 0;  /* 0149 */
  ST32(a1 + 0x34, a3);  /* 014b */
  ST32(a1 + 0x30, a3);  /* 014d */
  a3 = -1;  /* 014f */
  if (a4 < 2u) goto L_0157;  /* 0151: bltui a4, 2, 157 <esp_mesh_send_xon+0xa3> */
  L_0154: goto L_06cc;  /* 0154: j */
  L_0157: a3 = 7;  /* 0157 */
  a6 = (u32)&g_mesh_topology + 0x0;  /* 0159: l32r -> global */
  a10 = LD32(a6 + 0x0);  /* 015c */
  if (a10 == 0) goto L_0164;  /* 015e: beqz.n a10, 164 <esp_mesh_send_xon+0xb0> */
  L_0160: a3 = 8;  /* 0160 */
  a10 = 1;  /* 0162 */
  L_0164: a5 = (u32)(RODATA__rodata___func___17 + 0x0);  /* 0164: l32r -> .rodata.__func__$17 */
  a10 = a10 + a3;  /* 0167 */
  a10 = a10 << 2;  /* 0169 */
  a12 = 0x3f5;  /* 016c */
  a11 = a5;  /* 016f */
  a10 = a10 + (14);  /* 0171 */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 0176: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 0179: callx a8 via reloc-expand */
  ST32(a1 + 0x34, a10);  /* 017c */
  a3 = 0x00004007u;  /* 017e: l32r = 16391 */
  if (a10 == 0) goto L_06cc;  /* 0181: beqz a10, 6cc <esp_mesh_send_xon+0x618> */
  L_0184: a9 = -16;  /* 0184 */
  a11 = 8;  /* 0186 */
  a10 = LD32(a10 + 0x0);  /* 0188 */
  a8 = a10 + (14);  /* 018a */
  a3 = LD8U(a10 + 0xe);  /* 018c */
  a3 = a3 & a9;  /* 018f */
  a9 = 1;  /* 0192 */
  a3 = a3 | a9;  /* 0194 */
  ST8(a10 + 0xe, a3);  /* 0197 */
  __asm__ volatile("" ::: "memory");  /* 019a: memw */
  a9 = 0;  /* 019d */
  a3 = LD32(a6 + 0x0);  /* 019f */
  a6 = 7;  /* 01a1 */
  a12 = a6;  /* 01a3 */
  if (a3 != 0) a12 = a11;  /* 01a5 */
  ST32(a1 + 0x40, a10);  /* 01a8 */
  a10 = 1;  /* 01ab */
  if (a3 != 0) a9 = a10;  /* 01ad */
  a9 = a9 + a12;  /* 01b0 */
  a12 = LD32(a1 + 0x40);  /* 01b2 */
  ST8(a12 + 0xf, a9);  /* 01b5 */
  __asm__ volatile("" ::: "memory");  /* 01b8: memw */
  if (a3 == 0) goto L_01c1;  /* 01bb: beqz.n a3, 1c1 <esp_mesh_send_xon+0x10d> */
  L_01bd: a6 = a11;  /* 01bd */
  a3 = a10;  /* 01bf */
  L_01c1: a3 = a3 + a6;  /* 01c1 */
  a6 = LD32(a1 + 0x40);  /* 01c3 */
  a3 = a3 << 2;  /* 01c6 */
  a10 = a8;  /* 01c9 */
  ST16(a6 + 0x10, a3);  /* 01cb */
  __asm__ volatile("" ::: "memory");  /* 01ce: memw */
  ST32(a1 + 0x64, a8);  /* 01d1 */
  __asm__ volatile("" ::: "memory");  /* 01d4: memw */
  a8 = (u32)&mesh_send_process_topo + 0x0;  /* 01d7: l32r -> global */
  a2 = mesh_send_process_topo(a2, a3, a4, a5, a6, a7);  /* 01da: callx a8 via reloc-expand */
  a3 = LD8U(a6 + 0x13);  /* 01dd */
  a6 = 62;  /* 01e0 */
  a3 = a3 & a6;  /* 01e2 */
  a6 = -127;  /* 01e5 */
  a3 = a3 | a6;  /* 01e8 */
  a9 = LD32(a1 + 0x40);  /* 01eb */
  ST8(a9 + 0x13, a3);  /* 01ee */
  __asm__ volatile("" ::: "memory");  /* 01f1: memw */
  a8 = LD32(a1 + 0x64);  /* 01f4 */
  if (a4 != 0) goto L_0231;  /* 01f7: bnez.n a4, 231 <esp_mesh_send_xon+0x17d> */
  L_01f9: a4 = (u32)&LOCAL__bss_mesh_xreq_seqno + 0x0;  /* 01f9: l32r -> .bss.mesh_xreq_seqno (same-object static) */
  a3 = LD32(a4 + 0x0);  /* 01fc */
  if (a7 == 0) goto L_0214;  /* 01fe: beqz.n a7, 214 <esp_mesh_send_xon+0x160> */
  L_0200: a3 = a3 + (1);  /* 0200 */
  a5 = 0x0ffffffeu;  /* 0202: l32r = 268435454 */
  if (a5 < a3) goto L_020e;  /* 0205: bltu a5, a3, 20e <esp_mesh_send_xon+0x15a> */
  L_0208: __asm__ volatile("" ::: "memory");  /* 0208: memw */
  goto L_0210;  /* 020b: j */
  L_020e: a3 = 1;  /* 020e */
  L_0210: ST32(a4 + 0x0, a3);  /* 0210 */
  a3 = LD32(a4 + 0x0);  /* 0212 */
  L_0214: a5 = LD32(a1 + 0x40);  /* 0214 */
  a4 = a5 + (18);  /* 0217 */
  ST32(a8 + 0x14, a3);  /* 021a */
  a3 = LD32(a1 + 0x44);  /* 021c */
  ST32(a8 + 0x18, a3);  /* 021f */
  a3 = LD32(a4 + 0x0);  /* 0221 */
  a5 = 0xffffc1ffu;  /* 0223: l32r = -15873 */
  a3 = a3 & a5;  /* 0226 */
  ST32(a4 + 0x0, a3);  /* 0229 */
  __asm__ volatile("" ::: "memory");  /* 022b: memw */
  goto L_0606;  /* 022e: j */
  L_0231: a11 = a1 + (48);  /* 0231 */
  a10 = a2;  /* 0234 */
  a8 = (u32)&esp_mesh_available_txupQ_num;  /* 0236: l32r -> func addr */
  a2 = esp_mesh_available_txupQ_num(a2, a3, a4, a5, a6, a7);  /* 0239: callx a8 via reloc-expand */
  a4 = 0x00004004u;  /* 023c: l32r = 16388 */
  a3 = a10;  /* 023f */
  if (a10 != a4) goto L_0294;  /* 0241: bne a10, a4, 294 <esp_mesh_send_xon+0x1e0> */
  L_0244: a2 = (u32)&g_log_level + 0x0;  /* 0244: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0247 */
  if (a2 < 3u) goto L_0280;  /* 0249: bltui a2, 3, 280 <esp_mesh_send_xon+0x1cc> */
  L_024c: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 024c: l32r -> global */
  a2 = LD32(a6 + 0x0);  /* 024f */
  if (a2 == 0) goto L_0280;  /* 0251: beqz.n a2, 280 <esp_mesh_send_xon+0x1cc> */
  L_0253: a4 = LD32(a2 + 0x150);  /* 0253 */
  if (a4 == 0) goto L_0280;  /* 0256: beqz.n a4, 280 <esp_mesh_send_xon+0x1cc> */
  L_0258: a10 = LD32(a2 + 0x158);  /* 0258 */
  /* 025b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 025e */
  a6 = LD32(a6 + 0x0);  /* 0260 */
  a10 = LD32(a6 + 0xb8);  /* 0263 */
  /* 0266: INDIRECT callx a10 <- mem[a6+0xb8]; result unknown */ a2 = 0;
  a15 = 0x418;  /* 0269 */
  a13 = a2;  /* 026c */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 026e: -> "mesh" */
  a14 = a11;  /* 0271 */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_xon_str1_1 + 0x0);  /* 0273: -> ", restart??" */
  ST32(a1 + 0x0, a10);  /* 0276 */
  a10 = 3;  /* 0278 */
  __asm__ volatile("" ::: "memory");  /* 027a: memw */
  /* 027d: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0280: a13 = 0x41a;  /* 0280 */
  a12 = a5;  /* 0283 */
  a11 = 0x00004004u;  /* 0285: l32r = 16388 */
  a10 = LD32(a1 + 0x34);  /* 0288 */
  a8 = (u32)&esp_mesh_discard_context;  /* 028a: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 028d: callx a8 via reloc-expand */
  goto L_06cc;  /* 0290: j */
  L_0294: a5 = a10 + (1);  /* 0294 */
  a4 = LD32(a1 + 0x30);  /* 0296 */
  if (a5 >= 2u) goto L_02b1;  /* 0298: bgeui a5, 2, 2b1 <esp_mesh_send_xon+0x1fd> */
  L_029b: a6 = LD32(a1 + 0x40);  /* 029b */
  a4 = a6 + (18);  /* 029e */
  a3 = LD32(a4 + 0x0);  /* 02a1 */
  a5 = 0xffffc1ffu;  /* 02a3: l32r = -15873 */
  a3 = a3 & a5;  /* 02a6 */
  ST32(a4 + 0x0, a3);  /* 02a9 */
  __asm__ volatile("" ::: "memory");  /* 02ab: memw */
  goto L_05f8;  /* 02ae: j */
  L_02b1: a8 = LD32(a1 + 0x44);  /* 02b1 */
  if (a4 >= a8) goto L_02ba;  /* 02b4: bgeu a4, a8, 2ba <esp_mesh_send_xon+0x206> */
  L_02b7: goto L_0349;  /* 02b7: j */
  L_02ba: a4 = (u32)&g_log_level + 0x0;  /* 02ba: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 02bd */
  if (a4 < 3u) goto L_033a;  /* 02c0: bltui a4, 3, 33a <esp_mesh_send_xon+0x286> */
  L_02c3: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 02c3: l32r -> global */
  a5 = LD32(a4 + 0x0);  /* 02c6 */
  if (a5 == 0) goto L_033a;  /* 02c9: beqz a5, 33a <esp_mesh_send_xon+0x286> */
  L_02cc: a4 = LD32(a5 + 0x150);  /* 02cc */
  if (a4 == 0) goto L_033a;  /* 02cf: beqz a4, 33a <esp_mesh_send_xon+0x286> */
  L_02d2: a10 = LD32(a5 + 0x158);  /* 02d2 */
  /* 02d5: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a9 = LD8U(a2 + 0x3);  /* 02d8 */
  a8 = LD32(a1 + 0x44);  /* 02db */
  ST32(a1 + 0x68, a9);  /* 02de */
  a5 = LD32(a1 + 0x30);  /* 02e1 */
  a15 = LD8U(a2 + 0x0);  /* 02e4 */
  a14 = LD8U(a2 + 0x1);  /* 02e7 */
  a13 = LD8U(a2 + 0x2);  /* 02ea */
  a9 = LD8U(a2 + 0x4);  /* 02ed */
  a12 = LD8U(a2 + 0x5);  /* 02f0 */
  a6 = (u32)(RODATA__rodata_esp_mesh_send_xon_str1_1 + 0x0);  /* 02f3: -> ", restart??" */
  if (a8 == 1) goto L_02fc;  /* 02f6: beqi a8, 1, 2fc <esp_mesh_send_xon+0x248> */
  L_02f9: a6 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 02f9: -> "no window" */
  L_02fc: a7 = (u32)(RODATA__rodata_esp_mesh_send_xon_str1_1 + 0x0);  /* 02fc: -> ", restart??" */
  if (a5 == 0) goto L_0304;  /* 02ff: beqz.n a5, 304 <esp_mesh_send_xon+0x250> */
  L_0301: a7 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0301: -> "no window" */
  L_0304: a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0304: -> "mesh" */
  a8 = LD32(a1 + 0x48);  /* 0307 */
  ST32(a1 + 0x1c, a9);  /* 030a */
  ST32(a1 + 0x8, a5);  /* 030c */
  a9 = LD32(a1 + 0x68);  /* 030e */
  a5 = LD32(a1 + 0x44);  /* 0311 */
  ST32(a1 + 0x20, a12);  /* 0314 */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_xon_str1_1 + 0x0);  /* 0316: -> ", restart??" */
  ST32(a1 + 0x14, a13);  /* 0319 */
  a13 = a10;  /* 031b */
  a10 = 3;  /* 031d */
  ST32(a1 + 0x10, a14);  /* 031f */
  a14 = a11;  /* 0321 */
  ST32(a1 + 0xc, a15);  /* 0323 */
  a15 = 0x442;  /* 0325 */
  ST32(a1 + 0x2c, a8);  /* 0328 */
  ST32(a1 + 0x28, a7);  /* 032a */
  ST32(a1 + 0x24, a6);  /* 032c */
  ST32(a1 + 0x18, a9);  /* 032e */
  ST32(a1 + 0x4, a5);  /* 0330 */
  ST32(a1 + 0x0, a3);  /* 0332 */
  __asm__ volatile("" ::: "memory");  /* 0334: memw */
  /* 0337: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_033a: a4 = 0;  /* 033a */
  a10 = a2;  /* 033c */
  ST32(a1 + 0x30, a4);  /* 033e */
  __asm__ volatile("" ::: "memory");  /* 0340: memw */
  a8 = (u32)&esp_mesh_txupQ_pending_clear_xonseq;  /* 0343: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending_clear_xonseq(a2, a3, a4, a5, a6, a7);  /* 0346: callx a8 via reloc-expand */
  L_0349: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0349: l32r -> global */
  a8 = LD32(a1 + 0x44);  /* 034c */
  a5 = LD32(a4 + 0x0);  /* 034f */
  a7 = LD32(a1 + 0x30);  /* 0351 */
  a11 = a8 - a7;  /* 0353: sub */
  a6 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0356: l32r -> global */
  a10 = LD32(a5 + 0xb8);  /* 0359 */
  a8 = LD8U(a6 + 0xbd);  /* 035c */
  a8 = a8 + a8;  /* 035f */
  a8 = a8 + (1);  /* 0361 */
  a5 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0363: l32r -> global */
  a9 = LD32(a5 + 0x0);  /* 0366 */
  a8 = a9 / a8;  /* 0368: quos */
  if (a8 < a11) goto L_0385;  /* 036b: bltu a8, a11, 385 <esp_mesh_send_xon+0x2d1> */
  L_036e: a7 = a3 + a7;  /* 036e */
  a9 = LD32(a1 + 0x44);  /* 0370 */
  a4 = a7 + (1);  /* 0373 */
  a3 = 0;  /* 0375 */
  if (a4 >= a9) goto L_037d;  /* 0377: bgeu a4, a9, 37d <esp_mesh_send_xon+0x2c9> */
  L_037a: goto L_059c;  /* 037a: j */
  L_037d: a7 = a7 - a9;  /* 037d: sub */
  a3 = a7 + (1);  /* 0380 */
  goto L_059c;  /* 0382: j */
  L_0385: /* 0385: INDIRECT callx a10 <- mem[a5+0xb8]; result unknown */ a2 = 0;
  a7 = 0x5db;  /* 0388 */
  a3 = (u32)&g_log_level + 0x0;  /* 038b: l32r -> global */
  if (a7 >= a10) goto L_0394;  /* 038e: bgeu a7, a10, 394 <esp_mesh_send_xon+0x2e0> */
  L_0391: goto L_0454;  /* 0391: j */
  L_0394: a8 = LD32(a4 + 0x0);  /* 0394 */
  a10 = LD32(a8 + 0xb8);  /* 0396 */
  /* 0399: INDIRECT callx a10 <- mem[a8+0xb8]; result unknown */ a2 = 0;
  if (a7 >= a10) goto L_03a2;  /* 039c: bgeu a7, a10, 3a2 <esp_mesh_send_xon+0x2ee> */
  L_039f: goto L_0454;  /* 039f: j */
  L_03a2: a9 = LD32(a1 + 0x40);  /* 03a2 */
  a8 = a9 + (18);  /* 03a5 */
  a7 = LD32(a8 + 0x0);  /* 03a8 */
  a9 = 0xffffc1ffu;  /* 03aa: l32r = -15873 */
  a7 = a7 & a9;  /* 03ad */
  ST32(a8 + 0x0, a7);  /* 03b0 */
  a3 = LD32(a3 + 0x0);  /* 03b2 */
  if (a3 >= 3u) goto L_03ba;  /* 03b4: bgeui a3, 3, 3ba <esp_mesh_send_xon+0x306> */
  L_03b7: goto L_05f8;  /* 03b7: j */
  L_03ba: a7 = LD32(a4 + 0x0);  /* 03ba */
  if (a7 == 0) goto L_05f8;  /* 03bc: beqz a7, 5f8 <esp_mesh_send_xon+0x544> */
  L_03bf: a3 = LD32(a7 + 0x150);  /* 03bf */
  if (a3 == 0) goto L_05f8;  /* 03c2: beqz a3, 5f8 <esp_mesh_send_xon+0x544> */
  L_03c5: a10 = LD32(a7 + 0x158);  /* 03c5 */
  __asm__ volatile("" ::: "memory");  /* 03c8: memw */
  /* 03cb: INDIRECT callx a10 <- mem[a7+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 03ce */
  a6 = LD8U(a6 + 0xbd);  /* 03d0 */
  a6 = a6 + a6;  /* 03d3 */
  a6 = a6 + (1);  /* 03d5 */
  a4 = LD32(a4 + 0x0);  /* 03d7 */
  a15 = LD8U(a2 + 0x0);  /* 03d9 */
  a8 = LD8U(a2 + 0x2);  /* 03dc */
  a9 = LD8U(a2 + 0x3);  /* 03df */
  a12 = LD8U(a2 + 0x4);  /* 03e2 */
  a13 = LD8U(a2 + 0x5);  /* 03e5 */
  a5 = LD32(a5 + 0x0);  /* 03e8 */
  a5 = a5 / a6;  /* 03ea: quos */
  a14 = LD32(a1 + 0x30);  /* 03ed */
  a10 = LD32(a4 + 0xb8);  /* 03ef */
  a6 = LD8U(a2 + 0x1);  /* 03f2 */
  ST32(a1 + 0x64, a8);  /* 03f5 */
  ST32(a1 + 0x58, a9);  /* 03f8 */
  ST32(a1 + 0x5c, a12);  /* 03fb */
  ST32(a1 + 0x60, a13);  /* 03fe */
  ST32(a1 + 0x50, a14);  /* 0401 */
  ST32(a1 + 0x54, a15);  /* 0404 */
  __asm__ volatile("" ::: "memory");  /* 0407: memw */
  /* 040a: INDIRECT callx a10 <- mem[a4+0xb8]; result unknown */ a2 = 0;
  a12 = LD32(a1 + 0x5c);  /* 040d */
  a13 = LD32(a1 + 0x60);  /* 0410 */
  a15 = LD32(a1 + 0x54);  /* 0413 */
  a14 = LD32(a1 + 0x50);  /* 0416 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0419: -> "mesh" */
  a4 = LD32(a1 + 0x48);  /* 041c */
  a9 = LD32(a1 + 0x58);  /* 041f */
  a8 = LD32(a1 + 0x64);  /* 0422 */
  ST32(a1 + 0x4, a5);  /* 0425 */
  a5 = LD32(a1 + 0x44);  /* 0427 */
  ST32(a1 + 0x1c, a12);  /* 042a */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_xon_str1_1 + 0x0);  /* 042c: -> ", restart??" */
  ST32(a1 + 0x28, a10);  /* 042f */
  a10 = 3;  /* 0431 */
  ST32(a1 + 0x20, a13);  /* 0433 */
  a13 = a7;  /* 0435 */
  ST32(a1 + 0xc, a15);  /* 0437 */
  a15 = 0x46f;  /* 0439 */
  ST32(a1 + 0x8, a14);  /* 043c */
  a14 = a11;  /* 043e */
  ST32(a1 + 0x24, a4);  /* 0440 */
  ST32(a1 + 0x18, a9);  /* 0442 */
  ST32(a1 + 0x14, a8);  /* 0444 */
  ST32(a1 + 0x10, a6);  /* 0446 */
  ST32(a1 + 0x0, a5);  /* 0448 */
  __asm__ volatile("" ::: "memory");  /* 044a: memw */
  /* 044d: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  goto L_05f8;  /* 0450: j */
  L_0454: a7 = LD32(a1 + 0x30);  /* 0454 */
  a7 = a7 + (1);  /* 0456 */
  a3 = LD32(a3 + 0x0);  /* 0458 */
  ST32(a1 + 0x30, a7);  /* 045a */
  if (a3 >= 3u) goto L_0462;  /* 045c: bgeui a3, 3, 462 <esp_mesh_send_xon+0x3ae> */
  L_045f: goto L_04f8;  /* 045f: j */
  L_0462: a7 = LD32(a4 + 0x0);  /* 0462 */
  if (a7 == 0) goto L_04f8;  /* 0464: beqz a7, 4f8 <esp_mesh_send_xon+0x444> */
  L_0467: a3 = LD32(a7 + 0x150);  /* 0467 */
  if (a3 == 0) goto L_04f8;  /* 046a: beqz a3, 4f8 <esp_mesh_send_xon+0x444> */
  L_046d: a10 = LD32(a7 + 0x158);  /* 046d */
  __asm__ volatile("" ::: "memory");  /* 0470: memw */
  /* 0473: INDIRECT callx a10 <- mem[a7+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 0476 */
  a6 = LD8U(a6 + 0xbd);  /* 0478 */
  a6 = a6 + a6;  /* 047b */
  a6 = a6 + (1);  /* 047d */
  a4 = LD32(a4 + 0x0);  /* 047f */
  a5 = LD32(a5 + 0x0);  /* 0481 */
  a5 = a5 / a6;  /* 0483: quos */
  a15 = LD8U(a2 + 0x0);  /* 0486 */
  a8 = LD8U(a2 + 0x2);  /* 0489 */
  a9 = LD8U(a2 + 0x3);  /* 048c */
  a12 = LD8U(a2 + 0x4);  /* 048f */
  a13 = LD8U(a2 + 0x5);  /* 0492 */
  a14 = LD32(a1 + 0x30);  /* 0495 */
  a10 = LD32(a4 + 0xb8);  /* 0497 */
  a6 = LD8U(a2 + 0x1);  /* 049a */
  ST32(a1 + 0x64, a8);  /* 049d */
  ST32(a1 + 0x58, a9);  /* 04a0 */
  ST32(a1 + 0x5c, a12);  /* 04a3 */
  ST32(a1 + 0x60, a13);  /* 04a6 */
  ST32(a1 + 0x50, a14);  /* 04a9 */
  ST32(a1 + 0x54, a15);  /* 04ac */
  __asm__ volatile("" ::: "memory");  /* 04af: memw */
  /* 04b2: INDIRECT callx a10 <- mem[a4+0xb8]; result unknown */ a2 = 0;
  a12 = LD32(a1 + 0x5c);  /* 04b5 */
  a13 = LD32(a1 + 0x60);  /* 04b8 */
  a15 = LD32(a1 + 0x54);  /* 04bb */
  a14 = LD32(a1 + 0x50);  /* 04be */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 04c1: -> "mesh" */
  a4 = LD32(a1 + 0x48);  /* 04c4 */
  a9 = LD32(a1 + 0x58);  /* 04c7 */
  a8 = LD32(a1 + 0x64);  /* 04ca */
  ST32(a1 + 0x4, a5);  /* 04cd */
  a5 = LD32(a1 + 0x44);  /* 04cf */
  ST32(a1 + 0x1c, a12);  /* 04d2 */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_xon_str1_1 + 0x0);  /* 04d4: -> ", restart??" */
  ST32(a1 + 0x28, a10);  /* 04d7 */
  a10 = 3;  /* 04d9 */
  ST32(a1 + 0x20, a13);  /* 04db */
  a13 = a7;  /* 04dd */
  ST32(a1 + 0xc, a15);  /* 04df */
  a15 = 0x476;  /* 04e1 */
  ST32(a1 + 0x8, a14);  /* 04e4 */
  a14 = a11;  /* 04e6 */
  ST32(a1 + 0x24, a4);  /* 04e8 */
  ST32(a1 + 0x18, a9);  /* 04ea */
  ST32(a1 + 0x14, a8);  /* 04ec */
  ST32(a1 + 0x10, a6);  /* 04ee */
  ST32(a1 + 0x0, a5);  /* 04f0 */
  __asm__ volatile("" ::: "memory");  /* 04f2: memw */
  /* 04f5: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  L_04f8: a12 = 6;  /* 04f8 */
  a11 = a2;  /* 04fa */
  a3 = LD32(a1 + 0x34);  /* 04fc */
  a10 = a3 + (12);  /* 04fe */
  a8 = (u32)&memcpy + 0x0;  /* 0500: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0503: callx a8 (libc, via reloc-expand) */
  a10 = a3;  /* 0506 */
  a4 = (u32)(RODATA__rodata___func___17 + 0x0);  /* 0508: l32r -> .rodata.__func__$17 */
  a14 = 0x480;  /* 050b */
  a13 = a4;  /* 050e */
  a11 = 1;  /* 0510 */
  a12 = LD32(a1 + 0x30);  /* 0513 */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 0516: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0519: callx a8 via reloc-expand */
  a3 = a10;  /* 051c */
  a12 = 0x483;  /* 051e */
  a5 = 0x00004004u;  /* 0521: l32r = 16388 */
  if (a10 == a5) goto L_057c;  /* 0524: beq a10, a5, 57c <esp_mesh_send_xon+0x4c8> */
  L_0527: if (a10 == 0) goto L_0589;  /* 0527: beqz a10, 589 <esp_mesh_send_xon+0x4d5> */
  L_052a: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 052a: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 052d */
  if (a5 == 0) goto L_0579;  /* 052f: beqz a5, 579 <esp_mesh_send_xon+0x4c5> */
  L_0532: a6 = LD32(a5 + 0x150);  /* 0532 */
  if (a6 == 0) goto L_0579;  /* 0535: beqz a6, 579 <esp_mesh_send_xon+0x4c5> */
  L_0538: a10 = LD32(a5 + 0x158);  /* 0538 */
  /* 053b: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 053e */
  a10 = 2;  /* 0540 */
  ST32(a1 + 0x1c, a3);  /* 0542 */
  a5 = LD8U(a2 + 0x5);  /* 0544 */
  ST32(a1 + 0x18, a5);  /* 0547 */
  a5 = LD8U(a2 + 0x4);  /* 0549 */
  ST32(a1 + 0x14, a5);  /* 054c */
  a5 = LD8U(a2 + 0x3);  /* 054e */
  ST32(a1 + 0x10, a5);  /* 0551 */
  a5 = LD8U(a2 + 0x2);  /* 0553 */
  ST32(a1 + 0xc, a5);  /* 0556 */
  a5 = LD8U(a2 + 0x1);  /* 0558 */
  ST32(a1 + 0x8, a5);  /* 055b */
  a2 = LD8U(a2 + 0x0);  /* 055d */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0560: -> "mesh" */
  a14 = a11;  /* 0563 */
  ST32(a1 + 0x4, a2);  /* 0565 */
  a2 = 0x48b;  /* 0567 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 056a: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_xon_str1_1 + 0x0);  /* 056d: -> ", restart??" */
  ST32(a1 + 0x0, a2);  /* 0570 */
  __asm__ volatile("" ::: "memory");  /* 0573: memw */
  /* 0576: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_0579: a12 = 0x48d;  /* 0579 */
  L_057c: a11 = a4;  /* 057c */
  a10 = LD32(a1 + 0x34);  /* 057e */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0580: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 0583: callx a8 via reloc-expand */
  goto L_06cc;  /* 0586: j */
  L_0589: a11 = a10;  /* 0589 */
  a12 = LD32(a1 + 0x30);  /* 058b */
  a14 = 0x493;  /* 058d */
  a13 = a4;  /* 0590 */
  a3 = 1;  /* 0592 */
  a10 = LD32(a1 + 0x34);  /* 0594 */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 0596: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0599: callx a8 via reloc-expand */
  L_059c: a4 = 31;  /* 059c */
  a3 = ((i32)a3 < (i32)a4) ? a3 : a4;  /* 059e: min */
  a6 = LD32(a1 + 0x40);  /* 05a1 */
  a3 = a3 & a4;  /* 05a4 */
  a5 = a6 + (18);  /* 05a7 */
  a3 = a3 << 9;  /* 05aa */
  a4 = LD32(a5 + 0x0);  /* 05ad */
  a6 = 0xffffc1ffu;  /* 05af: l32r = -15873 */
  a4 = a4 & a6;  /* 05b2 */
  a3 = a4 | a3;  /* 05b5 */
  a6 = (u32)&g_osi_funcs_p + 0x0;  /* 05b8: l32r -> global */
  ST32(a5 + 0x0, a3);  /* 05bb */
  a3 = LD32(a6 + 0x0);  /* 05bd */
  a10 = LD32(a3 + 0xb8);  /* 05bf */
  __asm__ volatile("" ::: "memory");  /* 05c2: memw */
  /* 05c5: INDIRECT callx a10 <- mem[a3+0xb8]; result unknown */ a2 = 0;
  a4 = 0x057619f1u;  /* 05c8: l32r = 91625969 */
  a10 = (u32)(((u64)a10 * a4) >> 32);  /* 05cb: muluh */
  a10 = a10 >> 5;  /* 05ce */
  a3 = LD32(a5 + 0x0);  /* 05d1 */
  a3 = (a3 >> 5) & 0x3ff;  /* 05d3: extui width 10 */
  if (a10 >= a3) goto L_05e7;  /* 05d6: bgeu a10, a3, 5e7 <esp_mesh_send_xon+0x533> */
  L_05d9: a3 = LD32(a6 + 0x0);  /* 05d9 */
  a10 = LD32(a3 + 0xb8);  /* 05db */
  /* 05de: INDIRECT callx a10 <- mem[a3+0xb8]; result unknown */ a2 = 0;
  a3 = (u32)(((u64)a10 * a4) >> 32);  /* 05e1: muluh */
  a3 = (a3 >> 5) & 0x3f;  /* 05e4: extui width 6 */
  L_05e7: a4 = LD32(a5 + 0x0);  /* 05e7 */
  a3 = a3 << 9;  /* 05e9 */
  a6 = 0xffffc1ffu;  /* 05ec: l32r = -15873 */
  a4 = a4 & a6;  /* 05ef */
  a3 = a4 | a3;  /* 05f2 */
  ST32(a5 + 0x0, a3);  /* 05f5 */
  L_05f8: a8 = LD32(a1 + 0x40);  /* 05f8 */
  a3 = a8 + (14);  /* 05fb */
  a9 = LD32(a1 + 0x48);  /* 05fd */
  a4 = LD32(a1 + 0x30);  /* 0600 */
  ST32(a3 + 0x14, a9);  /* 0602 */
  ST32(a3 + 0x18, a4);  /* 0604 */
  L_0606: a11 = a2;  /* 0606 */
  a12 = 6;  /* 0608 */
  a6 = 1;  /* 060a */
  a7 = -11;  /* 060c */
  a3 = LD32(a1 + 0x40);  /* 060e */
  a10 = a3 + (22);  /* 0611 */
  __asm__ volatile("" ::: "memory");  /* 0614: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0617: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 061a: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 061d */
  a5 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 061f: l32r -> global */
  a10 = a3 + (28);  /* 0622 */
  a11 = a5;  /* 0625 */
  a8 = (u32)&memcpy + 0x0;  /* 0627: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 062a: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 062d */
  a3 = LD32(a1 + 0x40);  /* 062f */
  a11 = a5;  /* 0632 */
  a3 = LD16U(a3 + 0x10);  /* 0634 */
  a3 = a3 + (14);  /* 0637 */
  a4 = LD32(a1 + 0x34);  /* 0639 */
  a10 = a4 + (12);  /* 063b */
  ST16(a4 + 0x4, a3);  /* 063d */
  __asm__ volatile("" ::: "memory");  /* 0640: memw */
  a3 = LD32(a4 + 0x28);  /* 0643 */
  a3 = a3 | a6;  /* 0645 */
  a6 = 2;  /* 0648 */
  a8 = LD32(a1 + 0x4c);  /* 064a */
  ST32(a4 + 0x28, a3);  /* 064d */
  a3 = (u32)&g_mesh_is_root + 0x0;  /* 064f: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0652: memw */
  a3 = LD8U(a3 + 0x0);  /* 0655 */
  a3 = (a3 >> 8) & 0x1;  /* 0658: extui width 1 */
  a3 = a3 << 3;  /* 065b */
  a3 = a3 | a6;  /* 065e */
  a6 = 10;  /* 0661 */
  a3 = a3 & a6;  /* 0663 */
  a6 = LD8U(a4 + 0x28);  /* 0666 */
  a6 = a6 & a7;  /* 0669 */
  a3 = a3 | a6;  /* 066c */
  ST8(a4 + 0x28, a3);  /* 066f */
  a3 = -1;  /* 0672 */
  ST8(a4 + 0x12, a8);  /* 0674 */
  __asm__ volatile("" ::: "memory");  /* 0677: memw */
  ST32(a4 + 0x20, a3);  /* 067a */
  __asm__ volatile("" ::: "memory");  /* 067c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 067f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0682: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0685 */
  a11 = a2;  /* 0687 */
  a10 = a4 + a12;  /* 0689 */
  a8 = (u32)&memcpy + 0x0;  /* 068b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 068e: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0691: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0694 */
  a10 = LD32(a4 + 0x24);  /* 0697 */
  a2 = LD32(a2 + 0xa0);  /* 069a */
  /* 069d: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 06a0: mov */
  a10 = a1 + (52);  /* 06a3 */
  a8 = (u32)&esp_mesh_push_to_tx_queue;  /* 06a6: l32r -> func addr */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 06a9: callx a8 via reloc-expand */
  a3 = a10;  /* 06ac */
  if (a10 == 0) goto L_06cc;  /* 06ae: beqz a10, 6cc <esp_mesh_send_xon+0x618> */
  L_06b1: a11 = (u32)(RODATA__rodata___func___17 + 0x0);  /* 06b1: l32r -> .rodata.__func__$17 */
  a12 = 0x4ce;  /* 06b4 */
  a10 = LD32(a1 + 0x34);  /* 06b7 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 06ba: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 06bd: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_print_txQ_waiting;  /* 06c0: l32r -> func addr */
  a2 = esp_mesh_print_txQ_waiting(a2, a3, a4, a5, a6, a7);  /* 06c3: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_print_rxQ_waiting + 0x0;  /* 06c6: l32r -> global */
  a2 = esp_mesh_print_rxQ_waiting(a2, a3, a4, a5, a6, a7);  /* 06c9: callx a8 via reloc-expand */
  L_06cc: a2 = a3;  /* 06cc */
  return a2;  /* 06ce: retw.n */
}


/* esp_mesh_tx_task_deinit @ mesh_schedule.o 00000018 size 137B bind GLOBAL
 * Calls: esp_mesh_push_to_ps_tx_queue, mesh_tx_task_deinit | indirect[2]: mem[a8+0x70]; mem[a2+0x8c] | Data refs: .bss.is_mesh_tx_started, g_mesh_stop_event_group, .bss.mesh_tx_task, g_osi_funcs_p
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=6); reloc-direct=2, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_tx_task_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  a2 = (u32)&LOCAL__bss_is_mesh_tx_started + 0x0;  /* 001b: l32r -> .bss.is_mesh_tx_started (same-object static) */
  a10 = 15;  /* 001e */
  a2 = LD8U(a2 + 0x0);  /* 0020 */
  ST32(a1 + 0x0, a10);  /* 0023 */
  if (a2 == 0) goto L_009f;  /* 0025: beqz a2, 9f <esp_mesh_tx_task_deinit+0x87> */
  L_0028: a5 = (u32)&g_mesh_stop_event_group + 0x0;  /* 0028: l32r -> global */
  a2 = LD32(a5 + 0x0);  /* 002b */
  if (a2 == 0) goto L_009f;  /* 002d: beqz a2, 9f <esp_mesh_tx_task_deinit+0x87> */
  L_0030: __asm__ volatile("" ::: "memory");  /* 0030: memw */
  a8 = (u32)&esp_mesh_push_to_ps_tx_queue;  /* 0033: l32r -> func addr */
  a2 = esp_mesh_push_to_ps_tx_queue(a2, a3, a4, a5, a6, a7);  /* 0036: callx a8 via reloc-expand */
  a3 = 0;  /* 0039 */
  a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 003b: l32r -> .bss.mesh_tx_task (same-object static) */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 003e: l32r -> global */
  goto L_0056;  /* 0041: j */
  L_0044: a8 = LD32(a4 + 0x0);  /* 0044 */
  a12 = 0;  /* 0046 */
  a11 = a1;  /* 0048 */
  a8 = LD32(a8 + 0x74);  /* 004a */
  a10 = LD32(a2 + 0x0);  /* 004d */
  a2 = esp_mesh_push_to_ps_tx_queue(a2, a3, a4, a5, a6, a7);  /* 004f: callx a8 via literal-trampoline */
  a8 = 15;  /* 0052 */
  ST32(a1 + 0x0, a8);  /* 0054 */
  L_0056: a10 = LD32(a2 + 0x0);  /* 0056 */
  a8 = LD32(a4 + 0x0);  /* 0058 */
  if (a10 != 0) goto L_0070;  /* 005a: bnez.n a10, 70 <esp_mesh_tx_task_deinit+0x58> */
  L_005c: a8 = 0;  /* 005c */
  ST8(a2 + 0xc, a8);  /* 005e */
  __asm__ volatile("" ::: "memory");  /* 0061: memw */
  a2 = a2 + (24);  /* 0064 */
  if (a3 != 1) goto L_0082;  /* 0067: bnei a3, 1, 82 <esp_mesh_tx_task_deinit+0x6a> */
  L_006a: __asm__ volatile("" ::: "memory");  /* 006a: memw */
  goto L_0087;  /* 006d: j */
  L_0070: a8 = LD32(a8 + 0x70);  /* 0070 */
  a12 = 0;  /* 0073 */
  a11 = a1;  /* 0076: mov */
  /* 0079: INDIRECT callx a8 <- mem[a8+0x70]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_0044;  /* 007c: bnei a10, 1, 44 <esp_mesh_tx_task_deinit+0x2c> */
  L_007f: goto L_005c;  /* 007f: j */
  L_0082: a3 = 1;  /* 0082 */
  goto L_0056;  /* 0084: j */
  L_0087: a2 = LD32(a4 + 0x0);  /* 0087 */
  a14 = -1;  /* 0089 */
  a13 = a3;  /* 008b */
  a12 = 0;  /* 008d */
  a11 = 6;  /* 008f */
  a2 = LD32(a2 + 0x8c);  /* 0091 */
  a10 = LD32(a5 + 0x0);  /* 0094 */
  /* 0096: INDIRECT callx a2 <- mem[a2+0x8c]; result unknown */ a2 = 0;
  a8 = (u32)&mesh_tx_task_deinit;  /* 0099: l32r -> func addr */
  a2 = mesh_tx_task_deinit(a2, a3, a4, a5, a6, a7);  /* 009c: callx a8 via reloc-expand */
  L_009f: return a2;  /* 009f: retw.n */
}


/* esp_mesh_tx_task_init @ mesh_schedule.o 0000007c size 445B bind GLOBAL
 * Calls: memset, esp_mesh_create_mbox, mesh_tx_task_deinit | indirect[2]: mem[a7+0x94]; mem[a6+0x94] | Data refs: .bss.is_mesh_tx_started, .bss.mesh_reassign_xseqno, mesh_xon, .bss.mesh_xreq_seqno, mesh_conn_leave, mesh_self_xonseq, .bss.mesh_tx_task, g_mesh_xon_cfg_qsize, .rodata.esp_mesh_tx_task_init, g_mesh_ext_cfg, .bss.mesh_tx_mbox, g_osi_funcs_p +5 more
 * Fidelity: low - jump-table switch present; cases not recovered
 * Edges: funcdb-v3 (calls=3, refs=20); reloc-direct=3, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_tx_task_init(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 007c: entry a1, 32 (frame 32 bytes) */
  a5 = (u32)&LOCAL__bss_is_mesh_tx_started + 0x0;  /* 007f: l32r -> .bss.is_mesh_tx_started (same-object static) */
  a2 = 0;  /* 0082 */
  a3 = LD8U(a5 + 0x0);  /* 0084 */
  if (a3 == a2) goto L_008d;  /* 0087: beq a3, a2, 8d <esp_mesh_tx_task_init+0x11> */
  L_008a: goto L_0237;  /* 008a: j */
  L_008d: a11 = a3;  /* 008d */
  a12 = 16;  /* 008f */
  a2 = (u32)&LOCAL__bss_mesh_reassign_xseqno + 0x0;  /* 0091: l32r -> .bss.mesh_reassign_xseqno (same-object static) */
  a4 = 1;  /* 0094 */
  ST32(a2 + 0x0, a3);  /* 0096 */
  a10 = (u32)&mesh_xon + 0x0;  /* 0098: l32r -> global */
  a2 = (u32)&LOCAL__bss_mesh_xreq_seqno + 0x0;  /* 009b: l32r -> .bss.mesh_xreq_seqno (same-object static) */
  ST32(a2 + 0x0, a3);  /* 009e */
  __asm__ volatile("" ::: "memory");  /* 00a1: memw */
  a8 = (u32)&memset + 0x0;  /* 00a4: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00a7: callx a8 (libc, via reloc-expand) */
  a11 = a3;  /* 00aa */
  a12 = 0x2c8;  /* 00ac */
  a10 = (u32)&mesh_conn_leave + 0x0;  /* 00af: l32r -> global */
  a8 = (u32)&memset + 0x0;  /* 00b2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00b5: callx a8 (libc, via reloc-expand) */
  a11 = a3;  /* 00b8 */
  a12 = 12;  /* 00ba */
  a10 = (u32)&mesh_self_xonseq + 0x0;  /* 00bc: l32r -> global */
  a8 = (u32)&memset + 0x0;  /* 00bf: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00c2: callx a8 (libc, via reloc-expand) */
  a12 = 1;  /* 00c5 */
  a3 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 00c7: l32r -> .bss.mesh_tx_task (same-object static) */
  a10 = a3;  /* 00ca */
  a2 = LD8U(a3 + 0x8);  /* 00cc */
  a2 = a2 | a4;  /* 00cf */
  a6 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 00d2: l32r -> global */
  ST8(a3 + 0x8, a2);  /* 00d5 */
  __asm__ volatile("" ::: "memory");  /* 00d8: memw */
  a2 = LD8U(a3 + 0x20);  /* 00db */
  a2 = a2 | a4;  /* 00de */
  a11 = LD32(a6 + 0x0);  /* 00e1 */
  a11 = a11 + (5);  /* 00e3 */
  ST8(a3 + 0x20, a2);  /* 00e5 */
  __asm__ volatile("" ::: "memory");  /* 00e8: memw */
  __asm__ volatile("" ::: "memory");  /* 00eb: memw */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 00ee: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 00f1: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0110;  /* 00f4: bnez.n a10, 110 <esp_mesh_tx_task_init+0x94> */
  L_00f6: a12 = 1;  /* 00f6 */
  a11 = LD32(a6 + 0x0);  /* 00f8 */
  a11 = a11 + (5);  /* 00fa */
  a10 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 00fc: l32r -> .bss.mesh_tx_task (same-object static) */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 00ff: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 0102: callx a8 via reloc-expand */
  a2 = a10;  /* 0105 */
  if (a10 != 0) goto L_0110;  /* 0107: bnez.n a10, 110 <esp_mesh_tx_task_init+0x94> */
  L_0109: a4 = a10;  /* 0109 */
  a7 = 9;  /* 010b */
  goto L_011c;  /* 010d: j */
  L_0110: a8 = (u32)&mesh_tx_task_deinit;  /* 0110: l32r -> func addr */
  a2 = mesh_tx_task_deinit(a2, a3, a4, a5, a6, a7);  /* 0113: callx a8 via reloc-expand */
  a2 = -1;  /* 0116 */
  goto L_0237;  /* 0118: j */
  L_011c: if (a4 == a7) goto L_0198;  /* 011c: beq a4, a7, 198 <esp_mesh_tx_task_init+0x11c> */
  L_011f: a8 = 13;  /* 011f */
  if (a8 < a4) goto L_0171;  /* 0121: bltu a8, a4, 171 <esp_mesh_tx_task_init+0xf5> */
  L_0124: a8 = (u32)(RODATA__rodata_esp_mesh_tx_task_init + 0x0);  /* 0124: l32r -> .rodata.esp_mesh_tx_task_init */
  a8 = a4 + (a8 << 2);  /* 0127 */
  a8 = LD32(a8 + 0x0);  /* 012a */
  /* 012c: jx a8 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a2 = 1;  /* 012f */
  goto L_0171;  /* 0131: j */
  a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0134: l32r -> global */
  a2 = LD8U(a2 + 0xbd);  /* 0137 */
  a8 = a2 + (16);  /* 013a */
  a9 = LD32(a6 + 0x0);  /* 013d */
  a8 = a8 + a9;  /* 013f */
  a8 = a8 + a8;  /* 0141 */
  a2 = a2 + (a8 << 1);  /* 0143 */
  a2 = a2 + (34);  /* 0146 */
  goto L_0171;  /* 0149: j */
  a2 = LD32(a6 + 0x0);  /* 014c */
  goto L_0171;  /* 014e: j */
  a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0151: l32r -> global */
  a2 = LD8U(a2 + 0xbd);  /* 0154 */
  a2 = a2 + (16);  /* 0157 */
  a2 = a2 + a2;  /* 015a */
  goto L_0171;  /* 015c: j */
  a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0162: l32r -> global */
  a2 = LD8U(a2 + 0xbd);  /* 0165 */
  a2 = a2 + a2;  /* 0168 */
  a2 = a2 + (1);  /* 016a */
  goto L_0171;  /* 016c: j */
  a2 = 32;  /* 016f */
  L_0171: a8 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0171: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a10 = a4 + (a4 << 1);  /* 0174 */
  a10 = a10 + (a8 << 2);  /* 0177 */
  a9 = 1;  /* 017a */
  a12 = 4;  /* 017c */
  a8 = LD8U(a10 + 0x8);  /* 017e */
  a11 = a2;  /* 0181 */
  a8 = a8 | a9;  /* 0183 */
  ST8(a10 + 0x8, a8);  /* 0186 */
  __asm__ volatile("" ::: "memory");  /* 0189: memw */
  __asm__ volatile("" ::: "memory");  /* 018c: memw */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 018f: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 0192: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0110;  /* 0195: bnez a10, 110 <esp_mesh_tx_task_init+0x94> */
  L_0198: a4 = a4 + (1);  /* 0198 */
  a8 = 14;  /* 019a */
  if (a4 == a8) goto L_01a2;  /* 019c: beq a4, a8, 1a2 <esp_mesh_tx_task_init+0x126> */
  L_019f: goto L_011c;  /* 019f: j */
  L_01a2: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 01a2: l32r -> global */
  a2 = 3;  /* 01a5 */
  a4 = 1;  /* 01a7 */
  a2 = a2 << 10;  /* 01a9 */
  a14 = 13;  /* 01ac */
  a7 = LD32(a6 + 0x0);  /* 01ae */
  a13 = 0;  /* 01b0 */
  a12 = a2;  /* 01b2 */
  a7 = LD32(a7 + 0x94);  /* 01b4 */
  a15 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 01b7: l32r -> .bss.mesh_tx_task (same-object static) */
  a11 = (u32)(RODATA__rodata_esp_mesh_tx_task_init_str1_1 + 0x0);  /* 01ba: -> "MTX" */
  a10 = (u32)&mesh_tx_task_main;  /* 01bd: l32r -> func addr */
  ST8(a3 + 0xc, a4);  /* 01c0 */
  __asm__ volatile("" ::: "memory");  /* 01c3: memw */
  __asm__ volatile("" ::: "memory");  /* 01c6: memw */
  /* 01c9: INDIRECT callx a7 <- mem[a7+0x94]; result unknown */ a2 = 0;
  a7 = LD32(a3 + 0x10);  /* 01cc */
  if (a7 == 0) goto L_0110;  /* 01ce: beqz a7, 110 <esp_mesh_tx_task_init+0x94> */
  L_01d1: a12 = a2;  /* 01d1 */
  a14 = 13;  /* 01d3 */
  a6 = LD32(a6 + 0x0);  /* 01d5 */
  a13 = 0;  /* 01d7 */
  a6 = LD32(a6 + 0x94);  /* 01d9 */
  a15 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 01dc: l32r -> .bss.mesh_tx_task (same-object static) */
  a11 = (u32)(RODATA__rodata_esp_mesh_tx_task_init_str1_1 + 0x0);  /* 01df: -> "MTX" */
  a10 = (u32)&mesh_xon_task_main;  /* 01e2: l32r -> func addr */
  ST8(a3 + 0x24, a4);  /* 01e5 */
  __asm__ volatile("" ::: "memory");  /* 01e8: memw */
  __asm__ volatile("" ::: "memory");  /* 01eb: memw */
  /* 01ee: INDIRECT callx a6 <- mem[a6+0x94]; result unknown */ a2 = 0;
  a2 = LD32(a3 + 0x28);  /* 01f1 */
  if (a2 == 0) goto L_0110;  /* 01f3: beqz a2, 110 <esp_mesh_tx_task_init+0x94> */
  L_01f6: a12 = 8;  /* 01f6 */
  a11 = 32;  /* 01f9 */
  a10 = (u32)&LOCAL__bss_mesh_ack_state_mbox + 0x0;  /* 01fc: l32r -> .bss.mesh_ack_state_mbox (same-object static) */
  a2 = LD8U(a10 + 0x8);  /* 01ff */
  a2 = a2 | a4;  /* 0202 */
  ST8(a10 + 0x8, a2);  /* 0205 */
  __asm__ volatile("" ::: "memory");  /* 0208: memw */
  __asm__ volatile("" ::: "memory");  /* 020b: memw */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 020e: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 0211: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0110;  /* 0214: bnez a10, 110 <esp_mesh_tx_task_init+0x94> */
  L_0217: a12 = 16;  /* 0217 */
  a11 = 32;  /* 0219 */
  a10 = (u32)&LOCAL__bss_mesh_new_wnd_mbox + 0x0;  /* 021b: l32r -> .bss.mesh_new_wnd_mbox (same-object static) */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 021e: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 0221: callx a8 via reloc-expand */
  a2 = a10;  /* 0224 */
  if (a10 != 0) goto L_0234;  /* 0226: bnez.n a10, 234 <esp_mesh_tx_task_init+0x1b8> */
  L_0228: ST8(a5 + 0x0, a4);  /* 0228 */
  __asm__ volatile("" ::: "memory");  /* 022b: memw */
  __asm__ volatile("" ::: "memory");  /* 022e: memw */
  goto L_0237;  /* 0231: j */
  L_0234: a2 = 0x00004007u;  /* 0234: l32r = 16391 */
  L_0237: return a2;  /* 0237: retw.n */
}


/* esp_mesh_tx_tid_flush @ mesh_schedule.o 00000044 size 413B bind GLOBAL
 * Calls: memset, mesh_get_tx_pending, esp_mesh_print_txQ_waiting, esp_mesh_print_rxQ_waiting, mesh_flush_txQ | indirect[14]: mem[a3+0x158]; mem[a5+0xb8]; mem[a2+0x78]; mem[a8+0x158] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.esp_mesh_tx_tid_flush.str1.1, .bss.mesh_tx_mbox, g_mesh_is_root
 * Fidelity: medium - 14 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=11); reloc-direct=5, funcdb-attributed=0, unknown-indirect=14 */
u32 esp_mesh_tx_tid_flush(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0044: entry a1, 80 (frame 80 bytes) */
  a12 = 24;  /* 0047 */
  a11 = 0;  /* 0049 */
  a10 = a1 + (16);  /* 004b */
  a8 = (u32)&memset + 0x0;  /* 004e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0051: callx a8 (libc, via reloc-expand) */
  a10 = a1 + (16);  /* 0054 */
  a8 = (u32)&mesh_get_tx_pending;  /* 0057: l32r -> func addr */
  a2 = mesh_get_tx_pending(a2, a3, a4, a5, a6, a7);  /* 005a: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_print_txQ_waiting;  /* 005d: l32r -> func addr */
  a2 = esp_mesh_print_txQ_waiting(a2, a3, a4, a5, a6, a7);  /* 0060: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_print_rxQ_waiting + 0x0;  /* 0063: l32r -> global */
  a2 = esp_mesh_print_rxQ_waiting(a2, a3, a4, a5, a6, a7);  /* 0066: callx a8 via reloc-expand */
  a2 = LD32(a1 + 0x24);  /* 0069 */
  if (a2 == 0) goto L_00bd;  /* 006b: beqz a2, bd <esp_mesh_tx_tid_flush+0x79> */
  L_006e: a11 = a2;  /* 006e */
  a10 = 8;  /* 0070 */
  a8 = (u32)&mesh_flush_txQ;  /* 0073: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 0076: callx a8 via reloc-expand */
  a3 = (u32)&g_log_level + 0x0;  /* 0079: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 007c */
  if (a3 >= 3u) goto L_0085;  /* 007f: bgeui a3, 3, 85 <esp_mesh_tx_tid_flush+0x41> */
  L_0082: goto L_0119;  /* 0082: j */
  L_0085: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0085: l32r -> global */
  a3 = LD32(a5 + 0x0);  /* 0088 */
  if (a3 == 0) goto L_0119;  /* 008b: beqz a3, 119 <esp_mesh_tx_tid_flush+0xd5> */
  L_008e: a4 = LD32(a3 + 0x150);  /* 008e */
  if (a4 == 0) goto L_0119;  /* 0091: beqz a4, 119 <esp_mesh_tx_tid_flush+0xd5> */
  L_0094: a10 = LD32(a3 + 0x158);  /* 0094 */
  /* 0097: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 009a */
  a5 = LD32(a5 + 0x0);  /* 009c */
  a10 = LD32(a5 + 0xb8);  /* 009e */
  /* 00a1: INDIRECT callx a10 <- mem[a5+0xb8]; result unknown */ a2 = 0;
  a15 = 0x768;  /* 00a4 */
  a13 = a3;  /* 00a7 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00a9: -> "mesh" */
  a14 = a11;  /* 00ac */
  a12 = (u32)(RODATA__rodata_esp_mesh_tx_tid_flush_str1_1 + 0x0);  /* 00ae: l32r -> .rodata.esp_mesh_tx_tid_flush.str1.1 */
  ST32(a1 + 0x4, a10);  /* 00b1 */
  ST32(a1 + 0x0, a2);  /* 00b3 */
  __asm__ volatile("" ::: "memory");  /* 00b5: memw */
  goto L_0111;  /* 00b8: j */
  L_00bd: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00bd: l32r -> global */
  a4 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 00c0: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a2 = LD32(a3 + 0x0);  /* 00c3 */
  a10 = LD32(a4 + 0xc);  /* 00c5 */
  a2 = LD32(a2 + 0x78);  /* 00c8 */
  /* 00cb: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a2 = a10;  /* 00ce */
  if ((i32)a10 < 1) goto L_0119;  /* 00d0: blti a10, 1, 119 <esp_mesh_tx_tid_flush+0xd5> */
  L_00d3: a11 = a10;  /* 00d3 */
  a10 = 1;  /* 00d5 */
  a8 = (u32)&mesh_flush_txQ;  /* 00d7: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 00da: callx a8 via reloc-expand */
  a4 = (u32)&g_log_level + 0x0;  /* 00dd: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 00e0 */
  if (a4 < 3u) goto L_0119;  /* 00e2: bltui a4, 3, 119 <esp_mesh_tx_tid_flush+0xd5> */
  L_00e5: a8 = LD32(a3 + 0x0);  /* 00e5 */
  if (a8 == 0) goto L_0119;  /* 00e8: beqz.n a8, 119 <esp_mesh_tx_tid_flush+0xd5> */
  L_00ea: a4 = LD32(a8 + 0x150);  /* 00ea */
  if (a4 == 0) goto L_0119;  /* 00ed: beqz a4, 119 <esp_mesh_tx_tid_flush+0xd5> */
  L_00f0: a10 = LD32(a8 + 0x158);  /* 00f0 */
  /* 00f3: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 00f6 */
  a3 = LD32(a3 + 0x0);  /* 00f8 */
  a10 = LD32(a3 + 0xb8);  /* 00fa */
  /* 00fd: INDIRECT callx a10 <- mem[a3+0xb8]; result unknown */ a2 = 0;
  a15 = 0x76e;  /* 0100 */
  a13 = a5;  /* 0103 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0105: -> "mesh" */
  a14 = a11;  /* 0108 */
  a12 = (u32)(RODATA__rodata_esp_mesh_tx_tid_flush_str1_1 + 0x0);  /* 010a: l32r -> .rodata.esp_mesh_tx_tid_flush.str1.1 */
  ST32(a1 + 0x4, a10);  /* 010d */
  ST32(a1 + 0x0, a2);  /* 010f */
  L_0111: a10 = 3;  /* 0111 */
  __asm__ volatile("" ::: "memory");  /* 0113: memw */
  /* 0116: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0119: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0119: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 011c: memw */
  a2 = LD8U(a2 + 0x0);  /* 011f */
  a2 = (a2 >> 8) & 0x1;  /* 0122: extui width 1 */
  if (a2 == 0) goto L_01dd;  /* 0125: beqz a2, 1dd <esp_mesh_tx_tid_flush+0x199> */
  L_0128: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0128: l32r -> global */
  a4 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 012b: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a3 = LD32(a2 + 0x0);  /* 012e */
  a10 = LD32(a4 + 0xc);  /* 0131 */
  a3 = LD32(a3 + 0x78);  /* 0134 */
  /* 0137: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a3 = a10;  /* 013a */
  if (a10 == 0) goto L_0186;  /* 013c: beqz a10, 186 <esp_mesh_tx_tid_flush+0x142> */
  L_013f: a11 = a10;  /* 013f */
  a10 = 1;  /* 0141 */
  a8 = (u32)&mesh_flush_txQ;  /* 0143: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 0146: callx a8 via reloc-expand */
  a5 = (u32)&g_log_level + 0x0;  /* 0149: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 014c */
  if (a5 < 3u) goto L_0186;  /* 014e: bltui a5, 3, 186 <esp_mesh_tx_tid_flush+0x142> */
  L_0151: a8 = LD32(a2 + 0x0);  /* 0151 */
  if (a8 == 0) goto L_0186;  /* 0154: beqz.n a8, 186 <esp_mesh_tx_tid_flush+0x142> */
  L_0156: a5 = LD32(a8 + 0x150);  /* 0156 */
  if (a5 == 0) goto L_0186;  /* 0159: beqz a5, 186 <esp_mesh_tx_tid_flush+0x142> */
  L_015c: a10 = LD32(a8 + 0x158);  /* 015c */
  /* 015f: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a6 = a10;  /* 0162 */
  a8 = LD32(a2 + 0x0);  /* 0164 */
  a10 = LD32(a8 + 0xb8);  /* 0166 */
  /* 0169: INDIRECT callx a10 <- mem[a8+0xb8]; result unknown */ a2 = 0;
  a15 = 0x777;  /* 016c */
  a13 = a6;  /* 016f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0171: -> "mesh" */
  a14 = a11;  /* 0174 */
  a12 = (u32)(RODATA__rodata_esp_mesh_tx_tid_flush_str1_1 + 0x0);  /* 0176: l32r -> .rodata.esp_mesh_tx_tid_flush.str1.1 */
  ST32(a1 + 0x4, a10);  /* 0179 */
  a10 = 3;  /* 017b */
  ST32(a1 + 0x0, a3);  /* 017d */
  __asm__ volatile("" ::: "memory");  /* 0180: memw */
  /* 0183: INDIRECT callx a5 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0186: a3 = LD32(a2 + 0x0);  /* 0186 */
  a10 = LD32(a4 + 0x3c);  /* 0188 */
  a3 = LD32(a3 + 0x78);  /* 018b */
  /* 018e: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a3 = a10;  /* 0191 */
  if (a10 == 0) goto L_01dd;  /* 0193: beqz a10, 1dd <esp_mesh_tx_tid_flush+0x199> */
  L_0196: a11 = a10;  /* 0196 */
  a10 = 5;  /* 0198 */
  a8 = (u32)&mesh_flush_txQ;  /* 019b: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 019e: callx a8 via reloc-expand */
  a4 = (u32)&g_log_level + 0x0;  /* 01a1: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 01a4 */
  if (a4 < 3u) goto L_01dd;  /* 01a6: bltui a4, 3, 1dd <esp_mesh_tx_tid_flush+0x199> */
  L_01a9: a8 = LD32(a2 + 0x0);  /* 01a9 */
  if (a8 == 0) goto L_01dd;  /* 01ac: beqz.n a8, 1dd <esp_mesh_tx_tid_flush+0x199> */
  L_01ae: a4 = LD32(a8 + 0x150);  /* 01ae */
  if (a4 == 0) goto L_01dd;  /* 01b1: beqz a4, 1dd <esp_mesh_tx_tid_flush+0x199> */
  L_01b4: a10 = LD32(a8 + 0x158);  /* 01b4 */
  /* 01b7: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 01ba */
  a2 = LD32(a2 + 0x0);  /* 01bc */
  a10 = LD32(a2 + 0xb8);  /* 01be */
  /* 01c1: INDIRECT callx a10 <- mem[a2+0xb8]; result unknown */ a2 = 0;
  a15 = 0x77d;  /* 01c4 */
  a13 = a5;  /* 01c7 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 01c9: -> "mesh" */
  a14 = a11;  /* 01cc */
  a12 = (u32)(RODATA__rodata_esp_mesh_tx_tid_flush_str1_1 + 0x0);  /* 01ce: l32r -> .rodata.esp_mesh_tx_tid_flush.str1.1 */
  ST32(a1 + 0x4, a10);  /* 01d1 */
  a10 = 3;  /* 01d3 */
  ST32(a1 + 0x0, a3);  /* 01d5 */
  __asm__ volatile("" ::: "memory");  /* 01d7: memw */
  /* 01da: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_01dd: a2 = 0;  /* 01dd */
  return a2;  /* 01df: retw.n */
}


/* esp_mesh_txupQ_pending @ mesh_schedule.o 000000e0 size 2910B bind GLOBAL
 * Calls: esp_mesh_match_self, memcmp, txq_opr2str, mesh_mutex_lock, mesh_mutex_unlock, esp_mesh_get_child_idx, esp_mesh_txupQ_pending_get_cidx | indirect[31]: mem[a3+0x158]; mem[a3+0x150]; mem[a5+0x158]; unknown | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, g_mesh_current_parent, .rodata.esp_mesh_txupQ_pending.str1.1, mesh_self_xonseq, .rodata.esp_mesh_send_block_event.str1.1, .bss.mesh_tx_task, .rodata.__func__$13, mesh_conn_mutex +2 more
 * Fidelity: low - large state machine / jump-table switch; goto skeleton preserves flow, some blocks summarized
 * Edges: funcdb-v3 (calls=7, refs=21); reloc-direct=7, funcdb-attributed=0, unknown-indirect=31 */
u32 esp_mesh_txupQ_pending(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a04, a10, a11, a12, a13, a14, a15, a65, a7, a8, a84, a9;
  float F0000001;
  /* 00e0: entry a1, 192 (frame 192 bytes) */
  a7 = a2;  /* 00e3 */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 00e5: l32r -> global */
  ST32(a1 + 0x60, a4);  /* 00e8 */
  a4 = LD8U(a2 + 0x0);  /* 00eb */
  ST32(a1 + 0x7c, a5);  /* 00ee */
  ST32(a1 + 0x80, a6);  /* 00f1 */
  a2 = 0x00004004u;  /* 00f4: l32r = 16388 */
  if (a4 != 0) goto L_00fc;  /* 00f7: bnez.n a4, fc <esp_mesh_txupQ_pending+0x1c> */
  L_00f9: goto L_0c3c;  /* 00f9: j */
  L_00fc: if (a7 != 0) goto L_0132;  /* 00fc: bnez.n a7, 132 <esp_mesh_txupQ_pending+0x52> */
  L_00fe: a2 = (u32)&g_log_level + 0x0;  /* 00fe: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0101 */
  a2 = 0x00004008u;  /* 0104: l32r = 16392 */
  if (a3 >= 3u) goto L_010d;  /* 0107: bgeui a3, 3, 10d <esp_mesh_txupQ_pending+0x2d> */
  L_010a: goto L_0c3c;  /* 010a: j */
  L_010d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 010d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0110 */
  if (a3 != 0) goto L_0118;  /* 0113: bnez.n a3, 118 <esp_mesh_txupQ_pending+0x38> */
  L_0115: goto L_0c3c;  /* 0115: j */
  L_0118: a4 = LD32(a3 + 0x150);  /* 0118 */
  if (a4 != 0) goto L_0120;  /* 011b: bnez.n a4, 120 <esp_mesh_txupQ_pending+0x40> */
  L_011d: goto L_0c3c;  /* 011d: j */
  L_0120: a10 = LD32(a3 + 0x158);  /* 0120 */
  a3 = 0x5f9;  /* 0123 */
  __asm__ volatile("" ::: "memory");  /* 0126: memw */
  /* 0129: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 012c: -> "mesh" */
  goto L_016b;  /* 012f: j */
  L_0132: a2 = LD32(a7 + 0x0);  /* 0132 */
  ST32(a1 + 0x68, a2);  /* 0134 */
  if (a2 != 0) goto L_0184;  /* 0137: bnez a2, 184 <esp_mesh_txupQ_pending+0xa4> */
  L_013a: a2 = (u32)&g_log_level + 0x0;  /* 013a: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 013d */
  a2 = 0x00004008u;  /* 0140: l32r = 16392 */
  if (a3 >= 3u) goto L_0149;  /* 0143: bgeui a3, 3, 149 <esp_mesh_txupQ_pending+0x69> */
  L_0146: goto L_0c3c;  /* 0146: j */
  L_0149: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0149: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 014c */
  if (a3 != 0) goto L_0154;  /* 014f: bnez.n a3, 154 <esp_mesh_txupQ_pending+0x74> */
  L_0151: goto L_0c3c;  /* 0151: j */
  L_0154: a4 = LD32(a3 + 0x150);  /* 0154 */
  if (a4 != 0) goto L_015c;  /* 0157: bnez.n a4, 15c <esp_mesh_txupQ_pending+0x7c> */
  L_0159: goto L_0c3c;  /* 0159: j */
  L_015c: a10 = LD32(a3 + 0x158);  /* 015c */
  a3 = 0x5fa;  /* 015f */
  __asm__ volatile("" ::: "memory");  /* 0162: memw */
  /* 0165: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0168: -> "mesh" */
  L_016b: a13 = a10;  /* 016b */
  a14 = a11;  /* 016d */
  a10 = 3;  /* 016f */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0171: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0174: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 0177 */
  __asm__ volatile("" ::: "memory");  /* 017a: memw */
  /* 017d: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0c3c;  /* 0180: j */
  L_0184: a4 = a7 + (12);  /* 0184 */
  a10 = a4;  /* 0186 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0188: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6);  /* 018b: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01a0;  /* 018e: bnez.n a10, 1a0 <esp_mesh_txupQ_pending+0xc0> */
  L_0190: a11 = (u32)&g_mesh_current_parent + 0x0;  /* 0190: l32r -> global */
  a12 = 6;  /* 0193 */
  a10 = a4;  /* 0195 */
  a8 = (u32)&memcmp + 0x0;  /* 0197: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 019a: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0585;  /* 019d: bnez a10, 585 <esp_mesh_txupQ_pending+0x4a5> */
  L_01a0: a5 = a3 + (-2);  /* 01a0 */
  a2 = 0;  /* 01a3 */
  if (a5 >= 2u) goto L_01ab;  /* 01a5: bgeui a5, 2, 1ab <esp_mesh_txupQ_pending+0xcb> */
  L_01a8: goto L_0c3c;  /* 01a8: j */
  L_01ab: a8 = LD32(a1 + 0x60);  /* 01ab */
  if (a8 == a2) goto L_01c5;  /* 01ae: beq a8, a2, 1c5 <esp_mesh_txupQ_pending+0xe5> */
  L_01b1: a2 = 0x0fffffffu;  /* 01b1: l32r = 268435455 */
  if (a8 == a2) goto L_01ba;  /* 01b4: beq a8, a2, 1ba <esp_mesh_txupQ_pending+0xda> */
  L_01b7: goto L_02e4;  /* 01b7: j */
  L_01ba: a5 = 96;  /* 01ba */
  a2 = LD32(a7 + 0x28);  /* 01bd */
  if ((a5 & a2) != 0) goto L_01c5;  /* 01bf: bany a5, a2, 1c5 <esp_mesh_txupQ_pending+0xe5> */
  L_01c2: goto L_02e4;  /* 01c2: j */
  L_01c5: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01c5: l32r -> global */
  a5 = LD32(a2 + 0x0);  /* 01c8 */
  if (a5 == 0) goto L_02b8;  /* 01cb: beqz a5, 2b8 <esp_mesh_txupQ_pending+0x1d8> */
  L_01ce: a2 = LD32(a5 + 0x150);  /* 01ce */
  if (a2 == 0) goto L_02b8;  /* 01d1: beqz a2, 2b8 <esp_mesh_txupQ_pending+0x1d8> */
  L_01d4: a10 = LD32(a5 + 0x158);  /* 01d4 */
  /* 01d7: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 01da */
  a10 = a4;  /* 01dc: mov */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 01df: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6);  /* 01e2: callx a8 via reloc-expand */
  a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 01e5: -> "self" */
  if (a10 != 0) goto L_01ee;  /* 01e8: bnez a10, 1ee <esp_mesh_txupQ_pending+0x10e> */
  L_01eb: a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 01eb: -> "self" */
  L_01ee: a10 = a3;  /* 01ee */
  a9 = LD8U(a7 + 0xc);  /* 01f0 */
  a11 = LD8U(a7 + 0xd);  /* 01f3 */
  a12 = LD8U(a7 + 0xe);  /* 01f6 */
  a8 = LD8U(a7 + 0x10);  /* 01f9 */
  a15 = LD8U(a7 + 0xf);  /* 01fc */
  ST32(a1 + 0x68, a9);  /* 01ff */
  a9 = LD8U(a7 + 0x11);  /* 0202 */
  ST32(a1 + 0x6c, a11);  /* 0205 */
  ST32(a1 + 0x64, a12);  /* 0208 */
  ST32(a1 + 0x74, a8);  /* 020b */
  ST32(a1 + 0x70, a15);  /* 020e */
  ST32(a1 + 0x78, a9);  /* 0211 */
  __asm__ volatile("" ::: "memory");  /* 0214: memw */
  a8 = (u32)&txq_opr2str + 0x0;  /* 0217: l32r -> global */
  a2 = txq_opr2str(a2, a3, a4, a5, a6);  /* 021a: callx a8 via reloc-expand */
  a8 = (u32)&mesh_self_xonseq + 0x0;  /* 021d: l32r -> global */
  a11 = LD8U(a8 + 0x8);  /* 0220 */
  a12 = LD32(a8 + 0x0);  /* 0223 */
  ST32(a1 + 0x84, a11);  /* 0225 */
  a11 = LD32(a7 + 0x28);  /* 0228 */
  ST32(a1 + 0x88, a12);  /* 022a */
  a13 = LD32(a8 + 0x4);  /* 022d */
  a14 = LD16U(a7 + 0x4);  /* 0230 */
  a8 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0233: -> "self" */
  if (((a11 >> 5) & 1) != 0) goto L_023c;  /* 0236: bbsi a11, 5, 23c <esp_mesh_txupQ_pending+0x15c> */
  L_0239: a8 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0239: -> "no window" */
  L_023c: a9 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 023c: -> "self" */
  if (((a11 >> 6) & 1) != 0) goto L_0245;  /* 023f: bbsi a11, 6, 245 <esp_mesh_txupQ_pending+0x165> */
  L_0242: a9 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0242: -> "no window" */
  L_0245: a15 = LD32(a1 + 0x60);  /* 0245 */
  a11 = 0x0fffffffu;  /* 0248: l32r = 268435455 */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 024b: -> "self" */
  if (a15 == a11) goto L_0254;  /* 024e: beq a15, a11, 254 <esp_mesh_txupQ_pending+0x174> */
  L_0251: a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0251: -> "no window" */
  L_0254: ST32(a1 + 0x40, a8);  /* 0254 */
  a8 = LD32(a1 + 0x60);  /* 0257 */
  ST32(a1 + 0x44, a9);  /* 025a */
  ST32(a1 + 0x38, a8);  /* 025d */
  a9 = LD32(a1 + 0x88);  /* 025f */
  a8 = LD32(a1 + 0x74);  /* 0262 */
  a15 = LD32(a1 + 0x78);  /* 0265 */
  ST32(a1 + 0x48, a12);  /* 0268 */
  ST32(a1 + 0x30, a9);  /* 026b */
  a12 = LD32(a1 + 0x84);  /* 026d */
  a9 = LD32(a1 + 0x70);  /* 0270 */
  ST32(a1 + 0x20, a8);  /* 0273 */
  a8 = LD32(a1 + 0x68);  /* 0275 */
  ST32(a1 + 0x2c, a12);  /* 0278 */
  ST32(a1 + 0x24, a15);  /* 027a */
  a12 = LD32(a1 + 0x64);  /* 027c */
  a15 = LD32(a1 + 0x6c);  /* 027f */
  ST32(a1 + 0x1c, a9);  /* 0282 */
  ST32(a1 + 0x10, a8);  /* 0284 */
  a9 = LD32(a1 + 0x80);  /* 0286 */
  a8 = LD32(a1 + 0x7c);  /* 0289 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 028c: -> "mesh" */
  ST32(a1 + 0xc, a6);  /* 028f */
  a6 = 0x615;  /* 0291 */
  ST32(a1 + 0x3c, a14);  /* 0294 */
  a14 = a11;  /* 0296 */
  ST32(a1 + 0x34, a13);  /* 0298 */
  a13 = a5;  /* 029a */
  ST32(a1 + 0x28, a10);  /* 029c */
  a10 = 1;  /* 029e */
  ST32(a1 + 0x14, a15);  /* 02a0 */
  ST32(a1 + 0x18, a12);  /* 02a2 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 02a4: -> "mesh_schedule.c" */
  ST32(a1 + 0x8, a9);  /* 02a7 */
  ST32(a1 + 0x4, a8);  /* 02aa */
  ST32(a1 + 0x0, a6);  /* 02ac */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 02af: -> "self" */
  __asm__ volatile("" ::: "memory");  /* 02b2: memw */
  /* 02b5: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  L_02b8: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 02b8: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 02bb */
  if (a2 == 0) goto L_02e4;  /* 02bd: beqz.n a2, 2e4 <esp_mesh_txupQ_pending+0x204> */
  L_02bf: a5 = LD32(a2 + 0x150);  /* 02bf */
  if (a5 == 0) goto L_02e4;  /* 02c2: beqz.n a5, 2e4 <esp_mesh_txupQ_pending+0x204> */
  L_02c4: a10 = LD32(a2 + 0x158);  /* 02c4 */
  a2 = 0x620;  /* 02c7 */
  /* 02ca: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02cd */
  a10 = 1;  /* 02cf */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 02d1: -> "mesh" */
  a14 = a11;  /* 02d4 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 02d6: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 02d9: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 02dc */
  __asm__ volatile("" ::: "memory");  /* 02de: memw */
  /* 02e1: INDIRECT callx a5 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_02e4: if (a3 != 0) goto L_041d;  /* 02e4: bnez a3, 41d <esp_mesh_txupQ_pending+0x33d> */
  L_02e7: a5 = a3;  /* 02e7 */
  a2 = (u32)&mesh_self_xonseq + 0x0;  /* 02e9: l32r -> global */
  a6 = LD8U(a2 + 0x8);  /* 02ec */
  a2 = 1;  /* 02ef */
  if (a6 == 0) a5 = a2;  /* 02f1 */
  a5 = (a5 >> 8) & 0x1;  /* 02f4: extui width 1 */
  if (a5 == 0) goto L_041d;  /* 02f7: beqz a5, 41d <esp_mesh_txupQ_pending+0x33d> */
  L_02fa: a5 = 0xf0000001u;  /* 02fa: l32r = -268435455 */
  a9 = LD32(a1 + 0x60);  /* 02fd */
  a5 = a9 + a5;  /* 0300 */
  if (a5 == 0) a2 = a3;  /* 0302 */
  a2 = (a2 >> 8) & 0x1;  /* 0305: extui width 1 */
  if (a2 == 0) goto L_041d;  /* 0308: beqz a2, 41d <esp_mesh_txupQ_pending+0x33d> */
  L_030b: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 030b: l32r -> global */
  a5 = LD32(a2 + 0x0);  /* 030e */
  if (a5 != 0) goto L_0320;  /* 0311: bnez a5, 320 <esp_mesh_txupQ_pending+0x240> */
  L_0314: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0314: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0317 */
  if (a2 != 0) goto L_03f8;  /* 0319: bnez a2, 3f8 <esp_mesh_txupQ_pending+0x318> */
  L_031c: goto L_041d;  /* 031c: j */
  L_0320: a2 = LD32(a5 + 0x150);  /* 0320 */
  if (a2 == 0) goto L_0314;  /* 0323: beqz a2, 314 <esp_mesh_txupQ_pending+0x234> */
  L_0326: a10 = LD32(a5 + 0x158);  /* 0326 */
  /* 0329: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 032c: mov */
  a10 = a4;  /* 032f: mov */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0332: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6);  /* 0335: callx a8 via reloc-expand */
  a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0338: -> "self" */
  if (a10 != 0) goto L_0341;  /* 033b: bnez a10, 341 <esp_mesh_txupQ_pending+0x261> */
  L_033e: a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 033e: -> "self" */
  L_0341: a10 = 0;  /* 0341 */
  a11 = LD8U(a7 + 0xc);  /* 0343 */
  a12 = LD8U(a7 + 0xd);  /* 0346 */
  a15 = LD8U(a7 + 0xe);  /* 0349 */
  a8 = LD8U(a7 + 0xf);  /* 034c */
  a9 = LD8U(a7 + 0x10);  /* 034f */
  ST32(a1 + 0x68, a11);  /* 0352 */
  a11 = LD8U(a7 + 0x11);  /* 0355 */
  ST32(a1 + 0x6c, a12);  /* 0358 */
  ST32(a1 + 0x64, a15);  /* 035b */
  ST32(a1 + 0x70, a8);  /* 035e */
  ST32(a1 + 0x78, a11);  /* 0361 */
  ST32(a1 + 0x74, a9);  /* 0364 */
  __asm__ volatile("" ::: "memory");  /* 0367: memw */
  a8 = (u32)&txq_opr2str + 0x0;  /* 036a: l32r -> global */
  a2 = txq_opr2str(a2, a3, a4, a5, a6);  /* 036d: callx a8 via reloc-expand */
  a8 = (u32)&mesh_self_xonseq + 0x0;  /* 0370: l32r -> global */
  a11 = LD32(a7 + 0x28);  /* 0373 */
  a15 = LD8U(a8 + 0x8);  /* 0375 */
  a12 = LD32(a8 + 0x0);  /* 0378 */
  a13 = LD32(a8 + 0x4);  /* 037a */
  a14 = LD16U(a7 + 0x4);  /* 037c */
  a8 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 037f: -> "self" */
  if (((a11 >> 5) & 1) != 0) goto L_0388;  /* 0382: bbsi a11, 5, 388 <esp_mesh_txupQ_pending+0x2a8> */
  L_0385: a8 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0385: -> "no window" */
  L_0388: a9 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0388: -> "self" */
  if (((a11 >> 6) & 1) != 0) goto L_0391;  /* 038b: bbsi a11, 6, 391 <esp_mesh_txupQ_pending+0x2b1> */
  L_038e: a9 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 038e: -> "no window" */
  L_0391: ST32(a1 + 0x40, a8);  /* 0391 */
  a8 = LD32(a1 + 0x60);  /* 0394 */
  ST32(a1 + 0x30, a12);  /* 0397 */
  a12 = LD32(a1 + 0x74);  /* 0399 */
  ST32(a1 + 0x44, a9);  /* 039c */
  ST32(a1 + 0x38, a8);  /* 039f */
  a9 = LD32(a1 + 0x78);  /* 03a1 */
  a8 = LD32(a1 + 0x64);  /* 03a4 */
  ST32(a1 + 0x2c, a15);  /* 03a7 */
  ST32(a1 + 0x20, a12);  /* 03a9 */
  a15 = LD32(a1 + 0x70);  /* 03ab */
  a12 = LD32(a1 + 0x68);  /* 03ae */
  ST32(a1 + 0xc, a6);  /* 03b1 */
  a6 = LD32(a1 + 0x80);  /* 03b3 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 03b6: -> "mesh" */
  ST32(a1 + 0x24, a9);  /* 03b9 */
  ST32(a1 + 0x18, a8);  /* 03bb */
  a9 = LD32(a1 + 0x6c);  /* 03bd */
  a8 = LD32(a1 + 0x7c);  /* 03c0 */
  ST32(a1 + 0x1c, a15);  /* 03c3 */
  ST32(a1 + 0x10, a12);  /* 03c5 */
  ST32(a1 + 0x8, a6);  /* 03c7 */
  a6 = 0x629;  /* 03c9 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 03cc: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 03cf: -> "self" */
  ST32(a1 + 0x3c, a14);  /* 03d2 */
  a14 = a11;  /* 03d4 */
  ST32(a1 + 0x34, a13);  /* 03d6 */
  a13 = a5;  /* 03d8 */
  ST32(a1 + 0x28, a10);  /* 03da */
  a10 = 1;  /* 03dc */
  ST32(a1 + 0x14, a9);  /* 03de */
  ST32(a1 + 0x4, a8);  /* 03e0 */
  ST32(a1 + 0x0, a6);  /* 03e3 */
  __asm__ volatile("" ::: "memory");  /* 03e6: memw */
  /* 03e9: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  a2 = (u32)&mesh_self_xonseq + 0x0;  /* 03ec: l32r -> global */
  a2 = LD8U(a2 + 0x8);  /* 03ef */
  if (a2 != 0) goto L_041d;  /* 03f2: bnez.n a2, 41d <esp_mesh_txupQ_pending+0x33d> */
  L_03f4: goto L_0314;  /* 03f4: j */
  L_03f8: a5 = LD32(a2 + 0x150);  /* 03f8 */
  if (a5 == 0) goto L_041d;  /* 03fb: beqz.n a5, 41d <esp_mesh_txupQ_pending+0x33d> */
  L_03fd: a10 = LD32(a2 + 0x158);  /* 03fd */
  a2 = 0x630;  /* 0400 */
  /* 0403: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0406 */
  a10 = 1;  /* 0408 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 040a: -> "mesh" */
  a14 = a11;  /* 040d */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 040f: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0412: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 0415 */
  __asm__ volatile("" ::: "memory");  /* 0417: memw */
  /* 041a: INDIRECT callx a5 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_041d: a12 = 0x633;  /* 041d */
  a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0420: l32r -> .bss.mesh_tx_task (same-object static) */
  a5 = (u32)(RODATA__rodata___func___13 + 0x0);  /* 0423: l32r -> .rodata.__func__$13 */
  a11 = a5;  /* 0426 */
  a10 = LD32(a2 + 0x1c);  /* 0428 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 042b: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6);  /* 042e: callx a8 via reloc-expand */
  if (a3 != 1) goto L_04ab;  /* 0431: bnei a3, 1, 4ab <esp_mesh_txupQ_pending+0x3cb> */
  L_0434: a10 = LD32(a2 + 0x1c);  /* 0434 */
  a2 = (u32)&mesh_self_xonseq + 0x0;  /* 0436: l32r -> global */
  a9 = LD32(a1 + 0x60);  /* 0439 */
  a4 = LD32(a2 + 0x0);  /* 043c */
  if (a4 < a9) goto L_048c;  /* 043e: bltu a4, a9, 48c <esp_mesh_txupQ_pending+0x3ac> */
  L_0441: a12 = 0x643;  /* 0441 */
  a11 = a5;  /* 0444 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0446: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6);  /* 0449: callx a8 via reloc-expand */
  a2 = LD32(a2 + 0x0);  /* 044c */
  a4 = LD32(a1 + 0x60);  /* 044e */
  if (a2 >= a4) goto L_0458;  /* 0451: bgeu a2, a4, 458 <esp_mesh_txupQ_pending+0x378> */
  L_0454: goto L_0484;  /* 0454: j */
  L_0458: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0458: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 045b */
  if (a2 == 0) goto L_0484;  /* 045d: beqz.n a2, 484 <esp_mesh_txupQ_pending+0x3a4> */
  L_045f: a4 = LD32(a2 + 0x150);  /* 045f */
  if (a4 == 0) goto L_0484;  /* 0462: beqz.n a4, 484 <esp_mesh_txupQ_pending+0x3a4> */
  L_0464: a10 = LD32(a2 + 0x158);  /* 0464 */
  a2 = 0x644;  /* 0467 */
  /* 046a: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 046d */
  a10 = a3;  /* 046f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0471: -> "mesh" */
  a14 = a11;  /* 0474 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0476: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0479: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 047c */
  __asm__ volatile("" ::: "memory");  /* 047e: memw */
  /* 0481: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0484: a2 = 0x00004014u;  /* 0484: l32r = 16404 */
  goto L_0c3c;  /* 0487: j */
  L_048c: a3 = LD8U(a2 + 0x8);  /* 048c */
  a3 = a3 + (1);  /* 048f */
  a8 = LD32(a1 + 0x60);  /* 0491 */
  ST8(a2 + 0x8, a3);  /* 0494 */
  __asm__ volatile("" ::: "memory");  /* 0497: memw */
  a3 = 32;  /* 049a */
  ST32(a2 + 0x0, a8);  /* 049c */
  a2 = LD32(a7 + 0x28);  /* 049e */
  a2 = a2 | a3;  /* 04a0 */
  ST32(a7 + 0x28, a2);  /* 04a3 */
  __asm__ volatile("" ::: "memory");  /* 04a5: memw */
  goto L_0575;  /* 04a8: j */
  L_04ab: if (a3 != 0) goto L_04cd;  /* 04ab: bnez.n a3, 4cd <esp_mesh_txupQ_pending+0x3ed> */
  L_04ad: a2 = LD32(a7 + 0x28);  /* 04ad */
  if (((a2 >> 5) & 1) == 0) goto L_04cd;  /* 04af: bbci a2, 5, 4cd <esp_mesh_txupQ_pending+0x3ed> */
  L_04b2: a2 = (u32)&mesh_self_xonseq + 0x0;  /* 04b2: l32r -> global */
  a3 = LD8U(a2 + 0x8);  /* 04b5 */
  a3 = a3 + (-1);  /* 04b8 */
  a9 = LD32(a1 + 0x60);  /* 04ba */
  ST8(a2 + 0x8, a3);  /* 04bd */
  __asm__ volatile("" ::: "memory");  /* 04c0: memw */
  ST32(a2 + 0x4, a9);  /* 04c3 */
  __asm__ volatile("" ::: "memory");  /* 04c5: memw */
  goto L_0575;  /* 04c8: j */
  L_04cd: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 04cd: l32r -> global */
  a5 = LD32(a2 + 0x0);  /* 04d0 */
  if (a5 == 0) goto L_0575;  /* 04d3: beqz a5, 575 <esp_mesh_txupQ_pending+0x495> */
  L_04d6: a2 = LD32(a5 + 0x150);  /* 04d6 */
  if (a2 == 0) goto L_0575;  /* 04d9: beqz a2, 575 <esp_mesh_txupQ_pending+0x495> */
  L_04dc: a10 = LD32(a5 + 0x158);  /* 04dc */
  /* 04df: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a6 = a10;  /* 04e2 */
  a10 = a3;  /* 04e4: mov */
  a8 = (u32)&txq_opr2str + 0x0;  /* 04e7: l32r -> global */
  a2 = txq_opr2str(a2, a3, a4, a5, a6);  /* 04ea: callx a8 via reloc-expand */
  a8 = a10;  /* 04ed */
  a10 = a4;  /* 04ef */
  ST32(a1 + 0x94, a8);  /* 04f1 */
  __asm__ volatile("" ::: "memory");  /* 04f4: memw */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 04f7: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6);  /* 04fa: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x94);  /* 04fd */
  a3 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0500: -> "self" */
  if (a10 != 0) goto L_0509;  /* 0503: bnez a10, 509 <esp_mesh_txupQ_pending+0x429> */
  L_0506: a3 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0506: -> "self" */
  L_0509: a4 = (u32)&mesh_self_xonseq + 0x0;  /* 0509: l32r -> global */
  a11 = LD8U(a7 + 0xc);  /* 050c */
  a4 = LD32(a4 + 0x0);  /* 050f */
  a9 = LD32(a1 + 0x60);  /* 0512 */
  ST32(a1 + 0x64, a11);  /* 0515 */
  a10 = LD8U(a7 + 0xd);  /* 0518 */
  a12 = LD8U(a7 + 0xe);  /* 051b */
  a13 = LD8U(a7 + 0xf);  /* 051e */
  a14 = LD8U(a7 + 0x10);  /* 0521 */
  a15 = LD8U(a7 + 0x11);  /* 0524 */
  a5 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0527: -> "self" */
  if (a4 >= a9) goto L_0530;  /* 052a: bgeu a4, a9, 530 <esp_mesh_txupQ_pending+0x450> */
  L_052d: a5 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 052d: -> "self" */
  L_0530: a7 = LD16U(a7 + 0x4);  /* 0530 */
  ST32(a1 + 0x1c, a12);  /* 0533 */
  ST32(a1 + 0x10, a3);  /* 0535 */
  a12 = LD32(a1 + 0x64);  /* 0537 */
  a3 = LD32(a1 + 0x80);  /* 053a */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 053d: -> "mesh" */
  a9 = LD32(a1 + 0x60);  /* 0540 */
  ST32(a1 + 0x2c, a4);  /* 0543 */
  a4 = LD32(a1 + 0x7c);  /* 0545 */
  ST32(a1 + 0x28, a15);  /* 0548 */
  ST32(a1 + 0x14, a12);  /* 054a */
  ST32(a1 + 0x8, a3);  /* 054c */
  a3 = 0x652;  /* 054e */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0551: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0554: -> "self" */
  ST32(a1 + 0x24, a14);  /* 0557 */
  a14 = a11;  /* 0559 */
  ST32(a1 + 0x20, a13);  /* 055b */
  a13 = a6;  /* 055d */
  ST32(a1 + 0x18, a10);  /* 055f */
  a10 = 2;  /* 0561 */
  ST32(a1 + 0x38, a7);  /* 0563 */
  ST32(a1 + 0x34, a9);  /* 0565 */
  ST32(a1 + 0x30, a5);  /* 0567 */
  ST32(a1 + 0xc, a8);  /* 0569 */
  ST32(a1 + 0x4, a4);  /* 056b */
  ST32(a1 + 0x0, a3);  /* 056d */
  __asm__ volatile("" ::: "memory");  /* 056f: memw */
  /* 0572: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  L_0575: a12 = 0x659;  /* 0575 */
  a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0578: l32r -> .bss.mesh_tx_task (same-object static) */
  a11 = (u32)(RODATA__rodata___func___13 + 0x0);  /* 057b: l32r -> .rodata.__func__$13 */
  a10 = LD32(a2 + 0x1c);  /* 057e */
  goto L_0aec;  /* 0580: j */
  L_0585: a5 = (u32)&mesh_conn_mutex + 0x0;  /* 0585: l32r -> global */
  a12 = 0x662;  /* 0588 */
  a2 = -3;  /* 058b */
  a2 = a3 & a2;  /* 058d */
  a6 = (u32)(RODATA__rodata___func___13 + 0x0);  /* 0590: l32r -> .rodata.__func__$13 */
  a11 = a6;  /* 0593 */
  a10 = LD32(a5 + 0x0);  /* 0595 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 0597: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6);  /* 059a: callx a8 via reloc-expand */
  a10 = a4;  /* 059d */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 059f: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6);  /* 05a2: callx a8 via reloc-expand */
  a8 = (a10 >> 8) & 0x1;  /* 05a5: extui width 1 */
  a10 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 05a8: sext */
  ST32(a1 + 0x6c, a8);  /* 05ab */
  ST32(a1 + 0x64, a10);  /* 05ae */
  if (a10 != -1) goto L_05b7;  /* 05b1: bnei a10, -1, 5b7 <esp_mesh_txupQ_pending+0x4d7> */
  L_05b4: goto L_0af9;  /* 05b4: j */
  L_05b7: a9 = LD32(a1 + 0x60);  /* 05b7 */
  if (a9 == 0) goto L_05d0;  /* 05ba: beqz.n a9, 5d0 <esp_mesh_txupQ_pending+0x4f0> */
  L_05bc: a4 = 0x0fffffffu;  /* 05bc: l32r = 268435455 */
  if (a9 == a4) goto L_05c5;  /* 05bf: beq a9, a4, 5c5 <esp_mesh_txupQ_pending+0x4e5> */
  L_05c2: goto L_06e8;  /* 05c2: j */
  L_05c5: a5 = 96;  /* 05c5 */
  a4 = LD32(a7 + 0x28);  /* 05c8 */
  if ((a5 & a4) != 0) goto L_05d0;  /* 05ca: bany a5, a4, 5d0 <esp_mesh_txupQ_pending+0x4f0> */
  L_05cd: goto L_06e8;  /* 05cd: j */
  L_05d0: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 05d0: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 05d3 */
  if (a4 == 0) goto L_06bc;  /* 05d5: beqz a4, 6bc <esp_mesh_txupQ_pending+0x5dc> */
  L_05d8: a5 = LD32(a4 + 0x150);  /* 05d8 */
  ST32(a1 + 0x70, a5);  /* 05db */
  if (a5 == 0) goto L_06bc;  /* 05de: beqz a5, 6bc <esp_mesh_txupQ_pending+0x5dc> */
  L_05e1: a10 = LD32(a4 + 0x158);  /* 05e1 */
  __asm__ volatile("" ::: "memory");  /* 05e4: memw */
  /* 05e7: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 05ea */
  a10 = a3;  /* 05ec */
  a6 = LD32(a1 + 0x64);  /* 05ee */
  a5 = a6 << 6;  /* 05f1 */
  a4 = (u32)&g_mesh_conn + 0x0;  /* 05f4: l32r -> global */
  a4 = a4 + a5;  /* 05f7 */
  a8 = LD8U(a4 + 0x0);  /* 05f9 */
  a9 = LD8U(a4 + 0x1);  /* 05fc */
  a11 = LD8U(a4 + 0x2);  /* 05ff */
  a12 = LD8U(a4 + 0x3);  /* 0602 */
  a15 = LD8U(a4 + 0x4);  /* 0605 */
  a5 = LD8U(a4 + 0x5);  /* 0608 */
  ST32(a1 + 0x74, a8);  /* 060b */
  ST32(a1 + 0x78, a9);  /* 060e */
  ST32(a1 + 0x84, a11);  /* 0611 */
  ST32(a1 + 0x88, a12);  /* 0614 */
  ST32(a1 + 0x8c, a15);  /* 0617 */
  ST32(a1 + 0x90, a5);  /* 061a */
  ST32(a1 + 0x94, a13);  /* 061d */
  __asm__ volatile("" ::: "memory");  /* 0620: memw */
  a8 = (u32)&txq_opr2str + 0x0;  /* 0623: l32r -> global */
  a2 = txq_opr2str(a2, a3, a4, a5, a6);  /* 0626: callx a8 via reloc-expand */
  a6 = LD32(a1 + 0x68);  /* 0629 */
  a8 = LD8U(a4 + 0x10);  /* 062c */
  a15 = LD32(a4 + 0x8);  /* 062f */
  a14 = LD32(a4 + 0xc);  /* 0631 */
  a4 = a6 + (14);  /* 0633 */
  a12 = LD32(a4 + 0x14);  /* 0635 */
  a4 = a6 + (18);  /* 0637 */
  a4 = LD32(a4 + 0x0);  /* 063a */
  a4 = (a4 >> 5) & 0x3ff;  /* 063c: extui width 10 */
  a11 = LD32(a7 + 0x28);  /* 063f */
  a9 = LD16U(a7 + 0x4);  /* 0641 */
  a5 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0644: -> "self" */
  a13 = LD32(a1 + 0x94);  /* 0647 */
  if (((a11 >> 5) & 1) != 0) goto L_0650;  /* 064a: bbsi a11, 5, 650 <esp_mesh_txupQ_pending+0x570> */
  L_064d: a5 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 064d: -> "no window" */
  L_0650: a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0650: -> "self" */
  if (((a11 >> 6) & 1) != 0) goto L_0659;  /* 0653: bbsi a11, 6, 659 <esp_mesh_txupQ_pending+0x579> */
  L_0656: a6 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0656: -> "no window" */
  L_0659: ST32(a1 + 0x44, a4);  /* 0659 */
  a4 = LD32(a1 + 0x88);  /* 065c */
  ST32(a1 + 0x48, a5);  /* 065f */
  ST32(a1 + 0x3c, a9);  /* 0662 */
  a5 = LD32(a1 + 0x84);  /* 0664 */
  a9 = LD32(a1 + 0x60);  /* 0667 */
  ST32(a1 + 0x1c, a4);  /* 066a */
  a4 = LD32(a1 + 0x80);  /* 066c */
  ST32(a1 + 0x4c, a6);  /* 066f */
  ST32(a1 + 0x40, a12);  /* 0672 */
  a6 = LD32(a1 + 0x78);  /* 0675 */
  a12 = LD32(a1 + 0x90);  /* 0678 */
  ST32(a1 + 0x38, a9);  /* 067b */
  ST32(a1 + 0x30, a15);  /* 067d */
  a9 = LD32(a1 + 0x64);  /* 067f */
  a15 = LD32(a1 + 0x8c);  /* 0682 */
  ST32(a1 + 0x2c, a8);  /* 0685 */
  ST32(a1 + 0x18, a5);  /* 0687 */
  a8 = LD32(a1 + 0x74);  /* 0689 */
  a5 = LD32(a1 + 0x7c);  /* 068c */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 068f: -> "mesh" */
  ST32(a1 + 0x8, a4);  /* 0692 */
  a4 = 0x673;  /* 0694 */
  ST32(a1 + 0x34, a14);  /* 0697 */
  a14 = a11;  /* 0699 */
  ST32(a1 + 0x28, a10);  /* 069b */
  a10 = 1;  /* 069d */
  ST32(a1 + 0x20, a15);  /* 069f */
  ST32(a1 + 0x14, a6);  /* 06a1 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 06a3: -> "mesh_schedule.c" */
  ST32(a1 + 0x24, a12);  /* 06a6 */
  ST32(a1 + 0x10, a8);  /* 06a8 */
  ST32(a1 + 0xc, a9);  /* 06aa */
  ST32(a1 + 0x4, a5);  /* 06ac */
  ST32(a1 + 0x0, a4);  /* 06ae */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 06b0: -> "self" */
  a6 = LD32(a1 + 0x70);  /* 06b3 */
  __asm__ volatile("" ::: "memory");  /* 06b6: memw */
  /* 06b9: INDIRECT callx a6 <- mem[a1+0x70]; result unknown */ a2 = 0;
  L_06bc: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 06bc: l32r -> global */
  a5 = LD32(a4 + 0x0);  /* 06bf */
  if (a5 == 0) goto L_06e8;  /* 06c1: beqz.n a5, 6e8 <esp_mesh_txupQ_pending+0x608> */
  L_06c3: a4 = LD32(a5 + 0x150);  /* 06c3 */
  if (a4 == 0) goto L_06e8;  /* 06c6: beqz.n a4, 6e8 <esp_mesh_txupQ_pending+0x608> */
  L_06c8: a10 = LD32(a5 + 0x158);  /* 06c8 */
  a5 = 0x680;  /* 06cb */
  /* 06ce: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 06d1 */
  a10 = 1;  /* 06d3 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 06d5: -> "mesh" */
  a14 = a11;  /* 06d8 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 06da: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 06dd: -> "no window" */
  ST32(a1 + 0x0, a5);  /* 06e0 */
  __asm__ volatile("" ::: "memory");  /* 06e2: memw */
  /* 06e5: INDIRECT callx a4 <- mem[a5+0x150]; result unknown */ a2 = 0;
  L_06e8: if (a2 == 0) goto L_06f4;  /* 06e8: beqz.n a2, 6f4 <esp_mesh_txupQ_pending+0x614> */
  L_06ea: if (a2 != 1) goto L_06f0;  /* 06ea: bnei a2, 1, 6f0 <esp_mesh_txupQ_pending+0x610> */
  L_06ed: goto L_0850;  /* 06ed: j */
  L_06f0: goto L_0ae1;  /* 06f0: j */
  L_06f4: a8 = LD32(a1 + 0x6c);  /* 06f4 */
  a4 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 06f7: sext */
  a6 = a4 << 6;  /* 06fa */
  a8 = a2;  /* 06fd */
  a5 = (u32)&g_mesh_conn + 0x0;  /* 06ff: l32r -> global */
  a5 = a5 + a6;  /* 0702 */
  a6 = 1;  /* 0704 */
  a9 = LD8U(a5 + 0x10);  /* 0706 */
  if (a9 == 0) a8 = a6;  /* 0709 */
  a8 = (a8 >> 8) & 0x1;  /* 070c: extui width 1 */
  if (a8 == 0) goto L_09d2;  /* 070f: beqz a8, 9d2 <esp_mesh_txupQ_pending+0x8f2> */
  L_0712: a8 = 0xf0000001u;  /* 0712: l32r = -268435455 */
  a9 = LD32(a1 + 0x60);  /* 0715 */
  a8 = a9 + a8;  /* 0718 */
  if (a8 == 0) a6 = a2;  /* 071a */
  a6 = (a6 >> 8) & 0x1;  /* 071d: extui width 1 */
  if (a6 == 0) goto L_09d2;  /* 0720: beqz a6, 9d2 <esp_mesh_txupQ_pending+0x8f2> */
  L_0723: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0723: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0726 */
  if (a2 != 0) goto L_0739;  /* 0729: bnez a2, 739 <esp_mesh_txupQ_pending+0x659> */
  L_072c: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 072c: l32r -> global */
  a4 = LD32(a2 + 0x0);  /* 072f */
  if (a4 != 0) goto L_0825;  /* 0731: bnez a4, 825 <esp_mesh_txupQ_pending+0x745> */
  L_0734: goto L_09d2;  /* 0734: j */
  L_0739: a6 = LD32(a2 + 0x150);  /* 0739 */
  ST32(a1 + 0x64, a6);  /* 073c */
  if (a6 == 0) goto L_072c;  /* 073f: beqz a6, 72c <esp_mesh_txupQ_pending+0x64c> */
  L_0742: a10 = LD32(a2 + 0x158);  /* 0742 */
  __asm__ volatile("" ::: "memory");  /* 0745: memw */
  /* 0748: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 074b */
  a10 = a3;  /* 074d: mov */
  a8 = LD8U(a5 + 0x0);  /* 0750 */
  a9 = LD8U(a5 + 0x1);  /* 0753 */
  a11 = LD8U(a5 + 0x2);  /* 0756 */
  a12 = LD8U(a5 + 0x3);  /* 0759 */
  a15 = LD8U(a5 + 0x4);  /* 075c */
  a2 = LD8U(a5 + 0x5);  /* 075f */
  ST32(a1 + 0x70, a8);  /* 0762 */
  ST32(a1 + 0x74, a9);  /* 0765 */
  ST32(a1 + 0x78, a11);  /* 0768 */
  ST32(a1 + 0x84, a12);  /* 076b */
  ST32(a1 + 0x88, a15);  /* 076e */
  ST32(a1 + 0x8c, a2);  /* 0771 */
  ST32(a1 + 0x94, a13);  /* 0774 */
  __asm__ volatile("" ::: "memory");  /* 0777: memw */
  a8 = (u32)&txq_opr2str + 0x0;  /* 077a: l32r -> global */
  a2 = txq_opr2str(a2, a3, a4, a5, a6);  /* 077d: callx a8 via reloc-expand */
  a15 = LD8U(a5 + 0x10);  /* 0780 */
  a14 = LD32(a5 + 0x8);  /* 0783 */
  a8 = LD32(a5 + 0xc);  /* 0785 */
  a5 = LD32(a1 + 0x68);  /* 0787 */
  a2 = a5 + (14);  /* 078a */
  a12 = LD32(a2 + 0x14);  /* 078c */
  a2 = a5 + (18);  /* 078e */
  a2 = LD32(a2 + 0x0);  /* 0791 */
  a2 = (a2 >> 5) & 0x3ff;  /* 0793: extui width 10 */
  a11 = LD32(a7 + 0x28);  /* 0796 */
  a9 = LD16U(a7 + 0x4);  /* 0799 */
  a5 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 079c: -> "self" */
  a13 = LD32(a1 + 0x94);  /* 079f */
  if (((a11 >> 5) & 1) != 0) goto L_07a8;  /* 07a2: bbsi a11, 5, 7a8 <esp_mesh_txupQ_pending+0x6c8> */
  L_07a5: a5 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 07a5: -> "no window" */
  L_07a8: a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 07a8: -> "self" */
  if (((a11 >> 6) & 1) != 0) goto L_07b1;  /* 07ab: bbsi a11, 6, 7b1 <esp_mesh_txupQ_pending+0x6d1> */
  L_07ae: a6 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 07ae: -> "no window" */
  L_07b1: ST32(a1 + 0x44, a2);  /* 07b1 */
  a2 = LD32(a1 + 0x84);  /* 07b4 */
  ST32(a1 + 0x3c, a9);  /* 07b7 */
  a9 = LD32(a1 + 0x60);  /* 07b9 */
  ST32(a1 + 0x1c, a2);  /* 07bc */
  a2 = LD32(a1 + 0x7c);  /* 07be */
  ST32(a1 + 0x4c, a6);  /* 07c1 */
  ST32(a1 + 0x48, a5);  /* 07c4 */
  a6 = LD32(a1 + 0x74);  /* 07c7 */
  a5 = LD32(a1 + 0x78);  /* 07ca */
  ST32(a1 + 0x40, a12);  /* 07cd */
  ST32(a1 + 0x38, a9);  /* 07d0 */
  a12 = LD32(a1 + 0x8c);  /* 07d2 */
  a9 = LD32(a1 + 0x80);  /* 07d5 */
  ST32(a1 + 0x34, a8);  /* 07d8 */
  ST32(a1 + 0x2c, a15);  /* 07da */
  a8 = LD32(a1 + 0x70);  /* 07dc */
  a15 = LD32(a1 + 0x88);  /* 07df */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 07e2: -> "mesh" */
  ST32(a1 + 0x4, a2);  /* 07e5 */
  a2 = 0x685;  /* 07e7 */
  ST32(a1 + 0x30, a14);  /* 07ea */
  a14 = a11;  /* 07ec */
  ST32(a1 + 0x28, a10);  /* 07ee */
  a10 = 1;  /* 07f0 */
  ST32(a1 + 0x24, a12);  /* 07f2 */
  ST32(a1 + 0x20, a15);  /* 07f4 */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 07f6: -> "self" */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 07f9: -> "mesh_schedule.c" */
  ST32(a1 + 0x10, a8);  /* 07fc */
  ST32(a1 + 0xc, a4);  /* 07fe */
  a4 = a4 << 6;  /* 0800 */
  ST32(a1 + 0x8, a9);  /* 0803 */
  ST32(a1 + 0x0, a2);  /* 0805 */
  ST32(a1 + 0x18, a5);  /* 0807 */
  ST32(a1 + 0x14, a6);  /* 0809 */
  a5 = LD32(a1 + 0x64);  /* 080b */
  __asm__ volatile("" ::: "memory");  /* 080e: memw */
  /* 0811: INDIRECT callx a5 <- mem[a1+0x64]; result unknown */ a2 = 0;
  a2 = (u32)&g_mesh_conn + 0x0;  /* 0814: l32r -> global */
  a2 = a2 + a4;  /* 0817 */
  a2 = LD8U(a2 + 0x10);  /* 0819 */
  if (a2 != 0) goto L_09d2;  /* 081c: bnez a2, 9d2 <esp_mesh_txupQ_pending+0x8f2> */
  L_081f: goto L_072c;  /* 081f: j */
  L_0825: a2 = LD32(a4 + 0x150);  /* 0825 */
  if (a2 == 0) goto L_09d2;  /* 0828: beqz a2, 9d2 <esp_mesh_txupQ_pending+0x8f2> */
  L_082b: a10 = LD32(a4 + 0x158);  /* 082b */
  a4 = 0x68f;  /* 082e */
  /* 0831: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0834 */
  a10 = 1;  /* 0836 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0838: -> "mesh" */
  a14 = a11;  /* 083b */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 083d: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0840: -> "no window" */
  ST32(a1 + 0x0, a4);  /* 0843 */
  __asm__ volatile("" ::: "memory");  /* 0846: memw */
  /* 0849: INDIRECT callx a2 <- mem[a4+0x150]; result unknown */ a2 = 0;
  goto L_09d2;  /* 084c: j */
  L_0850: a6 = LD32(a1 + 0x6c);  /* 0850 */
  a2 = (i32)(a6 << (32 - 7)) >> (32 - 7);  /* 0853: sext */
  a4 = a2 << 6;  /* 0856 */
  a5 = (u32)&g_mesh_conn + 0x0;  /* 0859: l32r -> global */
  a5 = a5 + a4;  /* 085c */
  a4 = LD32(a5 + 0x8);  /* 085e */
  a8 = LD32(a1 + 0x60);  /* 0860 */
  if (a8 < a4) goto L_0869;  /* 0863: bltu a8, a4, 869 <esp_mesh_txupQ_pending+0x789> */
  L_0866: goto L_09a8;  /* 0866: j */
  L_0869: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0869: l32r -> global */
  a6 = LD32(a4 + 0x0);  /* 086c */
  if (a6 == 0) goto L_0951;  /* 086e: beqz a6, 951 <esp_mesh_txupQ_pending+0x871> */
  L_0871: a4 = LD32(a6 + 0x150);  /* 0871 */
  if (a4 == 0) goto L_0951;  /* 0874: beqz a4, 951 <esp_mesh_txupQ_pending+0x871> */
  L_0877: a10 = LD32(a6 + 0x158);  /* 0877 */
  /* 087a: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 087d */
  a10 = a3;  /* 087f */
  ST32(a1 + 0x94, a13);  /* 0881 */
  __asm__ volatile("" ::: "memory");  /* 0884: memw */
  a8 = (u32)&txq_opr2str + 0x0;  /* 0887: l32r -> global */
  a2 = txq_opr2str(a2, a3, a4, a5, a6);  /* 088a: callx a8 via reloc-expand */
  a9 = LD8U(a7 + 0xc);  /* 088d */
  a15 = LD8U(a7 + 0xf);  /* 0890 */
  a6 = LD8U(a7 + 0x11);  /* 0893 */
  a11 = LD8U(a7 + 0xd);  /* 0896 */
  a12 = LD8U(a7 + 0xe);  /* 0899 */
  a3 = LD8U(a7 + 0x10);  /* 089c */
  a8 = LD32(a5 + 0xc);  /* 089f */
  ST32(a1 + 0x6c, a9);  /* 08a2 */
  ST32(a1 + 0x74, a15);  /* 08a5 */
  a9 = LD32(a1 + 0x60);  /* 08a8 */
  a15 = LD8U(a5 + 0x10);  /* 08ab */
  a5 = LD32(a5 + 0x8);  /* 08ae */
  ST32(a1 + 0x84, a6);  /* 08b0 */
  ST32(a1 + 0x64, a11);  /* 08b3 */
  ST32(a1 + 0x70, a12);  /* 08b6 */
  ST32(a1 + 0x78, a3);  /* 08b9 */
  a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 08bc: -> "self" */
  a13 = LD32(a1 + 0x94);  /* 08bf */
  if (a5 >= a9) goto L_08c8;  /* 08c2: bgeu a5, a9, 8c8 <esp_mesh_txupQ_pending+0x7e8> */
  L_08c5: a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 08c5: -> "self" */
  L_08c8: a11 = LD32(a1 + 0x68);  /* 08c8 */
  a3 = a11 + (14);  /* 08cb */
  a12 = LD32(a3 + 0x14);  /* 08cd */
  a3 = a11 + (18);  /* 08cf */
  a3 = LD32(a3 + 0x0);  /* 08d2 */
  a3 = (a3 >> 5) & 0x3ff;  /* 08d4: extui width 10 */
  a11 = LD32(a7 + 0x28);  /* 08d7 */
  a9 = LD16U(a7 + 0x4);  /* 08d9 */
  a7 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 08dc: -> "self" */
  if (((a11 >> 5) & 1) != 0) goto L_08e5;  /* 08df: bbsi a11, 5, 8e5 <esp_mesh_txupQ_pending+0x805> */
  L_08e2: a7 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 08e2: -> "no window" */
  L_08e5: a14 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 08e5: -> "self" */
  if (((a11 >> 6) & 1) != 0) goto L_08ee;  /* 08e8: bbsi a11, 6, 8ee <esp_mesh_txupQ_pending+0x80e> */
  L_08eb: a14 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 08eb: -> "no window" */
  L_08ee: ST32(a1 + 0x48, a3);  /* 08ee */
  a3 = LD32(a1 + 0x60);  /* 08f1 */
  ST32(a1 + 0x34, a5);  /* 08f4 */
  a5 = LD32(a1 + 0x84);  /* 08f6 */
  ST32(a1 + 0x3c, a3);  /* 08f9 */
  a3 = LD32(a1 + 0x80);  /* 08fb */
  ST32(a1 + 0x44, a12);  /* 08fe */
  ST32(a1 + 0x40, a9);  /* 0901 */
  a12 = LD32(a1 + 0x64);  /* 0904 */
  a9 = LD32(a1 + 0x70);  /* 0907 */
  ST32(a1 + 0x38, a6);  /* 090a */
  ST32(a1 + 0x30, a8);  /* 090c */
  a6 = LD32(a1 + 0x78);  /* 090e */
  a8 = LD32(a1 + 0x74);  /* 0911 */
  ST32(a1 + 0x2c, a15);  /* 0914 */
  ST32(a1 + 0x28, a5);  /* 0916 */
  a15 = LD32(a1 + 0x6c);  /* 0918 */
  a5 = LD32(a1 + 0x7c);  /* 091b */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 091e: -> "mesh" */
  ST32(a1 + 0x8, a3);  /* 0921 */
  a3 = 0x69d;  /* 0923 */
  ST32(a1 + 0x50, a14);  /* 0926 */
  a14 = a11;  /* 0929 */
  ST32(a1 + 0x14, a15);  /* 092b */
  ST32(a1 + 0xc, a10);  /* 092d */
  a10 = 2;  /* 092f */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0931: -> "mesh_schedule.c" */
  ST32(a1 + 0x4c, a7);  /* 0934 */
  ST32(a1 + 0x24, a6);  /* 0937 */
  ST32(a1 + 0x20, a8);  /* 0939 */
  ST32(a1 + 0x1c, a9);  /* 093b */
  ST32(a1 + 0x18, a12);  /* 093d */
  ST32(a1 + 0x10, a2);  /* 093f */
  ST32(a1 + 0x4, a5);  /* 0942 */
  ST32(a1 + 0x0, a3);  /* 0945 */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0948: -> "self" */
  __asm__ volatile("" ::: "memory");  /* 094b: memw */
  /* 094e: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_0951: a12 = 0x6a7;  /* 0951 */
  a2 = a2 << 6;  /* 0954 */
  a3 = (u32)&mesh_conn_mutex + 0x0;  /* 0957: l32r -> global */
  a11 = (u32)(RODATA__rodata___func___13 + 0x0);  /* 095a: l32r -> .rodata.__func__$13 */
  a10 = LD32(a3 + 0x0);  /* 095d */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 095f: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6);  /* 0962: callx a8 via reloc-expand */
  a3 = (u32)&g_mesh_conn + 0x0;  /* 0965: l32r -> global */
  a2 = a3 + a2;  /* 0968 */
  a2 = LD32(a2 + 0x8);  /* 096a */
  a8 = LD32(a1 + 0x60);  /* 096c */
  if (a8 < a2) goto L_0975;  /* 096f: bltu a8, a2, 975 <esp_mesh_txupQ_pending+0x895> */
  L_0972: goto L_0484;  /* 0972: j */
  L_0975: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0975: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0978 */
  if (a2 == 0) goto L_0484;  /* 097b: beqz a2, 484 <esp_mesh_txupQ_pending+0x3a4> */
  L_097e: a3 = LD32(a2 + 0x150);  /* 097e */
  if (a3 == 0) goto L_0484;  /* 0981: beqz a3, 484 <esp_mesh_txupQ_pending+0x3a4> */
  L_0984: a10 = LD32(a2 + 0x158);  /* 0984 */
  a2 = 0x6b3;  /* 0987 */
  /* 098a: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 098d */
  a10 = 1;  /* 098f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0991: -> "mesh" */
  a14 = a11;  /* 0994 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0996: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0999: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 099c */
  __asm__ volatile("" ::: "memory");  /* 099e: memw */
  /* 09a1: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0484;  /* 09a4: j */
  L_09a8: a2 = LD8U(a5 + 0x10);  /* 09a8 */
  a2 = a2 + (1);  /* 09ab */
  a9 = LD32(a1 + 0x60);  /* 09ad */
  ST8(a5 + 0x10, a2);  /* 09b0 */
  __asm__ volatile("" ::: "memory");  /* 09b3: memw */
  ST32(a5 + 0x8, a9);  /* 09b6 */
  a2 = LD32(a7 + 0x28);  /* 09b8 */
  if (a3 != 1) goto L_09c5;  /* 09ba: bnei a3, 1, 9c5 <esp_mesh_txupQ_pending+0x8e5> */
  L_09bd: a3 = 32;  /* 09bd */
  __asm__ volatile("" ::: "memory");  /* 09bf: memw */
  goto L_09c7;  /* 09c2: j */
  L_09c5: a3 = 64;  /* 09c5 */
  L_09c7: a2 = a2 | a3;  /* 09c7 */
  ST32(a7 + 0x28, a2);  /* 09ca */
  __asm__ volatile("" ::: "memory");  /* 09cc: memw */
  goto L_0ae1;  /* 09cf: j */
  L_09d2: a2 = LD32(a7 + 0x28);  /* 09d2 */
  if (a3 != 0) goto L_09dd;  /* 09d4: bnez.n a3, 9dd <esp_mesh_txupQ_pending+0x8fd> */
  L_09d6: if (((a2 >> 5) & 1) != 0) goto L_09e0;  /* 09d6: bbsi a2, 5, 9e0 <esp_mesh_txupQ_pending+0x900> */
  L_09d9: goto L_0a04;  /* 09d9: j */
  L_09dd: if (((a2 >> 6) & 1) == 0) goto L_0a04;  /* 09dd: bbci a2, 6, a04 <esp_mesh_txupQ_pending+0x924> */
  L_09e0: a2 = LD32(a1 + 0x6c);  /* 09e0 */
  a3 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 09e3: sext */
  a3 = a3 << 6;  /* 09e6 */
  a2 = (u32)&g_mesh_conn + 0x0;  /* 09e9: l32r -> global */
  a2 = a2 + a3;  /* 09ec */
  a3 = LD8U(a2 + 0x10);  /* 09ee */
  a3 = a3 + (-1);  /* 09f1 */
  ST8(a2 + 0x10, a3);  /* 09f3 */
  __asm__ volatile("" ::: "memory");  /* 09f6: memw */
  a3 = LD32(a1 + 0x60);  /* 09f9 */
  ST32(a2 + 0xc, a3);  /* 09fc */
  __asm__ volatile("" ::: "memory");  /* 09fe: memw */
  goto L_0ae1;  /* 0a01: j */
  L_0a04: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0a04: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0a07 */
  if (a2 == 0) goto L_0ae1;  /* 0a09: beqz a2, ae1 <esp_mesh_txupQ_pending+0xa01> */
  L_0a0c: a4 = LD32(a2 + 0x150);  /* 0a0c */
  if (a4 == 0) goto L_0ae1;  /* 0a0f: beqz a4, ae1 <esp_mesh_txupQ_pending+0xa01> */
  L_0a12: a10 = LD32(a2 + 0x158);  /* 0a12 */
  /* 0a15: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0a18 */
  a10 = a3;  /* 0a1a */
  ST32(a1 + 0x94, a13);  /* 0a1c */
  __asm__ volatile("" ::: "memory");  /* 0a1f: memw */
  a8 = (u32)&txq_opr2str + 0x0;  /* 0a22: l32r -> global */
  a2 = txq_opr2str(a2, a3, a4, a5, a6);  /* 0a25: callx a8 via reloc-expand */
  a5 = LD32(a1 + 0x6c);  /* 0a28 */
  a3 = (i32)(a5 << (32 - 7)) >> (32 - 7);  /* 0a2b: sext */
  a5 = a3 << 6;  /* 0a2e */
  a2 = (u32)&g_mesh_conn + 0x0;  /* 0a31: l32r -> global */
  a2 = a2 + a5;  /* 0a34 */
  a6 = LD8U(a7 + 0xc);  /* 0a36 */
  a8 = LD8U(a7 + 0xd);  /* 0a39 */
  a9 = LD8U(a7 + 0xe);  /* 0a3c */
  a11 = LD8U(a7 + 0xf);  /* 0a3f */
  a5 = LD32(a2 + 0x8);  /* 0a42 */
  a2 = LD32(a1 + 0x60);  /* 0a44 */
  ST32(a1 + 0x6c, a6);  /* 0a47 */
  ST32(a1 + 0x64, a8);  /* 0a4a */
  ST32(a1 + 0x70, a9);  /* 0a4d */
  ST32(a1 + 0x74, a11);  /* 0a50 */
  a15 = LD8U(a7 + 0x10);  /* 0a53 */
  a8 = LD8U(a7 + 0x11);  /* 0a56 */
  a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0a59: -> "self" */
  a13 = LD32(a1 + 0x94);  /* 0a5c */
  if (a5 >= a2) goto L_0a65;  /* 0a5f: bgeu a5, a2, a65 <esp_mesh_txupQ_pending+0x985> */
  L_0a62: a6 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0a62: -> "self" */
  L_0a65: a11 = LD32(a1 + 0x68);  /* 0a65 */
  a2 = a11 + (14);  /* 0a68 */
  a12 = LD32(a2 + 0x14);  /* 0a6a */
  a2 = a11 + (18);  /* 0a6d */
  a2 = LD32(a2 + 0x0);  /* 0a70 */
  a2 = (a2 >> 5) & 0x3ff;  /* 0a73: extui width 10 */
  a11 = LD32(a7 + 0x28);  /* 0a76 */
  a9 = LD16U(a7 + 0x4);  /* 0a78 */
  a7 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0a7b: -> "self" */
  if (((a11 >> 5) & 1) != 0) goto L_0a84;  /* 0a7e: bbsi a11, 5, a84 <esp_mesh_txupQ_pending+0x9a4> */
  L_0a81: a7 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0a81: -> "no window" */
  L_0a84: a14 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0a84: -> "self" */
  if (((a11 >> 6) & 1) != 0) goto L_0a8d;  /* 0a87: bbsi a11, 6, a8d <esp_mesh_txupQ_pending+0x9ad> */
  L_0a8a: a14 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0a8a: -> "no window" */
  L_0a8d: ST32(a1 + 0x40, a2);  /* 0a8d */
  a2 = LD32(a1 + 0x60);  /* 0a90 */
  ST32(a1 + 0x34, a2);  /* 0a93 */
  a2 = LD32(a1 + 0x80);  /* 0a95 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0a98: -> "mesh" */
  ST32(a1 + 0x38, a9);  /* 0a9b */
  ST32(a1 + 0x30, a6);  /* 0a9d */
  a9 = LD32(a1 + 0x6c);  /* 0a9f */
  a6 = LD32(a1 + 0x70);  /* 0aa2 */
  ST32(a1 + 0x2c, a5);  /* 0aa5 */
  ST32(a1 + 0x28, a8);  /* 0aa7 */
  a5 = LD32(a1 + 0x74);  /* 0aa9 */
  a8 = LD32(a1 + 0x64);  /* 0aac */
  ST32(a1 + 0x10, a3);  /* 0aaf */
  a3 = LD32(a1 + 0x7c);  /* 0ab1 */
  ST32(a1 + 0x3c, a12);  /* 0ab4 */
  ST32(a1 + 0x24, a15);  /* 0ab6 */
  ST32(a1 + 0x8, a2);  /* 0ab8 */
  a2 = 0x6c8;  /* 0aba */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0abd: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0ac0: -> "self" */
  ST32(a1 + 0x48, a14);  /* 0ac3 */
  a14 = a11;  /* 0ac6 */
  ST32(a1 + 0xc, a10);  /* 0ac8 */
  a10 = 2;  /* 0aca */
  ST32(a1 + 0x44, a7);  /* 0acc */
  ST32(a1 + 0x20, a5);  /* 0acf */
  ST32(a1 + 0x1c, a6);  /* 0ad1 */
  ST32(a1 + 0x18, a8);  /* 0ad3 */
  ST32(a1 + 0x14, a9);  /* 0ad5 */
  ST32(a1 + 0x4, a3);  /* 0ad7 */
  ST32(a1 + 0x0, a2);  /* 0ad9 */
  __asm__ volatile("" ::: "memory");  /* 0adb: memw */
  /* 0ade: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_0ae1: a12 = 0x6d1;  /* 0ae1 */
  a2 = (u32)&mesh_conn_mutex + 0x0;  /* 0ae4: l32r -> global */
  a11 = (u32)(RODATA__rodata___func___13 + 0x0);  /* 0ae7: l32r -> .rodata.__func__$13 */
  a10 = LD32(a2 + 0x0);  /* 0aea */
  L_0aec: a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0aec: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6);  /* 0aef: callx a8 via reloc-expand */
  a2 = 0;  /* 0af2 */
  goto L_0c3c;  /* 0af4: j */
  L_0af9: if (a2 != 0) goto L_0c2d;  /* 0af9: bnez a2, c2d <esp_mesh_txupQ_pending+0xb4d> */
  L_0afc: a10 = a4;  /* 0afc */
  a8 = (u32)&esp_mesh_txupQ_pending_get_cidx;  /* 0afe: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending_get_cidx(a2, a3, a4, a5, a6);  /* 0b01: callx a8 via reloc-expand */
  a4 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 0b04: sext */
  if (a4 != -1) goto L_0b0d;  /* 0b07: bnei a4, -1, b0d <esp_mesh_txupQ_pending+0xa2d> */
  L_0b0a: goto L_0c2d;  /* 0b0a: j */
  L_0b0d: a5 = LD32(a7 + 0x28);  /* 0b0d */
  if (a3 != 0) goto L_0b19;  /* 0b0f: bnez.n a3, b19 <esp_mesh_txupQ_pending+0xa39> */
  L_0b11: if (((a5 >> 5) & 1) != 0) goto L_0b1c;  /* 0b11: bbsi a5, 5, b1c <esp_mesh_txupQ_pending+0xa3c> */
  L_0b14: goto L_0b3d;  /* 0b14: j */
  L_0b19: if (((a5 >> 6) & 1) == 0) goto L_0b3d;  /* 0b19: bbci a5, 6, b3d <esp_mesh_txupQ_pending+0xa5d> */
  L_0b1c: a3 = (u32)&mesh_conn_leave + 0x0;  /* 0b1c: l32r -> global */
  a4 = a4 << 6;  /* 0b1f */
  a4 = a3 + a4;  /* 0b22 */
  a3 = LD8U(a4 + 0x10);  /* 0b24 */
  a3 = a3 + (-1);  /* 0b27 */
  a8 = LD32(a1 + 0x60);  /* 0b29 */
  ST8(a4 + 0x10, a3);  /* 0b2c */
  __asm__ volatile("" ::: "memory");  /* 0b2f: memw */
  ST32(a4 + 0xc, a8);  /* 0b32 */
  __asm__ volatile("" ::: "memory");  /* 0b34: memw */
  goto L_0c19;  /* 0b37: j */
  L_0b3d: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0b3d: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 0b40 */
  if (a6 == 0) goto L_0c19;  /* 0b43: beqz a6, c19 <esp_mesh_txupQ_pending+0xb39> */
  L_0b46: a5 = LD32(a6 + 0x150);  /* 0b46 */
  if (a5 == 0) goto L_0c19;  /* 0b49: beqz a5, c19 <esp_mesh_txupQ_pending+0xb39> */
  L_0b4c: a10 = LD32(a6 + 0x158);  /* 0b4c */
  a6 = a4 << 6;  /* 0b4f */
  /* 0b52: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0b55 */
  a10 = a3;  /* 0b57 */
  ST32(a1 + 0x94, a13);  /* 0b59 */
  __asm__ volatile("" ::: "memory");  /* 0b5c: memw */
  a8 = (u32)&txq_opr2str + 0x0;  /* 0b5f: l32r -> global */
  a2 = txq_opr2str(a2, a3, a4, a5, a6);  /* 0b62: callx a8 via reloc-expand */
  a3 = LD8U(a7 + 0x10);  /* 0b65 */
  ST32(a1 + 0x78, a3);  /* 0b68 */
  a3 = (u32)&g_mesh_conn + 0x0;  /* 0b6b: l32r -> global */
  a3 = a3 + a6;  /* 0b6e */
  a9 = LD8U(a7 + 0xc);  /* 0b70 */
  a15 = LD8U(a7 + 0xf);  /* 0b73 */
  a11 = LD8U(a7 + 0xd);  /* 0b76 */
  a12 = LD8U(a7 + 0xe);  /* 0b79 */
  ST32(a1 + 0x6c, a9);  /* 0b7c */
  a6 = LD32(a3 + 0x8);  /* 0b7f */
  a9 = LD32(a1 + 0x60);  /* 0b81 */
  ST32(a1 + 0x74, a15);  /* 0b84 */
  ST32(a1 + 0x64, a11);  /* 0b87 */
  ST32(a1 + 0x70, a12);  /* 0b8a */
  a15 = LD8U(a7 + 0x11);  /* 0b8d */
  a8 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0b90: -> "self" */
  a13 = LD32(a1 + 0x94);  /* 0b93 */
  if (a6 >= a9) goto L_0b9c;  /* 0b96: bgeu a6, a9, b9c <esp_mesh_txupQ_pending+0xabc> */
  L_0b99: a8 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0b99: -> "self" */
  L_0b9c: a11 = LD32(a1 + 0x68);  /* 0b9c */
  a3 = a11 + (18);  /* 0b9f */
  a11 = a11 + (14);  /* 0ba2 */
  a3 = LD32(a3 + 0x0);  /* 0ba4 */
  a3 = (a3 >> 5) & 0x3ff;  /* 0ba6: extui width 10 */
  a12 = LD32(a11 + 0x14);  /* 0ba9 */
  a11 = LD32(a7 + 0x28);  /* 0bab */
  a9 = LD16U(a7 + 0x4);  /* 0bad */
  a7 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0bb0: -> "self" */
  if (((a11 >> 5) & 1) != 0) goto L_0bb9;  /* 0bb3: bbsi a11, 5, bb9 <esp_mesh_txupQ_pending+0xad9> */
  L_0bb6: a7 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0bb6: -> "no window" */
  L_0bb9: a14 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0bb9: -> "self" */
  if (((a11 >> 6) & 1) != 0) goto L_0bc2;  /* 0bbc: bbsi a11, 6, bc2 <esp_mesh_txupQ_pending+0xae2> */
  L_0bbf: a14 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0bbf: -> "no window" */
  L_0bc2: ST32(a1 + 0x3c, a3);  /* 0bc2 */
  a3 = LD32(a1 + 0x60);  /* 0bc4 */
  ST32(a1 + 0x40, a12);  /* 0bc7 */
  ST32(a1 + 0x34, a3);  /* 0bca */
  a12 = LD32(a1 + 0x64);  /* 0bcc */
  a3 = LD32(a1 + 0x80);  /* 0bcf */
  ST32(a1 + 0x28, a15);  /* 0bd2 */
  a15 = LD32(a1 + 0x6c);  /* 0bd4 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0bd7: -> "mesh" */
  ST32(a1 + 0x38, a9);  /* 0bda */
  ST32(a1 + 0x30, a8);  /* 0bdc */
  a9 = LD32(a1 + 0x70);  /* 0bde */
  a8 = LD32(a1 + 0x74);  /* 0be1 */
  ST32(a1 + 0x2c, a6);  /* 0be4 */
  ST32(a1 + 0x10, a4);  /* 0be6 */
  a6 = LD32(a1 + 0x78);  /* 0be8 */
  a4 = LD32(a1 + 0x7c);  /* 0beb */
  ST32(a1 + 0x18, a12);  /* 0bee */
  ST32(a1 + 0x14, a15);  /* 0bf0 */
  ST32(a1 + 0x8, a3);  /* 0bf2 */
  a3 = 0x6e8;  /* 0bf4 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0bf7: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_txupQ_pending_str1_1 + 0x0);  /* 0bfa: -> "self" */
  ST32(a1 + 0x48, a14);  /* 0bfd */
  a14 = a11;  /* 0c00 */
  ST32(a1 + 0xc, a10);  /* 0c02 */
  a10 = 2;  /* 0c04 */
  ST32(a1 + 0x44, a7);  /* 0c06 */
  ST32(a1 + 0x24, a6);  /* 0c09 */
  ST32(a1 + 0x20, a8);  /* 0c0b */
  ST32(a1 + 0x1c, a9);  /* 0c0d */
  ST32(a1 + 0x4, a4);  /* 0c0f */
  ST32(a1 + 0x0, a3);  /* 0c11 */
  __asm__ volatile("" ::: "memory");  /* 0c13: memw */
  /* 0c16: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_0c19: a12 = 0x6f0;  /* 0c19 */
  a3 = (u32)&mesh_conn_mutex + 0x0;  /* 0c1c: l32r -> global */
  a11 = (u32)(RODATA__rodata___func___13 + 0x0);  /* 0c1f: l32r -> .rodata.__func__$13 */
  a10 = LD32(a3 + 0x0);  /* 0c22 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0c24: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6);  /* 0c27: callx a8 via reloc-expand */
  goto L_0c3c;  /* 0c2a: j */
  L_0c2d: a10 = LD32(a5 + 0x0);  /* 0c2d */
  a12 = 0x6f5;  /* 0c2f */
  a11 = a6;  /* 0c32 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0c34: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6);  /* 0c37: callx a8 via reloc-expand */
  a2 = -1;  /* 0c3a */
  L_0c3c: return a2;  /* 0c3c: retw.n */
}


/* esp_mesh_txupQ_pending_clear_xonseq @ mesh_schedule.o 00000018 size 68B bind GLOBAL
 * Calls: mesh_mutex_lock, esp_mesh_get_child_idx, mesh_mutex_unlock | Data refs: mesh_conn_mutex, .rodata.__func__$15, g_mesh_conn
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=6); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_txupQ_pending_clear_xonseq(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&mesh_conn_mutex + 0x0;  /* 001b: l32r -> global */
  a12 = 0x5d4;  /* 001e */
  a4 = (u32)(RODATA__rodata___func___15 + 0x0);  /* 0021: -> "esp_mesh_txupQ_pending_clear_xonseq" */
  a11 = a4;  /* 0024 */
  a10 = LD32(a3 + 0x0);  /* 0026 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 0028: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 002b: callx a8 via reloc-expand */
  a10 = a2;  /* 002e */
  a8 = (u32)&esp_mesh_get_child_idx + 0x0;  /* 0030: l32r -> global */
  a2 = esp_mesh_get_child_idx(a2, a3, a4, a5, a6, a7);  /* 0033: callx a8 via reloc-expand */
  a10 = (i32)(a10 << (32 - 7)) >> (32 - 7);  /* 0036: sext */
  if (a10 == -1) goto L_0048;  /* 0039: beqi a10, -1, 48 <esp_mesh_txupQ_pending_clear_xonseq+0x30> */
  L_003c: a8 = (u32)&g_mesh_conn + 0x0;  /* 003c: l32r -> global */
  a10 = a10 << 6;  /* 003f */
  a8 = a8 + a10;  /* 0042 */
  a9 = 0;  /* 0044 */
  ST32(a8 + 0x8, a9);  /* 0046 */
  L_0048: a12 = 0x5d9;  /* 0048 */
  a11 = a4;  /* 004b */
  a2 = 0;  /* 004d */
  a10 = LD32(a3 + 0x0);  /* 004f */
  __asm__ volatile("" ::: "memory");  /* 0051: memw */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0054: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 0057: callx a8 via reloc-expand */
  return a2;  /* 005a: retw.n */
}


/* esp_mesh_txupQ_pending_delete_child @ mesh_schedule.o 00000008 size 51B bind GLOBAL
 * Calls: memset | Data refs: mesh_conn_leave
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_txupQ_pending_delete_child(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a10 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 000b: sext */
  a9 = a10 + (1);  /* 000e */
  a2 = 0;  /* 0010 */
  a8 = 1;  /* 0012 */
  if (a9 != 0) a8 = a2;  /* 0014 */
  a2 = (a8 >> 8) & 0x1;  /* 0017: extui width 1 */
  if (a8 != 0) goto L_0037;  /* 001a: bnez.n a8, 37 <esp_mesh_txupQ_pending_delete_child+0x2f> */
  L_001c: a8 = 9;  /* 001c */
  if ((i32)a8 < (i32)a10) goto L_0037;  /* 001e: blt a8, a10, 37 <esp_mesh_txupQ_pending_delete_child+0x2f> */
  L_0021: a8 = (u32)&mesh_conn_leave + 0x0;  /* 0021: l32r -> global */
  a10 = a10 << 6;  /* 0024 */
  a12 = 64;  /* 0027 */
  a11 = a2;  /* 0029 */
  a10 = a8 + a10;  /* 002b */
  a8 = (u32)&memset + 0x0;  /* 002e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0031: callx a8 (libc, via reloc-expand) */
  goto L_0039;  /* 0034: j */
  L_0037: a2 = -1;  /* 0037 */
  L_0039: return a2;  /* 0039: retw.n */
}


/* esp_mesh_txupQ_pending_get_cidx @ mesh_schedule.o 0000000c size 97B bind GLOBAL
 * Calls: memcmp | Data refs: mesh_conn_leave
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_txupQ_pending_get_cidx(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a3 = 255;  /* 000f */
  if (a2 == 0) goto L_0069;  /* 0012: beqz a2, 69 <esp_mesh_txupQ_pending_get_cidx+0x5d> */
  L_0015: a4 = (u32)&mesh_conn_leave + 0x0;  /* 0015: l32r -> global */
  a3 = 0;  /* 0018 */
  a5 = 6;  /* 001a */
  L_001c: a8 = LD8U(a4 + 0x10);  /* 001c */
  if (a8 == 0) goto L_005e;  /* 001f: beqz.n a8, 5e <esp_mesh_txupQ_pending_get_cidx+0x52> */
  L_0021: a12 = a5;  /* 0021 */
  a11 = a4;  /* 0023 */
  a10 = a2;  /* 0025 */
  a8 = (u32)&memcmp + 0x0;  /* 0027: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 002a: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0032;  /* 002d: bnez.n a10, 32 <esp_mesh_txupQ_pending_get_cidx+0x26> */
  L_002f: goto L_0058;  /* 002f: j */
  L_0032: a8 = LD32(a4 + 0x0);  /* 0032 */
  a12 = a5;  /* 0034 */
  a11 = a1;  /* 0036 */
  a10 = a2;  /* 0038 */
  a9 = LD16U(a4 + 0x4);  /* 003a */
  ST32(a1 + 0x0, a8);  /* 003d */
  a8 = (a9 >> 8) & 0x1ff;  /* 003f: extui width 9 */
  a8 = a8 + (1);  /* 0042 */
  ST16(a1 + 0x4, a9);  /* 0044 */
  ST8(a1 + 0x5, a8);  /* 0047 */
  __asm__ volatile("" ::: "memory");  /* 004a: memw */
  __asm__ volatile("" ::: "memory");  /* 004d: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0050: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0053: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_005e;  /* 0056: bnez.n a10, 5e <esp_mesh_txupQ_pending_get_cidx+0x52> */
  L_0058: a3 = (a3 >> 8) & 0x1;  /* 0058: extui width 1 */
  goto L_0069;  /* 005b: j */
  L_005e: a3 = a3 + (1);  /* 005e */
  a4 = a4 + (64);  /* 0060 */
  if (a3 != 10) goto L_001c;  /* 0063: bnei a3, 10, 1c <esp_mesh_txupQ_pending_get_cidx+0x10> */
  L_0066: a3 = 255;  /* 0066 */
  L_0069: a2 = a3;  /* 0069 */
  return a2;  /* 006b: retw.n */
}


/* esp_mesh_txupQ_pending_get_xonseq @ mesh_schedule.o 00000008 size 80B bind GLOBAL
 * Calls: memcpy | Data refs: mesh_conn_leave
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_txupQ_pending_get_xonseq(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 000b: sext */
  a11 = 0;  /* 000e */
  a12 = a8 + (1);  /* 0010 */
  a2 = 1;  /* 0012 */
  a9 = a11;  /* 0014 */
  if (a12 == 0) a9 = a2;  /* 0016 */
  a12 = 9;  /* 0019 */
  a10 = a3;  /* 001b: mov */
  if ((i32)a12 < (i32)a8) goto L_0024;  /* 001e: blt a12, a8, 24 <esp_mesh_txupQ_pending_get_xonseq+0x1c> */
  L_0021: a2 = a11;  /* 0021: mov */
  L_0024: a9 = a9 | a2;  /* 0024 */
  a9 = (a9 >> 8) & 0x1;  /* 0027: extui width 1 */
  if (a9 != 0) goto L_0054;  /* 002a: bnez.n a9, 54 <esp_mesh_txupQ_pending_get_xonseq+0x4c> */
  L_002c: a2 = 1;  /* 002c */
  if (a10 != 0) a2 = a9;  /* 002e */
  if (a2 != 0) goto L_0054;  /* 0031: bnez.n a2, 54 <esp_mesh_txupQ_pending_get_xonseq+0x4c> */
  L_0033: a11 = (u32)&mesh_conn_leave + 0x0;  /* 0033: l32r -> global */
  a9 = a8 << 6;  /* 0036 */
  a9 = a11 + a9;  /* 0039 */
  a9 = LD8U(a9 + 0x10);  /* 003b */
  if (a9 == 0) goto L_0056;  /* 003e: beqz.n a9, 56 <esp_mesh_txupQ_pending_get_xonseq+0x4e> */
  L_0040: a8 = a8 << 6;  /* 0040 */
  a8 = a8 + (8);  /* 0043 */
  a12 = 12;  /* 0045 */
  a11 = a11 + a8;  /* 0047 */
  a8 = (u32)&memcpy + 0x0;  /* 004a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 004d: callx a8 (libc, via reloc-expand) */
  goto L_0056;  /* 0050: j */
  L_0054: a2 = -1;  /* 0054 */
  L_0056: return a2;  /* 0056: retw.n */
}


/* esp_mesh_txupQ_pending_insert_child @ mesh_schedule.o 00000020 size 116B bind GLOBAL
 * Calls: memcpy | indirect[2]: mem[a3+0x158]; mem[a3+0x150] | Data refs: mesh_conn_leave, g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=6); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_txupQ_pending_insert_child(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  a9 = (u32)&mesh_conn_leave + 0x0;  /* 0023: l32r -> global */
  a8 = 0;  /* 0026 */
  a10 = a9;  /* 0028 */
  a12 = 10;  /* 002a */
  if (a2 != a8) goto L_006c;  /* 002c: bne a2, a8, 6c <esp_mesh_txupQ_pending_insert_child+0x4c> */
  L_002f: a2 = (u32)&g_log_level + 0x0;  /* 002f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0032 */
  a2 = 0x00004008u;  /* 0034: l32r = 16392 */
  if (a3 < 3u) goto L_0092;  /* 0037: bltui a3, 3, 92 <esp_mesh_txupQ_pending_insert_child+0x72> */
  L_003a: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 003a: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 003d */
  if (a3 == a8) goto L_0092;  /* 003f: beq a3, a8, 92 <esp_mesh_txupQ_pending_insert_child+0x72> */
  L_0042: a4 = LD32(a3 + 0x150);  /* 0042 */
  if (a4 == a8) goto L_0092;  /* 0045: beq a4, a8, 92 <esp_mesh_txupQ_pending_insert_child+0x72> */
  L_0048: a10 = LD32(a3 + 0x158);  /* 0048 */
  a3 = 0x5b1;  /* 004b */
  /* 004e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0051 */
  a10 = 3;  /* 0053 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0055: -> "mesh" */
  a14 = a11;  /* 0058 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 005a: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 005d: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 0060 */
  __asm__ volatile("" ::: "memory");  /* 0062: memw */
  /* 0065: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0092;  /* 0068: j */
  L_006c: a3 = LD8U(a9 + 0x10);  /* 006c */
  if (a3 == 0) goto L_0081;  /* 006f: beqz.n a3, 81 <esp_mesh_txupQ_pending_insert_child+0x61> */
  L_0071: a8 = a8 + (1);  /* 0071 */
  a9 = a9 + (64);  /* 0073 */
  a12 = a12 + (-1);  /* 0076 */
  if (a12 != 0) goto L_006c;  /* 0078: bnez a12, 6c <esp_mesh_txupQ_pending_insert_child+0x4c> */
  L_007b: a2 = 0;  /* 007b */
  goto L_0092;  /* 007d: j */
  L_0081: a8 = a8 << 6;  /* 0081 */
  a11 = a2;  /* 0084 */
  a12 = 64;  /* 0086 */
  a10 = a10 + a8;  /* 0088 */
  a8 = (u32)&memcpy + 0x0;  /* 008a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 008d: callx a8 (libc, via reloc-expand) */
  a2 = a3;  /* 0090 */
  L_0092: return a2;  /* 0092: retw.n */
}


/* mesh_check_tid_mbox_full @ mesh_schedule.o 0000003c size 398B bind GLOBAL
 * Calls: print_txupQ_pending, esp_mesh_print_txQ_waiting | indirect[4]: mem[a3+0x78]; mem[a8+0x158]; mem[a7+0x78]; unknown | Data refs: .bss.mesh_tx_mbox, g_mesh_topology, g_osi_funcs_p, .rodata.mesh_check_tid_mbox_full, g_mesh_xon_cfg_qsize, .rodata.__func__$20, g_mesh_ext_cfg, g_log_level, .rodata.mesh_check_tid_mbox_full.str1.1, .rodata.mesh_print_txQ_waiting.str1.1
 * Fidelity: low - jump-table switch present; cases not recovered
 * Edges: funcdb-v3 (calls=2, refs=12); reloc-direct=2, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_check_tid_mbox_full(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a5, a6, a7, a8, a9;
  /* 003c: entry a1, 96 (frame 96 bytes) */
  a5 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 003f: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a3 = a2 + (a2 << 1);  /* 0042 */
  a3 = a3 + (a5 << 2);  /* 0045 */
  a9 = LD32(a3 + 0x0);  /* 0048 */
  a3 = -1;  /* 004a */
  if (a9 == 0) goto L_01c6;  /* 004c: beqz a9, 1c6 <mesh_check_tid_mbox_full+0x18a> */
  L_004f: a3 = 33;  /* 004f */
  a8 = 28;  /* 0051 */
  a11 = (u32)&g_mesh_topology + 0x0;  /* 0053: l32r -> global */
  a10 = a9;  /* 0056 */
  a6 = LD32(a11 + 0x0);  /* 0058 */
  if (a6 != 0) a8 = a3;  /* 005a */
  a7 = (u32)&g_osi_funcs_p + 0x0;  /* 005d: l32r -> global */
  a3 = LD32(a7 + 0x0);  /* 0060 */
  a3 = LD32(a3 + 0x78);  /* 0062 */
  a5 = LD32(a4 + 0x0);  /* 0065 */
  ST32(a1 + 0x34, a8);  /* 0067 */
  ST32(a1 + 0x38, a9);  /* 0069 */
  ST32(a1 + 0x30, a11);  /* 006b */
  __asm__ volatile("" ::: "memory");  /* 006e: memw */
  /* 0071: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a3 = 13;  /* 0074 */
  a6 = a10;  /* 0076 */
  a8 = LD32(a1 + 0x34);  /* 0078 */
  a9 = LD32(a1 + 0x38);  /* 007a */
  a11 = LD32(a1 + 0x30);  /* 007c */
  if (a3 < a2) goto L_008c;  /* 007e: bltu a3, a2, 8c <mesh_check_tid_mbox_full+0x50> */
  L_0081: a3 = (u32)(RODATA__rodata_mesh_check_tid_mbox_full + 0x0);  /* 0081: l32r -> .rodata.mesh_check_tid_mbox_full */
  a3 = a2 + (a3 << 2);  /* 0084 */
  a3 = LD32(a3 + 0x0);  /* 0087 */
  /* 0089: jx a3 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  L_008c: a3 = 0;  /* 008c */
  goto L_01b1;  /* 008e: j */
  a3 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0092: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0095 */
  if ((i32)a10 >= (i32)a3) goto L_009d;  /* 0097: bge a10, a3, 9d <mesh_check_tid_mbox_full+0x61> */
  L_009a: goto L_01c0;  /* 009a: j */
  L_009d: if (a2 != 0) goto L_00ad;  /* 009d: bnez.n a2, ad <mesh_check_tid_mbox_full+0x71> */
  L_009f: a12 = 0x237;  /* 009f */
  a11 = (u32)(RODATA__rodata___func___20 + 0x0);  /* 00a2: l32r -> .rodata.__func__$20 */
  a10 = a2;  /* 00a5 */
  a8 = (u32)&print_txupQ_pending + 0x0;  /* 00a7: l32r -> global */
  a2 = print_txupQ_pending(a2, a3, a4);  /* 00aa: callx a8 via reloc-expand */
  L_00ad: a8 = (u32)&esp_mesh_print_txQ_waiting;  /* 00ad: l32r -> func addr */
  a2 = esp_mesh_print_txQ_waiting(a2, a3, a4);  /* 00b0: callx a8 via reloc-expand */
  if ((i32)a3 >= 2) goto L_00b9;  /* 00b3: bgei a3, 2, b9 <mesh_check_tid_mbox_full+0x7d> */
  L_00b6: goto L_01b9;  /* 00b6: j */
  L_00b9: goto L_01a8;  /* 00b9: j */
  a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 00bc: l32r -> global */
  a3 = LD8U(a2 + 0xbd);  /* 00bf */
  a3 = a3 + (16);  /* 00c2 */
  a3 = a3 + a3;  /* 00c5 */
  if ((i32)a10 >= (i32)a3) goto L_00cd;  /* 00c7: bge a10, a3, cd <mesh_check_tid_mbox_full+0x91> */
  L_00ca: goto L_01a8;  /* 00ca: j */
  L_00cd: a2 = a5 + (18);  /* 00cd */
  a12 = LD32(a2 + 0x0);  /* 00d0 */
  if (((a12 >> 24) & 1) == 0) goto L_00e9;  /* 00d2: bbci a12, 24, e9 <mesh_check_tid_mbox_full+0xad> */
  L_00d5: a10 = 28;  /* 00d5 */
  a13 = 33;  /* 00d7 */
  a14 = LD32(a11 + 0x0);  /* 00da */
  if (a14 != 0) a10 = a13;  /* 00dd */
  a2 = LD8U(a5 + 0xf);  /* 00e0 */
  a2 = a2 - a10;  /* 00e3: subx4 */
  if (a2 >= 4u) goto L_0105;  /* 00e6: bgeui a2, 4, 105 <mesh_check_tid_mbox_full+0xc9> */
  L_00e9: if (((a12 >> 23) & 1) != 0) goto L_00ef;  /* 00e9: bbsi a12, 23, ef <mesh_check_tid_mbox_full+0xb3> */
  L_00ec: goto L_01a8;  /* 00ec: j */
  L_00ef: a12 = LD32(a11 + 0x0);  /* 00ef */
  a10 = 28;  /* 00f1 */
  a11 = 33;  /* 00f3 */
  if (a12 != 0) a10 = a11;  /* 00f6 */
  a2 = LD8U(a5 + 0xf);  /* 00f9 */
  a2 = a2 - a10;  /* 00fc: subx4 */
  if (a2 >= 3u) goto L_0105;  /* 00ff: bgeui a2, 3, 105 <mesh_check_tid_mbox_full+0xc9> */
  L_0102: goto L_01a8;  /* 0102: j */
  L_0105: a8 = a5 + a8;  /* 0105 */
  a2 = LD8U(a8 + 0xe);  /* 0107 */
  if (a2 == 4) goto L_0110;  /* 010a: beqi a2, 4, 110 <mesh_check_tid_mbox_full+0xd4> */
  L_010d: goto L_01a8;  /* 010d: j */
  L_0110: a2 = (u32)&g_log_level + 0x0;  /* 0110: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0113 */
  if (a2 >= 3u) goto L_011b;  /* 0115: bgeui a2, 3, 11b <mesh_check_tid_mbox_full+0xdf> */
  L_0118: goto L_01a8;  /* 0118: j */
  L_011b: a8 = LD32(a7 + 0x0);  /* 011b */
  if (a8 == 0) goto L_01a8;  /* 011d: beqz a8, 1a8 <mesh_check_tid_mbox_full+0x16c> */
  L_0120: a2 = LD32(a8 + 0x150);  /* 0120 */
  if (a2 == 0) goto L_01a8;  /* 0123: beqz a2, 1a8 <mesh_check_tid_mbox_full+0x16c> */
  L_0126: a10 = LD32(a8 + 0x158);  /* 0126 */
  ST32(a1 + 0x38, a9);  /* 0129 */
  __asm__ volatile("" ::: "memory");  /* 012c: memw */
  /* 012f: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0132 */
  a10 = LD32(a4 + 0x28);  /* 0134 */
  a8 = (u32)(RODATA__rodata_mesh_check_tid_mbox_full_str1_1 + 0x0);  /* 0136: -> "xmit" */
  a9 = LD32(a1 + 0x38);  /* 0139 */
  if (((a10 >> 0) & 1) != 0) goto L_0141;  /* 013b: bbsi a10, 0, 141 <mesh_check_tid_mbox_full+0x105> */
  L_013e: a8 = (u32)(RODATA__rodata_mesh_check_tid_mbox_full_str1_1 + 0x0);  /* 013e: -> "xmit" */
  L_0141: a10 = a9;  /* 0141 */
  a5 = a5 + (14);  /* 0143 */
  a7 = LD32(a7 + 0x0);  /* 0145 */
  a7 = LD32(a7 + 0x78);  /* 0147 */
  ST32(a1 + 0x34, a8);  /* 014a */
  ST32(a1 + 0x30, a13);  /* 014c */
  __asm__ volatile("" ::: "memory");  /* 014f: memw */
  /* 0152: INDIRECT callx a7 <- mem[a7+0x78]; result unknown */ a2 = 0;
  a15 = 0x241;  /* 0155 */
  a5 = LD32(a5 + 0x14);  /* 0158 */
  ST32(a1 + 0x24, a5);  /* 015a */
  a5 = LD8U(a4 + 0x11);  /* 015c */
  ST32(a1 + 0x20, a5);  /* 015f */
  a5 = LD8U(a4 + 0x10);  /* 0161 */
  ST32(a1 + 0x1c, a5);  /* 0164 */
  a5 = LD8U(a4 + 0xf);  /* 0166 */
  ST32(a1 + 0x18, a5);  /* 0169 */
  a5 = LD8U(a4 + 0xe);  /* 016b */
  ST32(a1 + 0x14, a5);  /* 016e */
  a5 = LD8U(a4 + 0xd);  /* 0170 */
  ST32(a1 + 0x10, a5);  /* 0173 */
  a4 = LD8U(a4 + 0xc);  /* 0175 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0178: -> "mesh" */
  a14 = a11;  /* 017b */
  a8 = LD32(a1 + 0x34);  /* 017d */
  a13 = LD32(a1 + 0x30);  /* 017f */
  a12 = (u32)(RODATA__rodata_mesh_check_tid_mbox_full_str1_1 + 0x0);  /* 0181: -> "xmit" */
  ST32(a1 + 0x4, a10);  /* 0184 */
  a10 = 3;  /* 0186 */
  ST32(a1 + 0xc, a4);  /* 0188 */
  ST32(a1 + 0x8, a3);  /* 018a */
  ST32(a1 + 0x0, a8);  /* 018c */
  __asm__ volatile("" ::: "memory");  /* 018e: memw */
  /* 0191: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  goto L_01a8;  /* 0194: j */
  a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0197: l32r -> global */
  a2 = LD8U(a2 + 0xbd);  /* 019a */
  a2 = a2 + a2;  /* 019d */
  a3 = a2 + (1);  /* 019f */
  if (a2 == 0) goto L_01b1;  /* 01a1: beqz.n a2, 1b1 <mesh_check_tid_mbox_full+0x175> */
  L_01a3: goto L_01a8;  /* 01a3: j */
  a3 = 32;  /* 01a6 */
  L_01a8: a3 = a3 + (-1);  /* 01a8 */
  goto L_01b1;  /* 01aa: j */
  a3 = 1;  /* 01af */
  L_01b1: if ((i32)a6 >= (i32)a3) goto L_01b9;  /* 01b1: bge a6, a3, 1b9 <mesh_check_tid_mbox_full+0x17d> */
  L_01b4: a3 = 0;  /* 01b4 */
  goto L_01c6;  /* 01b6: j */
  L_01b9: a3 = 0x0000400du;  /* 01b9: l32r = 16397 */
  goto L_01c6;  /* 01bc: j */
  L_01c0: if ((i32)a3 < 2) goto L_01b4;  /* 01c0: blti a3, 2, 1b4 <mesh_check_tid_mbox_full+0x178> */
  L_01c3: goto L_01a8;  /* 01c3: j */
  L_01c6: a2 = a3;  /* 01c6 */
  return a2;  /* 01c8: retw.n */
}


/* mesh_flush_txQ @ mesh_schedule.o 00000024 size 262B bind GLOBAL
 * Calls: mesh_mutex_lock, esp_mesh_free_context, mesh_mutex_unlock | indirect[3]: mem[a5+0x74]; mem[a6+0x74] | Data refs: .bss.mesh_tx_mbox, .rodata.__func__$11, g_osi_funcs_p
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=6); reloc-direct=3, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_flush_txQ(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a3, a4, a5, a6, a7, a8;
  float F9;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a3 = 0;  /* 0027 */
  a2 = (a2 >> 8) & 0x1;  /* 0029: extui width 1 */
  ST32(a1 + 0x4, a3);  /* 002c */
  a5 = 8;  /* 002e */
  ST32(a1 + 0x0, a3);  /* 0030 */
  a3 = a2 + a2;  /* 0032 */
  a4 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0034: l32r -> .bss.mesh_tx_mbox (same-object static) */
  if (a5 >= a2) goto L_004c;  /* 0037: bgeu a5, a2, 4c <mesh_flush_txQ+0x28> */
  L_003a: a3 = a3 + a2;  /* 003a */
  a2 = a2 + (-10);  /* 003c */
  a3 = a3 + (a4 << 2);  /* 003f */
  a2 = (a2 >> 8) & 0x1;  /* 0042: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 0045: memw */
  goto L_0111;  /* 0048: j */
  L_004c: a5 = a3 + a2;  /* 004c */
  a6 = (u32)(RODATA__rodata___func___11 + 0x0);  /* 004e: l32r -> .rodata.__func__$11 */
  a7 = a5 << 2;  /* 0051 */
  a5 = a5 + (a4 << 2);  /* 0054 */
  a12 = 0x73b;  /* 0057 */
  a11 = a6;  /* 005a */
  a10 = LD32(a5 + 0x4);  /* 005c */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 005e: l32r -> global */
  a2 = mesh_mutex_lock(a2);  /* 0061: callx a8 via reloc-expand */
  goto L_007a;  /* 0064: j */
  L_0069: a10 = LD32(a1 + 0x4);  /* 0069 */
  a12 = 0x741;  /* 006b */
  a11 = a6;  /* 006e */
  a5 = 0;  /* 0070 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0072: l32r -> global */
  a2 = esp_mesh_free_context(a2);  /* 0075: callx a8 via reloc-expand */
  ST32(a1 + 0x4, a5);  /* 0078 */
  L_007a: a5 = a4 + a7;  /* 007a */
  a10 = LD32(a5 + 0x0);  /* 007c */
  if (a10 != 0) goto L_0099;  /* 007e: bnez.n a10, 99 <mesh_flush_txQ+0x75> */
  L_0080: a2 = a3 + a2;  /* 0080 */
  a2 = a2 + (a4 << 2);  /* 0082 */
  a10 = LD32(a2 + 0x4);  /* 0085 */
  a12 = 0x744;  /* 0087 */
  a11 = a6;  /* 008a */
  __asm__ volatile("" ::: "memory");  /* 008c: memw */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 008f: l32r -> global */
  a2 = mesh_mutex_unlock(a2);  /* 0092: callx a8 via reloc-expand */
  goto L_0128;  /* 0095: j */
  L_0099: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0099: l32r -> global */
  a12 = 0;  /* 009c */
  a11 = a1 + (4);  /* 009e */
  a5 = LD32(a5 + 0x0);  /* 00a0 */
  a5 = LD32(a5 + 0x74);  /* 00a2 */
  /* 00a5: INDIRECT callx a5 <- mem[a5+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_0069;  /* 00a8: beqi a10, 1, 69 <mesh_flush_txQ+0x45> */
  L_00ab: goto L_0080;  /* 00ab: j */
  L_00ae: if (a2 >= 2u) goto L_0111;  /* 00ae: bgeui a2, 2, 111 <mesh_flush_txQ+0xed> */
  L_00b1: a8 = LD32(a1 + 0x0);  /* 00b1 */
  a12 = 0x74c;  /* 00b3 */
  a8 = a8 + (a8 << 1);  /* 00b6 */
  a8 = a8 + (a4 << 2);  /* 00b9 */
  a5 = (u32)(RODATA__rodata___func___11 + 0x0);  /* 00bc: l32r -> .rodata.__func__$11 */
  a11 = a5;  /* 00bf */
  a10 = LD32(a8 + 0x4);  /* 00c1 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 00c3: l32r -> global */
  a2 = mesh_mutex_lock(a2);  /* 00c6: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x0);  /* 00c9 */
  a8 = a8 + (a8 << 1);  /* 00cb */
  a8 = a8 + (a4 << 2);  /* 00ce */
  a10 = LD32(a8 + 0x0);  /* 00d1 */
  if (a10 == 0) goto L_00f9;  /* 00d3: beqz.n a10, f9 <mesh_flush_txQ+0xd5> */
  L_00d5: a12 = 0;  /* 00d5 */
  a11 = a1 + (4);  /* 00d7 */
  a6 = LD32(a6 + 0x0);  /* 00d9 */
  a6 = LD32(a6 + 0x74);  /* 00db */
  /* 00de: INDIRECT callx a6 <- mem[a6+0x74]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_00f9;  /* 00e1: bnei a10, 1, f9 <mesh_flush_txQ+0xd5> */
  L_00e4: a12 = 0x753;  /* 00e4 */
  a10 = LD32(a1 + 0x4);  /* 00e7 */
  a11 = a5;  /* 00ea: mov */
  a6 = 0;  /* 00ed */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 00f0: l32r -> global */
  a2 = esp_mesh_free_context(a2);  /* 00f3: callx a8 via reloc-expand */
  ST32(a1 + 0x4, a6);  /* 00f6 */
  L_00f9: a12 = 0x756;  /* 00f9 */
  a11 = a5;  /* 00fc */
  a8 = LD32(a1 + 0x0);  /* 00fe */
  a8 = a8 + (a8 << 1);  /* 0100 */
  a8 = a8 + (a4 << 2);  /* 0103 */
  a10 = LD32(a8 + 0x4);  /* 0106 */
  __asm__ volatile("" ::: "memory");  /* 0108: memw */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 010b: l32r -> global */
  a2 = mesh_mutex_unlock(a2);  /* 010e: callx a8 via reloc-expand */
  L_0111: a10 = LD32(a3 + 0x0);  /* 0111 */
  if (a10 == 0) goto L_0128;  /* 0113: beqz.n a10, 128 <mesh_flush_txQ+0x104> */
  L_0115: a12 = 0;  /* 0115 */
  a11 = a1;  /* 0117 */
  a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0119: l32r -> global */
  a5 = LD32(a6 + 0x0);  /* 011c */
  a5 = LD32(a5 + 0x74);  /* 011f */
  /* 0122: INDIRECT callx a5 <- mem[a5+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_00ae;  /* 0125: beqi a10, 1, ae <mesh_flush_txQ+0x8a> */
  L_0128: return a2;  /* 0128: retw.n */
}


/* mesh_flush_upstream_packets @ mesh_schedule.o 00000018 size 86B bind GLOBAL
 * Calls: mesh_xon_flush_packets | indirect[4]: mem[a3+0x78]; mem[a8+0x158]; mem[a2+0x78]; mem[a8+0x150] | Data refs: g_osi_funcs_p, .bss.mesh_tx_mbox, g_log_level, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_flush_upstream_packets.str1.1
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=6); reloc-direct=1, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_flush_upstream_packets(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 001b: l32r -> global */
  a4 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 001e: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a3 = LD32(a2 + 0x0);  /* 0021 */
  a10 = LD32(a4 + 0x0);  /* 0023 */
  a3 = LD32(a3 + 0x78);  /* 0026 */
  /* 0029: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  if (a10 == 0) goto L_006a;  /* 002c: beqz.n a10, 6a <mesh_flush_upstream_packets+0x52> */
  L_002e: a3 = (u32)&g_log_level + 0x0;  /* 002e: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0031 */
  if (a3 < 3u) goto L_0064;  /* 0033: bltui a3, 3, 64 <mesh_flush_upstream_packets+0x4c> */
  L_0036: a8 = LD32(a2 + 0x0);  /* 0036 */
  if (a8 == 0) goto L_0064;  /* 0038: beqz.n a8, 64 <mesh_flush_upstream_packets+0x4c> */
  L_003a: a3 = LD32(a8 + 0x150);  /* 003a */
  if (a3 == 0) goto L_0064;  /* 003d: beqz.n a3, 64 <mesh_flush_upstream_packets+0x4c> */
  L_003f: a10 = LD32(a8 + 0x158);  /* 003f */
  /* 0042: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 0045 */
  a2 = LD32(a2 + 0x0);  /* 0047 */
  a10 = LD32(a4 + 0x0);  /* 0049 */
  a2 = LD32(a2 + 0x78);  /* 004b */
  /* 004e: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a15 = a10;  /* 0051 */
  a13 = a5;  /* 0053 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0055: -> "mesh" */
  a10 = 3;  /* 0058 */
  a14 = a11;  /* 005b: mov */
  a12 = (u32)(RODATA__rodata_mesh_flush_upstream_packets_str1_1 + 0x0);  /* 005e: l32r -> .rodata.mesh_flush_upstream_packets.str1.1 */
  /* 0061: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0064: a8 = (u32)&mesh_xon_flush_packets;  /* 0064: l32r -> func addr */
  a2 = mesh_xon_flush_packets(a2, a3, a4, a5, a6, a7);  /* 0067: callx a8 via reloc-expand */
  L_006a: a2 = 0;  /* 006a */
  return a2;  /* 006c: retw.n */
}


/* mesh_get_tx_pending @ mesh_schedule.o 0000001c size 405B bind GLOBAL
 * Calls: none | indirect[12]: mem[a3+0x158]; mem[a3+0x150]; mem[a8+0x78]; mem[a4+0x78] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .bss.mesh_tx_mbox, .rodata.mesh_get_tx_pending.str1.1
 * Fidelity: medium - 12 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=5); reloc-direct=0, funcdb-attributed=0, unknown-indirect=12 */
u32 mesh_get_tx_pending(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  float F8;
  /* 001c: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0051;  /* 001f: bnez.n a2, 51 <mesh_get_tx_pending+0x35> */
  L_0021: a2 = (u32)&g_log_level + 0x0;  /* 0021: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0024 */
  a2 = 0x00004008u;  /* 0027: l32r = 16392 */
  if (a3 >= 3u) goto L_0030;  /* 002a: bgeui a3, 3, 30 <mesh_get_tx_pending+0x14> */
  L_002d: goto L_01ac;  /* 002d: j */
  L_0030: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0030: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0033 */
  if (a3 == 0) goto L_01ac;  /* 0036: beqz a3, 1ac <mesh_get_tx_pending+0x190> */
  L_0039: a4 = LD32(a3 + 0x150);  /* 0039 */
  if (a4 == 0) goto L_01ac;  /* 003c: beqz a4, 1ac <mesh_get_tx_pending+0x190> */
  L_003f: a10 = LD32(a3 + 0x158);  /* 003f */
  a3 = 159;  /* 0042 */
  /* 0045: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0048: -> "mesh" */
  goto L_0080;  /* 004b: j */
  L_0051: a3 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0051: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a10 = LD32(a3 + 0x0);  /* 0054 */
  if (a10 != 0) goto L_0098;  /* 0056: bnez.n a10, 98 <mesh_get_tx_pending+0x7c> */
  L_0058: a2 = (u32)&g_log_level + 0x0;  /* 0058: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005b */
  a2 = 0x00004008u;  /* 005d: l32r = 16392 */
  if (a3 >= 3u) goto L_0066;  /* 0060: bgeui a3, 3, 66 <mesh_get_tx_pending+0x4a> */
  L_0063: goto L_01ac;  /* 0063: j */
  L_0066: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0066: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0069 */
  if (a3 == 0) goto L_01ac;  /* 006b: beqz a3, 1ac <mesh_get_tx_pending+0x190> */
  L_006e: a4 = LD32(a3 + 0x150);  /* 006e */
  if (a4 == 0) goto L_01ac;  /* 0071: beqz a4, 1ac <mesh_get_tx_pending+0x190> */
  L_0074: a10 = LD32(a3 + 0x158);  /* 0074 */
  a3 = 160;  /* 0077 */
  /* 007a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 007d: -> "mesh" */
  L_0080: a13 = a10;  /* 0080 */
  a14 = a11;  /* 0082 */
  a10 = 3;  /* 0084 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0086: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0089: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 008c */
  __asm__ volatile("" ::: "memory");  /* 008e: memw */
  /* 0091: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01ac;  /* 0094: j */
  L_0098: a4 = LD32(a3 + 0xc);  /* 0098 */
  if (a4 != 0) goto L_00c8;  /* 009a: bnez.n a4, c8 <mesh_get_tx_pending+0xac> */
  L_009c: a2 = (u32)&g_log_level + 0x0;  /* 009c: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 009f */
  a2 = 0x00004008u;  /* 00a1: l32r = 16392 */
  if (a3 >= 3u) goto L_00aa;  /* 00a4: bgeui a3, 3, aa <mesh_get_tx_pending+0x8e> */
  L_00a7: goto L_01ac;  /* 00a7: j */
  L_00aa: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00aa: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00ad */
  if (a3 == 0) goto L_01ac;  /* 00af: beqz a3, 1ac <mesh_get_tx_pending+0x190> */
  L_00b2: a4 = LD32(a3 + 0x150);  /* 00b2 */
  if (a4 == 0) goto L_01ac;  /* 00b5: beqz a4, 1ac <mesh_get_tx_pending+0x190> */
  L_00b8: a10 = LD32(a3 + 0x158);  /* 00b8 */
  a3 = 161;  /* 00bb */
  /* 00be: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00c1: -> "mesh" */
  goto L_0080;  /* 00c4: j */
  L_00c8: a4 = LD32(a3 + 0x18);  /* 00c8 */
  if (a4 != 0) goto L_00f8;  /* 00ca: bnez.n a4, f8 <mesh_get_tx_pending+0xdc> */
  L_00cc: a2 = (u32)&g_log_level + 0x0;  /* 00cc: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00cf */
  a2 = 0x00004008u;  /* 00d1: l32r = 16392 */
  if (a3 >= 3u) goto L_00da;  /* 00d4: bgeui a3, 3, da <mesh_get_tx_pending+0xbe> */
  L_00d7: goto L_01ac;  /* 00d7: j */
  L_00da: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00da: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00dd */
  if (a3 == 0) goto L_01ac;  /* 00df: beqz a3, 1ac <mesh_get_tx_pending+0x190> */
  L_00e2: a4 = LD32(a3 + 0x150);  /* 00e2 */
  if (a4 == 0) goto L_01ac;  /* 00e5: beqz a4, 1ac <mesh_get_tx_pending+0x190> */
  L_00e8: a10 = LD32(a3 + 0x158);  /* 00e8 */
  a3 = 162;  /* 00eb */
  /* 00ee: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00f1: -> "mesh" */
  goto L_0080;  /* 00f4: j */
  L_00f8: a4 = LD32(a3 + 0x3c);  /* 00f8 */
  if (a4 != 0) goto L_0129;  /* 00fa: bnez.n a4, 129 <mesh_get_tx_pending+0x10d> */
  L_00fc: a2 = (u32)&g_log_level + 0x0;  /* 00fc: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ff */
  a2 = 0x00004008u;  /* 0101: l32r = 16392 */
  if (a3 >= 3u) goto L_010a;  /* 0104: bgeui a3, 3, 10a <mesh_get_tx_pending+0xee> */
  L_0107: goto L_01ac;  /* 0107: j */
  L_010a: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 010a: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 010d */
  if (a3 == 0) goto L_01ac;  /* 010f: beqz a3, 1ac <mesh_get_tx_pending+0x190> */
  L_0112: a4 = LD32(a3 + 0x150);  /* 0112 */
  if (a4 == 0) goto L_01ac;  /* 0115: beqz a4, 1ac <mesh_get_tx_pending+0x190> */
  L_0118: a10 = LD32(a3 + 0x158);  /* 0118 */
  a3 = 163;  /* 011b */
  /* 011e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0121: -> "mesh" */
  goto L_0080;  /* 0124: j */
  L_0129: a4 = LD32(a3 + 0x60);  /* 0129 */
  if (a4 != 0) goto L_0158;  /* 012c: bnez.n a4, 158 <mesh_get_tx_pending+0x13c> */
  L_012e: a2 = (u32)&g_log_level + 0x0;  /* 012e: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0131 */
  a2 = 0x00004008u;  /* 0133: l32r = 16392 */
  if (a3 < 3u) goto L_01ac;  /* 0136: bltui a3, 3, 1ac <mesh_get_tx_pending+0x190> */
  L_0139: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0139: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 013c */
  if (a3 == 0) goto L_01ac;  /* 013e: beqz a3, 1ac <mesh_get_tx_pending+0x190> */
  L_0141: a4 = LD32(a3 + 0x150);  /* 0141 */
  if (a4 == 0) goto L_01ac;  /* 0144: beqz a4, 1ac <mesh_get_tx_pending+0x190> */
  L_0147: a10 = LD32(a3 + 0x158);  /* 0147 */
  a3 = 164;  /* 014a */
  /* 014d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0150: -> "mesh" */
  goto L_0080;  /* 0153: j */
  L_0158: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0158: l32r -> global */
  a5 = 0;  /* 015b */
  a8 = LD32(a4 + 0x0);  /* 015d */
  a8 = LD32(a8 + 0x78);  /* 015f */
  ST32(a2 + 0x0, a5);  /* 0162 */
  __asm__ volatile("" ::: "memory");  /* 0164: memw */
  /* 0167: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = LD32(a4 + 0x0);  /* 016a */
  ST32(a2 + 0x4, a10);  /* 016c */
  a8 = LD32(a8 + 0x78);  /* 016e */
  a10 = LD32(a3 + 0xc);  /* 0171 */
  __asm__ volatile("" ::: "memory");  /* 0174: memw */
  /* 0177: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = LD32(a4 + 0x0);  /* 017a */
  ST32(a2 + 0x8, a10);  /* 017c */
  a8 = LD32(a8 + 0x78);  /* 017e */
  a10 = LD32(a3 + 0x18);  /* 0181 */
  __asm__ volatile("" ::: "memory");  /* 0183: memw */
  /* 0186: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = LD32(a4 + 0x0);  /* 0189 */
  ST32(a2 + 0xc, a10);  /* 018b */
  a8 = LD32(a8 + 0x78);  /* 018d */
  a10 = LD32(a3 + 0x3c);  /* 0190 */
  __asm__ volatile("" ::: "memory");  /* 0192: memw */
  /* 0195: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a4 = LD32(a4 + 0x0);  /* 0198 */
  ST32(a2 + 0x10, a10);  /* 019a */
  a4 = LD32(a4 + 0x78);  /* 019c */
  a10 = LD32(a3 + 0x60);  /* 019f */
  __asm__ volatile("" ::: "memory");  /* 01a2: memw */
  /* 01a5: INDIRECT callx a4 <- mem[a4+0x78]; result unknown */ a2 = 0;
  ST32(a2 + 0x14, a10);  /* 01a8 */
  a2 = a5;  /* 01aa */
  L_01ac: __asm__ volatile("" ::: "memory");  /* 01ac: memw */
  return a2;  /* 01af: retw.n */
}


/* mesh_print_txQ_waiting @ mesh_schedule.o 0000001c size 288B bind GLOBAL
 * Calls: none | indirect[9]: mem[a3+0x158]; mem[a4+0x78]; mem[a5+0x78]; mem[a6+0x78] | Data refs: g_log_level, g_osi_funcs_p, g_mesh_xon_cfg_qsize, .bss.mesh_tx_mbox, mesh_xon, .rodata.mesh_print_txQ_waiting.str1.1
 * Fidelity: medium - 9 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=6); reloc-direct=0, funcdb-attributed=0, unknown-indirect=9 */
u32 mesh_print_txQ_waiting(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 001c: entry a1, 128 (frame 128 bytes) */
  a2 = (u32)&g_log_level + 0x0;  /* 001f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0022 */
  if (a2 >= 3u) goto L_002b;  /* 0025: bgeui a2, 3, 2b <mesh_print_txQ_waiting+0xf> */
  L_0028: goto L_0138;  /* 0028: j */
  L_002b: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 002b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002e */
  if (a3 == 0) goto L_0138;  /* 0031: beqz a3, 138 <mesh_print_txQ_waiting+0x11c> */
  L_0034: a4 = LD32(a3 + 0x150);  /* 0034 */
  ST32(a1 + 0x40, a4);  /* 0037 */
  if (a4 == 0) goto L_0138;  /* 003a: beqz a4, 138 <mesh_print_txQ_waiting+0x11c> */
  L_003d: a4 = 0;  /* 003d */
  a10 = LD32(a3 + 0x158);  /* 003f */
  __asm__ volatile("" ::: "memory");  /* 0042: memw */
  /* 0045: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0048: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 004b */
  ST32(a1 + 0x4c, a3);  /* 004d */
  a3 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0050: l32r -> .bss.mesh_tx_mbox (same-object static) */
  ST32(a1 + 0x48, a10);  /* 0053 */
  a10 = LD32(a3 + 0x0);  /* 0056 */
  ST32(a1 + 0x44, a4);  /* 0058 */
  if (a10 == a4) goto L_006c;  /* 005b: beq a10, a4, 6c <mesh_print_txQ_waiting+0x50> */
  L_005e: a4 = LD32(a2 + 0x0);  /* 005e */
  a4 = LD32(a4 + 0x78);  /* 0060 */
  __asm__ volatile("" ::: "memory");  /* 0063: memw */
  /* 0066: INDIRECT callx a4 <- mem[a4+0x78]; result unknown */ a2 = 0;
  ST32(a1 + 0x44, a10);  /* 0069 */
  L_006c: a4 = 0;  /* 006c */
  a10 = LD32(a3 + 0xc);  /* 006e */
  if (a10 == a4) goto L_0082;  /* 0071: beq a10, a4, 82 <mesh_print_txQ_waiting+0x66> */
  L_0074: a4 = LD32(a2 + 0x0);  /* 0074 */
  a4 = LD32(a4 + 0x78);  /* 0077 */
  __asm__ volatile("" ::: "memory");  /* 007a: memw */
  /* 007d: INDIRECT callx a4 <- mem[a4+0x78]; result unknown */ a2 = 0;
  a4 = a10;  /* 0080 */
  L_0082: a5 = 0;  /* 0082 */
  a10 = LD32(a3 + 0x18);  /* 0084 */
  if (a10 == a5) goto L_0094;  /* 0086: beq a10, a5, 94 <mesh_print_txQ_waiting+0x78> */
  L_0089: a5 = LD32(a2 + 0x0);  /* 0089 */
  a5 = LD32(a5 + 0x78);  /* 008c */
  /* 008f: INDIRECT callx a5 <- mem[a5+0x78]; result unknown */ a2 = 0;
  a5 = a10;  /* 0092 */
  L_0094: a6 = 0;  /* 0094 */
  a10 = LD32(a3 + 0x3c);  /* 0096 */
  if (a10 == a6) goto L_00a6;  /* 0099: beq a10, a6, a6 <mesh_print_txQ_waiting+0x8a> */
  L_009c: a6 = LD32(a2 + 0x0);  /* 009c */
  a6 = LD32(a6 + 0x78);  /* 009e */
  /* 00a1: INDIRECT callx a6 <- mem[a6+0x78]; result unknown */ a2 = 0;
  a6 = a10;  /* 00a4 */
  L_00a6: a7 = 0;  /* 00a6 */
  a10 = LD32(a3 + 0x48);  /* 00a8 */
  if (a10 == a7) goto L_00b8;  /* 00ab: beq a10, a7, b8 <mesh_print_txQ_waiting+0x9c> */
  L_00ae: a7 = LD32(a2 + 0x0);  /* 00ae */
  a7 = LD32(a7 + 0x78);  /* 00b0 */
  /* 00b3: INDIRECT callx a7 <- mem[a7+0x78]; result unknown */ a2 = 0;
  a7 = a10;  /* 00b6 */
  L_00b8: a8 = 0;  /* 00b8 */
  a10 = LD32(a3 + 0x54);  /* 00ba */
  if (a10 == a8) goto L_00ca;  /* 00bd: beq a10, a8, ca <mesh_print_txQ_waiting+0xae> */
  L_00c0: a8 = LD32(a2 + 0x0);  /* 00c0 */
  a8 = LD32(a8 + 0x78);  /* 00c2 */
  /* 00c5: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = a10;  /* 00c8 */
  L_00ca: a10 = LD32(a3 + 0x60);  /* 00ca */
  a3 = 0;  /* 00cd */
  if (a10 == a3) goto L_00e5;  /* 00cf: beq a10, a3, e5 <mesh_print_txQ_waiting+0xc9> */
  L_00d2: a2 = LD32(a2 + 0x0);  /* 00d2 */
  a2 = LD32(a2 + 0x78);  /* 00d4 */
  ST32(a1 + 0x50, a8);  /* 00d7 */
  __asm__ volatile("" ::: "memory");  /* 00da: memw */
  /* 00dd: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a3 = a10;  /* 00e0 */
  a8 = LD32(a1 + 0x50);  /* 00e2 */
  L_00e5: a10 = 3;  /* 00e5 */
  a2 = (u32)&mesh_xon + 0x0;  /* 00e7: l32r -> global */
  a9 = LD8U(a2 + 0xd);  /* 00ea */
  ST32(a1 + 0x38, a9);  /* 00ed */
  a9 = LD8U(a2 + 0xc);  /* 00ef */
  ST32(a1 + 0x34, a9);  /* 00f2 */
  a9 = LD8U(a2 + 0xb);  /* 00f4 */
  ST32(a1 + 0x30, a9);  /* 00f7 */
  a9 = LD8U(a2 + 0xa);  /* 00f9 */
  ST32(a1 + 0x2c, a9);  /* 00fc */
  a9 = LD8U(a2 + 0x9);  /* 00fe */
  ST32(a1 + 0x28, a9);  /* 0101 */
  a9 = LD8U(a2 + 0x8);  /* 0103 */
  ST32(a1 + 0x24, a9);  /* 0106 */
  a2 = LD32(a2 + 0x0);  /* 0108 */
  ST32(a1 + 0x20, a2);  /* 010a */
  a2 = LD32(a1 + 0x44);  /* 010c */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 010f: -> "mesh" */
  a14 = a11;  /* 0112 */
  ST32(a1 + 0x8, a4);  /* 0114 */
  ST32(a1 + 0x4, a2);  /* 0116 */
  a2 = 0;  /* 0118 */
  a15 = LD32(a1 + 0x4c);  /* 011a */
  a13 = LD32(a1 + 0x48);  /* 011d */
  a12 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0120: -> "mesh" */
  a4 = LD32(a1 + 0x40);  /* 0123 */
  ST32(a1 + 0x1c, a3);  /* 0126 */
  ST32(a1 + 0x18, a8);  /* 0128 */
  ST32(a1 + 0x14, a7);  /* 012a */
  ST32(a1 + 0x10, a6);  /* 012c */
  ST32(a1 + 0xc, a5);  /* 012e */
  ST32(a1 + 0x0, a2);  /* 0130 */
  __asm__ volatile("" ::: "memory");  /* 0132: memw */
  /* 0135: INDIRECT callx a4 <- mem[a1+0x40]; result unknown */ a2 = 0;
  L_0138: a2 = 0;  /* 0138 */
  return a2;  /* 013a: retw.n */
}


/* mesh_ps_tx @ mesh_schedule.o 00000024 size 286B bind GLOBAL
 * Calls: esp_mesh_forward_check_active | indirect[6]: mem[a8+0x70]; mem[a4+0x158]; mem[a1+0x2c]; mem[a5+0x6c] | Data refs: g_mesh_init_ps_type, g_is_wifi_connected, .bss.mesh_tx_mbox, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.esp_mesh_send_block_event.str1.1
 * Fidelity: medium - 6 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=8); reloc-direct=1, funcdb-attributed=0, unknown-indirect=6 */
u32 mesh_ps_tx(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0024: entry a1, 80 (frame 80 bytes) */
  ST32(a1 + 0x20, a3);  /* 0027 */
  a3 = (a2 >> 8) & 0x1;  /* 0029: extui width 1 */
  a2 = (u32)&g_mesh_init_ps_type + 0x0;  /* 002c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 002f */
  ST32(a1 + 0x24, a4);  /* 0031 */
  ST32(a1 + 0x28, a6);  /* 0033 */
  if (a2 != 0) goto L_0040;  /* 0035: bnez a2, 40 <mesh_ps_tx+0x1c> */
  L_0038: a2 = -1;  /* 0038 */
  __asm__ volatile("" ::: "memory");  /* 003a: memw */
  goto L_013d;  /* 003d: j */
  L_0040: a2 = LD32(a1 + 0x20);  /* 0040 */
  if (a2 != 6) goto L_004e;  /* 0042: bnei a2, 6, 4e <mesh_ps_tx+0x2a> */
  L_0045: a2 = (u32)&g_is_wifi_connected + 0x0;  /* 0045: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0048 */
  if (a2 == 0) goto L_0038;  /* 004b: beqz a2, 38 <mesh_ps_tx+0x14> */
  L_004e: a2 = 1;  /* 004e */
  a12 = a1 + (16);  /* 0050 */
  a10 = LD32(a1 + 0x24);  /* 0053 */
  a11 = a1 + (17);  /* 0055 */
  ST8(a1 + 0x11, a2);  /* 0058 */
  a2 = 0;  /* 005b */
  ST8(a1 + 0x10, a2);  /* 005d */
  __asm__ volatile("" ::: "memory");  /* 0060: memw */
  __asm__ volatile("" ::: "memory");  /* 0063: memw */
  a8 = (u32)&esp_mesh_forward_check_active;  /* 0066: l32r -> func addr */
  a2 = esp_mesh_forward_check_active(a2, a3, a4, a5, a6, a7);  /* 0069: callx a8 via reloc-expand */
  a2 = a10;  /* 006c */
  if (a10 != 0) goto L_0038;  /* 006e: bnez a10, 38 <mesh_ps_tx+0x14> */
  L_0071: a4 = LD8U(a1 + 0x10);  /* 0071 */
  if (a4 == 0) goto L_0038;  /* 0074: beqz a4, 38 <mesh_ps_tx+0x14> */
  L_0077: a4 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0077: l32r -> .bss.mesh_tx_mbox (same-object static) */
  if (a3 != 0) goto L_0084;  /* 007a: bnez.n a3, 84 <mesh_ps_tx+0x60> */
  L_007c: a6 = LD32(a4 + 0x78);  /* 007c */
  goto L_0087;  /* 007f: j */
  L_0084: a6 = LD32(a4 + 0x84);  /* 0084 */
  L_0087: a12 = -1;  /* 0087 */
  a11 = a1 + (36);  /* 0089 */
  a3 = LD32(a1 + 0x20);  /* 008c */
  a3 = a3 + (a3 << 1);  /* 008e */
  a4 = a3 + (a4 << 2);  /* 0091 */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0094: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0097 */
  a10 = LD32(a4 + 0x0);  /* 0099 */
  a8 = LD32(a8 + 0x70);  /* 009b */
  /* 009e: INDIRECT callx a8 <- mem[a8+0x70]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_00d6;  /* 00a1: beqi a10, 1, d6 <mesh_ps_tx+0xb2> */
  L_00a4: a4 = LD32(a3 + 0x0);  /* 00a4 */
  if (a4 == 0) goto L_00d6;  /* 00a6: beqz.n a4, d6 <mesh_ps_tx+0xb2> */
  L_00a8: a8 = LD32(a4 + 0x150);  /* 00a8 */
  if (a8 == 0) goto L_00d6;  /* 00ab: beqz.n a8, d6 <mesh_ps_tx+0xb2> */
  L_00ad: a10 = LD32(a4 + 0x158);  /* 00ad */
  a4 = 0x7f9;  /* 00b0 */
  ST32(a1 + 0x2c, a8);  /* 00b3 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  /* 00b9: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00bc */
  a10 = 1;  /* 00be */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00c0: -> "mesh" */
  a14 = a11;  /* 00c3 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00c5: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 00c8: -> "no window" */
  a8 = LD32(a1 + 0x2c);  /* 00cb */
  ST32(a1 + 0x0, a4);  /* 00cd */
  __asm__ volatile("" ::: "memory");  /* 00d0: memw */
  /* 00d3: INDIRECT callx a8 <- mem[a1+0x2c]; result unknown */ a2 = 0;
  L_00d6: a4 = 1;  /* 00d6 */
  a8 = LD8U(a1 + 0x11);  /* 00d8 */
  if (a8 == 0) goto L_0135;  /* 00db: beqz a8, 135 <mesh_ps_tx+0x111> */
  L_00de: a8 = LD32(a1 + 0x28);  /* 00de */
  if ((i32)a5 >= (i32)a8) goto L_0135;  /* 00e0: bge a5, a8, 135 <mesh_ps_tx+0x111> */
  L_00e3: a9 = a4 << 14;  /* 00e3 */
  a8 = LD32(a1 + 0x24);  /* 00e6 */
  a5 = LD32(a8 + 0x28);  /* 00e8 */
  if ((a5 & a9) != 0) goto L_0130;  /* 00ea: bany a5, a9, 130 <mesh_ps_tx+0x10c> */
  L_00ed: a5 = a5 | a9;  /* 00ed */
  a12 = -1;  /* 00f0 */
  ST32(a8 + 0x28, a5);  /* 00f2 */
  a11 = a1 + (32);  /* 00f4 */
  a10 = a6;  /* 00f7 */
  a5 = LD32(a3 + 0x0);  /* 00f9 */
  a5 = LD32(a5 + 0x6c);  /* 00fb */
  __asm__ volatile("" ::: "memory");  /* 00fe: memw */
  /* 0101: INDIRECT callx a5 <- mem[a5+0x6c]; result unknown */ a2 = 0;
  if (a10 == a4) goto L_0130;  /* 0104: beq a10, a4, 130 <mesh_ps_tx+0x10c> */
  L_0107: a3 = LD32(a3 + 0x0);  /* 0107 */
  if (a3 == 0) goto L_0130;  /* 0109: beqz.n a3, 130 <mesh_ps_tx+0x10c> */
  L_010b: a5 = LD32(a3 + 0x150);  /* 010b */
  if (a5 == 0) goto L_0130;  /* 010e: beqz.n a5, 130 <mesh_ps_tx+0x10c> */
  L_0110: a10 = LD32(a3 + 0x158);  /* 0110 */
  /* 0113: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0116 */
  a10 = a4;  /* 0118 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 011a: -> "mesh" */
  a14 = a11;  /* 011d */
  a3 = 0x0000080eu;  /* 011f: l32r = 2062 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0122: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0125: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 0128 */
  __asm__ volatile("" ::: "memory");  /* 012a: memw */
  /* 012d: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_0130: a3 = 0;  /* 0130 */
  goto L_0137;  /* 0132: j */
  L_0135: a3 = 1;  /* 0135 */
  L_0137: ST8(a7 + 0x0, a3);  /* 0137 */
  __asm__ volatile("" ::: "memory");  /* 013a: memw */
  L_013d: __asm__ volatile("" ::: "memory");  /* 013d: memw */
  return a2;  /* 0140: retw.n */
}


/* mesh_send_block_deinit @ mesh_schedule.o 00000020 size 113B bind GLOBAL
 * Calls: esp_mesh_free_context, esp_mesh_free_mbox, memset | indirect[2]: mem[a3+0x74]; mem[a3+0x98] | Data refs: .bss.send_block_mbox, .rodata.__func__$0, .bss.send_block_task, g_osi_funcs_p
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=7); reloc-direct=3, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_send_block_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0020: entry a1, 64 (frame 64 bytes) */
  a2 = (u32)&LOCAL__bss_send_block_mbox + 0x0;  /* 0023: l32r -> .bss.send_block_mbox (same-object static) */
  goto L_003e;  /* 0026: j */
  L_0029: a3 = LD32(a1 + 0xc);  /* 0029 */
  if (a3 != 0) goto L_003e;  /* 002b: bnez.n a3, 3e <mesh_send_block_deinit+0x1e> */
  L_002d: a12 = 0x00000df3u;  /* 002d: l32r = 3571 */
  a10 = a3;  /* 0030: mov */
  a11 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 0033: l32r -> .rodata.__func__$0 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0036: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 0039: callx a8 via reloc-expand */
  ST32(a1 + 0xc, a3);  /* 003c */
  L_003e: a10 = LD32(a2 + 0x0);  /* 003e */
  if (a10 != 0) goto L_0065;  /* 0040: bnez.n a10, 65 <mesh_send_block_deinit+0x45> */
  L_0042: a10 = a2;  /* 0042 */
  __asm__ volatile("" ::: "memory");  /* 0044: memw */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 0047: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6, a7);  /* 004a: callx a8 via reloc-expand */
  a10 = a2;  /* 004d */
  a12 = 12;  /* 004f */
  a11 = 0;  /* 0051 */
  a8 = (u32)&memset + 0x0;  /* 0053: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0056: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&LOCAL__bss_send_block_task + 0x0;  /* 0059: l32r -> .bss.send_block_task (same-object static) */
  a10 = LD32(a2 + 0x0);  /* 005c */
  if (a10 != 0) goto L_007d;  /* 005e: bnez.n a10, 7d <mesh_send_block_deinit+0x5d> */
  L_0060: goto L_008c;  /* 0060: j */
  L_0065: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0065: l32r -> global */
  a12 = 0;  /* 0068 */
  a11 = a1;  /* 006a */
  a3 = LD32(a3 + 0x0);  /* 006c */
  a3 = LD32(a3 + 0x74);  /* 006e */
  /* 0071: INDIRECT callx a3 <- mem[a3+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_0029;  /* 0074: beqi a10, 1, 29 <mesh_send_block_deinit+0x9> */
  L_0077: goto L_0042;  /* 0077: j */
  L_007d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 007d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0080 */
  a3 = LD32(a3 + 0x98);  /* 0082 */
  /* 0085: INDIRECT callx a3 <- mem[a3+0x98]; result unknown */ a2 = 0;
  a3 = 0;  /* 0088 */
  ST32(a2 + 0x0, a3);  /* 008a */
  L_008c: __asm__ volatile("" ::: "memory");  /* 008c: memw */
  return a2;  /* 008f: retw.n */
}


/* mesh_send_block_main @ mesh_schedule.o 00000090 size 1050B bind GLOBAL
 * Calls: esp_mesh_send_sem_signal, esp_mesh_free_context, esp_mesh_available_txupQ_num, esp_mesh_discard_context, esp_mesh_push_to_tcpip_queue, esp_mesh_push_to_tx_queue, esp_mesh_process_txupQ_pending, mesh_send_block_deinit | indirect[32]: mem[a3+0x74]; mem[a3+0x158]; mem[a3+0x150]; mem[a6+0xb8] | Data refs: .bss.is_block_running, g_osi_funcs_p, .bss.send_block_flush_mbox, .bss.send_block_mbox, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.esp_mesh_send_block_event.str1.1, g_log_level, .rodata.mesh_send_block_main.str1.1, .rodata.__func__$21, g_mesh_self_sta_addr, g_mesh_is_root +2 more
 * Fidelity: medium - 32 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=8, refs=22); reloc-direct=8, funcdb-attributed=0, unknown-indirect=32 */
u32 mesh_send_block_main(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  float F3;
  /* 0090: entry a1, 80 (frame 80 bytes) */
  a2 = 0;  /* 0093 */
  a4 = (u32)&LOCAL__bss_is_block_running + 0x0;  /* 0095: l32r -> .bss.is_block_running (same-object static) */
  ST32(a1 + 0x24, a2);  /* 0098 */
  a2 = 14;  /* 009a */
  ST8(a1 + 0x28, a2);  /* 009c */
  a2 = 1;  /* 009f */
  ST8(a4 + 0x0, a2);  /* 00a1 */
  __asm__ volatile("" ::: "memory");  /* 00a4: memw */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00a7: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 00aa: memw */
  goto L_0464;  /* 00ad: j */
  L_00b1: a5 = (u32)&LOCAL__bss_send_block_flush_mbox + 0x0;  /* 00b1: l32r -> .bss.send_block_flush_mbox (same-object static) */
  a3 = 0;  /* 00b4 */
  a12 = -1;  /* 00b6 */
  a11 = a1 + (16);  /* 00b8 */
  a6 = (u32)&LOCAL__bss_send_block_mbox + 0x0;  /* 00bb: l32r -> .bss.send_block_mbox (same-object static) */
  ST32(a1 + 0x20, a3);  /* 00be */
  ST32(a1 + 0x1c, a3);  /* 00c0 */
  ST32(a5 + 0x0, a3);  /* 00c2 */
  a3 = LD32(a2 + 0x0);  /* 00c4 */
  a10 = LD32(a6 + 0x0);  /* 00c6 */
  a3 = LD32(a3 + 0x74);  /* 00c8 */
  __asm__ volatile("" ::: "memory");  /* 00cb: memw */
  /* 00ce: INDIRECT callx a3 <- mem[a3+0x74]; result unknown */ a2 = 0;
  a6 = a10;  /* 00d1 */
  if (a10 == 1) goto L_00d9;  /* 00d3: beqi a10, 1, d9 <mesh_send_block_main+0x49> */
  L_00d6: goto L_0464;  /* 00d6: j */
  L_00d9: a11 = LD32(a1 + 0x1c);  /* 00d9 */
  a3 = LD32(a1 + 0x20);  /* 00db */
  ST32(a1 + 0x24, a11);  /* 00dd */
  if (a3 != -1) goto L_011a;  /* 00df: bnei a3, -1, 11a <mesh_send_block_main+0x8a> */
  L_00e2: if (a11 == 0) goto L_046a;  /* 00e2: beqz a11, 46a <mesh_send_block_main+0x3da> */
  L_00e5: a3 = LD32(a2 + 0x0);  /* 00e5 */
  if (a3 == 0) goto L_046a;  /* 00e8: beqz a3, 46a <mesh_send_block_main+0x3da> */
  L_00eb: a4 = LD32(a3 + 0x150);  /* 00eb */
  if (a4 == 0) goto L_046a;  /* 00ee: beqz a4, 46a <mesh_send_block_main+0x3da> */
  L_00f1: a10 = LD32(a3 + 0x158);  /* 00f1 */
  a3 = 0x166;  /* 00f4 */
  __asm__ volatile("" ::: "memory");  /* 00f7: memw */
  /* 00fa: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00fd */
  a10 = a6;  /* 00ff */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0101: -> "mesh" */
  a14 = a11;  /* 0104 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0106: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0109: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 010c */
  __asm__ volatile("" ::: "memory");  /* 010e: memw */
  /* 0111: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_046a;  /* 0114: j */
  L_011a: if (a11 == 0) goto L_0121;  /* 011a: beqz.n a11, 121 <mesh_send_block_main+0x91> */
  L_011c: a6 = LD32(a11 + 0x0);  /* 011c */
  if (a6 != 0) goto L_0174;  /* 011e: bnez a6, 174 <mesh_send_block_main+0xe4> */
  L_0121: a3 = (u32)&g_log_level + 0x0;  /* 0121: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0124 */
  if (a3 < 3u) goto L_015c;  /* 0126: bltui a3, 3, 15c <mesh_send_block_main+0xcc> */
  L_0129: a3 = LD32(a2 + 0x0);  /* 0129 */
  if (a3 == 0) goto L_015c;  /* 012b: beqz a3, 15c <mesh_send_block_main+0xcc> */
  L_012e: a5 = LD32(a3 + 0x150);  /* 012e */
  if (a5 == 0) goto L_015c;  /* 0131: beqz a5, 15c <mesh_send_block_main+0xcc> */
  L_0134: a10 = LD32(a3 + 0x158);  /* 0134 */
  /* 0137: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 013a */
  a6 = LD32(a2 + 0x0);  /* 013c */
  a10 = LD32(a6 + 0xb8);  /* 013f */
  /* 0142: INDIRECT callx a10 <- mem[a6+0xb8]; result unknown */ a2 = 0;
  a15 = 0x16d;  /* 0145 */
  a13 = a3;  /* 0148 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 014a: -> "mesh" */
  a14 = a11;  /* 014d */
  a12 = (u32)(RODATA__rodata_mesh_send_block_main_str1_1 + 0x0);  /* 014f: l32r -> .rodata.mesh_send_block_main.str1.1 */
  ST32(a1 + 0x0, a10);  /* 0152 */
  a10 = 3;  /* 0154 */
  __asm__ volatile("" ::: "memory");  /* 0156: memw */
  /* 0159: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_015c: a8 = (u32)&esp_mesh_send_sem_signal + 0x0;  /* 015c: l32r -> global */
  a2 = esp_mesh_send_sem_signal(a2, a3, a4, a5, a6, a7);  /* 015f: callx a8 via reloc-expand */
  a12 = 0x170;  /* 0162 */
  a11 = (u32)(RODATA__rodata___func___21 + 0x0);  /* 0165: l32r -> .rodata.__func__$21 */
  a10 = LD32(a1 + 0x24);  /* 0168 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 016a: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 016d: callx a8 via reloc-expand */
  goto L_0464;  /* 0170: j */
  L_0174: a6 = 0x0000400du;  /* 0174: l32r = 16397 */
  if (a3 != a6) goto L_017d;  /* 0177: bne a3, a6, 17d <mesh_send_block_main+0xed> */
  L_017a: goto L_030f;  /* 017a: j */
  L_017d: a5 = 0x00004012u;  /* 017d: l32r = 16402 */
  if (a3 == a5) goto L_0186;  /* 0180: beq a3, a5, 186 <mesh_send_block_main+0xf6> */
  L_0183: goto L_0435;  /* 0183: j */
  L_0186: a11 = 0;  /* 0186 */
  a10 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 0188: l32r -> global */
  a8 = (u32)&esp_mesh_available_txupQ_num;  /* 018b: l32r -> func addr */
  a2 = esp_mesh_available_txupQ_num(a2, a3, a4, a5, a6, a7);  /* 018e: callx a8 via reloc-expand */
  a3 = 0x00004004u;  /* 0191: l32r = 16388 */
  if (a10 != a3) goto L_01f2;  /* 0194: bne a10, a3, 1f2 <mesh_send_block_main+0x162> */
  L_0197: a3 = (u32)&g_log_level + 0x0;  /* 0197: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 019a */
  if (a3 < 3u) goto L_01d0;  /* 019c: bltui a3, 3, 1d0 <mesh_send_block_main+0x140> */
  L_019f: a3 = LD32(a2 + 0x0);  /* 019f */
  if (a3 == 0) goto L_01d0;  /* 01a1: beqz.n a3, 1d0 <mesh_send_block_main+0x140> */
  L_01a3: a5 = LD32(a3 + 0x150);  /* 01a3 */
  if (a5 == 0) goto L_01d0;  /* 01a6: beqz.n a5, 1d0 <mesh_send_block_main+0x140> */
  L_01a8: a10 = LD32(a3 + 0x158);  /* 01a8 */
  /* 01ab: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 01ae */
  a6 = LD32(a2 + 0x0);  /* 01b0 */
  a10 = LD32(a6 + 0xb8);  /* 01b3 */
  /* 01b6: INDIRECT callx a10 <- mem[a6+0xb8]; result unknown */ a2 = 0;
  a15 = 0x179;  /* 01b9 */
  a13 = a3;  /* 01bc */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 01be: -> "mesh" */
  a14 = a11;  /* 01c1 */
  a12 = (u32)(RODATA__rodata_mesh_send_block_main_str1_1 + 0x0);  /* 01c3: l32r -> .rodata.mesh_send_block_main.str1.1 */
  ST32(a1 + 0x0, a10);  /* 01c6 */
  a10 = 3;  /* 01c8 */
  __asm__ volatile("" ::: "memory");  /* 01ca: memw */
  /* 01cd: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_01d0: a8 = (u32)&esp_mesh_send_sem_signal + 0x0;  /* 01d0: l32r -> global */
  a2 = esp_mesh_send_sem_signal(a2, a3, a4, a5, a6, a7);  /* 01d3: callx a8 via reloc-expand */
  a13 = 0x17c;  /* 01d6 */
  a12 = (u32)(RODATA__rodata___func___21 + 0x0);  /* 01d9: l32r -> .rodata.__func__$21 */
  a3 = 0;  /* 01dc */
  a11 = 0x00004004u;  /* 01de: l32r = 16388 */
  a10 = LD32(a1 + 0x24);  /* 01e1 */
  a8 = (u32)&esp_mesh_discard_context;  /* 01e3: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 01e6: callx a8 via reloc-expand */
  ST32(a1 + 0x24, a3);  /* 01e9 */
  __asm__ volatile("" ::: "memory");  /* 01eb: memw */
  goto L_020e;  /* 01ee: j */
  L_01f2: if (a10 != 0) goto L_020e;  /* 01f2: bnez.n a10, 20e <mesh_send_block_main+0x17e> */
  L_01f4: a3 = LD32(a2 + 0x0);  /* 01f4 */
  a10 = 10;  /* 01f6 */
  a5 = LD32(a3 + 0x9c);  /* 01f8 */
  a3 = LD32(a3 + 0xa0);  /* 01fb */
  /* 01fe: INDIRECT callx a3 <- mem[a3+0xa0]; result unknown */ a2 = 0;
  /* 0201: INDIRECT callx a5 <- mem[a3+0x9c]; result unknown */ a2 = 0;
  a3 = LD8U(a4 + 0x0);  /* 0204 */
  if (a3 == 0) goto L_020e;  /* 0207: beqz.n a3, 20e <mesh_send_block_main+0x17e> */
  L_0209: a3 = LD32(a1 + 0x24);  /* 0209 */
  if (a3 != 0) goto L_0186;  /* 020b: bnez a3, 186 <mesh_send_block_main+0xf6> */
  L_020e: a3 = LD32(a1 + 0x24);  /* 020e */
  if (a3 == 0) goto L_0464;  /* 0210: beqz a3, 464 <mesh_send_block_main+0x3d4> */
  L_0213: a6 = 2;  /* 0213 */
  a5 = LD32(a3 + 0x28);  /* 0215 */
  a5 = a5 | a6;  /* 0217 */
  ST32(a3 + 0x28, a5);  /* 021a */
  a5 = (u32)&g_mesh_is_root + 0x0;  /* 021c: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 021f: memw */
  a5 = LD8U(a5 + 0x0);  /* 0222 */
  a5 = (a5 >> 8) & 0x1;  /* 0225: extui width 1 */
  a6 = LD32(a2 + 0x0);  /* 0228 */
  a10 = LD32(a3 + 0x24);  /* 022a */
  a6 = LD32(a6 + 0xa0);  /* 022d */
  if (a5 == 0) goto L_0299;  /* 0230: beqz a5, 299 <mesh_send_block_main+0x209> */
  L_0233: __asm__ volatile("" ::: "memory");  /* 0233: memw */
  /* 0236: INDIRECT callx a6 <- mem[a6+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 0239 */
  a10 = a1 + (36);  /* 023b */
  a8 = (u32)&esp_mesh_push_to_tcpip_queue + 0x0;  /* 023e: l32r -> global */
  a2 = esp_mesh_push_to_tcpip_queue(a2, a3, a4, a5, a6, a7);  /* 0241: callx a8 via reloc-expand */
  a6 = a10;  /* 0244 */
  if (a10 == 0) goto L_0426;  /* 0246: beqz a10, 426 <mesh_send_block_main+0x396> */
  L_0249: a3 = (u32)&g_log_level + 0x0;  /* 0249: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 024c */
  if (a3 >= 3u) goto L_0254;  /* 024e: bgeui a3, 3, 254 <mesh_send_block_main+0x1c4> */
  L_0251: goto L_049a;  /* 0251: j */
  L_0254: a3 = LD32(a2 + 0x0);  /* 0254 */
  if (a3 == 0) goto L_049a;  /* 0256: beqz a3, 49a <mesh_send_block_main+0x40a> */
  L_0259: a5 = LD32(a3 + 0x150);  /* 0259 */
  if (a5 == 0) goto L_049a;  /* 025c: beqz a5, 49a <mesh_send_block_main+0x40a> */
  L_025f: a10 = LD32(a3 + 0x158);  /* 025f */
  /* 0262: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0265 */
  a15 = 0x18e;  /* 0267 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 026a: -> "mesh" */
  a10 = 3;  /* 026d */
  a14 = a11;  /* 026f */
  a12 = (u32)(RODATA__rodata_mesh_send_block_main_str1_1 + 0x0);  /* 0271: l32r -> .rodata.mesh_send_block_main.str1.1 */
  ST32(a1 + 0x0, a6);  /* 0274 */
  __asm__ volatile("" ::: "memory");  /* 0276: memw */
  /* 0279: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_049a;  /* 027c: j */
  L_0281: a5 = LD32(a3 + 0x150);  /* 0281 */
  if (a5 == 0) goto L_0426;  /* 0284: beqz a5, 426 <mesh_send_block_main+0x396> */
  L_0287: a10 = LD32(a3 + 0x158);  /* 0287 */
  a3 = 0x190;  /* 028a */
  /* 028d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0290: -> "mesh" */
  goto L_02f7;  /* 0293: j */
  L_0299: /* 0299: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  a11 = a10;  /* 029c: mov */
  a10 = a1 + (36);  /* 029f */
  a8 = (u32)&esp_mesh_push_to_tx_queue;  /* 02a2: l32r -> func addr */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6, a7);  /* 02a5: callx a8 via reloc-expand */
  a6 = a10;  /* 02a8 */
  if (a10 == 0) goto L_0426;  /* 02aa: beqz a10, 426 <mesh_send_block_main+0x396> */
  L_02ad: a3 = (u32)&g_log_level + 0x0;  /* 02ad: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 02b0 */
  if (a3 >= 3u) goto L_02b8;  /* 02b2: bgeui a3, 3, 2b8 <mesh_send_block_main+0x228> */
  L_02b5: goto L_04a2;  /* 02b5: j */
  L_02b8: a3 = LD32(a2 + 0x0);  /* 02b8 */
  if (a3 == 0) goto L_04a2;  /* 02ba: beqz a3, 4a2 <mesh_send_block_main+0x412> */
  L_02bd: a5 = LD32(a3 + 0x150);  /* 02bd */
  if (a5 == 0) goto L_04a2;  /* 02c0: beqz a5, 4a2 <mesh_send_block_main+0x412> */
  L_02c3: a10 = LD32(a3 + 0x158);  /* 02c3 */
  /* 02c6: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02c9 */
  a15 = 0x194;  /* 02cb */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 02ce: -> "mesh" */
  a10 = 3;  /* 02d1 */
  a14 = a11;  /* 02d3 */
  a12 = (u32)(RODATA__rodata_mesh_send_block_main_str1_1 + 0x0);  /* 02d5: l32r -> .rodata.mesh_send_block_main.str1.1 */
  ST32(a1 + 0x0, a6);  /* 02d8 */
  __asm__ volatile("" ::: "memory");  /* 02da: memw */
  /* 02dd: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_04a2;  /* 02e0: j */
  L_02e5: a5 = LD32(a3 + 0x150);  /* 02e5 */
  if (a5 == 0) goto L_0426;  /* 02e8: beqz a5, 426 <mesh_send_block_main+0x396> */
  L_02eb: a10 = LD32(a3 + 0x158);  /* 02eb */
  a3 = 0x196;  /* 02ee */
  /* 02f1: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 02f4: -> "mesh" */
  L_02f7: a13 = a10;  /* 02f7 */
  a14 = a11;  /* 02f9 */
  a10 = 1;  /* 02fb */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 02fd: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0300: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 0303 */
  __asm__ volatile("" ::: "memory");  /* 0306: memw */
  /* 0309: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0426;  /* 030c: j */
  L_030f: a10 = LD8U(a1 + 0x10);  /* 030f */
  a3 = LD32(a1 + 0x14);  /* 0312 */
  ST8(a1 + 0x28, a10);  /* 0314 */
  __asm__ volatile("" ::: "memory");  /* 0317: memw */
  ST32(a5 + 0x0, a3);  /* 031a */
  a6 = LD32(a1 + 0x18);  /* 031c */
  if (a3 == 0) goto L_03d5;  /* 031e: beqz a3, 3d5 <mesh_send_block_main+0x345> */
  L_0321: __asm__ volatile("" ::: "memory");  /* 0321: memw */
  a8 = (u32)&esp_mesh_process_txupQ_pending;  /* 0324: l32r -> func addr */
  a2 = esp_mesh_process_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0327: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0356;  /* 032a: beqz.n a10, 356 <mesh_send_block_main+0x2c6> */
  L_032c: a8 = LD32(a2 + 0x0);  /* 032c */
  if (a8 == 0) goto L_0356;  /* 032e: beqz a8, 356 <mesh_send_block_main+0x2c6> */
  L_0331: a7 = LD32(a8 + 0x150);  /* 0331 */
  if (a7 == 0) goto L_0356;  /* 0334: beqz.n a7, 356 <mesh_send_block_main+0x2c6> */
  L_0336: a10 = LD32(a8 + 0x158);  /* 0336 */
  /* 0339: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x1a7;  /* 033c */
  a13 = a10;  /* 033f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0341: -> "mesh" */
  a10 = 1;  /* 0344 */
  a14 = a11;  /* 0346 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0348: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 034b: -> "no window" */
  ST32(a1 + 0x0, a8);  /* 034e */
  __asm__ volatile("" ::: "memory");  /* 0350: memw */
  /* 0353: INDIRECT callx a7 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0356: a12 = -1;  /* 0356 */
  a11 = a1 + (36);  /* 0358 */
  a10 = a3;  /* 035b */
  a7 = LD32(a2 + 0x0);  /* 035d */
  a7 = LD32(a7 + 0x6c);  /* 035f */
  /* 0362: INDIRECT callx a7 <- mem[a7+0x6c]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_0381;  /* 0365: bnei a10, 1, 381 <mesh_send_block_main+0x2f1> */
  L_0368: if (a6 == 0) goto L_0422;  /* 0368: beqz a6, 422 <mesh_send_block_main+0x392> */
  L_036b: a3 = LD32(a2 + 0x0);  /* 036b */
  a12 = 0;  /* 036d */
  a11 = a1 + (40);  /* 0370 */
  a10 = a6;  /* 0373: mov */
  a3 = LD32(a3 + 0x6c);  /* 0376 */
  /* 0379: INDIRECT callx a3 <- mem[a3+0x6c]; result unknown */ a2 = 0;
  goto L_0422;  /* 037c: j */
  L_0381: a3 = (u32)&g_log_level + 0x0;  /* 0381: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0384 */
  if (a3 < 3u) goto L_03c0;  /* 0386: bltui a3, 3, 3c0 <mesh_send_block_main+0x330> */
  L_0389: a3 = LD32(a2 + 0x0);  /* 0389 */
  if (a3 == 0) goto L_03c0;  /* 038b: beqz.n a3, 3c0 <mesh_send_block_main+0x330> */
  L_038d: a6 = LD32(a3 + 0x150);  /* 038d */
  if (a6 == 0) goto L_03c0;  /* 0390: beqz a6, 3c0 <mesh_send_block_main+0x330> */
  L_0393: a10 = LD32(a3 + 0x158);  /* 0393 */
  /* 0396: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0399 */
  a15 = 0x1b1;  /* 039b */
  a3 = LD32(a1 + 0x24);  /* 039e */
  a10 = 3;  /* 03a0 */
  a7 = LD32(a3 + 0x0);  /* 03a2 */
  ST32(a1 + 0xc, a7);  /* 03a4 */
  a7 = LD16U(a3 + 0x4);  /* 03a6 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 03a9: -> "mesh" */
  a14 = a11;  /* 03ac */
  ST32(a1 + 0x4, a3);  /* 03ae */
  a3 = LD8U(a1 + 0x28);  /* 03b0 */
  a12 = (u32)(RODATA__rodata_mesh_send_block_main_str1_1 + 0x0);  /* 03b3: l32r -> .rodata.mesh_send_block_main.str1.1 */
  ST32(a1 + 0x8, a7);  /* 03b6 */
  ST32(a1 + 0x0, a3);  /* 03b8 */
  __asm__ volatile("" ::: "memory");  /* 03ba: memw */
  /* 03bd: INDIRECT callx a6 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_03c0: a13 = 0x1b3;  /* 03c0 */
  a12 = (u32)(RODATA__rodata___func___21 + 0x0);  /* 03c3: l32r -> .rodata.__func__$21 */
  a11 = 0x0000400cu;  /* 03c6: l32r = 16396 */
  a10 = LD32(a1 + 0x24);  /* 03c9 */
  a8 = (u32)&esp_mesh_discard_context;  /* 03cb: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 03ce: callx a8 via reloc-expand */
  goto L_0422;  /* 03d1: j */
  L_03d5: a3 = (u32)&g_log_level + 0x0;  /* 03d5: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 03d8 */
  if (a3 < 3u) goto L_0414;  /* 03da: bltui a3, 3, 414 <mesh_send_block_main+0x384> */
  L_03dd: a3 = LD32(a2 + 0x0);  /* 03dd */
  if (a3 == 0) goto L_0414;  /* 03df: beqz.n a3, 414 <mesh_send_block_main+0x384> */
  L_03e1: a6 = LD32(a3 + 0x150);  /* 03e1 */
  if (a6 == 0) goto L_0414;  /* 03e4: beqz a6, 414 <mesh_send_block_main+0x384> */
  L_03e7: a10 = LD32(a3 + 0x158);  /* 03e7 */
  /* 03ea: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 03ed */
  a15 = 0x1b6;  /* 03ef */
  a3 = LD32(a1 + 0x24);  /* 03f2 */
  a10 = 3;  /* 03f4 */
  a7 = LD32(a3 + 0x0);  /* 03f6 */
  ST32(a1 + 0xc, a7);  /* 03f8 */
  a7 = LD16U(a3 + 0x4);  /* 03fa */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 03fd: -> "mesh" */
  a14 = a11;  /* 0400 */
  ST32(a1 + 0x4, a3);  /* 0402 */
  a3 = LD8U(a1 + 0x28);  /* 0404 */
  a12 = (u32)(RODATA__rodata_mesh_send_block_main_str1_1 + 0x0);  /* 0407: l32r -> .rodata.mesh_send_block_main.str1.1 */
  ST32(a1 + 0x8, a7);  /* 040a */
  ST32(a1 + 0x0, a3);  /* 040c */
  __asm__ volatile("" ::: "memory");  /* 040e: memw */
  /* 0411: INDIRECT callx a6 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_0414: a12 = 0x1b8;  /* 0414 */
  a11 = (u32)(RODATA__rodata___func___21 + 0x0);  /* 0417: l32r -> .rodata.__func__$21 */
  a10 = LD32(a1 + 0x24);  /* 041a */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 041c: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 041f: callx a8 via reloc-expand */
  L_0422: a3 = 0;  /* 0422 */
  ST32(a5 + 0x0, a3);  /* 0424 */
  L_0426: __asm__ volatile("" ::: "memory");  /* 0426: memw */
  a8 = (u32)&esp_mesh_send_sem_signal + 0x0;  /* 0429: l32r -> global */
  a2 = esp_mesh_send_sem_signal(a2, a3, a4, a5, a6, a7);  /* 042c: callx a8 via reloc-expand */
  goto L_0464;  /* 042f: j */
  L_0435: a5 = (u32)&g_log_level + 0x0;  /* 0435: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 0438 */
  if (a5 < 3u) goto L_0464;  /* 043a: bltui a5, 3, 464 <mesh_send_block_main+0x3d4> */
  L_043d: a8 = LD32(a2 + 0x0);  /* 043d */
  if (a8 == 0) goto L_0464;  /* 043f: beqz.n a8, 464 <mesh_send_block_main+0x3d4> */
  L_0441: a5 = LD32(a8 + 0x150);  /* 0441 */
  if (a5 == 0) goto L_0464;  /* 0444: beqz a5, 464 <mesh_send_block_main+0x3d4> */
  L_0447: a10 = LD32(a8 + 0x158);  /* 0447 */
  /* 044a: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 044d */
  a15 = 0x1c3;  /* 044f */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0452: -> "mesh" */
  a10 = 3;  /* 0455 */
  a14 = a11;  /* 0457 */
  a12 = (u32)(RODATA__rodata_mesh_send_block_main_str1_1 + 0x0);  /* 0459: l32r -> .rodata.mesh_send_block_main.str1.1 */
  ST32(a1 + 0x0, a3);  /* 045c */
  __asm__ volatile("" ::: "memory");  /* 045e: memw */
  /* 0461: INDIRECT callx a5 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0464: a3 = LD8U(a4 + 0x0);  /* 0464 */
  if (a3 != 0) goto L_00b1;  /* 0467: bnez a3, b1 <mesh_send_block_main+0x21> */
  L_046a: a3 = (u32)&LOCAL__bss_send_block_task + 0x0;  /* 046a: l32r -> .bss.send_block_task (same-object static) */
  a4 = 0;  /* 046d */
  ST32(a3 + 0x0, a4);  /* 0470 */
  __asm__ volatile("" ::: "memory");  /* 0473: memw */
  a8 = (u32)&mesh_send_block_deinit;  /* 0476: l32r -> func addr */
  a2 = mesh_send_block_deinit(a2, a3, a4, a5, a6, a7);  /* 0479: callx a8 via reloc-expand */
  a3 = (u32)&g_mesh_stop_event_group + 0x0;  /* 047c: l32r -> global */
  a10 = LD32(a3 + 0x0);  /* 047f */
  if (a10 == a4) goto L_048e;  /* 0481: beq a10, a4, 48e <mesh_send_block_main+0x3fe> */
  L_0484: a11 = 64;  /* 0484 */
  a3 = LD32(a2 + 0x0);  /* 0486 */
  a3 = LD32(a3 + 0x84);  /* 0488 */
  /* 048b: INDIRECT callx a3 <- mem[a3+0x84]; result unknown */ a2 = 0;
  L_048e: a10 = 0;  /* 048e */
  a2 = LD32(a2 + 0x0);  /* 0490 */
  a2 = LD32(a2 + 0x98);  /* 0492 */
  /* 0495: INDIRECT callx a2 <- mem[a2+0x98]; result unknown */ a2 = 0;
  return a2;  /* 0498: retw.n */
  L_049a: a3 = LD32(a2 + 0x0);  /* 049a */
  if (a3 != 0) goto L_0281;  /* 049c: bnez a3, 281 <mesh_send_block_main+0x1f1> */
  L_049f: goto L_0426;  /* 049f: j */
  L_04a2: a3 = LD32(a2 + 0x0);  /* 04a2 */
  if (a3 != 0) goto L_02e5;  /* 04a4: bnez a3, 2e5 <mesh_send_block_main+0x255> */
  L_04a7: goto L_0426;  /* 04a7: j */
  L_ret: return a2;
}


/* mesh_tx_cb @ mesh_schedule.o 0000002c size 215B bind GLOBAL
 * Calls: mesh_mutex_lock, esp_mesh_match_self, mesh_topo_get_ttl, memset, esp_mesh_push_to_nwk_queue, esp_mesh_push_to_ack_state_queue, mesh_mutex_unlock | Data refs: .bss.mesh_tx_task, .rodata.__func__$18, g_mesh_topology, g_mesh_max_layer
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=7, refs=11); reloc-direct=7, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_tx_cb(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  float F4;
  /* 002c: entry a1, 224 (frame 224 bytes) */
  a4 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 002f: l32r -> .bss.mesh_tx_task (same-object static) */
  a12 = 0x30e;  /* 0032 */
  a5 = (u32)(RODATA__rodata___func___18 + 0x0);  /* 0035: l32r -> .rodata.__func__$18 */
  a11 = a5;  /* 0038: mov */
  a10 = LD32(a4 + 0x4);  /* 003b */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 003e: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 0041: callx a8 via reloc-expand */
  if (a2 == 0) goto L_00f4;  /* 0044: beqz a2, f4 <mesh_tx_cb+0xc8> */
  L_0047: a9 = LD8U(a2 + 0x20);  /* 0047 */
  a3 = LD32(a2 + 0x4);  /* 004a */
  a8 = LD16U(a2 + 0x14);  /* 004c */
  a8 = a8 + a9;  /* 004f */
  a8 = a8 + (8);  /* 0051 */
  a9 = 33;  /* 0053 */
  a3 = LD32(a3 + 0x4);  /* 0055 */
  a3 = a3 + a8;  /* 0057 */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 0059: l32r -> global */
  a10 = LD32(a8 + 0x0);  /* 005c */
  a8 = 28;  /* 005e */
  if (a10 != 0) a8 = a9;  /* 0060 */
  a10 = LD32(a3 + 0x4);  /* 0063 */
  if (((a10 >> 24) & 1) == 0) goto L_0071;  /* 0065: bbci a10, 24, 71 <mesh_tx_cb+0x45> */
  L_0068: a9 = LD8U(a3 + 0x1);  /* 0068 */
  a9 = a9 - a8;  /* 006b: subx4 */
  if (a9 >= 4u) goto L_007d;  /* 006e: bgeui a9, 4, 7d <mesh_tx_cb+0x51> */
  L_0071: if (((a10 >> 23) & 1) == 0) goto L_00dc;  /* 0071: bbci a10, 23, dc <mesh_tx_cb+0xb0> */
  L_0074: a9 = LD8U(a3 + 0x1);  /* 0074 */
  a9 = a9 - a8;  /* 0077: subx4 */
  if (a9 < 3u) goto L_00dc;  /* 007a: bltui a9, 3, dc <mesh_tx_cb+0xb0> */
  L_007d: a8 = a3 + a8;  /* 007d */
  a8 = LD8U(a8 + 0x0);  /* 007f */
  if (a8 != 4) goto L_00dc;  /* 0082: bnei a8, 4, dc <mesh_tx_cb+0xb0> */
  L_0085: a10 = a3 + (14);  /* 0085 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0087: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 008a: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00dc;  /* 008d: beqz a10, dc <mesh_tx_cb+0xb0> */
  L_0090: a11 = a3 + (28);  /* 0090 */
  a10 = a3;  /* 0093: mov */
  a8 = (u32)&mesh_topo_get_ttl + 0x0;  /* 0096: l32r -> global */
  a2 = mesh_topo_get_ttl(a2, a3, a4, a5, a6, a7);  /* 0099: callx a8 via reloc-expand */
  a8 = (u32)&g_mesh_max_layer + 0x0;  /* 009c: l32r -> global */
  a8 = LD16U(a8 + 0x0);  /* 009f */
  a8 = a8 + a8;  /* 00a2 */
  a8 = a8 + (-1);  /* 00a4 */
  if (a10 != a8) goto L_00dc;  /* 00a6: bne a10, a8, dc <mesh_tx_cb+0xb0> */
  L_00a9: a12 = 180;  /* 00a9 */
  a11 = 0;  /* 00ac */
  a10 = a1 + (4);  /* 00ae */
  a8 = (u32)&memset + 0x0;  /* 00b0: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00b3: callx a8 (libc, via reloc-expand) */
  a2 = LD32(a2 + 0x2c);  /* 00b6 */
  a8 = 37;  /* 00b8 */
  a11 = 0;  /* 00ba */
  a10 = a1;  /* 00bc */
  a2 = LD8U(a2 + 0x13);  /* 00be */
  ST8(a1 + 0x4, a2);  /* 00c1 */
  __asm__ volatile("" ::: "memory");  /* 00c4: memw */
  a2 = LD32(a3 + 0x14);  /* 00c7 */
  ST32(a1 + 0x0, a8);  /* 00c9 */
  ST32(a1 + 0x8, a2);  /* 00cc */
  __asm__ volatile("" ::: "memory");  /* 00cf: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 00d2: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 00d5: callx a8 via reloc-expand */
  goto L_00f4;  /* 00d8: j */
  L_00dc: a2 = LD32(a2 + 0x2c);  /* 00dc */
  a11 = 0;  /* 00de */
  a10 = a1;  /* 00e0 */
  a3 = LD32(a3 + 0x14);  /* 00e2 */
  a2 = LD8U(a2 + 0x13);  /* 00e4 */
  ST32(a1 + 0x0, a3);  /* 00e7 */
  ST32(a1 + 0x4, a2);  /* 00e9 */
  __asm__ volatile("" ::: "memory");  /* 00eb: memw */
  a8 = (u32)&esp_mesh_push_to_ack_state_queue;  /* 00ee: l32r -> func addr */
  a2 = esp_mesh_push_to_ack_state_queue(a2, a3, a4, a5, a6, a7);  /* 00f1: callx a8 via reloc-expand */
  L_00f4: a12 = 0x345;  /* 00f4 */
  a11 = a5;  /* 00f7 */
  a10 = LD32(a4 + 0x4);  /* 00f9 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 00fb: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 00fe: callx a8 via reloc-expand */
  return a2;  /* 0101: retw.n */
}


/* mesh_tx_task_deinit @ mesh_schedule.o 0000004c size 380B bind GLOBAL
 * Calls: esp_mesh_free_context, esp_mesh_free_mbox, memset | indirect[7]: mem[a4+0x74]; mem[a8+0x74]; mem[a2+0x98]; mem[a3+0x74] | Data refs: .bss.mesh_tx_mbox, .rodata.__func__$2, g_osi_funcs_p, .bss.mesh_tx_task, .bss.mesh_ack_state_mbox, .bss.mesh_new_wnd_mbox, .bss.is_mesh_tx_started
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=10); reloc-direct=3, funcdb-attributed=0, unknown-indirect=7 */
u32 mesh_tx_task_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  float F6, F8;
  /* 004c: entry a1, 64 (frame 64 bytes) */
  a2 = 0;  /* 004f */
  a3 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0051: l32r -> .bss.mesh_tx_mbox (same-object static) */
  ST32(a1 + 0x18, a2);  /* 0054 */
  __asm__ volatile("" ::: "memory");  /* 0056: memw */
  goto L_0072;  /* 0059: j */
  L_005d: a11 = (u32)(RODATA__rodata___func___2 + 0x0);  /* 005d: -> "mesh_tx_task_deinit" */
  a12 = 0x35f;  /* 0060 */
  a12 = a12 << 2;  /* 0063 */
  a4 = 0;  /* 0066 */
  a10 = LD32(a1 + 0x18);  /* 0068 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 006a: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 006d: callx a8 via reloc-expand */
  ST32(a1 + 0x18, a4);  /* 0070 */
  L_0072: a10 = LD32(a3 + 0x0);  /* 0072 */
  if (a10 != 0) goto L_0099;  /* 0074: bnez.n a10, 99 <mesh_tx_task_deinit+0x4d> */
  L_0076: a10 = a3;  /* 0076 */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 007b: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6, a7);  /* 007e: callx a8 via reloc-expand */
  a10 = a3;  /* 0081 */
  a12 = 12;  /* 0083 */
  a11 = 0;  /* 0085 */
  a2 = a2 + (1);  /* 0087 */
  a4 = 14;  /* 0089 */
  a8 = (u32)&memset + 0x0;  /* 008b: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 008e: callx a8 (libc, via reloc-expand) */
  a3 = a3 + (12);  /* 0091 */
  if (a2 != a4) goto L_0072;  /* 0093: bne a2, a4, 72 <mesh_tx_task_deinit+0x26> */
  L_0096: goto L_00af;  /* 0096: j */
  L_0099: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0099: l32r -> global */
  a12 = 0;  /* 009c */
  a11 = a1 + (24);  /* 009e */
  a4 = LD32(a4 + 0x0);  /* 00a1 */
  a4 = LD32(a4 + 0x74);  /* 00a3 */
  /* 00a6: INDIRECT callx a4 <- mem[a4+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_005d;  /* 00a9: beqi a10, 1, 5d <mesh_tx_task_deinit+0x11> */
  L_00ac: goto L_0076;  /* 00ac: j */
  L_00af: a2 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 00af: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a3 = 12;  /* 00b2 */
  goto L_00b9;  /* 00b4: j */
  L_00b7: a3 = a8;  /* 00b7 */
  L_00b9: a10 = LD32(a2 + 0x0);  /* 00b9 */
  if (a10 == 0) goto L_00d0;  /* 00bb: beqz.n a10, d0 <mesh_tx_task_deinit+0x84> */
  L_00bd: a12 = 0;  /* 00bd */
  a11 = a1 + (28);  /* 00bf */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00c2: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 00c5 */
  a4 = LD32(a4 + 0x74);  /* 00c7 */
  /* 00ca: INDIRECT callx a4 <- mem[a4+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_00b9;  /* 00cd: beqi a10, 1, b9 <mesh_tx_task_deinit+0x6d> */
  L_00d0: a10 = a2;  /* 00d0 */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 00d2: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6, a7);  /* 00d5: callx a8 via reloc-expand */
  a10 = a2;  /* 00d8 */
  a12 = 12;  /* 00da */
  a11 = 0;  /* 00dc */
  a8 = (u32)&memset + 0x0;  /* 00de: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00e1: callx a8 (libc, via reloc-expand) */
  a8 = 13;  /* 00e4 */
  a2 = a2 + (12);  /* 00e6 */
  if (a3 != a8) goto L_00b7;  /* 00e8: bne a3, a8, b7 <mesh_tx_task_deinit+0x6b> */
  L_00eb: a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 00eb: l32r -> .bss.mesh_tx_task (same-object static) */
  a4 = 0;  /* 00ee */
  a3 = a2;  /* 00f0 */
  goto L_00f8;  /* 00f2: j */
  L_00f6: a4 = 1;  /* 00f6 */
  L_00f8: a10 = LD32(a2 + 0x0);  /* 00f8 */
  if (a10 == 0) goto L_0110;  /* 00fa: beqz.n a10, 110 <mesh_tx_task_deinit+0xc4> */
  L_00fc: a12 = 0;  /* 00fc */
  a11 = a1 + (28);  /* 00fe */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0101: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0104 */
  a8 = LD32(a8 + 0x74);  /* 0107 */
  /* 010a: INDIRECT callx a8 <- mem[a8+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_00f8;  /* 010d: beqi a10, 1, f8 <mesh_tx_task_deinit+0xac> */
  L_0110: a10 = a2;  /* 0110 */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 0112: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6, a7);  /* 0115: callx a8 via reloc-expand */
  a10 = a2;  /* 0118 */
  a12 = 12;  /* 011a */
  a11 = 0;  /* 011c */
  a8 = (u32)&memset + 0x0;  /* 011f: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0122: callx a8 (libc, via reloc-expand) */
  a2 = a2 + (24);  /* 0125 */
  if (a4 != 1) goto L_00f6;  /* 0128: bnei a4, 1, f6 <mesh_tx_task_deinit+0xaa> */
  L_012b: a10 = LD32(a3 + 0x10);  /* 012b */
  if (a10 == 0) goto L_013a;  /* 012d: beqz.n a10, 13a <mesh_tx_task_deinit+0xee> */
  L_012f: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 012f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0132 */
  a2 = LD32(a2 + 0x98);  /* 0134 */
  /* 0137: INDIRECT callx a2 <- mem[a2+0x98]; result unknown */ a2 = 0;
  L_013a: a2 = 0;  /* 013a */
  a10 = LD32(a3 + 0x28);  /* 013c */
  ST32(a3 + 0x10, a2);  /* 013e */
  if (a10 == a2) goto L_0152;  /* 0140: beq a10, a2, 152 <mesh_tx_task_deinit+0x106> */
  L_0143: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0143: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0146 */
  a2 = LD32(a2 + 0x98);  /* 0149 */
  __asm__ volatile("" ::: "memory");  /* 014c: memw */
  /* 014f: INDIRECT callx a2 <- mem[a2+0x98]; result unknown */ a2 = 0;
  L_0152: a2 = 0;  /* 0152 */
  ST32(a3 + 0x28, a2);  /* 0154 */
  a2 = (u32)&LOCAL__bss_mesh_ack_state_mbox + 0x0;  /* 0157: l32r -> .bss.mesh_ack_state_mbox (same-object static) */
  L_015a: a10 = LD32(a2 + 0x0);  /* 015a */
  if (a10 == 0) goto L_0174;  /* 015c: beqz.n a10, 174 <mesh_tx_task_deinit+0x128> */
  L_015e: a12 = 0;  /* 015e */
  a11 = a1 + (16);  /* 0160 */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0163: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0166 */
  a3 = LD32(a3 + 0x74);  /* 0168 */
  __asm__ volatile("" ::: "memory");  /* 016b: memw */
  /* 016e: INDIRECT callx a3 <- mem[a3+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_015a;  /* 0171: beqi a10, 1, 15a <mesh_tx_task_deinit+0x10e> */
  L_0174: a10 = a2;  /* 0174 */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 0176: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6, a7);  /* 0179: callx a8 via reloc-expand */
  a10 = a2;  /* 017c */
  a12 = 12;  /* 017e */
  a11 = 0;  /* 0180 */
  a8 = (u32)&memset + 0x0;  /* 0183: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0186: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&LOCAL__bss_mesh_new_wnd_mbox + 0x0;  /* 0189: l32r -> .bss.mesh_new_wnd_mbox (same-object static) */
  L_018c: a10 = LD32(a2 + 0x0);  /* 018c */
  if (a10 == 0) goto L_01a4;  /* 018e: beqz.n a10, 1a4 <mesh_tx_task_deinit+0x158> */
  L_0190: a12 = 0;  /* 0190 */
  a11 = a1;  /* 0192: mov */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0195: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0198 */
  a3 = LD32(a3 + 0x74);  /* 019b */
  /* 019e: INDIRECT callx a3 <- mem[a3+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_018c;  /* 01a1: beqi a10, 1, 18c <mesh_tx_task_deinit+0x140> */
  L_01a4: a10 = a2;  /* 01a4 */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 01a6: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6, a7);  /* 01a9: callx a8 via reloc-expand */
  a10 = a2;  /* 01ac */
  a12 = 12;  /* 01ae */
  a11 = 0;  /* 01b0 */
  a8 = (u32)&memset + 0x0;  /* 01b2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01b5: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&LOCAL__bss_is_mesh_tx_started + 0x0;  /* 01b8: l32r -> .bss.is_mesh_tx_started (same-object static) */
  a3 = 0;  /* 01bb */
  ST8(a2 + 0x0, a3);  /* 01bd */
  __asm__ volatile("" ::: "memory");  /* 01c0: memw */
  __asm__ volatile("" ::: "memory");  /* 01c3: memw */
  return a2;  /* 01c6: retw.n */
}


/* mesh_tx_task_main @ mesh_schedule.o 0000010c size 2158B bind GLOBAL
 * Calls: mesh_tx_tid_stop, tx_task_main, esp_mesh_discard_context, esp_mesh_txupQ_pending, memcmp, mesh_mutex_lock, esp_mesh_best_effort_tx, mesh_mutex_unlock, memcpy, wifi_get_macaddr, memset, esp_mesh_push_to_nwk_queue, esp_wifi_mesh_tx, route_announce_timer_start, esp_mesh_get_layer | indirect[34]: mem[a2+0x74]; mem[a7+0x78]; mem[a4+0x158]; mem[a4+0x150] | Data refs: .bss.mesh_tx_task, .bss.mesh_tx_mbox, g_mesh_init_ps_type, g_osi_funcs_p, g_log_level, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_tx_task_main.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.esp_mesh_send_block_event.str1.1, g_mesh_stop_event_group, g_mesh_topology, .rodata.__func__$9 +6 more
 * Fidelity: low - large state machine / jump-table switch; goto skeleton preserves flow, some blocks summarized
 * Edges: funcdb-v3 (calls=15, refs=33); reloc-direct=15, funcdb-attributed=0, unknown-indirect=34 */
u32 mesh_tx_task_main(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a7, a8, a9;
  float F0, F0000001, F4, F8;
  /* 010c: entry a1, 0x120 (frame 0x120 bytes) */
  a2 = 14;  /* 010f */
  a5 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0111: l32r -> .bss.mesh_tx_task (same-object static) */
  ST8(a1 + 0xec, a2);  /* 0114 */
  a2 = 9;  /* 0117 */
  ST32(a1 + 0xe8, a2);  /* 0119 */
  a2 = 0;  /* 011c */
  ST8(a5 + 0x14, a2);  /* 011e */
  __asm__ volatile("" ::: "memory");  /* 0121: memw */
  a2 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0124: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a2 = LD32(a2 + 0x78);  /* 0127 */
  ST32(a1 + 0xf0, a2);  /* 012a */
  __asm__ volatile("" ::: "memory");  /* 012d: memw */
  goto L_08e2;  /* 0130: j */
  L_0135: a4 = 9;  /* 0135 */
  a2 = LD8U(a5 + 0x14);  /* 0137 */
  ST32(a1 + 0xe8, a4);  /* 013a */
  a3 = (u32)&g_mesh_init_ps_type + 0x0;  /* 013d: l32r -> global */
  if (a2 == 0) goto L_01ca;  /* 0140: beqz a2, 1ca <mesh_tx_task_main+0xbe> */
  L_0143: a2 = 14;  /* 0143 */
  a11 = 236;  /* 0145 */
  a12 = -1;  /* 0148 */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 014a: l32r -> global */
  a11 = a11 + a1;  /* 014d */
  a7 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 014f: l32r -> .bss.mesh_tx_mbox (same-object static) */
  ST8(a1 + 0xec, a2);  /* 0152 */
  __asm__ volatile("" ::: "memory");  /* 0155: memw */
  a2 = LD32(a4 + 0x0);  /* 0158 */
  a10 = LD32(a7 + 0x90);  /* 015a */
  a2 = LD32(a2 + 0x74);  /* 015d */
  __asm__ volatile("" ::: "memory");  /* 0160: memw */
  /* 0163: INDIRECT callx a2 <- mem[a2+0x74]; result unknown */ a2 = 0;
  a2 = a10;  /* 0166 */
  if (a10 != 1) goto L_01ca;  /* 0168: bnei a10, 1, 1ca <mesh_tx_task_main+0xbe> */
  L_016b: a7 = 0;  /* 016b */
  a8 = LD8U(a1 + 0xec);  /* 016d */
  ST8(a5 + 0x14, a7);  /* 0170 */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  a7 = 15;  /* 0176 */
  if (a8 != a7) goto L_01ca;  /* 0178: bne a8, a7, 1ca <mesh_tx_task_main+0xbe> */
  L_017b: a7 = LD32(a4 + 0x0);  /* 017b */
  a10 = LD32(a1 + 0xf0);  /* 017e */
  a7 = LD32(a7 + 0x78);  /* 0181 */
  __asm__ volatile("" ::: "memory");  /* 0184: memw */
  /* 0187: INDIRECT callx a7 <- mem[a7+0x78]; result unknown */ a2 = 0;
  a6 = a10;  /* 018a */
  a7 = (u32)&g_log_level + 0x0;  /* 018c: l32r -> global */
  a7 = LD32(a7 + 0x0);  /* 018f */
  if (a7 < 3u) goto L_01c2;  /* 0191: bltui a7, 3, 1c2 <mesh_tx_task_main+0xb6> */
  L_0194: a4 = LD32(a4 + 0x0);  /* 0194 */
  if (a4 == 0) goto L_01c2;  /* 0196: beqz.n a4, 1c2 <mesh_tx_task_main+0xb6> */
  L_0198: a7 = LD32(a4 + 0x150);  /* 0198 */
  if (a7 == 0) goto L_01c2;  /* 019b: beqz.n a7, 1c2 <mesh_tx_task_main+0xb6> */
  L_019d: a10 = LD32(a4 + 0x158);  /* 019d */
  a4 = 0;  /* 01a0 */
  /* 01a3: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a15 = a4;  /* 01a6 */
  a13 = a10;  /* 01a8 */
  a9 = LD32(a3 + 0x0);  /* 01aa */
  a10 = 3;  /* 01ac */
  if (a9 != 0) a15 = a2;  /* 01ae */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 01b1: -> "mesh" */
  a14 = a11;  /* 01b4 */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 01b6: -> "stop" */
  ST32(a1 + 0x0, a6);  /* 01b9 */
  __asm__ volatile("" ::: "memory");  /* 01bc: memw */
  /* 01bf: INDIRECT callx a7 <- mem[a4+0x150]; result unknown */ a2 = 0;
  L_01c2: a10 = 0;  /* 01c2 */
  a8 = (u32)&mesh_tx_tid_stop;  /* 01c4: l32r -> func addr */
  a2 = mesh_tx_tid_stop(a2, a3, a4, a5, a6);  /* 01c7: callx a8 via reloc-expand */
  L_01ca: a2 = 14;  /* 01ca */
  ST8(a1 + 0xec, a2);  /* 01cc */
  __asm__ volatile("" ::: "memory");  /* 01cf: memw */
  a2 = LD32(a3 + 0x0);  /* 01d2 */
  if (a2 == 0) goto L_022d;  /* 01d4: beqz a2, 22d <mesh_tx_task_main+0x121> */
  L_01d7: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01d7: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 01da */
  a10 = LD32(a1 + 0xf0);  /* 01dd */
  a3 = LD32(a3 + 0x78);  /* 01e0 */
  __asm__ volatile("" ::: "memory");  /* 01e3: memw */
  /* 01e6: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  if (a10 == 0) goto L_022d;  /* 01e9: beqz a10, 22d <mesh_tx_task_main+0x121> */
  L_01ec: a11 = 236;  /* 01ec */
  a3 = LD32(a2 + 0x0);  /* 01ef */
  a12 = -1;  /* 01f2 */
  a11 = a11 + a1;  /* 01f5 */
  a3 = LD32(a3 + 0x74);  /* 01f7 */
  a10 = LD32(a1 + 0xf0);  /* 01fa */
  /* 01fd: INDIRECT callx a3 <- mem[a3+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_022d;  /* 0200: beqi a10, 1, 22d <mesh_tx_task_main+0x121> */
  L_0203: a2 = LD32(a2 + 0x0);  /* 0203 */
  if (a2 == 0) goto L_022d;  /* 0205: beqz.n a2, 22d <mesh_tx_task_main+0x121> */
  L_0207: a3 = LD32(a2 + 0x150);  /* 0207 */
  if (a3 == 0) goto L_022d;  /* 020a: beqz.n a3, 22d <mesh_tx_task_main+0x121> */
  L_020c: a10 = LD32(a2 + 0x158);  /* 020c */
  /* 020f: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0212 */
  a10 = 1;  /* 0214 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0216: -> "mesh" */
  a14 = a11;  /* 0219 */
  a2 = 0x000008b0u;  /* 021b: l32r = 2224 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 021e: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0221: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 0224 */
  __asm__ volatile("" ::: "memory");  /* 0227: memw */
  /* 022a: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_022d: a12 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 022d: l32r -> .bss.mesh_tx_task (same-object static) */
  a11 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0230: l32r -> .bss.mesh_tx_task (same-object static) */
  a10 = LD8U(a1 + 0xec);  /* 0233 */
  a8 = (u32)&tx_task_main;  /* 0236: l32r -> func addr */
  a2 = tx_task_main(a2, a3, a4, a5, a6);  /* 0239: callx a8 via reloc-expand */
  a2 = a10;  /* 023c */
  a3 = LD8U(a5 + 0xc);  /* 023e */
  if (a3 != 0) goto L_0260;  /* 0241: bnez.n a3, 260 <mesh_tx_task_main+0x154> */
  L_0243: a10 = 0;  /* 0243 */
  a2 = 0;  /* 0245 */
  a8 = (u32)&mesh_tx_tid_stop;  /* 0247: l32r -> func addr */
  a2 = mesh_tx_tid_stop(a2, a3, a4, a5, a6);  /* 024a: callx a8 via reloc-expand */
  ST32(a5 + 0x10, a2);  /* 024d */
  a2 = (u32)&g_mesh_stop_event_group + 0x0;  /* 024f: l32r -> global */
  a10 = LD32(a2 + 0x0);  /* 0252 */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0254: l32r -> global */
  if (a10 != 0) goto L_08ec;  /* 0257: bnez a10, 8ec <mesh_tx_task_main+0x7e0> */
  L_025a: __asm__ volatile("" ::: "memory");  /* 025a: memw */
  goto L_08f6;  /* 025d: j */
  L_0260: a3 = LD8U(a5 + 0x14);  /* 0260 */
  if (a3 != 0) goto L_08e2;  /* 0263: bnez a3, 8e2 <mesh_tx_task_main+0x7d6> */
  L_0266: a4 = (u32)&g_mesh_topology + 0x0;  /* 0266: l32r -> global */
  if (a10 == 0) goto L_0274;  /* 0269: beqz.n a10, 274 <mesh_tx_task_main+0x168> */
  L_026b: a3 = LD32(a10 + 0x0);  /* 026b */
  if (a3 != 0) goto L_0350;  /* 026d: bnez a3, 350 <mesh_tx_task_main+0x244> */
  L_0270: goto L_02a9;  /* 0270: j */
  L_0274: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0274: l32r -> global */
  a7 = LD32(a3 + 0x0);  /* 0277 */
  if (a7 == 0) goto L_0962;  /* 0279: beqz a7, 962 <mesh_tx_task_main+0x856> */
  L_027c: a6 = LD32(a7 + 0x150);  /* 027c */
  if (a6 == 0) goto L_0962;  /* 027f: beqz a6, 962 <mesh_tx_task_main+0x856> */
  L_0282: a10 = LD32(a7 + 0x158);  /* 0282 */
  /* 0285: INDIRECT callx a10 <- mem[a7+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0288 */
  a10 = 1;  /* 028a */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 028c: -> "mesh" */
  a14 = a11;  /* 028f: mov */
  a7 = 0x000008c0u;  /* 0292: l32r = 2240 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0295: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 0298: -> "stop" */
  ST32(a1 + 0x0, a7);  /* 029b */
  __asm__ volatile("" ::: "memory");  /* 029e: memw */
  /* 02a1: INDIRECT callx a6 <- mem[a7+0x150]; result unknown */ a2 = 0;
  goto L_0962;  /* 02a4: j */
  L_02a9: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 02a9: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 02ac */
  if (a3 != 0) goto L_02bd;  /* 02ae: bnez.n a3, 2bd <mesh_tx_task_main+0x1b1> */
  L_02b0: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 02b0: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 02b3 */
  if (a3 != 0) goto L_0324;  /* 02b5: bnez a3, 324 <mesh_tx_task_main+0x218> */
  L_02b8: goto L_0390;  /* 02b8: j */
  L_02bd: a7 = LD32(a3 + 0x150);  /* 02bd */
  if (a7 == 0) goto L_02b0;  /* 02c0: beqz a7, 2b0 <mesh_tx_task_main+0x1a4> */
  L_02c3: a10 = LD32(a3 + 0x158);  /* 02c3 */
  /* 02c6: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a8 = LD32(a2 + 0x28);  /* 02c9 */
  a3 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 02cb: -> "stop" */
  if (((a8 >> 4) & 1) != 0) goto L_02d4;  /* 02ce: bbsi a8, 4, 2d4 <mesh_tx_task_main+0x1c8> */
  L_02d1: a3 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 02d1: -> "no window" */
  L_02d4: a13 = a10;  /* 02d4 */
  a10 = 1;  /* 02d6 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 02d8: -> "mesh" */
  a14 = a11;  /* 02db */
  ST32(a1 + 0x8, a3);  /* 02dd */
  a3 = 0x000008c0u;  /* 02df: l32r = 2240 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 02e2: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 02e5: -> "stop" */
  ST32(a1 + 0x4, a2);  /* 02e8 */
  ST32(a1 + 0x0, a3);  /* 02eb */
  __asm__ volatile("" ::: "memory");  /* 02ee: memw */
  /* 02f1: INDIRECT callx a7 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_031c;  /* 02f4: j */
  L_02f7: a7 = LD32(a3 + 0x150);  /* 02f7 */
  if (a7 == 0) goto L_031c;  /* 02fa: beqz.n a7, 31c <mesh_tx_task_main+0x210> */
  L_02fc: a10 = LD32(a3 + 0x158);  /* 02fc */
  /* 02ff: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0302 */
  a10 = 1;  /* 0304 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0306: -> "mesh" */
  a14 = a11;  /* 0309 */
  a3 = 0x000008c0u;  /* 030b: l32r = 2240 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 030e: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0311: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 0314 */
  __asm__ volatile("" ::: "memory");  /* 0316: memw */
  /* 0319: INDIRECT callx a7 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_031c: a3 = LD32(a2 + 0x0);  /* 031c */
  if (a3 != 0) goto L_0390;  /* 031e: bnez a3, 390 <mesh_tx_task_main+0x284> */
  L_0321: goto L_02b0;  /* 0321: j */
  L_0324: a7 = LD32(a3 + 0x150);  /* 0324 */
  if (a7 == 0) goto L_0390;  /* 0327: beqz a7, 390 <mesh_tx_task_main+0x284> */
  L_032a: a10 = LD32(a3 + 0x158);  /* 032a */
  /* 032d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0330 */
  a10 = 1;  /* 0332 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0334: -> "mesh" */
  a14 = a11;  /* 0337: mov */
  a3 = 0x000008c0u;  /* 033a: l32r = 2240 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 033d: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0340: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 0343 */
  __asm__ volatile("" ::: "memory");  /* 0346: memw */
  /* 0349: INDIRECT callx a7 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0390;  /* 034c: j */
  L_0350: a9 = LD32(a4 + 0x0);  /* 0350 */
  a3 = 42;  /* 0352 */
  a8 = 47;  /* 0354 */
  if (a9 != 0) a3 = a8;  /* 0356 */
  a7 = LD16U(a10 + 0x4);  /* 0359 */
  if (a7 >= a3) goto L_03a2;  /* 035c: bgeu a7, a3, 3a2 <mesh_tx_task_main+0x296> */
  L_035f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 035f: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0362 */
  if (a3 == 0) goto L_0390;  /* 0364: beqz.n a3, 390 <mesh_tx_task_main+0x284> */
  L_0366: a7 = LD32(a3 + 0x150);  /* 0366 */
  if (a7 == 0) goto L_0390;  /* 0369: beqz.n a7, 390 <mesh_tx_task_main+0x284> */
  L_036b: a10 = LD32(a3 + 0x158);  /* 036b */
  /* 036e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0371 */
  a10 = 1;  /* 0373 */
  a3 = LD16U(a2 + 0x4);  /* 0375 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0378: -> "mesh" */
  a14 = a11;  /* 037b */
  ST32(a1 + 0x4, a3);  /* 037d */
  a3 = 0x000008c0u;  /* 037f: l32r = 2240 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0382: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 0385: -> "stop" */
  ST32(a1 + 0x0, a3);  /* 0388 */
  __asm__ volatile("" ::: "memory");  /* 038a: memw */
  /* 038d: INDIRECT callx a7 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_0390: a13 = 35;  /* 0390 */
  a13 = a13 << 6;  /* 0392 */
  a11 = 8;  /* 0395 */
  a12 = (u32)(RODATA__rodata___func___9 + 0x0);  /* 0397: l32r -> .rodata.__func__$9 */
  a10 = a2;  /* 039a */
  a8 = (u32)&esp_mesh_discard_context;  /* 039c: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6);  /* 039f: callx a8 via reloc-expand */
  L_03a2: a9 = 33;  /* 03a2 */
  a3 = LD32(a2 + 0x28);  /* 03a4 */
  a8 = (a3 >> 5) & 0x3ff;  /* 03a6: extui width 10 */
  a3 = 28;  /* 03a9 */
  a10 = LD32(a4 + 0x0);  /* 03ab */
  if (a10 != 0) a3 = a9;  /* 03ad */
  a3 = a3 + (14);  /* 03b0 */
  ST8(a1 + 0xec, a8);  /* 03b2 */
  __asm__ volatile("" ::: "memory");  /* 03b5: memw */
  a6 = LD32(a2 + 0x0);  /* 03b8 */
  a9 = a6 + (18);  /* 03ba */
  a3 = a6 + a3;  /* 03bd */
  a10 = LD32(a9 + 0x0);  /* 03bf */
  if (a8 != 8) goto L_03d1;  /* 03c1: bnei a8, 8, 3d1 <mesh_tx_task_main+0x2c5> */
  L_03c4: a7 = a6 + (14);  /* 03c4 */
  a10 = 0x0fffffffu;  /* 03c6: l32r = 268435455 */
  ST32(a7 + 0x18, a10);  /* 03c9 */
  __asm__ volatile("" ::: "memory");  /* 03cb: memw */
  goto L_0435;  /* 03ce: j */
  L_03d1: a7 = 0x403;  /* 03d1 */
  a7 = a7 << 14;  /* 03d4 */
  a10 = a10 & a7;  /* 03d7 */
  a7 = 1;  /* 03da */
  a7 = a7 << 24;  /* 03dc */
  if (a10 != a7) goto L_0429;  /* 03df: bne a10, a7, 429 <mesh_tx_task_main+0x31d> */
  L_03e2: a7 = a6 + (14);  /* 03e2 */
  a12 = LD32(a7 + 0x18);  /* 03e4 */
  if (a12 == 0) goto L_0429;  /* 03e6: beqz.n a12, 429 <mesh_tx_task_main+0x31d> */
  L_03e8: a7 = 0xf0000001u;  /* 03e8: l32r = -268435455 */
  a7 = a12 + a7;  /* 03eb */
  if (a7 == 0) goto L_0429;  /* 03ed: beqz.n a7, 429 <mesh_tx_task_main+0x31d> */
  L_03ef: a11 = 2;  /* 03ef */
  a7 = (u32)(RODATA__rodata___func___9 + 0x0);  /* 03f1: l32r -> .rodata.__func__$9 */
  a10 = a2;  /* 03f4 */
  a13 = a7;  /* 03f6: mov */
  a14 = 0x000008f3u;  /* 03f9: l32r = 2291 */
  ST32(a1 + 0xfc, a9);  /* 03fc */
  __asm__ volatile("" ::: "memory");  /* 03ff: memw */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 0402: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0405: callx a8 via reloc-expand */
  a11 = 0x00004004u;  /* 0408: l32r = 16388 */
  a9 = LD32(a1 + 0xfc);  /* 040b */
  if (a10 != a11) goto L_0429;  /* 040e: bne a10, a11, 429 <mesh_tx_task_main+0x31d> */
  L_0411: a13 = 0x23f;  /* 0411 */
  a11 = a10;  /* 0414 */
  a13 = a13 << 2;  /* 0416 */
  a12 = a7;  /* 0419 */
  a10 = a2;  /* 041b: mov */
  a8 = (u32)&esp_mesh_discard_context;  /* 041e: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6);  /* 0421: callx a8 via reloc-expand */
  goto L_08e2;  /* 0424: j */
  L_0429: a7 = LD8U(a1 + 0xec);  /* 0429 */
  a7 = a7 + (-6);  /* 042c */
  a7 = (a7 >> 8) & 0x1;  /* 042f: extui width 1 */
  if (a7 >= 2u) goto L_03c4;  /* 0432: bgeui a7, 2, 3c4 <mesh_tx_task_main+0x2b8> */
  L_0435: a9 = LD32(a9 + 0x0);  /* 0435 */
  a7 = 0x0800c000u;  /* 0437: l32r = 134266880 */
  if ((a9 & a7) == 0) goto L_0440;  /* 043a: bnone a9, a7, 440 <mesh_tx_task_main+0x334> */
  L_043d: goto L_0520;  /* 043d: j */
  L_0440: a12 = 6;  /* 0440 */
  a10 = a6 + (22);  /* 0442 */
  a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 0445: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  ST32(a1 + 0xfc, a9);  /* 0448 */
  __asm__ volatile("" ::: "memory");  /* 044b: memw */
  a8 = (u32)&memcmp + 0x0;  /* 044e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 0451: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0xfc);  /* 0454 */
  if (a10 == 0) goto L_0520;  /* 0457: beqz a10, 520 <mesh_tx_task_main+0x414> */
  L_045a: a7 = LD8U(a6 + 0x16);  /* 045a */
  if (((a7 >> 0) & 1) == 0) goto L_0469;  /* 045d: bbci a7, 0, 469 <mesh_tx_task_main+0x35d> */
  L_0460: a7 = LD8U(a6 + 0xe);  /* 0460 */
  if (((a7 >> 5) & 1) != 0) goto L_0469;  /* 0463: bbsi a7, 5, 469 <mesh_tx_task_main+0x35d> */
  L_0466: goto L_0520;  /* 0466: j */
  L_0469: a7 = 1;  /* 0469 */
  a7 = a7 << 24;  /* 046b */
  a7 = a9 & a7;  /* 046e */
  if (a7 == 0) goto L_0485;  /* 0471: beqz.n a7, 485 <mesh_tx_task_main+0x379> */
  L_0473: a13 = LD32(a4 + 0x0);  /* 0473 */
  a11 = 28;  /* 0475 */
  a12 = 33;  /* 0477 */
  if (a13 != 0) a11 = a12;  /* 0479 */
  a10 = LD8U(a6 + 0xf);  /* 047c */
  a10 = a10 - a11;  /* 047f: subx4 */
  if (a10 >= 4u) goto L_04a1;  /* 0482: bgeui a10, 4, 4a1 <mesh_tx_task_main+0x395> */
  L_0485: if (((a9 >> 23) & 1) != 0) goto L_048b;  /* 0485: bbsi a9, 23, 48b <mesh_tx_task_main+0x37f> */
  L_0488: goto L_0974;  /* 0488: j */
  L_048b: a13 = LD32(a4 + 0x0);  /* 048b */
  a11 = 28;  /* 048d */
  a12 = 33;  /* 048f */
  if (a13 != 0) a11 = a12;  /* 0492 */
  a10 = LD8U(a6 + 0xf);  /* 0495 */
  a10 = a10 - a11;  /* 0498: subx4 */
  if (a10 >= 3u) goto L_04a1;  /* 049b: bgeui a10, 3, 4a1 <mesh_tx_task_main+0x395> */
  L_049e: goto L_096c;  /* 049e: j */
  L_04a1: a10 = LD8U(a3 + 0x0);  /* 04a1 */
  if (a10 != 4) goto L_04ac;  /* 04a4: bnei a10, 4, 4ac <mesh_tx_task_main+0x3a0> */
  L_04a7: a10 = LD32(a2 + 0x28);  /* 04a7 */
  if (((a10 >> 0) & 1) != 0) goto L_0520;  /* 04a9: bbsi a10, 0, 520 <mesh_tx_task_main+0x414> */
  L_04ac: if (a7 == 0) goto L_04c0;  /* 04ac: beqz.n a7, 4c0 <mesh_tx_task_main+0x3b4> */
  L_04ae: a10 = 28;  /* 04ae */
  a12 = LD32(a4 + 0x0);  /* 04b0 */
  a11 = 33;  /* 04b2 */
  if (a12 != 0) a10 = a11;  /* 04b4 */
  a7 = LD8U(a6 + 0xf);  /* 04b7 */
  a7 = a7 - a10;  /* 04ba: subx4 */
  if (a7 >= 4u) goto L_04d5;  /* 04bd: bgeui a7, 4, 4d5 <mesh_tx_task_main+0x3c9> */
  L_04c0: if (((a9 >> 23) & 1) == 0) goto L_04e9;  /* 04c0: bbci a9, 23, 4e9 <mesh_tx_task_main+0x3dd> */
  L_04c3: a9 = LD32(a4 + 0x0);  /* 04c3 */
  a8 = 33;  /* 04c5 */
  a4 = 28;  /* 04c7 */
  if (a9 != 0) a4 = a8;  /* 04c9 */
  a7 = LD8U(a6 + 0xf);  /* 04cc */
  a4 = a7 - a4;  /* 04cf: subx4 */
  if (a4 < 3u) goto L_04e9;  /* 04d2: bltui a4, 3, 4e9 <mesh_tx_task_main+0x3dd> */
  L_04d5: a3 = LD8U(a3 + 0x0);  /* 04d5 */
  if (a3 != 4) goto L_04e9;  /* 04d8: bnei a3, 4, 4e9 <mesh_tx_task_main+0x3dd> */
  L_04db: a4 = 0;  /* 04db */
  a3 = (u32)&g_is_wifi_connected + 0x0;  /* 04dd: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 04e0 */
  if (a3 != a4) goto L_04e9;  /* 04e3: bne a3, a4, 4e9 <mesh_tx_task_main+0x3dd> */
  L_04e6: goto L_08c0;  /* 04e6: j */
  L_04e9: a3 = (u32)&LOCAL__bss_mesh_ack_state_mbox + 0x0;  /* 04e9: l32r -> .bss.mesh_ack_state_mbox (same-object static) */
  a7 = (u32)(RODATA__rodata___func___9 + 0x0);  /* 04ec: l32r -> .rodata.__func__$9 */
  a11 = a7;  /* 04ef */
  a12 = 0x00000937u;  /* 04f1: l32r = 2359 */
  a10 = LD32(a3 + 0x4);  /* 04f4 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 04f7: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 04fa: callx a8 via reloc-expand */
  a8 = a1 + (48);  /* 04fd */
  a11 = 184;  /* 0500 */
  a11 = a8 + a11;  /* 0503 */
  a10 = a2;  /* 0505 */
  a8 = (u32)&esp_mesh_best_effort_tx;  /* 0507: l32r -> func addr */
  a2 = esp_mesh_best_effort_tx(a2, a3, a4, a5, a6);  /* 050a: callx a8 via reloc-expand */
  a4 = a10;  /* 050d */
  a12 = 0x00000939u;  /* 050f: l32r = 2361 */
  a11 = a7;  /* 0512 */
  a10 = LD32(a3 + 0x4);  /* 0514 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0516: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6);  /* 0519: callx a8 via reloc-expand */
  goto L_08b5;  /* 051c: j */
  L_0520: a4 = LD32(a2 + 0x0);  /* 0520 */
  a8 = a2 + (6);  /* 0522 */
  a11 = a8;  /* 0524 */
  a12 = 6;  /* 0526 */
  a10 = a4;  /* 0528 */
  ST32(a1 + 0xf4, a8);  /* 052a */
  __asm__ volatile("" ::: "memory");  /* 052d: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0530: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 0533: callx a8 (libc, via reloc-expand) */
  a7 = -18;  /* 0536 */
  a11 = a4 + (6);  /* 0538 */
  a10 = LD8U(a2 + 0x12);  /* 053b */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 053e: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6, a7);  /* 0541: callx a8 via reloc-expand */
  ST8(a4 + 0xc, a7);  /* 0544 */
  ST8(a4 + 0xd, a7);  /* 0547 */
  __asm__ volatile("" ::: "memory");  /* 054a: memw */
  a7 = a6 + (18);  /* 054d */
  L_0550: a4 = LD8U(a1 + 0xec);  /* 0550 */
  if (a4 == 5) goto L_0559;  /* 0553: beqi a4, 5, 559 <mesh_tx_task_main+0x44d> */
  L_0556: goto L_0669;  /* 0556: j */
  L_0559: a4 = 1;  /* 0559 */
  a4 = a4 << 24;  /* 055b */
  a9 = LD32(a7 + 0x0);  /* 055e */
  a4 = a9 & a4;  /* 0560 */
  if (a4 == 0) goto L_057c;  /* 0563: beqz.n a4, 57c <mesh_tx_task_main+0x470> */
  L_0565: a12 = 33;  /* 0565 */
  a11 = (u32)&g_mesh_topology + 0x0;  /* 0568: l32r -> global */
  a13 = LD32(a11 + 0x0);  /* 056b */
  a11 = 28;  /* 056e */
  if (a13 != 0) a11 = a12;  /* 0570 */
  a10 = LD8U(a6 + 0xf);  /* 0573 */
  a10 = a10 - a11;  /* 0576: subx4 */
  if (a10 >= 4u) goto L_059c;  /* 0579: bgeui a10, 4, 59c <mesh_tx_task_main+0x490> */
  L_057c: if (((a9 >> 23) & 1) != 0) goto L_0582;  /* 057c: bbsi a9, 23, 582 <mesh_tx_task_main+0x476> */
  L_057f: goto L_0669;  /* 057f: j */
  L_0582: a11 = (u32)&g_mesh_topology + 0x0;  /* 0582: l32r -> global */
  a12 = 33;  /* 0585 */
  a13 = LD32(a11 + 0x0);  /* 0588 */
  a11 = 28;  /* 058b */
  if (a13 != 0) a11 = a12;  /* 058d */
  a10 = LD8U(a6 + 0xf);  /* 0590 */
  a10 = a10 - a11;  /* 0593: subx4 */
  if (a10 >= 3u) goto L_059c;  /* 0596: bgeui a10, 3, 59c <mesh_tx_task_main+0x490> */
  L_0599: goto L_0669;  /* 0599: j */
  L_059c: a10 = LD8U(a3 + 0x0);  /* 059c */
  a11 = a10 + (-3);  /* 059f */
  a11 = (a11 >> 8) & 0x1;  /* 05a2: extui width 1 */
  if (a11 < 2u) goto L_05ab;  /* 05a5: bltui a11, 2, 5ab <mesh_tx_task_main+0x49f> */
  L_05a8: goto L_0669;  /* 05a8: j */
  L_05ab: a11 = (u32)&g_mesh_is_root + 0x0;  /* 05ab: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 05ae: memw */
  a11 = LD8U(a11 + 0x0);  /* 05b1 */
  a11 = (a11 >> 8) & 0x1;  /* 05b4: extui width 1 */
  if (a11 != 0) goto L_05c2;  /* 05b7: bnez.n a11, 5c2 <mesh_tx_task_main+0x4b6> */
  L_05b9: a11 = (u32)&g_is_wifi_connected + 0x0;  /* 05b9: l32r -> global */
  a11 = LD8U(a11 + 0x0);  /* 05bc */
  if (a11 != 0) goto L_0669;  /* 05bf: bnez a11, 669 <mesh_tx_task_main+0x55d> */
  L_05c2: if (a4 == 0) goto L_05da;  /* 05c2: beqz.n a4, 5da <mesh_tx_task_main+0x4ce> */
  L_05c4: a7 = (u32)&g_mesh_topology + 0x0;  /* 05c4: l32r -> global */
  a11 = 33;  /* 05c7 */
  a12 = LD32(a7 + 0x0);  /* 05c9 */
  a7 = 28;  /* 05cb */
  if (a12 != 0) a7 = a11;  /* 05ce */
  a4 = LD8U(a6 + 0xf);  /* 05d1 */
  a4 = a4 - a7;  /* 05d4: subx4 */
  if (a4 >= 4u) goto L_05fa;  /* 05d7: bgeui a4, 4, 5fa <mesh_tx_task_main+0x4ee> */
  L_05da: a4 = 0;  /* 05da */
  if (((a9 >> 23) & 1) != 0) goto L_05e2;  /* 05dc: bbsi a9, 23, 5e2 <mesh_tx_task_main+0x4d6> */
  L_05df: goto L_077d;  /* 05df: j */
  L_05e2: a9 = (u32)&g_mesh_topology + 0x0;  /* 05e2: l32r -> global */
  a11 = 33;  /* 05e5 */
  a12 = LD32(a9 + 0x0);  /* 05e7 */
  a9 = 28;  /* 05e9 */
  if (a12 != 0) a9 = a11;  /* 05eb */
  a7 = LD8U(a6 + 0xf);  /* 05ee */
  a7 = a7 - a9;  /* 05f1: subx4 */
  if (a7 >= 3u) goto L_05fa;  /* 05f4: bgeui a7, 3, 5fa <mesh_tx_task_main+0x4ee> */
  L_05f7: goto L_077d;  /* 05f7: j */
  L_05fa: a4 = 0;  /* 05fa */
  if (a10 == 4) goto L_0602;  /* 05fc: beqi a10, 4, 602 <mesh_tx_task_main+0x4f6> */
  L_05ff: goto L_077d;  /* 05ff: j */
  L_0602: a11 = a4;  /* 0602 */
  a7 = 37;  /* 0604 */
  a12 = 180;  /* 0607 */
  a10 = a1 + (52);  /* 060a */
  __asm__ volatile("" ::: "memory");  /* 060d: memw */
  a8 = (u32)&memset + 0x0;  /* 0610: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0613: callx a8 (libc, via reloc-expand) */
  ST32(a1 + 0x30, a7);  /* 0616 */
  a7 = 7;  /* 0618 */
  a11 = a4;  /* 061a */
  a10 = a1 + (48);  /* 061c */
  ST8(a1 + 0x34, a7);  /* 061f */
  __asm__ volatile("" ::: "memory");  /* 0622: memw */
  a7 = a6 + (14);  /* 0625 */
  a7 = LD32(a7 + 0x14);  /* 0627 */
  ST32(a1 + 0x38, a7);  /* 0629 */
  __asm__ volatile("" ::: "memory");  /* 062c: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 062f: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 0632: callx a8 via reloc-expand */
  if (a10 == a4) goto L_0664;  /* 0635: beq a10, a4, 664 <mesh_tx_task_main+0x558> */
  L_0638: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0638: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 063b */
  if (a4 == 0) goto L_0664;  /* 063d: beqz.n a4, 664 <mesh_tx_task_main+0x558> */
  L_063f: a7 = LD32(a4 + 0x150);  /* 063f */
  if (a7 == 0) goto L_0664;  /* 0642: beqz.n a7, 664 <mesh_tx_task_main+0x558> */
  L_0644: a10 = LD32(a4 + 0x158);  /* 0644 */
  /* 0647: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 064a */
  a10 = 1;  /* 064c */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 064e: -> "mesh" */
  a14 = a11;  /* 0651 */
  a4 = 0x00000952u;  /* 0653: l32r = 2386 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0656: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0659: -> "no window" */
  ST32(a1 + 0x0, a4);  /* 065c */
  __asm__ volatile("" ::: "memory");  /* 065e: memw */
  /* 0661: INDIRECT callx a7 <- mem[a4+0x150]; result unknown */ a2 = 0;
  L_0664: a4 = 0;  /* 0664 */
  goto L_077d;  /* 0666: j */
  L_0669: a11 = LD32(a2 + 0x0);  /* 0669 */
  a13 = LD32(a1 + 0xf4);  /* 066b */
  a12 = LD16U(a2 + 0x4);  /* 066e */
  a10 = LD8U(a2 + 0x12);  /* 0671 */
  a8 = (u32)&esp_wifi_mesh_tx + 0x0;  /* 0674: l32r -> global */
  a2 = esp_wifi_mesh_tx(a2, a3, a4, a5, a6);  /* 0677: callx a8 via reloc-expand */
  a4 = a10;  /* 067a */
  a11 = LD32(a7 + 0x0);  /* 067c */
  if (((a11 >> 24) & 1) != 0) goto L_0684;  /* 067e: bbsi a11, 24, 684 <mesh_tx_task_main+0x578> */
  L_0681: goto L_0956;  /* 0681: j */
  L_0684: a9 = 84;  /* 0684 */
  if (a10 == a9) goto L_068c;  /* 0686: beq a10, a9, 68c <mesh_tx_task_main+0x580> */
  L_0689: goto L_095c;  /* 0689: j */
  L_068c: a9 = (u32)&g_osi_funcs_p + 0x0;  /* 068c: l32r -> global */
  a10 = 10;  /* 068f */
  a9 = LD32(a9 + 0x0);  /* 0692 */
  a11 = LD32(a9 + 0x9c);  /* 0695 */
  a9 = LD32(a9 + 0xa0);  /* 0698 */
  ST32(a1 + 0xf8, a11);  /* 069b */
  __asm__ volatile("" ::: "memory");  /* 069e: memw */
  /* 06a1: INDIRECT callx a9 <- mem[a9+0xa0]; result unknown */ a2 = 0;
  a11 = LD32(a1 + 0xf8);  /* 06a4 */
  /* 06a7: INDIRECT callx a11 <- mem[a1+0xf8]; result unknown */ a2 = 0;
  goto L_0771;  /* 06aa: j */
  L_06ad: a10 = (u32)&g_mesh_topology + 0x0;  /* 06ad: l32r -> global */
  a12 = 33;  /* 06b0 */
  a13 = LD32(a10 + 0x0);  /* 06b2 */
  a10 = 28;  /* 06b4 */
  if (a13 != 0) a10 = a12;  /* 06b6 */
  a9 = LD8U(a6 + 0xf);  /* 06b9 */
  a9 = a9 - a10;  /* 06bc: subx4 */
  if (a9 >= 4u) goto L_06e1;  /* 06bf: bgeui a9, 4, 6e1 <mesh_tx_task_main+0x5d5> */
  L_06c2: if (((a11 >> 23) & 1) != 0) goto L_06c8;  /* 06c2: bbsi a11, 23, 6c8 <mesh_tx_task_main+0x5bc> */
  L_06c5: goto L_0771;  /* 06c5: j */
  L_06c8: a10 = (u32)&g_mesh_topology + 0x0;  /* 06c8: l32r -> global */
  a11 = 33;  /* 06cb */
  a12 = LD32(a10 + 0x0);  /* 06cd */
  a10 = 28;  /* 06cf */
  if (a12 != 0) a10 = a11;  /* 06d2 */
  a9 = LD8U(a6 + 0xf);  /* 06d5 */
  a9 = a9 - a10;  /* 06d8: subx4 */
  if (a9 >= 3u) goto L_06e1;  /* 06db: bgeui a9, 3, 6e1 <mesh_tx_task_main+0x5d5> */
  L_06de: goto L_0771;  /* 06de: j */
  L_06e1: a9 = LD8U(a3 + 0x0);  /* 06e1 */
  if (a9 == 4) goto L_06ea;  /* 06e4: beqi a9, 4, 6ea <mesh_tx_task_main+0x5de> */
  L_06e7: goto L_0771;  /* 06e7: j */
  L_06ea: a12 = 180;  /* 06ea */
  a11 = 0;  /* 06ed */
  a10 = a1 + (52);  /* 06ef */
  a8 = (u32)&memset + 0x0;  /* 06f2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 06f5: callx a8 (libc, via reloc-expand) */
  a9 = 37;  /* 06f8 */
  ST32(a1 + 0x30, a9);  /* 06fa */
  a9 = 8;  /* 06fc */
  ST8(a1 + 0x34, a9);  /* 06fe */
  __asm__ volatile("" ::: "memory");  /* 0701: memw */
  a9 = a6 + (14);  /* 0704 */
  a9 = LD32(a9 + 0x14);  /* 0706 */
  ST32(a1 + 0x38, a9);  /* 0708 */
  a9 = (u32)&g_osi_funcs_p + 0x0;  /* 070a: l32r -> global */
  a10 = LD32(a9 + 0x0);  /* 070d */
  a11 = LD32(a10 + 0x9c);  /* 0710 */
  a12 = LD32(a10 + 0xa0);  /* 0713 */
  a10 = 10;  /* 0716 */
  ST32(a1 + 0xfc, a9);  /* 0718 */
  ST32(a1 + 0xf8, a11);  /* 071b */
  __asm__ volatile("" ::: "memory");  /* 071e: memw */
  /* 0721: INDIRECT callx a12 <- mem[a10+0xa0]; result unknown */ a2 = 0;
  a11 = LD32(a1 + 0xf8);  /* 0724 */
  /* 0727: INDIRECT callx a11 <- mem[a1+0xf8]; result unknown */ a2 = 0;
  a11 = 0;  /* 072a */
  a10 = a1 + (48);  /* 072c */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 072f: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6);  /* 0732: callx a8 via reloc-expand */
  a9 = LD32(a1 + 0xfc);  /* 0735 */
  if (a10 == 0) goto L_0771;  /* 0738: beqz.n a10, 771 <mesh_tx_task_main+0x665> */
  L_073a: a10 = LD32(a9 + 0x0);  /* 073a */
  if (a10 == 0) goto L_0771;  /* 073d: beqz a10, 771 <mesh_tx_task_main+0x665> */
  L_0740: a9 = LD32(a10 + 0x150);  /* 0740 */
  if (a9 == 0) goto L_0771;  /* 0743: beqz.n a9, 771 <mesh_tx_task_main+0x665> */
  L_0745: a10 = LD32(a10 + 0x158);  /* 0745 */
  ST32(a1 + 0xfc, a9);  /* 0748 */
  __asm__ volatile("" ::: "memory");  /* 074b: memw */
  /* 074e: INDIRECT callx a10 <- mem[a10+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0751 */
  a10 = 1;  /* 0753 */
  a12 = 0x00000969u;  /* 0756: l32r = 2409 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0759: -> "mesh" */
  a14 = a11;  /* 075c: mov */
  ST32(a1 + 0x0, a12);  /* 075f */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0762: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0765: -> "no window" */
  a9 = LD32(a1 + 0xfc);  /* 0768 */
  __asm__ volatile("" ::: "memory");  /* 076b: memw */
  /* 076e: INDIRECT callx a9 <- mem[a1+0xfc]; result unknown */ a2 = 0;
  L_0771: a9 = LD8U(a7 + 0x3);  /* 0771 */
  if (((a9 >> 0) & 1) == 0) goto L_077d;  /* 0774: bbci a9, 0, 77d <mesh_tx_task_main+0x671> */
  L_0777: a9 = a4 + (-84);  /* 0777 */
  if (a9 == 0) goto L_0550;  /* 077a: beqz a9, 550 <mesh_tx_task_main+0x444> */
  L_077d: a7 = (u32)&g_is_wifi_connected + 0x0;  /* 077d: l32r -> global */
  a7 = LD8U(a7 + 0x0);  /* 0780 */
  a9 = LD8U(a1 + 0xec);  /* 0783 */
  if (a7 == 0) goto L_07f0;  /* 0786: beqz a7, 7f0 <mesh_tx_task_main+0x6e4> */
  L_0789: a7 = (u32)&g_mesh_is_root + 0x0;  /* 0789: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 078c: memw */
  a7 = LD8U(a7 + 0x0);  /* 078f */
  a7 = (a7 >> 8) & 0x1;  /* 0792: extui width 1 */
  if (a7 != 0) goto L_07f0;  /* 0795: bnez a7, 7f0 <mesh_tx_task_main+0x6e4> */
  L_0798: if (a9 == 5) goto L_079e;  /* 0798: beqi a9, 5, 79e <mesh_tx_task_main+0x692> */
  L_079b: goto L_08b5;  /* 079b: j */
  L_079e: a7 = a6 + (18);  /* 079e */
  a10 = LD32(a7 + 0x0);  /* 07a1 */
  a7 = LD32(a2 + 0x28);  /* 07a3 */
  if (((a7 >> 0) & 1) != 0) goto L_07b4;  /* 07a5: bbsi a7, 0, 7b4 <mesh_tx_task_main+0x6a8> */
  L_07a8: a7 = a6 + (18);  /* 07a8 */
  a10 = LD32(a7 + 0x0);  /* 07ab */
  if (((a10 >> 24) & 1) != 0) goto L_07fd;  /* 07ad: bbsi a10, 24, 7fd <mesh_tx_task_main+0x6f1> */
  L_07b0: goto L_0812;  /* 07b0: j */
  L_07b4: if (((a10 >> 24) & 1) == 0) goto L_07cc;  /* 07b4: bbci a10, 24, 7cc <mesh_tx_task_main+0x6c0> */
  L_07b7: a9 = (u32)&g_mesh_topology + 0x0;  /* 07b7: l32r -> global */
  a11 = 33;  /* 07ba */
  a12 = LD32(a9 + 0x0);  /* 07bc */
  a9 = 28;  /* 07be */
  if (a12 != 0) a9 = a11;  /* 07c0 */
  a7 = LD8U(a6 + 0xf);  /* 07c3 */
  a7 = a7 - a9;  /* 07c6: subx4 */
  if (a7 >= 4u) goto L_07e4;  /* 07c9: bgeui a7, 4, 7e4 <mesh_tx_task_main+0x6d8> */
  L_07cc: if (((a10 >> 23) & 1) == 0) goto L_07a8;  /* 07cc: bbci a10, 23, 7a8 <mesh_tx_task_main+0x69c> */
  L_07cf: a9 = (u32)&g_mesh_topology + 0x0;  /* 07cf: l32r -> global */
  a10 = 33;  /* 07d2 */
  a11 = LD32(a9 + 0x0);  /* 07d4 */
  a9 = 28;  /* 07d6 */
  if (a11 != 0) a9 = a10;  /* 07d8 */
  a7 = LD8U(a6 + 0xf);  /* 07db */
  a7 = a7 - a9;  /* 07de: subx4 */
  if (a7 < 3u) goto L_07a8;  /* 07e1: bltui a7, 3, 7a8 <mesh_tx_task_main+0x69c> */
  L_07e4: a7 = LD8U(a3 + 0x0);  /* 07e4 */
  if (a7 != 3) goto L_07a8;  /* 07e7: bnei a7, 3, 7a8 <mesh_tx_task_main+0x69c> */
  L_07ea: a8 = (u32)&route_announce_timer_start + 0x0;  /* 07ea: l32r -> global */
  a2 = route_announce_timer_start(a2, a3, a4, a5, a6);  /* 07ed: callx a8 via reloc-expand */
  L_07f0: a7 = LD8U(a1 + 0xec);  /* 07f0 */
  if (a7 == 5) goto L_07f9;  /* 07f3: beqi a7, 5, 7f9 <mesh_tx_task_main+0x6ed> */
  L_07f6: goto L_08b5;  /* 07f6: j */
  L_07f9: goto L_07a8;  /* 07f9: j */
  L_07fd: a9 = (u32)&g_mesh_topology + 0x0;  /* 07fd: l32r -> global */
  a11 = 33;  /* 0800 */
  a12 = LD32(a9 + 0x0);  /* 0802 */
  a9 = 28;  /* 0804 */
  if (a12 != 0) a9 = a11;  /* 0806 */
  a7 = LD8U(a6 + 0xf);  /* 0809 */
  a7 = a7 - a9;  /* 080c: subx4 */
  if (a7 >= 4u) goto L_0831;  /* 080f: bgeui a7, 4, 831 <mesh_tx_task_main+0x725> */
  L_0812: if (((a10 >> 23) & 1) != 0) goto L_0818;  /* 0812: bbsi a10, 23, 818 <mesh_tx_task_main+0x70c> */
  L_0815: goto L_08b5;  /* 0815: j */
  L_0818: a9 = (u32)&g_mesh_topology + 0x0;  /* 0818: l32r -> global */
  a10 = 33;  /* 081b */
  a11 = LD32(a9 + 0x0);  /* 081d */
  a9 = 28;  /* 081f */
  if (a11 != 0) a9 = a10;  /* 0822 */
  a7 = LD8U(a6 + 0xf);  /* 0825 */
  a7 = a7 - a9;  /* 0828: subx4 */
  if (a7 >= 3u) goto L_0831;  /* 082b: bgeui a7, 3, 831 <mesh_tx_task_main+0x725> */
  L_082e: goto L_08b5;  /* 082e: j */
  L_0831: a7 = LD8U(a3 + 0x0);  /* 0831 */
  if (a7 != 1) goto L_08b5;  /* 0834: bnei a7, 1, 8b5 <mesh_tx_task_main+0x7a9> */
  L_0837: a7 = LD32(a2 + 0x28);  /* 0837 */
  if (((a7 >> 0) & 1) == 0) goto L_08b5;  /* 0839: bbci a7, 0, 8b5 <mesh_tx_task_main+0x7a9> */
  L_083c: a7 = (u32)&g_log_level + 0x0;  /* 083c: l32r -> global */
  a7 = LD32(a7 + 0x0);  /* 083f */
  if (a7 < 3u) goto L_08b5;  /* 0841: bltui a7, 3, 8b5 <mesh_tx_task_main+0x7a9> */
  L_0844: a7 = (u32)&g_osi_funcs_p + 0x0;  /* 0844: l32r -> global */
  a9 = LD32(a7 + 0x0);  /* 0847 */
  if (a9 == 0) goto L_08b5;  /* 0849: beqz a9, 8b5 <mesh_tx_task_main+0x7a9> */
  L_084c: a7 = LD32(a9 + 0x150);  /* 084c */
  if (a7 == 0) goto L_08b5;  /* 084f: beqz a7, 8b5 <mesh_tx_task_main+0x7a9> */
  L_0852: a10 = LD32(a9 + 0x158);  /* 0852 */
  /* 0855: INDIRECT callx a10 <- mem[a9+0x158]; result unknown */ a2 = 0;
  ST32(a1 + 0xf8, a10);  /* 0858 */
  __asm__ volatile("" ::: "memory");  /* 085b: memw */
  a8 = (u32)&esp_mesh_get_layer + 0x0;  /* 085e: l32r -> global */
  a2 = esp_mesh_get_layer(a2, a3, a4, a5, a6);  /* 0861: callx a8 via reloc-expand */
  a11 = LD32(a2 + 0x28);  /* 0864 */
  a9 = (u32)(RODATA__rodata_mesh_check_tid_mbox_full_str1_1 + 0x0);  /* 0866: -> "xmit" */
  a13 = LD32(a1 + 0xf8);  /* 0869 */
  if (((a11 >> 0) & 1) != 0) goto L_0872;  /* 086c: bbsi a11, 0, 872 <mesh_tx_task_main+0x766> */
  L_086f: a9 = (u32)(RODATA__rodata_mesh_check_tid_mbox_full_str1_1 + 0x0);  /* 086f: -> "xmit" */
  L_0872: a11 = LD8U(a3 + 0x3);  /* 0872 */
  a3 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 0875: -> "stop" */
  if (a11 == 0) goto L_087d;  /* 0878: beqz.n a11, 87d <mesh_tx_task_main+0x771> */
  L_087a: a3 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 087a: -> "stop" */
  L_087d: a12 = LD8U(a6 + 0x1b);  /* 087d */
  ST32(a1 + 0x20, a12);  /* 0880 */
  a12 = LD8U(a6 + 0x1a);  /* 0882 */
  ST32(a1 + 0x1c, a12);  /* 0885 */
  a12 = LD8U(a6 + 0x19);  /* 0887 */
  ST32(a1 + 0x18, a12);  /* 088a */
  a12 = LD8U(a6 + 0x18);  /* 088c */
  ST32(a1 + 0x14, a12);  /* 088f */
  a12 = LD8U(a6 + 0x17);  /* 0891 */
  ST32(a1 + 0x10, a12);  /* 0894 */
  a8 = LD8U(a6 + 0x16);  /* 0896 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0899: -> "mesh" */
  a14 = a11;  /* 089c */
  a15 = 0x0000097bu;  /* 089e: l32r = 2427 */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 08a1: -> "stop" */
  ST32(a1 + 0x0, a10);  /* 08a4 */
  a10 = 3;  /* 08a6 */
  ST32(a1 + 0xc, a8);  /* 08a8 */
  ST32(a1 + 0x8, a3);  /* 08aa */
  ST32(a1 + 0x4, a9);  /* 08ac */
  __asm__ volatile("" ::: "memory");  /* 08af: memw */
  /* 08b2: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_08b5: if (a4 == 0) goto L_08c0;  /* 08b5: beqz.n a4, 8c0 <mesh_tx_task_main+0x7b4> */
  L_08b7: a7 = (u32)&LOCAL__bss_mesh_tx_fail_cnt_8 + 0x0;  /* 08b7: l32r -> .bss.mesh_tx_fail_cnt$8 (same-object static) */
  a3 = LD32(a7 + 0x0);  /* 08ba */
  a3 = a3 + (1);  /* 08bc */
  ST32(a7 + 0x0, a3);  /* 08be */
  L_08c0: a10 = a2;  /* 08c0 */
  a13 = 0x000009d1u;  /* 08c2: l32r = 2513 */
  a12 = (u32)(RODATA__rodata___func___9 + 0x0);  /* 08c5: l32r -> .rodata.__func__$9 */
  a11 = LD32(a1 + 0xe8);  /* 08c8 */
  __asm__ volatile("" ::: "memory");  /* 08cb: memw */
  a8 = (u32)&esp_mesh_discard_context;  /* 08ce: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6);  /* 08d1: callx a8 via reloc-expand */
  a2 = 0x00004004u;  /* 08d4: l32r = 16388 */
  if (a4 != a2) goto L_08e2;  /* 08d7: bne a4, a2, 8e2 <mesh_tx_task_main+0x7d6> */
  L_08da: a10 = 0;  /* 08da */
  a8 = (u32)&mesh_tx_tid_stop;  /* 08dc: l32r -> func addr */
  a2 = mesh_tx_tid_stop(a2, a3, a4, a5, a6);  /* 08df: callx a8 via reloc-expand */
  L_08e2: a2 = LD8U(a5 + 0xc);  /* 08e2 */
  if (a2 != 0) goto L_0135;  /* 08e5: bnez a2, 135 <mesh_tx_task_main+0x29> */
  L_08e8: goto L_0243;  /* 08e8: j */
  L_08ec: a3 = LD32(a2 + 0x0);  /* 08ec */
  a11 = 2;  /* 08ee */
  a3 = LD32(a3 + 0x84);  /* 08f0 */
  /* 08f3: INDIRECT callx a3 <- mem[a3+0x84]; result unknown */ a2 = 0;
  L_08f6: a3 = LD32(a2 + 0x0);  /* 08f6 */
  if (a3 == 0) goto L_0921;  /* 08f8: beqz.n a3, 921 <mesh_tx_task_main+0x815> */
  L_08fa: a4 = LD32(a3 + 0x150);  /* 08fa */
  if (a4 == 0) goto L_0921;  /* 08fd: beqz a4, 921 <mesh_tx_task_main+0x815> */
  L_0900: a10 = LD32(a3 + 0x158);  /* 0900 */
  /* 0903: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0906 */
  a10 = 2;  /* 0908 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 090a: -> "mesh" */
  a14 = a11;  /* 090d */
  a3 = 0x000009dcu;  /* 090f: l32r = 2524 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0912: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 0915: -> "stop" */
  ST32(a1 + 0x0, a3);  /* 0918 */
  __asm__ volatile("" ::: "memory");  /* 091b: memw */
  /* 091e: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_0921: a3 = LD32(a2 + 0x0);  /* 0921 */
  if (a3 == 0) goto L_094a;  /* 0923: beqz.n a3, 94a <mesh_tx_task_main+0x83e> */
  L_0925: a4 = LD32(a3 + 0x150);  /* 0925 */
  if (a4 == 0) goto L_094a;  /* 0928: beqz.n a4, 94a <mesh_tx_task_main+0x83e> */
  L_092a: a10 = LD32(a3 + 0x158);  /* 092a */
  /* 092d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0930 */
  a10 = 2;  /* 0932 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0934: -> "mesh" */
  a14 = a11;  /* 0937 */
  a3 = 0x000009ddu;  /* 0939: l32r = 2525 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 093c: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 093f: -> "stop" */
  ST32(a1 + 0x0, a3);  /* 0942 */
  __asm__ volatile("" ::: "memory");  /* 0944: memw */
  /* 0947: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_094a: a10 = 0;  /* 094a */
  a2 = LD32(a2 + 0x0);  /* 094c */
  a2 = LD32(a2 + 0x98);  /* 094e */
  /* 0951: INDIRECT callx a2 <- mem[a2+0x98]; result unknown */ a2 = 0;
  return a2;  /* 0954: retw.n */
  L_0956: if (a10 == 0) goto L_077d;  /* 0956: beqz a10, 77d <mesh_tx_task_main+0x671> */
  L_0959: goto L_06c2;  /* 0959: j */
  L_095c: if (a10 != 0) goto L_06ad;  /* 095c: bnez a10, 6ad <mesh_tx_task_main+0x5a1> */
  L_095f: goto L_077d;  /* 095f: j */
  L_0962: a3 = LD32(a3 + 0x0);  /* 0962 */
  if (a3 != 0) goto L_02f7;  /* 0964: bnez a3, 2f7 <mesh_tx_task_main+0x1eb> */
  L_0967: goto L_031c;  /* 0967: j */
  L_096c: if (a7 != 0) goto L_04ae;  /* 096c: bnez a7, 4ae <mesh_tx_task_main+0x3a2> */
  L_096f: goto L_04c3;  /* 096f: j */
  L_0974: if (a7 == 0) goto L_04e9;  /* 0974: beqz a7, 4e9 <mesh_tx_task_main+0x3dd> */
  L_0977: goto L_04ae;  /* 0977: j */
  L_ret: return a2;
}


/* mesh_tx_tid_stop @ mesh_schedule.o 00000048 size 424B bind GLOBAL
 * Calls: mesh_get_tx_pending, mesh_flush_txQ | indirect[10]: mem[a3+0x78]; mem[a4+0x78]; mem[a8+0x158]; mem[a1+0x4c] | Data refs: g_osi_funcs_p, .bss.mesh_tx_mbox, g_log_level, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_tx_tid_stop.str1.1, g_mesh_ext_cfg
 * Fidelity: medium - 10 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=8); reloc-direct=2, funcdb-attributed=0, unknown-indirect=10 */
u32 mesh_tx_tid_stop(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F6;
  /* 0048: entry a1, 112 (frame 112 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 004b: extui width 1 */
  a10 = a1 + (32);  /* 004e */
  a8 = (u32)&mesh_get_tx_pending;  /* 0051: l32r -> func addr */
  a2 = mesh_get_tx_pending(a2, a3, a4, a5, a6, a7);  /* 0054: callx a8 via reloc-expand */
  if (a2 != 0) goto L_016d;  /* 0057: bnez a2, 16d <mesh_tx_tid_stop+0x125> */
  L_005a: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 005a: l32r -> global */
  a2 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 005d: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a3 = LD32(a5 + 0x0);  /* 0060 */
  a10 = LD32(a2 + 0x48);  /* 0063 */
  a3 = LD32(a3 + 0x78);  /* 0066 */
  /* 0069: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a7 = a10;  /* 006c */
  a3 = LD32(a5 + 0x0);  /* 006e */
  a10 = LD32(a2 + 0x54);  /* 0070 */
  a3 = LD32(a3 + 0x78);  /* 0073 */
  /* 0076: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a6 = a10;  /* 0079 */
  a3 = LD32(a5 + 0x0);  /* 007b */
  a10 = LD32(a2 + 0x90);  /* 007d */
  a3 = LD32(a3 + 0x78);  /* 0080 */
  /* 0083: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a3 = a10;  /* 0086 */
  a4 = LD32(a5 + 0x0);  /* 0088 */
  a10 = LD32(a2 + 0x78);  /* 008b */
  a4 = LD32(a4 + 0x78);  /* 008e */
  /* 0091: INDIRECT callx a4 <- mem[a4+0x78]; result unknown */ a2 = 0;
  a2 = a10;  /* 0094 */
  a8 = LD32(a1 + 0x28);  /* 0096 */
  a9 = (u32)&g_log_level + 0x0;  /* 0098: l32r -> global */
  a4 = LD32(a1 + 0x30);  /* 009b */
  ST32(a1 + 0x44, a8);  /* 009d */
  a8 = LD32(a1 + 0x2c);  /* 00a0 */
  a9 = LD32(a9 + 0x0);  /* 00a2 */
  ST32(a1 + 0x48, a4);  /* 00a4 */
  ST32(a1 + 0x40, a8);  /* 00a7 */
  a4 = LD32(a1 + 0x34);  /* 00aa */
  if (a9 < 3u) goto L_00f6;  /* 00ac: bltui a9, 3, f6 <mesh_tx_tid_stop+0xae> */
  L_00af: a8 = LD32(a5 + 0x0);  /* 00af */
  if (a8 == 0) goto L_00f6;  /* 00b1: beqz a8, f6 <mesh_tx_tid_stop+0xae> */
  L_00b4: a9 = LD32(a8 + 0x150);  /* 00b4 */
  if (a9 == 0) goto L_00f6;  /* 00b7: beqz.n a9, f6 <mesh_tx_tid_stop+0xae> */
  L_00b9: a10 = LD32(a8 + 0x158);  /* 00b9 */
  ST32(a1 + 0x4c, a9);  /* 00bc */
  __asm__ volatile("" ::: "memory");  /* 00bf: memw */
  /* 00c2: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00c5 */
  a15 = 0x790;  /* 00c7 */
  a10 = 3;  /* 00ca */
  a5 = LD32(a1 + 0x40);  /* 00cc */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00cf: -> "mesh" */
  a14 = a11;  /* 00d2 */
  a8 = LD32(a1 + 0x44);  /* 00d4 */
  ST32(a1 + 0x14, a5);  /* 00d7 */
  a5 = LD32(a1 + 0x48);  /* 00d9 */
  a12 = (u32)(RODATA__rodata_mesh_tx_tid_stop_str1_1 + 0x0);  /* 00dc: l32r -> .rodata.mesh_tx_tid_stop.str1.1 */
  a9 = LD32(a1 + 0x4c);  /* 00df */
  ST32(a1 + 0x1c, a2);  /* 00e2 */
  ST32(a1 + 0x18, a3);  /* 00e4 */
  ST32(a1 + 0x10, a8);  /* 00e6 */
  ST32(a1 + 0xc, a4);  /* 00e8 */
  ST32(a1 + 0x8, a5);  /* 00ea */
  ST32(a1 + 0x4, a6);  /* 00ec */
  ST32(a1 + 0x0, a7);  /* 00ee */
  __asm__ volatile("" ::: "memory");  /* 00f0: memw */
  /* 00f3: INDIRECT callx a9 <- mem[a1+0x4c]; result unknown */ a2 = 0;
  L_00f6: if (a7 == 0) goto L_0102;  /* 00f6: beqz.n a7, 102 <mesh_tx_tid_stop+0xba> */
  L_00f8: a11 = a7;  /* 00f8 */
  a10 = 1;  /* 00fa */
  a8 = (u32)&mesh_flush_txQ;  /* 00fc: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 00ff: callx a8 via reloc-expand */
  L_0102: if (a6 == 0) goto L_0119;  /* 0102: beqz.n a6, 119 <mesh_tx_tid_stop+0xd1> */
  L_0104: a7 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0104: l32r -> global */
  a11 = a6;  /* 0107 */
  a10 = LD8U(a7 + 0xbd);  /* 0109 */
  a10 = a10 + a10;  /* 010c */
  a10 = a10 + (1);  /* 010e */
  a10 = (a10 >> 8) & 0x1;  /* 0110: extui width 1 */
  a8 = (u32)&mesh_flush_txQ;  /* 0113: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 0116: callx a8 via reloc-expand */
  L_0119: a8 = LD32(a1 + 0x48);  /* 0119 */
  if (a8 == 0) goto L_0129;  /* 011c: beqz.n a8, 129 <mesh_tx_tid_stop+0xe1> */
  L_011e: a11 = a8;  /* 011e */
  a10 = 5;  /* 0120 */
  a8 = (u32)&mesh_flush_txQ;  /* 0123: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 0126: callx a8 via reloc-expand */
  L_0129: if (a4 == 0) goto L_0135;  /* 0129: beqz.n a4, 135 <mesh_tx_tid_stop+0xed> */
  L_012b: a11 = a4;  /* 012b */
  a10 = 8;  /* 012d */
  a8 = (u32)&mesh_flush_txQ;  /* 012f: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 0132: callx a8 via reloc-expand */
  L_0135: a4 = LD32(a1 + 0x44);  /* 0135 */
  if (a4 == 0) goto L_0145;  /* 0138: beqz.n a4, 145 <mesh_tx_tid_stop+0xfd> */
  L_013a: a11 = a4;  /* 013a */
  a10 = 1;  /* 013c */
  a8 = (u32)&mesh_flush_txQ;  /* 013f: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 0142: callx a8 via reloc-expand */
  L_0145: a5 = LD32(a1 + 0x40);  /* 0145 */
  if (a5 == 0) goto L_0154;  /* 0148: beqz.n a5, 154 <mesh_tx_tid_stop+0x10c> */
  L_014a: a11 = a5;  /* 014a */
  a10 = 2;  /* 014c */
  a8 = (u32)&mesh_flush_txQ;  /* 014e: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 0151: callx a8 via reloc-expand */
  L_0154: if (a3 == 0) goto L_0160;  /* 0154: beqz.n a3, 160 <mesh_tx_tid_stop+0x118> */
  L_0156: a11 = a3;  /* 0156 */
  a10 = 12;  /* 0158 */
  a8 = (u32)&mesh_flush_txQ;  /* 015a: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 015d: callx a8 via reloc-expand */
  L_0160: a11 = a2;  /* 0160 */
  a10 = 10;  /* 0162 */
  if (a2 != 0) goto L_01e8;  /* 0164: bnez a2, 1e8 <mesh_tx_tid_stop+0x1a0> */
  L_0167: goto L_01ee;  /* 0167: j */
  L_016d: if (a2 != 1) goto L_01ee;  /* 016d: bnei a2, 1, 1ee <mesh_tx_tid_stop+0x1a6> */
  L_0170: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0170: l32r -> global */
  a2 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0173: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a3 = LD32(a5 + 0x0);  /* 0176 */
  a10 = LD32(a2 + 0x9c);  /* 0178 */
  a3 = LD32(a3 + 0x78);  /* 017b */
  /* 017e: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a3 = a10;  /* 0181 */
  a4 = LD32(a5 + 0x0);  /* 0183 */
  a10 = LD32(a2 + 0x84);  /* 0185 */
  a4 = LD32(a4 + 0x78);  /* 0188 */
  /* 018b: INDIRECT callx a4 <- mem[a4+0x78]; result unknown */ a2 = 0;
  a2 = a10;  /* 018e */
  a6 = (u32)&g_log_level + 0x0;  /* 0190: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 0193 */
  a4 = LD32(a1 + 0x24);  /* 0195 */
  if (a6 < 3u) goto L_01ca;  /* 0197: bltui a6, 3, 1ca <mesh_tx_tid_stop+0x182> */
  L_019a: a5 = LD32(a5 + 0x0);  /* 019a */
  if (a5 == 0) goto L_01ca;  /* 019c: beqz.n a5, 1ca <mesh_tx_tid_stop+0x182> */
  L_019e: a6 = LD32(a5 + 0x150);  /* 019e */
  if (a6 == 0) goto L_01ca;  /* 01a1: beqz a6, 1ca <mesh_tx_tid_stop+0x182> */
  L_01a4: a10 = LD32(a5 + 0x158);  /* 01a4 */
  /* 01a7: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01aa */
  a15 = 0x7b2;  /* 01ac */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 01af: -> "mesh" */
  a10 = 3;  /* 01b2 */
  a14 = a11;  /* 01b4 */
  a5 = LD32(a1 + 0x20);  /* 01b6 */
  a12 = (u32)(RODATA__rodata_mesh_tx_tid_stop_str1_1 + 0x0);  /* 01b8: l32r -> .rodata.mesh_tx_tid_stop.str1.1 */
  ST32(a1 + 0xc, a2);  /* 01bb */
  ST32(a1 + 0x8, a3);  /* 01bd */
  ST32(a1 + 0x4, a4);  /* 01bf */
  ST32(a1 + 0x0, a5);  /* 01c1 */
  __asm__ volatile("" ::: "memory");  /* 01c4: memw */
  /* 01c7: INDIRECT callx a6 <- mem[a5+0x150]; result unknown */ a2 = 0;
  L_01ca: if (a4 == 0) goto L_01d6;  /* 01ca: beqz.n a4, 1d6 <mesh_tx_tid_stop+0x18e> */
  L_01cc: a11 = a4;  /* 01cc */
  a10 = 0;  /* 01ce */
  a8 = (u32)&mesh_flush_txQ;  /* 01d0: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 01d3: callx a8 via reloc-expand */
  L_01d6: if (a3 == 0) goto L_01e2;  /* 01d6: beqz.n a3, 1e2 <mesh_tx_tid_stop+0x19a> */
  L_01d8: a11 = a3;  /* 01d8 */
  a10 = 13;  /* 01da */
  a8 = (u32)&mesh_flush_txQ;  /* 01dc: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 01df: callx a8 via reloc-expand */
  L_01e2: if (a2 == 0) goto L_01ee;  /* 01e2: beqz.n a2, 1ee <mesh_tx_tid_stop+0x1a6> */
  L_01e4: a11 = a2;  /* 01e4 */
  a10 = 11;  /* 01e6 */
  L_01e8: a8 = (u32)&mesh_flush_txQ;  /* 01e8: l32r -> func addr */
  a2 = mesh_flush_txQ(a2, a3, a4, a5, a6, a7);  /* 01eb: callx a8 via reloc-expand */
  L_01ee: return a2;  /* 01ee: retw.n */
}


/* mesh_xon_deliver_packet @ mesh_schedule.o 00000054 size 360B bind GLOBAL
 * Calls: esp_mesh_match_self, memcmp, esp_mesh_delivery_toSelf, esp_mesh_delivery_toDS, esp_mesh_discard_context | indirect[7]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, g_mesh_is_root, .bss.MESH_ZERO_ADDR, .rodata.mesh_xon_deliver_packet.str1.1, .rodata.__func__$6
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=13); reloc-direct=5, funcdb-attributed=0, unknown-indirect=7 */
u32 mesh_xon_deliver_packet(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0054: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0086;  /* 0057: bnez.n a2, 86 <mesh_xon_deliver_packet+0x32> */
  L_0059: a2 = (u32)&g_log_level + 0x0;  /* 0059: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 005c */
  a3 = 0x00004008u;  /* 005e: l32r = 16392 */
  if (a2 >= 3u) goto L_0067;  /* 0061: bgeui a2, 3, 67 <mesh_xon_deliver_packet+0x13> */
  L_0064: goto L_01b8;  /* 0064: j */
  L_0067: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0067: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 006a */
  if (a2 == 0) goto L_01b8;  /* 006d: beqz a2, 1b8 <mesh_xon_deliver_packet+0x164> */
  L_0070: a4 = LD32(a2 + 0x150);  /* 0070 */
  if (a4 == 0) goto L_01b8;  /* 0073: beqz a4, 1b8 <mesh_xon_deliver_packet+0x164> */
  L_0076: a10 = LD32(a2 + 0x158);  /* 0076 */
  /* 0079: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 007c: -> "mesh" */
  a2 = 0x000009f9u;  /* 007f: l32r = 2553 */
  goto L_00b3;  /* 0082: j */
  L_0086: a10 = LD32(a2 + 0x0);  /* 0086 */
  if (a10 != 0) goto L_00cc;  /* 0088: bnez a10, cc <mesh_xon_deliver_packet+0x78> */
  L_008b: a2 = (u32)&g_log_level + 0x0;  /* 008b: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 008e */
  a3 = 0x00004008u;  /* 0090: l32r = 16392 */
  if (a2 >= 3u) goto L_0099;  /* 0093: bgeui a2, 3, 99 <mesh_xon_deliver_packet+0x45> */
  L_0096: goto L_01b8;  /* 0096: j */
  L_0099: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0099: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 009c */
  if (a2 == 0) goto L_01b8;  /* 009e: beqz a2, 1b8 <mesh_xon_deliver_packet+0x164> */
  L_00a1: a4 = LD32(a2 + 0x150);  /* 00a1 */
  if (a4 == 0) goto L_01b8;  /* 00a4: beqz a4, 1b8 <mesh_xon_deliver_packet+0x164> */
  L_00a7: a10 = LD32(a2 + 0x158);  /* 00a7 */
  /* 00aa: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00ad: -> "mesh" */
  a2 = 0x000009fau;  /* 00b0: l32r = 2554 */
  L_00b3: a13 = a10;  /* 00b3 */
  a14 = a11;  /* 00b5 */
  a10 = 3;  /* 00b7 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00b9: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00bc: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a2);  /* 00bf */
  __asm__ volatile("" ::: "memory");  /* 00c2: memw */
  /* 00c5: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_01b8;  /* 00c8: j */
  L_00cc: a3 = (u32)&g_mesh_is_root + 0x0;  /* 00cc: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 00cf: memw */
  a8 = LD8U(a3 + 0x0);  /* 00d2 */
  a3 = -1;  /* 00d5 */
  a8 = (a8 >> 8) & 0x1;  /* 00d7: extui width 1 */
  if (a8 == 0) goto L_01b8;  /* 00da: beqz a8, 1b8 <mesh_xon_deliver_packet+0x164> */
  L_00dd: a4 = LD8U(a10 + 0xe);  /* 00dd */
  if (((a4 >> 5) & 1) != 0) goto L_00e6;  /* 00e0: bbsi a4, 5, e6 <mesh_xon_deliver_packet+0x92> */
  L_00e3: goto L_01b8;  /* 00e3: j */
  L_00e6: a4 = 4;  /* 00e6 */
  a3 = LD32(a2 + 0x28);  /* 00e8 */
  a3 = a3 | a4;  /* 00ea */
  ST32(a2 + 0x28, a3);  /* 00ed */
  a3 = a10 + (18);  /* 00ef */
  a3 = LD32(a3 + 0x0);  /* 00f2 */
  if (((a3 >> 22) & 1) == 0) goto L_0162;  /* 00f4: bbci a3, 22, 162 <mesh_xon_deliver_packet+0x10e> */
  L_00f7: a3 = a10 + (22);  /* 00f7 */
  a10 = a3;  /* 00fa */
  __asm__ volatile("" ::: "memory");  /* 00fc: memw */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 00ff: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0102: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0119;  /* 0105: bnez.n a10, 119 <mesh_xon_deliver_packet+0xc5> */
  L_0107: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 0107: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 010a */
  a10 = a3;  /* 010c */
  a8 = (u32)&memcmp + 0x0;  /* 010e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0111: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0119;  /* 0114: beqz.n a10, 119 <mesh_xon_deliver_packet+0xc5> */
  L_0116: goto L_01b6;  /* 0116: j */
  L_0119: a10 = a2;  /* 0119 */
  a8 = (u32)&esp_mesh_delivery_toSelf + 0x0;  /* 011b: l32r -> global */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 011e: callx a8 via reloc-expand */
  a5 = a10;  /* 0121 */
  if (a10 == 0) goto L_01b6;  /* 0123: beqz a10, 1b6 <mesh_xon_deliver_packet+0x162> */
  L_0126: a3 = (u32)&g_log_level + 0x0;  /* 0126: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0129 */
  if (a3 < 3u) goto L_0159;  /* 012b: bltui a3, 3, 159 <mesh_xon_deliver_packet+0x105> */
  L_012e: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 012e: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0131 */
  if (a3 == 0) goto L_0159;  /* 0133: beqz.n a3, 159 <mesh_xon_deliver_packet+0x105> */
  L_0135: a4 = LD32(a3 + 0x150);  /* 0135 */
  if (a4 == 0) goto L_0159;  /* 0138: beqz.n a4, 159 <mesh_xon_deliver_packet+0x105> */
  L_013a: a10 = LD32(a3 + 0x158);  /* 013a */
  /* 013d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a15 = 0x505;  /* 0140 */
  a13 = a10;  /* 0143 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0145: -> "mesh" */
  a15 = a15 + a15;  /* 0148 */
  a14 = a11;  /* 014a */
  a10 = 3;  /* 014c */
  a12 = (u32)(RODATA__rodata_mesh_xon_deliver_packet_str1_1 + 0x0);  /* 014e: l32r -> .rodata.mesh_xon_deliver_packet.str1.1 */
  ST32(a1 + 0x0, a5);  /* 0151 */
  __asm__ volatile("" ::: "memory");  /* 0153: memw */
  /* 0156: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_0159: a13 = 0x00000a0bu;  /* 0159: l32r = 2571 */
  goto L_01a8;  /* 015c: j */
  L_0162: a10 = a2;  /* 0162 */
  a8 = (u32)&esp_mesh_delivery_toDS + 0x0;  /* 0164: l32r -> global */
  a2 = esp_mesh_delivery_toDS(a2, a3, a4, a5, a6, a7);  /* 0167: callx a8 via reloc-expand */
  a5 = a10;  /* 016a */
  if (a10 == 0) goto L_01b6;  /* 016c: beqz a10, 1b6 <mesh_xon_deliver_packet+0x162> */
  L_016f: a3 = (u32)&g_log_level + 0x0;  /* 016f: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0172 */
  if (a3 < 3u) goto L_01a5;  /* 0174: bltui a3, 3, 1a5 <mesh_xon_deliver_packet+0x151> */
  L_0177: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0177: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 017a */
  if (a3 == 0) goto L_01a5;  /* 017c: beqz.n a3, 1a5 <mesh_xon_deliver_packet+0x151> */
  L_017e: a4 = LD32(a3 + 0x150);  /* 017e */
  if (a4 == 0) goto L_01a5;  /* 0181: beqz.n a4, 1a5 <mesh_xon_deliver_packet+0x151> */
  L_0183: a10 = LD32(a3 + 0x158);  /* 0183 */
  /* 0186: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a15 = 0x509;  /* 0189 */
  a13 = a10;  /* 018c */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 018e: -> "mesh" */
  a15 = a15 + a15;  /* 0191 */
  a14 = a11;  /* 0193: mov */
  a10 = 3;  /* 0196 */
  a12 = (u32)(RODATA__rodata_mesh_xon_deliver_packet_str1_1 + 0x0);  /* 0199: l32r -> .rodata.mesh_xon_deliver_packet.str1.1 */
  ST32(a1 + 0x0, a5);  /* 019c */
  __asm__ volatile("" ::: "memory");  /* 019f: memw */
  /* 01a2: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_01a5: a13 = 0x00000a13u;  /* 01a5: l32r = 2579 */
  L_01a8: a10 = a2;  /* 01a8 */
  a12 = (u32)(RODATA__rodata___func___6 + 0x0);  /* 01aa: -> "mesh_xon_deliver_packet" */
  a11 = 0x00004015u;  /* 01ad: l32r = 16405 */
  a8 = (u32)&esp_mesh_discard_context;  /* 01b0: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 01b3: callx a8 via reloc-expand */
  L_01b6: a3 = 0;  /* 01b6 */
  L_01b8: a2 = a3;  /* 01b8 */
  return a2;  /* 01ba: retw.n */
}


/* mesh_xon_flush_packets @ mesh_schedule.o 00000058 size 547B bind GLOBAL
 * Calls: esp_mesh_discard_context, esp_mesh_txupQ_pending, mesh_xon_deliver_packet | indirect[14]: mem[a2+0x74]; mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x158] | Data refs: .bss.mesh_tx_mbox, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.mesh_tx_task_main.str1.1, .rodata.esp_mesh_send_block_event.str1.1, g_mesh_topology, .rodata.__func__$5, g_mesh_is_root, g_osi_funcs_p
 * Fidelity: medium - 14 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=12); reloc-direct=3, funcdb-attributed=0, unknown-indirect=14 */
u32 mesh_xon_flush_packets(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a26, a35, a39, a8;
  float F0000001;
  /* 0058: entry a1, 64 (frame 64 bytes) */
  a2 = 0;  /* 005b */
  ST32(a1 + 0x10, a2);  /* 005d */
  __asm__ volatile("" ::: "memory");  /* 005f: memw */
  goto L_0263;  /* 0062: j */
  L_0065: a2 = 0;  /* 0065 */
  a4 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0067: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a12 = -1;  /* 006a */
  a11 = a1 + (16);  /* 006c */
  ST32(a1 + 0x10, a2);  /* 006f */
  a2 = LD32(a3 + 0x0);  /* 0071 */
  a10 = LD32(a4 + 0x0);  /* 0073 */
  a2 = LD32(a2 + 0x74);  /* 0075 */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  /* 007b: INDIRECT callx a2 <- mem[a2+0x74]; result unknown */ a2 = 0;
  a7 = a10;  /* 007e */
  if (a10 == 1) goto L_0086;  /* 0080: beqi a10, 1, 86 <mesh_xon_flush_packets+0x2e> */
  L_0083: goto L_0263;  /* 0083: j */
  L_0086: a2 = LD32(a1 + 0x10);  /* 0086 */
  if (a2 == 0) goto L_0092;  /* 0088: beqz.n a2, 92 <mesh_xon_flush_packets+0x3a> */
  L_008a: a5 = LD32(a2 + 0x0);  /* 008a */
  if (a5 != 0) goto L_016d;  /* 008c: bnez a5, 16d <mesh_xon_flush_packets+0x115> */
  L_008f: goto L_00cc;  /* 008f: j */
  L_0092: a2 = LD32(a3 + 0x0);  /* 0092 */
  if (a2 != 0) goto L_00a0;  /* 0094: bnez.n a2, a0 <mesh_xon_flush_packets+0x48> */
  L_0096: a2 = LD32(a3 + 0x0);  /* 0096 */
  if (a2 != 0) goto L_0111;  /* 0098: bnez a2, 111 <mesh_xon_flush_packets+0xb9> */
  L_009b: goto L_0136;  /* 009b: j */
  L_00a0: a5 = LD32(a2 + 0x150);  /* 00a0 */
  if (a5 == 0) goto L_0096;  /* 00a3: beqz a5, 96 <mesh_xon_flush_packets+0x3e> */
  L_00a6: a10 = LD32(a2 + 0x158);  /* 00a6 */
  /* 00a9: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ac */
  a10 = a7;  /* 00ae */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00b0: -> "mesh" */
  a14 = a11;  /* 00b3: mov */
  a2 = 0x00000a26u;  /* 00b6: l32r = 2598 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00b9: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 00bc: -> "stop" */
  ST32(a1 + 0x0, a2);  /* 00bf */
  __asm__ volatile("" ::: "memory");  /* 00c2: memw */
  /* 00c5: INDIRECT callx a5 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0108;  /* 00c8: j */
  L_00cc: a2 = LD32(a3 + 0x0);  /* 00cc */
  if (a2 == 0) goto L_013d;  /* 00ce: beqz a2, 13d <mesh_xon_flush_packets+0xe5> */
  L_00d1: a5 = LD32(a2 + 0x150);  /* 00d1 */
  if (a5 == 0) goto L_013d;  /* 00d4: beqz a5, 13d <mesh_xon_flush_packets+0xe5> */
  L_00d7: a10 = LD32(a2 + 0x158);  /* 00d7 */
  /* 00da: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = LD32(a1 + 0x10);  /* 00dd */
  a7 = LD32(a2 + 0x28);  /* 00df */
  a6 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 00e1: -> "stop" */
  if (((a7 >> 4) & 1) != 0) goto L_00ea;  /* 00e4: bbsi a7, 4, ea <mesh_xon_flush_packets+0x92> */
  L_00e7: a6 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 00e7: -> "no window" */
  L_00ea: a13 = a10;  /* 00ea */
  a10 = 1;  /* 00ec */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00ee: -> "mesh" */
  a14 = a11;  /* 00f1 */
  ST32(a1 + 0x4, a2);  /* 00f3 */
  a2 = 0x00000a26u;  /* 00f5: l32r = 2598 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00f8: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 00fb: -> "stop" */
  ST32(a1 + 0x8, a6);  /* 00fe */
  ST32(a1 + 0x0, a2);  /* 0100 */
  __asm__ volatile("" ::: "memory");  /* 0102: memw */
  /* 0105: INDIRECT callx a5 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0108: a2 = LD32(a1 + 0x10);  /* 0108 */
  if (a2 != 0) goto L_0136;  /* 010a: bnez.n a2, 136 <mesh_xon_flush_packets+0xde> */
  L_010c: goto L_0096;  /* 010c: j */
  L_0111: a5 = LD32(a2 + 0x150);  /* 0111 */
  if (a5 == 0) goto L_0136;  /* 0114: beqz.n a5, 136 <mesh_xon_flush_packets+0xde> */
  L_0116: a10 = LD32(a2 + 0x158);  /* 0116 */
  /* 0119: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 011c */
  a10 = 1;  /* 011e */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0120: -> "mesh" */
  a14 = a11;  /* 0123 */
  a2 = 0x00000a26u;  /* 0125: l32r = 2598 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0128: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 012b: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 012e */
  __asm__ volatile("" ::: "memory");  /* 0130: memw */
  /* 0133: INDIRECT callx a5 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0136: a2 = LD32(a1 + 0x10);  /* 0136 */
  a2 = LD32(a2 + 0x0);  /* 0138 */
  if (a2 != 0) goto L_01dd;  /* 013a: bnez a2, 1dd <mesh_xon_flush_packets+0x185> */
  L_013d: a2 = LD32(a3 + 0x0);  /* 013d */
  if (a2 == 0) goto L_01dd;  /* 013f: beqz a2, 1dd <mesh_xon_flush_packets+0x185> */
  L_0142: a3 = LD32(a2 + 0x150);  /* 0142 */
  if (a3 == 0) goto L_01dd;  /* 0145: beqz a3, 1dd <mesh_xon_flush_packets+0x185> */
  L_0148: a10 = LD32(a2 + 0x158);  /* 0148 */
  /* 014b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 014e */
  a10 = 1;  /* 0150 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0152: -> "mesh" */
  a14 = a11;  /* 0155 */
  a2 = 0x00000a26u;  /* 0157: l32r = 2598 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 015a: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 015d: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 0160 */
  __asm__ volatile("" ::: "memory");  /* 0162: memw */
  /* 0165: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_01dd;  /* 0168: j */
  L_016d: a5 = LD16U(a2 + 0x4);  /* 016d */
  a6 = 47;  /* 0170 */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 0172: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 0175 */
  a2 = 42;  /* 0177 */
  if (a8 != 0) a2 = a6;  /* 0179 */
  if (a5 >= a2) goto L_01f0;  /* 017c: bgeu a5, a2, 1f0 <mesh_xon_flush_packets+0x198> */
  L_017f: a2 = LD32(a3 + 0x0);  /* 017f */
  if (a2 == 0) goto L_01dd;  /* 0181: beqz a2, 1dd <mesh_xon_flush_packets+0x185> */
  L_0184: a4 = LD32(a2 + 0x150);  /* 0184 */
  if (a4 == 0) goto L_01dd;  /* 0187: beqz a4, 1dd <mesh_xon_flush_packets+0x185> */
  L_018a: a10 = LD32(a2 + 0x158);  /* 018a */
  /* 018d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0190 */
  a10 = a7;  /* 0192 */
  a6 = LD32(a1 + 0x10);  /* 0194 */
  a6 = LD16U(a6 + 0x4);  /* 0196 */
  a2 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0199: -> "mesh" */
  a14 = a2;  /* 019c */
  a11 = a2;  /* 019e */
  a5 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 01a0: -> "mesh_schedule.c" */
  a15 = a5;  /* 01a3 */
  ST32(a1 + 0x4, a6);  /* 01a5 */
  a6 = 0x00000a26u;  /* 01a7: l32r = 2598 */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 01aa: -> "stop" */
  ST32(a1 + 0x0, a6);  /* 01ad */
  __asm__ volatile("" ::: "memory");  /* 01af: memw */
  /* 01b2: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  a7 = LD32(a1 + 0x10);  /* 01b5 */
  if (a7 != 0) goto L_01dd;  /* 01b7: bnez.n a7, 1dd <mesh_xon_flush_packets+0x185> */
  L_01b9: a3 = LD32(a3 + 0x0);  /* 01b9 */
  if (a3 == 0) goto L_01dd;  /* 01bb: beqz.n a3, 1dd <mesh_xon_flush_packets+0x185> */
  L_01bd: a7 = LD32(a3 + 0x150);  /* 01bd */
  if (a7 == 0) goto L_01dd;  /* 01c0: beqz.n a7, 1dd <mesh_xon_flush_packets+0x185> */
  L_01c2: a10 = LD32(a3 + 0x158);  /* 01c2 */
  /* 01c5: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01c8 */
  a15 = a5;  /* 01ca */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 01cc: -> "no window" */
  a14 = a2;  /* 01cf */
  a11 = a2;  /* 01d1 */
  a10 = 1;  /* 01d3 */
  ST32(a1 + 0x0, a6);  /* 01d5 */
  __asm__ volatile("" ::: "memory");  /* 01d7: memw */
  /* 01da: INDIRECT callx a7 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_01dd: a13 = 0x513;  /* 01dd */
  a13 = a13 + a13;  /* 01e0 */
  a11 = 8;  /* 01e2 */
  a12 = (u32)(RODATA__rodata___func___5 + 0x0);  /* 01e5: l32r -> .rodata.__func__$5 */
  a10 = LD32(a1 + 0x10);  /* 01e8 */
  a8 = (u32)&esp_mesh_discard_context;  /* 01ea: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 01ed: callx a8 via reloc-expand */
  L_01f0: a2 = 0x403;  /* 01f0 */
  a2 = a2 << 14;  /* 01f3 */
  a10 = LD32(a1 + 0x10);  /* 01f6 */
  a3 = LD32(a10 + 0x0);  /* 01f8 */
  a5 = a3 + (18);  /* 01fa */
  a8 = LD32(a5 + 0x0);  /* 01fd */
  a8 = a8 & a2;  /* 01ff */
  a2 = 1;  /* 0202 */
  a2 = a2 << 24;  /* 0204 */
  if (a8 != a2) goto L_0225;  /* 0207: bne a8, a2, 225 <mesh_xon_flush_packets+0x1cd> */
  L_020a: a3 = a3 + (14);  /* 020a */
  a12 = LD32(a3 + 0x18);  /* 020c */
  a2 = 0xf0000001u;  /* 020e: l32r = -268435455 */
  a2 = a12 + a2;  /* 0211 */
  if (a2 == 0) goto L_0225;  /* 0213: beqz.n a2, 225 <mesh_xon_flush_packets+0x1cd> */
  L_0215: if (a12 == 0) goto L_0225;  /* 0215: beqz.n a12, 225 <mesh_xon_flush_packets+0x1cd> */
  L_0217: a14 = 0x00000a2bu;  /* 0217: l32r = 2603 */
  a11 = 0;  /* 021a */
  a13 = (u32)(RODATA__rodata___func___5 + 0x0);  /* 021c: l32r -> .rodata.__func__$5 */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 021f: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0222: callx a8 via reloc-expand */
  L_0225: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0225: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0228: memw */
  a2 = LD8U(a2 + 0x0);  /* 022b */
  a2 = (a2 >> 8) & 0x1;  /* 022e: extui width 1 */
  a10 = LD32(a1 + 0x10);  /* 0231 */
  if (a2 == 0) goto L_0255;  /* 0233: beqz.n a2, 255 <mesh_xon_flush_packets+0x1fd> */
  L_0235: a13 = 163;  /* 0235 */
  a13 = a13 << 4;  /* 0238 */
  a2 = LD32(a5 + 0x0);  /* 023b */
  if (((a2 >> 26) & 1) != 0) goto L_0258;  /* 023d: bbsi a2, 26, 258 <mesh_xon_flush_packets+0x200> */
  L_0240: a8 = (u32)&mesh_xon_deliver_packet;  /* 0240: l32r -> func addr */
  a2 = mesh_xon_deliver_packet(a2, a3, a4, a5, a6, a7);  /* 0243: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0263;  /* 0246: beqz.n a10, 263 <mesh_xon_flush_packets+0x20b> */
  L_0248: a13 = 0x00000a35u;  /* 0248: l32r = 2613 */
  a11 = 6;  /* 024b */
  a12 = (u32)(RODATA__rodata___func___5 + 0x0);  /* 024d: l32r -> .rodata.__func__$5 */
  a10 = LD32(a1 + 0x10);  /* 0250 */
  goto L_025d;  /* 0252: j */
  L_0255: a13 = 0x00000a39u;  /* 0255: l32r = 2617 */
  L_0258: a11 = 6;  /* 0258 */
  a12 = (u32)(RODATA__rodata___func___5 + 0x0);  /* 025a: l32r -> .rodata.__func__$5 */
  L_025d: a8 = (u32)&esp_mesh_discard_context;  /* 025d: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 0260: callx a8 via reloc-expand */
  L_0263: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0263: l32r -> global */
  a4 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0266: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a2 = LD32(a3 + 0x0);  /* 0269 */
  a10 = LD32(a4 + 0x0);  /* 026b */
  a2 = LD32(a2 + 0x78);  /* 026e */
  /* 0271: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a2 = a10;  /* 0274 */
  if (a10 != 0) goto L_0065;  /* 0276: bnez a10, 65 <mesh_xon_flush_packets+0xd> */
  L_0279: return a2;  /* 0279: retw.n */
}


/* mesh_xon_process_disconnected @ mesh_schedule.o 00000078 size 641B bind GLOBAL
 * Calls: esp_mesh_match_self, memcmp, esp_mesh_discard_context, mesh_xon_flush_packets, mesh_xon_deliver_packet, esp_mesh_tx_tid_flush | indirect[11]: mem[a3+0x158]; mem[a3+0x150]; mem[a6+0x158]; mem[a6+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .bss.mesh_tx_task, .bss.MESH_ZERO_ADDR, g_mesh_is_root, .rodata.mesh_xon_process_disconnected.str1.1, .rodata.__func__$4, g_is_wifi_connected, g_mesh_ext_cfg, g_mesh_stop_reconnection
 * Fidelity: medium - 11 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=18); reloc-direct=6, funcdb-attributed=0, unknown-indirect=11 */
u32 mesh_xon_process_disconnected(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a43, a44, a45, a46, a63, a8, a9;
  float F2;
  /* 0078: entry a1, 80 (frame 80 bytes) */
  a6 = a2;  /* 007b */
  if (a2 != 0) goto L_00ac;  /* 007d: bnez.n a2, ac <mesh_xon_process_disconnected+0x34> */
  L_007f: a2 = (u32)&g_log_level + 0x0;  /* 007f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0082 */
  a2 = 0x00004008u;  /* 0084: l32r = 16392 */
  if (a3 >= 3u) goto L_008d;  /* 0087: bgeui a3, 3, 8d <mesh_xon_process_disconnected+0x15> */
  L_008a: goto L_02f4;  /* 008a: j */
  L_008d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 008d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0090 */
  if (a3 == 0) goto L_02f4;  /* 0092: beqz a3, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_0095: a4 = LD32(a3 + 0x150);  /* 0095 */
  if (a4 == 0) goto L_02f4;  /* 0098: beqz a4, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_009b: a10 = LD32(a3 + 0x158);  /* 009b */
  /* 009e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00a1: -> "mesh" */
  a3 = 0x00000a43u;  /* 00a4: l32r = 2627 */
  goto L_00d7;  /* 00a7: j */
  L_00ac: if (a3 != 0) goto L_00f2;  /* 00ac: bnez a3, f2 <mesh_xon_process_disconnected+0x7a> */
  L_00af: a2 = (u32)&g_log_level + 0x0;  /* 00af: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00b2 */
  a2 = 0x00004008u;  /* 00b4: l32r = 16392 */
  if (a3 >= 3u) goto L_00bd;  /* 00b7: bgeui a3, 3, bd <mesh_xon_process_disconnected+0x45> */
  L_00ba: goto L_02f4;  /* 00ba: j */
  L_00bd: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00bd: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00c0 */
  if (a3 == 0) goto L_02f4;  /* 00c2: beqz a3, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_00c5: a4 = LD32(a3 + 0x150);  /* 00c5 */
  if (a4 == 0) goto L_02f4;  /* 00c8: beqz a4, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_00cb: a10 = LD32(a3 + 0x158);  /* 00cb */
  /* 00ce: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00d1: -> "mesh" */
  a3 = 0x00000a44u;  /* 00d4: l32r = 2628 */
  L_00d7: a13 = a10;  /* 00d7 */
  a14 = a11;  /* 00d9 */
  a10 = 3;  /* 00db */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00dd: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00e0: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 00e3 */
  __asm__ volatile("" ::: "memory");  /* 00e6: memw */
  /* 00e9: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_02f4;  /* 00ec: j */
  L_00f2: a5 = LD32(a3 + 0x0);  /* 00f2 */
  if (a5 != 0) goto L_0121;  /* 00f4: bnez.n a5, 121 <mesh_xon_process_disconnected+0xa9> */
  L_00f6: a2 = (u32)&g_log_level + 0x0;  /* 00f6: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00f9 */
  a2 = 0x00004008u;  /* 00fb: l32r = 16392 */
  if (a3 >= 3u) goto L_0104;  /* 00fe: bgeui a3, 3, 104 <mesh_xon_process_disconnected+0x8c> */
  L_0101: goto L_02f4;  /* 0101: j */
  L_0104: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0104: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0107 */
  if (a3 == 0) goto L_02f4;  /* 0109: beqz a3, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_010c: a4 = LD32(a3 + 0x150);  /* 010c */
  if (a4 == 0) goto L_02f4;  /* 010f: beqz a4, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_0112: a10 = LD32(a3 + 0x158);  /* 0112 */
  /* 0115: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0118: -> "mesh" */
  a3 = 0x00000a45u;  /* 011b: l32r = 2629 */
  goto L_00d7;  /* 011e: j */
  L_0121: if (a4 != 0) goto L_014e;  /* 0121: bnez.n a4, 14e <mesh_xon_process_disconnected+0xd6> */
  L_0123: a2 = (u32)&g_log_level + 0x0;  /* 0123: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0126 */
  a2 = 0x00004008u;  /* 0128: l32r = 16392 */
  if (a3 >= 3u) goto L_0131;  /* 012b: bgeui a3, 3, 131 <mesh_xon_process_disconnected+0xb9> */
  L_012e: goto L_02f4;  /* 012e: j */
  L_0131: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0131: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0134 */
  if (a3 == 0) goto L_02f4;  /* 0136: beqz a3, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_0139: a4 = LD32(a3 + 0x150);  /* 0139 */
  if (a4 == 0) goto L_02f4;  /* 013c: beqz a4, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_013f: a10 = LD32(a3 + 0x158);  /* 013f */
  /* 0142: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0145: -> "mesh" */
  a3 = 0x00000a46u;  /* 0148: l32r = 2630 */
  goto L_00d7;  /* 014b: j */
  L_014e: a2 = 0;  /* 014e */
  ST32(a4 + 0x0, a2);  /* 0150 */
  __asm__ volatile("" ::: "memory");  /* 0152: memw */
  goto L_028f;  /* 0155: j */
  L_0158: a9 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0158: l32r -> .bss.mesh_tx_task (same-object static) */
  a8 = LD8U(a9 + 0x24);  /* 015b */
  if (a8 != 0) goto L_016d;  /* 015e: bnez.n a8, 16d <mesh_xon_process_disconnected+0xf5> */
  L_0160: a5 = (u32)&g_log_level + 0x0;  /* 0160: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 0163 */
  if (a5 >= 3u) goto L_01d8;  /* 0165: bgeui a5, 3, 1d8 <mesh_xon_process_disconnected+0x160> */
  L_0168: a5 = 6;  /* 0168 */
  goto L_01fc;  /* 016a: j */
  L_016d: a8 = LD32(a3 + 0x28);  /* 016d */
  if (((a8 >> 0) & 1) != 0) goto L_0175;  /* 016f: bbsi a8, 0, 175 <mesh_xon_process_disconnected+0xfd> */
  L_0172: goto L_0219;  /* 0172: j */
  L_0175: a8 = a5 + (18);  /* 0175 */
  a9 = LD32(a8 + 0x0);  /* 0178 */
  a8 = 0x403;  /* 017a */
  a8 = a8 << 14;  /* 017d */
  a9 = a9 & a8;  /* 0180 */
  a8 = 1;  /* 0183 */
  a8 = a8 << 24;  /* 0186 */
  if (a9 == a8) goto L_018f;  /* 0189: beq a9, a8, 18f <mesh_xon_process_disconnected+0x117> */
  L_018c: goto L_0219;  /* 018c: j */
  L_018f: a7 = a5 + (22);  /* 018f */
  a10 = a7;  /* 0192 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0194: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0197: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0219;  /* 019a: bnez a10, 219 <mesh_xon_process_disconnected+0x1a1> */
  L_019d: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 019d: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 01a0 */
  a10 = a7;  /* 01a2 */
  a8 = (u32)&memcmp + 0x0;  /* 01a4: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 01a7: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a3 + 0x28);  /* 01aa */
  if (a10 != 0) goto L_01c0;  /* 01ac: bnez.n a10, 1c0 <mesh_xon_process_disconnected+0x148> */
  L_01ae: a8 = (u32)&g_mesh_is_root + 0x0;  /* 01ae: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 01b1: memw */
  a8 = LD8U(a8 + 0x0);  /* 01b4 */
  a8 = (a8 >> 8) & 0x1;  /* 01b7: extui width 1 */
  if (a8 == 0) goto L_01c0;  /* 01ba: beqz a8, 1c0 <mesh_xon_process_disconnected+0x148> */
  L_01bd: if (((a9 >> 2) & 1) == 0) goto L_0219;  /* 01bd: bbci a9, 2, 219 <mesh_xon_process_disconnected+0x1a1> */
  L_01c0: if (((a9 >> 3) & 1) == 0) goto L_01c9;  /* 01c0: bbci a9, 3, 1c9 <mesh_xon_process_disconnected+0x151> */
  L_01c3: a8 = LD8U(a5 + 0xe);  /* 01c3 */
  if (((a8 >> 5) & 1) != 0) goto L_0219;  /* 01c6: bbsi a8, 5, 219 <mesh_xon_process_disconnected+0x1a1> */
  L_01c9: a5 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 01c9: l32r -> .bss.mesh_tx_task (same-object static) */
  a6 = LD8U(a5 + 0x24);  /* 01cc */
  a5 = 7;  /* 01cf */
  if (a6 != 0) goto L_01fc;  /* 01d1: bnez.n a6, 1fc <mesh_xon_process_disconnected+0x184> */
  L_01d3: goto L_0160;  /* 01d3: j */
  L_01d8: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 01d8: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 01db */
  a5 = 6;  /* 01dd */
  if (a6 == 0) goto L_01fc;  /* 01df: beqz.n a6, 1fc <mesh_xon_process_disconnected+0x184> */
  L_01e1: a7 = LD32(a6 + 0x150);  /* 01e1 */
  if (a7 == 0) goto L_01fc;  /* 01e4: beqz a7, 1fc <mesh_xon_process_disconnected+0x184> */
  L_01e7: a10 = LD32(a6 + 0x158);  /* 01e7 */
  /* 01ea: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01ed */
  a10 = 3;  /* 01ef */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 01f1: -> "mesh" */
  a14 = a11;  /* 01f4 */
  a12 = (u32)(RODATA__rodata_mesh_xon_process_disconnected_str1_1 + 0x0);  /* 01f6: -> "root" */
  /* 01f9: INDIRECT callx a7 <- mem[a6+0x150]; result unknown */ a2 = 0;
  L_01fc: a13 = 0x297;  /* 01fc */
  a10 = a3;  /* 01ff */
  a12 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 0201: l32r -> .rodata.__func__$4 */
  a13 = a13 << 2;  /* 0204 */
  a11 = a5;  /* 0207 */
  a3 = 1;  /* 0209 */
  a8 = (u32)&esp_mesh_discard_context;  /* 020b: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 020e: callx a8 via reloc-expand */
  ST32(a4 + 0x0, a3);  /* 0211 */
  __asm__ volatile("" ::: "memory");  /* 0213: memw */
  goto L_02f4;  /* 0216: j */
  L_0219: a2 = 14;  /* 0219 */
  ST32(a1 + 0x10, a2);  /* 021b */
  a10 = 10;  /* 021d */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 021f: l32r -> global */
  a7 = LD32(a2 + 0x0);  /* 0222 */
  a8 = LD32(a7 + 0x74);  /* 0225 */
  a7 = LD32(a7 + 0xa0);  /* 0228 */
  ST32(a1 + 0x20, a8);  /* 022b */
  __asm__ volatile("" ::: "memory");  /* 022e: memw */
  /* 0231: INDIRECT callx a7 <- mem[a7+0xa0]; result unknown */ a2 = 0;
  a12 = a10;  /* 0234 */
  a11 = a1 + (16);  /* 0236 */
  a10 = a6;  /* 0239 */
  a8 = LD32(a1 + 0x20);  /* 023b */
  /* 023e: INDIRECT callx a8 <- mem[a1+0x20]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_028f;  /* 0241: bnei a10, 1, 28f <mesh_xon_process_disconnected+0x217> */
  L_0244: a7 = LD32(a1 + 0x10);  /* 0244 */
  if (a7 != 16) goto L_028f;  /* 0246: bnei a7, 16, 28f <mesh_xon_process_disconnected+0x217> */
  L_0249: a2 = LD32(a2 + 0x0);  /* 0249 */
  if (a2 == 0) goto L_0289;  /* 024b: beqz.n a2, 289 <mesh_xon_process_disconnected+0x211> */
  L_024d: a7 = LD32(a2 + 0x150);  /* 024d */
  if (a7 == 0) goto L_0289;  /* 0250: beqz.n a7, 289 <mesh_xon_process_disconnected+0x211> */
  L_0252: a10 = LD32(a2 + 0x158);  /* 0252 */
  /* 0255: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = (u32)&g_mesh_is_root + 0x0;  /* 0258: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 025b: memw */
  a2 = LD8U(a2 + 0x0);  /* 025e */
  a2 = (a2 >> 8) & 0x1;  /* 0261: extui width 1 */
  a8 = (u32)(RODATA__rodata_mesh_xon_process_disconnected_str1_1 + 0x0);  /* 0264: -> "root" */
  if (a2 != 0) goto L_026c;  /* 0267: bnez.n a2, 26c <mesh_xon_process_disconnected+0x1f4> */
  L_0269: a8 = (u32)(RODATA__rodata_mesh_xon_process_disconnected_str1_1 + 0x0);  /* 0269: -> "root" */
  L_026c: a13 = a10;  /* 026c */
  a10 = 2;  /* 026e */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0270: -> "mesh" */
  a14 = a11;  /* 0273 */
  a2 = 0x00000a63u;  /* 0275: l32r = 2659 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0278: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_xon_process_disconnected_str1_1 + 0x0);  /* 027b: -> "root" */
  ST32(a1 + 0x4, a8);  /* 027e */
  ST32(a1 + 0x0, a2);  /* 0280 */
  __asm__ volatile("" ::: "memory");  /* 0283: memw */
  /* 0286: INDIRECT callx a7 <- unknown; result unknown */ a2 = 0;
  L_0289: a8 = (u32)&mesh_xon_flush_packets;  /* 0289: l32r -> func addr */
  a2 = mesh_xon_flush_packets(a2, a3, a4, a5, a6, a7);  /* 028c: callx a8 via reloc-expand */
  L_028f: a8 = (u32)&g_is_wifi_connected + 0x0;  /* 028f: l32r -> global */
  a2 = LD8U(a8 + 0x0);  /* 0292 */
  if (a2 != 0) goto L_02a8;  /* 0295: bnez.n a2, 2a8 <mesh_xon_process_disconnected+0x230> */
  L_0297: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0297: l32r -> global */
  a2 = LD8U(a2 + 0xc4);  /* 029a */
  if (((a2 >> 1) & 1) != 0) goto L_02a8;  /* 029d: bbsi a2, 1, 2a8 <mesh_xon_process_disconnected+0x230> */
  L_02a0: a2 = (u32)&g_mesh_stop_reconnection + 0x0;  /* 02a0: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 02a3 */
  if (a2 == 0) goto L_0158;  /* 02a5: beqz a2, 158 <mesh_xon_process_disconnected+0xe0> */
  L_02a8: a2 = (u32)&g_mesh_is_root + 0x0;  /* 02a8: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 02ab: memw */
  a6 = LD8U(a2 + 0x0);  /* 02ae */
  a2 = 0;  /* 02b1 */
  a6 = (a6 >> 8) & 0x1;  /* 02b3: extui width 1 */
  if (a6 == a2) goto L_02f4;  /* 02b6: beq a6, a2, 2f4 <mesh_xon_process_disconnected+0x27c> */
  L_02b9: a5 = a5 + (18);  /* 02b9 */
  a2 = LD32(a5 + 0x0);  /* 02bc */
  a13 = 0x539;  /* 02be */
  if (((a2 >> 26) & 1) != 0) goto L_02d1;  /* 02c1: bbsi a2, 26, 2d1 <mesh_xon_process_disconnected+0x259> */
  L_02c4: a10 = a3;  /* 02c4 */
  a8 = (u32)&mesh_xon_deliver_packet;  /* 02c6: l32r -> func addr */
  a2 = mesh_xon_deliver_packet(a2, a3, a4, a5, a6, a7);  /* 02c9: callx a8 via reloc-expand */
  if (a10 == 0) goto L_02e0;  /* 02cc: beqz.n a10, 2e0 <mesh_xon_process_disconnected+0x268> */
  L_02ce: a13 = 0x53b;  /* 02ce */
  L_02d1: a12 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 02d1: l32r -> .rodata.__func__$4 */
  a13 = a13 + a13;  /* 02d4 */
  a11 = 6;  /* 02d6 */
  a10 = a3;  /* 02d8 */
  a8 = (u32)&esp_mesh_discard_context;  /* 02da: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 02dd: callx a8 via reloc-expand */
  L_02e0: a2 = 1;  /* 02e0 */
  a8 = (u32)&mesh_xon_flush_packets;  /* 02e2: l32r -> func addr */
  a2 = mesh_xon_flush_packets(a2, a3, a4, a5, a6, a7);  /* 02e5: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_tx_tid_flush;  /* 02e8: l32r -> func addr */
  a2 = esp_mesh_tx_tid_flush(a2, a3, a4, a5, a6, a7);  /* 02eb: callx a8 via reloc-expand */
  ST32(a4 + 0x0, a2);  /* 02ee */
  a2 = 0;  /* 02f1 */
  L_02f4: __asm__ volatile("" ::: "memory");  /* 02f4: memw */
  return a2;  /* 02f7: retw.n */
}


/* mesh_xon_process_expired @ mesh_schedule.o 00000024 size 277B bind GLOBAL
 * Calls: none | indirect[6]: mem[a3+0x158]; mem[a3+0x150]; mem[a8+0x110]; mem[a4+0x110] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, g_mesh_packet_lifetime
 * Fidelity: medium - 6 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=5); reloc-direct=0, funcdb-attributed=0, unknown-indirect=6 */
u32 mesh_xon_process_expired(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a83, a84, a9;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0055;  /* 0027: bnez.n a2, 55 <mesh_xon_process_expired+0x31> */
  L_0029: a2 = (u32)&g_log_level + 0x0;  /* 0029: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002c */
  a2 = 0x00004008u;  /* 002e: l32r = 16392 */
  if (a3 >= 3u) goto L_0037;  /* 0031: bgeui a3, 3, 37 <mesh_xon_process_expired+0x13> */
  L_0034: goto L_0134;  /* 0034: j */
  L_0037: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0037: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 003a */
  if (a3 == 0) goto L_0134;  /* 003d: beqz a3, 134 <mesh_xon_process_expired+0x110> */
  L_0040: a4 = LD32(a3 + 0x150);  /* 0040 */
  if (a4 == 0) goto L_0134;  /* 0043: beqz a4, 134 <mesh_xon_process_expired+0x110> */
  L_0046: a10 = LD32(a3 + 0x158);  /* 0046 */
  /* 0049: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 004c: -> "mesh" */
  a3 = 0x00000a83u;  /* 004f: l32r = 2691 */
  goto L_007f;  /* 0052: j */
  L_0055: if (a3 != 0) goto L_0098;  /* 0055: bnez.n a3, 98 <mesh_xon_process_expired+0x74> */
  L_0057: a2 = (u32)&g_log_level + 0x0;  /* 0057: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005a */
  a2 = 0x00004008u;  /* 005c: l32r = 16392 */
  if (a3 >= 3u) goto L_0065;  /* 005f: bgeui a3, 3, 65 <mesh_xon_process_expired+0x41> */
  L_0062: goto L_0134;  /* 0062: j */
  L_0065: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0065: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0068 */
  if (a3 == 0) goto L_0134;  /* 006a: beqz a3, 134 <mesh_xon_process_expired+0x110> */
  L_006d: a4 = LD32(a3 + 0x150);  /* 006d */
  if (a4 == 0) goto L_0134;  /* 0070: beqz a4, 134 <mesh_xon_process_expired+0x110> */
  L_0073: a10 = LD32(a3 + 0x158);  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0079: -> "mesh" */
  a3 = 0x00000a84u;  /* 007c: l32r = 2692 */
  L_007f: a13 = a10;  /* 007f */
  a14 = a11;  /* 0081 */
  a10 = 3;  /* 0083 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0085: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0088: -> "mesh_schedule.c" */
  ST32(a1 + 0x0, a3);  /* 008b */
  __asm__ volatile("" ::: "memory");  /* 008e: memw */
  /* 0091: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0134;  /* 0094: j */
  L_0098: a4 = 0;  /* 0098 */
  ST32(a3 + 0x0, a4);  /* 009a */
  a4 = LD32(a2 + 0x28);  /* 009c */
  if (((a4 >> 0) & 1) != 0) goto L_00a9;  /* 009e: bbsi a4, 0, a9 <mesh_xon_process_expired+0x85> */
  L_00a1: __asm__ volatile("" ::: "memory");  /* 00a1: memw */
  goto L_0132;  /* 00a4: j */
  L_00a9: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00a9: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 00ac */
  a10 = LD32(a8 + 0x110);  /* 00af */
  /* 00b2: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = LD32(a2 + 0x1c);  /* 00b5 */
  if ((i32)a11 < (i32)a8) goto L_00e8;  /* 00b7: blt a11, a8, e8 <mesh_xon_process_expired+0xc4> */
  L_00ba: if (a8 != a11) goto L_00c2;  /* 00ba: bne a8, a11, c2 <mesh_xon_process_expired+0x9e> */
  L_00bd: a8 = LD32(a2 + 0x18);  /* 00bd */
  if (a10 < a8) goto L_00e8;  /* 00bf: bltu a10, a8, e8 <mesh_xon_process_expired+0xc4> */
  L_00c2: a4 = LD32(a4 + 0x0);  /* 00c2 */
  a10 = LD32(a4 + 0x110);  /* 00c4 */
  /* 00c7: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a8 = LD32(a2 + 0x18);  /* 00ca */
  a8 = a10 - a8;  /* 00cc: sub */
  a4 = LD32(a2 + 0x1c);  /* 00cf */
  a2 = 1;  /* 00d1 */
  if (a10 < a8) goto L_00d8;  /* 00d3: bltu a10, a8, d8 <mesh_xon_process_expired+0xb4> */
  L_00d6: a2 = 0;  /* 00d6 */
  L_00d8: a11 = a11 - a4;  /* 00d8: sub */
  a11 = a11 - a2;  /* 00db: sub */
  a2 = a11 << 22;  /* 00de */
  a8 = a8 >> 10;  /* 00e1 */
  goto L_0118;  /* 00e4: j */
  L_00e8: a4 = LD32(a4 + 0x0);  /* 00e8 */
  a10 = LD32(a4 + 0x110);  /* 00ea */
  a4 = -1;  /* 00ed */
  /* 00ef: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  a8 = LD32(a2 + 0x18);  /* 00f2 */
  a8 = a8 ^ a4;  /* 00f4 */
  a10 = a8 + a10;  /* 00f7 */
  a4 = 1;  /* 00f9 */
  a2 = LD32(a2 + 0x1c);  /* 00fb */
  if (a10 < a8) goto L_0102;  /* 00fd: bltu a10, a8, 102 <mesh_xon_process_expired+0xde> */
  L_0100: a4 = 0;  /* 0100 */
  L_0102: a11 = a2 + a11;  /* 0102 */
  a9 = a10 + (1);  /* 0104 */
  a11 = a4 + a11;  /* 0106 */
  a8 = 1;  /* 0108 */
  if (a9 < a10) goto L_0110;  /* 010b: bltu a9, a10, 110 <mesh_xon_process_expired+0xec> */
  L_010e: a8 = 0;  /* 010e */
  L_0110: a11 = a8 + a11;  /* 0110 */
  a2 = a11 << 22;  /* 0112 */
  a8 = a9 >> 10;  /* 0115 */
  L_0118: a8 = a2 | a8;  /* 0118 */
  a2 = (u32)&g_mesh_packet_lifetime + 0x0;  /* 011b: l32r -> global */
  a11 = (i32)a11 >> 10;  /* 011e */
  a4 = 0;  /* 0121 */
  a2 = LD32(a2 + 0x0);  /* 0123 */
  if ((i32)a4 < (i32)a11) goto L_012e;  /* 0125: blt a4, a11, 12e <mesh_xon_process_expired+0x10a> */
  L_0128: if (a11 != a4) goto L_0132;  /* 0128: bne a11, a4, 132 <mesh_xon_process_expired+0x10e> */
  L_012b: if (a2 >= a8) goto L_0132;  /* 012b: bgeu a2, a8, 132 <mesh_xon_process_expired+0x10e> */
  L_012e: a2 = 1;  /* 012e */
  ST32(a3 + 0x0, a2);  /* 0130 */
  L_0132: a2 = 0;  /* 0132 */
  L_0134: __asm__ volatile("" ::: "memory");  /* 0134: memw */
  return a2;  /* 0137: retw.n */
}


/* mesh_xon_process_no_wnd @ mesh_schedule.o 00000008 size 192B bind GLOBAL
 * Calls: none | indirect[6]: mem[a8+0xa0]; mem[a8+0x110]; mem[a2+0xa0]; mem[a2+0x9c] | Data refs: g_mesh_packet_lifetime, g_osi_funcs_p
 * Fidelity: medium - 6 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=6 */
u32 mesh_xon_process_no_wnd(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&g_mesh_packet_lifetime + 0x0;  /* 000b: l32r -> global */
  a6 = (u32)&g_osi_funcs_p + 0x0;  /* 000e: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0011 */
  a8 = LD32(a6 + 0x0);  /* 0013 */
  if (a3 != -1) goto L_003d;  /* 0015: bnei a3, -1, 3d <mesh_xon_process_no_wnd+0x35> */
  L_0018: a10 = 50;  /* 0018 */
  a3 = LD32(a8 + 0x9c);  /* 001a */
  a4 = LD32(a8 + 0xa0);  /* 001d */
  if ((i32)a2 < 4) goto L_0035;  /* 0020: blti a2, 4, 35 <mesh_xon_process_no_wnd+0x2d> */
  L_0023: a10 = 100;  /* 0023 */
  if ((i32)a2 < 7) goto L_0035;  /* 0026: blti a2, 7, 35 <mesh_xon_process_no_wnd+0x2d> */
  L_0029: a5 = 9;  /* 0029 */
  a10 = 200;  /* 002c */
  if ((i32)a5 >= (i32)a2) goto L_0035;  /* 002f: bge a5, a2, 35 <mesh_xon_process_no_wnd+0x2d> */
  L_0032: a10 = 0x3e8;  /* 0032 */
  L_0035: /* 0035: INDIRECT callx a4 <- mem[a8+0xa0]; result unknown */ a2 = 0;
  goto L_00c1;  /* 0038: j */
  L_003d: a10 = LD32(a8 + 0x110);  /* 003d */
  /* 0040: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  if ((i32)a11 < (i32)a5) goto L_006a;  /* 0043: blt a11, a5, 6a <mesh_xon_process_no_wnd+0x62> */
  L_0046: if (a5 != a11) goto L_004c;  /* 0046: bne a5, a11, 4c <mesh_xon_process_no_wnd+0x44> */
  L_0049: if (a10 < a4) goto L_006a;  /* 0049: bltu a10, a4, 6a <mesh_xon_process_no_wnd+0x62> */
  L_004c: a8 = LD32(a6 + 0x0);  /* 004c */
  a10 = LD32(a8 + 0x110);  /* 004e */
  /* 0051: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a4 = a10 - a4;  /* 0054: sub */
  a9 = 1;  /* 0057 */
  if (a10 < a4) goto L_0060;  /* 005a: bltu a10, a4, 60 <mesh_xon_process_no_wnd+0x58> */
  L_005d: a9 = 0;  /* 005d */
  L_0060: a8 = a11 - a5;  /* 0060: sub */
  a8 = a8 - a9;  /* 0063: sub */
  goto L_008f;  /* 0066: j */
  L_006a: a8 = LD32(a6 + 0x0);  /* 006a */
  a10 = LD32(a8 + 0x110);  /* 006c */
  /* 006f: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a8 = -1;  /* 0072 */
  a4 = a8 ^ a4;  /* 0074 */
  a10 = a4 + a10;  /* 0077 */
  a8 = 1;  /* 0079 */
  if (a10 < a4) goto L_0080;  /* 007b: bltu a10, a4, 80 <mesh_xon_process_no_wnd+0x78> */
  L_007e: a8 = 0;  /* 007e */
  L_0080: a5 = a5 + a11;  /* 0080 */
  a4 = a10 + (1);  /* 0082 */
  a5 = a8 + a5;  /* 0084 */
  a8 = 1;  /* 0086 */
  if (a4 < a10) goto L_008d;  /* 0088: bltu a4, a10, 8d <mesh_xon_process_no_wnd+0x85> */
  L_008b: a8 = 0;  /* 008b */
  L_008d: a8 = a8 + a5;  /* 008d */
  L_008f: a8 = a8 << 22;  /* 008f */
  a4 = a4 >> 10;  /* 0092 */
  a8 = a8 | a4;  /* 0095 */
  a3 = a3 - a8;  /* 0098: sub */
  a10 = 50;  /* 009b */
  if ((i32)a2 < 4) goto L_00b1;  /* 009d: blti a2, 4, b1 <mesh_xon_process_no_wnd+0xa9> */
  L_00a0: a10 = 100;  /* 00a0 */
  if ((i32)a2 < 7) goto L_00b1;  /* 00a3: blti a2, 7, b1 <mesh_xon_process_no_wnd+0xa9> */
  L_00a6: a4 = 9;  /* 00a6 */
  a10 = 200;  /* 00a8 */
  if ((i32)a4 >= (i32)a2) goto L_00b1;  /* 00ab: bge a4, a2, b1 <mesh_xon_process_no_wnd+0xa9> */
  L_00ae: a10 = 0x3e8;  /* 00ae */
  L_00b1: a2 = 1;  /* 00b1 */
  if ((i32)a10 >= (i32)a3) goto L_00c6;  /* 00b3: bge a10, a3, c6 <mesh_xon_process_no_wnd+0xbe> */
  L_00b6: a2 = LD32(a6 + 0x0);  /* 00b6 */
  a3 = LD32(a2 + 0x9c);  /* 00b8 */
  a2 = LD32(a2 + 0xa0);  /* 00bb */
  /* 00be: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  L_00c1: /* 00c1: INDIRECT callx a3 <- mem[a2+0x9c]; result unknown */ a2 = 0;
  a2 = 0;  /* 00c4 */
  L_00c6: return a2;  /* 00c6: retw.n */
}


/* mesh_xon_task_main @ mesh_schedule.o 00000158 size 2366B bind GLOBAL
 * Calls: mesh_tx_tid_stop, xon_task_main, esp_mesh_discard_context, esp_mesh_txupQ_pending, mesh_xon_deliver_packet, mesh_xon_process_expired, mesh_xon_process_disconnected, memcmp, esp_mesh_get_parent_bssid, esp_mesh_send_xon, mesh_xon_process_no_wnd, mesh_mutex_lock, esp_mesh_best_effort_tx, mesh_mutex_unlock, memcpy, wifi_get_macaddr, esp_wifi_mesh_tx | indirect[44]: mem[a2+0x74]; mem[a6+0x78]; mem[a6+0x158]; mem[a6+0x150] | Data refs: .bss.mesh_tx_task, .bss.mesh_tx_mbox, g_mesh_init_ps_type, g_osi_funcs_p, g_log_level, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_xon_task_main.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.esp_mesh_send_block_event.str1.1, g_mesh_stop_event_group, .rodata.mesh_tx_task_main.str1.1, g_mesh_topology +11 more
 * Fidelity: low - large state machine / jump-table switch; goto skeleton preserves flow, some blocks summarized
 * Edges: funcdb-v3 (calls=17, refs=40); reloc-direct=17, funcdb-attributed=0, unknown-indirect=44 */
u32 mesh_xon_task_main(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a02, a10, a11, a12, a13, a14, a15, a56, a64, a8, a88, a9;
  float F0, F0000001, F4, F8;
  /* 0158: entry a1, 160 (frame 160 bytes) */
  a2 = 14;  /* 015b */
  a3 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 015d: l32r -> .bss.mesh_tx_task (same-object static) */
  a5 = 0;  /* 0160 */
  ST32(a1 + 0x40, a2);  /* 0162 */
  a2 = 9;  /* 0165 */
  ST32(a1 + 0x38, a2);  /* 0167 */
  a2 = 0;  /* 0169 */
  ST8(a3 + 0x2c, a2);  /* 016b */
  __asm__ volatile("" ::: "memory");  /* 016e: memw */
  a2 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0171: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a4 = LD32(a3 + 0x18);  /* 0174 */
  a2 = LD32(a2 + 0x84);  /* 0176 */
  ST32(a1 + 0x6c, a4);  /* 0179 */
  a4 = 1;  /* 017c */
  ST32(a1 + 0x64, a2);  /* 017e */
  ST32(a1 + 0x50, a5);  /* 0181 */
  ST32(a1 + 0x5c, a5);  /* 0184 */
  __asm__ volatile("" ::: "memory");  /* 0187: memw */
  goto L_09ea;  /* 018a: j */
  L_018d: a6 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 018d: l32r -> .bss.mesh_tx_task (same-object static) */
  a2 = 9;  /* 0190 */
  ST32(a1 + 0x38, a2);  /* 0192 */
  a2 = LD8U(a6 + 0x2c);  /* 0194 */
  a3 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0197: l32r -> global */
  if (a2 == 0) goto L_0225;  /* 019a: beqz a2, 225 <mesh_xon_task_main+0xcd> */
  L_019d: a2 = 14;  /* 019d */
  a12 = -1;  /* 01a0 */
  a11 = a1 + (64);  /* 01a3 */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 01a6: l32r -> global */
  a6 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 01a9: l32r -> .bss.mesh_tx_mbox (same-object static) */
  ST32(a1 + 0x40, a2);  /* 01ac */
  a2 = LD32(a5 + 0x0);  /* 01af */
  a10 = LD32(a6 + 0x9c);  /* 01b2 */
  a2 = LD32(a2 + 0x74);  /* 01b5 */
  __asm__ volatile("" ::: "memory");  /* 01b8: memw */
  /* 01bb: INDIRECT callx a2 <- mem[a2+0x74]; result unknown */ a2 = 0;
  a2 = a10;  /* 01be */
  if (a10 != 1) goto L_0225;  /* 01c0: bnei a10, 1, 225 <mesh_xon_task_main+0xcd> */
  L_01c3: a8 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 01c3: l32r -> .bss.mesh_tx_task (same-object static) */
  a6 = 0;  /* 01c6 */
  a7 = LD32(a1 + 0x40);  /* 01c8 */
  ST8(a8 + 0x2c, a6);  /* 01cb */
  __asm__ volatile("" ::: "memory");  /* 01ce: memw */
  a6 = 15;  /* 01d1 */
  if (a7 != a6) goto L_0225;  /* 01d4: bne a7, a6, 225 <mesh_xon_task_main+0xcd> */
  L_01d7: a6 = LD32(a5 + 0x0);  /* 01d7 */
  a10 = LD32(a1 + 0x64);  /* 01da */
  a6 = LD32(a6 + 0x78);  /* 01dd */
  __asm__ volatile("" ::: "memory");  /* 01e0: memw */
  /* 01e3: INDIRECT callx a6 <- mem[a6+0x78]; result unknown */ a2 = 0;
  a7 = a10;  /* 01e6 */
  a6 = (u32)&g_log_level + 0x0;  /* 01e8: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 01eb */
  if (a6 < 3u) goto L_021d;  /* 01ed: bltui a6, 3, 21d <mesh_xon_task_main+0xc5> */
  L_01f0: a6 = LD32(a5 + 0x0);  /* 01f0 */
  if (a6 == 0) goto L_021d;  /* 01f2: beqz.n a6, 21d <mesh_xon_task_main+0xc5> */
  L_01f4: a5 = LD32(a6 + 0x150);  /* 01f4 */
  if (a5 == 0) goto L_021d;  /* 01f7: beqz.n a5, 21d <mesh_xon_task_main+0xc5> */
  L_01f9: a10 = LD32(a6 + 0x158);  /* 01f9 */
  a6 = 0;  /* 01fc */
  /* 01fe: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a15 = a6;  /* 0201 */
  a13 = a10;  /* 0203 */
  a8 = LD32(a3 + 0x0);  /* 0205 */
  a10 = 3;  /* 0207 */
  if (a8 != 0) a15 = a2;  /* 0209 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 020c: -> "mesh" */
  a14 = a11;  /* 020f */
  a12 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 0211: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  ST32(a1 + 0x0, a7);  /* 0214 */
  __asm__ volatile("" ::: "memory");  /* 0217: memw */
  /* 021a: INDIRECT callx a5 <- mem[a6+0x150]; result unknown */ a2 = 0;
  L_021d: a10 = 1;  /* 021d */
  a8 = (u32)&mesh_tx_tid_stop;  /* 021f: l32r -> func addr */
  a2 = mesh_tx_tid_stop(a2, a3, a4, a5, a6, a7);  /* 0222: callx a8 via reloc-expand */
  L_0225: a2 = 14;  /* 0225 */
  ST32(a1 + 0x40, a2);  /* 0227 */
  a2 = LD32(a3 + 0x0);  /* 022a */
  if (a2 == 0) goto L_0281;  /* 022d: beqz a2, 281 <mesh_xon_task_main+0x129> */
  L_0230: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0230: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0233 */
  a10 = LD32(a1 + 0x64);  /* 0236 */
  a3 = LD32(a3 + 0x78);  /* 0239 */
  __asm__ volatile("" ::: "memory");  /* 023c: memw */
  /* 023f: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  if (a10 == 0) goto L_0281;  /* 0242: beqz.n a10, 281 <mesh_xon_task_main+0x129> */
  L_0244: a12 = -1;  /* 0244 */
  a3 = LD32(a2 + 0x0);  /* 0246 */
  a11 = a1 + (64);  /* 0248 */
  a3 = LD32(a3 + 0x74);  /* 024b */
  a10 = LD32(a1 + 0x64);  /* 024e */
  /* 0251: INDIRECT callx a3 <- mem[a3+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_0281;  /* 0254: beqi a10, 1, 281 <mesh_xon_task_main+0x129> */
  L_0257: a2 = LD32(a2 + 0x0);  /* 0257 */
  if (a2 == 0) goto L_0281;  /* 0259: beqz.n a2, 281 <mesh_xon_task_main+0x129> */
  L_025b: a3 = LD32(a2 + 0x150);  /* 025b */
  if (a3 == 0) goto L_0281;  /* 025e: beqz.n a3, 281 <mesh_xon_task_main+0x129> */
  L_0260: a10 = LD32(a2 + 0x158);  /* 0260 */
  /* 0263: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0266 */
  a10 = 1;  /* 0268 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 026a: -> "mesh" */
  a14 = a11;  /* 026d */
  a2 = 0x00000b57u;  /* 026f: l32r = 2903 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0272: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 0275: -> "no window" */
  ST32(a1 + 0x0, a2);  /* 0278 */
  __asm__ volatile("" ::: "memory");  /* 027b: memw */
  /* 027e: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0281: a12 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0281: l32r -> .bss.mesh_tx_task (same-object static) */
  a11 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0284: l32r -> .bss.mesh_tx_task (same-object static) */
  a10 = LD32(a1 + 0x40);  /* 0287 */
  a8 = (u32)&xon_task_main;  /* 028a: l32r -> func addr */
  a2 = xon_task_main(a2, a3, a4, a5, a6, a7);  /* 028d: callx a8 via reloc-expand */
  a2 = a10;  /* 0290 */
  a9 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0292: l32r -> .bss.mesh_tx_task (same-object static) */
  a3 = LD8U(a9 + 0x24);  /* 0295 */
  if (a3 != 0) goto L_02bc;  /* 0298: bnez a3, 2bc <mesh_xon_task_main+0x164> */
  L_029b: a10 = 1;  /* 029b */
  a8 = (u32)&mesh_tx_tid_stop;  /* 029e: l32r -> func addr */
  a2 = mesh_tx_tid_stop(a2, a3, a4, a5, a6, a7);  /* 02a1: callx a8 via reloc-expand */
  a11 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 02a4: l32r -> .bss.mesh_tx_task (same-object static) */
  a2 = 0;  /* 02a7 */
  ST32(a11 + 0x28, a2);  /* 02a9 */
  a2 = (u32)&g_mesh_stop_event_group + 0x0;  /* 02ab: l32r -> global */
  a10 = LD32(a2 + 0x0);  /* 02ae */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 02b0: l32r -> global */
  if (a10 != 0) goto L_09f8;  /* 02b3: bnez a10, 9f8 <mesh_xon_task_main+0x8a0> */
  L_02b6: __asm__ volatile("" ::: "memory");  /* 02b6: memw */
  goto L_0a02;  /* 02b9: j */
  L_02bc: a14 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 02bc: l32r -> .bss.mesh_tx_task (same-object static) */
  a3 = LD8U(a14 + 0x2c);  /* 02bf */
  if (a3 != 0) goto L_09ea;  /* 02c2: bnez a3, 9ea <mesh_xon_task_main+0x892> */
  L_02c5: if (a10 == 0) goto L_02cf;  /* 02c5: beqz.n a10, 2cf <mesh_xon_task_main+0x177> */
  L_02c7: a3 = LD32(a10 + 0x0);  /* 02c7 */
  if (a3 != 0) goto L_03b1;  /* 02c9: bnez a3, 3b1 <mesh_xon_task_main+0x259> */
  L_02cc: goto L_0305;  /* 02cc: j */
  L_02cf: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 02cf: l32r -> global */
  a5 = LD32(a3 + 0x0);  /* 02d2 */
  if (a5 == 0) goto L_0a8e;  /* 02d5: beqz a5, a8e <mesh_xon_task_main+0x936> */
  L_02d8: a6 = LD32(a5 + 0x150);  /* 02d8 */
  if (a6 == 0) goto L_0a8e;  /* 02db: beqz a6, a8e <mesh_xon_task_main+0x936> */
  L_02de: a10 = LD32(a5 + 0x158);  /* 02de */
  /* 02e1: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02e4 */
  a10 = 1;  /* 02e6 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 02e8: -> "mesh" */
  a14 = a11;  /* 02eb: mov */
  a5 = 0x00000b6au;  /* 02ee: l32r = 2922 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 02f1: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 02f4: -> "stop" */
  ST32(a1 + 0x0, a5);  /* 02f7 */
  __asm__ volatile("" ::: "memory");  /* 02fa: memw */
  /* 02fd: INDIRECT callx a6 <- mem[a5+0x150]; result unknown */ a2 = 0;
  goto L_0a8e;  /* 0300: j */
  L_0305: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0305: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0308 */
  if (a3 != 0) goto L_0319;  /* 030a: bnez.n a3, 319 <mesh_xon_task_main+0x1c1> */
  L_030c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 030c: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 030f */
  if (a3 != 0) goto L_0384;  /* 0311: bnez a3, 384 <mesh_xon_task_main+0x22c> */
  L_0314: goto L_03f4;  /* 0314: j */
  L_0319: a5 = LD32(a3 + 0x150);  /* 0319 */
  if (a5 == 0) goto L_030c;  /* 031c: beqz a5, 30c <mesh_xon_task_main+0x1b4> */
  L_031f: a10 = LD32(a3 + 0x158);  /* 031f */
  /* 0322: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a6 = LD32(a2 + 0x28);  /* 0325 */
  a3 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 0327: -> "stop" */
  if (((a6 >> 4) & 1) != 0) goto L_0330;  /* 032a: bbsi a6, 4, 330 <mesh_xon_task_main+0x1d8> */
  L_032d: a3 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 032d: -> "no window" */
  L_0330: a13 = a10;  /* 0330 */
  a10 = 1;  /* 0332 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0334: -> "mesh" */
  a14 = a11;  /* 0337 */
  ST32(a1 + 0x8, a3);  /* 0339 */
  a3 = 0x00000b6au;  /* 033b: l32r = 2922 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 033e: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 0341: -> "stop" */
  ST32(a1 + 0x4, a2);  /* 0344 */
  ST32(a1 + 0x0, a3);  /* 0347 */
  __asm__ volatile("" ::: "memory");  /* 034a: memw */
  /* 034d: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_037a;  /* 0350: j */
  L_0355: a5 = LD32(a3 + 0x150);  /* 0355 */
  if (a5 == 0) goto L_037a;  /* 0358: beqz.n a5, 37a <mesh_xon_task_main+0x222> */
  L_035a: a10 = LD32(a3 + 0x158);  /* 035a */
  /* 035d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0360 */
  a10 = 1;  /* 0362 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0364: -> "mesh" */
  a14 = a11;  /* 0367 */
  a3 = 0x00000b6au;  /* 0369: l32r = 2922 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 036c: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 036f: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 0372 */
  __asm__ volatile("" ::: "memory");  /* 0374: memw */
  /* 0377: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_037a: a3 = LD32(a2 + 0x0);  /* 037a */
  if (a3 != 0) goto L_03f4;  /* 037c: bnez a3, 3f4 <mesh_xon_task_main+0x29c> */
  L_037f: goto L_030c;  /* 037f: j */
  L_0384: a5 = LD32(a3 + 0x150);  /* 0384 */
  if (a5 == 0) goto L_03f4;  /* 0387: beqz a5, 3f4 <mesh_xon_task_main+0x29c> */
  L_038a: a10 = LD32(a3 + 0x158);  /* 038a */
  /* 038d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0390 */
  a10 = 1;  /* 0392 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0394: -> "mesh" */
  a14 = a11;  /* 0397: mov */
  a3 = 0x00000b6au;  /* 039a: l32r = 2922 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 039d: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_block_event_str1_1 + 0x0);  /* 03a0: -> "no window" */
  ST32(a1 + 0x0, a3);  /* 03a3 */
  __asm__ volatile("" ::: "memory");  /* 03a6: memw */
  /* 03a9: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03f4;  /* 03ac: j */
  L_03b1: a3 = (u32)&g_mesh_topology + 0x0;  /* 03b1: l32r -> global */
  a6 = 47;  /* 03b4 */
  a7 = LD32(a3 + 0x0);  /* 03b6 */
  a3 = 42;  /* 03b8 */
  if (a7 != 0) a3 = a6;  /* 03ba */
  a5 = LD16U(a10 + 0x4);  /* 03bd */
  if (a5 >= a3) goto L_0408;  /* 03c0: bgeu a5, a3, 408 <mesh_xon_task_main+0x2b0> */
  L_03c3: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 03c3: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 03c6 */
  if (a3 == 0) goto L_03f4;  /* 03c8: beqz.n a3, 3f4 <mesh_xon_task_main+0x29c> */
  L_03ca: a5 = LD32(a3 + 0x150);  /* 03ca */
  if (a5 == 0) goto L_03f4;  /* 03cd: beqz.n a5, 3f4 <mesh_xon_task_main+0x29c> */
  L_03cf: a10 = LD32(a3 + 0x158);  /* 03cf */
  /* 03d2: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 03d5 */
  a10 = 1;  /* 03d7 */
  a3 = LD16U(a2 + 0x4);  /* 03d9 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 03dc: -> "mesh" */
  a14 = a11;  /* 03df */
  ST32(a1 + 0x4, a3);  /* 03e1 */
  a3 = 0x00000b6au;  /* 03e3: l32r = 2922 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 03e6: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_tx_task_main_str1_1 + 0x0);  /* 03e9: -> "stop" */
  ST32(a1 + 0x0, a3);  /* 03ec */
  __asm__ volatile("" ::: "memory");  /* 03ee: memw */
  /* 03f1: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_03f4: a13 = 0x5b5;  /* 03f4 */
  a13 = a13 + a13;  /* 03f7 */
  a11 = 8;  /* 03f9 */
  a12 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 03fc: l32r -> .rodata.__func__$3 */
  a10 = a2;  /* 03ff: mov */
  a8 = (u32)&esp_mesh_discard_context;  /* 0402: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 0405: callx a8 via reloc-expand */
  L_0408: a5 = 0x403;  /* 0408 */
  a5 = a5 << 14;  /* 040b */
  a3 = LD32(a2 + 0x28);  /* 040e */
  a3 = (a3 >> 5) & 0x3ff;  /* 0410: extui width 10 */
  ST32(a1 + 0x40, a3);  /* 0413 */
  a3 = LD32(a2 + 0x0);  /* 0416 */
  a6 = a3 + (18);  /* 0418 */
  a7 = LD32(a6 + 0x0);  /* 041b */
  a7 = a7 & a5;  /* 041d */
  a5 = 1;  /* 0420 */
  a5 = a5 << 24;  /* 0422 */
  if (a7 != a5) goto L_045c;  /* 0425: bne a7, a5, 45c <mesh_xon_task_main+0x304> */
  L_0428: a5 = a3 + (14);  /* 0428 */
  a12 = LD32(a5 + 0x18);  /* 042a */
  a5 = 0xf0000001u;  /* 042c: l32r = -268435455 */
  a5 = a12 + a5;  /* 042f */
  if (a5 == 0) goto L_045c;  /* 0431: beqz.n a5, 45c <mesh_xon_task_main+0x304> */
  L_0433: if (a12 == 0) goto L_045c;  /* 0433: beqz.n a12, 45c <mesh_xon_task_main+0x304> */
  L_0435: a5 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 0435: l32r -> .rodata.__func__$3 */
  a14 = 0x5bd;  /* 0438 */
  a14 = a14 + a14;  /* 043b */
  a13 = a5;  /* 043d */
  a11 = 0;  /* 043f */
  a10 = a2;  /* 0441 */
  __asm__ volatile("" ::: "memory");  /* 0443: memw */
  a8 = (u32)&esp_mesh_txupQ_pending;  /* 0446: l32r -> func addr */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0449: callx a8 via reloc-expand */
  a7 = 0x00004004u;  /* 044c: l32r = 16388 */
  if (a10 != a7) goto L_045c;  /* 044f: bne a10, a7, 45c <mesh_xon_task_main+0x304> */
  L_0452: a12 = a5;  /* 0452 */
  a11 = a10;  /* 0454 */
  a13 = 0x00000b7du;  /* 0456: l32r = 2941 */
  goto L_047a;  /* 0459: j */
  L_045c: a5 = (u32)&g_mesh_is_root + 0x0;  /* 045c: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 045f: memw */
  a5 = LD8U(a5 + 0x0);  /* 0462 */
  a5 = (a5 >> 8) & 0x1;  /* 0465: extui width 1 */
  ST32(a1 + 0x54, a5);  /* 0468 */
  if (a5 == 0) goto L_0499;  /* 046b: beqz.n a5, 499 <mesh_xon_task_main+0x341> */
  L_046d: a3 = LD32(a6 + 0x0);  /* 046d */
  if (((a3 >> 26) & 1) == 0) goto L_0488;  /* 046f: bbci a3, 26, 488 <mesh_xon_task_main+0x330> */
  L_0472: a13 = 0x00000b85u;  /* 0472: l32r = 2949 */
  L_0475: a11 = 6;  /* 0475 */
  a12 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 0477: l32r -> .rodata.__func__$3 */
  L_047a: a10 = a2;  /* 047a */
  __asm__ volatile("" ::: "memory");  /* 047c: memw */
  a8 = (u32)&esp_mesh_discard_context;  /* 047f: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 0482: callx a8 via reloc-expand */
  goto L_09ea;  /* 0485: j */
  L_0488: a10 = a2;  /* 0488 */
  a8 = (u32)&mesh_xon_deliver_packet;  /* 048a: l32r -> func addr */
  a2 = mesh_xon_deliver_packet(a2, a3, a4, a5, a6, a7);  /* 048d: callx a8 via reloc-expand */
  a13 = 0x00000b89u;  /* 0490: l32r = 2953 */
  if (a10 != 0) goto L_0475;  /* 0493: bnez a10, 475 <mesh_xon_task_main+0x31d> */
  L_0496: goto L_09ea;  /* 0496: j */
  L_0499: a5 = LD8U(a2 + 0x12);  /* 0499 */
  a13 = 0x00000b91u;  /* 049c: l32r = 2961 */
  if (a5 != 0) goto L_0475;  /* 049f: bnez a5, 475 <mesh_xon_task_main+0x31d> */
  L_04a2: a5 = (u32)&LOCAL__bss_mesh_reassign_xseqno + 0x0;  /* 04a2: l32r -> .bss.mesh_reassign_xseqno (same-object static) */
  a6 = LD32(a5 + 0x0);  /* 04a5 */
  a6 = a6 + (1);  /* 04a7 */
  a7 = 0x0ffffffeu;  /* 04a9: l32r = 268435454 */
  if (a7 < a6) goto L_04b2;  /* 04ac: bltu a7, a6, 4b2 <mesh_xon_task_main+0x35a> */
  L_04af: goto L_04b4;  /* 04af: j */
  L_04b2: a6 = 1;  /* 04b2 */
  L_04b4: ST32(a5 + 0x0, a6);  /* 04b4 */
  a6 = a3 + (14);  /* 04b6 */
  a5 = LD32(a5 + 0x0);  /* 04b8 */
  ST32(a6 + 0x18, a5);  /* 04ba */
  a6 = (u32)&mesh_xon + 0x0;  /* 04bc: l32r -> global */
  ST32(a6 + 0x4, a5);  /* 04bf */
  L_04c1: a5 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 04c1: l32r -> .bss.mesh_tx_task (same-object static) */
  a5 = LD8U(a5 + 0x24);  /* 04c4 */
  ST32(a1 + 0x68, a5);  /* 04c7 */
  if (a5 != 0) goto L_04d9;  /* 04ca: bnez.n a5, 4d9 <mesh_xon_task_main+0x381> */
  L_04cc: a13 = 0x5cf;  /* 04cc */
  a13 = a13 + a13;  /* 04cf */
  __asm__ volatile("" ::: "memory");  /* 04d1: memw */
  goto L_0475;  /* 04d4: j */
  L_04d9: a11 = a1 + (60);  /* 04d9 */
  a10 = a2;  /* 04dc */
  a8 = (u32)&mesh_xon_process_expired;  /* 04de: l32r -> func addr */
  a2 = mesh_xon_process_expired(a2, a3, a4, a5, a6, a7);  /* 04e1: callx a8 via reloc-expand */
  a5 = LD32(a1 + 0x3c);  /* 04e4 */
  if (a5 == 0) goto L_04ee;  /* 04e6: beqz.n a5, 4ee <mesh_xon_task_main+0x396> */
  L_04e8: a13 = 0x00000ba5u;  /* 04e8: l32r = 2981 */
  goto L_0475;  /* 04eb: j */
  L_04ee: a10 = LD32(a1 + 0x6c);  /* 04ee */
  a13 = 0x5d7;  /* 04f1 */
  a13 = a13 + a13;  /* 04f4 */
  a12 = a1 + (60);  /* 04f6 */
  a11 = a2;  /* 04f9 */
  a8 = (u32)&mesh_xon_process_disconnected;  /* 04fb: l32r -> func addr */
  a2 = mesh_xon_process_disconnected(a2, a3, a4, a5, a6, a7);  /* 04fe: callx a8 via reloc-expand */
  a6 = LD32(a1 + 0x3c);  /* 0501 */
  ST32(a1 + 0x58, a6);  /* 0503 */
  if (a6 != 0) goto L_09ea;  /* 0506: bnez a6, 9ea <mesh_xon_task_main+0x892> */
  L_0509: a8 = a2 + (6);  /* 0509 */
  a12 = 6;  /* 050b */
  a10 = a8;  /* 050d */
  a5 = (u32)&g_mesh_current_parent + 0x0;  /* 050f: l32r -> global */
  a11 = a5;  /* 0512: mov */
  ST32(a1 + 0x60, a8);  /* 0515 */
  __asm__ volatile("" ::: "memory");  /* 0518: memw */
  a8 = (u32)&memcmp + 0x0;  /* 051b: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 051e: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_054c;  /* 0521: beqz.n a10, 54c <mesh_xon_task_main+0x3f4> */
  L_0523: a10 = LD32(a1 + 0x60);  /* 0523 */
  a8 = (u32)&esp_mesh_get_parent_bssid + 0x0;  /* 0526: l32r -> global */
  a2 = esp_mesh_get_parent_bssid(a2, a3, a4, a5, a6, a7);  /* 0529: callx a8 via reloc-expand */
  a12 = 6;  /* 052c */
  a11 = a5;  /* 052e */
  a10 = (u32)&mesh_xon + 0x8;  /* 0530: l32r -> global */
  a8 = (u32)&memcmp + 0x0;  /* 0533: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0536: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_054c;  /* 0539: beqz.n a10, 54c <mesh_xon_task_main+0x3f4> */
  L_053b: a5 = (u32)&mesh_xon + 0x0;  /* 053b: l32r -> global */
  ST32(a5 + 0x0, a6);  /* 053e */
  a5 = (u32)&LOCAL__bss_mesh_reassign_xseqno + 0x0;  /* 0540: l32r -> .bss.mesh_reassign_xseqno (same-object static) */
  ST32(a5 + 0x0, a6);  /* 0543 */
  __asm__ volatile("" ::: "memory");  /* 0545: memw */
  goto L_0564;  /* 0548: j */
  L_054c: a5 = (u32)&mesh_xon + 0x0;  /* 054c: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 054f */
  if (a5 == 0) goto L_0564;  /* 0551: beqz.n a5, 564 <mesh_xon_task_main+0x40c> */
  L_0553: a12 = 6;  /* 0553 */
  a11 = (u32)&g_mesh_current_parent + 0x0;  /* 0555: l32r -> global */
  a10 = (u32)&mesh_xon + 0x8;  /* 0558: l32r -> global */
  a8 = (u32)&memcmp + 0x0;  /* 055b: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 055e: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0a64;  /* 0561: beqz a10, a64 <mesh_xon_task_main+0x90c> */
  L_0564: a7 = (u32)&LOCAL__bss_mesh_reassign_xseqno + 0x0;  /* 0564: l32r -> .bss.mesh_reassign_xseqno (same-object static) */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0567: l32r -> global */
  a6 = LD32(a7 + 0x0);  /* 056a */
  a5 = LD32(a5 + 0x0);  /* 056c */
  if (a6 != 0) goto L_05c0;  /* 056e: bnez a6, 5c0 <mesh_xon_task_main+0x468> */
  L_0571: a6 = 1;  /* 0571 */
  a8 = (u32)&mesh_xon + 0x0;  /* 0573: l32r -> global */
  ST32(a7 + 0x0, a6);  /* 0576 */
  a7 = a3 + (14);  /* 0578 */
  ST32(a7 + 0x18, a6);  /* 057a */
  ST32(a8 + 0x4, a6);  /* 057c */
  a6 = (u32)&g_log_level + 0x0;  /* 057e: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 0581 */
  if (a6 < 3u) goto L_05c0;  /* 0583: bltui a6, 3, 5c0 <mesh_xon_task_main+0x468> */
  L_0586: if (a5 == 0) goto L_05c0;  /* 0586: beqz.n a5, 5c0 <mesh_xon_task_main+0x468> */
  L_0588: a6 = LD32(a5 + 0x150);  /* 0588 */
  if (a6 == 0) goto L_05c0;  /* 058b: beqz a6, 5c0 <mesh_xon_task_main+0x468> */
  L_058e: a10 = LD32(a5 + 0x158);  /* 058e */
  ST32(a1 + 0x78, a8);  /* 0591 */
  __asm__ volatile("" ::: "memory");  /* 0594: memw */
  /* 0597: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 059a */
  a10 = 3;  /* 059c */
  a8 = LD32(a1 + 0x78);  /* 059e */
  a5 = LD32(a8 + 0x0);  /* 05a1 */
  ST32(a1 + 0x8, a5);  /* 05a3 */
  a5 = LD32(a7 + 0x18);  /* 05a5 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 05a7: -> "mesh" */
  a14 = a11;  /* 05aa */
  ST32(a1 + 0x4, a5);  /* 05ac */
  a5 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 05ae: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  a15 = 0x00000be5u;  /* 05b1: l32r = 3045 */
  a12 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 05b4: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  ST32(a1 + 0x0, a5);  /* 05b7 */
  __asm__ volatile("" ::: "memory");  /* 05ba: memw */
  /* 05bd: INDIRECT callx a6 <- mem[a5+0x150]; result unknown */ a2 = 0;
  L_05c0: a7 = (u32)&LOCAL__bss_mesh_new_wnd_mbox + 0x0;  /* 05c0: l32r -> .bss.mesh_new_wnd_mbox (same-object static) */
  L_05c3: a12 = 0;  /* 05c3 */
  a11 = a1 + (32);  /* 05c5 */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 05c8: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 05cb */
  a10 = LD32(a7 + 0x0);  /* 05cd */
  a6 = LD32(a6 + 0x74);  /* 05cf */
  /* 05d2: INDIRECT callx a6 <- mem[a6+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_05c3;  /* 05d5: beqi a10, 1, 5c3 <mesh_xon_task_main+0x46b> */
  L_05d8: a10 = a1 + (48);  /* 05d8 */
  a8 = (u32)&esp_mesh_get_parent_bssid + 0x0;  /* 05db: l32r -> global */
  a2 = esp_mesh_get_parent_bssid(a2, a3, a4, a5, a6, a7);  /* 05de: callx a8 via reloc-expand */
  a6 = a3 + (14);  /* 05e1 */
  a14 = 0;  /* 05e3 */
  a13 = LD32(a6 + 0x18);  /* 05e5 */
  a15 = a4;  /* 05e7 */
  a12 = a14;  /* 05e9 */
  a10 = a1 + (48);  /* 05eb */
  a4 = 0;  /* 05ee */
  a11 = LD8U(a2 + 0x12);  /* 05f1 */
  a8 = (u32)&esp_mesh_send_xon;  /* 05f4: l32r -> func addr */
  a2 = esp_mesh_send_xon(a2, a3, a4, a5, a6, a7);  /* 05f7: callx a8 via reloc-expand */
  a8 = a10;  /* 05fa */
  ST32(a1 + 0x20, a4);  /* 05fc */
  if (a10 != a4) goto L_0604;  /* 05fe: bne a10, a4, 604 <mesh_xon_task_main+0x4ac> */
  L_0601: goto L_076c;  /* 0601: j */
  L_0604: a4 = (u32)&g_log_level + 0x0;  /* 0604: l32r -> global */
  a9 = 0x00004004u;  /* 0607: l32r = 16388 */
  a7 = LD32(a4 + 0x0);  /* 060a */
  if (a10 == a9) goto L_0612;  /* 060c: beq a10, a9, 612 <mesh_xon_task_main+0x4ba> */
  L_060f: goto L_06cc;  /* 060f: j */
  L_0612: if (a7 >= 3u) goto L_0618;  /* 0612: bgeui a7, 3, 618 <mesh_xon_task_main+0x4c0> */
  L_0615: goto L_06a2;  /* 0615: j */
  L_0618: a6 = LD32(a5 + 0x0);  /* 0618 */
  if (a6 != 0) goto L_0629;  /* 061a: bnez.n a6, 629 <mesh_xon_task_main+0x4d1> */
  L_061c: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 061c: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 061f */
  if (a4 != 0) goto L_0660;  /* 0621: bnez.n a4, 660 <mesh_xon_task_main+0x508> */
  L_0623: __asm__ volatile("" ::: "memory");  /* 0623: memw */
  goto L_06a2;  /* 0626: j */
  L_0629: a7 = LD32(a6 + 0x150);  /* 0629 */
  if (a7 == 0) goto L_061c;  /* 062c: beqz a7, 61c <mesh_xon_task_main+0x4c4> */
  L_062f: a10 = LD32(a6 + 0x158);  /* 062f */
  /* 0632: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a6 = a10;  /* 0635 */
  a5 = LD32(a5 + 0x0);  /* 0637 */
  a10 = LD32(a5 + 0xb8);  /* 063a */
  /* 063d: INDIRECT callx a10 <- mem[a5+0xb8]; result unknown */ a2 = 0;
  a13 = a6;  /* 0640 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0642: -> "mesh" */
  a14 = a11;  /* 0645 */
  a15 = 0x00000c05u;  /* 0647: l32r = 3077 */
  a12 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 064a: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  ST32(a1 + 0x0, a10);  /* 064d */
  a10 = 3;  /* 064f */
  __asm__ volatile("" ::: "memory");  /* 0652: memw */
  /* 0655: INDIRECT callx a7 <- mem[a6+0x150]; result unknown */ a2 = 0;
  a4 = LD32(a4 + 0x0);  /* 0658 */
  if (a4 >= 3u) goto L_061c;  /* 065a: bgeui a4, 3, 61c <mesh_xon_task_main+0x4c4> */
  L_065d: goto L_06a2;  /* 065d: j */
  L_0660: a5 = LD32(a4 + 0x150);  /* 0660 */
  if (a5 == 0) goto L_06a2;  /* 0663: beqz.n a5, 6a2 <mesh_xon_task_main+0x54a> */
  L_0665: a7 = a3 + (14);  /* 0665 */
  a10 = LD32(a4 + 0x158);  /* 0667 */
  /* 066a: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 066d */
  a10 = 3;  /* 066f */
  a4 = 0x00004004u;  /* 0671: l32r = 16388 */
  a6 = LD32(a7 + 0x18);  /* 0674 */
  ST32(a1 + 0x14, a4);  /* 0676 */
  a4 = LD16U(a2 + 0x4);  /* 0678 */
  ST32(a1 + 0x10, a4);  /* 067b */
  a4 = a3 + (18);  /* 067d */
  a4 = LD32(a4 + 0x0);  /* 0680 */
  a4 = (a4 >> 5) & 0x3ff;  /* 0682: extui width 10 */
  ST32(a1 + 0xc, a4);  /* 0685 */
  a4 = LD32(a7 + 0x14);  /* 0687 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0689: -> "mesh" */
  a14 = a11;  /* 068c */
  ST32(a1 + 0x8, a4);  /* 068e */
  a4 = a6 + (-1);  /* 0690 */
  a15 = 0x00000c07u;  /* 0692: l32r = 3079 */
  a12 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 0695: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  ST32(a1 + 0x4, a4);  /* 0698 */
  ST32(a1 + 0x0, a6);  /* 069a */
  __asm__ volatile("" ::: "memory");  /* 069c: memw */
  /* 069f: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  L_06a2: a3 = a3 + (14);  /* 06a2 */
  a10 = a2;  /* 06a4 */
  a5 = (u32)&LOCAL__bss_mesh_reassign_xseqno + 0x0;  /* 06a6: l32r -> .bss.mesh_reassign_xseqno (same-object static) */
  a4 = LD32(a5 + 0x0);  /* 06a9 */
  a4 = a4 + (-1);  /* 06ab */
  a13 = 0x00000c0du;  /* 06ad: l32r = 3085 */
  a12 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 06b0: l32r -> .rodata.__func__$3 */
  a11 = 0x00004004u;  /* 06b3: l32r = 16388 */
  ST32(a3 + 0x18, a4);  /* 06b6 */
  ST32(a5 + 0x0, a4);  /* 06b8 */
  __asm__ volatile("" ::: "memory");  /* 06bb: memw */
  a8 = (u32)&esp_mesh_discard_context;  /* 06be: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 06c1: callx a8 via reloc-expand */
  a4 = LD32(a1 + 0x54);  /* 06c4 */
  goto L_09ea;  /* 06c7: j */
  L_06cc: if (a7 < 3u) goto L_0728;  /* 06cc: bltui a7, 3, 728 <mesh_xon_task_main+0x5d0> */
  L_06cf: a5 = LD32(a5 + 0x0);  /* 06cf */
  if (a5 == 0) goto L_0728;  /* 06d1: beqz a5, 728 <mesh_xon_task_main+0x5d0> */
  L_06d4: a4 = LD32(a5 + 0x150);  /* 06d4 */
  if (a4 == 0) goto L_0728;  /* 06d7: beqz a4, 728 <mesh_xon_task_main+0x5d0> */
  L_06da: a10 = LD32(a5 + 0x158);  /* 06da */
  ST32(a1 + 0x78, a8);  /* 06dd */
  __asm__ volatile("" ::: "memory");  /* 06e0: memw */
  /* 06e3: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a15 = 0x60b;  /* 06e6 */
  a13 = a10;  /* 06e9 */
  a15 = a15 + a15;  /* 06eb */
  a5 = LD32(a6 + 0x18);  /* 06ed */
  a10 = 3;  /* 06ef */
  ST32(a1 + 0x1c, a5);  /* 06f1 */
  a5 = LD8U(a1 + 0x35);  /* 06f3 */
  ST32(a1 + 0x18, a5);  /* 06f6 */
  a5 = LD8U(a1 + 0x34);  /* 06f8 */
  ST32(a1 + 0x14, a5);  /* 06fb */
  a5 = LD8U(a1 + 0x33);  /* 06fd */
  ST32(a1 + 0x10, a5);  /* 0700 */
  a5 = LD8U(a1 + 0x32);  /* 0702 */
  ST32(a1 + 0xc, a5);  /* 0705 */
  a5 = LD8U(a1 + 0x31);  /* 0707 */
  a8 = LD32(a1 + 0x78);  /* 070a */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 070d: -> "mesh" */
  a14 = a11;  /* 0710 */
  ST32(a1 + 0x8, a5);  /* 0712 */
  a5 = LD8U(a1 + 0x30);  /* 0714 */
  a12 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 0717: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  ST32(a1 + 0x0, a8);  /* 071a */
  ST32(a1 + 0x4, a5);  /* 071c */
  __asm__ volatile("" ::: "memory");  /* 071f: memw */
  /* 0722: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  a8 = LD32(a1 + 0x78);  /* 0725 */
  L_0728: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0728: l32r -> global */
  a6 = 0x0000400du;  /* 072b: l32r = 16397 */
  a5 = LD32(a4 + 0x0);  /* 072e */
  a4 = LD32(a5 + 0x9c);  /* 0730 */
  a5 = LD32(a5 + 0xa0);  /* 0733 */
  if (a8 != a6) goto L_0754;  /* 0736: bne a8, a6, 754 <mesh_xon_task_main+0x5fc> */
  L_0739: a10 = 0x177;  /* 0739 */
  a10 = a10 << 3;  /* 073c */
  /* 073f: INDIRECT callx a5 <- mem[a5+0xa0]; result unknown */ a2 = 0;
  /* 0742: INDIRECT callx a4 <- mem[a5+0x9c]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x58);  /* 0745 */
  a4 = LD32(a1 + 0x54);  /* 0748 */
  ST32(a1 + 0x50, a9);  /* 074b */
  __asm__ volatile("" ::: "memory");  /* 074e: memw */
  goto L_08a7;  /* 0751: j */
  L_0754: a10 = 110;  /* 0754 */
  /* 0757: INDIRECT callx a5 <- mem[a5+0xa0]; result unknown */ a2 = 0;
  /* 075a: INDIRECT callx a4 <- mem[a1+0x54]; result unknown */ a2 = 0;
  a5 = LD32(a1 + 0x58);  /* 075d */
  a4 = LD32(a1 + 0x54);  /* 0760 */
  ST32(a1 + 0x50, a5);  /* 0763 */
  __asm__ volatile("" ::: "memory");  /* 0766: memw */
  goto L_08a7;  /* 0769: j */
  L_076c: a4 = LD32(a5 + 0x0);  /* 076c */
  a14 = (u32)&g_mesh_init_ps_type + 0x0;  /* 076e: l32r -> global */
  a9 = LD32(a4 + 0x74);  /* 0771 */
  a10 = LD32(a14 + 0x0);  /* 0774 */
  a11 = LD32(a4 + 0xa0);  /* 0776 */
  a4 = 0x4b0;  /* 0779 */
  a12 = a4;  /* 077c */
  a14 = (u32)&g_mesh_packet_lifetime + 0x0;  /* 077e: l32r -> global */
  a13 = LD32(a7 + 0x0);  /* 0781 */
  a7 = 0x708;  /* 0783 */
  if (a10 != 0) a12 = a7;  /* 0786 */
  a10 = LD32(a14 + 0x0);  /* 0789 */
  a10 = (a12 < a10) ? a12 : a10;  /* 078b: minu */
  ST32(a1 + 0x78, a8);  /* 078e */
  ST32(a1 + 0x70, a9);  /* 0791 */
  ST32(a1 + 0x74, a13);  /* 0794 */
  __asm__ volatile("" ::: "memory");  /* 0797: memw */
  /* 079a: INDIRECT callx a11 <- mem[a4+0xa0]; result unknown */ a2 = 0;
  a12 = a10;  /* 079d */
  a11 = a1 + (32);  /* 079f */
  a13 = LD32(a1 + 0x74);  /* 07a2 */
  a10 = a13;  /* 07a5 */
  a9 = LD32(a1 + 0x70);  /* 07a7 */
  /* 07aa: INDIRECT callx a9 <- mem[a1+0x70]; result unknown */ a2 = 0;
  a8 = LD32(a1 + 0x78);  /* 07ad */
  if (a10 != 1) goto L_0815;  /* 07b0: bnei a10, 1, 815 <mesh_xon_task_main+0x6bd> */
  L_07b3: a4 = (u32)&mesh_xon + 0x0;  /* 07b3: l32r -> global */
  a7 = LD32(a1 + 0x28);  /* 07b6 */
  a5 = LD32(a1 + 0x20);  /* 07b8 */
  ST32(a4 + 0x8, a7);  /* 07ba */
  a7 = LD16U(a1 + 0x2c);  /* 07bc */
  ST32(a4 + 0x0, a5);  /* 07bf */
  ST16(a4 + 0xc, a7);  /* 07c1 */
  __asm__ volatile("" ::: "memory");  /* 07c4: memw */
  if (a5 != 0) goto L_0894;  /* 07c7: bnez a5, 894 <mesh_xon_task_main+0x73c> */
  L_07ca: a4 = LD32(a1 + 0x5c);  /* 07ca */
  a4 = a4 + (1);  /* 07cd */
  a10 = a4;  /* 07cf */
  a12 = LD32(a2 + 0x18);  /* 07d1 */
  a13 = LD32(a2 + 0x1c);  /* 07d3 */
  ST32(a1 + 0x5c, a4);  /* 07d5 */
  __asm__ volatile("" ::: "memory");  /* 07d8: memw */
  a8 = (u32)&mesh_xon_process_no_wnd;  /* 07db: l32r -> func addr */
  a2 = mesh_xon_process_no_wnd(a2, a3, a4, a5, a6, a7);  /* 07de: callx a8 via reloc-expand */
  a4 = a10;  /* 07e1 */
  if (a10 == 0) goto L_08a4;  /* 07e3: beqz a10, 8a4 <mesh_xon_task_main+0x74c> */
  L_07e6: a4 = (u32)&LOCAL__bss_mesh_reassign_xseqno + 0x0;  /* 07e6: l32r -> .bss.mesh_reassign_xseqno (same-object static) */
  a13 = 0x617;  /* 07e9 */
  a13 = a13 + a13;  /* 07ec */
  a11 = 6;  /* 07ee */
  a10 = a2;  /* 07f0 */
  a3 = LD32(a4 + 0x0);  /* 07f2 */
  a3 = a3 + (-1);  /* 07f4 */
  a12 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 07f6: l32r -> .rodata.__func__$3 */
  ST32(a6 + 0x18, a3);  /* 07f9 */
  ST32(a4 + 0x0, a3);  /* 07fc */
  __asm__ volatile("" ::: "memory");  /* 07ff: memw */
  a8 = (u32)&esp_mesh_discard_context;  /* 0802: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 0805: callx a8 via reloc-expand */
  a4 = LD32(a1 + 0x54);  /* 0808 */
  ST32(a1 + 0x50, a5);  /* 080b */
  __asm__ volatile("" ::: "memory");  /* 080e: memw */
  goto L_09ea;  /* 0811: j */
  L_0815: a5 = LD32(a5 + 0x0);  /* 0815 */
  if (a5 == 0) goto L_0881;  /* 0817: beqz a5, 881 <mesh_xon_task_main+0x729> */
  L_081a: a8 = LD32(a5 + 0x150);  /* 081a */
  if (a8 == 0) goto L_0881;  /* 081d: beqz a8, 881 <mesh_xon_task_main+0x729> */
  L_0820: a10 = LD32(a5 + 0x158);  /* 0820 */
  ST32(a1 + 0x78, a8);  /* 0823 */
  __asm__ volatile("" ::: "memory");  /* 0826: memw */
  /* 0829: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 082c */
  a10 = 2;  /* 082e */
  a5 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0830: l32r -> global */
  a9 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0833: l32r -> global */
  a5 = LD8U(a5 + 0xbd);  /* 0836 */
  a5 = a5 + a5;  /* 0839 */
  a5 = a5 + (1);  /* 083b */
  a9 = LD32(a9 + 0x0);  /* 083d */
  a5 = a9 / a5;  /* 083f: quos */
  a11 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0842: l32r -> global */
  a9 = LD32(a11 + 0x0);  /* 0845 */
  if (a9 != 0) a4 = a7;  /* 0847 */
  a9 = LD32(a1 + 0x50);  /* 084a */
  ST32(a1 + 0x18, a9);  /* 084d */
  a9 = LD32(a1 + 0x5c);  /* 084f */
  ST32(a1 + 0x14, a9);  /* 0852 */
  a7 = LD32(a6 + 0x18);  /* 0854 */
  ST32(a1 + 0x10, a7);  /* 0856 */
  a6 = LD32(a6 + 0x14);  /* 0858 */
  a14 = (u32)&g_mesh_packet_lifetime + 0x0;  /* 085a: l32r -> global */
  ST32(a1 + 0xc, a6);  /* 085d */
  a6 = LD32(a14 + 0x0);  /* 085f */
  a4 = (a4 < a6) ? a4 : a6;  /* 0861: minu */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0864: -> "mesh" */
  a14 = a11;  /* 0867 */
  ST32(a1 + 0x8, a4);  /* 0869 */
  a4 = 0x00000c37u;  /* 086b: l32r = 3127 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 086e: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 0871: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  a8 = LD32(a1 + 0x78);  /* 0874 */
  ST32(a1 + 0x4, a5);  /* 0877 */
  ST32(a1 + 0x0, a4);  /* 0879 */
  __asm__ volatile("" ::: "memory");  /* 087b: memw */
  /* 087e: INDIRECT callx a8 <- mem[a1+0x78]; result unknown */ a2 = 0;
  L_0881: a4 = LD32(a1 + 0x50);  /* 0881 */
  a4 = a4 + (1);  /* 0884 */
  ST32(a1 + 0x50, a4);  /* 0886 */
  a4 = LD32(a1 + 0x54);  /* 0889 */
  __asm__ volatile("" ::: "memory");  /* 088c: memw */
  goto L_08a7;  /* 088f: j */
  L_0894: a4 = LD32(a1 + 0x68);  /* 0894 */
  ST32(a1 + 0x50, a8);  /* 0897 */
  ST32(a1 + 0x5c, a8);  /* 089a */
  __asm__ volatile("" ::: "memory");  /* 089d: memw */
  goto L_08a7;  /* 08a0: j */
  L_08a4: ST32(a1 + 0x50, a10);  /* 08a4 */
  L_08a7: a5 = (u32)&mesh_xon + 0x0;  /* 08a7: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 08aa */
  if (a5 == 0) goto L_04c1;  /* 08ac: beqz a5, 4c1 <mesh_xon_task_main+0x369> */
  L_08af: a12 = 6;  /* 08af */
  a11 = (u32)&g_mesh_current_parent + 0x0;  /* 08b1: l32r -> global */
  a10 = (u32)&mesh_xon + 0x8;  /* 08b4: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 08b7: memw */
  a8 = (u32)&memcmp + 0x0;  /* 08ba: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 08bd: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_04c1;  /* 08c0: bnez a10, 4c1 <mesh_xon_task_main+0x369> */
  L_08c3: goto L_0a64;  /* 08c3: j */
  L_08c8: a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 08c8: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  a12 = 6;  /* 08cb */
  a10 = a3 + (22);  /* 08cd */
  a8 = (u32)&memcmp + 0x0;  /* 08d0: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 08d3: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0958;  /* 08d6: beqz a10, 958 <mesh_xon_task_main+0x800> */
  L_08d9: a7 = LD8U(a3 + 0x16);  /* 08d9 */
  if (((a7 >> 0) & 1) == 0) goto L_08e5;  /* 08dc: bbci a7, 0, 8e5 <mesh_xon_task_main+0x78d> */
  L_08df: a7 = LD8U(a3 + 0xe);  /* 08df */
  if (((a7 >> 5) & 1) == 0) goto L_0958;  /* 08e2: bbci a7, 5, 958 <mesh_xon_task_main+0x800> */
  L_08e5: a12 = 99;  /* 08e5 */
  a12 = a12 << 5;  /* 08e8 */
  a8 = (u32)&LOCAL__bss_mesh_ack_state_mbox + 0x0;  /* 08eb: l32r -> .bss.mesh_ack_state_mbox (same-object static) */
  a5 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 08ee: l32r -> .rodata.__func__$3 */
  a11 = a5;  /* 08f1: mov */
  a10 = LD32(a8 + 0x4);  /* 08f4 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 08f7: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 08fa: callx a8 via reloc-expand */
  a11 = a1 + (56);  /* 08fd */
  a10 = a2;  /* 0900 */
  a8 = (u32)&esp_mesh_best_effort_tx;  /* 0902: l32r -> func addr */
  a2 = esp_mesh_best_effort_tx(a2, a3, a4, a5, a6, a7);  /* 0905: callx a8 via reloc-expand */
  a9 = (u32)&LOCAL__bss_mesh_ack_state_mbox + 0x0;  /* 0908: l32r -> .bss.mesh_ack_state_mbox (same-object static) */
  a7 = a10;  /* 090b */
  a12 = 0x631;  /* 090d */
  a11 = a5;  /* 0910 */
  a12 = a12 + a12;  /* 0912 */
  a10 = LD32(a9 + 0x4);  /* 0914 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0917: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 091a: callx a8 via reloc-expand */
  a5 = LD32(a1 + 0x38);  /* 091d */
  if (a7 != 0) goto L_0936;  /* 091f: bnez.n a7, 936 <mesh_xon_task_main+0x7de> */
  L_0921: if (a5 != 1) goto L_0936;  /* 0921: bnei a5, 1, 936 <mesh_xon_task_main+0x7de> */
  L_0924: a5 = (u32)&mesh_xon + 0x0;  /* 0924: l32r -> global */
  a3 = LD32(a5 + 0x0);  /* 0927 */
  a3 = a3 + (-1);  /* 0929 */
  a7 = LD32(a1 + 0x58);  /* 092b */
  ST32(a5 + 0x0, a3);  /* 092e */
  __asm__ volatile("" ::: "memory");  /* 0930: memw */
  goto L_09c8;  /* 0933: j */
  L_0936: if (a5 != 7) goto L_0944;  /* 0936: bnei a5, 7, 944 <mesh_xon_task_main+0x7ec> */
  L_0939: a3 = 0;  /* 0939 */
  ST32(a6 + 0x0, a3);  /* 093b */
  __asm__ volatile("" ::: "memory");  /* 093d: memw */
  goto L_09be;  /* 0940: j */
  L_0944: a6 = (u32)&LOCAL__bss_mesh_reassign_xseqno + 0x0;  /* 0944: l32r -> .bss.mesh_reassign_xseqno (same-object static) */
  a3 = a3 + (14);  /* 0947 */
  a5 = LD32(a6 + 0x0);  /* 0949 */
  a5 = a5 + (-1);  /* 094b */
  ST32(a6 + 0x0, a5);  /* 094d */
  ST32(a3 + 0x18, a5);  /* 094f */
  __asm__ volatile("" ::: "memory");  /* 0951: memw */
  goto L_09be;  /* 0954: j */
  L_0958: a3 = LD32(a2 + 0x0);  /* 0958 */
  a12 = 6;  /* 095a */
  a10 = a3;  /* 095c */
  a6 = -18;  /* 095e */
  a11 = LD32(a1 + 0x60);  /* 0960 */
  a8 = (u32)&memcpy + 0x0;  /* 0963: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0966: callx a8 (libc, via reloc-expand) */
  a11 = a3 + (6);  /* 0969 */
  a10 = LD8U(a2 + 0x12);  /* 096b */
  a8 = (u32)&wifi_get_macaddr + 0x0;  /* 096e: l32r -> global */
  a2 = wifi_get_macaddr(a2, a3, a4, a5, a6, a7);  /* 0971: callx a8 via reloc-expand */
  ST8(a3 + 0xc, a6);  /* 0974 */
  ST8(a3 + 0xd, a6);  /* 0977 */
  __asm__ volatile("" ::: "memory");  /* 097a: memw */
  L_097d: a13 = LD32(a1 + 0x60);  /* 097d */
  a12 = LD16U(a2 + 0x4);  /* 0980 */
  a11 = LD32(a2 + 0x0);  /* 0983 */
  a10 = LD8U(a2 + 0x12);  /* 0985 */
  __asm__ volatile("" ::: "memory");  /* 0988: memw */
  a8 = (u32)&esp_wifi_mesh_tx + 0x0;  /* 098b: l32r -> global */
  a2 = esp_wifi_mesh_tx(a2, a3, a4, a5, a6, a7);  /* 098e: callx a8 via reloc-expand */
  a7 = a10;  /* 0991 */
  a3 = LD8U(a5 + 0x3);  /* 0993 */
  if (((a3 >> 0) & 1) == 0) goto L_09be;  /* 0996: bbci a3, 0, 9be <mesh_xon_task_main+0x866> */
  L_0999: a3 = a10 + (-84);  /* 0999 */
  if (a3 != 0) goto L_09be;  /* 099c: bnez a3, 9be <mesh_xon_task_main+0x866> */
  L_099f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 099f: l32r -> global */
  a10 = 10;  /* 09a2 */
  a3 = LD32(a3 + 0x0);  /* 09a5 */
  a6 = LD32(a3 + 0x9c);  /* 09a8 */
  a3 = LD32(a3 + 0xa0);  /* 09ab */
  /* 09ae: INDIRECT callx a3 <- mem[a3+0xa0]; result unknown */ a2 = 0;
  /* 09b1: INDIRECT callx a6 <- mem[a3+0x9c]; result unknown */ a2 = 0;
  a3 = LD32(a5 + 0x0);  /* 09b4 */
  if (((a3 >> 24) & 1) != 0) goto L_097d;  /* 09b6: bbsi a3, 24, 97d <mesh_xon_task_main+0x825> */
  L_09b9: a7 = 84;  /* 09b9 */
  goto L_09c8;  /* 09bb: j */
  L_09be: if (a7 != 0) goto L_09c8;  /* 09be: bnez.n a7, 9c8 <mesh_xon_task_main+0x870> */
  L_09c0: a3 = LD32(a1 + 0x38);  /* 09c0 */
  if (a3 != 1) goto L_09c8;  /* 09c2: bnei a3, 1, 9c8 <mesh_xon_task_main+0x870> */
  L_09c5: goto L_0924;  /* 09c5: j */
  L_09c8: a13 = 0x653;  /* 09c8 */
  a10 = a2;  /* 09cb */
  a12 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 09cd: l32r -> .rodata.__func__$3 */
  a13 = a13 + a13;  /* 09d0 */
  a11 = LD32(a1 + 0x38);  /* 09d3 */
  a8 = (u32)&esp_mesh_discard_context;  /* 09d6: l32r -> func addr */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 09d9: callx a8 via reloc-expand */
  a2 = 0x00004004u;  /* 09dc: l32r = 16388 */
  if (a7 != a2) goto L_09ea;  /* 09df: bne a7, a2, 9ea <mesh_xon_task_main+0x892> */
  L_09e2: a10 = 1;  /* 09e2 */
  a8 = (u32)&mesh_tx_tid_stop;  /* 09e4: l32r -> func addr */
  a2 = mesh_tx_tid_stop(a2, a3, a4, a5, a6, a7);  /* 09e7: callx a8 via reloc-expand */
  L_09ea: a11 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 09ea: l32r -> .bss.mesh_tx_task (same-object static) */
  a2 = LD8U(a11 + 0x24);  /* 09ed */
  if (a2 == 0) goto L_09f5;  /* 09f0: beqz.n a2, 9f5 <mesh_xon_task_main+0x89d> */
  L_09f2: goto L_018d;  /* 09f2: j */
  L_09f5: goto L_029b;  /* 09f5: j */
  L_09f8: a3 = LD32(a2 + 0x0);  /* 09f8 */
  a11 = 4;  /* 09fa */
  a3 = LD32(a3 + 0x84);  /* 09fc */
  /* 09ff: INDIRECT callx a3 <- mem[a3+0x84]; result unknown */ a2 = 0;
  L_0a02: a3 = LD32(a2 + 0x0);  /* 0a02 */
  if (a3 == 0) goto L_0a2d;  /* 0a04: beqz.n a3, a2d <mesh_xon_task_main+0x8d5> */
  L_0a06: a4 = LD32(a3 + 0x150);  /* 0a06 */
  if (a4 == 0) goto L_0a2d;  /* 0a09: beqz a4, a2d <mesh_xon_task_main+0x8d5> */
  L_0a0c: a10 = LD32(a3 + 0x158);  /* 0a0c */
  /* 0a0f: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0a12 */
  a10 = 2;  /* 0a14 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0a16: -> "mesh" */
  a14 = a11;  /* 0a19 */
  a3 = 0x00000cb4u;  /* 0a1b: l32r = 3252 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0a1e: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 0a21: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  ST32(a1 + 0x0, a3);  /* 0a24 */
  __asm__ volatile("" ::: "memory");  /* 0a27: memw */
  /* 0a2a: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_0a2d: a3 = LD32(a2 + 0x0);  /* 0a2d */
  if (a3 == 0) goto L_0a56;  /* 0a2f: beqz.n a3, a56 <mesh_xon_task_main+0x8fe> */
  L_0a31: a4 = LD32(a3 + 0x150);  /* 0a31 */
  if (a4 == 0) goto L_0a56;  /* 0a34: beqz.n a4, a56 <mesh_xon_task_main+0x8fe> */
  L_0a36: a10 = LD32(a3 + 0x158);  /* 0a36 */
  /* 0a39: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0a3c */
  a10 = 2;  /* 0a3e */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 0a40: -> "mesh" */
  a14 = a11;  /* 0a43 */
  a3 = 0x00000cb5u;  /* 0a45: l32r = 3253 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0a48: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_mesh_xon_task_main_str1_1 + 0x0);  /* 0a4b: l32r -> .rodata.mesh_xon_task_main.str1.1 */
  ST32(a1 + 0x0, a3);  /* 0a4e */
  __asm__ volatile("" ::: "memory");  /* 0a50: memw */
  /* 0a53: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_0a56: a10 = 0;  /* 0a56 */
  a2 = LD32(a2 + 0x0);  /* 0a58 */
  a2 = LD32(a2 + 0x98);  /* 0a5a */
  /* 0a5d: INDIRECT callx a2 <- mem[a2+0x98]; result unknown */ a2 = 0;
  return a2;  /* 0a60: retw.n */
  L_0a64: a6 = (u32)&mesh_xon + 0x0;  /* 0a64: l32r -> global */
  a5 = a3 + (18);  /* 0a67 */
  a8 = LD32(a6 + 0x0);  /* 0a6a */
  a8 = (a8 >> 5) & 0x1;  /* 0a6c: extui width 1 */
  a8 = a8 << 9;  /* 0a6f */
  a7 = LD32(a5 + 0x0);  /* 0a72 */
  a9 = 0xffffc1ffu;  /* 0a74: l32r = -15873 */
  a7 = a7 & a9;  /* 0a77 */
  a7 = a7 | a8;  /* 0a7a */
  a8 = 0x0800c000u;  /* 0a7d: l32r = 134266880 */
  ST32(a5 + 0x0, a7);  /* 0a80 */
  if ((a7 & a8) != 0) goto L_0a88;  /* 0a82: bany a7, a8, a88 <mesh_xon_task_main+0x930> */
  L_0a85: goto L_08c8;  /* 0a85: j */
  L_0a88: __asm__ volatile("" ::: "memory");  /* 0a88: memw */
  goto L_0958;  /* 0a8b: j */
  L_0a8e: a3 = LD32(a3 + 0x0);  /* 0a8e */
  if (a3 != 0) goto L_0355;  /* 0a90: bnez a3, 355 <mesh_xon_task_main+0x1fd> */
  L_0a93: goto L_037a;  /* 0a93: j */
  L_ret: return a2;
}


/* tx_task_main @ mesh_schedule.o 0000003c size 516B bind GLOBAL
 * Calls: mesh_mutex_lock, mesh_mutex_unlock, mesh_ps_tx | indirect[17]: mem[a7+0x78]; mem[a8+0x78]; mem[a9+0x74]; mem[a2+0x158] | Data refs: .bss.mesh_tx_task, g_osi_funcs_p, .bss.mesh_tx_mbox, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.tx_task_main.str1.1, .rodata.__func__$10
 * Fidelity: medium - 17 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=10); reloc-direct=3, funcdb-attributed=0, unknown-indirect=17 */
u32 tx_task_main(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a5, a6, a7, a8, a9;
  /* 003c: entry a1, 80 (frame 80 bytes) */
  ST32(a1 + 0x20, a2);  /* 003f */
  a6 = 0;  /* 0041 */
  a2 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0043: l32r -> .bss.mesh_tx_task (same-object static) */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0046: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0049 */
  a7 = LD32(a5 + 0x0);  /* 004b */
  ST32(a1 + 0x24, a2);  /* 004d */
  a2 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 004f: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a7 = LD32(a7 + 0x78);  /* 0052 */
  a10 = LD32(a2 + 0x48);  /* 0055 */
  ST32(a1 + 0x10, a6);  /* 0058 */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  /* 005d: INDIRECT callx a7 <- mem[a7+0x78]; result unknown */ a2 = 0;
  a7 = a10;  /* 0060 */
  a8 = LD32(a5 + 0x0);  /* 0062 */
  a10 = LD32(a2 + 0x54);  /* 0064 */
  a8 = LD32(a8 + 0x78);  /* 0067 */
  /* 006a: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a7 = a7 + a10;  /* 006d */
  a8 = LD32(a5 + 0x0);  /* 006f */
  a10 = LD32(a2 + 0x3c);  /* 0071 */
  a8 = LD32(a8 + 0x78);  /* 0073 */
  /* 0076: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a7 = a7 + a10;  /* 0079 */
  a8 = LD32(a5 + 0x0);  /* 007b */
  a10 = LD32(a2 + 0x18);  /* 007d */
  a8 = LD32(a8 + 0x78);  /* 007f */
  /* 0082: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a7 = a7 + a10;  /* 0085 */
  a8 = LD32(a5 + 0x0);  /* 0087 */
  a10 = LD32(a2 + 0xc);  /* 0089 */
  a8 = LD32(a8 + 0x78);  /* 008b */
  /* 008e: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a7 = a7 + a10;  /* 0091 */
  a8 = LD32(a5 + 0x0);  /* 0093 */
  a10 = LD32(a2 + 0x60);  /* 0095 */
  a8 = LD32(a8 + 0x78);  /* 0098 */
  /* 009b: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a10 = a7 + a10;  /* 009e */
  a7 = 14;  /* 00a0 */
  ST32(a1 + 0x28, a10);  /* 00a2 */
  L_00a4: a8 = LD32(a1 + 0x20);  /* 00a4 */
  if (a8 == a7) goto L_00ac;  /* 00a6: beq a8, a7, ac <tx_task_main+0x70> */
  L_00a9: goto L_0176;  /* 00a9: j */
  L_00ac: a8 = LD32(a5 + 0x0);  /* 00ac */
  a10 = LD32(a2 + 0x48);  /* 00ae */
  a8 = LD32(a8 + 0x78);  /* 00b1 */
  __asm__ volatile("" ::: "memory");  /* 00b4: memw */
  /* 00b7: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = 6;  /* 00ba */
  if (a10 != 0) goto L_010a;  /* 00bc: bnez a10, 10a <tx_task_main+0xce> */
  L_00bf: a8 = LD32(a5 + 0x0);  /* 00bf */
  a10 = LD32(a2 + 0x54);  /* 00c1 */
  a8 = LD32(a8 + 0x78);  /* 00c4 */
  /* 00c7: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = 7;  /* 00ca */
  if (a10 != 0) goto L_010a;  /* 00cc: bnez.n a10, 10a <tx_task_main+0xce> */
  L_00ce: a8 = LD32(a5 + 0x0);  /* 00ce */
  a10 = LD32(a2 + 0x18);  /* 00d0 */
  a8 = LD32(a8 + 0x78);  /* 00d2 */
  /* 00d5: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = 2;  /* 00d8 */
  if (a10 != 0) goto L_010a;  /* 00da: bnez.n a10, 10a <tx_task_main+0xce> */
  L_00dc: a8 = LD32(a5 + 0x0);  /* 00dc */
  a10 = LD32(a2 + 0x3c);  /* 00de */
  a8 = LD32(a8 + 0x78);  /* 00e0 */
  /* 00e3: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = 5;  /* 00e6 */
  if (a10 != 0) goto L_010a;  /* 00e8: bnez.n a10, 10a <tx_task_main+0xce> */
  L_00ea: a8 = LD32(a5 + 0x0);  /* 00ea */
  a10 = LD32(a2 + 0xc);  /* 00ec */
  a8 = LD32(a8 + 0x78);  /* 00ef */
  /* 00f2: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = 1;  /* 00f5 */
  if (a10 != 0) goto L_010a;  /* 00f7: bnez.n a10, 10a <tx_task_main+0xce> */
  L_00f9: a8 = LD32(a5 + 0x0);  /* 00f9 */
  a10 = LD32(a2 + 0x60);  /* 00fb */
  a8 = LD32(a8 + 0x78);  /* 00fe */
  /* 0101: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = a10;  /* 0104 */
  if (a10 == 0) goto L_0112;  /* 0106: beqz.n a10, 112 <tx_task_main+0xd6> */
  L_0108: a8 = 8;  /* 0108 */
  L_010a: ST32(a1 + 0x20, a8);  /* 010a */
  __asm__ volatile("" ::: "memory");  /* 010c: memw */
  goto L_0176;  /* 010f: j */
  L_0112: a9 = LD32(a5 + 0x0);  /* 0112 */
  a12 = -1;  /* 0114 */
  a11 = a1 + (32);  /* 0116 */
  a9 = LD32(a9 + 0x74);  /* 0119 */
  a10 = LD32(a1 + 0x24);  /* 011c */
  ST32(a1 + 0x2c, a8);  /* 011e */
  ST32(a1 + 0x20, a7);  /* 0121 */
  __asm__ volatile("" ::: "memory");  /* 0124: memw */
  /* 0127: INDIRECT callx a9 <- mem[a9+0x74]; result unknown */ a2 = 0;
  a8 = LD32(a1 + 0x2c);  /* 012a */
  if (a10 == 1) goto L_0132;  /* 012c: beqi a10, 1, 132 <tx_task_main+0xf6> */
  L_012f: goto L_0234;  /* 012f: j */
  L_0132: a9 = 15;  /* 0132 */
  a10 = LD32(a1 + 0x20);  /* 0134 */
  if (a10 == a9) goto L_013c;  /* 0136: beq a10, a9, 13c <tx_task_main+0x100> */
  L_0139: goto L_0234;  /* 0139: j */
  L_013c: ST8(a4 + 0x0, a8);  /* 013c */
  __asm__ volatile("" ::: "memory");  /* 013f: memw */
  a2 = LD32(a5 + 0x0);  /* 0142 */
  if (a2 == 0) goto L_023c;  /* 0144: beqz a2, 23c <tx_task_main+0x200> */
  L_0147: a3 = LD32(a2 + 0x150);  /* 0147 */
  if (a3 == 0) goto L_023c;  /* 014a: beqz a3, 23c <tx_task_main+0x200> */
  L_014d: a10 = LD32(a2 + 0x158);  /* 014d */
  __asm__ volatile("" ::: "memory");  /* 0150: memw */
  /* 0153: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0156 */
  a10 = 2;  /* 0158 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 015a: -> "mesh" */
  a14 = a11;  /* 015d */
  a2 = 0x00000846u;  /* 015f: l32r = 2118 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 0162: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_tx_task_main_str1_1 + 0x0);  /* 0165: l32r -> .rodata.tx_task_main.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0168 */
  __asm__ volatile("" ::: "memory");  /* 016a: memw */
  /* 016d: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_023c;  /* 0170: j */
  L_0176: a10 = LD32(a1 + 0x20);  /* 0176 */
  a8 = 0;  /* 0178 */
  a9 = a10 + (-5);  /* 017a */
  ST32(a1 + 0x10, a8);  /* 017d */
  a8 = a10 + a10;  /* 017f */
  if (a9 >= 4u) goto L_01e8;  /* 0181: bgeui a9, 4, 1e8 <tx_task_main+0x1ac> */
  L_0184: a8 = a8 + a10;  /* 0184 */
  a8 = a8 + (a2 << 2);  /* 0186 */
  a9 = (u32)(RODATA__rodata___func___10 + 0x0);  /* 0189: l32r -> .rodata.__func__$10 */
  a11 = a9;  /* 018c */
  a10 = LD32(a8 + 0x4);  /* 018e */
  a12 = 0x0000085fu;  /* 0190: l32r = 2143 */
  ST32(a1 + 0x2c, a9);  /* 0193 */
  __asm__ volatile("" ::: "memory");  /* 0195: memw */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 0198: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4);  /* 019b: callx a8 via reloc-expand */
  a12 = -1;  /* 019e */
  a11 = a1 + (16);  /* 01a0 */
  a8 = LD32(a1 + 0x20);  /* 01a3 */
  a8 = a8 + (a8 << 1);  /* 01a5 */
  a8 = a8 + (a2 << 2);  /* 01a8 */
  a10 = LD32(a5 + 0x0);  /* 01ab */
  a13 = LD32(a10 + 0x74);  /* 01ad */
  a10 = LD32(a8 + 0x0);  /* 01b0 */
  /* 01b3: INDIRECT callx a13 <- mem[a10+0x74]; result unknown */ a2 = 0;
  a8 = LD32(a1 + 0x20);  /* 01b6 */
  a8 = a8 + (a8 << 1);  /* 01b8 */
  a8 = a8 + (a2 << 2);  /* 01bb */
  a9 = LD32(a1 + 0x2c);  /* 01be */
  if (a10 == 1) goto L_01d4;  /* 01c0: beqi a10, 1, 1d4 <tx_task_main+0x198> */
  L_01c3: a11 = a9;  /* 01c3 */
  a12 = 0x00000861u;  /* 01c5: l32r = 2145 */
  a10 = LD32(a8 + 0x4);  /* 01c8 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 01ca: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4);  /* 01cd: callx a8 via reloc-expand */
  goto L_00a4;  /* 01d0: j */
  L_01d4: a10 = LD32(a8 + 0x4);  /* 01d4 */
  a12 = 0x219;  /* 01d6 */
  a12 = a12 << 2;  /* 01d9 */
  a11 = a9;  /* 01dc */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 01de: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4);  /* 01e1: callx a8 via reloc-expand */
  goto L_0202;  /* 01e4: j */
  L_01e8: a8 = a8 + a10;  /* 01e8 */
  a9 = LD32(a5 + 0x0);  /* 01ea */
  a8 = a8 + (a2 << 2);  /* 01ec */
  a12 = -1;  /* 01ef */
  a11 = a1 + (16);  /* 01f1 */
  a9 = LD32(a9 + 0x74);  /* 01f4 */
  a10 = LD32(a8 + 0x0);  /* 01f7 */
  /* 01f9: INDIRECT callx a9 <- mem[a9+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_0202;  /* 01fc: beqi a10, 1, 202 <tx_task_main+0x1c6> */
  L_01ff: goto L_00a4;  /* 01ff: j */
  L_0202: a6 = a6 + (1);  /* 0202 */
  a12 = LD32(a1 + 0x10);  /* 0204 */
  a15 = a3;  /* 0206 */
  a13 = a6;  /* 0208 */
  a11 = LD32(a1 + 0x20);  /* 020a */
  a9 = (a11 >> 5) & 0x1;  /* 020c: extui width 1 */
  a9 = a9 << 9;  /* 020f */
  a8 = LD32(a12 + 0x28);  /* 0212 */
  a10 = 0xffffc1ffu;  /* 0214: l32r = -15873 */
  a8 = a8 & a10;  /* 0217 */
  a8 = a8 | a9;  /* 021a */
  a10 = 0;  /* 021d */
  ST32(a12 + 0x28, a8);  /* 021f */
  a14 = LD32(a1 + 0x28);  /* 0221 */
  __asm__ volatile("" ::: "memory");  /* 0224: memw */
  a8 = (u32)&mesh_ps_tx;  /* 0227: l32r -> func addr */
  a2 = mesh_ps_tx(a2, a3, a4);  /* 022a: callx a8 via reloc-expand */
  if (a10 != 0) goto L_023c;  /* 022d: bnez.n a10, 23c <tx_task_main+0x200> */
  L_022f: a8 = LD8U(a3 + 0x0);  /* 022f */
  if (a8 != 0) goto L_023c;  /* 0232: bnez.n a8, 23c <tx_task_main+0x200> */
  L_0234: ST32(a1 + 0x20, a7);  /* 0234 */
  __asm__ volatile("" ::: "memory");  /* 0236: memw */
  goto L_00a4;  /* 0239: j */
  L_023c: a2 = LD32(a1 + 0x10);  /* 023c */
  return a2;  /* 023e: retw.n */
}


/* xon_task_main @ mesh_schedule.o 00000040 size 372B bind GLOBAL
 * Calls: mesh_xon_flush_packets, esp_mesh_tx_tid_flush, mesh_ps_tx | indirect[8]: mem[a6+0x78]; mem[a8+0x78]; mem[a8+0x74]; mem[a2+0x158] | Data refs: .bss.mesh_tx_task, g_osi_funcs_p, .bss.mesh_tx_mbox, .rodata.mesh_print_txQ_waiting.str1.1, .rodata.mesh_get_tx_pending.str1.1, .rodata.xon_task_main.str1.1, g_log_level, g_mesh_is_root, .rodata.mesh_xon_process_disconnected.str1.1
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=12); reloc-direct=3, funcdb-attributed=0, unknown-indirect=8 */
u32 xon_task_main(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F1, F7;
  /* 0040: entry a1, 80 (frame 80 bytes) */
  a5 = (u32)&LOCAL__bss_mesh_tx_task + 0x0;  /* 0043: l32r -> .bss.mesh_tx_task (same-object static) */
  a5 = LD32(a5 + 0x18);  /* 0046 */
  ST32(a1 + 0x24, a5);  /* 0048 */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 004a: l32r -> global */
  a8 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 004d: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a6 = LD32(a5 + 0x0);  /* 0050 */
  ST32(a1 + 0x20, a2);  /* 0052 */
  a2 = 0;  /* 0054 */
  a6 = LD32(a6 + 0x78);  /* 0056 */
  a10 = LD32(a8 + 0x0);  /* 0059 */
  ST32(a1 + 0x10, a2);  /* 005b */
  __asm__ volatile("" ::: "memory");  /* 005e: memw */
  /* 0061: INDIRECT callx a6 <- mem[a6+0x78]; result unknown */ a2 = 0;
  a7 = a10;  /* 0064 */
  a6 = 14;  /* 0066 */
  goto L_006e;  /* 0068: j */
  L_006c: ST32(a1 + 0x20, a6);  /* 006c */
  L_006e: a9 = LD32(a1 + 0x20);  /* 006e */
  a8 = LD32(a5 + 0x0);  /* 0070 */
  if (a9 == a6) goto L_0078;  /* 0072: beq a9, a6, 78 <xon_task_main+0x38> */
  L_0075: goto L_0158;  /* 0075: j */
  L_0078: a9 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0078: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a8 = LD32(a8 + 0x78);  /* 007b */
  a10 = LD32(a9 + 0x0);  /* 007e */
  __asm__ volatile("" ::: "memory");  /* 0080: memw */
  /* 0083: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a9 = a10;  /* 0086 */
  if (a10 == 0) goto L_0094;  /* 0088: beqz.n a10, 94 <xon_task_main+0x54> */
  L_008a: a8 = 0;  /* 008a */
  ST32(a1 + 0x20, a8);  /* 008c */
  __asm__ volatile("" ::: "memory");  /* 008e: memw */
  goto L_0158;  /* 0091: j */
  L_0094: a8 = LD32(a5 + 0x0);  /* 0094 */
  a12 = -1;  /* 0096 */
  a11 = a1 + (32);  /* 0098 */
  a8 = LD32(a8 + 0x74);  /* 009b */
  a10 = LD32(a1 + 0x24);  /* 009e */
  ST32(a1 + 0x28, a9);  /* 00a0 */
  ST32(a1 + 0x20, a6);  /* 00a2 */
  __asm__ volatile("" ::: "memory");  /* 00a4: memw */
  /* 00a7: INDIRECT callx a8 <- mem[a8+0x74]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x28);  /* 00aa */
  if (a10 != 1) goto L_006c;  /* 00ac: bnei a10, 1, 6c <xon_task_main+0x2c> */
  L_00af: a10 = 15;  /* 00af */
  a8 = LD32(a1 + 0x20);  /* 00b1 */
  if (a8 != a10) goto L_00f1;  /* 00b4: bne a8, a10, f1 <xon_task_main+0xb1> */
  L_00b7: ST8(a4 + 0x0, a9);  /* 00b7 */
  __asm__ volatile("" ::: "memory");  /* 00ba: memw */
  a2 = LD32(a5 + 0x0);  /* 00bd */
  if (a2 == 0) goto L_01b0;  /* 00c0: beqz a2, 1b0 <xon_task_main+0x170> */
  L_00c3: a3 = LD32(a2 + 0x150);  /* 00c3 */
  if (a3 == 0) goto L_01b0;  /* 00c6: beqz a3, 1b0 <xon_task_main+0x170> */
  L_00c9: a10 = LD32(a2 + 0x158);  /* 00c9 */
  __asm__ volatile("" ::: "memory");  /* 00cc: memw */
  /* 00cf: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00d2 */
  a10 = 2;  /* 00d4 */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 00d6: -> "mesh" */
  a14 = a11;  /* 00d9 */
  a2 = 0x00000abfu;  /* 00db: l32r = 2751 */
  a15 = (u32)(RODATA__rodata_mesh_get_tx_pending_str1_1 + 0x0);  /* 00de: -> "mesh_schedule.c" */
  a12 = (u32)(RODATA__rodata_xon_task_main_str1_1 + 0x0);  /* 00e1: l32r -> .rodata.xon_task_main.str1.1 */
  ST32(a1 + 0x0, a2);  /* 00e4 */
  __asm__ volatile("" ::: "memory");  /* 00e6: memw */
  /* 00e9: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_01b0;  /* 00ec: j */
  L_00f1: if (a8 == 16) goto L_00f7;  /* 00f1: beqi a8, 16, f7 <xon_task_main+0xb7> */
  L_00f4: goto L_006c;  /* 00f4: j */
  L_00f7: a8 = (u32)&g_log_level + 0x0;  /* 00f7: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 00fa */
  if (a8 < 3u) goto L_0139;  /* 00fc: bltui a8, 3, 139 <xon_task_main+0xf9> */
  L_00ff: a8 = LD32(a5 + 0x0);  /* 00ff */
  if (a8 == 0) goto L_0139;  /* 0102: beqz.n a8, 139 <xon_task_main+0xf9> */
  L_0104: a9 = LD32(a8 + 0x150);  /* 0104 */
  if (a9 == 0) goto L_0139;  /* 0107: beqz.n a9, 139 <xon_task_main+0xf9> */
  L_0109: a10 = LD32(a8 + 0x158);  /* 0109 */
  ST32(a1 + 0x28, a9);  /* 010c */
  __asm__ volatile("" ::: "memory");  /* 010e: memw */
  /* 0111: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = (u32)&g_mesh_is_root + 0x0;  /* 0114: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0117: memw */
  a8 = LD8U(a8 + 0x0);  /* 011a */
  a8 = (a8 >> 8) & 0x1;  /* 011d: extui width 1 */
  a15 = (u32)(RODATA__rodata_mesh_xon_process_disconnected_str1_1 + 0x0);  /* 0120: -> "root" */
  a9 = LD32(a1 + 0x28);  /* 0123 */
  if (a8 != 0) goto L_012a;  /* 0125: bnez.n a8, 12a <xon_task_main+0xea> */
  L_0127: a15 = (u32)(RODATA__rodata_mesh_xon_process_disconnected_str1_1 + 0x0);  /* 0127: -> "root" */
  L_012a: a13 = a10;  /* 012a */
  a10 = 3;  /* 012c */
  a11 = (u32)(RODATA__rodata_mesh_print_txQ_waiting_str1_1 + 0x0);  /* 012e: -> "mesh" */
  a14 = a11;  /* 0131 */
  a12 = (u32)(RODATA__rodata_xon_task_main_str1_1 + 0x0);  /* 0133: l32r -> .rodata.xon_task_main.str1.1 */
  /* 0136: INDIRECT callx a9 <- mem[a1+0x28]; result unknown */ a2 = 0;
  L_0139: a8 = (u32)&mesh_xon_flush_packets;  /* 0139: l32r -> func addr */
  a2 = mesh_xon_flush_packets(a2, a3, a4, a5, a6, a7);  /* 013c: callx a8 via reloc-expand */
  a8 = (u32)&g_mesh_is_root + 0x0;  /* 013f: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0142: memw */
  a8 = LD8U(a8 + 0x0);  /* 0145 */
  a8 = (a8 >> 8) & 0x1;  /* 0148: extui width 1 */
  if (a8 == 0) goto L_006c;  /* 014b: beqz a8, 6c <xon_task_main+0x2c> */
  L_014e: a8 = (u32)&esp_mesh_tx_tid_flush;  /* 014e: l32r -> func addr */
  a2 = esp_mesh_tx_tid_flush(a2, a3, a4, a5, a6, a7);  /* 0151: callx a8 via reloc-expand */
  goto L_006c;  /* 0154: j */
  L_0158: a8 = 0;  /* 0158 */
  ST32(a1 + 0x10, a8);  /* 015a */
  a12 = -1;  /* 015c */
  a11 = a1 + (16);  /* 015e */
  a8 = LD32(a1 + 0x20);  /* 0161 */
  a8 = a8 + (a8 << 1);  /* 0163 */
  a9 = (u32)&LOCAL__bss_mesh_tx_mbox + 0x0;  /* 0166: l32r -> .bss.mesh_tx_mbox (same-object static) */
  a8 = a8 + (a9 << 2);  /* 0169 */
  a9 = LD32(a5 + 0x0);  /* 016c */
  a10 = LD32(a8 + 0x0);  /* 016e */
  a9 = LD32(a9 + 0x74);  /* 0170 */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  /* 0176: INDIRECT callx a9 <- mem[a9+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_017f;  /* 0179: beqi a10, 1, 17f <xon_task_main+0x13f> */
  L_017c: goto L_006c;  /* 017c: j */
  L_017f: a2 = a2 + (1);  /* 017f */
  a12 = LD32(a1 + 0x10);  /* 0181 */
  a15 = a3;  /* 0183 */
  a14 = a7;  /* 0185 */
  a11 = LD32(a1 + 0x20);  /* 0187 */
  a9 = (a11 >> 5) & 0x1;  /* 0189: extui width 1 */
  a9 = a9 << 9;  /* 018c */
  a8 = LD32(a12 + 0x28);  /* 018f */
  a13 = 0xffffc1ffu;  /* 0191: l32r = -15873 */
  a8 = a8 & a13;  /* 0194 */
  a8 = a8 | a9;  /* 0197 */
  a13 = a2;  /* 019a */
  ST32(a12 + 0x28, a8);  /* 019c */
  __asm__ volatile("" ::: "memory");  /* 019f: memw */
  a8 = (u32)&mesh_ps_tx;  /* 01a2: l32r -> func addr */
  a2 = mesh_ps_tx(a2, a3, a4, a5, a6, a7);  /* 01a5: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01b0;  /* 01a8: bnez.n a10, 1b0 <xon_task_main+0x170> */
  L_01aa: a8 = LD8U(a3 + 0x0);  /* 01aa */
  if (a8 == 0) goto L_006c;  /* 01ad: beqz a8, 6c <xon_task_main+0x2c> */
  L_01b0: a2 = LD32(a1 + 0x10);  /* 01b0 */
  return a2;  /* 01b2: retw.n */
}

