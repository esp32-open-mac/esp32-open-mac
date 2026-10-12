/* libmesh.a mesh.o --- reconstructed C (offline).
 * Role: public esp_mesh_* API: init/start/stop, send/recv, config, groups, PS control.
 * Object file: 143936 bytes on disk; 103/103 functions reconstructed, ~20123 code bytes.
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
extern u32 WIFI_EVENT; /* undefined data (reloc-referenced) */
extern u32 WIFI_MESH_EVENT; /* undefined data (reloc-referenced) */
extern u32 g_is_mesh_started; /* undefined data (reloc-referenced) */
extern u32 g_is_root_fixed; /* undefined data (reloc-referenced) */
extern u32 g_is_standalone_sta; /* undefined data (reloc-referenced) */
extern u32 g_is_wifi_connected; /* undefined data (reloc-referenced) */
extern u32 g_is_wifi_connecting; /* undefined data (reloc-referenced) */
extern u32 g_is_wifi_disconnecting; /* undefined data (reloc-referenced) */
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ann_interval; /* undefined data (reloc-referenced) */
extern u32 g_mesh_cfg_attemps; /* undefined data (reloc-referenced) */
extern u32 g_mesh_cfg_switch_parent; /* undefined data (reloc-referenced) */
extern u32 g_mesh_cfg_vote_percent; /* undefined data (reloc-referenced) */
extern u32 g_mesh_chain; /* undefined data (reloc-referenced) */
extern u32 g_mesh_current_parent; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ext_cfg; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ext_vote_state; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ie; /* undefined data (reloc-referenced) */
extern u32 g_mesh_init_ps_type; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_manual_nwk; /* undefined data (reloc-referenced) */
extern u32 g_mesh_max_layer; /* undefined data (reloc-referenced) */
extern u32 g_mesh_monitor_parent_beacon_count; /* undefined data (reloc-referenced) */
extern u32 g_mesh_passive_scan_time; /* undefined data (reloc-referenced) */
extern u32 g_mesh_root_healing_delay; /* undefined data (reloc-referenced) */
extern u32 g_mesh_rt_capacity; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_map_addr; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_organized; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_sta_addr; /* undefined data (reloc-referenced) */
extern u32 g_mesh_stop_event_group; /* undefined data (reloc-referenced) */
extern u32 g_mesh_stop_reconnection; /* undefined data (reloc-referenced) */
extern u32 g_mesh_topology; /* undefined data (reloc-referenced) */
extern u32 g_mesh_xon_cfg_qsize; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 mesh_ioctl_sem; /* undefined data (reloc-referenced) */
extern u32 mesh_myself_mbox; /* undefined data (reloc-referenced) */
extern u32 mesh_tcpip_mbox; /* undefined data (reloc-referenced) */
extern u32 mesh_xmit_state_mbox; /* undefined data (reloc-referenced) */
extern u32 s_mesh_send_mutex; /* undefined data (reloc-referenced) */
extern u32 s_mesh_stop_mutex; /* undefined data (reloc-referenced) */
extern u32 wpa_crypto_funcs; /* undefined data (reloc-referenced) */
extern u32 chm_check_channel_is_valid(); /* undefined func (args unknown, returns u32) */
extern u32 esp_event_handler_register(); /* undefined func (args unknown, returns u32) */
extern u32 esp_event_handler_unregister(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_available_txupQ_num(); /* defined in another libmesh.a object */
extern u32 esp_mesh_channel_enable_jp(); /* defined in another libmesh.a object */
extern u32 esp_mesh_create_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_create_mbox(); /* defined in another libmesh.a object */
extern u32 esp_mesh_delivery_toSelf(); /* defined in another libmesh.a object */
extern u32 esp_mesh_discard_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_forward_packet(); /* defined in another libmesh.a object */
extern u32 esp_mesh_free_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_free_mbox(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_beacon_interval(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_router_bssid(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_get_storage(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_is_nwk_inited(); /* defined in another libmesh.a object */
extern u32 esp_mesh_is_nwk_running(); /* defined in another libmesh.a object */
extern u32 esp_mesh_map_deauth(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_match_self(); /* defined in another libmesh.a object */
extern u32 esp_mesh_nvs_deinit(); /* defined in another libmesh.a object */
extern u32 esp_mesh_nvs_init(); /* defined in another libmesh.a object */
extern u32 esp_mesh_nwk_task_deinit(); /* defined in another libmesh.a object */
extern u32 esp_mesh_nwk_task_init(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_nwk_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_tx_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_route_deinit(); /* defined in another libmesh.a object */
extern u32 esp_mesh_route_init(); /* defined in another libmesh.a object */
extern u32 esp_mesh_rx_task_deinit(); /* defined in another libmesh.a object */
extern u32 esp_mesh_rx_task_init(); /* defined in another libmesh.a object */
extern u32 esp_mesh_send_block_deinit(); /* defined in another libmesh.a object */
extern u32 esp_mesh_send_block_init(); /* defined in another libmesh.a object */
extern u32 esp_mesh_send_event_internal(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_set_beacon_interval(); /* defined in another libmesh.a object */
extern u32 esp_mesh_set_ie_crypto_funcs_internal(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_set_ie_crypto_key_internal(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_set_router_bssid(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_sta_disassoc(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_tx_task_deinit(); /* defined in another libmesh.a object */
extern u32 esp_mesh_tx_task_init(); /* defined in another libmesh.a object */
extern u32 esp_mesh_txupQ_pending(); /* defined in another libmesh.a object */
extern u32 esp_wifi_disconnect(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_config(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_mac(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_mode(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_ps(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_config(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_mode(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_non_mesh_connections(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_ps(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_vnd_mesh_deinit(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_vnd_mesh_get(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_vnd_mesh_init(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_vnd_mesh_set(); /* undefined func (args unknown, returns u32) */
extern u32 is_my_ie_encrypted(); /* defined in another libmesh.a object */
extern u32 mesh_free(); /* defined in another libmesh.a object */
extern u32 mesh_get_subnet_nodes_list(); /* defined in another libmesh.a object */
extern u32 mesh_get_subnet_nodes_num(); /* defined in another libmesh.a object */
extern u32 mesh_ie_type2str(); /* defined in another libmesh.a object */
extern u32 mesh_look_for_network(); /* defined in another libmesh.a object */
extern u32 mesh_malloc(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_lock(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_unlock(); /* defined in another libmesh.a object */
extern u32 mesh_nwk_manual_networking(); /* defined in another libmesh.a object */
extern u32 mesh_ps_get_duties(); /* defined in another libmesh.a object */
extern u32 mesh_set_default_rssi_threshold(); /* defined in another libmesh.a object */
extern u32 mesh_set_io_process(); /* defined in another libmesh.a object */
extern u32 mesh_set_router(); /* defined in another libmesh.a object */
extern u32 mesh_set_self_organized(); /* defined in another libmesh.a object */
extern u32 mesh_set_type(); /* defined in another libmesh.a object */
extern u32 mesh_switch_channel(); /* defined in another libmesh.a object */
extern u32 pm_is_waked(); /* undefined func (args unknown, returns u32) */
extern u32 print_txupQ_pending(); /* defined in another libmesh.a object */
extern u32 snprintf(); /* undefined func (args unknown, returns u32) */
extern u32 sprintf(); /* undefined func (args unknown, returns u32) */
extern u32 tx_state_id2str(); /* defined in another libmesh.a object */
static const u8 RODATA__rodata___func___0[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x61, 0x64 }; /* .rodata.__func__$0 (24 bytes) */
static const u8 RODATA__rodata___func___1[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x69, 0x6e, 0x73, 0x65, 0x72, 0x74, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x61, 0x64 }; /* .rodata.__func__$1 (24 bytes) */
static const u8 RODATA__rodata___func___12[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x74, 0x6f }; /* .rodata.__func__$12 (12 bytes) */
static const u8 RODATA__rodata___func___13[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x74, 0x6f, 0x70, 0x5f, 0x72, 0x65 }; /* .rodata.__func__$13 (12 bytes) */
static const u8 RODATA__rodata___func___2[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x6e, 0x64, 0x5f, 0x73, 0x74, 0x6f, 0x70, 0x5f, 0x76, 0x6f, 0x74, 0x65, 0x00 }; /* .rodata.__func__$2 (20 bytes) strings: [0x0]="mesh_send_stop_vote" */
static const u8 RODATA__rodata___func___3[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x5f, 0x74, 0x63, 0x70, 0x69, 0x70, 0x5f, 0x71, 0x75, 0x65 }; /* .rodata.__func__$3 (24 bytes) */
static const u8 RODATA__rodata___func___4[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x75, 0x73, 0x68, 0x5f, 0x74, 0x6f, 0x5f, 0x74, 0x63, 0x70, 0x69, 0x70, 0x5f, 0x71, 0x75, 0x65, 0x75, 0x65 }; /* .rodata.__func__$4 (28 bytes) */
static const u8 RODATA__rodata___func___5[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x70, 0x75, 0x73, 0x68, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x79, 0x73, 0x65, 0x6c, 0x66, 0x5f, 0x71, 0x75, 0x65, 0x75 }; /* .rodata.__func__$5 (28 bytes) */
static const u8 RODATA__rodata___func___6[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x00 }; /* .rodata.__func__$6 (20 bytes) strings: [0x0]="esp_mesh_set_config" */
static const u8 RODATA__rodata___func___7[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x65, 0x63 }; /* .rodata.__func__$7 (8 bytes) */
static const u8 RODATA__rodata___func___8[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x6e }; /* .rodata.__func__$8 (12 bytes) */
static const u8 RODATA__rodata___func___9[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x6e, 0x64, 0x5f, 0x6d, 0x67 }; /* .rodata.__func__$9 (16 bytes) */
static const u8 RODATA__rodata_esp_mesh_get_rx_pending_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x0a, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x63, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73, 0x0a, 0x00 }; /* .rodata.esp_mesh_get_rx_pending.str1.1 (72 bytes) strings: [0x0]="mesh"; [0x25]="mesh.c" */
static const u8 RODATA__rodata_esp_mesh_print_rxQ_waiting_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x52, 0x58, 0x51, 0x5d, 0x3c, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x20, 0x3d, 0x20, 0x63, 0x66, 0x67, 0x3a, 0x25, 0x64, 0x20, 0x2b, 0x20, 0x65, 0x78, 0x74, 0x72, 0x61, 0x3a, 0x25, 0x64, 0x3e, 0x73, 0x65, 0x6c, 0x66, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x3c, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x20, 0x3d, 0x20, 0x63, 0x66, 0x67, 0x3a, 0x25, 0x64, 0x20, 0x2b, 0x20, 0x65, 0x78, 0x74, 0x72, 0x61, 0x3a, 0x25, 0x64, 0x3e, 0x74, 0x6f, 0x64, 0x73, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x52, 0x58, 0x51, 0x5d, 0x3c, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x2c, 0x63, 0x66, 0x67, 0x3a, 0x25, 0x64, 0x2b, 0x65, 0x78, 0x74, 0x72, 0x61, 0x3a, 0x25, 0x64, 0x3e, 0x53, 0x45, 0x4c, 0x46, 0x3a, 0x25 }; /* .rodata.esp_mesh_print_rxQ_waiting.str1.1 (136 bytes) */
static const u8 RODATA__rodata_esp_mesh_push_to_tcpip_queue_str1_1[] = { 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x71, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x5b, 0x6d, 0x61, 0x78, 0x2f, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x5d, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x54, 0x41, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x64, 0x65, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x51, 0x3a, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x70, 0x61, 0x6e, 0x64, 0x6f, 0x72, 0x61, 0x0a, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x71, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x5b, 0x6d, 0x61, 0x78, 0x2f, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x2f, 0x25, 0x64, 0x5d, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x54, 0x41, 0x5d, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x5b, 0x64, 0x65, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x51, 0x3a, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x0a, 0x00 }; /* .rodata.esp_mesh_push_to_tcpip_queue.str1.1 (344 bytes) */
static const u8 RODATA__rodata_esp_mesh_recv_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x69, 0x6e, 0x69, 0x74, 0x65 }; /* .rodata.esp_mesh_recv.str1.1 (28 bytes) */
static const u8 RODATA__rodata_esp_mesh_send[] = { 0xb2, 0x06, 0x00, 0x00, 0xd8, 0x05, 0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x33, 0x06, 0x00, 0x00, 0xd2, 0x05, 0x00, 0x00, 0x5b, 0x06, 0x00, 0x00, 0xb2, 0x06, 0x00, 0x00, 0x85, 0x06, 0x00, 0x00, 0x85, 0x06, 0x00, 0x00, 0x85, 0x06, 0x00, 0x00, 0xb2, 0x06, 0x00, 0x00, 0xb2, 0x06, 0x00, 0x00, 0xb2, 0x06, 0x00, 0x00, 0xb2, 0x06, 0x00, 0x00, 0xb2, 0x06, 0x00, 0x00, 0xb2, 0x06, 0x00, 0x00, 0xb2, 0x06, 0x00, 0x00 }; /* .rodata.esp_mesh_send (68 bytes) */
static const u8 RODATA__rodata_esp_mesh_send_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x74, 0x78, 0x2d, 0x77, 0x69, 0x66, 0x69, 0x5d, 0x74, 0x78, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x25, 0x73, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x74, 0x78, 0x2d, 0x77, 0x69, 0x66, 0x69, 0x5d, 0x74, 0x78, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x74, 0x78, 0x2d, 0x77, 0x69, 0x66, 0x69, 0x5d, 0x74, 0x78, 0x20, 0x70, 0x6f, 0x73, 0x74, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x74, 0x78, 0x2d, 0x77, 0x69, 0x66, 0x69, 0x5d, 0x74, 0x78, 0x20, 0x71, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x74, 0x78, 0x2d, 0x77, 0x69, 0x66, 0x69, 0x5d, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x74, 0x78, 0x2d, 0x77, 0x69, 0x66, 0x69, 0x5d, 0x74, 0x78, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00 }; /* .rodata.esp_mesh_send.str1.1 (212 bytes) */
static const u8 RODATA__rodata_esp_mesh_set_ap_connections_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x6d, 0x61, 0x78, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25 }; /* .rodata.esp_mesh_set_ap_connections.str1.1 (40 bytes) */
static const u8 RODATA__rodata_esp_mesh_set_ap_password_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x79, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6d, 0x6f, 0x64, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x73, 0x6f, 0x66, 0x74, 0x41, 0x50, 0x20, 0x6d, 0x6f, 0x64 }; /* .rodata.esp_mesh_set_ap_password.str1.1 (60 bytes) */
static const u8 RODATA__rodata_esp_mesh_set_config_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x73, 0x65, 0x74, 0x28, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x61, 0x78, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x73, 0x65, 0x74, 0x28, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x6e, 0x6f, 0x6e, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x61, 0x78, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x73, 0x65, 0x74, 0x28, 0x6d, 0x61, 0x78, 0x3a, 0x25, 0x64, 0x29, 0x2c, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x61, 0x78, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6e, 0x6f, 0x6e, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x61, 0x78, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x45, 0x53, 0x50, 0x4d, 0x5f, 0x25, 0x30, 0x32, 0x58, 0x25, 0x30, 0x32, 0x58, 0x25, 0x30 }; /* .rodata.esp_mesh_set_config.str1.1 (244 bytes) */
static const u8 RODATA__rodata_esp_mesh_set_ie_crypto_funcs_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x49, 0x45, 0x20, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x20, 0x66, 0x75, 0x6e, 0x63, 0x73, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78 }; /* .rodata.esp_mesh_set_ie_crypto_funcs.str1.1 (56 bytes) */
static const u8 RODATA__rodata_esp_mesh_set_ie_crypto_key_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x49, 0x45, 0x20, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x20, 0x6b, 0x65, 0x79, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00 }; /* .rodata.esp_mesh_set_ie_crypto_key.str1.1 (56 bytes) */
static const u8 RODATA__rodata_esp_mesh_set_non_mesh_connections_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x6e, 0x6f, 0x6e, 0x2d, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x6d, 0x61, 0x78, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25 }; /* .rodata.esp_mesh_set_non_mesh_connections.str1.1 (44 bytes) */
static const u8 RODATA__rodata_esp_mesh_set_parent_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65 }; /* .rodata.esp_mesh_set_parent.str1.1 (32 bytes) */
static const u8 RODATA__rodata_esp_mesh_stop_str1_1[] = { 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x20, 0x73, 0x74, 0x6f, 0x70, 0x20, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x69, 0x73, 0x20, 0x64, 0x65, 0x69, 0x6e, 0x69, 0x74, 0x65, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x20, 0x69, 0x65, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x72, 0x78, 0x20, 0x74, 0x61, 0x73, 0x6b, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x74, 0x78, 0x20, 0x74, 0x61, 0x73, 0x6b, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x6e, 0x77, 0x6b, 0x20, 0x74, 0x61, 0x73, 0x6b, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x66, 0x72, 0x65, 0x65, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6d, 0x79, 0x73, 0x65, 0x6c, 0x66, 0x5f, 0x6d, 0x62, 0x6f, 0x78, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x66, 0x72, 0x65, 0x65, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x63, 0x70, 0x69, 0x70, 0x5f, 0x6d, 0x62, 0x6f, 0x78, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x73, 0x74, 0x6f, 0x70, 0x3e, 0x69, 0x73, 0x5f, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x69, 0x6e, 0x67, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x64, 0x6f, 0x6e, 0x65, 0x3e, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x42, 0x49, 0x54, 0x5f, 0x58, 0x4d, 0x49, 0x54, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, /* ... +104 bytes */ }; /* .rodata.esp_mesh_stop.str1.1 (616 bytes) strings: [0x246]="ESP_%02X%02X%02X" */
static const u8 RODATA__rodata_esp_mesh_switch_channel_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x63, 0x73, 0x61, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x25, 0x64, 0x0a }; /* .rodata.esp_mesh_switch_channel.str1.1 (32 bytes) */
static const u8 RODATA__rodata_mesh_encrypt_ie_plain_key_str1_1[] = { 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32 }; /* .rodata.mesh_encrypt_ie_plain_key.str1.1 (28 bytes) */
static const u8 RODATA__rodata_mesh_parse_option[] = { 0xc3, 0x00, 0x00, 0x00, 0xcf, 0x00, 0x00, 0x00, 0xdb, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00, 0xeb, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00 }; /* .rodata.mesh_parse_option (32 bytes) */
static const u8 RODATA__rodata_mesh_send_stop_vote_str1_1[] = { 0xff, 0xff, 0xff, 0xff }; /* .rodata.mesh_send_stop_vote.str1.1 (4 bytes) */
static const u8 RODATA__rodata_mesh_set_parent_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x73, 0x65, 0x74, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x2d, 0x3e, 0x73, 0x74, 0x61, 0x2e, 0x73, 0x73, 0x69, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x61, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x73, 0x65, 0x74, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6d, 0x6f, 0x64, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x73, 0x6f, 0x66, 0x74, 0x41, 0x50, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x6c, 0x65, 0x61, 0x66, 0x28, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x29, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x5f, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x25, 0x64, 0x28, 0x41, 0x50, 0x2b, 0x53, 0x54, 0x41, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x29, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x67, 0x65, 0x74, 0x20, 0x73, 0x6f, 0x66, 0x74, 0x41, 0x50, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00 }; /* .rodata.mesh_set_parent.str1.1 (440 bytes) */
static const u8 RODATA__rodata_mesh_stop_recv_str1_1[] = { 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x42, 0x49, 0x54, 0x5f, 0x54, 0x4f, 0x44, 0x53, 0x00, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x42, 0x49, 0x54, 0x5f, 0x53, 0x45, 0x4c, 0x46, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x64, 0x6f, 0x6e, 0x65, 0x3e, 0x25, 0x73, 0x0a, 0x00, 0x72, 0x65, 0x63, 0x76, 0x20, 0x74, 0x6f, 0x44, 0x53, 0x00, 0x72, 0x65, 0x63, 0x76, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x66, 0x72, 0x65, 0x65, 0x20, 0x63, 0x74, 0x78, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x25, 0x73, 0x20, 0x73, 0x74, 0x6f }; /* .rodata.mesh_stop_recv.str1.1 (156 bytes) strings: [0x0]="MESH_STOP_EVENT_BIT_TODS"; [0x19]="MESH_STOP_EVENT_BIT_SELF"; [0x4f]="recv toDS"; [0x59]="recv" */
static const u8 RODATA__rodata_mesh_wifi_event_init_str1_1[] = { 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x20, 0x77, 0x69, 0x66, 0x69, 0x20, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x28, 0x25, 0x78, 0x29, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x20, 0x77, 0x69, 0x66, 0x69, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x28, 0x25, 0x78, 0x29, 0x0a }; /* .rodata.mesh_wifi_event_init.str1.1 (112 bytes) */
static u8 LOCAL__bss_MESH_ZERO_ADDR[0x4]; /* stand-in for .bss.MESH_ZERO_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_g_is_mesh_inited[0x4]; /* stand-in for .bss.g_is_mesh_inited (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_xmit_sem[0x4]; /* stand-in for .bss.mesh_xmit_sem (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_option_10[0x4]; /* stand-in for .bss.option$10 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_extra_toDS_qsize[0x4]; /* stand-in for .bss.s_extra_toDS_qsize (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_extra_toSelf_qsize[0x4]; /* stand-in for .bss.s_extra_toSelf_qsize (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_ext_crypto_config[0x4]; /* stand-in for .bss.s_mesh_ext_crypto_config (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_group_addr[0x4]; /* stand-in for .bss.s_mesh_group_addr (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_value_11[0x4]; /* stand-in for .bss.value$11 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_MESH_BCAST_ADDR[0x4]; /* stand-in for .data.MESH_BCAST_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_s_mesh_ie_crypto_plain_key[0x4]; /* stand-in for .data.s_mesh_ie_crypto_plain_key (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_deinit @ mesh.o 00000008 size 24B bind GLOBAL
 * Calls: esp_mesh_stop | Data refs: .bss.g_is_mesh_inited
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 000b: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a10 = 0;  /* 000e */
  a8 = LD8U(a8 + 0x0);  /* 0010 */
  if (a8 == a10) goto L_001c;  /* 0013: beq a8, a10, 1c <esp_mesh_deinit+0x14> */
  L_0016: a8 = (u32)&esp_mesh_stop;  /* 0016: l32r -> func addr */
  a2 = esp_mesh_stop(a2, a3, a4, a5, a6, a7);  /* 0019: callx a8 via reloc-expand */
  L_001c: a2 = a10;  /* 001c */
  return a2;  /* 001e: retw.n */
}


/* esp_mesh_delete_group_addr @ mesh.o 00000050 size 356B bind GLOBAL
 * Calls: memcmp, memset, mesh_malloc, memcpy, mesh_free | indirect[4]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.__func__$0, .bss.MESH_ZERO_ADDR, .rodata.esp_mesh_push_to_tcpip_queue.str1.1
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=11); reloc-direct=5, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_delete_group_addr(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a81;
  /* 0050: entry a1, 64 (frame 64 bytes) */
  a4 = a2;  /* 0053 */
  if (a2 != 0) goto L_0082;  /* 0055: bnez.n a2, 82 <esp_mesh_delete_group_addr+0x32> */
  L_0057: a2 = (u32)&g_log_level + 0x0;  /* 0057: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005a */
  a2 = 0x00004008u;  /* 005c: l32r = 16392 */
  if (a3 >= 3u) goto L_0065;  /* 005f: bgeui a3, 3, 65 <esp_mesh_delete_group_addr+0x15> */
  L_0062: goto L_01b2;  /* 0062: j */
  L_0065: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0065: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0068 */
  if (a3 == 0) goto L_01b2;  /* 006a: beqz a3, 1b2 <esp_mesh_delete_group_addr+0x162> */
  L_006d: a4 = LD32(a3 + 0x150);  /* 006d */
  if (a4 == 0) goto L_01b2;  /* 0070: beqz a4, 1b2 <esp_mesh_delete_group_addr+0x162> */
  L_0073: a10 = LD32(a3 + 0x158);  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0079: -> "mesh" */
  a3 = 0x00000a5au;  /* 007c: l32r = 2650 */
  goto L_00b6;  /* 007f: j */
  L_0082: if (a3 == 0) goto L_008d;  /* 0082: beqz.n a3, 8d <esp_mesh_delete_group_addr+0x3d> */
  L_0084: a7 = LD32(a2 + 0x0);  /* 0084 */
  a6 = 0;  /* 0086 */
  a8 = 6;  /* 0088 */
  goto L_0106;  /* 008a: j */
  L_008d: a2 = (u32)&g_log_level + 0x0;  /* 008d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0090 */
  a2 = 0x00004008u;  /* 0092: l32r = 16392 */
  if (a3 >= 3u) goto L_009b;  /* 0095: bgeui a3, 3, 9b <esp_mesh_delete_group_addr+0x4b> */
  L_0098: goto L_01b2;  /* 0098: j */
  L_009b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 009b: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 009e */
  if (a3 == 0) goto L_01b2;  /* 00a1: beqz a3, 1b2 <esp_mesh_delete_group_addr+0x162> */
  L_00a4: a4 = LD32(a3 + 0x150);  /* 00a4 */
  if (a4 == 0) goto L_01b2;  /* 00a7: beqz a4, 1b2 <esp_mesh_delete_group_addr+0x162> */
  L_00aa: a10 = LD32(a3 + 0x158);  /* 00aa */
  /* 00ad: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b0: -> "mesh" */
  a3 = 0x00000a5bu;  /* 00b3: l32r = 2651 */
  L_00b6: a13 = a10;  /* 00b6 */
  a14 = a11;  /* 00b8 */
  a10 = 3;  /* 00ba */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00bc: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00bf: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 00c2 */
  __asm__ volatile("" ::: "memory");  /* 00c4: memw */
  goto L_01ac;  /* 00c7: j */
  L_00ca: a2 = LD32(a4 + 0x4);  /* 00ca */
  a5 = a6 + (a6 << 1);  /* 00cc */
  a5 = a5 + (a2 << 1);  /* 00cf */
  a12 = a8;  /* 00d2 */
  a11 = a3;  /* 00d4 */
  a10 = a5;  /* 00d6: mov */
  ST32(a1 + 0x10, a8);  /* 00d9 */
  __asm__ volatile("" ::: "memory");  /* 00db: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00de: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00e1: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 00e4 */
  a8 = LD32(a1 + 0x10);  /* 00e6 */
  if (a10 != 0) goto L_0104;  /* 00e8: bnez.n a10, 104 <esp_mesh_delete_group_addr+0xb4> */
  L_00ea: a11 = a10;  /* 00ea */
  a12 = 6;  /* 00ec */
  a10 = a5;  /* 00ee */
  a8 = (u32)&memset + 0x0;  /* 00f0: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00f3: callx a8 (libc, via reloc-expand) */
  a10 = LD32(a4 + 0x0);  /* 00f6 */
  a6 = a2;  /* 00f8 */
  a7 = a2;  /* 00fa */
  if (a10 == 1) goto L_0165;  /* 00fc: beqi a10, 1, 165 <esp_mesh_delete_group_addr+0x115> */
  L_00ff: goto L_010e;  /* 00ff: j */
  L_0104: a6 = a6 + (1);  /* 0104 */
  L_0106: if ((i32)a6 < (i32)a7) goto L_00ca;  /* 0106: blt a6, a7, ca <esp_mesh_delete_group_addr+0x7a> */
  L_0109: a2 = 0;  /* 0109 */
  goto L_01b2;  /* 010b: j */
  L_010e: a10 = a10 + (-1);  /* 010e */
  a12 = 0x00000a6fu;  /* 0110: l32r = 2671 */
  a10 = a10 + (a10 << 1);  /* 0113 */
  a10 = a10 + a10;  /* 0116 */
  a3 = a2;  /* 0118: mov */
  a11 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 011b: l32r -> .rodata.__func__$0 */
  a8 = (u32)&mesh_malloc + 0x0;  /* 011e: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0121: callx a8 via reloc-expand */
  a7 = a10;  /* 0124 */
  a5 = a10;  /* 0126 */
  if (a10 != 0) goto L_015e;  /* 0128: bnez.n a10, 15e <esp_mesh_delete_group_addr+0x10e> */
  L_012a: a2 = 0x00004007u;  /* 012a: l32r = 16391 */
  goto L_01b2;  /* 012d: j */
  L_0130: a8 = a3 + (a3 << 1);  /* 0130 */
  a8 = a8 + (a10 << 1);  /* 0133 */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 0136: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a10 = a8;  /* 0139 */
  a12 = 6;  /* 013b */
  ST32(a1 + 0x10, a8);  /* 013d */
  __asm__ volatile("" ::: "memory");  /* 013f: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0142: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0145: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x10);  /* 0148 */
  if (a10 == 0) goto L_015c;  /* 014a: beqz.n a10, 15c <esp_mesh_delete_group_addr+0x10c> */
  L_014c: a10 = a5;  /* 014c */
  a12 = 6;  /* 014e */
  a11 = a8;  /* 0150 */
  a8 = (u32)&memcpy + 0x0;  /* 0152: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0155: callx a8 (libc, via reloc-expand) */
  a6 = a6 + (1);  /* 0158 */
  a5 = a5 + (6);  /* 015a */
  L_015c: a3 = a3 + (1);  /* 015c */
  L_015e: a8 = LD32(a4 + 0x0);  /* 015e */
  a10 = LD32(a4 + 0x4);  /* 0160 */
  if ((i32)a3 < (i32)a8) goto L_0130;  /* 0162: blt a3, a8, 130 <esp_mesh_delete_group_addr+0xe0> */
  L_0165: a12 = 0x53f;  /* 0165 */
  a12 = a12 + a12;  /* 0168 */
  a11 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 016a: l32r -> .rodata.__func__$0 */
  a10 = LD32(a4 + 0x4);  /* 016d */
  a8 = (u32)&mesh_free + 0x0;  /* 0170: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0173: callx a8 via reloc-expand */
  a3 = LD32(a4 + 0x0);  /* 0176 */
  a3 = a3 + (-1);  /* 0178 */
  ST32(a4 + 0x4, a7);  /* 017a */
  ST32(a4 + 0x0, a3);  /* 017c */
  if (a3 == a6) goto L_0109;  /* 017e: beq a3, a6, 109 <esp_mesh_delete_group_addr+0xb9> */
  L_0181: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0181: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0184 */
  if (a3 == 0) goto L_0109;  /* 0186: beqz a3, 109 <esp_mesh_delete_group_addr+0xb9> */
  L_0189: a4 = LD32(a3 + 0x150);  /* 0189 */
  if (a4 == 0) goto L_0109;  /* 018c: beqz a4, 109 <esp_mesh_delete_group_addr+0xb9> */
  L_018f: a10 = LD32(a3 + 0x158);  /* 018f */
  __asm__ volatile("" ::: "memory");  /* 0192: memw */
  /* 0195: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0198 */
  a10 = 1;  /* 019a */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 019c: -> "mesh" */
  a14 = a11;  /* 019f */
  a3 = 0x00000a81u;  /* 01a1: l32r = 2689 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 01a4: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_tcpip_queue_str1_1 + 0x0);  /* 01a7: l32r -> .rodata.esp_mesh_push_to_tcpip_queue.str1.1 */
  ST32(a1 + 0x0, a3);  /* 01aa */
  L_01ac: __asm__ volatile("" ::: "memory");  /* 01ac: memw */
  /* 01af: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  L_01b2: return a2;  /* 01b2: retw.n */
}


/* esp_mesh_delete_group_id @ mesh.o 00000008 size 52B bind GLOBAL
 * Calls: esp_mesh_delete_group_addr | Data refs: .bss.s_mesh_group_addr
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_delete_group_id(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a4 = 1;  /* 000b */
  a8 = 0;  /* 000d */
  if (a2 == 0) a8 = a4;  /* 000f */
  a9 = (a8 >> 8) & 0x1;  /* 0012: extui width 1 */
  if (a8 != 0) goto L_0038;  /* 0015: bnez.n a8, 38 <esp_mesh_delete_group_id+0x30> */
  L_0017: if (a3 != 0) a4 = a9;  /* 0017 */
  if (a4 != 0) goto L_0038;  /* 001a: bnez.n a4, 38 <esp_mesh_delete_group_id+0x30> */
  L_001c: goto L_0030;  /* 001c: j */
  L_0021: a10 = (u32)&LOCAL__bss_s_mesh_group_addr + 0x0;  /* 0021: l32r -> .bss.s_mesh_group_addr (same-object static) */
  a11 = a2;  /* 0024 */
  a8 = (u32)&esp_mesh_delete_group_addr;  /* 0026: l32r -> func addr */
  a2 = esp_mesh_delete_group_addr(a2, a3, a4, a5, a6, a7);  /* 0029: callx a8 via reloc-expand */
  a4 = a4 + (1);  /* 002c */
  a2 = a2 + (6);  /* 002e */
  L_0030: if ((i32)a4 < (i32)a3) goto L_0021;  /* 0030: blt a4, a3, 21 <esp_mesh_delete_group_id+0x19> */
  L_0033: a2 = 0;  /* 0033 */
  goto L_003a;  /* 0035: j */
  L_0038: a2 = -1;  /* 0038 */
  L_003a: return a2;  /* 003a: retw.n */
}


/* esp_mesh_disable_ps @ mesh.o 0000000c size 24B bind GLOBAL
 * Calls: esp_wifi_set_ps | Data refs: g_is_mesh_started
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_disable_ps(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 000f: l32r -> global */
  a10 = LD8U(a2 + 0x0);  /* 0012 */
  a2 = 0x00004006u;  /* 0015: l32r = 16390 */
  if (a10 != 0) goto L_0022;  /* 0018: bnez.n a10, 22 <esp_mesh_disable_ps+0x16> */
  L_001a: a8 = (u32)&esp_wifi_set_ps + 0x0;  /* 001a: l32r -> global */
  a2 = esp_wifi_set_ps(a2, a3, a4, a5, a6, a7);  /* 001d: callx a8 via reloc-expand */
  a2 = a10;  /* 0020 */
  L_0022: return a2;  /* 0022: retw.n */
}


/* esp_mesh_enable_ps @ mesh.o 0000000c size 26B bind GLOBAL
 * Calls: esp_wifi_set_ps | Data refs: g_is_mesh_started
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_enable_ps(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_is_mesh_started + 0x0;  /* 000f: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 0012 */
  a10 = 0x00004006u;  /* 0015: l32r = 16390 */
  if (a8 != 0) goto L_0022;  /* 0018: bnez.n a8, 22 <esp_mesh_enable_ps+0x16> */
  L_001a: a10 = 1;  /* 001a */
  a8 = (u32)&esp_wifi_set_ps + 0x0;  /* 001c: l32r -> global */
  a2 = esp_wifi_set_ps(a2, a3, a4, a5, a6, a7);  /* 001f: callx a8 via reloc-expand */
  L_0022: a2 = a10;  /* 0022 */
  return a2;  /* 0024: retw.n */
}


/* esp_mesh_fix_root @ mesh.o 0000000c size 56B bind GLOBAL
 * Calls: esp_mesh_is_nwk_inited, esp_mesh_push_to_nwk_queue | Data refs: g_is_root_fixed
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_fix_root(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8;
  /* 000c: entry a1, 224 (frame 224 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 000f: extui width 1 */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 0012: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 0015: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0034;  /* 0018: beqz.n a10, 34 <esp_mesh_fix_root+0x28> */
  L_001a: a8 = 38;  /* 001a */
  a11 = 0;  /* 001c */
  a10 = a1;  /* 001e */
  ST32(a1 + 0x0, a8);  /* 0020 */
  ST8(a1 + 0x4, a2);  /* 0022 */
  __asm__ volatile("" ::: "memory");  /* 0025: memw */
  __asm__ volatile("" ::: "memory");  /* 0028: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 002b: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 002e: callx a8 via reloc-expand */
  goto L_003d;  /* 0031: j */
  L_0034: a8 = (u32)&g_is_root_fixed + 0x0;  /* 0034: l32r -> global */
  ST8(a8 + 0x0, a2);  /* 0037 */
  __asm__ volatile("" ::: "memory");  /* 003a: memw */
  L_003d: a2 = 0;  /* 003d */
  __asm__ volatile("" ::: "memory");  /* 003f: memw */
  return a2;  /* 0042: retw.n */
}


/* esp_mesh_flush_tcpip_queue @ mesh.o 00000020 size 133B bind GLOBAL
 * Calls: esp_mesh_txupQ_pending, esp_mesh_discard_context | indirect[2]: mem[a4+0x74]; mem[a4+0x78] | Data refs: mesh_tcpip_mbox, g_osi_funcs_p, .rodata.__func__$3, .bss.s_extra_toDS_qsize
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=6); reloc-direct=2, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_flush_tcpip_queue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8, a9;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  a2 = 0;  /* 0023 */
  ST32(a1 + 0x0, a2);  /* 0025 */
  a2 = (u32)&mesh_tcpip_mbox + 0x0;  /* 0027: l32r -> global */
  a4 = LD32(a2 + 0x0);  /* 002a */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 002c: l32r -> global */
  if (a4 != 0) goto L_0094;  /* 002f: bnez a4, 94 <esp_mesh_flush_tcpip_queue+0x74> */
  L_0032: __asm__ volatile("" ::: "memory");  /* 0032: memw */
  goto L_00a1;  /* 0035: j */
  L_0039: a4 = LD32(a3 + 0x0);  /* 0039 */
  a12 = 0;  /* 003b */
  a11 = a1;  /* 003d */
  a4 = LD32(a4 + 0x74);  /* 003f */
  a10 = LD32(a2 + 0x0);  /* 0042 */
  ST32(a1 + 0x0, a12);  /* 0044 */
  __asm__ volatile("" ::: "memory");  /* 0046: memw */
  /* 0049: INDIRECT callx a4 <- mem[a4+0x74]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_0094;  /* 004c: bnei a10, 1, 94 <esp_mesh_flush_tcpip_queue+0x74> */
  L_004f: a10 = LD32(a1 + 0x0);  /* 004f */
  a4 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 0051: l32r -> .rodata.__func__$3 */
  if (a10 == 0) goto L_0081;  /* 0054: beqz.n a10, 81 <esp_mesh_flush_tcpip_queue+0x61> */
  L_0056: a8 = LD32(a10 + 0x0);  /* 0056 */
  if (a8 == 0) goto L_0081;  /* 0058: beqz.n a8, 81 <esp_mesh_flush_tcpip_queue+0x61> */
  L_005a: a11 = 4;  /* 005a */
  a9 = LD32(a10 + 0x28);  /* 005c */
  a11 = a11 & a9;  /* 005e */
  if (a11 != 0) goto L_0078;  /* 0061: bnez.n a11, 78 <esp_mesh_flush_tcpip_queue+0x58> */
  L_0063: a8 = a8 + (14);  /* 0063 */
  a12 = LD32(a8 + 0x18);  /* 0065 */
  a14 = 65;  /* 0067 */
  a14 = a14 << 5;  /* 0069 */
  a13 = a4;  /* 006c */
  a8 = (u32)&esp_mesh_txupQ_pending + 0x0;  /* 006e: l32r -> global */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 via reloc-expand */
  goto L_0081;  /* 0074: j */
  L_0078: a9 = (u32)&LOCAL__bss_s_extra_toDS_qsize + 0x0;  /* 0078: l32r -> .bss.s_extra_toDS_qsize (same-object static) */
  a8 = LD32(a9 + 0x0);  /* 007b */
  a8 = a8 + (-1);  /* 007d */
  ST32(a9 + 0x0, a8);  /* 007f */
  L_0081: a12 = a4;  /* 0081 */
  a13 = 0x00000833u;  /* 0083: l32r = 2099 */
  a11 = 0x00004015u;  /* 0086: l32r = 16405 */
  a10 = LD32(a1 + 0x0);  /* 0089 */
  __asm__ volatile("" ::: "memory");  /* 008b: memw */
  a8 = (u32)&esp_mesh_discard_context + 0x0;  /* 008e: l32r -> global */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 0091: callx a8 via reloc-expand */
  L_0094: a4 = LD32(a3 + 0x0);  /* 0094 */
  a10 = LD32(a2 + 0x0);  /* 0096 */
  a4 = LD32(a4 + 0x78);  /* 0098 */
  /* 009b: INDIRECT callx a4 <- mem[a4+0x78]; result unknown */ a2 = 0;
  if (a10 != 0) goto L_0039;  /* 009e: bnez a10, 39 <esp_mesh_flush_tcpip_queue+0x19> */
  L_00a1: a2 = 0;  /* 00a1 */
  return a2;  /* 00a3: retw.n */
}


/* esp_mesh_get_announce_interval @ mesh.o 00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: g_mesh_ann_interval
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_announce_interval(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  if (a2 == 0) goto L_0010;  /* 0007: beqz.n a2, 10 <esp_mesh_get_announce_interval+0xc> */
  L_0009: a8 = (u32)&g_mesh_ann_interval + 0x0;  /* 0009: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 000c */
  ST32(a2 + 0x0, a8);  /* 000e */
  L_0010: if (a3 == 0) goto L_0019;  /* 0010: beqz.n a3, 19 <esp_mesh_get_announce_interval+0x15> */
  L_0012: a2 = (u32)&g_mesh_ann_interval + 0x0;  /* 0012: l32r -> global */
  a2 = LD32(a2 + 0x4);  /* 0015 */
  ST32(a3 + 0x0, a2);  /* 0017 */
  L_0019: a2 = 0;  /* 0019 */
  __asm__ volatile("" ::: "memory");  /* 001b: memw */
  return a2;  /* 001e: retw.n */
}


/* esp_mesh_get_ap_authmode @ mesh.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_mesh_ext_cfg
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_ap_authmode(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0007: l32r -> global */
  a2 = LD32(a8 + 0xc8);  /* 000a */
  return a2;  /* 000d: retw.n */
}


/* esp_mesh_get_ap_connections @ mesh.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_mesh_ext_cfg
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_ap_connections(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0007: l32r -> global */
  a2 = LD8U(a8 + 0xbd);  /* 000a */
  return a2;  /* 000d: retw.n */
}


/* esp_mesh_get_attempts @ mesh.o 00000024 size 82B bind GLOBAL
 * Calls: memcpy | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_cfg_attemps
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=5); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_attempts(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0065;  /* 0027: bnez.n a2, 65 <esp_mesh_get_attempts+0x41> */
  L_0029: a2 = (u32)&g_log_level + 0x0;  /* 0029: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002c */
  a2 = 0x00004008u;  /* 002e: l32r = 16392 */
  if (a3 < 3u) goto L_0074;  /* 0031: bltui a3, 3, 74 <esp_mesh_get_attempts+0x50> */
  L_0034: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0034: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0037 */
  if (a8 == 0) goto L_0074;  /* 0039: beqz.n a8, 74 <esp_mesh_get_attempts+0x50> */
  L_003b: a3 = LD32(a8 + 0x150);  /* 003b */
  if (a3 == 0) goto L_0074;  /* 003e: beqz.n a3, 74 <esp_mesh_get_attempts+0x50> */
  L_0040: a10 = LD32(a8 + 0x158);  /* 0040 */
  /* 0043: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0046 */
  a10 = 3;  /* 0048 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 004a: -> "mesh" */
  a14 = a11;  /* 004d */
  a8 = 0x000009d5u;  /* 004f: l32r = 2517 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0052: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0055: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 0058 */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  /* 005d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0074;  /* 0060: j */
  L_0065: a11 = (u32)&g_mesh_cfg_attemps + 0x0;  /* 0065: l32r -> global */
  a10 = a2;  /* 0068 */
  a12 = 16;  /* 006a */
  a8 = (u32)&memcpy + 0x0;  /* 006c: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 006f: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0072 */
  L_0074: return a2;  /* 0074: retw.n */
}


/* esp_mesh_get_capacity_num @ mesh.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_mesh_rt_capacity
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_capacity_num(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_rt_capacity + 0x0;  /* 0007: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 000a */
  return a2;  /* 000c: retw.n */
}


/* esp_mesh_get_config @ mesh.o 00000020 size 86B bind GLOBAL
 * Calls: memcpy | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_ext_cfg
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=5); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_config(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0064;  /* 0023: bnez.n a2, 64 <esp_mesh_get_config+0x44> */
  L_0025: a2 = (u32)&g_log_level + 0x0;  /* 0025: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0028 */
  a2 = 0x00004008u;  /* 002b: l32r = 16392 */
  if (a3 < 3u) goto L_0074;  /* 002e: bltui a3, 3, 74 <esp_mesh_get_config+0x54> */
  L_0031: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0031: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0034 */
  if (a8 == 0) goto L_0074;  /* 0037: beqz.n a8, 74 <esp_mesh_get_config+0x54> */
  L_0039: a3 = LD32(a8 + 0x150);  /* 0039 */
  if (a3 == 0) goto L_0074;  /* 003c: beqz.n a3, 74 <esp_mesh_get_config+0x54> */
  L_003e: a10 = LD32(a8 + 0x158);  /* 003e */
  /* 0041: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x682;  /* 0044 */
  a13 = a10;  /* 0047 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0049: -> "mesh" */
  a10 = 3;  /* 004c */
  a14 = a11;  /* 004e: mov */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0051: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0054: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 0057 */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  /* 005d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0074;  /* 0060: j */
  L_0064: a11 = (u32)&g_mesh_ext_cfg + 0x4;  /* 0064: l32r -> global */
  a10 = a2;  /* 0067 */
  a12 = 184;  /* 0069 */
  a8 = (u32)&memcpy + 0x0;  /* 006c: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 006f: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0072 */
  L_0074: return a2;  /* 0074: retw.n */
}


/* esp_mesh_get_group_list @ mesh.o 00000024 size 102B bind GLOBAL
 * Calls: memcpy | indirect[2]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .bss.s_mesh_group_addr
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=5); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_group_list(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a10 = a2;  /* 0027 */
  if (a2 != 0) goto L_0068;  /* 0029: bnez.n a2, 68 <esp_mesh_get_group_list+0x44> */
  L_002b: a2 = (u32)&g_log_level + 0x0;  /* 002b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002e */
  a2 = 0x00004008u;  /* 0030: l32r = 16392 */
  if (a3 < 3u) goto L_0088;  /* 0033: bltui a3, 3, 88 <esp_mesh_get_group_list+0x64> */
  L_0036: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0036: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0039 */
  if (a3 == 0) goto L_0088;  /* 003b: beqz a3, 88 <esp_mesh_get_group_list+0x64> */
  L_003e: a4 = LD32(a3 + 0x150);  /* 003e */
  if (a4 == 0) goto L_0088;  /* 0041: beqz a4, 88 <esp_mesh_get_group_list+0x64> */
  L_0044: a10 = LD32(a3 + 0x158);  /* 0044 */
  /* 0047: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 004a */
  a10 = 3;  /* 004c */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 004e: -> "mesh" */
  a14 = a11;  /* 0051 */
  a3 = 0x00000ab0u;  /* 0053: l32r = 2736 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0056: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0059: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 005c */
  __asm__ volatile("" ::: "memory");  /* 005e: memw */
  /* 0061: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0088;  /* 0064: j */
  L_0068: a2 = 0x00004008u;  /* 0068: l32r = 16392 */
  if (a3 == 0) goto L_0088;  /* 006b: beqz.n a3, 88 <esp_mesh_get_group_list+0x64> */
  L_006d: a2 = (u32)&LOCAL__bss_s_mesh_group_addr + 0x0;  /* 006d: l32r -> .bss.s_mesh_group_addr (same-object static) */
  a4 = LD32(a2 + 0x0);  /* 0070 */
  a3 = ((i32)a3 < (i32)a4) ? a3 : a4;  /* 0072: min */
  a12 = (a3 >> 8) & 0x1;  /* 0075: extui width 1 */
  a12 = a12 + (a12 << 1);  /* 0078 */
  a11 = LD32(a2 + 0x4);  /* 007b */
  a12 = a12 + a12;  /* 007d */
  a8 = (u32)&memcpy + 0x0;  /* 0080: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0083: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0086 */
  L_0088: return a2;  /* 0088: retw.n */
}


/* esp_mesh_get_group_num @ mesh.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: .bss.s_mesh_group_addr
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_group_num(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&LOCAL__bss_s_mesh_group_addr + 0x0;  /* 0007: l32r -> .bss.s_mesh_group_addr (same-object static) */
  a2 = LD32(a8 + 0x0);  /* 000a */
  return a2;  /* 000c: retw.n */
}


/* esp_mesh_get_id @ mesh.o 00000020 size 88B bind GLOBAL
 * Calls: memcpy | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_ext_cfg
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=5); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_id(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0065;  /* 0023: bnez.n a2, 65 <esp_mesh_get_id+0x45> */
  L_0025: a2 = (u32)&g_log_level + 0x0;  /* 0025: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0028 */
  a2 = 0x00004008u;  /* 002b: l32r = 16392 */
  if (a3 < 3u) goto L_0076;  /* 002e: bltui a3, 3, 76 <esp_mesh_get_id+0x56> */
  L_0031: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0031: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0034 */
  if (a8 == 0) goto L_0076;  /* 0037: beqz.n a8, 76 <esp_mesh_get_id+0x56> */
  L_0039: a3 = LD32(a8 + 0x150);  /* 0039 */
  if (a3 == 0) goto L_0076;  /* 003c: beqz.n a3, 76 <esp_mesh_get_id+0x56> */
  L_003e: a10 = LD32(a8 + 0x158);  /* 003e */
  /* 0041: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x6d1;  /* 0044 */
  a13 = a10;  /* 0047 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0049: -> "mesh" */
  a10 = 3;  /* 004c */
  a14 = a11;  /* 004e: mov */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0051: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0054: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 0057 */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  /* 005d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0076;  /* 0060: j */
  L_0065: a11 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0065: l32r -> global */
  a12 = 6;  /* 0068 */
  a10 = a2;  /* 006a */
  a11 = a11 + a12;  /* 006c */
  a8 = (u32)&memcpy + 0x0;  /* 006e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0074 */
  L_0076: return a2;  /* 0076: retw.n */
}


/* esp_mesh_get_ie_crypto_key @ mesh.o 00000034 size 174B bind GLOBAL
 * Calls: strnlen, memcpy | indirect[4]: mem[a8+0x158]; mem[a8+0x150] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, .data.s_mesh_ie_crypto_plain_key
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=8); reloc-direct=2, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_get_ie_crypto_key(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0034: entry a1, 48 (frame 48 bytes) */
  a4 = a2;  /* 0037 */
  a2 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 0039: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = LD8U(a2 + 0x0);  /* 003c */
  if (a2 != 0) goto L_0079;  /* 003f: bnez.n a2, 79 <esp_mesh_get_ie_crypto_key+0x45> */
  L_0041: a2 = (u32)&g_log_level + 0x0;  /* 0041: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0044 */
  a2 = 0x00004002u;  /* 0047: l32r = 16386 */
  if (a3 >= 3u) goto L_0050;  /* 004a: bgeui a3, 3, 50 <esp_mesh_get_ie_crypto_key+0x1c> */
  L_004d: goto L_00e0;  /* 004d: j */
  L_0050: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0050: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0053 */
  if (a8 == 0) goto L_00e0;  /* 0056: beqz a8, e0 <esp_mesh_get_ie_crypto_key+0xac> */
  L_0059: a3 = LD32(a8 + 0x150);  /* 0059 */
  if (a3 == 0) goto L_00e0;  /* 005c: beqz a3, e0 <esp_mesh_get_ie_crypto_key+0xac> */
  L_005f: a10 = LD32(a8 + 0x158);  /* 005f */
  /* 0062: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0065 */
  a10 = 3;  /* 0067 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0069: -> "mesh" */
  a14 = a11;  /* 006c */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 006e: l32r -> .rodata.esp_mesh_recv.str1.1 */
  /* 0071: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00e0;  /* 0074: j */
  L_0079: if (a4 != 0) goto L_00b9;  /* 0079: bnez.n a4, b9 <esp_mesh_get_ie_crypto_key+0x85> */
  L_007b: a2 = (u32)&g_log_level + 0x0;  /* 007b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 007e */
  a2 = 0x00004008u;  /* 0080: l32r = 16392 */
  if (a3 < 3u) goto L_00e0;  /* 0083: bltui a3, 3, e0 <esp_mesh_get_ie_crypto_key+0xac> */
  L_0086: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0086: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0089 */
  if (a8 == 0) goto L_00e0;  /* 008b: beqz a8, e0 <esp_mesh_get_ie_crypto_key+0xac> */
  L_008e: a3 = LD32(a8 + 0x150);  /* 008e */
  if (a3 == 0) goto L_00e0;  /* 0091: beqz a3, e0 <esp_mesh_get_ie_crypto_key+0xac> */
  L_0094: a10 = LD32(a8 + 0x158);  /* 0094 */
  /* 0097: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 009a */
  a10 = 3;  /* 009c */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 009e: -> "mesh" */
  a14 = a11;  /* 00a1 */
  a4 = 0x00000b24u;  /* 00a3: l32r = 2852 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a6: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a9: -> "mesh" */
  ST32(a1 + 0x0, a4);  /* 00ac */
  __asm__ volatile("" ::: "memory");  /* 00ae: memw */
  /* 00b1: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00e0;  /* 00b4: j */
  L_00b9: a8 = a3 + (-8);  /* 00b9 */
  a9 = 56;  /* 00bc */
  a2 = 0x00004008u;  /* 00be: l32r = 16392 */
  if (a9 < a8) goto L_00e0;  /* 00c1: bltu a9, a8, e0 <esp_mesh_get_ie_crypto_key+0xac> */
  L_00c4: a11 = 64;  /* 00c4 */
  a2 = (u32)&LOCAL__data_s_mesh_ie_crypto_plain_key + 0x0;  /* 00c6: l32r -> .data.s_mesh_ie_crypto_plain_key (same-object static) */
  a10 = a2;  /* 00c9 */
  a8 = (u32)&strnlen + 0x0;  /* 00cb: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 00ce: callx a8 (libc, via reloc-expand) */
  a12 = (a3 < a10) ? a3 : a10;  /* 00d1: minu */
  a11 = a2;  /* 00d4 */
  a10 = a4;  /* 00d6 */
  a8 = (u32)&memcpy + 0x0;  /* 00d8: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00db: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 00de */
  L_00e0: return a2;  /* 00e0: retw.n */
}


/* esp_mesh_get_layer @ mesh.o 0000001c size 73B bind GLOBAL
 * Calls: none | Data refs: .bss.g_is_mesh_inited, g_is_mesh_started, g_mesh_is_root, g_is_wifi_connected, g_mesh_topology, g_mesh_ie, g_mesh_chain
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=7); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_layer(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 001c: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 001f: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a8 = LD8U(a2 + 0x0);  /* 0022 */
  a2 = -1;  /* 0025 */
  if (a8 == 0) goto L_0063;  /* 0027: beqz.n a8, 63 <esp_mesh_get_layer+0x47> */
  L_0029: a2 = (u32)&g_is_mesh_started + 0x0;  /* 0029: l32r -> global */
  a8 = LD8U(a2 + 0x0);  /* 002c */
  a2 = -1;  /* 002f */
  if (a8 == 0) goto L_0063;  /* 0031: beqz.n a8, 63 <esp_mesh_get_layer+0x47> */
  L_0033: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0033: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0036: memw */
  a8 = LD8U(a2 + 0x0);  /* 0039 */
  a2 = 1;  /* 003c */
  a8 = (a8 >> 8) & 0x1;  /* 003e: extui width 1 */
  if (a8 != 0) goto L_0063;  /* 0041: bnez.n a8, 63 <esp_mesh_get_layer+0x47> */
  L_0043: a2 = (u32)&g_is_wifi_connected + 0x0;  /* 0043: l32r -> global */
  a8 = LD8U(a2 + 0x0);  /* 0046 */
  a2 = -1;  /* 0049 */
  if (a8 == 0) goto L_0063;  /* 004b: beqz.n a8, 63 <esp_mesh_get_layer+0x47> */
  L_004d: a2 = (u32)&g_mesh_topology + 0x0;  /* 004d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0050 */
  if (a2 != 0) goto L_005d;  /* 0052: bnez.n a2, 5d <esp_mesh_get_layer+0x41> */
  L_0054: a2 = (u32)&g_mesh_ie + 0x0;  /* 0054: l32r -> global */
  a2 = LD8U(a2 + 0xf);  /* 0057 */
  goto L_0063;  /* 005a: j */
  L_005d: a2 = (u32)&g_mesh_chain + 0x0;  /* 005d: l32r -> global */
  a2 = LD16U(a2 + 0x2);  /* 0060 */
  L_0063: return a2;  /* 0063: retw.n */
}


/* esp_mesh_get_max_layer @ mesh.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_mesh_max_layer
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
void esp_mesh_get_max_layer(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_max_layer + 0x0;  /* 0007: l32r -> global */
  a2 = LD16U(a8 + 0x0);  /* 000a */
  return;  /* 000d: retw.n */
}


/* esp_mesh_get_non_mesh_connections @ mesh.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_mesh_ext_cfg
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_non_mesh_connections(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0007: l32r -> global */
  a2 = LD8U(a8 + 0xbc);  /* 000a */
  return a2;  /* 000d: retw.n */
}


/* esp_mesh_get_parent_bssid @ mesh.o 00000030 size 124B bind GLOBAL
 * Calls: esp_mesh_get_router_bssid, memcpy | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_is_root, g_mesh_current_parent, g_is_wifi_connected
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=8); reloc-direct=2, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_parent_bssid(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0030: entry a1, 48 (frame 48 bytes) */
  a10 = a2;  /* 0033 */
  if (a2 != 0) goto L_0077;  /* 0035: bnez.n a2, 77 <esp_mesh_get_parent_bssid+0x47> */
  L_0037: a2 = (u32)&g_log_level + 0x0;  /* 0037: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 003a */
  a2 = 0x00004008u;  /* 003d: l32r = 16392 */
  if (a3 < 3u) goto L_00aa;  /* 0040: bltui a3, 3, aa <esp_mesh_get_parent_bssid+0x7a> */
  L_0043: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0043: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0046 */
  if (a8 == 0) goto L_00aa;  /* 0049: beqz a8, aa <esp_mesh_get_parent_bssid+0x7a> */
  L_004c: a3 = LD32(a8 + 0x150);  /* 004c */
  if (a3 == 0) goto L_00aa;  /* 004f: beqz a3, aa <esp_mesh_get_parent_bssid+0x7a> */
  L_0052: a10 = LD32(a8 + 0x158);  /* 0052 */
  /* 0055: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x75b;  /* 0058 */
  a13 = a10;  /* 005b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 005d: -> "mesh" */
  a10 = 3;  /* 0060 */
  a14 = a11;  /* 0062: mov */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0065: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0068: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 006b */
  __asm__ volatile("" ::: "memory");  /* 006e: memw */
  /* 0071: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00aa;  /* 0074: j */
  L_0077: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0077: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 007a: memw */
  a2 = LD8U(a2 + 0x0);  /* 007d */
  a2 = (a2 >> 8) & 0x1;  /* 0080: extui width 1 */
  if (a2 == 0) goto L_0091;  /* 0083: beqz a2, 91 <esp_mesh_get_parent_bssid+0x61> */
  L_0086: a8 = (u32)&esp_mesh_get_router_bssid + 0x0;  /* 0086: l32r -> global */
  a2 = esp_mesh_get_router_bssid(a2, a3, a4, a5, a6, a7);  /* 0089: callx a8 via reloc-expand */
  goto L_009c;  /* 008c: j */
  L_0091: a11 = (u32)&g_mesh_current_parent + 0x0;  /* 0091: l32r -> global */
  a12 = 6;  /* 0094 */
  a8 = (u32)&memcpy + 0x0;  /* 0096: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0099: callx a8 (libc, via reloc-expand) */
  L_009c: a2 = (u32)&g_is_wifi_connected + 0x0;  /* 009c: l32r -> global */
  a3 = LD8U(a2 + 0x0);  /* 009f */
  a2 = 0;  /* 00a2 */
  if (a3 != a2) goto L_00aa;  /* 00a4: bne a3, a2, aa <esp_mesh_get_parent_bssid+0x7a> */
  L_00a7: a2 = 0x0000400bu;  /* 00a7: l32r = 16395 */
  L_00aa: return a2;  /* 00aa: retw.n */
}


/* esp_mesh_get_passive_scan_time @ mesh.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_mesh_passive_scan_time
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_passive_scan_time(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_passive_scan_time + 0x0;  /* 0007: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 000a */
  return a2;  /* 000c: retw.n */
}


/* esp_mesh_get_root_addr @ mesh.o 00000030 size 122B bind GLOBAL
 * Calls: memcmp, memcpy | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_ie, .bss.MESH_ZERO_ADDR
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_root_addr(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0030: entry a1, 48 (frame 48 bytes) */
  a3 = a2;  /* 0033 */
  if (a2 != 0) goto L_0074;  /* 0035: bnez.n a2, 74 <esp_mesh_get_root_addr+0x44> */
  L_0037: a2 = (u32)&g_log_level + 0x0;  /* 0037: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 003a */
  a2 = 0x00004008u;  /* 003c: l32r = 16392 */
  if (a3 < 3u) goto L_00a8;  /* 003f: bltui a3, 3, a8 <esp_mesh_get_root_addr+0x78> */
  L_0042: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0042: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0045 */
  if (a8 == 0) goto L_00a8;  /* 0047: beqz a8, a8 <esp_mesh_get_root_addr+0x78> */
  L_004a: a3 = LD32(a8 + 0x150);  /* 004a */
  if (a3 == 0) goto L_00a8;  /* 004d: beqz a3, a8 <esp_mesh_get_root_addr+0x78> */
  L_0050: a10 = LD32(a8 + 0x158);  /* 0050 */
  /* 0053: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0056 */
  a10 = 3;  /* 0058 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 005a: -> "mesh" */
  a14 = a11;  /* 005d */
  a4 = 0x000009b2u;  /* 005f: l32r = 2482 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0062: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0065: -> "mesh" */
  ST32(a1 + 0x0, a4);  /* 0068 */
  __asm__ volatile("" ::: "memory");  /* 006a: memw */
  /* 006d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00a8;  /* 0070: j */
  L_0074: a4 = (u32)&g_mesh_ie + 0x1f;  /* 0074: l32r -> global */
  a12 = 6;  /* 0077 */
  a10 = a4;  /* 0079 */
  a2 = -1;  /* 007b */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 007d: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a8 = (u32)&memcmp + 0x0;  /* 0080: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0083: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_00a8;  /* 0086: beqz.n a10, a8 <esp_mesh_get_root_addr+0x78> */
  L_0088: a9 = -120;  /* 0088 */
  a2 = (u32)&g_mesh_ie + 0x0;  /* 008b: l32r -> global */
  a8 = LD8U(a2 + 0x25);  /* 008e */
  a2 = -1;  /* 0091 */
  a8 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 0093: sext */
  if (a8 == a9) goto L_00a8;  /* 0096: beq a8, a9, a8 <esp_mesh_get_root_addr+0x78> */
  L_0099: a12 = 6;  /* 0099 */
  a11 = a4;  /* 009b */
  a10 = a3;  /* 009d: mov */
  a8 = (u32)&memcpy + 0x0;  /* 00a0: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00a3: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 00a6 */
  L_00a8: return a2;  /* 00a8: retw.n */
}


/* esp_mesh_get_root_healing_delay @ mesh.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_mesh_root_healing_delay
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_root_healing_delay(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_root_healing_delay + 0x0;  /* 0007: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 000a */
  return a2;  /* 000c: retw.n */
}


/* esp_mesh_get_router @ mesh.o 00000020 size 88B bind GLOBAL
 * Calls: memcpy | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_ext_cfg
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=5); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_router(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0063;  /* 0023: bnez.n a2, 63 <esp_mesh_get_router+0x43> */
  L_0025: a2 = (u32)&g_log_level + 0x0;  /* 0025: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0028 */
  a2 = 0x00004008u;  /* 002b: l32r = 16392 */
  if (a3 < 3u) goto L_0076;  /* 002e: bltui a3, 3, 76 <esp_mesh_get_router+0x56> */
  L_0031: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0031: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0034 */
  if (a8 == 0) goto L_0076;  /* 0037: beqz.n a8, 76 <esp_mesh_get_router+0x56> */
  L_0039: a3 = LD32(a8 + 0x150);  /* 0039 */
  if (a3 == 0) goto L_0076;  /* 003c: beqz.n a3, 76 <esp_mesh_get_router+0x56> */
  L_003e: a10 = LD32(a8 + 0x158);  /* 003e */
  /* 0041: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x69a;  /* 0044 */
  a13 = a10;  /* 0047 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0049: -> "mesh" */
  a10 = 3;  /* 004c */
  a14 = a11;  /* 004e: mov */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0051: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0054: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 0057 */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  /* 005d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0076;  /* 0060: j */
  L_0063: a11 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0063: l32r -> global */
  a10 = a2;  /* 0066: mov */
  a12 = 104;  /* 0069 */
  a11 = a11 + (12);  /* 006c */
  a8 = (u32)&memcpy + 0x0;  /* 006e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0074 */
  L_0076: return a2;  /* 0076: retw.n */
}


/* esp_mesh_get_rx_pending @ mesh.o 0000002c size 279B bind GLOBAL
 * Calls: none | indirect[8]: mem[a8+0x158]; mem[a8+0x150]; mem[a8+0x78]; mem[a3+0x78] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, mesh_tcpip_mbox, mesh_myself_mbox
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=6); reloc-direct=0, funcdb-attributed=0, unknown-indirect=8 */
u32 esp_mesh_get_rx_pending(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 002c: entry a1, 48 (frame 48 bytes) */
  a3 = (u32)&g_is_mesh_started + 0x0;  /* 002f: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 0032 */
  if (a3 != 0) goto L_006d;  /* 0035: bnez.n a3, 6d <esp_mesh_get_rx_pending+0x41> */
  L_0037: a2 = (u32)&g_log_level + 0x0;  /* 0037: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 003a */
  a2 = 0x00004004u;  /* 003c: l32r = 16388 */
  if (a3 >= 3u) goto L_0045;  /* 003f: bgeui a3, 3, 45 <esp_mesh_get_rx_pending+0x19> */
  L_0042: goto L_013e;  /* 0042: j */
  L_0045: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0045: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0048 */
  if (a8 == 0) goto L_013e;  /* 004a: beqz a8, 13e <esp_mesh_get_rx_pending+0x112> */
  L_004d: a3 = LD32(a8 + 0x150);  /* 004d */
  if (a3 == 0) goto L_013e;  /* 0050: beqz a3, 13e <esp_mesh_get_rx_pending+0x112> */
  L_0053: a10 = LD32(a8 + 0x158);  /* 0053 */
  /* 0056: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0059 */
  a10 = 3;  /* 005b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 005d: -> "mesh" */
  a14 = a11;  /* 0060 */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0062: -> "mesh" */
  /* 0065: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_013e;  /* 0068: j */
  L_006d: if (a2 != 0) goto L_009d;  /* 006d: bnez.n a2, 9d <esp_mesh_get_rx_pending+0x71> */
  L_006f: a2 = (u32)&g_log_level + 0x0;  /* 006f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0072 */
  a2 = 0x00004008u;  /* 0074: l32r = 16392 */
  if (a3 >= 3u) goto L_007d;  /* 0077: bgeui a3, 3, 7d <esp_mesh_get_rx_pending+0x51> */
  L_007a: goto L_013e;  /* 007a: j */
  L_007d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 007d: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0080 */
  if (a8 == 0) goto L_013e;  /* 0082: beqz a8, 13e <esp_mesh_get_rx_pending+0x112> */
  L_0085: a3 = LD32(a8 + 0x150);  /* 0085 */
  if (a3 == 0) goto L_013e;  /* 0088: beqz a3, 13e <esp_mesh_get_rx_pending+0x112> */
  L_008b: a4 = 145;  /* 008b */
  a10 = LD32(a8 + 0x158);  /* 008e */
  /* 0091: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0094: -> "mesh" */
  goto L_00cf;  /* 0097: j */
  L_009d: a3 = (u32)&mesh_tcpip_mbox + 0x0;  /* 009d: l32r -> global */
  a10 = LD32(a3 + 0x0);  /* 00a0 */
  if (a10 != 0) goto L_00e9;  /* 00a2: bnez a10, e9 <esp_mesh_get_rx_pending+0xbd> */
  L_00a5: a2 = (u32)&g_log_level + 0x0;  /* 00a5: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00a8 */
  a2 = 0x00004008u;  /* 00ab: l32r = 16392 */
  if (a3 >= 3u) goto L_00b4;  /* 00ae: bgeui a3, 3, b4 <esp_mesh_get_rx_pending+0x88> */
  L_00b1: goto L_013e;  /* 00b1: j */
  L_00b4: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b4: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00b7 */
  if (a8 == 0) goto L_013e;  /* 00ba: beqz a8, 13e <esp_mesh_get_rx_pending+0x112> */
  L_00bd: a3 = LD32(a8 + 0x150);  /* 00bd */
  if (a3 == 0) goto L_013e;  /* 00c0: beqz a3, 13e <esp_mesh_get_rx_pending+0x112> */
  L_00c3: a4 = 146;  /* 00c3 */
  a10 = LD32(a8 + 0x158);  /* 00c6 */
  /* 00c9: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00cc: -> "mesh" */
  L_00cf: a13 = a10;  /* 00cf */
  a14 = a11;  /* 00d1 */
  a10 = 3;  /* 00d3 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00d5: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00d8: -> "mesh" */
  ST32(a1 + 0x0, a4);  /* 00db */
  __asm__ volatile("" ::: "memory");  /* 00de: memw */
  /* 00e1: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_013e;  /* 00e4: j */
  L_00e9: a4 = (u32)&mesh_myself_mbox + 0x0;  /* 00e9: l32r -> global */
  a3 = LD32(a4 + 0x0);  /* 00ec */
  if (a3 != 0) goto L_0119;  /* 00ee: bnez.n a3, 119 <esp_mesh_get_rx_pending+0xed> */
  L_00f0: a2 = (u32)&g_log_level + 0x0;  /* 00f0: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00f3 */
  a2 = 0x00004008u;  /* 00f5: l32r = 16392 */
  if (a3 < 3u) goto L_013e;  /* 00f8: bltui a3, 3, 13e <esp_mesh_get_rx_pending+0x112> */
  L_00fb: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00fb: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00fe */
  if (a8 == 0) goto L_013e;  /* 0100: beqz.n a8, 13e <esp_mesh_get_rx_pending+0x112> */
  L_0102: a3 = LD32(a8 + 0x150);  /* 0102 */
  if (a3 == 0) goto L_013e;  /* 0105: beqz.n a3, 13e <esp_mesh_get_rx_pending+0x112> */
  L_0107: a4 = 147;  /* 0107 */
  a10 = LD32(a8 + 0x158);  /* 010a */
  /* 010d: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0110: -> "mesh" */
  goto L_00cf;  /* 0113: j */
  L_0119: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0119: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 011c */
  a8 = LD32(a8 + 0x78);  /* 011e */
  /* 0121: INDIRECT callx a8 <- mem[a8+0x78]; result unknown */ a2 = 0;
  a8 = 0;  /* 0124 */
  ST32(a2 + 0x0, a10);  /* 0126 */
  a10 = LD32(a4 + 0x0);  /* 0128 */
  if (a10 == a8) goto L_013a;  /* 012a: beq a10, a8, 13a <esp_mesh_get_rx_pending+0x10e> */
  L_012d: a3 = LD32(a3 + 0x0);  /* 012d */
  a3 = LD32(a3 + 0x78);  /* 012f */
  __asm__ volatile("" ::: "memory");  /* 0132: memw */
  /* 0135: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a8 = a10;  /* 0138 */
  L_013a: ST32(a2 + 0x4, a8);  /* 013a */
  a2 = 0;  /* 013c */
  L_013e: __asm__ volatile("" ::: "memory");  /* 013e: memw */
  return a2;  /* 0141: retw.n */
}


/* esp_mesh_get_self_organized @ mesh.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: g_mesh_self_organized
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_self_organized(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_mesh_self_organized + 0x0;  /* 0007: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 000a: memw */
  a2 = LD8U(a2 + 0x0);  /* 000d */
  a2 = (a2 >> 8) & 0x1;  /* 0010: extui width 1 */
  return a2;  /* 0013: retw.n */
}


/* esp_mesh_get_subnet_nodes_list @ mesh.o 00000038 size 246B bind GLOBAL
 * Calls: esp_mesh_is_nwk_running, mesh_get_subnet_nodes_list, mesh_set_io_process | indirect[6]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0xa4] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1
 * Fidelity: medium - 6 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=7); reloc-direct=3, funcdb-attributed=0, unknown-indirect=6 */
u32 esp_mesh_get_subnet_nodes_list(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0038: entry a1, 80 (frame 80 bytes) */
  a5 = a2;  /* 003b */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 003d: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0040 */
  if (a2 != 0) goto L_007c;  /* 0043: bnez.n a2, 7c <esp_mesh_get_subnet_nodes_list+0x44> */
  L_0045: a2 = (u32)&g_log_level + 0x0;  /* 0045: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0048 */
  a2 = 0x00004004u;  /* 004b: l32r = 16388 */
  if (a3 >= 3u) goto L_0054;  /* 004e: bgeui a3, 3, 54 <esp_mesh_get_subnet_nodes_list+0x1c> */
  L_0051: goto L_012c;  /* 0051: j */
  L_0054: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0054: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0057 */
  if (a3 == 0) goto L_012c;  /* 005a: beqz a3, 12c <esp_mesh_get_subnet_nodes_list+0xf4> */
  L_005d: a4 = LD32(a3 + 0x150);  /* 005d */
  if (a4 == 0) goto L_012c;  /* 0060: beqz a4, 12c <esp_mesh_get_subnet_nodes_list+0xf4> */
  L_0063: a10 = LD32(a3 + 0x158);  /* 0063 */
  /* 0066: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0069 */
  a10 = 3;  /* 006b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 006d: -> "mesh" */
  a14 = a11;  /* 0070 */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0072: -> "mesh" */
  /* 0075: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_012c;  /* 0078: j */
  L_007c: if (a5 != 0) goto L_00a9;  /* 007c: bnez.n a5, a9 <esp_mesh_get_subnet_nodes_list+0x71> */
  L_007e: a2 = (u32)&g_log_level + 0x0;  /* 007e: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0081 */
  a2 = 0x00004008u;  /* 0083: l32r = 16392 */
  if (a3 >= 3u) goto L_008c;  /* 0086: bgeui a3, 3, 8c <esp_mesh_get_subnet_nodes_list+0x54> */
  L_0089: goto L_012c;  /* 0089: j */
  L_008c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 008c: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 008f */
  if (a3 == 0) goto L_012c;  /* 0091: beqz a3, 12c <esp_mesh_get_subnet_nodes_list+0xf4> */
  L_0094: a4 = LD32(a3 + 0x150);  /* 0094 */
  if (a4 == 0) goto L_012c;  /* 0097: beqz a4, 12c <esp_mesh_get_subnet_nodes_list+0xf4> */
  L_009a: a10 = LD32(a3 + 0x158);  /* 009a */
  /* 009d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a0: -> "mesh" */
  a3 = 0x00000b88u;  /* 00a3: l32r = 2952 */
  goto L_00d2;  /* 00a6: j */
  L_00a9: if (a3 != 0) goto L_00ec;  /* 00a9: bnez.n a3, ec <esp_mesh_get_subnet_nodes_list+0xb4> */
  L_00ab: a2 = (u32)&g_log_level + 0x0;  /* 00ab: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ae */
  a2 = 0x00004008u;  /* 00b1: l32r = 16392 */
  if (a3 < 3u) goto L_012c;  /* 00b4: bltui a3, 3, 12c <esp_mesh_get_subnet_nodes_list+0xf4> */
  L_00b7: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b7: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00ba */
  if (a3 == 0) goto L_012c;  /* 00bd: beqz a3, 12c <esp_mesh_get_subnet_nodes_list+0xf4> */
  L_00c0: a4 = LD32(a3 + 0x150);  /* 00c0 */
  if (a4 == 0) goto L_012c;  /* 00c3: beqz a4, 12c <esp_mesh_get_subnet_nodes_list+0xf4> */
  L_00c6: a10 = LD32(a3 + 0x158);  /* 00c6 */
  /* 00c9: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00cc: -> "mesh" */
  a3 = 0x00000b89u;  /* 00cf: l32r = 2953 */
  L_00d2: a13 = a10;  /* 00d2 */
  a14 = a11;  /* 00d4 */
  a10 = 3;  /* 00d6 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00d9: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00dc: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 00df */
  __asm__ volatile("" ::: "memory");  /* 00e2: memw */
  /* 00e5: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_012c;  /* 00e8: j */
  L_00ec: a2 = 0x00004008u;  /* 00ec: l32r = 16392 */
  if (a4 == 0) goto L_012c;  /* 00ef: beqz.n a4, 12c <esp_mesh_get_subnet_nodes_list+0xf4> */
  L_00f1: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00f1: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00f4 */
  a10 = LD32(a2 + 0xa4);  /* 00f6 */
  /* 00f9: INDIRECT callx a10 <- mem[a2+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 00fc: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 00ff: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0114;  /* 0102: beqz.n a10, 114 <esp_mesh_get_subnet_nodes_list+0xdc> */
  L_0104: a12 = a4;  /* 0104 */
  a11 = a3;  /* 0106 */
  a10 = a5;  /* 0108 */
  a8 = (u32)&mesh_get_subnet_nodes_list + 0x0;  /* 010a: l32r -> global */
  a2 = mesh_get_subnet_nodes_list(a2, a3, a4, a5, a6, a7);  /* 010d: callx a8 via reloc-expand */
  goto L_012a;  /* 0110: j */
  L_0114: a2 = 3;  /* 0114 */
  a10 = a1 + (16);  /* 0116 */
  ST32(a1 + 0x10, a2);  /* 0119 */
  ST32(a1 + 0x14, a5);  /* 011b */
  ST32(a1 + 0x18, a4);  /* 011d */
  ST32(a1 + 0x1c, a3);  /* 011f */
  __asm__ volatile("" ::: "memory");  /* 0121: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 0124: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 0127: callx a8 via reloc-expand */
  L_012a: a2 = a10;  /* 012a */
  L_012c: return a2;  /* 012c: retw.n */
}


/* esp_mesh_get_subnet_nodes_num @ mesh.o 00000034 size 188B bind GLOBAL
 * Calls: esp_mesh_is_nwk_running, mesh_get_subnet_nodes_num, mesh_set_io_process | indirect[5]: mem[a8+0x158]; mem[a8+0x150]; mem[a8+0xa4] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=7); reloc-direct=3, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_get_subnet_nodes_num(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0034: entry a1, 80 (frame 80 bytes) */
  a8 = (u32)&g_is_mesh_started + 0x0;  /* 0037: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 003a */
  if (a8 != 0) goto L_0075;  /* 003d: bnez.n a8, 75 <esp_mesh_get_subnet_nodes_num+0x41> */
  L_003f: a2 = (u32)&g_log_level + 0x0;  /* 003f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0042 */
  a2 = 0x00004004u;  /* 0044: l32r = 16388 */
  if (a3 >= 3u) goto L_004d;  /* 0047: bgeui a3, 3, 4d <esp_mesh_get_subnet_nodes_num+0x19> */
  L_004a: goto L_00ee;  /* 004a: j */
  L_004d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 004d: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0050 */
  if (a8 == 0) goto L_00ee;  /* 0052: beqz a8, ee <esp_mesh_get_subnet_nodes_num+0xba> */
  L_0055: a3 = LD32(a8 + 0x150);  /* 0055 */
  if (a3 == 0) goto L_00ee;  /* 0058: beqz a3, ee <esp_mesh_get_subnet_nodes_num+0xba> */
  L_005b: a10 = LD32(a8 + 0x158);  /* 005b */
  /* 005e: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0061 */
  a10 = 3;  /* 0063 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0065: -> "mesh" */
  a14 = a11;  /* 0068 */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 006a: -> "mesh" */
  /* 006d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00ee;  /* 0070: j */
  L_0075: if (a2 != 0) goto L_00b5;  /* 0075: bnez.n a2, b5 <esp_mesh_get_subnet_nodes_num+0x81> */
  L_0077: a2 = (u32)&g_log_level + 0x0;  /* 0077: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 007a */
  a2 = 0x00004008u;  /* 007c: l32r = 16392 */
  if (a3 < 3u) goto L_00ee;  /* 007f: bltui a3, 3, ee <esp_mesh_get_subnet_nodes_num+0xba> */
  L_0082: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0082: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0085 */
  if (a8 == 0) goto L_00ee;  /* 0087: beqz a8, ee <esp_mesh_get_subnet_nodes_num+0xba> */
  L_008a: a3 = LD32(a8 + 0x150);  /* 008a */
  if (a3 == 0) goto L_00ee;  /* 008d: beqz a3, ee <esp_mesh_get_subnet_nodes_num+0xba> */
  L_0090: a10 = LD32(a8 + 0x158);  /* 0090 */
  /* 0093: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0096 */
  a10 = 3;  /* 0098 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 009a: -> "mesh" */
  a14 = a11;  /* 009d */
  a8 = 0x00000b72u;  /* 009f: l32r = 2930 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a2: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a5: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 00a8 */
  __asm__ volatile("" ::: "memory");  /* 00aa: memw */
  /* 00ad: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00ee;  /* 00b0: j */
  L_00b5: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 00b5: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 00b8 */
  a10 = LD32(a8 + 0xa4);  /* 00ba */
  /* 00bd: INDIRECT callx a10 <- mem[a8+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 00c0: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 00c3: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00d8;  /* 00c6: beqz.n a10, d8 <esp_mesh_get_subnet_nodes_num+0xa4> */
  L_00c8: a11 = a3;  /* 00c8: mov */
  a10 = a2;  /* 00cb: mov */
  a8 = (u32)&mesh_get_subnet_nodes_num + 0x0;  /* 00ce: l32r -> global */
  a2 = mesh_get_subnet_nodes_num(a2, a3, a4, a5, a6, a7);  /* 00d1: callx a8 via reloc-expand */
  goto L_00ec;  /* 00d4: j */
  L_00d8: a8 = 2;  /* 00d8 */
  a10 = a1 + (16);  /* 00da */
  ST32(a1 + 0x10, a8);  /* 00dd */
  ST32(a1 + 0x14, a2);  /* 00df */
  ST32(a1 + 0x18, a3);  /* 00e1 */
  __asm__ volatile("" ::: "memory");  /* 00e3: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 00e6: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 00e9: callx a8 via reloc-expand */
  L_00ec: a2 = a10;  /* 00ec */
  L_00ee: return a2;  /* 00ee: retw.n */
}


/* esp_mesh_get_switch_parent_paras @ mesh.o 00000024 size 82B bind GLOBAL
 * Calls: memcpy | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_cfg_switch_parent
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=5); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_get_switch_parent_paras(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0065;  /* 0027: bnez.n a2, 65 <esp_mesh_get_switch_parent_paras+0x41> */
  L_0029: a2 = (u32)&g_log_level + 0x0;  /* 0029: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002c */
  a2 = 0x00004008u;  /* 002e: l32r = 16392 */
  if (a3 < 3u) goto L_0074;  /* 0031: bltui a3, 3, 74 <esp_mesh_get_switch_parent_paras+0x50> */
  L_0034: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0034: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0037 */
  if (a8 == 0) goto L_0074;  /* 0039: beqz.n a8, 74 <esp_mesh_get_switch_parent_paras+0x50> */
  L_003b: a3 = LD32(a8 + 0x150);  /* 003b */
  if (a3 == 0) goto L_0074;  /* 003e: beqz.n a3, 74 <esp_mesh_get_switch_parent_paras+0x50> */
  L_0040: a10 = LD32(a8 + 0x158);  /* 0040 */
  /* 0043: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0046 */
  a10 = 3;  /* 0048 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 004a: -> "mesh" */
  a14 = a11;  /* 004d */
  a8 = 0x00000a13u;  /* 004f: l32r = 2579 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0052: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0055: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 0058 */
  __asm__ volatile("" ::: "memory");  /* 005a: memw */
  /* 005d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0074;  /* 0060: j */
  L_0065: a11 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 0065: l32r -> global */
  a10 = a2;  /* 0068 */
  a12 = 20;  /* 006a */
  a8 = (u32)&memcpy + 0x0;  /* 006c: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 006f: callx a8 (libc, via reloc-expand) */
  a2 = 0;  /* 0072 */
  L_0074: return a2;  /* 0074: retw.n */
}


/* esp_mesh_get_topology @ mesh.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_mesh_topology
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_topology(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 0007: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 000a */
  return a2;  /* 000c: retw.n */
}


/* esp_mesh_get_total_node_num @ mesh.o 0000000c size 78B bind GLOBAL
 * Calls: memset, esp_wifi_vnd_mesh_get | Data refs: g_mesh_ie
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_total_node_num(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 000c: entry a1, 96 (frame 96 bytes) */
  a12 = 58;  /* 000f */
  a11 = 0;  /* 0012 */
  a10 = a1;  /* 0015: mov */
  a8 = (u32)&memset + 0x0;  /* 0018: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 001b: callx a8 (libc, via reloc-expand) */
  a11 = 0;  /* 001e */
  a10 = a1;  /* 0020 */
  a8 = (u32)&esp_wifi_vnd_mesh_get + 0x0;  /* 0022: l32r -> global */
  a2 = esp_wifi_vnd_mesh_get(a2, a3, a4, a5, a6, a7);  /* 0025: callx a8 via reloc-expand */
  a8 = (u32)&g_mesh_ie + 0x0;  /* 0028: l32r -> global */
  a10 = LD8U(a8 + 0x15);  /* 002b */
  a10 = a10 << 8;  /* 002e */
  a2 = LD8U(a8 + 0x14);  /* 0031 */
  a10 = a10 | a2;  /* 0034 */
  a9 = LD16U(a1 + 0x14);  /* 0037 */
  if (a9 == a10) goto L_0049;  /* 003a: beq a9, a10, 49 <esp_mesh_get_total_node_num+0x3d> */
  L_003d: ST8(a8 + 0x14, a9);  /* 003d */
  a9 = a9 >> 8;  /* 0040 */
  ST8(a8 + 0x15, a9);  /* 0043 */
  __asm__ volatile("" ::: "memory");  /* 0046: memw */
  L_0049: a2 = LD8U(a8 + 0x14);  /* 0049 */
  a8 = LD8U(a8 + 0x15);  /* 004c */
  a8 = a8 << 8;  /* 004f */
  a2 = a8 | a2;  /* 0052 */
  __asm__ volatile("" ::: "memory");  /* 0055: memw */
  return a2;  /* 0058: retw.n */
}


/* esp_mesh_get_type @ mesh.o 00000014 size 72B bind GLOBAL
 * Calls: none | Data refs: g_is_standalone_sta, g_mesh_is_root, g_is_wifi_connected, g_mesh_ie, g_mesh_max_layer
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=5); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_type(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8, a9;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_is_standalone_sta + 0x0;  /* 0017: l32r -> global */
  a8 = LD8U(a2 + 0x0);  /* 001a */
  a2 = (u32)&g_mesh_is_root + 0x0;  /* 001d: l32r -> global */
  if (a8 == 0) goto L_0030;  /* 0020: beqz.n a8, 30 <esp_mesh_get_type+0x1c> */
  L_0022: __asm__ volatile("" ::: "memory");  /* 0022: memw */
  a2 = LD8U(a2 + 0x0);  /* 0025 */
  a2 = (a2 >> 8) & 0x1;  /* 0028: extui width 1 */
  a2 = a2 + (3);  /* 002b */
  goto L_005a;  /* 002d: j */
  L_0030: __asm__ volatile("" ::: "memory");  /* 0030: memw */
  a8 = LD8U(a2 + 0x0);  /* 0033 */
  a2 = 1;  /* 0036 */
  a8 = (a8 >> 8) & 0x1;  /* 0038: extui width 1 */
  if (a8 != 0) goto L_005a;  /* 003b: bnez.n a8, 5a <esp_mesh_get_type+0x46> */
  L_003d: a2 = (u32)&g_is_wifi_connected + 0x0;  /* 003d: l32r -> global */
  a9 = LD8U(a2 + 0x0);  /* 0040 */
  a2 = a8;  /* 0043 */
  if (a9 == 0) goto L_005a;  /* 0045: beqz.n a9, 5a <esp_mesh_get_type+0x46> */
  L_0047: a2 = (u32)&g_mesh_ie + 0x0;  /* 0047: l32r -> global */
  a9 = LD8U(a2 + 0xf);  /* 004a */
  a2 = (u32)&g_mesh_max_layer + 0x0;  /* 004d: l32r -> global */
  a8 = LD16U(a2 + 0x0);  /* 0050 */
  a2 = 2;  /* 0053 */
  if (a9 < a8) goto L_005a;  /* 0055: bltu a9, a8, 5a <esp_mesh_get_type+0x46> */
  L_0058: a2 = 3;  /* 0058 */
  L_005a: return a2;  /* 005a: retw.n */
}


/* esp_mesh_get_vote_percentage @ mesh.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_mesh_cfg_vote_percent
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_vote_percentage(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_cfg_vote_percent + 0x0;  /* 0007: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 000a */
  return a2;  /* 000c: retw.n */
}


/* esp_mesh_get_xon_qsize @ mesh.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_mesh_xon_cfg_qsize
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_get_xon_qsize(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0007: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 000a */
  return a2;  /* 000c: retw.n */
}


/* esp_mesh_ie_init @ mesh.o 00000048 size 238B bind GLOBAL
 * Calls: esp_mesh_set_ie_crypto_funcs_internal, esp_mesh_set_ie_crypto_key_internal, is_my_ie_encrypted, esp_wifi_vnd_mesh_init, memset, esp_wifi_vnd_mesh_get, memcpy, esp_wifi_vnd_mesh_set | Data refs: .bss.s_mesh_ext_crypto_config, mesh_tx_cb, mesh_init_cb, g_mesh_ie, g_mesh_chain, g_mesh_ext_cfg, g_mesh_topology, g_mesh_max_layer
 * Fidelity: medium - straight goto-form mapping; all calls/constants captured, no indirects
 * Edges: funcdb-v3 (calls=8, refs=16); reloc-direct=8, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_ie_init(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0048: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&LOCAL__bss_s_mesh_ext_crypto_config + 0x0;  /* 004b: l32r -> .bss.s_mesh_ext_crypto_config (same-object static) */
  a3 = 0;  /* 004e */
  a10 = LD32(a2 + 0x20);  /* 0051 */
  a8 = (u32)&esp_mesh_set_ie_crypto_funcs_internal + 0x0;  /* 0054: l32r -> global */
  a2 = esp_mesh_set_ie_crypto_funcs_internal(a2, a3, a4, a5, a6, a7);  /* 0057: callx a8 via reloc-expand */
  a11 = 32;  /* 005a */
  a10 = a2;  /* 005c */
  a8 = (u32)&esp_mesh_set_ie_crypto_key_internal + 0x0;  /* 005e: l32r -> global */
  a2 = esp_mesh_set_ie_crypto_key_internal(a2, a3, a4, a5, a6, a7);  /* 0061: callx a8 via reloc-expand */
  a8 = (u32)&is_my_ie_encrypted + 0x0;  /* 0064: l32r -> global */
  a2 = is_my_ie_encrypted(a2, a3, a4, a5, a6, a7);  /* 0067: callx a8 via reloc-expand */
  a12 = a10;  /* 006a: mov */
  a11 = (u32)&mesh_tx_cb + 0x0;  /* 006d: l32r -> global */
  a10 = (u32)&mesh_init_cb + 0x0;  /* 0070: l32r -> global */
  a8 = (u32)&esp_wifi_vnd_mesh_init + 0x0;  /* 0073: l32r -> global */
  a2 = esp_wifi_vnd_mesh_init(a2, a3, a4, a5, a6, a7);  /* 0076: callx a8 via reloc-expand */
  a12 = 58;  /* 0079 */
  a11 = 0;  /* 007b */
  a2 = (u32)&g_mesh_ie + 0x0;  /* 007d: l32r -> global */
  a10 = a2;  /* 0080 */
  a8 = (u32)&memset + 0x0;  /* 0082: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0085: callx a8 (libc, via reloc-expand) */
  a10 = a2;  /* 0088 */
  a4 = (u32)&g_mesh_chain + 0x0;  /* 008a: l32r -> global */
  a11 = a4;  /* 008d */
  ST16(a4 + 0x0, a3);  /* 008f */
  ST16(a4 + 0x2, a3);  /* 0092 */
  __asm__ volatile("" ::: "memory");  /* 0095: memw */
  __asm__ volatile("" ::: "memory");  /* 0098: memw */
  a8 = (u32)&esp_wifi_vnd_mesh_get + 0x0;  /* 009b: l32r -> global */
  a2 = esp_wifi_vnd_mesh_get(a2, a3, a4, a5, a6, a7);  /* 009e: callx a8 via reloc-expand */
  a12 = 6;  /* 00a1 */
  a10 = a2 + (8);  /* 00a3 */
  ST8(a2 + 0x7, a3);  /* 00a5 */
  __asm__ volatile("" ::: "memory");  /* 00a8: memw */
  a3 = (u32)&g_mesh_ext_cfg + 0x0;  /* 00ab: l32r -> global */
  a11 = a3 + a12;  /* 00ae */
  __asm__ volatile("" ::: "memory");  /* 00b0: memw */
  a8 = (u32)&memcpy + 0x0;  /* 00b3: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00b6: callx a8 (libc, via reloc-expand) */
  a5 = (u32)&g_mesh_topology + 0x0;  /* 00b9: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 00bc */
  a5 = 0;  /* 00be */
  if (a6 != a5) goto L_00c9;  /* 00c0: bne a6, a5, c9 <esp_mesh_ie_init+0x81> */
  L_00c3: a5 = (u32)&g_mesh_max_layer + 0x0;  /* 00c3: l32r -> global */
  a5 = LD8U(a5 + 0x0);  /* 00c6 */
  L_00c9: a8 = -120;  /* 00c9 */
  a12 = 6;  /* 00cc */
  a3 = LD8U(a3 + 0xbd);  /* 00ce */
  a10 = (u32)&g_mesh_ie + 0x33;  /* 00d1: l32r -> global */
  ST8(a2 + 0x10, a3);  /* 00d4 */
  a3 = 0;  /* 00d7 */
  a11 = a3;  /* 00da: mov */
  ST8(a2 + 0xe, a5);  /* 00dd */
  a5 = 0;  /* 00e0 */
  ST8(a2 + 0xf, a5);  /* 00e3 */
  ST8(a2 + 0x11, a5);  /* 00e6 */
  ST8(a2 + 0x1a, a3);  /* 00e9 */
  ST8(a2 + 0x1b, a3);  /* 00ec */
  ST8(a2 + 0x1c, a8);  /* 00ef */
  ST8(a2 + 0x1d, a8);  /* 00f2 */
  ST8(a2 + 0x1e, a5);  /* 00f5 */
  ST8(a2 + 0x25, a8);  /* 00f8 */
  ST8(a2 + 0x2c, a8);  /* 00fb */
  ST8(a2 + 0x2d, a5);  /* 00fe */
  __asm__ volatile("" ::: "memory");  /* 0101: memw */
  __asm__ volatile("" ::: "memory");  /* 0104: memw */
  a8 = (u32)&memset + 0x0;  /* 0107: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 010a: callx a8 (libc, via reloc-expand) */
  ST8(a2 + 0x39, a5);  /* 010d */
  __asm__ volatile("" ::: "memory");  /* 0110: memw */
  if (a6 == a3) goto L_011c;  /* 0113: beq a6, a3, 11c <esp_mesh_ie_init+0xd4> */
  L_0116: a3 = (u32)&g_mesh_max_layer + 0x0;  /* 0116: l32r -> global */
  a3 = LD16U(a3 + 0x0);  /* 0119 */
  L_011c: a11 = a4;  /* 011c */
  a10 = a2;  /* 011e */
  ST16(a4 + 0x0, a3);  /* 0120 */
  a3 = 0;  /* 0123 */
  ST16(a4 + 0x2, a3);  /* 0125 */
  __asm__ volatile("" ::: "memory");  /* 0128: memw */
  __asm__ volatile("" ::: "memory");  /* 012b: memw */
  a8 = (u32)&esp_wifi_vnd_mesh_set + 0x0;  /* 012e: l32r -> global */
  a2 = esp_wifi_vnd_mesh_set(a2, a3, a4, a5, a6, a7);  /* 0131: callx a8 via reloc-expand */
  return a2;  /* 0134: retw.n */
}


/* esp_mesh_init @ mesh.o 000000a0 size 449B bind GLOBAL
 * Calls: esp_mesh_get_beacon_interval, esp_wifi_get_mode, esp_mesh_set_beacon_interval, esp_wifi_set_mode, esp_mesh_get_storage, esp_mesh_nvs_init, memset, mesh_set_default_rssi_threshold | indirect[4]: mem[a4+0x48]; mem[a2+0x34]; mem[a4+0x34]; mem[a3+0x38] | Data refs: .bss.g_is_mesh_inited, s_mesh_stop_mutex, g_osi_funcs_p, g_mesh_init_ps_type, mesh_ioctl_sem, .bss.mesh_xmit_sem, g_mesh_ext_cfg, g_mesh_manual_nwk, g_mesh_cfg_attemps, .bss.s_mesh_ext_crypto_config, g_mesh_monitor_parent_beacon_count, g_mesh_cfg_switch_parent +13 more
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=8, refs=33); reloc-direct=8, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_init(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 00a0: entry a1, 48 (frame 48 bytes) */
  a3 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 00a3: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = 0;  /* 00a6 */
  a4 = LD8U(a3 + 0x0);  /* 00a8 */
  ST32(a1 + 0x4, a2);  /* 00ab */
  if (a4 == a2) goto L_00b3;  /* 00ad: beq a4, a2, b3 <esp_mesh_init+0x13> */
  L_00b0: goto L_025c;  /* 00b0: j */
  L_00b3: a2 = (u32)&s_mesh_stop_mutex + 0x0;  /* 00b3: l32r -> global */
  a4 = LD32(a2 + 0x0);  /* 00b6 */
  if (a4 == 0) goto L_00d0;  /* 00b8: beqz.n a4, d0 <esp_mesh_init+0x30> */
  L_00ba: a10 = a1 + (4);  /* 00ba */
  __asm__ volatile("" ::: "memory");  /* 00bc: memw */
  a8 = (u32)&esp_mesh_get_beacon_interval + 0x0;  /* 00bf: l32r -> global */
  a2 = esp_mesh_get_beacon_interval(a2, a3, a4, a5, a6, a7);  /* 00c2: callx a8 via reloc-expand */
  a2 = 0xffffcfffu;  /* 00c5: l32r = -12289 */
  a10 = a10 + a2;  /* 00c8 */
  if (a10 >= 2u) goto L_00ed;  /* 00ca: bgeui a10, 2, ed <esp_mesh_init+0x4d> */
  L_00cd: goto L_00e7;  /* 00cd: j */
  L_00d0: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00d0: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 00d3 */
  a10 = LD32(a4 + 0x48);  /* 00d6 */
  /* 00d9: INDIRECT callx a10 <- mem[a4+0x48]; result unknown */ a2 = 0;
  ST32(a2 + 0x0, a10);  /* 00dc */
  if (a10 != 0) goto L_00ba;  /* 00de: bnez a10, ba <esp_mesh_init+0x1a> */
  L_00e1: __asm__ volatile("" ::: "memory");  /* 00e1: memw */
  goto L_017b;  /* 00e4: j */
  L_00e7: a2 = 0x00004001u;  /* 00e7: l32r = 16385 */
  goto L_025c;  /* 00ea: j */
  L_00ed: a4 = (u32)&g_mesh_init_ps_type + 0x0;  /* 00ed: l32r -> global */
  a10 = 100;  /* 00f0 */
  a5 = LD32(a4 + 0x0);  /* 00f3 */
  a4 = 0x12c;  /* 00f5 */
  if (a5 != 0) a10 = a4;  /* 00f8 */
  a4 = LD32(a1 + 0x4);  /* 00fb */
  if (a4 != a10) goto L_010d;  /* 00fd: bne a4, a10, 10d <esp_mesh_init+0x6d> */
  L_0100: a10 = a1;  /* 0100 */
  a8 = (u32)&esp_wifi_get_mode + 0x0;  /* 0102: l32r -> global */
  a2 = esp_wifi_get_mode(a2, a3, a4, a5, a6, a7);  /* 0105: callx a8 via reloc-expand */
  if (a10 == 0) goto L_011c;  /* 0108: beqz.n a10, 11c <esp_mesh_init+0x7c> */
  L_010a: goto L_0121;  /* 010a: j */
  L_010d: a8 = (u32)&esp_mesh_set_beacon_interval + 0x0;  /* 010d: l32r -> global */
  a2 = esp_mesh_set_beacon_interval(a2, a3, a4, a5, a6, a7);  /* 0110: callx a8 via reloc-expand */
  a10 = a10 + a2;  /* 0113 */
  if (a10 >= 2u) goto L_0100;  /* 0115: bgeui a10, 2, 100 <esp_mesh_init+0x60> */
  L_0118: goto L_00e7;  /* 0118: j */
  L_011c: a2 = LD32(a1 + 0x0);  /* 011c */
  if (a2 == 3) goto L_0129;  /* 011e: beqi a2, 3, 129 <esp_mesh_init+0x89> */
  L_0121: a10 = 3;  /* 0121 */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 0123: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 0126: callx a8 via reloc-expand */
  L_0129: a8 = (u32)&esp_mesh_get_storage + 0x0;  /* 0129: l32r -> global */
  a2 = esp_mesh_get_storage(a2, a3, a4, a5, a6, a7);  /* 012c: callx a8 via reloc-expand */
  if (a10 == 0) goto L_014d;  /* 012f: beqz.n a10, 14d <esp_mesh_init+0xad> */
  L_0131: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0131: l32r -> global */
  a11 = 0;  /* 0134 */
  a10 = 1;  /* 0136 */
  a2 = LD32(a5 + 0x0);  /* 0138 */
  a2 = LD32(a2 + 0x34);  /* 013a */
  /* 013d: INDIRECT callx a2 <- mem[a2+0x34]; result unknown */ a2 = 0;
  a2 = (u32)&mesh_ioctl_sem + 0x0;  /* 0140: l32r -> global */
  ST32(a2 + 0x0, a10);  /* 0143 */
  if (a10 != 0) goto L_0159;  /* 0145: bnez.n a10, 159 <esp_mesh_init+0xb9> */
  L_0147: __asm__ volatile("" ::: "memory");  /* 0147: memw */
  goto L_017b;  /* 014a: j */
  L_014d: a8 = (u32)&esp_mesh_nvs_init + 0x0;  /* 014d: l32r -> global */
  a2 = esp_mesh_nvs_init(a2, a3, a4, a5, a6, a7);  /* 0150: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0131;  /* 0153: beqz a10, 131 <esp_mesh_init+0x91> */
  L_0156: goto L_017b;  /* 0156: j */
  L_0159: a4 = LD32(a5 + 0x0);  /* 0159 */
  a11 = 0;  /* 015b */
  a10 = 1;  /* 015d */
  a4 = LD32(a4 + 0x34);  /* 015f */
  /* 0161: INDIRECT callx a4 <- mem[a4+0x34]; result unknown */ a2 = 0;
  a4 = a10;  /* 0164 */
  a8 = (u32)&LOCAL__bss_mesh_xmit_sem + 0x0;  /* 0166: l32r -> .bss.mesh_xmit_sem (same-object static) */
  ST32(a8 + 0x0, a10);  /* 0169 */
  if (a10 != 0) goto L_0185;  /* 016b: bnez.n a10, 185 <esp_mesh_init+0xe5> */
  L_016d: a3 = LD32(a5 + 0x0);  /* 016d */
  a10 = LD32(a2 + 0x0);  /* 016f */
  a3 = LD32(a3 + 0x38);  /* 0171 */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  /* 0176: INDIRECT callx a3 <- mem[a3+0x38]; result unknown */ a2 = 0;
  ST32(a2 + 0x0, a4);  /* 0179 */
  L_017b: a2 = -1;  /* 017b */
  __asm__ volatile("" ::: "memory");  /* 017d: memw */
  goto L_025c;  /* 0180: j */
  L_0185: a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0185: l32r -> global */
  a12 = 208;  /* 0188 */
  a11 = 0;  /* 018b */
  a10 = a4;  /* 018d */
  a8 = (u32)&memset + 0x0;  /* 018f: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0192: callx a8 (libc, via reloc-expand) */
  a5 = (u32)&g_mesh_manual_nwk + 0x0;  /* 0195: l32r -> global */
  a2 = 0;  /* 0198 */
  a9 = 10;  /* 019a */
  a12 = 36;  /* 019c */
  a11 = a2;  /* 019e */
  a8 = (u32)&g_mesh_cfg_attemps + 0x0;  /* 01a0: l32r -> global */
  ST32(a5 + 0x0, a2);  /* 01a3 */
  ST32(a5 + 0x4, a2);  /* 01a5 */
  a5 = 15;  /* 01a7 */
  ST32(a8 + 0x4, a5);  /* 01a9 */
  a5 = 60;  /* 01ab */
  ST32(a8 + 0x8, a5);  /* 01ad */
  a10 = (u32)&LOCAL__bss_s_mesh_ext_crypto_config + 0x0;  /* 01af: l32r -> .bss.s_mesh_ext_crypto_config (same-object static) */
  a5 = (u32)&g_mesh_monitor_parent_beacon_count + 0x0;  /* 01b2: l32r -> global */
  ST32(a8 + 0x0, a9);  /* 01b5 */
  ST32(a8 + 0xc, a9);  /* 01b7 */
  ST32(a5 + 0x0, a9);  /* 01b9 */
  __asm__ volatile("" ::: "memory");  /* 01bb: memw */
  a8 = (u32)&memset + 0x0;  /* 01be: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01c1: callx a8 (libc, via reloc-expand) */
  a9 = -78;  /* 01c4 */
  a8 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 01c7: l32r -> global */
  a5 = 0x0000ea60u;  /* 01ca: l32r = 60000 */
  ST32(a8 + 0x0, a5);  /* 01cd */
  a5 = -120;  /* 01cf */
  ST32(a8 + 0x4, a5);  /* 01d2 */
  a5 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 01d4: l32r -> global */
  ST32(a8 + 0x8, a9);  /* 01d7 */
  ST32(a8 + 0xc, a9);  /* 01d9 */
  ST32(a8 + 0x10, a9);  /* 01db */
  a8 = 32;  /* 01dd */
  ST32(a5 + 0x0, a8);  /* 01e0 */
  __asm__ volatile("" ::: "memory");  /* 01e3: memw */
  a8 = (u32)&mesh_set_default_rssi_threshold + 0x0;  /* 01e6: l32r -> global */
  a2 = mesh_set_default_rssi_threshold(a2, a3, a4, a5, a6, a7);  /* 01e9: callx a8 via reloc-expand */
  a5 = (u32)&g_mesh_is_root + 0x0;  /* 01ec: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 01ef: memw */
  ST8(a5 + 0x0, a2);  /* 01f2 */
  a5 = (u32)&g_is_root_fixed + 0x0;  /* 01f5: l32r -> global */
  a8 = (u32)&g_mesh_self_organized + 0x0;  /* 01f8: l32r -> global */
  ST8(a5 + 0x0, a2);  /* 01fb */
  __asm__ volatile("" ::: "memory");  /* 01fe: memw */
  a5 = 1;  /* 0201 */
  __asm__ volatile("" ::: "memory");  /* 0203: memw */
  ST8(a8 + 0x0, a5);  /* 0206 */
  a8 = (u32)&g_is_standalone_sta + 0x0;  /* 0209: l32r -> global */
  a9 = 0x00001770u;  /* 020c: l32r = 6000 */
  ST8(a8 + 0x0, a2);  /* 020f */
  __asm__ volatile("" ::: "memory");  /* 0212: memw */
  a8 = (u32)&g_mesh_root_healing_delay + 0x0;  /* 0215: l32r -> global */
  ST32(a8 + 0x0, a9);  /* 0218 */
  a8 = 0x12c;  /* 021a */
  a9 = (u32)&g_mesh_passive_scan_time + 0x0;  /* 021d: l32r -> global */
  ST32(a9 + 0x0, a8);  /* 0220 */
  a9 = (u32)&g_mesh_rt_capacity + 0x0;  /* 0222: l32r -> global */
  ST32(a9 + 0x0, a8);  /* 0225 */
  a8 = (u32)&g_mesh_cfg_vote_percent + 0x0;  /* 0227: l32r -> global */
  a9 = 0x3f666666u;  /* 022a: l32r = 1063675494 */
  ST32(a8 + 0x0, a9);  /* 022d */
  a9 = 0x1f4;  /* 022f */
  a8 = (u32)&g_mesh_ann_interval + 0x0;  /* 0232: l32r -> global */
  ST32(a8 + 0x0, a9);  /* 0235 */
  a9 = 0x00000bb8u;  /* 0237: l32r = 3000 */
  ST32(a8 + 0x4, a9);  /* 023a */
  a9 = 25;  /* 023c */
  a8 = (u32)&g_mesh_max_layer + 0x0;  /* 023e: l32r -> global */
  ST16(a8 + 0x0, a9);  /* 0241 */
  __asm__ volatile("" ::: "memory");  /* 0244: memw */
  a8 = (u32)&g_mesh_stop_reconnection + 0x0;  /* 0247: l32r -> global */
  ST32(a8 + 0x0, a2);  /* 024a */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 024d: l32r -> global */
  ST8(a4 + 0xbc, a2);  /* 0250 */
  ST32(a8 + 0x0, a2);  /* 0253 */
  ST8(a3 + 0x0, a5);  /* 0256 */
  __asm__ volatile("" ::: "memory");  /* 0259: memw */
  L_025c: __asm__ volatile("" ::: "memory");  /* 025c: memw */
  return a2;  /* 025f: retw.n */
}


/* esp_mesh_insert_group_addr @ mesh.o 00000040 size 256B bind GLOBAL
 * Calls: memcmp, mesh_malloc, memcpy, mesh_free | indirect[3]: mem[a2+0x158]; mem[a2+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.__func__$1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=8); reloc-direct=4, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_insert_group_addr(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0040: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0071;  /* 0043: bnez.n a2, 71 <esp_mesh_insert_group_addr+0x31> */
  L_0045: a2 = (u32)&g_log_level + 0x0;  /* 0045: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0048 */
  a6 = 0x00004008u;  /* 004a: l32r = 16392 */
  if (a2 >= 3u) goto L_0053;  /* 004d: bgeui a2, 3, 53 <esp_mesh_insert_group_addr+0x13> */
  L_0050: goto L_0139;  /* 0050: j */
  L_0053: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0053: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0056 */
  if (a2 == 0) goto L_0139;  /* 0059: beqz a2, 139 <esp_mesh_insert_group_addr+0xf9> */
  L_005c: a3 = LD32(a2 + 0x150);  /* 005c */
  if (a3 == 0) goto L_0139;  /* 005f: beqz a3, 139 <esp_mesh_insert_group_addr+0xf9> */
  L_0062: a10 = LD32(a2 + 0x158);  /* 0062 */
  /* 0065: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0068: -> "mesh" */
  a2 = 0x00000a3bu;  /* 006b: l32r = 2619 */
  goto L_00a6;  /* 006e: j */
  L_0071: if (a3 == 0) goto L_007c;  /* 0071: beqz.n a3, 7c <esp_mesh_insert_group_addr+0x3c> */
  L_0073: a4 = LD32(a2 + 0x0);  /* 0073 */
  a5 = 0;  /* 0075 */
  a7 = 6;  /* 0077 */
  goto L_00d9;  /* 0079: j */
  L_007c: a2 = (u32)&g_log_level + 0x0;  /* 007c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 007f */
  a6 = 0x00004008u;  /* 0082: l32r = 16392 */
  if (a2 >= 3u) goto L_008b;  /* 0085: bgeui a2, 3, 8b <esp_mesh_insert_group_addr+0x4b> */
  L_0088: goto L_0139;  /* 0088: j */
  L_008b: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 008b: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 008e */
  if (a2 == 0) goto L_0139;  /* 0091: beqz a2, 139 <esp_mesh_insert_group_addr+0xf9> */
  L_0094: a3 = LD32(a2 + 0x150);  /* 0094 */
  if (a3 == 0) goto L_0139;  /* 0097: beqz a3, 139 <esp_mesh_insert_group_addr+0xf9> */
  L_009a: a10 = LD32(a2 + 0x158);  /* 009a */
  /* 009d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a0: -> "mesh" */
  a2 = 0x00000a3cu;  /* 00a3: l32r = 2620 */
  L_00a6: a13 = a10;  /* 00a6 */
  a14 = a11;  /* 00a8 */
  a10 = 3;  /* 00aa */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00ad: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b0: -> "mesh" */
  ST32(a1 + 0x0, a2);  /* 00b3 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  /* 00b9: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0139;  /* 00bc: j */
  L_00c0: a6 = LD32(a2 + 0x4);  /* 00c0 */
  a10 = a5 + (a5 << 1);  /* 00c2 */
  a10 = a10 + (a6 << 1);  /* 00c5 */
  a12 = a7;  /* 00c8 */
  a11 = a3;  /* 00ca */
  a8 = (u32)&memcmp + 0x0;  /* 00cc: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00cf: callx a8 (libc, via reloc-expand) */
  a6 = a10;  /* 00d2 */
  if (a10 == 0) goto L_0139;  /* 00d4: beqz a10, 139 <esp_mesh_insert_group_addr+0xf9> */
  L_00d7: a5 = a5 + (1);  /* 00d7 */
  L_00d9: if ((i32)a5 < (i32)a4) goto L_00c0;  /* 00d9: blt a5, a4, c0 <esp_mesh_insert_group_addr+0x80> */
  L_00dc: a5 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 00dc: l32r -> .rodata.__func__$1 */
  a4 = a4 + (1);  /* 00df */
  a4 = a4 + (a4 << 1);  /* 00e1 */
  a12 = 0x149;  /* 00e4 */
  a10 = a4 + a4;  /* 00e7 */
  a12 = a12 << 3;  /* 00ea */
  a11 = a5;  /* 00ed: mov */
  a8 = (u32)&mesh_malloc + 0x0;  /* 00f0: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 00f3: callx a8 via reloc-expand */
  a4 = a10;  /* 00f6 */
  a6 = 0x00004007u;  /* 00f8: l32r = 16391 */
  if (a10 == 0) goto L_0139;  /* 00fb: beqz.n a10, 139 <esp_mesh_insert_group_addr+0xf9> */
  L_00fd: a12 = LD32(a2 + 0x0);  /* 00fd */
  if (a12 == 0) goto L_011d;  /* 00ff: beqz.n a12, 11d <esp_mesh_insert_group_addr+0xdd> */
  L_0101: a11 = LD32(a2 + 0x4);  /* 0101 */
  if (a11 == 0) goto L_011d;  /* 0103: beqz.n a11, 11d <esp_mesh_insert_group_addr+0xdd> */
  L_0105: a12 = a12 + (a12 << 1);  /* 0105 */
  a12 = a12 + a12;  /* 0108 */
  a8 = (u32)&memcpy + 0x0;  /* 010a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 010d: callx a8 (libc, via reloc-expand) */
  a12 = 0x00000a4du;  /* 0110: l32r = 2637 */
  a11 = a5;  /* 0113 */
  a10 = LD32(a2 + 0x4);  /* 0115 */
  a8 = (u32)&mesh_free + 0x0;  /* 0117: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 011a: callx a8 via reloc-expand */
  L_011d: a11 = a3;  /* 011d */
  a12 = 6;  /* 011f */
  a10 = LD32(a2 + 0x0);  /* 0121 */
  a6 = 0;  /* 0123 */
  a10 = a10 + (a10 << 1);  /* 0125 */
  a10 = a10 + (a4 << 1);  /* 0128 */
  a8 = (u32)&memcpy + 0x0;  /* 012b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 012e: callx a8 (libc, via reloc-expand) */
  a3 = LD32(a2 + 0x0);  /* 0131 */
  a3 = a3 + (1);  /* 0133 */
  ST32(a2 + 0x4, a4);  /* 0135 */
  ST32(a2 + 0x0, a3);  /* 0137 */
  L_0139: a2 = a6;  /* 0139 */
  __asm__ volatile("" ::: "memory");  /* 013b: memw */
  return a2;  /* 013e: retw.n */
}


/* esp_mesh_is_device_active @ mesh.o 0000000c size 38B bind GLOBAL
 * Calls: esp_mesh_get_layer, pm_is_waked | Data refs: g_mesh_is_root
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_is_device_active(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&esp_mesh_get_layer;  /* 000f: l32r -> func addr */
  a2 = esp_mesh_get_layer(a2, a3, a4, a5, a6, a7);  /* 0012: callx a8 via reloc-expand */
  a2 = 1;  /* 0015 */
  if (a10 == -1) goto L_0030;  /* 0017: beqi a10, -1, 30 <esp_mesh_is_device_active+0x24> */
  L_001a: a2 = (u32)&g_mesh_is_root + 0x0;  /* 001a: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 001d: memw */
  a2 = LD8U(a2 + 0x0);  /* 0020 */
  a2 = (a2 >> 8) & 0x1;  /* 0023: extui width 1 */
  if (a2 != 0) goto L_0030;  /* 0026: bnez.n a2, 30 <esp_mesh_is_device_active+0x24> */
  L_0028: a8 = (u32)&pm_is_waked + 0x0;  /* 0028: l32r -> global */
  a2 = pm_is_waked(a2, a3, a4, a5, a6, a7);  /* 002b: callx a8 via reloc-expand */
  a2 = a10;  /* 002e */
  L_0030: return a2;  /* 0030: retw.n */
}


/* esp_mesh_is_my_group @ mesh.o 00000008 size 48B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.s_mesh_group_addr
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_is_my_group(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&LOCAL__bss_s_mesh_group_addr + 0x0;  /* 000b: l32r -> .bss.s_mesh_group_addr (same-object static) */
  a6 = 6;  /* 000e */
  a5 = LD32(a3 + 0x0);  /* 0010 */
  a4 = LD32(a3 + 0x4);  /* 0012 */
  a3 = 0;  /* 0014 */
  goto L_002b;  /* 0016: j */
  L_0019: a10 = a4;  /* 0019 */
  a12 = a6;  /* 001b */
  a11 = a2;  /* 001d */
  a8 = (u32)&memcmp + 0x0;  /* 001f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0022: callx a8 (libc, via reloc-expand) */
  a4 = a4 + (6);  /* 0025 */
  if (a10 == 0) goto L_0034;  /* 0027: beqz.n a10, 34 <esp_mesh_is_my_group+0x2c> */
  L_0029: a3 = a3 + (1);  /* 0029 */
  L_002b: if ((i32)a3 < (i32)a5) goto L_0019;  /* 002b: blt a3, a5, 19 <esp_mesh_is_my_group+0x11> */
  L_002e: a2 = 0;  /* 002e */
  goto L_0036;  /* 0030: j */
  L_0034: a2 = 1;  /* 0034 */
  L_0036: return a2;  /* 0036: retw.n */
}


/* esp_mesh_is_my_ie_encrypted @ mesh.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: .bss.s_mesh_ext_crypto_config
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_is_my_ie_encrypted(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&LOCAL__bss_s_mesh_ext_crypto_config + 0x0;  /* 0007: l32r -> .bss.s_mesh_ext_crypto_config (same-object static) */
  a8 = 0;  /* 000a */
  a9 = LD32(a2 + 0x20);  /* 000c */
  a2 = 1;  /* 000e */
  if (a9 == 0) a2 = a8;  /* 0010 */
  return a2;  /* 0013: retw.n */
}


/* esp_mesh_is_ps_enabled @ mesh.o 0000000c size 53B bind GLOBAL
 * Calls: esp_wifi_get_ps | Data refs: g_is_mesh_started, g_mesh_init_ps_type
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=3); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_is_ps_enabled(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 000f: l32r -> global */
  a3 = LD8U(a2 + 0x0);  /* 0012 */
  if (a3 == 0) goto L_0029;  /* 0015: beqz.n a3, 29 <esp_mesh_is_ps_enabled+0x1d> */
  L_0017: a3 = 0;  /* 0017 */
  a2 = (u32)&g_mesh_init_ps_type + 0x0;  /* 0019: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 001c */
  a2 = 1;  /* 001e */
  if (a8 == 0) a2 = a3;  /* 0020 */
  a2 = (a2 >> 8) & 0x1;  /* 0023: extui width 1 */
  goto L_003f;  /* 0026: j */
  L_0029: a10 = a1;  /* 0029 */
  ST32(a1 + 0x0, a3);  /* 002b */
  __asm__ volatile("" ::: "memory");  /* 002d: memw */
  a8 = (u32)&esp_wifi_get_ps + 0x0;  /* 0030: l32r -> global */
  a2 = esp_wifi_get_ps(a2, a3, a4, a5, a6, a7);  /* 0033: callx a8 via reloc-expand */
  a2 = 1;  /* 0036 */
  a8 = LD32(a1 + 0x0);  /* 0038 */
  a8 = a8 + (-1);  /* 003a */
  if (a8 != 0) a2 = a3;  /* 003c */
  L_003f: return a2;  /* 003f: retw.n */
}


/* esp_mesh_is_root @ mesh.o 0000000c size 39B bind GLOBAL
 * Calls: none | Data refs: g_is_mesh_started, g_mesh_self_organized, g_mesh_is_root
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_is_root(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 000f: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0012 */
  if (a2 != 0) goto L_0025;  /* 0015: bnez.n a2, 25 <esp_mesh_is_root+0x19> */
  L_0017: a8 = (u32)&g_mesh_self_organized + 0x0;  /* 0017: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 001a: memw */
  a8 = LD8U(a8 + 0x0);  /* 001d */
  a8 = (a8 >> 8) & 0x1;  /* 0020: extui width 1 */
  if (a8 != 0) goto L_0031;  /* 0023: bnez.n a8, 31 <esp_mesh_is_root+0x25> */
  L_0025: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0025: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0028: memw */
  a2 = LD8U(a2 + 0x0);  /* 002b */
  a2 = (a2 >> 8) & 0x1;  /* 002e: extui width 1 */
  L_0031: return a2;  /* 0031: retw.n */
}


/* esp_mesh_is_root_fixed @ mesh.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_is_root_fixed
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_is_root_fixed(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_is_root_fixed + 0x0;  /* 0007: l32r -> global */
  a2 = LD8U(a8 + 0x0);  /* 000a */
  return a2;  /* 000d: retw.n */
}


/* esp_mesh_look_for_network @ mesh.o 00000018 size 72B bind GLOBAL
 * Calls: memset, esp_mesh_is_nwk_inited, mesh_look_for_network, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[1]: mem[a8+0xa4] | Data refs: g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=6); reloc-direct=5, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_look_for_network(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0018: entry a1, 64 (frame 64 bytes) */
  a12 = 20;  /* 001b */
  a11 = 0;  /* 001d */
  a10 = a1;  /* 0020 */
  a8 = (u32)&memset + 0x0;  /* 0022: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0025: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 0028: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 002b: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0039;  /* 002e: bnez.n a10, 39 <esp_mesh_look_for_network+0x21> */
  L_0030: a8 = (u32)&mesh_look_for_network + 0x0;  /* 0030: l32r -> global */
  a2 = mesh_look_for_network(a2, a3, a4, a5, a6, a7);  /* 0033: callx a8 via reloc-expand */
  goto L_005c;  /* 0036: j */
  L_0039: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0039: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 003c */
  a10 = LD32(a8 + 0xa4);  /* 003e */
  /* 0041: INDIRECT callx a10 <- mem[a8+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 0044: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 0047: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0030;  /* 004a: bnez a10, 30 <esp_mesh_look_for_network+0x18> */
  L_004d: a8 = 11;  /* 004d */
  a10 = a1;  /* 004f */
  ST32(a1 + 0x0, a8);  /* 0051 */
  __asm__ volatile("" ::: "memory");  /* 0053: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 0056: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 0059: callx a8 via reloc-expand */
  L_005c: a2 = a10;  /* 005c */
  return a2;  /* 005e: retw.n */
}


/* esp_mesh_print_rxQ_waiting @ mesh.o 00000044 size 440B bind GLOBAL
 * Calls: esp_mesh_is_root | indirect[12]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x78]; mem[a4+0x78] | Data refs: g_log_level, g_is_mesh_started, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, mesh_tcpip_mbox, mesh_myself_mbox, g_mesh_xon_cfg_qsize, .bss.s_extra_toSelf_qsize, .bss.s_extra_toDS_qsize, .rodata.esp_mesh_print_rxQ_waiting.str1.1
 * Fidelity: medium - 12 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=11); reloc-direct=1, funcdb-attributed=0, unknown-indirect=12 */
u32 esp_mesh_print_rxQ_waiting(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a7, a8, a9;
  float F8;
  /* 0044: entry a1, 80 (frame 80 bytes) */
  a2 = (u32)&g_log_level + 0x0;  /* 0047: l32r -> global */
  a4 = LD32(a2 + 0x0);  /* 004a */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 004c: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 004f */
  if (a2 != 0) goto L_0085;  /* 0052: bnez.n a2, 85 <esp_mesh_print_rxQ_waiting+0x41> */
  L_0054: a7 = 0x00004004u;  /* 0054: l32r = 16388 */
  if (a4 >= 3u) goto L_005d;  /* 0057: bgeui a4, 3, 5d <esp_mesh_print_rxQ_waiting+0x19> */
  L_005a: goto L_01f8;  /* 005a: j */
  L_005d: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 005d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0060 */
  if (a2 == 0) goto L_01f8;  /* 0062: beqz a2, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_0065: a3 = LD32(a2 + 0x150);  /* 0065 */
  if (a3 == 0) goto L_01f8;  /* 0068: beqz a3, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_006b: a10 = LD32(a2 + 0x158);  /* 006b */
  /* 006e: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0071 */
  a10 = 3;  /* 0073 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0075: -> "mesh" */
  a14 = a11;  /* 0078 */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 007a: -> "mesh" */
  /* 007d: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_01f8;  /* 0080: j */
  L_0085: a3 = (u32)&mesh_tcpip_mbox + 0x0;  /* 0085: l32r -> global */
  a2 = LD32(a3 + 0x0);  /* 0088 */
  if (a2 != 0) goto L_00b5;  /* 008a: bnez.n a2, b5 <esp_mesh_print_rxQ_waiting+0x71> */
  L_008c: a7 = 0x00004008u;  /* 008c: l32r = 16392 */
  if (a4 >= 3u) goto L_0095;  /* 008f: bgeui a4, 3, 95 <esp_mesh_print_rxQ_waiting+0x51> */
  L_0092: goto L_01f8;  /* 0092: j */
  L_0095: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0095: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0098 */
  if (a2 == 0) goto L_01f8;  /* 009a: beqz a2, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_009d: a3 = LD32(a2 + 0x150);  /* 009d */
  if (a3 == 0) goto L_01f8;  /* 00a0: beqz a3, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_00a3: a10 = LD32(a2 + 0x158);  /* 00a3 */
  a2 = 116;  /* 00a6 */
  /* 00a9: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00ac: -> "mesh" */
  goto L_00e0;  /* 00af: j */
  L_00b5: a3 = (u32)&mesh_myself_mbox + 0x0;  /* 00b5: l32r -> global */
  a2 = LD32(a3 + 0x0);  /* 00b8 */
  if (a2 != 0) goto L_00f8;  /* 00ba: bnez.n a2, f8 <esp_mesh_print_rxQ_waiting+0xb4> */
  L_00bc: a7 = 0x00004008u;  /* 00bc: l32r = 16392 */
  if (a4 >= 3u) goto L_00c5;  /* 00bf: bgeui a4, 3, c5 <esp_mesh_print_rxQ_waiting+0x81> */
  L_00c2: goto L_01f8;  /* 00c2: j */
  L_00c5: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00c5: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00c8 */
  if (a2 == 0) goto L_01f8;  /* 00cb: beqz a2, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_00ce: a3 = LD32(a2 + 0x150);  /* 00ce */
  if (a3 == 0) goto L_01f8;  /* 00d1: beqz a3, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_00d4: a10 = LD32(a2 + 0x158);  /* 00d4 */
  a2 = 117;  /* 00d7 */
  /* 00da: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00dd: -> "mesh" */
  L_00e0: a13 = a10;  /* 00e0 */
  a14 = a11;  /* 00e2 */
  a10 = 3;  /* 00e4 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00e6: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00e9: -> "mesh" */
  ST32(a1 + 0x0, a2);  /* 00ec */
  __asm__ volatile("" ::: "memory");  /* 00ee: memw */
  /* 00f1: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_01f8;  /* 00f4: j */
  L_00f8: a8 = (u32)&esp_mesh_is_root;  /* 00f8: l32r -> func addr */
  a2 = esp_mesh_is_root(a2, a3, a4, a5, a6);  /* 00fb: callx a8 via reloc-expand */
  a2 = a10;  /* 00fe */
  if (a10 == 0) goto L_01a0;  /* 0100: beqz a10, 1a0 <esp_mesh_print_rxQ_waiting+0x15c> */
  L_0103: a7 = 0;  /* 0103 */
  if (a4 >= 3u) goto L_010b;  /* 0105: bgeui a4, 3, 10b <esp_mesh_print_rxQ_waiting+0xc7> */
  L_0108: goto L_01f8;  /* 0108: j */
  L_010b: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 010b: l32r -> global */
  a2 = LD32(a4 + 0x0);  /* 010e */
  if (a2 != a7) goto L_0117;  /* 0111: bne a2, a7, 117 <esp_mesh_print_rxQ_waiting+0xd3> */
  L_0114: goto L_01f8;  /* 0114: j */
  L_0117: a5 = LD32(a2 + 0x150);  /* 0117 */
  if (a5 != a7) goto L_0120;  /* 011a: bne a5, a7, 120 <esp_mesh_print_rxQ_waiting+0xdc> */
  L_011d: goto L_01f8;  /* 011d: j */
  L_0120: a10 = LD32(a2 + 0x158);  /* 0120 */
  /* 0123: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 0126 */
  a8 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0128: l32r -> global */
  a6 = LD32(a8 + 0x0);  /* 012b */
  a8 = (u32)&LOCAL__bss_s_extra_toSelf_qsize + 0x0;  /* 012d: l32r -> .bss.s_extra_toSelf_qsize (same-object static) */
  a8 = LD32(a8 + 0x0);  /* 0130 */
  a10 = LD32(a3 + 0x0);  /* 0132 */
  ST32(a1 + 0x20, a8);  /* 0134 */
  a8 = a6 + a8;  /* 0136 */
  ST32(a1 + 0x24, a8);  /* 0138 */
  if (a10 == a7) goto L_014d;  /* 013b: beq a10, a7, 14d <esp_mesh_print_rxQ_waiting+0x109> */
  L_013e: a3 = LD32(a4 + 0x0);  /* 013e */
  a3 = LD32(a3 + 0x78);  /* 0141 */
  __asm__ volatile("" ::: "memory");  /* 0144: memw */
  /* 0147: INDIRECT callx a3 <- mem[a3+0x78]; result unknown */ a2 = 0;
  a7 = a10;  /* 014a: mov */
  L_014d: a10 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 014d: l32r -> global */
  a9 = (u32)&LOCAL__bss_s_extra_toDS_qsize + 0x0;  /* 0150: l32r -> .bss.s_extra_toDS_qsize (same-object static) */
  a8 = LD32(a10 + 0x0);  /* 0153 */
  a10 = (u32)&mesh_tcpip_mbox + 0x0;  /* 0155: l32r -> global */
  a9 = LD32(a9 + 0x0);  /* 0158 */
  a3 = a8 + a9;  /* 015a */
  a11 = LD32(a10 + 0x0);  /* 015c */
  a10 = 0;  /* 015e */
  if (a11 == a10) goto L_0178;  /* 0160: beq a11, a10, 178 <esp_mesh_print_rxQ_waiting+0x134> */
  L_0163: a10 = a11;  /* 0163 */
  a4 = LD32(a4 + 0x0);  /* 0165 */
  a4 = LD32(a4 + 0x78);  /* 0167 */
  ST32(a1 + 0x28, a8);  /* 016a */
  ST32(a1 + 0x2c, a9);  /* 016c */
  __asm__ volatile("" ::: "memory");  /* 016e: memw */
  /* 0171: INDIRECT callx a4 <- mem[a4+0x78]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x2c);  /* 0174 */
  a8 = LD32(a1 + 0x28);  /* 0176 */
  L_0178: a13 = a2;  /* 0178 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 017a: -> "mesh" */
  a14 = a11;  /* 017d */
  ST32(a1 + 0xc, a3);  /* 017f */
  a3 = LD32(a1 + 0x20);  /* 0181 */
  a15 = LD32(a1 + 0x24);  /* 0183 */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_rxQ_waiting_str1_1 + 0x0);  /* 0185: l32r -> .rodata.esp_mesh_print_rxQ_waiting.str1.1 */
  ST32(a1 + 0x18, a10);  /* 0188 */
  a10 = 3;  /* 018a */
  ST32(a1 + 0x14, a9);  /* 018c */
  ST32(a1 + 0x10, a8);  /* 018e */
  ST32(a1 + 0x8, a7);  /* 0190 */
  ST32(a1 + 0x4, a3);  /* 0192 */
  ST32(a1 + 0x0, a6);  /* 0194 */
  __asm__ volatile("" ::: "memory");  /* 0196: memw */
  /* 0199: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  goto L_01f6;  /* 019c: j */
  L_01a0: a7 = a10;  /* 01a0 */
  if (a4 < 3u) goto L_01f8;  /* 01a2: bltui a4, 3, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_01a5: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 01a5: l32r -> global */
  a6 = LD32(a5 + 0x0);  /* 01a8 */
  if (a6 == 0) goto L_01f8;  /* 01aa: beqz a6, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_01ad: a4 = LD32(a6 + 0x150);  /* 01ad */
  if (a4 == 0) goto L_01f8;  /* 01b0: beqz a4, 1f8 <esp_mesh_print_rxQ_waiting+0x1b4> */
  L_01b3: a10 = LD32(a6 + 0x158);  /* 01b3 */
  /* 01b6: INDIRECT callx a10 <- mem[a6+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01b9 */
  a6 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 01bb: l32r -> global */
  a7 = (u32)&LOCAL__bss_s_extra_toSelf_qsize + 0x0;  /* 01be: l32r -> .bss.s_extra_toSelf_qsize (same-object static) */
  a6 = LD32(a6 + 0x0);  /* 01c1 */
  a7 = LD32(a7 + 0x0);  /* 01c3 */
  a15 = a6 + a7;  /* 01c5 */
  a10 = LD32(a3 + 0x0);  /* 01c7 */
  if (a10 == 0) goto L_01e0;  /* 01c9: beqz.n a10, 1e0 <esp_mesh_print_rxQ_waiting+0x19c> */
  L_01cb: a2 = LD32(a5 + 0x0);  /* 01cb */
  a2 = LD32(a2 + 0x78);  /* 01cd */
  ST32(a1 + 0x28, a13);  /* 01d0 */
  ST32(a1 + 0x2c, a15);  /* 01d2 */
  __asm__ volatile("" ::: "memory");  /* 01d4: memw */
  /* 01d7: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a2 = a10;  /* 01da */
  a15 = LD32(a1 + 0x2c);  /* 01dc */
  a13 = LD32(a1 + 0x28);  /* 01de */
  L_01e0: a10 = 3;  /* 01e0 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 01e2: -> "mesh" */
  a14 = a11;  /* 01e5 */
  a12 = (u32)(RODATA__rodata_esp_mesh_print_rxQ_waiting_str1_1 + 0x0);  /* 01e7: l32r -> .rodata.esp_mesh_print_rxQ_waiting.str1.1 */
  ST32(a1 + 0x8, a2);  /* 01ea */
  ST32(a1 + 0x4, a7);  /* 01ec */
  ST32(a1 + 0x0, a6);  /* 01ee */
  __asm__ volatile("" ::: "memory");  /* 01f0: memw */
  /* 01f3: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_01f6: a7 = 0;  /* 01f6 */
  L_01f8: a2 = a7;  /* 01f8 */
  return a2;  /* 01fa: retw.n */
}


/* esp_mesh_ps_get_duties @ mesh.o 00000034 size 182B bind GLOBAL
 * Calls: esp_mesh_is_nwk_running, mesh_ps_get_duties, mesh_set_io_process | indirect[5]: mem[a8+0x158]; mem[a8+0x150]; mem[a3+0xa4] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=7); reloc-direct=3, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_ps_get_duties(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0034: entry a1, 80 (frame 80 bytes) */
  a3 = (u32)&g_is_mesh_started + 0x0;  /* 0037: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 003a */
  if (a3 != 0) goto L_0075;  /* 003d: bnez.n a3, 75 <esp_mesh_ps_get_duties+0x41> */
  L_003f: a2 = (u32)&g_log_level + 0x0;  /* 003f: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0042 */
  a2 = 0x00004004u;  /* 0044: l32r = 16388 */
  if (a3 >= 3u) goto L_004d;  /* 0047: bgeui a3, 3, 4d <esp_mesh_ps_get_duties+0x19> */
  L_004a: goto L_00e8;  /* 004a: j */
  L_004d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 004d: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0050 */
  if (a8 == 0) goto L_00e8;  /* 0052: beqz a8, e8 <esp_mesh_ps_get_duties+0xb4> */
  L_0055: a3 = LD32(a8 + 0x150);  /* 0055 */
  if (a3 == 0) goto L_00e8;  /* 0058: beqz a3, e8 <esp_mesh_ps_get_duties+0xb4> */
  L_005b: a10 = LD32(a8 + 0x158);  /* 005b */
  /* 005e: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0061 */
  a10 = 3;  /* 0063 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0065: -> "mesh" */
  a14 = a11;  /* 0068 */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 006a: -> "mesh" */
  /* 006d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00e8;  /* 0070: j */
  L_0075: if (a2 != 0) goto L_00b5;  /* 0075: bnez.n a2, b5 <esp_mesh_ps_get_duties+0x81> */
  L_0077: a2 = (u32)&g_log_level + 0x0;  /* 0077: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 007a */
  a2 = 0x00004008u;  /* 007c: l32r = 16392 */
  if (a3 < 3u) goto L_00e8;  /* 007f: bltui a3, 3, e8 <esp_mesh_ps_get_duties+0xb4> */
  L_0082: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0082: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0085 */
  if (a8 == 0) goto L_00e8;  /* 0087: beqz a8, e8 <esp_mesh_ps_get_duties+0xb4> */
  L_008a: a3 = LD32(a8 + 0x150);  /* 008a */
  if (a3 == 0) goto L_00e8;  /* 008d: beqz a3, e8 <esp_mesh_ps_get_duties+0xb4> */
  L_0090: a10 = LD32(a8 + 0x158);  /* 0090 */
  /* 0093: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0096 */
  a10 = 3;  /* 0098 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 009a: -> "mesh" */
  a14 = a11;  /* 009d */
  a8 = 0x00000c28u;  /* 009f: l32r = 3112 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a2: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a5: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 00a8 */
  __asm__ volatile("" ::: "memory");  /* 00aa: memw */
  /* 00ad: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00e8;  /* 00b0: j */
  L_00b5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b5: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00b8 */
  a10 = LD32(a3 + 0xa4);  /* 00ba */
  /* 00bd: INDIRECT callx a10 <- mem[a3+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 00c0: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 00c3: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00d4;  /* 00c6: beqz.n a10, d4 <esp_mesh_ps_get_duties+0xa0> */
  L_00c8: a10 = a2;  /* 00c8 */
  a8 = (u32)&mesh_ps_get_duties + 0x0;  /* 00ca: l32r -> global */
  a2 = mesh_ps_get_duties(a2, a3, a4, a5, a6, a7);  /* 00cd: callx a8 via reloc-expand */
  goto L_00e6;  /* 00d0: j */
  L_00d4: a3 = 12;  /* 00d4 */
  a10 = a1 + (16);  /* 00d6 */
  ST32(a1 + 0x10, a3);  /* 00d9 */
  ST32(a1 + 0x14, a2);  /* 00db */
  __asm__ volatile("" ::: "memory");  /* 00dd: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 00e0: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 00e3: callx a8 via reloc-expand */
  L_00e6: a2 = a10;  /* 00e6 */
  L_00e8: return a2;  /* 00e8: retw.n */
}


/* esp_mesh_push_to_myself_queue @ mesh.o 0000004c size 466B bind GLOBAL
 * Calls: esp_mesh_txupQ_pending | indirect[8]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x78]; mem[a2+0x6c] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, mesh_myself_mbox, .bss.s_extra_toSelf_qsize, .rodata.__func__$5, g_mesh_xon_cfg_qsize
 * Fidelity: medium - 8 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=9); reloc-direct=1, funcdb-attributed=0, unknown-indirect=8 */
u32 esp_mesh_push_to_myself_queue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0, F0000001;
  /* 004c: entry a1, 48 (frame 48 bytes) */
  a5 = a2;  /* 004f */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 0051: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0054 */
  if (a2 != 0) goto L_0091;  /* 0057: bnez.n a2, 91 <esp_mesh_push_to_myself_queue+0x45> */
  L_0059: a2 = (u32)&g_log_level + 0x0;  /* 0059: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005c */
  a2 = 0x00004004u;  /* 005f: l32r = 16388 */
  if (a3 >= 3u) goto L_0068;  /* 0062: bgeui a3, 3, 68 <esp_mesh_push_to_myself_queue+0x1c> */
  L_0065: goto L_021c;  /* 0065: j */
  L_0068: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0068: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006b */
  if (a3 == 0) goto L_021c;  /* 006e: beqz a3, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_0071: a4 = LD32(a3 + 0x150);  /* 0071 */
  if (a4 == 0) goto L_021c;  /* 0074: beqz a4, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_0077: a10 = LD32(a3 + 0x158);  /* 0077 */
  /* 007a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 007d */
  a10 = 3;  /* 007f */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0081: -> "mesh" */
  a14 = a11;  /* 0084 */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0086: -> "mesh" */
  /* 0089: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_021c;  /* 008c: j */
  L_0091: if (a5 != 0) goto L_00c1;  /* 0091: bnez.n a5, c1 <esp_mesh_push_to_myself_queue+0x75> */
  L_0093: a2 = (u32)&g_log_level + 0x0;  /* 0093: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0096 */
  a2 = 0x00004008u;  /* 0098: l32r = 16392 */
  if (a3 >= 3u) goto L_00a1;  /* 009b: bgeui a3, 3, a1 <esp_mesh_push_to_myself_queue+0x55> */
  L_009e: goto L_021c;  /* 009e: j */
  L_00a1: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a1: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a4 */
  if (a3 == 0) goto L_021c;  /* 00a6: beqz a3, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_00a9: a4 = LD32(a3 + 0x150);  /* 00a9 */
  if (a4 == 0) goto L_021c;  /* 00ac: beqz a4, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_00af: a10 = LD32(a3 + 0x158);  /* 00af */
  a3 = 0x775;  /* 00b2 */
  /* 00b5: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b8: -> "mesh" */
  goto L_00f0;  /* 00bb: j */
  L_00c1: a6 = (u32)&mesh_myself_mbox + 0x0;  /* 00c1: l32r -> global */
  a2 = LD32(a6 + 0x0);  /* 00c4 */
  if (a2 != 0) goto L_0107;  /* 00c6: bnez.n a2, 107 <esp_mesh_push_to_myself_queue+0xbb> */
  L_00c8: a2 = (u32)&g_log_level + 0x0;  /* 00c8: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00cb */
  a2 = 0x00004008u;  /* 00cd: l32r = 16392 */
  if (a3 >= 3u) goto L_00d6;  /* 00d0: bgeui a3, 3, d6 <esp_mesh_push_to_myself_queue+0x8a> */
  L_00d3: goto L_021c;  /* 00d3: j */
  L_00d6: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00d6: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d9 */
  if (a3 == 0) goto L_021c;  /* 00db: beqz a3, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_00de: a4 = LD32(a3 + 0x150);  /* 00de */
  if (a4 == 0) goto L_021c;  /* 00e1: beqz a4, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_00e4: a10 = LD32(a3 + 0x158);  /* 00e4 */
  a3 = 0x776;  /* 00e7 */
  /* 00ea: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00ed: -> "mesh" */
  L_00f0: a13 = a10;  /* 00f0 */
  a14 = a11;  /* 00f2 */
  a10 = 3;  /* 00f4 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00f6: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00f9: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 00fc */
  __asm__ volatile("" ::: "memory");  /* 00fe: memw */
  /* 0101: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_021c;  /* 0104: j */
  L_0107: a10 = LD32(a5 + 0x0);  /* 0107 */
  a4 = LD32(a10 + 0x0);  /* 0109 */
  if (a4 != 0) goto L_013a;  /* 010b: bnez.n a4, 13a <esp_mesh_push_to_myself_queue+0xee> */
  L_010d: a2 = (u32)&g_log_level + 0x0;  /* 010d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0110 */
  a2 = 0x00004008u;  /* 0113: l32r = 16392 */
  if (a3 >= 3u) goto L_011c;  /* 0116: bgeui a3, 3, 11c <esp_mesh_push_to_myself_queue+0xd0> */
  L_0119: goto L_021c;  /* 0119: j */
  L_011c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 011c: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 011f */
  if (a3 == 0) goto L_021c;  /* 0122: beqz a3, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_0125: a4 = LD32(a3 + 0x150);  /* 0125 */
  if (a4 == 0) goto L_021c;  /* 0128: beqz a4, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_012b: a10 = LD32(a3 + 0x158);  /* 012b */
  a3 = 0x778;  /* 012e */
  /* 0131: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0134: -> "mesh" */
  goto L_00f0;  /* 0137: j */
  L_013a: a2 = LD32(a10 + 0x28);  /* 013a */
  a8 = 4;  /* 013c */
  a8 = a8 & a2;  /* 013e */
  if (a8 == 0) goto L_0200;  /* 0141: beqz a8, 200 <esp_mesh_push_to_myself_queue+0x1b4> */
  L_0144: a7 = (u32)&LOCAL__bss_s_extra_toSelf_qsize + 0x0;  /* 0144: l32r -> .bss.s_extra_toSelf_qsize (same-object static) */
  a2 = LD32(a7 + 0x0);  /* 0147 */
  a2 = a2 + (1);  /* 0149 */
  ST32(a7 + 0x0, a2);  /* 014b */
  __asm__ volatile("" ::: "memory");  /* 014d: memw */
  goto L_017f;  /* 0150: j */
  L_0153: a2 = a4 + (14);  /* 0153 */
  a12 = LD32(a2 + 0x18);  /* 0155 */
  a11 = 1;  /* 0157 */
  a9 = a8;  /* 0159 */
  a2 = 0xf0000001u;  /* 015b: l32r = -268435455 */
  a2 = a12 + a2;  /* 015e */
  if (a2 != 0) a9 = a11;  /* 0160 */
  a7 = a9;  /* 0163 */
  if (a9 == 0) goto L_017f;  /* 0165: beqz.n a9, 17f <esp_mesh_push_to_myself_queue+0x133> */
  L_0167: if (a12 != 0) a8 = a11;  /* 0167 */
  if (a8 == 0) goto L_017f;  /* 016a: beqz a8, 17f <esp_mesh_push_to_myself_queue+0x133> */
  L_016d: a13 = (u32)(RODATA__rodata___func___5 + 0x0);  /* 016d: l32r -> .rodata.__func__$5 */
  a14 = 0x799;  /* 0170 */
  a8 = (u32)&esp_mesh_txupQ_pending + 0x0;  /* 0173: l32r -> global */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 0176: callx a8 via reloc-expand */
  a2 = 0x00004014u;  /* 0179: l32r = 16404 */
  if (a10 != 0) goto L_021c;  /* 017c: bnez a10, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_017f: a7 = (u32)&g_osi_funcs_p + 0x0;  /* 017f: l32r -> global */
  a2 = LD32(a7 + 0x0);  /* 0182 */
  a10 = LD32(a6 + 0x0);  /* 0184 */
  a2 = LD32(a2 + 0x78);  /* 0186 */
  /* 0189: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a8 = (u32)&LOCAL__bss_s_extra_toSelf_qsize + 0x0;  /* 018c: l32r -> .bss.s_extra_toSelf_qsize (same-object static) */
  a2 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 018f: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0192 */
  a2 = LD32(a2 + 0x0);  /* 0194 */
  a2 = a2 + a8;  /* 0196 */
  if (a10 >= a2) goto L_01b4;  /* 0198: bgeu a10, a2, 1b4 <esp_mesh_push_to_myself_queue+0x168> */
  L_019b: a12 = a3;  /* 019b */
  a2 = LD32(a7 + 0x0);  /* 019d */
  a11 = a5;  /* 019f */
  a2 = LD32(a2 + 0x6c);  /* 01a1 */
  a10 = LD32(a6 + 0x0);  /* 01a4 */
  /* 01a6: INDIRECT callx a2 <- mem[a2+0x6c]; result unknown */ a2 = 0;
  a2 = 0;  /* 01a9 */
  if (a10 == 1) goto L_021c;  /* 01ab: beqi a10, 1, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_01ae: a2 = 0x0000400cu;  /* 01ae: l32r = 16396 */
  goto L_01b7;  /* 01b1: j */
  L_01b4: a2 = 0x0000400du;  /* 01b4: l32r = 16397 */
  L_01b7: a11 = 4;  /* 01b7 */
  a10 = LD32(a5 + 0x0);  /* 01b9 */
  a3 = LD32(a10 + 0x28);  /* 01bb */
  a11 = a11 & a3;  /* 01bd */
  if (a11 != 0) goto L_021c;  /* 01c0: bnez a11, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_01c3: a3 = a4 + (18);  /* 01c3 */
  a6 = LD32(a3 + 0x0);  /* 01c6 */
  a3 = 0x403;  /* 01c8 */
  a3 = a3 << 14;  /* 01cb */
  a6 = a6 & a3;  /* 01ce */
  a3 = 1;  /* 01d1 */
  a3 = a3 << 24;  /* 01d3 */
  a5 = 1;  /* 01d6 */
  if (a6 != a3) goto L_021c;  /* 01d8: bne a6, a3, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_01db: a4 = a4 + (14);  /* 01db */
  a12 = LD32(a4 + 0x18);  /* 01dd */
  a3 = a11;  /* 01df */
  if (a12 != 0) a3 = a5;  /* 01e1 */
  if (a3 == 0) goto L_021c;  /* 01e4: beqz.n a3, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_01e6: a3 = 0xf0000001u;  /* 01e6: l32r = -268435455 */
  a3 = a12 + a3;  /* 01e9 */
  if (a3 == 0) a5 = a11;  /* 01eb */
  if (a5 == 0) goto L_021c;  /* 01ee: beqz.n a5, 21c <esp_mesh_push_to_myself_queue+0x1d0> */
  L_01f0: a13 = (u32)(RODATA__rodata___func___5 + 0x0);  /* 01f0: l32r -> .rodata.__func__$5 */
  a14 = 0x7b9;  /* 01f3 */
  a8 = (u32)&esp_mesh_txupQ_pending + 0x0;  /* 01f6: l32r -> global */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 01f9: callx a8 via reloc-expand */
  goto L_021c;  /* 01fc: j */
  L_0200: a2 = a4 + (18);  /* 0200 */
  a9 = LD32(a2 + 0x0);  /* 0203 */
  a2 = 0x403;  /* 0205 */
  a2 = a2 << 14;  /* 0208 */
  a9 = a9 & a2;  /* 020b */
  a2 = 1;  /* 020e */
  a2 = a2 << 24;  /* 0210 */
  if (a9 == a2) goto L_0219;  /* 0213: beq a9, a2, 219 <esp_mesh_push_to_myself_queue+0x1cd> */
  L_0216: goto L_017f;  /* 0216: j */
  L_0219: goto L_0153;  /* 0219: j */
  L_021c: return a2;  /* 021c: retw.n */
}


/* esp_mesh_push_to_tcpip_queue @ mesh.o 00000054 size 853B bind GLOBAL
 * Calls: esp_mesh_available_txupQ_num, print_txupQ_pending, esp_mesh_txupQ_pending | indirect[14]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x78]; mem[a8+0x158] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, mesh_tcpip_mbox, .bss.s_extra_toDS_qsize, g_mesh_xon_cfg_qsize, .rodata.esp_mesh_push_to_tcpip_queue.str1.1, .rodata.__func__$4
 * Fidelity: medium - 14 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=11); reloc-direct=3, funcdb-attributed=0, unknown-indirect=14 */
u32 esp_mesh_push_to_tcpip_queue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a7, a8, a9;
  /* 0054: entry a1, 176 (frame 176 bytes) */
  a7 = a2;  /* 0057 */
  if (a2 != 0) goto L_0089;  /* 0059: bnez.n a2, 89 <esp_mesh_push_to_tcpip_queue+0x35> */
  L_005b: a2 = (u32)&g_log_level + 0x0;  /* 005b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005e */
  a2 = 0x00004008u;  /* 0060: l32r = 16392 */
  if (a3 >= 3u) goto L_0069;  /* 0063: bgeui a3, 3, 69 <esp_mesh_push_to_tcpip_queue+0x15> */
  L_0066: goto L_03a7;  /* 0066: j */
  L_0069: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0069: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006c */
  if (a3 == 0) goto L_03a7;  /* 006e: beqz a3, 3a7 <esp_mesh_push_to_tcpip_queue+0x353> */
  L_0071: a4 = LD32(a3 + 0x150);  /* 0071 */
  if (a4 == 0) goto L_03a7;  /* 0074: beqz a4, 3a7 <esp_mesh_push_to_tcpip_queue+0x353> */
  L_0077: a10 = LD32(a3 + 0x158);  /* 0077 */
  a3 = 0x7c2;  /* 007a */
  /* 007d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0080: -> "mesh" */
  goto L_00bb;  /* 0083: j */
  L_0089: a5 = (u32)&mesh_tcpip_mbox + 0x0;  /* 0089: l32r -> global */
  a2 = LD32(a5 + 0x0);  /* 008c */
  if (a2 != 0) goto L_00d5;  /* 008e: bnez a2, d5 <esp_mesh_push_to_tcpip_queue+0x81> */
  L_0091: a2 = (u32)&g_log_level + 0x0;  /* 0091: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0094 */
  a2 = 0x00004008u;  /* 0097: l32r = 16392 */
  if (a3 >= 3u) goto L_00a0;  /* 009a: bgeui a3, 3, a0 <esp_mesh_push_to_tcpip_queue+0x4c> */
  L_009d: goto L_03a7;  /* 009d: j */
  L_00a0: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a0: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a3 */
  if (a3 == 0) goto L_03a7;  /* 00a6: beqz a3, 3a7 <esp_mesh_push_to_tcpip_queue+0x353> */
  L_00a9: a4 = LD32(a3 + 0x150);  /* 00a9 */
  if (a4 == 0) goto L_03a7;  /* 00ac: beqz a4, 3a7 <esp_mesh_push_to_tcpip_queue+0x353> */
  L_00af: a10 = LD32(a3 + 0x158);  /* 00af */
  a3 = 0x7c3;  /* 00b2 */
  /* 00b5: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b8: -> "mesh" */
  L_00bb: a13 = a10;  /* 00bb */
  a14 = a11;  /* 00bd */
  a10 = 3;  /* 00bf */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c1: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c4: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 00c7 */
  __asm__ volatile("" ::: "memory");  /* 00ca: memw */
  /* 00cd: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03a7;  /* 00d0: j */
  L_00d5: a10 = LD32(a7 + 0x0);  /* 00d5 */
  a4 = LD32(a10 + 0x0);  /* 00d7 */
  if (a4 != 0) goto L_0106;  /* 00d9: bnez.n a4, 106 <esp_mesh_push_to_tcpip_queue+0xb2> */
  L_00db: a2 = (u32)&g_log_level + 0x0;  /* 00db: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00de */
  a2 = 0x00004008u;  /* 00e0: l32r = 16392 */
  if (a3 >= 3u) goto L_00e9;  /* 00e3: bgeui a3, 3, e9 <esp_mesh_push_to_tcpip_queue+0x95> */
  L_00e6: goto L_03a7;  /* 00e6: j */
  L_00e9: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00e9: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00ec */
  if (a3 == 0) goto L_03a7;  /* 00ee: beqz a3, 3a7 <esp_mesh_push_to_tcpip_queue+0x353> */
  L_00f1: a4 = LD32(a3 + 0x150);  /* 00f1 */
  if (a4 == 0) goto L_03a7;  /* 00f4: beqz a4, 3a7 <esp_mesh_push_to_tcpip_queue+0x353> */
  L_00f7: a10 = LD32(a3 + 0x158);  /* 00f7 */
  a3 = 0x7c5;  /* 00fa */
  /* 00fd: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0100: -> "mesh" */
  goto L_00bb;  /* 0103: j */
  L_0106: a2 = LD32(a10 + 0x28);  /* 0106 */
  if (((a2 >> 2) & 1) != 0) goto L_010e;  /* 0108: bbsi a2, 2, 10e <esp_mesh_push_to_tcpip_queue+0xba> */
  L_010b: goto L_038f;  /* 010b: j */
  L_010e: a6 = (u32)&LOCAL__bss_s_extra_toDS_qsize + 0x0;  /* 010e: l32r -> .bss.s_extra_toDS_qsize (same-object static) */
  a2 = LD32(a6 + 0x0);  /* 0111 */
  a2 = a2 + (1);  /* 0113 */
  ST32(a6 + 0x0, a2);  /* 0115 */
  L_0118: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0118: l32r -> global */
  a2 = LD32(a6 + 0x0);  /* 011b */
  a10 = LD32(a5 + 0x0);  /* 011d */
  a2 = LD32(a2 + 0x78);  /* 0120 */
  __asm__ volatile("" ::: "memory");  /* 0123: memw */
  /* 0126: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a8 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0129: l32r -> global */
  a2 = LD32(a8 + 0x0);  /* 012c */
  a8 = (u32)&LOCAL__bss_s_extra_toDS_qsize + 0x0;  /* 012e: l32r -> .bss.s_extra_toDS_qsize (same-object static) */
  a8 = LD32(a8 + 0x0);  /* 0131 */
  a2 = a2 + a8;  /* 0133 */
  a8 = LD32(a6 + 0x0);  /* 0136 */
  if (a10 >= a2) goto L_013f;  /* 0139: bgeu a10, a2, 13f <esp_mesh_push_to_tcpip_queue+0xeb> */
  L_013c: goto L_026c;  /* 013c: j */
  L_013f: if (a8 == 0) goto L_0228;  /* 013f: beqz a8, 228 <esp_mesh_push_to_tcpip_queue+0x1d4> */
  L_0142: a2 = LD32(a8 + 0x150);  /* 0142 */
  if (a2 == 0) goto L_0228;  /* 0145: beqz a2, 228 <esp_mesh_push_to_tcpip_queue+0x1d4> */
  L_0148: a10 = LD32(a8 + 0x158);  /* 0148 */
  /* 014b: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 014e */
  a8 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0150: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 0153 */
  a8 = LD32(a8 + 0x0);  /* 0155 */
  a6 = LD32(a6 + 0x78);  /* 0157 */
  a10 = LD32(a5 + 0x0);  /* 015a */
  ST32(a1 + 0x50, a8);  /* 015d */
  __asm__ volatile("" ::: "memory");  /* 0160: memw */
  /* 0163: INDIRECT callx a6 <- mem[a6+0x78]; result unknown */ a2 = 0;
  a5 = a10;  /* 0166 */
  a11 = 0;  /* 0168 */
  a8 = LD8U(a4 + 0x1d);  /* 016a */
  a6 = LD8U(a4 + 0x1c);  /* 016d */
  a10 = LD32(a7 + 0x0);  /* 0170 */
  a10 = a10 + (12);  /* 0172 */
  ST32(a1 + 0x58, a8);  /* 0175 */
  a8 = LD8U(a4 + 0x1f);  /* 0178 */
  ST32(a1 + 0x54, a6);  /* 017b */
  a6 = LD8U(a4 + 0x1e);  /* 017e */
  ST32(a1 + 0x60, a8);  /* 0181 */
  a8 = LD8U(a10 + 0x1);  /* 0184 */
  ST32(a1 + 0x5c, a6);  /* 0187 */
  a6 = LD8U(a4 + 0x20);  /* 018a */
  a9 = LD8U(a10 + 0x3);  /* 018d */
  a12 = LD8U(a10 + 0x4);  /* 0190 */
  a13 = LD8U(a10 + 0x5);  /* 0193 */
  a15 = LD8U(a4 + 0x21);  /* 0196 */
  ST32(a1 + 0x68, a8);  /* 0199 */
  a8 = LD8U(a10 + 0x2);  /* 019c */
  ST32(a1 + 0x64, a6);  /* 019f */
  a6 = LD8U(a10 + 0x0);  /* 01a2 */
  ST32(a1 + 0x74, a8);  /* 01a5 */
  ST32(a1 + 0x78, a9);  /* 01a8 */
  ST32(a1 + 0x7c, a12);  /* 01ab */
  ST32(a1 + 0x80, a13);  /* 01ae */
  ST32(a1 + 0x70, a15);  /* 01b1 */
  __asm__ volatile("" ::: "memory");  /* 01b4: memw */
  a8 = (u32)&esp_mesh_available_txupQ_num + 0x0;  /* 01b7: l32r -> global */
  a2 = esp_mesh_available_txupQ_num(a2, a3, a4, a5, a6);  /* 01ba: callx a8 via reloc-expand */
  a14 = a4 + (14);  /* 01bd */
  a14 = LD32(a14 + 0x18);  /* 01bf */
  a8 = LD32(a1 + 0x74);  /* 01c1 */
  ST32(a1 + 0x44, a14);  /* 01c4 */
  a14 = LD32(a7 + 0x0);  /* 01c7 */
  a14 = LD16U(a14 + 0x4);  /* 01c9 */
  ST32(a1 + 0x2c, a8);  /* 01cc */
  a8 = LD32(a1 + 0x68);  /* 01ce */
  ST32(a1 + 0x24, a6);  /* 01d1 */
  a6 = LD32(a1 + 0x64);  /* 01d3 */
  ST32(a1 + 0x28, a8);  /* 01d6 */
  a8 = LD32(a1 + 0x60);  /* 01d8 */
  ST32(a1 + 0x1c, a6);  /* 01db */
  a6 = LD32(a1 + 0x5c);  /* 01dd */
  ST32(a1 + 0x18, a8);  /* 01e0 */
  a8 = LD32(a1 + 0x58);  /* 01e2 */
  a13 = LD32(a1 + 0x80);  /* 01e5 */
  a12 = LD32(a1 + 0x7c);  /* 01e8 */
  a15 = LD32(a1 + 0x70);  /* 01eb */
  a9 = LD32(a1 + 0x78);  /* 01ee */
  ST32(a1 + 0x14, a6);  /* 01f1 */
  a6 = LD32(a1 + 0x54);  /* 01f3 */
  ST32(a1 + 0x10, a8);  /* 01f6 */
  a8 = LD32(a1 + 0x50);  /* 01f8 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 01fb: -> "mesh" */
  ST32(a1 + 0x40, a14);  /* 01fe */
  a14 = a11;  /* 0201 */
  ST32(a1 + 0x3c, a10);  /* 0203 */
  a10 = 1;  /* 0205 */
  ST32(a1 + 0x38, a13);  /* 0207 */
  a13 = a3;  /* 0209 */
  ST32(a1 + 0x34, a12);  /* 020b */
  ST32(a1 + 0x20, a15);  /* 020d */
  ST32(a1 + 0x8, a5);  /* 020f */
  a5 = 0x7de;  /* 0211 */
  ST32(a1 + 0x30, a9);  /* 0214 */
  ST32(a1 + 0xc, a6);  /* 0216 */
  ST32(a1 + 0x4, a8);  /* 0218 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 021a: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_tcpip_queue_str1_1 + 0x0);  /* 021d: l32r -> .rodata.esp_mesh_push_to_tcpip_queue.str1.1 */
  ST32(a1 + 0x0, a5);  /* 0220 */
  __asm__ volatile("" ::: "memory");  /* 0222: memw */
  /* 0225: INDIRECT callx a2 <- unknown; result unknown */ a2 = 0;
  L_0228: a12 = 0x7e8;  /* 0228 */
  a10 = 0;  /* 022b */
  a11 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 022d: l32r -> .rodata.__func__$4 */
  a8 = (u32)&print_txupQ_pending + 0x0;  /* 0230: l32r -> global */
  a2 = print_txupQ_pending(a2, a3, a4, a5, a6);  /* 0233: callx a8 via reloc-expand */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0236: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0239 */
  a2 = 0x0000400du;  /* 023c: l32r = 16397 */
  if (a3 == 0) goto L_0371;  /* 023f: beqz a3, 371 <esp_mesh_push_to_tcpip_queue+0x31d> */
  L_0242: a5 = LD32(a3 + 0x150);  /* 0242 */
  if (a5 == 0) goto L_0371;  /* 0245: beqz a5, 371 <esp_mesh_push_to_tcpip_queue+0x31d> */
  L_0248: a10 = LD32(a3 + 0x158);  /* 0248 */
  a3 = 0x7e9;  /* 024b */
  /* 024e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0251 */
  a10 = 1;  /* 0253 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0255: -> "mesh" */
  a14 = a11;  /* 0258 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 025a: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_tcpip_queue_str1_1 + 0x0);  /* 025d: l32r -> .rodata.esp_mesh_push_to_tcpip_queue.str1.1 */
  ST32(a1 + 0x0, a3);  /* 0260 */
  __asm__ volatile("" ::: "memory");  /* 0262: memw */
  /* 0265: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0371;  /* 0268: j */
  L_026c: a2 = LD32(a8 + 0x6c);  /* 026c */
  a12 = a3;  /* 026f */
  a11 = a7;  /* 0271 */
  a10 = LD32(a5 + 0x0);  /* 0273 */
  /* 0275: INDIRECT callx a2 <- mem[a8+0x6c]; result unknown */ a2 = 0;
  a2 = 0;  /* 0278 */
  if (a10 != 1) goto L_0280;  /* 027a: bnei a10, 1, 280 <esp_mesh_push_to_tcpip_queue+0x22c> */
  L_027d: goto L_03a7;  /* 027d: j */
  L_0280: a8 = LD32(a6 + 0x0);  /* 0280 */
  a2 = 0x0000400cu;  /* 0282: l32r = 16396 */
  if (a8 == 0) goto L_0371;  /* 0285: beqz a8, 371 <esp_mesh_push_to_tcpip_queue+0x31d> */
  L_0288: a3 = LD32(a8 + 0x150);  /* 0288 */
  if (a3 == 0) goto L_0371;  /* 028b: beqz a3, 371 <esp_mesh_push_to_tcpip_queue+0x31d> */
  L_028e: a10 = LD32(a8 + 0x158);  /* 028e */
  /* 0291: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0294 */
  a6 = LD32(a6 + 0x0);  /* 0296 */
  a8 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0298: l32r -> global */
  a6 = LD32(a6 + 0x78);  /* 029b */
  a8 = LD32(a8 + 0x0);  /* 029e */
  a10 = LD32(a5 + 0x0);  /* 02a0 */
  ST32(a1 + 0x80, a13);  /* 02a2 */
  ST32(a1 + 0x50, a8);  /* 02a5 */
  __asm__ volatile("" ::: "memory");  /* 02a8: memw */
  /* 02ab: INDIRECT callx a6 <- mem[a6+0x78]; result unknown */ a2 = 0;
  a5 = a10;  /* 02ae */
  a11 = 0;  /* 02b0 */
  a8 = LD8U(a4 + 0x1d);  /* 02b2 */
  ST32(a1 + 0x58, a8);  /* 02b5 */
  a8 = LD8U(a4 + 0x1f);  /* 02b8 */
  a6 = LD8U(a4 + 0x1c);  /* 02bb */
  a10 = LD32(a7 + 0x0);  /* 02be */
  a10 = a10 + (12);  /* 02c0 */
  ST32(a1 + 0x60, a8);  /* 02c3 */
  a8 = LD8U(a4 + 0x21);  /* 02c6 */
  ST32(a1 + 0x54, a6);  /* 02c9 */
  a6 = LD8U(a4 + 0x1e);  /* 02cc */
  ST32(a1 + 0x68, a8);  /* 02cf */
  a8 = LD8U(a10 + 0x2);  /* 02d2 */
  ST32(a1 + 0x5c, a6);  /* 02d5 */
  a6 = LD8U(a4 + 0x20);  /* 02d8 */
  a15 = LD8U(a10 + 0x0);  /* 02db */
  a9 = LD8U(a10 + 0x4);  /* 02de */
  a12 = LD8U(a10 + 0x5);  /* 02e1 */
  ST32(a1 + 0x6c, a8);  /* 02e4 */
  a8 = LD8U(a10 + 0x3);  /* 02e7 */
  ST32(a1 + 0x64, a6);  /* 02ea */
  a6 = LD8U(a10 + 0x1);  /* 02ed */
  ST32(a1 + 0x74, a8);  /* 02f0 */
  ST32(a1 + 0x78, a9);  /* 02f3 */
  ST32(a1 + 0x7c, a12);  /* 02f6 */
  ST32(a1 + 0x70, a15);  /* 02f9 */
  __asm__ volatile("" ::: "memory");  /* 02fc: memw */
  a8 = (u32)&esp_mesh_available_txupQ_num + 0x0;  /* 02ff: l32r -> global */
  a2 = esp_mesh_available_txupQ_num(a2, a3, a4, a5, a6);  /* 0302: callx a8 via reloc-expand */
  a14 = a4 + (14);  /* 0305 */
  a14 = LD32(a14 + 0x18);  /* 0307 */
  a8 = LD32(a1 + 0x74);  /* 0309 */
  ST32(a1 + 0x44, a14);  /* 030c */
  a14 = LD32(a7 + 0x0);  /* 030f */
  a14 = LD16U(a14 + 0x4);  /* 0311 */
  ST32(a1 + 0x30, a8);  /* 0314 */
  a8 = LD32(a1 + 0x6c);  /* 0316 */
  ST32(a1 + 0x28, a6);  /* 0319 */
  ST32(a1 + 0x2c, a8);  /* 031b */
  a6 = LD32(a1 + 0x68);  /* 031d */
  a8 = LD32(a1 + 0x64);  /* 0320 */
  ST32(a1 + 0x20, a6);  /* 0323 */
  ST32(a1 + 0x1c, a8);  /* 0325 */
  a6 = LD32(a1 + 0x60);  /* 0327 */
  a8 = LD32(a1 + 0x5c);  /* 032a */
  a12 = LD32(a1 + 0x7c);  /* 032d */
  a15 = LD32(a1 + 0x70);  /* 0330 */
  a9 = LD32(a1 + 0x78);  /* 0333 */
  ST32(a1 + 0x18, a6);  /* 0336 */
  ST32(a1 + 0x14, a8);  /* 0338 */
  a6 = LD32(a1 + 0x58);  /* 033a */
  a8 = LD32(a1 + 0x54);  /* 033d */
  ST32(a1 + 0x8, a5);  /* 0340 */
  a5 = LD32(a1 + 0x50);  /* 0342 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0345: -> "mesh" */
  ST32(a1 + 0x40, a14);  /* 0348 */
  a14 = a11;  /* 034b */
  ST32(a1 + 0x3c, a10);  /* 034d */
  a10 = 1;  /* 034f */
  ST32(a1 + 0x38, a12);  /* 0351 */
  ST32(a1 + 0x24, a15);  /* 0353 */
  ST32(a1 + 0x34, a9);  /* 0355 */
  ST32(a1 + 0x10, a6);  /* 0357 */
  ST32(a1 + 0xc, a8);  /* 0359 */
  ST32(a1 + 0x4, a5);  /* 035b */
  a5 = 0x7ef;  /* 035d */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0360: -> "mesh" */
  a13 = LD32(a1 + 0x80);  /* 0363 */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_tcpip_queue_str1_1 + 0x0);  /* 0366: l32r -> .rodata.esp_mesh_push_to_tcpip_queue.str1.1 */
  ST32(a1 + 0x0, a5);  /* 0369 */
  __asm__ volatile("" ::: "memory");  /* 036b: memw */
  /* 036e: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  L_0371: a11 = 4;  /* 0371 */
  a10 = LD32(a7 + 0x0);  /* 0373 */
  a3 = LD32(a10 + 0x28);  /* 0375 */
  a11 = a11 & a3;  /* 0377 */
  if (a11 != 0) goto L_03a7;  /* 037a: bnez.n a11, 3a7 <esp_mesh_push_to_tcpip_queue+0x353> */
  L_037c: a4 = a4 + (14);  /* 037c */
  a13 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 037e: l32r -> .rodata.__func__$4 */
  a14 = 0x7fc;  /* 0381 */
  a12 = LD32(a4 + 0x18);  /* 0384 */
  a8 = (u32)&esp_mesh_txupQ_pending + 0x0;  /* 0386: l32r -> global */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6);  /* 0389: callx a8 via reloc-expand */
  goto L_03a7;  /* 038c: j */
  L_038f: a2 = a4 + (14);  /* 038f */
  a12 = LD32(a2 + 0x18);  /* 0391 */
  a14 = 0x7d7;  /* 0393 */
  a11 = 1;  /* 0396 */
  a13 = (u32)(RODATA__rodata___func___4 + 0x0);  /* 0398: l32r -> .rodata.__func__$4 */
  a8 = (u32)&esp_mesh_txupQ_pending + 0x0;  /* 039b: l32r -> global */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6);  /* 039e: callx a8 via reloc-expand */
  a2 = 0x00004014u;  /* 03a1: l32r = 16404 */
  if (a10 == 0) goto L_0118;  /* 03a4: beqz a10, 118 <esp_mesh_push_to_tcpip_queue+0xc4> */
  L_03a7: return a2;  /* 03a7: retw.n */
}


/* esp_mesh_push_to_xmit_state_queue @ mesh.o 00000028 size 142B bind GLOBAL
 * Calls: none | indirect[4]: mem[a8+0x158]; mem[a8+0x150]; mem[a3+0x6c] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, mesh_xmit_state_mbox
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=4); reloc-direct=0, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_push_to_xmit_state_queue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0028: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0055;  /* 002b: bnez.n a2, 55 <esp_mesh_push_to_xmit_state_queue+0x2d> */
  L_002d: a2 = (u32)&g_log_level + 0x0;  /* 002d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0030 */
  a2 = 0x00004008u;  /* 0032: l32r = 16392 */
  if (a3 < 3u) goto L_00b4;  /* 0035: bltui a3, 3, b4 <esp_mesh_push_to_xmit_state_queue+0x8c> */
  L_0038: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0038: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 003b */
  if (a8 == 0) goto L_00b4;  /* 003d: beqz a8, b4 <esp_mesh_push_to_xmit_state_queue+0x8c> */
  L_0040: a3 = LD32(a8 + 0x150);  /* 0040 */
  if (a3 == 0) goto L_00b4;  /* 0043: beqz a3, b4 <esp_mesh_push_to_xmit_state_queue+0x8c> */
  L_0046: a10 = LD32(a8 + 0x158);  /* 0046 */
  /* 0049: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 004c: -> "mesh" */
  a8 = 0x000009ddu;  /* 004f: l32r = 2525 */
  goto L_0082;  /* 0052: j */
  L_0055: a3 = (u32)&mesh_xmit_state_mbox + 0x0;  /* 0055: l32r -> global */
  a10 = LD32(a3 + 0x0);  /* 0058 */
  if (a10 != 0) goto L_009b;  /* 005a: bnez.n a10, 9b <esp_mesh_push_to_xmit_state_queue+0x73> */
  L_005c: a2 = (u32)&g_log_level + 0x0;  /* 005c: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005f */
  a2 = 0x00004008u;  /* 0062: l32r = 16392 */
  if (a3 < 3u) goto L_00b4;  /* 0065: bltui a3, 3, b4 <esp_mesh_push_to_xmit_state_queue+0x8c> */
  L_0068: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0068: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 006b */
  if (a8 == 0) goto L_00b4;  /* 006e: beqz a8, b4 <esp_mesh_push_to_xmit_state_queue+0x8c> */
  L_0071: a3 = LD32(a8 + 0x150);  /* 0071 */
  if (a3 == 0) goto L_00b4;  /* 0074: beqz.n a3, b4 <esp_mesh_push_to_xmit_state_queue+0x8c> */
  L_0076: a10 = LD32(a8 + 0x158);  /* 0076 */
  /* 0079: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 007c: -> "mesh" */
  a8 = 0x000009deu;  /* 007f: l32r = 2526 */
  L_0082: a13 = a10;  /* 0082 */
  a14 = a11;  /* 0084 */
  a10 = 3;  /* 0086 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0089: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 008c: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 008f */
  __asm__ volatile("" ::: "memory");  /* 0092: memw */
  /* 0095: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00b4;  /* 0098: j */
  L_009b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 009b: l32r -> global */
  a11 = a2;  /* 009e */
  a12 = 0;  /* 00a0 */
  a3 = LD32(a3 + 0x0);  /* 00a2 */
  a3 = LD32(a3 + 0x6c);  /* 00a4 */
  /* 00a7: INDIRECT callx a3 <- mem[a3+0x6c]; result unknown */ a2 = 0;
  a10 = a10 + (-1);  /* 00aa */
  a3 = 0;  /* 00ac */
  a2 = 0x0000400cu;  /* 00ae: l32r = 16396 */
  if (a10 == 0) a2 = a3;  /* 00b1 */
  L_00b4: return a2;  /* 00b4: retw.n */
}


/* esp_mesh_recv @ mesh.o 00000038 size 304B bind GLOBAL
 * Calls: mesh_recv | indirect[7]: mem[a8+0x158]; mem[a8+0x150] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_is_mesh_started, mesh_myself_mbox
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=8); reloc-direct=1, funcdb-attributed=0, unknown-indirect=7 */
u32 esp_mesh_recv(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0038: entry a1, 48 (frame 48 bytes) */
  a12 = a3;  /* 003b */
  a3 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 003d: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a13 = a4;  /* 0040 */
  a14 = a5;  /* 0042 */
  a15 = a6;  /* 0044 */
  a3 = LD8U(a3 + 0x0);  /* 0046 */
  if (a3 != 0) goto L_007c;  /* 0049: bnez.n a3, 7c <esp_mesh_recv+0x44> */
  L_004b: a2 = (u32)&g_log_level + 0x0;  /* 004b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 004e */
  a2 = 0x00004002u;  /* 0050: l32r = 16386 */
  if (a3 >= 3u) goto L_0059;  /* 0053: bgeui a3, 3, 59 <esp_mesh_recv+0x21> */
  L_0056: goto L_0166;  /* 0056: j */
  L_0059: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0059: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 005c */
  if (a8 == 0) goto L_0166;  /* 005e: beqz a8, 166 <esp_mesh_recv+0x12e> */
  L_0061: a3 = LD32(a8 + 0x150);  /* 0061 */
  if (a3 == 0) goto L_0166;  /* 0064: beqz a3, 166 <esp_mesh_recv+0x12e> */
  L_0067: a10 = LD32(a8 + 0x158);  /* 0067 */
  /* 006a: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 006d */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 006f: -> "mesh" */
  a14 = a11;  /* 0072 */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 0074: l32r -> .rodata.esp_mesh_recv.str1.1 */
  goto L_00b0;  /* 0077: j */
  L_007c: a3 = (u32)&g_is_mesh_started + 0x0;  /* 007c: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 007f */
  if (a3 != 0) goto L_00b8;  /* 0082: bnez.n a3, b8 <esp_mesh_recv+0x80> */
  L_0084: a2 = (u32)&g_log_level + 0x0;  /* 0084: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0087 */
  a2 = 0x00004004u;  /* 0089: l32r = 16388 */
  if (a3 >= 3u) goto L_0092;  /* 008c: bgeui a3, 3, 92 <esp_mesh_recv+0x5a> */
  L_008f: goto L_0166;  /* 008f: j */
  L_0092: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0092: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0095 */
  if (a8 == 0) goto L_0166;  /* 0097: beqz a8, 166 <esp_mesh_recv+0x12e> */
  L_009a: a3 = LD32(a8 + 0x150);  /* 009a */
  if (a3 == 0) goto L_0166;  /* 009d: beqz a3, 166 <esp_mesh_recv+0x12e> */
  L_00a0: a10 = LD32(a8 + 0x158);  /* 00a0 */
  /* 00a3: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00a6 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00a8: -> "mesh" */
  a14 = a11;  /* 00ab */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00ad: -> "mesh" */
  L_00b0: a10 = 3;  /* 00b0 */
  /* 00b2: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0166;  /* 00b5: j */
  L_00b8: a3 = (u32)&mesh_myself_mbox + 0x0;  /* 00b8: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00bb */
  if (a3 != 0) goto L_00ea;  /* 00bd: bnez.n a3, ea <esp_mesh_recv+0xb2> */
  L_00bf: a2 = (u32)&g_log_level + 0x0;  /* 00bf: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c2 */
  a2 = 0x00004008u;  /* 00c4: l32r = 16392 */
  if (a3 >= 3u) goto L_00cd;  /* 00c7: bgeui a3, 3, cd <esp_mesh_recv+0x95> */
  L_00ca: goto L_0166;  /* 00ca: j */
  L_00cd: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00cd: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00d0 */
  if (a8 == 0) goto L_0166;  /* 00d2: beqz a8, 166 <esp_mesh_recv+0x12e> */
  L_00d5: a3 = LD32(a8 + 0x150);  /* 00d5 */
  if (a3 == 0) goto L_0166;  /* 00d8: beqz a3, 166 <esp_mesh_recv+0x12e> */
  L_00db: a7 = 0x5b9;  /* 00db */
  a10 = LD32(a8 + 0x158);  /* 00de */
  /* 00e1: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00e4: -> "mesh" */
  goto L_013c;  /* 00e7: j */
  L_00ea: if (a2 != 0) goto L_0116;  /* 00ea: bnez.n a2, 116 <esp_mesh_recv+0xde> */
  L_00ec: a2 = (u32)&g_log_level + 0x0;  /* 00ec: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ef */
  a2 = 0x00004008u;  /* 00f2: l32r = 16392 */
  if (a3 < 3u) goto L_0166;  /* 00f5: bltui a3, 3, 166 <esp_mesh_recv+0x12e> */
  L_00f8: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00f8: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00fb */
  if (a8 == 0) goto L_0166;  /* 00fe: beqz a8, 166 <esp_mesh_recv+0x12e> */
  L_0101: a3 = LD32(a8 + 0x150);  /* 0101 */
  if (a3 == 0) goto L_0166;  /* 0104: beqz a3, 166 <esp_mesh_recv+0x12e> */
  L_0107: a7 = 0x5ba;  /* 0107 */
  a10 = LD32(a8 + 0x158);  /* 010a */
  /* 010d: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0110: -> "mesh" */
  goto L_013c;  /* 0113: j */
  L_0116: if (a12 != 0) goto L_0155;  /* 0116: bnez.n a12, 155 <esp_mesh_recv+0x11d> */
  L_0118: a2 = (u32)&g_log_level + 0x0;  /* 0118: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 011b */
  a2 = 0x00004008u;  /* 011d: l32r = 16392 */
  if (a3 < 3u) goto L_0166;  /* 0120: bltui a3, 3, 166 <esp_mesh_recv+0x12e> */
  L_0123: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0123: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0126 */
  if (a8 == 0) goto L_0166;  /* 0129: beqz.n a8, 166 <esp_mesh_recv+0x12e> */
  L_012b: a3 = LD32(a8 + 0x150);  /* 012b */
  if (a3 == 0) goto L_0166;  /* 012e: beqz.n a3, 166 <esp_mesh_recv+0x12e> */
  L_0130: a7 = 0x5bb;  /* 0130 */
  a10 = LD32(a8 + 0x158);  /* 0133 */
  /* 0136: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0139: -> "mesh" */
  L_013c: a13 = a10;  /* 013c */
  a14 = a11;  /* 013e */
  a10 = 3;  /* 0140 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0142: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0145: -> "mesh" */
  ST32(a1 + 0x0, a7);  /* 0148 */
  __asm__ volatile("" ::: "memory");  /* 014a: memw */
  /* 014d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0166;  /* 0150: j */
  L_0155: a10 = a2;  /* 0155 */
  ST32(a1 + 0x0, a7);  /* 0157 */
  a11 = 0;  /* 0159 */
  __asm__ volatile("" ::: "memory");  /* 015b: memw */
  a8 = (u32)&mesh_recv;  /* 015e: l32r -> func addr */
  a2 = mesh_recv(a2, a3, a4, a5, a6, a7);  /* 0161: callx a8 via reloc-expand */
  a2 = a10;  /* 0164 */
  L_0166: return a2;  /* 0166: retw.n */
}


/* esp_mesh_recv_release @ mesh.o 0000000c size 52B bind GLOBAL
 * Calls: esp_mesh_flush_tcpip_queue | Data refs: mesh_tcpip_mbox, g_osi_funcs_p
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=3); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_recv_release(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 000c: entry a1, 48 (frame 48 bytes) */
  a3 = 0;  /* 000f */
  a2 = (a2 >> 8) & 0x1;  /* 0012: extui width 1 */
  ST32(a1 + 0x0, a3);  /* 0015 */
  if (a2 == a3) goto L_003c;  /* 0018: beq a2, a3, 3c <esp_mesh_recv_release+0x30> */
  L_001b: __asm__ volatile("" ::: "memory");  /* 001b: memw */
  a8 = (u32)&esp_mesh_flush_tcpip_queue;  /* 001e: l32r -> func addr */
  a2 = esp_mesh_flush_tcpip_queue(a2, a3, a4, a5, a6, a7);  /* 0021: callx a8 via reloc-expand */
  a8 = (u32)&mesh_tcpip_mbox + 0x0;  /* 0024: l32r -> global */
  a10 = LD32(a8 + 0x0);  /* 0027 */
  if (a10 == a3) goto L_003c;  /* 0029: beq a10, a3, 3c <esp_mesh_recv_release+0x30> */
  L_002c: a12 = a3;  /* 002c */
  a11 = a1;  /* 002e */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0030: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0033 */
  a8 = LD32(a8 + 0x6c);  /* 0036 */
  a2 = esp_mesh_flush_tcpip_queue(a2, a3, a4, a5, a6, a7);  /* 0039: callx a8 via literal-trampoline */
  L_003c: a2 = 0;  /* 003c */
  return a2;  /* 003e: retw.n */
}


/* esp_mesh_recv_toDS @ mesh.o 00000048 size 408B bind GLOBAL
 * Calls: esp_mesh_flush_tcpip_queue, mesh_recv | indirect[9]: mem[a8+0x158]; mem[a8+0x150]; mem[a3+0x84] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_is_mesh_started, mesh_tcpip_mbox, g_mesh_is_root, g_mesh_stop_event_group
 * Fidelity: medium - 9 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=11); reloc-direct=2, funcdb-attributed=0, unknown-indirect=9 */
u32 esp_mesh_recv_toDS(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0048: entry a1, 48 (frame 48 bytes) */
  a11 = a3;  /* 004b */
  a3 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 004d: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a15 = a7;  /* 0050 */
  a12 = a4;  /* 0052 */
  a13 = a5;  /* 0054 */
  a3 = LD8U(a3 + 0x0);  /* 0056 */
  a14 = a6;  /* 0059 */
  if (a3 != 0) goto L_008d;  /* 005b: bnez.n a3, 8d <esp_mesh_recv_toDS+0x45> */
  L_005d: a2 = (u32)&g_log_level + 0x0;  /* 005d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0060 */
  a2 = 0x00004002u;  /* 0062: l32r = 16386 */
  if (a3 >= 3u) goto L_006b;  /* 0065: bgeui a3, 3, 6b <esp_mesh_recv_toDS+0x23> */
  L_0068: goto L_01de;  /* 0068: j */
  L_006b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 006b: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 006e */
  if (a8 == 0) goto L_01de;  /* 0071: beqz a8, 1de <esp_mesh_recv_toDS+0x196> */
  L_0074: a3 = LD32(a8 + 0x150);  /* 0074 */
  if (a3 == 0) goto L_01de;  /* 0077: beqz a3, 1de <esp_mesh_recv_toDS+0x196> */
  L_007a: a10 = LD32(a8 + 0x158);  /* 007a */
  /* 007d: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0080 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0082: -> "mesh" */
  a14 = a11;  /* 0085 */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 0087: l32r -> .rodata.esp_mesh_recv.str1.1 */
  goto L_00c3;  /* 008a: j */
  L_008d: a3 = (u32)&g_is_mesh_started + 0x0;  /* 008d: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 0090 */
  if (a3 != 0) goto L_00cc;  /* 0093: bnez.n a3, cc <esp_mesh_recv_toDS+0x84> */
  L_0095: a2 = (u32)&g_log_level + 0x0;  /* 0095: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0098 */
  a2 = 0x00004004u;  /* 009b: l32r = 16388 */
  if (a3 >= 3u) goto L_00a4;  /* 009e: bgeui a3, 3, a4 <esp_mesh_recv_toDS+0x5c> */
  L_00a1: goto L_01de;  /* 00a1: j */
  L_00a4: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a4: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00a7 */
  if (a8 == 0) goto L_01de;  /* 00aa: beqz a8, 1de <esp_mesh_recv_toDS+0x196> */
  L_00ad: a3 = LD32(a8 + 0x150);  /* 00ad */
  if (a3 == 0) goto L_01de;  /* 00b0: beqz a3, 1de <esp_mesh_recv_toDS+0x196> */
  L_00b3: a10 = LD32(a8 + 0x158);  /* 00b3 */
  /* 00b6: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00b9 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00bb: -> "mesh" */
  a14 = a11;  /* 00be */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c0: -> "mesh" */
  L_00c3: a10 = 3;  /* 00c3 */
  /* 00c5: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_01de;  /* 00c8: j */
  L_00cc: a3 = (u32)&mesh_tcpip_mbox + 0x0;  /* 00cc: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00cf */
  if (a3 != 0) goto L_0100;  /* 00d1: bnez.n a3, 100 <esp_mesh_recv_toDS+0xb8> */
  L_00d3: a2 = (u32)&g_log_level + 0x0;  /* 00d3: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00d6 */
  a2 = 0x00004008u;  /* 00d8: l32r = 16392 */
  if (a3 >= 3u) goto L_00e1;  /* 00db: bgeui a3, 3, e1 <esp_mesh_recv_toDS+0x99> */
  L_00de: goto L_01de;  /* 00de: j */
  L_00e1: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00e1: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00e4 */
  if (a8 == 0) goto L_01de;  /* 00e6: beqz a8, 1de <esp_mesh_recv_toDS+0x196> */
  L_00e9: a3 = LD32(a8 + 0x150);  /* 00e9 */
  if (a3 == 0) goto L_01de;  /* 00ec: beqz a3, 1de <esp_mesh_recv_toDS+0x196> */
  L_00ef: a10 = LD32(a8 + 0x158);  /* 00ef */
  /* 00f2: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x5c6;  /* 00f5 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00f8: -> "mesh" */
  goto L_012b;  /* 00fb: j */
  L_0100: if (a2 != 0) goto L_0144;  /* 0100: bnez a2, 144 <esp_mesh_recv_toDS+0xfc> */
  L_0103: a2 = (u32)&g_log_level + 0x0;  /* 0103: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0106 */
  a2 = 0x00004008u;  /* 0108: l32r = 16392 */
  if (a3 >= 3u) goto L_0111;  /* 010b: bgeui a3, 3, 111 <esp_mesh_recv_toDS+0xc9> */
  L_010e: goto L_01de;  /* 010e: j */
  L_0111: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0111: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0114 */
  if (a8 == 0) goto L_01de;  /* 0116: beqz a8, 1de <esp_mesh_recv_toDS+0x196> */
  L_0119: a3 = LD32(a8 + 0x150);  /* 0119 */
  if (a3 == 0) goto L_01de;  /* 011c: beqz a3, 1de <esp_mesh_recv_toDS+0x196> */
  L_011f: a10 = LD32(a8 + 0x158);  /* 011f */
  /* 0122: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x5c7;  /* 0125 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0128: -> "mesh" */
  L_012b: a13 = a10;  /* 012b */
  a14 = a11;  /* 012d */
  a10 = 3;  /* 012f */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0131: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0134: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 0137 */
  __asm__ volatile("" ::: "memory");  /* 013a: memw */
  /* 013d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_01de;  /* 0140: j */
  L_0144: if (a11 != 0) goto L_0171;  /* 0144: bnez.n a11, 171 <esp_mesh_recv_toDS+0x129> */
  L_0146: a2 = (u32)&g_log_level + 0x0;  /* 0146: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0149 */
  a2 = 0x00004008u;  /* 014b: l32r = 16392 */
  if (a3 >= 3u) goto L_0154;  /* 014e: bgeui a3, 3, 154 <esp_mesh_recv_toDS+0x10c> */
  L_0151: goto L_01de;  /* 0151: j */
  L_0154: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0154: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0157 */
  if (a8 == 0) goto L_01de;  /* 0159: beqz a8, 1de <esp_mesh_recv_toDS+0x196> */
  L_015c: a3 = LD32(a8 + 0x150);  /* 015c */
  if (a3 == 0) goto L_01de;  /* 015f: beqz a3, 1de <esp_mesh_recv_toDS+0x196> */
  L_0162: a10 = LD32(a8 + 0x158);  /* 0162 */
  /* 0165: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x5c8;  /* 0168 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 016b: -> "mesh" */
  goto L_012b;  /* 016e: j */
  L_0171: if (a4 != 0) goto L_019d;  /* 0171: bnez.n a4, 19d <esp_mesh_recv_toDS+0x155> */
  L_0173: a2 = (u32)&g_log_level + 0x0;  /* 0173: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0176 */
  a2 = 0x00004008u;  /* 0179: l32r = 16392 */
  if (a3 < 3u) goto L_01de;  /* 017c: bltui a3, 3, 1de <esp_mesh_recv_toDS+0x196> */
  L_017f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 017f: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0182 */
  if (a8 == 0) goto L_01de;  /* 0185: beqz a8, 1de <esp_mesh_recv_toDS+0x196> */
  L_0188: a3 = LD32(a8 + 0x150);  /* 0188 */
  if (a3 == 0) goto L_01de;  /* 018b: beqz a3, 1de <esp_mesh_recv_toDS+0x196> */
  L_018e: a10 = LD32(a8 + 0x158);  /* 018e */
  /* 0191: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x5c9;  /* 0194 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0197: -> "mesh" */
  goto L_012b;  /* 019a: j */
  L_019d: a3 = (u32)&g_mesh_is_root + 0x0;  /* 019d: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 01a0: memw */
  a8 = LD8U(a3 + 0x0);  /* 01a3 */
  a8 = (a8 >> 8) & 0x1;  /* 01a6: extui width 1 */
  if (a8 != 0) goto L_01cd;  /* 01a9: bnez.n a8, 1cd <esp_mesh_recv_toDS+0x185> */
  L_01ab: a8 = (u32)&esp_mesh_flush_tcpip_queue;  /* 01ab: l32r -> func addr */
  a2 = esp_mesh_flush_tcpip_queue(a2, a3, a4, a5, a6, a7);  /* 01ae: callx a8 via reloc-expand */
  a2 = (u32)&g_mesh_stop_event_group + 0x0;  /* 01b1: l32r -> global */
  a10 = LD32(a2 + 0x0);  /* 01b4 */
  a2 = 0x00004006u;  /* 01b6: l32r = 16390 */
  if (a10 == 0) goto L_01de;  /* 01b9: beqz.n a10, 1de <esp_mesh_recv_toDS+0x196> */
  L_01bb: a11 = 32;  /* 01bb */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 01bd: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 01c0 */
  a3 = LD32(a3 + 0x84);  /* 01c2 */
  /* 01c5: INDIRECT callx a3 <- mem[a3+0x84]; result unknown */ a2 = 0;
  goto L_01de;  /* 01c8: j */
  L_01cd: a3 = LD32(a1 + 0x30);  /* 01cd */
  a10 = a2;  /* 01cf */
  ST32(a1 + 0x0, a3);  /* 01d1 */
  __asm__ volatile("" ::: "memory");  /* 01d3: memw */
  a8 = (u32)&mesh_recv;  /* 01d6: l32r -> func addr */
  a2 = mesh_recv(a2, a3, a4, a5, a6, a7);  /* 01d9: callx a8 via reloc-expand */
  a2 = a10;  /* 01dc */
  L_01de: return a2;  /* 01de: retw.n */
}


/* esp_mesh_send @ mesh.o 000000e0 size 1497B bind GLOBAL
 * Calls: memcmp, mesh_parse_option, esp_mesh_create_context, mesh_send_process_flag, mesh_send_process_topo, memcpy, mesh_add_option, mesh_mutex_lock, esp_mesh_match_self, esp_mesh_delivery_toSelf, esp_mesh_forward_packet, mesh_mutex_unlock, esp_mesh_free_context, esp_mesh_send_sem_wait, tx_state_id2str | indirect[13]: mem[a2+0x158]; mem[a8+0x110]; mem[a4+0x74]; mem[a4+0x84] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .bss.MESH_ZERO_ADDR, .data.MESH_BCAST_ADDR, g_mesh_is_root, g_is_root_fixed, g_is_wifi_connected, g_mesh_topology, .rodata.__func__$8, g_mesh_self_sta_addr +5 more
 * Fidelity: medium - single jx dispatch fully recovered, idx a2-80 in 0..16, default L_0685, 17-entry rodata table all consumed with every target an in-skeleton boundary; 15 calls and 31 refs match funcdb-v3; 13 indirect sites cite driving loads
 * Edges: funcdb-v3 (calls=15, refs=32); reloc-direct=15, funcdb-attributed=0, unknown-indirect=13 */
u32 esp_mesh_send(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 00e0: entry a1, 96 (frame 96 bytes) */
  a9 = a2;  /* 00e3 */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 00e5: l32r -> global */
  a8 = a3;  /* 00e8 */
  a2 = LD8U(a2 + 0x0);  /* 00ea */
  ST32(a1 + 0x20, a5);  /* 00ed */
  ST32(a1 + 0x24, a6);  /* 00ef */
  if (a2 != 0) goto L_0126;  /* 00f1: bnez.n a2, 126 <esp_mesh_send+0x46> */
  L_00f3: a2 = (u32)&g_log_level + 0x0;  /* 00f3: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00f6 */
  a6 = 0x00004004u;  /* 00f8: l32r = 16388 */
  if (a2 >= 3u) goto L_0101;  /* 00fb: bgeui a2, 3, 101 <esp_mesh_send+0x21> */
  L_00fe: goto L_06b5;  /* 00fe: j */
  L_0101: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0101: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0104 */
  if (a2 == 0) goto L_06b5;  /* 0106: beqz a2, 6b5 <esp_mesh_send+0x5d5> */
  L_0109: a3 = LD32(a2 + 0x150);  /* 0109 */
  if (a3 == 0) goto L_06b5;  /* 010c: beqz a3, 6b5 <esp_mesh_send+0x5d5> */
  L_010f: a10 = LD32(a2 + 0x158);  /* 010f */
  __asm__ volatile("" ::: "memory");  /* 0112: memw */
  /* 0115: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0118 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 011a: -> "mesh" */
  a14 = a11;  /* 011d */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 011f: -> "mesh" */
  goto L_0600;  /* 0122: j */
  L_0126: a2 = 9;  /* 0126 */
  a5 = LD32(a1 + 0x20);  /* 0128 */
  a3 = 0;  /* 012a */
  ST32(a1 + 0x10, a2);  /* 012c */
  a2 = 1;  /* 012e */
  if (a5 == 0) a2 = a3;  /* 0130 */
  a2 = (a2 >> 8) & 0x1;  /* 0133: extui width 1 */
  a6 = LD32(a1 + 0x24);  /* 0136 */
  ST32(a1 + 0x14, a3);  /* 0138 */
  if (a6 == 1) goto L_0149;  /* 013a: beqi a6, 1, 149 <esp_mesh_send+0x69> */
  L_013d: if (a2 == a3) goto L_0149;  /* 013d: beq a2, a3, 149 <esp_mesh_send+0x69> */
  L_0140: a6 = 0x00004008u;  /* 0140: l32r = 16392 */
  __asm__ volatile("" ::: "memory");  /* 0143: memw */
  goto L_06b5;  /* 0146: j */
  L_0149: a3 = LD32(a1 + 0x20);  /* 0149 */
  if (a3 == 0) goto L_016c;  /* 014b: beqz.n a3, 16c <esp_mesh_send+0x8c> */
  L_014d: a3 = LD8U(a3 + 0x0);  /* 014d */
  if (a3 != 7) goto L_0161;  /* 0150: bnei a3, 7, 161 <esp_mesh_send+0x81> */
  L_0153: if (a8 == 0) goto L_0140;  /* 0153: beqz a8, 140 <esp_mesh_send+0x60> */
  L_0156: if (a9 == 0) goto L_016e;  /* 0156: beqz.n a9, 16e <esp_mesh_send+0x8e> */
  L_0158: a3 = LD8U(a9 + 0x0);  /* 0158 */
  if (((a3 >> 0) & 1) != 0) goto L_0176;  /* 015b: bbsi a3, 0, 176 <esp_mesh_send+0x96> */
  L_015e: goto L_0140;  /* 015e: j */
  L_0161: if (a3 >= 7u) goto L_016c;  /* 0161: bgeui a3, 7, 16c <esp_mesh_send+0x8c> */
  L_0164: a6 = 0x00004011u;  /* 0164: l32r = 16401 */
  goto L_06b5;  /* 0167: j */
  L_016c: if (a9 != 0) goto L_0176;  /* 016c: bnez.n a9, 176 <esp_mesh_send+0x96> */
  L_016e: a3 = 10;  /* 016e */
  a9 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 0170: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a4 = a4 | a3;  /* 0173 */
  L_0176: a10 = a9;  /* 0176 */
  a12 = 6;  /* 0178 */
  a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 017a: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  ST32(a1 + 0x3c, a8);  /* 017d */
  ST32(a1 + 0x38, a9);  /* 017f */
  __asm__ volatile("" ::: "memory");  /* 0181: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0184: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0187: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x3c);  /* 018a */
  a9 = LD32(a1 + 0x38);  /* 018c */
  if (a10 == 0) goto L_0199;  /* 018e: beqz.n a10, 199 <esp_mesh_send+0xb9> */
  L_0190: a3 = LD8U(a9 + 0x0);  /* 0190 */
  if (((a3 >> 0) & 1) == 0) goto L_019e;  /* 0193: bbci a3, 0, 19e <esp_mesh_send+0xbe> */
  L_0196: if (((a4 >> 3) & 1) != 0) goto L_01a1;  /* 0196: bbsi a4, 3, 1a1 <esp_mesh_send+0xc1> */
  L_0199: a3 = 18;  /* 0199 */
  a4 = a4 | a3;  /* 019b */
  L_019e: if (((a4 >> 3) & 1) == 0) goto L_01d0;  /* 019e: bbci a4, 3, 1d0 <esp_mesh_send+0xf0> */
  L_01a1: a5 = (u32)&g_mesh_is_root + 0x0;  /* 01a1: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 01a4: memw */
  a3 = LD8U(a5 + 0x0);  /* 01a7 */
  a3 = (a3 >> 8) & 0x1;  /* 01aa: extui width 1 */
  if (a3 == 0) goto L_01b8;  /* 01ad: beqz.n a3, 1b8 <esp_mesh_send+0xd8> */
  L_01af: a3 = (u32)&g_is_root_fixed + 0x0;  /* 01af: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 01b2 */
  if (a3 == 0) goto L_01c4;  /* 01b5: beqz a3, 1c4 <esp_mesh_send+0xe4> */
  L_01b8: __asm__ volatile("" ::: "memory");  /* 01b8: memw */
  a3 = LD8U(a5 + 0x0);  /* 01bb */
  a3 = (a3 >> 8) & 0x1;  /* 01be: extui width 1 */
  if (a3 != 0) goto L_01d0;  /* 01c1: bnez a3, 1d0 <esp_mesh_send+0xf0> */
  L_01c4: a3 = (u32)&g_is_wifi_connected + 0x0;  /* 01c4: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 01c7 */
  a6 = 0x0000400bu;  /* 01ca: l32r = 16395 */
  if (a3 == 0) goto L_06b5;  /* 01cd: beqz a3, 6b5 <esp_mesh_send+0x5d5> */
  L_01d0: a3 = 14;  /* 01d0 */
  if ((a4 & a3) != 0) goto L_01d8;  /* 01d2: bany a4, a3, 1d8 <esp_mesh_send+0xf8> */
  L_01d5: goto L_0140;  /* 01d5: j */
  L_01d8: if (a8 == 0) goto L_0205;  /* 01d8: beqz.n a8, 205 <esp_mesh_send+0x125> */
  L_01da: a3 = LD32(a8 + 0x0);  /* 01da */
  if (a3 == 0) goto L_0140;  /* 01dc: beqz a3, 140 <esp_mesh_send+0x60> */
  L_01df: a5 = 0x5bb;  /* 01df */
  a3 = (u32)&g_mesh_topology + 0x0;  /* 01e2: l32r -> global */
  a6 = LD32(a3 + 0x0);  /* 01e5 */
  a3 = 0x5c0;  /* 01e7 */
  if (a6 != 0) a3 = a5;  /* 01ea */
  a7 = LD16U(a8 + 0x4);  /* 01ed */
  if (a3 >= a7) goto L_01f6;  /* 01f0: bgeu a3, a7, 1f6 <esp_mesh_send+0x116> */
  L_01f3: goto L_0140;  /* 01f3: j */
  L_01f6: a3 = LD32(a8 + 0xc);  /* 01f6 */
  a6 = 0x00004005u;  /* 01f8: l32r = 16389 */
  if (a3 != 1) goto L_0201;  /* 01fb: bnei a3, 1, 201 <esp_mesh_send+0x121> */
  L_01fe: goto L_06b5;  /* 01fe: j */
  L_0201: goto L_0207;  /* 0201: j */
  L_0205: a7 = a8;  /* 0205 */
  L_0207: a6 = LD32(a1 + 0x24);  /* 0207 */
  a3 = 1;  /* 0209 */
  a5 = 0;  /* 020b */
  if (a6 == 0) a3 = a5;  /* 020d */
  a3 = a2 & a3;  /* 0210 */
  ST32(a1 + 0x2c, a3);  /* 0213 */
  if (a3 != a5) goto L_0224;  /* 0215: bne a3, a5, 224 <esp_mesh_send+0x144> */
  L_0218: a5 = LD32(a1 + 0x14);  /* 0218 */
  a2 = a5 + a7;  /* 021a */
  if (a2 != 0) goto L_0244;  /* 021c: bnez.n a2, 244 <esp_mesh_send+0x164> */
  L_021e: __asm__ volatile("" ::: "memory");  /* 021e: memw */
  goto L_0140;  /* 0221: j */
  L_0224: a11 = LD32(a1 + 0x24);  /* 0224 */
  a12 = a1 + (20);  /* 0226 */
  a10 = LD32(a1 + 0x20);  /* 0229 */
  ST32(a1 + 0x3c, a8);  /* 022b */
  ST32(a1 + 0x38, a9);  /* 022d */
  __asm__ volatile("" ::: "memory");  /* 022f: memw */
  a8 = (u32)&mesh_parse_option;  /* 0232: l32r -> func addr */
  a2 = mesh_parse_option(a2, a3, a4, a5, a6, a7);  /* 0235: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x3c);  /* 0238 */
  a9 = LD32(a1 + 0x38);  /* 023a */
  if (a10 == 0) goto L_0218;  /* 023c: beqz a10, 218 <esp_mesh_send+0x138> */
  L_023f: goto L_0164;  /* 023f: j */
  L_0244: a10 = (u32)&g_mesh_topology + 0x0;  /* 0244: l32r -> global */
  a3 = 28;  /* 0247 */
  a6 = 33;  /* 0249 */
  a2 = LD32(a10 + 0x0);  /* 024b */
  if (a2 == 0) a6 = a3;  /* 024d */
  a6 = a5 + a6;  /* 0250 */
  a10 = (a6 >> 2) & 0x1;  /* 0252: extui width 1 */
  a3 = 1;  /* 0255 */
  a2 = 0;  /* 0257 */
  a6 = a6 >> 2;  /* 0259 */
  if (a10 != 0) a2 = a3;  /* 025c */
  a2 = a2 + a6;  /* 025f */
  a2 = a2 << 2;  /* 0261 */
  a6 = 0x3fc;  /* 0264 */
  if (a6 >= a2) goto L_026d;  /* 0267: bgeu a6, a2, 26d <esp_mesh_send+0x18d> */
  L_026a: goto L_0140;  /* 026a: j */
  L_026d: a13 = a7 + a2;  /* 026d */
  a2 = 0x5dc;  /* 026f */
  a6 = 0x00004009u;  /* 0272: l32r = 16393 */
  if (a2 >= a13) goto L_027b;  /* 0275: bgeu a2, a13, 27b <esp_mesh_send+0x19b> */
  L_0278: goto L_06b5;  /* 0278: j */
  L_027b: a10 = a13 + (14);  /* 027b */
  a12 = 0x3d6;  /* 027d */
  a11 = (u32)(RODATA__rodata___func___8 + 0x0);  /* 0280: l32r -> .rodata.__func__$8 */
  ST32(a1 + 0x3c, a8);  /* 0283 */
  ST32(a1 + 0x38, a9);  /* 0285 */
  ST32(a1 + 0x34, a13);  /* 0287 */
  __asm__ volatile("" ::: "memory");  /* 0289: memw */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 028c: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 028f: callx a8 via reloc-expand */
  a2 = a10;  /* 0292 */
  a6 = 0x00004007u;  /* 0294: l32r = 16391 */
  a8 = LD32(a1 + 0x3c);  /* 0297 */
  a9 = LD32(a1 + 0x38);  /* 0299 */
  a13 = LD32(a1 + 0x34);  /* 029b */
  if (a10 == 0) goto L_06b5;  /* 029d: beqz a10, 6b5 <esp_mesh_send+0x5d5> */
  L_02a0: a11 = -9;  /* 02a0 */
  a7 = LD32(a10 + 0x0);  /* 02a2 */
  a10 = -16;  /* 02a4 */
  a6 = a7 + (14);  /* 02a6 */
  ST32(a1 + 0x28, a6);  /* 02a8 */
  a6 = LD8U(a7 + 0xe);  /* 02aa */
  a6 = a6 & a10;  /* 02ad */
  a6 = a6 | a3;  /* 02b0 */
  ST8(a7 + 0xe, a6);  /* 02b3 */
  __asm__ volatile("" ::: "memory");  /* 02b6: memw */
  a6 = LD32(a2 + 0x28);  /* 02b9 */
  a6 = a6 | a3;  /* 02bb */
  a10 = (u32)&g_mesh_is_root + 0x0;  /* 02be: l32r -> global */
  ST32(a2 + 0x28, a6);  /* 02c1 */
  a6 = a6 & a11;  /* 02c3 */
  a11 = a4;  /* 02c6 */
  a4 = 33;  /* 02c8 */
  __asm__ volatile("" ::: "memory");  /* 02ca: memw */
  a10 = LD8U(a10 + 0x0);  /* 02cd */
  a10 = a10 & a3;  /* 02d0 */
  a10 = a10 << 3;  /* 02d3 */
  a6 = a6 | a10;  /* 02d6 */
  ST32(a2 + 0x28, a6);  /* 02d9 */
  a6 = 3;  /* 02db */
  a10 = a2;  /* 02dd */
  ST8(a2 + 0x12, a6);  /* 02df */
  __asm__ volatile("" ::: "memory");  /* 02e2: memw */
  ST32(a1 + 0x3c, a8);  /* 02e5 */
  ST32(a1 + 0x38, a9);  /* 02e7 */
  ST32(a1 + 0x34, a13);  /* 02e9 */
  __asm__ volatile("" ::: "memory");  /* 02eb: memw */
  a8 = (u32)&mesh_send_process_flag;  /* 02ee: l32r -> func addr */
  a2 = mesh_send_process_flag(a2, a3, a4, a5, a6, a7);  /* 02f1: callx a8 via reloc-expand */
  a10 = (u32)&g_mesh_topology + 0x0;  /* 02f4: l32r -> global */
  a6 = LD32(a10 + 0x0);  /* 02f7 */
  a10 = 28;  /* 02f9 */
  if (a6 == 0) a4 = a10;  /* 02fb */
  a5 = a5 + a4;  /* 02fe */
  a6 = (a5 >> 2) & 0x1;  /* 0300: extui width 1 */
  a4 = 0;  /* 0303 */
  a5 = a5 >> 2;  /* 0305 */
  if (a6 != 0) a4 = a3;  /* 0308 */
  a4 = a4 + a5;  /* 030b */
  ST8(a7 + 0xf, a4);  /* 030d */
  __asm__ volatile("" ::: "memory");  /* 0310: memw */
  a5 = a7 + (18);  /* 0313 */
  a13 = LD32(a1 + 0x34);  /* 0316 */
  a13 = (a13 >> 16) & 0x1;  /* 0318: extui width 1 */
  a10 = LD32(a1 + 0x28);  /* 031b */
  ST16(a7 + 0x10, a13);  /* 031d */
  __asm__ volatile("" ::: "memory");  /* 0320: memw */
  ST32(a1 + 0x30, a13);  /* 0323 */
  __asm__ volatile("" ::: "memory");  /* 0325: memw */
  a8 = (u32)&mesh_send_process_topo;  /* 0328: l32r -> func addr */
  a2 = mesh_send_process_topo(a2, a3, a4, a5, a6, a7);  /* 032b: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x3c);  /* 032e */
  a9 = LD32(a1 + 0x38);  /* 0330 */
  if (a8 == 0) goto L_0359;  /* 0332: beqz.n a8, 359 <esp_mesh_send+0x279> */
  L_0334: a3 = 0x100;  /* 0334 */
  a10 = 0xfffffec0;  /* 0337 */
  a6 = LD32(a8 + 0x8);  /* 033a */
  a6 = (a6 >> 6) & 0x1;  /* 033c: extui width 1 */
  a3 = a3 | a6;  /* 033f */
  a6 = LD16U(a7 + 0x14);  /* 0342 */
  a6 = a6 & a10;  /* 0345 */
  a3 = a3 | a6;  /* 0348 */
  a4 = LD32(a8 + 0xc);  /* 034b */
  ST16(a7 + 0x14, a3);  /* 034d */
  __asm__ volatile("" ::: "memory");  /* 0350: memw */
  __asm__ volatile("" ::: "memory");  /* 0353: memw */
  goto L_0371;  /* 0356: j */
  L_0359: a6 = LD32(a1 + 0x20);  /* 0359 */
  a4 = 2;  /* 035b */
  if (a6 == 0) goto L_0371;  /* 035d: beqz.n a6, 371 <esp_mesh_send+0x291> */
  L_035f: a6 = LD8U(a6 + 0x0);  /* 035f */
  if (a6 != 8) goto L_0371;  /* 0362: bnei a6, 8, 371 <esp_mesh_send+0x291> */
  L_0365: a3 = a3 << 24;  /* 0365 */
  a4 = LD32(a5 + 0x0);  /* 0368 */
  a3 = a4 | a3;  /* 036a */
  a4 = a8;  /* 036d */
  ST32(a5 + 0x0, a3);  /* 036f */
  L_0371: a6 = a7 + (22);  /* 0371 */
  a12 = 6;  /* 0374 */
  a11 = a9;  /* 0376 */
  a10 = a6;  /* 0378 */
  ST32(a1 + 0x3c, a8);  /* 037a */
  __asm__ volatile("" ::: "memory");  /* 037c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 037f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0382: callx a8 (libc, via reloc-expand) */
  a3 = LD32(a5 + 0x0);  /* 0385 */
  a8 = LD32(a1 + 0x3c);  /* 0387 */
  if (((a3 >> 27) & 1) != 0) goto L_03b6;  /* 0389: bbsi a3, 27, 3b6 <esp_mesh_send+0x2d6> */
  L_038c: a12 = 6;  /* 038c */
  a10 = a6;  /* 038e */
  a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 0390: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  a8 = (u32)&memcmp + 0x0;  /* 0393: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0396: callx a8 (libc, via reloc-expand) */
  a8 = LD32(a1 + 0x3c);  /* 0399 */
  if (a10 == 0) goto L_03b6;  /* 039b: beqz.n a10, 3b6 <esp_mesh_send+0x2d6> */
  L_039d: a3 = LD8U(a7 + 0x16);  /* 039d */
  if (((a3 >> 0) & 1) == 0) goto L_03b8;  /* 03a0: bbci a3, 0, 3b8 <esp_mesh_send+0x2d8> */
  L_03a3: a3 = LD8U(a7 + 0xe);  /* 03a3 */
  if (((a3 >> 5) & 1) != 0) goto L_03b8;  /* 03a6: bbsi a3, 5, 3b8 <esp_mesh_send+0x2d8> */
  L_03a9: a3 = 1;  /* 03a9 */
  ST16(a7 + 0x16, a3);  /* 03ab */
  a3 = 94;  /* 03ae */
  ST8(a7 + 0x18, a3);  /* 03b0 */
  __asm__ volatile("" ::: "memory");  /* 03b3: memw */
  L_03b6: a4 = 2;  /* 03b6 */
  L_03b8: a9 = (a4 >> 2) & 0x1;  /* 03b8: extui width 1 */
  a9 = a9 << 14;  /* 03bb */
  a12 = 6;  /* 03be */
  a3 = LD32(a5 + 0x0);  /* 03c0 */
  a10 = 0xffff3fffu;  /* 03c2: l32r = -49153 */
  a3 = a3 & a10;  /* 03c5 */
  a3 = a3 | a9;  /* 03c8 */
  a10 = a7 + (28);  /* 03cb */
  ST32(a5 + 0x0, a3);  /* 03ce */
  a5 = 2;  /* 03d0 */
  a3 = LD32(a2 + 0x28);  /* 03d2 */
  a5 = a5 & a3;  /* 03d4 */
  a3 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 03d7: l32r -> global */
  a11 = a3;  /* 03da: mov */
  ST32(a1 + 0x3c, a8);  /* 03dd */
  __asm__ volatile("" ::: "memory");  /* 03df: memw */
  a8 = (u32)&memcpy + 0x0;  /* 03e2: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 03e5: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x2c);  /* 03e8 */
  a8 = LD32(a1 + 0x3c);  /* 03ea */
  if (a9 == 0) goto L_040d;  /* 03ec: beqz.n a9, 40d <esp_mesh_send+0x32d> */
  L_03ee: a12 = 28;  /* 03ee */
  a9 = (u32)&g_mesh_topology + 0x0;  /* 03f0: l32r -> global */
  a10 = LD32(a9 + 0x0);  /* 03f3 */
  a9 = 33;  /* 03f5 */
  if (a10 != 0) a12 = a9;  /* 03f7 */
  a9 = LD32(a1 + 0x28);  /* 03fa */
  a12 = a9 + a12;  /* 03fc */
  a11 = LD32(a1 + 0x24);  /* 03fe */
  a10 = LD32(a1 + 0x20);  /* 0401 */
  a8 = (u32)&mesh_add_option;  /* 0404: l32r -> func addr */
  a2 = mesh_add_option(a2, a3, a4, a5, a6, a7);  /* 0407: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x3c);  /* 040a */
  L_040d: if (a8 == 0) goto L_0422;  /* 040d: beqz.n a8, 422 <esp_mesh_send+0x342> */
  L_040f: a10 = LD8U(a7 + 0xf);  /* 040f */
  a12 = LD16U(a8 + 0x4);  /* 0412 */
  a11 = LD32(a8 + 0x0);  /* 0415 */
  a8 = LD32(a1 + 0x28);  /* 0417 */
  a10 = a10 + (a8 << 2);  /* 0419 */
  a8 = (u32)&memcpy + 0x0;  /* 041c: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 041f: callx a8 (libc, via reloc-expand) */
  L_0422: a12 = 6;  /* 0422 */
  a9 = LD32(a1 + 0x30);  /* 0424 */
  a11 = a3;  /* 0426 */
  a8 = a9 + (14);  /* 0428 */
  a10 = a2 + (12);  /* 042b */
  ST16(a2 + 0x4, a8);  /* 042e */
  __asm__ volatile("" ::: "memory");  /* 0431: memw */
  __asm__ volatile("" ::: "memory");  /* 0434: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0437: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 043a: callx a8 (libc, via reloc-expand) */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 043d: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0440 */
  a10 = LD32(a8 + 0x110);  /* 0443 */
  /* 0446: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a12 = 0x436;  /* 0449 */
  a8 = (u32)&s_mesh_send_mutex + 0x0;  /* 044c: l32r -> global */
  ST32(a2 + 0x18, a10);  /* 044f */
  ST32(a2 + 0x1c, a11);  /* 0451 */
  a10 = LD32(a8 + 0x0);  /* 0453 */
  a11 = (u32)(RODATA__rodata___func___8 + 0x0);  /* 0455: l32r -> .rodata.__func__$8 */
  __asm__ volatile("" ::: "memory");  /* 0458: memw */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 045b: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 045e: callx a8 via reloc-expand */
  a10 = a6;  /* 0461 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0463: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0466: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0488;  /* 0469: bnez.n a10, 488 <esp_mesh_send+0x3a8> */
  L_046b: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 046b: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 046e */
  a10 = a6;  /* 0470 */
  a8 = (u32)&memcmp + 0x0;  /* 0472: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0475: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&g_mesh_is_root + 0x0;  /* 0478: l32r -> global */
  if (a10 != 0) goto L_0498;  /* 047b: bnez.n a10, 498 <esp_mesh_send+0x3b8> */
  L_047d: __asm__ volatile("" ::: "memory");  /* 047d: memw */
  a6 = LD8U(a8 + 0x0);  /* 0480 */
  a6 = (a6 >> 8) & 0x1;  /* 0483: extui width 1 */
  if (a6 == 0) goto L_0498;  /* 0486: beqz.n a6, 498 <esp_mesh_send+0x3b8> */
  L_0488: a10 = a2;  /* 0488 */
  a8 = (u32)&esp_mesh_delivery_toSelf + 0x0;  /* 048a: l32r -> global */
  a2 = esp_mesh_delivery_toSelf(a2, a3, a4, a5, a6, a7);  /* 048d: callx a8 via reloc-expand */
  a6 = a10;  /* 0490 */
  a4 = 2;  /* 0492 */
  goto L_04b8;  /* 0494: j */
  L_0498: __asm__ volatile("" ::: "memory");  /* 0498: memw */
  a6 = LD8U(a8 + 0x0);  /* 049b */
  a6 = (a6 >> 8) & 0x1;  /* 049e: extui width 1 */
  if (a6 == 0) goto L_04ae;  /* 04a1: beqz.n a6, 4ae <esp_mesh_send+0x3ce> */
  L_04a3: a8 = 2;  /* 04a3 */
  a6 = LD8U(a7 + 0xe);  /* 04a5 */
  a6 = (a6 >> 1) & 0x3f;  /* 04a8: extui width 6 */
  if (a6 != 0) a4 = a8;  /* 04ab */
  L_04ae: a10 = a2;  /* 04ae */
  a8 = (u32)&esp_mesh_forward_packet + 0x0;  /* 04b0: l32r -> global */
  a2 = esp_mesh_forward_packet(a2, a3, a4, a5, a6, a7);  /* 04b3: callx a8 via reloc-expand */
  a6 = a10;  /* 04b6 */
  L_04b8: a9 = (u32)&s_mesh_send_mutex + 0x0;  /* 04b8: l32r -> global */
  a12 = 0x442;  /* 04bb */
  a11 = (u32)(RODATA__rodata___func___8 + 0x0);  /* 04be: l32r -> .rodata.__func__$8 */
  a10 = LD32(a9 + 0x0);  /* 04c1 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 04c4: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 04c7: callx a8 via reloc-expand */
  if (a5 != 0) goto L_04e4;  /* 04ca: bnez.n a5, 4e4 <esp_mesh_send+0x404> */
  L_04cc: a8 = 1;  /* 04cc */
  a9 = 0xffffbff3u;  /* 04ce: l32r = -16397 */
  a10 = a5;  /* 04d1 */
  a9 = a6 + a9;  /* 04d3 */
  if (a9 == 0) a10 = a8;  /* 04d5 */
  if (a10 != 0) goto L_04f8;  /* 04d8: bnez.n a10, 4f8 <esp_mesh_send+0x418> */
  L_04da: a9 = 0xffffbfeeu;  /* 04da: l32r = -16402 */
  a9 = a6 + a9;  /* 04dd */
  if (a9 != 0) a8 = a5;  /* 04df */
  if (a8 != 0) goto L_04f8;  /* 04e2: bnez.n a8, 4f8 <esp_mesh_send+0x418> */
  L_04e4: if (a6 == 0) goto L_04fe;  /* 04e4: beqz.n a6, 4fe <esp_mesh_send+0x41e> */
  L_04e6: a11 = (u32)(RODATA__rodata___func___8 + 0x0);  /* 04e6: l32r -> .rodata.__func__$8 */
  a12 = 0x457;  /* 04e9 */
  a10 = a2;  /* 04ec */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 04ee: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 04f1: callx a8 via reloc-expand */
  goto L_06b5;  /* 04f4: j */
  L_04f8: a8 = (u32)&esp_mesh_send_sem_wait;  /* 04f8: l32r -> func addr */
  a2 = esp_mesh_send_sem_wait(a2, a3, a4, a5, a6, a7);  /* 04fb: callx a8 via reloc-expand */
  L_04fe: if (a4 == 0) goto L_0505;  /* 04fe: beqz.n a4, 505 <esp_mesh_send+0x425> */
  L_0500: a6 = 0;  /* 0500 */
  goto L_06b5;  /* 0502: j */
  L_0505: a2 = (u32)&mesh_xmit_state_mbox + 0x0;  /* 0505: l32r -> global */
  a10 = LD32(a2 + 0x0);  /* 0508 */
  if (a10 == 0) goto L_0500;  /* 050a: beqz a10, 500 <esp_mesh_send+0x420> */
  L_050d: a5 = 2;  /* 050d */
  a12 = -1;  /* 050f */
  a4 = LD8U(a2 + 0x8);  /* 0511 */
  a11 = a1 + (16);  /* 0514 */
  a4 = a4 | a5;  /* 0517 */
  ST8(a2 + 0x8, a4);  /* 051a */
  __asm__ volatile("" ::: "memory");  /* 051d: memw */
  a4 = LD32(a3 + 0x0);  /* 0520 */
  a4 = LD32(a4 + 0x74);  /* 0523 */
  __asm__ volatile("" ::: "memory");  /* 0526: memw */
  /* 0529: INDIRECT callx a4 <- mem[a4+0x74]; result unknown */ a2 = 0;
  a5 = a10;  /* 052c */
  a4 = (u32)&g_mesh_stop_event_group + 0x0;  /* 052e: l32r -> global */
  a10 = LD32(a4 + 0x0);  /* 0531 */
  if (a10 == 0) goto L_0540;  /* 0533: beqz.n a10, 540 <esp_mesh_send+0x460> */
  L_0535: a11 = 8;  /* 0535 */
  a4 = LD32(a3 + 0x0);  /* 0537 */
  a4 = LD32(a4 + 0x84);  /* 053a */
  /* 053d: INDIRECT callx a4 <- mem[a4+0x84]; result unknown */ a2 = 0;
  L_0540: a6 = -3;  /* 0540 */
  a4 = LD8U(a2 + 0x8);  /* 0542 */
  a4 = a4 & a6;  /* 0545 */
  ST8(a2 + 0x8, a4);  /* 0548 */
  __asm__ volatile("" ::: "memory");  /* 054b: memw */
  a6 = 0x00004018u;  /* 054e: l32r = 16408 */
  if (a5 == 1) goto L_0557;  /* 0551: beqi a5, 1, 557 <esp_mesh_send+0x477> */
  L_0554: goto L_06b5;  /* 0554: j */
  L_0557: a2 = LD32(a1 + 0x10);  /* 0557 */
  if (a2 == 1) goto L_0500;  /* 0559: beqi a2, 1, 500 <esp_mesh_send+0x420> */
  L_055c: a6 = 0x0000400au;  /* 055c: l32r = 16394 */
  if (a2 != 6) goto L_0565;  /* 055f: bnei a2, 6, 565 <esp_mesh_send+0x485> */
  L_0562: goto L_06b5;  /* 0562: j */
  L_0565: a6 = 0x0000400bu;  /* 0565: l32r = 16395 */
  if (a2 != 7) goto L_056e;  /* 0568: bnei a2, 7, 56e <esp_mesh_send+0x48e> */
  L_056b: goto L_06b5;  /* 056b: j */
  L_056e: a4 = 8;  /* 056e */
  if ((i32)a4 < (i32)a2) goto L_05bc;  /* 0570: blt a4, a2, 5bc <esp_mesh_send+0x4dc> */
  L_0573: a2 = (u32)&g_log_level + 0x0;  /* 0573: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0576 */
  a6 = 0x00004017u;  /* 0578: l32r = 16407 */
  if (a2 >= 3u) goto L_0581;  /* 057b: bgeui a2, 3, 581 <esp_mesh_send+0x4a1> */
  L_057e: goto L_06b5;  /* 057e: j */
  L_0581: a2 = LD32(a3 + 0x0);  /* 0581 */
  if (a2 == 0) goto L_06b5;  /* 0584: beqz a2, 6b5 <esp_mesh_send+0x5d5> */
  L_0587: a3 = LD32(a2 + 0x150);  /* 0587 */
  if (a3 == 0) goto L_06b5;  /* 058a: beqz a3, 6b5 <esp_mesh_send+0x5d5> */
  L_058d: a10 = LD32(a2 + 0x158);  /* 058d */
  __asm__ volatile("" ::: "memory");  /* 0590: memw */
  /* 0593: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 0596 */
  a2 = LD32(a1 + 0x10);  /* 0598 */
  a10 = a2;  /* 059a */
  a8 = (u32)&tx_state_id2str + 0x0;  /* 059c: l32r -> global */
  a2 = tx_state_id2str(a2, a3, a4, a5, a6, a7);  /* 059f: callx a8 via reloc-expand */
  a15 = a2;  /* 05a2 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 05a4: -> "mesh" */
  a13 = a4;  /* 05a7 */
  a14 = a11;  /* 05a9 */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_str1_1 + 0x0);  /* 05ab: l32r -> .rodata.esp_mesh_send.str1.1 */
  ST32(a1 + 0x0, a10);  /* 05ae */
  a10 = 3;  /* 05b0 */
  __asm__ volatile("" ::: "memory");  /* 05b2: memw */
  /* 05b5: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_06b5;  /* 05b8: j */
  L_05bc: a2 = a2 + (-80);  /* 05bc */
  a4 = 16;  /* 05bf */
  if (a4 >= a2) goto L_05c7;  /* 05c1: bgeu a4, a2, 5c7 <esp_mesh_send+0x4e7> */
  L_05c4: goto L_0685;  /* 05c4: j */
  /* JX-DISPATCH recovered from rodata.esp_mesh_send base +0: 17 words of R_XTENSA_32
     absolutized at link time to text.esp_mesh_send plus the stored offset, verified
     word-for-word against readelf relocs. All 17 entries consumed.
     Switch on the a2 frame word from LD32 sp+0x10, pre-filtered upstream: value 1
     routes to L_0500, values 6 and 7 exit at L_06b5, inflow here only when a2 is
     greater than 8 signed at L_0570. idx = a2-80 in 0..16 covers ids 80..96,
     default L_0685, bounds check at L_05c1.
     id to target map: 80 to 0x6b2, 81 to 0x5d8, 82 to 0x608, 83 to 0x633,
     84 to 0x5d2, 85 to 0x65b, 86 to 0x6b2, 87 to 0x685, 88 to 0x685, 89 to 0x685,
     90 to 0x6b2, 91 to 0x6b2, 92 to 0x6b2, 93 to 0x6b2, 94 to 0x6b2, 95 to 0x6b2,
     96 to 0x6b2.
     Every target is an in-skeleton instruction boundary: 0x6b2 in L_06ad, 0x5d8
     and 0x5d2 in L_05c7, 0x608 in L_0600, 0x633 in L_0620, 0x65b in L_0648,
     0x685 is L_0685. */
  L_05c7: a4 = (u32)(RODATA__rodata_esp_mesh_send + 0x0);  /* 05c7: l32r -> .rodata.esp_mesh_send */
  a2 = (a2 << 2) + a4;  /* 05ca: addx4 = base + idx*4 */
  a2 = LD32(a2 + 0x0);  /* 05cd */
  /* 05cf: jx a2 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a6 = 0x00004007u;  /* 05d2: l32r = 16391 */
  goto L_06b5;  /* 05d5: j */
  a2 = (u32)&g_log_level + 0x0;  /* 05d8: l32r -> global */
  a6 = -1;  /* 05db */
  a2 = LD32(a2 + 0x0);  /* 05dd */
  if (a2 >= 3u) goto L_05e5;  /* 05df: bgeui a2, 3, 5e5 <esp_mesh_send+0x505> */
  L_05e2: goto L_06b5;  /* 05e2: j */
  L_05e5: a2 = LD32(a3 + 0x0);  /* 05e5 */
  if (a2 == 0) goto L_06b5;  /* 05e7: beqz a2, 6b5 <esp_mesh_send+0x5d5> */
  L_05ea: a3 = LD32(a2 + 0x150);  /* 05ea */
  if (a3 == 0) goto L_06b5;  /* 05ed: beqz a3, 6b5 <esp_mesh_send+0x5d5> */
  L_05f0: a10 = LD32(a2 + 0x158);  /* 05f0 */
  /* 05f3: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 05f6 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 05f8: -> "mesh" */
  a14 = a11;  /* 05fb */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_str1_1 + 0x0);  /* 05fd: l32r -> .rodata.esp_mesh_send.str1.1 */
  L_0600: a10 = 3;  /* 0600 */
  /* 0602: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_06b5;  /* 0605: j */
  a2 = (u32)&g_log_level + 0x0;  /* 0608: l32r -> global */
  a6 = -1;  /* 060b */
  a2 = LD32(a2 + 0x0);  /* 060d */
  if (a2 >= 3u) goto L_0615;  /* 060f: bgeui a2, 3, 615 <esp_mesh_send+0x535> */
  L_0612: goto L_06b5;  /* 0612: j */
  L_0615: a2 = LD32(a3 + 0x0);  /* 0615 */
  if (a2 == 0) goto L_06b5;  /* 0617: beqz a2, 6b5 <esp_mesh_send+0x5d5> */
  L_061a: a3 = LD32(a2 + 0x150);  /* 061a */
  if (a3 == 0) goto L_06b5;  /* 061d: beqz a3, 6b5 <esp_mesh_send+0x5d5> */
  L_0620: a10 = LD32(a2 + 0x158);  /* 0620 */
  /* 0623: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0626 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0628: -> "mesh" */
  a14 = a11;  /* 062b */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_str1_1 + 0x0);  /* 062d: l32r -> .rodata.esp_mesh_send.str1.1 */
  goto L_0600;  /* 0630: j */
  a2 = (u32)&g_log_level + 0x0;  /* 0633: l32r -> global */
  a6 = -1;  /* 0636 */
  a2 = LD32(a2 + 0x0);  /* 0638 */
  if (a2 < 3u) goto L_06b5;  /* 063a: bltui a2, 3, 6b5 <esp_mesh_send+0x5d5> */
  L_063d: a2 = LD32(a3 + 0x0);  /* 063d */
  if (a2 == 0) goto L_06b5;  /* 063f: beqz a2, 6b5 <esp_mesh_send+0x5d5> */
  L_0642: a3 = LD32(a2 + 0x150);  /* 0642 */
  if (a3 == 0) goto L_06b5;  /* 0645: beqz a3, 6b5 <esp_mesh_send+0x5d5> */
  L_0648: a10 = LD32(a2 + 0x158);  /* 0648 */
  /* 064b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 064e */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0650: -> "mesh" */
  a14 = a11;  /* 0653 */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_str1_1 + 0x0);  /* 0655: l32r -> .rodata.esp_mesh_send.str1.1 */
  goto L_0600;  /* 0658: j */
  a2 = (u32)&g_log_level + 0x0;  /* 065b: l32r -> global */
  a6 = -1;  /* 065e */
  a2 = LD32(a2 + 0x0);  /* 0660 */
  if (a2 < 3u) goto L_06b5;  /* 0662: bltui a2, 3, 6b5 <esp_mesh_send+0x5d5> */
  L_0665: a2 = LD32(a3 + 0x0);  /* 0665 */
  if (a2 == 0) goto L_06b5;  /* 0667: beqz a2, 6b5 <esp_mesh_send+0x5d5> */
  L_066a: a3 = LD32(a2 + 0x150);  /* 066a */
  if (a3 == 0) goto L_06b5;  /* 066d: beqz a3, 6b5 <esp_mesh_send+0x5d5> */
  L_0670: a10 = LD32(a2 + 0x158);  /* 0670 */
  /* 0673: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0676 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0678: -> "mesh" */
  a14 = a11;  /* 067b */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_str1_1 + 0x0);  /* 067d: l32r -> .rodata.esp_mesh_send.str1.1 */
  goto L_0600;  /* 0680: j */
  L_0685: a2 = (u32)&g_log_level + 0x0;  /* 0685: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0688 */
  if (a2 < 3u) goto L_06ad;  /* 068a: bltui a2, 3, 6ad <esp_mesh_send+0x5cd> */
  L_068d: a2 = LD32(a3 + 0x0);  /* 068d */
  if (a2 == 0) goto L_06ad;  /* 068f: beqz.n a2, 6ad <esp_mesh_send+0x5cd> */
  L_0691: a3 = LD32(a2 + 0x150);  /* 0691 */
  if (a3 == 0) goto L_06ad;  /* 0694: beqz.n a3, 6ad <esp_mesh_send+0x5cd> */
  L_0696: a10 = LD32(a2 + 0x158);  /* 0696 */
  /* 0699: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 069c */
  a10 = 3;  /* 069e */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 06a0: -> "mesh" */
  a14 = a11;  /* 06a3 */
  a15 = LD32(a1 + 0x10);  /* 06a5 */
  a12 = (u32)(RODATA__rodata_esp_mesh_send_str1_1 + 0x0);  /* 06a7: l32r -> .rodata.esp_mesh_send.str1.1 */
  /* 06aa: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_06ad: a6 = LD32(a1 + 0x10);  /* 06ad */
  goto L_06b5;  /* 06af: j */
  a6 = 0x0000400bu;  /* 06b2: l32r = 16395 */
  L_06b5: a2 = a6;  /* 06b5 */
  return a2;  /* 06b7: retw.n */
}


/* esp_mesh_send_mgmt @ mesh.o 0000007c size 614B bind GLOBAL
 * Calls: memcmp, mesh_parse_option, esp_mesh_create_context, mesh_send_process_flag, mesh_send_process_topo, memcpy, mesh_add_option, esp_mesh_forward_packet, esp_mesh_free_context | indirect[3]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x110] | Data refs: g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .data.MESH_BCAST_ADDR, .bss.MESH_ZERO_ADDR, g_is_wifi_connected, g_mesh_topology, .rodata.__func__$9, g_mesh_is_root, g_mesh_self_sta_addr
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=9, refs=20); reloc-direct=9, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_send_mgmt(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a7, a8, a9;
  float F9;
  /* 007c: entry a1, 80 (frame 80 bytes) */
  a7 = a2;  /* 007f */
  a2 = (u32)&g_is_mesh_started + 0x0;  /* 0081: l32r -> global */
  a5 = (a5 >> 8) & 0x1;  /* 0084: extui width 1 */
  a2 = LD8U(a2 + 0x0);  /* 0087 */
  ST32(a1 + 0x18, a6);  /* 008a */
  ST32(a1 + 0x14, a5);  /* 008c */
  if (a2 != 0) goto L_00c9;  /* 008e: bnez.n a2, c9 <esp_mesh_send_mgmt+0x4d> */
  L_0090: a2 = (u32)&g_log_level + 0x0;  /* 0090: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0093 */
  a2 = 0x00004004u;  /* 0095: l32r = 16388 */
  if (a3 >= 3u) goto L_009e;  /* 0098: bgeui a3, 3, 9e <esp_mesh_send_mgmt+0x22> */
  L_009b: goto L_02e0;  /* 009b: j */
  L_009e: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 009e: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a1 */
  if (a3 == 0) goto L_02e0;  /* 00a3: beqz a3, 2e0 <esp_mesh_send_mgmt+0x264> */
  L_00a6: a4 = LD32(a3 + 0x150);  /* 00a6 */
  if (a4 == 0) goto L_02e0;  /* 00a9: beqz a4, 2e0 <esp_mesh_send_mgmt+0x264> */
  L_00ac: a10 = LD32(a3 + 0x158);  /* 00ac */
  __asm__ volatile("" ::: "memory");  /* 00af: memw */
  /* 00b2: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00b5 */
  a10 = 3;  /* 00b7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b9: -> "mesh" */
  a14 = a11;  /* 00bc */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00be: -> "mesh" */
  /* 00c1: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_02e0;  /* 00c4: j */
  L_00c9: a2 = 0;  /* 00c9 */
  ST32(a1 + 0x0, a2);  /* 00cb */
  if (a4 != a2) goto L_00d9;  /* 00cd: bne a4, a2, d9 <esp_mesh_send_mgmt+0x5d> */
  L_00d0: a2 = 0x00004008u;  /* 00d0: l32r = 16392 */
  __asm__ volatile("" ::: "memory");  /* 00d3: memw */
  goto L_02e0;  /* 00d6: j */
  L_00d9: a2 = LD8U(a4 + 0x0);  /* 00d9 */
  if (a2 < 7u) goto L_00e5;  /* 00dc: bltui a2, 7, e5 <esp_mesh_send_mgmt+0x69> */
  L_00df: a2 = 0x00004011u;  /* 00df: l32r = 16401 */
  goto L_02e0;  /* 00e2: j */
  L_00e5: a5 = a2 + (-3);  /* 00e5 */
  a5 = (a5 >> 8) & 0x1;  /* 00e8: extui width 1 */
  if (a5 >= 2u) goto L_00f9;  /* 00eb: bgeui a5, 2, f9 <esp_mesh_send_mgmt+0x7d> */
  L_00ee: if (a7 != 0) goto L_00d0;  /* 00ee: bnez a7, d0 <esp_mesh_send_mgmt+0x54> */
  L_00f1: if (((a3 >> 3) & 1) != 0) goto L_011d;  /* 00f1: bbsi a3, 3, 11d <esp_mesh_send_mgmt+0xa1> */
  L_00f4: goto L_00d0;  /* 00f4: j */
  L_00f9: if (a2 != 2) goto L_0112;  /* 00f9: bnei a2, 2, 112 <esp_mesh_send_mgmt+0x96> */
  L_00fc: if (a7 == 0) goto L_00d0;  /* 00fc: beqz a7, d0 <esp_mesh_send_mgmt+0x54> */
  L_00ff: a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 00ff: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  a12 = 6;  /* 0102 */
  a10 = a7;  /* 0104 */
  a8 = (u32)&memcmp + 0x0;  /* 0106: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6);  /* 0109: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0114;  /* 010c: beqz.n a10, 114 <esp_mesh_send_mgmt+0x98> */
  L_010e: goto L_00d0;  /* 010e: j */
  L_0112: if (a7 == 0) goto L_011d;  /* 0112: beqz.n a7, 11d <esp_mesh_send_mgmt+0xa1> */
  L_0114: a2 = 0x00001012u;  /* 0114: l32r = 4114 */
  a14 = a3 | a2;  /* 0117 */
  goto L_0126;  /* 011a: j */
  L_011d: a2 = 0x0000101au;  /* 011d: l32r = 4122 */
  a14 = a3 | a2;  /* 0120 */
  a7 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 0123: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  L_0126: if (((a14 >> 3) & 1) == 0) goto L_0135;  /* 0126: bbci a14, 3, 135 <esp_mesh_send_mgmt+0xb9> */
  L_0129: a2 = (u32)&g_is_wifi_connected + 0x0;  /* 0129: l32r -> global */
  a3 = LD8U(a2 + 0x0);  /* 012c */
  a2 = 0x0000400bu;  /* 012f: l32r = 16395 */
  if (a3 == 0) goto L_02e0;  /* 0132: beqz a3, 2e0 <esp_mesh_send_mgmt+0x264> */
  L_0135: a12 = a1;  /* 0135 */
  a11 = 1;  /* 0137 */
  a10 = a4;  /* 0139 */
  ST32(a1 + 0x1c, a14);  /* 013b */
  __asm__ volatile("" ::: "memory");  /* 013d: memw */
  a8 = (u32)&mesh_parse_option;  /* 0140: l32r -> func addr */
  a2 = mesh_parse_option(a2, a3, a4, a5, a6);  /* 0143: callx a8 via reloc-expand */
  ST32(a1 + 0x10, a10);  /* 0146 */
  if (a10 != 0) goto L_00df;  /* 0148: bnez a10, df <esp_mesh_send_mgmt+0x63> */
  L_014b: a8 = LD32(a1 + 0x0);  /* 014b */
  if (a8 == 0) goto L_00d0;  /* 014d: beqz a8, d0 <esp_mesh_send_mgmt+0x54> */
  L_0150: a5 = 28;  /* 0150 */
  a13 = a10;  /* 0152 */
  a2 = (u32)&g_mesh_topology + 0x0;  /* 0154: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0157 */
  a2 = 33;  /* 0159 */
  if (a3 == 0) a2 = a5;  /* 015b */
  a2 = a8 + a2;  /* 015e */
  a5 = (a2 >> 2) & 0x1;  /* 0160: extui width 1 */
  a3 = 1;  /* 0163 */
  a2 = a2 >> 2;  /* 0165 */
  if (a5 != 0) a13 = a3;  /* 0168 */
  a13 = a13 + a2;  /* 016b */
  a13 = a13 << 2;  /* 016d */
  a2 = 0x3fc;  /* 0170 */
  if ((i32)a2 >= (i32)a13) goto L_0179;  /* 0173: bge a2, a13, 179 <esp_mesh_send_mgmt+0xfd> */
  L_0176: goto L_00d0;  /* 0176: j */
  L_0179: a11 = (u32)(RODATA__rodata___func___9 + 0x0);  /* 0179: l32r -> .rodata.__func__$9 */
  a10 = a13 + (14);  /* 017c */
  a12 = 0x339;  /* 017e */
  ST32(a1 + 0x20, a8);  /* 0181 */
  ST32(a1 + 0x24, a13);  /* 0183 */
  __asm__ volatile("" ::: "memory");  /* 0185: memw */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 0188: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6);  /* 018b: callx a8 via reloc-expand */
  a5 = a10;  /* 018e */
  a2 = 0x00004007u;  /* 0190: l32r = 16391 */
  a8 = LD32(a1 + 0x20);  /* 0193 */
  a13 = LD32(a1 + 0x24);  /* 0195 */
  a14 = LD32(a1 + 0x1c);  /* 0197 */
  if (a10 == 0) goto L_02e0;  /* 0199: beqz a10, 2e0 <esp_mesh_send_mgmt+0x264> */
  L_019c: a11 = -16;  /* 019c */
  a12 = -9;  /* 019e */
  a6 = LD32(a10 + 0x0);  /* 01a0 */
  a2 = a6 + (14);  /* 01a2 */
  a10 = LD8U(a6 + 0xe);  /* 01a4 */
  a10 = a10 & a11;  /* 01a7 */
  a10 = a10 | a3;  /* 01aa */
  ST8(a6 + 0xe, a10);  /* 01ad */
  __asm__ volatile("" ::: "memory");  /* 01b0: memw */
  a10 = LD32(a5 + 0x28);  /* 01b3 */
  a10 = a10 | a3;  /* 01b5 */
  a11 = (u32)&g_mesh_is_root + 0x0;  /* 01b8: l32r -> global */
  ST32(a5 + 0x28, a10);  /* 01bb */
  a10 = a10 & a12;  /* 01bd */
  __asm__ volatile("" ::: "memory");  /* 01c0: memw */
  a11 = LD8U(a11 + 0x0);  /* 01c3 */
  a11 = a11 & a3;  /* 01c6 */
  a11 = a11 << 3;  /* 01c9 */
  a10 = a10 | a11;  /* 01cc */
  ST32(a5 + 0x28, a10);  /* 01cf */
  a10 = 3;  /* 01d1 */
  a11 = a14;  /* 01d3 */
  ST8(a5 + 0x12, a10);  /* 01d5 */
  __asm__ volatile("" ::: "memory");  /* 01d8: memw */
  a10 = a5;  /* 01db */
  ST32(a1 + 0x20, a8);  /* 01dd */
  ST32(a1 + 0x24, a13);  /* 01df */
  __asm__ volatile("" ::: "memory");  /* 01e1: memw */
  a8 = (u32)&mesh_send_process_flag;  /* 01e4: l32r -> func addr */
  a2 = mesh_send_process_flag(a2, a3, a4, a5, a6);  /* 01e7: callx a8 via reloc-expand */
  a10 = 33;  /* 01ea */
  a9 = (u32)&g_mesh_topology + 0x0;  /* 01ec: l32r -> global */
  a11 = LD32(a9 + 0x0);  /* 01ef */
  a9 = 28;  /* 01f1 */
  if (a11 == 0) a10 = a9;  /* 01f3 */
  a8 = LD32(a1 + 0x20);  /* 01f6 */
  a8 = a8 + a10;  /* 01f8 */
  a10 = (a8 >> 2) & 0x1;  /* 01fa: extui width 1 */
  a8 = a8 >> 2;  /* 01fd */
  a9 = LD32(a1 + 0x10);  /* 0200 */
  if (a10 == 0) a3 = a9;  /* 0202 */
  a3 = a3 + a8;  /* 0205 */
  a10 = a2;  /* 0208: mov */
  ST8(a6 + 0xf, a3);  /* 020b */
  __asm__ volatile("" ::: "memory");  /* 020e: memw */
  a13 = LD32(a1 + 0x24);  /* 0211 */
  a3 = (a13 >> 16) & 0x1;  /* 0214: extui width 1 */
  ST16(a6 + 0x10, a3);  /* 0217 */
  __asm__ volatile("" ::: "memory");  /* 021a: memw */
  __asm__ volatile("" ::: "memory");  /* 021d: memw */
  a8 = (u32)&mesh_send_process_topo;  /* 0220: l32r -> func addr */
  a2 = mesh_send_process_topo(a2, a3, a4, a5, a6);  /* 0223: callx a8 via reloc-expand */
  a12 = 6;  /* 0226 */
  a11 = a7;  /* 0228: mov */
  a10 = a6 + (22);  /* 022b */
  a8 = (u32)&memcpy + 0x0;  /* 022e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 0231: callx a8 (libc, via reloc-expand) */
  a9 = LD8U(a4 + 0x0);  /* 0234 */
  a8 = 2;  /* 0237 */
  if (a9 != 4) goto L_0245;  /* 0239: bnei a9, 4, 245 <esp_mesh_send_mgmt+0x1c9> */
  L_023c: a9 = LD32(a1 + 0x14);  /* 023c */
  a8 = (i32)(a9 << (32 - 7)) >> (32 - 7);  /* 023e: sext */
  ST32(a2 + 0x14, a8);  /* 0241 */
  a8 = LD32(a1 + 0x10);  /* 0243 */
  L_0245: a9 = a6 + (18);  /* 0245 */
  a8 = a8 << 14;  /* 0248 */
  a12 = 6;  /* 024b */
  a3 = a3 + (14);  /* 024d */
  a7 = LD32(a9 + 0x0);  /* 024f */
  a10 = 0xffff3fffu;  /* 0251: l32r = -49153 */
  a7 = a7 & a10;  /* 0254 */
  a7 = a7 | a8;  /* 0257 */
  a10 = a6 + (28);  /* 025a */
  ST32(a9 + 0x0, a7);  /* 025d */
  a7 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 025f: l32r -> global */
  a11 = a7;  /* 0262 */
  __asm__ volatile("" ::: "memory");  /* 0264: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0267: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 026a: callx a8 (libc, via reloc-expand) */
  a12 = 28;  /* 026d */
  a6 = (u32)&g_mesh_topology + 0x0;  /* 026f: l32r -> global */
  a11 = 1;  /* 0272 */
  a10 = a4;  /* 0274 */
  a4 = 0xfffffe7f;  /* 0276 */
  a8 = LD32(a6 + 0x0);  /* 0279 */
  a6 = 33;  /* 027b */
  if (a8 != 0) a12 = a6;  /* 027e */
  a12 = a2 + a12;  /* 0281 */
  a8 = (u32)&mesh_add_option;  /* 0283: l32r -> func addr */
  a2 = mesh_add_option(a2, a3, a4, a5, a6);  /* 0286: callx a8 via reloc-expand */
  a12 = 6;  /* 0289 */
  ST16(a5 + 0x4, a3);  /* 028c */
  __asm__ volatile("" ::: "memory");  /* 028f: memw */
  a11 = a7;  /* 0292: mov */
  a10 = a5 + (12);  /* 0295 */
  __asm__ volatile("" ::: "memory");  /* 0298: memw */
  a8 = (u32)&memcpy + 0x0;  /* 029b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 029e: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 02a1: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 02a4 */
  a10 = LD32(a2 + 0x110);  /* 02a6 */
  /* 02a9: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x18);  /* 02ac */
  a3 = (a9 >> 2) & 0x1;  /* 02ae: extui width 1 */
  a3 = a3 << 7;  /* 02b1 */
  a2 = LD32(a5 + 0x28);  /* 02b4 */
  a2 = a2 & a4;  /* 02b6 */
  a2 = a2 | a3;  /* 02b9 */
  ST32(a5 + 0x18, a10);  /* 02bc */
  a10 = a5;  /* 02be */
  ST32(a5 + 0x28, a2);  /* 02c0 */
  ST32(a5 + 0x1c, a11);  /* 02c2 */
  __asm__ volatile("" ::: "memory");  /* 02c5: memw */
  a8 = (u32)&esp_mesh_forward_packet + 0x0;  /* 02c8: l32r -> global */
  a2 = esp_mesh_forward_packet(a2, a3, a4, a5, a6);  /* 02cb: callx a8 via reloc-expand */
  a2 = a10;  /* 02ce */
  if (a10 == 0) goto L_02e0;  /* 02d0: beqz.n a10, 2e0 <esp_mesh_send_mgmt+0x264> */
  L_02d2: a12 = 0x373;  /* 02d2 */
  a11 = (u32)(RODATA__rodata___func___9 + 0x0);  /* 02d5: l32r -> .rodata.__func__$9 */
  a10 = a5;  /* 02d8 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 02da: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6);  /* 02dd: callx a8 via reloc-expand */
  L_02e0: return a2;  /* 02e0: retw.n */
}


/* esp_mesh_send_sem_signal @ mesh.o 00000008 size 23B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x40] | Data refs: .bss.mesh_xmit_sem, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_send_sem_signal(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&LOCAL__bss_mesh_xmit_sem + 0x0;  /* 000b: l32r -> .bss.mesh_xmit_sem (same-object static) */
  a10 = LD32(a8 + 0x0);  /* 000e */
  if (a10 == 0) goto L_001d;  /* 0010: beqz.n a10, 1d <esp_mesh_send_sem_signal+0x15> */
  L_0012: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0012: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0015 */
  a8 = LD32(a8 + 0x40);  /* 0017 */
  /* 001a: INDIRECT callx a8 <- mem[a8+0x40]; result unknown */ a2 = 0;
  L_001d: return a2;  /* 001d: retw.n */
}


/* esp_mesh_send_sem_wait @ mesh.o 00000008 size 24B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x3c] | Data refs: .bss.mesh_xmit_sem, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_send_sem_wait(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&LOCAL__bss_mesh_xmit_sem + 0x0;  /* 000b: l32r -> .bss.mesh_xmit_sem (same-object static) */
  a10 = LD32(a8 + 0x0);  /* 000e */
  if (a10 == 0) goto L_001e;  /* 0010: beqz.n a10, 1e <esp_mesh_send_sem_wait+0x16> */
  L_0012: a11 = -1;  /* 0012 */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0014: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0017 */
  a8 = LD32(a8 + 0x3c);  /* 0019 */
  /* 001b: INDIRECT callx a8 <- mem[a8+0x3c]; result unknown */ a2 = 0;
  L_001e: return a2;  /* 001e: retw.n */
}


/* esp_mesh_send_stop_vote @ mesh.o 00000008 size 24B bind GLOBAL
 * Calls: mesh_send_stop_vote | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_send_stop_vote(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a10 = 0;  /* 000b */
  a8 = (u32)&mesh_send_stop_vote;  /* 000e: l32r -> func addr */
  a2 = mesh_send_stop_vote(a2, a3, a4, a5, a6, a7);  /* 0011: callx a8 via reloc-expand */
  a10 = 1;  /* 0014 */
  a8 = (u32)&mesh_send_stop_vote;  /* 0016: l32r -> func addr */
  a2 = mesh_send_stop_vote(a2, a3, a4, a5, a6, a7);  /* 0019: callx a8 via reloc-expand */
  a2 = 0;  /* 001c */
  return a2;  /* 001e: retw.n */
}


/* esp_mesh_set_announce_interval @ mesh.o 0000000c size 37B bind GLOBAL
 * Calls: none | Data refs: g_mesh_ann_interval
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_announce_interval(u32 a2, u32 a3) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a8 = 0x1f3;  /* 000f */
  if ((i32)a8 >= (i32)a2) goto L_002c;  /* 0012: bge a8, a2, 2c <esp_mesh_set_announce_interval+0x20> */
  L_0015: a8 = 0x00000bb7u;  /* 0015: l32r = 2999 */
  if ((i32)a8 >= (i32)a3) goto L_002c;  /* 0018: bge a8, a3, 2c <esp_mesh_set_announce_interval+0x20> */
  L_001b: a8 = (u32)&g_mesh_ann_interval + 0x0;  /* 001b: l32r -> global */
  ST32(a8 + 0x0, a2);  /* 001e */
  a2 = 0;  /* 0020 */
  ST32(a8 + 0x4, a3);  /* 0022 */
  __asm__ volatile("" ::: "memory");  /* 0024: memw */
  goto L_002f;  /* 0027: j */
  L_002c: a2 = 0x00004008u;  /* 002c: l32r = 16392 */
  L_002f: return a2;  /* 002f: retw.n */
}


/* esp_mesh_set_ap_authmode @ mesh.o 00000008 size 40B bind GLOBAL
 * Calls: none | Data refs: g_mesh_ext_cfg
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_ap_authmode(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a9 = 17;  /* 000b */
  a8 = 0x00004008u;  /* 000d: l32r = 16392 */
  if (a9 < a2) goto L_0029;  /* 0010: bltu a9, a2, 29 <esp_mesh_set_ap_authmode+0x21> */
  L_0013: a10 = 1;  /* 0013 */
  a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0015: l32r -> global */
  a9 = LD8U(a8 + 0xcc);  /* 0018 */
  a9 = a9 | a10;  /* 001b */
  ST8(a8 + 0xcc, a9);  /* 001e */
  __asm__ volatile("" ::: "memory");  /* 0021: memw */
  ST32(a8 + 0xc8, a2);  /* 0024 */
  a8 = 0;  /* 0027 */
  L_0029: a2 = a8;  /* 0029 */
  __asm__ volatile("" ::: "memory");  /* 002b: memw */
  return a2;  /* 002e: retw.n */
}


/* esp_mesh_set_ap_connections @ mesh.o 00000018 size 95B bind GLOBAL
 * Calls: none | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_mesh_ext_cfg, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_set_ap_connections.str1.1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=5); reloc-direct=0, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_set_ap_connections(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  if ((i32)a2 < 1) goto L_002c;  /* 001b: blti a2, 1, 2c <esp_mesh_set_ap_connections+0x14> */
  L_001e: a9 = (u32)&g_mesh_ext_cfg + 0x0;  /* 001e: l32r -> global */
  a10 = 10;  /* 0021 */
  a8 = LD8U(a9 + 0xbc);  /* 0023 */
  a10 = a10 - a8;  /* 0026: sub */
  if ((i32)a10 >= (i32)a2) goto L_005f;  /* 0029: bge a10, a2, 5f <esp_mesh_set_ap_connections+0x47> */
  L_002c: a3 = (u32)&g_log_level + 0x0;  /* 002c: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 002f */
  a3 = 0x00004008u;  /* 0031: l32r = 16392 */
  if (a4 < 3u) goto L_0070;  /* 0034: bltui a4, 3, 70 <esp_mesh_set_ap_connections+0x58> */
  L_0037: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0037: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 003a */
  if (a8 == 0) goto L_0070;  /* 003c: beqz.n a8, 70 <esp_mesh_set_ap_connections+0x58> */
  L_003e: a4 = LD32(a8 + 0x150);  /* 003e */
  if (a4 == 0) goto L_0070;  /* 0041: beqz.n a4, 70 <esp_mesh_set_ap_connections+0x58> */
  L_0043: a10 = LD32(a8 + 0x158);  /* 0043 */
  /* 0046: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0049 */
  a15 = a2;  /* 004b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 004d: -> "mesh" */
  a10 = 3;  /* 0050 */
  a14 = a11;  /* 0053: mov */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_ap_connections_str1_1 + 0x0);  /* 0056: l32r -> .rodata.esp_mesh_set_ap_connections.str1.1 */
  /* 0059: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0070;  /* 005c: j */
  L_005f: a2 = (a2 >> 8) & 0x1;  /* 005f: extui width 1 */
  a8 = a8 + a2;  /* 0062 */
  ST8(a9 + 0xbd, a2);  /* 0064 */
  a3 = 0;  /* 0067 */
  ST8(a9 + 0xb4, a8);  /* 006a */
  __asm__ volatile("" ::: "memory");  /* 006d: memw */
  L_0070: a2 = a3;  /* 0070 */
  __asm__ volatile("" ::: "memory");  /* 0072: memw */
  return a2;  /* 0075: retw.n */
}


/* esp_mesh_set_ap_password @ mesh.o 0000002c size 167B bind GLOBAL
 * Calls: memset, memcpy | indirect[4]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_ext_cfg, .rodata.esp_mesh_set_ap_password.str1.1
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=7); reloc-direct=2, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_set_ap_password(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 002c: entry a1, 48 (frame 48 bytes) */
  a4 = a2;  /* 002f */
  if (a2 != 0) goto L_0075;  /* 0031: bnez a2, 75 <esp_mesh_set_ap_password+0x49> */
  L_0034: a2 = (u32)&g_log_level + 0x0;  /* 0034: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0037 */
  a2 = 0x00004008u;  /* 0039: l32r = 16392 */
  if (a3 >= 3u) goto L_0042;  /* 003c: bgeui a3, 3, 42 <esp_mesh_set_ap_password+0x16> */
  L_003f: goto L_00d1;  /* 003f: j */
  L_0042: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0042: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0045 */
  if (a8 == 0) goto L_00d1;  /* 0047: beqz a8, d1 <esp_mesh_set_ap_password+0xa5> */
  L_004a: a3 = LD32(a8 + 0x150);  /* 004a */
  if (a3 == 0) goto L_00d1;  /* 004d: beqz a3, d1 <esp_mesh_set_ap_password+0xa5> */
  L_0050: a4 = 0x70b;  /* 0050 */
  a10 = LD32(a8 + 0x158);  /* 0053 */
  /* 0056: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0059 */
  a10 = 3;  /* 005b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 005d: -> "mesh" */
  a14 = a11;  /* 0060 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0062: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0065: -> "mesh" */
  ST32(a1 + 0x0, a4);  /* 0068 */
  __asm__ volatile("" ::: "memory");  /* 006a: memw */
  /* 006d: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00d1;  /* 0070: j */
  L_0075: a8 = a3 + (-1);  /* 0075 */
  a9 = 63;  /* 0077 */
  a2 = 0x00004008u;  /* 0079: l32r = 16392 */
  if (a9 < a8) goto L_00d1;  /* 007c: bltu a9, a8, d1 <esp_mesh_set_ap_password+0xa5> */
  L_007f: a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 007f: l32r -> global */
  a8 = LD32(a8 + 0xc8);  /* 0082 */
  if (a8 == 0) goto L_00a8;  /* 0085: beqz.n a8, a8 <esp_mesh_set_ap_password+0x7c> */
  L_0087: a12 = 64;  /* 0087 */
  a11 = 0;  /* 0089 */
  a8 = (u32)&g_mesh_ext_cfg + 0x74;  /* 008b: l32r -> global */
  a2 = 0;  /* 008e */
  a10 = a8;  /* 0091: mov */
  a8 = (u32)&memset + 0x0;  /* 0094: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0097: callx a8 (libc, via reloc-expand) */
  a12 = a3;  /* 009a */
  a11 = a4;  /* 009c */
  a8 = (u32)&memcpy + 0x0;  /* 009e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00a1: callx a8 (libc, via reloc-expand) */
  goto L_00d1;  /* 00a4: j */
  L_00a8: a3 = (u32)&g_log_level + 0x0;  /* 00a8: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00ab */
  if (a3 < 3u) goto L_00d1;  /* 00ad: bltui a3, 3, d1 <esp_mesh_set_ap_password+0xa5> */
  L_00b0: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b0: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00b3 */
  if (a8 == 0) goto L_00d1;  /* 00b5: beqz.n a8, d1 <esp_mesh_set_ap_password+0xa5> */
  L_00b7: a3 = LD32(a8 + 0x150);  /* 00b7 */
  if (a3 == 0) goto L_00d1;  /* 00ba: beqz.n a3, d1 <esp_mesh_set_ap_password+0xa5> */
  L_00bc: a10 = LD32(a8 + 0x158);  /* 00bc */
  /* 00bf: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00c2 */
  a10 = 3;  /* 00c4 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c6: -> "mesh" */
  a14 = a11;  /* 00c9 */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_ap_password_str1_1 + 0x0);  /* 00cb: l32r -> .rodata.esp_mesh_set_ap_password.str1.1 */
  /* 00ce: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_00d1: return a2;  /* 00d1: retw.n */
}


/* esp_mesh_set_attempts @ mesh.o 00000024 size 142B bind GLOBAL
 * Calls: none | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_cfg_attemps, g_mesh_monitor_parent_beacon_count
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=5); reloc-direct=0, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_set_attempts(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a8 = a2;  /* 0027 */
  if (a2 != 0) goto L_0068;  /* 0029: bnez.n a2, 68 <esp_mesh_set_attempts+0x44> */
  L_002b: a2 = (u32)&g_log_level + 0x0;  /* 002b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002e */
  a2 = 0x00004008u;  /* 0030: l32r = 16392 */
  if (a3 < 3u) goto L_00b0;  /* 0033: bltui a3, 3, b0 <esp_mesh_set_attempts+0x8c> */
  L_0036: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0036: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0039 */
  if (a8 == 0) goto L_00b0;  /* 003b: beqz a8, b0 <esp_mesh_set_attempts+0x8c> */
  L_003e: a3 = LD32(a8 + 0x150);  /* 003e */
  if (a3 == 0) goto L_00b0;  /* 0041: beqz a3, b0 <esp_mesh_set_attempts+0x8c> */
  L_0044: a10 = LD32(a8 + 0x158);  /* 0044 */
  /* 0047: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 004a */
  a10 = 3;  /* 004c */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 004e: -> "mesh" */
  a14 = a11;  /* 0051 */
  a8 = 0x000009bdu;  /* 0053: l32r = 2493 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0056: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0059: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 005c */
  __asm__ volatile("" ::: "memory");  /* 005e: memw */
  /* 0061: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00b0;  /* 0064: j */
  L_0068: a11 = LD32(a2 + 0x0);  /* 0068 */
  a2 = 0x00004008u;  /* 006a: l32r = 16392 */
  if ((i32)a11 < 0) goto L_00b0;  /* 006d: bltz a11, b0 <esp_mesh_set_attempts+0x8c> */
  L_0070: a10 = LD32(a8 + 0x4);  /* 0070 */
  if ((i32)a10 < 0) goto L_00b0;  /* 0072: bltz a10, b0 <esp_mesh_set_attempts+0x8c> */
  L_0075: a9 = LD32(a8 + 0x8);  /* 0075 */
  if ((i32)a9 < 0) goto L_00b0;  /* 0077: bltz a9, b0 <esp_mesh_set_attempts+0x8c> */
  L_007a: a2 = LD32(a8 + 0xc);  /* 007a */
  if ((i32)a2 < 0) goto L_00ad;  /* 007c: bltz a2, ad <esp_mesh_set_attempts+0x89> */
  L_007f: if (a11 == 0) goto L_0086;  /* 007f: beqz.n a11, 86 <esp_mesh_set_attempts+0x62> */
  L_0081: a3 = (u32)&g_mesh_cfg_attemps + 0x0;  /* 0081: l32r -> global */
  ST32(a3 + 0x0, a11);  /* 0084 */
  L_0086: if (a10 == 0) goto L_008d;  /* 0086: beqz.n a10, 8d <esp_mesh_set_attempts+0x69> */
  L_0088: a3 = (u32)&g_mesh_cfg_attemps + 0x0;  /* 0088: l32r -> global */
  ST32(a3 + 0x4, a10);  /* 008b */
  L_008d: if (a9 == 0) goto L_0094;  /* 008d: beqz.n a9, 94 <esp_mesh_set_attempts+0x70> */
  L_008f: a3 = (u32)&g_mesh_cfg_attemps + 0x0;  /* 008f: l32r -> global */
  ST32(a3 + 0x8, a9);  /* 0092 */
  L_0094: if (a2 == 0) goto L_00b0;  /* 0094: beqz.n a2, b0 <esp_mesh_set_attempts+0x8c> */
  L_0096: a3 = (u32)&g_mesh_cfg_attemps + 0x0;  /* 0096: l32r -> global */
  ST32(a3 + 0xc, a2);  /* 0099 */
  a3 = 10;  /* 009b */
  a2 = (u32)&g_mesh_monitor_parent_beacon_count + 0x0;  /* 009d: l32r -> global */
  ST32(a2 + 0x0, a3);  /* 00a0 */
  a2 = 0;  /* 00a2 */
  __asm__ volatile("" ::: "memory");  /* 00a4: memw */
  goto L_00b0;  /* 00a7: j */
  L_00ad: a2 = 0x00004008u;  /* 00ad: l32r = 16392 */
  L_00b0: return a2;  /* 00b0: retw.n */
}


/* esp_mesh_set_capacity_num @ mesh.o 00000028 size 94B bind GLOBAL
 * Calls: none | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_is_mesh_started, g_mesh_rt_capacity
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=7); reloc-direct=0, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_set_capacity_num(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8, a9;
  /* 0028: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 002b */
  a2 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 002d: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = LD8U(a2 + 0x0);  /* 0030 */
  if (a2 != 0) goto L_0064;  /* 0033: bnez.n a2, 64 <esp_mesh_set_capacity_num+0x3c> */
  L_0035: a2 = (u32)&g_log_level + 0x0;  /* 0035: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0038 */
  a2 = 0x00004002u;  /* 003a: l32r = 16386 */
  if (a3 < 3u) goto L_0081;  /* 003d: bltui a3, 3, 81 <esp_mesh_set_capacity_num+0x59> */
  L_0040: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0040: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0043 */
  if (a8 == 0) goto L_0081;  /* 0045: beqz.n a8, 81 <esp_mesh_set_capacity_num+0x59> */
  L_0047: a3 = LD32(a8 + 0x150);  /* 0047 */
  if (a3 == 0) goto L_0081;  /* 004a: beqz.n a3, 81 <esp_mesh_set_capacity_num+0x59> */
  L_004c: a10 = LD32(a8 + 0x158);  /* 004c */
  /* 004f: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0052 */
  a10 = 3;  /* 0054 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0056: -> "mesh" */
  a14 = a11;  /* 0059 */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 005b: l32r -> .rodata.esp_mesh_recv.str1.1 */
  /* 005e: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0081;  /* 0061: j */
  L_0064: a2 = (u32)&g_is_mesh_started + 0x0;  /* 0064: l32r -> global */
  a9 = LD8U(a2 + 0x0);  /* 0067 */
  a2 = 0x00004006u;  /* 006a: l32r = 16390 */
  if (a9 != 0) goto L_0081;  /* 006d: bnez.n a9, 81 <esp_mesh_set_capacity_num+0x59> */
  L_006f: a8 = a10 + (-1);  /* 006f */
  a3 = 0x3e7;  /* 0071 */
  a2 = 0x00004008u;  /* 0074: l32r = 16392 */
  if (a3 < a8) goto L_0081;  /* 0077: bltu a3, a8, 81 <esp_mesh_set_capacity_num+0x59> */
  L_007a: a2 = (u32)&g_mesh_rt_capacity + 0x0;  /* 007a: l32r -> global */
  ST32(a2 + 0x0, a10);  /* 007d */
  a2 = a9;  /* 007f */
  L_0081: __asm__ volatile("" ::: "memory");  /* 0081: memw */
  return a2;  /* 0084: retw.n */
}


/* esp_mesh_set_config @ mesh.o 000000e0 size 998B bind GLOBAL
 * Calls: esp_mesh_set_router, chm_check_channel_is_valid, esp_mesh_channel_enable_jp, esp_mesh_set_ap_connections, esp_mesh_set_non_mesh_connections, memcmp, memcpy, esp_wifi_set_mode, esp_wifi_get_mac, mesh_malloc, memset, esp_wifi_get_config, sprintf, strnlen, esp_mesh_get_beacon_interval, esp_wifi_set_config, mesh_free, mesh_encrypt_ie_plain_key, esp_wifi_set_non_mesh_connections | indirect[11]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0x158]; mem[a2+0x150] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_is_mesh_started, g_is_root_fixed, g_mesh_ext_cfg, .rodata.esp_mesh_set_config.str1.1, .bss.s_mesh_ext_crypto_config, g_mesh_self_sta_addr, g_mesh_self_map_addr +3 more
 * Fidelity: medium - 11 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=19, refs=34); reloc-direct=19, funcdb-attributed=0, unknown-indirect=11 */
u32 esp_mesh_set_config(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 00e0: entry a1, 48 (frame 48 bytes) */
  a3 = a2;  /* 00e3 */
  a2 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 00e5: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = LD8U(a2 + 0x0);  /* 00e8 */
  if (a2 != 0) goto L_0124;  /* 00eb: bnez.n a2, 124 <esp_mesh_set_config+0x44> */
  L_00ed: a2 = (u32)&g_log_level + 0x0;  /* 00ed: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00f0 */
  a2 = 0x00004002u;  /* 00f3: l32r = 16386 */
  if (a3 >= 3u) goto L_00fc;  /* 00f6: bgeui a3, 3, fc <esp_mesh_set_config+0x1c> */
  L_00f9: goto L_04c4;  /* 00f9: j */
  L_00fc: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00fc: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00ff */
  if (a3 == 0) goto L_04c4;  /* 0102: beqz a3, 4c4 <esp_mesh_set_config+0x3e4> */
  L_0105: a4 = LD32(a3 + 0x150);  /* 0105 */
  if (a4 == 0) goto L_04c4;  /* 0108: beqz a4, 4c4 <esp_mesh_set_config+0x3e4> */
  L_010b: a10 = LD32(a3 + 0x158);  /* 010b */
  /* 010e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0111 */
  a10 = 3;  /* 0113 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0115: -> "mesh" */
  a14 = a11;  /* 0118 */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 011a: l32r -> .rodata.esp_mesh_recv.str1.1 */
  /* 011d: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_04c4;  /* 0120: j */
  L_0124: a2 = (u32)&g_is_mesh_started + 0x0;  /* 0124: l32r -> global */
  a4 = LD8U(a2 + 0x0);  /* 0127 */
  a2 = 0x00004006u;  /* 012a: l32r = 16390 */
  if (a4 != 0) goto L_04c4;  /* 012d: bnez a4, 4c4 <esp_mesh_set_config+0x3e4> */
  L_0130: if (a3 != 0) goto L_0170;  /* 0130: bnez.n a3, 170 <esp_mesh_set_config+0x90> */
  L_0132: a2 = (u32)&g_log_level + 0x0;  /* 0132: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0135 */
  if (a2 >= 3u) goto L_013d;  /* 0137: bgeui a2, 3, 13d <esp_mesh_set_config+0x5d> */
  L_013a: goto L_0169;  /* 013a: j */
  L_013d: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 013d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0140 */
  if (a2 == 0) goto L_0169;  /* 0142: beqz.n a2, 169 <esp_mesh_set_config+0x89> */
  L_0144: a3 = LD32(a2 + 0x150);  /* 0144 */
  if (a3 == 0) goto L_0169;  /* 0147: beqz.n a3, 169 <esp_mesh_set_config+0x89> */
  L_0149: a10 = LD32(a2 + 0x158);  /* 0149 */
  a2 = 0x5f2;  /* 014c */
  /* 014f: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0152 */
  a10 = 3;  /* 0154 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0156: -> "mesh" */
  a14 = a11;  /* 0159 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 015b: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 015e: -> "mesh" */
  ST32(a1 + 0x0, a2);  /* 0161 */
  __asm__ volatile("" ::: "memory");  /* 0163: memw */
  /* 0166: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0169: a2 = 0x00004008u;  /* 0169: l32r = 16392 */
  goto L_04c4;  /* 016c: j */
  L_0170: a10 = a3 + (8);  /* 0170 */
  a8 = (u32)&esp_mesh_set_router;  /* 0172: l32r -> func addr */
  a2 = esp_mesh_set_router(a2, a3, a4, a5, a6, a7);  /* 0175: callx a8 via reloc-expand */
  a2 = a10;  /* 0178 */
  if (a10 == 0) goto L_0185;  /* 017a: beqz.n a10, 185 <esp_mesh_set_config+0xa5> */
  L_017c: a4 = (u32)&g_is_root_fixed + 0x0;  /* 017c: l32r -> global */
  a4 = LD8U(a4 + 0x0);  /* 017f */
  if (a4 == 0) goto L_04c4;  /* 0182: beqz a4, 4c4 <esp_mesh_set_config+0x3e4> */
  L_0185: a10 = LD8U(a3 + 0x0);  /* 0185 */
  if (a10 != 0) goto L_01ac;  /* 0188: bnez.n a10, 1ac <esp_mesh_set_config+0xcc> */
  L_018a: a5 = 9;  /* 018a */
  a2 = LD8U(a3 + 0x1);  /* 018c */
  a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 018f: l32r -> global */
  a10 = LD8U(a3 + 0xb0);  /* 0192 */
  ST8(a4 + 0x5, a2);  /* 0195 */
  __asm__ volatile("" ::: "memory");  /* 0198: memw */
  a2 = a10 + (-1);  /* 019b */
  a2 = (a2 >> 8) & 0x1;  /* 019d: extui width 1 */
  if (a5 < a2) goto L_01a6;  /* 01a0: bltu a5, a2, 1a6 <esp_mesh_set_config+0xc6> */
  L_01a3: goto L_0233;  /* 01a3: j */
  L_01a6: __asm__ volatile("" ::: "memory");  /* 01a6: memw */
  goto L_01fd;  /* 01a9: j */
  L_01ac: a8 = (u32)&chm_check_channel_is_valid + 0x0;  /* 01ac: l32r -> global */
  a2 = chm_check_channel_is_valid(a2, a3, a4, a5, a6, a7);  /* 01af: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01e8;  /* 01b2: bnez.n a10, 1e8 <esp_mesh_set_config+0x108> */
  L_01b4: a2 = (u32)&g_log_level + 0x0;  /* 01b4: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01b7 */
  if (a2 < 3u) goto L_0169;  /* 01ba: bltui a2, 3, 169 <esp_mesh_set_config+0x89> */
  L_01bd: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01bd: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01c0 */
  if (a2 == 0) goto L_0169;  /* 01c3: beqz a2, 169 <esp_mesh_set_config+0x89> */
  L_01c6: a4 = LD32(a2 + 0x150);  /* 01c6 */
  if (a4 == 0) goto L_0169;  /* 01c9: beqz a4, 169 <esp_mesh_set_config+0x89> */
  L_01cc: a10 = LD32(a2 + 0x158);  /* 01cc */
  /* 01cf: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01d2 */
  a10 = 3;  /* 01d4 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 01d6: -> "mesh" */
  a14 = a11;  /* 01d9 */
  a15 = LD8U(a3 + 0x0);  /* 01db */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_config_str1_1 + 0x0);  /* 01de: l32r -> .rodata.esp_mesh_set_config.str1.1 */
  /* 01e1: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0169;  /* 01e4: j */
  L_01e8: a4 = LD8U(a3 + 0x0);  /* 01e8 */
  a2 = 14;  /* 01eb */
  if (a4 != a2) goto L_018a;  /* 01ed: bne a4, a2, 18a <esp_mesh_set_config+0xaa> */
  L_01f0: a8 = (u32)&esp_mesh_channel_enable_jp + 0x0;  /* 01f0: l32r -> global */
  a2 = esp_mesh_channel_enable_jp(a2, a3, a4, a5, a6, a7);  /* 01f3: callx a8 via reloc-expand */
  if (a10 == 0) goto L_018a;  /* 01f6: beqz a10, 18a <esp_mesh_set_config+0xaa> */
  L_01f9: goto L_0169;  /* 01f9: j */
  L_01fd: a2 = (u32)&g_log_level + 0x0;  /* 01fd: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0200 */
  if (a2 >= 3u) goto L_0208;  /* 0202: bgeui a2, 3, 208 <esp_mesh_set_config+0x128> */
  L_0205: goto L_0169;  /* 0205: j */
  L_0208: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0208: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 020b */
  if (a2 == 0) goto L_0169;  /* 020d: beqz a2, 169 <esp_mesh_set_config+0x89> */
  L_0210: a4 = LD32(a2 + 0x150);  /* 0210 */
  if (a4 == 0) goto L_0169;  /* 0213: beqz a4, 169 <esp_mesh_set_config+0x89> */
  L_0216: a10 = LD32(a2 + 0x158);  /* 0216 */
  /* 0219: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a15 = 10;  /* 021c */
  a13 = a10;  /* 021e */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0220: -> "mesh" */
  a14 = a11;  /* 0223 */
  a2 = LD8U(a3 + 0xb0);  /* 0225 */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_config_str1_1 + 0x0);  /* 0228: l32r -> .rodata.esp_mesh_set_config.str1.1 */
  ST32(a1 + 0x0, a2);  /* 022b */
  __asm__ volatile("" ::: "memory");  /* 022d: memw */
  goto L_0269;  /* 0230: j */
  L_0233: a2 = LD8U(a3 + 0xb1);  /* 0233 */
  if (a5 >= a2) goto L_0275;  /* 0236: bgeu a5, a2, 275 <esp_mesh_set_config+0x195> */
  L_0239: a2 = (u32)&g_log_level + 0x0;  /* 0239: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 023c */
  if (a2 >= 3u) goto L_0244;  /* 023e: bgeui a2, 3, 244 <esp_mesh_set_config+0x164> */
  L_0241: goto L_0169;  /* 0241: j */
  L_0244: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0244: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0247 */
  if (a2 == 0) goto L_0169;  /* 0249: beqz a2, 169 <esp_mesh_set_config+0x89> */
  L_024c: a4 = LD32(a2 + 0x150);  /* 024c */
  if (a4 == 0) goto L_0169;  /* 024f: beqz a4, 169 <esp_mesh_set_config+0x89> */
  L_0252: a10 = LD32(a2 + 0x158);  /* 0252 */
  /* 0255: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a15 = 10;  /* 0258 */
  a13 = a10;  /* 025a */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 025c: -> "mesh" */
  a14 = a11;  /* 025f */
  a2 = LD8U(a3 + 0xb1);  /* 0261 */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_config_str1_1 + 0x0);  /* 0264: l32r -> .rodata.esp_mesh_set_config.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0267 */
  L_0269: a10 = 3;  /* 0269 */
  __asm__ volatile("" ::: "memory");  /* 026b: memw */
  /* 026e: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0169;  /* 0271: j */
  L_0275: a2 = a10 + a2;  /* 0275 */
  a2 = a2 + (-1);  /* 0277 */
  a2 = (a2 >> 8) & 0x1;  /* 0279: extui width 1 */
  if (a5 >= a2) goto L_02c0;  /* 027c: bgeu a5, a2, 2c0 <esp_mesh_set_config+0x1e0> */
  L_027f: a2 = (u32)&g_log_level + 0x0;  /* 027f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0282 */
  if (a2 >= 3u) goto L_028a;  /* 0284: bgeui a2, 3, 28a <esp_mesh_set_config+0x1aa> */
  L_0287: goto L_0169;  /* 0287: j */
  L_028a: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 028a: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 028d */
  if (a2 == 0) goto L_0169;  /* 028f: beqz a2, 169 <esp_mesh_set_config+0x89> */
  L_0292: a4 = LD32(a2 + 0x150);  /* 0292 */
  if (a4 == 0) goto L_0169;  /* 0295: beqz a4, 169 <esp_mesh_set_config+0x89> */
  L_0298: a10 = LD32(a2 + 0x158);  /* 0298 */
  /* 029b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 029e */
  a15 = 10;  /* 02a0 */
  a2 = LD8U(a3 + 0xb1);  /* 02a2 */
  a10 = 3;  /* 02a5 */
  ST32(a1 + 0x4, a2);  /* 02a7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 02a9: -> "mesh" */
  a14 = a11;  /* 02ac */
  a2 = LD8U(a3 + 0xb0);  /* 02ae */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_config_str1_1 + 0x0);  /* 02b1: l32r -> .rodata.esp_mesh_set_config.str1.1 */
  ST32(a1 + 0x0, a2);  /* 02b4 */
  __asm__ volatile("" ::: "memory");  /* 02b6: memw */
  /* 02b9: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0169;  /* 02bc: j */
  L_02c0: a8 = (u32)&esp_mesh_set_ap_connections;  /* 02c0: l32r -> func addr */
  a2 = esp_mesh_set_ap_connections(a2, a3, a4, a5, a6, a7);  /* 02c3: callx a8 via reloc-expand */
  a2 = a10;  /* 02c6 */
  if (a10 != 0) goto L_04c4;  /* 02c8: bnez a10, 4c4 <esp_mesh_set_config+0x3e4> */
  L_02cb: a10 = LD8U(a3 + 0xb1);  /* 02cb */
  a8 = (u32)&esp_mesh_set_non_mesh_connections;  /* 02ce: l32r -> func addr */
  a2 = esp_mesh_set_non_mesh_connections(a2, a3, a4, a5, a6, a7);  /* 02d1: callx a8 via reloc-expand */
  a2 = a10;  /* 02d4 */
  if (a10 != 0) goto L_04c4;  /* 02d6: bnez a10, 4c4 <esp_mesh_set_config+0x3e4> */
  L_02d9: a2 = (u32)&LOCAL__bss_s_mesh_ext_crypto_config + 0x0;  /* 02d9: l32r -> .bss.s_mesh_ext_crypto_config (same-object static) */
  a12 = 6;  /* 02dc */
  a5 = LD32(a3 + 0xb4);  /* 02de */
  ST32(a2 + 0x20, a5);  /* 02e1 */
  a2 = LD8U(a3 + 0x0);  /* 02e3 */
  a7 = (u32)&g_mesh_ext_cfg + 0x6;  /* 02e6: l32r -> global */
  a11 = a7;  /* 02e9 */
  ST8(a4 + 0x4, a2);  /* 02eb */
  __asm__ volatile("" ::: "memory");  /* 02ee: memw */
  a2 = a3 + (2);  /* 02f1 */
  a10 = a2;  /* 02f3 */
  __asm__ volatile("" ::: "memory");  /* 02f5: memw */
  a8 = (u32)&memcmp + 0x0;  /* 02f8: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 02fb: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_030e;  /* 02fe: beqz.n a10, 30e <esp_mesh_set_config+0x22e> */
  L_0300: a12 = 6;  /* 0300 */
  a11 = a2;  /* 0302: mov */
  a10 = a7;  /* 0305: mov */
  a8 = (u32)&memcpy + 0x0;  /* 0308: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 030b: callx a8 (libc, via reloc-expand) */
  L_030e: a10 = 3;  /* 030e */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 0310: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 0313: callx a8 via reloc-expand */
  a2 = a10;  /* 0316 */
  if (a10 != 0) goto L_04c4;  /* 0318: bnez a10, 4c4 <esp_mesh_set_config+0x3e4> */
  L_031b: a5 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 031b: l32r -> global */
  a11 = a5;  /* 031e */
  a8 = (u32)&esp_wifi_get_mac + 0x0;  /* 0320: l32r -> global */
  a2 = esp_wifi_get_mac(a2, a3, a4, a5, a6, a7);  /* 0323: callx a8 via reloc-expand */
  a10 = 1;  /* 0326 */
  a11 = (u32)&g_mesh_self_map_addr + 0x0;  /* 0328: l32r -> global */
  a8 = (u32)&esp_wifi_get_mac + 0x0;  /* 032b: l32r -> global */
  a2 = esp_wifi_get_mac(a2, a3, a4, a5, a6, a7);  /* 032e: callx a8 via reloc-expand */
  a12 = 0x636;  /* 0331 */
  a10 = 184;  /* 0334 */
  a11 = (u32)(RODATA__rodata___func___6 + 0x0);  /* 0337: -> "esp_mesh_set_config" */
  a8 = (u32)&mesh_malloc + 0x0;  /* 033a: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 033d: callx a8 via reloc-expand */
  a6 = a10;  /* 0340 */
  if (a10 == 0) goto L_04c1;  /* 0342: beqz a10, 4c1 <esp_mesh_set_config+0x3e1> */
  L_0345: a12 = 184;  /* 0345 */
  a11 = a2;  /* 0348 */
  a8 = (u32)&memset + 0x0;  /* 034a: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 034d: callx a8 (libc, via reloc-expand) */
  a11 = a6;  /* 0350 */
  a10 = 1;  /* 0352 */
  a8 = (u32)&esp_wifi_get_config + 0x0;  /* 0354: l32r -> global */
  a2 = esp_wifi_get_config(a2, a3, a4, a5, a6, a7);  /* 0357: callx a8 via reloc-expand */
  a11 = a2;  /* 035a */
  a12 = 32;  /* 035c */
  a10 = a6;  /* 035f: mov */
  a8 = (u32)&memset + 0x0;  /* 0362: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0365: callx a8 (libc, via reloc-expand) */
  a14 = LD8U(a5 + 0x5);  /* 0368 */
  a10 = a6;  /* 036b */
  a13 = LD8U(a5 + 0x4);  /* 036d */
  a12 = LD8U(a5 + 0x3);  /* 0370 */
  a11 = (u32)(RODATA__rodata_esp_mesh_set_config_str1_1 + 0x0);  /* 0373: l32r -> .rodata.esp_mesh_set_config.str1.1 */
  a8 = (u32)&sprintf + 0x0;  /* 0376: l32r -> global */
  a2 = sprintf(a2, a3, a4, a5, a6, a7);  /* 0379: callx a8 via reloc-expand */
  a11 = 32;  /* 037c */
  a10 = a6;  /* 037f: mov */
  a8 = (u32)&strnlen + 0x0;  /* 0382: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0385: callx a8 (libc, via reloc-expand) */
  a2 = LD32(a4 + 0xc8);  /* 0388 */
  ST8(a6 + 0x60, a10);  /* 038b */
  __asm__ volatile("" ::: "memory");  /* 038e: memw */
  if (a2 == 0) goto L_03b8;  /* 0391: beqz.n a2, 3b8 <esp_mesh_set_config+0x2d8> */
  L_0393: a5 = a3 + (112);  /* 0393 */
  a2 = a6 + (32);  /* 0396 */
  a12 = 64;  /* 0399 */
  a11 = a2;  /* 039b: mov */
  a10 = a5;  /* 039e: mov */
  __asm__ volatile("" ::: "memory");  /* 03a1: memw */
  a8 = (u32)&memcmp + 0x0;  /* 03a4: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 03a7: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_03b8;  /* 03aa: beqz.n a10, 3b8 <esp_mesh_set_config+0x2d8> */
  L_03ac: a12 = 64;  /* 03ac */
  a11 = a5;  /* 03ae */
  a10 = a2;  /* 03b0 */
  a8 = (u32)&memcpy + 0x0;  /* 03b2: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 03b5: callx a8 (libc, via reloc-expand) */
  L_03b8: a2 = LD8U(a3 + 0x0);  /* 03b8 */
  a11 = LD8U(a4 + 0xcc);  /* 03bb */
  a11 = (a11 >> 1) & 0x1;  /* 03be: extui width 1 */
  ST8(a6 + 0x61, a2);  /* 03c1 */
  __asm__ volatile("" ::: "memory");  /* 03c4: memw */
  if (a11 == 0) goto L_03d5;  /* 03c7: beqz.n a11, 3d5 <esp_mesh_set_config+0x2f5> */
  L_03c9: a2 = LD32(a4 + 0xc8);  /* 03c9 */
  ST32(a6 + 0x64, a2);  /* 03cc */
  __asm__ volatile("" ::: "memory");  /* 03cf: memw */
  goto L_03e6;  /* 03d2: j */
  L_03d5: ST32(a6 + 0x64, a11);  /* 03d5 */
  a12 = 64;  /* 03d8 */
  a10 = a6 + (32);  /* 03da */
  __asm__ volatile("" ::: "memory");  /* 03dd: memw */
  a8 = (u32)&memset + 0x0;  /* 03e0: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 03e3: callx a8 (libc, via reloc-expand) */
  L_03e6: a2 = 0;  /* 03e6 */
  ST32(a6 + 0x78, a2);  /* 03e8 */
  a10 = a6 + (106);  /* 03eb */
  a2 = LD8U(a4 + 0xb4);  /* 03ee */
  ST8(a6 + 0x69, a2);  /* 03f1 */
  a2 = 1;  /* 03f4 */
  ST8(a6 + 0x68, a2);  /* 03f7 */
  __asm__ volatile("" ::: "memory");  /* 03fa: memw */
  __asm__ volatile("" ::: "memory");  /* 03fd: memw */
  a8 = (u32)&esp_mesh_get_beacon_interval + 0x0;  /* 0400: l32r -> global */
  a2 = esp_mesh_get_beacon_interval(a2, a3, a4, a5, a6, a7);  /* 0403: callx a8 via reloc-expand */
  a11 = a6;  /* 0406: mov */
  a10 = 1;  /* 0409 */
  a8 = (u32)&esp_wifi_set_config + 0x0;  /* 040c: l32r -> global */
  a2 = esp_wifi_set_config(a2, a3, a4, a5, a6, a7);  /* 040f: callx a8 via reloc-expand */
  a2 = a10;  /* 0412 */
  if (a10 == 0) goto L_0429;  /* 0414: beqz.n a10, 429 <esp_mesh_set_config+0x349> */
  L_0416: a11 = (u32)(RODATA__rodata___func___6 + 0x0);  /* 0416: -> "esp_mesh_set_config" */
  a12 = 0x656;  /* 0419 */
  a10 = a6;  /* 041c */
  a8 = (u32)&mesh_free + 0x0;  /* 041e: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0421: callx a8 via reloc-expand */
  goto L_04c4;  /* 0424: j */
  L_0429: a9 = LD32(a6 + 0x64);  /* 0429 */
  if (a9 == 0) goto L_0460;  /* 042c: beqz.n a9, 460 <esp_mesh_set_config+0x380> */
  L_042e: a9 = a6 + (32);  /* 042e */
  a10 = a9;  /* 0431 */
  a11 = 64;  /* 0433 */
  a5 = a9;  /* 0435 */
  a8 = (u32)&strnlen + 0x0;  /* 0437: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 043a: callx a8 (libc, via reloc-expand) */
  a12 = a10;  /* 043d */
  a10 = (u32)&LOCAL__data_s_mesh_ie_crypto_plain_key + 0x0;  /* 043f: l32r -> .data.s_mesh_ie_crypto_plain_key (same-object static) */
  a11 = a5;  /* 0442 */
  a8 = (u32)&memcpy + 0x0;  /* 0444: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0447: callx a8 (libc, via reloc-expand) */
  a10 = a5;  /* 044a */
  a11 = 64;  /* 044c */
  a8 = (u32)&strnlen + 0x0;  /* 044f: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0452: callx a8 (libc, via reloc-expand) */
  a5 = (u32)&LOCAL__data_s_mesh_ie_crypto_plain_key + 0x0;  /* 0455: l32r -> .data.s_mesh_ie_crypto_plain_key (same-object static) */
  a10 = a5 + a10;  /* 0458 */
  ST8(a10 + 0x0, a2);  /* 045a */
  __asm__ volatile("" ::: "memory");  /* 045d: memw */
  L_0460: a11 = a7;  /* 0460 */
  a10 = (u32)&LOCAL__data_s_mesh_ie_crypto_plain_key + 0x0;  /* 0462: l32r -> .data.s_mesh_ie_crypto_plain_key (same-object static) */
  __asm__ volatile("" ::: "memory");  /* 0465: memw */
  a8 = (u32)&mesh_encrypt_ie_plain_key;  /* 0468: l32r -> func addr */
  a2 = mesh_encrypt_ie_plain_key(a2, a3, a4, a5, a6, a7);  /* 046b: callx a8 via reloc-expand */
  a12 = 0x66e;  /* 046e */
  a10 = a6;  /* 0471 */
  a11 = (u32)(RODATA__rodata___func___6 + 0x0);  /* 0473: -> "esp_mesh_set_config" */
  a8 = (u32)&mesh_free + 0x0;  /* 0476: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0479: callx a8 via reloc-expand */
  a10 = LD8U(a4 + 0xbc);  /* 047c */
  a8 = (u32)&esp_wifi_set_non_mesh_connections + 0x0;  /* 047f: l32r -> global */
  a2 = esp_wifi_set_non_mesh_connections(a2, a3, a4, a5, a6, a7);  /* 0482: callx a8 via reloc-expand */
  a5 = LD32(a4 + 0xc8);  /* 0485 */
  if (a5 == 0) goto L_0498;  /* 0488: beqz.n a5, 498 <esp_mesh_set_config+0x3b8> */
  L_048a: a12 = 64;  /* 048a */
  a11 = a3 + (112);  /* 048c */
  a10 = a4 + (116);  /* 048f */
  a8 = (u32)&memcpy + 0x0;  /* 0492: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0495: callx a8 (libc, via reloc-expand) */
  L_0498: a3 = (u32)&g_is_standalone_sta + 0x0;  /* 0498: l32r -> global */
  a3 = LD8U(a3 + 0x0);  /* 049b */
  if (a3 != 0) goto L_04ae;  /* 049e: bnez.n a3, 4ae <esp_mesh_set_config+0x3ce> */
  L_04a0: a3 = 1;  /* 04a0 */
  ST8(a4 + 0x0, a3);  /* 04a2 */
  __asm__ volatile("" ::: "memory");  /* 04a5: memw */
  __asm__ volatile("" ::: "memory");  /* 04a8: memw */
  goto L_04c4;  /* 04ab: j */
  L_04ae: a10 = 1;  /* 04ae */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 04b0: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 04b3: callx a8 via reloc-expand */
  if (a10 == 0) goto L_04a0;  /* 04b6: beqz a10, 4a0 <esp_mesh_set_config+0x3c0> */
  L_04b9: a2 = a10;  /* 04b9 */
  goto L_04c4;  /* 04bb: j */
  L_04c1: a2 = 0x00004007u;  /* 04c1: l32r = 16391 */
  L_04c4: return a2;  /* 04c4: retw.n */
}


/* esp_mesh_set_group_id @ mesh.o 00000008 size 52B bind GLOBAL
 * Calls: esp_mesh_insert_group_addr | Data refs: .bss.s_mesh_group_addr
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_group_id(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a4 = 1;  /* 000b */
  a8 = 0;  /* 000d */
  if (a2 == 0) a8 = a4;  /* 000f */
  a9 = (a8 >> 8) & 0x1;  /* 0012: extui width 1 */
  if (a8 != 0) goto L_0038;  /* 0015: bnez.n a8, 38 <esp_mesh_set_group_id+0x30> */
  L_0017: if (a3 != 0) a4 = a9;  /* 0017 */
  if (a4 != 0) goto L_0038;  /* 001a: bnez.n a4, 38 <esp_mesh_set_group_id+0x30> */
  L_001c: goto L_0030;  /* 001c: j */
  L_0021: a10 = (u32)&LOCAL__bss_s_mesh_group_addr + 0x0;  /* 0021: l32r -> .bss.s_mesh_group_addr (same-object static) */
  a11 = a2;  /* 0024 */
  a8 = (u32)&esp_mesh_insert_group_addr;  /* 0026: l32r -> func addr */
  a2 = esp_mesh_insert_group_addr(a2, a3, a4, a5, a6, a7);  /* 0029: callx a8 via reloc-expand */
  a4 = a4 + (1);  /* 002c */
  a2 = a2 + (6);  /* 002e */
  L_0030: if ((i32)a4 < (i32)a3) goto L_0021;  /* 0030: blt a4, a3, 21 <esp_mesh_set_group_id+0x19> */
  L_0033: a2 = 0;  /* 0033 */
  goto L_003a;  /* 0035: j */
  L_0038: a2 = -1;  /* 0038 */
  L_003a: return a2;  /* 003a: retw.n */
}


/* esp_mesh_set_id @ mesh.o 0000004c size 266B bind GLOBAL
 * Calls: memcmp, memcpy, memset, esp_mesh_is_nwk_inited, mesh_set_id, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[5]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0xa4] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_mesh_ext_cfg, g_is_mesh_started
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=7, refs=14); reloc-direct=7, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_set_id(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 004c: entry a1, 80 (frame 80 bytes) */
  a3 = a2;  /* 004f */
  a2 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 0051: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = LD8U(a2 + 0x0);  /* 0054 */
  if (a2 != 0) goto L_0092;  /* 0057: bnez.n a2, 92 <esp_mesh_set_id+0x46> */
  L_0059: a2 = (u32)&g_log_level + 0x0;  /* 0059: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 005c */
  a2 = 0x00004002u;  /* 005f: l32r = 16386 */
  if (a3 >= 3u) goto L_0068;  /* 0062: bgeui a3, 3, 68 <esp_mesh_set_id+0x1c> */
  L_0065: goto L_0154;  /* 0065: j */
  L_0068: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0068: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006b */
  if (a3 == 0) goto L_0154;  /* 006e: beqz a3, 154 <esp_mesh_set_id+0x108> */
  L_0071: a4 = LD32(a3 + 0x150);  /* 0071 */
  if (a4 == 0) goto L_0154;  /* 0074: beqz a4, 154 <esp_mesh_set_id+0x108> */
  L_0077: a10 = LD32(a3 + 0x158);  /* 0077 */
  /* 007a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 007d */
  a10 = 3;  /* 007f */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0081: -> "mesh" */
  a14 = a11;  /* 0084 */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 0086: l32r -> .rodata.esp_mesh_recv.str1.1 */
  /* 0089: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0154;  /* 008c: j */
  L_0092: if (a3 != 0) goto L_00d5;  /* 0092: bnez a3, d5 <esp_mesh_set_id+0x89> */
  L_0095: a2 = (u32)&g_log_level + 0x0;  /* 0095: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0098 */
  a2 = 0x00004008u;  /* 009a: l32r = 16392 */
  if (a3 >= 3u) goto L_00a3;  /* 009d: bgeui a3, 3, a3 <esp_mesh_set_id+0x57> */
  L_00a0: goto L_0154;  /* 00a0: j */
  L_00a3: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a3: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a6 */
  if (a3 == 0) goto L_0154;  /* 00a8: beqz a3, 154 <esp_mesh_set_id+0x108> */
  L_00ab: a4 = LD32(a3 + 0x150);  /* 00ab */
  if (a4 == 0) goto L_0154;  /* 00ae: beqz a4, 154 <esp_mesh_set_id+0x108> */
  L_00b1: a10 = LD32(a3 + 0x158);  /* 00b1 */
  a3 = 0x6b2;  /* 00b4 */
  /* 00b7: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ba */
  a10 = 3;  /* 00bc */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00be: -> "mesh" */
  a14 = a11;  /* 00c1 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c3: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c6: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 00c9 */
  __asm__ volatile("" ::: "memory");  /* 00cb: memw */
  /* 00ce: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0154;  /* 00d1: j */
  L_00d5: a4 = (u32)&g_mesh_ext_cfg + 0x6;  /* 00d5: l32r -> global */
  a12 = 6;  /* 00d8 */
  a11 = a3;  /* 00da */
  a10 = a4;  /* 00dc */
  a8 = (u32)&memcmp + 0x0;  /* 00de: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00e1: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 00e4 */
  if (a10 == 0) goto L_0154;  /* 00e6: beqz a10, 154 <esp_mesh_set_id+0x108> */
  L_00e9: a2 = (u32)&g_is_mesh_started + 0x0;  /* 00e9: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 00ec */
  if (a2 != 0) goto L_0100;  /* 00ef: bnez.n a2, 100 <esp_mesh_set_id+0xb4> */
  L_00f1: a12 = 6;  /* 00f1 */
  a11 = a3;  /* 00f3 */
  a10 = a4;  /* 00f5 */
  a8 = (u32)&memcpy + 0x0;  /* 00f7: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00fa: callx a8 (libc, via reloc-expand) */
  goto L_0154;  /* 00fd: j */
  L_0100: a12 = 20;  /* 0100 */
  a11 = 0;  /* 0102 */
  a10 = a1 + (16);  /* 0104 */
  a8 = (u32)&memset + 0x0;  /* 0107: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 010a: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 010d: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 0110: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0121;  /* 0113: bnez.n a10, 121 <esp_mesh_set_id+0xd5> */
  L_0115: a10 = a3;  /* 0115 */
  a8 = (u32)&mesh_set_id;  /* 0117: l32r -> func addr */
  a2 = mesh_set_id(a2, a3, a4, a5, a6, a7);  /* 011a: callx a8 via reloc-expand */
  goto L_0152;  /* 011d: j */
  L_0121: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0121: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0124 */
  a10 = LD32(a2 + 0xa4);  /* 0126 */
  /* 0129: INDIRECT callx a10 <- mem[a2+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 012c: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 012f: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0115;  /* 0132: bnez a10, 115 <esp_mesh_set_id+0xc9> */
  L_0135: a2 = 1;  /* 0135 */
  a12 = 6;  /* 0137 */
  a11 = a3;  /* 0139 */
  a10 = a1 + (20);  /* 013b */
  ST32(a1 + 0x10, a2);  /* 013e */
  __asm__ volatile("" ::: "memory");  /* 0140: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0143: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0146: callx a8 (libc, via reloc-expand) */
  a10 = a1 + (16);  /* 0149 */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 014c: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 014f: callx a8 via reloc-expand */
  L_0152: a2 = a10;  /* 0152 */
  L_0154: return a2;  /* 0154: retw.n */
}


/* esp_mesh_set_ie_crypto_funcs @ mesh.o 00000038 size 208B bind GLOBAL
 * Calls: memset, esp_mesh_is_nwk_inited, mesh_set_ie_crypto_funcs, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[5]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0xa4]; mem[a8+0x158] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_mesh_ext_cfg, .bss.s_mesh_ext_crypto_config, .rodata.esp_mesh_set_ie_crypto_funcs.str1.1
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=13); reloc-direct=5, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_set_ie_crypto_funcs(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0038: entry a1, 64 (frame 64 bytes) */
  a3 = a2;  /* 003b */
  a2 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 003d: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = LD8U(a2 + 0x0);  /* 0040 */
  if (a2 != 0) goto L_007c;  /* 0043: bnez.n a2, 7c <esp_mesh_set_ie_crypto_funcs+0x44> */
  L_0045: a2 = (u32)&g_log_level + 0x0;  /* 0045: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0048 */
  a2 = 0x00004002u;  /* 004b: l32r = 16386 */
  if (a3 >= 3u) goto L_0054;  /* 004e: bgeui a3, 3, 54 <esp_mesh_set_ie_crypto_funcs+0x1c> */
  L_0051: goto L_0106;  /* 0051: j */
  L_0054: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0054: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0057 */
  if (a3 == 0) goto L_0106;  /* 005a: beqz a3, 106 <esp_mesh_set_ie_crypto_funcs+0xce> */
  L_005d: a4 = LD32(a3 + 0x150);  /* 005d */
  if (a4 == 0) goto L_0106;  /* 0060: beqz a4, 106 <esp_mesh_set_ie_crypto_funcs+0xce> */
  L_0063: a10 = LD32(a3 + 0x158);  /* 0063 */
  /* 0066: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0069 */
  a10 = 3;  /* 006b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 006d: -> "mesh" */
  a14 = a11;  /* 0070 */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 0072: l32r -> .rodata.esp_mesh_recv.str1.1 */
  /* 0075: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0106;  /* 0078: j */
  L_007c: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 007c: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 007f */
  if (a2 != 0) goto L_0091;  /* 0082: bnez.n a2, 91 <esp_mesh_set_ie_crypto_funcs+0x59> */
  L_0084: a2 = (u32)&LOCAL__bss_s_mesh_ext_crypto_config + 0x0;  /* 0084: l32r -> .bss.s_mesh_ext_crypto_config (same-object static) */
  ST32(a2 + 0x20, a3);  /* 0087 */
  a2 = 0;  /* 0089 */
  __asm__ volatile("" ::: "memory");  /* 008b: memw */
  goto L_0106;  /* 008e: j */
  L_0091: a12 = 20;  /* 0091 */
  a11 = 0;  /* 0093 */
  a10 = a1;  /* 0095 */
  a8 = (u32)&memset + 0x0;  /* 0097: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 009a: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 009d: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 00a0: callx a8 via reloc-expand */
  if (a10 != 0) goto L_00b1;  /* 00a3: bnez.n a10, b1 <esp_mesh_set_ie_crypto_funcs+0x79> */
  L_00a5: a10 = a3;  /* 00a5 */
  a8 = (u32)&mesh_set_ie_crypto_funcs;  /* 00a7: l32r -> func addr */
  a2 = mesh_set_ie_crypto_funcs(a2, a3, a4, a5, a6, a7);  /* 00aa: callx a8 via reloc-expand */
  goto L_00d6;  /* 00ad: j */
  L_00b1: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00b1: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00b4 */
  a10 = LD32(a2 + 0xa4);  /* 00b6 */
  /* 00b9: INDIRECT callx a10 <- mem[a2+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 00bc: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 00bf: callx a8 via reloc-expand */
  if (a10 != 0) goto L_00a5;  /* 00c2: bnez a10, a5 <esp_mesh_set_ie_crypto_funcs+0x6d> */
  L_00c5: a2 = 5;  /* 00c5 */
  a10 = a1;  /* 00c7 */
  ST32(a1 + 0x0, a2);  /* 00c9 */
  ST32(a1 + 0x4, a3);  /* 00cb */
  __asm__ volatile("" ::: "memory");  /* 00cd: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 00d0: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 00d3: callx a8 via reloc-expand */
  L_00d6: a2 = a10;  /* 00d6 */
  if (a10 == 0) goto L_0084;  /* 00d8: beqz a10, 84 <esp_mesh_set_ie_crypto_funcs+0x4c> */
  L_00db: a3 = (u32)&g_log_level + 0x0;  /* 00db: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00de */
  if (a3 < 3u) goto L_0106;  /* 00e0: bltui a3, 3, 106 <esp_mesh_set_ie_crypto_funcs+0xce> */
  L_00e3: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00e3: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00e6 */
  if (a8 == 0) goto L_0106;  /* 00e8: beqz.n a8, 106 <esp_mesh_set_ie_crypto_funcs+0xce> */
  L_00ea: a3 = LD32(a8 + 0x150);  /* 00ea */
  if (a3 == 0) goto L_0106;  /* 00ed: beqz.n a3, 106 <esp_mesh_set_ie_crypto_funcs+0xce> */
  L_00ef: a10 = LD32(a8 + 0x158);  /* 00ef */
  /* 00f2: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00f5 */
  a15 = a2;  /* 00f7 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00f9: -> "mesh" */
  a10 = 3;  /* 00fc */
  a14 = a11;  /* 00fe */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_ie_crypto_funcs_str1_1 + 0x0);  /* 0100: l32r -> .rodata.esp_mesh_set_ie_crypto_funcs.str1.1 */
  /* 0103: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0106: return a2;  /* 0106: retw.n */
}


/* esp_mesh_set_ie_crypto_key @ mesh.o 00000050 size 347B bind GLOBAL
 * Calls: memcpy, memset, esp_mesh_is_nwk_inited, mesh_set_ie_crypto_key, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[7]: mem[a3+0x158]; mem[a3+0x150]; mem[a2+0xa4]; mem[a4+0x158] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_mesh_ext_cfg, .data.s_mesh_ie_crypto_plain_key, .rodata.esp_mesh_set_ie_crypto_key.str1.1
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=14); reloc-direct=6, funcdb-attributed=0, unknown-indirect=7 */
u32 esp_mesh_set_ie_crypto_key(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0050: entry a1, 80 (frame 80 bytes) */
  a4 = a2;  /* 0053 */
  a2 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 0055: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = LD8U(a2 + 0x0);  /* 0058 */
  if (a2 != 0) goto L_0093;  /* 005b: bnez.n a2, 93 <esp_mesh_set_ie_crypto_key+0x43> */
  L_005d: a2 = (u32)&g_log_level + 0x0;  /* 005d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0060 */
  a2 = 0x00004002u;  /* 0063: l32r = 16386 */
  if (a3 >= 3u) goto L_006c;  /* 0066: bgeui a3, 3, 6c <esp_mesh_set_ie_crypto_key+0x1c> */
  L_0069: goto L_01a9;  /* 0069: j */
  L_006c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 006c: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006f */
  if (a3 == 0) goto L_01a9;  /* 0072: beqz a3, 1a9 <esp_mesh_set_ie_crypto_key+0x159> */
  L_0075: a4 = LD32(a3 + 0x150);  /* 0075 */
  if (a4 == 0) goto L_01a9;  /* 0078: beqz a4, 1a9 <esp_mesh_set_ie_crypto_key+0x159> */
  L_007b: a10 = LD32(a3 + 0x158);  /* 007b */
  /* 007e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0081 */
  a10 = 3;  /* 0083 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0085: -> "mesh" */
  a14 = a11;  /* 0088 */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 008a: l32r -> .rodata.esp_mesh_recv.str1.1 */
  /* 008d: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01a9;  /* 0090: j */
  L_0093: if (a4 != 0) goto L_00d8;  /* 0093: bnez a4, d8 <esp_mesh_set_ie_crypto_key+0x88> */
  L_0096: a2 = (u32)&g_log_level + 0x0;  /* 0096: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0099 */
  a2 = 0x00004008u;  /* 009c: l32r = 16392 */
  if (a3 >= 3u) goto L_00a5;  /* 009f: bgeui a3, 3, a5 <esp_mesh_set_ie_crypto_key+0x55> */
  L_00a2: goto L_01a9;  /* 00a2: j */
  L_00a5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a5: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00a8 */
  if (a3 == 0) goto L_01a9;  /* 00ab: beqz a3, 1a9 <esp_mesh_set_ie_crypto_key+0x159> */
  L_00ae: a4 = LD32(a3 + 0x150);  /* 00ae */
  if (a4 == 0) goto L_01a9;  /* 00b1: beqz a4, 1a9 <esp_mesh_set_ie_crypto_key+0x159> */
  L_00b4: a10 = LD32(a3 + 0x158);  /* 00b4 */
  /* 00b7: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ba */
  a10 = 3;  /* 00bc */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00be: -> "mesh" */
  a14 = a11;  /* 00c1 */
  a3 = 0x00000b02u;  /* 00c3: l32r = 2818 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c6: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c9: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 00cc */
  __asm__ volatile("" ::: "memory");  /* 00ce: memw */
  /* 00d1: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01a9;  /* 00d4: j */
  L_00d8: a8 = a3 + (-8);  /* 00d8 */
  a5 = 56;  /* 00db */
  a2 = 0x00004008u;  /* 00dd: l32r = 16392 */
  if (a5 >= a8) goto L_00e6;  /* 00e0: bgeu a5, a8, e6 <esp_mesh_set_ie_crypto_key+0x96> */
  L_00e3: goto L_01a9;  /* 00e3: j */
  L_00e6: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 00e6: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 00e9 */
  if (a2 != 0) goto L_010c;  /* 00ec: bnez.n a2, 10c <esp_mesh_set_ie_crypto_key+0xbc> */
  L_00ee: a12 = a3;  /* 00ee */
  a11 = a4;  /* 00f0 */
  a8 = (u32)&LOCAL__data_s_mesh_ie_crypto_plain_key + 0x0;  /* 00f2: l32r -> .data.s_mesh_ie_crypto_plain_key (same-object static) */
  a10 = a8;  /* 00f5 */
  a8 = (u32)&memcpy + 0x0;  /* 00f7: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00fa: callx a8 (libc, via reloc-expand) */
  a8 = a10 + a3;  /* 00fd */
  ST8(a8 + 0x0, a2);  /* 00ff */
  __asm__ volatile("" ::: "memory");  /* 0102: memw */
  __asm__ volatile("" ::: "memory");  /* 0105: memw */
  goto L_01a9;  /* 0108: j */
  L_010c: a12 = 20;  /* 010c */
  a11 = 0;  /* 010e */
  a10 = a1 + (16);  /* 0110 */
  a8 = (u32)&memset + 0x0;  /* 0113: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0116: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 0119: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 011c: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0131;  /* 011f: bnez a10, 131 <esp_mesh_set_ie_crypto_key+0xe1> */
  L_0122: a11 = a3;  /* 0122 */
  a10 = a4;  /* 0124 */
  a8 = (u32)&mesh_set_ie_crypto_key;  /* 0126: l32r -> func addr */
  a2 = mesh_set_ie_crypto_key(a2, a3, a4, a5, a6, a7);  /* 0129: callx a8 via reloc-expand */
  goto L_015d;  /* 012c: j */
  L_0131: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0131: l32r -> global */
  a2 = LD32(a5 + 0x0);  /* 0134 */
  a10 = LD32(a2 + 0xa4);  /* 0137 */
  /* 013a: INDIRECT callx a10 <- mem[a2+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 013d: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 0140: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0122;  /* 0143: bnez a10, 122 <esp_mesh_set_ie_crypto_key+0xd2> */
  L_0146: a2 = 6;  /* 0146 */
  a10 = a1 + (16);  /* 0148 */
  ST32(a1 + 0x10, a2);  /* 014b */
  ST32(a1 + 0x14, a4);  /* 014d */
  __asm__ volatile("" ::: "memory");  /* 0150: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 0153: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 0156: callx a8 via reloc-expand */
  a2 = a10;  /* 0159 */
  if (a10 != 0) goto L_0181;  /* 015b: bnez.n a10, 181 <esp_mesh_set_ie_crypto_key+0x131> */
  L_015d: a12 = a3;  /* 015d */
  a2 = (u32)&LOCAL__data_s_mesh_ie_crypto_plain_key + 0x0;  /* 015f: l32r -> .data.s_mesh_ie_crypto_plain_key (same-object static) */
  a11 = a4;  /* 0162 */
  a10 = a2;  /* 0164 */
  a2 = a2 + a3;  /* 0166 */
  a3 = 0;  /* 0168 */
  a8 = (u32)&memcpy + 0x0;  /* 016a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 016d: callx a8 (libc, via reloc-expand) */
  ST8(a2 + 0x0, a3);  /* 0170 */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  a2 = 0;  /* 0176 */
  __asm__ volatile("" ::: "memory");  /* 0178: memw */
  goto L_01a9;  /* 017b: j */
  L_0181: a3 = (u32)&g_log_level + 0x0;  /* 0181: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0184 */
  if (a3 < 3u) goto L_01a9;  /* 0186: bltui a3, 3, 1a9 <esp_mesh_set_ie_crypto_key+0x159> */
  L_0189: a4 = LD32(a5 + 0x0);  /* 0189 */
  if (a4 == 0) goto L_01a9;  /* 018b: beqz.n a4, 1a9 <esp_mesh_set_ie_crypto_key+0x159> */
  L_018d: a3 = LD32(a4 + 0x150);  /* 018d */
  if (a3 == 0) goto L_01a9;  /* 0190: beqz.n a3, 1a9 <esp_mesh_set_ie_crypto_key+0x159> */
  L_0192: a10 = LD32(a4 + 0x158);  /* 0192 */
  /* 0195: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0198 */
  a15 = a2;  /* 019a */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 019c: -> "mesh" */
  a10 = 3;  /* 019f */
  a14 = a11;  /* 01a1 */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_ie_crypto_key_str1_1 + 0x0);  /* 01a3: l32r -> .rodata.esp_mesh_set_ie_crypto_key.str1.1 */
  /* 01a6: INDIRECT callx a3 <- mem[a4+0x150]; result unknown */ a2 = 0;
  L_01a9: return a2;  /* 01a9: retw.n */
}


/* esp_mesh_set_max_layer @ mesh.o 00000014 size 56B bind GLOBAL
 * Calls: none | Data refs: g_is_mesh_started, g_mesh_topology, g_mesh_max_layer
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_max_layer(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_is_mesh_started + 0x0;  /* 0017: l32r -> global */
  a9 = LD8U(a8 + 0x0);  /* 001a */
  a8 = 0x00004006u;  /* 001d: l32r = 16390 */
  if (a9 != 0) goto L_0045;  /* 0020: bnez.n a9, 45 <esp_mesh_set_max_layer+0x31> */
  L_0022: a8 = 0x00004008u;  /* 0022: l32r = 16392 */
  if ((i32)a2 < 1) goto L_0045;  /* 0025: blti a2, 1, 45 <esp_mesh_set_max_layer+0x31> */
  L_0028: a9 = 25;  /* 0028 */
  a8 = (u32)&g_mesh_topology + 0x0;  /* 002a: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 002d */
  if (a8 == 0) goto L_0034;  /* 002f: beqz.n a8, 34 <esp_mesh_set_max_layer+0x20> */
  L_0031: a9 = 0x3e8;  /* 0031 */
  L_0034: a8 = 0x00004008u;  /* 0034: l32r = 16392 */
  if ((i32)a9 < (i32)a2) goto L_0045;  /* 0037: blt a9, a2, 45 <esp_mesh_set_max_layer+0x31> */
  L_003a: a8 = (u32)&g_mesh_max_layer + 0x0;  /* 003a: l32r -> global */
  ST16(a8 + 0x0, a2);  /* 003d */
  __asm__ volatile("" ::: "memory");  /* 0040: memw */
  a8 = 0;  /* 0043 */
  L_0045: a2 = a8;  /* 0045 */
  __asm__ volatile("" ::: "memory");  /* 0047: memw */
  return a2;  /* 004a: retw.n */
}


/* esp_mesh_set_non_mesh_connections @ mesh.o 0000001c size 104B bind GLOBAL
 * Calls: esp_wifi_set_non_mesh_connections | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_mesh_ext_cfg, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_set_non_mesh_connections.str1.1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=6); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_set_non_mesh_connections(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 001c: entry a1, 32 (frame 32 bytes) */
  if ((i32)a2 < 0) goto L_0030;  /* 001f: bltz a2, 30 <esp_mesh_set_non_mesh_connections+0x14> */
  L_0022: a9 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0022: l32r -> global */
  a10 = 10;  /* 0025 */
  a8 = LD8U(a9 + 0xbd);  /* 0027 */
  a10 = a10 - a8;  /* 002a: sub */
  if ((i32)a10 >= (i32)a2) goto L_0065;  /* 002d: bge a10, a2, 65 <esp_mesh_set_non_mesh_connections+0x49> */
  L_0030: a3 = (u32)&g_log_level + 0x0;  /* 0030: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 0033 */
  a3 = 0x00004008u;  /* 0035: l32r = 16392 */
  if (a4 < 3u) goto L_0080;  /* 0038: bltui a4, 3, 80 <esp_mesh_set_non_mesh_connections+0x64> */
  L_003b: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 003b: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 003e */
  if (a8 == 0) goto L_0080;  /* 0040: beqz.n a8, 80 <esp_mesh_set_non_mesh_connections+0x64> */
  L_0042: a4 = LD32(a8 + 0x150);  /* 0042 */
  if (a4 == 0) goto L_0080;  /* 0045: beqz.n a4, 80 <esp_mesh_set_non_mesh_connections+0x64> */
  L_0047: a10 = LD32(a8 + 0x158);  /* 0047 */
  /* 004a: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 004d */
  a15 = a2;  /* 004f */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0051: -> "mesh" */
  a10 = 3;  /* 0054 */
  a14 = a11;  /* 0057: mov */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_non_mesh_connections_str1_1 + 0x0);  /* 005a: l32r -> .rodata.esp_mesh_set_non_mesh_connections.str1.1 */
  /* 005d: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0080;  /* 0060: j */
  L_0065: a3 = (a2 >> 8) & 0x1;  /* 0065: extui width 1 */
  a8 = a8 + a3;  /* 0068 */
  a10 = a2;  /* 006a */
  ST8(a9 + 0xbc, a3);  /* 006c */
  a3 = 0;  /* 006f */
  ST8(a9 + 0xb4, a8);  /* 0071 */
  __asm__ volatile("" ::: "memory");  /* 0074: memw */
  __asm__ volatile("" ::: "memory");  /* 0077: memw */
  a8 = (u32)&esp_wifi_set_non_mesh_connections + 0x0;  /* 007a: l32r -> global */
  a2 = esp_wifi_set_non_mesh_connections(a2, a3, a4, a5, a6, a7);  /* 007d: callx a8 via reloc-expand */
  L_0080: a2 = a3;  /* 0080 */
  return a2;  /* 0082: retw.n */
}


/* esp_mesh_set_parent @ mesh.o 00000048 size 278B bind GLOBAL
 * Calls: memset, esp_mesh_is_nwk_inited, mesh_set_parent, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[6]: mem[a8+0x158]; mem[a8+0x150]; mem[a8+0xa4] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_mesh_ext_cfg, .rodata.esp_mesh_set_parent.str1.1
 * Fidelity: medium - 6 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=12); reloc-direct=5, funcdb-attributed=0, unknown-indirect=6 */
u32 esp_mesh_set_parent(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0048: entry a1, 80 (frame 80 bytes) */
  a8 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 004b: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a8 = LD8U(a8 + 0x0);  /* 004e */
  if (a8 != 0) goto L_0084;  /* 0051: bnez.n a8, 84 <esp_mesh_set_parent+0x3c> */
  L_0053: a2 = (u32)&g_log_level + 0x0;  /* 0053: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0056 */
  a2 = 0x00004002u;  /* 0058: l32r = 16386 */
  if (a3 >= 3u) goto L_0061;  /* 005b: bgeui a3, 3, 61 <esp_mesh_set_parent+0x19> */
  L_005e: goto L_015c;  /* 005e: j */
  L_0061: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0061: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0064 */
  if (a8 == 0) goto L_015c;  /* 0066: beqz a8, 15c <esp_mesh_set_parent+0x114> */
  L_0069: a3 = LD32(a8 + 0x150);  /* 0069 */
  if (a3 == 0) goto L_015c;  /* 006c: beqz a3, 15c <esp_mesh_set_parent+0x114> */
  L_006f: a10 = LD32(a8 + 0x158);  /* 006f */
  /* 0072: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0075 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0077: -> "mesh" */
  a14 = a11;  /* 007a */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 007c: l32r -> .rodata.esp_mesh_recv.str1.1 */
  goto L_00b8;  /* 007f: j */
  L_0084: a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0084: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 0087 */
  if (a8 != 0) goto L_00c2;  /* 008a: bnez.n a8, c2 <esp_mesh_set_parent+0x7a> */
  L_008c: a2 = (u32)&g_log_level + 0x0;  /* 008c: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 008f */
  a2 = 0x00004003u;  /* 0091: l32r = 16387 */
  if (a3 >= 3u) goto L_009a;  /* 0094: bgeui a3, 3, 9a <esp_mesh_set_parent+0x52> */
  L_0097: goto L_015c;  /* 0097: j */
  L_009a: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 009a: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 009d */
  if (a8 == 0) goto L_015c;  /* 009f: beqz a8, 15c <esp_mesh_set_parent+0x114> */
  L_00a2: a3 = LD32(a8 + 0x150);  /* 00a2 */
  if (a3 == 0) goto L_015c;  /* 00a5: beqz a3, 15c <esp_mesh_set_parent+0x114> */
  L_00a8: a10 = LD32(a8 + 0x158);  /* 00a8 */
  /* 00ab: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00ae */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b0: -> "mesh" */
  a14 = a11;  /* 00b3 */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_parent_str1_1 + 0x0);  /* 00b5: l32r -> .rodata.esp_mesh_set_parent.str1.1 */
  L_00b8: a10 = 3;  /* 00b8 */
  /* 00ba: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_015c;  /* 00bd: j */
  L_00c2: if (a2 != 0) goto L_0103;  /* 00c2: bnez.n a2, 103 <esp_mesh_set_parent+0xbb> */
  L_00c4: a2 = (u32)&g_log_level + 0x0;  /* 00c4: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00c7 */
  a2 = 0x00004008u;  /* 00c9: l32r = 16392 */
  if (a3 >= 3u) goto L_00d2;  /* 00cc: bgeui a3, 3, d2 <esp_mesh_set_parent+0x8a> */
  L_00cf: goto L_015c;  /* 00cf: j */
  L_00d2: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00d2: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00d5 */
  if (a8 == 0) goto L_015c;  /* 00d7: beqz a8, 15c <esp_mesh_set_parent+0x114> */
  L_00da: a3 = LD32(a8 + 0x150);  /* 00da */
  if (a3 == 0) goto L_015c;  /* 00dd: beqz a3, 15c <esp_mesh_set_parent+0x114> */
  L_00e0: a10 = LD32(a8 + 0x158);  /* 00e0 */
  /* 00e3: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00e6 */
  a10 = 3;  /* 00e8 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00ea: -> "mesh" */
  a14 = a11;  /* 00ed */
  a4 = 0x00000920u;  /* 00ef: l32r = 2336 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00f2: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00f5: -> "mesh" */
  ST32(a1 + 0x0, a4);  /* 00f8 */
  __asm__ volatile("" ::: "memory");  /* 00fa: memw */
  /* 00fd: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_015c;  /* 0100: j */
  L_0103: a12 = 20;  /* 0103 */
  a11 = 0;  /* 0105 */
  a10 = a1 + (16);  /* 0107 */
  a8 = (u32)&memset + 0x0;  /* 010a: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 010d: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 0110: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 0113: callx a8 via reloc-expand */
  if (a10 != 0) goto L_012d;  /* 0116: bnez.n a10, 12d <esp_mesh_set_parent+0xe5> */
  L_0118: a13 = a5;  /* 0118 */
  a12 = a4;  /* 011a */
  a11 = a3;  /* 011c: mov */
  a10 = a2;  /* 011f: mov */
  a8 = (u32)&mesh_set_parent;  /* 0122: l32r -> func addr */
  a2 = mesh_set_parent(a2, a3, a4, a5, a6, a7);  /* 0125: callx a8 via reloc-expand */
  goto L_015a;  /* 0128: j */
  L_012d: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 012d: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0130 */
  a10 = LD32(a8 + 0xa4);  /* 0132 */
  /* 0135: INDIRECT callx a10 <- mem[a8+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 0138: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 013b: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0118;  /* 013e: bnez a10, 118 <esp_mesh_set_parent+0xd0> */
  L_0141: a8 = 4;  /* 0141 */
  a10 = a1 + (16);  /* 0143 */
  ST32(a1 + 0x10, a8);  /* 0146 */
  ST32(a1 + 0x14, a2);  /* 0148 */
  ST32(a1 + 0x18, a3);  /* 014a */
  ST32(a1 + 0x1c, a4);  /* 014c */
  ST32(a1 + 0x20, a5);  /* 014e */
  __asm__ volatile("" ::: "memory");  /* 0151: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 0154: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 0157: callx a8 via reloc-expand */
  L_015a: a2 = a10;  /* 015a */
  L_015c: return a2;  /* 015c: retw.n */
}


/* esp_mesh_set_passive_scan_time @ mesh.o 00000008 size 29B bind GLOBAL
 * Calls: none | Data refs: g_mesh_passive_scan_time
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_passive_scan_time(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a9 = a2 + (-100);  /* 000b */
  a10 = 0x5db;  /* 000e */
  a8 = 0x00004008u;  /* 0011: l32r = 16392 */
  if (a10 < a9) goto L_001e;  /* 0014: bltu a10, a9, 1e <esp_mesh_set_passive_scan_time+0x16> */
  L_0017: a8 = (u32)&g_mesh_passive_scan_time + 0x0;  /* 0017: l32r -> global */
  ST32(a8 + 0x0, a2);  /* 001a */
  a8 = 0;  /* 001c */
  L_001e: a2 = a8;  /* 001e */
  __asm__ volatile("" ::: "memory");  /* 0020: memw */
  return a2;  /* 0023: retw.n */
}


/* esp_mesh_set_root_healing_delay @ mesh.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_mesh_root_healing_delay
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_root_healing_delay(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_root_healing_delay + 0x0;  /* 0007: l32r -> global */
  ST32(a8 + 0x0, a2);  /* 000a */
  a2 = 0;  /* 000c */
  __asm__ volatile("" ::: "memory");  /* 000e: memw */
  return a2;  /* 0011: retw.n */
}


/* esp_mesh_set_router @ mesh.o 0000002c size 144B bind GLOBAL
 * Calls: memset, esp_mesh_is_nwk_inited, mesh_set_router, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[3]: mem[a8+0x158]; mem[a8+0x150]; mem[a3+0xa4] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=8); reloc-direct=5, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_set_router(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 002c: entry a1, 80 (frame 80 bytes) */
  if (a2 != 0) goto L_0070;  /* 002f: bnez.n a2, 70 <esp_mesh_set_router+0x44> */
  L_0031: a2 = (u32)&g_log_level + 0x0;  /* 0031: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0034 */
  a2 = 0x00004008u;  /* 0036: l32r = 16392 */
  if (a3 < 3u) goto L_00ba;  /* 0039: bltui a3, 3, ba <esp_mesh_set_router+0x8e> */
  L_003c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 003c: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 003f */
  if (a8 == 0) goto L_00ba;  /* 0041: beqz a8, ba <esp_mesh_set_router+0x8e> */
  L_0044: a3 = LD32(a8 + 0x150);  /* 0044 */
  if (a3 == 0) goto L_00ba;  /* 0047: beqz a3, ba <esp_mesh_set_router+0x8e> */
  L_004a: a10 = LD32(a8 + 0x158);  /* 004a */
  /* 004d: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x68a;  /* 0050 */
  a13 = a10;  /* 0053 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0055: -> "mesh" */
  a10 = 3;  /* 0058 */
  a14 = a11;  /* 005a: mov */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 005d: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0060: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 0063 */
  __asm__ volatile("" ::: "memory");  /* 0066: memw */
  /* 0069: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00ba;  /* 006c: j */
  L_0070: a12 = 20;  /* 0070 */
  a11 = 0;  /* 0072 */
  a10 = a1 + (16);  /* 0074 */
  a8 = (u32)&memset + 0x0;  /* 0077: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 007a: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 007d: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 0080: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0091;  /* 0083: bnez.n a10, 91 <esp_mesh_set_router+0x65> */
  L_0085: a10 = a2;  /* 0085 */
  a8 = (u32)&mesh_set_router + 0x0;  /* 0087: l32r -> global */
  a2 = mesh_set_router(a2, a3, a4, a5, a6, a7);  /* 008a: callx a8 via reloc-expand */
  goto L_00b8;  /* 008d: j */
  L_0091: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0091: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0094 */
  a10 = LD32(a3 + 0xa4);  /* 0097 */
  /* 009a: INDIRECT callx a10 <- mem[a3+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 009d: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 00a0: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0085;  /* 00a3: bnez a10, 85 <esp_mesh_set_router+0x59> */
  L_00a6: a3 = 9;  /* 00a6 */
  a10 = a1 + (16);  /* 00a8 */
  ST32(a1 + 0x10, a3);  /* 00ab */
  ST32(a1 + 0x14, a2);  /* 00ad */
  __asm__ volatile("" ::: "memory");  /* 00af: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 00b2: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 00b5: callx a8 via reloc-expand */
  L_00b8: a2 = a10;  /* 00b8 */
  L_00ba: return a2;  /* 00ba: retw.n */
}


/* esp_mesh_set_self_organized @ mesh.o 00000018 size 92B bind GLOBAL
 * Calls: memset, esp_mesh_is_nwk_inited, mesh_set_self_organized, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[1]: mem[a8+0xa4] | Data refs: g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=6); reloc-direct=5, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_set_self_organized(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0018: entry a1, 64 (frame 64 bytes) */
  a12 = 20;  /* 001b */
  a11 = 0;  /* 001d */
  a10 = a1;  /* 001f */
  a2 = (a2 >> 8) & 0x1;  /* 0021: extui width 1 */
  a3 = (a3 >> 8) & 0x1;  /* 0024: extui width 1 */
  a8 = (u32)&memset + 0x0;  /* 0027: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 002a: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 002d: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 0030: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0045;  /* 0033: bnez.n a10, 45 <esp_mesh_set_self_organized+0x2d> */
  L_0035: a12 = 2;  /* 0035 */
  a11 = a3;  /* 0037 */
  a10 = a2;  /* 0039 */
  a8 = (u32)&mesh_set_self_organized + 0x0;  /* 003b: l32r -> global */
  a2 = mesh_set_self_organized(a2, a3, a4, a5, a6, a7);  /* 003e: callx a8 via reloc-expand */
  goto L_0070;  /* 0041: j */
  L_0045: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0045: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0048 */
  a10 = LD32(a8 + 0xa4);  /* 004b */
  /* 004e: INDIRECT callx a10 <- mem[a8+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 0051: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 0054: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0035;  /* 0057: bnez a10, 35 <esp_mesh_set_self_organized+0x1d> */
  L_005a: ST32(a1 + 0x0, a10);  /* 005a */
  a10 = a1;  /* 005c */
  ST8(a1 + 0x4, a2);  /* 005e */
  ST8(a1 + 0x5, a3);  /* 0061 */
  __asm__ volatile("" ::: "memory");  /* 0064: memw */
  __asm__ volatile("" ::: "memory");  /* 0067: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 006a: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 006d: callx a8 via reloc-expand */
  L_0070: a2 = a10;  /* 0070 */
  return a2;  /* 0072: retw.n */
}


/* esp_mesh_set_switch_parent_paras @ mesh.o 00000024 size 157B bind GLOBAL
 * Calls: none | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_cfg_switch_parent
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=4); reloc-direct=0, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_set_switch_parent_paras(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a8 = a2;  /* 0027 */
  if (a2 != 0) goto L_006c;  /* 0029: bnez.n a2, 6c <esp_mesh_set_switch_parent_paras+0x48> */
  L_002b: a2 = (u32)&g_log_level + 0x0;  /* 002b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002e */
  a2 = 0x00004008u;  /* 0030: l32r = 16392 */
  if (a3 >= 3u) goto L_0039;  /* 0033: bgeui a3, 3, 39 <esp_mesh_set_switch_parent_paras+0x15> */
  L_0036: goto L_00bc;  /* 0036: j */
  L_0039: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0039: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 003c */
  if (a8 == 0) goto L_00bc;  /* 003f: beqz a8, bc <esp_mesh_set_switch_parent_paras+0x98> */
  L_0042: a3 = LD32(a8 + 0x150);  /* 0042 */
  if (a3 == 0) goto L_00bc;  /* 0045: beqz a3, bc <esp_mesh_set_switch_parent_paras+0x98> */
  L_0048: a10 = LD32(a8 + 0x158);  /* 0048 */
  /* 004b: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 004e */
  a10 = 3;  /* 0050 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0052: -> "mesh" */
  a14 = a11;  /* 0055 */
  a8 = 0x000009f3u;  /* 0057: l32r = 2547 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 005a: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 005d: -> "mesh" */
  ST32(a1 + 0x0, a8);  /* 0060 */
  __asm__ volatile("" ::: "memory");  /* 0062: memw */
  /* 0065: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00bc;  /* 0068: j */
  L_006c: a10 = LD32(a2 + 0x4);  /* 006c */
  a3 = 118;  /* 006e */
  a2 = a10 + (119);  /* 0071 */
  if (a3 < a2) goto L_0089;  /* 0074: bltu a3, a2, 89 <esp_mesh_set_switch_parent_paras+0x65> */
  L_0077: a9 = LD32(a8 + 0x0);  /* 0077 */
  a3 = 0x00001387u;  /* 0079: l32r = 4999 */
  a2 = 0x00004008u;  /* 007c: l32r = 16392 */
  if ((i32)a3 >= (i32)a9) goto L_00bc;  /* 007f: bge a3, a9, bc <esp_mesh_set_switch_parent_paras+0x98> */
  L_0082: a2 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 0082: l32r -> global */
  ST32(a2 + 0x4, a10);  /* 0085 */
  ST32(a2 + 0x0, a9);  /* 0087 */
  L_0089: a9 = 118;  /* 0089 */
  a2 = LD32(a8 + 0x4);  /* 008c */
  a3 = a2 + (119);  /* 008e */
  if (a9 < a3) goto L_009a;  /* 0091: bltu a9, a3, 9a <esp_mesh_set_switch_parent_paras+0x76> */
  L_0094: a3 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 0094: l32r -> global */
  ST32(a3 + 0x4, a2);  /* 0097 */
  L_009a: a2 = LD32(a8 + 0x8);  /* 009a */
  if ((i32)a2 >= 0) goto L_00a4;  /* 009c: bgez a2, a4 <esp_mesh_set_switch_parent_paras+0x80> */
  L_009f: a3 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 009f: l32r -> global */
  ST32(a3 + 0x8, a2);  /* 00a2 */
  L_00a4: a2 = LD32(a8 + 0x10);  /* 00a4 */
  if ((i32)a2 >= 0) goto L_00ae;  /* 00a6: bgez a2, ae <esp_mesh_set_switch_parent_paras+0x8a> */
  L_00a9: a3 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 00a9: l32r -> global */
  ST32(a3 + 0x10, a2);  /* 00ac */
  L_00ae: a2 = 0;  /* 00ae */
  a8 = LD32(a8 + 0xc);  /* 00b0 */
  if ((i32)a8 >= (i32)a2) goto L_00bc;  /* 00b3: bge a8, a2, bc <esp_mesh_set_switch_parent_paras+0x98> */
  L_00b6: a3 = (u32)&g_mesh_cfg_switch_parent + 0x0;  /* 00b6: l32r -> global */
  ST32(a3 + 0xc, a8);  /* 00b9 */
  L_00bc: __asm__ volatile("" ::: "memory");  /* 00bc: memw */
  return a2;  /* 00bf: retw.n */
}


/* esp_mesh_set_topology @ mesh.o 00000010 size 35B bind GLOBAL
 * Calls: none | Data refs: g_is_mesh_started, g_mesh_topology
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_topology(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_is_mesh_started + 0x0;  /* 0013: l32r -> global */
  a9 = LD8U(a8 + 0x0);  /* 0016 */
  a8 = 0x00004006u;  /* 0019: l32r = 16390 */
  if (a9 != 0) goto L_002c;  /* 001c: bnez.n a9, 2c <esp_mesh_set_topology+0x1c> */
  L_001e: a8 = 0x00004008u;  /* 001e: l32r = 16392 */
  if (a2 >= 2u) goto L_002c;  /* 0021: bgeui a2, 2, 2c <esp_mesh_set_topology+0x1c> */
  L_0024: a8 = (u32)&g_mesh_topology + 0x0;  /* 0024: l32r -> global */
  ST32(a8 + 0x0, a2);  /* 0027 */
  a8 = a9;  /* 0029: mov */
  L_002c: a2 = a8;  /* 002c */
  __asm__ volatile("" ::: "memory");  /* 002e: memw */
  return a2;  /* 0031: retw.n */
}


/* esp_mesh_set_type @ mesh.o 0000002c size 134B bind GLOBAL
 * Calls: memset, esp_mesh_is_nwk_inited, mesh_set_type, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[3]: mem[a8+0x158]; mem[a8+0x150]; mem[a3+0xa4] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=10); reloc-direct=5, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_set_type(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  /* 002c: entry a1, 64 (frame 64 bytes) */
  a3 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 002f: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a3 = LD8U(a3 + 0x0);  /* 0032 */
  if (a3 != 0) goto L_0068;  /* 0035: bnez.n a3, 68 <esp_mesh_set_type+0x3c> */
  L_0037: a2 = (u32)&g_log_level + 0x0;  /* 0037: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 003a */
  a2 = 0x00004002u;  /* 003c: l32r = 16386 */
  if (a3 < 3u) goto L_00b0;  /* 003f: bltui a3, 3, b0 <esp_mesh_set_type+0x84> */
  L_0042: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0042: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0045 */
  if (a8 == 0) goto L_00b0;  /* 0047: beqz a8, b0 <esp_mesh_set_type+0x84> */
  L_004a: a3 = LD32(a8 + 0x150);  /* 004a */
  if (a3 == 0) goto L_00b0;  /* 004d: beqz a3, b0 <esp_mesh_set_type+0x84> */
  L_0050: a10 = LD32(a8 + 0x158);  /* 0050 */
  /* 0053: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0056 */
  a10 = 3;  /* 0058 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 005a: -> "mesh" */
  a14 = a11;  /* 005d */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 005f: l32r -> .rodata.esp_mesh_recv.str1.1 */
  /* 0062: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00b0;  /* 0065: j */
  L_0068: a12 = 20;  /* 0068 */
  a11 = 0;  /* 006a */
  a10 = a1;  /* 006c */
  a8 = (u32)&memset + 0x0;  /* 006e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 0074: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 0077: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0089;  /* 007a: bnez.n a10, 89 <esp_mesh_set_type+0x5d> */
  L_007c: a10 = a2;  /* 007c */
  a8 = (u32)&mesh_set_type + 0x0;  /* 007e: l32r -> global */
  a2 = mesh_set_type(a2, a3, a4, a5, a6, a7);  /* 0081: callx a8 via reloc-expand */
  goto L_00ae;  /* 0084: j */
  L_0089: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0089: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 008c */
  a10 = LD32(a3 + 0xa4);  /* 008e */
  /* 0091: INDIRECT callx a10 <- mem[a3+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 0094: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 0097: callx a8 via reloc-expand */
  if (a10 != 0) goto L_007c;  /* 009a: bnez a10, 7c <esp_mesh_set_type+0x50> */
  L_009d: a3 = 8;  /* 009d */
  a10 = a1;  /* 009f */
  ST32(a1 + 0x0, a3);  /* 00a1 */
  ST32(a1 + 0x4, a2);  /* 00a3 */
  __asm__ volatile("" ::: "memory");  /* 00a5: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 00a8: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 00ab: callx a8 via reloc-expand */
  L_00ae: a2 = a10;  /* 00ae */
  L_00b0: return a2;  /* 00b0: retw.n */
}


/* esp_mesh_set_vote_percentage @ mesh.o 00000010 size 46B bind GLOBAL
 * Calls: none | Data refs: g_mesh_cfg_vote_percent
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_vote_percentage(void) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a2, a3;
  float F0, F1;
  u32 BOOL_b0; /* boolean special-regs (FP compare results) */
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a3 = 0x00000000u;  /* 0013: l32r = 0 */
  F0 = u2f(a2);  /* 0016: wfr (bitcast u32->float) */
  F1 = u2f(a3);  /* 0019: wfr (bitcast u32->float) */
  BOOL_b0 = (F0 <= F1);  /* 001c: ole.s (false if unordered/NaN) */
  a2 = 0x00004008u;  /* 001f: l32r = 16392 */
  if (BOOL_b0) goto L_0039;  /* 0022: bt b0, 39 <esp_mesh_set_vote_percentage+0x29> (boolean reg) */
  a3 = 0x3f800000u;  /* 0025: l32r = 1065353216 */
  F1 = u2f(a3);  /* 0028: wfr (bitcast u32->float) */
  BOOL_b0 = (F1 < F0);  /* 002b: olt.s (false if unordered/NaN) */
  if (BOOL_b0) goto L_0039;  /* 002e: bt b0, 39 <esp_mesh_set_vote_percentage+0x29> (boolean reg) */
  a2 = (u32)&g_mesh_cfg_vote_percent + 0x0;  /* 0031: l32r -> global */
  ST32F(a2 + 0x0, F0);  /* 0034: ssi */
  a2 = 0;  /* 0037 */
  L_0039: __asm__ volatile("" ::: "memory");  /* 0039: memw */
  return a2;  /* 003c: retw.n */
}


/* esp_mesh_set_xon_qsize @ mesh.o 00000008 size 25B bind GLOBAL
 * Calls: none | Data refs: g_mesh_xon_cfg_qsize
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_set_xon_qsize(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a9 = 15;  /* 000b */
  a8 = 0x00004008u;  /* 000d: l32r = 16392 */
  if ((i32)a9 >= (i32)a2) goto L_001a;  /* 0010: bge a9, a2, 1a <esp_mesh_set_xon_qsize+0x12> */
  L_0013: a8 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0013: l32r -> global */
  ST32(a8 + 0x0, a2);  /* 0016 */
  a8 = 0;  /* 0018 */
  L_001a: a2 = a8;  /* 001a */
  __asm__ volatile("" ::: "memory");  /* 001c: memw */
  return a2;  /* 001f: retw.n */
}


/* esp_mesh_start @ mesh.o 0000008c size 396B bind GLOBAL
 * Calls: esp_wifi_get_ps, esp_mesh_sta_disassoc, esp_mesh_ie_init, esp_mesh_map_deauth, mesh_wifi_event_init, esp_mesh_create_mbox, esp_mesh_route_init, esp_mesh_stop, esp_mesh_send_block_init, esp_mesh_tx_task_init, esp_mesh_rx_task_init, esp_mesh_nwk_task_init, esp_mesh_send_event_internal | indirect[4]: mem[a8+0x158]; mem[a8+0x150]; mem[a2+0x48] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_mesh_ext_cfg, .rodata.esp_mesh_set_parent.str1.1, g_is_mesh_started, g_is_standalone_sta, g_mesh_init_ps_type, s_mesh_send_mutex, mesh_myself_mbox +3 more
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=13, refs=28); reloc-direct=13, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_start(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  /* 008c: entry a1, 48 (frame 48 bytes) */
  a2 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 008f: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = LD8U(a2 + 0x0);  /* 0092 */
  if (a2 != 0) goto L_00c8;  /* 0095: bnez.n a2, c8 <esp_mesh_start+0x3c> */
  L_0097: a2 = (u32)&g_log_level + 0x0;  /* 0097: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 009a */
  a2 = 0x00004002u;  /* 009c: l32r = 16386 */
  if (a3 >= 3u) goto L_00a5;  /* 009f: bgeui a3, 3, a5 <esp_mesh_start+0x19> */
  L_00a2: goto L_0216;  /* 00a2: j */
  L_00a5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a5: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00a8 */
  if (a8 == 0) goto L_0216;  /* 00aa: beqz a8, 216 <esp_mesh_start+0x18a> */
  L_00ad: a3 = LD32(a8 + 0x150);  /* 00ad */
  if (a3 == 0) goto L_0216;  /* 00b0: beqz a3, 216 <esp_mesh_start+0x18a> */
  L_00b3: a10 = LD32(a8 + 0x158);  /* 00b3 */
  /* 00b6: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00b9 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00bb: -> "mesh" */
  a14 = a11;  /* 00be */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 00c0: l32r -> .rodata.esp_mesh_recv.str1.1 */
  goto L_00fc;  /* 00c3: j */
  L_00c8: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 00c8: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 00cb */
  if (a2 != 0) goto L_0104;  /* 00ce: bnez.n a2, 104 <esp_mesh_start+0x78> */
  L_00d0: a2 = (u32)&g_log_level + 0x0;  /* 00d0: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00d3 */
  a2 = 0x00004003u;  /* 00d5: l32r = 16387 */
  if (a3 >= 3u) goto L_00de;  /* 00d8: bgeui a3, 3, de <esp_mesh_start+0x52> */
  L_00db: goto L_0216;  /* 00db: j */
  L_00de: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00de: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00e1 */
  if (a8 == 0) goto L_0216;  /* 00e3: beqz a8, 216 <esp_mesh_start+0x18a> */
  L_00e6: a3 = LD32(a8 + 0x150);  /* 00e6 */
  if (a3 == 0) goto L_0216;  /* 00e9: beqz a3, 216 <esp_mesh_start+0x18a> */
  L_00ec: a10 = LD32(a8 + 0x158);  /* 00ec */
  /* 00ef: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00f2 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00f4: -> "mesh" */
  a14 = a11;  /* 00f7 */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_parent_str1_1 + 0x0);  /* 00f9: l32r -> .rodata.esp_mesh_set_parent.str1.1 */
  L_00fc: a10 = 3;  /* 00fc */
  /* 00fe: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_0216;  /* 0101: j */
  L_0104: a3 = (u32)&g_is_mesh_started + 0x0;  /* 0104: l32r -> global */
  a2 = 0;  /* 0107 */
  a4 = LD8U(a3 + 0x0);  /* 0109 */
  if (a4 == a2) goto L_0112;  /* 010c: beq a4, a2, 112 <esp_mesh_start+0x86> */
  L_010f: goto L_0216;  /* 010f: j */
  L_0112: a4 = (u32)&g_is_standalone_sta + 0x0;  /* 0112: l32r -> global */
  ST32(a1 + 0x0, a2);  /* 0115 */
  a2 = LD8U(a4 + 0x0);  /* 0117 */
  if (a2 == 0) goto L_013c;  /* 011a: beqz.n a2, 13c <esp_mesh_start+0xb0> */
  L_011c: a10 = (u32)&g_mesh_init_ps_type + 0x0;  /* 011c: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 011f: memw */
  a8 = (u32)&esp_wifi_get_ps + 0x0;  /* 0122: l32r -> global */
  a2 = esp_wifi_get_ps(a2, a3, a4, a5, a6, a7);  /* 0125: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_sta_disassoc + 0x0;  /* 0128: l32r -> global */
  a2 = esp_mesh_sta_disassoc(a2, a3, a4, a5, a6, a7);  /* 012b: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_ie_init;  /* 012e: l32r -> func addr */
  a2 = esp_mesh_ie_init(a2, a3, a4, a5, a6, a7);  /* 0131: callx a8 via reloc-expand */
  a10 = LD8U(a4 + 0x0);  /* 0134 */
  if (a10 != 0) goto L_015a;  /* 0137: bnez.n a10, 15a <esp_mesh_start+0xce> */
  L_0139: goto L_0152;  /* 0139: j */
  L_013c: a10 = a1;  /* 013c */
  a8 = (u32)&esp_wifi_get_ps + 0x0;  /* 013e: l32r -> global */
  a2 = esp_wifi_get_ps(a2, a3, a4, a5, a6, a7);  /* 0141: callx a8 via reloc-expand */
  a2 = 0x00004019u;  /* 0144: l32r = 16409 */
  if (a10 != 0) goto L_0216;  /* 0147: bnez a10, 216 <esp_mesh_start+0x18a> */
  L_014a: a8 = LD32(a1 + 0x0);  /* 014a */
  if (a8 < 2u) goto L_011c;  /* 014c: bltui a8, 2, 11c <esp_mesh_start+0x90> */
  L_014f: goto L_0216;  /* 014f: j */
  L_0152: a11 = 6;  /* 0152 */
  a8 = (u32)&esp_mesh_map_deauth + 0x0;  /* 0154: l32r -> global */
  a2 = esp_mesh_map_deauth(a2, a3, a4, a5, a6, a7);  /* 0157: callx a8 via reloc-expand */
  L_015a: a8 = (u32)&mesh_wifi_event_init;  /* 015a: l32r -> func addr */
  a2 = mesh_wifi_event_init(a2, a3, a4, a5, a6, a7);  /* 015d: callx a8 via reloc-expand */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0160: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0163 */
  a10 = LD32(a2 + 0x48);  /* 0166 */
  /* 0169: INDIRECT callx a10 <- mem[a2+0x48]; result unknown */ a2 = 0;
  a2 = (u32)&s_mesh_send_mutex + 0x0;  /* 016c: l32r -> global */
  ST32(a2 + 0x0, a10);  /* 016f */
  if (a10 != 0) goto L_017d;  /* 0171: bnez a10, 17d <esp_mesh_start+0xf1> */
  L_0174: a2 = 0x00004007u;  /* 0174: l32r = 16391 */
  __asm__ volatile("" ::: "memory");  /* 0177: memw */
  goto L_0216;  /* 017a: j */
  L_017d: a10 = (u32)&mesh_myself_mbox + 0x0;  /* 017d: l32r -> global */
  a4 = 1;  /* 0180 */
  a12 = 4;  /* 0182 */
  a2 = LD8U(a10 + 0x8);  /* 0184 */
  a2 = a2 | a4;  /* 0187 */
  ST8(a10 + 0x8, a2);  /* 018a */
  __asm__ volatile("" ::: "memory");  /* 018d: memw */
  a2 = (u32)&g_mesh_xon_cfg_qsize + 0x0;  /* 0190: l32r -> global */
  a11 = LD32(a2 + 0x0);  /* 0193 */
  a11 = a11 + a11;  /* 0195 */
  __asm__ volatile("" ::: "memory");  /* 0198: memw */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 019b: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 019e: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0174;  /* 01a1: bnez a10, 174 <esp_mesh_start+0xe8> */
  L_01a4: a11 = LD32(a2 + 0x0);  /* 01a4 */
  a12 = 4;  /* 01a6 */
  a11 = a11 + a11;  /* 01a9 */
  a10 = (u32)&mesh_tcpip_mbox + 0x0;  /* 01ac: l32r -> global */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 01af: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 01b2: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0174;  /* 01b5: bnez a10, 174 <esp_mesh_start+0xe8> */
  L_01b8: a12 = 4;  /* 01b8 */
  a10 = (u32)&mesh_xmit_state_mbox + 0x0;  /* 01ba: l32r -> global */
  a11 = 32;  /* 01bd */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 01bf: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 01c2: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0174;  /* 01c5: bnez a10, 174 <esp_mesh_start+0xe8> */
  L_01c8: a8 = (u32)&esp_mesh_route_init + 0x0;  /* 01c8: l32r -> global */
  a2 = esp_mesh_route_init(a2, a3, a4, a5, a6, a7);  /* 01cb: callx a8 via reloc-expand */
  if (a10 == 0) goto L_01dd;  /* 01ce: beqz.n a10, 1dd <esp_mesh_start+0x151> */
  L_01d0: a8 = (u32)&esp_mesh_stop;  /* 01d0: l32r -> func addr */
  a2 = esp_mesh_stop(a2, a3, a4, a5, a6, a7);  /* 01d3: callx a8 via reloc-expand */
  a2 = -1;  /* 01d6 */
  goto L_0216;  /* 01d8: j */
  L_01dd: a8 = (u32)&esp_mesh_send_block_init + 0x0;  /* 01dd: l32r -> global */
  a2 = esp_mesh_send_block_init(a2, a3, a4, a5, a6, a7);  /* 01e0: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01d0;  /* 01e3: bnez a10, 1d0 <esp_mesh_start+0x144> */
  L_01e6: a8 = (u32)&esp_mesh_tx_task_init + 0x0;  /* 01e6: l32r -> global */
  a2 = esp_mesh_tx_task_init(a2, a3, a4, a5, a6, a7);  /* 01e9: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01d0;  /* 01ec: bnez a10, 1d0 <esp_mesh_start+0x144> */
  L_01ef: a8 = (u32)&esp_mesh_rx_task_init + 0x0;  /* 01ef: l32r -> global */
  a2 = esp_mesh_rx_task_init(a2, a3, a4, a5, a6, a7);  /* 01f2: callx a8 via reloc-expand */
  if (a10 != 0) goto L_01d0;  /* 01f5: bnez a10, 1d0 <esp_mesh_start+0x144> */
  L_01f8: a8 = (u32)&esp_mesh_nwk_task_init + 0x0;  /* 01f8: l32r -> global */
  a2 = esp_mesh_nwk_task_init(a2, a3, a4, a5, a6, a7);  /* 01fb: callx a8 via reloc-expand */
  a2 = a10;  /* 01fe */
  if (a10 != 0) goto L_01d0;  /* 0200: bnez a10, 1d0 <esp_mesh_start+0x144> */
  L_0203: a12 = a10;  /* 0203 */
  a11 = a10;  /* 0205 */
  ST8(a3 + 0x0, a4);  /* 0207 */
  __asm__ volatile("" ::: "memory");  /* 020a: memw */
  __asm__ volatile("" ::: "memory");  /* 020d: memw */
  a8 = (u32)&esp_mesh_send_event_internal + 0x0;  /* 0210: l32r -> global */
  a2 = esp_mesh_send_event_internal(a2, a3, a4, a5, a6, a7);  /* 0213: callx a8 via reloc-expand */
  L_0216: return a2;  /* 0216: retw.n */
}


/* esp_mesh_stop @ mesh.o 00000138 size 1510B bind GLOBAL
 * Calls: memset, mesh_mutex_lock, esp_wifi_set_ps, esp_wifi_vnd_mesh_deinit, esp_mesh_send_block_deinit, esp_mesh_rx_task_deinit, esp_mesh_tx_task_deinit, esp_mesh_nwk_task_deinit, mesh_wifi_event_deinit, esp_mesh_route_deinit, mesh_stop_recv, esp_mesh_free_mbox, mesh_mutex_unlock, esp_mesh_push_to_xmit_state_queue, esp_mesh_get_storage, esp_mesh_nvs_deinit, esp_wifi_get_config, sprintf, strnlen, esp_wifi_set_config, esp_mesh_set_router_bssid, mesh_free, esp_mesh_send_event_internal | indirect[39]: mem[a3+0x158]; mem[a3+0x150]; mem[a3+0x7c]; mem[a4+0x158] | Data refs: .bss.g_is_mesh_inited, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_recv.str1.1, g_mesh_stop_event_group, .rodata.esp_mesh_stop.str1.1, s_mesh_send_mutex, .rodata.__func__$12, g_is_mesh_started, g_mesh_init_ps_type, mesh_deinit_cb +11 more
 * Fidelity: medium - 39 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=23, refs=46); reloc-direct=23, funcdb-attributed=0, unknown-indirect=39 */
u32 esp_mesh_stop(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a7, a8, a9;
  float F0, F4, F8;
  /* 0138: entry a1, 0x100 (frame 0x100 bytes) */
  a7 = (u32)&LOCAL__bss_g_is_mesh_inited + 0x0;  /* 013b: l32r -> .bss.g_is_mesh_inited (same-object static) */
  a2 = LD8U(a7 + 0x0);  /* 013e */
  if (a2 != 0) goto L_0178;  /* 0141: bnez.n a2, 178 <esp_mesh_stop+0x40> */
  L_0143: a2 = (u32)&g_log_level + 0x0;  /* 0143: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0146 */
  a2 = 0x00004002u;  /* 0148: l32r = 16386 */
  if (a3 >= 3u) goto L_0151;  /* 014b: bgeui a3, 3, 151 <esp_mesh_stop+0x19> */
  L_014e: goto L_071c;  /* 014e: j */
  L_0151: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0151: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0154 */
  if (a3 == 0) goto L_071c;  /* 0156: beqz a3, 71c <esp_mesh_stop+0x5e4> */
  L_0159: a4 = LD32(a3 + 0x150);  /* 0159 */
  if (a4 == 0) goto L_071c;  /* 015c: beqz a4, 71c <esp_mesh_stop+0x5e4> */
  L_015f: a10 = LD32(a3 + 0x158);  /* 015f */
  /* 0162: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0165 */
  a10 = 3;  /* 0167 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0169: -> "mesh" */
  a14 = a11;  /* 016c */
  a12 = (u32)(RODATA__rodata_esp_mesh_recv_str1_1 + 0x0);  /* 016e: l32r -> .rodata.esp_mesh_recv.str1.1 */
  /* 0171: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_071c;  /* 0174: j */
  L_0178: a12 = 184;  /* 0178 */
  a11 = 0;  /* 017b */
  a10 = a1 + (16);  /* 017d */
  a8 = (u32)&memset + 0x0;  /* 0180: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 0183: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0186: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0189 */
  a10 = LD32(a3 + 0x7c);  /* 018b */
  /* 018e: INDIRECT callx a10 <- mem[a3+0x7c]; result unknown */ a2 = 0;
  a5 = (u32)&g_mesh_stop_event_group + 0x0;  /* 0191: l32r -> global */
  ST32(a5 + 0x0, a10);  /* 0194 */
  if (a10 != 0) goto L_01cc;  /* 0196: bnez.n a10, 1cc <esp_mesh_stop+0x94> */
  L_0198: a3 = LD32(a2 + 0x0);  /* 0198 */
  a2 = -1;  /* 019a */
  if (a3 == 0) goto L_071c;  /* 019c: beqz a3, 71c <esp_mesh_stop+0x5e4> */
  L_019f: a4 = LD32(a3 + 0x150);  /* 019f */
  if (a4 == 0) goto L_071c;  /* 01a2: beqz a4, 71c <esp_mesh_stop+0x5e4> */
  L_01a5: a10 = LD32(a3 + 0x158);  /* 01a5 */
  a3 = 0x1b9;  /* 01a8 */
  __asm__ volatile("" ::: "memory");  /* 01ab: memw */
  /* 01ae: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01b1 */
  a10 = 1;  /* 01b3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 01b5: -> "mesh" */
  a14 = a11;  /* 01b8 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 01ba: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 01bd: l32r -> .rodata.esp_mesh_stop.str1.1 */
  ST32(a1 + 0x0, a3);  /* 01c0 */
  __asm__ volatile("" ::: "memory");  /* 01c2: memw */
  /* 01c5: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_071c;  /* 01c8: j */
  L_01cc: a6 = (u32)&s_mesh_send_mutex + 0x0;  /* 01cc: l32r -> global */
  a12 = 0x1c0;  /* 01cf */
  a4 = 0;  /* 01d2 */
  a3 = (u32)(RODATA__rodata___func___12 + 0x0);  /* 01d4: l32r -> .rodata.__func__$12 */
  a11 = a3;  /* 01d7 */
  a10 = LD32(a6 + 0x0);  /* 01d9 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 01db: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6);  /* 01de: callx a8 via reloc-expand */
  a10 = 0;  /* 01e1 */
  a8 = (u32)&esp_wifi_set_ps + 0x0;  /* 01e3: l32r -> global */
  a2 = esp_wifi_set_ps(a2, a3, a4, a5, a6);  /* 01e6: callx a8 via reloc-expand */
  ST8(a7 + 0x0, a4);  /* 01e9 */
  __asm__ volatile("" ::: "memory");  /* 01ec: memw */
  a7 = (u32)&g_is_mesh_started + 0x0;  /* 01ef: l32r -> global */
  a8 = (u32)&g_mesh_init_ps_type + 0x0;  /* 01f2: l32r -> global */
  ST8(a7 + 0x0, a4);  /* 01f5 */
  __asm__ volatile("" ::: "memory");  /* 01f8: memw */
  a7 = (u32)&g_log_level + 0x0;  /* 01fb: l32r -> global */
  ST32(a8 + 0x0, a4);  /* 01fe */
  a4 = LD32(a7 + 0x0);  /* 0200 */
  if (a4 < 3u) goto L_0268;  /* 0202: bltui a4, 3, 268 <esp_mesh_stop+0x130> */
  L_0205: a4 = LD32(a2 + 0x0);  /* 0205 */
  if (a4 != 0) goto L_0214;  /* 0207: bnez.n a4, 214 <esp_mesh_stop+0xdc> */
  L_0209: a4 = LD32(a2 + 0x0);  /* 0209 */
  if (a4 != 0) goto L_0241;  /* 020b: bnez.n a4, 241 <esp_mesh_stop+0x109> */
  L_020d: __asm__ volatile("" ::: "memory");  /* 020d: memw */
  goto L_0268;  /* 0210: j */
  L_0214: a8 = LD32(a4 + 0x150);  /* 0214 */
  if (a8 == 0) goto L_0209;  /* 0217: beqz a8, 209 <esp_mesh_stop+0xd1> */
  L_021a: a10 = LD32(a4 + 0x158);  /* 021a */
  ST32(a1 + 0xd0, a8);  /* 021d */
  __asm__ volatile("" ::: "memory");  /* 0220: memw */
  /* 0223: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0226 */
  a10 = 3;  /* 0228 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 022a: -> "mesh" */
  a14 = a11;  /* 022d */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 022f: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 0232 */
  /* 0235: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  a4 = LD32(a7 + 0x0);  /* 0238 */
  if (a4 >= 3u) goto L_0209;  /* 023a: bgeui a4, 3, 209 <esp_mesh_stop+0xd1> */
  L_023d: goto L_0268;  /* 023d: j */
  L_0241: a8 = LD32(a4 + 0x150);  /* 0241 */
  if (a8 == 0) goto L_0268;  /* 0244: beqz.n a8, 268 <esp_mesh_stop+0x130> */
  L_0246: a10 = LD32(a4 + 0x158);  /* 0246 */
  ST32(a1 + 0xd0, a8);  /* 0249 */
  __asm__ volatile("" ::: "memory");  /* 024c: memw */
  /* 024f: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0252 */
  a15 = 0x1c6;  /* 0254 */
  a10 = 3;  /* 0257 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0259: -> "mesh" */
  a14 = a11;  /* 025c: mov */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 025f: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 0262 */
  /* 0265: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_0268: a10 = (u32)&mesh_deinit_cb + 0x0;  /* 0268: l32r -> global */
  a8 = (u32)&esp_wifi_vnd_mesh_deinit + 0x0;  /* 026b: l32r -> global */
  a2 = esp_wifi_vnd_mesh_deinit(a2, a3, a4, a5, a6);  /* 026e: callx a8 via reloc-expand */
  a4 = LD32(a2 + 0x0);  /* 0271 */
  if (a4 == 0) goto L_02a4;  /* 0273: beqz.n a4, 2a4 <esp_mesh_stop+0x16c> */
  L_0275: a8 = LD32(a4 + 0x150);  /* 0275 */
  if (a8 == 0) goto L_02a4;  /* 0278: beqz a8, 2a4 <esp_mesh_stop+0x16c> */
  L_027b: a10 = LD32(a4 + 0x158);  /* 027b */
  a4 = 0x1c9;  /* 027e */
  ST32(a1 + 0xd0, a8);  /* 0281 */
  __asm__ volatile("" ::: "memory");  /* 0284: memw */
  /* 0287: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 028a */
  a10 = 2;  /* 028c */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 028e: -> "mesh" */
  a14 = a11;  /* 0291 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0293: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 0296: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 0299 */
  ST32(a1 + 0x0, a4);  /* 029c */
  __asm__ volatile("" ::: "memory");  /* 029e: memw */
  /* 02a1: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_02a4: a8 = (u32)&esp_mesh_send_block_deinit + 0x0;  /* 02a4: l32r -> global */
  a2 = esp_mesh_send_block_deinit(a2, a3, a4, a5, a6);  /* 02a7: callx a8 via reloc-expand */
  a4 = LD32(a2 + 0x0);  /* 02aa */
  if (a4 == 0) goto L_02dc;  /* 02ac: beqz.n a4, 2dc <esp_mesh_stop+0x1a4> */
  L_02ae: a8 = LD32(a4 + 0x150);  /* 02ae */
  if (a8 == 0) goto L_02dc;  /* 02b1: beqz.n a8, 2dc <esp_mesh_stop+0x1a4> */
  L_02b3: a10 = LD32(a4 + 0x158);  /* 02b3 */
  a4 = 0x1cc;  /* 02b6 */
  ST32(a1 + 0xd0, a8);  /* 02b9 */
  __asm__ volatile("" ::: "memory");  /* 02bc: memw */
  /* 02bf: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02c2 */
  a10 = 2;  /* 02c4 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 02c6: -> "mesh" */
  a14 = a11;  /* 02c9 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 02cb: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 02ce: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 02d1 */
  ST32(a1 + 0x0, a4);  /* 02d4 */
  __asm__ volatile("" ::: "memory");  /* 02d6: memw */
  /* 02d9: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_02dc: a8 = (u32)&esp_mesh_rx_task_deinit + 0x0;  /* 02dc: l32r -> global */
  a2 = esp_mesh_rx_task_deinit(a2, a3, a4, a5, a6);  /* 02df: callx a8 via reloc-expand */
  a4 = LD32(a2 + 0x0);  /* 02e2 */
  if (a4 == 0) goto L_0314;  /* 02e4: beqz.n a4, 314 <esp_mesh_stop+0x1dc> */
  L_02e6: a8 = LD32(a4 + 0x150);  /* 02e6 */
  if (a8 == 0) goto L_0314;  /* 02e9: beqz.n a8, 314 <esp_mesh_stop+0x1dc> */
  L_02eb: a10 = LD32(a4 + 0x158);  /* 02eb */
  a4 = 0x1cf;  /* 02ee */
  ST32(a1 + 0xd0, a8);  /* 02f1 */
  __asm__ volatile("" ::: "memory");  /* 02f4: memw */
  /* 02f7: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02fa */
  a10 = 2;  /* 02fc */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 02fe: -> "mesh" */
  a14 = a11;  /* 0301 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0303: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 0306: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 0309 */
  ST32(a1 + 0x0, a4);  /* 030c */
  __asm__ volatile("" ::: "memory");  /* 030e: memw */
  /* 0311: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_0314: a8 = (u32)&esp_mesh_tx_task_deinit + 0x0;  /* 0314: l32r -> global */
  a2 = esp_mesh_tx_task_deinit(a2, a3, a4, a5, a6);  /* 0317: callx a8 via reloc-expand */
  a4 = LD32(a2 + 0x0);  /* 031a */
  if (a4 == 0) goto L_034c;  /* 031c: beqz.n a4, 34c <esp_mesh_stop+0x214> */
  L_031e: a8 = LD32(a4 + 0x150);  /* 031e */
  if (a8 == 0) goto L_034c;  /* 0321: beqz.n a8, 34c <esp_mesh_stop+0x214> */
  L_0323: a10 = LD32(a4 + 0x158);  /* 0323 */
  a4 = 0x1d2;  /* 0326 */
  ST32(a1 + 0xd0, a8);  /* 0329 */
  __asm__ volatile("" ::: "memory");  /* 032c: memw */
  /* 032f: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0332 */
  a10 = 2;  /* 0334 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0336: -> "mesh" */
  a14 = a11;  /* 0339 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 033b: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 033e: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 0341 */
  ST32(a1 + 0x0, a4);  /* 0344 */
  __asm__ volatile("" ::: "memory");  /* 0346: memw */
  /* 0349: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_034c: a8 = (u32)&esp_mesh_nwk_task_deinit + 0x0;  /* 034c: l32r -> global */
  a2 = esp_mesh_nwk_task_deinit(a2, a3, a4, a5, a6);  /* 034f: callx a8 via reloc-expand */
  a4 = LD32(a2 + 0x0);  /* 0352 */
  if (a4 == 0) goto L_0384;  /* 0354: beqz.n a4, 384 <esp_mesh_stop+0x24c> */
  L_0356: a8 = LD32(a4 + 0x150);  /* 0356 */
  if (a8 == 0) goto L_0384;  /* 0359: beqz.n a8, 384 <esp_mesh_stop+0x24c> */
  L_035b: a10 = LD32(a4 + 0x158);  /* 035b */
  a4 = 0x1d5;  /* 035e */
  ST32(a1 + 0xd0, a8);  /* 0361 */
  __asm__ volatile("" ::: "memory");  /* 0364: memw */
  /* 0367: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 036a */
  a10 = 2;  /* 036c */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 036e: -> "mesh" */
  a14 = a11;  /* 0371 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0373: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 0376: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 0379 */
  ST32(a1 + 0x0, a4);  /* 037c */
  __asm__ volatile("" ::: "memory");  /* 037e: memw */
  /* 0381: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_0384: a8 = (u32)&mesh_wifi_event_deinit;  /* 0384: l32r -> func addr */
  a2 = mesh_wifi_event_deinit(a2, a3, a4, a5, a6);  /* 0387: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_route_deinit + 0x0;  /* 038a: l32r -> global */
  a2 = esp_mesh_route_deinit(a2, a3, a4, a5, a6);  /* 038d: callx a8 via reloc-expand */
  a4 = LD32(a2 + 0x0);  /* 0390 */
  if (a4 == 0) goto L_03c2;  /* 0392: beqz.n a4, 3c2 <esp_mesh_stop+0x28a> */
  L_0394: a8 = LD32(a4 + 0x150);  /* 0394 */
  if (a8 == 0) goto L_03c2;  /* 0397: beqz.n a8, 3c2 <esp_mesh_stop+0x28a> */
  L_0399: a10 = LD32(a4 + 0x158);  /* 0399 */
  a4 = 0x1da;  /* 039c */
  ST32(a1 + 0xd0, a8);  /* 039f */
  __asm__ volatile("" ::: "memory");  /* 03a2: memw */
  /* 03a5: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 03a8 */
  a10 = 2;  /* 03aa */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 03ac: -> "mesh" */
  a14 = a11;  /* 03af */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 03b1: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 03b4: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 03b7 */
  ST32(a1 + 0x0, a4);  /* 03ba */
  __asm__ volatile("" ::: "memory");  /* 03bc: memw */
  /* 03bf: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_03c2: a10 = 0;  /* 03c2 */
  a4 = (u32)&mesh_myself_mbox + 0x0;  /* 03c4: l32r -> global */
  a11 = LD32(a4 + 0x0);  /* 03c7 */
  a12 = LD32(a4 + 0x4);  /* 03c9 */
  a13 = LD32(a4 + 0x8);  /* 03cc */
  a8 = (u32)&mesh_stop_recv;  /* 03ce: l32r -> func addr */
  a2 = mesh_stop_recv(a2, a3, a4, a5, a6);  /* 03d1: callx a8 via reloc-expand */
  a10 = a4;  /* 03d4 */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 03d6: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6);  /* 03d9: callx a8 via reloc-expand */
  a10 = a4;  /* 03dc */
  a12 = 12;  /* 03de */
  a11 = 0;  /* 03e0 */
  a8 = (u32)&memset + 0x0;  /* 03e2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 03e5: callx a8 (libc, via reloc-expand) */
  a4 = LD32(a2 + 0x0);  /* 03e8 */
  if (a4 == 0) goto L_041a;  /* 03ea: beqz.n a4, 41a <esp_mesh_stop+0x2e2> */
  L_03ec: a8 = LD32(a4 + 0x150);  /* 03ec */
  if (a8 == 0) goto L_041a;  /* 03ef: beqz.n a8, 41a <esp_mesh_stop+0x2e2> */
  L_03f1: a10 = LD32(a4 + 0x158);  /* 03f1 */
  a4 = 0x1df;  /* 03f4 */
  ST32(a1 + 0xd0, a8);  /* 03f7 */
  __asm__ volatile("" ::: "memory");  /* 03fa: memw */
  /* 03fd: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0400 */
  a10 = 2;  /* 0402 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0404: -> "mesh" */
  a14 = a11;  /* 0407 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0409: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 040c: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 040f */
  ST32(a1 + 0x0, a4);  /* 0412 */
  __asm__ volatile("" ::: "memory");  /* 0414: memw */
  /* 0417: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_041a: a10 = 1;  /* 041a */
  a4 = (u32)&mesh_tcpip_mbox + 0x0;  /* 041c: l32r -> global */
  a11 = LD32(a4 + 0x0);  /* 041f */
  a12 = LD32(a4 + 0x4);  /* 0421 */
  a13 = LD32(a4 + 0x8);  /* 0424 */
  a8 = (u32)&mesh_stop_recv;  /* 0426: l32r -> func addr */
  a2 = mesh_stop_recv(a2, a3, a4, a5, a6);  /* 0429: callx a8 via reloc-expand */
  a10 = a4;  /* 042c */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 042e: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6);  /* 0431: callx a8 via reloc-expand */
  a10 = a4;  /* 0434 */
  a12 = 12;  /* 0436 */
  a11 = 0;  /* 0439 */
  a8 = (u32)&memset + 0x0;  /* 043c: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 043f: callx a8 (libc, via reloc-expand) */
  a4 = LD32(a2 + 0x0);  /* 0442 */
  if (a4 == 0) goto L_0474;  /* 0444: beqz.n a4, 474 <esp_mesh_stop+0x33c> */
  L_0446: a8 = LD32(a4 + 0x150);  /* 0446 */
  if (a8 == 0) goto L_0474;  /* 0449: beqz.n a8, 474 <esp_mesh_stop+0x33c> */
  L_044b: a10 = LD32(a4 + 0x158);  /* 044b */
  a4 = 0x1e4;  /* 044e */
  ST32(a1 + 0xd0, a8);  /* 0451 */
  __asm__ volatile("" ::: "memory");  /* 0454: memw */
  /* 0457: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 045a */
  a10 = 2;  /* 045c */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 045e: -> "mesh" */
  a14 = a11;  /* 0461 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0463: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 0466: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 0469 */
  ST32(a1 + 0x0, a4);  /* 046c */
  __asm__ volatile("" ::: "memory");  /* 046e: memw */
  /* 0471: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_0474: a12 = 0x1e5;  /* 0474 */
  a11 = a3;  /* 0477 */
  a10 = LD32(a6 + 0x0);  /* 0479 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 047b: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6);  /* 047e: callx a8 via reloc-expand */
  a4 = (u32)&mesh_xmit_state_mbox + 0x0;  /* 0481: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 0484 */
  if (a8 == 0) goto L_052e;  /* 0486: beqz a8, 52e <esp_mesh_stop+0x3f6> */
  L_0489: a8 = LD32(a2 + 0x0);  /* 0489 */
  if (a8 == 0) goto L_04c4;  /* 048b: beqz.n a8, 4c4 <esp_mesh_stop+0x38c> */
  L_048d: a9 = LD32(a8 + 0x150);  /* 048d */
  if (a9 == 0) goto L_04c4;  /* 0490: beqz.n a9, 4c4 <esp_mesh_stop+0x38c> */
  L_0492: a10 = LD32(a8 + 0x158);  /* 0492 */
  ST32(a1 + 0xd0, a9);  /* 0495 */
  __asm__ volatile("" ::: "memory");  /* 0498: memw */
  /* 049b: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 049e */
  a10 = 2;  /* 04a0 */
  a8 = LD32(a4 + 0x8);  /* 04a2 */
  a8 = (a8 >> 1) & 0x3;  /* 04a4: extui width 2 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 04a7: -> "mesh" */
  a14 = a11;  /* 04aa */
  ST32(a1 + 0x4, a8);  /* 04ac */
  a8 = 0x1e8;  /* 04af */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 04b2: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 04b5: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a9 = LD32(a1 + 0xd0);  /* 04b8 */
  ST32(a1 + 0x0, a8);  /* 04bb */
  __asm__ volatile("" ::: "memory");  /* 04be: memw */
  /* 04c1: INDIRECT callx a9 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_04c4: a8 = LD8U(a4 + 0x8);  /* 04c4 */
  if (((a8 >> 1) & 1) == 0) goto L_0526;  /* 04c7: bbci a8, 1, 526 <esp_mesh_stop+0x3ee> */
  L_04ca: a8 = 7;  /* 04ca */
  a10 = 184;  /* 04cc */
  ST32(a1 + 0xc8, a8);  /* 04cf */
  a8 = a1 + (16);  /* 04d2 */
  a11 = 0;  /* 04d5 */
  a10 = a8 + a10;  /* 04d7 */
  __asm__ volatile("" ::: "memory");  /* 04d9: memw */
  a8 = (u32)&esp_mesh_push_to_xmit_state_queue;  /* 04dc: l32r -> func addr */
  a2 = esp_mesh_push_to_xmit_state_queue(a2, a3, a4, a5, a6);  /* 04df: callx a8 via reloc-expand */
  a8 = LD32(a2 + 0x0);  /* 04e2 */
  a14 = -1;  /* 04e4 */
  a13 = 1;  /* 04e6 */
  a12 = 0;  /* 04e8 */
  a11 = 8;  /* 04ea */
  a8 = LD32(a8 + 0x8c);  /* 04ec */
  a10 = LD32(a5 + 0x0);  /* 04ef */
  a2 = esp_mesh_push_to_xmit_state_queue(a2, a3, a4, a5, a6);  /* 04f1: callx a8 via literal-trampoline */
  a8 = LD32(a2 + 0x0);  /* 04f4 */
  if (a8 == 0) goto L_0526;  /* 04f6: beqz.n a8, 526 <esp_mesh_stop+0x3ee> */
  L_04f8: a9 = LD32(a8 + 0x150);  /* 04f8 */
  if (a9 == 0) goto L_0526;  /* 04fb: beqz.n a9, 526 <esp_mesh_stop+0x3ee> */
  L_04fd: a10 = LD32(a8 + 0x158);  /* 04fd */
  ST32(a1 + 0xd0, a9);  /* 0500 */
  __asm__ volatile("" ::: "memory");  /* 0503: memw */
  /* 0506: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x1ee;  /* 0509 */
  a13 = a10;  /* 050c */
  a10 = 2;  /* 050e */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0510: -> "mesh" */
  a14 = a11;  /* 0513 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0515: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 0518: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a9 = LD32(a1 + 0xd0);  /* 051b */
  ST32(a1 + 0x0, a8);  /* 051e */
  __asm__ volatile("" ::: "memory");  /* 0520: memw */
  /* 0523: INDIRECT callx a9 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_0526: a10 = a4;  /* 0526 */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 0528: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6);  /* 052b: callx a8 via reloc-expand */
  L_052e: a10 = a4;  /* 052e */
  a12 = 12;  /* 0530 */
  a11 = 0;  /* 0532 */
  a8 = (u32)&memset + 0x0;  /* 0534: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 0537: callx a8 (libc, via reloc-expand) */
  a4 = LD32(a2 + 0x0);  /* 053a */
  if (a4 == 0) goto L_056c;  /* 053c: beqz.n a4, 56c <esp_mesh_stop+0x434> */
  L_053e: a8 = LD32(a4 + 0x150);  /* 053e */
  if (a8 == 0) goto L_056c;  /* 0541: beqz.n a8, 56c <esp_mesh_stop+0x434> */
  L_0543: a10 = LD32(a4 + 0x158);  /* 0543 */
  a4 = 0x1f3;  /* 0546 */
  ST32(a1 + 0xd0, a8);  /* 0549 */
  __asm__ volatile("" ::: "memory");  /* 054c: memw */
  /* 054f: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0552 */
  a10 = 2;  /* 0554 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0556: -> "mesh" */
  a14 = a11;  /* 0559 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 055b: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 055e: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = LD32(a1 + 0xd0);  /* 0561 */
  ST32(a1 + 0x0, a4);  /* 0564 */
  __asm__ volatile("" ::: "memory");  /* 0566: memw */
  /* 0569: INDIRECT callx a8 <- mem[a1+0xd0]; result unknown */ a2 = 0;
  L_056c: a4 = (u32)&LOCAL__bss_mesh_xmit_sem + 0x0;  /* 056c: l32r -> .bss.mesh_xmit_sem (same-object static) */
  a10 = LD32(a4 + 0x0);  /* 056f */
  if (a10 == 0) goto L_0581;  /* 0571: beqz a10, 581 <esp_mesh_stop+0x449> */
  L_0574: a8 = LD32(a2 + 0x0);  /* 0574 */
  a8 = LD32(a8 + 0x38);  /* 0577 */
  /* 057a: INDIRECT callx a8 <- mem[a8+0x38]; result unknown */ a2 = 0;
  a8 = 0;  /* 057d */
  ST32(a4 + 0x0, a8);  /* 057f */
  L_0581: a4 = (u32)&mesh_ioctl_sem + 0x0;  /* 0581: l32r -> global */
  a10 = LD32(a4 + 0x0);  /* 0584 */
  if (a10 == 0) goto L_0596;  /* 0586: beqz.n a10, 596 <esp_mesh_stop+0x45e> */
  L_0588: a8 = LD32(a2 + 0x0);  /* 0588 */
  a8 = LD32(a8 + 0x38);  /* 058a */
  __asm__ volatile("" ::: "memory");  /* 058c: memw */
  /* 058f: INDIRECT callx a8 <- mem[a8+0x38]; result unknown */ a2 = 0;
  a8 = 0;  /* 0592 */
  ST32(a4 + 0x0, a8);  /* 0594 */
  L_0596: a10 = LD32(a6 + 0x0);  /* 0596 */
  if (a10 == 0) goto L_05a9;  /* 0598: beqz.n a10, 5a9 <esp_mesh_stop+0x471> */
  L_059a: a4 = LD32(a2 + 0x0);  /* 059a */
  a4 = LD32(a4 + 0x50);  /* 059c */
  __asm__ volatile("" ::: "memory");  /* 059f: memw */
  /* 05a2: INDIRECT callx a4 <- mem[a4+0x50]; result unknown */ a2 = 0;
  a4 = 0;  /* 05a5 */
  ST32(a6 + 0x0, a4);  /* 05a7 */
  L_05a9: __asm__ volatile("" ::: "memory");  /* 05a9: memw */
  a8 = (u32)&esp_mesh_get_storage + 0x0;  /* 05ac: l32r -> global */
  a2 = esp_mesh_get_storage(a2, a3, a4, a5, a6);  /* 05af: callx a8 via reloc-expand */
  if (a10 != 0) goto L_05ba;  /* 05b2: bnez.n a10, 5ba <esp_mesh_stop+0x482> */
  L_05b4: a8 = (u32)&esp_mesh_nvs_deinit + 0x0;  /* 05b4: l32r -> global */
  a2 = esp_mesh_nvs_deinit(a2, a3, a4, a5, a6);  /* 05b7: callx a8 via reloc-expand */
  L_05ba: a4 = LD32(a2 + 0x0);  /* 05ba */
  if (a4 == 0) goto L_05e5;  /* 05bc: beqz a4, 5e5 <esp_mesh_stop+0x4ad> */
  L_05bf: a6 = LD32(a4 + 0x150);  /* 05bf */
  if (a6 == 0) goto L_05e5;  /* 05c2: beqz a6, 5e5 <esp_mesh_stop+0x4ad> */
  L_05c5: a10 = LD32(a4 + 0x158);  /* 05c5 */
  a4 = 0x204;  /* 05c8 */
  /* 05cb: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 05ce */
  a10 = 2;  /* 05d0 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 05d2: -> "mesh" */
  a14 = a11;  /* 05d5 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 05d7: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 05da: l32r -> .rodata.esp_mesh_stop.str1.1 */
  ST32(a1 + 0x0, a4);  /* 05dd */
  __asm__ volatile("" ::: "memory");  /* 05df: memw */
  /* 05e2: INDIRECT callx a6 <- mem[a4+0x150]; result unknown */ a2 = 0;
  L_05e5: a11 = a1 + (16);  /* 05e5 */
  a10 = 1;  /* 05e8 */
  a8 = (u32)&esp_wifi_get_config + 0x0;  /* 05ea: l32r -> global */
  a2 = esp_wifi_get_config(a2, a3, a4, a5, a6);  /* 05ed: callx a8 via reloc-expand */
  a8 = a10;  /* 05f0: mov */
  a4 = (u32)&g_mesh_self_map_addr + 0x0;  /* 05f3: l32r -> global */
  a6 = (u32)&g_mesh_ext_cfg + 0x0;  /* 05f6: l32r -> global */
  if (a10 != 0) goto L_065c;  /* 05f9: bnez a10, 65c <esp_mesh_stop+0x524> */
  L_05fc: a11 = a10;  /* 05fc */
  a12 = 32;  /* 05fe */
  a10 = a1 + (16);  /* 0601 */
  ST32(a1 + 0xd0, a8);  /* 0604 */
  __asm__ volatile("" ::: "memory");  /* 0607: memw */
  a8 = (u32)&memset + 0x0;  /* 060a: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 060d: callx a8 (libc, via reloc-expand) */
  a10 = a1 + (16);  /* 0610 */
  a14 = LD8U(a4 + 0x5);  /* 0613 */
  a13 = LD8U(a4 + 0x4);  /* 0616 */
  a12 = LD8U(a4 + 0x3);  /* 0619 */
  a11 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 061c: l32r -> .rodata.esp_mesh_stop.str1.1 */
  a8 = (u32)&sprintf + 0x0;  /* 061f: l32r -> global */
  a2 = sprintf(a2, a3, a4, a5, a6);  /* 0622: callx a8 via reloc-expand */
  a11 = 32;  /* 0625 */
  a10 = a1 + (16);  /* 0627 */
  a8 = (u32)&strnlen + 0x0;  /* 062a: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6);  /* 062d: callx a8 (libc, via reloc-expand) */
  a9 = 100;  /* 0630 */
  a8 = LD32(a1 + 0xd0);  /* 0633 */
  a11 = a1 + (16);  /* 0636 */
  ST16(a1 + 0x7a, a9);  /* 0639 */
  __asm__ volatile("" ::: "memory");  /* 063c: memw */
  a9 = LD8U(a6 + 0x4);  /* 063f */
  ST8(a1 + 0x70, a10);  /* 0642 */
  a10 = 1;  /* 0645 */
  ST8(a1 + 0x78, a8);  /* 0647 */
  ST8(a1 + 0x71, a9);  /* 064a */
  __asm__ volatile("" ::: "memory");  /* 064d: memw */
  ST32(a1 + 0x74, a8);  /* 0650 */
  __asm__ volatile("" ::: "memory");  /* 0653: memw */
  a8 = (u32)&esp_wifi_set_config + 0x0;  /* 0656: l32r -> global */
  a2 = esp_wifi_set_config(a2, a3, a4, a5, a6);  /* 0659: callx a8 via reloc-expand */
  L_065c: a12 = 92;  /* 065c */
  a11 = 0;  /* 065e */
  a10 = (u32)&g_mesh_current_parent + 0x0;  /* 0660: l32r -> global */
  a8 = (u32)&memset + 0x0;  /* 0663: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 0666: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0669 */
  a11 = 0;  /* 066c */
  a10 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 066f: l32r -> global */
  a8 = (u32)&memset + 0x0;  /* 0672: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 0675: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0678 */
  a11 = 0;  /* 067a */
  a10 = a4;  /* 067c */
  a8 = (u32)&memset + 0x0;  /* 067e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 0681: callx a8 (libc, via reloc-expand) */
  a12 = 208;  /* 0684 */
  a11 = 0;  /* 0687 */
  a10 = a6;  /* 0689 */
  a8 = (u32)&memset + 0x0;  /* 068b: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6);  /* 068e: callx a8 (libc, via reloc-expand) */
  a10 = (u32)&g_mesh_ext_cfg + 0xbe;  /* 0691: l32r -> global */
  a8 = (u32)&esp_mesh_set_router_bssid + 0x0;  /* 0694: l32r -> global */
  a2 = esp_mesh_set_router_bssid(a2, a3, a4, a5, a6);  /* 0697: callx a8 via reloc-expand */
  a12 = 0x222;  /* 069a */
  a11 = a3;  /* 069d */
  a4 = (u32)&s_mesh_stop_mutex + 0x0;  /* 069f: l32r -> global */
  a10 = LD32(a4 + 0x0);  /* 06a2 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 06a4: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6);  /* 06a7: callx a8 via reloc-expand */
  a10 = LD32(a5 + 0x0);  /* 06aa */
  if (a10 == 0) goto L_06ba;  /* 06ac: beqz.n a10, 6ba <esp_mesh_stop+0x582> */
  L_06ae: a6 = LD32(a2 + 0x0);  /* 06ae */
  a6 = LD32(a6 + 0x80);  /* 06b0 */
  /* 06b3: INDIRECT callx a6 <- mem[a6+0x80]; result unknown */ a2 = 0;
  a6 = 0;  /* 06b6 */
  ST32(a5 + 0x0, a6);  /* 06b8 */
  L_06ba: a11 = a3;  /* 06ba */
  a12 = 0x227;  /* 06bc */
  a5 = 0;  /* 06bf */
  a10 = LD32(a4 + 0x0);  /* 06c1 */
  __asm__ volatile("" ::: "memory");  /* 06c3: memw */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 06c6: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6);  /* 06c9: callx a8 via reloc-expand */
  a11 = a3;  /* 06cc */
  a12 = 0x22a;  /* 06ce */
  a4 = (u32)&LOCAL__bss_s_mesh_group_addr + 0x0;  /* 06d1: l32r -> .bss.s_mesh_group_addr (same-object static) */
  a10 = LD32(a4 + 0x4);  /* 06d4 */
  ST32(a4 + 0x0, a5);  /* 06d6 */
  __asm__ volatile("" ::: "memory");  /* 06d8: memw */
  a8 = (u32)&mesh_free + 0x0;  /* 06db: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6);  /* 06de: callx a8 via reloc-expand */
  a3 = LD32(a7 + 0x0);  /* 06e1 */
  ST32(a4 + 0x4, a5);  /* 06e3 */
  if (a3 < 3u) goto L_070e;  /* 06e5: bltui a3, 3, 70e <esp_mesh_stop+0x5d6> */
  L_06e8: a2 = LD32(a2 + 0x0);  /* 06e8 */
  if (a2 == a5) goto L_070e;  /* 06ea: beq a2, a5, 70e <esp_mesh_stop+0x5d6> */
  L_06ed: a3 = LD32(a2 + 0x150);  /* 06ed */
  if (a3 == a5) goto L_070e;  /* 06f0: beq a3, a5, 70e <esp_mesh_stop+0x5d6> */
  L_06f3: a10 = LD32(a2 + 0x158);  /* 06f3 */
  __asm__ volatile("" ::: "memory");  /* 06f6: memw */
  /* 06f9: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 06fc */
  a15 = 0x22d;  /* 06fe */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0701: -> "mesh" */
  a10 = 3;  /* 0704 */
  a14 = a11;  /* 0706 */
  a12 = (u32)(RODATA__rodata_esp_mesh_stop_str1_1 + 0x0);  /* 0708: l32r -> .rodata.esp_mesh_stop.str1.1 */
  /* 070b: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_070e: a12 = 0;  /* 070e */
  a11 = a12;  /* 0710 */
  a10 = 1;  /* 0712 */
  a8 = (u32)&esp_mesh_send_event_internal + 0x0;  /* 0714: l32r -> global */
  a2 = esp_mesh_send_event_internal(a2, a3, a4, a5, a6);  /* 0717: callx a8 via reloc-expand */
  a2 = 0;  /* 071a */
  L_071c: return a2;  /* 071c: retw.n */
}


/* esp_mesh_switch_channel @ mesh.o 00000034 size 244B bind GLOBAL
 * Calls: memset, esp_mesh_is_nwk_inited, mesh_switch_channel, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[4]: mem[a4+0x158]; mem[a3+0x158]; mem[a3+0x150]; mem[a2+0xa4] | Data refs: g_mesh_is_root, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.esp_mesh_set_config.str1.1, .rodata.esp_mesh_switch_channel.str1.1
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=11); reloc-direct=5, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_switch_channel(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  float F9;
  /* 0034: entry a1, 64 (frame 64 bytes) */
  a5 = a2;  /* 0037 */
  a2 = (u32)&g_mesh_is_root + 0x0;  /* 0039: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 003c: memw */
  a8 = LD8U(a2 + 0x0);  /* 003f */
  a8 = (a8 >> 8) & 0x1;  /* 0042: extui width 1 */
  a2 = 0x00004006u;  /* 0045: l32r = 16390 */
  if (a8 == 0) goto L_0126;  /* 0048: beqz a8, 126 <esp_mesh_switch_channel+0xf2> */
  L_004b: a8 = a3 + (-1);  /* 004b */
  a2 = 13;  /* 004d */
  if (a2 >= a8) goto L_0084;  /* 004f: bgeu a2, a8, 84 <esp_mesh_switch_channel+0x50> */
  L_0052: a2 = (u32)&g_log_level + 0x0;  /* 0052: l32r -> global */
  a4 = LD32(a2 + 0x0);  /* 0055 */
  a2 = 0x00004008u;  /* 0057: l32r = 16392 */
  if (a4 >= 3u) goto L_0060;  /* 005a: bgeui a4, 3, 60 <esp_mesh_switch_channel+0x2c> */
  L_005d: goto L_0126;  /* 005d: j */
  L_0060: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0060: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0063 */
  if (a4 == 0) goto L_0126;  /* 0065: beqz a4, 126 <esp_mesh_switch_channel+0xf2> */
  L_0068: a5 = LD32(a4 + 0x150);  /* 0068 */
  if (a5 == 0) goto L_0126;  /* 006b: beqz a5, 126 <esp_mesh_switch_channel+0xf2> */
  L_006e: a10 = LD32(a4 + 0x158);  /* 006e */
  /* 0071: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a15 = a3;  /* 0074 */
  a13 = a10;  /* 0076 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0078: -> "mesh" */
  a14 = a11;  /* 007b */
  a12 = (u32)(RODATA__rodata_esp_mesh_set_config_str1_1 + 0x0);  /* 007d: l32r -> .rodata.esp_mesh_set_config.str1.1 */
  goto L_00b6;  /* 0080: j */
  L_0084: if ((i32)a4 >= 0) goto L_00c1;  /* 0084: bgez a4, c1 <esp_mesh_switch_channel+0x8d> */
  L_0087: a2 = (u32)&g_log_level + 0x0;  /* 0087: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 008a */
  a2 = 0x00004008u;  /* 008c: l32r = 16392 */
  if (a3 >= 3u) goto L_0095;  /* 008f: bgeui a3, 3, 95 <esp_mesh_switch_channel+0x61> */
  L_0092: goto L_0126;  /* 0092: j */
  L_0095: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0095: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0098 */
  if (a3 == 0) goto L_0126;  /* 009a: beqz a3, 126 <esp_mesh_switch_channel+0xf2> */
  L_009d: a5 = LD32(a3 + 0x150);  /* 009d */
  if (a5 == 0) goto L_0126;  /* 00a0: beqz a5, 126 <esp_mesh_switch_channel+0xf2> */
  L_00a3: a10 = LD32(a3 + 0x158);  /* 00a3 */
  /* 00a6: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a15 = a4;  /* 00a9 */
  a13 = a10;  /* 00ab */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00ad: -> "mesh" */
  a14 = a11;  /* 00b0: mov */
  a12 = (u32)(RODATA__rodata_esp_mesh_switch_channel_str1_1 + 0x0);  /* 00b3: l32r -> .rodata.esp_mesh_switch_channel.str1.1 */
  L_00b6: a10 = 3;  /* 00b6 */
  /* 00b9: INDIRECT callx a5 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0126;  /* 00bc: j */
  L_00c1: a12 = 20;  /* 00c1 */
  a11 = 0;  /* 00c3 */
  a10 = a1;  /* 00c5 */
  a8 = (u32)&memset + 0x0;  /* 00c7: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00ca: callx a8 (libc, via reloc-expand) */
  ST32(a1 + 0x14, a5);  /* 00cd */
  ST8(a1 + 0x18, a3);  /* 00cf */
  __asm__ volatile("" ::: "memory");  /* 00d2: memw */
  if (a4 != 0) goto L_00d9;  /* 00d5: bnez.n a4, d9 <esp_mesh_switch_channel+0xa5> */
  L_00d7: a4 = 15;  /* 00d7 */
  L_00d9: ST8(a1 + 0x19, a4);  /* 00d9 */
  __asm__ volatile("" ::: "memory");  /* 00dc: memw */
  __asm__ volatile("" ::: "memory");  /* 00df: memw */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 00e2: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 00e5: callx a8 via reloc-expand */
  if (a10 != 0) goto L_00f9;  /* 00e8: bnez.n a10, f9 <esp_mesh_switch_channel+0xc5> */
  L_00ea: a10 = a1 + (20);  /* 00ea */
  a8 = (u32)&mesh_switch_channel + 0x0;  /* 00ed: l32r -> global */
  a2 = mesh_switch_channel(a2, a3, a4, a5, a6, a7);  /* 00f0: callx a8 via reloc-expand */
  goto L_0124;  /* 00f3: j */
  L_00f9: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00f9: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00fc */
  a10 = LD32(a2 + 0xa4);  /* 00fe */
  /* 0101: INDIRECT callx a10 <- mem[a2+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 0104: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 0107: callx a8 via reloc-expand */
  if (a10 != 0) goto L_00ea;  /* 010a: bnez a10, ea <esp_mesh_switch_channel+0xb6> */
  L_010d: a2 = 10;  /* 010d */
  a3 = LD32(a1 + 0x14);  /* 010f */
  a10 = a1;  /* 0111 */
  ST32(a1 + 0x0, a2);  /* 0113 */
  a2 = LD32(a1 + 0x18);  /* 0115 */
  ST32(a1 + 0x4, a3);  /* 0117 */
  ST32(a1 + 0x8, a2);  /* 0119 */
  __asm__ volatile("" ::: "memory");  /* 011b: memw */
  a8 = (u32)&mesh_set_io_process + 0x0;  /* 011e: l32r -> global */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 0121: callx a8 via reloc-expand */
  L_0124: a2 = a10;  /* 0124 */
  L_0126: return a2;  /* 0126: retw.n */
}


/* esp_mesh_waive_root @ mesh.o 00000028 size 128B bind GLOBAL
 * Calls: mesh_waive_root | Data refs: g_mesh_is_root, g_mesh_ext_vote_state, g_mesh_cfg_vote_percent
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_waive_root(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  float F0, F1;
  u32 BOOL_b0; /* boolean special-regs (FP compare results) */
  /* 0028: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_mesh_is_root + 0x0;  /* 002b: l32r -> global */
  a11 = a2;  /* 002e */
  a10 = a3;  /* 0030 */
  __asm__ volatile("" ::: "memory");  /* 0032: memw */
  a9 = LD8U(a8 + 0x0);  /* 0035 */
  a9 = (a9 >> 8) & 0x1;  /* 0038: extui width 1 */
  a2 = 0x00004006u;  /* 003b: l32r = 16390 */
  if (a9 == 0) goto L_00a6;  /* 003e: beqz a9, a6 <esp_mesh_waive_root+0x7e> */
  L_0041: a9 = 5;  /* 0041 */
  a8 = (u32)&g_mesh_ext_vote_state + 0x0;  /* 0043: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0046 */
  a9 = a9 & a8;  /* 0048 */
  a2 = 0x00004016u;  /* 004b: l32r = 16406 */
  if (a9 != 4) goto L_00a6;  /* 004e: bnei a9, 4, a6 <esp_mesh_waive_root+0x7e> */
  L_0051: if (a11 != 0) goto L_005d;  /* 0051: bnez a11, 5d <esp_mesh_waive_root+0x35> */
  L_0054: if (a10 != 1) goto L_006c;  /* 0054: bnei a10, 1, 6c <esp_mesh_waive_root+0x44> */
  L_0057: goto L_009c;  /* 0057: j */
  L_005d: a2 = 0x00000000u;  /* 005d: l32r = 0 */
  F1 = u2f(a2);  /* 0060: wfr (bitcast u32->float) */
  F0 = LD32F(a11 + 0x0);  /* 0063: lsi */
  BOOL_b0 = (F0 <= F1);  /* 0066: ole.s (false if unordered/NaN) */
  if (!BOOL_b0) goto L_0074;  /* 0069: bf b0, 74 <esp_mesh_waive_root+0x4c> (boolean reg) */
  L_006c: a2 = 0x00004008u;  /* 006c: l32r = 16392 */
  goto L_00a6;  /* 006f: j */
  L_0074: a2 = 0x3f800000u;  /* 0074: l32r = 1065353216 */
  F1 = u2f(a2);  /* 0077: wfr (bitcast u32->float) */
  BOOL_b0 = (F1 < F0);  /* 007a: olt.s (false if unordered/NaN) */
  if (BOOL_b0) goto L_006c;  /* 007d: bt b0, 6c <esp_mesh_waive_root+0x44> (boolean reg) */
  a8 = (u32)&g_mesh_cfg_vote_percent + 0x0;  /* 0080: l32r -> global */
  a9 = LD8U(a11 + 0x4);  /* 0083 */
  ST32F(a8 + 0x0, F0);  /* 0086: ssi */
  a2 = 0x00004005u;  /* 0089: l32r = 16389 */
  if (a9 != 0) goto L_00a6;  /* 008c: bnez.n a9, a6 <esp_mesh_waive_root+0x7e> */
  L_008e: a9 = 14;  /* 008e */
  a8 = LD32(a11 + 0x8);  /* 0090 */
  if ((i32)a9 < (i32)a8) goto L_0054;  /* 0092: blt a9, a8, 54 <esp_mesh_waive_root+0x2c> */
  L_0095: __asm__ volatile("" ::: "memory");  /* 0095: memw */
  goto L_006c;  /* 0098: j */
  L_009c: a12 = a10;  /* 009c */
  a8 = (u32)&mesh_waive_root;  /* 009e: l32r -> func addr */
  a2 = mesh_waive_root(a2, a3, a4, a5, a6, a7);  /* 00a1: callx a8 via reloc-expand */
  a2 = a10;  /* 00a4 */
  L_00a6: return a2;  /* 00a6: retw.n */
}


/* mesh_add_option @ mesh.o 00000020 size 252B bind GLOBAL
 * Calls: memcpy | indirect[3]: mem[a2+0x158]; mem[a2+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_add_option(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0052;  /* 0023: bnez.n a2, 52 <mesh_add_option+0x32> */
  L_0025: a2 = (u32)&g_log_level + 0x0;  /* 0025: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0028 */
  a5 = 0x00004008u;  /* 002b: l32r = 16392 */
  if (a2 >= 3u) goto L_0034;  /* 002e: bgeui a2, 3, 34 <mesh_add_option+0x14> */
  L_0031: goto L_0118;  /* 0031: j */
  L_0034: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0034: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0037 */
  if (a2 == 0) goto L_0118;  /* 003a: beqz a2, 118 <mesh_add_option+0xf8> */
  L_003d: a3 = LD32(a2 + 0x150);  /* 003d */
  if (a3 == 0) goto L_0118;  /* 0040: beqz a3, 118 <mesh_add_option+0xf8> */
  L_0043: a10 = LD32(a2 + 0x158);  /* 0043 */
  a2 = 0x26b;  /* 0046 */
  /* 0049: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 004c: -> "mesh" */
  goto L_007c;  /* 004f: j */
  L_0052: if (a4 != 0) goto L_0094;  /* 0052: bnez.n a4, 94 <mesh_add_option+0x74> */
  L_0054: a2 = (u32)&g_log_level + 0x0;  /* 0054: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0057 */
  a5 = 0x00004008u;  /* 0059: l32r = 16392 */
  if (a2 >= 3u) goto L_0062;  /* 005c: bgeui a2, 3, 62 <mesh_add_option+0x42> */
  L_005f: goto L_0118;  /* 005f: j */
  L_0062: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0062: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0065 */
  if (a2 == 0) goto L_0118;  /* 0067: beqz a2, 118 <mesh_add_option+0xf8> */
  L_006a: a3 = LD32(a2 + 0x150);  /* 006a */
  if (a3 == 0) goto L_0118;  /* 006d: beqz a3, 118 <mesh_add_option+0xf8> */
  L_0070: a10 = LD32(a2 + 0x158);  /* 0070 */
  a2 = 0x26c;  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0079: -> "mesh" */
  L_007c: a13 = a10;  /* 007c */
  a14 = a11;  /* 007e */
  a10 = 3;  /* 0080 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0082: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0085: -> "mesh" */
  ST32(a1 + 0x0, a2);  /* 0088 */
  __asm__ volatile("" ::: "memory");  /* 008a: memw */
  /* 008d: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0118;  /* 0090: j */
  L_0094: a5 = -1;  /* 0094 */
  if (a3 == 0) goto L_0118;  /* 0096: beqz a3, 118 <mesh_add_option+0xf8> */
  L_0099: a8 = 0;  /* 0099 */
  a7 = a8;  /* 009b */
  goto L_010a;  /* 009d: j */
  L_00a0: a5 = a2;  /* 00a0 */
  a9 = LD8U(a5 + 0x0);  /* 00a2 */
  a2 = a2 + (7);  /* 00a5 */
  a6 = a9 + (-1);  /* 00a7 */
  if (a6 >= 8u) goto L_0115;  /* 00a9: bgeui a6, 8, 115 <mesh_add_option+0xf5> */
  L_00ac: a6 = a4 + a8;  /* 00ac */
  a10 = LD8U(a5 + 0x1);  /* 00ae */
  a7 = a7 + (1);  /* 00b1 */
  ST8(a6 + 0x0, a9);  /* 00b3 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  a9 = LD8U(a5 + 0x2);  /* 00b9 */
  ST8(a6 + 0x1, a10);  /* 00bc */
  ST8(a6 + 0x2, a9);  /* 00bf */
  __asm__ volatile("" ::: "memory");  /* 00c2: memw */
  a6 = a8 + (3);  /* 00c5 */
  a9 = LD8U(a5 + 0x4);  /* 00c7 */
  a9 = a9 << 8;  /* 00ca */
  a8 = LD8U(a5 + 0x3);  /* 00cd */
  a9 = a9 | a8;  /* 00d0 */
  a8 = LD8U(a5 + 0x5);  /* 00d3 */
  a8 = a8 << 16;  /* 00d6 */
  a8 = a8 | a9;  /* 00d9 */
  a10 = LD8U(a5 + 0x2);  /* 00dc */
  a10 = a10 << 8;  /* 00df */
  a11 = LD8U(a5 + 0x6);  /* 00e2 */
  a11 = a11 << 24;  /* 00e5 */
  a11 = a11 | a8;  /* 00e8 */
  a12 = LD8U(a5 + 0x1);  /* 00eb */
  a12 = a10 | a12;  /* 00ee */
  a10 = a4 + a6;  /* 00f1 */
  __asm__ volatile("" ::: "memory");  /* 00f3: memw */
  a8 = (u32)&memcpy + 0x0;  /* 00f6: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00f9: callx a8 (libc, via reloc-expand) */
  a8 = LD8U(a5 + 0x1);  /* 00fc */
  a5 = LD8U(a5 + 0x2);  /* 00ff */
  a5 = a5 << 8;  /* 0102 */
  a5 = a5 | a8;  /* 0105 */
  a8 = a5 + a6;  /* 0108 */
  L_010a: if ((i32)a7 < (i32)a3) goto L_00a0;  /* 010a: blt a7, a3, a0 <mesh_add_option+0x80> */
  L_010d: a5 = 0;  /* 010d */
  goto L_0118;  /* 010f: j */
  L_0115: a5 = 0x00004011u;  /* 0115: l32r = 16401 */
  L_0118: a2 = a5;  /* 0118 */
  return a2;  /* 011a: retw.n */
}


/* mesh_chain_header_add_ttl @ mesh.o 0000000c size 78B bind GLOBAL
 * Calls: none | Data refs: g_mesh_max_layer, .bss.option$10, .bss.value$11
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_chain_header_add_ttl(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a9 = (a2 >> 16) & 0x1;  /* 000f: extui width 1 */
  a2 = (u32)&g_mesh_max_layer + 0x0;  /* 0012: l32r -> global */
  a8 = LD16U(a2 + 0x0);  /* 0015 */
  a2 = 0;  /* 0018 */
  a8 = a8 + a8;  /* 001a */
  if ((i32)a9 >= (i32)a8) goto L_0055;  /* 001c: bge a9, a8, 55 <mesh_chain_header_add_ttl+0x49> */
  L_001f: a10 = 2;  /* 001f */
  a2 = (u32)&LOCAL__bss_option_10 + 0x0;  /* 0021: l32r -> .bss.option$10 (same-object static) */
  a8 = (u32)&LOCAL__bss_value_11 + 0x0;  /* 0024: l32r -> .bss.value$11 (same-object static) */
  ST8(a2 + 0x1, a10);  /* 0027 */
  a10 = 0;  /* 002a */
  ST8(a8 + 0x0, a9);  /* 002c */
  a9 = a9 >> 8;  /* 002f */
  ST8(a2 + 0x2, a10);  /* 0032 */
  a10 = (a8 >> 8) & 0x1ff;  /* 0035: extui width 9 */
  ST8(a8 + 0x1, a9);  /* 0038 */
  a9 = 6;  /* 003b */
  ST8(a2 + 0x3, a8);  /* 003d */
  ST8(a2 + 0x4, a10);  /* 0040 */
  a10 = (a8 >> 8) & 0x1ffff;  /* 0043: extui width 17 */
  a8 = (a8 >> 8) & 0x1ffffff;  /* 0046: extui width 25 */
  ST8(a2 + 0x0, a9);  /* 0049 */
  ST8(a2 + 0x5, a10);  /* 004c */
  ST8(a2 + 0x6, a8);  /* 004f */
  __asm__ volatile("" ::: "memory");  /* 0052: memw */
  L_0055: __asm__ volatile("" ::: "memory");  /* 0055: memw */
  return a2;  /* 0058: retw.n */
}


/* mesh_encrypt_ie_plain_key @ mesh.o 00000034 size 230B bind GLOBAL
 * Calls: memset, snprintf, strnlen, esp_mesh_set_ie_crypto_key_internal | indirect[4]: mem[a3+0x158]; mem[a3+0x150]; mem[a3+0xc] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.mesh_encrypt_ie_plain_key.str1.1, wpa_crypto_funcs, .bss.s_mesh_ext_crypto_config
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=10); reloc-direct=4, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_encrypt_ie_plain_key(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0034: entry a1, 80 (frame 80 bytes) */
  if (a2 != 0) goto L_0066;  /* 0037: bnez.n a2, 66 <mesh_encrypt_ie_plain_key+0x32> */
  L_0039: a2 = (u32)&g_log_level + 0x0;  /* 0039: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 003c */
  a2 = 0x00004008u;  /* 003f: l32r = 16392 */
  if (a3 >= 3u) goto L_0048;  /* 0042: bgeui a3, 3, 48 <mesh_encrypt_ie_plain_key+0x14> */
  L_0045: goto L_0118;  /* 0045: j */
  L_0048: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0048: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 004b */
  if (a3 == 0) goto L_0118;  /* 004e: beqz a3, 118 <mesh_encrypt_ie_plain_key+0xe4> */
  L_0051: a4 = LD32(a3 + 0x150);  /* 0051 */
  if (a4 == 0) goto L_0118;  /* 0054: beqz a4, 118 <mesh_encrypt_ie_plain_key+0xe4> */
  L_0057: a10 = LD32(a3 + 0x158);  /* 0057 */
  a3 = 0x5da;  /* 005a */
  /* 005d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0060: -> "mesh" */
  goto L_0090;  /* 0063: j */
  L_0066: if (a3 != 0) goto L_00a8;  /* 0066: bnez.n a3, a8 <mesh_encrypt_ie_plain_key+0x74> */
  L_0068: a2 = (u32)&g_log_level + 0x0;  /* 0068: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 006b */
  a2 = 0x00004008u;  /* 006d: l32r = 16392 */
  if (a3 >= 3u) goto L_0076;  /* 0070: bgeui a3, 3, 76 <mesh_encrypt_ie_plain_key+0x42> */
  L_0073: goto L_0118;  /* 0073: j */
  L_0076: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0076: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0079 */
  if (a3 == 0) goto L_0118;  /* 007b: beqz a3, 118 <mesh_encrypt_ie_plain_key+0xe4> */
  L_007e: a4 = LD32(a3 + 0x150);  /* 007e */
  if (a4 == 0) goto L_0118;  /* 0081: beqz a4, 118 <mesh_encrypt_ie_plain_key+0xe4> */
  L_0084: a10 = LD32(a3 + 0x158);  /* 0084 */
  a3 = 0x5db;  /* 0087 */
  /* 008a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 008d: -> "mesh" */
  L_0090: a13 = a10;  /* 0090 */
  a14 = a11;  /* 0092 */
  a10 = 3;  /* 0094 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0096: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0099: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 009c */
  __asm__ volatile("" ::: "memory");  /* 009e: memw */
  /* 00a1: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0118;  /* 00a4: j */
  L_00a8: a11 = 0;  /* 00a8 */
  a12 = 14;  /* 00aa */
  a10 = a1 + (20);  /* 00ac */
  ST32(a1 + 0x10, a11);  /* 00af */
  __asm__ volatile("" ::: "memory");  /* 00b1: memw */
  a8 = (u32)&memset + 0x0;  /* 00b4: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00b7: callx a8 (libc, via reloc-expand) */
  a11 = 18;  /* 00ba */
  a10 = a1 + (16);  /* 00bc */
  a4 = LD8U(a3 + 0x5);  /* 00bf */
  ST32(a1 + 0x8, a4);  /* 00c2 */
  a4 = LD8U(a3 + 0x4);  /* 00c4 */
  ST32(a1 + 0x4, a4);  /* 00c7 */
  a4 = LD8U(a3 + 0x3);  /* 00c9 */
  ST32(a1 + 0x0, a4);  /* 00cc */
  a15 = LD8U(a3 + 0x2);  /* 00cf */
  a14 = LD8U(a3 + 0x1);  /* 00d2 */
  a13 = LD8U(a3 + 0x0);  /* 00d5 */
  a12 = (u32)(RODATA__rodata_mesh_encrypt_ie_plain_key_str1_1 + 0x0);  /* 00d8: l32r -> .rodata.mesh_encrypt_ie_plain_key.str1.1 */
  __asm__ volatile("" ::: "memory");  /* 00db: memw */
  a8 = (u32)&snprintf + 0x0;  /* 00de: l32r -> global */
  a2 = snprintf(a2, a3, a4, a5, a6, a7);  /* 00e1: callx a8 via reloc-expand */
  a3 = (u32)&wpa_crypto_funcs + 0x0;  /* 00e4: l32r -> global */
  a4 = LD32(a3 + 0xc);  /* 00e7 */
  a3 = (u32)&LOCAL__bss_s_mesh_ext_crypto_config + 0x0;  /* 00e9: l32r -> .bss.s_mesh_ext_crypto_config (same-object static) */
  if (a4 == 0) goto L_010c;  /* 00ec: beqz.n a4, 10c <mesh_encrypt_ie_plain_key+0xd8> */
  L_00ee: a11 = 18;  /* 00ee */
  a10 = a1 + (16);  /* 00f0 */
  a8 = (u32)&strnlen + 0x0;  /* 00f3: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 00f6: callx a8 (libc, via reloc-expand) */
  a13 = 1;  /* 00f9 */
  a12 = a10;  /* 00fb */
  a15 = 32;  /* 00fd */
  a14 = a3;  /* 00ff */
  a13 = a13 << 12;  /* 0101 */
  a11 = a1 + (16);  /* 0104 */
  a10 = a2;  /* 0107 */
  /* 0109: INDIRECT callx a4 <- mem[a3+0xc]; result unknown */ a2 = 0;
  L_010c: a11 = 32;  /* 010c */
  a10 = a3;  /* 010e */
  a8 = (u32)&esp_mesh_set_ie_crypto_key_internal + 0x0;  /* 0110: l32r -> global */
  a2 = esp_mesh_set_ie_crypto_key_internal(a2, a3, a4, a5, a6, a7);  /* 0113: callx a8 via reloc-expand */
  a2 = a10;  /* 0116 */
  L_0118: return a2;  /* 0118: retw.n */
}


/* mesh_parse_option @ mesh.o 00000020 size 248B bind GLOBAL
 * Calls: none | indirect[3]: mem[a2+0x158]; mem[a2+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.mesh_parse_option
 * Fidelity: low - tri-indirect dispatch via g_osi_funcs_p slots 0x150/0x158 with NULL-arg log guards (g_log_level>=3, code 0x4008); exact guard/dispatch shape verified, no direct calls - need osi_funcs slot naming (RX-pending/log callbacks) to raise
 * Edges: funcdb-v3 (calls=0, refs=4); reloc-direct=0, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_parse_option(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F4;
  /* 0020: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0052;  /* 0023: bnez.n a2, 52 <mesh_parse_option+0x32> */
  L_0025: a2 = (u32)&g_log_level + 0x0;  /* 0025: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0028 */
  a5 = 0x00004008u;  /* 002b: l32r = 16392 */
  if (a2 >= 3u) goto L_0034;  /* 002e: bgeui a2, 3, 34 <mesh_parse_option+0x14> */
  L_0031: goto L_0114;  /* 0031: j */
  L_0034: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0034: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0037 */
  if (a2 == 0) goto L_0114;  /* 003a: beqz a2, 114 <mesh_parse_option+0xf4> */
  L_003d: a3 = LD32(a2 + 0x150);  /* 003d */
  if (a3 == 0) goto L_0114;  /* 0040: beqz a3, 114 <mesh_parse_option+0xf4> */
  L_0043: a10 = LD32(a2 + 0x158);  /* 0043 */
  a2 = 0x236;  /* 0046 */
  /* 0049: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 004c: -> "mesh" */
  goto L_007c;  /* 004f: j */
  L_0052: if (a4 != 0) goto L_0094;  /* 0052: bnez.n a4, 94 <mesh_parse_option+0x74> */
  L_0054: a2 = (u32)&g_log_level + 0x0;  /* 0054: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0057 */
  a5 = 0x00004008u;  /* 0059: l32r = 16392 */
  if (a2 >= 3u) goto L_0062;  /* 005c: bgeui a2, 3, 62 <mesh_parse_option+0x42> */
  L_005f: goto L_0114;  /* 005f: j */
  L_0062: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0062: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0065 */
  if (a2 == 0) goto L_0114;  /* 0067: beqz a2, 114 <mesh_parse_option+0xf4> */
  L_006a: a3 = LD32(a2 + 0x150);  /* 006a */
  if (a3 == 0) goto L_0114;  /* 006d: beqz a3, 114 <mesh_parse_option+0xf4> */
  L_0070: a10 = LD32(a2 + 0x158);  /* 0070 */
  a2 = 0x237;  /* 0073 */
  /* 0076: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0079: -> "mesh" */
  L_007c: a13 = a10;  /* 007c */
  a14 = a11;  /* 007e */
  a10 = 3;  /* 0080 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0082: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0085: -> "mesh" */
  ST32(a1 + 0x0, a2);  /* 0088 */
  __asm__ volatile("" ::: "memory");  /* 008a: memw */
  /* 008d: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0114;  /* 0090: j */
  L_0094: a5 = -1;  /* 0094 */
  if (a3 == 0) goto L_0114;  /* 0096: beqz a3, 114 <mesh_parse_option+0xf4> */
  L_0099: a9 = 0;  /* 0099 */
  a11 = (u32)(RODATA__rodata_mesh_parse_option + 0x0);  /* 009b: l32r -> .rodata.mesh_parse_option */
  a10 = a9;  /* 009e */
  a12 = -154;  /* 00a0 */
  a13 = 24;  /* 00a3 */
  goto L_0102;  /* 00a5: j */
  L_00a8: a5 = LD8U(a2 + 0x0);  /* 00a8 */
  a5 = a5 + (-1);  /* 00ab */
  a5 = (a5 >> 8) & 0x1;  /* 00ad: extui width 1 */
  if (a5 >= 8u) goto L_0111;  /* 00b0: bgeui a5, 8, 111 <mesh_parse_option+0xf1> */
  L_00b3: a5 = a5 + (a11 << 2);  /* 00b3 */
  a14 = LD32(a5 + 0x0);  /* 00b6 */
  a8 = LD8U(a2 + 0x2);  /* 00b8 */
  a5 = LD8U(a2 + 0x1);  /* 00bb */
  /* 00be: jx a14 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a14 = a8 << 8;  /* 00c3 */
  a14 = a14 | a5;  /* 00c6 */
  if (a14 == 8) goto L_00f4;  /* 00c9: beqi a14, 8, f4 <mesh_parse_option+0xd4> */
  L_00cc: goto L_0111;  /* 00cc: j */
  a14 = a8 << 8;  /* 00cf */
  a14 = a14 | a5;  /* 00d2 */
  if (a14 == a13) goto L_00f4;  /* 00d5: beq a14, a13, f4 <mesh_parse_option+0xd4> */
  L_00d8: goto L_0111;  /* 00d8: j */
  a14 = a8 << 8;  /* 00db */
  a14 = a14 | a5;  /* 00de */
  a15 = a14 + a12;  /* 00e1 */
  if (a15 == 0) goto L_00f4;  /* 00e3: beqz.n a15, f4 <mesh_parse_option+0xd4> */
  L_00e5: if (a14 == 12) goto L_00f4;  /* 00e5: beqi a14, 12, f4 <mesh_parse_option+0xd4> */
  L_00e8: goto L_0111;  /* 00e8: j */
  a14 = a8 << 8;  /* 00eb */
  a14 = a14 | a5;  /* 00ee */
  if (a14 != 5) goto L_0111;  /* 00f1: bnei a14, 5, 111 <mesh_parse_option+0xf1> */
  L_00f4: a8 = a8 << 8;  /* 00f4 */
  a8 = a8 | a5;  /* 00f7 */
  a8 = a8 + (3);  /* 00fa */
  a9 = a9 + a8;  /* 00fc */
  a10 = a10 + (1);  /* 00fe */
  a2 = a2 + (7);  /* 0100 */
  L_0102: if ((i32)a10 < (i32)a3) goto L_00a8;  /* 0102: blt a10, a3, a8 <mesh_parse_option+0x88> */
  L_0105: ST32(a4 + 0x0, a9);  /* 0105 */
  a5 = 0;  /* 0107 */
  __asm__ volatile("" ::: "memory");  /* 0109: memw */
  goto L_0114;  /* 010c: j */
  L_0111: a5 = 0x00004011u;  /* 0111: l32r = 16401 */
  L_0114: a2 = a5;  /* 0114 */
  return a2;  /* 0116: retw.n */
}


/* mesh_recv @ mesh.o 00000088 size 860B bind GLOBAL
 * Calls: mesh_mutex_lock, mesh_mutex_unlock, esp_mesh_txupQ_pending, memcpy, mesh_recv_process_flag, mesh_recv_add_option, esp_mesh_discard_context, esp_mesh_free_context | indirect[7]: mem[a3+0x158]; mem[a3+0x150]; mem[a7+0xa0]; mem[a7+0x74] | Data refs: mesh_tcpip_mbox, mesh_myself_mbox, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.__func__$7, s_mesh_stop_mutex, g_mesh_stop_event_group, .bss.s_extra_toDS_qsize, .bss.s_extra_toSelf_qsize, g_mesh_topology
 * Fidelity: medium - 7 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=8, refs=19); reloc-direct=8, funcdb-attributed=0, unknown-indirect=7 */
u32 mesh_recv(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0000001;
  /* 0088: entry a1, 80 (frame 80 bytes) */
  a9 = a4;  /* 008b */
  a4 = 0;  /* 008d */
  ST32(a1 + 0x24, a7);  /* 008f */
  ST32(a1 + 0x28, a2);  /* 0091 */
  ST32(a1 + 0x10, a4);  /* 0093 */
  if (a6 == a4) goto L_009c;  /* 0096: beq a6, a4, 9c <mesh_recv+0x14> */
  L_0099: ST32(a6 + 0x0, a4);  /* 0099 */
  L_009c: a7 = (u32)&mesh_tcpip_mbox + 0x0;  /* 009c: l32r -> global */
  if (a3 != 0) goto L_00a4;  /* 009f: bnez.n a3, a4 <mesh_recv+0x1c> */
  L_00a1: a7 = (u32)&mesh_myself_mbox + 0x0;  /* 00a1: l32r -> global */
  L_00a4: a4 = LD32(a7 + 0x0);  /* 00a4 */
  if (a4 != 0) goto L_00ed;  /* 00a6: bnez a4, ed <mesh_recv+0x65> */
  L_00a9: a2 = (u32)&g_log_level + 0x0;  /* 00a9: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 00ac */
  a2 = 0x00004008u;  /* 00ae: l32r = 16392 */
  if (a3 >= 3u) goto L_00b7;  /* 00b1: bgeui a3, 3, b7 <mesh_recv+0x2f> */
  L_00b4: goto L_03e2;  /* 00b4: j */
  L_00b7: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00b7: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00ba */
  if (a3 == 0) goto L_03e2;  /* 00bc: beqz a3, 3e2 <mesh_recv+0x35a> */
  L_00bf: a4 = LD32(a3 + 0x150);  /* 00bf */
  if (a4 == 0) goto L_03e2;  /* 00c2: beqz a4, 3e2 <mesh_recv+0x35a> */
  L_00c5: a10 = LD32(a3 + 0x158);  /* 00c5 */
  a3 = 0x51f;  /* 00c8 */
  __asm__ volatile("" ::: "memory");  /* 00cb: memw */
  /* 00ce: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00d1 */
  a10 = 3;  /* 00d3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00d5: -> "mesh" */
  a14 = a11;  /* 00d8 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00da: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00dd: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 00e0 */
  __asm__ volatile("" ::: "memory");  /* 00e2: memw */
  /* 00e5: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_03e2;  /* 00e8: j */
  L_00ed: a8 = LD8U(a7 + 0x8);  /* 00ed */
  a10 = 2;  /* 00f0 */
  a8 = a8 | a10;  /* 00f2 */
  a10 = a5;  /* 00f5 */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00f7: l32r -> global */
  ST8(a7 + 0x8, a8);  /* 00fa */
  __asm__ volatile("" ::: "memory");  /* 00fd: memw */
  a7 = LD32(a2 + 0x0);  /* 0100 */
  a2 = LD32(a7 + 0x74);  /* 0103 */
  a7 = LD32(a7 + 0xa0);  /* 0106 */
  ST32(a1 + 0x2c, a9);  /* 0109 */
  __asm__ volatile("" ::: "memory");  /* 010c: memw */
  /* 010f: INDIRECT callx a7 <- mem[a7+0xa0]; result unknown */ a2 = 0;
  a12 = a10;  /* 0112 */
  a11 = a1 + (16);  /* 0114 */
  a10 = a4;  /* 0117: mov */
  /* 011a: INDIRECT callx a2 <- mem[a7+0x74]; result unknown */ a2 = 0;
  a9 = LD32(a1 + 0x2c);  /* 011d */
  a7 = a10;  /* 011f */
  a8 = -3;  /* 0121 */
  a5 = (u32)(RODATA__rodata___func___7 + 0x0);  /* 0123: l32r -> .rodata.__func__$7 */
  a4 = (u32)&s_mesh_stop_mutex + 0x0;  /* 0126: l32r -> global */
  if (a10 == 1) goto L_0180;  /* 0129: beqi a10, 1, 180 <mesh_recv+0xf8> */
  L_012c: a6 = (u32)&mesh_tcpip_mbox + 0x0;  /* 012c: l32r -> global */
  if (a3 != 0) goto L_0134;  /* 012f: bnez.n a3, 134 <mesh_recv+0xac> */
  L_0131: a6 = (u32)&mesh_myself_mbox + 0x0;  /* 0131: l32r -> global */
  L_0134: a12 = 0x536;  /* 0134 */
  a11 = a5;  /* 0137 */
  a2 = LD8U(a6 + 0x8);  /* 0139 */
  a2 = a2 & a8;  /* 013c */
  ST8(a6 + 0x8, a2);  /* 013f */
  __asm__ volatile("" ::: "memory");  /* 0142: memw */
  a10 = LD32(a4 + 0x0);  /* 0145 */
  __asm__ volatile("" ::: "memory");  /* 0147: memw */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 014a: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 014d: callx a8 via reloc-expand */
  a6 = (u32)&g_mesh_stop_event_group + 0x0;  /* 0150: l32r -> global */
  a10 = LD32(a6 + 0x0);  /* 0153 */
  if (a10 == 0) goto L_0169;  /* 0155: beqz.n a10, 169 <mesh_recv+0xe1> */
  L_0157: a11 = 32;  /* 0157 */
  a6 = 16;  /* 0159 */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 015b: l32r -> global */
  if (a3 == 0) a11 = a6;  /* 015e */
  a2 = LD32(a8 + 0x0);  /* 0161 */
  a2 = LD32(a2 + 0x84);  /* 0163 */
  /* 0166: INDIRECT callx a2 <- mem[a2+0x84]; result unknown */ a2 = 0;
  L_0169: a12 = 0x53b;  /* 0169 */
  a11 = a5;  /* 016c: mov */
  a10 = LD32(a4 + 0x0);  /* 016f */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 0172: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 0175: callx a8 via reloc-expand */
  a2 = 0x0000400au;  /* 0178: l32r = 16394 */
  goto L_03e2;  /* 017b: j */
  L_0180: a11 = (u32)&mesh_tcpip_mbox + 0x0;  /* 0180: l32r -> global */
  if (a3 != 0) goto L_0188;  /* 0183: bnez.n a3, 188 <mesh_recv+0x100> */
  L_0185: a11 = (u32)&mesh_myself_mbox + 0x0;  /* 0185: l32r -> global */
  L_0188: a10 = LD8U(a11 + 0x8);  /* 0188 */
  a8 = a10 & a8;  /* 018b */
  ST8(a11 + 0x8, a8);  /* 018e */
  __asm__ volatile("" ::: "memory");  /* 0191: memw */
  a10 = LD32(a1 + 0x10);  /* 0194 */
  if (a10 == 0) goto L_01b0;  /* 0196: beqz.n a10, 1b0 <mesh_recv+0x128> */
  L_0198: a11 = LD32(a10 + 0x28);  /* 0198 */
  if (((a11 >> 4) & 1) != 0) goto L_01b8;  /* 019a: bbsi a11, 4, 1b8 <mesh_recv+0x130> */
  L_019d: a2 = LD32(a10 + 0x0);  /* 019d */
  if (a2 == 0) goto L_03d1;  /* 019f: beqz a2, 3d1 <mesh_recv+0x349> */
  L_01a2: a4 = 4;  /* 01a2 */
  a11 = a11 & a4;  /* 01a4 */
  if (a11 != 0) goto L_01f3;  /* 01a7: bnez a11, 1f3 <mesh_recv+0x16b> */
  L_01aa: __asm__ volatile("" ::: "memory");  /* 01aa: memw */
  goto L_03b5;  /* 01ad: j */
  L_01b0: a2 = 0x0000401au;  /* 01b0: l32r = 16410 */
  goto L_01bb;  /* 01b3: j */
  L_01b8: a2 = 0x00004004u;  /* 01b8: l32r = 16388 */
  L_01bb: a12 = 0x560;  /* 01bb */
  a11 = a5;  /* 01be */
  a10 = LD32(a4 + 0x0);  /* 01c0 */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 01c2: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 01c5: callx a8 via reloc-expand */
  a6 = (u32)&g_mesh_stop_event_group + 0x0;  /* 01c8: l32r -> global */
  a10 = LD32(a6 + 0x0);  /* 01cb */
  if (a10 == 0) goto L_01e1;  /* 01cd: beqz.n a10, 1e1 <mesh_recv+0x159> */
  L_01cf: a11 = 32;  /* 01cf */
  a7 = 16;  /* 01d1 */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 01d3: l32r -> global */
  if (a3 == 0) a11 = a7;  /* 01d6 */
  a6 = LD32(a8 + 0x0);  /* 01d9 */
  a6 = LD32(a6 + 0x84);  /* 01db */
  /* 01de: INDIRECT callx a6 <- mem[a6+0x84]; result unknown */ a2 = 0;
  L_01e1: a12 = 0x565;  /* 01e1 */
  a11 = a5;  /* 01e4: mov */
  a10 = LD32(a4 + 0x0);  /* 01e7 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 01ea: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 01ed: callx a8 via reloc-expand */
  goto L_03e2;  /* 01f0: j */
  L_01f3: a5 = (u32)&LOCAL__bss_s_extra_toDS_qsize + 0x0;  /* 01f3: l32r -> .bss.s_extra_toDS_qsize (same-object static) */
  if (a3 != 0) goto L_01fc;  /* 01f6: bnez a3, 1fc <mesh_recv+0x174> */
  L_01f9: a5 = (u32)&LOCAL__bss_s_extra_toSelf_qsize + 0x0;  /* 01f9: l32r -> .bss.s_extra_toSelf_qsize (same-object static) */
  L_01fc: a4 = LD32(a5 + 0x0);  /* 01fc */
  a4 = a4 + (-1);  /* 01fe */
  ST32(a5 + 0x0, a4);  /* 0200 */
  __asm__ volatile("" ::: "memory");  /* 0202: memw */
  goto L_0235;  /* 0205: j */
  L_0208: a4 = a2 + (14);  /* 0208 */
  a12 = LD32(a4 + 0x18);  /* 020a */
  a13 = a11;  /* 020c */
  a4 = 1;  /* 020e */
  a5 = 0xf0000001u;  /* 0210: l32r = -268435455 */
  a5 = a12 + a5;  /* 0213 */
  if (a5 != 0) a13 = a4;  /* 0215 */
  if (a13 == 0) goto L_0235;  /* 0218: beqz.n a13, 235 <mesh_recv+0x1ad> */
  L_021a: if (a12 == 0) a4 = a11;  /* 021a */
  if (a4 == 0) goto L_0235;  /* 021d: beqz a4, 235 <mesh_recv+0x1ad> */
  L_0220: a13 = (u32)(RODATA__rodata___func___7 + 0x0);  /* 0220: l32r -> .rodata.__func__$7 */
  a14 = 0x583;  /* 0223 */
  ST32(a1 + 0x2c, a9);  /* 0226 */
  __asm__ volatile("" ::: "memory");  /* 0229: memw */
  a8 = (u32)&esp_mesh_txupQ_pending + 0x0;  /* 022c: l32r -> global */
  a2 = esp_mesh_txupQ_pending(a2, a3, a4, a5, a6, a7);  /* 022f: callx a8 via reloc-expand */
  a9 = LD32(a1 + 0x2c);  /* 0232 */
  L_0235: a11 = LD8U(a2 + 0xf);  /* 0235 */
  a5 = a11 << 2;  /* 0238 */
  a4 = LD16U(a2 + 0x10);  /* 023b */
  a4 = a4 - a5;  /* 023e: sub */
  a4 = (a4 >> 16) & 0x1;  /* 0241: extui width 1 */
  a5 = LD16U(a9 + 0x4);  /* 0244 */
  if (a5 >= a4) goto L_024d;  /* 0247: bgeu a5, a4, 24d <mesh_recv+0x1c5> */
  L_024a: goto L_0345;  /* 024a: j */
  L_024d: a5 = a2 + (14);  /* 024d */
  a12 = a4;  /* 024f */
  a10 = LD32(a9 + 0x0);  /* 0251 */
  a11 = a11 + (a5 << 2);  /* 0253 */
  ST32(a1 + 0x20, a5);  /* 0256 */
  a5 = a2 + (18);  /* 0258 */
  ST32(a1 + 0x2c, a9);  /* 025b */
  __asm__ volatile("" ::: "memory");  /* 025d: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0260: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0263: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 0266 */
  a11 = a2 + (28);  /* 0268 */
  a9 = LD32(a1 + 0x2c);  /* 026b */
  ST16(a9 + 0x4, a4);  /* 026d */
  __asm__ volatile("" ::: "memory");  /* 0270: memw */
  a4 = LD32(a5 + 0x0);  /* 0273 */
  a4 = (a4 >> 6) & 0x1ffff;  /* 0275: extui width 17 */
  ST32(a9 + 0x8, a4);  /* 0278 */
  a4 = LD32(a5 + 0x0);  /* 027a */
  a4 = (a4 >> 2) & 0x7fff;  /* 027c: extui width 15 */
  a10 = LD32(a1 + 0x28);  /* 027f */
  ST32(a9 + 0xc, a4);  /* 0281 */
  __asm__ volatile("" ::: "memory");  /* 0284: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0287: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 028a: callx a8 (libc, via reloc-expand) */
  if (a3 == 0) goto L_029c;  /* 028d: beqz.n a3, 29c <mesh_recv+0x214> */
  L_028f: a12 = 6;  /* 028f */
  a11 = a2 + (22);  /* 0291 */
  a10 = a3;  /* 0294 */
  a8 = (u32)&memcpy + 0x0;  /* 0296: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0299: callx a8 (libc, via reloc-expand) */
  L_029c: a10 = LD32(a1 + 0x10);  /* 029c */
  a11 = a6;  /* 029e */
  a8 = (u32)&mesh_recv_process_flag;  /* 02a0: l32r -> func addr */
  a2 = mesh_recv_process_flag(a2, a3, a4, a5, a6, a7);  /* 02a3: callx a8 via reloc-expand */
  a6 = 33;  /* 02a6 */
  a4 = (u32)&g_mesh_topology + 0x0;  /* 02a8: l32r -> global */
  a9 = LD32(a4 + 0x0);  /* 02ab */
  a4 = 28;  /* 02ad */
  if (a9 != 0) a4 = a6;  /* 02af */
  a5 = LD32(a5 + 0x0);  /* 02b2 */
  a6 = LD32(a1 + 0x20);  /* 02b4 */
  a10 = a6 + a4;  /* 02b6 */
  if (((a5 >> 24) & 1) == 0) goto L_02c4;  /* 02b8: bbci a5, 24, 2c4 <mesh_recv+0x23c> */
  L_02bb: a6 = LD8U(a2 + 0xf);  /* 02bb */
  a6 = a6 - a4;  /* 02be: subx4 */
  if (a6 >= 4u) goto L_02d8;  /* 02c1: bgeui a6, 4, 2d8 <mesh_recv+0x250> */
  L_02c4: a7 = 0;  /* 02c4 */
  if (((a5 >> 23) & 1) == 0) goto L_02d8;  /* 02c6: bbci a5, 23, 2d8 <mesh_recv+0x250> */
  L_02c9: a6 = LD8U(a2 + 0xf);  /* 02c9 */
  a5 = 1;  /* 02cc */
  a4 = a6 - a4;  /* 02ce: subx4 */
  if (a4 >= 3u) goto L_02d6;  /* 02d1: bgeui a4, 3, 2d6 <mesh_recv+0x24e> */
  L_02d4: a5 = a7;  /* 02d4 */
  L_02d6: a7 = a5;  /* 02d6 */
  L_02d8: a13 = LD32(a1 + 0x50);  /* 02d8 */
  a11 = a7;  /* 02db */
  a12 = LD32(a1 + 0x24);  /* 02dd */
  a8 = (u32)&mesh_recv_add_option;  /* 02df: l32r -> func addr */
  a2 = mesh_recv_add_option(a2, a3, a4, a5, a6, a7);  /* 02e2: callx a8 via reloc-expand */
  a8 = LD32(a1 + 0x50);  /* 02e5 */
  if (a8 == 0) goto L_034b;  /* 02e8: beqz a8, 34b <mesh_recv+0x2c3> */
  L_02eb: a4 = a8 - a8;  /* 02eb: subx8 */
  a4 = a4 + (-7);  /* 02ee */
  a8 = LD32(a1 + 0x24);  /* 02f1 */
  a2 = 0;  /* 02f3 */
  a4 = a8 + a4;  /* 02f5 */
  a5 = 9;  /* 02f7 */
  a6 = LD8U(a4 + 0x0);  /* 02f9 */
  ST32(a1 + 0x50, a2);  /* 02fc */
  if (a6 != a5) goto L_034b;  /* 02ff: bne a6, a5, 34b <mesh_recv+0x2c3> */
  L_0302: a5 = LD8U(a4 + 0x2);  /* 0302 */
  a5 = a5 << 8;  /* 0305 */
  a6 = LD8U(a4 + 0x1);  /* 0308 */
  a5 = a5 | a6;  /* 030b */
  if (a5 == a2) goto L_034b;  /* 030e: beq a5, a2, 34b <mesh_recv+0x2c3> */
  L_0311: a6 = LD8U(a4 + 0x4);  /* 0311 */
  a6 = a6 << 8;  /* 0314 */
  a5 = LD8U(a4 + 0x3);  /* 0317 */
  a6 = a6 | a5;  /* 031a */
  a5 = LD8U(a4 + 0x5);  /* 031d */
  a5 = a5 << 16;  /* 0320 */
  a5 = a5 | a6;  /* 0323 */
  a4 = LD8U(a4 + 0x6);  /* 0326 */
  a4 = a4 << 24;  /* 0329 */
  a4 = a4 | a5;  /* 032c */
  if (a4 == a2) goto L_034b;  /* 032f: beq a4, a2, 34b <mesh_recv+0x2c3> */
  L_0332: a5 = LD32(a1 + 0x10);  /* 0332 */
  a5 = LD32(a5 + 0x28);  /* 0334 */
  a5 = (a5 >> 8) & 0xffff;  /* 0336: extui width 16 */
  ST8(a4 + 0x0, a5);  /* 0339 */
  __asm__ volatile("" ::: "memory");  /* 033c: memw */
  __asm__ volatile("" ::: "memory");  /* 033f: memw */
  goto L_034b;  /* 0342: j */
  L_0345: a5 = 0x00004008u;  /* 0345: l32r = 16392 */
  ST32(a1 + 0x50, a5);  /* 0348 */
  L_034b: a10 = LD32(a1 + 0x10);  /* 034b */
  a5 = LD32(a10 + 0x28);  /* 034d */
  a4 = (u32)(RODATA__rodata___func___7 + 0x0);  /* 034f: l32r -> .rodata.__func__$7 */
  if (((a5 >> 2) & 1) == 0) goto L_0369;  /* 0352: bbci a5, 2, 369 <mesh_recv+0x2e1> */
  L_0355: a13 = 0x5a7;  /* 0355 */
  a12 = a4;  /* 0358 */
  a11 = 1;  /* 035a */
  __asm__ volatile("" ::: "memory");  /* 035c: memw */
  a8 = (u32)&esp_mesh_discard_context + 0x0;  /* 035f: l32r -> global */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 0362: callx a8 via reloc-expand */
  goto L_0374;  /* 0365: j */
  L_0369: a12 = 0x5a9;  /* 0369 */
  a11 = a4;  /* 036c */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 036e: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 0371: callx a8 via reloc-expand */
  L_0374: a5 = (u32)&s_mesh_stop_mutex + 0x0;  /* 0374: l32r -> global */
  a12 = 0x5ab;  /* 0377 */
  a11 = a4;  /* 037a */
  a10 = LD32(a5 + 0x0);  /* 037c */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 037e: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 0381: callx a8 via reloc-expand */
  a6 = (u32)&g_mesh_stop_event_group + 0x0;  /* 0384: l32r -> global */
  a10 = LD32(a6 + 0x0);  /* 0387 */
  if (a10 == 0) goto L_039d;  /* 0389: beqz.n a10, 39d <mesh_recv+0x315> */
  L_038b: a11 = 32;  /* 038b */
  a7 = 16;  /* 038d */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 038f: l32r -> global */
  if (a3 == 0) a11 = a7;  /* 0392 */
  a6 = LD32(a8 + 0x0);  /* 0395 */
  a6 = LD32(a6 + 0x84);  /* 0397 */
  /* 039a: INDIRECT callx a6 <- mem[a6+0x84]; result unknown */ a2 = 0;
  L_039d: a12 = 0x5b0;  /* 039d */
  a11 = a4;  /* 03a0: mov */
  a10 = LD32(a5 + 0x0);  /* 03a3 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 03a6: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 03a9: callx a8 via reloc-expand */
  a2 = LD32(a1 + 0x50);  /* 03ac */
  goto L_03e2;  /* 03af: j */
  L_03b5: a4 = a2 + (18);  /* 03b5 */
  a5 = LD32(a4 + 0x0);  /* 03b8 */
  a4 = 0x403;  /* 03ba */
  a4 = a4 << 14;  /* 03bd */
  a5 = a5 & a4;  /* 03c0 */
  a4 = 1;  /* 03c3 */
  a4 = a4 << 24;  /* 03c5 */
  if (a5 == a4) goto L_03ce;  /* 03c8: beq a5, a4, 3ce <mesh_recv+0x346> */
  L_03cb: goto L_0235;  /* 03cb: j */
  L_03ce: goto L_0208;  /* 03ce: j */
  L_03d1: a12 = 0x55e;  /* 03d1 */
  a11 = a5;  /* 03d4 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 03d6: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 03d9: callx a8 via reloc-expand */
  a2 = 0x00004015u;  /* 03dc: l32r = 16405 */
  goto L_01bb;  /* 03df: j */
  L_03e2: return a2;  /* 03e2: retw.n */
}


/* mesh_recv_add_option @ mesh.o 0000001c size 332B bind GLOBAL
 * Calls: memcpy | indirect[3]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_recv_add_option(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 001c: entry a1, 64 (frame 64 bytes) */
  if (a2 != 0) goto L_004e;  /* 001f: bnez.n a2, 4e <mesh_recv_add_option+0x32> */
  L_0021: a2 = (u32)&g_log_level + 0x0;  /* 0021: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0024 */
  a2 = 0x00004008u;  /* 0027: l32r = 16392 */
  if (a3 >= 3u) goto L_0030;  /* 002a: bgeui a3, 3, 30 <mesh_recv_add_option+0x14> */
  L_002d: goto L_0166;  /* 002d: j */
  L_0030: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0030: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0033 */
  if (a3 == 0) goto L_0166;  /* 0036: beqz a3, 166 <mesh_recv_add_option+0x14a> */
  L_0039: a4 = LD32(a3 + 0x150);  /* 0039 */
  if (a4 == 0) goto L_0166;  /* 003c: beqz a4, 166 <mesh_recv_add_option+0x14a> */
  L_003f: a10 = LD32(a3 + 0x158);  /* 003f */
  a3 = 0x4b4;  /* 0042 */
  /* 0045: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0048: -> "mesh" */
  goto L_00b4;  /* 004b: j */
  L_004e: a8 = 1;  /* 004e */
  a6 = 0;  /* 0050 */
  if (a3 == 0) a6 = a8;  /* 0052 */
  a7 = (a6 >> 8) & 0x1;  /* 0055: extui width 1 */
  if (a6 != 0) goto L_0164;  /* 0058: bnez a6, 164 <mesh_recv_add_option+0x148> */
  L_005b: if (a5 != 0) a8 = a7;  /* 005b */
  if (a8 != 0) goto L_0164;  /* 005e: bnez a8, 164 <mesh_recv_add_option+0x148> */
  L_0061: goto L_00ce;  /* 0061: j */
  L_0065: a6 = a8 - a8;  /* 0065: subx8 */
  a6 = a4 + a6;  /* 0068 */
  a9 = LD8U(a6 + 0x4);  /* 006a */
  a9 = a9 << 8;  /* 006d */
  a7 = LD8U(a6 + 0x3);  /* 0070 */
  a9 = a9 | a7;  /* 0073 */
  a7 = LD8U(a6 + 0x5);  /* 0076 */
  a7 = a7 << 16;  /* 0079 */
  a7 = a7 | a9;  /* 007c */
  a6 = LD8U(a6 + 0x6);  /* 007f */
  a6 = a6 << 24;  /* 0082 */
  a6 = a6 | a7;  /* 0085 */
  if (a6 != 0) goto L_00cc;  /* 0088: bnez a6, cc <mesh_recv_add_option+0xb0> */
  L_008b: a2 = (u32)&g_log_level + 0x0;  /* 008b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 008e */
  a2 = 0x00004008u;  /* 0090: l32r = 16392 */
  if (a3 >= 3u) goto L_0099;  /* 0093: bgeui a3, 3, 99 <mesh_recv_add_option+0x7d> */
  L_0096: goto L_0166;  /* 0096: j */
  L_0099: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0099: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 009c */
  if (a3 == 0) goto L_0166;  /* 009f: beqz a3, 166 <mesh_recv_add_option+0x14a> */
  L_00a2: a4 = LD32(a3 + 0x150);  /* 00a2 */
  if (a4 == 0) goto L_0166;  /* 00a5: beqz a4, 166 <mesh_recv_add_option+0x14a> */
  L_00a8: a10 = LD32(a3 + 0x158);  /* 00a8 */
  a3 = 0x4b9;  /* 00ab */
  /* 00ae: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b1: -> "mesh" */
  L_00b4: a13 = a10;  /* 00b4 */
  a14 = a11;  /* 00b6 */
  a10 = 3;  /* 00b8 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00ba: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00bd: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 00c0 */
  __asm__ volatile("" ::: "memory");  /* 00c2: memw */
  /* 00c5: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0166;  /* 00c8: j */
  L_00cc: a8 = a8 + (1);  /* 00cc */
  L_00ce: if ((i32)a8 < (i32)a5) goto L_0065;  /* 00ce: blt a8, a5, 65 <mesh_recv_add_option+0x49> */
  L_00d1: a6 = LD8U(a2 + 0x0);  /* 00d1 */
  if (a6 != 8) goto L_00e0;  /* 00d4: bnei a6, 8, e0 <mesh_recv_add_option+0xc4> */
  L_00d7: a6 = a4;  /* 00d7 */
  a7 = 0;  /* 00d9 */
  a9 = a2 + (3);  /* 00db */
  goto L_015e;  /* 00dd: j */
  L_00e0: a6 = LD8U(a2 + 0x2);  /* 00e0 */
  a6 = a6 << 8;  /* 00e3 */
  a7 = LD8U(a2 + 0x1);  /* 00e6 */
  a6 = a6 | a7;  /* 00e9 */
  a6 = a6 + (3);  /* 00ec */
  a3 = a3 - a6;  /* 00ee: sub */
  a2 = a2 + a6;  /* 00f1 */
  if ((i32)a3 >= 4) goto L_00d1;  /* 00f3: bgei a3, 4, d1 <mesh_recv_add_option+0xb5> */
  L_00f6: a2 = 0;  /* 00f6 */
  goto L_0166;  /* 00f8: j */
  L_00fb: a8 = LD8U(a6 + 0x0);  /* 00fb */
  if (a8 != 8) goto L_015a;  /* 00fe: bnei a8, 8, 15a <mesh_recv_add_option+0x13e> */
  L_0101: a8 = LD8U(a6 + 0x2);  /* 0101 */
  a8 = a8 << 8;  /* 0104 */
  a10 = LD8U(a6 + 0x1);  /* 0107 */
  a8 = a8 | a10;  /* 010a */
  if (a8 == 0) goto L_015a;  /* 010d: beqz a8, 15a <mesh_recv_add_option+0x13e> */
  L_0110: a10 = LD8U(a6 + 0x4);  /* 0110 */
  a10 = a10 << 8;  /* 0113 */
  a8 = LD8U(a6 + 0x3);  /* 0116 */
  a10 = a10 | a8;  /* 0119 */
  a8 = LD8U(a6 + 0x5);  /* 011c */
  a8 = a8 << 16;  /* 011f */
  a8 = a8 | a10;  /* 0122 */
  a10 = LD8U(a6 + 0x6);  /* 0125 */
  a10 = a10 << 24;  /* 0128 */
  a10 = a10 | a8;  /* 012b */
  if (a10 == 0) goto L_015a;  /* 012e: beqz.n a10, 15a <mesh_recv_add_option+0x13e> */
  L_0130: a12 = LD8U(a4 + 0x2);  /* 0130 */
  a12 = a12 << 8;  /* 0133 */
  a8 = LD8U(a2 + 0x2);  /* 0136 */
  a8 = a8 << 8;  /* 0139 */
  a11 = LD8U(a2 + 0x1);  /* 013c */
  a8 = a8 | a11;  /* 013f */
  a11 = a9;  /* 0142 */
  a13 = LD8U(a4 + 0x1);  /* 0144 */
  a12 = a12 | a13;  /* 0147 */
  a12 = (a12 < a8) ? a12 : a8;  /* 014a: minu */
  ST32(a1 + 0x10, a9);  /* 014d */
  __asm__ volatile("" ::: "memory");  /* 014f: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0152: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0155: callx a8 (libc, via reloc-expand) */
  a9 = LD32(a1 + 0x10);  /* 0158 */
  L_015a: a7 = a7 + (1);  /* 015a */
  a6 = a6 + (7);  /* 015c */
  L_015e: if ((i32)a7 < (i32)a5) goto L_00fb;  /* 015e: blt a7, a5, fb <mesh_recv_add_option+0xdf> */
  L_0161: goto L_00e0;  /* 0161: j */
  L_0164: a2 = -1;  /* 0164 */
  L_0166: return a2;  /* 0166: retw.n */
}


/* mesh_recv_process_flag @ mesh.o 00000018 size 197B bind GLOBAL
 * Calls: none | indirect[4]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_recv_process_flag(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_004a;  /* 001b: bnez.n a2, 4a <mesh_recv_process_flag+0x32> */
  L_001d: a2 = (u32)&g_log_level + 0x0;  /* 001d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0020 */
  a2 = 0x00004008u;  /* 0023: l32r = 16392 */
  if (a3 >= 3u) goto L_002c;  /* 0026: bgeui a3, 3, 2c <mesh_recv_process_flag+0x14> */
  L_0029: goto L_00d8;  /* 0029: j */
  L_002c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 002c: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 002f */
  if (a3 == 0) goto L_00d8;  /* 0032: beqz a3, d8 <mesh_recv_process_flag+0xc0> */
  L_0035: a4 = LD32(a3 + 0x150);  /* 0035 */
  if (a4 == 0) goto L_00d8;  /* 0038: beqz a4, d8 <mesh_recv_process_flag+0xc0> */
  L_003b: a10 = LD32(a3 + 0x158);  /* 003b */
  a3 = 0x4fa;  /* 003e */
  /* 0041: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0044: -> "mesh" */
  goto L_0074;  /* 0047: j */
  L_004a: a2 = LD32(a2 + 0x0);  /* 004a */
  if (a2 != 0) goto L_008e;  /* 004c: bnez.n a2, 8e <mesh_recv_process_flag+0x76> */
  L_004e: a2 = (u32)&g_log_level + 0x0;  /* 004e: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0051 */
  a2 = 0x00004008u;  /* 0053: l32r = 16392 */
  if (a3 < 3u) goto L_00d8;  /* 0056: bltui a3, 3, d8 <mesh_recv_process_flag+0xc0> */
  L_0059: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0059: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 005c */
  if (a3 == 0) goto L_00d8;  /* 005f: beqz a3, d8 <mesh_recv_process_flag+0xc0> */
  L_0062: a4 = LD32(a3 + 0x150);  /* 0062 */
  if (a4 == 0) goto L_00d8;  /* 0065: beqz a4, d8 <mesh_recv_process_flag+0xc0> */
  L_0068: a10 = LD32(a3 + 0x158);  /* 0068 */
  a3 = 0x4fb;  /* 006b */
  /* 006e: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0071: -> "mesh" */
  L_0074: a13 = a10;  /* 0074 */
  a14 = a11;  /* 0076 */
  a10 = 3;  /* 0078 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 007a: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 007d: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 0080 */
  __asm__ volatile("" ::: "memory");  /* 0082: memw */
  /* 0085: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_00d8;  /* 0088: j */
  L_008e: if (a3 != 0) goto L_00b9;  /* 008e: bnez.n a3, b9 <mesh_recv_process_flag+0xa1> */
  L_0090: a2 = (u32)&g_log_level + 0x0;  /* 0090: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0093 */
  a2 = 0x00004008u;  /* 0095: l32r = 16392 */
  if (a3 < 3u) goto L_00d8;  /* 0098: bltui a3, 3, d8 <mesh_recv_process_flag+0xc0> */
  L_009b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 009b: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 009e */
  if (a3 == 0) goto L_00d8;  /* 00a0: beqz.n a3, d8 <mesh_recv_process_flag+0xc0> */
  L_00a2: a4 = LD32(a3 + 0x150);  /* 00a2 */
  if (a4 == 0) goto L_00d8;  /* 00a5: beqz.n a4, d8 <mesh_recv_process_flag+0xc0> */
  L_00a7: a10 = LD32(a3 + 0x158);  /* 00a7 */
  a3 = 0x4ff;  /* 00aa */
  /* 00ad: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b0: -> "mesh" */
  goto L_0074;  /* 00b3: j */
  L_00b9: a8 = LD8U(a2 + 0xe);  /* 00b9 */
  if (((a8 >> 5) & 1) == 0) goto L_00ca;  /* 00bc: bbci a8, 5, ca <mesh_recv_process_flag+0xb2> */
  L_00bf: a4 = 8;  /* 00bf */
  a2 = LD32(a3 + 0x0);  /* 00c1 */
  a2 = a2 | a4;  /* 00c4 */
  ST32(a3 + 0x0, a2);  /* 00c7 */
  L_00ca: a2 = 0;  /* 00ca */
  if (((a8 >> 4) & 1) == 0) goto L_00d8;  /* 00cc: bbci a8, 4, d8 <mesh_recv_process_flag+0xc0> */
  L_00cf: a4 = 4;  /* 00cf */
  a8 = LD32(a3 + 0x0);  /* 00d1 */
  a8 = a8 | a4;  /* 00d3 */
  ST32(a3 + 0x0, a8);  /* 00d6 */
  L_00d8: __asm__ volatile("" ::: "memory");  /* 00d8: memw */
  return a2;  /* 00db: retw.n */
}


/* mesh_send_process_flag @ mesh.o 00000018 size 300B bind GLOBAL
 * Calls: none | indirect[3]: mem[a2+0x158]; mem[a2+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=3 */
u32 mesh_send_process_flag(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_004a;  /* 001b: bnez.n a2, 4a <mesh_send_process_flag+0x32> */
  L_001d: a2 = (u32)&g_log_level + 0x0;  /* 001d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0020 */
  a3 = 0x00004008u;  /* 0023: l32r = 16392 */
  if (a2 >= 3u) goto L_002c;  /* 0026: bgeui a2, 3, 2c <mesh_send_process_flag+0x14> */
  L_0029: goto L_013d;  /* 0029: j */
  L_002c: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 002c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 002f */
  if (a2 == 0) goto L_013d;  /* 0032: beqz a2, 13d <mesh_send_process_flag+0x125> */
  L_0035: a4 = LD32(a2 + 0x150);  /* 0035 */
  if (a4 == 0) goto L_013d;  /* 0038: beqz a4, 13d <mesh_send_process_flag+0x125> */
  L_003b: a10 = LD32(a2 + 0x158);  /* 003b */
  a2 = 0x2b4;  /* 003e */
  /* 0041: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0044: -> "mesh" */
  goto L_0078;  /* 0047: j */
  L_004a: a8 = LD32(a2 + 0x0);  /* 004a */
  if (a8 != 0) goto L_0091;  /* 004c: bnez a8, 91 <mesh_send_process_flag+0x79> */
  L_004f: a2 = (u32)&g_log_level + 0x0;  /* 004f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0052 */
  a3 = 0x00004008u;  /* 0054: l32r = 16392 */
  if (a2 >= 3u) goto L_005d;  /* 0057: bgeui a2, 3, 5d <mesh_send_process_flag+0x45> */
  L_005a: goto L_013d;  /* 005a: j */
  L_005d: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 005d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0060 */
  if (a2 == 0) goto L_013d;  /* 0063: beqz a2, 13d <mesh_send_process_flag+0x125> */
  L_0066: a4 = LD32(a2 + 0x150);  /* 0066 */
  if (a4 == 0) goto L_013d;  /* 0069: beqz a4, 13d <mesh_send_process_flag+0x125> */
  L_006c: a10 = LD32(a2 + 0x158);  /* 006c */
  a2 = 0x2b5;  /* 006f */
  /* 0072: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0075: -> "mesh" */
  L_0078: a13 = a10;  /* 0078 */
  a14 = a11;  /* 007a */
  a10 = 3;  /* 007c */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 007e: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0081: -> "mesh" */
  ST32(a1 + 0x0, a2);  /* 0084 */
  __asm__ volatile("" ::: "memory");  /* 0086: memw */
  /* 0089: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_013d;  /* 008c: j */
  L_0091: if (((a3 >> 2) & 1) == 0) goto L_00a8;  /* 0091: bbci a3, 2, a8 <mesh_send_process_flag+0x90> */
  L_0094: a9 = LD8U(a8 + 0xe);  /* 0094 */
  a4 = 16;  /* 0097 */
  a9 = a9 | a4;  /* 009a */
  a4 = 0;  /* 009d */
  ST8(a8 + 0xe, a9);  /* 009f */
  ST8(a2 + 0x12, a4);  /* 00a2 */
  __asm__ volatile("" ::: "memory");  /* 00a5: memw */
  L_00a8: if (((a3 >> 3) & 1) == 0) goto L_00b9;  /* 00a8: bbci a3, 3, b9 <mesh_send_process_flag+0xa1> */
  L_00ab: a4 = 32;  /* 00ab */
  a9 = LD8U(a8 + 0xe);  /* 00ad */
  a9 = a9 | a4;  /* 00b0 */
  ST8(a8 + 0xe, a9);  /* 00b3 */
  __asm__ volatile("" ::: "memory");  /* 00b6: memw */
  L_00b9: if (((a3 >> 0) & 1) == 0) goto L_00ca;  /* 00b9: bbci a3, 0, ca <mesh_send_process_flag+0xb2> */
  L_00bc: a4 = 64;  /* 00bc */
  a9 = LD8U(a8 + 0xe);  /* 00be */
  a9 = a9 | a4;  /* 00c1 */
  ST8(a8 + 0xe, a9);  /* 00c4 */
  __asm__ volatile("" ::: "memory");  /* 00c7: memw */
  L_00ca: if (((a3 >> 1) & 1) == 0) goto L_00dc;  /* 00ca: bbci a3, 1, dc <mesh_send_process_flag+0xc4> */
  L_00cd: a11 = a8 + (18);  /* 00cd */
  a10 = 1;  /* 00d0 */
  a10 = a10 << 22;  /* 00d2 */
  a9 = LD32(a11 + 0x0);  /* 00d5 */
  a9 = a9 | a10;  /* 00d7 */
  ST32(a11 + 0x0, a9);  /* 00da */
  L_00dc: if (((a3 >> 5) & 1) == 0) goto L_00f0;  /* 00dc: bbci a3, 5, f0 <mesh_send_process_flag+0xd8> */
  L_00df: a11 = a8 + (18);  /* 00df */
  a10 = 1;  /* 00e2 */
  a10 = a10 << 26;  /* 00e4 */
  a9 = LD32(a11 + 0x0);  /* 00e7 */
  a9 = a9 | a10;  /* 00ea */
  ST32(a11 + 0x0, a9);  /* 00ed */
  L_00f0: if (((a3 >> 12) & 1) == 0) goto L_0104;  /* 00f0: bbci a3, 12, 104 <mesh_send_process_flag+0xec> */
  L_00f3: a11 = a8 + (18);  /* 00f3 */
  a10 = 1;  /* 00f6 */
  a10 = a10 << 23;  /* 00f8 */
  a9 = LD32(a11 + 0x0);  /* 00fb */
  a9 = a9 | a10;  /* 00fe */
  ST32(a11 + 0x0, a9);  /* 0101 */
  L_0104: if (((a3 >> 4) & 1) == 0) goto L_0110;  /* 0104: bbci a3, 4, 110 <mesh_send_process_flag+0xf8> */
  L_0107: a4 = 2;  /* 0107 */
  a9 = LD32(a2 + 0x28);  /* 0109 */
  a9 = a9 | a4;  /* 010b */
  ST32(a2 + 0x28, a9);  /* 010e */
  L_0110: a4 = 64;  /* 0110 */
  a3 = a3 & a4;  /* 0112 */
  if (a3 == 0) goto L_013d;  /* 0115: beqz.n a3, 13d <mesh_send_process_flag+0x125> */
  L_0117: a8 = a8 + (18);  /* 0117 */
  a3 = LD32(a8 + 0x0);  /* 011a */
  a9 = 1;  /* 011c */
  a9 = a9 << 27;  /* 011e */
  a3 = a3 | a9;  /* 0121 */
  a4 = 2;  /* 0124 */
  ST32(a8 + 0x0, a3);  /* 0126 */
  a3 = LD32(a2 + 0x28);  /* 0128 */
  a3 = a3 | a4;  /* 012a */
  ST32(a2 + 0x28, a3);  /* 012d */
  a3 = 1;  /* 012f */
  a3 = a3 << 22;  /* 0131 */
  a2 = LD32(a8 + 0x0);  /* 0134 */
  a2 = a2 | a3;  /* 0136 */
  a3 = 0;  /* 0139 */
  ST32(a8 + 0x0, a2);  /* 013b */
  L_013d: a2 = a3;  /* 013d */
  __asm__ volatile("" ::: "memory");  /* 013f: memw */
  return a2;  /* 0142: retw.n */
}


/* mesh_send_process_topo @ mesh.o 00000010 size 77B bind GLOBAL
 * Calls: mesh_chain_header_add_ttl, mesh_add_option | Data refs: g_mesh_max_layer, g_mesh_topology
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_send_process_topo(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a3 = (u32)&g_mesh_max_layer + 0x0;  /* 0013: l32r -> global */
  a10 = LD16U(a3 + 0x0);  /* 0016 */
  a10 = a10 + a10;  /* 0019 */
  a3 = (u32)&g_mesh_topology + 0x0;  /* 001b: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 001e */
  if (a8 != 0) goto L_0030;  /* 0020: bnez.n a8, 30 <mesh_send_process_topo+0x20> */
  L_0022: a10 = a10 + (-1);  /* 0022 */
  ST8(a2 + 0x4, a10);  /* 0024 */
  __asm__ volatile("" ::: "memory");  /* 0027: memw */
  __asm__ volatile("" ::: "memory");  /* 002a: memw */
  goto L_0059;  /* 002d: j */
  L_0030: a8 = 0;  /* 0030 */
  a10 = a10 + (-1);  /* 0032 */
  ST8(a2 + 0x4, a8);  /* 0034 */
  __asm__ volatile("" ::: "memory");  /* 0037: memw */
  a10 = (a10 >> 16) & 0x1;  /* 003a: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 003d: memw */
  a8 = (u32)&mesh_chain_header_add_ttl;  /* 0040: l32r -> func addr */
  a2 = mesh_chain_header_add_ttl(a2, a3, a4, a5, a6, a7);  /* 0043: callx a8 via reloc-expand */
  a8 = 23;  /* 0046 */
  a11 = 1;  /* 0048 */
  a9 = LD32(a3 + 0x0);  /* 004a */
  a3 = 28;  /* 004c */
  if (a9 != 0) a8 = a3;  /* 004e */
  a12 = a2 + a8;  /* 0051 */
  a8 = (u32)&mesh_add_option;  /* 0053: l32r -> func addr */
  a2 = mesh_add_option(a2, a3, a4, a5, a6, a7);  /* 0056: callx a8 via reloc-expand */
  L_0059: a2 = 0;  /* 0059 */
  return a2;  /* 005b: retw.n */
}


/* mesh_send_stop_vote @ mesh.o 00000048 size 360B bind GLOBAL
 * Calls: memcpy, esp_mesh_create_context, mesh_send_process_topo, esp_mesh_push_to_tx_queue, esp_mesh_free_context | indirect[1]: mem[a2+0xa0] | Data refs: g_mesh_is_root, .rodata.mesh_send_stop_vote.str1.1, g_mesh_topology, .rodata.__func__$2, g_mesh_self_sta_addr, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=11); reloc-direct=5, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_send_stop_vote(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a7, a8, a9;
  /* 0048: entry a1, 48 (frame 48 bytes) */
  a7 = (u32)&g_mesh_is_root + 0x0;  /* 004b: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 004e: memw */
  a3 = LD8U(a7 + 0x0);  /* 0051 */
  a3 = (a3 >> 8) & 0x1;  /* 0054: extui width 1 */
  if (a2 != 0) goto L_0061;  /* 0057: bnez.n a2, 61 <mesh_send_stop_vote+0x19> */
  L_0059: a5 = 0;  /* 0059 */
  if (a3 == a5) goto L_0061;  /* 005b: beq a3, a5, 61 <mesh_send_stop_vote+0x19> */
  L_005e: goto L_01ac;  /* 005e: j */
  L_0061: a11 = (u32)(RODATA__rodata_mesh_send_stop_vote_str1_1 + 0x0);  /* 0061: l32r -> .rodata.mesh_send_stop_vote.str1.1 */
  a12 = 6;  /* 0064 */
  a10 = a1;  /* 0066 */
  a8 = (u32)&memcpy + 0x0;  /* 0068: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 006b: callx a8 (libc, via reloc-expand) */
  a3 = 0;  /* 006e */
  a4 = (u32)&g_mesh_topology + 0x0;  /* 0070: l32r -> global */
  a5 = 7;  /* 0073 */
  a10 = LD32(a4 + 0x0);  /* 0075 */
  ST32(a1 + 0x8, a3);  /* 0077 */
  if (a10 == a3) goto L_0080;  /* 0079: beq a10, a3, 80 <mesh_send_stop_vote+0x38> */
  L_007c: a5 = 8;  /* 007c */
  a10 = 1;  /* 007e */
  L_0080: a10 = a10 + a5;  /* 0080 */
  a3 = (u32)(RODATA__rodata___func___2 + 0x0);  /* 0082: -> "mesh_send_stop_vote" */
  a10 = a10 << 2;  /* 0085 */
  a11 = a3;  /* 0088 */
  a10 = a10 + (14);  /* 008a */
  a12 = 0x00000979u;  /* 008c: l32r = 2425 */
  __asm__ volatile("" ::: "memory");  /* 008f: memw */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 0092: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6);  /* 0095: callx a8 via reloc-expand */
  ST32(a1 + 0x8, a10);  /* 0098 */
  a5 = 0x00004007u;  /* 009a: l32r = 16391 */
  if (a10 == 0) goto L_01ac;  /* 009d: beqz a10, 1ac <mesh_send_stop_vote+0x164> */
  L_00a0: a8 = -16;  /* 00a0 */
  a11 = 8;  /* 00a2 */
  a12 = a11;  /* 00a4 */
  a5 = LD32(a10 + 0x0);  /* 00a6 */
  a9 = 1;  /* 00a8 */
  a10 = a5 + (14);  /* 00aa */
  a6 = LD8U(a5 + 0xe);  /* 00ac */
  a6 = a6 & a8;  /* 00af */
  a8 = 1;  /* 00b2 */
  a6 = a6 | a8;  /* 00b4 */
  a4 = LD32(a4 + 0x0);  /* 00b7 */
  a8 = 0;  /* 00b9 */
  if (a4 != 0) a8 = a9;  /* 00bb */
  ST8(a5 + 0xe, a6);  /* 00be */
  a6 = 7;  /* 00c1 */
  if (a4 == 0) a12 = a6;  /* 00c3 */
  a8 = a8 + a12;  /* 00c6 */
  ST8(a5 + 0xf, a8);  /* 00c8 */
  __asm__ volatile("" ::: "memory");  /* 00cb: memw */
  if (a4 == 0) goto L_00d4;  /* 00ce: beqz.n a4, d4 <mesh_send_stop_vote+0x8c> */
  L_00d0: a6 = a11;  /* 00d0 */
  a4 = a9;  /* 00d2 */
  L_00d4: a4 = a4 + a6;  /* 00d4 */
  a4 = a4 << 2;  /* 00d6 */
  ST16(a5 + 0x10, a4);  /* 00d9 */
  __asm__ volatile("" ::: "memory");  /* 00dc: memw */
  __asm__ volatile("" ::: "memory");  /* 00df: memw */
  a8 = (u32)&mesh_send_process_topo;  /* 00e2: l32r -> func addr */
  a2 = mesh_send_process_topo(a2, a3, a4, a5, a6);  /* 00e5: callx a8 via reloc-expand */
  a8 = a5 + (18);  /* 00e8 */
  a12 = 6;  /* 00eb */
  a11 = a1;  /* 00ed */
  a4 = LD32(a8 + 0x0);  /* 00ef */
  a10 = a5 + (22);  /* 00f1 */
  a6 = 0xfd7f3fffu;  /* 00f4: l32r = -41992193 */
  a4 = a4 & a6;  /* 00f7 */
  a6 = 0x501;  /* 00fa */
  a6 = a6 << 15;  /* 00fd */
  a4 = a4 | a6;  /* 0100 */
  ST32(a8 + 0x0, a4);  /* 0103 */
  __asm__ volatile("" ::: "memory");  /* 0105: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0108: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 010b: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 010e */
  a10 = a5 + (28);  /* 0110 */
  a6 = (u32)&g_mesh_self_sta_addr + 0x0;  /* 0113: l32r -> global */
  a11 = a6;  /* 0116 */
  a8 = (u32)&memcpy + 0x0;  /* 0118: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 011b: callx a8 (libc, via reloc-expand) */
  a8 = 1;  /* 011e */
  a5 = LD16U(a5 + 0x10);  /* 0120 */
  a12 = 6;  /* 0123 */
  a5 = a5 + (14);  /* 0125 */
  a11 = a6;  /* 0127 */
  a4 = LD32(a1 + 0x8);  /* 0129 */
  a10 = a4 + (12);  /* 012b */
  ST16(a4 + 0x4, a5);  /* 012d */
  __asm__ volatile("" ::: "memory");  /* 0130: memw */
  a5 = LD32(a4 + 0x28);  /* 0133 */
  a5 = a5 | a8;  /* 0135 */
  ST32(a4 + 0x28, a5);  /* 0138 */
  a5 = 2;  /* 013a */
  __asm__ volatile("" ::: "memory");  /* 013c: memw */
  a8 = LD8U(a7 + 0x0);  /* 013f */
  a7 = -11;  /* 0142 */
  a8 = (a8 >> 8) & 0x1;  /* 0144: extui width 1 */
  a8 = a8 << 3;  /* 0147 */
  a8 = a8 | a5;  /* 014a */
  a5 = 10;  /* 014d */
  a8 = a8 & a5;  /* 0150 */
  a5 = LD8U(a4 + 0x28);  /* 0153 */
  a5 = a5 & a7;  /* 0156 */
  a8 = a8 | a5;  /* 0159 */
  ST8(a4 + 0x28, a8);  /* 015c */
  ST8(a4 + 0x12, a2);  /* 015f */
  __asm__ volatile("" ::: "memory");  /* 0162: memw */
  __asm__ volatile("" ::: "memory");  /* 0165: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0168: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 016b: callx a8 (libc, via reloc-expand) */
  a12 = 6;  /* 016e */
  a11 = a1;  /* 0170 */
  a10 = a4 + a12;  /* 0172 */
  a2 = -1;  /* 0174 */
  a8 = (u32)&memcpy + 0x0;  /* 0176: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6);  /* 0179: callx a8 (libc, via reloc-expand) */
  ST32(a4 + 0x20, a2);  /* 017c */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 017e: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0181 */
  a10 = LD32(a4 + 0x24);  /* 0183 */
  a2 = LD32(a2 + 0xa0);  /* 0185 */
  __asm__ volatile("" ::: "memory");  /* 0188: memw */
  /* 018b: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 018e */
  a10 = a1 + (8);  /* 0190 */
  a8 = (u32)&esp_mesh_push_to_tx_queue + 0x0;  /* 0192: l32r -> global */
  a2 = esp_mesh_push_to_tx_queue(a2, a3, a4, a5, a6);  /* 0195: callx a8 via reloc-expand */
  a5 = a10;  /* 0198 */
  if (a10 == 0) goto L_01ac;  /* 019a: beqz.n a10, 1ac <mesh_send_stop_vote+0x164> */
  L_019c: a12 = 0x265;  /* 019c */
  a10 = LD32(a1 + 0x8);  /* 019f */
  a12 = a12 << 2;  /* 01a1 */
  a11 = a3;  /* 01a4 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 01a6: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6);  /* 01a9: callx a8 via reloc-expand */
  L_01ac: a2 = a5;  /* 01ac */
  return a2;  /* 01ae: retw.n */
}


/* mesh_set_id @ mesh.o 0000003c size 156B bind GLOBAL
 * Calls: memset, esp_wifi_vnd_mesh_get, memcpy, mesh_encrypt_ie_plain_key, esp_wifi_vnd_mesh_set | indirect[2]: mem[a2+0x158]; mem[a2+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_ext_cfg, .data.s_mesh_ie_crypto_plain_key, g_mesh_ie
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=11); reloc-direct=5, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_set_id(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 003c: entry a1, 112 (frame 112 bytes) */
  if (a2 != 0) goto L_0080;  /* 003f: bnez.n a2, 80 <mesh_set_id+0x44> */
  L_0041: a2 = (u32)&g_log_level + 0x0;  /* 0041: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0044 */
  a3 = 0x00004008u;  /* 0046: l32r = 16392 */
  if (a2 >= 3u) goto L_004f;  /* 0049: bgeui a2, 3, 4f <mesh_set_id+0x13> */
  L_004c: goto L_00d4;  /* 004c: j */
  L_004f: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 004f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0052 */
  if (a2 == 0) goto L_00d4;  /* 0054: beqz a2, d4 <mesh_set_id+0x98> */
  L_0057: a4 = LD32(a2 + 0x150);  /* 0057 */
  if (a4 == 0) goto L_00d4;  /* 005a: beqz a4, d4 <mesh_set_id+0x98> */
  L_005d: a10 = LD32(a2 + 0x158);  /* 005d */
  a2 = 0x6a2;  /* 0060 */
  /* 0063: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0066 */
  a10 = 3;  /* 0068 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 006a: -> "mesh" */
  a14 = a11;  /* 006d */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 006f: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0072: -> "mesh" */
  ST32(a1 + 0x0, a2);  /* 0075 */
  __asm__ volatile("" ::: "memory");  /* 0077: memw */
  /* 007a: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_00d4;  /* 007d: j */
  L_0080: a12 = 58;  /* 0080 */
  a11 = 0;  /* 0082 */
  a10 = a1 + (16);  /* 0084 */
  a8 = (u32)&memset + 0x0;  /* 0087: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 008a: callx a8 (libc, via reloc-expand) */
  a11 = 0;  /* 008d */
  a10 = a1 + (16);  /* 008f */
  a8 = (u32)&esp_wifi_vnd_mesh_get + 0x0;  /* 0092: l32r -> global */
  a2 = esp_wifi_vnd_mesh_get(a2, a3, a4, a5, a6, a7);  /* 0095: callx a8 via reloc-expand */
  a4 = a10;  /* 0098 */
  a3 = 1;  /* 009a */
  if (a10 != 0) goto L_00d4;  /* 009c: bnez.n a10, d4 <mesh_set_id+0x98> */
  L_009e: a10 = (u32)&g_mesh_ext_cfg + 0x0;  /* 009e: l32r -> global */
  a12 = 6;  /* 00a1 */
  a10 = a10 + a12;  /* 00a3 */
  a11 = a2;  /* 00a5 */
  a8 = (u32)&memcpy + 0x0;  /* 00a7: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00aa: callx a8 (libc, via reloc-expand) */
  a10 = (u32)&LOCAL__data_s_mesh_ie_crypto_plain_key + 0x0;  /* 00ad: l32r -> .data.s_mesh_ie_crypto_plain_key (same-object static) */
  a11 = a2;  /* 00b0: mov */
  a8 = (u32)&mesh_encrypt_ie_plain_key;  /* 00b3: l32r -> func addr */
  a2 = mesh_encrypt_ie_plain_key(a2, a3, a4, a5, a6, a7);  /* 00b6: callx a8 via reloc-expand */
  a12 = 6;  /* 00b9 */
  a11 = a2;  /* 00bb */
  a3 = (u32)&g_mesh_ie + 0x0;  /* 00bd: l32r -> global */
  a10 = a3 + (8);  /* 00c0 */
  a8 = (u32)&memcpy + 0x0;  /* 00c2: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00c5: callx a8 (libc, via reloc-expand) */
  a10 = a3;  /* 00c8 */
  a11 = a4;  /* 00ca */
  a8 = (u32)&esp_wifi_vnd_mesh_set + 0x0;  /* 00cc: l32r -> global */
  a2 = esp_wifi_vnd_mesh_set(a2, a3, a4, a5, a6, a7);  /* 00cf: callx a8 via reloc-expand */
  a3 = a10;  /* 00d2 */
  L_00d4: a2 = a3;  /* 00d4 */
  return a2;  /* 00d6: retw.n */
}


/* mesh_set_ie_crypto_funcs @ mesh.o 00000010 size 45B bind GLOBAL
 * Calls: esp_wifi_disconnect, esp_mesh_set_ie_crypto_funcs_internal | Data refs: g_is_wifi_connected, g_is_wifi_disconnecting
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_set_ie_crypto_funcs(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_is_wifi_connected + 0x0;  /* 0013: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 0016 */
  if (a8 == 0) goto L_002e;  /* 0019: beqz.n a8, 2e <mesh_set_ie_crypto_funcs+0x1e> */
  L_001b: a8 = (u32)&esp_wifi_disconnect + 0x0;  /* 001b: l32r -> global */
  a2 = esp_wifi_disconnect(a2, a3, a4, a5, a6, a7);  /* 001e: callx a8 via reloc-expand */
  if (a10 != 0) goto L_002e;  /* 0021: bnez.n a10, 2e <mesh_set_ie_crypto_funcs+0x1e> */
  L_0023: a8 = (u32)&g_is_wifi_disconnecting + 0x0;  /* 0023: l32r -> global */
  a9 = 1;  /* 0026 */
  ST8(a8 + 0x0, a9);  /* 0028 */
  __asm__ volatile("" ::: "memory");  /* 002b: memw */
  L_002e: a10 = a2;  /* 002e */
  __asm__ volatile("" ::: "memory");  /* 0030: memw */
  a8 = (u32)&esp_mesh_set_ie_crypto_funcs_internal + 0x0;  /* 0033: l32r -> global */
  a2 = esp_mesh_set_ie_crypto_funcs_internal(a2, a3, a4, a5, a6, a7);  /* 0036: callx a8 via reloc-expand */
  a2 = a10;  /* 0039 */
  return a2;  /* 003b: retw.n */
}


/* mesh_set_ie_crypto_key @ mesh.o 00000014 size 48B bind GLOBAL
 * Calls: esp_wifi_disconnect, mesh_encrypt_ie_plain_key | Data refs: g_is_wifi_connected, g_is_wifi_disconnecting, g_mesh_ext_cfg
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=5); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_set_ie_crypto_key(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_is_wifi_connected + 0x0;  /* 0017: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 001a */
  if (a8 == 0) goto L_0032;  /* 001d: beqz.n a8, 32 <mesh_set_ie_crypto_key+0x1e> */
  L_001f: a8 = (u32)&esp_wifi_disconnect + 0x0;  /* 001f: l32r -> global */
  a2 = esp_wifi_disconnect(a2, a3, a4, a5, a6, a7);  /* 0022: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0032;  /* 0025: bnez.n a10, 32 <mesh_set_ie_crypto_key+0x1e> */
  L_0027: a8 = (u32)&g_is_wifi_disconnecting + 0x0;  /* 0027: l32r -> global */
  a9 = 1;  /* 002a */
  ST8(a8 + 0x0, a9);  /* 002c */
  __asm__ volatile("" ::: "memory");  /* 002f: memw */
  L_0032: a10 = a2;  /* 0032 */
  a11 = (u32)&g_mesh_ext_cfg + 0x6;  /* 0034: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0037: memw */
  a8 = (u32)&mesh_encrypt_ie_plain_key;  /* 003a: l32r -> func addr */
  a2 = mesh_encrypt_ie_plain_key(a2, a3, a4, a5, a6, a7);  /* 003d: callx a8 via reloc-expand */
  a2 = a10;  /* 0040 */
  return a2;  /* 0042: retw.n */
}


/* mesh_set_parent @ mesh.o 000000f4 size 1393B bind GLOBAL
 * Calls: memset, chm_check_channel_is_valid, strnlen, esp_wifi_set_mode, esp_wifi_get_mode, esp_wifi_set_non_mesh_connections, mesh_ie_type2str, mesh_set_self_organized, esp_wifi_disconnect, esp_wifi_get_config, esp_mesh_channel_enable_jp, memcpy, esp_wifi_set_config, esp_mesh_set_ap_password, esp_mesh_send_event_internal, esp_mesh_set_id, esp_mesh_set_router, esp_mesh_is_nwk_inited, esp_mesh_recv_release, mesh_nwk_manual_networking | indirect[15]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.mesh_set_parent.str1.1, g_mesh_ext_cfg, g_is_standalone_sta, g_mesh_max_layer, g_mesh_manual_nwk, g_is_wifi_connecting, g_is_wifi_disconnecting, g_is_wifi_connected, g_mesh_is_root +2 more
 * Fidelity: medium - 15 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=20, refs=34); reloc-direct=20, funcdb-attributed=0, unknown-indirect=15 */
u32 mesh_set_parent(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0;
  /* 00f4: entry a1, 0x170 (frame 0x170 bytes) */
  if (a2 != 0) goto L_0139;  /* 00f7: bnez.n a2, 139 <mesh_set_parent+0x45> */
  L_00f9: a2 = (u32)&g_log_level + 0x0;  /* 00f9: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 00fc */
  if (a2 >= 3u) goto L_0104;  /* 00fe: bgeui a2, 3, 104 <mesh_set_parent+0x10> */
  L_0101: goto L_0130;  /* 0101: j */
  L_0104: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0104: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0107 */
  if (a2 == 0) goto L_0130;  /* 0109: beqz.n a2, 130 <mesh_set_parent+0x3c> */
  L_010b: a3 = LD32(a2 + 0x150);  /* 010b */
  if (a3 == 0) goto L_0130;  /* 010e: beqz.n a3, 130 <mesh_set_parent+0x3c> */
  L_0110: a10 = LD32(a2 + 0x158);  /* 0110 */
  /* 0113: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0116 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0118: -> "mesh" */
  a14 = a11;  /* 011b */
  a2 = 0x0000085eu;  /* 011d: l32r = 2142 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0120: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0123: -> "mesh" */
  ST32(a1 + 0x0, a2);  /* 0126 */
  L_0128: a10 = 3;  /* 0128 */
  __asm__ volatile("" ::: "memory");  /* 012a: memw */
  /* 012d: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0130: a7 = 0x00004008u;  /* 0130: l32r = 16392 */
  goto L_0661;  /* 0133: j */
  L_0139: a10 = 184;  /* 0139 */
  a6 = a1 + (16);  /* 013c */
  a12 = 104;  /* 013f */
  a11 = 0;  /* 0142 */
  a10 = a6 + a10;  /* 0144 */
  a8 = (u32)&memset + 0x0;  /* 0147: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 014a: callx a8 (libc, via reloc-expand) */
  a10 = LD8U(a2 + 0x6b);  /* 014d */
  if (a10 == 0) goto L_018c;  /* 0150: beqz.n a10, 18c <mesh_set_parent+0x98> */
  L_0152: a8 = (u32)&chm_check_channel_is_valid + 0x0;  /* 0152: l32r -> global */
  a2 = chm_check_channel_is_valid(a2, a3, a4, a5, a6, a7);  /* 0155: callx a8 via reloc-expand */
  if (a10 != 0) goto L_018c;  /* 0158: bnez.n a10, 18c <mesh_set_parent+0x98> */
  L_015a: a3 = (u32)&g_log_level + 0x0;  /* 015a: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 015d */
  if (a3 < 3u) goto L_0130;  /* 015f: bltui a3, 3, 130 <mesh_set_parent+0x3c> */
  L_0162: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0162: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0165 */
  if (a3 == 0) goto L_0130;  /* 0167: beqz a3, 130 <mesh_set_parent+0x3c> */
  L_016a: a4 = LD32(a3 + 0x150);  /* 016a */
  if (a4 == 0) goto L_0130;  /* 016d: beqz a4, 130 <mesh_set_parent+0x3c> */
  L_0170: a10 = LD32(a3 + 0x158);  /* 0170 */
  /* 0173: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0176 */
  a10 = 3;  /* 0178 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 017a: -> "mesh" */
  a14 = a11;  /* 017d */
  a15 = LD8U(a2 + 0x6b);  /* 017f */
  a12 = (u32)(RODATA__rodata_mesh_set_parent_str1_1 + 0x0);  /* 0182: l32r -> .rodata.mesh_set_parent.str1.1 */
  /* 0185: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0130;  /* 0188: j */
  L_018c: a11 = 32;  /* 018c */
  a10 = a2;  /* 018e */
  a8 = (u32)&strnlen + 0x0;  /* 0190: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0193: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_01c1;  /* 0196: bnez.n a10, 1c1 <mesh_set_parent+0xcd> */
  L_0198: a2 = (u32)&g_log_level + 0x0;  /* 0198: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 019b */
  if (a2 < 3u) goto L_0130;  /* 019d: bltui a2, 3, 130 <mesh_set_parent+0x3c> */
  L_01a0: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01a0: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01a3 */
  if (a2 == 0) goto L_0130;  /* 01a5: beqz a2, 130 <mesh_set_parent+0x3c> */
  L_01a8: a3 = LD32(a2 + 0x150);  /* 01a8 */
  if (a3 == 0) goto L_0130;  /* 01ab: beqz a3, 130 <mesh_set_parent+0x3c> */
  L_01ae: a10 = LD32(a2 + 0x158);  /* 01ae */
  /* 01b1: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01b4 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 01b6: -> "mesh" */
  a14 = a11;  /* 01b9 */
  a12 = (u32)(RODATA__rodata_mesh_set_parent_str1_1 + 0x0);  /* 01bb: l32r -> .rodata.mesh_set_parent.str1.1 */
  goto L_0203;  /* 01be: j */
  L_01c1: a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 01c1: l32r -> global */
  a6 = LD32(a8 + 0xc8);  /* 01c4 */
  if (a6 != 0) goto L_020b;  /* 01c7: bnez a6, 20b <mesh_set_parent+0x117> */
  L_01ca: if (a4 == 1) goto L_020b;  /* 01ca: beqi a4, 1, 20b <mesh_set_parent+0x117> */
  L_01cd: a11 = 64;  /* 01cd */
  a10 = a2 + (32);  /* 01cf */
  a8 = (u32)&strnlen + 0x0;  /* 01d2: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 01d5: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_020b;  /* 01d8: beqz.n a10, 20b <mesh_set_parent+0x117> */
  L_01da: a2 = (u32)&g_log_level + 0x0;  /* 01da: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01dd */
  if (a2 >= 3u) goto L_01e5;  /* 01df: bgeui a2, 3, 1e5 <mesh_set_parent+0xf1> */
  L_01e2: goto L_0130;  /* 01e2: j */
  L_01e5: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 01e5: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 01e8 */
  if (a2 == 0) goto L_0130;  /* 01ea: beqz a2, 130 <mesh_set_parent+0x3c> */
  L_01ed: a3 = LD32(a2 + 0x150);  /* 01ed */
  if (a3 == 0) goto L_0130;  /* 01f0: beqz a3, 130 <mesh_set_parent+0x3c> */
  L_01f3: a10 = LD32(a2 + 0x158);  /* 01f3 */
  /* 01f6: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01f9 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 01fb: -> "mesh" */
  a14 = a11;  /* 01fe */
  a12 = (u32)(RODATA__rodata_mesh_set_parent_str1_1 + 0x0);  /* 0200: l32r -> .rodata.mesh_set_parent.str1.1 */
  L_0203: a10 = 3;  /* 0203 */
  /* 0205: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0130;  /* 0208: j */
  L_020b: a6 = (u32)&g_is_standalone_sta + 0x0;  /* 020b: l32r -> global */
  a8 = 0;  /* 020e */
  ST8(a6 + 0x0, a8);  /* 0210 */
  __asm__ volatile("" ::: "memory");  /* 0213: memw */
  if (a4 == 2) goto L_0238;  /* 0216: beqi a4, 2, 238 <mesh_set_parent+0x144> */
  L_0219: if (a4 == 3) goto L_024d;  /* 0219: beqi a4, 3, 24d <mesh_set_parent+0x159> */
  L_021c: if (a4 != 1) goto L_0299;  /* 021c: bnei a4, 1, 299 <mesh_set_parent+0x1a5> */
  L_021f: if (a5 == 1) goto L_0225;  /* 021f: beqi a5, 1, 225 <mesh_set_parent+0x131> */
  L_0222: goto L_0130;  /* 0222: j */
  L_0225: a6 = (u32)&g_mesh_max_layer + 0x0;  /* 0225: l32r -> global */
  a6 = LD16U(a6 + 0x0);  /* 0228 */
  if ((i32)a6 < (i32)a5) goto L_0231;  /* 022b: blt a6, a5, 231 <mesh_set_parent+0x13d> */
  L_022e: goto L_0308;  /* 022e: j */
  L_0231: __asm__ volatile("" ::: "memory");  /* 0231: memw */
  goto L_02cf;  /* 0234: j */
  L_0238: a6 = (u32)&g_mesh_max_layer + 0x0;  /* 0238: l32r -> global */
  a6 = LD16U(a6 + 0x0);  /* 023b */
  if ((i32)a5 < (i32)a6) goto L_0244;  /* 023e: blt a5, a6, 244 <mesh_set_parent+0x150> */
  L_0241: goto L_0130;  /* 0241: j */
  L_0244: if (a5 == 1) goto L_024a;  /* 0244: beqi a5, 1, 24a <mesh_set_parent+0x156> */
  L_0247: goto L_02cc;  /* 0247: j */
  L_024a: goto L_0130;  /* 024a: j */
  L_024d: a10 = 1;  /* 024d */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 024f: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 0252: callx a8 via reloc-expand */
  a7 = a10;  /* 0255 */
  if (a10 == 0) goto L_0288;  /* 0257: beqz.n a10, 288 <mesh_set_parent+0x194> */
  L_0259: a2 = (u32)&g_log_level + 0x0;  /* 0259: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 025c */
  if (a2 >= 3u) goto L_0264;  /* 025e: bgeui a2, 3, 264 <mesh_set_parent+0x170> */
  L_0261: goto L_0661;  /* 0261: j */
  L_0264: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0264: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0267 */
  if (a2 == 0) goto L_0661;  /* 0269: beqz a2, 661 <mesh_set_parent+0x56d> */
  L_026c: a3 = LD32(a2 + 0x150);  /* 026c */
  if (a3 == 0) goto L_0661;  /* 026f: beqz a3, 661 <mesh_set_parent+0x56d> */
  L_0272: a10 = LD32(a2 + 0x158);  /* 0272 */
  /* 0275: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a15 = a7;  /* 0278 */
  a13 = a10;  /* 027a */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 027c: -> "mesh" */
  a14 = a11;  /* 027f */
  a12 = (u32)(RODATA__rodata_mesh_set_parent_str1_1 + 0x0);  /* 0281: l32r -> .rodata.mesh_set_parent.str1.1 */
  goto L_0422;  /* 0284: j */
  L_0288: a8 = 1;  /* 0288 */
  ST8(a6 + 0x0, a8);  /* 028a */
  __asm__ volatile("" ::: "memory");  /* 028d: memw */
  __asm__ volatile("" ::: "memory");  /* 0290: memw */
  goto L_02cc;  /* 0293: j */
  L_0299: a2 = (u32)&g_log_level + 0x0;  /* 0299: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 029c */
  if (a2 >= 3u) goto L_02a4;  /* 029e: bgeui a2, 3, 2a4 <mesh_set_parent+0x1b0> */
  L_02a1: goto L_0130;  /* 02a1: j */
  L_02a4: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 02a4: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 02a7 */
  if (a2 == 0) goto L_0130;  /* 02a9: beqz a2, 130 <mesh_set_parent+0x3c> */
  L_02ac: a3 = LD32(a2 + 0x150);  /* 02ac */
  if (a3 == 0) goto L_0130;  /* 02af: beqz a3, 130 <mesh_set_parent+0x3c> */
  L_02b2: a10 = LD32(a2 + 0x158);  /* 02b2 */
  /* 02b5: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 02b8 */
  a15 = a4;  /* 02ba */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 02bc: -> "mesh" */
  a10 = 3;  /* 02bf */
  a14 = a11;  /* 02c1 */
  a12 = (u32)(RODATA__rodata_mesh_set_parent_str1_1 + 0x0);  /* 02c3: l32r -> .rodata.mesh_set_parent.str1.1 */
  /* 02c6: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0130;  /* 02c9: j */
  L_02cc: if (a5 != 0) goto L_0225;  /* 02cc: bnez a5, 225 <mesh_set_parent+0x131> */
  L_02cf: a2 = (u32)&g_log_level + 0x0;  /* 02cf: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 02d2 */
  if (a2 >= 3u) goto L_02da;  /* 02d4: bgeui a2, 3, 2da <mesh_set_parent+0x1e6> */
  L_02d7: goto L_0130;  /* 02d7: j */
  L_02da: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 02da: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 02dd */
  if (a2 == 0) goto L_0130;  /* 02df: beqz a2, 130 <mesh_set_parent+0x3c> */
  L_02e2: a3 = LD32(a2 + 0x150);  /* 02e2 */
  if (a3 == 0) goto L_0130;  /* 02e5: beqz a3, 130 <mesh_set_parent+0x3c> */
  L_02e8: a10 = LD32(a2 + 0x158);  /* 02e8 */
  /* 02eb: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a15 = a5;  /* 02ee */
  a13 = a10;  /* 02f0 */
  a2 = (u32)&g_mesh_max_layer + 0x0;  /* 02f2: l32r -> global */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 02f5: -> "mesh" */
  a14 = a11;  /* 02f8 */
  a2 = LD16U(a2 + 0x0);  /* 02fa */
  a12 = (u32)(RODATA__rodata_mesh_set_parent_str1_1 + 0x0);  /* 02fd: l32r -> .rodata.mesh_set_parent.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0300 */
  __asm__ volatile("" ::: "memory");  /* 0302: memw */
  goto L_0128;  /* 0305: j */
  L_0308: if (a4 == 3) goto L_0380;  /* 0308: beqi a4, 3, 380 <mesh_set_parent+0x28c> */
  L_030b: a10 = 0x120;  /* 030b */
  a9 = a1 + (16);  /* 030e */
  a10 = a9 + a10;  /* 0311 */
  a8 = (u32)&esp_wifi_get_mode + 0x0;  /* 0313: l32r -> global */
  a2 = esp_wifi_get_mode(a2, a3, a4, a5, a6, a7);  /* 0316: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0321;  /* 0319: bnez.n a10, 321 <mesh_set_parent+0x22d> */
  L_031b: a6 = LD32(a1 + 0x130);  /* 031b */
  if (a6 == 3) goto L_0380;  /* 031e: beqi a6, 3, 380 <mesh_set_parent+0x28c> */
  L_0321: a10 = 3;  /* 0321 */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 0323: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 0326: callx a8 via reloc-expand */
  a6 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0329: l32r -> global */
  a7 = a10;  /* 032c: mov */
  a10 = LD8U(a6 + 0xbc);  /* 032f */
  a8 = (u32)&esp_wifi_set_non_mesh_connections + 0x0;  /* 0332: l32r -> global */
  a2 = esp_wifi_set_non_mesh_connections(a2, a3, a4, a5, a6, a7);  /* 0335: callx a8 via reloc-expand */
  if (a7 == 0) goto L_0380;  /* 0338: beqz a7, 380 <mesh_set_parent+0x28c> */
  L_033b: a2 = (u32)&g_log_level + 0x0;  /* 033b: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 033e */
  if (a2 >= 3u) goto L_0346;  /* 0340: bgeui a2, 3, 346 <mesh_set_parent+0x252> */
  L_0343: goto L_0661;  /* 0343: j */
  L_0346: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0346: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0349 */
  if (a2 == 0) goto L_0661;  /* 034b: beqz a2, 661 <mesh_set_parent+0x56d> */
  L_034e: a3 = LD32(a2 + 0x150);  /* 034e */
  if (a3 == 0) goto L_0661;  /* 0351: beqz a3, 661 <mesh_set_parent+0x56d> */
  L_0354: a10 = LD32(a2 + 0x158);  /* 0354 */
  /* 0357: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 035a */
  a10 = a4;  /* 035c */
  a8 = (u32)&mesh_ie_type2str + 0x0;  /* 035e: l32r -> global */
  a2 = mesh_ie_type2str(a2, a3, a4, a5, a6, a7);  /* 0361: callx a8 via reloc-expand */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0364: -> "mesh" */
  a15 = a10;  /* 0367 */
  a14 = a11;  /* 0369 */
  a13 = a2;  /* 036b */
  a10 = 3;  /* 036d */
  a12 = (u32)(RODATA__rodata_mesh_set_parent_str1_1 + 0x0);  /* 0370: l32r -> .rodata.mesh_set_parent.str1.1 */
  ST32(a1 + 0x0, a7);  /* 0373 */
  __asm__ volatile("" ::: "memory");  /* 0376: memw */
  /* 0379: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0661;  /* 037c: j */
  L_0380: a6 = (u32)&g_mesh_manual_nwk + 0x0;  /* 0380: l32r -> global */
  a10 = 0;  /* 0383 */
  a12 = a10;  /* 0385 */
  a11 = a10;  /* 0387 */
  ST32(a6 + 0x0, a10);  /* 0389 */
  ST32(a6 + 0x4, a10);  /* 038c */
  __asm__ volatile("" ::: "memory");  /* 038f: memw */
  a8 = (u32)&mesh_set_self_organized + 0x0;  /* 0392: l32r -> global */
  a2 = mesh_set_self_organized(a2, a3, a4, a5, a6, a7);  /* 0395: callx a8 via reloc-expand */
  a8 = (u32)&g_is_wifi_connecting + 0x0;  /* 0398: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 039b */
  if (a8 != 0) goto L_03a8;  /* 039e: bnez.n a8, 3a8 <mesh_set_parent+0x2b4> */
  L_03a0: a9 = (u32)&g_is_wifi_disconnecting + 0x0;  /* 03a0: l32r -> global */
  a8 = LD8U(a9 + 0x0);  /* 03a3 */
  if (a8 == 0) goto L_03b9;  /* 03a6: beqz.n a8, 3b9 <mesh_set_parent+0x2c5> */
  L_03a8: a8 = 0;  /* 03a8 */
  ST8(a6 + 0x6, a8);  /* 03aa */
  __asm__ volatile("" ::: "memory");  /* 03ad: memw */
  __asm__ volatile("" ::: "memory");  /* 03b0: memw */
  goto L_03e0;  /* 03b3: j */
  L_03b9: a9 = (u32)&g_is_wifi_connected + 0x0;  /* 03b9: l32r -> global */
  a7 = 1;  /* 03bc */
  a9 = LD8U(a9 + 0x0);  /* 03be */
  ST8(a6 + 0x6, a7);  /* 03c1 */
  __asm__ volatile("" ::: "memory");  /* 03c4: memw */
  if (a9 == 0) goto L_03e0;  /* 03c7: beqz.n a9, 3e0 <mesh_set_parent+0x2ec> */
  L_03c9: __asm__ volatile("" ::: "memory");  /* 03c9: memw */
  a8 = (u32)&esp_wifi_disconnect + 0x0;  /* 03cc: l32r -> global */
  a2 = esp_wifi_disconnect(a2, a3, a4, a5, a6, a7);  /* 03cf: callx a8 via reloc-expand */
  if (a10 != 0) goto L_03e0;  /* 03d2: bnez.n a10, 3e0 <mesh_set_parent+0x2ec> */
  L_03d4: a8 = (u32)&g_is_wifi_disconnecting + 0x0;  /* 03d4: l32r -> global */
  ST8(a6 + 0x6, a10);  /* 03d7 */
  ST8(a8 + 0x0, a7);  /* 03da */
  __asm__ volatile("" ::: "memory");  /* 03dd: memw */
  L_03e0: a11 = a1 + (16);  /* 03e0 */
  a10 = 1;  /* 03e3 */
  __asm__ volatile("" ::: "memory");  /* 03e5: memw */
  a8 = (u32)&esp_wifi_get_config + 0x0;  /* 03e8: l32r -> global */
  a2 = esp_wifi_get_config(a2, a3, a4, a5, a6, a7);  /* 03eb: callx a8 via reloc-expand */
  a7 = a10;  /* 03ee */
  if (a10 == 0) goto L_042c;  /* 03f0: beqz.n a10, 42c <mesh_set_parent+0x338> */
  L_03f2: a2 = (u32)&g_log_level + 0x0;  /* 03f2: l32r -> global */
  a7 = 1;  /* 03f5 */
  a2 = LD32(a2 + 0x0);  /* 03f8 */
  if (a2 >= 3u) goto L_0401;  /* 03fb: bgeui a2, 3, 401 <mesh_set_parent+0x30d> */
  L_03fe: goto L_0661;  /* 03fe: j */
  L_0401: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0401: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0404 */
  if (a2 == 0) goto L_0661;  /* 0406: beqz a2, 661 <mesh_set_parent+0x56d> */
  L_0409: a3 = LD32(a2 + 0x150);  /* 0409 */
  if (a3 == 0) goto L_0661;  /* 040c: beqz a3, 661 <mesh_set_parent+0x56d> */
  L_040f: a10 = LD32(a2 + 0x158);  /* 040f */
  /* 0412: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a15 = a7;  /* 0415 */
  a13 = a10;  /* 0417 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0419: -> "mesh" */
  a14 = a11;  /* 041c: mov */
  a12 = (u32)(RODATA__rodata_mesh_set_parent_str1_1 + 0x0);  /* 041f: l32r -> .rodata.mesh_set_parent.str1.1 */
  L_0422: a10 = 3;  /* 0422 */
  /* 0425: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0661;  /* 0428: j */
  L_042c: a9 = LD8U(a2 + 0x6b);  /* 042c */
  a10 = LD8U(a1 + 0x71);  /* 042f */
  if (a10 != a9) goto L_043d;  /* 0432: bne a10, a9, 43d <mesh_set_parent+0x349> */
  L_0435: if (a4 != 1) goto L_044f;  /* 0435: bnei a4, 1, 44f <mesh_set_parent+0x35b> */
  L_0438: goto L_065b;  /* 0438: j */
  L_043d: a8 = 14;  /* 043d */
  if (a9 != a8) goto L_0460;  /* 043f: bne a9, a8, 460 <mesh_set_parent+0x36c> */
  L_0442: a8 = (u32)&esp_mesh_channel_enable_jp + 0x0;  /* 0442: l32r -> global */
  a2 = esp_mesh_channel_enable_jp(a2, a3, a4, a5, a6, a7);  /* 0445: callx a8 via reloc-expand */
  a7 = a10;  /* 0448 */
  if (a10 == 0) goto L_0460;  /* 044a: beqz.n a10, 460 <mesh_set_parent+0x36c> */
  L_044c: goto L_0661;  /* 044c: j */
  L_044f: a11 = 64;  /* 044f */
  a10 = a2 + (32);  /* 0451 */
  a8 = (u32)&strnlen + 0x0;  /* 0454: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0457: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0471;  /* 045a: bnez.n a10, 471 <mesh_set_parent+0x37d> */
  L_045c: goto L_0655;  /* 045c: j */
  L_0460: a9 = 1;  /* 0460 */
  ST32(a1 + 0x140, a9);  /* 0462 */
  if (a4 != a9) goto L_0474;  /* 0465: bne a4, a9, 474 <mesh_set_parent+0x380> */
  L_0468: __asm__ volatile("" ::: "memory");  /* 0468: memw */
  goto L_04a9;  /* 046b: j */
  L_0471: ST32(a1 + 0x140, a7);  /* 0471 */
  L_0474: a7 = a2 + (32);  /* 0474 */
  a11 = 64;  /* 0477 */
  a10 = a7;  /* 0479 */
  __asm__ volatile("" ::: "memory");  /* 047b: memw */
  a8 = (u32)&strnlen + 0x0;  /* 047e: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0481: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_04a9;  /* 0484: beqz.n a10, 4a9 <mesh_set_parent+0x3b5> */
  L_0486: a10 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0486: l32r -> global */
  a11 = 64;  /* 0489 */
  a9 = LD32(a10 + 0xc8);  /* 048b */
  a10 = a7;  /* 048e */
  ST32(a1 + 0x74, a9);  /* 0490 */
  __asm__ volatile("" ::: "memory");  /* 0493: memw */
  a8 = (u32)&strnlen + 0x0;  /* 0496: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0499: callx a8 (libc, via reloc-expand) */
  a12 = a10;  /* 049c */
  a11 = a7;  /* 049e */
  a10 = a1 + (48);  /* 04a0 */
  a8 = (u32)&memcpy + 0x0;  /* 04a3: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 04a6: callx a8 (libc, via reloc-expand) */
  L_04a9: a8 = LD8U(a2 + 0x6b);  /* 04a9 */
  a11 = a1 + (16);  /* 04ac */
  a10 = 1;  /* 04af */
  a7 = 1;  /* 04b2 */
  ST8(a1 + 0x71, a8);  /* 04b5 */
  __asm__ volatile("" ::: "memory");  /* 04b8: memw */
  __asm__ volatile("" ::: "memory");  /* 04bb: memw */
  a8 = (u32)&esp_wifi_set_config + 0x0;  /* 04be: l32r -> global */
  a2 = esp_wifi_set_config(a2, a3, a4, a5, a6, a7);  /* 04c1: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0661;  /* 04c4: bnez a10, 661 <mesh_set_parent+0x56d> */
  L_04c7: if (a4 == a7) goto L_04e4;  /* 04c7: beq a4, a7, 4e4 <mesh_set_parent+0x3f0> */
  L_04ca: a7 = a2 + (32);  /* 04ca */
  a11 = 64;  /* 04cd */
  a10 = a7;  /* 04cf: mov */
  a8 = (u32)&strnlen + 0x0;  /* 04d2: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 04d5: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_04e4;  /* 04d8: beqz.n a10, 4e4 <mesh_set_parent+0x3f0> */
  L_04da: a11 = a10;  /* 04da */
  a10 = a7;  /* 04dc */
  a8 = (u32)&esp_mesh_set_ap_password;  /* 04de: l32r -> func addr */
  a2 = esp_mesh_set_ap_password(a2, a3, a4, a5, a6, a7);  /* 04e1: callx a8 via reloc-expand */
  L_04e4: a8 = LD32(a1 + 0x140);  /* 04e4 */
  if (a8 == 0) goto L_050a;  /* 04e7: beqz.n a8, 50a <mesh_set_parent+0x416> */
  L_04e9: a10 = a1 + (16);  /* 04e9 */
  a11 = 0x124;  /* 04ec */
  a9 = LD8U(a2 + 0x6b);  /* 04ef */
  a8 = a10 + 0x10000;  /* 04f2: addmi a8, a10, 0x100 */
  a11 = a10 + a11;  /* 04f5 */
  a12 = 1;  /* 04f7 */
  a10 = 2;  /* 04f9 */
  ST8(a8 + 0x24, a9);  /* 04fb */
  __asm__ volatile("" ::: "memory");  /* 04fe: memw */
  __asm__ volatile("" ::: "memory");  /* 0501: memw */
  a8 = (u32)&esp_mesh_send_event_internal + 0x0;  /* 0504: l32r -> global */
  a2 = esp_mesh_send_event_internal(a2, a3, a4, a5, a6, a7);  /* 0507: callx a8 via reloc-expand */
  L_050a: if (a3 != 0) goto L_0512;  /* 050a: bnez.n a3, 512 <mesh_set_parent+0x41e> */
  L_050c: if (a4 == 1) goto L_0525;  /* 050c: beqi a4, 1, 525 <mesh_set_parent+0x431> */
  L_050f: goto L_05a0;  /* 050f: j */
  L_0512: a10 = a3;  /* 0512 */
  a8 = (u32)&esp_mesh_set_id;  /* 0514: l32r -> func addr */
  a2 = esp_mesh_set_id(a2, a3, a4, a5, a6, a7);  /* 0517: callx a8 via reloc-expand */
  a7 = a10;  /* 051a */
  if (a10 == 0) goto L_050c;  /* 051c: beqz a10, 50c <mesh_set_parent+0x418> */
  L_051f: goto L_0661;  /* 051f: j */
  L_0525: if (a5 == 1) goto L_052b;  /* 0525: beqi a5, 1, 52b <mesh_set_parent+0x437> */
  L_0528: goto L_0130;  /* 0528: j */
  L_052b: a11 = 32;  /* 052b */
  a10 = a2;  /* 052d */
  a8 = (u32)&strnlen + 0x0;  /* 052f: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0532: callx a8 (libc, via reloc-expand) */
  ST8(a1 + 0xe8, a10);  /* 0535 */
  __asm__ volatile("" ::: "memory");  /* 0538: memw */
  a12 = (a10 >> 8) & 0x1;  /* 053b: extui width 1 */
  a3 = a1 + (16);  /* 053e */
  a10 = 184;  /* 0541 */
  a10 = a3 + a10;  /* 0544 */
  a11 = a2;  /* 0546 */
  __asm__ volatile("" ::: "memory");  /* 0548: memw */
  a8 = (u32)&memcpy + 0x0;  /* 054b: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 054e: callx a8 (libc, via reloc-expand) */
  a3 = LD8U(a2 + 0x64);  /* 0551 */
  if (a3 == 0) goto L_0569;  /* 0554: beqz.n a3, 569 <mesh_set_parent+0x475> */
  L_0556: a10 = 217;  /* 0556 */
  a8 = a1 + (16);  /* 0559 */
  a12 = 6;  /* 055c */
  a11 = a2 + (101);  /* 055e */
  a10 = a8 + a10;  /* 0561 */
  a8 = (u32)&memcpy + 0x0;  /* 0563: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0566: callx a8 (libc, via reloc-expand) */
  L_0569: a9 = a1 + (16);  /* 0569 */
  a10 = 223;  /* 056c */
  a12 = 64;  /* 056f */
  a11 = a2 + (32);  /* 0571 */
  a10 = a9 + a10;  /* 0574 */
  a8 = (u32)&memcpy + 0x0;  /* 0576: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0579: callx a8 (libc, via reloc-expand) */
  a10 = 184;  /* 057c */
  a3 = a1 + (16);  /* 057f */
  a10 = a3 + a10;  /* 0582 */
  a8 = (u32)&esp_mesh_set_router;  /* 0584: l32r -> func addr */
  a2 = esp_mesh_set_router(a2, a3, a4, a5, a6, a7);  /* 0587: callx a8 via reloc-expand */
  a7 = a10;  /* 058a */
  if (a10 != 0) goto L_0661;  /* 058c: bnez a10, 661 <mesh_set_parent+0x56d> */
  L_058f: a8 = (u32)&g_mesh_is_root + 0x0;  /* 058f: l32r -> global */
  a3 = 1;  /* 0592 */
  __asm__ volatile("" ::: "memory");  /* 0594: memw */
  ST8(a8 + 0x0, a3);  /* 0597 */
  a8 = (u32)&g_is_root_fixed + 0x0;  /* 059a: l32r -> global */
  ST8(a8 + 0x0, a3);  /* 059d */
  L_05a0: a11 = a2;  /* 05a0 */
  a12 = 184;  /* 05a2 */
  a10 = a1 + (16);  /* 05a5 */
  ST16(a6 + 0x4, a5);  /* 05a8 */
  __asm__ volatile("" ::: "memory");  /* 05ab: memw */
  ST32(a6 + 0x0, a4);  /* 05ae */
  __asm__ volatile("" ::: "memory");  /* 05b0: memw */
  a8 = (u32)&memcpy + 0x0;  /* 05b3: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 05b6: callx a8 (libc, via reloc-expand) */
  a11 = LD8U(a2 + 0x64);  /* 05b9 */
  if (a11 != 0) goto L_05c9;  /* 05bc: bnez.n a11, 5c9 <mesh_set_parent+0x4d5> */
  L_05be: a12 = 6;  /* 05be */
  a10 = a1 + (117);  /* 05c0 */
  a8 = (u32)&memset + 0x0;  /* 05c3: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 05c6: callx a8 (libc, via reloc-expand) */
  L_05c9: a11 = a1 + (16);  /* 05c9 */
  a10 = 0;  /* 05cc */
  a8 = (u32)&esp_wifi_set_config + 0x0;  /* 05ce: l32r -> global */
  a2 = esp_wifi_set_config(a2, a3, a4, a5, a6, a7);  /* 05d1: callx a8 via reloc-expand */
  a7 = a10;  /* 05d4 */
  if (a10 != 0) goto L_0661;  /* 05d6: bnez a10, 661 <mesh_set_parent+0x56d> */
  L_05d9: a3 = (u32)&g_mesh_current_parent + 0x0;  /* 05d9: l32r -> global */
  a11 = a10;  /* 05dc */
  a12 = 92;  /* 05de */
  a10 = a3;  /* 05e0 */
  a8 = (u32)&memset + 0x0;  /* 05e2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 05e5: callx a8 (libc, via reloc-expand) */
  a4 = LD8U(a2 + 0x64);  /* 05e8 */
  if (a4 == 0) goto L_05fa;  /* 05eb: beqz.n a4, 5fa <mesh_set_parent+0x506> */
  L_05ed: a12 = 6;  /* 05ed */
  a11 = a2 + (101);  /* 05ef */
  a10 = a3;  /* 05f2 */
  a8 = (u32)&memcpy + 0x0;  /* 05f4: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 05f7: callx a8 (libc, via reloc-expand) */
  L_05fa: a11 = a2;  /* 05fa */
  a10 = a3 + (6);  /* 05fc */
  a12 = 33;  /* 05ff */
  a8 = (u32)&memcpy + 0x0;  /* 0602: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0605: callx a8 (libc, via reloc-expand) */
  a3 = (u32)&g_mesh_is_root + 0x0;  /* 0608: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 060b: memw */
  a2 = LD8U(a3 + 0x0);  /* 060e */
  a2 = (a2 >> 8) & 0x1;  /* 0611: extui width 1 */
  if (a2 == 0) goto L_062c;  /* 0614: beqz a2, 62c <mesh_set_parent+0x538> */
  L_0617: a4 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0617: l32r -> global */
  a2 = LD8U(a4 + 0xc4);  /* 061a */
  a4 = -3;  /* 061d */
  a2 = a2 & a4;  /* 0620 */
  a8 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0623: l32r -> global */
  ST8(a8 + 0xc4, a2);  /* 0626 */
  __asm__ volatile("" ::: "memory");  /* 0629: memw */
  L_062c: __asm__ volatile("" ::: "memory");  /* 062c: memw */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 062f: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 0632: callx a8 via reloc-expand */
  if (a10 == 0) goto L_0661;  /* 0635: beqz.n a10, 661 <mesh_set_parent+0x56d> */
  L_0637: __asm__ volatile("" ::: "memory");  /* 0637: memw */
  a2 = LD8U(a3 + 0x0);  /* 063a */
  a2 = (a2 >> 8) & 0x1;  /* 063d: extui width 1 */
  if (a2 != 0) goto L_064a;  /* 0640: bnez.n a2, 64a <mesh_set_parent+0x556> */
  L_0642: a10 = 1;  /* 0642 */
  a8 = (u32)&esp_mesh_recv_release;  /* 0644: l32r -> func addr */
  a2 = esp_mesh_recv_release(a2, a3, a4, a5, a6, a7);  /* 0647: callx a8 via reloc-expand */
  L_064a: a10 = a6;  /* 064a */
  a8 = (u32)&mesh_nwk_manual_networking + 0x0;  /* 064c: l32r -> global */
  a2 = mesh_nwk_manual_networking(a2, a3, a4, a5, a6, a7);  /* 064f: callx a8 via reloc-expand */
  goto L_0661;  /* 0652: j */
  L_0655: if (a3 != 0) goto L_0512;  /* 0655: bnez a3, 512 <mesh_set_parent+0x41e> */
  L_0658: goto L_05a0;  /* 0658: j */
  L_065b: if (a3 != 0) goto L_0512;  /* 065b: bnez a3, 512 <mesh_set_parent+0x41e> */
  L_065e: goto L_0525;  /* 065e: j */
  L_0661: a2 = a7;  /* 0661 */
  return a2;  /* 0663: retw.n */
}


/* mesh_stop_recv @ mesh.o 00000044 size 391B bind GLOBAL
 * Calls: memset, esp_mesh_free_context | indirect[11]: mem[a3+0x158]; mem[a3+0x150]; mem[a7+0x70]; mem[a8+0x8c] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, g_mesh_stop_event_group, .rodata.mesh_stop_recv.str1.1, .rodata.__func__$13
 * Fidelity: medium - 11 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=8); reloc-direct=2, funcdb-attributed=0, unknown-indirect=11 */
u32 mesh_stop_recv(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0044: entry a1, 128 (frame 128 bytes) */
  ST32(a1 + 0x54, a4);  /* 0047 */
  a4 = 0;  /* 004a */
  a6 = a3;  /* 004c */
  a2 = (a2 >> 8) & 0x1;  /* 004e: extui width 1 */
  ST32(a1 + 0x50, a3);  /* 0051 */
  ST32(a1 + 0x58, a5);  /* 0054 */
  ST32(a1 + 0x40, a4);  /* 0057 */
  if (a3 != a4) goto L_00a4;  /* 005a: bne a3, a4, a4 <mesh_stop_recv+0x60> */
  L_005d: a2 = (u32)&g_log_level + 0x0;  /* 005d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0060 */
  a2 = 0x00004008u;  /* 0062: l32r = 16392 */
  if (a3 >= 3u) goto L_006b;  /* 0065: bgeui a3, 3, 6b <mesh_stop_recv+0x27> */
  L_0068: goto L_01c9;  /* 0068: j */
  L_006b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 006b: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 006e */
  if (a3 != a4) goto L_0077;  /* 0071: bne a3, a4, 77 <mesh_stop_recv+0x33> */
  L_0074: goto L_01c9;  /* 0074: j */
  L_0077: a4 = LD32(a3 + 0x150);  /* 0077 */
  if (a4 == 0) goto L_01c9;  /* 007a: beqz a4, 1c9 <mesh_stop_recv+0x185> */
  L_007d: a10 = LD32(a3 + 0x158);  /* 007d */
  a3 = 0x195;  /* 0080 */
  __asm__ volatile("" ::: "memory");  /* 0083: memw */
  /* 0086: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0089 */
  a10 = 3;  /* 008b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 008d: -> "mesh" */
  a14 = a11;  /* 0090 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0092: -> "mesh" */
  a12 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0095: -> "mesh" */
  ST32(a1 + 0x0, a3);  /* 0098 */
  __asm__ volatile("" ::: "memory");  /* 009a: memw */
  /* 009d: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01c9;  /* 00a0: j */
  L_00a4: a5 = LD8U(a1 + 0x58);  /* 00a4 */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a7: l32r -> global */
  if (((a5 >> 1) & 1) == 0) goto L_0125;  /* 00aa: bbci a5, 1, 125 <mesh_stop_recv+0xe1> */
  L_00ad: a9 = a1 + (16);  /* 00ad */
  a11 = a4;  /* 00b0 */
  a10 = a9;  /* 00b2 */
  a12 = 48;  /* 00b4 */
  a7 = LD32(a3 + 0x0);  /* 00b6 */
  a8 = (u32)&memset + 0x0;  /* 00b8: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00bb: callx a8 (libc, via reloc-expand) */
  a5 = 16;  /* 00be */
  a12 = a4;  /* 00c0 */
  a11 = a1 + (64);  /* 00c2 */
  a8 = LD32(a1 + 0x38);  /* 00c5 */
  a8 = a8 | a5;  /* 00c7 */
  ST32(a1 + 0x38, a8);  /* 00ca */
  a8 = LD32(a7 + 0x70);  /* 00cc */
  ST32(a1 + 0x40, a10);  /* 00cf */
  a10 = a6;  /* 00d2 */
  __asm__ volatile("" ::: "memory");  /* 00d4: memw */
  /* 00d7: INDIRECT callx a8 <- mem[a7+0x70]; result unknown */ a2 = 0;
  a12 = a4;  /* 00da */
  a11 = 32;  /* 00dc */
  a4 = (u32)&g_mesh_stop_event_group + 0x0;  /* 00de: l32r -> global */
  a14 = -1;  /* 00e1 */
  a13 = 1;  /* 00e3 */
  if (a2 == 0) a11 = a5;  /* 00e5 */
  a8 = LD32(a3 + 0x0);  /* 00e8 */
  a10 = LD32(a4 + 0x0);  /* 00ea */
  a8 = LD32(a8 + 0x8c);  /* 00ec */
  /* 00ef: INDIRECT callx a8 <- mem[a8+0x8c]; result unknown */ a2 = 0;
  a4 = LD32(a3 + 0x0);  /* 00f2 */
  if (a4 == 0) goto L_0125;  /* 00f4: beqz.n a4, 125 <mesh_stop_recv+0xe1> */
  L_00f6: a5 = LD32(a4 + 0x150);  /* 00f6 */
  if (a5 == 0) goto L_0125;  /* 00f9: beqz.n a5, 125 <mesh_stop_recv+0xe1> */
  L_00fb: a10 = LD32(a4 + 0x158);  /* 00fb */
  /* 00fe: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a4 = (u32)(RODATA__rodata_mesh_stop_recv_str1_1 + 0x0);  /* 0101: -> "MESH_STOP_EVENT_BIT_TODS" */
  if (a2 != 0) goto L_0109;  /* 0104: bnez.n a2, 109 <mesh_stop_recv+0xc5> */
  L_0106: a4 = (u32)(RODATA__rodata_mesh_stop_recv_str1_1 + 0x0);  /* 0106: -> "MESH_STOP_EVENT_BIT_TODS" */
  L_0109: a13 = a10;  /* 0109 */
  a10 = 2;  /* 010b */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 010d: -> "mesh" */
  a14 = a11;  /* 0110 */
  ST32(a1 + 0x4, a4);  /* 0112 */
  a4 = 0x19f;  /* 0114 */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0117: -> "mesh" */
  a12 = (u32)(RODATA__rodata_mesh_stop_recv_str1_1 + 0x0);  /* 011a: -> "MESH_STOP_EVENT_BIT_TODS" */
  ST32(a1 + 0x0, a4);  /* 011d */
  __asm__ volatile("" ::: "memory");  /* 011f: memw */
  /* 0122: INDIRECT callx a5 <- mem[a4+0x150]; result unknown */ a2 = 0;
  L_0125: a5 = (u32)(RODATA__rodata_mesh_stop_recv_str1_1 + 0x0);  /* 0125: -> "MESH_STOP_EVENT_BIT_TODS" */
  a4 = (u32)(RODATA__rodata_mesh_stop_recv_str1_1 + 0x0);  /* 0128: -> "MESH_STOP_EVENT_BIT_TODS" */
  if (a2 == 0) a4 = a5;  /* 012b */
  a5 = 0;  /* 012e */
  goto L_01ac;  /* 0130: j */
  L_0134: a2 = LD32(a1 + 0x40);  /* 0134 */
  a8 = LD32(a3 + 0x0);  /* 0137 */
  if (a2 == 0) goto L_0183;  /* 0139: beqz a2, 183 <mesh_stop_recv+0x13f> */
  L_013c: a2 = LD32(a2 + 0x28);  /* 013c */
  if (((a2 >> 4) & 1) != 0) goto L_0183;  /* 013e: bbsi a2, 4, 183 <mesh_stop_recv+0x13f> */
  L_0141: if (a8 == 0) goto L_0171;  /* 0141: beqz.n a8, 171 <mesh_stop_recv+0x12d> */
  L_0143: a2 = LD32(a8 + 0x150);  /* 0143 */
  if (a2 == 0) goto L_0171;  /* 0146: beqz.n a2, 171 <mesh_stop_recv+0x12d> */
  L_0148: a10 = LD32(a8 + 0x158);  /* 0148 */
  /* 014b: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 014e */
  a10 = 2;  /* 0150 */
  a8 = LD32(a1 + 0x40);  /* 0152 */
  a8 = LD16U(a8 + 0x4);  /* 0155 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0158: -> "mesh" */
  a14 = a11;  /* 015b */
  ST32(a1 + 0x4, a8);  /* 015d */
  a8 = 0x1a5;  /* 015f */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0162: -> "mesh" */
  a12 = (u32)(RODATA__rodata_mesh_stop_recv_str1_1 + 0x0);  /* 0165: -> "MESH_STOP_EVENT_BIT_TODS" */
  ST32(a1 + 0x0, a8);  /* 0168 */
  __asm__ volatile("" ::: "memory");  /* 016b: memw */
  /* 016e: INDIRECT callx a2 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_0171: a12 = 0x1a6;  /* 0171 */
  a11 = (u32)(RODATA__rodata___func___13 + 0x0);  /* 0174: l32r -> .rodata.__func__$13 */
  a10 = LD32(a1 + 0x40);  /* 0177 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 017a: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 017d: callx a8 via reloc-expand */
  goto L_01ac;  /* 0180: j */
  L_0183: if (a8 == 0) goto L_01ac;  /* 0183: beqz.n a8, 1ac <mesh_stop_recv+0x168> */
  L_0185: a2 = LD32(a8 + 0x150);  /* 0185 */
  if (a2 == 0) goto L_01ac;  /* 0188: beqz.n a2, 1ac <mesh_stop_recv+0x168> */
  L_018a: a10 = LD32(a8 + 0x158);  /* 018a */
  /* 018d: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 0x1a8;  /* 0190 */
  a13 = a10;  /* 0193 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0195: -> "mesh" */
  a10 = 2;  /* 0198 */
  a14 = a11;  /* 019a */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 019c: -> "mesh" */
  a12 = (u32)(RODATA__rodata_mesh_stop_recv_str1_1 + 0x0);  /* 019f: -> "MESH_STOP_EVENT_BIT_TODS" */
  ST32(a1 + 0x4, a4);  /* 01a2 */
  ST32(a1 + 0x0, a8);  /* 01a4 */
  __asm__ volatile("" ::: "memory");  /* 01a6: memw */
  /* 01a9: INDIRECT callx a2 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_01ac: a12 = 0;  /* 01ac */
  a11 = a1 + (64);  /* 01ae */
  a10 = a6;  /* 01b1 */
  a2 = LD32(a3 + 0x0);  /* 01b3 */
  a2 = LD32(a2 + 0x74);  /* 01b5 */
  ST32(a1 + 0x40, a5);  /* 01b8 */
  __asm__ volatile("" ::: "memory");  /* 01bb: memw */
  /* 01be: INDIRECT callx a2 <- mem[a2+0x74]; result unknown */ a2 = 0;
  if (a10 != 1) goto L_01c7;  /* 01c1: bnei a10, 1, 1c7 <mesh_stop_recv+0x183> */
  L_01c4: goto L_0134;  /* 01c4: j */
  L_01c7: a2 = 0;  /* 01c7 */
  L_01c9: return a2;  /* 01c9: retw.n */
}


/* mesh_waive_root @ mesh.o 00000018 size 145B bind GLOBAL
 * Calls: memcpy, esp_mesh_send_mgmt | Data refs: g_mesh_cfg_vote_percent, g_mesh_cfg_attemps, .data.MESH_BCAST_ADDR
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=5); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_waive_root(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8;
  float F0;
  /* 0018: entry a1, 64 (frame 64 bytes) */
  a11 = a3;  /* 001b */
  if (a3 == 0) goto L_002c;  /* 001d: beqz.n a3, 2c <mesh_waive_root+0x14> */
  L_001f: a12 = 16;  /* 001f */
  a10 = a1;  /* 0021 */
  a8 = (u32)&memcpy + 0x0;  /* 0023: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0026: callx a8 (libc, via reloc-expand) */
  goto L_004f;  /* 0029: j */
  L_002c: a2 = (u32)&g_mesh_cfg_vote_percent + 0x0;  /* 002c: l32r -> global */
  F0 = LD32F(a2 + 0x0);  /* 002f: lsi */
  a2 = 0x1f4;  /* 0032 */
  ST32F(a1 + 0x0, F0);  /* 0035: ssi */
  ST8(a1 + 0x4, a3);  /* 0038 */
  __asm__ volatile("" ::: "memory");  /* 003b: memw */
  if (a4 != 1) goto L_004d;  /* 003e: bnei a4, 1, 4d <mesh_waive_root+0x35> */
  L_0041: a2 = (u32)&g_mesh_cfg_attemps + 0x0;  /* 0041: l32r -> global */
  a2 = LD32(a2 + 0x4);  /* 0044 */
  __asm__ volatile("" ::: "memory");  /* 0046: memw */
  goto L_004d;  /* 0049: j */
  L_004d: ST32(a1 + 0x8, a2);  /* 004d */
  L_004f: a3 = a1;  /* 004f */
  a2 = 2;  /* 0051 */
  a12 = a1 + (24);  /* 0053 */
  a13 = -1;  /* 0056 */
  ST8(a1 + 0x1b, a3);  /* 0058 */
  a3 = (a1 >> 8) & 0x1ff;  /* 005b: extui width 9 */
  ST8(a1 + 0x1c, a3);  /* 005e */
  a3 = (a1 >> 8) & 0x1ffff;  /* 0061: extui width 17 */
  ST8(a1 + 0x1d, a3);  /* 0064 */
  a3 = (a1 >> 8) & 0x1ffffff;  /* 0067: extui width 25 */
  ST8(a1 + 0x18, a2);  /* 006a */
  a2 = 24;  /* 006d */
  ST8(a1 + 0x1e, a3);  /* 006f */
  __asm__ volatile("" ::: "memory");  /* 0072: memw */
  a3 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 0075: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  a10 = a3;  /* 0078 */
  ST8(a1 + 0x19, a2);  /* 007a */
  a2 = 0;  /* 007d */
  a14 = a2;  /* 007f */
  a11 = a2;  /* 0081 */
  ST8(a1 + 0x1a, a2);  /* 0083 */
  __asm__ volatile("" ::: "memory");  /* 0086: memw */
  ST32(a1 + 0x10, a4);  /* 0089 */
  __asm__ volatile("" ::: "memory");  /* 008b: memw */
  a8 = (u32)&esp_mesh_send_mgmt;  /* 008e: l32r -> func addr */
  a2 = esp_mesh_send_mgmt(a2, a3, a4, a5, a6, a7);  /* 0091: callx a8 via reloc-expand */
  a11 = a2;  /* 0094 */
  a14 = 1;  /* 0096 */
  a13 = -1;  /* 0098 */
  a12 = a1 + (24);  /* 009a */
  a10 = a3;  /* 009d */
  a8 = (u32)&esp_mesh_send_mgmt;  /* 009f: l32r -> func addr */
  a2 = esp_mesh_send_mgmt(a2, a3, a4, a5, a6, a7);  /* 00a2: callx a8 via reloc-expand */
  a2 = a10;  /* 00a5 */
  return a2;  /* 00a7: retw.n */
}


/* mesh_wifi_event_deinit @ mesh.o 00000014 size 40B bind GLOBAL
 * Calls: esp_event_handler_unregister | Data refs: WIFI_EVENT, mesh_wifi_event_cb, WIFI_MESH_EVENT
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_wifi_event_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&WIFI_EVENT + 0x0;  /* 0017: l32r -> global */
  a11 = -1;  /* 001a */
  a2 = (u32)&mesh_wifi_event_cb + 0x0;  /* 001c: l32r -> global */
  a12 = a2;  /* 001f */
  a10 = LD32(a8 + 0x0);  /* 0021 */
  a8 = (u32)&esp_event_handler_unregister + 0x0;  /* 0023: l32r -> global */
  a2 = esp_event_handler_unregister(a2, a3, a4, a5, a6, a7);  /* 0026: callx a8 via reloc-expand */
  a12 = a2;  /* 0029 */
  a11 = -1;  /* 002b */
  a2 = (u32)&WIFI_MESH_EVENT + 0x0;  /* 002d: l32r -> global */
  a10 = LD32(a2 + 0x0);  /* 0030 */
  a2 = 0;  /* 0032 */
  a8 = (u32)&esp_event_handler_unregister + 0x0;  /* 0034: l32r -> global */
  a2 = esp_event_handler_unregister(a2, a3, a4, a5, a6, a7);  /* 0037: callx a8 via reloc-expand */
  return a2;  /* 003a: retw.n */
}


/* mesh_wifi_event_init @ mesh.o 0000002c size 168B bind GLOBAL
 * Calls: esp_event_handler_register, esp_event_handler_unregister | indirect[4]: mem[a3+0x158]; mem[a3+0x150]; mem[a8+0x158]; mem[a8+0x150] | Data refs: WIFI_EVENT, mesh_wifi_event_cb, g_osi_funcs_p, .rodata.esp_mesh_get_rx_pending.str1.1, .rodata.mesh_wifi_event_init.str1.1, WIFI_MESH_EVENT
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=8); reloc-direct=2, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_wifi_event_init(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 002c: entry a1, 48 (frame 48 bytes) */
  a4 = (u32)&WIFI_EVENT + 0x0;  /* 002f: l32r -> global */
  a13 = 0;  /* 0032 */
  a11 = -1;  /* 0034 */
  a3 = (u32)&mesh_wifi_event_cb + 0x0;  /* 0036: l32r -> global */
  a12 = a3;  /* 0039 */
  a10 = LD32(a4 + 0x0);  /* 003b */
  a8 = (u32)&esp_event_handler_register + 0x0;  /* 003e: l32r -> global */
  a2 = esp_event_handler_register(a2, a3, a4, a5, a6, a7);  /* 0041: callx a8 via reloc-expand */
  a2 = a10;  /* 0044 */
  if (a10 == 0) goto L_0080;  /* 0046: beqz.n a10, 80 <mesh_wifi_event_init+0x54> */
  L_0048: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0048: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 004b */
  if (a3 != 0) goto L_0054;  /* 004d: bnez.n a3, 54 <mesh_wifi_event_init+0x28> */
  L_004f: goto L_00d0;  /* 004f: j */
  L_0054: a4 = LD32(a3 + 0x150);  /* 0054 */
  if (a4 == 0) goto L_00d0;  /* 0057: beqz a4, d0 <mesh_wifi_event_init+0xa4> */
  L_005a: a10 = LD32(a3 + 0x158);  /* 005a */
  /* 005d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0060 */
  a10 = 1;  /* 0062 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 0064: -> "mesh" */
  a14 = a11;  /* 0067 */
  ST32(a1 + 0x4, a2);  /* 0069 */
  a2 = 214;  /* 006b */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 006e: -> "mesh" */
  a12 = (u32)(RODATA__rodata_mesh_wifi_event_init_str1_1 + 0x0);  /* 0071: l32r -> .rodata.mesh_wifi_event_init.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0074 */
  __asm__ volatile("" ::: "memory");  /* 0076: memw */
  /* 0079: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_00d0;  /* 007c: j */
  L_0080: a2 = (u32)&WIFI_MESH_EVENT + 0x0;  /* 0080: l32r -> global */
  a13 = a10;  /* 0083 */
  a12 = a3;  /* 0085 */
  a11 = -1;  /* 0087 */
  a10 = LD32(a2 + 0x0);  /* 0089 */
  a8 = (u32)&esp_event_handler_register + 0x0;  /* 008b: l32r -> global */
  a2 = esp_event_handler_register(a2, a3, a4, a5, a6, a7);  /* 008e: callx a8 via reloc-expand */
  a2 = a10;  /* 0091 */
  if (a10 == 0) goto L_00d2;  /* 0093: beqz.n a10, d2 <mesh_wifi_event_init+0xa6> */
  L_0095: a10 = LD32(a4 + 0x0);  /* 0095 */
  a12 = a3;  /* 0097 */
  a11 = -1;  /* 0099 */
  a8 = (u32)&esp_event_handler_unregister + 0x0;  /* 009b: l32r -> global */
  a2 = esp_event_handler_unregister(a2, a3, a4, a5, a6, a7);  /* 009e: callx a8 via reloc-expand */
  a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00a1: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 00a4 */
  if (a8 == 0) goto L_00d0;  /* 00a6: beqz a8, d0 <mesh_wifi_event_init+0xa4> */
  L_00a9: a3 = LD32(a8 + 0x150);  /* 00a9 */
  if (a3 == 0) goto L_00d0;  /* 00ac: beqz.n a3, d0 <mesh_wifi_event_init+0xa4> */
  L_00ae: a10 = LD32(a8 + 0x158);  /* 00ae */
  /* 00b1: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00b4 */
  a10 = 1;  /* 00b6 */
  a11 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00b8: -> "mesh" */
  a14 = a11;  /* 00bb */
  ST32(a1 + 0x4, a2);  /* 00bd */
  a2 = 221;  /* 00bf */
  a15 = (u32)(RODATA__rodata_esp_mesh_get_rx_pending_str1_1 + 0x0);  /* 00c2: -> "mesh" */
  a12 = (u32)(RODATA__rodata_mesh_wifi_event_init_str1_1 + 0x0);  /* 00c5: l32r -> .rodata.mesh_wifi_event_init.str1.1 */
  ST32(a1 + 0x0, a2);  /* 00c8 */
  __asm__ volatile("" ::: "memory");  /* 00ca: memw */
  /* 00cd: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_00d0: a2 = -1;  /* 00d0 */
  L_00d2: return a2;  /* 00d2: retw.n */
}

