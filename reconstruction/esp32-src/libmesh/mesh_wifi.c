/* libmesh.a mesh_wifi.o --- reconstructed C (offline).
 * Role: wifi receive path: rx queue, rx task, promiscuous recv callback, topology TTL.
 * Object file: 16648 bytes on disk; 7/7 functions reconstructed, ~2851 code bytes.
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
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_topology; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_create_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_create_mbox(); /* defined in another libmesh.a object */
extern u32 esp_mesh_discard_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_forward_packet(); /* defined in another libmesh.a object */
extern u32 esp_mesh_free_context(); /* defined in another libmesh.a object */
extern u32 esp_mesh_free_mbox(); /* defined in another libmesh.a object */
extern u32 esp_mesh_match_self(); /* defined in another libmesh.a object */
extern u32 esp_mesh_operation_rxseqno(); /* defined in another libmesh.a object */
extern u32 esp_mesh_print_rxQ_waiting(); /* defined in another libmesh.a object */
extern u32 esp_mesh_print_txQ_waiting(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_nwk_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_recv_xon(); /* defined in another libmesh.a object */
extern u32 esp_mesh_tx_tid_flush(); /* defined in another libmesh.a object */
extern u32 esp_wifi_mesh_reg_rxcb(); /* undefined func (args unknown, returns u32) */
static const u8 RODATA__rodata___func___0[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x78, 0x5f, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x64, 0x65, 0x69, 0x6e, 0x69, 0x74, 0x00 }; /* .rodata.__func__$0 (20 bytes) strings: [0x0]="mesh_rx_task_deinit" */
static const u8 RODATA__rodata___func___1[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x77, 0x69, 0x66, 0x69, 0x5f, 0x72, 0x65, 0x63, 0x76, 0x5f, 0x63 }; /* .rodata.__func__$1 (20 bytes) */
static const u8 RODATA__rodata___func___3[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x72, 0x78, 0x5f, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x6d, 0x61, 0x69 }; /* .rodata.__func__$3 (16 bytes) */
static const u8 RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x77, 0x69, 0x66, 0x69, 0x2e, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73, 0x0a }; /* .rodata.esp_mesh_push_to_rx_queue.str1.1 (44 bytes) strings: [0x0]="mesh_wifi.c"; [0xc]="mesh" */
static const u8 RODATA__rodata_esp_mesh_rx_task_init_str1_1[] = { 0x4d, 0x52, 0x58, 0x00 }; /* .rodata.esp_mesh_rx_task_init.str1.1 (4 bytes) strings: [0x0]="MRX" */
static const u8 RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1[] = { 0x41, 0x50, 0x00, 0x53, 0x54, 0x41, 0x00, 0x41, 0x50, 0x2c, 0x20, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x3a, 0x00, 0x53, 0x54, 0x41, 0x2c, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x3a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x72, 0x65, 0x63, 0x76, 0x5d, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x72, 0x65, 0x63, 0x76, 0x5d, 0x74, 0x74, 0x6c, 0x20, 0x30, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x72, 0x65, 0x63, 0x76, 0x5d, 0x69, 0x66, 0x78, 0x3a, 0x25, 0x73, 0x20, 0x54, 0x41, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2d, 0x2d, 0x3e, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x5b, 0x68, 0x64, 0x72, 0x3a, 0x25, 0x64, 0x2c, 0x25, 0x64, 0x5d, 0x2c, 0x20, 0x74, 0x74, 0x6c, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6d, 0x61, 0x63, 0x5f, 0x73, 0x65, 0x71, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6f, 0x70, 0x74, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x72, 0x65, 0x63, 0x76, 0x20, 0x63, 0x74, 0x78, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x3c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x3e, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x72, 0x65, 0x63, 0x76, 0x20, 0x63, 0x74, 0x78, 0x2c, 0x20, 0x68, 0x65, 0x61, 0x70, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x72, 0x65, 0x63, 0x76, 0x5d, 0x70, 0x75, 0x73, 0x68, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x78, 0x20, 0x71, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x2c, 0x20, 0x69, 0x66, 0x78, 0x3a, 0x25, 0x73, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x3c, 0x68, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x78, 0x73, 0x65, 0x71, 0x6e, 0x6f, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x74, 0x6c, 0x3a, 0x25, /* ... +24 bytes */ }; /* .rodata.esp_mesh_wifi_recv_cb.str1.1 (536 bytes) strings: [0x3]="STA"; [0x7]="AP, child:"; [0x12]="STA, parent:" */
static const u8 RODATA__rodata_mesh_rx_task_main_str1_1[] = { 0x73, 0x74, 0x6f, 0x70, 0x00, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x63, 0x74, 0x78, 0x3a, 0x25, 0x70, 0x3c, 0x25, 0x73, 0x3e, 0x2c, 0x20, 0x63, 0x74, 0x78, 0x2d, 0x3e, 0x62, 0x75, 0x66, 0x20, 0x4e, 0x55, 0x4c, 0x4c, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x63, 0x74, 0x78, 0x2d, 0x3e, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00 }; /* .rodata.mesh_rx_task_main.str1.1 (92 bytes) strings: [0x0]="stop" */
static const u8 RODATA__rodata_mesh_topo_get_ttl_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x64, 0x5b, 0x72, 0x65, 0x63, 0x76, 0x5d, 0x74, 0x74, 0x6c, 0x2c, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x45, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x70, 0x61, 0x6e, 0x64, 0x6f, 0x72, 0x61, 0x0a, 0x0a, 0x00 }; /* .rodata.mesh_topo_get_ttl.str1.1 (80 bytes) */
static u8 LOCAL__bss_MESH_ZERO_ADDR[0x4]; /* stand-in for .bss.MESH_ZERO_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_is_rx_running[0x4]; /* stand-in for .bss.is_rx_running (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_rx_mbox[0x4]; /* stand-in for .bss.mesh_rx_mbox (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_mesh_rx_task[0x4]; /* stand-in for .bss.mesh_rx_task (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_parent_last_mac_seqno_2[0x4]; /* stand-in for .bss.parent_last_mac_seqno$2 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_MESH_BCAST_ADDR[0x4]; /* stand-in for .data.MESH_BCAST_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_push_to_rx_queue @ mesh_wifi.o 00000024 size 166B bind GLOBAL
 * Calls: none | indirect[5]: mem[a8+0x158]; mem[a8+0x150]; mem[a2+0x78]; mem[a2+0x6c] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_push_to_rx_queue.str1.1, .bss.mesh_rx_mbox
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=4); reloc-direct=0, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_push_to_rx_queue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  a5 = a2;  /* 0027 */
  if (a2 != 0) goto L_0059;  /* 0029: bnez.n a2, 59 <esp_mesh_push_to_rx_queue+0x35> */
  L_002b: a2 = (u32)&g_log_level + 0x0;  /* 002b: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002e */
  a2 = 0x00004008u;  /* 0030: l32r = 16392 */
  if (a3 >= 3u) goto L_0039;  /* 0033: bgeui a3, 3, 39 <esp_mesh_push_to_rx_queue+0x15> */
  L_0036: goto L_00c8;  /* 0036: j */
  L_0039: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0039: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 003c */
  if (a8 == 0) goto L_00c8;  /* 003e: beqz a8, c8 <esp_mesh_push_to_rx_queue+0xa4> */
  L_0041: a4 = LD32(a8 + 0x150);  /* 0041 */
  if (a4 == 0) goto L_00c8;  /* 0044: beqz a4, c8 <esp_mesh_push_to_rx_queue+0xa4> */
  L_0047: a3 = 86;  /* 0047 */
  a10 = LD32(a8 + 0x158);  /* 004a */
  /* 004d: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 0050: -> "mesh_wifi.c" */
  goto L_0084;  /* 0053: j */
  L_0059: a4 = (u32)&LOCAL__bss_mesh_rx_mbox + 0x0;  /* 0059: l32r -> .bss.mesh_rx_mbox (same-object static) */
  a10 = LD32(a4 + 0x0);  /* 005c */
  if (a10 != 0) goto L_009d;  /* 005e: bnez.n a10, 9d <esp_mesh_push_to_rx_queue+0x79> */
  L_0060: a2 = (u32)&g_log_level + 0x0;  /* 0060: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0063 */
  a2 = 0x00004008u;  /* 0065: l32r = 16392 */
  if (a3 < 3u) goto L_00c8;  /* 0068: bltui a3, 3, c8 <esp_mesh_push_to_rx_queue+0xa4> */
  L_006b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 006b: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 006e */
  if (a8 == 0) goto L_00c8;  /* 0070: beqz a8, c8 <esp_mesh_push_to_rx_queue+0xa4> */
  L_0073: a4 = LD32(a8 + 0x150);  /* 0073 */
  if (a4 == 0) goto L_00c8;  /* 0076: beqz a4, c8 <esp_mesh_push_to_rx_queue+0xa4> */
  L_0079: a3 = 87;  /* 0079 */
  a10 = LD32(a8 + 0x158);  /* 007b */
  /* 007e: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 0081: -> "mesh_wifi.c" */
  L_0084: a13 = a10;  /* 0084 */
  a14 = a11;  /* 0086 */
  a10 = 3;  /* 0088 */
  a15 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 008a: -> "mesh_wifi.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 008d: -> "mesh_wifi.c" */
  ST32(a1 + 0x0, a3);  /* 0090 */
  __asm__ volatile("" ::: "memory");  /* 0092: memw */
  /* 0095: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00c8;  /* 0098: j */
  L_009d: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 009d: l32r -> global */
  a2 = LD32(a6 + 0x0);  /* 00a0 */
  a2 = LD32(a2 + 0x78);  /* 00a2 */
  /* 00a5: INDIRECT callx a2 <- mem[a2+0x78]; result unknown */ a2 = 0;
  a8 = 63;  /* 00a8 */
  a2 = 0x0000400du;  /* 00aa: l32r = 16397 */
  if (a8 < a10) goto L_00c8;  /* 00ad: bltu a8, a10, c8 <esp_mesh_push_to_rx_queue+0xa4> */
  L_00b0: a12 = a3;  /* 00b0 */
  a11 = a5;  /* 00b2 */
  a2 = LD32(a6 + 0x0);  /* 00b4 */
  a10 = LD32(a4 + 0x0);  /* 00b6 */
  a4 = 0;  /* 00b8 */
  a2 = LD32(a2 + 0x6c);  /* 00ba */
  /* 00bd: INDIRECT callx a2 <- mem[a2+0x6c]; result unknown */ a2 = 0;
  a10 = a10 + (-1);  /* 00c0 */
  a2 = 0x0000400cu;  /* 00c2: l32r = 16396 */
  if (a10 == 0) a2 = a4;  /* 00c5 */
  L_00c8: return a2;  /* 00c8: retw.n */
}


/* esp_mesh_rx_task_deinit @ mesh_wifi.o 00000010 size 56B bind GLOBAL
 * Calls: esp_wifi_mesh_reg_rxcb | indirect[1]: mem[a8+0x6c] | Data refs: .bss.is_rx_running, .bss.mesh_rx_mbox, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_rx_task_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0010: entry a1, 48 (frame 48 bytes) */
  a8 = (u32)&LOCAL__bss_is_rx_running + 0x0;  /* 0013: l32r -> .bss.is_rx_running (same-object static) */
  a10 = 0;  /* 0016 */
  a9 = LD8U(a8 + 0x0);  /* 0019 */
  ST32(a1 + 0x0, a10);  /* 001c */
  if (a9 == a10) goto L_0046;  /* 001e: beq a9, a10, 46 <esp_mesh_rx_task_deinit+0x36> */
  L_0021: ST8(a8 + 0x0, a10);  /* 0021 */
  __asm__ volatile("" ::: "memory");  /* 0024: memw */
  __asm__ volatile("" ::: "memory");  /* 0027: memw */
  a8 = (u32)&esp_wifi_mesh_reg_rxcb + 0x0;  /* 002a: l32r -> global */
  a2 = esp_wifi_mesh_reg_rxcb(a2, a3, a4, a5, a6, a7);  /* 002d: callx a8 via reloc-expand */
  a8 = (u32)&LOCAL__bss_mesh_rx_mbox + 0x0;  /* 0030: l32r -> .bss.mesh_rx_mbox (same-object static) */
  a10 = LD32(a8 + 0x0);  /* 0033 */
  if (a10 == 0) goto L_0046;  /* 0035: beqz.n a10, 46 <esp_mesh_rx_task_deinit+0x36> */
  L_0037: a12 = -1;  /* 0037 */
  a11 = a1;  /* 0039 */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 003b: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 003e */
  a8 = LD32(a8 + 0x6c);  /* 0040 */
  /* 0043: INDIRECT callx a8 <- mem[a8+0x6c]; result unknown */ a2 = 0;
  L_0046: return a2;  /* 0046: retw.n */
}


/* esp_mesh_rx_task_init @ mesh_wifi.o 00000028 size 92B bind GLOBAL
 * Calls: esp_wifi_mesh_reg_rxcb, esp_mesh_create_mbox, mesh_rx_task_deinit | indirect[1]: mem[a8+0x94] | Data refs: .bss.mesh_rx_mbox, esp_mesh_wifi_recv_cb, .bss.mesh_rx_task, g_osi_funcs_p, .rodata.esp_mesh_rx_task_init.str1.1, mesh_rx_task_main
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=9); reloc-direct=3, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_rx_task_init(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0028: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&LOCAL__bss_mesh_rx_mbox + 0x0;  /* 002b: l32r -> .bss.mesh_rx_mbox (same-object static) */
  a8 = LD32(a2 + 0x0);  /* 002e */
  if (a8 == 0) goto L_0038;  /* 0030: beqz.n a8, 38 <esp_mesh_rx_task_init+0x10> */
  L_0032: a2 = 0;  /* 0032 */
  goto L_0082;  /* 0034: j */
  L_0038: a10 = (u32)&esp_mesh_wifi_recv_cb;  /* 0038: l32r -> func addr */
  a8 = (u32)&esp_wifi_mesh_reg_rxcb + 0x0;  /* 003b: l32r -> global */
  a2 = esp_wifi_mesh_reg_rxcb(a2, a3, a4, a5, a6, a7);  /* 003e: callx a8 via reloc-expand */
  a10 = a2;  /* 0041 */
  a12 = 4;  /* 0043 */
  a11 = 64;  /* 0045 */
  a8 = (u32)&esp_mesh_create_mbox + 0x0;  /* 0047: l32r -> global */
  a2 = esp_mesh_create_mbox(a2, a3, a4, a5, a6, a7);  /* 004a: callx a8 via reloc-expand */
  a2 = 0x00004007u;  /* 004d: l32r = 16391 */
  if (a10 != 0) goto L_0082;  /* 0050: bnez.n a10, 82 <esp_mesh_rx_task_init+0x5a> */
  L_0052: a2 = (u32)&LOCAL__bss_mesh_rx_task + 0x0;  /* 0052: l32r -> .bss.mesh_rx_task (same-object static) */
  a13 = LD32(a2 + 0x0);  /* 0055 */
  if (a13 != 0) goto L_0032;  /* 0057: bnez a13, 32 <esp_mesh_rx_task_init+0xa> */
  L_005a: a12 = 3;  /* 005a */
  a15 = a2;  /* 005c */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 005e: l32r -> global */
  a14 = 13;  /* 0061 */
  a12 = a12 << 10;  /* 0063 */
  a8 = LD32(a8 + 0x0);  /* 0066 */
  a11 = (u32)(RODATA__rodata_esp_mesh_rx_task_init_str1_1 + 0x0);  /* 0069: -> "MRX" */
  a8 = LD32(a8 + 0x94);  /* 006c */
  a10 = (u32)&mesh_rx_task_main;  /* 006f: l32r -> func addr */
  /* 0072: INDIRECT callx a8 <- mem[a8+0x94]; result unknown */ a2 = 0;
  a2 = LD32(a2 + 0x0);  /* 0075 */
  if (a2 != 0) goto L_0032;  /* 0077: bnez a2, 32 <esp_mesh_rx_task_init+0xa> */
  L_007a: a8 = (u32)&mesh_rx_task_deinit;  /* 007a: l32r -> func addr */
  a2 = mesh_rx_task_deinit(a2, a3, a4, a5, a6, a7);  /* 007d: callx a8 via reloc-expand */
  a2 = -1;  /* 0080 */
  L_0082: return a2;  /* 0082: retw.n */
}


/* esp_mesh_wifi_recv_cb @ mesh_wifi.o 000000ac size 1712B bind GLOBAL
 * Calls: mesh_topo_get_ttl, memcmp, esp_mesh_match_self, esp_mesh_push_to_nwk_queue, esp_mesh_operation_rxseqno, esp_mesh_create_context, memcpy, esp_mesh_push_to_rx_queue, esp_mesh_free_context, esp_mesh_print_txQ_waiting, esp_mesh_print_rxQ_waiting, esp_mesh_tx_tid_flush | indirect[20]: mem[a2+0x158]; mem[a2+0x150]; mem[a8+0x158]; mem[a8+0x150] | Data refs: g_mesh_topology, g_is_mesh_started, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_push_to_rx_queue.str1.1, .rodata.esp_mesh_wifi_recv_cb.str1.1, .data.MESH_BCAST_ADDR, g_is_wifi_connected, g_mesh_is_root, .bss.MESH_ZERO_ADDR, .bss.parent_last_mac_seqno$2, .rodata.mesh_topo_get_ttl.str1.1 +2 more
 * Fidelity: medium - 20 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=12, refs=26); reloc-direct=12, funcdb-attributed=0, unknown-indirect=20 */
u32 esp_mesh_wifi_recv_cb(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F0000001;
  /* 00ac: entry a1, 0x1c0 (frame 0x1c0 bytes) */
  a4 = (a4 >> 16) & 0x1;  /* 00af: extui width 1 */
  ST32(a1 + 0x144, a4);  /* 00b2 */
  a4 = 0;  /* 00b5 */
  ST32(a1 + 0x12c, a4);  /* 00b7 */
  a4 = -1;  /* 00ba */
  ST32(a1 + 0x14c, a7);  /* 00bc */
  ST32(a1 + 0x140, a6);  /* 00bf */
  ST32(a1 + 0x128, a4);  /* 00c2 */
  if (a2 < 3u) goto L_00cb;  /* 00c5: bltui a2, 3, cb <esp_mesh_wifi_recv_cb+0x1f> */
  L_00c8: goto L_075a;  /* 00c8: j */
  L_00cb: if (a3 == 0) goto L_075a;  /* 00cb: beqz a3, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_00ce: a4 = 13;  /* 00ce */
  a6 = LD32(a1 + 0x144);  /* 00d0 */
  if (a4 < a6) goto L_00d9;  /* 00d3: bltu a4, a6, d9 <esp_mesh_wifi_recv_cb+0x2d> */
  L_00d6: goto L_075a;  /* 00d6: j */
  L_00d9: a6 = 47;  /* 00d9 */
  a4 = (u32)&g_mesh_topology + 0x0;  /* 00db: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 00de */
  a4 = 42;  /* 00e0 */
  if (a8 != 0) a4 = a6;  /* 00e2 */
  a8 = LD32(a1 + 0x144);  /* 00e5 */
  if (a8 >= a4) goto L_00ee;  /* 00e8: bgeu a8, a4, ee <esp_mesh_wifi_recv_cb+0x42> */
  L_00eb: goto L_075a;  /* 00eb: j */
  L_00ee: a4 = (u32)&g_is_mesh_started + 0x0;  /* 00ee: l32r -> global */
  a4 = LD8U(a4 + 0x0);  /* 00f1 */
  if (a4 != 0) goto L_0100;  /* 00f4: bnez a4, 100 <esp_mesh_wifi_recv_cb+0x54> */
  L_00f7: a4 = LD8U(a3 + 0x2a);  /* 00f7 */
  if (a4 != 3) goto L_0100;  /* 00fa: bnei a4, 3, 100 <esp_mesh_wifi_recv_cb+0x54> */
  L_00fd: goto L_075a;  /* 00fd: j */
  L_0100: a4 = LD8U(a3 + 0xe);  /* 0100 */
  a4 = (a4 >> 4) & 0x1;  /* 0103: extui width 1 */
  if (a4 == 1) goto L_014c;  /* 0106: beqi a4, 1, 14c <esp_mesh_wifi_recv_cb+0xa0> */
  L_0109: a2 = (u32)&g_log_level + 0x0;  /* 0109: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 010c */
  if (a2 >= 3u) goto L_0114;  /* 010e: bgeui a2, 3, 114 <esp_mesh_wifi_recv_cb+0x68> */
  L_0111: goto L_075a;  /* 0111: j */
  L_0114: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0114: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0117 */
  if (a2 == 0) goto L_075a;  /* 0119: beqz a2, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_011c: a4 = LD32(a2 + 0x150);  /* 011c */
  if (a4 == 0) goto L_075a;  /* 011f: beqz a4, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_0122: a3 = a3 + (14);  /* 0122 */
  a10 = LD32(a2 + 0x158);  /* 0124 */
  __asm__ volatile("" ::: "memory");  /* 0127: memw */
  /* 012a: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 012d */
  a15 = 0x131;  /* 012f */
  a2 = LD32(a3 + 0x0);  /* 0132 */
  a10 = 3;  /* 0134 */
  a2 = (a2 >> 4) & 0x1;  /* 0136: extui width 1 */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 0139: -> "mesh_wifi.c" */
  a14 = a11;  /* 013c */
  a12 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 013e: -> "AP" */
  ST32(a1 + 0x0, a2);  /* 0141 */
  __asm__ volatile("" ::: "memory");  /* 0143: memw */
  /* 0146: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_075a;  /* 0149: j */
  L_014c: a6 = a3 + (14);  /* 014c */
  a11 = a3 + (42);  /* 014e */
  a10 = a6;  /* 0151 */
  a8 = (u32)&mesh_topo_get_ttl;  /* 0153: l32r -> func addr */
  a2 = mesh_topo_get_ttl(a2, a3, a4, a5, a6, a7);  /* 0156: callx a8 via reloc-expand */
  a9 = a3 + (22);  /* 0159 */
  ST32(a1 + 0x128, a10);  /* 015c */
  a4 = a10;  /* 015f */
  a7 = a3 + (18);  /* 0161 */
  ST32(a1 + 0x148, a9);  /* 0164 */
  if (a10 != 0) goto L_0362;  /* 0167: bnez a10, 362 <esp_mesh_wifi_recv_cb+0x2b6> */
  L_016a: a12 = 6;  /* 016a */
  a10 = a9;  /* 016d: mov */
  a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 0170: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  a8 = (u32)&memcmp + 0x0;  /* 0176: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0179: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0362;  /* 017c: beqz a10, 362 <esp_mesh_wifi_recv_cb+0x2b6> */
  L_017f: a9 = LD8U(a3 + 0x16);  /* 017f */
  if (((a9 >> 0) & 1) == 0) goto L_018e;  /* 0182: bbci a9, 0, 18e <esp_mesh_wifi_recv_cb+0xe2> */
  L_0185: a9 = LD8U(a3 + 0xe);  /* 0185 */
  if (((a9 >> 5) & 1) != 0) goto L_018e;  /* 0188: bbsi a9, 5, 18e <esp_mesh_wifi_recv_cb+0xe2> */
  L_018b: goto L_0362;  /* 018b: j */
  L_018e: a9 = LD32(a7 + 0x0);  /* 018e */
  if (((a9 >> 27) & 1) == 0) goto L_0196;  /* 0190: bbci a9, 27, 196 <esp_mesh_wifi_recv_cb+0xea> */
  L_0193: goto L_0362;  /* 0193: j */
  L_0196: a10 = LD32(a1 + 0x148);  /* 0196 */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 0199: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 019c: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0362;  /* 019f: bnez a10, 362 <esp_mesh_wifi_recv_cb+0x2b6> */
  L_01a2: a6 = (u32)&g_log_level + 0x0;  /* 01a2: l32r -> global */
  a4 = LD32(a6 + 0x0);  /* 01a5 */
  if (a4 >= 3u) goto L_01ad;  /* 01a7: bgeui a4, 3, 1ad <esp_mesh_wifi_recv_cb+0x101> */
  L_01aa: goto L_0320;  /* 01aa: j */
  L_01ad: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 01ad: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 01b0 */
  if (a8 != 0) goto L_01bc;  /* 01b2: bnez.n a8, 1bc <esp_mesh_wifi_recv_cb+0x110> */
  L_01b4: a4 = LD32(a4 + 0x0);  /* 01b4 */
  if (a4 != 0) goto L_01e4;  /* 01b6: bnez.n a4, 1e4 <esp_mesh_wifi_recv_cb+0x138> */
  L_01b8: goto L_0320;  /* 01b8: j */
  L_01bc: a7 = LD32(a8 + 0x150);  /* 01bc */
  if (a7 == 0) goto L_01b4;  /* 01bf: beqz a7, 1b4 <esp_mesh_wifi_recv_cb+0x108> */
  L_01c2: a10 = LD32(a8 + 0x158);  /* 01c2 */
  /* 01c5: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01c8 */
  a15 = 0x13d;  /* 01ca */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 01cd: -> "mesh_wifi.c" */
  a10 = 3;  /* 01d0 */
  a14 = a11;  /* 01d2 */
  a12 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 01d4: -> "AP" */
  /* 01d7: INDIRECT callx a7 <- mem[a8+0x150]; result unknown */ a2 = 0;
  a6 = LD32(a6 + 0x0);  /* 01da */
  if (a6 >= 3u) goto L_01b4;  /* 01dc: bgeui a6, 3, 1b4 <esp_mesh_wifi_recv_cb+0x108> */
  L_01df: goto L_0320;  /* 01df: j */
  L_01e4: a6 = LD32(a4 + 0x150);  /* 01e4 */
  if (a6 == 0) goto L_0320;  /* 01e7: beqz a6, 320 <esp_mesh_wifi_recv_cb+0x274> */
  L_01ea: a10 = LD32(a4 + 0x158);  /* 01ea */
  /* 01ed: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a7 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 01f0: -> "AP" */
  if (a2 != 0) goto L_01f8;  /* 01f3: bnez.n a2, 1f8 <esp_mesh_wifi_recv_cb+0x14c> */
  L_01f5: a7 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 01f5: -> "AP" */
  L_01f8: a4 = a3 + (18);  /* 01f8 */
  a2 = LD8U(a5 + 0x0);  /* 01fb */
  a8 = LD8U(a5 + 0x1);  /* 01fe */
  a9 = LD8U(a5 + 0x2);  /* 0201 */
  ST32(a1 + 0x14c, a2);  /* 0204 */
  ST32(a1 + 0x150, a8);  /* 0207 */
  a2 = LD8U(a5 + 0x3);  /* 020a */
  a8 = LD8U(a5 + 0x4);  /* 020d */
  ST32(a1 + 0x154, a9);  /* 0210 */
  ST32(a1 + 0x158, a2);  /* 0213 */
  a9 = LD8U(a3 + 0x1c);  /* 0216 */
  a2 = LD8U(a3 + 0x1d);  /* 0219 */
  ST32(a1 + 0x15c, a8);  /* 021c */
  a8 = LD8U(a3 + 0x1e);  /* 021f */
  ST32(a1 + 0x164, a9);  /* 0222 */
  ST32(a1 + 0x168, a2);  /* 0225 */
  a9 = LD8U(a3 + 0x1f);  /* 0228 */
  a2 = LD8U(a3 + 0x20);  /* 022b */
  ST32(a1 + 0x16c, a8);  /* 022e */
  a8 = LD8U(a3 + 0x21);  /* 0231 */
  a5 = LD8U(a5 + 0x5);  /* 0234 */
  ST32(a1 + 0x170, a9);  /* 0237 */
  ST32(a1 + 0x174, a2);  /* 023a */
  a9 = LD8U(a3 + 0x16);  /* 023d */
  a2 = LD8U(a3 + 0x17);  /* 0240 */
  ST32(a1 + 0x178, a8);  /* 0243 */
  a8 = LD8U(a3 + 0x18);  /* 0246 */
  ST32(a1 + 0x17c, a9);  /* 0249 */
  ST32(a1 + 0x180, a2);  /* 024c */
  a15 = LD8U(a3 + 0x19);  /* 024f */
  a14 = LD8U(a3 + 0x1a);  /* 0252 */
  ST32(a1 + 0x160, a5);  /* 0255 */
  ST32(a1 + 0x184, a8);  /* 0258 */
  a8 = LD8U(a3 + 0x1b);  /* 025b */
  a2 = LD8U(a3 + 0xf);  /* 025e */
  a2 = a2 << 2;  /* 0261 */
  a11 = LD32(a4 + 0x0);  /* 0264 */
  a9 = LD16U(a3 + 0x10);  /* 0266 */
  a12 = LD32(a1 + 0x140);  /* 0269 */
  if (((a11 >> 24) & 1) == 0) goto L_0282;  /* 026c: bbci a11, 24, 282 <esp_mesh_wifi_recv_cb+0x1d6> */
  L_026f: a5 = 33;  /* 026f */
  a4 = (u32)&g_mesh_topology + 0x0;  /* 0271: l32r -> global */
  a13 = LD32(a4 + 0x0);  /* 0274 */
  a4 = 28;  /* 0276 */
  if (a13 != 0) a4 = a5;  /* 0279 */
  a4 = a2 - a4;  /* 027c: sub */
  if (a4 >= 4u) goto L_0299;  /* 027f: bgeui a4, 4, 299 <esp_mesh_wifi_recv_cb+0x1ed> */
  L_0282: a5 = -1;  /* 0282 */
  if (((a11 >> 23) & 1) == 0) goto L_029c;  /* 0284: bbci a11, 23, 29c <esp_mesh_wifi_recv_cb+0x1f0> */
  L_0287: a4 = (u32)&g_mesh_topology + 0x0;  /* 0287: l32r -> global */
  a11 = 33;  /* 028a */
  a13 = LD32(a4 + 0x0);  /* 028c */
  a4 = 28;  /* 028e */
  if (a13 != 0) a4 = a11;  /* 0290 */
  a4 = a2 - a4;  /* 0293: sub */
  if (a4 < 3u) goto L_029c;  /* 0296: bltui a4, 3, 29c <esp_mesh_wifi_recv_cb+0x1f0> */
  L_0299: a5 = LD8U(a3 + 0x2a);  /* 0299 */
  L_029c: a13 = a10;  /* 029c */
  a10 = 3;  /* 029e */
  a3 = LD32(a1 + 0x144);  /* 02a0 */
  ST32(a1 + 0x50, a9);  /* 02a3 */
  ST32(a1 + 0x48, a8);  /* 02a6 */
  a9 = LD32(a1 + 0x180);  /* 02a9 */
  a8 = LD32(a1 + 0x184);  /* 02ac */
  ST32(a1 + 0x5c, a3);  /* 02af */
  a3 = 0;  /* 02b2 */
  ST32(a1 + 0x4c, a2);  /* 02b4 */
  a2 = LD32(a1 + 0x17c);  /* 02b7 */
  ST32(a1 + 0x54, a3);  /* 02ba */
  ST32(a1 + 0x3c, a8);  /* 02bd */
  a3 = LD32(a1 + 0x178);  /* 02bf */
  a8 = LD32(a1 + 0x174);  /* 02c2 */
  ST32(a1 + 0x38, a9);  /* 02c5 */
  a9 = LD32(a1 + 0x170);  /* 02c7 */
  ST32(a1 + 0x34, a2);  /* 02ca */
  a2 = LD32(a1 + 0x16c);  /* 02cc */
  ST32(a1 + 0x30, a3);  /* 02cf */
  ST32(a1 + 0x2c, a8);  /* 02d1 */
  a3 = LD32(a1 + 0x168);  /* 02d3 */
  a8 = LD32(a1 + 0x164);  /* 02d6 */
  ST32(a1 + 0x28, a9);  /* 02d9 */
  a9 = LD32(a1 + 0x160);  /* 02db */
  ST32(a1 + 0x24, a2);  /* 02de */
  a2 = LD32(a1 + 0x15c);  /* 02e0 */
  ST32(a1 + 0x58, a12);  /* 02e3 */
  ST32(a1 + 0x44, a14);  /* 02e6 */
  ST32(a1 + 0x40, a15);  /* 02e9 */
  a15 = 0x13e;  /* 02ec */
  ST32(a1 + 0x20, a3);  /* 02ef */
  ST32(a1 + 0x1c, a8);  /* 02f1 */
  ST32(a1 + 0x18, a9);  /* 02f3 */
  ST32(a1 + 0x60, a5);  /* 02f5 */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 02f8: -> "mesh_wifi.c" */
  a14 = a11;  /* 02fb */
  ST32(a1 + 0x14, a2);  /* 02fd */
  a3 = LD32(a1 + 0x158);  /* 02ff */
  a8 = LD32(a1 + 0x154);  /* 0302 */
  a9 = LD32(a1 + 0x150);  /* 0305 */
  a2 = LD32(a1 + 0x14c);  /* 0308 */
  a12 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 030b: -> "AP" */
  ST32(a1 + 0x10, a3);  /* 030e */
  ST32(a1 + 0xc, a8);  /* 0310 */
  ST32(a1 + 0x8, a9);  /* 0312 */
  ST32(a1 + 0x4, a2);  /* 0315 */
  ST32(a1 + 0x0, a7);  /* 0317 */
  __asm__ volatile("" ::: "memory");  /* 031a: memw */
  /* 031d: INDIRECT callx a6 <- unknown; result unknown */ a2 = 0;
  L_0320: a2 = (u32)&g_is_wifi_connected + 0x0;  /* 0320: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 0323 */
  if (a2 == 0) goto L_075a;  /* 0326: beqz a2, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_0329: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0329: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 032c: memw */
  a2 = LD8U(a2 + 0x0);  /* 032f */
  a2 = (a2 >> 8) & 0x1;  /* 0332: extui width 1 */
  if (a2 == 0) goto L_0348;  /* 0335: beqz.n a2, 348 <esp_mesh_wifi_recv_cb+0x29c> */
  L_0337: a12 = 6;  /* 0337 */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 0339: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a10 = LD32(a1 + 0x148);  /* 033c */
  a8 = (u32)&memcmp + 0x0;  /* 033f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0342: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_075a;  /* 0345: beqz a10, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_0348: a2 = 22;  /* 0348 */
  a11 = 0;  /* 034a */
  a10 = a1 + (112);  /* 034d */
  ST32(a1 + 0x70, a2);  /* 0350 */
  __asm__ volatile("" ::: "memory");  /* 0353: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 0356: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 0359: callx a8 via reloc-expand */
  goto L_075a;  /* 035c: j */
  L_0362: a7 = LD32(a7 + 0x0);  /* 0362 */
  if (((a7 >> 27) & 1) == 0) goto L_036a;  /* 0364: bbci a7, 27, 36a <esp_mesh_wifi_recv_cb+0x2be> */
  L_0367: goto L_047c;  /* 0367: j */
  L_036a: a12 = 6;  /* 036a */
  a11 = (u32)&LOCAL__data_MESH_BCAST_ADDR + 0x0;  /* 036c: l32r -> .data.MESH_BCAST_ADDR (same-object static) */
  a10 = LD32(a1 + 0x148);  /* 036f */
  a8 = (u32)&memcmp + 0x0;  /* 0372: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0375: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_047c;  /* 0378: beqz a10, 47c <esp_mesh_wifi_recv_cb+0x3d0> */
  L_037b: a8 = LD8U(a3 + 0x16);  /* 037b */
  if (((a8 >> 0) & 1) == 0) goto L_038a;  /* 037e: bbci a8, 0, 38a <esp_mesh_wifi_recv_cb+0x2de> */
  L_0381: a8 = LD8U(a3 + 0xe);  /* 0381 */
  if (((a8 >> 5) & 1) != 0) goto L_038a;  /* 0384: bbsi a8, 5, 38a <esp_mesh_wifi_recv_cb+0x2de> */
  L_0387: goto L_047c;  /* 0387: j */
  L_038a: if (a2 != 0) goto L_03ac;  /* 038a: bnez.n a2, 3ac <esp_mesh_wifi_recv_cb+0x300> */
  L_038c: a6 = LD32(a1 + 0x140);  /* 038c */
  a8 = (u32)&LOCAL__bss_parent_last_mac_seqno_2 + 0x0;  /* 038f: l32r -> .bss.parent_last_mac_seqno$2 (same-object static) */
  if (((a7 >> 24) & 1) == 0) goto L_03a0;  /* 0392: bbci a7, 24, 3a0 <esp_mesh_wifi_recv_cb+0x2f4> */
  L_0395: if (a6 == 0) goto L_03a0;  /* 0395: beqz.n a6, 3a0 <esp_mesh_wifi_recv_cb+0x2f4> */
  L_0397: a9 = LD16U(a8 + 0x0);  /* 0397 */
  if (a9 != a6) goto L_03a0;  /* 039a: bne a9, a6, 3a0 <esp_mesh_wifi_recv_cb+0x2f4> */
  L_039d: goto L_075a;  /* 039d: j */
  L_03a0: ST16(a8 + 0x0, a6);  /* 03a0 */
  __asm__ volatile("" ::: "memory");  /* 03a3: memw */
  __asm__ volatile("" ::: "memory");  /* 03a6: memw */
  goto L_047c;  /* 03a9: j */
  L_03ac: a14 = a1 + (112);  /* 03ac */
  a7 = a3 + (28);  /* 03af */
  a13 = 192;  /* 03b2 */
  a8 = 0;  /* 03b5 */
  a10 = 0;  /* 03b7 */
  a13 = a14 + a13;  /* 03b9 */
  a12 = a7;  /* 03bb */
  a11 = a5;  /* 03bd */
  ST16(a1 + 0x130, a8);  /* 03bf */
  __asm__ volatile("" ::: "memory");  /* 03c2: memw */
  ST32(a1 + 0x70, a10);  /* 03c5 */
  __asm__ volatile("" ::: "memory");  /* 03c8: memw */
  a8 = (u32)&esp_mesh_operation_rxseqno + 0x0;  /* 03cb: l32r -> global */
  a2 = esp_mesh_operation_rxseqno(a2, a3, a4, a5, a6, a7);  /* 03ce: callx a8 via reloc-expand */
  a9 = LD32(a1 + 0x140);  /* 03d1 */
  if (a9 == 0) goto L_03e0;  /* 03d4: beqz a9, 3e0 <esp_mesh_wifi_recv_cb+0x334> */
  L_03d7: a10 = LD16U(a1 + 0x130);  /* 03d7 */
  if (a9 != a10) goto L_03e0;  /* 03da: bne a9, a10, 3e0 <esp_mesh_wifi_recv_cb+0x334> */
  L_03dd: goto L_075a;  /* 03dd: j */
  L_03e0: a9 = a3 + (18);  /* 03e0 */
  a14 = LD32(a9 + 0x0);  /* 03e3 */
  a9 = 1;  /* 03e5 */
  a9 = a9 << 24;  /* 03e7 */
  a14 = a14 & a9;  /* 03ea */
  if (a14 == 0) goto L_0468;  /* 03ed: beqz a14, 468 <esp_mesh_wifi_recv_cb+0x3bc> */
  L_03f0: a6 = LD32(a6 + 0x18);  /* 03f0 */
  a9 = LD32(a1 + 0x70);  /* 03f2 */
  if (a6 != a9) goto L_042c;  /* 03f5: bne a6, a9, 42c <esp_mesh_wifi_recv_cb+0x380> */
  L_03f8: if (a6 != 0) goto L_075a;  /* 03f8: bnez a6, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_03fb: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 03fb: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 03fe */
  if (a2 == 0) goto L_075a;  /* 0400: beqz a2, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_0403: a3 = LD32(a2 + 0x150);  /* 0403 */
  if (a3 == 0) goto L_075a;  /* 0406: beqz a3, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_0409: a10 = LD32(a2 + 0x158);  /* 0409 */
  a2 = 0x195;  /* 040c */
  /* 040f: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0412 */
  a10 = 1;  /* 0414 */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 0416: -> "mesh_wifi.c" */
  a14 = a11;  /* 0419 */
  a15 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 041b: -> "mesh_wifi.c" */
  a12 = (u32)(RODATA__rodata_mesh_topo_get_ttl_str1_1 + 0x0);  /* 041e: l32r -> .rodata.mesh_topo_get_ttl.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0421 */
  __asm__ volatile("" ::: "memory");  /* 0423: memw */
  /* 0426: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_075a;  /* 0429: j */
  L_042c: if (a6 != 0) goto L_045c;  /* 042c: bnez.n a6, 45c <esp_mesh_wifi_recv_cb+0x3b0> */
  L_042e: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 042e: l32r -> global */
  a9 = LD32(a6 + 0x0);  /* 0431 */
  if (a9 == 0) goto L_045c;  /* 0433: beqz.n a9, 45c <esp_mesh_wifi_recv_cb+0x3b0> */
  L_0435: a6 = LD32(a9 + 0x150);  /* 0435 */
  if (a6 == 0) goto L_045c;  /* 0438: beqz.n a6, 45c <esp_mesh_wifi_recv_cb+0x3b0> */
  L_043a: a10 = LD32(a9 + 0x158);  /* 043a */
  /* 043d: INDIRECT callx a10 <- mem[a9+0x158]; result unknown */ a2 = 0;
  a9 = 0x199;  /* 0440 */
  a13 = a10;  /* 0443 */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 0445: -> "mesh_wifi.c" */
  a10 = 1;  /* 0448 */
  a14 = a11;  /* 044a: mov */
  a15 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 044d: -> "mesh_wifi.c" */
  a12 = (u32)(RODATA__rodata_mesh_topo_get_ttl_str1_1 + 0x0);  /* 0450: l32r -> .rodata.mesh_topo_get_ttl.str1.1 */
  ST32(a1 + 0x0, a9);  /* 0453 */
  __asm__ volatile("" ::: "memory");  /* 0456: memw */
  /* 0459: INDIRECT callx a6 <- mem[a9+0x150]; result unknown */ a2 = 0;
  L_045c: a13 = 0x140;  /* 045c */
  a14 = a3 + (38);  /* 045f */
  a13 = a1 + a13;  /* 0462 */
  goto L_0470;  /* 0464: j */
  L_0468: a13 = 208;  /* 0468 */
  a6 = a1 + (112);  /* 046b */
  a13 = a6 + a13;  /* 046e */
  L_0470: a12 = a7;  /* 0470 */
  a11 = a5;  /* 0472 */
  a10 = 1;  /* 0474 */
  a8 = (u32)&esp_mesh_operation_rxseqno + 0x0;  /* 0476: l32r -> global */
  a2 = esp_mesh_operation_rxseqno(a2, a3, a4, a5, a6, a7);  /* 0479: callx a8 via reloc-expand */
  L_047c: a10 = LD32(a1 + 0x148);  /* 047c */
  a8 = (u32)&esp_mesh_match_self + 0x0;  /* 047f: l32r -> global */
  a2 = esp_mesh_match_self(a2, a3, a4, a5, a6, a7);  /* 0482: callx a8 via reloc-expand */
  if (a10 != 0) goto L_04b7;  /* 0485: bnez.n a10, 4b7 <esp_mesh_wifi_recv_cb+0x40b> */
  L_0487: a6 = (u32)&g_mesh_topology + 0x0;  /* 0487: l32r -> global */
  a6 = LD32(a6 + 0x0);  /* 048a */
  if (a6 != 0) goto L_04a6;  /* 048c: bnez.n a6, 4a6 <esp_mesh_wifi_recv_cb+0x3fa> */
  L_048e: a4 = LD8U(a3 + 0x12);  /* 048e */
  a4 = a4 + (-1);  /* 0491 */
  a4 = (a4 >> 8) & 0x1;  /* 0493: extui width 1 */
  ST8(a3 + 0x12, a4);  /* 0496 */
  __asm__ volatile("" ::: "memory");  /* 0499: memw */
  ST32(a1 + 0x128, a4);  /* 049c */
  __asm__ volatile("" ::: "memory");  /* 049f: memw */
  goto L_04b7;  /* 04a2: j */
  L_04a6: a4 = a4 + (-1);  /* 04a6 */
  a6 = (a4 >> 8) & 0x1ff;  /* 04a8: extui width 9 */
  ST32(a1 + 0x128, a4);  /* 04ab */
  ST8(a3 + 0x2d, a4);  /* 04ae */
  ST8(a3 + 0x2e, a6);  /* 04b1 */
  __asm__ volatile("" ::: "memory");  /* 04b4: memw */
  L_04b7: a12 = 0x1ed;  /* 04b7 */
  a11 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 04ba: l32r -> .rodata.__func__$1 */
  a10 = LD32(a1 + 0x144);  /* 04bd */
  __asm__ volatile("" ::: "memory");  /* 04c0: memw */
  a8 = (u32)&esp_mesh_create_context + 0x0;  /* 04c3: l32r -> global */
  a2 = esp_mesh_create_context(a2, a3, a4, a5, a6, a7);  /* 04c6: callx a8 via reloc-expand */
  a4 = a10;  /* 04c9 */
  ST32(a1 + 0x12c, a10);  /* 04cb */
  if (a10 != 0) goto L_05b5;  /* 04ce: bnez a10, 5b5 <esp_mesh_wifi_recv_cb+0x509> */
  L_04d1: a6 = 1;  /* 04d1 */
  a6 = a6 << 24;  /* 04d3 */
  a2 = (u32)&g_log_level + 0x0;  /* 04d6: l32r -> global */
  a8 = LD32(a2 + 0x0);  /* 04d9 */
  a2 = a3 + (18);  /* 04db */
  a7 = LD32(a2 + 0x0);  /* 04de */
  a2 = 0x403;  /* 04e0 */
  a2 = a2 << 14;  /* 04e3 */
  a7 = a7 & a2;  /* 04e6 */
  a2 = 1;  /* 04e9 */
  if (a7 == a6) goto L_04f1;  /* 04eb: beq a7, a6, 4f1 <esp_mesh_wifi_recv_cb+0x445> */
  L_04ee: goto L_0574;  /* 04ee: j */
  L_04f1: a3 = a3 + (14);  /* 04f1 */
  a6 = LD32(a3 + 0x18);  /* 04f3 */
  a9 = a10;  /* 04f5 */
  if (a6 != 0) a9 = a2;  /* 04f7 */
  a7 = (a9 >> 8) & 0x1;  /* 04fa: extui width 1 */
  if (a7 == 0) goto L_0574;  /* 04fd: beqz a7, 574 <esp_mesh_wifi_recv_cb+0x4c8> */
  L_0500: a7 = 0xf0000001u;  /* 0500: l32r = -268435455 */
  a6 = a6 + a7;  /* 0503 */
  if (a6 == 0) a2 = a10;  /* 0506 */
  a2 = (a2 >> 8) & 0x1;  /* 0509: extui width 1 */
  if (a2 == 0) goto L_0574;  /* 050c: beqz a2, 574 <esp_mesh_wifi_recv_cb+0x4c8> */
  L_050f: if (a8 >= 3u) goto L_0515;  /* 050f: bgeui a8, 3, 515 <esp_mesh_wifi_recv_cb+0x469> */
  L_0512: goto L_0754;  /* 0512: j */
  L_0515: a6 = (u32)&g_osi_funcs_p + 0x0;  /* 0515: l32r -> global */
  a2 = LD32(a6 + 0x0);  /* 0518 */
  if (a2 == 0) goto L_0754;  /* 051a: beqz a2, 754 <esp_mesh_wifi_recv_cb+0x6a8> */
  L_051d: a4 = LD32(a2 + 0x150);  /* 051d */
  if (a4 == 0) goto L_0754;  /* 0520: beqz a4, 754 <esp_mesh_wifi_recv_cb+0x6a8> */
  L_0523: a10 = LD32(a2 + 0x158);  /* 0523 */
  __asm__ volatile("" ::: "memory");  /* 0526: memw */
  /* 0529: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 052c: mov */
  a6 = LD32(a6 + 0x0);  /* 052f */
  a10 = LD32(a6 + 0xb8);  /* 0532 */
  /* 0535: INDIRECT callx a10 <- mem[a6+0xb8]; result unknown */ a2 = 0;
  a15 = 0x1ef;  /* 0538 */
  a13 = a2;  /* 053b */
  a3 = LD32(a3 + 0x18);  /* 053d */
  ST32(a1 + 0x1c, a3);  /* 053f */
  a3 = LD8U(a5 + 0x5);  /* 0541 */
  ST32(a1 + 0x18, a3);  /* 0544 */
  a3 = LD8U(a5 + 0x4);  /* 0546 */
  ST32(a1 + 0x14, a3);  /* 0549 */
  a3 = LD8U(a5 + 0x3);  /* 054b */
  ST32(a1 + 0x10, a3);  /* 054e */
  a3 = LD8U(a5 + 0x2);  /* 0550 */
  ST32(a1 + 0xc, a3);  /* 0553 */
  a3 = LD8U(a5 + 0x1);  /* 0555 */
  ST32(a1 + 0x8, a3);  /* 0558 */
  a3 = LD8U(a5 + 0x0);  /* 055a */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 055d: -> "mesh_wifi.c" */
  a14 = a11;  /* 0560 */
  a12 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 0562: -> "AP" */
  ST32(a1 + 0x0, a10);  /* 0565 */
  a10 = 3;  /* 0567 */
  ST32(a1 + 0x4, a3);  /* 0569 */
  __asm__ volatile("" ::: "memory");  /* 056b: memw */
  /* 056e: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  goto L_0754;  /* 0571: j */
  L_0574: if (a8 >= 3u) goto L_057a;  /* 0574: bgeui a8, 3, 57a <esp_mesh_wifi_recv_cb+0x4ce> */
  L_0577: goto L_0754;  /* 0577: j */
  L_057a: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 057a: l32r -> global */
  a2 = LD32(a4 + 0x0);  /* 057d */
  if (a2 == 0) goto L_0754;  /* 057f: beqz a2, 754 <esp_mesh_wifi_recv_cb+0x6a8> */
  L_0582: a3 = LD32(a2 + 0x150);  /* 0582 */
  if (a3 == 0) goto L_0754;  /* 0585: beqz a3, 754 <esp_mesh_wifi_recv_cb+0x6a8> */
  L_0588: a10 = LD32(a2 + 0x158);  /* 0588 */
  /* 058b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 058e */
  a4 = LD32(a4 + 0x0);  /* 0590 */
  a10 = LD32(a4 + 0xb8);  /* 0593 */
  /* 0596: INDIRECT callx a10 <- mem[a4+0xb8]; result unknown */ a2 = 0;
  a15 = 0x1f4;  /* 0599 */
  a13 = a2;  /* 059c */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 059e: -> "mesh_wifi.c" */
  a14 = a11;  /* 05a1 */
  a12 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 05a3: -> "AP" */
  ST32(a1 + 0x0, a10);  /* 05a6 */
  a10 = 3;  /* 05a8 */
  __asm__ volatile("" ::: "memory");  /* 05aa: memw */
  /* 05ad: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0754;  /* 05b0: j */
  L_05b5: a6 = LD32(a1 + 0x144);  /* 05b5 */
  a12 = 6;  /* 05b8 */
  a11 = a5;  /* 05ba */
  ST16(a10 + 0x4, a6);  /* 05bc */
  __asm__ volatile("" ::: "memory");  /* 05bf: memw */
  a10 = a10 + (12);  /* 05c2 */
  __asm__ volatile("" ::: "memory");  /* 05c4: memw */
  a8 = (u32)&memcpy + 0x0;  /* 05c7: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 05ca: callx a8 (libc, via reloc-expand) */
  a11 = a3;  /* 05cd */
  a8 = LD32(a1 + 0x14c);  /* 05cf */
  a7 = a8 << 15;  /* 05d2 */
  ST8(a4 + 0x12, a2);  /* 05d5 */
  __asm__ volatile("" ::: "memory");  /* 05d8: memw */
  a2 = -1;  /* 05db */
  ST32(a4 + 0x20, a2);  /* 05dd */
  a2 = 255;  /* 05df */
  a2 = a2 << 15;  /* 05e2 */
  a7 = a7 & a2;  /* 05e5 */
  a2 = 2;  /* 05e8 */
  a6 = 0xff807ffcu;  /* 05ea: l32r = -8355844 */
  a7 = a7 | a2;  /* 05ed */
  a2 = LD32(a4 + 0x28);  /* 05f0 */
  a2 = a2 & a6;  /* 05f2 */
  a7 = a7 | a2;  /* 05f5 */
  a12 = LD32(a1 + 0x144);  /* 05f8 */
  a10 = LD32(a4 + 0x0);  /* 05fb */
  ST32(a4 + 0x28, a7);  /* 05fd */
  __asm__ volatile("" ::: "memory");  /* 05ff: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0602: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0605: callx a8 (libc, via reloc-expand) */
  a7 = (u32)&g_osi_funcs_p + 0x0;  /* 0608: l32r -> global */
  a3 = LD32(a1 + 0x12c);  /* 060b */
  a2 = LD32(a7 + 0x0);  /* 060e */
  a10 = LD32(a3 + 0x24);  /* 0610 */
  a2 = LD32(a2 + 0xa0);  /* 0612 */
  /* 0615: INDIRECT callx a2 <- mem[a2+0xa0]; result unknown */ a2 = 0;
  a11 = a10;  /* 0618 */
  a10 = 0x12c;  /* 061a */
  a10 = a1 + a10;  /* 061d */
  a8 = (u32)&esp_mesh_push_to_rx_queue;  /* 061f: l32r -> func addr */
  a2 = esp_mesh_push_to_rx_queue(a2, a3, a4, a5, a6, a7);  /* 0622: callx a8 via reloc-expand */
  a6 = a10;  /* 0625 */
  if (a10 == 0) goto L_075a;  /* 0627: beqz a10, 75a <esp_mesh_wifi_recv_cb+0x6ae> */
  L_062a: a2 = LD32(a1 + 0x12c);  /* 062a */
  a3 = 1;  /* 062d */
  a3 = a3 << 24;  /* 062f */
  a11 = LD32(a2 + 0x0);  /* 0632 */
  a2 = a11 + (18);  /* 0634 */
  a4 = LD32(a2 + 0x0);  /* 0637 */
  a2 = 0x403;  /* 0639 */
  a2 = a2 << 14;  /* 063c */
  a4 = a4 & a2;  /* 063f */
  a2 = 1;  /* 0642 */
  if (a4 != a3) goto L_0660;  /* 0644: bne a4, a3, 660 <esp_mesh_wifi_recv_cb+0x5b4> */
  L_0647: a3 = a11 + (14);  /* 0647 */
  a3 = LD32(a3 + 0x18);  /* 0649 */
  a4 = 0;  /* 064b */
  if (a3 == 0) a4 = a2;  /* 064d */
  a8 = (a4 >> 8) & 0x1;  /* 0650: extui width 1 */
  if (a4 != 0) goto L_0660;  /* 0653: bnez.n a4, 660 <esp_mesh_wifi_recv_cb+0x5b4> */
  L_0655: a4 = 0xf0000001u;  /* 0655: l32r = -268435455 */
  a3 = a3 + a4;  /* 0658 */
  if (a3 != 0) a2 = a8;  /* 065a */
  if (a2 == 0) goto L_0739;  /* 065d: beqz a2, 739 <esp_mesh_wifi_recv_cb+0x68d> */
  L_0660: a2 = (u32)&g_log_level + 0x0;  /* 0660: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0663 */
  if (a2 >= 3u) goto L_066b;  /* 0665: bgeui a2, 3, 66b <esp_mesh_wifi_recv_cb+0x5bf> */
  L_0668: goto L_0739;  /* 0668: j */
  L_066b: a2 = LD32(a7 + 0x0);  /* 066b */
  if (a2 == 0) goto L_0739;  /* 066d: beqz a2, 739 <esp_mesh_wifi_recv_cb+0x68d> */
  L_0670: a3 = LD32(a2 + 0x150);  /* 0670 */
  if (a3 == 0) goto L_0739;  /* 0673: beqz a3, 739 <esp_mesh_wifi_recv_cb+0x68d> */
  L_0676: a10 = LD32(a2 + 0x158);  /* 0676 */
  ST32(a1 + 0x188, a11);  /* 0679 */
  __asm__ volatile("" ::: "memory");  /* 067c: memw */
  /* 067f: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 0682 */
  a2 = LD32(a1 + 0x12c);  /* 0684 */
  a8 = LD8U(a2 + 0x12);  /* 0687 */
  a4 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 068a: -> "AP" */
  a11 = LD32(a1 + 0x188);  /* 068d */
  if (a8 == 1) goto L_0696;  /* 0690: beqi a8, 1, 696 <esp_mesh_wifi_recv_cb+0x5ea> */
  L_0693: a4 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 0693: -> "AP" */
  L_0696: a11 = a11 + (14);  /* 0696 */
  a9 = LD8U(a5 + 0x0);  /* 0698 */
  a8 = LD8U(a5 + 0x1);  /* 069b */
  ST32(a1 + 0x144, a9);  /* 069e */
  a9 = LD8U(a5 + 0x2);  /* 06a1 */
  a12 = LD8U(a5 + 0x5);  /* 06a4 */
  ST32(a1 + 0x148, a8);  /* 06a7 */
  ST32(a1 + 0x14c, a9);  /* 06aa */
  a8 = LD8U(a5 + 0x3);  /* 06ad */
  a9 = LD8U(a5 + 0x4);  /* 06b0 */
  a5 = (u32)&LOCAL__bss_mesh_rx_mbox + 0x0;  /* 06b3: l32r -> .bss.mesh_rx_mbox (same-object static) */
  a13 = LD16U(a2 + 0x4);  /* 06b6 */
  a10 = LD32(a5 + 0x0);  /* 06b9 */
  a5 = 0;  /* 06bb */
  a2 = LD8U(a11 + 0x1);  /* 06bd */
  a2 = a2 << 2;  /* 06c0 */
  a14 = LD32(a11 + 0x18);  /* 06c3 */
  a15 = LD32(a1 + 0x128);  /* 06c5 */
  if (a10 == a5) goto L_0700;  /* 06c8: beq a10, a5, 700 <esp_mesh_wifi_recv_cb+0x654> */
  L_06cb: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 06cb: l32r -> global */
  a5 = LD32(a5 + 0x0);  /* 06ce */
  a5 = LD32(a5 + 0x78);  /* 06d1 */
  ST32(a1 + 0x188, a8);  /* 06d4 */
  ST32(a1 + 0x18c, a9);  /* 06d7 */
  ST32(a1 + 0x190, a12);  /* 06da */
  ST32(a1 + 0x194, a13);  /* 06dd */
  ST32(a1 + 0x198, a14);  /* 06e0 */
  ST32(a1 + 0x19c, a15);  /* 06e3 */
  __asm__ volatile("" ::: "memory");  /* 06e6: memw */
  /* 06e9: INDIRECT callx a5 <- mem[a5+0x78]; result unknown */ a2 = 0;
  a5 = a10;  /* 06ec */
  a15 = LD32(a1 + 0x19c);  /* 06ee */
  a14 = LD32(a1 + 0x198);  /* 06f1 */
  a13 = LD32(a1 + 0x194);  /* 06f4 */
  a12 = LD32(a1 + 0x190);  /* 06f7 */
  a9 = LD32(a1 + 0x18c);  /* 06fa */
  a8 = LD32(a1 + 0x188);  /* 06fd */
  L_0700: a10 = 3;  /* 0700 */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 0702: -> "mesh_wifi.c" */
  ST32(a1 + 0x30, a6);  /* 0705 */
  ST32(a1 + 0x20, a2);  /* 0707 */
  a6 = LD32(a1 + 0x148);  /* 0709 */
  a2 = LD32(a1 + 0x14c);  /* 070c */
  ST32(a1 + 0x10, a8);  /* 070f */
  a8 = LD32(a1 + 0x144);  /* 0711 */
  ST32(a1 + 0x18, a12);  /* 0714 */
  a12 = (u32)(RODATA__rodata_esp_mesh_wifi_recv_cb_str1_1 + 0x0);  /* 0716: -> "AP" */
  ST32(a1 + 0x28, a15);  /* 0719 */
  a15 = 0x20e;  /* 071b */
  ST32(a1 + 0x24, a14);  /* 071e */
  a14 = a11;  /* 0720 */
  ST32(a1 + 0x1c, a13);  /* 0722 */
  a13 = a7;  /* 0724 */
  ST32(a1 + 0x2c, a5);  /* 0726 */
  ST32(a1 + 0x14, a9);  /* 0728 */
  ST32(a1 + 0xc, a2);  /* 072a */
  ST32(a1 + 0x8, a6);  /* 072c */
  ST32(a1 + 0x4, a8);  /* 072e */
  ST32(a1 + 0x0, a4);  /* 0730 */
  __asm__ volatile("" ::: "memory");  /* 0733: memw */
  /* 0736: INDIRECT callx a3 <- unknown; result unknown */ a2 = 0;
  L_0739: a12 = 0x22a;  /* 0739 */
  a11 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 073c: l32r -> .rodata.__func__$1 */
  a10 = LD32(a1 + 0x12c);  /* 073f */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0742: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 0745: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_print_txQ_waiting + 0x0;  /* 0748: l32r -> global */
  a2 = esp_mesh_print_txQ_waiting(a2, a3, a4, a5, a6, a7);  /* 074b: callx a8 via reloc-expand */
  a8 = (u32)&esp_mesh_print_rxQ_waiting + 0x0;  /* 074e: l32r -> global */
  a2 = esp_mesh_print_rxQ_waiting(a2, a3, a4, a5, a6, a7);  /* 0751: callx a8 via reloc-expand */
  L_0754: a8 = (u32)&esp_mesh_tx_tid_flush + 0x0;  /* 0754: l32r -> global */
  a2 = esp_mesh_tx_tid_flush(a2, a3, a4, a5, a6, a7);  /* 0757: callx a8 via reloc-expand */
  L_075a: return a2;  /* 075a: retw.n */
}


/* mesh_rx_task_deinit @ mesh_wifi.o 0000001c size 113B bind GLOBAL
 * Calls: esp_mesh_free_context, esp_mesh_free_mbox, memset | indirect[2]: mem[a8+0x74]; mem[a3+0x98] | Data refs: .rodata.__func__$0, .bss.mesh_rx_mbox, .bss.mesh_rx_task, g_osi_funcs_p
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=3, refs=7); reloc-direct=3, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_rx_task_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 001c: entry a1, 48 (frame 48 bytes) */
  a3 = 0;  /* 001f */
  goto L_0034;  /* 0021: j */
  L_0024: a10 = LD32(a1 + 0x0);  /* 0024 */
  if (a10 == 0) goto L_0039;  /* 0026: beqz.n a10, 39 <mesh_rx_task_deinit+0x1d> */
  L_0028: a12 = 0x268;  /* 0028 */
  a11 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 002b: -> "mesh_rx_task_deinit" */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 002e: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 0031: callx a8 via reloc-expand */
  L_0034: a2 = (u32)&LOCAL__bss_mesh_rx_mbox + 0x0;  /* 0034: l32r -> .bss.mesh_rx_mbox (same-object static) */
  ST32(a1 + 0x0, a3);  /* 0037 */
  L_0039: a10 = LD32(a2 + 0x0);  /* 0039 */
  if (a10 != 0) goto L_0061;  /* 003b: bnez.n a10, 61 <mesh_rx_task_deinit+0x45> */
  L_003d: a10 = a2;  /* 003d */
  __asm__ volatile("" ::: "memory");  /* 003f: memw */
  a8 = (u32)&esp_mesh_free_mbox + 0x0;  /* 0042: l32r -> global */
  a2 = esp_mesh_free_mbox(a2, a3, a4, a5, a6, a7);  /* 0045: callx a8 via reloc-expand */
  a10 = a2;  /* 0048 */
  a12 = 12;  /* 004a */
  a11 = 0;  /* 004c */
  a8 = (u32)&memset + 0x0;  /* 004e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0051: callx a8 (libc, via reloc-expand) */
  a2 = (u32)&LOCAL__bss_mesh_rx_task + 0x0;  /* 0054: l32r -> .bss.mesh_rx_task (same-object static) */
  a10 = LD32(a2 + 0x0);  /* 0057 */
  if (a10 != 0) goto L_0079;  /* 0059: bnez.n a10, 79 <mesh_rx_task_deinit+0x5d> */
  L_005b: goto L_0088;  /* 005b: j */
  L_0061: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0061: l32r -> global */
  a12 = a3;  /* 0064 */
  a11 = a1;  /* 0066 */
  a8 = LD32(a8 + 0x0);  /* 0068 */
  a8 = LD32(a8 + 0x74);  /* 006a */
  /* 006d: INDIRECT callx a8 <- mem[a8+0x74]; result unknown */ a2 = 0;
  if (a10 == 1) goto L_0024;  /* 0070: beqi a10, 1, 24 <mesh_rx_task_deinit+0x8> */
  L_0073: goto L_003d;  /* 0073: j */
  L_0079: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0079: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 007c */
  a3 = LD32(a3 + 0x98);  /* 007e */
  /* 0081: INDIRECT callx a3 <- mem[a3+0x98]; result unknown */ a2 = 0;
  a3 = 0;  /* 0084 */
  ST32(a2 + 0x0, a3);  /* 0086 */
  L_0088: __asm__ volatile("" ::: "memory");  /* 0088: memw */
  return a2;  /* 008b: retw.n */
}


/* mesh_rx_task_main @ mesh_wifi.o 0000004c size 546B bind GLOBAL
 * Calls: esp_mesh_discard_context, esp_mesh_recv_xon, esp_mesh_forward_packet, esp_mesh_free_context, mesh_rx_task_deinit | indirect[14]: mem[a4+0x74]; mem[a3+0x158]; mem[a3+0x150]; mem[a4+0x158] | Data refs: .bss.is_rx_running, g_osi_funcs_p, .bss.mesh_rx_mbox, .rodata.esp_mesh_push_to_rx_queue.str1.1, .rodata.mesh_topo_get_ttl.str1.1, .rodata.mesh_rx_task_main.str1.1, g_mesh_topology, .rodata.__func__$3, g_mesh_is_root, .bss.mesh_rx_task
 * Fidelity: medium - 14 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=15); reloc-direct=5, funcdb-attributed=0, unknown-indirect=14 */
u32 mesh_rx_task_main(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 004c: entry a1, 80 (frame 80 bytes) */
  a2 = 0;  /* 004f */
  a3 = (u32)&LOCAL__bss_is_rx_running + 0x0;  /* 0051: l32r -> .bss.is_rx_running (same-object static) */
  ST32(a1 + 0x10, a2);  /* 0054 */
  a2 = 1;  /* 0056 */
  ST8(a3 + 0x0, a2);  /* 0058 */
  __asm__ volatile("" ::: "memory");  /* 005b: memw */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 005e: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0061: memw */
  goto L_024c;  /* 0064: j */
  L_0068: a4 = 0;  /* 0068 */
  ST32(a1 + 0x10, a4);  /* 006a */
  a4 = (u32)&LOCAL__bss_mesh_rx_mbox + 0x0;  /* 006c: l32r -> .bss.mesh_rx_mbox (same-object static) */
  a10 = LD32(a4 + 0x0);  /* 006f */
  if (a10 == 0) goto L_0252;  /* 0071: beqz a10, 252 <mesh_rx_task_main+0x206> */
  L_0074: a12 = -1;  /* 0074 */
  a11 = a1 + (16);  /* 0076 */
  a4 = LD32(a2 + 0x0);  /* 0079 */
  a4 = LD32(a4 + 0x74);  /* 007b */
  __asm__ volatile("" ::: "memory");  /* 007e: memw */
  /* 0081: INDIRECT callx a4 <- mem[a4+0x74]; result unknown */ a2 = 0;
  a7 = a10;  /* 0084 */
  if (a10 == 1) goto L_008c;  /* 0086: beqi a10, 1, 8c <mesh_rx_task_main+0x40> */
  L_0089: goto L_024c;  /* 0089: j */
  L_008c: a4 = LD32(a1 + 0x10);  /* 008c */
  if (a4 != 0) goto L_00c4;  /* 008e: bnez.n a4, c4 <mesh_rx_task_main+0x78> */
  L_0090: a3 = LD8U(a3 + 0x0);  /* 0090 */
  if (a3 == 0) goto L_0252;  /* 0093: beqz a3, 252 <mesh_rx_task_main+0x206> */
  L_0096: a3 = LD32(a2 + 0x0);  /* 0096 */
  if (a3 == 0) goto L_0252;  /* 0098: beqz a3, 252 <mesh_rx_task_main+0x206> */
  L_009b: a4 = LD32(a3 + 0x150);  /* 009b */
  if (a4 == 0) goto L_0252;  /* 009e: beqz a4, 252 <mesh_rx_task_main+0x206> */
  L_00a1: a10 = LD32(a3 + 0x158);  /* 00a1 */
  a3 = 137;  /* 00a4 */
  /* 00a7: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00aa */
  a10 = a7;  /* 00ac */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 00ae: -> "mesh_wifi.c" */
  a14 = a11;  /* 00b1 */
  a15 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 00b3: -> "mesh_wifi.c" */
  a12 = (u32)(RODATA__rodata_mesh_topo_get_ttl_str1_1 + 0x0);  /* 00b6: l32r -> .rodata.mesh_topo_get_ttl.str1.1 */
  ST32(a1 + 0x0, a3);  /* 00b9 */
  __asm__ volatile("" ::: "memory");  /* 00bb: memw */
  /* 00be: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_0252;  /* 00c1: j */
  L_00c4: a5 = LD32(a4 + 0x0);  /* 00c4 */
  if (a5 != 0) goto L_0171;  /* 00c6: bnez a5, 171 <mesh_rx_task_main+0x125> */
  L_00c9: a4 = LD32(a2 + 0x0);  /* 00c9 */
  if (a4 == 0) goto L_0141;  /* 00cb: beqz a4, 141 <mesh_rx_task_main+0xf5> */
  L_00ce: a5 = LD32(a4 + 0x150);  /* 00ce */
  if (a5 == 0) goto L_0141;  /* 00d1: beqz a5, 141 <mesh_rx_task_main+0xf5> */
  L_00d4: a10 = LD32(a4 + 0x158);  /* 00d4 */
  /* 00d7: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a7 = LD32(a1 + 0x10);  /* 00da */
  a4 = LD32(a7 + 0x28);  /* 00dc */
  a8 = (u32)(RODATA__rodata_mesh_rx_task_main_str1_1 + 0x0);  /* 00df: -> "stop" */
  if (((a4 >> 4) & 1) != 0) goto L_00e8;  /* 00e2: bbsi a4, 4, e8 <mesh_rx_task_main+0x9c> */
  L_00e5: a8 = (u32)(RODATA__rodata_mesh_rx_task_main_str1_1 + 0x0);  /* 00e5: -> "stop" */
  L_00e8: a13 = a10;  /* 00e8 */
  a10 = 1;  /* 00ea */
  a4 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 00ec: -> "mesh_wifi.c" */
  a14 = a4;  /* 00ef */
  a11 = a4;  /* 00f1 */
  a6 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 00f3: -> "mesh_wifi.c" */
  a15 = a6;  /* 00f6 */
  ST32(a1 + 0x4, a7);  /* 00f8 */
  a7 = 140;  /* 00fa */
  a12 = (u32)(RODATA__rodata_mesh_rx_task_main_str1_1 + 0x0);  /* 00fd: -> "stop" */
  ST32(a1 + 0x8, a8);  /* 0100 */
  ST32(a1 + 0x0, a7);  /* 0102 */
  __asm__ volatile("" ::: "memory");  /* 0104: memw */
  /* 0107: INDIRECT callx a5 <- unknown; result unknown */ a2 = 0;
  a5 = LD32(a1 + 0x10);  /* 010a */
  if (a5 != 0) goto L_013a;  /* 010c: bnez.n a5, 13a <mesh_rx_task_main+0xee> */
  L_010e: a5 = LD32(a2 + 0x0);  /* 010e */
  if (a5 == 0) goto L_013a;  /* 0110: beqz.n a5, 13a <mesh_rx_task_main+0xee> */
  L_0112: a8 = LD32(a5 + 0x150);  /* 0112 */
  if (a8 == 0) goto L_013a;  /* 0115: beqz.n a8, 13a <mesh_rx_task_main+0xee> */
  L_0117: a10 = LD32(a5 + 0x158);  /* 0117 */
  ST32(a1 + 0x20, a8);  /* 011a */
  __asm__ volatile("" ::: "memory");  /* 011c: memw */
  /* 011f: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0122 */
  a15 = a6;  /* 0124 */
  a14 = a4;  /* 0126 */
  a12 = (u32)(RODATA__rodata_mesh_topo_get_ttl_str1_1 + 0x0);  /* 0128: l32r -> .rodata.mesh_topo_get_ttl.str1.1 */
  a11 = a4;  /* 012b */
  a10 = 1;  /* 012d */
  a8 = LD32(a1 + 0x20);  /* 012f */
  ST32(a1 + 0x0, a7);  /* 0131 */
  __asm__ volatile("" ::: "memory");  /* 0134: memw */
  /* 0137: INDIRECT callx a8 <- mem[a1+0x20]; result unknown */ a2 = 0;
  L_013a: a4 = LD32(a1 + 0x10);  /* 013a */
  a4 = LD32(a4 + 0x0);  /* 013c */
  if (a4 != 0) goto L_01ed;  /* 013e: bnez a4, 1ed <mesh_rx_task_main+0x1a1> */
  L_0141: a4 = LD32(a2 + 0x0);  /* 0141 */
  if (a4 == 0) goto L_01ed;  /* 0143: beqz a4, 1ed <mesh_rx_task_main+0x1a1> */
  L_0146: a5 = LD32(a4 + 0x150);  /* 0146 */
  if (a5 == 0) goto L_01ed;  /* 0149: beqz a5, 1ed <mesh_rx_task_main+0x1a1> */
  L_014c: a10 = LD32(a4 + 0x158);  /* 014c */
  a4 = 140;  /* 014f */
  /* 0152: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0155 */
  a10 = 1;  /* 0157 */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 0159: -> "mesh_wifi.c" */
  a14 = a11;  /* 015c */
  a15 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 015e: -> "mesh_wifi.c" */
  a12 = (u32)(RODATA__rodata_mesh_topo_get_ttl_str1_1 + 0x0);  /* 0161: l32r -> .rodata.mesh_topo_get_ttl.str1.1 */
  ST32(a1 + 0x0, a4);  /* 0164 */
  __asm__ volatile("" ::: "memory");  /* 0166: memw */
  /* 0169: INDIRECT callx a5 <- mem[a4+0x150]; result unknown */ a2 = 0;
  goto L_01ed;  /* 016c: j */
  L_0171: a5 = LD16U(a4 + 0x4);  /* 0171 */
  a6 = 47;  /* 0174 */
  a4 = (u32)&g_mesh_topology + 0x0;  /* 0176: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 0179 */
  a4 = 42;  /* 017b */
  if (a8 != 0) a4 = a6;  /* 017d */
  if (a5 >= a4) goto L_01fe;  /* 0180: bgeu a5, a4, 1fe <mesh_rx_task_main+0x1b2> */
  L_0183: a4 = LD32(a2 + 0x0);  /* 0183 */
  if (a4 == 0) goto L_01ed;  /* 0185: beqz a4, 1ed <mesh_rx_task_main+0x1a1> */
  L_0188: a8 = LD32(a4 + 0x150);  /* 0188 */
  if (a8 == 0) goto L_01ed;  /* 018b: beqz a8, 1ed <mesh_rx_task_main+0x1a1> */
  L_018e: a10 = LD32(a4 + 0x158);  /* 018e */
  ST32(a1 + 0x20, a8);  /* 0191 */
  __asm__ volatile("" ::: "memory");  /* 0193: memw */
  /* 0196: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0199 */
  a10 = a7;  /* 019b */
  a6 = LD32(a1 + 0x10);  /* 019d */
  a6 = LD16U(a6 + 0x4);  /* 019f */
  a4 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 01a2: -> "mesh_wifi.c" */
  a14 = a4;  /* 01a5 */
  a11 = a4;  /* 01a7 */
  a5 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 01a9: -> "mesh_wifi.c" */
  a15 = a5;  /* 01ac */
  ST32(a1 + 0x4, a6);  /* 01ae */
  a6 = 140;  /* 01b0 */
  a12 = (u32)(RODATA__rodata_mesh_rx_task_main_str1_1 + 0x0);  /* 01b3: -> "stop" */
  a8 = LD32(a1 + 0x20);  /* 01b6 */
  ST32(a1 + 0x0, a6);  /* 01b9 */
  __asm__ volatile("" ::: "memory");  /* 01bb: memw */
  /* 01be: INDIRECT callx a8 <- mem[a1+0x20]; result unknown */ a2 = 0;
  a7 = LD32(a1 + 0x10);  /* 01c1 */
  if (a7 != 0) goto L_01ed;  /* 01c3: bnez.n a7, 1ed <mesh_rx_task_main+0x1a1> */
  L_01c5: a8 = LD32(a2 + 0x0);  /* 01c5 */
  if (a8 == 0) goto L_01ed;  /* 01c7: beqz a8, 1ed <mesh_rx_task_main+0x1a1> */
  L_01ca: a7 = LD32(a8 + 0x150);  /* 01ca */
  if (a7 == 0) goto L_01ed;  /* 01cd: beqz.n a7, 1ed <mesh_rx_task_main+0x1a1> */
  L_01cf: a10 = LD32(a8 + 0x158);  /* 01cf */
  /* 01d2: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 01d5 */
  a15 = a5;  /* 01d7 */
  a12 = (u32)(RODATA__rodata_mesh_topo_get_ttl_str1_1 + 0x0);  /* 01d9: l32r -> .rodata.mesh_topo_get_ttl.str1.1 */
  a14 = a4;  /* 01dc */
  a11 = a4;  /* 01de: mov */
  a10 = 1;  /* 01e1 */
  ST32(a1 + 0x0, a6);  /* 01e4 */
  __asm__ volatile("" ::: "memory");  /* 01e7: memw */
  /* 01ea: INDIRECT callx a7 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_01ed: a13 = 140;  /* 01ed */
  a11 = 8;  /* 01f0 */
  a12 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 01f2: l32r -> .rodata.__func__$3 */
  a10 = LD32(a1 + 0x10);  /* 01f5 */
  a8 = (u32)&esp_mesh_discard_context + 0x0;  /* 01f8: l32r -> global */
  a2 = esp_mesh_discard_context(a2, a3, a4, a5, a6, a7);  /* 01fb: callx a8 via reloc-expand */
  L_01fe: a10 = LD32(a1 + 0x10);  /* 01fe */
  a4 = LD32(a10 + 0x0);  /* 0200 */
  a4 = a4 + (18);  /* 0202 */
  a4 = LD32(a4 + 0x0);  /* 0205 */
  if (((a4 >> 8) & 1) == 0) goto L_0218;  /* 0207: bbci a4, 8, 218 <mesh_rx_task_main+0x1cc> */
  L_020a: a8 = (u32)&esp_mesh_recv_xon + 0x0;  /* 020a: l32r -> global */
  a2 = esp_mesh_recv_xon(a2, a3, a4, a5, a6, a7);  /* 020d: callx a8 via reloc-expand */
  a12 = 164;  /* 0210 */
  goto L_0241;  /* 0213: j */
  L_0218: a4 = (u32)&g_mesh_is_root + 0x0;  /* 0218: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 021b: memw */
  a9 = LD8U(a4 + 0x0);  /* 021e */
  a4 = -9;  /* 0221 */
  a9 = (a9 >> 1) & 0x1;  /* 0223: extui width 1 */
  a9 = a9 << 3;  /* 0226 */
  a8 = LD32(a10 + 0x28);  /* 0229 */
  a8 = a8 & a4;  /* 022b */
  a8 = a8 | a9;  /* 022e */
  ST32(a10 + 0x28, a8);  /* 0231 */
  __asm__ volatile("" ::: "memory");  /* 0233: memw */
  a8 = (u32)&esp_mesh_forward_packet + 0x0;  /* 0236: l32r -> global */
  a2 = esp_mesh_forward_packet(a2, a3, a4, a5, a6, a7);  /* 0239: callx a8 via reloc-expand */
  if (a10 == 0) goto L_024c;  /* 023c: beqz.n a10, 24c <mesh_rx_task_main+0x200> */
  L_023e: a12 = 229;  /* 023e */
  L_0241: a11 = (u32)(RODATA__rodata___func___3 + 0x0);  /* 0241: l32r -> .rodata.__func__$3 */
  a10 = LD32(a1 + 0x10);  /* 0244 */
  a8 = (u32)&esp_mesh_free_context + 0x0;  /* 0246: l32r -> global */
  a2 = esp_mesh_free_context(a2, a3, a4, a5, a6, a7);  /* 0249: callx a8 via reloc-expand */
  L_024c: a4 = LD8U(a3 + 0x0);  /* 024c */
  if (a4 != 0) goto L_0068;  /* 024f: bnez a4, 68 <mesh_rx_task_main+0x1c> */
  L_0252: a4 = (u32)&LOCAL__bss_mesh_rx_task + 0x0;  /* 0252: l32r -> .bss.mesh_rx_task (same-object static) */
  a3 = 0;  /* 0255 */
  ST32(a4 + 0x0, a3);  /* 0257 */
  __asm__ volatile("" ::: "memory");  /* 0259: memw */
  a8 = (u32)&mesh_rx_task_deinit;  /* 025c: l32r -> func addr */
  a2 = mesh_rx_task_deinit(a2, a3, a4, a5, a6, a7);  /* 025f: callx a8 via reloc-expand */
  a10 = a3;  /* 0262 */
  a2 = LD32(a2 + 0x0);  /* 0264 */
  a2 = LD32(a2 + 0x98);  /* 0266 */
  /* 0269: INDIRECT callx a2 <- mem[a2+0x98]; result unknown */ a2 = 0;
  return a2;  /* 026c: retw.n */
}


/* mesh_topo_get_ttl @ mesh_wifi.o 0000001c size 166B bind GLOBAL
 * Calls: none | indirect[4]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x158]; mem[a3+0x150] | Data refs: g_mesh_topology, g_log_level, g_osi_funcs_p, .rodata.esp_mesh_push_to_rx_queue.str1.1, .rodata.mesh_topo_get_ttl.str1.1
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=5); reloc-direct=0, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_topo_get_ttl(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 001c: entry a1, 48 (frame 48 bytes) */
  a4 = (u32)&g_mesh_topology + 0x0;  /* 001f: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0022 */
  if (a4 != 0) goto L_002c;  /* 0024: bnez.n a4, 2c <mesh_topo_get_ttl+0x10> */
  L_0026: a2 = LD8U(a2 + 0x4);  /* 0026 */
  goto L_00c0;  /* 0029: j */
  L_002c: a2 = LD8U(a3 + 0x0);  /* 002c */
  if (a2 != 6) goto L_0041;  /* 002f: bnei a2, 6, 41 <mesh_topo_get_ttl+0x25> */
  L_0032: a2 = LD8U(a3 + 0x2);  /* 0032 */
  a2 = a2 << 8;  /* 0035 */
  a4 = LD8U(a3 + 0x1);  /* 0038 */
  a2 = a2 | a4;  /* 003b */
  if (a2 == 2) goto L_00b4;  /* 003e: beqi a2, 2, b4 <mesh_topo_get_ttl+0x98> */
  L_0041: a2 = (u32)&g_log_level + 0x0;  /* 0041: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0044 */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0046: l32r -> global */
  if (a2 < 3u) goto L_0085;  /* 0049: bltui a2, 3, 85 <mesh_topo_get_ttl+0x69> */
  L_004c: a2 = LD32(a4 + 0x0);  /* 004c */
  if (a2 == 0) goto L_0085;  /* 004e: beqz.n a2, 85 <mesh_topo_get_ttl+0x69> */
  L_0050: a5 = LD32(a2 + 0x150);  /* 0050 */
  if (a5 == 0) goto L_0085;  /* 0053: beqz a5, 85 <mesh_topo_get_ttl+0x69> */
  L_0056: a10 = LD32(a2 + 0x158);  /* 0056 */
  /* 0059: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 005c */
  a15 = 250;  /* 005e */
  a2 = LD8U(a3 + 0x2);  /* 0061 */
  a10 = 3;  /* 0064 */
  a2 = a2 << 8;  /* 0066 */
  a8 = LD8U(a3 + 0x1);  /* 0069 */
  a2 = a2 | a8;  /* 006c */
  ST32(a1 + 0x4, a2);  /* 006f */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 0071: -> "mesh_wifi.c" */
  a14 = a11;  /* 0074 */
  a2 = LD8U(a3 + 0x0);  /* 0076 */
  a12 = (u32)(RODATA__rodata_mesh_topo_get_ttl_str1_1 + 0x0);  /* 0079: l32r -> .rodata.mesh_topo_get_ttl.str1.1 */
  ST32(a1 + 0x0, a2);  /* 007c */
  __asm__ volatile("" ::: "memory");  /* 007f: memw */
  /* 0082: INDIRECT callx a5 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0085: a2 = -1;  /* 0085 */
  a3 = LD32(a4 + 0x0);  /* 0087 */
  if (a3 == 0) goto L_00c0;  /* 0089: beqz.n a3, c0 <mesh_topo_get_ttl+0xa4> */
  L_008b: a4 = LD32(a3 + 0x150);  /* 008b */
  if (a4 == 0) goto L_00c0;  /* 008e: beqz.n a4, c0 <mesh_topo_get_ttl+0xa4> */
  L_0090: a10 = LD32(a3 + 0x158);  /* 0090 */
  a3 = 252;  /* 0093 */
  /* 0096: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0099 */
  a10 = 1;  /* 009b */
  a11 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 009d: -> "mesh_wifi.c" */
  a14 = a11;  /* 00a0 */
  a15 = (u32)(RODATA__rodata_esp_mesh_push_to_rx_queue_str1_1 + 0x0);  /* 00a2: -> "mesh_wifi.c" */
  a12 = (u32)(RODATA__rodata_mesh_topo_get_ttl_str1_1 + 0x0);  /* 00a5: l32r -> .rodata.mesh_topo_get_ttl.str1.1 */
  ST32(a1 + 0x0, a3);  /* 00a8 */
  __asm__ volatile("" ::: "memory");  /* 00aa: memw */
  /* 00ad: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_00c0;  /* 00b0: j */
  L_00b4: a2 = LD8U(a3 + 0x4);  /* 00b4 */
  a2 = a2 << 8;  /* 00b7 */
  a4 = LD8U(a3 + 0x3);  /* 00ba */
  a2 = a2 | a4;  /* 00bd */
  L_00c0: return a2;  /* 00c0: retw.n */
}

