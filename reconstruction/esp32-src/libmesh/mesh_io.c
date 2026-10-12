/* libmesh.a mesh_io.o --- reconstructed C (offline).
 * Role: IO control: self-organized mode, type, router, channel switch, scan requests.
 * Object file: 19344 bytes on disk; 11/11 functions reconstructed, ~2221 code bytes.
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
extern u32 g_is_root_fixed; /* undefined data (reloc-referenced) */
extern u32 g_is_standalone_sta; /* undefined data (reloc-referenced) */
extern u32 g_is_wifi_connected; /* undefined data (reloc-referenced) */
extern u32 g_is_wifi_disconnecting; /* undefined data (reloc-referenced) */
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ext_cfg; /* undefined data (reloc-referenced) */
extern u32 g_mesh_ie; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_manual_nwk; /* undefined data (reloc-referenced) */
extern u32 g_mesh_self_organized; /* undefined data (reloc-referenced) */
extern u32 g_mesh_stop_reconnection; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 mesh_ioctl_sem; /* undefined data (reloc-referenced) */
extern u32 mesh_myself_mbox; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_clear_parent(); /* defined in another libmesh.a object */
extern u32 esp_mesh_get_router_bssid(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_is_nwk_inited(); /* defined in another libmesh.a object */
extern u32 esp_mesh_is_nwk_running(); /* defined in another libmesh.a object */
extern u32 esp_mesh_nvs_set_assoc(); /* defined in another libmesh.a object */
extern u32 esp_mesh_nvs_set_layer(); /* defined in another libmesh.a object */
extern u32 esp_mesh_push_to_nwk_queue(); /* defined in another libmesh.a object */
extern u32 esp_mesh_recv_release(); /* defined in another libmesh.a object */
extern u32 esp_mesh_set_router_bssid(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_switch_channel_internal(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_disconnect(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_config(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_get_mode(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_config(); /* undefined func (args unknown, returns u32) */
extern u32 esp_wifi_set_mode(); /* undefined func (args unknown, returns u32) */
extern u32 io_cfg2str(); /* defined in another libmesh.a object */
extern u32 mesh_connect_to_router(); /* defined in another libmesh.a object */
extern u32 mesh_get_subnet_nodes_list(); /* defined in another libmesh.a object */
extern u32 mesh_get_subnet_nodes_num(); /* defined in another libmesh.a object */
extern u32 mesh_ie_type2str(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_lock(); /* defined in another libmesh.a object */
extern u32 mesh_mutex_unlock(); /* defined in another libmesh.a object */
extern u32 mesh_nwk_manual_networking(); /* defined in another libmesh.a object */
extern u32 mesh_ps_get_duties(); /* defined in another libmesh.a object */
extern u32 mesh_set_id(); /* defined in another libmesh.a object */
extern u32 mesh_set_ie_crypto_funcs(); /* defined in another libmesh.a object */
extern u32 mesh_set_ie_crypto_key(); /* defined in another libmesh.a object */
extern u32 mesh_set_parent(); /* defined in another libmesh.a object */
extern u32 reconnect_type2str(); /* defined in another libmesh.a object */
static const u8 RODATA__rodata___func___0[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x74, 0x5f, 0x73, 0x65, 0x6c, 0x66, 0x5f, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x00 }; /* .rodata.__func__$0 (24 bytes) strings: [0x0]="mesh_set_self_organized" */
static const u8 RODATA__rodata___func___1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x65, 0x74, 0x5f, 0x69, 0x6f, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x00 }; /* .rodata.__func__$1 (20 bytes) strings: [0x0]="mesh_set_io_process" */
static const u8 RODATA__rodata_mesh_nwk_io_process[] = { 0xbb, 0x00, 0x00, 0x00, 0xcd, 0x00, 0x00, 0x00, 0x31, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x4f, 0x01, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x6e, 0x01, 0x00, 0x00, 0x88, 0x01, 0x00, 0x00, 0x98, 0x01, 0x00, 0x00, 0xa4, 0x01, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00, 0xbb, 0x01, 0x00, 0x00, 0xc6, 0x01, 0x00, 0x00 }; /* .rodata.mesh_nwk_io_process (52 bytes) */
static const u8 RODATA__rodata_mesh_nwk_io_process_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x49, 0x4f, 0x5d, 0x3c, 0x25, 0x73, 0x3e, 0x6e, 0x65, 0x77, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x20, 0x49, 0x44, 0x20, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78 }; /* .rodata.mesh_nwk_io_process.str1.1 (60 bytes) */
static const u8 RODATA__rodata_mesh_set_io_process_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x69, 0x6f, 0x2e, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67 }; /* .rodata.mesh_set_io_process.str1.1 (40 bytes) strings: [0x0]="mesh_io.c"; [0xa]="mesh" */
static const u8 RODATA__rodata_mesh_set_router_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x2c, 0x20, 0x73, 0x73, 0x69, 0x64, 0x5f, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x73, 0x69, 0x64, 0x3a, 0x25, 0x73, 0x2c, 0x20, 0x62, 0x73, 0x73, 0x69, 0x64, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x3a, 0x25, 0x30, 0x32, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x20, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x2c, 0x20, 0x6c, 0x65, 0x6e, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a, 0x25, 0x73, 0x0a, 0x00 }; /* .rodata.mesh_set_router.str1.1 (168 bytes) */
static const u8 RODATA__rodata_mesh_set_self_organized_str1_1[] = { 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x2d, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x69, 0x6e, 0x67, 0x00, 0x64, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x2d, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x69, 0x6e, 0x67, 0x00, 0x2c, 0x20, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x00, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x49, 0x4f, 0x5d, 0x25, 0x73, 0x25, 0x73, 0x3c, 0x25, 0x73, 0x3e, 0x0a }; /* .rodata.mesh_set_self_organized.str1.1 (88 bytes) strings: [0x0]="enable self-organizing"; [0x17]="disable self-organizing"; [0x2f]=", search parent" */
static const u8 RODATA__rodata_mesh_set_type_str1_1[] = { 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x25, 0x73, 0x28, 0x41, 0x50, 0x2b, 0x53, 0x54, 0x41, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x29, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x25, 0x73, 0x28, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x29, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5d, 0x66, 0x61, 0x69, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x74, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78 }; /* .rodata.mesh_set_type.str1.1 (160 bytes) */
static u8 LOCAL__bss_MESH_ZERO_ADDR[0x4]; /* stand-in for .bss.MESH_ZERO_ADDR (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_csa_bssid[0x4]; /* stand-in for .bss.csa_bssid (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_io_error[0x4]; /* stand-in for .bss.s_mesh_io_error (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_io_sem_signal @ mesh_io.o 00000008 size 23B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x40] | Data refs: mesh_ioctl_sem, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_io_sem_signal(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&mesh_ioctl_sem + 0x0;  /* 000b: l32r -> global */
  a10 = LD32(a8 + 0x0);  /* 000e */
  if (a10 == 0) goto L_001d;  /* 0010: beqz.n a10, 1d <esp_mesh_io_sem_signal+0x15> */
  L_0012: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0012: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0015 */
  a8 = LD32(a8 + 0x40);  /* 0017 */
  /* 001a: INDIRECT callx a8 <- mem[a8+0x40]; result unknown */ a2 = 0;
  L_001d: return a2;  /* 001d: retw.n */
}


/* esp_mesh_io_sem_wait @ mesh_io.o 00000008 size 24B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x3c] | Data refs: mesh_ioctl_sem, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_io_sem_wait(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&mesh_ioctl_sem + 0x0;  /* 000b: l32r -> global */
  a10 = LD32(a8 + 0x0);  /* 000e */
  if (a10 == 0) goto L_001e;  /* 0010: beqz.n a10, 1e <esp_mesh_io_sem_wait+0x16> */
  L_0012: a11 = -1;  /* 0012 */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0014: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0017 */
  a8 = LD32(a8 + 0x3c);  /* 0019 */
  /* 001b: INDIRECT callx a8 <- mem[a8+0x3c]; result unknown */ a2 = 0;
  L_001e: return a2;  /* 001e: retw.n */
}


/* esp_mesh_stop_parent_reconnection @ mesh_io.o 00000018 size 86B bind GLOBAL
 * Calls: memset, esp_mesh_is_nwk_inited, esp_mesh_is_nwk_running, mesh_set_io_process | indirect[1]: mem[a8+0xa4] | Data refs: g_mesh_stop_reconnection, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=4, refs=6); reloc-direct=4, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_stop_parent_reconnection(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0018: entry a1, 64 (frame 64 bytes) */
  a12 = 20;  /* 001b */
  a11 = 0;  /* 001d */
  a10 = a1;  /* 0020: mov */
  a2 = (a2 >> 8) & 0x1;  /* 0023: extui width 1 */
  a8 = (u32)&memset + 0x0;  /* 0026: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0029: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 002c: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 002f: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0041;  /* 0032: bnez.n a10, 41 <esp_mesh_stop_parent_reconnection+0x29> */
  L_0034: a8 = (u32)&g_mesh_stop_reconnection + 0x0;  /* 0034: l32r -> global */
  ST32(a8 + 0x0, a2);  /* 0037 */
  __asm__ volatile("" ::: "memory");  /* 0039: memw */
  goto L_006a;  /* 003c: j */
  L_0041: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0041: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 0044 */
  a10 = LD32(a8 + 0xa4);  /* 0046 */
  /* 0049: INDIRECT callx a10 <- mem[a8+0xa4]; result unknown */ a2 = 0;
  a8 = (u32)&esp_mesh_is_nwk_running + 0x0;  /* 004c: l32r -> global */
  a2 = esp_mesh_is_nwk_running(a2, a3, a4, a5, a6, a7);  /* 004f: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0034;  /* 0052: bnez a10, 34 <esp_mesh_stop_parent_reconnection+0x1c> */
  L_0055: a8 = 7;  /* 0055 */
  a10 = a1;  /* 0057 */
  ST32(a1 + 0x0, a8);  /* 0059 */
  ST8(a1 + 0x4, a2);  /* 005b */
  __asm__ volatile("" ::: "memory");  /* 005e: memw */
  __asm__ volatile("" ::: "memory");  /* 0061: memw */
  a8 = (u32)&mesh_set_io_process;  /* 0064: l32r -> func addr */
  a2 = mesh_set_io_process(a2, a3, a4, a5, a6, a7);  /* 0067: callx a8 via reloc-expand */
  L_006a: a2 = 0;  /* 006a */
  return a2;  /* 006c: retw.n */
}


/* mesh_csa_set_bssid @ mesh_io.o 00000024 size 110B bind GLOBAL
 * Calls: memcmp, memset, esp_wifi_get_config, memcpy, esp_wifi_set_config, esp_mesh_set_router_bssid | Data refs: .bss.csa_bssid, .bss.MESH_ZERO_ADDR
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=6, refs=8); reloc-direct=6, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_csa_set_bssid(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0024: entry a1, 224 (frame 224 bytes) */
  a2 = (u32)&LOCAL__bss_csa_bssid + 0x0;  /* 0027: l32r -> .bss.csa_bssid (same-object static) */
  a12 = 6;  /* 002a */
  a10 = a2;  /* 002d: mov */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 0030: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a8 = (u32)&memcmp + 0x0;  /* 0033: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0036: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_008e;  /* 0039: beqz a10, 8e <mesh_csa_set_bssid+0x6a> */
  L_003c: a12 = 184;  /* 003c */
  a11 = 0;  /* 003f */
  a10 = a1;  /* 0041: mov */
  a8 = (u32)&memset + 0x0;  /* 0044: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0047: callx a8 (libc, via reloc-expand) */
  a11 = a1;  /* 004a */
  a10 = 0;  /* 004c */
  a8 = (u32)&esp_wifi_get_config + 0x0;  /* 004e: l32r -> global */
  a2 = esp_wifi_get_config(a2, a3, a4, a5, a6, a7);  /* 0051: callx a8 via reloc-expand */
  a3 = a10;  /* 0054 */
  if (a10 != 0) goto L_0082;  /* 0056: bnez.n a10, 82 <mesh_csa_set_bssid+0x5e> */
  L_0058: a8 = 1;  /* 0058 */
  a12 = 6;  /* 005a */
  a11 = a2;  /* 005c */
  a10 = a1 + (101);  /* 005e */
  ST8(a1 + 0x64, a8);  /* 0061 */
  __asm__ volatile("" ::: "memory");  /* 0064: memw */
  __asm__ volatile("" ::: "memory");  /* 0067: memw */
  a8 = (u32)&memcpy + 0x0;  /* 006a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 006d: callx a8 (libc, via reloc-expand) */
  a11 = a1;  /* 0070 */
  a10 = a3;  /* 0072 */
  a8 = (u32)&esp_wifi_set_config + 0x0;  /* 0074: l32r -> global */
  a2 = esp_wifi_set_config(a2, a3, a4, a5, a6, a7);  /* 0077: callx a8 via reloc-expand */
  a10 = a2;  /* 007a */
  a8 = (u32)&esp_mesh_set_router_bssid + 0x0;  /* 007c: l32r -> global */
  a2 = esp_mesh_set_router_bssid(a2, a3, a4, a5, a6, a7);  /* 007f: callx a8 via reloc-expand */
  L_0082: a12 = 6;  /* 0082 */
  a11 = 0;  /* 0084 */
  a10 = a2;  /* 0086 */
  a8 = (u32)&memset + 0x0;  /* 0088: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 008b: callx a8 (libc, via reloc-expand) */
  L_008e: a2 = 0;  /* 008e */
  return a2;  /* 0090: retw.n */
}


/* mesh_look_for_network @ mesh_io.o 00000010 size 56B bind GLOBAL
 * Calls: memset, esp_wifi_set_mode, esp_mesh_push_to_nwk_queue | Data refs: g_is_standalone_sta
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=4); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_look_for_network(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0010: entry a1, 224 (frame 224 bytes) */
  a12 = 180;  /* 0013 */
  a11 = 0;  /* 0016 */
  a10 = a1 + (4);  /* 0019 */
  a8 = (u32)&memset + 0x0;  /* 001c: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 001f: callx a8 (libc, via reloc-expand) */
  a8 = 43;  /* 0022 */
  ST32(a1 + 0x0, a8);  /* 0024 */
  a8 = (u32)&g_is_standalone_sta + 0x0;  /* 0026: l32r -> global */
  a8 = LD8U(a8 + 0x0);  /* 0029 */
  if (a8 != 0) goto L_003a;  /* 002c: bnez.n a8, 3a <mesh_look_for_network+0x2a> */
  L_002e: a10 = 1;  /* 002e */
  __asm__ volatile("" ::: "memory");  /* 0031: memw */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 0034: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 0037: callx a8 via reloc-expand */
  L_003a: a11 = 0;  /* 003a */
  a10 = a1;  /* 003c */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 003e: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 0041: callx a8 via reloc-expand */
  a2 = 0;  /* 0044 */
  return a2;  /* 0046: retw.n */
}


/* mesh_nwk_io_process @ mesh_io.o 00000060 size 380B bind GLOBAL
 * Calls: mesh_set_self_organized, io_cfg2str, mesh_set_id, mesh_get_subnet_nodes_num, mesh_get_subnet_nodes_list, mesh_set_parent, mesh_set_ie_crypto_funcs, strnlen, mesh_set_ie_crypto_key, mesh_set_type, mesh_set_router, mesh_switch_channel, mesh_look_for_network, mesh_ps_get_duties | indirect[4]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x158]; unknown | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_set_io_process.str1.1, .rodata.mesh_nwk_io_process, .rodata.mesh_nwk_io_process.str1.1, g_mesh_stop_reconnection, .bss.s_mesh_io_error
 * Fidelity: low - jump-table switch present; cases not recovered
 * Edges: funcdb-v3 (calls=14, refs=21); reloc-direct=14, funcdb-attributed=0, unknown-indirect=4 */
u32 mesh_nwk_io_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0060: entry a1, 64 (frame 64 bytes) */
  if (a2 != 0) goto L_00a4;  /* 0063: bnez.n a2, a4 <mesh_nwk_io_process+0x44> */
  L_0065: a2 = (u32)&g_log_level + 0x0;  /* 0065: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0068 */
  a3 = 0x00004008u;  /* 006a: l32r = 16392 */
  if (a2 >= 3u) goto L_0073;  /* 006d: bgeui a2, 3, 73 <mesh_nwk_io_process+0x13> */
  L_0070: goto L_01d5;  /* 0070: j */
  L_0073: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0073: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0076 */
  if (a2 == 0) goto L_01d5;  /* 0078: beqz a2, 1d5 <mesh_nwk_io_process+0x175> */
  L_007b: a4 = LD32(a2 + 0x150);  /* 007b */
  if (a4 == 0) goto L_01d5;  /* 007e: beqz a4, 1d5 <mesh_nwk_io_process+0x175> */
  L_0081: a10 = LD32(a2 + 0x158);  /* 0081 */
  a2 = 101;  /* 0084 */
  /* 0087: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 008a */
  a10 = 3;  /* 008c */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 008e: -> "mesh_io.c" */
  a14 = a11;  /* 0091 */
  a15 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0093: -> "mesh_io.c" */
  a12 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0096: -> "mesh_io.c" */
  ST32(a1 + 0x0, a2);  /* 0099 */
  __asm__ volatile("" ::: "memory");  /* 009b: memw */
  /* 009e: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_01d5;  /* 00a1: j */
  L_00a4: a8 = LD32(a2 + 0x0);  /* 00a4 */
  a4 = 12;  /* 00a6 */
  a3 = 0;  /* 00a8 */
  if (a4 >= a8) goto L_00b0;  /* 00aa: bgeu a4, a8, b0 <mesh_nwk_io_process+0x50> */
  L_00ad: goto L_01d0;  /* 00ad: j */
  L_00b0: a3 = (u32)(RODATA__rodata_mesh_nwk_io_process + 0x0);  /* 00b0: l32r -> .rodata.mesh_nwk_io_process */
  a8 = a8 + (a3 << 2);  /* 00b3 */
  a3 = LD32(a8 + 0x0);  /* 00b6 */
  /* 00b8: jx a3 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a11 = LD8U(a2 + 0x5);  /* 00bb */
  a12 = 2;  /* 00be */
  a10 = LD8U(a2 + 0x4);  /* 00c0 */
  a8 = (u32)&mesh_set_self_organized;  /* 00c3: l32r -> func addr */
  a2 = mesh_set_self_organized(a2, a3, a4, a5, a6, a7);  /* 00c6: callx a8 via reloc-expand */
  goto L_01ce;  /* 00c9: j */
  a3 = (u32)&g_log_level + 0x0;  /* 00cd: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d0 */
  if (a3 < 3u) goto L_0126;  /* 00d2: bltui a3, 3, 126 <mesh_nwk_io_process+0xc6> */
  L_00d5: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00d5: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d8 */
  if (a3 == 0) goto L_0126;  /* 00db: beqz a3, 126 <mesh_nwk_io_process+0xc6> */
  L_00de: a4 = LD32(a3 + 0x150);  /* 00de */
  if (a4 == 0) goto L_0126;  /* 00e1: beqz a4, 126 <mesh_nwk_io_process+0xc6> */
  L_00e4: a10 = LD32(a3 + 0x158);  /* 00e4 */
  /* 00e7: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a3 = a10;  /* 00ea */
  a10 = LD32(a2 + 0x0);  /* 00ec */
  a8 = (u32)&io_cfg2str + 0x0;  /* 00ee: l32r -> global */
  a2 = io_cfg2str(a2, a3, a4, a5, a6, a7);  /* 00f1: callx a8 via reloc-expand */
  a15 = a10;  /* 00f4 */
  a13 = a3;  /* 00f6 */
  a8 = LD8U(a2 + 0x9);  /* 00f8 */
  a10 = 3;  /* 00fb */
  ST32(a1 + 0x14, a8);  /* 00fd */
  a8 = LD8U(a2 + 0x8);  /* 00ff */
  ST32(a1 + 0x10, a8);  /* 0102 */
  a8 = LD8U(a2 + 0x7);  /* 0104 */
  ST32(a1 + 0xc, a8);  /* 0107 */
  a8 = LD8U(a2 + 0x6);  /* 0109 */
  ST32(a1 + 0x8, a8);  /* 010c */
  a8 = LD8U(a2 + 0x5);  /* 010e */
  ST32(a1 + 0x4, a8);  /* 0111 */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0113: -> "mesh_io.c" */
  a14 = a11;  /* 0116 */
  a8 = LD8U(a2 + 0x4);  /* 0118 */
  a12 = (u32)(RODATA__rodata_mesh_nwk_io_process_str1_1 + 0x0);  /* 011b: l32r -> .rodata.mesh_nwk_io_process.str1.1 */
  ST32(a1 + 0x0, a8);  /* 011e */
  __asm__ volatile("" ::: "memory");  /* 0120: memw */
  /* 0123: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  L_0126: a10 = a2 + (4);  /* 0126 */
  a8 = (u32)&mesh_set_id + 0x0;  /* 0128: l32r -> global */
  a2 = mesh_set_id(a2, a3, a4, a5, a6, a7);  /* 012b: callx a8 via reloc-expand */
  goto L_01ce;  /* 012e: j */
  a11 = LD32(a2 + 0x8);  /* 0131 */
  a10 = LD32(a2 + 0x4);  /* 0133 */
  a8 = (u32)&mesh_get_subnet_nodes_num + 0x0;  /* 0136: l32r -> global */
  a2 = mesh_get_subnet_nodes_num(a2, a3, a4, a5, a6, a7);  /* 0139: callx a8 via reloc-expand */
  goto L_01ce;  /* 013c: j */
  a12 = LD32(a2 + 0x8);  /* 0140 */
  a11 = LD32(a2 + 0xc);  /* 0142 */
  a10 = LD32(a2 + 0x4);  /* 0144 */
  a8 = (u32)&mesh_get_subnet_nodes_list + 0x0;  /* 0146: l32r -> global */
  a2 = mesh_get_subnet_nodes_list(a2, a3, a4, a5, a6, a7);  /* 0149: callx a8 via reloc-expand */
  goto L_01ce;  /* 014c: j */
  a13 = LD32(a2 + 0x10);  /* 014f */
  a12 = LD32(a2 + 0xc);  /* 0151 */
  a11 = LD32(a2 + 0x8);  /* 0153 */
  a10 = LD32(a2 + 0x4);  /* 0155 */
  a8 = (u32)&mesh_set_parent + 0x0;  /* 0157: l32r -> global */
  a2 = mesh_set_parent(a2, a3, a4, a5, a6, a7);  /* 015a: callx a8 via reloc-expand */
  goto L_01ce;  /* 015d: j */
  a10 = LD32(a2 + 0x4);  /* 0160 */
  a8 = (u32)&mesh_set_ie_crypto_funcs + 0x0;  /* 0162: l32r -> global */
  a2 = mesh_set_ie_crypto_funcs(a2, a3, a4, a5, a6, a7);  /* 0165: callx a8 via reloc-expand */
  goto L_01ce;  /* 0168: j */
  a2 = LD32(a2 + 0x4);  /* 016e */
  a11 = 32;  /* 0170 */
  a10 = a2;  /* 0172 */
  a8 = (u32)&strnlen + 0x0;  /* 0174: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0177: callx a8 (libc, via reloc-expand) */
  a11 = a10;  /* 017a */
  a10 = a2;  /* 017c */
  a8 = (u32)&mesh_set_ie_crypto_key + 0x0;  /* 017e: l32r -> global */
  a2 = mesh_set_ie_crypto_key(a2, a3, a4, a5, a6, a7);  /* 0181: callx a8 via reloc-expand */
  goto L_01ce;  /* 0184: j */
  a3 = LD8U(a2 + 0x4);  /* 0188 */
  a2 = (u32)&g_mesh_stop_reconnection + 0x0;  /* 018b: l32r -> global */
  ST32(a2 + 0x0, a3);  /* 018e */
  a3 = 0;  /* 0190 */
  __asm__ volatile("" ::: "memory");  /* 0192: memw */
  goto L_01d0;  /* 0195: j */
  a10 = LD32(a2 + 0x4);  /* 0198 */
  a8 = (u32)&mesh_set_type;  /* 019a: l32r -> func addr */
  a2 = mesh_set_type(a2, a3, a4, a5, a6, a7);  /* 019d: callx a8 via reloc-expand */
  goto L_01ce;  /* 01a0: j */
  a10 = LD32(a2 + 0x4);  /* 01a4 */
  a8 = (u32)&mesh_set_router;  /* 01a6: l32r -> func addr */
  a2 = mesh_set_router(a2, a3, a4, a5, a6, a7);  /* 01a9: callx a8 via reloc-expand */
  goto L_01ce;  /* 01ac: j */
  a10 = a2 + (4);  /* 01b0 */
  a8 = (u32)&mesh_switch_channel;  /* 01b2: l32r -> func addr */
  a2 = mesh_switch_channel(a2, a3, a4, a5, a6, a7);  /* 01b5: callx a8 via reloc-expand */
  goto L_01ce;  /* 01b8: j */
  a8 = (u32)&mesh_look_for_network;  /* 01bb: l32r -> func addr */
  a2 = mesh_look_for_network(a2, a3, a4, a5, a6, a7);  /* 01be: callx a8 via reloc-expand */
  goto L_01ce;  /* 01c1: j */
  a10 = LD32(a2 + 0x4);  /* 01c6 */
  a8 = (u32)&mesh_ps_get_duties + 0x0;  /* 01c8: l32r -> global */
  a2 = mesh_ps_get_duties(a2, a3, a4, a5, a6, a7);  /* 01cb: callx a8 via reloc-expand */
  L_01ce: a3 = a10;  /* 01ce */
  L_01d0: a2 = (u32)&LOCAL__bss_s_mesh_io_error + 0x0;  /* 01d0: l32r -> .bss.s_mesh_io_error (same-object static) */
  ST32(a2 + 0x0, a3);  /* 01d3 */
  L_01d5: a2 = a3;  /* 01d5 */
  __asm__ volatile("" ::: "memory");  /* 01d7: memw */
  return a2;  /* 01da: retw.n */
}


/* mesh_set_io_process @ mesh_io.o 0000003c size 163B bind GLOBAL
 * Calls: mesh_mutex_lock, memset, memcpy, esp_mesh_push_to_nwk_queue, esp_mesh_io_sem_wait, mesh_mutex_unlock | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_set_io_process.str1.1, mesh_myself_mbox, .rodata.__func__$1, .bss.s_mesh_io_error
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=12); reloc-direct=6, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_set_io_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 003c: entry a1, 240 (frame 240 bytes) */
  if (a2 != 0) goto L_0080;  /* 003f: bnez.n a2, 80 <mesh_set_io_process+0x44> */
  L_0041: a2 = (u32)&g_log_level + 0x0;  /* 0041: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0044 */
  a2 = 0x00004008u;  /* 0046: l32r = 16392 */
  if (a3 >= 3u) goto L_004f;  /* 0049: bgeui a3, 3, 4f <mesh_set_io_process+0x13> */
  L_004c: goto L_00dd;  /* 004c: j */
  L_004f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 004f: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0052 */
  if (a8 == 0) goto L_00dd;  /* 0054: beqz a8, dd <mesh_set_io_process+0xa1> */
  L_0057: a3 = LD32(a8 + 0x150);  /* 0057 */
  if (a3 == 0) goto L_00dd;  /* 005a: beqz a3, dd <mesh_set_io_process+0xa1> */
  L_005d: a4 = 67;  /* 005d */
  a10 = LD32(a8 + 0x158);  /* 005f */
  /* 0062: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0065 */
  a10 = 3;  /* 0067 */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0069: -> "mesh_io.c" */
  a14 = a11;  /* 006c */
  a15 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 006e: -> "mesh_io.c" */
  a12 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0071: -> "mesh_io.c" */
  ST32(a1 + 0x0, a4);  /* 0074 */
  __asm__ volatile("" ::: "memory");  /* 0076: memw */
  /* 0079: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_00dd;  /* 007c: j */
  L_0080: a3 = (u32)&mesh_myself_mbox + 0x0;  /* 0080: l32r -> global */
  a12 = 70;  /* 0083 */
  a4 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 0086: -> "mesh_set_io_process" */
  a11 = a4;  /* 0089: mov */
  a10 = LD32(a3 + 0x4);  /* 008c */
  a8 = (u32)&mesh_mutex_lock + 0x0;  /* 008e: l32r -> global */
  a2 = mesh_mutex_lock(a2, a3, a4, a5, a6, a7);  /* 0091: callx a8 via reloc-expand */
  a12 = 160;  /* 0094 */
  a11 = 0;  /* 0097 */
  a10 = a1 + (40);  /* 0099 */
  a8 = (u32)&memset + 0x0;  /* 009c: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 009f: callx a8 (libc, via reloc-expand) */
  a12 = 20;  /* 00a2 */
  a8 = 39;  /* 00a4 */
  a11 = a2;  /* 00a6 */
  a10 = a1 + a12;  /* 00a8 */
  ST32(a1 + 0x10, a8);  /* 00aa */
  __asm__ volatile("" ::: "memory");  /* 00ad: memw */
  a8 = (u32)&memcpy + 0x0;  /* 00b0: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 00b3: callx a8 (libc, via reloc-expand) */
  a11 = 0;  /* 00b6 */
  a10 = a1 + (16);  /* 00b9 */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 00bc: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 00bf: callx a8 via reloc-expand */
  a2 = a10;  /* 00c2 */
  if (a10 != 0) goto L_00d1;  /* 00c4: bnez.n a10, d1 <mesh_set_io_process+0x95> */
  L_00c6: a8 = (u32)&esp_mesh_io_sem_wait;  /* 00c6: l32r -> func addr */
  a2 = esp_mesh_io_sem_wait(a2, a3, a4, a5, a6, a7);  /* 00c9: callx a8 via reloc-expand */
  a2 = (u32)&LOCAL__bss_s_mesh_io_error + 0x0;  /* 00cc: l32r -> .bss.s_mesh_io_error (same-object static) */
  a2 = LD32(a2 + 0x0);  /* 00cf */
  L_00d1: a12 = 79;  /* 00d1 */
  a11 = a4;  /* 00d3 */
  a10 = LD32(a3 + 0x4);  /* 00d5 */
  a8 = (u32)&mesh_mutex_unlock + 0x0;  /* 00d7: l32r -> global */
  a2 = mesh_mutex_unlock(a2, a3, a4, a5, a6, a7);  /* 00da: callx a8 via reloc-expand */
  L_00dd: return a2;  /* 00dd: retw.n */
}


/* mesh_set_router @ mesh_io.o 00000054 size 424B bind GLOBAL
 * Calls: memcmp, strnlen, memcpy, memset, esp_mesh_set_router_bssid | indirect[5]: mem[a2+0x158]; mem[a3+0x158]; unknown; mem[a2+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_set_io_process.str1.1, g_mesh_ext_cfg, .bss.MESH_ZERO_ADDR, .rodata.mesh_set_router.str1.1
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=11); reloc-direct=5, funcdb-attributed=0, unknown-indirect=5 */
u32 mesh_set_router(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0054: entry a1, 64 (frame 64 bytes) */
  if (a2 != 0) goto L_0091;  /* 0057: bnez.n a2, 91 <mesh_set_router+0x3d> */
  L_0059: a2 = (u32)&g_log_level + 0x0;  /* 0059: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 005c */
  if (a2 >= 3u) goto L_0065;  /* 005e: bgeui a2, 3, 65 <mesh_set_router+0x11> */
  L_0061: goto L_0174;  /* 0061: j */
  L_0065: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0065: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0068 */
  if (a2 == 0) goto L_0174;  /* 006a: beqz a2, 174 <mesh_set_router+0x120> */
  L_006d: a3 = LD32(a2 + 0x150);  /* 006d */
  if (a3 == 0) goto L_0174;  /* 0070: beqz a3, 174 <mesh_set_router+0x120> */
  L_0073: a10 = LD32(a2 + 0x158);  /* 0073 */
  a2 = 0x10d;  /* 0076 */
  /* 0079: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 007c */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 007e: -> "mesh_io.c" */
  a14 = a11;  /* 0081 */
  a15 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0083: -> "mesh_io.c" */
  a12 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0086: -> "mesh_io.c" */
  ST32(a1 + 0x0, a2);  /* 0089 */
  __asm__ volatile("" ::: "memory");  /* 008b: memw */
  goto L_016b;  /* 008e: j */
  L_0091: a3 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0091: l32r -> global */
  a8 = 2;  /* 0094 */
  a4 = LD8U(a3 + 0xc4);  /* 0096 */
  a4 = a4 | a8;  /* 0099 */
  ST8(a3 + 0xc4, a4);  /* 009c */
  __asm__ volatile("" ::: "memory");  /* 009f: memw */
  a4 = 31;  /* 00a2 */
  a8 = LD8U(a2 + 0x20);  /* 00a4 */
  a8 = a8 + (-1);  /* 00a7 */
  a8 = (a8 >> 8) & 0x1;  /* 00a9: extui width 1 */
  if (a4 >= a8) goto L_011c;  /* 00ac: bgeu a4, a8, 11c <mesh_set_router+0xc8> */
  L_00af: a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 00af: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 00b2 */
  a10 = a2 + (33);  /* 00b4 */
  __asm__ volatile("" ::: "memory");  /* 00b7: memw */
  a8 = (u32)&memcmp + 0x0;  /* 00ba: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00bd: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_011c;  /* 00c0: bnez a10, 11c <mesh_set_router+0xc8> */
  L_00c3: a3 = (u32)&g_log_level + 0x0;  /* 00c3: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00c6 */
  if (a3 >= 3u) goto L_00ce;  /* 00c8: bgeui a3, 3, ce <mesh_set_router+0x7a> */
  L_00cb: goto L_0174;  /* 00cb: j */
  L_00ce: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00ce: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 00d1 */
  if (a3 == 0) goto L_0174;  /* 00d3: beqz a3, 174 <mesh_set_router+0x120> */
  L_00d6: a4 = LD32(a3 + 0x150);  /* 00d6 */
  if (a4 == 0) goto L_0174;  /* 00d9: beqz a4, 174 <mesh_set_router+0x120> */
  L_00dc: a10 = LD32(a3 + 0x158);  /* 00dc */
  /* 00df: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00e2 */
  a10 = 3;  /* 00e4 */
  a3 = LD8U(a2 + 0x26);  /* 00e6 */
  ST32(a1 + 0x18, a3);  /* 00e9 */
  a3 = LD8U(a2 + 0x25);  /* 00eb */
  ST32(a1 + 0x14, a3);  /* 00ee */
  a3 = LD8U(a2 + 0x24);  /* 00f0 */
  ST32(a1 + 0x10, a3);  /* 00f3 */
  a3 = LD8U(a2 + 0x23);  /* 00f5 */
  ST32(a1 + 0xc, a3);  /* 00f8 */
  a3 = LD8U(a2 + 0x22);  /* 00fa */
  ST32(a1 + 0x8, a3);  /* 00fd */
  a3 = LD8U(a2 + 0x21);  /* 00ff */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0102: -> "mesh_io.c" */
  a14 = a11;  /* 0105 */
  ST32(a1 + 0x4, a3);  /* 0107 */
  ST32(a1 + 0x0, a2);  /* 0109 */
  a15 = LD8U(a2 + 0x20);  /* 010c */
  a12 = (u32)(RODATA__rodata_mesh_set_router_str1_1 + 0x0);  /* 010f: l32r -> .rodata.mesh_set_router.str1.1 */
  __asm__ volatile("" ::: "memory");  /* 0112: memw */
  /* 0115: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  goto L_0174;  /* 0118: j */
  L_011c: a4 = a2 + (39);  /* 011c */
  a11 = 64;  /* 011f */
  a10 = a4;  /* 0121 */
  a8 = (u32)&strnlen + 0x0;  /* 0123: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0126: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_017d;  /* 0129: beqz a10, 17d <mesh_set_router+0x129> */
  L_012c: a10 = a10 + (-8);  /* 012c */
  a8 = 56;  /* 012f */
  if (a8 >= a10) goto L_017d;  /* 0131: bgeu a8, a10, 17d <mesh_set_router+0x129> */
  L_0134: a2 = (u32)&g_log_level + 0x0;  /* 0134: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0137 */
  if (a2 < 3u) goto L_0174;  /* 0139: bltui a2, 3, 174 <mesh_set_router+0x120> */
  L_013c: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 013c: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 013f */
  if (a2 == 0) goto L_0174;  /* 0141: beqz.n a2, 174 <mesh_set_router+0x120> */
  L_0143: a3 = LD32(a2 + 0x150);  /* 0143 */
  if (a3 == 0) goto L_0174;  /* 0146: beqz.n a3, 174 <mesh_set_router+0x120> */
  L_0148: a10 = LD32(a2 + 0x158);  /* 0148 */
  /* 014b: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 014e */
  a11 = 64;  /* 0150 */
  a10 = a4;  /* 0153: mov */
  a8 = (u32)&strnlen + 0x0;  /* 0156: l32r -> global */
  a2 = strnlen(a2, a3, a4, a5, a6, a7);  /* 0159: callx a8 (libc, via reloc-expand) */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 015c: -> "mesh_io.c" */
  a15 = a10;  /* 015f */
  a14 = a11;  /* 0161 */
  a13 = a2;  /* 0163 */
  a12 = (u32)(RODATA__rodata_mesh_set_router_str1_1 + 0x0);  /* 0165: l32r -> .rodata.mesh_set_router.str1.1 */
  ST32(a1 + 0x0, a4);  /* 0168 */
  L_016b: a10 = 3;  /* 016b */
  __asm__ volatile("" ::: "memory");  /* 016e: memw */
  /* 0171: INDIRECT callx a3 <- mem[a2+0x150]; result unknown */ a2 = 0;
  L_0174: a2 = 0x00004008u;  /* 0174: l32r = 16392 */
  goto L_01f7;  /* 0177: j */
  L_017d: a4 = (u32)&g_mesh_ext_cfg + 0xc;  /* 017d: l32r -> global */
  a12 = 104;  /* 0180 */
  a11 = a4;  /* 0183 */
  a10 = a2;  /* 0185 */
  a8 = (u32)&memcmp + 0x0;  /* 0187: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 018a: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_01b5;  /* 018d: beqz.n a10, 1b5 <mesh_set_router+0x161> */
  L_018f: a12 = 104;  /* 018f */
  a11 = a2;  /* 0192 */
  a10 = a4;  /* 0194 */
  a8 = (u32)&memcpy + 0x0;  /* 0196: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0199: callx a8 (libc, via reloc-expand) */
  a12 = 32;  /* 019c */
  a11 = 0;  /* 019e */
  a10 = a4;  /* 01a0 */
  a8 = (u32)&memset + 0x0;  /* 01a2: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 01a5: callx a8 (libc, via reloc-expand) */
  a12 = LD8U(a2 + 0x20);  /* 01a8 */
  a11 = a2;  /* 01ab */
  a10 = a4;  /* 01ad */
  a8 = (u32)&memcpy + 0x0;  /* 01af: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 01b2: callx a8 (libc, via reloc-expand) */
  L_01b5: a2 = a2 + (33);  /* 01b5 */
  a11 = (u32)&LOCAL__bss_MESH_ZERO_ADDR + 0x0;  /* 01b8: l32r -> .bss.MESH_ZERO_ADDR (same-object static) */
  a12 = 6;  /* 01bb */
  a10 = a2;  /* 01bd: mov */
  a8 = (u32)&memcmp + 0x0;  /* 01c0: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 01c3: callx a8 (libc, via reloc-expand) */
  a4 = 0;  /* 01c6 */
  if (a10 == a4) goto L_01e4;  /* 01c8: beq a10, a4, 1e4 <mesh_set_router+0x190> */
  L_01cb: a8 = 190;  /* 01cb */
  a8 = a3 + a8;  /* 01ce */
  a12 = 6;  /* 01d0 */
  a11 = a2;  /* 01d2 */
  a10 = a8;  /* 01d4 */
  a8 = (u32)&memcpy + 0x0;  /* 01d6: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 01d9: callx a8 (libc, via reloc-expand) */
  a8 = (u32)&esp_mesh_set_router_bssid + 0x0;  /* 01dc: l32r -> global */
  a2 = esp_mesh_set_router_bssid(a2, a3, a4, a5, a6, a7);  /* 01df: callx a8 via reloc-expand */
  a4 = 1;  /* 01e2 */
  L_01e4: a2 = LD8U(a3 + 0xc4);  /* 01e4 */
  a8 = -4;  /* 01e7 */
  a2 = a2 & a8;  /* 01e9 */
  a2 = a2 | a4;  /* 01ec */
  ST8(a3 + 0xc4, a2);  /* 01ef */
  __asm__ volatile("" ::: "memory");  /* 01f2: memw */
  a2 = 0;  /* 01f5 */
  L_01f7: __asm__ volatile("" ::: "memory");  /* 01f7: memw */
  return a2;  /* 01fa: retw.n */
}


/* mesh_set_self_organized @ mesh_io.o 0000004c size 245B bind GLOBAL
 * Calls: esp_wifi_disconnect, esp_mesh_clear_parent, esp_mesh_is_nwk_inited, memset, esp_mesh_push_to_nwk_queue, reconnect_type2str | indirect[2]: mem[a8+0x158]; unknown | Data refs: g_mesh_self_organized, g_mesh_stop_reconnection, .rodata.__func__$0, g_is_wifi_connected, g_log_level, g_osi_funcs_p, .rodata.mesh_set_self_organized.str1.1, .rodata.mesh_set_io_process.str1.1, g_is_wifi_disconnecting
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=6, refs=15); reloc-direct=6, funcdb-attributed=0, unknown-indirect=2 */
u32 mesh_set_self_organized(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 004c: entry a1, 240 (frame 240 bytes) */
  a5 = (u32)&g_mesh_self_organized + 0x0;  /* 004f: l32r -> global */
  a2 = (a2 >> 8) & 0x1;  /* 0052: extui width 1 */
  a3 = (a3 >> 8) & 0x1;  /* 0055: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 0058: memw */
  ST8(a5 + 0x0, a2);  /* 005b */
  __asm__ volatile("" ::: "memory");  /* 005e: memw */
  a8 = LD8U(a5 + 0x0);  /* 0061 */
  a8 = (a8 >> 8) & 0x1;  /* 0064: extui width 1 */
  a2 = (u32)&g_mesh_stop_reconnection + 0x0;  /* 0067: l32r -> global */
  ST32(a2 + 0x0, a4);  /* 006a */
  if (a8 == 0) goto L_00bd;  /* 006d: beqz a8, bd <mesh_set_self_organized+0x71> */
  L_0070: if (a3 == 0) goto L_00cd;  /* 0070: beqz a3, cd <mesh_set_self_organized+0x81> */
  L_0073: __asm__ volatile("" ::: "memory");  /* 0073: memw */
  a8 = (u32)&esp_wifi_disconnect + 0x0;  /* 0076: l32r -> global */
  a2 = esp_wifi_disconnect(a2, a3, a4, a5, a6, a7);  /* 0079: callx a8 via reloc-expand */
  a4 = a10;  /* 007c */
  a10 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 007e: -> "mesh_set_self_organized" */
  a11 = 0x13f;  /* 0081 */
  a8 = (u32)&esp_mesh_clear_parent + 0x0;  /* 0084: l32r -> global */
  a2 = esp_mesh_clear_parent(a2, a3, a4, a5, a6, a7);  /* 0087: callx a8 via reloc-expand */
  if (a4 == 0) goto L_012c;  /* 008a: beqz a4, 12c <mesh_set_self_organized+0xe0> */
  L_008d: a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 008d: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 0090: callx a8 via reloc-expand */
  if (a10 == 0) goto L_00cd;  /* 0093: beqz.n a10, cd <mesh_set_self_organized+0x81> */
  L_0095: a12 = 180;  /* 0095 */
  a11 = 0;  /* 0098 */
  a10 = a1 + (20);  /* 009b */
  a8 = (u32)&memset + 0x0;  /* 009e: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00a1: callx a8 (libc, via reloc-expand) */
  a4 = 6;  /* 00a4 */
  a11 = 0;  /* 00a6 */
  a10 = a1 + (16);  /* 00a9 */
  ST32(a1 + 0x10, a4);  /* 00ac */
  __asm__ volatile("" ::: "memory");  /* 00af: memw */
  a8 = (u32)&esp_mesh_push_to_nwk_queue + 0x0;  /* 00b2: l32r -> global */
  a2 = esp_mesh_push_to_nwk_queue(a2, a3, a4, a5, a6, a7);  /* 00b5: callx a8 via reloc-expand */
  goto L_00cd;  /* 00b8: j */
  L_00bd: if (a4 != 2) goto L_00cd;  /* 00bd: bnei a4, 2, cd <mesh_set_self_organized+0x81> */
  L_00c0: a4 = (u32)&g_is_wifi_connected + 0x0;  /* 00c0: l32r -> global */
  a4 = LD8U(a4 + 0x0);  /* 00c3 */
  if (a4 != 0) goto L_00cd;  /* 00c6: bnez.n a4, cd <mesh_set_self_organized+0x81> */
  L_00c8: a4 = 1;  /* 00c8 */
  ST32(a2 + 0x0, a4);  /* 00ca */
  L_00cd: a4 = (u32)&g_log_level + 0x0;  /* 00cd: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 00d0 */
  if (a4 < 3u) goto L_013d;  /* 00d2: bltui a4, 3, 13d <mesh_set_self_organized+0xf1> */
  L_00d5: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00d5: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 00d8 */
  if (a8 == 0) goto L_013d;  /* 00db: beqz a8, 13d <mesh_set_self_organized+0xf1> */
  L_00de: a4 = LD32(a8 + 0x150);  /* 00de */
  if (a4 == 0) goto L_013d;  /* 00e1: beqz a4, 13d <mesh_set_self_organized+0xf1> */
  L_00e4: a10 = LD32(a8 + 0x158);  /* 00e4 */
  __asm__ volatile("" ::: "memory");  /* 00e7: memw */
  /* 00ea: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a7 = a10;  /* 00ed */
  __asm__ volatile("" ::: "memory");  /* 00ef: memw */
  a5 = LD8U(a5 + 0x0);  /* 00f2 */
  a5 = (a5 >> 8) & 0x1;  /* 00f5: extui width 1 */
  a6 = (u32)(RODATA__rodata_mesh_set_self_organized_str1_1 + 0x0);  /* 00f8: -> "enable self-organizing" */
  if (a5 != 0) goto L_0100;  /* 00fb: bnez.n a5, 100 <mesh_set_self_organized+0xb4> */
  L_00fd: a6 = (u32)(RODATA__rodata_mesh_set_self_organized_str1_1 + 0x0);  /* 00fd: -> "enable self-organizing" */
  L_0100: a5 = (u32)(RODATA__rodata_mesh_set_self_organized_str1_1 + 0x0);  /* 0100: -> "enable self-organizing" */
  if (a3 != 0) goto L_0108;  /* 0103: bnez.n a3, 108 <mesh_set_self_organized+0xbc> */
  L_0105: a5 = (u32)(RODATA__rodata_mesh_set_self_organized_str1_1 + 0x0);  /* 0105: -> "enable self-organizing" */
  L_0108: a10 = LD32(a2 + 0x0);  /* 0108 */
  a8 = (u32)&reconnect_type2str + 0x0;  /* 010a: l32r -> global */
  a2 = reconnect_type2str(a2, a3, a4, a5, a6, a7);  /* 010d: callx a8 via reloc-expand */
  a15 = a6;  /* 0110 */
  a13 = a7;  /* 0112 */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0114: -> "mesh_io.c" */
  a14 = a11;  /* 0117 */
  a12 = (u32)(RODATA__rodata_mesh_set_self_organized_str1_1 + 0x0);  /* 0119: -> "enable self-organizing" */
  ST32(a1 + 0x4, a10);  /* 011c */
  a10 = 3;  /* 011e */
  ST32(a1 + 0x0, a5);  /* 0120 */
  __asm__ volatile("" ::: "memory");  /* 0122: memw */
  /* 0125: INDIRECT callx a4 <- unknown; result unknown */ a2 = 0;
  goto L_013d;  /* 0128: j */
  L_012c: a4 = (u32)&g_is_wifi_disconnecting + 0x0;  /* 012c: l32r -> global */
  a6 = 1;  /* 012f */
  ST8(a4 + 0x0, a6);  /* 0131 */
  __asm__ volatile("" ::: "memory");  /* 0134: memw */
  __asm__ volatile("" ::: "memory");  /* 0137: memw */
  goto L_00cd;  /* 013a: j */
  L_013d: a2 = 0;  /* 013d */
  return a2;  /* 013f: retw.n */
}


/* mesh_set_type @ mesh_io.o 00000074 size 616B bind GLOBAL
 * Calls: esp_wifi_get_mode, esp_wifi_set_mode, mesh_ie_type2str, mesh_set_self_organized, esp_mesh_nvs_set_layer, esp_mesh_nvs_set_assoc, esp_wifi_disconnect, esp_mesh_is_nwk_inited, mesh_nwk_manual_networking, mesh_connect_to_router, esp_mesh_recv_release | indirect[5]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_set_io_process.str1.1, .rodata.mesh_set_type.str1.1, g_mesh_is_root, g_is_root_fixed, g_is_standalone_sta, g_mesh_manual_nwk, g_mesh_ie, g_is_wifi_connected, g_is_wifi_disconnecting, g_mesh_ext_cfg
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=11, refs=23); reloc-direct=11, funcdb-attributed=0, unknown-indirect=5 */
u32 mesh_set_type(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0074: entry a1, 64 (frame 64 bytes) */
  a3 = a2;  /* 0077 */
  a2 = 0;  /* 0079 */
  ST32(a1 + 0x10, a2);  /* 007b */
  ST32(a1 + 0x14, a2);  /* 007d */
  if (a3 < 2u) goto L_0091;  /* 007f: bltui a3, 2, 91 <mesh_set_type+0x1d> */
  L_0082: a2 = a3 + (-3);  /* 0082 */
  if (a2 >= 2u) goto L_008b;  /* 0085: bgeui a2, 2, 8b <mesh_set_type+0x17> */
  L_0088: goto L_0142;  /* 0088: j */
  L_008b: __asm__ volatile("" ::: "memory");  /* 008b: memw */
  goto L_029a;  /* 008e: j */
  L_0091: a10 = a1 + (24);  /* 0091 */
  a8 = (u32)&esp_wifi_get_mode + 0x0;  /* 0094: l32r -> global */
  a2 = esp_wifi_get_mode(a2, a3, a4, a5, a6, a7);  /* 0097: callx a8 via reloc-expand */
  if (a10 != 0) goto L_00a1;  /* 009a: bnez.n a10, a1 <mesh_set_type+0x2d> */
  L_009c: a2 = LD32(a1 + 0x18);  /* 009c */
  if (a2 == 3) goto L_00ec;  /* 009e: beqi a2, 3, ec <mesh_set_type+0x78> */
  L_00a1: a10 = 3;  /* 00a1 */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 00a3: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 00a6: callx a8 via reloc-expand */
  a2 = a10;  /* 00a9 */
  if (a10 == 0) goto L_00ec;  /* 00ab: beqz.n a10, ec <mesh_set_type+0x78> */
  L_00ad: a4 = (u32)&g_log_level + 0x0;  /* 00ad: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 00b0 */
  if (a4 >= 3u) goto L_00b9;  /* 00b3: bgeui a4, 3, b9 <mesh_set_type+0x45> */
  L_00b6: goto L_029d;  /* 00b6: j */
  L_00b9: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00b9: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 00bc */
  if (a8 == 0) goto L_029d;  /* 00bf: beqz a8, 29d <mesh_set_type+0x229> */
  L_00c2: a4 = LD32(a8 + 0x150);  /* 00c2 */
  if (a4 == 0) goto L_029d;  /* 00c5: beqz a4, 29d <mesh_set_type+0x229> */
  L_00c8: a10 = LD32(a8 + 0x158);  /* 00c8 */
  /* 00cb: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 00ce */
  a10 = a3;  /* 00d0 */
  a8 = (u32)&mesh_ie_type2str + 0x0;  /* 00d2: l32r -> global */
  a2 = mesh_ie_type2str(a2, a3, a4, a5, a6, a7);  /* 00d5: callx a8 via reloc-expand */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 00d8: -> "mesh_io.c" */
  a15 = a10;  /* 00db */
  a14 = a11;  /* 00dd */
  a13 = a5;  /* 00df */
  a12 = (u32)(RODATA__rodata_mesh_set_type_str1_1 + 0x0);  /* 00e1: l32r -> .rodata.mesh_set_type.str1.1 */
  ST32(a1 + 0x0, a2);  /* 00e4 */
  __asm__ volatile("" ::: "memory");  /* 00e6: memw */
  goto L_0187;  /* 00e9: j */
  L_00ec: a10 = (u32)&g_mesh_is_root + 0x0;  /* 00ec: l32r -> global */
  a9 = (u32)&g_is_root_fixed + 0x0;  /* 00ef: l32r -> global */
  a4 = (u32)&g_is_standalone_sta + 0x0;  /* 00f2: l32r -> global */
  a2 = (u32)&g_mesh_manual_nwk + 0x0;  /* 00f5: l32r -> global */
  if (a3 != 1) goto L_011c;  /* 00f8: bnei a3, 1, 11c <mesh_set_type+0xa8> */
  L_00fb: a5 = 0;  /* 00fb */
  a12 = 0;  /* 00fd */
  a11 = a12;  /* 00ff */
  __asm__ volatile("" ::: "memory");  /* 0101: memw */
  ST8(a10 + 0x0, a3);  /* 0104 */
  ST8(a9 + 0x0, a3);  /* 0107 */
  ST8(a4 + 0x0, a5);  /* 010a */
  ST32(a2 + 0x0, a3);  /* 010d */
  ST16(a2 + 0x4, a3);  /* 010f */
  __asm__ volatile("" ::: "memory");  /* 0112: memw */
  __asm__ volatile("" ::: "memory");  /* 0115: memw */
  goto L_01bc;  /* 0118: j */
  L_011c: a8 = 0;  /* 011c */
  ST8(a4 + 0x0, a8);  /* 011e */
  __asm__ volatile("" ::: "memory");  /* 0121: memw */
  a12 = 0;  /* 0124 */
  a4 = (u32)&g_mesh_ie + 0x0;  /* 0126: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0129: memw */
  ST8(a10 + 0x0, a8);  /* 012c */
  ST8(a9 + 0x0, a8);  /* 012f */
  ST8(a4 + 0x7, a8);  /* 0132 */
  __asm__ volatile("" ::: "memory");  /* 0135: memw */
  ST32(a2 + 0x0, a12);  /* 0138 */
  ST32(a2 + 0x4, a12);  /* 013a */
  __asm__ volatile("" ::: "memory");  /* 013c: memw */
  goto L_01ba;  /* 013f: j */
  L_0142: a10 = 1;  /* 0142 */
  a8 = (u32)&esp_wifi_set_mode + 0x0;  /* 0144: l32r -> global */
  a2 = esp_wifi_set_mode(a2, a3, a4, a5, a6, a7);  /* 0147: callx a8 via reloc-expand */
  a2 = a10;  /* 014a */
  if (a10 == 0) goto L_0194;  /* 014c: beqz a10, 194 <mesh_set_type+0x120> */
  L_014f: a4 = (u32)&g_log_level + 0x0;  /* 014f: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0152 */
  if (a4 >= 3u) goto L_015a;  /* 0154: bgeui a4, 3, 15a <mesh_set_type+0xe6> */
  L_0157: goto L_029d;  /* 0157: j */
  L_015a: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 015a: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 015d */
  if (a8 == 0) goto L_029d;  /* 015f: beqz a8, 29d <mesh_set_type+0x229> */
  L_0162: a4 = LD32(a8 + 0x150);  /* 0162 */
  if (a4 == 0) goto L_029d;  /* 0165: beqz a4, 29d <mesh_set_type+0x229> */
  L_0168: a10 = LD32(a8 + 0x158);  /* 0168 */
  /* 016b: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 016e */
  a10 = a3;  /* 0170 */
  a8 = (u32)&mesh_ie_type2str + 0x0;  /* 0172: l32r -> global */
  a2 = mesh_ie_type2str(a2, a3, a4, a5, a6, a7);  /* 0175: callx a8 via reloc-expand */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 0178: -> "mesh_io.c" */
  a15 = a10;  /* 017b */
  a14 = a11;  /* 017d */
  a13 = a5;  /* 017f */
  a12 = (u32)(RODATA__rodata_mesh_set_type_str1_1 + 0x0);  /* 0181: l32r -> .rodata.mesh_set_type.str1.1 */
  ST32(a1 + 0x0, a2);  /* 0184 */
  L_0187: a10 = 3;  /* 0187 */
  __asm__ volatile("" ::: "memory");  /* 018a: memw */
  /* 018d: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_029d;  /* 0190: j */
  L_0194: a11 = (u32)&g_mesh_is_root + 0x0;  /* 0194: l32r -> global */
  a10 = (u32)&g_is_root_fixed + 0x0;  /* 0197: l32r -> global */
  a4 = (u32)&g_is_standalone_sta + 0x0;  /* 019a: l32r -> global */
  a8 = (u32)&g_mesh_manual_nwk + 0x0;  /* 019d: l32r -> global */
  if (a3 != 3) goto L_01c5;  /* 01a0: bnei a3, 3, 1c5 <mesh_set_type+0x151> */
  L_01a3: a5 = 1;  /* 01a3 */
  a12 = a2;  /* 01a5 */
  __asm__ volatile("" ::: "memory");  /* 01a7: memw */
  ST8(a11 + 0x0, a2);  /* 01aa */
  ST8(a10 + 0x0, a2);  /* 01ad */
  ST8(a4 + 0x0, a5);  /* 01b0 */
  __asm__ volatile("" ::: "memory");  /* 01b3: memw */
  ST32(a8 + 0x0, a2);  /* 01b6 */
  ST32(a8 + 0x4, a2);  /* 01b8 */
  L_01ba: a11 = 1;  /* 01ba */
  L_01bc: a10 = a11;  /* 01bc */
  __asm__ volatile("" ::: "memory");  /* 01be: memw */
  goto L_01e3;  /* 01c1: j */
  L_01c5: a9 = 1;  /* 01c5 */
  ST8(a4 + 0x0, a9);  /* 01c7 */
  a4 = 1;  /* 01ca */
  a12 = a2;  /* 01cc */
  __asm__ volatile("" ::: "memory");  /* 01ce: memw */
  ST8(a11 + 0x0, a9);  /* 01d1 */
  a11 = a2;  /* 01d4 */
  ST8(a10 + 0x0, a9);  /* 01d6 */
  a10 = a2;  /* 01d9 */
  ST32(a8 + 0x0, a4);  /* 01db */
  ST16(a8 + 0x4, a4);  /* 01dd */
  __asm__ volatile("" ::: "memory");  /* 01e0: memw */
  L_01e3: __asm__ volatile("" ::: "memory");  /* 01e3: memw */
  a8 = (u32)&mesh_set_self_organized;  /* 01e6: l32r -> func addr */
  a2 = mesh_set_self_organized(a2, a3, a4, a5, a6, a7);  /* 01e9: callx a8 via reloc-expand */
  a10 = 0;  /* 01ec */
  a8 = (u32)&esp_mesh_nvs_set_layer + 0x0;  /* 01ee: l32r -> global */
  a2 = esp_mesh_nvs_set_layer(a2, a3, a4, a5, a6, a7);  /* 01f1: callx a8 via reloc-expand */
  a10 = 0;  /* 01f4 */
  a8 = (u32)&esp_mesh_nvs_set_assoc + 0x0;  /* 01f6: l32r -> global */
  a2 = esp_mesh_nvs_set_assoc(a2, a3, a4, a5, a6, a7);  /* 01f9: callx a8 via reloc-expand */
  a2 = (u32)&g_is_wifi_connected + 0x0;  /* 01fc: l32r -> global */
  a2 = LD8U(a2 + 0x0);  /* 01ff */
  if (a2 == 0) goto L_0218;  /* 0202: beqz.n a2, 218 <mesh_set_type+0x1a4> */
  L_0204: a8 = (u32)&esp_wifi_disconnect + 0x0;  /* 0204: l32r -> global */
  a2 = esp_wifi_disconnect(a2, a3, a4, a5, a6, a7);  /* 0207: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0218;  /* 020a: bnez.n a10, 218 <mesh_set_type+0x1a4> */
  L_020c: a2 = (u32)&g_is_wifi_disconnecting + 0x0;  /* 020c: l32r -> global */
  a4 = 1;  /* 020f */
  ST8(a2 + 0x0, a4);  /* 0212 */
  __asm__ volatile("" ::: "memory");  /* 0215: memw */
  L_0218: __asm__ volatile("" ::: "memory");  /* 0218: memw */
  a8 = (u32)&esp_mesh_is_nwk_inited + 0x0;  /* 021b: l32r -> global */
  a2 = esp_mesh_is_nwk_inited(a2, a3, a4, a5, a6, a7);  /* 021e: callx a8 via reloc-expand */
  a2 = 0;  /* 0221 */
  if (a10 != a2) goto L_0229;  /* 0223: bne a10, a2, 229 <mesh_set_type+0x1b5> */
  L_0226: goto L_02da;  /* 0226: j */
  L_0229: if (a3 == 3) goto L_028d;  /* 0229: beqi a3, 3, 28d <mesh_set_type+0x219> */
  L_022c: if (a3 >= 4u) goto L_023e;  /* 022c: bgeui a3, 4, 23e <mesh_set_type+0x1ca> */
  L_022f: if (a3 == a2) goto L_028d;  /* 022f: beq a3, a2, 28d <mesh_set_type+0x219> */
  L_0232: a2 = 0x00004008u;  /* 0232: l32r = 16392 */
  if (a3 == 1) goto L_023b;  /* 0235: beqi a3, 1, 23b <mesh_set_type+0x1c7> */
  L_0238: goto L_02da;  /* 0238: j */
  L_023b: goto L_0247;  /* 023b: j */
  L_023e: a2 = 0x00004008u;  /* 023e: l32r = 16392 */
  if (a3 == 4) goto L_0247;  /* 0241: beqi a3, 4, 247 <mesh_set_type+0x1d3> */
  L_0244: goto L_02da;  /* 0244: j */
  L_0247: a2 = (u32)&g_mesh_is_root + 0x0;  /* 0247: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 024a: memw */
  a2 = LD8U(a2 + 0x0);  /* 024d */
  a2 = (a2 >> 8) & 0x1;  /* 0250: extui width 1 */
  if (a2 == 0) goto L_0280;  /* 0253: beqz.n a2, 280 <mesh_set_type+0x20c> */
  L_0255: a2 = (u32)&g_mesh_ext_cfg + 0x0;  /* 0255: l32r -> global */
  a2 = LD8U(a2 + 0xc4);  /* 0258 */
  if (((a2 >> 1) & 1) == 0) goto L_0280;  /* 025b: bbci a2, 1, 280 <mesh_set_type+0x20c> */
  L_025e: a10 = a1 + (16);  /* 025e */
  a2 = (u32)&g_mesh_manual_nwk + 0x0;  /* 0261: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0264 */
  a2 = LD16U(a2 + 0x4);  /* 0267 */
  ST32(a1 + 0x10, a3);  /* 026a */
  ST16(a1 + 0x14, a2);  /* 026d */
  __asm__ volatile("" ::: "memory");  /* 0270: memw */
  __asm__ volatile("" ::: "memory");  /* 0273: memw */
  a8 = (u32)&mesh_nwk_manual_networking + 0x0;  /* 0276: l32r -> global */
  a2 = mesh_nwk_manual_networking(a2, a3, a4, a5, a6, a7);  /* 0279: callx a8 via reloc-expand */
  goto L_0288;  /* 027c: j */
  L_0280: a10 = 39;  /* 0280 */
  a8 = (u32)&mesh_connect_to_router + 0x0;  /* 0282: l32r -> global */
  a2 = mesh_connect_to_router(a2, a3, a4, a5, a6, a7);  /* 0285: callx a8 via reloc-expand */
  L_0288: a2 = a10;  /* 0288 */
  goto L_02da;  /* 028a: j */
  L_028d: a10 = 1;  /* 028d */
  a8 = (u32)&esp_mesh_recv_release + 0x0;  /* 028f: l32r -> global */
  a2 = esp_mesh_recv_release(a2, a3, a4, a5, a6, a7);  /* 0292: callx a8 via reloc-expand */
  a2 = 0;  /* 0295 */
  goto L_02da;  /* 0297: j */
  L_029a: a2 = 0x00004008u;  /* 029a: l32r = 16392 */
  L_029d: a4 = (u32)&g_log_level + 0x0;  /* 029d: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 02a0 */
  if (a4 < 3u) goto L_02da;  /* 02a2: bltui a4, 3, 2da <mesh_set_type+0x266> */
  L_02a5: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 02a5: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 02a8 */
  if (a8 == 0) goto L_02da;  /* 02ab: beqz.n a8, 2da <mesh_set_type+0x266> */
  L_02ad: a4 = LD32(a8 + 0x150);  /* 02ad */
  if (a4 == 0) goto L_02da;  /* 02b0: beqz a4, 2da <mesh_set_type+0x266> */
  L_02b3: a10 = LD32(a8 + 0x158);  /* 02b3 */
  /* 02b6: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 02b9 */
  a10 = (a3 >> 8) & 0x1;  /* 02bb: extui width 1 */
  a8 = (u32)&mesh_ie_type2str + 0x0;  /* 02be: l32r -> global */
  a2 = mesh_ie_type2str(a2, a3, a4, a5, a6, a7);  /* 02c1: callx a8 via reloc-expand */
  a11 = (u32)(RODATA__rodata_mesh_set_io_process_str1_1 + 0x0);  /* 02c4: -> "mesh_io.c" */
  a15 = a10;  /* 02c7 */
  a14 = a11;  /* 02c9 */
  a13 = a5;  /* 02cb */
  a10 = 3;  /* 02cd */
  a12 = (u32)(RODATA__rodata_mesh_set_type_str1_1 + 0x0);  /* 02cf: l32r -> .rodata.mesh_set_type.str1.1 */
  ST32(a1 + 0x0, a2);  /* 02d2 */
  __asm__ volatile("" ::: "memory");  /* 02d4: memw */
  /* 02d7: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_02da: return a2;  /* 02da: retw.n */
}


/* mesh_switch_channel @ mesh_io.o 00000018 size 94B bind GLOBAL
 * Calls: esp_mesh_switch_channel_internal, esp_mesh_get_router_bssid, memcmp, memcpy | Data refs: g_mesh_is_root, .bss.csa_bssid
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=4, refs=6); reloc-direct=4, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_switch_channel(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  a11 = LD8U(a2 + 0x5);  /* 001b */
  a3 = a2;  /* 001e: mov */
  a10 = LD8U(a2 + 0x4);  /* 0021 */
  a8 = (u32)&esp_mesh_switch_channel_internal + 0x0;  /* 0024: l32r -> global */
  a2 = esp_mesh_switch_channel_internal(a2, a3, a4, a5, a6, a7);  /* 0027: callx a8 via reloc-expand */
  a2 = a10;  /* 002a */
  if (a10 != 0) goto L_0074;  /* 002c: bnez a10, 74 <mesh_switch_channel+0x5c> */
  L_002f: a8 = (u32)&g_mesh_is_root + 0x0;  /* 002f: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0032: memw */
  a8 = LD8U(a8 + 0x0);  /* 0035 */
  a8 = (a8 >> 8) & 0x1;  /* 0038: extui width 1 */
  ST32(a1 + 0x0, a10);  /* 003b */
  ST16(a1 + 0x4, a10);  /* 003d */
  __asm__ volatile("" ::: "memory");  /* 0040: memw */
  if (a8 == 0) goto L_0074;  /* 0043: beqz.n a8, 74 <mesh_switch_channel+0x5c> */
  L_0045: a8 = LD32(a3 + 0x0);  /* 0045 */
  if (a8 == 0) goto L_0074;  /* 0048: beqz.n a8, 74 <mesh_switch_channel+0x5c> */
  L_004a: a10 = a1;  /* 004a: mov */
  __asm__ volatile("" ::: "memory");  /* 004d: memw */
  a8 = (u32)&esp_mesh_get_router_bssid + 0x0;  /* 0050: l32r -> global */
  a2 = esp_mesh_get_router_bssid(a2, a3, a4, a5, a6, a7);  /* 0053: callx a8 via reloc-expand */
  a3 = LD32(a3 + 0x0);  /* 0056 */
  a12 = 6;  /* 0058 */
  a11 = a3;  /* 005a */
  a10 = a1;  /* 005c: mov */
  a8 = (u32)&memcmp + 0x0;  /* 005f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0062: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_0074;  /* 0065: beqz.n a10, 74 <mesh_switch_channel+0x5c> */
  L_0067: a10 = (u32)&LOCAL__bss_csa_bssid + 0x0;  /* 0067: l32r -> .bss.csa_bssid (same-object static) */
  a12 = 6;  /* 006a */
  a11 = a3;  /* 006c */
  a8 = (u32)&memcpy + 0x0;  /* 006e: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0071: callx a8 (libc, via reloc-expand) */
  L_0074: return a2;  /* 0074: retw.n */
}

