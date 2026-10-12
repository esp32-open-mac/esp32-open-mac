/* libmesh.a mesh_common.o --- reconstructed C (offline).
 * Role: AP scan-list management: enqueue/find/clear/expire/invalidate.
 * Object file: 10900 bytes on disk; 8/8 functions reconstructed, ~1330 code bytes.
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
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 mesh_free(); /* defined in another libmesh.a object */
extern u32 mesh_malloc(); /* defined in another libmesh.a object */
static const u8 RODATA__rodata___func___0[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x61, 0x70, 0x5f, 0x65, 0x6e, 0x71, 0x75, 0x65, 0x75, 0x65, 0x00 }; /* .rodata.__func__$0 (20 bytes) strings: [0x0]="esp_mesh_ap_enqueue" */
static const u8 RODATA__rodata___func___1[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x61, 0x70, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x5f, 0x63, 0x6c, 0x65 }; /* .rodata.__func__$1 (20 bytes) */
static const u8 RODATA__rodata_esp_mesh_ap_list_clear_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67 }; /* .rodata.esp_mesh_ap_list_clear.str1.1 (44 bytes) strings: [0x0]="mesh_common.c"; [0xe]="mesh" */

/* esp_mesh_ap_enqueue @ mesh_common.o 00000044 size 353B bind GLOBAL
 * Calls: esp_mesh_ap_list_find, mesh_malloc, memset, mesh_free, memcpy | indirect[3]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_ap_list_clear.str1.1, .rodata.__func__$0
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=5, refs=9); reloc-direct=5, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_ap_enqueue(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0044: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0076;  /* 0047: bnez.n a2, 76 <esp_mesh_ap_enqueue+0x32> */
  L_0049: a2 = (u32)&g_log_level + 0x0;  /* 0049: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 004c */
  a2 = 0x00004008u;  /* 004f: l32r = 16392 */
  if (a3 >= 3u) goto L_0058;  /* 0052: bgeui a3, 3, 58 <esp_mesh_ap_enqueue+0x14> */
  L_0055: goto L_01a0;  /* 0055: j */
  L_0058: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0058: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 005b */
  if (a3 == 0) goto L_01a0;  /* 005e: beqz a3, 1a0 <esp_mesh_ap_enqueue+0x15c> */
  L_0061: a4 = LD32(a3 + 0x150);  /* 0061 */
  if (a4 == 0) goto L_01a0;  /* 0064: beqz a4, 1a0 <esp_mesh_ap_enqueue+0x15c> */
  L_0067: a10 = LD32(a3 + 0x158);  /* 0067 */
  a3 = 250;  /* 006a */
  /* 006d: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 0070: -> "mesh_common.c" */
  goto L_00a0;  /* 0073: j */
  L_0076: if (a3 != 0) goto L_00b8;  /* 0076: bnez.n a3, b8 <esp_mesh_ap_enqueue+0x74> */
  L_0078: a2 = (u32)&g_log_level + 0x0;  /* 0078: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 007b */
  a2 = 0x00004008u;  /* 007d: l32r = 16392 */
  if (a3 >= 3u) goto L_0086;  /* 0080: bgeui a3, 3, 86 <esp_mesh_ap_enqueue+0x42> */
  L_0083: goto L_01a0;  /* 0083: j */
  L_0086: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0086: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0089 */
  if (a3 == 0) goto L_01a0;  /* 008b: beqz a3, 1a0 <esp_mesh_ap_enqueue+0x15c> */
  L_008e: a4 = LD32(a3 + 0x150);  /* 008e */
  if (a4 == 0) goto L_01a0;  /* 0091: beqz a4, 1a0 <esp_mesh_ap_enqueue+0x15c> */
  L_0094: a10 = LD32(a3 + 0x158);  /* 0094 */
  a3 = 251;  /* 0097 */
  /* 009a: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 009d: -> "mesh_common.c" */
  L_00a0: a13 = a10;  /* 00a0 */
  a14 = a11;  /* 00a2 */
  a10 = 3;  /* 00a4 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 00a6: -> "mesh_common.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 00a9: -> "mesh_common.c" */
  ST32(a1 + 0x0, a3);  /* 00ac */
  __asm__ volatile("" ::: "memory");  /* 00ae: memw */
  /* 00b1: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_01a0;  /* 00b4: j */
  L_00b8: a12 = 0;  /* 00b8 */
  a11 = a3;  /* 00ba */
  a10 = a2;  /* 00bc */
  a8 = (u32)&esp_mesh_ap_list_find;  /* 00be: l32r -> func addr */
  a2 = esp_mesh_ap_list_find(a2, a3, a4, a5, a6, a7);  /* 00c1: callx a8 via reloc-expand */
  a4 = a10;  /* 00c4 */
  if (a10 == 0) goto L_00cb;  /* 00c6: beqz.n a10, cb <esp_mesh_ap_enqueue+0x87> */
  L_00c8: goto L_019e;  /* 00c8: j */
  L_00cb: a7 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 00cb: -> "esp_mesh_ap_enqueue" */
  a12 = 0x108;  /* 00ce */
  a11 = a7;  /* 00d1 */
  a10 = 116;  /* 00d3 */
  a8 = (u32)&mesh_malloc + 0x0;  /* 00d6: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 00d9: callx a8 via reloc-expand */
  a6 = a10;  /* 00dc */
  if (a10 == 0) goto L_019e;  /* 00de: beqz a10, 19e <esp_mesh_ap_enqueue+0x15a> */
  L_00e1: a11 = a4;  /* 00e1 */
  a12 = 116;  /* 00e3 */
  a8 = (u32)&memset + 0x0;  /* 00e6: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 00e9: callx a8 (libc, via reloc-expand) */
  a4 = LD32(a3 + 0x5c);  /* 00ec */
  if (a4 == 0) goto L_0105;  /* 00ef: beqz.n a4, 105 <esp_mesh_ap_enqueue+0xc1> */
  L_00f1: a12 = 0x10d;  /* 00f1 */
  a11 = a7;  /* 00f4 */
  a10 = 58;  /* 00f6 */
  a8 = (u32)&mesh_malloc + 0x0;  /* 00f8: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 00fb: callx a8 via reloc-expand */
  a4 = a10;  /* 00fe */
  a12 = 0x10f;  /* 0100 */
  if (a10 == 0) goto L_012c;  /* 0103: beqz.n a10, 12c <esp_mesh_ap_enqueue+0xe8> */
  L_0105: a5 = LD32(a3 + 0x60);  /* 0105 */
  if (a5 == 0) goto L_0139;  /* 0108: beqz.n a5, 139 <esp_mesh_ap_enqueue+0xf5> */
  L_010a: a12 = 0x115;  /* 010a */
  a11 = a7;  /* 010d */
  a10 = 13;  /* 010f */
  a8 = (u32)&mesh_malloc + 0x0;  /* 0112: l32r -> global */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0115: callx a8 via reloc-expand */
  a5 = a10;  /* 0118 */
  if (a10 != 0) goto L_0139;  /* 011a: bnez.n a10, 139 <esp_mesh_ap_enqueue+0xf5> */
  L_011c: a12 = 0x117;  /* 011c */
  a11 = a7;  /* 011f */
  a10 = a4;  /* 0121 */
  a8 = (u32)&mesh_free + 0x0;  /* 0123: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0126: callx a8 via reloc-expand */
  a12 = 0x118;  /* 0129 */
  L_012c: a11 = a7;  /* 012c */
  a10 = a6;  /* 012e */
  a8 = (u32)&mesh_free + 0x0;  /* 0130: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0133: callx a8 via reloc-expand */
  goto L_019e;  /* 0136: j */
  L_0139: a12 = 108;  /* 0139 */
  a11 = a3;  /* 013c: mov */
  a10 = a6;  /* 013f: mov */
  a8 = (u32)&memcpy + 0x0;  /* 0142: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0145: callx a8 (libc, via reloc-expand) */
  a7 = LD32(a3 + 0x68);  /* 0148 */
  ST32(a6 + 0x68, a7);  /* 014b */
  if (a4 == 0) goto L_0176;  /* 014e: beqz.n a4, 176 <esp_mesh_ap_enqueue+0x132> */
  L_0150: a12 = 58;  /* 0150 */
  a10 = a4;  /* 0152 */
  a11 = LD32(a3 + 0x5c);  /* 0154 */
  __asm__ volatile("" ::: "memory");  /* 0157: memw */
  a8 = (u32)&memcpy + 0x0;  /* 015a: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 015d: callx a8 (libc, via reloc-expand) */
  ST32(a6 + 0x5c, a4);  /* 0160 */
  a7 = LD8U(a4 + 0x1e);  /* 0163 */
  if (((a7 >> 3) & 1) == 0) goto L_0176;  /* 0166: bbci a7, 3, 176 <esp_mesh_ap_enqueue+0x132> */
  L_0169: a4 = LD8U(a4 + 0x7);  /* 0169 */
  if (a4 == 0) goto L_0176;  /* 016c: beqz.n a4, 176 <esp_mesh_ap_enqueue+0x132> */
  L_016e: a4 = 1;  /* 016e */
  ST8(a6 + 0x6c, a4);  /* 0170 */
  __asm__ volatile("" ::: "memory");  /* 0173: memw */
  L_0176: if (a5 == 0) goto L_018c;  /* 0176: beqz.n a5, 18c <esp_mesh_ap_enqueue+0x148> */
  L_0178: a12 = 13;  /* 0178 */
  a10 = a5;  /* 017a: mov */
  a11 = LD32(a3 + 0x60);  /* 017d */
  __asm__ volatile("" ::: "memory");  /* 0180: memw */
  a8 = (u32)&memcpy + 0x0;  /* 0183: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0186: callx a8 (libc, via reloc-expand) */
  ST32(a6 + 0x60, a5);  /* 0189 */
  L_018c: a3 = LD32(a2 + 0x0);  /* 018c */
  ST32(a6 + 0x70, a3);  /* 018e */
  a3 = LD8U(a2 + 0x4);  /* 0191 */
  a3 = a3 + (1);  /* 0194 */
  ST32(a2 + 0x0, a6);  /* 0196 */
  ST8(a2 + 0x4, a3);  /* 0198 */
  __asm__ volatile("" ::: "memory");  /* 019b: memw */
  L_019e: a2 = 0;  /* 019e */
  L_01a0: __asm__ volatile("" ::: "memory");  /* 01a0: memw */
  return a2;  /* 01a3: retw.n */
}


/* esp_mesh_ap_list_clear @ mesh_common.o 0000002c size 166B bind GLOBAL
 * Calls: memset, mesh_free | indirect[2]: mem[a3+0x158]; mem[a3+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_ap_list_clear.str1.1, .rodata.__func__$1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=2, refs=6); reloc-direct=2, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_ap_list_clear(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 002c: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0072;  /* 002f: bnez.n a2, 72 <esp_mesh_ap_list_clear+0x46> */
  L_0031: a2 = (u32)&g_log_level + 0x0;  /* 0031: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0034 */
  a2 = 0x00004008u;  /* 0036: l32r = 16392 */
  if (a3 >= 3u) goto L_003f;  /* 0039: bgeui a3, 3, 3f <esp_mesh_ap_list_clear+0x13> */
  L_003c: goto L_00d0;  /* 003c: j */
  L_003f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 003f: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0042 */
  if (a3 == 0) goto L_00d0;  /* 0044: beqz a3, d0 <esp_mesh_ap_list_clear+0xa4> */
  L_0047: a4 = LD32(a3 + 0x150);  /* 0047 */
  if (a4 == 0) goto L_00d0;  /* 004a: beqz a4, d0 <esp_mesh_ap_list_clear+0xa4> */
  L_004d: a10 = LD32(a3 + 0x158);  /* 004d */
  a3 = 41;  /* 0050 */
  /* 0052: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0055 */
  a10 = 3;  /* 0057 */
  a11 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 0059: -> "mesh_common.c" */
  a14 = a11;  /* 005c */
  a15 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 005e: -> "mesh_common.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 0061: -> "mesh_common.c" */
  ST32(a1 + 0x0, a3);  /* 0064 */
  __asm__ volatile("" ::: "memory");  /* 0066: memw */
  /* 0069: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_00d0;  /* 006c: j */
  L_0072: a10 = a2;  /* 0072 */
  a12 = 8;  /* 0074 */
  a11 = 0;  /* 0076 */
  a3 = LD32(a2 + 0x0);  /* 0078 */
  a8 = (u32)&memset + 0x0;  /* 007a: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 007d: callx a8 (libc, via reloc-expand) */
  a2 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 0080: l32r -> .rodata.__func__$1 */
  goto L_00cb;  /* 0083: j */
  L_0089: a10 = LD32(a3 + 0x5c);  /* 0089 */
  a4 = LD32(a3 + 0x70);  /* 008c */
  if (a10 == 0) goto L_00a2;  /* 008f: beqz a10, a2 <esp_mesh_ap_list_clear+0x76> */
  L_0092: a12 = 53;  /* 0092 */
  a11 = a2;  /* 0095 */
  a8 = (u32)&mesh_free + 0x0;  /* 0097: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 009a: callx a8 via reloc-expand */
  a8 = 0;  /* 009d */
  ST32(a3 + 0x5c, a8);  /* 009f */
  L_00a2: a10 = LD32(a3 + 0x60);  /* 00a2 */
  if (a10 == 0) goto L_00b9;  /* 00a5: beqz.n a10, b9 <esp_mesh_ap_list_clear+0x8d> */
  L_00a7: a12 = 57;  /* 00a7 */
  a11 = a2;  /* 00a9 */
  __asm__ volatile("" ::: "memory");  /* 00ab: memw */
  a8 = (u32)&mesh_free + 0x0;  /* 00ae: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 00b1: callx a8 via reloc-expand */
  a8 = 0;  /* 00b4 */
  ST32(a3 + 0x60, a8);  /* 00b6 */
  L_00b9: a10 = a3;  /* 00b9 */
  a12 = 60;  /* 00bb */
  a11 = a2;  /* 00bd: mov */
  __asm__ volatile("" ::: "memory");  /* 00c0: memw */
  a8 = (u32)&mesh_free + 0x0;  /* 00c3: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 00c6: callx a8 via reloc-expand */
  a3 = a4;  /* 00c9 */
  L_00cb: if (a3 != 0) goto L_0089;  /* 00cb: bnez a3, 89 <esp_mesh_ap_list_clear+0x5d> */
  L_00ce: a2 = a3;  /* 00ce */
  L_00d0: return a2;  /* 00d0: retw.n */
}


/* esp_mesh_ap_list_clear_expire @ mesh_common.o 0000001c size 166B bind GLOBAL
 * Calls: memcmp | indirect[3]: mem[a4+0x158]; mem[a4+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_ap_list_clear.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_ap_list_clear_expire(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 001c: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_004e;  /* 001f: bnez.n a2, 4e <esp_mesh_ap_list_clear_expire+0x32> */
  L_0021: a2 = (u32)&g_log_level + 0x0;  /* 0021: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0024 */
  a2 = 0x00004008u;  /* 0026: l32r = 16392 */
  if (a3 >= 3u) goto L_002f;  /* 0029: bgeui a3, 3, 2f <esp_mesh_ap_list_clear_expire+0x13> */
  L_002c: goto L_00c0;  /* 002c: j */
  L_002f: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 002f: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 0032 */
  if (a4 == 0) goto L_00c0;  /* 0034: beqz a4, c0 <esp_mesh_ap_list_clear_expire+0xa4> */
  L_0037: a3 = LD32(a4 + 0x150);  /* 0037 */
  if (a3 == 0) goto L_00c0;  /* 003a: beqz a3, c0 <esp_mesh_ap_list_clear_expire+0xa4> */
  L_003d: a10 = LD32(a4 + 0x158);  /* 003d */
  a4 = 84;  /* 0040 */
  /* 0042: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 0045: -> "mesh_common.c" */
  goto L_0074;  /* 0048: j */
  L_004e: if (a3 != 0) goto L_008c;  /* 004e: bnez.n a3, 8c <esp_mesh_ap_list_clear_expire+0x70> */
  L_0050: a2 = (u32)&g_log_level + 0x0;  /* 0050: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0053 */
  a2 = 0x00004008u;  /* 0055: l32r = 16392 */
  if (a3 < 3u) goto L_00c0;  /* 0058: bltui a3, 3, c0 <esp_mesh_ap_list_clear_expire+0xa4> */
  L_005b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 005b: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 005e */
  if (a4 == 0) goto L_00c0;  /* 0060: beqz a4, c0 <esp_mesh_ap_list_clear_expire+0xa4> */
  L_0063: a3 = LD32(a4 + 0x150);  /* 0063 */
  if (a3 == 0) goto L_00c0;  /* 0066: beqz a3, c0 <esp_mesh_ap_list_clear_expire+0xa4> */
  L_0069: a10 = LD32(a4 + 0x158);  /* 0069 */
  a4 = 85;  /* 006c */
  /* 006e: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 0071: -> "mesh_common.c" */
  L_0074: a13 = a10;  /* 0074 */
  a14 = a11;  /* 0076 */
  a10 = 3;  /* 0078 */
  a15 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 007a: -> "mesh_common.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 007d: -> "mesh_common.c" */
  ST32(a1 + 0x0, a4);  /* 0080 */
  __asm__ volatile("" ::: "memory");  /* 0082: memw */
  /* 0085: INDIRECT callx a3 <- mem[a4+0x150]; result unknown */ a2 = 0;
  goto L_00c0;  /* 0088: j */
  L_008c: a4 = LD32(a2 + 0x0);  /* 008c */
  a5 = 6;  /* 008e */
  goto L_00bb;  /* 0090: j */
  L_0094: a2 = LD8U(a4 + 0x6c);  /* 0094 */
  if (a2 != 0) goto L_00b8;  /* 0097: bnez.n a2, b8 <esp_mesh_ap_list_clear_expire+0x9c> */
  L_0099: a12 = a5;  /* 0099 */
  a11 = a3;  /* 009b */
  a10 = a4;  /* 009d */
  a8 = (u32)&memcmp + 0x0;  /* 009f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00a2: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 00a5 */
  if (a10 != 0) goto L_00b8;  /* 00a7: bnez.n a10, b8 <esp_mesh_ap_list_clear_expire+0x9c> */
  L_00a9: a3 = 1;  /* 00a9 */
  ST8(a4 + 0x6c, a3);  /* 00ab */
  __asm__ volatile("" ::: "memory");  /* 00ae: memw */
  __asm__ volatile("" ::: "memory");  /* 00b1: memw */
  goto L_00c0;  /* 00b4: j */
  L_00b8: a4 = LD32(a4 + 0x70);  /* 00b8 */
  L_00bb: if (a4 != 0) goto L_0094;  /* 00bb: bnez a4, 94 <esp_mesh_ap_list_clear_expire+0x78> */
  L_00be: a2 = a4;  /* 00be */
  L_00c0: return a2;  /* 00c0: retw.n */
}


/* esp_mesh_ap_list_clear_invalid @ mesh_common.o 0000001c size 170B bind GLOBAL
 * Calls: memcmp | indirect[3]: mem[a4+0x158]; mem[a4+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_ap_list_clear.str1.1
 * Fidelity: medium - 3 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=3 */
u32 esp_mesh_ap_list_clear_invalid(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 001c: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_004e;  /* 001f: bnez.n a2, 4e <esp_mesh_ap_list_clear_invalid+0x32> */
  L_0021: a2 = (u32)&g_log_level + 0x0;  /* 0021: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0024 */
  a2 = 0x00004008u;  /* 0027: l32r = 16392 */
  if (a3 >= 3u) goto L_0030;  /* 002a: bgeui a3, 3, 30 <esp_mesh_ap_list_clear_invalid+0x14> */
  L_002d: goto L_00c4;  /* 002d: j */
  L_0030: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0030: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 0033 */
  if (a4 == 0) goto L_00c4;  /* 0036: beqz a4, c4 <esp_mesh_ap_list_clear_invalid+0xa8> */
  L_0039: a3 = LD32(a4 + 0x150);  /* 0039 */
  if (a3 == 0) goto L_00c4;  /* 003c: beqz a3, c4 <esp_mesh_ap_list_clear_invalid+0xa8> */
  L_003f: a10 = LD32(a4 + 0x158);  /* 003f */
  a4 = 179;  /* 0042 */
  /* 0045: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 0048: -> "mesh_common.c" */
  goto L_0077;  /* 004b: j */
  L_004e: if (a3 != 0) goto L_0090;  /* 004e: bnez.n a3, 90 <esp_mesh_ap_list_clear_invalid+0x74> */
  L_0050: a2 = (u32)&g_log_level + 0x0;  /* 0050: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0053 */
  a2 = 0x00004008u;  /* 0056: l32r = 16392 */
  if (a3 < 3u) goto L_00c4;  /* 0059: bltui a3, 3, c4 <esp_mesh_ap_list_clear_invalid+0xa8> */
  L_005c: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 005c: l32r -> global */
  a4 = LD32(a3 + 0x0);  /* 005f */
  if (a4 == 0) goto L_00c4;  /* 0062: beqz a4, c4 <esp_mesh_ap_list_clear_invalid+0xa8> */
  L_0065: a3 = LD32(a4 + 0x150);  /* 0065 */
  if (a3 == 0) goto L_00c4;  /* 0068: beqz a3, c4 <esp_mesh_ap_list_clear_invalid+0xa8> */
  L_006b: a10 = LD32(a4 + 0x158);  /* 006b */
  a4 = 180;  /* 006e */
  /* 0071: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a11 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 0074: -> "mesh_common.c" */
  L_0077: a13 = a10;  /* 0077 */
  a14 = a11;  /* 0079 */
  a10 = 3;  /* 007b */
  a15 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 007d: -> "mesh_common.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_ap_list_clear_str1_1 + 0x0);  /* 0080: -> "mesh_common.c" */
  ST32(a1 + 0x0, a4);  /* 0083 */
  __asm__ volatile("" ::: "memory");  /* 0086: memw */
  /* 0089: INDIRECT callx a3 <- mem[a4+0x150]; result unknown */ a2 = 0;
  goto L_00c4;  /* 008c: j */
  L_0090: a4 = LD32(a2 + 0x0);  /* 0090 */
  a5 = 6;  /* 0092 */
  goto L_00be;  /* 0094: j */
  L_0098: a2 = LD8U(a4 + 0x6c);  /* 0098 */
  if (a2 != 0) goto L_00bb;  /* 009b: bnez.n a2, bb <esp_mesh_ap_list_clear_invalid+0x9f> */
  L_009d: a12 = a5;  /* 009d */
  a11 = a3;  /* 009f */
  a10 = a4;  /* 00a1 */
  a8 = (u32)&memcmp + 0x0;  /* 00a3: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 00a6: callx a8 (libc, via reloc-expand) */
  a2 = a10;  /* 00a9 */
  if (a10 != 0) goto L_00bb;  /* 00ab: bnez.n a10, bb <esp_mesh_ap_list_clear_invalid+0x9f> */
  L_00ad: a3 = 1;  /* 00ad */
  ST8(a4 + 0x6c, a3);  /* 00af */
  __asm__ volatile("" ::: "memory");  /* 00b2: memw */
  __asm__ volatile("" ::: "memory");  /* 00b5: memw */
  goto L_00c4;  /* 00b8: j */
  L_00bb: a4 = LD32(a4 + 0x70);  /* 00bb */
  L_00be: if (a4 != 0) goto L_0098;  /* 00be: bnez a4, 98 <esp_mesh_ap_list_clear_invalid+0x7c> */
  L_00c1: a2 = a4;  /* 00c1: mov */
  L_00c4: return a2;  /* 00c4: retw.n */
}


/* esp_mesh_ap_list_find @ mesh_common.o 0000000c size 146B bind GLOBAL
 * Calls: memcmp, memcpy | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=2); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_ap_list_find(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  a9 = 0;  /* 000f */
  a8 = 1;  /* 0011 */
  a5 = a9;  /* 0013 */
  if (a3 == 0) a5 = a8;  /* 0015 */
  if (a2 != 0) a8 = a9;  /* 0018 */
  a10 = a2;  /* 001b */
  a2 = a5 | a8;  /* 001d */
  a4 = (a4 >> 8) & 0x1;  /* 0020: extui width 1 */
  if (a2 != a9) goto L_009a;  /* 0023: bne a2, a9, 9a <esp_mesh_ap_list_find+0x8e> */
  L_0026: a5 = LD32(a10 + 0x0);  /* 0026 */
  if (a5 == a9) goto L_009c;  /* 0028: beq a5, a9, 9c <esp_mesh_ap_list_find+0x90> */
  L_002b: a6 = 6;  /* 002b */
  L_002d: a12 = a6;  /* 002d */
  a11 = a3;  /* 002f */
  a10 = a5;  /* 0031 */
  a8 = (u32)&memcmp + 0x0;  /* 0033: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0036: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0090;  /* 0039: bnez a10, 90 <esp_mesh_ap_list_find+0x84> */
  L_003c: if (a4 != 0) goto L_0044;  /* 003c: bnez.n a4, 44 <esp_mesh_ap_list_find+0x38> */
  L_003e: a2 = 1;  /* 003e */
  goto L_009c;  /* 0040: j */
  L_0044: a2 = LD8U(a5 + 0x2c);  /* 0044 */
  a2 = (i32)(a2 << (32 - 7)) >> (32 - 7);  /* 0047: sext */
  a8 = LD8U(a3 + 0x2c);  /* 004a */
  if ((i32)a2 < -1) goto L_0054;  /* 004d: blti a2, -1, 54 <esp_mesh_ap_list_find+0x48> */
  L_0050: goto L_005a;  /* 0050: j */
  L_0054: a6 = (i32)(a8 << (32 - 7)) >> (32 - 7);  /* 0054: sext */
  if ((i32)a6 >= (i32)a2) goto L_0060;  /* 0057: bge a6, a2, 60 <esp_mesh_ap_list_find+0x54> */
  L_005a: ST8(a5 + 0x2c, a8);  /* 005a */
  __asm__ volatile("" ::: "memory");  /* 005d: memw */
  L_0060: a10 = LD32(a5 + 0x5c);  /* 0060 */
  if (a10 == 0) goto L_0075;  /* 0063: beqz.n a10, 75 <esp_mesh_ap_list_find+0x69> */
  L_0065: a11 = LD32(a3 + 0x5c);  /* 0065 */
  if (a11 == 0) goto L_0075;  /* 0068: beqz.n a11, 75 <esp_mesh_ap_list_find+0x69> */
  L_006a: a12 = 58;  /* 006a */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  a8 = (u32)&memcpy + 0x0;  /* 006f: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0072: callx a8 (libc, via reloc-expand) */
  L_0075: a10 = LD32(a5 + 0x60);  /* 0075 */
  if (a10 == 0) goto L_003e;  /* 0078: beqz a10, 3e <esp_mesh_ap_list_find+0x32> */
  L_007b: a11 = LD32(a3 + 0x60);  /* 007b */
  if (a11 == 0) goto L_003e;  /* 007e: beqz a11, 3e <esp_mesh_ap_list_find+0x32> */
  L_0081: a12 = 13;  /* 0081 */
  a8 = (u32)&memcpy + 0x0;  /* 0083: l32r -> global */
  a2 = memcpy(a2, a3, a4, a5, a6, a7);  /* 0086: callx a8 (libc, via reloc-expand) */
  a2 = a4;  /* 0089 */
  goto L_009c;  /* 008b: j */
  L_0090: a5 = LD32(a5 + 0x70);  /* 0090 */
  if (a5 != 0) goto L_002d;  /* 0093: bnez a5, 2d <esp_mesh_ap_list_find+0x21> */
  L_0096: goto L_009c;  /* 0096: j */
  L_009a: a2 = a9;  /* 009a */
  L_009c: return a2;  /* 009c: retw.n */
}


/* esp_mesh_ap_list_find_expire @ mesh_common.o 00000004 size 86B bind GLOBAL
 * Calls: memcmp | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_ap_list_find_expire(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = 0;  /* 0007 */
  a8 = 1;  /* 0009 */
  a4 = a9;  /* 000b */
  if (a3 == 0) a4 = a8;  /* 000d */
  if (a2 != 0) a8 = a9;  /* 0010 */
  a10 = a2;  /* 0013: mov */
  a2 = a4 | a8;  /* 0016 */
  if (a2 != a9) goto L_0050;  /* 0019: bne a2, a9, 50 <esp_mesh_ap_list_find_expire+0x4c> */
  L_001c: a4 = LD32(a10 + 0x0);  /* 001c */
  if (a4 == a9) goto L_0058;  /* 001e: beq a4, a9, 58 <esp_mesh_ap_list_find_expire+0x54> */
  L_0021: a5 = 6;  /* 0021 */
  L_0024: a8 = LD8U(a4 + 0x6c);  /* 0024 */
  if (a8 != 0) goto L_0046;  /* 0027: bnez.n a8, 46 <esp_mesh_ap_list_find_expire+0x42> */
  L_0029: a12 = a5;  /* 0029 */
  a11 = a3;  /* 002b */
  a10 = a4;  /* 002d */
  a8 = (u32)&memcmp + 0x0;  /* 002f: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5, a6, a7);  /* 0032: callx a8 (libc, via reloc-expand) */
  if (a10 != 0) goto L_0046;  /* 0035: bnez.n a10, 46 <esp_mesh_ap_list_find_expire+0x42> */
  L_0037: a8 = LD32(a4 + 0x5c);  /* 0037 */
  a9 = LD32(a3 + 0x5c);  /* 003a */
  a8 = LD8U(a8 + 0x2d);  /* 003d */
  a9 = LD8U(a9 + 0x2d);  /* 0040 */
  if (a9 < a8) goto L_0056;  /* 0043: bltu a9, a8, 56 <esp_mesh_ap_list_find_expire+0x52> */
  L_0046: a4 = LD32(a4 + 0x70);  /* 0046 */
  if (a4 != 0) goto L_0024;  /* 0049: bnez a4, 24 <esp_mesh_ap_list_find_expire+0x20> */
  L_004c: goto L_0058;  /* 004c: j */
  L_0050: a2 = a9;  /* 0050 */
  goto L_0058;  /* 0052: j */
  L_0056: a2 = 1;  /* 0056 */
  L_0058: return a2;  /* 0058: retw.n */
}


/* esp_mesh_ap_list_find_invalid @ mesh_common.o 00000004 size 177B bind GLOBAL
 * Calls: memcmp | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_ap_list_find_invalid(u32 a2, u32 a3, u32 a4, u32 a5) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a0 = 0; /* return address register */
  u32 a10, a11, a12, a6, a7, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a9 = 0;  /* 0007 */
  a8 = 1;  /* 0009 */
  a6 = a2;  /* 000b */
  a2 = a9;  /* 000d */
  if (a4 == 0) a2 = a8;  /* 000f */
  if (a3 != 0) a8 = a9;  /* 0012 */
  a2 = a2 | a8;  /* 0015 */
  if (a2 == a9) goto L_001e;  /* 0018: beq a2, a9, 1e <esp_mesh_ap_list_find_invalid+0x1a> */
  L_001b: goto L_00a0;  /* 001b: j */
  L_001e: a3 = LD32(a3 + 0x0);  /* 001e */
  if (a3 != a9) goto L_0026;  /* 0020: bne a3, a9, 26 <esp_mesh_ap_list_find_invalid+0x22> */
  L_0023: goto L_00b3;  /* 0023: j */
  L_0026: a7 = 6;  /* 0026 */
  L_0028: a12 = a7;  /* 0028 */
  a11 = a4;  /* 002a */
  a10 = a3;  /* 002c */
  a8 = (u32)&memcmp + 0x0;  /* 002e: l32r -> global */
  a2 = memcmp(a2, a3, a4, a5);  /* 0031: callx a8 (libc, via reloc-expand) */
  if (a10 == 0) goto L_00a5;  /* 0034: beqz a10, a5 <esp_mesh_ap_list_find_invalid+0xa1> */
  L_0037: a3 = LD32(a3 + 0x70);  /* 0037 */
  if (a3 != 0) goto L_0028;  /* 003a: bnez a3, 28 <esp_mesh_ap_list_find_invalid+0x24> */
  L_003d: goto L_00b3;  /* 003d: j */
  L_0040: a4 = LD8U(a3 + 0x6c);  /* 0040 */
  if (a4 == 0) goto L_00b1;  /* 0043: beqz a4, b1 <esp_mesh_ap_list_find_invalid+0xad> */
  L_0046: ST8(a3 + 0x6c, a10);  /* 0046 */
  __asm__ volatile("" ::: "memory");  /* 0049: memw */
  ST32(a3 + 0x68, a5);  /* 004c */
  __asm__ volatile("" ::: "memory");  /* 004f: memw */
  goto L_00b3;  /* 0052: j */
  L_0055: a8 = LD8U(a3 + 0x6c);  /* 0055 */
  if (a4 == 0) a10 = a6;  /* 0058 */
  a10 = a10 | a8;  /* 005b */
  a10 = (a10 >> 8) & 0x1;  /* 005e: extui width 1 */
  if (a10 != 0) goto L_00b3;  /* 0061: bnez a10, b3 <esp_mesh_ap_list_find_invalid+0xaf> */
  L_0064: a2 = LD8U(a4 + 0x7);  /* 0064 */
  if (a2 != 0) goto L_0075;  /* 0067: bnez.n a2, 75 <esp_mesh_ap_list_find_invalid+0x71> */
  L_0069: ST8(a3 + 0x6c, a6);  /* 0069 */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  __asm__ volatile("" ::: "memory");  /* 006f: memw */
  goto L_00b3;  /* 0072: j */
  L_0075: ST32(a3 + 0x68, a5);  /* 0075 */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  goto L_00b1;  /* 007b: j */
  L_0080: a6 = LD8U(a3 + 0x6c);  /* 0080 */
  if (a6 != 0) goto L_00b3;  /* 0083: bnez.n a6, b3 <esp_mesh_ap_list_find_invalid+0xaf> */
  L_0085: a2 = 1;  /* 0085 */
  a4 = LD32(a3 + 0x68);  /* 0087 */
  a4 = a5 - a4;  /* 008a: sub */
  a5 = 9;  /* 008d */
  if ((i32)a5 >= (i32)a4) goto L_00b3;  /* 008f: bge a5, a4, b3 <esp_mesh_ap_list_find_invalid+0xaf> */
  L_0092: ST8(a3 + 0x6c, a2);  /* 0092 */
  __asm__ volatile("" ::: "memory");  /* 0095: memw */
  a2 = a6;  /* 0098 */
  __asm__ volatile("" ::: "memory");  /* 009a: memw */
  goto L_00b3;  /* 009d: j */
  L_00a0: a2 = a9;  /* 00a0 */
  goto L_00b3;  /* 00a2: j */
  L_00a5: a4 = LD32(a4 + 0x5c);  /* 00a5 */
  if (a6 == 2) goto L_0040;  /* 00a8: beqi a6, 2, 40 <esp_mesh_ap_list_find_invalid+0x3c> */
  L_00ab: if (a6 == 3) goto L_0080;  /* 00ab: beqi a6, 3, 80 <esp_mesh_ap_list_find_invalid+0x7c> */
  L_00ae: if (a6 == 1) goto L_0055;  /* 00ae: beqi a6, 1, 55 <esp_mesh_ap_list_find_invalid+0x51> */
  L_00b1: a2 = 1;  /* 00b1 */
  L_00b3: return a2;  /* 00b3: retw.n */
}


/* esp_mesh_ap_list_update_invalid @ mesh_common.o 00000004 size 66B bind GLOBAL
 * Calls: esp_mesh_ap_list_find_invalid | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_ap_list_update_invalid(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8, a9;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  if (a2 == 0) goto L_0042;  /* 0007: beqz.n a2, 42 <esp_mesh_ap_list_update_invalid+0x3e> */
  L_0009: a5 = 1;  /* 0009 */
  a8 = 0;  /* 000b */
  if (a3 == 0) a8 = a5;  /* 000d */
  a2 = LD32(a2 + 0x0);  /* 0010 */
  a9 = (a8 >> 8) & 0x1;  /* 0012: extui width 1 */
  if (a8 != 0) goto L_0042;  /* 0015: bnez.n a8, 42 <esp_mesh_ap_list_update_invalid+0x3e> */
  L_0017: a8 = a9;  /* 0017 */
  if (a2 == 0) a8 = a5;  /* 0019 */
  if (a8 != 0) goto L_0042;  /* 001c: bnez.n a8, 42 <esp_mesh_ap_list_update_invalid+0x3e> */
  L_001e: a8 = LD32(a3 + 0x0);  /* 001e */
  if (a8 == 0) goto L_0042;  /* 0021: beqz a8, 42 <esp_mesh_ap_list_update_invalid+0x3e> */
  L_0024: a8 = LD32(a2 + 0x5c);  /* 0024 */
  if (a8 != 0) goto L_002e;  /* 0027: bnez.n a8, 2e <esp_mesh_ap_list_update_invalid+0x2a> */
  L_0029: goto L_003c;  /* 0029: j */
  L_002e: a13 = a4;  /* 002e */
  a12 = a2;  /* 0030 */
  a11 = a3;  /* 0032 */
  a10 = a5;  /* 0034 */
  a8 = (u32)&esp_mesh_ap_list_find_invalid;  /* 0036: l32r -> func addr */
  a2 = esp_mesh_ap_list_find_invalid(a2, a3, a4, a5, a6, a7);  /* 0039: callx a8 via reloc-expand */
  L_003c: a2 = LD32(a2 + 0x70);  /* 003c */
  if (a2 != 0) goto L_0024;  /* 003f: bnez a2, 24 <esp_mesh_ap_list_update_invalid+0x20> */
  L_0042: a2 = 0;  /* 0042 */
  return a2;  /* 0044: retw.n */
}

