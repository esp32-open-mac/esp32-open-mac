/* libmesh.a mesh_config.o --- reconstructed C (offline).
 * Role: NVS persistence of mesh association/layer settings.
 * Object file: 8956 bytes on disk; 6/6 functions reconstructed, ~1056 code bytes.
 * Method: xtensa-esp32-elf-objdump -d/-s + readelf -rW/-sW + funcdb_libmesh.json v3
 * (calls/refs edges). Control flow preserved 1:1 via labels+gotos; regs a0-a15
 * are u32 locals; window rotation flattened. Direct calls come from
 * R_XTENSA_ASM_EXPAND relocs (ground truth); leftover indirect sites are
 * attributed in order from funcdb-v3 calls and marked funcdb-attributed;
 * literal-pool-only inferences contradicting funcdb-v3 were demoted (see
 * corrections). No logic invented; see Fidelity tags. */
#include <stdint.h>
#include <stddef.h>
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
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_mesh_max_layer; /* undefined data (reloc-referenced) */
extern u32 g_mesh_nvs_settings; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 esp_mesh_get_storage(); /* undefined func (args unknown, returns u32) */
static const u8 RODATA__rodata_CSWTCH_63[] = { 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x4d, 0x00, 0x00, 0x00 }; /* .rodata.CSWTCH$63 (28 bytes) */
static const u8 RODATA__rodata_esp_mesh_nvs_init_str1_1[] = { 0x4d, 0x45, 0x53, 0x48 }; /* .rodata.esp_mesh_nvs_init.str1.1 (4 bytes) */
static const u8 RODATA__rodata_esp_mesh_nvs_operate[] = { 0xd4, 0x00, 0x00, 0x00, 0x45, 0x01, 0x00, 0x00, 0xfc, 0x01, 0x00, 0x00, 0x82, 0x02, 0x00, 0x00, 0x3b, 0x03, 0x00, 0x00, 0x5b, 0x03, 0x00, 0x00 }; /* .rodata.esp_mesh_nvs_operate (24 bytes) */
static const u8 RODATA__rodata_esp_mesh_nvs_operate_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x57, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x5b, 0x25, 0x73, 0x2c, 0x25, 0x64, 0x5d, 0x20, 0x3c, 0x6e, 0x76, 0x73, 0x3e, 0x25, 0x73, 0x2c, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x6e, 0x76, 0x73, 0x5f, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x0a, 0x00, 0x4c, 0x41, 0x59, 0x45, 0x52, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x6e, 0x76, 0x73, 0x3e, 0x25, 0x73, 0x3a, 0x25, 0x64, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x3c, 0x6e, 0x76, 0x73, 0x3e, 0x25, 0x73, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x78, 0x25, 0x78, 0x0a, 0x00, 0x41, 0x53, 0x53, 0x4f, 0x43, 0x00, 0x4d, 0x4c, 0x41, 0x59 }; /* .rodata.esp_mesh_nvs_operate.str1.1 (144 bytes) strings: [0x0]="mesh_config.c"; [0xe]="mesh"; [0x48]="LAYER"; [0x86]="ASSOC" */
static const u8 RODATA__rodata_nvs_op2str_str1_1[] = { 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x00 }; /* .rodata.nvs_op2str.str1.1 (8 bytes) strings: [0x0]="unknown" */
static u8 LOCAL__bss_mesh_nvs_settings[0x4]; /* stand-in for .bss.mesh_nvs_settings (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_mesh_nvs_handle[0x4]; /* stand-in for .data.mesh_nvs_handle (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_nvs_deinit @ mesh_config.o 00000008 size 29B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x130] | Data refs: g_osi_funcs_p, .data.mesh_nvs_handle
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_nvs_deinit(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 000b: l32r -> global */
  a2 = (u32)&LOCAL__data_mesh_nvs_handle + 0x0;  /* 000e: l32r -> .data.mesh_nvs_handle (same-object static) */
  a8 = LD32(a8 + 0x0);  /* 0011 */
  a10 = LD32(a2 + 0x0);  /* 0013 */
  a8 = LD32(a8 + 0x130);  /* 0016 */
  /* 0019: INDIRECT callx a8 <- mem[a8+0x130]; result unknown */ a2 = 0;
  a8 = -1;  /* 001c */
  ST32(a2 + 0x0, a8);  /* 001e */
  __asm__ volatile("" ::: "memory");  /* 0020: memw */
  return a2;  /* 0023: retw.n */
}


/* esp_mesh_nvs_init @ mesh_config.o 00000014 size 75B bind GLOBAL
 * Calls: esp_mesh_nvs_operate | Data refs: .data.mesh_nvs_handle, g_osi_funcs_p, .rodata.esp_mesh_nvs_init.str1.1
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_nvs_init(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0014: entry a1, 48 (frame 48 bytes) */
  a2 = (u32)&LOCAL__data_mesh_nvs_handle + 0x0;  /* 0017: l32r -> .data.mesh_nvs_handle (same-object static) */
  a8 = LD32(a2 + 0x0);  /* 001a */
  if (a8 == -1) goto L_0045;  /* 001d: beqi a8, -1, 45 <esp_mesh_nvs_init+0x31> */
  L_0020: a2 = 1;  /* 0020 */
  a10 = a1;  /* 0022: mov */
  ST32(a1 + 0x0, a2);  /* 0025 */
  __asm__ volatile("" ::: "memory");  /* 0028: memw */
  a8 = (u32)&esp_mesh_nvs_operate;  /* 002b: l32r -> func addr */
  a2 = esp_mesh_nvs_operate(a2, a3, a4, a5, a6, a7);  /* 002e: callx a8 via reloc-expand */
  a2 = 3;  /* 0031 */
  a10 = a1;  /* 0033 */
  ST32(a1 + 0x0, a2);  /* 0035 */
  __asm__ volatile("" ::: "memory");  /* 0037: memw */
  a8 = (u32)&esp_mesh_nvs_operate;  /* 003a: l32r -> func addr */
  a2 = esp_mesh_nvs_operate(a2, a3, a4, a5, a6, a7);  /* 003d: callx a8 via reloc-expand */
  a2 = 0;  /* 0040 */
  goto L_005d;  /* 0042: j */
  L_0045: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0045: l32r -> global */
  a12 = a2;  /* 0048 */
  a11 = 1;  /* 004a */
  a8 = LD32(a8 + 0x0);  /* 004c */
  a10 = (u32)(RODATA__rodata_esp_mesh_nvs_init_str1_1 + 0x0);  /* 004f: l32r -> .rodata.esp_mesh_nvs_init.str1.1 */
  a8 = LD32(a8 + 0x12c);  /* 0052 */
  a2 = esp_mesh_nvs_operate(a2, a3, a4, a5, a6, a7);  /* 0055: callx a8 via literal-trampoline */
  a2 = LD32(a2 + 0x0);  /* 0058 */
  if (a2 != -1) goto L_0020;  /* 005a: bnei a2, -1, 20 <esp_mesh_nvs_init+0xc> */
  L_005d: return a2;  /* 005d: retw.n */
}


/* esp_mesh_nvs_operate @ mesh_config.o 00000060 size 788B bind GLOBAL
 * Calls: esp_mesh_get_storage, nvs_op2str | indirect[22]: mem[a4+0x158]; mem[a4+0x150]; mem[a5+0x138]; mem[a8+0x134] | Data refs: .data.mesh_nvs_handle, g_osi_funcs_p, .rodata.esp_mesh_nvs_operate.str1.1, .rodata.esp_mesh_nvs_operate, .bss.mesh_nvs_settings, g_log_level, g_mesh_nvs_settings, g_mesh_max_layer
 * Fidelity: low - jump-table switch present; cases not recovered
 * Edges: funcdb-v3 (calls=2, refs=10); reloc-direct=2, funcdb-attributed=0, unknown-indirect=22 */
u32 esp_mesh_nvs_operate(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0060: entry a1, 64 (frame 64 bytes) */
  a3 = a2;  /* 0063 */
  a2 = 0;  /* 0065 */
  ST32(a1 + 0x10, a2);  /* 0067 */
  __asm__ volatile("" ::: "memory");  /* 0069: memw */
  a8 = (u32)&esp_mesh_get_storage + 0x0;  /* 006c: l32r -> global */
  a2 = esp_mesh_get_storage(a2, a3, a4, a5, a6, a7);  /* 006f: callx a8 via reloc-expand */
  a2 = a10;  /* 0072 */
  if (a10 == 0) goto L_0079;  /* 0074: beqz.n a10, 79 <esp_mesh_nvs_operate+0x19> */
  L_0076: goto L_0370;  /* 0076: j */
  L_0079: a4 = (u32)&LOCAL__data_mesh_nvs_handle + 0x0;  /* 0079: l32r -> .data.mesh_nvs_handle (same-object static) */
  a10 = LD32(a4 + 0x0);  /* 007c */
  if (a10 != -1) goto L_00c0;  /* 007e: bnei a10, -1, c0 <esp_mesh_nvs_operate+0x60> */
  L_0081: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0081: l32r -> global */
  a4 = LD32(a2 + 0x0);  /* 0084 */
  a2 = 1;  /* 0086 */
  if (a4 == 0) goto L_0372;  /* 0089: beqz a4, 372 <esp_mesh_nvs_operate+0x312> */
  L_008c: a5 = LD32(a4 + 0x150);  /* 008c */
  if (a5 == 0) goto L_0372;  /* 008f: beqz a5, 372 <esp_mesh_nvs_operate+0x312> */
  L_0092: a10 = LD32(a4 + 0x158);  /* 0092 */
  /* 0095: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 0098 */
  a10 = LD32(a3 + 0x0);  /* 009a */
  a3 = 82;  /* 009c */
  a8 = (u32)&nvs_op2str;  /* 009e: l32r -> func addr */
  a2 = nvs_op2str(a2, a3, a4, a5, a6, a7);  /* 00a1: callx a8 via reloc-expand */
  a13 = a4;  /* 00a4 */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 00a6: -> "mesh_config.c" */
  a14 = a11;  /* 00a9 */
  a15 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 00ab: -> "mesh_config.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 00ae: -> "mesh_config.c" */
  ST32(a1 + 0x4, a10);  /* 00b1 */
  a10 = 2;  /* 00b3 */
  ST32(a1 + 0x0, a3);  /* 00b5 */
  __asm__ volatile("" ::: "memory");  /* 00b7: memw */
  /* 00ba: INDIRECT callx a5 <- mem[a4+0x150]; result unknown */ a2 = 0;
  goto L_0372;  /* 00bd: j */
  L_00c0: a8 = LD32(a3 + 0x0);  /* 00c0 */
  if (a8 < 6u) goto L_00c8;  /* 00c2: bltui a8, 6, c8 <esp_mesh_nvs_operate+0x68> */
  L_00c5: goto L_0372;  /* 00c5: j */
  L_00c8: a2 = (u32)(RODATA__rodata_esp_mesh_nvs_operate + 0x0);  /* 00c8: l32r -> .rodata.esp_mesh_nvs_operate */
  a8 = a8 + (a2 << 2);  /* 00cb */
  a2 = LD32(a8 + 0x0);  /* 00ce */
  /* 00d0: jx a2 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a6 = (u32)&LOCAL__bss_mesh_nvs_settings + 0x0;  /* 00d4: l32r -> .bss.mesh_nvs_settings (same-object static) */
  a2 = LD16U(a3 + 0x4);  /* 00d7 */
  a5 = LD16U(a6 + 0x0);  /* 00da */
  if (a5 != a2) goto L_00e3;  /* 00dd: bne a5, a2, e3 <esp_mesh_nvs_operate+0x83> */
  L_00e0: goto L_0370;  /* 00e0: j */
  L_00e3: a13 = 2;  /* 00e3 */
  a12 = a3 + (4);  /* 00e5 */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 00e7: l32r -> global */
  a5 = LD32(a2 + 0x0);  /* 00ea */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 00ec: -> "mesh_config.c" */
  a5 = LD32(a5 + 0x138);  /* 00ef */
  /* 00f2: INDIRECT callx a5 <- mem[a5+0x138]; result unknown */ a2 = 0;
  a5 = a10;  /* 00f5 */
  a8 = LD32(a2 + 0x0);  /* 00f7 */
  a10 = LD32(a4 + 0x0);  /* 00f9 */
  a8 = LD32(a8 + 0x134);  /* 00fb */
  /* 00fe: INDIRECT callx a8 <- mem[a8+0x134]; result unknown */ a2 = 0;
  a10 = a5 | a10;  /* 0101 */
  if (a10 != 0) goto L_0110;  /* 0104: bnez a10, 110 <esp_mesh_nvs_operate+0xb0> */
  L_0107: a4 = LD16U(a3 + 0x4);  /* 0107 */
  ST16(a6 + 0x0, a4);  /* 010a */
  __asm__ volatile("" ::: "memory");  /* 010d: memw */
  L_0110: a4 = (u32)&g_log_level + 0x0;  /* 0110: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0113 */
  if (a4 >= 3u) goto L_011c;  /* 0116: bgeui a4, 3, 11c <esp_mesh_nvs_operate+0xbc> */
  L_0119: goto L_0370;  /* 0119: j */
  L_011c: a2 = LD32(a2 + 0x0);  /* 011c */
  if (a2 == 0) goto L_0370;  /* 011e: beqz a2, 370 <esp_mesh_nvs_operate+0x310> */
  L_0121: a4 = LD32(a2 + 0x150);  /* 0121 */
  if (a4 == 0) goto L_0370;  /* 0124: beqz a4, 370 <esp_mesh_nvs_operate+0x310> */
  L_0127: a10 = LD32(a2 + 0x158);  /* 0127 */
  __asm__ volatile("" ::: "memory");  /* 012a: memw */
  /* 012d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 0130: mov */
  a10 = LD32(a3 + 0x0);  /* 0133 */
  a8 = (u32)&nvs_op2str;  /* 0136: l32r -> func addr */
  a2 = nvs_op2str(a2, a3, a4, a5, a6, a7);  /* 0139: callx a8 via reloc-expand */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 013c: -> "mesh_config.c" */
  a3 = LD16U(a3 + 0x4);  /* 013f */
  goto L_026a;  /* 0142: j */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 0145: l32r -> global */
  a2 = 2;  /* 0148 */
  a13 = a1 + (16);  /* 014a */
  ST32(a1 + 0x10, a2);  /* 014d */
  a2 = LD32(a5 + 0x0);  /* 014f */
  a4 = (u32)&g_mesh_nvs_settings + 0x0;  /* 0151: l32r -> global */
  a12 = a4;  /* 0154 */
  a2 = LD32(a2 + 0x13c);  /* 0156 */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 0159: -> "mesh_config.c" */
  __asm__ volatile("" ::: "memory");  /* 015c: memw */
  /* 015f: INDIRECT callx a2 <- mem[a2+0x13c]; result unknown */ a2 = 0;
  a2 = a10;  /* 0162 */
  a6 = (u32)&g_log_level + 0x0;  /* 0164: l32r -> global */
  if (a10 != 0) goto L_01b9;  /* 0167: bnez a10, 1b9 <esp_mesh_nvs_operate+0x159> */
  L_016a: a9 = LD16U(a4 + 0x0);  /* 016a */
  a8 = (u32)&LOCAL__bss_mesh_nvs_settings + 0x0;  /* 016d: l32r -> .bss.mesh_nvs_settings (same-object static) */
  a6 = LD32(a6 + 0x0);  /* 0170 */
  ST16(a8 + 0x0, a9);  /* 0172 */
  __asm__ volatile("" ::: "memory");  /* 0175: memw */
  if (a6 >= 3u) goto L_017e;  /* 0178: bgeui a6, 3, 17e <esp_mesh_nvs_operate+0x11e> */
  L_017b: goto L_0370;  /* 017b: j */
  L_017e: a5 = LD32(a5 + 0x0);  /* 017e */
  if (a5 == 0) goto L_0370;  /* 0180: beqz a5, 370 <esp_mesh_nvs_operate+0x310> */
  L_0183: a6 = LD32(a5 + 0x150);  /* 0183 */
  if (a6 == 0) goto L_0370;  /* 0186: beqz a6, 370 <esp_mesh_nvs_operate+0x310> */
  L_0189: a10 = LD32(a5 + 0x158);  /* 0189 */
  __asm__ volatile("" ::: "memory");  /* 018c: memw */
  /* 018f: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 0192 */
  a10 = LD32(a3 + 0x0);  /* 0194 */
  a8 = (u32)&nvs_op2str;  /* 0196: l32r -> func addr */
  a2 = nvs_op2str(a2, a3, a4, a5, a6, a7);  /* 0199: callx a8 via reloc-expand */
  a15 = a10;  /* 019c */
  a13 = a5;  /* 019e */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 01a0: -> "mesh_config.c" */
  a10 = 3;  /* 01a3 */
  a14 = a11;  /* 01a5 */
  a3 = LD16U(a4 + 0x0);  /* 01a7 */
  a12 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 01aa: -> "mesh_config.c" */
  ST32(a1 + 0x0, a3);  /* 01ad */
  __asm__ volatile("" ::: "memory");  /* 01af: memw */
  /* 01b2: INDIRECT callx a6 <- mem[a5+0x150]; result unknown */ a2 = 0;
  goto L_0372;  /* 01b5: j */
  L_01b9: a6 = LD32(a6 + 0x0);  /* 01b9 */
  if (a6 >= 3u) goto L_01c1;  /* 01bb: bgeui a6, 3, 1c1 <esp_mesh_nvs_operate+0x161> */
  L_01be: goto L_0370;  /* 01be: j */
  L_01c1: a5 = LD32(a5 + 0x0);  /* 01c1 */
  if (a5 == 0) goto L_0370;  /* 01c3: beqz a5, 370 <esp_mesh_nvs_operate+0x310> */
  L_01c6: a6 = LD32(a5 + 0x150);  /* 01c6 */
  if (a6 == 0) goto L_0370;  /* 01c9: beqz a6, 370 <esp_mesh_nvs_operate+0x310> */
  L_01cc: a10 = LD32(a5 + 0x158);  /* 01cc */
  /* 01cf: INDIRECT callx a10 <- mem[a5+0x158]; result unknown */ a2 = 0;
  a5 = a10;  /* 01d2 */
  a10 = LD32(a3 + 0x0);  /* 01d4 */
  a8 = (u32)&nvs_op2str;  /* 01d7: l32r -> func addr */
  a2 = nvs_op2str(a2, a3, a4, a5, a6, a7);  /* 01da: callx a8 via reloc-expand */
  a15 = a10;  /* 01dd */
  a13 = a5;  /* 01df */
  ST32(a1 + 0x4, a2);  /* 01e1 */
  a10 = 3;  /* 01e3 */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 01e5: -> "mesh_config.c" */
  a14 = a11;  /* 01e8 */
  a2 = LD16U(a4 + 0x0);  /* 01ea */
  a12 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 01ed: -> "mesh_config.c" */
  ST32(a1 + 0x0, a2);  /* 01f0 */
  __asm__ volatile("" ::: "memory");  /* 01f2: memw */
  /* 01f5: INDIRECT callx a6 <- mem[a5+0x150]; result unknown */ a2 = 0;
  goto L_0370;  /* 01f8: j */
  a6 = (u32)&LOCAL__bss_mesh_nvs_settings + 0x0;  /* 01fc: l32r -> .bss.mesh_nvs_settings (same-object static) */
  a2 = LD8U(a3 + 0x4);  /* 01ff */
  a5 = LD8U(a6 + 0x2);  /* 0202 */
  if (a5 != a2) goto L_020b;  /* 0205: bne a5, a2, 20b <esp_mesh_nvs_operate+0x1ab> */
  L_0208: goto L_0370;  /* 0208: j */
  L_020b: a13 = 1;  /* 020b */
  a12 = a3 + (4);  /* 020d */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 020f: l32r -> global */
  a5 = LD32(a2 + 0x0);  /* 0212 */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 0214: -> "mesh_config.c" */
  a5 = LD32(a5 + 0x138);  /* 0217 */
  /* 021a: INDIRECT callx a5 <- mem[a5+0x138]; result unknown */ a2 = 0;
  a5 = a10;  /* 021d */
  a8 = LD32(a2 + 0x0);  /* 021f */
  a10 = LD32(a4 + 0x0);  /* 0221 */
  a8 = LD32(a8 + 0x134);  /* 0223 */
  /* 0226: INDIRECT callx a8 <- mem[a8+0x134]; result unknown */ a2 = 0;
  a10 = a5 | a10;  /* 0229 */
  if (a10 != 0) goto L_0238;  /* 022c: bnez a10, 238 <esp_mesh_nvs_operate+0x1d8> */
  L_022f: a4 = LD8U(a3 + 0x4);  /* 022f */
  ST8(a6 + 0x2, a4);  /* 0232 */
  __asm__ volatile("" ::: "memory");  /* 0235: memw */
  L_0238: a4 = (u32)&g_log_level + 0x0;  /* 0238: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 023b */
  if (a4 >= 3u) goto L_0244;  /* 023e: bgeui a4, 3, 244 <esp_mesh_nvs_operate+0x1e4> */
  L_0241: goto L_0370;  /* 0241: j */
  L_0244: a2 = LD32(a2 + 0x0);  /* 0244 */
  if (a2 == 0) goto L_0370;  /* 0246: beqz a2, 370 <esp_mesh_nvs_operate+0x310> */
  L_0249: a4 = LD32(a2 + 0x150);  /* 0249 */
  if (a4 == 0) goto L_0370;  /* 024c: beqz a4, 370 <esp_mesh_nvs_operate+0x310> */
  L_024f: a10 = LD32(a2 + 0x158);  /* 024f */
  __asm__ volatile("" ::: "memory");  /* 0252: memw */
  /* 0255: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a2 = a10;  /* 0258: mov */
  a10 = LD32(a3 + 0x0);  /* 025b */
  a8 = (u32)&nvs_op2str;  /* 025e: l32r -> func addr */
  a2 = nvs_op2str(a2, a3, a4, a5, a6, a7);  /* 0261: callx a8 via reloc-expand */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 0264: -> "mesh_config.c" */
  a3 = LD8U(a3 + 0x4);  /* 0267 */
  L_026a: a15 = a10;  /* 026a */
  a14 = a11;  /* 026c */
  a13 = a2;  /* 026e */
  a10 = 3;  /* 0270 */
  a12 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 0272: -> "mesh_config.c" */
  ST32(a1 + 0x0, a3);  /* 0275 */
  __asm__ volatile("" ::: "memory");  /* 0277: memw */
  /* 027a: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_0370;  /* 027d: j */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0282: l32r -> global */
  a2 = 1;  /* 0285 */
  a13 = a1 + (16);  /* 0287 */
  ST32(a1 + 0x10, a2);  /* 028a */
  a2 = LD32(a4 + 0x0);  /* 028c */
  a12 = (u32)&g_mesh_nvs_settings + 0x2;  /* 028e: l32r -> global */
  a2 = LD32(a2 + 0x13c);  /* 0291 */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 0294: -> "mesh_config.c" */
  __asm__ volatile("" ::: "memory");  /* 0297: memw */
  /* 029a: INDIRECT callx a2 <- mem[a2+0x13c]; result unknown */ a2 = 0;
  a2 = a10;  /* 029d */
  a5 = (u32)&g_log_level + 0x0;  /* 029f: l32r -> global */
  if (a10 != 0) goto L_02fa;  /* 02a2: bnez a10, 2fa <esp_mesh_nvs_operate+0x29a> */
  L_02a5: a6 = (u32)&g_mesh_nvs_settings + 0x0;  /* 02a5: l32r -> global */
  a8 = (u32)&LOCAL__bss_mesh_nvs_settings + 0x0;  /* 02a8: l32r -> .bss.mesh_nvs_settings (same-object static) */
  a9 = LD8U(a6 + 0x2);  /* 02ab */
  a5 = LD32(a5 + 0x0);  /* 02ae */
  ST8(a8 + 0x2, a9);  /* 02b0 */
  __asm__ volatile("" ::: "memory");  /* 02b3: memw */
  if (a5 >= 3u) goto L_02bc;  /* 02b6: bgeui a5, 3, 2bc <esp_mesh_nvs_operate+0x25c> */
  L_02b9: goto L_0370;  /* 02b9: j */
  L_02bc: a4 = LD32(a4 + 0x0);  /* 02bc */
  if (a4 == 0) goto L_0370;  /* 02be: beqz a4, 370 <esp_mesh_nvs_operate+0x310> */
  L_02c1: a5 = LD32(a4 + 0x150);  /* 02c1 */
  if (a5 == 0) goto L_0370;  /* 02c4: beqz a5, 370 <esp_mesh_nvs_operate+0x310> */
  L_02c7: a10 = LD32(a4 + 0x158);  /* 02c7 */
  __asm__ volatile("" ::: "memory");  /* 02ca: memw */
  /* 02cd: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 02d0 */
  a10 = LD32(a3 + 0x0);  /* 02d2 */
  a8 = (u32)&nvs_op2str;  /* 02d4: l32r -> func addr */
  a2 = nvs_op2str(a2, a3, a4, a5, a6, a7);  /* 02d7: callx a8 via reloc-expand */
  a15 = a10;  /* 02da */
  a13 = a4;  /* 02dc */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 02de: -> "mesh_config.c" */
  a10 = 3;  /* 02e1 */
  a14 = a11;  /* 02e3 */
  a3 = LD8U(a6 + 0x2);  /* 02e5 */
  a12 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 02e8: -> "mesh_config.c" */
  ST32(a1 + 0x0, a3);  /* 02eb */
  __asm__ volatile("" ::: "memory");  /* 02ee: memw */
  /* 02f1: INDIRECT callx a5 <- mem[a4+0x150]; result unknown */ a2 = 0;
  goto L_0372;  /* 02f4: j */
  L_02fa: a5 = LD32(a5 + 0x0);  /* 02fa */
  if (a5 < 3u) goto L_0370;  /* 02fc: bltui a5, 3, 370 <esp_mesh_nvs_operate+0x310> */
  L_02ff: a4 = LD32(a4 + 0x0);  /* 02ff */
  if (a4 == 0) goto L_0370;  /* 0301: beqz a4, 370 <esp_mesh_nvs_operate+0x310> */
  L_0304: a5 = LD32(a4 + 0x150);  /* 0304 */
  if (a5 == 0) goto L_0370;  /* 0307: beqz a5, 370 <esp_mesh_nvs_operate+0x310> */
  L_030a: a10 = LD32(a4 + 0x158);  /* 030a */
  /* 030d: INDIRECT callx a10 <- mem[a4+0x158]; result unknown */ a2 = 0;
  a4 = a10;  /* 0310 */
  a10 = LD32(a3 + 0x0);  /* 0312 */
  a8 = (u32)&nvs_op2str;  /* 0314: l32r -> func addr */
  a2 = nvs_op2str(a2, a3, a4, a5, a6, a7);  /* 0317: callx a8 via reloc-expand */
  a15 = a10;  /* 031a */
  a13 = a4;  /* 031c */
  ST32(a1 + 0x4, a2);  /* 031e */
  a10 = 3;  /* 0320 */
  a2 = (u32)&g_mesh_nvs_settings + 0x0;  /* 0322: l32r -> global */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 0325: -> "mesh_config.c" */
  a14 = a11;  /* 0328 */
  a2 = LD8U(a2 + 0x2);  /* 032a */
  a12 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 032d: -> "mesh_config.c" */
  ST32(a1 + 0x0, a2);  /* 0330 */
  __asm__ volatile("" ::: "memory");  /* 0332: memw */
  /* 0335: INDIRECT callx a5 <- mem[a4+0x150]; result unknown */ a2 = 0;
  goto L_0370;  /* 0338: j */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 033b: l32r -> global */
  a13 = 2;  /* 033e */
  a3 = LD32(a2 + 0x0);  /* 0340 */
  a12 = (u32)&g_mesh_max_layer + 0x0;  /* 0342: l32r -> global */
  a3 = LD32(a3 + 0x138);  /* 0345 */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 0348: -> "mesh_config.c" */
  /* 034b: INDIRECT callx a3 <- mem[a3+0x138]; result unknown */ a2 = 0;
  a2 = LD32(a2 + 0x0);  /* 034e */
  a10 = LD32(a4 + 0x0);  /* 0350 */
  a2 = LD32(a2 + 0x134);  /* 0352 */
  /* 0355: INDIRECT callx a2 <- mem[a2+0x134]; result unknown */ a2 = 0;
  goto L_0370;  /* 0358: j */
  a2 = (u32)&g_osi_funcs_p + 0x0;  /* 035b: l32r -> global */
  a13 = a1 + (16);  /* 035e */
  a2 = LD32(a2 + 0x0);  /* 0361 */
  a12 = (u32)&g_mesh_max_layer + 0x0;  /* 0364: l32r -> global */
  a2 = LD32(a2 + 0x13c);  /* 0367 */
  a11 = (u32)(RODATA__rodata_esp_mesh_nvs_operate_str1_1 + 0x0);  /* 036a: -> "mesh_config.c" */
  /* 036d: INDIRECT callx a2 <- mem[a2+0x13c]; result unknown */ a2 = 0;
  L_0370: a2 = 0;  /* 0370 */
  L_0372: return a2;  /* 0372: retw.n */
}


/* esp_mesh_nvs_set_assoc @ mesh_config.o 00000010 size 72B bind GLOBAL
 * Calls: esp_mesh_nvs_operate | Data refs: g_mesh_is_root, g_is_root_fixed, .bss.mesh_nvs_settings
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_nvs_set_assoc(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0010: entry a1, 48 (frame 48 bytes) */
  a9 = (u32)&g_mesh_is_root + 0x0;  /* 0013: l32r -> global */
  a2 = (a2 >> 8) & 0x1;  /* 0016: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 0019: memw */
  a9 = LD8U(a9 + 0x0);  /* 001c */
  a9 = (a9 >> 8) & 0x1;  /* 001f: extui width 1 */
  if (a9 == 0) goto L_0032;  /* 0022: beqz.n a9, 32 <esp_mesh_nvs_set_assoc+0x22> */
  L_0024: a9 = (u32)&g_is_root_fixed + 0x0;  /* 0024: l32r -> global */
  a10 = LD8U(a9 + 0x0);  /* 0027 */
  a9 = 0;  /* 002a */
  if (a10 != 0) a2 = a9;  /* 002c */
  goto L_0034;  /* 002f: j */
  L_0032: a2 = a9;  /* 0032 */
  L_0034: a9 = (u32)&LOCAL__bss_mesh_nvs_settings + 0x0;  /* 0034: l32r -> .bss.mesh_nvs_settings (same-object static) */
  a10 = 0;  /* 0037 */
  a9 = LD8U(a9 + 0x2);  /* 0039 */
  if (a9 == a2) goto L_0054;  /* 003c: beq a9, a2, 54 <esp_mesh_nvs_set_assoc+0x44> */
  L_003f: a9 = 2;  /* 003f */
  a10 = a1;  /* 0041 */
  ST32(a1 + 0x0, a9);  /* 0043 */
  ST16(a1 + 0x4, a2);  /* 0045 */
  __asm__ volatile("" ::: "memory");  /* 0048: memw */
  __asm__ volatile("" ::: "memory");  /* 004b: memw */
  a8 = (u32)&esp_mesh_nvs_operate;  /* 004e: l32r -> func addr */
  a2 = esp_mesh_nvs_operate(a2, a3, a4, a5, a6, a7);  /* 0051: callx a8 via reloc-expand */
  L_0054: a2 = a10;  /* 0054 */
  return a2;  /* 0056: retw.n */
}


/* esp_mesh_nvs_set_layer @ mesh_config.o 00000010 size 70B bind GLOBAL
 * Calls: esp_mesh_nvs_operate | Data refs: g_mesh_is_root, g_is_root_fixed, .bss.mesh_nvs_settings
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_nvs_set_layer(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0010: entry a1, 48 (frame 48 bytes) */
  a9 = (u32)&g_mesh_is_root + 0x0;  /* 0013: l32r -> global */
  a2 = (a2 >> 16) & 0x1;  /* 0016: extui width 1 */
  __asm__ volatile("" ::: "memory");  /* 0019: memw */
  a9 = LD8U(a9 + 0x0);  /* 001c */
  a9 = (a9 >> 8) & 0x1;  /* 001f: extui width 1 */
  if (a9 == 0) goto L_0032;  /* 0022: beqz.n a9, 32 <esp_mesh_nvs_set_layer+0x22> */
  L_0024: a9 = (u32)&g_is_root_fixed + 0x0;  /* 0024: l32r -> global */
  a10 = LD8U(a9 + 0x0);  /* 0027 */
  a9 = 0;  /* 002a */
  if (a10 != 0) a2 = a9;  /* 002c */
  goto L_0034;  /* 002f: j */
  L_0032: a2 = a9;  /* 0032 */
  L_0034: a9 = (u32)&LOCAL__bss_mesh_nvs_settings + 0x0;  /* 0034: l32r -> .bss.mesh_nvs_settings (same-object static) */
  a10 = 0;  /* 0037 */
  a9 = LD16U(a9 + 0x0);  /* 0039 */
  if (a9 == a2) goto L_0052;  /* 003c: beq a9, a2, 52 <esp_mesh_nvs_set_layer+0x42> */
  L_003f: ST32(a1 + 0x0, a10);  /* 003f */
  a10 = a1;  /* 0041 */
  ST16(a1 + 0x4, a2);  /* 0043 */
  __asm__ volatile("" ::: "memory");  /* 0046: memw */
  __asm__ volatile("" ::: "memory");  /* 0049: memw */
  a8 = (u32)&esp_mesh_nvs_operate;  /* 004c: l32r -> func addr */
  a2 = esp_mesh_nvs_operate(a2, a3, a4, a5, a6, a7);  /* 004f: callx a8 via reloc-expand */
  L_0052: a2 = a10;  /* 0052 */
  return a2;  /* 0054: retw.n */
}


/* nvs_op2str @ mesh_config.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.nvs_op2str.str1.1, .rodata.CSWTCH$63
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 nvs_op2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 000b */
  a2 = (u32)(RODATA__rodata_nvs_op2str_str1_1 + 0x0);  /* 000d: -> "unknown" */
  if (a8 >= 7u) goto L_001c;  /* 0010: bgeui a8, 7, 1c <nvs_op2str+0x14> */
  L_0013: a2 = (u32)(RODATA__rodata_CSWTCH_63 + 0x0);  /* 0013: l32r -> .rodata.CSWTCH$63 */
  a8 = a8 + (a2 << 2);  /* 0016 */
  a2 = LD32(a8 + 0x0);  /* 0019 */
  L_001c: return a2;  /* 001c: retw.n */
}

