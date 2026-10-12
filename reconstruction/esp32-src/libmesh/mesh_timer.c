/* libmesh.a mesh_timer.o --- reconstructed C (offline).
 * Role: timer-callback thunks dispatching to mesh_timer_do_process.
 * Object file: 6260 bytes on disk; 8/8 functions reconstructed, ~269 code bytes.
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
extern u32 g_log_level; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 mesh_timer_info; /* undefined data (reloc-referenced) */
extern u32 mesh_bcn_change_timeout_process(); /* defined in another libmesh.a object */
extern u32 mesh_candidate_monitor_timeout_process(); /* defined in another libmesh.a object */
extern u32 mesh_free(); /* defined in another libmesh.a object */
extern u32 mesh_ie_monitor_timeout_process(); /* defined in another libmesh.a object */
extern u32 mesh_ps_control_timeout_process(); /* defined in another libmesh.a object */
extern u32 mesh_root_connect_timeout_process(); /* defined in another libmesh.a object */
extern u32 mesh_rt_change_timeout_process(); /* defined in another libmesh.a object */
extern u32 route_announce_timeout_process(); /* defined in another libmesh.a object */
static const u8 RODATA__rodata___func___0[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x5f, 0x64, 0x6f, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73 }; /* .rodata.__func__$0 (20 bytes) */
static const u8 RODATA__rodata_mesh_timer_do_process_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x2e, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73, 0x0a, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x6e, 0x6f, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x2c, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x3a, 0x25, 0x64 }; /* .rodata.mesh_timer_do_process.str1.1 (88 bytes) strings: [0x0]="mesh_timer.c"; [0xd]="mesh" */

/* mesh_timer_bcn_change @ mesh_timer.o 00000004 size 11B bind GLOBAL
 * Calls: mesh_bcn_change_timeout_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_timer_bcn_change(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&mesh_bcn_change_timeout_process + 0x0;  /* 0007: l32r -> global */
  a2 = mesh_bcn_change_timeout_process(a2, a3, a4, a5, a6, a7);  /* 000a: callx a8 via reloc-expand */
  return a2;  /* 000d: retw.n */
}


/* mesh_timer_candidate_monitor @ mesh_timer.o 00000004 size 11B bind GLOBAL
 * Calls: mesh_candidate_monitor_timeout_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_timer_candidate_monitor(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&mesh_candidate_monitor_timeout_process + 0x0;  /* 0007: l32r -> global */
  a2 = mesh_candidate_monitor_timeout_process(a2, a3, a4, a5, a6, a7);  /* 000a: callx a8 via reloc-expand */
  return a2;  /* 000d: retw.n */
}


/* mesh_timer_do_process @ mesh_timer.o 00000028 size 192B bind GLOBAL
 * Calls: mesh_free | indirect[5]: mem[a3+0x158]; mem[a3+0x150]; mem[a3+0x4]; mem[a8+0x158] | Data refs: g_log_level, g_osi_funcs_p, .rodata.mesh_timer_do_process.str1.1, mesh_timer_info, .rodata.__func__$0
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=6); reloc-direct=1, funcdb-attributed=0, unknown-indirect=5 */
u32 mesh_timer_do_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0028: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_006c;  /* 002b: bnez.n a2, 6c <mesh_timer_do_process+0x44> */
  L_002d: a2 = (u32)&g_log_level + 0x0;  /* 002d: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 0030 */
  a2 = 0x00004008u;  /* 0032: l32r = 16392 */
  if (a3 >= 3u) goto L_003b;  /* 0035: bgeui a3, 3, 3b <mesh_timer_do_process+0x13> */
  L_0038: goto L_00e6;  /* 0038: j */
  L_003b: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 003b: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 003e */
  if (a3 == 0) goto L_00e6;  /* 0040: beqz a3, e6 <mesh_timer_do_process+0xbe> */
  L_0043: a4 = LD32(a3 + 0x150);  /* 0043 */
  if (a4 == 0) goto L_00e6;  /* 0046: beqz a4, e6 <mesh_timer_do_process+0xbe> */
  L_0049: a10 = LD32(a3 + 0x158);  /* 0049 */
  a3 = 97;  /* 004c */
  /* 004f: INDIRECT callx a10 <- mem[a3+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0052 */
  a10 = 3;  /* 0054 */
  a11 = (u32)(RODATA__rodata_mesh_timer_do_process_str1_1 + 0x0);  /* 0056: -> "mesh_timer.c" */
  a14 = a11;  /* 0059 */
  a15 = (u32)(RODATA__rodata_mesh_timer_do_process_str1_1 + 0x0);  /* 005b: -> "mesh_timer.c" */
  a12 = (u32)(RODATA__rodata_mesh_timer_do_process_str1_1 + 0x0);  /* 005e: -> "mesh_timer.c" */
  ST32(a1 + 0x0, a3);  /* 0061 */
  __asm__ volatile("" ::: "memory");  /* 0063: memw */
  /* 0066: INDIRECT callx a4 <- mem[a3+0x150]; result unknown */ a2 = 0;
  goto L_00e6;  /* 0069: j */
  L_006c: a9 = LD8U(a2 + 0x0);  /* 006c */
  a8 = (u32)&mesh_timer_info + 0x0;  /* 006f: l32r -> global */
  a3 = a9 + (a8 << 3);  /* 0072 */
  a3 = LD8U(a3 + 0x0);  /* 0075 */
  if (a3 == a9) goto L_0095;  /* 0078: beq a3, a9, 95 <mesh_timer_do_process+0x6d> */
  L_007b: a10 = a8;  /* 007b */
  a3 = 0;  /* 007d */
  goto L_0087;  /* 007f: j */
  L_0082: a3 = a3 + (1);  /* 0082 */
  a3 = (a3 >> 8) & 0x1;  /* 0084: extui width 1 */
  L_0087: a10 = a10 + (8);  /* 0087 */
  a4 = a10 + (-8);  /* 0089 */
  a4 = LD8U(a4 + 0x0);  /* 008c */
  if (a4 != a9) goto L_0082;  /* 008f: bne a4, a9, 82 <mesh_timer_do_process+0x5a> */
  L_0092: goto L_009a;  /* 0092: j */
  L_0095: a4 = 8;  /* 0095 */
  if (a4 < a3) goto L_00ab;  /* 0097: bltu a4, a3, ab <mesh_timer_do_process+0x83> */
  L_009a: a3 = a3 + (a8 << 3);  /* 009a */
  a3 = LD32(a3 + 0x4);  /* 009d */
  if (a3 == 0) goto L_00d6;  /* 00a0: beqz.n a3, d6 <mesh_timer_do_process+0xae> */
  L_00a2: a10 = a2;  /* 00a2: mov */
  /* 00a5: INDIRECT callx a3 <- mem[a3+0x4]; result unknown */ a2 = 0;
  goto L_00d6;  /* 00a8: j */
  L_00ab: a4 = (u32)&g_log_level + 0x0;  /* 00ab: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 00ae */
  if (a4 < 3u) goto L_00d6;  /* 00b0: bltui a4, 3, d6 <mesh_timer_do_process+0xae> */
  L_00b3: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 00b3: l32r -> global */
  a8 = LD32(a4 + 0x0);  /* 00b6 */
  if (a8 == 0) goto L_00d6;  /* 00b8: beqz.n a8, d6 <mesh_timer_do_process+0xae> */
  L_00ba: a4 = LD32(a8 + 0x150);  /* 00ba */
  if (a4 == 0) goto L_00d6;  /* 00bd: beqz.n a4, d6 <mesh_timer_do_process+0xae> */
  L_00bf: a10 = LD32(a8 + 0x158);  /* 00bf */
  /* 00c2: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 00c5 */
  a15 = a3;  /* 00c7 */
  a11 = (u32)(RODATA__rodata_mesh_timer_do_process_str1_1 + 0x0);  /* 00c9: -> "mesh_timer.c" */
  a10 = 3;  /* 00cc */
  a14 = a11;  /* 00ce */
  a12 = (u32)(RODATA__rodata_mesh_timer_do_process_str1_1 + 0x0);  /* 00d0: -> "mesh_timer.c" */
  /* 00d3: INDIRECT callx a4 <- mem[a8+0x150]; result unknown */ a2 = 0;
  L_00d6: a10 = a2;  /* 00d6 */
  a12 = 116;  /* 00d8 */
  a11 = (u32)(RODATA__rodata___func___0 + 0x0);  /* 00db: l32r -> .rodata.__func__$0 */
  a2 = 0;  /* 00de */
  a8 = (u32)&mesh_free + 0x0;  /* 00e0: l32r -> global */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 00e3: callx a8 via reloc-expand */
  L_00e6: return a2;  /* 00e6: retw.n */
}


/* mesh_timer_mie_monitor @ mesh_timer.o 00000004 size 11B bind GLOBAL
 * Calls: mesh_ie_monitor_timeout_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_timer_mie_monitor(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&mesh_ie_monitor_timeout_process + 0x0;  /* 0007: l32r -> global */
  a2 = mesh_ie_monitor_timeout_process(a2, a3, a4, a5, a6, a7);  /* 000a: callx a8 via reloc-expand */
  return a2;  /* 000d: retw.n */
}


/* mesh_timer_ps_control @ mesh_timer.o 00000004 size 11B bind GLOBAL
 * Calls: mesh_ps_control_timeout_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_timer_ps_control(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&mesh_ps_control_timeout_process + 0x0;  /* 0007: l32r -> global */
  a2 = mesh_ps_control_timeout_process(a2, a3, a4, a5, a6, a7);  /* 000a: callx a8 via reloc-expand */
  return a2;  /* 000d: retw.n */
}


/* mesh_timer_root_connect @ mesh_timer.o 00000004 size 11B bind GLOBAL
 * Calls: mesh_root_connect_timeout_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_timer_root_connect(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&mesh_root_connect_timeout_process + 0x0;  /* 0007: l32r -> global */
  a2 = mesh_root_connect_timeout_process(a2, a3, a4, a5, a6, a7);  /* 000a: callx a8 via reloc-expand */
  return a2;  /* 000d: retw.n */
}


/* mesh_timer_route_announce @ mesh_timer.o 00000004 size 11B bind GLOBAL
 * Calls: route_announce_timeout_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_timer_route_announce(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&route_announce_timeout_process + 0x0;  /* 0007: l32r -> global */
  a2 = route_announce_timeout_process(a2, a3, a4, a5, a6, a7);  /* 000a: callx a8 via reloc-expand */
  return a2;  /* 000d: retw.n */
}


/* mesh_timer_rt_change @ mesh_timer.o 00000004 size 11B bind GLOBAL
 * Calls: mesh_rt_change_timeout_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_timer_rt_change(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&mesh_rt_change_timeout_process + 0x0;  /* 0007: l32r -> global */
  a2 = mesh_rt_change_timeout_process(a2, a3, a4, a5, a6, a7);  /* 000a: callx a8 via reloc-expand */
  return a2;  /* 000d: retw.n */
}

