/* libmesh.a mesh_utilities.o --- reconstructed C (offline).
 * Role: string helpers (event/state id to string), context/mbox create/free, task create.
 * Object file: 31080 bytes on disk; 24/24 functions reconstructed, ~1457 code bytes.
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
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 sprintf(); /* undefined func (args unknown, returns u32) */
static const u8 RODATA__rodata_CSWTCH_52[] = { 0x7c, 0x04, 0x00, 0x00, 0x8d, 0x04, 0x00, 0x00, 0xa0, 0x04, 0x00, 0x00, 0xb2, 0x04, 0x00, 0x00, 0xc5, 0x04, 0x00, 0x00, 0xd7, 0x04, 0x00, 0x00, 0xe9, 0x04, 0x00, 0x00, 0x03, 0x05, 0x00, 0x00, 0x16, 0x05, 0x00, 0x00, 0x30, 0x05, 0x00, 0x00, 0x4a, 0x05, 0x00, 0x00, 0x67, 0x05, 0x00, 0x00, 0x81, 0x05, 0x00, 0x00, 0x99, 0x05, 0x00, 0x00, 0xb1, 0x05, 0x00, 0x00, 0xc8, 0x05, 0x00, 0x00, 0xe1, 0x05, 0x00, 0x00, 0xfd, 0x05, 0x00, 0x00, 0x15, 0x06, 0x00, 0x00, 0x2e, 0x06, 0x00, 0x00, 0x48, 0x06, 0x00, 0x00, 0x5c, 0x06, 0x00, 0x00, 0x6b, 0x06, 0x00, 0x00, 0x81, 0x06, 0x00, 0x00, 0x96, 0x06, 0x00, 0x00, 0xac, 0x06, 0x00, 0x00, 0xbe, 0x06, 0x00, 0x00, 0xd1, 0x06, 0x00, 0x00, 0xe7, 0x06, 0x00, 0x00, 0xfe, 0x06, 0x00, 0x00, 0x13, 0x07, 0x00, 0x00, 0x27, 0x07, 0x00, 0x00, 0x40, 0x07, 0x00, 0x00, 0x58, 0x07, 0x00, 0x00, 0x71, 0x07, 0x00, 0x00, 0x8a, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa3, 0x07, 0x00, 0x00, 0xba, 0x07, 0x00, 0x00, 0xd2, 0x07, 0x00, 0x00, 0xe2, 0x07, 0x00, 0x00, 0xf6, 0x07, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00, 0x28, 0x08, 0x00, 0x00, 0x42, 0x08, 0x00, 0x00, 0x52, 0x08, 0x00, 0x00, 0x63, 0x08, 0x00, 0x00, 0x82, 0x08, 0x00, 0x00 }; /* .rodata.CSWTCH$52 (192 bytes) */
static const u8 RODATA__rodata_CSWTCH_54[] = { 0xfa, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x05, 0x04, 0x00, 0x00, 0x0d, 0x04, 0x00, 0x00, 0x14, 0x04, 0x00, 0x00, 0x19, 0x04, 0x00, 0x00, 0x1e, 0x04, 0x00, 0x00, 0x2a, 0x04, 0x00, 0x00, 0x37, 0x04, 0x00, 0x00, 0x3d, 0x04, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x4b, 0x04, 0x00, 0x00, 0x52, 0x04, 0x00, 0x00, 0x5f, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x04, 0x00, 0x00, 0x72, 0x04, 0x00, 0x00 }; /* .rodata.CSWTCH$54 (68 bytes) */
static const u8 RODATA__rodata_CSWTCH_56[] = { 0xbe, 0x03, 0x00, 0x00, 0x8f, 0x03, 0x00, 0x00, 0xc2, 0x03, 0x00, 0x00, 0xcd, 0x03, 0x00, 0x00, 0xd8, 0x03, 0x00, 0x00, 0xe0, 0x03, 0x00, 0x00, 0xe7, 0x03, 0x00, 0x00, 0xef, 0x03, 0x00, 0x00, 0x97, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; /* .rodata.CSWTCH$56 (40 bytes) */
static const u8 RODATA__rodata_CSWTCH_59[] = { 0x1d, 0x00, 0x00, 0x00, 0xb0, 0x03, 0x00, 0x00, 0xb5, 0x03, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00 }; /* .rodata.CSWTCH$59 (20 bytes) */
static const u8 RODATA__rodata_CSWTCH_61[] = { 0x8f, 0x03, 0x00, 0x00, 0x97, 0x03, 0x00, 0x00, 0x9c, 0x03, 0x00, 0x00, 0xa4, 0x03, 0x00, 0x00, 0xa9, 0x03, 0x00, 0x00 }; /* .rodata.CSWTCH$61 (20 bytes) */
static const u8 RODATA__rodata_CSWTCH_63[] = { 0xd8, 0x02, 0x00, 0x00, 0xf1, 0x02, 0x00, 0x00, 0x0a, 0x03, 0x00, 0x00, 0x24, 0x03, 0x00, 0x00, 0x40, 0x03, 0x00, 0x00, 0x58, 0x03, 0x00, 0x00, 0x77, 0x03, 0x00, 0x00 }; /* .rodata.CSWTCH$63 (28 bytes) */
static const u8 RODATA__rodata_CSWTCH_65[] = { 0x8a, 0x02, 0x00, 0x00, 0xa4, 0x02, 0x00, 0x00, 0xbf, 0x02, 0x00, 0x00 }; /* .rodata.CSWTCH$65 (12 bytes) */
static const u8 RODATA__rodata_CSWTCH_67[] = { 0x56, 0x02, 0x00, 0x00, 0x62, 0x02, 0x00, 0x00, 0x6e, 0x02, 0x00, 0x00, 0x7c, 0x02, 0x00, 0x00 }; /* .rodata.CSWTCH$67 (16 bytes) */
static const u8 RODATA__rodata_CSWTCH_69[] = { 0xfe, 0x00, 0x00, 0x00, 0x16, 0x01, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x48, 0x01, 0x00, 0x00, 0x5f, 0x01, 0x00, 0x00, 0x77, 0x01, 0x00, 0x00, 0x8f, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa7, 0x01, 0x00, 0x00, 0xc0, 0x01, 0x00, 0x00, 0xd9, 0x01, 0x00, 0x00, 0xf2, 0x01, 0x00, 0x00, 0x0c, 0x02, 0x00, 0x00, 0x24, 0x02, 0x00, 0x00, 0x3c, 0x02, 0x00, 0x00 }; /* .rodata.CSWTCH$69 (68 bytes) */
static const u8 RODATA__rodata_CSWTCH_71[] = { 0x84, 0x00, 0x00, 0x00, 0x9f, 0x00, 0x00, 0x00, 0xb3, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xee, 0x00, 0x00, 0x00 }; /* .rodata.CSWTCH$71 (56 bytes) */
static const u8 RODATA__rodata_CSWTCH_73[] = { 0x22, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x56, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; /* .rodata.CSWTCH$73 (40 bytes) */
static const u8 RODATA__rodata_CSWTCH_75[] = { 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00 }; /* .rodata.CSWTCH$75 (12 bytes) */
static const u8 RODATA__rodata___func___1[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x66, 0x72, 0x65, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78 }; /* .rodata.__func__$1 (20 bytes) */
static const u8 RODATA__rodata___func___2[] = { 0x65, 0x73, 0x70, 0x5f, 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x00 }; /* .rodata.__func__$2 (24 bytes) strings: [0x0]="esp_mesh_create_context" */
static const u8 RODATA__rodata_discnx_reason_id2str[] = { 0x44, 0x01, 0x00, 0x00, 0xd9, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0x00, 0xe5, 0x00, 0x00, 0x00, 0xeb, 0x00, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, 0xf7, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x15, 0x01, 0x00, 0x00, 0x1b, 0x01, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00, 0xac, 0x00, 0x00, 0x00, 0xd3, 0x00, 0x00, 0x00, 0x32, 0x01, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00, 0x38, 0x01, 0x00, 0x00, 0x3e, 0x01, 0x00, 0x00 }; /* .rodata.discnx_reason_id2str (104 bytes) */
static const u8 RODATA__rodata_discnx_reason_id2str_str1_1[] = { 0x61, 0x75, 0x74, 0x68, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x00, 0x00, 0x74, 0x6f, 0x6f, 0x20, 0x6d, 0x61, 0x6e, 0x79, 0x00, 0x63, 0x79, 0x63, 0x6c, 0x69, 0x63, 0x00, 0x69, 0x64, 0x6c, 0x65, 0x00, 0x6c, 0x65, 0x61, 0x66, 0x00, 0x64, 0x69, 0x66, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x64, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x00, 0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x00, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x74, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x00, 0x73, 0x63, 0x61, 0x6e, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x00, 0x69, 0x65, 0x20, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x00, 0x77, 0x61, 0x69, 0x76, 0x65, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x61, 0x73, 0x73, 0x6f, 0x63, 0x20, 0x6c, 0x65, 0x61, 0x76, 0x65, 0x00, 0x6e, 0x6f, 0x20, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x00, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x77, 0x6f, 0x72, 0x73, 0x65, 0x00, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x20, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x20, 0x75, 0x6e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x00, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x75, 0x6e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x00, 0x6e, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x20, 0x53, 0x54, 0x41, 0x00, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x00, 0x4d, 0x49, 0x43, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x00, 0x34, 0x2d, 0x77, 0x61, 0x79, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x00, 0x64, 0x69, 0x73, 0x61, 0x73, 0x73, 0x6f, 0x63, 0x20, 0x64, 0x75, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79 }; /* .rodata.discnx_reason_id2str.str1.1 (324 bytes) strings: [0x0]="auth expire"; [0xd]="too many"; [0x16]="cyclic"; [0x1d]="idle"; [0x22]="leaf"; [0x27]="different id" */
static const u8 RODATA__rodata_dutytype2str[] = { 0xb5, 0x00, 0x00, 0x00, 0x9c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0xa2, 0x00, 0x00, 0x00, 0x56, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0xaf, 0x00, 0x00, 0x00 }; /* .rodata.dutytype2str (64 bytes) */
static const u8 RODATA__rodata_dutytype2str_str1_1[] = { 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x00, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x7c, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x73, 0x75, 0x67, 0x67, 0x65, 0x73, 0x74, 0x00, 0x73, 0x75, 0x67, 0x67, 0x65, 0x73, 0x74, 0x7c, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x64, 0x65, 0x6d, 0x61, 0x6e, 0x64, 0x00, 0x64, 0x65, 0x6d, 0x61, 0x6e, 0x64, 0x7c, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00, 0x61, 0x6c, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x65, 0x00, 0x64, 0x69, 0x63, 0x74, 0x61, 0x74, 0x65, 0x00, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x7c, 0x64, 0x65, 0x6d, 0x61, 0x6e }; /* .rodata.dutytype2str.str1.1 (112 bytes) strings: [0x0]="request"; [0x8]="request|master"; [0x17]="suggest"; [0x1f]="suggest|master"; [0x2e]="demand"; [0x35]="demand|master" */
static const u8 RODATA__rodata_esp_mesh_create_mbox_str1_1[] = { 0x6d, 0x65, 0x73, 0x68, 0x5f, 0x75, 0x74, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x2e, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x68, 0x00, 0x49, 0x20, 0x28, 0x25, 0x64, 0x29, 0x20, 0x25, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x20, 0x25, 0x75, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x61, 0x72, 0x67, 0x73 }; /* .rodata.esp_mesh_create_mbox.str1.1 (48 bytes) strings: [0x0]="mesh_utilities.c"; [0x11]="mesh" */
static const u8 RODATA__rodata_nwk_event_id2str_str1_1[] = { 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x4e, 0x57, 0x4b, 0x5f, 0x4d, 0x41, 0x58 }; /* .rodata.nwk_event_id2str.str1.1 (12 bytes) */
static const u8 RODATA__rodata_tx_msg_id2str_str1_1[] = { 0x6d, 0x61, 0x78, 0x00 }; /* .rodata.tx_msg_id2str.str1.1 (4 bytes) strings: [0x0]="max" */
static const u8 RODATA__rodata_tx_state_id2str_str1_1[] = { 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x00 }; /* .rodata.tx_state_id2str.str1.1 (8 bytes) strings: [0x0]="unknown" */
static const u8 RODATA__rodata_vote_done2str_str1_1[] = { 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x00 }; /* .rodata.vote_done2str.str1.1 (8 bytes) strings: [0x0]="Unknown" */
static const u8 RODATA__rodata_wifi_event_id2str[] = { 0x63, 0x01, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x00, 0x00, 0xbc, 0x00, 0x00, 0x00, 0xc2, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0xce, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0xda, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00, 0xec, 0x00, 0x00, 0x00, 0xf2, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x16, 0x01, 0x00, 0x00, 0x1c, 0x01, 0x00, 0x00, 0x22, 0x01, 0x00, 0x00, 0x28, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x2e, 0x01, 0x00, 0x00, 0x34, 0x01, 0x00, 0x00, 0x3a, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x46, 0x01, 0x00, 0x00, 0xe6, 0x00, 0x00, 0x00 }; /* .rodata.wifi_event_id2str (276 bytes) */
static const u8 RODATA__rodata_wifi_event_id2str_str1_1[] = { 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x52, 0x45, 0x41, 0x44, 0x59, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x43, 0x41, 0x4e, 0x5f, 0x44, 0x4f, 0x4e, 0x45, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x53, 0x54, 0x41, 0x52, 0x54, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x45, 0x44, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x44, 0x49, 0x53, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x45, 0x44, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x43, 0x48, 0x41, 0x4e, 0x47, 0x45, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x57, 0x50, 0x53, 0x5f, 0x45, 0x52, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x57, 0x50, 0x53, 0x5f, 0x45, 0x52, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x45, 0x44, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x57, 0x50, 0x53, 0x5f, 0x45, 0x52, 0x5f, 0x54, 0x49, 0x4d, 0x45, 0x4f, 0x55, 0x54, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x54, 0x41, 0x5f, 0x57, 0x50, 0x53, 0x5f, 0x45, 0x52, 0x5f, 0x50, 0x49, 0x4e, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x41, 0x50, 0x5f, 0x53, 0x54, 0x41, 0x52, 0x54, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x41, 0x50, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x4d, 0x41, 0x43, 0x5f, 0x53, 0x54, 0x41, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x45, 0x44, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x41, 0x50, 0x5f, 0x53, 0x54, 0x41, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x45, 0x44, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x41, 0x50, 0x5f, 0x53, 0x54, 0x41, 0x44, 0x49, 0x53, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x45, 0x44, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x41, 0x50, 0x5f, 0x50, 0x52, 0x4f, 0x42, 0x45, 0x52, 0x45, 0x51, 0x52, 0x45, 0x43, 0x56, 0x45, 0x44, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x49, 0x45, 0x5f, 0x43, 0x48, 0x41, 0x4e, 0x47, 0x45, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x57, 0x45, 0x41, 0x4b, 0x5f, 0x52, 0x53, 0x53, 0x49, 0x00, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x45, 0x56, 0x45, 0x4e, 0x54, 0x5f, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x53, 0x54, 0x4f, /* ... +312 bytes */ }; /* .rodata.wifi_event_id2str.str1.1 (824 bytes) strings: [0x0]="WIFI_EVENT_WIFI_READY"; [0x16]="WIFI_EVENT_SCAN_DONE"; [0x2b]="WIFI_EVENT_STA_START"; [0x40]="WIFI_EVENT_STA_STOP"; [0x54]="WIFI_EVENT_STA_CONNECTED"; [0x6d]="WIFI_EVENT_STA_DISCONNECTED" */
static u8 LOCAL__bss_strid_0[0x4]; /* stand-in for .bss.strid$0 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* discnx_reason_id2str @ mesh_utilities.o 0000006c size 229B bind GLOBAL
 * Calls: none | Data refs: .rodata.discnx_reason_id2str.str1.1, .rodata.discnx_reason_id2str, g_mesh_is_root
 * Fidelity: low - jump-table switch present; cases not recovered
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 discnx_reason_id2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  float F4;
  /* 006c: entry a1, 32 (frame 32 bytes) */
  a8 = 111;  /* 006f */
  if ((i32)a8 < (i32)a2) goto L_00b8;  /* 0072: blt a8, a2, b8 <discnx_reason_id2str+0x4c> */
  L_0075: a8 = 99;  /* 0075 */
  if ((i32)a8 < (i32)a2) goto L_0088;  /* 0078: blt a8, a2, 88 <discnx_reason_id2str+0x1c> */
  L_007b: a2 = a2 + (-1);  /* 007b */
  a9 = 14;  /* 007d */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 007f: -> "auth expire" */
  if (a9 >= a2) goto L_00a1;  /* 0082: bgeu a9, a2, a1 <discnx_reason_id2str+0x35> */
  L_0085: goto L_014d;  /* 0085: j */
  L_0088: a2 = a2 + (-101);  /* 0088 */
  a9 = 10;  /* 008b */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 008d: -> "auth expire" */
  if (a9 >= a2) goto L_0096;  /* 0090: bgeu a9, a2, 96 <discnx_reason_id2str+0x2a> */
  L_0093: goto L_014d;  /* 0093: j */
  L_0096: a8 = (u32)(RODATA__rodata_discnx_reason_id2str + 0x0);  /* 0096: l32r -> .rodata.discnx_reason_id2str */
  a2 = a2 + (a8 << 2);  /* 0099 */
  a2 = LD32(a2 + 0x0);  /* 009c */
  /* 009e: jx a2 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  L_00a1: a8 = (u32)(RODATA__rodata_discnx_reason_id2str + 0x0);  /* 00a1: l32r -> .rodata.discnx_reason_id2str */
  a2 = a2 + (a8 << 2);  /* 00a4 */
  a2 = LD32(a2 + 0x0);  /* 00a7 */
  /* 00a9: jx a2 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00ac: -> "auth expire" */
  goto L_014d;  /* 00af: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00b2: -> "auth expire" */
  goto L_014d;  /* 00b5: j */
  L_00b8: a9 = 200;  /* 00b8 */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00bb: -> "auth expire" */
  if (a2 != a9) goto L_00c4;  /* 00be: bne a2, a9, c4 <discnx_reason_id2str+0x58> */
  L_00c1: goto L_014d;  /* 00c1: j */
  L_00c4: a9 = 204;  /* 00c4 */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00c7: -> "auth expire" */
  if (a2 != a9) goto L_014d;  /* 00ca: bne a2, a9, 14d <discnx_reason_id2str+0xe1> */
  L_00cd: a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00cd: -> "auth expire" */
  goto L_014d;  /* 00d0: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00d3: -> "auth expire" */
  goto L_014d;  /* 00d6: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00d9: -> "auth expire" */
  goto L_014d;  /* 00dc: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00df: -> "auth expire" */
  goto L_014d;  /* 00e2: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00e5: -> "auth expire" */
  goto L_014d;  /* 00e8: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00eb: -> "auth expire" */
  goto L_014d;  /* 00ee: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00f1: -> "auth expire" */
  goto L_014d;  /* 00f4: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00f7: -> "auth expire" */
  goto L_014d;  /* 00fa: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 00fd: -> "auth expire" */
  goto L_014d;  /* 0100: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 0103: -> "auth expire" */
  goto L_014d;  /* 0106: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 0109: -> "auth expire" */
  goto L_014d;  /* 010c: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 010f: -> "auth expire" */
  goto L_014d;  /* 0112: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 0115: -> "auth expire" */
  goto L_014d;  /* 0118: j */
  a2 = (u32)&g_mesh_is_root + 0x0;  /* 011b: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 011e: memw */
  a2 = LD8U(a2 + 0x0);  /* 0121 */
  a2 = (a2 >> 8) & 0x1;  /* 0124: extui width 1 */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 0127: -> "auth expire" */
  if (a2 != 0) goto L_014d;  /* 012a: bnez.n a2, 14d <discnx_reason_id2str+0xe1> */
  L_012c: a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 012c: -> "auth expire" */
  goto L_014d;  /* 012f: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 0132: -> "auth expire" */
  goto L_014d;  /* 0135: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 0138: -> "auth expire" */
  goto L_014d;  /* 013b: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 013e: -> "auth expire" */
  goto L_014d;  /* 0141: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 0144: -> "auth expire" */
  goto L_014d;  /* 0147: j */
  a8 = (u32)(RODATA__rodata_discnx_reason_id2str_str1_1 + 0x0);  /* 014a: -> "auth expire" */
  L_014d: a2 = a8;  /* 014d */
  return a2;  /* 014f: retw.n */
}


/* dutytype2str @ mesh_utilities.o 00000034 size 136B bind GLOBAL
 * Calls: none | Data refs: .rodata.tx_state_id2str.str1.1, .rodata.dutytype2str, .rodata.dutytype2str.str1.1
 * Fidelity: low - jump-table switch present; cases not recovered
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 dutytype2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0034: entry a1, 32 (frame 32 bytes) */
  a8 = 16;  /* 0037 */
  if ((i32)a8 < (i32)a2) goto L_0064;  /* 0039: blt a8, a2, 64 <dutytype2str+0x30> */
  L_003c: a8 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 003c: -> "unknown" */
  if ((i32)a2 < 1) goto L_00b8;  /* 003f: blti a2, 1, b8 <dutytype2str+0x84> */
  L_0042: a2 = a2 + (-1);  /* 0042 */
  a8 = 15;  /* 0044 */
  if (a8 < a2) goto L_005c;  /* 0046: bltu a8, a2, 5c <dutytype2str+0x28> */
  L_0049: a8 = (u32)(RODATA__rodata_dutytype2str + 0x0);  /* 0049: l32r -> .rodata.dutytype2str */
  a2 = a2 + (a8 << 2);  /* 004c */
  a2 = LD32(a2 + 0x0);  /* 004f */
  /* 0051: jx a2 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 0056: -> "request" */
  goto L_00b8;  /* 0059: j */
  L_005c: a8 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 005c: -> "unknown" */
  goto L_00b8;  /* 005f: j */
  L_0064: a9 = 129;  /* 0064 */
  a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 0067: -> "request" */
  if (a2 == a9) goto L_00b8;  /* 006a: beq a2, a9, b8 <dutytype2str+0x84> */
  L_006d: if ((i32)a9 < (i32)a2) goto L_0084;  /* 006d: blt a9, a2, 84 <dutytype2str+0x50> */
  L_0070: a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 0070: -> "request" */
  if (a2 == 32) goto L_00b8;  /* 0073: beqi a2, 32, b8 <dutytype2str+0x84> */
  L_0076: a8 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 0076: -> "unknown" */
  if (a2 != 64) goto L_00b8;  /* 0079: bnei a2, 64, b8 <dutytype2str+0x84> */
  L_007c: a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 007c: -> "request" */
  goto L_00b8;  /* 007f: j */
  L_0084: a9 = 130;  /* 0084 */
  a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 0087: -> "request" */
  if (a2 == a9) goto L_00b8;  /* 008a: beq a2, a9, b8 <dutytype2str+0x84> */
  L_008d: a9 = 132;  /* 008d */
  a8 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 0090: -> "unknown" */
  if (a2 != a9) goto L_00b8;  /* 0093: bne a2, a9, b8 <dutytype2str+0x84> */
  L_0096: a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 0096: -> "request" */
  goto L_00b8;  /* 0099: j */
  a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 009c: -> "request" */
  goto L_00b8;  /* 009f: j */
  a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 00a2: -> "request" */
  goto L_00b8;  /* 00a5: j */
  a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 00a9: -> "request" */
  goto L_00b8;  /* 00ac: j */
  a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 00af: -> "request" */
  goto L_00b8;  /* 00b2: j */
  a8 = (u32)(RODATA__rodata_dutytype2str_str1_1 + 0x0);  /* 00b5: -> "request" */
  L_00b8: a2 = a8;  /* 00b8 */
  return a2;  /* 00ba: retw.n */
}


/* esp_mesh_create_context @ mesh_utilities.o 00000014 size 82B bind GLOBAL
 * Calls: mesh_malloc, memset, mesh_free | Data refs: .rodata.__func__$2
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=3, refs=4); reloc-direct=3, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_create_context(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0014: entry a1, 32 (frame 32 bytes) */
  a3 = a2;  /* 0017 */
  if (a2 != 0) goto L_0021;  /* 0019: bnez a2, 21 <esp_mesh_create_context+0xd> */
  L_001c: a2 = 0;  /* 001c */
  goto L_0064;  /* 001e: j */
  L_0021: a4 = (u32)(RODATA__rodata___func___2 + 0x0);  /* 0021: -> "esp_mesh_create_context" */
  a12 = 43;  /* 0024 */
  a11 = a4;  /* 0026 */
  a10 = 48;  /* 0028 */
  a8 = (u32)&mesh_malloc;  /* 002b: l32r -> func addr */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 002e: callx a8 via reloc-expand */
  a2 = a10;  /* 0031 */
  if (a10 == 0) goto L_001c;  /* 0033: beqz a10, 1c <esp_mesh_create_context+0x8> */
  L_0036: a12 = 48;  /* 0036 */
  a11 = 0;  /* 0038 */
  a8 = (u32)&memset + 0x0;  /* 003a: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 003d: callx a8 (libc, via reloc-expand) */
  a10 = a3;  /* 0040 */
  a12 = 48;  /* 0042 */
  a11 = a4;  /* 0044 */
  a8 = (u32)&mesh_malloc;  /* 0046: l32r -> func addr */
  a2 = mesh_malloc(a2, a3, a4, a5, a6, a7);  /* 0049: callx a8 via reloc-expand */
  ST32(a2 + 0x0, a10);  /* 004c */
  a3 = a10;  /* 004e */
  if (a10 != 0) goto L_0064;  /* 0050: bnez.n a10, 64 <esp_mesh_create_context+0x50> */
  L_0052: a10 = a2;  /* 0052 */
  a12 = 50;  /* 0054 */
  a11 = a4;  /* 0056: mov */
  __asm__ volatile("" ::: "memory");  /* 0059: memw */
  a8 = (u32)&mesh_free;  /* 005c: l32r -> func addr */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 005f: callx a8 via reloc-expand */
  a2 = a3;  /* 0062 */
  L_0064: return a2;  /* 0064: retw.n */
}


/* esp_mesh_create_mbox @ mesh_utilities.o 00000018 size 141B bind GLOBAL
 * Calls: none | indirect[5]: mem[a2+0x158]; mem[a2+0x150]; mem[a8+0x5c]; mem[a3+0x48] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_create_mbox.str1.1
 * Fidelity: medium - 5 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=5 */
u32 esp_mesh_create_mbox(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  a11 = a4;  /* 001b */
  if (a2 != 0) goto L_005d;  /* 001d: bnez.n a2, 5d <esp_mesh_create_mbox+0x45> */
  L_001f: a2 = (u32)&g_log_level + 0x0;  /* 001f: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0022 */
  a3 = 0x00004008u;  /* 0024: l32r = 16392 */
  if (a2 < 3u) goto L_009e;  /* 0027: bltui a2, 3, 9e <esp_mesh_create_mbox+0x86> */
  L_002a: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 002a: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 002d */
  if (a2 == 0) goto L_009e;  /* 002f: beqz a2, 9e <esp_mesh_create_mbox+0x86> */
  L_0032: a5 = LD32(a2 + 0x150);  /* 0032 */
  if (a5 == 0) goto L_009e;  /* 0035: beqz a5, 9e <esp_mesh_create_mbox+0x86> */
  L_0038: a10 = LD32(a2 + 0x158);  /* 0038 */
  a2 = 98;  /* 003b */
  /* 003e: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0041 */
  a10 = 3;  /* 0043 */
  a11 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 0045: -> "mesh_utilities.c" */
  a14 = a11;  /* 0048 */
  a15 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 004a: -> "mesh_utilities.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 004d: -> "mesh_utilities.c" */
  ST32(a1 + 0x0, a2);  /* 0050 */
  __asm__ volatile("" ::: "memory");  /* 0052: memw */
  /* 0055: INDIRECT callx a5 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_009e;  /* 0058: j */
  L_005d: a5 = (u32)&g_osi_funcs_p + 0x0;  /* 005d: l32r -> global */
  a10 = a3;  /* 0060 */
  a3 = -1;  /* 0062 */
  a8 = LD32(a5 + 0x0);  /* 0064 */
  a8 = LD32(a8 + 0x5c);  /* 0066 */
  /* 0069: INDIRECT callx a8 <- mem[a8+0x5c]; result unknown */ a2 = 0;
  ST32(a2 + 0x0, a10);  /* 006c */
  if (a10 == 0) goto L_009e;  /* 006e: beqz.n a10, 9e <esp_mesh_create_mbox+0x86> */
  L_0070: a3 = LD8U(a2 + 0x8);  /* 0070 */
  if (((a3 >> 0) & 1) != 0) goto L_007e;  /* 0073: bbsi a3, 0, 7e <esp_mesh_create_mbox+0x66> */
  L_0076: a3 = 0;  /* 0076 */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  goto L_009e;  /* 007b: j */
  L_007e: a3 = LD32(a5 + 0x0);  /* 007e */
  a10 = LD32(a3 + 0x48);  /* 0080 */
  /* 0083: INDIRECT callx a10 <- mem[a3+0x48]; result unknown */ a2 = 0;
  a3 = a10;  /* 0086 */
  ST32(a2 + 0x4, a10);  /* 0088 */
  if (a10 != 0) goto L_0076;  /* 008a: bnez a10, 76 <esp_mesh_create_mbox+0x5e> */
  L_008d: a5 = LD32(a5 + 0x0);  /* 008d */
  a10 = LD32(a2 + 0x0);  /* 008f */
  a5 = LD32(a5 + 0x60);  /* 0091 */
  __asm__ volatile("" ::: "memory");  /* 0094: memw */
  /* 0097: INDIRECT callx a5 <- mem[a5+0x60]; result unknown */ a2 = 0;
  ST32(a2 + 0x0, a3);  /* 009a */
  a3 = -1;  /* 009c */
  L_009e: a2 = a3;  /* 009e */
  __asm__ volatile("" ::: "memory");  /* 00a0: memw */
  return a2;  /* 00a3: retw.n */
}


/* esp_mesh_free_context @ mesh_utilities.o 00000024 size 104B bind GLOBAL
 * Calls: mesh_free | indirect[2]: mem[a8+0x158]; mem[a8+0x150] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_create_mbox.str1.1, .rodata.__func__$1
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=5); reloc-direct=1, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_free_context(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8;
  /* 0024: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_0064;  /* 0027: bnez.n a2, 64 <esp_mesh_free_context+0x40> */
  L_0029: a2 = (u32)&g_log_level + 0x0;  /* 0029: l32r -> global */
  a3 = LD32(a2 + 0x0);  /* 002c */
  a2 = 0x00004008u;  /* 002e: l32r = 16392 */
  if (a3 < 3u) goto L_008a;  /* 0031: bltui a3, 3, 8a <esp_mesh_free_context+0x66> */
  L_0034: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0034: l32r -> global */
  a8 = LD32(a3 + 0x0);  /* 0037 */
  if (a8 == 0) goto L_008a;  /* 0039: beqz a8, 8a <esp_mesh_free_context+0x66> */
  L_003c: a3 = LD32(a8 + 0x150);  /* 003c */
  if (a3 == 0) goto L_008a;  /* 003f: beqz a3, 8a <esp_mesh_free_context+0x66> */
  L_0042: a10 = LD32(a8 + 0x158);  /* 0042 */
  /* 0045: INDIRECT callx a10 <- mem[a8+0x158]; result unknown */ a2 = 0;
  a8 = 61;  /* 0048 */
  a13 = a10;  /* 004a */
  a11 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 004c: -> "mesh_utilities.c" */
  a10 = 3;  /* 004f */
  a14 = a11;  /* 0051 */
  a15 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 0053: -> "mesh_utilities.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 0056: -> "mesh_utilities.c" */
  ST32(a1 + 0x0, a8);  /* 0059 */
  __asm__ volatile("" ::: "memory");  /* 005b: memw */
  /* 005e: INDIRECT callx a3 <- mem[a8+0x150]; result unknown */ a2 = 0;
  goto L_008a;  /* 0061: j */
  L_0064: a10 = LD32(a2 + 0x0);  /* 0064 */
  a3 = (u32)(RODATA__rodata___func___1 + 0x0);  /* 0066: l32r -> .rodata.__func__$1 */
  if (a10 == 0) goto L_0079;  /* 0069: beqz.n a10, 79 <esp_mesh_free_context+0x55> */
  L_006b: a12 = 69;  /* 006b */
  a11 = a3;  /* 006d */
  a8 = (u32)&mesh_free;  /* 006f: l32r -> func addr */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0072: callx a8 via reloc-expand */
  a8 = 0;  /* 0075 */
  ST32(a2 + 0x0, a8);  /* 0077 */
  L_0079: a10 = a2;  /* 0079 */
  a12 = 72;  /* 007b */
  a11 = a3;  /* 007d */
  __asm__ volatile("" ::: "memory");  /* 007f: memw */
  a8 = (u32)&mesh_free;  /* 0082: l32r -> func addr */
  a2 = mesh_free(a2, a3, a4, a5, a6, a7);  /* 0085: callx a8 via reloc-expand */
  a2 = 0;  /* 0088 */
  L_008a: return a2;  /* 008a: retw.n */
}


/* esp_mesh_free_mbox @ mesh_utilities.o 00000018 size 125B bind GLOBAL
 * Calls: none | indirect[4]: mem[a2+0x158]; mem[a2+0x150]; mem[a3+0x60]; mem[a4+0x50] | Data refs: g_log_level, g_osi_funcs_p, .rodata.esp_mesh_create_mbox.str1.1
 * Fidelity: medium - 4 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=3); reloc-direct=0, funcdb-attributed=0, unknown-indirect=4 */
u32 esp_mesh_free_mbox(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15;
  /* 0018: entry a1, 48 (frame 48 bytes) */
  if (a2 != 0) goto L_005e;  /* 001b: bnez.n a2, 5e <esp_mesh_free_mbox+0x46> */
  L_001d: a2 = (u32)&g_log_level + 0x0;  /* 001d: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 0020 */
  a3 = 0x00004008u;  /* 0022: l32r = 16392 */
  if (a2 < 3u) goto L_008e;  /* 0025: bltui a2, 3, 8e <esp_mesh_free_mbox+0x76> */
  L_0028: a2 = (u32)&g_osi_funcs_p + 0x0;  /* 0028: l32r -> global */
  a2 = LD32(a2 + 0x0);  /* 002b */
  if (a2 == 0) goto L_008e;  /* 002e: beqz a2, 8e <esp_mesh_free_mbox+0x76> */
  L_0031: a4 = LD32(a2 + 0x150);  /* 0031 */
  if (a4 == 0) goto L_008e;  /* 0034: beqz a4, 8e <esp_mesh_free_mbox+0x76> */
  L_0037: a10 = LD32(a2 + 0x158);  /* 0037 */
  a2 = 122;  /* 003a */
  /* 003d: INDIRECT callx a10 <- mem[a2+0x158]; result unknown */ a2 = 0;
  a13 = a10;  /* 0040 */
  a10 = 3;  /* 0042 */
  a11 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 0044: -> "mesh_utilities.c" */
  a14 = a11;  /* 0047 */
  a15 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 0049: -> "mesh_utilities.c" */
  a12 = (u32)(RODATA__rodata_esp_mesh_create_mbox_str1_1 + 0x0);  /* 004c: -> "mesh_utilities.c" */
  ST32(a1 + 0x0, a2);  /* 004f */
  __asm__ volatile("" ::: "memory");  /* 0052: memw */
  /* 0055: INDIRECT callx a4 <- mem[a2+0x150]; result unknown */ a2 = 0;
  goto L_008e;  /* 0058: j */
  L_005e: a10 = LD32(a2 + 0x0);  /* 005e */
  if (a10 == 0) goto L_0071;  /* 0060: beqz.n a10, 71 <esp_mesh_free_mbox+0x59> */
  L_0062: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 0062: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0065 */
  a3 = LD32(a3 + 0x60);  /* 0067 */
  /* 006a: INDIRECT callx a3 <- mem[a3+0x60]; result unknown */ a2 = 0;
  a3 = 0;  /* 006d */
  ST32(a2 + 0x0, a3);  /* 006f */
  L_0071: a3 = 0;  /* 0071 */
  a4 = LD8U(a2 + 0x8);  /* 0073 */
  if (((a4 >> a3) & 1) == 0) goto L_008e;  /* 0076: bbc a4, a3, 8e <esp_mesh_free_mbox+0x76> */
  L_0079: a10 = LD32(a2 + 0x4);  /* 0079 */
  if (a10 == a3) goto L_008e;  /* 007b: beq a10, a3, 8e <esp_mesh_free_mbox+0x76> */
  L_007e: a4 = (u32)&g_osi_funcs_p + 0x0;  /* 007e: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 0081 */
  a4 = LD32(a4 + 0x50);  /* 0083 */
  __asm__ volatile("" ::: "memory");  /* 0086: memw */
  /* 0089: INDIRECT callx a4 <- mem[a4+0x50]; result unknown */ a2 = 0;
  ST32(a2 + 0x4, a3);  /* 008c */
  L_008e: a2 = a3;  /* 008e */
  __asm__ volatile("" ::: "memory");  /* 0090: memw */
  return a2;  /* 0093: retw.n */
}


/* io_cfg2str @ mesh_utilities.o 00000008 size 23B bind GLOBAL
 * Calls: none | Data refs: .rodata.vote_done2str.str1.1, .rodata.CSWTCH$71
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 io_cfg2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 000b */
  a9 = 13;  /* 000d */
  a2 = (u32)(RODATA__rodata_vote_done2str_str1_1 + 0x0);  /* 000f: -> "Unknown" */
  if (a9 < a8) goto L_001d;  /* 0012: bltu a9, a8, 1d <io_cfg2str+0x15> */
  L_0015: a2 = (u32)(RODATA__rodata_CSWTCH_71 + 0x0);  /* 0015: l32r -> .rodata.CSWTCH$71 */
  a8 = a8 + (a2 << 2);  /* 0018 */
  a2 = LD32(a8 + 0x0);  /* 001b */
  L_001d: return a2;  /* 001d: retw.n */
}


/* mesh_create_task @ mesh_utilities.o 00000004 size 48B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x90] | Data refs: g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_create_task(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  /* 0004: entry a1, 48 (frame 48 bytes) */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 0007: l32r -> global */
  a15 = a7;  /* 000a */
  a14 = a6;  /* 000c */
  a13 = 0;  /* 000e */
  a12 = a4;  /* 0010 */
  a9 = LD32(a1 + 0x30);  /* 0012 */
  a11 = a3;  /* 0014 */
  a10 = a2;  /* 0016 */
  a2 = 1;  /* 0018 */
  a8 = LD32(a8 + 0x0);  /* 001a */
  ST32(a1 + 0x0, a9);  /* 001c */
  a8 = LD32(a8 + 0x90);  /* 001f */
  __asm__ volatile("" ::: "memory");  /* 0022: memw */
  /* 0025: INDIRECT callx a8 <- mem[a8+0x90]; result unknown */ a2 = 0;
  a10 = a10 + (-1);  /* 0028 */
  a8 = 0;  /* 002a */
  if (a10 == 0) a2 = a8;  /* 002c */
  a2 = -a2;  /* 002f */
  return a2;  /* 0032: retw.n */
}


/* mesh_free @ mesh_utilities.o 00000004 size 20B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0xb0] | Data refs: g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_free(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 0007 */
  if (a2 == 0) goto L_0016;  /* 0009: beqz.n a2, 16 <mesh_free+0x12> */
  L_000b: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 000b: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 000e */
  a8 = LD32(a8 + 0xb0);  /* 0010 */
  /* 0013: INDIRECT callx a8 <- mem[a8+0xb0]; result unknown */ a2 = 0;
  L_0016: return a2;  /* 0016: retw.n */
}


/* mesh_ie_type2str @ mesh_utilities.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.tx_state_id2str.str1.1, .rodata.CSWTCH$59
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_ie_type2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (a2 >> 8) & 0x1;  /* 000b: extui width 1 */
  a2 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 000e: -> "unknown" */
  if (a8 >= 5u) goto L_001c;  /* 0011: bgeui a8, 5, 1c <mesh_ie_type2str+0x14> */
  L_0014: a2 = (u32)(RODATA__rodata_CSWTCH_59 + 0x0);  /* 0014: l32r -> .rodata.CSWTCH$59 */
  a8 = a8 + (a2 << 2);  /* 0017 */
  a2 = LD32(a8 + 0x0);  /* 001a */
  L_001c: return a2;  /* 001c: retw.n */
}


/* mesh_malloc @ mesh_utilities.o 00000008 size 36B bind GLOBAL
 * Calls: memset | indirect[1]: mem[a8+0x16c] | Data refs: g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=2); reloc-direct=1, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_malloc(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&g_osi_funcs_p + 0x0;  /* 000b: l32r -> global */
  a10 = a2;  /* 000e */
  a8 = LD32(a8 + 0x0);  /* 0010 */
  a8 = LD32(a8 + 0x16c);  /* 0012 */
  /* 0015: INDIRECT callx a8 <- mem[a8+0x16c]; result unknown */ a2 = 0;
  a8 = a10;  /* 0018 */
  if (a10 == 0) goto L_0028;  /* 001a: beqz.n a10, 28 <mesh_malloc+0x20> */
  L_001c: a12 = a2;  /* 001c */
  a11 = 0;  /* 001e */
  a8 = (u32)&memset + 0x0;  /* 0020: l32r -> global */
  a2 = memset(a2, a3, a4, a5, a6, a7);  /* 0023: callx a8 (libc, via reloc-expand) */
  a8 = a10;  /* 0026 */
  L_0028: a2 = a8;  /* 0028 */
  return a2;  /* 002a: retw.n */
}


/* mesh_mutex_lock @ mesh_utilities.o 00000004 size 20B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x54] | Data refs: g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_mutex_lock(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 0007 */
  if (a2 == 0) goto L_0016;  /* 0009: beqz.n a2, 16 <mesh_mutex_lock+0x12> */
  L_000b: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 000b: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 000e */
  a8 = LD32(a8 + 0x54);  /* 0010 */
  /* 0013: INDIRECT callx a8 <- mem[a8+0x54]; result unknown */ a2 = 0;
  L_0016: return a2;  /* 0016: retw.n */
}


/* mesh_mutex_unlock @ mesh_utilities.o 00000004 size 20B bind GLOBAL
 * Calls: none | indirect[1]: mem[a8+0x58] | Data refs: g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=0, refs=1); reloc-direct=0, funcdb-attributed=0, unknown-indirect=1 */
u32 mesh_mutex_unlock(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a10 = a2;  /* 0007 */
  if (a2 == 0) goto L_0016;  /* 0009: beqz.n a2, 16 <mesh_mutex_unlock+0x12> */
  L_000b: a8 = (u32)&g_osi_funcs_p + 0x0;  /* 000b: l32r -> global */
  a8 = LD32(a8 + 0x0);  /* 000e */
  a8 = LD32(a8 + 0x58);  /* 0010 */
  /* 0013: INDIRECT callx a8 <- mem[a8+0x58]; result unknown */ a2 = 0;
  L_0016: return a2;  /* 0016: retw.n */
}


/* nwk_event_id2str @ mesh_utilities.o 00000008 size 23B bind GLOBAL
 * Calls: none | Data refs: .rodata.nwk_event_id2str.str1.1, .rodata.CSWTCH$52
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 nwk_event_id2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 000b */
  a9 = 47;  /* 000d */
  a2 = (u32)(RODATA__rodata_nwk_event_id2str_str1_1 + 0x0);  /* 000f: l32r -> .rodata.nwk_event_id2str.str1.1 */
  if (a9 < a8) goto L_001d;  /* 0012: bltu a9, a8, 1d <nwk_event_id2str+0x15> */
  L_0015: a2 = (u32)(RODATA__rodata_CSWTCH_52 + 0x0);  /* 0015: l32r -> .rodata.CSWTCH$52 */
  a8 = a8 + (a2 << 2);  /* 0018 */
  a2 = LD32(a8 + 0x0);  /* 001b */
  L_001d: return a2;  /* 001d: retw.n */
}


/* opt_type2str @ mesh_utilities.o 00000008 size 23B bind GLOBAL
 * Calls: none | Data refs: .rodata.tx_state_id2str.str1.1, .rodata.CSWTCH$73
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 opt_type2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2 + (-1);  /* 000b */
  a9 = 9;  /* 000d */
  a2 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 000f: -> "unknown" */
  if (a9 < a8) goto L_001d;  /* 0012: bltu a9, a8, 1d <opt_type2str+0x15> */
  L_0015: a2 = (u32)(RODATA__rodata_CSWTCH_73 + 0x0);  /* 0015: l32r -> .rodata.CSWTCH$73 */
  a8 = a8 + (a2 << 2);  /* 0018 */
  a2 = LD32(a8 + 0x0);  /* 001b */
  L_001d: return a2;  /* 001d: retw.n */
}


/* reconnect_type2str @ mesh_utilities.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.tx_state_id2str.str1.1, .rodata.CSWTCH$75
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 reconnect_type2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 000b */
  a2 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 000d: -> "unknown" */
  if (a8 >= 3u) goto L_001c;  /* 0010: bgeui a8, 3, 1c <reconnect_type2str+0x14> */
  L_0013: a2 = (u32)(RODATA__rodata_CSWTCH_75 + 0x0);  /* 0013: l32r -> .rodata.CSWTCH$75 */
  a8 = a8 + (a2 << 2);  /* 0016 */
  a2 = LD32(a8 + 0x0);  /* 0019 */
  L_001c: return a2;  /* 001c: retw.n */
}


/* scan_status2str @ mesh_utilities.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.tx_state_id2str.str1.1, .rodata.CSWTCH$61
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 scan_status2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (a2 >> 8) & 0x1;  /* 000b: extui width 1 */
  a2 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 000e: -> "unknown" */
  if (a8 >= 5u) goto L_001c;  /* 0011: bgeui a8, 5, 1c <scan_status2str+0x14> */
  L_0014: a2 = (u32)(RODATA__rodata_CSWTCH_61 + 0x0);  /* 0014: l32r -> .rodata.CSWTCH$61 */
  a8 = a8 + (a2 << 2);  /* 0017 */
  a2 = LD32(a8 + 0x0);  /* 001a */
  L_001c: return a2;  /* 001c: retw.n */
}


/* tx_msg_id2str @ mesh_utilities.o 00000008 size 24B bind GLOBAL
 * Calls: none | Data refs: .rodata.tx_msg_id2str.str1.1, .rodata.CSWTCH$54
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 tx_msg_id2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (a2 >> 8) & 0x1;  /* 000b: extui width 1 */
  a9 = 16;  /* 000e */
  a2 = (u32)(RODATA__rodata_tx_msg_id2str_str1_1 + 0x0);  /* 0010: -> "max" */
  if (a9 < a8) goto L_001e;  /* 0013: bltu a9, a8, 1e <tx_msg_id2str+0x16> */
  L_0016: a2 = (u32)(RODATA__rodata_CSWTCH_54 + 0x0);  /* 0016: l32r -> .rodata.CSWTCH$54 */
  a8 = a8 + (a2 << 2);  /* 0019 */
  a2 = LD32(a8 + 0x0);  /* 001c */
  L_001e: return a2;  /* 001e: retw.n */
}


/* tx_state_id2str @ mesh_utilities.o 00000008 size 23B bind GLOBAL
 * Calls: none | Data refs: .rodata.tx_state_id2str.str1.1, .rodata.CSWTCH$56
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 tx_state_id2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 000b */
  a9 = 9;  /* 000d */
  a2 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 000f: -> "unknown" */
  if (a9 < a8) goto L_001d;  /* 0012: bltu a9, a8, 1d <tx_state_id2str+0x15> */
  L_0015: a2 = (u32)(RODATA__rodata_CSWTCH_56 + 0x0);  /* 0015: l32r -> .rodata.CSWTCH$56 */
  a8 = a8 + (a2 << 2);  /* 0018 */
  a2 = LD32(a8 + 0x0);  /* 001b */
  L_001d: return a2;  /* 001d: retw.n */
}


/* tx_wifi_err2str @ mesh_utilities.o 00000008 size 24B bind GLOBAL
 * Calls: none | Data refs: .rodata.vote_done2str.str1.1, .rodata.CSWTCH$69
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 tx_wifi_err2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8, a9;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2 + (-80);  /* 000b */
  a9 = 16;  /* 000e */
  a2 = (u32)(RODATA__rodata_vote_done2str_str1_1 + 0x0);  /* 0010: -> "Unknown" */
  if (a9 < a8) goto L_001e;  /* 0013: bltu a9, a8, 1e <tx_wifi_err2str+0x16> */
  L_0016: a2 = (u32)(RODATA__rodata_CSWTCH_69 + 0x0);  /* 0016: l32r -> .rodata.CSWTCH$69 */
  a8 = a8 + (a2 << 2);  /* 0019 */
  a2 = LD32(a8 + 0x0);  /* 001c */
  L_001e: return a2;  /* 001e: retw.n */
}


/* txq_opr2str @ mesh_utilities.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.tx_state_id2str.str1.1, .rodata.CSWTCH$67
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 txq_opr2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2;  /* 000b */
  a2 = (u32)(RODATA__rodata_tx_state_id2str_str1_1 + 0x0);  /* 000d: -> "unknown" */
  if (a8 >= 4u) goto L_001c;  /* 0010: bgeui a8, 4, 1c <txq_opr2str+0x14> */
  L_0013: a2 = (u32)(RODATA__rodata_CSWTCH_67 + 0x0);  /* 0013: l32r -> .rodata.CSWTCH$67 */
  a8 = a8 + (a2 << 2);  /* 0016 */
  a2 = LD32(a8 + 0x0);  /* 0019 */
  L_001c: return a2;  /* 001c: retw.n */
}


/* vote_done2str @ mesh_utilities.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.vote_done2str.str1.1, .rodata.CSWTCH$63
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 vote_done2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2 + (-1);  /* 000b */
  a2 = (u32)(RODATA__rodata_vote_done2str_str1_1 + 0x0);  /* 000d: -> "Unknown" */
  if (a8 >= 7u) goto L_001c;  /* 0010: bgeui a8, 7, 1c <vote_done2str+0x14> */
  L_0013: a2 = (u32)(RODATA__rodata_CSWTCH_63 + 0x0);  /* 0013: l32r -> .rodata.CSWTCH$63 */
  a8 = a8 + (a2 << 2);  /* 0016 */
  a2 = LD32(a8 + 0x0);  /* 0019 */
  L_001c: return a2;  /* 001c: retw.n */
}


/* vote_start2str @ mesh_utilities.o 00000008 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.vote_done2str.str1.1, .rodata.CSWTCH$65
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=2); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 vote_start2str(u32 a2) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = a2 + (-1);  /* 000b */
  a2 = (u32)(RODATA__rodata_vote_done2str_str1_1 + 0x0);  /* 000d: -> "Unknown" */
  if (a8 >= 3u) goto L_001c;  /* 0010: bgeui a8, 3, 1c <vote_start2str+0x14> */
  L_0013: a2 = (u32)(RODATA__rodata_CSWTCH_65 + 0x0);  /* 0013: l32r -> .rodata.CSWTCH$65 */
  a8 = a8 + (a2 << 2);  /* 0016 */
  a2 = LD32(a8 + 0x0);  /* 0019 */
  L_001c: return a2;  /* 001c: retw.n */
}


/* wifi_event_id2str @ mesh_utilities.o 00000088 size 224B bind GLOBAL
 * Calls: sprintf | Data refs: .rodata.wifi_event_id2str, .rodata.wifi_event_id2str.str1.1, .bss.strid$0
 * Fidelity: low - jump-table switch present; cases not recovered
 * Edges: funcdb-v3 (calls=1, refs=4); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 wifi_event_id2str(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0088: entry a1, 32 (frame 32 bytes) */
  a3 = 68;  /* 008b */
  if (a3 >= a2) goto L_0093;  /* 008d: bgeu a3, a2, 93 <wifi_event_id2str+0xb> */
  L_0090: goto L_014c;  /* 0090: j */
  L_0093: a3 = (u32)(RODATA__rodata_wifi_event_id2str + 0x0);  /* 0093: l32r -> .rodata.wifi_event_id2str */
  a3 = a2 + (a3 << 2);  /* 0096 */
  a3 = LD32(a3 + 0x0);  /* 0099 */
  /* 009b: jx a3 — jump table/switch, target computed; see bounds check above */ goto L_ret;
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 009e: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00a1: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00a4: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00a7: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00aa: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00ad: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00b0: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00b3: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00b6: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00b9: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00bc: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00bf: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00c2: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00c5: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00c8: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00cb: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00ce: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00d1: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00d4: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00d7: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00da: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00dd: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00e0: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00e3: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00e6: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00e9: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00ec: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00ef: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00f2: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00f5: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00f8: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 00fb: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 00fe: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0101: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0104: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0107: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 010a: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 010d: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0110: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0113: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0116: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0119: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 011c: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 011f: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0122: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0125: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0128: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 012b: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 012e: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0131: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0134: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0137: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 013a: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 013d: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0140: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0143: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0146: -> "WIFI_EVENT_WIFI_READY" */
  goto L_0166;  /* 0149: j */
  L_014c: a3 = (u32)&LOCAL__bss_strid_0 + 0x0;  /* 014c: l32r -> .bss.strid$0 (same-object static) */
  a12 = a2;  /* 014f */
  a10 = a3;  /* 0151: mov */
  a2 = a3;  /* 0154: mov */
  a11 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0157: -> "WIFI_EVENT_WIFI_READY" */
  a8 = (u32)&sprintf + 0x0;  /* 015a: l32r -> global */
  a2 = sprintf(a2, a3, a4, a5, a6, a7);  /* 015d: callx a8 via reloc-expand */
  goto L_0166;  /* 0160: j */
  a2 = (u32)(RODATA__rodata_wifi_event_id2str_str1_1 + 0x0);  /* 0163: -> "WIFI_EVENT_WIFI_READY" */
  L_0166: return a2;  /* 0166: retw.n */
}

