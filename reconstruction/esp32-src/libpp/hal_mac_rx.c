/* ===== hal_mac_rx.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .iram1.2, .iram1.6, .wifislprxiram.3, .wifislprxiram.4, .wifislprxiram.5
 * Undefined refs (0): 

 * DESCRIPTOR RING HANDLING (observed):
 * - TX: per-queue state words hal_mac_get_txq_state (queue select in a2:
 *   0 -> word bits[10:0], 1 -> bits[26:16], 2 -> low nibble) and
 *   hal_mac_clr_txq_state (mask/OR update of the same words); PMD snapshot
 *   hal_mac_get_txq_pmd splits one status word into bytes [24:31]->[3],
 *   [8:15]->[1], [16:23]->[2] with bit24-gated fixup; PLCP words built in
 *   mac_tx_set_plcp1/plcp2/htsig and pushed with memw barriers.
 * - RX: end-state byte hal_mac_rx_get_end_state, last-descriptor pointer
 *   hal_mac_rx_get_last_dscr, reload flag bit0 hal_mac_rx_{is,set}_dscr_reload,
 *   6-word end-info snapshot hal_mac_rx_get_end_info.

 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

/* pool[hal_mac_rx_get_end_state]: +0x0=0x3FF730A4 */
/* pool[hal_mac_rx_get_last_dscr]: +0x0=0x3FF73090 */
/* pool[hal_mac_rx_is_dscr_reload]: +0x0=0x3FF73084 */
/* pool[hal_mac_rx_set_dscr_reload]: +0x0=0x3FF73084 */
/* pool[hal_mac_rx_get_end_info]: +0x0=0x3FF73D84, +0x4=0x3FF73D88, +0x8=0x3FF730A4, +0xc=0x3FF732F8, +0x10=0x3FF732F4, +0x14=0x3FF732F0 */

/* hal_mac_rx_get_end_state @ hal_mac_rx.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF730A4
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_get_end_state(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x3FF730A4; /* 0007: l32r a2, 0 <hal_mac_rx_get_end_state-0x4> (3ff730a4 <hal_mac_rx_get_end_info+0x3ff7308c>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a2 = REG32(0x3FF730A4); /* 000d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF730A4+0 */
  a2 = (a2 >> 0) & 0xFF; /* 000f: extui a2, a2, 0, 8 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* hal_mac_rx_get_last_dscr @ hal_mac_rx.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73090
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_get_last_dscr(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.3; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x3FF73090; /* 0007: l32r a2, 0 <hal_mac_rx_get_last_dscr-0x4> (3ff73090 <hal_mac_rx_get_end_info+0x3ff73078>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a2 = REG32(0x3FF73090); /* 000d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF73090+0 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* hal_mac_rx_is_dscr_reload @ hal_mac_rx.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_is_dscr_reload(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x3FF73084; /* 0007: l32r a2, 0 <hal_mac_rx_is_dscr_reload-0x4> (3ff73084 <hal_mac_rx_get_end_info+0x3ff7306c>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a2 = REG32(0x3FF73084); /* 000d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a2 = (a2 >> 0) & 0x1; /* 000f: extui a2, a2, 0, 1 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* hal_mac_rx_set_dscr_reload @ hal_mac_rx.o 00000004 size 26B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_set_dscr_reload(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.5; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = 0x3FF73084; /* 0007: l32r a9, 0 <hal_mac_rx_set_dscr_reload-0x4> (3ff73084 <hal_mac_rx_get_end_info+0x3ff7306c>) */ /* MMIO base */ @0x0
  a10 = 0x1; /* 000a: movi.n a10, 1 */
  MEMW(); /* 000c: memw  */
  a8 = REG32(0x3FF73084); /* 000f: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a8 = a8 | a10; /* 0011: or a8, a8, a10 */
  MEMW(); /* 0014: memw  */
  REG32(0x3FF73084) = a8; /* 0017: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 0019: memw  */
  return (int32_t)a2; /* 001c: retw.n  */
}

/* hal_mac_rx_get_end_info @ hal_mac_rx.o 00000018 size 71B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73D84, 0x3FF73D88, 0x3FF730A4, 0x3FF732F8, 0x3FF732F4, 0x3FF732F0
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_get_end_info(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.6; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a8 = 0x3FF73D84; /* 001b: l32r a8, 0 <hal_mac_rx_get_end_info-0x18> (3ff73d84 <hal_mac_rx_get_end_info+0x3ff73d6c>) */ /* MMIO base */ @0x0
  MEMW(); /* 001e: memw  */
  a8 = REG32(0x3FF73D84); /* 0021: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF73D84+0 */
  MEM32(a2 + 0) = a8; /* 0023: s32i.n a8, a2, 0 */
  a8 = 0x3FF73D88; /* 0025: l32r a8, 4 <hal_mac_rx_get_end_info-0x14> (3ff73d88 <hal_mac_rx_get_end_info+0x3ff73d70>) */ /* MMIO base */ @0x4
  MEMW(); /* 0028: memw  */
  a8 = REG32(0x3FF73D88); /* 002b: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF73D88+0 */
  MEM32(a3 + 0) = a8; /* 002d: s32i.n a8, a3, 0 */
  a8 = 0x3FF730A4; /* 002f: l32r a8, 8 <hal_mac_rx_get_end_info-0x10> (3ff730a4 <hal_mac_rx_get_end_info+0x3ff7308c>) */ /* MMIO base */ @0x8
  MEMW(); /* 0032: memw  */
  a8 = REG32(0x3FF730A4); /* 0035: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF730A4+0 */
  a8 = (a8 >> 0) & 0xFF; /* 0037: extui a8, a8, 0, 8 */
  MEM32(a4 + 0) = a8; /* 003a: s32i.n a8, a4, 0 */
  a8 = 0x3FF732F8; /* 003c: l32r a8, c <hal_mac_rx_get_end_info-0xc> (3ff732f8 <hal_mac_rx_get_end_info+0x3ff732e0>) */ /* MMIO base */ @0xC
  MEMW(); /* 003f: memw  */
  a8 = REG32(0x3FF732F8); /* 0042: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF732F8+0 */
  MEM32(a5 + 0) = a8; /* 0044: s32i.n a8, a5, 0 */
  a8 = 0x3FF732F4; /* 0046: l32r a8, 10 <hal_mac_rx_get_end_info-0x8> (3ff732f4 <hal_mac_rx_get_end_info+0x3ff732dc>) */ /* MMIO base */ @0x10
  MEMW(); /* 0049: memw  */
  a8 = REG32(0x3FF732F4); /* 004c: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF732F4+0 */
  MEM32(a6 + 0) = a8; /* 004e: s32i.n a8, a6, 0 */
  a8 = 0x3FF732F0; /* 0050: l32r a8, 14 <hal_mac_rx_get_end_info-0x4> (3ff732f0 <hal_mac_rx_get_end_info+0x3ff732d8>) */ /* MMIO base */ @0x14
  MEMW(); /* 0053: memw  */
  a8 = REG32(0x3FF732F0); /* 0056: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF732F0+0 */
  MEM32(a7 + 0) = a8; /* 0058: s32i.n a8, a7, 0 */
  MEMW(); /* 005a: memw  */
  return (int32_t)a2; /* 005d: retw.n  */
}

