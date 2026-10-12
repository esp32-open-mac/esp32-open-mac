/* ===== hal_mac.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .iram1.12, .iram1.13, .iram1.14, .iram1.15, .text.hal_deinit, .text.hal_disable_mac, .text.hal_enable_mac, .text.hal_init, .text.hal_mac_clr_bssid, .text.hal_mac_disable_low_rate, .text.hal_mac_enable_low_rate, .text.hal_mac_is_txq_enabled, .text.hal_mac_is_txq_valid, .text.hal_mac_rx_disable, .text.hal_mac_rx_enable, .text.hal_mac_rx_set_policy, .text.hal_mac_set_addr, .text.hal_mac_set_bssid, .text.hal_mac_set_csi, .text.hal_mac_set_rxq_policy, .text.hal_mac_set_txq_invalid, .text.hal_mac_tsf_get_time, .text.hal_mac_tsf_reset, .text.hal_mac_tsf_set_time, .text.hal_mac_tx_set_cca, .text.hal_mac_tx_set_ppdu, .text.hal_now, .text.hal_rx_disable_bssid_check, .text.hal_rx_enable_bssid_check, .text.mac_last_rxbuf_deinit, .text.mac_last_rxbuf_init, .text.mac_rxbuf_disable, .text.mac_rxbuf_init, .text.mac_tx_set_duration, .text.mac_tx_set_plcp0, .text.mac_txrx_init, .text.wDev_Mesh_Disable_Tsf, .wifi0iram.17, .wifi0iram.2, .wifi0iram.3, .wifi0iram.4, .wifi0iram.6, .wifi0iram.7, .wifi0iram.8, .wifiextrairam.5, .wifislpiram.9, .wifislprxiram.10, .wifislprxiram.11, .wifislprxiram.16
 * Undefined refs (21): bb_wdt_int_enable, ets_delay_us, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, g_wifi_menuconfig, hal_attenna_init, hal_crypto_init, hal_disable_sta_tsf, hal_mac_rate_autoack_init, mac_tx_set_htsig, mac_tx_set_plcp1, mac_tx_set_plcp2, memcpy, phy_disable_low_rate, phy_enable_low_rate, wDevCtrl, wDev_reset_bcnSendTick, wifi_log
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t mac_tx_set_plcp1();
extern int32_t mac_tx_set_plcp2();
extern int32_t mac_tx_set_htsig();
extern uint32_t g_mesh_is_started; /* g_mesh_is_started */
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern uint32_t g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern uint32_t g_osi_funcs_p; /* g_osi_funcs_p */
extern uint32_t g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern int32_t phy_disable_low_rate();
extern int32_t phy_enable_low_rate();
extern uint32_t wDevCtrl; /* wDevCtrl */
extern uint32_t rodata_hal_mac_rx_set_policy_str1_1; /* .rodata.hal_mac_rx_set_policy.str1.1 */
extern int32_t memcpy();
extern int32_t hal_mac_rate_autoack_init();
extern int32_t hal_crypto_init();
extern int32_t hal_attenna_init();
extern int32_t bb_wdt_int_enable();
extern int32_t hal_disable_sta_tsf();
extern int32_t wDev_reset_bcnSendTick();
extern uint32_t g_wifi_menuconfig; /* g_wifi_menuconfig */
extern int32_t ets_delay_us();
extern uint32_t rodata_wlog_error_18; /* .rodata_wlog_error.18 */
extern int32_t wifi_log();
extern uint32_t rodata_wlog_error_19; /* .rodata_wlog_error.19 */
extern uint32_t rodata_wlog_error_20; /* .rodata_wlog_error.20 */

/* pool[mac_tx_set_plcp0]: +0x0=0x000FFFFF, +0x4=0x002FFFFF, +0x8=0xF8FFFFFF, +0xc=0x00FFFFFF, +0x10=0x07FEE7A4 */
/* pool[mac_tx_set_duration]: +0x0=0x3FF74268 */
/* pool[hal_mac_tx_set_ppdu]: +0x0=0x00000000(mac_tx_set_plcp0), +0x4=0x00000000(mac_tx_set_plcp1), +0x8=0x00000000(mac_tx_set_plcp2), +0xc=0x00000000(mac_tx_set_duration), +0x10=0x00000000(mac_tx_set_htsig) */
/* pool[hal_mac_tx_config_timeout]: +0x0=0x3FF73D1C */
/* pool[hal_mac_tx_config_edca]: +0x0=0x3FF73D1C, +0x4=0xF0FFFFFF, +0x8=0xFFC00FFF */
/* pool[hal_mac_txq_enable]: +0x0=0x07FEE7A4 */
/* pool[hal_mac_txq_disable]: +0x0=0x07FEE7A4, +0x4=0x3FFFFFFF */
/* pool[hal_mac_tx_get_blockack]: +0x0=0x3FF74284, +0x4=0x3FF74278, +0x8=0x3FF74274 */
/* pool[hal_mac_set_txq_invalid]: +0x0=0x07FEE7A4, +0x4=0xBFFFFFFF */
/* pool[hal_mac_is_txq_valid]: +0x0=0x07FEE7A4 */
/* pool[hal_mac_is_txq_enabled]: +0x0=0x07FEE7A4 */
/* pool[hal_random]: +0x0=0x3FF75144 */
/* pool[hal_now]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x3FF73C00, +0x14=0x00000000(g_wifi_mac_time_delta) */
/* pool[hal_mac_tx_set_cca]: +0x0=0x3FF73C58, +0x4=0x3FFFFFFF */
/* pool[hal_mac_disable_low_rate]: +0x1c=0x00000000(phy_disable_low_rate), +0x0=0x3FF7341C, +0x4=0x090B0B0B, +0x8=0x3FF73418, +0xc=0x09090909, +0x10=0x6001C860, +0x14=0xFFFFF7FF, +0x18=0x6001C87C */
/* pool[hal_mac_enable_low_rate]: +0x14=0x00000000(phy_enable_low_rate), +0x4=0x0B0B0B0B, +0x0=0x3FF7341C, +0x8=0x3FF73418, +0xc=0x6001C860, +0x10=0x6001C87C */
/* pool[hal_mac_is_low_rate_enabled]: +0x0=0x6001C860, +0x4=0x6001C87C */
/* pool[mac_rxbuf_init]: +0x4=0x3FFAE000, +0x0=0x3FF7311C, +0x8=0x3FF73124, +0x10=0x400A0000, +0xc=0x3FF73118, +0x14=0x3FF73120, +0x18=0x3FF73080, +0x1c=0x00000000(wDevCtrl), +0x20=0x3FF73088, +0x24=0xDFFFFFFF */
/* pool[hal_disable_mac]: +0x0=0x3FF73C04, +0x4=0x3FF73C40, +0x8=0x3FF73C44, +0xc=0x3FF73C30 */
/* pool[hal_enable_mac]: +0x0=0x3FF73C04, +0x4=0x3FF73C40, +0x8=0x3FF73088 */
/* pool[hal_mac_rx_read_rxdscrlast]: +0x0=0x3FF73090 */
/* pool[hal_mac_rx_read_rxdscrnext]: +0x0=0x3FF7308C */
/* pool[hal_mac_rx_set_base]: +0x0=0x3FF73088 */
/* pool[mac_txrx_init]: +0x4=0x3FF73C6C, +0x8=0x80802000, +0x0=0x3FF730D8, +0xc=0x3FF73C74, +0x10=0x3FF730F8, +0x14=0x3FF730FC, +0x18=0x3FF73100, +0x1c=0x3FF73104, +0x20=0x3FF7310C, +0x24=0x3FF73114, +0x28=0xF00FFFFF, +0x2c=0x3FF73C78, +0x30=0x3FF73D78, +0x34=0x3FF73C54, +0x38=0xFFFF00FF, +0x3c=0x3FF73C1C, +0x40=0x3FF73C20, +0x44=0x3FF73C24, +0x48=0x3FF73CAC, +0x4c=0x3FF73C5C, +0x50=0x7FFF0000, +0x54=0x3FF73C88, +0x58=0xF0FFFFFF, +0x5c=0x3FF73288, +0x60=0x3FF73084, +0x64=0x7FFFFFFF */
/* pool[hal_mac_set_rxq_policy]: +0x0=0x0FFDCC36 */
/* pool[mac_last_rxbuf_init]: +0x0=0x3FF7314C, +0x4=0x00003000, +0x8=0x3FF73158, +0xc=0x3FF73164, +0x10=0x3FF73148, +0x14=0x3FF7309C */
/* pool[mac_last_rxbuf_deinit]: +0x0=0x3FF7314C, +0x4=0x3FF73158, +0x8=0x3FF73164, +0xc=0x3FF73148, +0x10=0xFFFFF7FF, +0x14=0x3FF7309C, +0x18=0xF7FFFFFF */
/* pool[hal_deinit]: +0x0=0x3FF73288, +0x4=0x3FF73C40, +0x8=0xFE17C61F, +0xc=0x3FF73C4C, +0x10=0x3FF73D24 */
/* pool[hal_mac_interrupt_get_event]: +0x0=0x3FF73C48 */
/* pool[hal_mac_interrupt_clr_event]: +0x0=0x3FF73C4C */
/* pool[hal_mac_interrupt_clr_watchdog]: +0x0=0x3FF73C4C */
/* pool[hal_mac_set_addr]: +0x0=0x07FEE608, +0x4=0x0000FFFF */
/* pool[hal_mac_set_bssid]: +0x0=0x3FF73024, +0x4=0xFFFEFFFF, +0x8=0x3FF73000, +0xc=0x3FF73004, +0x10=0x3FF73020, +0x14=0x0000FFFF */
/* pool[hal_mac_rx_set_policy]: +0x0=0x0FFDCC36, +0x4=0x3FF73024, +0x8=0xFFFEFFFF, +0xc=0x00000000(.rodata.hal_mac_rx_set_policy.str1.1), +0x14=0x00000000(memcpy), +0x18=0x00000000(hal_mac_set_bssid), +0x10=0x3FF73064 */
/* pool[hal_init]: +0x0=0x3FF73D24, +0x4=0x3FF73C40, +0x8=0x3FF73C4C, +0x1c=0x00000000(mac_txrx_init), +0xc=0x3FF730D8, +0x10=0xFFFFF6FF, +0x20=0x00000000(hal_mac_rx_set_policy), +0x24=0x00000000(mac_rxbuf_init), +0x28=0x00000000(mac_last_rxbuf_init), +0x2c=0x00000000(hal_mac_rate_autoack_init), +0x30=0x00000000(hal_mac_disable_low_rate), +0x34=0x00000000(hal_crypto_init), +0x38=0x00000000(hal_attenna_init), +0x14=0x01E839E0, +0x3c=0x00000000(bb_wdt_int_enable), +0x18=0x3FF7309C */
/* pool[hal_mac_clr_bssid]: +0x0=0x3FF73024, +0x4=0xFFFEFFFF */
/* pool[hal_mac_tsf_get_time]: +0x0=0x3FF75010, +0xc=0x3FF75054, +0x4=0x3FF75094, +0x8=0x3FF75090 */
/* pool[wDev_Mesh_Disable_Tsf]: +0x0=0x00000000(hal_disable_sta_tsf) */
/* pool[hal_get_tsf_time]: +0x0=0x3FF75010, +0x4=0x3FF75018, +0x8=0x3FF75014, +0xc=0x3FF75058, +0x10=0x3FF75054 */
/* pool[hal_mac_tsf_set_time]: +0x0=0x3FF7509C, +0x4=0x3FF750A0, +0x8=0x3FF75010, +0xc=0x3FF75060, +0x10=0x3FF75064 */
/* pool[hal_mac_tsf_reset]: +0x0=0x3FF75098, +0x4=0x7FFFFFFF, +0x8=0x3FF7509C, +0xc=0x3FF750A0, +0x10=0x3FF75010, +0x14=0x3FF7505C, +0x18=0x3DFFFFFF, +0x30=0x00000000(wDev_reset_bcnSendTick), +0x1c=0x3FF75060, +0x20=0x3FF75064, +0x24=0x3FF75020, +0x28=0x3FF75024, +0x2c=0x3FF75028 */
/* pool[hal_mac_set_csi]: +0x0=0x00000000(g_wifi_menuconfig), +0x4=0x3FF7309C, +0x8=0xFF7FFFFF */
/* pool[hal_mac_init]: +0x0=0x3FF73CB8 */
/* pool[hal_mac_deinit]: +0x0=0x3FF73CB8, +0x4=0x000017FF, +0x1c=0x00000000(ets_delay_us), +0x8=0x00000000(.rodata_wlog_error.18), +0x20=0x00000000(wifi_log), +0xc=0x3FF73C58, +0x10=0xFFFCFFFF, +0x14=0x00000000(.rodata_wlog_error.19), +0x24=0x00000000(wifi_log), +0x18=0x00000000(.rodata_wlog_error.20), +0x28=0x00000000(wifi_log), +0x2c=0x00000000(ets_delay_us) */
/* pool[hal_mac_rx_enable]: +0x0=0x3FF73084 */
/* pool[hal_mac_rx_disable]: +0x0=0x3FF73084, +0x4=0x7FFFFFFF */
/* pool[hal_rx_disable_bssid_check]: +0x0=0x0FFDCC36 */
/* pool[hal_rx_enable_bssid_check]: +0x0=0x0FFDCC36 */

/* mac_tx_set_plcp0 @ hal_mac.o 00000014 size 189B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 68 instr, 9 branches, calls resolved */
int32_t mac_tx_set_plcp0(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_tx_set_plcp0; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a10 = MEM32(a2 + 0); /* 0017: l32i.n a10, a2, 0 */
  a9 = 0xFFFFF; /* 0019: l32r a9, 0 <mac_tx_set_plcp0-0x14> (fffff <mac_txrx_init+0xfff97>) */ @0x0
  a8 = MEM32(a10 + 4); /* 001c: l32i.n a8, a10, 4 */
  a8 = a8 & a9; /* 001e: and a8, a8, a9 */
  a9 = 0x1; /* 0021: movi.n a9, 1 */
  a9 = 0x200000; /* 0023: slli a9, a9, 21 */
  a11 = MEM32(a10 + 44); /* 0026: l32i.n a11, a10, 44 */
  a8 = a8 | a9; /* 0028: or a8, a8, a9 */
  a10 = MEM16(a2 + 20); /* 002b: l16si a10, a2, 20 */
  a9 = 0x2FFFFF; /* 002e: l32r a9, 4 <mac_tx_set_plcp0-0x10> (2fffff <mac_txrx_init+0x2fff97>) */ @0x4
  a8 = a8 & a9; /* 0031: and a8, a8, a9 */
  a9 = MEM32(a11 + 0); /* 0034: l32i.n a9, a11, 0 */
  if (a10 >= 1) goto L_58; /* 0036: bgei a10, 1, 58 <mac_tx_set_plcp0+0x44> */
  a10 = 0xC0; /* 0039: movi a10, 192 */
  a10 = a9 & a10; /* 003c: and a10, a9, a10 */
  if (a10 == 128) goto L_58; /* 003f: beqi a10, 128, 58 <mac_tx_set_plcp0+0x44> */
  a10 = MEM8(a11 + 12); /* 0042: l8ui a10, a11, 12 */
  a11 = 0xF; /* 0045: movi.n a11, 15 */
  a10 = a10 + (-16); /* 0047: addi a10, a10, -16 */
  a10 = (a10 >> 0) & 0xFF; /* 004a: extui a10, a10, 0, 8 */
  if (a11 >= a10) goto L_58; /* 004d: bgeu a11, a10, 58 <mac_tx_set_plcp0+0x44> */
  a10 = 0x1; /* 0050: movi.n a10, 1 */
  a10 = 0x400000; /* 0052: slli a10, a10, 22 */
  a8 = a8 | a10; /* 0055: or a8, a8, a10 */
L_58:;
  a10 = 0x402; /* 0058: movi a10, 0x402 */
  if ((a9 & a10) != 0) goto L_93; /* 005b: bany a9, a10, 93 <mac_tx_set_plcp0+0x7f> */
  a10 = 0x9; /* 005e: movi.n a10, 9 */
  a10 = 0x480000; /* 0060: slli a10, a10, 19 */
  a12 = 0x1; /* 0063: movi.n a12, 1 */
  a10 = a9 & a10; /* 0065: and a10, a9, a10 */
  a12 = 0x400000; /* 0068: slli a12, a12, 22 */
  a11 = 0x1; /* 006b: movi.n a11, 1 */
  if (a10 == a12) goto L_93; /* 006d: beq a10, a12, 93 <mac_tx_set_plcp0+0x7f> */
  a10 = 0xF8FFFFFF; /* 0070: l32r a10, 8 <mac_tx_set_plcp0-0xc> (f8ffffff <mac_txrx_init+0xf8ffff97>) */ @0x8
  a10 = a8 & a10; /* 0073: and a10, a8, a10 */
  if (!((a9 >> 20) & 1)) goto L_84; /* 0076: bbci a9, 20, 84 <mac_tx_set_plcp0+0x70> */
  a8 = 0x3; /* 0079: movi.n a8, 3 */
  a8 = 0x3000000; /* 007b: slli a8, a8, 24 */
  a8 = a10 | a8; /* 007e: or a8, a10, a8 */
  goto L_93; /* 0081: j 93 <mac_tx_set_plcp0+0x7f> */
L_84:;
  if (!((a9 >> 19) & 1)) goto L_8d; /* 0084: bbci a9, 19, 8d <mac_tx_set_plcp0+0x79> */
  a11 = 0x2000000; /* 0087: slli a11, a11, 25 */
  goto L_90; /* 008a: j 90 <mac_tx_set_plcp0+0x7c> */
L_8d:;
  a11 = 0x0; /* 008d: slli a11, a11, 24 */
L_90:;
  a8 = a10 | a11; /* 0090: or a8, a10, a11 */
L_93:;
  a10 = (a9 >> 9) & 0x1; /* 0093: extui a10, a9, 9, 1 */
  a9 = (a9 >> 8) & 0x1; /* 0096: extui a9, a9, 8, 1 */
  a10 = a10 << (4 & 31); /* 0099: slli a10, a10, 4 */
  a9 = a9 << (3 & 31); /* 009c: slli a9, a9, 3 */
  a9 = a10 | a9; /* 009f: or a9, a10, a9 */
  a11 = 0xFFFFFFE7; /* 00a2: movi.n a11, -25 */
  a10 = (a8 >> 24) & 0xFF; /* 00a4: extui a10, a8, 24, 8 */
  a10 = a10 & a11; /* 00a7: and a10, a10, a11 */
  a9 = a9 | a10; /* 00aa: or a9, a9, a10 */
  a10 = 0xFFFFFF; /* 00ad: l32r a10, c <mac_tx_set_plcp0-0x8> (ffffff <mac_txrx_init+0xffff97>) */ @0xC
  a9 = a9 << (24 & 31); /* 00b0: slli a9, a9, 24 */
  a8 = a8 & a10; /* 00b3: and a8, a8, a10 */
  a8 = a8 | a9; /* 00b6: or a8, a8, a9 */
  a9 = MEM8(a2 + 4); /* 00b9: l8ui a9, a2, 4 */
  a2 = 0x7FEE7A4; /* 00bc: l32r a2, 10 <mac_tx_set_plcp0-0x4> (7fee7a4 <mac_txrx_init+0x7fee73c>) */ @0x10
  a2 = a2 - a9; /* 00bf: sub a2, a2, a9 */
  a2 = a2 << (3 & 31); /* 00c2: slli a2, a2, 3 */
  MEMW(); /* 00c5: memw  */
  MEM32(a2 + 0) = a8; /* 00c8: s32i.n a8, a2, 0 */
  a2 = 0x0; /* 00ca: movi.n a2, 0 */
  MEMW(); /* 00cc: memw  */
  return (int32_t)a2; /* 00cf: retw.n  */
}

/* mac_tx_set_duration @ hal_mac.o 00000004 size 59B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74268
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t mac_tx_set_duration(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_tx_set_duration; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = MEM32(a2 + 0); /* 0007: l32i.n a9, a2, 0 */
  a8 = MEM32(a9 + 4); /* 0009: l32i.n a8, a9, 4 */
  a9 = MEM32(a9 + 44); /* 000b: l32i.n a9, a9, 44 */
  a9 = MEM32(a9 + 0); /* 000d: l32i.n a9, a9, 0 */
  a8 = MEM32(a8 + 4); /* 000f: l32i a8, a8, 4 */
  if (!((a9 >> 18) & 1)) goto L_18; /* 0012: bbci a9, 18, 18 <mac_tx_set_duration+0x14> */
  a8 = a8 + (4); /* 0015: addi a8, a8, 4 */
L_18:;
  a10 = MEM16(a8 + 2); /* 0018: l16ui a10, a8, 2 */
  a10 = a10 << (16 & 31); /* 001b: slli a10, a10, 16 */
  a9 = MEM16(a8 + 2); /* 001e: l16ui a9, a8, 2 */
  a9 = a9 | a10; /* 0021: or a9, a9, a10 */
  a8 = MEM8(a2 + 4); /* 0024: l8ui a8, a2, 4 */
  a2 = a8 << (4 & 31); /* 0027: slli a2, a8, 4 */
  a8 = a8 - a2; /* 002a: sub a8, a8, a2 */
  a2 = 0x3FF74268; /* 002d: l32r a2, 0 <mac_tx_set_duration-0x4> (3ff74268 <mac_txrx_init+0x3ff74200>) */ /* MMIO base */ @0x0
  a8 = (a8 << 4) + a2; /* 0030: addx4 a8, a8, a2 */
  a2 = 0x0; /* 0033: movi.n a2, 0 */
  MEMW(); /* 0035: memw  */
  MEM32(a8 + 0) = a9; /* 0038: s32i.n a9, a8, 0 */
  MEMW(); /* 003a: memw  */
  return (int32_t)a2; /* 003d: retw.n  */
}

/* hal_mac_tx_set_ppdu @ hal_mac.o 00000014 size 50B bind GLOBAL
 * Calls: mac_tx_set_duration, mac_tx_set_htsig, mac_tx_set_plcp0, mac_tx_set_plcp1, mac_tx_set_plcp2 | Data refs: mac_tx_set_duration, mac_tx_set_htsig, mac_tx_set_plcp0, mac_tx_set_plcp1, mac_tx_set_plcp2
 *   MMIO: none
 *   funcdb v3: 5 call(s), 5 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_tx_set_ppdu(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_tx_set_ppdu; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a10 = a2 | a2; /* 0017: or a10, a2, a2 */
  a8 = (uint32_t)&mac_tx_set_plcp0; /* 001a: l32r a8, 0 <hal_mac_tx_set_ppdu-0x14> (0 <hal_mac_tx_set_ppdu-0x14>) */ /* literal: GOT slot for mac_tx_set_plcp0 */
  mac_tx_set_plcp0(a2, a3, a4, a5); /* call via literal slot */ /* 001d: callx8 a8 */
  a10 = a2; /* 0020: mov.n a10, a2 */
  a8 = (uint32_t)&mac_tx_set_plcp1; /* 0022: l32r a8, 4 <hal_mac_tx_set_ppdu-0x10> (0 <hal_mac_tx_set_ppdu-0x14>) */ /* literal: GOT slot for mac_tx_set_plcp1 */
  mac_tx_set_plcp1(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
  a10 = a2; /* 0028: mov.n a10, a2 */
  a8 = (uint32_t)&mac_tx_set_plcp2; /* 002a: l32r a8, 8 <hal_mac_tx_set_ppdu-0xc> (0 <hal_mac_tx_set_ppdu-0x14>) */ /* literal: GOT slot for mac_tx_set_plcp2 */
  mac_tx_set_plcp2(a2, a3, a4, a5); /* call via literal slot */ /* 002d: callx8 a8 */
  a10 = a2; /* 0030: mov.n a10, a2 */
  a8 = (uint32_t)&mac_tx_set_duration; /* 0032: l32r a8, c <hal_mac_tx_set_ppdu-0x8> (0 <hal_mac_tx_set_ppdu-0x14>) */ /* literal: GOT slot for mac_tx_set_duration */
  mac_tx_set_duration(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  a11 = a3; /* 0038: mov.n a11, a3 */
  a10 = a2; /* 003a: mov.n a10, a2 */
  a8 = (uint32_t)&mac_tx_set_htsig; /* 003c: l32r a8, 10 <hal_mac_tx_set_ppdu-0x4> (0 <hal_mac_tx_set_ppdu-0x14>) */ /* literal: GOT slot for mac_tx_set_htsig */
  mac_tx_set_htsig(a2, a3, a4, a5); /* call via literal slot */ /* 003f: callx8 a8 */
  a2 = 0x0; /* 0042: movi.n a2, 0 */
  return (int32_t)a2; /* 0044: retw.n  */
}

/* hal_mac_tx_config_timeout @ hal_mac.o 00000004 size 46B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73D1C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_tx_config_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM8(a2 + 4); /* 0007: l8ui a8, a2, 4 */
  a10 = 0xFFFFFFFF; /* 000a: movi.n a10, -1 */
  a8 = a8 << (3 & 31); /* 000c: slli a8, a8, 3 */
  a10 = 0xFFFFF000; /* 000f: slli a10, a10, 12 */
  a3 = (a3 >> 0) & 0xFFF; /* 0012: extui a3, a3, 0, 12 */
  a9 = 0x3FF73D1C; /* 0015: l32r a9, 0 <hal_mac_tx_config_timeout-0x4> (3ff73d1c <mac_txrx_init+0x3ff73cb4>) */ /* MMIO base */ @0x0
  a2 = 0x0; /* 0018: movi.n a2, 0 */
  a9 = a9 - a8; /* 001a: sub a9, a9, a8 */
  MEMW(); /* 001d: memw  */
  a8 = MEM32(a9 + 0); /* 0020: l32i.n a8, a9, 0 */
  a8 = a8 & a10; /* 0022: and a8, a8, a10 */
  a8 = a8 | a3; /* 0025: or a8, a8, a3 */
  MEMW(); /* 0028: memw  */
  MEM32(a9 + 0) = a8; /* 002b: s32i.n a8, a9, 0 */
  MEMW(); /* 002d: memw  */
  return (int32_t)a2; /* 0030: retw.n  */
}

/* hal_mac_tx_config_edca @ hal_mac.o 0000000c size 89B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73D1C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_tx_config_edca(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.3; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a8 = MEM8(a2 + 4); /* 000f: l8ui a8, a2, 4 */
  a11 = 0xF; /* 0012: movi.n a11, 15 */
  a8 = a8 << (3 & 31); /* 0014: slli a8, a8, 3 */
  a11 = 0xF000000; /* 0017: slli a11, a11, 24 */
  a9 = 0x3FF73D1C; /* 001a: l32r a9, 0 <hal_mac_tx_config_edca-0xc> (3ff73d1c <mac_txrx_init+0x3ff73cb4>) */ /* MMIO base */ @0x0
  a9 = a9 - a8; /* 001d: sub a9, a9, a8 */
  a8 = MEM8(a2 + 5); /* 0020: l8ui a8, a2, 5 */
  a8 = a8 << (24 & 31); /* 0023: slli a8, a8, 24 */
  a8 = a8 & a11; /* 0026: and a8, a8, a11 */
  MEMW(); /* 0029: memw  */
  a10 = MEM32(a9 + 0); /* 002c: l32i.n a10, a9, 0 */
  a11 = 0xF0FFFFFF; /* 002e: l32r a11, 4 <hal_mac_tx_config_edca-0x8> (f0ffffff <mac_txrx_init+0xf0ffff97>) */ @0x4
  a10 = a10 & a11; /* 0031: and a10, a10, a11 */
  a8 = a8 | a10; /* 0034: or a8, a8, a10 */
  a11 = 0x3FF; /* 0037: movi a11, 0x3ff */
  MEMW(); /* 003a: memw  */
  MEM32(a9 + 0) = a8; /* 003d: s32i.n a8, a9, 0 */
  a11 = 0x3FF000; /* 003f: slli a11, a11, 12 */
  a8 = MEM16(a2 + 6); /* 0042: l16ui a8, a2, 6 */
  a8 = a8 << (12 & 31); /* 0045: slli a8, a8, 12 */
  a8 = a8 & a11; /* 0048: and a8, a8, a11 */
  MEMW(); /* 004b: memw  */
  a10 = MEM32(a9 + 0); /* 004e: l32i.n a10, a9, 0 */
  a2 = 0xFFC00FFF; /* 0050: l32r a2, 8 <hal_mac_tx_config_edca-0x4> (ffc00fff <mac_txrx_init+0xffc00f97>) */ @0x8
  a10 = a10 & a2; /* 0053: and a10, a10, a2 */
  a8 = a8 | a10; /* 0056: or a8, a8, a10 */
  a2 = 0x0; /* 0059: movi.n a2, 0 */
  MEMW(); /* 005b: memw  */
  MEM32(a9 + 0) = a8; /* 005e: s32i.n a8, a9, 0 */
  MEMW(); /* 0060: memw  */
  return (int32_t)a2; /* 0063: retw.n  */
}

/* hal_mac_txq_enable @ hal_mac.o 00000004 size 38B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_txq_enable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x7FEE7A4; /* 0007: l32r a8, 0 <hal_mac_txq_enable-0x4> (7fee7a4 <mac_txrx_init+0x7fee73c>) */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a8 = a8 - a2; /* 000d: sub a8, a8, a2 */
  a8 = a8 << (3 & 31); /* 0010: slli a8, a8, 3 */
  a10 = 0xFFFFFFFF; /* 0013: movi.n a10, -1 */
  MEMW(); /* 0015: memw  */
  a9 = MEM32(a8 + 0); /* 0018: l32i.n a9, a8, 0 */
  a10 = 0xC0000000; /* 001a: slli a10, a10, 30 */
  a9 = a9 | a10; /* 001d: or a9, a9, a10 */
  MEMW(); /* 0020: memw  */
  MEM32(a8 + 0) = a9; /* 0023: s32i.n a9, a8, 0 */
  MEMW(); /* 0025: memw  */
  return (int32_t)a2; /* 0028: retw.n  */
}

/* hal_mac_txq_disable @ hal_mac.o 00000008 size 36B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FFFFFFF
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_txq_disable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.5; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = 0x7FEE7A4; /* 000b: l32r a8, 0 <hal_mac_txq_disable-0x8> (7fee7a4 <mac_txrx_init+0x7fee73c>) */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a8 = a8 - a2; /* 0011: sub a8, a8, a2 */
  a8 = a8 << (3 & 31); /* 0014: slli a8, a8, 3 */
  MEMW(); /* 0017: memw  */
  a9 = MEM32(a8 + 0); /* 001a: l32i.n a9, a8, 0 */
  a10 = 0x3FFFFFFF; /* 001c: l32r a10, 4 <hal_mac_txq_disable-0x4> (3fffffff <mac_txrx_init+0x3fffff97>) */ /* MMIO base */ @0x4
  a9 = a9 & a10; /* 001f: and a9, a9, a10 */
  MEMW(); /* 0022: memw  */
  MEM32(a8 + 0) = a9; /* 0025: s32i.n a9, a8, 0 */
  MEMW(); /* 0027: memw  */
  return (int32_t)a2; /* 002a: retw.n  */
}

/* hal_mac_tx_get_blockack @ hal_mac.o 0000000c size 79B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74284, 0x3FF74278, 0x3FF74274
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_tx_get_blockack(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.6; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 000f: extui a2, a2, 0, 8 */
  a8 = a2 << (4 & 31); /* 0012: slli a8, a2, 4 */
  a2 = a2 - a8; /* 0015: sub a2, a2, a8 */
  a8 = 0x3FF74284; /* 0018: l32r a8, 0 <hal_mac_tx_get_blockack-0xc> (3ff74284 <mac_txrx_init+0x3ff7421c>) */ /* MMIO base */ @0x0
  a8 = (a2 << 4) + a8; /* 001b: addx4 a8, a2, a8 */
  MEMW(); /* 001e: memw  */
  a9 = MEM32(a8 + 0); /* 0021: l32i.n a9, a8, 0 */
  a9 = (a9 >> 12) & 0xF; /* 0023: extui a9, a9, 12, 4 */
  MEM8(a3 + 0) = a9; /* 0026: s8i a9, a3, 0 */
  MEMW(); /* 0029: memw  */
  MEMW(); /* 002c: memw  */
  a8 = MEM32(a8 + 0); /* 002f: l32i.n a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFFF; /* 0031: extui a8, a8, 0, 12 */
  MEM16(a3 + 2) = a8; /* 0034: s16i a8, a3, 2 */
  MEMW(); /* 0037: memw  */
  a8 = 0x3FF74278; /* 003a: l32r a8, 4 <hal_mac_tx_get_blockack-0x8> (3ff74278 <mac_txrx_init+0x3ff74210>) */ /* MMIO base */ @0x4
  a8 = (a2 << 4) + a8; /* 003d: addx4 a8, a2, a8 */
  MEMW(); /* 0040: memw  */
  a8 = MEM32(a8 + 0); /* 0043: l32i.n a8, a8, 0 */
  MEM32(a3 + 4) = a8; /* 0045: s32i.n a8, a3, 4 */
  a8 = 0x3FF74274; /* 0047: l32r a8, 8 <hal_mac_tx_get_blockack-0x4> (3ff74274 <mac_txrx_init+0x3ff7420c>) */ /* MMIO base */ @0x8
  a2 = (a2 << 4) + a8; /* 004a: addx4 a2, a2, a8 */
  MEMW(); /* 004d: memw  */
  a2 = MEM32(a2 + 0); /* 0050: l32i.n a2, a2, 0 */
  MEM32(a3 + 8) = a2; /* 0052: s32i.n a2, a3, 8 */
  a2 = 0x0; /* 0054: movi.n a2, 0 */
  MEMW(); /* 0056: memw  */
  return (int32_t)a2; /* 0059: retw.n  */
}

/* hal_mac_set_txq_invalid @ hal_mac.o 00000008 size 36B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_set_txq_invalid(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_set_txq_invalid; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = 0x7FEE7A4; /* 000b: l32r a8, 0 <hal_mac_set_txq_invalid-0x8> (7fee7a4 <mac_txrx_init+0x7fee73c>) */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a8 = a8 - a2; /* 0011: sub a8, a8, a2 */
  a8 = a8 << (3 & 31); /* 0014: slli a8, a8, 3 */
  MEMW(); /* 0017: memw  */
  a9 = MEM32(a8 + 0); /* 001a: l32i.n a9, a8, 0 */
  a10 = 0xBFFFFFFF; /* 001c: l32r a10, 4 <hal_mac_set_txq_invalid-0x4> (bfffffff <mac_txrx_init+0xbfffff97>) */ @0x4
  a9 = a9 & a10; /* 001f: and a9, a9, a10 */
  MEMW(); /* 0022: memw  */
  MEM32(a8 + 0) = a9; /* 0025: s32i.n a9, a8, 0 */
  MEMW(); /* 0027: memw  */
  return (int32_t)a2; /* 002a: retw.n  */
}

/* hal_mac_is_txq_valid @ hal_mac.o 00000004 size 25B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_is_txq_valid(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_is_txq_valid; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x7FEE7A4; /* 0007: l32r a8, 0 <hal_mac_is_txq_valid-0x4> (7fee7a4 <mac_txrx_init+0x7fee73c>) */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a8 = a8 - a2; /* 000d: sub a8, a8, a2 */
  a8 = a8 << (3 & 31); /* 0010: slli a8, a8, 3 */
  MEMW(); /* 0013: memw  */
  a2 = MEM32(a8 + 0); /* 0016: l32i.n a2, a8, 0 */
  a2 = (a2 >> 30) & 0x1; /* 0018: extui a2, a2, 30, 1 */
  return (int32_t)a2; /* 001b: retw.n  */
}

/* hal_mac_is_txq_enabled @ hal_mac.o 00000004 size 25B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_is_txq_enabled(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_is_txq_enabled; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x7FEE7A4; /* 0007: l32r a8, 0 <hal_mac_is_txq_enabled-0x4> (7fee7a4 <mac_txrx_init+0x7fee73c>) */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a8 = a8 - a2; /* 000d: sub a8, a8, a2 */
  a8 = a8 << (3 & 31); /* 0010: slli a8, a8, 3 */
  MEMW(); /* 0013: memw  */
  a2 = MEM32(a8 + 0); /* 0016: l32i.n a2, a8, 0 */
  a2 = (a2 >> 31) & 0x1; /* 0018: extui a2, a2, 31, 1 */
  return (int32_t)a2; /* 001b: retw.n  */
}

/* hal_random @ hal_mac.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF75144
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_random(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.7; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x3FF75144; /* 0007: l32r a2, 0 <hal_random-0x4> (3ff75144 <mac_txrx_init+0x3ff750dc>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a2 = REG32(0x3FF75144); /* 000d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF75144+0 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* hal_now @ hal_mac.o 00000018 size 67B bind GLOBAL
 * Calls: none | Data refs: g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 5 ref(s); disasm: 0 call(s), 5 data ref(s)
 * Fidelity: medium - 26 instr, 4 branches, calls resolved */
int32_t hal_now(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_now; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a8 = (uint32_t)&g_mesh_is_started; /* 001b: l32r a8, 0 <hal_now-0x18> (0 <hal_now-0x18>) */ /* literal @0x0: g_mesh_is_started */
  a8 = MEM8(a8 + 0); /* 001e: l8ui a8, a8, 0 */
  if (a8 == 0) goto L_48; /* 0021: beqz.n a8, 48 <hal_now+0x30> */
  a8 = (uint32_t)&g_mesh_is_root; /* 0023: l32r a8, 4 <hal_now-0x14> (0 <hal_now-0x18>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 0026: memw  */
  a8 = MEM8(a8 + 0); /* 0029: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 002c: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_48; /* 002f: bnez.n a8, 48 <hal_now+0x30> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 0031: l32r a8, 8 <hal_now-0x10> (0 <hal_now-0x18>) */ /* literal @0x8: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 0034: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_48; /* 0036: beqz.n a8, 48 <hal_now+0x30> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0038: l32r a8, c <hal_now-0xc> (0 <hal_now-0x18>) */ /* literal @0xC: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 003b: l32i a8, a8, 0 */
  a10 = MEM32(a8 + 272); /* 003e: l32i a10, a8, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0041: callx8 a10 */ /* indirect */
  goto L_57; /* 0044: j 57 <hal_now+0x3f> */
  /* 0047: .byte 00 */
L_48:;
  a8 = 0x3FF73C00; /* 0048: l32r a8, 10 <hal_now-0x8> (3ff73c00 <mac_txrx_init+0x3ff73b98>) */ /* MMIO base */ @0x10
  MEMW(); /* 004b: memw  */
  a10 = REG32(0x3FF73C00); /* 004e: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 0050: l32r a8, 14 <hal_now-0x4> (0 <hal_now-0x18>) */ /* literal @0x14: g_wifi_mac_time_delta */
  a8 = MEM32(a8 + 0); /* 0053: l32i.n a8, a8, 0 */
  a10 = a10 + a8; /* 0055: add.n a10, a10, a8 */
L_57:;
  a2 = a10; /* 0057: mov.n a2, a10 */
  return (int32_t)a2; /* 0059: retw.n  */
}

/* hal_mac_tx_set_cca @ hal_mac.o 00000008 size 35B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73C58
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FFFFFFF
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_tx_set_cca(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_tx_set_cca; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = 0x3FF73C58; /* 000b: l32r a9, 0 <hal_mac_tx_set_cca-0x8> (3ff73c58 <mac_txrx_init+0x3ff73bf0>) */ /* MMIO base */ @0x0
  a2 = a2 << (30 & 31); /* 000e: slli a2, a2, 30 */
  MEMW(); /* 0011: memw  */
  a8 = REG32(0x3FF73C58); /* 0014: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73C58+0 */
  a10 = 0x3FFFFFFF; /* 0016: l32r a10, 4 <hal_mac_tx_set_cca-0x4> (3fffffff <mac_txrx_init+0x3fffff97>) */ /* MMIO base */ @0x4
  a8 = a8 & a10; /* 0019: and a8, a8, a10 */
  a8 = a8 | a2; /* 001c: or a8, a8, a2 */
  a2 = 0x0; /* 001f: movi.n a2, 0 */
  MEMW(); /* 0021: memw  */
  REG32(0x3FF73C58) = a8; /* 0024: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73C58+0 */
  MEMW(); /* 0026: memw  */
  return (int32_t)a2; /* 0029: retw.n  */
}

/* hal_mac_disable_low_rate @ hal_mac.o 00000020 size 87B bind GLOBAL
 * Calls: phy_disable_low_rate | Data refs: phy_disable_low_rate
 *   MMIO: 0x3FF7341C, 0x3FF73418, 0x6001C860, 0x6001C87C
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_disable_low_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_disable_low_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a8 = (uint32_t)&phy_disable_low_rate; /* 0023: l32r a8, 1c <hal_mac_disable_low_rate-0x4> (0 <hal_mac_disable_low_rate-0x20>) */ /* literal: GOT slot for phy_disable_low_rate */
  phy_disable_low_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0026: callx8 a8 */
  a8 = 0x3FF7341C; /* 0029: l32r a8, 0 <hal_mac_disable_low_rate-0x20> (3ff7341c <mac_txrx_init+0x3ff733b4>) */ /* MMIO base */ @0x0
  a10 = 0xFFFFFBFF; /* 002c: movi a10, 0xfffffbff */
  a9 = 0x90B0B0B; /* 002f: l32r a9, 4 <hal_mac_disable_low_rate-0x1c> (90b0b0b <mac_txrx_init+0x90b0aa3>) */ @0x4
  MEMW(); /* 0032: memw  */
  REG32(0x3FF7341C) = a9; /* 0035: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF7341C+0 */
  a8 = 0x3FF73418; /* 0037: l32r a8, 8 <hal_mac_disable_low_rate-0x18> (3ff73418 <mac_txrx_init+0x3ff733b0>) */ /* MMIO base */ @0x8
  a9 = 0x9090909; /* 003a: l32r a9, c <hal_mac_disable_low_rate-0x14> (9090909 <mac_txrx_init+0x90908a1>) */ @0xC
  MEMW(); /* 003d: memw  */
  REG32(0x3FF73418) = a9; /* 0040: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73418+0 */
  a8 = 0x6001C860; /* 0042: l32r a8, 10 <hal_mac_disable_low_rate-0x10> (6001c860 <mac_txrx_init+0x6001c7f8>) */ /* MMIO base */ @0x10
  MEMW(); /* 0045: memw  */
  a9 = REG32(0x6001C860); /* 0048: l32i.n a9, a8, 0 */ /* MMIO read: base 0x6001C860+0 */
  a9 = a9 & a10; /* 004a: and a9, a9, a10 */
  MEMW(); /* 004d: memw  */
  REG32(0x6001C860) = a9; /* 0050: s32i.n a9, a8, 0 */ /* MMIO write: base 0x6001C860+0 */
  MEMW(); /* 0052: memw  */
  a9 = REG32(0x6001C860); /* 0055: l32i.n a9, a8, 0 */ /* MMIO read: base 0x6001C860+0 */
  a10 = 0xFFFFF7FF; /* 0057: l32r a10, 14 <hal_mac_disable_low_rate-0xc> (fffff7ff <mac_txrx_init+0xfffff797>) */ @0x14
  a9 = a9 & a10; /* 005a: and a9, a9, a10 */
  MEMW(); /* 005d: memw  */
  REG32(0x6001C860) = a9; /* 0060: s32i.n a9, a8, 0 */ /* MMIO write: base 0x6001C860+0 */
  a9 = 0x6001C87C; /* 0062: l32r a9, 18 <hal_mac_disable_low_rate-0x8> (6001c87c <mac_txrx_init+0x6001c814>) */ /* MMIO base */ @0x18
  MEMW(); /* 0065: memw  */
  a8 = REG32(0x6001C87C); /* 0068: l32i.n a8, a9, 0 */ /* MMIO read: base 0x6001C87C+0 */
  a8 = a8 & a10; /* 006a: and a8, a8, a10 */
  MEMW(); /* 006d: memw  */
  REG32(0x6001C87C) = a8; /* 0070: s32i.n a8, a9, 0 */ /* MMIO write: base 0x6001C87C+0 */
  MEMW(); /* 0072: memw  */
  return (int32_t)a2; /* 0075: retw.n  */
}

/* hal_mac_enable_low_rate @ hal_mac.o 00000018 size 86B bind GLOBAL
 * Calls: phy_enable_low_rate | Data refs: phy_enable_low_rate
 *   MMIO: 0x3FF7341C, 0x3FF73418, 0x6001C860, 0x6001C87C
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_enable_low_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_enable_low_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a8 = (uint32_t)&phy_enable_low_rate; /* 001b: l32r a8, 14 <hal_mac_enable_low_rate-0x4> (0 <hal_mac_enable_low_rate-0x18>) */ /* literal: GOT slot for phy_enable_low_rate */
  phy_enable_low_rate(a2, a3, a4, a5); /* call via literal slot */ /* 001e: callx8 a8 */
  a8 = 0xB0B0B0B; /* 0021: l32r a8, 4 <hal_mac_enable_low_rate-0x14> (b0b0b0b <mac_txrx_init+0xb0b0aa3>) */ @0x4
  a10 = 0x400; /* 0024: movi a10, 0x400 */
  a9 = 0x3FF7341C; /* 0027: l32r a9, 0 <hal_mac_enable_low_rate-0x18> (3ff7341c <mac_txrx_init+0x3ff733b4>) */ /* MMIO base */ @0x0
  MEMW(); /* 002a: memw  */
  REG32(0x3FF7341C) = a8; /* 002d: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF7341C+0 */
  a9 = 0x3FF73418; /* 002f: l32r a9, 8 <hal_mac_enable_low_rate-0x10> (3ff73418 <mac_txrx_init+0x3ff733b0>) */ /* MMIO base */ @0x8
  MEMW(); /* 0032: memw  */
  REG32(0x3FF73418) = a8; /* 0035: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73418+0 */
  a9 = 0x6001C860; /* 0037: l32r a9, c <hal_mac_enable_low_rate-0xc> (6001c860 <mac_txrx_init+0x6001c7f8>) */ /* MMIO base */ @0xC
  MEMW(); /* 003a: memw  */
  a8 = REG32(0x6001C860); /* 003d: l32i.n a8, a9, 0 */ /* MMIO read: base 0x6001C860+0 */
  a8 = a8 | a10; /* 003f: or a8, a8, a10 */
  MEMW(); /* 0042: memw  */
  REG32(0x6001C860) = a8; /* 0045: s32i.n a8, a9, 0 */ /* MMIO write: base 0x6001C860+0 */
  a8 = 0x1; /* 0047: movi.n a8, 1 */
  a8 = 0x800; /* 0049: slli a8, a8, 11 */
  MEMW(); /* 004c: memw  */
  a10 = REG32(0x6001C860); /* 004f: l32i.n a10, a9, 0 */ /* MMIO read: base 0x6001C860+0 */
  a10 = a10 | a8; /* 0051: or a10, a10, a8 */
  MEMW(); /* 0054: memw  */
  REG32(0x6001C860) = a10; /* 0057: s32i.n a10, a9, 0 */ /* MMIO write: base 0x6001C860+0 */
  a10 = 0x6001C87C; /* 0059: l32r a10, 10 <hal_mac_enable_low_rate-0x8> (6001c87c <mac_txrx_init+0x6001c814>) */ /* MMIO base */ @0x10
  MEMW(); /* 005c: memw  */
  a9 = REG32(0x6001C87C); /* 005f: l32i.n a9, a10, 0 */ /* MMIO read: base 0x6001C87C+0 */
  a8 = a9 | a8; /* 0061: or a8, a9, a8 */
  MEMW(); /* 0064: memw  */
  REG32(0x6001C87C) = a8; /* 0067: s32i.n a8, a10, 0 */ /* MMIO write: base 0x6001C87C+0 */
  MEMW(); /* 0069: memw  */
  return (int32_t)a2; /* 006c: retw.n  */
}

/* hal_mac_is_low_rate_enabled @ hal_mac.o 00000008 size 38B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x6001C860, 0x6001C87C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_is_low_rate_enabled(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.8; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = 0x6001C860; /* 000b: l32r a2, 0 <hal_mac_is_low_rate_enabled-0x8> (6001c860 <mac_txrx_init+0x6001c7f8>) */ /* MMIO base */ @0x0
  a8 = 0x3; /* 000e: movi.n a8, 3 */
  a8 = 0xC00; /* 0010: slli a8, a8, 10 */
  MEMW(); /* 0013: memw  */
  a9 = REG32(0x6001C860); /* 0016: l32i.n a9, a2, 0 */ /* MMIO read: base 0x6001C860+0 */
  a2 = 0x0; /* 0018: movi.n a2, 0 */
  a9 = a9 & a8; /* 001a: and a9, a9, a8 */
  if (a9 != a8) goto L_2c; /* 001d: bne a9, a8, 2c <hal_mac_is_low_rate_enabled+0x24> */
  a2 = 0x6001C87C; /* 0020: l32r a2, 4 <hal_mac_is_low_rate_enabled-0x4> (6001c87c <mac_txrx_init+0x6001c814>) */ /* MMIO base */ @0x4
  MEMW(); /* 0023: memw  */
  a2 = REG32(0x6001C87C); /* 0026: l32i a2, a2, 0 */ /* MMIO read: base 0x6001C87C+0 */
  a2 = (a2 >> 11) & 0x1; /* 0029: extui a2, a2, 11, 1 */
L_2c:;
  return (int32_t)a2; /* 002c: retw.n  */
}

/* mac_rxbuf_init @ hal_mac.o 00000028 size 94B bind GLOBAL
 * Calls: none | Data refs: wDevCtrl
 *   MMIO: 0x3FF7311C, 0x3FF73124, 0x3FF73118, 0x3FF73120, 0x3FF73080, 0x3FF73088
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FFAE000, 0x400A0000
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t mac_rxbuf_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_rxbuf_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_28:;
  /* 0028: entry a1, 32 */
  a8 = 0x3FFAE000; /* 002b: l32r a8, 4 <mac_rxbuf_init-0x24> (3ffae000 <mac_txrx_init+0x3ffadf98>) */ /* MMIO base */ @0x4
  a10 = 0xFFFFFF00; /* 002e: movi a10, 0xffffff00 */
  a9 = 0x3FF7311C; /* 0031: l32r a9, 0 <mac_rxbuf_init-0x28> (3ff7311c <mac_txrx_init+0x3ff730b4>) */ /* MMIO base */ @0x0
  MEMW(); /* 0034: memw  */
  REG32(0x3FF7311C) = a8; /* 0037: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF7311C+0 */
  a9 = 0x3FF73124; /* 0039: l32r a9, 8 <mac_rxbuf_init-0x20> (3ff73124 <mac_txrx_init+0x3ff730bc>) */ /* MMIO base */ @0x8
  MEMW(); /* 003c: memw  */
  REG32(0x3FF73124) = a8; /* 003f: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73124+0 */
  a8 = 0x400A0000; /* 0041: l32r a8, 10 <mac_rxbuf_init-0x18> (400a0000 <mac_txrx_init+0x4009ff98>) */ /* MMIO base */ @0x10
  a9 = 0x3FF73118; /* 0044: l32r a9, c <mac_rxbuf_init-0x1c> (3ff73118 <mac_txrx_init+0x3ff730b0>) */ /* MMIO base */ @0xC
  MEMW(); /* 0047: memw  */
  REG32(0x3FF73118) = a8; /* 004a: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73118+0 */
  a9 = 0x3FF73120; /* 004c: l32r a9, 14 <mac_rxbuf_init-0x14> (3ff73120 <mac_txrx_init+0x3ff730b8>) */ /* MMIO base */ @0x14
  MEMW(); /* 004f: memw  */
  REG32(0x3FF73120) = a8; /* 0052: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73120+0 */
  a8 = 0x3FF73080; /* 0054: l32r a8, 18 <mac_rxbuf_init-0x10> (3ff73080 <mac_txrx_init+0x3ff73018>) */ /* MMIO base */ @0x18
  MEMW(); /* 0057: memw  */
  a9 = REG32(0x3FF73080); /* 005a: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73080+0 */
  a9 = a9 & a10; /* 005c: and a9, a9, a10 */
  MEMW(); /* 005f: memw  */
  REG32(0x3FF73080) = a9; /* 0062: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73080+0 */
  a9 = (uint32_t)&wDevCtrl; /* 0064: l32r a9, 1c <mac_rxbuf_init-0xc> (0 <mac_rxbuf_init-0x28>) */ /* literal @0x1C: wDevCtrl */
  a10 = MEM32(a9 + 0); /* 0067: l32i.n a10, a9, 0 */
  a9 = 0x3FF73088; /* 0069: l32r a9, 20 <mac_rxbuf_init-0x8> (3ff73088 <mac_txrx_init+0x3ff73020>) */ /* MMIO base */ @0x20
  MEMW(); /* 006c: memw  */
  REG32(0x3FF73088) = a10; /* 006f: s32i.n a10, a9, 0 */ /* MMIO write: base 0x3FF73088+0 */
  MEMW(); /* 0071: memw  */
  a9 = REG32(0x3FF73080); /* 0074: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73080+0 */
  a10 = 0xDFFFFFFF; /* 0076: l32r a10, 24 <mac_rxbuf_init-0x4> (dfffffff <mac_txrx_init+0xdfffff97>) */ @0x24
  a9 = a9 & a10; /* 0079: and a9, a9, a10 */
  MEMW(); /* 007c: memw  */
  REG32(0x3FF73080) = a9; /* 007f: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73080+0 */
  MEMW(); /* 0081: memw  */
  return (int32_t)a2; /* 0084: retw.n  */
}

/* hal_disable_mac @ hal_mac.o 00000010 size 58B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73C04, 0x3FF73C40, 0x3FF73C44, 0x3FF73C30
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_disable_mac(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_disable_mac; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a9 = 0x3FF73C04; /* 0013: l32r a9, 0 <hal_disable_mac-0x10> (3ff73c04 <mac_txrx_init+0x3ff73b9c>) */ /* MMIO base */ @0x0
  a2 = 0xF0; /* 0016: movi a2, 240 */
  MEMW(); /* 0019: memw  */
  a8 = REG32(0x3FF73C04); /* 001c: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73C04+0 */
  a8 = a8 | a2; /* 001e: or a8, a8, a2 */
  MEMW(); /* 0021: memw  */
  REG32(0x3FF73C04) = a8; /* 0024: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73C04+0 */
  a8 = 0x0; /* 0026: movi.n a8, 0 */
  a9 = 0x3FF73C40; /* 0028: l32r a9, 4 <hal_disable_mac-0xc> (3ff73c40 <mac_txrx_init+0x3ff73bd8>) */ /* MMIO base */ @0x4
  MEMW(); /* 002b: memw  */
  a2 = REG32(0x3FF73C40); /* 002e: l32i.n a2, a9, 0 */ /* MMIO read: base 0x3FF73C40+0 */
  MEMW(); /* 0030: memw  */
  REG32(0x3FF73C40) = a8; /* 0033: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73C40+0 */
  a9 = 0x3FF73C44; /* 0035: l32r a9, 8 <hal_disable_mac-0x8> (3ff73c44 <mac_txrx_init+0x3ff73bdc>) */ /* MMIO base */ @0x8
  MEMW(); /* 0038: memw  */
  REG32(0x3FF73C44) = a8; /* 003b: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73C44+0 */
  a9 = 0x3FF73C30; /* 003d: l32r a9, c <hal_disable_mac-0x4> (3ff73c30 <mac_txrx_init+0x3ff73bc8>) */ /* MMIO base */ @0xC
  MEMW(); /* 0040: memw  */
  REG32(0x3FF73C30) = a8; /* 0043: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73C30+0 */
  MEMW(); /* 0045: memw  */
  return (int32_t)a2; /* 0048: retw.n  */
}

/* hal_enable_mac @ hal_mac.o 0000000c size 43B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73C04, 0x3FF73C40, 0x3FF73088
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_enable_mac(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_enable_mac; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a9 = 0x3FF73C04; /* 000f: l32r a9, 0 <hal_enable_mac-0xc> (3ff73c04 <mac_txrx_init+0x3ff73b9c>) */ /* MMIO base */ @0x0
  a10 = 0xFFFFFF0F; /* 0012: movi a10, -241 */
  MEMW(); /* 0015: memw  */
  a8 = REG32(0x3FF73C04); /* 0018: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73C04+0 */
  a8 = a8 & a10; /* 001a: and a8, a8, a10 */
  MEMW(); /* 001d: memw  */
  REG32(0x3FF73C04) = a8; /* 0020: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73C04+0 */
  a8 = 0x3FF73C40; /* 0022: l32r a8, 4 <hal_enable_mac-0x8> (3ff73c40 <mac_txrx_init+0x3ff73bd8>) */ /* MMIO base */ @0x4
  MEMW(); /* 0025: memw  */
  REG32(0x3FF73C40) = a2; /* 0028: s32i.n a2, a8, 0 */ /* MMIO write: base 0x3FF73C40+0 */
  a8 = 0x3FF73088; /* 002a: l32r a8, 8 <hal_enable_mac-0x4> (3ff73088 <mac_txrx_init+0x3ff73020>) */ /* MMIO base */ @0x8
  MEMW(); /* 002d: memw  */
  REG32(0x3FF73088) = a3; /* 0030: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF73088+0 */
  MEMW(); /* 0032: memw  */
  return (int32_t)a2; /* 0035: retw.n  */
}

/* hal_mac_rx_read_rxdscrlast @ hal_mac.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73090
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_read_rxdscrlast(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.9; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x3FF73090; /* 0007: l32r a2, 0 <hal_mac_rx_read_rxdscrlast-0x4> (3ff73090 <mac_txrx_init+0x3ff73028>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a2 = REG32(0x3FF73090); /* 000d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF73090+0 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* hal_mac_rx_read_rxdscrnext @ hal_mac.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF7308C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_read_rxdscrnext(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.10; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x3FF7308C; /* 0007: l32r a2, 0 <hal_mac_rx_read_rxdscrnext-0x4> (3ff7308c <mac_txrx_init+0x3ff73024>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a2 = REG32(0x3FF7308C); /* 000d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF7308C+0 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* hal_mac_rx_set_base @ hal_mac.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73088
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_set_base(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.11; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x3FF73088; /* 0007: l32r a8, 0 <hal_mac_rx_set_base-0x4> (3ff73088 <mac_txrx_init+0x3ff73020>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  REG32(0x3FF73088) = a2; /* 000d: s32i.n a2, a8, 0 */ /* MMIO write: base 0x3FF73088+0 */
  MEMW(); /* 000f: memw  */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* mac_txrx_init @ hal_mac.o 00000068 size 576B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73C6C, 0x3FF730D8, 0x3FF73C74, 0x3FF730F8, 0x3FF730FC, 0x3FF73100, 0x3FF73104, 0x3FF7310C, 0x3FF73114, 0x3FF73C78, 0x3FF73D78, 0x3FF73C54, 0x3FF73C1C, 0x3FF73C20, 0x3FF73C24, 0x3FF73CAC, 0x3FF73C5C, 0x3FF73C88, 0x3FF73288, 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: low - 217 instr, 1 branch, 0 indirect; hardware loop at +0x99 (loop a9, movi 4, MMIO 0x3FF730D8 table init); trip/stride mapping needed - need loop-trip decode to raise */
int32_t mac_txrx_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_txrx_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_68:;
  /* 0068: entry a1, 32 */
  a8 = 0x3FF73C6C; /* 006b: l32r a8, 4 <mac_txrx_init-0x64> (3ff73c6c <mac_txrx_init+0x3ff73c04>) */ /* MMIO base */ @0x4
  a11 = 0x40; /* 006e: movi.n a11, 64 */
  a12 = 0x20; /* 0070: movi.n a12, 32 */
  MEMW(); /* 0072: memw  */
  a9 = REG32(0x3FF73C6C); /* 0075: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73C6C+0 */
  a10 = 0x80802000; /* 0077: l32r a10, 8 <mac_txrx_init-0x60> (80802000 <mac_txrx_init+0x80801f98>) */ @0x8
  a9 = a9 | a10; /* 007a: or a9, a9, a10 */
  a10 = 0x100; /* 007d: movi a10, 0x100 */
  MEMW(); /* 0080: memw  */
  REG32(0x3FF73C6C) = a9; /* 0083: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73C6C+0 */
  MEMW(); /* 0085: memw  */
  a9 = REG32(0x3FF73C6C); /* 0088: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73C6C+0 */
  a9 = a9 | a10; /* 008a: or a9, a9, a10 */
  MEMW(); /* 008d: memw  */
  REG32(0x3FF73C6C) = a9; /* 0090: s32i a9, a8, 0 */ /* MMIO write: base 0x3FF73C6C+0 */
  a9 = 0x4; /* 0093: movi a9, 4 */
  a8 = 0x3FF730D8; /* 0096: l32r a8, 0 <mac_txrx_init-0x68> (3ff730d8 <mac_txrx_init+0x3ff73070>) */ /* MMIO base */ @0x0
  /* 0099: loop a9, b8 <mac_txrx_init+0x50> */ /* loop a9 times, end L_b8; body shown single-pass */
  MEMW(); /* 009c: memw  */
  a10 = REG32(0x3FF730D8); /* 009f: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF730D8+0 */
  a10 = a10 | a11; /* 00a1: or a10, a10, a11 */
  MEMW(); /* 00a4: memw  */
  REG32(0x3FF730D8) = a10; /* 00a7: s32i.n a10, a8, 0 */ /* MMIO write: base 0x3FF730D8+0 */
  MEMW(); /* 00a9: memw  */
  a10 = REG32(0x3FF730D8); /* 00ac: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF730D8+0 */
  a10 = a10 | a12; /* 00ae: or a10, a10, a12 */
  MEMW(); /* 00b1: memw  */
  REG32(0x3FF730D8) = a10; /* 00b4: s32i.n a10, a8, 0 */ /* MMIO write: base 0x3FF730D8+0 */
  a8 = 0x3FF730DC; /* 00b6: addi.n a8, a8, 4 */
L_b8:;
  a10 = 0x8; /* 00b8: movi.n a10, 8 */
  a13 = 0xFFFFFF0F; /* 00ba: movi a13, -241 */
  a9 = 0x3FF73C74; /* 00bd: l32r a9, c <mac_txrx_init-0x5c> (3ff73c74 <mac_txrx_init+0x3ff73c0c>) */ /* MMIO base */ @0xC
  a14 = 0xF0; /* 00c0: movi a14, 240 */
  a15 = 0x1; /* 00c3: movi.n a15, 1 */
  a15 = 0x40000000; /* 00c5: slli a15, a15, 30 */
  MEMW(); /* 00c8: memw  */
  a8 = REG32(0x3FF73C74); /* 00cb: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73C74+0 */
  a8 = a8 | a10; /* 00cd: or a8, a8, a10 */
  MEMW(); /* 00d0: memw  */
  REG32(0x3FF73C74) = a8; /* 00d3: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73C74+0 */
  a9 = 0x3FF730F8; /* 00d5: l32r a9, 10 <mac_txrx_init-0x58> (3ff730f8 <mac_txrx_init+0x3ff73090>) */ /* MMIO base */ @0x10
  MEMW(); /* 00d8: memw  */
  a8 = REG32(0x3FF730F8); /* 00db: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF730F8+0 */
  a8 = (a8 >> 0) & 0xFFFF; /* 00dd: extui a8, a8, 0, 16 */
  MEMW(); /* 00e0: memw  */
  REG32(0x3FF730F8) = a8; /* 00e3: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF730F8+0 */
  a8 = 0x3FF730FC; /* 00e5: l32r a8, 14 <mac_txrx_init-0x54> (3ff730fc <mac_txrx_init+0x3ff73094>) */ /* MMIO base */ @0x14
  MEMW(); /* 00e8: memw  */
  a10 = REG32(0x3FF730FC); /* 00eb: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF730FC+0 */
  a10 = (a10 >> 0) & 0xFFFF; /* 00ed: extui a10, a10, 0, 16 */
  a12 = 0x3FF73100; /* 00f0: l32r a12, 18 <mac_txrx_init-0x50> (3ff73100 <mac_txrx_init+0x3ff73098>) */ /* MMIO base */ @0x18
  MEMW(); /* 00f3: memw  */
  REG32(0x3FF730FC) = a10; /* 00f6: s32i.n a10, a8, 0 */ /* MMIO write: base 0x3FF730FC+0 */
  MEMW(); /* 00f8: memw  */
  a10 = REG32(0x3FF73100); /* 00fb: l32i.n a10, a12, 0 */ /* MMIO read: base 0x3FF73100+0 */
  a10 = (a10 >> 0) & 0xFFFF; /* 00fd: extui a10, a10, 0, 16 */
  MEMW(); /* 0100: memw  */
  REG32(0x3FF73100) = a10; /* 0103: s32i.n a10, a12, 0 */ /* MMIO write: base 0x3FF73100+0 */
  a12 = 0x3FF73104; /* 0105: l32r a12, 1c <mac_txrx_init-0x4c> (3ff73104 <mac_txrx_init+0x3ff7309c>) */ /* MMIO base */ @0x1C
  MEMW(); /* 0108: memw  */
  a10 = REG32(0x3FF73104); /* 010b: l32i.n a10, a12, 0 */ /* MMIO read: base 0x3FF73104+0 */
  a10 = (a10 >> 0) & 0xFFFF; /* 010d: extui a10, a10, 0, 16 */
  MEMW(); /* 0110: memw  */
  REG32(0x3FF73104) = a10; /* 0113: s32i.n a10, a12, 0 */ /* MMIO write: base 0x3FF73104+0 */
  a10 = 0x1; /* 0115: movi.n a10, 1 */
  a10 = 0x1000000; /* 0117: slli a10, a10, 24 */
  MEMW(); /* 011a: memw  */
  a12 = REG32(0x3FF730F8); /* 011d: l32i.n a12, a9, 0 */ /* MMIO read: base 0x3FF730F8+0 */
  a12 = a12 | a10; /* 011f: or a12, a12, a10 */
  MEMW(); /* 0122: memw  */
  REG32(0x3FF730F8) = a12; /* 0125: s32i.n a12, a9, 0 */ /* MMIO write: base 0x3FF730F8+0 */
  MEMW(); /* 0127: memw  */
  a12 = REG32(0x3FF730FC); /* 012a: l32i.n a12, a8, 0 */ /* MMIO read: base 0x3FF730FC+0 */
  a10 = a12 | a10; /* 012c: or a10, a12, a10 */
  MEMW(); /* 012f: memw  */
  REG32(0x3FF730FC) = a10; /* 0132: s32i.n a10, a8, 0 */ /* MMIO write: base 0x3FF730FC+0 */
  a10 = 0x1; /* 0134: movi.n a10, 1 */
  a10 = 0x4000000; /* 0136: slli a10, a10, 26 */
  MEMW(); /* 0139: memw  */
  a12 = REG32(0x3FF730F8); /* 013c: l32i.n a12, a9, 0 */ /* MMIO read: base 0x3FF730F8+0 */
  a12 = a12 | a10; /* 013e: or a12, a12, a10 */
  MEMW(); /* 0141: memw  */
  REG32(0x3FF730F8) = a12; /* 0144: s32i.n a12, a9, 0 */ /* MMIO write: base 0x3FF730F8+0 */
  MEMW(); /* 0146: memw  */
  a9 = REG32(0x3FF730FC); /* 0149: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730FC+0 */
  a9 = a9 | a10; /* 014b: or a9, a9, a10 */
  MEMW(); /* 014e: memw  */
  REG32(0x3FF730FC) = a9; /* 0151: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730FC+0 */
  a9 = 0x3FF7310C; /* 0153: l32r a9, 20 <mac_txrx_init-0x48> (3ff7310c <mac_txrx_init+0x3ff730a4>) */ /* MMIO base */ @0x20
  MEMW(); /* 0156: memw  */
  a8 = REG32(0x3FF7310C); /* 0159: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF7310C+0 */
  a8 = a8 & a13; /* 015b: and a8, a8, a13 */
  a10 = 0x3FF73114; /* 015e: l32r a10, 24 <mac_txrx_init-0x44> (3ff73114 <mac_txrx_init+0x3ff730ac>) */ /* MMIO base */ @0x24
  MEMW(); /* 0161: memw  */
  REG32(0x3FF7310C) = a8; /* 0164: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF7310C+0 */
  a9 = 0xFFFFFFFF; /* 0166: movi.n a9, -1 */
  a9 = 0x80000000; /* 0168: slli a9, a9, 31 */
  MEMW(); /* 016b: memw  */
  a8 = REG32(0x3FF73114); /* 016e: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73114+0 */
  a8 = a8 | a9; /* 0170: or a8, a8, a9 */
  MEMW(); /* 0173: memw  */
  REG32(0x3FF73114) = a8; /* 0176: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73114+0 */
  MEMW(); /* 0178: memw  */
  a8 = REG32(0x3FF73114); /* 017b: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73114+0 */
  a12 = 0xF00FFFFF; /* 017d: l32r a12, 28 <mac_txrx_init-0x40> (f00fffff <mac_txrx_init+0xf00fff97>) */ @0x28
  a8 = a8 & a12; /* 0180: and a8, a8, a12 */
  a12 = 0x1B; /* 0183: movi.n a12, 27 */
  a12 = 0x1B00000; /* 0185: slli a12, a12, 20 */
  a8 = a8 | a12; /* 0188: or a8, a8, a12 */
  MEMW(); /* 018b: memw  */
  REG32(0x3FF73114) = a8; /* 018e: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73114+0 */
  a12 = 0x3; /* 0190: movi.n a12, 3 */
  a10 = 0x3FF73C78; /* 0192: l32r a10, 2c <mac_txrx_init-0x3c> (3ff73c78 <mac_txrx_init+0x3ff73c10>) */ /* MMIO base */ @0x2C
  MEMW(); /* 0195: memw  */
  a8 = REG32(0x3FF73C78); /* 0198: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73C78+0 */
  a8 = a8 | a12; /* 019a: or a8, a8, a12 */
  a12 = 0xFFFFFF00; /* 019d: movi a12, 0xffffff00 */
  MEMW(); /* 01a0: memw  */
  REG32(0x3FF73C78) = a8; /* 01a3: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73C78+0 */
  a10 = 0x3FF73D78; /* 01a5: l32r a10, 30 <mac_txrx_init-0x38> (3ff73d78 <mac_txrx_init+0x3ff73d10>) */ /* MMIO base */ @0x30
  MEMW(); /* 01a8: memw  */
  a8 = REG32(0x3FF73D78); /* 01ab: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73D78+0 */
  a8 = a8 & a13; /* 01ad: and a8, a8, a13 */
  MEMW(); /* 01b0: memw  */
  REG32(0x3FF73D78) = a8; /* 01b3: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73D78+0 */
  a10 = 0x3FF73C54; /* 01b5: l32r a10, 34 <mac_txrx_init-0x34> (3ff73c54 <mac_txrx_init+0x3ff73bec>) */ /* MMIO base */ @0x34
  MEMW(); /* 01b8: memw  */
  a8 = REG32(0x3FF73C54); /* 01bb: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73C54+0 */
  a8 = a8 & a12; /* 01bd: and a8, a8, a12 */
  a12 = 0x4; /* 01c0: movi.n a12, 4 */
  a8 = a8 | a12; /* 01c2: or a8, a8, a12 */
  MEMW(); /* 01c5: memw  */
  REG32(0x3FF73C54) = a8; /* 01c8: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73C54+0 */
  MEMW(); /* 01ca: memw  */
  a8 = REG32(0x3FF73C54); /* 01cd: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73C54+0 */
  a12 = 0xFFFF00FF; /* 01cf: l32r a12, 38 <mac_txrx_init-0x30> (ffff00ff <mac_txrx_init+0xffff0097>) */ @0x38
  a8 = a8 & a12; /* 01d2: and a8, a8, a12 */
  a12 = 0x400; /* 01d5: movi a12, 0x400 */
  a8 = a8 | a12; /* 01d8: or a8, a8, a12 */
  MEMW(); /* 01db: memw  */
  REG32(0x3FF73C54) = a8; /* 01de: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73C54+0 */
  a10 = 0xFFFFFFFF; /* 01e0: movi.n a10, -1 */
  a10 = 0xFFFFF000; /* 01e2: slli a10, a10, 12 */
  a8 = 0x3FF73C1C; /* 01e5: l32r a8, 3c <mac_txrx_init-0x2c> (3ff73c1c <mac_txrx_init+0x3ff73bb4>) */ /* MMIO base */ @0x3C
  MEMW(); /* 01e8: memw  */
  a12 = REG32(0x3FF73C1C); /* 01eb: l32i.n a12, a8, 0 */ /* MMIO read: base 0x3FF73C1C+0 */
  a12 = a12 & a10; /* 01ed: and a12, a12, a10 */
  a12 = a12 | a14; /* 01f0: or a12, a12, a14 */
  MEMW(); /* 01f3: memw  */
  REG32(0x3FF73C1C) = a12; /* 01f6: s32i.n a12, a8, 0 */ /* MMIO write: base 0x3FF73C1C+0 */
  MEMW(); /* 01f8: memw  */
  a12 = REG32(0x3FF73C1C); /* 01fb: l32i.n a12, a8, 0 */ /* MMIO read: base 0x3FF73C1C+0 */
  a12 = a12 | a9; /* 01fd: or a12, a12, a9 */
  MEMW(); /* 0200: memw  */
  REG32(0x3FF73C1C) = a12; /* 0203: s32i.n a12, a8, 0 */ /* MMIO write: base 0x3FF73C1C+0 */
  MEMW(); /* 0205: memw  */
  a12 = REG32(0x3FF73C1C); /* 0208: l32i.n a12, a8, 0 */ /* MMIO read: base 0x3FF73C1C+0 */
  a12 = a12 | a15; /* 020a: or a12, a12, a15 */
  MEMW(); /* 020d: memw  */
  REG32(0x3FF73C1C) = a12; /* 0210: s32i.n a12, a8, 0 */ /* MMIO write: base 0x3FF73C1C+0 */
  a12 = 0x3FF73C20; /* 0212: l32r a12, 40 <mac_txrx_init-0x28> (3ff73c20 <mac_txrx_init+0x3ff73bb8>) */ /* MMIO base */ @0x40
  MEMW(); /* 0215: memw  */
  a8 = REG32(0x3FF73C20); /* 0218: l32i.n a8, a12, 0 */ /* MMIO read: base 0x3FF73C20+0 */
  a8 = a8 & a10; /* 021a: and a8, a8, a10 */
  a8 = a8 | a14; /* 021d: or a8, a8, a14 */
  MEMW(); /* 0220: memw  */
  REG32(0x3FF73C20) = a8; /* 0223: s32i.n a8, a12, 0 */ /* MMIO write: base 0x3FF73C20+0 */
  a12 = 0x3FF73C24; /* 0225: l32r a12, 44 <mac_txrx_init-0x24> (3ff73c24 <mac_txrx_init+0x3ff73bbc>) */ /* MMIO base */ @0x44
  MEMW(); /* 0228: memw  */
  a8 = REG32(0x3FF73C24); /* 022b: l32i.n a8, a12, 0 */ /* MMIO read: base 0x3FF73C24+0 */
  a8 = a8 & a10; /* 022d: and a8, a8, a10 */
  a8 = a8 | a14; /* 0230: or a8, a8, a14 */
  a10 = 0x3FF73CAC; /* 0233: l32r a10, 48 <mac_txrx_init-0x20> (3ff73cac <mac_txrx_init+0x3ff73c44>) */ /* MMIO base */ @0x48
  MEMW(); /* 0236: memw  */
  REG32(0x3FF73C24) = a8; /* 0239: s32i.n a8, a12, 0 */ /* MMIO write: base 0x3FF73C24+0 */
  MEMW(); /* 023b: memw  */
  a8 = REG32(0x3FF73CAC); /* 023e: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73CAC+0 */
  a8 = a8 & a13; /* 0240: and a8, a8, a13 */
  a8 = a8 | a11; /* 0243: or a8, a8, a11 */
  MEMW(); /* 0246: memw  */
  REG32(0x3FF73CAC) = a8; /* 0249: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73CAC+0 */
  a8 = 0x3FF73C5C; /* 024b: l32r a8, 4c <mac_txrx_init-0x1c> (3ff73c5c <mac_txrx_init+0x3ff73bf4>) */ /* MMIO base */ @0x4C
  a11 = 0x7FFF0000; /* 024e: l32r a11, 50 <mac_txrx_init-0x18> (7fff0000 <mac_txrx_init+0x7ffeff98>) */ @0x50
  MEMW(); /* 0251: memw  */
  a10 = REG32(0x3FF73C5C); /* 0254: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73C5C+0 */
  a10 = a10 | a11; /* 0256: or a10, a10, a11 */
  MEMW(); /* 0259: memw  */
  REG32(0x3FF73C5C) = a10; /* 025c: s32i.n a10, a8, 0 */ /* MMIO write: base 0x3FF73C5C+0 */
  MEMW(); /* 025e: memw  */
  a10 = REG32(0x3FF73C5C); /* 0261: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73C5C+0 */
  a9 = a10 | a9; /* 0263: or a9, a10, a9 */
  MEMW(); /* 0266: memw  */
  REG32(0x3FF73C5C) = a9; /* 0269: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73C5C+0 */
  a9 = 0x3FF73C88; /* 026b: l32r a9, 54 <mac_txrx_init-0x14> (3ff73c88 <mac_txrx_init+0x3ff73c20>) */ /* MMIO base */ @0x54
  a10 = 0xF0FFFFFF; /* 026e: l32r a10, 58 <mac_txrx_init-0x10> (f0ffffff <mac_txrx_init+0xf0ffff97>) */ @0x58
  MEMW(); /* 0271: memw  */
  a8 = REG32(0x3FF73C88); /* 0274: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73C88+0 */
  a8 = a8 & a10; /* 0276: and a8, a8, a10 */
  a10 = 0x2; /* 0279: movi.n a10, 2 */
  MEMW(); /* 027b: memw  */
  REG32(0x3FF73C88) = a8; /* 027e: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73C88+0 */
  a9 = 0x3FF73288; /* 0280: l32r a9, 5c <mac_txrx_init-0xc> (3ff73288 <mac_txrx_init+0x3ff73220>) */ /* MMIO base */ @0x5C
  MEMW(); /* 0283: memw  */
  a8 = REG32(0x3FF73288); /* 0286: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73288+0 */
  a8 = a8 | a10; /* 0288: or a8, a8, a10 */
  MEMW(); /* 028b: memw  */
  REG32(0x3FF73288) = a8; /* 028e: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73288+0 */
  a9 = 0x3FF73084; /* 0290: l32r a9, 60 <mac_txrx_init-0x8> (3ff73084 <mac_txrx_init+0x3ff7301c>) */ /* MMIO base */ @0x60
  a10 = 0x7FFFFFFF; /* 0293: l32r a10, 64 <mac_txrx_init-0x4> (7fffffff <mac_txrx_init+0x7fffff97>) */ @0x64
  MEMW(); /* 0296: memw  */
  a8 = REG32(0x3FF73084); /* 0299: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a8 = a8 & a10; /* 029b: and a8, a8, a10 */
  MEMW(); /* 029e: memw  */
  REG32(0x3FF73084) = a8; /* 02a1: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 02a3: memw  */
  return (int32_t)a2; /* 02a6: retw.n  */
}

/* hal_mac_set_rxq_policy @ hal_mac.o 00000004 size 47B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_set_rxq_policy(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_set_rxq_policy; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0xFFDCC36; /* 0007: l32r a8, 0 <hal_mac_set_rxq_policy-0x4> (ffdcc36 <mac_txrx_init+0xffdcbce>) */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = a2 + a8; /* 000d: add.n a2, a2, a8 */
  a2 = a2 << (2 & 31); /* 000f: slli a2, a2, 2 */
  a3 = (a3 >> 0) & 0xFF; /* 0012: extui a3, a3, 0, 8 */
  MEMW(); /* 0015: memw  */
  a8 = MEM32(a2 + 0); /* 0018: l32i.n a8, a2, 0 */
  if (a3 == 0) goto L_24; /* 001a: beqz.n a3, 24 <hal_mac_set_rxq_policy+0x20> */
  a9 = 0x2; /* 001c: movi.n a9, 2 */
  a8 = a8 | a9; /* 001e: or a8, a8, a9 */
  goto L_29; /* 0021: j 29 <hal_mac_set_rxq_policy+0x25> */
L_24:;
  a9 = 0xFFFFFFFD; /* 0024: movi.n a9, -3 */
  a8 = a8 & a9; /* 0026: and a8, a8, a9 */
L_29:;
  MEMW(); /* 0029: memw  */
  MEM32(a2 + 0) = a8; /* 002c: s32i.n a8, a2, 0 */
  MEMW(); /* 002e: memw  */
  return (int32_t)a2; /* 0031: retw.n  */
}

/* mac_last_rxbuf_init @ hal_mac.o 00000018 size 97B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF7314C, 0x3FF73158, 0x3FF73164, 0x3FF73148, 0x3FF7309C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t mac_last_rxbuf_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_last_rxbuf_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a8 = 0x3FF7314C; /* 001b: l32r a8, 0 <mac_last_rxbuf_init-0x18> (3ff7314c <mac_txrx_init+0x3ff730e4>) */ /* MMIO base */ @0x0
  a10 = 0x1; /* 001e: movi.n a10, 1 */
  a10 = 0x800; /* 0020: slli a10, a10, 11 */
  a9 = 0x3000; /* 0023: l32r a9, 4 <mac_last_rxbuf_init-0x14> (3000 <mac_txrx_init+0x2f98>) */ @0x4
  MEMW(); /* 0026: memw  */
  REG32(0x3FF7314C) = a9; /* 0029: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF7314C+0 */
  a9 = 0x0; /* 002b: movi.n a9, 0 */
  a8 = 0x3FF73158; /* 002d: l32r a8, 8 <mac_last_rxbuf_init-0x10> (3ff73158 <mac_txrx_init+0x3ff730f0>) */ /* MMIO base */ @0x8
  MEMW(); /* 0030: memw  */
  REG32(0x3FF73158) = a9; /* 0033: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73158+0 */
  a9 = 0xC; /* 0035: movi.n a9, 12 */
  a8 = 0x3FF73164; /* 0037: l32r a8, c <mac_last_rxbuf_init-0xc> (3ff73164 <mac_txrx_init+0x3ff730fc>) */ /* MMIO base */ @0xC
  MEMW(); /* 003a: memw  */
  REG32(0x3FF73164) = a9; /* 003d: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73164+0 */
  a8 = 0x3FF73148; /* 003f: l32r a8, 10 <mac_last_rxbuf_init-0x8> (3ff73148 <mac_txrx_init+0x3ff730e0>) */ /* MMIO base */ @0x10
  MEMW(); /* 0042: memw  */
  a9 = REG32(0x3FF73148); /* 0045: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73148+0 */
  a9 = a9 | a10; /* 0047: or a9, a9, a10 */
  a10 = 0x100; /* 004a: movi a10, 0x100 */
  MEMW(); /* 004d: memw  */
  REG32(0x3FF73148) = a9; /* 0050: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73148+0 */
  MEMW(); /* 0052: memw  */
  a9 = REG32(0x3FF73148); /* 0055: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73148+0 */
  a9 = a9 | a10; /* 0057: or a9, a9, a10 */
  a10 = 0x3FF7309C; /* 005a: l32r a10, 14 <mac_last_rxbuf_init-0x4> (3ff7309c <mac_txrx_init+0x3ff73034>) */ /* MMIO base */ @0x14
  MEMW(); /* 005d: memw  */
  REG32(0x3FF73148) = a9; /* 0060: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73148+0 */
  a9 = 0x1; /* 0062: movi.n a9, 1 */
  a9 = 0x8000000; /* 0064: slli a9, a9, 27 */
  MEMW(); /* 0067: memw  */
  a8 = REG32(0x3FF7309C); /* 006a: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF7309C+0 */
  a8 = a8 | a9; /* 006c: or a8, a8, a9 */
  MEMW(); /* 006f: memw  */
  REG32(0x3FF7309C) = a8; /* 0072: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF7309C+0 */
  MEMW(); /* 0074: memw  */
  return (int32_t)a2; /* 0077: retw.n  */
}

/* mac_last_rxbuf_deinit @ hal_mac.o 0000001c size 88B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF7314C, 0x3FF73158, 0x3FF73164, 0x3FF73148, 0x3FF7309C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t mac_last_rxbuf_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_last_rxbuf_deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a9 = 0x3FF7314C; /* 001f: l32r a9, 0 <mac_last_rxbuf_deinit-0x1c> (3ff7314c <mac_txrx_init+0x3ff730e4>) */ /* MMIO base */ @0x0
  a8 = 0x0; /* 0022: movi.n a8, 0 */
  MEMW(); /* 0024: memw  */
  REG32(0x3FF7314C) = a8; /* 0027: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF7314C+0 */
  a9 = 0x3FF73158; /* 0029: l32r a9, 4 <mac_last_rxbuf_deinit-0x18> (3ff73158 <mac_txrx_init+0x3ff730f0>) */ /* MMIO base */ @0x4
  MEMW(); /* 002c: memw  */
  REG32(0x3FF73158) = a8; /* 002f: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73158+0 */
  a9 = 0x3FF73164; /* 0031: l32r a9, 8 <mac_last_rxbuf_deinit-0x14> (3ff73164 <mac_txrx_init+0x3ff730fc>) */ /* MMIO base */ @0x8
  MEMW(); /* 0034: memw  */
  REG32(0x3FF73164) = a8; /* 0037: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73164+0 */
  a8 = 0x3FF73148; /* 0039: l32r a8, c <mac_last_rxbuf_deinit-0x10> (3ff73148 <mac_txrx_init+0x3ff730e0>) */ /* MMIO base */ @0xC
  a10 = 0xFFFFF7FF; /* 003c: l32r a10, 10 <mac_last_rxbuf_deinit-0xc> (fffff7ff <mac_txrx_init+0xfffff797>) */ @0x10
  MEMW(); /* 003f: memw  */
  a9 = REG32(0x3FF73148); /* 0042: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73148+0 */
  a9 = a9 & a10; /* 0044: and a9, a9, a10 */
  a10 = 0xFFFFFEFF; /* 0047: movi a10, 0xfffffeff */
  MEMW(); /* 004a: memw  */
  REG32(0x3FF73148) = a9; /* 004d: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73148+0 */
  MEMW(); /* 004f: memw  */
  a9 = REG32(0x3FF73148); /* 0052: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73148+0 */
  a9 = a9 & a10; /* 0054: and a9, a9, a10 */
  MEMW(); /* 0057: memw  */
  REG32(0x3FF73148) = a9; /* 005a: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73148+0 */
  a9 = 0x3FF7309C; /* 005c: l32r a9, 14 <mac_last_rxbuf_deinit-0x8> (3ff7309c <mac_txrx_init+0x3ff73034>) */ /* MMIO base */ @0x14
  a10 = 0xF7FFFFFF; /* 005f: l32r a10, 18 <mac_last_rxbuf_deinit-0x4> (f7ffffff <mac_txrx_init+0xf7ffff97>) */ @0x18
  MEMW(); /* 0062: memw  */
  a8 = REG32(0x3FF7309C); /* 0065: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF7309C+0 */
  a8 = a8 & a10; /* 0067: and a8, a8, a10 */
  MEMW(); /* 006a: memw  */
  REG32(0x3FF7309C) = a8; /* 006d: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF7309C+0 */
  MEMW(); /* 006f: memw  */
  return (int32_t)a2; /* 0072: retw.n  */
}

/* mac_rxbuf_disable @ hal_mac.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t mac_rxbuf_disable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_rxbuf_disable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* hal_deinit @ hal_mac.o 00000014 size 89B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73288, 0x3FF73C40, 0x3FF73C4C, 0x3FF73D24
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a9 = 0x3FF73288; /* 0017: l32r a9, 0 <hal_deinit-0x14> (3ff73288 <mac_txrx_init+0x3ff73220>) */ /* MMIO base */ @0x0
  a10 = 0x1; /* 001a: movi.n a10, 1 */
  MEMW(); /* 001c: memw  */
  a8 = REG32(0x3FF73288); /* 001f: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73288+0 */
  a8 = a8 | a10; /* 0021: or a8, a8, a10 */
  MEMW(); /* 0024: memw  */
  REG32(0x3FF73288) = a8; /* 0027: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73288+0 */
  a8 = 0x3FF73C40; /* 0029: l32r a8, 4 <hal_deinit-0x10> (3ff73c40 <mac_txrx_init+0x3ff73bd8>) */ /* MMIO base */ @0x4
  a10 = 0xFE17C61F; /* 002c: l32r a10, 8 <hal_deinit-0xc> (fe17c61f <mac_txrx_init+0xfe17c5b7>) */ @0x8
  MEMW(); /* 002f: memw  */
  a9 = REG32(0x3FF73C40); /* 0032: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73C40+0 */
  a9 = a9 & a10; /* 0034: and a9, a9, a10 */
  a10 = 0x2; /* 0037: movi.n a10, 2 */
  MEMW(); /* 0039: memw  */
  REG32(0x3FF73C40) = a9; /* 003c: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73C40+0 */
  a9 = 0x0; /* 003e: movi.n a9, 0 */
  MEMW(); /* 0040: memw  */
  REG32(0x3FF73C40) = a9; /* 0043: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73C40+0 */
  a9 = 0xFFFFFFFF; /* 0045: movi.n a9, -1 */
  a8 = 0x3FF73C4C; /* 0047: l32r a8, c <hal_deinit-0x8> (3ff73c4c <mac_txrx_init+0x3ff73be4>) */ /* MMIO base */ @0xC
  MEMW(); /* 004a: memw  */
  REG32(0x3FF73C4C) = a9; /* 004d: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73C4C+0 */
  a8 = 0x3FF73D24; /* 004f: l32r a8, 10 <hal_deinit-0x4> (3ff73d24 <mac_txrx_init+0x3ff73cbc>) */ /* MMIO base */ @0x10
  MEMW(); /* 0052: memw  */
  a9 = REG32(0x3FF73D24); /* 0055: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73D24+0 */
  a9 = a9 | a10; /* 0057: or a9, a9, a10 */
  MEMW(); /* 005a: memw  */
  REG32(0x3FF73D24) = a9; /* 005d: s32i a9, a8, 0 */ /* MMIO write: base 0x3FF73D24+0 */
L_60:;
  MEMW(); /* 0060: memw  */
  a9 = REG32(0x3FF73D24); /* 0063: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73D24+0 */
  if (!((a9 >> 0) & 1)) goto L_60; /* 0065: bbci a9, 0, 60 <hal_deinit+0x4c> */
  MEMW(); /* 0068: memw  */
  return (int32_t)a2; /* 006b: retw.n  */
}

/* hal_mac_interrupt_get_event @ hal_mac.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73C48
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_interrupt_get_event(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.12; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x3FF73C48; /* 0007: l32r a2, 0 <hal_mac_interrupt_get_event-0x4> (3ff73c48 <mac_txrx_init+0x3ff73be0>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a2 = REG32(0x3FF73C48); /* 000d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF73C48+0 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* hal_mac_interrupt_clr_event @ hal_mac.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73C4C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_interrupt_clr_event(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.13; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x3FF73C4C; /* 0007: l32r a8, 0 <hal_mac_interrupt_clr_event-0x4> (3ff73c4c <mac_txrx_init+0x3ff73be4>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  REG32(0x3FF73C4C) = a2; /* 000d: s32i.n a2, a8, 0 */ /* MMIO write: base 0x3FF73C4C+0 */
  MEMW(); /* 000f: memw  */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* hal_mac_interrupt_clr_watchdog @ hal_mac.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73C4C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_interrupt_clr_watchdog(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.14; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x3FF73C4C; /* 0007: l32r a10, 0 <hal_mac_interrupt_clr_watchdog-0x4> (3ff73c4c <mac_txrx_init+0x3ff73be4>) */ /* MMIO base */ @0x0
  a9 = 0x1; /* 000a: movi.n a9, 1 */
  a9 = 0x800; /* 000c: slli a9, a9, 11 */
  MEMW(); /* 000f: memw  */
  a8 = REG32(0x3FF73C4C); /* 0012: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73C4C+0 */
  a8 = a8 | a9; /* 0014: or a8, a8, a9 */
  MEMW(); /* 0017: memw  */
  REG32(0x3FF73C4C) = a8; /* 001a: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73C4C+0 */
  MEMW(); /* 001c: memw  */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* hal_mac_set_addr @ hal_mac.o 00000008 size 104B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_set_addr(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_set_addr; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = MEM8(a3 + 1); /* 000b: l8ui a8, a3, 1 */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a8 = a8 << (8 & 31); /* 0011: slli a8, a8, 8 */
  a9 = MEM8(a3 + 0); /* 0014: l8ui a9, a3, 0 */
  a8 = a8 | a9; /* 0017: or a8, a8, a9 */
  a9 = MEM8(a3 + 2); /* 001a: l8ui a9, a3, 2 */
  a9 = a9 << (16 & 31); /* 001d: slli a9, a9, 16 */
  a9 = a9 | a8; /* 0020: or a9, a9, a8 */
  a8 = MEM8(a3 + 3); /* 0023: l8ui a8, a3, 3 */
  a8 = a8 << (24 & 31); /* 0026: slli a8, a8, 24 */
  a8 = a8 | a9; /* 0029: or a8, a8, a9 */
  a9 = 0x7FEE608; /* 002c: l32r a9, 0 <hal_mac_set_addr-0x8> (7fee608 <mac_txrx_init+0x7fee5a0>) */ @0x0
  a2 = a2 + a9; /* 002f: add.n a2, a2, a9 */
  a2 = a2 << (3 & 31); /* 0031: slli a2, a2, 3 */
  MEMW(); /* 0034: memw  */
  MEM32(a2 + 0) = a8; /* 0037: s32i.n a8, a2, 0 */
  a8 = MEM8(a3 + 4); /* 0039: l8ui a8, a3, 4 */
  a3 = MEM8(a3 + 5); /* 003c: l8ui a3, a3, 5 */
  a3 = a3 << (8 & 31); /* 003f: slli a3, a3, 8 */
  a3 = a3 | a8; /* 0042: or a3, a3, a8 */
  a8 = 0x1; /* 0045: movi.n a8, 1 */
  MEMW(); /* 0047: memw  */
  MEM32(a2 + 4) = a3; /* 004a: s32i.n a3, a2, 4 */
  a3 = 0xFFFFFFFF; /* 004c: movi.n a3, -1 */
  a8 = 0x10000; /* 004e: slli a8, a8, 16 */
  MEMW(); /* 0051: memw  */
  MEM32(a2 + 32) = a3; /* 0054: s32i.n a3, a2, 32 */
  a3 = 0xFFFF; /* 0056: l32r a3, 4 <hal_mac_set_addr-0x4> (ffff <mac_txrx_init+0xff97>) */ @0x4
  MEMW(); /* 0059: memw  */
  MEM32(a2 + 36) = a3; /* 005c: s32i.n a3, a2, 36 */
  MEMW(); /* 005e: memw  */
  a3 = MEM32(a2 + 36); /* 0061: l32i.n a3, a2, 36 */
  a3 = a3 | a8; /* 0063: or a3, a3, a8 */
  MEMW(); /* 0066: memw  */
  MEM32(a2 + 36) = a3; /* 0069: s32i.n a3, a2, 36 */
  MEMW(); /* 006b: memw  */
  return (int32_t)a2; /* 006e: retw.n  */
}

/* hal_mac_set_bssid @ hal_mac.o 00000018 size 152B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73024, 0x3FF73000, 0x3FF73004, 0x3FF73020
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 55 instr, 0 branches, calls resolved */
int32_t hal_mac_set_bssid(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_set_bssid; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a9 = MEM8(a3 + 1); /* 001b: l8ui a9, a3, 1 */
  a2 = (a2 >> 0) & 0xFF; /* 001e: extui a2, a2, 0, 8 */
  a9 = a9 << (8 & 31); /* 0021: slli a9, a9, 8 */
  a8 = MEM8(a3 + 0); /* 0024: l8ui a8, a3, 0 */
  a9 = a9 | a8; /* 0027: or a9, a9, a8 */
  a8 = MEM8(a3 + 2); /* 002a: l8ui a8, a3, 2 */
  a8 = a8 << (16 & 31); /* 002d: slli a8, a8, 16 */
  a8 = a8 | a9; /* 0030: or a8, a8, a9 */
  a9 = MEM8(a3 + 3); /* 0033: l8ui a9, a3, 3 */
  a9 = a9 << (24 & 31); /* 0036: slli a9, a9, 24 */
  a9 = a9 | a8; /* 0039: or a9, a9, a8 */
  a8 = 0x3FF73024; /* 003c: l32r a8, 0 <hal_mac_set_bssid-0x18> (3ff73024 <mac_txrx_init+0x3ff72fbc>) */ /* MMIO base */ @0x0
  a8 = (a2 << 8) + a8; /* 003f: addx8 a8, a2, a8 */
  MEMW(); /* 0042: memw  */
  a10 = MEM32(a8 + 0); /* 0045: l32i.n a10, a8, 0 */
  a11 = 0xFFFEFFFF; /* 0047: l32r a11, 4 <hal_mac_set_bssid-0x14> (fffeffff <mac_txrx_init+0xfffeff97>) */ @0x4
  a10 = a10 & a11; /* 004a: and a10, a10, a11 */
  a11 = 0xFFFFFFFF; /* 004d: movi.n a11, -1 */
  a11 = 0xFFFF0000; /* 004f: slli a11, a11, 16 */
  MEMW(); /* 0052: memw  */
  MEM32(a8 + 0) = a10; /* 0055: s32i.n a10, a8, 0 */
  a10 = 0x3FF73000; /* 0057: l32r a10, 8 <hal_mac_set_bssid-0x10> (3ff73000 <mac_txrx_init+0x3ff72f98>) */ /* MMIO base */ @0x8
  a10 = (a2 << 8) + a10; /* 005a: addx8 a10, a2, a10 */
  MEMW(); /* 005d: memw  */
  MEM32(a10 + 0) = a9; /* 0060: s32i.n a9, a10, 0 */
  a10 = 0x3FF73004; /* 0062: l32r a10, c <hal_mac_set_bssid-0xc> (3ff73004 <mac_txrx_init+0x3ff72f9c>) */ /* MMIO base */ @0xC
  a10 = (a2 << 8) + a10; /* 0065: addx8 a10, a2, a10 */
  MEMW(); /* 0068: memw  */
  a9 = MEM32(a10 + 0); /* 006b: l32i.n a9, a10, 0 */
  a9 = a9 & a11; /* 006d: and a9, a9, a11 */
  a11 = MEM8(a3 + 4); /* 0070: l8ui a11, a3, 4 */
  a3 = MEM8(a3 + 5); /* 0073: l8ui a3, a3, 5 */
  a3 = a3 << (8 & 31); /* 0076: slli a3, a3, 8 */
  a3 = a3 | a11; /* 0079: or a3, a3, a11 */
  a9 = a9 | a3; /* 007c: or a9, a9, a3 */
  a3 = 0x3FF73020; /* 007f: l32r a3, 10 <hal_mac_set_bssid-0x8> (3ff73020 <mac_txrx_init+0x3ff72fb8>) */ /* MMIO base */ @0x10
  a2 = (a2 << 8) + a3; /* 0082: addx8 a2, a2, a3 */
  a3 = 0xFFFFFFFF; /* 0085: movi.n a3, -1 */
  MEMW(); /* 0087: memw  */
  MEM32(a10 + 0) = a9; /* 008a: s32i.n a9, a10, 0 */
  MEMW(); /* 008c: memw  */
  MEM32(a2 + 0) = a3; /* 008f: s32i.n a3, a2, 0 */
  a3 = 0x1; /* 0091: movi.n a3, 1 */
  a3 = 0x10000; /* 0093: slli a3, a3, 16 */
  a2 = 0xFFFF; /* 0096: l32r a2, 14 <hal_mac_set_bssid-0x4> (ffff <mac_txrx_init+0xff97>) */ @0x14
  MEMW(); /* 0099: memw  */
  MEM32(a8 + 0) = a2; /* 009c: s32i.n a2, a8, 0 */
  MEMW(); /* 009e: memw  */
  a2 = MEM32(a8 + 0); /* 00a1: l32i.n a2, a8, 0 */
  a2 = a2 | a3; /* 00a3: or a2, a2, a3 */
  MEMW(); /* 00a6: memw  */
  MEM32(a8 + 0) = a2; /* 00a9: s32i.n a2, a8, 0 */
  MEMW(); /* 00ab: memw  */
  return (int32_t)a2; /* 00ae: retw.n  */
}

/* hal_mac_rx_set_policy @ hal_mac.o 0000001c size 196B bind GLOBAL
 * Calls: hal_mac_set_bssid, memcpy | Data refs: .rodata.hal_mac_rx_set_policy.str1.1, hal_mac_set_bssid, memcpy
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73024, 0x3FF73064
 *   funcdb v3: 2 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 75 instr, 11 branches, calls resolved */
int32_t hal_mac_rx_set_policy(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_rx_set_policy; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a2 = (a2 >> 0) & 0xFF; /* 001f: extui a2, a2, 0, 8 */
  if (a2 < 3) goto L_28; /* 0022: bltui a2, 3, 28 <hal_mac_rx_set_policy+0xc> */
  goto L_da; /* 0025: j da <hal_mac_rx_set_policy+0xbe> */
L_28:;
  a8 = 0xFFDCC36; /* 0028: l32r a8, 0 <hal_mac_rx_set_policy-0x1c> (ffdcc36 <mac_txrx_init+0xffdcbce>) */ @0x0
  a8 = a2 + a8; /* 002b: add.n a8, a2, a8 */
  a8 = a8 << (2 & 31); /* 002d: slli a8, a8, 2 */
  if (a3 >= 2) goto L_41; /* 0030: bgeui a3, 2, 41 <hal_mac_rx_set_policy+0x25> */
  MEMW(); /* 0033: memw  */
  a3 = MEM32(a8 + 0); /* 0036: l32i.n a3, a8, 0 */
  a9 = 0xFFFFFEEF; /* 0038: movi a9, 0xfffffeef */
  a3 = a3 & a9; /* 003b: and a3, a3, a9 */
  goto L_4c; /* 003e: j 4c <hal_mac_rx_set_policy+0x30> */
L_41:;
  MEMW(); /* 0041: memw  */
  a3 = MEM32(a8 + 0); /* 0044: l32i.n a3, a8, 0 */
  a9 = 0x110; /* 0046: movi a9, 0x110 */
  a3 = a3 | a9; /* 0049: or a3, a3, a9 */
L_4c:;
  MEMW(); /* 004c: memw  */
  MEM32(a8 + 0) = a3; /* 004f: s32i.n a3, a8, 0 */
  a3 = a2 << (3 & 31); /* 0051: slli a3, a2, 3 */
  if (a4 != 0) goto L_71; /* 0054: bnez.n a4, 71 <hal_mac_rx_set_policy+0x55> */
  a2 = 0x3FF73024; /* 0056: l32r a2, 4 <hal_mac_rx_set_policy-0x18> (3ff73024 <mac_txrx_init+0x3ff72fbc>) */ /* MMIO base */ @0x4
  a2 = a3 + a2; /* 0059: add.n a2, a3, a2 */
  MEMW(); /* 005b: memw  */
  a4 = MEM32(a2 + 0); /* 005e: l32i.n a4, a2, 0 */
  a8 = 0xFFFEFFFF; /* 0060: l32r a8, 8 <hal_mac_rx_set_policy-0x14> (fffeffff <mac_txrx_init+0xfffeff97>) */ @0x8
  a4 = a4 & a8; /* 0063: and a4, a4, a8 */
  MEMW(); /* 0066: memw  */
  MEM32(a2 + 0) = a4; /* 0069: s32i.n a4, a2, 0 */
  MEMW(); /* 006b: memw  */
  goto L_a8; /* 006e: j a8 <hal_mac_rx_set_policy+0x8c> */
L_71:;
  if (a4 != 1) goto L_91; /* 0071: bnei a4, 1, 91 <hal_mac_rx_set_policy+0x75> */
  a2 = 0x3FF73024; /* 0074: l32r a2, 4 <hal_mac_rx_set_policy-0x18> (3ff73024 <mac_txrx_init+0x3ff72fbc>) */ /* MMIO base */ @0x4
  a4 = a4 << (16 & 31); /* 0077: slli a4, a4, 16 */
  a2 = a3 + a2; /* 007a: add.n a2, a3, a2 */
  MEMW(); /* 007c: memw  */
  a8 = MEM32(a2 + 0); /* 007f: l32i.n a8, a2, 0 */
  a8 = a8 | a4; /* 0081: or a8, a8, a4 */
  MEMW(); /* 0084: memw  */
  MEM32(a2 + 0) = a8; /* 0087: s32i.n a8, a2, 0 */
  MEMW(); /* 0089: memw  */
  goto L_a8; /* 008c: j a8 <hal_mac_rx_set_policy+0x8c> */
  /* 008f: .byte 00 */
  /* 0090: .byte 00 */
L_91:;
  a11 = (uint32_t)&lit_rodata_hal_mac_rx_set_policy_str1_1; /* 0091: l32r a11, c <hal_mac_rx_set_policy-0x10> (0 <hal_mac_rx_set_policy-0x1c>) */ /* literal @0xC: .rodata.hal_mac_rx_set_policy.str1.1 */
  a12 = 0x6; /* 0094: movi.n a12, 6 */
  a10 = a1; /* 0096: mov.n a10, a1 */
  a8 = (uint32_t)&memcpy; /* 0098: l32r a8, 14 <hal_mac_rx_set_policy-0x8> (0 <hal_mac_rx_set_policy-0x1c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 009b: callx8 a8 */
  a11 = a1; /* 009e: mov.n a11, a1 */
  a10 = a2; /* 00a0: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_set_bssid; /* 00a2: l32r a8, 18 <hal_mac_rx_set_policy-0x4> (0 <hal_mac_rx_set_policy-0x1c>) */ /* literal: GOT slot for hal_mac_set_bssid */
  hal_mac_set_bssid(a2, a3, a4, a5); /* call via literal slot */ /* 00a5: callx8 a8 */
L_a8:;
  a2 = 0x3FF73064; /* 00a8: l32r a2, 10 <hal_mac_rx_set_policy-0xc> (3ff73064 <mac_txrx_init+0x3ff72ffc>) */ /* MMIO base */ @0x10
  a8 = a3 + a2; /* 00ab: add.n a8, a3, a2 */
  MEMW(); /* 00ad: memw  */
  a2 = MEM32(a8 + 0); /* 00b0: l32i.n a2, a8, 0 */
  if (a5 != 0) goto L_c5; /* 00b2: bnez.n a5, c5 <hal_mac_rx_set_policy+0xa9> */
  a3 = 0xFFFEFFFF; /* 00b4: l32r a3, 8 <hal_mac_rx_set_policy-0x14> (fffeffff <mac_txrx_init+0xfffeff97>) */ @0x8
  a2 = a2 & a3; /* 00b7: and a2, a2, a3 */
  MEMW(); /* 00ba: memw  */
  MEM32(a8 + 0) = a2; /* 00bd: s32i.n a2, a8, 0 */
  MEMW(); /* 00bf: memw  */
  goto L_dc; /* 00c2: j dc <hal_mac_rx_set_policy+0xc0> */
L_c5:;
  a3 = 0x1; /* 00c5: movi.n a3, 1 */
  a3 = 0x10000; /* 00c7: slli a3, a3, 16 */
  a2 = a2 | a3; /* 00ca: or a2, a2, a3 */
  MEMW(); /* 00cd: memw  */
  MEM32(a8 + 0) = a2; /* 00d0: s32i.n a2, a8, 0 */
  a5 = 0x0; /* 00d2: movi.n a5, 0 */
  MEMW(); /* 00d4: memw  */
  goto L_dc; /* 00d7: j dc <hal_mac_rx_set_policy+0xc0> */
L_da:;
  a5 = 0xFFFFFFFF; /* 00da: movi.n a5, -1 */
L_dc:;
  a2 = 0xFFFFFFFF; /* 00dc: mov.n a2, a5 */
  return (int32_t)a2; /* 00de: retw.n  */
}

/* hal_init @ hal_mac.o 00000040 size 206B bind GLOBAL
 * Calls: bb_wdt_int_enable, hal_attenna_init, hal_crypto_init, hal_mac_disable_low_rate, hal_mac_rate_autoack_init, hal_mac_rx_set_policy, mac_last_rxbuf_init, mac_rxbuf_init, mac_txrx_init | Data refs: bb_wdt_int_enable, hal_attenna_init, hal_crypto_init, hal_mac_disable_low_rate, hal_mac_rate_autoack_init, hal_mac_rx_set_policy, mac_last_rxbuf_init, mac_rxbuf_init, mac_txrx_init
 *   MMIO: 0x3FF73D24, 0x3FF73C40, 0x3FF73C4C, 0x3FF7309C
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF730D8
 *   funcdb v3: 9 call(s), 9 ref(s); disasm: 9 call(s), 9 data ref(s)
 * Fidelity: medium - 77 instr, 2 branches, calls resolved */
int32_t hal_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_40:;
  /* 0040: entry a1, 32 */
  a2 = 0x3FF73D24; /* 0043: l32r a2, 0 <hal_init-0x40> (3ff73d24 <mac_txrx_init+0x3ff73cbc>) */ /* MMIO base */ @0x0
  a8 = 0x2; /* 0046: movi.n a8, 2 */
  MEMW(); /* 0048: memw  */
  a3 = REG32(0x3FF73D24); /* 004b: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF73D24+0 */
  a3 = a3 | a8; /* 004d: or a3, a3, a8 */
  MEMW(); /* 0050: memw  */
  REG32(0x3FF73D24) = a3; /* 0053: s32i.n a3, a2, 0 */ /* MMIO write: base 0x3FF73D24+0 */
L_55:;
  MEMW(); /* 0055: memw  */
  a3 = REG32(0x3FF73D24); /* 0058: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF73D24+0 */
  if (!((a3 >> 0) & 1)) goto L_55; /* 005a: bbci a3, 0, 55 <hal_init+0x15> */
  a2 = 0x0; /* 005d: movi.n a2, 0 */
  a8 = 0xFFFFFFFF; /* 005f: movi.n a8, -1 */
  a3 = 0x3FF73C40; /* 0061: l32r a3, 4 <hal_init-0x3c> (3ff73c40 <mac_txrx_init+0x3ff73bd8>) */ /* MMIO base */ @0x4
  MEMW(); /* 0064: memw  */
  REG32(0x3FF73C40) = a2; /* 0067: s32i.n a2, a3, 0 */ /* MMIO write: base 0x3FF73C40+0 */
  a3 = 0x3FF73C4C; /* 0069: l32r a3, 8 <hal_init-0x38> (3ff73c4c <mac_txrx_init+0x3ff73be4>) */ /* MMIO base */ @0x8
  MEMW(); /* 006c: memw  */
  REG32(0x3FF73C4C) = a8; /* 006f: s32i.n a8, a3, 0 */ /* MMIO write: base 0x3FF73C4C+0 */
  MEMW(); /* 0071: memw  */
  a8 = (uint32_t)&mac_txrx_init; /* 0074: l32r a8, 1c <hal_init-0x24> (0 <hal_init-0x40>) */ /* literal: GOT slot for mac_txrx_init */
  mac_txrx_init(a2, a3, a4, a5); /* call via literal slot */ /* 0077: callx8 a8 */
  a3 = a2; /* 007a: mov.n a3, a2 */
L_7c:;
  a10 = 0x5; /* 007c: movi.n a10, 5 */
  a13 = a3; /* 007e: mov.n a13, a3 */
  a8 = 0x3FF730D8; /* 0080: l32r a8, c <hal_init-0x34> (3ff730d8 <mac_txrx_init+0x3ff73070>) */ /* MMIO base */ @0xC
  a12 = a3; /* 0083: mov.n a12, a3 */
  a8 = (a2 << 4) + a8; /* 0085: addx4 a8, a2, a8 */
  a11 = a3; /* 0088: mov.n a11, a3 */
  MEMW(); /* 008a: memw  */
  a9 = MEM32(a8 + 0); /* 008d: l32i.n a9, a8, 0 */
  a9 = a9 | a10; /* 008f: or a9, a9, a10 */
  MEMW(); /* 0092: memw  */
  MEM32(a8 + 0) = a9; /* 0095: s32i.n a9, a8, 0 */
  MEMW(); /* 0097: memw  */
  a9 = MEM32(a8 + 0); /* 009a: l32i.n a9, a8, 0 */
  a10 = 0xFFFFF6FF; /* 009c: l32r a10, 10 <hal_init-0x30> (fffff6ff <mac_txrx_init+0xfffff697>) */ @0x10
  a9 = a9 & a10; /* 009f: and a9, a9, a10 */
  a10 = a2; /* 00a2: mov.n a10, a2 */
  a2 = a2 + (1); /* 00a4: addi.n a2, a2, 1 */
  MEMW(); /* 00a6: memw  */
  MEM32(a8 + 0) = a9; /* 00a9: s32i.n a9, a8, 0 */
  MEMW(); /* 00ab: memw  */
  a8 = (uint32_t)&hal_mac_rx_set_policy; /* 00ae: l32r a8, 20 <hal_init-0x20> (0 <hal_init-0x40>) */ /* literal: GOT slot for hal_mac_rx_set_policy */
  hal_mac_rx_set_policy(a2, a3, a4, a5); /* call via literal slot */ /* 00b1: callx8 a8 */
  if (a2 != 4) goto L_7c; /* 00b4: bnei a2, 4, 7c <hal_init+0x3c> */
  a8 = (uint32_t)&mac_rxbuf_init; /* 00b7: l32r a8, 24 <hal_init-0x1c> (0 <hal_init-0x40>) */ /* literal: GOT slot for mac_rxbuf_init */
  mac_rxbuf_init(a2, a3, a4, a5); /* call via literal slot */ /* 00ba: callx8 a8 */
  a8 = (uint32_t)&mac_last_rxbuf_init; /* 00bd: l32r a8, 28 <hal_init-0x18> (0 <hal_init-0x40>) */ /* literal: GOT slot for mac_last_rxbuf_init */
  mac_last_rxbuf_init(a2, a3, a4, a5); /* call via literal slot */ /* 00c0: callx8 a8 */
  a8 = (uint32_t)&hal_mac_rate_autoack_init; /* 00c3: l32r a8, 2c <hal_init-0x14> (0 <hal_init-0x40>) */ /* literal: GOT slot for hal_mac_rate_autoack_init */
  hal_mac_rate_autoack_init(a2, a3, a4, a5); /* call via literal slot */ /* 00c6: callx8 a8 */
  a8 = (uint32_t)&hal_mac_disable_low_rate; /* 00c9: l32r a8, 30 <hal_init-0x10> (0 <hal_init-0x40>) */ /* literal: GOT slot for hal_mac_disable_low_rate */
  hal_mac_disable_low_rate(a2, a3, a4, a5); /* call via literal slot */ /* 00cc: callx8 a8 */
  a8 = (uint32_t)&hal_crypto_init; /* 00cf: l32r a8, 34 <hal_init-0xc> (0 <hal_init-0x40>) */ /* literal: GOT slot for hal_crypto_init */
  hal_crypto_init(a2, a3, a4, a5); /* call via literal slot */ /* 00d2: callx8 a8 */
  a8 = (uint32_t)&hal_attenna_init; /* 00d5: l32r a8, 38 <hal_init-0x8> (0 <hal_init-0x40>) */ /* literal: GOT slot for hal_attenna_init */
  hal_attenna_init(a2, a3, a4, a5); /* call via literal slot */ /* 00d8: callx8 a8 */
  a2 = 0x3FF73C40; /* 00db: l32r a2, 4 <hal_init-0x3c> (3ff73c40 <mac_txrx_init+0x3ff73bd8>) */ /* MMIO base */ @0x4
  a10 = 0x1; /* 00de: movi.n a10, 1 */
  a3 = 0x1E839E0; /* 00e0: l32r a3, 14 <hal_init-0x2c> (1e839e0 <mac_txrx_init+0x1e83978>) */ @0x14
  MEMW(); /* 00e3: memw  */
  REG32(0x3FF73C40) = a3; /* 00e6: s32i.n a3, a2, 0 */ /* MMIO write: base 0x3FF73C40+0 */
  MEMW(); /* 00e8: memw  */
  a8 = (uint32_t)&bb_wdt_int_enable; /* 00eb: l32r a8, 3c <hal_init-0x4> (0 <hal_init-0x40>) */ /* literal: GOT slot for bb_wdt_int_enable */
  bb_wdt_int_enable(a2, a3, a4, a5); /* call via literal slot */ /* 00ee: callx8 a8 */
  a8 = 0xFFFFFF00; /* 00f1: movi a8, 0xffffff00 */
  a3 = 0x3FF7309C; /* 00f4: l32r a3, 18 <hal_init-0x28> (3ff7309c <mac_txrx_init+0x3ff73034>) */ /* MMIO base */ @0x18
  MEMW(); /* 00f7: memw  */
  a2 = REG32(0x3FF7309C); /* 00fa: l32i.n a2, a3, 0 */ /* MMIO read: base 0x3FF7309C+0 */
  a2 = a2 & a8; /* 00fc: and a2, a2, a8 */
  a8 = 0x2; /* 00ff: movi.n a8, 2 */
  a2 = a2 | a8; /* 0101: or a2, a2, a8 */
  MEMW(); /* 0104: memw  */
  REG32(0x3FF7309C) = a2; /* 0107: s32i.n a2, a3, 0 */ /* MMIO write: base 0x3FF7309C+0 */
  MEMW(); /* 0109: memw  */
  return (int32_t)a2; /* 010c: retw.n  */
}

/* hal_mac_clr_bssid @ hal_mac.o 00000008 size 33B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73024
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_clr_bssid(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_clr_bssid; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = 0x3FF73024; /* 000b: l32r a8, 0 <hal_mac_clr_bssid-0x8> (3ff73024 <mac_txrx_init+0x3ff72fbc>) */ /* MMIO base */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a2 = (a2 << 8) + a8; /* 0011: addx8 a2, a2, a8 */
  MEMW(); /* 0014: memw  */
  a8 = MEM32(a2 + 0); /* 0017: l32i.n a8, a2, 0 */
  a9 = 0xFFFEFFFF; /* 0019: l32r a9, 4 <hal_mac_clr_bssid-0x4> (fffeffff <mac_txrx_init+0xfffeff97>) */ @0x4
  a8 = a8 & a9; /* 001c: and a8, a8, a9 */
  MEMW(); /* 001f: memw  */
  MEM32(a2 + 0) = a8; /* 0022: s32i.n a8, a2, 0 */
  MEMW(); /* 0024: memw  */
  return (int32_t)a2; /* 0027: retw.n  */
}

/* hal_mac_tsf_get_time @ hal_mac.o 00000010 size 114B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF75010, 0x3FF75054, 0x3FF75094, 0x3FF75090
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 45 instr, 5 branches, calls resolved */
int32_t hal_mac_tsf_get_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_tsf_get_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = a2; /* 0013: mov.n a3, a2 */
  if (a2 == 1) goto L_4c; /* 0015: beqi a2, 1, 4c <hal_mac_tsf_get_time+0x3c> */
  if (a2 == 2) goto L_4c; /* 0018: beqi a2, 2, 4c <hal_mac_tsf_get_time+0x3c> */
  if (a2 == 0) goto L_24; /* 001b: beqz.n a2, 24 <hal_mac_tsf_get_time+0x14> */
  a2 = 0x0; /* 001d: movi.n a2, 0 */
  a3 = 0x0; /* 001f: mov.n a3, a2 */
  goto L_7d; /* 0021: j 7d <hal_mac_tsf_get_time+0x6d> */
L_24:;
  a8 = 0x3FF75010; /* 0024: l32r a8, 0 <hal_mac_tsf_get_time-0x10> (3ff75010 <mac_txrx_init+0x3ff74fa8>) */ /* MMIO base */ @0x0
  a2 = 0x2; /* 0027: movi.n a2, 2 */
  a10 = 0xFFFFFFFD; /* 0029: movi.n a10, -3 */
  MEMW(); /* 002b: memw  */
  a9 = REG32(0x3FF75010); /* 002e: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
  a9 = a9 | a2; /* 0030: or a9, a9, a2 */
  a2 = 0x3FF75054; /* 0033: l32r a2, c <hal_mac_tsf_get_time-0x4> (3ff75054 <mac_txrx_init+0x3ff74fec>) */ /* MMIO base */ @0xC
  MEMW(); /* 0036: memw  */
  REG32(0x3FF75010) = a9; /* 0039: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF75010+0 */
  MEMW(); /* 003b: memw  */
  a2 = REG32(0x3FF75054); /* 003e: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF75054+0 */
  MEMW(); /* 0040: memw  */
  a9 = REG32(0x3FF75010); /* 0043: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
  MEMW(); /* 0045: memw  */
  goto L_75; /* 0048: j 75 <hal_mac_tsf_get_time+0x65> */
  /* 004b: .byte 00 */
L_4c:;
  a8 = 0x3FF75010; /* 004c: l32r a8, 0 <hal_mac_tsf_get_time-0x10> (3ff75010 <mac_txrx_init+0x3ff74fa8>) */ /* MMIO base */ @0x0
  a2 = 0x4; /* 004f: movi.n a2, 4 */
  a10 = 0xFFFFFFFB; /* 0051: movi.n a10, -5 */
  MEMW(); /* 0053: memw  */
  a3 = REG32(0x3FF75010); /* 0056: l32i.n a3, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
  a3 = a3 | a2; /* 0058: or a3, a3, a2 */
  a2 = 0x3FF75094; /* 005b: l32r a2, 4 <hal_mac_tsf_get_time-0xc> (3ff75094 <mac_txrx_init+0x3ff7502c>) */ /* MMIO base */ @0x4
  MEMW(); /* 005e: memw  */
  REG32(0x3FF75010) = a3; /* 0061: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF75010+0 */
  MEMW(); /* 0063: memw  */
  a3 = REG32(0x3FF75094); /* 0066: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF75094+0 */
  a2 = 0x3FF75090; /* 0068: l32r a2, 8 <hal_mac_tsf_get_time-0x8> (3ff75090 <mac_txrx_init+0x3ff75028>) */ /* MMIO base */ @0x8
  MEMW(); /* 006b: memw  */
  a2 = REG32(0x3FF75090); /* 006e: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF75090+0 */
  MEMW(); /* 0070: memw  */
  a9 = REG32(0x3FF75010); /* 0073: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
L_75:;
  a9 = a9 & a10; /* 0075: and a9, a9, a10 */
  MEMW(); /* 0078: memw  */
  REG32(0x3FF75010) = a9; /* 007b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF75010+0 */
L_7d:;
  MEMW(); /* 007d: memw  */
  return (int32_t)a2; /* 0080: retw.n  */
}

/* wDev_Mesh_Disable_Tsf @ hal_mac.o 00000004 size 11B bind GLOBAL
 * Calls: hal_disable_sta_tsf | Data refs: hal_disable_sta_tsf
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_Mesh_Disable_Tsf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Mesh_Disable_Tsf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&hal_disable_sta_tsf; /* 0007: l32r a8, 0 <wDev_Mesh_Disable_Tsf-0x4> (0 <wDev_Mesh_Disable_Tsf-0x4>) */ /* literal: GOT slot for hal_disable_sta_tsf */
  hal_disable_sta_tsf(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* hal_get_tsf_time @ hal_mac.o 00000014 size 98B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF75010, 0x3FF75018, 0x3FF75014, 0x3FF75058, 0x3FF75054
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_get_tsf_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.15; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a8 = 0x3FF75010; /* 0017: l32r a8, 0 <hal_get_tsf_time-0x14> (3ff75010 <mac_txrx_init+0x3ff74fa8>) */ /* MMIO base */ @0x0
  MEMW(); /* 001a: memw  */
  a3 = REG32(0x3FF75010); /* 001d: l32i.n a3, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
  if (a2 != 0) goto L_48; /* 001f: bnez.n a2, 48 <hal_get_tsf_time+0x34> */
  a2 = 0x1; /* 0021: movi.n a2, 1 */
  a3 = a3 | a2; /* 0023: or a3, a3, a2 */
  a10 = 0xFFFFFFFE; /* 0026: movi.n a10, -2 */
  a2 = 0x3FF75018; /* 0028: l32r a2, 4 <hal_get_tsf_time-0x10> (3ff75018 <mac_txrx_init+0x3ff74fb0>) */ /* MMIO base */ @0x4
  MEMW(); /* 002b: memw  */
  REG32(0x3FF75010) = a3; /* 002e: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF75010+0 */
  MEMW(); /* 0030: memw  */
  a3 = REG32(0x3FF75018); /* 0033: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF75018+0 */
  a2 = 0x3FF75014; /* 0035: l32r a2, 8 <hal_get_tsf_time-0xc> (3ff75014 <mac_txrx_init+0x3ff74fac>) */ /* MMIO base */ @0x8
  MEMW(); /* 0038: memw  */
  a2 = REG32(0x3FF75014); /* 003b: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF75014+0 */
  MEMW(); /* 003d: memw  */
  a9 = REG32(0x3FF75010); /* 0040: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
  MEMW(); /* 0042: memw  */
  goto L_69; /* 0045: j 69 <hal_get_tsf_time+0x55> */
L_48:;
  a2 = 0x2; /* 0048: movi.n a2, 2 */
  a3 = a3 | a2; /* 004a: or a3, a3, a2 */
  a2 = 0x3FF75058; /* 004d: l32r a2, c <hal_get_tsf_time-0x8> (3ff75058 <mac_txrx_init+0x3ff74ff0>) */ /* MMIO base */ @0xC
  a10 = 0xFFFFFFFD; /* 0050: movi.n a10, -3 */
  MEMW(); /* 0052: memw  */
  REG32(0x3FF75010) = a3; /* 0055: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF75010+0 */
  MEMW(); /* 0057: memw  */
  a3 = REG32(0x3FF75058); /* 005a: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF75058+0 */
  a2 = 0x3FF75054; /* 005c: l32r a2, 10 <hal_get_tsf_time-0x4> (3ff75054 <mac_txrx_init+0x3ff74fec>) */ /* MMIO base */ @0x10
  MEMW(); /* 005f: memw  */
  a2 = REG32(0x3FF75054); /* 0062: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF75054+0 */
  MEMW(); /* 0064: memw  */
  a9 = REG32(0x3FF75010); /* 0067: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
L_69:;
  a9 = a9 & a10; /* 0069: and a9, a9, a10 */
  MEMW(); /* 006c: memw  */
  REG32(0x3FF75010) = a9; /* 006f: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF75010+0 */
  MEMW(); /* 0071: memw  */
  return (int32_t)a2; /* 0074: retw.n  */
}

/* hal_mac_tsf_set_time @ hal_mac.o 00000014 size 93B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF7509C, 0x3FF750A0, 0x3FF75010, 0x3FF75060, 0x3FF75064
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_tsf_set_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_tsf_set_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  if (a2 == 1) goto L_49; /* 0017: beqi a2, 1, 49 <hal_mac_tsf_set_time+0x35> */
  if (a2 != 2) goto L_6c; /* 001a: bnei a2, 2, 6c <hal_mac_tsf_set_time+0x58> */
  a2 = 0x3FF7509C; /* 001d: l32r a2, 0 <hal_mac_tsf_set_time-0x14> (3ff7509c <mac_txrx_init+0x3ff75034>) */ /* MMIO base */ @0x0
  MEMW(); /* 0020: memw  */
  REG32(0x3FF7509C) = a4; /* 0023: s32i.n a4, a2, 0 */ /* MMIO write: base 0x3FF7509C+0 */
  a2 = 0x3FF750A0; /* 0025: l32r a2, 4 <hal_mac_tsf_set_time-0x10> (3ff750a0 <mac_txrx_init+0x3ff75038>) */ /* MMIO base */ @0x4
  a4 = 0x3FF75010; /* 0028: l32r a4, 8 <hal_mac_tsf_set_time-0xc> (3ff75010 <mac_txrx_init+0x3ff74fa8>) */ /* MMIO base */ @0x8
  MEMW(); /* 002b: memw  */
  REG32(0x3FF750A0) = a5; /* 002e: s32i.n a5, a2, 0 */ /* MMIO write: base 0x3FF750A0+0 */
  a2 = 0x100; /* 0030: movi a2, 0x100 */
  MEMW(); /* 0033: memw  */
  a8 = REG32(0x3FF75010); /* 0036: l32i.n a8, a4, 0 */ /* MMIO read: base 0x3FF75010+0 */
  a8 = a8 | a2; /* 0038: or a8, a8, a2 */
  MEMW(); /* 003b: memw  */
  REG32(0x3FF75010) = a8; /* 003e: s32i.n a8, a4, 0 */ /* MMIO write: base 0x3FF75010+0 */
  MEMW(); /* 0040: memw  */
  goto L_6c; /* 0043: j 6c <hal_mac_tsf_set_time+0x58> */
  /* 0046: .byte 00 */
  /* 0047: .byte 00 */
  /* 0048: .byte 00 */
L_49:;
  a2 = 0x3FF75060; /* 0049: l32r a2, c <hal_mac_tsf_set_time-0x8> (3ff75060 <mac_txrx_init+0x3ff74ff8>) */ /* MMIO base */ @0xC
  MEMW(); /* 004c: memw  */
  REG32(0x3FF75060) = a4; /* 004f: s32i.n a4, a2, 0 */ /* MMIO write: base 0x3FF75060+0 */
  a2 = 0x3FF75064; /* 0051: l32r a2, 10 <hal_mac_tsf_set_time-0x4> (3ff75064 <mac_txrx_init+0x3ff74ffc>) */ /* MMIO base */ @0x10
  a9 = 0x3FF75010; /* 0054: l32r a9, 8 <hal_mac_tsf_set_time-0xc> (3ff75010 <mac_txrx_init+0x3ff74fa8>) */ /* MMIO base */ @0x8
  MEMW(); /* 0057: memw  */
  REG32(0x3FF75064) = a5; /* 005a: s32i.n a5, a2, 0 */ /* MMIO write: base 0x3FF75064+0 */
  a2 = 0x80; /* 005c: movi a2, 128 */
  MEMW(); /* 005f: memw  */
  a8 = REG32(0x3FF75010); /* 0062: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF75010+0 */
  a8 = a8 | a2; /* 0064: or a8, a8, a2 */
  MEMW(); /* 0067: memw  */
  REG32(0x3FF75010) = a8; /* 006a: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF75010+0 */
L_6c:;
  MEMW(); /* 006c: memw  */
  return (int32_t)a2; /* 006f: retw.n  */
}

/* hal_mac_tsf_reset @ hal_mac.o 00000034 size 321B bind GLOBAL
 * Calls: wDev_reset_bcnSendTick | Data refs: wDev_reset_bcnSendTick
 *   MMIO: 0x3FF75098, 0x3FF7509C, 0x3FF750A0, 0x3FF75010, 0x3FF7505C, 0x3FF75060, 0x3FF75064, 0x3FF75020, 0x3FF75024, 0x3FF75028
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: medium - 121 instr, 7 branches, calls resolved */
int32_t hal_mac_tsf_reset(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_tsf_reset; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 32 */
  if (a2 != 1) goto L_3d; /* 0037: bnei a2, 1, 3d <hal_mac_tsf_reset+0x9> */
  goto L_e8; /* 003a: j e8 <hal_mac_tsf_reset+0xb4> */
L_3d:;
  if (a2 == 2) goto L_46; /* 003d: beqi a2, 2, 46 <hal_mac_tsf_reset+0x12> */
  if (a2 != 0) goto L_170; /* 0040: bnez a2, 170 <hal_mac_tsf_reset+0x13c> */
  goto L_90; /* 0043: j 90 <hal_mac_tsf_reset+0x5c> */
L_46:;
  a2 = 0x3FF75098; /* 0046: l32r a2, 0 <hal_mac_tsf_reset-0x34> (3ff75098 <mac_txrx_init+0x3ff75030>) */ /* MMIO base */ @0x0
  a9 = 0x100; /* 0049: movi a9, 0x100 */
  MEMW(); /* 004c: memw  */
  a3 = REG32(0x3FF75098); /* 004f: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF75098+0 */
  a8 = 0x7FFFFFFF; /* 0051: l32r a8, 4 <hal_mac_tsf_reset-0x30> (7fffffff <mac_txrx_init+0x7fffff97>) */ @0x4
  a3 = a3 & a8; /* 0054: and a3, a3, a8 */
  a8 = 0x3FF7509C; /* 0057: l32r a8, 8 <hal_mac_tsf_reset-0x2c> (3ff7509c <mac_txrx_init+0x3ff75034>) */ /* MMIO base */ @0x8
  MEMW(); /* 005a: memw  */
  REG32(0x3FF75098) = a3; /* 005d: s32i.n a3, a2, 0 */ /* MMIO write: base 0x3FF75098+0 */
  a3 = 0x0; /* 005f: movi.n a3, 0 */
  MEMW(); /* 0061: memw  */
  REG32(0x3FF7509C) = a3; /* 0064: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF7509C+0 */
  a8 = 0x3FF750A0; /* 0066: l32r a8, c <hal_mac_tsf_reset-0x28> (3ff750a0 <mac_txrx_init+0x3ff75038>) */ /* MMIO base */ @0xC
  MEMW(); /* 0069: memw  */
  REG32(0x3FF750A0) = a3; /* 006c: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF750A0+0 */
  a8 = 0x3FF75010; /* 006e: l32r a8, 10 <hal_mac_tsf_reset-0x24> (3ff75010 <mac_txrx_init+0x3ff74fa8>) */ /* MMIO base */ @0x10
  MEMW(); /* 0071: memw  */
  a3 = REG32(0x3FF75010); /* 0074: l32i.n a3, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
  a3 = a3 | a9; /* 0076: or a3, a3, a9 */
  MEMW(); /* 0079: memw  */
  REG32(0x3FF75010) = a3; /* 007c: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF75010+0 */
  a8 = 0xFFFFFFFF; /* 007e: movi.n a8, -1 */
  a8 = 0x80000000; /* 0080: slli a8, a8, 31 */
  MEMW(); /* 0083: memw  */
  a3 = REG32(0x3FF75098); /* 0086: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF75098+0 */
  MEMW(); /* 0088: memw  */
  goto L_167; /* 008b: j 167 <hal_mac_tsf_reset+0x133> */
  /* 008e: .byte 00 */
  /* 008f: .byte 00 */
L_90:;
  a3 = 0x3FF7505C; /* 0090: l32r a3, 14 <hal_mac_tsf_reset-0x20> (3ff7505c <mac_txrx_init+0x3ff74ff4>) */ /* MMIO base */ @0x14
  a9 = 0x3DFFFFFF; /* 0093: l32r a9, 18 <hal_mac_tsf_reset-0x1c> (3dffffff <mac_txrx_init+0x3dffff97>) */ @0x18
  MEMW(); /* 0096: memw  */
  a8 = REG32(0x3FF7505C); /* 0099: l32i.n a8, a3, 0 */ /* MMIO read: base 0x3FF7505C+0 */
  a8 = a8 & a9; /* 009b: and a8, a8, a9 */
  MEMW(); /* 009e: memw  */
  REG32(0x3FF7505C) = a8; /* 00a1: s32i.n a8, a3, 0 */ /* MMIO write: base 0x3FF7505C+0 */
  MEMW(); /* 00a3: memw  */
  a8 = (uint32_t)&wDev_reset_bcnSendTick; /* 00a6: l32r a8, 30 <hal_mac_tsf_reset-0x4> (0 <hal_mac_tsf_reset-0x34>) */ /* literal: GOT slot for wDev_reset_bcnSendTick */
  wDev_reset_bcnSendTick(a2, a3, a4, a5); /* call via literal slot */ /* 00a9: callx8 a8 */
  a9 = 0x80; /* 00ac: movi a9, 128 */
  a8 = 0x3FF75060; /* 00af: l32r a8, 1c <hal_mac_tsf_reset-0x18> (3ff75060 <mac_txrx_init+0x3ff74ff8>) */ /* MMIO base */ @0x1C
  MEMW(); /* 00b2: memw  */
  REG32(0x3FF75060) = a2; /* 00b5: s32i.n a2, a8, 0 */ /* MMIO write: base 0x3FF75060+0 */
  a8 = 0x3FF75064; /* 00b7: l32r a8, 20 <hal_mac_tsf_reset-0x14> (3ff75064 <mac_txrx_init+0x3ff74ffc>) */ /* MMIO base */ @0x20
  MEMW(); /* 00ba: memw  */
  REG32(0x3FF75064) = a2; /* 00bd: s32i.n a2, a8, 0 */ /* MMIO write: base 0x3FF75064+0 */
  a8 = 0x3FF75010; /* 00bf: l32r a8, 10 <hal_mac_tsf_reset-0x24> (3ff75010 <mac_txrx_init+0x3ff74fa8>) */ /* MMIO base */ @0x10
  MEMW(); /* 00c2: memw  */
  a2 = REG32(0x3FF75010); /* 00c5: l32i.n a2, a8, 0 */ /* MMIO read: base 0x3FF75010+0 */
  a2 = a2 | a9; /* 00c7: or a2, a2, a9 */
  MEMW(); /* 00ca: memw  */
  REG32(0x3FF75010) = a2; /* 00cd: s32i.n a2, a8, 0 */ /* MMIO write: base 0x3FF75010+0 */
  a8 = 0xFFFFFFE1; /* 00cf: movi.n a8, -31 */
  a8 = 0xC2000000; /* 00d1: slli a8, a8, 25 */
  MEMW(); /* 00d4: memw  */
  a2 = MEM32(a3 + 0); /* 00d7: l32i.n a2, a3, 0 */
  a2 = a2 | a8; /* 00d9: or a2, a2, a8 */
  MEMW(); /* 00dc: memw  */
  MEM32(a3 + 0) = a2; /* 00df: s32i.n a2, a3, 0 */
  MEMW(); /* 00e1: memw  */
  goto L_170; /* 00e4: j 170 <hal_mac_tsf_reset+0x13c> */
  /* 00e7: .byte 00 */
L_e8:;
  a2 = 0x3FF75020; /* 00e8: l32r a2, 24 <hal_mac_tsf_reset-0x10> (3ff75020 <mac_txrx_init+0x3ff74fb8>) */ /* MMIO base */ @0x24
  a10 = 0x0; /* 00eb: movi.n a10, 0 */
  a8 = 0x40; /* 00ed: movi.n a8, 64 */
  MEMW(); /* 00ef: memw  */
  a3 = REG32(0x3FF75020); /* 00f2: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF75020+0 */
  a11 = 0x7FFFFFFF; /* 00f4: l32r a11, 4 <hal_mac_tsf_reset-0x30> (7fffffff <mac_txrx_init+0x7fffff97>) */ @0x4
  a3 = a3 & a11; /* 00f7: and a3, a3, a11 */
  MEMW(); /* 00fa: memw  */
  REG32(0x3FF75020) = a3; /* 00fd: s32i.n a3, a2, 0 */ /* MMIO write: base 0x3FF75020+0 */
  a3 = 0x3FF75024; /* 00ff: l32r a3, 28 <hal_mac_tsf_reset-0xc> (3ff75024 <mac_txrx_init+0x3ff74fbc>) */ /* MMIO base */ @0x28
  MEMW(); /* 0102: memw  */
  REG32(0x3FF75024) = a10; /* 0105: s32i.n a10, a3, 0 */ /* MMIO write: base 0x3FF75024+0 */
  a3 = 0x3FF75028; /* 0107: l32r a3, 2c <hal_mac_tsf_reset-0x8> (3ff75028 <mac_txrx_init+0x3ff74fc0>) */ /* MMIO base */ @0x2C
  a9 = 0x3FF75010; /* 010a: l32r a9, 10 <hal_mac_tsf_reset-0x24> (3ff75010 <mac_txrx_init+0x3ff74fa8>) */ /* MMIO base */ @0x10
  MEMW(); /* 010d: memw  */
  REG32(0x3FF75028) = a10; /* 0110: s32i.n a10, a3, 0 */ /* MMIO write: base 0x3FF75028+0 */
  MEMW(); /* 0112: memw  */
  a3 = REG32(0x3FF75010); /* 0115: l32i.n a3, a9, 0 */ /* MMIO read: base 0x3FF75010+0 */
  a3 = a3 | a8; /* 0117: or a3, a3, a8 */
  a8 = 0xFFFFFFFF; /* 011a: movi.n a8, -1 */
  a8 = 0x80000000; /* 011c: slli a8, a8, 31 */
  MEMW(); /* 011f: memw  */
  REG32(0x3FF75010) = a3; /* 0122: s32i.n a3, a9, 0 */ /* MMIO write: base 0x3FF75010+0 */
  MEMW(); /* 0124: memw  */
  a3 = REG32(0x3FF75020); /* 0127: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF75020+0 */
  a3 = a3 | a8; /* 0129: or a3, a3, a8 */
  MEMW(); /* 012c: memw  */
  REG32(0x3FF75020) = a3; /* 012f: s32i.n a3, a2, 0 */ /* MMIO write: base 0x3FF75020+0 */
  a2 = 0x3FF7505C; /* 0131: l32r a2, 14 <hal_mac_tsf_reset-0x20> (3ff7505c <mac_txrx_init+0x3ff74ff4>) */ /* MMIO base */ @0x14
  MEMW(); /* 0134: memw  */
  a3 = REG32(0x3FF7505C); /* 0137: l32i.n a3, a2, 0 */ /* MMIO read: base 0x3FF7505C+0 */
  a3 = a3 & a11; /* 0139: and a3, a3, a11 */
  MEMW(); /* 013c: memw  */
  REG32(0x3FF7505C) = a3; /* 013f: s32i.n a3, a2, 0 */ /* MMIO write: base 0x3FF7505C+0 */
  a3 = 0x3FF75060; /* 0141: l32r a3, 1c <hal_mac_tsf_reset-0x18> (3ff75060 <mac_txrx_init+0x3ff74ff8>) */ /* MMIO base */ @0x1C
  MEMW(); /* 0144: memw  */
  REG32(0x3FF75060) = a10; /* 0147: s32i.n a10, a3, 0 */ /* MMIO write: base 0x3FF75060+0 */
  a3 = 0x3FF75064; /* 0149: l32r a3, 20 <hal_mac_tsf_reset-0x14> (3ff75064 <mac_txrx_init+0x3ff74ffc>) */ /* MMIO base */ @0x20
  MEMW(); /* 014c: memw  */
  REG32(0x3FF75064) = a10; /* 014f: s32i.n a10, a3, 0 */ /* MMIO write: base 0x3FF75064+0 */
  a10 = 0x80; /* 0151: movi a10, 128 */
  MEMW(); /* 0154: memw  */
  a3 = REG32(0x3FF75010); /* 0157: l32i.n a3, a9, 0 */ /* MMIO read: base 0x3FF75010+0 */
  a3 = a3 | a10; /* 0159: or a3, a3, a10 */
  MEMW(); /* 015c: memw  */
  REG32(0x3FF75010) = a3; /* 015f: s32i.n a3, a9, 0 */ /* MMIO write: base 0x3FF75010+0 */
  MEMW(); /* 0161: memw  */
  a3 = REG32(0x3FF7505C); /* 0164: l32i a3, a2, 0 */ /* MMIO read: base 0x3FF7505C+0 */
L_167:;
  a3 = a3 | a8; /* 0167: or a3, a3, a8 */
  MEMW(); /* 016a: memw  */
  REG32(0x3FF7505C) = a3; /* 016d: s32i a3, a2, 0 */ /* MMIO write: base 0x3FF7505C+0 */
L_170:;
  MEMW(); /* 0170: memw  */
  return (int32_t)a2; /* 0173: retw.n  */
}

/* hal_mac_set_csi @ hal_mac.o 0000000c size 73B bind GLOBAL
 * Calls: none | Data refs: g_wifi_menuconfig
 *   MMIO: 0x3FF7309C
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_set_csi(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_set_csi; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 000f: extui a10, a2, 0, 8 */
  a2 = (uint32_t)&g_wifi_menuconfig; /* 0012: l32r a2, 0 <hal_mac_set_csi-0xc> (0 <hal_mac_set_csi-0xc>) */ /* literal @0x0: g_wifi_menuconfig */
  a8 = MEM32(a2 + 24); /* 0015: l32i.n a8, a2, 24 */
  a2 = 0xFFFFFFFF; /* 0017: movi.n a2, -1 */
  if (a8 == 0) goto L_50; /* 0019: beqz.n a8, 50 <hal_mac_set_csi+0x44> */
  a8 = 0x3FF7309C; /* 001b: l32r a8, 4 <hal_mac_set_csi-0x8> (3ff7309c <mac_txrx_init+0x3ff73034>) */ /* MMIO base */ @0x4
  if (a10 == 0) goto L_3c; /* 001e: beqz.n a10, 3c <hal_mac_set_csi+0x30> */
  a9 = 0x1; /* 0020: movi.n a9, 1 */
  a9 = 0x800000; /* 0022: slli a9, a9, 23 */
  MEMW(); /* 0025: memw  */
  a2 = REG32(0x3FF7309C); /* 0028: l32i.n a2, a8, 0 */ /* MMIO read: base 0x3FF7309C+0 */
  a2 = a2 | a9; /* 002a: or a2, a2, a9 */
  MEMW(); /* 002d: memw  */
  REG32(0x3FF7309C) = a2; /* 0030: s32i.n a2, a8, 0 */ /* MMIO write: base 0x3FF7309C+0 */
  a2 = 0x0; /* 0032: movi.n a2, 0 */
  MEMW(); /* 0034: memw  */
  goto L_50; /* 0037: j 50 <hal_mac_set_csi+0x44> */
  /* 003a: .byte 00 */
  /* 003b: .byte 00 */
L_3c:;
  MEMW(); /* 003c: memw  */
  a9 = REG32(0x3FF7309C); /* 003f: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF7309C+0 */
  a2 = 0xFF7FFFFF; /* 0041: l32r a2, 8 <hal_mac_set_csi-0x4> (ff7fffff <mac_txrx_init+0xff7fff97>) */ @0x8
  a9 = a9 & a2; /* 0044: and a9, a9, a2 */
  a2 = a10 | a10; /* 0047: or a2, a10, a10 */
  MEMW(); /* 004a: memw  */
  REG32(0x3FF7309C) = a9; /* 004d: s32i a9, a8, 0 */ /* MMIO write: base 0x3FF7309C+0 */
L_50:;
  MEMW(); /* 0050: memw  */
  return (int32_t)a2; /* 0053: retw.n  */
}

/* hal_mac_init @ hal_mac.o 00000004 size 31B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73CB8
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.16; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x3FF73CB8; /* 0007: l32r a10, 0 <hal_mac_init-0x4> (3ff73cb8 <mac_txrx_init+0x3ff73c50>) */ /* MMIO base */ @0x0
  a9 = 0xFFFFFFFD; /* 000a: movi.n a9, -3 */
  a9 = 0xFFFFE800; /* 000c: slli a9, a9, 11 */
  a2 = 0x0; /* 000f: movi.n a2, 0 */
  MEMW(); /* 0011: memw  */
  a8 = REG32(0x3FF73CB8); /* 0014: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73CB8+0 */
  a8 = a8 & a9; /* 0016: and a8, a8, a9 */
  MEMW(); /* 0019: memw  */
  REG32(0x3FF73CB8) = a8; /* 001c: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73CB8+0 */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* hal_mac_deinit @ hal_mac.o 00000030 size 190B bind GLOBAL
 * Calls: ets_delay_us[got], wifi_log[got], wifi_log[got], wifi_log[got], ets_delay_us[got] | Data refs: ets_delay_us, .rodata_wlog_error.18, wifi_log, .rodata_wlog_error.19, .rodata_wlog_error.20
 *   MMIO: 0x3FF73CB8, 0x3FF73C58
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: medium - 73 instr, 3 branches, calls resolved */
int32_t hal_mac_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.17; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a3 = 0x3FF73CB8; /* 0033: l32r a3, 0 <hal_mac_deinit-0x30> (3ff73cb8 <mac_txrx_init+0x3ff73c50>) */ /* MMIO base */ @0x0
  a10 = 0x20; /* 0036: movi.n a10, 32 */
  MEMW(); /* 0038: memw  */
  a2 = REG32(0x3FF73CB8); /* 003b: l32i.n a2, a3, 0 */ /* MMIO read: base 0x3FF73CB8+0 */
  a4 = 0x17FF; /* 003d: l32r a4, 4 <hal_mac_deinit-0x2c> (17ff <mac_txrx_init+0x1797>) */ @0x4
  a2 = a2 | a4; /* 0040: or a2, a2, a4 */
  a4 = 0x0; /* 0043: movi.n a4, 0 */
  MEMW(); /* 0045: memw  */
  REG32(0x3FF73CB8) = a2; /* 0048: s32i a2, a3, 0 */ /* MMIO write: base 0x3FF73CB8+0 */
  MEMW(); /* 004b: memw  */
  a8 = (uint32_t)&ets_delay_us; /* 004e: l32r a8, 1c <hal_mac_deinit-0x14> (0 <hal_mac_deinit-0x30>) */ /* literal: GOT slot for ets_delay_us */
  ets_delay_us(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
L_54:;
  a5 = 0x1; /* 0054: movi.n a5, 1 */
  a5 = 0x2000; /* 0056: slli a5, a5, 13 */
  MEMW(); /* 0059: memw  */
  a2 = MEM32(a3 + 0); /* 005c: l32i.n a2, a3, 0 */
  a2 = a2 & a5; /* 005e: and a2, a2, a5 */
  if (a2 == 0) goto L_ec; /* 0061: beqz a2, ec <hal_mac_deinit+0xbc> */
  a2 = 0x271; /* 0064: movi a2, 0x271 */
  a2 = 0x4E20; /* 0067: slli a2, a2, 5 */
  if (a4 != a2) goto L_de; /* 006a: bne a4, a2, de <hal_mac_deinit+0xae> */
  a12 = 0x1; /* 006d: movi.n a12, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_18; /* 006f: l32r a13, 8 <hal_mac_deinit-0x28> (0 <hal_mac_deinit-0x30>) */ /* literal @0x8: .rodata_wlog_error.18 */
  a11 = 0x1; /* 0072: mov.n a11, a12 */
  a10 = 0x5; /* 0074: movi.n a10, 5 */
  a8 = (uint32_t)&wifi_log; /* 0076: l32r a8, 20 <hal_mac_deinit-0x10> (0 <hal_mac_deinit-0x30>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
  a5 = 0x1; /* 007c: movi.n a5, 1 */
  a2 = 0x3FF73C58; /* 007e: l32r a2, c <hal_mac_deinit-0x24> (3ff73c58 <mac_txrx_init+0x3ff73bf0>) */ /* MMIO base */ @0xC
  a5 = 0x20000; /* 0081: slli a5, a5, 17 */
  a14 = 0x3FF73C58; /* 0084: mov.n a14, a2 */
  a12 = 0x1; /* 0086: movi.n a12, 1 */
  a10 = 0x6; /* 0088: movi.n a10, 6 */
  MEMW(); /* 008a: memw  */
  a8 = REG32(0x3FF73C58); /* 008d: l32i.n a8, a2, 0 */ /* MMIO read: base 0x3FF73C58+0 */
  a4 = 0xFFFCFFFF; /* 008f: l32r a4, 10 <hal_mac_deinit-0x20> (fffcffff <mac_txrx_init+0xfffcff97>) */ @0x10
  a8 = a8 & a4; /* 0092: and a8, a8, a4 */
  a8 = a8 | a5; /* 0095: or a8, a8, a5 */
  a5 = 0x1; /* 0098: movi.n a5, 1 */
  MEMW(); /* 009a: memw  */
  REG32(0x3FF73C58) = a8; /* 009d: s32i.n a8, a2, 0 */ /* MMIO write: base 0x3FF73C58+0 */
  a5 = 0x1000; /* 009f: slli a5, a5, 12 */
  a11 = 0x1000; /* 00a2: mov.n a11, a5 */
  MEMW(); /* 00a4: memw  */
  a15 = REG32(0x3FF73C58); /* 00a7: l32i.n a15, a2, 0 */ /* MMIO read: base 0x3FF73C58+0 */
  a13 = (uint32_t)&lit_rodata_wlog_error_19; /* 00a9: l32r a13, 14 <hal_mac_deinit-0x1c> (0 <hal_mac_deinit-0x30>) */ /* literal @0x14: .rodata_wlog_error.19 */
  MEMW(); /* 00ac: memw  */
  a8 = (uint32_t)&wifi_log; /* 00af: l32r a8, 24 <hal_mac_deinit-0xc> (0 <hal_mac_deinit-0x30>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00b2: callx8 a8 */
  a14 = a2; /* 00b5: mov.n a14, a2 */
  a12 = 0x1; /* 00b7: movi.n a12, 1 */
  MEMW(); /* 00b9: memw  */
  a8 = MEM32(a2 + 0); /* 00bc: l32i.n a8, a2, 0 */
  a11 = a5; /* 00be: mov.n a11, a5 */
  a4 = a8 & a4; /* 00c0: and a4, a8, a4 */
  a10 = 0x6; /* 00c3: movi.n a10, 6 */
  MEMW(); /* 00c5: memw  */
  MEM32(a2 + 0) = a4; /* 00c8: s32i.n a4, a2, 0 */
  a4 = 0x0; /* 00ca: movi.n a4, 0 */
  MEMW(); /* 00cc: memw  */
  a15 = MEM32(a2 + 0); /* 00cf: l32i a15, a2, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_error_20; /* 00d2: l32r a13, 18 <hal_mac_deinit-0x18> (0 <hal_mac_deinit-0x30>) */ /* literal @0x18: .rodata_wlog_error.20 */
  MEMW(); /* 00d5: memw  */
  a8 = (uint32_t)&wifi_log; /* 00d8: l32r a8, 28 <hal_mac_deinit-0x8> (0 <hal_mac_deinit-0x30>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00db: callx8 a8 */
L_de:;
  a10 = 0x2; /* 00de: movi.n a10, 2 */
  a4 = a4 + (1); /* 00e0: addi.n a4, a4, 1 */
  a8 = (uint32_t)&ets_delay_us; /* 00e2: l32r a8, 2c <hal_mac_deinit-0x4> (0 <hal_mac_deinit-0x30>) */ /* literal: GOT slot for ets_delay_us */
  ets_delay_us(a2, a3, a4, a5); /* call via literal slot */ /* 00e5: callx8 a8 */
  goto L_54; /* 00e8: j 54 <hal_mac_deinit+0x24> */
  /* 00eb: .byte 00 */
L_ec:;
  return (int32_t)a2; /* 00ec: retw.n  */
}

/* hal_mac_rx_enable @ hal_mac.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_enable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_rx_enable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x3FF73084; /* 0007: l32r a10, 0 <hal_mac_rx_enable-0x4> (3ff73084 <mac_txrx_init+0x3ff7301c>) */ /* MMIO base */ @0x0
  a9 = 0xFFFFFFFF; /* 000a: movi.n a9, -1 */
  a9 = 0x80000000; /* 000c: slli a9, a9, 31 */
  MEMW(); /* 000f: memw  */
  a8 = REG32(0x3FF73084); /* 0012: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a8 = a8 | a9; /* 0014: or a8, a8, a9 */
  MEMW(); /* 0017: memw  */
  REG32(0x3FF73084) = a8; /* 001a: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 001c: memw  */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* hal_mac_rx_disable @ hal_mac.o 00000008 size 27B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rx_disable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_rx_disable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = 0x3FF73084; /* 000b: l32r a9, 0 <hal_mac_rx_disable-0x8> (3ff73084 <mac_txrx_init+0x3ff7301c>) */ /* MMIO base */ @0x0
  a10 = 0x7FFFFFFF; /* 000e: l32r a10, 4 <hal_mac_rx_disable-0x4> (7fffffff <mac_txrx_init+0x7fffff97>) */ @0x4
  MEMW(); /* 0011: memw  */
  a8 = REG32(0x3FF73084); /* 0014: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a8 = a8 & a10; /* 0016: and a8, a8, a10 */
  MEMW(); /* 0019: memw  */
  REG32(0x3FF73084) = a8; /* 001c: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* hal_rx_disable_bssid_check @ hal_mac.o 00000004 size 34B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_rx_disable_bssid_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_rx_disable_bssid_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0xFFDCC36; /* 0007: l32r a8, 0 <hal_rx_disable_bssid_check-0x4> (ffdcc36 <mac_txrx_init+0xffdcbce>) */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = a2 + a8; /* 000d: add.n a2, a2, a8 */
  a2 = a2 << (2 & 31); /* 000f: slli a2, a2, 2 */
  a9 = 0xFFFFFFFD; /* 0012: movi.n a9, -3 */
  MEMW(); /* 0014: memw  */
  a8 = MEM32(a2 + 0); /* 0017: l32i.n a8, a2, 0 */
  a8 = a8 & a9; /* 0019: and a8, a8, a9 */
  MEMW(); /* 001c: memw  */
  MEM32(a2 + 0) = a8; /* 001f: s32i.n a8, a2, 0 */
  MEMW(); /* 0021: memw  */
  return (int32_t)a2; /* 0024: retw.n  */
}

/* hal_rx_enable_bssid_check @ hal_mac.o 00000004 size 34B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_rx_enable_bssid_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_rx_enable_bssid_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0xFFDCC36; /* 0007: l32r a8, 0 <hal_rx_enable_bssid_check-0x4> (ffdcc36 <mac_txrx_init+0xffdcbce>) */ @0x0
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = a2 + a8; /* 000d: add.n a2, a2, a8 */
  a2 = a2 << (2 & 31); /* 000f: slli a2, a2, 2 */
  a9 = 0x2; /* 0012: movi.n a9, 2 */
  MEMW(); /* 0014: memw  */
  a8 = MEM32(a2 + 0); /* 0017: l32i.n a8, a2, 0 */
  a8 = a8 | a9; /* 0019: or a8, a8, a9 */
  MEMW(); /* 001c: memw  */
  MEM32(a2 + 0) = a8; /* 001f: s32i.n a8, a2, 0 */
  MEMW(); /* 0021: memw  */
  return (int32_t)a2; /* 0024: retw.n  */
}

