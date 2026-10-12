/* Reconstruction of bt_rw_testmode.o (libbttestmode.a)
 * CU: bt_rw_testmode.c | comp_dir: /home/lxf/gittree/chip7.1_rtc/board_code/app_test/pp/bt_testmode
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 240 | funcdb functions: 132
 * Disasm: re/esp32-phy/disasm/libbttestmode/bt_rw_testmode.rdis
 * Signatures tagged [dwarf-sig] (concrete DIE), [dwarf-sig-decl] (declaration-only DIE),
 * [dwarf-sig-base] (split $part$ clone; signature of base), or [inferred] (no DIE).
 * Fidelity: high = exact (stub or hand-verified); medium = structure + calls/MMIO verified,
 *   some expressions approximate; low = signature + header only, logic TODO.
 */
#include <stdint.h>
/* DWARF-derived fixed-width aliases (Xtensa LE, ILP32). bool is an 8-bit
 * unsigned type in this TU per DWARF (bool -> unsigned char). */
typedef unsigned char U8, u8, uint8, uint8_t, SDL_Octet, bool;
typedef signed char S8, s8, sint8, int8;
typedef unsigned short U16, u16, uint16, UnsignedShortInt;
typedef short S16, s16, sint16, ShortInt;
typedef unsigned int U32, u32, uint32, uint32_t, STATUS, CriticalType;
typedef int S32, s32, sint32, int32;
typedef unsigned long long U64, u64, uint64;
typedef long long S64, s64;

/* RW_resume_radiocntl bt_rw_testmode.c:3121 @ bt_rw_testmode.o size 43B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600041c8, 0x60031300
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void RW_resume_radiocntl(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <RW_resume_radiocntl> (16 insns) + DWARF line rows for bt_rw_testmode.c:3121.
     */
}

/* RW_stop_radiocntl bt_rw_testmode.c:3115 @ bt_rw_testmode.o size 67B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x600041c8, 0x60031300, 0x60033d40
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void RW_stop_radiocntl(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <RW_stop_radiocntl> (25 insns) + DWARF line rows for bt_rw_testmode.c:3115.
     */
}

/* bt_bb_dump bt_rw_testmode.c:3900 @ bt_rw_testmode.o size 276B [dwarf-sig]
 * Calls: mac_write | Data refs: mac_write | MMIO: 0x3ff000a8, 0x3ff510f4, 0x3ff5c0b8, 0x60033d90, 0x60033dc4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_bb_dump(u32 data_sel, u32 dump_len)
{
    (void)data_sel;
    (void)dump_len;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <bt_bb_dump> (104 insns) + DWARF line rows for bt_rw_testmode.c:3900.
     * Ordered callee relocs: mac_write.
     */
}

/* bt_force_tx_tone bt_rw_testmode.c:3071 @ bt_rw_testmode.o size 75B [dwarf-sig-decl]
 * Calls: phy_printf | Data refs: .rodata.str1.4, g_phyFuns, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_force_tx_tone(u32 start, u32 bt_chan, u32 power)
{
    (void)start;
    (void)bt_chan;
    (void)power;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <bt_force_tx_tone> (30 insns) + DWARF line rows for bt_rw_testmode.c:3071.
     * Ordered callee relocs: phy_printf.
     */
}

/* bt_tx_pwr_check bt_rw_testmode.c:67 @ bt_rw_testmode.o size 254B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ff4506c, 0x3ff46000, 0x3ff46004, 0x3ff46008, 0x3ff4600c, 0x3ff46010
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_tx_pwr_check(void)
{
    /* DWARF locals: u32 i@l84 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <bt_tx_pwr_check> (93 insns) + DWARF line rows for bt_rw_testmode.c:67.
     * Ordered callee relocs: phy_printf.
     */
}

/* bt_tx_pwr_force bt_rw_testmode.c:94 @ bt_rw_testmode.o size 148B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ff46000, 0x3ff46004, 0x3ff46008, 0x3ff4600c, 0x3ff46010
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_tx_pwr_force(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <bt_tx_pwr_force> (54 insns) + DWARF line rows for bt_rw_testmode.c:94.
     * Ordered callee relocs: phy_printf.
     */
}

/* cmd_polling_test bt_rw_testmode.c:4689 @ bt_rw_testmode.o size 127B [dwarf-sig]
 * Calls: cmd_polling_start, cmd_polling_attach | Data refs: arga, argb, cmd_polling_attach, cmd_polling_start, cmd_polling_test0, cmd_polling_test1, cmd_polling_test2, cmd_polling_test3, my_samp | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cmd_polling_test(void)
{
    /* DWARF locals: u32 a@l4690, u32 b@l4691, void * aa@l4696, void * bb@l4697 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <cmd_polling_test> (51 insns) + DWARF line rows for bt_rw_testmode.c:4689.
     * Ordered callee relocs: cmd_polling_start, cmd_polling_attach.
     */
}

/* cmd_polling_test0 bt_rw_testmode.c:4663 @ bt_rw_testmode.o size 16B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cmd_polling_test0(u32 a)
{
    (void)a;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <cmd_polling_test0> (6 insns) + DWARF line rows for bt_rw_testmode.c:4663.
     * Ordered callee relocs: phy_printf.
     */
}

/* cmd_polling_test1 bt_rw_testmode.c:4668 @ bt_rw_testmode.o size 22B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, arga, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cmd_polling_test1(u32 b)
{
    (void)b;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <cmd_polling_test1> (8 insns) + DWARF line rows for bt_rw_testmode.c:4668.
     * Ordered callee relocs: phy_printf.
     */
}

/* cmd_polling_test2 bt_rw_testmode.c:4677 @ bt_rw_testmode.o size 18B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cmd_polling_test2(polling_sample * b)
{
    (void)b;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <cmd_polling_test2> (7 insns) + DWARF line rows for bt_rw_testmode.c:4677.
     * Ordered callee relocs: phy_printf.
     */
}

/* cmd_polling_test3 bt_rw_testmode.c:4681 @ bt_rw_testmode.o size 26B [dwarf-sig]
 * Calls: phy_printf | Data refs: .bss.loop$7365, .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cmd_polling_test3(void)
{
    /* DWARF locals: u32 loop@l4682 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <cmd_polling_test3> (10 insns) + DWARF line rows for bt_rw_testmode.c:4681.
     * Ordered callee relocs: phy_printf.
     */
}

/* em_clean bt_rw_testmode.c:2277 @ bt_rw_testmode.o size 25B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void em_clean(void)
{
    /* DWARF locals: u32 data@l2278, u32 i@l2278 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <em_clean> (10 insns) + DWARF line rows for bt_rw_testmode.c:2277.
     */
}

/* em_test bt_rw_testmode.c:2249 @ bt_rw_testmode.o size 77B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ffb0000, 0x3ffb0100
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void em_test(void)
{
    /* DWARF locals: u32 data@l2250, u32 i@l2250 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <em_test> (29 insns) + DWARF line rows for bt_rw_testmode.c:2249.
     * Ordered callee relocs: phy_printf.
     */
}

/* esp_get_btrx_result bt_rw_testmode.c:3559 @ bt_rw_testmode.o size 54B [dwarf-sig]
 * Calls: (none) | Data refs: btrx_result, btrx_valid | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
bool esp_get_btrx_result(int32 * rx_result)
{
    (void)rx_result;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <esp_get_btrx_result> (23 insns) + DWARF line rows for bt_rw_testmode.c:3559.
     */
}

/* fcc_bt_en bt_rw_testmode.c:3290 @ bt_rw_testmode.o size 102B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, g_phyFuns, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_bt_en(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <fcc_bt_en> (42 insns) + DWARF line rows for bt_rw_testmode.c:3290.
     * Ordered callee relocs: phy_printf.
     */
}

/* fcc_tx bt_rw_testmode.c:3301 @ bt_rw_testmode.o size 216B [dwarf-sig]
 * Calls: phy_printf, rw_tx_test | Data refs: .rodata.str1.4, phy_printf, rw_tx_test | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_tx(u32 txpwr, u32 hoppe, u32 chan, u32 rate, u32 DH_type, u32 data_type, u32 tx_num_in)
{
    (void)txpwr;
    (void)hoppe;
    (void)chan;
    (void)rate;
    (void)DH_type;
    (void)data_type;
    (void)tx_num_in;
    /* DWARF locals: u32 fi@l3302, u32 type@l3303, u32 length@l3303, u32 edr@l3303 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <fcc_tx> (82 insns) + DWARF line rows for bt_rw_testmode.c:3301.
     * Ordered callee relocs: phy_printf, rw_tx_test.
     */
}

/* fcc_tx_len bt_rw_testmode.c:3343 @ bt_rw_testmode.o size 226B [dwarf-sig]
 * Calls: phy_printf, rw_tx_test | Data refs: .rodata.str1.4, phy_printf, rw_tx_test | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_tx_len(u32 txpwr, u32 hoppe, u32 chan, u32 rate, u32 length, u32 data_type, u32 tx_num_in)
{
    (void)txpwr;
    (void)hoppe;
    (void)chan;
    (void)rate;
    (void)length;
    (void)data_type;
    (void)tx_num_in;
    /* DWARF locals: u32 fi@l3345, u32 type@l3346, u32 edr@l3346 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <fcc_tx_len> (88 insns) + DWARF line rows for bt_rw_testmode.c:3343.
     * Ordered callee relocs: phy_printf, rw_tx_test.
     */
}

/* fe_force_tx_tone bt_rw_testmode.c:3059 @ bt_rw_testmode.o size 80B [dwarf-sig]
 * Calls: RFChannelSel | Data refs: RFChannelSel, g_phyFuns | MMIO: 0x600060a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fe_force_tx_tone(u32 wifi_chan)
{
    (void)wifi_chan;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <fe_force_tx_tone> (31 insns) + DWARF line rows for bt_rw_testmode.c:3059.
     * Ordered callee relocs: RFChannelSel.
     */
}

/* force_wifi_toggle bt_rw_testmode.c:3105 @ bt_rw_testmode.o size 35B [dwarf-sig]
 * Calls: force_wifi_mode, ets_delay_us, unforce_wifi_mode | Data refs: ets_delay_us, force_wifi_mode, unforce_wifi_mode | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void force_wifi_toggle(u32 n)
{
    (void)n;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <force_wifi_toggle> (13 insns) + DWARF line rows for bt_rw_testmode.c:3105.
     * Ordered callee relocs: force_wifi_mode, ets_delay_us, unforce_wifi_mode.
     */
}

/* rom_test bt_rw_testmode.c:2262 @ bt_rw_testmode.o size 142B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rom_test(u32 base, u32 len, u32 repeat)
{
    (void)base;
    (void)len;
    (void)repeat;
    /* DWARF locals: u32 data@l2263, u32 i@l2263 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rom_test> (55 insns) + DWARF line rows for bt_rw_testmode.c:2262.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_autotest bt_rw_testmode.c:4722 @ bt_rw_testmode.o size 3072B [dwarf-sig]
 * Calls: ets_isr_unmask, wifi_init_bt, coex_bt_high_prio, phy_printf, rf_rw_init, UartGetCmdLn, cmd_parse, strcmp, WifiTxStart, force_wifi_mode, force_wifi_toggle, unforce_wifi_mode, force_bt_mode, adctrig, rw_tx_test, fe_force_tx_tone, bt_force_tx_tone, fcc_tx, fcc_le_tx, fcc_le_tx_syncw, rw_le_tx_hoppe_syncw, fcc_bt_en, rw_le_tx, rw_le_tx_nohoppe, rw_rx_per, rw_rx_per_ulap, rw_rx_per_ulap_rssi, rw_le_rx_per_syncw, rw_le_rx_per_syncw_rssi, rw_rx_dump, rw_inq_cmd, rw_inq_scan_cmd, rw_page_scan_cmd, rw_page_cmd, rw_mst_cmd, cmd_polling_test, cmd_polling_start, rw_le_rx_per_syncw_polling, rw_le_rx_per_syncw_polling_stop, READ_SPI_INIT_PARAM, gpio_output_set, gpio_output_set_high, gpio_input_get, gpio_input_get_high, RFChannelSel, WifiRxStart, FillTxPacket, mac_init, phy_init_pwr_print, bt_track_tx_power, _xtos_ints_off, _xtos_ints_on, inquiry, inquiry_scan, page, page_scan, le_adv, le_advscan, le_adv_test, le_advscan_test, adv_scan_test, encrypt | Data refs: .rodata.str1.4, FillTxPacket, READ_SPI_INIT_PARAM, RFChannelSel, UartGetCmdLn, WifiRxStart, WifiTxStart, _xtos_ints_off, _xtos_ints_on, adctrig, adv_scan_test, bt_force_tx_tone, bt_track_tx_power, cmd_parse, cmd_polling_start, cmd_polling_test, coex_bt_high_prio, command, encrypt, ets_isr_unmask, fcc_bt_en, fcc_le_tx, fcc_le_tx_syncw, fcc_tx, fe_force_tx_tone, force_bt_mode, force_wifi_mode, force_wifi_toggle, g_phyFuns, gpio_input_get, gpio_input_get_high, gpio_output_set, gpio_output_set_high, inquiry, inquiry_scan, le_adv, le_adv_test, le_advscan, le_advscan_test, mac_init, pString, page, page_scan, para_array, para_num, phy_init_pwr_print, phy_printf, rf_rw_init, rw_inq_cmd, rw_inq_scan_cmd, rw_le_rx_per_syncw, rw_le_rx_per_syncw_polling, rw_le_rx_per_syncw_polling_stop, rw_le_rx_per_syncw_rssi, rw_le_tx, rw_le_tx_hoppe_syncw, rw_le_tx_nohoppe, rw_mst_cmd, rw_page_cmd, rw_page_scan_cmd, rw_rx_dump, rw_rx_per, rw_rx_per_ulap, rw_rx_per_ulap_rssi, rw_tx_test, strcmp, t_force_wifi, unforce_wifi_mode, wifi_init_bt | MMIO: 0x3ff5c0a4, 0x60033c68, 0x60033d38
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_autotest(void)
{
    /* DWARF locals: u32 result@l4723, u32 i@l4723, struct rwip_rf_api api@l4725, u32 rslt@l4904 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_autotest> (1113 insns) + DWARF line rows for bt_rw_testmode.c:4722.
     * Ordered callee relocs: ets_isr_unmask, wifi_init_bt, coex_bt_high_prio, phy_printf, rf_rw_init, UartGetCmdLn, cmd_parse, strcmp, WifiTxStart, force_wifi_mode, force_wifi_toggle, unforce_wifi_mode, force_bt_mode, adctrig, rw_tx_test, fe_force_tx_tone, bt_force_tx_tone, fcc_tx, fcc_le_tx, fcc_le_tx_syncw, rw_le_tx_hoppe_syncw, fcc_bt_en, rw_le_tx, rw_le_tx_nohoppe, rw_rx_per, rw_rx_per_ulap, rw_rx_per_ulap_rssi, rw_le_rx_per_syncw, rw_le_rx_per_syncw_rssi, rw_rx_dump, rw_inq_cmd, rw_inq_scan_cmd, rw_page_scan_cmd, rw_page_cmd, rw_mst_cmd, cmd_polling_test, cmd_polling_start, rw_le_rx_per_syncw_polling, rw_le_rx_per_syncw_polling_stop, READ_SPI_INIT_PARAM, gpio_output_set, gpio_output_set_high, gpio_input_get, gpio_input_get_high, RFChannelSel, WifiRxStart, FillTxPacket, mac_init, phy_init_pwr_print, bt_track_tx_power, _xtos_ints_off, _xtos_ints_on, inquiry, inquiry_scan, page, page_scan, le_adv, le_advscan, le_adv_test, le_advscan_test, adv_scan_test, encrypt.
     */
}

/* rw_bb_ac_refesh bt_rw_testmode.c:1761 @ bt_rw_testmode.o size 79B [dwarf-sig-decl]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ff51030, 0x3ff51038, 0x3ff51050
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bb_ac_refesh(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bb_ac_refesh> (29 insns) + DWARF line rows for bt_rw_testmode.c:1761.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_bb_rx_refesh bt_rw_testmode.c:1771 @ bt_rw_testmode.o size 22B [dwarf-sig-decl]
 * Calls: .text.rw_bb_rx_refesh$part$2+0x8 | Data refs: (none) | MMIO: 0x3ff51030
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bb_rx_refesh(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bb_rx_refesh> (8 insns) + DWARF line rows for bt_rw_testmode.c:1771.
     * Ordered callee relocs: .text.rw_bb_rx_refesh$part$2+0x8.
     */
}

/* rw_bb_rx_refesh$part$2 bt_rw_testmode.c:1771 @ bt_rw_testmode.o size 30B [dwarf-sig-base-decl]
 * Calls: bt_track_pll_cap | Data refs: bt_track_pll_cap | MMIO: 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bb_rx_refesh$part$2(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bb_rx_refesh$part$2> (11 insns) + DWARF line rows for bt_rw_testmode.c:1771.
     * Ordered callee relocs: bt_track_pll_cap.
     */
}

/* rw_bb_tx_refesh bt_rw_testmode.c:1780 @ bt_rw_testmode.o size 22B [dwarf-sig-decl]
 * Calls: .text.rw_bb_tx_refesh$part$3+0xc | Data refs: (none) | MMIO: 0x3ff51030
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bb_tx_refesh(void)
{
    /* DWARF locals: u32 bt_tx_num@l1781 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bb_tx_refesh> (8 insns) + DWARF line rows for bt_rw_testmode.c:1780.
     * Ordered callee relocs: .text.rw_bb_tx_refesh$part$3+0xc.
     */
}

/* rw_bb_tx_refesh$part$3 bt_rw_testmode.c:1780 @ bt_rw_testmode.o size 39B [dwarf-sig-base-decl]
 * Calls: bt_track_pll_cap | Data refs: bt_track_pll_cap, bt_tx_num | MMIO: 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bb_tx_refesh$part$3(void)
{
    /* DWARF locals: u32 bt_tx_num@l1781 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bb_tx_refesh$part$3> (15 insns) + DWARF line rows for bt_rw_testmode.c:1780.
     * Ordered callee relocs: bt_track_pll_cap.
     */
}

/* rw_bch_gen bt_rw_testmode.c:118 @ bt_rw_testmode.o size 110B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bch_gen(u32 lap, u32 * bchl, u32 * bchh)
{
    (void)lap;
    (void)bchl;
    (void)bchh;
    /* DWARF locals: u32 a@l119, u32 pl@l120, u32 ph@l121, u32 xw@l122, u32 xwh@l123, u32 xwl@l124, u32 gh@l125, u32 gl@l126, u32 gmb@l129 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bch_gen> (37 insns) + DWARF line rows for bt_rw_testmode.c:118.
     */
}

/* rw_bch_gen_test bt_rw_testmode.c:153 @ bt_rw_testmode.o size 46B [dwarf-sig]
 * Calls: rw_bch_gen, phy_printf | Data refs: .rodata.str1.4, phy_printf, rw_bch_gen | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bch_gen_test(void)
{
    /* DWARF locals: u32 lap@l154, u32 bchl@l155, u32 bchh@l155, u32 acl@l157, u32 ach@l158 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bch_gen_test> (17 insns) + DWARF line rows for bt_rw_testmode.c:153.
     * Ordered callee relocs: rw_bch_gen, phy_printf.
     */
}

/* rw_bt_func_dut bt_rw_testmode.c:4518 @ bt_rw_testmode.o size 316B [dwarf-sig]
 * Calls: phy_printf, rw_test_init, rw_tx_buf_init, rw_bt_core_on, rw_bch_gen, rw_dut_try_con, rw_dut_con | Data refs: .rodata.str1.4, phy_printf, rw_bch_gen, rw_bt_core_on, rw_dut_con, rw_dut_try_con, rw_test_init, rw_tx_buf_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bt_func_dut(void)
{
    /* DWARF locals: u32 bchl@l4519, u32 bchh@l4519, u32 mbchl@l4519, u32 mbchh@l4519, u32 clknos@l4519, u32 bitos@l4519, u32 i@l4519, u32 mulap@l4519, u32 mnap@l4519, u32 nfrm@l4520, u32 nduttx@l4520, u32 ndutrx@l4520, u32 ntesttx@l4520, u32 ntestrx@l4520 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bt_func_dut> (116 insns) + DWARF line rows for bt_rw_testmode.c:4518.
     * Ordered callee relocs: phy_printf, rw_test_init, rw_tx_buf_init, rw_bt_core_on, rw_bch_gen, rw_dut_try_con, rw_dut_con.
     */
}

/* rw_bt_func_test_dut bt_rw_testmode.c:4502 @ bt_rw_testmode.o size 206B [dwarf-sig]
 * Calls: rw_bch_gen, rw_tester_try_con, rw_tester_con | Data refs: bt_dut_param, rw_bch_gen, rw_tester_con, rw_tester_try_con | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_bt_func_test_dut(u32 ulap, u32 nap, u32 freq, u32 n, u32 * nslvtx, u32 * nslvrx, u32 * ntx, u32 * nrx, u32 * nrxac, u32 * nrxall, s8 * con_rssi_max, s8 * con_rssi_min, s8 * con_rssi_avg, s8 * tester_rssi_max, s8 * tester_rssi_min, s8 * tester_rssi_avg)
{
    (void)ulap;
    (void)nap;
    (void)freq;
    (void)n;
    (void)nslvtx;
    (void)nslvrx;
    (void)ntx;
    (void)nrx;
    (void)nrxac;
    (void)nrxall;
    (void)con_rssi_max;
    (void)con_rssi_min;
    (void)con_rssi_avg;
    (void)tester_rssi_max;
    (void)tester_rssi_min;
    (void)tester_rssi_avg;
    /* DWARF locals: u32 bchl@l4504, u32 bchh@l4504, u32 mbchl@l4504, u32 mbchh@l4504, u32 i@l4504, s8 try_rssi@l4505 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bt_func_test_dut> (79 insns) + DWARF line rows for bt_rw_testmode.c:4502.
     * Ordered callee relocs: rw_bch_gen, rw_tester_try_con, rw_tester_con.
     */
}

/* rw_bt_func_test_init bt_rw_testmode.c:4551 @ bt_rw_testmode.o size 37B [dwarf-sig]
 * Calls: force_bt_mode, rf_rw_init, rw_test_init, rw_tx_buf_init, rw_bt_core_on | Data refs: force_bt_mode, rf_rw_init, rw_bt_core_on, rw_test_init, rw_tx_buf_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bt_func_test_init(void)
{
    /* DWARF locals: struct rwip_rf_api api@l4552 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bt_func_test_init> (13 insns) + DWARF line rows for bt_rw_testmode.c:4551.
     * Ordered callee relocs: force_bt_mode, rf_rw_init, rw_test_init, rw_tx_buf_init, rw_bt_core_on.
     */
}

/* rw_bt_func_test_tester bt_rw_testmode.c:4560 @ bt_rw_testmode.o size 275B [dwarf-sig]
 * Calls: rw_bch_gen, rw_dut_try_con, GetStopCmd, rw_dut_con | Data refs: GetStopCmd, bt_tester_param, rw_bch_gen, rw_dut_con, rw_dut_try_con | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bt_func_test_tester(u32 freq0, u32 freq1, u32 n)
{
    (void)freq0;
    (void)freq1;
    (void)n;
    /* DWARF locals: u32 bchl@l4562, u32 bchh@l4562, u32 mbchl@l4562, u32 mbchh@l4562, u32 i@l4562, u32 clknos@l4562, u32 bitos@l4562, u32 mulap@l4562, u32 mnap@l4562, u32 nfrm@l4562, u32 nduttx@l4562, u32 ndutrx@l4562, u32 ntx@l4562, u32 nrx@l4562, u32 clknos_old@l4562, u32 bitos_old@l4562 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bt_func_test_tester> (102 insns) + DWARF line rows for bt_rw_testmode.c:4560.
     * Ordered callee relocs: rw_bch_gen, rw_dut_try_con, GetStopCmd, rw_dut_con.
     */
}

/* rw_bt_func_tester bt_rw_testmode.c:4468 @ bt_rw_testmode.o size 343B [dwarf-sig]
 * Calls: phy_printf, rw_test_init, rw_tx_buf_init, rw_bt_core_on, rw_bch_gen, rw_tester_try_con, rw_tester_con | Data refs: .rodata.str1.4, phy_printf, rw_bch_gen, rw_bt_core_on, rw_test_init, rw_tester_con, rw_tester_try_con, rw_tx_buf_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bt_func_tester(void)
{
    /* DWARF locals: u32 bchl@l4469, u32 bchh@l4469, u32 mbchl@l4469, u32 mbchh@l4469, u32 i@l4469, u32 nfrm@l4470, u32 nduttx@l4470, u32 ndutrx@l4470, u32 ntesttx@l4470, u32 ntestrx@l4470, u32 ntestrxa@l4470, u32 ntestrxac@l4470, s8 try_rssi@l4471, s8 con_rssi_max@l4471, s8 con_rssi_min@l4471, s8 con_rssi_avg@l4471 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bt_func_tester> (126 insns) + DWARF line rows for bt_rw_testmode.c:4468.
     * Ordered callee relocs: phy_printf, rw_test_init, rw_tx_buf_init, rw_bt_core_on, rw_bch_gen, rw_tester_try_con, rw_tester_con.
     */
}

/* rw_bt_rxdone bt_rw_testmode.c:1711 @ bt_rw_testmode.o size 19B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_bt_rxdone(u32 desc_addr)
{
    (void)desc_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bt_rxdone> (7 insns) + DWARF line rows for bt_rw_testmode.c:1711.
     */
}

/* rw_bt_rxstat_unpack bt_rw_testmode.c:1693 @ bt_rw_testmode.o size 79B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bt_rxstat_unpack(u32 desc_addr, u32 * rxlinklbl, u32 * rxeirstat, u32 * rxguarderr, u32 * rxbadlt, u32 * rxfecerr, u32 * rxseqerr, u32 * rxmicerr, u32 * rxcrcerr, u32 * rxhecerr, u32 * rxsyncerr)
{
    (void)desc_addr;
    (void)rxlinklbl;
    (void)rxeirstat;
    (void)rxguarderr;
    (void)rxbadlt;
    (void)rxfecerr;
    (void)rxseqerr;
    (void)rxmicerr;
    (void)rxcrcerr;
    (void)rxhecerr;
    (void)rxsyncerr;
    /* DWARF locals: u32 localVal@l1697 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bt_rxstat_unpack> (32 insns) + DWARF line rows for bt_rw_testmode.c:1693.
     */
}

/* rw_bt_rxundone bt_rw_testmode.c:1714 @ bt_rw_testmode.o size 30B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_bt_rxundone(u32 desc_addr)
{
    (void)desc_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_bt_rxundone> (11 insns) + DWARF line rows for bt_rw_testmode.c:1714.
     */
}

/* rw_clkn bt_rw_testmode.c:4058 @ bt_rw_testmode.o size 45B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x6003101c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_clkn(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_clkn> (16 insns) + DWARF line rows for bt_rw_testmode.c:4058.
     */
}

/* rw_cs_get_rxbit bt_rw_testmode.c:1239 @ bt_rw_testmode.o size 24B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0054
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_cs_get_rxbit(u32 ptr)
{
    (void)ptr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_cs_get_rxbit> (9 insns) + DWARF line rows for bt_rw_testmode.c:1239.
     */
}

/* rw_cs_get_rxclkn bt_rw_testmode.c:1235 @ bt_rw_testmode.o size 37B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0050, 0x3ffb0054
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_cs_get_rxclkn(u32 ptr)
{
    (void)ptr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_cs_get_rxclkn> (14 insns) + DWARF line rows for bt_rw_testmode.c:1235.
     */
}

/* rw_cs_set_freq bt_rw_testmode.c:1226 @ bt_rw_testmode.o size 30B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_cs_set_freq(u32 addr, u32 freq)
{
    (void)addr;
    (void)freq;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_cs_set_freq> (11 insns) + DWARF line rows for bt_rw_testmode.c:1226.
     */
}

/* rw_cs_set_txdesc bt_rw_testmode.c:1230 @ bt_rw_testmode.o size 27B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_cs_set_txdesc(u32 addr, u32 desc)
{
    (void)addr;
    (void)desc;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_cs_set_txdesc> (10 insns) + DWARF line rows for bt_rw_testmode.c:1230.
     */
}

/* rw_debug_freq bt_rw_testmode.c:2352 @ bt_rw_testmode.o size 87B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60031000, 0x600310a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_debug_freq(u32 tx_freq, u32 rx_freq)
{
    (void)tx_freq;
    (void)rx_freq;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_debug_freq> (32 insns) + DWARF line rows for bt_rw_testmode.c:2352.
     */
}

/* rw_dm_activate bt_rw_testmode.c:191 @ bt_rw_testmode.o size 57B [dwarf-sig]
 * Calls: mac_write | Data refs: mac_write | MMIO: 0x600311e0, 0x60031390
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_dm_activate(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_dm_activate> (21 insns) + DWARF line rows for bt_rw_testmode.c:191.
     * Ordered callee relocs: mac_write.
     */
}

/* rw_dut_con bt_rw_testmode.c:4220 @ bt_rw_testmode.o size 853B [dwarf-sig]
 * Calls: rw_init_cs, rw_dut_timing_refresh | Data refs: rw_dut_timing_refresh, rw_init_cs | MMIO: 0x3ffb0000, 0x3ffb0200, 0x3ffb0204, 0x3ffb0254, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x3ffb0b00, 0x3ffb0b04, 0x60031014, 0x60031018, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_dut_con(u32 ulap, u32 nap, u32 bchl, u32 bchh, u32 hoppe, u32 freq, u32 whdsb, u32 edr, u32 type, u32 len, u32 et_mask, u32 * nfrm, u32 * nduttx, u32 * ndutrx, u32 * ntesttx, u32 * ntestrx, u32 n, u32 nfrmmax, u32 * clknos, u32 * bitos, u32 txpwr)
{
    (void)ulap;
    (void)nap;
    (void)bchl;
    (void)bchh;
    (void)hoppe;
    (void)freq;
    (void)whdsb;
    (void)edr;
    (void)type;
    (void)len;
    (void)et_mask;
    (void)nfrm;
    (void)nduttx;
    (void)ndutrx;
    (void)ntesttx;
    (void)ntestrx;
    (void)n;
    (void)nfrmmax;
    (void)clknos;
    (void)bitos;
    (void)txpwr;
    /* DWARF locals: u32 i@l4222, u32 rx_status@l4222, u32 entry@l4222, u32 rw_rxlinklbl@l4223, u32 rw_rxeirstat@l4223, u32 rw_rxguarderr@l4223, u32 rw_rxbadlt@l4223, u32 rw_rxfecerr@l4223, u32 rw_rxseqerr@l4223, u32 rw_rxmicerr@l4223, u32 rw_rxcrcerr@l4224, u32 rw_rxhecerr@l4224, u32 rw_rxsyncerr@l4224, u32 ptype@l4224, u32 rxbit@l4224, s32 rssi_now@l4225 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_dut_con> (319 insns) + DWARF line rows for bt_rw_testmode.c:4220.
     * Ordered callee relocs: rw_init_cs, rw_dut_timing_refresh.
     */
}

/* rw_dut_timing_refresh bt_rw_testmode.c:4085 @ bt_rw_testmode.o size 104B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_dut_timing_refresh(u32 * clknos, u32 * bitos, u32 rxbit)
{
    (void)clknos;
    (void)bitos;
    (void)rxbit;
    /* DWARF locals: s32 bitos_full@l4086, s32 delta@l4087, s32 rxbit_full@l4087, s32 bitos_pre@l4087 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_dut_timing_refresh> (42 insns) + DWARF line rows for bt_rw_testmode.c:4085.
     */
}

/* rw_dut_timing_refresh_cs bt_rw_testmode.c:4125 @ bt_rw_testmode.o size 63B [dwarf-sig-decl]
 * Calls: rw_dut_timing_refresh | Data refs: rw_dut_timing_refresh | MMIO: 0x3ffb0000, 0x3ffb0004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_dut_timing_refresh_cs(u32 ptr, u32 * clknos, u32 * bitos, u32 rxbit, u32 refresh)
{
    (void)ptr;
    (void)clknos;
    (void)bitos;
    (void)rxbit;
    (void)refresh;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_dut_timing_refresh_cs> (25 insns) + DWARF line rows for bt_rw_testmode.c:4125.
     * Ordered callee relocs: rw_dut_timing_refresh.
     */
}

/* rw_dut_try_con bt_rw_testmode.c:4134 @ bt_rw_testmode.o size 743B [dwarf-sig]
 * Calls: rw_init_cs | Data refs: ifreq, rw_init_cs | MMIO: 0x3ffb0000, 0x3ffb0250, 0x3ffb0254, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb0b00, 0x3ffb0b04, 0x3ffb0b08, 0x60031014, 0x60031018, 0x6003101c, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_dut_try_con(u32 ulap, u32 nap, u32 bchl, u32 bchh, u32 freq, u32 freq1, u32 t, u32 * clknos, u32 * bitos, u32 nmin, u32 nmax, u32 * mulap, u32 * mnap)
{
    (void)ulap;
    (void)nap;
    (void)bchl;
    (void)bchh;
    (void)freq;
    (void)freq1;
    (void)t;
    (void)clknos;
    (void)bitos;
    (void)nmin;
    (void)nmax;
    (void)mulap;
    (void)mnap;
    /* DWARF locals: u32 i@l4135, u32 rx_status@l4135, u32 entry@l4135, u32 carry@l4135, u32 ptype@l4135, u32 freq_@l4135, u32 rxclkn@l4136, u32 rxbit@l4136, u32 fhsclkn@l4136, u32 npac@l4136, u32 et_mask@l4136, u32 nfrm@l4136, u32 rw_rxlinklbl@l4137, u32 rw_rxeirstat@l4137, u32 rw_rxguarderr@l4137, u32 rw_rxbadlt@l4137 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_dut_try_con> (284 insns) + DWARF line rows for bt_rw_testmode.c:4134.
     * Ordered callee relocs: rw_init_cs.
     */
}

/* rw_em_diag_print bt_rw_testmode.c:2303 @ bt_rw_testmode.o size 99B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, em_diag_last, em_diag_print_start, phy_printf | MMIO: 0x60031050, 0x60031054
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_em_diag_print(void)
{
    /* DWARF locals: u32 print@l2304, u32 em_diag@l2307 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_em_diag_print> (37 insns) + DWARF line rows for bt_rw_testmode.c:2303.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_em_print bt_rw_testmode.c:2287 @ bt_rw_testmode.o size 55B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, em_data_last, em_print_start, phy_printf | MMIO: 0x3ffb0004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_em_print(void)
{
    /* DWARF locals: u32 print@l2288, u32 em_data@l2289 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_em_print> (21 insns) + DWARF line rows for bt_rw_testmode.c:2287.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_error_print bt_rw_testmode.c:2211 @ bt_rw_testmode.o size 63B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, error_data_last, error_print_start, phy_printf | MMIO: 0x60031060
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_error_print(void)
{
    /* DWARF locals: u32 print@l2212, u32 error_data@l2213 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_error_print> (23 insns) + DWARF line rows for bt_rw_testmode.c:2211.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_et_csb_init bt_rw_testmode.c:387 @ bt_rw_testmode.o size 148B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000, 0x3ffb0004, 0x3ffb0008, 0x3ffb000c, 0x3ffb0010, 0x3ffb0014, 0x3ffb0018, 0x3ffb001c, 0x3ffb0020, 0x3ffb0024, 0x3ffb0028, 0x3ffb002c, 0x3ffb0030, 0x3ffb0034, 0x3ffb0038, 0x3ffb003c, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_et_csb_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_et_csb_init> (56 insns) + DWARF line rows for bt_rw_testmode.c:387.
     */
}

/* rw_et_fill bt_rw_testmode.c:803 @ bt_rw_testmode.o size 65B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_et_fill(u32 mask, u32 cs_addr)
{
    (void)mask;
    (void)cs_addr;
    /* DWARF locals: u32 i@l804, u32 mask_@l805 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_et_fill> (24 insns) + DWARF line rows for bt_rw_testmode.c:803.
     */
}

/* rw_et_init bt_rw_testmode.c:201 @ bt_rw_testmode.o size 148B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000, 0x3ffb0004, 0x3ffb0008, 0x3ffb000c, 0x3ffb0010, 0x3ffb0014, 0x3ffb0018, 0x3ffb001c, 0x3ffb0020, 0x3ffb0024, 0x3ffb0028, 0x3ffb002c, 0x3ffb0030, 0x3ffb0034, 0x3ffb0038, 0x3ffb003c, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_et_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_et_init> (56 insns) + DWARF line rows for bt_rw_testmode.c:201.
     */
}

/* rw_et_off bt_rw_testmode.c:574 @ bt_rw_testmode.o size 30B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_et_off(void)
{
    /* DWARF locals: u32 i@l575 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_et_off> (12 insns) + DWARF line rows for bt_rw_testmode.c:574.
     */
}

/* rw_et_on bt_rw_testmode.c:604 @ bt_rw_testmode.o size 149B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000, 0x3ffb0004, 0x3ffb0008, 0x3ffb000c, 0x3ffb0010, 0x3ffb0014, 0x3ffb0018, 0x3ffb001c, 0x3ffb0020, 0x3ffb0024, 0x3ffb0028, 0x3ffb002c, 0x3ffb0030, 0x3ffb0034, 0x3ffb0038, 0x3ffb003c, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_et_on(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_et_on> (56 insns) + DWARF line rows for bt_rw_testmode.c:604.
     */
}

/* rw_et_on_mask bt_rw_testmode.c:790 @ bt_rw_testmode.o size 57B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_et_on_mask(u32 mask)
{
    (void)mask;
    /* DWARF locals: u32 i@l794 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_et_on_mask> (21 insns) + DWARF line rows for bt_rw_testmode.c:790.
     */
}

/* rw_et_one bt_rw_testmode.c:596 @ bt_rw_testmode.o size 41B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_et_one(u32 one)
{
    (void)one;
    /* DWARF locals: u32 i@l597 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_et_one> (16 insns) + DWARF line rows for bt_rw_testmode.c:596.
     */
}

/* rw_fill_FHS_buf bt_rw_testmode.c:1666 @ bt_rw_testmode.o size 121B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000, 0x3ffb0004, 0x3ffb0008, 0x3ffb000c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_fill_FHS_buf(u32 ptr, u32 parity_l, u32 parity_h, u32 lap, u32 eir, u32 sr, u32 uap, u32 nap, u32 cod, u32 ltaddr)
{
    (void)ptr;
    (void)parity_l;
    (void)parity_h;
    (void)lap;
    (void)eir;
    (void)sr;
    (void)uap;
    (void)nap;
    (void)cod;
    (void)ltaddr;
    /* DWARF locals: u32 data@l1669 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_fill_FHS_buf> (44 insns) + DWARF line rows for bt_rw_testmode.c:1666.
     */
}

/* rw_fill_eir_buf bt_rw_testmode.c:1684 @ bt_rw_testmode.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: eir_payload | MMIO: 0x3ffb0000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_fill_eir_buf(u32 ptr)
{
    (void)ptr;
    /* DWARF locals: u32 i@l1685 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_fill_eir_buf> (12 insns) + DWARF line rows for bt_rw_testmode.c:1684.
     */
}

/* rw_frm_refresh bt_rw_testmode.c:1809 @ bt_rw_testmode.o size 24B [dwarf-sig-decl]
 * Calls: .text.rw_frm_refresh$part$5+0x34 | Data refs: (none) | MMIO: 0x60031014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_frm_refresh(u32 txdesc_refresh)
{
    (void)txdesc_refresh;
    /* DWARF locals: u32 entry@l1810, u32 i@l1811, u8 rate@l1812 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_frm_refresh> (9 insns) + DWARF line rows for bt_rw_testmode.c:1809.
     * Ordered callee relocs: .text.rw_frm_refresh$part$5+0x34.
     */
}

/* rw_frm_refresh$part$5 bt_rw_testmode.c:1809 @ bt_rw_testmode.o size 133B [dwarf-sig-base-decl]
 * Calls: GetStopCmd, rw_bt_core_off, phy_get_tx_rate, phy_printf | Data refs: .rodata.str1.4, GetStopCmd, frm_refresh_ind, phy_get_tx_rate, phy_printf, run_end, rw_bt_core_off | MMIO: 0x3ffb0000, 0x3ffb02a0, 0x3ffb02b0, 0x60031018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_frm_refresh$part$5(u32 txdesc_refresh)
{
    (void)txdesc_refresh;
    /* DWARF locals: u32 entry@l1810, u32 i@l1811, u8 rate@l1812 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_frm_refresh$part$5> (50 insns) + DWARF line rows for bt_rw_testmode.c:1809.
     * Ordered callee relocs: GetStopCmd, rw_bt_core_off, phy_get_tx_rate, phy_printf.
     */
}

/* rw_frm_refresh_check_rx bt_rw_testmode.c:1913 @ bt_rw_testmode.o size 223B [dwarf-sig-decl]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: 0x3ffb0000, 0x3ffb02a0, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02c4, 0x60031014, 0x60031018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_frm_refresh_check_rx(void)
{
    /* DWARF locals: u32 entry@l1914, u32 i@l1915, u8 rate@l1916, u32 rx_status@l1917, u32 ltaddr@l1917, u32 crcerr@l1917, u32 type@l1917, u32 len@l1917 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_frm_refresh_check_rx> (83 insns) + DWARF line rows for bt_rw_testmode.c:1913.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_frm_refresh_no_cmd bt_rw_testmode.c:1885 @ bt_rw_testmode.o size 178B [dwarf-sig]
 * Calls: rw_rx_status_print | Data refs: frm_refresh_ind, rw_rx_status_print | MMIO: 0x3ffb0000, 0x3ffb02a0, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02d0, 0x60031014, 0x60031018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_frm_refresh_no_cmd(u32 txdesc_refresh)
{
    (void)txdesc_refresh;
    /* DWARF locals: u32 entry@l1886, u32 i@l1887, u8 rate@l1888 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_frm_refresh_no_cmd> (66 insns) + DWARF line rows for bt_rw_testmode.c:1885.
     * Ordered callee relocs: rw_rx_status_print.
     */
}

/* rw_frm_refresh_pscan bt_rw_testmode.c:1851 @ bt_rw_testmode.o size 24B [dwarf-sig-decl]
 * Calls: .text.rw_frm_refresh_pscan$part$6+0x38 | Data refs: (none) | MMIO: 0x60031014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_frm_refresh_pscan(u32 txdesc_refresh)
{
    (void)txdesc_refresh;
    /* DWARF locals: u32 entry@l1852, u32 i@l1853, u8 rate@l1854 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_frm_refresh_pscan> (9 insns) + DWARF line rows for bt_rw_testmode.c:1851.
     * Ordered callee relocs: .text.rw_frm_refresh_pscan$part$6+0x38.
     */
}

/* rw_frm_refresh_pscan$part$6 bt_rw_testmode.c:1851 @ bt_rw_testmode.o size 169B [dwarf-sig-base-decl]
 * Calls: GetStopCmd, rw_bt_core_off, phy_get_tx_rate, phy_printf | Data refs: .rodata.str1.4, GetStopCmd, frm_refresh_ind, phy_get_tx_rate, phy_printf, run_end, rw_bt_core_off | MMIO: 0x3ffb0000, 0x3ffb0200, 0x3ffb02a0, 0x3ffb02b0, 0x60031018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_frm_refresh_pscan$part$6(u32 txdesc_refresh)
{
    (void)txdesc_refresh;
    /* DWARF locals: u32 entry@l1852, u32 i@l1853, u8 rate@l1854 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_frm_refresh_pscan$part$6> (63 insns) + DWARF line rows for bt_rw_testmode.c:1851.
     * Ordered callee relocs: GetStopCmd, rw_bt_core_off, phy_get_tx_rate, phy_printf.
     */
}

/* rw_fsm_print bt_rw_testmode.c:2167 @ bt_rw_testmode.o size 190B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.rw_fsm_print, .rodata.str1.4, fsm_data_last, fsm_print_start, phy_printf | MMIO: 0x60031050, 0x60031054
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_fsm_print(void)
{
    /* DWARF locals: u32 print@l2168, u32 fsm_data@l2171 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_fsm_print> (67 insns) + DWARF line rows for bt_rw_testmode.c:2167.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_get_FHS_clkn bt_rw_testmode.c:1677 @ bt_rw_testmode.o size 15B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_get_FHS_clkn(u32 ptr)
{
    (void)ptr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_get_FHS_clkn> (6 insns) + DWARF line rows for bt_rw_testmode.c:1677.
     */
}

/* rw_init_cs bt_rw_testmode.c:1172 @ bt_rw_testmode.o size 644B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0200, 0x3ffb0204, 0x3ffb0208, 0x3ffb020c, 0x3ffb0210, 0x3ffb0214, 0x3ffb0218, 0x3ffb021c, 0x3ffb0220, 0x3ffb0224, 0x3ffb0228, 0x3ffb022c, 0x3ffb0230, 0x3ffb0234, 0x3ffb0238, 0x3ffb023c, 0x3ffb0240, 0x3ffb0244, 0x3ffb0248, 0x3ffb024c, 0x3ffb0250, 0x3ffb0254, 0x3ffb0258, 0x3ffb025c, 0x3ffb0260, 0x3ffb026c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_cs(u32 format, u32 ltaddr, u32 edr, u32 whdsb, u32 bdaddrl, u32 bdaddrh, u32 bchl, u32 bchh, u32 txpwr, u32 hoppe_en, u32 freq, u32 tx_eir, u32 rxwide, u32 rxwinsz, u32 txdesc, u32 maxfrmtime, u32 rxthr)
{
    (void)format;
    (void)ltaddr;
    (void)edr;
    (void)whdsb;
    (void)bdaddrl;
    (void)bdaddrh;
    (void)bchl;
    (void)bchh;
    (void)txpwr;
    (void)hoppe_en;
    (void)freq;
    (void)tx_eir;
    (void)rxwide;
    (void)rxwinsz;
    (void)txdesc;
    (void)maxfrmtime;
    (void)rxthr;
    /* DWARF locals: u32 maxrxbuf@l1205 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_cs> (239 insns) + DWARF line rows for bt_rw_testmode.c:1172.
     */
}

/* rw_init_cs_inqscan bt_rw_testmode.c:826 @ bt_rw_testmode.o size 247B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0200, 0x3ffb0204, 0x3ffb0208, 0x3ffb020c, 0x3ffb0210, 0x3ffb0214, 0x3ffb0218, 0x3ffb021c, 0x3ffb0220, 0x3ffb0224, 0x3ffb0228, 0x3ffb022c, 0x3ffb0230, 0x3ffb0234, 0x3ffb0238, 0x3ffb023c, 0x3ffb0240, 0x3ffb0244, 0x3ffb0248, 0x3ffb024c, 0x3ffb0250, 0x3ffb0254, 0x3ffb0258, 0x3ffb025c, 0x3ffb0260, 0x3ffb026c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_cs_inqscan(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_cs_inqscan> (93 insns) + DWARF line rows for bt_rw_testmode.c:826.
     */
}

/* rw_init_cs_rx_test bt_rw_testmode.c:1057 @ bt_rw_testmode.o size 248B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0200, 0x3ffb0204, 0x3ffb0208, 0x3ffb020c, 0x3ffb0210, 0x3ffb0214, 0x3ffb0218, 0x3ffb021c, 0x3ffb0220, 0x3ffb0224, 0x3ffb0228, 0x3ffb022c, 0x3ffb0230, 0x3ffb0234, 0x3ffb0238, 0x3ffb023c, 0x3ffb0240, 0x3ffb0244, 0x3ffb0248, 0x3ffb024c, 0x3ffb0250, 0x3ffb0254, 0x3ffb0258, 0x3ffb025c, 0x3ffb0260, 0x3ffb026c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_cs_rx_test(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_cs_rx_test> (93 insns) + DWARF line rows for bt_rw_testmode.c:1057.
     */
}

/* rw_init_cs_tx_test bt_rw_testmode.c:941 @ bt_rw_testmode.o size 263B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0200, 0x3ffb0204, 0x3ffb0208, 0x3ffb020c, 0x3ffb0210, 0x3ffb0214, 0x3ffb0218, 0x3ffb021c, 0x3ffb0220, 0x3ffb0224, 0x3ffb0228, 0x3ffb022c, 0x3ffb0230, 0x3ffb0234, 0x3ffb0238, 0x3ffb023c, 0x3ffb0240, 0x3ffb0244, 0x3ffb0248, 0x3ffb024c, 0x3ffb0250, 0x3ffb0254, 0x3ffb0258, 0x3ffb025c, 0x3ffb0260, 0x3ffb026c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_cs_tx_test(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_cs_tx_test> (99 insns) + DWARF line rows for bt_rw_testmode.c:941.
     */
}

/* rw_init_encryt_space bt_rw_testmode.c:816 @ bt_rw_testmode.o size 39B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_encryt_space(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_encryt_space> (15 insns) + DWARF line rows for bt_rw_testmode.c:816.
     */
}

/* rw_init_rx_descryptor bt_rw_testmode.c:1317 @ bt_rw_testmode.o size 85B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_rx_descryptor(u32 desc_addr, u32 nxt_desc_addr, u32 aclbuf_addr, u32 lmpbuf_addr)
{
    (void)desc_addr;
    (void)nxt_desc_addr;
    (void)aclbuf_addr;
    (void)lmpbuf_addr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_rx_descryptor> (32 insns) + DWARF line rows for bt_rw_testmode.c:1317.
     */
}

/* rw_init_rx_descryptor0 bt_rw_testmode.c:1335 @ bt_rw_testmode.o size 45B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_rx_descryptor0(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_rx_descryptor0> (17 insns) + DWARF line rows for bt_rw_testmode.c:1335.
     */
}

/* rw_init_rx_descryptor1 bt_rw_testmode.c:1349 @ bt_rw_testmode.o size 45B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_rx_descryptor1(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_rx_descryptor1> (17 insns) + DWARF line rows for bt_rw_testmode.c:1349.
     */
}

/* rw_init_tx_aclbuffer0 bt_rw_testmode.c:1364 @ bt_rw_testmode.o size 688B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0300, 0x3ffb0304, 0x3ffb0308, 0x3ffb030c, 0x3ffb0310, 0x3ffb0314, 0x3ffb0318, 0x3ffb031c, 0x3ffb0320, 0x3ffb0324, 0x3ffb0328, 0x3ffb032c, 0x3ffb0330, 0x3ffb0334, 0x3ffb0338, 0x3ffb033c, 0x3ffb0340, 0x3ffb0344, 0x3ffb0348, 0x3ffb034c, 0x3ffb0350, 0x3ffb0354, 0x3ffb0358, 0x3ffb035c, 0x3ffb0360, 0x3ffb0364, 0x3ffb0368, 0x3ffb036c, 0x3ffb0370, 0x3ffb0374, 0x3ffb0378, 0x3ffb037c, 0x3ffb0380, 0x3ffb0384, 0x3ffb0388, 0x3ffb038c, 0x3ffb0390, 0x3ffb0394, 0x3ffb0398, 0x3ffb039c, 0x3ffb03a0, 0x3ffb03a4, 0x3ffb03a8, 0x3ffb03ac, 0x3ffb03b0, 0x3ffb03b4, 0x3ffb03b8, 0x3ffb03bc, 0x3ffb03c0, 0x3ffb03c4, 0x3ffb03c8, 0x3ffb03cc, 0x3ffb03d0, 0x3ffb03d4, 0x3ffb03d8, 0x3ffb03dc, 0x3ffb03e0, 0x3ffb03e4, 0x3ffb03e8, 0x3ffb03ec, 0x3ffb03f0, 0x3ffb03f4, 0x3ffb03f8, 0x3ffb03fc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_aclbuffer0(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_aclbuffer0> (251 insns) + DWARF line rows for bt_rw_testmode.c:1364.
     */
}

/* rw_init_tx_aclbuffer1 bt_rw_testmode.c:1434 @ bt_rw_testmode.o size 700B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0400, 0x3ffb0404, 0x3ffb0408, 0x3ffb040c, 0x3ffb0410, 0x3ffb0414, 0x3ffb0418, 0x3ffb041c, 0x3ffb0420, 0x3ffb0424, 0x3ffb0428, 0x3ffb042c, 0x3ffb0430, 0x3ffb0434, 0x3ffb0438, 0x3ffb043c, 0x3ffb0440, 0x3ffb0444, 0x3ffb0448, 0x3ffb044c, 0x3ffb0450, 0x3ffb0454, 0x3ffb0458, 0x3ffb045c, 0x3ffb0460, 0x3ffb0464, 0x3ffb0468, 0x3ffb046c, 0x3ffb0470, 0x3ffb0474, 0x3ffb0478, 0x3ffb047c, 0x3ffb0480, 0x3ffb0484, 0x3ffb0488, 0x3ffb048c, 0x3ffb0490, 0x3ffb0494, 0x3ffb0498, 0x3ffb049c, 0x3ffb04a0, 0x3ffb04a4, 0x3ffb04a8, 0x3ffb04ac, 0x3ffb04b0, 0x3ffb04b4, 0x3ffb04b8, 0x3ffb04bc, 0x3ffb04c0, 0x3ffb04c4, 0x3ffb04c8, 0x3ffb04cc, 0x3ffb04d0, 0x3ffb04d4, 0x3ffb04d8, 0x3ffb04dc, 0x3ffb04e0, 0x3ffb04e4, 0x3ffb04e8, 0x3ffb04ec, 0x3ffb04f0, 0x3ffb04f4, 0x3ffb04f8, 0x3ffb04fc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_aclbuffer1(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_aclbuffer1> (255 insns) + DWARF line rows for bt_rw_testmode.c:1434.
     */
}

/* rw_init_tx_descriptor bt_rw_testmode.c:1243 @ bt_rw_testmode.o size 122B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_descriptor(u32 ptr, u32 nxt_ptr, u32 seqn, u32 arqn, u32 flow, u32 type, u32 ltaddr, u32 length, u32 pflow, u32 llid, u32 aclbufptr, u32 lmpbufptr)
{
    (void)ptr;
    (void)nxt_ptr;
    (void)seqn;
    (void)arqn;
    (void)flow;
    (void)type;
    (void)ltaddr;
    (void)length;
    (void)pflow;
    (void)llid;
    (void)aclbufptr;
    (void)lmpbufptr;
    /* DWARF locals: u32 data0@l1245 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_descriptor> (44 insns) + DWARF line rows for bt_rw_testmode.c:1243.
     */
}

/* rw_init_tx_descriptor0 bt_rw_testmode.c:1270 @ bt_rw_testmode.o size 38B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_descriptor0(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_descriptor0> (14 insns) + DWARF line rows for bt_rw_testmode.c:1270.
     */
}

/* rw_init_tx_descriptor1 bt_rw_testmode.c:1293 @ bt_rw_testmode.o size 38B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_descriptor1(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_descriptor1> (14 insns) + DWARF line rows for bt_rw_testmode.c:1293.
     */
}

/* rw_init_tx_descriptor_dh1or2dh1_test bt_rw_testmode.c:1252 @ bt_rw_testmode.o size 55B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_descriptor_dh1or2dh1_test(u32 ptr, u32 nxt_ptr, u32 aclbufptr, u32 lmpbufptr)
{
    (void)ptr;
    (void)nxt_ptr;
    (void)aclbufptr;
    (void)lmpbufptr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_descriptor_dh1or2dh1_test> (20 insns) + DWARF line rows for bt_rw_testmode.c:1252.
     */
}

/* rw_init_tx_descriptor_dh3or3dh3_test bt_rw_testmode.c:1258 @ bt_rw_testmode.o size 55B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_descriptor_dh3or3dh3_test(u32 ptr, u32 nxt_ptr, u32 aclbufptr, u32 lmpbufptr)
{
    (void)ptr;
    (void)nxt_ptr;
    (void)aclbufptr;
    (void)lmpbufptr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_descriptor_dh3or3dh3_test> (20 insns) + DWARF line rows for bt_rw_testmode.c:1258.
     */
}

/* rw_init_tx_descriptor_dm1_test bt_rw_testmode.c:1264 @ bt_rw_testmode.o size 54B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_descriptor_dm1_test(u32 ptr, u32 nxt_ptr, u32 aclbufptr, u32 lmpbufptr)
{
    (void)ptr;
    (void)nxt_ptr;
    (void)aclbufptr;
    (void)lmpbufptr;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_descriptor_dm1_test> (20 insns) + DWARF line rows for bt_rw_testmode.c:1264.
     */
}

/* rw_init_tx_lmpbuffer0 bt_rw_testmode.c:1503 @ bt_rw_testmode.o size 688B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x3ffb070c, 0x3ffb0710, 0x3ffb0714, 0x3ffb0718, 0x3ffb071c, 0x3ffb0720, 0x3ffb0724, 0x3ffb0728, 0x3ffb072c, 0x3ffb0730, 0x3ffb0734, 0x3ffb0738, 0x3ffb073c, 0x3ffb0740, 0x3ffb0744, 0x3ffb0748, 0x3ffb074c, 0x3ffb0750, 0x3ffb0754, 0x3ffb0758, 0x3ffb075c, 0x3ffb0760, 0x3ffb0764, 0x3ffb0768, 0x3ffb076c, 0x3ffb0770, 0x3ffb0774, 0x3ffb0778, 0x3ffb077c, 0x3ffb0780, 0x3ffb0784, 0x3ffb0788, 0x3ffb078c, 0x3ffb0790, 0x3ffb0794, 0x3ffb0798, 0x3ffb079c, 0x3ffb07a0, 0x3ffb07a4, 0x3ffb07a8, 0x3ffb07ac, 0x3ffb07b0, 0x3ffb07b4, 0x3ffb07b8, 0x3ffb07bc, 0x3ffb07c0, 0x3ffb07c4, 0x3ffb07c8, 0x3ffb07cc, 0x3ffb07d0, 0x3ffb07d4, 0x3ffb07d8, 0x3ffb07dc, 0x3ffb07e0, 0x3ffb07e4, 0x3ffb07e8, 0x3ffb07ec, 0x3ffb07f0, 0x3ffb07f4, 0x3ffb07f8, 0x3ffb07fc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_lmpbuffer0(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_lmpbuffer0> (251 insns) + DWARF line rows for bt_rw_testmode.c:1503.
     */
}

/* rw_init_tx_lmpbuffer1 bt_rw_testmode.c:1569 @ bt_rw_testmode.o size 700B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ffb0800, 0x3ffb0804, 0x3ffb0808, 0x3ffb080c, 0x3ffb0810, 0x3ffb0814, 0x3ffb0818, 0x3ffb081c, 0x3ffb0820, 0x3ffb0824, 0x3ffb0828, 0x3ffb082c, 0x3ffb0830, 0x3ffb0834, 0x3ffb0838, 0x3ffb083c, 0x3ffb0840, 0x3ffb0844, 0x3ffb0848, 0x3ffb084c, 0x3ffb0850, 0x3ffb0854, 0x3ffb0858, 0x3ffb085c, 0x3ffb0860, 0x3ffb0864, 0x3ffb0868, 0x3ffb086c, 0x3ffb0870, 0x3ffb0874, 0x3ffb0878, 0x3ffb087c, 0x3ffb0880, 0x3ffb0884, 0x3ffb0888, 0x3ffb088c, 0x3ffb0890, 0x3ffb0894, 0x3ffb0898, 0x3ffb089c, 0x3ffb08a0, 0x3ffb08a4, 0x3ffb08a8, 0x3ffb08ac, 0x3ffb08b0, 0x3ffb08b4, 0x3ffb08b8, 0x3ffb08bc, 0x3ffb08c0, 0x3ffb08c4, 0x3ffb08c8, 0x3ffb08cc, 0x3ffb08d0, 0x3ffb08d4, 0x3ffb08d8, 0x3ffb08dc, 0x3ffb08e0, 0x3ffb08e4, 0x3ffb08e8, 0x3ffb08ec, 0x3ffb08f0, 0x3ffb08f4, 0x3ffb08f8, 0x3ffb08fc
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_init_tx_lmpbuffer1(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_init_tx_lmpbuffer1> (255 insns) + DWARF line rows for bt_rw_testmode.c:1569.
     */
}

/* rw_inq bt_rw_testmode.c:2591 @ bt_rw_testmode.o size 471B [dwarf-sig]
 * Calls: phy_printf, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_error_print, .text.rw_frm_refresh$part$5+0x34, rw_rx_refresh, rw_bb_ac_refesh | Data refs: .rodata.str1.4, phy_printf, rw_bb_ac_refesh, rw_bch_gen, rw_bch_gen_test, rw_bt_core_off, rw_bt_core_on, rw_dm_activate, rw_error_print, rw_et_init, rw_init_cs, rw_init_em_radio_table, rw_rx_refresh | MMIO: 0x3ffb0000, 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb02d0, 0x3ffb02d8, 0x3ffb02dc, 0x60031014, 0x60031018, 0x60031024, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_inq(void)
{
    /* DWARF locals: u32 bdaddrl@l2592, u32 dbaddrh@l2593, u32 bchl@l2609, u32 bchh@l2609, u32 m@l2628 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_inq> (177 insns) + DWARF line rows for bt_rw_testmode.c:2591.
     * Ordered callee relocs: phy_printf, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_error_print, .text.rw_frm_refresh$part$5+0x34, rw_rx_refresh, rw_bb_ac_refesh.
     */
}

/* rw_inq_cmd bt_rw_testmode.c:2646 @ bt_rw_testmode.o size 719B [dwarf-sig]
 * Calls: phy_printf, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_error_print, .text.rw_frm_refresh$part$5+0x34, rw_rx_refresh, rw_bb_ac_refesh | Data refs: .rodata.str1.4, eir_payload, phy_printf, rw_bb_ac_refesh, rw_bch_gen, rw_bch_gen_test, rw_bt_core_off, rw_bt_core_on, rw_dm_activate, rw_error_print, rw_et_init, rw_init_cs, rw_init_em_radio_table, rw_rx_refresh | MMIO: 0x3ffb0000, 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb02d0, 0x3ffb02d8, 0x3ffb02dc, 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x3ffb070c, 0x3ffb0800, 0x3ffb0804, 0x3ffb0808, 0x3ffb080c, 0x3ffb0810, 0x60031000, 0x60031014, 0x60031018, 0x6003102c, 0x600310a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_inq_cmd(u32 tx_freq, u32 rx_freq)
{
    (void)tx_freq;
    (void)rx_freq;
    /* DWARF locals: u32 bdaddrl@l2647, u32 dbaddrh@l2648, u32 bchl@l2664, u32 bchh@l2664 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_inq_cmd> (267 insns) + DWARF line rows for bt_rw_testmode.c:2646.
     * Ordered callee relocs: phy_printf, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_error_print, .text.rw_frm_refresh$part$5+0x34, rw_rx_refresh, rw_bb_ac_refesh.
     */
}

/* rw_inq_scan bt_rw_testmode.c:2359 @ bt_rw_testmode.o size 531B [dwarf-sig]
 * Calls: phy_printf, em_test, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_pcntl_fsm_tx_print, rw_error_print, .text.rw_frm_refresh$part$5+0x34 | Data refs: .rodata.str1.4, eir_payload, em_test, phy_printf, rw_bch_gen, rw_bch_gen_test, rw_bt_core_off, rw_bt_core_on, rw_dm_activate, rw_error_print, rw_et_init, rw_init_cs, rw_init_em_radio_table, rw_pcntl_fsm_tx_print | MMIO: 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x3ffb070c, 0x3ffb0800, 0x3ffb0804, 0x3ffb0808, 0x3ffb080c, 0x3ffb0810, 0x60031014, 0x60031018, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_inq_scan(void)
{
    /* DWARF locals: u32 bdaddrl@l2360, u32 dbaddrh@l2361, u32 bchl@l2377, u32 bchh@l2377 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_inq_scan> (198 insns) + DWARF line rows for bt_rw_testmode.c:2359.
     * Ordered callee relocs: phy_printf, em_test, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_pcntl_fsm_tx_print, rw_error_print, .text.rw_frm_refresh$part$5+0x34.
     */
}

/* rw_inq_scan_cmd bt_rw_testmode.c:2413 @ bt_rw_testmode.o size 615B [dwarf-sig]
 * Calls: phy_printf, em_test, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_pcntl_fsm_tx_print, rw_error_print, .text.rw_frm_refresh$part$5+0x34 | Data refs: .rodata.str1.4, eir_payload, em_test, phy_printf, rw_bch_gen, rw_bch_gen_test, rw_bt_core_off, rw_bt_core_on, rw_dm_activate, rw_error_print, rw_et_init, rw_init_cs, rw_init_em_radio_table, rw_pcntl_fsm_tx_print | MMIO: 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x3ffb070c, 0x3ffb0800, 0x3ffb0804, 0x3ffb0808, 0x3ffb080c, 0x3ffb0810, 0x60031000, 0x60031014, 0x60031018, 0x6003102c, 0x600310a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_inq_scan_cmd(u32 tx_freq, u32 rx_freq)
{
    (void)tx_freq;
    (void)rx_freq;
    /* DWARF locals: u32 bdaddrl@l2414, u32 dbaddrh@l2415, u32 bchl@l2431, u32 bchh@l2431 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_inq_scan_cmd> (229 insns) + DWARF line rows for bt_rw_testmode.c:2413.
     * Ordered callee relocs: phy_printf, em_test, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_pcntl_fsm_tx_print, rw_error_print, .text.rw_frm_refresh$part$5+0x34.
     */
}

/* rw_inq_test_init bt_rw_testmode.c:2935 @ bt_rw_testmode.o size 500B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, phy_bt_pll_track, phy_bt_power_track, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on | Data refs: .rodata.str1.4, PRBS9, phy_bt_pll_track, phy_bt_power_track, phy_printf, prbs9_gen, run_end, rw_bch_gen, rw_bt_core_on, rw_init_cs, rw_test_init | MMIO: 0x3ff4609c, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0700, 0x60031024, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_inq_test_init(u32 txpwr, u32 hoppe, u32 freq, u32 edr, u32 type, u32 length, u32 et_mask)
{
    (void)txpwr;
    (void)hoppe;
    (void)freq;
    (void)edr;
    (void)type;
    (void)length;
    (void)et_mask;
    /* DWARF locals: u32 txdesc0_diag@l2936, u32 txdesc0_diag_start@l2936, u32 bchl@l2936, u32 bchh@l2936, u32 i@l2936 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_inq_test_init> (188 insns) + DWARF line rows for bt_rw_testmode.c:2935.
     * Ordered callee relocs: phy_printf, prbs9_gen, phy_bt_pll_track, phy_bt_power_track, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on.
     */
}

/* rw_inq_tx_freq_print bt_rw_testmode.c:2227 @ bt_rw_testmode.o size 135B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, inq_tx_freqlast, phy_printf | MMIO: 0x60031050, 0x60031054
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_inq_tx_freq_print(u32 all)
{
    (void)all;
    /* DWARF locals: u32 print@l2228, u32 pcntl_fsm_data@l2231, u32 freq@l2233, u32 freq_rf@l2234 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_inq_tx_freq_print> (50 insns) + DWARF line rows for bt_rw_testmode.c:2227.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_le_em_diag_print bt_rw_testmode.c:2336 @ bt_rw_testmode.o size 99B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, le_em_diag_last, le_em_diag_print_start, phy_printf | MMIO: 0x60031250, 0x60031254
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_em_diag_print(void)
{
    /* DWARF locals: u32 print@l2337, u32 em_diag@l2340 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_le_em_diag_print> (37 insns) + DWARF line rows for bt_rw_testmode.c:2336.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_mst_cmd bt_rw_testmode.c:2527 @ bt_rw_testmode.o size 623B [dwarf-sig]
 * Calls: phy_printf, em_test, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_on, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_error_print, .text.rw_frm_refresh$part$5+0x34, rw_rx_refresh, rw_bb_ac_refesh | Data refs: .rodata.str1.4, eir_payload, em_test, phy_printf, rw_bb_ac_refesh, rw_bch_gen, rw_bch_gen_test, rw_bt_core_off, rw_bt_core_on, rw_dm_activate, rw_error_print, rw_et_on, rw_init_cs, rw_init_em_radio_table, rw_rx_refresh | MMIO: 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x3ffb070c, 0x3ffb0800, 0x3ffb0804, 0x3ffb0808, 0x3ffb080c, 0x3ffb0810, 0x60031000, 0x60031014, 0x60031018, 0x6003102c, 0x600310a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_mst_cmd(u32 debug_freq, u32 tx_freq, u32 rx_freq)
{
    (void)debug_freq;
    (void)tx_freq;
    (void)rx_freq;
    /* DWARF locals: u32 bdaddrl@l2528, u32 dbaddrh@l2529, u32 bchl@l2545, u32 bchh@l2545 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_mst_cmd> (232 insns) + DWARF line rows for bt_rw_testmode.c:2527.
     * Ordered callee relocs: phy_printf, em_test, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_on, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_error_print, .text.rw_frm_refresh$part$5+0x34, rw_rx_refresh, rw_bb_ac_refesh.
     */
}

/* rw_next_et_entry bt_rw_testmode.c:4066 @ bt_rw_testmode.o size 16B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_next_et_entry(u32 clkn)
{
    (void)clkn;
    /* DWARF locals: u32 mask_shift@l4068 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_next_et_entry> (6 insns) + DWARF line rows for bt_rw_testmode.c:4066.
     */
}

/* rw_page_cmd bt_rw_testmode.c:2703 @ bt_rw_testmode.o size 731B [dwarf-sig]
 * Calls: phy_printf, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_csb_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_pcntl_fsm_tx_pld_print, rw_error_print, .text.rw_frm_refresh$part$5+0x34, rw_rx_refresh, rw_bb_ac_refesh | Data refs: .rodata.str1.4, eir_payload, phy_printf, rw_bb_ac_refesh, rw_bch_gen, rw_bch_gen_test, rw_bt_core_off, rw_bt_core_on, rw_dm_activate, rw_error_print, rw_et_csb_init, rw_init_cs, rw_init_em_radio_table, rw_pcntl_fsm_tx_pld_print, rw_rx_refresh | MMIO: 0x3ffb0000, 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb02d0, 0x3ffb02d8, 0x3ffb02dc, 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x3ffb070c, 0x3ffb0800, 0x3ffb0804, 0x3ffb0808, 0x3ffb080c, 0x3ffb0810, 0x60031000, 0x60031014, 0x60031018, 0x6003102c, 0x600310a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_page_cmd(u32 debug_freq, u32 tx_freq, u32 rx_freq)
{
    (void)debug_freq;
    (void)tx_freq;
    (void)rx_freq;
    /* DWARF locals: u32 bdaddrl@l2704, u32 dbaddrh@l2705, u32 bchl@l2721, u32 bchh@l2721 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_page_cmd> (271 insns) + DWARF line rows for bt_rw_testmode.c:2703.
     * Ordered callee relocs: phy_printf, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_csb_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_pcntl_fsm_tx_pld_print, rw_error_print, .text.rw_frm_refresh$part$5+0x34, rw_rx_refresh, rw_bb_ac_refesh.
     */
}

/* rw_page_scan_cmd bt_rw_testmode.c:2468 @ bt_rw_testmode.o size 616B [dwarf-sig]
 * Calls: phy_printf, em_test, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_csb_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_pcntl_fsm_tx_print, rw_error_print, .text.rw_frm_refresh_pscan$part$6+0x38 | Data refs: .rodata.str1.4, eir_payload, em_test, phy_printf, rw_bch_gen, rw_bch_gen_test, rw_bt_core_off, rw_bt_core_on, rw_dm_activate, rw_error_print, rw_et_csb_init, rw_init_cs, rw_init_em_radio_table, rw_pcntl_fsm_tx_print | MMIO: 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x3ffb070c, 0x3ffb0800, 0x3ffb0804, 0x3ffb0808, 0x3ffb080c, 0x3ffb0810, 0x60031000, 0x60031014, 0x60031018, 0x6003102c, 0x600310a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_page_scan_cmd(u32 debug_freq, u32 tx_freq, u32 rx_freq)
{
    (void)debug_freq;
    (void)tx_freq;
    (void)rx_freq;
    /* DWARF locals: u32 bdaddrl@l2469, u32 dbaddrh@l2470, u32 bchl@l2488, u32 bchh@l2488 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_page_scan_cmd> (230 insns) + DWARF line rows for bt_rw_testmode.c:2468.
     * Ordered callee relocs: phy_printf, em_test, rw_bch_gen_test, rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_et_csb_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_pcntl_fsm_tx_print, rw_error_print, .text.rw_frm_refresh_pscan$part$6+0x38.
     */
}

/* rw_pcntl_fsm_print bt_rw_testmode.c:1950 @ bt_rw_testmode.o size 440B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.rw_pcntl_fsm_print, .rodata.str1.4, pcntl_fsm_data_last, pcntl_fsm_print_start, phy_printf | MMIO: 0x60031050, 0x60031054
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_pcntl_fsm_print(void)
{
    /* DWARF locals: u32 print@l1951, u32 pcntl_fsm_data@l1954 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_pcntl_fsm_print> (151 insns) + DWARF line rows for bt_rw_testmode.c:1950.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_pcntl_fsm_tx_pld_print bt_rw_testmode.c:2113 @ bt_rw_testmode.o size 239B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.rw_pcntl_fsm_tx_pld_print, .rodata.str1.4, pcntl_fsm_data_last, pcntl_fsm_print_start, phy_printf | MMIO: 0x60031050, 0x60031054
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_pcntl_fsm_tx_pld_print(void)
{
    /* DWARF locals: u32 print@l2114, u32 pcntl_fsm_data@l2117 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_pcntl_fsm_tx_pld_print> (84 insns) + DWARF line rows for bt_rw_testmode.c:2113.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_pcntl_fsm_tx_print bt_rw_testmode.c:2052 @ bt_rw_testmode.o size 272B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.rw_pcntl_fsm_tx_print, .rodata.str1.4, pcntl_fsm_data_last, pcntl_fsm_print_start, phy_printf | MMIO: 0x60031050, 0x60031054
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_pcntl_fsm_tx_print(void)
{
    /* DWARF locals: u32 print@l2053, u32 pcntl_fsm_data@l2056 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_pcntl_fsm_tx_print> (95 insns) + DWARF line rows for bt_rw_testmode.c:2052.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_reg_diag_print bt_rw_testmode.c:2320 @ bt_rw_testmode.o size 47B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_reg_diag_print(u32 addr, u32 * diag_last, u32 * diag_print_start, u32 label)
{
    (void)addr;
    (void)diag_last;
    (void)diag_print_start;
    (void)label;
    /* DWARF locals: u32 diag_now@l2321, u32 print@l2322 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_reg_diag_print> (18 insns) + DWARF line rows for bt_rw_testmode.c:2320.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_rx_dump bt_rw_testmode.c:3934 @ bt_rw_testmode.o size 997B [dwarf-sig]
 * Calls: prbs9_gen, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, bt_bb_dump, ets_delay_us, phy_printf | Data refs: .rodata.str1.4, PRBS9, bt_bb_dump, ets_delay_us, phy_printf, prbs9_gen, rw_bch_gen, rw_bt_core_on, rw_init_cs, rw_test_init | MMIO: 0x3ff51098, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb02d0, 0x3ffb02d8, 0x3ffb02dc, 0x60031014, 0x60031018, 0x6003102c, 0x60033d90
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_rx_dump(u32 edr, u32 chan, u32 ulap, u32 ltaddr, u32 data_sel, u32 dump_len, u32 status_sel)
{
    (void)edr;
    (void)chan;
    (void)ulap;
    (void)ltaddr;
    (void)data_sel;
    (void)dump_len;
    (void)status_sel;
    /* DWARF locals: u32 cmd@l3935, u32 exit@l3935, u32 value@l3935, u32 noise@l3935, u32 pwr_in_band@l3935, u32 pwr_full_band@l3935, u32 gain@l3935, u32 bchl@l3935, u32 bchh@l3935, u32 entry@l3935, u32[] gain_fcs@l3936, u32 fcs_i@l3937, u32 i@l3962, u32 j@l3962, u32 success@l3962, u32 rx_status@l3963 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_dump> (364 insns) + DWARF line rows for bt_rw_testmode.c:3934.
     * Ordered callee relocs: prbs9_gen, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, bt_bb_dump, ets_delay_us, phy_printf.
     */
}

/* rw_rx_head_get bt_rw_testmode.c:1740 @ bt_rw_testmode.o size 55B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_head_get(u32 desc_addr, u32 * ptype, u32 * len, u32 * llid, s8 * rssi)
{
    (void)desc_addr;
    (void)ptype;
    (void)len;
    (void)llid;
    (void)rssi;
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_head_get> (21 insns) + DWARF line rows for bt_rw_testmode.c:1740.
     */
}

/* rw_rx_per bt_rw_testmode.c:3395 @ bt_rw_testmode.o size 1298B [dwarf-sig]
 * Calls: rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, phy_printf, .text.rw_bb_rx_refesh$part$2+0x8, ets_delay_us, GetStopCmd, get_bt_rx_rssi | Data refs: .rodata.str1.4, GetStopCmd, ets_delay_us, get_bt_rx_rssi, phy_printf, rw_bch_gen, rw_bt_core_on, rw_init_cs, rw_test_init | MMIO: 0x3ff51030, 0x3ff51050, 0x3ff51074, 0x3ff51078, 0x3ff51098, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb02d0, 0x3ffb02d8, 0x3ffb02dc, 0x60031014, 0x60031018, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_per(u32 edr, u32 chan)
{
    (void)edr;
    (void)chan;
    /* DWARF locals: u32 cmd@l3396, u32 exit@l3396, u32 value@l3396, u32 noise@l3396, u32 pwr_in_band@l3396, u32 pwr_full_band@l3396, u32 gain@l3396, u32 bchl@l3396, u32 bchh@l3396, u32 entry@l3396, u32[] gain_fcs@l3397, u32 fcs_i@l3398, u32 i@l3421, u32 total_p@l3424, u32 hec_ep@l3424, u32 rx_status@l3424 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_per> (478 insns) + DWARF line rows for bt_rw_testmode.c:3395.
     * Ordered callee relocs: rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, phy_printf, .text.rw_bb_rx_refesh$part$2+0x8, ets_delay_us, GetStopCmd, get_bt_rx_rssi.
     */
}

/* rw_rx_per_init bt_rw_testmode.c:3867 @ bt_rw_testmode.o size 503B [dwarf-sig]
 * Calls: rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, phy_printf | Data refs: .rodata.str1.4, phy_printf, rw_bch_gen, rw_bt_core_on, rw_init_cs, rw_test_init | MMIO: 0x3ff51098, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb02d0, 0x3ffb02d8, 0x3ffb02dc, 0x60031018, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_per_init(u32 edr, u32 chan)
{
    (void)edr;
    (void)chan;
    /* DWARF locals: u32 cmd@l3868, u32 exit@l3868, u32 value@l3868, u32 noise@l3868, u32 pwr_in_band@l3868, u32 pwr_full_band@l3868, u32 gain@l3868, u32 bchl@l3868, u32 bchh@l3868, u32 entry@l3868, u32[] gain_fcs@l3869, u32 fcs_i@l3870, u32 i@l3893 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_per_init> (189 insns) + DWARF line rows for bt_rw_testmode.c:3867.
     * Ordered callee relocs: rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, phy_printf.
     */
}

/* rw_rx_per_ulap bt_rw_testmode.c:3574 @ bt_rw_testmode.o size 1497B [dwarf-sig]
 * Calls: rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, prbs9_gen, phy_printf, .text.rw_bb_rx_refesh$part$2+0x8, rw_rx_prbs9_status, GetStopCmd, get_bt_rx_rssi | Data refs: .rodata.str1.4, GetStopCmd, PRBS9, btrx_result, btrx_valid, get_bt_rx_rssi, phy_printf, prbs9_gen, rw_bch_gen, rw_bt_core_on, rw_init_cs, rw_rx_prbs9_status, rw_test_init | MMIO: 0x3ff51030, 0x3ff51050, 0x3ff51074, 0x3ff51078, 0x3ff51098, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb02d0, 0x3ffb02d8, 0x3ffb02dc, 0x60031014, 0x60031018, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_per_ulap(u32 edr, u32 chan, u32 ulap, u32 ltaddr)
{
    (void)edr;
    (void)chan;
    (void)ulap;
    (void)ltaddr;
    /* DWARF locals: u32 cmd@l3575, u32 exit@l3575, u32 value@l3575, u32 noise@l3575, u32 pwr_in_band@l3575, u32 pwr_full_band@l3575, u32 gain@l3575, u32 bchl@l3575, u32 bchh@l3575, u32 entry@l3575, u32[] gain_fcs@l3576, u32 fcs_i@l3577, u32 i@l3600, u32 total_p@l3603, u32 hec_ep@l3603, u32 rx_status@l3603 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_per_ulap> (548 insns) + DWARF line rows for bt_rw_testmode.c:3574.
     * Ordered callee relocs: rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, prbs9_gen, phy_printf, .text.rw_bb_rx_refesh$part$2+0x8, rw_rx_prbs9_status, GetStopCmd, get_bt_rx_rssi.
     */
}

/* rw_rx_per_ulap_rssi bt_rw_testmode.c:3709 @ bt_rw_testmode.o size 1672B [dwarf-sig]
 * Calls: rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, prbs9_gen, phy_printf, .text.rw_bb_rx_refesh$part$2+0x8, ets_delay_us, rw_rx_prbs9_status, GetStopCmd, get_bt_rx_rssi | Data refs: .rodata.str1.4, GetStopCmd, PRBS9, ets_delay_us, get_bt_rx_rssi, phy_printf, prbs9_gen, rw_bch_gen, rw_bt_core_on, rw_init_cs, rw_rx_prbs9_status, rw_test_init | MMIO: 0x3ff51030, 0x3ff51050, 0x3ff51074, 0x3ff51078, 0x3ff51098, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb02d0, 0x3ffb02d8, 0x3ffb02dc, 0x60031014, 0x60031018, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_per_ulap_rssi(u32 edr, u32 chan, u32 ulap, u32 ltaddr)
{
    (void)edr;
    (void)chan;
    (void)ulap;
    (void)ltaddr;
    /* DWARF locals: u32 cmd@l3710, u32 exit@l3710, u32 value@l3710, u32 noise@l3710, u32 pwr_in_band@l3710, u32 pwr_full_band@l3710, u32 gain@l3710, u32 bchl@l3710, u32 bchh@l3710, u32 entry@l3710, u32[] gain_fcs@l3711, u32[] rssi_array@l3712, u32 rssi_n@l3713, u32 gain_record_start@l3714, u32 rssi_now@l3715, u32 rssi_max@l3715 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_per_ulap_rssi> (607 insns) + DWARF line rows for bt_rw_testmode.c:3709.
     * Ordered callee relocs: rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, prbs9_gen, phy_printf, .text.rw_bb_rx_refesh$part$2+0x8, ets_delay_us, rw_rx_prbs9_status, GetStopCmd, get_bt_rx_rssi.
     */
}

/* rw_rx_prbs9_status bt_rw_testmode.c:3510 @ bt_rw_testmode.o size 127B [dwarf-sig]
 * Calls: (none) | Data refs: PRBS9 | MMIO: 0x3ffb0000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_prbs9_status(u32 desc_addr, u32 * total_bits, u32 * err_bits)
{
    (void)desc_addr;
    (void)total_bits;
    (void)err_bits;
    /* DWARF locals: u32 rx_length@l3511, u32 buff_addr@l3512, u32 word_len@l3513, u32 byte_remain@l3514, u32 last_mask@l3515, u32 i@l3531, u32 rdata@l3531, u32 j@l3531 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_prbs9_status> (49 insns) + DWARF line rows for bt_rw_testmode.c:3510.
     */
}

/* rw_rx_refresh bt_rw_testmode.c:1754 @ bt_rw_testmode.o size 75B [dwarf-sig-decl]
 * Calls: rw_rx_status_print | Data refs: rw_rx_status_print | MMIO: 0x3ffb02c0, 0x3ffb02d0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_refresh(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_refresh> (28 insns) + DWARF line rows for bt_rw_testmode.c:1754.
     * Ordered callee relocs: rw_rx_status_print.
     */
}

/* rw_rx_rssi_get bt_rw_testmode.c:1748 @ bt_rw_testmode.o size 13B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
s8 rw_rx_rssi_get(u32 desc_addr)
{
    (void)desc_addr;
    /* DWARF locals: s8 rssi@l1750 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_rssi_get> (5 insns) + DWARF line rows for bt_rw_testmode.c:1748.
     */
}

/* rw_rx_status_print bt_rw_testmode.c:1718 @ bt_rw_testmode.o size 42B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_status_print(u32 desc_addr)
{
    (void)desc_addr;
    /* DWARF locals: u32 data@l1719, s8 rssi@l1720 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_status_print> (15 insns) + DWARF line rows for bt_rw_testmode.c:1718.
     * Ordered callee relocs: phy_printf.
     */
}

/* rw_rx_status_print_ bt_rw_testmode.c:1728 @ bt_rw_testmode.o size 33B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_rx_status_print_(u32 desc_addr)
{
    (void)desc_addr;
    /* DWARF locals: u32 data@l1729, s8 rssi@l1730, u32 llid@l1731, u32 len@l1732, u32 ptype@l1733 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_rx_status_print_> (13 insns) + DWARF line rows for bt_rw_testmode.c:1728.
     */
}

/* rw_set_current_rxdecriptor bt_rw_testmode.c:1662 @ bt_rw_testmode.o size 30B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_set_current_rxdecriptor(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_set_current_rxdecriptor> (11 insns) + DWARF line rows for bt_rw_testmode.c:1662.
     */
}

/* rw_set_inq_abtrain bt_rw_testmode.c:2584 @ bt_rw_testmode.o size 45B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60031024
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_set_inq_abtrain(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_set_inq_abtrain> (17 insns) + DWARF line rows for bt_rw_testmode.c:2584.
     */
}

/* rw_slp_test bt_rw_testmode.c:4595 @ bt_rw_testmode.o size 391B [dwarf-sig]
 * Calls: phy_printf, ets_delay_us, rtc_init_lite, pm_close_rf, rtc_slp_prep, rtc_sleep, rtc_set_cpu_freq, rtc_uart_div_modify | Data refs: .rodata.str1.4, ets_delay_us, phy_printf, pm_close_rf, rtc_init_lite, rtc_set_cpu_freq, rtc_sleep, rtc_slp_prep, rtc_uart_div_modify | MMIO: 0x3ff000d4, 0x3ff000d8, 0x3ff48038, 0x60031030, 0x60031034, 0x60031038, 0x6003103c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_slp_test(void)
{
    /* DWARF locals: u32 i@l4596, u32 slp@l4596, u32 cause@l4596, u32 dur@l4596 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_slp_test> (146 insns) + DWARF line rows for bt_rw_testmode.c:4595.
     * Ordered callee relocs: phy_printf, ets_delay_us, rtc_init_lite, pm_close_rf, rtc_slp_prep, rtc_sleep, rtc_set_cpu_freq, rtc_uart_div_modify.
     */
}

/* rw_test_init bt_rw_testmode.c:1641 @ bt_rw_testmode.o size 166B [dwarf-sig]
 * Calls: rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_init_tx_aclbuffer0, rw_init_tx_aclbuffer1 | Data refs: rw_bt_core_off, rw_dm_activate, rw_init_em_radio_table, rw_init_tx_aclbuffer0, rw_init_tx_aclbuffer1 | MMIO: 0x3ffb0000, 0x3ffb0160, 0x3ffb0164, 0x3ffb0168, 0x3ffb016c, 0x60031000, 0x60031018, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_test_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_test_init> (61 insns) + DWARF line rows for bt_rw_testmode.c:1641.
     * Ordered callee relocs: rw_bt_core_off, rw_init_em_radio_table, rw_dm_activate, rw_init_tx_aclbuffer0, rw_init_tx_aclbuffer1.
     */
}

/* rw_tester_con bt_rw_testmode.c:4361 @ bt_rw_testmode.o size 910B [dwarf-sig]
 * Calls: rw_init_cs | Data refs: rw_init_cs | MMIO: 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb0700, 0x3ffb0704, 0x3ffb0b00, 0x3ffb0b04, 0x3ffb0b08, 0x60031014, 0x60031018, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_tester_con(u32 ulap, u32 nap, u32 bchl, u32 bchh, u32 hoppe, u32 freq, u32 n, u32 whdsb, u32 edr, u32 type, u32 len, u32 et_mask, u32 * nduttx, u32 * ndutrx, u32 * ntesttx, u32 * ntestrx, u32 * testrxac, u32 * testrxa, u32 nfrmmax, s8 * rssi_max, s8 * rssi_min, s8 * rssi_avg, s8 * rssi_max_tester, s8 * rssi_min_tester, s8 * rssi_avg_tester, u32 txpwr)
{
    (void)ulap;
    (void)nap;
    (void)bchl;
    (void)bchh;
    (void)hoppe;
    (void)freq;
    (void)n;
    (void)whdsb;
    (void)edr;
    (void)type;
    (void)len;
    (void)et_mask;
    (void)nduttx;
    (void)ndutrx;
    (void)ntesttx;
    (void)ntestrx;
    (void)testrxac;
    (void)testrxa;
    (void)nfrmmax;
    (void)rssi_max;
    (void)rssi_min;
    (void)rssi_avg;
    (void)rssi_max_tester;
    (void)rssi_min_tester;
    (void)rssi_avg_tester;
    (void)txpwr;
    /* DWARF locals: u32 i@l4364, u32 rx_status@l4364, u32 entry@l4364, u32 rw_rxlinklbl@l4365, u32 rw_rxeirstat@l4365, u32 rw_rxguarderr@l4365, u32 rw_rxbadlt@l4365, u32 rw_rxfecerr@l4365, u32 rw_rxseqerr@l4365, u32 rw_rxmicerr@l4365, u32 rw_rxcrcerr@l4366, u32 rw_rxhecerr@l4366, u32 rw_rxsyncerr@l4366, u32 ptype@l4366, s32 rssi_sum@l4367, s32 rssi_now@l4367 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_tester_con> (342 insns) + DWARF line rows for bt_rw_testmode.c:4361.
     * Ordered callee relocs: rw_init_cs.
     */
}

/* rw_tester_try_con bt_rw_testmode.c:4296 @ bt_rw_testmode.o size 744B [dwarf-sig]
 * Calls: rw_init_cs | Data refs: rw_init_cs | MMIO: 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02c0, 0x3ffb02c8, 0x3ffb02cc, 0x3ffb0700, 0x3ffb0704, 0x3ffb0708, 0x60031014, 0x60031018, 0x6003101c, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rw_tester_try_con(u32 ulap, u32 nap, u32 mulap, u32 mnap, u32 bchl, u32 bchh, u32 freq, u32 n, u32 nmin, s8 * rssi)
{
    (void)ulap;
    (void)nap;
    (void)mulap;
    (void)mnap;
    (void)bchl;
    (void)bchh;
    (void)freq;
    (void)n;
    (void)nmin;
    (void)rssi;
    /* DWARF locals: u32 i@l4297, u32 rx_status@l4297, u32 entry@l4297, u32 con@l4297, u32 rw_rxlinklbl@l4298, u32 rw_rxeirstat@l4298, u32 rw_rxguarderr@l4298, u32 rw_rxbadlt@l4298, u32 rw_rxfecerr@l4298, u32 rw_rxseqerr@l4298, u32 rw_rxmicerr@l4298, u32 rw_rxcrcerr@l4299, u32 rw_rxhecerr@l4299, u32 rw_rxsyncerr@l4299, u32 clkn_now@l4318, u32 clkn_next@l4319 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_tester_try_con> (281 insns) + DWARF line rows for bt_rw_testmode.c:4296.
     * Ordered callee relocs: rw_init_cs.
     */
}

/* rw_tx_buf_init bt_rw_testmode.c:4072 @ bt_rw_testmode.o size 48B [dwarf-sig]
 * Calls: prbs9_gen | Data refs: PRBS9, prbs9_gen | MMIO: 0x3ffb0700
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_tx_buf_init(void)
{
    /* DWARF locals: u32 i@l4073 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_tx_buf_init> (19 insns) + DWARF line rows for bt_rw_testmode.c:4072.
     * Ordered callee relocs: prbs9_gen.
     */
}

/* rw_tx_test bt_rw_testmode.c:2813 @ bt_rw_testmode.o size 624B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, phy_bt_pll_track, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, .text.rw_txpwr_regulate$part$4+0x14, .text.rw_bb_tx_refesh$part$3+0xc, .text.rw_frm_refresh$part$5+0x34 | Data refs: .rodata.str1.4, PRBS9, bt_tx_num, frm_refresh_ind, phy_bt_pll_track, phy_printf, prbs9_gen, run_end, rw_bch_gen, rw_bt_core_on, rw_init_cs, rw_test_init | MMIO: 0x3ff4609c, 0x3ff51030, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0300, 0x3ffb0700, 0x60031014, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_tx_test(u32 txpwr, u32 hoppe, u32 freq, u32 edr, u32 type, u32 length, u32 et_mask, u32 data_type, u32 tx_num_in)
{
    (void)txpwr;
    (void)hoppe;
    (void)freq;
    (void)edr;
    (void)type;
    (void)length;
    (void)et_mask;
    (void)data_type;
    (void)tx_num_in;
    /* DWARF locals: u32 txdesc0_diag@l2814, u32 txdesc0_diag_start@l2814, u32 bchl@l2814, u32 bchh@l2814, u32 i@l2814 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_tx_test> (232 insns) + DWARF line rows for bt_rw_testmode.c:2813.
     * Ordered callee relocs: phy_printf, prbs9_gen, phy_bt_pll_track, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, .text.rw_txpwr_regulate$part$4+0x14, .text.rw_bb_tx_refesh$part$3+0xc, .text.rw_frm_refresh$part$5+0x34.
     */
}

/* rw_tx_test_init bt_rw_testmode.c:2896 @ bt_rw_testmode.o size 460B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, phy_bt_pll_track, phy_bt_power_track, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on | Data refs: .rodata.str1.4, PRBS9, phy_bt_pll_track, phy_bt_power_track, phy_printf, prbs9_gen, run_end, rw_bch_gen, rw_bt_core_on, rw_init_cs, rw_test_init | MMIO: 0x3ff4609c, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0700, 0x6003102c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_tx_test_init(u32 txpwr, u32 hoppe, u32 freq, u32 edr, u32 type, u32 length, u32 et_mask)
{
    (void)txpwr;
    (void)hoppe;
    (void)freq;
    (void)edr;
    (void)type;
    (void)length;
    (void)et_mask;
    /* DWARF locals: u32 txdesc0_diag@l2897, u32 txdesc0_diag_start@l2897, u32 bchl@l2897, u32 bchh@l2897, u32 i@l2897 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_tx_test_init> (172 insns) + DWARF line rows for bt_rw_testmode.c:2896.
     * Ordered callee relocs: phy_printf, prbs9_gen, phy_bt_pll_track, phy_bt_power_track, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on.
     */
}

/* rw_tx_test_wifi_tx bt_rw_testmode.c:2978 @ bt_rw_testmode.o size 614B [dwarf-sig]
 * Calls: phy_printf, prbs9_gen, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_error_print, .text.rw_bb_tx_refesh$part$3+0xc, unforce_wifi_mode, force_wifi_mode, .text.rw_frm_refresh$part$5+0x34, WifiTxStart | Data refs: .rodata.str1.4, PRBS9, WifiTxStart, force_wifi_mode, frm_refresh_ind, phy_printf, prbs9_gen, run_end, rw_bch_gen, rw_bt_core_on, rw_error_print, rw_init_cs, rw_test_init, unforce_wifi_mode | MMIO: 0x3ff4609c, 0x3ff51030, 0x3ffb0000, 0x3ffb02a0, 0x3ffb02a4, 0x3ffb02a8, 0x3ffb02b0, 0x3ffb02b4, 0x3ffb02b8, 0x3ffb02c0, 0x3ffb02c4, 0x3ffb02c8, 0x3ffb02d0, 0x3ffb02d4, 0x3ffb02d8, 0x3ffb0700, 0x60031014, 0x6003102c, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_tx_test_wifi_tx(u32 txpwr, u32 hoppe, u32 freq, u32 edr, u32 type, u32 length, u32 et_mask)
{
    (void)txpwr;
    (void)hoppe;
    (void)freq;
    (void)edr;
    (void)type;
    (void)length;
    (void)et_mask;
    /* DWARF locals: u32 txdesc0_diag@l2979, u32 txdesc0_diag_start@l2979, u32 bchl@l2979, u32 bchh@l2979, u32 i@l2979, u32 wifi_on@l2980, u32 tstamp@l2980 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_tx_test_wifi_tx> (229 insns) + DWARF line rows for bt_rw_testmode.c:2978.
     * Ordered callee relocs: phy_printf, prbs9_gen, rw_test_init, rw_bch_gen, rw_init_cs, rw_bt_core_on, rw_error_print, .text.rw_bb_tx_refesh$part$3+0xc, unforce_wifi_mode, force_wifi_mode, .text.rw_frm_refresh$part$5+0x34, WifiTxStart.
     */
}

/* rw_txpwr_regulate bt_rw_testmode.c:1793 @ bt_rw_testmode.o size 22B [dwarf-sig-decl]
 * Calls: .text.rw_txpwr_regulate$part$4+0x14 | Data refs: (none) | MMIO: 0x3ff51030
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_txpwr_regulate(void)
{
    /* DWARF locals: u32 chan@l1794 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_txpwr_regulate> (8 insns) + DWARF line rows for bt_rw_testmode.c:1793.
     * Ordered callee relocs: .text.rw_txpwr_regulate$part$4+0x14.
     */
}

/* rw_txpwr_regulate$part$4 bt_rw_testmode.c:1793 @ bt_rw_testmode.o size 58B [dwarf-sig-base-decl]
 * Calls: ets_delay_us, phy_set_bt_dig_gain | Data refs: ets_delay_us, phy_set_bt_dig_gain | MMIO: 0x3ff4e168, 0x3ff51038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_txpwr_regulate$part$4(void)
{
    /* DWARF locals: u32 chan@l1794 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <rw_txpwr_regulate$part$4> (20 insns) + DWARF line rows for bt_rw_testmode.c:1793.
     * Ordered callee relocs: ets_delay_us, phy_set_bt_dig_gain.
     */
}

/* t0_toggle_adv_check bt_rw_testmode.c:3212 @ bt_rw_testmode.o size 87B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, le_rx_n, phy_printf | MMIO: 0x6001f000, 0x6001f0a4, 0x60031200
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t0_toggle_adv_check(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <t0_toggle_adv_check> (33 insns) + DWARF line rows for bt_rw_testmode.c:3212.
     * Ordered callee relocs: phy_printf.
     */
}

/* t0_toggle_force_wifi bt_rw_testmode.c:3129 @ bt_rw_testmode.o size 244B [dwarf-sig]
 * Calls: unforce_wifi_mode, force_wifi_mode | Data refs: force_w_on, force_wifi_mode, t_force_wifi, unforce_wifi_mode | MMIO: 0x600041c8, 0x6001f000, 0x6001f010, 0x6001f0a4, 0x60031300, 0x60033d40
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t0_toggle_force_wifi(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <t0_toggle_force_wifi> (94 insns) + DWARF line rows for bt_rw_testmode.c:3129.
     * Ordered callee relocs: unforce_wifi_mode, force_wifi_mode.
     */
}

/* t0_toggle_scan_check bt_rw_testmode.c:3166 @ bt_rw_testmode.o size 376B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, last_scan_event_end, phy_printf, rw_scan_abort | MMIO: 0x6001f000, 0x6001f0a4, 0x60031250, 0x60031254, 0x60031300, 0x60033d40
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t0_toggle_scan_check(void)
{
    /* DWARF locals: u32 rdata@l3167, u32 pkt@l3167, u32 rdcnt@l3167 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <t0_toggle_scan_check> (136 insns) + DWARF line rows for bt_rw_testmode.c:3166.
     * Ordered callee relocs: phy_printf.
     */
}

/* t1_toggle_check_rx bt_rw_testmode.c:3235 @ bt_rw_testmode.o size 69B [dwarf-sig]
 * Calls: rw_error_print, rw_frm_refresh_check_rx | Data refs: rw_error_print, rw_frm_refresh_check_rx | MMIO: 0x6001f024, 0x6001f0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t1_toggle_check_rx(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <t1_toggle_check_rx> (25 insns) + DWARF line rows for bt_rw_testmode.c:3235.
     * Ordered callee relocs: rw_error_print, rw_frm_refresh_check_rx.
     */
}

/* t1_toggle_refresh_rw bt_rw_testmode.c:3225 @ bt_rw_testmode.o size 69B [dwarf-sig]
 * Calls: rw_error_print, rw_frm_refresh_no_cmd | Data refs: rw_error_print, rw_frm_refresh_no_cmd | MMIO: 0x6001f024, 0x6001f0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t1_toggle_refresh_rw(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <t1_toggle_refresh_rw> (26 insns) + DWARF line rows for bt_rw_testmode.c:3225.
     * Ordered callee relocs: rw_error_print, rw_frm_refresh_no_cmd.
     */
}

/* t1_toggle_refresh_rw_le bt_rw_testmode.c:3246 @ bt_rw_testmode.o size 69B [dwarf-sig]
 * Calls: rw_le_error_print, rw_evt_refresh | Data refs: rw_evt_refresh, rw_le_error_print | MMIO: 0x6001f024, 0x6001f0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t1_toggle_refresh_rw_le(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <t1_toggle_refresh_rw_le> (26 insns) + DWARF line rows for bt_rw_testmode.c:3246.
     * Ordered callee relocs: rw_le_error_print, rw_evt_refresh.
     */
}

/* t1_toggle_refresh_rw_le_advscan bt_rw_testmode.c:3275 @ bt_rw_testmode.o size 88B [dwarf-sig]
 * Calls: rw_le_error_print, rw_le_scan_print, rw_le_scan_refresh | Data refs: rw_le_error_print, rw_le_scan_print, rw_le_scan_refresh | MMIO: 0x3ffb02c0, 0x6001f024, 0x6001f0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t1_toggle_refresh_rw_le_advscan(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <t1_toggle_refresh_rw_le_advscan> (32 insns) + DWARF line rows for bt_rw_testmode.c:3275.
     * Ordered callee relocs: rw_le_error_print, rw_le_scan_print, rw_le_scan_refresh.
     */
}

/* t1_toggle_refresh_rw_le_check_rx bt_rw_testmode.c:3265 @ bt_rw_testmode.o size 69B [dwarf-sig]
 * Calls: rw_le_error_print, rw_evt_refresh_check_rx | Data refs: rw_evt_refresh_check_rx, rw_le_error_print | MMIO: 0x6001f024, 0x6001f0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t1_toggle_refresh_rw_le_check_rx(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <t1_toggle_refresh_rw_le_check_rx> (26 insns) + DWARF line rows for bt_rw_testmode.c:3265.
     * Ordered callee relocs: rw_le_error_print, rw_evt_refresh_check_rx.
     */
}

/* wifi_tx_coex_init bt_rw_testmode.c:3097 @ bt_rw_testmode.o size 11B [dwarf-sig]
 * Calls: mac_init | Data refs: mac_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wifi_tx_coex_init(void)
{
    /* TODO(ground-truth): reconstruct from libbttestmode/bt_rw_testmode.rdis
     * function <wifi_tx_coex_init> (4 insns) + DWARF line rows for bt_rw_testmode.c:3097.
     * Ordered callee relocs: mac_init.
     */
}

/* Undefined refs (79): FillTxPacket, GetStopCmd, PRBS9, READ_SPI_INIT_PARAM, RFChannelSel, UartGetCmdLn, WifiRxStart, WifiTxStart, _xtos_ints_off, _xtos_ints_on, adctrig, adv_scan_test, bt_track_pll_cap, bt_track_tx_power, cmd_parse, cmd_polling_attach, cmd_polling_start, coex_bt_high_prio, command, eir_payload, encrypt, ets_delay_us, ets_isr_unmask, fcc_le_tx, fcc_le_tx_syncw, force_bt_mode, force_wifi_mode, g_phyFuns, get_bt_rx_rssi, gpio_input_get, gpio_input_get_high, gpio_output_set, gpio_output_set_high, inquiry, inquiry_scan, le_adv, le_adv_test, le_advscan, le_advscan_test, le_rx_n, mac_init, mac_write, pString, page, page_scan, para_array, para_num, phy_bt_pll_track, phy_bt_power_track, phy_get_tx_rate, phy_init_pwr_print, phy_printf, phy_set_bt_dig_gain, pm_close_rf, prbs9_gen, rf_rw_init, rtc_init_lite, rtc_set_cpu_freq, rtc_sleep, rtc_slp_prep... */