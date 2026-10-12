/* Reconstruction of bt.o (libbttestmode.a)
 * CU: bt.c | comp_dir: /home/lxf/gittree/chip7.1_rtc/board_code/app_test/pp/bt_testmode
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 68 | funcdb functions: 2
 * Disasm: re/esp32-phy/disasm/libbttestmode/bt.rdis
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

/* BTAutotest bt.c:54 @ bt.o size 2956B [dwarf-sig]
 * Calls: ets_isr_unmask, wifi_init_bt, bt_bb_init_cmplx, force_bt_mode, phy_printf, uart_div_modify, BT_testmode_tester, UartGetCmdLn, cmd_parse, strcmp, WifiTxStart, adctrig, set_tx_gain_table_bt, set_chan_freq_hw_init, register_chipv7_phy, chip_v7_rxmax_ext_ana, freq_offset_cfg, BT_tx_8m_enable, BT_tx_forever, BT_tx_packet_8m, BT_tx_packet, set_chan_freq_sw_start, BT_wait4tx_end_new, BT_rx_start, BT_loopback_master, BT_loopback_slave, BT_testmode_init, BT_test_mode_fill_tx_payload, BT_set_packet_attributes, BT_tx_sim_debug, BT_rx_sim_debug, BT_inquiry_test, BT_inquiry_scan_test, BT_con_tx_test, BT_page_scan_test, BT_page_test, BT_mac_rx_start_debug, BT_inq, BT_inq_scan, BT_page, BT_page_scan, BT_m_discon, BT_s_discon, BT_con_loopback_master, BT_con_loopback_slave, LE_start_tx, BT_con, prbs9_test, BT_gen_prbs9, BT_rx_prbs9_err_bits, BT_rx_ber, BT_rx_per, BT_rx_dump, BT_init_rx_filters, BT_mac_set_tx_link_type, BT_mac_set_rx_link_type, BT_tx_if_init, BT_mac_iqview_debug, noise_init_bt, BT_get_pwr, LE_rx_per, LE_rx_ber, le_dtm, RFChannelSel, WifiRxStart, FillTxPacket | Data refs: .rodata.str1.4, BT_con, BT_con_loopback_master, BT_con_loopback_slave, BT_con_tx_test, BT_gen_prbs9, BT_get_pwr, BT_init_rx_filters, BT_inq, BT_inq_scan, BT_inquiry_scan_test, BT_inquiry_test, BT_loopback_master, BT_loopback_slave, BT_m_discon, BT_mac_iqview_debug, BT_mac_rx_start_debug, BT_mac_set_rx_link_type, BT_mac_set_tx_link_type, BT_page, BT_page_scan, BT_page_scan_test, BT_page_test, BT_rx_ber, BT_rx_dump, BT_rx_per, BT_rx_prbs9_err_bits, BT_rx_sim_debug, BT_rx_start, BT_s_discon, BT_set_packet_attributes, BT_test_mode_fill_tx_payload, BT_testmode_init, BT_testmode_tester, BT_tx_8m_enable, BT_tx_forever, BT_tx_if_init, BT_tx_packet, BT_tx_packet_8m, BT_tx_sim_debug, BT_wait4tx_end_new, FillTxPacket, LE_rx_ber, LE_rx_per, LE_start_tx, RFChannelSel, UartGetCmdLn, WifiRxStart, WifiTxStart, adctrig, bt_bb_init_cmplx, bt_mode_wifibb, chip_v7_rxmax_ext_ana, cmd_parse, command, ets_isr_unmask, force_bt_mode, freq_offset_cfg, g_phyFuns, init_param_default, le_dtm, noise_init_bt, pString, para_array, para_num, phy_printf, prbs9_test, register_chipv7_phy, set_chan_freq_hw_init, set_chan_freq_sw_start, set_tx_gain_table_bt, strcmp, uart_div_modify, wifi_init_bt | MMIO: 0x60033c68
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BTAutotest(void)
{
    /* DWARF locals: int result@l56, int i@l57, uint32 keycache_addr@l58, uint32 txdump_addr@l59, sint8[] array_temp_2@l60 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt.rdis
     * function <BTAutotest> (1047 insns) + DWARF line rows for bt.c:54.
     * Ordered callee relocs: ets_isr_unmask, wifi_init_bt, bt_bb_init_cmplx, force_bt_mode, phy_printf, uart_div_modify, BT_testmode_tester, UartGetCmdLn, cmd_parse, strcmp, WifiTxStart, adctrig, set_tx_gain_table_bt, set_chan_freq_hw_init, register_chipv7_phy, chip_v7_rxmax_ext_ana, freq_offset_cfg, BT_tx_8m_enable, BT_tx_forever, BT_tx_packet_8m, BT_tx_packet, set_chan_freq_sw_start, BT_wait4tx_end_new, BT_rx_start, BT_loopback_master, BT_loopback_slave, BT_testmode_init, BT_test_mode_fill_tx_payload, BT_set_packet_attributes, BT_tx_sim_debug, BT_rx_sim_debug, BT_inquiry_test, BT_inquiry_scan_test, BT_con_tx_test, BT_page_scan_test, BT_page_test, BT_mac_rx_start_debug, BT_inq, BT_inq_scan, BT_page, BT_page_scan, BT_m_discon, BT_s_discon, BT_con_loopback_master, BT_con_loopback_slave, LE_start_tx, BT_con, prbs9_test, BT_gen_prbs9, BT_rx_prbs9_err_bits, BT_rx_ber, BT_rx_per, BT_rx_dump, BT_init_rx_filters, BT_mac_set_tx_link_type, BT_mac_set_rx_link_type, BT_tx_if_init, BT_mac_iqview_debug, noise_init_bt, BT_get_pwr, LE_rx_per, LE_rx_ber, le_dtm, RFChannelSel, WifiRxStart, FillTxPacket.
     */
}

/* BT_hoppe bt.c:32 @ bt.o size 50B [dwarf-sig]
 * Calls: phy_printf, set_chan_freq_sw_start | Data refs: .rodata.str1.4, phy_printf, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void BT_hoppe(void)
{
    /* DWARF locals: u32 i@l33 */
    /* TODO(ground-truth): reconstruct from libbttestmode/bt.rdis
     * function <BT_hoppe> (18 insns) + DWARF line rows for bt.c:32.
     * Ordered callee relocs: phy_printf, set_chan_freq_sw_start.
     */
}

/* Undefined refs (73): BT_con, BT_con_loopback_master, BT_con_loopback_slave, BT_con_tx_test, BT_gen_prbs9, BT_get_pwr, BT_init_rx_filters, BT_inq, BT_inq_scan, BT_inquiry_scan_test, BT_inquiry_test, BT_loopback_master, BT_loopback_slave, BT_m_discon, BT_mac_iqview_debug, BT_mac_rx_start_debug, BT_mac_set_rx_link_type, BT_mac_set_tx_link_type, BT_page, BT_page_scan, BT_page_scan_test, BT_page_test, BT_rx_ber, BT_rx_dump, BT_rx_per, BT_rx_prbs9_err_bits, BT_rx_sim_debug, BT_rx_start, BT_s_discon, BT_set_packet_attributes, BT_test_mode_fill_tx_payload, BT_testmode_init, BT_testmode_tester, BT_tx_8m_enable, BT_tx_forever, BT_tx_if_init, BT_tx_packet, BT_tx_packet_8m, BT_tx_sim_debug, BT_wait4tx_end_new, FillTxPacket, LE_rx_ber, LE_rx_per, LE_start_tx, RFChannelSel, UartGetCmdLn, WifiRxStart, WifiTxStart, adctrig, bt_bb_init_cmplx, bt_mode_wifibb, chip_v7_rxmax_ext_ana, cmd_parse, command, ets_isr_unmask, force_bt_mode, freq_offset_cfg, g_phyFuns, init_param_default, le_dtm... */