/* Reconstruction of wifi.o (librftest.a)
 * CU: wifi.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 314 | funcdb functions: 74
 * Disasm: re/esp32-phy/disasm/librftest/wifi.rdis
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

/* FillTxPacket wifi.c:86 @ wifi.o size 124B [dwarf-sig-decl]
 * Calls: fill_tx_frame | Data refs: fill_tx_frame | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void FillTxPacket(uint32 PacketLen, uint32 PDU0Len, uint32 PDU1Len, uint32 Rate, uint32 key_entry_no, uint32 bssid_no, uint32 ap_mac_5, uint32 ap_mac_4, uint32 ap_mac_3, uint32 ap_mac_2, uint32 ap_mac_1, uint32 ap_mac_0)
{
    (void)PacketLen;
    (void)PDU0Len;
    (void)PDU1Len;
    (void)Rate;
    (void)key_entry_no;
    (void)bssid_no;
    (void)ap_mac_5;
    (void)ap_mac_4;
    (void)ap_mac_3;
    (void)ap_mac_2;
    (void)ap_mac_1;
    (void)ap_mac_0;
    /* DWARF locals: uint32 framelen@l88, uint32[] pdulen@l88, uint32 QueNo@l89, uint32 link_start_addr@l90, uint32 bssid@l91, uint32 gi_bit@l92 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <FillTxPacket> (50 insns) + DWARF line rows for wifi.c:86.
     * Ordered callee relocs: fill_tx_frame.
     */
}

/* WifiRxStart wifi.c:261 @ wifi.o size 22B [dwarf-sig-decl]
 * Calls: bb_wdt_rst_enable, do_rx_poll | Data refs: bb_wdt_rst_enable, do_rx_poll | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void WifiRxStart(WIFI_RATE rx_rate)
{
    (void)rx_rate;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <WifiRxStart> (8 insns) + DWARF line rows for wifi.c:261.
     * Ordered callee relocs: bb_wdt_rst_enable, do_rx_poll.
     */
}

/* WifiTxStart wifi.c:200 @ wifi.o size 382B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, test_tx_frame, GetStopCmd, tx_cont_cfg, dig_gain_rse_stop | Data refs: GetStopCmd, adaptive_test_en, dig_gain_rse_stop, esp_dport_access_reg_read, fcc_mode_flag, fcc_mode_sel, g_phyFuns, test_tx_frame, tx_cont_cfg, tx_contin_fcc_en, tx_pocket_num | MMIO: 0x3ff5c400, 0x3ff5c458, 0x60033cc0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void WifiTxStart(uint32 tx_att, uint32 TxPacketNum, unsigned int frame_delay, unsigned int tx_cbw40, unsigned int ht_dup, int dis_agc)
{
    (void)tx_att;
    (void)TxPacketNum;
    (void)frame_delay;
    (void)tx_cbw40;
    (void)ht_dup;
    (void)dis_agc;
    /* DWARF locals: WIFI_RATE tx_rate@l202, uint32 queue@l203 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <WifiTxStart> (144 insns) + DWARF line rows for wifi.c:200.
     * Ordered callee relocs: esp_dport_access_reg_read, test_tx_frame, GetStopCmd, tx_cont_cfg, dig_gain_rse_stop.
     */
}

/* accumiq wifi.c:390 @ wifi.o size 94B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void accumiq(uint32 start_addr, uint32 burst_len)
{
    (void)start_addr;
    (void)burst_len;
    /* DWARF locals: uint32 adc_data@l392, uint32 i@l393, int32 sample_q@l394, int32 sample_i@l394, int32 accum_i@l395, int32 accum_q@l395, int32 rssi@l395 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <accumiq> (36 insns) + DWARF line rows for wifi.c:390.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* bbpll_80m_cal wifi.c:1963 @ wifi.o size 22B [dwarf-sig-decl]
 * Calls: rtc_clk_cpu_freq_set_new, rtc_uart_div_modify | Data refs: rtc_clk_cpu_freq_set_new, rtc_uart_div_modify | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bbpll_80m_cal(uint8 ref)
{
    (void)ref;
    /* DWARF locals: uint8 i@l1965, uint32 rx_pwr@l1966, uint32 rx_pwr_sum@l1966 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <bbpll_80m_cal> (8 insns) + DWARF line rows for wifi.c:1963.
     * Ordered callee relocs: rtc_clk_cpu_freq_set_new, rtc_uart_div_modify.
     */
}

/* ble_chan_trans wifi.c:2068 @ wifi.o size 50B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 ble_chan_trans(u32 chan)
{
    (void)chan;
    /* DWARF locals: u32 fi@l2070 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <ble_chan_trans> (21 insns) + DWARF line rows for wifi.c:2068.
     */
}

/* bt_2480_opt_enter wifi.c:2013 @ wifi.o size 208B [dwarf-sig]
 * Calls: bt_rx_spur_cal | Data refs: bt_2480_opt_en, bt_2480_print, bt_rx_2440_dac, bt_rx_2440_dcur, bt_rx_2480_dac, bt_rx_2480_dcur, bt_rx_chan_old, bt_rx_spur_cal, g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_2480_opt_enter(uint32 chan)
{
    (void)chan;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <bt_2480_opt_enter> (80 insns) + DWARF line rows for wifi.c:2013.
     * Ordered callee relocs: bt_rx_spur_cal.
     */
}

/* bt_2480_opt_exit wifi.c:2031 @ wifi.o size 80B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: bt_2480_opt_en, g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_2480_opt_exit(void)
{
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <bt_2480_opt_exit> (33 insns) + DWARF line rows for wifi.c:2031.
     */
}

/* bt_3200_opt wifi.c:2041 @ wifi.o size 132B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_3200_opt(bool en)
{
    (void)en;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <bt_3200_opt> (55 insns) + DWARF line rows for wifi.c:2041.
     */
}

/* bt_chan_change wifi.c:2085 @ wifi.o size 114B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 bt_chan_change(bool bt_en, uint8 chan_num, bool tx_en)
{
    (void)bt_en;
    (void)chan_num;
    (void)tx_en;
    /* DWARF locals: uint16 freq@l2087, uint16 le_chan@l2087 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <bt_chan_change> (41 insns) + DWARF line rows for wifi.c:2085.
     */
}

/* bt_rx_spur_cal wifi.c:1991 @ wifi.o size 166B [dwarf-sig]
 * Calls: rx_spur_cal, set_chan_freq_sw_start | Data refs: bt_rx_2440_dac, bt_rx_2440_dcur, bt_rx_2480_dac, bt_rx_2480_dcur, chip7_phy_init_ctrl, rx_spur_cal, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_rx_spur_cal(uint32 chan, bool print_en)
{
    (void)chan;
    (void)print_en;
    /* DWARF locals: uint8 set_dac@l1993, uint8 set_dcur@l1993, uint32 freq@l1994, uint32[] rx_pwr@l1994 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <bt_rx_spur_cal> (61 insns) + DWARF line rows for wifi.c:1991.
     * Ordered callee relocs: rx_spur_cal, set_chan_freq_sw_start.
     */
}

/* bt_set_freq_cal wifi.c:2099 @ wifi.o size 40B [dwarf-sig]
 * Calls: bt_chan_change, set_chan_freq_sw_start | Data refs: bt_chan_change, chip7_phy_init_ctrl, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_set_freq_cal(bool bt_en, uint8 chan_num, bool tx_en)
{
    (void)bt_en;
    (void)chan_num;
    (void)tx_en;
    /* DWARF locals: uint16 freq@l2101, sint16 freq_offset@l2102, uint8 chan_freq@l2103 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <bt_set_freq_cal> (14 insns) + DWARF line rows for wifi.c:2099.
     * Ordered callee relocs: bt_chan_change, set_chan_freq_sw_start.
     */
}

/* burn_in_test wifi.c:552 @ wifi.o size 1017B [dwarf-sig]
 * Calls: Plcp1AddrGet, HTsigAddrGet, Plcp0AddrGet, wdt_nrst_inc, wdt_init, improve_dig_rtc_vol, phy_printf, uart_wait_idle, wdt_feed, register_chipv7_phy, chip_v7_set_chan, fill_tx_frame, WifiTxStart, fill_txbeacon, esp_dport_access_reg_read, ets_delay_us, wdt_nrst, GetStopCmd | Data refs: .rodata.str1.4, GetStopCmd, HTsigAddrGet, Plcp0AddrGet, Plcp1AddrGet, WifiTxStart, chip7_sleep_params, chip_v7_set_chan, esp_dport_access_reg_read, ets_delay_us, fill_tx_frame, fill_txbeacon, improve_dig_rtc_vol, init_param_default, phy_printf, re_entry, register_chipv7_phy, uart_wait_idle, wdt_feed, wdt_init, wdt_nrst, wdt_nrst_inc | MMIO: 0x40000002, 0x60033c00, 0x60033c10, 0x60033c40, 0x60033c48, 0x60033c4c, 0x60033c68, 0x60033cc0, 0x60033d1c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void burn_in_test(void)
{
    /* DWARF locals: sint8[] dc_comp@l554, U32 t0@l555, U32 t1@l555, U32 bea_delay@l555, U32 i@l556, U32 rst_num@l557, u8 untx_num@l558, u8 wtd_num@l558, unsigned int queue@l559, unsigned int tx_rate@l560, unsigned int plcp0_addr@l561, unsigned int plcp1_addr@l561, unsigned int htsig_addr@l561, u8 * byte0@l565, u8 * byte1@l565, u8 * byte2@l565 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <burn_in_test> (385 insns) + DWARF line rows for wifi.c:552.
     * Ordered callee relocs: Plcp1AddrGet, HTsigAddrGet, Plcp0AddrGet, wdt_nrst_inc, wdt_init, improve_dig_rtc_vol, phy_printf, uart_wait_idle, wdt_feed, register_chipv7_phy, chip_v7_set_chan, fill_tx_frame, WifiTxStart, fill_txbeacon, esp_dport_access_reg_read, ets_delay_us, wdt_nrst, GetStopCmd.
     */
}

/* change_data_rate wifi.c:1262 @ wifi.o size 206B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.change_data_rate, .rodata.str1.4, phy_printf, tx_cbw40m_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 change_data_rate(u32 rate)
{
    (void)rate;
    /* DWARF locals: u32 rate_bps@l1264 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <change_data_rate> (85 insns) + DWARF line rows for wifi.c:1262.
     * Ordered callee relocs: phy_printf.
     */
}

/* clk50m_pull_out wifi.c:776 @ wifi.o size 271B [dwarf-sig]
 * Calls: rtc_clk_apll_enable, esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf, rtc_clk_apll_enable | MMIO: 0x3ff49000, 0x3ff49044, 0x3ff4904c, 0x3ff49050, 0x3ff69800
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void clk50m_pull_out(u32 clk_sel)
{
    (void)clk_sel;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <clk50m_pull_out> (100 insns) + DWARF line rows for wifi.c:776.
     * Ordered callee relocs: rtc_clk_apll_enable, esp_dport_access_reg_read, phy_printf.
     */
}

/* clk_pull_out wifi.c:763 @ wifi.o size 114B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf, ets_delay_us | Data refs: .rodata.str1.4, esp_dport_access_reg_read, ets_delay_us, phy_printf | MMIO: 0x3ff49000, 0x3ff49044
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void clk_pull_out(u32 clk_sel)
{
    (void)clk_sel;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <clk_pull_out> (41 insns) + DWARF line rows for wifi.c:763.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf, ets_delay_us.
     */
}

/* coex_bt_wifi_test wifi.c:880 @ wifi.o size 128B [dwarf-sig]
 * Calls: intr_matrix_set, _xtos_set_interrupt_handler_arg, _xtos_ints_on, t0_start_toggle, rw_tx_test_init, t1_start_toggle | Data refs: _xtos_ints_on, _xtos_set_interrupt_handler_arg, intr_matrix_set, rw_tx_test_init, t0_start_toggle, t0_toggle_force_wifi, t1_start_toggle, t1_toggle_refresh_rw, t_force_wifi | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void coex_bt_wifi_test(void)
{
    /* DWARF locals: u32 t_force_wifi@l882 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <coex_bt_wifi_test> (47 insns) + DWARF line rows for wifi.c:880.
     * Ordered callee relocs: intr_matrix_set, _xtos_set_interrupt_handler_arg, _xtos_ints_on, t0_start_toggle, rw_tx_test_init, t1_start_toggle.
     */
}

/* coex_test wifi.c:1816 @ wifi.o size 397B [dwarf-sig]
 * Calls: intr_matrix_set, _xtos_set_interrupt_handler_arg, _xtos_ints_on, t0_start_toggle, phy_printf, rw_le_advscan_test_init, rw_le_rx_per_init, rw_rx_per_init, rw_inq_test_init, rw_tx_test_init, rw_le_adv_test_init, rw_le_tx_nohoppe_init, t1_start_toggle | Data refs: .rodata.str1.4, _xtos_ints_on, _xtos_set_interrupt_handler_arg, coex_test_enable, intr_matrix_set, phy_printf, rw_inq_test_init, rw_le_adv_test_init, rw_le_advscan_test_init, rw_le_rx_per_init, rw_le_tx_nohoppe_init, rw_rx_per_init, rw_tx_test_init, t0_start_toggle, t0_toggle_force_wifi, t1_start_toggle, t1_toggle_check_rx, t1_toggle_refresh_rw, t1_toggle_refresh_rw_le, t1_toggle_refresh_rw_le_advscan, t1_toggle_refresh_rw_le_check_rx, t_force_wifi | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void coex_test(u8 mode)
{
    (void)mode;
    /* DWARF locals: u32 t_force_wifi@l1819 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <coex_test> (145 insns) + DWARF line rows for wifi.c:1816.
     * Ordered callee relocs: intr_matrix_set, _xtos_set_interrupt_handler_arg, _xtos_ints_on, t0_start_toggle, phy_printf, rw_le_advscan_test_init, rw_le_rx_per_init, rw_rx_per_init, rw_inq_test_init, rw_tx_test_init, rw_le_adv_test_init, rw_le_tx_nohoppe_init, t1_start_toggle.
     */
}

/* dc_iq_est_test wifi.c:411 @ wifi.o size 194B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read, g_phyFuns | MMIO: 0x3ff460dc, 0x3ff460e0, 0x3ff460e4, 0x3ff460ec, 0x3ff460f0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void dc_iq_est_test(bool dc_est_en, uint16 smp_num, sint32 * dc_est, sint32 * power)
{
    (void)dc_est_en;
    (void)smp_num;
    (void)dc_est;
    (void)power;
    /* DWARF locals: int pwr@l419, int pwr_i@l420, int pwr_q@l421, int pwr_dc@l422, int pwr_ac@l423, int pwr_i_ac@l424, int pwr_q_ac@l425 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <dc_iq_est_test> (72 insns) + DWARF line rows for wifi.c:411.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* dig_gain_rse wifi.c:153 @ wifi.o size 189B [dwarf-sig]
 * Calls: get_target_power_offset, esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read, get_target_power_offset, phy_chan_pwr_index | MMIO: 0x3ff450e8, 0x3ff46000, 0x3ff46004, 0x3ff46008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void dig_gain_rse(u8 rate, u8 clip_val, u8 clip_cmp, s8 backoff, bool cbw40)
{
    (void)rate;
    (void)clip_val;
    (void)clip_cmp;
    (void)backoff;
    (void)cbw40;
    /* DWARF locals: s8 interp_offset@l155, s8[] chan_data@l155, s8 tx_scale@l155, s8 dig_gain@l155, u8 rate_offset@l156, u8 j@l156 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <dig_gain_rse> (66 insns) + DWARF line rows for wifi.c:153.
     * Ordered callee relocs: get_target_power_offset, esp_dport_access_reg_read.
     */
}

/* dig_gain_rse_stop wifi.c:178 @ wifi.o size 49B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff450e8, 0x3ff46000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void dig_gain_rse_stop(void)
{
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <dig_gain_rse_stop> (18 insns) + DWARF line rows for wifi.c:178.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* fcc_bt_force_tx_tone wifi.c:1744 @ wifi.o size 199B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, chip7_phy_init_ctrl, esp_dport_access_reg_read, g_phyFuns, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff460a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_bt_force_tx_tone(u32 start, u32 bt_chan, u32 power)
{
    (void)start;
    (void)bt_chan;
    (void)power;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <fcc_bt_force_tx_tone> (74 insns) + DWARF line rows for wifi.c:1744.
     * Ordered callee relocs: set_chan_freq_sw_start, esp_dport_access_reg_read, phy_printf.
     */
}

/* flash_init_param_print wifi.c:962 @ wifi.o size 16B [dwarf-sig-decl]
 * Calls: .text.flash_init_param_print$part$1+0x7c | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void flash_init_param_print(bool flash_valid)
{
    (void)flash_valid;
    /* DWARF locals: uint8 i@l964 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <flash_init_param_print> (6 insns) + DWARF line rows for wifi.c:962.
     * Ordered callee relocs: .text.flash_init_param_print$part$1+0x7c.
     */
}

/* flash_init_param_print$part$1 wifi.c:962 @ wifi.o size 334B [dwarf-sig-base-decl]
 * Calls: phy_printf, chip_v7_set_chan_offset, tx_contin_en, wifitxout | Data refs: .rodata.str1.4, chip7_phy_init_ctrl, chip_v7_set_chan_offset, fixedfreq_chan, fixedfreq_rate, fixedfreq_vaild, freqoff_vaild, freqoff_val, para_array, phy_freq_offset, phy_printf, tx_contin_en, wifitxout | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void flash_init_param_print$part$1(bool flash_valid)
{
    (void)flash_valid;
    /* DWARF locals: uint8 i@l964 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <flash_init_param_print$part$1> (121 insns) + DWARF line rows for wifi.c:962.
     * Ordered callee relocs: phy_printf, chip_v7_set_chan_offset, tx_contin_en, wifitxout.
     */
}

/* force_power_level wifi.c:2202 @ wifi.o size 185B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read, phy_chan_gain_table | MMIO: 0x3ff46000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void force_power_level(bool force_en, uint8 level)
{
    (void)force_en;
    (void)level;
    /* DWARF locals: sint8 dig_gain@l2204, uint16 addr@l2205, sint8[] phy_chan_gain_table@l2206 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <force_power_level> (67 insns) + DWARF line rows for wifi.c:2202.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* force_rx_gain wifi.c:2317 @ wifi.o size 131B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c02c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void force_rx_gain(bool force_en, uint8 gain, bool bt_mode)
{
    (void)force_en;
    (void)gain;
    (void)bt_mode;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <force_rx_gain> (47 insns) + DWARF line rows for wifi.c:2317.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* force_txon_en wifi.c:120 @ wifi.o size 190B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read, rx_pbus_set, tx_pbus_set, pa_pbus_set, ram_set_pbus_mem, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us, pa_pbus_set, ram_set_pbus_mem, rx_pbus_set, tx_pbus_set | MMIO: 0x3ff460a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void force_txon_en(bool en)
{
    (void)en;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <force_txon_en> (69 insns) + DWARF line rows for wifi.c:120.
     * Ordered callee relocs: esp_dport_access_reg_read, rx_pbus_set, tx_pbus_set, pa_pbus_set, ram_set_pbus_mem, ets_delay_us.
     */
}

/* get_length_delay wifi.c:1298 @ wifi.o size 139B [dwarf-sig]
 * Calls: memcpy, get_target_power_offset, change_data_rate | Data refs: .rodata, change_data_rate, chip7_phy_init_ctrl, get_target_power_offset, memcpy | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_length_delay(u32 * len_delay, u8 rate)
{
    (void)len_delay;
    (void)rate;
    /* DWARF locals: u16[] current@l1300, u16 mean_current@l1301, u32 ratio@l1302, u8 rate_bps@l1303, u8 power_index@l1303, u16 len_ext@l1304, u16 pocket_time@l1304 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <get_length_delay> (49 insns) + DWARF line rows for wifi.c:1298.
     * Ordered callee relocs: memcpy, get_target_power_offset, change_data_rate.
     */
}

/* get_path_loss_offset wifi.c:2240 @ wifi.o size 198B [dwarf-sig]
 * Calls: dc_iq_est_test | Data refs: .rodata, dc_iq_est_test, g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_path_loss_offset(s32 * pwr_list)
{
    (void)pwr_list;
    /* DWARF locals: sint32[] dc_est@l2242, sint32[] pwr_ac@l2242, sint16[] dc_comp@l2243 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <get_path_loss_offset> (79 insns) + DWARF line rows for wifi.c:2240.
     * Ordered callee relocs: dc_iq_est_test.
     */
}

/* get_rx_tone_pwr wifi.c:459 @ wifi.o size 123B [dwarf-sig]
 * Calls: ets_delay_us, ram_get_corr_power, phy_printf | Data refs: .rodata.str1.4, ets_delay_us, g_phyFuns, phy_printf, ram_get_corr_power | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_rx_tone_pwr(float tone_freq_set)
{
    (void)tone_freq_set;
    /* DWARF locals: const U16 timer_exp@l461, const U8 bb_atten@l462, int[] get_power@l463, S16 sig_power@l464, S16 total_power@l464 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <get_rx_tone_pwr> (49 insns) + DWARF line rows for wifi.c:459.
     * Ordered callee relocs: ets_delay_us, ram_get_corr_power, phy_printf.
     */
}

/* get_sar2_vol wifi.c:1768 @ wifi.o size 326B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, set_xpd_sar, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us, g_phyFuns, set_xpd_sar | MMIO: 0x3ff460c0, 0x3ff4882c, 0x3ff48838, 0x3ff48890, 0x3ff4e050, 0x3ff4e05c, 0x3fffffff
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
U16 get_sar2_vol(uint8 atten)
{
    (void)atten;
    /* DWARF locals: U8 i@l1770, U16 sar_dout@l1771, U16 code@l1771, U16[] e@l1771 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <get_sar2_vol> (119 insns) + DWARF line rows for wifi.c:1768.
     * Ordered callee relocs: esp_dport_access_reg_read, set_xpd_sar, ets_delay_us.
     */
}

/* gpio_conf_for_certific wifi.c:1687 @ wifi.o size 73B [dwarf-sig]
 * Calls: uart_wait_idle, rtc_set_dig_gpio_out | Data refs: .bss.uart_no, rtc_set_dig_gpio_out, uart_wait_idle | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void gpio_conf_for_certific(void)
{
    /* DWARF locals: uint8 i@l1689, uint8 uart_flag@l1689, uint8 sdio_flag@l1689, uint8 txd_flag@l1689, uint8 rxd_flag@l1689, bool txd_en@l1690, bool rxd_en@l1691 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <gpio_conf_for_certific> (28 insns) + DWARF line rows for wifi.c:1687.
     * Ordered callee relocs: uart_wait_idle, rtc_set_dig_gpio_out.
     */
}

/* idf_enable wifi.c:2330 @ wifi.o size 14B [dwarf-sig]
 * Calls: (none) | Data refs: short_log_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void idf_enable(uint8 conf)
{
    (void)conf;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <idf_enable> (5 insns) + DWARF line rows for wifi.c:2330.
     */
}

/* improve_dig_rtc_vol wifi.c:538 @ wifi.o size 26B [dwarf-sig]
 * Calls: DIG_pwc_mea_ate, RTC_pwc_mea_ate | Data refs: DIG_pwc_mea_ate, RTC_pwc_mea_ate | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void improve_dig_rtc_vol(void)
{
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <improve_dig_rtc_vol> (10 insns) + DWARF line rows for wifi.c:538.
     * Ordered callee relocs: DIG_pwc_mea_ate, RTC_pwc_mea_ate.
     */
}

/* init_param_read wifi.c:924 @ wifi.o size 246B [dwarf-sig]
 * Calls: ets_efuse_get_spiconfig, spi_flash_attach, SPIRead, phy_printf | Data refs: .rodata.str1.4, SPIRead, ets_efuse_get_spiconfig, fixedfreq_chan, fixedfreq_rate, fixedfreq_vaild, freqoff_vaild, freqoff_val, init_param_default, phy_printf, spi_flash_attach | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
bool init_param_read(void)
{
    /* DWARF locals: uint8[] init_param@l927, uint8 i@l927, uint8 valid_num@l928, bool flash_valid@l929, uint32 flash_addr@l930, uint32_t spiconfig0@l932 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <init_param_read> (92 insns) + DWARF line rows for wifi.c:924.
     * Ordered callee relocs: ets_efuse_get_spiconfig, spi_flash_attach, SPIRead, phy_printf.
     */
}

/* mac_filter_enable wifi.c:2262 @ wifi.o size 14B [dwarf-sig-decl]
 * Calls: (none) | Data refs: mac_filter_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void mac_filter_enable(bool enable)
{
    (void)enable;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <mac_filter_enable> (5 insns) + DWARF line rows for wifi.c:2262.
     */
}

/* my_temprature_sens_read wifi.c:305 @ wifi.o size 254B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff4880c, 0x3ff48844, 0x3ff4884c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint8 my_temprature_sens_read(u16 delay, u8 clk_div)
{
    (void)delay;
    (void)clk_div;
    /* DWARF locals: uint8 temp@l307 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <my_temprature_sens_read> (90 insns) + DWARF line rows for wifi.c:305.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* noise_init_check wifi.c:484 @ wifi.o size 135B [dwarf-sig]
 * Calls: chip_v7_set_chan, phy_printf | Data refs: .rodata.str1.4, chip_v7_set_chan, g_phyFuns, noise_array, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void noise_init_check(int chan_en, int upd_en)
{
    (void)chan_en;
    (void)upd_en;
    /* DWARF locals: uint8 i@l486, uint8 j@l486, s16[] noise_t@l487 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <noise_init_check> (54 insns) + DWARF line rows for wifi.c:484.
     * Ordered callee relocs: chip_v7_set_chan, phy_printf.
     */
}

/* pa_pbus_set wifi.c:1553 @ wifi.o size 427B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff45034, 0x3ff45038, 0x3ff46038
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pa_pbus_set(uint16 paon_txrf1, uint16 paoff_txrf1)
{
    (void)paon_txrf1;
    (void)paoff_txrf1;
    /* DWARF locals: unsigned int index_start@l1555, unsigned int index_end@l1555, unsigned int i@l1555, unsigned int[] pbus_table@l1556, const unsigned int[] table_paon@l1557, const unsigned int[] table_paoff@l1559 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <pa_pbus_set> (165 insns) + DWARF line rows for wifi.c:1553.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* pad_gpio_set wifi.c:811 @ wifi.o size 129B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pad_gpio_set(u32 pad_addr, bool high_en)
{
    (void)pad_addr;
    (void)high_en;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <pad_gpio_set> (46 insns) + DWARF line rows for wifi.c:811.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* pbus_debug_test wifi.c:2180 @ wifi.o size 417B [dwarf-sig]
 * Calls: phy_printf, pbus_wr_que, ets_delay_us, GetStopCmd | Data refs: .rodata.str1.4, GetStopCmd, ets_delay_us, g_phyFuns, pbus_wr_que, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pbus_debug_test(bool bt_sel, uint8 rfrx_num, uint8 txbb_num, uint8 pa_num, uint16 delay1, uint16 delay2, uint16 delay3, uint16 rx_bb, uint16 rx_pa, uint16 rfrx, uint32 * txdc_in)
{
    (void)bt_sel;
    (void)rfrx_num;
    (void)txbb_num;
    (void)pa_num;
    (void)delay1;
    (void)delay2;
    (void)delay3;
    (void)rx_bb;
    (void)rx_pa;
    (void)rfrx;
    (void)txdc_in;
    /* DWARF locals: uint16[] txdc@l2182, uint16 i@l2182 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <pbus_debug_test> (168 insns) + DWARF line rows for wifi.c:2180.
     * Ordered callee relocs: phy_printf, pbus_wr_que, ets_delay_us, GetStopCmd.
     */
}

/* pbus_test_init wifi.c:2135 @ wifi.o size 194B [dwarf-sig]
 * Calls: ets_delay_us | Data refs: chip7_sleep_params, ets_delay_us, g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pbus_test_init(bool bt_sel)
{
    (void)bt_sel;
    /* DWARF locals: uint16[] txdc@l2137 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <pbus_test_init> (75 insns) + DWARF line rows for wifi.c:2135.
     * Ordered callee relocs: ets_delay_us.
     */
}

/* pbus_wr_que wifi.c:2156 @ wifi.o size 218B [dwarf-sig]
 * Calls: ets_delay_us | Data refs: chip7_sleep_params, ets_delay_us, g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pbus_wr_que(bool bt_sel, bool rfrx_en, bool filt_en, bool pa_en, uint16 delay_us, uint16 * txdc)
{
    (void)bt_sel;
    (void)rfrx_en;
    (void)filt_en;
    (void)pa_en;
    (void)delay_us;
    (void)txdc;
    /* DWARF locals: uint8 i@l2158 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <pbus_wr_que> (82 insns) + DWARF line rows for wifi.c:2156.
     * Ordered callee relocs: ets_delay_us.
     */
}

/* phy_ofdm_bandage_opt wifi.c:1240 @ wifi.o size 91B [dwarf-sig]
 * Calls: dig_gain_rse | Data refs: dig_gain_rse, fcc_mode_sel | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void phy_ofdm_bandage_opt(uint8 rate, sint8 backoff, bool tx_cbw40m_en)
{
    (void)rate;
    (void)backoff;
    (void)tx_cbw40m_en;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <phy_ofdm_bandage_opt> (35 insns) + DWARF line rows for wifi.c:1240.
     * Ordered callee relocs: dig_gain_rse.
     */
}

/* phy_temp_track wifi.c:1208 @ wifi.o size 316B [dwarf-sig]
 * Calls: tsens_code_read, get_rate_target_power, phy_printf | Data refs: .rodata.str1.4, g_phyFuns, get_rate_target_power, phy_printf, phy_temp_init, phy_temp_meas, phy_tx_pwr_print_en, phy_tx_pwr_track_en, tsens_code_read | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void phy_temp_track(uint8 rate)
{
    (void)rate;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <phy_temp_track> (122 insns) + DWARF line rows for wifi.c:1208.
     * Ordered callee relocs: tsens_code_read, get_rate_target_power, phy_printf.
     */
}

/* print_efuse_mac wifi.c:798 @ wifi.o size 39B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff5a004, 0x3ff5a008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void print_efuse_mac(void)
{
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <print_efuse_mac> (14 insns) + DWARF line rows for wifi.c:798.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* pvt_ate wifi.c:2223 @ wifi.o size 144B [dwarf-sig]
 * Calls: pvt_pwr_ctrl, ets_delay_us, pvt_test, phy_printf | Data refs: .rodata.str1.4, ets_delay_us, phy_printf, pvt_pwr_ctrl, pvt_test | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pvt_ate(void)
{
    /* DWARF locals: uint16[] count@l2225 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <pvt_ate> (54 insns) + DWARF line rows for wifi.c:2223.
     * Ordered callee relocs: pvt_pwr_ctrl, ets_delay_us, pvt_test, phy_printf.
     */
}

/* ram_get_corr_power wifi.c:438 @ wifi.o size 241B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff46080, 0x3ff46084, 0x3ff46088, 0x3ff4608c, 0x3ff460dc, 0x3ff460e0, 0x3ff460e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ram_get_corr_power(int * power, U8 shift_bits)
{
    (void)power;
    (void)shift_bits;
    /* DWARF locals: int sig_i@l440, int sig_q@l440, int dc_i@l440, int dc_q@l440, sint64 temp_power@l441 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <ram_get_corr_power> (86 insns) + DWARF line rows for wifi.c:438.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* read_efuse_dig_reserve wifi.c:346 @ wifi.o size 26B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff5a018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void read_efuse_dig_reserve(void)
{
    /* DWARF locals: u32 blk0_rdata6@l348, u8 rd_data24@l349, u8 dig_reserve@l349 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <read_efuse_dig_reserve> (9 insns) + DWARF line rows for wifi.c:346.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* read_flash_init_para wifi.c:1722 @ wifi.o size 32B [dwarf-sig]
 * Calls: ets_efuse_get_spiconfig, spi_flash_attach, SPIRead | Data refs: SPIRead, ets_efuse_get_spiconfig, spi_flash_attach | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void read_flash_init_para(u32 addr, u8 * data)
{
    (void)addr;
    (void)data;
    /* DWARF locals: u32[] flash_data@l1724, u32 i@l1724, uint32_t spiconfig0@l1726 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <read_flash_init_para> (12 insns) + DWARF line rows for wifi.c:1722.
     * Ordered callee relocs: ets_efuse_get_spiconfig, spi_flash_attach, SPIRead.
     */
}

/* remove_11b_4p8G_spur wifi.c:1323 @ wifi.o size 188B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5c454, 0x3ff5c458
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void remove_11b_4p8G_spur(u8 remove_en, u8 num, u8 thres)
{
    (void)remove_en;
    (void)num;
    (void)thres;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <remove_11b_4p8G_spur> (65 insns) + DWARF line rows for wifi.c:1323.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rftest_optimize wifi.c:905 @ wifi.o size 32B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff5cd04, 0x3ff5cd08
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rftest_optimize(void)
{
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <rftest_optimize> (13 insns) + DWARF line rows for wifi.c:905.
     */
}

/* rtc_brown_out_set wifi.c:803 @ wifi.o size 91B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff480d4, 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_brown_out_set(void)
{
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <rtc_brown_out_set> (33 insns) + DWARF line rows for wifi.c:803.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rtc_brown_out_test wifi.c:825 @ wifi.o size 134B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf, ets_delay_us | Data refs: .rodata.str1.4, esp_dport_access_reg_read, ets_delay_us, phy_printf | MMIO: 0x3ff480d4, 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_brown_out_test(u8 thres, u8 rst)
{
    (void)thres;
    (void)rst;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <rtc_brown_out_test> (48 insns) + DWARF line rows for wifi.c:825.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf, ets_delay_us.
     */
}

/* rtc_clk_bbpll_set_new wifi.c:1900 @ wifi.o size 131B [dwarf-sig]
 * Calls: ets_delay_us | Data refs: ets_delay_us, g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_clk_bbpll_set_new(uint8 ref)
{
    (void)ref;
    /* DWARF locals: uint8_t div_ref@l1902, uint8_t div7_0@l1903, uint8_t div10_8@l1904, uint8_t lref@l1905, uint8_t dcur@l1906, uint8_t bw@l1907, rtc_xtal_freq_t xtal_freq@l1908, rtc_cpu_freq_t cpu_freq@l1909, uint8_t i2c_bbpll_lref@l1936, uint8_t i2c_bbpll_div_7_0@l1937, uint8_t i2c_bbpll_dcur@l1938 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <rtc_clk_bbpll_set_new> (51 insns) + DWARF line rows for wifi.c:1900.
     * Ordered callee relocs: ets_delay_us.
     */
}

/* rtc_clk_cpu_freq_set_new wifi.c:1945 @ wifi.o size 152B [dwarf-sig]
 * Calls: rtc_clk_xtal_freq_get, ets_update_cpu_frequency, rtc_clk_wait_for_slow_cycle, esp_dport_access_reg_read, rtc_clk_apb_freq_update, rtc_clk_bbpll_set_new | Data refs: esp_dport_access_reg_read, ets_update_cpu_frequency, rtc_clk_apb_freq_update, rtc_clk_bbpll_set_new, rtc_clk_wait_for_slow_cycle, rtc_clk_xtal_freq_get | MMIO: 0x3ff48000, 0x3ff48070
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rtc_clk_cpu_freq_set_new(uint8 ref)
{
    (void)ref;
    /* DWARF locals: rtc_xtal_freq_t xtal_freq@l1947 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <rtc_clk_cpu_freq_set_new> (54 insns) + DWARF line rows for wifi.c:1945.
     * Ordered callee relocs: rtc_clk_xtal_freq_get, ets_update_cpu_frequency, rtc_clk_wait_for_slow_cycle, esp_dport_access_reg_read, rtc_clk_apb_freq_update, rtc_clk_bbpll_set_new.
     */
}

/* run_rftest_case wifi.c:2335 @ wifi.o size 13960B [dwarf-sig]
 * Calls: strcmp x247 (dispatch) + per-branch ATE callees, all verified in bodies:
 * WifiTxStart, FillTxPacket, SPIRead/SPIEraseSector/SPIWrite, memset, register_chipv7_phy,
 * bb_init, mac_init, rf_init, noise_init, adctrig, rw/bt/fcc/le test fns, pbus/gpio/rtc
 * helpers, ets_* drivers, phy_printf, esp_dport_access_reg_read; indirect g_phyFuns[N].
 * Fidelity: medium - 247-entry strcmp dispatch fully reconstructed from
 * .text.run_rftest_case disasm + relocs + .rodata.str1.4 strings: exact command
 * strings in exact order, exact per-branch calls/branch-targets/immediates/MMIO.
 * para_array (a7-saved) word/byte/halfword lanes, g_phyFuns[N] indirect calls,
 * 0x900 stack frame modeled as __fr union, join-value ternaries, ATE loops as
 * for-loops (RdMem/read_flash/erase_flash/write_flash/txdc/dig_atten/atten-prt/
 * initdata/noise-check/txpower/wr_rfcal/i2c/efuse/memcpy). Approximate: joined
 * values on multi-path labels, (g_phyFuns[0])[N] method identities. Returns
 * true on match (a3=1, common exit), false on total mismatch (last dispatch
 * exits with a3=0). Ground truth: wifi.o `.text.run_rftest_case` (5078 insns).
 */
bool run_rftest_case(char * command, uint32 * para_array, uint32 para_num)
{
    /* DWARF locals: uint32 i, result (a3 return flag; modeled by returns) */
    uint32 i, t0, t1, p;
    u32 *dst;
    u32 rv0, rv1, rv2, rv3, rv4, rv5;
    union { u8 b[0x900]; u16 h[0x480]; u32 w[0x240]; } __fr;
    extern unsigned g_phyFuns[];
    extern u32 chip7_sleep_params, short_gi_enable;
    extern u8 adaptive_test_en[], tx_cbw40m_en[], rssi_min_max_print[];
    extern u8 uart_test_enable[], flash_test_enable[], psram_test_enable[];
    extern u8 chip7_phy_init_ctrl[], init_param_default[], re_entry[];
    extern u8 noise_array[], tx_rf_ana_gain[], phy_wifi_pll_track_en[];
    extern u8 phy_bt_pll_track_en[], phy_bt_power_track_en[];
    extern u8 phy_tx_pwr_track_en[], phy_tx_pwr_correct_en[], phy_tx_pwr_print_en[];
    extern u8 phy_tx_power_out[], btpwr_tsen_init[], chan14_mic_en[];
    extern u8 chan14_mic_most_power[], phy_chan_target_power[], phy_chan_pwr_index[];
    extern u8 phy_chan_gain_table[], phy_freq_offset[], bt_rx_2440_dac[];
    extern u8 bt_rx_2480_dac[], temp_offset[], pwrdet_offset[];
    extern u8 bt_2480_opt_en[], bt_2480_print[], wr_data[], wr_en[];
    extern u8 mac_filter_en[], rc_cal_en[], wifi_txband[], wifi_txband_ht40[];
    extern u8 force_tx_gain_en[], bt_tester_param[], bt_dut_param[];
if (!strcmp(command, "WifiTxStart")) {
if (para_array[1] != 0) goto L_14b4;
__fr.w[0] = para_array[5];
phy_printf("wifi tx out: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]) /* stack args: __fr.w[0] */;
L_14b4:;
WifiTxStart(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]);
rv2 = esp_dport_access_reg_read(0x60033c68);
phy_printf(" Tx Over, tx_state:0x%x!\n", (rv2 & 0xff));
goto L_done;
}
if (!strcmp(command, "remove_11b_4p8G_spur")) {
remove_11b_4p8G_spur(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8]);
phy_printf("remove_11b_4p8G_spur: %d %d %d\n", para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "adaptive_test_en")) {
*(u8*)(adaptive_test_en) = para_array[0];
if (para_num == 1) goto L_1546;
goto L_154a;
L_1546:;
L_154a:;
rv0 = esp_dport_access_reg_read(0x3ff5c01c);
*(u32*)(0x3ff5c01c) = ((rv0 & 0xffffff00) | (para_num == 1 ? 0x10 : (para_array[1] & 0xff)));
phy_printf("adaptive_test_en: %d, %d\n", (*(u8*)(adaptive_test_en)), (para_num == 1 ? 0x10 : (para_array[1] & 0xff)));
goto L_done;
}
if (!strcmp(command, "tx_cbw40m_en")) {
*(u8*)(tx_cbw40m_en) = para_array[0];
phy_printf("tx_cbw40m_en: %d\n", (para_array[0] & 0xff));
goto L_done;
}
if (!strcmp(command, "cbw40m_en")) {
cbw40m_en(((u8*)para_array)[0]);
goto L_done;
}
if (!strcmp(command, "DIG_GAIN_RSE")) {
dig_gain_rse(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8], ((s32)(para_array[3] << 25) >> 25), ((u8*)para_array)[16]);
phy_printf("rate=0x%x,clip_val=0x%x,clip_cmp=%d,backoff=%d,cbw40=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]);
goto L_done;
}
if (!strcmp(command, "short_gi_enable")) {
short_gi_enable = para_array[0];
phy_printf("short_gi_enable=%d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "rssi_min_max_print")) {
*(u8*)(rssi_min_max_print) = para_array[0];
phy_printf("rssi_min_max_print=%d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "gpio_test_init")) {
phy_printf("gpio_test_init: 0x%x\n", para_array[0]);
gpio_test_init(para_array[0]);
goto L_done;
}
if (!strcmp(command, "uart_test_enable")) {
*(u8*)(uart_test_enable) = para_array[0];
phy_printf("uart_test_enable: %d\n", (para_array[0] & 0xff));
goto L_done;
}
if (!strcmp(command, "flash_test_init")) {
if (para_num <u 3) goto L_16ba;
L_16ba:;
phy_printf("flash_test_init: clk_div=%d, drv=%d, mode=%d\n", para_array[0], para_array[1], (para_num <u 3 ? 0 : ((u8*)para_array)[8]));
flash_test_init(para_array[0], para_array[1], (para_num <u 3 ? 0 : ((u8*)para_array)[8]));
SPI_read_local(0x1000, 0);
goto L_done;
}
if (!strcmp(command, "flash_pad_drv")) {
__fr.w[0] = para_array[5];
phy_printf("flash_pad_drv: clk_drv=%d, cmd_drv=%d, data0_drv=%d, data1_drv=%d, data2_drv=%d, data3_drv=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]) /* stack args: __fr.w[0] */;
gpio_set_flash_drv(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8], ((u8*)para_array)[12], ((u8*)para_array)[16], ((u8*)para_array)[20]);
goto L_done;
}
if (!strcmp(command, "flash_test_enable")) {
*(u8*)(flash_test_enable) = para_array[0];
phy_printf("flash_test_enable=%d\n", (para_array[0] & 0xff));
goto L_done;
}
if (!strcmp(command, "psram_test_enable")) {
*(u8*)(psram_test_enable) = para_array[0];
phy_printf("psram_test_enable=%d\n", (para_array[0] & 0xff));
goto L_done;
}
if (!strcmp(command, "tx_contin_en")) {
tx_contin_en(((u8*)para_array)[0]);
goto L_done;
}
if (!strcmp(command, "wifitxout")) {
wifitxout(para_array, para_num);
goto L_done;
}
if (!strcmp(command, "wifiscwout")) {
wifiscwout(para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "esp_tx")) {
esp_tx_func(para_array, para_num);
goto L_done;
}
if (!strcmp(command, "esp_rx")) {
esp_rx_func(para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "esp_tx_duty")) {
esp_tx_func_duty(para_array[0], para_array[1], para_array[2], ((u8*)para_array)[12]);
goto L_done;
}
if (!strcmp(command, "esp_tx_notxon")) {
esp_tx_func_notxon(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]);
goto L_done;
}
if (!strcmp(command, "WifiRxStart")) {
phy_printf("wifi rx in\n");
bb_wdt_rst_enable(1);
do_rx_poll(para_array[0]);
goto L_done;
}
if (!strcmp(command, "FillTxPacket")) {
__fr.w[5] = para_array[11];
__fr.w[1] = para_array[7];
__fr.w[4] = para_array[10];
__fr.w[3] = para_array[9];
__fr.w[2] = para_array[8];
__fr.w[0] = para_array[6];
FillTxPacket(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]) /* stack args: __fr.w[5], __fr.w[1], __fr.w[4], __fr.w[3], __fr.w[2], __fr.w[0] */;
phy_printf("Fill Tx Packet OK!\n");
goto L_done;
}
if (!strcmp(command, "rd")) {
rv0 = esp_dport_access_reg_read(para_array[0]);
phy_printf("0x%x\n", rv0);
goto L_done;
}
if (!strcmp(command, "rd_dport")) {
phy_printf("0x%x\n", *(u32*)(para_array[0]));
goto L_done;
}
if (!strcmp(command, "wr_dport")) {
*(u32*)(para_array[0]) = para_array[1];
phy_printf("0x%x\n", *(u32*)(para_array[0]));
goto L_done;
}
if (!strcmp(command, "wr")) {
*(u32*)(para_array[0]) = para_array[1];
rv0 = esp_dport_access_reg_read(para_array[0]);
phy_printf("0x%x\n", rv0);
goto L_done;
}
if (!strcmp(command, "RdMem")) {
_xtos_ints_off(0x1000);
for (i = para_array[0]; i <u para_array[0] + para_array[1]; i += 4)
    phy_printf("0x%x ", esp_dport_access_reg_read(i));
phy_printf("\n");
_xtos_ints_on(0x1000);
goto L_done;
}
if (!strcmp(command, "sm")) {
rv0 = esp_dport_access_reg_read(para_array[0]);
*(u32*)(para_array[0]) = (rv0 | para_array[1]);
rv1 = esp_dport_access_reg_read(para_array[0]);
phy_printf("reg 0x%x readback is 0x%x\n", para_array[0], rv1);
goto L_done;
}
if (!strcmp(command, "cm")) {
rv0 = esp_dport_access_reg_read(para_array[0]);
*(u32*)(para_array[0]) = ((0xffffffff ^ para_array[1]) & rv0);
rv1 = esp_dport_access_reg_read(para_array[0]);
phy_printf("reg 0x%x readback is 0x%x\n", para_array[0], rv1);
goto L_done;
}
if (!strcmp(command, "gb")) {
rv0 = esp_dport_access_reg_read(para_array[0]);
phy_printf("0x%x\n", ((((1 << ((para_array[1] + 1) - para_array[2])) & 0xffffffff)-1) & (((u32)(rv0)) >> para_array[2])));
goto L_done;
}
if (!strcmp(command, "ri")) {
rv0 = (*(g_phyFuns[0])[38]/*indirect*/)(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8]);
phy_printf("0x%x\n", rv0);
goto L_done;
}
if (!strcmp(command, "wi")) {
(*(g_phyFuns[0])[40]/*indirect*/)(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8], ((u8*)para_array)[12]);
phy_printf("write ok!\n");
goto L_done;
}
if (!strcmp(command, "wim")) {
(*(g_phyFuns[0])[42]/*indirect*/)(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8], ((u8*)para_array)[12], ((u8*)para_array)[16], ((u8*)para_array)[20]);
phy_printf("write ok!\n");
goto L_done;
}
if (!strcmp(command, "rim")) {
rv0 = (*(g_phyFuns[0])[41]/*indirect*/)(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8], ((u8*)para_array)[12], ((u8*)para_array)[16]);
phy_printf("0x%x\n", rv0);
goto L_done;
}
if (!strcmp(command, "pbus_debugmode")) {
(*(g_phyFuns[0])[48]/*indirect*/)();
phy_printf("pbus set debugmode ok!\n");
goto L_done;
}
if (!strcmp(command, "pbus_workmode")) {
(*(g_phyFuns[0])[49]/*indirect*/)();
phy_printf("pbus set workmode ok!\n");
goto L_done;
}
if (!strcmp(command, "pbus")) {
(*(g_phyFuns[0])[46]/*indirect*/)(((u8*)para_array)[0], ((u8*)para_array)[4], (((u16*)para_array)[4]));
phy_printf("pbus set ok!\n");
goto L_done;
}
if (!strcmp(command, "pbus_rd")) {
rv0 = (*(g_phyFuns[0])[47]/*indirect*/)(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("0x%x\n", rv0);
goto L_done;
}
if (!strcmp(command, "txtone")) {
(*(g_phyFuns[0])[18]/*indirect*/)(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]);
phy_printf("tx tone ok!\n");
if ((*(u8*)(uart_test_enable)) != 0) goto L_1c6d;
L_1c68:;
goto L_done;
L_1c6d:;
phy_printf("a");
rv3 = GetStopCmd();
if (rv3 != 0) goto L_1c6d;
goto L_1c68;
}
if (!strcmp(command, "txtone_step")) {
(*(g_phyFuns[0])[17]/*indirect*/)(((u8*)para_array)[0], ((s16)((u16*)para_array)[2]), ((u8*)para_array)[8], ((u8*)para_array)[12], ((s16)((u16*)para_array)[8]), ((u8*)para_array)[20]);
phy_printf("tx tone step ok!\n");
goto L_done;
}
if (!strcmp(command, "stoptone")) {
(*(g_phyFuns[0])[19]/*indirect*/)(para_array[0]);
phy_printf("stop tone ok!\n");
goto L_done;
}
if (!strcmp(command, "adctrig")) {
__fr.w[1] = para_array[7];
__fr.w[2] = para_array[8];
__fr.w[0] = para_array[6];
adctrig(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]) /* stack args: __fr.w[1], __fr.w[2], __fr.w[0] */;
phy_printf("adctrig done\n");
goto L_done;
}
if (!strcmp(command, "noise_init_check")) {
noise_init_check(para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "check_noise_floor")) {
(*(g_phyFuns[0])[32]/*indirect*/)();
rv1 = esp_dport_access_reg_read(0x3ff5c050);
phy_printf("%d\n", ((rv1 & 0x3ff)-1024));
goto L_done;
}
if (!strcmp(command, "noise_init")) {
if (para_array[0] != 1) goto L_1d9d;
*(u8*)(chip7_phy_init_ctrl+2) = para_array[1];
*(u8*)(chip7_phy_init_ctrl+3) = para_array[2];
*(u8*)(chip7_phy_init_ctrl+4) = para_array[3];
L_1d9d:;
chip7_sleep_params = (chip7_sleep_params & 0xffdfffff);
noise_init();
phy_printf("noise_init done\n");
goto L_done;
}
if (!strcmp(command, "init_para_chg")) {
if (para_array[0] != 1) goto L_1dea;
*(u8*)((init_param_default + para_array[1])) = para_array[2];
L_1dea:;
register_chipv7_phy_init_param(init_param_default);
phy_printf("init_param_default[%d]=0x%x\n", para_array[1], ((s32)((*(u8*)((init_param_default + para_array[1]))) << 25) >> 25));
goto L_done;
}
if (!strcmp(command, "bb_init")) {
chip7_sleep_params = 0;
bb_init();
rx_gain_level(0);
phy_printf("bb_init done\n");
goto L_done;
}
if (!strcmp(command, "mac_init")) {
mac_init();
phy_printf("mac_init done\n");
goto L_done;
}
if (!strcmp(command, "wifi_track_pll_cap")) {
wifi_track_pll_cap();
phy_printf("wifi_track_pll_cap: %dus\n", (*(u32*)(0x60033c00) - *(u32*)(0x60033c00)));
goto L_done;
}
if (!strcmp(command, "phy_close_pa")) {
phy_close_pa(((u8*)para_array)[0]);
phy_printf("phy_close_pa %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "uart1_sel")) {
rv0 = esp_dport_access_reg_read(0x3ff000bc);
*(u32*)(0x3ff000bc) = (rv0 | 1);
rv1 = esp_dport_access_reg_read(0x3ff49054);
*(u32*)(0x3ff49054) = ((rv1 & 0xffff8fff) | 0x4000);
rv2 = esp_dport_access_reg_read(0x3ff49058);
*(u32*)(0x3ff49058) = ((rv2 & 0xffff8fff) | 0x4000);
rv3 = esp_dport_access_reg_read(0x3ff0018c);
*(u32*)(0x3ff0018c) = ((rv3 & 0xffffffe0) | 5);
goto L_done;
}
if (!strcmp(command, "psram_op")) {
ets_efuse_get_spiconfig();
spi_flash_attach();
__fr.w[1] = para_array[7];
__fr.w[4] = para_array[10];
__fr.w[3] = para_array[9];
__fr.w[2] = para_array[8];
__fr.w[0] = para_array[6];
PsramBoardTest(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]) /* stack args: __fr.w[1], __fr.w[4], __fr.w[3], __fr.w[2], __fr.w[0] */;
goto L_done;
}
if (!strcmp(command, "read_flash")) {
ets_efuse_get_spiconfig();
spi_flash_attach();
memset(((u32)&__fr.b[48]), 0, 0x400);
if (0x400 >=u para_array[1]) goto L_1fc9;
phy_printf("Error: data length > %d\r\n", 0x400);
goto L_2008;
L_1fc9:;
SPIRead(para_array[0], ((u32)&__fr.b[48]), para_array[1]);
phy_printf("READ FLASH 0x%08x, length: %d :\r\n", para_array[0], para_array[1]);
for (i = 0; i != para_array[1]; i++)
    phy_printf("%02x ", __fr.b[48 + i]);
phy_printf("\r\nFLASH READ END.\r\n");
L_2008:;
goto L_done;
}
if (!strcmp(command, "erase_flash")) {
ets_efuse_get_spiconfig();
spi_flash_attach();
if (0x400 <u (para_array[0] + para_array[1])) goto L_203d;
for (i = 0; i != para_array[1]; i++)
    SPIEraseSector(para_array[0] + i);
phy_printf("ERASE OK\r\n");
goto L_done;
L_203d:;
phy_printf("ERROR:SECTOR OUT OF RANGE\r\n");
goto L_done;
}
if (!strcmp(command, "write_flash")) {
ets_efuse_get_spiconfig();
spi_flash_attach();
memset(((u32)&__fr.b[48]), 0, 0x78);
if (0x78 >=u para_array[1]) goto L_20af;
phy_printf("ERROR:LENGTH EXCEED 120 BYTES\r\n");
goto L_20e9;
L_20af:;
if ((para_array[0] & 0x3) == 0) goto L_20d1;
phy_printf("ERROR:ADDR MUST BE 4 BYTES ALIGNED\r\n");
goto L_20e9;
for (i = 0; i != para_array[1]; i++)
    __fr.b[48 + i] = ((u8*)para_array)[8 + 4 * i];
L_20d1:;
SPIWrite(para_array[0], ((u32)&__fr.b[48]), para_array[1]);
phy_printf("FLASH WRITE OK\r\n");
L_20e9:;
/* multi-path join L_20e9: values approximate */
goto L_done;
}
if (!strcmp(command, "RFChannelSel")) {
RFChannelSel(((s32)(para_array[0] << 25) >> 25), ((s32)(para_array[1] << 25) >> 25));
phy_printf(" RF channel select as %d %d, %dus\n", para_array[0], para_array[1], (*(u32*)(0x60033c00) - *(u32*)(0x60033c00)));
goto L_done;
}
if (!strcmp(command, "set_chan")) {
chip_v7_set_chan(((s32)(para_array[0] << 25) >> 25), ((s32)(para_array[1] << 25) >> 25));
phy_printf(" RF channel select as %d %d\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "read_hw_noisefloor")) {
rv0 = read_hw_noisefloor();
phy_printf("noisefloor=%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "txdc_cal_init")) {
(*(g_phyFuns[0])[69]/*indirect*/)(((u32)&__fr.b[48]), (*(u16*)(tx_rf_ana_gain)), (*(u16*)(tx_rf_ana_gain+2)), 0);
phy_printf("txdc: ");
for (i = 0; i < 5; i++)
    phy_printf("%d, %d, %d, %d; ", __fr.h[24 + 4 * i], __fr.h[25 + 4 * i], __fr.h[26 + 4 * i], __fr.h[27 + 4 * i]);
phy_printf("\n");
goto L_done;
}
if (!strcmp(command, "txdc_cal")) {
phy_printf("pa=0x%x, bb=0x%x,delay=%d,workmode=%d,bt_mode=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]);
(*(g_phyFuns[0])[48]/*indirect*/)();
(*(g_phyFuns[0])[54]/*indirect*/)((((u16*)para_array)[0]), (((u16*)para_array)[2]));
if (para_array[4] != 1) goto L_224d;
rv3 = (*(g_phyFuns[0])[47]/*indirect*/)(para_array[4], para_array[4]);
(*(g_phyFuns[0])[46]/*indirect*/)(para_array[4], para_array[4], ((rv3 | 2) & 0xffff));
L_224d:;
for (i = 0; i <u para_array[2]; i++)
    ets_delay_us(1000);
(*(g_phyFuns[0])[70]/*indirect*/)(((u32)&__fr.b[48]));
phy_printf("txdc_cal, %d, %d, %d, %d, %dus\n", ((s16)__fr.h[24]), ((s16)__fr.h[25]), ((s16)__fr.h[26]), ((s16)__fr.h[27]));
if (para_array[3] != 0) goto L_2299;
(*(g_phyFuns[0])[52]/*indirect*/)(para_array[3]);
(*(g_phyFuns[0])[49]/*indirect*/)();
L_2299:;
goto L_done;
}
if (!strcmp(command, "target_power_backoff")) {
target_power_backoff(((s32)(para_array[0] << 25) >> 25));
phy_printf("target_power_backoff %d dB set ok!\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "set_tx_gain")) {
*(u8*)(force_tx_gain_en) = 1;
set_tx_gain_table((((u16*)para_array)[0]), (((u16*)para_array)[2]));
*(u16*)(tx_rf_ana_gain+2) = para_array[1];
*(u16*)(tx_rf_ana_gain) = para_array[0];
phy_printf("set_tx_gain, 0x%x, 0x%x, done\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "set_bttx_gain")) {
*(u8*)(chip7_sleep_params+127) = para_array[0];
*(u8*)(chip7_sleep_params+136) = para_array[2];
*(u16*)(chip7_sleep_params+144) = para_array[1];
wr_bt_tx_gain_mem(0xff, 0xff);
wr_bt_tx_atten(chip7_sleep_params);
phy_printf("set_bttx_gain, 0x%x, 0x%x, %d, done\n", para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "phy_set_most_tpw")) {
phy_set_most_tpw(((s32)(para_array[0] << 25) >> 25));
phy_printf("phy_set_most_tpw: %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "phy_get_most_tpw")) {
rv0 = phy_get_most_tpw();
phy_printf("phy_gset_most_tpw: %d\n", ((s32)(rv0 << 25) >> 25));
goto L_done;
}
if (!strcmp(command, "phy_get_tx_pwr")) {
rv0 = phy_get_tx_pwr();
phy_printf("phy_get_tx_pwr, %d\n", rv0);
goto L_done;
}
if (!strcmp(command, "set_tx_dig_gain")) {
set_tx_dig_gain(para_array[0], para_array[1]);
phy_printf("set_tx_dig_gain, 0x%x, 0x%x, done\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "readvdd33")) {
rv0 = (*(g_phyFuns[0])[102]/*indirect*/)();
phy_printf("vdd33=%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "tsen_meas")) {
rv0 = temprature_sens_read();
phy_printf("temp=%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "set_rf_freq_offset")) {
(*(g_phyFuns[0])[63]/*indirect*/)(((u8*)para_array)[0], (((u16*)para_array)[2]), ((s16)((u16*)para_array)[4]));
phy_printf("set_rf_freq_offset: %d, %d, %d\n", para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "pll_cap_track_en")) {
*(u8*)(phy_wifi_pll_track_en) = para_array[0];
phy_printf("phy_wifi_pll_track_en: %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "dpd_bypass")) {
rv0 = esp_dport_access_reg_read(0x3ff450cc);
*(u32*)(0x3ff450cc) = ((((para_array[0] & 0x1) << 22) & 0xffffffff) | (rv0 & 0xffbfffff));
phy_printf("dpd_bypass = %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "accumiq")) {
accumiq(para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "get_rx_tone_pwr")) {
get_rx_tone_pwr((float)(u32)(para_array[0]));
goto L_done;
}
if (!strcmp(command, "rfcal_rxiq")) {
(*(g_phyFuns[0])[88]/*indirect*/)(0xe, 0x40, 0x28, ((u32)&__fr.b[48]), 0);
phy_printf("rxiq: %d %d\n", ((s32)(__fr.b[48] << 25) >> 25), ((s32)(__fr.b[49] << 25) >> 25));
goto L_done;
}
if (!strcmp(command, "phy_init")) {
chip7_sleep_params = 0;
*(u8*)(re_entry) = 0;
register_chipv7_phy(init_param_default, ((u32)&__fr.b[48]), 2);
rx_gain_level(0);
phy_printf("phy_init done%d\n");
goto L_done;
}
if (!strcmp(command, "rxdc_cal")) {
static const u16 rxdc_init[4] = {256, 256, 256, 256}; /* wifi.o .rodata+0xc */
__fr.h[24] = rxdc_init[0];
__fr.h[25] = rxdc_init[1];
__fr.h[26] = rxdc_init[2];
__fr.h[27] = rxdc_init[3];
(*(g_phyFuns[0])[84]/*indirect*/)(0xfa0, ((u32)&__fr.b[48]), 0xa, ((u8*)para_array)[0], ((u8*)para_array)[0]);
phy_printf("rxdc: %d %d %d %d\n", ((s16)__fr.h[24]), ((s16)__fr.h[25]), ((s16)__fr.h[26]), ((s16)__fr.h[27]));
goto L_done;
}
if (!strcmp(command, "set_chan_offset")) {
chip_v7_set_chan_offset(((s16)((u16*)para_array)[0]));
phy_printf("freq: %d %dkhz %d\n", para_array[0], ((s16)((u16*)para_array)[0]), ((s16)*(u16*)(phy_freq_offset)));
goto L_done;
}
if (!strcmp(command, "freq_correct")) {
*(u16*)(phy_freq_offset) = ((s16)((u16*)para_array)[0]);
t0 = *(u32*)(0x60033c00);
rv0 = (*(g_phyFuns[0])[62]/*indirect*/)(1, ((s16)((u16*)para_array)[0]));
t1 = *(u32*)(0x60033c00);
phy_printf("freq: %dkhz %d, %dus\n", ((s16)((u16*)para_array)[0]), ((s16)*(u16*)(phy_freq_offset)), t1 - t0);
goto L_done;
}
if (!strcmp(command, "bt_tx_gain")) {
set_tx_gain_table_bt();
phy_printf("bt_tx_gain, %ddB\n", ((s32)(para_array[0] << 25) >> 25));
goto L_done;
}
if (!strcmp(command, "read_noise")) {
phy_printf("noise, %d, %d, %d\n", ((s16)*(u16*)(noise_array)), ((s16)*(u16*)(noise_array+2)), ((s16)*(u16*)(noise_array+4)));
goto L_done;
}
if (!strcmp(command, "rf_init")) {
chip7_sleep_params = 0;
rf_init();
phy_printf("rf_init done\n");
goto L_done;
}
if (!strcmp(command, "RF_init_sel")) {
RF_init_sel(((u8*)para_array)[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "RF_pwrdet_recal")) {
memset(((u32)&__fr.b[2096]), 0, 0x80);
__fr.w[566] = 0;
*(u8*)(((u32)&__fr.b[2096])) = 6;
*(u8*)((u32)&__fr.b[2100]) = 6;
*(u8*)((u32)&__fr.b[2103]) = 6;
*(u8*)((u32)&__fr.b[2106]) = 6;
*(u8*)((u32)&__fr.b[2115]) = 6;
*(u8*)((u32)&__fr.b[2118]) = 6;
*(u8*)((u32)&__fr.b[2099]) = 9;
__fr.w[564] = ((u32)&__fr.b[2096]);
*(u8*)((u32)&__fr.b[2105]) = 4;
*(u8*)((u32)&__fr.b[2107]) = 4;
*(u8*)((u32)&__fr.b[2114]) = 9;
*(u8*)((u32)&__fr.b[2130]) = 0xfffffffe;
*(u8*)((u32)&__fr.b[2098]) = 5;
*(u8*)((u32)&__fr.b[2101]) = 5;
*(u8*)((u32)&__fr.b[2102]) = 3;
*(u8*)((u32)&__fr.b[2104]) = 5;
*(u8*)((u32)&__fr.b[2108]) = 5;
*(u8*)((u32)&__fr.b[2113]) = 5;
*(u8*)((u32)&__fr.b[2116]) = 5;
*(u8*)((u32)&__fr.b[2117]) = 3;
*(u8*)((u32)&__fr.b[2119]) = 5;
*(u8*)((u32)&__fr.b[2128]) = 0xfffffffc;
*(u8*)((u32)&__fr.b[2129]) = 0xfffffffc;
*(u8*)((u32)&__fr.b[2131]) = 0xfffffff0;
*(u8*)((u32)&__fr.b[2132]) = 0xfffffff0;
*(u8*)((u32)&__fr.b[2133]) = 0xfffffff0;
*(u8*)((u32)&__fr.b[2134]) = 0xffffffe0;
*(u8*)((u32)&__fr.b[2135]) = 0xffffffe0;
*(u8*)((u32)&__fr.b[2136]) = 0xffffffe0;
*(u8*)((u32)&__fr.b[2137]) = 0x18;
*(u8*)((u32)&__fr.b[2138]) = 0x18;
*(u8*)((u32)&__fr.b[2139]) = 0x18;
*(u8*)((u32)&__fr.b[2152]) = 4;
*(u8*)((u32)&__fr.b[2142]) = 0x42;
*(u8*)((u32)&__fr.b[2140]) = 0x4e;
*(u8*)((u32)&__fr.b[2143]) = 0x3c;
*(u8*)((u32)&__fr.b[2141]) = 0x48;
*(u8*)((u32)&__fr.b[2144]) = 0x38;
*(u8*)((u32)&__fr.b[2149]) = 2;
*(u8*)((u32)&__fr.b[2150]) = 2;
*(u8*)((u32)&__fr.b[2145]) = 0x34;
*(u8*)((u32)&__fr.b[2146]) = 1;
*(u8*)((u32)&__fr.b[2147]) = 1;
*(u8*)((u32)&__fr.b[2148]) = 1;
*(u8*)((u32)&__fr.b[2151]) = 3;
*(u8*)((u32)&__fr.b[2153]) = 5;
*(u8*)((u32)&__fr.b[2154]) = 1;
for (__fr.w[566] = 0; __fr.w[566] < 0x80; __fr.w[566]++)
    (*(u8*)(init_param_default + __fr.w[566])) = (*(u8*)(__fr.w[564] + __fr.w[566]));
if (para_array[0] == 0) goto L_2889;
L_2889:;
*(u8*)(init_param_default+81) = (para_array[0] == 0 ? para_array[0] : 1);
chip7_sleep_params = 0;
*(u8*)(re_entry) = 0;
register_chipv7_phy(init_param_default, ((u32)&__fr.b[48]), 2);
phy_printf("power detector recal,pwrdet_offset=%d!\n", (*(u16*)(pwrdet_offset)));
goto L_done;
}
if (!strcmp(command, "esp_chg_freqoff")) {
esp_chg_freqoff(((s32)(para_array[0] << 25) >> 25), para_array[1]);
goto L_done;
}
if (!strcmp(command, "write_temp_efuse")) {
rv0 = slow_clk_write_efuse(((u8*)para_array)[0]);
if (rv0 != 1) goto L_2910;
phy_printf("%d,burn_efuse Pass!\n", rv0);
goto L_done;
L_2910:;
if (((rv0-2) & 0xff) >=u 2) goto L_2929;
phy_printf("%d,burn_efuse Fail!\n", rv0);
goto L_done;
L_2929:;
phy_printf("%d,error!\n", rv0);
goto L_done;
}
if (!strcmp(command, "dig_atten")) {
for (i = 1; i <= 6; i++)
    phy_printf("%d,", ((s32)((*(u8*)(chip7_sleep_params+95+i)) << 25) >> 25));
L_2963:;
phy_printf("\n");
goto L_done;
}
if (!strcmp(command, "read_temp")) {
rv0 = slow_clk_read_temp();
if (rv0 != 0xff) goto L_2998;
phy_printf("temp efuse unburnning!\n");
goto L_done;
L_2998:;
phy_printf("temp:%d\n", (rv0 - (*(u8*)(temp_offset))));
goto L_done;
}
if (!strcmp(command, "rtc_xtal_32k_test")) {
rtc_xtal_32k_test(0, 2, 3, 0);
goto L_done;
}
if (!strcmp(command, "rtc_slowck_cali")) {
rv0 = rtc_slowck_cali(para_array[0], 0x80);
phy_printf("period: %d\n", rv0);
phy_printf("cali: %d value: %d\n", para_array[0], (((((u64)(u32)(rv0) * (u32)(0xf4240) >> 32) << 13) & 0xffffffff) | ((((rv0 * 0xf4240) & 0xffffffff) >> 19) & 0x1fff)));
goto L_done;
}
if (!strcmp(command, "ESP_TEST_GPIO")) {
ESP_TEST_GPIO_func(para_array);
goto L_done;
}
if (!strcmp(command, "ESP_TEST_GPIO_DRV")) {
ESP_TEST_GPIO_DRV(para_array, ((u32)&__fr.b[48]), ((u8*)para_array)[12]);
phy_printf("Input result:0x%x,0x%x,0x%x\n", __fr.w[12], __fr.w[13], __fr.w[14]);
goto L_done;
}
if (!strcmp(command, "cmdstop_gpio")) {
CMDSTOP_GPIO();
goto L_done;
}
if (!strcmp(command, "Vsar2_pwc_mea_ate")) {
Vsar2_pwc_mea_ate(4, 7);
phy_printf("output SARADC reference voltage on pad gpio27!\n");
goto L_done;
}
if (!strcmp(command, "DIG_pwc_mea_ate")) {
DIG_pwc_mea_ate(para_array[0], ((u8*)para_array)[4]);
phy_printf("DIG_pwc_mea_ate OK!\n");
goto L_done;
}
if (!strcmp(command, "RTC_pwc_mea_ate")) {
RTC_pwc_mea_ate(para_array[0], ((u8*)para_array)[4]);
phy_printf("RTC_pwc_mea_ate OK\n");
goto L_done;
}
if (!strcmp(command, "clr_pwc_mea")) {
clr_pwc_mea();
phy_printf("clr ok!\n");
goto L_done;
}
if (!strcmp(command, "phy_wifitx_low_power")) {
phy_wifitx_low_power(((u8*)para_array)[0], ((u8*)para_array)[4], ((s32)(para_array[2] << 25) >> 25));
phy_printf("phy_wifitx_low_power ok!\n");
goto L_done;
}
if (!strcmp(command, "rx_pbus_set")) {
rx_pbus_set((((u16*)para_array)[0]), (((u16*)para_array)[2]), (((u16*)para_array)[4]), (((u16*)para_array)[6]));
phy_printf("rx_pbus_set: 0x%x, 0x%x, 0x%x, 0x%x\n", para_array[0], para_array[1], para_array[2], para_array[3]);
goto L_done;
}
if (!strcmp(command, "tx_pbus_set")) {
tx_pbus_set((((u16*)para_array)[0]), (((u16*)para_array)[2]), (((u16*)para_array)[4]), (((u16*)para_array)[6]));
phy_printf("tx_pbus_set: 0x%x, 0x%x, 0x%x, 0x%x\n", para_array[0], para_array[1], para_array[2], para_array[3]);
goto L_done;
}
if (!strcmp(command, "pa_pbus_set")) {
pa_pbus_set((((u16*)para_array)[0]), (((u16*)para_array)[2]));
phy_printf("pa_pbus_set: 0x%x, 0x%x\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "write_efuse_dig_reserve_bit")) {
*(u8*)(wr_en+24) = (((para_array[0] << 2) & 0xffffffff) & 4);
*(u8*)(wr_data+24) = (((para_array[0] << 2) & 0xffffffff) & 4);
rv0 = burn_efuse(wr_data, wr_en);
*(u8*)(wr_data+24) = 0;
*(u8*)(wr_en+24) = 0;
if (rv0 != 1) goto L_2c54;
phy_printf("%d, PASS!\n", rv0);
goto L_done;
L_2c54:;
if (rv0 != 2) goto L_2c69;
phy_printf("%d, already burned!\n", rv0);
goto L_done;
L_2c69:;
phy_printf("%d, Fail!\n", rv0);
goto L_done;
}
if (!strcmp(command, "read_efuse_dig_reserve_bit")) {
rv0 = esp_dport_access_reg_read(0x3ff5a018);
phy_printf("dig_reserve_bit:%d\n", ((rv0 >> 2) & 0x1));
goto L_done;
}
if (!strcmp(command, "esp_chk_mac")) {
esp_chk_mac();
goto L_done;
}
if (!strcmp(command, "esp_set_mac")) {
esp_set_mac(para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "esp_set_target_txp")) {
esp_set_target_txp(para_array);
goto L_done;
}
if (!strcmp(command, "esp_get_target_txp")) {
esp_get_target_txp(para_array);
goto L_done;
}
if (!strcmp(command, "esp_origin_mac")) {
esp_origin_mac();
goto L_done;
}
if (!strcmp(command, "print_ver")) {
phy_printf("phy_version: %d.%d, %s, %s, %s\n", 0x1e6, 3, "a3a4459", "Oct 28 2025", "14:30:13");
phy_printf("*RFTestBIN %d\n", 0xc3);
phy_printf("print end\n");
goto L_done;
}
if (!strcmp(command, "init_print")) {
module_test_cal_print(1);
phy_printf("print end\n");
goto L_done;
}
if (!strcmp(command, "rx_per_init")) {
rx_per_init();
phy_printf("rx_per_init!\n");
goto L_done;
}
if (!strcmp(command, "test_noise_floor")) {
test_noise_floor(((u8*)para_array)[0], para_array[1]);
phy_printf("\n");
goto L_done;
}
if (!strcmp(command, "get_rx_buffer")) {
phy_printf("get_rx_buffer: %d, 0x%x,0x%x\n", para_array[0], para_array[1], para_array[2]);
get_rx_buffer(((u8*)para_array)[0], ((u8*)para_array)[4], para_array[2]);
phy_printf("\n");
goto L_done;
}
if (!strcmp(command, "dig_11b_filter_sel")) {
rv0 = esp_dport_access_reg_read(0x3ff5c400);
*(u32*)(0x3ff5c400) = ((((para_array[0] & 0x3) << 13) & 0xffffffff) | (rv0 & 0xffff9fff));
phy_printf("dig_11b_filter_sel: %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "rifs_mode_en")) {
wifi_rifs_mode_en(((u8*)para_array)[0]);
phy_printf("rifs_mode_en: %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "tsen_code")) {
rv0 = tsens_code_read();
phy_printf("tsen_code: %d %d\n", rv0, (*(u8*)(btpwr_tsen_init)));
goto L_done;
}
if (!strcmp(command, "set_bbfreq_init")) {
phy_set_bbfreq_init(((u8*)para_array)[0]);
phy_printf("sel 11b: %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "set_noise_floor")) {
(*(g_phyFuns[0])[33]/*indirect*/)(((s32)((-para_array[0]) << 17) >> 17));
phy_printf("set_noise_floor: %d\n", ((s32)((-para_array[0]) << 17) >> 17));
goto L_done;
}
if (!strcmp(command, "chan14_mic_enable")) {
chan14_mic_enable(((u8*)para_array)[0], ((s32)(para_array[1] << 25) >> 25));
phy_printf("chan14_mic_enable: %d,%d\n", (*(u8*)(chan14_mic_en)), ((s32)((*(u8*)(chan14_mic_most_power)) << 25) >> 25));
goto L_done;
}
if (!strcmp(command, "set_cca")) {
*(u8*)(adaptive_test_en) = para_array[0];
set_cca((para_array[0] & 0xff), ((s32)(para_array[1] << 25) >> 25));
phy_printf("%d,%d\n", (para_array[0] & 0xff), (para_array[1] & 0xff));
goto L_done;
}
if (!strcmp(command, "wr_bt_tx_atten")) {
wr_bt_tx_atten(chip7_sleep_params);
for (i = 0; i < 8; i++)
    phy_printf("%d:PA:%d,dig:%d\n", i, (*(u8*)(chip7_sleep_params+120+i)), ((s32)((*(u8*)(chip7_sleep_params+129+i)) << 25) >> 25));
goto L_1c68; /* shared GetStopCmd wait loop in "txtone" branch */
}
if (!strcmp(command, "set_bt_chan_cal_interp")) {
rv0 = set_bt_chan_cal_interp(((u8*)para_array)[0]);
phy_printf("%d,%d\n", ((u8*)para_array)[0], ((s32)(rv0 << 25) >> 25));
phy_set_bt_dig_gain(((u8*)para_array)[0]);
goto L_done;
}
if (!strcmp(command, "read_initdata_from_flash")) {
ets_efuse_get_spiconfig();
spi_flash_attach();
SPIRead(para_array[0], ((u32)&__fr.b[48]), 0x80);
for (i = 0; i < 128; i++)
    phy_printf("%d,%d,%d\n", i, __fr.b[48 + i], ((s32)((*(u8*)(init_param_default+i)) << 25) >> 25));
goto L_done;
}
if (!strcmp(command, "clk_pull_out")) {
clk_pull_out(para_array[0]);
goto L_done;
}
if (!strcmp(command, "clk50m_pull_out")) {
clk50m_pull_out(para_array[0]);
goto L_done;
}
if (!strcmp(command, "rtc_dac_out")) {
dac_out(((u8*)para_array)[0], ((u8*)para_array)[4], (((u16*)para_array)[4]), (((u16*)para_array)[6]), (((u16*)para_array)[8]));
phy_printf("dac_en=%d,tone_en=%d,dac_value=%d,tone_scale=%d,tone_step=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]);
goto L_done;
}
if (!strcmp(command, "rtc_adc1_read")) {
rv0 = adc1_read(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "rtc_adc2_read")) {
rv0 = adc2_read(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "rtc_get_tsen")) {
rv0 = my_temprature_sens_read((((u16*)para_array)[0]), ((u8*)para_array)[4]);
phy_printf("%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "bt_track")) {
phy_printf("bt_track start\n");
phy_bt_power_track(1);
__fr.w[0] = 0;
fcc_tx(0, 1, 1, 1, 1, 0) /* stack args: __fr.w[0] */;
goto L_done;
}
if (!strcmp(command, "burn_in_test")) {
burn_in_test();
goto L_done;
}
if (!strcmp(command, "improve_vol")) {
improve_dig_rtc_vol();
phy_printf("improve_vol\n");
goto L_done;
}
if (!strcmp(command, "test_txtone_pwr")) {
test_txtone_pwr(para_array[0], para_array[1], para_array[2], ((s16)((u16*)para_array)[6]));
phy_printf("\n");
goto L_done;
}
if (!strcmp(command, "txpwr_track_en")) {
*(u8*)(phy_tx_pwr_track_en) = para_array[0];
*(u8*)(phy_tx_pwr_correct_en) = para_array[1];
*(u8*)(phy_tx_pwr_print_en) = para_array[2];
phy_printf("txpwr_track_en: track_en=%d, correct_en=%d, print_en=%d\n", (para_array[0] & 0xff), (para_array[1] & 0xff), (para_array[2] & 0xff));
goto L_done;
}
if (!strcmp(command, "packet_pwdet_out")) {
phy_printf("%d\n", ((s16)*(u16*)(phy_tx_power_out)));
goto L_done;
}
if (!strcmp(command, "btpwr_track_en")) {
phy_bt_power_track(((u8*)para_array)[0]);
phy_printf("txpwr_track_en: track_en=%d\n", (*(u8*)(phy_bt_power_track_en)));
goto L_done;
}
if (!strcmp(command, "phy_get_txpwr_param")) {
phy_get_txpwr_param(((u32)&__fr.b[2096]), ((u32)&__fr.b[2224]), ((u32)&__fr.b[2232]), ((u32)&__fr.b[48]), ((u32)&__fr.b[2236]), ((u32)&__fr.b[2228]));
phy_printf("backoff: %d, %d, %d, %d\n", ((s32)((*(u8*)((u32)&__fr.b[2096])) << 25) >> 25), ((s32)((*(u8*)((u32)&__fr.b[2097])) << 25) >> 25), ((s32)((*(u8*)((u32)&__fr.b[2098])) << 25) >> 25), ((s32)((*(u8*)((u32)&__fr.b[2099])) << 25) >> 25));
phy_printf("rf_gain=0x%x, ana_gain=0x%x\n", (((u32)(*(u16*)((u32)&__fr.b[2232]))) >> 9), ((*(u16*)((u32)&__fr.b[2232])) & 0x1ff));
phy_printf("correct_pwr=%d, meas_error=%d\n", ((s32)((*(u8*)((u32)&__fr.b[2236])) << 25) >> 25), ((s16)*(u16*)((u32)&__fr.b[2228])));
goto L_done;
}
if (!strcmp(command, "linear_to_db")) {
rv0 = (*(g_phyFuns[0])[93]/*indirect*/)(para_array[0], ((u8*)para_array)[4]);
phy_printf("linear_to_db, %d, %d, %d\n", para_array[0], para_array[1], rv0);
goto L_done;
}
if (!strcmp(command, "get_noisefloor")) {
rv0 = esp_dport_access_reg_read(0x3ff5c050);
rv1 = esp_dport_access_reg_read(0x3ff5d050);
*(u32*)(0x3ff5d050) = (rv1 | 1);
phy_printf("noisefloor, %d\n", ((rv0 & 0x3ff)-1024));
goto L_done;
}
if (!strcmp(command, "get_tx_rate")) {
rv0 = phy_get_tx_rate();
phy_printf("txrate=%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "set_txcap_reg")) {
(*(g_phyFuns[0])[91]/*indirect*/)(chip7_sleep_params, ((u8*)para_array)[0]);
phy_printf("set_txcap_reg: chan=%d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "rx_gain_level")) {
rx_gain_level(((u8*)para_array)[0]);
phy_printf("rx_gain_level level=%d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "dc_iq_est")) {
dc_iq_est_test(1, (((u16*)para_array)[0]), ((u32)&__fr.b[2096]), ((u32)&__fr.b[48]));
__fr.w[0] = __fr.w[14];
phy_printf("%d,%d,%d,%d,%d,%d\n", *(u32*)(((u32)&__fr.b[2096])), *(u32*)((u32)&__fr.b[2100]), *(u32*)((u32)&__fr.b[2104]), __fr.w[12], __fr.w[13]) /* stack args: __fr.w[0] */;
goto L_done;
}
if (!strcmp(command, "gpio_output_set")) {
if (0x1f <u para_array[0]) goto L_3484;
gpio_output_set(((para_array[1] << para_array[0]) & 0xffffffff), ((((para_array[1] == 0) ? (1) : (0)) << para_array[0]) & 0xffffffff), ((1 << para_array[0]) & 0xffffffff), 0);
goto L_34aa;
L_3484:;
gpio_output_set_high(((para_array[1] << (para_array[0]-32)) & 0xffffffff), ((((para_array[1] == 0) ? (1) : (0)) << (para_array[0]-32)) & 0xffffffff), ((1 << (para_array[0]-32)) & 0xffffffff), 0);
L_34aa:;
phy_printf("gpio_output_set: gpio_no=%d, out_set=%d\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "gpio_dis_output")) {
if (0x1f <u para_array[0]) goto L_34e7;
gpio_output_set(0, 0, 0, ((1 << para_array[0]) & 0xffffffff));
goto L_34ed;
L_34e7:;
gpio_output_set_high(0, 0, 0, ((1 << para_array[0]) & 0xffffffff));
L_34ed:;
phy_printf("gpio_dis_output: gpio_no=%d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "gpio_input_get")) {
if (0x1f <u para_array[0]) goto L_352c;
rv0 = gpio_input_get();
goto L_353d;
L_352c:;
rv1 = gpio_input_get_high();
L_353d:;
phy_printf("gpio_input_get: gpio_no=%d, get_value=%d\n", para_array[0], (0x1f <u para_array[0] ? ((((u32)(rv1)) >> para_array[0]) & 0x1) : ((((u32)(rv0)) >> para_array[0]) & 0x1)));
goto L_done;
}
if (!strcmp(command, "modify_noise")) {
phy_printf("modify_noise: %d, %d\n", ((s16)*(u16*)(chip7_sleep_params+78)), para_array[0]);
*(u16*)(chip7_sleep_params+78) = para_array[0];
goto L_done;
}
if (!strcmp(command, "force_wifi_chan")) {
phy_printf("phy_force_wifi_chan\n");
phy_force_wifi_chan();
goto L_done;
}
if (!strcmp(command, "unforce_wifi_chan")) {
phy_printf("phy_unforce_wifi_chan\n");
phy_unforce_wifi_chan();
goto L_done;
}
if (!strcmp(command, "bt_txpwr_backoff")) {
btpwr_backoff(((s32)(para_array[0] << 25) >> 25));
phy_printf("bt_txpwr_backoff=%d\n ", ((s32)(para_array[0] << 25) >> 25));
goto L_done;
}
if (!strcmp(command, "bt_tx_tone")) {
bt_tx_tone(para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "fcc_bt_tx")) {
fcc_bt_tx_func(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]);
goto L_done;
}
if (!strcmp(command, "fcc_bt_tx_len")) {
__fr.w[1] = para_array[6];
__fr.w[0] = para_array[5];
phy_printf("fcc_bt_tx_len: txpwr=%d, hoppe=%d, chan=%d, rate=%d, length=%d, data_type=%d, num=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]) /* stack args: __fr.w[1], __fr.w[0] */;
__fr.w[0] = para_array[6];
fcc_tx_len(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]) /* stack args: __fr.w[0] */;
goto L_done;
}
if (!strcmp(command, "fcc_le_tx")) {
fcc_le_tx_func(para_array[0], para_array[1], para_array[2], para_array[3]);
goto L_done;
}
if (!strcmp(command, "fcc_le_tx_num")) {
phy_printf("fcc_le_tx_num: txpwr=%d, chan=%d, length=%d, data_type=%d,num=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]);
fcc_le_tx(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]);
goto L_done;
}
if (!strcmp(command, "fcc_le_tx_syncw_num")) {
__fr.w[0] = para_array[5];
phy_printf("fcc_le_tx_syncw_num: txpwr=%d, chan=%d, length=%d, data_type=%d,syncword=0x%x,num=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]) /* stack args: __fr.w[0] */;
fcc_le_tx_syncw(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]);
goto L_done;
}
if (!strcmp(command, "fcc_le_tx_syncw")) {
fcc_le_tx_syncw_func(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], 0);
goto L_done;
}
if (!strcmp(command, "rw_rx_per")) {
rw_rx_per_func(para_array[0], para_array[1], para_array[2], para_array[3]);
goto L_done;
}
if (!strcmp(command, "rw_le_rx_per")) {
rw_le_rx_per_func(para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "rw_le_rx_per_rssi")) {
rw_le_rx_per_syncw_rssi(para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "bttx_low_power")) {
phy_bttx_low_power(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("bttx_low_power en=%d,level=%d\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "force_bttx_gain")) {
force_bttx_gain(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8], ((u8*)para_array)[12]);
phy_printf("force_bttx_gain en=%d,pa=0x%x,bb=0x%x,dig=%d\n", para_array[0], para_array[1], para_array[2], para_array[3]);
goto L_done;
}
if (!strcmp(command, "bt_track_en")) {
*(u8*)(phy_bt_pll_track_en) = para_array[0];
*(u8*)(phy_bt_power_track_en) = para_array[1];
phy_printf("pll_track=%d, power_track=%d\n", (para_array[0] & 0xff), (para_array[1] & 0xff));
goto L_done;
}
if (!strcmp(command, "bt_set_chan_test")) {
ets_delay_us(0x64);
coex_bt_high_prio();
ets_delay_us(0x64);
force_bt_mode();
ets_delay_us(0x64);
chip_v7_set_chan(((s32)(para_array[0] << 25) >> 25), ((s32)(para_array[1] << 25) >> 25));
force_wifi_mode(1);
goto L_done;
}
if (!strcmp(command, "cmd_polling_start")) {
cmd_polling_start(0x64);
phy_printf("start polling\n");
goto L_done;
}
if (!strcmp(command, "rw_le_rx_per_polling")) {
rw_le_rx_per_syncw_polling(para_array[0]);
goto L_done;
}
if (!strcmp(command, "rw_le_rx_per_polling_stop")) {
rw_le_rx_per_syncw_polling_stop();
goto L_done;
}
if (!strcmp(command, "read_efuse_all")) {
dst = (u32*)&__fr.b[48];
for (p = 0x3ff5a000; p != 0x3ff5a01c; p += 4)
    *dst++ = esp_dport_access_reg_read(p);
for (p = 0x3ff5a038; p != 0x3ff5a058; p += 4)
    *dst++ = esp_dport_access_reg_read(p);
for (p = 0x3ff5a058; p != 0x3ff5a078; p += 4)
    *dst++ = esp_dport_access_reg_read(p);
for (p = 0x3ff5a078; p != 0x3ff5a098; p += 4)
    *dst++ = esp_dport_access_reg_read(p);
for (i = 0; i < 32; i++)
    phy_printf("word_:%d, 0x%x\n", i, __fr.w[12 + i]);
goto L_done;
}
if (!strcmp(command, "esp_en_reboot")) {
esp_en_reboot();
goto L_done;
}
if (!strcmp(command, "flash_wr")) {
phy_printf("flash_wr: 0x%x\n", para_array[0]);
SPIEraseSector((((u32)(para_array[0])) >> 12));
goto L_done;
}
if (!strcmp(command, "deep_sleep_test")) {
phy_printf("go to sleep\n");
ets_delay_us(0x2710);
rtc_set_cpu_freq(0);
ets_unpack_flash_code(0x20000, ((u32)&__fr.b[48]), 0, 0, 0);
set_rtc_memory_crc();
*(u32*)(0x3ff480b8) = __fr.w[12];
rtc_slp_prep_lite(3, 0);
rtc_sleep(0, para_array[0], 8, 0);
goto L_done;
}
if (!strcmp(command, "sleep_proc_test")) {
phy_printf("sleep_proc_test start\n");
uart_wait_idle(0);
sleep_proc_test(((u8*)para_array)[0], ((u8*)para_array)[4], para_array[2]);
phy_printf("sleep_proc_test: mode=%d, wakeup=%d, sleep_time=%d, %dus\n", para_array[0], para_array[1], para_array[2], (*(u32*)(0x60033c00) - *(u32*)(0x60033c00)));
goto L_done;
}
if (!strcmp(command, "phy_wakeup")) {
phy_printf("phy_wakeup start\n");
ets_delay_us(0x2710);
rtc_set_cpu_freq(1);
rtc_uart_div_modify(0);
rv4 = esp_dport_access_reg_read(0x3ff000cc);
*(u32*)(0x3ff000cc) = (rv4 | 0x87cf);
rv5 = esp_dport_access_reg_read(0x3ff48030);
*(u32*)(0x3ff48030) = (rv5 | 0xd8000000);
phy_wakeup_init();
mac_init();
phy_printf("phy_wakeup\n");
goto L_done;
}
if (!strcmp(command, "esp_chk_cpu_level")) {
rv0 = rtc_get_cpu_clk_grade();
phy_printf("level:%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "rtc_set_cpu_freq")) {
rtc_set_cpu_freq(para_array[0]);
rtc_uart_div_modify(0);
phy_printf("cpu_freq: 0:40M 1:80M 2: 160M 3: 240M 4:2M, curr_freq: %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "noise_check_loop")) {
phy_printf("noise_check_loop: check_level=%d, delay_ms=%d\n", para_array[0], para_array[1]);
for (;;) {
    noise_check_loop(((u8*)para_array)[0], 1);
    for (i = 0; i <u para_array[1]; i++)
        ets_delay_us(1000);
    if (GetStopCmd(1000) != 0) break;
}
phy_printf("noise_check_loop done!!!\n");
goto L_done;
}
if (!strcmp(command, "bt_coex_init")) {
coex_bt_high_prio();
rf_rw_init(((u32)&__fr.b[48]));
phy_printf("COEX BT HP\n");
goto L_done;
}
if (!strcmp(command, "enable_lr")) {
phy_enable_low_rate();
phy_printf("enable LR \n");
goto L_done;
}
if (!strcmp(command, "disable_lr")) {
phy_disable_low_rate();
phy_printf("disable LR \n");
goto L_done;
}
if (!strcmp(command, "bt_force_init")) {
force_bt_mode();
rf_rw_init(((u32)&__fr.b[48]));
phy_printf("Force BT\n");
goto L_done;
}
if (!strcmp(command, "rw_rx_per_ulap_rssi")) {
rw_rx_per_ulap_rssi(para_array[0], para_array[1], para_array[2], para_array[3]);
goto L_done;
}
if (!strcmp(command, "phy_close_rf")) {
phy_close_rf();
phy_printf("phy_close_rf done\n");
goto L_done;
}
if (!strcmp(command, "rx_sense_set")) {
phy_rx_sense_set(((u8*)para_array)[0]);
phy_printf("phy_rx_sense_set thr=%d done\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "ant_dft_cfg")) {
ant_dft_cfg(((u8*)para_array)[0]);
phy_printf("ant_dft_cfg val=%d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "ant_wifitx_cfg")) {
ant_wifitx_cfg(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("ant_wifitx_cfg val0=%d, val1=%d\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "ant_wifirx_cfg")) {
ant_wifirx_cfg(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8]);
phy_printf("ant_wifirx_cfg auto_en=%d, val0=%d, val1=%d\n", para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "ant_bttx_cfg")) {
ant_bttx_cfg(((u8*)para_array)[0]);
phy_printf("ant_bttx_cfg val=%d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "ant_btrx_cfg")) {
ant_btrx_cfg(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8]);
phy_printf("ant_btrx_cfg auto_en=%d, val0=%d, val1=%d\n", para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "esp_tx_state_out")) {
esp_tx_state_out(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("esp_tx_state_out %d %d\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "get_power_db")) {
rv0 = ram_get_power_db((*(u16*)(pwrdet_offset)));
phy_printf("%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "flash_erase")) {
SPIEraseSector((((u32)(para_array[0])) >> 12));
phy_printf("flash_erase 0x%x\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "pwdet_always_en")) {
phy_pwdet_always_en(((u8*)para_array)[0]);
phy_printf("pwdet_always_en %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "pwdet_onetime_en")) {
phy_pwdet_onetime_en();
phy_printf("phy_pwdet_onetime_en\n");
goto L_done;
}
if (!strcmp(command, "rtc_get_gpio_dig_conf")) {
rv0 = rtc_get_gpio_dig_conf((para_array[0] & 0xff));
phy_printf("rtc_get_gpio_dig_conf %d 0x%x\n", para_array[0], rv0);
goto L_done;
}
if (!strcmp(command, "rtc_restore_dig_gpio")) {
rtc_restore_dig_gpio(((u8*)para_array)[0], para_array[1]);
phy_printf("rtc_restore_dig_gpio %d 0x%x\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "rtc_set_dig_gpio_out")) {
rtc_set_dig_gpio_out(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8]);
phy_printf("rtc_set_dig_gpio_out gpio_num=%d drv=%d value=%d\n", para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "tx_power_print")) {
phy_printf("phy_chan_target_power:");
for (i = 0; i < 0x11; i++)
    phy_printf("%d, ", (*(u8*)(phy_chan_target_power+i)));
phy_printf("phy_chan_pwr_index:");
for (i = 0; i < 0x11; i++)
    phy_printf("%d, ", (*(u8*)(phy_chan_pwr_index+i)));
phy_printf("phy_chan_gain_table:");
for (i = 0; i < 8; i++)
    phy_printf("%d, ", ((s32)((*(u8*)(phy_chan_gain_table+i)) << 25) >> 25));
goto L_2963; /* shared tail: print loop epilogue in "dig_atten" branch */
}
if (!strcmp(command, "test_rf_cal_level")) {
test_rf_cal_level(((u8*)para_array)[0], para_array[1]);
phy_printf("%s %d 0x%x\n", command, para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "wr_rf_cal_data")) {
read_macaddr_from_otp(((u32)&__fr.b[2096]));
for (i = 0; i < 6; i++)
    __fr.b[52 + i] = __fr.b[2096 + i];
rf_cal_data_backup(((u32)&__fr.b[48]));
phy_rfcal_data_check(0, ((u32)&__fr.b[48]), init_param_default);
SPIEraseSector(0xfc);
SPIWrite(0xfc000, ((u32)&__fr.b[48]), 0x800);
phy_printf("write rf_cal_data done\n");
goto L_done;
}
if (!strcmp(command, "force_txon_en")) {
force_txon_en(((u8*)para_array)[0]);
phy_printf("force_txon_en %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "brown_out_test")) {
rtc_brown_out_test(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("rtc_brown_out_test %d %d\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "test_tx_vdd33")) {
phy_printf("test_tx_vdd33 %d\n", para_array[0]);
test_tx_vdd33(para_array[0]);
goto L_done;
}
if (!strcmp(command, "get_adc_rand")) {
phy_get_adc_rand(((u8*)para_array)[0]);
phy_printf("get_adc_rand %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "test_i2c")) {
t0 = *(u32*)(0x60033c00);
for (i = 0; i <u para_array[0]; i++)
    ram_chip_i2c_readReg(0x62, 1, 0);
t1 = *(u32*)(0x60033c00);
phy_printf("test_i2c %d %dus\n", t1 - t0, 0 /* a12 last set 0 pre-loop */);
goto L_done;
}
if (!strcmp(command, "get_sar2_vol")) {
rv0 = get_sar2_vol(((u8*)para_array)[0]);
phy_printf("%d\n", rv0);
goto L_done;
}
if (!strcmp(command, "pvt_test")) {
pvt_test_func();
goto L_done;
}
if (!strcmp(command, "coex_test")) {
coex_test(((u8*)para_array)[0]);
phy_printf("coex_test mode=%d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "ap_ack_test")) {
phy_printf("ap_ack_test: chan=%d rate=0x%x len=%d \n", para_array[0], para_array[1], para_array[2]);
ap_ack_test(((u8*)para_array)[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "wifi_ack_test")) {
__fr.w[1] = ((u8*)para_array)[28];
__fr.w[4] = para_array[10];
__fr.w[3] = ((u8*)para_array)[36];
__fr.w[2] = ((u8*)para_array)[32];
__fr.w[0] = (((u16*)para_array)[12]);
wifi_ack_test(para_array[0], para_array[1], ((u8*)para_array)[8], para_array[3], para_array[4], para_array[5]) /* stack args: __fr.w[1], __fr.w[4], __fr.w[3], __fr.w[2], __fr.w[0] */;
goto L_done;
}
if (!strcmp(command, "tx_ack_test")) {
__fr.w[2] = ((u8*)para_array)[32];
__fr.w[1] = para_array[7];
__fr.w[0] = para_array[6];
tx_ack_test(para_array[0], para_array[1], ((u8*)para_array)[8], (((u16*)para_array)[6]), para_array[4], para_array[5]) /* stack args: __fr.w[2], __fr.w[1], __fr.w[0] */;
__fr.w[1] = para_array[6];
__fr.w[3] = para_array[8];
__fr.w[2] = para_array[7];
__fr.w[0] = para_array[5];
phy_printf("tx_ack_test:ap_addr0=0x%x, ap_addr1=0x%x, tx_rate=0x%x, tx_num=%d, tx_length=%d, backoff=%d, aifs=%d, delay_ms=%d, tx_cbw40=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]) /* stack args: __fr.w[1], __fr.w[3], __fr.w[2], __fr.w[0] */;
goto L_done;
}
if (!strcmp(command, "tx_ack_init")) {
tx_ack_init(para_array[0], para_array[1], ((u8*)para_array)[8], para_array[3], ((u8*)para_array)[16]);
phy_printf("tx_ack_init:ap_addr0=0x%x, ap_addr1=0x%x, tx_rate=0x%x, tx_length=%d,tx_cbw40=%d\n", para_array[0], para_array[1], para_array[2], para_array[3], para_array[4]);
goto L_done;
}
if (!strcmp(command, "tx_ack_start")) {
tx_ack_start((((u16*)para_array)[0]), para_array[1], para_array[2], para_array[3], ((u32)&__fr.b[48]));
phy_printf("rx_flag:0x%x,ack_num:%d,rssi:%d,rssi_max:%d,rssi_min:%d\n", __fr.w[12], __fr.w[13], __fr.w[14], __fr.w[15], __fr.w[16]);
goto L_done;
}
if (!strcmp(command, "rfpll_cal_time")) {
rfpll_cal_time(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("rfpll_cal_time: chan_freq=%d, mode=%d\n", para_array[0], para_array[1]);
goto L_done;
}
if (!strcmp(command, "esp_get_rx_result")) {
rv0 = esp_get_rx_result(((u32)&__fr.b[48]));
phy_printf("esp_get_rx_result: %d, %d, %d, flag=%d\n", __fr.w[12], __fr.w[13], __fr.w[14], rv0);
goto L_done;
}
if (!strcmp(command, "set_rx_sense")) {
*(u8*)(adaptive_test_en) = 1;
set_rx_sense(((s32)(para_array[0] << 25) >> 25));
phy_printf("set_rx_sense: rssi=%d\n", ((s32)(para_array[0] << 25) >> 25));
goto L_done;
}
if (!strcmp(command, "phy_set_freq")) {
test_set_rf_freq_offset((*(u8*)(chip7_phy_init_ctrl+1)), (((u16*)para_array)[0]), ((s16)((u16*)para_array)[2]));
phy_printf("phy_set_freq %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "get_spur4m_pwr")) {
get_spur4m_pwr(((u32)&__fr.b[48]));
phy_printf("get_spur4m_pwr %d,%d\n", __fr.w[12], __fr.w[13]);
goto L_done;
}
if (!strcmp(command, "bt_rx_spur_cal")) {
bt_rx_spur_cal(para_array[0], 1);
phy_printf("get_spur4m_pwr chan=%d,%d %d\n", para_array[0], (*(u8*)(bt_rx_2440_dac)), (*(u8*)(bt_rx_2480_dac)));
goto L_done;
}
if (!strcmp(command, "bbpll_80m_cal")) {
rtc_clk_cpu_freq_set_new(((u8*)para_array)[0]);
rtc_uart_div_modify(0);
phy_printf("bbpll_80m_cal %d done\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "test_2480_power")) {
test_2480_power(para_array[0]);
phy_printf("test_2480_power %d\n", para_array[0]);
goto L_done;
}
if (!strcmp(command, "bt_2480_opt_en")) {
*(u8*)(bt_2480_opt_en) = para_array[0];
*(u8*)(bt_2480_print) = para_array[1];
phy_printf("bt_2480_opt_en %d %d\n", (para_array[0] & 0xff), (para_array[1] & 0xff));
goto L_done;
}
if (!strcmp(command, "phy_version_print")) {
phy_version_print();
goto L_done;
}
if (!strcmp(command, "clk_test_tmp")) {
*(u32*)(0x3ff48070) = (*(u32*)(0x3ff48070) & 0xe7ffffff);
*(u32*)(0x3ff48070) = ((*(u32*)(0x3ff48070) & 0xe7ffffff) | 0x8000000);
phy_printf("clk_test_tmp done\n");
goto L_done;
}
if (!strcmp(command, "bt_rx_spur_opt")) {
bt_rx_spur_opt(((u8*)para_array)[0]);
phy_printf("%s %d\n", command, para_array[0]);
goto L_done;
}
if (!strcmp(command, "txdc_stable_test")) {
txdc_stable_test(1);
goto L_done;
}
if (!strcmp(command, "rxspur_test")) {
rxspur_test(1);
phy_printf("%s\n", command);
goto L_done;
}
if (!strcmp(command, "rfpll_cap_sign")) {
ate_rfpll_cap_sign(((u8*)para_array)[0]);
goto L_done;
}
if (!strcmp(command, "ate_bt_fb")) {
__fr.w[0] = (((u16*)para_array)[10]);
*(u16*)(bt_tester_param) = para_array[1];
*(u16*)(bt_tester_param+2) = para_array[2];
*(u16*)(bt_tester_param+4) = para_array[3];
*(u16*)(bt_tester_param+6) = para_array[4];
phy_printf("ate_bt_fb: num=%d,edr=%d,type=%d,len=%d,pwr=%d,freq=%d\n", para_array[0], (para_array[1] & 0xffff), (para_array[2] & 0xffff), (para_array[3] & 0xffff), (para_array[4] & 0xffff)) /* stack args: __fr.w[0] */;
rw_bt_func_test_init();
rw_bt_func_test_tester((((u16*)para_array)[10]), (((u16*)para_array)[10]), para_array[0]);
phy_printf("ate_bt_fb done\n");
goto L_done;
}
if (!strcmp(command, "ate_bt_dut")) {
__fr.w[564] = (((u16*)para_array)[10]);
__fr.w[566] = para_array[1];
__fr.w[0] = __fr.w[564];
*(u16*)(bt_dut_param) = __fr.w[566];
*(u16*)(bt_dut_param+2) = para_array[2];
*(u16*)(bt_dut_param+4) = para_array[3];
*(u16*)(bt_dut_param+6) = para_array[4];
__fr.w[565] = ((u32)&__fr.b[48]);
phy_printf("ate_bt_dut: num=%d,edr=%d,type=%d,len=%d,pwr=%d,freq=%d\n", para_array[0], (para_array[1] & 0xffff), (para_array[2] & 0xffff), (para_array[3] & 0xffff), (para_array[4] & 0xffff)) /* stack args: __fr.w[0] */;
*(u32*)((u32)&__fr.b[2236]) = 0;
*(u32*)((u32)&__fr.b[2232]) = 0;
*(u32*)((u32)&__fr.b[2228]) = 0;
*(u32*)((u32)&__fr.b[2224]) = 0;
*(u32*)(((u32)&__fr.b[2096])) = 0;
*(u8*)((u32)&__fr.b[2245]) = 0;
*(u8*)((u32)&__fr.b[2244]) = 0;
*(u8*)((u32)&__fr.b[2243]) = 0;
*(u8*)((u32)&__fr.b[2242]) = 0;
*(u8*)((u32)&__fr.b[2241]) = 0;
*(u8*)((u32)&__fr.b[2240]) = 0;
__fr.w[12] = 0;
rv1 = esp_dport_access_reg_read(0x3ff5a008);
rv2 = esp_dport_access_reg_read(0x3ff5a004);
rw_bt_func_test_init();
__fr.w[7] = (&__fr.b[0x8c2]);
__fr.w[6] = (&__fr.b[0x8c3]);
__fr.w[5] = (&__fr.b[0x8c4]);
__fr.w[4] = (&__fr.b[0x8c5]);
__fr.w[3] = __fr.w[565];
__fr.w[2] = ((u32)&__fr.b[2096]);
__fr.w[1] = (&__fr.b[0x8b0]);
__fr.w[0] = (&__fr.b[0x8b4]);
__fr.w[9] = (&__fr.b[0x8c0]);
__fr.w[8] = (&__fr.b[0x8c1]);
rw_bt_func_test_dut(((rv1 & 0xffff) | 0x45110000), rv2, 0, para_array[0], (__fr.w[565] + 0x88c), (__fr.w[565] + 0x888)) /* stack args: __fr.w[7], __fr.w[6], __fr.w[5], __fr.w[4], __fr.w[3], __fr.w[2], __fr.w[1], __fr.w[0], __fr.w[9], __fr.w[8] */;
__fr.w[0] = *(u32*)((u32)&__fr.b[2236]);
__fr.w[2] = __fr.w[12];
__fr.w[1] = *(u32*)(((u32)&__fr.b[2096]));
phy_printf("ate_bt_dut done: dut_rx_num=%d, fb_rx_num=%d, bt_dut_rssi=%d, bt_fb_rssi=%d, ntx=%d, nslvtx=%d, nrxac=%d, nrxall=%d\n", *(u32*)((u32)&__fr.b[2224]), *(u32*)((u32)&__fr.b[2232]), ((s32)((*(u8*)((u32)&__fr.b[2243])) << 25) >> 25), ((s32)((*(u8*)((u32)&__fr.b[2240])) << 25) >> 25), *(u32*)((u32)&__fr.b[2228])) /* stack args: __fr.w[0], __fr.w[2], __fr.w[1] */;
goto L_done;
}
if (!strcmp(command, "flash_op")) {
ets_efuse_get_spiconfig();
spi_flash_attach();
__fr.w[566] = para_array[6];
__fr.w[564] = para_array[13];
__fr.w[2] = para_array[8];
__fr.w[3] = para_array[9];
__fr.w[7] = para_array[13];
__fr.w[6] = para_array[12];
__fr.w[5] = para_array[11];
__fr.w[4] = para_array[10];
__fr.w[1] = para_array[7];
__fr.w[0] = __fr.w[566];
FlashBoardTest(para_array[0], para_array[1], para_array[2], para_array[3], para_array[4], para_array[5]) /* stack args: __fr.w[2], __fr.w[3], __fr.w[7], __fr.w[6], __fr.w[5], __fr.w[4], __fr.w[1], __fr.w[0] */;
goto L_done;
}
if (!strcmp(command, "set_freq_test")) {
set_freq_test(para_array, para_num);
goto L_done;
}
if (!strcmp(command, "pbus_debug_test")) {
__fr.w[1] = (((u16*)para_array)[14]);
__fr.w[4] = (para_array+40);
__fr.w[3] = (((u16*)para_array)[18]);
__fr.w[2] = (((u16*)para_array)[16]);
__fr.w[0] = (((u16*)para_array)[12]);
pbus_debug_test(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8], ((u8*)para_array)[12], (((u16*)para_array)[8]), (((u16*)para_array)[10])) /* stack args: __fr.w[1], __fr.w[4], __fr.w[3], __fr.w[2], __fr.w[0] */;
goto L_done;
}
if (!strcmp(command, "pvt_ate")) {
pvt_ate();
goto L_done;
}
if (!strcmp(command, "get_path_loss_offset")) {
get_path_loss_offset(((u32)&__fr.b[48]));
phy_printf("%s=%d\n", command, __fr.w[13]);
goto L_done;
}
if (!strcmp(command, "mac_filter_en")) {
*(u8*)(mac_filter_en) = para_array[0];
phy_printf("%s %d\n", command, para_array[0]);
goto L_done;
}
if (!strcmp(command, "force_rx_gain")) {
force_rx_gain(((u8*)para_array)[0], ((u8*)para_array)[4], ((u8*)para_array)[8]);
phy_printf("%s %d %d %d\n", command, para_array[0], para_array[1], para_array[2]);
goto L_done;
}
if (!strcmp(command, "rx_11b_opt")) {
rx_11b_opt(((u8*)para_array)[0]);
phy_printf("%s %d\n", command, para_array[0]);
goto L_done;
}
if (!strcmp(command, "rfpll_1p2_test")) {
rfpll_1p2_test();
phy_printf("%s\n", command);
goto L_done;
}
if (!strcmp(command, "phy_param_set")) {
*(u8*)(rc_cal_en) = ((u8*)para_array)[0];
if (((u8*)para_array)[0] != 0) goto L_4970;
*(u8*)(wifi_txband) = 0x5f;
*(u8*)(wifi_txband_ht40) = 0xffffffc3;
goto L_49a9;
L_4970:;
rv0 = (*(g_phyFuns[0])[11]/*indirect*/)(para_array[1], 0x5f, 0x32);
*(u8*)(wifi_txband) = rv0;
rv1 = (*(g_phyFuns[0])[11]/*indirect*/)(para_array[2], 0xc3, 0x64);
*(u8*)(wifi_txband_ht40) = rv1;
L_49a9:;
chip7_sleep_params = 0;
bb_init();
phy_printf("phy_band_opt: enable=%d,%d,%d\n", para_array[0], (*(u8*)(chip7_sleep_params+84)), (*(u8*)(chip7_sleep_params+86)));
goto L_done;
}
if (!strcmp(command, "rx_gain_comp_cal")) {
rx_gain_comp_cal(((u8*)para_array)[0], ((u8*)para_array)[4]);
phy_printf("%s %d\n", command, (*(u32*)(0x60033c00) - *(u32*)(0x60033c00)));
goto L_done;
}
if (!strcmp(command, "bt_bb_init_cmplx")) {
bt_bb_init_cmplx_reg();
phy_printf("%s\n", command);
goto L_done;
}
if (!strcmp(command, "phy_reg_check")) {
phy_reg_check();
phy_printf("%s\n", command);
goto L_done;
}
if (!strcmp(command, "phy_wakeup_init")) {
phy_wakeup_init();
phy_printf("%s\n", command);
goto L_done;
}
if (!strcmp(command, "phy_i2c_init")) {
phy_i2c_init();
phy_printf("%s\n", command);
goto L_done;
}
if (!strcmp(command, "get_rfcal_num")) {
phy_printf("%s, %d\n", command, 0x56c);
goto L_done;
}
if (!strcmp(command, "io_adc_test")) {
if (0x23 >=u (para_array[0] & 0xff)) goto L_4ae8;
goto L_4aeb;
L_4ae8:;
L_4aeb:;
rv0 = adc_test1(((0x23 >=u (para_array[0] & 0xff) ? ((para_array[0] & 0xff)-28) : ((para_array[0] & 0xff)-36)) & 0xff));
phy_printf("%s: adc_io=%d, adc_chan=%d, adc_dout=%d\n", command, (para_array[0] & 0xff), (0x23 >=u (para_array[0] & 0xff) ? ((para_array[0] & 0xff)-28) : ((para_array[0] & 0xff)-36)), rv0);
goto L_done;
}
    return false; /* no command matched */
L_done:;
    return true;
}

/* rx_gain_comp_cal wifi.c:2267 @ wifi.o size 478B [dwarf-sig]
 * Calls: get_rfrx_dcap_bt, ets_delay_us, ram_dc_iq_est, phy_printf, force_rx_gain, set_chan_rxcomp | Data refs: .rodata, .rodata.str1.4, ets_delay_us, force_rx_gain, g_phyFuns, get_rfrx_dcap_bt, phy_printf, ram_dc_iq_est, set_chan_rxcomp | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_gain_comp_cal(bool print_en, bool bt_mode)
{
    (void)print_en;
    (void)bt_mode;
    /* DWARF locals: sint16[] rx_dc_comp@l2269, uint32[] dc_est@l2270, uint16 rfrx@l2271, uint16 rftx@l2272, uint16 bbgain@l2273, sint16 offset@l2274, uint32 target_pwr@l2275, uint8 btcmplx@l2276 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <rx_gain_comp_cal> (189 insns) + DWARF line rows for wifi.c:2267.
     * Ordered callee relocs: get_rfrx_dcap_bt, ets_delay_us, ram_dc_iq_est, phy_printf, force_rx_gain, set_chan_rxcomp.
     */
}

/* rx_pbus_set wifi.c:1470 @ wifi.o size 515B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff45034, 0x3ff45038, 0x3ff46030
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_pbus_set(uint16 rxon_rfrx, uint16 rxon_bb1, uint16 rxoff_rfrx, uint16 rxoff_bb1)
{
    (void)rxon_rfrx;
    (void)rxon_bb1;
    (void)rxoff_rfrx;
    (void)rxoff_bb1;
    /* DWARF locals: unsigned int index_start@l1472, unsigned int index_end@l1472, unsigned int i@l1472, unsigned int[] pbus_table@l1473, const unsigned int[] table_rxon@l1475, const unsigned int[] table_rxoff@l1479 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <rx_pbus_set> (200 insns) + DWARF line rows for wifi.c:1470.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rx_per_init wifi.c:705 @ wifi.o size 117B [dwarf-sig]
 * Calls: set_mac_filter, esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read, set_mac_filter | MMIO: 0x600330d8, 0x600330dc, 0x600330e0, 0x600330e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rx_per_init(void)
{
    /* DWARF locals: unsigned int mac_upper@l707, unsigned int mac_lower@l708, int bitmap@l711 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <rx_per_init> (41 insns) + DWARF line rows for wifi.c:705.
     * Ordered callee relocs: set_mac_filter, esp_dport_access_reg_read.
     */
}

/* sampledeal wifi.c:379 @ wifi.o size 17B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int32 sampledeal(uint32 sample)
{
    (void)sample;
    /* DWARF locals: uint32 dc_offset@l381, int32 sampledata@l382 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <sampledeal> (6 insns) + DWARF line rows for wifi.c:379.
     */
}

/* set_freq_test wifi.c:2109 @ wifi.o size 242B [dwarf-sig]
 * Calls: phy_printf, esp_dport_access_reg_read, ets_delay_us, GetStopCmd, set_chan_freq_sw_start | Data refs: .rodata.str1.4, GetStopCmd, chip7_phy_init_ctrl, esp_dport_access_reg_read, ets_delay_us, g_phyFuns, phy_printf, set_chan_freq_sw_start | MMIO: 0x3ff460a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_freq_test(uint32 * para_array, uint32 para_num)
{
    (void)para_array;
    (void)para_num;
    /* DWARF locals: uint8 i@l2111 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <set_freq_test> (90 insns) + DWARF line rows for wifi.c:2109.
     * Ordered callee relocs: phy_printf, esp_dport_access_reg_read, ets_delay_us, GetStopCmd, set_chan_freq_sw_start.
     */
}

/* set_rtc_dig_dbias wifi.c:1888 @ wifi.o size 64B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4807c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_rtc_dig_dbias(uint8 dig_dbias)
{
    (void)dig_dbias;
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <set_rtc_dig_dbias> (23 insns) + DWARF line rows for wifi.c:1888.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_2480_power wifi.c:2055 @ wifi.o size 133B [dwarf-sig]
 * Calls: freq_offset_get_pwr, phy_printf | Data refs: .rodata.str1.4, freq_offset_get_pwr, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_2480_power(uint32 shift)
{
    (void)shift;
    /* DWARF locals: S16 tone_step@l2057, const U8 loop_bits@l2058, const U8 corr_cycle_bits@l2059, uint64[] pwr_sum@l2060, S16 rxiq_remain@l2061 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <test_2480_power> (48 insns) + DWARF line rows for wifi.c:2055.
     * Ordered callee relocs: freq_offset_get_pwr, phy_printf.
     */
}

/* test_rf_cal_level wifi.c:504 @ wifi.o size 130B [dwarf-sig]
 * Calls: phy_set_wifi_mode_only, ets_efuse_get_spiconfig, spi_flash_attach, SPIRead, register_chipv7_phy, phy_printf, SPIEraseSector, SPIWrite | Data refs: .rodata.str1.4, SPIEraseSector, SPIRead, SPIWrite, ets_efuse_get_spiconfig, init_param_default, phy_printf, phy_set_wifi_mode_only, re_entry, register_chipv7_phy, spi_flash_attach | MMIO: 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_rf_cal_level(u8 rf_cal_level, uint32 flash_addr)
{
    (void)rf_cal_level;
    (void)flash_addr;
    /* DWARF locals: bool check_fail@l508, bool deep_sleep_wakeup@l508, uint8[] rf_cal_data@l509, uint8[] mac_addr@l510, uint32 t0@l511, uint32 t1@l511, uint32 i@l511, char * esp_init_data_add_rf_cal@l515, uint32_t spiconfig0@l518 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <test_rf_cal_level> (49 insns) + DWARF line rows for wifi.c:504.
     * Ordered callee relocs: phy_set_wifi_mode_only, ets_efuse_get_spiconfig, spi_flash_attach, SPIRead, register_chipv7_phy, phy_printf, SPIEraseSector, SPIWrite.
     */
}

/* test_tx_vdd33 wifi.c:835 @ wifi.o size 352B [dwarf-sig]
 * Calls: txcal_debuge_mode, set_channel_rfpll_freq, ram_rfcal_pwrctrl, phy_printf, uart_wait_idle, ets_delay_us | Data refs: .rodata.str1.4, chip7_phy_init_ctrl, chip7_sleep_params, ets_delay_us, g_phyFuns, phy_printf, pwrdet_offset, ram_rfcal_pwrctrl, rfcal_bb_atten_init, set_channel_rfpll_freq, tx_rf_ana_gain, txcal_debuge_mode, uart_wait_idle | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_tx_vdd33(uint32 delay_us)
{
    (void)delay_us;
    /* DWARF locals: S8 bb_atten@l837, S8 i@l837, S8[] txdc@l838, S8 target_bb_atten@l839, U8 index@l840, bool print_debug@l841, uint16 vdd33@l842, S8 rfcal_bb_atten_init@l843, uint8 chan_num@l844, S16 power_sum@l845 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <test_tx_vdd33> (131 insns) + DWARF line rows for wifi.c:835.
     * Ordered callee relocs: txcal_debuge_mode, set_channel_rfpll_freq, ram_rfcal_pwrctrl, phy_printf, uart_wait_idle, ets_delay_us.
     */
}

/* tx_lo_for_5g wifi.c:1003 @ wifi.o size 110B [dwarf-sig]
 * Calls: test_set_rf_freq_offset, set_tx_gain_table, esp_dport_access_reg_read | Data refs: chip7_phy_init_ctrl, esp_dport_access_reg_read, g_phyFuns, set_tx_gain_table, test_set_rf_freq_offset, tx_rf_ana_gain | MMIO: 0x3ff460a0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_lo_for_5g(void)
{
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <tx_lo_for_5g> (42 insns) + DWARF line rows for wifi.c:1003.
     * Ordered callee relocs: test_set_rf_freq_offset, set_tx_gain_table, esp_dport_access_reg_read.
     */
}

/* tx_pbus_set wifi.c:1512 @ wifi.o size 535B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff45034, 0x3ff45038, 0x3ff46034
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_pbus_set(uint16 txon_rfrx, uint16 txon_bb1, uint16 txoff_rfrx, uint16 txoff_bb1)
{
    (void)txon_rfrx;
    (void)txon_bb1;
    (void)txoff_rfrx;
    (void)txoff_bb1;
    /* DWARF locals: unsigned int index_start@l1514, unsigned int index_end@l1514, unsigned int i@l1514, unsigned int[] pbus_table@l1515, const unsigned int[] table_txon@l1516, const unsigned int[] table_txoff@l1521 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <tx_pbus_set> (209 insns) + DWARF line rows for wifi.c:1512.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* txpwr_track_correct wifi.c:1352 @ wifi.o size 5B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void txpwr_track_correct(s8 pwcorrect_v, bool print_en)
{
    return;
}

/* txpwr_track_disable wifi.c:184 @ wifi.o size 66B [dwarf-sig]
 * Calls: tx_gain_table_set | Data refs: chip7_sleep_params, target_power_backoff_qdb, tx_gain_table_set, tx_rf_ana_gain, tx_rf_ana_gain_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void txpwr_track_disable(void)
{
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <txpwr_track_disable> (23 insns) + DWARF line rows for wifi.c:184.
     * Ordered callee relocs: tx_gain_table_set.
     */
}

/* wifi_init wifi.c:1017 @ wifi.o size 545B [dwarf-sig]
 * Calls: phy_get_romfunc_addr, i2c_xtal_init, phy_printf, rtc_init_lite, esp_dport_access_reg_read, GetUartDevice, uart_tx_switch, uart_wait_idle, ets_delay_us, uart_div_modify, rtc_set_cpu_freq, ets_update_cpu_frequency, print_efuse_mac, phy_set_wifi_mode_only, read_macaddr_from_otp, init_param_read, register_chipv7_phy, rx_gain_level, noise_init, coex_bt_high_prio, rf_rw_init, phy_bt_power_track, mac_init, write_efuse_dig_reserve, phy_pwdet_always_en, .text.flash_init_param_print$part$1+0x7c, phy_version_print, tsens_code_read | Data refs: .bss.uart_no, .rodata.str1.4, GetUartDevice, coex_bt_high_prio, esp_dport_access_reg_read, ets_delay_us, ets_update_cpu_frequency, i2c_xtal_init, init_param_default, init_param_read, mac_init, noise_init, phy_bt_power_track, phy_get_romfunc_addr, phy_printf, phy_pwdet_always_en, phy_set_wifi_mode_only, phy_temp_init, phy_version_print, print_efuse_mac, read_macaddr_from_otp, register_chipv7_phy, rf_rw_init, rtc_init_lite, rtc_set_cpu_freq, rx_gain_level, tsens_code_read, tx_rf_ana_gain, tx_rf_ana_gain_init, uart_div_modify, uart_tx_switch, uart_wait_idle, write_efuse_dig_reserve | MMIO: 0x3ff000c0, 0x3ff000cc, 0x3ff44038, 0x3ff4808c, 0x3ff5cd04, 0x3ff5cd08, 0x3ff5f048
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wifi_init(void)
{
    /* DWARF locals: u8 xtal_clk@l1020, u8 i@l1020, struct rwip_rf_api api@l1021, uint8[] rf_cal_data@l1106, uint8[] mac_addr@l1107, bool flash_valid@l1113 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <wifi_init> (198 insns) + DWARF line rows for wifi.c:1017.
     * Ordered callee relocs: phy_get_romfunc_addr, i2c_xtal_init, phy_printf, rtc_init_lite, esp_dport_access_reg_read, GetUartDevice, uart_tx_switch, uart_wait_idle, ets_delay_us, uart_div_modify, rtc_set_cpu_freq, ets_update_cpu_frequency, print_efuse_mac, phy_set_wifi_mode_only, read_macaddr_from_otp, init_param_read, register_chipv7_phy, rx_gain_level, noise_init, coex_bt_high_prio, rf_rw_init, phy_bt_power_track, mac_init, write_efuse_dig_reserve, phy_pwdet_always_en, .text.flash_init_param_print$part$1+0x7c, phy_version_print, tsens_code_read.
     */
}

/* write_efuse_dig_reserve wifi.c:326 @ wifi.o size 55B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read, burn_efuse | Data refs: burn_efuse, esp_dport_access_reg_read, wr_data, wr_en | MMIO: 0x3ff5a018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void write_efuse_dig_reserve(void)
{
    /* DWARF locals: u32 blk0_rdata6@l328, u8 rd_data24@l329, u8 result@l329 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <write_efuse_dig_reserve> (20 insns) + DWARF line rows for wifi.c:326.
     * Ordered callee relocs: esp_dport_access_reg_read, burn_efuse.
     */
}

/* write_flash_init_para wifi.c:1737 @ wifi.o size 27B [dwarf-sig]
 * Calls: SPIEraseSector, SPIWrite | Data refs: SPIEraseSector, SPIWrite | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void write_flash_init_para(u32 addr, u8 * data)
{
    (void)addr;
    (void)data;
    /* DWARF locals: u32[] flash_data@l1739, u32 i@l1739 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <write_flash_init_para> (10 insns) + DWARF line rows for wifi.c:1737.
     * Ordered callee relocs: SPIEraseSector, SPIWrite.
     */
}

/* write_rtc_mem_test wifi.c:1251 @ wifi.o size 47B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff61000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void write_rtc_mem_test(void)
{
    /* DWARF locals: u32 i@l1253 */
    /* TODO(ground-truth): reconstruct from librftest/wifi.rdis
     * function <write_rtc_mem_test> (18 insns) + DWARF line rows for wifi.c:1251.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* Undefined refs (270): CMDSTOP_GPIO, DIG_pwc_mea_ate, ESP_TEST_GPIO_DRV, ESP_TEST_GPIO_func, FlashBoardTest, GetStopCmd, GetUartDevice, HTsigAddrGet, Plcp0AddrGet, Plcp1AddrGet, PsramBoardTest, RFChannelSel, RF_init_sel, RTC_pwc_mea_ate, SPIEraseSector, SPIRead, SPIWrite, SPI_read_local, Vsar2_pwc_mea_ate, _xtos_ints_off, _xtos_ints_on, _xtos_set_interrupt_handler_arg, adc1_read, adc2_read, adc_test1, adctrig, ant_btrx_cfg, ant_bttx_cfg, ant_dft_cfg, ant_wifirx_cfg, ant_wifitx_cfg, ap_ack_test, ate_rfpll_cap_sign, bb_init, bb_wdt_rst_enable, bt_bb_init_cmplx_reg, bt_dut_param, bt_rx_spur_opt, bt_tester_param, bt_tx_tone, btpwr_backoff, btpwr_tsen_init, burn_efuse, cbw40m_en, chan14_mic_en, chan14_mic_enable, chan14_mic_most_power, chip7_phy_init_ctrl, chip7_sleep_params, chip_v7_set_chan, chip_v7_set_chan_offset, clr_pwc_mea, cmd_polling_start, coex_bt_high_prio, dac_out, do_rx_poll, esp_chg_freqoff, esp_chk_mac, esp_dport_access_reg_read, esp_en_reboot... */