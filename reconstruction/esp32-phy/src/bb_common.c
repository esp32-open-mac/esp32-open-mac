/* Reconstruction of bb_common.o (librftest.a)
 * CU: bb_common.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 80 | funcdb functions: 33
 * Disasm: re/esp32-phy/disasm/librftest/bb_common.rdis
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

/* ap_ack_test bb_common.c:1403 @ bb_common.o size 840B [dwarf-sig]
 * Calls: Plcp0AddrGet, Plcp1AddrGet, ConfAddrGet, HTsigAddrGet, chip_v7_set_chan, phy_printf, esp_dport_access_reg_read, set_macrxfilter, fill_txdataframe, GetStopCmd, tx_add_pocketnum | Data refs: .rodata.str1.4, ConfAddrGet, GetStopCmd, HTsigAddrGet, Plcp0AddrGet, Plcp1AddrGet, chip_v7_set_chan, esp_dport_access_reg_read, fill_txdataframe, phy_printf, set_macrxfilter, tx_add_pocketnum, tx_pocket_num | MMIO: 0x40000000, 0x60033040, 0x60033044, 0x60033080, 0x60033084, 0x60033098, 0x60033c00, 0x60033c40, 0x60033c48, 0x60033c4c, 0x60033c78, 0x60033c8c, 0x60033cac
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ap_ack_test(uint8 chan_num, u32 fb_rate, u32 fb_len)
{
    (void)chan_num;
    (void)fb_rate;
    (void)fb_len;
    /* DWARF locals: bool print_debug@l1405, uint32_t keyword@l1407, uint32_t rxaddr@l1408, uint32_t res_buf_size@l1408, uint32_t ate_frame_ctrl@l1409, uint32_t txdata_addr@l1410, uint32_t ate_num@l1411, uint32_t chip_id_lo@l1412, uint32_t[] rx_macaddr@l1413, uint32_t rx_num@l1414, uint32_t fb_rxrssi@l1415, uint32_t start_time@l1416, uint32_t rxaddr_rssi@l1417, uint32_t rxaddr_ate@l1417, uint32_t rxaddrlo_chip_id@l1417, uint32_t rxaddrhi_chip_id@l1417 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <ap_ack_test> (313 insns) + DWARF line rows for bb_common.c:1403.
     * Ordered callee relocs: Plcp0AddrGet, Plcp1AddrGet, ConfAddrGet, HTsigAddrGet, chip_v7_set_chan, phy_printf, esp_dport_access_reg_read, set_macrxfilter, fill_txdataframe, GetStopCmd, tx_add_pocketnum.
     */
}

/* ate_rxframe_fb bb_common.c:1255 @ bb_common.o size 1027B [dwarf-sig]
 * Calls: Plcp0AddrGet, Plcp1AddrGet, ConfAddrGet, HTsigAddrGet, chip_v7_set_chan, phy_printf, esp_dport_access_reg_read, set_macrxfilter, fill_txdataframe, GetStopCmd, tx_add_pocketnum | Data refs: .rodata.str1.4, ConfAddrGet, GetStopCmd, HTsigAddrGet, Plcp0AddrGet, Plcp1AddrGet, chip_v7_set_chan, esp_dport_access_reg_read, fill_txdataframe, phy_printf, set_macrxfilter, tx_add_pocketnum, tx_pocket_num | MMIO: 0x40000000, 0x60033040, 0x60033044, 0x60033080, 0x60033084, 0x60033098, 0x60033c00, 0x60033c40, 0x60033c48, 0x60033c4c, 0x60033c78, 0x60033c8c, 0x60033cac
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ate_rxframe_fb(uint8 chan_num, u32 fb_rate, u32 fb_len)
{
    (void)chan_num;
    (void)fb_rate;
    (void)fb_len;
    /* DWARF locals: bool print_debug@l1257, uint32_t keyword@l1259, uint32_t rxaddr@l1260, uint32_t res_buf_size@l1260, uint32_t ate_frame_ctrl@l1261, uint32_t txdata_addr@l1262, uint32_t ate_num@l1263, uint32_t chip_id_lo@l1264, uint32_t[] rx_macaddr@l1265, uint32_t fb_rxseq@l1266, uint32_t fb_rxbitmap0@l1267, uint32_t fb_rxbitmap1@l1268, uint32_t fb_rxbitmap2@l1269, uint32_t fb_rxbitmap3@l1270, uint32_t fb_rxrssi@l1271, uint32_t start_time@l1272 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <ate_rxframe_fb> (386 insns) + DWARF line rows for bb_common.c:1255.
     * Ordered callee relocs: Plcp0AddrGet, Plcp1AddrGet, ConfAddrGet, HTsigAddrGet, chip_v7_set_chan, phy_printf, esp_dport_access_reg_read, set_macrxfilter, fill_txdataframe, GetStopCmd, tx_add_pocketnum.
     */
}

/* delay_ns bb_common.c:45 @ bb_common.o size 5B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: high - trivial stub; body exact per disasm */
void delay_ns(unsigned int n_ns)
{
    return;
}

/* do_rx_poll bb_common.c:324 @ bb_common.o size 2221B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, flash_test_run, get_rx_freq_local, ets_delay_us, GetStopCmd, bb_wdt_rst_enable, phy_printf | Data refs: .rodata.str1.4, GetStopCmd, bb_wdt_rst_enable, chip7_sleep_params, esp_dport_access_reg_read, esp_rx_result, esp_rx_valid, ets_delay_us, flash_test_run, get_rx_freq_local, phy_printf, rssi_min_max_print, short_log_en | MMIO: 0x3ff5c018, 0x3ff5c06c, 0x3ff5c104, 0x3ff5cc5c, 0x60033080, 0x600330a4, 0x600330a8, 0x600330ac, 0x600330f8, 0x60033800, 0x60033c00, 0x60033c08, 0x60033c0c, 0x60033c48, 0x60033c4c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void do_rx_poll(unsigned int rx_rate_in)
{
    (void)rx_rate_in;
    /* DWARF locals: int gain@l326, int rssi@l327, int noise@l328, int reg_rx_gain@l329, int reg_noiseflorr@l329, int reg_rssi@l329, unsigned int state@l330, unsigned int err_type@l330, unsigned int rx_para@l330, unsigned int rx_para2@l330, int desired_count@l331, int gooddata_count@l332, unsigned int correct_count@l333, unsigned int err_count@l334, unsigned int err_a1_count@l335, unsigned int err_fcs_count@l336 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <do_rx_poll> (884 insns) + DWARF line rows for bb_common.c:324.
     * Ordered callee relocs: esp_dport_access_reg_read, flash_test_run, get_rx_freq_local, ets_delay_us, GetStopCmd, bb_wdt_rst_enable, phy_printf.
     */
}

/* esp_get_rx_result bb_common.c:316 @ bb_common.o size 50B [dwarf-sig]
 * Calls: (none) | Data refs: esp_rx_result, esp_rx_valid | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
bool esp_get_rx_result(int32 * rx_result)
{
    (void)rx_result;
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <esp_get_rx_result> (23 insns) + DWARF line rows for bb_common.c:316.
     */
}

/* fill_txaddr bb_common.c:1044 @ bb_common.o size 43B [dwarf-sig]
 * Calls: read_macaddr_from_otp | Data refs: read_macaddr_from_otp | MMIO: 0x60033040, 0x60033044
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fill_txaddr(void)
{
    /* DWARF locals: u8[] mac_addr@l1046 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <fill_txaddr> (17 insns) + DWARF line rows for bb_common.c:1044.
     * Ordered callee relocs: read_macaddr_from_otp.
     */
}

/* fill_txbeacon bb_common.c:997 @ bb_common.o size 431B [dwarf-sig]
 * Calls: fill_txaddr, fill_txdataframe | Data refs: fill_txaddr, fill_txdataframe | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fill_txbeacon(u8 * byte0, u8 * byte1, u8 * byte2, u32 * byte128, u8 * byte_m)
{
    (void)byte0;
    (void)byte1;
    (void)byte2;
    (void)byte128;
    (void)byte_m;
    /* DWARF locals: uint32_t rate@l999, uint32_t gi_bit@l999, uint32_t txdata_addr@l1000, int i@l1001 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <fill_txbeacon> (172 insns) + DWARF line rows for bb_common.c:997.
     * Ordered callee relocs: fill_txaddr, fill_txdataframe.
     */
}

/* fill_txdataframe bb_common.c:1079 @ bb_common.o size 737B [dwarf-sig]
 * Calls: Plcp0AddrGet, ConfAddrGet, esp_dport_access_reg_read, fill_tx_frame | Data refs: ConfAddrGet, PSDU0_OFFSET, Plcp0AddrGet, TXBUF_START, ate_gi_bit, ate_rate, esp_dport_access_reg_read, fill_tx_frame, test_tx_rate | MMIO: 0x60033040, 0x60033044, 0x60035144
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t fill_txdataframe(int cmd, int data_length, uint32_t addr0lo, uint32_t addr0hi, uint32_t key_word, uint32_t * rate, uint32_t * gi_bit, u32 tx_rate_in)
{
    (void)cmd;
    (void)data_length;
    (void)addr0lo;
    (void)addr0hi;
    (void)key_word;
    (void)rate;
    (void)gi_bit;
    (void)tx_rate_in;
    /* DWARF locals: unsigned int tx_queue@l1081, uint32 plcp0_addr@l1082, uint32 conf_addr@l1083, int psdu0_len@l1084, int psdu1_len@l1085, int psdu2_len@l1086, int psdu3_len@l1087, uint32_t frame_head0@l1088, uint32_t frame_head1@l1088, uint32_t frame_head2@l1088, uint32_t frame_head3@l1088, uint32_t frame_head4@l1088, uint32_t frame_head5@l1088, uint32_t frame_head6@l1088, uint32_t frame_head7@l1088, uint32_t frame_head8@l1088 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <fill_txdataframe> (290 insns) + DWARF line rows for bb_common.c:1079.
     * Ordered callee relocs: Plcp0AddrGet, ConfAddrGet, esp_dport_access_reg_read, fill_tx_frame.
     */
}

/* get_macaddr bb_common.c:1515 @ bb_common.o size 23B [dwarf-sig]
 * Calls: read_macaddr_from_otp | Data refs: read_macaddr_from_otp | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_macaddr(uint32_t * mac_addr)
{
    (void)mac_addr;
    /* DWARF locals: uint8[] macaddr@l1517 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <get_macaddr> (9 insns) + DWARF line rows for bb_common.c:1515.
     * Ordered callee relocs: read_macaddr_from_otp.
     */
}

/* get_rx_buffer bb_common.c:2487 @ bb_common.o size 403B [dwarf-sig]
 * Calls: chip_v7_set_chan, esp_dport_access_reg_read, phy_get_rx_freq, phy_printf, GetStopCmd | Data refs: .rodata.str1.4, GetStopCmd, chip_v7_set_chan, esp_dport_access_reg_read, phy_get_rx_freq, phy_printf | MMIO: 0x40000000, 0x60033080, 0x60033084, 0x60033098
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_rx_buffer(uint8 chan, uint8 mac_sel, u32 mac_id)
{
    (void)chan;
    (void)mac_sel;
    (void)mac_id;
    /* DWARF locals: RxControl * rxctrl@l2490, u8 rssi@l2491, u8 rate@l2491, u32 bb_info@l2492, u32 length@l2492, u32 rx_para@l2493, u32 rx_para2@l2493, u32 reg_rssi@l2493, u32 reg_sigmode@l2493, u32 reg_rxrate@l2493, RxControl * p_addr@l2494, u32 rxctrl_addr@l2495, u32 * mac_addr@l2496, u32 i@l2497, u32 mac_id_g@l2497, bool print_en@l2498 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <get_rx_buffer> (150 insns) + DWARF line rows for bb_common.c:2487.
     * Ordered callee relocs: chip_v7_set_chan, esp_dport_access_reg_read, phy_get_rx_freq, phy_printf, GetStopCmd.
     */
}

/* get_rx_freq_local bb_common.c:268 @ bb_common.o size 109B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf, phy_get_rx_freq | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_get_rx_freq, phy_printf | MMIO: 0x60033080, 0x60033098
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
sint16 get_rx_freq_local(void)
{
    /* DWARF locals: u32 rxctrl_addr@l270, RxControl * rxctrl@l271, u32 bb_info@l272, u32 length@l272, u8 rssi@l273, u8 rate@l273, sint16 freq_offset1@l274, u32 rxlink_addr@l276 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <get_rx_freq_local> (40 insns) + DWARF line rows for bb_common.c:268.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf, phy_get_rx_freq.
     */
}

/* get_temp_cal_wifi bb_common.c:70 @ bb_common.o size 120B [dwarf-sig]
 * Calls: tsens_code_read, tx_gain_table_set, phy_printf | Data refs: .rodata.str1.4, btpwr_tsen_init, chip7_sleep_params, phy_printf, phy_tx_pwr_print_en, tsens_code_read, tx_gain_table_set | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
sint16 get_temp_cal_wifi(void)
{
    /* DWARF locals: sint16 gain_offset@l72, sint16 temp_delta@l72, sint16 pwcorrect_v@l72, uint8 temp_meas@l73 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <get_temp_cal_wifi> (43 insns) + DWARF line rows for bb_common.c:70.
     * Ordered callee relocs: tsens_code_read, tx_gain_table_set, phy_printf.
     */
}

/* light_sleep bb_common.c:2317 @ bb_common.o size 191B [dwarf-sig]
 * Calls: phy_close_rf, pm_set_sleep_mode_local, rtc_slowck_cali, rtc_usec2rtc, pm_set_sleep_cycles, pm_wakeup_opt, pm_goto_sleep, rtc_set_cpu_freq, rtc_uart_div_modify, esp_dport_access_reg_read, ets_delay_us, pm_open_rf | Data refs: esp_dport_access_reg_read, ets_delay_us, phy_close_rf, pm_goto_sleep, pm_open_rf, pm_set_sleep_cycles, pm_set_sleep_mode_local, pm_wakeup_opt, rtc_set_cpu_freq, rtc_slowck_cali, rtc_uart_div_modify, rtc_usec2rtc | MMIO: 0x3ff000cc, 0x3ff48084, 0x3ff48088
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void light_sleep(u8 sleep_mode, u32 sleep_time)
{
    (void)sleep_mode;
    (void)sleep_time;
    /* DWARF locals: u32 period@l2319, u32 soft_reject@l2320, u32 slp_cycles_h@l2322, u32 slp_cycles@l2322, struct rwip_rf_api api@l2323 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <light_sleep> (70 insns) + DWARF line rows for bb_common.c:2317.
     * Ordered callee relocs: phy_close_rf, pm_set_sleep_mode_local, rtc_slowck_cali, rtc_usec2rtc, pm_set_sleep_cycles, pm_wakeup_opt, pm_goto_sleep, rtc_set_cpu_freq, rtc_uart_div_modify, esp_dport_access_reg_read, ets_delay_us, pm_open_rf.
     */
}

/* pm_set_sleep_mode_local bb_common.c:2279 @ bb_common.o size 102B [dwarf-sig-decl]
 * Calls: pm_mac_deinit, pm_check_mac_idle, pm_mac_init, rtc_sleep_init, __assert_func | Data refs: .rodata.__func__$6594, .rodata.str1.4, __assert_func, pm_check_mac_idle, pm_mac_deinit, pm_mac_init, rtc_sleep_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
pm_sw_reject_t pm_set_sleep_mode_local(PM_SLEEP_MODE sleep_mode, void (*)() * pmac_save_params)
{
    (void)sleep_mode;
    (void)pmac_save_params;
    /* DWARF locals: rtc_sleep_config_t cfg@l2289, const char[] __func__@lNone */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <pm_set_sleep_mode_local> (36 insns) + DWARF line rows for bb_common.c:2279.
     * Ordered callee relocs: pm_mac_deinit, pm_check_mac_idle, pm_mac_init, rtc_sleep_init, __assert_func.
     */
}

/* ram_get_power_db bb_common.c:2406 @ bb_common.o size 109B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read, g_phyFuns | MMIO: 0x3ff460b8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S16 ram_get_power_db(uint16 pw_offset)
{
    (void)pw_offset;
    /* DWARF locals: S16 vsig_dc@l2408, S16 vref_dc@l2408 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <ram_get_power_db> (42 insns) + DWARF line rows for bb_common.c:2406.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* read_macaddr_from_otp bb_common.c:1053 @ bb_common.o size 59B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5a004, 0x3ff5a008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void read_macaddr_from_otp(uint8 * macaddr)
{
    (void)macaddr;
    /* DWARF locals: u32 efuse17@l1055, u32 efuse16@l1055 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <read_macaddr_from_otp> (20 insns) + DWARF line rows for bb_common.c:1053.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* rx_data_check bb_common.c:670 @ bb_common.o size 167B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int rx_data_check(unsigned int RX_buff_start, unsigned int rxrate)
{
    (void)RX_buff_start;
    (void)rxrate;
    /* DWARF locals: unsigned int i@l672, unsigned int j@l672, unsigned int * packet@l673, unsigned int packet_word_len@l674, unsigned int packet_tail_len@l675, unsigned int tailmask@l676, unsigned int packet_byte_len@l677 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <rx_data_check> (66 insns) + DWARF line rows for bb_common.c:670.
     */
}

/* set_mac_filter bb_common.c:254 @ bb_common.o size 114B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60033040, 0x60033044, 0x60033060, 0x60033064, 0x600330dc, 0x600330e0, 0x600330e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_mac_filter(u32 mac_lower, u32 mac_upper)
{
    (void)mac_lower;
    (void)mac_upper;
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <set_mac_filter> (49 insns) + DWARF line rows for bb_common.c:254.
     */
}

/* set_macrxfilter bb_common.c:1529 @ bb_common.o size 242B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x600330d8, 0x600330dc, 0x600330e0, 0x600330e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void set_macrxfilter(bool mac_filter_en)
{
    (void)mac_filter_en;
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <set_macrxfilter> (86 insns) + DWARF line rows for bb_common.c:1529.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* setmacaddr bb_common.c:1229 @ bb_common.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60033040, 0x60033044
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void setmacaddr(uint32_t da_lo, uint32_t da_hi)
{
    (void)da_lo;
    (void)da_hi;
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <setmacaddr> (12 insns) + DWARF line rows for bb_common.c:1229.
     */
}

/* settxframe_chipid bb_common.c:1235 @ bb_common.o size 43B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void settxframe_chipid(uint32_t txdata_addr, uint32_t chip_id_lo, uint32_t chip_id_hi)
{
    (void)txdata_addr;
    (void)chip_id_lo;
    (void)chip_id_hi;
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <settxframe_chipid> (15 insns) + DWARF line rows for bb_common.c:1235.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* settxframe_rate bb_common.c:1241 @ bb_common.o size 66B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void settxframe_rate(uint32_t plcp1_addr, uint32_t htsig_addr, uint32_t len, uint32_t rate)
{
    (void)plcp1_addr;
    (void)htsig_addr;
    (void)len;
    (void)rate;
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <settxframe_rate> (24 insns) + DWARF line rows for bb_common.c:1241.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* sleep_proc_test bb_common.c:2351 @ bb_common.o size 164B [dwarf-sig-decl]
 * Calls: phy_close_rf, rtc_set_cpu_freq, rtc_uart_div_modify, pm_wakeup_init, light_sleep, phy_printf, coex_bt_high_prio, rf_rw_init, mac_init | Data refs: .rodata.str1.4, coex_bt_high_prio, light_sleep, mac_init, phy_close_rf, phy_printf, pm_wakeup_init, rf_rw_init, rtc_set_cpu_freq, rtc_uart_div_modify | MMIO: 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void sleep_proc_test(u8 sleep_mode, u8 wakeup, u32 sleep_time)
{
    (void)sleep_mode;
    (void)wakeup;
    (void)sleep_time;
    /* DWARF locals: u32 slp_cycles_h@l2355, u32 slp_cycles_l@l2355, RTC_clock rtc_clk@l2357, u32 soft_reject@l2358, struct rwip_rf_api api@l2359 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <sleep_proc_test> (60 insns) + DWARF line rows for bb_common.c:2351.
     * Ordered callee relocs: phy_close_rf, rtc_set_cpu_freq, rtc_uart_div_modify, pm_wakeup_init, light_sleep, phy_printf, coex_bt_high_prio, rf_rw_init, mac_init.
     */
}

/* test_noise_floor bb_common.c:2569 @ bb_common.o size 78B [dwarf-sig]
 * Calls: chip_v7_set_chan, noise_check_loop, read_hw_noisefloor, phy_printf, GetStopCmd, ets_delay_us | Data refs: .rodata.str1.4, GetStopCmd, chip_v7_set_chan, ets_delay_us, noise_check_loop, phy_printf, read_hw_noisefloor | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_noise_floor(u8 channel, u32 delay)
{
    (void)channel;
    (void)delay;
    /* DWARF locals: int i@l2571 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <test_noise_floor> (28 insns) + DWARF line rows for bb_common.c:2569.
     * Ordered callee relocs: chip_v7_set_chan, noise_check_loop, read_hw_noisefloor, phy_printf, GetStopCmd, ets_delay_us.
     */
}

/* test_tx_frame bb_common.c:163 @ bb_common.o size 370B [dwarf-sig]
 * Calls: Plcp1AddrGet, HTsigAddrGet, esp_dport_access_reg_read, tx_a_frame, tx_pwctrl_background, phy_ofdm_bandage_opt, phy_temp_track, wifi_track_pll_cap, ets_delay_us | Data refs: HTsigAddrGet, Plcp1AddrGet, chip7_sleep_params, esp_dport_access_reg_read, ets_delay_us, lr_enable, phy_ofdm_bandage_opt, phy_temp_track, phy_tx_pwr_correct_en, phy_tx_pwr_print_en, phy_tx_pwr_track_en, test_tx_cbw40, test_tx_rate, tx_a_frame, tx_pwctrl_background, wifi_track_pll_cap | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_tx_frame(unsigned int queue, unsigned int tx_rate, unsigned int tx_num, unsigned int tx_ext_idle_us, unsigned int tx_cbw40, unsigned int ht_dup)
{
    (void)queue;
    (void)tx_rate;
    (void)tx_num;
    (void)tx_ext_idle_us;
    (void)tx_cbw40;
    (void)ht_dup;
    /* DWARF locals: int i@l165, unsigned int plcp1_addr@l166, unsigned int htsig_addr@l166 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <test_tx_frame> (135 insns) + DWARF line rows for bb_common.c:163.
     * Ordered callee relocs: Plcp1AddrGet, HTsigAddrGet, esp_dport_access_reg_read, tx_a_frame, tx_pwctrl_background, phy_ofdm_bandage_opt, phy_temp_track, wifi_track_pll_cap, ets_delay_us.
     */
}

/* test_txtone_pwr bb_common.c:2419 @ bb_common.o size 178B [dwarf-sig]
 * Calls: txcal_debuge_mode, phy_printf | Data refs: .rodata.str1.4, g_phyFuns, phy_printf, pwrdet_offset, txcal_debuge_mode | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
sint32 test_txtone_pwr(int tone_atten, int loop_num, int mode, S16 step)
{
    (void)tone_atten;
    (void)loop_num;
    (void)mode;
    (void)step;
    /* DWARF locals: int pwdet_out@l2423, int pout_db@l2423, int tx_scale@l2423, int bb_att@l2423, int loop_i@l2423, S16 power_sum@l2424, s16 tone_step@l2425 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <test_txtone_pwr> (68 insns) + DWARF line rows for bb_common.c:2419.
     * Ordered callee relocs: txcal_debuge_mode, phy_printf.
     */
}

/* tx_a_frame bb_common.c:92 @ bb_common.o size 377B [dwarf-sig]
 * Calls: Plcp0AddrGet, ConfAddrGet, tx_add_pocketnum, esp_dport_access_reg_read, flash_test_run, phy_printf, get_temp_cal_wifi, phy_ofdm_bandage_opt, ets_delay_us, GetStopCmd | Data refs: .rodata.str1.4, ConfAddrGet, GetStopCmd, Plcp0AddrGet, esp_dport_access_reg_read, ets_delay_us, flash_test_run, get_temp_cal_wifi, phy_ofdm_bandage_opt, phy_printf, phy_tx_pwr_track_en, test_tx_cbw40, test_tx_rate, tx_add_pocketnum, tx_contin_fcc_en | MMIO: 0x3ff5c400, 0x3ff5c458, 0x40000002, 0x60033c00, 0x60033c10, 0x60033c40, 0x60033c48, 0x60033c4c, 0x60033cb8, 0x60033cc0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_a_frame(unsigned int queue)
{
    (void)queue;
    /* DWARF locals: unsigned int plcp0_addr@l94, unsigned int conf_addr@l95, uint32_t timer0@l99, uint32_t timer1@l99 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <tx_a_frame> (136 insns) + DWARF line rows for bb_common.c:92.
     * Ordered callee relocs: Plcp0AddrGet, ConfAddrGet, tx_add_pocketnum, esp_dport_access_reg_read, flash_test_run, phy_printf, get_temp_cal_wifi, phy_ofdm_bandage_opt, ets_delay_us, GetStopCmd.
     */
}

/* tx_ack_init bb_common.c:2157 @ bb_common.o size 283B [dwarf-sig]
 * Calls: HTsigAddrGet, set_macrxfilter, get_macaddr, esp_dport_access_reg_read, fill_txdataframe | Data refs: HTsigAddrGet, esp_dport_access_reg_read, fill_txdataframe, get_macaddr, set_macrxfilter, test_tx_rate | MMIO: 0x60033040, 0x60033044, 0x60033080, 0x60033084, 0x60033c50, 0x60033c78
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_ack_init(u32 ap_addr0, u32 ap_addr1, uint8 tx_rate, u32 tx_length, bool tx_cbw40)
{
    (void)ap_addr0;
    (void)ap_addr1;
    (void)tx_rate;
    (void)tx_length;
    (void)tx_cbw40;
    /* DWARF locals: uint32_t txdata_addr@l2159, uint32_t[] mac_addr@l2160, uint32_t rate@l2161, uint32_t gi_bit@l2161, uint32 htsig_addr@l2162 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <tx_ack_init> (105 insns) + DWARF line rows for bb_common.c:2157.
     * Ordered callee relocs: HTsigAddrGet, set_macrxfilter, get_macaddr, esp_dport_access_reg_read, fill_txdataframe.
     */
}

/* tx_ack_start bb_common.c:2054 @ bb_common.o size 495B [dwarf-sig]
 * Calls: Plcp0AddrGet, ConfAddrGet, esp_dport_access_reg_read, tx_data_frame, ets_delay_us | Data refs: ConfAddrGet, Plcp0AddrGet, esp_dport_access_reg_read, ets_delay_us, rx_ack_num, tx_data_frame, tx_pocket_num | MMIO: 0x3ff5c018, 0x600330a8, 0x60035144
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_ack_start(uint16 tx_num, u32 backoff, u32 aifs, u32 delay_ms, u32 * result)
{
    (void)tx_num;
    (void)backoff;
    (void)aifs;
    (void)delay_ms;
    (void)result;
    /* DWARF locals: uint32_t txdata_addr@l2056, uint32_t txpmd@l2057, uint32_t res_buf_size@l2058, uint32_t rxaddr@l2059, uint32_t rate@l2060, uint32_t gi_bit@l2060, int rssi_min@l2061, int rssi_max@l2061, int rssi_min1@l2061, int rssi_max1@l2061, int rssi_min2@l2061, int rssi_max2@l2061, int tx_queue@l2062, uint32 plcp0_addr@l2063, uint32 conf_addr@l2064, uint32_t[] mac_addr@l2067 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <tx_ack_start> (199 insns) + DWARF line rows for bb_common.c:2054.
     * Ordered callee relocs: Plcp0AddrGet, ConfAddrGet, esp_dport_access_reg_read, tx_data_frame, ets_delay_us.
     */
}

/* tx_ack_test bb_common.c:2187 @ bb_common.o size 102B [dwarf-sig]
 * Calls: tx_ack_init, tx_ack_start, phy_printf | Data refs: .rodata.str1.4, PSDU0_OFFSET, phy_printf, tx_ack_init, tx_ack_start, tx_pocket_num | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_ack_test(u32 ap_addr0, u32 ap_addr1, uint8 tx_rate, uint16 tx_num, u32 tx_length, u32 backoff, u32 aifs, u32 delay_ms, bool tx_cbw40)
{
    (void)ap_addr0;
    (void)ap_addr1;
    (void)tx_rate;
    (void)tx_num;
    (void)tx_length;
    (void)backoff;
    (void)aifs;
    (void)delay_ms;
    (void)tx_cbw40;
    /* DWARF locals: int rssi@l2189, int rssi_min@l2189, int rssi_max@l2189, u16 ack_num@l2190, u32 rx_flag@l2191, u32[] result@l2192, unsigned char * packet0@l2194 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <tx_ack_test> (40 insns) + DWARF line rows for bb_common.c:2187.
     * Ordered callee relocs: tx_ack_init, tx_ack_start, phy_printf.
     */
}

/* tx_add_pocketnum bb_common.c:54 @ bb_common.o size 110B [dwarf-sig]
 * Calls: (none) | Data refs: PSDU0_OFFSET, rx_ack_num, tx_pocket_num | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_add_pocketnum(void)
{
    /* DWARF locals: unsigned char * packet0@l56 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <tx_add_pocketnum> (40 insns) + DWARF line rows for bb_common.c:54.
     */
}

/* tx_data_frame bb_common.c:1560 @ bb_common.o size 176B [dwarf-sig-decl]
 * Calls: Plcp0AddrGet, tx_add_pocketnum, esp_dport_access_reg_read | Data refs: Plcp0AddrGet, esp_dport_access_reg_read, tx_add_pocketnum | MMIO: 0x40000002, 0x60033c00, 0x60033c10, 0x60033c40, 0x60033c48, 0x60033c4c, 0x60033c68
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t tx_data_frame(uint32_t timelim)
{
    (void)timelim;
    /* DWARF locals: int tx_queue@l1562, uint32 plcp0_addr@l1563, uint32_t rxpmd@l1564, uint32_t timer0@l1565, uint32_t timer1@l1565 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <tx_data_frame> (63 insns) + DWARF line rows for bb_common.c:1560.
     * Ordered callee relocs: Plcp0AddrGet, tx_add_pocketnum, esp_dport_access_reg_read.
     */
}

/* wifi_ack_test bb_common.c:2213 @ bb_common.o size 536B [dwarf-sig]
 * Calls: tx_ack_init, chip_v7_set_chan_nomac, sleep_proc_test, ets_delay_us, tx_ack_start, phy_printf | Data refs: .rodata.str1.4, chip_v7_set_chan_nomac, coex_test_enable, ets_delay_us, phy_force_wifi_chan_en, phy_printf, sleep_proc_test, tx_ack_init, tx_ack_start | MMIO: 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wifi_ack_test(u32 ap_addr0, u32 ap_addr1, uint8 tx_rate, u32 tx_length, u32 chan_org, u32 chan_cfg_org, u16 tx_num, u8 test_num, u8 backoff, u8 test_mode, u32 delay_ms)
{
    (void)ap_addr0;
    (void)ap_addr1;
    (void)tx_rate;
    (void)tx_length;
    (void)chan_org;
    (void)chan_cfg_org;
    (void)tx_num;
    (void)test_num;
    (void)backoff;
    (void)test_mode;
    (void)delay_ms;
    /* DWARF locals: u32 rx_flag@l2215, u32 ack_num@l2215, u32 i@l2215, u32 di@l2215, int rssi@l2216, int rssi_max@l2216, int rssi_min@l2216, int[] rssi_m@l2216, u32[] result@l2217, u32[] ack_num_m@l2217, u32[] rx_flag_m@l2217, u32 t0@l2218 */
    /* TODO(ground-truth): reconstruct from librftest/bb_common.rdis
     * function <wifi_ack_test> (199 insns) + DWARF line rows for bb_common.c:2213.
     * Ordered callee relocs: tx_ack_init, chip_v7_set_chan_nomac, sleep_proc_test, ets_delay_us, tx_ack_start, phy_printf.
     */
}

/* Undefined refs (53): ConfAddrGet, GetStopCmd, HTsigAddrGet, PSDU0_OFFSET, Plcp0AddrGet, Plcp1AddrGet, TXBUF_START, __assert_func, bb_wdt_rst_enable, btpwr_tsen_init, chip7_sleep_params, chip_v7_set_chan, chip_v7_set_chan_nomac, coex_bt_high_prio, coex_test_enable, esp_dport_access_reg_read, ets_delay_us, fill_tx_frame, flash_test_run, g_phyFuns, lr_enable, mac_init, noise_check_loop, phy_close_rf, phy_force_wifi_chan_en, phy_get_rx_freq, phy_ofdm_bandage_opt, phy_printf, phy_temp_track, pm_check_mac_idle, pm_goto_sleep, pm_mac_deinit, pm_mac_init, pm_open_rf, pm_set_sleep_cycles, pm_wakeup_init, pm_wakeup_opt, pwrdet_offset, read_hw_noisefloor, rf_rw_init, rtc_set_cpu_freq, rtc_sleep_init, rtc_slowck_cali, rtc_uart_div_modify, rtc_usec2rtc, short_log_en, tsens_code_read, tx_contin_fcc_en, tx_gain_table_set, tx_pocket_num, tx_pwctrl_background, txcal_debuge_mode, wifi_track_pll_cap */