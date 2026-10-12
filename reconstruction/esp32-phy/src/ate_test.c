/* Reconstruction of ate_test.o (librftest.a)
 * CU: ate_test.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 23 | funcdb functions: 12
 * Disasm: re/esp32-phy/disasm/librftest/ate_test.rdis
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

/* ate_rfpll_cap_sign ate_test.c:3893 @ ate_test.o size 324B [dwarf-sig]
 * Calls: chip_v7_set_chan, ets_delay_us, phy_printf | Data refs: .rodata.str1.4, chip_v7_set_chan, ets_delay_us, g_phyFuns, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ate_rfpll_cap_sign(bool print_en_in)
{
    (void)print_en_in;
    /* DWARF locals: uint16 cap@l3895, uint16 cap_set@l3895, sint8 i@l3896, sint8 j@l3896, uint8 cap_sign@l3897, uint8[] sign_num@l3898 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <ate_rfpll_cap_sign> (124 insns) + DWARF line rows for ate_test.c:3893.
     * Ordered callee relocs: chip_v7_set_chan, ets_delay_us, phy_printf.
     */
}

/* ate_rxdc_remain_check ate_test.c:2905 @ ate_test.o size 246B [dwarf-sig]
 * Calls: chip_v7_set_chan, esp_dport_access_reg_read | Data refs: chip_v7_set_chan, esp_dport_access_reg_read, g_phyFuns | MMIO: 0x3ff5c02c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ate_rxdc_remain_check(void)
{
    /* DWARF locals: uint8 chan@l2911, uint8 i@l2911, uint8 j@l2911, uint8 k@l2911, uint8 mem_addr@l2911, sint32[] dc_est@l2912, sint8[] dc_est_min@l2913 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <ate_rxdc_remain_check> (96 insns) + DWARF line rows for ate_test.c:2905.
     * Ordered callee relocs: chip_v7_set_chan, esp_dport_access_reg_read.
     */
}

/* freq_offset_get_pwr ate_test.c:722 @ ate_test.o size 1374B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, get_iq_est_snr, phy_printf, linear_to_db_64bits | Data refs: .rodata.str1.4, esp_dport_access_reg_read, g_phyFuns, get_iq_est_snr, linear_to_db_64bits, phy_printf | MMIO: 0x3ff450a8, 0x3ff460b8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void freq_offset_get_pwr(U8 loop_bits, S16 tone_step, U8 corr_cycle_bits, uint64 * pwr_sum, S16 * rxiq_remain, bool rxiq_sign, bool print_en)
{
    (void)loop_bits;
    (void)tone_step;
    (void)corr_cycle_bits;
    (void)pwr_sum;
    (void)rxiq_remain;
    (void)rxiq_sign;
    (void)print_en;
    /* DWARF locals: U8 loop_i@l724, uint64[] get_power@l725 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <freq_offset_get_pwr> (556 insns) + DWARF line rows for ate_test.c:722.
     * Ordered callee relocs: esp_dport_access_reg_read, get_iq_est_snr, phy_printf, linear_to_db_64bits.
     */
}

/* get_corr_power ate_test.c:776 @ ate_test.o size 228B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff46080, 0x3ff46084, 0x3ff46088, 0x3ff4608c, 0x3ff460dc, 0x3ff460e0, 0x3ff460e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void get_corr_power(int * power, U8 shift_bits, bool print_en)
{
    (void)power;
    (void)shift_bits;
    (void)print_en;
    /* DWARF locals: int sig_i@l778, int sig_q@l778, int dc_i@l778, int dc_q@l778, sint64 temp_power@l779 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <get_corr_power> (82 insns) + DWARF line rows for ate_test.c:776.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* get_iq_est_snr ate_test.c:621 @ ate_test.o size 1324B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, __divdi3, phy_printf, linear_to_db_64bits | Data refs: .rodata.str1.4, __divdi3, esp_dport_access_reg_read, linear_to_db_64bits, phy_printf | MMIO: 0x3ff46080, 0x3ff46084, 0x3ff46088, 0x3ff4608c, 0x3ff460cc, 0x3ff460d0, 0x3ff460d4, 0x3ff460d8, 0x3ff460dc, 0x3ff460e0, 0x3ff460e4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S16 get_iq_est_snr(uint64 * get_power, uint8 shift_bits, bool print_en)
{
    (void)get_power;
    (void)shift_bits;
    (void)print_en;
    /* DWARF locals: sint64 sig1_i@l623, sint64 sig1_q@l623, sint64 sig2_i@l623, sint64 sig2_q@l623, sint64 sig12_i@l623, sint64 sig12_q@l623, sint64 dc_i@l623, sint64 dc_q@l623, uint64 sig_power@l624, uint64 dc_power@l624, uint64 total_power@l624, sint64 noise_power@l625, const int32 cw_rms@l626, uint8 pwr_lshift@l630 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <get_iq_est_snr> (518 insns) + DWARF line rows for ate_test.c:621.
     * Ordered callee relocs: esp_dport_access_reg_read, __divdi3, phy_printf, linear_to_db_64bits.
     */
}

/* linear_to_db_64bits ate_test.c:598 @ ate_test.o size 287B [dwarf-sig]
 * Calls: memcpy | Data refs: .rodata, memcpy | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
S16 linear_to_db_64bits(uint64 power_sig, uint8 frac_bits)
{
    (void)power_sig;
    (void)frac_bits;
    /* DWARF locals: U8[] db_table@l600, int8 maxbit@l601, uint8 sig_ind@l602, uint8 i@l602 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <linear_to_db_64bits> (104 insns) + DWARF line rows for ate_test.c:598.
     * Ordered callee relocs: memcpy.
     */
}

/* module_test_cal_print ate_test.c:148 @ ate_test.o size 1126B [dwarf-sig]
 * Calls: phy_get_rf_cal_version, phy_printf, esp_dport_access_reg_read | Data refs: .rodata.str1.4, chip7_sleep_params, esp_dport_access_reg_read, noise_array, phy_get_rf_cal_version, phy_printf, phy_rxbb_dc, phy_rxrf_dc, tx_rf_ana_gain | MMIO: 0x3ff5a004, 0x3ff5a008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void module_test_cal_print(bool print_en)
{
    (void)print_en;
    /* DWARF locals: uint8 i@l150, sint32 temp@l151, s8 iq_mg@l152, s8 iq_mp@l152, u32 loop_i@l153, uint16 * txdc@l154, sint16[] rxdc@l155, u8 rfrx_index@l156, u16 bbgain@l157, u32 vdd33@l164, s8 vdd33_offset@l165, u8 temp_code@l166, uint16 i_m@l397 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <module_test_cal_print> (404 insns) + DWARF line rows for ate_test.c:148.
     * Ordered callee relocs: phy_get_rf_cal_version, phy_printf, esp_dport_access_reg_read.
     */
}

/* rxspur_test ate_test.c:3840 @ ate_test.o size 234B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, rx_spur_cal, get_spur4m_pwr, phy_printf | Data refs: .rodata.str1.4, chip7_phy_init_ctrl, g_phyFuns, get_spur4m_pwr, phy_printf, rx_spur_cal, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rxspur_test(bool print_en)
{
    (void)print_en;
    /* DWARF locals: uint8 set_dac1@l3847, uint8 dac_org@l3847, uint8 dcur_org@l3847, uint8 i@l3847, uint8 data@l3847, uint32[] rx_pwr1@l3848, uint32[] rx_pwr2@l3848 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <rxspur_test> (95 insns) + DWARF line rows for ate_test.c:3840.
     * Ordered callee relocs: set_chan_freq_sw_start, rx_spur_cal, get_spur4m_pwr, phy_printf.
     */
}

/* test_set_rf_freq_offset ate_test.c:796 @ ate_test.o size 82B [dwarf-sig]
 * Calls: chip_v7_rxmax_ext_ana | Data refs: chip_v7_rxmax_ext_ana, g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_set_rf_freq_offset(uint8 crystal_select, uint16 freq, sint16 freq_offset)
{
    (void)crystal_select;
    (void)freq;
    (void)freq_offset;
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <test_set_rf_freq_offset> (33 insns) + DWARF line rows for ate_test.c:796.
     * Ordered callee relocs: chip_v7_rxmax_ext_ana.
     */
}

/* txdc_delta_max ate_test.c:3761 @ ate_test.o size 123B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: g_phyFuns | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void txdc_delta_max(sint16 * delta, sint16 * delta_max)
{
    (void)delta;
    (void)delta_max;
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <txdc_delta_max> (44 insns) + DWARF line rows for ate_test.c:3761.
     */
}

/* txdc_stable_sub ate_test.c:3776 @ ate_test.o size 197B [dwarf-sig]
 * Calls: ets_delay_us, txdc_delta_max | Data refs: ets_delay_us, g_phyFuns, txdc_delta_max | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void txdc_stable_sub(bool bt_mode, sint16 * txdc)
{
    (void)bt_mode;
    (void)txdc;
    /* DWARF locals: uint8 i@l3778, uint8 max_i@l3778, sint16[] txdc_cal@l3779, sint16[] txdc_0@l3779, sint16[] delta@l3780, sint16[] delta_max@l3780 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <txdc_stable_sub> (74 insns) + DWARF line rows for ate_test.c:3776.
     * Ordered callee relocs: ets_delay_us, txdc_delta_max.
     */
}

/* txdc_stable_test ate_test.c:3807 @ ate_test.o size 71B [dwarf-sig]
 * Calls: txdc_stable_sub, txdc_delta_max, ets_delay_us, phy_printf | Data refs: .rodata.str1.4, ets_delay_us, phy_printf, txdc_delta_max, txdc_stable_sub | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void txdc_stable_test(bool print_en)
{
    (void)print_en;
    /* DWARF locals: uint8 i@l3814, uint8 num@l3814, sint16[] dc_delta@l3815, sint16[] delta_max@l3815 */
    /* TODO(ground-truth): reconstruct from librftest/ate_test.rdis
     * function <txdc_stable_test> (27 insns) + DWARF line rows for ate_test.c:3807.
     * Ordered callee relocs: txdc_stable_sub, txdc_delta_max, ets_delay_us, phy_printf.
     */
}

/* Undefined refs (18): __divdi3, chip7_phy_init_ctrl, chip7_sleep_params, chip_v7_rxmax_ext_ana, chip_v7_set_chan, esp_dport_access_reg_read, ets_delay_us, g_phyFuns, get_spur4m_pwr, memcpy, noise_array, phy_get_rf_cal_version, phy_printf, phy_rxbb_dc, phy_rxrf_dc, rx_spur_cal, set_chan_freq_sw_start, tx_rf_ana_gain */